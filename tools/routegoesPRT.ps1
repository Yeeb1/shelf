<#
.SYNOPSIS
    Performs reverse DNS lookups on selected routes and optionally pings hosts before lookup.

.DESCRIPTION
    This script allows you to select network interfaces and routes, perform reverse DNS lookups on IP addresses within those routes, and optionally ping hosts before performing lookups.

.PARAMETER ping
    Optional switch. If specified, the script pings hosts before attempting reverse DNS lookups and only looks up hosts that respond to ping.

.EXAMPLE
    .\routegoesPTR.ps1 -ping

    Runs the script with pinging enabled.
#>

[CmdletBinding()]
param(
    [switch]$ping
)

# Im not very good with powershell 
if (-not ([Type]::GetType("IPNetwork"))) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Net;

public class IPNetwork
{
    public static string GetSubnetMask(string ipAddress, int prefixLength)
    {
        uint mask = (uint.MaxValue << (32 - prefixLength)) & uint.MaxValue;
        var bytes = BitConverter.GetBytes(mask);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return new IPAddress(bytes).ToString();
    }

    public static string GetNetworkAddress(string ipAddress, int prefixLength)
    {
        var ip = IPAddress.Parse(ipAddress).GetAddressBytes();
        if (BitConverter.IsLittleEndian) Array.Reverse(ip);
        uint ipAsUint = BitConverter.ToUInt32(ip, 0);
        uint mask = (uint.MaxValue << (32 - prefixLength)) & uint.MaxValue;
        uint networkAsUint = ipAsUint & mask;
        var networkBytes = BitConverter.GetBytes(networkAsUint);
        if (BitConverter.IsLittleEndian) Array.Reverse(networkBytes);
        return new IPAddress(networkBytes).ToString();
    }

    public static IEnumerable<string> GetAllIPs(string networkAddress, int prefixLength)
    {
        var ip = IPAddress.Parse(networkAddress).GetAddressBytes();
        if (BitConverter.IsLittleEndian) Array.Reverse(ip);
        uint startIP = BitConverter.ToUInt32(ip, 0) + 1; // skip network address
        uint endIP = startIP + (uint)(Math.Pow(2, 32 - prefixLength)) - 3; // skip broadcast 

        for (uint i = startIP; i <= endIP; i++)
        {
            var bytes = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
            yield return new IPAddress(bytes).ToString();
        }
    }
}
"@
} 

Write-Host "[+] Available Network Interfaces:" -ForegroundColor Cyan
$interfaces = Get-NetIPAddress | Select-Object -Unique InterfaceAlias | ForEach-Object { $_.InterfaceAlias }
$interfaces = $interfaces | Sort-Object -Unique

$interfaceList = @()
$index = 1
foreach ($iface in $interfaces) {
    Write-Host "$($index): $($iface)"
    $interfaceList += $iface
    $index++
}

$selectedInterfaceNumber = Read-Host "[?] Enter the number of the interface to use"
$selectedInterfaceIndex = [int]$selectedInterfaceNumber - 1

if ($selectedInterfaceIndex -lt 0 -or $selectedInterfaceIndex -ge $interfaceList.Count) {
    Write-Host "[!] Invalid interface selection. Exiting..." -ForegroundColor Red
    exit
}

$selectedInterfaceAlias = $interfaceList[$selectedInterfaceIndex]

if (-not $selectedInterfaceAlias) {
    Write-Host "[!] No interface selected. Exiting..." -ForegroundColor Red
    exit
}

$dnsServers = (Get-DnsClientServerAddress -InterfaceAlias $selectedInterfaceAlias).ServerAddresses

if ($dnsServers -and $dnsServers.Count -gt 0) {
    Write-Host "[+] Discovered DNS servers: $($dnsServers -join ', ')" -ForegroundColor Green
    $useDiscovered = Read-Host "[?] Do you want to use these DNS servers? (Y/N)"
    if ($useDiscovered -match '^[Nn]') {
        $dnsInput = Read-Host "[?] Please specify DNS server(s) (comma-separated for multiple)"
        $dnsServers = $dnsInput -split ',' | ForEach-Object { $_.Trim() }
    }
} else {
    Write-Host "[!] No DNS servers configured for this interface." -ForegroundColor Yellow
    $dnsInput = Read-Host "[?] Please specify DNS server(s) (comma-separated for multiple)"
    $dnsServers = $dnsInput -split ',' | ForEach-Object { $_.Trim() }
}

Write-Host "[+] Using DNS servers: $($dnsServers -join ', ')" -ForegroundColor Green

$routes = Get-NetRoute | Where-Object { $_.InterfaceAlias -eq $selectedInterfaceAlias -and $_.DestinationPrefix -notin ('::/0', '0.0.0.0/0') }

if (-not $routes) {
    Write-Host "[!] No routes found for this interface. Exiting..." -ForegroundColor Red
    exit
}

Write-Host "[+] Available Routes:" -ForegroundColor Cyan
$routeList = @()
$index = 1
foreach ($route in $routes) {
    Write-Host "$($index): $($route.DestinationPrefix) via Gateway: $($route.NextHop)"
    $routeList += $route
    $index++
}

$routeSelection = Read-Host "[?] Enter the numbers of the routes to reverse lookup (comma-separated)"
$routeIndexes = $routeSelection -split ',' | ForEach-Object { [int]($_.Trim()) - 1 }
$selectedRoutes = @()
foreach ($idx in $routeIndexes) {
    if ($idx -ge 0 -and $idx -lt $routeList.Count) {
        $selectedRoutes += $routeList[$idx]
    }
}

if (-not $selectedRoutes) {
    Write-Host "[!] No valid routes selected. Exiting..." -ForegroundColor Red
    exit
}

$results = @()
$pingResults = @()

foreach ($route in $selectedRoutes) {
    $destinationPrefix = $route.DestinationPrefix
    $ip = $destinationPrefix.Split('/')[0]
    $prefixLength = [int]$destinationPrefix.Split('/')[1]

    Write-Host "[+] Route: $($destinationPrefix) via Gateway: $($route.NextHop)" -ForegroundColor Yellow

    $networkAddress = [IPNetwork]::GetNetworkAddress($ip, $prefixLength)
    $subnetMask = [IPNetwork]::GetSubnetMask($ip, $prefixLength)

    Write-Host "[+] Network Address: $($networkAddress)" -ForegroundColor Cyan
    Write-Host "[+] Subnet Mask: $($subnetMask)" -ForegroundColor Cyan

    $allIPs = [IPNetwork]::GetAllIPs($networkAddress, $prefixLength)

    if ($ping.IsPresent) {
        Write-Host "[+] Pinging hosts to find live IPs..." -ForegroundColor Cyan

        $liveIPs = @()

        foreach ($currentIP in $allIPs) {
            $pingResult = [PSCustomObject]@{
                IP = $currentIP
                Pingable = $false
            }

            if (Test-Connection -ComputerName $currentIP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                $pingResult.Pingable = $true
                $liveIPs += $currentIP
                Write-Host "[+] Host $($currentIP) is pingable." -ForegroundColor Green
            } else {
            }

            $pingResults += $pingResult
        }

        Write-Host "[+] Found $($liveIPs.Count) pingable hosts." -ForegroundColor Green

        if ($liveIPs.Count -eq 0) {
            Write-Host "[!] No pingable hosts found in this subnet. Skipping..." -ForegroundColor Yellow
            continue
        }

        Write-Host "[+] Performing reverse DNS lookups on pingable hosts..." -ForegroundColor Cyan

        $lookupIPs = $liveIPs
    } else {
        Write-Host "[+] Performing reverse DNS lookups on all IPs..." -ForegroundColor Cyan
        $lookupIPs = $allIPs
    }

    foreach ($currentIP in $lookupIPs) {
        $hostName = $null
        foreach ($dnsServer in $dnsServers) {
            try {
                $reverseLookup = Resolve-DnsName -Name $currentIP -Server $dnsServer -Type PTR -ErrorAction Stop
                $hostName = $reverseLookup.NameHost
                break
            } catch {
            }
        }

        if ($hostName) {
            $result = [PSCustomObject]@{
                Interface   = $selectedInterfaceAlias
                Network     = $destinationPrefix
                IP          = $currentIP
                SubnetMask  = $subnetMask
                HostName    = $hostName.TrimEnd('.')
            }
            $results += $result
            Write-Host "[+] Reverse lookup for $($currentIP): $($result.HostName)" -ForegroundColor Green
        }
    }
}

if ($pingResults.Count -gt 0) {
    $pingOutputFile = "$env:USERPROFILE\Desktop\PingableHosts.csv"
    $pingResults | Export-Csv -Path $pingOutputFile -NoTypeInformation
    Write-Host "[+] Ping results saved to: $($pingOutputFile)" -ForegroundColor Green
}

if ($results.Count -gt 0) {
    $outputFile = "$env:USERPROFILE\Desktop\DNSReverseLookupResults.csv"
    $results | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Host "[+] Reverse DNS results saved to: $($outputFile)" -ForegroundColor Green
} else {
    Write-Host "[!] No reverse DNS records found." -ForegroundColor Yellow
}
