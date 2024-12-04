<#
.SYNOPSIS
Monitors an SMB share for new files and downloads them to a local directory.

.DESCRIPTION
This script accepts an SMB share path or a path to a folder on an SMB share.
It monitors for new files placed in the folder or subfolders up to a specified depth,
downloads them to a local directory, and searches for sensitive strings within the files.

.PARAMETER SMBSharePath
The UNC path to the SMB share or folder to monitor.

.PARAMETER DownloadDirectory
The local directory where files will be downloaded.

.PARAMETER IntervalInSeconds
The interval in seconds for how often the share is inspected. Default is 60 seconds.

.PARAMETER MaxFileSizeMB
The maximum file size in MB to process. Files larger than this size will be skipped. Default is 10 MB.

.PARAMETER MaxDepth
The maximum depth of subdirectories to search. Default is 5.

.PARAMETER FileTypes
An array of file patterns to include (e.g., "*.txt", "*.docx"). Default is "*.*".

.PARAMETER SensitiveStrings
An array of sensitive strings to search for within the files. Default is "password", "classified", "secret".

.PARAMETER ProcessExistingFiles
If specified, existing files in the SMB share will be processed upon script startup. Default is true.

.PARAMETER ExcludeExtensions
An array of file extensions (e.g., ".exe", ".dll") to exclude from sensitive string search.

.PARAMETER LogFile
The path to a log file where output will be saved. If not specified, logging to a file is disabled.

.EXAMPLE
.\TransferSnatch.ps1 -SMBSharePath "\\Server\Share" -DownloadDirectory "C:\Downloads" -IntervalInSeconds 60 -MaxFileSizeMB 5 -MaxDepth 3 -FileTypes "*.txt","*.docx","*.exe" -SensitiveStrings "password","classified","secret" -ProcessExistingFiles:$false -ExcludeExtensions ".exe", ".dll" -LogFile "C:\Logs\MonitorSMBShare.log"

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$SMBSharePath,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$DownloadDirectory,

    [Parameter(Position = 2)]
    [int]$IntervalInSeconds = 60,

    [Parameter(Position = 3)]
    [int]$MaxFileSizeMB = 10,

    [Parameter(Position = 4)]
    [int]$MaxDepth = 5,

    [Parameter(Position = 5)]
    [string[]]$FileTypes = @("*.*"),

    [Parameter(Position = 6)]
    [string[]]$SensitiveStrings = @("password", "classified", "secret", "kennwort", "passwort"),

    [Parameter(Position = 7)]
    [switch]$ProcessExistingFiles = $true,

    [Parameter(Position = 8)]
    [string[]]$ExcludeExtensions = @(".exe", ".dll"),

    [Parameter(Position = 9)]
    [string]$LogFile
)

function Write-Log {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"

    Write-Host $logMessage -ForegroundColor $Color

    if ($LogFile) {
        Add-Content -Path $LogFile -Value $logMessage
    }
}

function Get-FilesUpToDepth {
    param(
        [string]$Path,
        [int]$CurrentDepth = 0,
        [int]$MaxDepth,
        [string[]]$FileTypes
    )
    $files = @()

    if ($CurrentDepth -gt $MaxDepth) {
        return $files
    }

    try {
        $items = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue -Force
    } catch {
        return $files
    }

    foreach ($item in $items) {
        if ($item.PSIsContainer) {
            $files += Get-FilesUpToDepth -Path $item.FullName -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -FileTypes $FileTypes
        } else {
            foreach ($fileType in $FileTypes) {
                if ($item.Name -like $fileType) {
                    $files += $item
                    break
                }
            }
        }
    }
    return $files
}

$processedFiles = @{}

if (!(Test-Path -Path $DownloadDirectory)) {
    New-Item -ItemType Directory -Path $DownloadDirectory -Force | Out-Null
}

if (-not $ProcessExistingFiles) {
    Write-Log "[!] Skipping existing files..." -Color Yellow
    $existingFiles = Get-FilesUpToDepth -Path $SMBSharePath -MaxDepth $MaxDepth -FileTypes $FileTypes
    foreach ($file in $existingFiles) {
        $processedFiles[$file.FullName] = $true
    }
}

while ($true) {
    Write-Log "[+] Scanning SMB share..." -Color Cyan

    $files = Get-FilesUpToDepth -Path $SMBSharePath -MaxDepth $MaxDepth -FileTypes $FileTypes

    $newFilesFound = $false

    foreach ($file in $files) {
        if (-not $processedFiles.ContainsKey($file.FullName)) {
            $newFilesFound = $true

            Write-Log "[+] Processing new file: $($file.FullName)" -Color Green

            if ($file.Length -le ($MaxFileSizeMB * 1MB)) {
                try {
                    $relativePath = $file.FullName.Substring($SMBSharePath.Length).TrimStart('\')
                    $destinationPath = Join-Path -Path $DownloadDirectory -ChildPath $relativePath
                    $destinationDir = Split-Path -Path $destinationPath -Parent

                    if (!(Test-Path -Path $destinationDir)) {
                        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
                    }

                    # Copy file to DownloadDirectory
                    Copy-Item -Path $file.FullName -Destination $destinationPath -Force

                    $fileExtension = [System.IO.Path]::GetExtension($file.FullName)

                    # Check if file extension is in the exclusion list
                    if ($ExcludeExtensions -notcontains $fileExtension) {
                        # Search for sensitive strings
                        $foundStrings = Select-String -Path $file.FullName -Pattern $SensitiveStrings -SimpleMatch
                        if ($foundStrings) {
                            Write-Log "[!] Sensitive strings found in ${file.FullName}:" -Color Red
                            foreach ($match in $foundStrings) {
                                Write-Log "    Line $($match.LineNumber): $($match.Line.Trim())" -Color Red
                            }
                        }
                    } else {
                        Write-Log "[!] Skipping sensitive string search for file with excluded extension: $($file.FullName)" -Color Yellow
                    }

                    $processedFiles[$file.FullName] = $true

                } catch {
                    Write-Log "[!] Error processing file ${file.FullName}: $($_)" -Color Red
                }
            } else {
                Write-Log "[!] Skipping file due to size: $($file.FullName)" -Color Yellow
                $processedFiles[$file.FullName] = $true
            }
        }
    }

    if (-not $newFilesFound) {
        Write-Log "[!] No new files found." -Color Yellow
    }

    Start-Sleep -Seconds $IntervalInSeconds
}
