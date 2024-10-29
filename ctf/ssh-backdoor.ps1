$today = Get-Date -Format "yyyy_MM_dd__HH_mm_ss"
$currentUser = $env:USERNAME
$userProfile = "$env:USERPROFILE"
$sshDir = Join-Path $userProfile ".ssh"
$authKeysFile = Join-Path $sshDir "authorized_keys"
$adminAuthKeysFile = "C:\ProgramData\ssh\administrators_authorized_keys"
$sshdConfigFile = "C:\ProgramData\ssh\sshd_config"

$KEYS = @(
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJxVi/t1Cm4pc1ZZsvXLWF6ZxWiS/gLLWW63wLZOI9l3',
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC4cW0w7jAp1WiUN4QrVCD0W2IhkZo1Ixqc79PpLoz4zzTj3sSmB3HOk/2XO5v5Dp1oqNkL+DTzhtZAus/A1u0Sa0Ir5Y4OUEq0Kmo4mwanpcpGP5zoEnOGQWvsleM9vPowHXCWTsM7WPUoP34bR8l9sXgVYiQZzWRQqHFp+7nx5te706YV5velZYc1R6tESbawsU6vTphgJfb9KPIowLlz3DHUc/JWvbjnwu57ZKLbmpTbw+YS8b0n2hF941tT95fBcIl05WdZc2C/Nh7+kICyfWlObnmKGYnnrghM8NhKs1aJJ9KX4G0zWafPoePTDJLcALHxGyV27nrl5qghq/lUNBtp+6QR7WtsLUqCMJ+cNCiDyIUpD0WFEpv9Z5olDiRgFFMgeUTSK3aGM1B4OwXWh0WCp0Fs5tWyyI2Nv1hsZyxHEBZ03hjkp3QMnhxPpdp9bHErmSaqdPOJAVDVK7pDAuAgSPi78xwyEzEpBiWneUq3kCASKT0GPecE4fpI891r2RkD85XhPsATYcXn7PVLIID8kBG1dRYTSFSVkXqZii10GO6/vE8311Zhl/ZeuF5iOoRYixsAQEKlTofJsuKfka3G4Hngnq0YxPM8RKxCcFn+TVt+91Dq2j18xcunkYnmZ1WqMcKZSUt0uvEUja6rlevHfEP05AaR6Y0bGgwsVQ=='
)

Write-Host "===> Setting up SSH keys and configuration..." -ForegroundColor Green

# Step 1: Ensure the .ssh directory exists
if (-not (Test-Path -Path $sshDir)) {
    Write-Host "--> Creating .ssh directory for $currentUser" -ForegroundColor Blue
    New-Item -ItemType Directory -Path $sshDir | Out-Null
}

# Step 2: Ensure the authorized_keys file exists for the current user
if (Test-Path -Path $authKeysFile) {
    Write-Host "--> Backing up existing authorized_keys for $currentUser" -ForegroundColor Yellow
    Copy-Item -Path $authKeysFile -Destination "$authKeysFile.$today.backup"
    Write-Host "--> Backup created: $authKeysFile.$today.backup" -ForegroundColor Cyan
} else {
    Write-Host "--> Creating authorized_keys file for $currentUser" -ForegroundColor Blue
    New-Item -ItemType File -Path $authKeysFile | Out-Null
}

# Step 3: Add SSH keys to current user's authorized_keys file if not already present
foreach ($key in $KEYS) {
    if (-not (Select-String -Path $authKeysFile -Pattern ([Regex]::Escape($key)) -Quiet)) {
        Write-Host "--> Adding key to authorized_keys for $currentUser" -ForegroundColor Cyan
        Add-Content -Path $authKeysFile -Value $key
    }
}

# Step 4: Check if the user is an Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "===> User is an Administrator. Performing additional setup..." -ForegroundColor Green

    # Step 5: Enable PubkeyAuthentication in sshd_config if not already set
    if (-not (Select-String -Path $sshdConfigFile -Pattern '^PubkeyAuthentication yes' -Quiet)) {
        Write-Host "--> Enabling PubkeyAuthentication in sshd_config" -ForegroundColor Blue
        Copy-Item -Path $sshdConfigFile -Destination "$sshdConfigFile.$today.backup"
        Write-Host "--> Backup created: $sshdConfigFile.$today.backup" -ForegroundColor Cyan
        (Get-Content -Path $sshdConfigFile) -replace '^#?(PubkeyAuthentication)\s+\w+', 'PubkeyAuthentication yes' | Set-Content -Path $sshdConfigFile
    }

    # Step 6: Add keys to administrators_authorized_keys with restricted ACLs
    if (Test-Path -Path $adminAuthKeysFile) {
        Write-Host "--> Backing up existing administrators_authorized_keys" -ForegroundColor Yellow
        Copy-Item -Path $adminAuthKeysFile -Destination "$adminAuthKeysFile.$today.backup"
        Write-Host "--> Backup created: $adminAuthKeysFile.$today.backup" -ForegroundColor Cyan
    } else {
        Write-Host "--> Creating administrators_authorized_keys file" -ForegroundColor Blue
        New-Item -ItemType File -Path $adminAuthKeysFile | Out-Null
    }
    
    foreach ($key in $KEYS) {
        if (-not (Select-String -Path $adminAuthKeysFile -Pattern ([Regex]::Escape($key)) -Quiet)) {
            Write-Host "--> Adding key to administrators_authorized_keys" -ForegroundColor Cyan
            Add-Content -Path $adminAuthKeysFile -Value $key
        }
    }

    # Step 7: Set ACLs on administrators_authorized_keys
    Write-Host "--> Setting permissions on administrators_authorized_keys" -ForegroundColor Blue
    & icacls $adminAuthKeysFile /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null

    # Step 8: Add keys to all users' authorized_keys files
    Write-Host "===> Adding keys to all local user profiles" -ForegroundColor Green
    $users = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false -and $_.LocalPath -like "C:\Users\*" }
    foreach ($user in $users) {
        $userSshDir = Join-Path $user.LocalPath ".ssh"
        $userAuthKeysFile = Join-Path $userSshDir "authorized_keys"

        if (-not (Test-Path -Path $userSshDir)) {
            Write-Host "--> Creating .ssh directory for $($user.LocalPath)" -ForegroundColor Blue
            New-Item -ItemType Directory -Path $userSshDir | Out-Null
        }
        
        if (Test-Path -Path $userAuthKeysFile) {
            Write-Host "--> Backing up existing authorized_keys for $($user.LocalPath)" -ForegroundColor Yellow
            Copy-Item -Path $userAuthKeysFile -Destination "$userAuthKeysFile.$today.backup"
            Write-Host "--> Backup created: $userAuthKeysFile.$today.backup" -ForegroundColor Cyan
        } else {
            Write-Host "--> Creating authorized_keys file for $($user.LocalPath)" -ForegroundColor Blue
            New-Item -ItemType File -Path $userAuthKeysFile | Out-Null
        }

        foreach ($key in $KEYS) {
            if (-not (Select-String -Path $userAuthKeysFile -Pattern ([Regex]::Escape($key)) -Quiet)) {
                Write-Host "--> Adding key to authorized_keys for $($user.LocalPath)" -ForegroundColor Cyan
                Add-Content -Path $userAuthKeysFile -Value $key
            }
        }
    }

    # Restart the SSH service to apply changes if the user was an administrator
    Write-Host "===> Restarting SSH service to apply changes..." -ForegroundColor Green
    Restart-Service -Name sshd
}

Write-Host "===> SSH setup completed successfully." -ForegroundColor Green
