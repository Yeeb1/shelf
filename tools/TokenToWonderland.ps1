<#
.SYNOPSIS
    Request OAuth 2.0 tokens using a refresh token and client ID.

.DESCRIPTION
    This script accepts a domain, refresh token, and client ID as parameters
    and requests tokens (access token, refresh token, etc.) from the Microsoft
    identity platform. Optionally, you can store the tokens in a variable.

.PARAMETER domain
    The domain of the tenant (e.g., contoso.com).

.PARAMETER refreshToken
    The refresh token used to authenticate and request new tokens.

.PARAMETER clientId
    The client ID for the application to authenticate with.

.PARAMETER resource
    The resource URL (default: "https://graph.microsoft.com/").

.PARAMETER OutputColor
    The output color for messages (default: "White").

.PARAMETER PassTokens
    A switch to indicate whether to store the tokens in the `$tokens` variable.

.EXAMPLE
    .\TokenToWonderland.ps1 -domain "contoso.com" -refreshToken "your_refresh_token" -clientId "27922004-5251-4030-b22d-91ecd9a37ea4" -PassTokens
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$domain,

    [Parameter(Mandatory = $true)]
    [string]$refreshToken,

    [Parameter(Mandatory = $true)]
    [string]$clientId,

    [Parameter(Mandatory = $false)]
    [string]$resource = "https://graph.microsoft.com/",

    [Parameter(Mandatory = $false)]
    [ValidateSet('Yellow', 'Red', 'DarkGreen', 'DarkRed')]
    [string]$OutputColor = "White",

    [switch]$PassTokens
)

function Invoke-TokenToWonderland {
    param (
        [string]$Domain,
        [string]$RefreshToken,
        [string]$ClientID,
        [string]$Resource,
        [string]$OutputColor,
        [switch]$PassTokens
    )

    $TenantId = Get-TenantID -domain $Domain
    if (-not $TenantId) {
        Write-Host -ForegroundColor Red "Failed to retrieve Tenant ID for domain $Domain"
        return
    }

    $authUrl = "https://login.microsoftonline.com/$TenantId"
    $body = @{
        "resource" = $Resource
        "client_id" = $ClientID
        "grant_type" = "refresh_token"
        "refresh_token" = $RefreshToken
        "scope" = "openid"
    }

    try {
        $TokenResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$authUrl/oauth2/token" -Body $body
        if ($TokenResponse) {
            Write-Host -ForegroundColor $OutputColor "Access Token: $($TokenResponse.access_token)"
            Write-Host -ForegroundColor $OutputColor "Scope: $($TokenResponse.scope)"
            Write-Host -ForegroundColor $OutputColor "Expires In: $($TokenResponse.expires_in) seconds"

            if ($PassTokens) {
                $global:tokens = [pscustomobject]@{
                    token_type     = $TokenResponse.token_type
                    scope          = $TokenResponse.scope
                    expires_in     = $TokenResponse.expires_in
                    ext_expires_in = $TokenResponse.ext_expires_in
                    expires_on     = $TokenResponse.expires_on
                    not_before     = $TokenResponse.not_before
                    resource       = $TokenResponse.resource
                    access_token   = $TokenResponse.access_token
                    refresh_token  = $TokenResponse.refresh_token
                    foci           = $TokenResponse.foci
                    id_token       = $TokenResponse.id_token
                }

                Write-Host -ForegroundColor $OutputColor "Tokens stored in variable: `$tokens"
            }
        } else {
            Write-Host -ForegroundColor Red "No token response received. Check your input and try again."
        }
    } catch {
        Write-Host -ForegroundColor Red "Error encountered: $_"
    }
}

Invoke-TokenToWonderland -Domain $domain -RefreshToken $refreshToken -ClientID $clientId -Resource $resource -OutputColor $OutputColor -PassTokens:$PassTokens
