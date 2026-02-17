param(
    [Parameter(Mandatory=$true)]
    [string]$ArubaHost,

    [Parameter(Mandatory=$true)]
    [string]$ArubaUsername,

    [Parameter(Mandatory=$true)]
    [string]$ArubaPassword,

    [Parameter(Mandatory=$true)]
    [string]$ClearPassHost,

    [Parameter(Mandatory=$true)]
    [string]$ClearPassClientId,

    [Parameter(Mandatory=$true)]
    [string]$ClearPassClientSecret,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "correlated_clients.csv"
)

$ErrorActionPreference = "Stop"

class ArubaSession {
    [string]$BaseUrl
    [string]$Token
    [hashtable]$Headers
}

class ClearPassSession {
    [string]$BaseUrl
    [string]$Token
    [hashtable]$Headers
}

function Connect-Aruba {
    param(
        [string]$Host,
        [string]$Username,
        [string]$Password
    )

    $baseUrl = "https://$Host"
    $loginUrl = "$baseUrl/v1/api/login"

    $body = @{
        username = $Username
        password = $Password
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $loginUrl -Method Post -Body $body -ContentType "application/json" -SkipCertificateCheck
        $token = $response._global_result.HTTPCookie

        $headers = @{
            "Cookie" = "SESSION=$token"
            "Content-Type" = "application/json"
        }

        return [ArubaSession]@{
            BaseUrl = $baseUrl
            Token = $token
            Headers = $headers
        }
    }
    catch {
        throw "Failed to authenticate to Aruba: $_"
    }
}

function Connect-ClearPass {
    param(
        [string]$Host,
        [string]$ClientId,
        [string]$ClientSecret
    )

    $baseUrl = "https://$Host"
    $tokenUrl = "$baseUrl/api/oauth"

    $body = @{
        grant_type = "client_credentials"
        client_id = $ClientId
        client_secret = $ClientSecret
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/json" -SkipCertificateCheck
        $token = $response.access_token

        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }

        return [ClearPassSession]@{
            BaseUrl = $baseUrl
            Token = $token
            Headers = $headers
        }
    }
    catch {
        throw "Failed to authenticate to ClearPass: $_"
    }
}

function Get-ArubaUserTable {
    param([ArubaSession]$Session)

    $url = "$($Session.BaseUrl)/v1/api/show-command?command=show+user-table"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck
        return $response
    }
    catch {
        throw "Failed to fetch user table from Aruba: $_"
    }
}

function Get-ArubaAccessList {
    param([ArubaSession]$Session)

    $url = "$($Session.BaseUrl)/v1/api/show-command?command=show+ip+access-list"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck
        return $response
    }
    catch {
        throw "Failed to fetch access list from Aruba: $_"
    }
}

function Get-ClearPassServices {
    param([ClearPassSession]$Session)

    $url = "$($Session.BaseUrl)/api/service"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck
        return $response
    }
    catch {
        throw "Failed to fetch services from ClearPass: $_"
    }
}

function Get-ClearPassRoleMappings {
    param([ClearPassSession]$Session)

    $url = "$($Session.BaseUrl)/api/role-mapping"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck
        return $response
    }
    catch {
        throw "Failed to fetch role mappings from ClearPass: $_"
    }
}

function Get-ClearPassAuthenticationMethods {
    param([ClearPassSession]$Session)

    $url = "$($Session.BaseUrl)/api/authentication-method"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck
        return $response
    }
    catch {
        throw "Failed to fetch authentication methods from ClearPass: $_"
    }
}

function FindMatchingService {
    param(
        [array]$Services,
        [string]$AuthMethod
    )

    foreach ($service in $Services) {
        if ($service.auth_method -eq $AuthMethod -or $service.name -like "*$AuthMethod*") {
            return $service.name
        }
    }
    return "Unknown"
}

function FindMatchingRoleMapping {
    param(
        [array]$RoleMappings,
        [string]$Role
    )

    foreach ($mapping in $RoleMappings) {
        if ($mapping.name -eq $Role -or $mapping.roles -contains $Role) {
            return $mapping.name
        }
    }
    return "Unknown"
}

function FindAppliedFirewallRules {
    param(
        [array]$AccessLists,
        [string]$RoleOrVlan
    )

    $rules = @()

    if ($AccessLists -and $AccessLists.Count -gt 0) {
        foreach ($acl in $AccessLists) {
            if ($acl.name -like "*$RoleOrVlan*" -or $acl.role -eq $RoleOrVlan) {
                $rules += $acl.name
            }
        }
    }

    if ($rules.Count -eq 0) {
        return "Default"
    }

    return ($rules -join "; ")
}

Write-Host "Authenticating to Aruba..." -ForegroundColor Cyan
$arubaSession = Connect-Aruba -Host $ArubaHost -Username $ArubaUsername -Password $ArubaPassword
Write-Host "Connected to Aruba" -ForegroundColor Green

Write-Host "Authenticating to ClearPass..." -ForegroundColor Cyan
$clearPassSession = Connect-ClearPass -Host $ClearPassHost -ClientId $ClearPassClientId -ClientSecret $ClearPassClientSecret
Write-Host "Connected to ClearPass" -ForegroundColor Green

Write-Host "Fetching data from Aruba..." -ForegroundColor Cyan
$userTable = Get-ArubaUserTable -Session $arubaSession
$accessLists = Get-ArubaAccessList -Session $arubaSession
Write-Host "Retrieved $($userTable.Count) user sessions and $($accessLists.Count) access lists from Aruba" -ForegroundColor Green

Write-Host "Fetching data from ClearPass..." -ForegroundColor Cyan
$services = Get-ClearPassServices -Session $clearPassSession
$roleMappings = Get-ClearPassRoleMappings -Session $clearPassSession
$authMethods = Get-ClearPassAuthenticationMethods -Session $clearPassSession
Write-Host "Retrieved $($services.Count) services, $($roleMappings.Count) role mappings, and $($authMethods.Count) auth methods from ClearPass" -ForegroundColor Green

Write-Host "Correlating data..." -ForegroundColor Cyan

$correlatedData = @()

if ($userTable.user_table) {
    foreach ($client in $userTable.user_table) {
        $mac = $client.mac
        $ssid = $client["ssid-name"]
        $role = $client.role
        $authMethod = $client.auth_method
        $vlan = $client.vlan

        if (-not $mac) { continue }

        $serviceName = FindMatchingService -Services $services -AuthMethod $authMethod

        $roleMappingName = FindMatchingRoleMapping -RoleMappings $roleMappings -Role $role

        $firewallRules = FindAppliedFirewallRules -AccessLists $accessLists -RoleOrVlan ($role, $vlan)

        $authModel = "Unknown"
        if ($authMethods -and $authMethods.Count -gt 0) {
            foreach ($method in $authMethods) {
                if ($method.name -eq $authMethod -or $method.type -eq $authMethod) {
                    $authModel = $method.type
                    break
                }
            }
        }
        if ($authModel -eq "Unknown" -and $authMethod) {
            $authModel = $authMethod
        }

        $correlatedData += [PSCustomObject]@{
            "Client MAC" = $mac
            "SSID" = if ($ssid) { $ssid } else { "N/A" }
            "ClearPass Service" = $serviceName
            "Auth Model" = $authModel
            "Applied Aruba Firewall Rules" = $firewallRules
        }
    }
}

Write-Host "Exporting to CSV..." -ForegroundColor Cyan
$correlatedData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Data exported to $OutputFile" -ForegroundColor Green
Write-Host "Total clients processed: $($correlatedData.Count)" -ForegroundColor Cyan
