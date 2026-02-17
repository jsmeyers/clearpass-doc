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
    [string]$OutputFile = "correlated_clients.csv",

    [Parameter(Mandatory=$false)]
    [switch]$SkipCertificateCheck = $true
)

$ErrorActionPreference = "Stop"
$verbosePref = $VerbosePreference
$VerbosePreference = "Continue"

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
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        if ($null -eq $response -or -not $response.PSObject.Properties.Name.Contains("user_table")) {
            Write-Warning "No user_table found in Aruba response"
            return [PSCustomObject]@{ user_table = @() }
        }
        return $response
    }
    catch {
        Write-Error "Failed to fetch user table from Aruba: $($_.Exception.Message)"
        return [PSCustomObject]@{ user_table = @() }
    }
}

function Get-ArubaAccessList {
    param([ArubaSession]$Session)

    $url = "$($Session.BaseUrl)/v1/api/show-command?command=show+ip+access-list"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        if ($null -eq $response) {
            Write-Warning "No response from Aruba access list query"
            return @()
        }
        return @($response)
    }
    catch {
        Write-Error "Failed to fetch access list from Aruba: $($_.Exception.Message)"
        return @()
    }
}

function Get-ClearPassServices {
    param([ClearPassSession]$Session)

    $url = "$($Session.BaseUrl)/api/service"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        return @($response._embedded.services)
    }
    catch {
        Write-Error "Failed to fetch services from ClearPass: $($_.Exception.Message)"
        return @()
    }
}

function Get-ClearPassRoleMappings {
    param([ClearPassSession]$Session)

    $url = "$($Session.BaseUrl)/api/role-mapping"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        return @($response._embedded.role_mappings)
    }
    catch {
        Write-Error "Failed to fetch role mappings from ClearPass: $($_.Exception.Message)"
        return @()
    }
}

function Get-ClearPassAuthenticationMethods {
    param([ClearPassSession]$Session)

    $url = "$($Session.BaseUrl)/api/authentication-method"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        return @($response._embedded.authentication_methods)
    }
    catch {
        Write-Error "Failed to fetch authentication methods from ClearPass: $($_.Exception.Message)"
        return @()
    }
}

function FindMatchingService {
    param(
        [array]$Services,
        [string]$AuthMethod
    )

    if (-not $Services -or $Services.Count -eq 0) { return "Unknown" }
    if (-not $AuthMethod) { return "Unknown" }

    foreach ($service in $Services) {
        try {
            $svcName = $service.name ?? "Unknown"
            $svcAuth = $service.auth_method ?? ""
            if ($svcAuth -eq $AuthMethod -or $svcName -like "*$AuthMethod*") {
                return $svcName
            }
        }
        catch {
            continue
        }
    }
    return "Unknown"
}

function FindMatchingRoleMapping {
    param(
        [array]$RoleMappings,
        [string]$Role
    )

    if (-not $RoleMappings -or $RoleMappings.Count -eq 0) { return "Unknown" }
    if (-not $Role) { return "Unknown" }

    foreach ($mapping in $RoleMappings) {
        try {
            $mapName = $mapping.name ?? ""
            $mapRoles = $mapping.roles ?? @()
            if ($mapName -eq $Role) { return $mapName }
            if ($mapRoles -is [array] -and $mapRoles -contains $Role) { return $mapName }
            if ($mapRoles -eq $Role) { return $mapName }
        }
        catch {
            continue
        }
    }
    return "Unknown"
}

function FindAppliedFirewallRules {
    param(
        [array]$AccessLists,
        [string]$RoleOrVlan
    )

    if (-not $AccessLists -or $AccessLists.Count -eq 0) { return "Default" }
    if (-not $RoleOrVlan) { return "Default" }

    $rules = @()

    foreach ($acl in $AccessLists) {
        try {
            $aclName = $acl.name ?? ""
            $aclRole = $acl.role ?? ""
            if ($aclName -like "*$RoleOrVlan*" -or $aclRole -eq $RoleOrVlan) {
                if ($aclName -and -not ($rules -contains $aclName)) {
                    $rules += $aclName
                }
            }
        }
        catch {
            continue
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
$usersProcessed = @($userTable.user_table).Count
Write-Host "Retrieved $usersProcessed user sessions and $($accessLists.Count) access lists from Aruba" -ForegroundColor Green

Write-Host "Fetching data from ClearPass..." -ForegroundColor Cyan
$services = Get-ClearPassServices -Session $clearPassSession
$roleMappings = Get-ClearPassRoleMappings -Session $clearPassSession
$authMethods = Get-ClearPassAuthenticationMethods -Session $clearPassSession
Write-Host "Retrieved $($services.Count) services, $($roleMappings.Count) role mappings, and $($authMethods.Count) auth methods from ClearPass" -ForegroundColor Green

Write-Host "Correlating data..." -ForegroundColor Cyan

$correlatedData = @()
$skippedClients = 0

if ($userTable.user_table) {
    foreach ($client in $userTable.user_table) {
        $mac = $client.mac ?? ""
        $ssid = $client["ssid-name"] ?? ""
        $role = $client.role ?? ""
        $authMethod = $client.auth_method ?? ""
        $vlan = $client.vlan ?? ""

        if (-not $mac) { $skippedClients++; continue }

        $serviceName = FindMatchingService -Services $services -AuthMethod $authMethod

        $roleMappingName = FindMatchingRoleMapping -RoleMappings $roleMappings -Role $role

        $firewallRules = FindAppliedFirewallRules -AccessLists $accessLists -RoleOrVlan ($role, $vlan)

        $authModel = "Unknown"
        if ($authMethods -and $authMethods.Count -gt 0) {
            foreach ($method in $authMethods) {
                try {
                    $mName = $method.name ?? ""
                    $mType = $method.type ?? ""
                    if ($mName -eq $authMethod -or $mType -eq $authMethod) {
                        $authModel = $mType
                        break
                    }
                }
                catch {
                    continue
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
if ($skippedClients -gt 0) {
    Write-Host "Skipped $skippedClients clients (missing MAC address)" -ForegroundColor Yellow
}
