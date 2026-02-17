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
    [switch]$SkipCertificateCheck = $true,

    [Parameter(Mandatory=$false)]
    [ValidateSet("v1", "rest")]
    [string]$ArubaApiVersion = "v1"
)

$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

class ArubaSession {
    [string]$BaseUrl
    [hashtable]$Headers
}

class ClearPassSession {
    [string]$BaseUrl
    [hashtable]$Headers
}

function Connect-Aruba {
    param(
        [string]$Host,
        [string]$Username,
        [string]$Password
    )

    $baseUrl = "https://$Host"

    try {
        $body = @{
            username = $Username
            password = $Password
        } | ConvertTo-Json

        $response = Invoke-RestMethod -Uri "$baseUrl/v1/api/login" -Method Post -Body $body -ContentType "application/json" -SkipCertificateCheck:$SkipCertificateCheck

        $cookie = ""
        if ($response.PSObject.Properties.Name.Contains("_global_result")) {
            $cookie = $response._global_result.HTTPCookie
        } elseif ($response.PSObject.Properties.Name.Contains("cookie")) {
            $cookie = $response.cookie
        }

        if (-not $cookie) {
            throw "Failed to extract session cookie from Aruba response"
        }

        $headers = @{
            "Cookie" = $cookie
            "Content-Type" = "application/json"
        }

        return [ArubaSession]@{
            BaseUrl = $baseUrl
            Headers = $headers
        }
    }
    catch {
        Write-Error "Failed to authenticate to Aruba: $($_.Exception.Message)"
        return $null
    }
}

function Connect-ClearPass {
    param(
        [string]$Host,
        [string]$ClientId,
        [string]$ClientSecret
    )

    $baseUrl = "https://$Host"

    try {
        $body = @{
            grant_type = "client_credentials"
            client_id = $ClientId
            client_secret = $ClientSecret
        } | ConvertTo-Json

        $response = Invoke-RestMethod -Uri "$baseUrl/api/oauth" -Method Post -Body $body -ContentType "application/json" -SkipCertificateCheck:$SkipCertificateCheck

        $token = $response.access_token

        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }

        return [ClearPassSession]@{
            BaseUrl = $baseUrl
            Headers = $headers
        }
    }
    catch {
        Write-Error "Failed to authenticate to ClearPass: $($_.Exception.Message)"
        return $null
    }
}

function Get-ArubaClients {
    param([ArubaSession]$Session)

    try {
        $response = Invoke-RestMethod -Uri "$($Session.BaseUrl)/v1/clients" -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        return @($response.clients)
    }
    catch {
        Write-Warning "Failed to fetch clients from Aruba: $($_.Exception.Message)"
        return @()
    }
}

function Get-ArubaAccessRules {
    param([ArubaSession]$Session)

    try {
        $response = Invoke-RestMethod -Uri "$($Session.BaseUrl)/v1/access-rules" -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        return @($response.access_rules)
    }
    catch {
        Write-Warning "Failed to fetch access rules from Aruba: $($_.Exception.Message)"
        return @()
    }
}

function Get-ArubaRoles {
    param([ArubaSession]$Session)

    try {
        $response = Invoke-RestMethod -Uri "$($Session.BaseUrl)/v1/roles" -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        return @($response.roles)
    }
    catch {
        Write-Warning "Failed to fetch roles from Aruba: $($_.Exception.Message)"
        return @()
    }
}

function Get-ClearPassServices {
    param([ClearPassSession]$Session)

    try {
        $response = Invoke-RestMethod -Uri "$($Session.BaseUrl)/api/service" -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        if ($response.PSObject.Properties.Name.Contains("_embedded")) {
            return @($response._embedded.services)
        } elseif ($response -is [array]) {
            return @($response)
        }
        return @()
    }
    catch {
        Write-Warning "Failed to fetch services from ClearPass: $($_.Exception.Message)"
        return @()
    }
}

function Get-ClearPassRoleMappings {
    param([ClearPassSession]$Session)

    try {
        $response = Invoke-RestMethod -Uri "$($Session.BaseUrl)/api/role-mapping" -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        if ($response.PSObject.Properties.Name.Contains("_embedded")) {
            return @($response._embedded.role_mappings)
        } elseif ($response -is [array]) {
            return @($response)
        }
        return @()
    }
    catch {
        Write-Warning "Failed to fetch role mappings from ClearPass: $($_.Exception.Message)"
        return @()
    }
}

function Get-ClearPassAuthenticationMethods {
    param([ClearPassSession]$Session)

    try {
        $response = Invoke-RestMethod -Uri "$($Session.BaseUrl)/api/authentication-method" -Method Get -Headers $Session.Headers -SkipCertificateCheck:$SkipCertificateCheck
        if ($response.PSObject.Properties.Name.Contains("_embedded")) {
            return @($response._embedded.authentication_methods)
        } elseif ($response -is [array]) {
            return @($response)
        }
        return @()
    }
    catch {
        Write-Warning "Failed to fetch authentication methods from ClearPass: $($_.Exception.Message)"
        return @()
    }
}

function FindMatchingService {
    param([array]$Services, [string]$AuthMethod)

    if (-not $Services -or $Services.Count -eq 0 -or -not $AuthMethod) { return "Unknown" }

    foreach ($service in $Services) {
        try {
            $svcName = $service.name ?? ""
            $svcAuth = $service.auth_method ?? ""
            if ($svcAuth -eq $AuthMethod -or $svcName -like "*$AuthMethod*") {
                return $svcName
            }
        }
        catch { continue }
    }
    return "Unknown"
}

function FindMatchingRoleMapping {
    param([array]$RoleMappings, [string]$Role)

    if (-not $RoleMappings -or $RoleMappings.Count -eq 0 -or -not $Role) { return "Unknown" }

    foreach ($mapping in $RoleMappings) {
        try {
            $mapName = $mapping.name ?? ""
            $mapRoles = $mapping.roles ?? @()
            if ($mapName -eq $Role) { return $mapName }
            if ($mapRoles -is [array] -and $mapRoles -contains $Role) { return $mapName }
            if ($mapRoles -eq $Role) { return $mapName }
        }
        catch { continue }
    }
    return "Unknown"
}

function FindAppliedFirewallRules {
    param([array]$AccessRules, [string]$Role)

    if (-not $AccessRules -or $AccessRules.Count -eq 0 -or -not $Role) { return "Default" }

    $rules = @()

    foreach ($rule in $AccessRules) {
        try {
            $ruleName = $rule.name ?? ""
            $ruleRoles = $rule.roles ?? @()
            if ($ruleName -like "*$Role*" -or $ruleRoles -contains $Role) {
                if ($ruleName -and -not ($rules -contains $ruleName)) {
                    $rules += $ruleName
                }
            }
        }
        catch { continue }
    }

    return if ($rules.Count -eq 0) { "Default" } else { ($rules -join "; ") }
}

Write-Host "Authenticating to Aruba..." -ForegroundColor Cyan
$arubaSession = Connect-Aruba -Host $ArubaHost -Username $ArubaUsername -Password $ArubaPassword
if (-not $arubaSession) { Write-Error "Aruba authentication failed"; exit 1 }
Write-Host "Connected to Aruba" -ForegroundColor Green

Write-Host "Authenticating to ClearPass..." -ForegroundColor Cyan
$clearPassSession = Connect-ClearPass -Host $ClearPassHost -ClientId $ClearPassClientId -ClientSecret $ClearPassClientSecret
if (-not $clearPassSession) { Write-Error "ClearPass authentication failed"; exit 1 }
Write-Host "Connected to ClearPass" -ForegroundColor Green

Write-Host "Fetching data from Aruba..." -ForegroundColor Cyan
$clients = Get-ArubaClients -Session $arubaSession
$accessRules = Get-ArubaAccessRules -Session $arubaSession
$roles = Get-ArubaRoles -Session $arubaSession

if ($null -eq $clients) { $clients = @() }
if ($null -eq $accessRules) { $accessRules = @() }
if ($null -eq $roles) { $roles = @() }

Write-Host "Retrieved $($clients.Count) clients, $($accessRules.Count) access rules, and $($roles.Count) roles from Aruba" -ForegroundColor Green

Write-Host "Fetching data from ClearPass..." -ForegroundColor Cyan
$services = Get-ClearPassServices -Session $clearPassSession
$roleMappings = Get-ClearPassRoleMappings -Session $clearPassSession
$authMethods = Get-ClearPassAuthenticationMethods -Session $clearPassSession

if ($null -eq $services) { $services = @() }
if ($null -eq $roleMappings) { $roleMappings = @() }
if ($null -eq $authMethods) { $authMethods = @() }

Write-Host "Retrieved $($services.Count) services, $($roleMappings.Count) role mappings, and $($authMethods.Count) auth methods from ClearPass" -ForegroundColor Green

Write-Host "Correlating data..." -ForegroundColor Cyan

$correlatedData = @()
$skippedClients = 0

foreach ($client in $clients) {
    $mac = $client.mac ?? ""
    $ssid = $client.ssid_name ?? $client.ssid ?? "N/A"
    $role = $client.role ?? ""
    $authMethod = $client.auth_method ?? ""
    $vlan = $client.vlan_id ?? $client.vlan ?? ""
    $ip = $client.ip ?? ""

    if (-not $mac) { $skippedClients++; continue }

    $serviceName = FindMatchingService -Services $services -AuthMethod $authMethod
    $roleMappingName = FindMatchingRoleMapping -RoleMappings $roleMappings -Role $role
    $firewallRules = FindAppliedFirewallRules -AccessRules $accessRules -Role $role

    $authModel = $authMethod
    if ($authMethods.Count -gt 0) {
        foreach ($method in $authMethods) {
            try {
                if (($method.name ?? "") -eq $authMethod) {
                    $authModel = $method.type ?? $authMethod
                    break
                }
            }
            catch { continue }
        }
    }

    $correlatedData += [PSCustomObject]@{
        "Client MAC" = $mac
        "IP Address" = $ip
        "SSID" = $ssid
        "Aruba Role" = $role
        "ClearPass Service" = $serviceName
        "ClearPass Role Mapping" = $roleMappingName
        "Auth Method" = $authMethod
        "Auth Model" = $authModel
        "VLAN" = $vlan
        "Applied Aruba Firewall Rules" = $firewallRules
    }
}

Write-Host "Exporting to CSV..." -ForegroundColor Cyan
$correlatedData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Data exported to $OutputFile" -ForegroundColor Green
Write-Host "Total clients processed: $($correlatedData.Count)" -ForegroundColor Cyan
if ($skippedClients -gt 0) {
    Write-Warning "Skipped $skippedClients clients (missing MAC address)"
}
