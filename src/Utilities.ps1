# Utility functions for Audit-AVD-Program-Usage script

# Import the configuration
. "$PSScriptRoot\Config.ps1"

$script:OrgDomain = $null

function Initialize-MgConnection {
    [CmdletBinding()]
    param (
        [switch]$UseCurrentUser
    )

    if (Get-MgContext) {
        Write-Verbose "Already connected to Microsoft Graph"
        return $script:OrgDomain
    }

    foreach ($module in $Config.RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module -Name $module -Force
    }
    
    Write-Host "Connecting to Microsoft Graph..."
    try {
        $connectParams = @{
            Scopes = $Config.GraphScopes
            NoWelcome = $true
        }
        if ($UseCurrentUser) {
            Connect-MgGraph @connectParams -UseDeviceAuthentication
        } else {
            Connect-MgGraph @connectParams
        }
        
        # Verify permissions
        $context = Get-MgContext
        if (-not $context) {
            throw "Failed to get Graph context"
        }
        
        Write-Host ("Connected as: " + $context.Account)
        
        # Test access by getting current user
        $currentUser = Get-MgUser -UserId $context.Account -ErrorAction Stop
        if (-not $currentUser) {
            throw "Failed to get user information"
        }
        
        if ($currentUser.UserPrincipalName -match '@(.+)$') {
            $script:OrgDomain = $matches[1]
            Write-Host ("Successfully connected to organization: " + $script:OrgDomain)
            return $script:OrgDomain
        }
        throw "Could not determine organization domain"
    }
    catch {
        Write-Error ("Graph API Error: " + $_)
        Write-Host "Please ensure you have the following Graph permissions:"
        $Config.GraphScopes | ForEach-Object { Write-Host ("- " + $_) }
        exit 1
    }
}

function Test-UserApplication {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ProcessPath,
        [Parameter(Mandatory=$true)]
        [string]$ProcessName,
        [Parameter(Mandatory=$false)]
        [switch]$Filter
    )
    
    if ([string]::IsNullOrWhiteSpace($ProcessPath)) { return $true }
    
    if ($Filter) {
        if ($Config.SystemProcesses -contains $ProcessName.ToLower()) {
            return $false
        }
        
        foreach ($path in $Config.SystemPaths) {
            if ($ProcessPath -like ("*" + $path + "*")) {
                return $false
            }
        }
        
        foreach ($path in $Config.UserPaths) {
            if ($ProcessPath -like ("*" + $path + "*")) {
                return $true
            }
        }
    }
    
    # If filtering is disabled or no filters matched, include everything
    return $true
}

function Get-FriendlyProgramName {
    param (
        [string]$ProcessPath,
        [string]$ProcessName
    )
    
    if ($Config.CommonNames.ContainsKey($ProcessName)) { 
        return $Config.CommonNames[$ProcessName] 
    }
    
    if (-not [string]::IsNullOrEmpty($ProcessPath)) {
        try {
            $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcessPath)
            if (-not [string]::IsNullOrEmpty($info.ProductName)) { 
                return $info.ProductName 
            }
        } catch {
            $errorMessage = "Could not get version info for " + $ProcessPath + ". Error: " + $_.Exception.Message
            Write-Verbose $errorMessage
        }
    }
    
    return $ProcessName -replace '\.exe$',''
}

function Get-UserInfo {
    param ($Username)
    
    Write-Verbose "Getting user info for $Username in domain $script:OrgDomain"
    
    # Only exclude core system accounts
    if ($Username -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
        Write-Verbose "System account detected: $Username"
        return @{ Department = "System"; JobTitle = "System Account" }
    }
    
    # Machine accounts (ending in $) should be included but marked appropriately
    if ($Username.EndsWith('$')) {
        Write-Verbose "Machine account detected: $Username"
        return @{ Department = "Machine Account"; JobTitle = "Computer Account" }
    }
    
    try {
        Write-Verbose "Attempting to retrieve user info from Azure AD for $Username@$script:OrgDomain"
        $user = Get-MgUser -UserId ($Username + "@" + $script:OrgDomain) -Property "displayName,jobTitle,department" -ErrorAction Stop
        
        $department = if ($user.Department) { $user.Department } else { "Not Set in Azure AD" }
        $jobTitle = if ($user.JobTitle) { $user.JobTitle } else { "Not Set in Azure AD" }
        
        Write-Verbose "User info retrieved successfully. Department: $department, Job Title: $jobTitle"
        
        return @{
            Department = $department
            JobTitle = $jobTitle
        }
    }
    catch {
        $errorMessage = "User lookup failed for $Username@$script:OrgDomain: $_"
        Write-Verbose $errorMessage
        Write-Host $errorMessage -ForegroundColor Red
        return @{ Department = "Lookup Failed"; JobTitle = "Lookup Failed" }
    }
}

# No export needed for script files
