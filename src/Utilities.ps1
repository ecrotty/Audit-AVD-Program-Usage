# Utility functions for Audit-AVD-Program-Usage script

# Import the configuration
. "$PSScriptRoot\Config.ps1"

$script:OrgDomain = $null

function Initialize-MgConnection {
    [CmdletBinding()]
    param (
        [switch]$UseCurrentUser,
        [switch]$IsRemoteExecution
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
        if ($IsRemoteExecution) {
            Write-Verbose "Using remote execution authentication method"
            # Use Az module for non-interactive authentication
            if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
                Install-Module -Name Az.Accounts -Scope CurrentUser -Force -AllowClobber
            }
            Import-Module -Name Az.Accounts -Force

            # Connect to Azure using the managed identity
            Connect-AzAccount -Identity

            # Get an access token for Microsoft Graph
            $tokenResponse = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
            $secureToken = ConvertTo-SecureString $tokenResponse.Token -AsPlainText -Force
            Connect-MgGraph -AccessToken $secureToken
        }
        else {
            Write-Verbose "Using interactive authentication method"
            $connectParams = @{
                Scopes = $Config.GraphScopes
                NoWelcome = $true
            }
            if ($UseCurrentUser) {
                Connect-MgGraph @connectParams -UseDeviceAuthentication
            } else {
                Connect-MgGraph @connectParams
            }
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
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [switch]$Filter
    )
    
    if ([string]::IsNullOrWhiteSpace($ProcessPath)) { return $true }
    
    if ($Filter) {
        # Filter out system accounts
        if ($Username -eq "SYSTEM" -or $Username -eq "LOCAL SERVICE" -or $Username -eq "NETWORK SERVICE" -or $Username.EndsWith('$')) {
            return $false
        }

        # Filter out system processes
        if ($Config.SystemProcesses -contains $ProcessName.ToLower()) {
            return $false
        }
        
        # Filter out processes from system paths
        foreach ($path in $Config.SystemPaths) {
            if ($ProcessPath -like ("*" + $path + "*")) {
                return $false
            }
        }
        
        # Include processes from user paths
        foreach ($path in $Config.UserPaths) {
            if ($ProcessPath -like ("*" + $path + "*")) {
                return $true
            }
        }

        # Additional checks for system-run commands
        if ($ProcessPath -like "*\Windows\*" -or $ProcessPath -like "*\System32\*" -or $ProcessPath -like "*\SysWOW64\*") {
            return $false
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
        
        if ([string]::IsNullOrEmpty($script:OrgDomain)) {
            Write-Verbose "OrgDomain is not set. Attempting to retrieve it."
            $script:OrgDomain = Initialize-MgConnection
        }
        
        if ([string]::IsNullOrEmpty($Username) -or [string]::IsNullOrEmpty($script:OrgDomain)) {
            throw "Username or OrgDomain is empty. Username: '$Username', OrgDomain: '$script:OrgDomain'"
        }
        
        $userId = $Username + "@" + $script:OrgDomain
        Write-Verbose "Constructed user ID: $userId"
        
        $user = Get-MgUser -UserId $userId -Property "displayName,jobTitle,department" -ErrorAction Stop
        
        Write-Verbose "Raw user object: $($user | ConvertTo-Json -Depth 1)"
        
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
        
        Write-Verbose "Error details: $($_.Exception.Message)"
        Write-Verbose "Error stack trace: $($_.ScriptStackTrace)"
        
        return @{ Department = "Lookup Failed"; JobTitle = "Lookup Failed" }
    }
}

# No export needed for script files
