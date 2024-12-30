# Audit-AVD-Program-Usage.ps1
# Author: Ed Crotty
# Created: 2024-12-27
#
# Description:
# This PowerShell script analyzes program usage in Azure Virtual Desktop (AVD) environments by monitoring
# process creation events (Event ID 4688) in the Windows Security Log. It helps administrators track
# and audit which applications users are running in their AVD sessions.
#
# Usage:
# .\Audit-AVD-Program-Usage.ps1 [-ExportPath <path>] [-History <timespan>]
#
# Prerequisites:
# 1. Process Creation Auditing must be enabled via Group Policy:
#    - Computer Configuration > Windows Settings > Security Settings > 
#      Advanced Audit Policy Configuration > Detailed Tracking
#    - Enable "Audit Process Creation" for Success events
#    - Run 'gpupdate /force' after changes
#
# Event ID 4688 provides detailed tracking of process creation, helping identify:
# - What processes users are running
# - Command line arguments used
# - Process creation time and context

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Export results to CSV file")]
    [string]$ExportPath,
    
    [Parameter(HelpMessage="History duration to analyze (1h=1 hour, 1d=1 day, 3d=3 days, etc)")]
    [ValidateSet("1h", "1d", "3d", "7d", "14d", "30d", "all")]
    [string]$History = "1h",
    
    [Parameter(HelpMessage="Show help information")]
    [switch]$Help
)

# Show help if requested
if ($Help) {
    Write-Host "Usage: .\Audit-AVD-Program-Usage.ps1 [-ExportPath <path>] [-History <duration>] [-Help]"
    Write-Host "Monitors and analyzes process creation events (4688) with Microsoft Entra ID title standardization."
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -ExportPath    Optional. Path to export CSV results"
    Write-Host "  -History       Optional. Duration of history to analyze (1h=1 hour, 1d=1 day, 3d=3 days, etc). Default: 1h"
    Write-Host "  -Help          Show this help message"
    exit
}

# Function to ensure required modules are installed
function Ensure-ModuleInstalled {
    param (
        [string]$ModuleName,
        [string]$MinimumVersion = $null
    )
    
    if ($MinimumVersion) {
        $module = Get-Module -ListAvailable -Name $ModuleName | Where-Object { $_.Version -ge $MinimumVersion }
    } else {
        $module = Get-Module -ListAvailable -Name $ModuleName
    }
    
    if (-not $module) {
        Write-Host "Installing module: $ModuleName..."
        try {
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
            Import-Module -Name $ModuleName -Force
        } catch {
            Write-Error "Failed to install $ModuleName module: $_"
            exit 1
        }
    } else {
        Import-Module -Name $ModuleName -Force
    }
}

# Ensure Microsoft.Graph modules are installed
Ensure-ModuleInstalled -ModuleName "Microsoft.Graph.Authentication"
Ensure-ModuleInstalled -ModuleName "Microsoft.Graph.Users"
Ensure-ModuleInstalled -ModuleName "Microsoft.Graph.Identity.DirectoryManagement"

# Ensure fresh authentication for each script run
function Ensure-Authentication {
    # Disconnect any existing connections
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    } catch {
        # Ignore errors if no connection exists
    }

    # Force interactive login with explicit scopes
    Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "Directory.Read.All"
}

# Call authentication function early in the script
Ensure-Authentication

# Get organization domain after authentication
try {
    # First try to get the domain from the current user's UPN
    $currentUser = Get-MgUser -UserId (Get-MgContext).Account
    if ($currentUser.UserPrincipalName -match '@(.+)$') {
        $OrgDomain = $matches[1]
        Write-Verbose "Organization domain: $OrgDomain"
    } else {
        Write-Error "Could not determine organization domain from current user"
        exit 1
    }
} catch {
    Write-Error "Failed to get organization domain: $_"
    exit 1
}

# Define system processes and locations to exclude
$SystemPaths = @(
    "\\Windows\\",
    "\\Microsoft.NET\\",
    "\\WinSxS\\",
    "\\System32\\",
    "\\SysWOW64\\",
    "\\WindowsApps\\",
    "\\ProgramData\\Microsoft\\",
    "\\Windows Defender\\",
    "\\Microsoft\\Edge\\",
    "\\Microsoft\\EdgeUpdate\\",
    "\\Microsoft OneDrive\\",
    "\\AppData\\Local\\Microsoft\\",
    "\\AppData\\Local\\Temp\\"
)

$SystemProcessPatterns = @(
    # Windows core processes
    '^(svchost|RuntimeBroker|SearchHost|SearchIndexer|dwm|csrss|conhost|WmiPrvSE|spoolsv|lsass|services|winlogon|explorer|ShellExperienceHost|StartMenuExperienceHost|sihost|taskhostw|ctfmon|fontdrvhost|dllhost|backgroundTaskHost)\.exe$',
    
    # System utilities
    '^(vdsldr|vds|wsqmcons|hvsievaluator|cscript|wscript|msiexec|consent|smartscreen|CompPkgSrv|SgrmBroker|audiodg|dasHost|SystemSettings|UserOOBEBroker)\.exe$',
    
    # Windows services and updates
    '^(TiWorker|TrustedInstaller|wuauclt|sppsvc|MsMpEng|NisSrv|SecurityHealthService|uhssvc)\.exe$',
    
    # Temporary and generated executables
    '^[0-9a-f]{32}\.exe$',
    '\.tmp$'
)

# Combine patterns into a single regex for performance
$SystemProcessRegex = [regex]::new(($SystemProcessPatterns -join '|'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

# Function to test if a process is a user application
function Test-UserApplication {
    param (
        [string]$ProcessPath,
        [string]$ProcessName,
        [string]$CommandLine
    )
    
    Write-Verbose "Test-UserApplication: Testing process: $ProcessName"
    Write-Verbose "  Path: $ProcessPath"
    Write-Verbose "  Command: $CommandLine"
    
    # Skip empty process paths
    if ([string]::IsNullOrWhiteSpace($ProcessPath)) {
        Write-Verbose "  Result: Skipped (Empty process path)"
        return $false
    }

    # Skip core Windows system processes
    $SystemProcesses = @(
        'svchost.exe',
        'csrss.exe',
        'lsass.exe',
        'services.exe',
        'smss.exe',
        'wininit.exe',
        'system'
    )
    
    if ($SystemProcesses -contains $ProcessName.ToLower()) {
        Write-Verbose "  Result: Skipped (Core Windows process)"
        return $false
    }

    # Skip Windows system directories
    $SystemDirs = @(
        '\Windows\System32\',
        '\Windows\SysWOW64\',
        '\Windows\WinSxS\'
    )
    
    foreach ($dir in $SystemDirs) {
        if ($ProcessPath -like "*$dir*") {
            Write-Verbose "  Result: Skipped (System directory: $dir)"
            return $false
        }
    }

    # Accept anything in Program Files
    if ($ProcessPath -like "*\Program Files*") {
        Write-Verbose "  Result: Accepted (Program Files location)"
        return $true
    }

    # Accept Microsoft Store apps
    if ($ProcessPath -like "*\WindowsApps\*") {
        Write-Verbose "  Result: Accepted (Microsoft Store app)"
        return $true
    }

    # Accept user profile apps
    if ($ProcessPath -like "*\Users\*") {
        Write-Verbose "  Result: Accepted (User profile location)"
        return $true
    }

    # Accept anything that's not explicitly filtered
    if ($ProcessName -like "*.exe") {
        Write-Verbose "  Result: Accepted (Executable file)"
        return $true
    }

    Write-Verbose "  Result: Skipped (No matching criteria)"
    return $false
}

# Common program name mappings for cases where FileVersionInfo isn't available
$ProgramNameMappings = @{
    'msedgewebview2.exe' = 'Microsoft Edge WebView2'
    'msedge.exe'         = 'Microsoft Edge'
    'chrome.exe'         = 'Google Chrome'
    'Teams.exe'          = 'Microsoft Teams'
    'ms-teams.exe'       = 'Microsoft Teams'
    'OneDrive.exe'       = 'Microsoft OneDrive'
    'OUTLOOK.EXE'        = 'Microsoft Outlook'
    'acrotray.exe'       = 'Adobe Acrobat'
    'EXCEL.EXE'          = 'Microsoft Excel'
    'dbeaver.exe'        = 'DBeaver'
    'Ssms.exe'           = 'SQL Server Management Studio'
}

function Get-FriendlyProgramName {
    param (
        [string]$ProcessPath,
        [string]$ProcessName
    )
    
    # First try to get the product name from FileVersionInfo
    try {
        # Skip testing paths that are likely to cause access denied errors
        $systemPaths = @(
            'C:\\ProgramData\\',
            'C:\\Windows\\',
            'C:\\Program Files\\',
            'C:\\Program Files (x86)\\'
        )
        
        $isSystemPath = $systemPaths | Where-Object { $ProcessPath -like "$_*" }
        
        if (-not $isSystemPath) {
            if (Test-Path $ProcessPath -ErrorAction SilentlyContinue) {
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcessPath)
                if (-not [string]::IsNullOrWhiteSpace($versionInfo.ProductName)) {
                    return $versionInfo.ProductName
                }
            }
        }
    } catch {
        Write-Verbose "Could not get FileVersionInfo for $ProcessPath"
    }
    
    # Fallback to our mapping dictionary
    if ($ProgramNameMappings.ContainsKey($ProcessName)) {
        return $ProgramNameMappings[$ProcessName]
    }
    
    # If all else fails, return the process name without .exe
    return $ProcessName -replace '\.exe$',''
}

# Create cache for user information
$UserCache = @{}
$ProcessData = @()
$UserClassificationData = @{}
$UnknownPrograms = @{}
$ProcessCount = 0

# Pre-compile regex patterns for performance
$SystemAccountPattern = [regex]'^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$'

# Add function to check audit policy
function Check-AuditPolicy {
    Write-Host "`nChecking Audit Policy Settings..." -ForegroundColor Cyan
    $auditPolicy = auditpol /get /category:"Detailed Tracking"
    Write-Host $auditPolicy
    
    # Check if we can access the Security event log
    try {
        $secLog = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
        Write-Host "Successfully accessed Security event log" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Cannot access Security event log: $_" -ForegroundColor Yellow
    }
}

try {
    Check-AuditPolicy

    $endTime = Get-Date
    if ($History -eq "all") {
        Write-Host "`nRetrieving all available events..." -ForegroundColor Cyan
        $filter = @{
            LogName = 'Security'
            ID = 4688
        }
        Write-Host "No time filter applied - retrieving ALL historical events"
    } else {
        # Parse history duration
        $duration = switch -Regex ($History) {
            '^\d+h$' { [int]($History -replace 'h',''); $unit = 'hours'; break }
            '^\d+d$' { [int]($History -replace 'd',''); $unit = 'days'; break }
            default { 1; $unit = 'hours' } # Default to 1 hour if invalid
        }
        
        $startTime = if ($unit -eq 'hours') {
            $endTime.AddHours(-$duration)
        } else {
            $endTime.AddDays(-$duration)
        }
        Write-Host "`nRetrieving events from the last $duration $unit..." -ForegroundColor Cyan
        $filter = @{
            LogName = 'Security'
            ID = 4688
            StartTime = $startTime
            EndTime = $endTime
        }
        Write-Host "Time range: $($startTime) to $($endTime)"
    }
    
    Write-Host "Retrieving events..." -ForegroundColor Cyan
    $AllEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    Write-Host "Retrieved $($AllEvents.Count) events" -ForegroundColor Green

    # Process all events regardless of time range
    Write-Host "Processing events..." -ForegroundColor Cyan
    Write-Host "Debug: Starting event processing loop" -ForegroundColor Gray
    
    $userEventCount = 0
    $systemEventCount = 0
    $skippedEventCount = 0
    
    foreach ($Event in $AllEvents) {
        $ProcessCount++
        $EventXml = [xml]$Event.ToXml()
        
        # Extract process information
        $ProcessPath = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'
        $ProcessName = Split-Path $ProcessPath -Leaf
        $CommandLine = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
        $SubjectUserSid = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserSid' }).'#text'
        $TargetUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $SubjectDomainName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'
        
        Write-Verbose "Processing event $ProcessCount"
        Write-Verbose "  Process: $ProcessName"
        Write-Verbose "  Path: $ProcessPath"
        Write-Verbose "  User SID: $SubjectUserSid"
        Write-Verbose "  Domain: $SubjectDomainName"
        Write-Verbose "  Username: $TargetUserName"
        Write-Verbose "  Command: $CommandLine"
        
        # Extract username and clean it
        $Username = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $Username = $Username -replace '^.*\\', ''
        
        # Skip system accounts using robust pattern
        if ($Username -match $SystemAccountPattern) {
            Write-Verbose "Skipped system account: $Username"
            $systemEventCount++
            continue
        }
        
        # Add domain information to the process data
        $ProcessInfo = [PSCustomObject]@{
            Timestamp     = $Event.TimeCreated
            Username      = $Username
            Domain        = $Domain
            ProcessName   = $ProcessName
            CommandLine   = $CommandLine
            Department   = $userInfo.UserClass
            FriendlyName = Get-FriendlyProgramName -ProcessPath $ProcessPath -ProcessName $ProcessName
            LogonType    = $LogonType
        }
        
        Write-Verbose "  Processed Username: $Username"
        
        # Skip empty usernames
        if ([string]::IsNullOrWhiteSpace($Username)) {
            Write-Verbose "  Skipped empty username"
            $systemEventCount++
            continue
        }
        
        
        # Check if it's a user application
        $isUserApp = Test-UserApplication -ProcessPath $ProcessPath -ProcessName $ProcessName -CommandLine $CommandLine
        Write-Verbose "  Is User Application: $isUserApp"
        
        if (-not $isUserApp) {
            if ($ProcessName.EndsWith('.exe')) {
                if (-not $UnknownPrograms.ContainsKey($ProcessName)) {
                    Write-Verbose "  Adding to Unknown Programs: $ProcessName"
                    $UnknownPrograms[$ProcessName] = $ProcessPath
                }
            }
            $skippedEventCount++
            continue
        }
        
        # If we got here, it's a user application
        $userEventCount++
        Write-Verbose "  Processing user application: $ProcessName for user $Username"
        
        # Get user info from cache, but don't skip if not found
        $userInfo = $UserCache[$Username]
        if (-not $userInfo) {
            Write-Verbose "  No cached user info for: $Username"
            $userInfo = @{
                JobTitle = "Unknown"
                Department = "Unknown"
            }
        }
        
        # Update user classification data
        if (-not $UserClassificationData.ContainsKey($Username)) {
            Write-Verbose "  Creating new user classification data for: $Username"
            $UserClassificationData[$Username] = @{
                Username = $Username
                JobTitle = $userInfo.JobTitle
                Department = $userInfo.Department
                LastSeen = $Event.TimeCreated
                ProcessCount = 0
                Programs = [System.Collections.Generic.HashSet[string]]::new()
            }
        }
        
        $userData = $UserClassificationData[$Username]
        $userData.ProcessCount++
        [void]$userData.Programs.Add($ProcessName)
        if ($Event.TimeCreated -gt $userData.LastSeen) {
            $userData.LastSeen = $Event.TimeCreated
        }
        
        # Add to process data
        $ProcessInfo = [PSCustomObject]@{
            Timestamp     = $Event.TimeCreated
            Username      = $Username
            ProcessName   = $ProcessName
            CommandLine   = $CommandLine
            Department   = $userInfo.UserClass
            FriendlyName = Get-FriendlyProgramName -ProcessPath $ProcessPath -ProcessName $ProcessName
        }

        $ProcessData += $ProcessInfo
        Write-Verbose "  Added to ProcessData: $ProcessName"
    }

    Write-Host "`nProcessing Summary:" -ForegroundColor Cyan
    Write-Host "Total processes examined: $ProcessCount"
    Write-Host "User events found: $userEventCount"
    Write-Host "System events skipped: $systemEventCount"
    Write-Host "Other events skipped: $skippedEventCount"
    Write-Host "User applications found: $($ProcessData.Count)"
    Write-Host "Unknown programs found: $($UnknownPrograms.Count)"
} catch {
    Write-Host "Error retrieving events: $_" -ForegroundColor Red
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Host "No events found in the specified time range. This might indicate:"
        Write-Host "1. Process Creation Auditing is not enabled"
        Write-Host "2. The Security log has been cleared"
        Write-Host "3. No processes were created in the specified time range"
    }
    exit 1
}

# Get unique usernames from events for bulk processing
Write-Host "Processing unique users..." -ForegroundColor Cyan
$UniqueUsers = $AllEvents | ForEach-Object {
    $EventXml = [xml]$_.ToXml()
    
    # Extract username from SubjectUserName field
    $Username = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    
    # Clean username by removing domain prefix
    $cleanUsername = $Username -replace '^.*\\', ''
    
    # Skip only actual system accounts
    if ($cleanUsername -match $SystemAccountPattern) {
        Write-Verbose "Skipping system account: $cleanUsername"
        return
    }
    
    if (-not [string]::IsNullOrWhiteSpace($cleanUsername)) {
        Write-Verbose "Found user: $cleanUsername"
        $cleanUsername
    }
} | Select-Object -Unique

Write-Host "Found $($UniqueUsers.Count) unique users" -ForegroundColor Cyan

# Bulk process user information
Write-Host "Retrieving user information from Entra ID..." -ForegroundColor Cyan
$UserCache = @{}
$foundUsers = 0

foreach ($username in $UniqueUsers) {
    try {
        Write-Host "Looking up user: $username" -ForegroundColor Yellow
        # Skip system accounts and machine accounts
        if ($username -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$' -or $username.EndsWith('$')) {
            Write-Host "  Skipping system/machine account" -ForegroundColor Gray
            $UserCache[$username] = @{
                JobTitle = "System Account"
                UserClass = "System"
                Department = "System"
            }
            continue
        }

        # Skip machine accounts earlier in processing
        if ($username.EndsWith('$')) {
            Write-Host "  Skipping machine account: $username" -ForegroundColor Gray
            $UserCache[$username] = @{
                JobTitle = "Machine Account"
                UserClass = "Machine"
                Department = "Machine"
            }
            continue
        }

        # Try exact UPN match first
        $upn = "$username@$OrgDomain"
        Write-Host "  Trying UPN: $upn" -ForegroundColor Gray
        $mgUser = Get-MgUser -UserId $upn -Property "id,displayName,jobTitle,department,userPrincipalName" -ErrorAction SilentlyContinue
        
        if (-not $mgUser) {
            # Try filter-based search if exact match fails
            Write-Host "  No exact match, trying filter search" -ForegroundColor Gray
            $filter = "startsWith(userPrincipalName, '$username')"
            Write-Host "  Filter: $filter" -ForegroundColor Gray
            $mgUser = Get-MgUser -Filter $filter -Property "id,displayName,jobTitle,department,userPrincipalName" -Top 1
        }
        
        if ($mgUser) {
            $foundUsers++
            Write-Host "  Found user: $($mgUser.UserPrincipalName)" -ForegroundColor Green
            Write-Host "    Display Name: $($mgUser.DisplayName)" -ForegroundColor Gray
            Write-Host "    Job Title: $($mgUser.JobTitle)" -ForegroundColor Gray
            Write-Host "    Department: $($mgUser.Department)" -ForegroundColor Gray
            
            $jobTitle = if ([string]::IsNullOrWhiteSpace($mgUser.JobTitle)) { 
                "No Title"
            } else { 
                $mgUser.JobTitle 
            }
            
            # Enhanced department retrieval with multiple fallback options
            $department = "Unclassified"
            
            # Get all relevant user properties in a single call
            $userDetails = Get-MgUser -UserId $mgUser.Id -Property `
                "department,companyName,officeLocation,onPremisesExtensionAttributes,jobTitle,mailNickname,mail,userPrincipalName,assignedLicenses"
            
            # Try primary department field
            if (-not [string]::IsNullOrWhiteSpace($userDetails.Department)) {
                $department = $userDetails.Department
            }
            # Try company name if department is empty
            elseif (-not [string]::IsNullOrWhiteSpace($userDetails.CompanyName)) {
                $department = $userDetails.CompanyName
            }
            # Try extension attributes
            else {
                $extProps = $userDetails.OnPremisesExtensionAttributes
                if ($extProps) {
                    # Check all extension attributes for department info
                    $dept = ($extProps.extensionAttribute1, $extProps.extensionAttribute2,
                            $extProps.extensionAttribute3, $extProps.extensionAttribute4,
                            $extProps.extensionAttribute5) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
                    
                    if ($dept) {
                        $department = $dept
                    }
                }
            }
            
            # Try office location if still unclassified
            if ($department -eq "Unclassified" -and -not [string]::IsNullOrWhiteSpace($userDetails.OfficeLocation)) {
                $department = $userDetails.OfficeLocation
            }
            
            # Try job title if still unclassified
            if ($department -eq "Unclassified" -and -not [string]::IsNullOrWhiteSpace($userDetails.JobTitle)) {
                $department = $userDetails.JobTitle
            }
            
            # Try mail nickname if still unclassified
            if ($department -eq "Unclassified" -and -not [string]::IsNullOrWhiteSpace($userDetails.MailNickname)) {
                $department = $userDetails.MailNickname
            }
            
            # Try to extract department from email domain
            if ($department -eq "Unclassified" -and -not [string]::IsNullOrWhiteSpace($userDetails.Mail)) {
                $domain = $userDetails.Mail.Split('@')[1]
                if (-not [string]::IsNullOrWhiteSpace($domain)) {
                    $department = $domain.Split('.')[0]
                }
            }
            
            # Try to get department from group memberships
            if ($department -eq "Unclassified") {
                try {
                    $groups = Get-MgUserMemberOf -UserId $mgUser.Id -All
                    $departmentGroup = $groups | Where-Object { 
                        $_.DisplayName -match 'Department|Team|Group|Division' 
                    } | Select-Object -First 1
                    
                    if ($departmentGroup) {
                        $department = $departmentGroup.DisplayName
                    }
                } catch {
                    Write-Verbose "Failed to retrieve group memberships for department info"
                }
            }
            
            # Try to get department from license SKUs
            if ($department -eq "Unclassified" -and $userDetails.AssignedLicenses.Count -gt 0) {
                $license = $userDetails.AssignedLicenses[0].SkuId
                if (-not [string]::IsNullOrWhiteSpace($license)) {
                    $department = "License-$license"
                }
            }
            
            Write-Host "    Using department: $department" -ForegroundColor Gray
            
            # Log the source of the department information
            $source = switch ($department) {
                { $_ -eq $userDetails.Department } { "Primary Department Field" }
                { $_ -eq $userDetails.CompanyName } { "Company Name Field" }
                { $_ -in ($extProps.extensionAttribute1, $extProps.extensionAttribute2,
                        $extProps.extensionAttribute3, $extProps.extensionAttribute4,
                        $extProps.extensionAttribute5) } { "Extension Attribute" }
                { $_ -eq $userDetails.OfficeLocation } { "Office Location" }
                { $_ -eq $userDetails.JobTitle } { "Job Title" }
                { $_ -eq $userDetails.MailNickname } { "Mail Nickname" }
                { $_ -eq ($userDetails.Mail.Split('@')[1].Split('.')[0]) } { "Email Domain" }
                { $_ -match '^License-' } { "License SKU" }
                default { "Default (Unclassified)" }
            }
            
            Write-Verbose "    Department source: $source"
            
            $UserCache[$username] = @{
                JobTitle = $jobTitle
                UserClass = $department
                Department = $department
                DepartmentSource = $source
            }
        } else {
            Write-Host "  No user found in Entra ID" -ForegroundColor Red
            $UserCache[$username] = @{
                JobTitle = "Unknown"
                UserClass = "Unknown"
                Department = "Unknown"
            }
        }
    } catch {
        Write-Host "  Error looking up user: $_" -ForegroundColor Red
        $UserCache[$username] = @{
            JobTitle = "Error"
            UserClass = "Unknown"
            Department = "Unknown"
        }
    }
}

Write-Host "Found $foundUsers users in Entra ID" -ForegroundColor Cyan

# Create program usage summary
$ProgramUsageSummary = $ProcessData | Group-Object ProcessName | ForEach-Object {
    $users = $_.Group | Select-Object -ExpandProperty Username -Unique | Sort-Object
    $departments = $users | ForEach-Object { $UserCache[$_].Department } | Select-Object -Unique | Sort-Object
    [PSCustomObject]@{
        'User'          = ($users -join ', ')
        'Program Name'  = $_.Name
        'Friendly Name' = ($_.Group | Select-Object -ExpandProperty FriendlyName -First 1)
        'Department'    = ($departments -join ', ')
        'Times Run'     = $_.Count
        'Last Run'      = ($_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp.ToString('MM/dd/yyyy h:mm:ss tt')
    }
} | Sort-Object 'Program Name'

# Create user classification summary
$UserClassificationSummary = $ProcessData | Group-Object Username | ForEach-Object {
    [PSCustomObject]@{
        'Username'      = $_.Name
        'Department'    = ($_.Group | Select-Object -ExpandProperty Department -First 1)
        'Programs Used' = ($_.Group | Select-Object -ExpandProperty ProcessName -Unique)
        'Times Run'     = $_.Count
        'Last Run'      = ($_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp.ToString('MM/dd/yyyy h:mm:ss tt')
    }
} | Sort-Object Username

# Display results to console
Write-Host "`nProgram Usage Summary:" -ForegroundColor Cyan
Write-Host "User applications found: $($ProcessData.Count)" -ForegroundColor Yellow
    $ProgramUsageSummary | Sort-Object 'Times Run' -Descending | Format-Table -Property @(
        @{Name='User'; Expression={$_.User}; Width=30},
        @{Name='Program Name'; Expression={$_.'Program Name'}; Width=25},
        @{Name='Friendly Name'; Expression={$_.'Friendly Name'}; Width=30},
        @{Name='Department'; Expression={$_.Department}; Width=20},
        @{Name='Times Run'; Expression={$_.'Times Run'}; Width=10},
        @{Name='Last Run'; Expression={$_.'Last Run'}; Width=20}
    ) -Wrap

# Display results to console
Write-Host "`nUser Classification Summary:" -ForegroundColor Cyan
Write-Host "User applications found: $($UserClassificationSummary.Count)" -ForegroundColor Yellow
    $UserClassificationSummary | Sort-Object 'Times Run' -Descending | Format-Table -Property @(
        @{Name='Username'; Expression={$_.Username}; Width=20},
        @{Name='Department'; Expression={$_.Department}; Width=20},
        @{Name='Programs Used'; Expression={$_.'Programs Used'}; Width=40},
        @{Name='Times Run'; Expression={$_.'Times Run'}; Width=10},
        @{Name='Last Run'; Expression={$_.'Last Run'}; Width=20}
    ) -Wrap

# After processing, show unknown programs with full paths
if ($UnknownPrograms.Count -gt 0) {
    Write-Host "`nPotential user applications not categorized:" -ForegroundColor Yellow
    
    # Convert unknown programs to simple format with just name and friendly name
    $UnknownProgramsSummary = $UnknownPrograms.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            'Program Name'  = $_.Key
            'Friendly Name' = Get-FriendlyProgramName -ProcessPath $_.Value -ProcessName $_.Key
        }
    } | Sort-Object 'Program Name'

    $UnknownProgramsSummary | Format-Table -Property @(
        'Program Name',
        'Friendly Name'
    ) -AutoSize
}

# Export to CSV if path provided
if ($ExportPath) {
    try {
        # Ensure path ends with a backslash
        $basePath = $ExportPath.TrimEnd('\') + '\'
        
        # Get current date for filenames
        $dateStamp = Get-Date -Format "yyyyMMdd"
        
        # Create paths for both files
        $programPath = Join-Path $basePath "Programs-$dateStamp.csv"
        $userPath = Join-Path $basePath "Users-$dateStamp.csv"
        
        # Export both summaries
        $ProgramUsageSummary | Export-Csv -Path $programPath -NoTypeInformation
        $UserClassificationSummary | Export-Csv -Path $userPath -NoTypeInformation
        
        Write-Host "`nResults exported to:"
        Write-Host "Program summary: $programPath"
        Write-Host "User summary: $userPath"
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# Disconnect from Microsoft Graph when done
Disconnect-MgGraph
