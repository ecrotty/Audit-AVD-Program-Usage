<#
.SYNOPSIS
    Monitors and analyzes process creation events in Azure Virtual Desktop environments with Microsoft Entra ID integration.

.DESCRIPTION
    This script monitors process creation events (Event ID 4688) in the Windows Security Log and correlates them
    with Microsoft Entra ID (formerly Azure AD) user information to provide insights into program usage patterns
    across different user roles. It includes sophisticated role classification, intelligent application detection,
    and performance optimizations through bulk processing and caching.

    Key features:
    - Advanced process monitoring with intelligent application detection
    - Sophisticated role classification with fuzzy matching
    - Bulk user information processing for improved performance
    - Comprehensive system process and path filtering
    - Detailed program and user classification summaries
    - Multiple CSV export formats
    - Unknown program logging for review
    - Progress indicators and detailed statistics
    - Performance optimizations through caching and pre-compiled patterns

.PARAMETER ExportPath
    Optional path to export results as CSV files. The script will create two files:
    - [ExportPath]-Programs.csv: Program usage summary with execution counts and user classes
    - [ExportPath]-Users.csv: User classification summary with program usage details

.PARAMETER Help
    Shows detailed help information about the script usage.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1
    Runs the script with default settings, outputting summarized results to the console.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1 -ExportPath "C:\Logs\audit_report.csv"
    Runs the script and exports both program and user summaries to CSV files:
    - C:\Logs\audit_report-Programs.csv: Contains program usage statistics
    - C:\Logs\audit_report-Users.csv: Contains user classification data

.NOTES
    File Name      : Audit-AVD-Program-Usage.ps1
    Author         : Ed Crotty (ecrotty@edcrotty.com)
    Prerequisite   : - Process Creation Auditing enabled via Group Policy
                    - Microsoft.Graph.Authentication module
                    - Microsoft.Graph.Users module
                    - Microsoft.Graph.Identity.DirectoryManagement module
                    - Microsoft Entra ID permissions: User.Read.All, Organization.Read.All
    License        : BSD 3-Clause License
    Version        : 1.0.0
    Repository     : https://github.com/ecrotty/Audit-AVD-Program-Usage

.LINK
    https://github.com/ecrotty/Audit-AVD-Program-Usage
#>

# Event ID 4688 Monitoring Script
# This script monitors process creation events (Event ID 4688) in the Windows Security Log
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
    
    [Parameter(HelpMessage="Show help information")]
    [switch]$Help
)

# Show help if requested
if ($Help) {
    Write-Host "Usage: .\Audit-AVD-Program-Usage.ps1 [-ExportPath <path>] [-Help]"
    Write-Host "Monitors and analyzes process creation events (4688) with Microsoft Entra ID title standardization."
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -ExportPath    Optional. Path to export CSV results"
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

# Connect to Microsoft Graph
try {
    Connect-MgGraph -Scopes "User.Read.All", "Organization.Read.All"
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Define job title-to-class mappings (adjust to match environment)
$TitleToClassMapping = @{
    # Development roles
    "Developer"             = "Developer"
    "Software Engineer"     = "Developer"
    "Senior Developer"      = "Developer"
    "Application Developer" = "Developer"
    ".NET Developer"        = "Developer"
    "Full Stack Developer"  = "Developer"
    "Salesforce Administrator Developer" = "Developer"
     
    # DevOps Roles
    "Azure Devops Engineer" = "DevOps"

    # Security Roles
    "Junior Security Analyst" = "Security"

    # Data roles
    "Data Architect"        = "Data Professional"
    "Data Engineer"         = "Data Professional"
    "Data Analyst"          = "Data Professional"
    "Data Design Architect" = "Data Professional"
    "Health Information Analyst" = "Data Professional"    
    "BI Developer"          = "Data Professional"
    "Principal Data Architect" = "Data Professional"
    "Lead Data Analyst"     = "Data Professional"
    "Data Vault Analyst"    = "Data Professional"
    "ETL Developer"         = "Data Professional"

    # SCRUM roles
    "Lead Scrum Master"     = "SCRUM Professional"

    # Engineering roles
    "Systems Engineer"      = "Engineer"
    "DevOps Engineer"       = "Engineer"
    "Cloud Engineer"        = "Engineer"

    # Consultant roles
    "Consultant"        = "Consultant"

    # Contractor roles
    "Contractor"            = "Contractor"

    # QA roles
    "QA"                    = "QA"
    "QA Engineer"           = "QA"
    
    # Admin roles
    "IT Admin"             = "IT"
    "System Administrator" = "IT"
    "Network Admin"        = "IT"  
    "Security Analyst"     = "IT"
    "Sr. Cloud Engineer"   = "IT"

    # Executive roles
    "Sr. Dr., Data Informatics" = "Executives"
    "Director, Analytics Insights" = "Executives"
    "Sr. Director, IT Operations" = "Executives"
    "Sr. Dr. Technology, ES" = "Executives"
}

# Define role keywords for fuzzy matching
$RoleKeywords = @{
    "Developer" = @(
        "Dev",
        "Developer",
        "Software",
        "Programmer",
        ".NET",
        "Full Stack",
        "Salesforce"
    )
    "DevOps" = @(
        "DevOps",
        "Platform Engineer",
        "Release Engineer"
    )
    "Security" = @(
        "Security",
        "InfoSec",
        "Cyber"
    )
    "Data Professional" = @(
        "Data",
        "Analytics",
        "BI ",
        "ETL",
        "Business Intelligence",
        "Informatics",
        "Information"
    )
    "SCRUM Professional" = @(
        "Scrum",
        "Agile",
        "Product Owner"
    )
    "Engineer" = @(
        "Engineer",
        "Engineering",
        "Systems"
    )
    "Consultant" = @(
        "Consultant",
        "Consulting"
    )
    "Contractor" = @(
        "Contractor",
        "Contract"
    )
    "QA" = @(
        "QA",
        "Quality",
        "Test",
        "Testing"
    )
    "IT" = @(
        "IT",
        "System Admin",
        "Network",
        "Support",
        "Infrastructure"
    )
    "Executives" = @(
        "Director",
        "Sr. Dr",
        "Chief",
        "VP",
        "Vice President",
        "Head of",
        "Senior Director"
    )
}

# Function to get the best matching role class
function Get-BestRoleMatch {
    param (
        [string]$JobTitle
    )
    
    if ([string]::IsNullOrWhiteSpace($JobTitle)) {
        return "Unknown"
    }
    
    # First try exact match from TitleToClassMapping
    if ($TitleToClassMapping.ContainsKey($JobTitle)) {
        return $TitleToClassMapping[$JobTitle]
    }
    
    # Normalize the job title
    $normalizedTitle = $JobTitle.ToUpper()
    $bestMatch = $null
    $bestMatchCount = 0
    
    foreach ($roleClass in $RoleKeywords.Keys) {
        $keywords = $RoleKeywords[$roleClass]
        $matchCount = 0
        
        foreach ($keyword in $keywords) {
            if ($normalizedTitle.Contains($keyword.ToUpper())) {
                $matchCount++
                
                # Give extra weight to exact role matches
                if ($roleClass -eq $TitleToClassMapping[$JobTitle]) {
                    $matchCount += 2
                }
            }
        }
        
        if ($matchCount -gt $bestMatchCount) {
            $bestMatch = $roleClass
            $bestMatchCount = $matchCount
        }
    }
    
    # If we found a match, return it
    if ($bestMatch) {
        return $bestMatch
    }
    
    # If no match found, try to extract role from similar titles
    foreach ($knownTitle in $TitleToClassMapping.Keys) {
        if ($normalizedTitle.Contains($knownTitle.ToUpper())) {
            return $TitleToClassMapping[$knownTitle]
        }
    }
    
    return "Other"
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

# Function to check if a process is likely a user application
function Test-UserApplication {
    param (
        [string]$ProcessPath,
        [string]$ProcessName,
        [string]$CommandLine
    )
    
    Write-Verbose "Checking process: $ProcessName ($ProcessPath)"
    
    # Skip system processes
    if ($ProcessName -match $SystemProcessRegex) {
        Write-Verbose "  Skipped: Matches system process pattern"
        return $false
    }
    
    # Skip processes from system paths
    foreach ($path in $SystemPaths) {
        if ($ProcessPath -like "*$path*") {
            Write-Verbose "  Skipped: In system path $path"
            return $false
        }
    }
    
    # Known user application paths
    if ($ProcessPath -match "\\Program Files( \(x86\))?\\") {
        Write-Verbose "  Accepted: In Program Files"
        return $true
    }
    
    # Skip temporary or randomly named executables
    if ($ProcessName -match '^\d+$' -or $ProcessName -match '^[0-9a-f]{8,}$') {
        Write-Verbose "  Skipped: Temporary or random name"
        return $false
    }
    
    # Additional heuristics for user applications
    $userAppIndicators = @(
        # Common program paths
        '\\Program Files',
        '\\Users\\[^\\]+\\AppData\\Local\\Programs\\',
        # Development tools
        'Visual Studio',
        '\\Python',
        '\\nodejs',
        # Common application vendors
        'Microsoft Office',
        'Adobe',
        'Google',
        'Mozilla',
        'Tableau',
        'Power BI'
    )
    
    foreach ($indicator in $userAppIndicators) {
        if ($ProcessPath -match $indicator) {
            Write-Verbose "  Accepted: Matches user app indicator: $indicator"
            return $true
        }
    }
    
    # Common user applications (fallback list)
    $commonUserApps = @(
        '^(excel|word|powerpnt|outlook|teams|chrome|msedge|firefox|code|notepad\+\+|putty|winscp|powershell_ise)\.exe$'
    )
    
    if ($ProcessName -match ($commonUserApps -join '|')) {
        Write-Verbose "  Accepted: Common user application"
        return $true
    }
    
    # If command line contains specific parameters that indicate user interaction
    $userInteractionParams = @(
        '--user-data-dir=',
        '--profile=',
        '-foreground',
        '-interactive',
        '/user:'
    )
    
    foreach ($param in $userInteractionParams) {
        if ($CommandLine -like "*$param*") {
            Write-Verbose "  Accepted: User interaction parameter found: $param"
            return $true
        }
    }
    
    Write-Verbose "  Skipped: No matching criteria"
    return $false
}

# Create cache for user information
$UserCache = @{}
$ProcessData = @()
$UserClassificationData = @{}

# Pre-compile regex patterns for performance
$SystemAccountPattern = [regex]'(?:\$$|^SYSTEM$|admin|^NT)'

# Get all events first and filter in memory
Write-Host "Retrieving events..." -ForegroundColor Cyan
$AllEvents = Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4688]]" -ErrorAction Stop

# Get unique usernames from events for bulk processing
Write-Host "Processing unique users..." -ForegroundColor Cyan
$UniqueUsers = $AllEvents | ForEach-Object {
    $username = ([xml]$_.ToXml()).Event.EventData.Data | 
    Where-Object {$_.Name -eq "SubjectUserName"} | 
    Select-Object -ExpandProperty '#text'
    if (-not ($username -match $SystemAccountPattern)) {
        # Extract username without domain and clean it
        $cleanUsername = $username -replace '^.*\\', ''
        if (-not [string]::IsNullOrEmpty($cleanUsername)) {
            Write-Verbose "Found user: $cleanUsername"
            $cleanUsername
        }
    }
} | Select-Object -Unique

Write-Host "Found $($UniqueUsers.Count) unique users" -ForegroundColor Cyan

# Bulk process user information
Write-Host "Retrieving user information from Entra ID..." -ForegroundColor Cyan
foreach ($username in $UniqueUsers) {
    try {
        Write-Verbose "Looking up user: $username"
        $filter = "startsWith(userPrincipalName, '$username')"
        $mgUser = Get-MgUser -Filter $filter -Property "jobTitle"
        if ($mgUser) {
            Write-Verbose "Found user $username with title: $($mgUser.JobTitle)"
            $UserCache[$username] = @{
                JobTitle = $mgUser.JobTitle
                UserClass = Get-BestRoleMatch -JobTitle $mgUser.JobTitle
            }
        } else {
            Write-Verbose "No exact match found for $username, trying UPN search"
            # Try searching with domain
            $mgUser = Get-MgUser -Filter "userPrincipalName eq '$username@$OrgDomain'" -Property "jobTitle"
            if ($mgUser) {
                Write-Verbose "Found user with domain: $username@$OrgDomain"
                $UserCache[$username] = @{
                    JobTitle = $mgUser.JobTitle
                    UserClass = Get-BestRoleMatch -JobTitle $mgUser.JobTitle
                }
            }
        }
    } catch {
        Write-Verbose "Error looking up user $username`: $_"
    }
}

Write-Host "Found $($UserCache.Count) users in Entra ID" -ForegroundColor Cyan

Write-Host "Processing events..." -ForegroundColor Cyan
$UnknownPrograms = [System.Collections.Generic.HashSet[string]]::new()
$ProcessCount = 0
$UserAppCount = 0

foreach ($Event in $AllEvents) {
    $ProcessCount++
    $EventXml = [xml]$Event.ToXml()
    
    # Extract process information
    $ProcessPath = $EventXml.Event.EventData.Data[5].'#text'
    $ProcessName = Split-Path -Leaf $ProcessPath
    $CommandLine = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"}).'#text'
    
    # Check if it's a user application
    if (-not (Test-UserApplication -ProcessPath $ProcessPath -ProcessName $ProcessName -CommandLine $CommandLine)) {
        if ($ProcessName.EndsWith('.exe')) {
            [void]$UnknownPrograms.Add("$ProcessName ($ProcessPath)")
        }
        continue
    }
    
    $UserAppCount++
    
    # Get username and clean it
    $username = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
    $username = $username -replace '^.*\\', ''
    
    # Skip system accounts
    if ($username -match $SystemAccountPattern) {
        Write-Verbose "Skipped system account: $username"
        continue
    }
    
    # Get cached user info
    $userInfo = $UserCache[$username]
    if (-not $userInfo) {
        Write-Verbose "No cached info for user: $username"
        continue
    }
    
    Write-Verbose "Processing $ProcessName for user $username ($($userInfo.UserClass))"
    
    # Skip if we couldn't get valid user info
    if ($userInfo.UserClass -eq "Unknown") {
        Write-Verbose "Skipping unknown user class: $username"
        continue
    }
    
    # Update user classification data using cached information
    if (-not $UserClassificationData.ContainsKey($username)) {
        $UserClassificationData[$username] = @{
            Username = $username
            JobTitle = $userInfo.JobTitle
            UserClass = $userInfo.UserClass
            LastSeen = $Event.TimeCreated
            ProcessCount = 0
            Programs = [System.Collections.Generic.HashSet[string]]::new()
        }
    }
    
    $userData = $UserClassificationData[$username]
    $userData.ProcessCount++
    [void]$userData.Programs.Add($ProcessName)
    if ($Event.TimeCreated -gt $userData.LastSeen) {
        $userData.LastSeen = $Event.TimeCreated
    }
    
    # Add to process data
    $ProcessInfo = [PSCustomObject]@{
        Timestamp     = $Event.TimeCreated
        Username      = $username
        ProcessName   = $ProcessName
        CommandLine   = $CommandLine
        JobTitle      = $userInfo.JobTitle
        UserClass     = $userInfo.UserClass
    }

    $ProcessData += $ProcessInfo
}

Write-Host "`nProcessing Summary:" -ForegroundColor Cyan
Write-Host "Total processes examined: $ProcessCount"
Write-Host "User applications found: $UserAppCount"

# Get organization domain
try {
    # First try to get the domain from the current user's UPN
    $currentUser = Get-MgUser -UserId (Get-MgContext).Account
    if ($currentUser.UserPrincipalName -match '@(.+)$') {
        $OrgDomain = $matches[1]
    } else {
        Write-Error "Could not determine organization domain from current user"
        exit 1
    }
} catch {
    Write-Error "Failed to get organization domain: $_"
    exit 1
}

# Output results
if ($ProcessData.Count -eq 0) {
    Write-Warning "No process data found"
    exit
}

# Create user classification summary
$UserSummary = $UserClassificationData.Values | ForEach-Object {
    [PSCustomObject]@{
        'Username'      = $_.Username
        'Job Title'     = $_.JobTitle
        'User Class'    = $_.UserClass
        'Programs Used' = ($_.Programs | Sort-Object) -join ', '
        'Process Count' = $_.ProcessCount
        'Last Active'   = $_.LastSeen
    }
} | Sort-Object Username

# Group and summarize the process data
$SummaryData = $ProcessData | Group-Object ProcessName | ForEach-Object {
    # Get unique user classes, excluding Unknown and Other
    $UserClasses = ($_.Group | Select-Object -ExpandProperty UserClass -Unique | 
                   Where-Object { $_ -notin @("Unknown", "Other") }) -join ', '
    
    # If no valid classes found, skip this process
    if ([string]::IsNullOrWhiteSpace($UserClasses)) {
        return
    }
    
    [PSCustomObject]@{
        'Program Name'    = $_.Name
        'User Classes'    = $UserClasses
        'Times Run'       = $_.Count
        'Last Run'        = ($_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
    }
} | Where-Object { $_ -ne $null } | Sort-Object 'Times Run' -Descending

# Display results to console
Write-Host "`nProgram Usage Summary:" -ForegroundColor Cyan
$SummaryData | Format-Table -AutoSize

Write-Host "`nUser Classification Summary:" -ForegroundColor Cyan
$UserSummary | Format-Table -AutoSize

# After processing, show unknown programs for review
if ($UnknownPrograms.Count -gt 0) {
    Write-Host "`nPotential user applications not categorized:" -ForegroundColor Yellow
    $UnknownPrograms | Sort-Object | ForEach-Object {
        Write-Host "  $_"
    }
}

# Export to CSV if path provided
if ($ExportPath) {
    try {
        # Get the base path without extension
        $basePath = [System.IO.Path]::GetDirectoryName($ExportPath)
        $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
        $extension = [System.IO.Path]::GetExtension($ExportPath)
        
        # Create paths for both files
        $programPath = Join-Path $basePath "$baseFileName-Programs$extension"
        $userPath = Join-Path $basePath "$baseFileName-Users$extension"
        
        # Export both summaries
        $SummaryData | Export-Csv -Path $programPath -NoTypeInformation
        $UserSummary | Export-Csv -Path $userPath -NoTypeInformation
        
        Write-Host "`nResults exported to:"
        Write-Host "Program summary: $programPath"
        Write-Host "User summary: $userPath"
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# Disconnect from Microsoft Graph when done
Disconnect-MgGraph
