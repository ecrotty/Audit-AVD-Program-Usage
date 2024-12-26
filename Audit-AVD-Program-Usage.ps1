<#
BSD 3-Clause License

Copyright (c) 2024, Edward Crotty
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

<#
.SYNOPSIS
    Monitors and analyzes process creation events in Azure Virtual Desktop environments.

.DESCRIPTION
    This script analyzes Windows Security Event ID 4688 (Process Creation) events to track
    program usage in Azure Virtual Desktop (AVD) environments. It identifies user applications
    versus system processes and generates usage summaries by user.

    Key Features:
    - Tracks user program usage through Event ID 4688 analysis
    - Filters out system processes and utilities
    - Identifies common user applications (Office, dev tools, etc.)
    - Generates user-based program usage summaries
    - Optional CSV export of results

.NOTES
    Author: Edward Crotty
    Created: December 2023
    Version: 2.0
    
    Prerequisites:
    - Process Creation Auditing enabled (Event ID 4688)
    - Microsoft.Graph PowerShell module
    - Administrator rights to read Security event log
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
    
    [Parameter(HelpMessage="History duration to analyze")]
    [ValidateSet("1", "3", "7", "14", "30", "all")]
    [string]$History = "1",
    
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
    Write-Host "  -History       Optional. Duration of history to analyze (1, 3, 7, 14, 30, or 'all' days). Default: 1"
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
    
    Write-Verbose "Testing process: $ProcessName ($ProcessPath)"
    
    # Skip empty process paths
    if ([string]::IsNullOrWhiteSpace($ProcessPath)) {
        Write-Verbose "  Skipped: Empty process path"
        return $false
    }

    # Always include certain user applications
    $UserApps = @(
        'teams.exe',
        'outlook.exe',
        'excel.exe',
        'word.exe',
        'powerpnt.exe',
        'chrome.exe',
        'msedge.exe',
        'firefox.exe',
        'code.exe',
        'notepad.exe',
        'notepad++.exe',
        'mstsc.exe'
    )

    if ($UserApps -contains $ProcessName.ToLower()) {
        Write-Verbose "  Accepted: Known user application"
        return $true
    }

    # Skip system paths unless they're known user applications
    foreach ($path in $SystemPaths) {
        if ($ProcessPath -like "*$path*") {
            Write-Verbose "  Skipped: System path"
            return $false
        }
    }

    # Check for user interaction parameters
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
    
    # If it's not in system paths and has an .exe extension, consider it a user app
    if ($ProcessName -like "*.exe") {
        Write-Verbose "  Accepted: Non-system .exe file"
        return $true
    }

    Write-Verbose "  Skipped: No matching criteria"
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
        if (Test-Path $ProcessPath) {
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcessPath)
            if (-not [string]::IsNullOrWhiteSpace($versionInfo.ProductName)) {
                return $versionInfo.ProductName
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

# Pre-compile regex patterns for performance
$SystemAccountPattern = [regex]'(?:\$$|^SYSTEM$|admin|^NT)'

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
    } else {
        $days = [int]$History
        $startTime = $endTime.AddDays(-$days)
        Write-Host "`nRetrieving events from the last $days day(s)..." -ForegroundColor Cyan
        $filter = @{
            LogName = 'Security'
            ID = 4688
            StartTime = $startTime
            EndTime = $endTime
        }
        Write-Host "Time range: $($startTime) to $($endTime)"
    }
    
    $AllEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    Write-Host "Retrieved $($AllEvents.Count) events" -ForegroundColor Green
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
    
    # Get user info from cache, but don't skip if not found
    $userInfo = $UserCache[$username]
    if (-not $userInfo) {
        $userInfo = @{
            JobTitle = "Unknown"
            UserClass = "Unknown"
        }
    }
    
    Write-Verbose "Processing $ProcessName for user $username ($($userInfo.UserClass))"
    
    # Update user classification data
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
        FriendlyName  = Get-FriendlyProgramName -ProcessPath $ProcessPath -ProcessName $ProcessName
    }

    $ProcessData += $ProcessInfo
}

Write-Host "`nProcessing Summary:" -ForegroundColor Cyan
Write-Host "Total processes examined: $ProcessCount"
Write-Host "User applications found: $UserAppCount"

# Get unique usernames from events for bulk processing
Write-Host "Processing unique users..." -ForegroundColor Cyan
$UniqueUsers = $AllEvents | ForEach-Object {
    $username = ([xml]$_.ToXml()).Event.EventData.Data | 
    Where-Object {$_.Name -eq "SubjectUserName"} | 
    Select-Object -ExpandProperty '#text'
    if (-not ($username -match $SystemAccountPattern)) {
        # Extract username without domain and clean it
        $cleanUsername = $username -replace '^.*\\', ''
        if (-not [string]::IsNullOrWhiteSpace($cleanUsername)) {
            Write-Verbose "Found user: $cleanUsername"
            $cleanUsername
        }
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
        # Skip system accounts
        if ($username -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
            Write-Host "  Skipping system account" -ForegroundColor Gray
            $UserCache[$username] = @{
                JobTitle = "System Account"
                UserClass = "System"
                Department = "System"
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
            
            $department = if ([string]::IsNullOrWhiteSpace($mgUser.Department)) {
                "No Department"
            } else {
                $mgUser.Department
            }
            
            Write-Host "    Using department as class: $department" -ForegroundColor Gray
            
            $UserCache[$username] = @{
                JobTitle = $jobTitle
                UserClass = $department
                Department = $department
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

# Create user classification summary
$UserSummary = $UniqueUsers | ForEach-Object {
    $username = $_
    $userInfo = $UserCache[$username]
    $programs = $ProcessData | Where-Object { $_.Username -eq $username } | 
                Select-Object -ExpandProperty ProcessName -Unique | Sort-Object

    [PSCustomObject]@{
        'Username'      = $username
        'Job Title'     = $userInfo.JobTitle
        'User Class'    = $userInfo.UserClass
        'Department'    = $userInfo.Department
        'Programs Used' = ($programs -join ', ')
        'Process Count' = ($ProcessData | Where-Object { $_.Username -eq $username }).Count
        'Last Active'   = ($ProcessData | Where-Object { $_.Username -eq $username } | 
                          Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
    }
} | Sort-Object Username

# Display results to console
Write-Host "`nUser Classification Summary:" -ForegroundColor Cyan
$UserSummary | Format-Table -AutoSize

# Group and summarize the process data
$SummaryData = $ProcessData | Group-Object ProcessName | ForEach-Object {
    # Get unique departments for this process
    $departments = $_.Group | Select-Object -ExpandProperty Username -Unique | ForEach-Object {
        $UserCache[$_].Department
    } | Sort-Object -Unique | Where-Object { $_ -ne "Unknown" }

    [PSCustomObject]@{
        'Program Name'    = $_.Name
        'Friendly Name'   = ($_.Group | Select-Object -ExpandProperty FriendlyName -First 1)
        'User Count'      = ($_.Group | Select-Object -ExpandProperty Username -Unique).Count
        'Departments'     = ($departments -join ', ')
        'Times Run'       = $_.Count
        'Last Run'        = ($_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
    }
} | Sort-Object 'Times Run' -Descending

# Display results to console
Write-Host "`nProgram Usage Summary:" -ForegroundColor Cyan
$SummaryData | Format-Table -AutoSize

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
