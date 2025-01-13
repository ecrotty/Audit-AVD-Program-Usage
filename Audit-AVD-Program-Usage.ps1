<#
.SYNOPSIS
    Audit-AVD-Program-Usage.ps1 - Monitors and analyzes process creation events (4688) with Microsoft Entra ID title standardization.

.DESCRIPTION
    This script retrieves and analyzes process creation events from Windows Event Logs, correlating them with user information from Microsoft Entra ID (formerly Azure AD). It provides insights into program usage and user activity within an Azure Virtual Desktop (AVD) environment.

.PARAMETER ExportPath
    Path to export CSV results. Creates two files:
    - Programs-YYYYMMDD.csv: Program usage summary
    - Users-YYYYMMDD.csv: User activity summary

.PARAMETER History
    Duration of history to analyze. Default: 1h
    Valid values: 1h, 1d, 3d, 7d, 14d, 30d, all

.PARAMETER Filter
    Optional. Enable filtering of system processes and paths.

.PARAMETER Help
    Shows the help message.

.PARAMETER UseCurrentUser
    Use current logged in user's account to run the script.

.NOTES
    Copyright (c) 2025 Ed Crotty
    Licensed under the BSD 3-Clause License
#>
[CmdletBinding()]
param(
    [Parameter(HelpMessage="Export results to CSV file")]
    [string]$ExportPath,
    
    [Parameter(HelpMessage="History duration to analyze (1h=1 hour, 1d=1 day, etc)")]
    [ValidateSet("1h", "1d", "3d", "7d", "14d", "30d", "all")]
    [string]$History = "1h",
    
    [Parameter(HelpMessage="Filter out system processes and paths")]
    [switch]$Filter,
    
    [Parameter(HelpMessage="Show help information")]
    [switch]$Help,
    
    [Parameter(HelpMessage="Use current logged in user's account to run the script")]
    [switch]$UseCurrentUser
)

# The built-in $VerbosePreference will be set to "Continue" automatically when -Verbose is used

# Unblock all .ps1 files in the script directory and subdirectories
Get-ChildItem -Path $PSScriptRoot -Recurse -Filter *.ps1 | ForEach-Object {
    if ((Get-Item $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue) -ne $null) {
        Unblock-File $_.FullName
        Write-Verbose "Unblocked file: $($_.FullName)"
    }
}

# Import modules
. "$PSScriptRoot\src\Config.ps1"
. "$PSScriptRoot\src\Utilities.ps1"
. "$PSScriptRoot\src\EventProcessing.ps1"
. "$PSScriptRoot\src\Reporting.ps1"

if ($Help) {
    @"
Audit-AVD-Program-Usage.ps1
Monitors and analyzes process creation events (4688) with Microsoft Entra ID title standardization.

SYNTAX
    .\Audit-AVD-Program-Usage.ps1 [flags]

FLAGS
    -ExportPath <string>
        Path to export CSV results. Creates two files:
        - Programs-YYYYMMDD.csv: Program usage summary
        - Users-YYYYMMDD.csv: User activity summary

    -History <string>
        Duration of history to analyze. Default: 1h
        Valid values:
          1h  = 1 hour
          1d  = 1 day
          3d  = 3 days
          7d  = 7 days
          14d = 14 days
          30d = 30 days
          all = All available history

    -Filter [switch]
        Optional. Enable filtering of system processes and paths.
        When enabled, excludes core Windows processes and system paths.
        Default: Disabled (shows all processes)

    -Help [switch]
        Shows this help message

EXAMPLES
    # Show all program usage for the last hour (default)
    .\Audit-AVD-Program-Usage.ps1

    # Show filtered program usage for the last hour
    .\Audit-AVD-Program-Usage.ps1 -Filter

    # Analyze last 24 hours and export all results
    .\Audit-AVD-Program-Usage.ps1 -History 1d -ExportPath C:\Reports

    # Analyze all available history with filtering
    .\Audit-AVD-Program-Usage.ps1 -History all -Filter
"@ | Write-Host
    exit
}

# Main execution
try {
    $initParams = @{}
    if ($UseCurrentUser) {
        $initParams['UseCurrentUser'] = $true
    }
    
    try {
        Initialize-MgConnection @initParams

        # Check for required permissions
        $requiredScopes = @("User.Read.All", "AuditLog.Read.All", "Directory.Read.All")
        $context = Get-MgContext
        $missingScopes = $requiredScopes | Where-Object { $context.Scopes -notcontains $_ }
        
        if ($missingScopes) {
            Write-Host "Missing required permissions: $($missingScopes -join ', ')" -ForegroundColor Red
            Write-Host "Please ensure you have the following Graph permissions:" -ForegroundColor Yellow
            $requiredScopes | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
            exit 1
        }

        # Test user lookup
        $testUser = Get-MgUser -Top 1 -Property "UserPrincipalName,Department"
        if ($testUser) {
            Write-Host "Successfully retrieved a user from Azure AD"
            Write-Host "Test User: $($testUser.UserPrincipalName)"
            Write-Host "Department: $($testUser.Department)"
        } else {
            Write-Host "Failed to retrieve a user from Azure AD" -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Host "Error during initialization: $_" -ForegroundColor Red
        exit 1
    }
    
    # Get events
    $endTime = Get-Date
    if ($History -eq "all") {
        $startTime = $null
        Write-Host "Retrieving all available events..."
    } else {
        $duration = switch -Regex ($History) {
            '^\d+h$' { [TimeSpan]::FromHours([int]($History -replace 'h','')) }
            '^\d+d$' { [TimeSpan]::FromDays([int]($History -replace 'd','')) }
            default { [TimeSpan]::FromHours(1) }
        }
        $startTime = $endTime - $duration
        Write-Host "Retrieving events from $startTime to $endTime..."
    }

    Write-Host "Verbose logging enabled for troubleshooting" -ForegroundColor Yellow
    $VerbosePreference = "Continue"
    
    # Verify admin rights
    $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) {
        Write-Error "This script requires Administrator privileges to access security events for all users. Please run as Administrator."
        exit 1
    }

    # Configure advanced audit policies
    Write-Host "Configuring audit policies..."
    $null = & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    $null = & auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    
    # Get events
    $events = Get-ProcessEvents -StartTime $startTime -EndTime $endTime
    $logonEvents = Get-LogonEvents -StartTime $startTime -EndTime $endTime
    
    # Build user sessions and process events
    $userSessions = Build-UserSessions -LogonEvents $logonEvents
    $processData = Process-Events -Events $events -UserSessions $userSessions -Filter:$Filter
    
    # Generate summaries
    $programSummary = Generate-ProgramSummary -ProcessData $processData
    $userSummary = Generate-UserSummary -ProcessData $processData
    
    # Output results
    Output-Results -ProgramSummary $programSummary -UserSummary $userSummary -TotalEvents $processData.Count
    
    # Export if requested
    if ($ExportPath) {
        Export-Results -ProgramSummary $programSummary -UserSummary $userSummary -ExportPath $ExportPath
    }
} catch {
    Write-Error "Error: $_"
    exit 1
} finally {
    Disconnect-MgGraph
}
