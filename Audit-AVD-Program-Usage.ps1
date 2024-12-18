<#
.SYNOPSIS
    Monitors and analyzes process creation events in Azure Virtual Desktop environments with Microsoft Entra ID integration.

.DESCRIPTION
    This script monitors process creation events (Event ID 4688) in the Windows Security Log and correlates them
    with Microsoft Entra ID (formerly Azure AD) user information to provide insights into program usage patterns
    across different user roles.

.PARAMETER ExportPath
    Optional path to export results as a CSV file.

.PARAMETER Help
    Shows detailed help information about the script usage.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1
    Runs the script with default settings, outputting results to the console.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1 -ExportPath "C:\Logs\process_audit.csv"
    Runs the script and exports results to the specified CSV file.

.NOTES
    File Name      : Audit-AVD-Program-Usage.ps1
    Author         : Ed Crotty (ecrotty@edcrotty.com)
    Prerequisite   : Process Creation Auditing must be enabled via Group Policy
    License        : BSD 3-Clause License
    Version        : 1.0.0
    Repository     : https://github.com/ecrotty/Audit-AVD-Program-Usage

.LINK
    https://github.com/ecrotty/Audit-AVD-Program-Usage
#>

# Event ID 4688 Monitoring Script
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

# Connect to Microsoft Graph
try {
    Connect-MgGraph -Scopes "User.Read.All"
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
    
    # Data roles
    "Data Architect"        = "Data Professional"
    "Data Engineer"         = "Data Professional"
    "Data Analyst"         = "Data Professional"
    
    # Engineering roles
    "Systems Engineer"      = "Engineer"
    "DevOps Engineer"       = "Engineer"
    "Cloud Engineer"        = "Engineer"
    
    # Admin roles
    "IT Admin"             = "Administrator"
    "System Administrator" = "Administrator"
    "Network Admin"        = "Administrator"
}

# Extract Event Log for Process Creation (Event ID 4688)
try {
    $Events = Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4688]]" -ErrorAction Stop
} catch {
    Write-Warning "No process creation events found or access denied. Ensure audit policy is enabled."
    Write-Warning $_.Exception.Message
    exit 1
}

# Process and extract details
$ProcessData = @()

foreach ($Event in $Events) {
    $EventXml = [xml]$Event.ToXml()
    
    # Extract event details
    $ProcessInfo = [PSCustomObject]@{
        Timestamp     = $Event.TimeCreated
        Username      = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
        ProcessName   = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq "NewProcessName"}).'#text'
        CommandLine   = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"}).'#text'
        JobTitle      = $null
        UserClass     = "Unknown"
    }

    # Lookup user job title in Microsoft Graph
    try {
        # Remove domain prefix if present
        $username = $ProcessInfo.Username -replace '^.*\\', ''
        
        $mgUser = Get-MgUser -Filter "userPrincipalName eq '$username@$((Get-MgOrganization).VerifiedDomains[0].Name)'" -Property "jobTitle"
        if ($mgUser) {
            $ProcessInfo.JobTitle = $mgUser.JobTitle
            
            # Map job title to user class
            if ($ProcessInfo.JobTitle -and $TitleToClassMapping.ContainsKey($ProcessInfo.JobTitle)) {
                $ProcessInfo.UserClass = $TitleToClassMapping[$ProcessInfo.JobTitle]
            }
        }
    } catch {
        Write-Verbose "Could not find Entra ID info for user: $($ProcessInfo.Username)"
    }

    $ProcessData += $ProcessInfo
}

# Output results
if ($ProcessData.Count -eq 0) {
    Write-Warning "No process data found"
    exit
}

# Display results to console
$ProcessData | Format-Table -AutoSize

# Export to CSV if path provided
if ($ExportPath) {
    try {
        $ProcessData | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "Results exported to: $ExportPath"
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# Disconnect from Microsoft Graph when done
Disconnect-MgGraph
