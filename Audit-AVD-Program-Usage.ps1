<#
.SYNOPSIS
    Monitors and analyzes process creation events in Azure Virtual Desktop environments with Microsoft Entra ID integration.

.DESCRIPTION
    This script monitors process creation events (Event ID 4688) in the Windows Security Log and correlates them
    with Microsoft Entra ID (formerly Azure AD) user information to provide insights into program usage patterns
    across different user roles. It includes performance optimizations through user information caching and
    intelligent filtering of system processes.

    Key features:
    - Process creation monitoring with system process filtering
    - Microsoft Entra ID integration for user role classification
    - User information caching for improved performance
    - Automated data summarization and grouping
    - CSV export capabilities

.PARAMETER ExportPath
    Optional path to export results as a CSV file. The export will contain summarized data including
    program names, user classes, execution counts, and last run timestamps.

.PARAMETER Help
    Shows detailed help information about the script usage.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1
    Runs the script with default settings, outputting summarized results to the console.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1 -ExportPath "C:\Logs\process_audit.csv"
    Runs the script and exports summarized results to the specified CSV file.

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

# Define system processes to exclude
$ExcludedProcesses = @(
    # System processes
    "svchost.exe",
    "RuntimeBroker.exe",
    "SearchHost.exe",
    "SearchIndexer.exe",
    "dwm.exe",
    "csrss.exe",
    "conhost.exe",
    "WmiPrvSE.exe",
    "spoolsv.exe",
    "lsass.exe",
    "services.exe",
    "winlogon.exe",
    "explorer.exe",
    "ShellExperienceHost.exe",
    "StartMenuExperienceHost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "fontdrvhost.exe",
    "dllhost.exe",
    "backgroundTaskHost.exe",
    
    # System utilities and background processes
    "vdsldr.exe",
    "vds.exe",
    "wsqmcons.exe",
    "hvsievaluator.exe",
    "cscript.exe",
    "wscript.exe",
    "msiexec.exe",
    "consent.exe",
    "SecurityHealthService.exe",
    "smartscreen.exe",
    "CompPkgSrv.exe",
    "SgrmBroker.exe",
    "audiodg.exe",
    "dasHost.exe",
    "SystemSettings.exe",
    "UserOOBEBroker.exe",
    "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe"
)

# Define patterns for user applications we want to track
$UserAppPatterns = @(
    # Microsoft Office Suite
    "excel.exe",
    "word.exe",
    "powerpnt.exe",
    "outlook.exe",
    "teams.exe",
    "onenote.exe",
    "msaccess.exe",
    "mspub.exe",
    "Teams.exe",              # Teams desktop client
    "Update.exe",             # Microsoft 365 Apps updater
    
    # Browsers
    "chrome.exe",             # Google Chrome
    "msedge.exe",            # Microsoft Edge
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    
    # Development Tools and IDEs
    "devenv.exe",            # Visual Studio
    "Code.exe",              # VS Code
    "ServiceHub.Host.Node.x86.exe", # VS Code Service
    "ServiceHub.IdentityHost.exe",  # VS Code Identity Service
    "git.exe",               # Git
    "gitextensions.exe",     # Git Extensions
    "GitHubDesktop.exe",     # GitHub Desktop
    "node.exe",              # Node.js
    "npm.exe",               # Node Package Manager
    "iisexpress.exe",        # IIS Express
    "java.exe",              # Java Runtime
    "javaw.exe",             # Java Window Runtime
    "pwsh.exe",              # PowerShell 7
    "sfdx.exe",              # Salesforce CLI
    
    # Database and Data Tools
    "Ssms.exe",              # SQL Server Management Studio
    "azuredatastudio.exe",   # Azure Data Studio
    "sqlcmd.exe",            # SQL Command Line
    "psql.exe",              # PostgreSQL CLI
    "snowsql.exe",           # Snowflake CLI
    "DiskPie.exe",           # PC Magazine DiskPie Pro
    
    # BI and Analytics Tools
    "PBIDesktop.exe",        # Power BI Desktop
    "RSHostingService.exe",  # Power BI Report Builder
    "Tableau.exe",           # Tableau
    "tableau.exe",           # Tableau (alternate)
    "TableauPrep.exe",       # Tableau Prep Builder
    
    # Statistical and Data Science
    "Rstudio.exe",           # RStudio
    "R.exe",                 # R Runtime
    "python.exe",            # Python
    "pythonw.exe",           # Python Window Runtime
    "jupyter-notebook.exe",  # Jupyter Notebook
    "jupyter-lab.exe",       # Jupyter Lab
    "anaconda-navigator.exe", # Anaconda Navigator
    
    # Azure and Cloud Tools
    "func.exe",              # Azure Functions Core Tools
    "az.exe",                # Azure CLI
    "AzureStorageEmulator.exe", # Azure Storage Emulator
    "StorageExplorer.exe",   # Azure Storage Explorer
    
    # Enterprise Tools
    "EA.exe",                # Enterprise Architect
    "CompareIt.exe",         # Compare It!
    "CozyrocSsisPlus.exe",   # COZYROC SSIS+
    
    # Remote Access and Network Tools
    "putty.exe",             # PuTTY
    "winscp.exe",            # WinSCP
    "asdm.exe",              # Cisco ASDM-IDM
    "TortoiseProc.exe",      # TortoiseSVN
    
    # File Management and Utilities
    "7zFM.exe",              # 7-Zip File Manager
    "7z.exe",                # 7-Zip Command Line
    "Acrobat.exe",           # Adobe Acrobat
    "AcroRd32.exe",          # Adobe Reader
    "notepad++.exe",         # Notepad++
    "OneDrive.exe",          # Microsoft OneDrive
    
    # Monitoring and Management
    "MonitoringHost.exe",    # Microsoft Monitoring Agent
    "TaegisAgent.exe",       # Taegis Agent
    "FSLogixApps.exe",       # Microsoft FSLogix Apps
    "IntuneManagementExtension.exe" # Microsoft Intune Management
)

# Create a cache for user information
$UserCache = @{}

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

# Function to get user class information
function Get-UserClassInfo {
    param (
        [string]$Username
    )
    
    # Remove domain prefix if present
    $username = $Username -replace '^.*\\', ''
    
    # Check if user is already in cache
    if ($UserCache.ContainsKey($username)) {
        return $UserCache[$username]
    }
    
    # If not in cache, lookup in Entra ID
    try {
        $mgUser = Get-MgUser -Filter "userPrincipalName eq '$username@$OrgDomain'" -Property "jobTitle"
        $userInfo = @{
            JobTitle = $mgUser.JobTitle
            UserClass = "Unknown"
        }
        
        # Map job title to user class
        if ($userInfo.JobTitle -and $TitleToClassMapping.ContainsKey($userInfo.JobTitle)) {
            $userInfo.UserClass = $TitleToClassMapping[$userInfo.JobTitle]
        }
        
        # Add to cache
        $UserCache[$username] = $userInfo
        return $userInfo
    } catch {
        Write-Verbose "Could not find Entra ID info for user: $Username"
        return @{
            JobTitle = $null
            UserClass = "Unknown"
        }
    }
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
    
    # Extract process name from NewProcessName
    $ProcessName = Split-Path -Leaf $EventXml.Event.EventData.Data[5].'#text'
    
    # Skip if process is in the excluded list
    if ($ExcludedProcesses -contains $ProcessName) {
        continue
    }
    
    # Skip if username ends with $ (system account) or is "SYSTEM"
    $username = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
    if ($username -match '\$$' -or $username -eq "SYSTEM") {
        continue
    }
    
    # Only include if it matches our user application patterns
    if ($UserAppPatterns -notcontains $ProcessName) {
        continue
    }
    
    $userInfo = Get-UserClassInfo -Username $username
    
    # Extract event details
    $ProcessInfo = [PSCustomObject]@{
        Timestamp     = $Event.TimeCreated
        Username      = $username
        ProcessName   = $ProcessName
        CommandLine   = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"}).'#text'
        JobTitle      = $userInfo.JobTitle
        UserClass     = $userInfo.UserClass
    }

    $ProcessData += $ProcessInfo
}

# Output results
if ($ProcessData.Count -eq 0) {
    Write-Warning "No process data found"
    exit
}

# Group and summarize the data
$SummaryData = $ProcessData | Group-Object ProcessName | ForEach-Object {
    $UserClasses = ($_.Group | Select-Object -ExpandProperty UserClass -Unique) -join ', '
    if ($UserClasses -eq 'Unknown') { $UserClasses = 'System Account' }
    
    [PSCustomObject]@{
        'Program Name'    = $_.Name
        'User Classes'    = $UserClasses
        'Times Run'       = $_.Count
        'Last Run'        = ($_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
    }
} | Sort-Object 'Times Run' -Descending

# Display results to console
$SummaryData | Format-Table -AutoSize

# Export to CSV if path provided
if ($ExportPath) {
    try {
        $SummaryData | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "Results exported to: $ExportPath"
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# Disconnect from Microsoft Graph when done
Disconnect-MgGraph