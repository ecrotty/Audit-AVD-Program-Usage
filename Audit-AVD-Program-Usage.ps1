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
    [switch]$UseCurrentUser,

    [Parameter(HelpMessage="List of remote servers to connect to, separated by commas")]
    [string]$RemoteServers,

    [Parameter(HelpMessage="Indicates if the script is running in remote execution mode")]
    [switch]$IsRemoteExecution,

    [Parameter(HelpMessage="Credentials for remote execution and Graph API")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
)

# Function to run the script on a remote server
function Invoke-RemoteScript {
    param (
        [string]$ComputerName,
        [hashtable]$ScriptParams
    )
    
    $scriptBlock = {
        param($ScriptPath, $Params)
        Set-Location (Split-Path $ScriptPath)
        $Params['IsRemoteExecution'] = $true
        & $ScriptPath @Params
    }

    $session = New-PSSession -ComputerName $ComputerName -Authentication Kerberos
    return Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $PSCommandPath, $ScriptParams
}

# Set VerbosePreference based on whether -Verbose is used
if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
    $VerbosePreference = "Continue"
} else {
    $VerbosePreference = "SilentlyContinue"
}

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

    -UseCurrentUser [switch]
        Use the current logged-in user's account to run the script

    -RemoteServers <string>
        Comma-separated list of remote servers to connect to and run the script

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

    # Run the script on remote servers
    .\Audit-AVD-Program-Usage.ps1 -RemoteServers "server1,server2,server3" -History 1d -ExportPath C:\RemoteReports
"@ | Write-Host
    exit
}

# Main execution
try {
    $initParams = @{}
    if ($UseCurrentUser) {
        $initParams['UseCurrentUser'] = $true
    }

    if ($RemoteServers) {
        Write-Host "Running script on remote servers: $RemoteServers" -ForegroundColor Cyan
        $servers = $RemoteServers -split ','
        $allResults = @()

        # Authenticate locally and get access token
        Write-Host "Authenticating locally..." -ForegroundColor Yellow
        
        # Ensure the Microsoft.Graph.Authentication module is imported
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        
        # Connect to Microsoft Graph
        Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "Directory.Read.All" -ErrorAction Stop
        $localContext = Get-MgContext
        if ($null -eq $localContext) {
            throw "Failed to get Microsoft Graph context after authentication"
        }
        Write-Verbose "Local context obtained. Attempting to retrieve access token..."

        # Try to get the access token using the context
        $accessToken = $null
        try {
            $accessToken = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.AcquireToken("https://graph.microsoft.com", $localContext.ClientId, [Microsoft.Identity.Client.AcquireTokenInteractiveParameters]::new()).ExecuteAsync().GetAwaiter().GetResult().AccessToken
        }
        catch {
            Write-Verbose "Failed to retrieve access token from context: $_"
        }

        Write-Verbose "Access token from context: $(if ($accessToken) { 'Retrieved' } else { 'Not found' })"

        # If still null or empty, try disconnecting and reconnecting
        if ([string]::IsNullOrEmpty($accessToken)) {
            Write-Verbose "Access token not available. Attempting to disconnect and reconnect..."
            Disconnect-MgGraph
            Start-Sleep -Seconds 2
            Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "Directory.Read.All" -ErrorAction Stop
            $localContext = Get-MgContext
            try {
                $accessToken = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.AcquireToken("https://graph.microsoft.com", $localContext.ClientId, [Microsoft.Identity.Client.AcquireTokenInteractiveParameters]::new()).ExecuteAsync().GetAwaiter().GetResult().AccessToken
            }
            catch {
                Write-Verbose "Failed to retrieve access token after reconnection: $_"
            }
        }

        if ([string]::IsNullOrEmpty($accessToken)) {
            throw "Access token is null or empty after multiple retrieval attempts"
        }
        Write-Verbose "Local authentication successful. Access Token: $($accessToken.Substring(0, 10))..."

        foreach ($server in $servers) {
            Write-Host "Processing remote server: $server" -ForegroundColor Yellow
            $remoteParams = @{
                ExportPath = $ExportPath
                History = $History
                Filter = $Filter
                UseCurrentUser = $UseCurrentUser
                IsRemoteExecution = $true
                AccessToken = $accessToken
            }
            try {
                Write-Verbose "Attempting to connect to server: $server"
                $scriptBlock = {
                    param($ScriptPath, $Params, $VerbosePreference)
                    try {
                        Set-Location (Split-Path $ScriptPath)
                        
                        $currentPath = (Get-Location).Path
                        Write-Verbose "Current working directory on remote server: $currentPath"
                        
                        # Import required modules
                        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
                        Import-Module Microsoft.Graph.Users -ErrorAction Stop
                        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
                        Write-Verbose "Required modules imported successfully"

                        # Verify AccessToken
                        if ([string]::IsNullOrEmpty($Params.AccessToken)) {
                            throw "AccessToken is null or empty"
                        }
                        Write-Verbose "AccessToken received: $($Params.AccessToken.Substring(0, 10))..."

                        # Connect to Microsoft Graph using the passed access token
                        try {
                            Connect-MgGraph -AccessToken $Params.AccessToken -ErrorAction Stop
                            $remoteContext = Get-MgContext
                            if ($null -eq $remoteContext) {
                                throw "Failed to get Microsoft Graph context after connection"
                            }
                            Write-Verbose "Connected to Microsoft Graph using passed access token"
                        }
                        catch {
                            throw "Failed to connect to Microsoft Graph: $_"
                        }

                        # Remove AccessToken from Params to avoid passing it to the script
                        $Params.Remove('AccessToken')

                        # Run the script with remote execution flag
                        Write-Verbose "Executing script on remote server with parameters:"
                        Write-Verbose ([System.Management.Automation.PSSerializer]::Serialize($Params))
                        $output = & $ScriptPath @Params
                        
                        # Ensure we return a result even if the script doesn't produce output
                        if ($null -eq $output) {
                            Write-Verbose "Script execution completed, but no output was produced"
                            $output = @{
                                ProgramSummary = @()
                                UserSummary = @()
                                TotalEvents = 0
                            }
                        }
                        Write-Verbose "Script execution completed successfully"
                        @{
                            Output = $output
                            VerboseOutput = $VerbosePreference
                            Error = $null
                        }
                    }
                    catch {
                        Write-Verbose "An error occurred during remote execution: $_"
                        @{
                            Output = $null
                            VerboseOutput = $VerbosePreference
                            Error = $_
                        }
                    }
                    finally {
                        # Disconnect from Microsoft Graph
                        Disconnect-MgGraph -ErrorAction SilentlyContinue
                        Write-Verbose "Disconnected from Microsoft Graph"
                    }
                }

                $result = Invoke-Command -ComputerName $server -ScriptBlock $scriptBlock -ArgumentList $PSCommandPath, $remoteParams, $VerbosePreference -ErrorAction Stop

                if ($null -ne $result) {
                    $allResults += $result
                    Write-Host "Successfully processed server: $server" -ForegroundColor Green
                    Write-Verbose ("Result from server {0}: {1}" -f $server, ($result | Out-String))
                } else {
                    Write-Warning "No results returned from server: $server"
                }
            }
            catch {
                Write-Error "Failed to process server $server. Error: $_"
                Write-Verbose "Detailed error information: $($_.Exception | Out-String)"
            }
        }

        if ($allResults.Count -gt 0) {
            Write-Host "Aggregating results from all servers..." -ForegroundColor Cyan
            # Aggregate results from all servers
            $programSummary = $allResults | ForEach-Object { 
                if ($_.Output -and $_.Output.ProgramSummary) { 
                    $_.Output.ProgramSummary 
                } else {
                    Write-Warning "No program summary data found for a server"
                }
            } | Where-Object { $null -ne $_ } | Group-Object ProgramName | ForEach-Object {
                [PSCustomObject]@{
                    ProgramName = $_.Name
                    TotalExecutions = ($_.Group | Measure-Object -Property TotalExecutions -Sum).Sum
                    UniqueUsers = ($_.Group | ForEach-Object { $_.UniqueUsers } | Sort-Object -Unique).Count
                    AverageDuration = ($_.Group | Measure-Object -Property AverageDuration -Average).Average
                }
            }

            $userSummary = $allResults | ForEach-Object { 
                if ($_.Output -and $_.Output.UserSummary) { 
                    $_.Output.UserSummary 
                } else {
                    Write-Warning "No user summary data found for a server"
                }
            } | Where-Object { $null -ne $_ } | Group-Object Username | ForEach-Object {
                [PSCustomObject]@{
                    Username = $_.Name
                    TotalExecutions = ($_.Group | Measure-Object -Property TotalExecutions -Sum).Sum
                    UniqueProgramsUsed = ($_.Group | ForEach-Object { $_.UniqueProgramsUsed } | Sort-Object -Unique).Count
                    TotalDuration = ($_.Group | Measure-Object -Property TotalDuration -Sum).Sum
                }
            }

            $totalEvents = ($allResults | ForEach-Object { 
                if ($_.Output -and $_.Output.TotalEvents) { 
                    $_.Output.TotalEvents 
                } else {
                    Write-Warning "No total events data found for a server"
                    0
                }
            } | Measure-Object -Sum).Sum

            # Output results for remote execution
            Write-Host "Outputting aggregated results from all servers:" -ForegroundColor Cyan
            Output-Results -ProgramSummary $programSummary -UserSummary $userSummary -TotalEvents $totalEvents
            
            # Export if requested
            if ($ExportPath) {
                Write-Host "Exporting aggregated results to: $ExportPath" -ForegroundColor Cyan
                Export-Results -ProgramSummary $programSummary -UserSummary $userSummary -ExportPath $ExportPath
            }
        }
        else {
            Write-Warning "No results were collected from remote servers. Please check the errors above."
        }
    }
    else {
        Write-Host "Running script locally" -ForegroundColor Cyan
        $initParams['IsRemoteExecution'] = $IsRemoteExecution
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
    }
}
catch {
    Write-Error "Error: $_"
    exit 1
}
finally {
    if (-not $RemoteServers) {
        try {
            $context = Get-MgContext
            if ($null -ne $context) {
                Disconnect-MgGraph
                Write-Verbose "Disconnected from Microsoft Graph"
            }
        }
        catch {
            Write-Verbose "No active Microsoft Graph connection to disconnect"
        }
    }
}
