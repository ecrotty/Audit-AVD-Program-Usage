# Event processing functions for Audit-AVD-Program-Usage script

# Import the configuration and utilities
. "$PSScriptRoot\Config.ps1"
. "$PSScriptRoot\Utilities.ps1"
. "$PSScriptRoot\EventRetrieval.ps1"
. "$PSScriptRoot\SessionManagement.ps1"
. "$PSScriptRoot\ParseEventData.ps1"
. "$PSScriptRoot\ResolveUsername.ps1"
. "$PSScriptRoot\GetUserInformation.ps1"

function Get-ApplicationFriendlyName {
    param (
        [string]$ProcessName
    )

    # This is a basic mapping. You may want to expand this or use a more sophisticated method
    $friendlyNames = @{
        'chrome.exe' = 'Google Chrome'
        'msedge.exe' = 'Microsoft Edge'
        'msedgewebview2.exe' = 'Microsoft Edge WebView2'
        'firefox.exe' = 'Mozilla Firefox'
        'iexplore.exe' = 'Internet Explorer'
        'outlook.exe' = 'Microsoft Outlook'
        'winword.exe' = 'Microsoft Word'
        'excel.exe' = 'Microsoft Excel'
        'powerpnt.exe' = 'Microsoft PowerPoint'
        'teams.exe' = 'Microsoft Teams'
        'code.exe' = 'Visual Studio Code'
        'devenv.exe' = 'Visual Studio'
        'notepad.exe' = 'Notepad'
        'explorer.exe' = 'File Explorer'
        'cmd.exe' = 'Command Prompt'
        'powershell.exe' = 'PowerShell'
    }

    if ($friendlyNames.ContainsKey($ProcessName)) {
        return $friendlyNames[$ProcessName]
    } else {
        return $ProcessName
    }
}

function Process-Events {
    param (
        [array]$Events,
        [hashtable]$UserSessions,
        [switch]$Filter
    )

    $processData = @()
    $userCache = @{}
    $eventCount = 0
    $oldestEvent = [DateTime]::MaxValue
    $newestEvent = [DateTime]::MinValue
    $processedCount = 0
    $filteredCount = 0
    $includedCount = 0

    Write-Host ("Starting to process " + $Events.Count + " events...")

    foreach ($event in $Events) {
        $eventCount++
        $processedCount++
        if ($event.TimeCreated -lt $oldestEvent) { $oldestEvent = $event.TimeCreated }
        if ($event.TimeCreated -gt $newestEvent) { $newestEvent = $event.TimeCreated }
        
        try {
            Write-Verbose ("Processing event " + $eventCount + " of " + $Events.Count)
            Write-Verbose ("Event Time: " + $event.TimeCreated)
            
            $data = Parse-EventData -Event $event
            if (-not $data) { continue }
            
            $username = Resolve-Username -Data $data -UserSessions $UserSessions
            
            if (-not $userCache.ContainsKey($username)) {
                try {
                    $userCache[$username] = Get-UserInfo -Username $username
                } catch {
                    Write-Verbose ("Error getting user info for " + $username + ": " + $_.Exception.Message)
                    $userCache[$username] = @{}
                }
            }
            
            if ($Filter -and ($username -eq "SYSTEM" -or $username -eq "LOCAL SERVICE" -or $username -eq "NETWORK SERVICE" -or $username.EndsWith('$') -or $userCache[$username].Department -eq "machine account")) {
                $filteredCount++
                Write-Verbose ("Filtered out event: " + $data.NewProcessName + " for user " + $username)
                continue
            }
            
            $processName = Split-Path $data.NewProcessName -Leaf
            $friendlyName = Get-ApplicationFriendlyName -ProcessName $processName
            
            $processData += [PSCustomObject]@{
                'Timestamp' = $event.TimeCreated
                'ProcessId' = $data.NewProcessId
                'ProcessName' = $processName
                'ProcessPath' = $data.NewProcessName
                'CommandLine' = $data.CommandLine
                'Username' = $username
                'FriendlyName' = $friendlyName
                'Department' = $userCache[$username].Department
            }
            
            $includedCount++
        } catch {
            Write-Verbose ("Error processing event: " + $_)
            continue
        }
    }
    
    Write-Host ("Finished processing " + $Events.Count + " events. Oldest: " + $oldestEvent + ", Newest: " + $newestEvent)
    Write-Host ("Included " + ($processedCount - $filteredCount) + " events, filtered out " + $filteredCount + " events.")
    return $processData
}
