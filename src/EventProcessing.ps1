# Event processing functions for Audit-AVD-Program-Usage script

# Import the configuration and utilities
. "$PSScriptRoot\Config.ps1"
. "$PSScriptRoot\Utilities.ps1"

function Get-ProcessEvents {
    param (
        [DateTime]$StartTime = [DateTime]::MinValue,
        [DateTime]$EndTime = [DateTime]::Now
    )

    $filterHashtable = @{
        LogName = 'Security'
        ID = 4688  # Process Creation
    }

    if ($StartTime -ne [DateTime]::MinValue) {
        $filterHashtable['StartTime'] = $StartTime
    }
    $filterHashtable['EndTime'] = $EndTime

    $events = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction Stop

    Write-Host ("Found " + $events.Count + " process creation events...")
    return $events
}

function Get-LogonEvents {
    param (
        [DateTime]$StartTime = [DateTime]::MinValue,
        [DateTime]$EndTime = [DateTime]::Now
    )

    $filterHashtable = @{
        LogName = 'Security'
        ID = @(4624, 4634)  # Logon/Logoff events
    }

    if ($StartTime -ne [DateTime]::MinValue) {
        $filterHashtable['StartTime'] = $StartTime
    }
    $filterHashtable['EndTime'] = $EndTime

    $logonEvents = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction Stop

    Write-Host ("Found " + $logonEvents.Count + " session events...")
    return $logonEvents
}

function Build-UserSessions {
    param (
        [array]$LogonEvents
    )

    $userSessions = @{}
    foreach ($evt in $LogonEvents) {
        try {
            $xml = [xml]$evt.ToXml()
            if ($null -eq $xml.Event.EventData.Data) { continue }
            
            $data = @{}
            foreach ($item in $xml.Event.EventData.Data) {
                if ($null -ne $item.Name) {
                    $data[$item.Name] = $item.'#text'
                }
            }
            
            if ($data.ContainsKey('TargetUserName') -and $data.ContainsKey('LogonId')) {
                $user = $data.TargetUserName -replace '^.*\\'
                if (-not [string]::IsNullOrEmpty($user) -and $user -ne "SYSTEM") {
                    if ($evt.Id -eq 4624) {  # Logon
                        $userSessions[$data.LogonId] = $user
                    }
                }
            }
        } catch {
            Write-Verbose ("Failed to process logon event: " + $_)
            continue
        }
    }

    return $userSessions
}

function Process-Events {
    param (
        [array]$Events,
        [hashtable]$UserSessions,
        [switch]$Filter
    )

    $processData = @()
    $userCache = @{}

    foreach ($event in $Events) {
        try {
            $xml = [xml]$event.ToXml()
            $data = @{}
            
            $eventData = $xml.Event.EventData.Data
            if (-not $eventData) {
                Write-Verbose ("Event " + $event.Id + " has no data")
                continue
            }
            
            if ($eventData[0].Name) {
                foreach ($item in $eventData) {
                    $data[$item.Name] = $item.'#text'
                }
            } else {
                $propertyMap = @{
                    0 = 'SubjectUserSid'
                    1 = 'SubjectUserName'
                    2 = 'SubjectDomainName'
                    3 = 'SubjectLogonId'
                    4 = 'NewProcessId'
                    5 = 'NewProcessName'
                    6 = 'TokenElevationType'
                    7 = 'ProcessId'
                    8 = 'CommandLine'
                    9 = 'TargetUserSid'
                    10 = 'TargetUserName'
                    11 = 'TargetDomainName'
                    12 = 'TargetLogonId'
                    13 = 'ParentProcessName'
                    14 = 'ParentProcessId'
                }
                
                for ($i = 0; $i -lt $eventData.Count; $i++) {
                    if ($propertyMap.ContainsKey($i)) {
                        $data[$propertyMap[$i]] = $eventData[$i].'#text'
                    }
                }
            }
            
            if (-not $data.ContainsKey('NewProcessName')) {
                Write-Verbose "Event missing process name, skipping..."
                continue
            }
            
            $subjectUsername = if ($data.ContainsKey('SubjectUserName')) { 
                $data.SubjectUserName -replace '^.*\\' 
            } else { $null }
            
            $targetUsername = if ($data.ContainsKey('TargetUserName')) { 
                $data.TargetUserName -replace '^.*\\' 
            } else { $null }
            
            $logonId = if ($data.ContainsKey('SubjectLogonId')) { 
                $data.SubjectLogonId 
            } else { $null }
            
            $targetLogonId = if ($data.ContainsKey('TargetLogonId')) {
                $data.TargetLogonId
            } else { $null }
            
            $username = $null
            $processPath = $data.NewProcessName
            $processName = Split-Path $processPath -Leaf
            
            if ($targetLogonId -and $UserSessions.ContainsKey($targetLogonId)) {
                $username = $UserSessions[$targetLogonId]
            }
            
            if (-not $username -and $logonId -and $UserSessions.ContainsKey($logonId)) {
                $username = $UserSessions[$logonId]
            }
            
            if (-not $username -or $username -eq "SYSTEM") {
                if (-not [string]::IsNullOrWhiteSpace($subjectUsername) -and $subjectUsername -ne "SYSTEM") {
                    $username = $subjectUsername
                } elseif (-not [string]::IsNullOrWhiteSpace($targetUsername) -and $targetUsername -ne "SYSTEM") {
                    $username = $targetUsername
                }
            }
            
            if (-not $username -or $username -eq "SYSTEM") {
                $parentProcessName = if ($data.ContainsKey('ParentProcessName')) {
                    Split-Path $data.ParentProcessName -Leaf
                } else { $null }
                
                if ($parentProcessName) {
                    $parentLogonId = if ($data.ContainsKey('ParentProcessLogonId')) {
                        $data.ParentProcessLogonId
                    } else { $null }
                    
                    if ($parentLogonId -and $UserSessions.ContainsKey($parentLogonId)) {
                        $username = $UserSessions[$parentLogonId]
                    } elseif ($parentProcessName -match '(explorer|cmd|powershell|winlogon|userinit|RuntimeBroker|SearchApp|sihost|taskhostw)\.exe$') {
                        $username = $targetUsername
                    }
                }
            }
            
            if (-not $username -or $username -eq "SYSTEM") {
                $username = "SYSTEM"
            }
            
            if ($username -eq "SYSTEM" -and $Filter) {
                continue
            }
            
            if (-not $userCache.ContainsKey($username)) {
                $userCache[$username] = Get-UserInfo -Username $username
            }
            
            if (Test-UserApplication -ProcessPath $processPath -ProcessName $processName -Filter:$Filter) {
                $processData += [PSCustomObject]@{
                    Timestamp = $event.TimeCreated
                    Username = $username
                    ProcessName = $processName
                    FriendlyName = Get-FriendlyProgramName -ProcessPath $processPath -ProcessName $processName
                    Department = $userCache[$username].Department
                    CommandLine = $data.CommandLine
                }
            }
        } catch {
            Write-Verbose ("Failed to process event: " + $_)
            continue
        }
    }

    return $processData
}

# No export needed for script files
