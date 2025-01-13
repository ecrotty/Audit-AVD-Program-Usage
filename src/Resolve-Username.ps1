# Resolves the username from event data and user sessions

function Resolve-Username {
    param (
        [hashtable]$EventData,
        [hashtable]$UserSessions
    )

    $subjectUsername = if ($EventData.ContainsKey('SubjectUserName')) { 
        $EventData.SubjectUserName -replace '^.*\\' 
    } else { $null }
    
    $targetUsername = if ($EventData.ContainsKey('TargetUserName')) { 
        $EventData.TargetUserName -replace '^.*\\' 
    } else { $null }
    
    $logonId = if ($EventData.ContainsKey('SubjectLogonId')) { 
        $EventData.SubjectLogonId 
    } else { $null }
    
    $targetLogonId = if ($EventData.ContainsKey('TargetLogonId')) {
        $EventData.TargetLogonId
    } else { $null }
    
    $username = $null
    
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
        $parentProcessName = if ($EventData.ContainsKey('ParentProcessName')) {
            Split-Path $EventData.ParentProcessName -Leaf
        } else { $null }
        
        if ($parentProcessName) {
            $parentLogonId = if ($EventData.ContainsKey('ParentProcessLogonId')) {
                $EventData.ParentProcessLogonId
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

    return $username
}
