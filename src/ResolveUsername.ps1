# Resolve username function for Audit-AVD-Program-Usage script

function Resolve-Username {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Data,
        [Parameter(Mandatory=$true)]
        [hashtable]$UserSessions
    )

    $subjectUsername = if ($Data.ContainsKey('SubjectUserName')) { 
        $Data.SubjectUserName -replace '^.*\\' 
    } else { $null }
    
    $targetUsername = if ($Data.ContainsKey('TargetUserName')) { 
        $Data.TargetUserName -replace '^.*\\' 
    } else { $null }
    
    $logonId = if ($Data.ContainsKey('SubjectLogonId')) { 
        $Data.SubjectLogonId 
    } else { $null }
    
    $targetLogonId = if ($Data.ContainsKey('TargetLogonId')) {
        $Data.TargetLogonId
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
        $parentProcessName = if ($Data.ContainsKey('ParentProcessName')) {
            Split-Path $Data.ParentProcessName -Leaf
        } else { $null }
        
        if ($parentProcessName) {
            $parentLogonId = if ($Data.ContainsKey('ParentProcessLogonId')) {
                $Data.ParentProcessLogonId
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
