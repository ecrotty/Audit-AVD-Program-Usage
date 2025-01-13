# Session management functions for Audit-AVD-Program-Usage script

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
