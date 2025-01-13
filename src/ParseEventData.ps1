# Parse event data function for Audit-AVD-Program-Usage script

function Parse-EventData {
    param (
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )

    $xml = [xml]$Event.ToXml()
    $data = @{}
    
    $eventData = $xml.Event.EventData.Data
    if (-not $eventData) {
        Write-Verbose ("Event " + $Event.Id + " has no data")
        return $null
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
        return $null
    }
    
    return $data
}
