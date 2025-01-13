# Parses event data from XML into a hashtable

function Parse-EventData {
    param (
        [xml]$EventXml
    )

    $data = @{}
    $eventData = $EventXml.Event.EventData.Data
    if (-not $eventData) {
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

    return $data
}
