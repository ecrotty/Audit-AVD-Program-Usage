# Event retrieval functions for Audit-AVD-Program-Usage script

function Get-ProcessEvents {
    param (
        [DateTime]$StartTime = [DateTime]::MinValue,
        [DateTime]$EndTime = [DateTime]::Now
    )

    $filterHashtable = @{
        LogName = 'Security'
        ID = 4688  # Process Creation
    }

    if ($StartTime -ne [DateTime]::MinValue -and $StartTime -ne $null) {
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

    if ($StartTime -ne [DateTime]::MinValue -and $StartTime -ne $null) {
        $filterHashtable['StartTime'] = $StartTime
    }
    $filterHashtable['EndTime'] = $EndTime

    $logonEvents = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction Stop

    Write-Host ("Found " + $logonEvents.Count + " session events...")
    return $logonEvents
}
