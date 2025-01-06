# Reporting functions for Audit-AVD-Program-Usage script

# Import the configuration and utilities
. "$PSScriptRoot\Config.ps1"
. "$PSScriptRoot\Utilities.ps1"

function Generate-ProgramSummary {
    param (
        [array]$ProcessData
    )

    $programSummary = $ProcessData | Group-Object ProcessName | ForEach-Object {
        $users = $_.Group | Select-Object -ExpandProperty Username -Unique | Where-Object { $_ -ne "-" }
        $departments = $_.Group | Select-Object -ExpandProperty Department -Unique | Where-Object { $_ -ne "Not Specified" -and $_ -ne "Not Found" }
        $isUserApp = $_.Name -match '(chrome|teams|office|edge|outlook|excel|word|powerpoint|acrobat|onedrive|code|notepad|powershell)\.exe$'
        
        [PSCustomObject]@{
            'Program' = $_.Name
            'Friendly Name' = ($_.Group[0].FriendlyName)
            'Users' = if ($users) { $users -join ', ' } else { "-" }
            'Departments' = if ($departments) { $departments -join ', ' } else { "Not Specified" }
            'Count' = $_.Count
            'Last Run' = ($_.Group | Sort-Object Timestamp -Descending)[0].Timestamp
            'IsUserApp' = $isUserApp -or ($users.Count -gt 0)
        }
    } | Sort-Object IsUserApp, { if ($_.Users -eq "-") { 2 } else { 1 } }, Count -Descending

    return $programSummary
}

function Generate-UserSummary {
    param (
        [array]$ProcessData
    )

    $userSummary = $ProcessData | Group-Object Username | ForEach-Object {
        [PSCustomObject]@{
            'Username' = $_.Name
            'Department' = ($_.Group | Select-Object -ExpandProperty Department -Unique) -join ', '
            'Programs' = ($_.Group | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
            'Count' = $_.Count
            'Last Activity' = ($_.Group | Sort-Object Timestamp -Descending)[0].Timestamp
        }
    }

    return $userSummary
}

function Output-Results {
    param (
        [array]$ProgramSummary,
        [array]$UserSummary,
        [int]$TotalEvents
    )

    Write-Host ("`nUser Application Summary (" + $TotalEvents + " events):") -ForegroundColor Cyan
    Write-Host "Common Applications:" -ForegroundColor Yellow
    $ProgramSummary | Where-Object { $_.IsUserApp } | 
        Select-Object Program, 'Friendly Name', Users, Departments, @{Name='Times Run'; Expression={$_.Count}}, 'Last Run' | 
        Format-Table -AutoSize -Wrap

    Write-Host "`nSystem and Background Processes:" -ForegroundColor Yellow
    $ProgramSummary | Where-Object { -not $_.IsUserApp } | 
        Select-Object Program, 'Friendly Name', Users, Departments, @{Name='Times Run'; Expression={$_.Count}}, 'Last Run' | 
        Format-Table -AutoSize -Wrap

    Write-Host ("`nUser Activity Summary (" + $UserSummary.Count + " users):") -ForegroundColor Cyan
    $UserSummary | Where-Object { $_.Username -ne "-" } | 
        Select-Object Username, Department, Programs, @{Name='Times Run'; Expression={$_.Count}}, 'Last Activity' | 
        Format-Table -AutoSize -Wrap
}

function Export-Results {
    param (
        [array]$ProgramSummary,
        [array]$UserSummary,
        [string]$ExportPath
    )

    if ($ExportPath) {
        $date = Get-Date -Format "yyyyMMdd"
        $ProgramSummary | Export-Csv -Path "$ExportPath\Programs-$date.csv" -NoTypeInformation
        $UserSummary | Export-Csv -Path "$ExportPath\Users-$date.csv" -NoTypeInformation
        Write-Host "`nExported results to $ExportPath"
    }
}

# No export needed for script files
