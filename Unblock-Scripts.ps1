# Unblock all .ps1 files in the current directory and subdirectories
Get-ChildItem -Path $PSScriptRoot -Recurse -Filter *.ps1 | Unblock-File -Verbose

Write-Host "All PowerShell scripts have been unblocked."
