# Configuration settings for Audit-AVD-Program-Usage script

$Config = @{
    RequiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )
    GraphScopes = @(
        "User.Read.All",
        "AuditLog.Read.All",
        "Directory.Read.All"
    )
    SystemProcesses = @(
        'svchost.exe',
        'csrss.exe',
        'lsass.exe',
        'services.exe',
        'smss.exe',
        'wininit.exe',
        'winlogon.exe'
    )
    SystemPaths = @(
        '\\Windows\\System32\\',
        '\\Windows\\SysWOW64\\',
        '\\Windows\\WinSxS\\'
    )
    UserPaths = @(
        '\\Program Files\\',
        '\\Program Files (x86)\\',
        '\\Users\\',
        '\\ProgramData\\',
        '\\WindowsApps\\'
    )
    CommonNames = @{
        'msedge.exe' = 'Microsoft Edge'
        'chrome.exe' = 'Google Chrome'
        'Teams.exe' = 'Microsoft Teams'
        'OUTLOOK.EXE' = 'Microsoft Outlook'
        'EXCEL.EXE' = 'Microsoft Excel'
        'WINWORD.EXE' = 'Microsoft Word'
        'POWERPNT.EXE' = 'Microsoft PowerPoint'
        'Code.exe' = 'Visual Studio Code'
        'notepad.exe' = 'Microsoft® Windows® Operating System'
        'powershell.exe' = 'Microsoft® Windows® Operating System'
        'cmd.exe' = 'Microsoft® Windows® Operating System'
        'explorer.exe' = 'Microsoft® Windows® Operating System'
    }
}

# No export needed for script files
