# Audit-AVD-Program-Usage

A PowerShell script for monitoring and analyzing process creation events (Event ID 4688) in Azure Virtual Desktop (AVD) environments. The script helps track and understand which applications users are running in their AVD sessions, with Microsoft Entra ID integration for user details.

## Features

### User Program Detection
- Intelligent filtering of user applications vs system processes
- Recognition of common user applications:
  - Microsoft Office applications (Teams, Outlook, Excel, Word, PowerPoint)
  - Web browsers (Chrome, Edge, Firefox)
  - Development tools (VS Code)
  - Basic Windows tools (Notepad, Remote Desktop)
- Comprehensive system process exclusion:
  - Windows core processes
  - System utilities
  - Background services
  - Temporary executables
  - Windows system paths

### Usage Analysis
- Per-user program usage tracking with Microsoft Entra ID integration
- Flexible historical analysis options (1, 3, 7, 14, 30 days, or all available history)
- CSV export capability
- Summary statistics and reporting
- User details enrichment from Microsoft Entra ID

## Prerequisites

- Windows Server 2019/2022 or Windows 10/11
- PowerShell 5.1 or later
- Process Creation Auditing enabled (Event ID 4688)
- Required Microsoft Graph PowerShell modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.DirectoryManagement
- Administrator rights to read Security event log
- Microsoft Entra ID account with appropriate permissions:
  - User.Read.All
  - AuditLog.Read.All
  - Directory.Read.All

## Installation

1. Enable Process Creation Auditing via Group Policy:
   ```
   Computer Configuration > Windows Settings > Security Settings > 
   Advanced Audit Policy Configuration > Detailed Tracking > 
   Audit Process Creation > Enable
   ```

2. Run `gpupdate /force` to apply the policy

3. The script will automatically install required Microsoft Graph modules if they're not present

## Usage

Basic usage:
```powershell
.\Audit-AVD-Program-Usage.ps1
```

With parameters:
```powershell
.\Audit-AVD-Program-Usage.ps1 -History 7 -ExportPath "C:\Reports\usage.csv"
```

### Parameters

- `-History`: Duration to analyze (1, 3, 7, 14, 30, or 'all' days). Default: 1
- `-ExportPath`: Path to export CSV results
- `-Help`: Show help information

### Authentication

The script will:
1. Automatically disconnect any existing Microsoft Graph connections
2. Prompt for interactive login with required scopes
3. Detect your organization's domain from your authenticated user account

## Output

The script provides:
1. User program usage summary with Microsoft Entra ID user details
2. Program execution statistics
3. Optional CSV export with detailed usage data

## License

BSD 3-Clause License - See LICENSE file for details

## Author

Edward Crotty (December 2023)
