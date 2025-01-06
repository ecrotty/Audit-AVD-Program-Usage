# Audit-AVD-Program-Usage

A PowerShell script for monitoring and analyzing process creation events (Event ID 4688) in Azure Virtual Desktop (AVD) environments. The script helps track and understand which applications users are running in their AVD sessions, with Microsoft Entra ID integration for user details.

## Project Structure

The project has been refactored into smaller, more manageable files:

- `Audit-AVD-Program-Usage.ps1`: Main script file
- `src/Config.ps1`: Configuration settings
- `src/Utilities.ps1`: Utility functions
- `src/EventProcessing.ps1`: Event processing logic
- `src/Reporting.ps1`: Reporting and output functions

This modular structure improves maintainability and makes it easier to extend the functionality.

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
- Flexible historical analysis options (1h, 1d, 3d, 7d, 14d, 30d, or all available history)
- Enhanced user department classification with multiple fallback options
- CSV export capability with timestamped files
- Detailed program and user summary statistics
- Improved system process filtering and path exclusion

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
.\Audit-AVD-Program-Usage.ps1 -History 3d -ExportPath "C:\Reports"
```

### Parameters

- `-History`: Duration to analyze (1h=1 hour, 1d=1 day, 3d=3 days, 7d=7 days, 14d=14 days, 30d=30 days, or 'all'). Default: 1h
- `-ExportPath`: Directory path to export timestamped CSV results (creates separate files for program and user summaries)
- `-Filter`: Enable filtering of system processes and paths
- `-Help`: Show detailed help information
- `-UseCurrentUser`: Use current logged in user's account to run the script

### Authentication

The script will:
1. Automatically install required Microsoft Graph modules if missing
2. Disconnect any existing Microsoft Graph connections
3. Prompt for interactive login with required scopes
4. Detect your organization's domain from your authenticated user account
5. Cache user information for improved performance

## Output

The script provides:
1. User program usage summary with Microsoft Entra ID user details
2. Program execution statistics
3. Optional CSV export with detailed usage data

## License

BSD 3-Clause License - See LICENSE file for details

## Author

Edward Crotty (December 2023)
