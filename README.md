# Audit-AVD-Program-Usage

A PowerShell script for monitoring and analyzing process creation events (Event ID 4688) in Azure Virtual Desktop (AVD) environments. The script helps track and understand which applications users are running in their AVD sessions, with Microsoft Entra ID integration for user details.

## Project Structure

The project is organized into modular components for improved maintainability and extensibility:

- `Audit-AVD-Program-Usage.ps1`: Main script file
- `src/Config.ps1`: Configuration settings
- `src/Utilities.ps1`: Utility functions
- `src/EventProcessing.ps1`: Event processing logic
- `src/Reporting.ps1`: Reporting and output functions

## Features

- User program detection with intelligent filtering of user applications vs system processes
- Per-user program usage tracking with Microsoft Entra ID integration
- Flexible historical analysis options (1h, 1d, 3d, 7d, 14d, 30d, or all available history)
- CSV export capability with timestamped files for program and user summaries
- Detailed program and user summary statistics
- System process filtering and path exclusion
- Automatic configuration of audit policies for Process Creation and Logon events
- User session tracking for improved accuracy in associating processes with users

## Prerequisites

- Windows Server 2019/2022 or Windows 10/11
- PowerShell 5.1 or later
- Administrator rights to read Security event log and configure audit policies
- Microsoft Entra ID account with the following Graph API permissions:
  - User.Read.All
  - AuditLog.Read.All
  - Directory.Read.All

## Installation

1. Clone or download the repository to your local machine.
2. Ensure you have the necessary permissions in Microsoft Entra ID.
3. The script will automatically configure the required audit policies when run with administrator privileges.

## Usage

Basic usage:
```powershell
.\Audit-AVD-Program-Usage.ps1
```

With parameters:
```powershell
.\Audit-AVD-Program-Usage.ps1 -History 3d -ExportPath "C:\Reports" -Filter
```

### Parameters

- `-ExportPath`: Directory path to export CSV results (creates separate files for program and user summaries)
- `-History`: Duration to analyze (1h, 1d, 3d, 7d, 14d, 30d, or 'all'). Default: 1h
- `-Filter`: Enable filtering of system processes and paths
- `-Help`: Show detailed help information
- `-UseCurrentUser`: Use current logged-in user's account to run the script
- `-Verbose`: Enable verbose logging for troubleshooting

## Authentication

The script handles authentication automatically:
1. Checks for and installs required Microsoft Graph modules if missing
2. Disconnects any existing Microsoft Graph connections
3. Prompts for interactive login with required scopes
4. Verifies the presence of required permissions
5. Tests user lookup to ensure proper connectivity

## Output

The script provides:
1. User program usage summary with Microsoft Entra ID user details
2. Program execution statistics
3. Optional CSV export with detailed usage data for programs and users

## License

BSD 3-Clause License - See LICENSE file for details

## Author

Edward Crotty (2025)
