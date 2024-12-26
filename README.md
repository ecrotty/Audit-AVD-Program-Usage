# Audit-AVD-Program-Usage

A PowerShell script for monitoring and analyzing process creation events (Event ID 4688) in Azure Virtual Desktop (AVD) environments. The script helps track and understand which applications users are running in their AVD sessions.

## Features

### User Program Detection
- Intelligent filtering of user applications vs system processes
- Recognition of common user applications:
  - Development tools (VS Code, DBeaver, etc.)
  - Office applications
  - Design tools (Figma)
  - Communication tools (Teams)
  - Custom applications in Program Files
- Comprehensive system process exclusion:
  - Windows core processes
  - System utilities
  - Background services
  - Temporary executables

### Usage Analysis
- Per-user program usage tracking
- Historical analysis options (1-30 days)
- CSV export capability
- Summary statistics and reporting

## Prerequisites

- Windows Server 2019/2022 or Windows 10/11
- PowerShell 5.1 or later
- Process Creation Auditing enabled (Event ID 4688)
- Microsoft.Graph PowerShell module
- Administrator rights to read Security event log

## Installation

1. Enable Process Creation Auditing via Group Policy:
   ```
   Computer Configuration > Windows Settings > Security Settings > 
   Advanced Audit Policy Configuration > Detailed Tracking > 
   Audit Process Creation > Enable
   ```

2. Run `gpupdate /force` to apply the policy

3. Install required PowerShell module:
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

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

- `-History`: Duration to analyze (1, 3, 7, 14, 30, or 'all' days)
- `-ExportPath`: Path to export CSV results
- `-Help`: Show help information

## Output

The script provides:
1. User program usage summary
2. List of unknown/uncategorized programs
3. Optional CSV export with detailed usage data

## License

BSD 3-Clause License - See LICENSE file for details

## Author

Edward Crotty (December 2023)
