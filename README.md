# Audit-AVD-Program-Usage

A PowerShell script for monitoring and analyzing process creation events (Event ID 4688) in Azure Virtual Desktop (AVD) environments, with Microsoft Entra ID (formerly Azure AD) integration for user role classification.

## Features

- Monitors process creation events (Event ID 4688) in Windows Security Log
- Integrates with Microsoft Graph API to fetch user job titles
- Standardizes job titles into user classes for better analysis
- Supports CSV export of collected data
- Automatic installation of required PowerShell modules

## Prerequisites

1. Windows PowerShell 5.1 or PowerShell Core 7.x
2. Process Creation Auditing enabled via Group Policy:
   - Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking
   - Enable "Audit Process Creation" for Success events
   - Run 'gpupdate /force' after changes
3. Microsoft Graph PowerShell SDK modules (automatically installed by script)
4. Appropriate Microsoft Entra ID permissions (User.Read.All)

## Installation

```powershell
# Clone the repository
git clone https://github.com/ecrotty/Audit-AVD-Program-Usage.git
cd Audit-AVD-Program-Usage
```

## Usage

```powershell
# Show help information
.\Audit-AVD-Program-Usage.ps1 -Help

# Run with default settings (output to console)
.\Audit-AVD-Program-Usage.ps1

# Export results to CSV
.\Audit-AVD-Program-Usage.ps1 -ExportPath "process_audit.csv"
```

### Parameters

- `-ExportPath`: Optional. Path to export CSV results
- `-Help`: Show help information

## Output

The script provides the following information for each process creation event:

- Timestamp
- Username
- Process Name
- Command Line
- Job Title (from Microsoft Entra ID)
- User Class (mapped from Job Title)

## Job Title Mapping

The script includes default mappings for common job titles to standardized classes:

- Developer class: Developer, Software Engineer, Senior Developer, etc.
- Data Professional class: Data Architect, Data Engineer, Data Analyst
- Engineer class: Systems Engineer, DevOps Engineer, Cloud Engineer
- Administrator class: IT Admin, System Administrator, Network Admin

You can customize these mappings by modifying the `$TitleToClassMapping` hashtable in the script.

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and contribute to the project.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

## Author

Ed Crotty (ecrotty@edcrotty.com)

## Version History

- 1.0.0 (2024): Initial release
  - Basic process monitoring functionality
  - Microsoft Entra ID integration
  - Job title standardization
  - CSV export capability
