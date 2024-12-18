# Audit-AVD-Program-Usage

A PowerShell script for monitoring and analyzing process creation events (Event ID 4688) in Azure Virtual Desktop (AVD) environments, with Microsoft Entra ID (formerly Azure AD) integration for user role classification.

## Features

- Monitors process creation events (Event ID 4688) in Windows Security Log
- Integrates with Microsoft Graph API to fetch user job titles
- Standardizes job titles into user classes for better analysis
- Implements intelligent caching of user information for improved performance
- Smart process filtering:
  - Excludes common system processes
  - Tracks specific user applications
  - Filters out system account activities
- Groups and summarizes program usage by user classes
- Supports CSV export of collected data
- Automatic installation of required PowerShell modules

## Prerequisites

1. Windows PowerShell 5.1 or PowerShell Core 7.x
2. Process Creation Auditing enabled via Group Policy:
   - Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking
   - Enable "Audit Process Creation" for Success events
   - Run 'gpupdate /force' after changes
3. Microsoft Graph PowerShell SDK modules (automatically installed by script):
   - Microsoft.Graph.Authentication
   - Microsoft.Graph.Users
   - Microsoft.Graph.Identity.DirectoryManagement
4. Microsoft Entra ID permissions:
   - User.Read.All
   - Organization.Read.All

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

The script provides a summarized view of process execution data:

- Program Name: Name of the executed process
- User Classes: Classes of users who ran the program
- Times Run: Total number of executions
- Last Run: Most recent execution timestamp

### Tracked Applications

The script monitors a comprehensive list of business and development applications across various categories:

#### Microsoft Office Suite
- Excel, Word, PowerPoint, Outlook, Teams, OneNote, Access, Publisher

#### Development Tools and IDEs
- Visual Studio, VS Code, Git tools, Node.js, Java Runtime, PowerShell
- IIS Express, Salesforce CLI

#### Database and Data Tools
- SQL Server Management Studio, Azure Data Studio
- PostgreSQL and Snowflake CLIs
- DiskPie Pro

#### BI and Analytics Tools
- Power BI Desktop, Tableau, Tableau Prep Builder

#### Statistical and Data Science
- RStudio, Python, Jupyter Notebook/Lab
- Anaconda Navigator

#### Cloud and Enterprise Tools
- Azure CLI, Storage Explorer, Enterprise Architect
- Azure Functions Core Tools

#### Remote Access and Network Tools
- PuTTY, WinSCP, Cisco ASDM-IDM
- TortoiseSVN

#### Browsers
- Chrome, Edge, Firefox, Internet Explorer, Brave

### System Process Filtering

The script automatically filters out:
- Common Windows system processes (svchost.exe, RuntimeBroker.exe, etc.)
- System utilities and background processes
- System account activities (accounts ending with $ or "SYSTEM")

### User Classification

The script includes default mappings for common job titles to standardized classes:

- Developer class: Developer, Software Engineer, Senior Developer, etc.
- Data Professional class: Data Architect, Data Engineer, Data Analyst
- Engineer class: Systems Engineer, DevOps Engineer, Cloud Engineer
- Administrator class: IT Admin, System Administrator, Network Admin

You can customize these mappings by modifying the `$TitleToClassMapping` hashtable in the script.

## Performance Optimization

The script implements several optimizations:
- Caches user information to reduce Microsoft Graph API calls
- Filters out system processes early in the processing pipeline
- Efficiently groups and summarizes data for meaningful analysis
- Smart filtering of relevant user applications

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and contribute to the project.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

## Author

Ed Crotty (ecrotty@edcrotty.com)

## Version History

- 1.0.0 (2024): Initial release
  - Process monitoring with smart application filtering
  - Microsoft Entra ID integration
  - Job title standardization
  - Comprehensive application tracking
  - System process exclusion
  - User information caching
  - Enhanced data summarization
