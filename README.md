# Audit-AVD-Program-Usage

A PowerShell script for monitoring and analyzing process creation events (Event ID 4688) in Azure Virtual Desktop (AVD) environments, with sophisticated Microsoft Entra ID (formerly Azure AD) integration for advanced user role classification and application usage analysis.

## Features

### Advanced Role Classification
- Sophisticated role matching using fuzzy logic and keyword analysis
- Hierarchical classification system with 11 primary role categories:
  - Developer: Software development and programming
  - DevOps: Platform and release engineering
  - Security: Information security and cybersecurity
  - Data Professional: Analytics, BI, and data engineering
  - SCRUM Professional: Agile and project management
  - Engineer: Systems and infrastructure
  - Consultant: Professional services
  - Contractor: Contract-based roles
  - QA: Quality assurance and testing
  - IT: System administration and support
  - Executives: Leadership and management
- Intelligent title matching with weighted keyword analysis
- Fallback classification for non-standard titles

### Intelligent Application Detection
- Multi-layered process filtering:
  - Path-based analysis (Program Files, User Programs)
  - Known application patterns
  - Command-line parameter analysis
  - User interaction indicators
- Comprehensive system process exclusion:
  - Windows core processes
  - System utilities and services
  - Temporary executables
  - System path executables
- Application categorization by type:
  - Microsoft Office Suite
  - Development Tools and IDEs
  - Database and Data Tools
  - BI and Analytics Tools
  - Statistical and Data Science
  - Cloud and Enterprise Tools
  - Remote Access and Network Tools

### Performance Optimizations
- Bulk user information processing
- Efficient caching mechanisms
- Pre-compiled regex patterns
- In-memory event processing
- Smart filtering algorithms
- Progress indicators and statistics

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

# Export detailed reports to CSV
.\Audit-AVD-Program-Usage.ps1 -ExportPath "audit_report.csv"
# Creates two files:
# - audit_report-Programs.csv
# - audit_report-Users.csv
```

### Parameters

- `-ExportPath`: Optional. Path to export CSV results (creates two files with -Programs and -Users suffixes)
- `-Help`: Show help information

## Output Reports

### Program Usage Summary (-Programs.csv)
- Program Name
- User Classes utilizing the program
- Execution frequency
- Last execution timestamp

### User Classification Summary (-Users.csv)
- Username
- Job Title
- User Class (mapped role)
- Programs Used (complete list)
- Process Count
- Last Active Time

### Console Output
- Processing statistics
- Program usage summary
- User classification summary
- Unclassified program logging
- Progress indicators

## Customization

### Role Classification
The script includes extensive customization options:
- `$TitleToClassMapping`: Direct job title to role mappings
- `$RoleKeywords`: Keywords for fuzzy matching
- `Get-BestRoleMatch`: Role classification logic

### Application Detection
Customizable detection rules:
- `$SystemPaths`: System path exclusions
- `$SystemProcessPatterns`: System process patterns
- `$userAppIndicators`: Application path indicators
- `$commonUserApps`: Known user applications
- `$userInteractionParams`: Command-line indicators

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and contribute to the project.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

## Author

Ed Crotty (ecrotty@edcrotty.com)

## Version History

- 1.0.0 (2024): Initial release
  - Advanced role classification with fuzzy matching
  - Intelligent application detection
  - Comprehensive system process filtering
  - Detailed program and user analysis
  - Multiple report formats
  - Performance optimizations
  - Progress indicators and statistics
