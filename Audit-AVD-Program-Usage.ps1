<#
.SYNOPSIS
    Monitors and analyzes process creation events in Azure Virtual Desktop environments with Microsoft Entra ID integration.

.DESCRIPTION
    This script monitors process creation events (Event ID 4688) in the Windows Security Log and correlates them
    with Microsoft Entra ID (formerly Azure AD) user information to provide insights into program usage patterns
    across different user roles. It includes performance optimizations through user information caching and
    intelligent filtering of system processes.

    Key features:
    - Process creation monitoring with system process filtering
    - Microsoft Entra ID integration for user role classification
    - User information caching for improved performance
    - Automated data summarization and grouping
    - CSV export capabilities

.PARAMETER ExportPath
    Optional path to export results as a CSV file. The export will contain summarized data including
    program names, user classes, execution counts, and last run timestamps.

.PARAMETER Help
    Shows detailed help information about the script usage.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1
    Runs the script with default settings, outputting summarized results to the console.

.EXAMPLE
    .\Audit-AVD-Program-Usage.ps1 -ExportPath "C:\Logs\process_audit.csv"
    Runs the script and exports summarized results to the specified CSV file.

.NOTES
    File Name      : Audit-AVD-Program-Usage.ps1
    Author         : Ed Crotty (ecrotty@edcrotty.com)
    Prerequisite   : - Process Creation Auditing enabled via Group Policy
                    - Microsoft.Graph.Authentication module
                    - Microsoft.Graph.Users module
                    - Microsoft.Graph.Identity.DirectoryManagement module
                    - Microsoft Entra ID permissions: User.Read.All, Organization.Read.All
    License        : BSD 3-Clause License
    Version        : 1.0.0
    Repository     : https://github.com/ecrotty/Audit-AVD-Program-Usage

.LINK
    https://github.com/ecrotty/Audit-AVD-Program-Usage
#>

[Rest of the script content remains unchanged...]
