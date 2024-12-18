# Contributing to Audit-AVD-Program-Usage

Thank you for your interest in contributing to Audit-AVD-Program-Usage! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

1. Check if the issue already exists in the [GitHub issue tracker](https://github.com/ecrotty/Audit-AVD-Program-Usage/issues)
2. If not, create a new issue using the provided issue template
3. Provide as much detail as possible:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - PowerShell version
   - Windows version
   - Error messages (if any)

### Submitting Changes

1. Fork the repository
2. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes following our coding standards
4. Test your changes thoroughly
5. Commit your changes with clear, descriptive commit messages:
   ```bash
   git commit -m "Add: brief description of your changes"
   ```
6. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
7. Submit a Pull Request using the provided template

## Coding Standards

### PowerShell Style Guide

- Use clear, descriptive variable and function names
- Include comment-based help for functions
- Follow [PowerShell Best Practices and Style Guide](https://poshcode.gitbook.io/powershell-practice-and-style/)
- Use proper error handling with try/catch blocks
- Include verbose logging where appropriate

### Documentation

- Update README.md if adding new features or changing functionality
- Include inline comments for complex logic
- Update parameter documentation if modifying script parameters

### Testing

- Test changes in both PowerShell 5.1 and PowerShell Core 7.x
- Verify Microsoft Graph integration functionality
- Test with different job title scenarios
- Ensure error handling works as expected

## Pull Request Process

1. Update documentation to reflect any changes
2. Add your changes to the version history in README.md
3. Ensure all tests pass
4. Wait for code review and address any feedback
5. Once approved, your PR will be merged

## Questions?

If you have questions about contributing, please create an issue with the "question" label.

## License

By contributing to this project, you agree that your contributions will be licensed under the BSD 3-Clause License.
