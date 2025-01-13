# Script to modify Security log settings for extended retention

# Increase max log size to 1 GB
Write-Host "Increasing Security log max size to 1 GB..."
wevtutil sl Security /ms:1073741824

# Enable log retention
Write-Host "Enabling log retention..."
wevtutil sl Security /rt:true

# Set retention period to 30 days
Write-Host "Setting retention period to 30 days..."
wevtutil sl Security /rt:true /ab:true /r:true /ca:30

# Verify changes
Write-Host "Verifying changes..."
wevtutil gl Security

Write-Host "Security log settings have been updated. Please note that it will take time for logs to accumulate."
Write-Host "Monitor system performance and disk space usage after these changes."
