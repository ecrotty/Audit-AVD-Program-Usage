# Retrieves user information

function Get-UserInformation {
    param (
        [string]$Username
    )

    try {
        $userInfo = Get-MgUser -Filter "UserPrincipalName eq '$Username'" -Property "DisplayName, Department" -ErrorAction Stop
        if ($userInfo) {
            return @{
                'DisplayName' = $userInfo.DisplayName
                'Department' = $userInfo.Department
            }
        } else {
            return @{
                'DisplayName' = "Not Found"
                'Department' = "Not Specified"
            }
        }
    } catch {
        Write-Verbose "Error getting user info for $Username: ${_.Exception.Message}"
        return @{
            'DisplayName' = "Not Found"
            'Department' = "Not Specified"
        }
    }
}
