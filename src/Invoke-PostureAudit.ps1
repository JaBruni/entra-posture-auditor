#Get stale accounts
function Get-StaleAccounts {
  param([int]$DaysInactive = 90)

  $cutoff = (Get-Date).AddDays(-$DaysInactive)
  $users  = Get-MgUser -All -Property `
    "Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity"

  $users | Where-Object {
    $_.AccountEnabled -and
    $_.SignInActivity.LastSignInDateTime -and
    $_.SignInActivity.LastSignInDateTime -lt $cutoff
  } | Select-Object DisplayName, UserPrincipalName,
      @{N="LastSignIn";E={$_.SignInActivity.LastSignInDateTime}}
}

#MFA gaps
function Get-MfaGaps {
  Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
    Where-Object { -not $_.IsMfaRegistered } |
    Select-Object UserPrincipalName, UserDisplayName, IsMfaRegistered, IsMfaCapable, IsAdmin
}

#Over-privileged accounts
function Get-PrivilegedAccounts {
  $privileged = @(
    "Global Administrator","Privileged Role Administrator",
    "User Administrator","Security Administrator",
    "Exchange Administrator","SharePoint Administrator"
  )

  $roles = Get-MgDirectoryRole -All
  foreach ($role in $roles) {
    if ($privileged -contains $role.DisplayName) {
      Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id | ForEach-Object {
        $member = Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue
        [PSCustomObject]@{
          Role = $role.DisplayName
          User = if ($member) { $member.UserPrincipalName } else { $_.Id }
        }
      }
    }
  }
}

#Password never expires
function Get-PasswordNeverExpires {
  Get-MgUser -All -Property "DisplayName,UserPrincipalName,PasswordPolicies" |
    Where-Object { $_.PasswordPolicies -match "DisablePasswordExpiration" } |
    Select-Object DisplayName, UserPrincipalName, PasswordPolicies
}

#Guest account hygiene
function Get-GuestRisks {
  Get-MgUser -All -Filter "userType eq 'Guest'" `
    -Property "DisplayName,UserPrincipalName,AccountEnabled,ExternalUserState" |
    Select-Object DisplayName, UserPrincipalName, AccountEnabled, ExternalUserState
}

function Get-DeviceRisks {
  param([int]$StaleDays = 30)

  $devices = Get-MgDeviceManagementManagedDevice -All
  $cutoff  = (Get-Date).AddDays(-$StaleDays)

  $nonCompliant = $devices |
    Where-Object { $_.ComplianceState -ne "compliant" } |
    Select-Object DeviceName, UserPrincipalName,
                  OperatingSystem, ComplianceState, LastSyncDateTime

  $stale = $devices |
    Where-Object { $_.LastSyncDateTime -lt $cutoff } |
    Select-Object DeviceName, UserPrincipalName, LastSyncDateTime

  [PSCustomObject]@{
    NonCompliant = $nonCompliant
    Stale        = $stale
  }
}