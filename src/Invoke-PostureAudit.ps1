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
  # Live check — reads each user's registered auth methods directly (no report latency).
  # Requires UserAuthenticationMethod.Read.All
  $strongMethods = @(
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
    "#microsoft.graph.phoneAuthenticationMethod",
    "#microsoft.graph.fido2AuthenticationMethod",
    "#microsoft.graph.softwareOathAuthenticationMethod",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"
  )

  $users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled" |
           Where-Object { $_.AccountEnabled }

  foreach ($user in $users) {
    $methods     = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
    $methodTypes = $methods | ForEach-Object { $_.AdditionalProperties["@odata.type"] }
    $hasMfa      = $methodTypes | Where-Object { $strongMethods -contains $_ }

    if (-not $hasMfa) {
      [PSCustomObject]@{
        DisplayName       = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        RegisteredMethods = (($methodTypes -replace '#microsoft.graph.', '') -join ', ')
      }
    }
  }
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

function Get-PostureScore {
  param($Findings)

  $score = 100
  $score -= ($Findings.MfaGaps.Count        * 3)
  $score -= ($Findings.Privileged.Count     * 4)
  $score -= ($Findings.Stale.Count          * 2)
  $score -= ($Findings.NeverExpire.Count    * 2)
  $score -= ($Findings.NonCompliant.Count   * 3)
  [Math]::Max($score, 0)
}

function Export-AuditReport {
  param($Findings, $Score, $Path = "reports/report.html")

  $css = "<style>body{font-family:Segoe UI,Arial;margin:24px;}" +
         "h1{color:#16213e;} h2{color:#2a3a6b;border-bottom:1px solid #ccc;}" +
         "table{border-collapse:collapse;width:100%;} " +
         "th,td{border:1px solid #ccc;padding:6px;font-size:13px;} " +
         "th{background:#2f3c63;color:#fff;} " +
         ".score{font-size:42px;font-weight:bold;}</style>"

  $html  = "<html><head>$css</head><body>"
  $html += "<h1>Tenant Security Posture Report</h1>"
  $html += "<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>"
  $html += "<p class='score'>Score: $Score / 100</p>"
  $html += "<h2>MFA Gaps</h2>"             + ($Findings.MfaGaps     | ConvertTo-Html -Fragment)
  $html += "<h2>Privileged Accounts</h2>"  + ($Findings.Privileged  | ConvertTo-Html -Fragment)
  $html += "<h2>Stale Accounts</h2>"       + ($Findings.Stale       | ConvertTo-Html -Fragment)
  $html += "<h2>Password Never Expires</h2>" + ($Findings.NeverExpire | ConvertTo-Html -Fragment)
  $html += "<h2>Non-Compliant Devices</h2>"  + ($Findings.NonCompliant | ConvertTo-Html -Fragment)
  $html += "</body></html>"

  $html | Out-File -FilePath $Path -Encoding utf8
  Write-Host "Report written to $Path"
}

# Invoke-PostureAudit.ps1 (main run block, after the functions)

$findings = [PSCustomObject]@{
  MfaGaps      = Get-MfaGaps
  Privileged   = Get-PrivilegedAccounts
  Stale        = Get-StaleAccounts
  NeverExpire  = Get-PasswordNeverExpires
  Guests       = Get-GuestRisks
  NonCompliant = (Get-DeviceRisks).NonCompliant
}

$score = Get-PostureScore -Findings $findings
Export-AuditReport -Findings $findings -Score $score

# Optional: raw CSV evidence per category
$findings.MfaGaps    | Export-Csv "reports/mfa_gaps.csv"   -NoTypeInformation
$findings.Privileged | Export-Csv "reports/privileged.csv" -NoTypeInformation