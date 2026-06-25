# Seed-TestTenant.ps1
# Populates a sandbox tenant with test users and deliberate security gaps
# so the posture auditor has findings to catch. Demo #1: write access to Graph.

# --- Connect with write scopes ---
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","RoleManagement.ReadWrite.Directory"

# --- Get the tenant's default domain ---
$Domain = (Get-MgOrganization).VerifiedDomains |
          Where-Object { $_.IsDefault } |
          Select-Object -ExpandProperty Name

# --- Create 15 test users ---
$PasswordProfile = @{
  Password = "TempP@ssw0rd!2026"
  ForceChangePasswordNextSignIn = $true
}

1..15 | ForEach-Object {
  $nick = "testuser$_"
  New-MgUser -DisplayName "Test User $_" `
             -UserPrincipalName "$nick@$Domain" `
             -MailNickname $nick `
             -AccountEnabled:$true `
             -PasswordProfile $PasswordProfile
  Write-Host "Created $nick@$Domain"
}

# --- Plant findings on purpose ---
# Password never expires
"testuser3","testuser4" | ForEach-Object {
  Update-MgUser -UserId "$_@$Domain" -PasswordPolicies "DisablePasswordExpiration"
}

# Over-privileged account
$roleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'User Administrator'"
$target  = Get-MgUser -UserId "testuser1@$Domain"
New-MgRoleManagementDirectoryRoleAssignment `
    -PrincipalId      $target.Id `
    -RoleDefinitionId $roleDef.Id `
    -DirectoryScopeId "/"

Write-Host "Seeding complete."