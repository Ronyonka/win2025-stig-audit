#Requires -RunAsAdministrator

# Windows Server 2025 STIG Compliance Checks

$passed = 0
$failed = 0

function Write-Result($id, $message, $ok) {
$status = if ($ok) { "PASS" } else { "FAIL" }
$color  = if ($ok) { "Green" } else { "Red" }
Write-Host "[$status] $id - $message" -ForegroundColor $color
}

# -----------------------------------------------------------------------

# V-277997 | Local volumes must use NTFS or ReFS

# -----------------------------------------------------------------------

$nonCompliant = Get-Volume |
Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystemType -notin @('NTFS', 'ReFS') }

if ($nonCompliant) {
Write-Result "SV-277997" "Non-compliant volumes found:" $false
$nonCompliant | Format-Table DriveLetter, FileSystemLabel, FileSystemType -AutoSize
$failed++
} else {
Write-Result "SV-277997" "All local fixed volumes use NTFS/ReFS." $true
$passed++
}

# -----------------------------------------------------------------------

# V-277987 | Admin accounts must not run internet-facing apps

# -----------------------------------------------------------------------

$internetApps = @(
'msedge', 'chrome', 'firefox', 'iexplore', 'opera', 'brave', 'vivaldi',
'outlook', 'thunderbird', 'wlmail',
'teams', 'slack', 'discord', 'zoom'
)

try {
$adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
}
catch {
Write-Result "SV-277987r1182010" "Unable to enumerate Administrators group." $false
$failed++
$adminMembers = @()
}

$adminSIDs = $adminMembers | Select-Object -ExpandProperty SID -ErrorAction SilentlyContinue

$findings = foreach ($proc in (Get-Process -IncludeUserName -ErrorAction SilentlyContinue)) {
if ($proc.Name.ToLower() -notin $internetApps) {
    continue
}

if ([string]::IsNullOrWhiteSpace($proc.UserName)) {
    continue
}

try {
    $ntAccount = New-Object System.Security.Principal.NTAccount($proc.UserName)
    $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])

    if ($sid.Value -in $adminSIDs.Value) {
        [PSCustomObject]@{
            UserName = $proc.UserName
            Process  = $proc.Name
            PID      = $proc.Id
        }
    }
}
catch {
    continue
}

}

if ($findings) {
Write-Result "SV-277987r1182010" "Administrator accounts are running internet-facing applications." $false
$findings | Sort-Object UserName, Process | Format-Table -AutoSize
$failed++
}
else {
Write-Result "SV-277987r1182010" "No administrator accounts are running internet-facing applications." $true
$passed++
}

# -----------------------------------------------------------------------

# V-278040 | Reversible password encryption must be disabled

# -----------------------------------------------------------------------

$secpol = & secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
$secpolContent = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

$setting = $secpolContent | Where-Object { $_ -match 'ClearTextPassword' }
$value   = if ($setting -match '=\s*(\d)') { $Matches[1] } else { $null }

if ($value -eq '0') {
Write-Result "SV-278040r1180826" "Reversible password encryption is disabled." $true
$passed++
} else {
Write-Result "SV-278040r1180826" "Reversible password encryption is enabled or not configured." $false
$failed++
}

# -----------------------------------------------------------------------

# V-278099 | AutoPlay must be turned off for nonvolume devices

# -----------------------------------------------------------------------

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$valueName = "NoAutoplayfornonVolume"

try {
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName
if ($currentValue -eq 1) {
    Write-Result "SV-278099r1181003" "AutoPlay is disabled for nonvolume devices." $true
    $passed++
} else {
    Write-Result "SV-278099r1181003" "AutoPlay for nonvolume devices is not disabled (value: $currentValue)." $false
    $failed++
}

}
catch {
Write-Result "SV-278099r1181003" "Registry value NoAutoplayfornonVolume is missing." $false
$failed++
}

# -----------------------------------------------------------------------

# V-278100 | Windows Server 2025 default AutoRun behavior must be configured to prevent AutoRun commands

# -----------------------------------------------------------------------

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoAutorun"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 1) {
        Write-Result "V-278100" "Default AutoRun behavior is configured to prevent AutoRun commands." $true
        $passed++
    } else {
        Write-Result "V-278100" "Default AutoRun behavior does not prevent AutoRun commands (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278100" "Registry value NoAutorun is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278101 | Windows Server 2025 AutoPlay must be disabled for all drives

# -----------------------------------------------------------------------

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoDriveTypeAutoRun"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 255) {
        Write-Result "V-278101" "AutoPlay is disabled for all drives." $true
        $passed++
    } else {
        Write-Result "V-278101" "AutoPlay is not disabled for all drives (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278101" "Registry value NoDriveTypeAutoRun is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278121 | Windows Server 2025 must disable the Windows Installer Always install with elevated privileges option

# -----------------------------------------------------------------------

$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
)
$valueName = "AlwaysInstallElevated"
$findings = @()

foreach ($path in $regPaths) {
    try {
        $currentValue = (Get-ItemProperty -Path $path -Name $valueName -ErrorAction Stop).$valueName
        if ($currentValue -eq 1) {
            $findings += [PSCustomObject]@{
                Hive  = if ($path -like "HKLM:*") { "HKLM" } else { "HKCU" }
                Value = $currentValue
            }
        }
    }
    catch {
        continue
    }
}

if ($findings) {
    Write-Result "V-278121" "Windows Installer Always install with elevated privileges is enabled." $false
    $findings | Format-Table -AutoSize
    $failed++
} else {
    Write-Result "V-278121" "Windows Installer Always install with elevated privileges is disabled." $true
    $passed++
}

# -----------------------------------------------------------------------

# V-278125 | Windows Server 2025 Windows Remote Management (WinRM) client must not use Basic authentication

# -----------------------------------------------------------------------

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$valueName = "AllowBasic"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 0) {
        Write-Result "V-278125" "WinRM client Basic authentication is disabled." $true
        $passed++
    } else {
        Write-Result "V-278125" "WinRM client Basic authentication is enabled or not configured (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278125" "Registry value AllowBasic is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278128 | Windows Server 2025 Windows Remote Management (WinRM) service must not use Basic authentication

# -----------------------------------------------------------------------

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "AllowBasic"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 0) {
        Write-Result "V-278128" "WinRM service Basic authentication is disabled." $true
        $passed++
    } else {
        Write-Result "V-278128" "WinRM service Basic authentication is enabled or not configured (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278128" "Registry value AllowBasic is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278132 | Windows Server 2025 must only allow administrators responsible for the domain controller to have Administrator rights on the system

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278132" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    $allowedMembers = @(
        "Administrator",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins"
    )

    try {
        $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    }
    catch {
        Write-Result "V-278132" "Unable to enumerate the Administrators group." $false
        $failed++
        $adminMembers = @()
    }

    $findings = foreach ($member in $adminMembers) {
        $simpleName = ($member.Name -replace '^.*\\', '')

        if ($simpleName -notin $allowedMembers) {
            [PSCustomObject]@{
                Name = $member.Name
                SID  = $member.SID.Value
            }
        }
    }

    if ($findings) {
        Write-Result "V-278132" "Administrators group contains unauthorized members." $false
        $findings | Sort-Object Name | Format-Table -AutoSize
        $failed++
    }
    else {
        Write-Result "V-278132" "Administrators group is restricted to domain controller administrators." $true
        $passed++
    }
}

# -----------------------------------------------------------------------

# V-278177 | Windows Server 2025 must only allow administrators responsible for the member server or stand-alone or nondomain-joined system to have Administrator rights on the system

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -in 4, 5) {
    Write-Result "V-278177" "System is a domain controller; rule not applicable." $true
    $passed++
}
else {
    $allowedMembers = @(
        "Administrator",
        "Domain Admins",
        "Enterprise Admins"
    )

    try {
        $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    }
    catch {
        Write-Result "V-278177" "Unable to enumerate the Administrators group." $false
        $failed++
        $adminMembers = @()
    }

    $findings = foreach ($member in $adminMembers) {
        $simpleName = ($member.Name -replace '^.*\\', '')

        if ($simpleName -notin $allowedMembers) {
            [PSCustomObject]@{
                Name = $member.Name
                SID  = $member.SID.Value
            }
        }
    }

    if ($findings) {
        Write-Result "V-278177" "Administrators group contains unauthorized members." $false
        $findings | Sort-Object Name | Format-Table -AutoSize
        $failed++
    }
    else {
        Write-Result "V-278177" "Administrators group is restricted to member server or standalone administrators." $true
        $passed++
    }
}

# -----------------------------------------------------------------------

# V-278138 | Windows Server 2025 permissions on the Active Directory data files must only allow system administrators (SAs) access

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278138" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    $ntdsPath = Join-Path $env:SystemRoot "NTDS"
    $allowedSids = @(
        "S-1-5-18",     # NT AUTHORITY\SYSTEM
        "S-1-5-32-544"  # BUILTIN\Administrators
    )
    $targets = @()

    if (Test-Path -Path $ntdsPath) {
        $targets += $ntdsPath
        $targets += Get-ChildItem -Path $ntdsPath -Force -File -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName
    }

    if (-not $targets) {
        Write-Result "V-278138" "Active Directory data files could not be located." $false
        $failed++
    }
    else {
        $findings = foreach ($target in $targets) {
            try {
                $acl = Get-Acl -Path $target -ErrorAction Stop
            }
            catch {
                [PSCustomObject]@{
                    Path  = $target
                    Issue = "Unable to read ACL"
                }
                continue
            }

            foreach ($ace in $acl.Access) {
                try {
                    $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    [PSCustomObject]@{
                        Path  = $target
                        Issue = "Unresolvable access rule identity: $($ace.IdentityReference)"
                    }
                    continue
                }

                if ($aceSid -notin $allowedSids) {
                    [PSCustomObject]@{
                        Path    = $target
                        Identity = $ace.IdentityReference.Value
                        Rights  = $ace.FileSystemRights
                        Type    = $ace.AccessControlType
                    }
                }
            }
        }

        if ($findings) {
            Write-Result "V-278138" "Active Directory data files grant access beyond system administrators." $false
            $findings | Sort-Object Path, Identity | Format-Table -AutoSize
            $failed++
        }
        else {
            Write-Result "V-278138" "Active Directory data files are restricted to system administrators." $true
            $passed++
        }
    }
}

# -----------------------------------------------------------------------

# V-278139 | Windows Server 2025 Active Directory SYSVOL directory must have the proper access control permissions

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278139" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    $sysvolPath = Join-Path $env:SystemRoot "SYSVOL"

    if (-not (Test-Path -Path $sysvolPath)) {
        Write-Result "V-278139" "SYSVOL directory could not be located." $false
        $failed++
    }
    else {
        try {
            $acl = Get-Acl -Path $sysvolPath -ErrorAction Stop
            $findings = @()

            foreach ($ace in $acl.Access) {
                try {
                    $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    $findings += [PSCustomObject]@{
                        Identity = $ace.IdentityReference.Value
                        Issue    = "Unresolvable access rule identity"
                    }
                    continue
                }

                switch ($aceSid) {
                    "S-1-5-18" {
                        if (($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq 0) {
                            $findings += [PSCustomObject]@{
                                Identity = $ace.IdentityReference.Value
                                Issue    = "SYSTEM does not have full control"
                            }
                        }
                    }
                    "S-1-5-32-544" {
                        if (($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq 0) {
                            $findings += [PSCustomObject]@{
                                Identity = $ace.IdentityReference.Value
                                Issue    = "Administrators do not have full control"
                            }
                        }
                    }
                    "S-1-3-0" {
                        continue
                    }
                    "S-1-5-11" {
                        $writeMask = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                                     [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
                                     [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                                     [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                                     [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                                     [System.Security.AccessControl.FileSystemRights]::Delete -bor
                                     [System.Security.AccessControl.FileSystemRights]::Modify -bor
                                     [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                                     [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
                                     [System.Security.AccessControl.FileSystemRights]::FullControl

                        if (($ace.FileSystemRights -band $writeMask) -ne 0) {
                            $findings += [PSCustomObject]@{
                                Identity = $ace.IdentityReference.Value
                                Issue    = "Authenticated Users has write or administrative access"
                            }
                        }
                    }
                    default {
                        $findings += [PSCustomObject]@{
                            Identity = $ace.IdentityReference.Value
                            Issue    = "Unexpected access rule"
                        }
                    }
                }
            }

            if ($findings) {
                Write-Result "V-278139" "SYSVOL directory permissions are not properly restricted." $false
                $findings | Sort-Object Identity, Issue | Format-Table -AutoSize
                $failed++
            }
            else {
                Write-Result "V-278139" "SYSVOL directory permissions are properly restricted." $true
                $passed++
            }
        }
        catch {
            Write-Result "V-278139" "Unable to read SYSVOL directory ACL." $false
            $failed++
        }
    }
}

# -----------------------------------------------------------------------

# V-278140 | Windows Server 2025 Active Directory (AD) Group Policy Objects (GPOs) must have proper access control permissions

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278140" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    $domainName = if ($computerSystem -and $computerSystem.Domain) { $computerSystem.Domain } elseif ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { $null }

    if (-not $domainName) {
        Write-Result "V-278140" "Unable to determine the Active Directory domain name." $false
        $failed++
    }
    else {
        $policiesPath = Join-Path (Join-Path (Join-Path $env:SystemRoot "SYSVOL") "sysvol") $domainName
        $policiesPath = Join-Path $policiesPath "Policies"

        if (-not (Test-Path -Path $policiesPath)) {
            Write-Result "V-278140" "GPO policy directory could not be located." $false
            $failed++
        }
        else {
            $allowedNames = @(
                "SYSTEM",
                "Administrators",
                "Domain Admins",
                "Enterprise Admins",
                "Creator Owner",
                "Authenticated Users"
            )
            $findings = @()
            $policyFolders = Get-ChildItem -Path $policiesPath -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\{[0-9A-Fa-f-]+\}$' }

            foreach ($policyFolder in $policyFolders) {
                try {
                    $acl = Get-Acl -Path $policyFolder.FullName -ErrorAction Stop
                }
                catch {
                    $findings += [PSCustomObject]@{
                        Policy   = $policyFolder.Name
                        Identity = ""
                        Issue    = "Unable to read ACL"
                    }
                    continue
                }

                foreach ($ace in $acl.Access) {
                    $identityName = ($ace.IdentityReference.Value -replace '^.*\\', '')

                    if ($identityName -notin $allowedNames) {
                        $findings += [PSCustomObject]@{
                            Policy   = $policyFolder.Name
                            Identity = $ace.IdentityReference.Value
                            Issue    = "Unexpected access rule"
                        }
                        continue
                    }

                    switch ($identityName) {
                        "Authenticated Users" {
                            $writeMask = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                                         [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
                                         [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                                         [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                                         [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                                         [System.Security.AccessControl.FileSystemRights]::Delete -bor
                                         [System.Security.AccessControl.FileSystemRights]::Modify -bor
                                         [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                                         [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
                                         [System.Security.AccessControl.FileSystemRights]::FullControl

                            if (($ace.FileSystemRights -band $writeMask) -ne 0) {
                                $findings += [PSCustomObject]@{
                                    Policy   = $policyFolder.Name
                                    Identity = $ace.IdentityReference.Value
                                    Issue    = "Authenticated Users has write or administrative access"
                                }
                            }
                        }
                        default {
                            if (($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq 0) {
                                $findings += [PSCustomObject]@{
                                    Policy   = $policyFolder.Name
                                    Identity = $ace.IdentityReference.Value
                                    Issue    = "Administrative principal does not have full control"
                                }
                            }
                        }
                    }
                }
            }

            if ($findings) {
                Write-Result "V-278140" "GPO access control permissions are not properly restricted." $false
                $findings | Sort-Object Policy, Identity, Issue | Format-Table -AutoSize
                $failed++
            }
            else {
                Write-Result "V-278140" "GPO access control permissions are properly restricted." $true
                $passed++
            }
        }
    }
}

# -----------------------------------------------------------------------

# V-278141 | Windows Server 2025 Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278141" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $defaultNamingContext = $rootDse.defaultNamingContext
        $ouPath = "LDAP://OU=Domain Controllers,$defaultNamingContext"
        $ou = New-Object System.DirectoryServices.DirectoryEntry($ouPath)
        $null = $ou.NativeObject

        $allowedNames = @(
            "SYSTEM",
            "Administrators",
            "Domain Admins",
            "Enterprise Admins",
            "Creator Owner"
        )

        $writeRightsMask = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::Self -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

        $findings = @()
        $rules = $ou.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

        foreach ($rule in $rules) {
            $identityName = ($rule.IdentityReference.Value -replace '^.*\\', '')

            if ($identityName -notin $allowedNames) {
                if (($rule.ActiveDirectoryRights -band $writeRightsMask) -ne 0) {
                    $findings += [PSCustomObject]@{
                        Identity = $rule.IdentityReference.Value
                        Rights   = $rule.ActiveDirectoryRights
                        Issue    = "Unexpected principal has write access"
                    }
                }
                continue
            }

            if (($rule.ActiveDirectoryRights -band $writeRightsMask) -eq 0) {
                continue
            }
        }

        if ($findings) {
            Write-Result "V-278141" "Domain Controllers OU permissions are not properly restricted." $false
            $findings | Sort-Object Identity, Issue | Format-Table -AutoSize
            $failed++
        }
        else {
            Write-Result "V-278141" "Domain Controllers OU permissions are properly restricted." $true
            $passed++
        }
    }
    catch {
        Write-Result "V-278141" "Unable to read the Domain Controllers OU ACL." $false
        $failed++
    }
}

# -----------------------------------------------------------------------

# V-278142 | Windows Server 2025 organization created Active Directory Organizational Unit (OU) objects must have proper access control permissions

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278142" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $defaultNamingContext = $rootDse.defaultNamingContext
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNamingContext")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.Filter = "(objectClass=organizationalUnit)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null

        $allowedNames = @(
            "SYSTEM",
            "Administrators",
            "Domain Admins",
            "Enterprise Admins",
            "Creator Owner"
        )

        $writeRightsMask = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::Self -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

        $findings = @()
        $ous = $searcher.FindAll()

        foreach ($result in $ous) {
            $dn = $result.Properties["distinguishedname"][0]
            if ($dn -match '^OU=Domain Controllers,') {
                continue
            }

            try {
                $ouEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
                $null = $ouEntry.NativeObject
                $rules = $ouEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
            }
            catch {
                $findings += [PSCustomObject]@{
                    OU    = $dn
                    Identity = ""
                    Issue = "Unable to read ACL"
                }
                continue
            }

            foreach ($rule in $rules) {
                $identityName = ($rule.IdentityReference.Value -replace '^.*\\', '')

                if ($identityName -notin $allowedNames) {
                    if (($rule.ActiveDirectoryRights -band $writeRightsMask) -ne 0) {
                        $findings += [PSCustomObject]@{
                            OU       = $dn
                            Identity = $rule.IdentityReference.Value
                            Issue    = "Unexpected principal has write access"
                        }
                    }
                    continue
                }

                if ($identityName -eq "Creator Owner") {
                    continue
                }

                if (($rule.ActiveDirectoryRights -band $writeRightsMask) -eq 0) {
                    continue
                }
            }
        }

        if ($findings) {
            Write-Result "V-278142" "Organization-created OU permissions are not properly restricted." $false
            $findings | Sort-Object OU, Identity, Issue | Format-Table -AutoSize
            $failed++
        }
        else {
            Write-Result "V-278142" "Organization-created OU permissions are properly restricted." $true
            $passed++
        }
    }
    catch {
        Write-Result "V-278142" "Unable to enumerate Active Directory OU objects." $false
        $failed++
    }
}

# -----------------------------------------------------------------------

# V-278146 | Windows Server 2025 directory data (outside the root DSE) of a nonpublic directory must be configured to prevent anonymous access

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278146" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    try {
        $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier("localhost", 389)
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.Bind()

        $rootRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            "",
            "(objectClass=*)",
            [System.DirectoryServices.Protocols.SearchScope]::Base,
            @("defaultNamingContext")
        )
        $rootResponse = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($rootRequest)

        if ($rootResponse.Entries.Count -eq 0) {
            Write-Result "V-278146" "Anonymous access to root DSE could not be validated." $false
            $failed++
        }
        else {
            $defaultNamingContext = $rootResponse.Entries[0].Attributes["defaultNamingContext"][0]

            if (-not $defaultNamingContext) {
                Write-Result "V-278146" "Default naming context could not be determined anonymously." $false
                $failed++
            }
            else {
                try {
                    $dataRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                        $defaultNamingContext,
                        "(objectClass=*)",
                        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
                        @("distinguishedName")
                    )
                    $dataResponse = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($dataRequest)

                    if ($dataResponse.Entries.Count -gt 0) {
                        Write-Result "V-278146" "Anonymous access to directory data is permitted." $false
                        $failed++
                    }
                    else {
                        Write-Result "V-278146" "Anonymous access to directory data is prevented." $true
                        $passed++
                    }
                }
                catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
                    Write-Result "V-278146" "Anonymous access to directory data is prevented." $true
                    $passed++
                }
            }
        }
    }
    catch {
        Write-Result "V-278146" "Unable to validate anonymous LDAP access." $false
        $failed++
    }
}

# -----------------------------------------------------------------------

# V-278160 | Windows Server 2025 domain Controller PKI certificates must be issued by the DOD PKI or an approved External Certificate Authority (ECA)

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if ($computerSystem -and $computerSystem.DomainRole -notin 4, 5) {
    Write-Result "V-278160" "System is not a domain controller; rule not applicable." $true
    $passed++
}
else {
    $approvedIssuerPatterns = @(
        "DoD",
        "Department of Defense",
        "External Certificate Authority",
        "ECA"
    )

    $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object {
            $_.HasPrivateKey -and (
                $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication" -or
                $_.EnhancedKeyUsageList.FriendlyName -contains "Domain Controller Authentication"
            )
        }

    if (-not $certs) {
        Write-Result "V-278160" "No domain controller PKI certificates were found." $false
        $failed++
    }
    else {
        $findings = foreach ($cert in $certs) {
            $issuerAllowed = $false

            foreach ($pattern in $approvedIssuerPatterns) {
                if ($cert.Issuer -like "*$pattern*") {
                    $issuerAllowed = $true
                    break
                }
            }

            if (-not $issuerAllowed) {
                [PSCustomObject]@{
                    Subject = $cert.Subject
                    Issuer  = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                }
            }
        }

        if ($findings) {
            Write-Result "V-278160" "One or more domain controller PKI certificates were not issued by an approved PKI." $false
            $findings | Sort-Object Subject, Issuer | Format-Table -AutoSize
            $failed++
        }
        else {
            Write-Result "V-278160" "Domain controller PKI certificates are issued by an approved PKI." $true
            $passed++
        }
    }
}

# -----------------------------------------------------------------------

# V-278161 | Windows Server 2025 PKI certificates associated with user accounts must be issued by a DOD PKI or an approved External Certificate Authority (ECA)

# -----------------------------------------------------------------------

$approvedIssuerPatterns = @(
    "DoD",
    "Department of Defense",
    "External Certificate Authority",
    "ECA"
)

$userCerts = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object {
        $_.HasPrivateKey -and (
            $_.EnhancedKeyUsageList.FriendlyName -contains "Client Authentication" -or
            $_.EnhancedKeyUsageList.FriendlyName -contains "Smart Card Logon" -or
            $_.EnhancedKeyUsageList.FriendlyName -contains "Secure Email"
        )
    }

if (-not $userCerts) {
    Write-Result "V-278161" "No user account PKI certificates were found." $true
    $passed++
}
else {
    $findings = foreach ($cert in $userCerts) {
        $issuerAllowed = $false

        foreach ($pattern in $approvedIssuerPatterns) {
            if ($cert.Issuer -like "*$pattern*") {
                $issuerAllowed = $true
                break
            }
        }

        if (-not $issuerAllowed) {
            [PSCustomObject]@{
                Subject    = $cert.Subject
                Issuer     = $cert.Issuer
                Thumbprint = $cert.Thumbprint
            }
        }
    }

    if ($findings) {
        Write-Result "V-278161" "One or more user account PKI certificates were not issued by an approved PKI." $false
        $findings | Sort-Object Subject, Issuer | Format-Table -AutoSize
        $failed++
    }
    else {
        Write-Result "V-278161" "User account PKI certificates are issued by an approved PKI." $true
        $passed++
    }
}

# -----------------------------------------------------------------------

# V-278190 | Windows Server 2025 must be running Credential Guard on domain-joined member servers

# -----------------------------------------------------------------------

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

if (-not $computerSystem -or -not $computerSystem.PartOfDomain -or $computerSystem.DomainRole -ne 3) {
    Write-Result "V-278190" "System is not a domain-joined member server; rule not applicable." $true
    $passed++
}
else {
    $credentialGuardRunning = $false

    try {
        $deviceGuard = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction Stop
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            $credentialGuardRunning = $true
        }
    }
    catch {
        $credentialGuardRunning = $false
    }

    if (-not $credentialGuardRunning) {
        try {
            $lsaCfgFlags = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction Stop).LsaCfgFlags
            if ($lsaCfgFlags -in 1, 2) {
                $credentialGuardRunning = $true
            }
        }
        catch {
            $credentialGuardRunning = $false
        }
    }

if ($credentialGuardRunning) {
        Write-Result "V-278190" "Credential Guard is running on the domain-joined member server." $true
        $passed++
    }
    else {
        Write-Result "V-278190" "Credential Guard is not running on the domain-joined member server." $false
        $failed++
    }
}

# -----------------------------------------------------------------------

# V-278196 | Windows Server 2025 must prevent local accounts with blank passwords from being used from the network

# -----------------------------------------------------------------------

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "LimitBlankPasswordUse"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 1) {
        Write-Result "V-278196" "Local accounts with blank passwords are prevented from network use." $true
        $passed++
    } else {
        Write-Result "V-278196" "Local accounts with blank passwords can be used from the network (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278196" "Registry value LimitBlankPasswordUse is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278215 | Windows Server 2025 must not allow anonymous SID/Name translation

# -----------------------------------------------------------------------

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "AllowAnonymousSIDNameTranslation"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 0) {
        Write-Result "V-278215" "Anonymous SID/Name translation is disabled." $true
        $passed++
    } else {
        Write-Result "V-278215" "Anonymous SID/Name translation is enabled (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278215" "Registry value AllowAnonymousSIDNameTranslation is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278216 | Windows Server 2025 must not allow anonymous enumeration of Security Account Manager (SAM) accounts

# -----------------------------------------------------------------------

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "RestrictAnonymousSAM"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 1) {
        Write-Result "V-278216" "Anonymous SAM account enumeration is disabled." $true
        $passed++
    } else {
        Write-Result "V-278216" "Anonymous SAM account enumeration is enabled (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278216" "Registry value RestrictAnonymousSAM is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278217 | Windows Server 2025 must not allow anonymous enumeration of shares

# -----------------------------------------------------------------------

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "RestrictAnonymous"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 1) {
        Write-Result "V-278217" "Anonymous share enumeration is disabled." $true
        $passed++
    } else {
        Write-Result "V-278217" "Anonymous share enumeration is enabled (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278217" "Registry value RestrictAnonymous is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278225 | Windows Server 2025 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM

# -----------------------------------------------------------------------

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "LmCompatibilityLevel"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 5) {
        Write-Result "V-278225" "LAN Manager authentication level is configured to send NTLMv2 response only and refuse LM and NTLM." $true
        $passed++
    } else {
        Write-Result "V-278225" "LAN Manager authentication level is not configured correctly (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278225" "Registry value LmCompatibilityLevel is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278246 | The Windows Server 2025 "Create a token object" user right must not be assigned to any groups or accounts

# -----------------------------------------------------------------------

$secpolFile = Join-Path $env:TEMP "secpol_v278246.cfg"
& secedit /export /cfg $secpolFile /quiet | Out-Null
$secpolContent = Get-Content $secpolFile -ErrorAction SilentlyContinue
Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue

$setting = $secpolContent | Where-Object { $_ -match '^SeCreateTokenPrivilege\s*=' }
$value = if ($setting -match '=\s*(.*)$') { $Matches[1].Trim() } else { $null }

if ([string]::IsNullOrWhiteSpace($value)) {
    Write-Result "V-278246" '"Create a token object" user right is not assigned to any groups or accounts.' $true
    $passed++
} else {
    Write-Result "V-278246" "Create a token object user right is assigned (value: $value)." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278250 | The Windows Server 2025 "Debug programs" user right must only be assigned to the Administrators group

# -----------------------------------------------------------------------

$secpolFile = Join-Path $env:TEMP "secpol_v278250.cfg"
& secedit /export /cfg $secpolFile /quiet | Out-Null
$secpolContent = Get-Content $secpolFile -ErrorAction SilentlyContinue
Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue

$setting = $secpolContent | Where-Object { $_ -match '^SeDebugPrivilege\s*=' }
$value = if ($setting -match '=\s*(.*)$') { $Matches[1].Trim() } else { $null }

if ($value -eq "Administrators") {
    Write-Result "V-278250" '"Debug programs" user right is assigned only to the Administrators group.' $true
    $passed++
} elseif ([string]::IsNullOrWhiteSpace($value)) {
    Write-Result "V-278250" '"Debug programs" user right is not assigned.' $false
    $failed++
} else {
    Write-Result "V-278250" "\"Debug programs\" user right is assigned to an unauthorized account or group (value: $value)." $false
    $failed++
}

# -----------------------------------------------------------------------

# V-278219 | Windows Server 2025 must restrict anonymous access to Named Pipes and Shares

# -----------------------------------------------------------------------

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$valueName = "RestrictNullSessAccess"

try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

    if ($currentValue -eq 1) {
        Write-Result "V-278219" "Anonymous access to Named Pipes and Shares is restricted." $true
        $passed++
    } else {
        Write-Result "V-278219" "Anonymous access to Named Pipes and Shares is not restricted (value: $currentValue)." $false
        $failed++
    }
}
catch {
    Write-Result "V-278219" "Registry value RestrictNullSessAccess is missing." $false
    $failed++
}

# -----------------------------------------------------------------------

# Summary

# -----------------------------------------------------------------------

Write-Host ""
Write-Host "Results: $passed passed, $failed failed." -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })

exit $(if ($failed -gt 0) { 1 } else { 0 })
