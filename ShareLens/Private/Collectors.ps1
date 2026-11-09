function Get-SLDfsData {
    <# DFS-Namespace: Roots, Ordner und Ziele als flache Zeilen. #>
    param(
        [string[]]$NamespacePath,
        [string]$Domain,
        [string[]]$NamespaceServer
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]

    if (-not (Get-Module -ListAvailable -Name Dfsn)) {
        $errors.Add((New-SLErrorRow -Stage 'DFS' -Target '' -Message 'PowerShell-Modul "Dfsn" fehlt (RSAT: DFS-Verwaltungstools installieren).'))
        return [pscustomobject]@{ Targets = @(); Errors = $errors.ToArray() }
    }
    Import-Module Dfsn -ErrorAction Stop -Verbose:$false

    $roots = New-Object System.Collections.Generic.List[object]
    try {
        if ($NamespacePath) {
            foreach ($ns in $NamespacePath) { foreach ($r in @(Get-DfsnRoot -Path $ns -ErrorAction Stop)) { $roots.Add($r) } }
        }
        else {
            if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
            if ($Domain) { foreach ($r in @(Get-DfsnRoot -Domain $Domain -ErrorAction Stop)) { $roots.Add($r) } }
        }
        foreach ($srv in $NamespaceServer) {
            foreach ($r in @(Get-DfsnRoot -ComputerName $srv -ErrorAction Stop)) { $roots.Add($r) }
        }
    }
    catch {
        $errors.Add((New-SLErrorRow -Stage 'DFS-Root' -Target (($NamespacePath + $Domain) -join ', ') -Message $_.Exception.Message))
    }

    $seenRoots = @{}
    foreach ($root in $roots) {
        $rootPath = $root.Path.TrimEnd('\')
        if ($seenRoots.ContainsKey($rootPath.ToUpperInvariant())) { continue }
        $seenRoots[$rootPath.ToUpperInvariant()] = $true

        try {
            foreach ($rt in @(Get-DfsnRootTarget -Path $rootPath -ErrorAction Stop)) {
                $u = Split-SLUncPath -Path $rt.TargetPath
                $rows.Add([pscustomobject]@{
                        Kind                  = 'RootTarget'
                        Namespace             = $rootPath
                        NamespaceType         = [string]$root.Type
                        DfsPath               = $rootPath
                        FolderState           = [string]$root.State
                        Description           = $root.Description
                        TargetPath            = $rt.TargetPath
                        TargetServer          = $(if ($u) { $u.Host } else { '' })
                        TargetShare           = $(if ($u) { $u.Share } else { '' })
                        TargetSubPath         = $(if ($u) { $u.SubPath } else { '' })
                        TargetState           = [string]$rt.State
                        ReferralPriorityClass = [string]$rt.ReferralPriorityClass
                        ReferralPriorityRank  = $rt.ReferralPriorityRank
                    })
            }
        }
        catch { $errors.Add((New-SLErrorRow -Stage 'DFS-RootTarget' -Target $rootPath -Message $_.Exception.Message)) }

        $folders = @()
        try { $folders = @(Get-DfsnFolder -Path ($rootPath + '\*') -ErrorAction Stop) }
        catch { $errors.Add((New-SLErrorRow -Stage 'DFS-Folder' -Target $rootPath -Message $_.Exception.Message)) }

        foreach ($folder in $folders) {
            $targets = @()
            try { $targets = @(Get-DfsnFolderTarget -Path $folder.Path -ErrorAction Stop) }
            catch { $errors.Add((New-SLErrorRow -Stage 'DFS-FolderTarget' -Target $folder.Path -Message $_.Exception.Message)) }

            if (-not $targets) {
                $rows.Add([pscustomobject]@{
                        Kind = 'FolderTarget'; Namespace = $rootPath; NamespaceType = [string]$root.Type; DfsPath = $folder.Path
                        FolderState = [string]$folder.State; Description = $folder.Description; TargetPath = ''; TargetServer = ''
                        TargetShare = ''; TargetSubPath = ''; TargetState = 'KeinZiel'; ReferralPriorityClass = ''; ReferralPriorityRank = $null
                    })
            }
            foreach ($t in $targets) {
                $u = Split-SLUncPath -Path $t.TargetPath
                $rows.Add([pscustomobject]@{
                        Kind                  = 'FolderTarget'
                        Namespace             = $rootPath
                        NamespaceType         = [string]$root.Type
                        DfsPath               = $folder.Path
                        FolderState           = [string]$folder.State
                        Description           = $folder.Description
                        TargetPath            = $t.TargetPath
                        TargetServer          = $(if ($u) { $u.Host } else { '' })
                        TargetShare           = $(if ($u) { $u.Share } else { '' })
                        TargetSubPath         = $(if ($u) { $u.SubPath } else { '' })
                        TargetState           = [string]$t.State
                        ReferralPriorityClass = [string]$t.ReferralPriorityClass
                        ReferralPriorityRank  = $t.ReferralPriorityRank
                    })
            }
        }
    }

    [pscustomobject]@{ Targets = $rows.ToArray(); Errors = $errors.ToArray() }
}

function Get-SLDfsReplicationData {
    param([string]$Domain)

    $rows = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Module -ListAvailable -Name DFSR)) {
        $errors.Add((New-SLErrorRow -Stage 'DFSR' -Target '' -Message 'PowerShell-Modul "DFSR" fehlt (RSAT: DFS-Verwaltungstools installieren).'))
        return [pscustomobject]@{ Rows = @(); Errors = $errors.ToArray() }
    }
    Import-Module DFSR -ErrorAction Stop -Verbose:$false
    if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
    try {
        foreach ($g in @(Get-DfsReplicationGroup -DomainName $Domain -ErrorAction Stop)) {
            try {
                foreach ($m in @(Get-DfsrMembership -GroupName $g.GroupName -DomainName $Domain -ErrorAction Stop)) {
                    $rows.Add([pscustomobject]@{
                            GroupName     = $m.GroupName
                            FolderName    = $m.FolderName
                            ComputerName  = $m.ComputerName
                            ContentPath   = $m.ContentPath
                            PrimaryMember = $m.PrimaryMember
                            ReadOnly      = $m.ReadOnly
                            Enabled       = $m.Enabled
                            StagingQuotaMB = $m.StagingPathQuotaInMB
                            GroupState    = [string]$g.State
                        })
                }
            }
            catch { $errors.Add((New-SLErrorRow -Stage 'DFSR-Membership' -Target $g.GroupName -Message $_.Exception.Message)) }
        }
    }
    catch { $errors.Add((New-SLErrorRow -Stage 'DFSR' -Target $Domain -Message $_.Exception.Message)) }
    [pscustomobject]@{ Rows = $rows.ToArray(); Errors = $errors.ToArray() }
}

function ConvertFrom-SLShareSddl {
    <# Freigabe-Sicherheitsbeschreibung (SDDL) in Zeilen wandeln. Leere DACL = Jeder Vollzugriff. #>
    param([string]$Sddl, [string]$ComputerName)

    if (-not $Sddl) {
        return [pscustomobject]@{ AccountName = 'Jeder'; Sid = 'S-1-1-0'; AccessControlType = 'Allow'; AccessRight = 'Full'; Mask = $script:SLMaskFull }
    }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -eq $sd.DiscretionaryAcl) {
        return [pscustomobject]@{ AccountName = 'Jeder'; Sid = 'S-1-1-0'; AccessControlType = 'Allow'; AccessRight = 'Full'; Mask = $script:SLMaskFull }
    }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) { continue }
        $sid = $ace.SecurityIdentifier.Value
        $name = Resolve-SLSidName -Sid $sid -ComputerName $ComputerName
        if (-not $name) { $name = $sid }
        $right = ConvertTo-SLShareRight -AccessMask ([int64]$ace.AccessMask)
        [pscustomobject]@{
            AccountName       = $name
            Sid               = $sid
            AccessControlType = $(if ([string]$ace.AceQualifier -eq 'AccessDenied') { 'Deny' } else { 'Allow' })
            AccessRight       = $right
            Mask              = (Get-SLShareMask -AccessRight $right -RawMask ([int64]$ace.AccessMask))
        }
    }
}

function Get-SLShareData {
    <#
      Freigaben + Freigabeberechtigungen eines Servers.
      Bevorzugt MSFT_SmbShare (Server 2012+), Fallback Win32_Share (2008/2008 R2).
      Cluster: UNC wird mit dem ScopeName (Clientzugriffspunkt) gebildet.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string[]]$ShareName = @('*'),
        [string[]]$ExcludeShare,
        [switch]$IncludeAdministrative,
        [pscredential]$Credential
    )

    $shares = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]

    $session = $null
    $cimArgs = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
    if ($Credential) { $cimArgs.Credential = $Credential }
    try { $session = New-CimSession @cimArgs }
    catch {
        try { $session = New-CimSession @cimArgs -SessionOption (New-CimSessionOption -Protocol Dcom) }
        catch {
            $errors.Add((New-SLErrorRow -Stage 'Freigaben' -Target $ComputerName -Message "CIM/WinRM und DCOM fehlgeschlagen: $($_.Exception.Message)"))
            return [pscustomobject]@{ Shares = @(); Errors = $errors.ToArray() }
        }
    }

    function Test-SLShareFilter([string]$Name) {
        $include = $false
        foreach ($p in $ShareName) { if ($Name -like $p) { $include = $true } }
        foreach ($p in $ExcludeShare) { if ($Name -like $p) { $include = $false } }
        $include
    }

    try {
        $smb = $null
        try { $smb = @(Get-CimInstance -CimSession $session -Namespace 'root/Microsoft/Windows/SMB' -ClassName MSFT_SmbShare -ErrorAction Stop) }
        catch { $smb = $null }

        if ($null -ne $smb) {
            foreach ($s in $smb) {
                if ($s.Special -and -not $IncludeAdministrative) { continue }
                if ($s.ShareType -ne 0) { continue }   # 0 = FileSystemDirectory
                if (-not (Test-SLShareFilter $s.Name)) { continue }

                $uncHost = $ComputerName
                if ($s.ScopeName -and $s.ScopeName -ne '*') { $uncHost = $s.ScopeName }
                $access = New-Object System.Collections.Generic.List[object]
                try {
                    # SDDL direkt aus MSFT_SmbShare – liefert SIDs, kein lokales SmbShare-Modul nötig
                    foreach ($a in @(ConvertFrom-SLShareSddl -Sddl $s.SecurityDescriptor -ComputerName $ComputerName)) { $access.Add($a) }
                }
                catch { $errors.Add((New-SLErrorRow -Stage 'Freigabe-Rechte' -Target "\\$uncHost\$($s.Name)" -Message $_.Exception.Message)) }

                $shares.Add([pscustomobject]@{
                        ComputerName          = $ComputerName
                        ScopeName             = $s.ScopeName
                        ShareName             = $s.Name
                        ShareUnc              = "\\$uncHost\$($s.Name)"
                        LocalPath             = $s.Path
                        Description           = $s.Description
                        Special               = [bool]$s.Special
                        ContinuouslyAvailable = [bool]$s.ContinuouslyAvailable
                        EncryptData           = [bool]$s.EncryptData
                        AccessBasedEnumeration = ([int]$s.FolderEnumerationMode -eq 0)
                        CachingMode           = (@('None', 'Manual', 'Documents', 'Programs', 'BranchCache', 'Unknown')[[Math]::Min([int]$s.CachingMode, 5)])
                        ConcurrentUserLimit   = $s.ConcurrentUserLimit
                        CurrentUsers          = $s.CurrentUsers
                        Source                = 'MSFT_SmbShare'
                        Access                = $access.ToArray()
                    })
            }
        }
        else {
            foreach ($s in @(Get-CimInstance -CimSession $session -ClassName Win32_Share -ErrorAction Stop)) {
                $type = [int64]$s.Type
                $special = [bool]($type -band [int64]2147483648)
                if ($special -and -not $IncludeAdministrative) { continue }
                if (($type -band 0xFF) -ne 0) { continue }   # nur Datenträger
                if (-not (Test-SLShareFilter $s.Name)) { continue }

                $access = New-Object System.Collections.Generic.List[object]
                try {
                    $setting = Get-CimInstance -CimSession $session -ClassName Win32_LogicalShareSecuritySetting -Filter "Name='$($s.Name -replace "'", "''")'" -ErrorAction Stop
                    $sd = (Invoke-CimMethod -InputObject $setting -MethodName GetSecurityDescriptor -ErrorAction Stop).Descriptor
                    if (-not $sd.DACL) {
                        $access.Add([pscustomobject]@{ AccountName = 'Jeder'; Sid = 'S-1-1-0'; AccessControlType = 'Allow'; AccessRight = 'Full'; Mask = $script:SLMaskFull })
                    }
                    foreach ($ace in @($sd.DACL)) {
                        $acct = $ace.Trustee.Name
                        if ($ace.Trustee.Domain) { $acct = "$($ace.Trustee.Domain)\$($ace.Trustee.Name)" }
                        $right = ConvertTo-SLShareRight -AccessMask ([int64]$ace.AccessMask)
                        $access.Add([pscustomobject]@{
                                AccountName       = $acct
                                Sid               = $ace.Trustee.SIDString
                                AccessControlType = $(if ([int]$ace.AceType -eq 1) { 'Deny' } else { 'Allow' })
                                AccessRight       = $right
                                Mask              = (Get-SLShareMask -AccessRight $right -RawMask ([int64]$ace.AccessMask))
                            })
                    }
                }
                catch { $errors.Add((New-SLErrorRow -Stage 'Freigabe-Rechte' -Target "\\$ComputerName\$($s.Name)" -Message $_.Exception.Message)) }

                $shares.Add([pscustomobject]@{
                        ComputerName = $ComputerName; ScopeName = ''; ShareName = $s.Name; ShareUnc = "\\$ComputerName\$($s.Name)"
                        LocalPath = $s.Path; Description = $s.Description; Special = $special; ContinuouslyAvailable = $false
                        EncryptData = $false; AccessBasedEnumeration = $null; CachingMode = ''; ConcurrentUserLimit = $s.MaximumAllowed
                        CurrentUsers = $null; Source = 'Win32_Share'; Access = $access.ToArray()
                    })
            }
        }
    }
    catch { $errors.Add((New-SLErrorRow -Stage 'Freigaben' -Target $ComputerName -Message $_.Exception.Message)) }
    finally { if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue } }

    [pscustomobject]@{ Shares = $shares.ToArray(); Errors = $errors.ToArray() }
}

function ConvertTo-SLAceRow {
    <# Eine FileSystemAccessRule (mit SID als IdentityReference) in eine Berichtszeile wandeln. #>
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth,
        [string]$ComputerName
    )

    $sid = [string]$Rule.IdentityReference.Value
    $name = Resolve-SLSidName -Sid $sid -ComputerName $ComputerName
    $category = Get-SLSidCategory -Sid $sid
    if (-not $name) {
        $name = $sid
        if ($category -eq 'Normal' -and $sid -match '^S-1-5-21-') { $category = 'Orphaned' }
    }
    $mask = ConvertTo-SLRightsMask -Rights $Rule.FileSystemRights
    $applies = Get-SLAppliesTo -InheritanceFlags $Rule.InheritanceFlags -PropagationFlags $Rule.PropagationFlags

    [pscustomobject]@{
        Path                = $Path
        Depth               = $Depth
        Identity            = $name
        IdentitySid         = $sid
        Category            = $category
        AccessType          = [string]$Rule.AccessControlType
        Level               = (Get-SLLevelName -Mask $mask)
        Rights              = [string]$Rule.FileSystemRights
        RightsMask          = $mask
        Inherited           = [bool]$Rule.IsInherited
        AppliesTo           = $applies.Text
        AppliesToThisFolder = $applies.AppliesToFolder
        InheritanceFlags    = [string]$Rule.InheritanceFlags
        PropagationFlags    = [string]$Rule.PropagationFlags
    }
}

function Invoke-SLNtfsScan {
    <#
      Liest NTFS-ACLs ab einem Startpfad bis zur angegebenen Tiefe.
      "Grenzordner" (Startordner, Vererbung unterbrochen oder explizite ACEs) bekommen alle ACEs,
      übrige Ordner nur mit -IncludeInherited – so bleibt der Bericht lesbar (Ansatz wie FolderSecurityViewer).
    #>
    param(
        [Parameter(Mandatory)][string]$Root,
        [int]$Depth = 2,
        [switch]$IncludeInherited,
        [string]$ComputerName,
        [hashtable]$Seen
    )

    $folders = New-Object System.Collections.Generic.List[object]
    $aces = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Seen) { $Seen = @{} }
    $sidType = [System.Security.Principal.SecurityIdentifier]

    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($Root.TrimEnd('\'), 0))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $path = [string]$item[0]
        $d = [int]$item[1]
        $seenKey = $path.ToUpperInvariant()
        $alreadySeen = $Seen.ContainsKey($seenKey)

        if (-not $alreadySeen) {
            $Seen[$seenKey] = $true
            try {
                $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                $rules = @($acl.GetAccessRules($true, $true, $sidType))
                $explicit = @($rules | Where-Object { -not $_.IsInherited }).Count
                $protected = [bool]$acl.AreAccessRulesProtected
                $isBoundary = ($d -eq 0) -or $protected -or ($explicit -gt 0)
                $ownerSid = $null
                try { $ownerSid = $acl.GetOwner($sidType).Value } catch { $ownerSid = $null }
                $ownerName = Resolve-SLSidName -Sid $ownerSid -ComputerName $ComputerName
                if (-not $ownerName) { $ownerName = $ownerSid }

                $folders.Add([pscustomobject]@{
                        Path                 = $path
                        Depth                = $d
                        Owner                = $ownerName
                        OwnerSid             = $ownerSid
                        InheritanceProtected = $protected
                        ExplicitAceCount     = $explicit
                        AceCount             = $rules.Count
                        IsBoundary           = $isBoundary
                    })

                if ($isBoundary -or $IncludeInherited) {
                    foreach ($rule in $rules) {
                        $aces.Add((ConvertTo-SLAceRow -Rule $rule -Path $path -Depth $d -ComputerName $ComputerName))
                    }
                }
            }
            catch {
                $errors.Add((New-SLErrorRow -Stage 'NTFS-ACL' -Target $path -Message $_.Exception.Message))
                continue
            }
        }

        if ($d -lt $Depth) {
            try {
                $children = @(Get-ChildItem -LiteralPath $path -Directory -Force -ErrorAction Stop |
                        Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } |
                        Sort-Object Name -Descending)
                foreach ($c in $children) { $stack.Push(@($c.FullName, ($d + 1))) }
            }
            catch {
                $errors.Add((New-SLErrorRow -Stage 'Ordnerliste' -Target $path -Message $_.Exception.Message))
            }
        }
    }

    [pscustomobject]@{ Folders = $folders.ToArray(); Aces = $aces.ToArray(); Errors = $errors.ToArray() }
}
