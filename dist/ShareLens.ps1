# ShareLens 0.1.0 – Einzeldatei-Build (generiert von tools/Build-SingleFile.ps1, nicht bearbeiten)
# Laden:  irm https://raw.githubusercontent.com/ichabot/sharelense/main/dist/ShareLens.ps1 | iex
if (Get-Module ShareLens) { Remove-Module ShareLens -Force }
New-Module -Name ShareLens -ScriptBlock {
$script:SLVersion = '0.1.0'
# ---- Private/Analysis.ps1
function Get-SLPrincipalMasks {
    <#
      Fasst ACEs (NTFS oder Freigabe) pro aufgelöstem Konto zusammen.
      Breite Gruppen (Jeder, Authentifizierte Benutzer, Domänen-Benutzer ...) werden separat
      akkumuliert und später jedem Konto zugeschlagen.
      Entries: Context, Sid, Name, Category, Type (Allow/Deny), Mask
    #>
    param([object[]]$Entries, [hashtable]$Members, [switch]$IncludeSystem)

    $principals = @{}
    $broadAllow = [int64]0
    $broadDeny = [int64]0
    $broadVia = New-Object System.Collections.Generic.List[string]

    foreach ($e in $Entries) {
        if ($e.Category -eq 'System' -and -not $IncludeSystem) { continue }
        $key = "$($e.Context)|$($e.Sid)"
        $leafs = $null
        if ($Members -and $Members.ContainsKey($key)) { $leafs = @($Members[$key]) }
        if ($null -eq $leafs) {
            switch ($e.Category) {
                'Broad' { $cls = 'broad' }
                'System' { $cls = 'system' }
                'Orphaned' { $cls = 'orphaned' }
                default { $cls = 'principal' }
            }
            $leafs = @(New-SLLeaf -Sid $e.Sid -Account $e.Name -ObjectClass $cls)
        }
        $isDeny = ($e.Type -eq 'Deny')
        $mask = [int64]$e.Mask

        foreach ($leaf in $leafs) {
            if ($leaf.ObjectClass -eq 'system' -and -not $IncludeSystem) { continue }
            if (@($leaf.Via).Count -gt 0) { $via = (@($leaf.Via) -join ' > ') } else { $via = 'direkt' }
            if ($isDeny) { $via = "VERWEIGERT: $via" }

            $pk = $leaf.Sid
            if (-not $pk) { $pk = $leaf.Account }
            if (-not $principals.ContainsKey($pk)) {
                $principals[$pk] = [pscustomobject]@{
                    Leaf  = $leaf
                    Allow = [int64]0
                    Deny  = [int64]0
                    Via   = (New-Object System.Collections.Generic.List[string])
                }
            }
            $st = $principals[$pk]
            if ($isDeny) { $st.Deny = $st.Deny -bor $mask } else { $st.Allow = $st.Allow -bor $mask }
            if (-not $st.Via.Contains($via)) { $st.Via.Add($via) }

            if ($leaf.ObjectClass -eq 'broad') {
                if ($isDeny) { $broadDeny = $broadDeny -bor $mask } else { $broadAllow = $broadAllow -bor $mask }
                $bv = $leaf.Account
                if ($isDeny) { $bv = "VERWEIGERT: $bv" }
                if (-not $broadVia.Contains($bv)) { $broadVia.Add($bv) }
            }
        }
    }

    [pscustomobject]@{
        Principals = $principals
        BroadAllow = $broadAllow
        BroadDeny  = $broadDeny
        BroadVia   = $broadVia.ToArray()
    }
}

function New-SLAccessMatrix {
    <#
      Effektiver Zugriff je Konto an jedem Grenzordner:
      effektiv = (NTFS erlaubt ohne NTFS verweigert) ∩ (Freigabe erlaubt ohne Freigabe verweigert)
      Folders: Path, DfsPath, ShareUnc, ShareKey, IsBoundary
      Aces:    Path, Context, IdentitySid, Identity, Category, AccessType, RightsMask, AppliesToThisFolder
      ShareAccess: ShareKey, Context, IdentitySid, Identity, Category, AccessType, Mask
    #>
    param(
        [object[]]$Folders,
        [object[]]$Aces,
        [object[]]$ShareAccess,
        [hashtable]$Members,
        [string[]]$UserProperty = @(),
        [switch]$IncludeSystem
    )

    $acesByPath = @{}
    foreach ($a in $Aces) {
        $k = $a.Path.ToUpperInvariant()
        if (-not $acesByPath.ContainsKey($k)) { $acesByPath[$k] = New-Object System.Collections.Generic.List[object] }
        $acesByPath[$k].Add($a)
    }
    $shareByKey = @{}
    foreach ($s in $ShareAccess) {
        if (-not $s.ShareKey) { continue }
        if (-not $shareByKey.ContainsKey($s.ShareKey)) { $shareByKey[$s.ShareKey] = New-Object System.Collections.Generic.List[object] }
        $shareByKey[$s.ShareKey].Add($s)
    }
    $shareStates = @{}
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($f in $Folders) {
        if (-not $f.IsBoundary) { continue }
        $fAces = $acesByPath[$f.Path.ToUpperInvariant()]
        if (-not $fAces) { continue }

        $entries = foreach ($a in $fAces) {
            if (-not $a.AppliesToThisFolder) { continue }
            [pscustomobject]@{ Context = $a.Context; Sid = $a.IdentitySid; Name = $a.Identity; Category = $a.Category; Type = $a.AccessType; Mask = $a.RightsMask }
        }
        $ntfs = Get-SLPrincipalMasks -Entries @($entries) -Members $Members -IncludeSystem:$IncludeSystem

        $share = $null
        if ($f.ShareKey -and $shareByKey.ContainsKey($f.ShareKey)) {
            if (-not $shareStates.ContainsKey($f.ShareKey)) {
                $sEntries = foreach ($s in $shareByKey[$f.ShareKey]) {
                    [pscustomobject]@{ Context = $s.Context; Sid = $s.IdentitySid; Name = $s.Identity; Category = $s.Category; Type = $s.AccessType; Mask = $s.Mask }
                }
                $shareStates[$f.ShareKey] = Get-SLPrincipalMasks -Entries @($sEntries) -Members $Members -IncludeSystem
            }
            $share = $shareStates[$f.ShareKey]
        }

        foreach ($pk in $ntfs.Principals.Keys) {
            $st = $ntfs.Principals[$pk]
            $leaf = $st.Leaf
            $isBroad = ($leaf.ObjectClass -eq 'broad')

            $nA = $st.Allow
            $nD = $st.Deny
            $viaN = New-Object System.Collections.Generic.List[string]
            foreach ($v in $st.Via) { $viaN.Add($v) }
            if (-not $isBroad) {
                $nA = $nA -bor $ntfs.BroadAllow
                $nD = $nD -bor $ntfs.BroadDeny
                foreach ($v in $ntfs.BroadVia) { if (-not $viaN.Contains($v)) { $viaN.Add($v) } }
            }
            if ($nA -eq 0 -and $nD -eq 0) { continue }

            if ($share) {
                $sA = $share.BroadAllow
                $sD = $share.BroadDeny
                $viaS = New-Object System.Collections.Generic.List[string]
                foreach ($v in $share.BroadVia) { $viaS.Add($v) }
                if (-not $isBroad -and $share.Principals.ContainsKey($pk)) {
                    $sp = $share.Principals[$pk]
                    $sA = $sA -bor $sp.Allow
                    $sD = $sD -bor $sp.Deny
                    foreach ($v in $sp.Via) { if (-not $viaS.Contains($v)) { $viaS.Add($v) } }
                }
                $shareEff = $sA -band (-bnot $sD)
                $shareLevel = Get-SLLevelName -Mask $shareEff
                $viaShare = $viaS -join ' | '
            }
            else {
                $shareEff = $script:SLMaskFull
                $sD = [int64]0
                $shareLevel = '(unbekannt)'
                $viaShare = ''
            }

            $ntfsEff = $nA -band (-bnot $nD)
            $eff = $ntfsEff -band $shareEff
            $rank = Get-SLLevelRank -Mask $eff

            $row = [ordered]@{
                Path           = $f.Path
                DfsPath        = $f.DfsPath
                ShareUnc       = $f.ShareUnc
                Principal      = $leaf.Account
                DisplayName    = $leaf.DisplayName
                ObjectClass    = $leaf.ObjectClass
                Enabled        = $leaf.Enabled
                EffectiveLevel = $script:SLLevelNames[$rank]
                EffectiveRank  = $rank
                NtfsLevel      = (Get-SLLevelName -Mask $ntfsEff)
                ShareLevel     = $shareLevel
                HasDeny        = (($nD -ne 0) -or ($sD -ne 0))
                ViaNtfs        = ($viaN -join ' | ')
                ViaShare       = $viaShare
                PrincipalSid   = $leaf.Sid
            }
            foreach ($p in $UserProperty) {
                $val = ''
                if ($leaf.Properties -and $leaf.Properties.ContainsKey($p)) { $val = $leaf.Properties[$p] }
                $row["AD_$p"] = $val
            }
            $rows.Add([pscustomobject]$row)
        }
    }

    $rows | Sort-Object Path, @{ Expression = 'EffectiveRank'; Descending = $true }, Principal
}

function Get-SLFindings {
    <# Auffälligkeiten aus dem Bericht ableiten. #>
    param([Parameter(Mandatory)]$Report)

    $out = New-Object System.Collections.Generic.List[object]
    function Add-Finding([string]$Severity, [string]$Category, [string]$Object, [string]$Detail) {
        $out.Add([pscustomobject]@{ Severity = $Severity; Category = $Category; Object = $Object; Detail = $Detail })
    }
    $levelRank = { param($name) [array]::IndexOf($script:SLLevelNames, [string]$name) }

    # DFS
    $dfsFolders = @($Report.Dfs | Where-Object { $_.Kind -eq 'FolderTarget' }) | Group-Object DfsPath
    foreach ($g in $dfsFolders) {
        $online = @($g.Group | Where-Object { $_.TargetState -eq 'Online' })
        if ($online.Count -eq 0) {
            Add-Finding 'Hoch' 'DFS' $g.Name 'Kein DFS-Ziel online – Pfad für Clients nicht erreichbar.'
        }
        else {
            foreach ($t in @($g.Group | Where-Object { $_.TargetState -ne 'Online' })) {
                Add-Finding 'Mittel' 'DFS' $g.Name "DFS-Ziel nicht online: $($t.TargetPath) ($($t.TargetState))."
            }
        }
    }

    # NTFS
    foreach ($a in @($Report.Aces)) {
        $relevant = (-not $a.Inherited) -or ($a.Depth -eq 0)
        if (-not $relevant) { continue }
        $rank = & $levelRank $a.Level

        if ($a.AccessType -eq 'Allow' -and $a.Category -eq 'Broad' -and $rank -ge 3) {
            Add-Finding 'Hoch' 'NTFS breit' $a.Path "$($a.Identity) hat '$($a.Level)' ($($a.AppliesTo))."
        }
        if ($a.Inherited) { continue }
        if ($a.Category -eq 'Orphaned') {
            Add-Finding 'Mittel' 'Verwaiste SID' $a.Path "Nicht auflösbare SID $($a.IdentitySid) mit '$($a.Level)'."
        }
        if ($a.AccessType -eq 'Allow' -and $a.IdentityClass -in @('user', 'localuser')) {
            Add-Finding 'Mittel' 'Direkte Benutzerberechtigung' $a.Path "$($a.Identity) direkt mit '$($a.Level)' berechtigt (statt über Gruppe)."
        }
        if ($a.AccessType -eq 'Allow' -and $rank -eq 5 -and $a.Category -eq 'Normal' -and -not (Test-SLAdminSid -Sid $a.IdentitySid)) {
            Add-Finding 'Mittel' 'Vollzugriff' $a.Path "$($a.Identity) hat Vollzugriff und kann damit Berechtigungen/Besitz ändern."
        }
        if ($a.AccessType -eq 'Deny') {
            Add-Finding 'Info' 'Verweigern-Eintrag' $a.Path "$($a.Identity): Verweigern '$($a.Level)'."
        }
    }

    foreach ($f in @($Report.Folders | Where-Object { $_.InheritanceProtected -and $_.Depth -gt 0 })) {
        Add-Finding 'Info' 'Vererbung unterbrochen' $f.Path "Vererbung deaktiviert, $($f.ExplicitAceCount) explizite Einträge."
    }

    # Freigaben
    foreach ($s in @($Report.Shares)) {
        if ($s.AccessBasedEnumeration -eq $false) {
            Add-Finding 'Info' 'Freigabe' $s.ShareUnc 'Zugriffsbasierte Aufzählung (ABE) ist deaktiviert.'
        }
    }
    foreach ($sa in @($Report.ShareAccess | Where-Object { $_.AccessType -eq 'Allow' -and $_.Category -eq 'Broad' -and $_.AccessRight -in @('Full', 'Change') })) {
        Add-Finding 'Info' 'Freigabe' $sa.ShareUnc "Freigabe erlaubt $($sa.Identity) '$($sa.AccessRight)' – Absicherung erfolgt nur über NTFS."
    }
    if (@($Report.Dfs).Count -gt 0) {
        foreach ($s in @($Report.Shares | Where-Object { -not $_.DfsPath -and -not $_.Special })) {
            Add-Finding 'Info' 'DFS' $s.ShareUnc 'Freigabe ist über keinen DFS-Pfad erreichbar.'
        }
    }

    # Effektive Zugriffe
    $disabled = @($Report.Matrix | Where-Object { $_.Enabled -eq $false -and [int]$_.EffectiveRank -ge 2 }) | Group-Object Principal
    foreach ($g in $disabled) {
        Add-Finding 'Mittel' 'Deaktiviertes Konto' $g.Name "Deaktiviertes Konto hat noch Zugriff auf $($g.Count) Ordner."
    }

    $errCount = @($Report.Errors).Count
    if ($errCount -gt 0) {
        Add-Finding 'Info' 'Scan' '' "$errCount Fehler beim Erfassen – siehe Tabelle 'Fehler'."
    }

    $order = @{ 'Hoch' = 0; 'Mittel' = 1; 'Info' = 2 }
    $out | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Object
}

function Compare-SLRows {
    param(
        [string]$Category,
        [object[]]$Old,
        [object[]]$New,
        [scriptblock]$Key,
        [scriptblock]$Label,
        [scriptblock]$Value
    )

    $o = @{}
    foreach ($r in $Old) { $k = ([string]($r | ForEach-Object -Process $Key)).ToUpperInvariant(); $o[$k] = $r }
    $n = @{}
    foreach ($r in $New) { $k = ([string]($r | ForEach-Object -Process $Key)).ToUpperInvariant(); $n[$k] = $r }

    foreach ($k in $n.Keys) {
        $nv = [string]($n[$k] | ForEach-Object -Process $Value)
        if (-not $o.ContainsKey($k)) {
            [pscustomobject]@{ Category = $Category; Change = 'Hinzugefügt'; Object = ($n[$k] | ForEach-Object -Process $Label); OldValue = ''; NewValue = $nv }
        }
        else {
            $ov = [string]($o[$k] | ForEach-Object -Process $Value)
            if ($ov -ne $nv) {
                [pscustomobject]@{ Category = $Category; Change = 'Geändert'; Object = ($n[$k] | ForEach-Object -Process $Label); OldValue = $ov; NewValue = $nv }
            }
        }
    }
    foreach ($k in $o.Keys) {
        if (-not $n.ContainsKey($k)) {
            [pscustomobject]@{ Category = $Category; Change = 'Entfernt'; Object = ($o[$k] | ForEach-Object -Process $Label); OldValue = [string]($o[$k] | ForEach-Object -Process $Value); NewValue = '' }
        }
    }
}

# ---- Private/Collectors.ps1
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

# ---- Private/HtmlTemplate.ps1
$script:SLHtmlTemplate = @'
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#1c2330; --muted:#5d6878; --line:#e2e6ec; --accent:#1f5fbf; --accent-soft:#e8f0fc;
  --hi:#b42318; --hi-bg:#fde8e7; --mid:#a35a00; --mid-bg:#fff1dc; --info:#36597d; --info-bg:#e8eef5;
  --l5:#b42318; --l4:#c2570c; --l3:#a16207; --l2:#1d7a46; --l1:#5d6878; --l0:#8a94a3;
  --mono: ui-monospace, "Cascadia Mono", Consolas, monospace;
}
@media (prefers-color-scheme: dark){
  :root{ --bg:#11151c; --panel:#181d26; --ink:#e6e9ef; --muted:#9aa4b2; --line:#2a3240; --accent:#6ea0ff; --accent-soft:#1d2a40;
  --hi:#ff8a80; --hi-bg:#3a1d1d; --mid:#ffb35c; --mid-bg:#3a2a14; --info:#9cc0e8; --info-bg:#1c2a3a;
  --l5:#ff8a80; --l4:#ffa366; --l3:#e6c35c; --l2:#6fd39b; --l1:#9aa4b2; --l0:#6b7584; }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
header{padding:20px 24px 12px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 4px;font-size:20px;font-weight:650;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px}
nav{display:flex;gap:2px;flex-wrap:wrap;padding:0 16px;background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
nav button{border:0;background:none;color:var(--muted);padding:10px 12px;font:inherit;cursor:pointer;border-bottom:2px solid transparent}
nav button:hover{color:var(--ink)}
nav button.on{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}
nav .n{display:inline-block;margin-left:6px;font-size:11px;background:var(--accent-soft);color:var(--accent);border-radius:9px;padding:0 6px}
main{padding:16px 24px 40px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .v{font-size:22px;font-weight:650}
.card .k{color:var(--muted);font-size:12px}
.card.hi .v{color:var(--hi)} .card.mid .v{color:var(--mid)}
h2{font-size:15px;margin:22px 0 8px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-size:13px}
.meta dt{color:var(--muted)} .meta dd{margin:0;word-break:break-word}
.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 10px}
.bar input[type=search]{flex:1 1 260px;max-width:420px;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);font:inherit}
.bar .cnt{color:var(--muted);font-size:12px}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:6px;padding:6px 10px;font:inherit;font-size:13px;cursor:pointer}
.btn:hover{border-color:var(--accent);color:var(--accent)}
details.cols{position:relative}
details.cols summary{list-style:none}
details.cols .pop{position:absolute;z-index:10;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;max-height:360px;overflow:auto;min-width:220px;box-shadow:0 6px 24px rgba(0,0,0,.12)}
details.cols label{display:block;font-size:13px;white-space:nowrap}
.wrap{overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;max-height:calc(100vh - 200px)}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{padding:5px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
thead th{position:sticky;top:0;background:var(--panel);z-index:2;white-space:nowrap;cursor:pointer;user-select:none;font-weight:600}
thead tr.f th{top:29px;cursor:default;padding:3px 4px}
thead tr.f input{width:100%;min-width:60px;padding:3px 5px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--ink);font:inherit;font-size:12px}
th .s{color:var(--accent);font-size:10px;margin-left:3px}
tbody tr:hover td{background:var(--accent-soft)}
td.wide{min-width:240px}
td.path{font-family:var(--mono);font-size:12px;word-break:break-all;min-width:220px}
.lv{display:inline-block;padding:0 6px;border-radius:4px;font-weight:600;font-size:12px;white-space:nowrap}
.lv5{color:var(--l5)} .lv4{color:var(--l4)} .lv3{color:var(--l3)} .lv2{color:var(--l2)} .lv1{color:var(--l1)} .lv0{color:var(--l0)}
.sev{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11.5px;font-weight:600}
.sev.Hoch{background:var(--hi-bg);color:var(--hi)} .sev.Mittel{background:var(--mid-bg);color:var(--mid)} .sev.Info{background:var(--info-bg);color:var(--info)}
.no{color:var(--muted)}
.more{margin:10px 0}
.note{color:var(--muted);font-size:12px;margin:6px 0}
@media (max-width:640px){ header,main{padding-left:16px;padding-right:16px} }
@media print{ nav,.bar{display:none} .wrap{max-height:none;overflow:visible} }
</style>
</head>
<body>
<header><h1 id="t"></h1><div class="sub" id="sub"></div></header>
<nav id="nav"></nav>
<main id="main"></main>
<script type="application/json" id="sl-data">__DATA__</script>
<script>
(function(){
var D = JSON.parse(document.getElementById('sl-data').textContent);
var LV = {'Vollzugriff':5,'Ändern':4,'Lesen+Schreiben':3,'Lesen':2,'Speziell':1,'Kein':0};
var LABELS = {Path:'Pfad',DfsPath:'DFS-Pfad',ShareUnc:'Freigabe',Principal:'Konto',DisplayName:'Anzeigename',ObjectClass:'Typ',
  Enabled:'Aktiv',EffectiveLevel:'Effektiv',NtfsLevel:'NTFS',ShareLevel:'Freigabe-Recht',HasDeny:'Verweigern',ViaNtfs:'Über (NTFS)',
  ViaShare:'Über (Freigabe)',PrincipalSid:'SID',Identity:'Konto',IdentitySid:'SID',IdentityClass:'Typ',Category:'Kategorie',
  AccessType:'Art',Level:'Stufe',Rights:'Rechte (roh)',Inherited:'Geerbt',AppliesTo:'Gilt für',AppliesToThisFolder:'Gilt für Ordner',
  InheritanceFlags:'Vererbung',PropagationFlags:'Weitergabe',Depth:'Tiefe',Owner:'Besitzer',OwnerSid:'Besitzer-SID',
  InheritanceProtected:'Vererbung aus',ExplicitAceCount:'Explizit',AceCount:'ACEs',IsBoundary:'Grenzordner',ScanRoot:'Scan-Wurzel',
  Severity:'Stufe',Object:'Objekt',Detail:'Detail',ComputerName:'Server',ShareName:'Name',LocalPath:'Lokaler Pfad',Description:'Beschreibung',
  Special:'Admin',ScopeName:'Scope',AccessBasedEnumeration:'ABE',EncryptData:'Verschl.',ContinuouslyAvailable:'CA',CachingMode:'Offline-Cache',
  CurrentUsers:'Sitzungen',FullAccess:'Vollzugriff',ChangeAccess:'Ändern',ReadAccess:'Lesen',DenyAccess:'Verweigert',Source:'Quelle',
  AccessRight:'Recht',Kind:'Art',Namespace:'Namespace',NamespaceType:'Typ',FolderState:'Ordnerstatus',TargetPath:'Ziel',
  TargetServer:'Zielserver',TargetShare:'Zielfreigabe',TargetSubPath:'Unterpfad',TargetState:'Zielstatus',
  ReferralPriorityClass:'Priorität',ReferralPriorityRank:'Rang',Member:'Mitglied',Via:'Über',MemberSid:'SID',Stage:'Schritt',
  Target:'Ziel',Message:'Meldung',Readable:'Lesbar',Writeable:'Schreibbar',WriteTestRequested:'Schreibtest',ResponseMilliseconds:'ms',
  Error:'Fehler',User:'Benutzer',GroupName:'Gruppe',FolderName:'Ordner',ContentPath:'Inhaltspfad',PrimaryMember:'Primär',ReadOnly:'Schreibgeschützt',
  StagingQuotaMB:'Staging MB',GroupState:'Gruppenstatus'};
var HIDE = {Matrix:['PrincipalSid','ShareUnc'],Aces:['IdentitySid','InheritanceFlags','PropagationFlags','AppliesToThisFolder','ShareUnc'],
  Folders:['OwnerSid','ScanRoot','ShareUnc'],Members:['PrincipalSid','MemberSid'],ShareAccess:['IdentitySid'],Dfs:['TargetServer','TargetShare','TargetSubPath']};
var WIDE = {AppliesTo:1,ViaNtfs:1,ViaShare:1,Detail:1,Via:1,Message:1,FullAccess:1,ChangeAccess:1,ReadAccess:1};
var PATHCOLS = {Path:1,DfsPath:1,ShareUnc:1,TargetPath:1,LocalPath:1,Target:1,ScanRoot:1,ContentPath:1,Object:1};

function el(tag, attrs, html){ var e=document.createElement(tag); if(attrs) for(var k in attrs) e.setAttribute(k, attrs[k]); if(html!=null) e.innerHTML=html; return e; }
function esc(v){ return String(v).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
function show(v){ if(v===null||v===undefined||v==='') return ''; if(v===true) return 'Ja'; if(v===false) return 'Nein'; return String(v); }
function cell(col, v){
  var s = show(v);
  if(s==='') return '<span class="no">–</span>';
  if(LV.hasOwnProperty(s) && /Level$|^Level$/.test(col)) return '<span class="lv lv'+LV[s]+'">'+esc(s)+'</span>';
  if(col==='AccessType'){ return s==='Deny' ? '<span class="lv lv5">Verweigern</span>' : 'Erlauben'; }
  if(col==='Severity') return '<span class="sev '+esc(s)+'">'+esc(s)+'</span>';
  return esc(s);
}

document.getElementById('t').textContent = D.title;
document.title = D.title;
var m = D.meta || {};
document.getElementById('sub').textContent = 'Erstellt ' + (m.GeneratedAt||'') + ' von ' + (m.GeneratedBy||'') + ' auf ' + (m.RunOn||'') + ' · ShareLens ' + (m.Version||'');

var tables = {}; D.tables.forEach(function(t){ tables[t.key]=t; });
var nav = document.getElementById('nav'), main = document.getElementById('main');
var views = [{key:'_overview', title:'Übersicht'}].concat(D.tables.filter(function(t){ return t.total>0; }));
var state = {};

views.forEach(function(v){
  var b = el('button', {'data-k':v.key}, esc(v.title) + (v.total!=null ? '<span class="n">'+v.total+'</span>' : ''));
  b.onclick = function(){ open(v.key); };
  nav.appendChild(b);
});

function open(key){
  [].forEach.call(nav.children, function(b){ b.classList.toggle('on', b.getAttribute('data-k')===key); });
  main.innerHTML = '';
  try { history.replaceState(null,'','#'+key); } catch(e){}
  if(key==='_overview') overview(); else table(tables[key]);
}

function count(key, fn){ var t=tables[key]; if(!t) return 0; return fn ? t.rows.filter(fn).length : t.total; }

function overview(){
  var f = tables.Findings ? tables.Findings.rows : [];
  var cards = [
    ['Freigaben', count('Shares')], ['DFS-Ziele', count('Dfs', function(r){return r.Kind==='FolderTarget';})],
    ['Ordner gelesen', count('Folders')], ['Grenzordner', count('Folders', function(r){return r.IsBoundary===true;})],
    ['Zugriffszeilen', count('Matrix')], ['Befunde Hoch', f.filter(function(r){return r.Severity==='Hoch';}).length, 'hi'],
    ['Befunde Mittel', f.filter(function(r){return r.Severity==='Mittel';}).length, 'mid'], ['Fehler', count('Errors')]
  ];
  var c = el('div',{'class':'cards'});
  cards.forEach(function(x){ c.appendChild(el('div',{'class':'card '+(x[2]||'')},'<div class="v">'+x[1]+'</div><div class="k">'+esc(x[0])+'</div>')); });
  main.appendChild(c);
  var dl = el('dl',{'class':'meta'});
  var ML = {Servers:'Server',Namespaces:'DFS-Namespaces',Depth:'Scan-Tiefe',GroupExpansion:'Gruppenauflösung',ScanRoots:'Scan-Wurzeln',DurationSec:'Dauer (s)',GeneratedBy:'Erstellt von',RunOn:'Ausgeführt auf'};
  Object.keys(ML).forEach(function(k){ dl.appendChild(el('dt',null,esc(ML[k]))); dl.appendChild(el('dd',null,esc(show(m[k]))||'–')); });
  main.appendChild(el('h2',null,'Rahmendaten'));
  main.appendChild(dl);
  if(tables.Findings && tables.Findings.total){ main.appendChild(el('h2',null,'Befunde')); table(tables.Findings, true); }
  main.appendChild(el('p',{'class':'note'},'Effektiv = Schnittmenge aus Freigabe- und NTFS-Recht am jeweiligen Ordner. Gruppen sind bis auf Benutzer aufgelöst; Jeder/Authentifizierte Benutzer/Domänen-Benutzer gelten für alle Konten.'));
}

function table(t, embedded){
  var st = state[t.key] || (state[t.key] = {q:'', f:{}, sort:null, dir:1, limit:500, hidden:null});
  var cols = []; var seen = {};
  t.rows.forEach(function(r){ for(var k in r) if(!seen[k]){ seen[k]=1; cols.push(k); } });
  if(st.hidden===null){ st.hidden = {}; (HIDE[t.key]||[]).forEach(function(c){ st.hidden[c]=1; }); }

  var box = el('div');
  var bar = el('div',{'class':'bar'});
  var q = el('input',{type:'search',placeholder:'Suchen in allen Spalten …'}); q.value = st.q;
  var cnt = el('span',{'class':'cnt'});
  var csv = el('button',{'class':'btn'},'CSV (gefiltert)');
  var cd = el('details',{'class':'cols'}); cd.appendChild(el('summary',{'class':'btn'},'Spalten'));
  var pop = el('div',{'class':'pop'});
  cols.forEach(function(c){
    var l = el('label'); var cb = el('input',{type:'checkbox'}); cb.checked = !st.hidden[c];
    cb.onchange = function(){ if(cb.checked) delete st.hidden[c]; else st.hidden[c]=1; render(); };
    l.appendChild(cb); l.appendChild(document.createTextNode(' '+(LABELS[c]||c))); pop.appendChild(l);
  });
  cd.appendChild(pop);
  bar.appendChild(q); bar.appendChild(cd); bar.appendChild(csv); bar.appendChild(cnt);
  if(!embedded) box.appendChild(bar);
  if(t.total > t.rows.length) box.appendChild(el('p',{'class':'note'},'Im HTML sind die ersten '+t.rows.length+' von '+t.total+' Zeilen enthalten – vollständig in CSV/XLSX.'));
  var wrap = el('div',{'class':'wrap'}); box.appendChild(wrap);
  var more = el('div',{'class':'more'}); box.appendChild(more);
  main.appendChild(box);

  var timer;
  q.oninput = function(){ clearTimeout(timer); timer=setTimeout(function(){ st.q=q.value; st.limit=500; render(); },150); };

  function filtered(){
    var needle = st.q.toLowerCase();
    var fk = Object.keys(st.f).filter(function(k){ return st.f[k]; });
    var rows = t.rows.filter(function(r){
      if(needle){ var hit=false; for(var k in r){ if(show(r[k]).toLowerCase().indexOf(needle)>=0){ hit=true; break; } } if(!hit) return false; }
      for(var i=0;i<fk.length;i++){ var term=st.f[fk[i]].toLowerCase(); var val=show(r[fk[i]]).toLowerCase();
        if(term.charAt(0)==='='){ if(val!==term.slice(1)) return false; }
        else if(term.charAt(0)==='!'){ if(val.indexOf(term.slice(1))>=0) return false; }
        else if(val.indexOf(term)<0) return false; }
      return true;
    });
    if(st.sort){
      var c=st.sort, d=st.dir;
      rows = rows.slice().sort(function(a,b){
        var x=a[c], y=b[c];
        if(LV.hasOwnProperty(x) && LV.hasOwnProperty(y)){ x=LV[x]; y=LV[y]; }
        if(typeof x==='number' && typeof y==='number') return (x-y)*d;
        return show(x).localeCompare(show(y),'de',{numeric:true})*d;
      });
    }
    return rows;
  }

  function render(){
    var vis = cols.filter(function(c){ return !st.hidden[c]; });
    var rows = filtered();
    cnt.textContent = rows.length + ' von ' + t.total + ' Zeilen';
    var h = '<table><thead><tr>';
    vis.forEach(function(c){ h += '<th data-c="'+esc(c)+'">'+esc(LABELS[c]||c)+(st.sort===c?'<span class="s">'+(st.dir>0?'▲':'▼')+'</span>':'')+'</th>'; });
    h += '</tr>';
    if(!embedded){ h += '<tr class="f">'; vis.forEach(function(c){ h += '<th><input data-f="'+esc(c)+'" value="'+esc(st.f[c]||'')+'" placeholder="Filter"></th>'; }); h += '</tr>'; }
    h += '</thead><tbody>';
    var n = Math.min(rows.length, st.limit);
    for(var i=0;i<n;i++){ var r=rows[i]; h+='<tr>'; vis.forEach(function(c){ h+='<td'+(PATHCOLS[c]?' class="path"':(WIDE[c]?' class="wide"':''))+'>'+cell(c,r[c])+'</td>'; }); h+='</tr>'; }
    h += '</tbody></table>';
    wrap.innerHTML = h;
    [].forEach.call(wrap.querySelectorAll('thead tr:first-child th'), function(th){
      th.onclick = function(){ var c=th.getAttribute('data-c'); if(st.sort===c) st.dir=-st.dir; else { st.sort=c; st.dir=1; } render(); };
    });
    [].forEach.call(wrap.querySelectorAll('input[data-f]'), function(inp){
      var tm; inp.oninput = function(){ clearTimeout(tm); tm=setTimeout(function(){ st.f[inp.getAttribute('data-f')]=inp.value; st.limit=500; var pos=inp.selectionStart; var name=inp.getAttribute('data-f'); render(); var again=wrap.querySelector('input[data-f="'+name+'"]'); if(again){ again.focus(); try{again.setSelectionRange(pos,pos);}catch(e){} } },250); };
    });
    more.innerHTML = '';
    if(rows.length > n){ var b=el('button',{'class':'btn'},'Weitere '+Math.min(1000, rows.length-n)+' anzeigen'); b.onclick=function(){ st.limit+=1000; render(); }; more.appendChild(b); }
    csv.onclick = function(){
      var lines = [vis.map(function(c){ return '"'+(LABELS[c]||c).replace(/"/g,'""')+'"'; }).join(';')];
      rows.forEach(function(r){ lines.push(vis.map(function(c){ return '"'+show(r[c]).replace(/"/g,'""')+'"'; }).join(';')); });
      var blob = new Blob(['﻿'+lines.join('\r\n')], {type:'text/csv;charset=utf-8'});
      var a = el('a',{href:URL.createObjectURL(blob), download:'ShareLens_'+t.key+'.csv'}); document.body.appendChild(a); a.click(); a.remove();
    };
  }
  render();
}

var start = (location.hash||'').slice(1);
open(tables[start] ? start : '_overview');
})();
</script>
</body>
</html>
'@

# ---- Private/Principals.ps1
$script:SLDomainCache = @{}
$script:SLLocalCache = @{}
$script:SLNameCache = @{}
$script:SLLookupCache = @{}
$script:SLLdapServer = $null
$script:SLUserProperty = @()

$script:SLNativeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace ShareLens {
  public static class Native {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountSid(string lpSystemName, byte[] Sid, StringBuilder lpName,
        ref uint cchName, StringBuilder lpReferencedDomainName, ref uint cchReferencedDomainName, out int peUse);

    public static string[] LookupSid(string systemName, byte[] sid) {
      uint nameLen = 512, domLen = 512; int use;
      StringBuilder name = new StringBuilder(512);
      StringBuilder dom = new StringBuilder(512);
      if (!LookupAccountSid(systemName, sid, name, ref nameLen, dom, ref domLen, out use)) { return null; }
      string full = dom.Length > 0 ? dom.ToString() + "\\" + name.ToString() : name.ToString();
      return new string[] { full, use.ToString() };
    }
  }
}
'@

function Reset-SLCache {
    $script:SLDomainCache = @{}
    $script:SLLocalCache = @{}
    $script:SLNameCache = @{}
    $script:SLLookupCache = @{}
}

function Get-SLSidCategory {
    <#
      Broad  = gilt praktisch für alle Benutzer (Jeder, Authentifizierte Benutzer, Benutzer, Domänen-Benutzer ...)
      System = technische Konten (SYSTEM, ERSTELLER-BESITZER, Dienste, TrustedInstaller ...)
      Normal = alles andere
    #>
    param([string]$Sid)

    if (-not $Sid) { return 'Normal' }
    if ($Sid -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-2', 'S-1-5-14')) { return 'Broad' }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-513$') { return 'Broad' }
    if ($Sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-3-0', 'S-1-3-1', 'S-1-3-4', 'S-1-5-10', 'S-1-5-32-549', 'S-1-5-32-550')) { return 'System' }
    if ($Sid -match '^S-1-5-(80|82|83|90|96)-' -or $Sid -match '^S-1-15-') { return 'System' }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(515|516|521)$') { return 'System' }
    'Normal'
}

function Test-SLAdminSid {
    param([string]$Sid)
    if ($Sid -in @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0')) { return $true }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(500|512|519)$') { return $true }
    $false
}

function Invoke-SLLookupAccountSid {
    param([string]$ComputerName, [string]$Sid)

    if (-not (Test-SLIsWindows)) { return $null }
    $key = "$ComputerName|$Sid"
    if ($script:SLLookupCache.ContainsKey($key)) { return $script:SLLookupCache[$key] }
    $res = $null
    try {
        if (-not ('ShareLens.Native' -as [type])) {
            Add-Type -TypeDefinition $script:SLNativeSource -Language CSharp -ErrorAction Stop
        }
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $bytes = New-Object byte[] ($sidObj.BinaryLength)
        $sidObj.GetBinaryForm($bytes, 0)
        $r = [ShareLens.Native]::LookupSid($ComputerName, $bytes)
        if ($r) { $res = [pscustomobject]@{ Name = $r[0]; Use = [int]$r[1] } }
    }
    catch {
        Write-Verbose "LookupAccountSid($ComputerName, $Sid): $($_.Exception.Message)"
    }
    $script:SLLookupCache[$key] = $res
    $res
}

function Resolve-SLSidName {
    param([string]$Sid, [string]$ComputerName)

    if (-not $Sid) { return $null }
    $key = "$ComputerName|$Sid"
    if ($script:SLNameCache.ContainsKey($key)) { return $script:SLNameCache[$key] }
    $name = $null
    if (Test-SLIsWindows) {
        try {
            $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
        }
        catch { $name = $null }
        if (-not $name -and $ComputerName) {
            $l = Invoke-SLLookupAccountSid -ComputerName $ComputerName -Sid $Sid
            if ($l) { $name = $l.Name }
        }
    }
    $script:SLNameCache[$key] = $name
    $name
}

function ConvertTo-SLSid {
    param([string]$Name)
    if (-not $Name) { return $null }
    if ($Name -match '^S-1-[\d-]+$') { return $Name }
    if (-not (Test-SLIsWindows)) { return $null }
    try {
        (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch { $null }
}

function New-SLLeaf {
    param(
        [string]$Sid,
        [string]$Account,
        [string]$DisplayName,
        [string]$ObjectClass,
        $Enabled = $null,
        [string[]]$Via = @(),
        [hashtable]$Properties = @{}
    )
    [pscustomobject]@{
        Sid         = $Sid
        Account     = $Account
        DisplayName = $DisplayName
        ObjectClass = $ObjectClass
        Enabled     = $Enabled
        Via         = @($Via | Where-Object { $_ })
        Properties  = $Properties
    }
}

function Copy-SLLeaf {
    param($Leaf, [string]$PrependVia)
    New-SLLeaf -Sid $Leaf.Sid -Account $Leaf.Account -DisplayName $Leaf.DisplayName -ObjectClass $Leaf.ObjectClass `
        -Enabled $Leaf.Enabled -Via (@($PrependVia) + @($Leaf.Via)) -Properties $Leaf.Properties
}

function Get-SLLdapPrefix {
    if ($script:SLLdapServer) { return "LDAP://$($script:SLLdapServer)/" }
    'LDAP://'
}

function Get-SLDirectoryEntry {
    param([string]$Sid, [string]$DistinguishedName)

    if ($Sid) { $path = (Get-SLLdapPrefix) + "<SID=$Sid>" }
    else { $path = (Get-SLLdapPrefix) + ($DistinguishedName -replace '/', '\/') }
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry($path)
        $entry.RefreshCache([string[]]@('objectClass', 'objectSid', 'sAMAccountName', 'displayName', 'userAccountControl', 'distinguishedName', 'name'))
        if (-not $entry.Properties['objectClass'].Value) { return $null }
        return $entry
    }
    catch {
        Write-Verbose "LDAP-Bindung fehlgeschlagen ($path): $($_.Exception.Message)"
        return $null
    }
}

function Get-SLEntryProperties {
    param($Entry)
    $props = @{}
    foreach ($p in $script:SLUserProperty) {
        try {
            $Entry.RefreshCache([string[]]@($p))
            $props[$p] = (@($Entry.Properties[$p]) | ForEach-Object { [string]$_ }) -join '; '
        }
        catch { $props[$p] = '' }
    }
    $props
}

function Get-SLEntryEnabled {
    param($Entry)
    $uac = $Entry.Properties['userAccountControl'].Value
    if ($null -eq $uac) { return $null }
    -not ([int]$uac -band 2)
}

function Get-SLGroupMemberDn {
    <# Alle "member"-Werte einer Gruppe, mit Range-Retrieval (>1500 Mitglieder). #>
    param($Entry)

    $result = New-Object System.Collections.Generic.List[string]
    $low = 0
    $step = 1500
    while ($true) {
        $high = $low + $step - 1
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($Entry, '(objectClass=*)', [string[]]@("member;range=$low-$high"), [System.DirectoryServices.SearchScope]::Base)
        $r = $searcher.FindOne()
        if (-not $r) { break }
        $propName = @($r.Properties.PropertyNames) | Where-Object { $_ -like 'member;range=*' } | Select-Object -First 1
        if (-not $propName) { break }
        foreach ($v in $r.Properties[$propName]) { $result.Add([string]$v) }
        if ($propName.EndsWith('-*')) { break }
        $low = $high + 1
    }
    $result
}

function Get-SLLocalGroupMemberSid {
    param([string]$ComputerName, [string]$GroupName)

    $short = ($GroupName -split '\\')[-1]
    $target = $ComputerName
    if (-not $target) { $target = $env:COMPUTERNAME }
    try {
        $group = [ADSI]"WinNT://$target/$short,group"
        foreach ($m in @($group.psbase.Invoke('Members'))) {
            try {
                $bytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
            }
            catch { Write-Verbose "Mitglied von $target\$short nicht lesbar: $($_.Exception.Message)" }
        }
    }
    catch {
        Write-Verbose "Lokale Gruppe $target\$short nicht lesbar: $($_.Exception.Message)"
    }
}

function Get-SLPrincipalLeaf {
    <#
      Löst eine SID rekursiv bis auf Benutzer/Computer auf.
      Domänenobjekte per LDAP (verschachtelte Gruppen, Range-Retrieval),
      lokale Gruppen des Fileservers (VORDEFINIERT\..., SERVER\...) per WinNT.
      Rückgabe: Leaf-Objekte mit Via-Kette (Gruppe > Untergruppe).
    #>
    param(
        [Parameter(Mandatory)][string]$Sid,
        [string]$ComputerName,
        [string]$Name,
        $Visiting
    )

    if ($null -eq $Visiting) {
        $Visiting = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    }

    $category = Get-SLSidCategory -Sid $Sid
    if ($category -in @('Broad', 'System')) {
        $acct = $Name
        if (-not $acct) { $acct = Resolve-SLSidName -Sid $Sid -ComputerName $ComputerName }
        if (-not $acct) { $acct = $Sid }
        $class = 'system'
        if ($category -eq 'Broad') { $class = 'broad' }
        return (New-SLLeaf -Sid $Sid -Account $acct -ObjectClass $class)
    }

    $isBuiltin = $Sid.StartsWith('S-1-5-32-')
    if (-not $isBuiltin -and $script:SLDomainCache.ContainsKey($Sid)) { return $script:SLDomainCache[$Sid] }
    $localKey = "$ComputerName|$Sid"
    if ($script:SLLocalCache.ContainsKey($localKey)) { return $script:SLLocalCache[$localKey] }

    if ($Visiting.Contains($Sid)) { return }   # Zirkelbezug
    [void]$Visiting.Add($Sid)

    $leafs = New-Object System.Collections.Generic.List[object]
    $source = 'none'
    try {
        $entry = $null
        if (-not $isBuiltin -and (Test-SLIsWindows)) { $entry = Get-SLDirectoryEntry -Sid $Sid }

        if ($entry) {
            $source = 'ldap'
            $classes = @($entry.Properties['objectClass'])
            $acct = Resolve-SLSidName -Sid $Sid -ComputerName $ComputerName
            if (-not $acct) { $acct = [string]$entry.Properties['sAMAccountName'].Value }
            $display = [string]$entry.Properties['displayName'].Value

            if ($classes -contains 'computer') {
                $leafs.Add((New-SLLeaf -Sid $Sid -Account $acct -DisplayName $display -ObjectClass 'computer' -Enabled (Get-SLEntryEnabled $entry)))
            }
            elseif ($classes -contains 'group') {
                foreach ($dn in @(Get-SLGroupMemberDn -Entry $entry)) {
                    $member = Get-SLDirectoryEntry -DistinguishedName $dn
                    if (-not $member) {
                        $leafs.Add((New-SLLeaf -Account $dn -ObjectClass 'unresolved' -Via @($acct)))
                        continue
                    }
                    $memberSid = $null
                    try { $memberSid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$member.Properties['objectSid'].Value, 0)).Value } catch { $memberSid = $null }
                    if (-not $memberSid -and (@($member.Properties['objectClass']) -contains 'foreignSecurityPrincipal')) {
                        $memberSid = [string]$member.Properties['name'].Value
                    }
                    if (-not $memberSid) {
                        $leafs.Add((New-SLLeaf -Account $dn -ObjectClass 'unresolved' -Via @($acct)))
                        continue
                    }
                    foreach ($child in @(Get-SLPrincipalLeaf -Sid $memberSid -ComputerName $ComputerName -Visiting $Visiting)) {
                        $leafs.Add((Copy-SLLeaf -Leaf $child -PrependVia $acct))
                    }
                }
            }
            elseif ($classes -contains 'user' -or $classes -contains 'inetOrgPerson') {
                $leafs.Add((New-SLLeaf -Sid $Sid -Account $acct -DisplayName $display -ObjectClass 'user' -Enabled (Get-SLEntryEnabled $entry) -Properties (Get-SLEntryProperties $entry)))
            }
            elseif ($classes -contains 'foreignSecurityPrincipal') {
                $leafs.Add((New-SLLeaf -Sid $Sid -Account $acct -ObjectClass 'foreign'))
            }
            else {
                $leafs.Add((New-SLLeaf -Sid $Sid -Account $acct -DisplayName $display -ObjectClass ([string]$classes[-1])))
            }
        }
        else {
            $lookup = $null
            if (Test-SLIsWindows) { $lookup = Invoke-SLLookupAccountSid -ComputerName $ComputerName -Sid $Sid }
            if ($lookup) {
                $source = 'local'
                switch ($lookup.Use) {
                    4 {
                        # Alias = lokale Gruppe (auch VORDEFINIERT\...)
                        foreach ($memberSid in @(Get-SLLocalGroupMemberSid -ComputerName $ComputerName -GroupName $lookup.Name)) {
                            foreach ($child in @(Get-SLPrincipalLeaf -Sid $memberSid -ComputerName $ComputerName -Visiting $Visiting)) {
                                $leafs.Add((Copy-SLLeaf -Leaf $child -PrependVia $lookup.Name))
                            }
                        }
                    }
                    1 { $leafs.Add((New-SLLeaf -Sid $Sid -Account $lookup.Name -ObjectClass 'localuser')) }
                    2 { $leafs.Add((New-SLLeaf -Sid $Sid -Account $lookup.Name -ObjectClass 'group-unresolved')) }
                    5 { $leafs.Add((New-SLLeaf -Sid $Sid -Account $lookup.Name -ObjectClass 'wellknown')) }
                    9 { $leafs.Add((New-SLLeaf -Sid $Sid -Account $lookup.Name -ObjectClass 'computer')) }
                    default { $leafs.Add((New-SLLeaf -Sid $Sid -Account $lookup.Name -ObjectClass 'unknown')) }
                }
            }
            else {
                $acct = $Name
                if (-not $acct) { $acct = $Sid }
                $leafs.Add((New-SLLeaf -Sid $Sid -Account $acct -ObjectClass 'unresolved'))
            }
        }
    }
    finally {
        [void]$Visiting.Remove($Sid)
    }

    $arr = $leafs.ToArray()
    if ($source -eq 'ldap') { $script:SLDomainCache[$Sid] = $arr }
    else { $script:SLLocalCache[$localKey] = $arr }
    $arr
}

# ---- Private/Rights.ps1
$script:SLLevelNames = @('Kein', 'Speziell', 'Lesen', 'Lesen+Schreiben', 'Ändern', 'Vollzugriff')

# Rechte-Masken (FileSystemRights)
$script:SLMaskFull   = [int64]0x1F01FF
$script:SLMaskModify = [int64]0x1301BF
$script:SLMaskRead   = [int64]0x1200A9

function ConvertTo-SLRightsMask {
    <# Wandelt FileSystemRights (Enum, Zahl oder Text) in eine normierte Maske um, inkl. GENERIC_*-Bits. #>
    param([Parameter(Mandatory)][AllowNull()]$Rights)

    if ($null -eq $Rights) { return [int64]0 }
    if ($Rights -is [string]) {
        $num = [int64]0
        if ([int64]::TryParse($Rights, [ref]$num)) { $Rights = $num }
        else { $Rights = [System.Security.AccessControl.FileSystemRights]$Rights }
    }
    $m = ([int64]$Rights) -band [int64]4294967295
    if ($m -band [int64]268435456)  { $m = $m -bor $script:SLMaskFull }      # GENERIC_ALL
    if ($m -band [int64]2147483648) { $m = $m -bor $script:SLMaskRead }      # GENERIC_READ
    if ($m -band [int64]1073741824) { $m = $m -bor [int64]0x100116 }         # GENERIC_WRITE
    if ($m -band [int64]536870912)  { $m = $m -bor [int64]0x1200A0 }         # GENERIC_EXECUTE
    $m -band $script:SLMaskFull
}

function Get-SLLevelRank {
    param([int64]$Mask)
    $m = $Mask -band [int64]0xF01FF
    if ($m -eq 0) { return 0 }
    if (($m -band [int64]0xF01FF) -eq [int64]0xF01FF) { return 5 }
    if (($m -band [int64]0x301BF) -eq [int64]0x301BF) { return 4 }
    $read = (($m -band [int64]0x89) -eq [int64]0x89)
    if ($read -and ($m -band [int64]0x6)) { return 3 }
    if ($read) { return 2 }
    return 1
}

function Get-SLLevelName {
    param([int64]$Mask)
    $script:SLLevelNames[(Get-SLLevelRank -Mask $Mask)]
}

function Get-SLShareMask {
    <# Freigabeberechtigung (Full/Change/Read/Custom) als NTFS-vergleichbare Maske. #>
    param([string]$AccessRight, [int64]$RawMask = 0)
    switch ($AccessRight) {
        'Full'   { return $script:SLMaskFull }
        'Change' { return $script:SLMaskModify }
        'Read'   { return $script:SLMaskRead }
        default  { return (ConvertTo-SLRightsMask -Rights $RawMask) }
    }
}

function ConvertTo-SLShareRight {
    <# Win32-Zugriffsmaske einer Freigabe in Full/Change/Read/Custom übersetzen. #>
    param([int64]$AccessMask)
    switch ($AccessMask) {
        2032127 { 'Full' }
        1245631 { 'Change' }
        1179817 { 'Read' }
        default { 'Custom' }
    }
}

function Get-SLAppliesTo {
    <# Anzeige wie im Explorer ("Gilt für"). #>
    param($InheritanceFlags, $PropagationFlags)

    $i = [int]([System.Security.AccessControl.InheritanceFlags]$InheritanceFlags)
    $p = [int]([System.Security.AccessControl.PropagationFlags]$PropagationFlags)
    $ci = [bool]($i -band 1)
    $oi = [bool]($i -band 2)
    $inheritOnly = [bool]($p -band 2)
    $noPropagate = [bool]($p -band 1)

    if (-not $inheritOnly) {
        if ($ci -and $oi) { $text = 'Dieser Ordner, Unterordner und Dateien' }
        elseif ($ci) { $text = 'Dieser Ordner und Unterordner' }
        elseif ($oi) { $text = 'Dieser Ordner und Dateien' }
        else { $text = 'Nur dieser Ordner' }
    }
    else {
        if ($ci -and $oi) { $text = 'Nur Unterordner und Dateien' }
        elseif ($ci) { $text = 'Nur Unterordner' }
        elseif ($oi) { $text = 'Nur Dateien' }
        else { $text = 'Nur dieser Ordner' }
    }
    if ($noPropagate -and ($ci -or $oi)) { $text += ' (nur eine Ebene)' }

    [pscustomobject]@{
        Text           = $text
        AppliesToFolder = (-not $inheritOnly)
    }
}

# ---- Private/Util.ps1
function Test-SLIsWindows {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    return [bool]$IsWindows
}

function Split-SLUncPath {
    <# Zerlegt \\host\share\sub\path. Gibt $null zurück, wenn kein UNC-Pfad. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    $p = $Path.Trim()
    if ($p -notmatch '^\\\\([^\\]+)\\([^\\]+)(\\.*)?$') { return $null }
    $hostName = $Matches[1]
    $share = $Matches[2]
    $rest = ''
    if ($Matches[3]) { $rest = $Matches[3].Trim('\') }
    $segments = @()
    if ($rest) { $segments = @($rest -split '\\' | Where-Object { $_ }) }

    [pscustomobject]@{
        Host      = $hostName
        HostShort = ($hostName.Split('.')[0]).ToUpperInvariant()
        Share     = $share
        SubPath   = ($segments -join '\')
        Segments  = $segments
    }
}

function ConvertTo-SLUncKey {
    <# Normalisierter Vergleichsschlüssel: \\HOSTKURZ\SHARE\SUB (Großbuchstaben, FQDN entfernt). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    $u = Split-SLUncPath -Path $Path
    if (-not $u) { return $Path.TrimEnd('\').ToUpperInvariant() }
    $key = '\\' + $u.HostShort + '\' + $u.Share.ToUpperInvariant()
    if ($u.SubPath) { $key += '\' + $u.SubPath.ToUpperInvariant() }
    $key
}

function Get-SLDfsPathForUnc {
    <# Liefert alle DFS-Pfade, über die ein UNC-Pfad erreichbar ist (durch "; " getrennt). #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [object[]]$DfsTargets
    )

    if (-not $DfsTargets) { return '' }
    $u = Split-SLUncPath -Path $Path
    if (-not $u) { return '' }
    $key = ConvertTo-SLUncKey -Path $Path
    $segments = @($u.Share) + @($u.Segments)

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($t in $DfsTargets) {
        if (-not $t.TargetPath -or -not $t.DfsPath) { continue }
        $tk = ConvertTo-SLUncKey -Path $t.TargetPath
        $dfs = $null
        if ($key -eq $tk) {
            $dfs = $t.DfsPath.TrimEnd('\')
        }
        elseif ($key.StartsWith($tk + '\')) {
            $tu = Split-SLUncPath -Path $t.TargetPath
            $skip = 1 + @($tu.Segments).Count
            $remainder = ($segments[$skip..($segments.Count - 1)]) -join '\'
            $dfs = $t.DfsPath.TrimEnd('\') + '\' + $remainder
        }
        if ($dfs -and -not $result.Contains($dfs)) { $result.Add($dfs) }
    }
    ($result | Sort-Object) -join '; '
}

function ConvertTo-SLFlatValue {
    <# Arrays/Collections für CSV/HTML zu Text zusammenfassen. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) { return (@($Value) | ForEach-Object { [string]$_ }) -join '; ' }
    $Value
}

function New-SLErrorRow {
    param([string]$Stage, [string]$Target, [string]$Message)
    [pscustomobject]@{
        Stage   = $Stage
        Target  = $Target
        Message = $Message
    }
}

# ---- Public/Export-SLReport.ps1
$script:SLTables = @(
    @{ Key = 'Findings';       Title = 'Befunde' }
    @{ Key = 'Dfs';            Title = 'DFS-Namespace' }
    @{ Key = 'DfsReplication'; Title = 'DFS-Replikation' }
    @{ Key = 'Shares';         Title = 'Freigaben' }
    @{ Key = 'ShareAccess';    Title = 'Freigabe-Rechte' }
    @{ Key = 'Matrix';         Title = 'Effektive Zugriffe' }
    @{ Key = 'Aces';           Title = 'NTFS-Rechte' }
    @{ Key = 'Folders';        Title = 'Ordner' }
    @{ Key = 'Members';        Title = 'Gruppenauflösung' }
    @{ Key = 'AccessTests';    Title = 'Zugriffstests' }
    @{ Key = 'Errors';         Title = 'Fehler' }
)

# Spalten, die im Export nicht benötigt werden (intern)
$script:SLHiddenColumns = @('ShareKey', 'Context', 'Mask', 'RightsMask', 'EffectiveRank', 'Access')

function ConvertTo-SLExportRows {
    param([object[]]$Rows)
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $o = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) {
            if ($p.Name -in $script:SLHiddenColumns) { continue }
            $o[$p.Name] = ConvertTo-SLFlatValue -Value $p.Value
        }
        [pscustomobject]$o
    }
}

function Export-SLReport {
    <#
    .SYNOPSIS
    Exportiert einen ShareLens-Bericht als HTML, CSV, XLSX und/oder JSON.

    .DESCRIPTION
    - Html: eine eigenständige Datei mit Reitern, Suche, Spaltenfiltern, Sortierung und CSV-Export.
    - Csv:  eine Datei je Tabelle (UTF-8 mit BOM, Trennzeichen = Listentrenner der Kultur, in DE ";").
    - Xlsx: eine Arbeitsmappe mit einem Blatt je Tabelle (benötigt Modul ImportExcel).
    - Json: Snapshot für Compare-SLReport.

    .EXAMPLE
    $r = Invoke-SLFileServerReport -ComputerName FS01
    Export-SLReport -Report $r -OutputPath C:\Reports -Format Html, Xlsx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Report,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Html', 'Csv', 'Xlsx', 'Json')][string[]]$Format = @('Html', 'Csv', 'Xlsx', 'Json'),
        [string]$Delimiter = (Get-Culture).TextInfo.ListSeparator,
        [int]$HtmlMaxRows = 25000,
        [string]$Title = 'Fileserver-Berechtigungsbericht',
        [string]$BaseName
    )

    process {
        if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force }
        $out = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
        if (-not $BaseName) { $BaseName = 'ShareLens_' + (Get-Date -Format 'yyyyMMdd_HHmmss') }
        if (-not $Delimiter) { $Delimiter = ';' }
        $files = New-Object System.Collections.Generic.List[object]

        $tables = foreach ($t in $script:SLTables) {
            $rows = @(ConvertTo-SLExportRows -Rows @($Report.($t.Key)))
            [pscustomobject]@{ Key = $t.Key; Title = $t.Title; Rows = $rows }
        }

        if ('Csv' -in $Format) {
            $enc = 'UTF8'
            if ($PSVersionTable.PSVersion.Major -ge 6) { $enc = 'utf8BOM' }
            foreach ($t in $tables) {
                if ($t.Rows.Count -eq 0) { continue }
                $file = Join-Path $out "$($BaseName)_$($t.Key).csv"
                $t.Rows | Export-Csv -LiteralPath $file -NoTypeInformation -Delimiter $Delimiter -Encoding $enc
                $files.Add((Get-Item -LiteralPath $file))
            }
        }

        if ('Json' -in $Format) {
            $file = Join-Path $out "$BaseName.json"
            $snap = [ordered]@{ Format = 'ShareLens.Snapshot'; Version = $script:SLVersion; Meta = $Report.Meta }
            foreach ($t in $script:SLTables) { $snap[$t.Key] = @($Report.($t.Key) | ForEach-Object { ConvertTo-SLExportRows -Rows @($_) }) }
            # Für Vergleiche interne Spalten behalten
            $snap['Matrix'] = @($Report.Matrix)
            $snap['Aces'] = @($Report.Aces)
            $json = $snap | ConvertTo-Json -Depth 6 -Compress
            [System.IO.File]::WriteAllText($file, $json, (New-Object System.Text.UTF8Encoding($false)))
            $files.Add((Get-Item -LiteralPath $file))
        }

        if ('Xlsx' -in $Format) {
            if (Get-Module -ListAvailable -Name ImportExcel) {
                Import-Module ImportExcel -ErrorAction Stop -Verbose:$false
                $file = Join-Path $out "$BaseName.xlsx"
                foreach ($t in $tables) {
                    if ($t.Rows.Count -eq 0) { continue }
                    $sheet = ($t.Title -replace '[\[\]\*\?/\\:]', '-')
                    if ($sheet.Length -gt 31) { $sheet = $sheet.Substring(0, 31) }
                    $t.Rows | Export-Excel -Path $file -WorksheetName $sheet -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow
                }
                if (Test-Path -LiteralPath $file) { $files.Add((Get-Item -LiteralPath $file)) }
            }
            else {
                Write-Warning 'XLSX übersprungen: Modul ImportExcel fehlt (Install-Module ImportExcel -Scope CurrentUser).'
            }
        }

        if ('Html' -in $Format) {
            $file = Join-Path $out "$BaseName.html"
            $payload = [ordered]@{
                title  = $Title
                meta   = $Report.Meta
                tables = @(foreach ($t in $tables) {
                        $rows = $t.Rows
                        $total = $rows.Count
                        if ($total -gt $HtmlMaxRows) { $rows = $rows[0..($HtmlMaxRows - 1)] }
                        [ordered]@{ key = $t.Key; title = $t.Title; total = $total; rows = @($rows) }
                    })
            }
            $json = ($payload | ConvertTo-Json -Depth 6 -Compress) -replace '</', '<\/'
            $html = $script:SLHtmlTemplate.Replace('__TITLE__', [System.Net.WebUtility]::HtmlEncode($Title)).Replace('__DATA__', $json)
            [System.IO.File]::WriteAllText($file, $html, (New-Object System.Text.UTF8Encoding($false)))
            $files.Add((Get-Item -LiteralPath $file))
        }

        $files
    }
}

function ConvertTo-SLPSObject {
    param($InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $o[$k] = ConvertTo-SLPSObject -InputObject $InputObject[$k] }
        return [pscustomobject]$o
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return , @(foreach ($i in $InputObject) { ConvertTo-SLPSObject -InputObject $i })
    }
    $InputObject
}

function Import-SLReport {
    <#
    .SYNOPSIS
    Lädt einen per Export-SLReport -Format Json gespeicherten Snapshot.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).ProviderPath)
    try { $obj = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch {
        # Windows PowerShell 5.1: ConvertFrom-Json scheitert bei großen Dateien (maxJsonLength)
        if ($PSVersionTable.PSEdition -ne 'Desktop') { throw }
        Add-Type -AssemblyName System.Web.Extensions
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $ser.RecursionLimit = 100
        $obj = ConvertTo-SLPSObject -InputObject $ser.DeserializeObject($raw)
    }
    if ($obj.Format -ne 'ShareLens.Snapshot') { throw "Keine ShareLens-Snapshot-Datei: $Path" }
    $report = [ordered]@{ PSTypeName = 'ShareLens.Report'; Meta = $obj.Meta }
    foreach ($t in $script:SLTables) { $report[$t.Key] = @($obj.($t.Key)) }
    [pscustomobject]$report
}

function Compare-SLReport {
    <#
    .SYNOPSIS
    Vergleicht zwei Berichte/Snapshots: was wurde hinzugefügt, entfernt, geändert?

    .DESCRIPTION
    Verglichen werden DFS-Ziele, Freigaben, Freigabe-Rechte, explizite NTFS-Einträge,
    Besitzer/Vererbung der Ordner und effektive Zugriffe je Konto.

    .EXAMPLE
    Compare-SLReport -Reference .\ShareLens_20260101.json -Difference .\ShareLens_20260401.json | Format-Table

    .EXAMPLE
    Compare-SLReport $alt $neu | Export-Csv .\Aenderungen.csv -Delimiter ';' -NoTypeInformation -Encoding UTF8
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]$Reference,
        [Parameter(Mandatory, Position = 1)]$Difference
    )

    if ($Reference -is [string]) { $Reference = Import-SLReport -Path $Reference }
    if ($Difference -is [string]) { $Difference = Import-SLReport -Path $Difference }

    Compare-SLRows -Category 'DFS-Ziel' -Old @($Reference.Dfs) -New @($Difference.Dfs) `
        -Key { "$($_.DfsPath)|$($_.TargetPath)" } -Label { "$($_.DfsPath) -> $($_.TargetPath)" } -Value { $_.TargetState }

    Compare-SLRows -Category 'Freigabe' -Old @($Reference.Shares) -New @($Difference.Shares) `
        -Key { $_.ShareUnc } -Label { $_.ShareUnc } -Value { "Pfad=$($_.LocalPath); ABE=$($_.AccessBasedEnumeration)" }

    Compare-SLRows -Category 'Freigabe-Recht' -Old @($Reference.ShareAccess) -New @($Difference.ShareAccess) `
        -Key { "$($_.ShareUnc)|$($_.IdentitySid)|$($_.AccessType)" } -Label { "$($_.ShareUnc): $($_.Identity) ($($_.AccessType))" } -Value { $_.AccessRight }

    Compare-SLRows -Category 'NTFS explizit' -Old @($Reference.Aces | Where-Object { -not $_.Inherited }) -New @($Difference.Aces | Where-Object { -not $_.Inherited }) `
        -Key { "$($_.Path)|$($_.IdentitySid)|$($_.AccessType)|$($_.AppliesTo)" } -Label { "$($_.Path): $($_.Identity) ($($_.AccessType), $($_.AppliesTo))" } -Value { "$($_.Level) [$($_.Rights)]" }

    Compare-SLRows -Category 'Ordner' -Old @($Reference.Folders) -New @($Difference.Folders) `
        -Key { $_.Path } -Label { $_.Path } -Value { "Besitzer=$($_.Owner); Vererbung unterbrochen=$($_.InheritanceProtected)" }

    Compare-SLRows -Category 'Effektiver Zugriff' -Old @($Reference.Matrix) -New @($Difference.Matrix) `
        -Key { "$($_.Path)|$($_.Principal)" } -Label { "$($_.Path): $($_.Principal)" } -Value { $_.EffectiveLevel }
}

# ---- Public/Get-SLDfsMap.ps1
function Get-SLDfsMap {
    <#
    .SYNOPSIS
    Listet DFS-Namespaces mit Ordnern und Zielen (UNC) als flache Tabelle.

    .DESCRIPTION
    Nutzt das Dfsn-Modul (RSAT). Ohne Parameter werden alle domänenbasierten
    Namespaces der aktuellen Domäne gelesen. Jede Zeile ist ein Root- oder Ordnerziel.
    Basiert auf der Idee von Get-SchunkDfsNamespaceHealth (windows-it-toolkit, MIT).

    .PARAMETER NamespacePath
    Ein oder mehrere Namespace-Roots, z. B. \\contoso.local\Daten.

    .PARAMETER Domain
    Domäne, deren Namespaces gelesen werden (Standard: $env:USERDNSDOMAIN).

    .PARAMETER NamespaceServer
    Server mit eigenständigen (standalone) Namespaces.

    .EXAMPLE
    Get-SLDfsMap | Format-Table DfsPath, TargetPath, TargetState

    .EXAMPLE
    Get-SLDfsMap -NamespacePath '\\contoso.local\Daten'
    #>
    [CmdletBinding()]
    param(
        [string[]]$NamespacePath,
        [string]$Domain,
        [string[]]$NamespaceServer
    )

    $data = Get-SLDfsData -NamespacePath $NamespacePath -Domain $Domain -NamespaceServer $NamespaceServer
    foreach ($e in $data.Errors) { Write-Warning "[$($e.Stage)] $($e.Target): $($e.Message)" }
    $data.Targets
}

function Get-SLDfsReplication {
    <#
    .SYNOPSIS
    Listet DFS-Replikationsgruppen mit Mitgliedern und lokalen Inhaltspfaden.

    .EXAMPLE
    Get-SLDfsReplication | Format-Table GroupName, FolderName, ComputerName, ContentPath, ReadOnly
    #>
    [CmdletBinding()]
    param([string]$Domain)

    $data = Get-SLDfsReplicationData -Domain $Domain
    foreach ($e in $data.Errors) { Write-Warning "[$($e.Stage)] $($e.Target): $($e.Message)" }
    $data.Rows
}

# ---- Public/Get-SLNtfsPermission.ps1
function Get-SLNtfsPermission {
    <#
    .SYNOPSIS
    NTFS-Berechtigungen ab einem Pfad bis zu einer Tiefe – nur dort, wo sich etwas ändert.

    .DESCRIPTION
    Standardmäßig werden ACEs nur für "Grenzordner" ausgegeben: Startordner, Ordner mit
    deaktivierter Vererbung oder mit expliziten Einträgen. Mit -IncludeInherited für alle Ordner.
    Reparse Points (Junctions) werden nicht verfolgt.
    Weiterentwicklung von Get-NtfsPermissionAudit.ps1 (windows-it-toolkit, MIT).

    .PARAMETER Folders
    Gibt statt der ACE-Zeilen die Ordnerzeilen aus (Besitzer, Vererbung, Anzahl expliziter ACEs).

    .EXAMPLE
    Get-SLNtfsPermission -Path \\FS01\Daten -Depth 3 | Format-Table Path, Identity, Level, AppliesTo, Inherited

    .EXAMPLE
    Get-SLNtfsPermission -Path \\FS01\Daten -Depth 5 -Folders | Where-Object InheritanceProtected
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string[]]$Path,
        [ValidateRange(0, 50)][int]$Depth = 2,
        [switch]$IncludeInherited,
        [switch]$Folders
    )

    process {
        foreach ($p in $Path) {
            $u = Split-SLUncPath -Path $p
            $computer = $null
            if ($u) { $computer = $u.Host }
            $scan = Invoke-SLNtfsScan -Root $p -Depth $Depth -IncludeInherited:$IncludeInherited -ComputerName $computer
            foreach ($e in $scan.Errors) { Write-Warning "[$($e.Stage)] $($e.Target): $($e.Message)" }
            if ($Folders) { $scan.Folders } else { $scan.Aces }
        }
    }
}

# ---- Public/Get-SLShareInventory.ps1
function Get-SLShareInventory {
    <#
    .SYNOPSIS
    Freigaben eines oder mehrerer Server inkl. Freigabeberechtigungen.

    .DESCRIPTION
    Liest remote per CIM (WinRM, Fallback DCOM). Ab Server 2012 über MSFT_SmbShare
    (inkl. ABE, Verschlüsselung, Caching, Cluster-Scope), bei 2008/2008 R2 über Win32_Share.
    Freigabeberechtigungen werden aus der Sicherheitsbeschreibung gelesen (mit SID).
    Weiterentwicklung von Get-SmbShareInventory.ps1 (windows-it-toolkit, MIT).

    .EXAMPLE
    Get-SLShareInventory -ComputerName FS01, FS02 | Format-Table ShareUnc, LocalPath, FullAccess, ChangeAccess, ReadAccess

    .EXAMPLE
    Get-SLShareInventory -ComputerName FS01 -ShareName 'Daten*' -ExcludeShare 'Daten_alt'
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][string[]]$ComputerName = @($env:COMPUTERNAME),
        [string[]]$ShareName = @('*'),
        [string[]]$ExcludeShare,
        [switch]$IncludeAdministrative,
        [pscredential]$Credential
    )

    process {
        foreach ($c in $ComputerName) {
            $data = Get-SLShareData -ComputerName $c -ShareName $ShareName -ExcludeShare $ExcludeShare -IncludeAdministrative:$IncludeAdministrative -Credential $Credential
            foreach ($e in $data.Errors) { Write-Warning "[$($e.Stage)] $($e.Target): $($e.Message)" }
            foreach ($s in $data.Shares) {
                $allow = @($s.Access | Where-Object AccessControlType -eq 'Allow')
                $s | Select-Object ComputerName, ScopeName, ShareName, ShareUnc, LocalPath, Description, Special,
                ContinuouslyAvailable, EncryptData, AccessBasedEnumeration, CachingMode, ConcurrentUserLimit, CurrentUsers, Source,
                @{ n = 'FullAccess'; e = { (@($allow | Where-Object AccessRight -eq 'Full').AccountName) -join '; ' } },
                @{ n = 'ChangeAccess'; e = { (@($allow | Where-Object AccessRight -eq 'Change').AccountName) -join '; ' } },
                @{ n = 'ReadAccess'; e = { (@($allow | Where-Object AccessRight -eq 'Read').AccountName) -join '; ' } },
                @{ n = 'DenyAccess'; e = { (@($s.Access | Where-Object AccessControlType -eq 'Deny').AccountName) -join '; ' } },
                Access
            }
        }
    }
}

# ---- Public/Invoke-SLFileServerReport.ps1
function Invoke-SLFileServerReport {
    <#
    .SYNOPSIS
    Komplettbericht: DFS-Namespace -> Freigaben -> NTFS -> Gruppenauflösung -> effektive Zugriffe.

    .DESCRIPTION
    1. DFS-Namespaces lesen (optional) und Zielserver ermitteln
    2. Freigaben + Freigabeberechtigungen aller Server lesen
    3. NTFS-ACLs je Freigabe bis -Depth (nur Grenzordner, s. Get-SLNtfsPermission)
    4. Alle Konten rekursiv bis auf Benutzer auflösen (AD + lokale Servergruppen)
    5. Effektiven Zugriff je Benutzer und Grenzordner berechnen (Freigabe ∩ NTFS)
    6. Befunde ableiten, optional Zugriffstests, Export als HTML/CSV/XLSX/JSON

    Ohne Angabe von -ComputerName/-DfsNamespace/-AllDomainNamespaces/-Path wird der lokale Server geprüft.
    Nur lesend – es wird nichts verändert (Ausnahme: keine; -TestAccess prüft nur Lesen).

    .PARAMETER ComputerName
    Fileserver (bei Clustern den Clientzugriffspunkt oder einen Knoten angeben).

    .PARAMETER DfsNamespace
    DFS-Namespace-Roots, z. B. \\contoso.local\Daten.

    .PARAMETER AllDomainNamespaces
    Alle domänenbasierten Namespaces der Domäne einbeziehen.

    .PARAMETER Path
    Zusätzliche beliebige UNC-Pfade (z. B. NAS-Freigaben ohne CIM-Zugriff).

    .PARAMETER SkipDfsTargetServers
    Zielserver aus DFS NICHT automatisch inventarisieren (nur die DFS-Ziele selbst scannen).

    .PARAMETER Depth
    Ordnertiefe für den NTFS-Scan (0 = nur Freigabe-Root). Standard 2.

    .PARAMETER UserProperty
    Zusätzliche AD-Attribute für die Matrix, z. B. mail, department, title.

    .PARAMETER OutputPath
    Zielordner für den Export. Ohne Angabe wird nur das Berichtsobjekt zurückgegeben.

    .EXAMPLE
    Invoke-SLFileServerReport -AllDomainNamespaces -Depth 3 -OutputPath C:\Reports

    .EXAMPLE
    Invoke-SLFileServerReport -ComputerName FS01, FS02 -DfsNamespace \\contoso.local\Daten -UserProperty mail, department -OutputPath C:\Reports -Format Html, Xlsx

    .EXAMPLE
    $r = Invoke-SLFileServerReport -ComputerName FS01 -Depth 1
    $r.Matrix | Where-Object Principal -like '*mueller*' | Format-Table Path, EffectiveLevel, ViaNtfs
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [string[]]$DfsNamespace,
        [switch]$AllDomainNamespaces,
        [string]$Domain,
        [string[]]$NamespaceServer,
        [string[]]$Path,
        [string[]]$ShareName = @('*'),
        [string[]]$ExcludeShare,
        [switch]$IncludeAdministrativeShares,
        [switch]$SkipDfsTargetServers,
        [ValidateRange(0, 50)][int]$Depth = 2,
        [switch]$IncludeInherited,
        [switch]$NoGroupExpansion,
        [string[]]$UserProperty = @(),
        [string]$LdapServer,
        [switch]$IncludeSystemPrincipals,
        [switch]$IncludeReplication,
        [switch]$TestAccess,
        [pscredential]$Credential,
        [string]$OutputPath,
        [ValidateSet('Html', 'Csv', 'Xlsx', 'Json')][string[]]$Format = @('Html', 'Csv', 'Xlsx', 'Json')
    )

    $started = Get-Date
    Reset-SLCache
    $script:SLUserProperty = @($UserProperty)
    $script:SLLdapServer = $LdapServer

    $errors = New-Object System.Collections.Generic.List[object]
    $useDfs = [bool]($DfsNamespace -or $AllDomainNamespaces -or $NamespaceServer)
    if (-not $ComputerName -and -not $useDfs -and -not $Path) { $ComputerName = @($env:COMPUTERNAME) }
    $activity = 'ShareLens Fileserver-Bericht'

    # 1) DFS ------------------------------------------------------------------------------
    $dfs = @()
    $dfsRepl = @()
    if ($useDfs) {
        Write-Progress -Activity $activity -Status 'DFS-Namespaces lesen' -PercentComplete 2
        $d = Get-SLDfsData -NamespacePath $DfsNamespace -Domain $Domain -NamespaceServer $NamespaceServer
        $dfs = @($d.Targets)
        foreach ($e in $d.Errors) { $errors.Add($e) }
        if ($IncludeReplication) {
            $r = Get-SLDfsReplicationData -Domain $Domain
            $dfsRepl = @($r.Rows)
            foreach ($e in $r.Errors) { $errors.Add($e) }
        }
    }
    $folderTargets = @($dfs | Where-Object { $_.Kind -eq 'FolderTarget' -and $_.TargetPath })

    # 2) Freigaben ---------------------------------------------------------------------------
    $computers = New-Object System.Collections.Generic.List[string]
    $seenHosts = @{}
    foreach ($c in @($ComputerName)) {
        if (-not $c) { continue }
        $k = $c.Split('.')[0].ToUpperInvariant()
        if (-not $seenHosts.ContainsKey($k)) { $seenHosts[$k] = $true; $computers.Add($c) }
    }
    if (-not $SkipDfsTargetServers) {
        foreach ($t in $folderTargets) {
            $k = $t.TargetServer.Split('.')[0].ToUpperInvariant()
            if ($t.TargetServer -and -not $seenHosts.ContainsKey($k)) { $seenHosts[$k] = $true; $computers.Add($t.TargetServer) }
        }
    }

    $shares = New-Object System.Collections.Generic.List[object]
    $shareKeys = @{}
    $i = 0
    foreach ($c in $computers) {
        $i++
        Write-Progress -Activity $activity -Status "Freigaben lesen: $c" -PercentComplete (5 + [int](15 * $i / [Math]::Max(1, $computers.Count)))
        $sd = Get-SLShareData -ComputerName $c -ShareName $ShareName -ExcludeShare $ExcludeShare -IncludeAdministrative:$IncludeAdministrativeShares -Credential $Credential
        foreach ($e in $sd.Errors) { $errors.Add($e) }
        foreach ($s in $sd.Shares) {
            $key = ConvertTo-SLUncKey -Path $s.ShareUnc
            if ($shareKeys.ContainsKey($key)) { continue }   # Cluster: gleiche Freigabe über mehrere Knoten
            $shareKeys[$key] = $s
            $shares.Add($s)
        }
    }

    # 3) Scan-Wurzeln --------------------------------------------------------------------------
    $roots = New-Object System.Collections.Generic.List[object]
    $rootKeys = @{}
    function Add-SLRoot([string]$Unc, [string]$ShareKey, [string]$ShareUnc, [string]$Source) {
        $k = ConvertTo-SLUncKey -Path $Unc
        if ($rootKeys.ContainsKey($k)) { return }
        $rootKeys[$k] = $true
        $u = Split-SLUncPath -Path $Unc
        $ctx = ''
        $hostName = ''
        if ($u) { $ctx = $u.HostShort; $hostName = $u.Host }
        $roots.Add([pscustomobject]@{ Root = $Unc.TrimEnd('\'); ShareKey = $ShareKey; ShareUnc = $ShareUnc; Source = $Source; Context = $ctx; Host = $hostName })
    }
    function Find-SLShareFor([string]$Unc) {
        $u = Split-SLUncPath -Path $Unc
        if (-not $u) { return $null }
        $sk = ConvertTo-SLUncKey -Path ('\\' + $u.Host + '\' + $u.Share)
        if ($shareKeys.ContainsKey($sk)) { return [pscustomobject]@{ Key = $sk; Share = $shareKeys[$sk]; SubDepth = @($u.Segments).Count } }
        $null
    }

    foreach ($s in $shares) { Add-SLRoot -Unc $s.ShareUnc -ShareKey (ConvertTo-SLUncKey -Path $s.ShareUnc) -ShareUnc $s.ShareUnc -Source 'Freigabe' }
    foreach ($t in $folderTargets) {
        $m = Find-SLShareFor -Unc $t.TargetPath
        if (-not $m) { Add-SLRoot -Unc $t.TargetPath -ShareKey $null -ShareUnc '' -Source 'DFS-Ziel' }
        elseif ($m.SubDepth -gt $Depth) { Add-SLRoot -Unc $t.TargetPath -ShareKey $m.Key -ShareUnc $m.Share.ShareUnc -Source 'DFS-Ziel' }
    }
    foreach ($p in @($Path)) {
        if (-not $p) { continue }
        $m = Find-SLShareFor -Unc $p
        if ($m) { Add-SLRoot -Unc $p -ShareKey $m.Key -ShareUnc $m.Share.ShareUnc -Source 'Pfad' }
        else { Add-SLRoot -Unc $p -ShareKey $null -ShareUnc '' -Source 'Pfad' }
    }

    # 4) NTFS --------------------------------------------------------------------------------
    $folders = New-Object System.Collections.Generic.List[object]
    $aces = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $i = 0
    foreach ($r in $roots) {
        $i++
        Write-Progress -Activity $activity -Status "NTFS lesen: $($r.Root)" -PercentComplete (20 + [int](45 * $i / [Math]::Max(1, $roots.Count)))
        $scan = Invoke-SLNtfsScan -Root $r.Root -Depth $Depth -IncludeInherited:$IncludeInherited -ComputerName $r.Host -Seen $seen
        foreach ($e in $scan.Errors) { $errors.Add($e) }
        foreach ($f in $scan.Folders) {
            $f | Add-Member -NotePropertyName DfsPath -NotePropertyValue (Get-SLDfsPathForUnc -Path $f.Path -DfsTargets $dfs)
            $f | Add-Member -NotePropertyName ShareUnc -NotePropertyValue $r.ShareUnc
            $f | Add-Member -NotePropertyName ShareKey -NotePropertyValue $r.ShareKey
            $f | Add-Member -NotePropertyName ScanRoot -NotePropertyValue $r.Root
            $f | Add-Member -NotePropertyName Context -NotePropertyValue $r.Context
            $folders.Add($f)
        }
        $dfsByPath = @{}
        foreach ($f in $scan.Folders) { $dfsByPath[$f.Path.ToUpperInvariant()] = $f.DfsPath }
        foreach ($a in $scan.Aces) {
            $a | Add-Member -NotePropertyName DfsPath -NotePropertyValue $dfsByPath[$a.Path.ToUpperInvariant()]
            $a | Add-Member -NotePropertyName ShareUnc -NotePropertyValue $r.ShareUnc
            $a | Add-Member -NotePropertyName Context -NotePropertyValue $r.Context
            $aces.Add($a)
        }
    }

    # Freigabeberechtigungen flach
    $shareAccess = New-Object System.Collections.Generic.List[object]
    foreach ($s in $shares) {
        $u = Split-SLUncPath -Path $s.ShareUnc
        $ctx = ''
        if ($u) { $ctx = $u.HostShort }
        foreach ($a in $s.Access) {
            $cat = Get-SLSidCategory -Sid $a.Sid
            $shareAccess.Add([pscustomobject]@{
                    ShareUnc    = $s.ShareUnc
                    ShareKey    = (ConvertTo-SLUncKey -Path $s.ShareUnc)
                    Identity    = $a.AccountName
                    IdentitySid = $a.Sid
                    Category    = $cat
                    AccessType  = $a.AccessControlType
                    AccessRight = $a.AccessRight
                    Level       = (Get-SLLevelName -Mask $a.Mask)
                    Mask        = $a.Mask
                    Context     = $ctx
                })
        }
    }

    # 5) Gruppenauflösung ------------------------------------------------------------------------
    $members = @{}
    $memberRows = New-Object System.Collections.Generic.List[object]
    $identityClass = @{}
    $principalList = @{}
    foreach ($a in $aces) {
        if (-not $a.IdentitySid) { continue }
        if ($a.Category -eq 'System' -and -not $IncludeSystemPrincipals) { continue }
        $principalList["$($a.Context)|$($a.IdentitySid)"] = @($a.Context, $a.IdentitySid, $a.Identity)
    }
    foreach ($a in $shareAccess) {
        if (-not $a.IdentitySid) { continue }
        $principalList["$($a.Context)|$($a.IdentitySid)"] = @($a.Context, $a.IdentitySid, $a.Identity)
    }

    if (-not $NoGroupExpansion) {
        $hostByContext = @{}
        foreach ($r in $roots) { $hostByContext[$r.Context] = $r.Host }
        foreach ($s in $shares) { $u = Split-SLUncPath -Path $s.ShareUnc; if ($u -and -not $hostByContext.ContainsKey($u.HostShort)) { $hostByContext[$u.HostShort] = $u.Host } }

        $i = 0
        $total = [Math]::Max(1, $principalList.Count)
        foreach ($k in @($principalList.Keys)) {
            $i++
            $ctx, $sid, $name = $principalList[$k]
            Write-Progress -Activity $activity -Status "Gruppen auflösen: $name" -PercentComplete (65 + [int](25 * $i / $total))
            $leafs = @(Get-SLPrincipalLeaf -Sid $sid -ComputerName $hostByContext[$ctx] -Name $name)
            $members[$k] = $leafs

            if ($leafs.Count -eq 1 -and $leafs[0].Sid -eq $sid -and @($leafs[0].Via).Count -eq 0) { $identityClass[$k] = $leafs[0].ObjectClass }
            elseif ($leafs.Count -eq 0) { $identityClass[$k] = 'group (leer)' }
            else { $identityClass[$k] = 'group' }

            if ($identityClass[$k] -like 'group*') {
                if ($leafs.Count -eq 0) {
                    $memberRows.Add([pscustomobject]@{ Context = $ctx; Principal = $name; PrincipalSid = $sid; Member = '(leer)'; DisplayName = ''; ObjectClass = ''; Enabled = $null; Via = ''; MemberSid = '' })
                }
                foreach ($l in $leafs) {
                    $memberRows.Add([pscustomobject]@{
                            Context = $ctx; Principal = $name; PrincipalSid = $sid; Member = $l.Account; DisplayName = $l.DisplayName
                            ObjectClass = $l.ObjectClass; Enabled = $l.Enabled; Via = (@($l.Via) -join ' > '); MemberSid = $l.Sid
                        })
                }
            }
        }
    }
    foreach ($a in $aces) {
        $cls = $identityClass["$($a.Context)|$($a.IdentitySid)"]
        if (-not $cls) { $cls = '' }
        $a | Add-Member -NotePropertyName IdentityClass -NotePropertyValue $cls
    }
    foreach ($a in $shareAccess) {
        $cls = $identityClass["$($a.Context)|$($a.IdentitySid)"]
        if (-not $cls) { $cls = '' }
        $a | Add-Member -NotePropertyName IdentityClass -NotePropertyValue $cls
    }

    # 6) Matrix --------------------------------------------------------------------------------
    Write-Progress -Activity $activity -Status 'Effektive Zugriffe berechnen' -PercentComplete 92
    $matrix = @(New-SLAccessMatrix -Folders $folders -Aces $aces -ShareAccess $shareAccess -Members $members -UserProperty $UserProperty -IncludeSystem:$IncludeSystemPrincipals)

    # Freigaben flach (für Tabellen)
    $shareRows = foreach ($s in $shares) {
        $allow = @($s.Access | Where-Object AccessControlType -eq 'Allow')
        [pscustomobject]@{
            ComputerName           = $s.ComputerName
            ShareName              = $s.ShareName
            ShareUnc               = $s.ShareUnc
            DfsPath                = (Get-SLDfsPathForUnc -Path $s.ShareUnc -DfsTargets $dfs)
            LocalPath              = $s.LocalPath
            Description            = $s.Description
            Special                = $s.Special
            ScopeName              = $s.ScopeName
            AccessBasedEnumeration = $s.AccessBasedEnumeration
            EncryptData            = $s.EncryptData
            ContinuouslyAvailable  = $s.ContinuouslyAvailable
            CachingMode            = $s.CachingMode
            CurrentUsers           = $s.CurrentUsers
            FullAccess             = (@($allow | Where-Object AccessRight -eq 'Full').AccountName) -join '; '
            ChangeAccess           = (@($allow | Where-Object AccessRight -eq 'Change').AccountName) -join '; '
            ReadAccess             = (@($allow | Where-Object AccessRight -eq 'Read').AccountName) -join '; '
            DenyAccess             = (@($s.Access | Where-Object AccessControlType -eq 'Deny').AccountName) -join '; '
            Source                 = $s.Source
        }
    }

    # 7) Zugriffstests ---------------------------------------------------------------------------
    $tests = @()
    if ($TestAccess) {
        Write-Progress -Activity $activity -Status 'Zugriffstests' -PercentComplete 95
        $testPaths = @(@($folderTargets | Select-Object -ExpandProperty DfsPath -Unique) + @($shares | Select-Object -ExpandProperty ShareUnc)) | Where-Object { $_ } | Select-Object -Unique
        $tests = @(Test-SLShareAccess -Path $testPaths)
    }

    $report = [pscustomobject]@{
        PSTypeName     = 'ShareLens.Report'
        Meta           = [pscustomobject]@{
            Tool          = 'ShareLens'
            Version       = $script:SLVersion
            GeneratedAt   = $started.ToString('yyyy-MM-dd HH:mm:ss')
            DurationSec   = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
            GeneratedBy   = "$env:USERDOMAIN\$env:USERNAME"
            RunOn         = $env:COMPUTERNAME
            Servers       = ($computers -join ', ')
            Namespaces    = ((@($dfs | Select-Object -ExpandProperty Namespace -Unique)) -join ', ')
            Depth         = $Depth
            GroupExpansion = (-not $NoGroupExpansion)
            ScanRoots     = $roots.Count
        }
        Findings       = @()
        Dfs            = $dfs
        DfsReplication = $dfsRepl
        Shares         = @($shareRows)
        ShareAccess    = $shareAccess.ToArray()
        Folders        = $folders.ToArray()
        Aces           = $aces.ToArray()
        Matrix         = $matrix
        Members        = $memberRows.ToArray()
        AccessTests    = $tests
        Errors         = $errors.ToArray()
    }
    $report.Findings = @(Get-SLFindings -Report $report)
    Write-Progress -Activity $activity -Completed

    if ($OutputPath) {
        $files = Export-SLReport -Report $report -OutputPath $OutputPath -Format $Format
        foreach ($f in $files) { Write-Verbose "Geschrieben: $($f.FullName)" }
        $report | Add-Member -NotePropertyName Files -NotePropertyValue @($files | ForEach-Object { $_.FullName })
    }
    $report
}

# ---- Public/Resolve-SLPrincipal.ps1
function Resolve-SLPrincipal {
    <#
    .SYNOPSIS
    Löst ein Konto oder eine Gruppe rekursiv bis auf Benutzer auf (verschachtelte Gruppen).

    .DESCRIPTION
    Domänengruppen per LDAP (kein RSAT nötig, >1500 Mitglieder per Range-Retrieval),
    lokale Gruppen eines Fileservers (z. B. VORDEFINIERT\Administratoren) per WinNT.
    Breite Gruppen (Jeder, Authentifizierte Benutzer, Domänen-Benutzer) werden nicht aufgelöst.

    .PARAMETER Identity
    Name (DOMAIN\Gruppe) oder SID.

    .PARAMETER ComputerName
    Server, in dessen Kontext lokale Gruppen aufgelöst werden.

    .PARAMETER UserProperty
    Zusätzliche AD-Attribute der Benutzer, z. B. mail, department.

    .EXAMPLE
    Resolve-SLPrincipal -Identity 'CONTOSO\GG_Vertrieb_RW' -UserProperty mail, department

    .EXAMPLE
    Resolve-SLPrincipal -Identity 'S-1-5-32-544' -ComputerName FS01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string[]]$Identity,
        [string]$ComputerName,
        [string[]]$UserProperty = @(),
        [string]$LdapServer
    )

    begin {
        $script:SLUserProperty = @($UserProperty)
        if ($LdapServer) { $script:SLLdapServer = $LdapServer }
    }
    process {
        foreach ($id in $Identity) {
            $sid = ConvertTo-SLSid -Name $id
            if (-not $sid) { Write-Warning "Konto '$id' nicht auflösbar."; continue }
            foreach ($leaf in @(Get-SLPrincipalLeaf -Sid $sid -ComputerName $ComputerName)) {
                $row = [ordered]@{
                    Principal   = $id
                    Account     = $leaf.Account
                    DisplayName = $leaf.DisplayName
                    ObjectClass = $leaf.ObjectClass
                    Enabled     = $leaf.Enabled
                    Via         = (@($leaf.Via) -join ' > ')
                    Sid         = $leaf.Sid
                }
                foreach ($p in $UserProperty) { $row["AD_$p"] = $leaf.Properties[$p] }
                [pscustomobject]$row
            }
        }
    }
}

# ---- Public/Test-SLShareAccess.ps1
function Test-SLShareAccess {
    <#
    .SYNOPSIS
    Prüft, ob Pfade (DFS oder UNC) mit dem aktuellen Konto lesbar und optional beschreibbar sind.

    .DESCRIPTION
    Übernommen aus Test-SmbShareAccess.ps1 (windows-it-toolkit, (c) 2026 David Schunk, MIT)
    und um Fehlerkategorie und DFS-Kennzeichnung erweitert.
    -WriteTest legt eine Testdatei an und löscht sie sofort wieder.

    .EXAMPLE
    Test-SLShareAccess -Path '\\contoso.local\Daten\Vertrieb', '\\FS01\Vertrieb$'

    .EXAMPLE
    Test-SLShareAccess -Path '\\FS01\Scans' -WriteTest
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string[]]$Path,
        [switch]$WriteTest
    )

    process {
        foreach ($share in $Path) {
            $started = Get-Date
            $readable = $false
            $writeable = $null
            $errorText = $null
            try {
                $null = Get-ChildItem -LiteralPath $share -ErrorAction Stop | Select-Object -First 1
                $readable = $true
                if ($WriteTest) {
                    $probe = Join-Path $share ".sharelens-probe-$([guid]::NewGuid().ToString('N')).tmp"
                    try {
                        Set-Content -LiteralPath $probe -Value 'ShareLens access probe' -Encoding UTF8 -ErrorAction Stop
                        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
                        $writeable = $true
                    }
                    catch { $writeable = $false; throw }
                }
            }
            catch { $errorText = $_.Exception.GetBaseException().Message }

            [pscustomobject]@{
                Path                 = $share
                User                 = [Environment]::UserName
                Readable             = $readable
                WriteTestRequested   = [bool]$WriteTest
                Writeable            = $writeable
                ResponseMilliseconds = [math]::Round(((Get-Date) - $started).TotalMilliseconds)
                Error                = $errorText
            }
        }
    }
}

Export-ModuleMember -Function @('Invoke-SLFileServerReport', 'Get-SLDfsMap', 'Get-SLDfsReplication', 'Get-SLShareInventory', 'Get-SLNtfsPermission', 'Resolve-SLPrincipal', 'Test-SLShareAccess', 'Export-SLReport', 'Import-SLReport', 'Compare-SLReport')
} | Import-Module -Force -DisableNameChecking
Write-Host 'ShareLens 0.1.0 geladen. Start: Invoke-SLFileServerReport -AllDomainNamespaces -OutputPath C:\Reports' -ForegroundColor Cyan
