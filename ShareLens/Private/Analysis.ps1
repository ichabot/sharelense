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
