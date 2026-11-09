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
