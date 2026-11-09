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
