# Erzeugt einen synthetischen Bericht (ohne Windows/AD) für Tests und Vorschau.
# Nutzung:  . ./tests/DemoData.ps1 ; $r = New-SLDemoReport

function New-SLDemoReport {
    $module = Get-Module ShareLens
    if (-not $module) { throw 'Modul ShareLens zuerst importieren.' }

    & $module {
        $dom = 'S-1-5-21-1000-2000-3000'
        $dfs = @(
            [pscustomobject]@{ Kind = 'FolderTarget'; Namespace = '\\contoso.local\Daten'; NamespaceType = 'DomainV2'; DfsPath = '\\contoso.local\Daten\Vertrieb'; FolderState = 'Online'; Description = ''; TargetPath = '\\fs01.contoso.local\Vertrieb$'; TargetServer = 'fs01.contoso.local'; TargetShare = 'Vertrieb$'; TargetSubPath = ''; TargetState = 'Online'; ReferralPriorityClass = 'SiteCostNormal'; ReferralPriorityRank = 0 }
            [pscustomobject]@{ Kind = 'FolderTarget'; Namespace = '\\contoso.local\Daten'; NamespaceType = 'DomainV2'; DfsPath = '\\contoso.local\Daten\Vertrieb'; FolderState = 'Online'; Description = ''; TargetPath = '\\fs02.contoso.local\Vertrieb$'; TargetServer = 'fs02.contoso.local'; TargetShare = 'Vertrieb$'; TargetSubPath = ''; TargetState = 'Offline'; ReferralPriorityClass = 'SiteCostNormal'; ReferralPriorityRank = 0 }
            [pscustomobject]@{ Kind = 'FolderTarget'; Namespace = '\\contoso.local\Daten'; NamespaceType = 'DomainV2'; DfsPath = '\\contoso.local\Daten\Projekte'; FolderState = 'Online'; Description = ''; TargetPath = '\\fs01\Projekte$\Aktiv'; TargetServer = 'fs01'; TargetShare = 'Projekte$'; TargetSubPath = 'Aktiv'; TargetState = 'Online'; ReferralPriorityClass = 'SiteCostNormal'; ReferralPriorityRank = 0 }
        )

        $shareAccess = @(
            [pscustomobject]@{ ShareUnc = '\\fs01\Vertrieb$'; ShareKey = '\\FS01\VERTRIEB$'; Identity = 'Jeder'; IdentitySid = 'S-1-1-0'; Category = 'Broad'; AccessType = 'Allow'; AccessRight = 'Full'; Level = 'Vollzugriff'; Mask = $script:SLMaskFull; Context = 'FS01'; IdentityClass = 'broad' }
            [pscustomobject]@{ ShareUnc = '\\fs01\Projekte$'; ShareKey = '\\FS01\PROJEKTE$'; Identity = 'Authentifizierte Benutzer'; IdentitySid = 'S-1-5-11'; Category = 'Broad'; AccessType = 'Allow'; AccessRight = 'Change'; Level = 'Ändern'; Mask = $script:SLMaskModify; Context = 'FS01'; IdentityClass = 'broad' }
            [pscustomobject]@{ ShareUnc = '\\fs01\Projekte$'; ShareKey = '\\FS01\PROJEKTE$'; Identity = 'CONTOSO\GG_Extern'; IdentitySid = "$dom-3001"; Category = 'Normal'; AccessType = 'Allow'; AccessRight = 'Read'; Level = 'Lesen'; Mask = $script:SLMaskRead; Context = 'FS01'; IdentityClass = 'group' }
        )

        function A($path, $depth, $name, $sid, $cat, $type, $mask, $inh, $applies = 'Dieser Ordner, Unterordner und Dateien', $cls = 'group', $ctx = 'FS01', $shareUnc = '\\fs01\Vertrieb$', $dfsPath = '') {
            [pscustomobject]@{ Path = $path; Depth = $depth; Identity = $name; IdentitySid = $sid; Category = $cat; AccessType = $type
                Level = (Get-SLLevelName -Mask $mask); Rights = 'x'; RightsMask = [int64]$mask; Inherited = $inh; AppliesTo = $applies
                AppliesToThisFolder = ($applies -notlike 'Nur Unter*' -and $applies -ne 'Nur Dateien'); InheritanceFlags = 'ContainerInherit, ObjectInherit'
                PropagationFlags = 'None'; DfsPath = $dfsPath; ShareUnc = $shareUnc; Context = $ctx; IdentityClass = $cls }
        }
        $v = '\\fs01\Vertrieb$'
        $p = '\\fs01\Projekte$'
        $aces = @(
            A $v 0 'VORDEFINIERT\Administratoren' 'S-1-5-32-544' 'Normal' 'Allow' 0x1F01FF $true -cls 'group' -dfsPath '\\contoso.local\Daten\Vertrieb'
            A $v 0 'NT-AUTORITÄT\SYSTEM' 'S-1-5-18' 'System' 'Allow' 0x1F01FF $true -cls 'system' -dfsPath '\\contoso.local\Daten\Vertrieb'
            A $v 0 'CONTOSO\GG_Vertrieb_RW' "$dom-2001" 'Normal' 'Allow' 0x1301BF $false -dfsPath '\\contoso.local\Daten\Vertrieb'
            A $v 0 'CONTOSO\GG_Vertrieb_R' "$dom-2002" 'Normal' 'Allow' 0x1200A9 $false -dfsPath '\\contoso.local\Daten\Vertrieb'
            A $v 0 'VORDEFINIERT\Benutzer' 'S-1-5-32-545' 'Broad' 'Allow' 0x1200A9 $true -cls 'broad' -dfsPath '\\contoso.local\Daten\Vertrieb'
            A "$v\Angebote" 1 'CONTOSO\GG_Vertrieb_RW' "$dom-2001" 'Normal' 'Allow' 0x1301BF $false -dfsPath '\\contoso.local\Daten\Vertrieb\Angebote'
            A "$v\Angebote" 1 'CONTOSO\m.mueller' "$dom-1105" 'Normal' 'Allow' 0x1F01FF $false -cls 'user' -dfsPath '\\contoso.local\Daten\Vertrieb\Angebote'
            A "$v\Angebote" 1 "$dom-1999" "$dom-1999" 'Orphaned' 'Allow' 0x1301BF $false -cls 'unresolved' -dfsPath '\\contoso.local\Daten\Vertrieb\Angebote'
            A "$v\Angebote" 1 'CONTOSO\a.azubi' "$dom-1201" 'Normal' 'Deny' 0x10000 $false -cls 'user' -dfsPath '\\contoso.local\Daten\Vertrieb\Angebote'
            A $p 0 'VORDEFINIERT\Administratoren' 'S-1-5-32-544' 'Normal' 'Allow' 0x1F01FF $true -cls 'group' -shareUnc $p
            A $p 0 'Jeder' 'S-1-1-0' 'Broad' 'Allow' 0x1301BF $false -cls 'broad' -shareUnc $p
            A "$p\Aktiv" 1 'VORDEFINIERT\Administratoren' 'S-1-5-32-544' 'Normal' 'Allow' 0x1F01FF $true -cls 'group' -shareUnc $p -dfsPath '\\contoso.local\Daten\Projekte'
            A "$p\Aktiv" 1 'Jeder' 'S-1-1-0' 'Broad' 'Allow' 0x1301BF $true -cls 'broad' -shareUnc $p -dfsPath '\\contoso.local\Daten\Projekte'
            A "$p\Aktiv" 1 'CONTOSO\GG_Extern' "$dom-3001" 'Normal' 'Allow' 0x1200A9 $false -shareUnc $p -dfsPath '\\contoso.local\Daten\Projekte'
        )
        $folders = @(
            [pscustomobject]@{ Path = $v; Depth = 0; Owner = 'VORDEFINIERT\Administratoren'; OwnerSid = 'S-1-5-32-544'; InheritanceProtected = $true; ExplicitAceCount = 2; AceCount = 5; IsBoundary = $true; DfsPath = '\\contoso.local\Daten\Vertrieb'; ShareUnc = $v; ShareKey = '\\FS01\VERTRIEB$'; ScanRoot = $v; Context = 'FS01' }
            [pscustomobject]@{ Path = "$v\Angebote"; Depth = 1; Owner = 'CONTOSO\m.mueller'; OwnerSid = "$dom-1105"; InheritanceProtected = $true; ExplicitAceCount = 4; AceCount = 4; IsBoundary = $true; DfsPath = '\\contoso.local\Daten\Vertrieb\Angebote'; ShareUnc = $v; ShareKey = '\\FS01\VERTRIEB$'; ScanRoot = $v; Context = 'FS01' }
            [pscustomobject]@{ Path = "$v\Archiv"; Depth = 1; Owner = 'VORDEFINIERT\Administratoren'; OwnerSid = 'S-1-5-32-544'; InheritanceProtected = $false; ExplicitAceCount = 0; AceCount = 5; IsBoundary = $false; DfsPath = '\\contoso.local\Daten\Vertrieb\Archiv'; ShareUnc = $v; ShareKey = '\\FS01\VERTRIEB$'; ScanRoot = $v; Context = 'FS01' }
            [pscustomobject]@{ Path = $p; Depth = 0; Owner = 'VORDEFINIERT\Administratoren'; OwnerSid = 'S-1-5-32-544'; InheritanceProtected = $false; ExplicitAceCount = 1; AceCount = 2; IsBoundary = $true; DfsPath = ''; ShareUnc = $p; ShareKey = '\\FS01\PROJEKTE$'; ScanRoot = $p; Context = 'FS01' }
            [pscustomobject]@{ Path = "$p\Aktiv"; Depth = 1; Owner = 'VORDEFINIERT\Administratoren'; OwnerSid = 'S-1-5-32-544'; InheritanceProtected = $false; ExplicitAceCount = 1; AceCount = 3; IsBoundary = $true; DfsPath = '\\contoso.local\Daten\Projekte'; ShareUnc = $p; ShareKey = '\\FS01\PROJEKTE$'; ScanRoot = $p; Context = 'FS01' }
        )

        $u = { param($sam, $rid, $name, $via, $enabled = $true) New-SLLeaf -Sid "$dom-$rid" -Account "CONTOSO\$sam" -DisplayName $name -ObjectClass 'user' -Enabled $enabled -Via $via -Properties @{ mail = "$sam@contoso.de"; department = 'Vertrieb' } }
        $members = @{
            'FS01|S-1-5-32-544'  = @((& $u 'admin.pd' 500 'Admin PD' @('VORDEFINIERT\Administratoren', 'CONTOSO\Domänen-Admins')))
            "FS01|$dom-2001"     = @((& $u 'm.mueller' 1105 'Maria Müller' @('CONTOSO\GG_Vertrieb_RW')), (& $u 'k.schulz' 1106 'Klaus Schulz' @('CONTOSO\GG_Vertrieb_RW', 'CONTOSO\GG_Vertrieb_Leitung')), (& $u 'alt.user' 1107 'Ehemaliger MA' @('CONTOSO\GG_Vertrieb_RW') $false))
            "FS01|$dom-2002"     = @((& $u 'a.azubi' 1201 'Anna Azubi' @('CONTOSO\GG_Vertrieb_R')))
            "FS01|$dom-1105"     = @((& $u 'm.mueller' 1105 'Maria Müller' @()))
            "FS01|$dom-1201"     = @((& $u 'a.azubi' 1201 'Anna Azubi' @()))
            "FS01|$dom-3001"     = @((& $u 'ext.berater' 4001 'Externer Berater' @('CONTOSO\GG_Extern')))
            'FS01|S-1-5-32-545'  = @(New-SLLeaf -Sid 'S-1-5-32-545' -Account 'VORDEFINIERT\Benutzer' -ObjectClass 'broad')
            'FS01|S-1-1-0'       = @(New-SLLeaf -Sid 'S-1-1-0' -Account 'Jeder' -ObjectClass 'broad')
            'FS01|S-1-5-11'      = @(New-SLLeaf -Sid 'S-1-5-11' -Account 'NT-AUTORITÄT\Authentifizierte Benutzer' -ObjectClass 'broad')
        }
        $memberRows = foreach ($k in $members.Keys) {
            foreach ($l in $members[$k]) {
                if (@($l.Via).Count -eq 0) { continue }
                [pscustomobject]@{ Context = 'FS01'; Principal = $l.Via[0]; PrincipalSid = ($k -split '\|')[1]; Member = $l.Account; DisplayName = $l.DisplayName; ObjectClass = $l.ObjectClass; Enabled = $l.Enabled; Via = (@($l.Via) -join ' > '); MemberSid = $l.Sid }
            }
        }

        $matrix = @(New-SLAccessMatrix -Folders $folders -Aces $aces -ShareAccess $shareAccess -Members $members -UserProperty @('mail', 'department'))
        $shares = @(
            [pscustomobject]@{ ComputerName = 'fs01'; ShareName = 'Vertrieb$'; ShareUnc = $v; DfsPath = (Get-SLDfsPathForUnc -Path $v -DfsTargets $dfs); LocalPath = 'D:\Shares\Vertrieb'; Description = ''; Special = $false; ScopeName = '*'; AccessBasedEnumeration = $true; EncryptData = $false; ContinuouslyAvailable = $false; CachingMode = 'Manual'; CurrentUsers = 12; FullAccess = 'Jeder'; ChangeAccess = ''; ReadAccess = ''; DenyAccess = ''; Source = 'MSFT_SmbShare' }
            [pscustomobject]@{ ComputerName = 'fs01'; ShareName = 'Projekte$'; ShareUnc = $p; DfsPath = (Get-SLDfsPathForUnc -Path $p -DfsTargets $dfs); LocalPath = 'D:\Shares\Projekte'; Description = 'Projektablage'; Special = $false; ScopeName = '*'; AccessBasedEnumeration = $false; EncryptData = $false; ContinuouslyAvailable = $false; CachingMode = 'Manual'; CurrentUsers = 3; FullAccess = ''; ChangeAccess = 'NT-AUTORITÄT\Authentifizierte Benutzer'; ReadAccess = 'CONTOSO\GG_Extern'; DenyAccess = ''; Source = 'MSFT_SmbShare' }
        )

        $report = [pscustomobject]@{
            PSTypeName     = 'ShareLens.Report'
            Meta           = [pscustomobject]@{ Tool = 'ShareLens'; Version = $script:SLVersion; GeneratedAt = '2026-11-09 10:00:00'; DurationSec = 4.2; GeneratedBy = 'CONTOSO\admin.pd'; RunOn = 'ADMIN01'; Servers = 'fs01.contoso.local, fs02.contoso.local'; Namespaces = '\\contoso.local\Daten'; Depth = 2; GroupExpansion = $true; ScanRoots = 2 }
            Findings       = @()
            Dfs            = $dfs
            DfsReplication = @()
            Shares         = $shares
            ShareAccess    = $shareAccess
            Folders        = $folders
            Aces           = $aces
            Matrix         = $matrix
            Members        = @($memberRows)
            AccessTests    = @()
            Errors         = @([pscustomobject]@{ Stage = 'Freigaben'; Target = 'fs02.contoso.local'; Message = 'CIM/WinRM und DCOM fehlgeschlagen: Der RPC-Server ist nicht verfügbar.' })
        }
        $report.Findings = @(Get-SLFindings -Report $report)
        $report
    }
}
