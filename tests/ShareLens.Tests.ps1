BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'ShareLens/ShareLens.psd1') -Force
    . (Join-Path $PSScriptRoot 'DemoData.ps1')
}

Describe 'Rechte-Stufen' {
    It 'erkennt Standardrechte' {
        InModuleScope ShareLens {
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights 'FullControl') | Should -Be 'Vollzugriff'
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights 'Modify, Synchronize') | Should -Be 'Ändern'
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights 'ReadAndExecute, Synchronize') | Should -Be 'Lesen'
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights 'Read, Write, Synchronize') | Should -Be 'Lesen+Schreiben'
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights 'Traverse, Synchronize') | Should -Be 'Speziell'
            Get-SLLevelName -Mask 0 | Should -Be 'Kein'
        }
    }
    It 'wertet GENERIC-Bits aus' {
        InModuleScope ShareLens {
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights 268435456) | Should -Be 'Vollzugriff'
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights -1610612736) | Should -Be 'Lesen'   # GENERIC_READ|GENERIC_EXECUTE
            Get-SLLevelName -Mask (ConvertTo-SLRightsMask -Rights -536805376) | Should -Be 'Ändern'   # typische CREATOR-OWNER-Maske (GENERIC_READ|WRITE|EXECUTE + DELETE)
        }
    }
    It 'übersetzt Freigaberechte' {
        InModuleScope ShareLens {
            ConvertTo-SLShareRight -AccessMask 2032127 | Should -Be 'Full'
            ConvertTo-SLShareRight -AccessMask 1245631 | Should -Be 'Change'
            ConvertTo-SLShareRight -AccessMask 1179817 | Should -Be 'Read'
            Get-SLLevelName -Mask (Get-SLShareMask -AccessRight 'Change') | Should -Be 'Ändern'
        }
    }
    It 'zeigt "Gilt für" wie der Explorer' {
        InModuleScope ShareLens {
            (Get-SLAppliesTo 'ContainerInherit, ObjectInherit' 'None').Text | Should -Be 'Dieser Ordner, Unterordner und Dateien'
            (Get-SLAppliesTo 'ContainerInherit, ObjectInherit' 'InheritOnly').Text | Should -Be 'Nur Unterordner und Dateien'
            (Get-SLAppliesTo 'ContainerInherit, ObjectInherit' 'InheritOnly').AppliesToFolder | Should -BeFalse
            (Get-SLAppliesTo 'None' 'None').Text | Should -Be 'Nur dieser Ordner'
            (Get-SLAppliesTo 'ContainerInherit' 'NoPropagateInherit').Text | Should -Be 'Dieser Ordner und Unterordner (nur eine Ebene)'
        }
    }
}

Describe 'UNC und DFS' {
    It 'normalisiert FQDN und Kurzname gleich' {
        InModuleScope ShareLens {
            ConvertTo-SLUncKey '\\fs01.contoso.local\Daten\A' | Should -Be (ConvertTo-SLUncKey '\\FS01\daten\a\')
        }
    }
    It 'bildet DFS-Pfade für Unterordner' {
        InModuleScope ShareLens {
            $t = @(
                [pscustomobject]@{ DfsPath = '\\contoso.local\Daten\Vertrieb'; TargetPath = '\\fs01.contoso.local\Vertrieb$' }
                [pscustomobject]@{ DfsPath = '\\contoso.local\Daten\Projekte'; TargetPath = '\\fs01\Projekte$\Aktiv' }
            )
            Get-SLDfsPathForUnc -Path '\\FS01\Vertrieb$\Angebote\2026' -DfsTargets $t | Should -Be '\\contoso.local\Daten\Vertrieb\Angebote\2026'
            Get-SLDfsPathForUnc -Path '\\fs01\Projekte$\Aktiv\P-100' -DfsTargets $t | Should -Be '\\contoso.local\Daten\Projekte\P-100'
            Get-SLDfsPathForUnc -Path '\\fs01\Projekte$\Alt' -DfsTargets $t | Should -Be ''
            Get-SLDfsPathForUnc -Path '\\fs01\Projekte$\AktivX' -DfsTargets $t | Should -Be ''
        }
    }
    It 'klassifiziert SIDs' {
        InModuleScope ShareLens {
            Get-SLSidCategory 'S-1-1-0' | Should -Be 'Broad'
            Get-SLSidCategory 'S-1-5-21-1-2-3-513' | Should -Be 'Broad'
            Get-SLSidCategory 'S-1-5-18' | Should -Be 'System'
            Get-SLSidCategory 'S-1-5-80-123-456' | Should -Be 'System'
            Get-SLSidCategory 'S-1-5-21-1-2-3-1105' | Should -Be 'Normal'
        }
    }
}

Describe 'Effektive Zugriffe' {
    BeforeAll { $script:r = New-SLDemoReport }

    It 'begrenzt NTFS-Ändern durch Freigabe-Lesen' {
        $row = $r.Matrix | Where-Object { $_.Path -eq '\\fs01\Projekte$\Aktiv' -and $_.Principal -eq 'CONTOSO\ext.berater' }
        $row.NtfsLevel | Should -Be 'Ändern'          # Jeder: Ändern (geerbt) + GG_Extern Lesen
        $row.ShareLevel | Should -Be 'Ändern'         # Auth. Benutzer Ändern + GG_Extern Lesen
        $row.EffectiveLevel | Should -Be 'Ändern'
    }
    It 'rechnet breite Gruppen jedem Konto zu' {
        $row = $r.Matrix | Where-Object { $_.Path -eq '\\fs01\Vertrieb$' -and $_.Principal -eq 'CONTOSO\a.azubi' }
        $row.EffectiveLevel | Should -Be 'Lesen'
        $row.ViaNtfs | Should -Match 'GG_Vertrieb_R'
        $row.ViaNtfs | Should -Match 'VORDEFINIERT\\Benutzer'
    }
    It 'berücksichtigt Verweigern' {
        $row = $r.Matrix | Where-Object { $_.Path -eq '\\fs01\Vertrieb$\Angebote' -and $_.Principal -eq 'CONTOSO\a.azubi' }
        $row.HasDeny | Should -BeTrue
        $row.ViaNtfs | Should -Match 'VERWEIGERT'
    }
    It 'kombiniert direkte und Gruppenrechte' {
        $row = $r.Matrix | Where-Object { $_.Path -eq '\\fs01\Vertrieb$\Angebote' -and $_.Principal -eq 'CONTOSO\m.mueller' }
        $row.EffectiveLevel | Should -Be 'Vollzugriff'
        $row.ViaNtfs | Should -Match 'direkt'
        $row.AD_mail | Should -Be 'm.mueller@contoso.de'
    }
    It 'blendet System-Konten aus' {
        @($r.Matrix | Where-Object { $_.Principal -like '*SYSTEM*' }).Count | Should -Be 0
    }
    It 'behält die Via-Kette verschachtelter Gruppen' {
        $row = $r.Matrix | Where-Object { $_.Path -eq '\\fs01\Vertrieb$' -and $_.Principal -eq 'CONTOSO\k.schulz' }
        $row.ViaNtfs | Should -Match 'GG_Vertrieb_RW > CONTOSO\\GG_Vertrieb_Leitung'
    }
}

Describe 'Befunde' {
    BeforeAll { $script:r = New-SLDemoReport }
    It 'findet die erwarteten Auffälligkeiten' {
        $f = $r.Findings
        ($f | Where-Object { $_.Category -eq 'NTFS breit' -and $_.Severity -eq 'Hoch' }).Count | Should -BeGreaterThan 0
        ($f | Where-Object Category -eq 'Verwaiste SID').Count | Should -Be 1
        ($f | Where-Object Category -eq 'Direkte Benutzerberechtigung').Count | Should -Be 1
        ($f | Where-Object Category -eq 'Deaktiviertes Konto').Object | Should -Be 'CONTOSO\alt.user'
        ($f | Where-Object { $_.Category -eq 'DFS' -and $_.Detail -like '*fs02*' }).Count | Should -Be 1
        $f[0].Severity | Should -Be 'Hoch'
    }
}

Describe 'Export und Vergleich' {
    BeforeAll {
        $script:r = New-SLDemoReport
        $script:dir = Join-Path ([IO.Path]::GetTempPath()) ("sltest_" + [guid]::NewGuid().ToString('N'))
        $script:files = Export-SLReport -Report $r -OutputPath $dir -Format Html, Csv, Json -BaseName 'demo' -Delimiter ';'
    }
    AfterAll { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'schreibt alle Formate' {
        Test-Path (Join-Path $dir 'demo.html') | Should -BeTrue
        Test-Path (Join-Path $dir 'demo.json') | Should -BeTrue
        Test-Path (Join-Path $dir 'demo_Matrix.csv') | Should -BeTrue
    }
    It 'schreibt CSV mit BOM und ohne interne Spalten' {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $dir 'demo_Matrix.csv'))
        $bytes[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
        $head = (Get-Content (Join-Path $dir 'demo_Matrix.csv') -TotalCount 1)
        $head | Should -Not -Match 'EffectiveRank'
        $head | Should -Match 'AD_mail'
    }
    It 'bettet Daten sicher in HTML ein' {
        $html = Get-Content (Join-Path $dir 'demo.html') -Raw
        $html | Should -Match 'id="sl-data"'
        $html | Should -Not -Match '__DATA__'
        ([regex]::Matches($html, '</script>')).Count | Should -Be 2
    }
    It 'vergleicht Snapshots' {
        $old = Import-SLReport -Path (Join-Path $dir 'demo.json')
        $new = Import-SLReport -Path (Join-Path $dir 'demo.json')
        @(Compare-SLReport $old $new).Count | Should -Be 0

        $new.Aces = @($new.Aces | Where-Object { $_.Identity -ne 'CONTOSO\m.mueller' })
        $new.Matrix = @($new.Matrix | ForEach-Object { if ($_.Principal -eq 'CONTOSO\alt.user') { $_.EffectiveLevel = 'Kein' }; $_ })
        $d = @(Compare-SLReport $old $new)
        ($d | Where-Object { $_.Category -eq 'NTFS explizit' -and $_.Change -eq 'Entfernt' }).Count | Should -Be 1
        ($d | Where-Object { $_.Category -eq 'Effektiver Zugriff' -and $_.Change -eq 'Geändert' }).Count | Should -BeGreaterThan 0
    }
}
