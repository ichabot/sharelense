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
