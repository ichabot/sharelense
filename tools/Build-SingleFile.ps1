<#
  Baut dist/ShareLens.ps1: alle Modul-Dateien in einer Datei, lädt sich per
  irm <url> | iex als In-Memory-Modul (keine Installation, keine Execution Policy nötig).
#>
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'ShareLens'
$dist = Join-Path $root 'dist'
$null = New-Item -ItemType Directory -Path $dist -Force

$psm1 = Get-Content (Join-Path $src 'ShareLens.psm1') -Raw -Encoding UTF8
$version = [regex]::Match($psm1, "SLVersion = '([^']+)'").Groups[1].Value
$exports = [regex]::Matches(($psm1 -split 'Export-ModuleMember')[1], "'([A-Za-z-]+)'") | ForEach-Object { "'$($_.Groups[1].Value)'" }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# ShareLens $version – Einzeldatei-Build (generiert von tools/Build-SingleFile.ps1, nicht bearbeiten)")
[void]$sb.AppendLine('# Laden:  irm https://raw.githubusercontent.com/ichabot/sharelense/main/dist/ShareLens.ps1 | iex')
[void]$sb.AppendLine('if (Get-Module ShareLens) { Remove-Module ShareLens -Force }')
[void]$sb.AppendLine('New-Module -Name ShareLens -ScriptBlock {')
[void]$sb.AppendLine("`$script:SLVersion = '$version'")
foreach ($folder in 'Private', 'Public') {
    foreach ($f in Get-ChildItem (Join-Path $src $folder) -Filter *.ps1 | Sort-Object Name) {
        [void]$sb.AppendLine("# ---- $folder/$($f.Name)")
        [void]$sb.AppendLine((Get-Content $f.FullName -Raw -Encoding UTF8).TrimStart([char]0xFEFF))
    }
}
[void]$sb.AppendLine("Export-ModuleMember -Function @($($exports -join ', '))")
[void]$sb.AppendLine('} | Import-Module -Force -DisableNameChecking')
[void]$sb.AppendLine("Write-Host 'ShareLens $version geladen. Start: Invoke-SLFileServerReport -AllDomainNamespaces -OutputPath C:\Reports' -ForegroundColor Cyan")

$out = Join-Path $dist 'ShareLens.ps1'
[System.IO.File]::WriteAllText($out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Get-Item $out
