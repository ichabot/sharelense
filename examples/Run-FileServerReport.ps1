<#
  Beispiel: monatlicher Bericht mit Vergleich zum Vormonat.
  Als geplanter Task unter einem Audit-Konto ausführen.
#>
param(
    [string]$ReportRoot = 'C:\Reports\ShareLens',
    [string[]]$ComputerName = @(),
    [switch]$AllDomainNamespaces = $true,
    [int]$Depth = 3
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\ShareLens\ShareLens.psd1') -Force

$stamp = Get-Date -Format 'yyyy-MM'
$out = Join-Path $ReportRoot $stamp

$params = @{
    Depth        = $Depth
    UserProperty = @('mail', 'department')
    OutputPath   = $out
    Format       = @('Html', 'Csv', 'Xlsx', 'Json')
}
if ($ComputerName) { $params.ComputerName = $ComputerName }
if ($AllDomainNamespaces) { $params.AllDomainNamespaces = $true }

$report = Invoke-SLFileServerReport @params

# Vergleich mit dem letzten Snapshot (falls vorhanden)
$snapshots = Get-ChildItem -Path $ReportRoot -Filter 'ShareLens_*.json' -Recurse | Sort-Object LastWriteTime
if ($snapshots.Count -ge 2) {
    $diff = Compare-SLReport -Reference $snapshots[-2].FullName -Difference $snapshots[-1].FullName
    $diff | Export-Csv -Path (Join-Path $out 'Aenderungen_zum_Vormonat.csv') -Delimiter ';' -NoTypeInformation -Encoding UTF8
    Write-Host "Änderungen zum letzten Lauf: $(@($diff).Count)"
}

$report.Findings | Group-Object Severity | Select-Object Name, Count | Format-Table
$report.Files
