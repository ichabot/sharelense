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
