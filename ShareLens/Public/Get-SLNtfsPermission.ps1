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
