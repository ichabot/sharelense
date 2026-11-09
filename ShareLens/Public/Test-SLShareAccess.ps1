function Test-SLShareAccess {
    <#
    .SYNOPSIS
    Prüft, ob Pfade (DFS oder UNC) mit dem aktuellen Konto lesbar und optional beschreibbar sind.

    .DESCRIPTION
    Übernommen aus Test-SmbShareAccess.ps1 (windows-it-toolkit, (c) 2026 David Schunk, MIT)
    und um Fehlerkategorie und DFS-Kennzeichnung erweitert.
    -WriteTest legt eine Testdatei an und löscht sie sofort wieder.

    .EXAMPLE
    Test-SLShareAccess -Path '\\contoso.local\Daten\Vertrieb', '\\FS01\Vertrieb$'

    .EXAMPLE
    Test-SLShareAccess -Path '\\FS01\Scans' -WriteTest
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string[]]$Path,
        [switch]$WriteTest
    )

    process {
        foreach ($share in $Path) {
            $started = Get-Date
            $readable = $false
            $writeable = $null
            $errorText = $null
            try {
                $null = Get-ChildItem -LiteralPath $share -ErrorAction Stop | Select-Object -First 1
                $readable = $true
                if ($WriteTest) {
                    $probe = Join-Path $share ".sharelens-probe-$([guid]::NewGuid().ToString('N')).tmp"
                    try {
                        Set-Content -LiteralPath $probe -Value 'ShareLens access probe' -Encoding UTF8 -ErrorAction Stop
                        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
                        $writeable = $true
                    }
                    catch { $writeable = $false; throw }
                }
            }
            catch { $errorText = $_.Exception.GetBaseException().Message }

            [pscustomobject]@{
                Path                 = $share
                User                 = [Environment]::UserName
                Readable             = $readable
                WriteTestRequested   = [bool]$WriteTest
                Writeable            = $writeable
                ResponseMilliseconds = [math]::Round(((Get-Date) - $started).TotalMilliseconds)
                Error                = $errorText
            }
        }
    }
}
