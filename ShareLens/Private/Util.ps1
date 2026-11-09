function Test-SLIsWindows {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    return [bool]$IsWindows
}

function Split-SLUncPath {
    <# Zerlegt \\host\share\sub\path. Gibt $null zurück, wenn kein UNC-Pfad. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    $p = $Path.Trim()
    if ($p -notmatch '^\\\\([^\\]+)\\([^\\]+)(\\.*)?$') { return $null }
    $hostName = $Matches[1]
    $share = $Matches[2]
    $rest = ''
    if ($Matches[3]) { $rest = $Matches[3].Trim('\') }
    $segments = @()
    if ($rest) { $segments = @($rest -split '\\' | Where-Object { $_ }) }

    [pscustomobject]@{
        Host      = $hostName
        HostShort = ($hostName.Split('.')[0]).ToUpperInvariant()
        Share     = $share
        SubPath   = ($segments -join '\')
        Segments  = $segments
    }
}

function ConvertTo-SLUncKey {
    <# Normalisierter Vergleichsschlüssel: \\HOSTKURZ\SHARE\SUB (Großbuchstaben, FQDN entfernt). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    $u = Split-SLUncPath -Path $Path
    if (-not $u) { return $Path.TrimEnd('\').ToUpperInvariant() }
    $key = '\\' + $u.HostShort + '\' + $u.Share.ToUpperInvariant()
    if ($u.SubPath) { $key += '\' + $u.SubPath.ToUpperInvariant() }
    $key
}

function Get-SLDfsPathForUnc {
    <# Liefert alle DFS-Pfade, über die ein UNC-Pfad erreichbar ist (durch "; " getrennt). #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [object[]]$DfsTargets
    )

    if (-not $DfsTargets) { return '' }
    $u = Split-SLUncPath -Path $Path
    if (-not $u) { return '' }
    $key = ConvertTo-SLUncKey -Path $Path
    $segments = @($u.Share) + @($u.Segments)

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($t in $DfsTargets) {
        if (-not $t.TargetPath -or -not $t.DfsPath) { continue }
        $tk = ConvertTo-SLUncKey -Path $t.TargetPath
        $dfs = $null
        if ($key -eq $tk) {
            $dfs = $t.DfsPath.TrimEnd('\')
        }
        elseif ($key.StartsWith($tk + '\')) {
            $tu = Split-SLUncPath -Path $t.TargetPath
            $skip = 1 + @($tu.Segments).Count
            $remainder = ($segments[$skip..($segments.Count - 1)]) -join '\'
            $dfs = $t.DfsPath.TrimEnd('\') + '\' + $remainder
        }
        if ($dfs -and -not $result.Contains($dfs)) { $result.Add($dfs) }
    }
    ($result | Sort-Object) -join '; '
}

function ConvertTo-SLFlatValue {
    <# Arrays/Collections für CSV/HTML zu Text zusammenfassen. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) { return (@($Value) | ForEach-Object { [string]$_ }) -join '; ' }
    $Value
}

function New-SLErrorRow {
    param([string]$Stage, [string]$Target, [string]$Message)
    [pscustomobject]@{
        Stage   = $Stage
        Target  = $Target
        Message = $Message
    }
}
