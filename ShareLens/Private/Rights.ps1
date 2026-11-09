$script:SLLevelNames = @('Kein', 'Speziell', 'Lesen', 'Lesen+Schreiben', 'Ändern', 'Vollzugriff')

# Rechte-Masken (FileSystemRights)
$script:SLMaskFull   = [int64]0x1F01FF
$script:SLMaskModify = [int64]0x1301BF
$script:SLMaskRead   = [int64]0x1200A9

function ConvertTo-SLRightsMask {
    <# Wandelt FileSystemRights (Enum, Zahl oder Text) in eine normierte Maske um, inkl. GENERIC_*-Bits. #>
    param([Parameter(Mandatory)][AllowNull()]$Rights)

    if ($null -eq $Rights) { return [int64]0 }
    if ($Rights -is [string]) {
        $num = [int64]0
        if ([int64]::TryParse($Rights, [ref]$num)) { $Rights = $num }
        else { $Rights = [System.Security.AccessControl.FileSystemRights]$Rights }
    }
    $m = ([int64]$Rights) -band [int64]4294967295
    if ($m -band [int64]268435456)  { $m = $m -bor $script:SLMaskFull }      # GENERIC_ALL
    if ($m -band [int64]2147483648) { $m = $m -bor $script:SLMaskRead }      # GENERIC_READ
    if ($m -band [int64]1073741824) { $m = $m -bor [int64]0x100116 }         # GENERIC_WRITE
    if ($m -band [int64]536870912)  { $m = $m -bor [int64]0x1200A0 }         # GENERIC_EXECUTE
    $m -band $script:SLMaskFull
}

function Get-SLLevelRank {
    param([int64]$Mask)
    $m = $Mask -band [int64]0xF01FF
    if ($m -eq 0) { return 0 }
    if (($m -band [int64]0xF01FF) -eq [int64]0xF01FF) { return 5 }
    if (($m -band [int64]0x301BF) -eq [int64]0x301BF) { return 4 }
    $read = (($m -band [int64]0x89) -eq [int64]0x89)
    if ($read -and ($m -band [int64]0x6)) { return 3 }
    if ($read) { return 2 }
    return 1
}

function Get-SLLevelName {
    param([int64]$Mask)
    $script:SLLevelNames[(Get-SLLevelRank -Mask $Mask)]
}

function Get-SLShareMask {
    <# Freigabeberechtigung (Full/Change/Read/Custom) als NTFS-vergleichbare Maske. #>
    param([string]$AccessRight, [int64]$RawMask = 0)
    switch ($AccessRight) {
        'Full'   { return $script:SLMaskFull }
        'Change' { return $script:SLMaskModify }
        'Read'   { return $script:SLMaskRead }
        default  { return (ConvertTo-SLRightsMask -Rights $RawMask) }
    }
}

function ConvertTo-SLShareRight {
    <# Win32-Zugriffsmaske einer Freigabe in Full/Change/Read/Custom übersetzen. #>
    param([int64]$AccessMask)
    switch ($AccessMask) {
        2032127 { 'Full' }
        1245631 { 'Change' }
        1179817 { 'Read' }
        default { 'Custom' }
    }
}

function Get-SLAppliesTo {
    <# Anzeige wie im Explorer ("Gilt für"). #>
    param($InheritanceFlags, $PropagationFlags)

    $i = [int]([System.Security.AccessControl.InheritanceFlags]$InheritanceFlags)
    $p = [int]([System.Security.AccessControl.PropagationFlags]$PropagationFlags)
    $ci = [bool]($i -band 1)
    $oi = [bool]($i -band 2)
    $inheritOnly = [bool]($p -band 2)
    $noPropagate = [bool]($p -band 1)

    if (-not $inheritOnly) {
        if ($ci -and $oi) { $text = 'Dieser Ordner, Unterordner und Dateien' }
        elseif ($ci) { $text = 'Dieser Ordner und Unterordner' }
        elseif ($oi) { $text = 'Dieser Ordner und Dateien' }
        else { $text = 'Nur dieser Ordner' }
    }
    else {
        if ($ci -and $oi) { $text = 'Nur Unterordner und Dateien' }
        elseif ($ci) { $text = 'Nur Unterordner' }
        elseif ($oi) { $text = 'Nur Dateien' }
        else { $text = 'Nur dieser Ordner' }
    }
    if ($noPropagate -and ($ci -or $oi)) { $text += ' (nur eine Ebene)' }

    [pscustomobject]@{
        Text           = $text
        AppliesToFolder = (-not $inheritOnly)
    }
}
