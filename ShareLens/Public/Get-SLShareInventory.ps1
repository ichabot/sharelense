function Get-SLShareInventory {
    <#
    .SYNOPSIS
    Freigaben eines oder mehrerer Server inkl. Freigabeberechtigungen.

    .DESCRIPTION
    Liest remote per CIM (WinRM, Fallback DCOM). Ab Server 2012 über MSFT_SmbShare
    (inkl. ABE, Verschlüsselung, Caching, Cluster-Scope), bei 2008/2008 R2 über Win32_Share.
    Freigabeberechtigungen werden aus der Sicherheitsbeschreibung gelesen (mit SID).
    Weiterentwicklung von Get-SmbShareInventory.ps1 (windows-it-toolkit, MIT).

    .EXAMPLE
    Get-SLShareInventory -ComputerName FS01, FS02 | Format-Table ShareUnc, LocalPath, FullAccess, ChangeAccess, ReadAccess

    .EXAMPLE
    Get-SLShareInventory -ComputerName FS01 -ShareName 'Daten*' -ExcludeShare 'Daten_alt'
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][string[]]$ComputerName = @($env:COMPUTERNAME),
        [string[]]$ShareName = @('*'),
        [string[]]$ExcludeShare,
        [switch]$IncludeAdministrative,
        [pscredential]$Credential
    )

    process {
        foreach ($c in $ComputerName) {
            $data = Get-SLShareData -ComputerName $c -ShareName $ShareName -ExcludeShare $ExcludeShare -IncludeAdministrative:$IncludeAdministrative -Credential $Credential
            foreach ($e in $data.Errors) { Write-Warning "[$($e.Stage)] $($e.Target): $($e.Message)" }
            foreach ($s in $data.Shares) {
                $allow = @($s.Access | Where-Object AccessControlType -eq 'Allow')
                $s | Select-Object ComputerName, ScopeName, ShareName, ShareUnc, LocalPath, Description, Special,
                ContinuouslyAvailable, EncryptData, AccessBasedEnumeration, CachingMode, ConcurrentUserLimit, CurrentUsers, Source,
                @{ n = 'FullAccess'; e = { (@($allow | Where-Object AccessRight -eq 'Full').AccountName) -join '; ' } },
                @{ n = 'ChangeAccess'; e = { (@($allow | Where-Object AccessRight -eq 'Change').AccountName) -join '; ' } },
                @{ n = 'ReadAccess'; e = { (@($allow | Where-Object AccessRight -eq 'Read').AccountName) -join '; ' } },
                @{ n = 'DenyAccess'; e = { (@($s.Access | Where-Object AccessControlType -eq 'Deny').AccountName) -join '; ' } },
                Access
            }
        }
    }
}
