function Resolve-SLPrincipal {
    <#
    .SYNOPSIS
    Löst ein Konto oder eine Gruppe rekursiv bis auf Benutzer auf (verschachtelte Gruppen).

    .DESCRIPTION
    Domänengruppen per LDAP (kein RSAT nötig, >1500 Mitglieder per Range-Retrieval),
    lokale Gruppen eines Fileservers (z. B. VORDEFINIERT\Administratoren) per WinNT.
    Breite Gruppen (Jeder, Authentifizierte Benutzer, Domänen-Benutzer) werden nicht aufgelöst.

    .PARAMETER Identity
    Name (DOMAIN\Gruppe) oder SID.

    .PARAMETER ComputerName
    Server, in dessen Kontext lokale Gruppen aufgelöst werden.

    .PARAMETER UserProperty
    Zusätzliche AD-Attribute der Benutzer, z. B. mail, department.

    .EXAMPLE
    Resolve-SLPrincipal -Identity 'CONTOSO\GG_Vertrieb_RW' -UserProperty mail, department

    .EXAMPLE
    Resolve-SLPrincipal -Identity 'S-1-5-32-544' -ComputerName FS01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string[]]$Identity,
        [string]$ComputerName,
        [string[]]$UserProperty = @(),
        [string]$LdapServer
    )

    begin {
        $script:SLUserProperty = @($UserProperty)
        if ($LdapServer) { $script:SLLdapServer = $LdapServer }
    }
    process {
        foreach ($id in $Identity) {
            $sid = ConvertTo-SLSid -Name $id
            if (-not $sid) { Write-Warning "Konto '$id' nicht auflösbar."; continue }
            foreach ($leaf in @(Get-SLPrincipalLeaf -Sid $sid -ComputerName $ComputerName)) {
                $row = [ordered]@{
                    Principal   = $id
                    Account     = $leaf.Account
                    DisplayName = $leaf.DisplayName
                    ObjectClass = $leaf.ObjectClass
                    Enabled     = $leaf.Enabled
                    Via         = (@($leaf.Via) -join ' > ')
                    Sid         = $leaf.Sid
                }
                foreach ($p in $UserProperty) { $row["AD_$p"] = $leaf.Properties[$p] }
                [pscustomobject]$row
            }
        }
    }
}
