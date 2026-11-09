@{
    RootModule           = 'ShareLens.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '6f0b6d1e-3c1a-4c5e-9a57-2f1d8e4b7c21'
    Author               = 'ichabot'
    Copyright            = '(c) 2026 ichabot. MIT-Lizenz. Teile (c) 2026 David Schunk (MIT).'
    Description          = 'Übersicht über Windows-Fileserver: DFS-Namespaces, Freigaben, NTFS-Berechtigungen, rekursive Gruppenauflösung und effektive Zugriffe je Benutzer. Export als HTML, CSV, XLSX und JSON, Vergleich von Snapshots.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Invoke-SLFileServerReport', 'Get-SLDfsMap', 'Get-SLDfsReplication', 'Get-SLShareInventory',
        'Get-SLNtfsPermission', 'Resolve-SLPrincipal', 'Test-SLShareAccess', 'Export-SLReport',
        'Import-SLReport', 'Compare-SLReport'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('FileServer', 'NTFS', 'Permissions', 'SMB', 'Share', 'DFS', 'DFSN', 'ActiveDirectory', 'Audit', 'Windows')
            LicenseUri   = 'https://github.com/ichabot/ShareLens/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/ichabot/ShareLens'
            ReleaseNotes = 'Erste Version: DFS-Mapping, Freigabe-Inventar, NTFS-Grenzordner-Scan, Gruppenauflösung, Matrix, Befunde, HTML/CSV/XLSX/JSON, Vergleich.'
        }
    }
}
