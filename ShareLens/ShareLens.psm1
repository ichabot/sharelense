# ShareLens – Fileserver-Übersicht: DFS, Freigaben, NTFS, effektive Zugriffe
$script:SLVersion = '0.1.0'

foreach ($folder in @('Private', 'Public')) {
    foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' | Sort-Object Name) {
        . $file.FullName
    }
}

Export-ModuleMember -Function @(
    'Invoke-SLFileServerReport'
    'Get-SLDfsMap'
    'Get-SLDfsReplication'
    'Get-SLShareInventory'
    'Get-SLNtfsPermission'
    'Resolve-SLPrincipal'
    'Test-SLShareAccess'
    'Export-SLReport'
    'Import-SLReport'
    'Compare-SLReport'
)
