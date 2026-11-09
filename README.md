# ShareLens

Übersicht über Windows-Fileserver in einem Lauf: **DFS-Namespace → Freigabe → NTFS → Gruppen → effektiver Zugriff je Benutzer**.
PowerShell-Modul, rein lesend, läuft unter Windows PowerShell 5.1 und PowerShell 7.

Ergebnis ist ein HTML-Bericht zum Durchklicken (Suche, Spaltenfilter, Sortierung, CSV-Export) plus CSV/XLSX für die Doku und ein JSON-Snapshot für spätere Vergleiche.

## Was es kann

| Bereich | Inhalt |
|---|---|
| DFS | Namespaces, Ordner, Ziele inkl. Status/Priorität; optional DFS-R-Mitgliedschaften. Jeder Ordner und jede Matrixzeile bekommt den passenden **DFS-Pfad** (auch bei Zielen auf Unterordner). |
| Freigaben | Remote per CIM (WinRM, Fallback DCOM). Server 2012+: MSFT_SmbShare inkl. ABE, Verschlüsselung, Offline-Cache, CA, **Cluster-Scopes**. Server 2008/2008 R2: Win32_Share. Freigaberechte mit SID. |
| NTFS | Scan bis `-Depth`, ACEs nur an **Grenzordnern** (Startordner, Vererbung unterbrochen, explizite Einträge). Besitzer, „Gilt für“ wie im Explorer, GENERIC-Rechte korrekt, Junctions werden nicht verfolgt. |
| Gruppen | Rekursiv bis auf Benutzer: AD per LDAP (ohne RSAT, >1500 Mitglieder per Range-Retrieval, Zirkelschutz), lokale Gruppen des Fileservers per WinNT (z. B. `VORDEFINIERT\Administratoren`), verwaiste SIDs. Optional AD-Attribute (`mail`, `department` …). |
| Effektiver Zugriff | Je Benutzer und Grenzordner: **Freigabe ∩ NTFS**, Verweigern berücksichtigt, Jeder/Authentifizierte Benutzer/Domänen-Benutzer werden jedem Konto zugerechnet, Herkunft als Kette (`GG_A > GG_B`). |
| Befunde | Breiter Schreibzugriff, verwaiste SIDs, direkte Benutzerrechte, Vollzugriff für Nicht-Admins, deaktivierte Konten mit Zugriff, DFS-Ziele offline, ABE aus, Freigaben ohne DFS-Pfad … |
| Vergleich | `Compare-SLReport` zeigt Änderungen zwischen zwei Snapshots (Freigaben, Rechte, Besitzer, effektive Zugriffe, DFS). |

## Schnellstart

Ohne Installation, direkt in die laufende Sitzung (lädt `dist/ShareLens.ps1` in den Speicher):

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; irm https://raw.githubusercontent.com/ichabot/ShareLens/main/dist/ShareLens.ps1 | iex
```

Danach stehen alle Befehle zur Verfügung, z. B. `Invoke-SLFileServerReport -AllDomainNamespaces -OutputPath C:\Reports`.
Die Einzeldatei wird mit `tools/Build-SingleFile.ps1` aus dem Modulordner erzeugt.

Klassisch als Modul:

```powershell
# Modul laden (Ordner ShareLens\ aus diesem Repo)
Import-Module .\ShareLens\ShareLens.psd1

# Alles aus dem DFS der Domäne, Zielserver automatisch, 3 Ebenen tief
Invoke-SLFileServerReport -AllDomainNamespaces -Depth 3 -OutputPath C:\Reports

# Bestimmte Server + Namespace, AD-Attribute in der Matrix, nur HTML und Excel
Invoke-SLFileServerReport -ComputerName FS01, FS02 -DfsNamespace '\\contoso.local\Daten' `
    -UserProperty mail, department -OutputPath C:\Reports -Format Html, Xlsx

# NAS oder sonstige UNC-Pfade mit aufnehmen (NTFS/ACL über SMB)
Invoke-SLFileServerReport -ComputerName FS01 -Path '\\nas01\Scans' -OutputPath C:\Reports
```

Interaktiv, ohne Export:

```powershell
$r = Invoke-SLFileServerReport -ComputerName FS01 -Depth 2
$r.Findings | Format-Table Severity, Category, Object, Detail
$r.Matrix | Where-Object Principal -like '*mueller*' | Format-Table Path, EffectiveLevel, ViaNtfs
```

Einzelbausteine:

```powershell
Get-SLDfsMap | Format-Table DfsPath, TargetPath, TargetState
Get-SLShareInventory -ComputerName FS01 | Format-Table ShareUnc, LocalPath, FullAccess, ChangeAccess, ReadAccess
Get-SLNtfsPermission -Path '\\FS01\Daten' -Depth 3 | Format-Table Path, Identity, Level, AppliesTo
Resolve-SLPrincipal -Identity 'CONTOSO\GG_Vertrieb_RW' -UserProperty mail
Test-SLShareAccess -Path '\\contoso.local\Daten\Vertrieb'
Compare-SLReport .\ShareLens_alt.json .\ShareLens_neu.json | Format-Table
```

## Voraussetzungen

- Ausführendes Konto mit Leserechten auf ACLs (Domänen-Admin oder dediziertes Audit-Konto mit „Sicherungsoperator“-ähnlichen Rechten). Für Ordner ohne Leserecht steht ein Eintrag unter *Fehler*.
- Für Freigaben: WinRM (Standard ab 2012) oder DCOM/RPC zum Fileserver. `-Credential` wird für CIM genutzt; NTFS und LDAP laufen immer im Kontext des angemeldeten Kontos (ggf. `runas /netonly` bzw. als Audit-Konto starten).
- Für DFS: RSAT „DFS-Verwaltungstools“ (`Dfsn`, `DFSR`). Ohne DFS-Parameter nicht nötig.
- XLSX: Modul `ImportExcel` (`Install-Module ImportExcel -Scope CurrentUser`). Fehlt es, wird XLSX übersprungen.
- Ausführung auf einem domänengebundenen Windows-Rechner (Admin-Workstation oder Server).

## Parameter von `Invoke-SLFileServerReport`

| Parameter | Bedeutung |
|---|---|
| `-ComputerName` | Fileserver. Bei Clustern Clientzugriffspunkt oder Knoten; Freigaben werden über den Scope-Namen adressiert. |
| `-DfsNamespace` / `-AllDomainNamespaces` / `-NamespaceServer` | DFS-Quellen (domänenbasiert bzw. standalone). |
| `-SkipDfsTargetServers` | DFS-Zielserver nicht komplett inventarisieren, nur die Ziele selbst scannen. |
| `-Path` | Zusätzliche UNC-Pfade (z. B. NAS). |
| `-ShareName` / `-ExcludeShare` | Wildcard-Filter für Freigaben. `-IncludeAdministrativeShares` nimmt `C$` & Co. dazu. |
| `-Depth` | Ordnertiefe (Standard 2). |
| `-IncludeInherited` | ACEs für **alle** Ordner ausgeben, nicht nur Grenzordner (groß!). |
| `-NoGroupExpansion` | Gruppen nicht auflösen (schnell, Matrix zeigt dann Gruppen statt Benutzer). |
| `-UserProperty` | Zusätzliche AD-Attribute in der Matrix (`AD_mail` …). |
| `-LdapServer` | Bestimmten DC für LDAP verwenden. |
| `-IncludeSystemPrincipals` | SYSTEM, ERSTELLER-BESITZER usw. in Matrix/Gruppen aufnehmen. |
| `-IncludeReplication` | DFS-R-Gruppen/Mitglieder lesen. |
| `-TestAccess` | Lesetest auf alle DFS-Pfade und Freigaben mit dem aktuellen Konto. |
| `-OutputPath` / `-Format` | Export (Html, Csv, Xlsx, Json). |

## Grenzen

- Effektive Rechte sind eine Näherung auf Ebene der üblichen Stufen (Vollzugriff, Ändern, Lesen+Schreiben, Lesen, Speziell). Nicht berücksichtigt: Dynamic Access Control/Claims, Ressourcen-Attribute, Datei-ACLs (nur Ordner), Mitgliedschaft über *primäre Gruppe* (außer Domänen-Benutzer, die ohnehin als „alle“ gilt), Konten aus vertrauten Gesamtstrukturen ohne GC-Zugriff (erscheinen als `foreign`/`unresolved`).
- Pfade > 260 Zeichen können unter Windows PowerShell 5.1 fehlschlagen (steht dann unter *Fehler*). PowerShell 7 hat das Problem nicht.
- Sehr große Umgebungen: `-Depth` klein halten oder pro Server laufen lassen. Die HTML-Datei enthält je Tabelle max. 25 000 Zeilen (`Export-SLReport -HtmlMaxRows`), CSV/XLSX sind vollständig.

## Tests

```powershell
Invoke-Pester ./tests        # benötigt Pester 5+, läuft auch unter Linux (synthetische Daten)
```

`tests/DemoData.ps1` erzeugt einen Beispielbericht ohne AD:

```powershell
Import-Module ./ShareLens/ShareLens.psd1; . ./tests/DemoData.ps1
New-SLDemoReport | Export-SLReport -OutputPath ./out -Format Html
```

## Herkunft und Lizenz

MIT, siehe [LICENSE](LICENSE). ShareLens kombiniert:

- [dschunk/windows-it-toolkit](https://github.com/dschunk/windows-it-toolkit) (MIT): `Test-SmbShareAccess.ps1`, `Get-SmbShareInventory.ps1`, `Get-NtfsPermissionAudit.ps1`, `Get-SchunkDfsNamespaceHealth` – übernommen bzw. weiterentwickelt.
- [carstenschaefer/FolderSecurityViewer](https://github.com/carstenschaefer/FolderSecurityViewer) (AGPL-3.0): **nur Konzepte** (Auflösung verschachtelter Gruppen bis auf Benutzer, Scan-Tiefe, Ausschluss von Gruppen, AD-Attribute im Bericht, Berichtsvergleich). Es wurde kein Code übernommen.

Details in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
