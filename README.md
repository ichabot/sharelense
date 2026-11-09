# ShareLens

**Wer darf wo was auf dem Fileserver?** ShareLens erstellt in einem Lauf eine vollständige Übersicht:
DFS-Namespace → Freigabe → NTFS-Rechte → Gruppen bis auf Benutzer → **effektiver Zugriff je Benutzer und Ordner**.

- PowerShell 5.1 und 7, rein lesend, ohne Agent und ohne Installation auf dem Fileserver
- Ergebnis: HTML-Bericht zum Durchklicken (Suche, Spaltenfilter, Sortierung, CSV-Export je Ansicht), dazu CSV/XLSX für die Doku und JSON-Snapshot für spätere Vergleiche
- Bewertete Befunde: breite Schreibrechte, verwaiste SIDs, direkte Benutzerrechte, deaktivierte Konten mit Zugriff, DFS-Ziele offline …

---

## In 30 Sekunden starten

PowerShell auf einer Admin-Workstation oder einem Server der Domäne öffnen und eingeben:

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; irm https://raw.githubusercontent.com/ichabot/sharelense/main/dist/ShareLens.ps1 | iex
```

Damit ist ShareLens in der aktuellen Sitzung geladen (nur im Speicher, nichts wird installiert). Dann den Bericht erzeugen:

```powershell
# Alle DFS-Namespaces der Domäne inkl. aller Zielserver, 3 Ordnerebenen
Invoke-SLFileServerReport -AllDomainNamespaces -Depth 3 -OutputPath C:\Reports
```

```powershell
# Bestimmte Fileserver ohne DFS
Invoke-SLFileServerReport -ComputerName FS01, FS02 -Depth 2 -OutputPath C:\Reports
```

Im Ordner `C:\Reports` liegt danach `ShareLens_<Datum>.html` – im Browser öffnen.

> Alles in einer Zeile (laden und Bericht für den lokalen Server erzeugen):
> ```powershell
> [Net.ServicePointManager]::SecurityProtocol='Tls12'; irm https://raw.githubusercontent.com/ichabot/sharelense/main/dist/ShareLens.ps1 | iex; Invoke-SLFileServerReport -OutputPath "$env:USERPROFILE\Desktop\ShareLens"
> ```

**Ohne Internet auf dem Zielsystem:** `dist/ShareLens.ps1` herunterladen, hinüberkopieren und laden mit
`Get-Content .\ShareLens.ps1 -Raw | iex`

**Dauerhaft als Modul:** Repo klonen bzw. ZIP entpacken, dann `Import-Module .\ShareLens\ShareLens.psd1`
(oder den Ordner `ShareLens` nach `Documents\WindowsPowerShell\Modules` kopieren).

---

## Was im Bericht steht

| Reiter | Inhalt |
|---|---|
| **Übersicht** | Kennzahlen, Rahmendaten, Befunde nach Schwere |
| **Befunde** | Hoch / Mittel / Info, jeweils mit Pfad und Erklärung |
| **DFS-Namespace** | Namespaces, Ordner, Ziele mit Status und Priorität |
| **Freigaben** | Server, Freigabe, lokaler Pfad, ABE, Verschlüsselung, Offline-Cache, Sitzungen, Freigaberechte zusammengefasst |
| **Freigabe-Rechte** | Jeder Eintrag der Freigabeberechtigung |
| **Effektive Zugriffe** | Je Benutzer und Grenzordner: effektiv / NTFS / Freigabe, Verweigern, **über welche Gruppen** (`GG_A > GG_B`), optionale AD-Attribute |
| **NTFS-Rechte** | ACEs mit Stufe, „Gilt für“ wie im Explorer, geerbt/explizit, DFS-Pfad |
| **Ordner** | Besitzer, Vererbung unterbrochen, Anzahl expliziter Einträge |
| **Gruppenauflösung** | Jede berechtigte Gruppe mit allen Mitgliedern (rekursiv) |
| **Zugriffstests / Fehler** | Optionaler Lesetest, nicht lesbare Pfade/Server |

**Effektiver Zugriff** = Freigaberecht ∩ NTFS-Recht am jeweiligen Ordner. Verweigern-Einträge werden abgezogen; Jeder, Authentifizierte Benutzer, Benutzer und Domänen-Benutzer zählen für jedes Konto.

**Grenzordner** = Freigabe-Root, Ordner mit unterbrochener Vererbung oder mit eigenen Einträgen. Nur dort ändert sich etwas, darum werden nur diese ausgegeben. Darunterliegende Ordner erben dieselben Rechte. Mit `-IncludeInherited` werden alle Ordner ausgegeben.

---

## Häufige Aufrufe

```powershell
# DFS-Namespace + AD-Attribute in der Matrix, nur HTML und Excel
Invoke-SLFileServerReport -DfsNamespace '\\contoso.local\Daten' -UserProperty mail, department -OutputPath C:\Reports -Format Html, Xlsx

# NAS oder andere UNC-Pfade zusätzlich
Invoke-SLFileServerReport -ComputerName FS01 -Path '\\nas01\Scans' -OutputPath C:\Reports

# Nur bestimmte Freigaben
Invoke-SLFileServerReport -ComputerName FS01 -ShareName 'Abteilung*' -ExcludeShare 'Abteilung_alt' -OutputPath C:\Reports

# Schnell, ohne Gruppenauflösung (Matrix zeigt dann Gruppen)
Invoke-SLFileServerReport -ComputerName FS01 -NoGroupExpansion -Depth 1 -OutputPath C:\Reports

# Interaktiv auswerten statt exportieren
$r = Invoke-SLFileServerReport -ComputerName FS01
$r.Findings | Format-Table Severity, Category, Object, Detail
$r.Matrix   | Where-Object Principal -like '*mueller*' | Format-Table Path, EffectiveLevel, ViaNtfs

# Was hat sich seit dem letzten Lauf geändert?
Compare-SLReport C:\Reports\ShareLens_20261001_080000.json C:\Reports\ShareLens_20261109_080000.json | Format-Table
```

Einzelne Bausteine:

| Befehl | Zweck |
|---|---|
| `Invoke-SLFileServerReport` | Komplettbericht (alles unten kombiniert) |
| `Get-SLDfsMap` | DFS-Namespaces → Ordner → Ziele |
| `Get-SLDfsReplication` | DFS-R-Gruppen, Mitglieder, Inhaltspfade |
| `Get-SLShareInventory` | Freigaben + Freigaberechte eines/mehrerer Server |
| `Get-SLNtfsPermission` | NTFS-ACEs ab einem Pfad (`-Folders` für Ordnerliste) |
| `Resolve-SLPrincipal` | Gruppe rekursiv bis auf Benutzer auflösen |
| `Test-SLShareAccess` | Lese-/Schreibtest auf Pfade mit dem aktuellen Konto |
| `Export-SLReport` / `Import-SLReport` | Export (HTML, CSV, XLSX, JSON) / Snapshot laden |
| `Compare-SLReport` | Zwei Snapshots vergleichen |

Hilfe zu jedem Befehl: `Get-Help Invoke-SLFileServerReport -Full`

---

## Parameter von `Invoke-SLFileServerReport`

| Parameter | Bedeutung |
|---|---|
| `-ComputerName` | Fileserver. Bei Clustern Clientzugriffspunkt oder Knoten; Freigaben werden über den Scope-Namen adressiert. Ohne Angabe von Quellen: lokaler Server. |
| `-DfsNamespace` / `-AllDomainNamespaces` / `-NamespaceServer` | DFS-Quellen (domänenbasiert bzw. eigenständig). Zielserver werden automatisch inventarisiert. |
| `-SkipDfsTargetServers` | Zielserver nicht komplett inventarisieren, nur die DFS-Ziele scannen. |
| `-Path` | Zusätzliche UNC-Pfade (z. B. NAS). |
| `-ShareName` / `-ExcludeShare` | Wildcard-Filter für Freigaben. `-IncludeAdministrativeShares` nimmt `C$` usw. dazu. |
| `-Depth` | Ordnertiefe für den NTFS-Scan (Standard 2, 0 = nur Freigabe-Root). |
| `-IncludeInherited` | ACEs aller Ordner ausgeben, nicht nur der Grenzordner (wird groß). |
| `-NoGroupExpansion` | Gruppen nicht auflösen. |
| `-UserProperty` | AD-Attribute in der Matrix, z. B. `mail, department, title` (Spalten `AD_…`). |
| `-LdapServer` | Bestimmten Domänencontroller für LDAP verwenden. |
| `-IncludeSystemPrincipals` | SYSTEM, ERSTELLER-BESITZER, Dienstkonten in Matrix/Gruppen aufnehmen. |
| `-IncludeReplication` | DFS-R-Daten lesen. |
| `-TestAccess` | Lesetest auf alle DFS-Pfade und Freigaben. |
| `-Credential` | Anmeldedaten für die CIM-Abfrage der Freigaben. |
| `-OutputPath` / `-Format` | Exportordner und Formate (`Html`, `Csv`, `Xlsx`, `Json`; Standard: alle). |

---

## Voraussetzungen

- Domänengebundener Windows-Rechner, Konto mit Leserecht auf die ACLs (Domänen-Admin oder dediziertes Audit-Konto). Nicht lesbare Ordner erscheinen unter *Fehler*.
- Freigaben werden remote per CIM gelesen: WinRM (Standard ab Server 2012), Fallback DCOM/RPC. Server 2008/2008 R2 werden über `Win32_Share` unterstützt.
- NTFS und LDAP laufen im Kontext des angemeldeten Kontos (`-Credential` gilt nur für CIM). Bei Bedarf PowerShell als Audit-Konto bzw. mit `runas /netonly` starten.
- Für DFS: RSAT „DFS-Verwaltungstools“ (Module `Dfsn`, `DFSR`). Ohne DFS-Parameter nicht nötig.
- Für XLSX: `Install-Module ImportExcel -Scope CurrentUser`. Fehlt das Modul, wird XLSX übersprungen, alles andere läuft.
- Die Gruppenauflösung braucht **kein** RSAT/ActiveDirectory-Modul (direkt per LDAP/WinNT).

## Grenzen

- Die effektiven Rechte werden auf die üblichen Stufen verdichtet (Vollzugriff, Ändern, Lesen+Schreiben, Lesen, Speziell). Nicht berücksichtigt: Dynamic Access Control/Claims, Datei-ACLs (nur Ordner), Mitgliedschaft über die *primäre Gruppe* (außer Domänen-Benutzer, die ohnehin für alle gelten). Konten aus fremden Gesamtstrukturen ohne GC-Zugriff erscheinen als `foreign`/`unresolved`.
- Pfade über 260 Zeichen können unter Windows PowerShell 5.1 fehlschlagen (stehen dann unter *Fehler*). PowerShell 7 ist davon nicht betroffen.
- Große Umgebungen: `-Depth` klein halten oder je Server laufen lassen. Im HTML stehen je Tabelle max. 25 000 Zeilen (`Export-SLReport -HtmlMaxRows`), CSV/XLSX sind vollständig.

---

## Entwicklung

```
ShareLens/            Modul (psd1/psm1, Private/, Public/)
dist/ShareLens.ps1    Einzeldatei für irm | iex – generiert, nicht von Hand bearbeiten
tools/                Build-SingleFile.ps1
tests/                Pester-Tests + synthetische Demodaten
examples/             Beispiel für monatlichen Lauf mit Vergleich
```

Nach Änderungen am Modul:

```powershell
./tools/Build-SingleFile.ps1     # dist/ShareLens.ps1 neu erzeugen
Invoke-Pester ./tests            # Pester 5+, läuft auch ohne AD (Demodaten)
```

Beispielbericht ohne AD erzeugen:

```powershell
Import-Module ./ShareLens/ShareLens.psd1; . ./tests/DemoData.ps1
New-SLDemoReport | Export-SLReport -OutputPath ./out -Format Html
```

## Herkunft und Lizenz

MIT, siehe [LICENSE](LICENSE). ShareLens kombiniert:

- [dschunk/windows-it-toolkit](https://github.com/dschunk/windows-it-toolkit) (MIT): `Test-SmbShareAccess.ps1`, `Get-SmbShareInventory.ps1`, `Get-NtfsPermissionAudit.ps1`, `Get-SchunkDfsNamespaceHealth` – übernommen bzw. weiterentwickelt.
- [carstenschaefer/FolderSecurityViewer](https://github.com/carstenschaefer/FolderSecurityViewer) (AGPL-3.0): **nur Konzepte** (Gruppenauflösung bis auf Benutzer, Scan-Tiefe, Ausschluss technischer Gruppen, AD-Attribute, Berichtsvergleich). Kein Code übernommen.

Details: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
