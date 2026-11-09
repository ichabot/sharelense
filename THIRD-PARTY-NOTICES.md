# Third-Party Notices

## windows-it-toolkit (MIT)

Source: https://github.com/dschunk/windows-it-toolkit

Code from the following files was copied or adapted:

| Original | Used in |
|---|---|
| `Test-SmbShareAccess.ps1` | `ShareLens/Public/Test-SLShareAccess.ps1` (copied, extended) |
| `Get-SmbShareInventory.ps1` | `ShareLens/Private/Collectors.ps1` (`Get-SLShareData`), `Public/Get-SLShareInventory.ps1` (rewritten for remote CIM, SDDL and Win32 fallback) |
| `Get-NtfsPermissionAudit.ps1` | `ShareLens/Private/Collectors.ps1` (`Invoke-SLNtfsScan`, rewritten) |
| `module/SchunkOps/Public/Get-SchunkDfsNamespaceHealth.ps1` | `ShareLens/Private/Collectors.ps1` (`Get-SLDfsData`, rewritten as flat target map) |

```
MIT License

Copyright (c) 2026 David Schunk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## FolderSecurityViewer (AGPL-3.0) – concepts only

Source: https://github.com/carstenschaefer/FolderSecurityViewer

FolderSecurityViewer is a C#/.NET application licensed under the GNU AGPL v3.
**No source code from FolderSecurityViewer is included in ShareLens.** The following
feature ideas were re-implemented independently in PowerShell:

- resolving nested AD groups down to individual users
- limiting the scan depth
- excluding technical/system groups from the report
- enriching the report with additional AD user attributes
- comparing saved reports to show added/changed/removed permissions
- owner information per folder

If you need the full FolderSecurityViewer feature set (GUI, SQL storage, encryption),
use the original project.
