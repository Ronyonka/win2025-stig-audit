# STIG Compliance Checks

This repository contains PowerShell checks for Windows Server 2025 STIG items.
The main script is [`Test-STIGCompliance.ps1`](./Test-STIGCompliance.ps1), which runs a series of local validation checks and prints pass/fail results to the console.

## Requirements

- Windows Server 2025
- Run PowerShell as Administrator
- Execute the script on the system you want to validate

The script uses built-in Windows tools and providers such as registry access, local group membership, certificate stores, and directory services.

## Setup

1. Clone or copy the repository to the target server.
2. Open PowerShell as Administrator.
3. If execution policy blocks the script, allow it for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

## Running

From the repository folder, run:

```powershell
.\Test-STIGCompliance.ps1
```

The script prints each rule result as `PASS` or `FAIL`, then exits with:

- `0` when all checks pass
- `1` when one or more checks fail

## Notes

- Some checks are specific to domain controllers and will report as not applicable on non-DC systems.
- Several checks inspect Active Directory, certificate, and file-system permissions, so they should be run on the live target system rather than copied output.
