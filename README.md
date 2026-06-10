# STIG Compliance Checks

This repository contains PowerShell checks for Windows Server 2025 STIG items.
The checks are organized into a flat, category-specific script layout under `scripts/` so you can run the CAT level you need without mixing the whole set into one file.
The active script for this repo is [`scripts/CAT1.ps1`](./scripts/CAT1.ps1), which runs a series of local validation checks and prints pass/fail results to the console.

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

From the repository folder, run the category script you want to validate:

```powershell
.\scripts\CAT1.ps1
```

The script prints each rule result as `PASS` or `FAIL`, then exits with:

- `0` when all checks pass
- `1` when one or more checks fail

## Notes

- Some checks are specific to domain controllers and will report as not applicable on non-DC systems.
- Several checks inspect Active Directory, certificate, and file-system permissions, so they should be run on the live target system rather than copied output.
- The older nested category folder layout has been replaced with a simpler file-per-category approach under `scripts/`.
