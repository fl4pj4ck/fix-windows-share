# Windows Network Discovery Fix

A PowerShell script to automatically configure and fix network discovery and file sharing on Windows 10 and 11.

## Features

- Configures network discovery and file sharing
- Supports both Windows 10 and 11
- Handles Home and Pro editions
- Optimizes network adapter settings
- Resets network stack when needed
- Provides detailed logging and diagnostics

## Requirements

- Windows 10/11
- PowerShell 5.0 or higher
- Administrative privileges

## Usage

1. Right-click `fix-windows-share.ps1` and select "Run with PowerShell"
   - Or open PowerShell as Administrator and run:
   ```powershell
   .\fix-windows-share.ps1
   ```

2. For detailed debug output:
   ```powershell
   .\fix-windows-share.ps1 -Debug
   ```

## What it Does

1. Configures network discovery services
2. Sets network profiles to Private
3. Enables required protocols
4. Optimizes network adapter settings
5. Configures file and printer sharing
6. Resets network stack if needed
7. Applies recommended security settings

## Logs

Logs are stored in:
- `%TEMP%\NetworkConfig_Debug.log` (Debug log)
- `%TEMP%\NetworkConfig_[timestamp].log` (Session log)

## License

MIT License - See LICENSE file for details

## Contributing

Pull requests welcome! Please read CONTRIBUTING.md first.