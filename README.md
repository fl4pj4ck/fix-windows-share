# Windows Network Discovery Fix

A PowerShell script to automatically configure and fix network discovery and file sharing on Windows 10 and 11.

## Features

- Configures network discovery and file sharing
- Supports both Windows 10 and 11
- Works with Home and Pro editions
- Automatically fixes common networking issues
- Resets network stack when needed
- Provides detailed logging and debug options

## Usage

1. Download the script
2. Right-click `fix-windows-share.ps1` and select "Run with PowerShell"
   - Or run from PowerShell with elevated privileges:
     ```powershell
     .\fix-windows-share.ps1
     ```
   - For debug output:
     ```powershell
     .\fix-windows-share.ps1 -Debug
     ```

## What it fixes

- Network discovery settings
- File and printer sharing
- Required Windows services
- Network protocols and bindings
- Firewall rules
- Network stack issues
- TCP/IP optimization
- SMB configuration

## Requirements

- Windows 10 or 11 (Home or Pro)
- PowerShell 5.0 or higher
- Administrative privileges

## Logs

The script creates log files in your temp directory:
- Debug log: `%TEMP%\NetworkConfig_Debug.log`
- Execution log: `%TEMP%\NetworkConfig_*.log`

## License

MIT License - see [LICENSE](LICENSE) file