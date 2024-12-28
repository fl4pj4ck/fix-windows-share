<#
.SYNOPSIS
    Network Discovery and Sharing Configuration Tool for Windows 10/11

.DESCRIPTION
    Automates the configuration of network discovery, file sharing, and related services
    on Windows 10 and Windows 11 systems. Handles both Home and Pro editions.

.PARAMETER Debug
    When specified, displays detailed debug information during script execution.
    Debug logs are always written to %TEMP%\NetworkConfig_Debug.log regardless of this parameter.

.EXAMPLE
    .\fix-windows-share.ps1
    Runs the script in normal mode with minimal output.

.EXAMPLE
    .\fix-windows-share.ps1 -Debug
    Runs the script with detailed debug information displayed.

.NOTES
    Version:        1.0
    Author:         fl4pj4ck
    Creation Date:  2024-03-19
    Requirements:
        - Windows 10/11
        - PowerShell 5.0 or higher
        - Administrative privileges

#>

param(
    [switch]$Debug
)

# Pause function
function Pause {
    Write-Host "`nPress Enter to continue..." -ForegroundColor Yellow -NoNewline
    [Console]::ReadKey($true) | Out-Null
    Write-Host
}

# Error handling
trap {
    Write-Host "`nScript failed at:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Write-Host "`nError message:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Pause
    exit 1
}

# Add this function near the start of the script, after the Pause function
function Start-ElevatedInstance {
    param (
        [string]$ScriptPath
    )

    try {
        Write-Host "Elevating script: $ScriptPath" -ForegroundColor Yellow

        # Create a unique log file for the elevated instance
        $elevatedLogFile = Join-Path $env:TEMP "NetworkConfig_Elevated_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

        # Pass through the debug parameter if it's set
        $debugParam = if ($Debug) { "-Debug" } else { "" }

        # Create a temporary script that will keep the window open after completion
        $tempScript = Join-Path $env:TEMP "NetworkConfig_Temp_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
        @"
Start-Transcript '$elevatedLogFile' -Force
& '$ScriptPath' $debugParam
Stop-Transcript
Write-Host "`nPress Enter to exit..." -ForegroundColor Yellow -NoNewline
[Console]::ReadKey(`$true) | Out-Null
"@ | Set-Content -Path $tempScript

        # Start elevated PowerShell process with the temporary script
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = "powershell.exe"
        $processStartInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`""
        $processStartInfo.Verb = "runas"
        $processStartInfo.UseShellExecute = $true
        $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal

        $process = [System.Diagnostics.Process]::Start($processStartInfo)
        if ($null -eq $process) {
            throw "Failed to start elevated process"
        }

        Write-Host "Waiting for elevated instance to complete..." -ForegroundColor Yellow
        $process.WaitForExit()

        # Clean up the temporary script
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue

        # Check the exit code
        if ($process.ExitCode -ne 0) {
            Write-Host "`nElevated instance failed (Exit Code: $($process.ExitCode))" -ForegroundColor Red

            # Try to read and display the elevated instance log
            if (Test-Path $elevatedLogFile) {
                Write-Host "`nElevated instance log:" -ForegroundColor Yellow
                Get-Content $elevatedLogFile | ForEach-Object {
                    Write-Host "  $_"
                }
            } else {
                Write-Host "Could not find elevated instance log at: $elevatedLogFile" -ForegroundColor Red
            }

            Pause
            exit $process.ExitCode
        }

        # Clean exit
        exit 0
    }
    catch {
        Write-Host "`nFailed to execute script with elevated privileges:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
        Write-Host "`nStack trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        Pause
        exit 1
    }
}

# Modify the elevation check block
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Requesting administrative privileges..." -ForegroundColor Yellow

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        Write-Host "Unable to determine script path. Please run the script directly from a file." -ForegroundColor Red
        Pause
        exit 1
    }

    # Create a transcript log for the non-elevated portion
    $baseLogFile = Join-Path $env:TEMP "NetworkConfig_Base_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $baseLogFile -Force | Out-Null

    try {
        Start-ElevatedInstance -ScriptPath $scriptPath
    }
    finally {
        Stop-Transcript | Out-Null
    }
    exit 0
}

# Initialize script variables
if ($null -eq $script:StepResults) {
    $script:StepResults = @{
        Critical = [System.Collections.ArrayList]@()
        Warnings = [System.Collections.ArrayList]@()
        Skipped = [System.Collections.ArrayList]@()
        Steps = @{}
    }
}

if ($null -eq $script:WindowsInfo) {
    $script:WindowsInfo = @{
        IsHome = $false
        IsWin11 = $false
        Build = 0
        Edition = ""
    }
}

# Initialize transcript
Start-Transcript -Path (Join-Path $env:TEMP "NetworkConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log") -Force | Out-Null

# Command execution function that logs output but doesn't show it
function Invoke-NetworkCommand {
    param(
        [string]$Command,
        [string]$DisplayName,
        [switch]$UseCmd,
        [switch]$SuppressOutput
    )

    try {
        # Initialize variables
        $output = $null
        $exitCode = 0

        # Execute command and capture output
        if ($UseCmd) {
            # For cmd.exe commands, use Start-Process to properly capture exit code
            $tempFile = [System.IO.Path]::GetTempFileName()
            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "$Command" -RedirectStandardOutput $tempFile -NoNewWindow -Wait -PassThru
            $exitCode = $process.ExitCode
            $output = Get-Content -Path $tempFile -Raw
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        } else {
            # For PowerShell commands
            $output = Invoke-Expression -Command $Command 2>&1
            $exitCode = $LASTEXITCODE
        }

        # Ensure we never return null
        if ([string]::IsNullOrEmpty($output)) {
            $output = "Command completed successfully"
        }

        # Set the exit code in the global scope for checking
        $global:LASTEXITCODE = $exitCode

        # Return output without displaying it
        if (-not $SuppressOutput) {
            return $output
        }
        return "Command executed successfully"
    }
    catch {
        Write-Error $_.Exception.Message
        $global:LASTEXITCODE = 1
        return "Error: $($_.Exception.Message)"
    }
}

# Script Variables
$script:StepResults = @{
    Critical = [System.Collections.ArrayList]@()
    Warnings = [System.Collections.ArrayList]@()
    Skipped = [System.Collections.ArrayList]@()
    Steps = @{}
}

$script:WindowsInfo = @{
    IsHome = $false
    IsWin11 = $false
    Build = 0
    Edition = ""
}

# Configuration
$services = @(
    @{
        Name = "dnscache"
        DisplayName = "DNS Client"
        Description = "DNS name resolution and cache"
    },
    @{
        Name = "LanmanServer"
        DisplayName = "Server"
        Description = "File and printer sharing"
    },
    @{
        Name = "LanmanWorkstation"
        DisplayName = "Workstation"
        Description = "Network connections"
    },
    @{
        Name = "rpcss"
        DisplayName = "Remote Procedure Call"
        Description = "RPC services"
    },
    @{
        Name = "NlaSvc"
        DisplayName = "Network Location Awareness"
        Description = "Network status detection"
    },
    @{
        Name = "nsi"
        DisplayName = "Network Store Interface Service"
        Description = "Network configuration"
    },
    @{
        Name = "FDResPub"
        DisplayName = "Function Discovery Resource Publication"
        Description = "Network resource publishing"
    }
)

$editionConfig = @{
    Home = @{
        SkipServices = @(
            "gpsvc",          # Group Policy Client
            "PolicyAgent"     # IPsec Policy Agent
        )
        RegistryFixes = @(
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkDiscovery"
                Name = "AllowNetworkDiscovery"
                Value = 1
                Type = "DWord"
            }
        )
    }
    Pro = @{
        AdditionalServices = @(
            @{
                Name = "gpsvc"
                DisplayName = "Group Policy Client"
                Description = "Group Policy management"
            },
            @{
                Name = "PolicyAgent"
                DisplayName = "IPsec Policy Agent"
                Description = "IPsec policy management"
            }
        )
    }
}

$windowsConfig = @{
    Win11 = @{
        Services = @(
            @{
                Name = "DevicesFlowUserSvc"
                DisplayName = "Devices Flow"
                Description = "Required for Windows 11 device discovery"
            }
        )
        Features = @(
            "NetFx4-AdvSrvs"  # Advanced networking features
        )
        RegistrySettings = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private"
                Name = "AutoSetup"
                Value = 1
                Type = "DWord"
            }
        )
    }
    Win10 = @{
        LegacySupport = @{
            Services = @(
                @{
                    Name = "upnphost"
                    DisplayName = "UPnP Device Host"
                    Description = "Universal Plug and Play device discovery"
                },
                @{
                    Name = "SSDPSRV"
                    DisplayName = "SSDP Discovery"
                    Description = "Simple Service Discovery Protocol"
                }
            )
        }
    }
}

$activeConfig = @{
    Services = @()
    Features = @()
    RegistrySettings = @()
    SkipServices = @()
}

# Helper Functions
function Write-StepHeader {
    param([string]$Message)
        Write-Host "`n=== $Message ===`n" -ForegroundColor Cyan
}

function Write-SubStep {
    param([string]$Message)
    $output = "  -> $Message"
    Write-Host $output -ForegroundColor White
}

function Write-Success {
    param([string]$Message)
    $output = "  + $Message"
    Write-Host $output -ForegroundColor Green
}

function Write-CustomWarning {
    param([string]$Message)
    $output = "  ! $Message"
    Write-Host $output -ForegroundColor Yellow
}

function Add-StepResult {
    param (
        [string]$Step,
        [string]$Component,
        [string]$Message,
        [ValidateSet('Critical', 'Warning', 'Skipped')]
        [string]$Type
    )

    # Ensure StepResults is initialized
    if ($null -eq $script:StepResults) {
        $script:StepResults = @{
            Critical = [System.Collections.ArrayList]@()
            Warnings = [System.Collections.ArrayList]@()
            Skipped = [System.Collections.ArrayList]@()
            Steps = @{}
        }
    }

    # Ensure the step exists in Steps
    if (-not $script:StepResults.Steps.ContainsKey($Step)) {
        $script:StepResults.Steps[$Step] = @{
            Critical = [System.Collections.ArrayList]::new()
            Warnings = [System.Collections.ArrayList]::new()
            Skipped = [System.Collections.ArrayList]::new()
        }
    }

    # Create the result object
    $result = @{
        Component = $Component
        Message = $Message
        Timestamp = Get-Date
    }

    # Ensure arrays exist before adding
    if ($null -eq $script:StepResults.Steps[$Step].$Type) {
        $script:StepResults.Steps[$Step].$Type = [System.Collections.ArrayList]::new()
    }
    if ($null -eq $script:StepResults.$Type) {
        $script:StepResults.$Type = [System.Collections.ArrayList]::new()
    }

    # Add results using null checks
    $stepArray = $script:StepResults.Steps[$Step].$Type
    if ($null -eq $stepArray) {
        $stepArray = [System.Collections.ArrayList]::new()
        $script:StepResults.Steps[$Step].$Type = $stepArray
    }
    $null = $stepArray.Add($result)

    $globalArray = $script:StepResults.$Type
    if ($null -eq $globalArray) {
        $globalArray = [System.Collections.ArrayList]::new()
        $script:StepResults.$Type = $globalArray
    }
    $null = $globalArray.Add($result)

    Write-DebugLog "Added $Type result for step '$Step': [$Component] $Message"
}

function Write-ReportSection {
    param(
        [string]$Title,
        [array]$Items,
        [string]$Prefix = "  - "
    )

    if ($Items.Count -gt 0) {
        Write-Host "$Title"
        foreach ($item in $Items) {
            Write-Host "$Prefix[$($item.Component)] $($item.Message)"
        }
        Write-Host ""
    }
}

function Show-StepReport {
    Write-Host "`n=== Configuration Report ===`n" -ForegroundColor Cyan

    # Ensure StepResults is initialized
    if ($null -eq $script:StepResults) {
        $script:StepResults = @{
            Critical = [System.Collections.ArrayList]@()
            Warnings = [System.Collections.ArrayList]@()
            Skipped = [System.Collections.ArrayList]@()
            Steps = @{}
        }
    }

    $hasIssues = ($script:StepResults.Critical -and $script:StepResults.Critical.Count -gt 0) -or
                 ($script:StepResults.Warnings -and $script:StepResults.Warnings.Count -gt 0) -or
                 ($script:StepResults.Skipped -and $script:StepResults.Skipped.Count -gt 0)

    if ($hasIssues) {
        # Summary Section
        Write-Host "Summary:"
        Write-Host "--------"
        Write-Host "Critical Issues: $($script:StepResults.Critical.Count)"
        Write-Host "Warnings: $($script:StepResults.Warnings.Count)"
        Write-Host "Skipped Items: $($script:StepResults.Skipped.Count)"
        Write-Host ""

        # Detailed Results Section
        if ($script:StepResults.Steps -and $script:StepResults.Steps.Count -gt 0) {
            foreach ($step in $script:StepResults.Steps.Keys) {
                $stepResults = $script:StepResults.Steps[$step]
                if ($null -eq $stepResults) { continue }

                $hasStepIssues = ($stepResults.Critical -and $stepResults.Critical.Count -gt 0) -or
                                ($stepResults.Warnings -and $stepResults.Warnings.Count -gt 0) -or
                                ($stepResults.Skipped -and $stepResults.Skipped.Count -gt 0)

                if ($hasStepIssues) {
                    Write-Host "Step: $step"
                    Write-Host "-------------------"
                    Write-Host ""

                    if ($stepResults.Critical -and $stepResults.Critical.Count -gt 0) {
                        Write-ReportSection "Critical Issues:" $stepResults.Critical
                    }
                    if ($stepResults.Warnings -and $stepResults.Warnings.Count -gt 0) {
                        Write-ReportSection "Warnings:" $stepResults.Warnings
                    }
                    if ($stepResults.Skipped -and $stepResults.Skipped.Count -gt 0) {
                        Write-ReportSection "Skipped Items:" $stepResults.Skipped
                    }
                }
            }
        }
    }

    # Recommendations Section
    Write-Host "Recommended Actions:"
    Write-Host "-------------------"

    if ($script:StepResults.Critical -and $script:StepResults.Critical.Count -gt 0) {
        Write-Host "`nSystem restart is NOT recommended until critical issues are resolved." -ForegroundColor Red
        Write-Host "Please review the report above and address any critical issues before restarting." -ForegroundColor Red
    } else {
        Write-Host "+ Configuration completed successfully!" -ForegroundColor Green

        # Check if any significant changes were made
        $needsReboot = $false
        if ($script:StepResults.Steps -and $script:StepResults.Steps.Count -gt 0) {
            foreach ($step in $script:StepResults.Steps.Keys) {
                if ($step -eq "Network Stack Reset" -and
                    (($script:StepResults.Steps[$step].Critical -and $script:StepResults.Steps[$step].Critical.Count -gt 0) -or
                     ($script:StepResults.Steps[$step].Warnings -and $script:StepResults.Steps[$step].Warnings.Count -gt 0))) {
                    $needsReboot = $true
                    break
                }
            }
        }

        Write-Host "  - Network Discovery and File Sharing should now be working"
        if ($needsReboot) {
            Write-Host "  - A system restart is recommended to apply network stack changes" -ForegroundColor Yellow
        }
        Write-Host "  - Verify network discovery by checking:"
        Write-Host "    1. File Explorer -> Network"
        Write-Host "    2. Control Panel -> Network and Sharing Center"
        Write-Host "    3. Settings -> Network & Internet -> Sharing options"
    }

    Write-Host ""

    # Add log file paths at the end
    Write-Host "`nLog Files:" -ForegroundColor Cyan
    Write-Host "----------"
    $logFiles = @(
        (Join-Path $env:TEMP "NetworkConfig_Debug.log"),
        (Get-ChildItem -Path $env:TEMP -Filter "NetworkConfig_*.log" |
         Where-Object { $_.Name -match "NetworkConfig_\d{8}_\d{6}\.log" } |
         Sort-Object LastWriteTime -Descending |
         Select-Object -First 1).FullName
    ) | Where-Object { Test-Path $_ } | Sort-Object -Unique

    foreach ($logFile in $logFiles) {
        Write-Host "  - $logFile"
    }
    Write-Host ""

    # Only prompt for restart if needed
    if ($needsReboot) {
        $restart = Read-Host "`nWould you like to restart the computer now? (y/n)"
        if ($restart -eq 'y') {
            Write-SubStep "Initiating system restart..."
            Start-Sleep -Seconds 3
            Restart-Computer -Force
        }
    }
}

function Set-NetworkProfilePrivate {
    [CmdletBinding()]
    param()

    $currentStep = "Network Profile"
    Write-SubStep "Setting network profiles to Private..."

    try {
        $profiles = Get-NetConnectionProfile
        foreach ($profile in $profiles) {
            if ($profile.NetworkCategory -ne "Private") {
                Write-SubStep "Changing profile '$($profile.Name)' from $($profile.NetworkCategory) to Private"
                Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Private
                Write-Success "Set profile '$($profile.Name)' to Private"
            } else {
                Write-CustomWarning "Profile '$($profile.Name)' already set to Private"
            }
        }
    } catch {
        Add-StepResult -Step $currentStep `
                      -Component "Network Profiles" `
                      -Message ("Failed to configure profiles: {0}" -f $_.Exception.Message) `
                      -Type 'Critical'
    }
}

function Enable-RequiredProtocols {
    [CmdletBinding()]
    param()

    $currentStep = "Network Protocols"
    Write-SubStep "Configuring required network protocols..."

    # Get all network adapters first
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }

    if (-not $adapters) {
        Add-StepResult -Step $currentStep `
                      -Component "Network Adapters" `
                      -Message "No active network adapters found" `
                      -Type 'Warning'
        Write-CustomWarning "No active network adapters found"
        return
    }

    foreach ($adapter in $adapters) {
        Write-SubStep "Configuring protocols for adapter: $($adapter.Name)"

        # Correct component IDs for network bindings
        $components = @(
            @{ ID = "ms_tcpip"; Name = "IPv4" },
            @{ ID = "ms_tcpip6"; Name = "IPv6" },
            @{ ID = "ms_msclient"; Name = "Client for Microsoft Networks" },
            @{ ID = "ms_server"; Name = "File and Printer Sharing" },
            @{ ID = "ms_rspndr"; Name = "Link-Layer Topology Discovery Responder" },
            @{ ID = "ms_lltdio"; Name = "Link-Layer Topology Discovery Mapper I/O Driver" }
        )

        foreach ($component in $components) {
            try {
                # Check if binding exists and its current state
                $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID $component.ID -ErrorAction SilentlyContinue
                if ($null -ne $binding) {
                    if (-not $binding.Enabled) {
                        Write-SubStep "Enabling $($component.Name) on adapter (currently disabled)"
                        Enable-NetAdapterBinding -Name $adapter.Name -ComponentID $component.ID -ErrorAction Stop
                        Write-Success "Enabled $($component.Name) on adapter"
                    } else {
                        Write-CustomWarning "$($component.Name) already enabled on adapter"
                    }
                } else {
                    Write-CustomWarning "$($component.Name) not available on adapter $($adapter.Name)"
                }
            } catch {
                Write-CustomWarning "Failed to configure $($component.Name) on adapter $($adapter.Name): $($_.Exception.Message)"
            }
        }

        # Check and optimize TCP/IP settings
        try {
            $tcpipBinding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip -ErrorAction SilentlyContinue
            if ($null -ne $tcpipBinding) {
                $ipInterface = Get-NetIPInterface -InterfaceAlias $adapter.Name -AddressFamily IPv4
                if ($ipInterface -and $ipInterface.RouterDiscovery -ne 'Enabled') {
                    Write-SubStep "Optimizing TCP/IP settings for adapter"
                    Set-NetIPInterface -InterfaceAlias $adapter.Name -AddressFamily IPv4 -RouterDiscovery Enabled
                    Write-Success "Updated TCP/IP settings for adapter"
                } else {
                    Write-CustomWarning "TCP/IP settings already optimized for adapter"
                }
            }
        } catch {
            Write-CustomWarning "Failed to optimize TCP/IP settings for adapter $($adapter.Name): $($_.Exception.Message)"
        }
    }
}

function Compare-Setting {
    param (
        [string]$Path,
        [string]$Name,
        [object]$DesiredValue,
        [string]$Type = "DWord"
    )

    try {
        if (!(Test-Path $Path)) {
            return @{
                Changed = $true
                Message = "Path does not exist"
            }
        }

        $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $current) {
            return @{
                Changed = $true
                Message = "Setting does not exist"
            }
        }

        $currentValue = $current.$Name
        if ($currentValue -eq $DesiredValue) {
            return @{
                Changed = $false
                Message = "Already set to desired value: $currentValue"
            }
        }

        return @{
            Changed = $true
            Message = "Current: $currentValue, Desired: $DesiredValue"
        }
    }
    catch {
        return @{
            Changed = $true
            Message = "Error checking value: $_"
        }
    }
}

function Enable-NetworkOptimization {
    [CmdletBinding()]
    param()

    $currentStep = "Network Optimization"
    Write-SubStep "Optimizing network performance..."

    try {
        # Configure TCP/IP parameters
        $tcpParams = @{
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" = @{
                "EnableConnectionRateLimiting" = 0
                "EnableDCA" = 1
                "EnablePMTUDiscovery" = 1
                "EnableWsd" = 1
                "GlobalMaxTcpWindowSize" = 65535
                "Tcp1323Opts" = 1
                "TcpMaxDupAcks" = 2
                "SackOpts" = 1
            }
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" = @{
                "DisabledComponents" = 0x20  # Prefer IPv4 over IPv6
                "EnableICSIPv6" = 0         # Disable IPv6 Internet Connection Sharing
            }
        }

        foreach ($path in $tcpParams.Keys) {
            foreach ($name in $tcpParams[$path].Keys) {
                try {
                    if (!(Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                        Write-Success "Created registry path: $path"
                    }

                    $comparison = Compare-Setting -Path $path -Name $name -DesiredValue $tcpParams[$path][$name]
                    if ($comparison.Changed) {
                        Set-ItemProperty -Path $path -Name $name -Value $tcpParams[$path][$name] -Type DWord -Force
                        Write-Success "Updated: $name ($($comparison.Message))"
                    } else {
                        Write-CustomWarning "Skipped: $name ($($comparison.Message))"
                    }
                } catch {
                    Add-StepResult -Step $currentStep `
                                  -Component $name `
                                  -Message ("Failed to configure: {0}" -f $_.Exception.Message) `
                                  -Type 'Warning'
                }
            }
        }
    } catch {
        Add-StepResult -Step $currentStep `
                      -Component "Network Optimization" `
                      -Message ("Failed to optimize network: {0}" -f $_.Exception.Message) `
                      -Type 'Critical'
    }
}

function Enable-UserNetworkDiscovery {
    [CmdletBinding()]
    param()

    $currentStep = "User Settings"
    Write-SubStep "Configuring user network discovery settings..."

    try {
        $userSettings = @{
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                "SharingWizardOn" = 0
            }
        }

        foreach ($path in $userSettings.Keys) {
            foreach ($name in $userSettings[$path].Keys) {
                try {
                    $comparison = Compare-Setting -Path $path -Name $name -DesiredValue $userSettings[$path][$name]
                    if ($comparison.Changed) {
                        Set-ItemProperty -Path $path -Name $name -Value $userSettings[$path][$name] -Type DWord -Force
                        Write-Success "Updated user setting: $name ($($comparison.Message))"
                    } else {
                        Write-CustomWarning "Skipped user setting: $name ($($comparison.Message))"
                    }
                } catch {
                    Add-StepResult -Step $currentStep `
                                  -Component "User Settings" `
                                  -Message ("Failed to configure setting: {0}" -f $_.Exception.Message) `
                                  -Type 'Critical'
                }
            }
        }
    } catch {
        Add-StepResult -Step $currentStep `
                      -Component "User Settings" `
                      -Message ("Failed to configure user settings: {0}" -f $_.Exception.Message) `
                      -Type 'Critical'
    }
}

# Main execution flow
function Initialize-Configuration {
    # Initialize base services
    $activeConfig.Services = @() + $services

    # Apply Windows version specific settings
    if ($script:WindowsInfo.IsWin11) {
        # Use ArrayList for dynamic array operations
        $activeConfig.Services = [System.Collections.ArrayList]@($activeConfig.Services)
        $activeConfig.Services.AddRange($windowsConfig.Win11.Services)
        $activeConfig.Features += $windowsConfig.Win11.Features
        $activeConfig.RegistrySettings += $windowsConfig.Win11.RegistrySettings
    } else {
        # For Windows 10, add legacy support services
        $activeConfig.Services = [System.Collections.ArrayList]@($activeConfig.Services)
        $activeConfig.Services.AddRange($windowsConfig.Win10.LegacySupport.Services)
    }

    # Apply edition specific settings
    if ($script:WindowsInfo.IsHome) {
        $activeConfig.SkipServices += $editionConfig.Home.SkipServices
        $activeConfig.RegistrySettings += $editionConfig.Home.RegistryFixes
    } else {
        $activeConfig.Services = [System.Collections.ArrayList]@($activeConfig.Services)
        $activeConfig.Services.AddRange($editionConfig.Pro.AdditionalServices)
    }

    # Remove any duplicate services
    $activeConfig.Services = @($activeConfig.Services | Where-Object { $_ -ne $null } |
        Sort-Object -Property Name -Unique)
}

function Start-NetworkConfiguration {
    try {
        Write-DebugLog "Starting network configuration"
        Clear-Host
        Write-StepHeader "Network Discovery Configuration Tool"

        # Check Windows version and requirements
        Write-DebugLog "Checking Windows requirements"
        if (-not (Initialize-WindowsInfo)) {
            Write-DebugLog "Windows requirements check failed"
            exit 1
        }

        # Configuration Steps
        Write-StepHeader "Step 1/10: Enabling Required Windows Features"
        Enable-WindowsFeatures

        Write-StepHeader "Step 2/10: Enabling Required Services"
        Enable-NetworkDiscoveryServices

        Write-StepHeader "Step 3/10: Setting Network Profile"
        Set-NetworkProfilePrivate

        Write-StepHeader "Step 4/10: Configuring Network Protocols"
        Enable-RequiredProtocols

        Write-StepHeader "Step 5/10: Optimizing Network Performance"
        Enable-NetworkOptimization

        Write-StepHeader "Step 6/10: Configuring Network Discovery Settings"
        Enable-NetworkDiscoverySettings

        Write-StepHeader "Step 7/10: Configuring User Settings"
        Enable-UserNetworkDiscovery

        Write-StepHeader "Step 8/10: Configuring Firewall Rules"
        Enable-NetworkDiscoveryFirewallRules
        Enable-FilePrinterSharing

        Write-StepHeader "Step 9/10: Resetting Network Stack"
        Write-DebugLog "Starting network stack reset"
        $resetResult = Reset-NetworkStack
        Write-DebugLog "Network stack reset result: $resetResult"

        if ($null -eq $resetResult) {
            Write-DebugLog "Reset result is null"
            throw "Network stack reset returned null"
        }

        if ($resetResult -eq $false) {
            Write-DebugLog "Reset result is false"
            throw "Network stack reset failed"
        }

        Write-DebugLog "Network stack reset completed successfully"

        # Final Status and Report
        Write-StepHeader "Step 10/10: Configuration Complete"
        Write-Success "Network Discovery configuration has been completed"

        # Show the configuration report
        Show-StepReport
    }
    catch {
        Write-DebugLog "Error in Start-NetworkConfiguration: $($_.Exception.Message)"
        Write-DebugLog "Stack trace: $($_.ScriptStackTrace)"
        Write-Error "An unexpected error occurred: $_"
        Show-StepReport
        exit 1
    }
    finally {
        Stop-Transcript | Out-Null
    }
}

function Enable-WindowsFeatures {
    [CmdletBinding()]
    param()

    $currentStep = "Windows Features"
    Write-SubStep "Configuring Windows features..."

    try {
        if ($activeConfig.Features.Count -gt 0) {
            foreach ($feature in $activeConfig.Features) {
                try {
                    $state = Get-WindowsOptionalFeature -Online -FeatureName $feature
                    if ($state.State -ne "Enabled") {
                        Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
                        Write-Success "Enabled feature: $feature"
                    } else {
                        Write-Success "Feature already enabled: $feature"
                    }
                } catch {
                    Add-StepResult -Step $currentStep `
                                  -Component $feature `
                                  -Message ("Failed to enable: {0}" -f $_.Exception.Message) `
                                  -Type 'Warning'
                }
            }
        } else {
            Write-Success "No additional features required for this Windows version"
        }
    } catch {
        Add-StepResult -Step $currentStep `
                      -Component "Feature Management" `
                      -Message ("Failed to configure Windows features: {0}" -f $_.Exception.Message) `
                      -Type 'Critical'
    }
}

function Enable-NetworkDiscoveryFirewallRules {
    [CmdletBinding()]
    param()

    $currentStep = "Firewall Rules"
    Write-SubStep "Configuring Network Discovery firewall rules..."

    $rules = @(
        @{
            Name = "NETDIS-WSDEVNTS-In-TCP"
            DisplayName = "Network Discovery (WSD Events)"
            Direction = "Inbound"
            Protocol = "TCP"
        },
        @{
            Name = "NETDIS-WSDEVNT-Out-TCP"
            DisplayName = "Network Discovery (WSD Events-Out)"
            Direction = "Outbound"
            Protocol = "TCP"
        },
        @{
            Name = "NETDIS-SSDPSrv-In-UDP"
            DisplayName = "Network Discovery (SSDP)"
            Direction = "Inbound"
            Protocol = "UDP"
        },
        @{
            Name = "NETDIS-UPnP-Out-TCP"
            DisplayName = "Network Discovery (UPnP-Out)"
            Direction = "Outbound"
            Protocol = "TCP"
        }
    )

    foreach ($rule in $rules) {
        Write-SubStep "Processing: $($rule.DisplayName)"
        try {
            $existingRule = Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue

            if ($existingRule) {
                if ($existingRule.Enabled -and $existingRule.Profile -match 'Private|Domain') {
                    Write-CustomWarning "Rule already configured: $($rule.DisplayName)"
                    continue
                }
                Write-SubStep "Updating existing rule: $($rule.DisplayName)"
                Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
            } else {
                Write-SubStep "Creating new rule: $($rule.DisplayName)"
            }

            $cmd = "New-NetFirewallRule -Name '$($rule.Name)' -DisplayName '$($rule.DisplayName)' " +
                   "-Direction $($rule.Direction) -Protocol $($rule.Protocol) " +
                   "-Profile 'Private,Domain' -Action Allow -Enabled True"

            Invoke-NetworkCommand -Command $cmd -DisplayName "Create firewall rule: $($rule.DisplayName)" -SuppressOutput
            Write-Success "Created/Updated firewall rule: $($rule.DisplayName)"
        }
        catch {
            Add-StepResult -Step $currentStep `
                          -Component $rule.DisplayName `
                          -Message ("Failed to configure: {0}" -f $_.Exception.Message) `
                          -Type 'Critical'
        }
    }
}

function Enable-FilePrinterSharing {
    [CmdletBinding()]
    param()

    Write-SubStep "Configuring File and Printer Sharing..."

    try {
        # Check and enable File and Printer Sharing firewall rules
        $fpsRules = Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue
        if ($fpsRules | Where-Object { -not $_.Enabled -or $_.Profile -notmatch 'Private|Domain' }) {
            Invoke-NetworkCommand -Command "Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled True -Profile Private,Domain" `
                -DisplayName "Enable File and Printer Sharing firewall rules"
            Write-Success "Updated File and Printer Sharing firewall rules"
        } else {
            Write-CustomWarning "File and Printer Sharing firewall rules already configured"
        }

        # Check and configure SMB settings
        $smbConfig = Get-SmbServerConfiguration

        # Check SMBv1
        if ($smbConfig.EnableSMB1Protocol) {
            Invoke-NetworkCommand -Command "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" `
                -DisplayName "Disable SMBv1"
            Write-Success "Disabled SMBv1 protocol"
        } else {
            Write-CustomWarning "SMBv1 protocol already disabled"
        }

        # Check SMBv2
        if (-not $smbConfig.EnableSMB2Protocol) {
            Invoke-NetworkCommand -Command "Set-SmbServerConfiguration -EnableSMB2Protocol `$true -Force" `
                -DisplayName "Enable SMBv2"
            Write-Success "Enabled SMBv2 protocol"
        } else {
            Write-CustomWarning "SMBv2 protocol already enabled"
        }

        # Check SMB performance settings
        $smbOptimizations = @{
            "EnableMultiChannel" = $true
            "Smb2CreditsMin" = 512
            "Smb2CreditsMax" = 8192
            "ServerHidden" = $false
            "AnnounceServer" = $true
        }

        $optimizationsNeeded = $false
        foreach ($setting in $smbOptimizations.Keys) {
            if ($smbConfig.$setting -ne $smbOptimizations[$setting]) {
                $optimizationsNeeded = $true
                break
            }
        }

        if ($optimizationsNeeded) {
            Invoke-NetworkCommand -Command @"
                Set-SmbServerConfiguration -EnableMultiChannel `$true -Force
                Set-SmbServerConfiguration -Smb2CreditsMin 512 -Smb2CreditsMax 8192 -Force
                Set-SmbServerConfiguration -ServerHidden `$false -AnnounceServer `$true -Force
"@ -DisplayName "Optimize SMB performance"
            Write-Success "Updated SMB performance settings"
        } else {
            Write-CustomWarning "SMB performance settings already optimized"
        }

        # Check LanmanServer service
        $svc = Get-Service -Name 'LanmanServer' -ErrorAction Stop
        if ($svc.StartType -ne 'Automatic' -or $svc.Status -ne 'Running') {
            Invoke-NetworkCommand -Command "Set-Service -Name 'LanmanServer' -StartupType Automatic; Start-Service -Name 'LanmanServer'" `
                -DisplayName "Start File and Printer Sharing service"
            Write-Success "File and Printer Sharing service configured and started"
        } else {
            Write-CustomWarning "File and Printer Sharing service already configured and running"
        }
    }
    catch {
        Add-StepResult -Step "File Sharing" `
                      -Component "File and Printer Sharing" `
                      -Message ("Failed to configure: {0}" -f $_.Exception.Message) `
                      -Type 'Critical'
    }
}

function Write-DebugLog {
    param(
        [string]$Message,
        [string]$Category = "Debug"
    )

    if (-not $Debug) {
        # If debug mode is off, only write to file
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Category] $Message"
        Add-Content -Path (Join-Path $env:TEMP "NetworkConfig_Debug.log") -Value $logMessage
        return
    }

    # If debug mode is on, write to both console and file
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Category] $Message"
    Write-Host $logMessage -ForegroundColor Magenta
    Add-Content -Path (Join-Path $env:TEMP "NetworkConfig_Debug.log") -Value $logMessage
}

function Reset-NetworkStack {
    [CmdletBinding()]
    param()

    $currentStep = "Network Stack Reset"
    Write-SubStep "Resetting network components..."
    Write-DebugLog "Starting Reset-NetworkStack function"

    try {
        $criticalChanges = $false
        $criticalFailures = $false
        $success = $true

        Write-DebugLog "Initialized variables"

        # Define commands array inside the function
        [array]$networkCommands = @(
            @{
                name = "DNS Cache Flush"
                cmd = "ipconfig /flushdns"
                critical = $false
                requiresReboot = $false
            },
            @{
                name = "DNS Registration"
                cmd = "ipconfig /registerdns"
                critical = $false
                requiresReboot = $false
            },
            @{
                name = "IP Release"
                cmd = "ipconfig /release"
                critical = $false
                requiresReboot = $false
            },
            @{
                name = "IP Renew"
                cmd = "ipconfig /renew"
                critical = $false
                requiresReboot = $false
            },
            @{
                name = "Winsock Reset"
                cmd = "netsh winsock reset"
                critical = $true
                requiresReboot = $true
            },
            @{
                name = "IP Stack Reset"
                cmd = "netsh int ip reset"
                critical = $true
                requiresReboot = $true
            }
        )

        Write-DebugLog "Network commands array defined"

        foreach ($command in $networkCommands) {
            Write-DebugLog "Processing command: $($command.name)"
            Write-SubStep "Executing: $($command.name)"

            try {
                Write-DebugLog "Resetting LASTEXITCODE"
                $global:LASTEXITCODE = 0

                Write-DebugLog "Executing command: $($command.cmd)"
                $output = Invoke-NetworkCommand -Command $command.cmd -DisplayName $command.name -UseCmd
                Write-DebugLog "Command output: $output"

                $cmdExitCode = $global:LASTEXITCODE
                Write-DebugLog "Command exit code: $cmdExitCode"

                if ($cmdExitCode -eq 0 -or
                    $output -match "completed successfully|OK|Command completed|processed|reset catalog") {
                    Write-Success "$($command.name) completed successfully"
                    Write-DebugLog "$($command.name) completed successfully"

                    if ($command.requiresReboot -and
                        $output -notmatch "No changes|There are no entries|The system cannot find") {
                        $criticalChanges = $true
                        Write-DebugLog "Critical changes detected, reboot required"
                    }
                } else {
                    $errorMsg = "Command completed with exit code $cmdExitCode"
                    Write-DebugLog "Command error: $errorMsg"

                    if ($command.critical) {
                        Write-CustomWarning "$($command.name) failed: $errorMsg"
                        $criticalFailures = $true
                        $success = $false
                        Write-DebugLog "Critical failure detected"
                    } else {
                        Write-CustomWarning "$($command.name): $errorMsg"
                        Write-DebugLog "Non-critical warning"
                    }
                }
            }
            catch {
                $errorMsg = if ($_.Exception.Message) { $_.Exception.Message } else { "Unknown error" }
                Write-DebugLog "Exception caught: $errorMsg"
                Write-DebugLog "Stack trace: $($_.ScriptStackTrace)"

                Add-StepResult -Step $currentStep `
                              -Component $command.name `
                              -Message ("Failed: {0}" -f $errorMsg) `
                              -Type $(if ($command.critical) { 'Critical' } else { 'Warning' })

                if ($command.critical) {
                    $criticalFailures = $true
                    $success = $false
                    Write-DebugLog "Critical failure in catch block"
                }
                continue
            }
        }

        Write-DebugLog "All commands processed"
        Write-DebugLog "Critical failures: $criticalFailures"
        Write-DebugLog "Critical changes: $criticalChanges"
        Write-DebugLog "Success status: $success"

        if ($criticalFailures) {
            Write-DebugLog "Adding critical failure result"
            Add-StepResult -Step $currentStep `
                          -Component "Network Stack" `
                          -Message "One or more critical network stack operations failed" `
                          -Type 'Critical'
            return $false
        }

        if ($criticalChanges) {
            Write-DebugLog "Adding warning about restart requirement"
            Add-StepResult -Step $currentStep `
                          -Component "Network Stack" `
                          -Message "Network stack changes require a system restart" `
                          -Type 'Warning'
        }

        Write-DebugLog "Returning success status: $success"
        return $success
    }
    catch {
        $errorMsg = if ($_.Exception.Message) { $_.Exception.Message } else { "Unknown error" }
        Write-DebugLog "Fatal error in Reset-NetworkStack: $errorMsg"
        Write-DebugLog "Stack trace: $($_.ScriptStackTrace)"

        Add-StepResult -Step $currentStep `
                      -Component "Network Stack" `
                      -Message ("Failed: {0}" -f $errorMsg) `
                      -Type 'Critical'
        return $false
    }
}

function Enable-NetworkDiscoverySettings {
    [CmdletBinding()]
    param()

    $currentStep = "Network Discovery Settings"
    Write-SubStep "Configuring registry settings..."

    try {
        $registrySettings = @{
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkDiscovery" = @{
                "AllowNetworkDiscovery" = @{
                    Type = "DWord"
                    Value = 1
                }
            }
        }

        foreach ($path in $registrySettings.Keys) {
            foreach ($name in $registrySettings[$path].Keys) {
                try {
                    if (!(Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                        Write-Success "Created registry path: $path"
                    }

                    $comparison = Compare-Setting -Path $path -Name $name -DesiredValue $registrySettings[$path][$name].Value
                    if ($comparison.Changed) {
                        Set-ItemProperty -Path $path -Name $name -Value $registrySettings[$path][$name].Value -Type $registrySettings[$path][$name].Type -Force
                        Write-Success "Updated policy: $name ($($comparison.Message))"
                    } else {
                        Write-CustomWarning "Skipped policy: $name ($($comparison.Message))"
                    }
                } catch {
                    Add-StepResult -Step $currentStep `
                                  -Component $name `
                                  -Message ("Failed to configure: {0}" -f $_.Exception.Message) `
                                  -Type 'Critical'
                }
            }
        }
    } catch {
        Add-StepResult -Step $currentStep `
                      -Component "Registry Settings" `
                      -Message ("Failed to configure settings: {0}" -f $_.Exception.Message) `
                      -Type 'Critical'
    }
}

function Enable-NetworkDiscoveryServices {
    [CmdletBinding()]
    param()

    $currentStep = "Services Configuration"
    Write-SubStep "Configuring required services..."

    foreach ($service in $activeConfig.Services) {
        Write-SubStep "Configuring: $($service.DisplayName) ($($service.Description))"

        try {
            # Check if service exists first
            $svcInfo = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if (-not $svcInfo) {
                Write-CustomWarning "Service $($service.DisplayName) not found"
                continue
            }

            # Check startup type
            if ($svcInfo.StartType -ne 'Automatic') {
                Write-SubStep "Changing startup type from $($svcInfo.StartType) to Automatic"
                Set-Service -Name $service.Name -StartupType Automatic -ErrorAction Stop
                Write-Success "Set $($service.DisplayName) to Automatic startup"
            } else {
                Write-CustomWarning "$($service.DisplayName) already set to Automatic startup"
            }

            # Check service status
            if ($svcInfo.Status -ne 'Running') {
                Write-SubStep "Starting service (current status: $($svcInfo.Status))"
                Start-Service -Name $service.Name -ErrorAction Stop
                Write-Success "Started $($service.DisplayName)"
            } else {
                Write-CustomWarning "$($service.DisplayName) already running"
            }
        }
        catch {
            if ($_.Exception.Message -match 'Access is denied') {
                Write-CustomWarning "Insufficient permissions for $($service.DisplayName), skipping..."
                continue
            }
            Add-StepResult -Step $currentStep `
                          -Component $service.DisplayName `
                          -Message ("Failed to configure: {0}" -f $_.Exception.Message) `
                          -Type 'Warning'
        }
    }
}

function Initialize-WindowsInfo {
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $script:WindowsInfo.Edition = $osInfo.Caption
        $script:WindowsInfo.Build = $osInfo.BuildNumber
        $script:WindowsInfo.IsHome = $osInfo.Caption -match "Home"
        $script:WindowsInfo.IsWin11 = $osInfo.BuildNumber -ge 22000

        Write-Host "Detected: $($script:WindowsInfo.Edition) (Build $($script:WindowsInfo.Build))"

        if ([System.Environment]::OSVersion.Version.Major -lt 10) {
            Write-Error "This script requires Windows 10 or later"
            return $false
        }

        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Error "PowerShell 5.0 or higher is required"
            return $false
        }

        return $true
    } catch {
        Write-Error "Failed to determine Windows version"
        return $false
    }
}

# Execute the script
Initialize-Configuration
Start-NetworkConfiguration

# Ensure we pause on any error
if ($Error.Count -gt 0) {
    Write-Host "`nScript completed with errors:" -ForegroundColor Red
    foreach ($err in $Error) {
        Write-Host "- $($err.Exception.Message)" -ForegroundColor Red
    }
    Pause
}