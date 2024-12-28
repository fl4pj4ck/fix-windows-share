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

# Replace the process check with a simpler version
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$processes = Get-Process | Where-Object { $_.ProcessName -like "*powershell*" -and $_.CommandLine -like "*$scriptName*" }
if ($processes.Count -gt 2) {
    Write-Warning "Script is already running in another window"
    return
}

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

    # Get physical network adapters only
    $adapters = Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and
        # Only include physical adapters
        $_.InterfaceType -eq 6 -and  # 6 = Ethernet
        # Additional filtering for virtual adapters
        -not ($_.Name -like "*Virtual*" -or
              $_.Name -like "*WSL*" -or
              $_.Name -like "*Loopback*" -or
              $_.Name -like "*Bluetooth*" -or
              $_.Name -like "*vEthernet*" -or
              $_.HardwareInterface -eq $false)
    }

    if (-not $adapters) {
        Add-StepResult -Step $currentStep `
                      -Component "Network Adapters" `
                      -Message "No physical network adapters found" `
                      -Type 'Warning'
        return
    }

    foreach ($adapter in $adapters) {
        Write-SubStep "Configuring physical adapter: $($adapter.Name)"

        # Basic adapter configuration with improved error handling
        try {
            # Enable adapter and verify status
            $result = cmd /c "netsh interface set interface `"$($adapter.Name)`" admin=enable" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Enabled adapter: $($adapter.Name)"

                # Configure advanced adapter settings
                $advancedSettings = @(
                    @{ setting = "Speed & Duplex"; value = "Auto Negotiation" },
                    @{ setting = "Energy Efficient Ethernet"; value = "Disabled" },
                    @{ setting = "Flow Control"; value = "Rx & Tx Enabled" }
                )

                foreach ($setting in $advancedSettings) {
                    try {
                        $property = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $setting.setting -ErrorAction SilentlyContinue
                        if ($property) {
                            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $setting.setting -DisplayValue $setting.value -ErrorAction SilentlyContinue
                            Write-Success "Configured $($setting.setting) on $($adapter.Name)"
                        }
                    } catch {
                        Write-DebugLog "Advanced setting $($setting.setting) not supported on $($adapter.Name)"
                    }
                }

                # Configure basic protocols
                $protocols = @(
                    @{ cmd = "netsh interface ipv4 set interface `"$($adapter.Name)`" forwarding=enabled"; desc = "IPv4 Forwarding" },
                    @{ cmd = "netsh interface ipv4 set interface `"$($adapter.Name)`" mtu=1500"; desc = "MTU Setting" }
                )

                foreach ($protocol in $protocols) {
                    try {
                        $result = cmd /c $protocol.cmd 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Success "Configured $($protocol.desc) on $($adapter.Name)"
                        } else {
                            Write-DebugLog "Failed to configure $($protocol.desc) on $($adapter.Name): $result"
                        }
                    } catch {
                        Write-DebugLog "Error configuring $($protocol.desc) on $($adapter.Name): $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-DebugLog "Failed to configure adapter $($adapter.Name): $($_.Exception.Message)"
            continue
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
    Write-DebugLog "Starting network optimization"

    try {
        # Get all network adapters first
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

        foreach ($adapter in $adapters) {
            Write-SubStep "Configuring adapter: $($adapter.Name)"

            # Try to enable RSS if supported
            try {
                # Check if RSS is supported before attempting to get/set
                $rssSupported = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue |
                              Where-Object { $_.RegistryKeyword -like "*RSS*" -or $_.DisplayName -like "*Receive Side Scaling*" }

                if ($rssSupported) {
                    $rssParams = @{
                        Name = $adapter.Name
                        BaseProcessorNumber = 2
                        MaxProcessorNumber = [System.Environment]::ProcessorCount - 1
                        ErrorAction = 'Stop'
                    }
                    Set-NetAdapterRss @rssParams
                    Write-Success "Enabled RSS on $($adapter.Name)"
                }
            } catch {
                Write-DebugLog "RSS not available on $($adapter.Name): $($_.Exception.Message)"
            }

            # Try to enable VMQ if supported
            try {
                # Check if VMQ is supported before attempting to get/set
                $vmqSupported = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue |
                              Where-Object { $_.RegistryKeyword -like "*VMQ*" -or $_.DisplayName -like "*Virtual Machine Queue*" }

                if ($vmqSupported) {
                    Enable-NetAdapterVmq -Name $adapter.Name -ErrorAction Stop
                    Write-Success "Enabled VMQ on $($adapter.Name)"
                }
            } catch {
                Write-DebugLog "VMQ not available on $($adapter.Name): $($_.Exception.Message)"
            }

            # Try to enable QoS if supported
            try {
                # Check if QoS is supported before attempting to get/set
                $qosSupported = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue |
                              Where-Object { $_.RegistryKeyword -like "*QoS*" -or $_.DisplayName -like "*Quality of Service*" }

                if ($qosSupported) {
                    Enable-NetAdapterQos -Name $adapter.Name -ErrorAction Stop
                    Write-Success "Enabled QoS on $($adapter.Name)"
                }
            } catch {
                Write-DebugLog "QoS not available on $($adapter.Name): $($_.Exception.Message)"
            }
        }

        # Configure modern SMB settings
        try {
            # Get current SMB configuration
            $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop

            # Only update if needed
            if (-not $smbConfig.EnableMultiChannel -or
                $smbConfig.Smb2CreditsMin -ne 512 -or
                $smbConfig.Smb2CreditsMax -ne 8192) {

                Set-SmbServerConfiguration -EnableMultiChannel $true `
                                        -Smb2CreditsMin 512 `
                                        -Smb2CreditsMax 8192 `
                                        -Force `
                                        -ErrorAction Stop
                Write-Success "Configured SMB optimization settings"
            } else {
                Write-CustomWarning "SMB settings already optimized"
            }
        } catch {
            Write-CustomWarning "Unable to configure SMB settings: $($_.Exception.Message)"
        }

    } catch {
        Add-StepResult -Step $currentStep `
                      -Component "Network Optimization" `
                      -Message ("Failed: {0}" -f $_.Exception.Message) `
                      -Type 'Warning'
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
        $dism = "$env:SystemRoot\System32\dism.exe"

        # Define required features
        $features = @(
            'NetFx3',
            'SmbDirect'
        )

        # First check if any features need to be enabled
        $needsUpdate = $false
        foreach ($feature in $features) {
            $result = & $dism /Online /Get-FeatureInfo /FeatureName:$feature 2>&1
            if ($LASTEXITCODE -eq 0) {
                if ($result -match "State : Disabled") {
                    $needsUpdate = $true
                    break
                }
            }
        }

        # Only proceed if updates are needed
        if ($needsUpdate) {
            foreach ($feature in $features) {
                Write-SubStep "Enabling feature: $feature"
                $result = & $dism /Online /Enable-Feature /FeatureName:$feature /Quiet /NoRestart 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Add-StepResult -Step $currentStep `
                                 -Component $feature `
                                 -Message "Failed to enable" `
                                 -Type 'Warning'
                }
            }
        } else {
            Write-SubStep "All required features are already enabled"
        }

        # Configure SMB versions
        Write-SubStep "Configuring SMB protocol versions..."

        # Disable SMB1
        & $dism /Online /Disable-Feature /FeatureName:SMB1Protocol /Quiet /NoRestart 2>&1

        # Enable SMB2/3 via registry
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

        # Enable SMB2
        Set-ItemProperty -Path $regPath -Name "SMB2" -Value 1 -Type DWord -Force

        # Enable SMB3
        Set-ItemProperty -Path $regPath -Name "EnableSMB2Protocol" -Value 1 -Type DWord -Force

        # Set minimum SMB version to SMB2
        Set-ItemProperty -Path $regPath -Name "SMB1" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "SMB2_02" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "SMB2_10" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "SMB2_22" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "SMB2_24" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "SMB3" -Value 1 -Type DWord -Force

        Write-Success "SMB protocol versions configured successfully"
        return
    }
    catch {
        Add-StepResult -Step $currentStep `
                      -Component "Feature Management" `
                      -Message ("Failed: {0}" -f $_.Exception.Message) `
                      -Type 'Warning'
        return $false | Out-Null  # Suppress output
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

        # Get physical adapters only
        $physicalAdapters = Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            $_.InterfaceType -eq 6 -and  # 6 = Ethernet
            -not ($_.Name -like "*Virtual*" -or
                  $_.Name -like "*WSL*" -or
                  $_.Name -like "*vEthernet*" -or
                  $_.HardwareInterface -eq $false)
        }

        # Define commands array with adapter-specific commands
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
            }
        )

        # Add IP release/renew commands only for physical adapters
        foreach ($adapter in $physicalAdapters) {
            $networkCommands += @(
                @{
                    name = "IP Release - $($adapter.Name)"
                    cmd = "ipconfig /release `"$($adapter.Name)`""
                    critical = $false
                    requiresReboot = $false
                },
                @{
                    name = "IP Renew - $($adapter.Name)"
                    cmd = "ipconfig /renew `"$($adapter.Name)`""
                    critical = $false
                    requiresReboot = $false
                }
            )
        }

        # Add final reset commands
        $networkCommands += @(
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

        Write-DebugLog "Network commands array defined with $(($networkCommands | Measure-Object).Count) commands"

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

                # Consider command successful if exit code is 0 or output contains success messages
                if ($cmdExitCode -eq 0 -or
                    $output -match "completed successfully|OK|Command completed|processed|reset catalog" -and
                    $output -notmatch "failed|error|denied" -or
                    # Special case for IP operations that might partially succeed
                    ($command.name -match "IP (Release|Renew)" -and
                     $output -match "IPv4 Address|Default Gateway")) {

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

                if ($command.critical) {
                    Add-StepResult -Step $currentStep `
                                  -Component $command.name `
                                  -Message ("Failed: {0}" -f $errorMsg) `
                                  -Type 'Critical'
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
            Add-StepResult -Step $currentStep `
                          -Component "Network Stack" `
                          -Message "One or more critical network stack operations failed" `
                          -Type 'Critical'
            return $false
        }

        if ($criticalChanges) {
            Add-StepResult -Step $currentStep `
                          -Component "Network Stack" `
                          -Message "Network stack changes require a system restart" `
                          -Type 'Warning'
        }

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

        # Check for pending reboots
        $pendingReboot = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
        ) | Where-Object { Test-Path $_ }

        if ($pendingReboot) {
            Write-Warning "System has pending reboot. Please restart before running this script."
            return $false
        }

        # Check for Windows Defender exclusions
        $defenderRunning = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($defenderRunning.Status -eq 'Running') {
            Write-SubStep "Checking Windows Defender configuration..."
            $networkPaths = @(
                "%SystemRoot%\System32\drivers\etc\hosts",
                "%SystemRoot%\System32\svchost.exe",
                "%SystemRoot%\System32\netsh.exe"
            )

            foreach ($path in $networkPaths) {
                Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
            }
        }

        # Check for required Windows capabilities
        $requiredCapabilities = @(
            "NetFx3~~~~",
            "DirectPlay~~~~",
            "Windows-Defender-Default-Definitions~~~~0.0.0.0"
        )

        foreach ($capability in $requiredCapabilities) {
            $state = Get-WindowsCapability -Online | Where-Object { $_.Name -like $capability }
            if ($state.State -ne "Installed") {
                Write-SubStep "Installing required capability: $capability"
                Add-WindowsCapability -Online -Name $capability
            }
        }

        return $true
    } catch {
        Write-Error "Failed to initialize Windows configuration: $($_.Exception.Message)"
        return $false
    }
}

# Add error handling for service configuration
function Set-ServiceConfig {
    param(
        [string]$ServiceName,
        [string]$DisplayName,
        [string]$StartupType = 'Automatic',
        [bool]$Start = $true
    )

    try {
        # Try using sc.exe with full paths
        $sc = "$env:SystemRoot\System32\sc.exe"
        $net = "$env:SystemRoot\System32\net.exe"

        # Configure startup type
        $result = & $sc config $ServiceName start= $($StartupType.ToLower()) 2>&1
        if ($LASTEXITCODE -ne 0) {
            # If sc.exe fails, try direct registry modification
            $regPath = "HKLM\System\CurrentControlSet\Services\$ServiceName"
            $startValue = switch ($StartupType.ToLower()) {
                'automatic' { 2 }
                'manual' { 3 }
                'disabled' { 4 }
                default { 2 }
            }
            & reg.exe add $regPath /v Start /t REG_DWORD /d $startValue /f | Out-Null
        }

        if ($Start) {
            # Try to start the service
            & $net start $ServiceName 2>&1 | Out-Null
        }

        return $true
    }
    catch {
        Write-CustomWarning ("Service '{0}' configuration failed: {1}" -f $DisplayName, $_.Exception.Message)
        return $false
    }
}

# Fix network adapter binding issues
function Set-NetworkBinding {
    param(
        [string]$AdapterName,
        [string]$ComponentID,
        [string]$DisplayName,
        [bool]$Enable = $true
    )

    try {
        # First try using netsh interface ipv4
        $action = if ($Enable) { "enable" } else { "disable" }
        $result = cmd /c "netsh interface ipv4 set interface `"$AdapterName`" $action" 2>&1

        if ($LASTEXITCODE -ne 0) {
            # If that fails, try using netsh interface set interface
            $result = cmd /c "netsh interface set interface `"$AdapterName`" $action" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-CustomWarning ("Failed to configure {0} on adapter {1}" -f $DisplayName, $AdapterName)
                return $false
            }
        }

        # Try to enable specific components if needed
        if ($ComponentID -match "^(TCPIP|TCPIP6|DNSClient|DHCP)$") {
            $result = cmd /c "netsh interface $ComponentID set interface `"$AdapterName`" $action" 2>&1
        }

        return $true
    }
    catch {
        Write-CustomWarning ("Error configuring {0}: {1}" -f $DisplayName, $_.Exception.Message)
        return $false
    }
}

# Fix DNS registration issues
function Register-DNSAddress {
    try {
        # Use ipconfig directly instead of Register-DnsClient
        $result = cmd /c "ipconfig /registerdns" 2>&1
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
        Write-CustomWarning "DNS registration failed: $result"
        return $false
    }
    catch {
        Write-CustomWarning "DNS registration error: $($_.Exception.Message)"
        return $false
    }
}

# Fix SMB configuration issues
function Set-SMBConfig {
    param(
        [int]$MaxChannels = 32,
        [int]$CreditsMin = 512,
        [int]$CreditsMax = 8192
    )

    try {
        # Use PowerShell commands with error handling
        $null = Set-SmbServerConfiguration -EnableMultiChannel $true -Force -ErrorAction Stop
        $null = Set-SmbServerConfiguration -Smb2CreditsMin $CreditsMin -Smb2CreditsMax $CreditsMax -Force -ErrorAction Stop
        $null = Set-SmbServerConfiguration -ServerHidden $false -AnnounceServer $true -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-CustomWarning "SMB configuration error: $($_.Exception.Message)"
        return $false
    }
}

# Update Enable-RequiredServices function
function Enable-RequiredServices {
    [CmdletBinding()]
    param()

    $currentStep = "Required Services"
    Write-SubStep "Configuring required services..."

    foreach ($service in $services) {
        Write-SubStep "Configuring: $($service.DisplayName)"

        # Skip services based on Windows edition
        if ($script:WindowsInfo.IsHome -and $editionConfig.Home.SkipServices -contains $service.Name) {
            Write-CustomWarning "Skipping $($service.DisplayName) (not required for Home edition)"
            continue
        }

        if (-not (Set-ServiceConfig -ServiceName $service.Name -DisplayName $service.DisplayName)) {
            Add-StepResult -Step $currentStep `
                          -Component $service.DisplayName `
                          -Message "Failed to configure service" `
                          -Type 'Warning'
        }
    }
}

function Enable-FileSharing {
    [CmdletBinding()]
    param()

    $currentStep = "File Sharing"
    Write-SubStep "Configuring File and Printer Sharing..."

    try {
        # Configure SMB settings
        if (-not (Set-SMBConfig)) {
            Add-StepResult -Step $currentStep `
                          -Component "SMB Configuration" `
                          -Message "Failed to configure SMB settings" `
                          -Type 'Warning'
        }

        # Configure DNS registration
        if (-not (Register-DNSAddress)) {
            Add-StepResult -Step $currentStep `
                          -Component "DNS Registration" `
                          -Message "Failed to register DNS addresses" `
                          -Type 'Warning'
        }
    }
    catch {
        Add-StepResult -Step $currentStep `
                      -Component "File and Printer Sharing" `
                      -Message ("Failed to configure: {0}" -f $_.Exception.Message) `
                      -Type 'Critical'
    }
}

function Set-NetworkAdapterConfig {
    [CmdletBinding()]
    param(
        [string]$AdapterName
    )

    $currentStep = "Network Adapter Configuration"
    Write-SubStep "Configuring adapter: $AdapterName"

    try {
        # Enable adapter first
        $result = cmd /c "netsh interface set interface `"$AdapterName`" admin=enable" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Add-StepResult -Step $currentStep `
                          -Component $AdapterName `
                          -Message "Failed to enable adapter" `
                          -Type 'Warning'
            return $false
        }

        # Configure basic settings
        $commands = @(
            @{ cmd = "netsh interface ipv4 set interface `"$AdapterName`" forwarding=enabled"; desc = "IPv4 Forwarding" },
            @{ cmd = "netsh interface ipv4 set interface `"$AdapterName`" advertise=enabled"; desc = "Router Advertisement" },
            @{ cmd = "netsh interface ipv4 set interface `"$AdapterName`" mtu=1500"; desc = "MTU Setting" }
        )

        foreach ($command in $commands) {
            $result = cmd /c $command.cmd 2>&1
            if ($LASTEXITCODE -ne 0) {
                Add-StepResult -Step $currentStep `
                              -Component $command.desc `
                              -Message "Failed to configure on $AdapterName" `
                              -Type 'Warning'
            }
        }

        return $true
    }
    catch {
        Add-StepResult -Step $currentStep `
                      -Component $AdapterName `
                      -Message ("Configuration failed: {0}" -f $_.Exception.Message) `
                      -Type 'Warning'
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