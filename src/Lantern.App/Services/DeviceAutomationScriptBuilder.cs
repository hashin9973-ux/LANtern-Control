using Lantern.App.ViewModels;

namespace Lantern.App.Services;

/// <summary>
/// Builds a ready-to-edit PowerShell UI Automation script for one device row.
/// </summary>
public static class DeviceAutomationScriptBuilder
{
    public static string Build(DeviceViewModel device)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (!device.CanControl)
        {
            throw new InvalidOperationException("Only controllable devices can have automation scripts.");
        }

        var displayName = device.DisplayName
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);

        return $$"""
            # LANtern Control — per-device PowerShell UI Automation
            # Target device: {{displayName}}
            # Paste this into the Script automation editor, then edit the example commands below.
            # The examples are commented out so running this template unchanged makes no changes.

            $ErrorActionPreference = 'Stop'

            Add-Type -AssemblyName UIAutomationClient
            Add-Type -AssemblyName UIAutomationTypes

            $LanternProcess = Get-Process -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.MainWindowTitle -eq 'LANtern Control' -and
                    $_.MainWindowHandle -ne [IntPtr]::Zero
                } |
                Select-Object -First 1

            if ($null -eq $LanternProcess) {
                throw 'LANtern Control is not running in this Windows session.'
            }

            $script:LanternWindow = [System.Windows.Automation.AutomationElement]::FromHandle(
                $LanternProcess.MainWindowHandle
            )
            if ($null -eq $script:LanternWindow) {
                throw 'Could not connect to the LANtern Control window.'
            }

            function Get-LanternElement {
                param(
                    [Parameter(Mandatory)]
                    [string]$AutomationId
                )

                $condition = [System.Windows.Automation.PropertyCondition]::new(
                    [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
                    $AutomationId
                )
                $element = $script:LanternWindow.FindFirst(
                    [System.Windows.Automation.TreeScope]::Descendants,
                    $condition
                )
                if ($null -eq $element) {
                    throw "Could not find '$AutomationId'. Make sure this device row is visible in LANtern's device list."
                }

                return $element
            }

            function Set-LanternText {
                param(
                    [Parameter(Mandatory)]
                    [string]$AutomationId,
                    [Parameter(Mandatory)]
                    [AllowEmptyString()]
                    [string]$Value
                )

                $control = Get-LanternElement -AutomationId $AutomationId
                if (-not $control.Current.IsEnabled) {
                    throw "Control '$AutomationId' is disabled. Only controllable device rows can be edited."
                }

                $pattern = $control.GetCurrentPattern(
                    [System.Windows.Automation.ValuePattern]::Pattern
                )
                if ($pattern.Current.IsReadOnly) {
                    throw "Control '$AutomationId' is read-only."
                }

                $pattern.SetValue($Value)
                # LANtern debounces TextBox-to-view-model updates by 350 ms.
                Start-Sleep -Milliseconds 600
            }

            function Set-LanternPaused {
                param(
                    [Parameter(Mandatory)]
                    [string]$AutomationId,
                    [Parameter(Mandatory)]
                    [bool]$Paused
                )

                $control = Get-LanternElement -AutomationId $AutomationId
                if (-not $control.Current.IsEnabled) {
                    throw "Control '$AutomationId' is disabled. Only controllable device rows can be edited."
                }

                $pattern = $control.GetCurrentPattern(
                    [System.Windows.Automation.TogglePattern]::Pattern
                )
                $desiredState = [System.Windows.Automation.ToggleState]::Off
                if ($Paused) {
                    $desiredState = [System.Windows.Automation.ToggleState]::On
                }

                # Toggle only when the current state differs from the requested state.
                if ($pattern.Current.ToggleState -ne $desiredState) {
                    $pattern.Toggle()
                }
            }

            $DeviceRowAutomationId = '{{device.RowAutomationId}}'
            $DeviceNameAutomationId = '{{device.NameAutomationId}}'
            $DownloadLimitAutomationId = '{{device.DownloadLimitAutomationId}}'
            $UploadLimitAutomationId = '{{device.UploadLimitAutomationId}}'
            $PauseAutomationId = '{{device.PauseAutomationId}}'

            # Resolve the row first. If it cannot be found, scroll it into view in LANtern and retry.
            $null = Get-LanternElement -AutomationId $DeviceRowAutomationId

            # Examples — uncomment and edit only the actions you intend to run.
            # Rename this device:
            # Set-LanternText -AutomationId $DeviceNameAutomationId -Value 'Living room TV'
            # Set download limit in KB/s (0 = unlimited):
            # Set-LanternText -AutomationId $DownloadLimitAutomationId -Value '500'
            # Set upload limit in KB/s (0 = unlimited):
            # Set-LanternText -AutomationId $UploadLimitAutomationId -Value '250'
            # Pause or resume internet: $true pauses, $false resumes.
            # Set-LanternPaused -AutomationId $PauseAutomationId -Paused $true
            """;
    }
}
