using Lantern.App.ViewModels;

namespace Lantern.App.Services;

/// <summary>
/// Builds a PowerShell script that controls one device through LANtern's local
/// automation pipe without activating or navigating the application window.
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
            # LANtern Control — per-device background PowerShell automation
            # Target device: {{displayName}}
            # LANtern must remain running; its window may be minimized.
            # This script talks to LANtern through a current-user-only local named pipe.
            # It does not use Windows UI Automation, activate the window, navigate pages, or scroll the device list.

            $ErrorActionPreference = 'Stop'
            $script:LanternPipeName = '{{DeviceAutomationPipeServer.PipeName}}'

            function Set-LanternPaused {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory)]
                    [string]$AutomationId,
                    [Parameter(Mandatory)]
                    [bool]$Paused
                )

                $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
                    '.',
                    $script:LanternPipeName,
                    [System.IO.Pipes.PipeDirection]::InOut
                )
                $encoding = [System.Text.UTF8Encoding]::new($false)
                $writer = $null
                $reader = $null

                try {
                    $pipe.Connect(3000)
                    $writer = [System.IO.StreamWriter]::new($pipe, $encoding, 1024, $true)
                    $writer.AutoFlush = $true
                    $reader = [System.IO.StreamReader]::new($pipe, $encoding, $false, 1024, $true)

                    $request = [ordered]@{
                        protocolVersion = 1
                        command = 'SetPaused'
                        automationId = $AutomationId
                        paused = $Paused
                    }
                    $writer.WriteLine(($request | ConvertTo-Json -Compress))
                    $responseJson = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($responseJson)) {
                        throw 'LANtern closed the automation connection without returning a result.'
                    }

                    $response = ConvertFrom-Json -InputObject $responseJson
                    if (-not $response.success) {
                        throw "LANtern could not update the device: $($response.error)"
                    }

                    return $response
                }
                finally {
                    if ($null -ne $reader) { $reader.Dispose() }
                    if ($null -ne $writer) { $writer.Dispose() }
                    $pipe.Dispose()
                }
            }

            $PauseAutomationId = '{{device.PauseAutomationId}}'

            # Examples — uncomment the action you want to run.
            # Pause internet:
            # Set-LanternPaused -AutomationId $PauseAutomationId -Paused $true
            # Resume internet:
            # Set-LanternPaused -AutomationId $PauseAutomationId -Paused $false
            """;
    }
}
