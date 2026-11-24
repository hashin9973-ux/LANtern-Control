using System.ComponentModel;
using System.Diagnostics;

namespace Lantern.App.Services;

/// <summary>Reads the SSID of the currently connected Windows WLAN interface.</summary>
public sealed class WindowsWifiNetworkMonitor
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(4);

    public async Task<string?> GetCurrentSsidAsync(CancellationToken cancellationToken = default)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };
        process.StartInfo.ArgumentList.Add("wlan");
        process.StartInfo.ArgumentList.Add("show");
        process.StartInfo.ArgumentList.Add("interfaces");

        var started = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!process.Start()) return null;
            started = true;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(CommandTimeout);
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                var output = await outputTask.ConfigureAwait(false);
                _ = await errorTask.ConfigureAwait(false);
                return process.ExitCode == 0 ? ParseConnectedSsid(output) : null;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                TryKill(process);
                return null;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
        finally
        {
            if (started) TryKill(process);
        }
    }

    public static string? ParseConnectedSsid(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var connected = false;
        foreach (var line in output.Split(['\\r', '\\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (key.Equals("Name", StringComparison.OrdinalIgnoreCase))
                connected = false;
            else if (key.Equals("State", StringComparison.OrdinalIgnoreCase))
                connected = value.Equals("connected", StringComparison.OrdinalIgnoreCase);
            else if (connected &&
                     key.Equals("SSID", StringComparison.OrdinalIgnoreCase) &&
                     !string.IsNullOrWhiteSpace(value))
                return value;
        }

        return null;
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception)
        {
        }
    }
}
