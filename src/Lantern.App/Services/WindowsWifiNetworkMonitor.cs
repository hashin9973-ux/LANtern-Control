using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace Lantern.App.Services;

/// <summary>
/// Scans the Wi-Fi networks currently visible to the Windows wireless adapter.
/// SSID extraction follows the same numbered-SSID output produced by
/// "netsh wlan show networks mode=bssid".
/// </summary>
public sealed class WindowsWifiNetworkMonitor
{
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(15);

    private static readonly Regex VisibleSsidPattern = new(
        @"(?im)^[ \\t]*SSID[ \\t]+\\d+[ \\t]*:[ \\t]*([^\\r\\n]*)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex NoVisibleNetworksPattern = new(
        @"(?i)\b(?:0|no)\s+networks?\s+currently\s+visible\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public async Task<IReadOnlyList<string>> GetVisibleSsidsAsync(
        CancellationToken cancellationToken = default)
    {
        var output = await GetNetworkScanOutputAsync(cancellationToken).ConfigureAwait(false);
        return ParseVisibleSsids(output);
    }

    public static IReadOnlyList<string> ParseVisibleSsids(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        var ssids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in VisibleSsidPattern.Matches(output))
        {
            var ssid = match.Groups[1].Value.Trim();
            if (!string.IsNullOrWhiteSpace(ssid))
            {
                ssids.Add(ssid);
            }
        }

        if (ssids.Count == 0 && !NoVisibleNetworksPattern.IsMatch(output))
        {
            throw new InvalidDataException(
                "Wi-Fi scan returned no recognizable SSIDs. The scan output was not treated as an empty network list.");
        }

        return ssids
            .OrderBy(ssid => ssid, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static async Task<string> GetNetworkScanOutputAsync(
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add("wlan");
        startInfo.ArgumentList.Add("show");
        startInfo.ArgumentList.Add("networks");
        startInfo.ArgumentList.Add("mode=bssid");

        using var process = new Process { StartInfo = startInfo };
        var started = false;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!process.Start())
            {
                throw new IOException("Windows could not start the Wi-Fi network scan.");
            }

            started = true;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ScanTimeout);

            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);

            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                var output = await outputTask.ConfigureAwait(false);
                var error = await errorTask.ConfigureAwait(false);

                if (process.ExitCode != 0)
                {
                    var details = string.IsNullOrWhiteSpace(error) ? output : error;
                    throw new IOException(
                        $"Wi-Fi scan failed with exit code {process.ExitCode}. {details.Trim()}");
                }

                return output;
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                try
                {
                    await Task.WhenAll(outputTask, errorTask).ConfigureAwait(false);
                }
                catch (Exception exception) when (
                    exception is OperationCanceledException or IOException or ObjectDisposedException)
                {
                    // The redirected streams may be cancelled while the process is being stopped.
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }

                throw new TimeoutException(
                    $"The Windows Wi-Fi scan did not finish within {ScanTimeout.TotalSeconds:0} seconds.");
            }
        }
        catch (Win32Exception exception)
        {
            throw new IOException("Could not start netsh to scan visible Wi-Fi networks.", exception);
        }
        finally
        {
            if (started)
            {
                TryKill(process);
            }
        }
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
            // The process may have exited between the check and the kill.
        }
    }
}
