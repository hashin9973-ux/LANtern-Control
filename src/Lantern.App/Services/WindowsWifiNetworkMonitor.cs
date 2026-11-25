using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace Lantern.App.Services;

/// <summary>
/// Scans the Wi-Fi networks currently visible to the Windows wireless adapter.
/// SSID extraction follows the numbered entries produced by
/// "netsh wlan show networks mode=bssid".
/// </summary>
public sealed class WindowsWifiNetworkMonitor
{
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(15);

    public async Task<IReadOnlyList<string>> GetVisibleSsidsAsync(
        CancellationToken cancellationToken = default)
    {
        var output = await GetNetworkScanOutputAsync(cancellationToken).ConfigureAwait(false);
        return ParseVisibleSsids(output);
    }

    public static IReadOnlyList<string> ParseVisibleSsids(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        var seenSsids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ssids = new List<string>();

        // Parse each line separately. In particular, whitespace after an empty
        // "SSID n :" entry must not consume the next line's SSID label.
        foreach (var line in output.Split(['\\r', '\\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmedLine = line.TrimStart();
            var separator = trimmedLine.IndexOf(':');
            if (separator < 0)
            {
                continue;
            }

            var label = trimmedLine[..separator].Trim();
            if (!label.StartsWith("SSID", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var numberText = label["SSID".Length..].Trim();
            if (numberText.Length == 0 || !numberText.All(char.IsDigit))
            {
                continue;
            }

            var ssid = trimmedLine[(separator + 1)..].Trim();
            if (!string.IsNullOrWhiteSpace(ssid) && seenSsids.Add(ssid))
            {
                ssids.Add(ssid);
            }
        }

        if (ssids.Count == 0 && !ReportsNoVisibleNetworks(output))
        {
            throw new InvalidDataException(
                "Wi-Fi scan returned no recognizable SSIDs. The scan output was not treated as an empty network list.");
        }

        return ssids
            .OrderBy(ssid => ssid, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool ReportsNoVisibleNetworks(string output) =>
        output.Contains("0 networks currently visible", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("no networks currently visible", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("no network currently visible", StringComparison.OrdinalIgnoreCase);

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
