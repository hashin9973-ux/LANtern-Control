using System.Diagnostics;
using System.IO;
using System.Text;

namespace Lantern.App.Services;

public sealed class PowerShellScriptRunner
{
    public static readonly TimeSpan MaximumRunTime = TimeSpan.FromMinutes(2);
    private const int MaximumCapturedCharacters = 16_000;

    public async Task<ScriptRunResult> RunAsync(
        string scriptPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scriptPath);

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Scheduled PowerShell scripts are available only in the Windows app.");
        }

        var fullPath = Path.GetFullPath(scriptPath.Trim());
        if (!string.Equals(Path.GetExtension(fullPath), ".ps1", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Select a PowerShell .ps1 script.", nameof(scriptPath));
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("The selected PowerShell script was not found.", fullPath);
        }

        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var powerShellPath = Path.Combine(
            systemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        if (!File.Exists(powerShellPath))
        {
            throw new FileNotFoundException(
                "Windows PowerShell could not be found on this computer.",
                powerShellPath);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = powerShellPath,
            WorkingDirectory = Path.GetDirectoryName(fullPath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(fullPath);

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException("Windows PowerShell could not be started.");
        }

        var standardOutputTask = ReadBoundedAsync(process.StandardOutput);
        var standardErrorTask = ReadBoundedAsync(process.StandardError);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(MaximumRunTime);

        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await StopProcessTreeAsync(process).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            timedOut = true;
        }

        var standardOutput = await standardOutputTask.ConfigureAwait(false);
        var standardError = await standardErrorTask.ConfigureAwait(false);
        return new ScriptRunResult(
            process.ExitCode,
            timedOut,
            standardOutput,
            standardError);
    }

    private static async Task StopProcessTreeAsync(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
            // The process already exited between the state check and Kill.
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Preserve the original cancellation or timeout result.
        }

        try
        {
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            // The process is no longer associated with a running process handle.
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader)
    {
        var captured = new StringBuilder(MaximumCapturedCharacters);
        var buffer = new char[1024];
        var truncated = false;
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            var remaining = MaximumCapturedCharacters - captured.Length;
            var retained = Math.Min(remaining, count);
            if (retained > 0)
            {
                captured.Append(buffer, 0, retained);
            }

            truncated |= retained < count;
        }

        if (truncated)
        {
            captured.AppendLine();
            captured.Append("[remaining output omitted]");
        }

        return captured.ToString();
    }
}

public sealed record ScriptRunResult(
    int ExitCode,
    bool TimedOut,
    string StandardOutput,
    string StandardError)
{
    public bool Succeeded => !TimedOut && ExitCode == 0;
}
