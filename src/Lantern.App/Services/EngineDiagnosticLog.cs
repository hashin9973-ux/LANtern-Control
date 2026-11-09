using System.IO;
using System.Text.Json;

namespace Lantern.App.Services;

/// <summary>
/// Writes low-volume, JSON-lines diagnostics for lifecycle transitions and
/// enforcement-health faults. Logging failures must never interfere with the
/// packet engine or its safe network-restoration path.
/// </summary>
public sealed class EngineDiagnosticLog
{
    private static readonly object FileLock = new();
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly string logPath;

    public EngineDiagnosticLog(string? logPath = null)
    {
        this.logPath = logPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LANternControl",
            "logs",
            "engine-diagnostics.jsonl");
    }

    public void Write(
        string eventName,
        string component,
        string? adapter,
        string state,
        string? reason = null,
        Exception? exception = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);
        ArgumentException.ThrowIfNullOrWhiteSpace(component);
        ArgumentException.ThrowIfNullOrWhiteSpace(state);

        try
        {
            var entry = new DiagnosticEntry(
                DateTimeOffset.UtcNow,
                eventName,
                component,
                adapter,
                state,
                reason,
                exception?.GetType().FullName,
                exception?.Message,
                exception?.ToString());

            var json = JsonSerializer.Serialize(entry, SerializerOptions);
            var directory = Path.GetDirectoryName(logPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            lock (FileLock)
            {
                File.AppendAllText(logPath, json + Environment.NewLine);
            }
        }
        catch
        {
            // Diagnostics must never take down packet forwarding or restoration.
        }
    }

    private sealed record DiagnosticEntry(
        DateTimeOffset TimestampUtc,
        string Event,
        string Component,
        string? Adapter,
        string State,
        string? Reason,
        string? ExceptionType,
        string? ExceptionMessage,
        string? ExceptionDetails);
}
