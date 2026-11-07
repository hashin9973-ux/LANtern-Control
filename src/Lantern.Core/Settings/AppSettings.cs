namespace Lantern.Core.Settings;

public sealed class AppSettings
{
    public bool DisableUpdateChecks { get; set; }

    public DateTimeOffset? LastUpdateCheckUtc { get; set; }

    public bool AutoScanEnabled { get; set; }

    public int AutoScanIntervalSeconds { get; set; } = 60;

    public bool ScriptAutomationEnabled { get; set; }

    public int ScriptAutomationIntervalSeconds { get; set; } = 60;

    public string? ScriptAutomationPath { get; set; }

    public Dictionary<string, DevicePreferences> Devices { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> BlockedDomains { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> AppliedDomainPresets { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
}

public sealed class DevicePreferences
{
    public string? Alias { get; set; }

    public string? LearnedHostName { get; set; }

    public int DownloadKiloBytesPerSecond { get; set; }

    public int UploadKiloBytesPerSecond { get; set; }

    public bool PauseInternet { get; set; }

    public string? LastKnownIp { get; set; }

    public DateTimeOffset? LastSeenUtc { get; set; }
}
