namespace Lantern.Core.Settings;

public sealed class NetworkKeywordAutomation
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string DeviceMacAddress { get; set; } = string.Empty;
    public string NetworkKeyword { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public bool HasCapturedPauseState { get; set; }
    public bool OriginalPauseInternet { get; set; }
}
