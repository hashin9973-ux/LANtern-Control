namespace Lantern.App.Services;

public static class NetworkKeywordPausePolicy
{
    public static bool ShouldPause(bool controlEnabled, string? connectedSsid, string keyword)
    {
        if (!controlEnabled || string.IsNullOrWhiteSpace(connectedSsid) ||
            string.IsNullOrWhiteSpace(keyword))
        {
            return false;
        }

        return connectedSsid.Contains(keyword.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
