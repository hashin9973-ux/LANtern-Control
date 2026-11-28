namespace Lantern.App.Services;

public static class NetworkKeywordPausePolicy
{
    public static IReadOnlyList<string> FindMatches(
        bool controlEnabled,
        IEnumerable<string>? visibleSsids,
        string keyword)
    {
        if (!controlEnabled ||
            visibleSsids is null ||
            string.IsNullOrWhiteSpace(keyword))
        {
            return Array.Empty<string>();
        }

        var normalizedKeyword = keyword.Trim();
        return visibleSsids
            .Where(ssid =>
                !string.IsNullOrWhiteSpace(ssid) &&
                ssid.Contains(normalizedKeyword, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static bool ShouldPause(
        bool controlEnabled,
        IEnumerable<string>? visibleSsids,
        string keyword) =>
        FindMatches(controlEnabled, visibleSsids, keyword).Count > 0;
}
