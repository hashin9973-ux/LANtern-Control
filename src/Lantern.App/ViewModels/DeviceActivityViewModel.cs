using System.ComponentModel;
using System.Runtime.CompilerServices;
using Lantern.Core.Networking;

namespace Lantern.App.ViewModels;

public sealed class DeviceActivityViewModel : INotifyPropertyChanged
{
    private readonly HashSet<DomainObservationSource> sources = [];
    private string deviceName;
    private string ipAddress;
    private DateTimeOffset lastSeen;
    private int hitCount;
    private bool isBlocked;

    public DeviceActivityViewModel(
        string macKey,
        string deviceName,
        string ipAddress,
        string domain,
        DomainObservationSource source,
        DateTimeOffset observedAt,
        IEnumerable<DomainObservationSource>? additionalSources = null,
        int observationCount = 1)
    {
        MacKey = macKey;
        this.deviceName = deviceName;
        this.ipAddress = ipAddress;
        Domain = domain;
        sources.Add(source);
        if (additionalSources is not null) sources.UnionWith(additionalSources);
        lastSeen = observedAt;
        hitCount = Math.Max(1, observationCount);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string MacKey { get; }

    public string DeviceName
    {
        get => deviceName;
        private set => SetField(ref deviceName, value);
    }

    public string IpAddress
    {
        get => ipAddress;
        private set => SetField(ref ipAddress, value);
    }

    public string Domain { get; }

    public string SourceLabel => string.Join(
        " + ",
        sources.OrderBy(source => source).Select(source => source.ToString().ToUpperInvariant()));

    public DateTimeOffset LastSeen
    {
        get => lastSeen;
        private set
        {
            if (SetField(ref lastSeen, value))
            {
                OnPropertyChanged(nameof(LastSeenText));
            }
        }
    }

    public string LastSeenText => LastSeen.ToLocalTime().ToString("HH:mm:ss");

    public int HitCount
    {
        get => hitCount;
        private set => SetField(ref hitCount, value);
    }

    public bool IsBlocked
    {
        get => isBlocked;
        private set
        {
            if (SetField(ref isBlocked, value))
            {
                OnPropertyChanged(nameof(CanBlock));
                OnPropertyChanged(nameof(BlockActionText));
            }
        }
    }

    public bool CanBlock => !IsBlocked;

    public string BlockActionText => IsBlocked ? "Blocked" : "Block";

    public void SetBlocked(bool blocked)
    {
        IsBlocked = blocked;
    }

    public void Observe(
        string latestDeviceName,
        string latestIpAddress,
        DomainObservationSource source,
        DateTimeOffset observedAt,
        IEnumerable<DomainObservationSource>? additionalSources = null,
        int observationCount = 1)
    {
        DeviceName = latestDeviceName;
        IpAddress = latestIpAddress;
        var sourcesChanged = sources.Add(source);
        if (additionalSources is not null)
        {
            foreach (var additionalSource in additionalSources)
                sourcesChanged |= sources.Add(additionalSource);
        }

        if (sourcesChanged) OnPropertyChanged(nameof(SourceLabel));
        LastSeen = observedAt;
        HitCount += Math.Max(1, observationCount);
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
