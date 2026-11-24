using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Lantern.App.ViewModels;

public sealed class NetworkKeywordAutomationViewModel(
    string id,
    string deviceMacAddress,
    string deviceName,
    string networkKeyword,
    bool isEnabled) : INotifyPropertyChanged
{
    private string deviceName = deviceName;
    private bool isEnabled = isEnabled;
    private string evaluationStatus = "Waiting for control";
    public event PropertyChangedEventHandler? PropertyChanged;
    public string Id { get; } = id;
    public string DeviceMacAddress { get; } = deviceMacAddress;
    public string NetworkKeyword { get; } = networkKeyword;

    public string DeviceName
    {
        get => deviceName;
        private set => SetField(ref deviceName, value);
    }

    public bool IsEnabled
    {
        get => isEnabled;
        set
        {
            if (SetField(ref isEnabled, value))
                OnPropertyChanged(nameof(StatusText));
        }
    }

    public string StatusText => IsEnabled ? "Enabled" : "Disabled";

    public string EvaluationStatus
    {
        get => evaluationStatus;
        private set => SetField(ref evaluationStatus, value);
    }

    public void UpdateDeviceName(string value) => DeviceName = value;
    public void UpdateEvaluationStatus(string value) => EvaluationStatus = value;

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
