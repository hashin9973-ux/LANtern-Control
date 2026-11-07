using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Lantern.App.Controls;
using Lantern.App.Services;
using Lantern.App.ViewModels;
using Lantern.Core.Control;
using Lantern.Core.Devices;
using Lantern.Core.Networking;
using Lantern.Core.Settings;

namespace Lantern.App;

public partial class MainWindow : Window
{
    private const int MaxWebsiteActivityRows = 250;
    private const int MinimumAutoScanIntervalSeconds = 60;
    private const int MaximumAutoScanIntervalSeconds = 3600;
    private const int MinimumScriptIntervalSeconds = 60;
    private const int MaximumScriptIntervalSeconds = 3600;
    private static readonly HttpClient UpdateHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(5),
    };
    private readonly DeviceRegistry registry = new();
    private readonly TrafficPolicy policy = new();
    private readonly SettingsStore settingsStore = new();
    private readonly SemaphoreSlim identitySaveSync = new(1, 1);
    private readonly DispatcherTimer refreshTimer;
    private readonly DispatcherTimer autoScanTimer;
    private readonly DispatcherTimer scriptAutomationTimer;
    private readonly PowerShellScriptRunner scriptRunner = new();
    private readonly CancellationTokenSource scriptRunCancellation = new();
    private Task? activeScriptRunTask;
    private bool scriptRunInProgress;
    private readonly Dictionary<string, DeviceViewModel> deviceIndex =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DeviceActivityViewModel> websiteActivityIndex =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DeviceActivityGroupViewModel> websiteActivityGroupIndex =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly TrafficHistory trafficHistory = new(TrafficSamplingProfile.Capacity, TrafficSamplingProfile.Retention);
    private readonly GitHubUpdateChecker updateChecker = new(UpdateHttpClient);
    private readonly LocalHostDiscoveryService localHostDiscoveryService = new();
    private PcapLanEngine engine;
    private AppSettings settings = new();
    private DateTimeOffset? controlStartedAt;
    private bool operationInProgress;
    private bool closeAfterStop;
    private bool settingsDirty;

    public string VersionText =>
        $"v{(typeof(MainWindow).Assembly.GetName().Version ?? new Version()).ToString(3)}";

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        SidebarVersionText.Text = VersionText;
        DomainPresetSelector.ItemsSource = DomainPresets;
        engine = new PcapLanEngine(registry, policy);
        engine.StatusChanged += Engine_OnStatusChanged;
        engine.StateChanged += Engine_OnStateChanged;
        engine.DeviceIdentityLearned += Engine_OnDeviceIdentityLearned;
        engine.DeviceDomainObserved += Engine_OnDeviceDomainObserved;
        engine.IdentityAlertDetected += Engine_OnIdentityAlertDetected;
        refreshTimer = new DispatcherTimer(
            TrafficSamplingProfile.Interval,
            DispatcherPriority.Background,
            RefreshDevices,
            Dispatcher);
        autoScanTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(MinimumAutoScanIntervalSeconds),
        };
        autoScanTimer.Tick += AutoScanTimer_OnTick;
        scriptAutomationTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(MinimumScriptIntervalSeconds),
        };
        scriptAutomationTimer.Tick += ScriptAutomationTimer_OnTick;
        Loaded += MainWindow_OnLoaded;
        Closing += MainWindow_OnClosing;

        var view = CollectionViewSource.GetDefaultView(Devices);
        view.SortDescriptions.Add(
            new SortDescription(nameof(DeviceViewModel.IsProtected), ListSortDirection.Ascending));
        view.SortDescriptions.Add(
            new SortDescription(nameof(DeviceViewModel.DisplayName), ListSortDirection.Ascending));

        var activityView = CollectionViewSource.GetDefaultView(WebsiteActivity);
        activityView.SortDescriptions.Add(
            new SortDescription(nameof(DeviceActivityViewModel.LastSeen), ListSortDirection.Descending));

        var groupView = CollectionViewSource.GetDefaultView(DeviceActivityGroups);
        groupView.SortDescriptions.Add(
            new SortDescription(nameof(DeviceActivityGroupViewModel.DeviceName), ListSortDirection.Ascending));

        var domainRuleView = CollectionViewSource.GetDefaultView(DomainRules);
        domainRuleView.SortDescriptions.Add(
            new SortDescription(nameof(DomainRuleViewModel.DeviceName), ListSortDirection.Ascending));
        domainRuleView.SortDescriptions.Add(
            new SortDescription(nameof(DomainRuleViewModel.Domain), ListSortDirection.Ascending));

        var domainPresetRuleView = CollectionViewSource.GetDefaultView(DomainPresetRules);
        domainPresetRuleView.SortDescriptions.Add(
            new SortDescription(nameof(DomainPresetRuleViewModel.DeviceName), ListSortDirection.Ascending));
        domainPresetRuleView.SortDescriptions.Add(
            new SortDescription(nameof(DomainPresetRuleViewModel.PresetName), ListSortDirection.Ascending));
    }

    public ObservableCollection<DeviceViewModel> Devices { get; } = [];

    public ObservableCollection<DeviceActivityViewModel> WebsiteActivity { get; } = [];

    public ObservableCollection<DeviceActivityGroupViewModel> DeviceActivityGroups { get; } = [];

    public ObservableCollection<DeviceViewModel> DomainRuleDevices { get; } = [];

    public ObservableCollection<DomainRuleViewModel> DomainRules { get; } = [];

    public ObservableCollection<DomainPresetRuleViewModel> DomainPresetRules { get; } = [];

    public IReadOnlyList<DomainBlockPreset> DomainPresets => DomainBlockPresetCatalog.All;

    private async void MainWindow_OnLoaded(object sender, RoutedEventArgs eventArgs)
    {
        settings = await settingsStore.LoadAsync();
        if (settings.AutoScanIntervalSeconds is < MinimumAutoScanIntervalSeconds or > MaximumAutoScanIntervalSeconds)
        {
            settings.AutoScanIntervalSeconds = MinimumAutoScanIntervalSeconds;
        }

        AutoScanIntervalTextBox.Text = settings.AutoScanIntervalSeconds.ToString();
        AutoScanCheckBox.IsChecked = settings.AutoScanEnabled;
        ConfigureAutoScanTimer();
        ScriptPathTextBox.Text = settings.ScriptAutomationPath ?? string.Empty;
        ScriptAutomationIntervalTextBox.Text = settings.ScriptAutomationIntervalSeconds.ToString();
        ScriptAutomationCheckBox.IsChecked = settings.ScriptAutomationEnabled;
        ConfigureScriptAutomationTimer();
        UpdateScriptAutomationControls();
        LoadDomainRulesFromSettings();
        var adapters = WindowsAdapterService.GetUsableAdapters();
        AdapterSelector.ItemsSource = adapters;
        AdapterSelector.SelectedIndex = adapters.Count > 0 ? 0 : -1;
        UpdateAdapterSummary();
        if (adapters.Count == 0)
        {
            SetStatus("No active IPv4 adapter with a gateway was found.", false);
            StartButton.IsEnabled = false;
        }

        UpdateButtons();
        await CheckForUpdatesAsync();
    }

    private async Task CheckForUpdatesAsync()
    {
        var checkedAt = DateTimeOffset.UtcNow;
        if (!GitHubUpdateChecker.ShouldCheck(
                settings.DisableUpdateChecks,
                settings.LastUpdateCheckUtc,
                checkedAt))
        {
            return;
        }

        settings.LastUpdateCheckUtc = checkedAt;
        try
        {
            var installedVersion = typeof(MainWindow).Assembly.GetName().Version ?? new Version();
            var available = await updateChecker.CheckAsync(
                installedVersion,
                UpdatePlatform.WindowsX64);
            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            if (available is null)
            {
                return;
            }

            var prompt = new UpdatePromptWindow(installedVersion, available.LatestVersion)
            {
                Owner = this,
            };
            prompt.ShowDialog();
            if (prompt.Choice == UpdatePromptChoice.NeverAskAgain)
            {
                settings.DisableUpdateChecks = true;
                await settingsStore.SaveAsync(settings);
                settingsDirty = false;
                return;
            }

            if (prompt.Choice == UpdatePromptChoice.Update)
            {
                Process.Start(new ProcessStartInfo(available.ReleasePage.AbsoluteUri)
                {
                    UseShellExecute = true,
                });
            }
        }
        catch (Exception)
        {
            // Update checks are optional and must never interrupt app startup.
        }
    }

    private async void StartButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        if (operationInProgress || AdapterSelector.SelectedItem is not AdapterProfile selected)
        {
            return;
        }

        operationInProgress = true;
        UpdateButtons();
        SetStatus("Starting packet capture…", null);
        try
        {
            ClearObservedActivity();
            ApplyAllSavedRules();
            UpdateKnownDeviceHints();
            await engine.StartAsync(selected, CancellationToken.None);
            controlStartedAt = DateTimeOffset.UtcNow;
            TrafficChart.Samples = trafficHistory.Samples;
            RefreshDevices(null, EventArgs.Empty);
            await SaveSettingsIfDirtyAsync();
            SetStatus("Control active", true);
            refreshTimer.Start();
        }
        catch (Exception exception)
        {
            SetStatus(exception.Message, false);
            MessageBox.Show(
                exception.Message,
                "Could not start LAN control",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            operationInProgress = false;
            UpdateButtons();
        }
    }

    private async void StopButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        await StopEngineAsync();
    }

    private async void ScanButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        if (AdapterSelector.SelectedItem is AdapterProfile adapter)
        {
            await RunDeviceScanAsync(adapter, isAutomatic: false);
        }
    }

    private async void AutoScanCheckBox_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        var enabled = AutoScanCheckBox.IsChecked == true;
        var intervalSeconds = settings.AutoScanIntervalSeconds;
        if (enabled && !TryGetAutoScanInterval(out intervalSeconds))
        {
            AutoScanCheckBox.IsChecked = false;
            SetStatus(
                $"Automatic scan interval must be between {MinimumAutoScanIntervalSeconds} and " +
                $"{MaximumAutoScanIntervalSeconds} seconds.",
                false);
            return;
        }

        var previousEnabled = settings.AutoScanEnabled;
        var previousInterval = settings.AutoScanIntervalSeconds;
        settings.AutoScanEnabled = enabled;
        if (enabled)
        {
            settings.AutoScanIntervalSeconds = intervalSeconds;
        }

        try
        {
            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            ConfigureAutoScanTimer();
            DetailStatusText.Text = enabled
                ? $"Automatic device discovery enabled: a full scan runs every {settings.AutoScanIntervalSeconds} seconds."
                : "Automatic device discovery disabled.";
        }
        catch (IOException exception)
        {
            settings.AutoScanEnabled = previousEnabled;
            settings.AutoScanIntervalSeconds = previousInterval;
            AutoScanCheckBox.IsChecked = previousEnabled;
            AutoScanIntervalTextBox.Text = previousInterval.ToString();
            ConfigureAutoScanTimer();
            SetStatus(exception.Message, false);
        }
    }

    private async void AutoScanIntervalTextBox_OnLostFocus(object sender, RoutedEventArgs eventArgs)
    {
        if (!TryGetAutoScanInterval(out var intervalSeconds))
        {
            AutoScanIntervalTextBox.Text = settings.AutoScanIntervalSeconds.ToString();
            SetStatus(
                $"Automatic scan interval must be between {MinimumAutoScanIntervalSeconds} and " +
                $"{MaximumAutoScanIntervalSeconds} seconds.",
                false);
            return;
        }

        if (settings.AutoScanIntervalSeconds == intervalSeconds)
        {
            return;
        }

        var previousInterval = settings.AutoScanIntervalSeconds;
        var previousDirtyState = settingsDirty;
        settings.AutoScanIntervalSeconds = intervalSeconds;
        settingsDirty = true;
        try
        {
            await SaveSettingsIfDirtyAsync();
            ConfigureAutoScanTimer();
            if (settings.AutoScanEnabled)
            {
                DetailStatusText.Text =
                    $"Automatic device discovery will run every {settings.AutoScanIntervalSeconds} seconds.";
            }
        }
        catch (IOException exception)
        {
            settings.AutoScanIntervalSeconds = previousInterval;
            settingsDirty = previousDirtyState;
            AutoScanIntervalTextBox.Text = previousInterval.ToString();
            SetStatus(exception.Message, false);
        }
    }

    private bool TryGetAutoScanInterval(out int intervalSeconds) =>
        int.TryParse(AutoScanIntervalTextBox.Text.Trim(), out intervalSeconds) &&
        intervalSeconds is >= MinimumAutoScanIntervalSeconds and <= MaximumAutoScanIntervalSeconds;

    private void ConfigureAutoScanTimer()
    {
        autoScanTimer.Stop();
        if (!settings.AutoScanEnabled)
        {
            return;
        }

        autoScanTimer.Interval = TimeSpan.FromSeconds(
            Math.Clamp(
                settings.AutoScanIntervalSeconds,
                MinimumAutoScanIntervalSeconds,
                MaximumAutoScanIntervalSeconds));
        autoScanTimer.Start();
    }

    private async void AutoScanTimer_OnTick(object? sender, EventArgs eventArgs)
    {
        if (!settings.AutoScanEnabled ||
            operationInProgress ||
            AdapterSelector.SelectedItem is not AdapterProfile adapter)
        {
            return;
        }

        await RunDeviceScanAsync(adapter, isAutomatic: true);
    }


    private async void BrowseScriptButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a PowerShell script",
            Filter = "PowerShell scripts (*.ps1)|*.ps1",
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        settings.ScriptAutomationPath = Path.GetFullPath(dialog.FileName);
        settings.ScriptAutomationEnabled = false;
        ScriptPathTextBox.Text = settings.ScriptAutomationPath;
        ScriptAutomationCheckBox.IsChecked = false;
        ConfigureScriptAutomationTimer();
        try
        {
            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            UpdateScriptAutomationControls();
            ScriptAutomationStatusText.Text =
                "Script selected. Review the file, then enable its schedule explicitly.";
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            ScriptAutomationStatusText.Text = $"Could not save script selection: {exception.Message}";
            SetStatus(exception.Message, false);
        }
    }

    private async void ScriptAutomationCheckBox_OnClick(
        object sender,
        RoutedEventArgs eventArgs)
    {
        var enabled = ScriptAutomationCheckBox.IsChecked == true;
        if (enabled &&
            (!TryGetScriptAutomationInterval(out var intervalSeconds) ||
             string.IsNullOrWhiteSpace(settings.ScriptAutomationPath) ||
             !File.Exists(settings.ScriptAutomationPath) ||
             !string.Equals(
                 Path.GetExtension(settings.ScriptAutomationPath),
                 ".ps1",
                 StringComparison.OrdinalIgnoreCase)))
        {
            ScriptAutomationCheckBox.IsChecked = false;
            ScriptAutomationStatusText.Text =
                "Choose an existing .ps1 file and set an interval from 60 to 3600 seconds first.";
            return;
        }

        if (enabled)
        {
            var choice = MessageBox.Show(
                this,
                "The selected PowerShell script will run on this schedule while LANtern is open. " +
                "It runs with the same Windows account and permissions as LANtern, including " +
                "Administrator permissions when LANtern is elevated. Only enable a script you " +
                "have inspected and trust. Windows PowerShell execution policy is not bypassed.\n\n" +
                "Enable scheduled execution?",
                "Confirm script automation",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (choice != MessageBoxResult.Yes)
            {
                ScriptAutomationCheckBox.IsChecked = false;
                return;
            }
        }

        var previousEnabled = settings.ScriptAutomationEnabled;
        var previousInterval = settings.ScriptAutomationIntervalSeconds;
        settings.ScriptAutomationEnabled = enabled;
        if (enabled && TryGetScriptAutomationInterval(out var selectedInterval))
        {
            settings.ScriptAutomationIntervalSeconds = selectedInterval;
        }

        try
        {
            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            ConfigureScriptAutomationTimer();
            UpdateScriptAutomationControls();
            ScriptAutomationStatusText.Text = enabled
                ? $"Scheduled script enabled. It will next run in {settings.ScriptAutomationIntervalSeconds} seconds."
                : "Scheduled script disabled.";
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            settings.ScriptAutomationEnabled = previousEnabled;
            settings.ScriptAutomationIntervalSeconds = previousInterval;
            ScriptAutomationCheckBox.IsChecked = previousEnabled;
            ScriptAutomationIntervalTextBox.Text = previousInterval.ToString();
            ConfigureScriptAutomationTimer();
            UpdateScriptAutomationControls();
            ScriptAutomationStatusText.Text = $"Could not save script schedule: {exception.Message}";
        }
    }

    private async void ScriptAutomationIntervalTextBox_OnLostFocus(
        object sender,
        RoutedEventArgs eventArgs)
    {
        if (!TryGetScriptAutomationInterval(out var intervalSeconds))
        {
            ScriptAutomationIntervalTextBox.Text =
                settings.ScriptAutomationIntervalSeconds.ToString();
            ScriptAutomationStatusText.Text =
                $"Script interval must be between {MinimumScriptIntervalSeconds} and " +
                $"{MaximumScriptIntervalSeconds} seconds.";
            return;
        }

        if (settings.ScriptAutomationIntervalSeconds == intervalSeconds)
        {
            return;
        }

        var previousInterval = settings.ScriptAutomationIntervalSeconds;
        settings.ScriptAutomationIntervalSeconds = intervalSeconds;
        try
        {
            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            ConfigureScriptAutomationTimer();
            if (settings.ScriptAutomationEnabled)
            {
                ScriptAutomationStatusText.Text =
                    $"Scheduled script interval changed to {intervalSeconds} seconds.";
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            settings.ScriptAutomationIntervalSeconds = previousInterval;
            ScriptAutomationIntervalTextBox.Text = previousInterval.ToString();
            ScriptAutomationStatusText.Text = $"Could not save script interval: {exception.Message}";
        }
    }

    private bool TryGetScriptAutomationInterval(out int intervalSeconds) =>
        int.TryParse(ScriptAutomationIntervalTextBox.Text.Trim(), out intervalSeconds) &&
        intervalSeconds is >= MinimumScriptIntervalSeconds and <= MaximumScriptIntervalSeconds;

    private void ConfigureScriptAutomationTimer()
    {
        scriptAutomationTimer.Stop();
        if (!settings.ScriptAutomationEnabled ||
            string.IsNullOrWhiteSpace(settings.ScriptAutomationPath) ||
            !File.Exists(settings.ScriptAutomationPath))
        {
            return;
        }

        scriptAutomationTimer.Interval = TimeSpan.FromSeconds(
            Math.Clamp(
                settings.ScriptAutomationIntervalSeconds,
                MinimumScriptIntervalSeconds,
                MaximumScriptIntervalSeconds));
        scriptAutomationTimer.Start();
    }

    private void UpdateScriptAutomationControls()
    {
        RunScriptNowButton.IsEnabled =
            !scriptRunInProgress &&
            !string.IsNullOrWhiteSpace(settings.ScriptAutomationPath) &&
            File.Exists(settings.ScriptAutomationPath);
        ScriptAutomationCheckBox.IsEnabled = !scriptRunInProgress;
        ScriptAutomationIntervalTextBox.IsEnabled = !scriptRunInProgress;
        BrowseScriptButton.IsEnabled = !scriptRunInProgress;
    }

    private async void RunScriptNowButton_OnClick(
        object sender,
        RoutedEventArgs eventArgs)
    {
        await StartSelectedScriptAsync(isScheduled: false);
    }

    private async void ScriptAutomationTimer_OnTick(
        object? sender,
        EventArgs eventArgs)
    {
        if (!settings.ScriptAutomationEnabled || scriptRunInProgress)
        {
            return;
        }

        await StartSelectedScriptAsync(isScheduled: true);
    }

    private Task StartSelectedScriptAsync(bool isScheduled)
    {
        if (scriptRunInProgress)
        {
            ScriptAutomationStatusText.Text =
                "Skipped: the previous script run has not finished.";
            return Task.CompletedTask;
        }

        if (string.IsNullOrWhiteSpace(settings.ScriptAutomationPath) ||
            !File.Exists(settings.ScriptAutomationPath))
        {
            ScriptAutomationStatusText.Text =
                "The selected script is missing. Browse to a valid .ps1 file.";
            return Task.CompletedTask;
        }

        scriptRunInProgress = true;
        UpdateScriptAutomationControls();
        activeScriptRunTask = RunSelectedScriptCoreAsync(
            settings.ScriptAutomationPath,
            isScheduled);
        return activeScriptRunTask;
    }

    private async Task RunSelectedScriptCoreAsync(string scriptPath, bool isScheduled)
    {
        var startedAt = DateTimeOffset.Now;
        ScriptAutomationStatusText.Text = isScheduled
            ? $"Scheduled script running — started {startedAt:HH:mm:ss}."
            : $"Script running — started {startedAt:HH:mm:ss}.";
        try
        {
            var result = await scriptRunner.RunAsync(
                scriptPath,
                scriptRunCancellation.Token);
            if (result.TimedOut)
            {
                ScriptAutomationStatusText.Text =
                    $"Script timed out after {PowerShellScriptRunner.MaximumRunTime.TotalMinutes:0} minutes.";
            }
            else if (result.Succeeded)
            {
                ScriptAutomationStatusText.Text =
                    $"Script completed successfully at {DateTimeOffset.Now:HH:mm:ss}.";
            }
            else
            {
                var detail = string.IsNullOrWhiteSpace(result.StandardError)
                    ? result.StandardOutput
                    : result.StandardError;
                detail = detail.Trim();
                if (detail.Length > 240)
                {
                    detail = detail[^240..];
                }

                ScriptAutomationStatusText.Text =
                    string.IsNullOrWhiteSpace(detail)
                        ? $"Script failed with exit code {result.ExitCode}."
                        : $"Script failed with exit code {result.ExitCode}: {detail}";
            }
        }
        catch (OperationCanceledException) when (scriptRunCancellation.IsCancellationRequested)
        {
            ScriptAutomationStatusText.Text = "Script execution cancelled because LANtern is closing.";
        }
        catch (Exception exception)
        {
            ScriptAutomationStatusText.Text = $"Script could not run: {exception.Message}";
        }
        finally
        {
            scriptRunInProgress = false;
            activeScriptRunTask = null;
            UpdateScriptAutomationControls();
        }
    }

    private void DeviceGrid_OnLoadingRow(object? sender, DataGridRowEventArgs eventArgs)
    {
        if (eventArgs.Row.Item is DeviceViewModel device)
        {
            AutomationProperties.SetAutomationId(eventArgs.Row, device.RowAutomationId);
            AutomationProperties.SetName(eventArgs.Row, device.DisplayName);
        }
    }

    private async Task RunDeviceScanAsync(AdapterProfile adapter, bool isAutomatic)
    {
        if (operationInProgress)
        {
            return;
        }

        operationInProgress = true;
        UpdateButtons();
        try
        {
            UpdateKnownDeviceHints();
            var scanStartedAt = DateTimeOffset.UtcNow;
            SetStatus(
                isAutomatic
                    ? $"Automatic device discovery running (every {settings.AutoScanIntervalSeconds} seconds)…"
                    : "Refreshing the neighbor cache and performing fast, paced ARP discovery first…",
                null);

            DiscoveryRefreshResult arpResult;
            string? arpFailure = null;
            try
            {
                // ARP gets first chance to identify hosts. Supplemental protocol
                // probes run only after this bounded, faster pass has completed.
                arpResult = await engine.ScanDevicesAsync(adapter);
            }
            catch (Exception exception)
            {
                arpFailure = exception.Message;
                arpResult = new DiscoveryRefreshResult(
                    0,
                    registry.Peek().Count,
                    ProbeWarning: exception.Message);
            }

            var observationTime = DateTimeOffset.UtcNow;
            var recentlyObservedAddresses = registry.Peek()
                .Where(snapshot =>
                    DevicePresencePolicy.Classify(snapshot.LastSeen, observationTime) ==
                    DevicePresence.Online)
                .Select(snapshot => snapshot.IpAddress)
                .ToHashSet();

            SetStatus(
                "Checking only addresses without recent reachability evidence using faster paced protocol fallbacks…",
                null);

            LocalHostDiscoveryResult hostResult;
            string? hostFailure = null;
            try
            {
                hostResult = await localHostDiscoveryService.ScanAsync(
                    adapter,
                    recentlyObservedAddresses);
            }
            catch (Exception exception)
            {
                hostFailure = exception.Message;
                hostResult = new LocalHostDiscoveryResult([], 0);
            }

            var liveMacByIp = registry.Peek()
                .Where(snapshot =>
                    snapshot.HasMacAddress &&
                    snapshot.LastSeen >= scanStartedAt)
                .GroupBy(snapshot => snapshot.IpAddress)
                .ToDictionary(group => group.Key, group => group.First());

            foreach (var host in hostResult.Hosts)
            {
                if (liveMacByIp.TryGetValue(host.Address, out var macSnapshot))
                {
                    if (!string.IsNullOrWhiteSpace(host.HostName))
                    {
                        registry.SetHostName(macSnapshot.MacAddress, host.HostName);
                    }
                }
                else
                {
                    // Positive reachability without a fresh, consistent MAC mapping
                    // is inventory-only. It cannot become an interception target.
                    registry.ObserveIpOnly(
                        host.Address,
                        DateTimeOffset.UtcNow,
                        host.HostName);
                }
            }

            RefreshDevices(null, EventArgs.Empty);
            await SaveSettingsIfDirtyAsync();

            var ipOnlyCount = hostResult.Hosts
                .Select(host => host.Address)
                .Distinct()
                .Count(address => !liveMacByIp.ContainsKey(address));

            var status = $"{arpResult.StatusMessage} {hostResult.StatusMessage}";
            if (ipOnlyCount > 0)
            {
                status +=
                    $" {ipOnlyCount} responding endpoint(s) had no fresh verified MAC mapping " +
                    "and are shown as inventory-only.";
            }

            if (!string.IsNullOrWhiteSpace(hostFailure))
            {
                status += $" Independent discovery warning: {hostFailure}";
            }

            if (!string.IsNullOrWhiteSpace(arpFailure))
            {
                status += $" ARP discovery warning: {arpFailure}";
            }

            if (isAutomatic)
            {
                status = $"Automatic scan completed ({settings.AutoScanIntervalSeconds}-second interval). {status}";
            }

            DetailStatusText.Text = status;
            SetStatus(status, true);
        }
        catch (Exception exception)
        {
            SetStatus(exception.Message, false);
        }
        finally
        {
            operationInProgress = false;
            UpdateButtons();
        }
    }

    private async void ClearDeviceCacheButton_OnClick(
        object sender,
        RoutedEventArgs eventArgs)
    {
        if (operationInProgress)
        {
            return;
        }

        var offlineDevices = Devices
            .Where(device => !device.IsOnline && !device.IsProtected)
            .ToArray();
        if (offlineDevices.Length == 0)
        {
            DetailStatusText.Text = "No offline device cache entries to clear.";
            return;
        }

        operationInProgress = true;
        UpdateButtons();
        try
        {
            var selectedAdapter = AdapterSelector.SelectedItem as AdapterProfile;
            var osEntriesRemoved = 0;
            var osEntriesNotRemoved = 0;
            foreach (var device in offlineDevices)
            {
                if (selectedAdapter is not null &&
                    IPAddress.TryParse(device.IpAddress, out var address))
                {
                    if (await WindowsNeighborCache.DeleteAsync(
                            selectedAdapter,
                            address,
                            CancellationToken.None))
                    {
                        osEntriesRemoved++;
                    }
                    else
                    {
                        osEntriesNotRemoved++;
                    }
                }

                if (device.HasMacAddress)
                {
                    var macAddress = PhysicalAddress.Parse(device.MacKey);
                    engine.ForgetDevice(macAddress);
                    registry.Remove(macAddress);
                }
                else if (IPAddress.TryParse(device.IpAddress, out var ipOnlyAddress))
                {
                    registry.RemoveIpOnly(ipOnlyAddress);
                }

                deviceIndex.Remove(device.DeviceKey);
                Devices.Remove(device);
            }

            UpdateKnownDeviceHints();
            settingsDirty = true;
            await SaveSettingsIfDirtyAsync();
            RefreshDevices(null, EventArgs.Empty);
            var cacheNote = osEntriesNotRemoved == 0
                ? $"Removed {osEntriesRemoved} matching Windows neighbor-cache entr" +
                  $"{(osEntriesRemoved == 1 ? "y" : "ies")}."
                : $"{osEntriesRemoved} Windows neighbor-cache entries were removed; " +
                  $"{osEntriesNotRemoved} were already absent or could not be removed.";
            SetStatus(
                $"Cleared {offlineDevices.Length} offline device cache entr" +
                $"{(offlineDevices.Length == 1 ? "y" : "ies")}. {cacheNote} " +
                "Saved IP/MAC history, names, and rules were retained for future offline checks.",
                true);
        }
        catch (Exception exception) when (
            exception is IOException or InvalidOperationException or FormatException)
        {
            SetStatus($"Could not clear the device cache: {exception.Message}", false);
        }
        finally
        {
            operationInProgress = false;
            UpdateButtons();
        }
    }

    private void ClearActivityButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        ClearObservedActivity();
        DetailStatusText.Text = "Website activity cleared from this session.";
    }

    private void ClearObservedActivity()
    {
        websiteActivityIndex.Clear();
        WebsiteActivity.Clear();
        websiteActivityGroupIndex.Clear();
        DeviceActivityGroups.Clear();
        RefreshWebsiteActivityState();
    }

    private void Engine_OnDeviceDomainObserved(
        object? sender,
        DeviceDomainObservedEventArgs eventArgs)
    {
        _ = Dispatcher.BeginInvoke(
            () => ObserveWebsiteActivity(eventArgs),
            DispatcherPriority.Background);
    }

    private void ObserveWebsiteActivity(DeviceDomainObservedEventArgs eventArgs)
    {
        var macKey = TrafficPolicy.NormalizeMac(eventArgs.MacAddress.ToString());
        var deviceName = deviceIndex.TryGetValue(macKey, out var device)
            ? device.DisplayName
            : $"Device {FormatMac(macKey)}";
        var ipAddress = device?.IpAddress ?? "-";
        var group = GetOrCreateWebsiteActivityGroup(macKey, deviceName, ipAddress);
        var domainKey = $"{macKey}|{eventArgs.Observation.Domain}";
        if (websiteActivityIndex.TryGetValue(domainKey, out var existing))
        {
            existing.Observe(
                deviceName,
                ipAddress,
                eventArgs.Observation.Source,
                eventArgs.ObservedAt);
            existing.SetBlocked(
                eventArgs.Blocked || policy.ShouldBlockDomain(macKey, existing.Domain));
            group.TouchDomain(existing);
        }
        else
        {
            var activity = new DeviceActivityViewModel(
                macKey,
                deviceName,
                ipAddress,
                eventArgs.Observation.Domain,
                eventArgs.Observation.Source,
                eventArgs.ObservedAt);
            activity.SetBlocked(
                eventArgs.Blocked || policy.ShouldBlockDomain(macKey, activity.Domain));
            websiteActivityIndex[domainKey] = activity;
            WebsiteActivity.Add(activity);
            group.AddDomain(activity);
        }

        while (WebsiteActivity.Count > MaxWebsiteActivityRows)
        {
            var oldest = WebsiteActivity.MinBy(activity => activity.LastSeen);
            if (oldest is null)
            {
                break;
            }

            WebsiteActivity.Remove(oldest);
            websiteActivityIndex.Remove($"{oldest.MacKey}|{oldest.Domain}");
            if (websiteActivityGroupIndex.TryGetValue(oldest.MacKey, out var oldestGroup))
            {
                oldestGroup.RemoveDomain(oldest);
            }
        }

        CollectionViewSource.GetDefaultView(WebsiteActivity).Refresh();
        RefreshWebsiteActivityState();
    }

    private async void BlockVisitedDomainButton_OnClick(
        object sender,
        RoutedEventArgs eventArgs)
    {
        if (sender is Button { Tag: DeviceActivityViewModel activity })
        {
            await AddDomainBlockAsync(activity.MacKey, activity.Domain);
        }
    }

    private async void AddDomainRuleButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        if (DomainRuleDeviceSelector.SelectedItem is not DeviceViewModel { CanControl: true } device)
        {
            DomainRuleValidationText.Text = "Choose a connected device.";
            DomainRuleValidationText.Visibility = Visibility.Visible;
            return;
        }

        string domain;
        try
        {
            domain = TrafficPolicy.NormalizeDomain(DomainRuleInput.Text);
        }
        catch (FormatException exception)
        {
            DomainRuleValidationText.Text = exception.Message;
            DomainRuleValidationText.Visibility = Visibility.Visible;
            DomainRuleInput.Focus();
            return;
        }

        DomainRuleValidationText.Visibility = Visibility.Collapsed;
        await AddDomainBlockAsync(device.MacKey, domain);
        DomainRuleInput.Clear();
    }

    private async void ApplyDomainPresetButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        if (DomainPresetDeviceSelector.SelectedItem is not DeviceViewModel { CanControl: true } device)
        {
            DomainPresetValidationText.Text = "Choose a connected device.";
            DomainPresetValidationText.Visibility = Visibility.Visible;
            return;
        }

        if (DomainPresetSelector.SelectedItem is not DomainBlockPreset preset)
        {
            DomainPresetValidationText.Text = "Choose an app preset.";
            DomainPresetValidationText.Visibility = Visibility.Visible;
            return;
        }

        DomainPresetValidationText.Visibility = Visibility.Collapsed;
        var macKey = TrafficPolicy.NormalizeMac(device.MacKey);
        if (!settings.AppliedDomainPresets.TryGetValue(macKey, out var appliedPresets))
        {
            appliedPresets = [];
            settings.AppliedDomainPresets[macKey] = appliedPresets;
        }

        if (!appliedPresets.Contains(preset.Name, StringComparer.OrdinalIgnoreCase))
        {
            appliedPresets.Add(preset.Name);
            appliedPresets.Sort(StringComparer.OrdinalIgnoreCase);
        }

        await AddDomainBlocksAsync(
            macKey,
            preset.Domains,
            $"Applied the {preset.Name} preset to {device.DisplayName}. " +
            "Reconnect the app so existing sessions close.");
    }

    private async void RemoveDomainRuleButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        if (sender is Button { Tag: DomainRuleViewModel rule })
        {
            await RemoveDomainBlockAsync(rule);
        }
    }

    private async void RemoveDomainPresetButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        if (sender is Button { Tag: DomainPresetRuleViewModel preset })
        {
            await RemoveDomainPresetAsync(preset);
        }
    }

    private async Task AddDomainBlockAsync(string macAddress, string domain)
    {
        var normalizedDomain = TrafficPolicy.NormalizeDomain(domain);
        await AddDomainBlocksAsync(
            macAddress,
            [normalizedDomain],
            $"Blocked {normalizedDomain} for {ResolveDeviceName(TrafficPolicy.NormalizeMac(macAddress))}. " +
            "New connections are filtered immediately.");
    }

    private async Task AddDomainBlocksAsync(
        string macAddress,
        IEnumerable<string> requestedDomains,
        string status)
    {
        var macKey = TrafficPolicy.NormalizeMac(macAddress);
        if (!settings.BlockedDomains.TryGetValue(macKey, out var domains))
        {
            domains = [];
            settings.BlockedDomains[macKey] = domains;
        }

        foreach (var requested in requestedDomains)
        {
            var normalized = TrafficPolicy.NormalizeDomain(requested);
            if (!domains.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                domains.Add(normalized);
            }
        }

        domains.Sort(StringComparer.OrdinalIgnoreCase);
        policy.SetBlockedDomains(macKey, domains);
        RebuildDomainRulePresentation();
        RefreshBlockedActivityState();
        await SaveDomainRulesAsync(status);
    }

    private async Task RemoveDomainBlockAsync(DomainRuleViewModel rule)
    {
        if (settings.BlockedDomains.TryGetValue(rule.MacKey, out var domains))
        {
            domains.RemoveAll(domain =>
                domain.Equals(rule.Domain, StringComparison.OrdinalIgnoreCase));
            if (domains.Count == 0)
            {
                settings.BlockedDomains.Remove(rule.MacKey);
            }
        }

        policy.SetBlockedDomains(
            rule.MacKey,
            settings.BlockedDomains.TryGetValue(rule.MacKey, out var remaining)
                ? remaining
                : []);
        RebuildDomainRulePresentation();
        RefreshBlockedActivityState();
        await SaveDomainRulesAsync($"Unblocked {rule.Domain} for {rule.DeviceName}.");
    }

    private async Task RemoveDomainPresetAsync(DomainPresetRuleViewModel preset)
    {
        if (settings.AppliedDomainPresets.TryGetValue(preset.MacKey, out var appliedPresets))
        {
            appliedPresets.RemoveAll(name =>
                name.Equals(preset.PresetName, StringComparison.OrdinalIgnoreCase));
            if (appliedPresets.Count == 0)
            {
                settings.AppliedDomainPresets.Remove(preset.MacKey);
            }
        }

        var domainsStillClaimed = settings.AppliedDomainPresets
            .GetValueOrDefault(preset.MacKey, [])
            .SelectMany(name => DomainBlockPresetCatalog.All
                .Where(candidate => candidate.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                .SelectMany(candidate => candidate.Domains))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (settings.BlockedDomains.TryGetValue(preset.MacKey, out var blockedDomains))
        {
            blockedDomains.RemoveAll(domain =>
                preset.Domains.Contains(domain, StringComparer.OrdinalIgnoreCase) &&
                !domainsStillClaimed.Contains(domain));
            if (blockedDomains.Count == 0)
            {
                settings.BlockedDomains.Remove(preset.MacKey);
            }
        }

        policy.SetBlockedDomains(
            preset.MacKey,
            settings.BlockedDomains.GetValueOrDefault(preset.MacKey, []));
        RebuildDomainRulePresentation();
        RefreshBlockedActivityState();
        await SaveDomainRulesAsync($"Removed the {preset.PresetName} preset from {preset.DeviceName}.");
    }

    private async Task SaveDomainRulesAsync(string status)
    {
        try
        {
            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            RefreshDomainRulesState();
            DetailStatusText.Text = status;
        }
        catch (IOException exception)
        {
            DetailStatusText.Text = exception.Message;
        }
    }

    private void LoadDomainRulesFromSettings()
    {
        foreach (var pair in settings.BlockedDomains)
        {
            policy.SetBlockedDomains(pair.Key, pair.Value);
        }

        RebuildDomainRulePresentation();
        RefreshBlockedActivityState();
        RefreshDomainRulesState();
    }

    private void RebuildDomainRulePresentation()
    {
        DomainPresetRules.Clear();
        DomainRules.Clear();
        foreach (var pair in settings.BlockedDomains)
        {
            var presentation = DomainRulePresentationBuilder.Build(
                pair.Key,
                ResolveDeviceName(pair.Key),
                pair.Value,
                settings.AppliedDomainPresets.GetValueOrDefault(pair.Key, []));
            foreach (var preset in presentation.Presets)
            {
                DomainPresetRules.Add(preset);
            }

            foreach (var rule in presentation.IndividualRules)
            {
                DomainRules.Add(rule);
            }
        }
    }

    private string ResolveDeviceName(string macKey)
    {
        if (deviceIndex.TryGetValue(macKey, out var device))
        {
            return device.DisplayName;
        }

        if (settings.Devices.TryGetValue(macKey, out var preferences))
        {
            if (!string.IsNullOrWhiteSpace(preferences.Alias))
            {
                return preferences.Alias;
            }

            if (!string.IsNullOrWhiteSpace(preferences.LearnedHostName))
            {
                return preferences.LearnedHostName;
            }
        }

        return $"Device {FormatMac(macKey)}";
    }

    private void RefreshBlockedActivityState()
    {
        foreach (var activity in WebsiteActivity)
        {
            activity.SetBlocked(policy.ShouldBlockDomain(activity.MacKey, activity.Domain));
        }
    }

    private void RefreshDomainRulesState()
    {
        DomainRulesEmptyState.Visibility = DomainRules.Count == 0 && DomainPresetRules.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
        var presetLabel = $"{DomainPresetRules.Count} preset{(DomainPresetRules.Count == 1 ? string.Empty : "s")}";
        var ruleLabel = $"{DomainRules.Count} rule{(DomainRules.Count == 1 ? string.Empty : "s")}";
        DomainRuleCountText.Text = $"{presetLabel}  •  {ruleLabel}";
        CollectionViewSource.GetDefaultView(DomainPresetRules).Refresh();
        CollectionViewSource.GetDefaultView(DomainRules).Refresh();
    }

    private void RefreshWebsiteActivityState()
    {
        WebsiteActivityEmptyState.Visibility = DeviceActivityGroups.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
        WebsiteActivityCountText.Text =
            $"{DeviceActivityGroups.Count} device{(DeviceActivityGroups.Count == 1 ? string.Empty : "s")}  •  " +
            $"{WebsiteActivity.Count} domain{(WebsiteActivity.Count == 1 ? string.Empty : "s")}";
    }

    private DeviceActivityGroupViewModel GetOrCreateWebsiteActivityGroup(
        string macKey,
        string deviceName,
        string ipAddress)
    {
        if (!websiteActivityGroupIndex.TryGetValue(macKey, out var group))
        {
            group = new DeviceActivityGroupViewModel(macKey, deviceName, ipAddress);
            websiteActivityGroupIndex[macKey] = group;
        }
        else
        {
            group.UpdateIdentity(deviceName, ipAddress);
        }

        if (!DeviceActivityGroups.Contains(group))
        {
            DeviceActivityGroups.Add(group);
        }

        return group;
    }

    private void SyncWebsiteActivityGroups()
    {
        var connectedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var device in Devices.Where(device => device.CanControl && device.IsOnline))
        {
            connectedKeys.Add(device.MacKey);
            _ = GetOrCreateWebsiteActivityGroup(
                device.MacKey,
                device.DisplayName,
                device.IpAddress);
        }

        foreach (var group in DeviceActivityGroups
                     .Where(group => !connectedKeys.Contains(group.MacKey))
                     .ToArray())
        {
            DeviceActivityGroups.Remove(group);
        }

        RefreshWebsiteActivityState();
    }

    private void SyncDomainRuleDevices()
    {
        var available = Devices
            .Where(device => device.CanControl && device.IsOnline)
            .ToArray();
        foreach (var stale in DomainRuleDevices
                     .Where(device => !available.Contains(device))
                     .ToArray())
        {
            DomainRuleDevices.Remove(stale);
        }

        foreach (var device in available)
        {
            if (!DomainRuleDevices.Contains(device))
            {
                DomainRuleDevices.Add(device);
            }

            foreach (var rule in DomainRules.Where(rule =>
                         rule.MacKey.Equals(device.MacKey, StringComparison.OrdinalIgnoreCase)))
            {
                rule.UpdateDeviceName(device.DisplayName);
            }

            foreach (var preset in DomainPresetRules.Where(preset =>
                         preset.MacKey.Equals(device.MacKey, StringComparison.OrdinalIgnoreCase)))
            {
                preset.UpdateDeviceName(device.DisplayName);
            }
        }

        if (DomainRuleDeviceSelector.SelectedItem is null && DomainRuleDevices.Count > 0)
        {
            DomainRuleDeviceSelector.SelectedIndex = 0;
        }

        if (DomainPresetDeviceSelector.SelectedItem is null && DomainRuleDevices.Count > 0)
        {
            DomainPresetDeviceSelector.SelectedIndex = 0;
        }

        CollectionViewSource.GetDefaultView(DomainRuleDevices).Refresh();
        CollectionViewSource.GetDefaultView(DomainPresetRules).Refresh();
        CollectionViewSource.GetDefaultView(DomainRules).Refresh();
    }

    private void AdapterSelector_OnSelectionChanged(object sender, SelectionChangedEventArgs eventArgs)
    {
        UpdateAdapterSummary();
        UpdateButtons();
    }

    private async Task StopEngineAsync()
    {
        if (operationInProgress)
        {
            return;
        }

        operationInProgress = true;
        refreshTimer.Stop();
        UpdateButtons();
        SetStatus("Restoring normal ARP mappings…", null);
        try
        {
            await engine.StopAsync();
            RefreshDevices(null, EventArgs.Empty);
            await SaveSettingsIfDirtyAsync();
            controlStartedAt = null;
            UptimeText.Text = "Idle";
            SetStatus("Stopped safely", null);
        }
        finally
        {
            operationInProgress = false;
            UpdateButtons();
        }
    }

    private void RefreshDevices(object? sender, EventArgs eventArgs)
    {
        var activeProfile = AdapterSelector.SelectedItem as AdapterProfile;
        var now = DateTimeOffset.UtcNow;
        var view = CollectionViewSource.GetDefaultView(Devices);
        var editableView = view as IEditableCollectionView;
        var canMutateView = DeviceListRefreshPolicy.ShouldRefresh(
            Keyboard.FocusedElement is TextBox,
            editableView?.IsAddingNew == true,
            editableView?.IsEditingItem == true);
        var visibleKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var snapshot in registry.TakeSnapshot(now))
        {
            if (activeProfile is not null &&
                (snapshot.IpAddress.Equals(activeProfile.LocalAddress) ||
                 snapshot.MacAddress.Equals(activeProfile.LocalMac)))
            {
                continue;
            }

            var macKey = snapshot.HasMacAddress
                ? TrafficPolicy.NormalizeMac(snapshot.MacAddress.ToString())
                : null;
            var key = macKey ?? $"ip:{snapshot.IpAddress}";
            DevicePreferences? preferences = null;
            if (macKey is not null)
            {
                settings.Devices.TryGetValue(macKey, out preferences);
            }

            var isGateway = activeProfile is not null &&
                            snapshot.IpAddress.Equals(activeProfile.GatewayAddress);
            var presence = isGateway
                ? DevicePresence.Online
                : DevicePresencePolicy.Classify(snapshot.LastSeen, now);
            if (presence == DevicePresence.Hidden)
            {
                continue;
            }

            visibleKeys.Add(key);
            if (!isGateway && macKey is not null)
            {
                preferences ??= settings.Devices[macKey] = new DevicePreferences();
                var currentIp = snapshot.IpAddress.ToString();
                if (!string.Equals(preferences.LastKnownIp, currentIp, StringComparison.Ordinal))
                {
                    preferences.LastKnownIp = currentIp;
                    settingsDirty = true;
                }

                if (snapshot.LastSeen != DateTimeOffset.MinValue &&
                    (preferences.LastSeenUtc is null || snapshot.LastSeen > preferences.LastSeenUtc))
                {
                    preferences.LastSeenUtc = snapshot.LastSeen;
                    settingsDirty = true;
                }
            }

            if (!deviceIndex.TryGetValue(key, out var viewModel))
            {
                if (!canMutateView)
                {
                    continue;
                }

                viewModel = new DeviceViewModel(OnDeviceRuleChangedAsync);
                viewModel.Initialize(
                    snapshot,
                    preferences,
                    isGateway,
                    isGateway
                        ? "Gateway — protected"
                        : snapshot.HasMacAddress
                            ? "Online"
                            : "MAC unavailable — inventory only");
                deviceIndex[key] = viewModel;
                Devices.Add(viewModel);
            }
            else
            {
                viewModel.Update(snapshot, preferences?.Alias);
            }

            viewModel.SetPresence(presence == DevicePresence.Online);
        }

        if (canMutateView)
        {
            foreach (var stale in Devices
                         .Where(device => !visibleKeys.Contains(device.DeviceKey))
                         .ToArray())
            {
                deviceIndex.Remove(stale.DeviceKey);
                Devices.Remove(stale);
            }

            view.Refresh();
        }

        SyncWebsiteActivityGroups();
        SyncDomainRuleDevices();
        RefreshDashboardSummary();
        EmptyState.Visibility = Devices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        DeviceCountText.Text = $"{Devices.Count} device{(Devices.Count == 1 ? string.Empty : "s")}";
    }

    private async Task OnDeviceRuleChangedAsync(DeviceViewModel device)
    {
        if (!device.CanControl)
        {
            return;
        }

        var preferences = settings.Devices.TryGetValue(device.MacKey, out var existing)
            ? existing
            : settings.Devices[device.MacKey] = new DevicePreferences();
        var rule = new TrafficRule(
                device.PauseInternet,
                device.DownloadLimit,
                device.UploadLimit)
            .ForForwardingMode();
        var ruleChanged =
            preferences.DownloadKiloBytesPerSecond != rule.DownloadKiloBytesPerSecond ||
            preferences.UploadKiloBytesPerSecond != rule.UploadKiloBytesPerSecond ||
            preferences.PauseInternet != rule.PauseInternet;
        var aliasChanged = !string.Equals(
            preferences.Alias,
            device.Alias,
            StringComparison.Ordinal);
        preferences.DownloadKiloBytesPerSecond = rule.DownloadKiloBytesPerSecond;
        preferences.UploadKiloBytesPerSecond = rule.UploadKiloBytesPerSecond;
        preferences.PauseInternet = rule.PauseInternet;
        preferences.Alias = device.Alias;

        try
        {
            if (ruleChanged)
            {
                await engine.ApplyRuleAsync(device.MacKey, rule);
            }

            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            await Dispatcher.InvokeAsync(
                () =>
                {
                    DetailStatusText.Text =
                        aliasChanged && !ruleChanged
                            ? $"Device renamed to {device.DisplayName}."
                            : engine.IsRunning
                            ? $"Rule applied to {device.DisplayName}."
                            : $"Rule saved for {device.DisplayName}; it activates when control starts.";
                    RefreshDashboardSummary(addTrafficSample: false);
                });
        }
        catch (Exception exception) when (
            exception is IOException or InvalidOperationException)
        {
            await Dispatcher.InvokeAsync(() => DetailStatusText.Text = exception.Message);
        }
    }

    private void ApplyAllSavedRules()
    {
        foreach (var pair in settings.Devices)
        {
            policy.SetRule(
                pair.Key,
                new TrafficRule(
                    pair.Value.PauseInternet,
                    pair.Value.DownloadKiloBytesPerSecond,
                    pair.Value.UploadKiloBytesPerSecond)
                    .ForForwardingMode());
        }

        foreach (var pair in settings.BlockedDomains)
        {
            policy.SetBlockedDomains(pair.Key, pair.Value);
        }
    }

    private void UpdateKnownDeviceHints()
    {
        engine.ReplaceKnownDeviceHints(KnownDeviceHintFactory.Build(settings));
        engine.ReplaceRejectedResolvedNames(
            KnownDeviceHintFactory.FindAmbiguousLearnedNames(settings));
    }

    private async Task SaveSettingsIfDirtyAsync()
    {
        if (!settingsDirty)
        {
            return;
        }

        await settingsStore.SaveAsync(settings);
        settingsDirty = false;
    }

    private void Engine_OnStatusChanged(object? sender, string message)
    {
        _ = Dispatcher.InvokeAsync(() => DetailStatusText.Text = message);
    }

    private void Engine_OnIdentityAlertDetected(object? sender, string warning)
    {
        _ = Dispatcher.InvokeAsync(() =>
        {
            DetailStatusText.Text = warning;
            SetStatus(warning, false);
        });
    }

    private void Engine_OnStateChanged(
        object? sender,
        PcapEngineStateChangedEventArgs eventArgs)
    {
        _ = Dispatcher.InvokeAsync(() =>
        {
            ApplyEngineState(eventArgs.IsRunning);
            DetailStatusText.Text = eventArgs.StatusMessage;
        });
    }

    private void ApplyEngineState(bool isRunning)
    {
        if (isRunning)
        {
            controlStartedAt ??= DateTimeOffset.UtcNow;
            refreshTimer.Start();
            TopStatusText.Text = "Active";
            StatusDot.Fill = new SolidColorBrush(Color.FromRgb(104, 192, 138));
        }
        else
        {
            refreshTimer.Stop();
            controlStartedAt = null;
            UptimeText.Text = "Idle";
            TopStatusText.Text = "Idle";
            StatusDot.Fill = new SolidColorBrush(Color.FromRgb(168, 144, 149));
        }

        UpdateButtons();
        RefreshDashboardSummary(addTrafficSample: false);
    }

    private void Engine_OnDeviceIdentityLearned(
        object? sender,
        DeviceIdentityLearnedEventArgs eventArgs)
    {
        _ = Dispatcher
            .InvokeAsync(() => PersistLearnedIdentityAsync(eventArgs))
            .Task
            .Unwrap();
    }

    private async Task PersistLearnedIdentityAsync(
        DeviceIdentityLearnedEventArgs eventArgs)
    {
        await identitySaveSync.WaitAsync();
        try
        {
            var lastKnownIp = registry.Peek()
                .FirstOrDefault(device => device.MacAddress.Equals(eventArgs.MacAddress))?
                .IpAddress
                .ToString();
            var identity = DeviceIdentityTracker.Learn(
                settings,
                eventArgs.MacAddress.ToString(),
                eventArgs.HostName,
                lastKnownIp);
            if (identity.PreviousMacKey is not null)
            {
                policy.RemoveRule(identity.PreviousMacKey);
            }

            var rule = new TrafficRule(
                    identity.Preferences.PauseInternet,
                    identity.Preferences.DownloadKiloBytesPerSecond,
                    identity.Preferences.UploadKiloBytesPerSecond)
                .ForForwardingMode();
            await engine.ApplyRuleAsync(identity.MacKey, rule);
            UpdateKnownDeviceHints();
            await settingsStore.SaveAsync(settings);
            settingsDirty = false;
            DetailStatusText.Text = identity.PreviousMacKey is null
                ? $"Remembered {eventArgs.HostName}."
                : $"Recognized {eventArgs.HostName} after its private MAC changed.";
        }
        catch (Exception exception) when (
            exception is IOException or InvalidOperationException)
        {
            DetailStatusText.Text = exception.Message;
        }
        finally
        {
            identitySaveSync.Release();
        }
    }

    private async void MainWindow_OnClosing(object? sender, CancelEventArgs eventArgs)
    {
        autoScanTimer.Stop();
        scriptAutomationTimer.Stop();
        scriptRunCancellation.Cancel();
        if (closeAfterStop ||
            (!engine.IsRunning && activeScriptRunTask is null))
        {
            return;
        }

        eventArgs.Cancel = true;
        IsEnabled = false;
        try
        {
            if (activeScriptRunTask is not null)
            {
                await activeScriptRunTask;
            }

            if (engine.IsRunning)
            {
                await StopEngineAsync();
                await engine.DisposeAsync();
            }
        }
        finally
        {
            closeAfterStop = true;
            Close();
        }
    }

    private void UpdateButtons()
    {
        StartButton.IsEnabled = !operationInProgress &&
                                !engine.IsRunning &&
                                AdapterSelector.SelectedItem is AdapterProfile;
        StopButton.IsEnabled = !operationInProgress && engine.IsRunning;
        var hasAdapter = AdapterSelector.SelectedItem is AdapterProfile;
        ScanButton.IsEnabled = !operationInProgress && hasAdapter;
        AutoScanCheckBox.IsEnabled = !operationInProgress && hasAdapter;
        AutoScanIntervalTextBox.IsEnabled = !operationInProgress && hasAdapter;
        UpdateScriptAutomationControls();
        ClearDeviceCacheButton.IsEnabled = !operationInProgress;
        AdapterSelector.IsEnabled = !operationInProgress && !engine.IsRunning;
        StartButton.Visibility = engine.IsRunning ? Visibility.Collapsed : Visibility.Visible;
        ScanButton.Visibility = AdapterSelector.SelectedItem is AdapterProfile
            ? Visibility.Visible
            : Visibility.Collapsed;
        StopButton.Visibility = engine.IsRunning ? Visibility.Visible : Visibility.Collapsed;
    }

    private void MinimizeWindowButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        WindowState = WindowState.Minimized;
    }

    private void MaximizeWindowButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;
    }

    private void CloseWindowButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        Close();
    }

    private void NavigationButton_OnClick(object sender, RoutedEventArgs eventArgs)
    {
        if (sender is not Button { Tag: string targetName } ||
            FindName(targetName) is not FrameworkElement target)
        {
            return;
        }

        SetVisiblePage(target);
        MainScrollViewer.ScrollToTop();
        if (target == OverviewSection)
        {
            target.BringIntoView();
        }

        if (target == AdapterStrip)
        {
            AdapterSelector.Focus();
        }
    }

    private void SetVisiblePage(FrameworkElement target)
    {
        var showOverview = target == OverviewSection;
        var overviewVisibility = showOverview ? Visibility.Visible : Visibility.Collapsed;
        OverviewSection.Visibility = overviewVisibility;
        AdapterStrip.Visibility = overviewVisibility;
        MetricsPanel.Visibility = overviewVisibility;
        ActivitySection.Visibility = overviewVisibility;
        DeviceSection.Visibility = overviewVisibility;
        WebsiteActivitySection.Visibility = target == WebsiteActivitySection
            ? Visibility.Visible
            : Visibility.Collapsed;
        DomainRulesSection.Visibility = target == DomainRulesSection
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void UpdateAdapterSummary()
    {
        if (AdapterSelector.SelectedItem is not AdapterProfile selected)
        {
            LocalIpText.Text = "-";
            GatewayIpText.Text = "-";
            return;
        }

        LocalIpText.Text = selected.LocalAddress.ToString();
        GatewayIpText.Text = selected.GatewayAddress.ToString();
    }

    private void RefreshDashboardSummary(bool addTrafficSample = true)
    {
        var summary = DashboardSummary.From(Devices);
        ConnectedDevicesMetric.Text = summary.ConnectedDevices.ToString();
        DownloadMetric.Text = DeviceViewModel.FormatRate(summary.DownloadBytesPerSecond);
        UploadMetric.Text = DeviceViewModel.FormatRate(summary.UploadBytesPerSecond);
        ActiveRulesMetric.Text = summary.ActiveRules.ToString();

        if (addTrafficSample && engine.IsRunning)
        {
            var sample = summary.ToTrafficSample(DateTimeOffset.UtcNow);
            if (trafficHistory.TryAdd(sample, TrafficSamplingProfile.Interval))
            {
                TrafficChart.Samples = trafficHistory.Samples;
                ChartDeviceSummaryText.Text = TrafficChartPresentation.BuildLatestSummary(sample);
            }
        }

        if (controlStartedAt is { } startedAt)
        {
            var elapsed = DateTimeOffset.UtcNow - startedAt;
            UptimeText.Text = $"Active {elapsed:hh\\:mm\\:ss}";
        }
    }

    private static string FormatMac(string macKey) =>
        string.Join(
            ":",
            Enumerable.Range(0, 6).Select(index => macKey.Substring(index * 2, 2)));

    private void SetStatus(string message, bool? active)
    {
        TopStatusText.Text = active switch
        {
            true => "Active",
            false => "Needs attention",
            null => engine.IsRunning ? "Working" : "Idle",
        };
        DetailStatusText.Text = message;
        StatusDot.Fill = new SolidColorBrush(
            active switch
            {
                true => Color.FromRgb(104, 192, 138),
                false => Color.FromRgb(240, 100, 115),
                null => Color.FromRgb(168, 144, 149),
            });
    }
}
