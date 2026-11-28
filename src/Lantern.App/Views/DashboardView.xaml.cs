using System.Windows;
using System.Windows.Controls;

namespace Lantern.App.Views;

public partial class DashboardView : UserControl
{
    private readonly MainWindow owner;

    public DashboardView(MainWindow owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        this.owner = owner;
        InitializeComponent();
        DataContext = owner;
    }

    private void MinimizeWindowButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.MinimizeWindowButton_OnClick(sender, eventArgs);

    private void MaximizeWindowButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.MaximizeWindowButton_OnClick(sender, eventArgs);

    private void CloseWindowButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.CloseWindowButton_OnClick(sender, eventArgs);

    private void NavigationButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.NavigationButton_OnClick(sender, eventArgs);

    private void AdapterSelector_OnSelectionChanged(object sender, SelectionChangedEventArgs eventArgs) => owner.AdapterSelector_OnSelectionChanged(sender, eventArgs);

    private void StartButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.StartButton_OnClick(sender, eventArgs);

    private void ScanButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.ScanButton_OnClick(sender, eventArgs);

    private void AutoScanCheckBox_OnClick(object sender, RoutedEventArgs eventArgs) => owner.AutoScanCheckBox_OnClick(sender, eventArgs);

    private void AutoScanIntervalTextBox_OnLostFocus(object sender, RoutedEventArgs eventArgs) => owner.AutoScanIntervalTextBox_OnLostFocus(sender, eventArgs);

    private void StopButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.StopButton_OnClick(sender, eventArgs);

    private void ClearActivityButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.ClearActivityButton_OnClick(sender, eventArgs);

    private void BlockVisitedDomainButton_OnClick(
        object sender,
        RoutedEventArgs eventArgs) => owner.BlockVisitedDomainButton_OnClick(sender, eventArgs);

    private void ApplyDomainPresetButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.ApplyDomainPresetButton_OnClick(sender, eventArgs);

    private void AddDomainRuleButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.AddDomainRuleButton_OnClick(sender, eventArgs);

    private void RemoveDomainPresetButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.RemoveDomainPresetButton_OnClick(sender, eventArgs);

    private void RemoveDomainRuleButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.RemoveDomainRuleButton_OnClick(sender, eventArgs);

    private void ClearDeviceCacheButton_OnClick(
        object sender,
        RoutedEventArgs eventArgs) => owner.ForwardClearDeviceCacheButton_OnClick(sender, eventArgs);

    private void DeviceGrid_OnLoadingRow(object? sender, DataGridRowEventArgs eventArgs) => owner.DeviceGrid_OnLoadingRow(sender, eventArgs);

    private void CopyAutomationScriptButton_OnClick(
        object sender,
        RoutedEventArgs eventArgs) => owner.CopyAutomationScriptButton_OnClick(sender, eventArgs);

    private void BrowseScriptButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.BrowseScriptButton_OnClick(sender, eventArgs);

    private void SaveScriptButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.SaveScriptButton_OnClick(sender, eventArgs);

    private void SaveScriptAsButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.SaveScriptAsButton_OnClick(sender, eventArgs);

    private void RunScriptNowButton_OnClick(
        object sender,
        RoutedEventArgs eventArgs) => owner.RunScriptNowButton_OnClick(sender, eventArgs);

    private void ScriptAutomationCheckBox_OnClick(
        object sender,
        RoutedEventArgs eventArgs) => owner.ScriptAutomationCheckBox_OnClick(sender, eventArgs);

    private void ScriptAutomationIntervalTextBox_OnLostFocus(
        object sender,
        RoutedEventArgs eventArgs) => owner.ScriptAutomationIntervalTextBox_OnLostFocus(sender, eventArgs);

    private void ScriptEditorTextBox_OnTextChanged(
        object sender,
        TextChangedEventArgs eventArgs) => owner.ScriptEditorTextBox_OnTextChanged(sender, eventArgs);

    private void AddNetworkAutomationButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.AddNetworkAutomationButton_OnClick(sender, eventArgs);

    private void NetworkAutomationPollIntervalTextBox_OnLostFocus(
        object sender,
        RoutedEventArgs eventArgs) => owner.NetworkAutomationPollIntervalTextBox_OnLostFocus(sender, eventArgs);

    private void NetworkAutomationEnabledCheckBox_OnClick(object sender, RoutedEventArgs eventArgs) => owner.NetworkAutomationEnabledCheckBox_OnClick(sender, eventArgs);

    private void DeleteNetworkAutomationButton_OnClick(object sender, RoutedEventArgs eventArgs) => owner.DeleteNetworkAutomationButton_OnClick(sender, eventArgs);
}
