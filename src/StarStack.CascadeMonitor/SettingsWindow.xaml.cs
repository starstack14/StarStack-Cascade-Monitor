using System.Windows;

namespace StarStack.CascadeMonitor;
public partial class SettingsWindow : Window
{
    private readonly AppSettings _settings;
    public SettingsWindow(AppSettings settings) { InitializeComponent(); _settings = settings; RouterHost.Text = settings.RouterHost; KeyPath.Text = settings.PrivateKeyPath; PanelUrl.Text = settings.PanelUrl; AccessQuery.Text = settings.AccessQuery; ApiToken.Password = settings.ApiToken; Notifications.IsChecked = settings.NotificationsEnabled; AutoStart.IsChecked = settings.AutoStart; CompactMode.IsChecked = settings.CompactMode; AutoUpdate.IsChecked = settings.AutoUpdate; LanguageSelect.SelectedValue = settings.Language; Profile.SelectedValue = settings.ActiveProfile; }
    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();
    private void Save_Click(object sender, RoutedEventArgs e) { _settings.RouterHost = RouterHost.Text.Trim(); _settings.PrivateKeyPath = KeyPath.Text.Trim(); _settings.PanelUrl = PanelUrl.Text.Trim(); _settings.AccessQuery = AccessQuery.Text.Trim(); if (!string.IsNullOrWhiteSpace(ApiToken.Password)) _settings.SetApiToken(ApiToken.Password); _settings.NotificationsEnabled = Notifications.IsChecked == true; _settings.AutoStart = AutoStart.IsChecked == true; _settings.CompactMode = CompactMode.IsChecked == true; _settings.AutoUpdate = AutoUpdate.IsChecked == true; if (LanguageSelect.SelectedItem is System.Windows.Controls.ComboBoxItem lang) _settings.Language = lang.Tag?.ToString() ?? "ru"; if (Profile.SelectedItem is System.Windows.Controls.ComboBoxItem item) _settings.ActiveProfile = item.Tag?.ToString() ?? "home"; _settings.Save(); DialogResult = true; Close(); }
}
