using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Target.Windows.App;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        SelectDestination(AppDestinations.Default);
    }

    private void ShellNavigationView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item &&
            AppDestinations.TryParseKey(item.Tag as string, out var destination))
        {
            SelectDestination(destination);
        }
    }

    private void SelectDestination(AppDestination destination)
    {
        DestinationTitle.Text = AppDestinations.GetTitle(destination);
        DestinationDescription.Text = GetDescription(destination);
        ShellNavigationView.SelectedItem = ShellNavigationView.MenuItems
            .OfType<NavigationViewItem>()
            .Single(item => item.Tag as string == AppDestinations.GetKey(destination));
    }

    private static string GetDescription(AppDestination destination) => destination switch
    {
        AppDestination.Dashboard => "Your Target Windows workspace is ready for future configuration and runtime features.",
        AppDestination.Profiles => "Profiles workspace. Profile management is not implemented yet.",
        AppDestination.Connections => "Connections workspace. Connection collection is not implemented yet.",
        AppDestination.Traffic => "Traffic workspace. Traffic statistics are not implemented yet.",
        AppDestination.Logs => "Logs workspace. Runtime log integration is not implemented yet.",
        _ => throw new ArgumentOutOfRangeException(nameof(destination), destination, null)
    };
}
