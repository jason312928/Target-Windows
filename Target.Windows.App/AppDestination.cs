namespace Target.Windows.App;

public enum AppDestination
{
    Dashboard,
    Profiles,
    Connections,
    Traffic,
    Logs
}

public static class AppDestinations
{
    public static readonly AppDestination[] All =
    [
        AppDestination.Dashboard,
        AppDestination.Profiles,
        AppDestination.Connections,
        AppDestination.Traffic,
        AppDestination.Logs
    ];

    public const AppDestination Default = AppDestination.Dashboard;

    public static string GetKey(AppDestination destination) => destination switch
    {
        AppDestination.Dashboard => "dashboard",
        AppDestination.Profiles => "profiles",
        AppDestination.Connections => "connections",
        AppDestination.Traffic => "traffic",
        AppDestination.Logs => "logs",
        _ => throw new ArgumentOutOfRangeException(nameof(destination), destination, null)
    };

    public static string GetTitle(AppDestination destination) => destination switch
    {
        AppDestination.Dashboard => "Dashboard",
        AppDestination.Profiles => "Profiles",
        AppDestination.Connections => "Connections",
        AppDestination.Traffic => "Traffic",
        AppDestination.Logs => "Logs",
        _ => throw new ArgumentOutOfRangeException(nameof(destination), destination, null)
    };

    public static bool TryParseKey(string? key, out AppDestination destination)
    {
        switch (key)
        {
            case "dashboard":
                destination = AppDestination.Dashboard;
                return true;
            case "profiles":
                destination = AppDestination.Profiles;
                return true;
            case "connections":
                destination = AppDestination.Connections;
                return true;
            case "traffic":
                destination = AppDestination.Traffic;
                return true;
            case "logs":
                destination = AppDestination.Logs;
                return true;
            default:
                destination = Default;
                return false;
        }
    }
}
