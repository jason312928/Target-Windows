using Target.Windows.App;
using Xunit;

namespace Target.Windows.Tests;

public sealed class AppDestinationTests
{
    [Fact]
    public void DestinationsHaveTheExpectedStableOrder()
    {
        Assert.Equal(
        [
            AppDestination.Dashboard,
            AppDestination.Profiles,
            AppDestination.Connections,
            AppDestination.Traffic,
            AppDestination.Logs
        ], AppDestinations.All);
    }

    [Fact]
    public void DefaultDestinationIsDashboard()
    {
        Assert.Equal(AppDestination.Dashboard, AppDestinations.Default);
    }

    [Theory]
    [InlineData("dashboard", AppDestination.Dashboard)]
    [InlineData("profiles", AppDestination.Profiles)]
    [InlineData("connections", AppDestination.Connections)]
    [InlineData("traffic", AppDestination.Traffic)]
    [InlineData("logs", AppDestination.Logs)]
    public void StableKeysParseToTheirDestinations(string key, AppDestination expected)
    {
        Assert.True(AppDestinations.TryParseKey(key, out var destination));
        Assert.Equal(expected, destination);
        Assert.Equal(key, AppDestinations.GetKey(destination));
    }

    [Fact]
    public void UnknownKeyFailsAndFallsBackToDashboard()
    {
        Assert.False(AppDestinations.TryParseKey("unknown", out var destination));
        Assert.Equal(AppDestination.Dashboard, destination);
    }
}
