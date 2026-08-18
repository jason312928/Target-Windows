using Target.Windows.Runtime;
using Xunit;

namespace Target.Windows.Tests;

public sealed class SingBoxEngineTests
{
    [Fact]
    public void ProductionPathIsFixedToPerUserTargetDirectory()
    {
        var expected = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Target",
            "sing-box",
            "bin",
            "sing-box.exe"));

        Assert.Equal(expected, SingBoxEngineLocation.Production().ExecutablePath, ignoreCase: true);
    }

    [Fact]
    public async Task MissingEngineDoesNotRunVersionCommand()
    {
        using var directory = new TemporaryDirectory("TargetEngineTests");
        var commands = new FakeCommands();
        var discovery = new SingBoxEngineDiscovery(
            SingBoxEngineLocation.ForTesting(Path.Combine(directory.Path, "sing-box.exe")),
            commands);

        var status = await discovery.GetStatusAsync();

        Assert.Equal(SingBoxEngineStatusKind.NotInstalled, status.Kind);
        Assert.Equal(0, commands.VersionCalls);
    }

    [Theory]
    [InlineData(0, "unexpected output", false)]
    [InlineData(1, "sing-box version 1.13.16", false)]
    [InlineData(-1, "", true)]
    public async Task MalformedNonZeroAndTimedOutVersionAreInvalid(
        int exitCode,
        string output,
        bool timedOut)
    {
        using var fixture = new EngineFixture();
        fixture.Commands.VersionResult = new BoundedCommandResult(exitCode, output, "bounded", timedOut);

        var status = await fixture.Discovery.GetStatusAsync();

        Assert.Equal(SingBoxEngineStatusKind.Invalid, status.Kind);
        Assert.Null(status.Version);
    }

    [Fact]
    public async Task CorrectFirstLineParsesInstalledVersion()
    {
        using var fixture = new EngineFixture();
        fixture.Commands.VersionResult = new BoundedCommandResult(
            0,
            "sing-box version 1.13.16\r\nenvironment: synthetic",
            string.Empty,
            false);

        var status = await fixture.Discovery.GetStatusAsync();

        Assert.Equal(SingBoxEngineStatusKind.Installed, status.Kind);
        Assert.Equal("1.13.16", status.Version);
    }

    private sealed class EngineFixture : IDisposable
    {
        private readonly TemporaryDirectory directory = new("TargetEngineTests");

        public EngineFixture()
        {
            var executable = Path.Combine(directory.Path, "sing-box.exe");
            File.WriteAllText(executable, "synthetic executable fixture");
            Commands = new FakeCommands();
            Discovery = new SingBoxEngineDiscovery(
                SingBoxEngineLocation.ForTesting(executable),
                Commands);
        }

        public FakeCommands Commands { get; }
        public SingBoxEngineDiscovery Discovery { get; }
        public void Dispose() => directory.Dispose();
    }
}
