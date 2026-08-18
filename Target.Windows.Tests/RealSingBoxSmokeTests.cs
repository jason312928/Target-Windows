using Target.Windows.Runtime;
using Xunit;

namespace Target.Windows.Tests;

public sealed class RealSingBoxSmokeTests
{
    [Fact]
    [Trait("Category", "RealEngineSmoke")]
    public async Task SyntheticLoopbackRuntimeStartsProvesOwnershipAndStopsWhenEnabled()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable("TARGET_REAL_SING_BOX_SMOKE"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        using var profile = new ProfileFixture(
            """{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}"""u8.ToArray());
        await using var runtime = new WindowsSingBoxRuntime(profile.Store);
        var started = false;
        try
        {
            var before = await runtime.QueryAsync();
            Assert.Equal(RuntimeDispositionKind.NoRecord, before.Disposition);

            var running = await runtime.StartAsync();
            started = true;
            Assert.True(running.IsRunning);
            Assert.Equal("1.13.16", running.EngineVersion);
            Assert.Equal("127.0.0.1", running.PrimaryHost);
            Assert.NotNull(running.PrimaryPort);
            Assert.InRange(running.PrimaryPort.Value, 49_152, 65_535);

            var proven = await runtime.QueryAsync();
            Assert.Equal(RuntimeDispositionKind.OwnedRunning, proven.Disposition);

            var stopped = await runtime.StopAsync();
            started = false;
            Assert.Equal(RuntimeDispositionKind.NoRecord, stopped.Disposition);
            Assert.False(Directory.Exists(SingBoxEngineLocation.GetProductionRuntimeRoot()));
        }
        finally
        {
            if (started)
            {
                try
                {
                    await runtime.StopAsync();
                }
                catch
                {
                    // Fail closed: leave evidence intact if ownership cannot be re-proven.
                }
            }
        }
    }
}
