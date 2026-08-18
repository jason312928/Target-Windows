using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Target.Windows.Core;
using Target.Windows.Runtime;
using Xunit;

namespace Target.Windows.Tests;

public sealed class RuntimeConfigurationTests
{
    [Fact]
    public void OutboundOnlyConfigurationAddsUniqueLoopbackMixedInboundWithoutPersistingChanges()
    {
        var source = Encoding.UTF8.GetBytes("""{"outbounds":[{"type":"direct","tag":"direct"}]}""");
        using var fixture = new ProfileFixture(source);
        var before = source.ToArray();

        var prepared = new RuntimeConfigurationPreparer(new SequencePortAllocator(51_201))
            .Prepare(fixture.Store);

        using var document = JsonDocument.Parse(prepared.Data);
        var inbound = Assert.Single(document.RootElement.GetProperty("inbounds").EnumerateArray());
        Assert.Equal("mixed", inbound.GetProperty("type").GetString());
        Assert.StartsWith("target-mixed", inbound.GetProperty("tag").GetString());
        Assert.Equal("127.0.0.1", inbound.GetProperty("listen").GetString());
        Assert.Equal(51_201, inbound.GetProperty("listen_port").GetInt32());
        Assert.Equal(before, source);
        Assert.Equal(before, fixture.Store.ReadCurrentConfiguration(fixture.ProfileId).Content);
        Assert.Equal(Sha256(source), prepared.SourceConfigurationSha256);
        Assert.Equal(Sha256(prepared.Data), prepared.RuntimeConfigurationSha256);
    }

    [Fact]
    public void ExistingLoopbackInboundPortsAreRewrittenAndMixedIsPrimary()
    {
        var source = """
            {"inbounds":[
              {"type":"socks","tag":"socks","listen":"127.0.0.1","listen_port":1080},
              {"type":"mixed","tag":"mixed","listen":"127.0.0.1","listen_port":2080}
            ],"outbounds":[{"type":"direct"}]}
            """u8.ToArray();
        using var fixture = new ProfileFixture(source);

        var prepared = new RuntimeConfigurationPreparer(new SequencePortAllocator(51_202, 51_203))
            .Prepare(fixture.Store);

        using var document = JsonDocument.Parse(prepared.Data);
        var inbounds = document.RootElement.GetProperty("inbounds").EnumerateArray().ToArray();
        Assert.Equal([51_202, 51_203], inbounds.Select(item => item.GetProperty("listen_port").GetInt32()).ToArray());
        Assert.All(inbounds, item => Assert.Equal("127.0.0.1", item.GetProperty("listen").GetString()));
        Assert.Equal(51_203, prepared.PrimaryPort);
    }

    [Theory]
    [MemberData(nameof(UnsafeConfigurations))]
    public void UnsafeConfigurationsFailClosed(string configuration)
    {
        using var fixture = new ProfileFixture(Encoding.UTF8.GetBytes(configuration));

        var error = Assert.Throws<RuntimeConfigurationException>(() =>
            new RuntimeConfigurationPreparer(new SequencePortAllocator(51_210)).Prepare(fixture.Store));

        Assert.Equal(RuntimeConfigurationFailure.UnsafeConfiguration, error.Failure);
    }

    public static TheoryData<string> UnsafeConfigurations => new()
    {
        """{"inbounds":[{"type":"tun","listen":"127.0.0.1"}]}""",
        """{"inbounds":[{"type":"redirect","listen":"127.0.0.1"}]}""",
        """{"inbounds":[{"type":"tproxy","listen":"127.0.0.1"}]}""",
        """{"inbounds":[{"type":"mixed","listen":"0.0.0.0"}]}""",
        """{"inbounds":[{"type":"mixed","listen":"::1"}]}""",
        """{"route":{"rule_set":[{"path":"C:\\Target\\rules.json"}]}}""",
        """{"route":{"rule_set":[{"path":"\\\\server\\share\\rules.json"}]}}""",
        """{"route":{"rule_set":[{"path":"/var/tmp/rules.json"}]}}""",
        """{"route":{"rule_set":[{"path":"..\\rules.json"}]}}""",
        """{"route":{"rule_set":[{"path":"../rules.json"}]}}""",
        """{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}"""
    };

    [Fact]
    public void WebSocketTransportPathIsNotMistakenForAFilePath()
    {
        var source = """
            {"inbounds":[{"type":"mixed","listen":"127.0.0.1"}],
             "outbounds":[{"type":"vmess","server":"example.invalid","server_port":443,
               "transport":{"type":"ws","path":"/synthetic-ws"}}]}
            """u8.ToArray();
        using var fixture = new ProfileFixture(source);

        var prepared = new RuntimeConfigurationPreparer(new SequencePortAllocator(51_220))
            .Prepare(fixture.Store);

        using var document = JsonDocument.Parse(prepared.Data);
        Assert.Equal(
            "/synthetic-ws",
            document.RootElement.GetProperty("outbounds")[0].GetProperty("transport").GetProperty("path").GetString());
    }

    [Fact]
    public void ConfigurationWithoutMixedInboundIsRejected()
    {
        var source = """{"inbounds":[{"type":"socks","listen":"127.0.0.1"}]}"""u8.ToArray();
        using var fixture = new ProfileFixture(source);

        var error = Assert.Throws<RuntimeConfigurationException>(() =>
            new RuntimeConfigurationPreparer(new SequencePortAllocator(51_230)).Prepare(fixture.Store));

        Assert.Equal(RuntimeConfigurationFailure.NoUsableMixedInbound, error.Failure);
    }

    private static string Sha256(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}

internal sealed class SequencePortAllocator(params ushort[] ports) : IDynamicHighPortAllocator
{
    private readonly Queue<ushort> ports = new(ports);

    public ushort Allocate()
    {
        if (ports.Count == 0)
        {
            throw new InvalidOperationException("No synthetic ports remain.");
        }

        return ports.Dequeue();
    }
}

internal sealed class ProfileFixture : IDisposable
{
    private readonly TemporaryDirectory directory = new("TargetRuntimeProfileTests");
    private readonly byte[] key = RandomNumberGenerator.GetBytes(32);

    public ProfileFixture(byte[] configuration)
    {
        Store = ProfileStore.Open(directory.Path, new FixedRuntimeTestKeyProvider(key));
        ProfileId = Store.CreateProfile("Synthetic", configuration).Id;
    }

    public ProfileStore Store { get; }
    public Guid ProfileId { get; }

    public void Dispose()
    {
        Store.Dispose();
        CryptographicOperations.ZeroMemory(key);
        directory.Dispose();
    }
}

internal sealed class FixedRuntimeTestKeyProvider(byte[] key) : IProfileEncryptionKeyProvider
{
    public byte[] GetKey(ProfileKeyAccess access) => key.ToArray();
}

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory(string category)
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), category, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }
}

internal sealed class FakeCommands : ISingBoxCommandExecutor
{
    public BoundedCommandResult VersionResult { get; set; } =
        new(0, "sing-box version 1.13.16", string.Empty, false);
    public BoundedCommandResult CheckResult { get; set; } =
        new(0, string.Empty, string.Empty, false);
    public int VersionCalls { get; private set; }
    public int CheckCalls { get; private set; }
    public List<string>? Operations { get; set; }

    public Task<BoundedCommandResult> VersionAsync(CancellationToken cancellationToken)
    {
        VersionCalls++;
        Operations?.Add("version");
        return Task.FromResult(VersionResult);
    }

    public Task<BoundedCommandResult> CheckAsync(string runtimeConfigurationPath, CancellationToken cancellationToken)
    {
        Assert.True(File.Exists(runtimeConfigurationPath));
        CheckCalls++;
        Operations?.Add("check");
        return Task.FromResult(CheckResult);
    }
}
