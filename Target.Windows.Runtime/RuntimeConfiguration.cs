using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Target.Windows.Core;

namespace Target.Windows.Runtime;

public interface IDynamicHighPortAllocator
{
    ushort Allocate();
}

public sealed class WindowsDynamicHighPortAllocator : IDynamicHighPortAllocator
{
    private const int FirstHighPort = 49_152;
    private const int Attempts = 32;

    public ushort Allocate()
    {
        for (var attempt = 0; attempt < Attempts; attempt++)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            if (port >= FirstHighPort && port <= ushort.MaxValue)
            {
                return (ushort)port;
            }
        }

        throw new RuntimeConfigurationException(
            RuntimeConfigurationFailure.PortUnavailable,
            "A high loopback port could not be allocated.");
    }
}

public sealed record PreparedRuntimeConfiguration(
    Guid RuntimeConfigurationId,
    Guid ProfileId,
    long ProfileRevision,
    string SourceConfigurationSha256,
    string RuntimeConfigurationSha256,
    string PrimaryHost,
    ushort PrimaryPort,
    byte[] Data);

public sealed class RuntimeConfigurationPreparer
{
    private const int MaximumSourceBytes = 10 * 1024 * 1024;
    private const ushort FirstDynamicPort = 49_152;
    private static readonly HashSet<string> RejectedControllerKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "clash_api",
        "external_controller",
        "external_ui",
        "external_ui_download_url",
        "external_ui_download_detour",
        "v2ray_api"
    };

    private readonly IDynamicHighPortAllocator portAllocator;

    public RuntimeConfigurationPreparer(IDynamicHighPortAllocator? portAllocator = null)
    {
        this.portAllocator = portAllocator ?? new WindowsDynamicHighPortAllocator();
    }

    public PreparedRuntimeConfiguration Prepare(ProfileStore profileStore)
    {
        ArgumentNullException.ThrowIfNull(profileStore);
        var profileId = profileStore.SelectedProfileId
            ?? throw new RuntimeConfigurationException(
                RuntimeConfigurationFailure.ProfileNotSelected,
                "A selected profile is required.");

        ProfileConfiguration source;
        try
        {
            source = profileStore.ReadCurrentConfiguration(profileId);
        }
        catch (Exception exception) when (exception is ProfileStorageException or InvalidOperationException)
        {
            throw new RuntimeConfigurationException(
                RuntimeConfigurationFailure.InvalidJson,
                "The selected profile configuration could not be read.");
        }

        if (source.Content.Length == 0 || source.Content.Length > MaximumSourceBytes)
        {
            CryptographicOperations.ZeroMemory(source.Content);
            throw new RuntimeConfigurationException(
                RuntimeConfigurationFailure.SourceTooLarge,
                "The selected profile configuration is outside the supported size limit.");
        }

        try
        {
            var sourceFingerprint = Sha256(source.Content);
            JsonObject root;
            try
            {
                root = JsonNode.Parse(source.Content) as JsonObject
                    ?? throw new InvalidOperationException();
            }
            catch
            {
                throw new RuntimeConfigurationException(
                    RuntimeConfigurationFailure.InvalidJson,
                    "The selected profile configuration is not a JSON object.");
            }

            RejectUnsafeValues(root);

            var inbounds = ReadInbounds(root);
            if (inbounds.Count == 0)
            {
                inbounds.Add(new JsonObject
                {
                    ["type"] = "mixed",
                    ["tag"] = CreateTargetInboundTag(root),
                    ["listen"] = SingBoxEngineConstants.PrimaryHost,
                    ["listen_port"] = 0
                });
            }

            var usedPorts = new HashSet<ushort>();
            ushort? primaryPort = null;
            foreach (var inbound in inbounds)
            {
                var type = ReadRequiredString(inbound, "type");
                if (type is null || type.Equals("tun", StringComparison.OrdinalIgnoreCase)
                    || type.Equals("redirect", StringComparison.OrdinalIgnoreCase)
                    || type.Equals("tproxy", StringComparison.OrdinalIgnoreCase))
                {
                    throw UnsafeConfiguration();
                }

                if (!string.Equals(ReadRequiredString(inbound, "listen"), SingBoxEngineConstants.PrimaryHost, StringComparison.Ordinal))
                {
                    throw UnsafeConfiguration();
                }

                var port = AllocateUniquePort(usedPorts);
                inbound["listen"] = SingBoxEngineConstants.PrimaryHost;
                inbound["listen_port"] = port;
                if (type.Equals("mixed", StringComparison.OrdinalIgnoreCase) && primaryPort is null)
                {
                    primaryPort = port;
                }
            }

            if (primaryPort is null)
            {
                throw new RuntimeConfigurationException(
                    RuntimeConfigurationFailure.NoUsableMixedInbound,
                    "The runtime configuration has no usable loopback mixed inbound.");
            }

            root["inbounds"] = new JsonArray(inbounds.Select(inbound => inbound.DeepClone()).ToArray());
            var data = JsonSerializer.SerializeToUtf8Bytes(root, new JsonSerializerOptions
            {
                WriteIndented = false
            });
            if (data.Length == 0 || data.Length > MaximumSourceBytes)
            {
                throw new RuntimeConfigurationException(
                    RuntimeConfigurationFailure.SourceTooLarge,
                    "The prepared runtime configuration is outside the supported size limit.");
            }

            return new PreparedRuntimeConfiguration(
                Guid.NewGuid(),
                profileId,
                source.Revision,
                sourceFingerprint,
                Sha256(data),
                SingBoxEngineConstants.PrimaryHost,
                primaryPort.Value,
                data);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(source.Content);
        }
    }

    private List<JsonObject> ReadInbounds(JsonObject root)
    {
        if (root["inbounds"] is null)
        {
            return [];
        }

        if (root["inbounds"] is not JsonArray array)
        {
            throw UnsafeConfiguration();
        }

        var result = new List<JsonObject>(array.Count);
        foreach (var node in array)
        {
            if (node is not JsonObject inbound)
            {
                throw UnsafeConfiguration();
            }

            result.Add(inbound);
        }

        return result;
    }

    private ushort AllocateUniquePort(HashSet<ushort> usedPorts)
    {
        for (var attempt = 0; attempt < 64; attempt++)
        {
            var port = AllocatePort();
            if (usedPorts.Add(port))
            {
                return port;
            }
        }

        throw new RuntimeConfigurationException(
            RuntimeConfigurationFailure.PortUnavailable,
            "Unique loopback ports could not be allocated.");
    }

    private ushort AllocatePort()
    {
        try
        {
            var port = portAllocator.Allocate();
            if (port < FirstDynamicPort)
            {
                throw new InvalidOperationException();
            }

            return port;
        }
        catch (RuntimeConfigurationException)
        {
            throw;
        }
        catch
        {
            throw new RuntimeConfigurationException(
                RuntimeConfigurationFailure.PortUnavailable,
                "A loopback port could not be allocated.");
        }
    }

    private static string? ReadRequiredString(JsonObject value, string key)
    {
        if (value[key] is not JsonValue jsonValue)
        {
            return null;
        }

        try
        {
            return jsonValue.GetValue<string>();
        }
        catch
        {
            return null;
        }
    }

    private static string CreateTargetInboundTag(JsonObject root)
    {
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in new[] { "inbounds", "outbounds" })
        {
            if (root[key] is not JsonArray array)
            {
                continue;
            }

            foreach (var item in array.OfType<JsonObject>())
            {
                var tag = ReadRequiredString(item, "tag");
                if (!string.IsNullOrWhiteSpace(tag))
                {
                    used.Add(tag);
                }
            }
        }

        var candidate = "target-mixed";
        var suffix = 2;
        while (!used.Add(candidate))
        {
            candidate = $"target-mixed-{suffix++}";
        }

        return candidate;
    }

    private static void RejectUnsafeValues(JsonNode node, string? key = null, IReadOnlyList<string>? ancestors = null)
    {
        ancestors ??= [];
        if (key is not null && RejectedControllerKeys.Contains(key))
        {
            throw UnsafeConfiguration();
        }

        if (node is JsonObject objectNode)
        {
            foreach (var property in objectNode)
            {
                RejectUnsafeValues(property.Value!, property.Key, [.. ancestors, key ?? string.Empty]);
            }

            return;
        }

        if (node is JsonArray arrayNode)
        {
            foreach (var child in arrayNode)
            {
                if (child is not null)
                {
                    RejectUnsafeValues(child, key, ancestors);
                }
            }

            return;
        }

        if (node is not JsonValue valueNode)
        {
            return;
        }

        string? value;
        try
        {
            value = valueNode.GetValue<string>();
        }
        catch
        {
            return;
        }

        var isTransportPath = string.Equals(key, "path", StringComparison.OrdinalIgnoreCase)
            && ancestors.Any(item => string.Equals(item, "transport", StringComparison.OrdinalIgnoreCase));
        var isFileUri = Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.IsFile;
        if (isFileUri
            || value.Contains("../", StringComparison.Ordinal)
            || value.Contains("..\\", StringComparison.Ordinal)
            || value.EndsWith("/..", StringComparison.Ordinal)
            || value.EndsWith("\\..", StringComparison.Ordinal)
            || value.Equals("..", StringComparison.Ordinal)
            || value.StartsWith("\\", StringComparison.Ordinal)
            || value.StartsWith("\\\\", StringComparison.Ordinal)
            || value.StartsWith("//", StringComparison.Ordinal)
            || (value.Length >= 2 && char.IsLetter(value[0]) && value[1] == ':')
            || (!isTransportPath && value.StartsWith("/", StringComparison.Ordinal)))
        {
            throw UnsafeConfiguration();
        }
    }

    private static RuntimeConfigurationException UnsafeConfiguration() =>
        new(RuntimeConfigurationFailure.UnsafeConfiguration, "The profile configuration is outside the Host-Safe runtime boundary.");

    private static string Sha256(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
