namespace Target.Windows.Core;

public sealed record Profile(
    Guid Id,
    string Name,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    long CurrentRevision);

public sealed record ProfileConfiguration(long Revision, byte[] Content);
