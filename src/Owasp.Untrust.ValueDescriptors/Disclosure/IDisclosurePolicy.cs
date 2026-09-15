namespace Owasp.Untrust.ValueDescriptors.Disclosure;

/// <summary>A mandatory compile-time disclosure decision.</summary>
public interface IDisclosurePolicy<TValue>
    where TValue : notnull
{
    static abstract string ToPublicString(TValue value);
}

/// <summary>
/// A disclosure policy that explicitly permits the underlying typed value to be
/// emitted as a public representation, including by serialization integrations.
/// </summary>
public interface IPublicDisclosurePolicy<TValue> : IDisclosurePolicy<TValue>
    where TValue : notnull
{
    static abstract TValue PublicValue(TValue value);
}

public interface IValueMasker<TValue>
    where TValue : notnull
{
    static abstract string Mask(TValue value);
}
