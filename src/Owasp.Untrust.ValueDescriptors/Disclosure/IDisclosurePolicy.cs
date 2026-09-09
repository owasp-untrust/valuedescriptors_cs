namespace Owasp.Untrust.ValueDescriptors.Disclosure;

/// <summary>A mandatory compile-time disclosure decision.</summary>
public interface IDisclosurePolicy<TValue>
    where TValue : notnull
{
    static abstract object? ToPublicValue(TValue value);

    static abstract string ToPublicString(TValue value);
}

public interface IValueMasker<TValue>
    where TValue : notnull
{
    static abstract string Mask(TValue value);
}
