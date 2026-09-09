using System.Globalization;

namespace Owasp.Untrust.ValueDescriptors.Disclosure;

public readonly struct Public<TValue> : IDisclosurePolicy<TValue>
    where TValue : notnull
{
    public static object ToPublicValue(TValue value) => value;
    public static string ToPublicString(TValue value) => value switch
    {
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? string.Empty,
    };
}

public readonly struct RedactedPii<TValue> : IDisclosurePolicy<TValue>
    where TValue : notnull
{
    private const string PUBLIC_REPLACEMENT = "[sensitive]";
    public static object ToPublicValue(TValue value) => PUBLIC_REPLACEMENT;
    public static string ToPublicString(TValue value) => PUBLIC_REPLACEMENT;
}

public readonly struct MaskedPii<TValue, TMasker> : IDisclosurePolicy<TValue>
    where TValue : notnull
    where TMasker : IValueMasker<TValue>
{
    public static object ToPublicValue(TValue value) => TMasker.Mask(value);
    public static string ToPublicString(TValue value) => TMasker.Mask(value);
}

public readonly struct RedactedSecret<TValue> : IDisclosurePolicy<TValue>
    where TValue : notnull
{
    private const string PUBLIC_REPLACEMENT = "[sensitive]";
    public static object ToPublicValue(TValue value) => PUBLIC_REPLACEMENT;
    public static string ToPublicString(TValue value) => PUBLIC_REPLACEMENT;
}
