using System.Globalization;

namespace Owasp.Untrust.ValueDescriptors.Disclosure;

public readonly struct Public<TValue> : IDisclosurePolicy<TValue>
    where TValue : notnull
{
    public static DisclosureKind Kind => DisclosureKind.Public;
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
    public const string PublicReplacement = "[sensitive]";
    public static DisclosureKind Kind => DisclosureKind.RedactedPii;
    public static object ToPublicValue(TValue value) => PublicReplacement;
    public static string ToPublicString(TValue value) => PublicReplacement;
}

public readonly struct MaskedPii<TValue, TMasker> : IDisclosurePolicy<TValue>
    where TValue : notnull
    where TMasker : IValueMasker<TValue>
{
    public static DisclosureKind Kind => DisclosureKind.MaskedPii;
    public static object ToPublicValue(TValue value) => TMasker.Mask(value);
    public static string ToPublicString(TValue value) => TMasker.Mask(value);
}

public readonly struct RedactedSecret<TValue> : IDisclosurePolicy<TValue>
    where TValue : notnull
{
    public const string PublicReplacement = "[sensitive]";
    public static DisclosureKind Kind => DisclosureKind.RedactedSecret;
    public static object ToPublicValue(TValue value) => PublicReplacement;
    public static string ToPublicString(TValue value) => PublicReplacement;
}
