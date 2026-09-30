using System.Text.RegularExpressions;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.ValueDescriptors;

/// <summary>Text asserted by the caller to originate in program code.</summary>
/// <remarks>Do not construct this descriptor from request, database, file, or configuration input.</remarks>
public sealed class RegexAscii 
    : DescribedValue<string, Public<string>>
    , IStringDescriptor
{
    private RegexAscii(string value) : base(value) { }

    //public static Hardcoded From(string value) => new(value);
    public RegexOptions Options => RegexOptions.ECMAScript | RegexOptions.CultureInvariant;

    internal static RegexAscii FromAnalyzedFactory(string value) => new(value);

    public RegexAscii Concat(RegexAscii suffix)
    {
        ArgumentNullException.ThrowIfNull(suffix);
        return new(ExposeUnchecked() + suffix.ExposeUnchecked());
    }
}

/// <summary>Factories intended for static import.</summary>
public static class RegexAsciiFactory
{
    /// <summary>Describes compile-time constant text as originating in code.</summary>
    public static RegexAscii RegexAscii(string value) => global::Owasp.Untrust.ValueDescriptors.RegexAscii.FromAnalyzedFactory(value);
}
