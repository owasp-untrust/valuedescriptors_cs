using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.ValueDescriptors;

/// <summary>Text asserted by the caller to originate in program code.</summary>
/// <remarks>Do not construct this descriptor from request, database, file, or configuration input.</remarks>
public sealed class Hardcoded : DescribedValue<string, Public<string>>, IStringDescriptor
{
    private Hardcoded(string value) : base(value) { }

    public static Hardcoded From(string value) => new(value);

    internal static Hardcoded FromAnalyzedFactory(string value) => new(value);

    public Hardcoded Concat(Hardcoded suffix)
    {
        ArgumentNullException.ThrowIfNull(suffix);
        return new(ExposeUnchecked() + suffix.ExposeUnchecked());
    }
}

/// <summary>Factories intended for static import.</summary>
public static class Descriptors
{
    /// <summary>Describes compile-time constant text as originating in code.</summary>
    public static Hardcoded hardcoded(string value) => Hardcoded.FromAnalyzedFactory(value);
}
