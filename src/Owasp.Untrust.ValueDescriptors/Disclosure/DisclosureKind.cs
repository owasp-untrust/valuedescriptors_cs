namespace Owasp.Untrust.ValueDescriptors.Disclosure;

/// <summary>The public-disclosure decision for a described value.</summary>
public enum DisclosureKind
{
    Public,
    RedactedPii,
    MaskedPii,
    RedactedSecret,
}
