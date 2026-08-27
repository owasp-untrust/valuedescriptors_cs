namespace Owasp.Untrust.ValueDescriptors.Core;

/// <summary>A value with an explicitly safe public representation.</summary>
public interface IPubliclyRepresentable
{
    object? ToPublicValue();

    string ToPublicString();
}
