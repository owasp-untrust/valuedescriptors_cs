namespace Owasp.Untrust.ValueDescriptors.Core;

/// <summary>A descriptor whose protected value can be deliberately exposed.</summary>
/// <summary>
/// Marks a value that deliberately permits callers to obtain its raw
/// representation. Exposure and public rendering are independent capabilities.
/// </summary>
public interface IExposableValue<out TValue>
    where TValue : notnull
{
    /// <summary>Crosses the descriptor boundary and returns the underlying value.</summary>
    TValue ExposeUnchecked();
}

/// <summary>Marker for descriptors whose underlying value is a string.</summary>
public interface IStringDescriptor : IExposableValue<string>;
