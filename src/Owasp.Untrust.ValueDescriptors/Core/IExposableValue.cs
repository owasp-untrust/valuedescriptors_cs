namespace Owasp.Untrust.ValueDescriptors.Core;

/// <summary>A descriptor whose protected value can be deliberately exposed.</summary>
public interface IExposableValue<out TValue> : IPubliclyRepresentable
    where TValue : notnull
{
    /// <summary>Crosses the descriptor boundary and returns the underlying value.</summary>
    TValue ExposeUnchecked();
}

/// <summary>Marker for descriptors whose underlying value is a string.</summary>
public interface IStringDescriptor : IExposableValue<string>;
