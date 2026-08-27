using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.ValueDescriptors.Core;

/// <summary>Immutable storage and safe rendering for a described value.</summary>
public abstract class DescribedValue<TValue, TDisclosure> : IExposableValue<TValue>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private readonly TValue _value;

    protected DescribedValue(TValue value)
    {
        _value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public TValue ExposeUnchecked() => _value;

    public object? ToPublicValue() => TDisclosure.ToPublicValue(_value);

    public string ToPublicString() => TDisclosure.ToPublicString(_value);

    public sealed override string ToString() => ToPublicString();
}
