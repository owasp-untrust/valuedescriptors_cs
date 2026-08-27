using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.ValueDescriptors;

/// <summary>Immutable base for values asserted to originate in configuration.</summary>
public abstract class ConfigurationValue<TValue, TDisclosure> : DescribedValue<TValue, TDisclosure>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected ConfigurationValue(TValue value) : base(value) { }
}

/// <summary>Configuration explicitly classified as safe to publish.</summary>
public sealed class ViewableConfig<TValue> : ConfigurationValue<TValue, Public<TValue>>
    where TValue : notnull
{
    private ViewableConfig(TValue value) : base(value) { }

    public static ViewableConfig<TValue> From(TValue value) => new(value);
}

/// <summary>Configuration classified as secret and redacted from public rendering.</summary>
public sealed class RedactedConfig<TValue> : ConfigurationValue<TValue, RedactedSecret<TValue>>
    where TValue : notnull
{
    private RedactedConfig(TValue value) : base(value) { }

    public static RedactedConfig<TValue> From(TValue value) => new(value);
}

/// <summary>Type-inferred factories for viewable configuration.</summary>
public static class ViewableConfig
{
    public static ViewableConfig<TValue> From<TValue>(TValue value)
        where TValue : notnull => ViewableConfig<TValue>.From(value);
}

/// <summary>Type-inferred factories for redacted configuration.</summary>
public static class RedactedConfig
{
    public static RedactedConfig<TValue> From<TValue>(TValue value)
        where TValue : notnull => RedactedConfig<TValue>.From(value);
}
