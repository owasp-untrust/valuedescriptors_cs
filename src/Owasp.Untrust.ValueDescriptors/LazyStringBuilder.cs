using System.Text;
using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.ValueDescriptors;

/// <summary>
/// Builds an outbound payload from code-owned text and publicly representable,
/// explicitly exposable strings. Safe rendering never exposes protected segments.
/// </summary>
public sealed class LazyStringBuilder
{
    private static readonly Func<string, string> IdentityTransform = value => value;
    private readonly Func<string, string> _defaultTransform;
    private readonly List<ISegment> _segments = [];

    public LazyStringBuilder() : this(IdentityTransform) { }

    public LazyStringBuilder(Func<string, string> encodeValue)
    {
        _defaultTransform = encodeValue ?? throw new ArgumentNullException(nameof(encodeValue));
    }

    private LazyStringBuilder(LazyStringBuilder source)
    {
        _defaultTransform = source._defaultTransform;
        _segments.AddRange(source._segments);
    }

    public static LazyStringBuilder From(Hardcoded value) =>
        new LazyStringBuilder().Append(value);

    public static LazyStringBuilder From(IExposableValue<string> value) =>
        new LazyStringBuilder().Append(value);

    public static LazyStringBuilder operator +(LazyStringBuilder left, Hardcoded right)
    {
        ArgumentNullException.ThrowIfNull(left);
        return new LazyStringBuilder(left).Append(right);
    }

    public static LazyStringBuilder operator +(Hardcoded left, LazyStringBuilder right)
    {
        ArgumentNullException.ThrowIfNull(right);
        return new LazyStringBuilder(right).PushPrefix(left);
    }

    public static LazyStringBuilder operator +(
        LazyStringBuilder left,
        IExposableValue<string> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        return new LazyStringBuilder(left).Append(right);
    }

    public static LazyStringBuilder operator +(
        IExposableValue<string> left,
        LazyStringBuilder right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        LazyStringBuilder result = new(right);
        result._segments.Insert(0, new ExposableValueSegment(left, result._defaultTransform));
        return result;
    }

    public LazyStringBuilder Append(Hardcoded value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _segments.Add(new HardcodedSegment(value));
        return this;
    }

    public LazyStringBuilder PushPrefix(Hardcoded value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _segments.Insert(0, new HardcodedSegment(value));
        return this;
    }

    public LazyStringBuilder Append(IExposableValue<string> value) =>
        Append(value, _defaultTransform);

    /// <summary>
    /// Adds a transport-only transform. Safe public rendering uses the value's
    /// disclosure policy and never invokes this transform on protected data.
    /// </summary>
    public LazyStringBuilder Append(
        IExposableValue<string> value,
        Func<string, string> transform)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(transform);
        _segments.Add(new ExposableValueSegment(value, transform));
        return this;
    }

    /// <summary>Explicitly exposes the completed transport payload.</summary>
    public string ExposeUnchecked()
    {
        StringBuilder payload = new();
        foreach (ISegment segment in _segments)
        {
            payload.Append(segment.ExposeUnchecked());
        }

        return payload.ToString();
    }

    public override string ToString()
    {
        StringBuilder publicRepresentation = new();
        foreach (ISegment segment in _segments)
        {
            publicRepresentation.Append(segment.ToPublicString());
        }

        return publicRepresentation.ToString();
    }

    private interface ISegment
    {
        string ExposeUnchecked();
        string ToPublicString();
    }

    private sealed class HardcodedSegment(Hardcoded value) : ISegment
    {
        public string ExposeUnchecked() => value.ExposeUnchecked();
        public string ToPublicString() => value.ToPublicString();
    }

    private sealed class ExposableValueSegment(
        IExposableValue<string> value,
        Func<string, string> transform) : ISegment
    {
        public string ExposeUnchecked()
        {
            string transformed = transform(value.ExposeUnchecked());
            return transformed ?? throw new InvalidOperationException(
                "The configured transform returned null.");
        }

        public string ToPublicString() => value.ToPublicString();
    }
}
