using Owasp.Untrust.ValueDescriptors.Core;
using Xunit;
using static Owasp.Untrust.ValueDescriptors.Descriptors;

namespace Owasp.Untrust.ValueDescriptors.Tests;

public sealed class DescriptorTests
{
    [Fact]
    public void Hardcoded_IsPublicAndConcatenatesOnlyWithHardcoded()
    {
        Hardcoded result = Hardcoded.From("field").Concat(Hardcoded.From(" is required"));

        Assert.Equal("field is required", result.ToString());
        Assert.Equal("field is required", result.ExposeUnchecked());
        Assert.IsAssignableFrom<IStringDescriptor>(result);
    }

    [Fact]
    public void StaticImport_ProvidesLowercaseFactory()
    {
        Hardcoded value = hardcoded("compile-time text");

        Assert.Equal("compile-time text", value.ExposeUnchecked());
    }

    [Fact]
    public void ViewableConfig_IsPublic()
    {
        ViewableConfig<string> value = ViewableConfig.From("eu-west-1");

        Assert.Equal("eu-west-1", value.ToPublicString());
        Assert.Equal("eu-west-1", value.ToPublicValue());
    }

    [Fact]
    public void RedactedConfig_DoesNotLeakThroughPublicRepresentations()
    {
        RedactedConfig<string> value = RedactedConfig.From("secret");

        Assert.Equal("[sensitive]", value.ToString());
        Assert.Equal("[sensitive]", value.ToPublicValue());
        Assert.Equal("secret", value.ExposeUnchecked());
    }
}
