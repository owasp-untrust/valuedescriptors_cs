using System.Collections.Immutable;
using Xunit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Owasp.Untrust.ValueDescriptors.Analyzers;

namespace Owasp.Untrust.ValueDescriptors.Tests;

public sealed class AnalyzerTests
{
    [Fact]
    public async Task Reports_RuntimeArgument_ForBothFactories()
    {
        const string source = """
            using Owasp.Untrust.ValueDescriptors;
            using static Owasp.Untrust.ValueDescriptors.Descriptors;
            public static class Example
            {
                public static void Use(string runtime)
                {
                    _ = Hardcoded.From(runtime);
                    _ = hardcoded(runtime);
                }
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.Equal(2, diagnostics.Count(d => d.Id == HardcodedArgumentAnalyzer.NonConstantArgumentId));
    }

    [Fact]
    public async Task Accepts_AllCompileTimeStringConstants()
    {
        const string source = """
            using Owasp.Untrust.ValueDescriptors;
            using static Owasp.Untrust.ValueDescriptors.Descriptors;
            public static class Example
            {
                private const string Prefix = "pre";
                public static void Use()
                {
                    _ = Hardcoded.From("literal");
                    _ = hardcoded(Prefix + "fix");
                    _ = hardcoded(nameof(Example));
                }
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.DoesNotContain(diagnostics, d => d.Id == HardcodedArgumentAnalyzer.NonConstantArgumentId);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            "AnalyzerTest",
            new[] { CSharpSyntaxTree.ParseText(source) },
            new[]
            {
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Hardcoded).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Runtime.GCSettings).Assembly.Location),
            },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        return await compilation
            .WithAnalyzers(ImmutableArray.Create<DiagnosticAnalyzer>(new HardcodedArgumentAnalyzer()))
            .GetAnalyzerDiagnosticsAsync();
    }
}
