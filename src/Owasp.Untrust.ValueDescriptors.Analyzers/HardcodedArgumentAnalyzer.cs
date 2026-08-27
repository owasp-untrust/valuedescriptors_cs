using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Owasp.Untrust.ValueDescriptors.Analyzers;

/// <summary>Prevents runtime-controlled text from being asserted as hardcoded.</summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class HardcodedArgumentAnalyzer : DiagnosticAnalyzer
{
    public const string NonConstantArgumentId = "VD1001";

    private static readonly DiagnosticDescriptor NonConstantArgument = new(
        NonConstantArgumentId,
        "Hardcoded text must be a compile-time constant",
        "Argument to '{0}' must be a compile-time constant string",
        "Owasp.Untrust.ValueDescriptors.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Hardcoded descriptors must not be constructible from request, configuration, database, file, or other runtime-controlled text.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(NonConstantArgument);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        if (!IsHardcodedFactory(invocation.TargetMethod))
        {
            return;
        }

        IArgumentOperation? valueArgument = invocation.Arguments.FirstOrDefault(
            static argument => argument.Parameter?.Ordinal == 0);
        if (valueArgument is null ||
            valueArgument.Value.ConstantValue is { HasValue: true, Value: string })
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            NonConstantArgument,
            valueArgument.Syntax.GetLocation(),
            invocation.TargetMethod.Name));
    }

    private static bool IsHardcodedFactory(IMethodSymbol method)
    {
        if (method.Parameters.Length != 1 || method.Parameters[0].Type.SpecialType != SpecialType.System_String)
        {
            return false;
        }

        if (method.ContainingAssembly.Name != "Owasp.Untrust.ValueDescriptors")
        {
            return false;
        }

        string containingType = method.ContainingType.ToDisplayString();
        return (method.Name == "From" && containingType == "Owasp.Untrust.ValueDescriptors.Hardcoded") ||
               (method.Name == "hardcoded" && containingType == "Owasp.Untrust.ValueDescriptors.Descriptors");
    }
}
