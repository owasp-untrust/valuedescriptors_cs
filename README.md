# Owasp.Untrust.ValueDescriptors for .NET

Origin and disclosure descriptors for values that are not necessarily validated
user input. The package owns the common public-rendering and disclosure-policy
contracts used by `vv_cs`.

```csharp
Hardcoded message = Hardcoded.From("username")
    .Concat(Hardcoded.From(" is required"));

ViewableConfig<string> region = ViewableConfig.From(configuration["Region"]!);
RedactedConfig<string> apiKey = RedactedConfig.From(configuration["ApiKey"]!);
```

For the most concise form, import the factory once (or make it a global using):

```csharp
using static Owasp.Untrust.ValueDescriptors.Descriptors;

Hardcoded message = hardcoded("username is required");
```

`ToString()` and `ToPublicString()` use the selected safe textual
representation. Raw access is deliberately named `ExposeUnchecked()`.

`IExposableValue<T>` also extends `IPubliclyRepresentable`, so every exposable
value must define its safe textual representation. `Public<T>` additionally
implements `IPublicDisclosurePolicy<T>` and supplies `PublicValue(T)`. Other
disclosure policies intentionally do not choose a machine-serialized value:
redaction, masking, tokenization, or the retained value may each be correct for
different boundaries.

- `Hardcoded` describes developer-controlled text and may concatenate only another
  `Hardcoded`. Analyzer error `VD1001` requires both `hardcoded(...)` and
  `Hardcoded.From(...)` to receive a compile-time constant string.
- `ViewableConfig<T>` describes configuration approved for public display.
- `RedactedConfig<T>` describes secret configuration and renders `[sensitive]`.
- `Public<T>`, `RedactedPii<T>`, `MaskedPii<T,TMasker>`, and
  `RedactedSecret<T>` are reusable compile-time disclosure policies.

The library does not read configuration itself. Keeping acquisition outside the
descriptor avoids coupling it to a particular configuration framework and makes
the disclosure decision explicit at the call site.

`DescribedValue<TValue,TDisclosure>` and `ConfigurationValue<TValue,TDisclosure>`
are extension points for application-specific descriptor families. They retain
the value in private immutable base storage and seal `ToString()` to the selected
disclosure policy.

`LazyStringBuilder` composes `Hardcoded` and any `IExposableValue<string>` without
depending on the validation library. `ToString()` keeps every component's safe
representation; `ExposeUnchecked()` is the explicit boundary that produces the
real composed string. Its `+` operators provide concise composition while still
rejecting unclassified raw strings.
