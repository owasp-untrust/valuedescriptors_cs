# Owasp.Untrust.ValueDescriptors for .NET

Origin and disclosure descriptors for values that are not necessarily validated
user input. The package owns the common public-rendering and disclosure-policy
contracts used by `vv_cs`.

```csharp
using static Owasp.Untrust.ValueDescriptors.HardcodedFactory;

Hardcoded message = Hardcoded("username")
    .Concat(Hardcoded(" is required"));

ViewableConfig<string> region = ViewableConfig.From(configuration["Region"]!);
RedactedConfig<string> apiKey = RedactedConfig.From(configuration["ApiKey"]!);
```

`Hardcoded` is intentionally created only through the static-import factory:

```csharp
using static Owasp.Untrust.ValueDescriptors.HardcodedFactory;

Hardcoded message = Hardcoded("username is required");
```

`Hardcoded.From(...)` is not public, and there is no `Descriptors.hardcoded(...)`
factory. The `Hardcoded(...)` factory is analyzer-protected: its argument must be
a compile-time constant string.

`ToString()` and `ToPublicString()` use the selected safe textual
representation. Raw access is deliberately named `ExposeUnchecked()`.

`IExposableValue<T>` also extends `IPubliclyRepresentable`, so every exposable
value must define its safe textual representation. `Public<T>` additionally
implements `IPublicDisclosurePolicy<T>` and supplies `PublicValue(T)`. Other
disclosure policies intentionally do not choose a machine-serialized value:
redaction, masking, tokenization, or the retained value may each be correct for
different boundaries.

- `Hardcoded` describes developer-controlled text and may concatenate only another
  `Hardcoded`. Analyzer error `VD1001` requires `Hardcoded(...)` to receive a
  compile-time constant string.
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
