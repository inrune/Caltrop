# Contributing to Caltrop

Thanks for helping. Caltrop is security code, so a few rules are stricter than usual.

## Getting started

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```shell
dotnet build
dotnet test
dotnet run --project samples/Caltrop.Samples
```

## Ground rules

1. **No home-made cryptography.** Caltrop combines the primitives in `System.Security.Cryptography` and never
   implements ciphers, hashes or curves itself.
2. **No new runtime dependencies.** The library depends only on .NET.
3. **Never break stored data.** Any change to a byte format needs a new version or kind byte, and the old
   format must still be readable. The tests in `CompatibilityTests.cs` hold data made by earlier releases.
   Never edit them to make a change pass.
4. **Safe by default.** New features should be hard to misuse: authenticated, constant-time where secrets
   are compared, and with clear errors that say what to do.
5. **Document every public member.** The build fails on missing XML docs, and warnings are errors in the
   library.
6. **Offline only.** Caltrop never uses the network or starts other programs. `OfflineTests` fails if the
   library references .NET's networking or process assemblies.

## Pull requests

- Add tests for new behaviour, including what happens when input is tampered with, cut off or malformed.
- Update `README.md`, `docs/guide.md` and `CHANGELOG.md` when you change the public API.
- Keep each pull request to one change.

## Project layout

| Folder | Contents |
| --- | --- |
| `src/Caltrop` | The library. `Internal/` holds the formats and helpers. |
| `tests/Caltrop.Tests` | xUnit tests. |
| `samples/Caltrop.Samples` | A runnable tour of the features. |
| `docs` | The guide, format specification and security model. |
