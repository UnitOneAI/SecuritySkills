# C# and .NET — Dependency Scanning Patterns

## Overview

Language-specific supplement for dependency-scanning covering NuGet packages, .NET project files, and the .NET supply chain ecosystem. This guide targets .NET 6, .NET 7, and .NET 8 (LTS) projects using the modern SDK-style project format and the NuGet package manager.

## .NET Package Manifest Files

### `*.csproj` / `*.fsproj` / `*.vbproj` — SDK-Style Project Files

The primary dependency declaration mechanism in modern .NET. Dependencies appear as `<PackageReference>` elements:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0.*" />
    <PackageReference Include="Serilog" Version="[3.1.1, 4.0.0)" />
  </ItemGroup>
</Project>
```

**What to look for:**
- Floating versions (`*`, `8.0.*`) — these resolve to the latest matching version at restore time and can introduce unexpected changes.
- Open-ended version ranges (`(, 5.0.0)`, `[3.0.0, )`) — allow pulling untested versions.
- Missing `Version` attribute — version may be inherited from Central Package Management or `Directory.Build.props`. Verify the source.
- `<PackageReference>` with `PrivateAssets="All"` — build-time-only dependencies, still a supply chain surface.
- `<PackageReference>` with `IncludeAssets` or `ExcludeAssets` — may suppress runtime assets but the package is still resolved and executed during build.

### `packages.config` (Legacy .NET Framework)

Legacy dependency format used by non-SDK-style projects (.NET Framework 4.x and earlier):

```xml
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="log4net" version="2.0.15" targetFramework="net48" />
</packages>
```

**Risks:**
- No transitive dependency resolution — each package must be explicitly listed, leading to stale or missing transitive entries.
- No automatic vulnerability auditing support (`dotnet list package --vulnerable` does not work with this format).
- Migration path: `dotnet migrate` or manual conversion to `<PackageReference>` format.

### `Directory.Build.props` — Centralized Build Properties

Applies MSBuild properties to all projects in a directory tree. Commonly used to set shared package versions:

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
    <NuGetAudit>true</NuGetAudit>
    <NuGetAuditLevel>low</NuGetAuditLevel>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <WarningsAsErrors>NU1901;NU1902;NU1903;NU1904</WarningsAsErrors>
  </PropertyGroup>
</Project>
```

**What to look for:**
- `<NuGetAudit>` setting — should be `true` for .NET 8+ projects.
- `<NuGetAuditLevel>` — controls minimum severity reported (`low`, `moderate`, `high`, `critical`).
- `<TreatWarningsAsErrors>` combined with NU1901-NU1904 — makes vulnerability warnings break the build.

### `Directory.Packages.props` — Central Package Management (CPM)

Centralizes all package version declarations for multi-project solutions:

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageVersion Include="Microsoft.EntityFrameworkCore" Version="8.0.2" />
    <PackageVersion Include="xunit" Version="2.7.0" />
  </ItemGroup>
</Project>
```

**What to look for:**
- When CPM is enabled, individual `*.csproj` files must not specify `Version` on `<PackageReference>` — if they do, restore fails unless `<CentralPackageVersionOverrideEnabled>` is set to `true`, which weakens centralized control.
- Verify all packages are listed here and not scattered across individual project files.

### `global.json` — SDK Version Pinning

Pins the .NET SDK version used for the repository:

```json
{
  "sdk": {
    "version": "8.0.201",
    "rollForward": "latestPatch"
  }
}
```

**What to look for:**
- Missing `global.json` — the build uses whatever SDK is installed, leading to inconsistent results.
- `rollForward` policy — `latestMajor` or `latestMinor` can pull in untested SDK versions. Prefer `latestPatch` or `disable` for reproducible builds.

### `nuget.config` — Package Source Configuration

Defines where NuGet resolves packages from:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="internal" value="https://pkgs.dev.azure.com/myorg/_packaging/myfeed/nuget/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="internal">
      <package pattern="MyCompany.*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

**What to look for:**
- Missing `<clear />` before source definitions — inherited sources from machine-level config may introduce unexpected feeds.
- Missing `<packageSourceMapping>` — without it, NuGet resolves from all configured sources, enabling dependency confusion attacks.
- Credentials stored in `nuget.config` — API keys or PATs should use environment variables or credential providers, not plaintext.

### `packages.lock.json` — NuGet Lockfile

Generated when `RestorePackagesWithLockFile` is enabled:

```xml
<!-- In csproj or Directory.Build.props -->
<PropertyGroup>
  <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
</PropertyGroup>
```

**What to look for:**
- Lockfile not committed to version control — defeats the purpose of deterministic restores.
- Lockfile present but `RestorePackagesWithLockFile` not enabled — the lockfile may be stale.
- Use `--locked-mode` in CI to fail the build if the lockfile is out of date: `dotnet restore --locked-mode`.

## SBOM Generation for .NET

| Tool | Command | Notes |
|------|---------|-------|
| CycloneDX .NET tool | `dotnet tool install --global CycloneDX && dotnet CycloneDX <project-or-solution> -o sbom -j` | Official CycloneDX integration; produces CycloneDX JSON. Supports `--exclude-dev` to omit test dependencies. |
| `syft` | `syft dir:. -o cyclonedx-json > sbom.json` | Multi-ecosystem scanner from Anchore; detects NuGet packages from project files and lockfiles. |
| `trivy` | `trivy fs --format cyclonedx -o sbom.json .` | Multi-ecosystem; also detects .NET framework assemblies in published output. |
| Microsoft SBOM Tool | `sbom-tool generate -b <build-drop-path> -bc <build-component-path> -pn MyApp -pv 1.0.0 -ps MyOrg -nsb https://myorg.com` | Microsoft's official SBOM generator; produces SPDX 2.2 format. Designed for integration into build pipelines. |

### CycloneDX Detailed Usage

```bash
# Install as global tool
dotnet tool install --global CycloneDX

# Generate SBOM for a solution
dotnet CycloneDX MySolution.sln -o ./sbom -j -dgl

# Flags:
#   -j          JSON output (default is XML)
#   -dgl        Disable GitHub license resolution (faster, no API calls)
#   --exclude-dev  Exclude development dependencies
#   -rs         Recurse subdirectories for project files
```

## Vulnerability Scanning Tools

| Tool | Command | Coverage |
|------|---------|----------|
| `dotnet list package --vulnerable` | Built-in .NET CLI (SDK 5.0+) | NuGet advisory database; shows packages with known vulnerabilities. |
| `dotnet list package --deprecated` | Built-in .NET CLI (SDK 5.0+) | Identifies deprecated packages that should be replaced. |
| NuGet Audit (.NET 8+) | Automatic during `dotnet restore` | Checks NuGet vulnerability database during package restore. Enable with `<NuGetAudit>true</NuGetAudit>`. |
| OSV Scanner | `osv-scanner --lockfile packages.lock.json` | Google's OSV database; supports `packages.lock.json` and `packages.config`. |
| Snyk | `snyk test --file=MyProject.csproj` | Snyk vulnerability database; supports `*.csproj`, `packages.config`, and `project.assets.json`. |
| Trivy | `trivy fs --scanners vuln .` | Multiple databases; detects NuGet packages from project files, lockfiles, and `bin/` output. |
| `dotnet-retire` | `dotnet tool install --global dotnet-retire && dotnet retire` | Checks for packages with known vulnerabilities using the RetireNET database. |

### Built-In NuGet Audit (.NET 8+)

.NET 8 introduced automatic vulnerability checking during `dotnet restore`. Configure severity and behavior:

```xml
<PropertyGroup>
  <!-- Enable NuGet audit (on by default in .NET 8+) -->
  <NuGetAudit>true</NuGetAudit>

  <!-- Minimum severity to report: low, moderate, high, critical -->
  <NuGetAuditLevel>low</NuGetAuditLevel>

  <!-- Audit mode: direct (default) or all (includes transitive) -->
  <!-- .NET 9+ supports "all"; for .NET 8, only direct dependencies are audited -->
  <NuGetAuditMode>all</NuGetAuditMode>

  <!-- Make vulnerability warnings fail the build -->
  <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  <WarningsAsErrors>$(WarningsAsErrors);NU1901;NU1902;NU1903;NU1904</WarningsAsErrors>
</PropertyGroup>
```

Warning codes:
- `NU1901` — Low severity vulnerability
- `NU1902` — Moderate severity vulnerability
- `NU1903` — High severity vulnerability
- `NU1904` — Critical severity vulnerability

### Full Dependency Tree Inspection

```bash
# List all vulnerable packages (direct + transitive)
dotnet list package --vulnerable --include-transitive

# List deprecated packages
dotnet list package --deprecated

# List outdated packages
dotnet list package --outdated

# JSON output for CI parsing (.NET 8+)
dotnet list package --vulnerable --include-transitive --format json
```

## NuGet-Specific Supply Chain Risks

### Package Source Confusion / Dependency Confusion

.NET projects can pull packages from multiple NuGet feeds (nuget.org, Azure Artifacts, GitHub Packages, private Artifactory feeds). If a private package name is not reserved on nuget.org, an attacker can publish a malicious package with the same name and a higher version number. NuGet's default behavior resolves the highest version across all configured sources.

**Mitigation — Package Source Mapping:**

```xml
<!-- nuget.config -->
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="azure-internal" value="https://pkgs.dev.azure.com/myorg/_packaging/internal/nuget/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="azure-internal">
      <package pattern="MyCompany.*" />
      <package pattern="MyCompany.Internal.*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

This ensures `MyCompany.*` packages are only resolved from the internal feed, preventing nuget.org from supplying a malicious substitute.

**Additional mitigations:**
- Reserve internal package name prefixes on nuget.org using NuGet prefix reservation.
- Use `<clear />` in `<packageSources>` to prevent machine-level config inheritance.
- Verify that `nuget.config` is committed to the repository root and not relying on user-level configuration.

### Typosquatting Patterns for .NET

| Legitimate | Typosquat Example | Attack Vector |
|-----------|-------------------|---------------|
| `Newtonsoft.Json` | `NewtonSoft.Json`, `Newtonsoft-Json`, `Newtonsoft.JSon` | Case variation and separator confusion |
| `Microsoft.Extensions.Logging` | `Microsoft.Extension.Logging`, `Microsoft.Extensions.Log` | Singular/truncation |
| `Dapper` | `Daper`, `Dapper.Core`, `DapperLib` | Character omission, suffix addition |
| `Serilog` | `SeriLog`, `Seri.Log`, `Serilog.Core.Extensions` | Case variation, fake sub-package |
| `AutoMapper` | `Auto-Mapper`, `AutoMaper`, `Automapper` | Separator injection, character omission, case change |
| `MediatR` | `Mediator`, `MediatoR`, `MediatR.Core` | Name confusion, case variation |

**Detection approach for NuGet:**
- Verify publisher identity on nuget.org — look for the blue verified prefix reservation badge.
- Compare download counts: legitimate packages like `Newtonsoft.Json` have billions of downloads; typosquats will have hundreds or fewer.
- Check `owners` field on the NuGet gallery page against known maintainers.

### Vulnerable Package Patterns

**Packages using `BinaryFormatter` internally:**
- `BinaryFormatter` was marked obsolete in .NET 7 and disabled by default in .NET 8 (SYSLIB0011) due to inherent deserialization vulnerabilities.
- Packages that use `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, or `ObjectStateFormatter` for serialization are high risk.
- Scan for: `<EnableUnsafeBinaryFormatterSerialization>true</EnableUnsafeBinaryFormatterSerialization>` in project files — this re-enables the dangerous API.

**Commonly affected package categories:**
- Legacy caching libraries that serialize objects with `BinaryFormatter`.
- Older versions of `System.Runtime.Serialization.Formatters` (pre-.NET 8).
- Session state providers using binary serialization.

**Packages that have not been updated for .NET 6+:**
- May depend on APIs removed or changed in modern .NET, leading to runtime failures.
- May carry unpatched vulnerabilities in bundled native dependencies.
- Check `Last Updated` date on nuget.org; packages not updated since before .NET 6 (November 2021) warrant review.

## License Compliance for NuGet

### Tooling

```bash
# Install the license analysis tool
dotnet tool install --global dotnet-project-licenses

# Generate license report as JSON
dotnet-project-licenses --input MyProject.csproj --json --output-directory ./license-report

# Generate license report for a solution
dotnet-project-licenses --input MySolution.sln --json --unique

# Flags:
#   --json                  Output as JSON
#   --unique                Deduplicate packages across projects
#   --output-directory      Write report files to this directory
#   --include-transitive    Include transitive dependency licenses
```

### NuGet License Metadata

NuGet packages declare licenses in two ways:

1. **License expression (modern):** SPDX expression in the `.nuspec` or `<PackageLicenseExpression>` in the `.csproj`:
   ```xml
   <PackageLicenseExpression>MIT</PackageLicenseExpression>
   ```

2. **License URL (legacy, deprecated):** A URL pointing to license text:
   ```xml
   <licenseUrl>https://licenses.nuget.org/MIT</licenseUrl>
   ```

**Audit considerations:**
- Packages using `licenseUrl` instead of `license` expression use legacy metadata that is harder to audit programmatically. The URL may change or become unavailable.
- `NOASSERTION` or missing license data should be treated as high risk.
- Dual-licensed packages (e.g., `MIT OR Apache-2.0`) require verifying which license applies to your usage.
- Some packages embed a `LICENSE.md` file in the `.nupkg` — verify its contents match the declared expression.

## .NET-Specific Transitive Dependency Analysis

### Viewing the Full Dependency Tree

```bash
# List all packages including transitive dependencies
dotnet list package --include-transitive

# Filter to a specific project in a solution
dotnet list MyProject/MyProject.csproj package --include-transitive

# Output as JSON for programmatic analysis (.NET 8+)
dotnet list package --include-transitive --format json
```

### Central Package Management for Version Consistency

For solutions with multiple projects, CPM ensures all projects use the same version of each package:

1. Create `Directory.Packages.props` at the solution root.
2. Move all `Version` attributes from individual `<PackageReference>` elements to `<PackageVersion>` elements in `Directory.Packages.props`.
3. Individual project files reference packages without versions:
   ```xml
   <!-- In the .csproj -->
   <PackageReference Include="Newtonsoft.Json" />
   ```

**Security benefit:** A single file to audit and update when vulnerabilities are discovered, rather than searching across dozens of project files.

### Making Vulnerability Warnings Break the Build

```xml
<!-- Directory.Build.props — applied to all projects -->
<Project>
  <PropertyGroup>
    <NuGetAudit>true</NuGetAudit>
    <NuGetAuditLevel>low</NuGetAuditLevel>

    <!-- Treat vulnerability warnings as errors -->
    <WarningsAsErrors>$(WarningsAsErrors);NU1901;NU1902;NU1903;NU1904</WarningsAsErrors>
  </PropertyGroup>
</Project>
```

This configuration causes `dotnet restore` (and by extension `dotnet build`) to fail if any package has a known vulnerability at or above the configured severity level.

### Pinning Transitive Dependencies

When a vulnerable transitive dependency cannot be updated by upgrading the direct dependency, pin the transitive package directly:

```xml
<!-- In the .csproj or Directory.Packages.props -->
<ItemGroup>
  <!-- Force a specific version of a transitive dependency -->
  <PackageReference Include="System.Text.Json" Version="8.0.5" />
</ItemGroup>
```

With CPM, use `<PackageVersion>` in `Directory.Packages.props` to pin transitives centrally.

## Assessment Additions for .NET Projects

Add these to the supply chain risk indicators when scanning a .NET project:

- [ ] Package source mapping configured in `nuget.config` (`<packageSourceMapping>` present with explicit source-to-package bindings)
- [ ] `packages.lock.json` committed to version control and `RestorePackagesWithLockFile` enabled in project or build props
- [ ] No `packages.config` files present — fully migrated to `<PackageReference>` format
- [ ] Central Package Management enabled via `Directory.Packages.props` for multi-project solutions
- [ ] `<NuGetAudit>true</NuGetAudit>` set in `Directory.Build.props` or individual project files
- [ ] NuGet audit warnings (NU1901-NU1904) treated as errors in CI builds
- [ ] SDK version pinned in `global.json` with `rollForward` set to `latestPatch` or `disable`
- [ ] `<clear />` present in `nuget.config` `<packageSources>` to prevent config inheritance
- [ ] No `<EnableUnsafeBinaryFormatterSerialization>true</EnableUnsafeBinaryFormatterSerialization>` in any project file
- [ ] NuGet prefix reservation claimed for internal package namespaces

## References

- [NuGet Security Best Practices](https://learn.microsoft.com/en-us/nuget/concepts/security-best-practices)
- [Microsoft Supply Chain Security — Securing the Software Supply Chain](https://learn.microsoft.com/en-us/nuget/concepts/package-source-mapping)
- [.NET Package Validation](https://learn.microsoft.com/en-us/dotnet/fundamentals/package-validation/overview)
- [NuGet Package Source Mapping](https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping)
- [Central Package Management](https://learn.microsoft.com/en-us/nuget/consume-packages/central-package-management)
- [NuGet Audit Documentation](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages)
- [CycloneDX .NET Tool](https://github.com/CycloneDX/cyclonedx-dotnet)
- [Microsoft SBOM Tool](https://github.com/microsoft/sbom-tool)
- [NuGet Prefix Reservation](https://learn.microsoft.com/en-us/nuget/nuget-org/id-prefix-reservation)
- [BinaryFormatter Security Guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
