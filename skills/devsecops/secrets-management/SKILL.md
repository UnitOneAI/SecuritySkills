# Secrets Management Review Skill

## Purpose

This skill helps security reviewers identify secrets management issues in source code, build pipelines, and published artifacts. It covers credential exposure risks across the entire software supply chain, from development to release.

## Scope

- Hardcoded secrets in source code (API keys, tokens, passwords, certificates)
- Secrets in configuration files (`.env`, `.npmrc`, `nuget.config`, etc.)
- Secrets in build-time arguments and environment variables
- Secrets in Docker image layers, history, and metadata
- Secrets in published package tarballs and release artifacts
- Secrets in CI/CD pipeline definitions and logs

## Evidence Categories

### 1. Source Code Evidence

#### 1.1 Hardcoded Credentials

**What to look for:**
- API keys, tokens, passwords, connection strings, private keys
- Base64-encoded credentials
- Placeholder values that resemble real credentials (e.g., `YOUR_API_KEY_HERE`)
- Test credentials that may have been used in production

**Evidence to collect:**
```
- File path and line number
- Type of credential (API key, password, token, etc.)
- Whether it's a real credential or placeholder
- Context of usage (test file, documentation, actual code)
```

**False positive mitigation:**
- Distinguish real secrets from placeholders (e.g., `example.com`, `your-key-here`)
- Distinguish public build arguments (e.g., `PUBLIC_BUILD_CHANNEL=stable`) from secrets
- Distinguish browser-exposed configuration (e.g., `NEXT_PUBLIC_*`) from server-side secrets
- Distinguish intentionally ephemeral BuildKit secret mounts from persisted secrets

#### 1.2 Configuration Files

**What to look for:**
- `.env`, `.env.*` files committed to repository
- `.npmrc`, `.yarnrc`, `nuget.config` with embedded tokens
- `web.config`, `appsettings.json` with connection strings
- `terraform.tfvars`, `variables.tf` with hardcoded secrets
- `secrets.yml`, `secrets.yaml` in Ansible/Kubernetes configs

**Evidence to collect:**
```
- File path
- Secret type and value (redacted)
- Whether file is in `.gitignore` or `.dockerignore`
- Whether file is included in published package (check `files` in `package.json`, `.npmignore`, etc.)
```

### 2. Build Pipeline Evidence

#### 2.1 CI/CD Configuration

**What to look for:**
- Secrets passed as plaintext environment variables in CI/CD config
- Secrets printed to build logs
- Secrets in build cache artifacts
- Secrets in build matrix configurations

**Evidence to collect:**
```
- Pipeline definition file (`.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`, etc.)
- Variable name and source (repository secret, variable group, etc.)
- Whether secret masking is enabled
- Whether logs are scanned for secrets after build
```

#### 2.2 Docker Build Arguments

**What to look for:**
- `ARG` with sensitive default values
- `ENV` with sensitive values set during build
- BuildKit `--mount=type=secret` usage (this is safe, but verify it's not persisted)
- Multi-stage builds that copy secrets from builder stage

**Evidence to collect:**
```
- Dockerfile path and line numbers
- ARG/ENV names and values (redacted)
- Whether secrets are used only during build and not persisted
- Whether `.dockerignore` excludes sensitive files
```

### 3. Release Artifact Evidence

#### 3.1 Docker Image Analysis

**What to look for:**
- Secrets in image history (`docker history`)
- Secrets in image config (environment variables, labels)
- Secrets in image layers (files that were deleted but remain in layers)
- Secrets in provenance attestations (SLSA, in-toto)
- Secrets in image manifest annotations

**Evidence to collect:**
```
- Image reference (registry, repository, tag, digest)
- Image history output showing ARG/ENV values
- Layer scan results (e.g., `dive`, `docker sbom`, `trivy image`)
- Attestation review (if available)
- Whether secrets are present in final image or only in intermediate layers
```

**Evidence collection commands:**
```bash
# Check image history for exposed ARG/ENV values
docker history --no-trunc <image>

# Inspect image config for environment variables
docker inspect <image> | jq '.[0].Config.Env'

# Scan image layers for sensitive files
dive <image>

# Generate SBOM and check for secrets
docker sbom <image> | grep -i -E '(secret|token|password|key|credential)'

# Check provenance attestations
cosign verify-attestation --type slsaprovenance <image>
```

#### 3.2 Package Tarball Analysis

**What to look for:**
- `.npmrc`, `.env.production`, `*.map` files included in published package
- Configuration files with secrets that are excluded from source but included in package
- Build artifacts that contain embedded credentials
- Source maps that expose internal paths or configuration

**Evidence to collect:**
```
- Package name and version
- Package tarball contents (e.g., `npm pack --dry-run`)
- `files` field in `package.json`
- `.npmignore` or `.gitignore` configuration
- Whether sensitive files are included in the tarball
```

**Evidence collection commands:**
```bash
# List files that would be included in npm package
npm pack --dry-run

# List files in published package
npm pack <package> && tar -tzf <package>-<version>.tgz

# Check files field in package.json
cat package.json | jq '.files'

# Compare .gitignore and .npmignore
cat .gitignore
cat .npmignore 2>/dev/null || echo "No .npmignore"
```

#### 3.3 Other Release Artifacts

**What to look for:**
- Compiled binaries with embedded credentials
- Installer packages (MSI, DMG, APK, etc.) with sensitive files
- Cloud storage buckets (S3, GCS, Azure Blob) with public artifacts containing secrets
- Release notes or changelogs that inadvertently expose credentials

**Evidence to collect:**
```
- Artifact type and location
- Method of analysis (strings, hexdump, unpacking)
- Findings with file paths and context
```

## Review Checklist

### Source Code Review
- [ ] Scan for hardcoded credentials in all source files
- [ ] Check `.gitignore` for sensitive file patterns
- [ ] Review configuration files for embedded secrets
- [ ] Verify test files don't contain production credentials
- [ ] Check documentation for leaked secrets

### Build Pipeline Review
- [ ] Review CI/CD configuration for secret handling
- [ ] Check Dockerfile for ARG/ENV with sensitive values
- [ ] Verify BuildKit secret mounts are ephemeral
- [ ] Check `.dockerignore` for sensitive file exclusions
- [ ] Review build logs for secret exposure

### Release Artifact Review
- [ ] Analyze Docker image history and config for secrets
- [ ] Scan Docker image layers for sensitive files
- [ ] Check package tarballs for unintended file inclusion
- [ ] Verify provenance attestations don't leak secrets
- [ ] Review other release artifacts for embedded credentials

## Remediation Guidance

### For Hardcoded Secrets
1. Remove secrets from source code
2. Use environment variables or secret management services (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
3. Rotate exposed credentials immediately
4. Add secret scanning to CI/CD pipeline

### For Docker Build Secrets
1. Use BuildKit `--mount=type=secret` instead of ARG/ENV for sensitive values
2. Use multi-stage builds to avoid copying secrets to final image
3. Add `.dockerignore` to exclude sensitive files
4. Scan final image for secrets before publishing

### For Package Artifacts
1. Review `files` field in `package.json` to exclude sensitive files
2. Use `.npmignore` or `.gitignore` to prevent inclusion
3. Scan package tarball before publishing
4. Use `npm pack --dry-run` to preview package contents

### For CI/CD Pipelines
1. Use repository/organization secrets instead of plaintext variables
2. Enable secret masking in build logs
3. Scan build logs for secrets after each run
4. Use short-lived credentials where possible

## Tools

- **Source scanning:** `gitleaks`, `truffleHog`, `git-secrets`, `detect-secrets`
- **Docker analysis:** `dive`, `docker history`, `docker sbom`, `trivy`, `grype`
- **Package analysis:** `npm pack --dry-run`, `tar`, `unzip`
- **Binary analysis:** `strings`, `binwalk`, `radare2`
- **CI/CD analysis:** Manual review of pipeline definitions

## References

- [Docker Build Secrets Best Practices](https://docs.docker.com/build/building/secrets/)
- [npm Publishing Best Practices](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)
- [SLSA Provenance](https://slsa.dev/provenance/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)