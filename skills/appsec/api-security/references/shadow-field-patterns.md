# Shadow Field Detection Patterns

This document contains machine-matchable detection patterns for shadow fields
and undocumented schema properties across multiple languages and frameworks.

---

## Regex Patterns (Language-Agnostic)

### Common Shadow Field Names

```regex
# Authorization/privilege escalation fields
\b(isAdmin|is_admin|admin|root|superuser|super_user|privileged|elevated)\b

# Bypass/override fields
\b(bypass|override|skip|ignore|disable)\w*(Auth|Validation|Check|Permission|RateLimit)\b

# Internal/operator flags
\b(internal|operator|system|service|backend|staff)\w*(Flag|Mode|Access|Token)\b

# Debug/test fields that leak to production
\b(debug|test|dev|staging|mock|fake|sample)\w*(Mode|Flag|User|Token|Key)\b

# Payment/financial override fields
\b(amount|price|cost|discount|credit|balance|currency)\w*(Override|Adjust|Manual|Force)\b
```

### Deserialization Configuration Patterns

```regex
# Jackson (Java) - fail-closed config
@JsonIgnoreProperties\s*\(\s*ignoreUnknown\s*=\s*false\s*\)
ObjectMapper\s*\.\s*configure\s*\(\s*DeserializationFeature\.FAIL_ON_UNKNOWN_PROPERTIES\s*,\s*true\s*\)

# Newtonsoft.Json (.NET) - fail-closed config
JsonSerializerSettings\s*\{\s*MissingMemberHandling\s*=\s*MissingMemberHandling\.Error\s*\}
DefaultContractResolver\s*\{\s*IgnoreSerializableInterface\s*=\s*true\s*\}

# System.Text.Json (.NET) - fail-closed config
JsonSerializerOptions\s*\{\s*PropertyNameCaseInsensitive\s*=\s*true\s*,\s*AllowTrailingCommas\s*=\s*true\s*\}
\.Configure\s*\(\s*options\s*=>\s*options\.NumberHandling\s*=\s*JsonNumberHandling\.AllowReadingFromString\s*\)

# Pydantic (Python) - fail-closed config
class Config:\s*extra\s*=\s*Extra\.forbid
model_config\s*=\s*ConfigDict\s*\(\s*extra\s*=\s*"forbid"\s*\)

# Go (encoding/json) - strict decoding
json:\s*Decoder\s*\.\s*DisallowUnknownFields\s*\(\s*\)
```

---

## Framework-Specific Patterns

### Java / Spring Boot

```regex
# @RequestBody without validation
@RequestBody\s+(?!@Valid)\w+

# DTO with extra fields not in OpenAPI
@Data\s+class\s+\w+Dto\s*\{[^}]*\b(?:isAdmin|bypass|internal)\w*\b

# Jackson ObjectMapper global config
@Bean\s+ObjectMapper\s+\w+\s*\(\)\s*\{[^}]*FAIL_ON_UNKNOWN_PROPERTIES\s*,\s*false
```

### C# / ASP.NET Core

```regex
# Model binding without [FromBody] validation
public\s+\w+\s+\w+\s*\(\s*\[FromBody\]\s*\w+\s+\w+\s*\)

# DTO with shadow fields
public\s+class\s+\w+(Request|Dto|Input)\s*\{[^}]*\b(?:IsAdmin|Bypass|Internal|Privileged)\w*\b

# Newtonsoft AllowUnknown
MissingMemberHandling\s*=\s*MissingMemberHandling\.Ignore

# STJ AllowTrailingCommas without validation
AllowTrailingCommas\s*=\s*true(?![^}]*PropertyNameCaseInsensitive)
```

### Python / FastAPI / Django

```regex
# Pydantic model with extra=allow
class\s+\w+\(BaseModel\):\s*[^}]*class Config:\s*extra\s*=\s*Extra\.allow

# FastAPI Body without model
Body\((?!\.\.\.)\s*\)

# Django REST Framework extra fields
class\s+\w+Serializer\(serializers\.\w+\):\s*[^}]*fields\s*=\s*['"]__all__['"]
```

### Go / Gin / Chi

```regex
# json tag without validation
`json:"[^"]+"`(?!.*validate)

# Binding without strict decoding
ShouldBindJSON|BindJSON(?![^}]*DisallowUnknownFields)

# Struct with unexported fields that could be shadow
type\s+\w+\s+struct\s*\{[^}]*\b(?:IsAdmin|Bypass|Internal)\w*\b
```

### Node.js / Express / NestJS

```regex
# express.json() without strict
express\.json\(\s*\{[^}]*strict\s*:\s*false

# class-validator without forbidNonWhitelisted
@Body\(\)\s+\w+:\s+\w+(?![^}]*forbidNonWhitelisted)

# DTO with extra properties
class\s+\w+Dto\s*\{[^}]*\b(?:isAdmin|bypass|internal)\w*\b
```

### GraphQL (All Languages)

```regex
# Input type with undocumented fields
input\s+\w+Input\s*\{[^}]*\b(?:isAdmin|bypass|internal|privileged)\w*\b

# Schema directive allowing extra fields
@allowExtraFields|@additionalProperties\s*\(\s*true\s*\)

# Resolver reading undocumented field
context\.args\.(?:isAdmin|bypass|internal)\w*
```

---

## AST Patterns (Semgrep Rules)

### Java - Unknown Property Deserialization

```yaml
rules:
  - id: jackson-unknown-properties-allowed
    pattern-either:
      - pattern: |
          @JsonIgnoreProperties(ignoreUnknown = true)
          class $X { ... }
      - pattern: |
          objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    message: "Jackson configured to ignore unknown properties - potential shadow field acceptance"
    languages: [java]
    severity: WARNING
```

### C# - Newtonsoft Ignore Unknown

```yaml
rules:
  - id: newtonsoft-ignore-unknown-properties
    pattern-either:
      - pattern: |
          MissingMemberHandling = MissingMemberHandling.Ignore
      - pattern: |
          JsonSerializerSettings { MissingMemberHandling = MissingMemberHandling.Ignore ... }
    message: "Newtonsoft configured to ignore missing/unknown properties"
    languages: [csharp]
    severity: WARNING
```

### Python - Pydantic Extra Allow

```yaml
rules:
  - id: pydantic-extra-allow
    pattern-either:
      - pattern: |
          class $X(BaseModel):
              class Config:
                  extra = Extra.allow
      - pattern: |
          model_config = ConfigDict(extra = "allow")
    message: "Pydantic model allows extra fields - potential shadow field acceptance"
    languages: [python]
    severity: WARNING
```

### Go - JSON Unknown Fields Allowed

```yaml
rules:
  - id: go-json-unknown-fields-allowed
    pattern: |
      json.Unmarshal($DATA, $TARGET)
    pattern-not: |
      dec := json.NewDecoder($READER)
      dec.DisallowUnknownFields()
      dec.Decode($TARGET)
    message: "JSON unmarshal without DisallowUnknownFields - accepts unknown properties"
    languages: [go]
    severity: WARNING
```

### GraphQL - Undocumented Input Fields

```yaml
rules:
  - id: graphql-undocumented-input-fields
    pattern: |
      input $NAME {
        ...
        $FIELD: $TYPE
        ...
      }
    pattern-not: |
      # Documented in schema or has @specifiedBy directive
    message: "GraphQL input type may have undocumented fields"
    languages: [graphql]
    severity: INFO
```

---

## OpenAPI / Swagger Patterns

### Missing Property Definitions

```yaml
# OpenAPI spec missing properties that exist in implementation
# Check: implementation DTO properties ∉ OpenAPI spec properties
```

### AdditionalProperties True Without Allowlist

```yaml
# Vulnerable: allows any extra properties
type: object
additionalProperties: true

# Secure: explicit allowlist or false
type: object
additionalProperties: false
# OR
additionalProperties:
  type: object
  properties:
    allowedExt1: { type: string }
    allowedExt2: { type: integer }
```

---

## CVE / Exploit References

| CVE / Reference | Description | Relevance |
|---|---|---|
| CVE-2021-44228 | Log4Shell - JNDI lookup via user-controlled field | Any deserialized field can be attack vector |
| CVE-2022-23529 | GitHub mass assignment | Framework protections can be bypassed |
| CVE-2019-5418 | Rails file content disclosure via accept header | Implicit behavior from undocumented fields |
| OWASP API3:2023 | Broken Object Property Level Authorization | Directly covers mass assignment and excessive data exposure |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | Mass assignment root cause |
| CWE-213 | Exposure of Information Through Incompatible Policies | Shadow fields exposing internal state |

---

## Framework Configuration Guides

### Spring Boot / Jackson

```java
// Secure ObjectMapper configuration
@Bean
public ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
    mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    return mapper;
}

// Per-class strict binding
@JsonIgnoreProperties(ignoreUnknown = false)
public class UserRequest { ... }
```

### ASP.NET Core / System.Text.Json

```csharp
// Program.cs - global strict options
builder.Services.Configure<JsonOptions>(options =>
{
    options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    options.JsonSerializerOptions.AllowTrailingCommas = true;
    // Default is to ignore unknown - make it strict per-model
});

// Per-model strict binding
[JsonSerializable(typeof(UserRequest))]
[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    AllowTrailingCommas = true,
    UnknownTypeHandling = JsonUnknownTypeHandling.JsonNode)] // or throw
internal partial class AppJsonContext : JsonSerializerContext { }

// Or use DTO pattern with explicit properties only
public record UserRequest(string Email, string DisplayName); // No extra fields possible
```

### FastAPI / Pydantic

```python
from pydantic import BaseModel, ConfigDict, Extra

# Strict model - forbids extra fields
class UserRequest(BaseModel):
    model_config = ConfigDict(extra=Extra.forbid)  # Pydantic v2
    # class Config: extra = Extra.forbid  # Pydantic v1
    
    email: str
    display_name: str
    # isAdmin, bypass, etc. will cause validation error

# FastAPI endpoint
@app.post("/users")
async def create_user(request: UserRequest):
    # request is guaranteed to have only defined fields
    ...
```

### Go / encoding/json

```go
// Strict decoding
func CreateUser(w http.ResponseWriter, r *http.Request) {
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()  // Key line - rejects unknown properties
    
    var req UserRequest
    if err := dec.Decode(&req); err != nil {
        // Returns error if unknown fields present
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    // req only has defined fields
}

// UserRequest struct - no extra fields possible
type UserRequest struct {
    Email       string `json:"email"`
    DisplayName string `json:"display_name"`
}
```

### Node.js / Express

```javascript
// Express 4.16+ built-in body parser with strict
app.use(express.json({ strict: true }));  // Default is true

// Or with body-parser
app.use(bodyParser.json({ strict: true }));

// Custom middleware to reject unknown properties
app.use((req, res, next) => {
    if (req.body && typeof req.body === 'object') {
        const allowed = ['email', 'display_name']; // per-endpoint or global schema
        const extra = Object.keys(req.body).filter(k => !allowed.includes(k));
        if (extra.length > 0) {
            return res.status(400).json({
                error: `Unknown properties: ${extra.join(', ')}`,
                allowedProperties: allowed
            });
        }
    }
    next();
});
```

---

## Detection Checklist for Code Review

When reviewing API implementations, check each endpoint for:

- [ ] Request DTO / input type matches OpenAPI spec / GraphQL schema exactly
- [ ] Deserializer configured to reject unknown properties (fail-closed)
- [ ] No conditional logic reads undocumented fields from request
- [ ] Authorization middleware only uses documented properties
- [ ] Extensibility points have explicit schema (not `additionalProperties: true`)
- [ ] Requests with extra properties are logged for security monitoring
- [ ] Integration tests verify rejection of requests with shadow fields