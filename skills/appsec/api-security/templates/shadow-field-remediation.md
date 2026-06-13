# Shadow Field Remediation Template

This template provides scaffolding for remediating shadow field vulnerabilities
across different frameworks. Copy the relevant section for your framework.

---

## Java / Spring Boot (Jackson)

### 1. Global ObjectMapper Configuration

```java
@Configuration
public class JacksonConfig {

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        
        // CRITICAL: Fail on unknown properties
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        
        // Additional hardening
        mapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);
        mapper.configure(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL, false);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(MapperFeature.DEFAULT_VIEW_INCLUSION, false);
        
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }
}
```

### 2. Per-Model Strict Binding

```java
// For DTOs that must reject unknown properties
@JsonIgnoreProperties(ignoreUnknown = false)
public class UserRequest {
    private String email;
    private String displayName;
    // Getters/setters...
}
```

### 3. Spring Boot 3.x Properties (application.yml)

```yaml
spring:
  jackson:
    deserialization:
      FAIL_ON_UNKNOWN_PROPERTIES: true
      FAIL_ON_NULL_FOR_PRIMITIVES: true
      READ_UNKNOWN_ENUM_VALUES_AS_NULL: false
```

---

## C# / ASP.NET Core (System.Text.Json)

### 1. Global Configuration (Program.cs)

```csharp
// STJ ignores unknown properties by default (SECURE)
// Add explicit configuration for clarity
builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
{
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
    options.SerializerOptions.AllowTrailingCommas = true;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

builder.Services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(options =>
{
    options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    options.JsonSerializerOptions.AllowTrailingCommas = true;
});
```

### 2. Source Generation (Explicit Contract)

```csharp
[JsonSerializable(typeof(UserRequest))]
[JsonSerializable(typeof(UserResponse))]
[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    AllowTrailingCommas = true
)]
internal partial class AppJsonContext : JsonSerializerContext { }

// Usage in Minimal API
app.MapPost("/users", async (UserRequest request, AppDbContext db) =>
{
    // request only contains defined properties
});
```

### 3. Newtonsoft.Json (Legacy)

```csharp
builder.Services.AddControllers()
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.MissingMemberHandling = MissingMemberHandling.Error;
        options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
    });
```

### 4. Strict DTO Pattern (Recommended)

```csharp
// Record types are inherently strict - no extra fields possible
public record UserRequest(string Email, string DisplayName);
public record UserResponse(int Id, string Email, string DisplayName, DateTime CreatedAt);
```

---

## Python / FastAPI (Pydantic v2)

### 1. Global Configuration

```python
from pydantic import ConfigDict, Extra, BaseModel

# Set global default
BaseModel.model_config = ConfigDict(
    extra=Extra.forbid,
    str_strip_whitespace=True,
    validate_assignment=True,
    use_enum_values=True,
)
```

### 2. Per-Model Configuration

```python
from pydantic import BaseModel, ConfigDict, Field, EmailStr
from datetime import datetime

class UserRequest(BaseModel):
    model_config = ConfigDict(
        extra=Extra.forbid,
        str_strip_whitespace=True,
    )
    
    email: EmailStr
    display_name: str = Field(..., min_length=1, max_length=100)

class UserResponse(BaseModel):
    model_config = ConfigDict(
        extra=Extra.forbid,
        from_attributes=True,
    )
    
    id: int
    email: EmailStr
    display_name: str
    created_at: datetime
```

### 3. FastAPI Exception Handler (Custom Error Response)

```python
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

app = FastAPI()

@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    errors = []
    for error in exc.errors():
        if error['type'] == 'extra_forbidden':
            errors.append({
                "field": '.'.join(str(loc) for loc in error['loc']),
                "message": f"Unknown property not allowed",
                "type": "shadow_field_rejected"
            })
        else:
            errors.append({
                "field": '.'.join(str(loc) for loc in error['loc']),
                "message": error['msg'],
                "type": error['type']
            })
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Request validation failed",
            "details": errors,
            "help": "Only documented properties are accepted. Check API specification."
        }
    )
```

---

## Go (Standard Library)

### 1. Strict Decoding in Handler

```go
func CreateUser(w http.ResponseWriter, r *http.Request) {
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()  // CRITICAL
    
    var req UserRequest
    if err := dec.Decode(&req); err != nil {
        var syntaxErr *json.SyntaxError
        var unmarshalTypeErr *json.UnmarshalTypeError
        
        if errors.As(err, &syntaxErr) || errors.As(err, &unmarshalTypeErr) {
            http.Error(w, `{"error":"Invalid JSON","details":"Unknown or invalid fields"}`, http.StatusBadRequest)
            return
        }
        http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
        return
    }
    
    // Process req...
}

type UserRequest struct {
    Email       string `json:"email"`
    DisplayName string `json:"display_name"`
}
```

### 2. Middleware for All JSON Endpoints

```go
func StrictJSONMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
            contentType := r.Header.Get("Content-Type")
            if strings.HasPrefix(contentType, "application/json") {
                r.Body = &strictJSONReader{body: r.Body}
            }
        }
        next.ServeHTTP(w, r)
    })
}
```

---

## Node.js / Express

### 1. Built-in Parser (Secure Default)

```javascript
const express = require('express');
const app = express();

// Strict: true by default (only accepts objects)
// Limit request size for DoS protection
app.use(express.json({ 
    strict: true,
    limit: '1mb'
}));
```

### 2. Reject Unknown Properties Middleware

```javascript
function rejectUnknownProperties(allowedFields) {
    return (req, res, next) => {
        if (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
            const received = Object.keys(req.body);
            const unknown = received.filter(f => !allowedFields.includes(f));
            
            if (unknown.length > 0) {
                return res.status(400).json({
                    error: 'Unknown properties in request',
                    unknownFields: unknown,
                    allowedFields: allowedFields,
                    message: 'Only documented API properties are accepted'
                });
            }
        }
        next();
    };
}

// Usage
app.post('/users', 
    rejectUnknownProperties(['email', 'display_name']),
    async (req, res) => {
        const user = await userService.create(req.body);
        res.status(201).json(user);
    }
);
```

---

## NestJS (TypeScript)

### 1. Global Validation Pipe (main.ts)

```typescript
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    
    app.useGlobalPipes(new ValidationPipe({
        whitelist: true,              // Strip unknown properties
        forbidNonWhitelisted: true,   // THROW on unknown properties (STRICT)
        transform: true,
        disableErrorMessages: false,
    }));
    
    await app.listen(3000);
}
```

### 2. Strict DTO

```typescript
import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
    @ApiProperty({ example: 'user@example.com' })
    @IsEmail()
    email: string;

    @ApiProperty({ example: 'John Doe' })
    @IsString()
    @MinLength(1)
    @MaxLength(100)
    display_name: string;
}
```

---

## GraphQL (Schema-First)

### 1. Strict Input Types (Schema Definition)

```graphql
# schema.graphql
input CreateUserInput {
    email: String!
    display_name: String!
    # NO extra fields - GraphQL schema is strictly typed
}

type Mutation {
    createUser(input: CreateUserInput!): User!
}
```

### 2. Disable Introspection in Production

```javascript
// Apollo Server
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',
});

// HotChocolate (.NET)
builder.Services
    .AddGraphQLServer()
    .AddIntrospectionAllowedRule(options => 
    {
        options.AllowIntrospection = builder.Environment.IsDevelopment();
    });
```

---

## OpenAPI / Swagger Specification

### 1. Explicit Property Definitions (No additionalProperties)

```yaml
# openapi.yaml
components:
  schemas:
    UserRequest:
      type: object
      required:
        - email
        - display_name
      properties:
        email:
          type: string
          format: email
        display_name:
          type: string
          minLength: 1
          maxLength: 100
      additionalProperties: false  # CRITICAL - reject unknown
```

### 2. Documented Extensibility (If Needed)

```yaml
components:
  schemas:
    UserRequest:
      type: object
      required:
        - email
        - display_name
      properties:
        email:
          type: string
          format: email
        display_name:
          type: string
          minLength: 1
          maxLength: 100
        extensions:
          type: object
          description: "Validated extension object for custom integrations"
          additionalProperties:
            type: string
            maxLength: 500
      additionalProperties: false
```

---

## Verification Checklist

After applying remediation, verify:

- [ ] All request DTOs / input types have explicit property definitions
- [ ] Deserializer configured to reject unknown properties (fail-closed)
- [ ] No conditional logic reads undocumented fields from request
- [ ] Authorization middleware only uses documented properties
- [ ] Extensibility points have explicit schema (not `additionalProperties: true`)
- [ ] Requests with extra properties are logged for security monitoring
- [ ] Integration tests verify rejection of requests with shadow fields
- [ ] Error responses clearly indicate which properties are unknown
- [ ] OpenAPI spec matches implementation exactly
- [ ] Client SDKs updated to not send deprecated/extra fields

---

## Rollback Plan

If strict mode breaks legitimate clients:

1. **Identify affected clients** - Check logs for 400/422 errors with "unknown properties"
2. **Document legitimate extensions** - Move to explicit `extensions` object
3. **Temporary per-endpoint relaxation** - Only for specific endpoints that need it
4. **Client notification** - Inform API consumers of required changes
5. **Gradual re-enforcement** - Re-enable strict mode after client updates

```java
// Temporary relaxation (DOCUMENT WHY)
@JsonIgnoreProperties(ignoreUnknown = true)  // TEMPORARY - remove after YYYY-MM-DD
public class LegacyWebhookPayload { ... }
```