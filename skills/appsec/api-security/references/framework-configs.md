# Framework-Specific Deserializer Configurations for Shadow Field Prevention

This document provides secure deserializer configurations for each major
framework. Use these as reference implementations when applying the
`api-schema-shadow-field-review` skill.

---

## Java / Spring Boot (Jackson)

### Global Configuration (Application-wide)

```java
@Configuration
public class JacksonConfig {

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        
        // CRITICAL: Fail on unknown properties - prevents shadow fields
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        
        // Additional security hardening
        mapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);
        mapper.configure(DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE, false);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(MapperFeature.DEFAULT_VIEW_INCLUSION, false);
        
        // Java 8 time module
        mapper.registerModule(new JavaTimeModule());
        
        return mapper;
    }
}
```

### Per-Controller/Endpoint Override (When Needed)

```java
// Only for specific endpoints that need flexible parsing (e.g., webhook receivers)
@JsonIgnoreProperties(ignoreUnknown = true)  // Use sparingly, document why
public class WebhookPayload { ... }

// Better: explicit extension point
public class WebhookPayload {
    // Documented, validated extension object
    @Valid
    private Map<String, @Valid ExtensionValue> extensions;
}
```

### Spring Boot 3.x / Jackson 2.15+ Properties

```yaml
# application.yml
spring:
  jackson:
    deserialization:
      FAIL_ON_UNKNOWN_PROPERTIES: true
      FAIL_ON_NULL_FOR_PRIMITIVES: true
      READ_UNKNOWN_ENUM_VALUES_AS_NULL: false
    serialization:
      WRITE_DATES_AS_TIMESTAMPS: false
```

---

## C# / ASP.NET Core (System.Text.Json)

### Global Configuration (Program.cs)

```csharp
// .NET 7+ - Configure STJ globally
builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
{
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
    options.SerializerOptions.AllowTrailingCommas = true;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    // Note: STJ ignores unknown properties by default - this is SECURE
    // No additional config needed for shadow field prevention!
});

builder.Services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(options =>
{
    options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    options.JsonSerializerOptions.AllowTrailingCommas = true;
});

// For controllers returning ProblemDetails
builder.Services.AddProblemDetails();
```

### Per-Model Strict Binding (When Using Source Generation)

```csharp
// .NET 7+ source generation - explicit contract
[JsonSerializable(typeof(UserRequest))]
[JsonSerializable(typeof(UserResponse))]
[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    AllowTrailingCommas = true,
    // Default: unknown properties ignored (secure)
    // To make it strict (throw on unknown), use:
    // UnknownTypeHandling = JsonUnknownTypeHandling.JsonNode  // captures unknown
)]
internal partial class AppJsonContext : JsonSerializerContext { }

// Usage in Minimal API
app.MapPost("/users", async (UserRequest request, AppDbContext db) =>
{
    // request only contains defined properties
    // Unknown properties were ignored (secure default)
})
.AddEndpointFilter(async (context, next) =>
{
    // Optional: Log if unknown properties were present
    var jsonNode = context.HttpContext.RequestServices
        .GetRequiredService<AppJsonContext>()
        .Deserialize<JsonNode>(context.HttpContext.Request.Body);
    // Check jsonNode for properties not in UserRequest
    return await next(context);
});
```

### Newtonsoft.Json (Legacy / When Required)

```csharp
// Program.cs - if using Newtonsoft
builder.Services.AddControllers()
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.MissingMemberHandling = MissingMemberHandling.Error;
        options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
        options.SerializerSettings.DateParseHandling = DateParseHandling.DateTimeOffset;
        options.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
    });
```

---

## Python / FastAPI (Pydantic v2)

### Global Configuration

```python
# main.py
from pydantic import ConfigDict, Extra

# Set global default to forbid extra fields
BaseModel.model_config = ConfigDict(
    extra=Extra.forbid,  # Reject unknown properties
    str_strip_whitespace=True,
    validate_assignment=True,
    use_enum_values=True,
)
```

### Per-Model Configuration

```python
# models.py
from pydantic import BaseModel, ConfigDict, Field, EmailStr
from typing import Optional
from datetime import datetime

class UserRequest(BaseModel):
    """Strict model - forbids extra fields (shadow fields)"""
    model_config = ConfigDict(
        extra=Extra.forbid,
        str_strip_whitespace=True,
    )
    
    email: EmailStr
    display_name: str = Field(..., min_length=1, max_length=100)
    # Any extra field (isAdmin, bypass, etc.) will raise ValidationError

class UserResponse(BaseModel):
    model_config = ConfigDict(
        extra=Extra.forbid,
        from_attributes=True,  # For ORM mode
    )
    
    id: int
    email: EmailStr
    display_name: str
    created_at: datetime
```

### FastAPI Integration

```python
# main.py
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

app = FastAPI()

@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    """Custom error response for shadow field detection"""
    errors = []
    for error in exc.errors():
        if error['type'] == 'extra_forbidden':
            errors.append({
                "field": '.'.join(str(loc) for loc in error['loc']),
                "message": f"Unknown property not allowed: {error['msg']}",
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

@app.post("/users")
async def create_user(request: UserRequest):
    # request guaranteed to have only defined fields
    return await user_service.create(request)
```

### Django REST Framework

```python
# serializers.py
from rest_framework import serializers

class UserRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    display_name = serializers.CharField(max_length=100)
    
    # DRF ignores unknown fields by default (secure)
    # To be explicit:
    class Meta:
        fields = ['email', 'display_name']
        # unknown fields are ignored (not an error, but not processed)

# For strict validation (reject unknown):
class StrictUserRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    display_name = serializers.CharField(max_length=100)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # This makes it raise error on unknown fields
        self._declared_fields = dict(self._declared_fields)
    
    def run_validation(self, data=empty):
        # Check for unknown fields
        if isinstance(data, dict):
            known = set(self.fields.keys())
            unknown = set(data.keys()) - known
            if unknown:
                raise serializers.ValidationError({
                    field: "This field is not allowed." for field in unknown
                })
        return super().run_validation(data)
```

---

## Go (Standard Library encoding/json)

### Strict Decoding Middleware

```go
// middleware/strict_json.go
package middleware

import (
    "encoding/json"
    "net/http"
    "strings"
)

func StrictJSONMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
            contentType := r.Header.Get("Content-Type")
            if strings.HasPrefix(contentType, "application/json") {
                // Wrap body reader to enforce strict decoding
                r.Body = &strictJSONReader{body: r.Body}
            }
        }
        next.ServeHTTP(w, r)
    })
}

type strictJSONReader struct {
    body       io.ReadCloser
    decoded    bool
    data       map[string]interface{}
    err        error
}

func (s *strictJSONReader) Read(p []byte) (n int, err error) {
    if s.decoded {
        // Already decoded, return cached data
        if s.data != nil {
            return json.NewEncoder(bytes.NewBuffer(p)).Encode(s.data)
        }
        return 0, io.EOF
    }
    
    // Read entire body
    bodyBytes, err := io.ReadAll(s.body)
    if err != nil {
        return 0, err
    }
    
    // Strict decode
    dec := json.NewDecoder(bytes.NewReader(bodyBytes))
    dec.DisallowUnknownFields()
    
    var data map[string]interface{}
    if err := dec.Decode(&data); err != nil {
        s.err = err
        // Return error response
        return 0, err
    }
    
    s.data = data
    s.decoded = true
    
    // Re-encode for downstream handlers
    return json.NewEncoder(bytes.NewBuffer(p)).Encode(data)
}

func (s *strictJSONReader) Close() error {
    return s.body.Close()
}
```

### Handler with Strict Struct

```go
// handlers/user.go
package handlers

import (
    "encoding/json"
    "net/http"
)

type UserRequest struct {
    Email       string `json:"email"`
    DisplayName string `json:"display_name"`
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
    // Strict decode - rejects unknown fields
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    
    var req UserRequest
    if err := dec.Decode(&req); err != nil {
        // Check if it's an unknown field error
        var syntaxErr *json.SyntaxError
        var unmarshalTypeErr *json.UnmarshalTypeError
        if errors.As(err, &syntaxErr) || errors.As(err, &unmarshalTypeErr) {
            http.Error(w, `{"error":"Invalid JSON","details":"Unknown or invalid fields"}`, http.StatusBadRequest)
            return
        }
        // Generic decode error
        http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
        return
    }
    
    // req only has Email and DisplayName
    // Process request...
}
```

---

## Node.js / Express (Built-in + Custom)

### Express 4.18+ Built-in Parser

```javascript
// app.js
const express = require('express');
const app = express();

// Built-in JSON parser - strict: true by default (secure)
// Only parses objects, rejects arrays/primitives at root
app.use(express.json({ 
    strict: true,        // Default: true - only accepts objects
    limit: '1mb',        // Limit request size
    verify: (req, res, buf, encoding) => {
        // Store raw body for potential logging
        req.rawBody = buf.toString(encoding);
    }
}));

// Custom middleware to reject unknown properties
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

// Usage per route
app.post('/users', 
    rejectUnknownProperties(['email', 'display_name']),
    async (req, res) => {
        // req.body only has email and display_name
        const user = await userService.create(req.body);
        res.status(201).json(user);
    }
);
```

### NestJS (class-validator + class-transformer)

```typescript
// main.ts
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    
    app.useGlobalPipes(new ValidationPipe({
        whitelist: true,           // Strip unknown properties (secure)
        forbidNonWhitelisted: true, // Throw error on unknown properties (STRICT)
        transform: true,
        disableErrorMessages: false,
        validationError: { target: false, value: false },
    }));
    
    await app.listen(3000);
}
```

```typescript
// user.dto.ts
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

    // Any extra property (isAdmin, bypass, etc.) will cause validation error
    // because of forbidNonWhitelisted: true
}
```

---

## GraphQL (Apollo Server / HotChocolate / graphql-go)

### Apollo Server (Node.js)

```javascript
// schema.js
const { gql } = require('apollo-server');

const typeDefs = gql`
    input CreateUserInput {
        email: String!
        display_name: String!
        # NO extra fields allowed - GraphQL schema is strict by default
    }
    
    type User {
        id: ID!
        email: String!
        display_name: String!
        created_at: String!
    }
    
    type Mutation {
        createUser(input: CreateUserInput!): User!
    }
`;

// Resolver - GraphQL validates against schema automatically
const resolvers = {
    Mutation: {
        createUser: async (_, { input }, context) => {
            // input ONLY contains email and display_name
            // GraphQL schema validation rejects unknown fields
            return userService.create(input);
        }
    }
};
```

### HotChocolate (.NET)

```csharp
// Schema
public class CreateUserInput : InputObjectType<CreateUserInput>
{
    protected override void Configure(IInputObjectTypeDescriptor<CreateUserInput> descriptor)
    {
        descriptor.Field(f => f.Email).Type<NonNullType<StringType>>();
        descriptor.Field(f => f.DisplayName).Type<NonNullType<StringType>>();
        // No extra fields possible - schema is strictly typed
    }
}

public record CreateUserInput(string Email, string DisplayName);

// Resolver
public class Mutation
{
    public async Task<User> CreateUserAsync(
        CreateUserInput input,  // Strictly typed - only Email and DisplayName
        [Service] IUserService userService)
    {
        return await userService.CreateAsync(input);
    }
}

// Disable introspection in production
builder.Services
    .AddGraphQLServer()
    .AddQueryType<Query>()
    .AddMutationType<Mutation>()
    .AddIntrospectionAllowedRule(options => 
    {
        // Only allow introspection in development
        options.AllowIntrospection = builder.Environment.IsDevelopment();
    });
```

### graphql-go (gqlgen)

```go
// schema.graphqls
input CreateUserInput {
    email: String!
    display_name: String!
}

type Mutation {
    createUser(input: CreateUserInput!): User!
}

// Resolver - generated code enforces schema
func (r *mutationResolver) CreateUser(ctx context.Context, input model.CreateUserInput) (*model.User, error) {
    // input struct only has Email and DisplayName fields
    // gqlgen validates against schema automatically
    return r.userService.Create(ctx, input)
}
```

---

## Configuration Summary Table

| Framework | Default Behavior | Secure Config | Strict Config |
|---|---|---|---|
| Jackson (Java) | Ignores unknown | `FAIL_ON_UNKNOWN_PROPERTIES=true` | Per-class `@JsonIgnoreProperties(ignoreUnknown=false)` |
| STJ (.NET) | Ignores unknown (secure) | Default is secure | Source gen with `UnknownTypeHandling=JsonNode` |
| Newtonsoft (.NET) | Ignores unknown | `MissingMemberHandling=Error` | Per-model attribute |
| Pydantic v2 (Python) | Allows extra | `ConfigDict(extra=Extra.forbid)` | Global `BaseModel.model_config` |
| DRF (Python) | Ignores unknown | Custom `run_validation` | Explicit field list + validation |
| encoding/json (Go) | Ignores unknown | `dec.DisallowUnknownFields()` | Middleware wrapper |
| Express (Node) | Strict objects only | Custom middleware | `rejectUnknownProperties()` |
| NestJS (Node) | Strips unknown | `whitelist: true` | `forbidNonWhitelisted: true` |
| GraphQL (all) | Schema-enforced | Default is strict | Disable introspection in prod |

---

## Migration Checklist

When upgrading existing APIs to strict mode:

1. **Audit current requests** - Log unknown properties for 2 weeks before enabling strict mode
2. **Identify legitimate extensions** - Move to documented `extensions` object with schema
3. **Update client SDKs** - Ensure clients don't send deprecated/extra fields
4. **Enable in staging first** - Test with production-like traffic
5. **Monitor error rates** - Watch for 400/422 spikes after deployment
6. **Gradual rollout** - Enable per-endpoint or per-API version
7. **Document exceptions** - Any endpoint that must accept unknown fields (webhooks) must be documented and isolated