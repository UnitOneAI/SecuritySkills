# Vulnerable and Remediated Code Patterns

## 1. Python -- SQL Injection (CWE-89)

```python
# VULNERABLE: string formatting in SQL query
def get_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
```
Remediation: Use parameterized queries -- `cursor.execute("SELECT * FROM users WHERE name = %s", (username,))`.

## 2. JavaScript -- Cross-site Scripting (CWE-79)

```javascript
// VULNERABLE: inserting unsanitized user input into DOM
app.get('/search', (req, res) => {
  res.send(`<h1>Results for: ${req.query.q}</h1>`);
});
```
Remediation: Use a templating engine with auto-escaping enabled, or explicitly escape with a library such as `he` or `DOMPurify`.

## 3. Go -- OS Command Injection (CWE-78)

```go
// VULNERABLE: user input passed directly to shell execution
func handler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    cmd := exec.Command("sh", "-c", "cat "+filename)
    output, _ := cmd.Output()
    w.Write(output)
}
```
Remediation: Avoid shell invocations. Use `exec.Command("cat", filename)` with an allowlist of permitted filenames.

## 4. Java -- Path Traversal (CWE-22)

```java
// VULNERABLE: user-controlled path with no canonicalization
String filename = request.getParameter("file");
File f = new File("/uploads/" + filename);
FileInputStream fis = new FileInputStream(f);
```
Remediation: Canonicalize the resolved path and verify it remains within the expected base directory.

## 5. Python -- Hard-coded Credentials (CWE-798)

```python
# VULNERABLE: credentials embedded in source code
DB_PASSWORD = "s3cretPassw0rd!"
conn = psycopg2.connect(host="db.internal", password=DB_PASSWORD)
```
Remediation: Load credentials from environment variables or a secrets manager. Never commit secrets to version control.

## 6. JavaScript -- Missing Authentication (CWE-306)

```javascript
// VULNERABLE: admin endpoint with no authentication middleware
app.post('/admin/delete-user', (req, res) => {
  db.deleteUser(req.body.userId);
  res.json({ success: true });
});
```
Remediation: Apply authentication middleware to all sensitive endpoints -- `app.post('/admin/delete-user', requireAuth, requireAdmin, handler)`.

## 7. Java -- Weak Session Management (CWE-287)

```java
// VULNERABLE: predictable session identifier
String sessionId = "session-" + System.currentTimeMillis();
response.addCookie(new Cookie("SESSIONID", sessionId));
```
Remediation: Use the framework's built-in session management (e.g., `HttpSession`) which generates cryptographically random tokens.

## 8. Python -- Missing Authorization (CWE-862)

```python
# VULNERABLE: no ownership check -- any authenticated user can view any profile
@app.route('/api/profile/<user_id>')
@login_required
def get_profile(user_id):
    return jsonify(db.get_profile(user_id))
```
Remediation: Verify `current_user.id == user_id` or that the requester holds an explicit role granting access.

## 9. Go -- CSRF on State-Changing Operations (CWE-352)

```go
// VULNERABLE: state-changing operation via GET with no CSRF token
http.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
    amount := r.URL.Query().Get("amount")
    to := r.URL.Query().Get("to")
    doTransfer(r.Context(), to, amount)
})
```
Remediation: Require POST with a validated CSRF token. Use a CSRF middleware library (e.g., `gorilla/csrf`).

## 10. Python -- Weak Cryptography (CWE-327)

```python
# VULNERABLE: using ECB mode (does not provide semantic security)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
```
Remediation: Use AES-GCM or AES-CBC with HMAC. Prefer high-level libraries like `cryptography.fernet`.

## 11. JavaScript -- Insecure Randomness (CWE-330)

```javascript
// VULNERABLE: Math.random() is not cryptographically secure
function generateToken() {
  return Math.random().toString(36).substring(2);
}
```
Remediation: Use `crypto.randomBytes(32).toString('hex')` (Node.js) or `crypto.getRandomValues()` (browser).

## 12. Python -- Unsafe Deserialization (CWE-502)

```python
# VULNERABLE: deserializing untrusted data with pickle
import pickle
data = pickle.loads(request.data)
```
Remediation: Never use `pickle` on untrusted input. Use JSON or a schema-validated format. If object serialization is required, use a safe library with type restrictions.

## 13. Java -- Unsafe Deserialization (CWE-502)

```java
// VULNERABLE: deserializing arbitrary objects from user input
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();
```
Remediation: Avoid native Java deserialization of untrusted data. Use JSON with explicit type mapping, or apply an allowlist filter (e.g., Apache Commons IO `ValidatingObjectInputStream`).

## 14. TypeScript -- Unrestricted File Upload (CWE-434)

```typescript
// VULNERABLE: no validation on uploaded file type or size
app.post('/upload', upload.single('file'), (req, res) => {
  fs.renameSync(req.file.path, `/uploads/${req.file.originalname}`);
  res.json({ url: `/uploads/${req.file.originalname}` });
});
```
Remediation: Validate MIME type against an allowlist, enforce maximum file size, generate a random filename, and store uploads outside the webroot.

## 15. Go -- SSRF (CWE-918)

```go
// VULNERABLE: user-supplied URL fetched without restriction
func fetchURL(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, _ := http.Get(url)
    io.Copy(w, resp.Body)
}
```
Remediation: Validate the URL scheme (allow only `https`), resolve the hostname and reject private/internal IP ranges, and use an allowlist of permitted domains.

## 16. Java -- Verbose Error Disclosure (CWE-209)

```java
// VULNERABLE: stack trace exposed to the end user
catch (SQLException e) {
    response.getWriter().println("Error: " + e.getMessage());
    e.printStackTrace(response.getWriter());
}
```
Remediation: Log the exception server-side with a correlation ID. Return a generic message -- `"An internal error occurred. Reference: <correlationId>"`.

## 17. Python -- Sensitive Data in Logs (CWE-532)

```python
# VULNERABLE: logging user credentials
logger.info(f"Login attempt for {username} with password {password}")
```
Remediation: Never log secrets. Log only the username and the outcome -- `logger.info(f"Login attempt for {username}: {'success' if ok else 'failure'}")`.
