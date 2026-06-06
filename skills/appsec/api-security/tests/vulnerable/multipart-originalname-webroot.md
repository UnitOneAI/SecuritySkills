# Vulnerable: multipart upload trusts metadata and serves from web root

This fixture should trigger API8:2023 and API4:2023 concerns.

```javascript
const multer = require('multer');
const fs = require('fs');
const upload = multer({ storage: multer.memoryStorage() });

app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (req.file.mimetype !== 'image/png') {
    return res.status(400).end();
  }

  const output = `/var/www/uploads/${req.file.originalname}`;
  await fs.promises.writeFile(output, req.file.buffer);
  res.json({ url: `/uploads/${req.file.originalname}` });
});
```

Expected findings:

- User-controlled `Content-Type` is treated as the file-type decision.
- `originalname` is used as a filesystem path and public URL component.
- Uploaded content is served from the application origin.
- No evidence of file count, per-file size, server-generated object key, magic-number validation, quarantine, or safe download headers.
