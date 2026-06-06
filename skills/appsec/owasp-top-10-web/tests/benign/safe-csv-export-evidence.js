const path = require("path");

const FORMULA_LEADING = /^[=+\-@\t\r]/;

function neutralizeCsvCell(value) {
  const text = String(value ?? "");
  return FORMULA_LEADING.test(text) ? `'${text}` : text;
}

function quoteCsv(value) {
  return `"${neutralizeCsvCell(value).replace(/"/g, '""')}"`;
}

function safeExportFilename(input) {
  const basename = path.basename(String(input || "report.csv"));
  const normalized = basename.replace(/[^A-Za-z0-9._-]/g, "_");

  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.csv$/.test(normalized)) {
    return "report.csv";
  }

  return normalized;
}

function exportUsersCsv(req, res) {
  const filename = safeExportFilename(req.query.filename);
  const rows = [
    ["email", "notes"],
    ["analyst@example.test", req.query.note || "=literal text"],
  ];
  const csv = rows.map((row) => row.map(quoteCsv).join(",")).join("\r\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
  );
  res.end(csv);
}

module.exports = {
  exportUsersCsv,
  neutralizeCsvCell,
  safeExportFilename,
};
