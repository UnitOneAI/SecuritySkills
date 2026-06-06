function downloadReport(req, res) {
  const requestedName = req.query.filename;

  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${requestedName}"`,
  );
  res.setHeader("Content-Type", "text/csv");
  res.end("id,total\n1,42\n");
}

module.exports = { downloadReport };
