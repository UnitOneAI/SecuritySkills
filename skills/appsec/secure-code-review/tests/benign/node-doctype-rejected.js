const { SaxesParser } = require("saxes");

function parseMetadata(xmlBody) {
  const parser = new SaxesParser({ xmlns: true });
  parser.on("doctype", () => {
    throw new Error("DOCTYPE is not accepted for metadata XML");
  });
  parser.write(xmlBody).close();
  return true;
}

module.exports = { parseMetadata };
