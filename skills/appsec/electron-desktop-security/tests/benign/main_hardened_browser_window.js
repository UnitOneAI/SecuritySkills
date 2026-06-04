const { BrowserWindow, shell } = require("electron");

const TRUSTED_ORIGIN = "https://app.example.com";

function isAllowedExternalUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    return url.protocol === "https:" && url.hostname === "docs.example.com";
  } catch {
    return false;
  }
}

function createMainWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      preload: require("path").join(__dirname, "preload.js"),
    },
  });

  win.loadURL(TRUSTED_ORIGIN);

  win.webContents.on("will-navigate", (event, targetUrl) => {
    if (!targetUrl.startsWith(TRUSTED_ORIGIN)) {
      event.preventDefault();
    }
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) {
      shell.openExternal(url);
    }
    return { action: "deny" };
  });

  return win;
}

module.exports = { createMainWindow };
