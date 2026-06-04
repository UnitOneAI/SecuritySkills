const { BrowserWindow, shell } = require("electron");

function createMainWindow(userControlledUrl) {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      webSecurity: false,
      allowRunningInsecureContent: true,
      preload: process.env.PRELOAD_PATH,
    },
  });

  win.loadURL(userControlledUrl);

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "allow" };
  });

  return win;
}

module.exports = { createMainWindow };
