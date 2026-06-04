const fs = require("fs");
const { ipcMain, shell } = require("electron");
const { autoUpdater } = require("electron-updater");

ipcMain.handle("read-local-file", async (_event, requestedPath) => {
  return fs.readFileSync(requestedPath, "utf8");
});

ipcMain.handle("open-anything", async (_event, target) => {
  await shell.openExternal(target);
});

ipcMain.handle("set-update-feed", async (_event, feedUrl) => {
  autoUpdater.setFeedURL({ url: feedUrl });
  return autoUpdater.checkForUpdates();
});
