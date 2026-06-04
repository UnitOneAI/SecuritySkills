const path = require("path");
const { app, ipcMain } = require("electron");
const { autoUpdater } = require("electron-updater");

const TRUSTED_ORIGIN = "https://app.example.com";
const REPORT_DIR = path.join(app.getPath("userData"), "reports");
const UPDATE_FEED = "https://updates.example.com/desktop/stable";

function assertTrustedSender(event) {
  const senderUrl = event.senderFrame && event.senderFrame.url;
  if (!senderUrl) {
    throw new Error("untrusted sender");
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(senderUrl);
  } catch {
    throw new Error("untrusted sender");
  }

  if (parsedUrl.origin !== TRUSTED_ORIGIN) {
    throw new Error("untrusted sender");
  }
}

function reportPath(reportId) {
  if (!/^[a-z0-9_-]{1,40}$/i.test(reportId)) {
    throw new Error("invalid report id");
  }
  return path.join(REPORT_DIR, `${reportId}.json`);
}

ipcMain.handle("reports:read", async (event, reportId) => {
  assertTrustedSender(event);
  return { path: reportPath(reportId) };
});

ipcMain.handle("updates:check", async (event) => {
  assertTrustedSender(event);
  autoUpdater.setFeedURL({ url: UPDATE_FEED });
  return autoUpdater.checkForUpdates();
});
