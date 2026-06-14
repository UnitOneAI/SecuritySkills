import { autoUpdater } from "electron";

autoUpdater.setFeedURL({
  url: "https://updates.example.com/stable",
  allowAnyVersion: false,
});

autoUpdater.on("update-downloaded", () => {
  notifyUserThatUpdateWillInstallOnRestart();
});

function notifyUserThatUpdateWillInstallOnRestart() {
  return true;
}
