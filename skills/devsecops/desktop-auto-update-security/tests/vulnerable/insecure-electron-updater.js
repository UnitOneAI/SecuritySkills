import { autoUpdater } from "electron";

autoUpdater.setFeedURL({
  url: "http://updates.example.com/latest",
  allowAnyVersion: true,
});

autoUpdater.on("update-downloaded", () => {
  autoUpdater.quitAndInstall();
});
