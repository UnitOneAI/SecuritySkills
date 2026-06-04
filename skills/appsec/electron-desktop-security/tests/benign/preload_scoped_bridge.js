const { contextBridge, ipcRenderer } = require("electron");

function assertReportId(reportId) {
  if (!/^[a-z0-9_-]{1,40}$/i.test(reportId)) {
    throw new Error("invalid report id");
  }
  return reportId;
}

contextBridge.exposeInMainWorld("reports", {
  read(reportId) {
    return ipcRenderer.invoke("reports:read", assertReportId(reportId));
  },
  export(reportId) {
    return ipcRenderer.invoke("reports:export", assertReportId(reportId));
  },
});
