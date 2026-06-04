const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("desktop", {
  send(channel, payload) {
    ipcRenderer.send(channel, payload);
  },
  invoke(channel, payload) {
    return ipcRenderer.invoke(channel, payload);
  },
  on(channel, listener) {
    ipcRenderer.on(channel, (_event, value) => listener(value));
  },
});
