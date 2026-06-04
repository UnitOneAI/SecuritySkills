window.addEventListener("message", (event) => {
  const payload = event.data || {};

  if (payload.type === "render-profile") {
    document.querySelector("#profile").innerHTML = payload.html;
  }

  if (payload.type === "save-token") {
    chrome.storage.local.set({ refreshToken: payload.refreshToken });
  }
});
