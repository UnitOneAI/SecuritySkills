window.addEventListener("message", (event) => {
  if (event.origin !== "https://app.example.com") {
    return;
  }

  const payload = event.data || {};
  if (payload.type !== "render-profile" || typeof payload.displayName !== "string") {
    return;
  }

  document.querySelector("#profile").textContent = payload.displayName;
});
