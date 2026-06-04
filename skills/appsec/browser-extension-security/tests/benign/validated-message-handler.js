const ALLOWED_EXTENSION_ID = chrome.runtime.id;
const ALLOWED_ORIGINS = new Set(["https://app.example.com"]);
const ALLOWED_EXPORT_URL = "https://api.example.com/export";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const origin = sender.origin || new URL(sender.url || "https://invalid.example").origin;

  if (sender.id !== ALLOWED_EXTENSION_ID || !ALLOWED_ORIGINS.has(origin)) {
    sendResponse({ error: "unauthorized" });
    return false;
  }

  if (!message || message.action !== "exportCurrentProject" || typeof message.projectId !== "string") {
    sendResponse({ error: "invalid_message" });
    return false;
  }

  fetch(ALLOWED_EXPORT_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ projectId: message.projectId })
  })
    .then((response) => response.json())
    .then((body) => sendResponse({ body }));

  return true;
});
