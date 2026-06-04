const TRUSTED_EXTENSION_IDS = new Set(["abcdefghijklmnopabcdefghijklmnop"]);
const TRUSTED_ORIGINS = new Set(["https://admin.example.com"]);
const ALLOWED_NATIVE_COMMANDS = new Set(["status", "openSupportBundle"]);

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  const origin = sender.origin || new URL(sender.url || "https://invalid.example").origin;

  if (!TRUSTED_EXTENSION_IDS.has(sender.id) || !TRUSTED_ORIGINS.has(origin)) {
    sendResponse({ error: "unauthorized" });
    return false;
  }

  if (!message || !ALLOWED_NATIVE_COMMANDS.has(message.command)) {
    sendResponse({ error: "invalid_command" });
    return false;
  }

  chrome.runtime.sendNativeMessage(
    "com.example.admin_host",
    { command: message.command },
    (response) => sendResponse(response)
  );

  return true;
});
