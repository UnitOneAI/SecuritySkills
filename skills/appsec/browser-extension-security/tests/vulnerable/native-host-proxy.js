chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (message.action !== "nativeCommand") {
    return false;
  }

  chrome.runtime.sendNativeMessage(
    "com.example.admin_host",
    {
      command: message.command,
      args: message.args,
      requester: sender.url
    },
    (response) => sendResponse(response)
  );

  return true;
});
