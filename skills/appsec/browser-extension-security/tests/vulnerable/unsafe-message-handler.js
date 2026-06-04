chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (message.action === "run") {
    chrome.scripting.executeScript({
      target: { tabId: message.tabId },
      func: (code) => eval(code),
      args: [message.code]
    });
  }

  if (message.action === "fetch") {
    fetch(message.url)
      .then((response) => response.text())
      .then((body) => sendResponse({ body }));
    return true;
  }
});
