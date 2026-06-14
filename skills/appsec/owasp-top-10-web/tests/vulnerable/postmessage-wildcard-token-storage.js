// VULNERABLE: checkout state and bearer token cross a window trust boundary
// without exact origin pinning or payload validation.

const accessToken = localStorage.getItem("access_token");

checkoutFrame.contentWindow.postMessage(
  {
    type: "checkout:resume",
    token: accessToken,
    redirect: new URLSearchParams(location.search).get("next"),
  },
  "*"
);

window.addEventListener("message", (event) => {
  if (event.origin !== "https://payments.example") return;

  if (event.data.action === "redirect") {
    location.href = event.data.url;
  }

  if (event.data.action === "linkAccount") {
    linkAccount(event.data.accountId, event.data.token);
  }
});
