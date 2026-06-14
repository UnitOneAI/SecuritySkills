// BENIGN: non-sensitive UI state is stored in localStorage, and cross-window
// messages are pinned to an exact origin plus a narrow payload schema.

localStorage.setItem("theme", "dark");

const PAY_ORIGIN = "https://payments.example";

checkoutFrame.contentWindow.postMessage(
  { type: "checkout:resize", height: 480 },
  PAY_ORIGIN
);

window.addEventListener("message", (event) => {
  if (event.origin !== PAY_ORIGIN) return;

  const data = event.data;
  if (
    !data ||
    data.type !== "checkout:resize" ||
    !Number.isInteger(data.height) ||
    data.height < 100 ||
    data.height > 900
  ) {
    return;
  }

  checkoutFrame.style.height = `${data.height}px`;
});
