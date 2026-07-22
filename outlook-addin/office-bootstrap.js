// Register immediately after Office.js loads. Classic Outlook can initialize
// before the task-pane application script at the end of the page is available.
window.uniphishguardOfficeReady = new Promise((resolve) => {
  let finished = false;
  const finish = (info) => {
    if (!finished) {
      finished = true;
      resolve(info || {});
    }
  };

  window.uniphishguardFinishOfficeReady = finish;
  if (!window.Office) {
    finish({ host: "browser" });
  } else {
    Office.initialize = () => finish({ host: "outlook", source: "initialize" });
    if (typeof Office.onReady === "function") {
      Office.onReady((info) => finish(info)).catch(() => {});
    }
  }
});
