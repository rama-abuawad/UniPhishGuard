// Register immediately so classic Outlook cannot fire Office.initialize
// before the task-pane application script has loaded.
window.uniphishguardOfficeReady = new Promise((resolve) => {
  let finished = false;
  const finish = (info) => {
    if (!finished) {
      finished = true;
      window.uniphishguardOfficeInfo = info || {};
      resolve(window.uniphishguardOfficeInfo);
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
