(function () {
  let finish;
  let finished = false;

  window.uniphishguardOfficeReady = new Promise((resolve) => {
    finish = (info) => {
      if (!finished) {
        finished = true;
        resolve(info || {});
      }
    };
  });

  if (!window.Office) {
    finish({ host: "browser" });
    return;
  }

  Office.initialize = function () {
    finish({ host: "outlook", source: "initialize" });
  };

  if (typeof Office.onReady === "function") {
    Office.onReady((info) => finish(info)).catch(() => {});
  }
})();
