// Register before Office.js loads. Classic Outlook can fire Office.initialize
// while the hosted library is loading, before later page scripts execute.
window.uniphishguardOfficeReady = new Promise((resolve) => {
  let finished = false;
  const finish = (info) => {
    if (!finished) {
      finished = true;
      resolve(info || {});
    }
  };

  window.uniphishguardFinishOfficeReady = finish;
  window.Office = window.Office || {};
  window.Office.initialize = () => finish({ host: "outlook", source: "initialize" });
});
