chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  const tabId = tabs[0].id;
  const key = `scan_${tabId}`;
  const stored = await chrome.storage.session.get(key);
  const result = stored[key];
  const el = document.getElementById("content");

  if (!result) {
    el.innerHTML = "<span class='verdict safe'>No risk detected</span>";
    return;
  }

  el.innerHTML = `
    <span class="verdict ${result.verdict}">${result.verdict.toUpperCase()} (${result.risk_score}/100)</span>
    <p>${result.ai_explanation}</p>
    <ul>${result.risk_factors.map(f => `<li>${f}</li>`).join("")}</ul>
  `;
});
