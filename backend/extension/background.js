// PhishGuard AI browser extension - background service worker.
// Calls the backend's /scan/public-demo (or /scan with a stored API key)
// every time the user navigates to a new page, and warns them if it's risky.
//
// This is a minimal starting point for feature #3 in MONETIZATION_GUIDE.md.
// Swap API_BASE to your deployed backend URL before publishing.

const API_BASE = "http://127.0.0.1:8000";

async function checkUrl(url) {
  try {
    const stored = await chrome.storage.sync.get("apiKey");
    const headers = { "Content-Type": "application/json" };
    let endpoint = `${API_BASE}/scan/public-demo`;
    if (stored.apiKey) {
      headers["X-API-Key"] = stored.apiKey;
      endpoint = `${API_BASE}/scan`;
    }
    const res = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({ url }),
    });
    return await res.json();
  } catch (e) {
    console.error("PhishGuard check failed:", e);
    return null;
  }
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // only top-level navigation
  const url = details.url;
  if (!url.startsWith("http")) return;

  const result = await checkUrl(url);
  if (!result) return;

  if (result.verdict === "phishing" || result.verdict === "suspicious") {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#E53E3E" });
    chrome.storage.session.set({ [`scan_${details.tabId}`]: result });
  } else {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
  }
});
