// SafeScope web UI. All server data is inserted with textContent (never innerHTML) to avoid XSS.
(function () {
  "use strict";

  var CHECK_NAMES = {
    transport: "HTTPS & HSTS", tls: "TLS & certificate", headers: "Security headers",
    cookies: "Cookie security", disclosure: "Information disclosure"
  };
  var GRADE_COLORS = { A: "#1f9d55", B: "#5a9e1f", C: "#d69e2e", D: "#dd6b20", F: "#c53030" };
  var form = document.getElementById("scan-form");
  var input = document.getElementById("target");
  var button = document.getElementById("scan-btn");
  var statusEl = document.getElementById("status");
  var resultEl = document.getElementById("result");

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.className = isError ? "error" : "";
  }

  function apiUrl(target, format) {
    return "/api/scan?format=" + format + "&target=" + encodeURIComponent(target);
  }

  function render(data, target) {
    var grade = document.getElementById("grade");
    grade.textContent = data.grade;
    grade.style.background = GRADE_COLORS[String(data.grade).charAt(0)] || "#64748b";

    document.getElementById("result-target").textContent = data.final_url || data.target;
    document.getElementById("result-meta").textContent =
      "Score " + data.score + "/100 · scanned in " + data.duration_seconds + "s · SafeScope v" + data.tool.version;
    document.getElementById("full-report").href = apiUrl(target, "html");
    document.getElementById("json-link").href = apiUrl(target, "json");

    var counts = document.getElementById("counts");
    counts.replaceChildren();
    Object.keys(data.summary).forEach(function (sev) {
      var box = el("div", "count");
      box.appendChild(el("b", "sev-" + sev, data.summary[sev]));
      box.appendChild(el("span", null, sev));
      counts.appendChild(box);
    });

    var groups = {};
    data.findings.forEach(function (f) {
      (groups[f.check_id] = groups[f.check_id] || []).push(f);
    });
    var container = document.getElementById("findings");
    container.replaceChildren();
    Object.keys(groups).forEach(function (checkId) {
      var group = el("div", "group");
      group.appendChild(el("h3", null, CHECK_NAMES[checkId] || checkId));
      groups[checkId]
        .sort(function (a, b) { return problemRank(b) - problemRank(a); })
        .forEach(function (f) { group.appendChild(renderFinding(f)); });
      container.appendChild(group);
    });

    resultEl.hidden = false;
  }

  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  function isProblem(f) { return f.status === "fail" || f.status === "warn"; }
  function problemRank(f) { return isProblem(f) ? 10 + SEV_RANK[f.severity] : 0; }

  function renderFinding(f) {
    var item = el("div", "item");
    var row = el("div", "row");
    row.appendChild(el("span", "badge st-" + f.status, f.status));
    row.appendChild(el("span", null, f.title));
    if (isProblem(f) && f.severity !== "info") row.appendChild(el("span", "sev sev-" + f.severity, f.severity));
    item.appendChild(row);
    if (isProblem(f)) {
      if (f.description) item.appendChild(el("p", "detail", f.description));
      if (f.recommendation) item.appendChild(el("div", "fix", "Fix: " + f.recommendation));
    } else if ((f.status === "error" || f.status === "skipped") && f.description) {
      item.appendChild(el("p", "detail", f.description));
    }
    return item;
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var target = input.value.trim();
    if (!target) return;
    button.disabled = true;
    resultEl.hidden = true;
    setStatus("Scanning " + target + "… this usually takes 2–10 seconds.");

    fetch(apiUrl(target, "json"), { headers: { Accept: "application/json" } })
      .then(function (resp) {
        return resp.json().then(function (body) { return { ok: resp.ok, body: body }; });
      })
      .then(function (r) {
        if (!r.ok) throw new Error(r.body && r.body.error ? r.body.error : "scan failed");
        setStatus("");
        render(r.body, target);
        history.replaceState(null, "", "?target=" + encodeURIComponent(target));
      })
      .catch(function (err) { setStatus(err.message || "Scan failed", true); })
      .finally(function () { button.disabled = false; });
  });

  var preset = new URLSearchParams(location.search).get("target");
  if (preset) input.value = preset;
})();
