/* PhishGuard NG front-end: tiny path-based view switcher + API call. */
(function () {
  "use strict";

  var VIEWS = { "/": "home", "/check": "check", "/awareness": "awareness", "/about": "about" };
  var EXAMPLES = {
    family: "Hi Mum, this is my new number. My old phone got stolen. Please save it and send ₦45,000 urgently to this account, I will explain later. Don't tell Daddy.",
    job: "Congratulations! You have been shortlisted for a job at a top oil company. No experience needed. Pay ₦15,000 registration fee to secure your slot. Hurry, limited vacancies.",
    otp: "Hello, I sent a verification code to your number by mistake. Please send it back to me quickly, it's very important."
  };

  var $ = function (id) { return document.getElementById(id); };
  var msg = $("msg"), urlInput = $("url"), btn = $("analyse-btn");

  function show(name) {
    ["home", "check", "results", "awareness", "about"].forEach(function (v) {
      $("view-" + v).hidden = v !== name;
    });
    var active = name === "results" ? "check" : name;
    document.querySelectorAll(".topbar nav a").forEach(function (a) {
      var isActive = VIEWS[a.getAttribute("href")] === active;
      if (isActive) { a.setAttribute("aria-current", "page"); } else { a.removeAttribute("aria-current"); }
    });
    window.scrollTo(0, 0);
  }

  function route() {
    var path = window.location.pathname.replace(/\/+$/, "") || "/";
    show(VIEWS[path] || "home");
  }

  function go(path) {
    if (window.location.pathname !== path) { history.pushState({}, "", path); }
    route();
  }

  document.addEventListener("click", function (e) {
    var link = e.target.closest("a[data-link]");
    if (link) { e.preventDefault(); go(link.getAttribute("href")); }
  });
  window.addEventListener("popstate", route);

  /* ---------- examples ---------- */
  document.querySelectorAll("[data-example]").forEach(function (b) {
    b.addEventListener("click", function () {
      msg.value = EXAMPLES[b.getAttribute("data-example")];
      urlInput.value = "";
      hideErrors();
      msg.focus();
    });
  });

  /* ---------- analyse ---------- */
  function hideErrors() { $("msg-error").hidden = true; $("api-error").hidden = true; }
  function showError(id, text) { var el = $(id); el.textContent = text; el.hidden = false; }

  function setLoading(on) {
    btn.disabled = on;
    btn.textContent = on ? "Checking…" : "Analyse message";
  }

  function analyse() {
    hideErrors();
    var text = msg.value.trim();
    if (!text) {
      showError("msg-error", "Paste the message you want to check first.");
      msg.focus();
      return;
    }
    setLoading(true);
    fetch("/api/analyse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text, url: urlInput.value.trim() || null })
    })
      .then(function (res) {
        return res.json().then(function (data) { return { ok: res.ok, data: data }; });
      })
      .then(function (r) {
        if (!r.ok) { throw new Error(typeof r.data.detail === "string" ? r.data.detail : "Something went wrong. Please try again."); }
        renderResults(r.data);
      })
      .catch(function (err) {
        showError("api-error", err.message || "Could not reach the server. Check your connection and try again.");
      })
      .then(function () { setLoading(false); });
  }

  /* All user-derived text is inserted with textContent (never innerHTML). */
  function el(tag, text, cls) {
    var n = document.createElement(tag);
    if (text) { n.textContent = text; }
    if (cls) { n.className = cls; }
    return n;
  }

  function renderResults(d) {
    var level = d.risk_level;
    $("banner").className = "banner risk-" + level.toLowerCase();
    $("r-level").textContent = d.level_label;
    $("r-score").textContent = d.score;
    $("r-summary").textContent = d.summary;
    $("r-meter").style.width = "0%";
    requestAnimationFrame(function () { $("r-meter").style.width = d.score + "%"; });

    var flags = $("r-flags");
    flags.textContent = "";
    if (!d.matched_rules.length) {
      var none = el("li", null, "none");
      none.appendChild(el("b", "No known red flags found"));
      flags.appendChild(none);
    }
    d.matched_rules.forEach(function (m) {
      var li = el("li");
      li.appendChild(el("b", m.name));
      if (m.details && m.details.length) {
        m.details.forEach(function (t) { li.appendChild(el("small", t)); });
      } else if (m.evidence) {
        li.appendChild(el("q", m.evidence));
      }
      flags.appendChild(li);
    });

    $("r-mode").textContent = d.ai_probability === null
      ? "Checked with the rule engine only (AI model not loaded)."
      : "Rules checked the wording; the AI model rated it " + Math.round(d.ai_probability * 100) + "% similar to known scams.";

    var advice = $("r-advice");
    advice.textContent = "";
    d.advice.forEach(function (a) { advice.appendChild(el("li", a)); });
    $("r-disclaimer").textContent = d.disclaimer;
    show("results");
    $("banner").setAttribute("tabindex", "-1");
    $("banner").focus({ preventScroll: true });
  }

  btn.addEventListener("click", analyse);
  $("again-btn").addEventListener("click", function () {
    msg.value = ""; urlInput.value = ""; hideErrors();
    show("check");
    msg.focus();
  });

  route();
})();
