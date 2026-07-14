/* ============================================================
   app.js — navigation, progress tracking, and the interactive
   widgets (email flags, domain game, tactics, tips, quiz).
   Pure vanilla JS, no dependencies.
   ============================================================ */

(function () {
  "use strict";

  const $  = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const sections = $$(".section");
  const nav = $("#nav");
  const visited = new Set();

  /* ---------------------------------------------------------
     Build the sidebar navigation from the sections present.
     --------------------------------------------------------- */
  sections.forEach((sec, i) => {
    const a = document.createElement("a");
    a.href = "#" + sec.id;
    a.dataset.target = sec.id;
    a.innerHTML =
      `<span class="num"><span>${String(i + 1).padStart(2, "0")}</span></span>` +
      `<span>${sec.dataset.title}</span>`;
    a.addEventListener("click", (e) => { e.preventDefault(); showSection(sec.id); });
    nav.appendChild(a);
  });

  function showSection(id) {
    sections.forEach((s) => s.classList.toggle("active", s.id === id));
    $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.target === id));
    visited.add(id);
    updateProgress();
    $("#content").scrollTo({ top: 0, behavior: "smooth" });
    window.scrollTo({ top: 0 });
    $("#sidebar").classList.remove("open");
    markDone();
  }

  function markDone() {
    $$("#nav a").forEach((a) => {
      if (visited.has(a.dataset.target)) a.classList.add("done");
    });
  }

  function updateProgress() {
    const pct = Math.round((visited.size / sections.length) * 100);
    $("#progressFill").style.transform = `scaleX(${pct / 100})`;
    $("#progressPct").textContent = pct + "%";
  }

  /* "Start the course" and any [data-goto] buttons. */
  $$("[data-goto]").forEach((b) =>
    b.addEventListener("click", () => showSection(b.dataset.goto))
  );

  /* Mobile menu toggle. */
  $("#menuToggle").addEventListener("click", () =>
    $("#sidebar").classList.toggle("open")
  );

  /* ---------------------------------------------------------
     Animated stat counters on the welcome screen.
     --------------------------------------------------------- */
  function animateCount(el) {
    const target = Number(el.dataset.count);
    const dur = 1400;
    const start = performance.now();
    const fmt = (n) => {
      if (target >= 1e9) return (n / 1e9).toFixed(1) + "B";
      if (target >= 1e6) return "$" + (n / 1e6).toFixed(2) + "M";
      return Math.round(n).toString();
    };
    function tick(now) {
      const p = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = fmt(target * eased);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  const statObserver = new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (en.isIntersecting) { animateCount(en.target); statObserver.unobserve(en.target); }
    });
  });
  $$(".stat__num").forEach((el) => statObserver.observe(el));

  /* ---------------------------------------------------------
     Module 02 — clickable red flags in the sample email.
     --------------------------------------------------------- */
  const flagButtons = $$(".flag");
  const foundFlags = new Set();
  $("#flagTotal").textContent = flagButtons.length;

  const checklist = $("#flagChecklist");
  flagButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.flag;
      const info = EMAIL_FLAGS[key];
      if (!info) return;
      if (!foundFlags.has(key)) {
        foundFlags.add(key);
        btn.classList.add("found");
        const li = document.createElement("li");
        li.innerHTML = `<strong>${info.title}.</strong> ${info.text}`;
        checklist.appendChild(li);
        $("#flagCount").textContent = foundFlags.size;
      }
      // Re-scroll the freshly added item into view for context.
      checklist.lastChild &&
        checklist.lastChild.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
  });

  /* ---------------------------------------------------------
     Module 04 — spot-the-fake domain game.
     --------------------------------------------------------- */
  const game = $("#domainGame");
  if (game && typeof DOMAIN_ROUNDS !== "undefined") {
    DOMAIN_ROUNDS.forEach((round) => {
      const card = document.createElement("div");
      card.className = "domain-card";
      card.innerHTML =
        `<div class="domain-card__q">Is this domain safe to trust?</div>` +
        `<div class="domain-card__url">${round.url}</div>` +
        `<div class="domain-card__btns">
           <button data-pick="safe">Safe ✓</button>
           <button data-pick="phish">Phishing ✗</button>
         </div>` +
        `<div class="domain-card__reveal"></div>`;
      const reveal = $(".domain-card__reveal", card);
      $$(".domain-card__btns button", card).forEach((b) => {
        b.addEventListener("click", () => {
          const pickedSafe = b.dataset.pick === "safe";
          const correct = pickedSafe === round.safe;
          card.classList.add("answered", correct ? "correct" : "wrong");
          const verdict = round.safe
            ? `<b class="safe">Genuine.</b>`
            : `<b class="bad">Phishing.</b>`;
          const you = correct ? "✓ Correct." : "✗ Not quite.";
          reveal.innerHTML = `${you} ${verdict} ${round.note}`;
          tallyGame();
        });
      });
      game.appendChild(card);
    });
  }
  function tallyGame() {
    const total = $$(".domain-card", game).length;
    const done = $$(".domain-card.answered", game).length;
    const right = $$(".domain-card.correct", game).length;
    if (done === total && !$("#domainScore")) {
      const s = document.createElement("div");
      s.id = "domainScore";
      s.className = "flag-tally";
      s.innerHTML = `You spotted <span>${right} of ${total}</span> correctly.`;
      game.after(s);
    }
  }

  /* ---------------------------------------------------------
     Module 05 — expandable social-engineering tactics.
     --------------------------------------------------------- */
  const tacticsWrap = $("#tactics");
  if (tacticsWrap && typeof TACTICS !== "undefined") {
    TACTICS.forEach((t) => {
      const card = document.createElement("div");
      card.className = "tactic";
      card.innerHTML =
        `<span class="tactic__icon">${t.icon}</span>` +
        `<h4>${t.name}</h4>` +
        `<p class="tactic__play">${t.play}</p>` +
        `<div class="tactic__defence"><strong>Defence:</strong> ${t.defence}</div>`;
      card.addEventListener("click", () => card.classList.toggle("open"));
      tacticsWrap.appendChild(card);
    });
  }

  /* ---------------------------------------------------------
     Module 06 — checkable tips list.
     --------------------------------------------------------- */
  const tipsWrap = $("#tipsList");
  if (tipsWrap && typeof TIPS !== "undefined") {
    TIPS.forEach((tip) => {
      const li = document.createElement("li");
      li.innerHTML =
        `<span class="tick">✓</span>` +
        `<span class="tip-text"><strong>${tip.h}</strong><span>${tip.s}</span></span>`;
      li.addEventListener("click", () => li.classList.toggle("checked"));
      tipsWrap.appendChild(li);
    });
  }

  /* ---------------------------------------------------------
     Module 07 — case studies.
     --------------------------------------------------------- */
  const casesWrap = $("#cases");
  if (casesWrap && typeof CASES !== "undefined") {
    CASES.forEach((c) => {
      const el = document.createElement("article");
      el.className = "case";
      el.innerHTML =
        `<div class="case__head">
           <h3>${c.title}</h3>
           <span class="case__year">${c.year}</span>
           <span class="case__loss">${c.loss}</span>
         </div>
         <div class="case__tag">${c.tag}</div>
         <p>${c.body}</p>
         <div class="case__lesson"><strong>Lesson:</strong> ${c.lesson}</div>`;
      casesWrap.appendChild(el);
    });
  }

  /* ---------------------------------------------------------
     Module 08 — the scored quiz.
     --------------------------------------------------------- */
  const quizWrap = $("#quiz");
  const answered = {};
  if (quizWrap && typeof QUIZ !== "undefined") {
    QUIZ.forEach((item, qi) => {
      const card = document.createElement("div");
      card.className = "q-card";
      card.dataset.index = qi;
      const opts = item.options
        .map(
          (opt, oi) =>
            `<div class="q-opt" data-q="${qi}" data-o="${oi}">
               <span class="mark">${String.fromCharCode(65 + oi)}</span>
               <span>${opt}</span>
             </div>`
        )
        .join("");
      card.innerHTML =
        `<div class="q-card__num">Question ${qi + 1} of ${QUIZ.length}</div>` +
        `<div class="q-card__q">${item.q}</div>` +
        `<div class="q-opts">${opts}</div>` +
        `<div class="q-explain"><b>Why:</b> ${item.explain}</div>`;
      quizWrap.appendChild(card);
    });

    // Actions row + score panel.
    const actions = document.createElement("div");
    actions.className = "quiz__actions";
    actions.innerHTML =
      `<button class="btn btn--primary" id="quizSubmit">Submit answers</button>` +
      `<button class="btn btn--ghost" id="quizReset">Reset</button>`;
    quizWrap.appendChild(actions);

    const scorePanel = document.createElement("div");
    scorePanel.className = "quiz__score";
    scorePanel.innerHTML =
      `<div class="quiz__score-num" id="scoreNum"></div>` +
      `<div class="quiz__score-msg" id="scoreMsg"></div>` +
      `<button class="btn btn--ghost" id="scoreRetry">Try again</button>`;
    quizWrap.appendChild(scorePanel);

    // Option selection.
    quizWrap.addEventListener("click", (e) => {
      const opt = e.target.closest(".q-opt");
      if (!opt) return;
      const card = opt.closest(".q-card");
      if (card.classList.contains("locked")) return;
      const qi = Number(opt.dataset.q);
      answered[qi] = Number(opt.dataset.o);
      $$(".q-opt", card).forEach((o) => o.classList.remove("selected"));
      opt.classList.add("selected");
      opt.style.borderColor = "var(--brand)";
      $$(".q-opt", card).forEach((o) => {
        if (o !== opt) o.style.borderColor = "";
      });
    });

    $("#quizSubmit").addEventListener("click", gradeQuiz);
    $("#quizReset").addEventListener("click", resetQuiz);
    $("#scoreRetry").addEventListener("click", resetQuiz);
  }

  function gradeQuiz() {
    if (Object.keys(answered).length < QUIZ.length) {
      const ok = confirm(
        `You've answered ${Object.keys(answered).length} of ${QUIZ.length} questions. ` +
        `Submit anyway?`
      );
      if (!ok) return;
    }
    let score = 0;
    $$(".q-card", quizWrap).forEach((card) => {
      const qi = Number(card.dataset.index);
      const correct = QUIZ[qi].answer;
      card.classList.add("locked");
      $$(".q-opt", card).forEach((o) => {
        o.style.borderColor = "";
        const oi = Number(o.dataset.o);
        if (oi === correct) o.classList.add("correct");
        else if (answered[qi] === oi) o.classList.add("wrong");
      });
      if (answered[qi] === correct) score++;
    });

    const panel = $(".quiz__score");
    const pass = score >= 8;
    panel.classList.add("show", pass ? "pass" : "fail");
    panel.classList.remove(pass ? "fail" : "pass");
    $("#scoreNum").textContent = `${score} / ${QUIZ.length}`;
    $("#scoreMsg").textContent = pass
      ? "Passed. You can spot a phish. Stay just as sharp in your real inbox."
      : "Not quite 8/10. Review the modules above and try again, it's worth getting right.";
    panel.scrollIntoView({ behavior: "smooth", block: "center" });
    if (pass) visited.add("quiz-passed");
  }

  function resetQuiz() {
    for (const k in answered) delete answered[k];
    $$(".q-card", quizWrap).forEach((card) => {
      card.classList.remove("locked");
      $$(".q-opt", card).forEach((o) => {
        o.classList.remove("correct", "wrong", "selected");
        o.style.borderColor = "";
      });
    });
    const panel = $(".quiz__score");
    panel.classList.remove("show", "pass", "fail");
    quizWrap.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ---------------------------------------------------------
     Boot — open the first section (or the URL hash).
     --------------------------------------------------------- */
  const initial = (location.hash || "#welcome").slice(1);
  showSection($("#" + initial) ? initial : "welcome");
})();
