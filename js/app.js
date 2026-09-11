(() => {
  const D = window.DARKRX;
  const I = window.ICONS;
  const main = document.getElementById("main");
  const nav = document.getElementById("nav");
  const menuBtn = document.getElementById("menu-btn");
  const mobile = document.getElementById("mobile-menu");
  const AUTH_KEY = "darkrx-console";

  document.getElementById("bg").innerHTML = `
    <canvas id="matrix-rain" class="matrix-canvas" aria-hidden="true"></canvas>
    <div class="scanlines"></div>
    <div class="glow glow-a"></div>
    <div class="glow glow-b"></div>
    <div class="glow glow-c"></div>
    <div class="orb orb-a"></div>
    <div class="orb orb-b"></div>
    <div class="orb orb-c"></div>
    <div class="orb orb-d"></div>
    <div class="ring ring-1"></div>
    <div class="ring ring-2"></div>
    <div class="ring ring-3"></div>
    <div class="ring ring-bl-1"></div>
    <div class="ring ring-bl-2"></div>
    <span class="dot-pulse dp-1"></span>
    <span class="dot-pulse dp-2"></span>
    <span class="dot-pulse dp-3"></span>
    ${Array.from({ length: 8 }, (_, i) => `<div class="fall" style="left:${12 + i * 12}%;animation-delay:${i * 0.8}s;animation-duration:${4 + i * 0.5}s"></div>`).join("")}
  `;

  (function matrixRain() {
    const canvas = document.getElementById("matrix-rain");
    if (!canvas || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = canvas.getContext("2d");
    const glyphs = "01アイウエオカキクケコDARKRX#";
    let cols = [];
    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const n = Math.floor(canvas.width / 18);
      cols = Array.from({ length: n }, () => Math.random() * canvas.height);
    }
    function draw() {
      ctx.fillStyle = "rgba(0,0,0,0.08)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "rgba(0,255,65,0.35)";
      ctx.font = "14px 'JetBrains Mono', monospace";
      cols.forEach((y, i) => {
        const ch = glyphs[Math.floor(Math.random() * glyphs.length)];
        ctx.fillText(ch, i * 18, y);
        cols[i] = y > canvas.height + Math.random() * 400 ? 0 : y + 14;
      });
      requestAnimationFrame(draw);
    }
    resize();
    window.addEventListener("resize", resize);
    draw();
  })();

  document.querySelectorAll("[data-icon]").forEach((el) => {
    const name = el.getAttribute("data-icon");
    if (I[name]) el.outerHTML = I[name];
  });

  function tick() {
    const t = new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" });
    const a = document.getElementById("clock");
    const b = document.getElementById("clock-m");
    if (a) a.textContent = t;
    if (b) b.textContent = t;
  }
  tick();
  setInterval(tick, 1000);

  window.addEventListener("scroll", () => {
    nav.classList.toggle("scrolled", window.scrollY > 10);
  });

  menuBtn.addEventListener("click", () => {
    const open = mobile.hasAttribute("hidden");
    if (open) mobile.removeAttribute("hidden");
    else mobile.setAttribute("hidden", "");
    menuBtn.setAttribute("aria-expanded", String(open));
    menuBtn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
  });

  mobile.addEventListener("click", (e) => {
    if (e.target.tagName === "A") {
      mobile.setAttribute("hidden", "");
      menuBtn.setAttribute("aria-expanded", "false");
    }
  });

  function path() {
    const h = location.hash.replace(/^#/, "") || "/";
    return h.startsWith("/") ? h : `/${h}`;
  }

  function authed() {
    return sessionStorage.getItem(AUTH_KEY) === "1";
  }

  function setActive() {
    const p = path().split("?")[0];
    document.querySelectorAll(".nav-links a, .mobile-menu a").forEach((a) => {
      const r = a.getAttribute("data-route") || a.getAttribute("href").replace("#", "");
      a.classList.toggle("active", r === p || (r !== "/" && p.startsWith(r)));
    });
  }

  function pageHome() {
    const id = D.identity;
    return `
      <section class="wrap home-hero" aria-labelledby="id-title">
        <p class="kicker">${id.kicker}</p>
        <h1 id="id-title" class="hero-title">${id.name}</h1>
        <div class="roles">${id.roles.map((r) => `<span>${r}</span>`).join("")}</div>
        <div class="manifesto">
          ${id.manifesto.map((l) => `<p>${l}</p>`).join("")}
        </div>
        <div class="cta-row">
          <a class="btn" href="#/projects">View My Work</a>
          <a class="btn ghost" href="#/about">About</a>
          <a class="btn ghost" href="#/console">Private console</a>
        </div>
      </section>`;
  }

  function pageAbout() {
    const a = D.about;
    const statIcon = (name) => I[name] || I.award;
    return `
      <section class="wrap about-page" aria-labelledby="about-title">
        <div class="center about-hero">
          <div class="pill">${I.sparkles} <span>${a.pill}</span></div>
          <h1 id="about-title" class="hero-title">${a.title[0]} <span class="accent">${a.title[1]}</span></h1>
          <p class="lede">${a.subtitle}</p>
        </div>
        <div class="bento">
          <article class="card profile-card glow-hover">
            <div class="lights" aria-hidden="true"><i class="r"></i><i class="y"></i><i class="g"></i></div>
            <div class="profile-row">
              <div class="avatar" aria-hidden="true">${I.shield}</div>
              <div>
                <h2>${a.name}</h2>
                <p class="mono">${a.titleLine}</p>
              </div>
            </div>
            <div class="bio">
              <p>${a.p1}</p>
              <p>${a.p2}</p>
            </div>
            <div class="tags">${a.tags.map((t) => `<span class="tag">${t}</span>`).join("")}</div>
          </article>
          <aside class="card stats-card">
            <h3 class="mono stats-title">${I.target} Quick Stats</h3>
            <div class="stats">
              ${a.stats
                .map(
                  (s) => `<div class="stat">
                    <span class="stat-icon" aria-hidden="true">${statIcon(s.icon)}</span>
                    <strong>${s.value}</strong>
                    <span>${s.label}</span>
                  </div>`
                )
                .join("")}
            </div>
          </aside>
        </div>
        <div class="grid-2 about-split">
          <article class="card">
            <div class="section-head">
              <div class="icon-box" aria-hidden="true">${I.cap}</div>
              <div>
                <h3>Education</h3>
                <p class="mono">Academic Journey</p>
              </div>
            </div>
            <ol class="timeline">
              ${D.education
                .map(
                  (e) => `<li>
                    <h4>${e.degree} <span class="period">${e.period}</span></h4>
                    <p class="mono">${e.institution}</p>
                    <p class="muted">${e.score}</p>
                  </li>`
                )
                .join("")}
            </ol>
          </article>
          <article class="card yellow">
            <div class="section-head">
              <div class="icon-box yellow" aria-hidden="true">${I.award}</div>
              <div>
                <h3>Certifications</h3>
                <p class="mono yellow-text">Professional Credentials</p>
              </div>
            </div>
            <div class="certs">
              ${D.certs
                .map(
                  (c) => `<div class="cert">
                    <span class="cert-mark" aria-hidden="true">${I.award}</span>
                    <div>
                      <h4>${c.name}</h4>
                      <p class="muted"><span class="dot"></span>${c.issuer}</p>
                    </div>
                  </div>`
                )
                .join("")}
            </div>
            <div class="pursuing">
              <h4>${I.bolt} Currently Pursuing</h4>
              <div class="tags">
                ${D.pursuing.map((p) => `<span class="tag gold">${p}</span>`).join("")}
              </div>
            </div>
          </article>
        </div>
        <article class="card cyan">
          <div class="section-head">
            <div class="icon-box cyan" aria-hidden="true">${I.briefcase}</div>
            <div>
              <h3>Professional Experience</h3>
              <p class="mono cyan-text">Career Journey</p>
            </div>
          </div>
          <div class="exp-grid">
            ${D.experience
              .map(
                (e) => `<article class="tile">
                  <h4>${e.role}</h4>
                  <p class="mono cyan-text">${e.org}</p>
                  <span class="chip">${I.calendar}${e.period}</span>
                  <span class="chip blue">${I.pin}${e.location}</span>
                  <p class="muted">${e.description}</p>
                </article>`
              )
              .join("")}
          </div>
        </article>
        <article class="card purple">
          <div class="section-head">
            <div class="icon-box purple" aria-hidden="true">${I.users}</div>
            <div>
              <h3>Positions &amp; Leadership</h3>
              <p class="mono purple-text">Community &amp; Organizations</p>
            </div>
          </div>
          <div class="lead-grid">
            ${D.leadership
              .map(
                (l) => `<article class="tile purple">
                  <h4>${l.org}</h4>
                  ${l.roles.map((r) => `<div class="role-row"><span>${r.title}</span><span>${r.period}</span></div>`).join("")}
                </article>`
              )
              .join("")}
          </div>
        </article>
        <p class="about-foot">Supporting evidence only. Cyber work lives in <a href="#/projects">Projects</a>. Operator detail stays in <a href="#/console">Admin</a>.</p>
      </section>`;
  }

  function pageProjects() {
    return `
      <section class="wrap" aria-labelledby="p-title">
        <div class="center">
          <div class="pill">Public portfolio</div>
          <h1 id="p-title" class="hero-title">Cyber work <span class="accent">first</span></h1>
          <p class="lede">Sanitized research and validation loops. Operator detail lives behind Admin.</p>
        </div>
        <div class="proj-grid">
          ${D.projects
            .map(
              (p) => `<article class="card">
                <h3>${p.title}</h3>
                <p class="muted">${p.blurb}</p>
                <div class="tags">${p.tags.map((t) => `<span class="tag">${t}</span>`).join("")}</div>
              </article>`
            )
            .join("")}
        </div>
      </section>`;
  }

  function pageSkills() {
    return `
      <section class="wrap" aria-labelledby="s-title">
        <div class="center">
          <div class="pill">Capabilities</div>
          <h1 id="s-title" class="hero-title">Stack <span class="accent">under fire</span></h1>
        </div>
        <div class="grid-3">
          ${D.skills
            .map(
              (g) => `<article class="card skill-group">
                <h3>${g.name}</h3>
                <div class="bars">
                  ${g.items
                    .map(
                      (i) => `<div>
                        <label><span>${i.n}</span><span>${i.p}%</span></label>
                        <div class="track" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${i.p}" aria-label="${i.n}"><span style="width:${i.p}%"></span></div>
                      </div>`
                    )
                    .join("")}
                </div>
              </article>`
            )
            .join("")}
        </div>
      </section>`;
  }

  function pageCerts() {
    return `
      <section class="wrap" aria-labelledby="c-title">
        <div class="center">
          <div class="pill">Credentials</div>
          <h1 id="c-title" class="hero-title">Lab <span class="accent">proof</span></h1>
          <p class="lede">Self-directed work until vendor paper exists. The private vault holds the retest records.</p>
        </div>
        <div class="certs" style="grid-template-columns:repeat(auto-fit,minmax(240px,1fr))">
          ${D.certs.map((c) => `<article class="cert card yellow"><h3>${c.name}</h3><p class="muted"><span class="dot"></span>${c.issuer}</p></article>`).join("")}
        </div>
      </section>`;
  }

  function pageBlog() {
    return `
      <section class="wrap" aria-labelledby="b-title">
        <div class="center">
          <div class="pill">Public notes</div>
          <h1 id="b-title" class="hero-title">Research <span class="accent">without payloads</span></h1>
        </div>
        <div class="blog-list">
          ${D.posts
            .map(
              (p) => `<article class="card article">
                <time datetime="${p.date}">${p.date}</time>
                <h3>${p.title}</h3>
                <p class="muted">${p.excerpt}</p>
              </article>`
            )
            .join("")}
        </div>
      </section>`;
  }

  function pageContact() {
    return `
      <section class="wrap" aria-labelledby="ct-title">
        <div class="center">
          <div class="pill">Signal</div>
          <h1 id="ct-title" class="hero-title">Contact <span class="accent">DarkRX</span></h1>
          <p class="lede">${D.contact.note}</p>
        </div>
        <form class="form card" id="contact-form" novalidate>
          <label class="field">Name
            <input name="name" autocomplete="name" required />
          </label>
          <label class="field">Email
            <input name="email" type="email" autocomplete="email" required />
          </label>
          <label class="field">Message
            <textarea name="message" required></textarea>
          </label>
          <p class="form-status" id="form-status" role="status"></p>
          <button class="btn" type="submit">Send</button>
          <p class="note">Opens a local draft to ${D.contact.email}. No server in this build.</p>
        </form>
      </section>`;
  }

  function pageLogin() {
    return `
      <section class="wrap">
        <article class="card login-box">
          <div class="lights" aria-hidden="true"><i class="r"></i><i class="y"></i><i class="g"></i></div>
          <h1>Preview Access Required</h1>
          <p class="muted">Private console. Enter operator key.</p>
          <form id="login-form" class="form" style="margin-top:1rem">
            <label class="field">Secret key
              <input id="pass" name="pass" type="password" autocomplete="current-password" required />
            </label>
            <p class="err" id="login-err" role="alert"></p>
            <button class="btn" type="submit">Verify Access</button>
            <p class="note">Demo key is documented in README. Change it before any real hosting.</p>
          </form>
        </article>
      </section>`;
  }

  function pageConsole() {
    const c = D.console;
    return `
      <section class="wrap console-page" aria-labelledby="con-title">
        <p class="kicker">DARKRX // PRIVATE</p>
        <h1 id="con-title" class="hero-title">DARKRX // <span class="accent">PRIVATE CONSOLE</span></h1>
        <article class="card profile-card glow-hover console-panel">
          <div class="lights" aria-hidden="true"><i class="r"></i><i class="y"></i><i class="g"></i></div>
          <table class="console-table">
            <caption class="sr-only">Vault counts</caption>
            <tbody>
              ${c.counts.map(([k, v]) => `<tr><th scope="row">${k}</th><td>${v}</td></tr>`).join("")}
            </tbody>
          </table>
        </article>
        <div class="lists">
          <article class="card">
            <h2 class="mono">LATEST RESEARCH</h2>
            <ul>${c.research.map((r) => `<li>${r}</li>`).join("")}</ul>
          </article>
          <article class="card cyan">
            <h2 class="mono cyan-text">LATEST OPERATIONS</h2>
            <ul>${c.ops.map((r) => `<li>${r}</li>`).join("")}</ul>
          </article>
        </div>
        <p class="cta-row">
          <a class="btn" href="#/console/cs-031">Open case CS-031</a>
          <button class="btn ghost" type="button" id="logout">Lock vault</button>
        </p>
      </section>`;
  }

  function pageCase() {
    const cs = D.caseStudy;
    return `
      <section class="wrap case" aria-labelledby="cs-title">
        <p class="kicker">PRIVATE CASE STUDY</p>
        <h1 id="cs-title" class="hero-title">${cs.id}</h1>
        <p class="lede">${cs.title}</p>
        <article class="card">
          <dl class="kv">
            ${cs.rows
              .map(([k, v]) => {
                const badge =
                  k === "RESULT"
                    ? `<span class="badge">${v}</span>`
                    : k === "RETEST"
                      ? `<span class="badge pass">${v}</span>`
                      : v;
                return `<dt>${k}</dt><dd>${badge}</dd>`;
              })
              .join("")}
          </dl>
        </article>
        <p class="cta-row"><a class="btn ghost" href="#/console">Back to console</a></p>
      </section>`;
  }

  function notFound() {
    return `<section class="wrap center"><h1>404</h1><p class="muted">Unknown path.</p><a class="btn" href="#/">Home</a></section>`;
  }

  function bindPage() {
    const form = document.getElementById("contact-form");
    if (form) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const fd = new FormData(form);
        const name = String(fd.get("name") || "").trim();
        const email = String(fd.get("email") || "").trim();
        const message = String(fd.get("message") || "").trim();
        const status = document.getElementById("form-status");
        if (!name || !email || !message) {
          status.textContent = "Fill every field.";
          status.className = "form-status err";
          return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          status.textContent = "Use a valid email.";
          status.className = "form-status err";
          return;
        }
        const body = encodeURIComponent(`From: ${name} <${email}>\n\n${message}`);
        window.location.href = `mailto:${D.contact.email}?subject=${encodeURIComponent("DarkRX contact")}&body=${body}`;
        status.textContent = "Draft opened.";
        status.className = "form-status";
        status.style.color = "var(--matrix)";
      });
    }

    const login = document.getElementById("login-form");
    if (login) {
      login.addEventListener("submit", (e) => {
        e.preventDefault();
        const val = document.getElementById("pass").value;
        const err = document.getElementById("login-err");
        if (val === D.passphrase) {
          sessionStorage.setItem(AUTH_KEY, "1");
          location.hash = "#/console";
          render();
        } else {
          err.textContent = "Access denied.";
        }
      });
    }

    const logout = document.getElementById("logout");
    if (logout) {
      logout.addEventListener("click", () => {
        sessionStorage.removeItem(AUTH_KEY);
        location.hash = "#/console";
        render();
      });
    }
  }

  function render() {
    const p = path();
    let html;
    if (p === "/" || p === "") html = pageHome();
    else if (p === "/about") html = pageAbout();
    else if (p === "/projects") html = pageProjects();
    else if (p === "/skills") html = pageSkills();
    else if (p === "/certs") html = pageCerts();
    else if (p === "/blog") html = pageBlog();
    else if (p === "/contact") html = pageContact();
    else if (p === "/console/cs-031") html = authed() ? pageCase() : pageLogin();
    else if (p === "/console" || p === "/admin") html = authed() ? pageConsole() : pageLogin();
    else html = notFound();
    main.innerHTML = html;
    main.focus({ preventScroll: true });
    window.scrollTo(0, 0);
    setActive();
    bindPage();
    document.title =
      p === "/about"
        ? "DARKRX // About"
        : p.startsWith("/console")
          ? "DARKRX // Private"
          : "DARKRX // Cyber Research Lab";
  }

  window.addEventListener("hashchange", render);
  render();
})();
