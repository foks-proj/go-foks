(function () {
  /**
   *
   * show table boundary between "mine" and "theirs" but only
   * if there are "their"s elements at play
   *
   */
  function showTableBoundary() {
    const needed =
      document.querySelectorAll("div#teams-table .theirs").length > 0;
    const el = document.getElementById("teams-table-sep");
    el.style.display = needed ? "block" : "none";
  }

  function toggleMoreTeams() {
    const max = parseInt(document.getElementById("max-teams").innerHTML);
    const have = document.querySelectorAll(
      "div#teams-table button.unclaim-button"
    ).length;
    const disabled = have >= max;
    const buttons = document.querySelectorAll(
      "div#teams-table button.claim-button"
    );
    buttons.forEach(function (butt) {
      butt.disabled = disabled;
    });
  }

  function teamTableUpdateHooks() {
    showTableBoundary();
    toggleMoreTeams();
  }

  function dismissToast(button) {
    const parent = button.currentTarget.closest("div.toast");
    if (parent) {
      parent.style.display = "none";
    }
  }

  function validateDomainPart(s) {
    const goodRe = /^[a-z0-9A-Z-]+$/;
    const badRe = /^-|-$|--/;
    if (s.length > 48) {
      msg = "too long";
    } else if (s.match(badRe) || !s.match(goodRe)) {
      msg = "invalid";
    } else {
      return null;
    }
    return new Error(msg);
  }

  function setHostnameValidator() {
    const cannedName = document.getElementById("canned-name");
    if (!cannedName) {
      return;
    }
    const goodRe = /^[a-z0-9A-Z-]+$/;
    const badRe = /^-|-$|--/;

    function validateHostname() {
      const cn = cannedName.value;
      cannedName.value = cn.toLowerCase();
      let msg = "";
      if (cn.length == 0) {
        // empty is fine
      } else if (cn.length < 3) {
        msg = "hostname too short";
      } else {
        const err = validateDomainPart(cn);
        if (err) {
          msg = "hostname  " + err.message;
        }
      }
      cannedName.setCustomValidity(msg);
    }

    if (!attachDespam(cannedName)) {
      return;
    }
    cannedName.addEventListener("input", function () {
      validateHostname();
      toggleVHostSubmit();
    });
  }

  function toggleVHostSubmit() {
    const byodName = document.getElementById("full-vanity-hostname");
    const cannedName = document.getElementById("canned-name");
    const submit = document.getElementById("vhost-submit");
    const toggle = document.getElementById("toggle-byod");
    if (!byodName || !toggle || !submit || !cannedName) {
      return;
    }
    if (
      (byodName.value.length > 0 && toggle.checked) ||
      (cannedName.value.length > 0 && !toggle.checked)
    ) {
      submit.disabled = false;
    } else {
      submit.disabled = true;
    }
  }

  function attachDespam(el) {
    const klass = "js-attached";
    if (el.classList.contains(klass)) {
      return false;
    }
    el.classList.add(klass);
    return true;
  }

  function setBYODValidator() {
    const byodName = document.getElementById("full-vanity-hostname");
    if (!byodName) {
      return;
    }

    function validateBYOD() {
      const val = byodName.value;
      byodName.value = val.toLowerCase();
      const parts = val.split(".");
      let msg = "";
      if (parts.length < 2) {
        msg = "No TLD found";
      } else if (parts.length < 3) {
        msg =
          "Hostname cannot be an apex domain; " +
          "valid examples include 'sub.acme.com' and 'foks.us.myco.com'";
      } else if (parts.length > 6) {
        msg = "too many domain parts";
      } else {
        const domain = parts.pop();
        const tldRe = /^[a-z]{2,10}$/;
        if (!domain.match(tldRe)) {
          msg = "invalid TLD";
        } else {
          parts.forEach(function (part) {
            const err = validateDomainPart(part);
            if (err) {
              msg = "domain part '" + part + "': " + err.message;
            }
          });
        }
      }
      byodName.setCustomValidity(msg);
    }
    if (!attachDespam(byodName)) {
      return;
    }
    byodName.addEventListener("input", function () {
      validateBYOD();
      toggleVHostSubmit();
    });
  }

  function setBYODomainToggle() {
    const el = document.getElementById("toggle-byod");
    if (!el) {
      return;
    }
    const nm = document.getElementById("canned-input");
    const dm = document.getElementById("byod-input");

    function clear(el) {
      el.querySelectorAll("input").forEach(function (inp) {
        if (!inp.validity.valid) {
          inp.value = "";
          inp.setCustomValidity("");
        }
      });
    }

    function showCanned() {
      nm.classList.remove("hidden");
      dm.classList.add("hidden");
      clear(dm);
    }

    function showBYOD() {
      nm.classList.add("hidden");
      dm.classList.remove("hidden");
      clear(nm);
    }

    if (el.hasAttribute("checked") || el.checked) {
      showBYOD();
    } else {
      showCanned();
    }

    if (!attachDespam(el)) {
      return;
    }
    el.addEventListener("input", function () {
      toggleVHostSubmit();
      if (this.checked) {
        showBYOD();
      } else {
        showCanned();
      }
    });
  }

  function setDisplayWidgets() {
    setGenericCollapseToggles();
    setSSOCollapseToggle();
  }

  function setSSOCollapseToggle() {
    const widget = document.querySelector("div#sso");
    if (!widget) {
      return;
    }
    const checkbox = widget.querySelector("input#toggle-sso");
    const target = widget.querySelector("div.collapse-target");
    if (!checkbox || !target) {
      return;
    }
    if (checkbox.checked) {
      target.classList.add("open");
    }
    if (!attachDespam(checkbox)) {
      return;
    }
    checkbox.addEventListener("change", (event) => {
      if (event.target.checked) {
        target.classList.add("open");
      } else {
        target.classList.remove("open");
      }
    })

  }

  function setGenericCollapseToggles() {
    const widgets = document.querySelectorAll("div.collapsible");
    widgets.forEach(function (widget) {
      const button = widget.querySelector("button.collapse-toggle");
      const span = widget.querySelector("span.collapse-toggle-img");
      const target = widget.querySelector("div.collapse-target");
      if (!button || !span || !target) {
        return;
      }
      if (!attachDespam(button)) {
        return;
      }
      button.addEventListener("click", function () {
        if (target.classList.contains("open")) {
          span.innerHTML = "▷";
          target.classList.remove("open");
        } else {
          span.innerHTML = "▽";
          target.classList.add("open");
        }
      });
    });
  }

  function setToggleViewershipSubmit() {
    const form = document.querySelector("form#user-viewership");
    if (!form) {
      return;
    }
    const sel = form.querySelector("select#mode");
    const but = form.querySelector("button#submit");
    const val = form.querySelector("input#current-val");
    if (!sel || !but || !val) {
      return;
    }
    function setBut() {
      but.disabled = sel.value === val.value;
    }
    setBut();
    if (!attachDespam(sel)) {
      return;
    }
    sel.addEventListener("change", function () {
      setBut();
    });
  }

  function setThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    if (!themeToggle) {
      return;
    }
    if (!attachDespam(themeToggle)) {
      return;
    }
    themeToggle.addEventListener('click', function() {
      toggleTheme();
    });
  }

  function setFormMachinery() {
    setHostnameValidator();
    setBYODValidator();
    setBYODomainToggle();
    setToggleViewershipSubmit();
    toggleVHostSubmit();
  }

  function updateDOM(evt) {
    const targ = evt.target;
    if (targ.classList.contains("usage-row") && targ.tagName === "FORM") {
      teamTableUpdateHooks();
    } else if (targ.classList.contains("toast") && targ.tagName === "DIV") {
      const butts = targ.querySelectorAll("button.dismiss-toast");
      butts.forEach(function (butt) {
        butt.onclick = dismissToast;
      });
    }
    setFormMachinery();
    setDisplayWidgets();
    setThemeToggle();
  }

  function beforeSwap(evt) {
    // Error = 422 returned from the server means we should show some sort
    // of toast with an error message. Same goes for error 401 unauthorized.
    if (evt.detail.xhr.status === 422 || evt.detail.xhr.status === 401) {
      evt.detail.shouldSwap = true;
      evt.detail.isError = false;
    }
  }

  function configRequest(evt) {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) {
      const val = meta.getAttribute("content");
      if (val) {
        evt.detail.headers["X-CSRF-Token"] = val;
      }
    }
  }

  // Dark mode functionality
  function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }

  function toggleTheme() {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
  }

  // Initialize theme on page load
  initTheme();

  htmx.on("htmx:load", updateDOM);
  htmx.on("htmx:beforeSwap", beforeSwap);
  htmx.on("htmx:configRequest", configRequest);
})();
