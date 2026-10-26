// Platypus front-end behaviour. Plain JavaScript, no inline scripts, no eval:
// everything here works under the strict Content-Security-Policy.
"use strict";

(function () {
  const csrfToken = () => document.querySelector('meta[name="csrf-token"]')?.content ?? "";

  // ---------------------------------------------------------------------
  // Confirmation dialog: the server swaps a summary into #dialog-content.
  // ---------------------------------------------------------------------
  const dialog = () => document.getElementById("dialog");

  function closeDialog() {
    const d = dialog();
    if (!d) return;
    d.close();
    document.getElementById("dialog-content").replaceChildren();
  }

  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.detail.target.id === "dialog-content" && event.detail.target.childElementCount > 0) {
      dialog().showModal();
    }
    hideRevealedValuesLater(event.detail.target);
    // A swapped fragment arrives as server-rendered UTC text. Localise it
    // before it settles, so a search never shows UTC.
    localizeTimes(event.detail.target);
  });

  document.addEventListener("htmx:afterSettle", () => localizeTimes());
  // Restored tabs and back/forward cache hits get no DOMContentLoaded.
  window.addEventListener("pageshow", () => {
    announceZone();
    localizeTimes();
  });
  // Last line of defence: any <time> that lands in the document, whatever
  // inserted it, is converted.
  let localizeSoon = 0;
  new MutationObserver(() => {
    clearTimeout(localizeSoon);
    localizeSoon = setTimeout(() => localizeTimes(), 40);
  }).observe(document.body, { childList: true, subtree: true });

  // "Load current value" swaps in a new, filled editor: wire it up.
  document.addEventListener("htmx:load", (event) => {
    const root = event.detail.elt;
    const editors = root.matches?.("[data-value-editor]") ? [root] : root.querySelectorAll?.("[data-value-editor]") ?? [];
    editors.forEach((editor) => {
      if (!editor.dataset.ready) initValueEditor(editor);
    });
  });

  document.addEventListener("click", (event) => {
    if (event.target.closest("[data-dismiss]")) {
      event.preventDefault();
      closeDialog();
      return;
    }
    // A list row's details open in place; the control stays outside any
    // <summary>, so the row survives keyboard and screen-reader use.
    const toggle = event.target.closest("[data-row-toggle]");
    if (!toggle) return;
    const detail = document.getElementById(toggle.getAttribute("aria-controls"));
    if (!detail) return;
    const show = detail.hasAttribute("hidden");
    detail.toggleAttribute("hidden", !show);
    toggle.setAttribute("aria-expanded", String(show));
  });

  // Errors from the "Continue" step are shown in the dialog's message area.
  document.addEventListener("htmx:beforeSwap", (event) => {
    if (event.detail.xhr.status >= 400 && event.detail.requestConfig.elt.closest("dialog")) {
      event.detail.shouldSwap = true;
      event.detail.target = document.getElementById("dialog-messages") ?? event.detail.target;
    }
  });

  // ---------------------------------------------------------------------
  // Revealed values hide themselves again after a while. The value returns
  // to its placeholder look and a quiet toast says what happened.
  // ---------------------------------------------------------------------
  function toast(text) {
    document.querySelectorAll("[data-toast]").forEach((el) => el.remove());
    const element = document.createElement("div");
    element.className = "toast";
    element.dataset.toast = "";
    element.setAttribute("role", "status");
    element.textContent = text;
    document.body.append(element);
    setTimeout(() => {
      element.classList.add("toast-out");
      setTimeout(() => element.remove(), 500);
    }, 3500);
  }

  function hideValue(box) {
    const restore = box.querySelector("template[data-reveal-restore]");
    const placeholder = document.createElement("span");
    placeholder.className = "value-hidden";
    placeholder.textContent = "••••••••";
    if (restore) {
      // Keep the template (it renders as nothing) so later cycles work too.
      box.replaceChildren(placeholder, restore, restore.content.cloneNode(true));
      // htmx binds content it swaps itself; content inserted by this script
      // needs an explicit nudge.
      window.htmx?.process(box);
    } else {
      box.replaceChildren(placeholder);
    }
    toast("Value hidden again");
  }

  function hideRevealedValuesLater(root) {
    root.querySelectorAll?.("[data-hide-after]").forEach((box) => {
      const seconds = Number(box.dataset.hideAfter);
      if (seconds > 0) setTimeout(() => hideValue(box), seconds * 1000);
    });
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-hide]");
    if (button) hideValue(button.closest("[data-hide-after]"));
  });

  // ---------------------------------------------------------------------
  // Value editor: plain text, JSON text, or JSON as key/value fields.
  // The textarea always holds the value that is submitted.
  // ---------------------------------------------------------------------
  function initValueEditor(editor) {
    editor.dataset.ready = "true";
    const textarea = editor.querySelector("textarea[name=value]");
    const rows = editor.querySelector(".field-rows");
    const message = editor.querySelector(".editor-message");
    const addButton = editor.querySelector("[data-add-field]");
    let current = editor.querySelector("input[name=format]:checked")?.value ?? "text";

    const say = (text) => { message.textContent = text; message.hidden = !text; };

    function addRow(key = "", value = "") {
      const row = document.createElement("div");
      row.className = "field-row";
      const keyInput = Object.assign(document.createElement("input"), { type: "text", value: key, placeholder: "key" });
      const valueInput = Object.assign(document.createElement("input"), { type: "text", value: value, placeholder: "value" });
      const remove = Object.assign(document.createElement("button"), { type: "button", textContent: "Remove" });
      remove.addEventListener("click", () => { row.remove(); syncFromFields(); });
      keyInput.addEventListener("input", syncFromFields);
      valueInput.addEventListener("input", syncFromFields);
      row.append(keyInput, valueInput, remove);
      rows.append(row);
    }

    function syncFromFields() {
      const entries = new Map();
      for (const row of rows.querySelectorAll(".field-row")) {
        const [key, value] = row.querySelectorAll("input");
        if (key.value === "") continue;
        if (entries.has(key.value)) {
          say(`The key ${JSON.stringify(key.value)} appears more than once.`);
          return;
        }
        entries.set(key.value, value.value);
      }
      if (entries.size === 0 && rows.querySelectorAll(".field-row").length > 0) {
        // Every field removed: that means an empty object, not "keep the old".
        textarea.value = "{}";
        say("");
        return;
      }
      textarea.value = entries.size ? JSON.stringify(Object.fromEntries(entries), null, 2) : "";
      say("");
    }

    function showFields(show) {
      rows.hidden = !show;
      addButton.hidden = !show;
      textarea.hidden = show;
    }

    editor.querySelectorAll("input[name=format]").forEach((radio) => {
      radio.addEventListener("change", () => {
        const next = radio.value;
        say("");
        if (next === "fields") {
          let object = {};
          if (textarea.value.trim() !== "") {
            try {
              object = JSON.parse(textarea.value);
            } catch {
              say("The value is not valid JSON, so it can't be shown as fields. Fix it in JSON mode first.");
              editor.querySelector(`input[name="format"][value="${current}"]`).checked = true;
              return;
            }
          }
          const flat = object && typeof object === "object" && !Array.isArray(object) &&
            Object.values(object).every((v) => typeof v === "string");
          if (!flat) {
            say("The field editor only supports a flat JSON object with text values. Use JSON mode for this value.");
            editor.querySelector(`input[name="format"][value="${current}"]`).checked = true;
            return;
          }
          rows.replaceChildren();
          Object.entries(object).forEach(([k, v]) => addRow(k, v));
          if (rows.childElementCount === 0) addRow();
          showFields(true);
        } else {
          if (current === "fields") syncFromFields();
          if (next === "json" && textarea.value.trim() !== "") {
            try {
              textarea.value = JSON.stringify(JSON.parse(textarea.value), null, 2);
            } catch {
              say("The current value is not valid JSON yet; it will be checked when you save.");
            }
          }
          showFields(false);
        }
        current = next;
      });
    });

    addButton?.addEventListener("click", () => addRow());
  }

  // ---------------------------------------------------------------------
  // Policy editor: add and remove rule rows.
  // ---------------------------------------------------------------------
  function initRuleEditor(editor) {
    const template = editor.querySelector("template");
    const list = editor.querySelector(".rules");
    const addButton = editor.querySelector("[data-add-rule]");
    if (template && list && addButton) {
      addButton.addEventListener("click", () => {
        const row = template.content.firstElementChild.cloneNode(true);
        const id = "new-" + Math.random().toString(36).slice(2);
        row.querySelector("input[name=rule_id]").value = id;
        row.querySelectorAll("input[type=checkbox]").forEach((box) => {
          box.value = id + ":" + box.dataset.permission;
          // A new rule starts with list; the rest are explicit choices.
          box.checked = box.dataset.permission === "list";
        });
        list.append(row);
        row.querySelector("select").focus();
      });
    }
    editor.addEventListener("click", (event) => {
      const button = event.target.closest("[data-remove-rule]");
      if (button) {
        button.closest(".rule-row")?.remove();
        // The summary must follow structural changes as well as edits.
        const form = button.closest("form");
        form?.querySelector(".rules")?.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }

  // ---------------------------------------------------------------------
  // Passkeys (WebAuthn). The server sends options with base64url-encoded
  // binary fields; the browser API wants ArrayBuffers.
  // ---------------------------------------------------------------------
  const fromBase64url = (text) => {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
  };
  const toBase64url = (buffer) =>
    btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  async function postJSON(url, body) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
      body: body === undefined ? "{}" : JSON.stringify(body),
      credentials: "same-origin",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Something went wrong.");
    return data;
  }

  function credentialToJSON(credential) {
    const response = credential.response;
    const json = {
      id: credential.id,
      rawId: toBase64url(credential.rawId),
      type: credential.type,
      response: { clientDataJSON: toBase64url(response.clientDataJSON) },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    };
    if (response.attestationObject) {
      json.response.attestationObject = toBase64url(response.attestationObject);
      json.response.transports = response.getTransports?.() ?? [];
    } else {
      json.response.authenticatorData = toBase64url(response.authenticatorData);
      json.response.signature = toBase64url(response.signature);
      json.response.userHandle = response.userHandle ? toBase64url(response.userHandle) : undefined;
    }
    return json;
  }

  async function registerPasskey(button) {
    const options = (await postJSON(button.dataset.begin)).publicKey;
    options.challenge = fromBase64url(options.challenge);
    options.user.id = fromBase64url(options.user.id);
    (options.excludeCredentials ?? []).forEach((c) => { c.id = fromBase64url(c.id); });
    const credential = await navigator.credentials.create({ publicKey: options });
    const name = document.getElementById("passkey-name")?.value ?? "";
    return postJSON(button.dataset.finish, { name: name, credential: credentialToJSON(credential) });
  }

  async function loginWithPasskey(button) {
    const options = (await postJSON(button.dataset.begin)).publicKey;
    options.challenge = fromBase64url(options.challenge);
    (options.allowCredentials ?? []).forEach((c) => { c.id = fromBase64url(c.id); });
    const credential = await navigator.credentials.get({ publicKey: options });
    return postJSON(button.dataset.finish, { credential: credentialToJSON(credential) });
  }

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-passkey]");
    if (!button) return;
    event.preventDefault();
    const message = document.getElementById(button.dataset.messages);
    button.disabled = true;
    try {
      const result = button.dataset.passkey === "register" ? await registerPasskey(button) : await loginWithPasskey(button);
      window.location.assign(result.redirect || window.location.href);
    } catch (error) {
      if (message) {
        message.hidden = false;
        message.textContent = error.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out." : error.message;
      }
    } finally {
      button.disabled = false;
    }
  });

  // ---------------------------------------------------------------------
  // Colour theme: auto (follow the system), light or dark. theme.js applies
  // the choice early; this switch changes it.
  // ---------------------------------------------------------------------
  const themes = ["auto", "light", "dark"];

  function currentTheme() {
    return document.documentElement.dataset.theme ?? "auto";
  }

  function showTheme() {
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      const theme = currentTheme();
      button.textContent = { auto: "◐ Auto", light: "☀ Light", dark: "☾ Dark" }[theme];
      button.title = "Colour theme: " + theme + " (click to change)";
    });
  }

  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-theme-toggle]")) return;
    const next = themes[(themes.indexOf(currentTheme()) + 1) % themes.length];
    if (next === "auto") {
      delete document.documentElement.dataset.theme;
      localStorage.removeItem("platypus-theme");
    } else {
      document.documentElement.dataset.theme = next;
      localStorage.setItem("platypus-theme", next);
    }
    showTheme();
  });

  // ---------------------------------------------------------------------
  // Local times: when the user prefers their own zone, every <time> element
  // (and every freshly swapped fragment) is shown in local time.
  // ---------------------------------------------------------------------
  // 24-hour, browser-local text built from plain date parts: no Intl, no
  // locale surprises, identical in every browser.
  function localText(instant) {
    const pad = (n) => String(n).padStart(2, "0");
    return `${instant.getFullYear()}-${pad(instant.getMonth() + 1)}-${pad(instant.getDate())} ` +
      `${pad(instant.getHours())}:${pad(instant.getMinutes())}`;
  }

  function localizeTimes(root = document) {
    if (document.body?.dataset.timezone !== "local") return;
    root.querySelectorAll?.("time[datetime][data-utc]").forEach((element) => {
      const instant = new Date(element.getAttribute("datetime"));
      if (Number.isNaN(instant.getTime())) return;
      element.textContent = localText(instant);
    });
  }

  // The server renders times in the zone named by this cookie, so a search
  // never swaps in UTC text that JavaScript has to correct afterwards.
  // It holds a zone name only — no identity, no secret.
  function announceZone() {
    const prefersLocal = document.body?.dataset.timezone === "local";
    let zone = "";
    if (prefersLocal) {
      try {
        zone = Intl.DateTimeFormat().resolvedOptions().timeZone ?? "";
      } catch {
        zone = "";
      }
      if (!zone) {
        const offset = -new Date().getTimezoneOffset();
        const sign = offset < 0 ? "-" : "+";
        const abs = Math.abs(offset);
        zone = `${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
      }
    }
    const name = "platypus_tz";
    const cookie = document.cookie.split("; ").find((entry) => entry.startsWith(name + "="));
    const current = cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : "";
    if (zone === current) return;
    if (!zone) {
      if (cookie) document.cookie = `${name}=; Max-Age=0; Path=/; SameSite=Lax`;
      return;
    }
    document.cookie = `${name}=${encodeURIComponent(zone)}; Path=/; SameSite=Lax; Max-Age=31536000` +
      (location.protocol === "https:" ? "; Secure" : "");
  }

  document.addEventListener("DOMContentLoaded", () => {
    showTheme();
    announceZone();
    localizeTimes();
    document.querySelectorAll("[data-value-editor]:not([data-ready])").forEach(initValueEditor);
    document.querySelectorAll("[data-rule-editor]").forEach(initRuleEditor);
    hideRevealedValuesLater(document);
    dismissToasts();
    initToggles(document);
    initDirtyForms(document);
  });

  // ---------------------------------------------------------------------
  // Forms that are only saved when something changed: Save stays disabled
  // until the first edit, and leaving the page with unsaved changes asks
  // first. Saving through the confirmation dialog is an intent to leave.
  // ---------------------------------------------------------------------
  function initDirtyForms(root) {
    root.querySelectorAll("form[data-dirty-form]").forEach((form) => {
      const save = form.querySelector("[data-save-policy]");
      const hint = form.querySelector("[data-save-hint]");
      const mark = () => {
        if (form.dataset.dirty === "true") return;
        form.dataset.dirty = "true";
        if (save) save.disabled = false;
        if (hint) hint.hidden = true;
      };
      form.addEventListener("input", mark);
      form.addEventListener("change", mark);
      // Enter in a field asks for confirmation, like the Save button.
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        form.querySelector("[data-save-policy]")?.click();
      });
      window.addEventListener("beforeunload", (event) => {
        if (form.dataset.dirty !== "true") return;
        event.preventDefault();
        event.returnValue = "";
      });
    });
    document.body.addEventListener("htmx:beforeRequest", (event) => {
      const form = document.querySelector("form[data-dirty-form]");
      if (form && event.detail.elt.closest("#dialog-content")) form.dataset.dirty = "false";
    });
  }

  // ---------------------------------------------------------------------
  // Fields that only show when their checkbox is ticked (the
  // identity-provider group link). Hiding a field also empties it, so a
  // leftover value can never link a team by accident.
  // ---------------------------------------------------------------------
  function initToggles(root) {
    root.querySelectorAll("[data-toggles]").forEach((box) => {
      const field = document.querySelector(box.dataset.toggles);
      if (!field) return;
      const sync = () => {
        field.hidden = !box.checked;
        if (!box.checked) {
          const input = field.querySelector("input[name]");
          if (input) input.value = "";
        }
      };
      sync();
      box.addEventListener("change", sync);
    });
  }

  // ---------------------------------------------------------------------
  // Toasts: transient confirmations. They fade out by themselves, and the
  // notice leaves the address bar so a reload doesn't replay them.
  // ---------------------------------------------------------------------
  function dismissToasts() {
    document.querySelectorAll("[data-toast]").forEach((toast) => {
      setTimeout(() => {
        toast.classList.add("toast-out");
        setTimeout(() => toast.remove(), 500);
      }, 3500);
    });
    if (new URLSearchParams(location.search).has("notice")) {
      const url = new URL(location);
      url.searchParams.delete("notice");
      history.replaceState(null, "", url);
    }
  }
})();
