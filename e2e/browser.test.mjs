// Browser tests: drives platypus through the main flows in Chromium, against
// the docker-compose stack with fresh data. Run with `make e2e`.
//
// Unit and handler tests can't see JavaScript, htmx swaps or the
// Content-Security-Policy at work; these tests do. Any console error other
// than the expected responses to wrong input fails the run.
import { chromium } from "playwright";
import crypto from "node:crypto";

const token = process.env.BOOTSTRAP_TOKEN;
const problems = [];
const shot = async (page, name) => page.screenshot({ path: `shots/${name}.png`, fullPage: true });

function totp(secret, offsetSteps = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offsetSteps));
  const digest = crypto.createHmac("sha1", key).update(counter).digest();
  const o = digest[19] & 15;
  return String((digest.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
}

// Chromium treats *.localhost origins as trustworthy, like https in
// production: it honours the security headers instead of logging that it
// ignored them. oidc.localhost is the web-oidc container; the specific rule
// comes first, before the wildcard.
const browser = await chromium.launch({
  args: ["--host-resolver-rules=MAP oidc.localhost web-oidc, MAP *.localhost dev-proxy"],
});
const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, timezoneId: "Europe/Amsterdam" });
const page = await context.newPage();
page.on("console", (m) => { if (m.type() === "error" || m.type() === "warning") problems.push(`console ${m.type()}: ${m.text()}`); });
page.on("pageerror", (e) => problems.push(`page error: ${e.message}`));
page.on("response", (r) => { if (r.request().method() === "POST") console.log("POST", r.url(), r.status(), r.headers()["location"] ?? ""); });
page.on("dialog", (d) => { console.log("DIALOG", d.type(), d.message()); d.dismiss().catch(() => {}); });


const checkoutBuild = async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const crypto = await import("node:crypto");
  const hash = crypto.createHash("sha256");
  for (const [dir, prefix] of [["templates", "templates"], ["static", "static"]]) {
    const files = [];
    const walk = (current, rel) => {
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const full = path.join(current, entry.name);
        const child = `${rel}/${entry.name}`;
        if (entry.isDirectory()) walk(full, child);
        else files.push([child, full]);
      }
    };
    walk(`/checkout/${dir}`, prefix);
    files.sort((a, b) => (a[0] < b[0] ? -1 : 1));
    for (const [rel, full] of files) {
      hash.update(rel + "\0");
      hash.update(fs.readFileSync(full));
      hash.update("\0");
    }
  }
  return hash.digest("hex").slice(0, 16);
};

const base = "http://admin.localhost:8090";
const assertLocalTimes = async (selector, where) => {
  const got = await page.evaluate((sel) => {
    const element = document.querySelector(sel);
    if (!element) return { error: "no time element" };
    const pad = (n) => String(n).padStart(2, "0");
    const d = new Date(element.getAttribute("datetime"));
    const expected = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    return { shown: element.textContent.trim(), expected };
  }, selector);
  if (got.error || got.shown !== got.expected) {
    throw new Error(`${where} shows UTC or a stale time: ${JSON.stringify(got)}`);
  }
};
const dump = async (page, name, err) => {
  try {
    const fs = await import("node:fs");
    fs.writeFileSync(`shots/${name}.html`, await page.content());
    if (err) fs.writeFileSync(`shots/${name}.txt`, err.message);
  } catch {}
};
const step = async (name, fn, onPage = page) => {
  try { await fn(); console.log("ok  ", name); }
  catch (e) {
    problems.push(`${name}: ${e.message.split("\n")[0]}`);
    console.log("FAIL", name, e.message.split("\n")[0]);
    await shot(onPage, "fail-" + name.replace(/\W+/g, "-"));
    await dump(onPage, "fail-" + name.replace(/\W+/g, "-"), e);
  }
};

await step("the running build matches the checkout", async () => {
  await page.goto(base + "/");
  const served = await page.evaluate(() => document.querySelector('meta[name="build"]')?.content ?? "");
  const expected = await checkoutBuild();
  if (!served) throw new Error("the page carries no build id, so staleness cannot be detected");
  if (served !== expected) {
    throw new Error(`stale build: serving ${served}, checkout is ${expected} — restart the stack (make dev-reload)`);
  }
});
await step("bootstrap page", async () => {
  await page.goto(base + "/");
  await page.waitForSelector("text=Bootstrap token");
  await shot(page, "01-bootstrap");
});
await step("wrong token shows an error", async () => {
  await page.fill("#token", "wrong");
  await page.click("button:has-text('Continue')");
  await page.waitForSelector(".alert.error");
});
await step("token accepted", async () => {
  await page.fill("#token", token);
  await page.click("button:has-text('Continue')");
  await page.waitForSelector("text=2. Second factor");
});
let secret;
await step("authenticator app setup", async () => {
  await page.click("button:has-text('Set up an authenticator app')");
  await page.waitForSelector("img.qr");
  const box = await page.locator("img.qr").boundingBox();
  if (!box || box.width < 100) throw new Error("QR code not visible");
  secret = await page.locator("code").last().innerText();
  await shot(page, "02-totp");
  await page.fill("#totp-code", totp(secret, -1));
  await page.click("button:has-text('Confirm')");
  await page.waitForSelector("text=3. Recovery codes");
});
await step("recovery codes", async () => {
  await page.click("button:has-text('Create recovery codes')");
  await page.waitForSelector("ul.codes li");
  await shot(page, "03-codes");
  await page.click("text=I saved my codes");
  await page.waitForSelector("text=4. Finish");
  await page.click("button:has-text('Finish setup')");
  await page.waitForURL("**/admin/elevate");
});
await step("admin mode", async () => {
  await page.fill("#code", totp(secret));
  await page.click("button:has-text('Confirm')");
  await page.waitForURL("**/admin?notice=admin-on");
  await shot(page, "04-admin");
});
await step("create a policy with the rule editor", async () => {
  await page.goto(base + "/admin/policies/new");
  // Deferred scripts attach the dirty-form handler; interact only after load.
  await page.waitForLoadState("load");
  await page.fill("#name", "Everything for admin");
  await page.click("[data-add-rule]");
  let row = page.locator(".rules .rule-row").last();
  await row.locator("select[name=rule_kind]").selectOption("ssm");
  await row.locator("input[name=rule_pattern]").fill("/*");
  for (const p of ["edit", "reveal", "create"]) await row.locator(`input[data-permission=${p}]`).check();
  await page.click("[data-add-rule]");
  row = page.locator(".rules .rule-row").last();
  await row.locator("select[name=rule_kind]").selectOption("secret");
  await row.locator("input[name=rule_pattern]").fill("prod/*");
  await row.locator("input[data-permission=edit]").check();
  await row.locator("input[data-permission=reveal]").check();
  // The preview follows the rules after a short delay; wait for the second one.
  await page.waitForSelector("#rule-preview tr:has-text('prod/*'):has-text('matches')");
  await shot(page, "05-policy");
  await page.click("button:has-text('Create policy')");
  await page.waitForSelector("dialog[open] >> text=Create this policy?");
  await page.click("dialog button:has-text('Create policy')");
  await page.waitForURL("**/admin/policies/*?notice=created");
  // On the saved policy, every rule row is editable, not just the first.
  const rows = page.locator(".rule-row");
  if ((await rows.count()) !== 2) throw new Error(`expected 2 rule rows, found ${await rows.count()}`);
  const glyph = await rows.nth(0).locator(".remove-row").evaluate((button) => {
    const box = button.getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(button);
    const text = range.getBoundingClientRect();
    return {
      dx: Math.abs((box.left + box.width / 2) - (text.left + text.width / 2)),
      dy: Math.abs((box.top + box.height / 2) - (text.top + text.height / 2)),
    };
  });
  if (glyph.dx >= 1 || glyph.dy >= 1) throw new Error(`the remove × is off centre: ${JSON.stringify(glyph)}`);
  await rows.nth(1).locator("input[name=rule_pattern]").fill("prod/changed/*");
  await page.waitForSelector("#rule-preview tr:has-text('prod/changed/*')");
  await rows.nth(1).locator("input[name=rule_pattern]").fill("prod/*");
  await page.waitForSelector("#rule-preview tr:has-text('prod/*')");
  await page.click("button:has-text('Save policy')");
  await page.waitForSelector("dialog[open] >> text=Save this policy?");
  await page.click("dialog button:has-text('Save policy')");
  await page.waitForURL("**/admin/policies/*?notice=saved");
  await shot(page, "05c-policy-edited");
});
await step("assign the policy to the admin", async () => {
  await page.goto(base + "/admin/users/1");
  await page.click(".policy-editor [data-add-choice]");
  await page.locator(".policy-editor [data-choice-select]").last().selectOption({ label: "Everything for admin" });
  // Save goes through a confirmation page first.
  await page.click(".policy-editor button:has-text('Save policies')");
  await page.waitForURL("**/admin/users/1/policies/preview");
  await page.waitForSelector("h2:has-text('Save these policies?')");
  await page.click("form[action$='/admin/users/1/policies'] button[type=submit]");
  await page.waitForURL("**/admin/users/1?notice=saved");
});
await step("save and add another", async () => {
  await page.goto(base + "/ssm/new");
  await page.waitForSelector("button[name=after][value=another]");
  const label = (await page.locator("button[name=after][value=view]").innerText()).trim();
  if (label !== "Save") throw new Error(`the first create button says ${JSON.stringify(label)}, want Save`);
  await page.fill("#name", "/apps/another-one");
  await page.fill("#description", "Another parameter");
  await page.fill("textarea[name=value]", "another-value");
  await page.click("button[name=after][value=another]");
  await page.waitForSelector("dialog[open]");
  await page.click("dialog button:has-text('Continue')");
  await page.waitForURL("**/ssm/new?notice=saved");
  const empty = await page.evaluate(() => ({
    name: document.querySelector("#name").value,
    value: document.querySelector("textarea[name=value]").value,
  }));
  if (empty.name !== "" || empty.value !== "") {
    throw new Error(`the next create form is not empty: ${JSON.stringify(empty)}`);
  }
});
await step("a group-linked team takes its members from the login", async () => {
  await page.goto(base + "/admin/policies/new");
  await page.fill("#name", "Payments group");
  await page.click("[data-add-rule]");
  const groupRow = page.locator(".rules .rule-row").last();
  await groupRow.locator("select[name=rule_kind]").selectOption("ssm");
  await groupRow.locator("input[name=rule_pattern]").fill("/payments/*");
  await page.click("button:has-text('Create policy')");
  await page.waitForSelector("dialog[open] >> text=Create this policy?");
  await page.click("dialog button:has-text('Create policy')");
  await page.waitForURL("**/admin/policies/*?notice=created");

  await page.goto(base + "/admin/teams/new");
  // The group field only exists once the link checkbox is ticked.
  if (await page.locator("#new-idp-group").isVisible()) throw new Error("the group field shows before the link is wanted");
  await page.fill("#name", "Payments");
  await page.check("#new-link-group");
  if (!(await page.locator("#new-idp-group").isVisible())) throw new Error("ticking the checkbox does not reveal the group field");
  await page.fill("#new-idp-group-input", "payments");
  await page.click("button:has-text('Create team')");
  await page.waitForURL("**/admin/teams/*?notice=created");
  const teamURL = new URL(page.url()).pathname;

  await page.click(".policy-editor [data-add-choice]");
  await page.locator(".policy-editor [data-choice-select]").last().selectOption({ label: "Payments group" });
  await page.click(".policy-editor button:has-text('Save policies')");
  await page.waitForURL("**/policies/preview");
  await page.waitForSelector("h2:has-text('Save these policies?')");
  await page.click("form[action$='/policies'] button[type=submit]");
  await page.waitForURL("**" + teamURL + "?notice=saved");

  // The user's Teams card is one table: checkbox, team, and that team's rules.
  await page.goto(base + "/admin/users/1");
  // The policy editor is one line per attached policy, each a dropdown.
  const policyEditor = await page.evaluate(() => {
    const form = document.querySelector(".policy-editor");
    if (!form) return { error: "no policy editor" };
    const selects = Array.from(form.querySelectorAll("[data-choice-select]"));
    return {
      rows: form.querySelectorAll("[data-choice-row]").length,
      selects: selects.length,
      add: Boolean(form.querySelector("[data-add-choice]")),
      chosen: selects.map((select) => select.value).filter(Boolean),
    };
  });
  if (policyEditor.error || policyEditor.rows < 1 || policyEditor.rows !== policyEditor.selects || !policyEditor.add) {
    throw new Error(`the policy editor is not a line per policy: ${JSON.stringify(policyEditor)}`);
  }
  // A new line starts empty; every already attached policy is disabled in it.
  await page.click(".policy-editor [data-add-choice]");
  const added = await page.evaluate(() => {
    const selects = Array.from(document.querySelectorAll(".policy-editor [data-choice-select]"));
    const last = selects.at(-1);
    return {
      value: last.value,
      attached: selects.slice(0, -1).map((select) => select.value).filter(Boolean),
      disabled: Array.from(last.options).filter((option) => option.disabled).map((option) => option.value),
    };
  });
  if (added.value !== "" || !added.attached.every((id) => added.disabled.includes(id))) {
    throw new Error(`a new policy line offers policies that are already attached: ${JSON.stringify(added)}`);
  }
  await page.locator(".policy-editor [data-choice-row]").last().locator("[data-remove-choice]").click();
  // The team editor is a line per team, with the remove button beside the
  // select (never wrapped to the next line).
  // The team page says where members come from and offers no manual changes.
  await page.goto(base + teamURL);
  await page.waitForSelector(".alert.info:has-text('Members come from the identity-provider group')");
  if (await page.locator(".member-editor").count()) throw new Error("a linked team offers manual members");
  await shot(page, "04b-group-team");

  // The editor's login reports the payments group (the dev proxy sets the
  // groups header), so the team and its policy reach them on the next page.
  const editor = await context.newPage();
  editor.on("console", (m) => { if (m.type() === "error") problems.push(`editor console: ${m.text()}`); });
  await editor.goto("http://editor.localhost:8090/me");
  await editor.waitForSelector("text=Payments group");
  await editor.close();
});
await step("add a user ahead of their first login", async () => {
  await page.goto(base + "/admin/users/new");
  await page.fill("#email", "newbie@example.com");
  await page.click("button:has-text('Create account')");
  await page.waitForURL("**/admin/users/*?notice=created");
  await page.waitForSelector("text=First login");
});
await step("user detail actions reach the server", async () => {
  await page.goto(base + "/admin/users");
  const href = await page.evaluate(() => {
    const row = Array.from(document.querySelectorAll("#user-list tbody tr"))
      .find((tr) => tr.textContent.includes("newbie@example.com"));
    return row?.querySelector("a.person-name")?.getAttribute("href") ?? "";
  });
  if (!href) throw new Error("the new account is not listed");
  await page.goto(base + href);
  await page.click("button:has-text('Disable account')");
  await page.waitForURL("**/admin/users/*?notice=saved");
  await page.click("button:has-text('Enable account')");
  await page.waitForURL("**/admin/users/*?notice=saved");
});
await step("search in teams and policies", async () => {
  await page.goto(base + "/admin/teams");
  await page.fill("input[name=q]", "payment");
  await page.waitForSelector("#team-list tbody a:has-text('Payments')");
  await page.fill("input[name=q]", "zzz-nothing");
  await page.waitForSelector("#team-list td:has-text('No teams match')");

  await page.goto(base + "/admin/policies");
  await page.fill("input[name=q]", "everything");
  await page.waitForSelector("#policy-list tbody a:has-text('Everything for admin')");
  await page.fill("input[name=q]", "zzz-nothing");
  await page.waitForSelector("#policy-list td:has-text('No policies match')");
});
await step("add a passkey", async () => {
  // Chrome's virtual authenticator stands in for Touch ID or a security key.
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  await page.goto(base + "/me/security");
  await page.fill("#passkey-name", "Virtual key");
  await page.click("button:has-text('Add a passkey')");
  await page.waitForURL("**notice=factor-added");
  await page.waitForSelector("td:has-text('Virtual key')");
  await shot(page, "05b-passkey");
});
await step("admin mode with the passkey", async () => {
  await page.click("button:has-text('Leave admin mode')");
  await page.waitForURL("**notice=admin-off");
  await page.goto(base + "/admin/elevate");
  await page.click("button:has-text('Use a passkey')");
  await page.waitForURL("**/admin?notice=admin-on");
  // A hard refresh keeps admin mode: no second TOTP, no bounce to elevate.
  await page.reload();
  await page.waitForSelector("h1:has-text('Admin')");
  if (page.url().includes("/admin/elevate")) throw new Error("a refresh dropped admin mode");
});
await step("front page and theme switch", async () => {
  await page.click("a.brand");
  await page.waitForSelector("h1:has-text('Hello')");
  await page.waitForSelector(".stat-number");
  await page.click("[data-theme-toggle]");
  if ((await page.getAttribute("html", "data-theme")) !== "light") throw new Error("theme switch didn't pick light");
  await shot(page, "06a-home-light");
  await page.click("[data-theme-toggle]");
  await shot(page, "06b-home-dark");
});
await step("profile and local times", async () => {
  await page.goto(base + "/me/profile");
  await page.fill("#display_name", "Ada Admin");
  await page.fill("#department", "Platform");
  await page.check("input[name=timezone][value=local]");
  await page.click("button:has-text('Save profile')");
  await page.waitForSelector(".user a:has-text('Ada Admin')");
  // Times now follow the browser's zone, not UTC.
  await page.goto(base + "/admin/audit");
  await page.waitForSelector("#audit-results table.audit-table");
  await assertLocalTimes("#audit-results time[datetime]", "the audit trail");
  // Searching re-renders the fragment server-side: it must come back local.
  await page.fill(".search-bar input[type=search][name=q]", "admin");
  await page.waitForTimeout(1200);
  await assertLocalTimes("#audit-results time[datetime]", "the audit trail after a search");
  await page.fill(".search-bar input[type=search][name=q]", "");
  await page.waitForTimeout(1200);
  // The server itself must render local time: read the HTML it sends and
  // check the <time> text against the instant. No page script is involved, so
  // a failure here means the flash is real, not that JS was slow.
  const served = await page.evaluate(async () => {
    const response = await fetch("/admin/audit");
    return { status: response.status, html: await response.text() };
  });
  const shown = served.html.match(/<time datetime="([^"]+)" data-utc="[^"]*">([^<]+)<\/time>/);
  if (!shown) throw new Error(`the server sent no time element: ${served.status}`);
  const expected = await page.evaluate((iso) => {
    const d = new Date(iso);
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }, shown[1]);
  if (shown[2] !== expected) {
    throw new Error(`the server rendered UTC: sent "${shown[2]}", browser zone says "${expected}"`);
  }
  if (!served.html.includes('data-zone="Europe/Amsterdam"')) {
    throw new Error("the server did not use the reported zone (tzdata missing in the image?)");
  }
  await page.waitForTimeout(1200);
});
await step("list and search", async () => {
  await page.goto(base + "/ssm");
  await page.waitForSelector("#results .item-name:has-text('/payments/api/key')");
  await page.fill("input[name=q]", "search");
  await page.waitForSelector("#results .item-name:has-text('/payments/api/key')", { state: "detached" });
  await page.waitForSelector("#results .item-name:has-text('/search/endpoint')");
  await assertLocalTimes("#results time[datetime]", "a typed search");

  // The same through the Search button, which submits the form.
  await page.click(".search-bar button:has-text('Search')");
  await page.waitForTimeout(1500);
  await assertLocalTimes("#results time[datetime]", "the Search button");
  await shot(page, "06-search");
});
await step("Terraform-managed secret", async () => {
  await page.goto(base + "/secrets/item?name=prod/platform/rds");
  await page.waitForSelector(".alert.terraform");
  if ((await page.locator("[aria-disabled=true]:has-text('Edit')").count()) === 0) {
    throw new Error("Edit is not disabled with a reason");
  }
  await shot(page, "06c-terraform");
});
await step("reveal and hide", async () => {
  await page.goto(base + "/ssm/item?name=/payments/api/key");
  await page.click("#value button:has-text('Reveal')");
  await page.waitForSelector("#value pre:has-text('fake-payments-key-0001')");
  await shot(page, "07-revealed");
  await page.click("text=Hide now");
  await page.waitForSelector("#value .value-hidden");
  // Hiding must restore the reveal control: no hard refresh needed.
  await page.click("#value button:has-text('Reveal')");
  await page.waitForSelector("#value pre:has-text('fake-payments-key-0001')");
  await page.click("text=Hide now");
  await page.waitForSelector("#value .value-hidden");
  // A secret reveals through the same cycle too (the restored control must
  // use the secrets route, not the singular kind).
  await page.goto(base + "/secrets/item?name=prod/payments/db");
  for (let i = 0; i < 2; i++) {
    await page.click("#value button:has-text('Reveal')");
    await page.waitForSelector("#value pre:has-text('fake-secret-password')");
    await page.click("text=Hide now");
    await page.waitForSelector("#value .value-hidden");
  }
});
await step("edit a JSON secret with the field editor", async () => {
  await page.goto(base + "/secrets/edit?name=prod/payments/db");
  if (await page.locator("textarea[name=value]").inputValue()) throw new Error("the value loaded without asking");
  await page.click("button:has-text('Load current value')");
  await page.waitForSelector("text=current value loaded");
  await page.click("label:has-text('JSON fields')");
  await page.waitForSelector(".field-row");
  const rows = page.locator(".field-row");
  const count = await rows.count();
  for (let i = 0; i < count; i++) {
    if ((await rows.nth(i).locator("input").first().inputValue()) === "password") {
      await rows.nth(i).locator("input").nth(1).fill("new-fake-password");
    }
  }
  await shot(page, "08-fields");
  await page.click("button:has-text('Save')");
  await page.waitForSelector("dialog[open] >> text=What changes");
  await page.waitForSelector("dialog[open] li:has(.badge:has-text('changed')) code:has-text('password')");
  await shot(page, "09-confirm");
  await page.click("dialog button:has-text('Continue')");
  await page.waitForURL("**notice=saved");
});
await step("rollback shows the value it restores", async () => {
  await page.goto(base + "/secrets/item?name=prod/payments/db");
  await page.waitForSelector("table:has-text('Version')");
  await page.click("button:has-text('Roll back to this')");
  await page.waitForSelector("dialog[open] >> h2:has-text('Roll back')");
  await page.waitForSelector("dialog[open] .rollback-value");
  if (!(await page.locator("dialog[open] .rollback-value").innerText()).includes("fake-secret-password")) {
    throw new Error("the rollback dialog does not show the value it restores");
  }
  await page.click("dialog button:has-text('Cancel')");
  await page.waitForSelector("dialog:not([open])", { state: "attached" });
});
await step("binary secret is refused politely", async () => {
  await page.goto(base + "/secrets/item?name=prod/legacy/certificate");
  await page.click("#value button:has-text('Reveal')");
  await page.waitForSelector("#value .alert.error:has-text('binary')");
});
await step("audit trail: filters apply as you change them", async () => {
  // The editor may only list /payments/*: opening anything else is refused
  // and audited as denied.
  const editor = await context.newPage();
  await editor.goto("http://editor.localhost:8090/ssm/item?name=/apps/other/key");
  await editor.waitForSelector("h1");
  await editor.close();

  await page.goto(base + "/admin/audit");
  await page.waitForSelector("#audit-results table.audit-table");
  // Selecting an outcome in the browser swaps the results in place.
  const events = page.locator("#audit-results .event-row");
  if ((await events.count()) === 0) throw new Error("the audit trail shows no events at all");
  await page.selectOption("#outcome", "allowed");
  await page.waitForSelector("#audit-results .badge.ok");
  await page.selectOption("#outcome", "denied");
  await page.waitForFunction(() => {
    const rows = document.querySelectorAll("#audit-results .event-row");
    return rows.length > 0 && [...rows].every((row) => row.textContent.includes("denied"));
  }, undefined, { timeout: 5000 }).catch(() => {
    throw new Error("the denied filter shows nothing");
  });
  // The export link is rendered with the results, so it follows the filter.
  const csvHref = await page.evaluate(() =>
    document.querySelector("#audit-results a[href^='/admin/audit.csv']")?.getAttribute("href") ?? "");
  if (!csvHref.includes("outcome=denied")) {
    throw new Error(`the CSV link does not follow the filter: ${csvHref}`);
  }
  // The row's toggle opens the full record; from there its user filters the
  // trail.
  await page.click("#audit-results .row-toggle");
  await page.waitForSelector("#audit-results .detail-row:not([hidden]) dl");
  await page.click("#audit-results .detail-row:not([hidden]) a[href*='actor=']");
  await page.waitForSelector("#actor");
  // And the filters can be cleared again.
  await page.click("a:has-text('Clear filters')");
  await page.waitForSelector("#audit-results .event-row");
  await shot(page, "10b-audit");
});

await step("docs", async () => {
  await page.goto(base + "/docs");
  await page.waitForSelector(".docs nav");
  const docsAlign = await page.evaluate(() => {
    const nav = document.querySelector(".docs nav").getBoundingClientRect();
    const article = document.querySelector(".docs article").getBoundingClientRect();
    return { diff: Math.round(article.bottom - nav.bottom), navBottom: Math.round(nav.bottom), articleBottom: Math.round(article.bottom) };
  });
  if (docsAlign.diff < 0) throw new Error(`the docs article is shorter than its navigation: ${JSON.stringify(docsAlign)}`);
  await page.goto(base + "/docs/working-with-values");
  await page.waitForSelector("h1:has-text('Working with values')");
  await shot(page, "10-docs");
});
await step("block switch dialog", async () => {
  await page.goto(base + "/admin");
  await page.click("button:has-text('Block all access')");
  await page.waitForSelector("dialog[open] >> text=Block all access?");
  await page.click("dialog button:has-text('Cancel')");
  await page.waitForSelector("dialog:not([open])", { state: "attached" });
});

await step("layout invariants hold", async () => {
  // The audit trail is a table: aligned columns, a circled toggle, an action
  // column that never clips, and an opened record that stays in its card.
  await page.goto(base + "/admin/audit");
  await page.waitForSelector("#audit-results table.audit-table");
  const auditTable = await page.evaluate(() => {
    const table = document.querySelector("#audit-results table.audit-table");
    const headers = Array.from(table.querySelectorAll("thead th"));
    const cells = Array.from(table.querySelectorAll("tbody tr.event-row:first-of-type > td"));
    return {
      headers: headers.length,
      cells: cells.length,
      aligned: headers.every((h, i) => cells[i] && Math.abs(h.getBoundingClientRect().x - cells[i].getBoundingClientRect().x) < 2),
      offsets: headers.map((h, i) => [Math.round(h.getBoundingClientRect().x), cells[i] ? Math.round(cells[i].getBoundingClientRect().x) : null]),
    };
  });
  if (auditTable.headers !== 5 || auditTable.cells !== 5) {
    throw new Error(`the audit table has ${auditTable.headers} headers for ${auditTable.cells} fields`);
  }
  if (!auditTable.aligned) throw new Error(`the audit columns misalign: ${JSON.stringify(auditTable.offsets)}`);
  const auditChevron = await page.evaluate(() => {
    const toggle = document.querySelector("#audit-results .row-toggle");
    const before = getComputedStyle(toggle, "::before");
    return { size: Math.round(toggle.getBoundingClientRect().width), radius: getComputedStyle(toggle).borderRadius, border: before.borderRightWidth };
  });
  if (auditChevron.size < 20 || auditChevron.radius !== "50%" || auditChevron.border !== "2px") {
    throw new Error(`the audit disclosure is not a circled chevron: ${JSON.stringify(auditChevron)}`);
  }
  const actionFits = await page.evaluate(() => {
    const cell = document.querySelector("#audit-results .action-cell");
    return cell.scrollWidth <= cell.clientWidth + 1;
  });
  if (!actionFits) throw new Error("the audit action column clips");
  await page.click("#audit-results .row-toggle");
  const audit = await page.evaluate(() => {
    const results = document.querySelector("#audit-results");
    const card = results.querySelector(".card");
    const detail = results.querySelector(".detail-row:not([hidden])");
    const json = detail?.querySelector(".event-json");
    const rect = (el) => (el ? { x: Math.round(el.getBoundingClientRect().x), w: Math.round(el.getBoundingClientRect().width) } : null);
    return {
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      resultsOverflow: results.scrollWidth - results.clientWidth,
      cardScroll: card ? card.scrollWidth - card.clientWidth : null,
      detail: rect(detail), json: rect(json),
      hasFilter: Boolean(detail?.querySelector("a[href*='actor=']")),
    };
  });
  if (audit.pageOverflow > 0 || audit.resultsOverflow > 0 || (audit.cardScroll ?? 0) > 0) {
    throw new Error(`audit overflows: ${JSON.stringify(audit)}`);
  }
  if (!audit.detail || !audit.hasFilter) {
    throw new Error(`the audit record did not open: ${JSON.stringify(audit)}`);
  }

  // Column headers sit exactly above their cells.
  const aligned = async (path, selector, column) => {
    await page.goto(base + path);
    await page.waitForSelector(selector + " tbody tr td");
    return page.evaluate(([selector, column]) => {
      const table = document.querySelector(selector);
      const th = table.querySelectorAll("thead th")[column];
      const td = table.querySelector("tbody tr").children[column];
      if (!th || !td) return { ok: false, why: "missing cell" };
      const a = th.getBoundingClientRect(), b = td.getBoundingClientRect();
      return { ok: Math.abs(a.x - b.x) < 2, th: a.x, td: b.x };
    }, [selector, column]);
  };
  // Item lists: a real table. Header cells sit above their cells, rows fit
  // their card, and every row has its ways in.
  await page.goto(base + "/ssm");
  await page.waitForSelector("#results table.items-table");
  const items = await page.evaluate(() => {
    const list = document.querySelector("#results");
    const table = list.querySelector("table.items-table");
    const headers = Array.from(table.querySelectorAll("thead th"));
    const cells = Array.from(table.querySelectorAll("tbody tr.item-row:first-of-type > td"));
    const offsets = headers.map((h, i) => [Math.round(h.getBoundingClientRect().x), i < cells.length ? Math.round(cells[i].getBoundingClientRect().x) : null]);
    return {
      overflow: list.scrollWidth - list.clientWidth,
      headers: headers.length,
      cells: cells.length,
      aligned: offsets.every(([h, c]) => c !== null && Math.abs(h - c) < 2),
      offsets,
    };
  });
  if (items.overflow > 0) throw new Error(`the item list overflows by ${items.overflow}px`);
  if (items.headers !== 6 || items.cells !== 6) {
    throw new Error(`the items table has ${items.headers} headers for ${items.cells} fields`);
  }
  if (!items.aligned) throw new Error(`item columns misaligned: ${JSON.stringify(items.offsets)}`);
  const pager = await page.evaluate(() => {
    const steps = document.querySelector(".page-steps");
    const select = document.querySelector(".page-size select");
    const step = document.querySelector(".page-step");
    const current = document.querySelector(".page-num.current");
    if (!steps || !select || !step || !current) return { error: "a pager part is missing" };
    const a = steps.getBoundingClientRect(), b = select.getBoundingClientRect();
    return {
      row: Math.abs((a.top + a.height / 2) - (b.top + b.height / 2)),
      heights: [Math.round(step.getBoundingClientRect().height), Math.round(select.getBoundingClientRect().height), Math.round(current.getBoundingClientRect().height)],
      current: current.textContent.trim(),
    };
  });
  if (pager.error || pager.row > 2 || new Set(pager.heights).size !== 1 || pager.current !== "1") {
    throw new Error(`the pager is not one aligned row: ${JSON.stringify(pager)}`);
  }
  if ((await page.locator("#results .row-actions a[href^='/ssm/edit']").count()) === 0) {
    throw new Error("rows have no Edit action");
  }
  if ((await page.locator("#results .row-actions a[href^='/ssm/item?name=']").count()) === 0) {
    throw new Error("rows have no direct View action");
  }
  const chevron = await page.evaluate(() => {
    const toggle = document.querySelector("#results .row-toggle");
    const before = getComputedStyle(toggle, "::before");
    const box = toggle.getBoundingClientRect();
    return { size: Math.round(box.width), radius: getComputedStyle(toggle).borderRadius, border: before.borderRightWidth };
  });
  if (chevron.size < 20 || chevron.radius !== "50%" || chevron.border !== "2px") {
    throw new Error(`the item disclosure is not a circled chevron: ${JSON.stringify(chevron)}`);
  }
  const firstItemToggle = page.locator("#results .row-toggle").first();
  await firstItemToggle.click();
  const itemOpened = await page.evaluate(() => {
    const row = document.querySelector("#results .detail-row");
    return {
      hidden: row?.hasAttribute("hidden"),
      link: Boolean(row?.querySelector("a[href^='/ssm/item?name=']")),
    };
  });
  if (itemOpened.hidden || !itemOpened.link) throw new Error(`the item detail row did not open: ${JSON.stringify(itemOpened)}`);
  await firstItemToggle.click();

  // Rows fit their card at every width: nothing paints past its edge.
  for (const width of [1280, 1216, 1152, 1088, 1024, 960, 900]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(base + "/ssm");
    await page.waitForSelector("#results table.items-table");
    const fits = await page.evaluate(() => {
      const card = document.querySelector("#results .card");
      const table = document.querySelector("#results table.items-table");
      const cardBox = card.getBoundingClientRect();
      const outside = Array.from(table.querySelectorAll("td")).filter((cell) => {
        const box = cell.getBoundingClientRect();
        return box.width > 0 && box.right > cardBox.right - 1;
      }).length;
      return { outside, overflow: table.scrollWidth - table.clientWidth };
    });
    if (fits.outside > 0 || fits.overflow > 0) {
      throw new Error(`item rows bleed out of the card at ${width}px: ${JSON.stringify(fits)}`);
    }
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(base + "/ssm");
  await page.waitForSelector("#results table.items-table");

  // The actions and the moment never overlap.
  const noOverlap = await page.evaluate(() => {
    const row = document.querySelector("#results tr.item-row");
    const when = row.querySelector("td.when").getBoundingClientRect();
    const actions = row.querySelector("td.row-actions").getBoundingClientRect();
    return when.right <= actions.left + 1;
  });
  if (!noOverlap) throw new Error("the actions overlap the timestamp");

  // Choosing a page size survives the next search.
  await page.goto(base + "/ssm");
  await page.waitForSelector("#results table.items-table");
  await page.selectOption(".page-size select[name=per_page]", "20");
  await page.waitForTimeout(900);
  await page.fill("input[name=q]", "payments");
  await page.waitForTimeout(900);
  const sizeKept = await page.evaluate(() => ({
    select: document.querySelector(".page-size select[name=per_page]")?.value ?? "",
    url: location.search,
  }));
  if (sizeKept.select !== "20" || !sizeKept.url.includes("per_page=20")) {
    throw new Error(`the page size was lost by the search: ${JSON.stringify(sizeKept)}`);
  }

  // People lists (users, team members) never overflow their card either.
  await page.goto(base + "/admin/users");
  await page.waitForSelector("#user-list table.people-table");
  const people = await page.evaluate(() => {
    const list = document.querySelector("#user-list");
    const table = list.querySelector("table.people-table");
    const headers = Array.from(table.querySelectorAll("thead th"));
    const cells = Array.from(table.querySelectorAll("tbody tr:first-child td"));
    const offsets = headers.map((h, i) => [Math.round(h.getBoundingClientRect().x), i < cells.length ? Math.round(cells[i].getBoundingClientRect().x) : null]);
    return {
      overflow: list.scrollWidth - list.clientWidth,
      headerCount: headers.length,
      cellCount: cells.length,
      aligned: offsets.every(([h, c]) => c !== null && Math.abs(h - c) < 2),
      offsets,
    };
  });
  if (people.overflow > 0) throw new Error(`the users list overflows by ${people.overflow}px`);
  if (people.headerCount !== 5 || people.cellCount !== 5) {
    throw new Error(`the users table has ${people.headerCount} headers for ${people.cellCount} fields`);
  }
  if (!people.aligned) throw new Error(`the users table is not aligned with its header: ${JSON.stringify(people.offsets)}`);
  // One separator, not two: the pager carries it, the last row does not.
  const separators = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll("#user-list tbody tr:not(.detail-row)"));
    const last = rows[rows.length - 1];
    const pager = document.querySelector("#user-list .pager");
    return {
      rowBorder: getComputedStyle(last.querySelector("td")).borderBottomWidth,
      pagerBorder: pager ? getComputedStyle(pager).borderTopWidth : null,
    };
  });
  const toggleChevron = await page.evaluate(() => {
    const toggle = document.querySelector("#user-list .row-toggle");
    const before = getComputedStyle(toggle, "::before");
    return { size: Math.round(toggle.getBoundingClientRect().width), radius: getComputedStyle(toggle).borderRadius,
             width: parseFloat(before.width), border: before.borderRightWidth };
  });
  if (toggleChevron.size < 20 || toggleChevron.radius !== "50%" || toggleChevron.border !== "2px") {
    throw new Error(`the user row toggle is not a circled chevron: ${JSON.stringify(toggleChevron)}`);
  }
  if (separators.rowBorder !== "0px" || !separators.pagerBorder || separators.pagerBorder === "0px") {
    throw new Error(`the users list draws a double separator: ${JSON.stringify(separators)}`);
  }
  const firstToggle = page.locator("#user-list .row-toggle").first();
  const detailId = await firstToggle.getAttribute("aria-controls");
  await firstToggle.click();
  const opened = await page.evaluate((id) => {
    const row = document.getElementById(id);
    return { hidden: row.hasAttribute("hidden"), text: row.textContent.replace(/\s+/g, " ") };
  }, detailId);
  if (opened.hidden || !opened.text.includes("Department")) {
    throw new Error(`the user row did not expand: ${JSON.stringify(opened)}`);
  }
  await firstToggle.click();

  // Lists in the same family share one search control: same shape and width.
  for (const paths of [
    ["/ssm", "/secrets"],
    ["/admin/users", "/admin/teams", "/admin/policies", "/admin/audit"],
  ]) {
    const widths = {};
    for (const path of paths) {
      await page.goto(base + path);
      await page.waitForSelector("input[type=search][name=q]");
      widths[path] = await page.evaluate(() => Math.round(document.querySelector("input[type=search][name=q]").getBoundingClientRect().width));
    }
    const sample = widths[paths[0]];
    for (const [path, width] of Object.entries(widths)) {
      if (Math.abs(width - sample) > 2) throw new Error(`search widths differ: ${JSON.stringify(widths)}`);
    }
  }

  // One status line at most, never stacked notifications.
  if ((await page.locator(".status-strip").count()) > 1) throw new Error("status strips stacked");
  if ((await page.locator(".toast").count()) > 1) throw new Error("toasts stacked");

  // Every admin view has the same page width and the same content start:
  // switching sections must not make the tables dance.
  const widths = {};
  const contentTops = {};
  for (const path of ["/admin", "/admin/users", "/admin/teams", "/admin/policies", "/admin/audit"]) {
    await page.goto(base + path);
    await page.waitForSelector(".admin-content");
    const box = await page.evaluate(() => {
      const content = document.querySelector(".admin-content");
      const card = content.querySelector(".card");
      return { width: content.getBoundingClientRect().width, top: card.getBoundingClientRect().top };
    });
    widths[path] = box.width;
    contentTops[path] = box.top;
  }
  const first = widths["/admin"];
  for (const [path, width] of Object.entries(widths)) {
    if (Math.abs(width - first) > 2) throw new Error(`admin view widths differ: ${JSON.stringify(widths)}`);
  }
  const firstTop = contentTops["/admin"];
  for (const [path, top] of Object.entries(contentTops)) {
    if (Math.abs(top - firstTop) > 2) throw new Error(`admin content starts lower on ${path}: ${JSON.stringify(contentTops)}`);
  }

  // Narrow screens: the admin sections collapse above the content.
  await page.setViewportSize({ width: 480, height: 900 });
  await page.goto(base + "/admin/users");
  await page.waitForSelector(".admin-content");
  const narrow = await page.evaluate(() => {
    const nav = document.querySelector(".admin-views").getBoundingClientRect();
    const content = document.querySelector(".admin-content").getBoundingClientRect();
    return { stacked: content.y > nav.y + nav.height - 1 };
  });
  await page.setViewportSize({ width: 1280, height: 900 });
  if (!narrow.stacked) throw new Error("admin sections do not collapse on narrow screens");

  // Form fields stack: the label sits above its own input, on the same x.
  await page.goto(base + "/admin/policies/new");
  await page.waitForSelector("#policy-form .form-stack .field");
  const field = await page.evaluate(() => {
    const wrap = document.querySelector("#policy-form .form-stack .field");
    const label = wrap.querySelector("label").getBoundingClientRect();
    const input = wrap.querySelector("input").getBoundingClientRect();
    return { stacked: input.y >= label.y + label.height - 1, sameX: Math.abs(input.x - label.x) < 2 };
  });
  if (!field.stacked || !field.sameX) throw new Error(`form field not stacked: ${JSON.stringify(field)}`);
});

// oidc mode: a second platypus that logs people in itself, with Dex as the
// identity provider. Runs after the header-mode steps, which bootstrapped
// the shared database.
const oidcBase = "http://oidc.localhost:8080";
const oidcContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const oidcPage = await oidcContext.newPage();
oidcPage.on("console", (m) => { if (m.type() === "error") problems.push(`oidc console: ${m.text()}`); });
oidcPage.on("pageerror", (e) => problems.push(`oidc page error: ${e.message}`));

await step("documentation screenshots", async () => {
  if (process.env.DOCS_SHOTS !== "1") return;
  const fs = await import("node:fs");
  const out = "/work/docs-images";
  fs.mkdirSync(out, { recursive: true });
  await page.setViewportSize({ width: 1280, height: 860 });
  await page.emulateMedia({ colorScheme: "light" });
  await page.evaluate(() => {
    localStorage.setItem("platypus-theme", "light");
    document.documentElement.dataset.theme = "light";
  });
  const shoot = async (name, path, selector) => {
    await page.goto(base + path);
    if (selector) await page.waitForSelector(selector);
    // The test-mode strip is a development banner, not part of the product.
    // (Inline CSS is blocked by the app's CSP, so remove it from the DOM.)
    await page.evaluate(() => {
      document.querySelectorAll(".status-strip, .toast").forEach((el) => el.remove());
    });
    await page.waitForTimeout(150);
    await page.screenshot({ path: `${out}/${name}.png` });
    console.log("shot", name);
  };

  await shoot("01-home", "/", ".welcome");
  await shoot("02-ssm-list", "/ssm", "#results .item-row");
  await page.click("#results .row-toggle");
  await page.waitForTimeout(200);
  await page.screenshot({ path: `${out}/03-ssm-row.png` });
  console.log("shot 03-ssm-row");
  await page.goto(base + "/secrets");
  const secretHref = await page.getAttribute("#results .item-row a[href^='/secrets/item?name=']", "href");
  await shoot("04-secret-detail", secretHref, "h1");

  // A normal team with the admin in it, so the examples show a populated
  // team editor, not "no unlinked teams".
  await page.goto(base + "/admin/teams/new");
  await page.fill("#name", "Platform");
  await page.click("button:has-text('Create team')");
  await page.waitForURL("**/admin/teams/*?notice=created");
  const platformPath = new URL(page.url()).pathname;
  // Give the team a policy, so the example shows one.
  await page.click(".policy-editor [data-add-choice]");
  await page.selectOption(".policy-editor [data-choice-select]", { label: "Everything for admin" });
  await page.click(".policy-editor button:has-text('Save policies')");
  await page.waitForURL("**/policies/preview");
  await page.click("form[action$='/policies'] button[type=submit]");
  await page.waitForURL("**" + platformPath + "?notice=saved");

  await page.goto(base + "/admin/users/1");
  await page.click(".team-editor [data-add-choice]");
  await page.selectOption(".team-editor [data-choice-select]", { label: "Platform" });
  await page.click(".team-editor button:has-text('Save teams')");
  await page.waitForURL("**/teams/preview");
  await page.click("form[action$='/admin/users/1/teams'] button[type=submit]");
  await page.waitForURL("**/admin/users/1?notice=saved");

  await page.goto(base + "/admin/users");
  const userHref = await page.getAttribute("#user-list a.person-name", "href");
  await shoot("05-users", "/admin/users", "#user-list .person-name");
  await shoot("06-user-detail", userHref, ".team-editor");

  await shoot("07-teams", "/admin/teams", "#team-list a.cell-name");
  await shoot("08-team-detail", platformPath, ".policy-editor");

  await page.goto(base + "/admin/policies");
  const policyHref = await page.getAttribute("#policy-list a.cell-name", "href");
  await shoot("09-policies", "/admin/policies", "#policy-list a.cell-name");
  await shoot("10-policy-editor", policyHref, ".rule-row");

  await shoot("11-audit", "/admin/audit", "#audit-results table.audit-table");
  await shoot("12-docs", "/docs", ".docs article");
});

await step("visual regression", async () => {
  if (process.env.VISUAL !== "1") return;
  const { PNG } = await import("pngjs");
  const { default: pixelmatch } = await import("pixelmatch");
  const fs = await import("node:fs");
  const dir = "/work/visual";
  fs.mkdirSync(dir, { recursive: true });
  const update = process.env.VISUAL_UPDATE === "1";

  await page.emulateMedia({ colorScheme: "light" });
  await page.evaluate(() => {
    localStorage.setItem("platypus-theme", "light");
    document.documentElement.dataset.theme = "light";
  });

  // Stable targets within the run: derive the policy URL from the list.
  await page.goto(base + "/admin/policies");
  const policyHref = await page.getAttribute("#policy-list a.cell-name", "href");
  const targets = [
    ["ssm", "/ssm", ".items-table"],
    ["users", "/admin/users", ".people-table"],
    // The team page is not a pixel target: linked membership materialises at
    // login, so the member list can legitimately differ between runs.
    ["policy", policyHref, ".rule-row"],
    // The audit trail is deliberately not a pixel target: every action logs an
    // event, so any test change alters its rows. Its layout is covered by the
    // table and column guards instead.
    ["docs", "/docs", ".docs article"],
  ];

  const failures = [];
  let compared = 0;
  for (const width of [1280, 1024]) {
    await page.setViewportSize({ width, height: 900 });
    for (const [name, path, selector] of targets) {
      await page.goto(base + path);
      await page.waitForSelector(selector);
      await page.evaluate(() => {
        // Times are the only content that changes between identical runs.
        document.querySelectorAll("time").forEach((el) => { el.textContent = "2026-01-02 03:04"; });
        document.querySelectorAll(".status-strip, .toast").forEach((el) => el.remove());
      });
      const shot = await page.screenshot();
      const file = `${dir}/${name}-${width}.png`;
      if (update) {
        fs.writeFileSync(file, shot);
        continue;
      }
      if (!fs.existsSync(file)) {
        failures.push(`${name}-${width}: no baseline (run make visual-update)`);
        continue;
      }
      const fresh = PNG.sync.read(shot);
      const baseline = PNG.sync.read(fs.readFileSync(file));
      if (fresh.width !== baseline.width || fresh.height !== baseline.height) {
        failures.push(`${name}-${width}: size ${fresh.width}x${fresh.height} vs ${baseline.width}x${baseline.height}`);
        continue;
      }
      const diff = new PNG({ width: fresh.width, height: fresh.height });
      const pixels = pixelmatch(fresh.data, baseline.data, diff.data, fresh.width, fresh.height, { threshold: 0.1 });
      compared += 1;
      if (pixels > 60) {
        fs.writeFileSync(`/work/shots/visual-${name}-${width}.png`, PNG.sync.write(diff));
        failures.push(`${name}-${width}: ${pixels} pixels differ (see shots/visual-${name}-${width}.png)`);
      }
    }
  }
  if (update) {
    console.log(`visual baselines updated (${compared} compared)`);
    return;
  }
  if (failures.length > 0) throw new Error(`visual changes: ${failures.join("; ")}`);
  console.log(`visual: ${compared} screenshots match`);
});

await step("oidc: log in at the identity provider", async () => {
  await oidcPage.goto(oidcBase + "/me");
  await oidcPage.waitForSelector("input[name=login]");
  await oidcPage.fill("input[name=login]", "olivia@example.com");
  await oidcPage.fill("input[name=password]", "platypus-dev");
  await oidcPage.click("button[type=submit]");
  await oidcPage.waitForURL(oidcBase + "/me");
  await oidcPage.waitForSelector(".user a:has-text('Olivia OIDC')");
  await oidcPage.screenshot({ path: "shots/12-oidc.png", fullPage: true });
}, oidcPage);
await step("oidc: log out", async () => {
  await oidcPage.click("button:has-text('Log out')");
  await oidcPage.waitForURL(oidcBase + "/auth/logged-out");
  await oidcPage.waitForSelector("h1:has-text('You are logged out')");
  // The platypus session is gone: platypus sends the browser to the identity
  // provider again. API requests don't go through the browser's resolver
  // rules, so this calls the same instance by its Docker name.
  const response = await oidcPage.request.get("http://web-oidc:8080/me", { maxRedirects: 0 });
  if (response.status() !== 303 || !response.headers().location.startsWith("/auth/login")) {
    throw new Error(`after logout /me answered ${response.status()} ${response.headers().location}`);
  }
}, oidcPage);

await step("a user without access sees how to get it, and nothing else", async () => {
  const nobody = await context.newPage();
  nobody.on("console", (m) => { if (m.type() === "error") problems.push(`nobody console: ${m.text()}`); });
  await nobody.goto("http://nobody.localhost:8090/ssm");
  await nobody.waitForSelector(".alert:has-text(\"You don't have access to any parameters yet\")");
  if (await nobody.locator("table, form.search-bar").count() > 0) throw new Error("a user without access sees a list");
  await nobody.screenshot({ path: "shots/11-nobody.png", fullPage: true });
});

await browser.close();

// Wrong input on purpose (a wrong token, a binary secret) answers 422; the
// browser logs those. Everything else is a problem.
const expected = /status of 422|Error Code 422 from \/(bootstrap\/token|secrets\/reveal)/;
const unexpected = problems.filter((p) => !expected.test(p));
console.log("\nproblems:", unexpected.length ? "\n" + unexpected.join("\n") : "none");
process.exit(unexpected.length ? 1 : 0);
