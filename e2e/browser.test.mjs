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
  await page.locator("label:has-text('Everything for admin') input").check();
  await page.click("button:has-text('Save policies')");
  await page.waitForURL("**/admin/users/1?notice=saved");
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

  await page.locator("label:has-text('Payments group') input").check();
  await page.click("button:has-text('Save policies')");
  await page.waitForURL("**" + teamURL + "?notice=saved");

  // The team page says where members come from and offers no manual changes.
  await page.goto(base + teamURL);
  await page.waitForSelector(".alert.info:has-text('Members come from the identity-provider group')");
  if (await page.locator("#member-search").count()) throw new Error("a linked team offers manual members");
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
  await page.waitForSelector("#audit-results .event-time");
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
  if (!(await page.locator("button:has-text('Edit')").isDisabled())) throw new Error("Edit is not disabled");
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
  await page.waitForSelector("#audit-results .event");
  // Selecting an outcome in the browser swaps the results in place.
  const events = page.locator("#audit-results .event");
  if ((await events.count()) === 0) throw new Error("the audit trail shows no events at all");
  await page.selectOption("#outcome", "allowed");
  await page.waitForSelector("#audit-results .badge.ok");
  await page.selectOption("#outcome", "denied");
  await page.waitForFunction(() => {
    const events = document.querySelectorAll("#audit-results .event");
    return events.length > 0 && [...events].every((e) => e.textContent.includes("denied"));
  }, undefined, { timeout: 5000 }).catch(() => {
    throw new Error("the denied filter shows nothing");
  });
  // Clicking an event line opens the full record; from there its user
  // filters the trail.
  await page.click("#audit-results .event > summary");
  await page.waitForSelector("#audit-results .event[open] .event-body dl");
  await page.click("#audit-results .event[open] a[href*='actor=']");
  await page.waitForSelector("#actor");
  // And the filters can be cleared again.
  await page.click("a:has-text('Clear filters')");
  await page.waitForSelector("#audit-results .event");
  await shot(page, "10b-audit");
});

await step("docs", async () => {
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
  // The audit date is one line, whatever the width.
  await page.goto(base + "/admin/audit");
  await page.waitForSelector("#audit-results .event");
  // The audit header sits exactly above its fields, and long actions are
  // never clipped.
  const auditAligned = await page.evaluate(() => {
    const header = Array.from(document.querySelectorAll("#audit-results .event-columns span"));
    const row = document.querySelector("#audit-results .event-grid");
    const cells = Array.from(row.children);
    return header.every((h, i) => cells[i] && Math.abs(h.getBoundingClientRect().x - cells[i].getBoundingClientRect().x) < 2);
  });
  if (!auditAligned) throw new Error("audit header and fields are not aligned");
  const outcomeAligned = await page.evaluate(() => {
    const textLeft = (el) => {
      const range = document.createRange();
      range.selectNodeContents(el);
      return range.getBoundingClientRect().left;
    };
    const header = Array.from(document.querySelectorAll("#audit-results .event-columns span")).at(-1);
    const badge = document.querySelector("#audit-results .event-grid .badge");
    return { drift: Math.abs(textLeft(header) - textLeft(badge)) };
  });
  if (outcomeAligned.drift >= 2) throw new Error(`the Outcome label sits ${outcomeAligned.drift}px off its badge`);
  const actionFits = await page.evaluate(() => {
    const cell = document.querySelector("#audit-results .event-grid .event-action");
    return cell.scrollWidth <= cell.clientWidth + 1;
  });
  if (!actionFits) throw new Error("the audit action column clips");
  await page.click("#audit-results .event > summary");
  const audit = await page.evaluate(() => {
    const results = document.querySelector("#audit-results");
    const card = results.querySelector(".card");
    const body = results.querySelector(".event-body");
    const json = results.querySelector(".event-json");
    const rect = (el) => (el ? { x: Math.round(el.getBoundingClientRect().x), w: Math.round(el.getBoundingClientRect().width) } : null);
    return {
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      resultsOverflow: results.scrollWidth - results.clientWidth,
      card: rect(card), body: rect(body), json: rect(json),
      cardScroll: card ? card.scrollWidth - card.clientWidth : null,
    };
  });
  if (audit.pageOverflow > 0 || audit.resultsOverflow > 0 || (audit.cardScroll ?? 0) > 0) {
    throw new Error(`audit overflows: ${JSON.stringify(audit)}`);
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
  // Item lists: no overflow, the header sits above its fields, and every row
  // has its way in.
  await page.goto(base + "/ssm");
  await page.waitForSelector("#results .item-grid");
  const items = await page.evaluate(() => {
    const list = document.querySelector("#results");
    const header = Array.from(document.querySelectorAll("#results .item-columns span"));
    const cells = Array.from(document.querySelector("#results .item-grid").children);
    const edit = document.querySelector("#results .item-row > .row-edit");
    const offsets = cells.map((cell, i) => [Math.round(header[i].getBoundingClientRect().x), Math.round(cell.getBoundingClientRect().x)]);
    const editOffset = [Math.round(header.at(-1).getBoundingClientRect().x), Math.round(edit.getBoundingClientRect().x)];
    return {
      overflow: list.scrollWidth - list.clientWidth,
      aligned: offsets.every(([h, c]) => Math.abs(h - c) < 2) && Math.abs(editOffset[0] - editOffset[1]) < 2,
      offsets: [...offsets, editOffset],
    };
  });
  if (items.overflow > 0) throw new Error(`the item list overflows by ${items.overflow}px`);
  if (!items.aligned) throw new Error(`item columns misaligned: ${JSON.stringify(items.offsets)}`);
  if ((await page.locator("#results .row-edit a[href^='/ssm/edit']").count()) === 0) {
    throw new Error("rows have no Edit action");
  }
  // The header's Edit WORD sits exactly above the row's Edit WORD. Comparing
  // the box edges proved nothing: both boxes end at the column edge.
  const editAligned = await page.evaluate(() => {
    const textRight = (el) => {
      const range = document.createRange();
      range.selectNodeContents(el);
      return range.getBoundingClientRect().right;
    };
    const header = document.querySelector("#results .item-columns .head-edit");
    const button = document.querySelector("#results .item-row .row-edit .button");
    return { drift: Math.abs(textRight(header) - textRight(button)) };
  });
  if (editAligned.drift >= 2) throw new Error(`the Edit label sits ${editAligned.drift}px off the Edit button`);
  const sameLine = await page.evaluate(() => {
    const name = document.querySelector("#results .item-name").getBoundingClientRect();
    const button = document.querySelector("#results .item-row .row-edit .button").getBoundingClientRect();
    return { nameTop: name.top, nameBottom: name.bottom, buttonTop: button.top, buttonBottom: button.bottom };
  });
  if (sameLine.buttonTop > sameLine.nameBottom || sameLine.buttonBottom < sameLine.nameTop) {
    throw new Error(`the Edit action is on another line: ${JSON.stringify(sameLine)}`);
  }
  const nested = await page.evaluate(() =>
    document.querySelectorAll("summary a, summary button, summary input, summary select, summary textarea").length);
  if (nested > 0) throw new Error(`${nested} interactive elements are inside a <summary>`);
  // Rows fit their card at every width: nothing paints past its edge.
  for (const width of [1280, 1216, 1152, 1088, 1024, 960, 900]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(base + "/ssm");
    await page.waitForSelector("#results .item-grid");
    const fits = await page.evaluate(() => {
      const card = document.querySelector("#results .card");
      const row = document.querySelector("#results .item-grid");
      const cardBox = card.getBoundingClientRect();
      const outside = [...row.children].filter((cell) => {
        const box = cell.getBoundingClientRect();
        return box.width > 0 && box.right > cardBox.right - 1;
      }).length;
      return { outside, overflow: row.scrollWidth - row.clientWidth };
    });
    if (fits.outside > 0 || fits.overflow > 0) {
      throw new Error(`item rows bleed out of the card at ${width}px: ${JSON.stringify(fits)}`);
    }
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(base + "/ssm");
  await page.waitForSelector("#results .item-grid");

  // The Edit action and the moment must never overlap, whatever the locale.
  const noOverlap = await page.evaluate(() => {
    const row = document.querySelector("#results .item-grid");
    const edit = document.querySelector("#results .item-row > .row-edit").getBoundingClientRect();
    const when = row.querySelector(".event-time").getBoundingClientRect();
    return when.right <= edit.left + 1;
  });
  if (!noOverlap) throw new Error("the Edit action overlaps the timestamp");

  // People lists (users, team members) never overflow their card either.
  await page.goto(base + "/admin/users");
  await page.waitForSelector("#user-list .event");
  const people = await page.evaluate(() => {
    const list = document.querySelector("#user-list");
    return list.scrollWidth - list.clientWidth;
  });
  if (people > 0) throw new Error(`the users list overflows by ${people}px`);

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
