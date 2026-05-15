// HIGH gap #1 from the JS coverage audit: CSRF token injection in the
// `htmx:configRequest` listener installed by web/src/js/app/30-feedback-htmx.js.
// Without this test, a regression that drops the `csrf_token` form parameter
// or the `X-CSRF-Token` header would only surface through whichever
// state-changing e2e happens to also assert on a server-side CSRF rejection.

import test from "node:test";
import assert from "node:assert/strict";
import { readAppBundle, loadDOMWithScript } from "./_helpers.mjs";

const APP_BUNDLE = readAppBundle();

const PAGE_WITH_CSRF_META = `<!doctype html><html><head>
  <meta name="csrf-token" content="csrf-token-abc-123">
</head><body></body></html>`;

const PAGE_WITHOUT_CSRF_META = `<!doctype html><html><head></head><body></body></html>`;

function dispatchConfigRequest(window) {
  const detail = { parameters: {}, headers: {} };
  const event = new window.CustomEvent("htmx:configRequest", { detail });
  window.document.body.dispatchEvent(event);
  return detail;
}

test("htmx:configRequest copies the csrf-token meta into parameters and headers", async () => {
  const dom = await loadDOMWithScript(APP_BUNDLE, { html: PAGE_WITH_CSRF_META });
  try {
    const detail = dispatchConfigRequest(dom.window);
    assert.equal(detail.parameters.csrf_token, "csrf-token-abc-123", "csrf_token form parameter is required for the server's form-field CSRF check");
    assert.equal(detail.headers["X-CSRF-Token"], "csrf-token-abc-123", "X-CSRF-Token header mirrors the parameter so handlers that prefer the header also see the token");
  } finally {
    dom.window.close();
  }
});

test("htmx:configRequest leaves the detail untouched when the meta tag is missing", async () => {
  const dom = await loadDOMWithScript(APP_BUNDLE, { html: PAGE_WITHOUT_CSRF_META });
  try {
    const detail = dispatchConfigRequest(dom.window);
    assert.equal(detail.parameters.csrf_token, undefined, "no token must be injected when the page never rendered a csrf-token meta tag");
    assert.equal(detail.headers["X-CSRF-Token"], undefined, "no header must be injected without a token source");
  } finally {
    dom.window.close();
  }
});

test("htmx:configRequest skips injection when the meta content is empty", async () => {
  // A meta tag with empty content is functionally the same as no meta at
  // all. The listener must not inject an empty token, otherwise the server
  // would see a stub csrf_token="" and reject the request with a less
  // useful "invalid token" error instead of the clear "missing token" path.
  const html = `<!doctype html><html><head>
    <meta name="csrf-token" content="">
  </head><body></body></html>`;
  const dom = await loadDOMWithScript(APP_BUNDLE, { html });
  try {
    const detail = dispatchConfigRequest(dom.window);
    assert.equal(detail.parameters.csrf_token, undefined);
    assert.equal(detail.headers["X-CSRF-Token"], undefined);
  } finally {
    dom.window.close();
  }
});
