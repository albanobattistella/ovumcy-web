// HIGH gap #2 from the JS coverage audit: the htmx:responseError handler
// installed by web/src/js/app/30-feedback-htmx.js used to assign the raw
// response body via `target.innerHTML = responseText` (the Sprint 3 #9
// finding). The handler now parses the fragment with DOMParser and rebuilds
// the status-error block with `document.createElement` + `textContent` so
// that even a malicious server response cannot inject executable markup.
//
// This test pins that safe-by-construction contract. A future regression
// that switches back to `innerHTML = responseText` would let the assertion
// "no <script> tag survives the swap" fail loudly.

import test from "node:test";
import assert from "node:assert/strict";
import { readAppBundle, loadDOMWithScript } from "./_helpers.mjs";

const APP_BUNDLE = readAppBundle();

const PAGE = `<!doctype html><html><head></head><body>
  <div class="save-status" id="status-target"></div>
</body></html>`;

function fireResponseError(window, responseText) {
  const target = window.document.getElementById("status-target");
  const detail = {
    target,
    xhr: { responseText },
  };
  const event = new window.CustomEvent("htmx:responseError", { detail });
  window.document.body.dispatchEvent(event);
  return target;
}

test("htmx:responseError swap preserves a plain status-error message", async () => {
  const dom = await loadDOMWithScript(APP_BUNDLE, { html: PAGE });
  try {
    const target = fireResponseError(
      dom.window,
      '<div class="status-error">Something went wrong.</div>'
    );

    const node = target.querySelector(".status-error");
    assert.ok(node, "the handler must produce a .status-error node in the target");
    assert.equal(node.textContent, "Something went wrong.", "the message text content is preserved verbatim");
    assert.equal(target.querySelectorAll("script").length, 0);
  } finally {
    dom.window.close();
  }
});

test("htmx:responseError swap strips embedded <script> tags from the response", async () => {
  // This is the load-bearing contract: if the server ever (incorrectly)
  // emitted unescaped HTML inside an error fragment, the OLD innerHTML
  // path would have parsed and executed it. The new path collapses the
  // fragment to its textContent, so <script> becomes literal characters.
  const dom = await loadDOMWithScript(APP_BUNDLE, { html: PAGE });
  try {
    let executed = false;
    dom.window.__unitTestXSSCanary = () => {
      executed = true;
    };

    const target = fireResponseError(
      dom.window,
      `<div class="status-error">prefix<script>window.__unitTestXSSCanary()</script>suffix</div>`
    );

    // Nothing under the target should be a parsed <script> element.
    assert.equal(
      target.querySelectorAll("script").length,
      0,
      "the response swap must not produce live <script> elements"
    );

    // The canary must never have fired. JSDOM does not execute scripts
    // injected via textContent, but if a regression flipped the handler
    // back to innerHTML, the script would be parsed and JSDOM would run
    // it inside `runScripts: "outside-only"` only if dispatched via the
    // <script> innerHTML path; we still check the canary as a belt-and-
    // braces signal.
    assert.equal(executed, false, "no XSS canary may execute regardless of where the safe-swap inserts the content");

    const node = target.querySelector(".status-error");
    assert.ok(node, "a sanitised .status-error block still wraps the message");
    assert.ok(
      node.textContent.includes("prefix") && node.textContent.includes("suffix"),
      "human-visible text from the response is preserved as plain characters"
    );
  } finally {
    dom.window.close();
  }
});

test("htmx:responseError swap strips attribute-based XSS like onerror", async () => {
  const dom = await loadDOMWithScript(APP_BUNDLE, { html: PAGE });
  try {
    const target = fireResponseError(
      dom.window,
      `<div class="status-error"><img src=x onerror="window.__attrXSSFired=true"></div>`
    );
    assert.equal(target.querySelectorAll("img").length, 0, "img elements from the response must not survive the swap");
    assert.equal(dom.window.__attrXSSFired, undefined, "no onerror handler may fire through the swap path");
  } finally {
    dom.window.close();
  }
});

test("htmx:responseError ignores responses that do not look like a status-error fragment", async () => {
  const dom = await loadDOMWithScript(APP_BUNDLE, { html: PAGE });
  try {
    const target = fireResponseError(
      dom.window,
      `<div class="some-other-class">payload</div>`
    );
    // Without the "status-error" marker, the handler delegates to the
    // generic fallback path (renderErrorStatus with a localized "Request
    // failed" message). The point of this test is to lock in that we
    // never blindly innerHTML the response in that branch either.
    assert.equal(target.querySelectorAll("script").length, 0);
    // Generic fallback message wraps a single .status-error div with the
    // page-supplied fallback text. We do not assert the exact text
    // (depends on locale), only that the structure is the safe one.
    const errorNode = target.querySelector(".status-error");
    assert.ok(errorNode, "fallback path still produces a .status-error wrapper");
    assert.ok(errorNode.textContent.length > 0, "fallback path renders some message text");
  } finally {
    dom.window.close();
  }
});
