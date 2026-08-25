"use strict";

// Unit tests for static/js/autofill.js (R8 autoFill runtime).
const assert = require("assert");

global.window = global;
require("../../static/js/autofill.js");

const { applyTemplate } = global.window.LDAPAutofill;

function expect(actual, want, label) {
  assert.strictEqual(actual, want, label + ": got " + JSON.stringify(actual) + " want " + JSON.stringify(want));
}

// Whole-value token.
expect(applyTemplate("Hello %givenName%!", { givenName: "Alice" }), "Hello Alice!", "plain token");

// Substring slice 0-based, end exclusive.
expect(applyTemplate("%givenName|0-2%", { givenName: "Alice" }), "Al", "slice 0-2");

// Open-ended slice.
expect(applyTemplate("%givenName|2-%", { givenName: "Alice" }), "ice", "slice 2-");

// Negative end counts from the end.
expect(applyTemplate("%givenName|-3%", { givenName: "Alice" }), "ice", "slice -3");

// Case modifiers.
expect(applyTemplate("%givenName|0-2/l%", { givenName: "ALICE" }), "al", "lower modifier");
expect(applyTemplate("%givenName/u%", { givenName: "alice" }), "ALICE", "upper modifier");

// Digits-only modifier.
expect(applyTemplate("%uid/d%", { uid: "ab12cd34" }), "1234", "digits modifier");

// Multiple tokens + literal text.
expect(
  applyTemplate("%givenName/u% %sn%", { givenName: "alice", sn: "Smith" }),
  "ALICE Smith",
  "multi token"
);

// Unknown variable renders empty (no error).
expect(applyTemplate("x%missing%y", {}), "xy", "unknown var");

// Case-insensitive variable lookup.
expect(applyTemplate("%GIVENNAME%", { givenName: "Bob" }), "Bob", "case-insensitive lookup");

// Code-point-safe slicing with U modifier (astral character).
expect(applyTemplate("%emoji|0-1/U%", { emoji: "😀x" }), "😀", "unicode slice keeps astral pair");

console.log("autofill_test.js: all assertions passed");
