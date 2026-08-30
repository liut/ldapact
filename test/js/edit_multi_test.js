"use strict";

// Unit tests for static/js/edit-multi.js: the document-level click handler
// must only intercept the multi-value "+ Add" buttons (button.add-row), not
// the edit form's "Add attribute" / "Add object class" submit buttons that
// happen to live inside a <div class="add-row"> wrapper.
const assert = require("assert");

let clickHandler = null;

class FakeEl {
  constructor(tag, className, dataset) {
    this.tagName = tag.toUpperCase();
    this.className = className || "";
    this.dataset = dataset || {};
    this.parentElement = null;
    this.children = [];
  }

  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
  }

  insertBefore(child) {
    this.appendChild(child);
  }

  setAttribute() {}

  addEventListener() {}

  focus() {
    this.focused = true;
  }

  closest(selector) {
    let el = this;
    while (el) {
      const classes = el.className.split(/\s+/);
      if (selector === ".add-row" && classes.indexOf("add-row") !== -1) return el;
      if (selector === "button.add-row" && el.tagName === "BUTTON" && classes.indexOf("add-row") !== -1) return el;
      el = el.parentElement;
    }
    return null;
  }
}

// The edit form's Add (attribute / object class) submit button lives inside
// a <div class="add-row"> wrapper alongside its select.
const submitBtn = new FakeEl("button", "secondary");
const wrapper = new FakeEl("div", "add-row");
wrapper.appendChild(submitBtn);

// The multi-value "+ Add" row button keeps the JS behavior (class add-row on
// the button itself, with data-target).
const addRowBtn = new FakeEl("button", "add-row", { target: "f-mail-group", name: "mail" });
const group = new FakeEl("div", "multi-group");

global.document = {
  addEventListener: (type, fn) => {
    clickHandler = fn;
  },
  getElementById: (id) => (id === "f-mail-group" ? group : null),
  createElement: (tag) => new FakeEl(tag),
};

require("../../static/js/edit-multi.js");

function click(el) {
  const prevented = { value: false };
  clickHandler({
    target: el,
    preventDefault: () => {
      prevented.value = true;
    },
  });
  return prevented.value;
}

assert.strictEqual(
  click(submitBtn),
  false,
  "Add attribute / Add object class submit button must not be intercepted"
);
assert.strictEqual(group.children.length, 0, "no row may be added for the submit button");

assert.strictEqual(
  click(addRowBtn),
  true,
  "multi-value add-row button must keep its JS behavior"
);
assert.strictEqual(group.children.length, 1, "addRow must append a new input row");

console.log("edit_multi_test.js: all assertions passed");
