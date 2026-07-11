#!/usr/bin/env node
"use strict";

const { main } = require("../lib/launcher.cjs");

module.exports = {
  main,
};

if (require.main === module) {
  main();
}
