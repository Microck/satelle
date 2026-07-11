#!/usr/bin/env node
"use strict";

// Package managers disagree about which satelle bin wins when the unscoped
// package and its canonical dependency are installed together. Keep this
// wrapper behaviorally identical to the canonical bin so either link is safe.
require("@microck/satelle/launcher").main();
