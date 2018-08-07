

// /home/admin/funfuzz/js/jsfunfuzz/preamble.js

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* jshint moz:true, evil:true, sub:true, maxerr:10000 */
//"use strict";
var jsStrictMode = false;


// /home/admin/funfuzz/js/jsfunfuzz/detect-engine.js

// jsfunfuzz is best run in a command-line shell.  It can also run in
// a web browser, but you might have trouble reproducing bugs that way.

var ENGINE_UNKNOWN = 0;
var ENGINE_SPIDERMONKEY_TRUNK = 1;
var ENGINE_SPIDERMONKEY_MOZILLA45 = 3;
var ENGINE_JAVASCRIPTCORE = 4;

var engine = ENGINE_UNKNOWN;
var jsshell = (typeof window == "undefined");
var xpcshell = jsshell && (typeof Components == "object");
var dump;
var dumpln;
var printImportant;
if (jsshell) {
  dumpln = print;
  printImportant = function(s) { dumpln("***"); dumpln(s); };
  if (typeof verifyprebarriers == "function") {
    // Run a diff between the help() outputs of different js shells.
    // Make sure the function to look out for is not located only in some
    // particular #ifdef, e.g. JS_GC_ZEAL, or controlled by --fuzzing-safe.
    if (typeof wasmIsSupported == "function") {
      engine = ENGINE_SPIDERMONKEY_TRUNK;
    } else {
      engine = ENGINE_SPIDERMONKEY_MOZILLA45;
    }

    // Avoid accidentally waiting for user input that will never come.
    readline = function(){};

    // 170: make "yield" and "let" work. 180: better for..in behavior.
    version(180);
  } else if (typeof XPCNativeWrapper == "function") {
    // e.g. xpcshell or firefox
    engine = ENGINE_SPIDERMONKEY_TRUNK;
  } else if (typeof debug == "function") {
    engine = ENGINE_JAVASCRIPTCORE;
  }
} else {
  if (navigator.userAgent.indexOf("WebKit") != -1) {
    // XXX detect Google Chrome for V8
    engine = ENGINE_JAVASCRIPTCORE;
    // This worked in Safari 3.0, but it might not work in Safari 3.1.
    dump = function(s) { console.log(s); };
  } else if (navigator.userAgent.indexOf("Gecko") != -1) {
    engine = ENGINE_SPIDERMONKEY_TRUNK;
  } else if (typeof dump != "function") {
    // In other browsers, jsfunfuzz does not know how to log anything.
    dump = function() { };
  }
  dumpln = function(s) { dump(s + "\n"); };

  printImportant = function(s) {
    dumpln(s);
    var p = document.createElement("pre");
    p.appendChild(document.createTextNode(s));
    document.body.appendChild(p);
  };
}

if (typeof gc == "undefined")
  this.gc = function(){};
var gcIsQuiet = !(gc()); // see bug 706433

// If the JavaScript engine being tested has heuristics like
//   "recompile any loop that is run more than X times"
// this should be set to the highest such X.
var HOTLOOP = 60;
function loopCount() { return rnd(rnd(HOTLOOP * 3)); }
function loopModulo() { return (rnd(2) ? rnd(rnd(HOTLOOP * 2)) : rnd(5)) + 2; }

function simpleSource(s)
{
  function hexify(c)
  {
    var code = c.charCodeAt(0);
    var hex = code.toString(16);
    while (hex.length < 4)
      hex = "0" + hex;
    return "\\u" + hex;
  }

  if (typeof s == "string")
    return ("\"" +
      s.replace(/\\/g, "\\\\")
       .replace(/\"/g, "\\\"")
       .replace(/\0/g, "\\0")
       .replace(/\n/g, "\\n")
       .replace(/[^ -~]/g, hexify) + // not space (32) through tilde (126)
      "\"");
  else
    return "" + s; // hope this is right ;)  should work for numbers.
}

var haveRealUneval = (typeof uneval == "function");
if (!haveRealUneval)
  uneval = simpleSource;

if (engine == ENGINE_UNKNOWN)
  printImportant("Targeting an unknown JavaScript engine!");
else if (engine == ENGINE_SPIDERMONKEY_TRUNK)
  printImportant("Targeting SpiderMonkey / Gecko (trunk).");
else if (engine == ENGINE_SPIDERMONKEY_MOZILLA45)
  printImportant("Targeting SpiderMonkey / Gecko (ESR45 branch).");
else if (engine == ENGINE_JAVASCRIPTCORE)
  printImportant("Targeting JavaScriptCore / WebKit.");


// /home/admin/funfuzz/js/jsfunfuzz/avoid-known-bugs.js

function whatToTestSpidermonkeyTrunk(code)
{
  /* jshint laxcomma: true */
  // regexps can't match across lines, so replace whitespace with spaces.
  var codeL = code.replace(/\s/g, " ");

  return {

    allowParse: true,

    allowExec: unlikelyToHang(code)
      && (jsshell || code.indexOf("nogeckoex") == -1)
    ,

    allowIter: true,

    // Ideally we'd detect whether the shell was compiled with --enable-more-deterministic
    // Ignore both within-process & across-process, e.g. nestTest mismatch & compareJIT
    expectConsistentOutput: true
       && (gcIsQuiet || code.indexOf("gc") == -1)
       && code.indexOf("/*NODIFF*/") == -1                // Ignore diff testing on these labels
       && code.indexOf(".script") == -1                   // Debugger; see bug 1237464
       && code.indexOf(".parameterNames") == -1           // Debugger; see bug 1237464
       && code.indexOf(".environment") == -1              // Debugger; see bug 1237464
       && code.indexOf(".onNewGlobalObject") == -1        // Debugger; see bug 1238246
       && code.indexOf(".takeCensus") == -1               // Debugger; see bug 1247863
       && code.indexOf(".findScripts") == -1              // Debugger; see bug 1250863
       && code.indexOf("Date") == -1                      // time marches on
       && code.indexOf("backtrace") == -1                 // shows memory addresses
       && code.indexOf("drainAllocationsLog") == -1       // drainAllocationsLog returns an object with a timestamp, see bug 1066313
       && code.indexOf("dumpObject") == -1                // shows heap addresses
       && code.indexOf("dumpHeap") == -1                  // shows heap addresses
       && code.indexOf("dumpStringRepresentation") == -1  // shows memory addresses
       && code.indexOf("evalInWorker") == -1              // causes diffs in --no-threads vs --ion-offthread-compile=off
       && code.indexOf("getBacktrace") == -1              // getBacktrace returns memory addresses which differs depending on flags
       && code.indexOf("getLcovInfo") == -1
       && code.indexOf("load") == -1                      // load()ed regression test might output dates, etc
       && code.indexOf("offThreadCompileScript") == -1    // causes diffs in --no-threads vs --ion-offthread-compile=off
       && code.indexOf("oomAfterAllocations") == -1
       && code.indexOf("oomAtAllocation") == -1
       && code.indexOf("printProfilerEvents") == -1       // causes diffs in --ion-eager vs --baseline-eager
       && code.indexOf("promiseID") == -1                 // Promise IDs are for debugger-use only
       && code.indexOf("runOffThreadScript") == -1
       && code.indexOf("shortestPaths") == -1             // See bug 1308743
       && code.indexOf("inIon") == -1                     // may become true after several iterations, or return a string with --no-ion
       && code.indexOf("inJit") == -1                     // may become true after several iterations, or return a string with --no-baseline
       && code.indexOf("random") == -1
       && code.indexOf("timeout") == -1                   // time runs and crawls
    ,

    expectConsistentOutputAcrossIter: true
    // within-process, e.g. ignore the following items for nestTest mismatch
       && code.indexOf("options") == -1             // options() is per-cx, and the js shell doesn't create a new cx for each sandbox/compartment
    ,

    expectConsistentOutputAcrossJITs: true
    // across-process (e.g. running js shell with different run-time options) e.g. compareJIT
       && code.indexOf("isAsmJSCompilationAvailable") == -1  // Causes false positives with --no-asmjs
       && code.indexOf("'strict") == -1                      // see bug 743425
       && code.indexOf("disassemble") == -1                  // see bug 1237403 (related to asm.js)
       && code.indexOf("sourceIsLazy") == -1                 // see bug 1286407
       && code.indexOf("getAllocationMetadata") == -1        // see bug 1296243
       && code.indexOf(".length") == -1                      // bug 1027846
       && !( codeL.match(/\/.*[\u0000\u0080-\uffff]/))       // doesn't stay valid utf-8 after going through python (?)

  };
}

function whatToTestSpidermonkeyMozilla45(code)
{
  /* jshint laxcomma: true */
  // regexps can't match across lines, so replace whitespace with spaces.
  var codeL = code.replace(/\s/g, " ");

  return {

    allowParse: true,

    allowExec: unlikelyToHang(code)
      && (jsshell || code.indexOf("nogeckoex") == -1)
    ,

    allowIter: true,

    // Ideally we'd detect whether the shell was compiled with --enable-more-deterministic
    // Ignore both within-process & across-process, e.g. nestTest mismatch & compareJIT
    expectConsistentOutput: true
       && (gcIsQuiet || code.indexOf("gc") == -1)
       && code.indexOf("/*NODIFF*/") == -1                // Ignore diff testing on these labels
       && code.indexOf(".script") == -1                   // Debugger; see bug 1237464
       && code.indexOf(".parameterNames") == -1           // Debugger; see bug 1237464
       && code.indexOf(".environment") == -1              // Debugger; see bug 1237464
       && code.indexOf(".onNewGlobalObject") == -1        // Debugger; see bug 1238246
       && code.indexOf(".takeCensus") == -1               // Debugger; see bug 1247863
       && code.indexOf(".findScripts") == -1              // Debugger; see bug 1250863
       && code.indexOf("Date") == -1                      // time marches on
       && code.indexOf("backtrace") == -1                 // shows memory addresses
       && code.indexOf("drainAllocationsLog") == -1       // drainAllocationsLog returns an object with a timestamp, see bug 1066313
       && code.indexOf("dumpObject") == -1                // shows heap addresses
       && code.indexOf("dumpHeap") == -1                  // shows heap addresses
       && code.indexOf("dumpStringRepresentation") == -1  // shows memory addresses
       && code.indexOf("evalInWorker") == -1              // causes diffs in --no-threads vs --ion-offthread-compile=off
       && code.indexOf("getBacktrace") == -1              // getBacktrace returns memory addresses which differs depending on flags
       && code.indexOf("getLcovInfo") == -1
       && code.indexOf("load") == -1                      // load()ed regression test might output dates, etc
       && code.indexOf("offThreadCompileScript") == -1    // causes diffs in --no-threads vs --ion-offthread-compile=off
       && code.indexOf("oomAfterAllocations") == -1
       && code.indexOf("oomAtAllocation") == -1
       && code.indexOf("printProfilerEvents") == -1       // causes diffs in --ion-eager vs --baseline-eager
       && code.indexOf("validategc") == -1
       && code.indexOf("inIon") == -1                     // may become true after several iterations, or return a string with --no-ion
       && code.indexOf("inJit") == -1                     // may become true after several iterations, or return a string with --no-baseline
       && code.indexOf("random") == -1
       && code.indexOf("timeout") == -1                   // time runs and crawls
    ,

    expectConsistentOutputAcrossIter: true
    // within-process, e.g. ignore the following items for nestTest mismatch
       && code.indexOf("options") == -1             // options() is per-cx, and the js shell doesn't create a new cx for each sandbox/compartment
    ,

    expectConsistentOutputAcrossJITs: true
    // across-process (e.g. running js shell with different run-time options) e.g. compareJIT
        && code.indexOf("'strict") == -1                 // see bug 743425
        && code.indexOf("disassemble") == -1             // see bug 1237403 (related to asm.js)
        && code.indexOf(".length") == -1                 // bug 1027846
        && code.indexOf("preventExtensions") == -1       // bug 1085299
        && code.indexOf("Math.round") == -1              // see bug 1236114 - ESR45 only
        && code.indexOf("with") == -1                    // see bug 1245187 - ESR45 only
        && code.indexOf("Number.MAX_VALUE") == -1        // see bug 1246200 - ESR45 only
        && code.indexOf("bailAfter") == -1               // see bug 1256324 - ESR45 only, bailAfter does not exist in ESR45
        && code.indexOf("arguments") == -1               // see bug 1263811 - ESR45 only
        && code.indexOf("sourceIsLazy") == -1            // see bug 1286407
        && !( codeL.match(/\/.*[\u0000\u0080-\uffff]/))  // doesn't stay valid utf-8 after going through python (?)

  };
}

function whatToTestJavaScriptCore(code)
{
  return {

    allowParse: true,
    allowExec: unlikelyToHang(code),
    allowIter: false, // JavaScriptCore does not support |yield| and |Iterator|
    expectConsistentOutput: false,
    expectConsistentOutputAcrossIter: false,
    expectConsistentOutputAcrossJITs: false

  };
}

function whatToTestGeneric(code)
{
  return {
    allowParse: true,
    allowExec: unlikelyToHang(code),
    allowIter: (typeof Iterator == "function"),
    expectConsistentOutput: false,
    expectConsistentOutputAcrossIter: false,
    expectConsistentOutputAcrossJITs: false
  };
}

var whatToTest;
if (engine == ENGINE_SPIDERMONKEY_TRUNK)
  whatToTest = whatToTestSpidermonkeyTrunk;
else if (engine == ENGINE_SPIDERMONKEY_MOZILLA45)
  whatToTest = whatToTestSpidermonkeyMozilla45;
else if (engine == ENGINE_JAVASCRIPTCORE)
  whatToTest = whatToTestJavaScriptCore;
else
  whatToTest = whatToTestGeneric;


function unlikelyToHang(code)
{
  var codeL = code.replace(/\s/g, " ");

  // Things that are likely to hang in all JavaScript engines
  return true
    && code.indexOf("infloop") == -1
    && !( codeL.match( /for.*in.*uneval/ )) // can be slow to loop through the huge string uneval(this), for example
    && !( codeL.match( /for.*for.*for/ )) // nested for loops (including for..in, array comprehensions, etc) can take a while
    && !( codeL.match( /for.*for.*gc/ ))
    ;
}


// /home/admin/funfuzz/js/jsfunfuzz/error-reporting.js

function confused(s)
{
  if (jsshell) {
    // Magic string that jsInteresting.py looks for
    print("jsfunfuzz broke its own scripting environment: " + s);
    quit();
  }
}

function foundABug(summary, details)
{
  // Magic pair of strings that jsInteresting.py looks for
  // Break up the following string so internal js functions do not print it deliberately
  printImportant("Found" + " a bug: " + summary);
  if (details) {
    printImportant(details);
  }
  if (jsshell) {
    dumpln("jsfunfuzz stopping due to finding a bug.");
    quit();
  }
}

function errorToString(e)
{
  try {
    return ("" + e);
  } catch (e2) {
    return "Can't toString the error!!";
  }
}

function errorstack()
{
  print("EEE");
  try {
    void ([].qwerty.qwerty);
  } catch(e) { print(e.stack); }
}


// /home/admin/funfuzz/js/shared/random.js

var Random = {
  twister: null,

  init: function (seed) {
    if (seed == null || seed === undefined) {
      seed = new Date().getTime();
    }
    this.twister = new MersenneTwister19937();
    this.twister.seed(seed);
  },
  number: function (limit) {
    // Returns an integer in [0, limit). Uniform distribution.
    if (limit == 0) {
      return limit;
    }
    if (limit == null || limit === undefined) {
      limit = 0xffffffff;
    }
    return (Random.twister.int32() >>> 0) % limit;
  },
  float: function () {
    // Returns a float in [0, 1]. Uniform distribution.
    return (Random.twister.int32() >>> 0) * (1.0/4294967295.0);
  },
  range: function (start, limit) {
    // Returns an integer in [start, limit]. Uniform distribution.
    if (isNaN(start) || isNaN(limit)) {
      Utils.traceback();
      throw new TypeError("Random.range() received a non number type: '" + start + "', '" + limit + "')");
    }
    return Random.number(limit - start + 1) + start;
  },
  ludOneTo: function(limit) {
    // Returns a float in [1, limit]. The logarithm has uniform distribution.
    return Math.exp(Random.float() * Math.log(limit));
  },
  index: function (list, emptyr) {
    if (!(list instanceof Array || (typeof list != "string" && "length" in list))) {
      Utils.traceback();
      throw new TypeError("Random.index() received a non array type: '" + list + "'");
    }
    if (!list.length)
      return emptyr;
    return list[this.number(list.length)];
  },
  key: function (obj) {
    var list = [];
    for (var i in obj) {
      list.push(i);
    }
    return this.index(list);
  },
  bool: function () {
    return this.index([true, false]);
  },
  pick: function (obj) {
    if (typeof obj == "function") {
      return obj();
    }
    if (obj instanceof Array) {
      return this.pick(this.index(obj));
    }
    return obj;
  },
  chance: function (limit) {
    if (limit == null || limit === undefined) {
      limit = 2;
    }
    if (isNaN(limit)) {
      Utils.traceback();
      throw new TypeError("Random.chance() received a non number type: '" + limit + "'");
    }
    return this.number(limit) == 1;
  },
  choose: function (list, flat) {
    if (!(list instanceof Array)) {
      Utils.traceback();
      throw new TypeError("Random.choose() received a non-array type: '" + list + "'");
    }
    var total = 0;
    for (var i = 0; i < list.length; i++) {
      total += list[i][0];
    }
    var n = this.number(total);
    for (var i = 0; i < list.length; i++) {
      if (n < list[i][0]) {
        if (flat == true) {
          return list[i][1];
        } else {
          return this.pick([list[i][1]]);
        }
      }
      n = n - list[i][0];
    }
    if (flat == true) {
      return list[0][1];
    }
    return this.pick([list[0][1]]);
  },
  weighted: function (wa) {
    // More memory-hungry but hopefully faster than Random.choose$flat
    var a = [];
    for (var i = 0; i < wa.length; ++i) {
      for (var j = 0; j < wa[i].w; ++j) {
        a.push(wa[i].v);
      }
    }
    return a;
  },
  use: function (obj) {
    return Random.bool() ? obj : "";
  },
  shuffle: function (arr) {
    var len = arr.length;
    var i = len;
    while (i--) {
      var p = Random.number(i + 1);
      var t = arr[i];
      arr[i] = arr[p];
      arr[p] = t;
    }
  },
  shuffled: function (arr) {
    var newArray = arr.slice();
    Random.shuffle(newArray);
    return newArray;
  },
  subset: function(a) {
    // TODO: shuffle, repeat, include bogus things [see also https://github.com/mozilla/rust/blob/d0ddc69298c41df04b0488d91d521eb531d79177/src/fuzzer/ivec_fuzz.rs]
    // Consider adding a weight argument, or swarming on inclusion/exclusion to make 'all' and 'none' more likely
    var subset = [];
    for (var i = 0; i < a.length; ++i) {
      if (rnd(2)) {
        subset.push(a[i]);
      }
    }
    return subset;
  },

};

function rnd(n) { return Random.number(n); }


// /home/admin/funfuzz/js/shared/mersenne-twister.js

// this program is a JavaScript version of Mersenne Twister, with concealment and encapsulation in class,
// an almost straight conversion from the original program, mt19937ar.c,
// translated by y. okada on July 17, 2006.

// Changes by Jesse Ruderman:
//   * Use intish/int32 rather than uint32 for intermediate calculations
//     (see https://bugzilla.mozilla.org/show_bug.cgi?id=883748#c1)
//   * Added functions for exporting/importing the entire PRNG state
//   * Removed parts not needed for fuzzing

// in this program, procedure descriptions and comments of original source code were not removed.
// lines commented with //c// were originally descriptions of c procedure. and a few following lines are appropriate JavaScript descriptions.
// lines commented with /* and */ are original comments.
// lines commented with // are additional comments in this JavaScript version.
// before using this version, create at least one instance of MersenneTwister19937 class, and initialize the each state, given below in c comments, of all the instances.

/*
   A C-program for MT19937, with initialization improved 2002/1/26.
   Coded by Takuji Nishimura and Makoto Matsumoto.

   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

     3. The names of its contributors may not be used to endorse or promote
        products derived from this software without specific prior written
        permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


   Any feedback is very welcome.
   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
   email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
*/


function MersenneTwister19937()
{
  const N = 624;
  const M = 397;
  const MAG01 = new Int32Array([0, 0x9908b0df]);

  var mt = new Int32Array(N);   /* the array for the state vector */
  var mti = 625;

  this.seed = function (s) {
    mt[0] = s | 0;
    for (mti=1; mti<N; mti++) {
      mt[mti] = Math.imul(1812433253, mt[mti-1] ^ (mt[mti-1] >>> 30)) + mti;
    }
  };

  this.export_state = function() { return [mt, mti]; };
  this.import_state = function(s) { mt = s[0]; mti = s[1]; };
  this.export_mta = function() { return mt; };
  this.import_mta = function(_mta) { mt = _mta; };
  this.export_mti = function() { return mti; };
  this.import_mti = function(_mti) { mti = _mti; };

  function mag01(y)
  {
    return MAG01[y & 0x1];
  }

  this.int32 = function () {
    var y;
    var kk;

    if (mti >= N) { /* generate N words at one time */
      for (kk=0;kk<N-M;kk++) {
        y = ((mt[kk]&0x80000000)|(mt[kk+1]&0x7fffffff));
        mt[kk] = (mt[kk+M] ^ (y >>> 1) ^ mag01(y));
      }
      for (;kk<N-1;kk++) {
        y = ((mt[kk]&0x80000000)|(mt[kk+1]&0x7fffffff));
        mt[kk] = (mt[kk+(M-N)] ^ (y >>> 1) ^ mag01(y));
      }
      y = ((mt[N-1]&0x80000000)|(mt[0]&0x7fffffff));
      mt[N-1] = (mt[M-1] ^ (y >>> 1) ^ mag01(y));
      mti = 0;
    }

    y = mt[mti++];

    /* Tempering */
    y = y ^ (y >>> 11);
    y = y ^ ((y << 7) & 0x9d2c5680);
    y = y ^ ((y << 15) & 0xefc60000);
    y = y ^ (y >>> 18);

    return y;
  };
}


// /home/admin/funfuzz/js/shared/testing-functions.js

// Generate calls to SpiderMonkey "testing functions" for:
// * testing that they do not cause assertions/crashes
// * testing that they do not alter visible results (compareJIT with and without the call)

function fuzzTestingFunctionsCtor(browser, fGlobal, fObject)
{
  var prefix = browser ? "fuzzPriv." : "";

  function numberOfInstructions() { return Math.floor(Random.ludOneTo(10000)); }
  function numberOfAllocs() { return Math.floor(Random.ludOneTo(500)); }
  function gcSliceSize() { return Math.floor(Random.ludOneTo(0x100000000)); }
  function maybeCommaShrinking() { return rnd(5) ? "" : ", 'shrinking'"; }

  function enableGCZeal()
  {
    var level = rnd(17);
    if (browser && level == 9) level = 0; // bug 815241
    var period = numberOfAllocs();
    return prefix + "gczeal" + "(" + level + ", " + period + ");";
  }

  function callSetGCCallback() {
    // https://dxr.mozilla.org/mozilla-central/source/js/src/shell/js.cpp - SetGCCallback
    var phases = Random.index(["both", "begin", "end"]);
    var actionAndOptions = rnd(2) ? 'action: "majorGC", depth: ' + rnd(17) : 'action: "minorGC"';
    var arg = "{ " + actionAndOptions + ", phases: \"" + phases + "\" }";
    return prefix + "setGCCallback(" + arg + ");";
  }

  function tryCatch(statement)
  {
    return "try { " + statement + " } catch(e) { }";
  }

  function setGcparam() {
    switch(rnd(2)) {
      case 0:  return _set("sliceTimeBudget", rnd(100));
      default: return _set("markStackLimit", rnd(2) ? (1 + rnd(30)) : 4294967295); // Artificially trigger delayed marking
    }

    function _set(name, value) {
      // try..catch because gcparam sets may throw, depending on GC state (see bug 973571)
      return tryCatch(prefix + "gcparam" + "('" + name + "', " + value + ");");
    }
  }

  // Functions shared between the SpiderMonkey shell and Firefox browser
  // https://mxr.mozilla.org/mozilla-central/source/js/src/builtin/TestingFunctions.cpp
  var sharedTestingFunctions = [
    // Force garbage collection (global or specific compartment)
    { w: 10, v: function(d, b) { return "void " + prefix + "gc" + "("                                            + ");"; } },
    { w: 10, v: function(d, b) { return "void " + prefix + "gc" + "(" + "'compartment'" + maybeCommaShrinking() + ");"; } },
    { w: 5,  v: function(d, b) { return "void " + prefix + "gc" + "(" + fGlobal(d, b)   + maybeCommaShrinking() + ");"; } },

    // Run a minor garbage collection on the nursery.
    { w: 20, v: function(d, b) { return prefix + "minorgc" + "(false);"; } },
    { w: 20, v: function(d, b) { return prefix + "minorgc" + "(true);"; } },

    // Start, continue, or abort incremental garbage collection.
    // startgc can throw: "Incremental GC already in progress"
    { w: 20, v: function(d, b) { return tryCatch(prefix + "startgc" + "(" + gcSliceSize() + maybeCommaShrinking() + ");"); } },
    { w: 20, v: function(d, b) { return prefix + "gcslice" + "(" + gcSliceSize() + ");"; } },
    { w: 10, v: function(d, b) { return prefix + "abortgc" + "(" + ");"; } },

    // Schedule the given objects to be marked in the next GC slice.
    { w: 10, v: function(d, b) { return prefix + "selectforgc" + "(" + fObject(d, b) + ");"; } },

    // Add a compartment to the next garbage collection.
    { w: 10, v: function(d, b) { return "void " + prefix + "schedulegc" + "(" + fGlobal(d, b) + ");"; } },

    // Schedule a GC for after N allocations.
    { w: 10, v: function(d, b) { return "void " + prefix + "schedulegc" + "(" + numberOfAllocs() + ");"; } },

    // Change a GC parameter.
    { w: 10, v: setGcparam },

    // Verify write barriers. This functions is effective in pairs.
    // The first call sets up the start barrier, the second call sets up the end barrier.
    // Nothing happens when there is only one call.
    { w: 10, v: function(d, b) { return prefix + "verifyprebarriers" + "();"; } },

    // hasChild(parent, child): Return true if |child| is a child of |parent|, as determined by a call to TraceChildren.
    // We ignore the return value because hasChild can be used to see which WeakMap entries have been GCed.
    { w: 1,  v: function(d, b) { return "void " + prefix + "hasChild(" + fObject(d, b) + ", " + fObject(d, b) + ");"; } },

    // Various validation functions (toggles)
    { w: 5,  v: function(d, b) { return prefix + "validategc" + "(false);"; } },
    { w: 1,  v: function(d, b) { return prefix + "validategc" + "(true);"; } },
    { w: 5,  v: function(d, b) { return prefix + "fullcompartmentchecks" + "(false);"; } },
    { w: 1,  v: function(d, b) { return prefix + "fullcompartmentchecks" + "(true);"; } },
    { w: 5,  v: function(d, b) { return prefix + "setIonCheckGraphCoherency" + "(false);"; } },
    { w: 1,  v: function(d, b) { return prefix + "setIonCheckGraphCoherency" + "(true);"; } },
    { w: 1,  v: function(d, b) { return prefix + "enableOsiPointRegisterChecks" + "();"; } },

    // Various validation functions (immediate)
    { w: 1,  v: function(d, b) { return prefix + "assertJitStackInvariants" + "();"; } },

    // Run-time equivalents to --baseline-eager, --baseline-warmup-threshold, --ion-eager, --ion-warmup-threshold
    { w: 1,  v: function(d, b) { return prefix + "setJitCompilerOption" + "('baseline.warmup.trigger', " + rnd(20) + ");"; } },
    { w: 1,  v: function(d, b) { return prefix + "setJitCompilerOption" + "('ion.warmup.trigger', " + rnd(40) + ");"; } },

    // Force inline cache.
    { w: 1,  v: function(d, b) { return prefix + "setJitCompilerOption" + "('ion.forceinlineCaches\', " + rnd(2) + ");"; } },

    // Run-time equivalents to --no-ion, --no-baseline
    // These can throw: "Can't turn off JITs with JIT code on the stack."
    { w: 1,  v: function(d, b) { return tryCatch(prefix + "setJitCompilerOption" + "('ion.enable', " + rnd(2) + ");"); } },
    { w: 1,  v: function(d, b) { return tryCatch(prefix + "setJitCompilerOption" + "('baseline.enable', " + rnd(2) + ");"); } },

    // Test the built-in profiler.
    { w: 1,  v: function(d, b) { return prefix + "enableSPSProfiling" + "();"; } },
    { w: 1,  v: function(d, b) { return prefix + "enableSPSProfilingWithSlowAssertions" + "();"; } },
    { w: 5,  v: function(d, b) { return prefix + "disableSPSProfiling" + "();"; } },
    { w: 1,  v: function(d, b) { return "void " + prefix + "readSPSProfilingStack" + "();"; } },

    // I'm not sure what this does in the shell.
    { w: 5,  v: function(d, b) { return prefix + "deterministicgc" + "(false);"; } },
    { w: 1,  v: function(d, b) { return prefix + "deterministicgc" + "(true);"; } },

    // Causes JIT code to always be preserved by GCs afterwards (see https://bugzilla.mozilla.org/show_bug.cgi?id=750834)
    { w: 5,  v: function(d, b) { return prefix + "gcPreserveCode" + "();"; } },

    // Generate an LCOV trace (but throw away the returned string)
    { w: 1,  v: function(d, b) { return "void " + prefix + "getLcovInfo" + "();"; } },
    { w: 1,  v: function(d, b) { return "void " + prefix + "getLcovInfo" + "(" + fGlobal(d, b) + ");"; } },

    // JIT bailout
    { w: 5,  v: function(d, b) { return prefix + "bailout" + "();"; } },
    { w: 10, v: function(d, b) { return prefix + "bailAfter" + "(" + numberOfInstructions() + ");"; } },
  ];

  // Functions only in the SpiderMonkey shell
  // https://mxr.mozilla.org/mozilla-central/source/js/src/shell/js.cpp
  var shellOnlyTestingFunctions = [
    // ARM simulator settings
    // These throw when not in the ARM simulator.
    { w: 1,  v: function(d, b) { return tryCatch("(void" + prefix + "disableSingleStepProfiling" + "()" + ")"); } },
    { w: 1,  v: function(d, b) { return tryCatch("(" + prefix + "enableSingleStepProfiling" + "()" + ")"); } },

    // Force garbage collection with function relazification
    { w: 10, v: function(d, b) { return "void " + prefix + "relazifyFunctions" + "();"; } },
    { w: 10, v: function(d, b) { return "void " + prefix + "relazifyFunctions" + "('compartment');"; } },
    { w: 5,  v: function(d, b) { return "void " + prefix + "relazifyFunctions" + "(" + fGlobal(d, b) + ");"; } },

    // [TestingFunctions.cpp, but debug-only and CRASHY]
    // After N js_malloc memory allocations, fail every following allocation
    { w: 1,  v: function(d, b) { return (typeof oomAfterAllocations == "function" && rnd(1000) === 0) ? prefix + "oomAfterAllocations" + "(" + (numberOfAllocs() - 1) + ");" : "void 0;"; } },
    // After N js_malloc memory allocations, fail one allocation
    { w: 1,  v: function(d, b) { return (typeof oomAtAllocation == "function" && rnd(100) === 0) ? prefix + "oomAtAllocation" + "(" + (numberOfAllocs() - 1) + ");" : "void 0;"; } },
    // Reset either of the above
    { w: 1,  v: function(d, b) { return (typeof resetOOMFailure == "function") ? "void " + prefix + "resetOOMFailure" + "(" + ");" : "void 0;"; } },

    // [TestingFunctions.cpp, but SLOW]
    // Make garbage collection extremely frequent
    { w: 1,  v: function(d, b) { return (rnd(100) === 0) ? (enableGCZeal()) : "void 0;"; } },

    { w: 10, v: callSetGCCallback },
  ];

  var testingFunctions = Random.weighted(browser ? sharedTestingFunctions : sharedTestingFunctions.concat(shellOnlyTestingFunctions));

  return { testingFunctions: testingFunctions, enableGCZeal: enableGCZeal };
}


// /home/admin/funfuzz/js/jsfunfuzz/built-in-constructors.js

/*
        It might be more interesting to use Object.getOwnPropertyDescriptor to find out if
        a thing is exposed as a getter (like Debugger.prototype.enabled).  But there are exceptions:

        <Jesse> why is Array.prototype.length not a getter? http://pastebin.mozilla.org/1990723
        <jorendorff> backward compatibility
        <jorendorff> ES3 already allowed programs to create objects with arbitrary __proto__
        <jorendorff> .length was specified to work as a data property; accessor properties inherit differently, especially when setting
        <jorendorff> maybe only when setting, come to think of it
        <jorendorff> I guess it could've been made an accessor property without breaking anything important. I didn't realize it at the time.
*/

var constructors = []; // "Array"
var builtinFunctions = []; // "Array.prototype.sort"
var builtinProperties = []; // "Array", "Array.prototype", "Array.prototype.length"
var allMethodNames = []; // "sort"
var allPropertyNames = []; // "length"

var builtinObjectNames = []; // "Array", "Array.prototype", ... (indexes into the builtinObjects)
var builtinObjects = {}; // { "Array.prototype": ["sort", "length", ...], ... }

(function exploreBuiltins(glob, debugMode) {

  function exploreDeeper(a, an)
  {
    if (!a)
      return;
    var hns = Object.getOwnPropertyNames(a);
    var propertyNames = [];
    for (var j = 0; j < hns.length; ++j) {
      var hn = hns[j];
      propertyNames.push(hn);
      allPropertyNames.push(hn);

      var fullName = an + "." + hn;
      builtinProperties.push(fullName);

      var h;
      try {
        h = a[hn];
      } catch(e) {
        if (debugMode) {
          dumpln("Threw: " + fullName);
        }
        h = null;
      }

      if (typeof h == "function" && hn != "constructor") {
        allMethodNames.push(hn);
        builtinFunctions.push(fullName);
      }
    }
    builtinObjects[an] = propertyNames;
    builtinObjectNames.push(an);
  }

  function exploreConstructors()
  {
    var gns = Object.getOwnPropertyNames(glob);
    for (var i = 0; i < gns.length; ++i) {
      var gn = gns[i];
      // Assume that most uppercase names are constructors.
      // Skip Worker in shell (removed in bug 771281).
      if (0x40 < gn.charCodeAt(0) && gn.charCodeAt(0) < 0x60 && gn != "PerfMeasurement" && !(jsshell && gn == "Worker")) {
        var g = glob[gn];
        if (typeof g == "function" && g.toString().indexOf("[native code]") != -1) {
          constructors.push(gn);
          builtinProperties.push(gn);
          builtinFunctions.push(gn);
          exploreDeeper(g, gn);
          exploreDeeper(g.prototype, gn + ".prototype");
        }
      }
    }
  }

  exploreConstructors();

  exploreDeeper(Math, "Math");
  exploreDeeper(JSON, "JSON");
  exploreDeeper(Proxy, "Proxy");

  if (debugMode) {
    for (let x of constructors) print("^^^^^ " + x);
    for (let x of builtinProperties) print("***** " + x);
    for (let x of builtinFunctions) print("===== " + x);
    for (let x of allMethodNames) print("!!!!! " + x);
    for (let x of allPropertyNames) print("&&&&& " + x);
    print(uneval(builtinObjects));
    quit();
  }

})(this, false);


// /home/admin/funfuzz/js/jsfunfuzz/mess-tokens.js

// Each input to |cat| should be a token or so, OR a bigger logical piece (such as a call to makeExpr).  Smaller than a token is ok too ;)

// When "torture" is true, it may do any of the following:
// * skip a token
// * skip all the tokens to the left
// * skip all the tokens to the right
// * insert unterminated comments
// * insert line breaks
// * insert entire expressions
// * insert any token

// Even when not in "torture" mode, it may sneak in extra line breaks.

// Why did I decide to toString at every step, instead of making larger and larger arrays (or more and more deeply nested arrays?).  no particular reason.

function cat(toks)
{
  if (rnd(1700) === 0)
    return totallyRandom(2, ["x"]);

  var torture = (rnd(1700) === 57);
  if (torture)
    dumpln("Torture!!!");

  var s = maybeLineBreak();
  for (var i = 0; i < toks.length; ++i) {

    // Catch bugs in the fuzzer.  An easy mistake is
    //   return /*foo*/ + ...
    // instead of
    //   return "/*foo*/" + ...
    // Unary plus in the first one coerces the string that follows to number!
    if (typeof(toks[i]) != "string") {
      dumpln("Strange item in the array passed to cat: typeof toks[" + i + "] == " + typeof(toks[i]));
      dumpln(cat.caller);
      dumpln(cat.caller.caller);
    }

    if (!(torture && rnd(12) === 0))
      s += toks[i];

    s += maybeLineBreak();

    if (torture) switch(rnd(120)) {
      case 0:
      case 1:
      case 2:
      case 3:
      case 4:
        s += maybeSpace() + totallyRandom(2, ["x"]) + maybeSpace();
        break;
      case 5:
        s = "(" + s + ")"; // randomly parenthesize some *prefix* of it.
        break;
      case 6:
        s = ""; // throw away everything before this point
        break;
      case 7:
        return s; // throw away everything after this point
      case 8:
        s += UNTERMINATED_COMMENT;
        break;
      case 9:
        s += UNTERMINATED_STRING_LITERAL;
        break;
      case 10:
        if (rnd(2))
          s += "(";
        s += UNTERMINATED_REGEXP_LITERAL;
        break;
      default:
    }

  }

  return s;
}

// For reference and debugging.
/*
function catNice(toks)
{
  var s = ""
  var i;
  for (i=0; i<toks.length; ++i) {
    if(typeof(toks[i]) != "string")
      confused("Strange toks[i]: " + toks[i]);

    s += toks[i];
  }

  return s;
}
*/


var UNTERMINATED_COMMENT = "/*"; /* this comment is here so my text editor won't get confused */
var UNTERMINATED_STRING_LITERAL = "'";
var UNTERMINATED_REGEXP_LITERAL = "/";

function maybeLineBreak()
{
  if (rnd(900) === 3)
    return Random.index(["\r", "\n", "//h\n", "/*\n*/"]); // line break to trigger semicolon insertion and stuff
  else if (rnd(400) === 3)
    return rnd(2) ? "\u000C" : "\t"; // weird space-like characters
  else
    return "";
}

function maybeSpace()
{
  if (rnd(2) === 0)
    return " ";
  else
    return "";
}

function stripSemicolon(c)
{
  var len = c.length;
  if (c.charAt(len - 1) == ";")
    return c.substr(0, len - 1);
  else
    return c;
}




// /home/admin/funfuzz/js/jsfunfuzz/mess-grammar.js

// Randomly ignore the grammar 1 in TOTALLY_RANDOM times we generate any grammar node.
var TOTALLY_RANDOM = 1000;

var allMakers = getListOfMakers(this);

function totallyRandom(d, b) {
  d = d + (rnd(5) - 2); // can increase!!

  var maker = Random.index(allMakers);
  var val = maker(d, b);
  if (typeof val != "string") {
    print(maker.name);
    print(maker);
    throw "We generated something that isn't a string!";
  }
  return val;
}

function getListOfMakers(glob)
{
  var r = [];
  for (var f in glob) {
    if (f.indexOf("make") == 0 && typeof glob[f] == "function" && f != "makeFinalizeObserver" && f != "makeFakePromise") {
      r.push(glob[f]);
    }
  }
  return r;
}


/*
function testEachMaker()
{
  for (var f of allMakers) {
    dumpln("");
    dumpln(f.name);
    dumpln("==========");
    dumpln("");
    for (var i = 0; i < 100; ++i) {
      try {
        var r = f(8, ["A", "B"]);
        if (typeof r != "string")
          throw ("Got a " + typeof r);
        dumpln(r);
      } catch(e) {
        dumpln("");
        dumpln(uneval(e));
        dumpln(e.stack);
        dumpln("");
        throw "testEachMaker found a bug in jsfunfuzz";
      }
    }
    dumpln("");
  }
}
*/


// /home/admin/funfuzz/js/jsfunfuzz/gen-asm.js

/***************************
 * GENERATE ASM.JS MODULES *
 ***************************/

// Not yet tested:
// * loops (avoiding hangs with special forms, counters, and/or not executing)
// * break/continue with and without labels
// * function calls within the module (somehow avoiding recursion?)
// * function tables
// * multiple exports

function asmJSInterior(foreignFunctions, sanePlease)
{
  function mess()
  {
    if (!sanePlease && rnd(600) === 0)
      return makeStatement(8, ["x"]) + "\n";
    if (!sanePlease && rnd(600) === 0)
      return totallyRandom(8, ["x"]);
    return "";
  }

  var globalEnv = {stdlibImported: {}, stdlibImports: "", heapImported: {}, heapImports: "", foreignFunctions: foreignFunctions, sanePlease: !!sanePlease};
  var asmFunDecl = asmJsFunction(globalEnv, "f", rnd(2) ? "signed" : "double", [rnd(2) ? "i0" : "d0", rnd(2) ? "i1" : "d1"]);
  var interior = mess() + globalEnv.stdlibImports +
                 mess() + importForeign(foreignFunctions) +
                 mess() + globalEnv.heapImports +
                 mess() + asmFunDecl +
                 mess() + "  return f;" +
                 mess();
  return interior;
}

function importForeign(foreignFunctions)
{
  var s = "";
  for (let h of foreignFunctions) {
    s += "  var " + h + " = foreign." + h + ";\n";
  }
  return s;
}

// ret in ["signed", "double", "void"]
// args looks like ["i0", "d1", "d2"] -- the first letter indicates int vs double
function asmJsFunction(globalEnv, name, ret, args)
{
  var s = "  function " + name + "(" + args.join(", ") + ")\n";
  s += "  {\n";
  s += parameterTypeAnnotations(args);

  // Add local variables
  var locals = args;
  while (rnd(2)) {
    var isDouble = rnd(2);
    var local = (isDouble ? "d" : "i") + locals.length;
    s += "    var " + local + " = " + (isDouble ? doubleLiteral() : "0") + ";\n";
    locals.push(local);
  }

  var env = {globalEnv: globalEnv, locals: locals, ret: ret};

  // Add assignment statements
  if (locals.length) {
    while (rnd(5)) {
      s += asmStatement("    ", env, 6);
    }
  }

  // Add the required return statement at the end of the function
  if (ret != "void" || rnd(2))
  s += asmReturnStatement("    ", env);

  s += "  }\n";

  return s;
}

function asmStatement(indent, env, d)
{
  if (!env.globalEnv.sanePlease && rnd(100) === 0)
    return makeStatement(3, ["x"]);

  if (rnd(5) === 0 && d > 0) {
    return indent + "{\n" + asmStatement(indent + "  ", env, d - 1) + indent + "}\n";
  }
  if (rnd(20) === 0 && d > 3) {
    return asmSwitchStatement(indent, env, d);
  }
  if (rnd(10) === 0) {
    return asmReturnStatement(indent, env);
  }
  if (rnd(50) === 0 && env.globalEnv.foreignFunctions.length) {
    return asmVoidCallStatement(indent, env);
  }
  if (rnd(100) === 0)
    return ";";
  return asmAssignmentStatement(indent, env);
}

function asmVoidCallStatement(indent, env)
{
  return indent + asmFfiCall(8, env) + ";\n";
}

function asmAssignmentStatement(indent, env)
{
  if (rnd(5) === 0 || !env.locals.length) {
    if (rnd(2)) {
      return indent + intishMemberExpr(8, env) + " = " + intishExpr(10, env) + ";\n";
    } else {
      return indent + doublishMemberExpr(8, env) + " = " + doublishExpr(10, env) + ";\n";
    }
  }

  var local = Random.index(env.locals);
    if (local.charAt(0) == "d") {
    return indent + local + " = " + doubleExpr(10, env) + ";\n";
  } else {
    return indent + local + " = " + intExpr(10, env) + ";\n";
  }
}

function asmReturnStatement(indent, env)
{
  var ret = rnd(2) ? env.ret : Random.index(["double", "signed", "void"]);
  if (env.ret == "double")
    return indent + "return +" + doublishExpr(10, env) + ";\n";
  else if (env.ret == "signed")
    return indent + "return (" + intishExpr(10, env) + ")|0;\n";
  else // (env.ret == "void")
    return indent + "return;\n";
}

function asmSwitchStatement(indent, env, d)
{
  var s = indent + "switch (" + signedExpr(4, env) + ") {\n";
  while (rnd(3)) {
    s += indent + "  case " + (rnd(5)-3) + ":\n";
    s += asmStatement(indent + "    ", env, d - 2);
    if (rnd(4))
      s += indent + "    break;\n";
  }
  if (rnd(2)) {
    s += indent + "  default:\n";
    s += asmStatement(indent + "    ", env, d - 2);
  }
  s += indent + "}\n";
  return s;
}

function parameterTypeAnnotations(args)
{
  var s = "";
  for (var a = 0; a < args.length; ++a) {
    var arg = args[a];
    if (arg.charAt(0) == "i")
      s += "    " + arg + " = " + arg + "|0;\n";
    else
      s += "    " + arg + " = " + "+" + arg + ";\n";
  }
  return s;
}


var additive = ["+", "-"];

// Special rules here:
// * Parens are automatic.  (We're not testing the grammar, just the types.)
// * The first element is the "too deep" fallback, and should not recurse far.
// * We're allowed to write to some fields of |e|

var intExpr = autoExpr(Random.weighted([
    {w: 1,  v: function(d, e) { return intLiteralRange(-0x8000000, 0xffffffff); }},
    {w: 1,  v: function(d, e) { return intExpr(d - 3, e) + " ? " + intExpr(d - 3, e) + " : " + intExpr(d - 3, e); }},
    {w: 1,  v: function(d, e) { return "!" + intExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return signedExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return unsignedExpr(d - 1, e); }},
    {w: 10, v: function(d, e) { return intVar(e); }}, // + "|0"  ??
    {w: 1,  v: function(d, e) { return e.globalEnv.foreignFunctions.length ? asmFfiCall(d, e) + "|0" : "1"; }},
    {w: 1,  v: function(d, e) { return signedExpr(d - 2, e) + Random.index([" < ", " <= ", " > ", " >= ", " == ", " != "]) + signedExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return unsignedExpr(d - 2, e) + Random.index([" < ", " <= ", " > ", " >= ", " == ", " != "]) + unsignedExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return doubleExpr(d - 2, e) + Random.index([" < ", " <= ", " > ", " >= ", " == ", " != "]) + doubleExpr(d - 2, e); }},
]));

var intishExpr = autoExpr(Random.weighted([
    {w: 10, v: function(d, e) { return intExpr(d, e); }},
    {w: 1,  v: function(d, e) { return intishMemberExpr(d, e); }},
    // Add two or more ints
    {w: 10, v: function(d, e) { return intExpr(d - 1, e) + Random.index(additive) + intExpr(d - 1, e); }},
    {w: 5,  v: function(d, e) { return intExpr(d - 2, e) + Random.index(additive) + intExpr(d - 2, e) + Random.index(additive) + intExpr(d - 2, e); }},
    // Multiply by a small int literal
    {w: 2,  v: function(d, e) { return intExpr(d - 1, e) + "*" + intLiteralRange(-0xfffff, 0xfffff); }},
    {w: 2,  v: function(d, e) { return intLiteralRange(-0xfffff, 0xfffff) + "*" + intExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return "-" + intExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return signedExpr(d - 2, e) + " / " + signedExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return unsignedExpr(d - 2, e) + " / " + unsignedExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return signedExpr(d - 2, e) + " % " + signedExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return unsignedExpr(d - 2, e) + " % " + unsignedExpr(d - 2, e); }},
]));

var signedExpr = autoExpr(Random.weighted([
    {w: 1,  v: function(d, e) { return intLiteralRange(-0x8000000, 0x7fffffff); }},
    {w: 1,  v: function(d, e) { return "~" + intishExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return "~~" + doubleExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return intishExpr(d - 1, e) + "|0"; }}, // this isn't a special form, but it's common for a good reason
    {w: 1,  v: function(d, e) { return ensureMathImport(e, "imul") + "(" + intExpr(d - 2, e) + ", " + intExpr(d - 2, e) + ")|0"; }},
    {w: 1,  v: function(d, e) { return ensureMathImport(e, "abs") + "(" + signedExpr(d - 1, e) + ")|0"; }},
    {w: 5,  v: function(d, e) { return intishExpr(d - 2, e) + Random.index([" | ", " & ", " ^ ", " << ", " >> "]) + intishExpr(d - 2, e); }},
]));

var unsignedExpr = autoExpr(Random.weighted([
    {w: 1,  v: function(d, e) { return intLiteralRange(0, 0xffffffff); }},
    {w: 1,  v: function(d, e) { return intishExpr(d - 2, e) + ">>>" + intishExpr(d - 2, e); }},
]));

var doublishExpr = autoExpr(Random.weighted([
    {w: 10, v: function(d, e) { return doubleExpr(d, e); }},
    {w: 1,  v: function(d, e) { return doublishMemberExpr(d, e); }},
    // Read from a doublish typed array view
]));

var doubleExpr = autoExpr(Random.weighted([
    {w: 1,  v: function(d, e) { return doubleLiteral(); }},
    {w: 20, v: function(d, e) { return doubleVar(e); }},
    {w: 1,  v: function(d, e) { return e.globalEnv.foreignFunctions.length ? "+" + asmFfiCall(d, e) : "1.0"; }},
    {w: 1,  v: function(d, e) { return "+(1.0/0.0)"; }},
    {w: 1,  v: function(d, e) { return "+(0.0/0.0)"; }},
    {w: 1,  v: function(d, e) { return "+(-1.0/0.0)"; }},
    // Unary ops that return double
    {w: 1,  v: function(d, e) { return "+" + signedExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return "+" + unsignedExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return "+" + doublishExpr(d - 1, e); }},
    {w: 1,  v: function(d, e) { return "-" + doublishExpr(d - 1, e); }},
    // Binary ops that return double
    {w: 1,  v: function(d, e) { return doubleExpr(d - 2, e) + " + " + doubleExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return doublishExpr(d - 2, e) + " - " + doublishExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return doublishExpr(d - 2, e) + " * " + doublishExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return doublishExpr(d - 2, e) + " / " + doublishExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return doublishExpr(d - 2, e) + " % " + doublishExpr(d - 2, e); }},
    {w: 1,  v: function(d, e) { return intExpr(d - 3, e) + " ? " + doubleExpr(d - 3, e) + " : " + doubleExpr(d - 3, e); }},
    // with stdlib
    {w: 1,  v: function(d, e) { return "+" + ensureMathImport(e, Random.index(["acos", "asin", "atan", "cos", "sin", "tan", "ceil", "floor", "exp", "log", "sqrt"])) + "(" + doublishExpr(d - 1, e) + ")"; }},
    {w: 1,  v: function(d, e) { return "+" + ensureMathImport(e, "abs") + "(" + doublishExpr(d - 1, e) + ")"; }},
    {w: 1,  v: function(d, e) { return "+" + ensureMathImport(e, Random.index(["atan2", "pow"])) + "(" + doublishExpr(d - 2, e) + ", " + doublishExpr(d - 2, e) + ")"; }},
    {w: 1,  v: function(d, e) { return ensureImport(e, "Infinity"); }},
    {w: 1,  v: function(d, e) { return ensureImport(e, "NaN"); }},
]));

var externExpr = autoExpr(Random.weighted([
    {w: 1,  v: function(d, e) { return doubleExpr(d, e); } },
    {w: 1,  v: function(d, e) { return signedExpr(d, e); } },
]));

var intishMemberExpr = autoExpr(Random.weighted([
    {w: 1,  v: function(d, e) { return ensureView(e, Random.index(["Int8Array",  "Uint8Array" ])) + "[" + asmIndex(d, e, 0) + "]"; }},
    {w: 1,  v: function(d, e) { return ensureView(e, Random.index(["Int16Array", "Uint16Array"])) + "[" + asmIndex(d, e, 1) + "]"; }},
    {w: 1,  v: function(d, e) { return ensureView(e, Random.index(["Int32Array", "Uint32Array"])) + "[" + asmIndex(d, e, 2) + "]"; }},
]), true);

var doublishMemberExpr = autoExpr(Random.weighted([
    {w: 1,  v: function(d, e) { return ensureView(e, "Float32Array") + "[" + asmIndex(d, e, 2) + "]"; }},
    {w: 1,  v: function(d, e) { return ensureView(e, "Float64Array") + "[" + asmIndex(d, e, 3) + "]"; }},
]), true);

function asmIndex(d, e, logSize)
{
  if (rnd(2) || d < 2)
    return Random.index(["0", "1", "2", "4096"]);

  return intishExpr(d - 2, e) + " >> " + logSize;
}

function asmFfiCall(d, e)
{
  var argList = "";
  while (rnd(6)) {
    if (argList)
      argList += ", ";
    d -= 1;
    argList += externExpr(d, e);
  }

  return "/*FFI*/" + Random.index(e.globalEnv.foreignFunctions) + "(" + argList + ")";
}


function ensureView(e, t)
{
  var varName = t + "View";
  if (!(varName in e.globalEnv.heapImported)) {
    e.globalEnv.heapImports += "  var " + varName + " = new stdlib." + t + "(heap);\n";
    e.globalEnv.heapImported[varName] = true;
  }
  return varName;
}

function ensureMathImport(e, f)
{
  return ensureImport(e, f, "Math.");
}

function ensureImport(e, f, prefix)
{
  if (!(f in e.globalEnv.stdlibImported)) {
    e.globalEnv.stdlibImports += "  var " + f + " = stdlib." + (prefix||"") + f + ";\n";
    e.globalEnv.stdlibImported[f] = true;
  }
  return f;
}


var anyAsmExpr = [intExpr, intishExpr, signedExpr, doublishExpr, doubleExpr, intishMemberExpr, doublishMemberExpr];

function autoExpr(funs, avoidSubst)
{
  return function(d, e) {
    var f = d < 1 ? funs[0] :
            rnd(50) === 0 && !e.globalEnv.sanePlease ? function(_d, _e) { return makeExpr(5, ["x"]); } :
            rnd(50) === 0 && !avoidSubst ? Random.index(anyAsmExpr) :
            Random.index(funs);
    return "(" + f(d, e) + ")";
  };
}

function intVar(e)
{
  var locals = e.locals;
  if (!locals.length)
    return intLiteralRange(-0x8000000, 0xffffffff);
  var local = Random.index(locals);
  if (local.charAt(0) == "i")
    return local;
  return intLiteralRange(-0x8000000, 0xffffffff);
}

function doubleVar(e)
{
  var locals = e.locals;
  if (!locals.length)
    return doubleLiteral();
  var local = Random.index(locals);
  if (local.charAt(0) == "d")
    return local;
  return doubleLiteral();
}


function doubleLiteral()
{
  return Random.index(["-", ""]) + positiveDoubleLiteral();
}

function positiveDoubleLiteral()
{
  if (rnd(3) === 0) {
    Random.index(["0.0", "1.0", "1.2345e60"]);
  }

  // A power of two
  var value = Math.pow(2, rnd(100) - 10);

  // One more or one less
  if (rnd(3)) {
    value += 1;
  } else if (value > 1 && rnd(2)) {
    value -= 1;
  }

  var str = value + "";
  if (str.indexOf(".") == -1) {
    return str + ".0";
  }
  // Numbers with decimal parts, or numbers serialized with exponential notation
  return str;
}

function fuzzyRange(min, max)
{
  if (rnd(10000) === 0)
    return min - 1;
  if (rnd(10000) === 0)
    return max + 1;
  if (rnd(10) === 0)
    return min;
  if (rnd(10) === 0)
    return max;

  // rnd() is limited to 2^32. (It also skews toward lower numbers, oh well.)
  if (max > min + 0x100000000 && rnd(3) === 0)
    return min + 0x100000000 + rnd(max - (min + 0x100000000) + 1);
  return min + rnd(max - min + 1);
}

function intLiteralRange(min, max)
{
  var val = fuzzyRange(min, max);
  var sign = val < 0 ? "-" : "";
  return sign + "0x" + Math.abs(val).toString(16);
}




// /home/admin/funfuzz/js/jsfunfuzz/gen-math.js

const NUM_MATH_FUNCTIONS = 6;

var binaryMathOps = [
  " * ", " / ", " % ",
  " + ", " - ",
  " ** ",
  " << ", " >> ", " >>> ",
  " < ", " > ", " <= ", " >= ",
  " == ", " != ",
  " === ", " !== ",
  " & ", " | ", " ^ ", " && ", " || ",
  " , ",
];

var leftUnaryMathOps = [
  " ! ", " + ", " - ", " ~ ",
];

// unaryMathFunctions and binaryMathFunctions updated on 2017-01-21 and added from:
// https://dxr.mozilla.org/mozilla-central/rev/3cedab21a7e65e6a1c4c2294ecfb5502575a46e3/js/src/jsmath.cpp#1330
// Update to the latest revision as needed.
var unaryMathFunctions = [
  "abs",
  "acos",
  "acosh",
  "asin",
  "asinh",
  "atan",
  "atanh",
  "cbrt",
  "ceil",
  "clz32",
  "cos",
  "cosh",
  "exp",
  "expm1",
  // "floor", // avoid breaking rnd.
  "fround",
  "log",
  "log2",
  "log10",
  "log1p",
  // "random", // avoid breaking rnd. avoid non-determinism.
  "round",
  "sign",
  "sin",
  "sinh",
  "sqrt",
  "tan",
  "tanh",
  "trunc",
];

// n-ary functions will also be tested with varying numbers of parameters by makeFunction
var binaryMathFunctions = [
  "atan2",
  "hypot", // n-ary
  "imul",
  "max", // n-ary
  "min", // n-ary
  "pow",
];

function makeMathFunction(d, b, i)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var ivars = ["x", "y"];
  if (rnd(10) == 0) {
    // Also use variables from the enclosing scope
    ivars = ivars.concat(b);
  }
  return "(function(x, y) { " + directivePrologue() + "return " + makeMathExpr(d, ivars, i) + "; })";
}

function makeMathExpr(d, b, i)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  // As depth decreases, make it more likely to bottom out
  if (d < rnd(5)) {
    if (rnd(4)) {
      return Random.index(b);
    }
    return Random.index(numericVals);
  }

  if (rnd(500) == 0 && d > 0)
    return makeExpr(d - 1, b);

  function r() { return makeMathExpr(d - 1, b, i); }

  // Frequently, coerce both the inputs and outputs to the same "numeric sub-type"
  // (asm.js formalizes this concept, but JITs may have their own variants)
  var commonCoercion = rnd(10);
  function mc(expr) {
    switch(rnd(3) ? commonCoercion : rnd(10)) {
      case 0: return "(" + " + " + expr + ")";     // f64 (asm.js)
      case 1: return "Math.fround(" + expr + ")";  // f32
      case 2: return "(" + expr + " | 0)";         // i32 (asm.js)
      case 3: return "(" + expr + " >>> 0)";       // u32
      default: return expr;
    }
  }

  if (i > 0 && rnd(10) == 0) {
    // Call a *lower-numbered* mathy function. (This avoids infinite recursion.)
    return mc("mathy" + rnd(i) + "(" + mc(r()) + ", " + mc(r()) + ")");
  }

  if (rnd(20) == 0) {
    return mc("(" + mc(r()) + " ? " + mc(r()) + " : " + mc(r()) + ")");
  }

  switch(rnd(4)) {
    case 0:  return mc("(" + mc(r()) + Random.index(binaryMathOps) + mc(r()) + ")");
    case 1:  return mc("(" + Random.index(leftUnaryMathOps) + mc(r()) + ")");
    case 2:  return mc("Math." + Random.index(unaryMathFunctions) + "(" + mc(r()) + ")");
    default: return mc("Math." + Random.index(binaryMathFunctions) + "(" + mc(r()) + ", " + mc(r()) + ")");
  }
}


// /home/admin/funfuzz/js/jsfunfuzz/gen-grammar.js


/****************************
 * GRAMMAR-BASED GENERATION *
 ****************************/


function makeScript(d, ignoredB)
{
  return directivePrologue() + makeScriptBody(d, ignoredB);
}

function makeScriptBody(d, ignoredB)
{
  if (rnd(3) == 0) {
    return makeMathyFunAndTest(d, ["x"]);
  }
  return makeStatement(d, ["x"]);
}

function makeScriptForEval(d, b)
{
  switch (rnd(4)) {
    case 0:  return makeExpr(d - 1, b);
    case 1:  return makeStatement(d - 1, b);
    case 2:  return makeUseRegressionTest(d, b);
    default: return makeScript(d - 3, b);
  }
}


// Statement or block of statements
function makeStatement(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (rnd(2))
    return makeBuilderStatement(d, b);

  if (d < 6 && rnd(3) === 0)
    return makePrintStatement(d, b);

  if (d < rnd(8)) // frequently for small depth, infrequently for large depth
    return makeLittleStatement(d, b);

  d = rnd(d); // !

  return (Random.index(statementMakers))(d, b);
}

var varBinder = ["var ", "let ", "const ", ""];
var varBinderFor = ["var ", "let ", ""]; // const is a syntax error in for loops

// The reason there are several types of loops here is to create different
// types of scripts without introducing infinite loops.

function forLoopHead(d, b, v, reps)
{
  var sInit = Random.index(varBinderFor) + v + " = 0";
  var sCond = v + " < " + reps;
  var sNext = "++" + v;

  while (rnd(10) === 0)
    sInit += ", " + makeLetHeadItem(d - 2, b);
  while (rnd(10) === 0)
    sInit += ", " + makeExpr(d - 2, b); // NB: only makes sense if our varBinder is ""

  while (rnd(20) === 0)
    sCond = sCond + " && (" + makeExpr(d - 2, b) + ")";
  while (rnd(20) === 0)
    sCond = "(" + makeExpr(d - 2, b) + ") && " + sCond;

  while (rnd(20) === 0)
    sNext = sNext + ", " + makeExpr(d - 2, b);
  while (rnd(20) === 0)
    sNext = makeExpr(d - 2, b) + ", " + sNext;

  return "for (" + sInit + "; " + sCond + "; " + sNext + ")";
}

function makeOpaqueIdiomaticLoop(d, b)
{
  var reps = loopCount();
  var vHidden = uniqueVarName();
  return "/*oLoop*/" + forLoopHead(d, b, vHidden, reps) + " { " +
      makeStatement(d - 2, b) +
      " } ";
}

function makeTransparentIdiomaticLoop(d, b)
{
  var reps = loopCount();
  var vHidden = uniqueVarName();
  var vVisible = makeNewId(d, b);
  return "/*vLoop*/" + forLoopHead(d, b, vHidden, reps) +
    " { " +
      Random.index(varBinder) + vVisible + " = " + vHidden + "; " +
      makeStatement(d - 2, b.concat([vVisible])) +
    " } ";
}

function makeBranchUnstableLoop(d, b)
{
  var reps = loopCount();
  var v = uniqueVarName();
  var mod = loopModulo();
  var target = rnd(mod);
  return "/*bLoop*/" + forLoopHead(d, b, v, reps) + " { " +
    "if (" + v + " % " + mod + " == " + target + ") { " + makeStatement(d - 2, b) + " } " +
    "else { " + makeStatement(d - 2, b) + " } " +
    " } ";
}

function makeTypeUnstableLoop(d, b) {
  var a = makeMixedTypeArray(d, b);
  var v = makeNewId(d, b);
  var bv = b.concat([v]);
  return "/*tLoop*/for (let " + v + " of " + a + ") { " + makeStatement(d - 2, bv) + " }";
}


function makeFunOnCallChain(d, b) {
  var s = "arguments.callee";
  while (rnd(2))
    s += ".caller";
  return s;
}


var statementMakers = Random.weighted([

  // Any two statements in sequence
  { w: 15, v: function(d, b) { return cat([makeStatement(d - 1, b),       makeStatement(d - 1, b)      ]); } },
  { w: 15, v: function(d, b) { return cat([makeStatement(d - 1, b), "\n", makeStatement(d - 1, b), "\n"]); } },

  // Stripping semilcolons.  What happens if semicolons are missing?  Especially with line breaks used in place of semicolons (semicolon insertion).
  { w: 1, v: function(d, b) { return cat([stripSemicolon(makeStatement(d, b)), "\n", makeStatement(d, b)]); } },
  { w: 1, v: function(d, b) { return cat([stripSemicolon(makeStatement(d, b)), "\n"                   ]); } },
  { w: 1, v: function(d, b) { return stripSemicolon(makeStatement(d, b)); } }, // usually invalid, but can be ok e.g. at the end of a block with curly braces

  // Simple variable declarations, followed (or preceded) by statements using those variables
  { w: 4, v: function(d, b) { var v = makeNewId(d, b); return cat([Random.index(varBinder), v, " = ", makeExpr(d, b), ";", makeStatement(d - 1, b.concat([v]))]); } },
  { w: 4, v: function(d, b) { var v = makeNewId(d, b); return cat([makeStatement(d - 1, b.concat([v])), Random.index(varBinder), v, " = ", makeExpr(d, b), ";"]); } },

  // Complex variable declarations, e.g. "const [a,b] = [3,4];" or "var a,b,c,d=4,e;"
  { w: 10, v: function(d, b) { return cat([Random.index(varBinder), makeLetHead(d, b), ";", makeStatement(d - 1, b)]); } },

  // Blocks
  { w: 2, v: function(d, b) { return cat(["{", makeStatement(d, b), " }"]); } },
  { w: 2, v: function(d, b) { return cat(["{", makeStatement(d - 1, b), makeStatement(d - 1, b), " }"]); } },

  // "with" blocks
  { w: 2, v: function(d, b) {                          return cat([maybeLabel(), "with", "(", makeExpr(d, b), ")",                    makeStatementOrBlock(d, b)]);             } },
  { w: 2, v: function(d, b) { var v = makeNewId(d, b); return cat([maybeLabel(), "with", "(", "{", v, ": ", makeExpr(d, b), "}", ")", makeStatementOrBlock(d, b.concat([v]))]); } },

  // C-style "for" loops
  // Two kinds of "for" loops: one with an expression as the first part, one with a var or let binding 'statement' as the first part.
  // I'm not sure if arbitrary statements are allowed there; I think not.
  { w: 1, v: function(d, b) {                          return "/*infloop*/" + cat([maybeLabel(), "for", "(", makeExpr(d, b), "; ", makeExpr(d, b), "; ", makeExpr(d, b), ") ", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b); return "/*infloop*/" + cat([maybeLabel(), "for", "(", Random.index(varBinderFor), v,                                                    "; ", makeExpr(d, b), "; ", makeExpr(d, b), ") ", makeStatementOrBlock(d, b.concat([v]))]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b); return "/*infloop*/" + cat([maybeLabel(), "for", "(", Random.index(varBinderFor), v, " = ", makeExpr(d, b),                             "; ", makeExpr(d, b), "; ", makeExpr(d, b), ") ", makeStatementOrBlock(d, b.concat([v]))]); } },
  { w: 1, v: function(d, b) {                          return "/*infloop*/" + cat([maybeLabel(), "for", "(", Random.index(varBinderFor), makeDestructuringLValue(d, b), " = ", makeExpr(d, b), "; ", makeExpr(d, b), "; ", makeExpr(d, b), ") ", makeStatementOrBlock(d, b)]); } },

  // Various types of "for" loops, specially set up to test tracing, carefully avoiding infinite loops
  { w: 6, v: makeTransparentIdiomaticLoop },
  { w: 6, v: makeOpaqueIdiomaticLoop },
  { w: 6, v: makeBranchUnstableLoop },
  { w: 8, v: makeTypeUnstableLoop },

  // "for..in" loops
  // arbitrary-LHS marked as infloop because
  // -- for (key in obj)
  { w: 1, v: function(d, b) {                          return "/*infloop*/" + cat([maybeLabel(), "for", "(", Random.index(varBinderFor), makeForInLHS(d, b), " in ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b); return                 cat([maybeLabel(), "for", "(", Random.index(varBinderFor), v,                  " in ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b.concat([v]))]); } },
  // -- for (key in generator())
  { w: 1, v: function(d, b) {                          return "/*infloop*/" + cat([maybeLabel(), "for", "(", Random.index(varBinderFor), makeForInLHS(d, b), " in ", "(", "(", makeFunction(d, b), ")", "(", makeExpr(d, b), ")", ")", ")", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b); return                 cat([maybeLabel(), "for", "(", Random.index(varBinderFor), v,                  " in ", "(", "(", makeFunction(d, b), ")", "(", makeExpr(d, b), ")", ")", ")", makeStatementOrBlock(d, b.concat([v]))]); } },
  // -- for each (value in obj)
  // to be removed: https://bugzilla.mozilla.org/show_bug.cgi?id=1083470
  { w: 1, v: function(d, b) {                          return "/*infloop*/" + cat([maybeLabel(), " for ", " each", "(", Random.index(varBinderFor), makeLValue(d, b), " in ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b); return                 cat([maybeLabel(), " for ", " each", "(", Random.index(varBinderFor), v,                " in ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b.concat([v]))]); } },
  // -- for (element of arraylike)
  { w: 1, v: function(d, b) {                          return "/*infloop*/" + cat([maybeLabel(), " for ", "(", Random.index(varBinderFor), makeLValue(d, b), " of ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b); return                 cat([maybeLabel(), " for ", "(", Random.index(varBinderFor), v,                " of ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b.concat([v]))]); } },

  // Modify something during a loop -- perhaps the thing being looped over
  // Since we use "let" to bind the for-variables, and only do wacky stuff once, I *think* this is unlikely to hang.
//  function(d, b) { return "let forCount = 0; for (let " + makeId(d, b) + " in " + makeExpr(d, b) + ") { if (forCount++ == " + rnd(3) + ") { " + makeStatement(d - 1, b) + " } }"; },

  // Hoisty "for..in" loops.  I don't know why this construct exists, but it does, and it hoists the initial-value expression above the loop.
  // With "var" or "const", the entire thing is hoisted.
  // With "let", only the value is hoisted, and it can be elim'ed as a useless statement.
  // The last form is specific to JavaScript 1.7 (only).
  { w: 1, v: function(d, b) {                                               return cat([maybeLabel(), "for", "(", Random.index(varBinderFor), makeId(d, b),         " = ", makeExpr(d, b), " in ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b);                      return cat([maybeLabel(), "for", "(", Random.index(varBinderFor), v,                    " = ", makeExpr(d, b), " in ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b.concat([v]))]); } },
  { w: 1, v: function(d, b) { var v = makeNewId(d, b), w = makeNewId(d, b); return cat([maybeLabel(), "for", "(", Random.index(varBinderFor), "[", v, ", ", w, "]", " = ", makeExpr(d, b), " in ", makeExpr(d - 2, b), ") ", makeStatementOrBlock(d, b.concat([v, w]))]); } },

  // do..while
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "while((", makeExpr(d, b), ") && 0)" /*don't split this, it's needed to avoid marking as infloop*/, makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { return "/*infloop*/" + cat([maybeLabel(), "while", "(", makeExpr(d, b), ")", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "do ", makeStatementOrBlock(d, b), " while((", makeExpr(d, b), ") && 0)" /*don't split this, it's needed to avoid marking as infloop*/, ";"]); } },
  { w: 1, v: function(d, b) { return "/*infloop*/" + cat([maybeLabel(), "do ", makeStatementOrBlock(d, b), " while", "(", makeExpr(d, b), ");"]); } },

  // Switch statement
  { w: 3, v: function(d, b) { return cat([maybeLabel(), "switch", "(", makeExpr(d, b), ")", " { ", makeSwitchBody(d, b), " }"]); } },

  // "let" blocks, with bound variable used inside the block
  { w: 2, v: function(d, b) { var v = makeNewId(d, b); return cat(["let ", "(", v, ")", " { ", makeStatement(d, b.concat([v])), " }"]); } },

  // "let" blocks, with and without multiple bindings, with and without initial values
  { w: 2, v: function(d, b) { return cat(["let ", "(", makeLetHead(d, b), ")", " { ", makeStatement(d, b), " }"]); } },

  // Conditionals, perhaps with 'else if' / 'else'
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "if(", makeBoolean(d, b), ") ", makeStatementOrBlock(d, b)]); } },
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "if(", makeBoolean(d, b), ") ", makeStatementOrBlock(d - 1, b), " else ", makeStatementOrBlock(d - 1, b)]); } },
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "if(", makeBoolean(d, b), ") ", makeStatementOrBlock(d - 1, b), " else ", " if ", "(", makeExpr(d, b), ") ", makeStatementOrBlock(d - 1, b)]); } },
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "if(", makeBoolean(d, b), ") ", makeStatementOrBlock(d - 1, b), " else ", " if ", "(", makeExpr(d, b), ") ", makeStatementOrBlock(d - 1, b), " else ", makeStatementOrBlock(d - 1, b)]); } },

  // A tricky pair of if/else cases.
  // In the SECOND case, braces must be preserved to keep the final "else" associated with the first "if".
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "if(", makeBoolean(d, b), ") ", "{", " if ", "(", makeExpr(d, b), ") ", makeStatementOrBlock(d - 1, b), " else ", makeStatementOrBlock(d - 1, b), "}"]); } },
  { w: 1, v: function(d, b) { return cat([maybeLabel(), "if(", makeBoolean(d, b), ") ", "{", " if ", "(", makeExpr(d, b), ") ", makeStatementOrBlock(d - 1, b), "}", " else ", makeStatementOrBlock(d - 1, b)]); } },

  // Expression statements
  { w: 5, v: function(d, b) { return cat([makeExpr(d, b), ";"]); } },
  { w: 5, v: function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); } },

  // Exception-related statements :)
  { w: 6, v: function(d, b) { return makeExceptionyStatement(d - 1, b) + makeExceptionyStatement(d - 1, b); } },
  { w: 7, v: function(d, b) { return makeExceptionyStatement(d, b); } },

  // Labels. (JavaScript does not have goto, but it does have break-to-label and continue-to-label).
  { w: 1, v: function(d, b) { return cat(["L", ": ", makeStatementOrBlock(d, b)]); } },

  // Function-declaration-statements with shared names
  { w: 10, v: function(d, b) { return cat([makeStatement(d-2, b), "function ", makeId(d, b), "(", makeFormalArgList(d, b), ")", makeFunctionBody(d - 1, b), makeStatement(d-2, b)]); } },

  // Function-declaration-statements with unique names, along with calls to those functions
  { w: 8, v: makeNamedFunctionAndUse },

  // Long script -- can confuse Spidermonkey's short vs long jmp or something like that.
  // Spidermonkey's regexp engine is so slow for long strings that we have to bypass whatToTest :(
  //{ w: 1, v: function(d, b) { return strTimes("try{}catch(e){}", rnd(10000)); } },
  { w: 1, v: function(d, b) { if (rnd(200)==0) return "/*DUPTRY" + rnd(10000) + "*/" + makeStatement(d - 1, b); return ";"; } },

  { w: 1, v: function(d, b) { return makeShapeyConstructorLoop(d, b); } },

  // Replace a variable with a long linked list pointing to it.  (Forces SpiderMonkey's GC marker into a stackless mode.)
  { w: 1, v: function(d, b) { var x = makeId(d, b); return x + " = linkedList(" + x + ", " + (rnd(100) * rnd(100)) + ");";  } },

  // Oddly placed "use strict" or "use asm"
  { w: 1, v: function(d, b) { return directivePrologue() + makeStatement(d - 1, b); } },

  // Spidermonkey GC and JIT controls
  { w: 3, v: function(d, b) { return makeTestingFunctionCall(d, b); } },
  { w: 3, v: function(d, b) { return makeTestingFunctionCall(d - 1, b) + " " + makeStatement(d - 1, b); } },

  // Blocks of statements related to typed arrays
  { w: 8, v: makeTypedArrayStatements },

  // Print statements
  { w: 8, v: makePrintStatement },

  { w: 20, v: makeRegexUseBlock },

  { w: 1, v: makeRegisterStompBody },

  { w: 20, v: makeUseRegressionTest },

  // Discover properties to add to the allPropertyNames list
  //{ w: 3, v: function(d, b) { return "for (var p in " + makeId(d, b) + ") { addPropertyName(p); }"; } },
  //{ w: 3, v: function(d, b) { return "var opn = Object.getOwnPropertyNames(" + makeId(d, b) + "); for (var j = 0; j < opn.length; ++j) { addPropertyName(opn[j]); }"; } },
]);

if (typeof oomTest == "function" && engine != ENGINE_SPIDERMONKEY_MOZILLA45) {
  statementMakers = statementMakers.concat([
    function(d, b) { return "oomTest(" + makeFunction(d - 1, b) + ")"; },
  ]);
}


function makeUseRegressionTest(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (typeof regressionTestList != "object") {
    return "/* no regression tests found */";
  }

  var maintest = regressionTestsRoot + Random.index(regressionTestList);
  var files = regressionTestDependencies(maintest);

  var s = "";

  if (rnd(5) == 0) {
    // Many tests call assertEq, intending to throw if something unexpected happens.
    // Sometimes, override it with a function that compares but does not throw.
    s += "assertEq = function(x, y) { if (x != y) { print(0); } }; ";
  }

  for (var i = 0; i < files.length; ++i) {
    var file = files[i];

    if (regressionTestIsEvil(read(file))) {
      continue;
    }

    switch (rnd(2)) {
      case 0:
        // simply inline the script -- this is the only one that will work in newGlobal()
        s += "/* regression-test-inline */ " + inlineTest(file);
        break;
      default:
        // run it using load()
        s += "/* regression-test-load */ " + "load(" + simpleSource(file) + ");";
        break;
      // NB: these scripts will also be run through eval(), evalcx(), evaluate() thanks to other parts of the fuzzer using makeScriptForEval or makeStatement
    }
  }
  return s;
}

function regressionTestIsEvil(contents)
{
  if (contents.indexOf("SIMD") != -1) {
    // Disable SIMD testing until it's more stable (and we can get better stacks?)
    return true;
  }
  if (contents.indexOf("print = ") != -1) {
    // A testcase that clobbers the |print| function would confuse jsInteresting.py
    return true;
  }
  return false;
}

function inlineTest(filename)
{
  // Inline a regression test, adding NODIFF (to disable differential testing) if it calls a testing function that might throw.

  const s = "/* " + filename + " */ " + read(filename) + "\n";

  const noDiffTestingFunctions = [
    // These can throw
    "gcparam",
    "startgc",
    "setJitCompilerOption",
    "disableSingleStepProfiling",
    "enableSingleStepProfiling",
    // These return values depending on command-line options, and some regression tests check them
    "isAsmJSCompilationAvailable",
    "isSimdAvailable", // in 32-bit x86 builds, it depends on whether --no-fpu is passed in, because --no-fpu also disables SSE
    "hasChild",
    "PerfMeasurement",
  ];

  for (var f of noDiffTestingFunctions) {
    if (s.indexOf(f) != -1) {
      return "/*NODIFF*/ " + s;
    }
  }

  return s;
}


function regressionTestDependencies(maintest)
{
  var files = [];

  if (rnd(3)) {
    // Include the chain of 'shell.js' files in their containing directories (starting from regressionTestsRoot)
    for (var i = regressionTestsRoot.length; i < maintest.length; ++i) {
      if (maintest.charAt(i) == "/" || maintest.charAt(i) == "\\") {
        var shelljs = maintest.substr(0, i + 1) + "shell.js";
        if (regressionTestList.indexOf(shelljs) != -1) {
          files.push(shelljs);
        }
      }
    }

    // Include prologue.js for jit-tests
    if (maintest.indexOf("jit-test") != -1) {
      files.push(libdir + "prologue.js");
    }
  }

  files.push(maintest);
  return files;
}


function linkedList(x, n)
{
  for (var i = 0; i < n; ++i)
    x = {a: x};
  return x;
}

function makeNamedFunctionAndUse(d, b) {
  // Use a unique function name to make it less likely that we'll accidentally make a recursive call
  var funcName = uniqueVarName();
  var formalArgList = makeFormalArgList(d, b);
  var bv = formalArgList.length == 1 ? b.concat(formalArgList) : b;
  var declStatement = cat(["/*hhh*/function ", funcName, "(", formalArgList, ")", "{", makeStatement(d - 1, bv), "}"]);
  var useStatement;
  if (rnd(2)) {
    // Direct call
    useStatement = cat([funcName, "(", makeActualArgList(d, b), ")", ";"]);
  } else {
    // Any statement, allowed to use the name of the function
    useStatement = "/*iii*/" + makeStatement(d - 1, b.concat([funcName]));
  }
  if (rnd(2)) {
    return declStatement + useStatement;
  } else {
    return useStatement + declStatement;
  }
}

function makePrintStatement(d, b)
{
  if (rnd(2) && b.length)
    return "print(" + Random.index(b) + ");";
  else
    return "print(" + makeExpr(d, b) + ");";
}


function maybeLabel()
{
  if (rnd(4) === 1)
    return cat([Random.index(["L", "M"]), ":"]);
  else
    return "";
}


function uniqueVarName()
{
  // Make a random variable name.
  var i, s = "";
  for (i = 0; i < 6; ++i)
    s += String.fromCharCode(97 + rnd(26)); // a lowercase english letter
  return s;
}



function makeSwitchBody(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var haveSomething = false;
  var haveDefault = false;
  var output = "";

  do {

    if (!haveSomething || rnd(2)) {
      // Want a case/default (or, if this is the beginning, "need").

      if (!haveDefault && rnd(2)) {
        output += "default: ";
        haveDefault = true;
      }
      else {
        // cases with numbers (integers?) have special optimizations,
        // so be sure to test those well in addition to testing complicated expressions.
        output += "case " + (rnd(2) ? rnd(10) : makeExpr(d, b)) + ": ";
      }

      haveSomething = true;
    }

    // Might want a statement.
    if (rnd(2))
      output += makeStatement(d, b);

    // Might want to break, or might want to fall through.
    if (rnd(2))
      output += "break; ";

    if (rnd(2))
      --d;

  } while (d && rnd(5));

  return output;
}

function makeLittleStatement(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  d = d - 1;

  if (rnd(4) === 1)
    return makeStatement(d, b);

  return (Random.index(littleStatementMakers))(d, b);
}

var littleStatementMakers =
[
  // Tiny
  function(d, b) { return cat([";"]); }, // e.g. empty "if" block
  function(d, b) { return cat(["{", "}"]); }, // e.g. empty "if" block
  function(d, b) { return cat([""]); },

  // Throw stuff.
  function(d, b) { return cat(["throw ", makeExpr(d, b), ";"]); },

  // Break/continue [to label].
  function(d, b) { return cat([Random.index(["continue", "break"]), " ", Random.index(["L", "M", "", ""]), ";"]); },

  // Named and unnamed functions (which have different behaviors in different places: both can be expressions,
  // but unnamed functions "want" to be expressions and named functions "want" to be special statements)
  function(d, b) { return makeFunction(d, b); },

  // Return, yield
  function(d, b) { return cat(["return ", makeExpr(d, b), ";"]); },
  function(d, b) { return "return;"; }, // return without a value is allowed in generators; return with a value is not.
  function(d, b) { return cat(["yield ", makeExpr(d, b), ";"]); }, // note: yield can also be a left-unary operator, or something like that
  function(d, b) { return "yield;"; },

  // Expression statements
  function(d, b) { return cat([makeExpr(d, b), ";"]); },
  function(d, b) { return cat([makeExpr(d, b), ";"]); },
  function(d, b) { return cat([makeExpr(d, b), ";"]); },
  function(d, b) { return cat([makeExpr(d, b), ";"]); },
  function(d, b) { return cat([makeExpr(d, b), ";"]); },
  function(d, b) { return cat([makeExpr(d, b), ";"]); },
  function(d, b) { return cat([makeExpr(d, b), ";"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", ";"]); },
];


// makeStatementOrBlock exists because often, things have different behaviors depending on where there are braces.
// for example, if braces are added or removed, the meaning of "let" can change.
function makeStatementOrBlock(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  return (Random.index(statementBlockMakers))(d - 1, b);
}

var statementBlockMakers = [
  function(d, b) { return makeStatement(d, b); },
  function(d, b) { return makeStatement(d, b); },
  function(d, b) { return cat(["{", makeStatement(d, b), " }"]); },
  function(d, b) { return cat(["{", makeStatement(d - 1, b), makeStatement(d - 1, b), " }"]); },
];


// Extra-hard testing for try/catch/finally and related things.

function makeExceptionyStatement(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  d = d - 1;
  if (d < 1)
    return makeLittleStatement(d, b);

  return (Random.index(exceptionyStatementMakers))(d, b);
}

var exceptionProperties = ["constructor", "message", "name", "fileName", "lineNumber", "stack"];

var exceptionyStatementMakers = [
  function(d, b) { return makeTryBlock(d, b); },

  function(d, b) { return makeStatement(d, b); },
  function(d, b) { return makeLittleStatement(d, b); },

  function(d, b) { return "return;"; }, // return without a value can be mixed with yield
  function(d, b) { return cat(["return ", makeExpr(d, b), ";"]); },
  function(d, b) { return cat(["yield ", makeExpr(d, b), ";"]); },
  function(d, b) { return cat(["throw ", makeId(d, b), ";"]); },
  function(d, b) { return "throw StopIteration;"; },
  function(d, b) { return "this.zzz.zzz;"; }, // throws; also tests js_DecompileValueGenerator in various locations
  function(d, b) { return b[b.length - 1] + "." + Random.index(exceptionProperties) + ";"; },
  function(d, b) { return makeId(d, b) + "." + Random.index(exceptionProperties) + ";"; },
  function(d, b) { return cat([makeId(d, b), " = ", makeId(d, b), ";"]); },
  function(d, b) { return cat([makeLValue(d, b), " = ", makeId(d, b), ";"]); },

  // Iteration uses StopIteration internally.
  // Iteration is also useful to test because it asserts that there is no pending exception.
  function(d, b) { var v = makeNewId(d, b); return "for(let " + v + " in []);"; },
  function(d, b) { var v = makeNewId(d, b); return "for(let " + v + " in " + makeIterable(d, b) + ") " + makeExceptionyStatement(d, b.concat([v])); },
  function(d, b) { var v = makeNewId(d, b); return "for(let " + v + " of " + makeIterable(d, b) + ") " + makeExceptionyStatement(d, b.concat([v])); },

  // Brendan says these are scary places to throw: with, let block, lambda called immediately in let expr.
  // And I think he was right.
  function(d, b) { return "with({}) "   + makeExceptionyStatement(d, b);         },
  function(d, b) { return "with({}) { " + makeExceptionyStatement(d, b) + " } "; },
  function(d, b) { var v = makeNewId(d, b); return "let(" + v + ") { " + makeExceptionyStatement(d, b.concat([v])) + "}"; },
  function(d, b) { var v = makeNewId(d, b); return "let(" + v + ") ((function(){" + makeExceptionyStatement(d, b.concat([v])) + "})());"; },
  function(d, b) { return "let(" + makeLetHead(d, b) + ") { " + makeExceptionyStatement(d, b) + "}"; },
  function(d, b) { return "let(" + makeLetHead(d, b) + ") ((function(){" + makeExceptionyStatement(d, b) + "})());"; },

  // Commented out due to causing too much noise on stderr and causing a nonzero exit code :/
/*
  // Generator close hooks: called during GC in this case!!!
  function(d, b) { return "(function () { try { yield " + makeExpr(d, b) + " } finally { " + makeStatement(d, b) + " } })().next()"; },

  function(d, b) { return "(function () { try { yield " + makeExpr(d, b) + " } finally { " + makeStatement(d, b) + " } })()"; },
  function(d, b) { return "(function () { try { yield " + makeExpr(d, b) + " } finally { " + makeStatement(d, b) + " } })"; },
  function(d, b) {
    return "function gen() { try { yield 1; } finally { " + makeStatement(d, b) + " } } var i = gen(); i.next(); i = null;";
  }

*/
];

function makeTryBlock(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  // Catches: 1/6 chance of having none
  // Catches: maybe 2 + 1/2
  // So approximately 4 recursions into makeExceptionyStatement on average!
  // Therefore we want to keep the chance of recursing too much down.

  d = d - rnd(3);


  var s = cat(["try", " { ", makeExceptionyStatement(d, b), " } "]);

  var numCatches = 0;

  while(rnd(3) === 0) {
    // Add a guarded catch, using an expression or a function call.
    ++numCatches;
    var catchId = makeId(d, b);
    var catchBlock = makeExceptionyStatement(d, b.concat([catchId]));
    if (rnd(2))
      s += cat(["catch", "(", catchId, " if ",                 makeExpr(d, b),                    ")", " { ", catchBlock, " } "]);
    else
      s += cat(["catch", "(", catchId, " if ", "(function(){", makeExceptionyStatement(d, b), "})())", " { ", catchBlock, " } "]);
  }

  if (rnd(2)) {
    // Add an unguarded catch.
    ++numCatches;
    var catchId = makeId(d, b);
    var catchBlock = makeExceptionyStatement(d, b.concat([catchId]));
    s +=   cat(["catch", "(", catchId,                                                          ")", " { ", catchBlock, " } "]);
  }

  if (numCatches == 0 || rnd(2) === 1) {
    // Add a finally.
    s += cat(["finally", " { ", makeExceptionyStatement(d, b), " } "]);
  }

  return s;
}



// Creates a string that sorta makes sense as an expression
function makeExpr(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (d <= 0 || (rnd(7) === 1))
    return makeTerm(d - 1, b);

  if (rnd(6) === 1 && b.length)
    return Random.index(b);

  if (rnd(10) === 1)
    return makeImmediateRecursiveCall(d, b);

  d = rnd(d); // !

  var expr = (Random.index(exprMakers))(d, b);

  if (rnd(4) === 1)
    return "(" + expr + ")";
  else
    return expr;
}

var binaryOps = [
  // Long-standing JavaScript operators, roughly in order from http://www.codehouse.com/javascript/precedence/
  " * ", " / ", " % ", " + ", " - ", " << ", " >> ", " >>> ", " < ", " > ", " <= ", " >= ", " instanceof ", " in ", " == ", " != ", " === ", " !== ",
  " & ", " | ", " ^ ", " && ", " || ", " = ", " *= ", " /= ", " %= ", " += ", " -= ", " <<= ", " >>= ", " >>>= ", " &= ", " ^= ", " |= ", " , ", " ** ", " **= "
];

var leftUnaryOps = [
  "!", "+", "-", "~",
  "void ", "typeof ", "delete ",
  "new ", // but note that "new" can also be a very strange left-binary operator
  "yield " // see http://www.python.org/dev/peps/pep-0342/ .  Often needs to be parenthesized, so there's also a special exprMaker for it.
];

var incDecOps = [
  "++", "--",
];


var specialProperties = [
  "__iterator__", "__count__",
  "__parent__", "__proto__", "constructor", "prototype",
  "wrappedJSObject",
  "arguments", "caller", "callee",
  "toString", "toSource", "valueOf",
  "call", "apply", // ({apply:...}).apply() hits a special case (speculation failure with funapply / funcall bytecode)
  "length",
  "0", "1",
];

// This makes it easier for fuzz-generated code to mess with the fuzzer. Will I regret it?
/*
function addPropertyName(p)
{
  p = "" + p;
  if (
      p != "floor" &&
      p != "random" &&
      p != "parent" && // unsafe spidermonkey shell function, see bug 619064
      true) {
    print("Adding: " + p);
    allPropertyNames.push(p);
  }
}
*/

var exprMakers =
[
  // Increment and decrement
  function(d, b) { return cat([makeLValue(d, b), Random.index(incDecOps)]); },
  function(d, b) { return cat([Random.index(incDecOps), makeLValue(d, b)]); },

  // Other left-unary operators
  function(d, b) { return cat([Random.index(leftUnaryOps), makeExpr(d, b)]); },

  // Methods
  function(d, b) { var id = makeId(d, b); return cat(["/*UUV1*/", "(", id, ".", Random.index(allMethodNames), " = ", makeFunction(d, b), ")"]); },
  function(d, b) { var id = makeId(d, b); return cat(["/*UUV2*/", "(", id, ".", Random.index(allMethodNames), " = ", id, ".", Random.index(allMethodNames), ")"]); },
  function(d, b) { return cat([makeExpr(d, b), ".", Random.index(allMethodNames), "(", makeActualArgList(d, b), ")"]); },
  function(d, b) { return cat([makeExpr(d, b), ".", "valueOf", "(", uneval("number"), ")"]); },

  // Binary operators
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), Random.index(binaryOps), makeExpr(d, b)]); },
  function(d, b) { return cat([makeId(d, b),   Random.index(binaryOps), makeId(d, b)]); },
  function(d, b) { return cat([makeId(d, b),   Random.index(binaryOps), makeId(d, b)]); },
  function(d, b) { return cat([makeId(d, b),   Random.index(binaryOps), makeId(d, b)]); },

  // Ternary operator
  function(d, b) { return cat([makeExpr(d, b), " ? ", makeExpr(d, b), " : ", makeExpr(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b), " ? ", makeExpr(d, b), " : ", makeExpr(d, b)]); },

  // In most contexts, yield expressions must be parenthesized, so including explicitly parenthesized yields makes actually-compiling yields appear more often.
  function(d, b) { return cat(["yield ", makeExpr(d, b)]); },
  function(d, b) { return cat(["(", "yield ", makeExpr(d, b), ")"]); },

  // Array functions (including extras).  The most interesting are map and filter, I think.
  // These are mostly interesting to fuzzers in the sense of "what happens if i do strange things from a filter function?"  e.g. modify the array.. :)
  // This fuzzer isn't the best for attacking this kind of thing, since it's unlikely that the code in the function will attempt to modify the array or make it go away.
  // The second parameter to "map" is used as the "this" for the function.
  function(d, b) { return cat([makeArrayLiteral(d, b), ".", Random.index(["map", "filter", "some", "sort"]) ]); },
  function(d, b) { return cat([makeArrayLiteral(d, b), ".", Random.index(["map", "filter", "some", "sort"]), "(", makeFunction(d, b), ", ", makeExpr(d, b), ")"]); },
  function(d, b) { return cat([makeArrayLiteral(d, b), ".", Random.index(["map", "filter", "some", "sort"]), "(", makeFunction(d, b), ")"]); },

  // RegExp replace.  This is interesting for the same reason as array extras.  Also, in SpiderMonkey, the "this" argument is weird (obj.__parent__?)
  function(d, b) { return cat(["'fafafa'", ".", "replace", "(", "/", "a", "/", "g", ", ", makeFunction(d, b), ")"]); },

  // Containment in an array or object (or, if this happens to end up on the LHS of an assignment, destructuring)
  function(d, b) { return cat(["[", makeExpr(d, b), "]"]); },
  function(d, b) { return cat(["(", "{", makeId(d, b), ": ", makeExpr(d, b), "}", ")"]); },

  // Functions: called immediately/not
  function(d, b) { return makeFunction(d, b); },
  function(d, b) { return makeFunction(d, b) + ".prototype"; },
  function(d, b) { return cat(["(", makeFunction(d, b), ")", "(", makeActualArgList(d, b), ")"]); },

  // Try to call things that may or may not be functions.
  function(d, b) { return cat([     makeExpr(d, b),          "(", makeActualArgList(d, b), ")"]); },
  function(d, b) { return cat(["(", makeExpr(d, b),     ")", "(", makeActualArgList(d, b), ")"]); },
  function(d, b) { return cat([     makeFunction(d, b),      "(", makeActualArgList(d, b), ")"]); },

  // Try to test function.call heavily.
  function(d, b) { return cat(["(", makeFunction(d, b), ")", ".", "call", "(", makeExpr(d, b), ", ", makeActualArgList(d, b), ")"]); },

  // Binary "new", with and without clarifying parentheses, with expressions or functions
  function(d, b) { return cat(["new ",      makeExpr(d, b),          "(", makeActualArgList(d, b), ")"]); },
  function(d, b) { return cat(["new ", "(", makeExpr(d, b), ")",     "(", makeActualArgList(d, b), ")"]); },

  function(d, b) { return cat(["new ",      makeFunction(d, b),      "(", makeActualArgList(d, b), ")"]); },
  function(d, b) { return cat(["new ", "(", makeFunction(d, b), ")", "(", makeActualArgList(d, b), ")"]); },

  // Sometimes we do crazy stuff, like putting a statement where an expression should go.  This frequently causes a syntax error.
  function(d, b) { return stripSemicolon(makeLittleStatement(d, b)); },
  function(d, b) { return ""; },

  // Let expressions -- note the lack of curly braces.
  function(d, b) { var v = makeNewId(d, b); return cat(["let ", "(", v,                            ") ", makeExpr(d - 1, b.concat([v]))]); },
  function(d, b) { var v = makeNewId(d, b); return cat(["let ", "(", v, " = ", makeExpr(d - 1, b), ") ", makeExpr(d - 1, b.concat([v]))]); },
  function(d, b) {                          return cat(["let ", "(", makeLetHead(d, b),            ") ", makeExpr(d, b)]); },

  // Comments and whitespace
  function(d, b) { return cat([" /* Comment */", makeExpr(d, b)]); },
  function(d, b) { return cat(["\n", makeExpr(d, b)]); }, // perhaps trigger semicolon insertion and stuff
  function(d, b) { return cat([makeExpr(d, b), "\n"]); },

  // LValue as an expression
  function(d, b) { return cat([makeLValue(d, b)]); },

  // Assignment (can be destructuring)
  function(d, b) { return cat([     makeLValue(d, b),      " = ", makeExpr(d, b)     ]); },
  function(d, b) { return cat([     makeLValue(d, b),      " = ", makeExpr(d, b)     ]); },
  function(d, b) { return cat(["(", makeLValue(d, b),      " = ", makeExpr(d, b), ")"]); },
  function(d, b) { return cat(["(", makeLValue(d, b), ")", " = ", makeExpr(d, b)     ]); },

  // Destructuring assignment
  function(d, b) { return cat([     makeDestructuringLValue(d, b),      " = ", makeExpr(d, b)     ]); },
  function(d, b) { return cat([     makeDestructuringLValue(d, b),      " = ", makeExpr(d, b)     ]); },
  function(d, b) { return cat(["(", makeDestructuringLValue(d, b),      " = ", makeExpr(d, b), ")"]); },
  function(d, b) { return cat(["(", makeDestructuringLValue(d, b), ")", " = ", makeExpr(d, b)     ]); },

  // Destructuring assignment with lots of group assignment
  function(d, b) { return cat([makeDestructuringLValue(d, b), " = ", makeDestructuringLValue(d, b)]); },

  // Modifying assignment, with operators that do various coercions
  function(d, b) { return cat([makeLValue(d, b), Random.index(["|=", "%=", "+=", "-="]), makeExpr(d, b)]); },

  // Watchpoints (similar to setters)
  function(d, b) { return cat([makeExpr(d, b), ".", "watch", "(", makePropertyName(d, b), ", ", makeFunction(d, b), ")"]); },
  function(d, b) { return cat([makeExpr(d, b), ".", "unwatch", "(", makePropertyName(d, b), ")"]); },

  // ES5 getter/setter syntax, imperative (added in Gecko 1.9.3?)
  function(d, b) { return cat(["Object.defineProperty", "(", makeId(d, b), ", ", makePropertyName(d, b), ", ", makePropertyDescriptor(d, b), ")"]); },

  // Old getter/setter syntax, imperative
  function(d, b) { return cat([makeExpr(d, b), ".", "__defineGetter__", "(", uneval(makeId(d, b)), ", ", makeFunction(d, b), ")"]); },
  function(d, b) { return cat([makeExpr(d, b), ".", "__defineSetter__", "(", uneval(makeId(d, b)), ", ", makeFunction(d, b), ")"]); },
  function(d, b) { return cat(["this", ".", "__defineGetter__", "(", uneval(makeId(d, b)), ", ", makeFunction(d, b), ")"]); },
  function(d, b) { return cat(["this", ".", "__defineSetter__", "(", uneval(makeId(d, b)), ", ", makeFunction(d, b), ")"]); },

  // Object literal
  function(d, b) { return cat(["(", "{", makeObjLiteralPart(d, b), " }", ")"]); },
  function(d, b) { return cat(["(", "{", makeObjLiteralPart(d, b), ", ", makeObjLiteralPart(d, b), " }", ")"]); },

  // Test js_ReportIsNotFunction heavily.
  function(d, b) { return "(p={}, (p.z = " + makeExpr(d, b) + ")())"; },

  // Test js_ReportIsNotFunction heavily.
  // Test decompilation for ".keyword" a bit.
  // Test throwing-into-generator sometimes.
  function(d, b) { return cat([makeExpr(d, b), ".", "throw", "(", makeExpr(d, b), ")"]); },
  function(d, b) { return cat([makeExpr(d, b), ".", "yoyo",   "(", makeExpr(d, b), ")"]); },

  // Test eval in various contexts. (but avoid clobbering eval)
  // Test the special "obj.eval" and "eval(..., obj)" forms.
  function(d, b) { return makeExpr(d, b) + ".eval(" + uneval(makeScriptForEval(d, b)) + ")"; },
  function(d, b) { return "eval(" + uneval(makeScriptForEval(d, b)) + ")"; },
  function(d, b) { return "eval(" + uneval(makeScriptForEval(d, b)) + ", " + makeExpr(d, b) + ")"; },

  // Uneval needs more testing than it will get accidentally.  No cat() because I don't want uneval clobbered (assigned to) accidentally.
  function(d, b) { return "(uneval(" + makeExpr(d, b) + "))"; },

  // Constructors.  No cat() because I don't want to screw with the constructors themselves, just call them.
  function(d, b) { return "new " + Random.index(constructors) + "(" + makeActualArgList(d, b) + ")"; },
  function(d, b) { return          Random.index(constructors) + "(" + makeActualArgList(d, b) + ")"; },

  // Unary Math functions
  function (d, b) { return "Math." + Random.index(unaryMathFunctions) + "(" + makeExpr(d, b)   + ")"; },
  function (d, b) { return "Math." + Random.index(unaryMathFunctions) + "(" + makeNumber(d, b) + ")"; },

  // Binary Math functions
  function (d, b) { return "Math." + Random.index(binaryMathFunctions) + "(" + makeExpr(d, b)   + ", " + makeExpr(d, b)   + ")"; },
  function (d, b) { return "Math." + Random.index(binaryMathFunctions) + "(" + makeExpr(d, b)   + ", " + makeNumber(d, b) + ")"; },
  function (d, b) { return "Math." + Random.index(binaryMathFunctions) + "(" + makeNumber(d, b) + ", " + makeExpr(d, b)   + ")"; },
  function (d, b) { return "Math." + Random.index(binaryMathFunctions) + "(" + makeNumber(d, b) + ", " + makeNumber(d, b) + ")"; },

  // Harmony proxy creation: object, function without constructTrap, function with constructTrap
  function(d, b) { return makeId(d, b) + " = " + "Proxy.create(" + makeProxyHandler(d, b) + ", " + makeExpr(d, b) + ")"; },
  function(d, b) { return makeId(d, b) + " = " + "Proxy.createFunction(" + makeProxyHandler(d, b) + ", " + makeFunction(d, b) + ")"; },
  function(d, b) { return makeId(d, b) + " = " + "Proxy.createFunction(" + makeProxyHandler(d, b) + ", " + makeFunction(d, b) + ", " + makeFunction(d, b) + ")"; },

  function(d, b) { return cat(["delete", " ", makeId(d, b), ".", makeId(d, b)]); },

  // Spidermonkey: global ES5 strict mode
  function(d, b) { return "(void options('strict_mode'))"; },

  // Spidermonkey: additional "strict" warnings, distinct from ES5 strict mode
  function(d, b) { return "(void options('strict'))"; },

  // Spidermonkey: versions
  function(d, b) { return "(void version(" + Random.index([170, 180, 185]) + "))"; },

  // More special Spidermonkey shell functions
  // (Note: functions without returned objects or visible side effects go in testing-functions.js, in order to allow presence/absence differential testing.)
  //  function(d, b) { return "dumpObject(" + makeExpr(d, b) + ")" } }, // crashes easily, bug 836603
  function(d, b) { return "(void shapeOf(" + makeExpr(d, b) + "))"; },
  function(d, b) { return "intern(" + makeExpr(d, b) + ")"; },
  function(d, b) { return "allocationMarker()"; },
  function(d, b) { return "timeout(1800)"; }, // see https://bugzilla.mozilla.org/show_bug.cgi?id=840284#c12 -- replace when bug 831046 is fixed
  function(d, b) { return "(makeFinalizeObserver('tenured'))"; },
  function(d, b) { return "(makeFinalizeObserver('nursery'))"; },

  makeRegexUseExpr,
  makeShapeyValue,
  makeIterable,
  function(d, b) { return makeMathExpr(d + rnd(3), b); },
];


var fuzzTestingFunctions = fuzzTestingFunctionsCtor(!jsshell, fuzzTestingFunctionArg, fuzzTestingFunctionArg);

// Ensure that even if makeExpr returns "" or "1, 2", we only pass one argument to functions like schedulegc
// (null || (" + makeExpr(d - 2, b) + "))
// Darn, only |this| and local variables are safe: an expression with side effects breaks the statement-level compareJIT hack
function fuzzTestingFunctionArg(d, b) { return "this"; }

function makeTestingFunctionCall(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var callStatement = Random.index(fuzzTestingFunctions.testingFunctions)(d, b);

  // Set the 'last expression evaluated' to undefined, in case we're in an eval
  // context, and the function throws in one run but not in another.
  var callBlock = "{ void 0; " + callStatement + " }";

  if (jsshell && rnd(5) === 0) {
    // Differential testing hack!
    // The idea here: make compareJIT tell us when functions like gc() surprise
    // us with visible side effects.
    // * Functions in testing-functions.js are chosen to be ones with no visible
    //   side effects except for return values (voided) or throwing (caught).
    // * This condition is controlled by --no-asmjs, which compareJIT.py flips.
    //     (A more principled approach would be to have compareJIT set an environment
    //     variable and read it here using os.getenv(), but os is not available
    //     when running with --fuzzing-safe...)
    // * The extra braces prevent a stray "else" from being associated with this "if".
    // * The 'void 0' at the end ensures the last expression-statement is consistent
    //     (needed because |eval| returns that as its result)
    var cond = (rnd(2) ? "!" : "") + "isAsmJSCompilationAvailable()";
    return "{ if (" + cond + ") " + callBlock + " void 0; }";
  }

  return callBlock;
}


// SpiderMonkey shell (but not xpcshell) has an "evalcx" function and a "newGlobal" function.
// This tests sandboxes and cross-compartment wrappers.
if (typeof evalcx == "function") {
  exprMakers = exprMakers.concat([
    function(d, b) { return makeGlobal(d, b); },
    function(d, b) { return "evalcx(" + uneval(makeScriptForEval(d, b)) + ", " + makeExpr(d, b) + ")"; },
    function(d, b) { return "evalcx(" + uneval(makeScriptForEval(d, b)) + ", " + makeGlobal(d, b) + ")"; },
  ]);
}

// xpcshell (but not SpiderMonkey shell) has some XPC wrappers available.
if (typeof XPCNativeWrapper == "function") {
  exprMakers = exprMakers.extend([
    function(d, b) { return "new XPCNativeWrapper(" + makeExpr(d, b) + ")"; },
    function(d, b) { return "new XPCSafeJSObjectWrapper(" + makeExpr(d, b) + ")"; },
  ]);
}

function makeNewGlobalArg(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  // Make an options object to pass to the |newGlobal| shell builtin.
  var propStrs = [];
  if (rnd(2))
    propStrs.push("sameZoneAs: " + makeExpr(d - 1, b));
  if (rnd(2))
    propStrs.push("cloneSingletons: " + makeBoolean(d - 1, b));
  if (rnd(2))
    propStrs.push("disableLazyParsing: " + makeBoolean(d - 1, b));
  return "{ " + propStrs.join(", ") + " }";
}

function makeGlobal(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (rnd(10))
    return "this";

  var gs;
  switch(rnd(4)) {
    case 0:  gs = "evalcx('')"; break;
    case 1:  gs = "evalcx('lazy')"; break;
    default: gs = "newGlobal(" + makeNewGlobalArg(d - 1, b) + ")"; break;
  }

  if (rnd(2))
    gs = "fillShellSandbox(" + gs + ")";

  return gs;
}

if (xpcshell) {
  exprMakers = exprMakers.concat([
    function(d, b) { var n = rnd(4); return "newGeckoSandbox(" + n + ")"; },
    function(d, b) { var n = rnd(4); return "s" + n + " = newGeckoSandbox(" + n + ")"; },
    // FIXME: Doesn't this need to be Components.utils.evalInSandbox?
    function(d, b) { var n = rnd(4); return "evalInSandbox(" + uneval(makeStatement(d, b)) + ", newGeckoSandbox(" + n + "))"; },
    function(d, b) { var n = rnd(4); return "evalInSandbox(" + uneval(makeStatement(d, b)) + ", s" + n + ")"; },
    function(d, b) { return "evalInSandbox(" + uneval(makeStatement(d, b)) + ", " + makeExpr(d, b) + ")"; },
    function(d, b) { return "(Components.classes ? quit() : gc()); }"; },
  ]);
}


function makeShapeyConstructor(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);
  var argName = uniqueVarName();
  var t = rnd(4) ? "this" : argName;
  var funText = "function shapeyConstructor(" + argName + "){" + directivePrologue();
  var bp = b.concat([argName]);

  var nPropNames = rnd(6) + 1;
  var propNames = [];
  for (var i = 0; i < nPropNames; ++i) {
    propNames[i] = makePropertyName(d, b);
  }

  var nStatements = rnd(11);
  for (var i = 0; i < nStatements; ++i) {
    var propName = Random.index(propNames);
    var tprop = t + "[" + propName + "]";
    if (rnd(5) === 0) {
      funText += "if (" + (rnd(2) ? argName : makeExpr(d, bp)) + ") ";
    }
    switch(rnd(8)) {
      case 0:  funText += "delete " + tprop + ";"; break;
      case 1:  funText += "Object.defineProperty(" + t + ", " + (rnd(2) ? propName : makePropertyName(d, b)) + ", " + makePropertyDescriptor(d, bp) + ");"; break;
      case 2:  funText += "{ " + makeStatement(d, bp) + " } "; break;
      case 3:  funText += tprop + " = " + makeExpr(d, bp)        + ";"; break;
      case 4:  funText += tprop + " = " + makeFunction(d, bp)    + ";"; break;
      case 5:  funText += "for (var ytq" + uniqueVarName() + " in " + t + ") { }"; break;
      case 6:  funText += "Object." + Random.index(["preventExtensions","seal","freeze"]) + "(" + t + ");"; break;
      default: funText += tprop + " = " + makeShapeyValue(d, bp) + ";"; break;
    }
  }
  funText += "return " + t + "; }";
  return funText;
}


var propertyNameMakers = Random.weighted([
  { w: 1,  v: function(d, b) { return makeExpr(d - 1, b); } },
  { w: 1,  v: function(d, b) { return maybeNeg() + rnd(20); } },
  { w: 1,  v: function(d, b) { return '"' + maybeNeg() + rnd(20) + '"'; } },
  { w: 1,  v: function(d, b) { return "new String(" + '"' + maybeNeg() + rnd(20) + '"' + ")"; } },
  { w: 5,  v: function(d, b) { return simpleSource(Random.index(specialProperties)); } },
  { w: 1,  v: function(d, b) { return simpleSource(makeId(d - 1, b)); } },
  { w: 5,  v: function(d, b) { return simpleSource(Random.index(allMethodNames)); } },
]);

function maybeNeg() { return rnd(5) ? "" : "-"; }

function makePropertyName(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  return (Random.index(propertyNameMakers))(d, b);
}

function makeShapeyConstructorLoop(d, b)
{
  var a = makeIterable(d, b);
  var v = makeNewId(d, b);
  var v2 = uniqueVarName(d, b);
  var bvv = b.concat([v, v2]);
  return makeShapeyConstructor(d - 1, b) +
    "/*tLoopC*/for (let " + v + " of " + a + ") { " +
     "try{" +
       "let " + v2 + " = " + Random.index(["new ", ""]) + "shapeyConstructor(" + v + "); print('EETT'); " +
       //"print(uneval(" + v2 + "));" +
       makeStatement(d - 2, bvv) +
     "}catch(e){print('TTEE ' + e); }" +
  " }";
}


function makePropertyDescriptor(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var s = "({";

  switch(rnd(3)) {
  case 0:
    // Data descriptor. Can have 'value' and 'writable'.
    if (rnd(2)) s += "value: " + makeExpr(d, b) + ", ";
    if (rnd(2)) s += "writable: " + makeBoolean(d, b) + ", ";
    break;
  case 1:
    // Accessor descriptor. Can have 'get' and 'set'.
    if (rnd(2)) s += "get: " + makeFunction(d, b) + ", ";
    if (rnd(2)) s += "set: " + makeFunction(d, b) + ", ";
    break;
  default:
  }

  if (rnd(2)) s += "configurable: " + makeBoolean(d, b) + ", ";
  if (rnd(2)) s += "enumerable: " + makeBoolean(d, b) + ", ";

  // remove trailing comma
  if (s.length > 2)
    s = s.substr(0, s.length - 2);

  s += "})";
  return s;
}

function makeBoolean(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);
  switch(rnd(4)) {
    case 0:   return "true";
    case 1:   return "false";
    case 2:   return makeExpr(d - 2, b);
    default:  var m = loopModulo(); return "(" + Random.index(b) + " % " + m + Random.index([" == ", " != "]) + rnd(m) + ")";
  }
}


function makeObjLiteralPart(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  switch(rnd(8))
  {
    // Literal getter/setter
    // Surprisingly, string literals, integer literals, and float literals are also good!
    // (See https://bugzilla.mozilla.org/show_bug.cgi?id=520696.)
    case 2: return cat([" get ", makeObjLiteralName(d, b), maybeName(d, b), "(", makeFormalArgList(d - 1, b), ")", makeFunctionBody(d, b)]);
    case 3: return cat([" set ", makeObjLiteralName(d, b), maybeName(d, b), "(", makeFormalArgList(d - 1, b), ")", makeFunctionBody(d, b)]);

    case 4: return "/*toXFun*/" + cat([Random.index(["toString", "toSource", "valueOf"]), ": ", makeToXFunction(d - 1, b)]);

    default: return cat([makeObjLiteralName(d, b), ": ", makeExpr(d, b)]);
  }
}

function makeToXFunction(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  switch(rnd(4)) {
    case 0:  return "function() { return " + makeExpr(d, b) + "; }";
    case 1:  return "function() { return this; }";
    case 2:  return makeEvilCallback(d, b);
    default: return makeFunction(d, b);
  }
}


function makeObjLiteralName(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  switch(rnd(6))
  {
    case 0:  return simpleSource(makeNumber(d, b)); // a quoted number
    case 1:  return makeNumber(d, b);
    case 2:  return Random.index(allPropertyNames);
    case 3:  return Random.index(specialProperties);
    default: return makeId(d, b);
  }
}


function makeFunction(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  d = d - 1;

  if(rnd(5) === 1)
    return makeExpr(d, b);

  if (rnd(4) === 1)
    return Random.index(builtinFunctions);

  return (Random.index(functionMakers))(d, b);
}


function maybeName(d, b)
{
  if (rnd(2) === 0)
    return " " + makeId(d, b) + " ";
  else
    return "";
}

function directivePrologue()
{
  var s = "";
  if (rnd(3) === 0)
    s += '"use strict"; ';
  if (rnd(30) === 0)
    s += '"use asm"; ';
  return s;
}

function makeFunctionBody(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  switch(rnd(5)) {
    case 0:  return cat([" { ", directivePrologue(), makeStatement(d - 1, b),   " } "]);
    case 1:  return cat([" { ", directivePrologue(), "return ", makeExpr(d, b), " } "]);
    case 2:  return cat([" { ", directivePrologue(), "yield ",  makeExpr(d, b), " } "]);
    case 3:  return '"use asm"; ' + asmJSInterior([]);
    default: return makeExpr(d, b); // make an "expression closure"
  }
}


var functionMakers = [
  // Note that a function with a name is sometimes considered a statement rather than an expression.

  makeFunOnCallChain,
  makeMathFunction,
  makeMathyFunRef,

  // Functions and expression closures
  function(d, b) { var v = makeNewId(d, b); return cat(["function", " ", maybeName(d, b), "(", v,                       ")", makeFunctionBody(d, b.concat([v]))]); },
  function(d, b) {                          return cat(["function", " ", maybeName(d, b), "(", makeFormalArgList(d, b), ")", makeFunctionBody(d, b)]); },

  // Arrow functions with one argument (no parens needed) (no destructuring allowed in this form?)
  function(d, b) { var v = makeNewId(d, b); return cat([     v,                            " => ", makeFunctionBody(d, b.concat([v]))]); },

  // Arrow functions with multiple arguments
  function(d, b) {                          return cat(["(", makeFormalArgList(d, b), ")", " => ", makeFunctionBody(d, b)]); },

  // The identity function
  function(d, b) { return "function(q) { " + directivePrologue() + "return q; }"; },
  function(d, b) { return "q => q"; },

  // A function that does something
  function(d, b) { return "function(y) { " + directivePrologue() + makeStatement(d, b.concat(["y"])) + " }"; },

  // A function that computes something
  function(d, b) { return "function(y) { " + directivePrologue() + "return " + makeExpr(d, b.concat(["y"])) + " }"; },

  // A generator that does something
  function(d, b) { return "function(y) { " + directivePrologue() + "yield y; " + makeStatement(d, b.concat(["y"])) + "; yield y; }"; },

  // A generator expression -- kinda a function??
  function(d, b) { return "(1 for (x in []))"; },

  // A simple wrapping pattern
  function(d, b) { return "/*wrap1*/(function(){ " + directivePrologue() + makeStatement(d, b) + "return " + makeFunction(d, b) + "})()"; },

  // Wrapping with upvar: escaping, may or may not be modified
  function(d, b) { var v1 = uniqueVarName(); var v2 = uniqueVarName(); return "/*wrap2*/(function(){ " + directivePrologue() + "var " + v1 + " = " + makeExpr(d, b) + "; var " + v2 + " = " + makeFunction(d, b.concat([v1])) + "; return " + v2 + ";})()"; },

  // Wrapping with upvar: non-escaping
  function(d, b) { var v1 = uniqueVarName(); var v2 = uniqueVarName(); return "/*wrap3*/(function(){ " + directivePrologue() + "var " + v1 + " = " + makeExpr(d, b) + "; (" + makeFunction(d, b.concat([v1])) + ")(); })"; },

  // Apply, call
  function(d, b) { return "(" + makeFunction(d-1, b) + ").apply"; },
  function(d, b) { return "(" + makeFunction(d-1, b) + ").call"; },

  // Bind
  function(d, b) { return "(" + makeFunction(d-1, b) + ").bind"; },
  function(d, b) { return "(" + makeFunction(d-1, b) + ").bind(" + makeActualArgList(d, b) + ")"; },

  // Methods with known names
  function(d, b) { return cat([makeExpr(d, b), ".", Random.index(allMethodNames)]); },

  // Special functions that might have interesting results, especially when called "directly" by things like string.replace or array.map.
  function(d, b) { return "eval"; }, // eval is interesting both for its "no indirect calls" feature and for the way it's implemented in spidermonkey (a special bytecode).
  function(d, b) { return "(let (e=eval) e)"; },
  function(d, b) { return "new Function"; }, // this won't be interpreted the same way for each caller of makeFunction, but that's ok
  function(d, b) { return "(new Function(" + uneval(makeStatement(d, b)) + "))"; },
  function(d, b) { return "Function"; }, // without "new"
  function(d, b) { return "decodeURI"; },
  function(d, b) { return "decodeURIComponent"; },
  function(d, b) { return "encodeURI"; },
  function(d, b) { return "encodeURIComponent"; },
  function(d, b) { return "neuter"; },
  function(d, b) { return "objectEmulatingUndefined"; }, // spidermonkey shell object like the browser's document.all
  function(d, b) { return "offThreadCompileScript"; },
  function(d, b) { return "runOffThreadScript"; },
  function(d, b) { return makeProxyHandlerFactory(d, b); },
  function(d, b) { return makeShapeyConstructor(d, b); },
  function(d, b) { return Random.index(typedArrayConstructors); },
  function(d, b) { return Random.index(constructors); },
];

if (typeof XPCNativeWrapper == "function") {
  functionMakers = functionMakers.concat([
    function(d, b) { return "XPCNativeWrapper"; },
    function(d, b) { return "XPCSafeJSObjectWrapper"; },
  ]);
}

if (typeof oomTest == "function" && engine != ENGINE_SPIDERMONKEY_MOZILLA45) {
  functionMakers = functionMakers.concat([
    function(d, b) { return "oomTest"; }
  ]);
}



var typedArrayConstructors = [
  "Int8Array",
  "Uint8Array",
  "Int16Array",
  "Uint16Array",
  "Int32Array",
  "Uint32Array",
  "Float32Array",
  "Float64Array",
  "Uint8ClampedArray"
];

function makeTypedArrayStatements(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (d < 0) return "";

  var numViews = rnd(d) + 1;
  var numExtraStatements = rnd(d) + 1;
  var buffer = uniqueVarName();
  var bufferSize = (1 + rnd(2)) * (1 + rnd(2)) * (1 + rnd(2)) * rnd(5);
  var statements = "var " + buffer + " = new " + arrayBufferType() + "(" + bufferSize + "); ";
  var bv = b.concat([buffer]);
  for (var j = 0; j < numViews; ++j) {
    var view = buffer + "_" + j;
    var type = Random.index(typedArrayConstructors);
    statements += "var " + view + " = new " + type + "(" + buffer + "); ";
    bv.push(view);
    var view_0 = view + "[0]";
    bv.push(view_0);
    if (rnd(3) === 0)
      statements += "print(" + view_0 + "); ";
    if (rnd(3))
      statements += view_0 + " = " + makeNumber(d - 2, b) + "; ";
    bv.push(view + "[" + rnd(11) + "]");
  }
  for (var j = 0; j < numExtraStatements; ++j) {
    statements += makeStatement(d - numExtraStatements, bv);
  }
  return statements;
}

function makeNumber(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var signStr = rnd(2) ? "-" : "";

  switch(rnd(60)) {
    case 0:  return makeExpr(d - 2, b);
    case 1:  return signStr + "0";
    case 2:  return signStr + (rnd(1000) / 1000);
    case 3:  return signStr + (rnd(0xffffffff) / 2);
    case 4:  return signStr + rnd(0xffffffff);
    case 5:  return Random.index(["0.1", ".2", "3", "1.3", "4.", "5.0000000000000000000000",
      "1.2e3", "1e81", "1e+81", "1e-81", "1e4", "0", "-0", "(-0)", "-1", "(-1)", "0x99", "033",
      "3.141592653589793", "3/0", "-3/0", "0/0", "0x2D413CCC", "0x5a827999", "0xB504F332",
      "(0x50505050 >> 1)",
      // Boundaries of int, signed, unsigned (near +/- 2^31, +/- 2^32)
      "0x07fffffff",  "0x080000000",  "0x080000001",
      "-0x07fffffff", "-0x080000000", "-0x080000001",
      "0x0ffffffff",  "0x100000000",  "0x100000001",
      "-0x0ffffffff", "-0x100000000",  "-0x100000001",
      // Boundaries of double
      "Number.MIN_VALUE", "-Number.MIN_VALUE",
      "Number.MAX_VALUE", "-Number.MAX_VALUE",
      // Boundaries of maximum safe integer
      "Number.MIN_SAFE_INTEGER", "-Number.MIN_SAFE_INTEGER",
      "-(2**53-2)", "-(2**53)", "-(2**53+2)",
      "Number.MAX_SAFE_INTEGER", "-Number.MAX_SAFE_INTEGER",
      "2**53-2", "2**53", "2**53+2",
      // See bug 1350097
      "0.000000000000001", "1.7976931348623157e308",
    ]);
    case 6:  return signStr + (Math.pow(2, rnd(66)) + (rnd(3) - 1));
    default: return signStr + rnd(30);
  }
}


function makeLetHead(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var items = (d > 0 || rnd(2) === 0) ? rnd(10) + 1 : 1;
  var result = "";

  for (var i = 0; i < items; ++i) {
    if (i > 0)
      result += ", ";
    result += makeLetHeadItem(d - i, b);
  }

  return result;
}

function makeLetHeadItem(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  d = d - 1;

  if (d < 0 || rnd(2) === 0)
    return rnd(2) ? uniqueVarName() : makeId(d, b);
  else if (rnd(5) === 0)
    return makeDestructuringLValue(d, b) + " = " + makeExpr(d, b);
  else
    return makeId(d, b) + " = " + makeExpr(d, b);
}


function makeActualArgList(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var nArgs = rnd(3);

  if (nArgs == 0)
    return "";

  var argList = makeExpr(d, b);

  for (var i = 1; i < nArgs; ++i)
    argList += ", " + makeExpr(d - i, b);

  return argList;
}

function makeFormalArgList(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var argList = [];

  var nArgs = rnd(5) ? rnd(3) : rnd(100);
  for (var i = 0; i < nArgs; ++i) {
    argList.push(makeFormalArg(d - i, b));
  }

  if (rnd(5) === 0) {
    // https://developer.mozilla.org/en-US/docs/JavaScript/Reference/rest_parameters
    argList.push("..." + makeId(d, b));
  }

  return argList.join(", ");
}

function makeFormalArg(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (rnd(8) === 1)
    return makeDestructuringLValue(d, b);

  return makeId(d, b) + (rnd(5) ? "" : " = " + makeExpr(d, b));
}


function makeNewId(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  return Random.index(["a", "b", "c", "d", "e", "w", "x", "y", "z"]);
}

function makeId(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (rnd(3) === 1 && b.length)
    return Random.index(b);

  switch(rnd(200))
  {
  case 0:
    return makeTerm(d, b);
  case 1:
    return makeExpr(d, b);
  case 2: case 3: case 4: case 5:
    return makeLValue(d, b);
  case 6: case 7:
    return makeDestructuringLValue(d, b);
  case 8: case 9: case 10:
    // some keywords that can be used as identifiers in some contexts (e.g. variables, function names, argument names)
    // but that's annoying, and some of these cause lots of syntax errors.
    return Random.index(["get", "set", "getter", "setter", "delete", "let", "yield", "of"]);
  case 11: case 12: case 13:
    return "this." + makeId(d, b);
  case 14: case 15: case 16:
    return makeObjLiteralName(d - 1, b);
  case 17: case 18:
    return makeId(d - 1, b);
  case 19:
    return " "; // [k, v] becomes [, v] -- test how holes are handled in unexpected destructuring
  case 20:
    return "this";
  }

  return Random.index(["a", "b", "c", "d", "e", "w", "x", "y", "z",
                 "window", "eval", "\u3056", "NaN",
//                 "valueOf", "toString", // e.g. valueOf getter :P // bug 381242, etc
                  ]);

  // window is a const (in the browser), so some attempts to redeclare it will cause errors

  // eval is interesting because it cannot be called indirectly. and maybe also because it has its own opcode in jsopcode.tbl.
  // but bad things happen if you have "eval setter". so let's not put eval in this list.
}


function makeComprehension(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (d < 0)
    return "";

  switch(rnd(7)) {
  case 0:
    return "";
  case 1:
    return cat([" for ",          "(", makeForInLHS(d, b), " in ", makeExpr(d - 2, b),     ")"]) + makeComprehension(d - 1, b);
  // |for each| to be removed: https://bugzilla.mozilla.org/show_bug.cgi?id=1083470
  case 2:
    return cat([" for ", "each ", "(", makeId(d, b),       " in ", makeExpr(d - 2, b),     ")"]) + makeComprehension(d - 1, b);
  case 3:
    return cat([" for ", "each ", "(", makeId(d, b),       " in ", makeIterable(d - 2, b), ")"]) + makeComprehension(d - 1, b);
  case 4:
    return cat([" for ",          "(", makeId(d, b),       " of ", makeExpr(d - 2, b),     ")"]) + makeComprehension(d - 1, b);
  case 5:
    return cat([" for ",          "(", makeId(d, b),       " of ", makeIterable(d - 2, b), ")"]) + makeComprehension(d - 1, b);
  default:
    return cat([" if ", "(", makeExpr(d - 2, b), ")"]); // this is always last (and must be preceded by a "for", oh well)
  }
}




// for..in LHS can be a single variable OR it can be a destructuring array of exactly two elements.
function makeForInLHS(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

// JS 1.7 only (removed in JS 1.8)
//
//  if (version() == 170 && rnd(4) === 0)
//    return cat(["[", makeLValue(d, b), ", ", makeLValue(d, b), "]"]);

  return makeLValue(d, b);
}


function makeLValue(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (d <= 0 || (rnd(2) === 1))
    return makeId(d - 1, b);

  d = rnd(d); // !

  return (Random.index(lvalueMakers))(d, b);
}


var lvalueMakers = [
  // Simple variable names :)
  function(d, b) { return cat([makeId(d, b)]); },

  // Parenthesized lvalues
  function(d, b) { return cat(["(", makeLValue(d, b), ")"]); },

  // Destructuring
  function(d, b) { return makeDestructuringLValue(d, b); },
  function(d, b) { return "(" + makeDestructuringLValue(d, b) + ")"; },

  // Certain functions can act as lvalues!  See JS_HAS_LVALUE_RETURN in js engine source.
  function(d, b) { return cat([makeId(d, b), "(", makeExpr(d, b), ")"]); },
  function(d, b) { return cat(["(", makeExpr(d, b), ")", "(", makeExpr(d, b), ")"]); },

  // Builtins
  function(d, b) { return Random.index(builtinProperties); },
  function(d, b) { return Random.index(builtinObjectNames); },

  // Arguments object, which can alias named parameters to the function
  function(d, b) { return "arguments"; },
  function(d, b) { return cat(["arguments", "[", makePropertyName(d, b), "]"]); },
  function(d, b) { return makeFunOnCallChain(d, b) + ".arguments"; }, // read-only arguments object

  // Property access / index into array
  function(d, b) { return cat([makeExpr(d, b),  ".", makeId(d, b)]); },
  function(d, b) { return cat([makeExpr(d, b),  ".", "__proto__"]); },
  function(d, b) { return cat([makeExpr(d, b), "[", makePropertyName(d, b), "]"]); },

  // Throws, but more importantly, tests js_DecompileValueGenerator in various contexts.
  function(d, b) { return "this.zzz.zzz"; },

  // Intentionally bogus, but not quite garbage.
  function(d, b) { return makeExpr(d, b); },
];


function makeDestructuringLValue(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  d = d - 1;

  if (d < 0 || rnd(4) === 1)
    return makeId(d, b);

  if (rnd(6) === 1)
    return makeLValue(d, b);

  return (Random.index(destructuringLValueMakers))(d, b);
}

var destructuringLValueMakers = [
  // destructuring assignment: arrays
  function(d, b)
  {
    var len = rnd(d, b);
    if (len == 0)
      return "[]";

    var Ti = [];
    Ti.push("[");
    Ti.push(maybeMakeDestructuringLValue(d, b));
    for (var i = 1; i < len; ++i) {
      Ti.push(", ");
      Ti.push(maybeMakeDestructuringLValue(d, b));
    }

    Ti.push("]");

    return cat(Ti);
  },

  // destructuring assignment: objects
  function(d, b)
  {
    var len = rnd(d, b);
    if (len == 0)
      return "{}";
    var Ti = [];
    Ti.push("{");
    for (var i = 0; i < len; ++i) {
      if (i > 0)
        Ti.push(", ");
      Ti.push(makeId(d, b));
      if (rnd(3)) {
        Ti.push(": ");
        Ti.push(makeDestructuringLValue(d, b));
      } // else, this is a shorthand destructuring, treated as "id: id".
    }
    Ti.push("}");

    return cat(Ti);
  }
];

// Allow "holes".
function maybeMakeDestructuringLValue(d, b)
{
  if (rnd(2) === 0)
    return "";

  return makeDestructuringLValue(d, b);
}



function makeTerm(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  return (Random.index(termMakers))(d, b);
}

var termMakers = [
  // Variable names
  function(d, b) { return makeId(d, b); },

  // Simple literals (no recursion required to make them)
  function(d, b) { return Random.index([
    // Arrays
    "[]", "[1]", "[[]]", "[[1]]", "[,]", "[,,]", "[1,,]",
    // Objects
    "{}", "({})", "({a1:1})",
    // Possibly-destructuring arrays
    "[z1]", "[z1,,]", "[,,z1]",
    // Possibly-destructuring objects
    "({a2:z2})",
    "function(id) { return id }",
    "function ([y]) { }",
    "(function ([y]) { })()",

    "arguments",
    "Math",
    "this",
    "length",

    '"\u03A0"', // unicode not escaped
    ]);
  },
  makeNumber,
  function(d, b) { return Random.index([ "true", "false", "undefined", "null"]); },
  function(d, b) { return Random.index([ "this", "window" ]); },
  function(d, b) { return Random.index([" \"\" ", " '' "]); },
  randomUnitStringLiteral, // unicode escaped
  function(d, b) { return Random.index([" /x/ ", " /x/g "]); },
  makeRegex,
];

function randomUnitStringLiteral()
{
  var s = "\"\\u";
  for (var i = 0; i < 4; ++i) {
    s += "0123456789ABCDEF".charAt(rnd(16));
  }
  s += "\"";
  return s;
}


function maybeMakeTerm(d, b)
{
  if (rnd(2))
    return makeTerm(d - 1, b);
  else
    return "";
}


function makeCrazyToken()
{
  if (rnd(3) === 0) {
    return String.fromCharCode(32 + rnd(128 - 32));
  }
  if (rnd(6) === 0) {
    return String.fromCharCode(rnd(65536));
  }

  return Random.index([

  // Some of this is from reading jsscan.h.

  // Comments; comments hiding line breaks.
  "//", UNTERMINATED_COMMENT, (UNTERMINATED_COMMENT + "\n"), "/*\n*/",

  // groupers (which will usually be unmatched if they come from here ;)
  "[", "]",
  "{", "}",
  "(", ")",

  // a few operators
  "!", "@", "%", "^", "*", "**", "|", ":", "?", "'", "\"", ",", ".", "/",
  "~", "_", "+", "=", "-", "++", "--", "+=", "%=", "|=", "-=",
  "...", "=>",

  // most real keywords plus a few reserved keywords
  " in ", " instanceof ", " let ", " new ", " get ", " for ", " if ", " else ", " else if ", " try ", " catch ", " finally ", " export ", " import ", " void ", " with ",
  " default ", " goto ", " case ", " switch ", " do ", " /*infloop*/while ", " return ", " yield ", " break ", " continue ", " typeof ", " var ", " const ",

  // reserved when found in strict mode code
  " package ",

  // several keywords can be used as identifiers. these are just a few of them.
  " enum ", // JS_HAS_RESERVED_ECMA_KEYWORDS
  " debugger ", // JS_HAS_DEBUGGER_KEYWORD
  " super ", // TOK_PRIMARY!

  " this ", // TOK_PRIMARY!
  " null ", // TOK_PRIMARY!
  " undefined ", // not a keyword, but a default part of the global object
  "\n", // trigger semicolon insertion, also acts as whitespace where it might not be expected
  "\r",
  "\u2028", // LINE_SEPARATOR?
  "\u2029", // PARA_SEPARATOR?
  "<" + "!" + "--", // beginning of HTML-style to-end-of-line comment (!)
  "--" + ">", // end of HTML-style comment
  "",
  "\0", // confuse anything that tries to guess where a string ends. but note: "illegal character"!
  ]);
}


function makeShapeyValue(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (rnd(10) === 0)
    return makeExpr(d, b);

  var a = [
    // Numbers and number-like things
    [
    "0", "1", "2", "3", "0.1", ".2", "1.3", "4.", "5.0000000000000000000000",
    "1.2e3", "1e81", "1e+81", "1e-81", "1e4", "-0", "(-0)",
    "-1", "(-1)", "0x99", "033", "3/0", "-3/0", "0/0",
    "Math.PI",
    "0x2D413CCC", "0x5a827999", "0xB504F332", "-0x2D413CCC", "-0x5a827999", "-0xB504F332", "0x50505050", "(0x50505050 >> 1)",

    // various powers of two, with values near JSVAL_INT_MAX especially tested
    "0x10000000", "0x20000000", "0x3FFFFFFE", "0x3FFFFFFF", "0x40000000", "0x40000001"
    ],

    // Boundaries
    [
    // Boundaries of int, signed, unsigned (near +/- 2^31, +/- 2^32)
    "0x07fffffff",  "0x080000000",  "0x080000001",
    "-0x07fffffff", "-0x080000000", "-0x080000001",
    "0x0ffffffff",  "0x100000000",  "0x100000001",
    "-0x0ffffffff", "-0x100000000",  "-0x100000001",

    // Boundaries of double
    "Number.MIN_VALUE", "-Number.MIN_VALUE",
    "Number.MAX_VALUE", "-Number.MAX_VALUE",

    // Boundaries of maximum safe integer
    "Number.MIN_SAFE_INTEGER", "-Number.MIN_SAFE_INTEGER",
    "-(2**53-2)", "-(2**53)", "-(2**53+2)",
    "Number.MAX_SAFE_INTEGER", "-Number.MAX_SAFE_INTEGER",
    "2**53-2", "2**53", "2**53+2",

    // See bug 1350097 - 1.79...e308 is the largest (by module) finite number
    "0.000000000000001", "1.7976931348623157e308",
    ],

    // Special numbers
    [ "(1/0)", "(-1/0)", "(0/0)" ],

    // String literals
    [" \"\" ", " '' ", " 'A' ", " '\\0' ", ' "use strict" '],

    // Regular expression literals
    [ " /x/ ", " /x/g "],

    // Booleans
    [ "true", "false" ],

    // Undefined and null
    [ "(void 0)", "null" ],

    // Object literals
    [ "[]", "[1]", "[(void 0)]", "{}", "{x:3}", "({})", "({x:3})" ],

    // Variables that really should have been constants in the ecmascript spec
    [ "NaN", "Infinity", "-Infinity", "undefined"],

    // Boxed booleans
    [ "new Boolean(true)", "new Boolean(false)" ],

    // Boxed numbers
    [ "new Number(1)", "new Number(1.5)" ],

    // Boxed strings
    [ "new String('')", "new String('q')" ],

    // Fun stuff
    [ "function(){}" ],
    [ "{}", "[]", "[1]", "['z']", "[undefined]", "this", "eval", "arguments", "arguments.caller", "arguments.callee" ],
    [ "objectEmulatingUndefined()" ],

    // Actual variables (slightly dangerous)
    [ b.length ? Random.index(b) : "x" ]
  ];

  return Random.index(Random.index(a));
}

function mixedTypeArrayElem(d, b)
{
  while (true) {
    var s = makeShapeyValue(d - 3, b);
    if (s.length < 60)
      return s;
  }
}

function makeMixedTypeArray(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  // Pick two to five values to use as array entries.
  var q = rnd(4) + 2;
  var picks = [];
  for (var j = 0; j < q; ++j) {
    picks.push(mixedTypeArrayElem(d, b));
  }

  // Create a large array literal by randomly repeating the values.
  var c = [];
  var count = loopCount();
  for (var j = 0; j < count; ++j) {
    var elem = Random.index(picks);
    // Sometimes, especially at the beginning of arrays, repeat a single value (or type) many times
    // (This is needed for shape warmup, but not for JIT warmup)
    var repeat = count === 0 ? rnd(4)===0 : rnd(50)===0;
    var repeats = repeat ? rnd(30) : 1;
    for (var k = 0; k < repeats; ++k) {
      c.push(elem);
    }
  }

  return "/*MARR*/" + "[" + c.join(", ") + "]";
}

function makeArrayLiteral(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (rnd(2) === 0)
    return makeMixedTypeArray(d, b);

  var elems = [];
  while (rnd(5)) elems.push(makeArrayLiteralElem(d, b));
  return "/*FARR*/" + "[" + elems.join(", ") + "]";
}

function makeArrayLiteralElem(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  switch (rnd(5)) {
    case 0:  return "..." + makeIterable(d - 1, b); // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Spread_operator
    case 1:  return ""; // hole
    default: return makeExpr(d - 1, b);
  }
}

function makeIterable(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (d < 1)
    return "[]";

  return (Random.index(iterableExprMakers))(d, b);
}

var iterableExprMakers = Random.weighted([
  // Arrays
  { w: 1, v: function(d, b) { return "new Array(" + makeNumber(d, b) + ")"; } },
  { w: 8, v: makeArrayLiteral },

  // Array comprehensions (JavaScript 1.7)
  { w: 1, v: function(d, b) { return cat(["[", makeExpr(d, b), makeComprehension(d, b), "]"]); } },

  // Generator expressions (JavaScript 1.8)
  { w: 1, v: function(d, b) { return cat([     makeExpr(d, b), makeComprehension(d, b)     ]); } },
  { w: 1, v: function(d, b) { return cat(["(", makeExpr(d, b), makeComprehension(d, b), ")"]); } },

  // A generator that yields once
  { w: 1, v: function(d, b) { return "(function() { " + directivePrologue() + "yield " + makeExpr(d - 1, b) + "; } })()"; } },
  // A pass-through generator
  { w: 1, v: function(d, b) { return "/*PTHR*/(function() { " + directivePrologue() + "for (var i of " + makeIterable(d - 1, b) + ") { yield i; } })()"; } },

  { w: 1, v: makeFunction },
  { w: 1, v: makeExpr },
]);

function strTimes(s, n)
{
  if (n == 0) return "";
  if (n == 1) return s;
  var s2 = s + s;
  var r = n % 2;
  var d = (n - r) / 2;
  var m = strTimes(s2, d);
  return r ? m + s : m;
}


function makeAsmJSModule(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var interior = asmJSInterior([]);
  return '(function(stdlib, foreign, heap){ "use asm"; ' + interior + ' })';
}

function makeAsmJSFunction(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var interior = asmJSInterior(["ff"]);
  return '(function(stdlib, foreign, heap){ "use asm"; ' + interior + ' })(this, {ff: ' + makeFunction(d - 2, b) + '}, new ' + arrayBufferType() + '(4096))';
}


// /home/admin/funfuzz/js/jsfunfuzz/gen-proxy.js



// In addition, can always use "undefined" or makeFunction
// Forwarding proxy code based on http://wiki.ecmascript.org/doku.php?id=harmony:proxies "Example: a no-op forwarding proxy"
// The letter 'x' is special.
var proxyHandlerProperties = {
  getOwnPropertyDescriptor: {
    empty:    "function(){}",
    forward:  "function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }",
    throwing: "function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }",
  },
  getPropertyDescriptor: {
    empty:    "function(){}",
    forward:  "function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }",
    throwing: "function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }",
  },
  defineProperty: {
    empty:    "function(){}",
    forward:  "function(name, desc) { Object.defineProperty(x, name, desc); }"
  },
  getOwnPropertyNames: {
    empty:    "function() { return []; }",
    forward:  "function() { return Object.getOwnPropertyNames(x); }"
  },
  delete: {
    empty:    "function() { return true; }",
    yes:      "function() { return true; }",
    no:       "function() { return false; }",
    forward:  "function(name) { return delete x[name]; }"
  },
  fix: {
    empty:    "function() { return []; }",
    yes:      "function() { return []; }",
    no:       "function() { }",
    forward:  "function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }"
  },
  has: {
    empty:    "function() { return false; }",
    yes:      "function() { return true; }",
    no:       "function() { return false; }",
    forward:  "function(name) { return name in x; }"
  },
  hasOwn: {
    empty:    "function() { return false; }",
    yes:      "function() { return true; }",
    no:       "function() { return false; }",
    forward:  "function(name) { return Object.prototype.hasOwnProperty.call(x, name); }"
  },
  get: {
    empty:    "function() { return undefined }",
    forward:  "function(receiver, name) { return x[name]; }",
    bind:     "function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }"
  },
  set: {
    empty:    "function() { return true; }",
    yes:      "function() { return true; }",
    no:       "function() { return false; }",
    forward:  "function(receiver, name, val) { x[name] = val; return true; }"
  },
  iterate: {
    empty:    "function() { return (function() { throw StopIteration; }); }",
    forward:  "function() { return (function() { for (var name in x) { yield name; } })(); }"
  },
  enumerate: {
    empty:    "function() { return []; }",
    forward:  "function() { var result = []; for (var name in x) { result.push(name); }; return result; }"
  },
  keys: {
    empty:    "function() { return []; }",
    forward:  "function() { return Object.keys(x); }"
  }
};

function makeProxyHandlerFactory(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  if (d < 1)
    return "({/*TOODEEP*/})";

  try { // in case we screwed Object.prototype, breaking proxyHandlerProperties
    var preferred = Random.index(["empty", "forward", "yes", "no", "bind", "throwing"]);
    var fallback = Random.index(["empty", "forward"]);
    var fidelity = rnd(10);

    var handlerFactoryText = "(function handlerFactory(x) {";
    handlerFactoryText += "return {";

    if (rnd(2)) {
      // handlerFactory has an argument 'x'
      bp = b.concat(['x']);
    } else {
      // handlerFactory has no argument
      handlerFactoryText = handlerFactoryText.replace(/x/, "");
      bp = b;
    }

    for (var p in proxyHandlerProperties) {
      var funText;
      if (proxyHandlerProperties[p][preferred] && rnd(10) <= fidelity) {
        funText = proxyMunge(proxyHandlerProperties[p][preferred], p);
      } else {
        switch(rnd(7)) {
        case 0:  funText = makeFunction(d - 3, bp); break;
        case 1:  funText = "undefined"; break;
        case 2:  funText = "function() { throw 3; }"; break;
        default: funText = proxyMunge(proxyHandlerProperties[p][fallback], p);
        }
      }
      handlerFactoryText += p + ": " + funText + ", ";
    }

    handlerFactoryText += "}; })";

    return handlerFactoryText;
  } catch(e) {
    return "({/* :( */})";
  }
}

function proxyMunge(funText, p)
{
  //funText = funText.replace(/\{/, "{ var yum = 'PCAL'; dumpln(yum + 'LED: " + p + "');");
  return funText;
}

function makeProxyHandler(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  return makeProxyHandlerFactory(d, b) + "(" + makeExpr(d - 3, b) + ")";
}


// /home/admin/funfuzz/js/jsfunfuzz/gen-recursion.js

/*
David Anderson suggested creating the following recursive structures:
  - recurse down an array of mixed types, car cdr kinda thing
  - multiple recursive calls in a function, like binary search left/right, sometimes calls neither and sometimes calls both

  the recursion support in spidermonkey only works with self-recursion.
  that is, two functions that call each other recursively will not be traced.

  two trees are formed, going down and going up.
  type instability matters on both sides.
  so the values returned from the function calls matter.

  so far, what i've thought of means recursing from the top of a function and if..else.
  but i'd probably also want to recurse from other points, e.g. loops.

  special code for tail recursion likely coming soon, but possibly as a separate patch, because it requires changes to the interpreter.
*/

// "@" indicates a point at which a statement can be inserted. XXX allow use of variables, as consts
// variable names will be replaced, and should be uppercase to reduce the chance of matching things they shouldn't.
// take care to ensure infinite recursion never occurs unexpectedly, especially with doubly-recursive functions.
var recursiveFunctions = [
  {
    // Unless the recursive call is in the tail position, this will throw.
    text: "(function too_much_recursion(depth) { @; if (depth > 0) { @; too_much_recursion(depth - 1); @ } else { @ } @ })",
    vars: ["depth"],
    args: function(d, b) { return singleRecursionDepth(d, b); },
    test: function(f) { try { f(5000); } catch(e) { } return true; }
  },
  {
    text: "(function factorial(N) { @; if (N == 0) { @; return 1; } @; return N * factorial(N - 1); @ })",
    vars: ["N"],
    args: function(d, b) { return singleRecursionDepth(d, b); },
    test: function(f) { return f(10) == 3628800; }
  },
  {
    text: "(function factorial_tail(N, Acc) { @; if (N == 0) { @; return Acc; } @; return factorial_tail(N - 1, Acc * N); @ })",
    vars: ["N", "Acc"],
    args: function(d, b) { return singleRecursionDepth(d, b) + ", 1"; },
    test: function(f) { return f(10, 1) == 3628800; }
  },
  {
    // two recursive calls
    text: "(function fibonacci(N) { @; if (N <= 1) { @; return 1; } @; return fibonacci(N - 1) + fibonacci(N - 2); @ })",
    vars: ["N"],
    args: function(d, b) { return "" + rnd(8); },
    test: function(f) { return f(6) == 13; }
  },
  {
    // do *anything* while indexing over mixed-type arrays
    text: "(function a_indexing(array, start) { @; if (array.length == start) { @; return EXPR1; } var thisitem = array[start]; var recval = a_indexing(array, start + 1); STATEMENT1 })",
    vars: ["array", "start", "thisitem", "recval"],
    args: function(d, b) { return makeMixedTypeArray(d-1, b) + ", 0"; },
    testSub: function(text) { return text.replace(/EXPR1/, "0").replace(/STATEMENT1/, "return thisitem + recval;"); },
    randSub: function(text, varMap, d, b) {
        var expr1 =      makeExpr(d, b.concat([varMap["array"], varMap["start"]]));
        var statement1 = rnd(2) ?
                                   makeStatement(d, b.concat([varMap["thisitem"], varMap["recval"]]))        :
                            "return " + makeExpr(d, b.concat([varMap["thisitem"], varMap["recval"]])) + ";";

        return (text.replace(/EXPR1/,      expr1)
                    .replace(/STATEMENT1/, statement1)
        ); },
    test: function(f) { return f([1,2,3,"4",5,6,7], 0) == "123418"; }
  },
  {
    // this lets us play a little with mixed-type arrays
    text: "(function sum_indexing(array, start) { @; return array.length == start ? 0 : array[start] + sum_indexing(array, start + 1); })",
    vars: ["array", "start"],
    args: function(d, b) { return makeMixedTypeArray(d-1, b) + ", 0"; },
    test: function(f) { return f([1,2,3,"4",5,6,7], 0) == "123418"; }
  },
  {
    text: "(function sum_slicing(array) { @; return array.length == 0 ? 0 : array[0] + sum_slicing(array.slice(1)); })",
    vars: ["array"],
    args: function(d, b) { return makeMixedTypeArray(d-1, b); },
    test: function(f) { return f([1,2,3,"4",5,6,7]) == "123418"; }
  }
];

function singleRecursionDepth(d, b)
{
  if (rnd(2) === 0) {
    return "" + rnd(4);
  }
  if (rnd(10) === 0) {
    return makeExpr(d - 2, b);
  }
  return "" + rnd(100000);
}

(function testAllRecursiveFunctions() {
  for (var i = 0; i < recursiveFunctions.length; ++i) {
    var a = recursiveFunctions[i];
    var text = a.text;
    if (a.testSub) text = a.testSub(text);
    var f = eval(text.replace(/@/g, ""));
    if (!a.test(f))
      throw "Failed test of: " + a.text;
  }
})();

function makeImmediateRecursiveCall(d, b, cheat1, cheat2)
{
  if (rnd(10) !== 0)
    return "(4277)";

  var a = (cheat1 == null) ? Random.index(recursiveFunctions) : recursiveFunctions[cheat1];
  var s = a.text;
  var varMap = {};
  for (var i = 0; i < a.vars.length; ++i) {
    var prettyName = a.vars[i];
    varMap[prettyName] = uniqueVarName();
    s = s.replace(new RegExp(prettyName, "g"), varMap[prettyName]);
  }
  var actualArgs = cheat2 == null ? a.args(d, b) : cheat2;
  s = s + "(" + actualArgs + ")";
  s = s.replace(/@/g, function() { if (rnd(4) === 0) return makeStatement(d-2, b); return ""; });
  if (a.randSub) s = a.randSub(s, varMap, d, b);
  s = "(" + s + ")";
  return s;
}


// /home/admin/funfuzz/js/jsfunfuzz/gen-regex.js


/*********************************
 * GENERATING REGEXPS AND INPUTS *
 *********************************/

// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions

// The basic data structure returned by most of the regex* functions is a tuple:
//   [ regex string, array of potential matches ]
// For example:
//   ["a|b*", ["a", "b", "bbbb", "", "c"]]
// These functions work together recursively to build up a regular expression
// along with input strings.

// This paradigm works well for the recursive nature of most regular expression components,
// but breaks down when we encounter lookahead assertions or backrefs (\1).

// How many potential matches to create per regexp
var POTENTIAL_MATCHES = 10;

// Stored captures
var backrefHack = [];
for (var i = 0; i < POTENTIAL_MATCHES; ++i) {
  backrefHack[i] = "";
}

function regexNumberOfMatches()
{
  if (rnd(10))
    return rnd(5);
  return Math.pow(2, rnd(40)) + rnd(3) - 1;
}

function regexPattern(depth, parentWasQuantifier)
{
  if (depth == 0 || (rnd(depth) == 0))
    return regexTerm();

  var dr = depth - 1;

  var index = rnd(regexMakers.length);
  if (parentWasQuantifier && rnd(30)) index = rnd(regexMakers.length - 1) + 1; // avoid double quantifiers
  return (Random.index(regexMakers[index]))(dr);
}

var regexMakers =
[
  [
    // Quantifiers
    function(dr) { return regexQuantified(dr, "+", 1, rnd(10)); },
    function(dr) { return regexQuantified(dr, "*", 0, rnd(10)); },
    function(dr) { return regexQuantified(dr, "?", 0, 1); },
    function(dr) { return regexQuantified(dr, "+?", 1, 1); },
    function(dr) { return regexQuantified(dr, "*?", 0, 1); },
    function(dr) { var x = regexNumberOfMatches(); return regexQuantified(dr, "{" + x + "}", x, x); },
    function(dr) { var x = regexNumberOfMatches(); return regexQuantified(dr, "{" + x + ",}", x, x + rnd(10)); },
    function(dr) { var min = regexNumberOfMatches(); var max = min + regexNumberOfMatches(); return regexQuantified(dr, "{" + min + "," + max + "}", min, max); }
  ],
  [
    // Combinations: concatenation, disjunction
    function(dr) { return regexConcatenation(dr); },
    function(dr) { return regexDisjunction(dr); }
  ],
  [
    // Grouping
    function(dr) { return ["\\" + (rnd(3) + 1), backrefHack.slice(0)]; }, // backref
    function(dr) { return regexGrouped("(", dr, ")");   }, // capturing: feeds \1 and exec() result
    function(dr) { return regexGrouped("(?:", dr, ")"); }, // non-capturing
    function(dr) { return regexGrouped("(?=", dr, ")"); }, // lookahead
    function(dr) { return regexGrouped("(?!", dr, ")"); }  // lookahead(not)
  ]
];


function quantifierHelper(pm, min, max, pms)
{
  var repeats = Math.min(min + rnd(max - min + 5) - 2, 10);
  var returnValue = "";
  for (var i = 0; i < repeats; i++)
  {
    if (rnd(100) < 80)
      returnValue = returnValue + pm;
    else
      returnValue = returnValue + Random.index(pms);
  }
  return returnValue;
}

function regexQuantified(dr, operator, min, max)
{
  var [re, pms] = regexPattern(dr, true);
  var newpms = [];
  for (var i = 0; i < POTENTIAL_MATCHES; i++)
    newpms[i] = quantifierHelper(pms[i], min, max, pms);
  return [re + operator, newpms];
}


function regexConcatenation(dr)
{
  var [re1, strings1] = regexPattern(dr, false);
  var [re2, strings2] = regexPattern(dr, false);
  var newStrings = [];

  for (var i = 0; i < POTENTIAL_MATCHES; i++)
  {
    var chance = rnd(100);
    if (chance < 10)
      newStrings[i] = "";
    else if (chance < 20)
      newStrings[i] = strings1[i];
    else if (chance < 30)
      newStrings[i] = strings2[i];
    else if (chance < 65)
      newStrings[i] = strings1[i] + strings2[i];
    else
      newStrings[i] = Random.index(strings1) + Random.index(strings2);
  }

  return [re1 + re2, newStrings];
}

function regexDisjunction(dr)
{
  var [re1, strings1] = regexPattern(dr, false);
  var [re2, strings2] = regexPattern(dr, false);
  var newStrings = [];

  for (var i = 0; i < POTENTIAL_MATCHES; i++)
  {
    var chance = rnd(100);
    if (chance < 10)
      newStrings[i] = "";
    else if (chance < 20)
      newStrings[i] = Random.index(strings1) + Random.index(strings2);
    else if (chance < 60)
      newStrings[i] = strings1[i];
    else
      newStrings[i] = strings2[i];
  }
  return [re1 + "|" + re2, newStrings];
}

function regexGrouped(prefix, dr, postfix)
{
  var [re, strings] = regexPattern(dr, false);
  var newStrings = [];
  for (var i = 0; i < POTENTIAL_MATCHES; ++i) {
    newStrings[i] = rnd(5) ? strings[i] : "";
    if (prefix == "(" && strings[i].length < 40 && rnd(3) === 0) {
      backrefHack[i] = strings[i];
    }
  }
  return [prefix + re + postfix, newStrings];
}


var letters =
["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
 "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"];

var hexDigits = [
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
  "a", "b", "c", "d", "e", "f",
  "A", "B", "C", "D", "E", "F"
];

function regexTerm()
{
  var [re, oneString] = regexTermPair();
  var strings = [];
  for (var i = 0; i < POTENTIAL_MATCHES; ++i) {
    strings[i] = rnd(5) ? oneString : regexTermPair()[1];
  }
  return [re, strings];
}

function regexCharCode()
{
  return rnd(2) ? rnd(256) : rnd(65536);
}

// These return matching pairs: [regex fragment, charcode for a matching one-character string].
var regexCharacterMakers = Random.weighted([
  // Possibly incorrect
  { w:20, v: function() { var cc = regexCharCode(); return [       String.fromCharCode(cc), cc]; } }, // literal that doesn't need to be escaped (OR wrong)
  { w: 4, v: function() { var cc = regexCharCode(); return ["\\" + String.fromCharCode(cc), cc]; } }, // escaped special character OR unnecessary escape (OR wrong)
  { w: 1, v: function() { return ["\\0",  0]; } },  // null [ignoring the "do not follow this with another digit" rule which would turn it into an octal escape]
  { w: 1, v: function() { return ["\\B", 66]; } },  // literal B -- ONLY within a character class. (Elsewhere, it's a "zero-width non-word boundary".)
  { w: 1, v: function() { return ["\\b",  8]; } },  // backspace -- ONLY within a character class. (Elsewhere, it's a "zero-width word boundary".)

  // Correct, unless I screwed up
  { w: 1, v: function() { return ["\\t",  9]; } },  // tab
  { w: 1, v: function() { return ["\\n", 10]; } },  // line break
  { w: 1, v: function() { return ["\\v", 11]; } },  // vertical tab
  { w: 1, v: function() { return ["\\f", 12]; } },  // form feed
  { w: 1, v: function() { return ["\\r", 13]; } },  // carriage return
  { w: 5, v: function() { var controlCharacterCode = rnd(26) + 1; return ["\\c" + String.fromCharCode(64 + controlCharacterCode), controlCharacterCode]; } },
  //{ w: 5, v: function() { var cc = regexCharCode(); return ["\\0" + cc.toString(8), cc] } }, // octal escape
  { w: 5, v: function() { var twoHex = Random.index(hexDigits) + Random.index(hexDigits); return ["\\x" + twoHex, parseInt(twoHex, 16)]; } },
  { w: 5, v: function() { var twoHex = Random.index(hexDigits) + Random.index(hexDigits); return ["\\u00" + twoHex, parseInt(twoHex, 16)]; } },
  { w: 5, v: function() { var fourHex = Random.index(hexDigits) + Random.index(hexDigits) + Random.index(hexDigits) + Random.index(hexDigits); return ["\\u" + fourHex, parseInt(fourHex, 16)]; } },
]);

function regexCharacter()
{
  var [matcher, charcode] = Random.index(regexCharacterMakers)();
  switch(rnd(10)) {
    case 0:  return [matcher, charcode + 32]; // lowercase
    case 1:  return [matcher, charcode - 32]; // uppercase
    case 2:  return [matcher, regexCharCode()]; // some other character
    default: return [matcher, charcode];
  }
}


var regexBuiltInCharClasses = [
    "\\d", "\\D", // digit
    "\\s", "\\S", // space
    "\\w", "\\W", // "word" character (alphanumeric plus underscore)
];

// Returns POTENTIAL_MATCHES one-character strings, mostly consisting of the input characters
function regexOneCharStringsWith(frequentChars) {
  var matches = [];
  for (var i = 0; i < POTENTIAL_MATCHES; ++i) {
    matches.push(rnd(8) ? Random.index(frequentChars) : String.fromCharCode(regexCharCode()));
  }
  return matches;
}

// Returns POTENTIAL_MATCHES short strings, using the input characters a lot.
function regexShortStringsWith(frequentChars) {
  var matches = [];
  for (var i = 0; i < POTENTIAL_MATCHES; ++i) {
    var s = "";
    while (rnd(3)) {
      s += rnd(4) ? Random.index(frequentChars) : String.fromCharCode(regexCharCode());
    }
    matches.push(s);
  }
  return matches;
}

var regexTermMakers =
  [
    function() { return regexCharacterClass(); },
    function() { var [re, cc] = regexCharacter();   return [re, regexOneCharStringsWith([String.fromCharCode(cc)])]; },
    function() { return [Random.index(regexBuiltInCharClasses), regexOneCharStringsWith(["0", "a", "_"])]; },
    function() { return ["[^]",                                 regexOneCharStringsWith(["\n"])];     },
    function() { return [".",                                   regexOneCharStringsWith(["\n"])];     },
    function() { return [Random.index(["^", "$"]),              regexShortStringsWith(["\n"])];     },            // string boundaries or line boundaries (with /m)
    function() { return [Random.index(["\\b", "\\B"]),          regexShortStringsWith([" ", "\n", "a", "1"])]; }, // word boundaries
  ];

function regexTerm()
{
  return Random.index(regexTermMakers)();
}

// Returns a pair: [(regex char class), (POTENTIAL_MATCHES number of strings that might match)]
// e.g. ["[a-z0-9]", ["a", "8", ...]]
function regexCharacterClass()
{
  var ranges = rnd(5);
  var inRange = rnd(2);
  var charBucket = [String.fromCharCode(regexCharCode())]; // from which potenial matches will be drawn

  var re = "[";
  if (!inRange) {
    re += "^";
  }

  var lo, hi;

  for (var i = 0; i < ranges; ++i) {
    if (rnd(100) == 0) {
      // Confuse things by tossing in an extra "-"
      re += "-";
      if (rnd(2)) {
        re += String.fromCharCode(regexCharCode());
      }
    }

    if (rnd(3) == 1) {
      // Add a built-in class, like "\d"
      re += Random.index(regexBuiltInCharClasses);
      charBucket.push("a");
      charBucket.push("0");
      charBucket.push("_");
    } else if (rnd(2)) {
      // Add a range, like "a-z"
      var a = regexCharacter();
      var b = regexCharacter();
      if ((a[1] <= b[1]) == !!rnd(10)) {
        [lo, hi] = [a, b];
      } else {
        [lo, hi] = [b, a];
      }

      re += lo[0] + "-" + hi[0];
      charBucket.push(String.fromCharCode(lo[1] + rnd(3) - 1));
      charBucket.push(String.fromCharCode(hi[1] + rnd(3) - 1));
      charBucket.push(String.fromCharCode(lo[1] + rnd(Math.max(hi[1] - lo[1], 1)))); // something in the middle
    } else {
      // Add a single character
      var a = regexCharacter();
      re += a[0];
      charBucket.push(String.fromCharCode(a[1]));
    }
  }

  re += "]";
  return [re, pickN(charBucket, POTENTIAL_MATCHES)];
}

function pickN(bucket, picks)
{
  var picked = [];
  for (var i = 0; i < picks; ++i) {
    picked.push(Random.index(bucket));
  }
  return picked;
}


// /home/admin/funfuzz/js/jsfunfuzz/gen-stomp-on-registers.js

// Using up all the registers can find bugs where a caller does not store its
// registers properly, or a callee violates an ABI.

function makeRegisterStompFunction(d, b, pure)
{
  var args = [];
  var nArgs = (rnd(10) ? rnd(20) : rnd(100)) + 1;
  for (var i = 0; i < nArgs; ++i) {
    args.push("a" + i);
  }

  var bv = b.concat(args);

  return (
    "(function(" + args.join(", ") + ") { " +
      makeRegisterStompBody(d, bv, pure) +
      "return " + Random.index(bv) + "; " +
    "})"
  );
}

function makeRegisterStompBody(d, b, pure)
{
  var bv = b.slice(0);
  var lastRVar = 0;
  var s = "";

  function value()
  {
    return rnd(3) && bv.length ? Random.index(bv) : "" + rnd(10);
  }

  function expr()
  {
    return value() + Random.index([" + ", " - ", " / ", " * ", " % ", " | ", " & ", " ^ "]) + value();
  }

  while (rnd(100)) {
    if (bv.length == 0 || rnd(4)) {
      var newVar = "r" + lastRVar;
      ++lastRVar;
      s += "var " + newVar + " = " + expr() + "; ";
      bv.push(newVar);
    } else if (rnd(5) === 0 && !pure) {
      s += "print(" + Random.index(bv) + "); ";
    } else {
      s += Random.index(bv) + " = " + expr() + "; ";
    }
  }

  return s;
}



// /home/admin/funfuzz/js/jsfunfuzz/gen-type-aware-code.js


/***********************
 * TEST BUILT-IN TYPES *
 ***********************/

var makeBuilderStatement;
var makeEvilCallback;

(function setUpBuilderStuff() {
  var ARRAY_SIZE = 20;
  var OBJECTS_PER_TYPE = 3;
  var smallPowersOfTwo = [1, 2, 4, 8]; // The largest typed array views are 64-bit aka 8-byte
  function bufsize() { return rnd(ARRAY_SIZE) * Random.index(smallPowersOfTwo); }
  function arrayIndex(d, b) {
    switch(rnd(8)) {
      case 0:  return m("v");
      case 1:  return makeExpr(d - 1, b);
      case 2:  return "({valueOf: function() { " + makeStatement(d, b) + "return " + rnd(ARRAY_SIZE) + "; }})";
      default: return "" + rnd(ARRAY_SIZE);
    }
  }

  // Emit a variable name for type-abbreviation t.
  function m(t)
  {
    if (!t)
      t = "aosmevbtihgfp";
    t = t.charAt(rnd(t.length));
    var name = t + rnd(OBJECTS_PER_TYPE);
    switch(rnd(16)) {
      case 0:  return m("o") + "." + name;
      case 1:  return m("g") + "." + name;
      case 2:  return "this." + name;
      default: return name;
    }
  }

  function val(d, b)
  {
    if (rnd(10))
      return m();
    return makeExpr(d, b);
  }

  // Emit an assignment (or a roughly-equivalent getter)
  function assign(d, b, t, rhs)
  {
    switch(rnd(18)) {
    // Could have two forms of the getter: one that computes it each time on demand, and one that computes a constant-function closure
    case 0:  return (
      "Object.defineProperty(" +
        (rnd(8)?"this":m("og")) + ", " +
        simpleSource(m(t)) + ", " +
        "{ " + propertyDescriptorPrefix(d-1, b) + " get: function() { " + (rnd(8)?"":makeBuilderStatement(d-1,b)) + " return " + rhs + "; } }" +
      ");"
    );
    case 1:  return Random.index(varBinder) + m(t) + " = " + rhs + ";";
    default: return m(t) + " = " + rhs + ";";
    }
  }

  function makeCounterClosure(d, b)
  {
    // A closure with a counter. Do stuff depending on the counter.
    var v = uniqueVarName();
    var infrequently = infrequentCondition(v, 10);
    return (
      "(function mcc_() { " +
        "var " + v + " = 0; " +
        "return function() { " +
          "++" + v + "; " +
            (rnd(3) ?
              "if (" + infrequently + ") { dumpln('hit!'); " + makeBuilderStatements(d, b) + " } " +
              "else { dumpln('miss!'); " + makeBuilderStatements(d, b) + " } "
            : m("f") + "(" + infrequently + ");"
            ) +
        "};" +
      "})()");
  }

  function fdecl(d, b)
  {
    var argName = m();
    var bv = b.concat([argName]);
    return "function " + m("f") + "(" + argName + ") " + makeFunctionBody(d, bv);
  }

  function makeBuilderStatements(d, b)
  {
    var s = "";
    var extras = rnd(4);
    for (var i = 0; i < extras; ++i) {
      s += "try { " + makeBuilderStatement(d - 2, b) +  " } catch(e" + i + ") { } ";
    }
    s += makeBuilderStatement(d - 1, b);
    return s;
  }

  var builderFunctionMakers = Random.weighted([
    { w: 9,  v: function(d, b) { return "(function() { " + makeBuilderStatements(d, b) + " return " + m() + "; })"; } },
    { w: 1,  v: function(d, b) { return "(function() { " + makeBuilderStatements(d, b) + " throw " + m() + "; })"; } },
    { w: 1,  v: function(d, b) { return "(function(j) { " + m("f") + "(j); })"; } }, // a function that just makes one call is begging to be inlined
    // The following pair create and use boolean-using functions.
    { w: 4,  v: function(d, b) { return "(function(j) { if (j) { " + makeBuilderStatements(d, b) + " } else { " + makeBuilderStatements(d, b) + " } })"; } },
    { w: 4,  v: function(d, b) { return "(function() { for (var j=0;j<" + loopCount() + ";++j) { " + m("f") + "(j%"+(2+rnd(4))+"=="+rnd(2)+"); } })"; } },
    { w: 1,  v: function(d, b) { return Random.index(builtinFunctions) + ".bind(" + m() + ")"; } },
    { w: 5,  v: function(d, b) { return m("f"); } },
    { w: 3,  v: makeCounterClosure },
    { w: 2,  v: makeFunction },
    { w: 1,  v: makeAsmJSModule },
    { w: 1,  v: makeAsmJSFunction },
    { w: 1,  v: makeRegisterStompFunction },
  ]);
  makeEvilCallback = function(d, b) {
    return (Random.index(builderFunctionMakers))(d - 1, b);
  };

  var handlerTraps = ["getOwnPropertyDescriptor", "getPropertyDescriptor", "defineProperty", "getOwnPropertyNames", "delete", "fix", "has", "hasOwn", "get", "set", "iterate", "enumerate", "keys"];

  function forwardingHandler(d, b) {
    return (
      "({"+
        "getOwnPropertyDescriptor: function(name) { Z; var desc = Object.getOwnPropertyDescriptor(X); desc.configurable = true; return desc; }, " +
        "getPropertyDescriptor: function(name) { Z; var desc = Object.getPropertyDescriptor(X); desc.configurable = true; return desc; }, " +
        "defineProperty: function(name, desc) { Z; Object.defineProperty(X, name, desc); }, " +
        "getOwnPropertyNames: function() { Z; return Object.getOwnPropertyNames(X); }, " +
        "delete: function(name) { Z; return delete X[name]; }, " +
        "fix: function() { Z; if (Object.isFrozen(X)) { return Object.getOwnProperties(X); } }, " +
        "has: function(name) { Z; return name in X; }, " +
        "hasOwn: function(name) { Z; return Object.prototype.hasOwnProperty.call(X, name); }, " +
        "get: function(receiver, name) { Z; return X[name]; }, " +
        "set: function(receiver, name, val) { Z; X[name] = val; return true; }, " +
        "iterate: function() { Z; return (function() { for (var name in X) { yield name; } })(); }, " +
        "enumerate: function() { Z; var result = []; for (var name in X) { result.push(name); }; return result; }, " +
        "keys: function() { Z; return Object.keys(X); } " +
      "})"
    )
    .replace(/X/g, m())
    .replace(/Z/g, function() {
      switch(rnd(20)){
        case 0:  return "return " + m();
        case 1:  return "throw " + m();
        default: return makeBuilderStatement(d - 2, b);
      }
    });
  }

  function propertyDescriptorPrefix(d, b)
  {
    return "configurable: " + makeBoolean(d, b) + ", " + "enumerable: " + makeBoolean(d, b) + ", ";
  }

  function strToEval(d, b)
  {
    switch(rnd(5)) {
      case 0:  return simpleSource(fdecl(d, b));
      case 1:  return simpleSource(makeBuilderStatement(d, b));
      default: return simpleSource(makeScriptForEval(d, b));
    }
  }

  function evaluateFlags(d, b)
  {
    // Options are in js.cpp: Evaluate() and ParseCompileOptions()
    return ("({ global: " + m("g") +
      ", fileName: " + Random.index(["'evaluate.js'", "null"]) +
      ", lineNumber: 42" +
      ", isRunOnce: " + makeBoolean(d, b) +
      ", noScriptRval: " + makeBoolean(d, b) +
      ", sourceIsLazy: " + makeBoolean(d, b) +
      ", catchTermination: " + makeBoolean(d, b) +
      ((rnd(5) == 0) ? (
        ((rnd(2) == 0) ? (", element: " + m("o")) : "") +
        ((rnd(2) == 0) ? (", elementAttributeName: " + m("s")) : "") +
        ((rnd(2) == 0) ? (", sourceMapURL: " + m("s")) : "")
        ) : ""
      ) +
    " })");
  }

  var initializedEverything = false;
  function initializeEverything(d, b)
  {
    if (initializedEverything)
      return ";";
    initializedEverything = true;

    var s = "";
    for (var i = 0; i < OBJECTS_PER_TYPE; ++i) {
      s += "a" + i + " = []; ";
      s += "o" + i + " = {}; ";
      s += "s" + i + " = ''; ";
      s += "r" + i + " = /x/; ";
      s += "g" + i + " = " + makeGlobal(d, b) + "; ";
      s += "f" + i + " = function(){}; ";
      s += "m" + i + " = new WeakMap; ";
      s += "e" + i + " = new Set; ";
      s += "v" + i + " = null; ";
      s += "b" + i + " = new ArrayBuffer(64); ";
      s += "t" + i + " = new Uint8ClampedArray; ";
      // nothing for iterators, handlers
    }
    return s;
  }

  // Emit a method call expression, in one of the following forms:
  //   Array.prototype.push.apply(a1, [x])
  //   Array.prototype.push.call(a1, x)
  //   a1.push(x)
  function method(d, b, clazz, obj, meth, arglist)
  {
    // Sometimes ignore our arguments
    if (rnd(10) == 0)
      arglist = [];

    // Stuff in extra arguments
    while (rnd(2))
      arglist.push(val(d, b));

    // Emit a method call expression
    switch (rnd(4)) {
      case 0:  return clazz + ".prototype." + meth + ".apply(" + obj + ", [" + arglist.join(", ") + "])";
      case 1:  return clazz + ".prototype." + meth + ".call(" + [obj].concat(arglist).join(", ") + ")";
      default: return obj + "." + meth + "(" + arglist.join(", ") + ")";
    }
  }

  function severalargs(f)
  {
    var arglist = [];
    arglist.push(f());
    while (rnd(2)) {
      arglist.push(f());
    }
    return arglist;
  }

  var builderStatementMakers = Random.weighted([
    // a: Array
    { w: 1,  v: function(d, b) { return assign(d, b, "a", "[]"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", "new Array"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", makeIterable(d, b)); } },
    { w: 1,  v: function(d, b) { return m("a") + ".length = " + arrayIndex(d, b) + ";"; } },
    { w: 8,  v: function(d, b) { return assign(d, b, "v", m("at") + ".length"); } },
    { w: 4,  v: function(d, b) { return m("at") + "[" + arrayIndex(d, b) + "]" + " = " + val(d, b) + ";"; } },
    { w: 4,  v: function(d, b) { return val(d, b) + " = " + m("at") + "[" + arrayIndex(d, b) + "]" + ";"; } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", makeFunOnCallChain(d, b) + ".arguments"); } }, // a read-only arguments object
    { w: 1,  v: function(d, b) { return assign(d, b, "a", "arguments"); } }, // a read-write arguments object

    // Array indexing
    { w: 3,  v: function(d, b) { return m("at") + "[" + arrayIndex(d, b) + "]" + ";"; } },
    { w: 3,  v: function(d, b) { return m("at") + "[" + arrayIndex(d, b) + "] = " + makeExpr(d, b) + ";"; } },
    { w: 1,  v: function(d, b) { return "/*ADP-1*/Object.defineProperty(" + m("a") + ", " + arrayIndex(d, b) + ", " + makePropertyDescriptor(d, b) + ");"; } },
    { w: 1,  v: function(d, b) { return "/*ADP-2*/Object.defineProperty(" + m("a") + ", " + arrayIndex(d, b) + ", { " + propertyDescriptorPrefix(d, b) + "get: " + makeEvilCallback(d,b) + ", set: " + makeEvilCallback(d, b) + " });"; } },
    { w: 1,  v: function(d, b) { return "/*ADP-3*/Object.defineProperty(" + m("a") + ", " + arrayIndex(d, b) + ", { " + propertyDescriptorPrefix(d, b) + "writable: " + makeBoolean(d,b) + ", value: " + val(d, b) + " });"; } },

    // Array mutators
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "push", severalargs(function() { return val(d, b); })) + ";"; } },
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "pop", []) + ";"; } },
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "unshift", severalargs(function() { return val(d, b); })) + ";"; } },
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "shift", []) + ";"; } },
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "reverse", []) + ";"; } },
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "sort", [makeEvilCallback(d, b)]) + ";"; } },
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "splice", [arrayIndex(d, b) - arrayIndex(d, b), arrayIndex(d, b)]) + ";"; } },
    // Array accessors
    { w: 1,  v: function(d, b) { return assign(d, b, "s", method(d, b, "Array", m("a"), "join", [m("s")])); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", method(d, b, "Array", m("a"), "concat", severalargs(function() { return m("at"); }))); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", method(d, b, "Array", m("a"), "slice", [arrayIndex(d, b) - arrayIndex(d, b), arrayIndex(d, b) - arrayIndex(d, b)])); } },

    // Array iterators
    { w: 5,  v: function(d, b) { return method(d, b, "Array", m("a"), "forEach", [makeEvilCallback(d, b)]) + ";"; } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", method(d, b, "Array", m("a"), "map", [makeEvilCallback(d, b)])); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", method(d, b, "Array", m("a"), "filter", [makeEvilCallback(d, b)])); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", method(d, b, "Array", m("a"), "some", [makeEvilCallback(d, b)])); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", method(d, b, "Array", m("a"), "every", [makeEvilCallback(d, b)])); } },

    // Array reduction, either with a starting value or with the default of starting with the first two elements.
    { w: 1,  v: function(d, b) { return assign(d, b, "v", method(d, b, "Array", m("a"), Random.index(["reduce, reduceRight"]), [makeEvilCallback(d, b)])); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", method(d, b, "Array", m("a"), Random.index(["reduce, reduceRight"]), [makeEvilCallback(d, b), val(d, b)])); } },

    // Typed Objects (aka Binary Data)
    // http://wiki.ecmascript.org/doku.php?id=harmony:typed_objects (does not match what's in spidermonkey as of 2014-02-11)
    // Do I need to keep track of 'types', 'objects of those types', and 'arrays of objects of those types'?
    //{ w: 1,  v: function(d, b) { return assign(d, b, "d", m("d") + ".flatten()"); } },
    //{ w: 1,  v: function(d, b) { return assign(d, b, "d", m("d") + ".partition(" + (rnd(2)?m("v"):rnd(10)) + ")"); } },

    // o: Object
    { w: 1,  v: function(d, b) { return assign(d, b, "o", "{}"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "o", "new Object"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "o", "Object.create(" + val(d, b) + ")"); } },
    { w: 3,  v: function(d, b) { return "selectforgc(" + m("o") + ");"; } },

    // s: String
    { w: 1,  v: function(d, b) { return assign(d, b, "s", "''"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "s", "new String"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "s", "new String(" + m() + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "s", m("s") + ".charAt(" + arrayIndex(d, b) + ")"); } },
    { w: 5,  v: function(d, b) { return m("s") + " += 'x';"; } },
    { w: 5,  v: function(d, b) { return m("s") + " += " + m("s") + ";"; } },
    // Should add substr, substring, replace

    // m: Map, WeakMap
    { w: 1,  v: function(d, b) { return assign(d, b, "m", "new Map"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "m", "new Map(" + m() + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "m", "new WeakMap"); } },
    { w: 5,  v: function(d, b) { return m("m") + ".has(" + val(d, b) + ");"; } },
    { w: 4,  v: function(d, b) { return m("m") + ".get(" + val(d, b) + ");"; } },
    { w: 1,  v: function(d, b) { return assign(d, b, null, m("m") + ".get(" + val(d, b) + ")"); } },
    { w: 5,  v: function(d, b) { return m("m") + ".set(" + val(d, b) + ", " + val(d, b) + ");"; } },
    { w: 3,  v: function(d, b) { return m("m") + ".delete(" + val(d, b) + ");"; } },

    // e: Set
    { w: 1,  v: function(d, b) { return assign(d, b, "e", "new Set"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "e", "new Set(" + m() + ")"); } },
    { w: 5,  v: function(d, b) { return m("e") + ".has(" + val(d, b) + ");"; } },
    { w: 5,  v: function(d, b) { return m("e") + ".add(" + val(d, b) + ");"; } },
    { w: 3,  v: function(d, b) { return m("e") + ".delete(" + val(d, b) + ");"; } },

    // b: Buffer
    { w: 1,  v: function(d, b) { return assign(d, b, "b", "new " + arrayBufferType() + "(" + bufsize() + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "b", m("t") + ".buffer"); } },
    { w: 1,  v: function(d, b) { return "neuter(" + m("b") + ", " + (rnd(2) ? '"same-data"' : '"change-data"') + ");"; } },

    // t: Typed arrays, aka ArrayBufferViews
    // Can be constructed using a length, typed array, sequence (e.g. array), or buffer with optional offsets!
    { w: 1,  v: function(d, b) { return assign(d, b, "t", "new " + Random.index(typedArrayConstructors) + "(" + arrayIndex(d, b) + ")"); } },
    { w: 3,  v: function(d, b) { return assign(d, b, "t", "new " + Random.index(typedArrayConstructors) + "(" + m("abt") + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "t", "new " + Random.index(typedArrayConstructors) + "(" + m("b") + ", " + bufsize() + ", " + arrayIndex(d, b) + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "t", m("t") + ".subarray(" + arrayIndex(d, b) + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "t", m("t") + ".subarray(" + arrayIndex(d, b) + ", " + arrayIndex(d, b) + ")"); } },
    { w: 3,  v: function(d, b) { return m("t") + ".set(" + m("at") + ", " + arrayIndex(d, b) + ");"; } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", m("tb") + ".byteLength"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", m("t") + ".byteOffset"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", m("t") + ".BYTES_PER_ELEMENT"); } },

    // h: proxy handler
    { w: 1,  v: function(d, b) { return assign(d, b, "h", "{}"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "h", forwardingHandler(d, b)); } },
    { w: 1,  v: function(d, b) { return "delete " + m("h") + "." + Random.index(handlerTraps) + ";"; } },
    { w: 4,  v: function(d, b) { return m("h") + "." + Random.index(handlerTraps) + " = " + makeEvilCallback(d, b) + ";"; } },
    { w: 4,  v: function(d, b) { return m("h") + "." + Random.index(handlerTraps) + " = " + m("f") + ";"; } },
    { w: 1,  v: function(d, b) { return assign(d, b, null, "Proxy.create(" + m("h") + ", " + m() + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "f", "Proxy.createFunction(" + m("h") + ", " + m("f") + ", " + m("f") + ")"); } },

    // r: regexp
    // The separate regex code is better at matching strings with regexps, but this is better at reusing the objects.
    // See https://bugzilla.mozilla.org/show_bug.cgi?id=808245 for why it is important to reuse regexp objects.
    { w: 1,  v: function(d, b) { return assign(d, b, "r", makeRegex(d, b)); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "a", m("r") + ".exec(" + m("s") + ")"); } },
    { w: 3,  v: function(d, b) { return makeRegexUseBlock(d, b, m("r")); } },
    { w: 3,  v: function(d, b) { return makeRegexUseBlock(d, b, m("r"), m("s")); } },
    { w: 3,  v: function(d, b) { return assign(d, b, "v", m("r") + "." + Random.index(builtinObjects["RegExp.prototype"])); } },

    // g: global or sandbox
    { w: 1,  v: function(d, b) { return assign(d, b, "g", makeGlobal(d, b)); } },
    { w: 5,  v: function(d, b) { return assign(d, b, "v", m("g") + ".eval(" + strToEval(d, b) + ")"); } },
    { w: 5,  v: function(d, b) { return assign(d, b, "v", "evalcx(" + strToEval(d, b) + ", " + m("g") + ")"); } },
    { w: 5,  v: function(d, b) { return assign(d, b, "v", "evaluate(" + strToEval(d, b) + ", " + evaluateFlags(d, b) + ")"); } },
    { w: 2,  v: function(d, b) { return m("g") + ".offThreadCompileScript(" + strToEval(d, b) + ");"; } },
    { w: 3,  v: function(d, b) { return m("g") + ".offThreadCompileScript(" + strToEval(d, b) + ", " + evaluateFlags(d, b) + ");"; } },
    { w: 5,  v: function(d, b) { return assign(d, b, "v", m("g") + ".runOffThreadScript()"); } },
    { w: 3,  v: function(d, b) { return "(void schedulegc(" + m("g") + "));"; } },

    // Mix builtins between globals
    { w: 3,  v: function(d, b) { return "/*MXX1*/" + assign(d, b, "o", m("g") + "." + Random.index(builtinProperties)); } },
    { w: 3,  v: function(d, b) { return "/*MXX2*/" + m("g") + "." + Random.index(builtinProperties) + " = " + m() + ";"; } },
    { w: 3,  v: function(d, b) { var prop = Random.index(builtinProperties); return "/*MXX3*/" + m("g") + "." + prop + " = " + m("g") + "." + prop + ";"; } },

    // f: function (?)
    // Could probably do better with args / b
    { w: 1,  v: function(d, b) { return assign(d, b, "f", makeEvilCallback(d, b)); } },
    { w: 1,  v: fdecl },
    { w: 2,  v: function(d, b) { return m("f") + "(" + m() + ");"; } },

    // i: Iterator
    { w: 1,  v: function(d, b) { return assign(d, b, "i", "new Iterator(" + m() + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "i", "new Iterator(" + m() + ", true)"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "i", m("ema") + "." + Random.index(["entries", "keys", "values", "iterator"])); } },
    { w: 3,  v: function(d, b) { return m("i") + ".next();"; } },
    { w: 3,  v: function(d, b) { return m("i") + ".send(" + m() + ");"; } },
    // Other ways to build iterators: https://developer.mozilla.org/en/JavaScript/Guide/Iterators_and_Generators

    // v: Primitive
    { w: 2,  v: function(d, b) { return assign(d, b, "v", Random.index(["4", "4.2", "NaN", "0", "-0", "Infinity", "-Infinity"])); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", "new Number(" + Random.index(["4", "4.2", "NaN", "0", "-0", "Infinity", "-Infinity"]) + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", "new Number(" + m() + ")"); } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", makeBoolean(d, b)); } },
    { w: 2,  v: function(d, b) { return assign(d, b, "v", Random.index(["undefined", "null", "true", "false"])); } },

    // evil things we can do to any object property
    { w: 1,  v: function(d, b) { return "/*ODP-1*/Object.defineProperty(" + m() + ", " + makePropertyName(d, b) + ", " + makePropertyDescriptor(d, b) + ");"; } },
    { w: 1,  v: function(d, b) { return "/*ODP-2*/Object.defineProperty(" + m() + ", " + makePropertyName(d, b) + ", { " + propertyDescriptorPrefix(d, b) + "get: " + makeEvilCallback(d,b) + ", set: " + makeEvilCallback(d, b) + " });"; } },
    { w: 1,  v: function(d, b) { return "/*ODP-3*/Object.defineProperty(" + m() + ", " + makePropertyName(d, b) + ", { " + propertyDescriptorPrefix(d, b) + "writable: " + makeBoolean(d,b) + ", value: " + val(d, b) + " });"; } },
    { w: 1,  v: function(d, b) { return "Object.prototype.watch.call(" + m() + ", " + makePropertyName(d, b) + ", " + makeEvilCallback(d, b) + ");"; } },
    { w: 1,  v: function(d, b) { return "Object.prototype.unwatch.call(" + m() + ", " + makePropertyName(d, b) + ");"; } },
    { w: 1,  v: function(d, b) { return "delete " + m() + "[" + makePropertyName(d, b) + "];"; } },
    { w: 1,  v: function(d, b) { return assign(d, b, "v", m() + "[" + makePropertyName(d, b) + "]"); } },
    { w: 1,  v: function(d, b) { return m() + "[" + makePropertyName(d, b) + "] = " + val(d, b) + ";"; } },

    // evil things we can do to any object
    { w: 5,  v: function(d, b) { return "print(" + m() + ");"; } },
    { w: 5,  v: function(d, b) { return "print(uneval(" + m() + "));"; } },
    { w: 5,  v: function(d, b) { return m() + ".toString = " + makeEvilCallback(d, b) + ";"; } },
    { w: 5,  v: function(d, b) { return m() + ".toSource = " + makeEvilCallback(d, b) + ";"; } },
    { w: 5,  v: function(d, b) { return m() + ".valueOf = " + makeEvilCallback(d, b) + ";"; } },
    { w: 2,  v: function(d, b) { return m() + ".__iterator__ = " + makeEvilCallback(d, b) + ";"; } },
    { w: 1,  v: function(d, b) { return m() + " = " + m() + ";"; } },
    { w: 1,  v: function(d, b) { return m() + " = " + m("g") + ".objectEmulatingUndefined();"; } },
    { w: 1,  v: function(d, b) { return m("o") + " = " + m() + ".__proto__;"; } },
    { w: 5,  v: function(d, b) { return m() + ".__proto__ = " + m() + ";"; } },
    { w: 10, v: function(d, b) { return "for (var p in " + m() + ") { " + makeBuilderStatements(d, b) + " }"; } },
    { w: 10, v: function(d, b) { return "for (var v of " + m() + ") { " + makeBuilderStatements(d, b) + " }"; } },
    { w: 10, v: function(d, b) { return m() + " + " + m() + ";"; } }, // valueOf
    { w: 10, v: function(d, b) { return m() + " + '';"; } }, // toString
    { w: 10, v: function(d, b) { return m("v") + " = (" + m() + " instanceof " + m() + ");"; } },
    { w: 10, v: function(d, b) { return m("v") + " = Object.prototype.isPrototypeOf.call(" + m() + ", " + m() + ");"; } },
    { w: 2,  v: function(d, b) { return "Object." + Random.index(["preventExtensions", "seal", "freeze"]) + "(" + m() + ");"; } },

    // Be promiscuous with the rest of jsfunfuzz
    { w: 1,  v: function(d, b) { return m() + " = x;"; } },
    { w: 1,  v: function(d, b) { return "x = " + m() + ";"; } },
    { w: 5,  v: makeStatement },

    { w: 5,  v: initializeEverything },
  ]);
  makeBuilderStatement = function(d, b) {
    return (Random.index(builderStatementMakers))(d - 1, b);
  };
})();


function infrequentCondition(v, n)
{
  switch (rnd(20)) {
    case 0: return true;
    case 1: return false;
    case 2: return v + " > " + rnd(n);
    default: var mod = rnd(n) + 2; var target = rnd(mod); return "/*ICCD*/" + v + " % " + mod + (rnd(8) ? " == " : " != ") + target;
  }
}

var arrayBufferType = "SharedArrayBuffer" in this ?
  function() { return rnd(2) ? "SharedArrayBuffer" : "ArrayBuffer"; } :
  function() { return "ArrayBuffer"; };


// /home/admin/funfuzz/js/jsfunfuzz/test-asm.js


/***************************
 * TEST ASM.JS CORRECTNESS *
 ***************************/

// asm.js functions should always have the same semantics as JavaScript functions.
//
// We just need to watch out for:
// * Invalid asm.js
// * Foreign imports of impure functions
// * Mixing int and double heap views (NaN bits)
// * Allowing mutable state to diverge (mutable module globals, heap)

// In those cases, we can test that the asm-compiled version matches the normal js version.
// *  isAsmJSFunction(f)
// * !isAsmJSFunction(g)

// Because we pass the 'sanePlease' flag to asmJSInterior,
// * We don't expect any parse errors. (testOneAsmJSInterior currently relies on this.)
// * We expect only the following asm.js type errors:
//   * "numeric literal out of representable integer range" (https://github.com/dherman/asm.js/issues/67 makes composition hard)
//   * "no duplicate case labels" (because asmSwitchStatement doesn't avoid this)
// * And the following, infrequently, due to out-of-range integer literals:
//   * "one arg to int multiply must be a small (-2^20, 2^20) int literal"
//   * "arguments to / or % must both be double, signed, or unsigned, unsigned and signed are given"
//   * "unsigned is not a subtype of signed or doublish" [Math.abs]


var compareAsm = (function() {

  function isSameNumber(a, b)
  {
    if (!(typeof a == "number" && typeof b == "number"))
      return false;

    // Differentiate between 0 and -0
    if (a === 0 && b === 0)
      return 1/a === 1/b;

    // Don't differentiate between NaNs
    return a === b || (a !== a && b !== b);
  }

  var asmvals = [
    1, Math.PI, 42,
    // Special float values
    0, -0, 0/0, 1/0, -1/0,
    // Boundaries of int, signed, unsigned (near +/- 2^31, +/- 2^32)
     0x07fffffff,  0x080000000,  0x080000001,
    -0x07fffffff, -0x080000000, -0x080000001,
     0x0ffffffff,  0x100000000,  0x100000001,
    -0x0ffffffff, -0x100000000,  0x100000001,
    // Boundaries of double
    Number.MIN_VALUE, -Number.MIN_VALUE,
    Number.MAX_VALUE, -Number.MAX_VALUE,
  ];
  var asmvalsLen = asmvals.length;

  function compareUnaryFunctions(f, g)
  {
    for (var i = 0; i < asmvalsLen; ++i) {
      var x = asmvals[i];
      var fr = f(x);
      var gr = g(x);
      if (!isSameNumber(fr, gr)) {
        foundABug("asm mismatch", "(" + uneval(x) + ") -> " + uneval(fr) + " vs "  + uneval(gr));
      }
    }
  }

  function compareBinaryFunctions(f, g)
  {
    for (var i = 0; i < asmvalsLen; ++i) {
      var x = asmvals[i];
      for (var j = 0; j < asmvalsLen; ++j) {
        var y = asmvals[j];
        var fr = f(x, y);
        var gr = g(x, y);
        if (!isSameNumber(fr, gr)) {
          foundABug("asm mismatch", "(" + uneval(x) + ", " + uneval(y) + ") -> " + uneval(fr) + " vs "  + uneval(gr));
        }
      }
    }
  }

  return {compareUnaryFunctions: compareUnaryFunctions, compareBinaryFunctions: compareBinaryFunctions};
})();

function nanBitsMayBeVisible(s)
{
  // Does the code use more than one of {*int*, float32, or float64} views on the same array buffer?
  return (s.indexOf("Uint") != -1 || s.indexOf("Int") != -1) + (s.indexOf("Float32Array") != -1) + (s.indexOf("Float64Array") != -1) > 1;
}

var pureForeign = {
  identity:  function(x) { return x; },
  quadruple: function(x) { return x * 4; },
  half:      function(x) { return x / 2; },
  // Test coercion coming back from FFI.
  asString:  function(x) { return uneval(x); },
  asValueOf: function(x) { return { valueOf: function() { return x; } }; },
  // Test register arguments vs stack arguments.
  sum:       function()  { var s = 0; for (var i = 0; i < arguments.length; ++i) s += arguments[i]; return s; },
  // Will be replaced by calling makeRegisterStompFunction
  stomp:     function()  { },
};

for (var f in unaryMathFunctions) {
  pureForeign["Math_" + unaryMathFunctions[f]] = Math[unaryMathFunctions[f]];
}

for (var f in binaryMathFunctions) {
  pureForeign["Math_" + binaryMathFunctions[f]] = Math[binaryMathFunctions[f]];
}

var pureMathNames = Object.keys(pureForeign);

function generateAsmDifferential()
{
  var foreignFunctions = rnd(10) ? [] : pureMathNames;
  return asmJSInterior(foreignFunctions, true);
}

function testAsmDifferential(stdlib, interior)
{
  if (nanBitsMayBeVisible(interior)) {
    dumpln("Skipping correctness test for asm module that could expose low bits of NaN");
    return;
  }

  var asmJs = "(function(stdlib, foreign, heap) { 'use asm'; " + interior + " })";
  var asmModule = eval(asmJs);

  if (isAsmJSModule(asmModule)) {
    var asmHeap = new ArrayBuffer(4096);
    (new Int32Array(asmHeap))[0] = 0x12345678;
    var asmFun = asmModule(stdlib, pureForeign, asmHeap);

    var normalHeap = new ArrayBuffer(4096);
    (new Int32Array(normalHeap))[0] = 0x12345678;
    var normalJs = "(function(stdlib, foreign, heap) { " + interior + " })";
    var normalModule = eval(normalJs);
    var normalFun = normalModule(stdlib, pureForeign, normalHeap);

    compareAsm.compareBinaryFunctions(asmFun, normalFun);
  }
}

// Call this instead of start() to run asm-differential tests
function startAsmDifferential()
{
  var asmFuzzSeed = Math.floor(Math.random() * Math.pow(2,28));
  dumpln("asmFuzzSeed: " + asmFuzzSeed);
  Random.init(asmFuzzSeed);

  while (true) {

    var stompStr = makeRegisterStompFunction(8, [], true);
    print(stompStr);
    pureForeign.stomp = eval(stompStr);

    for (var i = 0; i < 100; ++i) {
      var interior = generateAsmDifferential();
      print(interior);
      testAsmDifferential(this, interior);
    }
    gc();
  }
}


// /home/admin/funfuzz/js/jsfunfuzz/test-math.js


var numericVals = [
  "1", "Math.PI", "42",
  // Special float values
  "0", "-0", "0/0", "1/0", "-1/0",
  // Boundaries of int, signed, unsigned (near +/- 2^31, +/- 2^32)
   "0x07fffffff",  "0x080000000",  "0x080000001",
  "-0x07fffffff", "-0x080000000", "-0x080000001",
   "0x0ffffffff",  "0x100000000",  "0x100000001",
  "-0x0ffffffff", "-0x100000000",  "-0x100000001",
  // Boundaries of double
  "Number.MIN_VALUE", "-Number.MIN_VALUE",
  "Number.MAX_VALUE", "-Number.MAX_VALUE",
  // Boundaries of maximum safe integer
  "Number.MIN_SAFE_INTEGER", "-Number.MIN_SAFE_INTEGER",
  "-(2**53-2)", "-(2**53)", "-(2**53+2)",
  "Number.MAX_SAFE_INTEGER", "-Number.MAX_SAFE_INTEGER",
  "2**53-2", "2**53", "2**53+2",
  // See bug 1350097 - 1.79...e308 is the largest (by module) finite number
  "0.000000000000001", "1.7976931348623157e308",
];

var confusableVals = [
  "0",
  "0.1",
  "-0",
  "''",
  "'0'",
  "'\\0'",
  "[]",
  "[0]",
  "/0/",
  "'/0/'",
  "1",
  "({toString:function(){return '0';}})",
  "({valueOf:function(){return 0;}})",
  "({valueOf:function(){return '0';}})",
  "false",
  "true",
  "undefined",
  "null",
  "(function(){return 0;})",
  "NaN",
  "(new Boolean(false))",
  "(new Boolean(true))",
  "(new String(''))",
  "(new Number(0))",
  "(new Number(-0))",
  "objectEmulatingUndefined()",
];

function hashStr(s)
{
  var hash = 0;
  var L = s.length;
  for (var i = 0; i < L; i++) {
    var c = s.charCodeAt(i);
    hash = (Math.imul(hash, 31) + c) | 0;
  }
  return hash;
}

function testMathyFunction(f, inputs)
{
  var results = [];
  if (f) {
    for (var j = 0; j < inputs.length; ++j) {
      for (var k = 0; k < inputs.length; ++k) {
        try {
          results.push(f(inputs[j], inputs[k]));
        } catch(e) {
          results.push(errorToString(e));
        }
      }
    }
  }
  /* Use uneval to distinguish -0, 0, "0", etc. */
  /* Use hashStr to shorten the output and keep compareJIT files small. */
  print(hashStr(uneval(results)));
}

function mathInitFCM()
{
  // FCM cookie, lines with this cookie are used for compareJIT
  var cookie = "/*F" + "CM*/";

  print(cookie + hashStr.toString().replace(/\n/g, " "));
  print(cookie + testMathyFunction.toString().replace(/\n/g, " "));
}

function makeMathyFunAndTest(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  var i = rnd(NUM_MATH_FUNCTIONS);
  var s = "";

  if (rnd(5)) {
    if (rnd(8)) {
      s += "mathy" + i + " = " + makeMathFunction(6, b, i) + "; ";
    } else {
      s += "mathy" + i + " = " + makeAsmJSFunction(6, b) + "; ";
    }
  }

  if (rnd(5)) {
    var inputsStr;
    switch(rnd(8)) {
      case 0:  inputsStr = makeMixedTypeArray(d - 1, b); break;
      case 1:  inputsStr = "[" + Random.shuffled(confusableVals).join(", ") + "]"; break;
      default: inputsStr = "[" + Random.shuffled(numericVals).join(", ") + "]"; break;
    }

    s += "testMathyFunction(mathy" + i + ", " + inputsStr + "); ";
  }

  return s;
}

function makeMathyFunRef(d, b)
{
  if (rnd(TOTALLY_RANDOM) == 2) return totallyRandom(d, b);

  return "mathy" + rnd(NUM_MATH_FUNCTIONS);
}


// /home/admin/funfuzz/js/jsfunfuzz/test-regex.js


/*****************
 * USING REGEXPS *
 *****************/

function randomRegexFlags() {
  var s = "";
  if (rnd(2))
    s += "g";
  if (rnd(2))
    s += "y";
  if (rnd(2))
    s += "i";
  if (rnd(2))
    s += "m";
  return s;
}

function toRegexSource(rexpat)
{
  return (rnd(2) === 0 && rexpat.charAt(0) != "*") ?
    "/" + rexpat + "/" + randomRegexFlags() :
    "new RegExp(" + simpleSource(rexpat) + ", " + simpleSource(randomRegexFlags()) + ")";
}

function makeRegexUseBlock(d, b, rexExpr, strExpr)
{
  var rexpair = regexPattern(10, false);
  var rexpat = rexpair[0];
  var str = rexpair[1][rnd(POTENTIAL_MATCHES)];

  if (!rexExpr) rexExpr = rnd(10) === 0 ? makeExpr(d - 1, b) : toRegexSource(rexpat);
  if (!strExpr) strExpr = rnd(10) === 0 ? makeExpr(d - 1, b) : simpleSource(str);

  var bv = b.concat(["s", "r"]);

  return ("/*RXUB*/var r = " + rexExpr + "; " +
          "var s = " + strExpr + "; " +
          "print(" +
            Random.index([
              "r.exec(s)",
              "uneval(r.exec(s))",
              "r.test(s)",
              "s.match(r)",
              "uneval(s.match(r))",
              "s.search(r)",
              "s.replace(r, " + makeReplacement(d, bv) + (rnd(3) ? "" : ", " + simpleSource(randomRegexFlags())) + ")",
              "s.split(r)"
            ]) +
          "); " +
          (rnd(3) ? "" : "print(r.lastIndex); ")
          );
}

function makeRegexUseExpr(d, b)
{
  var rexpair = regexPattern(8, false);
  var rexpat = rexpair[0];
  var str = rexpair[1][rnd(POTENTIAL_MATCHES)];

  var rexExpr = rnd(10) === 0 ? makeExpr(d - 1, b) : toRegexSource(rexpat);
  var strExpr = rnd(10) === 0 ? makeExpr(d - 1, b) : simpleSource(str);

  return "/*RXUE*/" + rexExpr + ".exec(" + strExpr + ")";
}

function makeRegex(d, b)
{
  var rexpair = regexPattern(8, false);
  var rexpat = rexpair[0];
  var rexExpr = toRegexSource(rexpat);
  return rexExpr;
}

function makeReplacement(d, b)
{
  switch(rnd(3)) {
    case 0:  return Random.index(["''", "'x'", "'\\u0341'"]);
    case 1:  return makeExpr(d, b);
    default: return makeFunction(d, b);
  }
}



// /home/admin/funfuzz/js/jsfunfuzz/test-consistency.js




/*******************************
 * EXECUTION CONSISTENCY TESTS *
 *******************************/

function sandboxResult(code, zone)
{
  // Use sandbox to isolate side-effects.
  var result;
  var resultStr = "";
  try {
    // Using newGlobal(), rather than evalcx(''), to get
    // shell functions. (see bug 647412 comment 2)
    var sandbox = newGlobal({sameZoneAs: zone});

    result = evalcx(code, sandbox);
    if (typeof result != "object") {
      // Avoid cross-compartment excitement if it has a toString
      resultStr = "" + result;
    }
  } catch(e) {
    result = "Error: " + errorToString(e);
  }
  //print("resultStr: " + resultStr);
  return resultStr;
}

function nestingConsistencyTest(code)
{
  // Inspired by bug 676343
  // This only makes sense if |code| is an expression (or an expression followed by a semicolon). Oh well.
  function nestExpr(e) { return "(function() { return " + code + "; })()"; }
  var codeNestedOnce = nestExpr(code);
  var codeNestedDeep = code;
  var depth = (count % 7) + 14; // 16 might be special
  for (var i = 0; i < depth; ++i) {
    codeNestedDeep = nestExpr(codeNestedDeep);
  }

  // These are on the same line so that line numbers in stack traces will match.
  var resultO = sandboxResult(codeNestedOnce, null); var resultD = sandboxResult(codeNestedDeep, null);

  //if (resultO != "" && resultO != "undefined" && resultO != "use strict")
  //  print("NestTest: " + resultO);

  if (resultO != resultD) {
    foundABug("NestTest mismatch",
      "resultO: " + resultO + "\n" +
      "resultD: " + resultD);
  }
}



// /home/admin/funfuzz/js/jsfunfuzz/test-misc.js


function optionalTests(f, code, wtt)
{
  if (count % 100 == 1) {
    tryHalves(code);
  }

  if (count % 100 == 2 && engine == ENGINE_SPIDERMONKEY_TRUNK) {
    try {
      Reflect.parse(code);
    } catch(e) {
    }
  }

  if (count % 100 == 3 && f && typeof disassemble == "function") {
    // It's hard to use the recursive disassembly in the comparator,
    // but let's at least make sure the disassembler itself doesn't crash.
    disassemble("-r", f);
  }

  if (0 && f && wtt.allowExec && engine == ENGINE_SPIDERMONKEY_TRUNK) {
    testExpressionDecompiler(code);
    tryEnsureSanity();
  }

  if (count % 100 == 6 && f && wtt.allowExec && wtt.expectConsistentOutput && wtt.expectConsistentOutputAcrossIter
    && engine == ENGINE_SPIDERMONKEY_TRUNK && getBuildConfiguration()['more-deterministic']) {
    nestingConsistencyTest(code);
  }
}


function testExpressionDecompiler(code)
{
  var fullCode = "(function() { try { \n" + code + "\n; throw 1; } catch(exx) { this.nnn.nnn } })()";

  try {
    eval(fullCode);
  } catch(e) {
    if (e.message != "this.nnn is undefined" && e.message.indexOf("redeclaration of") == -1) {
      // Break up the following string intentionally, to prevent matching when contents of jsfunfuzz is printed.
      foundABug("Wrong error " + "message", e);
    }
  }
}


function tryHalves(code)
{
  // See if there are any especially horrible bugs that appear when the parser has to start/stop in the middle of something. this is kinda evil.

  // Stray "}"s are likely in secondHalf, so use new Function rather than eval.  "}" can't escape from new Function :)

  var f, firstHalf, secondHalf;

  try {

    firstHalf = code.substr(0, code.length / 2);
    if (verbose)
      dumpln("First half: " + firstHalf);
    f = new Function(firstHalf);
    void ("" + f);
  }
  catch(e) {
    if (verbose)
      dumpln("First half compilation error: " + e);
  }

  try {
    secondHalf = code.substr(code.length / 2, code.length);
    if (verbose)
      dumpln("Second half: " + secondHalf);
    f = new Function(secondHalf);
    void ("" + f);
  }
  catch(e) {
    if (verbose)
      dumpln("Second half compilation error: " + e);
  }
}


// /home/admin/funfuzz/js/jsfunfuzz/driver.js

function start(glob)
{
  var fuzzSeed = Math.floor(Math.random() * Math.pow(2,28));
  dumpln("fuzzSeed: " + fuzzSeed);
  Random.init(fuzzSeed);

  // Split this string across two source strings to ensure that if a
  // generated function manages to output the entire jsfunfuzz source,
  // that output won't match the grep command.
  var cookie = "/*F";
  cookie += "RC-fuzzSeed-" + fuzzSeed + "*/";

  // Can be set to true if makeStatement has side effects, such as crashing, so you have to reduce "the hard way".
  var dumpEachSeed = false;

  if (dumpEachSeed) {
    dumpln(cookie + "Random.init(0);");
  }

  mathInitFCM();

  count = 0;

  if (jsshell) {
    // If another script specified a "maxRunTime" argument, use it; otherwise, run forever
    var MAX_TOTAL_TIME = (glob.maxRunTime) || (Infinity);
    var startTime = new Date();
    var lastTime;

    do {
      testOne();
      var elapsed1 = new Date() - lastTime;
      if (elapsed1 > 1000) {
        print("That took " + elapsed1 + "ms!");
      }
      lastTime = new Date();
    } while(lastTime - startTime < MAX_TOTAL_TIME);
  } else {
    setTimeout(testStuffForAWhile, 200);
  }

  function testStuffForAWhile()
  {
    for (var j = 0; j < 100; ++j)
      testOne();

    if (count % 10000 < 100)
      printImportant("Iterations: " + count);

    setTimeout(testStuffForAWhile, 30);
  }

  function testOne()
  {
    ++count;

    // Sometimes it makes sense to start with simpler functions:
    //var depth = ((count / 1000) | 0) & 16;
    var depth = 14;

    if (dumpEachSeed) {
      // More complicated, but results in a much shorter script, making SpiderMonkey happier.
      var MTA = uneval(Random.twister.export_mta());
      var MTI = Random.twister.export_mti();
      if (MTA != Random.lastDumpedMTA) {
        dumpln(cookie + "Random.twister.import_mta(" + MTA + ");");
        Random.lastDumpedMTA = MTA;
      }
      dumpln(cookie + "Random.twister.import_mti(" + MTI + "); void (makeScript(" + depth + "));");
    }

    var code = makeScript(depth);

    if (count == 1 && engine == ENGINE_SPIDERMONKEY_TRUNK && rnd(5)) {
      code = "tryRunning = useSpidermonkeyShellSandbox(" + rnd(4) + ");";
      //print("Sane mode!")
    }

  //  if (rnd(10) === 1) {
  //    var dp = "/*infloop-deParen*/" + Random.index(deParen(code));
  //    if (dp)
  //      code = dp;
  //  }
    dumpln(cookie + "count=" + count + "; tryItOut(" + uneval(code) + ");");

    tryItOut(code);
  }
}


function failsToCompileInTry(code) {
  // Why would this happen? One way is "let x, x"
  try {
    var codeInTry = "try { " + code + " } catch(e) { }";
    void new Function(codeInTry);
    return false;
  } catch(e) {
    return true;
  }
}



// /home/admin/funfuzz/js/jsfunfuzz/run-reduction-marker.js

// SECOND NIGEBDD (NIGEBDD will be reversed RTL during jsfunfuzz testcase reduction)


// /home/admin/funfuzz/js/jsfunfuzz/run-in-sandbox.js


/*********************
 * SANDBOXED RUNNING *
 *********************/

// We support three ways to run generated code:
// * useGeckoSandbox(), which uses Components.utils.Sandbox.
//    * In xpcshell, we always use this method, so we don't accidentally erase the hard drive.
//
// * useSpidermonkeyShellSandbox(), which uses evalcx() with newGlobal().
//   * In spidermonkey shell, we often use this method, so we can do additional correctness tests.
//
// * tryRunningDirectly(), which uses eval() or new Function().
//   * This creates the most "interesting" testcases.

var tryRunning = xpcshell ? useGeckoSandbox() : tryRunningDirectly;
function fillShellSandbox(sandbox)
{
  var safeFuns = [
    "print",
    "schedulegc", "selectforgc", "gczeal", "gc", "gcslice",
    "verifyprebarriers", "gcPreserveCode",
    "minorgc", "abortgc",
    "evalcx", "newGlobal", "evaluate",
    "dumpln", "fillShellSandbox",
    "testMathyFunction", "hashStr",
    "isAsmJSCompilationAvailable",
  ];

  for (var i = 0; i < safeFuns.length; ++i) {
    var fn = safeFuns[i];
    if (sandbox[fn]) {
      //print("Target already has " + fn);
    } else if (this[fn]) { // FIXME: strict mode compliance requires passing glob around
      sandbox[fn] = this[fn].bind(this);
    } else {
      //print("Source is missing " + fn);
    }
  }

  return sandbox;
}

function useSpidermonkeyShellSandbox(sandboxType)
{
  var primarySandbox;

  switch (sandboxType) {
    case 0:  primarySandbox = evalcx('');
    case 1:  primarySandbox = evalcx('lazy');
    case 2:  primarySandbox = newGlobal({sameZoneAs: {}}); // same zone
    default: primarySandbox = newGlobal(); // new zone
  }

  fillShellSandbox(primarySandbox);

  return function(f, code, wtt) {
    try {
      evalcx(code, primarySandbox);
    } catch(e) {
      dumpln("Running in sandbox threw " + errorToString(e));
    }
  };
}

// When in xpcshell,
// * Run all testing in a sandbox so it doesn't accidentally wipe my hard drive.
// * Test interaction between sandboxes with same or different principals.
function newGeckoSandbox(n)
{
  var t = (typeof n == "number") ? n : 1;
  var s = Components.utils.Sandbox("http://x" + t + ".example.com/");

  // Allow the sandbox to do a few things
  s.newGeckoSandbox = newGeckoSandbox;
  s.evalInSandbox = function(str, sbx) {
    return Components.utils.evalInSandbox(str, sbx);
  };
  s.print = function(str) { print(str); };

  return s;
}

function useGeckoSandbox() {
  var primarySandbox = newGeckoSandbox(0);

  return function(f, code, wtt) {
    try {
      Components.utils.evalInSandbox(code, primarySandbox);
    } catch(e) {
      // It might not be safe to operate on |e|.
    }
  };
}


// /home/admin/funfuzz/js/jsfunfuzz/run.js



/***********************
 * UNSANDBOXED RUNNING *
 ***********************/

// Hack to make line numbers be consistent, to make spidermonkey
// disassemble() comparison testing easier (e.g. for round-trip testing)
function directEvalC(s) { var c; /* evil closureizer */ return eval(s); } function newFun(s) { return new Function(s); }

function tryRunningDirectly(f, code, wtt)
{
  if (count % 23 == 3) {
    dumpln("Plain eval!");
    try { eval(code); } catch(e) { }
    tryEnsureSanity();
    return;
  }

  if (count % 23 == 4) {
    dumpln("About to recompile, using eval hack.");
    f = directEvalC("(function(){" + code + "});");
  }

  try {
    if (verbose)
      dumpln("About to run it!");
    var rv = f();
    if (verbose)
      dumpln("It ran!");
    if (wtt.allowIter && rv && typeof rv == "object") {
      tryIteration(rv);
    }
  } catch(runError) {
    if(verbose)
      dumpln("Running threw!  About to toString to error.");
    var err = errorToString(runError);
    dumpln("Running threw: " + err);
  }

  tryEnsureSanity();
}


// Store things now so we can restore sanity later.
var realEval = eval;
var realMath = Math;
var realFunction = Function;
var realGC = gc;
var realUneval = uneval;
var realToString = toString;
var realToSource = this.toSource; // "this." because it only exists in spidermonkey


function tryEnsureSanity()
{
  // The script might have set up oomAfterAllocations or oomAtAllocation.
  // Turn it off so we can test only generated code with it.
  try {
    if (typeof resetOOMFailure == "function")
      resetOOMFailure();
  } catch(e) { }

  try {
    // The script might have turned on gczeal.
    // Turn it off to avoid slowness.
    if (typeof gczeal == "function")
      gczeal(0);
  } catch(e) { }

  // At least one bug in the past has put exceptions in strange places.  This also catches "eval getter" issues.
  try { eval(""); } catch(e) { dumpln("That really shouldn't have thrown: " + errorToString(e)); }

  if (!this) {
    // Strict mode. Great.
    return;
  }

  try {
    // Try to get rid of any fake 'unwatch' functions.
    delete this.unwatch;

    // Restore important stuff that might have been broken as soon as possible :)
    if ('unwatch' in this) {
      this.unwatch("eval");
      this.unwatch("Function");
      this.unwatch("gc");
      this.unwatch("uneval");
      this.unwatch("toSource");
      this.unwatch("toString");
    }

    if ('__defineSetter__' in this) {
      // The only way to get rid of getters/setters is to delete the property.
      if (!jsStrictMode)
        delete this.eval;
      delete this.Math;
      delete this.Function;
      delete this.gc;
      delete this.uneval;
      delete this.toSource;
      delete this.toString;
    }

    this.Math = realMath;
    this.eval = realEval;
    this.Function = realFunction;
    this.gc = realGC;
    this.uneval = realUneval;
    this.toSource = realToSource;
    this.toString = realToString;
  } catch(e) {
    confused("tryEnsureSanity failed: " + errorToString(e));
  }

  // These can fail if the page creates a getter for "eval", for example.
  if (this.eval != realEval)
    confused("Fuzz script replaced |eval|");
  if (Function != realFunction)
    confused("Fuzz script replaced |Function|");
}

function tryIteration(rv)
{
  try {
    if (Iterator(rv) !== rv)
      return; // not an iterator
  }
  catch(e) {
    // Is it a bug that it's possible to end up here?  Probably not!
    dumpln("Error while trying to determine whether it's an iterator!");
    dumpln("The error was: " + e);
    return;
  }

  dumpln("It's an iterator!");
  try {
    var iterCount = 0;
    for (var iterValue of rv)
      ++iterCount;
    dumpln("Iterating succeeded, iterCount == " + iterCount);
  } catch (iterError) {
    dumpln("Iterating threw!");
    dumpln("Iterating threw: " + errorToString(iterError));
  }
}

function tryItOut(code)
{
  // Accidentally leaving gczeal enabled for a long time would make jsfunfuzz really slow.
  if (typeof gczeal == "function")
    gczeal(0);

  // SpiderMonkey shell does not schedule GC on its own.  Help it not use too much memory.
  if (count % 1000 == 0) {
    dumpln("Paranoid GC (count=" + count + ")!");
    realGC();
  }

  var wtt = whatToTest(code);

  if (!wtt.allowParse)
    return;

  code = code.replace(/\/\*DUPTRY\d+\*\//, function(k) { var n = parseInt(k.substr(8), 10); dumpln(n); return strTimes("try{}catch(e){}", n); });

  if (jsStrictMode)
    code = "'use strict'; " + code; // ES5 10.1.1: new Function does not inherit strict mode

  var f;
  try {
    f = new Function(code);
  } catch(compileError) {
    dumpln("Compiling threw: " + errorToString(compileError));
  }

  if (f && wtt.allowExec && wtt.expectConsistentOutput && wtt.expectConsistentOutputAcrossJITs) {
    if (code.indexOf("\n") == -1 && code.indexOf("\r") == -1 && code.indexOf("\f") == -1 && code.indexOf("\0") == -1 &&
        code.indexOf("\u2028") == -1 && code.indexOf("\u2029") == -1 &&
        code.indexOf("<--") == -1 && code.indexOf("-->") == -1 && code.indexOf("//") == -1) {
      // FCM cookie, lines with this cookie are used for compareJIT
      var cookie1 = "/*F";
      var cookie2 = "CM*/";
      var nCode = code;
      // Avoid compile-time errors because those are no fun.
      // But leave some things out of function(){} because some bugs are only detectable at top-level, and
      // pure jsfunfuzz doesn't test top-level at all.
      // (This is a good reason to use compareJIT even if I'm not interested in finding JIT bugs!)
      if (nCode.indexOf("return") != -1 || nCode.indexOf("yield") != -1 || nCode.indexOf("const") != -1 || failsToCompileInTry(nCode))
        nCode = "(function(){" + nCode + "})()";
      dumpln(cookie1 + cookie2 + " try { " + nCode + " } catch(e) { }");
    }
  }

  if (tryRunning != tryRunningDirectly) {
    optionalTests(f, code, wtt);
  }

  if (wtt.allowExec && f) {
    tryRunning(f, code, wtt);
  }

  if (verbose)
    dumpln("Done trying out that function!");

  dumpln("");
}


// /home/admin/funfuzz/js/jsfunfuzz/tail.js

var count = 0;
var verbose = false;


/**************************************
 * To reproduce a crash or assertion: *
 **************************************/

// 1. grep tryIt LOGFILE | grep -v "function tryIt" | pbcopy
// 2. Paste the result between "ddbegin" and "ddend", replacing "start(this);"
// 3. Run Lithium to remove unnecessary lines between "ddbegin" and "ddend".
// SPLICE DDBEGIN
/*fuzzSeed-94431925*/count=1; tryItOut("e0.delete(s1);");
/*fuzzSeed-94431925*/count=2; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log1p(((Number.MIN_VALUE || Math.fround(Math.fround((Math.fround(Math.hypot(((y || x) >>> 0), x)) && Math.fround(( + Math.log2(( + y)))))))) | ((((Math.max(((Math.round(((y ? x : (y ? y : y)) >>> 0)) >>> 0) | 0), (Math.max(y, x) | 0)) | 0) >>> 0) ? (Math.fround(Math.log2((Math.fround(Math.clz32(y)) ^ Math.fround((Math.fround(Math.acos(( + y))) === x))))) >>> 0) : (x >>> 0)) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[['z'], true, ({})]); ");
/*fuzzSeed-94431925*/count=3; tryItOut("\"use asm\"; v1 = evalcx(\"x >= x\", g1);");
/*fuzzSeed-94431925*/count=4; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-94431925*/count=5; tryItOut("Array.prototype.forEach.apply(a2, [i0]);function x() { e2 = new Set; } v2 = (m2 instanceof g1);");
/*fuzzSeed-94431925*/count=6; tryItOut("\"use strict\"; v2 = evalcx(\"v0 = this.t1.length;\", this.g0);");
/*fuzzSeed-94431925*/count=7; tryItOut("with({w:  '' }){v2 = NaN;print(x); }");
/*fuzzSeed-94431925*/count=8; tryItOut("a1[1];");
/*fuzzSeed-94431925*/count=9; tryItOut("\"use strict\"; throw window;this.zzz.zzz;");
/*fuzzSeed-94431925*/count=10; tryItOut("a1.pop(o0.a1);");
/*fuzzSeed-94431925*/count=11; tryItOut("testMathyFunction(mathy3, [2**53, 0/0, 2**53-2, -0x080000000, 0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -0x0ffffffff, -0x100000000, 1.7976931348623157e308, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, 1/0, -(2**53), -(2**53+2), 0x080000001, 0, 0x080000000, 1, 42, 2**53+2, -0x100000001, -0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=12; tryItOut("/*tLoop*/for (let b of /*MARR*/[new String('q'), [1], new String('q'), new String('q'), [1], [1], new String('q'), [1], [1], new String('q'), [1], [1], new String('q'), [1], new String('q'), new String('q'), new String('q'), [1], new String('q'), new String('q'), [1], new String('q'), new String('q'), [1], new String('q')]) { print((b.__defineGetter__(\"z\", mathy3))); }");
/*fuzzSeed-94431925*/count=13; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (Math.fround(Math.fround(Math.ceil(Math.fround(Math.tan(Math.fround(((Math.hypot(( + (y < ( + y))), (y >>> 0)) >>> 0) <= y))))))) >>> (Math.fround(( ! (Math.max(Math.fround(Math.cbrt((Math.abs(x) | 0))), y) | 0))) + ( + (x | 0))))); }); ");
/*fuzzSeed-94431925*/count=14; tryItOut("\"use strict\"; /*bLoop*/for (let zbrqyc = 0; zbrqyc < 71; ++zbrqyc) { if (zbrqyc % 6 == 1) { x = v0; } else { print(x); }  } ");
/*fuzzSeed-94431925*/count=15; tryItOut("\"use strict\"; e2.has(v0);");
/*fuzzSeed-94431925*/count=16; tryItOut("\"use strict\"; /*infloop*/ for (var d of []) {i0.next(); }function NaN() { \"use strict\"; yield x } /*oLoop*/for (pcundn = 0; pcundn < 0; ++pcundn) { a2 = arguments.callee.caller.arguments; } ");
/*fuzzSeed-94431925*/count=17; tryItOut("mathy3 = (function(x, y) { return (Math.max((( + ( ! ( + mathy2(( + (Math.hypot((y >>> 0), (Math.cosh(Math.fround(Math.fround(( - Math.fround(2**53-2))))) >>> 0)) >>> 0)), ( + ( + Math.asinh(x))))))) | 0), (Math.pow(Math.hypot((Math.hypot(42, Math.pow(y, y)) < (y | 0)), x), Math.acos(( + (y & (Math.exp(Math.fround(Math.sinh(Math.fround(x)))) | 0))))) | 0)) | 0); }); testMathyFunction(mathy3, [-(2**53+2), Number.MAX_SAFE_INTEGER, 0, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, 0/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, 1, -0x100000001, 0x080000001, 0x100000001, -(2**53-2), -1/0, -0x07fffffff, 1/0, -0x0ffffffff, Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, Number.MIN_VALUE, 42, 0x07fffffff, 0x080000000, 2**53-2, -0x080000001, -(2**53), 1.7976931348623157e308, 0x0ffffffff, 0x100000000, -0x100000000]); ");
/*fuzzSeed-94431925*/count=18; tryItOut("\"use strict\"; s1 = t0[allocationMarker()];this.m0 = new Map(e2);");
/*fuzzSeed-94431925*/count=19; tryItOut("Array.prototype.push.apply(a1, [Math.min(1, -20), o1.o2.b0, h0]);");
/*fuzzSeed-94431925*/count=20; tryItOut("L:while(((void shapeOf(x))) && 0){(x);w = Math.imul(-1, \"\\u4C13\"); }");
/*fuzzSeed-94431925*/count=21; tryItOut("mathy1 = (function(x, y) { return Math.hypot((((Math.max(y, (mathy0(Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround(y))), x) == ((( + ((y ? Math.fround(y) : y) | 0)) | 0) >>> 0))) >>> 0) + ((x < mathy0(( + mathy0(((((y | 0) > (0/0 | 0)) | 0) >>> 0), ( + x))), x)) >>> 0)) >>> 0), (( ! ( + Math.atan2(Math.sinh(2**53-2), ((( + Math.fround((x > Math.fround(y)))) >>> 0) < Math.pow(y, y))))) | 0)); }); testMathyFunction(mathy1, [0, '', (new Number(-0)), 0.1, (new Boolean(true)), (new Number(0)), NaN, ({valueOf:function(){return '0';}}), [], false, true, '0', (new Boolean(false)), (new String('')), objectEmulatingUndefined(), '/0/', ({toString:function(){return '0';}}), (function(){return 0;}), [0], 1, -0, /0/, null, '\\0', undefined, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-94431925*/count=22; tryItOut("v2 = evaluate(\"function g2.f2(g2.h2) ((makeFinalizeObserver('tenured')))\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 != 1), sourceIsLazy: (void options('strict_mode')), catchTermination: (caller--) }));");
/*fuzzSeed-94431925*/count=23; tryItOut("\"use strict\"; rutqxr(Math.log10(-27));/*hhh*/function rutqxr(){/*RXUB*/var r = /(?!\\d|(?!$)){4}|[^](?:((?!^))){1}|\\3*\\b(.\\ueD99)*?|(?:(?=(?=(?!\\D))))?/yim; var s = \"\"; print(s.replace(r, String.prototype.startsWith, \"gym\")); }");
/*fuzzSeed-94431925*/count=24; tryItOut("\"use strict\"; x, zlpnvj, wazjdd, x, x, ibhsca;( /x/ );");
/*fuzzSeed-94431925*/count=25; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.fround(Math.pow(Math.fround(( + (x <= mathy4(Math.fround(( + Math.max(( + (0 != -Number.MIN_VALUE)), ( + (Math.hypot(x, -0) >>> 0))))), Math.fround((( + (-0x080000000 | 0)) | 0)))))), Math.fround(Math.atan2(( + (x >>> 0)), ((((Math.atan((x | 0)) | 0) | 0) == -0x080000001) << 2**53+2)))))) | (( + Math.asinh(Math.imul(Math.sinh(Math.fround(( ! y))), ( ~ ( + mathy1(x, (x + x))))))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[x, [undefined], [undefined], new Number(1), ({}), x, new Number(1), [undefined], [undefined], x, new Number(1), new Number(1), new Number(1), ({}), new Number(1), ({}), x, new Number(1), [undefined], new Number(1), [undefined], new Number(1), x, ({}), new Number(1), new Number(1), [undefined], [undefined], [undefined], new Number(1), x, x, ({}), x, [undefined], [undefined], new Number(1), new Number(1)]); ");
/*fuzzSeed-94431925*/count=26; tryItOut("\"use strict\"; e1.add(this.v0);");
/*fuzzSeed-94431925*/count=27; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(\\\\d+?|(.)|(?=$*))|\\\\W*(?=([\\\\u317D-\\\\\\u3679\\\\u0005]))|\\\\3{3}\", \"ym\"); var s = \"\\u3679\\u3679\"; print(s.match(r)); ");
/*fuzzSeed-94431925*/count=28; tryItOut("/*infloop*/ for  each(let RegExp.prototype.multiline in (eval(\"mathy1 = (function(x, y) { return (this << mathy0(Math.atan2((-0x080000001 ? y : Math.fround(Number.MIN_SAFE_INTEGER)), (mathy0(y, y) === ((((x ? -(2**53) : ( + ((y >>> 0) === ( + x)))) | 0) >>> 0) / mathy0(y, (x | 0))))), Math.fround(Math.fround((Math.fround(Math.max(-1/0, -0x080000000)) ^ Math.fround((((y >>> 0) / Math.fround(y)) >>> 0))))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), -0x07fffffff, -0, 0x100000001, 0/0, 0.000000000000001, 0x07fffffff, 0x100000000, -0x100000001, -Number.MIN_VALUE, 2**53+2, 0x0ffffffff, 1, -1/0, 2**53-2, -(2**53), Math.PI, -(2**53+2), -Number.MAX_VALUE, Number.MIN_VALUE, -0x100000000, -0x080000001, 0, 0x080000000, 1/0, -0x080000000, 42]); \") ? x : (eval(\"/* no regression tests found */\")\n))) {/*MXX1*/o0 = g1.Date.prototype.getUTCHours;a2 = a2.map((4277)); }");
/*fuzzSeed-94431925*/count=29; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(Math.acos(Math.max(( + Math.sinh(( ~ ( ! y)))), ( + Math.atan2(( + (( + 1) ? ( + Math.max(( + (Math.acosh(x) | 0)), ( + x))) : -0x0ffffffff)), (Math.hypot((x | 0), (x | 0)) | 0))))), ((((Math.pow(((Math.min((y >>> 0), ((Number.MIN_VALUE ^ y) >>> 0)) >>> 0) >>> 0), (Math.fround(Math.imul(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround(y))) >>> 0)) >>> 0) | 0) !== (Math.sinh((Math.fround(Math.max(y, ( + Math.atan2(( + -0), ( + y))))) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [0x100000001, -0, Number.MIN_VALUE, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 0x080000001, 1, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, -(2**53), 2**53-2, -0x080000000, 1/0, 0, -0x0ffffffff, -(2**53-2), 2**53+2, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, -1/0, 0.000000000000001, 0x080000000, Math.PI]); ");
/*fuzzSeed-94431925*/count=30; tryItOut("/*iii*/13/*hhh*/function mzijbz(){print( \"\"  ? -0 :  \"\" );}");
/*fuzzSeed-94431925*/count=31; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?:$|^)(\\\\3|^)){3,}([^\\\\>\\ucbcf\\\\cW]\\\\2)|(?!(?:(?:[^\\\\x97-\\uca06]))*?)*?\", \"m\"); var s = (( )); print(r.test(s)); ");
/*fuzzSeed-94431925*/count=32; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s1; print(r.test(s)); print(r.lastIndex); \n/* no regression tests found */\n");
/*fuzzSeed-94431925*/count=33; tryItOut("mathy4 = (function(x, y) { return Math.min(Math.fround(( ~ Math.fround(Math.imul(Math.log((( + (x | 0)) | 0)), Math.fround(( ! ( + mathy1(y, -1/0)))))))), Math.hypot(( ! Math.atan2(y, Math.fround(mathy3(Math.fround(( + x)), Math.fround(Math.pow(x, -0x0ffffffff)))))), ( + Math.sqrt(( + Math.pow((Math.pow((((2**53+2 | 0) <= (x | 0)) | 0), (Number.MAX_SAFE_INTEGER >>> 0)) | 0), ( - x))))))); }); testMathyFunction(mathy4, [0x080000000, Math.PI, -(2**53-2), -0, 1.7976931348623157e308, 0, 0x100000001, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, -(2**53+2), 0.000000000000001, 0/0, 1, -1/0, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 0x07fffffff, -0x080000000, 2**53+2, Number.MAX_VALUE, 42, -Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-94431925*/count=34; tryItOut("print(this.__defineSetter__(\"c\", Uint8Array));");
/*fuzzSeed-94431925*/count=35; tryItOut("mathy3 = (function(x, y) { return ( + (( + Math.hypot(Math.fround(Math.log(Math.fround(Math.atan2(( + Math.atan2(0x080000000, y)), mathy1(x, Math.fround(Math.min(Math.fround(y), Math.fround(y)))))))), Math.hypot(x, ( ! Math.abs(x))))) ? Math.fround(Math.sin((Math.acos(Math.fround(Math.atan((Math.log1p(( + y)) >>> 0)))) | 0))) : ( + ( + Math.imul(( + Math.fround(Math.hypot(Math.fround((Math.max(( ! -(2**53-2)), x) - x)), Math.fround(y)))), ( + Math.log(Math.expm1((Math.log1p(Math.fround((-0x080000001 >= Math.fround(( ~ y))))) >>> 0))))))))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, -(2**53-2), Math.PI, -0x100000000, -0x080000000, -Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 0x0ffffffff, -(2**53+2), -0x100000001, -0, 0x080000001, 0, -1/0, -0x07fffffff, 1/0, 0/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53+2, -Number.MIN_VALUE, 0x100000000, 2**53-2, 2**53, 0x100000001, Number.MAX_VALUE, 1, -0x080000001]); ");
/*fuzzSeed-94431925*/count=36; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.trunc(Math.fround(Math.fround(( ~ (Math.min(Math.exp(( - mathy0(-0x07fffffff, Math.fround(Math.hypot(x, y))))), ( + ( - Math.fround(Math.fround(( - Math.fround(x))))))) | 0))))); }); testMathyFunction(mathy1, [-(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), 42, 2**53-2, 0, -0x080000000, 0x100000001, -0x080000001, 0x07fffffff, -0, Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, 1/0, Number.MIN_VALUE, 1, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, -(2**53-2), 0x080000000, 1.7976931348623157e308, 0x100000000, 2**53+2, -0x100000001, 2**53, -1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=37; tryItOut("(((this.zzz.zzz) =  \"\" ));");
/*fuzzSeed-94431925*/count=38; tryItOut("delete e0[new String(\"1\")];");
/*fuzzSeed-94431925*/count=39; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=40; tryItOut("\"use strict\"; o1 + '';");
/*fuzzSeed-94431925*/count=41; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan2(Math.log10(Math.atan2((((Math.fround(Math.hypot((x | 0), (((( - y) ? (x >>> 0) : y) >>> 0) | 0))) != ( + y)) >>> 0) >>> 0), ((y || (Math.fround((x ? Math.fround(Math.pow(Math.fround(Number.MAX_SAFE_INTEGER), ( + y))) : x)) | 0)) >>> 0))), (Math.log1p(((( - Math.min(( + Number.MIN_VALUE), Math.max(y, x))) < y) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[ 'A' , new Boolean(true), new Boolean(true), new String('q'), new Boolean(true), objectEmulatingUndefined(),  'A' , new String('q'), new String('q'), new String('q'), (1/0),  'A' , objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), (1/0),  'A' , new Boolean(true), new Boolean(true), new Boolean(true),  'A' ,  'A' , (1/0), (1/0),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), (1/0), (1/0), new String('q'), new Boolean(true), objectEmulatingUndefined(), new String('q'), new String('q'), (1/0), (1/0), new String('q'),  'A' ,  'A' , objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true),  'A' , (1/0), (1/0), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0),  'A' , objectEmulatingUndefined(), new Boolean(true), (1/0), new Boolean(true), objectEmulatingUndefined(), new String('q'), (1/0),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , new Boolean(true), (1/0), new String('q'), new Boolean(true), objectEmulatingUndefined(), new Boolean(true),  'A' ,  'A' , new Boolean(true), (1/0), objectEmulatingUndefined(), (1/0), new String('q'), (1/0), new Boolean(true), (1/0),  'A' , objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'),  'A' , (1/0), new Boolean(true), (1/0), objectEmulatingUndefined(), (1/0), (1/0), new String('q'), (1/0), new String('q'),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new Boolean(true), (1/0), new String('q'),  'A' ]); ");
/*fuzzSeed-94431925*/count=42; tryItOut("testMathyFunction(mathy1, ['/0/', '', [], undefined, (new Number(-0)), null, ({valueOf:function(){return '0';}}), '\\0', (new Boolean(true)), '0', NaN, false, 1, (new Number(0)), [0], (new Boolean(false)), ({toString:function(){return '0';}}), objectEmulatingUndefined(), /0/, ({valueOf:function(){return 0;}}), (function(){return 0;}), true, 0, 0.1, -0, (new String(''))]); ");
/*fuzzSeed-94431925*/count=43; tryItOut("[z1];");
/*fuzzSeed-94431925*/count=44; tryItOut("for (var p in b2) { try { for (var v of s2) { try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e0) { } for (var p in o0.a2) { try { t2[12] = x; } catch(e0) { } try { e0.add(o0.g0); } catch(e1) { } m0.get(t0); } } } catch(e0) { } v1 = t2[6]; }");
/*fuzzSeed-94431925*/count=45; tryItOut("g2.v0 = a0.reduce, reduceRight((function() { h0 = this.a0[({valueOf: function() { /*RXUB*/var r = r2; var s = s1; print(uneval(r.exec(s))); return 2; }})]; return o0.t0; }));");
/*fuzzSeed-94431925*/count=46; tryItOut("mathy4 = (function(x, y) { return (( + Math.pow((( + mathy2(x, (y >>> 0))) !== (mathy0(x, (Math.imul(x, Math.atan(y)) | 0)) >>> 0)), (Math.trunc(Math.imul(y, (Math.fround(Math.min(Math.fround(( ! x)), Math.sign(y))) >>> 0))) | 0))) <= ((Math.hypot(Math.round(x), mathy0(( - ( + Math.sqrt(( + y)))), Math.fround(Math.min(Number.MIN_SAFE_INTEGER, Math.fround(x))))) | 0) << (((((( + mathy2(Math.abs((( ~ x) >>> 0)), x)) ? Math.fround((( + ( ! -0x080000000)) % Math.sign(x))) : ( + ( ~ ( ! Number.MAX_SAFE_INTEGER)))) >>> 0) | 0) === (( ~ ( ~ ( - y))) | 0)) | 0))); }); ");
/*fuzzSeed-94431925*/count=47; tryItOut("\"use strict\"; h0 = {};");
/*fuzzSeed-94431925*/count=48; tryItOut("let([] = x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: (void version(185)), enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(this.__defineGetter__(\"x\", \"\\uCDDC\")), /*wrap3*/(function(){ var mnhnig = x+=(x) = \"\\u4671\"; ((y, {}) =>  { \"use strict\"; yield new RegExp(\"(?=(?:(?:[h\\\\W\\\\S]))(?!,)(?=\\\\3){3,4})\", \"gm\") } )(); }), /*wrap3*/(function(){ var rdvujb = Math.hypot(16,  /x/ ); (allocationMarker())(); })), icxyyi, egscjr, a = \"\u03a0\", b = (makeFinalizeObserver('nursery')), e = (/(?=\\uC34A+)/gym in [,,z1] || 11), \u3056 = x, b = ( /x/ \n)) ((function(){try { this.zzz.zzz; } finally { let(etzlyn, z = x, a = x) ((function(){throw StopIteration;})()); } })());for(let a in (function() { \"use strict\"; yield x = new RegExp(\"[^]*|.|(?![\\\\D\\\\xd1-\\u4812]+)\\\\s{1}{2,}\", \"gyim\") == ((void options('strict_mode'))); } })()) let(a) { with({}) { return; } }");
/*fuzzSeed-94431925*/count=49; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-94431925*/count=50; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=51; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 36893488147419103000.0;\n    {\n      /*FFI*/ff((((((d1) != (d2))+((((0xfde6e590)-(/*FFI*/ff(((-65537.0)), ((-281474976710657.0)), ((1125899906842625.0)), ((-281474976710657.0)), ((1.00390625)), ((-1152921504606847000.0)), ((16777215.0)), ((1.125)), ((1.0625)))|0))>>>((/*FFI*/ff(((5.0)), ((-31.0)), ((-7.737125245533627e+25)), ((6.044629098073146e+23)), ((-1.0625)), ((1.25)), ((-1073741825.0)), ((33.0)), ((1.00390625)))|0)*0xbd59a))))|0)), (((((((0xf1acf1f7)) << ((0x2c92b8d9))))+((((+((0.25)))) * (((0xb3c98513) ? (16385.0) : (33.0)))))) ^ ((0x7fffffff) % (0x450e6885)))), ((-1.0)), ((abs((((Float32ArrayView[((0x1d41d7b3)) >> 2]))))|0)));\n    }\n    return (((0xedff1cfd)+(0xffffffff)))|0;\n  }\n  return f; })(this, {ff: Object.create}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x080000001, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0/0, -(2**53), Math.PI, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0, 2**53, 0x080000000, 0x07fffffff, 1/0, Number.MAX_VALUE, 1, -Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 0x100000000, 42, 0.000000000000001, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0x080000000, 2**53-2, -0x100000000, -Number.MIN_VALUE, -(2**53-2), -(2**53+2), -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=52; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.pow((Math.hypot(( - -0x0ffffffff), ( + -(2**53-2))) >>> 0), ( + ((Math.log1p(Math.min((( - x) | 0), y)) | 0) ? (Math.sin((Math.log1p(( + (((y >>> 0) ** x) >>> 0))) >>> 0)) >>> 0) : (Math.max(Math.pow(Math.asinh(-Number.MAX_SAFE_INTEGER), (Math.ceil(((x >= 0x080000000) >>> 0)) >>> 0)), (Math.sinh(Math.fround((y >>> y))) | 0)) >>> 0)))) >>> 0); }); ");
/*fuzzSeed-94431925*/count=53; tryItOut("g0 = a1[0];");
/*fuzzSeed-94431925*/count=54; tryItOut("\"use strict\"; g1.v1 = g2.runOffThreadScript();");
/*fuzzSeed-94431925*/count=55; tryItOut("testMathyFunction(mathy0, [1, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0x080000000, -0, -Number.MAX_VALUE, -0x100000001, Math.PI, 1.7976931348623157e308, -1/0, 0.000000000000001, 0x100000001, 2**53, -(2**53-2), 42, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, 0x07fffffff, 2**53+2, -Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 0x0ffffffff, 2**53-2, 1/0, 0/0]); ");
/*fuzzSeed-94431925*/count=56; tryItOut("t2 = new Float64Array(b1);\nmrebrs, c = true, x = x, NaN = (this.__proto__-=new (window)(\u3056, -29)), y;this.o2 = new Object;(new RegExp(\"(((?!(?=$)))+)|.|(?!\\\\b)\", \"y\"));\n");
/*fuzzSeed-94431925*/count=57; tryItOut("/*tLoop*/for (let x of /*MARR*/[new Boolean(true), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true)]) { v0 = t0.length; }");
/*fuzzSeed-94431925*/count=58; tryItOut("/*tLoop*/for (let e of /*MARR*/[x, [1], x, x, (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), x, (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), x, [1], (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), [1], x, [1], [1], (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), [1], x, x, (~\u3056 | /(?:\\2)/gm), (~\u3056 | /(?:\\2)/gm), x, [1], [1], [1], x, x, (~\u3056 | /(?:\\2)/gm), x, x, x, x, x, x, (~\u3056 | /(?:\\2)/gm), x, [1], (~\u3056 | /(?:\\2)/gm), [1], (~\u3056 | /(?:\\2)/gm), [1], [1], (~\u3056 | /(?:\\2)/gm)]) { a2.reverse(m2); }");
/*fuzzSeed-94431925*/count=59; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-94431925*/count=60; tryItOut("c = x.unwatch(\"a\");/*vLoop*/for (var dqrbyp = 0; dqrbyp < 9; ++dqrbyp) { const d = dqrbyp; let d = (/*MARR*/[ '\\0' , function(){},  '\\0' ,  '\\0' , 1e81, -Infinity, d, d, function(){}, function(){}, -Infinity, d, -Infinity, 1e81, -Infinity,  '\\0' , function(){}, function(){}, -Infinity,  '\\0' , d, -Infinity,  '\\0' , 1e81, function(){},  '\\0' ,  '\\0' , -Infinity, -Infinity, function(){},  '\\0' ,  '\\0' , -Infinity,  '\\0' ,  '\\0' , 1e81, -Infinity, 1e81,  '\\0' , d,  '\\0' , function(){}, d, -Infinity].sort), window, huwzun, xwjwro, c, c, y, d, x;(((x === c))); } ");
/*fuzzSeed-94431925*/count=61; tryItOut("mathy3 = (function(x, y) { return Math.fround((( ! ((((Math.atan(( ~ ((Math.clz32(1/0) >>> 0) | 0))) | 0) >>> 0) ** ( + Math.hypot(-0x100000001, Math.fround(x)))) >>> 0)) | ( + (Math.asin(Math.max(-0x100000000, x)) >>> 0)))); }); ");
/*fuzzSeed-94431925*/count=62; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((0 ** ( ! mathy0(x, 1.7976931348623157e308))) ? (( + (( + Number.MIN_VALUE) ** -0x07fffffff)) ? (( + Math.acos(Math.fround(-0x080000001))) ? ( + (Math.hypot((y | 0), (( ! y) | 0)) ? x : y)) : (Math.sqrt((y | 0)) | 0)) : Math.pow(Math.fround(Math.atan2(Math.fround(( ~ y)), Math.fround(y))), y)) : (Math.acos(((( ! (-Number.MIN_VALUE >>> 0)) >>> 0) >>> 0)) >>> 0)) | Math.ceil((( + Math.tanh(( + Math.pow(x, x)))) % (Math.expm1(( + (-0x07fffffff * -1/0))) >>> 0)))); }); testMathyFunction(mathy2, [-0, -(2**53-2), -0x100000001, -1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, 0x080000001, Number.MIN_VALUE, -0x100000000, -0x080000001, -Number.MAX_VALUE, 2**53+2, 0, 0x100000001, Math.PI, 0x100000000, 0x0ffffffff, 0.000000000000001, -(2**53), 1.7976931348623157e308, 1/0, 2**53, 0x080000000, -Number.MIN_VALUE, -0x0ffffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 1, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2]); ");
/*fuzzSeed-94431925*/count=63; tryItOut("for(z = e = true.unwatch(\"apply\") in (\ntrue)) /*RXUB*/var r = r2; var s = s0; print(uneval(s.match(r))); ");
/*fuzzSeed-94431925*/count=64; tryItOut("mathy4 = (function(x, y) { return ( - (Math.acos(Math.pow(y, x)) < ((Math.asin((-0x100000000 | 0)) | 0) | 0))); }); ");
/*fuzzSeed-94431925*/count=65; tryItOut("\"use strict\"; a0.unshift(Math.hypot(-9, (4277)) -= (4277), m0);");
/*fuzzSeed-94431925*/count=66; tryItOut("mathy4 = (function(x, y) { return Math.atan(Math.atanh(Math.expm1(Math.fround(x)))); }); testMathyFunction(mathy4, /*MARR*/[true, function(){}, function(){}, function(){}, (void 0), function(){}, [1], [1], true, [1], [1], function(){}, function(){}, function(){}, (void 0), function(){}, true, true, [1], function(){}, true, true, true, true, true, true, true, true, true, true, true, (void 0), function(){}, (void 0), function(){}, true, function(){}, function(){}, true, true, true, (void 0), true, (void 0), function(){}, (void 0), function(){}, function(){}, true, [1], (void 0), true, function(){}, (void 0), (void 0), (void 0), (void 0), [1], [1], (void 0), function(){}, true, function(){}, (void 0), true, true, true, [1], function(){}, true, (void 0), function(){}, true, (void 0)]); ");
/*fuzzSeed-94431925*/count=67; tryItOut("\"use strict\"; dcsgxx();/*hhh*/function dcsgxx(x, ...x){this.t0.set(a1, ({valueOf: function() { /*oLoop*/for (var riprhc = 0; riprhc < 107; ++riprhc) {  } return 9; }}));}");
/*fuzzSeed-94431925*/count=68; tryItOut("(new Function).bind(-16, [,])m1.get(e2);");
/*fuzzSeed-94431925*/count=69; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      (Float32ArrayView[((0xb2cc1cbc)-(0xfb73d4b5)+(!((\"\\u53E8\")))) >> 2]) = ((d1));\n    }\n    d0 = (d1);\n    d0 = (d1);\n    {\n      d1 = (((+abs(((d0)))) > (d0)) ? (d0) : (d0));\n    }\n    {\n      {\n        /*FFI*/ff(((abs(((((d0) != (((-1.0)) % ((-2199023255553.0))))-((0xffffffff) ? (0x33f1939b) : (0x7e702df6))) >> ((0xfa7a2810)*0xde9ae)))|0)), ((d1)), (((0x35618*(0x1ddbe37c)) | ((0xf5e154de)+((-1.25) < (1.0625))))), (((d0) + (+((Float64ArrayView[0]))))), ((((0x4aefb168)-(0x59194323)) >> ((0x181eeb2a)))), ((imul((0xf98b5b2d), (0xfe40dc32))|0)), ((~~(65537.0))), ((127.0)), ((35184372088833.0)), ((68719476737.0)), ((-2199023255553.0)), ((-590295810358705700000.0)), ((-576460752303423500.0)));\n      }\n    }\n    (Int32ArrayView[2]) = ((0xffa0d2f8)+(-0x8000000));\n    return ((-0x228a2*(0xfac80d73)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.setUTCSeconds}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [[0], 0.1, false, NaN, ({valueOf:function(){return '0';}}), (new Number(0)), true, ({toString:function(){return '0';}}), undefined, (function(){return 0;}), '\\0', '/0/', 1, '', [], 0, null, (new Boolean(false)), ({valueOf:function(){return 0;}}), (new String('')), /0/, objectEmulatingUndefined(), (new Boolean(true)), (new Number(-0)), -0, '0']); ");
/*fuzzSeed-94431925*/count=70; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = Object.defineProperty(d, \"call\", ({enumerable: (x % 5 == 4)})); print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=71; tryItOut("Array.prototype.unshift.call(a0, g2.i1, g0.f2);");
/*fuzzSeed-94431925*/count=72; tryItOut("g1.g0.t2.set(a0, (4277));");
/*fuzzSeed-94431925*/count=73; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy1((( + ( ~ ( + Math.fround(mathy3(Math.abs(Math.imul(Math.fround(Math.cosh((x ** y))), Math.fround(x))), Math.fround(Math.max(Math.pow(y, (( + Math.atan2(x, ( + 0x0ffffffff))) | 0)), (( ~ (Math.min(0x0ffffffff, -1/0) >>> 0)) | 0)))))))) >>> 0), (Math.cosh(((mathy0(((Math.clz32((0x100000000 ? (y | 0) : y)) >>> 0) | 0), (-Number.MIN_SAFE_INTEGER ** y)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, -0x0ffffffff, -(2**53-2), Math.PI, 0x100000001, 0x07fffffff, -0x07fffffff, 0x080000001, 1/0, -(2**53), -Number.MIN_VALUE, -0x100000001, 2**53+2, 2**53-2, 42, -0x100000000, -0x080000001, 0x100000000, Number.MIN_VALUE, -(2**53+2), -1/0, Number.MAX_SAFE_INTEGER, 0/0, 2**53, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-94431925*/count=74; tryItOut("Array.prototype.reverse.call(a0);");
/*fuzzSeed-94431925*/count=75; tryItOut("Object.defineProperty(this, \"a0\", { configurable: x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: RangeError.prototype.toString, enumerate: function() { throw 3; }, keys: undefined, }; })(x), eval--.getInt8, function shapeyConstructor(gxzjtx){if ( '' ) Object.defineProperty(this, \"set\", ({writable: true, configurable: (gxzjtx % 2 != 0)}));this[\"set\"] = (let (e=eval) e);this[\"set\"] = true;this[\"valueOf\"] = yield true;this[\"set\"] = ((void options('strict_mode')));{ g2.m2.get(o0.v1); } this[\"set\"] =  \"\" ;if ( /x/ ) this[\"set\"] = [];if ((eval++)) this[\"valueOf\"] = this.__defineGetter__(\"w\", eval).valueOf(\"number\");for (var ytqqiepzi in this) { }return this; }), enumerable: false,  get: function() {  return Array.prototype.concat.call(this.o2.a1, a1, m2, o0.v1); } });");
/*fuzzSeed-94431925*/count=76; tryItOut("/*ADP-3*/Object.defineProperty(a1, 7, { configurable: (x % 33 == 4), enumerable: x.watch(\"slice\", d => eval(\" '' ;\")), writable: x.yoyo(Object.defineProperty(x, 0, ({}))), value: a1 });");
/*fuzzSeed-94431925*/count=77; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(t0, s1);");
/*fuzzSeed-94431925*/count=78; tryItOut("e1.add(g1.s2);");
/*fuzzSeed-94431925*/count=79; tryItOut("mathy1 = (function(x, y) { return ((Math.ceil(y) - ( + ( - Math.fround(((2**53 && y) >>> 0))))) - Math.atan2(( + Math.acos(x)), Math.cbrt((((( ~ mathy0(Math.fround(y), Math.fround((x ? -Number.MAX_VALUE : 0x100000000)))) | 0) !== y) >>> 0)))); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-94431925*/count=80; tryItOut("v1 = t1.length;");
/*fuzzSeed-94431925*/count=81; tryItOut("i0 = new Iterator(f1);");
/*fuzzSeed-94431925*/count=82; tryItOut("t0.set(this.a2, 14);\ns0 = '';\n");
/*fuzzSeed-94431925*/count=83; tryItOut("\"use strict\"; for(let c in [(this - this)]) let(x = false, yewoqk, pgggqz, \u3056, nesbje, this, b) ((function(){yield;})());");
/*fuzzSeed-94431925*/count=84; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=85; tryItOut("\"use strict\"; let {z, this} = x, x = [/*UUV1*/(y.toString =  /x/ )], [[]] = ({} = {}), yyakwo, eliztj;{ if (!isAsmJSCompilationAvailable()) { void 0; gcPreserveCode(); } void 0; } m2 = new WeakMap;");
/*fuzzSeed-94431925*/count=86; tryItOut("e1.has(e2);");
/*fuzzSeed-94431925*/count=87; tryItOut("if((x % 29 != 17)) { if (e = Proxy.create(({/*TOODEEP*/})(({/*TOODEEP*/})( \"\" )),  \"\" ).unwatch(\"toTimeString\")) (Object.defineProperty(a, \"padEnd\", ({configurable: true})));} else ((encodeURIComponent)(this.__defineGetter__(\"x\", offThreadCompileScript)));");
/*fuzzSeed-94431925*/count=88; tryItOut("{zprint((x = ({z: new (\"\\uDA49\")(x)}))); }");
/*fuzzSeed-94431925*/count=89; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-94431925*/count=90; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        {\n          {\n            i1 = ((0x5f87319b));\n          }\n        }\n      }\n    }\n    d0 = (-1.1805916207174113e+21);\n    i1 = (0x7f138ad8);\n    {\n      i1 = (i1);\n    }\n    d0 = (d0);\n    /*FFI*/ff((((((+(((0xb8675e8e))>>>((0x1d77c5ef)))) == (+pow(((d0)), ((-1.2089258196146292e+24)))))) >> ((((0xfe41331b)+(-0x8000000))>>>((0x27af4f5) % (0x5eb032ec))) / (0x5fe62821)))), ((0x3e39497c)), ((0x8f8a6ca)), ((1.03125)), ((+(0.0/0.0))), ((+(1.0/0.0))), ((imul((0xffffffff), (0xc4cc50c5))|0)));\n    return +((-5.0));\n    d0 = (+(0.0/0.0));\n    return +((((-3.094850098213451e+26)) / (((0xffffffff) ? (d0) : (+((Int8ArrayView[((0xa1253c99)*-0x3eb66) >> 0])))))));\n  }\n  return f; })(this, {ff: Date.UTC}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [2**53, -Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -0x080000001, 2**53-2, 1, 1/0, -(2**53), -0, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, 0x080000000, 1.7976931348623157e308, Math.PI, 0.000000000000001, 0x100000001, 0x080000001, 0x100000000, -(2**53-2), 0/0, 42, -0x080000000]); ");
/*fuzzSeed-94431925*/count=91; tryItOut("print(s2);");
/*fuzzSeed-94431925*/count=92; tryItOut("this.zzz.zzz;");
/*fuzzSeed-94431925*/count=93; tryItOut("let a, y, y = ((yield window)), wsprky, mpnkos, utakxn, x, ziwagm;(/*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), (0/0), new String('q'), new String('q'), (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), (0/0), new String('q'), (0/0), objectEmulatingUndefined(), false, false, (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), false, (0/0), objectEmulatingUndefined(), (0/0), false, objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), (0/0), (0/0), objectEmulatingUndefined(), (0/0), (0/0), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), false, new String('q'), objectEmulatingUndefined(), false, false, new String('q'), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, objectEmulatingUndefined(), new String('q'), (0/0), false, false, false, (0/0), new String('q'), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (0/0), (0/0), objectEmulatingUndefined(), false, false, new String('q'), (0/0), objectEmulatingUndefined(), new String('q'), (0/0), false, new String('q'), objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), (0/0), false, false, objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), new String('q'), false, new String('q'), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), false, false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), new String('q'), (0/0), new String('q'), (0/0), (0/0), new String('q'), false, false, (0/0), new String('q'), new String('q'), (0/0), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, false, false, false, (0/0), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (0/0), (0/0), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), (0/0), (0/0)].sort(arguments.callee.caller, \"\\uAFE6\" > 24));");
/*fuzzSeed-94431925*/count=94; tryItOut("g0.v1 = new Number(p2);");
/*fuzzSeed-94431925*/count=95; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ! (Math.sqrt(mathy0(((x ? ( + Math.atan(Math.fround((0x100000001 | Math.fround(( - y)))))) : (Math.acosh((((Math.fround(( + ( + Number.MIN_SAFE_INTEGER))) >= (( + ( ! x)) >>> 0)) >>> 0) | 0)) | 0)) | 0), ( ! Math.fround(Math.min(( + (( ! -0x07fffffff) ? x : 0.000000000000001)), ( + x)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0, 1, -(2**53-2), 1.7976931348623157e308, 0/0, Math.PI, -0x100000001, 2**53+2, -(2**53), 0x080000000, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, Number.MIN_VALUE, 0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, -0x080000000, -0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -0x0ffffffff, -0x080000001, 1/0, 42, 2**53, -1/0, -(2**53+2), -0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=96; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -35184372088833.0;\n    switch (((((0x7fffffff) != (0x26f0a49))*0x69fd6)|0)) {\n      case -2:\n        {\n          d2 = (((1.5111572745182865e+23)) - ((-1.125)));\n        }\n      case -2:\n        (Float64ArrayView[(((0x32a46a4d))+(0xb358ad90)) >> 3]) = ((147573952589676410000.0));\n        break;\n    }\n    i0 = ((((+(-1.0/0.0))) % (((i1)))) <= (262143.0));\n    return +((34359738367.0));\n  }\n  return f; })(this, {ff: () =>  { return [] = x } }, new ArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=97; tryItOut("m0.has(f2);");
/*fuzzSeed-94431925*/count=98; tryItOut("var this.v0 = evaluate(\"/*vLoop*/for (eysrca = 0; eysrca < 32; ++eysrca) { c = eysrca; a2[\\\"constructor\\\"] = this.p2; } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (), sourceIsLazy: (x % 71 == 15), catchTermination: (x % 16 != 15) }));");
/*fuzzSeed-94431925*/count=99; tryItOut("\"use strict\"; v0 = (this.i2 instanceof o1.g0);");
/*fuzzSeed-94431925*/count=100; tryItOut("\"use strict\"; (28)\n");
/*fuzzSeed-94431925*/count=101; tryItOut("e0.add(h2);");
/*fuzzSeed-94431925*/count=102; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; try { startgc(32); } catch(e) { } } void 0; } /*tLoop*/for (let b of /*MARR*/[new String('q'), new Boolean(false), new String('q'), new String('q'), new Boolean(false), new String('q'), new Boolean(false), new String('q')]) { Array.prototype.splice.apply(a1, [-13, 7, g1.i0, h1]); }");
/*fuzzSeed-94431925*/count=103; tryItOut("print(x);d = (makeFinalizeObserver('nursery'));");
/*fuzzSeed-94431925*/count=104; tryItOut("g2.i0 + g2.t2;");
/*fuzzSeed-94431925*/count=105; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=106; tryItOut("\"use strict\"; v0 = evaluate(\"function f2(b0)  { yield (Math.max(-3, b0)) } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 17 == 12), sourceIsLazy: \"\\u8DB3\", catchTermination: (x % 4 != 0) }));");
/*fuzzSeed-94431925*/count=107; tryItOut("mathy5 = (function(x, y) { return Math.log1p((((Math.fround(Math.log1p(Math.fround(( ! Math.fround(x))))) | 0) & ((mathy2(( + y), Math.fround(( ~ Math.fround(Math.fround((Math.fround(0x080000000) ? x : Math.fround(x))))))) >>> 0) ? (Math.tanh(y) >>> 0) : Math.sqrt(x))) >>> 0)); }); ");
/*fuzzSeed-94431925*/count=108; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + (((Math.atan2((((x | 0) % (y | 0)) | 0), -0x07fffffff) == ((((x <= x) , 0x07fffffff) >>> 0) <= ((( + y) | 0) | 0))) < (((((( - -0) >>> x) ^ Math.tanh(x)) >>> 0) !== mathy0(Math.fround(Math.atan2(y, x)), x)) >>> 0)) >>> 0)) == ( + (Math.fround(Math.pow(( + ( ! (Math.atanh(( ~ y)) >>> 0))), Math.fround(Math.log1p(Math.fround(((0 | 0) !== (y >>> 0))))))) * Math.min((-0x0ffffffff && x), (( ! ( + x)) | 0))))); }); ");
/*fuzzSeed-94431925*/count=109; tryItOut("\"use strict\"; /*hhh*/function gosuyf(){if((x % 3 == 2)) {{}g0.o1.t2[19] = -24; } else (\"\\uA65F\");}gosuyf();");
/*fuzzSeed-94431925*/count=110; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.trunc(Math.atan(( ! ((( + y) >>> 0) >>> (x >>> 0)))))) ? ((Math.imul((( ! (x | 0)) | 0), ( + (( ~ ( + ( ~ (y >>> 0)))) >>> 0))) === Math.exp(y)) - ( + Math.ceil(( + Number.MIN_VALUE)))) : ( ~ (Math.imul(Math.hypot(( + x), ( + ((1.7976931348623157e308 !== y) | 0))), x) >>> 0))); }); testMathyFunction(mathy0, [0x07fffffff, 0x100000001, -0x0ffffffff, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, Number.MAX_VALUE, 0, 42, 1.7976931348623157e308, 2**53+2, 0x080000001, -0, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), -(2**53-2), Math.PI, 2**53-2, -0x080000000, -(2**53), 1/0, Number.MIN_VALUE, 0/0, -0x080000001, -0x100000001, 0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=111; tryItOut("let(x = arguments.callee, y = ((makeFinalizeObserver('nursery'))), c = ([, b] = x), e = (4277), dolrgk) { try { v2 = this.g0.runOffThreadScript(); } catch(\u3056 if (function(){let(x = allocationMarker(), a = /*RXUE*/new RegExp(\"\\\\1\", \"\").exec(\"0\\u00e0\\n\\n\\uf0a7\\n\\n\\uf396\\n0\\u00e0\\n\\n\\uf0a7\\n\\n\"), window =  '' , \u3056, window = x, x = this.__defineSetter__(\"a\", length)) { this.zzz.zzz;}})()) { let(e = \u3056, hxkann, tjbvlr, a, x = (4277), yftyop, a =  \"\" ) { this.zzz.zzz;} } finally { for(let e in /*PTHR*/(function() { for (var i of /*PTHR*/(function() { \"use strict\"; for (var i of Math.log2) { yield i; } })()) { yield i; } })()) e = NaN; } }for(let z of (function() { yield -4; } })()) for(let b in /*MARR*/[new Boolean(true), true, true, true, new Boolean(true), new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, true, true, true, new Boolean(true), true, new Boolean(true), new Boolean(true), true, new Boolean(true), true, true, true, new Boolean(true), true, true, true, true, true, true, true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, new Boolean(true), true, true, true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, new Boolean(true), true, new Boolean(true), true, new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), true, true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, true, true, true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), new Boolean(true), true, true, new Boolean(true), new Boolean(true), new Boolean(true), true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), true, true, true, new Boolean(true), true, true, true, true, true, true, true, new Boolean(true), true, true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true]) i2 = a0[({valueOf: function() { /* no regression tests found */return 0; }})];");
/*fuzzSeed-94431925*/count=112; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 36893488147419103000.0;\n    return +((+/*FFI*/ff(((NaN)), ((-0.0009765625)), ((((((0xffffffff)+(-0x8000000)-(0x486c4225))>>>((0x6aa7da61))) % (0xef429457))|0)), ((abs((((i1)-(0xf87a076b)) | ((0x1049943d)+((0x48a22d42) <= (0x6b09231f))-(0xc92191a8))))|0)), ((d0)), ((17592186044415.0)), (((+/*FFI*/ff(((-36893488147419103000.0)), ((3.094850098213451e+26)))) + (-((33.0))))), ((((0x7ff03584) / (0x6b33d863))|0)), (((((0xe95d87c))|0))), ((9.44473296573929e+21)), ((-288230376151711740.0)), ((-134217729.0)), ((-6.189700196426902e+26)))));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; yield y; this.e2.add(i2);; yield y; }}, new ArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=113; tryItOut("print(f1);");
/*fuzzSeed-94431925*/count=114; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.sinh(Math.fround(Math.acos(( ~ ((Math.tan((Math.atan2(( + mathy4(1.7976931348623157e308, ( + y))), x) | 0)) | 0) ** Math.pow(( + Math.imul(y, ( + y))), x)))))); }); testMathyFunction(mathy5, [0x100000001, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x100000001, 0x080000000, -(2**53), 0, -0x0ffffffff, 2**53+2, Math.PI, 0x080000001, 0x0ffffffff, -0x080000000, 1/0, -0, -0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -(2**53+2), 0x100000000, -0x07fffffff, -0x100000000, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 42, Number.MAX_VALUE, 2**53-2, 0/0]); ");
/*fuzzSeed-94431925*/count=115; tryItOut("i0 + '';");
/*fuzzSeed-94431925*/count=116; tryItOut("\"use strict\"; /*bLoop*/for (var rutpha = 0, (window); ((let (d) NaN = Proxy.createFunction(({/*TOODEEP*/})(false), String.prototype.toLocaleUpperCase, function(y) { \"use strict\"; yield y; print(uneval(m1));; yield y; }))) && rutpha < 23; ++rutpha) { if (rutpha % 6 == 2) { o1.m0.delete(h2);\nf1(m1);\n } else { s0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Int32ArrayView[(((+abs((((Uint32ArrayView[4096]))))) != (d1))-(i0)) >> 2]) = (-(i0));\n    d1 = ((1099511627776.0) + (-3.0));\n    {\n      i0 = (((((((i0))>>>(0xa954e*(i0)))))>>>(((((Uint16ArrayView[((-0x8000000)+(0xfc63397d)) >> 1]))|0) >= (imul((0xc037ee81), (i0))|0)))) > ((((((i0)+(!(0x8082dfd8)))>>>(((-((-16777216.0))) == (268435457.0))))))>>>((((0xf8375340))>>>(-(0x9be11a07))) / (((!(0x797acbc2))-((-17179869185.0) == (0.0625)))>>>((undefined))))));\n    }\n    i0 = (i0);\n    return +((d1));\n  }\n  return f; })(this, {ff: (x = /*MARR*/[window,  '' ,  '' , window,  '' , window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window,  '' , window, window,  '' ,  '' , window,  '' , window,  '' , window, window,  '' ,  '' , window, window, window].map(/*wrap2*/(function(){ \"use strict\"; var gigdus = new RegExp(\"(?:$)*?|(?:([^]*){2})[^]\", \"gi\").watch(\"callee\", (decodeURIComponent).apply); var nzrssa = q => q; return nzrssa;})(), name = Proxy.create(({/*TOODEEP*/})( '' ), \"\\u4315\")), ...x) =>  { return x } }, new ArrayBuffer(4096)); }  } ");
/*fuzzSeed-94431925*/count=117; tryItOut("mathy1 = (function(x, y) { return Math.pow(( + Math.hypot(( + Math.acosh((Math.cos(Math.fround(x)) | 0))), ((( + Math.sinh(0x080000000)) >> ( + Math.acos(( + Number.MIN_VALUE)))) | 0))), Math.fround((( + (((( + (x | 0)) | 0) && mathy0((Number.MAX_VALUE >>> 0), (Math.fround((Math.fround(y) == (x >>> 0))) ? 2**53+2 : Math.fround(Math.sinh(Math.fround((Math.imul(( + x), ( + x)) | 0))))))) >>> 0)) / ( + Math.fround(( - ( + ( ~ (((( + ( ~ ( + x))) ? ( + (Math.hypot(x, y) != mathy0(x, y))) : ( + x)) >>> 0) | 0))))))))); }); testMathyFunction(mathy1, [0.000000000000001, 0/0, -0x080000001, 0x100000000, 0x07fffffff, -(2**53-2), Number.MAX_VALUE, Math.PI, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, -0x07fffffff, 1, -0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, 2**53-2, -1/0, 1.7976931348623157e308, -Number.MAX_VALUE, 0x0ffffffff, 2**53, 0, -0, 0x100000001, -(2**53+2), 0x080000001, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=118; tryItOut("try { try { print(s1); } catch(NaN if /*FARR*/[].map) { \"\\u234C\"; } catch(__iterator__ if null.__defineGetter__(\"[[1]]\", function(y) { return \"\\uC142\" })) { {} } catch(d if (function(){{}})()) { return false; }  } finally { for(let c in new Array(-26)) return (6).call(true, ); } ");
/*fuzzSeed-94431925*/count=119; tryItOut("/*RXUB*/var r = ({a: function ()\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 0.03125;\n    d0 = (1.0);\n    d0 = (+atan2(((d0)), (((this == length.__defineGetter__(\"window\", Date.prototype.setMilliseconds))))));\n    d2 = (((1152921504606847000.0)) * ((d2)));\n    (Float64ArrayView[2]) = ((1.0));\n    return (((1)+(0x4e63f910)-(!(1))))|0;\n  }\n  return f;() }); var s = \"\\u00dd\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=120; tryItOut("v2 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-94431925*/count=121; tryItOut("\"use strict\"; { void 0; verifyprebarriers(); } e2.__proto__ = e1;");
/*fuzzSeed-94431925*/count=122; tryItOut("\"use strict\"; Object.defineProperty(this, \"g2.g1\", { configurable: false, enumerable: false,  get: function() {  return Proxy.create(h0, i1); } });");
/*fuzzSeed-94431925*/count=123; tryItOut("o2.a1.length = 1;");
/*fuzzSeed-94431925*/count=124; tryItOut("\"use strict\"; \"use asm\"; a1.push(b1, g1, v2, v2);");
/*fuzzSeed-94431925*/count=125; tryItOut("\"use strict\"; a1 = /*MARR*/[new String(''), new String(''),  '\\0' , function(){}, new String(''), function(){}, function(){}, new String(''), function(){}, new String(''), function(){}, function(){},  '\\0' , new String(''), function(){},  '\\0' , new String(''),  '\\0' , new String(''), new String(''),  '\\0' ,  '\\0' , function(){}, new String(''),  '\\0' ,  '\\0' , new String(''),  '\\0' , new String(''), function(){}, new String(''), new String(''), function(){},  '\\0' , function(){},  '\\0' , new String(''),  '\\0' , function(){}, new String(''), new String(''),  '\\0' , new String(''), new String(''), function(){},  '\\0' , function(){}, function(){}, new String(''), new String(''),  '\\0' , function(){}, new String(''), new String(''), new String(''),  '\\0' ,  '\\0' ,  '\\0' , function(){},  '\\0' , function(){}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), function(){},  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new String(''), new String(''), function(){}, new String(''),  '\\0' , function(){},  '\\0' , function(){},  '\\0' , function(){},  '\\0' , function(){},  '\\0' ,  '\\0' ,  '\\0' , new String(''),  '\\0' , function(){}, function(){},  '\\0' ,  '\\0' ];");
/*fuzzSeed-94431925*/count=126; tryItOut("mathy1 = (function(x, y) { return ( ! mathy0((( + ( ~ ( + ( - Math.pow(x, y))))) | 0), mathy0(((( + ((( - Math.fround(( + (x >>> 0)))) | 0) ? (Math.pow((x | 0), (x >>> 0)) | 0) : Math.log2(y))) && Math.exp(x)) | 0), y))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, -(2**53), 0/0, -0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, 0x07fffffff, 2**53-2, 0, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 1/0, -0x080000001, -0x07fffffff, 1.7976931348623157e308, 42, 0x080000001, -0x0ffffffff, 1, -1/0, 0x100000001, -(2**53-2), 0.000000000000001, 0x0ffffffff, 2**53, 2**53+2]); ");
/*fuzzSeed-94431925*/count=127; tryItOut("\"use strict\"; v1 = (t0 instanceof e1);");
/*fuzzSeed-94431925*/count=128; tryItOut("s1 = '';");
/*fuzzSeed-94431925*/count=129; tryItOut("a1 = /*MARR*/[ '\\0' , new String(''),  '\\0' , new String(''), new String(''),  '\\0' ,  '\\0' , new String(''), Infinity, new String(''), new String(''), Infinity, Infinity, Infinity,  '\\0' , Infinity,  '\\0' , Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new String(''),  '\\0' , Infinity, new String(''), new String(''), new String(''),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , Infinity, new String(''), new String(''),  '\\0' ,  '\\0' , new String(''), Infinity, Infinity, new String(''), new String(''), Infinity,  '\\0' , Infinity,  '\\0' , new String(''), new String(''),  '\\0' ,  '\\0' , Infinity,  '\\0' , Infinity, Infinity,  '\\0' , Infinity,  '\\0' , Infinity, Infinity, new String(''),  '\\0' ,  '\\0' , new String(''), new String('')];");
/*fuzzSeed-94431925*/count=130; tryItOut("this.v0 = Object.prototype.isPrototypeOf.call(i2, s2);");
/*fuzzSeed-94431925*/count=131; tryItOut("a2.forEach((function() { for (var j=0;j<41;++j) { f1(j%3==1); } }));");
/*fuzzSeed-94431925*/count=132; tryItOut("\"use strict\"; delete this.h2.getOwnPropertyDescriptor;");
/*fuzzSeed-94431925*/count=133; tryItOut("\"use strict\"; \"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ (( + mathy1(y, Math.pow(x, Math.fround(Math.pow(x, Math.fround(2**53)))))) * Math.atan2(Math.log(( + (( + -Number.MIN_VALUE) <= ( + Math.fround(mathy2(y, y)))))), x))); }); testMathyFunction(mathy4, /*MARR*/[ /x/g ,  '\\0' , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  /x/g ,  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  '\\0' ,  '\\0' , objectEmulatingUndefined(),  /x/g ,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' ,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(),  '\\0' ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  '\\0' ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  '\\0' ,  /x/g , objectEmulatingUndefined(),  /x/g ,  /x/g ,  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(),  '\\0' ,  /x/g ,  /x/g ,  '\\0' , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  /x/g ,  '\\0' ,  /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  '\\0' ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  /x/g ,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g ]); ");
/*fuzzSeed-94431925*/count=134; tryItOut("p2 + '';");
/*fuzzSeed-94431925*/count=135; tryItOut("v1 = false;");
/*fuzzSeed-94431925*/count=136; tryItOut("v0 = evaluate(\"function f0(g1.b0) \\\"use asm\\\";   var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = 1.2089258196146292e+24;\\n    var i3 = 0;\\n    var d4 = 70368744177665.0;\\n    var i5 = 0;\\n    i5 = (new  \\\"\\\" (b, null));\\n    return +((Float32ArrayView[2]));\\n  }\\n  return f;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: neuter, sourceIsLazy: (4277), catchTermination: false }));");
/*fuzzSeed-94431925*/count=137; tryItOut("\"use strict\"; a2.shift(o0, g2.a0, p0);");
/*fuzzSeed-94431925*/count=138; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.log(Math.fround((( + ( - x)) == Math.atan2(y, Math.round((( + (( + x) ? ( + Math.expm1(y)) : ( + x))) >>> 0))))))); }); testMathyFunction(mathy3, [0, '0', [], 1, -0, (new Boolean(true)), /0/, (new Number(0)), ({valueOf:function(){return 0;}}), null, (function(){return 0;}), false, ({toString:function(){return '0';}}), (new Boolean(false)), '', objectEmulatingUndefined(), NaN, '\\0', true, 0.1, '/0/', ({valueOf:function(){return '0';}}), undefined, (new Number(-0)), [0], (new String(''))]); ");
/*fuzzSeed-94431925*/count=139; tryItOut("\"use strict\"; a0.length = 0;");
/*fuzzSeed-94431925*/count=140; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    (Float64ArrayView[0]) = ((-0.0078125));\n    return ((((i1) ? (0xffa68051) : ((-1.1805916207174113e+21) < (NaN)))-(i2)-((((i3)) & (((i1) ? (i3) : (i0)))))))|0;\n  }\n  return f; })(this, {ff: \"\\uEE9C\" & [[1]]\n}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[function(){}, (x)(~timeout(1800), x), function(){}, (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), function(){}, (x)(~timeout(1800), x), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x), function(){}, function(){}, (x)(~timeout(1800), x), function(){}, function(){}, (x)(~timeout(1800), x), function(){}, function(){}, (x)(~timeout(1800), x), (x)(~timeout(1800), x), (x)(~timeout(1800), x)]); ");
/*fuzzSeed-94431925*/count=141; tryItOut("let(w) { let(y) ((function(){let(tkgvpb, eval, w, x = (w.eval(\"/* no regression tests found */\"))) ((function(){return;})());})());}");
/*fuzzSeed-94431925*/count=142; tryItOut("mathy2 = (function(x, y) { return ( + Math.sign(( + Math.sin(( ~ y))))); }); testMathyFunction(mathy2, [(new String('')), 0.1, '\\0', undefined, NaN, '', '/0/', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), /0/, [0], objectEmulatingUndefined(), (new Number(0)), (new Boolean(false)), [], 0, (new Number(-0)), 1, (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Boolean(true)), true, null, -0, '0', false]); ");
/*fuzzSeed-94431925*/count=143; tryItOut("\"use strict\"; testMathyFunction(mathy1, [2**53+2, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0x080000001, 2**53, -0x0ffffffff, 0/0, Number.MAX_VALUE, 0x100000001, 0x100000000, -1/0, -Number.MIN_VALUE, 0x080000001, 1/0, -0x100000001, 0, -0, -0x080000000, Math.PI, -(2**53-2), 42, 1, 0.000000000000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-94431925*/count=144; tryItOut("v0 = t1.BYTES_PER_ELEMENT;function x(eval, window) { a0.unshift(e2, this, o2, h2, this.s1, o0, this.p1); } print(this);");
/*fuzzSeed-94431925*/count=145; tryItOut("o0.a0 = /*MARR*/[(void 0), -3/0, -3/0, (void 0), (void 0), -3/0, (void 0), (void 0), -3/0, (void 0), -3/0, (void 0), -3/0, (void 0), -3/0, (void 0), (void 0), -3/0, -3/0, -3/0, (void 0), -3/0, -3/0, (void 0), (void 0), (void 0), -3/0, (void 0), -3/0, -3/0, (void 0), -3/0, (void 0), (void 0), (void 0), (void 0), -3/0, (void 0), -3/0, -3/0, (void 0), -3/0, (void 0), (void 0), -3/0, -3/0, (void 0), (void 0), (void 0), -3/0, (void 0), (void 0), (void 0), (void 0), -3/0, -3/0, (void 0), (void 0), (void 0), -3/0, (void 0), -3/0, (void 0), -3/0];");
/*fuzzSeed-94431925*/count=146; tryItOut("/*iii*/t1[8] = jdzzqj;/*hhh*/function jdzzqj(){t0[e];\nprint(x);\n}");
/*fuzzSeed-94431925*/count=147; tryItOut("testMathyFunction(mathy4, /*MARR*/[new Boolean(true), false, new Boolean(true), new Boolean(true), 2**53+2, false, 2**53+2, new Boolean(true), false, false, new Boolean(true), 2**53+2, new Boolean(true), 2**53+2, 2**53+2, new Boolean(true), 2**53+2, false, false, false, false, new Boolean(true), false, 2**53+2, false, new Boolean(true), 2**53+2, new Boolean(true), new Boolean(true), false, false, new Boolean(true), false, false, new Boolean(true), 2**53+2, new Boolean(true), false, false, false, false, 2**53+2, 2**53+2, new Boolean(true)]); ");
/*fuzzSeed-94431925*/count=148; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log(Math.min((mathy0((Math.fround(Math.sign(Math.fround(Math.fround((y + (x >>> 0)))))) >>> 0), ((( + (( + y) !== x)) >> y) | 0)) | 0), ((( - (Math.fround((Math.fround((( - (y | 0)) >>> 0)) <= Math.fround(-(2**53-2)))) | 0)) | 0) | 0))); }); testMathyFunction(mathy1, [2**53+2, -Number.MIN_VALUE, Math.PI, 0.000000000000001, 0x100000001, -0, -0x100000001, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, 0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53, -(2**53+2), 1, -(2**53-2), 1/0, -(2**53), 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 42, -0x07fffffff, -0x0ffffffff, -0x080000001, 0, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=149; tryItOut("const x = delete c.b, e, x = x, w = (4277)\n, pxixfv, nmxlng, xmqmpl, x = x;let c = (4277), x, \u3056 = /(\\S+)(?:(\\n|[^]))|.{3,}/m, w, x, x, x;v0 = new Number(4);");
/*fuzzSeed-94431925*/count=150; tryItOut("i0.next();");
/*fuzzSeed-94431925*/count=151; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:\\u00dc{511,513}(?=[^\\\\w\\\\f-\\\\u00C6])(?!\\\\\\ub746|${0,})(?!\\\\xC1)[^]|[^]+?|([^])+?))\", \"i\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-94431925*/count=152; tryItOut("/*vLoop*/for (let jiyggj = 0; jiyggj < 51; ++jiyggj) { b = jiyggj; /*vLoop*/for (var vgccoa = 0; vgccoa < 31; ++vgccoa) { let y = vgccoa; print( '' ); }  } ");
/*fuzzSeed-94431925*/count=153; tryItOut("\"use strict\"; var v0 = true;");
/*fuzzSeed-94431925*/count=154; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.imul(Math.atan2(( + (Math.sign(((( ~ (y | 0)) | 0) | 0)) !== x)), ( + Math.pow(-Number.MIN_SAFE_INTEGER, Math.atanh(x)))), ((Math.pow(y, (x ? ( + ( ! Math.cosh(y))) : -1/0)) | 0) != mathy1(Math.fround((Math.fround((Math.fround(y) ^ Math.fround(x))) ? Math.fround(( + (((-0x0ffffffff | 0) ? (y | 0) : (y | 0)) | 0))) : Math.fround((Math.atanh((-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))), ( + Math.exp(( + x)))))); }); testMathyFunction(mathy4, [0, Math.PI, -Number.MIN_VALUE, -1/0, 0x0ffffffff, 2**53+2, 42, -0x0ffffffff, -0x100000001, 0x080000000, 0x100000001, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), -0, 0x100000000, -0x080000001, -0x080000000, -(2**53+2), 0/0, Number.MIN_SAFE_INTEGER, 1, -(2**53), 1/0, 0x080000001, -0x100000000, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=155; tryItOut("testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 1/0, -0, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 0x080000001, -0x0ffffffff, 0x0ffffffff, 2**53, -Number.MAX_VALUE, -(2**53+2), 0x100000001, -1/0, 1.7976931348623157e308, 0, 0/0, 2**53-2, 42, 0x100000000, -0x080000001, 2**53+2, 0x07fffffff, -(2**53), -0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001]); ");
/*fuzzSeed-94431925*/count=156; tryItOut("x = [,], fpuyvy, lmxfuj, b, e, spvbhk, vogojn, tuasst;( /x/g );");
/*fuzzSeed-94431925*/count=157; tryItOut("o2.v2 = (m0 instanceof m0);");
/*fuzzSeed-94431925*/count=158; tryItOut("mathy5 = (function(x, y) { return Math.fround(( ~ Math.fround(Math.exp(Math.clz32(( - -Number.MAX_SAFE_INTEGER)))))); }); ");
/*fuzzSeed-94431925*/count=159; tryItOut("\"use strict\"; /*hhh*/function wpgifw({y: Date.prototype.setUTCMinutes}, this.w, [, window !== \u3056[\"apply\"]], x, x, w = x, eval, x = try { v0 = (s1 instanceof b1); } catch(b if \"\\u69C0\") { this; } catch(window\u0009 if (function(){;})()) { [,]; } catch(\u3056 if x) { v1 = t1.length; } catch(x if false) { continue ; } finally { continue ; } , x, this.x, x, d, y){print(x);function c(e, x, NaN, NaN = new RegExp(\"${0}(\\\\2)|(?!(?:^){0,0}(?=\\\\B)+)*\", \"gyim\"), x, \u3056, yield, x, y, eval = /(?!\\B)/g, d, b, c, x, window, x, x, x, x, c = w, y, x, z, NaN, d = \"\\u2017\", x, window =  /x/g , z, window, w, w, x, x, c, y = new RegExp(\"\\\\B\\\\1|(\\\\W|(?:(?!\\\\s)\\\\v[^]))|((?:\\\\S))\", \"gim\"), x = /(?:[^]){0,1}(\\b{1})\\cM|\\s[^\ud0e8\\xa5\\w]\\1\\B.*?|((\\1))+?$|(?!(?=(?=[^]){3})){3,}/gm, d = new RegExp(\"\\\\2\", \"gyim\"), x, let, e, c = false, x, d, x, b, a, x, w, e, d, NaN, e, x, NaN, false, eval, x) { yield /[]/gyim } print(uneval(a1));}/*iii*/{ void 0; gcslice(14839148); } print(uneval(i0));");
/*fuzzSeed-94431925*/count=160; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=161; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((( + (( + ( ~ Math.atan2(( ! ( + -0x07fffffff)), (mathy0(( + Math.hypot(( + y), x)), ( + (x ? y : -0x100000000))) | 0)))) | 0)) << (Math.max(( + Math.sign(( + y))), Math.fround(Math.hypot(Math.expm1((y >>> 0)), Math.fround(Math.log10(x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, -0x100000001, 2**53-2, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, -Number.MIN_VALUE, 1/0, -(2**53-2), 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000001, 1, 0, -0, 0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, -0x080000000, 0x080000001, 0/0, Math.PI, -1/0, 0x080000000, 2**53, -0x100000000]); ");
/*fuzzSeed-94431925*/count=162; tryItOut("v2 = Array.prototype.reduce, reduceRight.apply(a1, [(function() { try { a1.sort((function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var atan = stdlib.Math.atan;\n  var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (i0);\n    }\n    (Float32ArrayView[((i1)+(i2)) >> 2]) = ((+(~((0x286313b1) % ((((0xffffffff))-((((0xc6a891b2))>>>((0x25436474))) >= (((0x72972a94))>>>((0xfca3dc43)))))>>>(((Float32ArrayView[(((0x5a9c2a3a))-(i2)) >> 2]))))))));\n    {\n      (Float64ArrayView[(((((0x334c1025)-(0xd82a9609)+(0xffffffff))>>>((i0))) != (0x80e5389d))+(0xfcba5dd8)) >> 3]) = ((NaN));\n    }\n    return (((((0x3b63f24d) / (((/*FFI*/ff(((+atan(((-3.0))))))|0)) >> ((!(i2))))) ^ ((((+ceil(((+(-1.0/0.0))))) + (-18014398509481984.0)) > (295147905179352830000.0)))) / (~~(+(((i2)+(i0)-(0x1da209a6)) >> ((i2)-((0x7ac34aea) > (0xb75c2ef8))))))))|0;\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; /*hhh*/function opntuv(b = Math.max(-14, -27)){/*ODP-1*/Object.defineProperty(b0, \"charAt\", ({configurable: true}));}/*iii*/; }}, new ArrayBuffer(4096))); } catch(e0) { } try { /*MXX2*/g1.URIError.name = p0; } catch(e1) { } try { o0 + ''; } catch(e2) { } e0 = new Set; return t1; })]);");
/*fuzzSeed-94431925*/count=163; tryItOut("{ void 0; gcslice(5953); } v0 = g0.eval(\"x = o2;\");\nArray.prototype.splice.call(o2.a2, NaN, this.v1, g0);\n");
/*fuzzSeed-94431925*/count=164; tryItOut("testMathyFunction(mathy0, [0, /0/, (new Boolean(true)), NaN, '', 1, [], (new String('')), undefined, -0, [0], objectEmulatingUndefined(), false, '\\0', 0.1, (new Number(0)), null, ({valueOf:function(){return 0;}}), true, ({toString:function(){return '0';}}), (function(){return 0;}), '0', '/0/', (new Boolean(false)), (new Number(-0)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-94431925*/count=165; tryItOut("g2.offThreadCompileScript(\"/*RXUB*/var r = o0.r1; var s = \\\"\\\"; print(r.test(s)); print(r.lastIndex); \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy:  /* Comment */x, catchTermination: (x % 59 == 41) }));");
/*fuzzSeed-94431925*/count=166; tryItOut("\"use strict\"; Array.prototype.unshift.call(a2, m0, o0.i0);");
/*fuzzSeed-94431925*/count=167; tryItOut("v2 = evalcx(\"t1.set(t1, 1);\", g1);\u0009function NaN({}, \u3056) { \"use strict\"; (this); } s1 += this.g2.s1;");
/*fuzzSeed-94431925*/count=168; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(mathy1(Math.fround(((0x100000001 < Math.imul(( ~ ( ~ Number.MIN_VALUE)), Math.fround(( + x)))) ? (( + y) * x) : ( ~ Math.min(( + (( + Number.MAX_SAFE_INTEGER) ? y : ( + 0/0))), (mathy4((( + -0x100000001) >>> 0), (x >>> 0)) >>> 0))))), Math.fround((((mathy0((((( + Math.ceil(( + (Math.cbrt(((( + x) ? x : (-0x080000000 >>> 0)) >>> 0)) >>> 0)))) >>> 0) ? Math.fround(( ! ( + ((-(2**53-2) >>> 0) > x)))) : 0/0) | 0), (x | 0)) | 0) >>> 0) ** Math.fround((Math.fround(y) , Math.fround(y))))))); }); testMathyFunction(mathy5, [2**53-2, -Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, 0x100000001, -(2**53+2), 0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 2**53, 1/0, -0x07fffffff, -(2**53), 0.000000000000001, 0x100000000, 0, -0, 42, Math.PI, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, 1, -1/0, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=169; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( + ((Math.cos(mathy0(42, (x * x))) >>> 0) < (mathy0(mathy0(-1/0, y), Math.fround(Math.hypot(0x080000000, ( + mathy0(( + y), ( + Math.imul(x, x))))))) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, -0x100000000, -(2**53-2), -0x07fffffff, 1.7976931348623157e308, Math.PI, -Number.MAX_VALUE, 2**53+2, -0x100000001, 0/0, 1/0, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, Number.MAX_VALUE, -0x080000000, 42, -Number.MIN_VALUE, 0, -1/0, 2**53, -0, 0.000000000000001, 1, -(2**53+2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-94431925*/count=170; tryItOut("g0.s1 += g2.s1;");
/*fuzzSeed-94431925*/count=171; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[-Number.MIN_VALUE, -Number.MIN_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MIN_VALUE, -Number.MIN_VALUE, objectEmulatingUndefined(), -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=172; tryItOut("\"use strict\"; /*vLoop*/for (cbeops = 0; cbeops < 76; ++cbeops) { const c = cbeops; g0.m1.valueOf = (function() { try { h1 = ({getOwnPropertyDescriptor: function(name) { ;; var desc = Object.getOwnPropertyDescriptor(g0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { this.s0 = new String(h0);; var desc = Object.getPropertyDescriptor(g0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw i0; Object.defineProperty(g0, name, desc); }, getOwnPropertyNames: function() { Object.preventExtensions(o0.g1);; return Object.getOwnPropertyNames(g0); }, delete: function(name) { for (var v of v2) { t0 = new Float32Array(this.t0); }; return delete g0[name]; }, fix: function() { v1 = t1.length;; if (Object.isFrozen(g0)) { return Object.getOwnProperties(g0); } }, has: function(name) { return a2; return name in g0; }, hasOwn: function(name) { a1.unshift(h1, b1, t0);; return Object.prototype.hasOwnProperty.call(g0, name); }, get: function(receiver, name) { for (var p in f0) { for (var v of f0) { try { for (var p in o1.f2) { s2 += 'x'; } } catch(e0) { } try { v1 = Array.prototype.reduce, reduceRight.apply(a1, [(function() { try { v0 = g1.eval(\"continue ;\"); } catch(e0) { } try { a0.reverse(); } catch(e1) { } delete h2.hasOwn; return o0.a0; }), s0, v2, t1, b1, this]); } catch(e1) { } try { /*RXUB*/var r = r2; var s = new RegExp(\"(?!\\\\1){1,}\", \"i\"); print(s.split(r)); print(r.lastIndex);  } catch(e2) { } s2 += 'x'; } }; return g0[name]; }, set: function(receiver, name, val) { throw m2; g0[name] = val; return true; }, iterate: function() { g0.offThreadCompileScript(\"print(uneval(p2));\");; return (function() { for (var name in g0) { yield name; } })(); }, enumerate: function() { throw f0; var result = []; for (var name in g0) { result.push(name); }; return result; }, keys: function() { m0.get(\"\\u4F7B\");; return Object.keys(g0); } }); } catch(e0) { } try { g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (w = c), noScriptRval: (x % 2 == 0), sourceIsLazy: undefined.yoyo(\"\\u9F1E\"), catchTermination: (x % 4 == 2), element: o2.o2, sourceMapURL: s1 })); } catch(e1) { } v0 = a0.every(s2); return e0; }); } ");
/*fuzzSeed-94431925*/count=173; tryItOut("/*RXUB*/var r = /([^\u00ce\\u0001-\u84f7\u0007\\uC1a8-\ud0a4]|\\1|(?:\\b*){2,}{0,})/m; var s = \"\\ud0a4\\ud0a4\\ud0a4\\n\\ud0a4\\ud0a4\\ud0a4\"; print(r.test(s)); ");
/*fuzzSeed-94431925*/count=174; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[(-17 %= (4277)), objectEmulatingUndefined(), new Boolean(true), (-17 %= (4277)), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), (-17 %= (4277)), (-17 %= (4277)), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(true), (-17 %= (4277)), new Boolean(false), new Boolean(false), (-17 %= (4277)), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(true), (-17 %= (4277)), objectEmulatingUndefined(), (-17 %= (4277)), (-17 %= (4277)), objectEmulatingUndefined(), new Boolean(true), new Boolean(false), (-17 %= (4277)), (-17 %= (4277)), new Boolean(false), (-17 %= (4277)), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(false), (-17 %= (4277)), new Boolean(true), objectEmulatingUndefined(), (-17 %= (4277)), objectEmulatingUndefined(), (-17 %= (4277)), (-17 %= (4277)), new Boolean(false), new Boolean(false), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), (-17 %= (4277)), new Boolean(true), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(false), (-17 %= (4277)), objectEmulatingUndefined(), new Boolean(false), (-17 %= (4277)), (-17 %= (4277)), new Boolean(true)]) { /*hhh*/function tmpryf(e = (yield /(?!(?:.+?|(?!\\b{2}\\W[\\\uc235])|(?!(?!(?!.))?)))/yim) || (\u3056--) >> this.__defineGetter__(\"x\", decodeURIComponent)\u0009){a0.forEach((function mcc_() { var ihsdah = 0; return function() { ++ihsdah; if (/*ICCD*/ihsdah % 7 == 1) { dumpln('hit!'); m2.has(p2); } else { dumpln('miss!'); Array.prototype.reverse.call(a2); } };})());}tmpryf(((void options('strict')))); }");
/*fuzzSeed-94431925*/count=175; tryItOut("\"use strict\"; lvcetp();/*hhh*/function lvcetp(...x){print((makeFinalizeObserver('tenured')));\nh2.enumerate = (function() { try { b1 = t0.buffer; } catch(e0) { } e0.delete(s0); return a0; });\n}");
/*fuzzSeed-94431925*/count=176; tryItOut("\"use strict\"; v2 = g2.runOffThreadScript();");
/*fuzzSeed-94431925*/count=177; tryItOut("\"use strict\"; const s2 = new String;");
/*fuzzSeed-94431925*/count=178; tryItOut("for (var p in v1) { g2.o2 = Object.create(o2.b0); }");
/*fuzzSeed-94431925*/count=179; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    {\n      (Float32ArrayView[0]) = ((+floor(((d1)))));\n    }\n    (Float64ArrayView[1]) = ((+(-1.0/0.0)));\n    d1 = (d0);\n    d0 = (d1);\n    d0 = ((Float64ArrayView[4096]));\n    return (((0xfdea5f2e)+(/*FFI*/ff(((d0)))|0)+(((0xf9ba8303)))))|0;\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, 42, -0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, 0x080000001, 1, Math.PI, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, 0x100000001, 0, -1/0, 2**53-2, 2**53+2, 0x100000000, 2**53, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -0x07fffffff, 0x080000000, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=180; tryItOut("for (var v of g2) { try { Array.prototype.unshift.call(a0, o2.s2); } catch(e0) { } Object.prototype.watch.call(b2, \"6\", (function mcc_() { var uplbvp = 0; return function() { ++uplbvp; if (/*ICCD*/uplbvp % 6 == 4) { dumpln('hit!'); t0 + g1; } else { dumpln('miss!'); try { m2.has(m0); } catch(e0) { } Array.prototype.push.call(this.a2, m2, [b-=null]\n); } };})()); }");
/*fuzzSeed-94431925*/count=181; tryItOut("/*hhh*/function elsrpu(){print((void version(185)));}/*iii*/s1 += 'x';z = ((yield x));");
/*fuzzSeed-94431925*/count=182; tryItOut("mathy1 = (function(x, y) { return ( - ( ! (mathy0(Math.fround(((Math.log1p((y | 0)) | 0) / x)), (y | y)) >>> 0))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -(2**53+2), 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53, -1/0, 0.000000000000001, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000001, 1/0, -0x080000000, -0, 0x100000001, -(2**53), 0, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, 42, 0x080000000, 1, 0x0ffffffff, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=183; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -2147483647.0;\n    d2 = ((d2) + (+(-1.0/0.0)));\n    switch ((~((-0x8000000)+(0xfa4f1dad)))) {\n      case -2:\n        {\n          {\n            {\n              d1 = ((decodeURI).bind((( - (Math.fround(Math.imul(Math.fround(( + (( + x) >= ( + ( + ( - ( + x))))))), 0/0)) | 0)) | 0), x));\n            }\n          }\n        }\n        break;\n      case -1:\n        {\n          (Uint8ArrayView[((i0)+(0xfc1af359)) >> 0]) = ((-0x8000000)+((((0xf80e8438)) & (((((0xef42554c)+(0xf2257a36)-(0xf9fccc4c)) & (((0xb05722e7) != (0x44bb2070)))))+((((0xbd92d9b6)) << ((0xccf66c08))) < (0x46f8e67e)))) == ((new RegExp(\"\\\\2(?:(?:.{2,3})+)+\", \"y\").throw(this)))));\n        }\n        break;\n      case -3:\n        {\n          d2 = (d2);\n        }\n        break;\n      case -1:\n        {\n          (Uint8ArrayView[((Int16ArrayView[0])) >> 0]) = ((0xe6a56dd2)-(0xfeccfdd4));\n        }\n        break;\n      case 0:\n        d1 = (+(abs(((0x7a2ae*(i0)) >> (((((+((-0.03125))))) ? (0xb8ff7b88) : ((((0xf9b7802a))>>>((0x1e94e6e5)))))+(0xffffffff))))|0));\n      default:\n        i0 = (0x3e06fd68);\n    }\n    d1 = (+(1.0/0.0));\n    {\n      {\n        switch ((0x6a8d5a62)) {\n          case -2:\n            d1 = (d1);\n            break;\n        }\n      }\n    }\n    {\n      d2 = (+(1.0/0.0));\n    }\n    return ((-(/*FFI*/ff(((abs((~(((((0xfa059387)-(0xc26595bd)-(0xb46ae676)) >> ((Int8ArrayView[((0xebc42ee5)) >> 0]))) > (((i0)) << ((0xfb45a8e6)))))))|0)), ((d2)))|0)))|0;\n  }\n  return f; })(this, {ff: z =>  { \"use strict\"; \"use asm\"; return (4277) } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000001, -(2**53+2), -(2**53), -0x080000001, 0x080000000, 0x100000001, 42, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, 1/0, 2**53+2, 0x080000001, -1/0, -(2**53-2), -0x080000000, -0x100000000, -0x07fffffff, 2**53, 0x07fffffff, -0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE, 0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-94431925*/count=184; tryItOut("v1 = (p2 instanceof b0);");
/*fuzzSeed-94431925*/count=185; tryItOut("print(null);v1 = 4.2;");
/*fuzzSeed-94431925*/count=186; tryItOut("testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-94431925*/count=187; tryItOut("v0 = r2.flags;");
/*fuzzSeed-94431925*/count=188; tryItOut("mathy4 = (function(x, y) { return ( + ((mathy3(Math.fround((( ~ ( + -(2**53-2))) == (Math.acosh(x) || (((Math.cbrt(y) | 0) >>> (x | 0)) | 0)))), Math.fround(Math.imul(x, Math.hypot(( + x), Math.max(2**53+2, (Math.asinh(x) >>> 0)))))) >>> 0) != (Math.cbrt((( ~ ( + Math.atanh(( + x)))) | 0)) | 0))); }); ");
/*fuzzSeed-94431925*/count=189; tryItOut("\"use strict\"; /*infloop*/M:while(x){Object.defineProperty(this, \"v0\", { configurable: true, enumerable: (x % 4 != 2),  get: function() {  return evalcx(\"print(uneval(v0));\", g0); } });print(f1); }");
/*fuzzSeed-94431925*/count=190; tryItOut("print( /x/ );\nprint(x);\n");
/*fuzzSeed-94431925*/count=191; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( - Math.fround((mathy0(Math.fround((Math.fround(Math.hypot(x, y)) ? Math.imul(y, -0x100000001) : Math.fround(Math.atan2((0x080000001 | 0), Math.fround((Math.fround(y) ? ( + x) : (x >>> 0))))))), Math.cbrt(Math.atan2(( + Math.trunc(( + (Math.max((x >>> 0), y) >>> 0)))), x))) >>> 0))); }); testMathyFunction(mathy2, [0.000000000000001, -Number.MAX_VALUE, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, -0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53-2), 1/0, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, Number.MAX_VALUE, 42, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 0, 2**53-2, -0, 0/0, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, 1, 0x080000001, 0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=192; tryItOut("Object.prototype.unwatch.call(b2, \"arguments\");");
/*fuzzSeed-94431925*/count=193; tryItOut("/*ADP-2*/Object.defineProperty(a1, 2, { configurable: (x % 47 != 0), enumerable: /*UUV2*/(x.add = x.values), get: String.raw.bind(g2.f1), set: (let (e=eval) e) });");
/*fuzzSeed-94431925*/count=194; tryItOut("/*hhh*/function lidjmq(){var qeldns = new SharedArrayBuffer(16); var qeldns_0 = new Uint8Array(qeldns); qeldns_0[0] = 6; this.v0 = t0.length;}/*iii*//*hhh*/function flkqjq(){print(x);}flkqjq();");
/*fuzzSeed-94431925*/count=195; tryItOut("g0 + o1.g2.o2.e0;");
/*fuzzSeed-94431925*/count=196; tryItOut("{o0 = f1.__proto__;g0.s0 += 'x'; }");
/*fuzzSeed-94431925*/count=197; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; setJitCompilerOption('ion.forceinlineCaches', 1); } void 0; }");
/*fuzzSeed-94431925*/count=198; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.tan(Math.fround(Math.fround(Math.sinh(Math.imul(Math.fround(x), Math.sin(x)))))) >>> 0); }); testMathyFunction(mathy0, [-1/0, -0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 42, -(2**53-2), 0/0, Number.MIN_VALUE, -0, 0.000000000000001, -0x100000000, 1, -Number.MAX_VALUE, 2**53-2, -0x0ffffffff, Math.PI, 2**53+2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0, 2**53, -(2**53), 0x0ffffffff, -0x080000001, 0x080000001, 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1/0, -0x080000000]); ");
/*fuzzSeed-94431925*/count=199; tryItOut("v0 = g0.eval(\"print(b2);\");");
/*fuzzSeed-94431925*/count=200; tryItOut("s1 = Array.prototype.join.call(a2, s0);");
/*fuzzSeed-94431925*/count=201; tryItOut("switch(x) { case 4: i0.send(b2);break; default: print(x);case \u3056 ===  /x/ : case -15 /  \"\" :  }");
/*fuzzSeed-94431925*/count=202; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + ( ~ (((y | 0) | ( + Math.acosh(( + y)))) | 0))) >>> 0); }); testMathyFunction(mathy0, [0x100000001, 2**53-2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, -(2**53-2), 2**53+2, 0x0ffffffff, -(2**53), 0, -0x0ffffffff, -0, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -0x080000001, -0x100000001, -0x100000000, 1.7976931348623157e308, -0x080000000, 2**53, Math.PI, 0.000000000000001, 0x080000001, 0x07fffffff, -(2**53+2), 1/0, -Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, 0x100000000, -1/0, 0/0]); ");
/*fuzzSeed-94431925*/count=203; tryItOut("\"use strict\"; o2 = new Object;");
/*fuzzSeed-94431925*/count=204; tryItOut("Array.prototype.pop.apply(a0, [g1.a1]);");
/*fuzzSeed-94431925*/count=205; tryItOut("\"use asm\"; v1 = this.g0.eval(\"(Math.eval(\\\"window\\\"))\");");
/*fuzzSeed-94431925*/count=206; tryItOut("v1 = b0[(/*UUV1*/(x.padStart = (/*FARR*/[ /x/ ,  '' ].some( /x/ ))))];");
/*fuzzSeed-94431925*/count=207; tryItOut("/*vLoop*/for (let mzzqji = 0; mzzqji < 46; ++mzzqji) { e = mzzqji; for (var v of this.a2) { try { a0.unshift(v1, s0); } catch(e0) { } try { m2 = new WeakMap; } catch(e1) { } yield \"\\uB00F\"; } } x = (((Math.pow(x, Math.acos(x)) >>> 0) , (x >>> 0)));");
/*fuzzSeed-94431925*/count=208; tryItOut("let (lklqvd, window) { print(g1); }");
/*fuzzSeed-94431925*/count=209; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-94431925*/count=210; tryItOut("testMathyFunction(mathy4, [-(2**53), -Number.MAX_VALUE, 2**53, 0x080000000, -0x100000001, -0x100000000, Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0x100000000, Math.PI, -0x080000000, -Number.MIN_VALUE, 1/0, 0x080000001, 42, 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, 1.7976931348623157e308, -(2**53+2), 1, 2**53-2, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 0, -0, 2**53+2, -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=211; tryItOut("/*hhh*/function aytmgt(...a){t2 = new Uint32Array(t0);}/*iii*/for (var p in e2) { try { a1.sort(o1.f0, m1, true, this.i2, this.v0, o1.g2.b2); } catch(e0) { } try { for (var p in p1) { try { Array.prototype.pop.call(o1.a2, f2, t0); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(i2, t2); } catch(e1) { } try { v0 = evalcx(\"m0 = g0.objectEmulatingUndefined();\", g0); } catch(e2) { } m0.has(f2); } } catch(e1) { } try { Array.prototype.unshift.call(a0, t1, a2); } catch(e2) { } v2 = (p2 instanceof v2); }\nprint(h0);\n");
/*fuzzSeed-94431925*/count=212; tryItOut("print(x);");
/*fuzzSeed-94431925*/count=213; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.min(Math.fround(mathy0((Math.fround(( ! Math.fround(y))) ? Math.hypot(( - Math.fround(x)), (( + y) >>> 0)) : (((( ~ y) >>> 0) ^ ( + (x % y))) >>> 0)), mathy3(Math.cbrt(( + 0x080000000)), Math.acos(-Number.MAX_SAFE_INTEGER)))), (Math.min((Math.atan2((( + -Number.MIN_VALUE) << ( + Math.ceil(y))), (Math.trunc((-(2**53+2) | 0)) | 0)) | 0), ((y == y) >>> 0)) ? Math.fround(Math.log10(Math.fround(( ~ ( + (((Math.fround((Math.fround(-0x100000001) == Math.fround(Number.MIN_VALUE))) | 0) ? ((y | x) | 0) : -(2**53)) | 0)))))) : (Math.imul((mathy3((( - x) | 0), Math.fround(x)) >>> 0), Math.fround(( + Math.min(x, Math.fround(( ~ y)))))) >>> 0)))); }); testMathyFunction(mathy5, [-0, '/0/', [0], 0.1, NaN, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), '', true, (new String('')), undefined, (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Boolean(true)), false, (new Number(0)), (new Number(-0)), ({toString:function(){return '0';}}), '0', null, /0/, '\\0', [], (new Boolean(false)), 1, 0]); ");
/*fuzzSeed-94431925*/count=214; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var imul = stdlib.Math.imul;\n  var ceil = stdlib.Math.ceil;\n  var log = stdlib.Math.log;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1.5111572745182865e+23;\n    return +((+((((~~(+/*FFI*/ff(((+tan(((-9007199254740992.0))))), ((((0xfc487aa8)) & ((0xfd11d24f)))), ((((0xd8bddabc)) & ((0x25a444ed)))), ((134217729.0)), ((8589934592.0)), ((72057594037927940.0)), ((17179869183.0)), ((1.1805916207174113e+21)), ((257.0)), ((17592186044416.0)), ((32769.0)), ((-35184372088833.0)), ((-562949953421313.0)), ((-2251799813685248.0)), ((-17179869185.0)), ((-147573952589676410000.0))))) > (((/\\B|\\2{3,}./gy)*-0x31728) ^ ((((0xffffffff))>>>((-0x8000000))) / (((0xfc026868))>>>((0xa341c242)))))))>>>((!((0x518e73ad) == (((0xffffffff)-(0xbc22ab36)-(0x31ac786c)) & (-0x83377*((0xff101842) ? (0x11427d17) : (0xf588bb49))))))))));\n    {\n      /*FFI*/ff(((((imul((0xffffffff), (0x9fb5e19e))|0) / (0x780b568)) >> ((0x103cd407)-((~((0xae5b8a58)-(0xfead0c37)-(0x25b3ddc5))) < (~~(d0)))))), ((d0)), ((((i1)+(!(-0x8000000))+(/*FFI*/ff()|0)) >> (((i1)) % (~~(134217727.0))))), ((+ceil(((d0))))), ((((Uint32ArrayView[1])) ^ ((0xffffffff)))), ((d0)), ((((0xa2709d9a)) << ((0xbb51ebfd)))), ((590295810358705700000.0)), ((-33.0)), ((-536870913.0)), ((144115188075855870.0)), ((-4611686018427388000.0)), ((35184372088831.0)), ((-9.44473296573929e+21)), ((4503599627370495.0)));\n    }\n    i1 = ((0x4cab39a5) <= ((0x376d6*(0xd5708ef4))>>>(((+(1.0/0.0)) >= (d2))+((0x7851cad))+(x))));\n    return +((Float32ArrayView[4096]));\n    i1 = (0xf9ff6553);\n    (Uint32ArrayView[1]) = (((~((0x227d929b)+(0x9022c78c))) <= (((0xfab4f95f)) & (((0x1d8ff906) > (0x5e87d47c))-(-0x8000000))))-(/*MARR*/[[],  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(false), new String(''), new Boolean(false), new String(''), [],  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new String(''),  /x/ , new Boolean(false), [], new Boolean(false), new String(''), new String(''), new String(''), new Boolean(false), [], new String(''), [], [], new Boolean(false),  /x/ , [],  /x/ , new String(''), new String(''), [], new String(''), new Boolean(false), [], [],  /x/ , [],  /x/ , [],  /x/ , [],  /x/ , new Boolean(false),  /x/ ,  /x/ , new Boolean(false), new Boolean(false), new Boolean(false),  /x/ , [], [],  /x/ , []].some)-(i1));\n    i1 = (/*UUV2*/(x.\u0009parse = x.trimLeft));\n    d2 = (-1099511627777.0);\n    {\n      {\n        d0 = (((((+(1.0/0.0))) / ((d0)))) * ((d0)));\n      }\n    }\n    d2 = (d0);\n    (Uint32ArrayView[1]) = ((Uint8ArrayView[4096]));\n    {\n      d2 = ((d2) + (+log(((+(1.0/0.0))))));\n    }\n    (Float64ArrayView[((i1)-((d2) < (d0))) >> 3]) = ((((+(-1.0/0.0))) / ((d0))));\n    d2 = (+/*FFI*/ff(((d0))));\n    {\n      /*FFI*/ff(((~(((((0xffffffff)-(0xff4cf284))>>>((-0x8000000)-(-0x8000000)-(0xffffffff))))+(i1)+(/*FFI*/ff(((+(0.0/0.0))))|0)))), ((((i1)-(/*FFI*/ff(((~((-0x5aec15d)))), ((1.2089258196146292e+24)), ((-140737488355329.0)), ((-65537.0)), ((1.2089258196146292e+24)), ((8388609.0)), ((-274877906945.0)))|0)-(i1)) ^ (0xac087*(0xfe4cb58b)))), ((+(-1.0/0.0))), ((((0xa79d3578)*0xfffff) >> ((i1)))), ((~((0xe870e116)*-0xaed2d))), ((imul((0x632b5fe8), (0xfdf81a8d))|0)), ((0x6f6ea658)));\n    }\n    {\n      /*FFI*/ff(((((0xdf1af821)-(0xfb28054a)) >> ((i1)+((-((9.44473296573929e+21))) != (-((562949953421313.0))))+(0xffffffff)))), ((((w = Proxy.create(({/*TOODEEP*/})( \"\" ), \"\\u3E3C\"))) % ((+(0.0/0.0))))), ((d0)), ((p={}, (p.z = x)())), ((abs((~~(NaN)))|0)), ((-2.3611832414348226e+21)), (((0x9ca4f130))));\n    }\n    i1 = (!(i1));\n    {\n      {\n        d2 = (d0);\n      }\n    }\n    (Float64ArrayView[((0xfdc9eea2)) >> 3]) = (((i1) ? (+(-1.0/0.0)) : (+/*FFI*/ff())));\n    {\n      return +(((d0) + (d2)));\n    }\n    {\n      (Float32ArrayView[((0x5d5de1a1)+(/*FFI*/ff(((+(0.0/0.0))), ((imul((0x8b0cd1f0), ((0x2a8791ce) ? (0x1b765ea2) : (0xcd2fb70c)))|0)), ((+(-1.0/0.0))))|0)) >> 2]) = (((i1)));\n    }\n    {\n/* no regression tests found */    }\n    return +((-274877906945.0));\n    return +((d0));\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53), -0, -(2**53-2), 2**53, 2**53+2, -0x100000000, 0, 1, 0.000000000000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, 42, -Number.MAX_VALUE, -1/0, Math.PI, -0x100000001, -(2**53+2), -Number.MIN_VALUE, 2**53-2, 0x080000000, 0x100000000, 0/0, 0x080000001, Number.MIN_VALUE, -0x080000001, 0x0ffffffff, 0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=215; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.log2((((Math.fround((Math.hypot(( + Math.imul((y | 0), (( + (x << ( + y))) >>> 0))), y) === Math.fround(Math.atan2(x, x)))) >>> 0) , ((( ! (y | 0)) | 0) < ( - -(2**53-2)))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0.000000000000001, -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 0, Math.PI, -0, 0x100000001, 0x100000000, -0x100000000, 0x080000001, 1, 0x07fffffff, -(2**53-2), -(2**53), -1/0, Number.MIN_VALUE, 2**53+2, 1/0, -Number.MAX_SAFE_INTEGER, 42, -0x080000000, -Number.MAX_VALUE, 0x080000000, 2**53, -0x07fffffff, 0x0ffffffff, -0x100000001, 0/0, 1.7976931348623157e308, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=216; tryItOut(";");
/*fuzzSeed-94431925*/count=217; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.imul((((((( ~ ((((( ! x) | 0) >>> (42 ? x : x)) >>> 0) >>> 0)) | 0) >>> 0) != ((Math.atan2((0x080000001 >>> 0), (Math.fround((y ^ x)) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0), (( + (( + Math.log1p(( + x))) | Math.exp((((y + 0x07fffffff) | 0) + y)))) | 0))); }); testMathyFunction(mathy0, [-1/0, 0x080000000, -0x07fffffff, 0.000000000000001, Number.MIN_VALUE, Math.PI, -0x0ffffffff, -0x100000000, -Number.MAX_VALUE, 0/0, -0x080000001, -(2**53-2), -(2**53), Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), 0, 0x07fffffff, 2**53+2, 0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, 2**53-2, 0x080000001, -0, 42, 2**53, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=218; tryItOut("while((()) && 0){s1 += 'x'; }");
/*fuzzSeed-94431925*/count=219; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.hypot((Math.trunc(Math.imul(Math.fround(( + Math.fround(x))), Math.asinh((Math.asin((x | 0)) / y)))) >> Math.pow((Math.hypot((x >>> 0), Math.asinh(x)) >>> 0), ( + Math.expm1(( + x))))), Math.max((Math.min((y >>> 0), ( + Math.min(y, 0x100000000))) | 0), Math.min(Math.hypot(x, ( - x)), Math.atan2(x, (Math.clz32((x | 0)) >>> 0))))); }); testMathyFunction(mathy0, [0x100000001, 2**53, -0, 1, 0x0ffffffff, Number.MIN_VALUE, 0/0, -0x080000000, -Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, 1/0, 1.7976931348623157e308, -0x100000001, 2**53+2, -0x07fffffff, -(2**53), 0x080000000, -0x080000001, 0, 42, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0x07fffffff, 2**53-2, -Number.MIN_VALUE, 0x100000000, -1/0, -(2**53-2), -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=220; tryItOut("print(p2);");
/*fuzzSeed-94431925*/count=221; tryItOut("i2 + h0;function \u3056(...z)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((\u3056)\n = (let (b) [,]));\n  }\n  return f;s2 = this.a2.join(s1);");
/*fuzzSeed-94431925*/count=222; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-94431925*/count=223; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\3)|(?:\\u9c95)(?:\\u2bc1)|.(.){1,4}\\\\2|(\\\\2$\\u0099{3}){3,4}\", \"gi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-94431925*/count=224; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.pow(Math.cbrt(Math.fround(( + Math.fround(x)))), ((mathy0((Math.log10((( - (( + ( ! 0/0)) | 0)) | 0)) | 0), Math.hypot(Math.cosh((y | 0)), ( ! -0x080000001))) >>> 0) | 0)); }); testMathyFunction(mathy3, [0x100000000, 0x100000001, 42, 2**53, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, -(2**53+2), -0x0ffffffff, 0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 0/0, 0.000000000000001, -(2**53-2), Math.PI, 0x080000001, -0x100000001, 0x080000000, -0x080000000, Number.MIN_VALUE, -0x080000001, -0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, 1/0, 1, -Number.MIN_VALUE, 2**53-2, -0, -(2**53)]); ");
/*fuzzSeed-94431925*/count=225; tryItOut("/*oLoop*/for (var ulbyad = 0; ulbyad < 118; (4277), (makeFinalizeObserver('nursery')), ++ulbyad) { a0.toSource = (function mcc_() { var xkanuj = 0; return function() { ++xkanuj; if (/*ICCD*/xkanuj % 7 == 3) { dumpln('hit!'); try { ; } catch(e0) { } m1.has(g2); } else { dumpln('miss!'); try { m2 + ''; } catch(e0) { } try { v1 = evaluate(\"print(x);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 54 == 41), catchTermination: y.toLocaleTimeString(\"\\u2329\"), element: o1, elementAttributeName: s2, sourceMapURL: s1 })); } catch(e1) { } try { e1 + ''; } catch(e2) { } m2.has(o0); } };})(); } ");
/*fuzzSeed-94431925*/count=226; tryItOut("let(e) { e.stack;}");
/*fuzzSeed-94431925*/count=227; tryItOut("testMathyFunction(mathy3, /*MARR*/[(-1), -Infinity]); ");
/*fuzzSeed-94431925*/count=228; tryItOut("Object.defineProperty(this, \"s0\", { configurable: (x % 100 != 19), enumerable: false,  get: function() {  return Array.prototype.join.apply(a1, [s1]); } });");
/*fuzzSeed-94431925*/count=229; tryItOut("");
/*fuzzSeed-94431925*/count=230; tryItOut("v2 = g2.runOffThreadScript();");
/*fuzzSeed-94431925*/count=231; tryItOut("\"use strict\"; a2.push(262144.unwatch(\"setUTCHours\"), g0);");
/*fuzzSeed-94431925*/count=232; tryItOut("\"use strict\"; v0 = null;");
/*fuzzSeed-94431925*/count=233; tryItOut("\"use strict\"; \"use asm\"; /*infloop*/M:for(var x in ((Date.prototype.setMonth)(eval)))for(let c in []);return ( /x/g )(\"\\u0065\");;");
/*fuzzSeed-94431925*/count=234; tryItOut("\"use strict\"; /*vLoop*/for (lfjcox = 0; lfjcox < 54; ++lfjcox) { let w = lfjcox; /*bLoop*/for (var lctqfj = 0; lctqfj < 72; ++lctqfj) { if (lctqfj % 5 == 4) { a1.toSource = (function(j) { if (j) { try { a1.splice(6, this.v1, h0, t0, o0); } catch(e0) { } try { v2 = (o0.v2 instanceof t1); } catch(e1) { } e0.valueOf = (function() { try { h0.defineProperty = f1; } catch(e0) { } t2 = new Int16Array(a1); return this.f1; }); } else { try { selectforgc(o0); } catch(e0) { } try { /*RXUB*/var r = r0; var s = \"\"; print(r.exec(s));  } catch(e1) { } (void schedulegc(this.g2)); } }); } else { v1 = a0.some(f1); }  }  } ");
/*fuzzSeed-94431925*/count=235; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.abs(( + Math.atanh(Math.abs(( ! ( ~ -0x100000000)))))); }); testMathyFunction(mathy4, [2**53, -(2**53+2), -(2**53-2), Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, -0, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), 1/0, 0x080000001, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -0x080000000, -0x080000001, 1, -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, Number.MIN_VALUE, 2**53+2, -1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, 0, 2**53-2, 42]); ");
/*fuzzSeed-94431925*/count=236; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( + ( + Math.fround(Math.pow((mathy2((-0x07fffffff >>> 0), Math.min(Math.pow(y, ( + Math.hypot((x >>> 0), ( + Math.log10(x))))), Math.fround(Math.atan2(( + x), ( + y))))) >>> 0), (Math.imul((( ~ y) >>> 0), (y >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-94431925*/count=237; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - ( + Math.abs(Math.fround(((( + x) & Math.atanh((x ? y : y))) >>> 0))))) == Math.fround(Math.max(( + (mathy0(x, (Math.cos((Math.acos(y) | 0)) | 0)) ? Math.fround((Math.fround((Math.fround(y) + Math.fround(1.7976931348623157e308))) % x)) : ((mathy1((mathy2(2**53+2, -Number.MAX_VALUE) >>> 0), mathy2(Math.fround(y), x)) < (Math.fround(( + Math.fround((( ~ y) >>> 0)))) >>> ( + 1))) >>> 0))), ( ! Math.asinh(((x & (y && x)) >>> 0)))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -1/0, Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, -0x080000001, -0, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, 0x100000000, 0x080000001, 0x100000001, -Number.MAX_VALUE, -0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -0x0ffffffff, 0.000000000000001, 1, -(2**53), 2**53-2, -(2**53+2), 0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, 1/0, 0/0, -0x100000001, 42]); ");
/*fuzzSeed-94431925*/count=238; tryItOut("/*iii*/({call: \"\\u8D9C\",  set -4(jxvchj, x, ...window) { yield false }  });/*hhh*/function jxvchj(a, x){var v2 = -0;}");
/*fuzzSeed-94431925*/count=239; tryItOut("print((p={}, (p.z =  /x/g )()));");
/*fuzzSeed-94431925*/count=240; tryItOut("a1.__proto__ = e0;");
/*fuzzSeed-94431925*/count=241; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -590295810358705700000.0;\n    var d3 = 3.0;\n    var d4 = 1.5111572745182865e+23;\n    var i5 = 0;\n    var d6 = -524287.0;\nprint(x);    d0 = (+(0.0/0.0));\n    i5 = (-5 !== [1] / true);\n    d4 = (d6);\n    d0 = ((0x52bf6400) ? (d0) : (+pow(((((+(0xb43da886))) - ((d6)))), ((+/*FFI*/ff(((abs((((0xfb0379ae))|0))|0))))))));\n    return ((0xfffff*(x)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, 0/0, -0x100000000, -0x07fffffff, -0x080000001, -Number.MAX_VALUE, 0, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, -0, 1/0, 0.000000000000001, -0x100000001, 0x100000000, -(2**53), 42, 1.7976931348623157e308, 0x080000000, -(2**53-2), -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, 1, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=242; tryItOut("o0.v0 = this.g2.t2.length;");
/*fuzzSeed-94431925*/count=243; tryItOut("v2 = Object.prototype.isPrototypeOf.call(g2, a2);");
/*fuzzSeed-94431925*/count=244; tryItOut("o0.s1 = new String;");
/*fuzzSeed-94431925*/count=245; tryItOut("v0 = (b0 instanceof h2);");
/*fuzzSeed-94431925*/count=246; tryItOut("/*infloop*/while(Math.cos(-4))print(\"\\u19B8\");");
/*fuzzSeed-94431925*/count=247; tryItOut("\"use strict\"; v1 = r1.source;");
/*fuzzSeed-94431925*/count=248; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ Math.atan2(Math.fround(Math.cosh((x | 0))), (Math.cbrt(x) ? mathy0(x, Math.imul(x, y)) : Math.fround(Math.log1p((Math.fround(mathy0(Math.fround(-1/0), Math.fround(y))) | 0)))))); }); testMathyFunction(mathy1, [0x100000001, 0, 0x080000000, Math.PI, -Number.MAX_VALUE, 2**53, 0x100000000, -0x100000001, -Number.MIN_VALUE, -0x080000000, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -0x080000001, 0x0ffffffff, -1/0, 1/0, 2**53-2, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, 1, 2**53+2, -(2**53)]); ");
/*fuzzSeed-94431925*/count=249; tryItOut("\"use strict\"; /*hhh*/function kbfbyf(c){g1.offThreadCompileScript(\"b0 + '';\");}/*iii*/w = x.yoyo(((void shapeOf(arguments)))), wyfflw, x = /*UUV2*/(x.apply = x.getDate), \"-23\" = x, xflypy;m2.set(o1.b2, o1.o2);");
/*fuzzSeed-94431925*/count=250; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=251; tryItOut("\"use strict\"; x.constructor;for(let b of (1 for (x in []))) let(omvson, z, b, pnkmit, x = (eval = -25), a, z, jphupb) ((function(){return;})());");
/*fuzzSeed-94431925*/count=252; tryItOut("var d, d = ({}), b = y <<=  /x/g , x = x, c, e = (allocationMarker());v1 = Object.prototype.isPrototypeOf.call(o1, f2);");
/*fuzzSeed-94431925*/count=253; tryItOut("\"use strict\"; var r0 = 4 % 7; var r1 = r0 % 8; r0 = r1 % r1; r0 = r1 * r1; print(r0); var r2 = 0 ^ r0; print(r1); var r3 = r0 % r1; var r4 = 4 + r1; var r5 = 2 - 5; var r6 = r0 + r1; var r7 = r3 % r5; var r8 = r3 ^ r2; var r9 = r3 / r6; var r10 = 2 + r0; var r11 = r7 ^ r5; r9 = x + r10; var r12 = r1 - r7; var r13 = 0 | r3; var r14 = 9 / 3; var r15 = r1 % x; var r16 = 1 & 5; r3 = 2 - r3; var r17 = 2 * r7; var r18 = r11 - 6; r14 = 6 - r11; var r19 = 9 - r14; var r20 = 0 * 0; var r21 = 3 % 1; var r22 = 9 - r5; var r23 = r1 + 4; var r24 = r20 / r9; r8 = x % r12; var r25 = 0 | 9; var r26 = r25 & r2; print(r23); var r27 = 4 * r0; var r28 = r10 % 9; var r29 = r11 * r10; var r30 = 8 ^ r12; var r31 = 3 & 3; r0 = r22 * r6; var r32 = r19 - r25; var r33 = 8 * 9; var r34 = 3 | r17; var r35 = r30 | r23; var r36 = r24 & r7; r14 = 6 | 6; var r37 = r30 - 8; var r38 = r11 & r15; r22 = 9 | r33; var r39 = r8 + r34; var r40 = r26 & 2; var r41 = r27 ^ 1; var r42 = r24 | r36; var r43 = 4 / 7; var r44 = 9 * 1; var r45 = r29 + r24; ");
/*fuzzSeed-94431925*/count=254; tryItOut("x = linkedList(x, 5490);");
/*fuzzSeed-94431925*/count=255; tryItOut("\"use strict\"; v2 = t0.length;\ns1.toString = (function() { try { Array.prototype.unshift.call(a0, s1, this.h2, x, o1.e2); } catch(e0) { } m2.get(h2); return p2; });\n");
/*fuzzSeed-94431925*/count=256; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x100000001, -1/0, -0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, -0, Math.PI, -0x100000001, -0x07fffffff, 0, -(2**53-2), -0x100000000, 42, 2**53, Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 0/0, 2**53-2, -0x080000001, -(2**53), -0x080000000, 0x100000000, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=257; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ((( ! (Math.tan(2**53) | 0)) / ( + ((y || 1.7976931348623157e308) >> (( ~ (x | 0)) | 0)))) ? ( - (( - x) | 0)) : Math.ceil(Math.log1p(((Math.pow(y, (mathy0((-1/0 >>> 0), y) >>> 0)) !== Math.clz32(( + Math.imul(x, x)))) >>> 0)))); }); ");
/*fuzzSeed-94431925*/count=258; tryItOut("\"use strict\"; for(let x = new RegExp(\"[^]{0,4}[^]|\\\\b|\\\\cN+?|\\\\x35+?[^]+\", \"yi\") in  '' ) {}");
/*fuzzSeed-94431925*/count=259; tryItOut("a0.sort(this.t1);");
/*fuzzSeed-94431925*/count=260; tryItOut("mathy2 = (function(x, y) { return mathy0(mathy0(Math.pow(y, ( + (( + Math.imul(mathy0((((-Number.MIN_SAFE_INTEGER | 0) ? (y | 0) : (y | 0)) | 0), -(2**53)), (y !== (( ! y) | 0)))) || ( + Math.max(-0x07fffffff, y))))), (Math.pow((-0x100000001 >>> 0), (Math.cosh(-Number.MIN_VALUE) >>> 0)) >>> 0)), Math.fround(Math.sqrt(Math.atan2(Math.fround((((-0x0ffffffff | 0) < (Math.pow((2**53+2 | 0), x) | 0)) | 0)), Math.fround(Math.sign(Math.fround((((x >>> 0) && (x >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy2, /*MARR*/[ 'A' , null, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  'A' ,  'A' , null,  'A' ,  'A' , null,  'A' ,  'A' , null]); ");
/*fuzzSeed-94431925*/count=261; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.push.apply(a2, [m1, g2, new (x)()]);");
/*fuzzSeed-94431925*/count=262; tryItOut("var b0 = t2.buffer;");
/*fuzzSeed-94431925*/count=263; tryItOut("M: for  each(let z in d) {v1.__proto__ = f0;/*MXX3*/g0.String.prototype.lastIndexOf = g0.String.prototype.lastIndexOf; }");
/*fuzzSeed-94431925*/count=264; tryItOut("((((w)) = ((x | 0) ? (( + ( + ( + Math.fround((x === x))))) | 0) : (x | 0))));");
/*fuzzSeed-94431925*/count=265; tryItOut("var [] = (delete z.\u3056), zicmbk, ejoutj, bwpyhl, yxoulv, hgsrsz, x, gdpdct, x;o1.e2.add(m0);");
/*fuzzSeed-94431925*/count=266; tryItOut("testMathyFunction(mathy1, [0, -(2**53-2), -0x100000000, 0x080000000, 1, Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, 1.7976931348623157e308, 2**53-2, Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -0, 0.000000000000001, -(2**53), Number.MAX_VALUE, -0x07fffffff, 0x100000001, 0x07fffffff, 0x100000000, 0x0ffffffff, -1/0, -0x080000001, 42, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=267; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0((Math.cosh((Math.fround(( ~ Math.fround((Math.PI >> (((Math.expm1((x >> x)) | 0) === (y | 0)) | 0))))) >>> 0)) >>> 0), ( + ( + (mathy0(Math.exp(mathy0((Math.PI & y), -(2**53+2))), ( + Math.fround(Math.cbrt(Math.fround(this))))) ? 0x0ffffffff : (Math.asinh((-0x100000000 | 0)) | 0))))) | 0); }); testMathyFunction(mathy1, /*MARR*/[function(){}, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (void 0), (void 0), (void 0), function(){}, function(){}, (void 0), ['z'], function(){}, x, ['z'], ['z'], ['z'], ['z'], ['z'], function(){}]); ");
/*fuzzSeed-94431925*/count=268; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-94431925*/count=269; tryItOut("a2 = Array.prototype.concat.apply(a1, []);");
/*fuzzSeed-94431925*/count=270; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( - Math.sqrt(( + ( + Math.max(( + ( + mathy0(( + Math.clz32(( + y))), ( + (Number.MIN_VALUE < Number.MAX_SAFE_INTEGER))))), ( + ( - ((y > ( + -0)) | 0)))))))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), 0x100000001, -1/0, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -(2**53), 0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -0x080000001, 42, -0, -0x080000000, Math.PI, -0x100000001, 2**53-2, Number.MAX_VALUE, -(2**53+2), 0/0, 0x07fffffff, -Number.MAX_VALUE, 0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, 0x100000000]); ");
/*fuzzSeed-94431925*/count=271; tryItOut("Object.prototype.watch.call(g2.g1, new String(\"-6\"), (function() { for (var j=0;j<11;++j) { f1(j%4==1); } }));");
/*fuzzSeed-94431925*/count=272; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((( + mathy0(Math.fround(Math.max(Math.fround(y), Math.fround(( ! Math.fround(y))))), (( + ( ~ ( + ( + ( + ( + (( - (x >>> 0)) >>> 0))))))) | 0))) ? Math.imul(( + Math.cbrt(x)), Math.hypot((Math.round((x | 0)) | 0), x)) : (( ! (Math.min((mathy0((y | 0), (( ! (( ~ x) >>> 0)) | 0)) | 0), ((0x080000000 !== ( + Math.trunc(x))) >>> 0)) >>> 0)) >>> 0)) >> Math.fround(((Math.exp(( ! (Math.fround(y) && ((-Number.MAX_SAFE_INTEGER & x) >>> 0)))) ? (( + mathy0((mathy0(Math.hypot((Math.acos(x) | 0), y), 0.000000000000001) | 0), ( - Math.sinh(Math.tanh(y))))) | 0) : Math.acos(x)) | 0))); }); testMathyFunction(mathy1, [false, '/0/', (new Number(0)), null, (new Boolean(true)), -0, '0', (function(){return 0;}), NaN, true, [0], (new Number(-0)), '', /0/, (new String('')), 0.1, 0, (new Boolean(false)), '\\0', objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), [], ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), 1, undefined]); ");
/*fuzzSeed-94431925*/count=273; tryItOut("\"use strict\"; let ({x: [[], ], b, window, w} = x.__defineGetter__(\"window\", objectEmulatingUndefined), [{c,  '' .y, x: {e: {}, x: eval}, y: [, []]}, {y}, , , ] = (x = (/*wrap2*/(function(){ var colfxp = -29; var heyesf = (NaN, x) => \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      {\n        {\n          (Float64ArrayView[1]) = ((+(x < x)));\n        }\n      }\n    }\n    d1 = (d1);\n    return +((-((d1))));\n  }\n  return f;; return heyesf;})()).call(\"\\u93A3\", null, \"\\u1CAB\")), x, b = (x = {e}), w = x = undefined, eval = NaN / NaN) { /* no regression tests found */ }");
/*fuzzSeed-94431925*/count=274; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( ~ (Math.fround(Math.pow(Math.fround(Math.expm1(Math.fround(mathy0(Math.fround((( ! ((Math.atan2(Math.fround(y), Math.fround(( + (x || y)))) | 0) >>> 0)) >>> 0)), Math.fround(y))))), Math.fround(( - (((((((y >>> 0) ** ( + y)) >>> 0) <= y) >>> 0) | 0) >>> Math.fround(Math.cbrt(Math.fround((((x >>> 0) - ((( ~ (x >>> 0)) >>> 0) >>> 0)) >>> 0))))))))) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, -(2**53+2), Math.PI, 2**53, 2**53+2, -0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 0, 1, 0x100000001, 0x080000000, 1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, -0x07fffffff, 0x100000000, -0x100000001, 42, 0.000000000000001, 0/0, -(2**53-2), -1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -(2**53), 1.7976931348623157e308]); ");
/*fuzzSeed-94431925*/count=275; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.cbrt(Math.max(( ~ (( ! (y >>> 0)) | 0)), (( + (( + Math.atan2(( ! ( + y)), x)) <= ( + Math.fround(mathy0((x >= x), x))))) >>> 0))); }); testMathyFunction(mathy1, [-0x0ffffffff, -Number.MAX_VALUE, 2**53, 1/0, Number.MIN_VALUE, 1.7976931348623157e308, 0, -0x100000000, -0x07fffffff, 2**53+2, 0x100000001, -0x080000001, -(2**53), Math.PI, 0x0ffffffff, 42, 0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 0x100000000, 1, -(2**53+2), 0x080000001, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, -0, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-94431925*/count=276; tryItOut("s1.toSource = (function() { a0.push(b0, t0); return b0; });");
/*fuzzSeed-94431925*/count=277; tryItOut("{v2 = Object.prototype.isPrototypeOf.call(b1, this.o1);this.a0[17] = /*MARR*/[ /x/g ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ].filter(Array.prototype.unshift, 6)(-8); }");
/*fuzzSeed-94431925*/count=278; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow(( ~ mathy2(-(2**53), (Math.tan(((((0x0ffffffff > x) ** Math.log(0)) | 0) | 0)) | 0))), ( + mathy1(Math.atanh((Math.hypot((x ** mathy3(( + y), ( + y))), 0x100000001) <= (y ? Math.atan2((-1/0 ^ ( + -(2**53))), y) : 0))), Math.fround(Math.fround((( + ((x | 0) ^ (x | 0))) ? Math.fround(y) : x)))))); }); testMathyFunction(mathy4, [0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53), 0x100000001, Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, -0x07fffffff, Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), -Number.MIN_VALUE, Math.PI, 0x080000000, 0, 2**53, -0x100000001, -(2**53+2), 42, -0x100000000, -0x080000001, -1/0, 0/0, 2**53+2, 0x100000000, 0x080000001, -0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=279; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( - ( + (Math.asin(((Math.fround(( ~ (Math.fround(Math.pow((( + mathy1(( + x), ( + 0x07fffffff))) >>> 0), Math.fround(x))) >>> 0))) >>> y) >>> ( + Math.log1p(( + y))))) >>> 0)))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 1, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, 0x080000000, -0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, -(2**53-2), 0x100000000, 0x0ffffffff, 1/0, -Number.MAX_VALUE, -(2**53+2), 0x07fffffff, -0x080000000, 2**53+2, 1.7976931348623157e308, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, 2**53-2, 42, -(2**53), 0/0, 2**53, Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-94431925*/count=280; tryItOut("h0 + s1;");
/*fuzzSeed-94431925*/count=281; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( ~ ( ! Math.trunc((( ~ (Math.fround(Math.imul(( + (( ! 1.7976931348623157e308) | 0)), ( + mathy0(( + 0x07fffffff), Math.fround(y))))) >>> 0)) >>> 0)))) >>> 0); }); testMathyFunction(mathy5, [0x100000001, 0, -0x07fffffff, 0x0ffffffff, 0/0, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, 0.000000000000001, -0x080000001, Number.MAX_VALUE, 2**53, -(2**53-2), -0, -Number.MIN_VALUE, -(2**53), -0x0ffffffff, -1/0, 2**53+2, -0x100000001, 0x07fffffff, 0x080000001, 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, 1, -(2**53+2)]); ");
/*fuzzSeed-94431925*/count=282; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy2((Math.sqrt(((( + mathy1((Math.fround(Math.imul(Math.pow(mathy2(1.7976931348623157e308, y), (((x | 0) , (y | 0)) | 0)), ( + ((( + 0x080000000) | 0) != Math.hypot(y, -Number.MIN_VALUE))))) | 0), mathy0(( + ( + (( + (( ~ y) >>> 0)) - (x | 0)))), ( + -0x100000000)))) !== Math.PI) | 0)) | 0), (Math.fround(((( + (Math.max(y, (( ! (y | 0)) | 0)) >>> 0)) ? (((Math.fround(( ~ y)) > (( + Math.log1p(( + -0x100000000))) >>> 0)) >>> 0) | 0) : (x >>> 0)) | 0)) != Math.fround(( - 0.000000000000001)))); }); testMathyFunction(mathy3, /*MARR*/[new Boolean(false), x, new Boolean(false), new Boolean(false), function(){}, new Boolean(false), new Boolean(false), new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, new Boolean(false), x, new Boolean(false), function(){}, new Boolean(false), function(){}, x, function(){}, x, x, function(){}, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x, new Boolean(false), x, function(){}, function(){}, x, x, new Boolean(false), new Boolean(false), function(){}, x, new Boolean(false), x, x, x, new Boolean(false), function(){}, new Boolean(false), new Boolean(false), function(){}, new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, x, x, new Boolean(false), function(){}, function(){}]); ");
/*fuzzSeed-94431925*/count=283; tryItOut("with({}) { for(let y in  \"\"  for each (d in ((p={}, (p.z = this)()))) for (x of [])) return; } ");
/*fuzzSeed-94431925*/count=284; tryItOut("t0.__proto__ = g0.b1;");
/*fuzzSeed-94431925*/count=285; tryItOut("mathy5 = (function(x, y) { return Math.pow(Math.fround((Math.sign((( + Math.fround(x)) | 0)) >>> 0)), Math.log(( + ( ! Math.fround(y))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, 0x07fffffff, 42, -0x07fffffff, -Number.MAX_VALUE, 1/0, 0x080000001, -(2**53-2), 0, 2**53-2, 0/0, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, -Number.MIN_VALUE, -0x100000000, -0x100000001, 1.7976931348623157e308, -0, 1, 0x100000001, -(2**53+2), 0x080000000, Math.PI, Number.MAX_VALUE, 0.000000000000001, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=286; tryItOut("do {/*infloop*/for(y = Math.max(-14, -13);  \"\" ; x) (false); } while((x) && 0);");
/*fuzzSeed-94431925*/count=287; tryItOut("var eubbdp = new SharedArrayBuffer(6); var eubbdp_0 = new Int8Array(eubbdp); eubbdp_0[0] = -18; var eubbdp_1 = new Int32Array(eubbdp); print(eubbdp_1[0]); eubbdp_1[0] = -16; var eubbdp_2 = new Int8Array(eubbdp); var eubbdp_3 = new Float64Array(eubbdp); var eubbdp_4 = new Float64Array(eubbdp); print(eubbdp_4[0]); var eubbdp_5 = new Int32Array(eubbdp); eubbdp_5[0] = 13; var eubbdp_6 = new Float32Array(eubbdp); var eubbdp_7 = new Int8Array(eubbdp); eubbdp_7[0] = 24; var eubbdp_8 = new Uint8Array(eubbdp); eubbdp_8[0] = -19; m0.delete(( /* Comment */this.\u0009yoyo(/((?:(?:[^]))|.|\\B+?){1}|(?:.)(?=\\1){0,2}/y = Proxy.create(({/*TOODEEP*/})(this),  /x/g ))));this.i2.toString = (function(j) { if (j) { try { for (var p in v2) { try { /*RXUB*/var r = r2; var s = s1; print(r.test(s)); print(r.lastIndex);  } catch(e0) { } g0.a2.shift(i1); } } catch(e0) { } h1 = {}; } else { try { this.a0[15] = o0; } catch(e0) { } m2.get(m1); } });");
/*fuzzSeed-94431925*/count=288; tryItOut("v2 = Object.prototype.isPrototypeOf.call(p1, o0.t0);\n(void schedulegc(g0));function NaN() { \"use strict\"; for (var v of e1) { try { /*MXX3*/g0.g0.g1.Math.expm1 = g0.Math.expm1; } catch(e0) { } try { t0 = new Uint8Array(t0); } catch(e1) { } try { s2 += 'x'; } catch(e2) { } Object.prototype.unwatch.call(p2, \"getUTCSeconds\"); } } v2 = (o2 instanceof p1);\n");
/*fuzzSeed-94431925*/count=289; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((-0.0625)))|0;\n    i0 = (i0);\n    i1 = (i0);\n    i0 = ((0xffffffff));\n    {\n      {\n        i0 = (!(-0x8000000));\n      }\n    }\n    i1 = ((134217729.0) == ((Float32ArrayView[((window != /\\2/gim)) >> 2])));\n    return (((0xf9c0852c)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return Math.max((Math.asinh((y | 0)) | 0), Math.fround(Math.cos(-Number.MAX_VALUE))); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=290; tryItOut("Array.prototype.sort.call(this.a1, (function mcc_() { var pbkivc = 0; return function() { ++pbkivc; if (/*ICCD*/pbkivc % 11 == 9) { dumpln('hit!'); try { for (var v of a1) { h1.set = (function() { for (var j=0;j<48;++j) { f1(j%3==1); } }); } } catch(e0) { } try { this.a0.push((new Function( /x/g , window))); } catch(e1) { } Array.prototype.sort.apply(o1.a0, [(function() { for (var j=0;j<58;++j) { f1(j%4==0); } })]); } else { dumpln('miss!'); try { a0.toSource = this.f0; } catch(e0) { } o2.a0.splice(-2, x); } };})());");
/*fuzzSeed-94431925*/count=291; tryItOut("testMathyFunction(mathy2, [null, ({toString:function(){return '0';}}), 1, objectEmulatingUndefined(), [0], '', (new Boolean(false)), (new Boolean(true)), ({valueOf:function(){return '0';}}), NaN, ({valueOf:function(){return 0;}}), [], true, (new Number(-0)), '0', false, (function(){return 0;}), -0, (new String('')), 0.1, '/0/', undefined, 0, '\\0', (new Number(0)), /0/]); ");
/*fuzzSeed-94431925*/count=292; tryItOut("mathy1 = (function(x, y) { return ( + (( + (((( ! (Math.round(Math.log1p(-0x080000001)) == ( + (Math.max((y >>> 0), (( ~ ( ~ ( + 1.7976931348623157e308))) >>> 0)) >>> 0)))) >>> 0) != (Math.fround(( + Math.acosh(( + y)))) >>> 0)) >>> 0)) >= ( + mathy0(( + (mathy0(( + 2**53-2), (mathy0((( - (x >>> 0)) | 0), x) | 0)) >>> 0)), Math.fround((( + Math.max(( + Math.log(0/0)), ( + x))) === Math.fround(x))))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -0x100000000, Number.MIN_VALUE, -1/0, 0x0ffffffff, 42, 0x080000001, 0.000000000000001, -(2**53+2), 0x080000000, -0, 0/0, 1.7976931348623157e308, -Number.MAX_VALUE, 1, -Number.MIN_VALUE, -0x0ffffffff, -0x080000000, 0, 0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), 2**53-2]); ");
/*fuzzSeed-94431925*/count=293; tryItOut("/*tLoop*/for (let y of /*MARR*/[(void 0), (void 0), -0x080000001, x, -0x080000001, -0x080000001, -0x080000001, x, d, (void 0), d, x, d, d, -0x080000001, d, objectEmulatingUndefined(), (void 0), d, objectEmulatingUndefined(), d, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), x, (void 0), (void 0), d, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000001, -0x080000001, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, -0x080000001, -0x080000001, d, (void 0), objectEmulatingUndefined(), x, d, d, -0x080000001]) { m2.has(t1); }");
/*fuzzSeed-94431925*/count=294; tryItOut("f2(this.g0.h1);");
/*fuzzSeed-94431925*/count=295; tryItOut("new ( /x/ )(/*MARR*/[0x50505050, null, 0x50505050, 0x50505050, 0x50505050, null, null, null, null, null, null, null, 0x50505050, null, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, null, 0x50505050, 0x50505050, null, 0x50505050, 0x50505050, null, null, null, 0x50505050, 0x50505050, null, 0x50505050, null, null, null, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, null, null, 0x50505050, null, null, 0x50505050, 0x50505050, 0x50505050, null, 0x50505050, 0x50505050, 0x50505050, null, null, 0x50505050, 0x50505050, null, null, 0x50505050, null, 0x50505050, null, null, 0x50505050, null, 0x50505050, null, null, null, 0x50505050, null, null, null, 0x50505050, null, null, 0x50505050, null, null, 0x50505050, 0x50505050, 0x50505050, null, null, 0x50505050, 0x50505050, 0x50505050, null, 0x50505050, null, 0x50505050, 0x50505050, 0x50505050, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0x50505050, null, null, 0x50505050, null, null, 0x50505050, 0x50505050, null, null, 0x50505050, 0x50505050, null, null, 0x50505050, null, 0x50505050, 0x50505050, null, 0x50505050, 0x50505050, null, null, 0x50505050, null, null, null, 0x50505050, null, null, null, null, 0x50505050, null, 0x50505050, null, null, null, null, 0x50505050, null, null, 0x50505050, null, 0x50505050].filter);");
/*fuzzSeed-94431925*/count=296; tryItOut("mathy3 = (function(x, y) { return (( + Math.imul((Math.min(((((((x | Math.atan2(y, y)) > Math.fround(y)) | 0) >= (( - x) | 0)) | 0) >>> 0), Math.fround(Math.fround(((Math.atan2(Math.fround(( + (( + 0.000000000000001) * ( + 2**53-2)))), (Math.fround((Math.fround(y) === Math.fround(( + (( + 1.7976931348623157e308) ? ( + x) : ( + y)))))) | 0)) >>> 0) >>> 0x0ffffffff)))) >>> 0), (x >> (Math.fround(Math.pow((y | 0), (y | 0))) >>> 0)))) ? ( + ( + ( + Math.fround((Math.cos(((Number.MAX_SAFE_INTEGER / y) << Math.sqrt(x))) >>> 0))))) : Math.fround((mathy1(((( + y) >>> mathy0(Math.hypot(x, x), x)) >>> 0), y) | Math.atan2((( + (x ? (mathy2((-Number.MAX_SAFE_INTEGER | 0), (x | 0)) | 0) : 1)) * (y < x)), Math.pow(Math.min((y >>> 0), (x < (Math.cos(x) | 0))), y))))); }); testMathyFunction(mathy3, [0x100000000, 0x07fffffff, -0x080000000, -1/0, 1, -(2**53-2), 2**53+2, Math.PI, 0x0ffffffff, -0x100000000, 0x080000001, 2**53, Number.MIN_VALUE, 42, -(2**53+2), 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, 0/0, -(2**53), 1.7976931348623157e308, 0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, 0.000000000000001, 1/0, -Number.MAX_VALUE, 0x100000001, -0x080000001, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=297; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return (( ! (Math.max((( ~ Math.clz32(( ! Math.fround(( + Math.fround(y)))))) >>> 0), mathy0(( + -0x080000000), ( + Math.fround(( - Math.fround(-(2**53))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x080000000, 1/0, Number.MAX_VALUE, -0x0ffffffff, 1, -1/0, 42, -0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, 0, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0x080000001, Number.MIN_VALUE, -0x100000000, 0x07fffffff, -(2**53-2), -0x100000001, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -(2**53), 2**53, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 2**53-2, 0x080000000, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=298; tryItOut("mathy5 = (function(x, y) { return Math.hypot((Math.fround(Math.imul((Math.fround(( ! x)) >>> 0), Math.fround((( - (mathy4(Math.max(Math.hypot(y, y), Math.exp(Math.fround(y))), (( ! x) >>> 0)) >>> 0)) >>> 0)))) >>> 0), Math.min((((( + ((x + (Math.round((y >>> 0)) >>> 0)) >>> 0)) | 0) % (Math.log10((y >>> 0)) + ((( + 0x0ffffffff) && Math.cos(y)) | 0))) >>> 0), (Math.fround(mathy1(y, ( + ( + (Math.fround(((((Math.hypot((x >>> 0), x) | 0) >>> 0) ? (y | 0) : (( + ((Math.tanh((y | 0)) | 0) | 0)) >>> 0)) >>> 0)) % ( + y)))))) >>> 0))); }); ");
/*fuzzSeed-94431925*/count=299; tryItOut("print(uneval(g1.b1));");
/*fuzzSeed-94431925*/count=300; tryItOut("\"use asm\"; m0.set(i1, v1);");
/*fuzzSeed-94431925*/count=301; tryItOut("var x = window, ycmdkk, c =  '' .valueOf(\"number\"), \u3056 =  /x/ , kqkfra, wrlraf, czmvoz, x, eval;a0.sort((function() { for (var j=0;j<30;++j) { f1(j%5==0); } }));");
/*fuzzSeed-94431925*/count=302; tryItOut("testMathyFunction(mathy2, [0.000000000000001, -1/0, -Number.MAX_VALUE, 0x080000000, -(2**53), -0x100000000, Number.MIN_VALUE, 42, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, Number.MAX_VALUE, 1/0, -(2**53+2), 0, Math.PI, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -0, 0x0ffffffff, 0x100000001, 0/0, -(2**53-2), 0x07fffffff, 2**53-2, 0x080000001, -0x080000001, -0x0ffffffff, -0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=303; tryItOut("\"use strict\"; b1 + f2;");
/*fuzzSeed-94431925*/count=304; tryItOut("\"use strict\"; /*hhh*/function pfttfq({x: [, , ], c}, x){g0.offThreadCompileScript(\"m0 + '';\");(Math.max(/\\3{32,36}|[^]+?\\B*|([^])\\b(?=.+?\\3)|(([^]))[\\rU-\u00a8]|^*?/, ({a1:1})));}/*iii*/e1.has(f1);");
/*fuzzSeed-94431925*/count=305; tryItOut("i2 = x;");
/*fuzzSeed-94431925*/count=306; tryItOut("mathy0 = (function(x, y) { return (((( + (( + Math.imul((( + ( ! ( + ( + (x * ( + Number.MIN_VALUE)))))) | 0), (( - ((x >> case -5: break; case 6: v0 = t2.byteOffset;case 4: print(x);default: break; ) != x)) | 0))) ** (y >>> ( - x)))) | 0) >= (( + (( + Math.fround(Math.imul(Math.fround((Math.max((y >>> 0), (0x080000000 >>> 0)) >>> 0)), Math.fround(( - x))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy0, [[0], (new Boolean(true)), (new Number(0)), null, '/0/', /0/, objectEmulatingUndefined(), undefined, [], (function(){return 0;}), true, 1, 0.1, ({valueOf:function(){return 0;}}), (new Boolean(false)), NaN, (new String('')), '0', 0, ({valueOf:function(){return '0';}}), '', ({toString:function(){return '0';}}), -0, '\\0', false, (new Number(-0))]); ");
/*fuzzSeed-94431925*/count=307; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[null,  '\\0' ,  '\\0' ,  '\\0' , null, null, null, null, null, -Infinity,  '\\0' , (1/0),  '\\0' , null, -Infinity, -Infinity,  '\\0' , -Infinity, -Infinity, -Infinity, (1/0), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  '\\0' , null]) { print(uneval(v0)); }");
/*fuzzSeed-94431925*/count=308; tryItOut("g2.o0.h2 = {};");
/*fuzzSeed-94431925*/count=309; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( + Math.cos(Math.fround((Math.sin(y) ^ (mathy0((-0x0ffffffff | 0), y) >>> ( + Math.min(-Number.MAX_VALUE, -0x07fffffff)))))))); }); testMathyFunction(mathy2, [-0, [], (new Number(0)), null, ({toString:function(){return '0';}}), 0.1, [0], '\\0', false, 0, (function(){return 0;}), (new Boolean(true)), '0', '', undefined, ({valueOf:function(){return 0;}}), (new Number(-0)), ({valueOf:function(){return '0';}}), '/0/', (new String('')), objectEmulatingUndefined(), /0/, true, (new Boolean(false)), NaN, 1]); ");
/*fuzzSeed-94431925*/count=310; tryItOut("mathy0 = (function(x, y) { return ((Math.atan2((((Math.sin(( ~ x)) | 0) > (Math.min((x | 0), (Math.max(( + Math.imul((y >>> 0), ( + (y ? (0x080000001 >>> 0) : ( + y))))), Math.fround(Math.atan2(0x080000001, -0))) | 0)) >>> 0)) | 0), (( + (( + (-Number.MAX_SAFE_INTEGER ** x)) ? ( + ((y ** Number.MAX_SAFE_INTEGER) | 0)) : Math.fround(( + Math.atanh(Math.cos(-0)))))) | 0)) | 0) ? Math.fround(((Math.fround(Math.log1p((Math.imul(0x100000001, y) >>> 0))) ? Math.fround(( - Math.fround(y))) : ( + (Math.log2(((x > y) >>> 0)) >>> 0))) ? (( + Math.cos(Math.fround(Math.pow(Math.fround(((1.7976931348623157e308 | 0) < x)), Math.hypot(Math.fround((x & Math.fround(Math.fround((Math.fround(y) && Math.fround(x)))))), (1/0 % y)))))) >>> 0) : Math.fround(Math.atanh(Math.fround(Math.log2(y)))))) : ( + Math.log10(Math.fround(0x080000000)))); }); ");
/*fuzzSeed-94431925*/count=311; tryItOut("/(?:.|M{1,2}|.)|\\W\\6|((?=[^]))*?(?!.)+.?/gim;neuter");
/*fuzzSeed-94431925*/count=312; tryItOut("\"use strict\"; v1 = t2.length;");
/*fuzzSeed-94431925*/count=313; tryItOut("/*RXUB*/var r = /(?=.+?|(?=(?:[^])){1,3}){2}|((?=(\\b))*?\\u7bff[^\\S\\D]|(?!\\B)(?=[^])?*)+?/y; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=314; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 2251799813685249.0;\n    var d3 = 3.0;\n    return (((0x306b5111)-(0xf98326eb)+((0xff0194be) ? (-0x8000000) : (0xffffffff))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [2**53+2, 0x100000001, 2**53-2, 0/0, 1.7976931348623157e308, 0, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 0x080000000, 2**53, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, -0x080000001, -(2**53), Math.PI, -0x100000000, Number.MAX_VALUE, -1/0, -0x080000000, -(2**53+2), 0x0ffffffff, 42, 1/0, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, -0x0ffffffff, Number.MIN_VALUE, 1, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=315; tryItOut("\"use strict\"; /*vLoop*/for (var vaaxzq = 0; vaaxzq < 136; ++vaaxzq) { let c = vaaxzq; t0 = new Float64Array(b1, 16, 4); } ");
/*fuzzSeed-94431925*/count=316; tryItOut("mathy5 = (function(x, y) { return mathy0((( + (Math.min(( + Math.fround(Math.sign(Math.fround(1/0)))), (Math.atan2((1 | 0), (y | 0)) | 0)) | 0)) | 0), Math.max(Math.cosh(y), Math.max((( + 42) | 0), (( ! (((Math.pow((x >>> 0), -0x07fffffff) | 0) , Math.cosh(x)) | 0)) | 0)))); }); testMathyFunction(mathy5, [0x07fffffff, 0/0, -Number.MAX_VALUE, -(2**53-2), Math.PI, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000001, -0, Number.MIN_SAFE_INTEGER, 0x080000001, 0, 0x100000000, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, Number.MAX_VALUE, 0x100000001, 0x080000000, 0x0ffffffff, -(2**53), Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -(2**53+2), 1, -Number.MIN_VALUE, 1/0, -0x0ffffffff, 42, -0x100000001, -0x080000000]); ");
/*fuzzSeed-94431925*/count=317; tryItOut("g1.v2 = (h0 instanceof m2)\n");
/*fuzzSeed-94431925*/count=318; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[false, this, false, this, this, this, new Boolean(true), this, this, this, x, x, false, false, new Boolean(true), this, false, this, this, this, x, this, new Boolean(true), new Boolean(true), x, x, false, new Boolean(true), false, x]) { -19; }");
/*fuzzSeed-94431925*/count=319; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?!(?:\u0001))|(?:(?:\\d).{3,})\\2?)|\\1{4,}/gi; var s = Math.pow(9, --a); print(r.test(s)); ");
/*fuzzSeed-94431925*/count=320; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(Math.fround((((Math.max(Math.abs((Math.acos((y | 0)) | 0)), Math.max((Number.MAX_VALUE ? Math.fround((y ** Math.fround(-0x100000000))) : Math.fround((x >= y))), ( + Math.max(( + y), ( + x))))) | 0) <= Math.fround(mathy0((Math.exp((y >>> 0)) >>> 0), (((x >>> 0) ? (mathy0(x, Math.atan2(y, 2**53-2)) >>> 0) : (((y / x) < y) >>> 0)) >>> 0)))) | 0)), Math.fround(((( - Math.fround(Math.max(Math.fround(y), Math.fround((( ! (y | 0)) | 0))))) && ((Math.sin((y | 0)) != ((((y < (( - 0x07fffffff) >>> 0)) >>> 0) >>> 0) & (( + mathy0(( + Number.MAX_SAFE_INTEGER), ( + x))) | 0))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -(2**53), -0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -1/0, -(2**53+2), 2**53, 1, Number.MIN_VALUE, -0x07fffffff, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, -Number.MAX_VALUE, 42, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 0, 2**53-2, 1/0, 0x080000000, 0.000000000000001, 0x100000001, 0x080000001, 0x100000000]); ");
/*fuzzSeed-94431925*/count=321; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.asin((((Math.log1p((( + ( ~ ( + y))) >>> 0)) >>> 0) >>> 0) >> ((Math.expm1(( + ((x ? mathy1(( + ( - y)), Math.max(x, x)) : -1/0) | 0))) | 0) >>> 0))); }); testMathyFunction(mathy4, /*MARR*/[ /x/g , this, false, false,  /x/g , false, {x:3}, {x:3}, false, this, {x:3}, this, false, {x:3},  /x/g , false,  /x/g , x, false]); ");
/*fuzzSeed-94431925*/count=322; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!\\2{0})/g; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=323; tryItOut("mathy0 = (function(x, y) { return (Math.min(Math.sin(Math.atan2(x, 0x07fffffff)), ( + Math.imul(( + y), ( + ( + Math.fround(Math.atan2(Math.fround(Math.min(Math.imul(y, x), -0x100000001)), ( ! y)))))))) << ([,,z1] = undefined)); }); testMathyFunction(mathy0, [-0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 0x080000000, 0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, -0x100000000, -1/0, -0, 1/0, -0x080000000, 1.7976931348623157e308, 1, -(2**53-2), Math.PI, 0.000000000000001, 2**53-2, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, 2**53, -0x080000001, 0x100000000]); ");
/*fuzzSeed-94431925*/count=324; tryItOut(";\n((function ([y]) { })());\n");
/*fuzzSeed-94431925*/count=325; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.imul((Math.fround(( + ( - (Math.fround(x) ^ Math.fround((Math.ceil(y) >>> 0)))))) >>> 0), Math.atanh(( ! Math.abs((( ~ y) | 0))))) | 0); }); testMathyFunction(mathy2, [2**53+2, -0x080000001, 1, -0x080000000, 2**53, 0x100000001, 0x100000000, Number.MIN_VALUE, -1/0, -(2**53), -0x07fffffff, 42, -0, -0x0ffffffff, Math.PI, 0x080000001, Number.MAX_VALUE, -(2**53-2), 0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 1/0, -Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, -(2**53+2), 0.000000000000001, 0/0, 0x07fffffff, 2**53-2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=326; tryItOut("print((4277));");
/*fuzzSeed-94431925*/count=327; tryItOut("\"use strict\"; ;");
/*fuzzSeed-94431925*/count=328; tryItOut("\"use strict\"; Object.prototype.watch.call(a1, \"__proto__\", (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((0x3f44cc61) / (0x5419c179)))|0;\n    i0 = ((((137438953473.0))));\n    return ((((0x7a65f4e9))))|0;\n  }\n  return f; }));");
/*fuzzSeed-94431925*/count=329; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    switch ((((0x46666152)-(i1)) >> ((0x3cabdaab)*0xb1fdb))) {\n      case -3:\n        i1 = ((Float64ArrayView[((i1)) >> 3]));\n        break;\n    }\n    return (((i1)+(i1)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=330; tryItOut("Object.defineProperty(this, \"v0\", { configurable: x, enumerable: this.throw(-Number.MIN_SAFE_INTEGER),  get: function() {  return g1.runOffThreadScript(); } });");
/*fuzzSeed-94431925*/count=331; tryItOut("M:if((4277)) Object.prototype.watch.call(v2, new String(\"3\"), (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { a5 = a1 % a9; var r0 = a6 ^ a8; var r1 = a5 + 4; r1 = a0 % a9; x = r0 / r0; var r2 = a10 | 3; var r3 = a7 + r0; var r4 = 5 * 6; a9 = a0 * a10; a1 = 6 & a5; var r5 = 3 - 1; var r6 = a4 / 4; var r7 = a0 + r1; var r8 = 5 * a3; var r9 = r6 | a3; var r10 = r7 / a6; var r11 = r7 | a6; print(r0); var r12 = r5 * 9; print(a2); var r13 = 0 * 3; print(r3); print(r11); var r14 = a5 & x; var r15 = a10 ^ r14; var r16 = a6 + 1; var r17 = r16 + a3; var r18 = 6 % r16; var r19 = a2 | x; var r20 = r5 * r9; var r21 = 6 / r10; r11 = 1 % r8; var r22 = 8 ^ r21; var r23 = a10 | r8; var r24 = r9 + r2; var r25 = 6 % 8; var r26 = r5 | 8; var r27 = r26 ^ r25; var r28 = r21 | 1; var r29 = 0 / r27; r24 = r3 ^ 9; r11 = 1 & r4; var r30 = r9 % 1; r13 = 5 * r11; print(r19); var r31 = r15 + r14; var r32 = a8 ^ r4; var r33 = r12 & r5; a10 = r14 % 7; a8 = r17 & a3; var r34 = r32 & r30; var r35 = 7 ^ r16; var r36 = r11 / r3; var r37 = r28 + r4; var r38 = 7 & r31; var r39 = 9 % r11; var r40 = r38 ^ a4; var r41 = 0 ^ a10; var r42 = 8 | r12; var r43 = r28 / r37; var r44 = 7 & r23; var r45 = r4 * r7; var r46 = r32 * 5; r24 = r31 / 4; r38 = 3 / 4; var r47 = 8 + r6; var r48 = r28 & 7; print(r19); var r49 = r25 ^ a4; var r50 = 8 ^ r32; var r51 = a1 | r27; var r52 = r21 / 9; var r53 = r24 % r47; var r54 = 9 & r28; print(r52); print(r37); var r55 = 2 | r4; var r56 = 8 % r34; r15 = 4 - r27; r12 = r33 * r16; var r57 = r27 - 5; r28 = 4 ^ a9; r16 = a10 - r15; var r58 = r39 | r33; var r59 = 9 ^ r25; var r60 = 1 % r55; r0 = 8 & r56; var r61 = 2 + a8; var r62 = 1 % r38; var r63 = 8 * r13; print(r49); r15 = 2 * 3; var r64 = 8 + r9; var r65 = r4 - r47; var r66 = 8 ^ 7; var r67 = r15 | x; var r68 = r37 * 3; var r69 = r63 / r0; var r70 = a0 - r36; var r71 = r57 - r33; var r72 = r22 | r58; print(r8); var r73 = a9 ^ 2; var r74 = 6 + r61; var r75 = 3 | 8; var r76 = 2 / r62; var r77 = r73 | 9; var r78 = r3 | r12; r76 = r42 + r70; var r79 = r4 + r22; var r80 = r16 + a10; var r81 = r73 * r73; var r82 = 9 + r66; var r83 = 2 % r21; var r84 = r23 | a0; r46 = r9 + r56; r52 = a6 ^ r18; var r85 = r77 ^ r33; var r86 = a0 - r64; var r87 = r19 + a1; var r88 = r10 / 3; var r89 = r71 ^ r65; x = r18 * r3; var r90 = r42 & 8; print(r16); var r91 = r3 ^ 3; var r92 = r82 % 4; var r93 = r35 | r15; r85 = 6 % x; var r94 = 4 | r55; var r95 = r11 | r6; var r96 = r19 % r38; var r97 = r77 % 5; r4 = r5 | 1; r83 = 1 / 2; var r98 = r27 / 7; var r99 = r48 - r48; var r100 = r85 * r47; var r101 = r95 % 7; var r102 = r99 % a4; r0 = r29 + r72; var r103 = r40 + r79; var r104 = r9 ^ 0; var r105 = a1 * 5; var r106 = r47 - r78; var r107 = a7 / 4; print(r32); var r108 = r31 ^ 8; r45 = r73 + r14; r3 = 5 % r5; var r109 = r89 & r82; var r110 = r108 ^ r47; var r111 = r101 ^ r21; var r112 = r5 - r85; a9 = 9 ^ r93; var r113 = 2 | r65; var r114 = r94 / 1; var r115 = r96 & r36; var r116 = 4 * r38; var r117 = 9 / 6; var r118 = r43 * r27; var r119 = 7 * r91; var r120 = 4 % 2; r92 = r108 ^ r69; var r121 = r26 | r109; var r122 = r88 + 3; var r123 = r55 * 5; var r124 = r15 * r66; var r125 = r14 % 8; var r126 = r118 + r82; var r127 = r59 * a1; var r128 = 1 * 4; a1 = r58 - 0; r10 = a0 & r89; var r129 = 6 | r42; r83 = a1 ^ r34; var r130 = r21 + 7; var r131 = r52 * 8; r57 = 4 - 2; var r132 = 2 - r33; var r133 = r61 | 9; var r134 = r15 - r43; var r135 = r72 * r91; var r136 = r40 - r56; var r137 = r99 & r31; var r138 = 0 & r79; var r139 = 3 ^ r72; var r140 = 8 / a8; var r141 = r84 ^ 2; r33 = r72 & r69; var r142 = r65 & 4; var r143 = 8 / r131; r11 = r69 - r4; var r144 = 6 - 0; var r145 = r23 / r113; var r146 = r102 ^ r70; r107 = r87 | 7; var r147 = r37 % r16; var r148 = r102 ^ 5; r90 = 2 + r88; var r149 = r123 - r56; var r150 = r18 % r107; a6 = 6 + 9; var r151 = r106 + 2; var r152 = a1 - r53; var r153 = r142 ^ r8; r2 = 5 * 8; var r154 = r147 * r140; r23 = r140 & r103; print(r42); var r155 = r35 | r9; var r156 = r109 % 3; r18 = r152 % r31; var r157 = 7 & r34; var r158 = 5 * 2; r157 = r42 & r140; var r159 = r32 & r104; var r160 = r73 % 0; var r161 = r39 + 9; var r162 = 6 ^ 0; var r163 = 9 / r127; var r164 = r30 - 4; r145 = r8 + r28; r21 = r80 * 1; print(r66); var r165 = 8 + r32; var r166 = r155 ^ r135; var r167 = 1 * r159; r59 = r101 + r26; var r168 = 4 * r157; var r169 = 3 & 3; r30 = a7 % 2; var r170 = r167 & 4; r62 = 1 / r131; var r171 = 3 * r92; var r172 = r2 - 9; var r173 = r147 + r89; r53 = r94 + 4; var r174 = r110 ^ 2; var r175 = r164 % r6; var r176 = r139 & r137; print(r33); r71 = r58 | r83; var r177 = r140 - r78; var r178 = 9 ^ 9; var r179 = r71 & r44; var r180 = r82 + 4; var r181 = r176 / r41; var r182 = r11 & r80; var r183 = 7 & 6; var r184 = r113 * r84; print(r22); var r185 = 6 & r63; r59 = r140 | 8; var r186 = r184 + r0; var r187 = r126 / r59; r42 = 5 * r134; var r188 = r151 ^ 0; var r189 = r148 * r45; var r190 = r59 - r25; var r191 = 1 % r130; r100 = 4 - a5; var r192 = r31 | 5; var r193 = 5 * r168; var r194 = 1 / r68; var r195 = r54 - 1; print(r182); r106 = r144 + 5; r17 = 0 * r177; var r196 = r93 - r178; var r197 = 9 + 8; r44 = r0 % 2; var r198 = 7 / r111; var r199 = r26 - 2; r56 = 6 ^ r5; var r200 = r33 + 0; var r201 = 6 | 3; var r202 = r185 / r27; var r203 = r139 * 9; var r204 = r184 % 0; r101 = 1 ^ r39; var r205 = 4 | r104; var r206 = r134 + r195; var r207 = r56 * r48; var r208 = 6 ^ 7; r21 = 4 & r162; r88 = r100 | 5; var r209 = r9 % r135; r148 = r198 & r152; var r210 = 3 ^ 4; print(r195); return a7; })); else  if (/\\s/ym) v2 = Object.prototype.isPrototypeOf.call(p2, g1);");
/*fuzzSeed-94431925*/count=332; tryItOut("for(var b in (((++x ^ (4277)))(((x)(false) && (x)(d, (new RegExp(\"[^]\", \"gy\") >> \"\\uE41A\")))))){m1[\"__parent__\"] = t2; }");
/*fuzzSeed-94431925*/count=333; tryItOut("var vwrbse = new SharedArrayBuffer(6); var vwrbse_0 = new Uint8Array(vwrbse); vwrbse_0[0] = 24; var vwrbse_1 = new Uint8Array(vwrbse); vwrbse_1[0] = window; g2.offThreadCompileScript(\"function f0(g2.g0.v2) \\\"use asm\\\";   var sqrt = stdlib.Math.sqrt;\\n  var pow = stdlib.Math.pow;\\n  var abs = stdlib.Math.abs;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    return +((+sqrt((((i1) ? (-140737488355328.0) : (d0))))));\\n    return +((8589934593.0));\\n    {\\n      d0 = (((Float64ArrayView[((((0x3f5dd610) % (0x3f12ab61))>>>((0xfa4a81cf))) % (0x6f91aaf6)) >> 3])) * ((+pow(((Float32ArrayView[(((-(0x1cb3e2c9))|0) % (abs((~((0xf919c12b))))|0)) >> 2])), ((Float32ArrayView[((x)+((0xb96a0d5) < (-0x8000000))+(i1)) >> 2]))))));\\n    }\\n    return +((+((1.5111572745182865e+23))));\\n  }\\n  return f;\", ({ global: g0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (vwrbse % 5 == 0), catchTermination: vwrbse_0[0] }));(4277);/*vLoop*/for (rmpfoj = 0, vwrbse_1[4]; rmpfoj < 0; ++rmpfoj) { var e = rmpfoj; a2.forEach(); }  \"\" ;\ni2.send(m0);\nt1[12];with({x: \"\\u5F9C\"}){s0 + ''; }");
/*fuzzSeed-94431925*/count=334; tryItOut("\"use strict\"; qvywfl();/*hhh*/function qvywfl(x, x){/*infloop*/for(x in 24) {yield  '' ; }}");
/*fuzzSeed-94431925*/count=335; tryItOut("/*tLoop*/for (let a of /*MARR*/[(-1/0), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), (-1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), (-1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(true), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), (-1/0), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), (-1/0), (-1/0), new Boolean(true), (-1/0), (-1/0), new Boolean(true), new Boolean(true), (-1/0), (-1/0), new Boolean(true), new Boolean(true), (-1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), (-1/0), new Boolean(true), (-1/0), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), (-1/0), (-1/0), new Boolean(true), new Boolean(true), (-1/0), (-1/0), (-1/0), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true), (-1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true)]) { L:if(false) {o2.a0.unshift(g1, a1); } else {print(({}));window; } }");
/*fuzzSeed-94431925*/count=336; tryItOut("\"use strict\"; const c = (let (w) \"\\u23E7\");if(false) {e2 + ''; } else  if (Math.hypot(\"\\u32FD\", -0.592)) selectforgc(o0);");
/*fuzzSeed-94431925*/count=337; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a1, 1, ({configurable: (uneval((4277)))}));");
/*fuzzSeed-94431925*/count=338; tryItOut("/*vLoop*/for (var bexwrh = 0; bexwrh < 73; ++bexwrh) { var y = bexwrh; {} } ");
/*fuzzSeed-94431925*/count=339; tryItOut("/*infloop*/for(var  /x/g .window in this) {/*MXX2*/g0.Array.from = p2; }");
/*fuzzSeed-94431925*/count=340; tryItOut("p0 + o0.g1;");
/*fuzzSeed-94431925*/count=341; tryItOut("print(uneval(h1));");
/*fuzzSeed-94431925*/count=342; tryItOut("\"use strict\"; a1.reverse(s2, o2.h1, ((function factorial_tail(fjupoq, ykglxm) { ; if (fjupoq == 0) { g0 + g1;; return ykglxm; } g0.o1.a0.reverse(s1, v0);o0.m2.set(t2, p1);; return factorial_tail(fjupoq - 1, ykglxm * fjupoq);  })(2, 1)), g1, a0);");
/*fuzzSeed-94431925*/count=343; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.abs(( + ( + (( ! Math.abs(( + ( ~ x)))) >>> 0))))); }); ");
/*fuzzSeed-94431925*/count=344; tryItOut("/*RXUB*/var r = /(?!(?=(?!(?!\\u003E)|\\b*?))){3,}|(?:(?:\\2{2,2}))*?/im; var s =  '' ; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=345; tryItOut("let (e) { Array.prototype.unshift.call(a0, (makeFinalizeObserver('tenured')), e0); }");
/*fuzzSeed-94431925*/count=346; tryItOut("\"use asm\"; /*iii*/g0.m1 + '';/*hhh*/function pbmwve(){this.t0[15] = (((void version(185)))());}");
/*fuzzSeed-94431925*/count=347; tryItOut("Array.prototype.unshift.apply(a1, [f2]);");
/*fuzzSeed-94431925*/count=348; tryItOut("var  /x/g .__proto__ = ((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })).call(/*UUV2*/(x.min = x.call), null, Int32Array()) ? --WeakSet.prototype.delete : x, z = x, e = new (Object.entries)(x)(x), x = /*FARR*/[(4277), ( \"\"  %= true), ...(makeFinalizeObserver('tenured')) for (this.zzz.zzz of ({/*TOODEEP*/})) for (this.eval of /(?=$)[\u5c8b-\u6d90\\D]+/yim), , , (arguments.callee.arguments)].map((function(x, y) { return (( ! (x >>> 0)) >>> 0); }), (void options('strict'))), euuohi, {y: a, x: c} = NaN = x, z = (x = Proxy.createFunction(({/*TOODEEP*/})(undefined), Function)), NaN = this.__defineSetter__(\"x\", neuter), window;t0 = new Float64Array(11);const b = ((new (length)((uneval(undefined)))) ? (\u0009/*FARR*/[...[], ,  \"\" , this, [,,], , undefined].map) : (Math.max(null, e) ==  /x/ ));");
/*fuzzSeed-94431925*/count=349; tryItOut("g2.t2[( /x/  ** /(\\d)\\u0091|\\b{4,5}/im <= window)];");
/*fuzzSeed-94431925*/count=350; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[new String('q'), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), [1], arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), e =  \"\" , [1], e =  \"\" , [1], e =  \"\" , e =  \"\" , new String('q'), Infinity, new String('q'), new String('q'), new String('q'), new String('q'), e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), Infinity, arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), Infinity, [1], [1], e =  \"\" , new String('q'), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), new String('q'), e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), new String('q'), new String('q'), Infinity, arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), new String('q'), Infinity, new String('q'), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), e =  \"\" , [1], new String('q'), e =  \"\" , e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), new String('q'), Infinity, new String('q'), [1], [1], e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), Infinity, [1], arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), Infinity, [1], e =  \"\" , new String('q'), [1], e =  \"\" , Infinity, e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), [1], arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), e =  \"\" , [1], arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), arguments[\"valueOf\"] = eval(\"this\", ({a1:1})), Infinity, e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , e =  \"\" , arguments[\"valueOf\"] = eval(\"this\", ({a1:1}))]) { v0 = g0.eval(\"v2 = evaluate(\\\"function f2(t0) \\\\\\\"use asm\\\\\\\";   var Float32ArrayView = new stdlib.Float32Array(heap);\\\\n  function f(d0, d1)\\\\n  {\\\\n    d0 = +d0;\\\\n    d1 = +d1;\\\\n    var d2 = -576460752303423500.0;\\\\n    var d3 = 0.0078125;\\\\n    d1 = (d2);\\\\n    return +((Float32ArrayView[0]));\\\\n  }\\\\n  return f;\\\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: (e % 4 == 3) }));\"); }");
/*fuzzSeed-94431925*/count=351; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-94431925*/count=352; tryItOut("if(x) {f1 + b1; }");
/*fuzzSeed-94431925*/count=353; tryItOut("/*infloop*/for(a = x; (({x: (arguments)})); yield eval(\"\\\"use asm\\\"; Object.prototype.unwatch.call(g1.a0, new String(\\\"10\\\"));\")) Array.prototype.reverse.call(a1, p1);/\\3/yi");
/*fuzzSeed-94431925*/count=354; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.cos(Math.fround(Math.hypot((Math.fround(x) * mathy0(((( + Math.fround(Math.sin(Math.fround(Number.MIN_VALUE)))) >>> y) >>> 0), (( - y) | 0))), (( ~ Math.fround(Math.fround((Math.min(Math.atan2(x, ( + y)), y) ? y : x)))) | 0)))); }); testMathyFunction(mathy1, [-0x07fffffff, 2**53-2, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 1/0, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, 0x0ffffffff, -0x0ffffffff, -(2**53+2), 0x07fffffff, 0x080000000, -(2**53), 0.000000000000001, 2**53, -0x100000001, -0x080000000, 0x080000001, -Number.MAX_VALUE, 0/0, 1, 0x100000001, -0, 1.7976931348623157e308, -0x080000001]); ");
/*fuzzSeed-94431925*/count=355; tryItOut("\"use strict\"; with({}) x = x;x.constructor;");
/*fuzzSeed-94431925*/count=356; tryItOut("a1 + this.e0;");
/*fuzzSeed-94431925*/count=357; tryItOut("Array.prototype.splice.call(a2, -17, 2, a1);");
/*fuzzSeed-94431925*/count=358; tryItOut("delete h0.hasOwn;\nprint(null);\n");
/*fuzzSeed-94431925*/count=359; tryItOut("\"use strict\"; for (var v of f2) { try { a2.reverse(); } catch(e0) { } s1 + g0.p2; }");
/*fuzzSeed-94431925*/count=360; tryItOut("\"use strict\"; o2.a2.forEach(f1);");
/*fuzzSeed-94431925*/count=361; tryItOut("with({e: ({x: ([1].setMinutes())})}){{ void 0; selectforgc(this); } \"use strict\"; print(e);o0 + ''; }");
/*fuzzSeed-94431925*/count=362; tryItOut("/*infloop*/for(WeakSet.prototype in x) {/*ADP-2*/Object.defineProperty(o1.a2, v2, { configurable: true, enumerable: (x % 5 != 3), get: (function() { try { e2.add(h0); } catch(e0) { } try { Object.prototype.watch.call(v0, \"toGMTString\", (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { a5 = a1 - 9; a8 = a8 ^ 0; var r0 = a2 * x; var r1 = x / 8; var r2 = 9 % 2; var r3 = 8 ^ a0; a0 = a10 ^ 1; var r4 = a8 % r2; var r5 = 1 / a5; var r6 = 5 ^ a2; a1 = a2 + a4; var r7 = r4 - 2; var r8 = 8 ^ a1; var r9 = r2 - a8; var r10 = 5 * r3; var r11 = 0 ^ 6; var r12 = 4 / a9; return a9; })); } catch(e1) { } try { g2 + g1.o1.t2; } catch(e2) { } a2.splice(NaN, 18); return p2; }), set: (function mcc_() { var wmksve = 0; return function() { ++wmksve; f2(/*ICCD*/wmksve % 3 == 2);};})() });/*vLoop*/for (let pnavfy = 0; pnavfy < 35; ++pnavfy) { e = pnavfy; /*RXUB*/var r = r2; var s = s1; print(uneval(r.exec(s)));  }  }");
/*fuzzSeed-94431925*/count=363; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return ((((((0x722636cd)+((abs((((0x2350bce7)) & ((0x9987c34c))))|0) == (((0xfe809170)) ^ ((0xfc15eda1))))-(/*FFI*/ff(((((0x6cbf322b) % (0x48304036)) & ((0x9daecbda)-(0x7ed1b9cc)-(0xfe7331c3)))), ((+(((0xa9b92999))>>>((0x15b55535))))), ((((0xffffffff)) ^ ((0x6c546ee2)))), ((3.777893186295716e+22)), ((4503599627370495.0)), ((2251799813685248.0)), ((-0.0625)))|0)) >> ((0xffe779e1))))+((i2) ? ( \"\" ) : ((((((0x63644901)) & ((0x773df2fb))) / (imul((0x203f04bd), (0x62da3a4a))|0)) & ((-0x8000000)))))))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[-Infinity, Infinity, [], [], (void 0), Infinity, 2**53+2, Infinity, Infinity, 2**53+2, [], 2**53+2, 2**53+2, Infinity, -Infinity, Infinity, Infinity, Infinity, [], [], 2**53+2, -Infinity, 2**53+2, 2**53+2, (void 0), [], Infinity, [], 2**53+2, -Infinity, Infinity, Infinity, 2**53+2, -Infinity, 2**53+2, [], (void 0), [], 2**53+2, (void 0), (void 0), -Infinity, [], -Infinity, (void 0), Infinity, 2**53+2, (void 0), -Infinity, Infinity, [], Infinity, (void 0), 2**53+2, [], Infinity, Infinity, -Infinity, (void 0), 2**53+2, [], [], [], [], [], [], Infinity, Infinity, Infinity, 2**53+2, [], [], Infinity, -Infinity, -Infinity, -Infinity, 2**53+2, -Infinity, -Infinity, -Infinity, 2**53+2, 2**53+2, -Infinity, (void 0), -Infinity, Infinity, [], Infinity, [], []]); ");
/*fuzzSeed-94431925*/count=364; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.asinh(( ~ ( + x))); }); testMathyFunction(mathy0, ['', ({valueOf:function(){return '0';}}), (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(true)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), false, null, /0/, [0], 0.1, (function(){return 0;}), '\\0', [], -0, true, (new Number(0)), '/0/', (new Boolean(false)), 0, 1, '0', undefined, NaN, (new String(''))]); ");
/*fuzzSeed-94431925*/count=365; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:((?=(?:^))))\", \"gym\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=366; tryItOut("for (var v of s1) { try { a2.sort((function() { try { for (var v of t2) { try { s1.__proto__ = f0; } catch(e0) { } try { delete p2[\"toString\"]; } catch(e1) { } try { /*ODP-2*/Object.defineProperty(i0, \"__defineSetter__\", { configurable: true, enumerable: (x % 6 == 3), get: (function(j) { if (j) { o1.m0.set(h0, v1); } else { try { o1.a0 = a2.slice(NaN, NaN, h2); } catch(e0) { } try { i1 + b0; } catch(e1) { } try { a2[8]; } catch(e2) { } Array.prototype.shift.apply(o0.a2, [g2.s0]); } }), set: f2 }); } catch(e2) { } g0.e0.has(s0); } } catch(e0) { } try { f1(o0.f1); } catch(e1) { } try { v2 = g0.runOffThreadScript(); } catch(e2) { } for (var p in this.g2.i2) { try { Array.prototype.reverse.call(a1, this.v0, x); } catch(e0) { } t2[16] = g0.t0; } return v1; }), o1.a0, i1, a2); } catch(e0) { } v1 = a1.length; }");
/*fuzzSeed-94431925*/count=367; tryItOut("\"use strict\"; /(\\w+?|.)?\\1/gim;const c = (4277);function x(x, b)\"use asm\";   var imul = stdlib.Math.imul;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((0xfe27118f)+(0xffffffff)+(i1)))|0;\n    i1 = (i1);\n    i1 = (i1);\n    i1 = ((36028797018963970.0) <= (+((+((0x58aba*(i1)) << (true))))));\n    d0 = (d0);\n    i1 = (0xe4dc9432);\n    i1 = (!(i1));\n    i1 = ((0x696c975b));\n    i1 = (i1);\n    return ((((0xf7a68*((9.44473296573929e+21) > (+(0xfa8caeb5))))>>>(((imul((1), (!(i1)))|0)))) % (((i1)-(0xb12b82f3))>>>(((undefined -=  /x/ ))+(0x4866b78f)))))|0;\n  }\n  return f;v0 = a1.length;");
/*fuzzSeed-94431925*/count=368; tryItOut("\"use asm\"; /*oLoop*/for (var qtyinf = 0; qtyinf < 6; ++qtyinf) { s1 + o2.i2; } ");
/*fuzzSeed-94431925*/count=369; tryItOut("for(let y in /*FARR*/[\"\\uFF68\"]) 22;");
/*fuzzSeed-94431925*/count=370; tryItOut("v0 = (s1 instanceof h0);");
/*fuzzSeed-94431925*/count=371; tryItOut("/*vLoop*/for (var vlqenc = 0, 'fafafa'.replace(/a/g, \"\\u3632\"); vlqenc < 77; ++vlqenc) { const e = vlqenc; ; } ");
/*fuzzSeed-94431925*/count=372; tryItOut("\"use strict\"; v1 = a1.reduce, reduceRight((function() { for (var j=0;j<19;++j) { f1(j%3==0); } }), i2);");
/*fuzzSeed-94431925*/count=373; tryItOut("testMathyFunction(mathy3, [null, (new Boolean(false)), '/0/', (new Number(-0)), 0.1, ({valueOf:function(){return 0;}}), NaN, false, ({valueOf:function(){return '0';}}), true, [], -0, undefined, [0], 1, objectEmulatingUndefined(), (new Number(0)), '0', ({toString:function(){return '0';}}), '', (new String('')), /0/, (function(){return 0;}), (new Boolean(true)), '\\0', 0]); ");
/*fuzzSeed-94431925*/count=374; tryItOut("\"use strict\"; t0.set(a1, ((function sum_slicing(zpkesl) { ; return zpkesl.length == 0 ? 0 : zpkesl[0] + sum_slicing(zpkesl.slice(1)); })(/*MARR*/[0, 0, 1e81, 1e81, 0, 0, 1e81, 1e81, -(2**53+2), 1e81, 0, 0, 1e81, 0, 0, 1e81, 1e81, new String(''), 1e81, new String(''), new String(''), function(){}, 1e81, -(2**53+2), new String(''), 1e81, 0])));");
/*fuzzSeed-94431925*/count=375; tryItOut("m2.set(f2, m1);\ne2.add(g1);\n\nprint([]);var a = [1];\n");
/*fuzzSeed-94431925*/count=376; tryItOut("\"use strict\"; e1 = new Set(i0);");
/*fuzzSeed-94431925*/count=377; tryItOut("for (var v of a2) { try { v0 = a1.length; } catch(e0) { } t2.set(t2, x = Proxy.createFunction(({/*TOODEEP*/})(/[\\W]/), Date.prototype.toLocaleString, q => q) & x); }");
/*fuzzSeed-94431925*/count=378; tryItOut("Array.prototype.push.call(a0, t0, s1, m0, o0, f1, v2, p0);var w = ();");
/*fuzzSeed-94431925*/count=379; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan2((( ~ Math.max(Math.hypot(( + (y ? ( + ( + Math.atan2(( + y), ( + Math.sign(( + x)))))) : Math.fround((Math.fround(x) - ( + y))))), (((Math.min(y, x) | 0) | (y >= Math.hypot(( + x), x))) | 0)), ( + Math.cosh(Math.exp(-0x07fffffff))))) | 0), ((Math.hypot(Math.max(y, x), y) >>> x) ? Math.cbrt((((y >>> 0) ? (x >>> 0) : (Math.fround((( - y) , Math.fround(Math.fround(Math.imul(Math.fround(y), Math.fround(-(2**53))))))) >>> 0)) >>> 0)) : Math.pow(Math.fround(( + ( + ( - y)))), (Math.atan2((( - Number.MIN_VALUE) >>> 0), ((( + -(2**53-2)) >= x) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [0.000000000000001, 0x080000001, -0x100000001, 0x100000000, 1, -(2**53-2), Number.MIN_VALUE, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x100000000, 0x080000000, 0x100000001, -0x0ffffffff, 0, -1/0, 0x07fffffff, -(2**53), Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -0x080000000, 1/0, 1.7976931348623157e308, -0x07fffffff, 0/0, 42, -0, Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-94431925*/count=380; tryItOut("return ({x: (w =  '' ),  get x x ()\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float64ArrayView[2]) = ((+((-0x95afe*(x)) >> ((0x5544f497)))));\n    i1 = (i1);\n    d0 = (d0);\n    switch (((((0x927bd67) >= (0x1b832e80))) & ((1)))) {\n      case -2:\n        i1 = (0xe0a62e8b);\n        break;\n      default:\n        {\n          (Float32ArrayView[((0xe080752b)+((i1) ? (0xfb4609ec) : (0xc7b7a5b4))) >> 2]) = ((-2097151.0));\n        }\n    }\n    i1 = (0xa675edcb);\n    d0 = (+atan2(((+(((0xe18c9c39))|0))), ((d0))));\n    (Float64ArrayView[((-0x29a847a)) >> 3]) = ((268435457.0));\n    {\n      d0 = (-72057594037927940.0);\n    }\n    d0 = (d0);\n    return (((i1)+(i1)+(0xb6aaf6b1)))|0;\n    switch ((abs((~~(((-16777216.0)) / ((-262145.0)))))|0)) {\n    }\n    {\n      {\n        (Float32ArrayView[4096]) = ((((295147905179352830000.0)) * ((d0))));\n      }\n    }\n    return (((i1)))|0;\n  }\n  return f; });\no2.v0 = Object.prototype.isPrototypeOf.call(g2, i1);\n");
/*fuzzSeed-94431925*/count=381; tryItOut("\"use strict\"; o1.v1 = r1.constructor;");
/*fuzzSeed-94431925*/count=382; tryItOut("/*infloop*/do {v1.toSource = (function() { try { a1.sort(a0); } catch(e0) { } h1 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.shift.call(a1, o0.p0);; var desc = Object.getOwnPropertyDescriptor(g1.i0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { throw t1; var desc = Object.getPropertyDescriptor(g1.i0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { h2.fix = f2;; Object.defineProperty(g1.i0, name, desc); }, getOwnPropertyNames: function() { v0 = r2.constructor;; return Object.getOwnPropertyNames(g1.i0); }, delete: function(name) { v2 = t1.length;; return delete g1.i0[name]; }, fix: function() { const g2.a2 = a2.filter(f0, o1);; if (Object.isFrozen(g1.i0)) { return Object.getOwnProperties(g1.i0); } }, has: function(name) { this.e0.add(f2);; return name in g1.i0; }, hasOwn: function(name) { this.f0.toString = (function() { for (var j=0;j<10;++j) { f0(j%5==1); } });; return Object.prototype.hasOwnProperty.call(g1.i0, name); }, get: function(receiver, name) { /*MXX1*/o0 = o2.g0.RegExp.prototype.global;; return g1.i0[name]; }, set: function(receiver, name, val) { g1.i0 + '';; g1.i0[name] = val; return true; }, iterate: function() { v0 = a1.length;; return (function() { for (var name in g1.i0) { yield name; } })(); }, enumerate: function() { g2.e1.has(o2);; var result = []; for (var name in g1.i0) { result.push(name); }; return result; }, keys: function() { Object.prototype.watch.call(this.g2, \"padEnd\", f2);; return Object.keys(g1.i0); } }); return p1; });yield undefined; } while( '' .throw(true));");
/*fuzzSeed-94431925*/count=383; tryItOut("\"use strict\"; a2.sort((function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.2089258196146292e+24;\n    {\n      d0 = (+(((0xfd7b375b)+(((((uneval(x)))) != (imul((0x5d33dba4), (0x3cb591bb))|0)) ? (0xa98a9cb6) : (0xfcbfe908)))>>>((0xaa55ab69))));\n    }\n    switch (((-(0xffffffff)) & ((/*FFI*/ff(((d1)))|0)))) {\n      case 0:\n        d0 = (d1);\n        break;\n      case -1:\n        d0 = (d2);\n        break;\n      case -2:\n        {\n          {\n            d0 = (d2);\n          }\n        }\n        break;\n      default:\n        {\n          d1 = (d1);\n        }\n    }\n    d2 = (d2);\n    return (((0x2c479ea)-(0x553b98b5)))|0;\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var tuyevl = -2 << null; var eswnpi = tuyevl; return eswnpi;})()}, new ArrayBuffer(4096)), b2, f2);");
/*fuzzSeed-94431925*/count=384; tryItOut("testMathyFunction(mathy1, [0x100000000, -0x100000001, 0x07fffffff, -0x080000000, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x080000000, Number.MAX_VALUE, 0/0, 0.000000000000001, 0x080000001, -0, -0x07fffffff, -(2**53+2), 2**53-2, -0x0ffffffff, 1.7976931348623157e308, 1/0, -0x080000001, 2**53, 0, -Number.MAX_VALUE, Math.PI, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, 42, -1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-94431925*/count=385; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ((( + Math.max(( + Math.expm1(( + Math.round(1)))), ( + Math.cbrt(Math.fround(-0x07fffffff))))) | 0) ** (Math.fround(Math.trunc(Math.fround((Math.pow((Math.atan2(( - y), ( + y)) >>> 0), (( + (( + Math.min((Math.max(0x0ffffffff, ( + (mathy0(y, x) >>> 0))) >>> 0), (y | 0))) !== ( + (Math.min(Math.fround(y), Math.fround(1/0)) | 0)))) | 0)) | 0)))) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[(-1/0), -(2**53+2), -Infinity, -(2**53+2), (-1/0), (-1/0), -Infinity, -(2**53+2), -Infinity, -(2**53+2), (-1/0), -Infinity, -(2**53+2), -Infinity, -Infinity, -Infinity, -(2**53+2), (-1/0), -(2**53+2), -Infinity, -(2**53+2), -(2**53+2), -Infinity, (-1/0), -Infinity, (-1/0), (-1/0), (-1/0), -Infinity, (-1/0), -Infinity, -Infinity, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), -Infinity, -Infinity, -Infinity, -(2**53+2), -Infinity, -Infinity, (-1/0), (-1/0), -Infinity, -(2**53+2), (-1/0), -Infinity, -(2**53+2), (-1/0), (-1/0), -Infinity, -Infinity, (-1/0), -Infinity, -Infinity, -Infinity, -(2**53+2), -(2**53+2), -Infinity, (-1/0), -Infinity, -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), (-1/0), -Infinity, -Infinity, (-1/0), -Infinity, (-1/0), -Infinity, -Infinity, -(2**53+2), (-1/0), -Infinity, -Infinity, -Infinity, -(2**53+2), (-1/0), -(2**53+2), -Infinity, -(2**53+2), (-1/0), -(2**53+2), -(2**53+2), -(2**53+2), (-1/0), -(2**53+2), (-1/0), -(2**53+2), -(2**53+2), (-1/0), -Infinity, -Infinity, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), -Infinity, -Infinity, -(2**53+2)]); ");
/*fuzzSeed-94431925*/count=386; tryItOut("m1.toString = Function;var w = window ^= ({x: \"\\u48BE\"});");
/*fuzzSeed-94431925*/count=387; tryItOut("\"use strict\"; Array.prototype.shift.call(a2, f2, g2, o1.v1, h1);function shapeyConstructor(trahrk){\"use strict\"; this[\"entries\"] = x;if (trahrk) { var zpdglj = new ArrayBuffer(0); var zpdglj_0 = new Int32Array(zpdglj); var zpdglj_1 = new Uint8Array(zpdglj); zpdglj_1[0] = 24; s0 += s2;print(zpdglj_0);(\"\\uFDF4\");undefined;o2 = {}; } delete this[\"tanh\"];Object.defineProperty(this, \"0\", ({enumerable: (trahrk % 26 == 8)}));{ b1 = o0.t0.buffer; } this[\"tanh\"] = trahrk;this[\"entries\"] = true;return this; }/*tLoopC*/for (let d of /*MARR*/[null, ({x:3}), ({x:3}), null, ({x:3}), null, ({x:3}), null, ({x:3}), null, null, null, null, null, null, null, null, null, ({x:3})]) { try{let pcjdqr = new shapeyConstructor(d); print('EETT'); v0 = a2.reduce, reduceRight((function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d0 = (d1);\n    }\n    return (((0xd2f0fa65)-((abs((~~(d0)))|0))-(0xf9a191cd)))|0;\n  }\n  return f; }), b0);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-94431925*/count=388; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=389; tryItOut("/*MXX1*/o2 = g0.String.prototype.big;\nM:if(x) { if (void [,,z1]) this.m2.delete(a1);} else {\"\\u2BA8\";print([[1]]); }\n\na2 = c = false for (x of (p={}, (p.z = c)()));\n");
/*fuzzSeed-94431925*/count=390; tryItOut("p2.toString = (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xd55fb13d);\n    return +((((-4097.0) >= (9.0)) ? (d0) : (d0)));\n    {\n      d0 = (-9223372036854776000.0);\n    }\n    i1 = (i1);\n    return +(yield Set(undefined));\n  }\n  return f; });");
/*fuzzSeed-94431925*/count=391; tryItOut("f1 = this.t0[v1]");
/*fuzzSeed-94431925*/count=392; tryItOut("g1.a0.forEach((function() { try { v1 = g1.runOffThreadScript(); } catch(e0) { } try { h1.fix = (function(j) { if (j) { try { s2 += 'x'; } catch(e0) { } try { (void schedulegc(g1)); } catch(e1) { } this.v1 = g0.runOffThreadScript(); } else { try { s2 += 'x'; } catch(e0) { } o1.t0[this.v1]; } }); } catch(e1) { } try { Array.prototype.forEach.apply(a1, [f0]); } catch(e2) { } o0.m2 = new WeakMap; return m2; }), s2, [,,]);function c(e, ...z)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((((~(((0xf9b1bb82) ? (i1) : (0x5865291))-(1))) == (0x5f504e15))+(i1)))|0;\n  }\n  return f;Object.defineProperty(this, \"t2\", { configurable: (x % 14 != 5), enumerable: false, ({a1:1}),  get: function() {  return new Uint8Array(b1, 64, 16); } });\n/*RXUB*/var r = new RegExp(\"(?:(?!(?!\\\\cA{2,}|(?![^])(?!(?!^))|\\\\1{4,})))\", \"yi\"); var s = \"\\nda\\nda\\nda\"; print(s.search(r)); \n");
/*fuzzSeed-94431925*/count=393; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    (Float64ArrayView[((Array.prototype.copyWithin)-(i3)-((0x423fe031))) >> 3]) = ((+(-1.0/0.0)));\n    i2 = (i3);\n    d1 = (((2049.0)) / ((d1)));\n    i2 = (0x936bbfef);\n    return +((d0));\n  }\n  return f; })(this, {ff: (z, window, window = (4277), x = null, x, eval, b, x, d, e, x, this, e, delete, x, NaN, x = window, y, b, y, e, y, b, x, eval, d, c, a = -11, x, \u3056, x =  /x/g , c, c, x, b, x, x, x, z = ({a1:1}), x, x, x, b, x = c, NaN, set = true, y, a, b, x, w = length, e, eval, let, NaN, x, x =  /x/ , w = new RegExp(\"((?:\\\\B{2,2}|(?:\\\\1)))\", \"gi\"), e, w, 24, \u3056, yield, x, b, \u3056, window, window, x, x = a, x = null, x, x) =>  {  /x/g  *=  '' ; } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, -0x0ffffffff, 0/0, 0x100000001, 0x080000000, -0x100000000, 0x080000001, 2**53-2, 0x100000000, 2**53+2, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 42, -1/0, -0x080000000, 1/0, -(2**53), 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, -(2**53-2), 2**53, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=394; tryItOut("switch((x >>> c)) { case delete eval.x: continue L;break; break;  }");
/*fuzzSeed-94431925*/count=395; tryItOut("mathy5 = (function(x, y) { return Math.sign((Math.log1p((Math.max(y, Math.log1p(-0x100000001)) < (((( - x) >>> 0) * Math.fround(x)) >> x))) >>> 0)); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 42, 0x0ffffffff, 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, 0, 1, -0x080000001, -Number.MIN_VALUE, -(2**53), -0x100000000, 2**53+2, -1/0, -0x100000001, 1.7976931348623157e308, -(2**53-2), Number.MAX_SAFE_INTEGER, -0, 0x100000000, 0x100000001, -Number.MAX_VALUE, Math.PI, 0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, 1/0, -0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-94431925*/count=396; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.hypot(((( - (( ~ x) >>> 0)) >>> 0) >>> 0), ((mathy0((y >>> 0), (( - (Math.fround(Math.imul(Math.fround(x), (y >>> 0))) ? Math.fround(Math.hypot((((-0x0ffffffff >= y) | 0) | 0), x)) : 0x07fffffff)) >>> 0)) >>> 0) >>> 0)) >>> 0) ^ Math.max((( + ( ~ ( + y))) | 0), ( + Math.fround(Math.max(( + mathy1(x, Math.hypot(Math.fround(y), (Math.log2((Math.fround(Math.asinh(Math.fround(-(2**53-2)))) | 0)) | 0)))), (Math.fround(Math.min(((mathy1((y | 0), (x | 0)) >>> 0) | 0), x)) | 0)))))); }); testMathyFunction(mathy2, [-(2**53), 1/0, -Number.MIN_VALUE, 1, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, -0x080000000, -Number.MAX_SAFE_INTEGER, -0, -1/0, 2**53-2, -0x100000000, 0x080000000, -0x100000001, 42, 0x080000001, 0x100000000, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 2**53, 0.000000000000001, 2**53+2, -0x07fffffff, Math.PI, 0x0ffffffff, 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-94431925*/count=397; tryItOut("/*RXUB*/var r = new RegExp(\"((?!(?!$|\\\\x17^*?)?)*?(?:(..+|.|\\\\S{1,1}?)))\", \"gim\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=398; tryItOut("mathy0 = (function(x, y) { return (( ~ ((((y , (Math.trunc(x) == ((x >>> 0) ? y : 0x100000000))) | 0) ? ( + Math.imul(x, x)) : (x ? (( - Math.sin(Math.fround(Math.log1p((( ! (y | 0)) | 0))))) | 0) : Math.imul(( + Math.pow((( ~ (x >>> 0)) | 0), x)), -0x080000001))) | 0)) | 0); }); testMathyFunction(mathy0, [-(2**53), -(2**53-2), Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, -0, -Number.MAX_VALUE, 0x100000001, 0x080000000, -0x07fffffff, -1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, -0x100000001, 42, -0x080000000, 0x0ffffffff, 0x080000001, -Number.MIN_VALUE, -0x100000000, 2**53, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 2**53+2, 0x100000000, 2**53-2, 1, -0x080000001]); ");
/*fuzzSeed-94431925*/count=399; tryItOut("b2 = new SharedArrayBuffer(15);");
/*fuzzSeed-94431925*/count=400; tryItOut("testMathyFunction(mathy3, [(new Boolean(false)), objectEmulatingUndefined(), (new Number(0)), '\\0', (new String('')), (function(){return 0;}), false, ({valueOf:function(){return 0;}}), /0/, -0, 0.1, null, NaN, true, '0', ({valueOf:function(){return '0';}}), (new Boolean(true)), 1, '', [0], (new Number(-0)), '/0/', 0, ({toString:function(){return '0';}}), [], undefined]); ");
/*fuzzSeed-94431925*/count=401; tryItOut("\"use asm\"; ( ''  !== this);");
/*fuzzSeed-94431925*/count=402; tryItOut("for (var p in e2) { try { i2.send(f2); } catch(e0) { } try { Array.prototype.splice.apply(a1, [NaN, 13, g2.g0.g0]); } catch(e1) { } try { a1.splice(); } catch(e2) { } v1 = (e1 instanceof h1); }");
/*fuzzSeed-94431925*/count=403; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.cosh((( ! (Math.log1p((Math.fround(Math.trunc(Math.fround(y))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 2**53, -0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, Math.PI, 1/0, -0x07fffffff, 0/0, -1/0, 0x080000000, -0x080000000, 1, -0, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, 0x080000001, 0, 1.7976931348623157e308, 0x07fffffff, 2**53+2, 2**53-2, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-94431925*/count=404; tryItOut("a2.shift((4277), o1, h2, f1);");
/*fuzzSeed-94431925*/count=405; tryItOut("\"use strict\"; t1[v0] = new ((4277))();");
/*fuzzSeed-94431925*/count=406; tryItOut("m0.get(s2);");
/*fuzzSeed-94431925*/count=407; tryItOut("mathy1 = (function(x, y) { return (Math.clz32((Math.ceil(( + ( ~ ( + (y != -Number.MAX_SAFE_INTEGER))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [2**53-2, 42, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, -0, -(2**53), 0x080000000, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, -0x100000001, -(2**53-2), Number.MIN_VALUE, Number.MAX_VALUE, 1/0, 0x100000001, 0, -0x07fffffff, -Number.MIN_VALUE, -1/0, 2**53, -0x100000000, 0x07fffffff, 0x100000000, -0x0ffffffff, 1.7976931348623157e308, -0x080000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000]); ");
/*fuzzSeed-94431925*/count=408; tryItOut("\"use strict\"; const v1 = a2.reduce, reduceRight();");
/*fuzzSeed-94431925*/count=409; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(v2, a2);");
/*fuzzSeed-94431925*/count=410; tryItOut("/*vLoop*/for (let xsgpye = 0; xsgpye < 76; ++xsgpye) { var d = xsgpye; b2 = t1.buffer; } ");
/*fuzzSeed-94431925*/count=411; tryItOut("\"use strict\"; let epwxzt; /x/ ;");
/*fuzzSeed-94431925*/count=412; tryItOut("\"use strict\"; const o0.h2 = {};");
/*fuzzSeed-94431925*/count=413; tryItOut("\"use strict\"; \"use asm\"; this.v1 = g1.g2.runOffThreadScript();");
/*fuzzSeed-94431925*/count=414; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + ( ~ (( ! (Math.max(y, (Math.round((0x080000001 >>> 0)) >>> 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-94431925*/count=415; tryItOut("\"use strict\"; Array.prototype.splice.call(a2, NaN, 0, this.s0);");
/*fuzzSeed-94431925*/count=416; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.cosh(Math.sign((( - (Math.fround(Math.max(Math.fround((Math.atanh((Math.hypot((y | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0)) | Math.min(x, Math.fround(x)))), Math.fround((x <= x)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [-0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), 2**53+2, 2**53-2, 1/0, 0/0, 42, -0x080000000, -1/0, -0x100000001, Number.MIN_VALUE, 0x100000001, 0x080000000, 1, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -0x080000001, Math.PI, -0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 2**53, -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -0x100000000, 0.000000000000001, 0x100000000, 0x080000001, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=417; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - ( + ( - ((Math.atan2(Math.log2(y), Math.fround(mathy1(x, Math.fround(0/0)))) > ( + ( + Math.fround(x)))) >= y)))); }); testMathyFunction(mathy2, [0x080000001, 1, -0x0ffffffff, -0x100000000, 0/0, 42, 1/0, -0x07fffffff, 0x080000000, -1/0, 0, -(2**53), 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -(2**53-2), -(2**53+2), 2**53+2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 0.000000000000001, -0x100000001, Number.MIN_VALUE, -0x080000001, -0, 0x100000001]); ");
/*fuzzSeed-94431925*/count=418; tryItOut("mathy2 = (function(x, y) { return (Math.sign(((((Math.atanh(((Math.max((Math.sinh(x) | 0), (y | 0)) | 0) | 0)) | 0) - (( + Math.atan2(( + (( ! ( + ( + (( + Number.MIN_VALUE) !== ( + Math.max(( + y), x)))))) >>> 0)), ( + ( + Math.log10((((x >>> 0) && Math.fround(( + ( ! Math.fround(y))))) >>> 0)))))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, 2**53-2, Number.MAX_VALUE, 1/0, 0x080000001, -0x100000000, Math.PI, 0, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, -(2**53), Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 2**53+2, 42, 2**53, 0/0, 1.7976931348623157e308, -Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1, -0x080000001, 0x100000000, -0x100000001, -1/0]); ");
/*fuzzSeed-94431925*/count=419; tryItOut("\"use strict\"; for (var p in v2) { try { /*ADP-1*/Object.defineProperty(g0.a1, 11, ({set: new Function, enumerable: ( /x/ ).apply(x)})); } catch(e0) { } try { /*ADP-2*/Object.defineProperty(this.a1, 15, { configurable: true, enumerable: true, get: (function() { for (var j=0;j<55;++j) { f1(j%2==1); } }), set: (function() { for (var j=0;j<0;++j) { f1(j%3==0); } }) }); } catch(e1) { } try { Object.prototype.unwatch.call(g0.p0, \"values\"); } catch(e2) { } let v2 = t1.length; }");
/*fuzzSeed-94431925*/count=420; tryItOut("v2 = evaluate(\"mathy5 = (function(x, y) { \\\"use strict\\\"; return (((( - ((Math.acosh((Math.atan2(Math.fround(Math.pow(( + (y * y)), Math.fround(y))), y) >>> 0)) >>> 0) | Math.fround((Math.min(( + Math.log10(( + ( + -0x0ffffffff)))), (Math.cosh(y) >>> 0)) >>> 0)))) | 0) && (( + ( ~ (Math.atan2(y, Math.atan2(-Number.MAX_SAFE_INTEGER, y)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy5, [0x0ffffffff, Math.PI, 0x07fffffff, 1, 0x080000001, -0x07fffffff, 0.000000000000001, -1/0, 2**53+2, 2**53, 0/0, -0, -0x100000000, -0x080000000, 0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), -0x100000001, 42, 2**53-2, -0x0ffffffff, 0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2)]); \", ({ global: g0.g2, fileName: null, lineNumber: 42, isRunOnce: (x % 2 == 1), noScriptRval: (void shapeOf( /x/ )), sourceIsLazy: (x % 6 != 0), catchTermination: (x % 8 != 4) }));");
/*fuzzSeed-94431925*/count=421; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=422; tryItOut("delete a1[\"x\"];");
/*fuzzSeed-94431925*/count=423; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\d|(?=((?=\\\\w[^]*){4,}){274877906943,274877906946})\", \"\"); var s = \"a\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=424; tryItOut(";");
/*fuzzSeed-94431925*/count=425; tryItOut("\"use asm\"; var d = ((a =  /x/g )), fysrad, x = -28;print(new RegExp(\"\\\\b\", \"gim\"));");
/*fuzzSeed-94431925*/count=426; tryItOut("testMathyFunction(mathy0, [-0x100000000, -Number.MAX_VALUE, -0x100000001, 2**53+2, -0, 0.000000000000001, 2**53, Math.PI, 0x080000000, 0x100000001, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -0x080000000, -1/0, Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), -0x0ffffffff, 42, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, 0x080000001, 0x0ffffffff, 0, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53)]); ");
/*fuzzSeed-94431925*/count=427; tryItOut("\"use strict\"; testMathyFunction(mathy3, [2**53-2, -(2**53+2), 1/0, 0, -0x080000001, 1, 0x100000000, -0x080000000, 0x080000000, 0.000000000000001, 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 2**53, 0/0, -(2**53-2), Number.MAX_VALUE, 42, 0x100000001, 0x07fffffff, -(2**53), -1/0, Math.PI, -0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-94431925*/count=428; tryItOut("t2 = new Uint8ClampedArray(1);\n/* no regression tests found */\n");
/*fuzzSeed-94431925*/count=429; tryItOut("(\"\\u01D9\");\na0.length = 0;\n");
/*fuzzSeed-94431925*/count=430; tryItOut("return -16;yield (yield x);");
/*fuzzSeed-94431925*/count=431; tryItOut("(void options('strict_mode'));");
/*fuzzSeed-94431925*/count=432; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.pow(( + Math.fround(Math.atan2((Math.hypot(x, Math.cosh(x)) | 0), Math.fround(( - (x ^ ((( ~ (y >>> 0)) >>> 0) / x))))))), ( + ( + ( ~ ( + Math.fround(( ! Math.fround((((((y >>> 0) < (y >>> 0)) >>> 0) | (( ! 0x080000001) >>> 0)) | 0)))))))))); }); testMathyFunction(mathy0, /*MARR*/[ '' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '' , new Number(1.5), new Number(1.5),  '' ]); ");
/*fuzzSeed-94431925*/count=433; tryItOut("a2.unshift(h2, p1);");
/*fuzzSeed-94431925*/count=434; tryItOut("\"use strict\"; print(e0);function toString(x = ({/*toXFun*/toSource: Array.prototype.some, prototype: this })) { /*RXUB*/var r = /(?:(?=\\2)*?)*?/gm; var s = \"\"; print(s.replace(r, false, \"gyi\"));  } mathy1\nv0 = a1.reduce, reduceRight((function() { for (var j=0;j<14;++j) { this.f1(j%2==1); } }), m2, s0);function \u3056() { yield [\"\u03a0\"] } o0 + '';\n");
/*fuzzSeed-94431925*/count=435; tryItOut("\"use strict\"; (void version(180));");
/*fuzzSeed-94431925*/count=436; tryItOut("throw StopIteration;");
/*fuzzSeed-94431925*/count=437; tryItOut("\"use strict\"; p2 = this.t1[g2.v2];");
/*fuzzSeed-94431925*/count=438; tryItOut("\"use strict\"; e0.add(o2);");
/*fuzzSeed-94431925*/count=439; tryItOut("(/(?=[^\\S\\cM]\u0009{3,7}+?)(?=(?!^)+?{4})|([].|[\\u0035-\u160e\\\u00f8-\\xC4\\x90]|[\\cN\\S\uba6a\\D]{2,4}).|[]{17179869183,17179869183}*/gi);");
/*fuzzSeed-94431925*/count=440; tryItOut("\"use strict\"; Array.prototype.shift.call(a1, f0, e0, f2);function x()(/*FARR*/[(Math.max(0, -1)), /*UUV1*/(y.indexOf = NaN), (++x), new RegExp(\"(.|(?=$+?(?:\\\\D))\\\\b\\\\b)\", \"im\"), .../*FARR*/[let (w = \"\\uDD3E\") c, ]].map(SharedArrayBuffer, (({z: true})).throw(x) >>= [] = (4277)))s0 = a1[({valueOf: function() { Array.prototype.shift.call(a0);return 7; }})];print(x);");
/*fuzzSeed-94431925*/count=441; tryItOut("{ void 0; setIonCheckGraphCoherency(false); } m1.get(h2);\ne2.delete(o1.s0);\n");
/*fuzzSeed-94431925*/count=442; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=443; tryItOut("/*RXUB*/var r = (\u0009x = x); var s = Math.min(yield window, (void options('strict_mode'))); print(uneval(r.exec(s))); ");
/*fuzzSeed-94431925*/count=444; tryItOut("mathy4 = (function(x, y) { return ( + ( - ( + (Math.hypot(((( + ( + mathy3(Math.fround(Math.exp(x)), Math.fround((x ? x : (( ! 0x080000000) | 0)))))) - Math.fround((Math.fround((Math.imul(Math.asinh(Math.min(0, y)), (x | 0)) | 0)) !== Math.fround(x)))) | 0), Math.tanh(Math.fround(Math.sqrt(Math.fround(((Math.hypot((0x080000000 >>> 0), (x | 0)) | 0) === Math.imul(x, mathy2(y, -0x100000001)))))))) | 0)))); }); testMathyFunction(mathy4, [2**53, Number.MAX_VALUE, -0x07fffffff, -0x100000001, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, -0x080000001, 42, -(2**53+2), -(2**53), -Number.MIN_VALUE, 0x07fffffff, -0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 0x0ffffffff, 2**53+2, 0x100000000, 0x100000001, -0x100000000, 1, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, 0/0, 0x080000000]); ");
/*fuzzSeed-94431925*/count=445; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.acosh(((Math.log((Math.fround(( ~ (-0 >>> 0))) >>> 0)) && (( - (( - ((x >>> x) >>> 0)) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [2**53+2, 0.000000000000001, -0x100000000, 2**53, -Number.MIN_VALUE, -0x080000001, -0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, -0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, -1/0, 0x100000000, -0x100000001, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, -(2**53), -(2**53-2), 0x080000000, -0x0ffffffff, 0, 2**53-2, 0/0, 1, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=446; tryItOut("\"use strict\"; e2.has(s0);");
/*fuzzSeed-94431925*/count=447; tryItOut("/*vLoop*/for (gsofyj = 0, revwbq; gsofyj < 30; ++gsofyj) { const e = gsofyj; m2.set(p2, f2); } ");
/*fuzzSeed-94431925*/count=448; tryItOut("var lclsvz = new SharedArrayBuffer(12); var lclsvz_0 = new Int32Array(lclsvz); lclsvz_0[0] = -70183498; var lclsvz_1 = new Float32Array(lclsvz); lclsvz_1[0] = 14; var lclsvz_2 = new Uint8ClampedArray(lclsvz); lclsvz_2[0] = 24; var lclsvz_3 = new Uint32Array(lclsvz); i0.next();v0 = evalcx(\"/* no regression tests found */\", g0);/* no regression tests found */lzpbph();/*hhh*/function lzpbph(){print(uneval(b2));}\no0 = a0.__proto__;\n");
/*fuzzSeed-94431925*/count=449; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=450; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -131073.0;\n    {\n      d2 = (-288230376151711740.0);\n    }\n    i0 = (i1);\n    (Float64ArrayView[((i1)-((NaN))) >> 3]) = ((-4194305.0));\n    (Int16ArrayView[4096]) = ((i1)+(-0x8000000));\n    i0 = (i1);\n    i1 = ((i1));\n    i1 = (i1);\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: Int8Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [0x080000001, Number.MAX_VALUE, 0.000000000000001, 0, 0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53+2), -(2**53), -0x07fffffff, 1, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -1/0, 1/0, 0/0, 0x07fffffff, 2**53-2, 0x100000000, -Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, -0, Math.PI, 0x100000001, -0x080000000, -0x080000001, 2**53+2, 2**53, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=451; tryItOut(" \"\" .__defineSetter__(\"window\", window/*\n*/);");
/*fuzzSeed-94431925*/count=452; tryItOut("\"use strict\"; var hkvscc = new ArrayBuffer(6); var hkvscc_0 = new Uint8ClampedArray(hkvscc); hkvscc_0[0] = 3; var hkvscc_1 = new Int32Array(hkvscc); hkvscc_1[0] = 21; var hkvscc_2 = new Int8Array(hkvscc); var hkvscc_3 = new Int16Array(hkvscc); print(hkvscc_3[0]); var hkvscc_4 = new Int32Array(hkvscc); print(hkvscc_4[0]); var hkvscc_5 = new Uint8ClampedArray(hkvscc); hkvscc_5[0] = -10; var hkvscc_6 = new Float32Array(hkvscc); var hkvscc_7 = new Int8Array(hkvscc); print(hkvscc_7[0]); hkvscc_7[0] = -21; g2.offThreadCompileScript(\"/*bLoop*/for (tdkyxv = 0; tdkyxv < 72; ++tdkyxv) { if (tdkyxv % 4 == 1) { o0.o1 = {}; } else { /* no regression tests found */ }  } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (hkvscc_2 % 4 == 2), noScriptRval: hkvscc_2[0], sourceIsLazy: true, catchTermination: hkvscc_0[0] }));");
/*fuzzSeed-94431925*/count=453; tryItOut("/*vLoop*/for (var ogdvsg = 0; ogdvsg < 147; ++ogdvsg) { let w = ogdvsg; var v2 = t2.length; } ");
/*fuzzSeed-94431925*/count=454; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    {\n      d0 = (d0);\n    }\n    {\n      {\n        return (((0xfead8094)*-0xf925c))|0;\n      }\n    }\n    d1 = (d0);\n    {\n      d1 = (d1);\n    }\n    {\n      d0 = (d0);\n    }\n    d0 = (NaN);\n    d0 = (d0);\n    d0 = ((0xa4c90946) ? (d0) : (+atan2(((Infinity)), ((((Infinity)) * ((+abs((((2199023255553.0) + (67108864.0)))))))))));\n    d1 = (((d0)) - ((d0)));\n    return ((x))|0;\n  }\n  return f; })(this, {ff: Math.sinh}, new ArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=455; tryItOut("o0.__iterator__ = (function() { v1 = t2[new String(\"8\")]; return g2; });");
/*fuzzSeed-94431925*/count=456; tryItOut("o1.t2[7] = {} = (++arguments).__defineGetter__(\"y\", eval(\"/* no regression tests found */\"));");
/*fuzzSeed-94431925*/count=457; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround(Math.hypot(( ~ x), Math.pow((Math.log((-Number.MIN_VALUE | 0)) | 0), x))) + Math.fround(mathy0(Math.asinh(Math.fround(Math.sign(( + Math.asin(y))))), (Math.acosh(y) > ( + Math.max(Math.min(( + x), y), (x * (( - (y | 0)) | 0))))))))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, -(2**53-2), Number.MIN_VALUE, -0x100000000, -0x080000001, 1/0, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 0, -0x100000001, 2**53-2, -(2**53), 42, -Number.MAX_VALUE, 0x0ffffffff, Math.PI, -0, -(2**53+2), 0x07fffffff, -0x080000000, 2**53, 1.7976931348623157e308, 0x100000001, -0x07fffffff, 0x080000000, 0x100000000, Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-94431925*/count=458; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ! (((Math.fround(Math.imul(Math.fround(Math.hypot(0x100000000, Math.fround(Math.fround(Math.atan(( - ( + x))))))), x)) | 0) >> Math.fround((Math.asin(( + (x >> ((-0x07fffffff ^ -0x080000000) ? (( ! (-0x080000001 >>> 0)) | 0) : (Math.tan(y) >>> 0))))) | 0))) | 0)); }); testMathyFunction(mathy1, [-0x07fffffff, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -(2**53+2), -0x080000001, 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 1.7976931348623157e308, -0x080000000, -0, Math.PI, -(2**53), -0x0ffffffff, 0x100000000, 0/0, 42, -Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, Number.MAX_VALUE, -0x100000001, 1/0, -Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2, 1, Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=459; tryItOut("\"use strict\"; Object.prototype.unwatch.call(o0.m2, \"10\");");
/*fuzzSeed-94431925*/count=460; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-94431925*/count=461; tryItOut("\"use strict\"; b1 = Proxy.create(h2, this.g1.b1);");
/*fuzzSeed-94431925*/count=462; tryItOut("/*infloop*/while(w){v2 = Object.prototype.isPrototypeOf.call(i2, o1);print((25 / [z1,,]));function keys(x = new RegExp(Math.min(23, -2151177065)), b = (({x: delete a.eval})), window, x, x, d, w, c, x, e, x, x, 27, b, b, this.y, (function(stdlib, foreign, heap){ \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1.0009765625;\n    i1 = ((1.1805916207174113e+21) <= (((i1) ? (!(1)) : ((4277)())) ? (9.671406556917033e+24) : (73786976294838210000.0)));\n    {\n      (Float64ArrayView[2]) = ((d2));\n    }\n    d2 = (-144115188075855870.0);\n    i0 = (((d2)));\n    return +((-1023.0));\n    return +((1.1805916207174113e+21));\n  }\n  return f; }), NaN, z, \u3056, x, \u3056, a, window, d, c, y, x, \u3056, x, x, x, \u3056, b, \u3056, x, x = \"\\uC07A\", \u3056, delete, z = [1], z = [,])\"\\u8940\"return; }");
/*fuzzSeed-94431925*/count=463; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return ( - ( + (Math.abs(((((Math.min((Math.cosh(( + -Number.MAX_SAFE_INTEGER)) >>> 0), y) | 0) >>> 0) >> (((y | 0) << (Math.abs(x) | 0)) | 0)) >>> 0)) | 0))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, Number.MAX_VALUE, 42, 0x080000000, 0.000000000000001, 1, Math.PI, -0x080000000, 2**53-2, 0/0, -0x0ffffffff, 2**53+2, -1/0, -0x07fffffff, 0, -(2**53+2), Number.MIN_VALUE, -0x100000000, 2**53, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), 0x100000001, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=464; tryItOut("\"use strict\"; m0.get(this.p2);");
/*fuzzSeed-94431925*/count=465; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[false, false, false, 1e81, false]) { v0 = g1.eval(\"/* no regression tests found */\"); }");
/*fuzzSeed-94431925*/count=466; tryItOut("L: {/* no regression tests found */ }");
/*fuzzSeed-94431925*/count=467; tryItOut("testMathyFunction(mathy5, [-0x0ffffffff, 0x100000000, 0, 0x07fffffff, 0x100000001, 2**53+2, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), 1, Math.PI, 2**53, 1.7976931348623157e308, -0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, -0x100000000, -Number.MIN_VALUE, 2**53-2, -0x080000001, 0/0, -1/0, 1/0, 42, 0x080000001, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=468; tryItOut("print(uneval(o2));");
/*fuzzSeed-94431925*/count=469; tryItOut("\"use asm\"; /*oLoop*/for (var lsugxu = 0; lsugxu < 36; ++lsugxu, true) {  for (var w of a) {Array.prototype.splice.apply(o0.a1, [NaN, ({valueOf: function() { this.a0.sort(f0);return 17; }}), b1]); } } ");
/*fuzzSeed-94431925*/count=470; tryItOut("var y, e = false, bmzsmv, fyhght, a, b, y;print((this)(this, [z1,,]));");
/*fuzzSeed-94431925*/count=471; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.pow((Math.max((Math.fround(Math.atan2(Math.fround(Math.sin(((Math.atan2(-0x080000001, -(2**53)) , y) >>> 0))), Math.fround(Math.min(mathy0((x / y), Math.asin(Math.fround(mathy2(x, Math.fround(-(2**53)))))), y)))) >>> 0), (Math.tan(Math.max(y, -Number.MIN_SAFE_INTEGER)) >>> 0)) >>> 0), (Math.acos(((( - mathy2(( + Number.MAX_VALUE), (Math.imul(Math.fround(x), Math.fround(( + ( + Math.fround(Math.pow(Math.fround(y), Math.fround(x))))))) | 0))) >>> 0) | 0)) >>> 0)); }); testMathyFunction(mathy3, [2**53, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, Number.MAX_VALUE, 2**53-2, 0x07fffffff, Math.PI, -Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -0x07fffffff, 0/0, 0, Number.MIN_VALUE, 1/0, -(2**53+2), 2**53+2, -Number.MIN_SAFE_INTEGER, -0, 0x100000000, -Number.MIN_VALUE, -0x080000000, -0x100000001, 42, -0x0ffffffff, 1, -(2**53), 0x100000001, 0x080000001, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=472; tryItOut("\"use strict\"; o0.f2 + '';");
/*fuzzSeed-94431925*/count=473; tryItOut("t1.set(o1.a1, 6);");
/*fuzzSeed-94431925*/count=474; tryItOut("(NaN);function NaN(x, ...b) { \"use strict\"; yield ((p={}, (p.z = (-14 >= x))())) } a1[19] = new Uint8Array(\"\\uE191\", new RegExp(\"(?!\\\\d)|(?!\\\\3)\\\\r[^\\u91a5-\\\\\\u0012\\\\s]\\\\3{0,}\", \"m\")) *= new RegExp(\"\\\\B\\u5bde(?!(?=[^\\\\uE1Cb\\\\u0050\\u00a9-\\u9802\\\\s]))(?!(?![^])[^]*)|(?=(?:[])?|^)\\\\u4904?(?![\\\\n\\\\cT-\\u00c9])*??\", \"gym\").__defineGetter__(\"__lookupGetter__\", Math.sin);");
/*fuzzSeed-94431925*/count=475; tryItOut("/*oLoop*/for (yypewb = 0; yypewb < 54; ++yypewb, false) { { void 0; void schedulegc(63); } } ");
/*fuzzSeed-94431925*/count=476; tryItOut("/*bLoop*/for (let kuzgyr = 0; kuzgyr < 14; ++kuzgyr) { if (kuzgyr % 5 == 3) { /*hhh*/function fqeuus(w){yield undefined;\u0009}fqeuus(); } else { o1.p0 + v2; }  } ");
/*fuzzSeed-94431925*/count=477; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=478; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.min((Math.round((( ! Math.asinh(y)) | 0)) >>> 0), (( ! mathy0((( ~ (y >>> 0)) >>> 0), ( ~ y))) | ((Math.tanh((y >= (x >> ( + y)))) | 0) ^ ( + mathy1(( + y), ( + y)))))); }); ");
/*fuzzSeed-94431925*/count=479; tryItOut("var gpfvnm = new ArrayBuffer(16); var gpfvnm_0 = new Int16Array(gpfvnm); gpfvnm_0[0] = 2; var gpfvnm_1 = new Int32Array(gpfvnm); print(gpfvnm_1[0]); gpfvnm_1[0] = -27; g2.i0.next();print([,,]);\nthis.a2 = arguments;\n");
/*fuzzSeed-94431925*/count=480; tryItOut("\"use strict\"; f0.__proto__ = s0;");
/*fuzzSeed-94431925*/count=481; tryItOut("this.v2 = a2.length;");
/*fuzzSeed-94431925*/count=482; tryItOut("(( ! (( + ( + (( + ( + Math.log2(( + ( ! x))))) ? x : ( + x)))) | 0)) | 0);");
/*fuzzSeed-94431925*/count=483; tryItOut("\"use strict\"; /*bLoop*/for (nohaqk = 0, x; nohaqk < 15; ++nohaqk) { if (nohaqk % 6 == 3) { a2.sort((function() { s1.valueOf = (function() { for (var v of s1) { try { g1 = this; } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(v0, g1); } catch(e1) { } neuter(this.b2, \"change-data\"); } return i1; }); return this.h2; }), t1, a0); } else { /*RXUB*/var r = new RegExp(\"(((?=\\\\b)))+\", \"ym\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex);  }  } ");
/*fuzzSeed-94431925*/count=484; tryItOut("\"use strict\"; M:for(var e = x in this.__defineSetter__(\"d\", Int32Array)) {a0[\"fontcolor\"] = a2; }");
/*fuzzSeed-94431925*/count=485; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(mathy1(Math.fround(mathy1((( + ( ! ( + Math.sin(x)))) >>> 0), (((((x != (2**53 >>> 0)) * ((((y >>> 0) ? (Math.fround(( + (x >>> 0))) >>> 0) : (y >>> 0)) >>> 0) >>> 0)) | 0) !== (Math.atanh(x) | 0)) | 0))), Math.fround(Math.imul((( ! (y | 0)) | 0), (Math.hypot(( + Math.abs(( + Math.log2((-(2**53-2) >>> 0))))), ( ! 0x080000000)) | 0))))); }); ");
/*fuzzSeed-94431925*/count=486; tryItOut("var c = x, x = \"\\u5723\";( \"\" );");
/*fuzzSeed-94431925*/count=487; tryItOut("\"use strict\"; if((x % 24 != 5)) {print(x);print({}); }");
/*fuzzSeed-94431925*/count=488; tryItOut("Object.defineProperty(this, \"m0\", { configurable: false, enumerable: (x % 7 != 6),  get: function() {  return new Map(o2); } });");
/*fuzzSeed-94431925*/count=489; tryItOut("s0 = Array.prototype.join.apply(this.a2, [s2, o0, a0, this.h1, o1.p0, a1, o1, o1]);");
/*fuzzSeed-94431925*/count=490; tryItOut("mathy1 = (function(x, y) { return ( ~ Math.trunc((( ~ Math.fround(x)) | 0))); }); testMathyFunction(mathy1, [-0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), -(2**53-2), 0x100000001, 2**53+2, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, 1, -0x100000000, 2**53, 0x080000001, 0x100000000, 0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, 0/0, -0, Math.PI, -Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 0.000000000000001, 42, 0, 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=491; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.max((((Math.pow((((Math.fround(x) >>> Math.fround(( + ( + ( + x))))) | 0) >>> 0), (Math.log1p(Math.PI) >>> 0)) >>> 0) ^ ( + Math.hypot((Math.atan2((x | 0), x) >>> 0), ( + this.__defineGetter__(\"x\", Promise.resolve))))) | 0), (( + y) >>> 0))); }); testMathyFunction(mathy0, [0x07fffffff, -0x100000000, 0, Number.MIN_SAFE_INTEGER, -0x100000001, 1, -0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 0/0, 42, -Number.MIN_VALUE, -(2**53-2), 2**53, -0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, Math.PI, -(2**53), 2**53-2, -Number.MAX_VALUE, -0x080000001, 2**53+2, Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-94431925*/count=492; tryItOut("\"use strict\"; /*infloop*/for(var x = new RegExp(\"(?!.)|\\\\2{4,6}\", \"im\"); -18; window) print(x);");
/*fuzzSeed-94431925*/count=493; tryItOut("d;a2.unshift([[]], b2, h1, v1, v1);");
/*fuzzSeed-94431925*/count=494; tryItOut("/*oLoop*/for (let ljcgwo = 0; ljcgwo < 11; ++ljcgwo) { ; } ");
/*fuzzSeed-94431925*/count=495; tryItOut("for (var p in h1) { try { e0.has(m1); } catch(e0) { } s0 += 'x'; }");
/*fuzzSeed-94431925*/count=496; tryItOut("\"use strict\"; var vmhmli = new ArrayBuffer(4); var vmhmli_0 = new Float64Array(vmhmli); vmhmli_0[0] = -4; var vmhmli_1 = new Int8Array(vmhmli); print(vmhmli_1[0]); {}{}e0.add(o2.i2);");
/*fuzzSeed-94431925*/count=497; tryItOut("e2.add(g1.i2);");
/*fuzzSeed-94431925*/count=498; tryItOut("o1.v0 = a0.length;");
/*fuzzSeed-94431925*/count=499; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((Math.fround(Math.atan2((Math.min(( + x), x) <= Math.fround((Math.fround(((x == ( ~ x)) >>> 0)) ? Math.fround(-0x100000001) : Math.fround(x)))), Math.abs((Math.tanh((Math.hypot((Math.trunc((y | 0)) | 0), y) | 0)) | 0)))) > Math.fround(Math.atan(mathy0(x, Math.imul(x, (y + x))))))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-94431925*/count=500; tryItOut("mathy2 = (function(x, y) { return Math.abs(Math.fround((Math.fround(( + ((( - y) | 0) || (Math.min((y >>> 0), (mathy0(x, ( + y)) >>> 0)) >>> 0)))) <= Math.fround(( - Math.fround(mathy0(Math.fround(( + Math.pow(x, ( + Number.MIN_VALUE)))), Math.fround(-0x080000001)))))))); }); testMathyFunction(mathy2, [-0x07fffffff, -0, Number.MIN_VALUE, 0x100000000, 0.000000000000001, 0x07fffffff, 0/0, 0x0ffffffff, 0x080000001, -0x0ffffffff, 0, -1/0, 1, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 2**53-2, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), 2**53, 0x080000000, -0x080000001, 1/0, 42, -Number.MIN_VALUE, -(2**53+2), Math.PI, 1.7976931348623157e308]); ");
/*fuzzSeed-94431925*/count=501; tryItOut("\"use strict\"; a2[this];");
/*fuzzSeed-94431925*/count=502; tryItOut("a1 = this.a1.filter((function() { try { a0[1]; } catch(e0) { } a0 = []; return h0; }));");
/*fuzzSeed-94431925*/count=503; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ ( + Math.pow((Math.cosh((Math.imul(Math.atan2(x, y), Math.fround((Math.fround(x) ? Math.fround(y) : (y + -0x0ffffffff)))) >>> 0)) >>> 0), Math.max(( + (Math.trunc((-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)), (Math.atan2(Math.fround(x), Math.fround((x == x))) | 0))))); }); testMathyFunction(mathy0, [0x07fffffff, 2**53-2, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, 0x100000000, -0x07fffffff, Number.MIN_VALUE, -0x080000001, 1/0, -1/0, 1, -Number.MIN_SAFE_INTEGER, 2**53, -0, Math.PI, Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000000, 42, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), -0x0ffffffff, Number.MAX_VALUE, 0x080000001, -(2**53-2), 0x100000001, 0, -Number.MIN_VALUE, 2**53+2, -(2**53+2)]); ");
/*fuzzSeed-94431925*/count=504; tryItOut("a2.reverse(m1, , this.o0, v1);");
/*fuzzSeed-94431925*/count=505; tryItOut("\"use strict\"; this.b0 + g1;");
/*fuzzSeed-94431925*/count=506; tryItOut("if(true) { if ( \"\" ) a1.reverse(); else s2 += s1;}");
/*fuzzSeed-94431925*/count=507; tryItOut("\"use strict\"; m2 + '';");
/*fuzzSeed-94431925*/count=508; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\w)\", \"\"); var s = \"\\ud74d\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=509; tryItOut("var agjzog = new ArrayBuffer(1); var agjzog_0 = new Int16Array(agjzog); agjzog_0[0] = -14; var agjzog_1 = new Uint32Array(agjzog); s0 += s0;a1.reverse(h2);t1.set(a1, 10);print(agjzog_0[0]);/*tLoop*/for (let e of /*MARR*/[new Number(1), new Number(1), false, undefined, false, new Number(1), new Number(1), new Number(1), false, false, new Number(1), false, new Number(1), false, undefined, undefined, false]) { print(uneval(h1)); }");
/*fuzzSeed-94431925*/count=510; tryItOut("mathy3 = (function(x, y) { return Math.atan((Math.min(( + Math.log2(( + ((((( ~ (mathy2(Math.fround(x), Math.hypot(42, (-0x0ffffffff | 0))) >>> 0)) >>> 0) >>> 0) || (( ~ (Math.abs(Math.fround(-0)) | 0)) >>> 0)) >>> 0)))), (Math.max(Math.log(y), ( + Math.max(x, ( ! x)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -0x100000001, -0x07fffffff, Number.MIN_VALUE, 0/0, 2**53, 0x100000000, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -0, -Number.MIN_VALUE, -(2**53-2), -0x080000001, 0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, 1, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), 0x100000001, Number.MAX_VALUE, -(2**53), -0x100000000, 42, -0x0ffffffff, -Number.MAX_VALUE, -0x080000000, Math.PI]); ");
/*fuzzSeed-94431925*/count=511; tryItOut("/*RXUB*/var r = /(?!(?!(?!\\D|\\D([^])\\S?){0}))/y; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-94431925*/count=512; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( ~ Math.fround(mathy0(Math.fround(Math.atan2(Math.imul(Math.min((Math.sinh((x | 0)) | 0), 1), 1.7976931348623157e308), ( + Math.atan2(( + ( + ( - -1/0))), ( + x))))), ( + (((Math.min(( ~ y), Math.fround(x)) >>> 0) ? (Math.trunc(((x ? -Number.MIN_SAFE_INTEGER : Number.MAX_VALUE) >>> 0)) >>> 0) : (( + (y / ( + ( ~ 42)))) ? x : (-0x100000001 | ( + Math.atan2(x, ( + y)))))) + x)))))); }); ");
/*fuzzSeed-94431925*/count=513; tryItOut("\"use strict\"; const d = \"\\u7004\";a2.reverse(v1, i1);");
/*fuzzSeed-94431925*/count=514; tryItOut("\"use strict\"; g1.t1[9] = s0;");
/*fuzzSeed-94431925*/count=515; tryItOut("\"use strict\"; /*iii*/;/*hhh*/function sgjajg(b, NaN, NaN, {}, z, y, w = new RegExp(\"(?=((\\\\1)|[^\\\\w]+?|\\\\b))|^|\\ueac5?{0,}\", \"gyi\"), NaN =  /x/g , ...z){b0 = t0.buffer;}");
/*fuzzSeed-94431925*/count=516; tryItOut("let(w) { Array.prototype.unshift.apply(a0, [i2, i2]);}");
/*fuzzSeed-94431925*/count=517; tryItOut("\"use strict\"; /*hhh*/function ooburc(e, w, x, z, d, x(x), z = [[]], c, w, [], x, x, z, b, x, x, x){Object.preventExtensions(o2.g0.p1);}ooburc(intern( /x/g ) % undefined < (true >>  /x/ ), x);");
/*fuzzSeed-94431925*/count=518; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      (Float64ArrayView[(((+(1.0/0.0)))) >> 3]) = ((d1));\n    }\n    i0 = (i0);\n    return +((d1));\n    return +(((((((((-(i0))>>>((0x72b1cc10)+(0xf90d0e66)-(i0))))) >> ((0xbd451d0e)))))));\n  }\n  return f; })(this, {ff: String.prototype.codePointAt}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000001, 2**53, 0x0ffffffff, 2**53-2, -0x100000001, 0x100000000, Math.PI, 1/0, -1/0, -(2**53+2), 42, -(2**53), 0.000000000000001, 1.7976931348623157e308, -0, -0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, -0x080000001, -0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), 0/0, 0, -Number.MIN_VALUE, 0x080000000, 1, 2**53+2, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=519; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -2199023255553.0;\n    d2 = (-((d1)));\n    return +((d2));\n    (Int16ArrayView[2]) = (0x3ea4d*(0xffffffff));\n    d1 = (/*UUV1*/(z.isFrozen = Float32Array));\n    return +((d1));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var rahxgy = (function ([y]) { })(); (neuter)(); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=520; tryItOut("/*hhh*/function rcmtsh(d, a){v0 = t1.length;p2 + '';}/*iii*//*RXUB*/var r = new RegExp(\"(?!\\\\B)|((?!\\\\d{1,5}|[]$+{1})?)*?\", \"\"); var s = \"\"; print(s.search(r)); function x(rcmtsh, c)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 33554433.0;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    i4 = (0xa83eb3db);\n    i5 = ((0xf3f3e33f) == (((i0)+((d2) <= (147573952589676410000.0))-(i3))>>>((i5))));\n    (Float64ArrayView[4096]) = ((-16777217.0));\n    i4 = (i5);\n    return +((-9.44473296573929e+21));\n  }\n  return f;true;");
/*fuzzSeed-94431925*/count=521; tryItOut("this.g0.h0.__proto__ = v0;");
/*fuzzSeed-94431925*/count=522; tryItOut("this.s1 = new String;");
/*fuzzSeed-94431925*/count=523; tryItOut("/*tLoop*/for (let a of /*MARR*/[x, (0/0), new Boolean(true), (0/0), (4277), (0/0), x, x, x,  '' , new Boolean(true), new Boolean(true), new Boolean(true), (4277), (0/0),  '' , (4277), x, (0/0), (4277), (4277),  '' , x, (0/0),  '' , (0/0), (0/0), x, (4277), x, (0/0), (0/0), new Boolean(true), (0/0), x, x,  '' ,  '' , (4277),  '' ,  '' , (4277), (0/0), x,  '' , new Boolean(true), new Boolean(true),  '' ,  '' , x, (0/0), (0/0), (4277), x,  '' , x,  '' ,  '' , x, (0/0), x, (0/0),  '' , new Boolean(true), (4277), new Boolean(true), new Boolean(true), x, new Boolean(true),  '' , (4277),  '' , (4277),  '' , x, x, (0/0), (0/0),  '' , x, (4277), (0/0),  '' , x,  '' ,  '' , x,  '' , (0/0), new Boolean(true), (0/0), (4277), x, x, x, x, x, x, x, x, x, x, x, x, new Boolean(true), x,  '' , new Boolean(true), (4277), (0/0), x, x, (0/0),  '' , (4277), (4277), (0/0),  '' , (4277), (4277), (4277), new Boolean(true), x, new Boolean(true), x, new Boolean(true), new Boolean(true), (0/0), new Boolean(true), x, (0/0), x, new Boolean(true), x,  '' , x, (0/0),  '' ]) { e1.delete(e1); }");
/*fuzzSeed-94431925*/count=524; tryItOut("\"use strict\"; Array.prototype.reverse.apply(this.a0, []);");
/*fuzzSeed-94431925*/count=525; tryItOut("function shapeyConstructor(jslqif){{ /* no regression tests found */ } return this; }/*tLoopC*/for (let d of /*MARR*/[0x0ffffffff, [(void 0)], [], [], [(void 0)], [(void 0)], 0x0ffffffff, [], [], [(void 0)], [], [], [], [], [], [], [], [], [(void 0)], [(void 0)], [(void 0)], 0x0ffffffff, [(void 0)], [], 0x0ffffffff, [(void 0)], [], [], [(void 0)], [], 0x0ffffffff, 0x0ffffffff, [], 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, [], 0x0ffffffff, [(void 0)], 0x0ffffffff, [(void 0)]]) { try{let fjojen = new shapeyConstructor(d); print('EETT'); let (x) { m0.delete(this.f0); }}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-94431925*/count=526; tryItOut("/*ADP-3*/Object.defineProperty(this.g0.a0, 18, { configurable: (x % 2 != 0), enumerable: true, writable: true, value: p1 });");
/*fuzzSeed-94431925*/count=527; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, 0, 1, Number.MAX_VALUE, -0x080000001, -(2**53), 0x080000001, 0x100000000, 0x100000001, 1/0, 2**53+2, 1.7976931348623157e308, -(2**53-2), -0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, -0x100000001, -0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -0, 42, 0x0ffffffff, Math.PI, 0x080000000, -1/0, -(2**53+2)]); ");
/*fuzzSeed-94431925*/count=528; tryItOut("mathy0 = (function(x, y) { return Math.expm1(((Math.hypot((Math.atan2((Math.PI >>> 0), x) >>> 0), ( + ( ! ( + x)))) ** (Math.min(( ! 2**53), (Math.asinh(Math.imul(-Number.MIN_SAFE_INTEGER, ( + (x >>> 0)))) >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy0, [2**53, -(2**53-2), -0x100000000, 0/0, 0x080000001, -0, -0x080000001, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, Math.PI, -1/0, 0x0ffffffff, 0, 1, Number.MAX_VALUE, 0x080000000, 42, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 0.000000000000001, 1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x100000000, -Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53)]); ");
/*fuzzSeed-94431925*/count=529; tryItOut("with({e: (4277)}){/*RXUB*/var r = new RegExp(\"\\\\1|(?:^)\\\\2+?|[^](?=(\\\\S){4,8}(?:\\\\S)|[^\\\\u001F-\\ud2f2\\u29a6]([^]|(?=[^\\\\u05C1\\\\d\\\\x3F-\\\\r\\\\s])))*[]\", \"im\"); var s = \"\\u1ff7\\u885c\\n\\n\\u1ff7\\u885c\\n\\n\\u1ff7\\u885c\\n\\n\\u1ff7\\u885c\\n\\n\\u1ff7\\u885c\\n\\na \\ub21c \\u1ff7\\u885c\\n\\na \\ub21c \\n\\n\\n\\u00d4\\ud295\\u1ff7\\u885c\\n\\n\\u1ff7\\u885c\\n\\n\\u1ff7\\u885c\\n\\n\\u00c2\"; print(s.search(r));  }");
/*fuzzSeed-94431925*/count=530; tryItOut("s1 += 'x';");
/*fuzzSeed-94431925*/count=531; tryItOut("g1.s0 += this.o2.s1;");
/*fuzzSeed-94431925*/count=532; tryItOut("\"use strict\"; v1 = 4;");
/*fuzzSeed-94431925*/count=533; tryItOut("\"use strict\"; if(true) { /x/ ; }");
/*fuzzSeed-94431925*/count=534; tryItOut("/*hhh*/function yklztd(x, e, x, x, e = 23, x, x, x, x, \u3056, x, x, window, x, b, window, x, x, x, w, y, a, e, b, x, b, window, x, a, c, y, x, \u3056, x, y, x, NaN, eval, y, x, x, x, y, z, ...eval){print(({a1:1}));}yklztd(yield undefined);");
/*fuzzSeed-94431925*/count=535; tryItOut("testMathyFunction(mathy2, /*MARR*/[2**53+2, 1, new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new Boolean(false), 1, new String('q'), new String('q'), 2**53+2, new String('q'), new String('q'), new Boolean(false), 2**53+2, 1, objectEmulatingUndefined(), new Boolean(false), new String('q'), new Boolean(false), new String('q'), new String('q'), objectEmulatingUndefined(), 2**53+2, new Boolean(false), 1, 1, 1, new String('q'), new Boolean(false)]); ");
/*fuzzSeed-94431925*/count=536; tryItOut("\"use strict\"; g1.b1 = t1[({valueOf: function() { L:for(var w in ((q => q)(({e: (24 | [1,,])})))){ void 0; try { startgc(175495039); } catch(e) { } }return 7; }})];");
/*fuzzSeed-94431925*/count=537; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[new String('q'), function(){}, new String('q'), function(){}, new String('q'), null, new String('q'), new String('q'), function(){}, new String('q'), function(){}, new String('q'), new String('q'), null, function(){}, function(){}, null, new String('q'), function(){}, new String('q'), null, new String('q'), new String('q'), null, function(){}, new String('q'), null, null, new String('q'), new String('q'), new String('q'), new String('q'), null, new String('q'), function(){}, new String('q'), new String('q'), null, new String('q'), new String('q'), null, function(){}, new String('q'), new String('q'), null, function(){}, function(){}, new String('q'), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, new String('q'), null, null, new String('q'), function(){}, null, function(){}, new String('q'), null, null, new String('q'), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, new String('q'), new String('q'), function(){}, new String('q'), new String('q'), function(){}, null, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), function(){}, null, new String('q'), function(){}, new String('q'), null, null, null, new String('q'), new String('q'), null, null, null, null, null, null, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), function(){}, function(){}, null, new String('q'), null, function(){}, function(){}, null, new String('q'), function(){}, new String('q'), new String('q'), new String('q'), null, new String('q'), new String('q'), function(){}, function(){}, function(){}, function(){}, new String('q'), new String('q'), new String('q'), function(){}, null, new String('q'), function(){}, new String('q'), function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), null, null, null, null, null, null, null, null, null, null, new String('q'), function(){}, null, new String('q'), null, new String('q'), function(){}, new String('q'), null, function(){}, new String('q')]); ");
/*fuzzSeed-94431925*/count=538; tryItOut("\"use strict\"; const y = (w != z);M:if(true) g0.m0 = new Map; else o1.a1.length = 0;");
/*fuzzSeed-94431925*/count=539; tryItOut("o0.v2 = b2.byteLength;");
/*fuzzSeed-94431925*/count=540; tryItOut(" for (let w of 20) m1 = t0[11];");
/*fuzzSeed-94431925*/count=541; tryItOut("\"use strict\"; a2.unshift(o2.p2);");
/*fuzzSeed-94431925*/count=542; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (i1);\n    (Uint8ArrayView[((/*FFI*/ff(( \"\" ))|0)+(((0x8e2a012f) ? (0xff1df23f) : (0xdb83144c)) ? (i2) : ((0xc3da9820) < (0x85ebc31d)))) >> 0]) = (((0xd63772a6) == (0x6306a1bf))-(i1)-(0x31ce6891));\n    i0 = (i0);\n    i1 = (i1);\n    i1 = (0xd747d75a);\n    i2 = (i0);\n    i1 = (i2);\n    {\n      (Float64ArrayView[2]) = ((+((+(((((((0xff33701e)))))+(i1)+(((0xaff87231) ? (0xff0c3c9e) : (-0x8000000)) ? ((0x7fffffff) > (0x1a0205fc)) : (0x7949d41))) >> (((-2305843009213694000.0))))))));\n    }\n    return +((NaN));\n  }\n  return f; })(this, {ff: intern(new (arguments.callee.caller.caller.caller.caller)()).parse}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=543; tryItOut("b1.toString = Array.prototype.join.bind(f2);");
/*fuzzSeed-94431925*/count=544; tryItOut("/*ODP-1*/Object.defineProperty(o1.f1, new String(\"4\"), ({get: objectEmulatingUndefined, enumerable: (x % 4 != 2)}));");
/*fuzzSeed-94431925*/count=545; tryItOut("/*infloop*/for(x = d; y; -26) ( \"\" );");
/*fuzzSeed-94431925*/count=546; tryItOut("\"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = (i2);\n    return ((((2.3611832414348226e+21) >= (16777215.0))-(/*FFI*/ff((((Float64ArrayView[4096]))), ((abs(((((((i2))>>>((!(0x16d1b5af)))))) >> (-0x89ad0*(((i2))))))|0)))|0)))|0;\n    return ((-(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: function(q) { \"use strict\"; return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x080000000, 1.7976931348623157e308, -0x100000001, Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 0x080000000, -0x080000001, -0, Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 0x080000001, -1/0, -0x0ffffffff, 2**53+2, 0x07fffffff, 0x100000000, 0, -(2**53-2), 0/0, 42, Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x100000001, Math.PI, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=547; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.pow(((((( + Math.expm1(( + Math.hypot(y, Math.sign(y))))) >>> 0) , (-0x07fffffff | 0)) | 0) + (y + (Math.exp(Math.fround(y)) | x))), Math.log2(Math.atan2((( ~ (Math.atan2((y / ( + x)), x) >>> 0)) >>> 0), Math.fround((Math.fround((Math.fround(Math.fround(Math.max(( + x), Math.fround(mathy0((y | 0), x))))) / Math.fround(Math.asin(2**53-2)))) , x))))); }); ");
/*fuzzSeed-94431925*/count=548; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( ~ Math.fround(( + Math.log1p(Math.sqrt(( - Math.fround(Math.max(y, Math.fround(y)))))))))); }); ");
/*fuzzSeed-94431925*/count=549; tryItOut("mathy1 = (function(x, y) { return (Math.fround(Math.fround((Math.fround(mathy0(x, y)) / ((( ~ Math.fround(y)) >>> 0) ^ (Math.ceil(x) ? ((x || (Math.atanh(x) | 0)) | 0) : x))))) + (Math.asinh(((( ! Math.fround(Math.min(Math.fround((x << x)), Math.fround(x)))) , x) | 0)) | 0)); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, Math.PI, -1/0, 1/0, -(2**53+2), 0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, -0x100000001, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, 0/0, 0x080000000, 0.000000000000001, -(2**53), 1, 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -0x080000001, 42, 0x100000001, -0x100000000, Number.MIN_VALUE, -0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=550; tryItOut("Array.prototype.shift.apply(this.a1, [b1]);");
/*fuzzSeed-94431925*/count=551; tryItOut("let d, pyfrzd, \u3056 = x, x, cjvwto, c = this.__defineGetter__(\"y\", /(?:[^\\S\\d\\b-\\cD]+\\W|[^]?*?{4,})/gi);print(uneval(f1));\na0 = a1.concat(g2.t0);\n");
/*fuzzSeed-94431925*/count=552; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ! Math.fround(( + Math.atan2((mathy0(( ~ -(2**53+2)), ( + 1/0)) | 0), ( + ( - x)))))); }); testMathyFunction(mathy1, [0, false, null, [0], ({valueOf:function(){return '0';}}), -0, objectEmulatingUndefined(), NaN, (new Boolean(false)), true, [], /0/, '\\0', (new Number(-0)), '/0/', undefined, 1, 0.1, (new Number(0)), (function(){return 0;}), ({toString:function(){return '0';}}), '', (new Boolean(true)), ({valueOf:function(){return 0;}}), '0', (new String(''))]); ");
/*fuzzSeed-94431925*/count=553; tryItOut("mathy2 = (function(x, y) { return (Math.fround(mathy1((( - Math.hypot(1/0, y)) | 0), (((((x % -0x0ffffffff) | 0) | 0) | (Math.imul((Math.asin((Math.fround(( - (x ? -(2**53+2) : -0x100000001))) >>> 0)) >>> 0), y) | 0)) | 0))) != (mathy0(((Math.fround(( + Math.fround(y))) ? ( ! x) : 1) >= y), ((Math.log10(Math.acosh((y >>> 0))) | 0) | 0)) | 0)); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 1, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 2**53-2, 0x100000001, -0x100000001, 0x07fffffff, -0x100000000, 2**53, 0/0, -(2**53), -0x080000001, 42, -0x07fffffff, Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, 1/0, -0, -0x080000000, -1/0, -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-94431925*/count=554; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - Math.fround(Math.atan2(Math.fround((Math.imul((Math.atanh(( + Math.imul(x, -0x080000000))) >>> 0), Math.fround(x)) >>> 0)), mathy2(( + Math.trunc(( + y))), Math.fround(Math.acosh(x)))))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0.000000000000001, -(2**53-2), 1/0, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -0x07fffffff, 0, 0/0, 2**53-2, -(2**53), -Number.MAX_SAFE_INTEGER, 42, -0x100000001, -1/0, 0x080000000, 2**53+2, 0x100000001, Math.PI, -(2**53+2), -0x080000001, 1]); ");
/*fuzzSeed-94431925*/count=555; tryItOut("var tutcty = new ArrayBuffer(4); var tutcty_0 = new Int32Array(tutcty); tutcty_0[0] = -11; b2 + '';");
/*fuzzSeed-94431925*/count=556; tryItOut("/*RXUB*/var r = g0.r0; var s = \"_\"; print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=557; tryItOut("a2.shift(g0);");
/*fuzzSeed-94431925*/count=558; tryItOut("/*tLoop*/for (let c of /*MARR*/[Infinity, (4277), new Boolean(true), new Boolean(true), (4277), (4277), new Boolean(true), (4277), new Boolean(true), (4277), Infinity, new Boolean(true), (4277), Infinity, new Boolean(true), (4277), (4277), new String(''), new String(''), new Boolean(true), (4277), (4277), new Boolean(false), (4277), new Boolean(false), new Boolean(false), (4277), new Boolean(false), new String(''), new Boolean(false), new String(''), new Boolean(false), (4277), new Boolean(true), new String(''), new Boolean(false), new String(''), new Boolean(true), new Boolean(true), Infinity, new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(true)]) { g1.s2 += 'x'; }");
/*fuzzSeed-94431925*/count=559; tryItOut("\"use strict\"; h1 + v2;");
/*fuzzSeed-94431925*/count=560; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = (4277); print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=561; tryItOut("mathy0 = (function(x, y) { return ( + Math.atanh((( + (Math.hypot((x > y), (( ~ (2**53-2 | 0)) | 0)) & ((Math.acos(x) ** Math.sign(-Number.MIN_SAFE_INTEGER)) >>> (((( ! -0x080000001) | 0) | 0) - ( ~ ((Math.fround(x) > -(2**53+2)) | 0)))))) >>> 0))); }); testMathyFunction(mathy0, [-0, -Number.MAX_VALUE, -0x080000000, 0x080000001, -0x0ffffffff, -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -(2**53+2), 0x07fffffff, 1.7976931348623157e308, 2**53, -0x100000001, Number.MAX_VALUE, 2**53-2, Math.PI, Number.MIN_VALUE, -(2**53), 0/0, 0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, -Number.MIN_VALUE, 0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, 42, 0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=562; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(a1, g0.s1);");
/*fuzzSeed-94431925*/count=563; tryItOut("\"use asm\"; /*RXUB*/var r = x = [z1]; var s = \"\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-94431925*/count=564; tryItOut("/*tLoop*/for (let b of /*MARR*/[1.7976931348623157e308, (0/0),  '' , (0/0),  '' , 1.7976931348623157e308,  '' ,  '' , (0/0), (0/0), (0/0), 1.7976931348623157e308, 1.7976931348623157e308, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  '' , (0/0), 1.7976931348623157e308,  '' ,  '' , 1.7976931348623157e308,  '' , (0/0),  '' , (0/0),  '' ,  '' ,  '' ,  '' , (0/0), 1.7976931348623157e308, 1.7976931348623157e308, (0/0), (0/0), (0/0),  '' , (0/0),  '' , 1.7976931348623157e308,  '' , (0/0),  '' , (0/0),  '' , (0/0), (0/0), 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308,  '' ,  '' ,  '' , (0/0), 1.7976931348623157e308, 1.7976931348623157e308,  '' ,  '' , (0/0), 1.7976931348623157e308,  '' , (0/0), (0/0),  '' ,  '' , (0/0),  '' ,  '' , (0/0), 1.7976931348623157e308,  '' ,  '' , 1.7976931348623157e308,  '' , 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308,  '' ,  '' , (0/0),  '' , 1.7976931348623157e308, (0/0), (0/0),  '' ,  '' ,  '' , (0/0),  '' ]) { yield undefined; }");
/*fuzzSeed-94431925*/count=565; tryItOut("print(uneval(g0));");
/*fuzzSeed-94431925*/count=566; tryItOut("e1.add(o0.b0);");
/*fuzzSeed-94431925*/count=567; tryItOut("/*tLoop*/for (let z of /*MARR*/[-0x080000000, undefined, ['z'], function(){}, function(){}, function(){}, ['z'], function(){}, new Boolean(true), function(){}, function(){}, ['z'], undefined]) { m0.has(o2.g0); }");
/*fuzzSeed-94431925*/count=568; tryItOut("g1.v2 = a2.some((function(j) { f1(j); }), f0);");
/*fuzzSeed-94431925*/count=569; tryItOut("\"use asm\"; a0.splice(0, ({valueOf: function() { x;return 5; }}));");
/*fuzzSeed-94431925*/count=570; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return ( + mathy1((( + Math.sign(( + (Math.asinh(Math.max(x, Math.fround(( + (x | 0))))) >>> 0)))) | 0), ((Math.fround(mathy0(Math.round(mathy0(2**53, (x >>> 0))), mathy0(Math.fround(x), Math.fround(Math.tan((( + (y >= Math.fround(x))) >>> 0)))))) & Math.fround(Math.sqrt((Math.ceil(x) | 0)))) | 0))); }); testMathyFunction(mathy3, /*MARR*/[['z'], ['z'], (void 0), objectEmulatingUndefined(), {}, (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, ['z'], objectEmulatingUndefined(), objectEmulatingUndefined(), ['z'], objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), {}, (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, ['z'], {}, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), {}, ['z'], (void 0), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined()]); ");
/*fuzzSeed-94431925*/count=571; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.max(Math.min((( ~ 0) | 0), (( ! (0/0 >>> 0)) >>> 0)), Math.fround(( ~ (Math.fround(y) ? x : Math.fround(1))))) >>> 0), Math.min((Math.fround((Math.fround(( ~ -Number.MAX_VALUE)) || Math.fround(( - x)))) + x), ( + Math.tan(( + Math.hypot(( + mathy2(Math.hypot(y, 42), x)), ( + (( + mathy1(y, mathy1(x, x))) >>> ( + (Math.fround((y ^ 0x080000001)) >= Math.fround(y))))))))))) | 0); }); testMathyFunction(mathy3, [2**53, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -(2**53-2), 0x080000000, 42, 2**53+2, 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, 0x100000000, Number.MAX_VALUE, -(2**53), 1/0, 0x0ffffffff, -0x080000001, 0, 1.7976931348623157e308, -0, 0x080000001, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, Math.PI, -0x100000001, Number.MIN_VALUE, -0x07fffffff, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=572; tryItOut("let g1 = this;");
/*fuzzSeed-94431925*/count=573; tryItOut("\"use strict\"; /*RXUB*/var r = /$+?|\\2(?!(?=[^]))*|\\0|[^\ucddd\\w]?{3}(?=\\B)+?(?![\\B-\\u34E0\\W]\ued5a)*/gy; var s = \"\\n\\0\\0\\0 \\u28e6\\ued5a\\u28e6\\ued5a\\u28e6\\ued5a\\u28e6\\ued5a\\u28e6\\ued5a\\u28e6\\ued5a\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=574; tryItOut("/*MXX2*/g2.Object.isSealed = g2;");
/*fuzzSeed-94431925*/count=575; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-94431925*/count=576; tryItOut("");
/*fuzzSeed-94431925*/count=577; tryItOut("testMathyFunction(mathy1, [2**53, -Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, -(2**53), 2**53-2, -0x080000000, 42, 0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 1/0, 0.000000000000001, Math.PI, Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -0, -Number.MAX_VALUE, 0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, 1.7976931348623157e308, 0x100000001, -(2**53-2), 1, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=578; tryItOut("i2 + g1.e2;");
/*fuzzSeed-94431925*/count=579; tryItOut("mathy3 = (function(x, y) { return Math.cbrt(( ! ((Math.imul(x, (2**53+2 >>> 0)) >>> 0) == x))); }); testMathyFunction(mathy3, [0x080000001, -0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, 0x080000000, 0x0ffffffff, -0, 1.7976931348623157e308, Number.MIN_VALUE, 2**53-2, -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, 2**53, Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), -1/0, -(2**53+2), 0, -0x100000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 42, 0/0]); ");
/*fuzzSeed-94431925*/count=580; tryItOut("f1 = Proxy.createFunction(g2.h1, o0.g1.g1.g0.f1, f0);");
/*fuzzSeed-94431925*/count=581; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ((mathy1(((Math.hypot(y, ( + x)) | 0) | 0), ((( ~ (y >>> 0)) >>> 0) | 0)) | 0) << Math.fround((( + (( + ( ~ y)) ? ( + Math.imul(y, ( + Math.atan2(y, x)))) : (( + (y & Math.fround(Math.fround(( - x))))) - y))) + (Math.atan2((Math.atan2(-0x0ffffffff, ( + Math.trunc(y))) | 0), (Math.fround(((x <= x) / Math.fround(x))) | 0)) | 0))))); }); testMathyFunction(mathy2, [false, null, undefined, ({toString:function(){return '0';}}), -0, (new Number(-0)), 1, [], (new Number(0)), (new Boolean(false)), '', ({valueOf:function(){return 0;}}), NaN, objectEmulatingUndefined(), true, '0', 0.1, (function(){return 0;}), [0], 0, '\\0', '/0/', /0/, (new String('')), (new Boolean(true)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-94431925*/count=582; tryItOut("mathy1 = (function(x, y) { return mathy0(mathy0(( + ( - Math.fround(( ~ x)))), mathy0(( + (x ^ ( + Math.fround(Math.atanh(y))))), ( ! x))), Math.log(((Number.MIN_VALUE <= ((Math.min((0/0 | 0), (y | 0)) | 0) || ( + x))) < Math.atan2(Math.fround(Math.min(( - Math.fround((( + (y | 0)) | 0))), y)), Math.clz32(( + x)))))); }); ");
/*fuzzSeed-94431925*/count=583; tryItOut("\"use strict\"; /*vLoop*/for (var ztmiza = 0; ztmiza < 84; x, ++ztmiza) { var a = ztmiza; for (var v of v0) { try { t2[8] = m2; } catch(e0) { } try { o1.h1 + e2; } catch(e1) { } var a2 = Array.prototype.concat.apply(a0, [a1]); }\n//h\n(void schedulegc(g2.g1));\n } ");
/*fuzzSeed-94431925*/count=584; tryItOut("e0.has(o0.i0);");
/*fuzzSeed-94431925*/count=585; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.min(Math.fround(Math.tan(Math.min(-0x100000000, Math.asinh(x)))), (( - (( ! x) >>> 0)) >>> 0)) <= ( + Math.expm1(Math.fround((Math.tan((Math.fround(Math.pow(Math.fround(( + ( ! ( + x)))), (Math.atan2((x | 0), x) | 0))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy2, [1, (new String('')), true, ({valueOf:function(){return 0;}}), -0, false, 0, (new Boolean(true)), [], NaN, (new Number(-0)), undefined, (function(){return 0;}), null, ({valueOf:function(){return '0';}}), (new Number(0)), [0], 0.1, '/0/', (new Boolean(false)), '', ({toString:function(){return '0';}}), objectEmulatingUndefined(), '0', '\\0', /0/]); ");
/*fuzzSeed-94431925*/count=586; tryItOut("mathy1 = (function(x, y) { return ( + ( - ( + x))); }); testMathyFunction(mathy1, [0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 1, -0, -1/0, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, 0.000000000000001, 2**53, 0x080000001, 42, Number.MIN_SAFE_INTEGER, 0/0, 1/0, -0x080000000, 0, -(2**53+2), -Number.MIN_VALUE, -0x080000001, -(2**53), 0x0ffffffff, 2**53-2, -0x100000001, -(2**53-2), -0x07fffffff, 2**53+2]); ");
/*fuzzSeed-94431925*/count=587; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((( + Math.log2(( + Math.imul(x, 0x100000001)))) / Math.max(((((( + (( + x) ^ Math.atan(y))) ? y : ((y ? Math.imul(x, Math.pow(y, y)) : Math.fround(2**53+2)) | 0)) | 0) ? (((Math.atan2(( + y), ( + y)) >>> 0) * -0x07fffffff) | 0) : (( + ( ~ ( + (((Math.atan2(-1/0, x) >>> 0) ? (x >>> 0) : x) >>> 0)))) | 0)) | 0), (Math.pow(Math.round((Math.ceil(((x | ( + x)) | 0)) | 0)), (Math.imul(( + (( + y) ? ( + y) : ( + (x ** 0.000000000000001)))), 0x100000000) | 0)) | 0)))); }); testMathyFunction(mathy0, [42, -0x100000000, Number.MAX_VALUE, Math.PI, -0x0ffffffff, 0x080000001, 0x0ffffffff, -0x080000001, -0x07fffffff, 2**53+2, 0x100000000, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, 0, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, 1/0, Number.MIN_SAFE_INTEGER, -1/0, -0x100000001, -(2**53-2), -(2**53), 0/0, 1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, -0, 2**53-2]); ");
/*fuzzSeed-94431925*/count=588; tryItOut("x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: undefined, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: undefined, iterate: function  c (d)(function ([y]) { })(), enumerate: arguments.callee.caller.caller.caller.caller.caller, keys: function() { return Object.keys(x); }, }; })(15), (1 for (x in [])), function shapeyConstructor(rjadra){this[\"__proto__\"] = arguments;Object.preventExtensions(this);return this; }) = a2[9];");
/*fuzzSeed-94431925*/count=589; tryItOut("b1 = t0[(Math.tan(x))];");
/*fuzzSeed-94431925*/count=590; tryItOut("mathy1 = (function(x, y) { return (Math.sin((Math.fround(Math.max(Math.fround(((x > ( - Number.MIN_VALUE)) | 0)), Math.fround(( + ( ~ Math.imul(y, Math.fround(( - Math.fround(x))))))))) >>> 0)) | 0); }); testMathyFunction(mathy1, [Math.PI, 0x100000001, -(2**53+2), 2**53+2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 0, 2**53-2, -0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, 0x0ffffffff, 2**53, 1, 0x080000000, -0, 0/0, -(2**53), 42, 1/0, -Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=591; tryItOut("\"use strict\"; /*RXUB*/var r = o2.r2; var s = s1; print(r.test(s)); ");
/*fuzzSeed-94431925*/count=592; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.fround(mathy1(Math.tanh(( + Math.round(x))), (( - (Math.cosh((x >>> 0)) >>> 0)) >>> 0))) >>> 0), (mathy2(Math.acos(( + Math.fround(Math.sin(Math.fround(x))))), Math.hypot(Math.log2(0x0ffffffff), -Number.MAX_VALUE)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-(2**53+2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, -0x080000000, 0/0, 1/0, 1, -0x07fffffff, -(2**53-2), 0x080000001, 0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, Math.PI, -1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, 0, -0, 42, 0x100000000, -0x100000001, -(2**53), 2**53, 0x07fffffff, 0x100000001, 0x080000000, 2**53+2]); ");
/*fuzzSeed-94431925*/count=593; tryItOut("\"use strict\"; a1.sort((function(j) { if (j) { v1 = Object.prototype.isPrototypeOf.call(v2, o1.b1); } else { try { g0.e2.delete(i1); } catch(e0) { } o1.v2 = Object.prototype.isPrototypeOf.call(o1, o2.i0); } }), b1)");
/*fuzzSeed-94431925*/count=594; tryItOut("f2.__iterator__ = (function() { try { g1.offThreadCompileScript(\"\\\"use strict\\\"; for(w in false) {a2 = a2.map((function() { a1.reverse(); throw o0.e0; }), i1, o1.g0.f2);return null; }\", ({ global: o0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 6 != 5), catchTermination: true })); } catch(e0) { } try { g1.m2.get(-7); } catch(e1) { } try { for (var p in s1) { try { s0 += s2; } catch(e0) { } try { g1.h1.__proto__ = m0; } catch(e1) { } try { for (var p in a2) { try { b1 + m2; } catch(e0) { } try { o2.a0.valueOf = (function() { print(uneval(i0)); return p2; }); } catch(e1) { } t0 = new Uint32Array(4); } } catch(e2) { } Array.prototype.reverse.apply(a1, []); } } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(g0.b1, g1.v1); return e0; });");
/*fuzzSeed-94431925*/count=595; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.clz32(((Math.cos(((((( ! x) >>> 0) && ( + ( - y))) >>> 0) >>> 0)) >>> 0) >>> 0)) | 0); }); testMathyFunction(mathy2, [0x07fffffff, -0x0ffffffff, 2**53-2, -0x100000001, 2**53, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -1/0, -0, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0x080000001, -Number.MIN_VALUE, 0, Number.MAX_VALUE, -0x080000001, -(2**53+2), 1.7976931348623157e308, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, 0x0ffffffff, -Number.MAX_VALUE, 0x100000001, -0x100000000, Number.MIN_VALUE, -(2**53), Math.PI, 1/0, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=596; tryItOut("mathy5 = (function(x, y) { return Math.imul(Math.tan(Math.pow(Math.fround((y , ( - Math.fround(10)))), ( ! y))), Math.fround(mathy0(Math.max((Math.log2(y) + (Math.pow(0x100000000, y) | 0)), Math.fround(( ! Math.fround((mathy4((( + Math.pow(( + (Math.max((y | 0), (y | 0)) | 0)), ( + y))) | 0), (c | 0)) | 0))))), (( ! ( + (( + Math.fround(mathy0(y, (Math.sign((x | 0)) | 0)))) | ( + 0.000000000000001)))) >>> 0)))); }); testMathyFunction(mathy5, [-1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0/0, 0, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, 1, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), 0x080000001, -0x07fffffff, -0x100000001, -0x100000000, 0x07fffffff, 0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, 42, -(2**53+2), -0x080000000, 2**53-2, Number.MIN_VALUE, -0x080000001, 0.000000000000001, 0x0ffffffff, 2**53, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=597; tryItOut("mathy0 = (function(x, y) { return ((( + Math.fround((Math.fround(( + (Math.max(((y >>> 0) < ( + y)), Math.atan2(y, (0 >>> 0))) ? ( + Math.acosh(y)) : Math.sign(Math.fround(y))))) / Math.fround((Math.tanh((Math.max((y >>> 0), y) >>> 0)) >>> 0))))) <= Math.max(Math.imul(Math.cbrt(( + x)), (y | 0)), ( + (Math.sinh((y | 0)) | 0)))) >= (Math.max(Math.tan((Number.MAX_SAFE_INTEGER | 0)), (Math.imul(y, x) === Math.pow((0x100000001 | 0), x))) >>> 0)); }); testMathyFunction(mathy0, [null, 1, false, (new Boolean(false)), (new Boolean(true)), true, '\\0', NaN, ({valueOf:function(){return '0';}}), (new Number(-0)), (function(){return 0;}), ({toString:function(){return '0';}}), [0], objectEmulatingUndefined(), '', 0, /0/, 0.1, (new Number(0)), undefined, '0', -0, ({valueOf:function(){return 0;}}), '/0/', (new String('')), []]); ");
/*fuzzSeed-94431925*/count=598; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( - (( ~ Math.tan(( - ( ~ y)))) % ( ~ Math.fround(( - (Math.atan((Math.hypot(y, y) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy2, [2**53-2, -0x0ffffffff, 42, 0x100000001, -0x07fffffff, -1/0, -0x080000001, -(2**53-2), -(2**53+2), 2**53+2, -0, 0x080000000, 1/0, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 0x080000001, -Number.MAX_VALUE, 0, -Number.MIN_VALUE, 0x0ffffffff, -0x100000001, 0/0, -0x100000000, -(2**53), 1, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=599; tryItOut("m0.get(t2);");
/*fuzzSeed-94431925*/count=600; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), -Number.MAX_VALUE, Number.MAX_VALUE, 0, -0x0ffffffff, 0/0, 0x080000000, 42, 1/0, 2**53-2, -(2**53-2), Math.PI, -1/0, -0, 2**53, 0.000000000000001, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 0x100000000, 2**53+2, 1, -0x100000001, -0x080000001, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=601; tryItOut("/*RXUB*/var r = /(?:(?!(?:(\\B{3})\\)|[\\d\\x63-\\u88E0\\W\\cT-\ue19f])|(?!\\cD)*|\\d${2,}|(?=^){1,2}|[^\\w\\uA49b\\u0013]*?)+/gim; var s = \"0\"; print(r.test(s)); ");
/*fuzzSeed-94431925*/count=602; tryItOut("v2 = (o1.o1 instanceof h2);");
/*fuzzSeed-94431925*/count=603; tryItOut("s0 += 'x';");
/*fuzzSeed-94431925*/count=604; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.min(mathy2(((( - ( - -0)) | 0) >>> mathy1(mathy1(y, Math.fround(x)), 0x080000000)), (Math.max((Math.atan2(x, Math.fround(Math.log2(Math.fround(x)))) | 0), (1/0 | 0)) | 0)), ( + Math.exp((((Math.abs(y) >>> 0) ^ ( + Math.fround(Math.log1p(Math.fround(Math.fround(mathy0(Math.fround(x), Math.fround(Number.MIN_SAFE_INTEGER)))))))) >>> 0)))) >>> 0) > Math.fround(Math.hypot(Math.expm1(Math.fround(Math.atan2(Math.fround((x ? x : -0x0ffffffff)), Math.fround(Math.sign((Math.max((y | 0), x) >>> 0)))))), Math.fround((0x100000001 % Math.fround(Math.hypot(x, Math.fround((( - (Math.tanh(x) | 0)) | 0))))))))); }); ");
/*fuzzSeed-94431925*/count=605; tryItOut("v1 = Object.prototype.isPrototypeOf.call(t2, m0);");
/*fuzzSeed-94431925*/count=606; tryItOut("\"use strict\"; print(uneval(o0));");
/*fuzzSeed-94431925*/count=607; tryItOut("this.v0 = evaluate(\"function f0(m0)  { /*tLoop*/for (let b of /*MARR*/[0/0]) { p0 + ''; } } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: x, catchTermination:  \"\"  }));");
/*fuzzSeed-94431925*/count=608; tryItOut("s0 = new String;");
/*fuzzSeed-94431925*/count=609; tryItOut("testMathyFunction(mathy4, /*MARR*/[w, w, w, w, w, /* no regression tests found */, -(2**53-2), /* no regression tests found */, -(2**53-2), w, /* no regression tests found */, w, -(2**53-2), -(2**53-2), -(2**53-2), w, w, /* no regression tests found */, w, /* no regression tests found */, /* no regression tests found */, /* no regression tests found */, w, -(2**53-2), -(2**53-2), /* no regression tests found */, -(2**53-2), w, -(2**53-2), w, w, w, w, -(2**53-2), -(2**53-2), /* no regression tests found */, w, /* no regression tests found */, -(2**53-2), -(2**53-2), /* no regression tests found */, w, /* no regression tests found */, -(2**53-2), w, /* no regression tests found */, w, w, -(2**53-2), w, -(2**53-2), -(2**53-2), /* no regression tests found */, -(2**53-2), w, w, /* no regression tests found */, w, -(2**53-2), w, w, -(2**53-2), w, w, -(2**53-2), /* no regression tests found */, -(2**53-2), -(2**53-2), w, /* no regression tests found */, w, /* no regression tests found */, -(2**53-2), /* no regression tests found */, -(2**53-2), /* no regression tests found */, /* no regression tests found */, -(2**53-2), w, -(2**53-2), /* no regression tests found */, /* no regression tests found */, /* no regression tests found */, -(2**53-2), -(2**53-2), -(2**53-2), w, -(2**53-2), /* no regression tests found */, w, w, /* no regression tests found */, /* no regression tests found */, -(2**53-2), -(2**53-2), -(2**53-2), /* no regression tests found */, w, -(2**53-2), -(2**53-2), w, /* no regression tests found */, w, -(2**53-2), w, w, w, /* no regression tests found */, w, -(2**53-2), /* no regression tests found */, -(2**53-2), w, -(2**53-2), -(2**53-2), /* no regression tests found */, w, -(2**53-2), /* no regression tests found */, w, /* no regression tests found */, -(2**53-2), /* no regression tests found */, w, -(2**53-2), -(2**53-2), -(2**53-2), /* no regression tests found */, w, -(2**53-2), w]); ");
/*fuzzSeed-94431925*/count=610; tryItOut("{}e1.delete(i2);");
/*fuzzSeed-94431925*/count=611; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (-((Float32ArrayView[(((((72057594037927940.0) < (-1.015625))-(0xffffffff))>>>((0x618b9392)-(/*FFI*/ff((((0x9d715b70) ? (-1.125) : (262145.0))), ((-36028797018963970.0)), ((-1.1805916207174113e+21)), ((17592186044415.0)), ((-1.5)), ((1023.0)), ((8589934591.0)), ((0.25)), ((-0.125)), ((-562949953421313.0)), ((-513.0)), ((-18446744073709552000.0)), ((-1048577.0)), ((67108865.0)), ((16385.0)), ((-562949953421313.0)), ((-17179869185.0)))|0))) / (((!(i1))-((0x56a59045) > (0x4b65fd7)))>>>(((-0x8000000) >= (0x693db8aa))-(i1)+(0xfcd533c3)))) >> 2])));\n    i2 = (!(0xb2ebac3));\n    d0 = (x);\n    {\n      {\n        i1 = (((((-((+(((0xa865f949)) << ((0x6230f114)))))) > (-147573952589676410000.0))+((((0x1598608b) % (((-0x8000000)) >> ((0xffffffff)))) | (((0x84186359))-(i2)-(0xc4554c81))))) | (((((0x27fb690c) == (0x215d8f89))+(0xf4bcbbf2)) << ((i1))) / (((i1)) >> (((0x1d20da27) != (0xc2e86a53))+(i1))))));\n      }\n    }\n    (Float64ArrayView[2]) = ((+((((i1)-(i2)))>>>((!((Int8ArrayView[2])))-((0xab3553ba) == ((((0xb379a3a8) != (0x2d72bc70))+(/*FFI*/ff()|0))>>>((i1)*-0xa56a2)))))));\n    i2 = ((((x >= 147500990)) << ((0xfc4347fb))) <= ((((~((Int16ArrayView[1]))) == ((-(i2))|0))-(0xa8b2427a)) << ((i2)-(!(-0x8000000))-(i1))));\n    return ((((2199023255553.0) <= (+pow(((144115188075855870.0)), ((+abs(((+/*FFI*/ff(((36893488147419103000.0)), (allocationMarker()), ((~~(1.9342813113834067e+25))), ((-9.671406556917033e+24)), ((-9007199254740992.0)))))))))))-(i1)))|0;\n    switch (((-0x3dfafd4))) {\n      case -1:\n        i1 = ((abs((~~(d0)))|0) < (0x456fed5d));\n        break;\n    }\n    switch ((0xfb102dc)) {\n    }\n    {\n      d0 = (Infinity);\n    }\n    i1 = (0xe1527758);\n    i1 = ((i1) ? ((~((-0x8000000)+(i2)+((0x6f7434d8))))) : (i2));\n    {\n      i1 = (i2);\n    }\n    return ((-0xcb974*(0xe67e1d33)))|0;\n  }\n  return f; })(this, {ff: (e, ...x) => eval(\"s2 += s0;\")}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x0ffffffff, -(2**53+2), -0, 0, Number.MAX_VALUE, -0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, -0x080000000, 0x080000001, 1/0, 2**53+2, -(2**53-2), 1, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, 0/0, -(2**53), Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 2**53-2, -0x07fffffff, 42, 2**53, -0x100000000, 0.000000000000001, 1.7976931348623157e308, Math.PI, 0x080000000]); ");
/*fuzzSeed-94431925*/count=612; tryItOut("mathy0 = (function(x, y) { return Math.fround(( - ( + ( + Math.fround(Math.fround(Math.atanh(Math.fround(y)))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, Math.PI, -0x100000000, 0x07fffffff, 1/0, 0x0ffffffff, -Number.MAX_VALUE, 0x100000001, 0x080000000, -0x07fffffff, -Number.MIN_VALUE, -(2**53-2), 0x100000000, -0x0ffffffff, 2**53+2, -1/0, 42, -Number.MAX_SAFE_INTEGER, -0x100000001, 0, -0x080000001, Number.MIN_VALUE, 0x080000001, 0/0, Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 1, -(2**53), 2**53, 2**53-2]); ");
/*fuzzSeed-94431925*/count=613; tryItOut("\"use strict\"; with(window){t0.set(a0, 8);v0 = true; }");
/*fuzzSeed-94431925*/count=614; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=615; tryItOut("/*infloop*/for(a in (/*UUV1*/(this.x.setInt32 = URIError))) {s0 = Array.prototype.join.call(a0, s1, v1, \u000c\u3056++());(throw -5); }");
/*fuzzSeed-94431925*/count=616; tryItOut("let bbpaii, b, x, dkvdde, window, c, e, johbyd, isdwix, idkfze;Array.prototype.splice.call(a0, -5, 3);");
/*fuzzSeed-94431925*/count=617; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x07fffffff, -0, 0x080000001, -0x100000000, 0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 1, -(2**53), Number.MIN_VALUE, -1/0, -Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 2**53, 0/0, 0x07fffffff, 1/0, 0.000000000000001, -0x0ffffffff, -0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, Math.PI, 0x100000000, -(2**53+2), 42, -0x100000001, -0x080000001]); ");
/*fuzzSeed-94431925*/count=618; tryItOut("\"use asm\"; print(x);");
/*fuzzSeed-94431925*/count=619; tryItOut("/*MXX2*/g1.URIError.prototype = g0;");
/*fuzzSeed-94431925*/count=620; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.fround(Math.fround((Math.fround(( ! Math.cos((( - (x | 0)) | 0)))) > Math.fround(( + Math.min(Math.PI, x))))))); }); ");
/*fuzzSeed-94431925*/count=621; tryItOut("o0.v0 = Object.prototype.isPrototypeOf.call(h1, f1);");
/*fuzzSeed-94431925*/count=622; tryItOut("/*infloop*/M:while(x = x <= \"\\u9547\"){var pfyagj = new SharedArrayBuffer(4); var pfyagj_0 = new Uint8ClampedArray(pfyagj); o1.m1.has(true);a2.unshift(g2.b1, s2); }");
/*fuzzSeed-94431925*/count=623; tryItOut("\"use strict\"; h0.fix = (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (-1.9342813113834067e+25);\n    {\n      i1 = ((((1073741825.0)) * ((d0))) > (-1025.0));\n    }\n    {\n      d0 = (-0.0009765625);\n    }\n    return +((d0));\n  }\n  return f; });");
/*fuzzSeed-94431925*/count=624; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=625; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=626; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy2(Math.expm1(( ~ (Math.fround(Math.log2(x)) >>> 0))), ( ~ Math.fround(( + Math.fround(Math.PI))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0x07fffffff, -0x080000000, 2**53-2, -0x100000000, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -(2**53), 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, -0, 1/0, 0x080000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, 42, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, Math.PI, -Number.MAX_VALUE, 1, 0x0ffffffff, 0x100000000, 0, -(2**53+2), -1/0]); ");
/*fuzzSeed-94431925*/count=627; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-94431925*/count=628; tryItOut("\"use strict\"; e2.add(m2);");
/*fuzzSeed-94431925*/count=629; tryItOut("mathy0 = (function(x, y) { return Math.hypot(Math.imul((Math.ceil(( + Math.max(( + x), ( + (Math.tan((-0x100000001 | 0)) | 0))))) >> ( - ((((y != Math.imul(x, x)) | 0) > (Math.ceil(x) | 0)) | 0))), ( ~ ( ! (x >>> 0)))), ( + Math.fround(Math.ceil(( + (Math.imul((y >>> 0), x) >>> 0)))))); }); ");
/*fuzzSeed-94431925*/count=630; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((( + (((Math.acos(0x080000001) | 0) ? Math.fround((( ~ (x >>> 0)) >>> 0)) : Math.fround((y >>> ( + ( - ( + 42)))))) | 0)) >>> 0) <= ((Math.imul(( + x), ( + ( + y))) | 0) ? (Math.atanh((( + (( + Math.fround(( + ( + ( ! ( + x)))))) % ( + Math.acos(y)))) >>> 0)) >>> 0) : (((x >>> 0) - (y | 0)) >>> 0))); }); testMathyFunction(mathy0, ['\\0', 1, (new String('')), true, 0, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '', [0], 0.1, (new Boolean(false)), null, /0/, NaN, undefined, '0', [], objectEmulatingUndefined(), (function(){return 0;}), '/0/', (new Number(0)), ({toString:function(){return '0';}}), -0, false, (new Boolean(true)), (new Number(-0))]); ");
/*fuzzSeed-94431925*/count=631; tryItOut("testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 0, 42, Number.MAX_VALUE, -(2**53-2), -(2**53), 0x080000000, 1/0, -0, -Number.MAX_VALUE, -0x080000000, -1/0, 2**53-2, 0.000000000000001, Math.PI, -0x100000001, -0x07fffffff, 0/0, -Number.MIN_VALUE, -(2**53+2), -0x100000000, -0x080000001, Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, 1, 0x100000001]); ");
/*fuzzSeed-94431925*/count=632; tryItOut("mathy2 = (function(x, y) { return Math.log2(mathy1(Math.clz32(( + Math.expm1(( + Math.pow((( + Math.cbrt(x)) >>> 0), (x >>> 0)))))), Math.min(x, mathy1(Math.pow(( + Math.imul(-Number.MAX_SAFE_INTEGER, Math.fround(x))), (x >>> 0)), (y === ( ! Math.acos(y))))))); }); testMathyFunction(mathy2, [2**53+2, 1, -0x080000001, 42, 0, 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), -0, -0x100000000, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -0x100000001, Number.MIN_VALUE, 0/0, -0x07fffffff, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 0x080000000, 0x080000001, 2**53, -Number.MIN_VALUE, 0x07fffffff, Math.PI, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=633; tryItOut("for (var p in s2) { try { this.e2.add(a2); } catch(e0) { } g1.v1 = undefined; }var okavrb = new SharedArrayBuffer(24); var okavrb_0 = new Float64Array(okavrb); okavrb_0[0] = Number.MAX_SAFE_INTEGER; yield 29;");
/*fuzzSeed-94431925*/count=634; tryItOut("/*oLoop*/for (kyrrot = 0; (this) && kyrrot < 38; ++kyrrot) { v1 = g0.runOffThreadScript(); } ");
/*fuzzSeed-94431925*/count=635; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (/*FFI*/ff(((d1)), ((~(((d1) > (+(0xcf92e41)))+(/*FFI*/ff(((0x573768a5)), ((imul((0xfdac4a08), (0xb2f6582b))|0)), ((((-1.9342813113834067e+25)) - ((((0x7b2c30b7)-(0xed844928)))))), ((((0x52c77050)) & ((0xc82fd6fe)))), ((+((549755813889.0)))), ((-4398046511105.0)), ((576460752303423500.0)), ((-32767.0)), ((576460752303423500.0)), ((17592186044417.0)), ((-63.0)), ((1.9342813113834067e+25)))|0)))), ((((i0)-(0x82a8cbf8)) << ((0x0) / ((-(-0x8000000))>>>((0x28a26032)))))), ((((d1)) - ((+abs(((-0.015625))))))), ((((d1)) / ((d1)))), (((imul((/*FFI*/ff(((-9.0)), ((-1.888946593147858e+22)), ((5.0)), ((288230376151711740.0)), ((9223372036854776000.0)), ((-70368744177665.0)), ((-536870913.0)))|0), (0xffffffff))|0))))|0);\n    }\n    return (((((0x55e29c69)) << ((i0)+((0xa5022448) ? (0x570945d0) : (-0x8000000)))) % (~(-(i0)))))|0;\n  }\n  return f; })(this, {ff: function  e ([], x)/*FARR*/[\"\\u3774\", ...[], new RegExp(\".{0}\", \"g\"),  /x/g , , this, ...[], -5].sort((function(x, y) { \"use strict\"; return y; }), -17) **= \"\\uBFA1\"}, new ArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=636; tryItOut("x;");
/*fuzzSeed-94431925*/count=637; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ (((Math.atan2((Math.atan(Math.fround(( ~ y))) >>> 0), (((( + Math.fround(( ~ x))) , ((Math.min((y >>> 0), (x >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0) && ( + Math.log1p(( + -(2**53))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), new Boolean(false), x, x, (-1/0), objectEmulatingUndefined(),  /x/g , (-1/0), (-1/0), x,  /x/g , new Boolean(false),  /x/g , objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Boolean(false), (-1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (-1/0), x,  /x/g , (-1/0),  /x/g , (-1/0),  /x/g ,  /x/g ,  /x/g , (-1/0), x, (-1/0), new Boolean(false), x, new Boolean(false), new Boolean(false),  /x/g , new Boolean(false), (-1/0), (-1/0), x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false),  /x/g , new Boolean(false), (-1/0), (-1/0),  /x/g ,  /x/g , new Boolean(false), (-1/0), objectEmulatingUndefined(), (-1/0), new Boolean(false), x]); ");
/*fuzzSeed-94431925*/count=638; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=639; tryItOut("\"use strict\"; g0.t2.set(o1.t1, ({valueOf: function() { L: print(x);return 13; }}));");
/*fuzzSeed-94431925*/count=640; tryItOut("var bniocs = new SharedArrayBuffer(2); var bniocs_0 = new Uint8Array(bniocs); bniocs_0[0] = 18; var bniocs_1 = new Uint8Array(bniocs); print(bniocs_1[0]); bniocs_1[0] = 25;  /x/ yield;/*RXUB*/var r = r1; var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=641; tryItOut("a1.forEach(g1.f0, o2);");
/*fuzzSeed-94431925*/count=642; tryItOut("m2 = Proxy.create(h1, t2);");
/*fuzzSeed-94431925*/count=643; tryItOut("v1 = r2.flags;");
/*fuzzSeed-94431925*/count=644; tryItOut("testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined()]); ");
/*fuzzSeed-94431925*/count=645; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.imul((Math.ceil(Math.cosh(mathy1(y, y))) >>> 0), ((( - (( ~ (( + Math.imul((y >>> 0), ( + y))) >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-94431925*/count=646; tryItOut("a1[2] = continue ;");
/*fuzzSeed-94431925*/count=647; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + mathy1(Math.fround(Math.atan2(Math.fround(Math.fround(Math.imul(( ~ (( - (42 | 0)) | 0)), ( + ( - ( ! Math.imul(y, -(2**53-2)))))))), (Math.fround(((((y | 0) << ( ~ x)) | 0) != (((y ? x : x) !== x) | 0))) != (Math.hypot((( + Math.hypot((Math.expm1((Math.atan2(x, (y | 0)) >>> 0)) >>> 0), ( + x))) | 0), (y | 0)) | 0)))), Math.fround(Math.atan2((x ** (( ~ ((Math.min(y, y) >>> 0) >>> 0)) >>> 0)), Math.fround((x ? Math.min(( + ( + ((y >= y) | 0))), Math.atan(0x100000001)) : Math.fround(mathy1((Math.asin(( + ((Number.MAX_VALUE * x) / x))) >>> 0), ( + x))))))))); }); testMathyFunction(mathy3, /*MARR*/[(-1/0), (void 0), (-1/0), (-1/0), (void 0), (void 0), (void 0), (void 0), (-1/0), (-1/0), (void 0), (void 0), (-1/0), (void 0), (-1/0), (void 0)]); ");
/*fuzzSeed-94431925*/count=648; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + ( + (Math.imul((Math.atan(Math.fround(( ! Math.fround(Math.fround(( ! (x && (x | 0)))))))) >>> 0), y) ** ((((((y >>> 0) - ((y === ( - y)) >>> 0)) >>> 0) >>> 0) >>> (Math.log2((x && x)) | 0)) | 0)))) >>> 0); }); ");
/*fuzzSeed-94431925*/count=649; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=650; tryItOut("testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, 2**53-2, Number.MAX_VALUE, 0x0ffffffff, 1, 2**53, -Number.MAX_VALUE, 42, -0x07fffffff, Number.MIN_VALUE, -1/0, 0, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, 0.000000000000001, 0x100000000, 1.7976931348623157e308, -(2**53), Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, -0x0ffffffff, 1/0, -0x100000001, -0x080000001, -(2**53+2), -0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, 0x080000001, -0x100000000, Math.PI]); ");
/*fuzzSeed-94431925*/count=651; tryItOut("this.e0.has( \"\" );var x, x, NaN = [1], d;e1.add(b2);");
/*fuzzSeed-94431925*/count=652; tryItOut("let v0 = b1.byteLength;");
/*fuzzSeed-94431925*/count=653; tryItOut("for (var v of p1) { g2.a0.unshift(v1, p0); }v1 = evaluate(\"function f2(e1) \\\"use asm\\\";   var cos = stdlib.Math.cos;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d0 = (d0);\\n    d0 = (d1);\\n    {\\n      d1 = (d0);\\n    }\\n    d0 = (+(-1.0/0.0));\\n;    {\\n      (Float64ArrayView[0]) = ((x));\\n    }\\n    d0 = (d1);\\n    d0 = ((d0) + (((((0xca53ff28)-(0x9722cae2)) >> ((0x2a3522fe)-(-0x8000000))) != (((-0x8000000)-(0xfe44d15b))|0)) ? (d1) : (d1)));\\n    (Int32ArrayView[((0xb27244a1)*0x4802d) >> 2]) = ((-0x8000000));\\n    return +((+cos(((d0)))));\\n    d0 = (d1);\\n    return +((d1));\\n  }\\n  return f;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: x, sourceIsLazy: false, catchTermination: false }));o2 = o2.m0.__proto__;");
/*fuzzSeed-94431925*/count=654; tryItOut("m1 + '';/*MXX2*/g0.Math.LOG2E = h0;");
/*fuzzSeed-94431925*/count=655; tryItOut("v1 = Object.prototype.isPrototypeOf.call(b1, h0);");
/*fuzzSeed-94431925*/count=656; tryItOut("mathy5 = (function(x, y) { return Math.ceil(( + Math.asin((( + (( + (1.7976931348623157e308 + y)) , ( + ( ! y)))) >>> 0)))); }); testMathyFunction(mathy5, [2**53+2, -0x100000000, 0/0, -0x100000001, -0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, 1, 2**53-2, -1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 1/0, Math.PI, 42, 0x0ffffffff, -0x080000000, 0x080000001, 0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -0, 0x080000000, Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 0, -Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001]); ");
/*fuzzSeed-94431925*/count=657; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.atan2((( - Math.fround((Math.exp((x >>> 0)) >>> 0))) >>> 0), (( + ( ! Math.fround(( + ( + Math.atan2(( + mathy0(Math.pow(x, y), 2**53+2)), ( + y))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, 0x100000000, 1/0, 0.000000000000001, 0/0, 0x0ffffffff, 0x100000001, 42, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 1, -0, -1/0, -Number.MIN_VALUE, 2**53, -0x100000000, Math.PI, -(2**53), -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, -0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-94431925*/count=658; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ (Math.asinh(((((( - (Math.cbrt(Math.fround(y)) >>> 0)) | 0) >>> 0) | ( + Math.hypot(x, (Math.acos(( + x)) , Math.atan(-(2**53)))))) >>> 0)) | 0)); }); testMathyFunction(mathy4, [Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 42, 0x07fffffff, -0x0ffffffff, -0x07fffffff, 1/0, -Number.MAX_VALUE, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, -1/0, -0x080000001, -(2**53+2), 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, 2**53+2, Number.MIN_VALUE, -(2**53), 2**53, 2**53-2, 0/0, 0x100000000, 1, -0x080000000, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-94431925*/count=659; tryItOut("\"use strict\"; (this.__defineSetter__(\"y\", neuter));");
/*fuzzSeed-94431925*/count=660; tryItOut("\"use strict\"; \"use asm\"; t2.set(o1.a0, ({valueOf: function() { m0.get(new RegExp(\"(.)+?(?=^|(?:[^])[^])(?:([^])){0,0}+\", \"yim\"));return 10; }}));");
/*fuzzSeed-94431925*/count=661; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MAX_VALUE, 0/0, -0x100000001, 2**53-2, 0, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -0x07fffffff, 42, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0x07fffffff, 1, -0, -(2**53+2), 0x100000001, 1/0, Math.PI, -(2**53-2), -0x080000000, -1/0, -0x100000000, 0.000000000000001, 0x0ffffffff, 2**53+2, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=662; tryItOut("mathy1 = (function(x, y) { return (((( ~ (( ~ (x >>> 0)) >>> 0)) | 0) >>> mathy0(Math.fround(((Math.atanh(y) ** ((Number.MAX_VALUE != y) | 0)) | 0)), Math.fround(Math.fround(mathy0((y >>> 0), (y >>> 0)))))) >= Math.pow((Math.max(Math.fround(-(2**53)), Math.fround(mathy0((mathy0(( + y), ( + y)) | 0), x))) | 0), Math.cosh(-(2**53-2)))); }); testMathyFunction(mathy1, /*MARR*/[-Infinity, -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), -Infinity, -Infinity, -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new String('q'), new String('q'), new String('q'), new String('q'), -Infinity, -Infinity, new String('q'), -Infinity, new String('q'), new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), -Infinity, new String('q'), new String('q'), new String('q'), -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, new String('q'), new String('q'), new String('q'), new String('q'), -Infinity, new String('q'), new String('q'), new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, new String('q'), -Infinity, new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, new String('q'), new String('q'), new String('q'), new String('q'), -Infinity, -Infinity, -Infinity, new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, -Infinity, -Infinity, new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), -Infinity, -Infinity, -Infinity, new String('q')]); ");
/*fuzzSeed-94431925*/count=663; tryItOut("\"use strict\"; this.e1.has((4277));");
/*fuzzSeed-94431925*/count=664; tryItOut("\"use strict\"; var o0 = new Object;");
/*fuzzSeed-94431925*/count=665; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + ((( ~ Math.asinh((x | 0))) % Math.fround(y)) >> (Math.log10((Math.pow((Math.imul((Math.imul(y, x) >>> 0), ((y ? y : y) >>> 0)) >>> 0), Math.atan2(Number.MIN_VALUE, (x >>> 0))) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), -(2**53+2), Math.PI, 0x07fffffff, 0x0ffffffff, 0x080000000, -(2**53), 1, 0x080000001, -0x080000000, Number.MAX_VALUE, 0x100000001, -1/0, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000001, -0, -0x07fffffff, 1/0, 2**53-2, 42, 0, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, 2**53, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=666; tryItOut("Array.prototype.forEach.call(this.a0, (function() { try { a1 = arguments; } catch(e0) { } a2.pop(o0.g2, f2, a2); return o1.o0; }));");
/*fuzzSeed-94431925*/count=667; tryItOut("mathy3 = (function(x, y) { return ( + Math.fround(Math.log10((((x , (x | 0)) | 0) / Math.log(x))))); }); testMathyFunction(mathy3, [0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, 2**53, 0x100000000, 2**53-2, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -Number.MIN_VALUE, Math.PI, 0x0ffffffff, 1/0, -0x100000001, -0, 42, Number.MIN_VALUE, 0, -0x080000000, -1/0, 0x080000001, -(2**53), -Number.MAX_VALUE, -0x100000000, -0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, -0x07fffffff, 0x100000001]); ");
/*fuzzSeed-94431925*/count=668; tryItOut("m2 = new Map(v1);\nArray.prototype.pop.apply(this.a0, []);\n");
/*fuzzSeed-94431925*/count=669; tryItOut("\"use strict\"; /*oLoop*/for (qzhocj = 0; qzhocj < 102; ++qzhocj) { print(timeout(1800)); } ");
/*fuzzSeed-94431925*/count=670; tryItOut("testMathyFunction(mathy3, [0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -0x080000000, 42, 2**53-2, 0/0, 1/0, -(2**53+2), 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1, 0x100000001, -0x080000001, 2**53, 2**53+2, -Number.MIN_VALUE, -0x100000001, 0x080000000, 0x100000000, -1/0, -(2**53-2), 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, -(2**53), Number.MAX_VALUE, -0, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=671; tryItOut("\"use strict\";  \"\" ;(x);");
/*fuzzSeed-94431925*/count=672; tryItOut("\"use strict\"; Array.prototype.forEach.call(a0, (function(j) { if (j) { try { /*RXUB*/var r = r0; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex);  } catch(e0) { } try { this.s0 = ''; } catch(e1) { } Object.freeze(b0); } else { try { o1.s2 = ''; } catch(e0) { } s0 += s2; } }));");
/*fuzzSeed-94431925*/count=673; tryItOut("v1 = a1.length;");
/*fuzzSeed-94431925*/count=674; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0/0, 1, 2**53, -0x0ffffffff, -(2**53), -0, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, Math.PI, 1.7976931348623157e308, -0x080000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), -0x07fffffff, 0x0ffffffff, 0.000000000000001, -0x080000000, -Number.MIN_VALUE, 42, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=675; tryItOut("/*vLoop*/for (var dlhtwb = 0; dlhtwb < 109; ++dlhtwb) { const e = dlhtwb; let (w, x, x, NaN, x, eval, e) /\\b/yim; } \nArray.prototype.reverse.apply(o0.a0, [x]);\n");
/*fuzzSeed-94431925*/count=676; tryItOut("r2 = new RegExp(\"(?:\\\\B\\\\w+)*|(\\\\S*?)*\", \"gm\");");
/*fuzzSeed-94431925*/count=677; tryItOut("Array.prototype.splice.call(a0, NaN, v0, o0, i2, a2);");
/*fuzzSeed-94431925*/count=678; tryItOut("mathy0 = (function(x, y) { return Math.atan2((Math.sqrt((((((( ! y) | 0) >>> 0) <= (( ! y) >>> 0)) >>> 0) | 0)) | 0), Math.expm1(Math.atan(x))); }); testMathyFunction(mathy0, [-0x080000000, 0x100000000, Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0, 42, 2**53, 0x0ffffffff, 1, -(2**53), -(2**53+2), -(2**53-2), 0x080000001, 1.7976931348623157e308, 0, -1/0, Math.PI, -0x07fffffff, -0x0ffffffff, 0x100000001, -0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -0x100000001, 0.000000000000001, 2**53+2, Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=679; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.sinh((Math.log(( + ( + y))) ^ ((((Math.cbrt(y) | 0) | 0) , (((((( ~ Number.MAX_SAFE_INTEGER) >>> 0) , 0) >>> 0) ** x) | 0)) | 0)))); }); testMathyFunction(mathy0, [Math.PI, 2**53+2, -0x100000001, 1/0, 0/0, -0x100000000, 0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, 2**53, 1.7976931348623157e308, -0x080000000, 1, 2**53-2, -(2**53-2), -(2**53), -0x080000001, -Number.MIN_VALUE, -0, -0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 42, 0x080000001, 0.000000000000001, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=680; tryItOut("a1.valueOf = (function() { try { for (var p in v1) { try { selectforgc(o2); } catch(e0) { } for (var v of t2) { try { g1.toSource = (function() { try { v0 = evalcx(\"a0.reverse();\", g0); } catch(e0) { } try { i0 = e0.entries; } catch(e1) { } try { this.a0.reverse(i0); } catch(e2) { } v2 = a1.length; return b2; }); } catch(e0) { } try { Array.prototype.unshift.apply(a1, []); } catch(e1) { } h0.valueOf = (function(j) { if (j) { try { m1.set(x, o2); } catch(e0) { } try { e2 = new Set(b1); } catch(e1) { } this.s1 += 'x'; } else { try { /*MXX1*/g0.o0 = g1.Date.prototype.getDate; } catch(e0) { } m1 = this.o0.a2[\"\\u9E7B\"]; } }); } } } catch(e0) { } try { a0.splice(NaN, ({valueOf: function() { v2 = (v1 instanceof g2);return 12; }}), b1, s0); } catch(e1) { } ; return b2; });\nv1 = (b2 instanceof a1);\n");
/*fuzzSeed-94431925*/count=681; tryItOut("mathy5 = (function(x, y) { return Math.atan2(Math.fround(Math.hypot(Math.fround(mathy4(mathy0(y, Math.cos(Math.hypot(x, -0x100000001))), Math.acos(Math.fround(( ! ( + y)))))), (mathy1((( ! (Math.atan(y) >>> 0)) >>> 0), (Math.fround((0.000000000000001 | 0)) | 0)) >>> 0))), Math.atan(Math.pow(((Math.abs(((Math.sign(y) >>> 0) | 0)) | 0) >>> 0), (y >>> 0)))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000000, -Number.MIN_VALUE, -0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, 1/0, -Number.MAX_SAFE_INTEGER, -0, 0x080000000, -0x07fffffff, 42, 0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0.000000000000001, 0x100000001, 0x07fffffff, 0x080000001, 2**53, -(2**53), 0, -0x100000000, 1, Math.PI, -0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), 1.7976931348623157e308, -1/0, -0x080000000]); ");
/*fuzzSeed-94431925*/count=682; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1\\S(?=.)|$[\\\u4556-\u8dec]/gm; var s = \"\\n\\u4556\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=683; tryItOut("m0.has(t0);");
/*fuzzSeed-94431925*/count=684; tryItOut("var kdqdca = new SharedArrayBuffer(0); var kdqdca_0 = new Uint8ClampedArray(kdqdca); kdqdca_0[0] = -18; var kdqdca_1 = new Int16Array(kdqdca); kdqdca_1[0] = 5; var kdqdca_2 = new Uint16Array(kdqdca); kdqdca_2[0] = -0; var kdqdca_3 = new Int16Array(kdqdca); kdqdca_3[0] = 16; g2.m1 + '';print(kdqdca_2[1]);o2.s1 += 'x';m2.delete(v2);");
/*fuzzSeed-94431925*/count=685; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=686; tryItOut("\"use strict\"; /*infloop*/L:do /*bLoop*/for (let sjutcc = 0; sjutcc < 134 && ((function ([y]) { })()); ++sjutcc) { if (sjutcc % 6 == 0) { r0 = new RegExp(\"(?:(?:.(?=\\\\D|[^\\\\u2e3D\\u00dd-\\\\u0060]|$+)*?))\", \"i\"); } else { print(x);\n;\n }  } \na0.push(g0, m2, b1, this.t0, e0, t0, (void options('strict')));\n while(\u000c((void version(185))));");
/*fuzzSeed-94431925*/count=687; tryItOut("testMathyFunction(mathy4, [-0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, 0, -0x0ffffffff, 42, 0/0, -0, -0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, 0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, 0x100000001, 1, -Number.MAX_VALUE, Number.MAX_VALUE, -0x080000001, 0x07fffffff, -1/0, 0x080000000, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-94431925*/count=688; tryItOut(";\nv2 = r1.compile;\n");
/*fuzzSeed-94431925*/count=689; tryItOut("\"use asm\"; g1.offThreadCompileScript(\"\\\"use strict\\\"; a0.sort((function() { for (var j=0;j<17;++j) { f0(j%3==1); } }), b2, s1);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 26 == 12), noScriptRval: (x % 39 == 33), sourceIsLazy: true, catchTermination: new Boolean(true) }));");
/*fuzzSeed-94431925*/count=690; tryItOut("");
/*fuzzSeed-94431925*/count=691; tryItOut("/*RXUB*/var r = /$/yi; var s = \"\\n\\ufd48\"; print(s.replace(r, 'x', \"gym\")); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=692; tryItOut("h0 = {};");
/*fuzzSeed-94431925*/count=693; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=694; tryItOut("o2.i2 = a0.keys;");
/*fuzzSeed-94431925*/count=695; tryItOut("\"use strict\"; g2.v0 + '';");
/*fuzzSeed-94431925*/count=696; tryItOut("s1 += 'x';");
/*fuzzSeed-94431925*/count=697; tryItOut("testMathyFunction(mathy1, [1, 2**53, -Number.MIN_VALUE, -0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), -0x0ffffffff, 1.7976931348623157e308, 0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, 42, 2**53+2, -0x100000000, 1/0, Number.MAX_VALUE, 0, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, -(2**53+2), -0, 0.000000000000001, 0x100000000, 2**53-2]); ");
/*fuzzSeed-94431925*/count=698; tryItOut("/*oLoop*/for (var rumajh = 0, necrvx, btprzy; rumajh < 127;  \"\" , ++rumajh) { /*MXX3*/g1.Uint32Array.prototype.constructor = g1.Uint32Array.prototype.constructor; } ");
/*fuzzSeed-94431925*/count=699; tryItOut("t2.toString = (function() { try { e1.has(p2); } catch(e0) { } try { v1 = evaluate(\"function f0(p0)  { yield Math.pow(22, 21) } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (yield -6), noScriptRval: false, sourceIsLazy: false, catchTermination: false })); } catch(e1) { } try { a2.reverse(); } catch(e2) { } for (var v of p2) { try { m1 = new Map; } catch(e0) { } Array.prototype.sort.call(o0.a1, f0); } return a2; });");
/*fuzzSeed-94431925*/count=700; tryItOut("");
/*fuzzSeed-94431925*/count=701; tryItOut("\"use strict\"; m2.toString = DataView.prototype.getInt32.bind(s0);function Math.atan() { \"use strict\"; /*RXUB*/var r = new RegExp(\"^|(?:\\\\1)?{0,}\", \"gym\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex);  } ");
/*fuzzSeed-94431925*/count=702; tryItOut("\"use strict\"; \"use asm\"; v0 = evaluate(\"Object.prototype.unwatch.call(t1, \\\"arguments\\\");\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 == 3), sourceIsLazy: true, catchTermination: (x % 78 != 75), element: o2, elementAttributeName: s1, sourceMapURL: s1 }));");
/*fuzzSeed-94431925*/count=703; tryItOut("var a = /*FARR*/[.../*FARR*/[\"\\u2874\", -20, ...[], window, ...[]], .../*FARR*/[], ((void version(170)))].filter(x);;");
/*fuzzSeed-94431925*/count=704; tryItOut("v0 = this.r1.constructor;");
/*fuzzSeed-94431925*/count=705; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, -0x080000001, 0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, 0x0ffffffff, 2**53, -Number.MAX_VALUE, -(2**53), 0/0, Number.MIN_VALUE, 42, -0x0ffffffff, -0, 2**53+2, -0x100000000, 0x100000001, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 2**53-2, -0x100000001, 0, Math.PI, -0x080000000, -Number.MIN_VALUE, -(2**53+2), 1]); ");
/*fuzzSeed-94431925*/count=706; tryItOut("/*RXUB*/var r = r1; var s = \"a\"; print(s.match(r)); ");
/*fuzzSeed-94431925*/count=707; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=708; tryItOut("/*infloop*/for(window; intern(x(((new SharedArrayBuffer()).__proto__ = x), (function(q) { \"use strict\"; return q; }.prototype))); /*FARR*/[x.getMilliseconds(Object.defineProperty(e, \"call\", ({configurable: (x % 21 == 4), enumerable: (x % 2 == 1)}))), x, Math.hypot(10, (Math.cos(\"\u03a0\"))) >= (4277).prototype, ].sort(RangeError.prototype.toString, this.__defineGetter__(\"w\", (-3).apply))) {/*RXUB*/var r = r0; var s = s2; print(s.replace(r, '', \"gim\")); \u000c((yield [])); }");
/*fuzzSeed-94431925*/count=709; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=710; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"([^]){0,}|(?!\\\\d)[^]*{3}(?=(?:(\\\\\\u00ef)))(?:.\\\\W+?(?!\\\\3))|\\\\D{2,68719476739}$*(?!.|[\\\\cC\\\\xa7]*)(?:(?=\\\\W)+)?[^]{3,}*?\", \"gm\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=711; tryItOut("/*infloop*/while((x = false)){-11; }");
/*fuzzSeed-94431925*/count=712; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.max(( ~ ( ~ (Math.hypot((x | 0), (0 | 0)) | 0))), Math.fround(Math.sin(((mathy1((Math.tanh(((( - y) > -Number.MAX_VALUE) ? y : x)) | 0), (Math.pow((( - x) >>> 0), Math.sqrt((x | 0))) >>> 0)) >>> 0) | 0)))); }); ");
/*fuzzSeed-94431925*/count=713; tryItOut("\"use strict\"; g2.v0 = a1.every((function(j) { g1.f1(j); }), t1, t0);");
/*fuzzSeed-94431925*/count=714; tryItOut("testMathyFunction(mathy0, [Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), 0x0ffffffff, 0x07fffffff, -(2**53-2), 1.7976931348623157e308, -0x080000001, Math.PI, 1, 2**53-2, -0, -0x0ffffffff, 0.000000000000001, 0x080000000, 0x100000001, 1/0, -1/0, 0/0, -Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, -0x100000000, 2**53, -0x100000001, 0, -Number.MAX_VALUE, -(2**53), 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-94431925*/count=715; tryItOut("for (var p in o0) { try { m1.get(v2); } catch(e0) { } try { o1.s2 += s2; } catch(e1) { } try { o1.o1 = new Object; } catch(e2) { } this.v2 = g1.eval(\"x\"); }");
/*fuzzSeed-94431925*/count=716; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + ((( - (( ~ Math.fround(Math.pow(-(2**53-2), ( + ( ! ( + y)))))) >>> 0)) ? (( - (Math.fround(Math.fround(Math.fround(2**53-2))) >>> 0)) >>> 0) : y) ? (((( - x) / (( ! ( + x)) >>> 0)) >>> 0) % ( + Math.atan2(( + Math.cbrt(-(2**53))), (( - Math.fround(y)) | 0)))) : (-0x080000000 , ( + (( + ((x * 1) << (y | 0))) , ( + Math.sqrt(( + 0x0ffffffff)))))))) / ( ! ( + ( + (( ! ( ~ ( + -0x0ffffffff))) >>> 0))))); }); ");
/*fuzzSeed-94431925*/count=717; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return Math.pow(Math.fround((( + Math.tanh(( + Math.atan2((Math.PI >>> 0), Math.acosh(-0))))) , (Math.fround((Math.max(-0x07fffffff, x) ? ((0 ^ (x | 0)) | 0) : (((Math.atanh(2**53-2) >>> 0) + (-0 >>> 0)) >>> 0))) <= (0x07fffffff | 0)))), Math.fround(( + ( ~ ( + (( - (x >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [0/0, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -0x080000001, -(2**53+2), 2**53+2, 0x100000000, Math.PI, Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 42, -(2**53), 2**53-2, -0x080000000, -Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, 0x080000000, 1/0, 0x080000001, -0, -1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=718; tryItOut("\"use strict\"; v1 = g0.eval(\"function f1(this.s0)  { yield (p={}, (p.z =  /x/ )()) | new (Math.hypot(-7, 26))() } \");");
/*fuzzSeed-94431925*/count=719; tryItOut("h1.fix = (function(j) { if (j) { try { a2.push(this.g0); } catch(e0) { } try { s1 = new String; } catch(e1) { } this.m1.has(o2); } else { a2 = new Array; } });L:if(false) {\"\\uE462\";print(new RegExp(\"\\\\2+?\", \"\")); } else  if (false) print(uneval(i0)); else {v2 = g2.eval(\"a2.unshift(v0, s2);\");yield; }\ns0 += 'x';\n\n/*RXUB*/var r = new RegExp(\"(?:((?:\\\\f|[^]*{3,})))\", \"gyim\"); var s = \"\\n\\n\\u000c\\n\\n\\n\\n\\n\\n\\n\\u000c\\u000c\\u000c\\u000c\"; print(uneval(s.match(r))); \n");
/*fuzzSeed-94431925*/count=720; tryItOut("testMathyFunction(mathy1, [-0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -0x100000000, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, Math.PI, 2**53, 2**53-2, 0/0, -Number.MAX_VALUE, Number.MIN_VALUE, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0x080000000, -0x080000000, -Number.MIN_VALUE, 1, 0, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, -(2**53+2), -0x0ffffffff, 0x100000001, Number.MAX_VALUE, -0, 42, -(2**53)]); ");
/*fuzzSeed-94431925*/count=721; tryItOut("t1[13] = p1;");
/*fuzzSeed-94431925*/count=722; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=723; tryItOut("/*MXX2*/g1.Object.setPrototypeOf = t2;");
/*fuzzSeed-94431925*/count=724; tryItOut("\"use strict\"; v0 = evaluate(\"v0 = this.t0.byteLength;\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 != 2), noScriptRval: true, sourceIsLazy: x, catchTermination: false }));");
/*fuzzSeed-94431925*/count=725; tryItOut("mathy5 = (function(x, y) { return ( ~ (( - x) ? ( + (( + Math.atan2(Math.ceil(Math.fround(Math.pow((x | 0), y))), (Math.asin((-(2**53) | 0)) >>> 0))) || ( + (Math.pow(((((y >>> 0) - (x >>> 0)) >>> 0) | 0), ((((Math.tanh(x) | 0) > y) | 0) | 0)) | 0)))) : Math.fround(( + Math.fround(( ~ x)))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x07fffffff, -1/0, -0x080000000, -0x0ffffffff, -0x100000001, 2**53-2, 0, -(2**53-2), 1/0, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, 1, 0x080000000, 0/0, 2**53, 0x100000001, 42, 0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), -Number.MAX_VALUE, -0x07fffffff, -0x080000001, 0x100000000, -(2**53+2), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -0]); ");
/*fuzzSeed-94431925*/count=726; tryItOut("\"use asm\"; i2.send(i2);");
/*fuzzSeed-94431925*/count=727; tryItOut("s0 + h0;");
/*fuzzSeed-94431925*/count=728; tryItOut("mathy4 = (function(x, y) { return (Math.clz32((Math.fround(( + Math.fround(((Math.hypot(x, mathy1(x, Number.MIN_VALUE)) >>> 0) ? Math.fround(y) : ( + x))))) >>> 0)) / Math.fround(( - ((-0x100000001 && (( - ( + Math.log2(((mathy0(x, y) >>> 0) >>> 0)))) | 0)) >>> 0)))); }); testMathyFunction(mathy4, [-0x07fffffff, -(2**53+2), 0x100000000, -Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), -0x100000000, -0x080000001, -1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, -0x080000000, Number.MIN_VALUE, 42, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, 2**53-2, 0x07fffffff, 0/0, -(2**53), 1.7976931348623157e308, 0, 1/0, 0x100000001, 1]); ");
/*fuzzSeed-94431925*/count=729; tryItOut("function shapeyConstructor(yprnum){if (Object.defineProperty(x, 7, ({set: (1 for (x in []))}))) this[\"match\"] = decodeURIComponent;this[\"match\"] = new Boolean(false);this[\"match\"] = NaN;if (yprnum) delete this[\"match\"];if ((new RegExp(\"\\\\1\", \"im\") ? \"\\uC355\" : undefined)) this[-9] = function(y) { return (({e: (4277)})) }.prototype;this[\"match\"] = ++a;for (var ytqptyduf in this) { }this[\"match\"] = (-1);return this; }/*tLoopC*/for (let e of (function() { \"use strict\"; yield let (x, NaN, mvuofo, blgghj) eval && x; } })()) { try{let neoiug = shapeyConstructor(e); print('EETT'); v1 = a0.some(this.f1, f2, a0);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-94431925*/count=730; tryItOut("mathy3 = (function(x, y) { return Math.pow((Math.log1p((Math.hypot(( + ( - (( ! Math.fround(( + Math.min((y >>> 0), (( + Math.pow(y, ( + Number.MAX_VALUE))) >>> 0))))) >>> 0))), ( ! (Number.MAX_SAFE_INTEGER >>> 0))) >>> 0)) >>> 0), ( + Math.cos(x))); }); ");
/*fuzzSeed-94431925*/count=731; tryItOut("s0 += s1;");
/*fuzzSeed-94431925*/count=732; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ! (Math.max((( - Math.fround((y - y))) >>> 0), ((( - Math.min((-(2**53-2) || ( + y)), x)) | 0) >>> -Number.MIN_SAFE_INTEGER)) | 0)) / (( + Math.hypot((Math.imul(Math.fround(Math.fround(( + Math.fround(-0x100000001)))), x) >>> 0), Math.min(( + ( ~ ( + (Math.imul((y >>> 0), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)))), (Math.pow((y >>> 0), (((y >= y) < ((x >>> 0) ? x : y)) >>> 0)) | 0)))) | 0)); }); testMathyFunction(mathy0, ['0', '\\0', -0, (new Number(-0)), objectEmulatingUndefined(), false, null, 0, (new Number(0)), 1, (function(){return 0;}), /0/, undefined, (new String('')), 0.1, (new Boolean(true)), NaN, '/0/', [], true, ({valueOf:function(){return '0';}}), [0], '', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Boolean(false))]); ");
/*fuzzSeed-94431925*/count=733; tryItOut(";");
/*fuzzSeed-94431925*/count=734; tryItOut("v2 = (o1.f2 instanceof e1);");
/*fuzzSeed-94431925*/count=735; tryItOut("\"use strict\"; L:for(z in ((function (y)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i1 = (i3);\n    i3 = (i0);\n    i1 = (i3);\n    return ((0x15b5*((((((-0x8000000)+(0x865a819c)-(0xffffffff))>>>((-0x8000000)+(0x21b54313)-(0xfadbbd23))) % (((0xe65043b7)+(0x186d5923)+(-0x8000000))>>>((i3)+(i1))))>>>((i0))))))|0;\n  }\n  return f;)((new (4277)(x, true))))){Array.prototype.valuesv0 = o2[\"constructor\"]; }");
/*fuzzSeed-94431925*/count=736; tryItOut("mathy2 = (function(x, y) { return Math.log(( ! ((( + ( - Math.acosh(x))) << mathy0(y, x)) % x))); }); testMathyFunction(mathy2, [false, (new Number(0)), (new Boolean(false)), '\\0', '/0/', [0], true, null, (new Number(-0)), (new Boolean(true)), NaN, 0.1, ({toString:function(){return '0';}}), (new String('')), objectEmulatingUndefined(), /0/, undefined, ({valueOf:function(){return 0;}}), '0', 0, 1, [], (function(){return 0;}), '', ({valueOf:function(){return '0';}}), -0]); ");
/*fuzzSeed-94431925*/count=737; tryItOut("\"use strict\"; for(d in (((this.__defineSetter__(\"z\", /*wrap2*/(function(){ \"use strict\"; var nbsudz =  /x/g ; var jolexz = arguments.callee.caller; return jolexz;})())).call)(allocationMarker()))){{var deracr, mqatsh, mzqdip, window, d, w, hjjcxh, y;print(/([\\D\\s]+)(?!.)|[\\x2D\u0d41-\uc5dc\u00ab]/im); }function x(\u3056 = ({b: []} = []))(a.unwatch(\"toString\"))break ;/*vLoop*/for (var sjfuaw = 0; sjfuaw < 57; ++sjfuaw) { var w = sjfuaw; a2.__proto__ = t0; }  }");
/*fuzzSeed-94431925*/count=738; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(( - Math.fround((Math.tanh(( + Math.ceil((( ! y) >>> 0)))) >>> 0)))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 2**53+2, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, -1/0, -0x080000001, 0, Number.MAX_VALUE, -0x07fffffff, Math.PI, -(2**53), 0x100000001, 0x080000000, -0x100000000, 0x07fffffff, 0/0, 0x100000000, -Number.MIN_VALUE, 2**53-2, -0x080000000, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -0, 0x080000001, 1/0]); ");
/*fuzzSeed-94431925*/count=739; tryItOut("\"use strict\"; g2.h1.getOwnPropertyNames = f0;");
/*fuzzSeed-94431925*/count=740; tryItOut("v0 = new Number(m2);");
/*fuzzSeed-94431925*/count=741; tryItOut("\"use strict\"; o1 = g0.__proto__;");
/*fuzzSeed-94431925*/count=742; tryItOut("\"use strict\"; Array.prototype.push.apply(a0, []);function y(w)\"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -18014398509481984.0;\n    i0 = (i1);\n    i0 = ((imul((((((0xba757c55)))>>>((0x44ce7553)+(0x23658cca)-(0xd0dfc62f))) <= ((0x890ce*((0x58ded5ca) > (0x3c943888)))>>>((-0x8000000) % (0x6f86b019)))), (i0))|0) == (abs(((((~(-0xe53e3*((0x461d99c0) == (0xffffffff))))))|0))|0));\n    d2 = (((-63.0)) * ((d2)));\n    d2 = (+pow(((d2)), ((-73786976294838210000.0))));\n    (Uint32ArrayView[((((0xe3a4979e) % (0x444bbca))>>>((i1)*0xb71a8)) / (((i0))>>>((0x481985c9)))) >> 2]) = ((i1));\n    return (((0xffffffff)))|0;\n  }\n  return f;/*bLoop*/for (var uvbcko = 0; uvbcko < 10; ++uvbcko) { if (uvbcko % 5 == 1) { f0 = this.t2[v2]; } else { v1 = Object.prototype.isPrototypeOf.call(p0, g1.e1); }  } ");
/*fuzzSeed-94431925*/count=743; tryItOut("testMathyFunction(mathy1, [-0, (new Number(0)), NaN, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), '', [], null, true, '0', 0.1, [0], objectEmulatingUndefined(), (new Boolean(false)), 1, (new String('')), '\\0', /0/, undefined, false, '/0/', (new Number(-0)), (new Boolean(true)), (function(){return 0;}), 0]); ");
/*fuzzSeed-94431925*/count=744; tryItOut("switch((uneval(false))) { case 4:  }");
/*fuzzSeed-94431925*/count=745; tryItOut("\"use strict\"; o0.v0 = false;");
/*fuzzSeed-94431925*/count=746; tryItOut("i0 + '';");
/*fuzzSeed-94431925*/count=747; tryItOut("t2 = t0.subarray(({valueOf: function() { /*ODP-2*/Object.defineProperty(g2, new String(\"9\"), { configurable: (x % 10 != 3), enumerable: (x % 5 != 0), get: SharedArrayBuffer.prototype.slice.bind(v1), set: g1.f1 });return 4; }}), 17);");
/*fuzzSeed-94431925*/count=748; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return mathy0((( + ((((( ~ ( + 1.7976931348623157e308)) >>> 0) == (Math.asin(0.000000000000001) > ( - Math.fround(x)))) >>> 0) >>> 0)) | 0), (( + Math.atan2(( + ( - 0/0)), ( + (mathy1(( + ((x <= y) >>> 0)), (y >>> 0)) >>> 0)))) ? Math.hypot(Math.fround((Math.fround(x) > Math.fround((-Number.MAX_SAFE_INTEGER ** mathy0(((( + x) , -(2**53-2)) | 0), x))))), Math.fround(( + (( + y) ^ ( + ( + (( + ( + (( + y) + ( + -(2**53+2))))) && -(2**53-2)))))))) : Math.fround(( ~ Math.fround(Math.cosh(x)))))); }); testMathyFunction(mathy2, [0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, 2**53+2, -0x100000001, 42, 0x080000000, -0, 2**53, 0x07fffffff, 2**53-2, 1.7976931348623157e308, 0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, 0/0, 1/0, -Number.MIN_VALUE, -(2**53), Math.PI, Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), -0x080000001, -0x0ffffffff, 0x080000001, -1/0, 0x100000000]); ");
/*fuzzSeed-94431925*/count=749; tryItOut("mathy0 = (function(x, y) { return Math.trunc(( + ( - (((Math.sin(-0x0ffffffff) >>> 0) | 0) << ( + Math.acosh(( + Math.round((( - Math.fround(x)) >>> 0))))))))); }); ");
/*fuzzSeed-94431925*/count=750; tryItOut("/*RXUB*/var r = /.*|[^\u0016\\u0065](?=(?=\\2))/im; var s = \"e\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u000c\"; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=751; tryItOut("/*RXUB*/var r = r2; var s = g1.s2; print(s.match(r)); print(r.lastIndex); p0 + '';");
/*fuzzSeed-94431925*/count=752; tryItOut("\"use strict\"; v0 = r1.exec;");
/*fuzzSeed-94431925*/count=753; tryItOut("\"use strict\"; \"use asm\"; {a1.splice(NaN, /*RXUE*//\\w{3}/g.exec(\"_000a\"), f2, m0, this.g0); }");
/*fuzzSeed-94431925*/count=754; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(mathy2(( + mathy1(((Math.fround(Math.max(( + Math.pow(y, (Math.fround((Number.MIN_VALUE % -Number.MIN_SAFE_INTEGER)) | 0))), (y | 0))) | 0) ? (( + Math.atan2(( + x), ( + (( - ( + x)) >>> 0)))) >>> 0) : Math.ceil((-Number.MAX_SAFE_INTEGER & (Math.hypot((y >>> 0), (x >>> 0)) >>> 0)))), ( + ( + Math.trunc(( + Math.acosh(-Number.MIN_SAFE_INTEGER))))))), ( ~ (mathy2(Math.fround(y), (( - Math.tan((y > x))) | 0)) >>> 0)))); }); testMathyFunction(mathy3, [-0x07fffffff, 0x080000000, 0.000000000000001, -0, -(2**53+2), 1.7976931348623157e308, Number.MAX_VALUE, 0x080000001, 0x0ffffffff, -(2**53), 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), 2**53+2, -Number.MAX_VALUE, 42, 2**53-2, 0, Math.PI, -0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, 0x100000001, 0x07fffffff, 1, -1/0, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-94431925*/count=755; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + Math.imul(Math.fround((Math.trunc((Math.ceil(-0x07fffffff) | 0)) | 0)), (Math.min((y | 0), Math.imul(Math.fround(( - Math.fround(Math.pow(1, ( + -0x100000001))))), x)) | 0))) + (Math.log(Math.ceil(Math.fround(((-Number.MIN_VALUE >>> 0) + Math.fround((Math.atan2((x | 0), (((( + -(2**53)) < x) | 0) | 0)) | 0)))))) >>> 0)); }); testMathyFunction(mathy5, [-(2**53+2), Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53), 2**53, -0x080000001, 0x080000000, 0x0ffffffff, -0x100000000, -0x07fffffff, 0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 0, 1, -0x0ffffffff, Math.PI, -0, Number.MIN_SAFE_INTEGER, 42, -0x100000001, 0x100000000, -1/0, -(2**53-2), 2**53-2, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-94431925*/count=756; tryItOut("mathy3 = (function(x, y) { return ( - Math.fround(Math.cbrt(( + ( - (Math.acosh((-Number.MAX_VALUE | 0)) | 0)))))); }); testMathyFunction(mathy3, [1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, -(2**53), 2**53+2, -0, 0x100000000, -0x100000001, 2**53, -0x080000000, -Number.MAX_VALUE, 0, -(2**53+2), 0x080000001, Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, Math.PI, -0x080000001, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, -0x07fffffff, 1, -(2**53-2), 0/0, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=757; tryItOut("/*hhh*/function cszqmn(){(12);}/*iii*/Object.defineProperty(this, \"t1\", { configurable: (x % 6 == 2), enumerable: false,  get: function() {  return new Uint32Array(t1); } });");
/*fuzzSeed-94431925*/count=758; tryItOut("\"use strict\"; for (var v of s0) { try { t1 = new Uint16Array(o2.a2); } catch(e0) { } try { m2 = new Map(this.b2); } catch(e1) { } for (var v of s1) { try { i0.toString = Array.prototype.shift.bind(o2); } catch(e0) { } this.a2[v0] = i2; } }");
/*fuzzSeed-94431925*/count=759; tryItOut("return timeout(1800);with({}) { for(let c in Math.fround(Math.exp(Math.fround((Math.max(( + Math.min(x, ( + x))), (Math.atanh(-(2**53-2)) | 0)) % x))))) let(a) ((function(){let(b) { return;}})()); } ");
/*fuzzSeed-94431925*/count=760; tryItOut("mathy5 = (function(x, y) { return (Math.fround(( ! Math.fround(( + (Math.imul(y, ( + (Math.round(((((Math.acosh(x) >>> 0) === ( + y)) >>> 0) >>> 0)) >>> 0))) / ((y >= ( ! (x | 0))) >>> 0)))))) | Math.min((Math.tan((mathy3(( + Math.sqrt(( + Math.pow(( + (x , (y >>> 0))), -Number.MIN_VALUE)))), ((((Math.round((Math.hypot(x, y) >>> 0)) >>> 0) >>> 0) - (Math.atan2(((( + (y | 0)) | 0) >>> 0), x) >>> 0)) >>> 0)) | 0)) | 0), (( ! Math.hypot(Math.atan(y), ((y >>> 0) == (Math.fround(mathy3(y, Math.fround(Math.fround(( + Math.fround(x)))))) >>> 0)))) | 0))); }); testMathyFunction(mathy5, /*MARR*/[-(2**53+2), -(2**53+2), new Boolean(false), -(2**53+2), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -(2**53+2), -(2**53+2), new Boolean(false), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), new Boolean(false)]); ");
/*fuzzSeed-94431925*/count=761; tryItOut("e2.has(g1.s2);");
/*fuzzSeed-94431925*/count=762; tryItOut("mathy4 = (function(x, y) { return mathy2(Math.sqrt(( ! (Math.atan2((( - -0x07fffffff) | 0), ( + Math.atan2(x, -0x07fffffff))) | 0))), ( + ( + Math.pow(Math.fround((Math.fround(x) > ( + Math.min(( + y), ( + Math.pow(y, Math.fround(Math.fround((Math.fround(x) || Math.fround(1.7976931348623157e308)))))))))), Math.fround(x))))); }); testMathyFunction(mathy4, [0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0/0, -Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -(2**53), -0, 0x100000000, -Number.MIN_VALUE, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 1, -0x0ffffffff, Number.MIN_VALUE, -0x100000000, 1/0, 0x080000001, 2**53+2, -0x100000001, 0, -1/0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-94431925*/count=763; tryItOut("\"use strict\"; e2.delete(f2);this.a2.__proto__ = o1;");
/*fuzzSeed-94431925*/count=764; tryItOut("m1.get(s1);");
/*fuzzSeed-94431925*/count=765; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! (Math.atan2(Math.fround((((y ** y) >>> 0) , x)), (((y >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0)) ** (Math.pow((( ! -0x07fffffff) % ((0x0ffffffff >>> 0) != (y >>> 0))), (Math.log(Math.fround(Math.log(Math.fround(y)))) ? Math.atan2(( - x), Math.fround((x >= Math.fround(-0x07fffffff)))) : (x | 0))) | 0))); }); testMathyFunction(mathy3, [0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, -(2**53+2), -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, 0, 0x080000000, 42, 2**53+2, -0, 0x100000001, -Number.MAX_VALUE, 2**53, 0x100000000, -(2**53), -0x080000001, -(2**53-2), -Number.MIN_VALUE, 1, 2**53-2, 1/0]); ");
/*fuzzSeed-94431925*/count=766; tryItOut("mathy3 = (function(x, y) { return (Math.imul(Math.sqrt(( + Math.atan2(Math.hypot((y | 0), (mathy0(( + (mathy1((-0x100000000 | 0), (y | 0)) | 0)), (y | 0)) | 0)), Math.expm1(y)))), ( + ((mathy0((mathy2(x, x) >>> 0), Math.hypot(Math.imul(1/0, x), x)) >>> 0) != (y || (Math.atanh(Math.atan2(( + (-0 / Math.fround(2**53-2))), 0x07fffffff)) ? (x | 0) : (x != (x / y))))))) >>> 0); }); ");
/*fuzzSeed-94431925*/count=767; tryItOut("v2 = r2.sticky;");
/*fuzzSeed-94431925*/count=768; tryItOut("\"use strict\"; let b = (4277);for (var v of g2) { try { s1 + g0; } catch(e0) { } try { e0.has(b0); } catch(e1) { } /*MXX2*/this.o2.g1.Int16Array.length = o0.o1; }");
/*fuzzSeed-94431925*/count=769; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.ceil((Math.clz32((Math.fround(Math.atan2((mathy2((0x07fffffff >>> 0), (x >>> 0)) >>> 0), Math.fround(mathy3(((x | 0) ? (y | 0) : (( ~ y) | 0)), (Math.min(x, y) && -0x100000000))))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-94431925*/count=770; tryItOut("\"use asm\"; this.p0 = x;");
/*fuzzSeed-94431925*/count=771; tryItOut("a0.push(a0, o0.e0, g2.p1);");
/*fuzzSeed-94431925*/count=772; tryItOut("let (z) { a1.shift(h1, o2); }");
/*fuzzSeed-94431925*/count=773; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.cos(( + (( + Math.atan2(Math.fround((Math.max(( + (mathy0((-0x0ffffffff | 0), (( - Math.fround(0.000000000000001)) | 0)) | 0)), ( + y)) | 0)), Math.fround((Math.fround((x !== Math.fround(y))) === ( + Number.MAX_VALUE))))) ? ( + (( ~ ( + ( - ( + (Math.round(y) ** ( + (Math.sinh((x | 0)) | 0))))))) | 0)) : ( + ( + Math.hypot(( + (Math.expm1(( + mathy3(y, x))) >>> 0)), Number.MIN_SAFE_INTEGER))))))); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), '0', /0/, [], NaN, [0], 0.1, (new Boolean(false)), 1, (new String('')), '', (function(){return 0;}), null, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), undefined, (new Boolean(true)), 0, '\\0', true, false, (new Number(0)), (new Number(-0)), -0, '/0/', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-94431925*/count=774; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\xaD+?\", \"gyim\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); \nlet (x) { print(x); }\n");
/*fuzzSeed-94431925*/count=775; tryItOut("");
/*fuzzSeed-94431925*/count=776; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((Math.fround(((Math.fround(( ~ (Math.cosh(x) | 0))) >>> 0) ^ Math.fround((Math.fround(( ~ (( ! Math.fround(y)) >>> 0))) , y)))) | 0) > (( ! ( + ( ! ( + Math.atan2(Math.min(y, y), Math.cos(x)))))) | 0)) | 0); }); testMathyFunction(mathy5, [0x0ffffffff, -(2**53+2), 2**53+2, -0x100000000, 0, 42, -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, 0x080000001, 1, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000001, 2**53-2, 1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0x07fffffff, -(2**53-2), -0x100000001, -Number.MAX_VALUE, Math.PI, 0/0, -0x080000001, 0x080000000, -0, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=777; tryItOut("testMathyFunction(mathy1, [-(2**53), Number.MIN_VALUE, 42, 0x07fffffff, 0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -Number.MIN_VALUE, 2**53, -1/0, Math.PI, -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, 0x100000000, 0x100000001, -0x080000000, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, 1, -0x07fffffff, 0, 0.000000000000001, 0/0]); ");
/*fuzzSeed-94431925*/count=778; tryItOut("/*infloop*/ for  each(\u3056 in (/*UUV2*/(x.asin = x.toJSON))) {Array.prototype.sort.call(a1, (function mcc_() { var dlfjav = 0; return function() { ++dlfjav; if (/*ICCD*/dlfjav % 9 == 5) { dumpln('hit!'); try { v2.valueOf = (function() { try { v0 = o2.a1.length; } catch(e0) { } for (var p in e0) { a2 = a0.slice(14, NaN); } return t1; }); } catch(e0) { } g1.valueOf = (function() { try { this.s1 += s1; } catch(e0) { } a1[({valueOf: function() { ( /x/ );return 18; }})] = this.g0.s1; throw h2; }); } else { dumpln('miss!'); try { o0.b2.toString = (function(j) { if (j) { a1.shift(); } else { try { e2 = new Set(a2); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(e1, s2); } }); } catch(e0) { } try { s0 = new String(m0); } catch(e1) { } try { e2.valueOf = f0; } catch(e2) { } a2.forEach((function(j) { if (j) { try { v2 = t1.length; } catch(e0) { } v0 = a1.length; } else { try { a0[o2.v0] = \"\\uE220\"; } catch(e0) { } g0.offThreadCompileScript(\"\\\"\\\\u45AA\\\"\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 2), noScriptRval: false, sourceIsLazy: (x % 6 == 4), catchTermination:  /x/  })); } })); } };})());/*infloop*/for((x.yoyo(x)); (\u3056 = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: ({/*TOODEEP*/}), delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: /*wrap3*/(function(){ \"use strict\"; var qdiwwb =  /x/ ; (/*wrap1*/(function(){ \"use strict\"; return;return Date.prototype.getMinutes})())(); }), hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })(new RegExp(\"\\\\cG\", \"m\")), (Math.imul(-25, /\\D+/y)((function (d) { yield /(?=^)/gy } ).call(\"\\u4BFB\", null, ({a2:z2}))))\n)); x) x = 4 + x; var r0 = 2 | x; var r1 = x * x; var r2 = 6 ^ 8; var r3 = 7 | r0; var r4 = 8 - 0; var r5 = 9 * 8; var r6 = r3 % 4; var r7 = 3 + r5; var r8 = 3 + x; var r9 = 5 - r6; var r10 = r6 ^ r8; var r11 = r0 ^ r9; var r12 = 7 & x; r10 = 5 - r7; var r13 = 7 * r5; r6 = r11 - r3; var r14 = r0 ^ x; var r15 = r7 % 2; var r16 = 1 / r4; var r17 = r16 - 6; var r18 = r7 | r15; var r19 = r12 | 4; var r20 = r15 / 1; var r21 = r6 & r0; var r22 = 6 ^ 6; print(r8); var r23 = 2 | r10; var r24 = r8 & r0; var r25 = r10 % r2; var r26 = 5 ^ r5; var r27 = 1 + r10; var r28 = r9 + r21; var r29 = r28 ^ r22; var r30 = 4 % r26; var r31 = r26 ^ r8; var r32 = r4 % r14; var r33 = r27 / 2; x = 2 / r15; r26 = 6 / 0; var r34 = 8 - r18; var r35 = r34 * r25; var r36 = r22 & r7; var r37 = r20 ^ 4; r31 = 2 | 5; var r38 = r10 / 6;  }");
/*fuzzSeed-94431925*/count=779; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.log10(( + ( + ((Math.fround(( + x)) ^ (Math.hypot((( ~ -(2**53)) >>> 0), y) >>> 0)) + (x >> (( ! (x >>> 0)) >>> 0))))))); }); testMathyFunction(mathy1, [0x100000001, -0, -0x080000001, 0.000000000000001, -0x100000001, Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, -(2**53+2), -0x07fffffff, 1, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1/0, 1.7976931348623157e308, -1/0, 2**53-2, -0x080000000, -0x100000000, 0x0ffffffff, 0x080000000, 0, 2**53+2]); ");
/*fuzzSeed-94431925*/count=780; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -4398046511103.0;\n    return (((0xed1228e0)))|0;\n    d1 = (d2);\n    return (((0xe3a16690)))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; print(e);; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 1/0, 0x080000001, -0x100000001, -0x0ffffffff, 0x100000001, 0x100000000, 0/0, -0x080000000, Number.MIN_VALUE, -0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, -0x100000000, 1.7976931348623157e308, 2**53-2, -(2**53+2), Math.PI, 0.000000000000001, 1, 42, 0x0ffffffff, 2**53+2, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), -0x080000001, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=781; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.tan((Math.pow(( - (x >>> 0)), Math.fround(( ! Math.fround(x)))) == (( + x) < ( + Math.imul(Math.atan2(Math.fround(Math.acos(Number.MAX_SAFE_INTEGER)), y), y))))); }); ");
/*fuzzSeed-94431925*/count=782; tryItOut("/*MXX3*/g0.RegExp.$4 = g0.RegExp.$4;");
/*fuzzSeed-94431925*/count=783; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(v1, this.e2);");
/*fuzzSeed-94431925*/count=784; tryItOut("let x = throw this, x =  \"\" , iwxspm, y, pwsnrl, izjvfy, xgjxym, zucuzm, qimfjr, z;v1 = t0.length;");
/*fuzzSeed-94431925*/count=785; tryItOut("s2 += g1.s2;print(x);");
/*fuzzSeed-94431925*/count=786; tryItOut("\"use asm\"; i2.send(b2);");
/*fuzzSeed-94431925*/count=787; tryItOut("while(((4277)) && 0)print(x)");
/*fuzzSeed-94431925*/count=788; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 34359738368.0;\n    var i5 = 0;\n    return (([1,,] in undefined))|0;\n  }\n  return f; })(this, {ff: y => ({y: window})}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, -0x080000001, 0, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0x080000001, 0/0, 0x0ffffffff, -0x100000001, -0, -0x100000000, 2**53-2, -0x07fffffff, Math.PI, 1, Number.MAX_VALUE, 42, 1.7976931348623157e308, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -(2**53+2), 2**53, 0x080000000, 0x100000000, -(2**53-2), 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=789; tryItOut("s1 += 'x';");
/*fuzzSeed-94431925*/count=790; tryItOut("mathy1 = (function(x, y) { return (((Math.tanh(( ~ (( + (( + Math.asin(Math.fround(Math.atan2(Math.PI, ( + y))))) * ( + ( + Math.fround((Math.fround(mathy0(-0x07fffffff, x)) << Math.fround(x))))))) | 0))) | 0) >= (( + (Math.fround(Math.cosh(Math.abs(Math.hypot((Math.sin((x >>> 0)) | 0), x)))) ? ( + (y ? Math.fround(((((mathy0(x, mathy0(x, (y >>> 0))) | 0) | 0) > (y | 0)) | 0)) : x)) : Math.fround(Math.imul(Math.fround(Math.hypot(( + x), (y >>> 0))), y)))) | 0)) | 0); }); testMathyFunction(mathy1, [-0x080000000, -0x080000001, -0x100000001, -(2**53), 0.000000000000001, -0, -0x07fffffff, 42, -0x100000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, Math.PI, 0x080000001, 2**53+2, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, 1, -1/0, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 0x100000001, 2**53, Number.MAX_VALUE, 0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=791; tryItOut("\"use strict\"; \"use asm\"; ");
/*fuzzSeed-94431925*/count=792; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ (( ! (Math.max(( + ( ! Math.hypot(x, Math.abs(-Number.MAX_SAFE_INTEGER)))), y) >>> 0)) | 0)) | 0); }); ");
/*fuzzSeed-94431925*/count=793; tryItOut(";");
/*fuzzSeed-94431925*/count=794; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -131073.0;\n    return ((((-8796093022209.0) <= (Infinity))-((((!(i0)))>>>(-(0xb03b40fa))) != (((/*FFI*/ff()|0)-((17.0) != (+atan2(((-4.722366482869645e+21)), ((2199023255553.0))))))>>>((())-((0x9da8ee96) == (0x58764073))-(0xbd7f83f6))))))|0;\n    (Float32ArrayView[((((0x4bdd2371) / (0x81ae5b3)) | ((0x84798c54)-(0x3bbf213b)+(0x27b06fd3))) / (((0xf9f72054)) ^ ((0xb84a6c13)-(-0x8000000)+(-0x8000000)))) >> 2]) = ((Float32ArrayView[((i0)-((((i0))>>>(((0x25dd9e7a) == (0x19ae3feb))-(i0))) >= ((i0)))) >> 2]));\n    d2 = (d2);\n    (Float64ArrayView[0]) = ((-1.00390625));\n    d2 = (8589934593.0);\n    {\n      return (((i1)*-0xf20a9))|0;\n    }\n    i0 = ((+((-3.8685626227668134e+25))) != (-3.777893186295716e+22));\n    i0 = (i0);\n    return (((((-((i1)))>>>((i0))) < (0xffffffff))*-0x3efa8))|0;\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), (0/0), null, new Boolean(true)]); ");
/*fuzzSeed-94431925*/count=795; tryItOut("\"use strict\"; s2.valueOf = (function() { for (var j=0;j<0;++j) { f1(j%2==0); } });");
/*fuzzSeed-94431925*/count=796; tryItOut("\"use strict\"; g2.s0 += 'x';");
/*fuzzSeed-94431925*/count=797; tryItOut("\"use strict\"; /*bLoop*/for (bdlhrd = 0; bdlhrd < 66; ++bdlhrd) { if (bdlhrd % 7 == 2) { return /\\b|(?!(?:.))(?:^)*?$/g; } else { m1.has(b2); }  } ");
/*fuzzSeed-94431925*/count=798; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan2(Math.log1p(((((( + Math.log(x)) >> ( + x)) | 0) | ((( ! ((( + (x | 0)) | 0) | 0)) | 0) | 0)) | 0)), Math.sign(Math.fround(Math.atan2(Math.max((Math.fround(Math.imul((x >>> 0), ( + Math.pow(Number.MAX_VALUE, x)))) | Math.asinh((((x >>> 0) > (0x080000000 >>> 0)) >>> 0))), (x >>> 0)), Math.sinh(Number.MIN_SAFE_INTEGER))))); }); ");
/*fuzzSeed-94431925*/count=799; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-Number.MIN_VALUE, 2**53-2, -0x100000001, -(2**53+2), 0x080000001, -0x07fffffff, 1/0, 0/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -1/0, 2**53+2, 0x080000000, 1.7976931348623157e308, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0x07fffffff, -0x100000000, Number.MIN_VALUE, -0x080000001, -0x080000000, -0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 42, -Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff, 2**53, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-94431925*/count=800; tryItOut("s0 += s1;");
/*fuzzSeed-94431925*/count=801; tryItOut("mathy2 = (function(x, y) { return (mathy0(Math.ceil(Math.fround(Math.acosh((((Math.pow((x | 0), Math.fround(mathy0((y ? (y | 0) : Number.MIN_VALUE), -Number.MAX_SAFE_INTEGER))) | 0) | 0) , (Math.max(y, (Math.expm1(Math.fround(y)) >>> 0)) | 0))))), Math.atan2(Math.pow(Math.max(Math.fround(Math.min(Math.fround(((((( ! (2**53 | 0)) | 0) | 0) ? (y | 0) : (Math.fround((Math.fround(x) || Math.fround(x))) | 0)) | 0)), (Math.asin((x | 0)) >>> 0))), Math.pow((((x | 0) ? Math.fround(0x080000000) : (y | 0)) | 0), Math.fround(Math.atanh(Math.fround(y))))), y), (y , Math.max(y, (Math.atan2(x, (0/0 >>> 0)) >>> 0))))) | 0); }); testMathyFunction(mathy2, /*MARR*/[{x:3},  /x/ , {x:3}, x,  /x/ ,  /x/ , x, x, {x:3}, {x:3}, {x:3}, x,  /x/ , {x:3},  /x/ , x,  /x/ ,  /x/ , {x:3}, {x:3},  /x/ ,  /x/ , x, {x:3},  /x/ , x,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , {x:3}, {x:3}, {x:3},  /x/ ,  /x/ , x, x,  /x/ ]); ");
/*fuzzSeed-94431925*/count=802; tryItOut("v0 = r0.global;");
/*fuzzSeed-94431925*/count=803; tryItOut("/*tLoop*/for (let z of /*MARR*/[{}, (-1/0), 0x100000001, (-1/0), {}, (-1/0), 0x100000001, 0x100000001, (-1/0), {}, (0/0), (-1/0), (-1/0), (0/0), 0x100000001, (-1/0), 0x100000001, {}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), {}, 0x100000001, (-1/0), 0x100000001, 0x100000001, (0/0), 0x100000001, (0/0), 0x100000001, (0/0), (-1/0), 0x100000001, (-1/0), (-1/0), (-1/0), {}, (-1/0), 0x100000001, (-1/0), (0/0), {}, (0/0), (0/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), 0x100000001, 0x100000001, (-1/0), {}, {}, (0/0), (-1/0), 0x100000001, (-1/0), (-1/0), 0x100000001, {}, (-1/0), (-1/0), 0x100000001, {}, (0/0), (-1/0), (0/0), (-1/0), (-1/0), 0x100000001, (0/0), (-1/0), (-1/0), (0/0), (0/0), (0/0), (0/0), (-1/0), (-1/0), 0x100000001, {}, (0/0), {}, 0x100000001, (-1/0), (0/0), 0x100000001, 0x100000001, (-1/0), (0/0), (-1/0), (-1/0), (0/0), (0/0), {}, {}, (-1/0), {}, (0/0), 0x100000001, (0/0), (0/0), (0/0), 0x100000001, 0x100000001, (0/0), (-1/0), (0/0), 0x100000001, (0/0), (-1/0), (-1/0), (0/0), 0x100000001, 0x100000001, (-1/0), {}, 0x100000001, (0/0), 0x100000001, 0x100000001, (0/0), {}, 0x100000001, (0/0), (-1/0), (-1/0), 0x100000001, {}, 0x100000001, (0/0), {}, {}, 0x100000001, 0x100000001]) { v1 = evaluate(\"mathy3 = (function(x, y) { return Math.tanh(mathy1(( - 0x0ffffffff), ( + (Math.asinh(Math.fround(( - (Math.fround(x) * (x >>> 0))))) % Math.min(y, (( ~ x) >>> 0)))))); }); testMathyFunction(mathy3, /*MARR*/[eval, x, new String('q'), x, x, x, x, new String('q'), x, x, eval, eval,  /x/g , eval, x, new String('q'),  /x/g , new String('q'), eval, new String('q'), x, x, new String('q'), eval, new String('q'),  /x/g , eval,  /x/g , x, new String('q'),  /x/g , x, new String('q'),  /x/g , eval, new String('q'), new String('q'), new String('q'),  /x/g , eval,  /x/g , eval, new String('q'), x, new String('q'), eval, eval, new String('q'), x]); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: /\\2?/gym, sourceIsLazy: false, catchTermination: false })); }");
/*fuzzSeed-94431925*/count=804; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=805; tryItOut("mathy2 = (function(x, y) { return ( - Math.sign(( + Math.min(( + mathy0(y, (( + ( + y)) < Math.fround(y)))), ( + (Math.fround(mathy1(mathy0(x, y), y)) ? ( + (( + mathy0(( + y), ( + 0.000000000000001))) >>> ( + x))) : Math.sign(( - (Math.fround(x) + -0))))))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, -(2**53), 0, Number.MIN_VALUE, 0.000000000000001, -0x080000001, -(2**53-2), 0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, -0, 2**53-2, -(2**53+2), 0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, 1/0, -Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-94431925*/count=806; tryItOut("let b = null;function f0(i2)  { \"use strict\"; yield true } ");
/*fuzzSeed-94431925*/count=807; tryItOut("t0 = t1.subarray(v1, 0);");
/*fuzzSeed-94431925*/count=808; tryItOut("mathy5 = (function(x, y) { return ( + ((Math.imul(( + ( + -0x080000001)), ( + Math.hypot(( + ((Math.fround(( ~ x)) + Math.fround(Math.expm1((x >>> 0)))) ? -(2**53) : Math.fround(mathy4(y, x)))), x))) ? mathy3(Math.fround(Math.max(x, Math.acos(y))), (((x | 0) > Math.fround(y)) | 0)) : Math.sqrt(((x ? x : Math.trunc(x)) + ((y | 0) ^ (Math.sin(( ~ (x >>> 0))) | 0))))) ? (Math.sqrt(( + (( + Math.max(Math.fround(( - (Math.hypot(1, x) >>> 0))), Math.fround(-(2**53)))) ? ( + ( - (Math.imul((x >>> 0), (x >>> 0)) >>> 0))) : ( + Math.round(y))))) >>> 0) : Math.min(Math.atan2((Math.ceil((0x100000000 >>> 0)) ? X : mathy2(( ! -Number.MAX_SAFE_INTEGER), x)), mathy1((( - (x | 0)) | 0), x)), Math.pow((mathy2((((Math.tanh(y) >>> 0) ? (x >>> 0) : Number.MIN_SAFE_INTEGER) | 0), ((mathy4((x >>> 0), (x >>> 0)) >>> 0) | 0)) | 0), (Math.clz32((mathy2((Math.clz32(x) >>> 0), y) >>> 0)) | 0))))); }); testMathyFunction(mathy5, [-(2**53-2), 0x080000001, 1, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 2**53+2, Math.PI, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -1/0, 0, 0x100000000, 42, -(2**53), -(2**53+2), -0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, 0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 0.000000000000001, -0, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000]); ");
/*fuzzSeed-94431925*/count=809; tryItOut("mathy3 = (function(x, y) { return ((( ! ( + mathy1(Math.atan2(y, (mathy2(y, (((x >>> 0) / -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)), (Math.pow((mathy0(( + ( + -0x0ffffffff)), ( + Math.fround(((x | 0) === Math.fround(y))))) | 0), y) >>> 0)))) >>> 0) ? ( ~ Math.log1p((( + ( - ( + (( ~ y) >>> 0)))) | 0))) : (( + Math.min(( + (mathy2((( - mathy2(y, (Math.cbrt((x >>> 0)) >>> 0))) >>> 0), (Math.atan2(Math.pow(y, (Math.fround(Math.sinh(Math.fround(x))) >>> 0)), (Math.hypot(Math.max((x | 0), Math.fround(1.7976931348623157e308)), x) >>> 0)) >>> 0)) >>> 0)), ( + Math.pow((y >>> 0), ( - (( ! ((((1.7976931348623157e308 || y) | 0) ? (Math.cbrt((0 | 0)) >>> 0) : (mathy0(x, x) | 0)) | 0)) | 0)))))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), new String('')]); ");
/*fuzzSeed-94431925*/count=810; tryItOut("e1 + h2;");
/*fuzzSeed-94431925*/count=811; tryItOut("\"use strict\"; for (var v of f1) { a2.forEach((function() { try { /*MXX3*/g0.g2.EvalError.prototype = g0.EvalError.prototype; } catch(e0) { } function f2(p0) Math.hypot(2, -18) return b2; }), g2.g0, e0); }print(-29);");
/*fuzzSeed-94431925*/count=812; tryItOut("/*oLoop*/for (fehnnj = 0; fehnnj < 78; ++fehnnj) { offThreadCompileScript\nt1.toSource = g2.f1;\n } ");
/*fuzzSeed-94431925*/count=813; tryItOut("\"use strict\"; /*MXX2*/g0.g2.EvalError.prototype = o1.p0;");
/*fuzzSeed-94431925*/count=814; tryItOut("v1 = null;");
/*fuzzSeed-94431925*/count=815; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.min((mathy3(Math.fround(Math.max((( ! y) | 0), (Math.fround(Math.acosh(Math.fround(x))) | 0))), Math.fround((Math.abs(x) << (((0 | 0) >>> (x | 0)) | 0)))) | 0), ( + Math.sqrt(x)))), ( + Math.tan(((y > ( ~ (Math.exp((y | 0)) >>> 0))) | (Math.fround(x) ^ Math.fround(( ~ ( + 0x07fffffff))))))))); }); testMathyFunction(mathy4, [-0x07fffffff, 0x100000001, 1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0.000000000000001, -0x100000001, 2**53, -0x080000000, 0/0, -Number.MAX_VALUE, -0, 42, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000001, 0x080000000, 1, 2**53-2, 0, -1/0, 0x100000000, Math.PI, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-94431925*/count=816; tryItOut("xhbwkz(x, true);/*hhh*/function xhbwkz(w, eval){Array.prototype.sort.call(a0, (function() { v1 = (f2 instanceof t1); return f2; }), m1, h1, v0);}x = ((p={}, (p.z = (4277))()));");
/*fuzzSeed-94431925*/count=817; tryItOut("a0 = this.o2.r2.exec(s2);");
/*fuzzSeed-94431925*/count=818; tryItOut("mathy5 = (function(x, y) { return ( + (((Math.sign(Math.abs((( ~ y) << (((x | 0) && (( + Math.sinh(( + y))) | 0)) >>> 0)))) | 0) >>> 0) >>> Math.fround(((((( ~ ( + ( + ( + Math.round(x))))) | 0) >>> 0) ** (mathy2(Math.pow(y, x), (Math.hypot((0/0 | ( + y)), Math.max((Math.cbrt(y) | 0), ( + Math.atan2(( + (Math.max((x | 0), (x | 0)) | 0)), (x >>> 0))))) | 0)) | 0)) >>> 0)))); }); ");
/*fuzzSeed-94431925*/count=819; tryItOut("/*infloop*/ for  each(x in (  = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: function() { throw 3; }, }; })(Math.min(134217728, -11)), Array.prototype.unshift))) {a1 = Array.prototype.map.call(a2, (function() { try { s0 += 'x'; } catch(e0) { } v1 = o2.g1.runOffThreadScript(); return g0; })); }");
/*fuzzSeed-94431925*/count=820; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (+atan2(((+abs(((-6.189700196426902e+26))))), ((Float32ArrayView[((Uint8ArrayView[4096])) >> 2]))));\n    switch ((x)) {\n      default:\n        switch (((-0xfffff*((0x78d59111) ? (0xe402360) : (0x124f460a))) >> (((0x3cae5698))-(!(0xffffffff))))) {\n          case -3:\n            d0 = (-2049.0);\n            break;\n          case -3:\n            i1 = ((d0) > (((+(((0x1f30c94b)-(i2)) ^ (((0x9f24b4b9) > (0x2aea5fab)))))) - ((17592186044417.0))));\n          case -2:\n            i1 = ((('fafafa'.replace(/a/g, new x(new  \"\" (false, [1])).setTime)) >> ((((-0x2d6170d) / (0x586576)) >> ((i2)*0x55288)) / (-0x7fa47e6))) >= (imul((/*FFI*/ff(((0x64626c3a)))|0), (i2))|0));\n            break;\n          case 1:\n            {\n              d0 = (d0);\n            }\n            break;\n          case -3:\n            i2 = (i1);\n            break;\n          case 0:\n            /*FFI*/ff(((imul(((68719476736.0) > (32768.0)), ((-137438953473.0) >= (Infinity)))|0)), ((abs((~~(+(((0x579148a3)-(-0x8000000)) | ((Int16ArrayView[4096]))))))|0)), ((d0)), (((c = (({a1:1})(b-=x))))));\n          case -3:\n            i2 = (/*FFI*/ff(((((/*FFI*/ff()|0)) ^ ((0xffffffff) % ((-(0x867a3da))>>>((0xd254c812)*0xfffff))))), ((-129.0)), ((d0)))|0);\n            break;\n          case -2:\n            i2 = (!(0xffffffff));\n            break;\n          case -1:\n            i1 = (i1);\n            break;\n          case 0:\n            /*FFI*/ff(((let (c)  \"\" ) ^= (4277)), (((((((0xfa903014))|0) > (((0xd3604ddc)) ^ ((0xb1b9c298))))-(0xefe2e56f)) | ((i1)*0x7f31b))), ((0x6ea70159)), (((((((0xffffffff)))|0))|0)), ((+(0.0/0.0))));\n            break;\n          case -2:\n            i2 = (0xfdae3bdb);\n            break;\n          case -3:\n            (Float64ArrayView[((0xf7f152fd)-(i1)) >> 3]) = ((NaN));\n            break;\n          case 0:\n            (Float32ArrayView[1]) = ((d0));\n          case -2:\n            i1 = (((((i2)-(i2))>>>((0x0) / (0xa5f29361)))) ? (/*FFI*/ff((((((d0) == (-4503599627370497.0))-(/*FFI*/ff(((window in  /x/ )), ((imul((0xba9bed6b), (0x124178ce))|0)), ((262145.0)))|0)) & ((!(!(0xcd51a2df)))))), (((((0x4cc229f7) == (0x4e3bc0bc))-(-0x8000000)) & ((Int8ArrayView[((0xf9c2abba)) >> 0])))), ((+(1.0/0.0))), ((((-0x7d92dd6)+(0xb2ed383f)-(-0x8000000))|0)), ((+(((0xf69f739b))>>>((0xf8c4f647))))))|0) : (0xfa9eb836));\n            break;\n          default:\n            /*FFI*/ff((((i1))));\n        }\n    }\n    {\n      switch ((~(((0x1d38f840) == (((0x925d14d7)) ^ ((0xfa2d48a1))))))) {\n        case 1:\n          return +((+atan2(((d0)), ((-0.00390625)))));\n          break;\n        case 1:\n          d0 = (+((((0xfd9d5747) ? (/*FFI*/ff((((36028797018963970.0) + (+/*FFI*/ff()))), ((-147573952589676410000.0)), ((((0xfeb11715)) & ((0x89204051)))), ((0x4920759e)), ((8589934593.0)), ((-1125899906842624.0)), ((-1.5474250491067253e+26)), ((-134217729.0)), ((72057594037927940.0)), ((0.125)), ((0.015625)), ((1.5)), ((7.737125245533627e+25)), ((-257.0)), ((9007199254740992.0)), ((6.189700196426902e+26)), ((16385.0)))|0) : (((i1)))))|0));\n          break;\n        case 0:\n          i1 = (i2);\n      }\n    }\n    return +((+(imul((i2), ((((0x924d4ca4)+(i2))>>>((i1)-((0x1eb72b71))+((0xb3da696) >= (0x49a10b9c)))) > (0x7323ad1a)))|0)));\n  }\n  return f; })(this, {ff: (window, x, {}, a = 23, w, true, b, window, c, \u3056, e, d, c, x, x = false, x, x = \"\\uC111\", a, eval, window, \u3056, NaN, window, b, x, e, a = \"\\uAA9B\", d, NaN = d, x, d, x, c, c, eval, x = window, a, b, e, this.x, a, x, a, c, z, b, x, z, x = 13, x, x, a, x, \u3056, x, x, window, a, x, a, b, x, x = arguments, w, \u3056, ...w) =>  { {}function NaN(\u3056 = [z1]) { \"use strict\"; t0[({valueOf: function() { (/(?=(?=(?:^[])([^]+)))/gim);return 12; }})] = \"\\uF502\"; } yield new RegExp(\".\", \"\"); } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[true,  \"\" ,  \"\" , true, true]); ");
/*fuzzSeed-94431925*/count=821; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=822; tryItOut("\"use strict\"; v2 = evaluate(\"testMathyFunction(mathy4, [1/0, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, -0x07fffffff, -(2**53), 0, Number.MIN_VALUE, 2**53+2, -0x100000000, 0/0, -0x0ffffffff, -0x080000001, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -0, 2**53, 0x07fffffff, 42, 1.7976931348623157e308, 0x100000001, -(2**53+2), -(2**53-2), Math.PI, 0.000000000000001]); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: \"\\uF97A\", sourceIsLazy: true, catchTermination: (x % 19 != 8), element: this.o0, elementAttributeName: s1 }));\nprint(this);\n");
/*fuzzSeed-94431925*/count=823; tryItOut("\"use strict\"; t1[v1] = (4277);");
/*fuzzSeed-94431925*/count=824; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\2{1,2}|(?=\\\\D){0,0})+\", \"gy\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-94431925*/count=825; tryItOut("with(e =  \"\" ){print(/[\\xD0-\u7ea6\\x56-\u00c6](?=[^\\d])+{2,3}/gyim); }");
/*fuzzSeed-94431925*/count=826; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.fround(Math.min((mathy0(1, x) >>> 0), Math.fround(( + ( ~ ( + ( + Math.fround(y)))))))) >= ( + Math.hypot(( + ((y >>> 0) | y)), ( + ((Math.PI | x) | 0))))) && Math.fround((( ! (Math.cosh(Math.fround((((( + Math.cosh(Math.imul(Math.fround(y), -(2**53+2)))) | 0) > (-0x080000001 | 0)) | 0))) | 0)) | 0))); }); ");
/*fuzzSeed-94431925*/count=827; tryItOut("/*oLoop*/for (var ticeux = 0; ticeux < 37; ++ticeux) { g1.g2.a0 = []; } ");
/*fuzzSeed-94431925*/count=828; tryItOut("\"use strict\"; ");
/*fuzzSeed-94431925*/count=829; tryItOut("this.g1.__iterator__ = f2;var w = \"\\u3A0D\";");
/*fuzzSeed-94431925*/count=830; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1125899906842624.0;\n    d1 = (+pow(((+(-1.0/0.0))), ((+(1.0/0.0)))));\n    return +((Float64ArrayView[4096]));\n  }\n  return f; })(this, {ff: DataView.prototype.getInt16}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, ['0', ({valueOf:function(){return 0;}}), (new String('')), (new Boolean(false)), 1, '/0/', true, (new Number(-0)), false, '\\0', objectEmulatingUndefined(), (function(){return 0;}), ({toString:function(){return '0';}}), /0/, ({valueOf:function(){return '0';}}), '', [0], null, 0.1, (new Number(0)), undefined, [], (new Boolean(true)), 0, -0, NaN]); ");
/*fuzzSeed-94431925*/count=831; tryItOut("this.v1 = this.g2.eval(\"/* no regression tests found */\");");
/*fuzzSeed-94431925*/count=832; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(((( ~ ( + ( - ((y - Math.hypot(y, (x && Math.imul(x, 0x0ffffffff)))) >>> 0)))) | 0) ** ((Math.max(Math.round(((Math.asinh(y) >>> 0) , y)), ( + y)) && ( + (( + ( + ( ~ Math.PI))) , ( + Math.atanh((Math.atan2(Math.atan(y), (Math.max(Math.fround(-0x0ffffffff), -(2**53)) | 0)) | 0)))))) | 0))); }); testMathyFunction(mathy3, [0.000000000000001, 0/0, 2**53-2, 1/0, -0x07fffffff, 0x07fffffff, 0x100000000, 0, -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 42, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, -0x080000001, 0x080000000, -(2**53), 1, 0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, -(2**53-2), -0x100000001, 2**53, 0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000]); ");
/*fuzzSeed-94431925*/count=833; tryItOut("\"use strict\"; /*oLoop*/for (var wthcwu = 0; wthcwu < 60; ++wthcwu) { m2.toString = DataView.prototype.setFloat32; } ");
/*fuzzSeed-94431925*/count=834; tryItOut("");
/*fuzzSeed-94431925*/count=835; tryItOut("\"use strict\"; t0[v0] = p0;");
/*fuzzSeed-94431925*/count=836; tryItOut("mathy0 = (function(x, y) { return Math.fround(( ! Math.fround(Math.min((( ! (x | 0)) >>> 0), Math.fround(Math.atan2(Math.fround((((Math.fround((Math.exp((x >>> 0)) ? ((( ! ( - Number.MAX_SAFE_INTEGER)) >>> 0) | 0) : Math.fround(x))) | 0) ^ Math.expm1(x)) | 0)), Math.fround((((( + -Number.MAX_SAFE_INTEGER) | 0) && ((Math.sin((Math.imul(( - (x >>> 0)), y) | 0)) >>> 0) | 0)) | 0)))))))); }); testMathyFunction(mathy0, /*MARR*/[-Infinity, 2**53, objectEmulatingUndefined(), 2**53, new String('q'), 2**53, objectEmulatingUndefined(), 2**53, new String('q'), -Infinity, -Infinity, -Infinity, objectEmulatingUndefined(), 2**53, -Infinity, new String('q'), new String('q'), 2**53, objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, 2**53, objectEmulatingUndefined(), 2**53, 2**53, new String('q'), -Infinity, new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), 2**53, objectEmulatingUndefined(), -Infinity, 2**53, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, new String('q'), objectEmulatingUndefined(), new String('q')]); ");
/*fuzzSeed-94431925*/count=837; tryItOut("mathy5 = (function(x, y) { return Math.pow((((Math.fround((mathy0(y, -1/0) / ( + Math.atan2(( + (Math.pow(x, Math.min(Math.PI, Number.MAX_VALUE)) >>> 0)), ( + ( - y)))))) >>> 0) ^ ((Math.hypot((((x >= ((Math.imul(y, (Math.PI | 0)) >>> 0) >>> 0)) ? Math.max((Math.asinh((x >>> 0)) >>> 0), x) : y) >>> 0), Math.atan2(Math.fround((( + (Math.max(Number.MIN_VALUE, -Number.MIN_VALUE) <= y)) !== Math.fround(x))), Math.fround(( + mathy0(x, Math.fround(Math.log2(x))))))) >>> 0) >>> 0)) >>> 0), Math.fround(( + Math.log1p(Math.exp(Math.log2((x >>> 0))))))); }); testMathyFunction(mathy5, [0x100000001, 1/0, Number.MIN_SAFE_INTEGER, Math.PI, 42, -0x100000001, -Number.MIN_VALUE, -0x100000000, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, -0x080000000, 0x0ffffffff, 0, -(2**53-2), 2**53+2, 2**53, -0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, -Number.MAX_VALUE, 1, -1/0, Number.MIN_VALUE, -0x07fffffff, 2**53-2, 0x080000001, -0x080000001, Number.MAX_VALUE, 0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-94431925*/count=838; tryItOut("\"use strict\"; this.v1 = r0.global;");
/*fuzzSeed-94431925*/count=839; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"mathy3 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var NaN = stdlib.NaN;\\n  var ff = foreign.ff;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    return +((((d0)) % ((Float64ArrayView[(((NaN) > (+(((i1))|0)))+(i1)) >> 3]))));\\n  }\\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), false, (new Number(0)), 0.1, null, 0, objectEmulatingUndefined(), undefined, (function(){return 0;}), '', [0], /0/, (new Boolean(false)), NaN, '0', '\\\\0', (new Boolean(true)), 1, -0, true, '/0/', (new Number(-0)), (new String('')), [], ({toString:function(){return '0';}})]); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 21 != 7), catchTermination: (x % 3 == 2) }));");
/*fuzzSeed-94431925*/count=840; tryItOut("print(Math.pow((15), 3768464727));var b =  '' ;m1.get(a0)\nx;");
/*fuzzSeed-94431925*/count=841; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\ne1.has(b0);    switch ((abs((abs((((0x81e76555)) >> ((-0x8000000))))|0))|0)) {\n      default:\n        (Uint8ArrayView[(-0x8ac94*(x)) >> 0]) = (-0x6536f*(i1));\n    }\n    return +((+abs(((Infinity)))));\n  }\n  return f; })(this, {ff: (function(x, y) { return (( ~ (-(2**53) >>> 0)) >>> 0); })}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, 2**53-2, -0x0ffffffff, 1/0, Math.PI, 1, 2**53, 42, -0x100000000, 0x100000001, -0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, 0x100000000, -0x07fffffff, Number.MIN_VALUE, -(2**53), 0x07fffffff, 1.7976931348623157e308, 2**53+2, 0/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, -0, 0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=842; tryItOut("v1 = (p2 instanceof b1);");
/*fuzzSeed-94431925*/count=843; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=844; tryItOut("\"use strict\"; const e = x;print(x);function x(a = [[]]) { yield let (z =  /x/g )  ''  } a2.pop();");
/*fuzzSeed-94431925*/count=845; tryItOut("mathy4 = (function(x, y) { return ((Math.min((((( ! y) >= y) | 0) >>> 0), (mathy0(mathy2(-0x100000000, ((Math.fround(Math.sinh(y)) ? x : y) >>> 0)), Math.expm1(Math.pow((y <= Math.hypot(0x100000001, 0x080000001)), Math.fround(1.7976931348623157e308)))) >>> 0)) | 0) >>> ( + mathy3((( + ( ~ (mathy1(Math.max(Math.expm1(x), ( + x)), (mathy1(((Math.pow(0x100000001, -Number.MAX_SAFE_INTEGER) ? mathy2(x, ( + x)) : y) >>> 0), (x >>> 0)) | 0)) >>> 0))) | 0), ((Math.imul(((1 >>> 0) <= y), x) ? ( + (mathy2(( + 0x080000000), (x >>> 0)) | 0)) : (Number.MIN_SAFE_INTEGER > Math.min(x, x))) >>> 0)))); }); testMathyFunction(mathy4, [0, /0/, ({valueOf:function(){return '0';}}), 0.1, ({valueOf:function(){return 0;}}), '\\0', objectEmulatingUndefined(), (new Number(-0)), (new Boolean(false)), [0], (new Boolean(true)), '0', NaN, -0, '', '/0/', ({toString:function(){return '0';}}), null, [], (function(){return 0;}), true, undefined, 1, (new Number(0)), (new String('')), false]); ");
/*fuzzSeed-94431925*/count=846; tryItOut("e2.delete(p0);");
/*fuzzSeed-94431925*/count=847; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.atan2(( + (( + Math.fround(Math.round(Math.fround((Math.acosh(Math.imul(Math.tanh(x), (x | 0))) >>> 0))))) << (( - (-0x0ffffffff >>> 0)) >>> 0))), ( + (mathy3(((((((Math.fround((Math.fround(x) % Math.fround(Math.trunc((x >>> 0))))) | 0) & (Math.fround((Math.fround(Math.fround(mathy1(( + ( ~ (y | 0))), Math.fround(Math.imul(Math.fround(x), Math.fround(x)))))) <= Math.fround(Math.pow(-0x080000001, x)))) | 0)) >>> 0) << ((Math.PI ? mathy3(y, y) : 1) | 0)) | 0) | 0), Math.min(x, ((Math.fround(Math.min(x, ((( ! ( + y)) | 0) <= (y | 0)))) <= Math.fround(Number.MAX_SAFE_INTEGER)) | 0))) | 0))) >>> 0); }); testMathyFunction(mathy4, [-0x0ffffffff, 0x080000001, 0x0ffffffff, 0x100000000, -(2**53+2), 0, 0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 42, -(2**53), -(2**53-2), -0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0x080000000, 1, Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, Math.PI, 0x080000000, 2**53-2, 0/0, -0x100000001, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=848; tryItOut("mathy0 = (function(x, y) { return (( ! Math.tan(Math.log1p(x))) >> Math.fround(Math.min(Math.exp(x), ( ~ y)))); }); testMathyFunction(mathy0, [-1/0, 2**53-2, -0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, 0/0, 0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 2**53, -(2**53+2), -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, -0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 2**53+2, 0x07fffffff, -Number.MIN_VALUE, -0x07fffffff, -0x080000001, 0x080000000, 1, 0x100000000, -(2**53-2), 0, Number.MIN_VALUE, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-94431925*/count=849; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3\", \"y\"); var s = \"\\ued10\\ued10\\ued10\\n\\ued10\\ued10\\ued10\\ued10\"; print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=850; tryItOut("mathy1 = (function(x, y) { return Math.max(( + Math.tanh(Math.fround(( - Math.fround(Math.ceil(((mathy0(( ~ (y >>> 0)), (( - (x >>> 0)) | 0)) > 1) | 0))))))), Math.fround(( + Math.imul(( + Math.sinh(Math.atan2(y, y))), ( + mathy0(( + mathy0((Math.fround((Math.fround(Math.min(x, 2**53+2)) > Math.fround(y))) <= 1.7976931348623157e308), (Math.log(( + y)) | 0))), ( + ( ! ((( + y) | 0) | x))))))))); }); testMathyFunction(mathy1, /*MARR*/[false, 0x40000001, 3/0, (0x50505050 >> 1), 3/0, false, true, (0x50505050 >> 1), false, 3/0, 3/0, true, (0x50505050 >> 1), false, false, false, (0x50505050 >> 1), 0x40000001, (0x50505050 >> 1), (0x50505050 >> 1), false, 0x40000001, false, 3/0, 0x40000001, true, 3/0, (0x50505050 >> 1), true, false, false, 0x40000001, true, (0x50505050 >> 1), 0x40000001]); ");
/*fuzzSeed-94431925*/count=851; tryItOut("\"use strict\"; testMathyFunction(mathy4, [1/0, 0x0ffffffff, 0, 0x100000000, 1, 0.000000000000001, 2**53-2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, -0x0ffffffff, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, -0, 2**53+2, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, -0x100000001, 0x080000001, 2**53, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, -0x100000000, 0/0, 42, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=852; tryItOut("testMathyFunction(mathy1, [Math.PI, 0x100000001, -(2**53+2), 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, -0x080000000, 0x07fffffff, 2**53-2, 2**53, -1/0, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, 0x080000001, 0x080000000, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 1/0, 2**53+2, -0x100000000, -0, -(2**53), 0/0, 0]); ");
/*fuzzSeed-94431925*/count=853; tryItOut("\"use strict\"; /*hhh*/function vqsrve(c = Math.hypot(-24, 0.265)){/*ADP-3*/Object.defineProperty(o2.a1, 14, { configurable: arguments, enumerable: x, writable: x, value: e1 });}vqsrve(((new Function(\"o1.v0 = Object.prototype.isPrototypeOf.call(v1, g2.o1.e0);\"))).call( /x/g , (4277)), x);");
/*fuzzSeed-94431925*/count=854; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.cos(mathy0((((mathy0(x, Math.tanh(((y | 0) << (y | 0)))) | 0) >> (Math.asin(( + Math.hypot(( + x), ( + Math.fround((Math.fround((x >>> (1/0 | 0))) + Math.fround(2**53))))))) | 0)) | 0), ( + ( ~ (( - x) << Number.MIN_SAFE_INTEGER))))) | 0); }); testMathyFunction(mathy1, [0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 1, -0x100000001, -Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff, -0, -0x100000000, -0x080000000, 0/0, 0x100000000, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -1/0, 0.000000000000001, 1/0, 2**53+2, 0x080000000, Math.PI, -(2**53+2), Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, -0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=855; tryItOut("mathy0 = (function(x, y) { return ( + ((Math.asin((( ~ (((Number.MAX_SAFE_INTEGER | 0) - (x | 0)) | 0)) | 0)) === Math.sqrt(Math.imul(( ! (x | 0)), (x >>> 0)))) | 0)); }); testMathyFunction(mathy0, [(new Number(0)), (new Number(-0)), (new Boolean(false)), 0, [0], (function(){return 0;}), null, '\\0', true, objectEmulatingUndefined(), ({toString:function(){return '0';}}), /0/, (new Boolean(true)), (new String('')), undefined, false, ({valueOf:function(){return '0';}}), '/0/', 1, [], 0.1, NaN, '0', -0, ({valueOf:function(){return 0;}}), '']); ");
/*fuzzSeed-94431925*/count=856; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x07fffffff, -1/0, Math.PI, -0x100000000, Number.MAX_VALUE, -0x080000001, -(2**53+2), -(2**53), -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, 0/0, -(2**53-2), 1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 0x080000001, 2**53, Number.MIN_VALUE, 0.000000000000001, 42, 1, 0x07fffffff, -0x080000000, 0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=857; tryItOut("/*infloop*/M:for(var z in ((/*wrap1*/(function(){ /*vLoop*/for (var sptuza = 0; sptuza < 3; ++sptuza) { const y = sptuza; /* no regression tests found */ } return mathy3})())( /* Comment */x)))var skrfrt = new SharedArrayBuffer(16); var skrfrt_0 = new Int32Array(skrfrt);  /x/ ;");
/*fuzzSeed-94431925*/count=858; tryItOut("a2 + '';");
/*fuzzSeed-94431925*/count=859; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.fround(Math.imul((Math.sign((Math.acosh(( ! (-1/0 >> (mathy1(x, y) >>> 0)))) | 0)) >>> 0), Math.fround(( ~ ((x % y) >>> 0))))), ( + ( ~ ( + Math.exp(( + Math.fround((((x | 0) ? (Math.sinh(x) | 0) : (-0x080000000 | 0)) | 0)))))))); }); ");
/*fuzzSeed-94431925*/count=860; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=861; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q')]) { f1 + ''; }");
/*fuzzSeed-94431925*/count=862; tryItOut("v2 = new Number(Infinity);");
/*fuzzSeed-94431925*/count=863; tryItOut("/*MXX1*/o0 = g2.Date.prototype.getMinutes;");
/*fuzzSeed-94431925*/count=864; tryItOut("v2 = Object.prototype.isPrototypeOf.call(a1, o1);");
/*fuzzSeed-94431925*/count=865; tryItOut("i1.send(m2);");
/*fuzzSeed-94431925*/count=866; tryItOut("mathy5 = (function(x, y) { return mathy3((Math.fround(mathy4(Math.fround(Math.atanh(x)), Math.fround(Math.log(0x100000000)))) - ((y ? Math.tanh(x) : ( + Math.min(0, Math.cos((x ** x))))) | 0)), Math.atan2(Math.fround(Math.atan2(mathy4(((Math.fround(Math.min(Math.fround(1.7976931348623157e308), Math.fround(x))) , y) | 0), x), Math.log(( + ( ~ ( - ( + y))))))), Math.asinh((Math.fround(((x >>> 0) || Math.round((0x100000001 | 0)))) !== ( + Math.tan(y)))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, 0.000000000000001, -(2**53), 0x100000001, 0x0ffffffff, 42, 0/0, 2**53, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, Number.MAX_VALUE, Math.PI, 2**53-2, -1/0, -0x100000001, 2**53+2, -(2**53-2), -0x100000000, -0x080000001, -Number.MAX_VALUE, 1, 1/0, Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, 0x080000000]); ");
/*fuzzSeed-94431925*/count=867; tryItOut("/*oLoop*/for (var pkxmvn = 0; pkxmvn < 6; ++pkxmvn) { v2 = b1.byteLength;Array.prototype.pop.call(g1.a1, s0, [1,,], o2.e2); } ");
/*fuzzSeed-94431925*/count=868; tryItOut("\"use strict\"; /*oLoop*/for (let ojqhpa = 0, window; ojqhpa < 5; this, ++ojqhpa) { a2.valueOf = (function() { for (var j=0;j<18;++j) { f0(j%2==0); } }); } ");
/*fuzzSeed-94431925*/count=869; tryItOut("/*oLoop*/for (let cuzfdv = 0; cuzfdv < 0; ++cuzfdv) { f2(e1); } ");
/*fuzzSeed-94431925*/count=870; tryItOut("Array.prototype.pop.apply(a0, [a2, t1, i1]);");
/*fuzzSeed-94431925*/count=871; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(\\\\D?)|\\\\1.*?\\\\0*?{2,4})*?[^]+?\\\\D|(\\\\3)\", \"gi\"); var s = this; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=872; tryItOut("a2.splice(NaN, 13);");
/*fuzzSeed-94431925*/count=873; tryItOut("(/(?:((?:[^\\j-\\u91C3\\s\\xF5\\s])){513,515})/gi);\n{}\nfunction w(y) { this.zzz.zzz = (uneval(3)); } o2.g2.offThreadCompileScript(\"function f1(this.e0) \\\"\\\\u34E2\\\"\");\nf2 = DataView;\n");
/*fuzzSeed-94431925*/count=874; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.min(((Math.atan2(Math.fround(Math.cos(( ~ ( + x)))), Math.fround(Math.exp(Math.fround(( - Math.tan(( + y))))))) != Math.atan2(Math.log2(1/0), ((((0x100000000 >>> 0) != (y >>> 0)) >>> 0) | 0))) >>> 0), (Math.fround(( ~ Math.fround(( ~ ( + (( ! (y >>> 0)) >>> 0)))))) >>> 0))); }); ");
/*fuzzSeed-94431925*/count=875; tryItOut("\"use strict\"; return (uneval( \"\" )) ? allocationMarker().unwatch(\"sup\") : ((\u3056) = this);this.zzz.zzz;");
/*fuzzSeed-94431925*/count=876; tryItOut("v1 = new Number(f0);");
/*fuzzSeed-94431925*/count=877; tryItOut("\"use strict\"; /*MXX1*/o1.o2 = g1.g2.Uint32Array.prototype.constructor;\n;\n");
/*fuzzSeed-94431925*/count=878; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\"; ;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -63.0;\n    var d3 = -288230376151711740.0;\n    d0 = (d1);\n    d2 = (d3);\n    d2 = (d1);\n    return (((0xfaafd189)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return Math.tan((Math.fround(y) | 0)); })}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000001, 0x100000001, 0x100000000, -(2**53-2), 42, -Number.MAX_VALUE, -0x100000000, -(2**53), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, -0, 0x080000000, Number.MAX_VALUE, 2**53+2, 0, -0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -0x0ffffffff, 0x080000001, 2**53, -1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 1, 2**53-2, Math.PI, -0x07fffffff, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=879; tryItOut("\"use strict\"; v2 = g2.eval(\"function f1(o1.e2)  { return o1.e2 } \");c = z = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: Math.random, hasOwn: function() { throw 3; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(7), (4277));");
/*fuzzSeed-94431925*/count=880; tryItOut("mathy3 = (function(x, y) { return (Math.pow(((mathy1((( ~ (( + ( + (Math.log10(Math.pow(Math.fround(Math.trunc(y)), y)) >>> 0))) | 0)) | 0), Math.max((Math.asin(Math.atan(Math.log(x))) >>> 0), mathy0((( ~ (x | 0)) | 0), mathy1(y, y)))) | 0) | 0), (Math.log(Math.fround((Math.log1p(( + Math.fround(Math.asinh(( + Math.pow(( ! (x >>> 0)), x)))))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [-(2**53), 0x100000001, 1.7976931348623157e308, -0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, 0/0, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 1/0, -1/0, 0, 0x07fffffff, -(2**53-2), Math.PI, -0, -0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), -Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, -0x080000001, -0x080000000, 2**53-2, 42, 1]); ");
/*fuzzSeed-94431925*/count=881; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[[(void 0)]]) { /* no regression tests found */ }");
/*fuzzSeed-94431925*/count=882; tryItOut("");
/*fuzzSeed-94431925*/count=883; tryItOut("\"use strict\"; Array.prototype.reverse.apply(this.a1, [b1]);");
/*fuzzSeed-94431925*/count=884; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1, -0, 0.000000000000001, -(2**53-2), 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, 42, 0/0, 2**53+2, -0x07fffffff, -(2**53+2), -0x080000000, -0x100000001, 2**53, 1/0, 0x080000000, -Number.MIN_VALUE, 0x100000000, 2**53-2, -1/0, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=885; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (((Math.acosh((((y >>> 0) && -1/0) >>> 0)) >>> 0) >>> 0) || (Math.clz32((( - (x | 0)) | 0)) < (Math.trunc(( + ( + x))) | 0)))); }); ");
/*fuzzSeed-94431925*/count=886; tryItOut("\u000ce1.has(e1);let x = (4277);");
/*fuzzSeed-94431925*/count=887; tryItOut("\"use strict\"; this.m0 = new Map;");
/*fuzzSeed-94431925*/count=888; tryItOut("s1 = new String;");
/*fuzzSeed-94431925*/count=889; tryItOut("p2.toString = f0;");
/*fuzzSeed-94431925*/count=890; tryItOut("mathy2 = (function(x, y) { return Math.log1p(((Math.log10((( + Math.sin(Math.fround(mathy0(1, -1/0)))) | 0)) | 0) | 0)); }); testMathyFunction(mathy2, [0x100000000, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, -(2**53+2), -0, Math.PI, -Number.MAX_VALUE, 1/0, -1/0, 0, -(2**53-2), 0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 2**53-2, 2**53, 42, -0x07fffffff, -(2**53), 0x0ffffffff, 0x080000000, 0x100000001, 1, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=891; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((mathy3((Math.fround(((( ~ (Math.PI >>> 0)) >>> 0) | 0)) | 0), Math.max(y, mathy0(Math.fround(Math.atan2(Math.fround(Math.atanh(Number.MIN_VALUE)), Math.fround(x))), ((1 ? y : Math.fround((( + Math.atan2(( + x), x)) ** 0x100000000))) >>> 0)))) & ( + ( + Math.sin((Math.cos(( + Math.tan(0x100000000))) >>> 0))))) | 0); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 2**53+2, 1.7976931348623157e308, 0x080000001, Number.MAX_VALUE, 0, 0/0, -(2**53), -0x080000001, 1/0, -1/0, -0x100000001, Number.MIN_VALUE, -(2**53+2), 2**53-2, -0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0x0ffffffff, -(2**53-2), 0x100000001, 0.000000000000001, -0x100000000, 42, 1, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=892; tryItOut("\"use strict\"; a2.reverse(e1, ({\u3056: \u3056 }) ? (4277) : (4277), i2, g1.g1.v2);");
/*fuzzSeed-94431925*/count=893; tryItOut("\"use strict\"; v2 = a0.length;");
/*fuzzSeed-94431925*/count=894; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ (Math.trunc((Math.fround((x & x)) / Math.sin(( + Math.hypot(Math.cosh(Math.fround(x)), ((Math.fround(y) % y) >>> 0)))))) | 0)); }); testMathyFunction(mathy5, ['0', ({valueOf:function(){return 0;}}), (new Boolean(false)), -0, [], (new Number(-0)), (function(){return 0;}), NaN, 0, true, (new Number(0)), false, [0], 1, null, undefined, /0/, (new String('')), (new Boolean(true)), ({toString:function(){return '0';}}), objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), 0.1, '', '\\0', '/0/']); ");
/*fuzzSeed-94431925*/count=895; tryItOut("\"use strict\"; v0 = g1.eval(\"function f0(m2) x.__defineSetter__(\\\"x\\\", Promise.resolve) >>> m2\");");
/*fuzzSeed-94431925*/count=896; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.sign(( - (Math.clz32(((Math.max(((((( - x) | 0) >>> 0) * (y >>> 0)) >>> 0), ((( - y) | 0) , 0x07fffffff)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, -0x080000001, -0x07fffffff, 1, 0x100000001, 1.7976931348623157e308, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, 0x0ffffffff, 0.000000000000001, -0, -0x080000000, 0/0, -(2**53-2), -0x100000000, 0x100000000, Number.MIN_VALUE, 2**53, -(2**53), 2**53+2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, Math.PI, -Number.MAX_VALUE, -Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-94431925*/count=897; tryItOut("/*oLoop*/for (let rycuer = 0; rycuer < 71; ++rycuer) { yield null; } ");
/*fuzzSeed-94431925*/count=898; tryItOut("\"use strict\"; var ilhwlh = new ArrayBuffer(12); var ilhwlh_0 = new Uint32Array(ilhwlh); print(ilhwlh_0[0]); ilhwlh_0[0] = /\\r+?(?!^{0,3}\\b\\S|\\2)*|(?=^{0,2})/y; (-3);");
/*fuzzSeed-94431925*/count=899; tryItOut("L:while((x) && 0){const nfchod, b, ngvoiz;a0.pop(); }");
/*fuzzSeed-94431925*/count=900; tryItOut("\"use strict\"; /* no regression tests found */\nprint(x);\n");
/*fuzzSeed-94431925*/count=901; tryItOut("\"use strict\"; let (a) { /*hhh*/function qhkggb(b = false){Array.prototype.sort.apply(a1, [() =>  { \"use strict\"; \"use asm\"; return -6 } , a, g2]);}/*iii*/print(a); }");
/*fuzzSeed-94431925*/count=902; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=903; tryItOut("(eval(\";\", (({/*TOODEEP*/}))(false)));");
/*fuzzSeed-94431925*/count=904; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.cbrt((( + (((0x100000001 == Math.min(Number.MIN_VALUE, -0x080000001)) >>> 0) + ( + Math.atan2(( + Math.fround(Math.hypot(Math.fround(-(2**53+2)), Number.MIN_VALUE))), ( + x))))) === Math.max(1, Math.acos((y ? (( ~ (( + ( ~ y)) | 0)) | 0) : x))))) | 0); }); testMathyFunction(mathy4, [2**53+2, Math.PI, 1/0, -0x080000000, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, 0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, 0/0, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 0.000000000000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000000, -0, Number.MIN_VALUE, 0, 42, -0x080000001, 0x100000001, Number.MAX_VALUE, 2**53, -(2**53-2), -0x0ffffffff, -(2**53), 0x100000000]); ");
/*fuzzSeed-94431925*/count=905; tryItOut("\"use strict\"; d;");
/*fuzzSeed-94431925*/count=906; tryItOut("a0.pop();neuter(b2, \"change-data\");");
/*fuzzSeed-94431925*/count=907; tryItOut("f2 + o1.e2;");
/*fuzzSeed-94431925*/count=908; tryItOut("{ void 0; gcslice(11414298); }");
/*fuzzSeed-94431925*/count=909; tryItOut("\"use strict\"; a2 = arguments.callee.caller.arguments;\nprint(x);\n");
/*fuzzSeed-94431925*/count=910; tryItOut("o2.v1 = a2.length;");
/*fuzzSeed-94431925*/count=911; tryItOut("testMathyFunction(mathy0, [-1/0, Number.MIN_VALUE, 2**53, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -0, 0x080000001, 1, Math.PI, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, -0x100000001, -0x080000001, 2**53-2, 1.7976931348623157e308, Number.MAX_VALUE, 0x080000000, 42, 0.000000000000001, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0, -0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 0/0, 0x100000001, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=912; tryItOut("var vwthwx = new ArrayBuffer(8); var vwthwx_0 = new Int16Array(vwthwx); print(vwthwx_0[0]); o1.v1 = new Number(p2);");
/*fuzzSeed-94431925*/count=913; tryItOut("h1.keys = (function() { try { x = e0; } catch(e0) { } try { o2.t1 = new Int16Array(this.t0); } catch(e1) { } s0 += 'x'; return this.p2; });");
/*fuzzSeed-94431925*/count=914; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( - (( ~ Math.fround(Math.pow((Math.hypot(0/0, (Math.atan(((y ** x) !== x)) | 0)) | 0), ((Math.sqrt(((Math.pow((x >>> 0), (x >>> 0)) >>> 0) >>> 0)) >>> 0) | 0)))) | 0)); }); testMathyFunction(mathy3, [-0x07fffffff, 0, 0x080000001, -0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, Math.PI, 1.7976931348623157e308, 42, -Number.MIN_VALUE, -1/0, 0x100000000, 2**53, 0x0ffffffff, -(2**53), 0x100000001, 0.000000000000001, -0, Number.MIN_VALUE, -0x080000000, 0x07fffffff, -0x080000001, 2**53+2, 2**53-2, -(2**53-2), 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, -0x100000000, -(2**53+2), 0/0]); ");
/*fuzzSeed-94431925*/count=915; tryItOut("/*ODP-1*/Object.defineProperty(e0, \"constructor\", ({set: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { throw 3; }, has: ((/*wrap2*/(function(){ \"use strict\"; var kzmuvb = ((x = \"\\uE939\")); var pkaqtd = /*wrap3*/(function(){ var yzjtnf = undefined; ((makeFinalizeObserver('nursery')))(); }); return pkaqtd;})()).apply).call, hasOwn: function() { throw 3; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: (let (e=eval) e), enumerate: undefined, keys: function() { return Object.keys(x); }, }; })}));");
/*fuzzSeed-94431925*/count=916; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 4097.0;\n    d2 = (-68719476737.0);\n    (Float32ArrayView[((Uint16ArrayView[((!(0x56585e22))+(0xfdc1490e)) >> 1])) >> 2]) = ((Float32ArrayView[4096]));\n    (Float32ArrayView[(((((0xf8c8cb8c)) << ((0xfbb3aed5)+(0xff204b91))) <= (~~(+(((Float32ArrayView[2]))))))+(0xff3bad51)) >> 2]) = (((Float64ArrayView[(((0xa5b15f50) >= (0xcc03a0ac))-(0xf89f3575)) >> 3])));\n    d0 = (d1);\n    return +((Float32ArrayView[2]));\n  }\n  return f; })(this, {ff: function(y) { v2 = (p1 instanceof b2); }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [Math.PI, 1/0, -1/0, -0, -0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, -0x100000001, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), 2**53-2, 0/0, -0x100000000, 0x080000001, 1, 42, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, 0x080000000, 0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, 0, 0.000000000000001, 2**53+2]); ");
/*fuzzSeed-94431925*/count=917; tryItOut("{} = ((e =  /x/ )), x = /(?:$*?)|(\u7784{2}${0,0}|[\\D])|\\2\\3{3,}/gm, x, this.e, a, wppvuz;return  /x/g ;");
/*fuzzSeed-94431925*/count=918; tryItOut("for([z, w] = x = Proxy.createFunction(({/*TOODEEP*/})( /x/g ), Math.cos, function(y) { \"use strict\"; neuter(o0.b2, \"same-data\"); }) == eval(\"this\") in ((x) = true)) {Array.prototype.pop.call(a2);print(x); }");
/*fuzzSeed-94431925*/count=919; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.log(mathy2(((( ~ ( + (Math.fround(Number.MIN_SAFE_INTEGER) & Math.fround(-(2**53+2))))) | 0) < Math.min(Math.fround(( ~ Math.fround(x))), Math.PI)), (Math.hypot(y, -Number.MAX_VALUE) >>> 0))) == mathy0(Math.imul(((x > (Math.fround(( ! Math.fround((Math.atan2(2**53-2, (x >>> 0)) >>> 0)))) | 0)) | 0), Math.fround((Math.fround((1.7976931348623157e308 % x)) << y))), Math.fround(((x >>> 0) ? (y | 0) : ((x * mathy4(x, ( + Math.atan2(( + ( + (Math.fround(0.000000000000001) && ( + Number.MAX_VALUE)))), ( + y))))) >>> 0))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x100000001, 0/0, 0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, 0, -(2**53), 2**53+2, -0, 2**53, 1/0, -0x100000001, -0x07fffffff, Number.MAX_VALUE, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, -Number.MAX_VALUE, Math.PI, 2**53-2, 1, -1/0, 42, 0x100000000]); ");
/*fuzzSeed-94431925*/count=920; tryItOut("/*RXUB*/var r = r2; var s = \"\\n\\n\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=921; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.abs((mathy1(( + Math.log1p(( + Math.fround((Math.fround(y) ^ Math.fround(y)))))), Math.asin((( + ( ~ ( + ( + (( + x) !== ((Math.min(( + x), (-Number.MAX_VALUE | 0)) | 0) >>> 0)))))) !== -(2**53)))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[(4277), new String(''), (4277), (4277), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (4277), (4277), 6, (4277), new String(''), new String('q'), 6, (4277), (4277), new String('q'), new String(''), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String(''), 6, (4277), (4277), new String('q'), new String(''), new String('q'), new String(''), new String('q'), 6, new String('q'), new String('q'), new String(''), 6, 6, new String(''), new String(''), 6, new String(''), new String('q'), new String('q'), new String('q'), (4277), new String(''), new String('q'), 6, 6, new String('q'), (4277), new String('q'), (4277), new String(''), new String(''), (4277), 6, new String(''), new String(''), new String('q'), new String(''), new String(''), new String('')]); ");
/*fuzzSeed-94431925*/count=922; tryItOut("testMathyFunction(mathy4, [Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -0, -(2**53-2), Number.MIN_VALUE, 1, 2**53+2, 2**53-2, -1/0, -(2**53), -0x080000001, 0, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, 42, -Number.MIN_VALUE, 0x100000000, -0x100000000, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 2**53, 0x100000001, 0/0]); ");
/*fuzzSeed-94431925*/count=923; tryItOut("/*hhh*/function goager(){x;}/*iii*/a0.length = 19;");
/*fuzzSeed-94431925*/count=924; tryItOut("\"use strict\"; print(uneval(o0));");
/*fuzzSeed-94431925*/count=925; tryItOut("\"use strict\"; \"use asm\"; print([1]);");
/*fuzzSeed-94431925*/count=926; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! Math.fround((( + ( + y)) != (Math.acosh(((Math.imul(x, Math.fround(( + ( ~ ( + -0x080000001))))) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 0, -0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0x080000000, 2**53, 0.000000000000001, 1.7976931348623157e308, 1, -0, Math.PI, -1/0, 1/0, 0x100000001, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, -(2**53-2), Number.MAX_VALUE, 42, 0/0, 0x0ffffffff, -0x080000001, 2**53-2]); ");
/*fuzzSeed-94431925*/count=927; tryItOut("a2[9] = b2;");
/*fuzzSeed-94431925*/count=928; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( - ( + (Math.max(((Math.imul((((Math.fround(x) ** Math.fround(( - ( + Math.fround((x >>> 0)))))) | 0) | 0), ( + mathy0((Math.min(Math.fround((0x07fffffff >>> 0)), (( ~ Math.fround(Math.max((x | 0), (0x100000000 | 0)))) | 0)) >>> 0), Math.min(0x0ffffffff, ((x || Math.fround(Number.MIN_SAFE_INTEGER)) >>> 0))))) | 0) | 0), ((mathy0(Math.hypot(Math.tan(x), Math.atanh(x)), (Math.atanh(Math.fround(x)) != x)) >>> 0) | 0)) | 0))) | 0); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, -Number.MAX_VALUE, -(2**53+2), 0x07fffffff, 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, -0x080000000, 0, 42, 0/0, -0x07fffffff, 2**53-2, 0x080000000, 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, -1/0, 0x100000000, 0x100000001, -0x100000001, 1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=929; tryItOut("x = v0;");
/*fuzzSeed-94431925*/count=930; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?=\\\\s{0,}(?:\\\\b|\\\\W)*(?![^]){524287,}))*\", \"yim\"); var s = \"\\ua024\\ua024\\ua024_\\n\\ua024\\ua024\\ua024_\\n\\n\\ua024\\ua024\\ua024_\\n__0__a_\\ua024\\ua024\\ua024_\\n\\ua024\\ua024\\ua024_\\n\\ua024\\ua024\\ua024_\\n__0__a_\\ua024\\ua024\\ua024_\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=931; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.acosh((Math.hypot(( + Math.fround(( + Math.fround(x)))), Math.asin(( + (((y | 0) , ( + y)) !== y)))) & Math.imul((((Number.MIN_SAFE_INTEGER | 0) ? -0x080000000 : Math.pow(1, (Math.min(((Math.log1p((y >>> 0)) >>> 0) | 0), (y | 0)) | 0))) >>> 0), Math.cosh(Math.acos(( + ( - x))))))); }); testMathyFunction(mathy0, [-(2**53+2), -0x080000001, Number.MIN_VALUE, 0, 2**53, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, Math.PI, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, 0x080000001, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -0x100000001, -0, 2**53-2, -(2**53), -0x0ffffffff, 1/0, -Number.MAX_VALUE, -0x080000000, 0/0, 0x080000000, -0x100000000, -(2**53-2), 1.7976931348623157e308, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 0.000000000000001, -1/0]); ");
/*fuzzSeed-94431925*/count=932; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.fround((Math.max(Math.fround(( ~ ( ! Math.fround((Math.min(( + Math.exp(( + Number.MAX_VALUE))), (x >>> 0)) >>> 0))))), (Math.cos((Math.atan2((((( ! (( - (y >>> 0)) >>> 0)) >>> 0) , (x >>> 0)) >>> 0), 0.000000000000001) >>> 0)) | 0)) >>> 0)) >> Math.fround(Math.log2(( ! ( + Math.atan2(( + Math.log((function(x, y) { return y; }))), ( + (Math.pow((x | 0), (y | 0)) | 0)))))))); }); ");
/*fuzzSeed-94431925*/count=933; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h2, a2);");
/*fuzzSeed-94431925*/count=934; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.cos(( ~ Math.tan(Math.asinh(x)))); }); testMathyFunction(mathy3, [-0x080000001, -(2**53-2), 0.000000000000001, Math.PI, -Number.MAX_VALUE, 0, -(2**53+2), 2**53-2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, 2**53, Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, -0, 42, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, 1, 1/0, 0x100000001, -Number.MIN_VALUE, -(2**53), 0x100000000, -0x080000000, Number.MIN_VALUE, 0x080000001, -0x100000000, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=935; tryItOut("mathy3 = (function(x, y) { return Math.atanh((Math.abs(mathy1((Math.acosh(-0x080000001) != (2**53-2 >>> 0)), Math.fround(Math.pow(Math.fround(y), Math.fround(Math.log1p(-(2**53+2))))))) | 0)); }); testMathyFunction(mathy3, [-0x07fffffff, 0x07fffffff, Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, 0/0, -0, 0, Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), -1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 0x080000001, 0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 2**53, -0x080000001, 2**53-2, 0.000000000000001, 2**53+2, 1/0, 0x100000000, -(2**53+2), -0x100000000, 42, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -0x080000000]); ");
/*fuzzSeed-94431925*/count=936; tryItOut("mathy3 = (function(x, y) { return (((mathy1(( + Math.log(Math.fround(Math.min(( + ( + ( + Math.pow(x, y)))), ((y | 0) <= (x | 0)))))), Math.atan(mathy2((Math.sin(Math.fround(x)) | 0), y))) | 0) << (Math.acos(((Math.hypot((y | 0), y) | 0) >>> 0)) >>> 0)) >= ( + (( + Math.log1p(( + mathy0((x || Math.fround(( - x))), (Math.asin(y) >>> 0))))) | ( + mathy1(( ~ (x >>> 0)), ( - Math.fround(Math.min(Number.MIN_SAFE_INTEGER, x)))))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 1, 0/0, 2**53+2, 42, -0x0ffffffff, -0x100000001, 0x100000000, 0x080000000, -0x07fffffff, 1/0, -0, -0x100000000, -(2**53-2), -0x080000000, 2**53, -1/0, 2**53-2, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, 0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, 0, 1.7976931348623157e308, Math.PI]); ");
/*fuzzSeed-94431925*/count=937; tryItOut("\"use strict\"; h0.keys = (function() { try { v2 + ''; } catch(e0) { } /*MXX3*/g1.Uint8ClampedArray = g0.Uint8ClampedArray; return o1.v0; });");
/*fuzzSeed-94431925*/count=938; tryItOut("/*ODP-2*/Object.defineProperty(o0, \"-2\", { configurable: false, enumerable: y.__defineSetter__(\"x\", function(y) { print(x); }), get: f0, set: f1 });");
/*fuzzSeed-94431925*/count=939; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.pow(( ! ( ~ Math.fround(Math.exp(Math.fround(y))))), Math.max(( + ( + Math.sin(((mathy1(y, x) | 0) | 0)))), Math.abs(( + ( + (x >>> ( + x))))))); }); testMathyFunction(mathy3, ['\\0', (new Boolean(true)), false, (new Boolean(false)), ({valueOf:function(){return 0;}}), undefined, NaN, ({valueOf:function(){return '0';}}), '', null, '0', (new Number(-0)), ({toString:function(){return '0';}}), 1, (new Number(0)), true, '/0/', (function(){return 0;}), /0/, (new String('')), [], 0, [0], -0, 0.1, objectEmulatingUndefined()]); ");
/*fuzzSeed-94431925*/count=940; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=941; tryItOut("const b1 = new SharedArrayBuffer(11);");
/*fuzzSeed-94431925*/count=942; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-94431925*/count=943; tryItOut("\"use asm\"; testMathyFunction(mathy1, [-(2**53-2), -Number.MIN_VALUE, 0/0, 2**53, 0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, 0x100000001, -0x07fffffff, -0, 2**53-2, Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -1/0, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), -0x080000001, Number.MAX_VALUE, -0x100000000, 0x080000001, 42, 0.000000000000001, 0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 1, 1.7976931348623157e308, 0x100000000, Number.MIN_SAFE_INTEGER, 1/0, -(2**53)]); ");
/*fuzzSeed-94431925*/count=944; tryItOut("\"use strict\"; t1[13];");
/*fuzzSeed-94431925*/count=945; tryItOut("\"use strict\"; { void 0; bailout(); } /* no regression tests found */");
/*fuzzSeed-94431925*/count=946; tryItOut("\"use strict\"; /*RXUB*/var r = /[^]/im; var s = \"\\n\"; print(r.test(s)); ");
/*fuzzSeed-94431925*/count=947; tryItOut("for (var p in h0) { try { t2.set(a2, ({valueOf: function() { v2 = Object.prototype.isPrototypeOf.call(p1, this.b0);return 8; }})); } catch(e0) { } try { m1.set(i1, h0); } catch(e1) { } try { s0 += o2.s0; } catch(e2) { } m1.get(o2); }");
/*fuzzSeed-94431925*/count=948; tryItOut("\"use strict\"; (void schedulegc(g0));");
/*fuzzSeed-94431925*/count=949; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((0xcc9c34c) % (((i1)-((x) != (((0xd46356ad)*-0x65217) | ((0x93ae3bcf)*-0x47075))))>>>(-0x81602*(((((-0x1e48b80))) ^ ((0x426a0704) / (0x623594bd))) >= (abs((((0x7d744630)) >> ((-0x8000000))))|0))))))|0;\n  }\n  return f; })(this, {ff: Date.prototype.setUTCMonth}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x100000001, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, 1, 0x07fffffff, 2**53-2, 2**53+2, 0.000000000000001, -(2**53), -0, 1.7976931348623157e308, 0x080000001, 0x0ffffffff, 2**53, Number.MIN_VALUE, -(2**53-2), -1/0, -0x07fffffff, 0x100000001, 42, 0x080000000, 0x100000000, -Number.MAX_VALUE, 0, 0/0, -(2**53+2), Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=950; tryItOut("\"use strict\"; h2.defineProperty = (function() { try { this.o0 + a2; } catch(e0) { } try { s1 += 'x'; } catch(e1) { } try { o0.a1.shift(); } catch(e2) { } Object.defineProperty(this, \"g2.t2\", { configurable: a(), enumerable: throw true,  get: function() {  return new Int32Array(5); } }); throw v1; });for (var p in s2) { try { a0 = r2.exec(this.s2); } catch(e0) { } try { o2.s1 += 'x'; } catch(e1) { } m2.set(h2, o2); }");
/*fuzzSeed-94431925*/count=951; tryItOut("\"use strict\"; s1 += s2;");
/*fuzzSeed-94431925*/count=952; tryItOut("\"use strict\"; z = x;;\ng1.f1 + this.m1;\n");
/*fuzzSeed-94431925*/count=953; tryItOut("\"use strict\"; ;");
/*fuzzSeed-94431925*/count=954; tryItOut("/*infloop*/for(let b; (4277); (27.throw(false))) {print(i0);Array.prototype.reverse.apply(a1, [b1, o0, s2, f2, b2, p1, f0]); }");
/*fuzzSeed-94431925*/count=955; tryItOut("");
/*fuzzSeed-94431925*/count=956; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.max(Math.max(Math.hypot(( + (x ? (( + (x | 0)) | 0) : -(2**53+2))), (((Math.tan(Math.expm1(x)) >= (Math.acosh(Math.fround(-0x100000000)) | 0)) | 0) & ( + ( ~ ( + Math.max(x, mathy0(y, x))))))), (Math.imul(( ~ (Math.atan2(y, -0x100000001) >>> 0)), ((mathy3((x | 0), y) + ( + Math.atan2(0/0, ( + x)))) | 0)) >>> 0)), Math.hypot(( ~ mathy0((Math.pow(x, ((Math.pow(0x100000000, x) | 0) !== ( + (x + x)))) >>> 0), Math.fround(Math.imul(Math.fround(x), Math.fround(x))))), (( + (Math.fround(Math.log2(( + (( + y) * ( + -(2**53+2)))))) >>> (Math.cosh((Math.min((Math.PI | 0), Number.MIN_VALUE) | 0)) >>> 0))) | 0))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -0, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), 2**53+2, -0x07fffffff, 42, 0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, 0, Math.PI, 2**53-2, 0x080000000, -(2**53), -0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, 0.000000000000001, -1/0, 0x07fffffff, -Number.MIN_VALUE, 1/0, 2**53, 0x100000001]); ");
/*fuzzSeed-94431925*/count=957; tryItOut("\"use strict\";  /x/g ;\na2 = Array.prototype.concat.call(a1, a0);\n");
/*fuzzSeed-94431925*/count=958; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-94431925*/count=959; tryItOut("[].throw(e);function w(c) { return allocationMarker() } /*RXUB*/var r = new RegExp(\"(\\\\B*?\\\\1(?:[^]\\\\d.|\\\\D|\\\\S{0,})\\\\2[^\\u00cc\\ueb21][^]*?(\\ue79a)|[^\\\\w][^\\\\W{]{1,4}*?)\", \"m\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=960; tryItOut("e1.add(b2);");
/*fuzzSeed-94431925*/count=961; tryItOut("for (var v of this.g2) { try { /*MXX1*/o0 = g1.Math.LN2; } catch(e0) { } s2 += 'x'; }");
/*fuzzSeed-94431925*/count=962; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + (Math.log2(Math.ceil(y)) ? (Math.imul((Math.atan2((Math.imul(Number.MAX_SAFE_INTEGER, Math.sign(x)) | 0), (Math.sinh(( + Math.fround(y))) | 0)) | 0), (((x | 0) || 0.000000000000001) | 0)) >>> 0) : (Math.cbrt((mathy1(42, x) >>> 0)) >= (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })))) ? Math.log10(( + Math.fround(mathy0(( + Math.min(( + ( + y)), ( + x))), Math.max(Math.fround(-(2**53-2)), Math.fround(y)))))) : ( + (Math.fround(Math.fround(( + Math.fround((x , x))))) % Math.fround((Math.fround((mathy0(Math.fround((y >>> x)), y) , Math.fround(y))) && ( + (((((( ~ (x | 0)) | 0) | 0) === -0x100000000) | x) & x)))))))); }); testMathyFunction(mathy2, [2**53-2, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, -Number.MAX_VALUE, -0x080000001, 0/0, 2**53+2, Number.MIN_VALUE, -0x100000000, 0x080000001, 0.000000000000001, 0x100000000, -0x080000000, 0x080000000, 1/0, 0x07fffffff, -0x07fffffff, -(2**53+2), -0, 0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, -0x100000001, 0, -1/0, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=963; tryItOut("\"use strict\"; for(let d in []);");
/*fuzzSeed-94431925*/count=964; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.pow((Math.max(Math.fround(Math.trunc(( - Math.fround(Math.hypot((x >>> 0), Math.fround((( ~ x) | 0))))))), (Math.atan(2**53+2) >>> 0)) | 0), (Math.min((Math.acosh((( ! (Math.hypot(y, y) >>> 0)) >>> 0)) >>> 0), (mathy3(mathy1(1, ( + mathy3(x, x))), y) >>> 0)) >>> 0)) | 0) > Math.asinh((Math.pow((Math.fround(Math.abs(Math.fround(Number.MAX_VALUE))) | 0), (( ! y) | 0)) | 0))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, -(2**53+2), 0/0, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), 2**53, Math.PI, -0, -Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, 1/0, -0x100000000, 0, 0x080000000, 0x100000001, 1, 2**53-2, 0x100000000, -0x100000001, 42, -(2**53-2), 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=965; tryItOut("o2 + a1;");
/*fuzzSeed-94431925*/count=966; tryItOut("/*vLoop*/for (var fczjbl = 0, a = Proxy.createFunction(({/*TOODEEP*/})(8), WeakMap, Number.parseFloat); fczjbl < 38; ++fczjbl) { var d = fczjbl; print(( \"\" )(window)); } ");
/*fuzzSeed-94431925*/count=967; tryItOut("mathy0 = (function(x, y) { return (( + ( + Math.exp(Math.min(( - ((y | y) | 0)), ( + Math.abs(x)))))) >>> 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 1/0, 2**53+2, -(2**53), 1, Math.PI, Number.MAX_VALUE, 0x080000000, 42, -0, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), -0x100000001, -1/0, -0x07fffffff, 0x100000000, -0x100000000, -(2**53+2), Number.MIN_VALUE, 0.000000000000001, 2**53-2, 0x100000001, 0/0, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=968; tryItOut("L:do {g0.g2.a2 + '';; } while(( /x/g ) && 0);\nprint(x);\n");
/*fuzzSeed-94431925*/count=969; tryItOut("testMathyFunction(mathy0, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, 0.000000000000001, 0x100000001, 1/0, -0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 1, 0x100000000, 0x07fffffff, 0x080000001, 2**53, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, -0x080000000, -(2**53+2), -(2**53), 0, -0, -0x080000001, 0x080000000, 2**53+2, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=970; tryItOut("o0.m2 + '';");
/*fuzzSeed-94431925*/count=971; tryItOut("m0 + '';");
/*fuzzSeed-94431925*/count=972; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - (((Math.hypot((Math.fround(mathy0(x, x)) , Math.fround(Math.asinh((0x080000001 >>> 0)))), Math.tanh(Math.sqrt(x))) | 0) ? (( ! ((x << 2**53) >>> 0)) >>> 0) : (Math.clz32(mathy3(Number.MIN_SAFE_INTEGER, Math.fround(( + ( + Math.atan2(y, Math.imul(( + -(2**53+2)), y))))))) | 0)) | 0)); }); ");
/*fuzzSeed-94431925*/count=973; tryItOut("a1[8] = t1;");
/*fuzzSeed-94431925*/count=974; tryItOut(" for  each(var x in --this.zzz.zzz) a = false, zdpnfs, NaN, fxckfa, wgfsfm, c, ucsioc, bozktx, wqmgis, fawavl;print(x);");
/*fuzzSeed-94431925*/count=975; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(s1, p0);");
/*fuzzSeed-94431925*/count=976; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; void schedulegc(57); } void 0; } print();");
/*fuzzSeed-94431925*/count=977; tryItOut("o1.v0 = Object.prototype.isPrototypeOf.call(h0, p0)\n");
/*fuzzSeed-94431925*/count=978; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot(((mathy1(Math.fround(Math.imul(((mathy4(-(2**53+2), (y >>> 0)) & x) | 0), Math.fround(y))), (Math.pow(((( - y) | 0) | 0), (( + x) | 0)) | 0)) << (( + Math.atan2(( + Number.MIN_SAFE_INTEGER), ( + x))) , (y < (Math.atan((((x ** x) >>> 0) | 0)) | 0)))) | 0), Math.fround(Math.fround(Math.max(Math.fround((Math.acos(Math.cosh((Math.imul((0/0 | 0), (x | 0)) | 0))) == x)), Math.fround(Math.log1p(Math.fround(Math.log(Math.fround(Math.asinh(( + 2**53-2)))))))))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, 0x100000000, 1, 0, 0x080000001, 2**53-2, 1/0, -(2**53), -(2**53+2), -0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -1/0, -0x100000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, 2**53+2, -(2**53-2), 0x0ffffffff, -0x07fffffff, -0x0ffffffff, 2**53, -Number.MIN_VALUE, 42, 0x080000000, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=979; tryItOut("\"use strict\"; /*infloop*/ for (let eval of Math.hypot(4, -24)) {(((x = /\\b|\\b/gy)));var a1 = a2.filter((function() { try { m0.set(s0, v0); } catch(e0) { } try { g1.g2.toString = (function() { try { t0 = new Uint16Array(v0); } catch(e0) { } try { a0.shift(); } catch(e1) { } e0.add(h1); return t1; }); } catch(e1) { } try { (void schedulegc(g1)); } catch(e2) { } g1.offThreadCompileScript(\"/* no regression tests found */\"); throw o0; }), (void options('strict'))); }");
/*fuzzSeed-94431925*/count=980; tryItOut("/*tLoop*/for (let e of /*MARR*/[({}), new String(''), 1e-81,  '' , 1e-81, 1e-81, 1e-81, ({}),  '' , ({}), ({}),  '' , new String(''), 1e-81, ({}), 1e-81,  '' , ({}), ({}), 1e-81, ({}),  '' ,  '' ]) { m0.set(o2, this); }");
/*fuzzSeed-94431925*/count=981; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((( ! (((((y | 0) || (( + Math.hypot(( + y), y)) | 0)) | 0) - x) , x)) >>> 0) > Math.hypot(( + ((y > ( + mathy0(y, mathy0((y ? y : y), x)))) ? Math.acosh(x) : ( + (x >> ( + ( + x)))))), ( + ( ~ x)))) | 0); }); testMathyFunction(mathy2, /*MARR*/[ /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, function(){},  /x/g , function(){},  /x/g , function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, function(){}, function(){}, function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){},  /x/g ,  /x/g , function(){}, function(){}, function(){},  /x/g , function(){},  /x/g ,  /x/g , function(){}, function(){},  /x/g ,  /x/g ,  /x/g , function(){}, function(){},  /x/g ,  /x/g , function(){},  /x/g , function(){}, function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, function(){}, function(){},  /x/g ,  /x/g , function(){}, function(){},  /x/g , function(){},  /x/g , function(){}, function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){},  /x/g , function(){}, function(){},  /x/g ,  /x/g , function(){}, function(){}, function(){}, function(){},  /x/g ,  /x/g , function(){},  /x/g , function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){},  /x/g , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, function(){},  /x/g , function(){},  /x/g , function(){},  /x/g ,  /x/g ,  /x/g , function(){},  /x/g ,  /x/g , function(){}, function(){}, function(){}, function(){},  /x/g ,  /x/g , function(){},  /x/g ,  /x/g ,  /x/g , function(){}, function(){},  /x/g ,  /x/g ,  /x/g , function(){}, function(){}]); ");
/*fuzzSeed-94431925*/count=982; tryItOut("mathy5 = (function(x, y) { return ( ! ((Math.min((( + ((Math.max((((y >>> 0) ^ -Number.MIN_VALUE) >>> 0), (y >>> 0)) >>> 0) || ( + Math.trunc(( + 0x100000001))))) >>> 0), Math.fround(y)) >>> 0) << (Math.log10(((( + Math.pow(x, mathy2(-Number.MAX_SAFE_INTEGER, x))) !== y) | 0)) | 0))); }); testMathyFunction(mathy5, [0x100000000, -(2**53), -(2**53-2), -0x0ffffffff, -0x100000000, 0, -(2**53+2), 0.000000000000001, -1/0, -0x080000001, -0x07fffffff, 0x0ffffffff, -0, 1, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, Math.PI, 2**53-2, -0x080000000, Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53, 42]); ");
/*fuzzSeed-94431925*/count=983; tryItOut("/*vLoop*/for (var jleviq = 0; jleviq < 5; ++jleviq) { e = jleviq; { void 0; try { gcparam('sliceTimeBudget', 79); } catch(e) { } } } ");
/*fuzzSeed-94431925*/count=984; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      {\n        {\n          (Float32ArrayView[(((imul((0xeef71837), (0x53c2622f))|0) == ((-0x4e247*(0x53b11337))|0))-(i0)+(i0)) >> 2]) = ((-562949953421313.0));\n        }\n      }\n    }\n    i0 = ((((void options('strict'))) & ((i0)+(i0)-((0x6e20aa94) == (abs((~~(NaN)))|0)))));\n    i0 = ((0x20b62c8e) >= ((Float64ArrayView[((i0)) >> 3])));\n    {\n      i1 = (i1);\n    }\n    {\n      return ((-0x794b*(i1)))|0;\n    }\n    i0 = (!((((0x80d81fd)+(i0))>>>((i0)-(i1))) <= (0x6ebcfe17)));\n    i1 = (i1);\n    i1 = (i1);\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: ({} = x)}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=985; tryItOut("v0 = (a2 instanceof b0);");
/*fuzzSeed-94431925*/count=986; tryItOut("(yield window);");
/*fuzzSeed-94431925*/count=987; tryItOut("mathy5 = (function(x, y) { return ((((Math.min(( ! Math.fround((Math.fround(y) >>> Math.fround((Math.atan2((x | 0), (Math.sin(y) | 0)) | 0))))), ((Math.atan(-Number.MIN_VALUE) >>> 0) >>> 0)) >>> 0) >>> 0) ^ (( ~ (( + Math.sinh(((((Math.trunc((y | 0)) | 0) | 0) + y) >>> 0))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000001, 0.000000000000001, 0, 0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, -0x080000001, -(2**53), 0x100000000, 0x080000000, -0x07fffffff, 0x100000001, 0x0ffffffff, -(2**53-2), -0x080000000, 1/0, 0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 0x080000001, 1, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53, 42]); ");
/*fuzzSeed-94431925*/count=988; tryItOut("\"use strict\"; a2.forEach(f1, new (let (w) /\\3/yi)(), o1);");
/*fuzzSeed-94431925*/count=989; tryItOut("\"use strict\"; this.s1 = a2[this.v1];");
/*fuzzSeed-94431925*/count=990; tryItOut("mathy4 = (function(x, y) { return Math.clz32((mathy3(Math.tanh(((Math.sinh(( ~ \"\\uC1C6\")) | 0) ? y : ( - mathy3(y, ( + (((x >>> 0) * (y >>> 0)) >>> 0)))))), ((x & Math.log2(y)) === Math.ceil((( + (Math.pow((y | 0), (-0x080000000 | 0)) | 0)) ? y : mathy1(Math.fround(-(2**53+2)), Math.fround(x)))))) | 0)); }); testMathyFunction(mathy4, [(new Number(-0)), (new Number(0)), (function(){return 0;}), null, (new Boolean(false)), '/0/', 1, NaN, [0], (new Boolean(true)), undefined, /0/, ({valueOf:function(){return '0';}}), '', false, '0', objectEmulatingUndefined(), 0, -0, 0.1, '\\0', true, ({toString:function(){return '0';}}), (new String('')), [], ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-94431925*/count=991; tryItOut("\"\\uFDA0\";");
/*fuzzSeed-94431925*/count=992; tryItOut("o0.v2 = evaluate(\"v2 = (v1 instanceof v0);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: x, sourceIsLazy: allocationMarker(), catchTermination: true }));");
/*fuzzSeed-94431925*/count=993; tryItOut("mathy5 = (function(x, y) { return ( - ((Math.fround((Math.fround(-1/0) != Math.fround(y))) * ( ! Math.imul(( + ( + Math.pow(( + Math.PI), (y + 1)))), ( ! y)))) | 0)); }); testMathyFunction(mathy5, [1/0, 0.000000000000001, 0x100000001, -(2**53-2), 2**53, -0x080000001, -0x0ffffffff, 0/0, -1/0, -0x07fffffff, 0x100000000, -(2**53+2), 0x080000000, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 0, Number.MAX_SAFE_INTEGER, -(2**53), 1, -Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -0, 2**53+2, -0x100000000, 2**53-2, Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=994; tryItOut("\"use strict\"; Array.prototype.sort.call(a0, function(q) { \"use strict\"; return q; });");
/*fuzzSeed-94431925*/count=995; tryItOut("mathy0 = (function(x, y) { return (Math.fround((Math.fround(Math.min((Math.sign(-0x080000000) >= x), ( ~ x))) === Math.fround(Math.cbrt(Math.min((y << 2**53-2), x))))) === (Math.imul((Math.exp(Math.pow(( + Math.min(( + ((Math.tan(x) >>> 0) >> y)), Math.fround(x))), y)) >>> 0), Math.hypot(Math.fround((((( + Number.MIN_SAFE_INTEGER) << x) >>> 0) === Math.fround(y))), (( - ( + y)) | 0))) >>> 0)); }); testMathyFunction(mathy0, [0x100000000, 0/0, 0, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 1, -0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, 2**53, -1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 42, -0x100000000, 0x100000001, 0x080000001, 0x0ffffffff, -(2**53-2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, -0x080000000, -Number.MIN_VALUE, -0x100000001, 0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=996; tryItOut("L:for(var x = this in [(delete b.\u3056)]) {print(p2);e0.has(this.g0.s0); }");
/*fuzzSeed-94431925*/count=997; tryItOut("/*infloop*/for(let {} = Math.imul((4277), 18); (x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: encodeURI, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(15), Math.hypot( /x/g , \"\u03a0\"))); (makeFinalizeObserver('tenured'))) e1.delete(g0.f1);");
/*fuzzSeed-94431925*/count=998; tryItOut("mathy0 = (function(x, y) { return ( + (( + (Math.tan(Math.sqrt(-0x100000001)) <= (Math.max(x, Math.fround((-0x080000000 * ( + y)))) ? (Math.atan(x) >>> 0) : y))) ? ( + Math.fround(Math.min((Math.imul(((( ! (y >>> 0)) >>> 0) | 0), Math.fround(Math.atanh(y))) >>> 0), Math.fround(Math.fround((Math.fround((Math.min(x, 0.000000000000001) ? 1 : (x | Number.MAX_SAFE_INTEGER))) === Math.fround(( ! ( ! x))))))))) : ( + (Math.abs(((( + Math.sqrt(( + ( + (y ** x))))) , (( + Math.imul((Math.fround(y) - Math.fround(y)), ( + (( - Math.fround(x)) >>> 0)))) * ( + (-Number.MIN_SAFE_INTEGER >>> 0)))) >>> 0)) > ( - ((x ? y : ( + Math.max((y >>> 0), (-0x080000000 >>> 0)))) ? (Math.asin((y | 0)) | 0) : y)))))); }); ");
/*fuzzSeed-94431925*/count=999; tryItOut("testMathyFunction(mathy0, [Math.PI, -0, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), -(2**53), Number.MIN_VALUE, 0.000000000000001, 0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 1, -(2**53-2), 0, 0x100000001, 2**53+2, -0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000001, -1/0, 0/0, 0x07fffffff, 0x080000000, Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-94431925*/count=1000; tryItOut("a2.sort((function() { for (var j=0;j<12;++j) { f1(j%4==1); } }));");
/*fuzzSeed-94431925*/count=1001; tryItOut("\"use strict\"; ;");
/*fuzzSeed-94431925*/count=1002; tryItOut("v2 = t1.byteLength;");
/*fuzzSeed-94431925*/count=1003; tryItOut("v2 = g1.eval(\"i2.send(o1);\");");
/*fuzzSeed-94431925*/count=1004; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x080000000, 1, 0, 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, 1/0, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, -0x080000001, 2**53, -1/0, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, 0x080000000, -0x07fffffff, 42, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 0/0, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 0x100000000, 0x100000001, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1005; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.fround((Math.pow(-0x0ffffffff, Math.sign((Math.min((x | 0), x) | 0))) || (( - ((x | (Math.log10((0x100000001 | 0)) | 0)) | 0)) | 0))) > Math.atan2((( ~ Math.fround(x)) % ( + Math.round(( + ((((Math.min(x, y) | 0) | 0) * (Math.atan(y) | 0)) | 0))))), Math.fround(Math.min((Math.acos((( + ( ! x)) | 0)) | 0), (( ~ y) | 0))))); }); testMathyFunction(mathy4, /*MARR*/[new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q'), new String('q'), (4277) *= (yield \"\\uFB5B\"), (4277) *= (yield \"\\uFB5B\"), new String('q'), (4277) *= (yield \"\\uFB5B\"), (4277) *= (yield \"\\uFB5B\"), new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q'), new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q'), (4277) *= (yield \"\\uFB5B\"), (4277) *= (yield \"\\uFB5B\"), new String('q'), new String('q'), new String('q'), (4277) *= (yield \"\\uFB5B\"), (4277) *= (yield \"\\uFB5B\"), (4277) *= (yield \"\\uFB5B\"), (4277) *= (yield \"\\uFB5B\"), new String('q'), new String('q'), new String('q'), new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q'), new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q'), new String('q'), new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (4277) *= (yield \"\\uFB5B\"), new String('q')]); ");
/*fuzzSeed-94431925*/count=1006; tryItOut("for (var v of a2) { try { /*RXUB*/var r = r0; var s = \"\"; print(s.search(r)); print(r.lastIndex);  } catch(e0) { } try { b1 = new ArrayBuffer(64); } catch(e1) { } print(s2); }");
/*fuzzSeed-94431925*/count=1007; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(a0, o1.g2);");
/*fuzzSeed-94431925*/count=1008; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2((Math.imul(Math.pow(y, Math.fround(Math.min((Math.max(x, y) >>> 0), (-0x080000001 >>> 0)))), (Math.asinh(Math.max((Math.hypot((x >>> 0), ( + Math.atan2((( + ( + x)) | 0), ( + -(2**53+2))))) >>> 0), y)) >>> 0)) | 0), (((Math.fround(( + mathy1(x, ((( ~ ((( + y) == Math.fround(y)) | 0)) | 0) >>> 0)))) ^ Math.fround(Math.trunc(Math.fround(x)))) ? mathy2(mathy2(x, x), mathy2(((Math.atan2(( + x), x) >>> 0) ? ( - (x >>> 0)) : Math.fround(( + y))), ( + Math.cosh(0)))) : ((Math.hypot((Math.fround((y | Math.fround(y))) | 0), ( - -0)) , ( + Math.exp(( + Math.fround(( + Math.fround(y))))))) | 0)) | 0)); }); testMathyFunction(mathy3, /*MARR*/[(-1/0), false, false, (-1/0), (-1/0), (-1/0), (-1/0), false, false, (-1/0), false, (-1/0), (-1/0), (-1/0), (-1/0), false, (-1/0), (-1/0), false, (-1/0), (-1/0), false, false, (-1/0), (-1/0), false, (-1/0), (-1/0), (-1/0), (-1/0), false, false, false, false, (-1/0), (-1/0), (-1/0), false, (-1/0), false, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), false, false, false, (-1/0), (-1/0), false, false, false, false, false, false, false, false, false, (-1/0), false, (-1/0), false, (-1/0), false, false, (-1/0), false, (-1/0), false, false, (-1/0), false, false, false, false, (-1/0), false, (-1/0), false, (-1/0), false, (-1/0)]); ");
/*fuzzSeed-94431925*/count=1009; tryItOut("/*bLoop*/for (var ewygke = 0; ewygke < 78; ++ewygke) { if (ewygke % 6 == 5) { throw  \"\" ; } else { i1.next(); }  } ");
/*fuzzSeed-94431925*/count=1010; tryItOut("/*vLoop*/for (var mcrncp = 0; mcrncp < 113; ++mcrncp, this, undefined) { let b = mcrncp; this.v1 = g0.eval(\"function this.f0(g0.i1)  { yield  \\\"\\\"  } \"); } print(uneval(g2.h1));");
/*fuzzSeed-94431925*/count=1011; tryItOut("var a, cqtkdn, freujm, d = \"\\u628A\", gfnhyl, x;/*RXUB*/var r = new RegExp(\"(\\\\W((?!\\\\2){4,}.|\\\\1{4,}))|(?:\\\\1)|$*{4,5}\", \"gyim\"); var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1012; tryItOut("mathy0 = (function(x, y) { return ((( + (Math.hypot(y, x) > ( + ( ~ (((-0x07fffffff && (Math.fround(( + y)) / Math.fround(y))) >>> 0) | 0))))) >>> (Math.fround(Math.min(Math.fround(x), Math.fround(x))) / ( - Math.imul((((Math.min(( + y), y) >>> 0) && (2**53+2 >>> 0)) | 0), Math.fround((( ! (x >>> 0)) ? ( + y) : -1/0)))))) >= ( + (( + (( ! y) >>> (( + Math.max(x, ( + -Number.MAX_VALUE))) ? y : y))) >>> ( + (((Math.expm1(0x0ffffffff) | 0) <= (( + Math.log1p(y)) | 0)) | 0))))); }); ");
/*fuzzSeed-94431925*/count=1013; tryItOut("\"use strict\"; b0 = new ArrayBuffer(3);");
/*fuzzSeed-94431925*/count=1014; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min(Math.sign(( + (( + x) % ( + ( + (( + y) === y)))))), ( ~ Math.min(Math.pow(y, Math.sinh(Math.fround(Math.min(Math.fround(0.000000000000001), Math.fround(Math.atan2(y, y)))))), ((y || (Math.acos(y) | 0)) | 0)))); }); testMathyFunction(mathy0, [-0x100000001, 0x080000001, 0x100000000, 0.000000000000001, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, -(2**53+2), -(2**53), 0x07fffffff, 1/0, -0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 1, 42, 0, Math.PI, 2**53-2, 0x0ffffffff, -0x100000000, -0x07fffffff, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1015; tryItOut("\"use strict\"; e2.has(p1);");
/*fuzzSeed-94431925*/count=1016; tryItOut("\"use strict\"; e2.add(g1.o0);");
/*fuzzSeed-94431925*/count=1017; tryItOut("var zsqdnf = new ArrayBuffer(0); var zsqdnf_0 = new Int8Array(zsqdnf); print(zsqdnf_0[0]); zsqdnf_0[0] = 10; var zsqdnf_1 = new Float64Array(zsqdnf); print(zsqdnf_1[0]); var zsqdnf_2 = new Int16Array(zsqdnf); var zsqdnf_3 = new Int16Array(zsqdnf); print(zsqdnf_3[0]); zsqdnf_3[0] = 7; var zsqdnf_4 = new Uint32Array(zsqdnf); zsqdnf_4[0] = 1e-81; var zsqdnf_5 = new Uint16Array(zsqdnf); zsqdnf_5[0] = -9; var zsqdnf_6 = new Int32Array(zsqdnf); var zsqdnf_7 = new Float64Array(zsqdnf); print(zsqdnf_7[0]); zsqdnf_7[0] = 15; var zsqdnf_8 = new Uint16Array(zsqdnf); print(zsqdnf_8[0]); var zsqdnf_9 = new Int32Array(zsqdnf); zsqdnf_9[0] = -7; print(zsqdnf_9[3]);o2 + '';print(zsqdnf_0[0]);h0.has = g1.f2;a2.push(g2.t1, a2, a2);(void schedulegc(g0));/*MXX1*/o1 = this.g2.Map.prototype.values;print(zsqdnf_6[3]);throw yield;f0 + '';print(zsqdnf_2[5]);");
/*fuzzSeed-94431925*/count=1018; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min(mathy0(Math.pow(( + (( + x) - ( + y))), (y | y)), (y == (x > y))), ((mathy0((( ~ ( + y)) >>> 0), ( ~ (( ! (x | 0)) | 0))) >>> 0) >>> 0)); }); testMathyFunction(mathy1, [-(2**53), 2**53-2, 0, -1/0, 0.000000000000001, -0x080000000, 0x100000001, -0x080000001, Math.PI, -(2**53+2), 0x07fffffff, 1, Number.MIN_VALUE, -0x100000001, -0x100000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -0, 0/0, 2**53, -(2**53-2), 1.7976931348623157e308, 0x100000000, 0x0ffffffff, 42]); ");
/*fuzzSeed-94431925*/count=1019; tryItOut("a2 = /*FARR*/[ \"\" , (4277), new RegExp(\"(?!\\\\1)|\\\\3(?!${32767,}|\\\\3)+?.(?:$)|\\ua4bc\", \"gm\"), eval = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: (function  w (x)x).bind(26), fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(timeout(1800)),  \"\" ), x, .../*UUV2*/(x.of = x.toString), x, new /*MARR*/[ '' , true, true,  '' ,  '' , true,  '' ,  '' ,  '' ,  '' ,  '' , true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,  '' ,  '' ,  '' , true,  '' ,  '' ].some(x),  /x/g (this, ({a2:z2})).unwatch(\"lastIndexOf\"), ...x, , /*MARR*/[new Boolean(true), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), new Boolean(true), true, true, true, new Boolean(true), (-0), new Boolean(true), (-0), true, true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), (-0), new Boolean(true), new Boolean(true), (-0), new Boolean(true), new Boolean(true), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new Boolean(true), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), true, true, (-0), new Boolean(true), (-0), new Boolean(true), new Boolean(true), true, true, new Boolean(true), new Boolean(true), (-0), new Boolean(true), new Boolean(true), (-0), (-0), new Boolean(true), true, new Boolean(true), new Boolean(true), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new Boolean(true), new Boolean(true), (-0), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, (-0), true, new Boolean(true), (-0), new Boolean(true), new Boolean(true), (-0), true, true, new Boolean(true), true, (-0), new Boolean(true), (-0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true)], .../*FARR*/[...[this.__defineGetter__(\"NaN\", mathy5) for each (a in x) for (w of (Math.exp(28)))], , .../*PTHR*/(function() { for (var i of /*FARR*/[([]) = (x % x), \"\\uAA8A\", ((neuter).call((({configurable: true, enumerable: true})), (Math.hypot([,,], -17)).unwatch(\"caller\")))]) { yield i; } })(), (\"\\u1243\" < 7.__defineGetter__(\"NaN\", String.prototype.padEnd) ? new -12( '' ) : (Math.atan2(/((?=.|\\b+?).{2,}|^..{1,}\\b|(?:(?![^\\x8F-\\u00c0-\uf054\u009a])).*)/gim, 16)) , x)], this];function x(x) { \"use strict\"; return function ([y]) { } } /*oLoop*/for (kebpfy = 0; (a = new RegExp(\"(?=^*)\", \"gi\")) && kebpfy < 10; ++kebpfy) { this.v2 = b2.byteLength; } ");
/*fuzzSeed-94431925*/count=1020; tryItOut("h1.has = (function mcc_() { var hrjumi = 0; return function() { ++hrjumi; if (hrjumi > 2) { dumpln('hit!'); try { Object.defineProperty(this, \"v2\", { configurable: true, enumerable: (x % 5 != 4),  get: function() { a0.unshift(g1.f0, o1.v1, v2, e2); return Infinity; } }); } catch(e0) { } try { v0 = evaluate(\"/* no regression tests found */\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: (x % 57 != 25), noScriptRval: \n/*MARR*/[new String(''), (-1/0), \"\\uBE78\"].filter(this), sourceIsLazy: false, catchTermination: true })); } catch(e1) { } print(f0); } else { dumpln('miss!'); /*RXUB*/var r = r2; var s = s2; print(r.test(s));  } };})();");
/*fuzzSeed-94431925*/count=1021; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1022; tryItOut("/*infloop*/M:while(\"\\u008E\"){v2 = -0; }");
/*fuzzSeed-94431925*/count=1023; tryItOut("a2.sort(f0, b1, x, v2, p0);");
/*fuzzSeed-94431925*/count=1024; tryItOut("(x);");
/*fuzzSeed-94431925*/count=1025; tryItOut("\"use strict\"; a2 + '';");
/*fuzzSeed-94431925*/count=1026; tryItOut("v0 = (v1 instanceof i0);");
/*fuzzSeed-94431925*/count=1027; tryItOut("return (x === w);with({}) { try { throw NaN; } finally { with({}) return function ([y]) { }; }  } ");
/*fuzzSeed-94431925*/count=1028; tryItOut("mathy2 = (function(x, y) { return (( + Math.cbrt(((y / ( - (( + y) + x))) | 0))) | 0); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), (new Boolean(false)), undefined, (new Number(-0)), 0.1, 1, ({valueOf:function(){return 0;}}), /0/, 0, objectEmulatingUndefined(), '/0/', (new Boolean(true)), null, [0], NaN, true, (new String('')), ({valueOf:function(){return '0';}}), (function(){return 0;}), (new Number(0)), '0', -0, '', [], '\\0', false]); ");
/*fuzzSeed-94431925*/count=1029; tryItOut("\"use strict\"; d = linkedList(d, 840);");
/*fuzzSeed-94431925*/count=1030; tryItOut("mathy4 = (function(x, y) { return ( ! (Math.pow(((Math.fround((x <= Math.fround((((y >>> 0) - (y | 0)) >>> 0)))) != Math.sin(( ~ ((( + Math.cbrt((y | 0))) === y) >>> 0)))) | 0), ( - ((x % mathy1((Math.pow(Math.fround(y), 0x07fffffff) >>> 0), y)) >>> 0))) | 0)); }); testMathyFunction(mathy4, [false, 0, -0, undefined, ({valueOf:function(){return '0';}}), 1, (new String('')), /0/, (new Number(-0)), NaN, ({valueOf:function(){return 0;}}), 0.1, '\\0', '0', '/0/', [0], null, objectEmulatingUndefined(), (function(){return 0;}), ({toString:function(){return '0';}}), [], (new Number(0)), true, (new Boolean(false)), '', (new Boolean(true))]); ");
/*fuzzSeed-94431925*/count=1031; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-Number.MIN_VALUE, 0x0ffffffff, 2**53, 0.000000000000001, 2**53-2, -1/0, -0x080000001, 0x080000001, Number.MIN_VALUE, 42, 0x100000000, -(2**53+2), -(2**53), 0x100000001, -0x0ffffffff, -0x100000001, -0x080000000, -0, 1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 0, 0x080000000, 1.7976931348623157e308, -0x07fffffff, 2**53+2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1032; tryItOut("\"use strict\"; Array.prototype.shift.apply(a1, [g0.a2, t2, t0]);");
/*fuzzSeed-94431925*/count=1033; tryItOut("x = x, x;s1 = a1.join(g1.o1.s0);");
/*fuzzSeed-94431925*/count=1034; tryItOut("\"use strict\"; if(false) print([z1,,]); else  if (x = -13) (\"\\uB9CE\"); else {x = p1;a2.forEach((function(j) { if (j) { try { a2 + o0; } catch(e0) { } s2 += s0; } else { try { i1.send(a1); } catch(e0) { } try { e0.add(e2); } catch(e1) { } g1.a1.push(v2, p1, this.b2, v2, g2, 4, p0, s1, this.m0); } })); }");
/*fuzzSeed-94431925*/count=1035; tryItOut("h0 = {};");
/*fuzzSeed-94431925*/count=1036; tryItOut("\"use strict\"; o2.v0 = true;");
/*fuzzSeed-94431925*/count=1037; tryItOut("mathy2 = (function(x, y) { return ( ~ ((( + (Math.atanh(-(2**53+2)) + (y | 0))) + mathy1(2**53, ( ! Math.fround(Math.atanh(-(2**53+2)))))) >>> 0)); }); testMathyFunction(mathy2, [0x080000000, -Number.MIN_VALUE, 1/0, 1, -0x07fffffff, 0/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0, -0x100000001, -(2**53), -0x0ffffffff, -0x080000000, -(2**53+2), 2**53-2, 2**53+2, Number.MIN_VALUE, Math.PI, 0x100000001, 0x0ffffffff, 0, 0x100000000, -0x100000000, 2**53, -1/0, 0.000000000000001, 0x07fffffff, 42, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1038; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ( + ( + Math.fround(Math.atan(Math.fround((Math.min(Math.min(x, ( + y)), x) | Math.fround(Math.min(( + Math.max(y, Math.expm1(2**53-2))), Math.fround(((((( ! y) >>> 0) | 0) < (x | 0)) | 0))))))))))); }); testMathyFunction(mathy0, [[0], '\\0', /0/, ({toString:function(){return '0';}}), -0, (new String('')), ({valueOf:function(){return '0';}}), null, undefined, true, '', (new Number(0)), NaN, '/0/', (new Number(-0)), ({valueOf:function(){return 0;}}), 1, objectEmulatingUndefined(), 0, (function(){return 0;}), '0', [], false, 0.1, (new Boolean(true)), (new Boolean(false))]); ");
/*fuzzSeed-94431925*/count=1039; tryItOut("\"use strict\"; const arguments, ijhvrz, fedbqt, a;let (x) { print(x); }");
/*fuzzSeed-94431925*/count=1040; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((y) = ( \"\" )().slice(x))+( \"\" )-((i1) ? (i1) : (i0))))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ \"\\u5580\";return (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: Number.isSafeInteger, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; })})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, 0x080000001, -(2**53-2), 0, 0x100000001, -0x080000000, -0, 42, -1/0, -0x0ffffffff, 0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, Number.MAX_VALUE, 2**53, 0/0, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, 1, -Number.MIN_VALUE, 0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), -0x100000001]); ");
/*fuzzSeed-94431925*/count=1041; tryItOut("var nweglv = new SharedArrayBuffer(2); var nweglv_0 = new Float64Array(nweglv); nweglv_0[0] = -6; var nweglv_1 = new Int32Array(nweglv); var nweglv_2 = new Uint32Array(nweglv); nweglv_2[0] = -20; var nweglv_3 = new Uint32Array(nweglv); nweglv_3[0] = 6; var nweglv_4 = new Uint16Array(nweglv); print(nweglv_4[0]); (4277);");
/*fuzzSeed-94431925*/count=1042; tryItOut("/*RXUB*/var r = g1.r2; var s = s2; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=1043; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.888946593147858e+22;\n    return ((-(0xfb5cc19a)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.getFullYear}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x100000000, -0x07fffffff, -(2**53), -0x100000000, -(2**53+2), 0x100000001, 1, -0x100000001, -0x080000001, -0, -Number.MAX_VALUE, Number.MIN_VALUE, 0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 42, -1/0, -0x080000000, 0/0, 2**53-2, Math.PI, 0x080000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=1044; tryItOut("this;");
/*fuzzSeed-94431925*/count=1045; tryItOut("\"use strict\"; o1.v1 = g2.eval(\"\\\"use strict\\\"; testMathyFunction(mathy2, [-0x080000000, 0/0, 0x07fffffff, -(2**53), -(2**53-2), -0x100000000, 1, 0, 0x100000000, 0x080000001, 0x100000001, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, 1/0, 2**53-2, -Number.MAX_VALUE, 2**53+2, -0x080000001, Math.PI, -0x100000001, 1.7976931348623157e308, -0, -1/0, 2**53]); \");");
/*fuzzSeed-94431925*/count=1046; tryItOut("/*infloop*/M: for  each(var b in (arguments.callee.caller.caller.prototype)) {m2.get(g0.p0); }function e()\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    return (((((this.__defineGetter__(\"x\", neuter))>>>(((-3.094850098213451e+26) == (36893488147419103000.0)))) == (0xaa38b060))))|0;\n  }\n  return f;print((({x: new \"\\u806B\"()})));");
/*fuzzSeed-94431925*/count=1047; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(Math.max(Math.fround(( ~ (x * Math.pow(Math.atanh(y), 0.000000000000001)))), Math.asinh((y >>> 0))), mathy1((y < (Math.trunc((x >>> 0)) >>> 0)), (((x - ( ~ (-(2**53) | 0))) ** (( + mathy1(1/0, ( + (0x080000001 ? /((?:^\\B|(?!\\B))|\\b(?!\\B)*?)*(?=(?=(?=(?:$))))?[^]/gim : Math.fround(mathy1(Math.fround(x), Math.fround(y))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [1, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 0, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 1/0, Math.PI, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, 0x080000001, -0x100000001, -0x0ffffffff, -(2**53-2), -0x100000000, 0x0ffffffff, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0.000000000000001, -1/0, 0x07fffffff, -0x07fffffff, 0x080000000, 2**53, -0x080000001, Number.MAX_VALUE, -(2**53), 1.7976931348623157e308]); ");
/*fuzzSeed-94431925*/count=1048; tryItOut("/*tLoop*/for (let w of /*MARR*/[true,  /x/ , null,  /x/ , null,  /x/ , true,  /x/ ,  /x/ , null, true, true,  /x/ , true,  /x/ ,  /x/ ,  /x/ , null, null, true,  /x/ ,  /x/ , null, true,  /x/ , null, true,  /x/ , true, true,  /x/ ,  /x/ , true, null,  /x/ , null, true, null, null, null, null, null, null, null, null, null, null, null, null, null,  /x/ ,  /x/ ,  /x/ , null,  /x/ , null, true,  /x/ ,  /x/ , true, null, true, true, true,  /x/ , true, null, null,  /x/ , null, true,  /x/ ,  /x/ ,  /x/ ,  /x/ , true, null, null, null,  /x/ , true,  /x/ , null, true, null, null, true, null,  /x/ , true,  /x/ , true, true, null,  /x/ , true, null, null,  /x/ ]) { v2 = evaluate(\"o1.i1.send(g2);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 != 1), noScriptRval: true, sourceIsLazy: w, catchTermination: (w % 27 == 19) })); }");
/*fuzzSeed-94431925*/count=1049; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=^)*?/gim; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=1050; tryItOut("Object.defineProperty(this, \"m1\", { configurable: /*RXUE*//\\xEA?|\\b/ym.exec(\"\\u00ca\\u00ca\"), enumerable: false,  get: function() {  return new WeakMap; } });");
/*fuzzSeed-94431925*/count=1051; tryItOut("\"use strict\"; m2 + '';/*hhh*/function khllpb(a){print(x);}khllpb();");
/*fuzzSeed-94431925*/count=1052; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan2((Math.pow(( + (Math.sinh((Math.fround(( + Math.fround(( + Math.hypot(y, 0x080000000))))) | 0)) | 0)), ((( ! y) ? Math.min(y, ( + ( ~ ( + Math.fround(Math.log10(Math.fround(y))))))) : Math.hypot(( ! ((Math.fround(Math.ceil(( + x))) == ((x - y) | 0)) | 0)), x)) | 0)) | 0), Math.fround(( + (Math.fround((Math.fround((((y | 0) ? y : Math.sin(y)) | 0)) ? ( - Math.fround(( + ( + y)))) : Math.fround((( + (( ~ (0x080000001 | 0)) | 0)) ? x : ( + Math.abs(Math.fround(y))))))) >>> 0)))); }); ");
/*fuzzSeed-94431925*/count=1053; tryItOut("/*bLoop*/for (let qnuyvh = 0; (x) && qnuyvh < 64; ++qnuyvh) { if (qnuyvh % 54 == 20) { return; } else { yield; }  } ");
/*fuzzSeed-94431925*/count=1054; tryItOut(";");
/*fuzzSeed-94431925*/count=1055; tryItOut("print(f2);function d(x, x =  '' , w, \u3056, [], w, x, d,  , x = \"\\uA6F7\", b = x, x, w, x, x, x = \"\\u6CBA\", eval, /(?:(([\u5fe1-\\cK-#--\u00be\\r-\\x04])[^][\\u9814\\f]{2})){2}|[\u1e58\\uEF43]|.|.|(?:\\t)|$.*?/, y, x, \u3056, b, y, b = {}, b, a, eval, y, x, b, y, window, c, e) { \"use asm\"; yield length -= arguments } i2.next();");
/*fuzzSeed-94431925*/count=1056; tryItOut("for(var a = x in window - /((?=\\3)(?!^)*?)|\\3*?{0,}/m) /*infloop*/do /*ADP-3*/Object.defineProperty(a2, ({valueOf: function() { e0.valueOf = (function(j) { if (j) { try { a0[v0] = e: \"\\uF7A3\"; } catch(e0) { } try { a2[window] = b0; } catch(e1) { } try { o1.i1.next(); } catch(e2) { } this.h1 + t0; } else { try { Object.defineProperty(this, \"v1\", { configurable: true, enumerable: a,  get: function() {  return g2.eval(\"function f1(s0)  { yield  ''  } \"); } }); } catch(e0) { } try { a0.shift(this.m0, b1); } catch(e1) { } try { a1.length = 18; } catch(e2) { } a0.shift(); } });return 6; }}), { configurable: (x % 3 == 1), enumerable: true, writable: (x % 6 != 3), value: g0 }); while(yield undefined);a0 = Array.prototype.map.apply(a1, [(function() { try { /*ADP-3*/Object.defineProperty(a2, ({valueOf: function() { var khlryh = new SharedArrayBuffer(6); var khlryh_0 = new Int16Array(khlryh); khlryh_0[0] = -24; print(khlryh_0[0]);return 8; }}), { configurable: true, enumerable: (/*RXUE*/new RegExp(\"(?=(\\\\cR+|\\\\b).\\u726e{0,0}(?:$)*?)\", \"gi\").exec(\"\\u4AFE\")), writable: Math.atan2(26,  '' ), value: f0 }); } catch(e0) { } try { selectforgc(o0); } catch(e1) { } try { /*RXUB*/var r = r0; var s = \"\"; print(r.exec(s)); print(r.lastIndex);  } catch(e2) { } t0 = new Float64Array(b0, 68, 7); throw o0.p0; })]);");
/*fuzzSeed-94431925*/count=1057; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1058; tryItOut("\"use strict\"; ");
/*fuzzSeed-94431925*/count=1059; tryItOut(";");
/*fuzzSeed-94431925*/count=1060; tryItOut("v0 = undefined;function x(a, this.\u3056)x(x);");
/*fuzzSeed-94431925*/count=1061; tryItOut("var r0 = x ^ x; ");
/*fuzzSeed-94431925*/count=1062; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.min(((Math.max(y, Math.tanh((x | 0))) / Math.pow(( - y), Math.fround(Math.abs((( + (( + mathy0(-0x0ffffffff, x)) << ( + 1))) - Math.fround(Math.imul(Math.fround(x), Math.fround(( + Math.pow((y | 0), ( + -0x080000001))))))))))) | 0), Math.fround(Math.sin(Math.atan2(( + Math.hypot(y, ( + (((x | 0) ? Math.log10(x) : (y >>> 0)) | 0)))), Math.fround(Math.min(-Number.MIN_SAFE_INTEGER, ((y >> y) >>> 0))))))); }); testMathyFunction(mathy3, [1, 0x080000000, -0x100000000, -Number.MIN_VALUE, -0, -Number.MAX_VALUE, 2**53-2, Number.MAX_VALUE, 2**53+2, 1/0, -(2**53+2), -0x080000001, Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, 42, -0x07fffffff, 0x07fffffff, -(2**53), 0, 2**53, 0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, Math.PI]); ");
/*fuzzSeed-94431925*/count=1063; tryItOut("/*ADP-2*/Object.defineProperty(this.o0.a0, 12, { configurable: (4277), enumerable: false, get: (function(j) { if (j) { try { t0 = t2[5]; } catch(e0) { } try { t1 + v1; } catch(e1) { } f0.toSource = (function(j) { if (j) { try { for (var p in g1.f0) { m2.has(g1); } } catch(e0) { } try { o1.e0.delete(null); } catch(e1) { } g1.offThreadCompileScript(\"f0.toSource = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var NaN = stdlib.NaN;\\n  var abs = stdlib.Math.abs;\\n  var ff = foreign.ff;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    i0 = (((((/*FFI*/ff((((7.737125245533627e+25) + (-18014398509481984.0))), ((NaN)), ((3.094850098213451e+26)), ((-1.0)), ((-2305843009213694000.0)), ((-33.0)), ((4.722366482869645e+21)), ((-576460752303423500.0)), ((-8191.0)))|0)-((0xfa5acd9e) ? (0x5cd58811) : (0x9c8b0e78))) << ((/*FARR*/[...[], ...[], \\\"\\\\uF60F\\\", ].filter(true.toGMTString(\\\"\\\\u795A\\\")))+(i0)))) ? ( \\\"\\\"  =  \\\"\\\" ) : ((i0) ? (i1) : ((((0xb907d96b)) & ((0xffffffff))) == (((-0x8000000)+(-0x8000000))|0))));\\n    i0 = (!(((-9223372036854776000.0) + (-36028797018963970.0)) != (+(abs((((i1)-(i1)+(i1)) & (((-0x8000000) ? (0xd14928c5) : (0xfcd416c8))+((0xdeac5a4) != (0x30b537f8)))))|0))));\\n    {\\n      (Float32ArrayView[1]) = (((x -= x\\n)));\\n    }\\n    switch ((~(((0x4a8c1a8d) > (0x5d1ac811))+((0x32f3d7cb) != (-0x8000000))))) {\\n    }\\n    return (((0x2280f19e) % (0xcfbb6e34)))|0;\\n  }\\n  return f; })(this, {ff: () => null}, new SharedArrayBuffer(4096));\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: true })); } else { Array.prototype.pop.apply(a1, [t1]); } }); } else { g1.v2 = Object.prototype.isPrototypeOf.call(e1, p0); } }), set: (function() { /*MXX2*/g0.String.prototype.startsWith = f2; return m2; }) });\n(true = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: Error, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: undefined, keys: function() { return []; }, }; })(-18), NaN = ({a2:z2})));\n");
/*fuzzSeed-94431925*/count=1064; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2(?![j-\\\\u2938\\\\s\\\\uB1B6])*?\", \"yim\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1065; tryItOut("v0 = r2.test;function y()Math.imul(29, -10)\nv0 = g0.runOffThreadScript();");
/*fuzzSeed-94431925*/count=1066; tryItOut("\"use strict\"; throw w;let(z) ((function(){this.message;})());");
/*fuzzSeed-94431925*/count=1067; tryItOut("let(b) { return;}");
/*fuzzSeed-94431925*/count=1068; tryItOut("e1.add(b1);");
/*fuzzSeed-94431925*/count=1069; tryItOut("m0.set(i1, p1);");
/*fuzzSeed-94431925*/count=1070; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2((Math.log(((Math.asinh((Math.atan(Math.trunc(x)) >>> 0)) >>> 0) | 0)) | 0), Math.expm1(((( - (Math.asin(((x << 0x080000001) | 0)) >>> 0)) | 0) | 0)))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -0x100000000, 0x07fffffff, -0x100000001, -(2**53-2), 2**53, 0.000000000000001, 42, 0x080000001, 1, -0x07fffffff, -Number.MAX_VALUE, 0x100000001, 0/0, -(2**53), -0, -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, 0x100000000, Number.MIN_VALUE, 2**53-2, -Number.MIN_VALUE, 2**53+2, 0, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-94431925*/count=1071; tryItOut("m2.set(m1, this.e1);");
/*fuzzSeed-94431925*/count=1072; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.atanh((Math.round(Math.atan2((x >>> 0), ((Number.MIN_SAFE_INTEGER >>> 0) ? Math.pow(x, ((x | 0) , (x | 0))) : (x >>> 0)))) >>> 0))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 2**53, Math.PI, 0x080000001, -(2**53+2), -0x080000001, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), 2**53-2, -0x100000000, 1, 0x080000000, -0x100000001, 0, -Number.MIN_VALUE, 0x07fffffff, -0, -1/0, -0x07fffffff, 1.7976931348623157e308, 0x100000001, 42, 0.000000000000001, -0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=1073; tryItOut("mathy1 = (function(x, y) { return (( + (Math.fround(( ! (Math.fround(Math.abs(Math.min(Math.fround((Math.fround(y) >> Math.fround(x))), (x ** x)))) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -(2**53+2), -Number.MAX_VALUE, Math.PI, -0x100000000, 0/0, 0, -0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, 2**53, -(2**53-2), -Number.MIN_VALUE, 0x100000000, 42, 0x080000000, -(2**53), 1/0, 0x080000001, -0x080000000, 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, 0.000000000000001, -1/0, 2**53+2]); ");
/*fuzzSeed-94431925*/count=1074; tryItOut("");
/*fuzzSeed-94431925*/count=1075; tryItOut("\"use strict\"; h1.has = (function mcc_() { var wamwgp = 0; return function() { ++wamwgp; f0(wamwgp > 6);};})();");
/*fuzzSeed-94431925*/count=1076; tryItOut("\"use asm\"; var w = (Number.isNaN)();let y, c, \u3056 = \"\\uE32B\", ljcvej, fifitw, woeetc, x, yuitcg, ygubfx, x;return [,,];");
/*fuzzSeed-94431925*/count=1077; tryItOut("v1 = t0.byteOffset;function x() { i0 = g2.m2.iterator; } this.m0 = new Map(g0.p2);");
/*fuzzSeed-94431925*/count=1078; tryItOut("/*bLoop*/for (nqbvxv = 0; nqbvxv < 126; allocationMarker(), ++nqbvxv) { if (nqbvxv % 2 == 1) { throw \"\\u92AC\"; } else { for (var p in a0) { v1 = o2.g2.r2.multiline; } }  } ");
/*fuzzSeed-94431925*/count=1079; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xffffffff);\n    return ((0xd1350*(((+(((/*FFI*/ff()|0)+((+/*FFI*/ff(((4294967297.0)), ((-590295810358705700000.0)), ((1.125)), ((-511.0)))) <= (+(-1.0/0.0))))>>>(((i1) ? ((0x3e04ab57)) : (0xdc73bf71)))))) >= (((0xffd388a1)) >> ((i1)+(0x926cbc3b))))))|0;\n    {\n      {\n        switch ((((Int8ArrayView[2]))|0)) {\n          case 1:\n            {\n              i1 = (0x80ae8b24);\n            }\n            break;\n          case -1:\n            return ((((~((!(-0x8000000)))))-(i1)))|0;\n          case -2:\n            d0 = (35184372088832.0);\n            break;\n          case -3:\n            (Int16ArrayView[2]) = ((0x2dae822a));\n          default:\n            return (((((((((0xffffffff) == (0x1624f4db))) ^ ((!(0x13848af0)))) / (abs((((0x5bc0c34f)) >> ((0xf396cad4))))|0)) ^ ((i1)+((8796093022209.0) >= (+(0.0/0.0))))) != ((-((((0x84b6cdad)+(0xe8a5f21a))>>>((0x88557670) % (0x61574d08))))) ^ ((-0x8000000)-(-0x180b4af))))*-0x72cbf))|0;\n        }\n      }\n    }\n    (Float32ArrayView[4096]) = ((-18446744073709552000.0));\n    return ((((((i1))>>>(((-0.0009765625)))))))|0;\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=1080; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(( + Math.atan2(( + (Math.min(((Math.cosh((( + (x | 0)) | 0)) , 2**53+2) ? x : Math.imul(-0x080000000, x)), 0x080000001) >>> 0)), (( ! (( - (x >>> 0)) | 0)) | 0)))), (Math.exp(Math.fround(Math.min(( ! mathy2(mathy2(0.000000000000001, (y | 0)), x)), ( + Math.max(( + Math.fround(mathy3(x, x))), (x | 0)))))) % Math.fround(Math.sin(y)))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, 0, -(2**53), Number.MIN_VALUE, 2**53, 0x07fffffff, -Number.MIN_VALUE, -(2**53+2), -0x100000000, 2**53-2, 0x100000000, -0x07fffffff, 0x0ffffffff, 0x100000001, -(2**53-2), 1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 1, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000000, -0, 0.000000000000001, -1/0, Math.PI, 2**53+2, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0]); ");
/*fuzzSeed-94431925*/count=1081; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; }");
/*fuzzSeed-94431925*/count=1082; tryItOut("(void schedulegc(g1.g2));");
/*fuzzSeed-94431925*/count=1083; tryItOut("\"use strict\"; t1.set(t2, 8);");
/*fuzzSeed-94431925*/count=1084; tryItOut("/*RXUB*/var r = /\\w\u009a+/gim; var s = \"a\"; print(r.exec(s)); \ncontinue ;\n");
/*fuzzSeed-94431925*/count=1085; tryItOut("mathy3 = (function(x, y) { return Math.pow(Math.fround(( - Math.fround(Math.imul(x, ((x * Math.fround(y)) | 0))))), ((x << ( + Math.min(( + (mathy1((Math.atan2(Math.fround(Number.MIN_VALUE), 42) >>> 0), (0/0 >>> 0)) >>> 0)), ( + Math.atan2(x, (Math.sqrt(( + -Number.MIN_VALUE)) >>> 0)))))) + Math.fround(Math.hypot(Math.fround((Math.fround((Math.cosh(( + ((Math.min((y >>> 0), (x >>> 0)) | 0) <= x))) | 0)) <= Math.fround(x))), ( + Math.ceil(y)))))); }); ");
/*fuzzSeed-94431925*/count=1086; tryItOut("e2.delete(o0.g2);");
/*fuzzSeed-94431925*/count=1087; tryItOut("\"use strict\"; /*MXX3*/g2.RegExp.prototype.flags = this.g2.RegExp.prototype.flags;");
/*fuzzSeed-94431925*/count=1088; tryItOut("v2 = -0;");
/*fuzzSeed-94431925*/count=1089; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=1090; tryItOut("\"use strict\"; o1.m1 = new Map(o0.g0);");
/*fuzzSeed-94431925*/count=1091; tryItOut("mathy3 = (function(x, y) { return ( - ( + ( ~ Math.log1p(Math.log10(mathy2(Math.fround(x), Math.PI)))))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), objectEmulatingUndefined(), (function(){return 0;}), '', -0, (new Number(-0)), 0.1, (new Number(0)), (new String('')), 1, undefined, /0/, true, false, '/0/', ({valueOf:function(){return '0';}}), NaN, (new Boolean(false)), (new Boolean(true)), null, '0', [], '\\0', ({valueOf:function(){return 0;}}), [0], 0]); ");
/*fuzzSeed-94431925*/count=1092; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1093; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.pow((( + ( ~ Math.log(Math.clz32(Math.fround((-0x100000000 * Math.fround(y))))))) != ( + Math.fround((Math.fround((( + ( - y)) != ( + (( ~ (Math.fround(( - Math.fround(y))) | 0)) | 0)))) >>> Math.fround((x <= Math.log1p(Math.log(x)))))))), (( + ((( + Math.log2(Math.hypot(2**53-2, y))) | 0) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy1, [(function(){return 0;}), NaN, ({valueOf:function(){return '0';}}), null, 0.1, 0, [], undefined, -0, ({toString:function(){return '0';}}), /0/, 1, '\\0', (new Boolean(false)), (new Boolean(true)), '/0/', false, '', true, (new String('')), (new Number(0)), (new Number(-0)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), '0', [0]]); ");
/*fuzzSeed-94431925*/count=1094; tryItOut("\"use strict\"; neuter(b0, \"change-data\");");
/*fuzzSeed-94431925*/count=1095; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2((( - ( ! (x !== Math.fround(y)))) | 0), ((((((Math.round((Math.imul(x, 2**53) >>> 0)) >>> 0) & ((Math.hypot(( + mathy1(x, ( + (( + x) % ( + x))))), ( + Math.acos(42))) | 0) | 0)) | 0) | 0) >> ( + mathy1((Math.hypot(( ! Number.MAX_SAFE_INTEGER), (Math.imul(Math.imul(y, x), 2**53+2) >>> 0)) | 0), Math.acosh(( ! y))))) | 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[(void 0), (void 0), (void 0), (void 0)]); ");
/*fuzzSeed-94431925*/count=1096; tryItOut("print(x);");
/*fuzzSeed-94431925*/count=1097; tryItOut("a2.__proto__ = t2;");
/*fuzzSeed-94431925*/count=1098; tryItOut("\"use strict\"; v0 = evaluate(\"function f0(t1) \\\"use asm\\\";   function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    return +((+(0.0/0.0)));\\n    return +(((new true).eval(\\\"(let (x) [1,,])\\\")));\\n    i0 = ((0xb8d7908b));\\n    return +((3.8685626227668134e+25));\\n  }\\n  return f;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 64 != 25), noScriptRval: false, sourceIsLazy: true, catchTermination: (eval(\"\\\"use asm\\\"; yield;\", x)) }));");
/*fuzzSeed-94431925*/count=1099; tryItOut("/*RXUB*/var r = /$|\u00bd+?/i; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1100; tryItOut("print(x =  \"\" );");
/*fuzzSeed-94431925*/count=1101; tryItOut("var jqmtxb = new ArrayBuffer(24); var jqmtxb_0 = new Int32Array(jqmtxb); jqmtxb_0[0] = 23; var jqmtxb_1 = new Uint8Array(jqmtxb); jqmtxb_1[0] = 10; var jqmtxb_2 = new Uint16Array(jqmtxb); jqmtxb_2[0] = 8; this.a1.push(this.s1);");
/*fuzzSeed-94431925*/count=1102; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( - (( + ((Math.acosh((Math.atan((( + ((y * x) | 0)) | 0)) | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [2**53, -(2**53+2), -Number.MIN_VALUE, -0x07fffffff, 0x080000000, 0x07fffffff, Math.PI, -0x080000001, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000000, -0x100000001, 0x0ffffffff, 0, Number.MIN_VALUE, -1/0, -0, Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, -0x0ffffffff, -0x100000000, 42, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1103; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = (d1);\n    }\n    d1 = (d0);\n    d0 = (NaN);\n    (Float64ArrayView[((((-((0xb100bc4f)))>>>((0xbb69ceea))))) >> 3]) = ((d1));\n    d1 = (d0);\n    d1 = (d0);\n    {\n      return +((d0));\n    }\n    d1 = ((d1) + (-1.5474250491067253e+26));\n    return +((+(~((0xfa356d47)+(0x76e3cdb9)+(0xbf918662)))));\n    return +((d0));\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0.000000000000001, -0, 42, 0x100000000, Number.MAX_VALUE, 0, 0x100000001, 2**53, -(2**53), -0x080000001, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 2**53+2, 0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, -0x0ffffffff, Math.PI, -0x07fffffff, 0/0, 2**53-2, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), 0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1104; tryItOut("\"use strict\"; Array.prototype.sort.apply(a0, [(function() { for (var j=0;j<26;++j) { this.f1(j%4==1); } }), this.m0]);");
/*fuzzSeed-94431925*/count=1105; tryItOut("\"use strict\"; (3);");
/*fuzzSeed-94431925*/count=1106; tryItOut("\"use strict\"; o0.m1.has(f2);");
/*fuzzSeed-94431925*/count=1107; tryItOut("\"use strict\"; print(t2);");
/*fuzzSeed-94431925*/count=1108; tryItOut("\"use strict\"; for(z = \nx >> yield ((objectEmulatingUndefined)()) in Math.hypot(++RegExp.name,  /* Comment */eval(\"print(uneval(g1));\"))) var euxfnl = new ArrayBuffer(0); var euxfnl_0 = new Float32Array(euxfnl); var euxfnl_1 = new Uint32Array(euxfnl); euxfnl_1[0] = 7; s1 = s1.charAt(4);");
/*fuzzSeed-94431925*/count=1109; tryItOut("e1.has(this.i0);");
/*fuzzSeed-94431925*/count=1110; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy0(( - ( - (x <= ((x ? ( + x) : (x | 0)) | 0)))), Math.round(( + ( + Math.fround((Math.min((x | 0), (y | 0)) | 0)))))); }); ");
/*fuzzSeed-94431925*/count=1111; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.exp(( - ( + ( ~ ( + ((y & ((x ? (x >>> 0) : (y >>> 0)) | y)) & Math.expm1((Math.sinh((x >>> 0)) >>> 0)))))))); }); ");
/*fuzzSeed-94431925*/count=1112; tryItOut("\"use strict\"; this.e2.has(allocationMarker());");
/*fuzzSeed-94431925*/count=1113; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log1p(( - ( + Math.asinh(Math.fround(((x >>> 0) ? Math.fround(x) : Math.fround(Math.cbrt(-0x080000000)))))))); }); ");
/*fuzzSeed-94431925*/count=1114; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(mathy0(Math.fround(Math.fround((Math.fround(x) / Math.fround(( ! -0x100000001))))), Math.cos(x))) , Math.fround(Math.atan2(Math.max((Math.log10(Math.fround(( ~ Math.fround(y)))) | 0), y), Math.max(-(2**53), Math.fround((Math.atan2((y | 0), mathy0(( + Math.atan2((x >>> 0), (-0x100000000 >>> 0))), ( + Math.pow((y | 0), Math.fround(1))))) | 0)))))); }); testMathyFunction(mathy2, [-(2**53), -0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), 0x080000000, 1/0, 2**53-2, -0x080000001, 1.7976931348623157e308, -0x100000001, 42, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, 0/0, 2**53, 2**53+2, -0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, -(2**53+2), -1/0, -Number.MIN_VALUE, -0x100000000, 0x080000001, Number.MAX_VALUE, 1, Math.PI]); ");
/*fuzzSeed-94431925*/count=1115; tryItOut("v1 = (v2 instanceof o2.b2);h0.iterate = f1;");
/*fuzzSeed-94431925*/count=1116; tryItOut("v1 = 0;");
/*fuzzSeed-94431925*/count=1117; tryItOut("var new RegExp(\"\\\\B(?=[^u\\\\v])?|(?:\\\\b^|\\\\B+){3,}\", \"\")[\"toUTCString\"] = (arguments[\"caller\"]) = x, hwszdn, eval = 25, praslx, x, iikvwt, x, \"-16\";t0[\"\\uB8A1\"];\nfor (var v of t1) { try { a1 = new Array; } catch(e0) { } i2.send(t1); }\n");
/*fuzzSeed-94431925*/count=1118; tryItOut("let b = Date.prototype.toDateString, klqzdi, x = ([] = x)\u000c, x, x = \"\\u533C\", x, uxqrie, tbekaj;print(x)\nprint(x);");
/*fuzzSeed-94431925*/count=1119; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?!^)){2,}/gy; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=1120; tryItOut("this.a1 = a1.map((function(j) { if (j) { x = s1; } else { try { /*MXX1*/o2 = g0.Int16Array.name; } catch(e0) { } try { v1 = g1.runOffThreadScript(); } catch(e1) { } a1 = new Array; } }));");
/*fuzzSeed-94431925*/count=1121; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i0)-(i1)+(!(0xf5ffb3f8))))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [NaN, (new Boolean(true)), -0, '\\0', (new Number(0)), 0, '/0/', /0/, undefined, (new Boolean(false)), '0', true, ({valueOf:function(){return '0';}}), null, (new String('')), ({valueOf:function(){return 0;}}), (function(){return 0;}), 1, objectEmulatingUndefined(), 0.1, [], '', [0], ({toString:function(){return '0';}}), false, (new Number(-0))]); ");
/*fuzzSeed-94431925*/count=1122; tryItOut("v1 = t2.length;");
/*fuzzSeed-94431925*/count=1123; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[-Infinity, objectEmulatingUndefined(), [], objectEmulatingUndefined(), [], [], [], objectEmulatingUndefined(), -Infinity, -Infinity, objectEmulatingUndefined(), -Infinity]) {  /x/ ; }");
/*fuzzSeed-94431925*/count=1124; tryItOut("/*RXUB*/var r = new RegExp(\"(?![^])*(?:(?!(?:\\u9ff1)))\", \"gi\"); var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1125; tryItOut("mathy3 = (function(x, y) { return Math.fround(mathy1(Math.fround(((Math.acos(Math.fround((Math.fround(y) * y))) >>> 0) > (((( + Math.hypot(( + x), Math.atan2(Math.fround(0x100000000), -0x100000001))) >>> 0) !== -(2**53+2)) >>> 0))), (mathy1(((Math.hypot(0x100000000, (mathy0(Math.fround((Math.log(0x100000001) | 0)), (Math.max((x >>> 0), y) >>> 0)) | 0)) | 0) >> this), ( + Math.atan2(( + y), 0x080000001))) >>> 0))); }); ");
/*fuzzSeed-94431925*/count=1126; tryItOut("/*RXUB*/var r = new RegExp(\"((\\\\s)(?!(?:.))\\\\uC061?+?){4,}\", \"im\"); var s = \"___\\u0009\\u6cfb\\u0085\\n\\u0009\\u6cfb\\u0085_\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-94431925*/count=1127; tryItOut("/*infloop*/for({} = Symbol.split = -14 & undefined >>>= /((?!^(?=[]){2,}))/ ? true :  \"\" ; \u3056 | w; this.__defineSetter__(\"x\", Function.prototype.apply)) \n{Array.prototype.forEach.apply(a0, [(function() { try { Object.prototype.watch.call(t2, \"\\u6F35\", (function(j) { if (j) { ; } else { try { a1.shift(this.b1, b1); } catch(e0) { } try { g1.o2 = Object.create(v1); } catch(e1) { } try { m0.set(o0.h1, b0); } catch(e2) { } v2 = evaluate(\"v0 = Object.prototype.isPrototypeOf.call(i1, g2.h1);\", ({ global: this.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: function(id) { return id }, noScriptRval: window, sourceIsLazy: true, catchTermination: false })); } })); } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } try { /*ODP-2*/Object.defineProperty(b1, \"split\", { configurable:  \"\" , enumerable: (x % 3 != 2), get: (function() { g2.t1[({valueOf: function() { decodeURIreturn 9; }})] = true; throw v1; }), set: WeakSet.prototype.delete }); } catch(e2) { } a1.push(g2.t0, o1, m1, p2, b0); return a0; })]); }");
/*fuzzSeed-94431925*/count=1128; tryItOut("Array.prototype.reverse.apply(a1, [g0.o0.b1]);");
/*fuzzSeed-94431925*/count=1129; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ ( + Math.cos(mathy1((Math.fround(Math.imul(Math.fround(( + Math.round(x))), (x >>> 0))) >>> 0), (Math.abs((((Math.asin(1.7976931348623157e308) | 0) ? x : y) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-94431925*/count=1130; tryItOut("\"use strict\"; Array.prototype.pop.call(g1.a0, g2, v0);");
/*fuzzSeed-94431925*/count=1131; tryItOut("\"use strict\"; runOffThreadScriptyield a;");
/*fuzzSeed-94431925*/count=1132; tryItOut("\"use asm\"; with({e: (4277)}){sjsmda(let (x = \"\\u6FF5\", [] = e, aptiqk, pesubp, \u3056, y, cunhze) ( /x/ .unwatch(\"constructor\")));/*hhh*/function sjsmda(d){print([] = new (eval)());}print(uneval(i2));\u0009 }");
/*fuzzSeed-94431925*/count=1133; tryItOut("var e =  '' ;a1 = g0.a0.map(f0);");
/*fuzzSeed-94431925*/count=1134; tryItOut("mathy5 = (function(x, y) { return Math.clz32((( ~ Math.fround(Math.fround(Math.fround(Math.hypot(x, x))))) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[(-1/0), false, false, new Boolean(false), false, new Boolean(false), (-1/0), (void 0), false, (-1/0), (void 0), (void 0), new Boolean(false), -Infinity, false, (-1/0), new Boolean(false), (-1/0), new Boolean(false), false, false, false, false, -Infinity, (void 0), (-1/0), -Infinity, (-1/0), (void 0), -Infinity, new Boolean(false), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(false), false, false, new Boolean(false), (void 0), false, (-1/0), false, new Boolean(false), new Boolean(false), (void 0), -Infinity, -Infinity, (-1/0), -Infinity, false, false, (-1/0), (-1/0), -Infinity, false, false, -Infinity, -Infinity, -Infinity, false, (void 0), (void 0), (-1/0), false, new Boolean(false), (void 0), (-1/0), -Infinity, (void 0), -Infinity, (void 0), new Boolean(false), -Infinity, (-1/0), (void 0), new Boolean(false), (void 0), new Boolean(false), false, (void 0), -Infinity, new Boolean(false), -Infinity, new Boolean(false), new Boolean(false), (-1/0), -Infinity, (-1/0), -Infinity, new Boolean(false), false, (-1/0), (void 0), false, -Infinity, new Boolean(false), (-1/0), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, false, (-1/0), -Infinity, -Infinity, false, false, false, (void 0), (-1/0), -Infinity, false, (void 0), false, (void 0), (-1/0), -Infinity, new Boolean(false), new Boolean(false), (-1/0), new Boolean(false), (void 0), (-1/0), -Infinity, new Boolean(false), -Infinity, -Infinity, (-1/0), false, new Boolean(false), (void 0), false, (void 0), new Boolean(false), (-1/0), (-1/0), -Infinity, -Infinity, (-1/0), false, (void 0), (void 0), new Boolean(false), false, new Boolean(false), -Infinity, (void 0), (void 0), (void 0), false, (void 0), false, new Boolean(false), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), -Infinity, (void 0), -Infinity, -Infinity, (-1/0), -Infinity, (void 0)]); ");
/*fuzzSeed-94431925*/count=1135; tryItOut("(x);v0 = (i2 instanceof f0);");
/*fuzzSeed-94431925*/count=1136; tryItOut("testMathyFunction(mathy0, [Number.MAX_VALUE, Math.PI, 42, -Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 1.7976931348623157e308, 0, -0x07fffffff, -(2**53), -0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, -0x100000000, -0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, -0x080000001, 1/0, 2**53, 2**53+2, 0x080000000, 0x100000000, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, -(2**53+2), -1/0]); ");
/*fuzzSeed-94431925*/count=1137; tryItOut("mathy2 = (function(x, y) { return (Math.atan2((Math.max((( - Math.fround(x)) >= ( + y)), Math.cbrt(( + ( ~ (((y | Math.round(-(2**53-2))) ? -0 : x) >>> 0))))) >>> 0), ((((Math.sqrt(y) | 0) ? (Math.pow(( + y), (( + Math.atan2(( + (Math.cbrt((y >>> 0)) >>> 0)), ( + (( ! (x | 0)) | 0)))) ^ (Math.sinh((y | 0)) | 0))) | 0) : (Math.fround((Math.imul(( + y), 0x080000000) && Math.fround((( ! (Math.fround(Math.sinh(Math.fround(y))) | 0)) | 0)))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[null,  /x/ , null, new Number(1.5),  /x/ , new Number(1.5), null, undefined, null, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, arguments.callee, new Number(1.5), null, new Number(1.5), arguments.callee, null, new Number(1.5), new Number(1.5), arguments.callee, undefined, undefined, arguments.callee,  /x/ ,  /x/ , new Number(1.5), arguments.callee, arguments.callee, undefined,  /x/ , undefined, undefined,  /x/ , arguments.callee,  /x/ , arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee,  /x/ , new Number(1.5), undefined, undefined, undefined, null, new Number(1.5), new Number(1.5),  /x/ ,  /x/ , arguments.callee, new Number(1.5),  /x/ ,  /x/ , new Number(1.5),  /x/ , null, undefined, null, null, null, null, null, null, null, null, null, undefined, new Number(1.5), arguments.callee, new Number(1.5), new Number(1.5), null, arguments.callee, new Number(1.5), undefined,  /x/ , arguments.callee, null, new Number(1.5), new Number(1.5),  /x/ , null, new Number(1.5), arguments.callee, undefined, new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), undefined, undefined, null, null, undefined, new Number(1.5), null, arguments.callee, arguments.callee, arguments.callee, new Number(1.5), undefined, undefined, null,  /x/ , arguments.callee, null,  /x/ , arguments.callee, null, null, undefined, undefined, arguments.callee, arguments.callee, new Number(1.5), arguments.callee, undefined, null, null, undefined, null, null, new Number(1.5), null, arguments.callee, arguments.callee, null, null, undefined, new Number(1.5), new Number(1.5),  /x/ ,  /x/ , null, new Number(1.5), undefined, undefined,  /x/ , undefined, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), null, arguments.callee]); ");
/*fuzzSeed-94431925*/count=1138; tryItOut("/*bLoop*/for (let jtxayl = 0; jtxayl < 54; ++jtxayl) { if (jtxayl % 17 == 11) { delete this.h2.has; } else { a2.toSource = g0.f1;function y(b, x, x =  /x/ , x =  /x/g , x, x, x, x, window = /(?=$(?=(?!\\B))+)((?!(?=\\cC))){2,}/im, x = null, \u3056, x, x, eval, e, a, a, x, b, w, NaN, d = y, x, NaN, z, x, x = this, window, x, eval = ({a1:1}), z, a, a, d, e, c, get, x, x, e, x, (function ([y]) { })(), c =  \"\" , w, w, x, e, z = e, x, x, x, c, \u3056, x =  \"\" , x, x, d, e, eval, x = this.d, of = 22, \u3056, x, x, \u3056, y, x, y, yield =  \"\" , e, d, d, x = -16, e, x, x, x = /\\D+?/gy, z, true =  \"\" , d, b = window, x, e, b, c, NaN =  /x/ , window, x, y =  /x/g , x, x = \"\\u0A26\", this, x)\"\\u50D7\"a2.splice(6, 12, b2); }  } ");
/*fuzzSeed-94431925*/count=1139; tryItOut("/*RXUB*/var r = new RegExp(\".{524289}|\\ua88a{2}\", \"y\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=1140; tryItOut("\"use strict\"; a0.__proto__ = this.m2;");
/*fuzzSeed-94431925*/count=1141; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((((Float64ArrayView[((-0x4a88195)+(i1)) >> 3]))))|0;\n    return (((((((0x6f5a512c) >= (0x34016aa3)))>>>((0xf89fcd0a))) != ((imul((i1), (i1))|0)))-(((((0xf9dfa8bd)-(0x12159fbd)) & ((i1))) == (abs((~((i1))))|0)) ? (((0x2244298) ? (0x3795a8f0) : (-0x8000000)) ? (/*FFI*/ff(((((0x177499d8)) ^ ((0x86009bc)))), ((-8.0)), ((-1.888946593147858e+22)), ((-17179869185.0)), ((-1.5111572745182865e+23)), ((1.0)))|0) : (i1)) : (i1))+((0xffffffff) ? (0xfdbb32f7) : ((1.0078125) != (-295147905179352830000.0)))))|0;\n  }\n  return f; })(this, {ff: d}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0.000000000000001, 42, -(2**53), 1/0, 1.7976931348623157e308, 0, -1/0, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, -0x100000000, 0x080000001, -Number.MAX_VALUE, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, 0x07fffffff, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), -0x07fffffff, 0x100000001, -0x080000001, 2**53+2, -0, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1142; tryItOut("\"use strict\"; switch(({})) { case 2: g0.offThreadCompileScript(\"mathy1 = (function(x, y) { \\\"use strict\\\"; return Math.pow(((Math.atan2((y | 0), (( + mathy0(( + x), ( + y))) | 0)) ? y : (((( - (( ~ x) >>> 0)) >>> 0) * (( + Math.min((y | 0), ( + x))) >>> 0)) >>> 0)) <= Math.max(((mathy0((x >>> 0), (( + Math.min(( + (Math.fround(y) === ( + ( + ( ~ Math.fround(-0x0ffffffff)))))), ( + y))) >>> 0)) >>> 0) >>> 0), y)), Math.hypot((((( + Math.min(( + (((1.7976931348623157e308 >>> 0) , -1/0) >>> 0)), ( + y))) | 0) - (Math.atan2(y, mathy0(y, 0x0ffffffff)) | 0)) | 0), ( + Math.acosh((( - (x | 0)) >>> 0))))); }); \");break; case (4277): break; break; default: for(let y = (4277) in x) {v2 = (g1 instanceof e2);for (var v of f2) { try { e0.add(p0); } catch(e0) { } try { g1.valueOf = (function(j) { if (j) { try { ; } catch(e0) { } (void schedulegc(g1)); } else { try { v1 = evalcx(\"( \\\"\\\" );\", g2); } catch(e0) { } try { m0.__proto__ = o2.f1; } catch(e1) { } try { for (var v of g1.o0.b0) { f0 + ''; } } catch(e2) { } i2.send(o0.t2); } }); } catch(e1) { } for (var p in a1) { try { (void schedulegc(g1)); } catch(e0) { } try { v0.toString = (function mcc_() { var niavgd = 0; return function() { ++niavgd; f0(/*ICCD*/niavgd % 10 == 8);};})(); } catch(e1) { } try { a2.push(v1, a2); } catch(e2) { } v1 = r2.flags; } } }break;  }");
/*fuzzSeed-94431925*/count=1143; tryItOut("mathy2 = (function(x, y) { return mathy1(Math.fround(Math.fround(( ! (Math.tanh((Math.abs((y | 0)) | 0)) | 0)))), ( + ((( + y) != (y | 0)) , ((((y >>> 0) ? x : (x | 0)) >>> 0) | 0)))); }); testMathyFunction(mathy2, [2**53+2, 1, 0/0, Number.MAX_VALUE, -0x080000001, 42, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -(2**53), -0x100000000, -0, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, Math.PI, 0x07fffffff, -Number.MIN_VALUE, 0x100000001, 1/0, 0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, Number.MIN_VALUE, 0x080000000, 0x080000001, 0x0ffffffff, -0x07fffffff, -0x0ffffffff, -(2**53-2), -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0]); ");
/*fuzzSeed-94431925*/count=1144; tryItOut("mathy0 = (function(x, y) { return ( + Math.fround(Math.max(Math.fround((( ~ (Math.min((y | 0), (x | 0)) | 0)) >>> 0)), (( ~ (( + Math.sign(Math.fround(x))) / y)) >>> 0)))); }); testMathyFunction(mathy0, [0x100000001, 0x100000000, 0.000000000000001, 2**53, 2**53+2, Number.MIN_VALUE, 0x080000001, 0, 42, 2**53-2, -Number.MAX_VALUE, -0x100000000, -1/0, -0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, 1.7976931348623157e308, -0x100000001, -0x07fffffff, -0, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, 1/0, Math.PI, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-94431925*/count=1145; tryItOut("testMathyFunction(mathy2, [0/0, -0x100000001, -0x080000001, -1/0, -Number.MAX_VALUE, -(2**53+2), -0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 0x100000000, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, 1/0, 1.7976931348623157e308, 0x07fffffff, Number.MAX_VALUE, 0x100000001, 0, -0x0ffffffff, -(2**53), -0x07fffffff, 42, Math.PI, -(2**53-2), 2**53+2, 1, 0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-94431925*/count=1146; tryItOut("if(false) {print(\"\\u6842\");\nv2 = Object.prototype.isPrototypeOf.call(m0, v0);\n } else  if ((x ? true : (allocationMarker()))) /* no regression tests found */ else print(a0);function y(x) { yield undefined } Array.prototype.forEach.call(a2, (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { a7 = 9 & 4; var r0 = a10 & 8; var r1 = a1 - 8; a4 = 6 + r1; var r2 = a4 / a6; var r3 = a0 + a10; a10 = a8 % a7; var r4 = a1 / a9; var r5 = r3 | x; var r6 = x & a9; var r7 = 9 & a3; r7 = a11 - r7; var r8 = a8 * a11; var r9 = 4 * a4; var r10 = r3 ^ r7; var r11 = r1 - r10; var r12 = a8 | 9; var r13 = r1 - 7; a2 = 5 ^ 8; var r14 = 3 ^ 4; var r15 = 2 + r8; var r16 = a7 % 5; var r17 = 7 % 8; var r18 = r7 & r8; var r19 = 5 * a10; r17 = 3 % 5; var r20 = r5 / 8; return a10; }), b1, e0,  /x/ , g1, i0);");
/*fuzzSeed-94431925*/count=1147; tryItOut("\"use strict\"; h1 + '';");
/*fuzzSeed-94431925*/count=1148; tryItOut("\"use strict\"; h1.enumerate = f1;");
/*fuzzSeed-94431925*/count=1149; tryItOut("\"use asm\"; g2.v2 = evaluate(\"h0 = {};\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 69 == 33), sourceIsLazy: (DataView.prototype.getInt16).call(x, ), catchTermination: (x % 17 == 16) }));");
/*fuzzSeed-94431925*/count=1150; tryItOut("{ void 0; try { startgc(1); } catch(e) { } }");
/*fuzzSeed-94431925*/count=1151; tryItOut("Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-94431925*/count=1152; tryItOut("b1 = x;");
/*fuzzSeed-94431925*/count=1153; tryItOut("testMathyFunction(mathy1, [null, (new Number(-0)), objectEmulatingUndefined(), 0, true, false, (new Boolean(true)), ({valueOf:function(){return 0;}}), (new Boolean(false)), /0/, -0, [], (new Number(0)), [0], (new String('')), (function(){return 0;}), 0.1, NaN, '0', '\\0', ({toString:function(){return '0';}}), undefined, '', '/0/', ({valueOf:function(){return '0';}}), 1]); ");
/*fuzzSeed-94431925*/count=1154; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1155; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + ( - Math.fround(mathy1(Math.tanh(Math.sinh((y >>> 0))), Math.pow(( + ( ! ( + Number.MAX_SAFE_INTEGER))), Math.trunc(Math.fround(x))))))); }); testMathyFunction(mathy4, [2**53, -Number.MAX_VALUE, 0x080000000, -0x080000000, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, -(2**53-2), -0x07fffffff, 1.7976931348623157e308, -0x100000000, Math.PI, -0, 0x100000001, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, 42, 1/0, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), 0x100000000, -0x080000001, 0/0, 2**53+2, -1/0, Number.MAX_VALUE, 1, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1156; tryItOut("( /x/g );1e81;");
/*fuzzSeed-94431925*/count=1157; tryItOut("for (var p in g0.o0.e0) { try { e1.delete(this.o0); } catch(e0) { } m1.get(a2); }function x(\u3056, x, eval, e, b, x, x, y, x, x, b, NaN, x, x, w, window, c, d, y, NaN = new RegExp(\"\\\\2\", \"gim\"), x =  /x/g , NaN, e, x, \u3056 =  \"\" , \u3056, w, e, window, x = \"\\uF102\", x, e = {}, c, eval, window, y, eval, d = true, x = window, x, x, d, \u3056 =  /x/g , eval, w, y, x, c, a, x =  '' , eval = 1e+81, x, x, x, x, x, b, toString, x, x = \"\\uB22A\", x, x = window, x, c, NaN, eval, x, \u3056, d =  '' , b, x, x, x, y, x, d, z = window, window, w, a, x, window, window, \u3056, c, eval = eval, e, b, x, NaN, y, x = new RegExp(\"(?=[^\\\\xA0\\\\d\\\\S\\\\\\u0006-\\\\u0087])(?=\\\\B|(?=^)*?)?\", \"gm\"), window, x, eval =  \"\" , b) { \"use strict\"; x; } print(x);");
/*fuzzSeed-94431925*/count=1158; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-94431925*/count=1159; tryItOut("\"use strict\"; o2.e0.add(e2);function \u3056() { yield (void options('strict_mode')) } s0 += 'x';function eval(w, w, x, x, w, x, x = x, [], eval = this, x, e, eval, x, window, window =  \"\" , y, NaN, w, NaN, y = \"\\u6F0B\", x =  '' , a, NaN, x, \u3056, x, z, y, x, w, \u3056, y =  '' , a, eval, d, x, b, c, \u3056, e, d, x, \u3056, a, c, x, e, x = new RegExp(\"(?=(?=(?=\\\\d))|(?=\\\\b)|(?=\\\\u55BC)|.*?|\\\\\\u97bb\\\\b|$)*?\", \"gyim\"), x, x, x, window, e, e, w, this.z, x, x = window, a, x, c, b, x, d, a = -29, x, eval, eval, \u3056 = false, \u3056, e, x, x, x, e, x, e =  /x/g , x, this.NaN, x, x = function(id) { return id }, x, x = [,,], window = \u3056, c, w = this, a, x, a = \"\\u538D\", ...x) { \"use strict\"; yield (4277) } switch({ sameZoneAs:  /x/g  <<= \"\\uCCAD\" }) { default: break;  }");
/*fuzzSeed-94431925*/count=1160; tryItOut("mathy3 = (function(x, y) { return ( - Math.sinh(((( ~ ((-0x07fffffff , ((y ** -0x080000001) | 0)) >>> 0)) >>> Math.fround(y)) | 0))); }); testMathyFunction(mathy3, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), function(){}, function(){}, function(){}, function(){}, new Number(1.5), new Number(1.5), function(){}, new Number(1.5), function(){}, function(){}, new Number(1.5), new Number(1.5), new Number(1.5), function(){}, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), function(){}, new Number(1.5), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1.5), new Number(1.5), new Number(1.5), function(){}, function(){}, function(){}, new Number(1.5), new Number(1.5), new Number(1.5), function(){}, function(){}, new Number(1.5), function(){}, new Number(1.5), new Number(1.5), function(){}, function(){}]); ");
/*fuzzSeed-94431925*/count=1161; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( + (Math.log1p(( + Math.imul((Math.log10(42) | 0), (mathy2((x | 0), (y | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, 42, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, -1/0, -0x0ffffffff, -Number.MAX_VALUE, 2**53-2, 0x080000000, 0x100000001, 0, Math.PI, 2**53+2, 2**53, 0x0ffffffff, 0.000000000000001, -0x080000001, -0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, 0x080000001, Number.MAX_VALUE, -0, 1.7976931348623157e308, -(2**53), 1/0, 0x100000000]); ");
/*fuzzSeed-94431925*/count=1162; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + ( ! (( + ( ! ( + Math.hypot(y, x)))) >>> 0))), ( + ( ~ (Math.abs(( + (( + x) + ( + Math.PI)))) | 0))))); }); testMathyFunction(mathy4, /*MARR*/[null, (1/0), new String(''), (1/0), (1/0), (1/0), new Number(1.5), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new String(''), null, null, new Number(1.5), null, x, new String(''), (1/0), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), (1/0), x, new String(''), (1/0), new String(''), new Number(1.5), new String(''), new String(''), null, null, new Number(1.5), x, x, x, x, x, x, x, x, x, x, x, new String(''), (1/0), (1/0), new Number(1.5), null, new String(''), x, new String(''), new Number(1.5), null, new Number(1.5), x, (1/0), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), (1/0), (1/0), null, x, new String(''), null, new Number(1.5), new Number(1.5), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), null, null, new String(''), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), null, x, x, new String(''), x, new String(''), new String(''), x, null, null, null, new String(''), x, x, new String(''), new Number(1.5), new String(''), new String(''), new Number(1.5), (1/0), new Number(1.5), new String(''), (1/0), new String(''), (1/0), new Number(1.5), null, new Number(1.5), new String(''), (1/0), null, null, new Number(1.5), x, new String(''), x, null, (1/0), x, new String(''), x, x, new Number(1.5), null]); ");
/*fuzzSeed-94431925*/count=1163; tryItOut("mathy3 = (function(x, y) { return ((Math.atan2((( ! ( + ( - ( + y)))) >>> 0), Math.min(Math.max((x ? 2**53 : 1/0), y), (( ! Math.fround(y)) ? Math.fround(Math.sinh(Math.log2(Number.MIN_SAFE_INTEGER))) : y))) | Math.min(Math.min(42, Math.cosh(y)), (Math.asinh((y | 0)) | 0))) >= Math.fround(((Math.fround(Math.log10(x)) + ((Math.acosh(x) | 0) >= y)) ? ( ~ Math.fround((( + (y === y)) ? y : Math.log(x)))) : Math.fround(Math.atan2((((y >>> 0) + (Math.log1p(x) >>> 0)) >>> 0), Math.fround(y)))))); }); ");
/*fuzzSeed-94431925*/count=1164; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1165; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( - (Math.fround(Math.pow(Math.fround(( + (Math.tanh((((42 | 0) * (Math.exp(-Number.MIN_VALUE) | 0)) | 0)) ^ ( + (-(2**53-2) === Math.fround(y)))))), (x | (( + (-(2**53-2) > 0.000000000000001)) + ( ~ (mathy0(x, x) | 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[1.7976931348623157e308, function(){}, new String(''), (-1/0), function(){}, 1.7976931348623157e308, function(){}, undefined, 1.7976931348623157e308, function(){}, undefined, function(){}, undefined, 1.7976931348623157e308, undefined, (-1/0), (-1/0), undefined, 1.7976931348623157e308, function(){}, new String(''), undefined, new String(''), new String(''), new String(''), 1.7976931348623157e308, function(){}, 1.7976931348623157e308, 1.7976931348623157e308, function(){}, (-1/0), undefined, function(){}, function(){}, function(){}, 1.7976931348623157e308, (-1/0), 1.7976931348623157e308, undefined, new String(''), undefined, function(){}, undefined, (-1/0), new String(''), new String(''), function(){}, undefined, 1.7976931348623157e308, new String(''), undefined, new String(''), 1.7976931348623157e308, function(){}, new String(''), new String(''), 1.7976931348623157e308, new String(''), 1.7976931348623157e308, undefined, new String(''), 1.7976931348623157e308, new String(''), 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, (-1/0), 1.7976931348623157e308, function(){}, (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (-1/0), new String(''), 1.7976931348623157e308, (-1/0), (-1/0), undefined, (-1/0), undefined, (-1/0), 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, undefined, undefined, function(){}, function(){}, undefined, (-1/0), 1.7976931348623157e308, undefined, 1.7976931348623157e308, function(){}, undefined, 1.7976931348623157e308, undefined, 1.7976931348623157e308, 1.7976931348623157e308, function(){}, (-1/0), 1.7976931348623157e308, 1.7976931348623157e308, (-1/0), (-1/0), undefined, 1.7976931348623157e308, new String(''), (-1/0), new String(''), 1.7976931348623157e308, 1.7976931348623157e308, undefined, 1.7976931348623157e308, 1.7976931348623157e308, new String(''), 1.7976931348623157e308, undefined, undefined, (-1/0), (-1/0), 1.7976931348623157e308, function(){}, function(){}, (-1/0), (-1/0), (-1/0), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, 1.7976931348623157e308, undefined, undefined, 1.7976931348623157e308, function(){}, (-1/0), (-1/0), 1.7976931348623157e308, 1.7976931348623157e308, undefined, undefined, undefined, new String(''), 1.7976931348623157e308, 1.7976931348623157e308, (-1/0), function(){}, (-1/0), undefined, function(){}, undefined, function(){}]); ");
/*fuzzSeed-94431925*/count=1166; tryItOut("m1.delete(((() => /*UUV1*/(c.setFloat32 = Promise.reject))(let (gcojkk, x, klqrkb, rtqmzs, x, e, fmwuba)  /x/ )));");
/*fuzzSeed-94431925*/count=1167; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=1168; tryItOut("");
/*fuzzSeed-94431925*/count=1169; tryItOut("b = ((void version(180)) < x), x");
/*fuzzSeed-94431925*/count=1170; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i1);\n    }\n    i0 = (/*FFI*/ff((((-0x589f7*(i0)) | ((!(i0))))), (((((~~(-288230376151711740.0)) > (~((0xdda1c519)-(0xf9ce0d2f)+(0x4d15aaa5))))+((0x3fd805f1))) ^ (((((i1)-((0x506a5e6b) != (0x7fffffff)))>>>(Math.imul((new EvalError(17)), w <= false))))))), ((((i0)) << (((((0x5c9f05f2) / (0xff78cb60)) >> ((0x4688051b)+(0xffffffff))))-(i1)))), ((((i1)-((+((-18014398509481984.0))) != (-((9.671406556917033e+24))))) & ((Uint32ArrayView[((i1)) >> 2])))), (((((Uint32ArrayView[4096]))-(i0)+(i0))|0)), ('fafafa'.replace(/a/g, x).unwatch(\"setInt8\")), ((((~((0xfccb1af3))) != (((0x3d2b6a58)) ^ ((0xbeefba6f)))))), ((((0x5ad0062d)) ^ ((0x3533d2b1)))), ((590295810358705700000.0)), ((-17592186044417.0)), ((1.125)))|0);\n    return (((((this))>>>((i0)-(((((0x39f5eaaa))) | ((i1)))))) / (((0x88caa9b9)*-0x2f4ed)>>>((Uint32ArrayView[0])))))|0;\n  }\n  return f; })(this, {ff: (w =>  { return x } ).bind}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=1171; tryItOut("\"use strict\"; m2.delete(o1);");
/*fuzzSeed-94431925*/count=1172; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return ((( ~ (( + ((mathy2((y >>> 0), -Number.MIN_VALUE) >>> 0) - (Math.PI | 0))) | 0)) ? ((Math.fround(Math.hypot(Math.fround(0x100000000), (( + Math.imul(( + 0x07fffffff), ( + Math.pow(x, (x > 0/0))))) | 0))) | 0) % ( ! (((Math.fround(Math.cosh(Math.fround(y))) && (x >>> 0)) >>> 0) | 0))) : (( ! ( + (Math.cosh(Math.fround(( + Math.max(mathy1(( + (( + (0x0ffffffff | 0)) | 0)), (y | 0)), mathy2(y, (y | 0)))))) | 0))) | 0)) | 0); }); testMathyFunction(mathy3, [-0x0ffffffff, -0x080000001, Number.MAX_VALUE, 0x080000000, 1, 0x080000001, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, 2**53+2, 0x07fffffff, -(2**53), -0, -0x100000001, 0/0, Number.MIN_VALUE, 0x100000001, -1/0, 0.000000000000001, 2**53-2, -0x07fffffff, -0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, 1/0, 0x100000000]); ");
/*fuzzSeed-94431925*/count=1173; tryItOut("\"use strict\"; print(v0);");
/*fuzzSeed-94431925*/count=1174; tryItOut("\"use strict\"; g1 + '';");
/*fuzzSeed-94431925*/count=1175; tryItOut("i2 = new Iterator(this.t2, true);");
/*fuzzSeed-94431925*/count=1176; tryItOut("m2.has(-5);");
/*fuzzSeed-94431925*/count=1177; tryItOut("\"use strict\"; var qxtwgy = new ArrayBuffer(4); var qxtwgy_0 = new Float32Array(qxtwgy); qxtwgy_0[0] = -5; var qxtwgy_1 = new Int32Array(qxtwgy); print(qxtwgy_1[0]); qxtwgy_1[0] = 15; var qxtwgy_2 = new Float32Array(qxtwgy); var qxtwgy_3 = new Float64Array(qxtwgy); qxtwgy_3[0] = 1; g2.m0.get(t1);throw [,,z1]; /x/ ;for (var v of this.b0) { try { m2.delete(p1); } catch(e0) { } this = this.t0[9]; }a2.forEach((function() { h2.get = f0; return this.o0.g0.f1; }));for (var p in g2) { try { for (var v of b2) { try { m0.set(m0, a0); } catch(e0) { } try { Array.prototype.sort.call(a2, (function mcc_() { var ojcofb = 0; return function() { ++ojcofb; f1(/*ICCD*/ojcofb % 10 == 0);};})()); } catch(e1) { } g0.g0 + ''; } } catch(e0) { } try { a0.pop(); } catch(e1) { } try { for (var v of g2) { try { i1.send(g0); } catch(e0) { } h0.getOwnPropertyDescriptor = f2; } } catch(e2) { } /*RXUB*/var r = r2; var s = s2; print(s.match(r));  }a0 = Array.prototype.slice.call(a1, NaN, NaN, s0);print(c);");
/*fuzzSeed-94431925*/count=1178; tryItOut("v1 = g0.b0.byteLength;\na1 = Array.prototype.map.apply(a1, [Object.prototype.__lookupGetter__.bind(t2), o0, g2.g1.a0, i1, i1, h2]);\n");
/*fuzzSeed-94431925*/count=1179; tryItOut("let (y) { throw new Boolean(false); }");
/*fuzzSeed-94431925*/count=1180; tryItOut("testMathyFunction(mathy4, [false, (new String('')), (function(){return 0;}), 0, '0', true, ({valueOf:function(){return '0';}}), '\\0', /0/, 1, null, '/0/', (new Boolean(false)), [0], 0.1, [], undefined, ({valueOf:function(){return 0;}}), NaN, ({toString:function(){return '0';}}), objectEmulatingUndefined(), (new Number(0)), '', -0, (new Number(-0)), (new Boolean(true))]); ");
/*fuzzSeed-94431925*/count=1181; tryItOut("/*RXUB*/var r = new RegExp(\"((?=(^{0,}[^]))|\\\\2|((?=(\\\\B\\\\B\\\\B))))|\\\\3??\", \"gim\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-94431925*/count=1182; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.atan2(( + (( ! (Math.sqrt(( - (( + Math.fround(( - Math.fround(x)))) < (( - x) >>> 0)))) | 0)) | 0)), ((Math.atan2(Math.fround(( + (y ^ ( + Math.atan2(( + x), Math.fround(y)))))), Math.fround(0x100000001)) << (y | 0)) ? ((Math.log2(((Math.pow(Math.fround((Math.fround(y) > x)), y) ? x : (y ? 1.7976931348623157e308 : Math.min(y, Number.MIN_VALUE))) >>> 0)) | (Math.pow((x | Math.log1p(x)), mathy1((((-0 >>> 0) * (1.7976931348623157e308 >>> 0)) >>> 0), (y === (x >>> 0)))) | 0)) | 0) : (( + (Math.tan(Number.MAX_VALUE) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-0, 1/0, -0x100000001, Number.MIN_VALUE, 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0x080000001, -Number.MAX_VALUE, 0x100000000, 42, 0, 0x080000000, -0x0ffffffff, 2**53+2, -0x080000000, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -1/0, 2**53-2, 1, -0x080000001, 2**53, -Number.MIN_VALUE, -(2**53+2), 0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1183; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.atan2(Math.imul(Math.asinh(Math.sqrt(Math.fround(1/0))), mathy1(y, (Math.fround(Math.clz32((y >>> 0))) >>> 0))), ( + Math.imul(Math.fround(Math.tan(Math.fround((mathy4(y, ( + Math.max(( + y), ( + x)))) >>> 0)))), (-0 ^ ( ! Math.PI)))))); }); testMathyFunction(mathy5, [0x0ffffffff, 0, 0x100000000, 0.000000000000001, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -1/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, -0x080000001, 42, -(2**53), -0, 1/0, 2**53+2, -(2**53+2), 2**53, 0x100000001, -0x080000000, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1184; tryItOut("t0.toSource = (function(j) { f2(j); });function \u3056()(4277)t0.toString = (function(j) { f1(j); });");
/*fuzzSeed-94431925*/count=1185; tryItOut("/*RXUB*/var r = /\\3{16,}/; var s = \"\\n\\n\\n0\\n\\n\\n\\n0\\n\\n|  a1a\\n\\n\\n0\\n\\n\\n\\n0\\n\\n\\n\\n\\n0\\n\\n\\n\\n0\\n\\n\\u7e911|  a1a\\n\\n\\n0\\n\\n\\n\\n0\\n\\n\\n\\n\\n0\\n\\n\\n\\n0\\n\\n\\n\\n\\n0\\n\\n\\n\\n0\\n\\n\\u7e911|  a1a\\n\\n\\n0\\n\\n\\n\\n0\\n\\n\"; print(s.replace(r, '', \"ym\")); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1186; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xd59e0e7d)))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x080000000, -(2**53+2), -1/0, 0x100000000, 2**53, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, 0/0, Math.PI, -0x080000000, 1, 1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 0x100000001, 0x080000001, -0, 0, -Number.MIN_VALUE, -0x080000001, 0x07fffffff, 1.7976931348623157e308, -0x100000000, 2**53+2, 42, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-94431925*/count=1187; tryItOut("h1 = ({getOwnPropertyDescriptor: function(name) { m0 = new Map(o1.m2);; var desc = Object.getOwnPropertyDescriptor(a0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v0 = Object.prototype.isPrototypeOf.call(t1, o0.s0);; var desc = Object.getPropertyDescriptor(a0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v1 = Object.prototype.isPrototypeOf.call(this.s2, g2);; Object.defineProperty(a0, name, desc); }, getOwnPropertyNames: function() { this.e0 = new Set(p0);; return Object.getOwnPropertyNames(a0); }, delete: function(name) { s2 + e1;; return delete a0[name]; }, fix: function() { print(uneval(e1));; if (Object.isFrozen(a0)) { return Object.getOwnProperties(a0); } }, has: function(name) { o1.g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 3 != 0), element: o1 }));; return name in a0; }, hasOwn: function(name) { v1 = Object.prototype.isPrototypeOf.call(a1, o1.s0);; return Object.prototype.hasOwnProperty.call(a0, name); }, get: function(receiver, name) { v0 = g0.eval(\"h1 + '';\");; return a0[name]; }, set: function(receiver, name, val) { for (var v of this.o0) { try { a2[11]; } catch(e0) { } e1 = new Set(g1.t0); }; a0[name] = val; return true; }, iterate: function() { s0 = new String(b2);; return (function() { for (var name in a0) { yield name; } })(); }, enumerate: function() { v2 = g1.runOffThreadScript();; var result = []; for (var name in a0) { result.push(name); }; return result; }, keys: function() { var v1 = t1.BYTES_PER_ELEMENT;; return Object.keys(a0); } });");
/*fuzzSeed-94431925*/count=1188; tryItOut("for(var x = x in window) Object.defineProperty(this, \"g0.a0\", { configurable: false, enumerable: true,  get: function() {  return Array.prototype.slice.apply(o2.a1, [9, NaN]); } });");
/*fuzzSeed-94431925*/count=1189; tryItOut("\"use strict\"; m2.set(g1.o1.o2, t1);");
/*fuzzSeed-94431925*/count=1190; tryItOut("t0.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69) { var r0 = 5 * 1; var r1 = a62 & a0; var r2 = a6 % 6; a26 = a66 | a53; a52 = a16 / a38; var r3 = 6 % a4; var r4 = a20 / x; var r5 = a39 / a28; var r6 = a63 + 8; var r7 = r5 / a25; var r8 = 5 / a54; var r9 = 7 % a21; var r10 = a24 | 1; var r11 = 9 & a1; var r12 = r7 | a17; var r13 = r4 | 6; a46 = a48 % 4; var r14 = a10 / 4; var r15 = 0 ^ a16; a57 = 3 | a62; var r16 = 4 % a24; var r17 = 3 - 0; var r18 = a33 / a28; var r19 = 5 & 0; var r20 = r2 * 0; var r21 = 9 | 8; print(r7); var r22 = a57 / r4; r5 = 2 + a66; var r23 = 3 / a1; var r24 = 5 * 8; var r25 = a8 | a61; r3 = a30 % a42; a69 = a39 * a10; a64 = a21 & 5; var r26 = a7 % 0; var r27 = a47 - a42; var r28 = r15 + a21; var r29 = r1 * a61; var r30 = a62 | r3; var r31 = a19 & 9; a62 = a65 | 6; var r32 = r1 % 9; var r33 = 5 | a52; var r34 = r16 % r28; var r35 = a66 | 7; var r36 = 2 / a37; var r37 = a66 % a5; a17 = 2 - 6; var r38 = r10 & r23; var r39 = a45 ^ r18; var r40 = r19 - a50; var r41 = a29 ^ a69; var r42 = r19 % a45; a29 = 9 & 6; var r43 = r23 / 9; var r44 = 4 + 1; var r45 = a31 & a39; var r46 = r11 ^ 7; var r47 = 5 / a52; var r48 = a62 / a47; var r49 = a49 % a37; var r50 = r44 / a36; var r51 = 9 - a60; var r52 = 4 + a7; var r53 = a46 + a28; var r54 = 9 | a63; var r55 = a5 | a39; var r56 = 8 + 3; var r57 = 3 / r29; a6 = 9 * 3; var r58 = a14 * 8; var r59 = 4 % 4; var r60 = a4 - r15; var r61 = r60 % a36; var r62 = 4 - 3; var r63 = r31 + a54; var r64 = a12 + r37; print(r8); var r65 = a20 | r31; var r66 = r24 & a56; r28 = a47 % r30; r65 = 4 + 9; r59 = a46 - r32; var r67 = 5 / 5; print(r67); var r68 = a67 + r35; a7 = 0 / r32; var r69 = r63 | 1; var r70 = 6 ^ 5; var r71 = a64 / 6; var r72 = a7 - r17; print(a13); var r73 = x * 3; var r74 = 5 | r11; r73 = a68 / a47; var r75 = r69 | r3; var r76 = r48 / 3; var r77 = 4 * 8; var r78 = r72 ^ a63; var r79 = a4 * a43; var r80 = r0 & r5; var r81 = a58 & r78; var r82 = r71 + 9; var r83 = r44 + 6; a62 = a41 / a62; r5 = a54 & a52; var r84 = 7 - r82; var r85 = r81 | 5; var r86 = a32 / r21; var r87 = a45 - a47; var r88 = r55 % 6; var r89 = a25 | 1; var r90 = a63 - 2; var r91 = a29 - 1; r28 = a44 | 1; var r92 = a0 * 9; r2 = 6 / r56; var r93 = a36 / a9; var r94 = a5 / r93; print(a17); var r95 = r80 / 8; var r96 = 7 & r31; var r97 = r26 + a16; var r98 = 7 & r64; a61 = r16 - a13; r97 = a21 / a38; var r99 = r70 | r68; var r100 = r85 ^ r78; var r101 = 6 ^ a23; var r102 = r34 - r19; print(r43); r88 = a63 | 5; var r103 = a39 % r15; var r104 = r59 ^ 1; var r105 = r62 ^ 5; r32 = 1 ^ r2; var r106 = a5 - a24; var r107 = 0 - r97; a61 = a38 % r28; var r108 = 4 & 2; var r109 = 5 * 1; r80 = r97 % r94; var r110 = a50 | r19; var r111 = 7 - 8; var r112 = 2 ^ r21; var r113 = a7 & r58; var r114 = r96 ^ r46; var r115 = a57 - r24; a36 = 4 - r52; var r116 = 2 * r82; var r117 = a19 % 9; a52 = 7 * a17; var r118 = 7 / a13; var r119 = 0 ^ r54; var r120 = a46 ^ r3; var r121 = r94 % r118; var r122 = a12 % a6; var r123 = r91 / 7; var r124 = 6 % 2; var r125 = a55 & r72; var r126 = 0 + 4; var r127 = 3 | 9; var r128 = r43 ^ r74; var r129 = r91 | a59; var r130 = 2 / a11; var r131 = r82 | r66; var r132 = 0 | a49; r25 = 0 - r85; var r133 = r128 | 4; print(a21); a49 = r53 / a24; var r134 = r18 / r75; var r135 = a46 & 1; var r136 = 4 + 5; var r137 = 0 / 1; var r138 = r0 ^ 0; a36 = 1 * 5; var r139 = r26 | r108; var r140 = 7 | r21; var r141 = r120 & r87; var r142 = r125 % r90; var r143 = a6 * a54; var r144 = a52 - 6; var r145 = 0 / a41; var r146 = 5 - 2; var r147 = r27 * r15; var r148 = r4 & a46; var r149 = r91 / a1; var r150 = r148 % a44; var r151 = r61 | 5; var r152 = r75 ^ r135; r37 = r71 | r105; var r153 = 9 ^ 4; var r154 = r16 - r92; r25 = a6 + r107; var r155 = r59 & 3; var r156 = r97 - a21; var r157 = r0 - 4; var r158 = r75 % r56; print(r3); var r159 = 3 % r3; var r160 = 0 | 0; r92 = r159 - r134; var r161 = 2 % 6; var r162 = r66 * 9; var r163 = 2 % 5; a36 = a43 / 4; var r164 = 5 | 0; var r165 = a12 * 7; var r166 = 9 ^ r156; var r167 = r55 + 2; r76 = 4 % 2; var r168 = 0 + r93; var r169 = 4 - r63; var r170 = a8 + 7; var r171 = r53 / 3; var r172 = r131 / 5; a64 = a10 & r90; a69 = 6 | 4; r172 = 3 | 7; var r173 = r160 & r110; var r174 = r147 | r124; var r175 = r135 * 8; var r176 = r56 & 4; var r177 = 3 % r158; r87 = r70 % 8; var r178 = a41 & a43; var r179 = r43 % 1; var r180 = 4 & r140; var r181 = r127 & r44; print(r33); var r182 = r100 - 6; r45 = a60 + r25; r143 = r2 - a19; a34 = r34 - r115; var r183 = r95 / a40; r168 = r95 * r46; var r184 = r152 % 2; var r185 = 6 * 8; var r186 = a63 ^ a28; var r187 = a46 / r165; var r188 = 6 % r164; var r189 = 6 % r32; var r190 = a39 & 9; var r191 = r95 % r177; r139 = r97 % r129; x = a26 & a48; var r192 = 4 + 0; print(r14); var r193 = r93 * r60; var r194 = 2 & r60; var r195 = r152 - r49; a32 = r193 - r125; var r196 = r193 | 7; var r197 = r139 / 5; var r198 = 4 ^ r112; var r199 = r120 % r193; var r200 = r43 & 9; var r201 = r146 ^ r152; var r202 = 3 | r55; print(r185); var r203 = a60 + 2; var r204 = a7 / 6; var r205 = 8 - r161; var r206 = r150 & r166; var r207 = r131 ^ 1; var r208 = r92 * 1; var r209 = a30 | 2; var r210 = 0 / r149; var r211 = 0 / 0; var r212 = 5 * r57; var r213 = 9 & 7; var r214 = r194 ^ r177; var r215 = r184 ^ r190; var r216 = a25 | 3; r136 = r25 * r212; var r217 = r118 * r171; var r218 = r209 + r84; var r219 = r154 / 3; var r220 = 8 & 2; var r221 = r119 ^ 2; r92 = r42 ^ r191; var r222 = r221 * r184; var r223 = r92 | r189; var r224 = r5 / 2; var r225 = a40 / 7; r81 = a17 ^ 7; var r226 = r213 & r184; var r227 = 3 * 5; var r228 = r154 + r66; var r229 = r83 ^ a46; r128 = 7 & a11; var r230 = 8 % r35; var r231 = r190 - 2; var r232 = r134 ^ r53; var r233 = r109 * r38; r107 = r22 - r72; var r234 = 9 / r125; var r235 = r81 ^ r98; var r236 = r138 % r67; r186 = r151 & r31; var r237 = r69 / r69; r165 = r218 & r82; r208 = 8 / r81; var r238 = r223 / r160; r18 = r208 * 2; var r239 = a17 & 6; r214 = 3 ^ r205; var r240 = a12 + r171; var r241 = r69 + 5; var r242 = a13 % r69; var r243 = a21 * 0; var r244 = 3 / 7; var r245 = 0 % r13; r11 = a18 & r174; var r246 = 2 ^ r220; var r247 = r135 * 3; var r248 = r30 / 8; var r249 = r65 ^ 8; r148 = 8 * 4; r230 = r213 | r123; r21 = 3 % r179; var r250 = a68 * 8; r101 = 2 - 4; var r251 = r62 + 9; var r252 = r143 | a21; r203 = r177 ^ a67; var r253 = a62 & r184; print(r230); var r254 = 2 ^ r38; var r255 = 9 + a8; var r256 = 5 + a67; var r257 = 5 & a49; a21 = r217 / r122; var r258 = a42 - r89; r112 = r68 * r173; var r259 = r8 / r217; r24 = a1 & r172; var r260 = r168 & 8; var r261 = a37 | r105; var r262 = 7 ^ 9; var r263 = a11 | 1; var r264 = 0 * r117; var r265 = 3 | a64; r184 = a16 ^ r72; var r266 = r226 ^ a17; var r267 = r205 - r166; var r268 = r210 % r263; r127 = r243 / 5; var r269 = 4 / r254; var r270 = r210 + r258; r181 = a19 - r183; print(r260); var r271 = 2 * 1; var r272 = r247 % r58; var r273 = r237 | 8; r200 = 2 - r153; print(a56); print(r183); var r274 = r138 % 3; var r275 = r260 + a52; var r276 = r49 % 7; print(r265); var r277 = a18 / a20; var r278 = 4 & 8; var r279 = r26 & 1; var r280 = r27 * a40; var r281 = r126 ^ 6; var r282 = 4 % r42; var r283 = r242 | 1; r222 = 7 & 6; var r284 = 1 + r244; r79 = r178 % r118; var r285 = 6 / r168; r14 = r233 * r41; a44 = 6 * 6; var r286 = r213 | r93; r145 = a19 | r37; var r287 = r132 + r163; var r288 = 2 % r3; r182 = a35 & r196; r262 = r20 / 2; r256 = r45 % r127; var r289 = 6 & a24; var r290 = r256 | r39; var r291 = r148 / 1; var r292 = r192 - 9; var r293 = r180 ^ 1; r229 = 5 ^ 2; var r294 = 9 % r273; var r295 = r68 & r105; var r296 = 7 & 2; var r297 = r17 ^ 3; var r298 = r259 - r230; r100 = 6 + a40; var r299 = 6 % 8; var r300 = 1 & 8; var r301 = 9 & r247; r141 = 0 | r20; var r302 = r21 - r182; var r303 = r148 * r131; var r304 = r21 ^ 3; var r305 = r263 | 4; var r306 = r45 & 0; var r307 = r49 * r69; var r308 = r296 ^ 8; var r309 = r282 % r171; r177 = 2 % 2; var r310 = r265 / 4; var r311 = r147 - 2; var r312 = r115 ^ r149; var r313 = 7 % r264; r269 = a26 / r189; r219 = 0 - r196; var r314 = r206 ^ r303; var r315 = 2 * r24; var r316 = r243 ^ 7; var r317 = 1 % a28; var r318 = a49 / r83; var r319 = a3 % r179; var r320 = a56 % 8; var r321 = r300 - 2; var r322 = 5 + r66; r142 = 3 - r179; var r323 = r279 | r130; var r324 = r61 / r297; var r325 = 5 ^ r96; var r326 = r152 * r27; var r327 = r53 - a10; r106 = 4 & a9; var r328 = a53 % 5; var r329 = r13 & 1; var r330 = 5 % 5; var r331 = 8 | r233; a4 = a66 ^ 6; var r332 = 7 | 3; print(r240); var r333 = 0 - r49; var r334 = r69 - r319; var r335 = r112 + r183; var r336 = r186 & 4; var r337 = a8 ^ 3; r158 = r199 | r219; var r338 = r190 | r276; var r339 = r262 / 8; var r340 = 0 % r231; a21 = r212 & 1; var r341 = r61 ^ r149; var r342 = 5 ^ 9; var r343 = r332 - r93; return a36; });");
/*fuzzSeed-94431925*/count=1191; tryItOut("\"use strict\"; h0.get = DataView.prototype.getFloat64.bind(o1);");
/*fuzzSeed-94431925*/count=1192; tryItOut("print(x);\n17;\n");
/*fuzzSeed-94431925*/count=1193; tryItOut("testMathyFunction(mathy0, /*MARR*/[arguments.callee, Infinity, Infinity, arguments.callee, this, this, Infinity, arguments.callee, arguments.callee, this, Infinity, arguments.callee, arguments.callee, Infinity, arguments.callee, this, Infinity, Infinity, Infinity, arguments.callee, arguments.callee, arguments.callee, arguments.callee, Infinity, this, this, arguments.callee, this, Infinity, this, this, Infinity, this, arguments.callee, arguments.callee, Infinity, arguments.callee, arguments.callee, arguments.callee, arguments.callee, Infinity, Infinity, Infinity, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, this, arguments.callee, Infinity, this, this, this, this, this, this, this, this, this, this, this, this, Infinity, this, arguments.callee, arguments.callee, this, this, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, this, this, Infinity, arguments.callee, this, Infinity, arguments.callee, arguments.callee]); ");
/*fuzzSeed-94431925*/count=1194; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-94431925*/count=1195; tryItOut("Array.prototype.forEach.call(a2, (function() { for (var j=0;j<4;++j) { f2(j%3==1); } }), this.v0, g2.p2, g1.g0, arguments.callee.arguments =  /x/g , g0.p1, g2, o2.m0, f2);");
/*fuzzSeed-94431925*/count=1196; tryItOut("/*RXUB*/var r = /\\b/ym; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-94431925*/count=1197; tryItOut("e1.add((4277));");
/*fuzzSeed-94431925*/count=1198; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( + Math.fround(Math.min(Math.atan((y ** (( + Math.sin(y)) === y))), (Math.fround((Math.fround(y) >>> Math.fround(mathy1(y, 1/0)))) >>> 0))))); }); ");
/*fuzzSeed-94431925*/count=1199; tryItOut("\"use strict\"; (void options('strict'));\nv1 = (m0 instanceof h2);\n");
/*fuzzSeed-94431925*/count=1200; tryItOut("mathy4 = (function(x, y) { return Math.max((Math.cos(Math.asin(Math.fround(y))) + Math.round(( + mathy1(( + x), ( + Math.max(-1/0, 0x0ffffffff)))))), (Math.fround(Math.sinh(x)) ? (Math.fround(( ! (x >>> 0))) ? (( - y) >>> 0) : Math.min(Math.fround(x), x)) : Math.min(Math.fround((Math.fround(Math.clz32(2**53-2)) != (y | 0))), Math.asin(( ~ Math.fround(( + (( + 0x080000000) % ((x == y) >>> 0))))))))); }); testMathyFunction(mathy4, [-0, 2**53+2, 1/0, 2**53-2, 0/0, 0x100000001, 0x07fffffff, -0x080000000, -Number.MAX_VALUE, -1/0, -0x100000001, 0x100000000, -(2**53), 0x080000000, 0.000000000000001, 1, 1.7976931348623157e308, -(2**53+2), 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 0, 2**53, -0x080000001, -0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 42, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1201; tryItOut("\"use strict\"; o0.v2 = t2.length;\nprint(/\\w/gi);\n");
/*fuzzSeed-94431925*/count=1202; tryItOut("throw 17;throw StopIteration;function a(x, x) { \"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?![^\\\\S\\u0093-\\\\uF8Dc\\\\s]\\\\u2BFe\\\\w(?!(?=.))*?))\", \"yim\"); var s = \"\"; print(s.replace(r, ((NaN = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { throw 3; }, has: undefined, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })([z1,,]), s, String.prototype.lastIndexOf))).bind));  } /*oLoop*/for (let jbvcag = 0; jbvcag < 126; ++jbvcag) { continue L; } ");
/*fuzzSeed-94431925*/count=1203; tryItOut("\"use strict\"; L: {v2 = g0.eval(\"function this.f0(v1)  { yield 'fafafa'.replace(/\\u000ca/g, ReferenceError.prototype.toString) } \"); }");
/*fuzzSeed-94431925*/count=1204; tryItOut("\"use strict\"; testMathyFunction(mathy5, [2**53-2, -0x100000001, 0x100000001, Number.MAX_VALUE, -0x080000000, Math.PI, -0x080000001, 0, Number.MIN_VALUE, 2**53+2, 0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, -1/0, -0, -(2**53+2), 0x100000000, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 0/0, 2**53, 1/0, 0x080000001, -Number.MAX_VALUE, -0x07fffffff, 1, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 42, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=1205; tryItOut("mathy0 = (function(x, y) { return Math.log10(Math.log1p(Math.atan(Math.fround(Math.hypot(Math.fround(y), y))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, Number.MIN_VALUE, -(2**53-2), -1/0, -0x080000000, -0x0ffffffff, 0x100000001, 1.7976931348623157e308, -(2**53+2), -0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, -0, -Number.MAX_VALUE, 2**53-2, 0x07fffffff, 0, -0x07fffffff, 0x0ffffffff, 2**53+2, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 1, -0x080000001, -(2**53), 0x080000000, 1/0, Math.PI]); ");
/*fuzzSeed-94431925*/count=1206; tryItOut("a2 = Array.prototype.map.call(a1, (function() { f2(b1); return v2; }));");
/*fuzzSeed-94431925*/count=1207; tryItOut("v0 = 4;");
/*fuzzSeed-94431925*/count=1208; tryItOut("/*RXUB*/var r = /(?:(\\D+){2,5})/yi; var s = \"0____0____\"; print(s.search(r)); ");
/*fuzzSeed-94431925*/count=1209; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh((Math.round(( ~ Math.fround((Math.atan2((x | 0), y) >>> (x >>> 0))))) >>> 0)); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 0, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -0, -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -0x100000000, Number.MIN_VALUE, 0/0, 2**53-2, Math.PI, 2**53, -(2**53), 1/0, -0x100000001, 2**53+2, 42, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1210; tryItOut("\"use strict\"; Object.defineProperty(this, \"v2\", { configurable: (x) = (({}) = [1]), enumerable: true,  get: function() { h1.valueOf = this.f1; return evaluate(\"w%=delete new ((({/*TOODEEP*/})).apply)( /x/ ).unwatch(\\\"apply\\\")\", ({ global: g0.o2.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 10 != 7), sourceIsLazy: (x % 6 == 1), catchTermination: true, element: o2, sourceMapURL: s0 })); } });");
/*fuzzSeed-94431925*/count=1211; tryItOut("\"use strict\"; g1 = this;");
/*fuzzSeed-94431925*/count=1212; tryItOut("/*ADP-1*/Object.defineProperty(a2, 12, ({value: /(\\w)|[^]/i, writable: true, enumerable: (x % 4 == 3)}));\no0.o0.a2.unshift(a, g1.g0.t0, a2, a0);\n/* no regression tests found */\n\n");
/*fuzzSeed-94431925*/count=1213; tryItOut("f0 = Proxy.createFunction(h0, f1, f1);");
/*fuzzSeed-94431925*/count=1214; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.acosh(( + (( + x) === ( + (( + Math.atan2(Math.fround((Math.fround(x) ? Math.fround(Math.pow(( + (-Number.MAX_SAFE_INTEGER | 0)), Math.fround(Math.trunc(Math.fround(x))))) : (Math.log10(y) >>> 0))), mathy0(x, -Number.MIN_SAFE_INTEGER))) * ( + Math.tan(Math.fround(( - ( - (( ! (x >>> 0)) | 0)))))))))))); }); testMathyFunction(mathy2, [0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -0, -0x100000001, 2**53-2, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 2**53+2, -0x080000001, 42, 0x080000000, 0x100000001, -(2**53-2), -(2**53+2), 1/0, 0, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1, 0x07fffffff, -0x07fffffff, 0x100000000, 2**53, Number.MIN_SAFE_INTEGER, -1/0, 0/0, -(2**53), 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=1215; tryItOut("testMathyFunction(mathy3, [Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000000, -0x080000001, 0/0, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, -0x100000001, 0, -(2**53-2), 0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, -0x0ffffffff, 1/0, 2**53, 0x100000000, -0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000000, 1, 2**53-2, 0x080000001, -0, Number.MAX_SAFE_INTEGER, 2**53+2, 42, -(2**53), -1/0, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=1216; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.push.apply(o0.a1, [o2]);");
/*fuzzSeed-94431925*/count=1217; tryItOut("\"use strict\"; \"use asm\"; o1.o2.__iterator__ = (function() { for (var j=0;j<128;++j) { this.f2(j%3==0); } })");
/*fuzzSeed-94431925*/count=1218; tryItOut("const v1 = g1.runOffThreadScript();if((({ get LOG10E(x = true, b, e = 10, b, w, z, x = /[^]/, \u3056, eval, z, \u3056, a, z, x, x = a, x, x, \u3056, w, x, window, a, x, w, z =  \"\" , NaN, a, e, a, a, x, x, x, z, x = \"\u03a0\", NaN, this.w, window, a, \u3056 = 14, \u3056, /\\s/gyim, x, y, \u3056, w, d, window, e, x, \u3056, e, e, x, a = 26, x, x, eval, x, e = 15, NaN = \"\\uC3F3\", set, x, x =  '' , eval = x, x = x, \u3056, d = \"\\uD7C3\", a, NaN = window, b, x, z, x, y, e, y, x, eval, eval, z = [[1]]) { yield  /x/  }  }))) {o1.o2.__iterator__ = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) { print(a7); var r0 = a8 ^ a3; a1 = x + r0; var r1 = 1 ^ 8; var r2 = a6 & a2; var r3 = x + r1; var r4 = a9 ^ r0; var r5 = a4 % 8; a3 = 3 & a4; var r6 = r3 & a2; var r7 = 6 ^ r0; var r8 = 8 + r2; var r9 = a4 ^ r1; var r10 = r8 / a0; a0 = r10 & 4; var r11 = a9 - 2; var r12 = a0 | a10; var r13 = r12 & 1; var r14 = 8 - 8; var r15 = a4 * r0; print(a2); var r16 = 4 % 2; var r17 = 0 / r7; a2 = 5 - r0; var r18 = 6 - r6; var r19 = r7 ^ a0; r13 = r4 - a4; var r20 = a4 % r12; var r21 = 0 | a10; r16 = 7 + 6; print(r19); var r22 = 2 + a0; a3 = 0 / 8; var r23 = 8 % a10; var r24 = r10 - r2; var r25 = a5 * 4; var r26 = a4 | a8; r23 = r17 ^ 8; var r27 = r2 | 3; var r28 = r11 | r16; var r29 = 9 & 9; var r30 = a1 * r23; var r31 = r6 % r23; var r32 = r30 * r2; var r33 = a9 / r32; var r34 = r0 % r6; a6 = 8 | r18; var r35 = r7 + 4; print(a7); var r36 = 2 - 8; var r37 = r28 + r34; var r38 = r33 & a2; r10 = r15 ^ r37; var r39 = r17 | r19; r3 = 2 ^ 1; var r40 = r5 % r34; r32 = 7 % 2; var r41 = r12 % 8; var r42 = 6 / a0; var r43 = r24 / 5; var r44 = 1 ^ a4; var r45 = r28 - r17; r5 = 6 % 7; var r46 = 6 / r19; var r47 = 0 / 2; r35 = r34 % a0; var r48 = 8 & r34; r16 = 0 % 8; var r49 = a1 / r7; r41 = r12 - r44; x = r39 | r4; var r50 = a3 | r16; var r51 = 4 % 1; var r52 = r35 % r44; var r53 = a8 & r12; var r54 = 5 ^ r12; a9 = 0 / r3; r42 = r18 | r30; r38 = 7 ^ r39; var r55 = 9 % r15; var r56 = a6 - r22; var r57 = r55 / a9; print(r47); var r58 = r45 | a8; r31 = 9 & 2; var r59 = 3 + r57; var r60 = r5 % r14; var r61 = r49 ^ r47; var r62 = r34 ^ r38; var r63 = a9 - r48; var r64 = r46 ^ r26; print(r2); r25 = r43 - r41; var r65 = 6 | r8; var r66 = r40 | r13; r26 = 3 * r53; print(r3); var r67 = 6 - r57; r1 = a9 | a7; var r68 = r33 / 4; print(a10); var r69 = r31 & r42; var r70 = 0 * r51; r7 = r60 + 1; var r71 = 1 & r17; var r72 = x ^ 1; var r73 = r26 % r56; var r74 = r22 - 3; r32 = 3 & r63; var r75 = 0 - 0; var r76 = a2 % r57; var r77 = r69 & r53; var r78 = r68 ^ r11; var r79 = r72 % r7; var r80 = a10 - 3; var r81 = r77 / r71; var r82 = 2 & 4; var r83 = 4 * r52; var r84 = 3 & r82; r61 = 2 - r9; var r85 = 9 - r80; var r86 = 2 / r54; print(r41); r3 = 0 % r68; r75 = a3 * r45; r33 = r33 * r69; var r87 = 6 & 7; var r88 = 1 * r60; var r89 = 9 * r69; var r90 = r41 % r1; var r91 = r29 % r19; var r92 = 2 / r30; return a7; });undefined; }");
/*fuzzSeed-94431925*/count=1219; tryItOut("mathy1 = (function(x, y) { return (Math.hypot(Math.pow((( ! (x >>> 0)) >>> 0), ((Math.log1p((Math.fround(Math.imul(Math.fround(( - (y | 0))), Math.fround(x))) | 0)) | 0) >>> 0)), Math.hypot(( + Math.max(mathy0(y, (Math.fround(y) | 0)), ((Math.atan(Math.fround((mathy0(Math.fround(( + -(2**53-2))), ( + y)) >>> 0))) == (( + (Math.log1p((y >>> 0)) >>> 0)) == x)) >>> 0))), Math.fround((Math.fround((( - Math.fround(mathy0(x, Math.min(y, -0x0ffffffff)))) | 0)) > Math.fround(( + Math.asin(( + ( + mathy0(mathy0(x, y), (y + (y ** x)))))))))))) >>> 0); }); testMathyFunction(mathy1, [0x080000000, -(2**53-2), -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, 2**53-2, 42, 2**53, -0x100000001, Math.PI, 0x100000000, Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), -Number.MAX_VALUE, 0x100000001, -0x100000000, -1/0, 1, 1.7976931348623157e308, 0x080000001, -(2**53), 0, -0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, -0]); ");
/*fuzzSeed-94431925*/count=1220; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-94431925*/count=1221; tryItOut("\"use strict\"; (x);v2 = 4;");
/*fuzzSeed-94431925*/count=1222; tryItOut("\"use strict\"; const x = x;print(/*FARR*/[this, false,  '' , length,  /x/g , \"\\uE3FA\", ...[], \"\\uDECE\", 12, 23, , window].some);");
/*fuzzSeed-94431925*/count=1223; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - Math.cosh((( + ( ! (2**53-2 >>> 0))) | 0))); }); testMathyFunction(mathy1, [-1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, 0/0, -Number.MIN_VALUE, 0x07fffffff, -(2**53), 1, 0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, -0x0ffffffff, Number.MAX_VALUE, Math.PI, -0x100000001, 0x0ffffffff, 1/0, 0, -0x100000000, 2**53, -(2**53+2), -(2**53-2), 2**53+2, 0.000000000000001, 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, 0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 42]); ");
/*fuzzSeed-94431925*/count=1224; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((Infinity));\n    i0 = (i0);\n    {\n      i0 = (0xfa0346fe);\n    }\n    d1 = (d1);\n    return +((d1));\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 0.000000000000001, -0x100000000, -0, 42, -0x0ffffffff, -(2**53-2), 2**53, Math.PI, 2**53+2, 0/0, 1, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -Number.MIN_VALUE, Number.MAX_VALUE, 0, -0x080000000, 0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 2**53-2]); ");
/*fuzzSeed-94431925*/count=1225; tryItOut("");
/*fuzzSeed-94431925*/count=1226; tryItOut("f1 = Proxy.createFunction(h0, f1, f2);");
/*fuzzSeed-94431925*/count=1227; tryItOut("print(uneval(this.b2));( '' );");
/*fuzzSeed-94431925*/count=1228; tryItOut("mathy2 = (function(x, y) { return ( ! mathy1(Math.fround(( - Math.fround(Math.asinh((( ! 2**53) >>> 0))))), Math.fround(Math.log1p((((x | 0) * Math.fround(x)) >>> 0))))); }); testMathyFunction(mathy2, /*MARR*/[function(){}, null,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , null, null, undefined,  /x/ , function(){}, null,  /x/ ,  /x/ , undefined, function(){}, null, function(){}, null, function(){}, null, null, null, undefined, null,  /x/ , undefined, undefined, function(){}, null, function(){}, function(){}, null, undefined, null,  /x/ , null, function(){}, null, null, function(){}, undefined, null, null,  /x/ , null, null,  /x/ , null, null, function(){}, null, undefined, null,  /x/ , function(){}, null, undefined, null, undefined,  /x/ , undefined, null, function(){}, undefined, undefined, undefined, null, function(){},  /x/ ,  /x/ , null, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, null, undefined,  /x/ , function(){}, null,  /x/ , undefined,  /x/ , undefined, null, null, undefined, null, function(){}, null, null,  /x/ ,  /x/ , function(){}, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, undefined, null,  /x/ , undefined, null, null, undefined,  /x/ , function(){}, null,  /x/ , null]); ");
/*fuzzSeed-94431925*/count=1229; tryItOut("\"use strict\"; while((w) && 0)print(this);");
/*fuzzSeed-94431925*/count=1230; tryItOut("let(d) ((function(){\u3056 = c;})());return;");
/*fuzzSeed-94431925*/count=1231; tryItOut("g0 = this;");
/*fuzzSeed-94431925*/count=1232; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( - Math.fround((( + Math.trunc(( - ( + y)))) && (Math.acos(Math.fround(Math.imul(Math.fround(( + Math.min(1/0, x))), Math.fround(Math.fround(((x | 0) ** ( + ( + mathy0(( + x), (Math.PI | 0)))))))))) | 0))))); }); testMathyFunction(mathy2, [0x100000000, -1/0, -(2**53), Number.MAX_VALUE, -0, -Number.MIN_VALUE, Math.PI, 2**53, 42, 0.000000000000001, 1, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, -(2**53+2), 0/0, -0x100000001, -0x0ffffffff, -Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 0, -(2**53-2), 1.7976931348623157e308, 2**53+2, -0x080000000, 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-94431925*/count=1233; tryItOut("v1 = Object.prototype.isPrototypeOf.call(m2, g2);");
/*fuzzSeed-94431925*/count=1234; tryItOut("o2.a1 = Array.prototype.filter.call(a2, (function() { for (var j=0;j<72;++j) { g2.f0(j%5==1); } }), o1.t1);");
/*fuzzSeed-94431925*/count=1235; tryItOut("/*RXUB*/var r = o2.r0; var s = \" \\uf1fd1 a\"; print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=1236; tryItOut("\"use strict\"; L:switch(new (x)().__defineSetter__(\"x\", (let (e=eval) e))) { case 6: /*tLoop*/for (let a of /*MARR*/[-0, NaN, {}, -0, -0, function(){}, NaN, function(){}, function(){}, function(){}, NaN, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, NaN, {}, -0, NaN, {}, NaN, function(){}, function(){}, function(){}, -0, {}, function(){}, NaN, {}, {}, {}, {}, {}, -0, -0, {}, {}, -0, NaN, {}, function(){}, function(){}, {}, function(){}, {}, -0, -0, function(){}, function(){}, function(){}, function(){}, NaN, function(){}, {}, function(){}, function(){}, function(){}, NaN, function(){}, -0]) { v2 = (o1 instanceof f0); }break; i1.__iterator__ = (function() { try { a2 = []; } catch(e0) { } try { m0 + ''; } catch(e1) { } v2 = new Number(0); return t1; });\n/*MXX3*/g1.g0.Math.asinh = g0.Math.asinh;\nbreak; break;  }");
/*fuzzSeed-94431925*/count=1237; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.atan2((mathy1(Math.tan(( ~ y)), Math.acos((y ? x : (Math.clz32(((( ! y) | 0) >>> 0)) >>> 0)))) >>> 0), Math.fround(mathy3(( ! ((x + (( + (( + x) | 0)) | 0)) >>> 0)), Math.fround(( + Math.acos(( + ( ~ Math.fround(( + Math.ceil(( + Math.imul((x == y), 1.7976931348623157e308))))))))))))); }); testMathyFunction(mathy5, [-(2**53), 2**53-2, -0, 0x080000001, -1/0, 0.000000000000001, 0x0ffffffff, -0x100000000, 2**53, 2**53+2, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 42, Math.PI, -0x080000000, -(2**53-2), -(2**53+2), -0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 1, 0x100000000, 1/0, 0x07fffffff, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1238; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.min(Math.fround(( + mathy0(( + (((Math.acos((y >>> 0)) | 0) ? ( + (( + (Math.atan2(x, ( + y)) >>> 0)) + ( + y))) : ( + (( + y) - y))) | ( - (y ? x : Number.MIN_SAFE_INTEGER)))), (((Math.fround((((( ~ (Math.abs(y) | 0)) | 0) >>> 0) > (mathy0((x | 0), (0x07fffffff >>> 0)) | 0))) | 0) ? (x | 0) : (Math.max(y, (Math.log((x >>> 0)) >>> 0)) | 0)) | 0)))), Math.fround(Math.log1p((Math.fround(mathy0(((( ! ( ~ Math.max(x, x))) >>> 0) >>> 0), (( + Math.min(( + Math.log10(y)), (x | 0))) >>> 0))) >>> 0))))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0x080000001, -0x080000000, Number.MIN_VALUE, 0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, Number.MAX_VALUE, -(2**53-2), 2**53+2, 1, 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, 0, -0, -1/0, -(2**53), 0.000000000000001, -(2**53+2), 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, -0x100000001, 0x100000000, 2**53]); ");
/*fuzzSeed-94431925*/count=1239; tryItOut("s1 = this.s2.charAt(x);");
/*fuzzSeed-94431925*/count=1240; tryItOut("M:switch(x) { default:  }");
/*fuzzSeed-94431925*/count=1241; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1242; tryItOut("mathy5 = (function(x, y) { return (mathy2(Math.fround(( + (( + Math.fround(Math.hypot(Math.fround(Math.fround(( - Math.fround(( ~ ( - y)))))), x))) >>> ( + Math.min(mathy1((x != (Math.fround(((0x080000000 >>> 0) % ( + 0/0))) >>> 0)), (-0x100000001 >>> 0)), (y + ( + Math.hypot(( + 2**53+2), ( + y))))))))), ((((( - -0x100000000) | 0) % ( + ((y | 0) && ((0x080000000 && ( ~ ( + y))) | 0)))) | 0) < (((( + x) | ( + (( ~ (Math.ceil(y) >>> 0)) >>> 0))) >>> 0) | 0))) | 0); }); testMathyFunction(mathy5, [0x100000001, 2**53, 0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, -0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 1, 0.000000000000001, -0x07fffffff, -0x100000001, 1/0, 2**53-2, 0x07fffffff, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 0x080000001, -0x080000000, -0x0ffffffff, -(2**53+2), -0x080000001, Number.MAX_SAFE_INTEGER, 42, 0x080000000, 1.7976931348623157e308, 0x100000000, -(2**53-2), -1/0, -Number.MIN_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=1243; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((+(~~(-4611686018427388000.0))));\n  }\n  return f; })(this, {ff: Map.prototype.get}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [42, Number.MIN_VALUE, -0x080000001, 0x0ffffffff, 2**53+2, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, 0x100000000, 0x07fffffff, -0x080000000, -0, 0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, Math.PI, 0x100000001, Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, 2**53, -(2**53), -0x100000001, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1244; tryItOut("\"use strict\"; let(a) ((function(){for(let w of ( \"\"  + true if (a))) for(let c in (void options('strict'))) yield;})());L:if((x % 47 != 19)) o2.v2 = (g2 instanceof g1); else  if (x) {print( /x/g );this.g2.offThreadCompileScript(\"function f0(this.o2) \\\"use asm\\\";   var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = -1.125;\\n    var d3 = -9.0;\\n    {\\n      d3 = (8193.0);\\n    }\\n    return (((((((Int16ArrayView[((i1)-((0x0))-(i0)) >> 1]))+((((!(-0x8000000)))>>>((((0xffffffff) ? (15.0) : (18014398509481984.0)))))))>>>((0xfe5c1435))))+(0xffffffff)))|0;\\n  }\\n  return f;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 8 == 3), sourceIsLazy: false, catchTermination: (x % 2 != 0) })); } else {(window); }");
/*fuzzSeed-94431925*/count=1245; tryItOut("o2.o1.s1.toSource = (function mcc_() { var jtahvp = 0; return function() { ++jtahvp; if (/*ICCD*/jtahvp % 11 == 7) { dumpln('hit!'); try { e1.delete(p0); } catch(e0) { } f2(b2); } else { dumpln('miss!'); try { o1.f1 + ''; } catch(e0) { } Array.prototype.splice.call(a2, NaN, v1, Array.prototype.fill(((Object.prototype.__lookupGetter__)(Math.pow(-23, y))), (/*RXUE*/new RegExp(\"(?!(?:(?:\\\\1{0,})))|^?\", \"gy\").exec(\"\"))), f0); } };})();");
/*fuzzSeed-94431925*/count=1246; tryItOut("mathy1 = (function(x, y) { return (( + Math.atan2(Math.fround((((Math.fround(Math.min(( - y), Math.fround(x))) >>> 0) == ( + ( - y))) >> (Math.imul(( - x), Math.clz32(Math.fround(-0x080000000))) << y))), ( ~ (Math.fround(Math.atan2(Math.fround(Math.max(1.7976931348623157e308, Math.fround(y))), Math.fround(( ~ x)))) >>> 0)))) | 0); }); testMathyFunction(mathy1, /*MARR*/[new String('q'), new String('q'), false, false, ['z'], ['z'], new String('q')]); ");
/*fuzzSeed-94431925*/count=1247; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.max(( ! ( + ( + (Math.imul(0.000000000000001, Math.fround(Math.pow(Math.fround(Math.atan2(Math.fround(y), (x >>> 0))), y))) ? ( + Math.fround((Math.fround(Math.atan2(Math.imul(-(2**53-2), y), Math.log2((x >>> 0)))) * Math.fround(( + Math.hypot(( + Math.fround(Math.exp(Math.fround(y)))), ( + x))))))) : ( + Math.imul((y , y), Math.sqrt(Math.fround(-Number.MIN_SAFE_INTEGER)))))))), (((((((x | 0) + Math.fround(mathy1(Math.fround(( + (( + x) | ( + y)))), Math.fround(y)))) >>> 0) === (x < (Math.fround(( - -Number.MIN_SAFE_INTEGER)) >> mathy0(2**53-2, y)))) >>> 0) * mathy0((Math.fround((x >>> 0)) >>> 0), Math.atan2((Math.max((x | 0), (y | 0)) | 0), Math.max(y, x)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-94431925*/count=1248; tryItOut("\"use strict\"; print(((void shapeOf(x)).throw(x)));");
/*fuzzSeed-94431925*/count=1249; tryItOut("\"use strict\"; /*hhh*/function deetfi(){throw  /x/g ;}/*iii*/Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-94431925*/count=1250; tryItOut("(\"\\u4B48\");z =  /x/ ;");
/*fuzzSeed-94431925*/count=1251; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(mathy1(x, x), (y >>> x)) ? ( + ( ~ Math.acos(( + Math.hypot(((( ~ Math.fround(Math.fround(Math.imul(Math.fround(y), y)))) | 0) | 0), x))))) : ((Math.imul(Math.max((y ? x : x), 0x100000001), ((x ? (( ! y) >>> 0) : Math.fround(y)) - -Number.MIN_SAFE_INTEGER)) >>> 0) / (((y >>> 0) && Math.max(mathy1(Math.imul(y, Math.atan2(-Number.MIN_SAFE_INTEGER, x)), y), Math.atan(x))) >>> 0))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0.000000000000001, 0x07fffffff, 0x100000001, 1, 1.7976931348623157e308, -0x080000001, -0x080000000, -0x100000001, -0, Number.MIN_VALUE, 0x080000000, 0, 0x100000000, -0x07fffffff, 0/0, 2**53+2, -(2**53-2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, -(2**53), 42, 0x080000001, 2**53, 1/0, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=1252; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, false, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, x, {x:3}, false, false, false, x, {x:3}, false, x, x, x, false, false, {x:3}, {x:3}, x, x, false, x, x, {x:3}, {x:3}, false, {x:3}, false, false, {x:3}, false, false, false, false, false, {x:3}, false, false, {x:3}, x, false, false, {x:3}, false, x, false, false, {x:3}]) { var snhuij = new ArrayBuffer(0); var snhuij_0 = new Float32Array(snhuij); print(snhuij_0[0]); snhuij_0[0] = -6; var snhuij_1 = new Int8Array(snhuij); print(snhuij_1[0]); snhuij_1[0] = -8; a2 = new Array; }");
/*fuzzSeed-94431925*/count=1253; tryItOut("/*RXUB*/var r = new RegExp(\"(?:z|(?![^]))\\\\2{2,}\", \"gi\"); var s = \"zaza\"; print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=1254; tryItOut("\"use strict\"; b2 = new ArrayBuffer(40);function x()\"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (0x42f826a7);\n    return +(((-147573952589676410000.0) + (((+pow(((((+abs(((-68719476737.0))))) * ((-562949953421313.0)))), ((Float64ArrayView[0]))))) * ((-(x))))));\n  }\n  return f;m0.set(o2, v0);");
/*fuzzSeed-94431925*/count=1255; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 2.3611832414348226e+21;\n    var d4 = 7.737125245533627e+25;\n    var d5 = 4398046511103.0;\n    var d6 = -6.189700196426902e+26;\n    var d7 = 9.671406556917033e+24;\n    return (((void options('strict_mode'))))|0;\n    d7 = (+pow(((Infinity)), ((d4))));\n    d7 = (+atan2(((-36893488147419103000.0)), ((Float64ArrayView[((0xdab489ec)+(0xfd790d76)+(!(0xffffffff))) >> 3]))));\n    return ((-0x47c79*((0x0))))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return ( + ((y > y) ** y)); })}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [1.7976931348623157e308, 0, 0x100000001, -(2**53), -0x080000000, 0x0ffffffff, 0x07fffffff, 0x100000000, -0x100000001, 2**53+2, 2**53, -0x100000000, -(2**53-2), 0/0, -Number.MIN_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 42, -0, 0x080000001, Number.MAX_VALUE, -(2**53+2), -0x080000001, 1/0, -1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 1, -Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001]); ");
/*fuzzSeed-94431925*/count=1256; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.imul(( + Math.hypot((y === ( ! (y > x))), (-0x080000000 >>> 0))), (( ! ((Math.atanh((Math.fround(( ~ (( + Math.exp(( + (( ! x) >>> 0)))) >>> 0))) | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [[], (new Boolean(false)), true, (new Boolean(true)), '\\0', '', ({valueOf:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), [0], /0/, '/0/', 0, (function(){return 0;}), NaN, '0', (new Number(0)), undefined, 0.1, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), 1, false, (new String('')), null, -0]); ");
/*fuzzSeed-94431925*/count=1257; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.imul(Math.fround(Math.fround(( ~ Math.trunc(Math.fround(y))))), Math.imul((( + ( + ( + ( + (( + Math.max(Math.asin(x), -(2**53+2))) ? ( + (x * y)) : ( + Math.max(y, 2**53+2))))))) ? (x == x) : Math.sign(x)), Math.min(x, (Math.min((( ~ ( - y)) | 0), Math.fround((Math.atan((-0x080000001 >>> 0)) >>> 0))) | 0))))); }); testMathyFunction(mathy4, [-(2**53-2), 0x100000001, 2**53+2, 42, Number.MAX_SAFE_INTEGER, 2**53-2, 0, -0x080000001, -0x100000001, Number.MIN_VALUE, -1/0, 0x100000000, -Number.MIN_VALUE, -(2**53+2), 0x080000000, -0x100000000, -0x0ffffffff, -0x080000000, 1, 0x080000001, -0x07fffffff, 0.000000000000001, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, 0/0, 0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1258; tryItOut("\"use strict\"; print(\"\u03a0\");\n\n");
/*fuzzSeed-94431925*/count=1259; tryItOut("\"use strict\"; {/*RXUB*/var r = g0.r2; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u581b\\n\\u581b\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u581b\\n\\u581b\"; print(s.match(r)); print(r.lastIndex); /*RXUB*/var r = new RegExp(\"(?!(?=(?=.)\\\\W|(?=.).*|^*\\\\1*?)){0,2}\", \"gyi\"); var s = \"\"; print(uneval(s.match(r)));  }");
/*fuzzSeed-94431925*/count=1260; tryItOut("i0 + '';");
/*fuzzSeed-94431925*/count=1261; tryItOut("\"use strict\"; var uxzovp = new ArrayBuffer(0); var uxzovp_0 = new Float32Array(uxzovp); uxzovp_0[0] = 25;  /x/ ;m0 = new Map;");
/*fuzzSeed-94431925*/count=1262; tryItOut("mathy4 = (function(x, y) { return ( + ( ~ ( + Math.sinh(((((mathy3(Number.MAX_VALUE, Math.max(y, x)) >>> 0) >= (y >>> 0)) >>> 0) ^ Math.atan(-0x080000000)))))); }); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-94431925*/count=1263; tryItOut("\"use strict\"; /*RXUB*/var r = /((?=((?:.){1}))){4,8}\\b{1}/gim; var s = \"\"; print(s.replace(r,  /* Comment */s)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1264; tryItOut("t1.set(a0, 1);function x()\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    {\n      i0 = (i2);\n    }\n    return (((1)-(!(i3))))|0;\n  }\n  return f;");
/*fuzzSeed-94431925*/count=1265; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot(((Math.atan(Math.atan2((Math.min(((( + 0/0) > ( + x)) >>> 0), (x >>> 0)) >>> 0), y)) >>> 0) ? ((( - x) | 0) >>> 0) : ( + Math.exp((Math.atan2((0x07fffffff | 0), (( ! y) >>> 0)) | 0)))), ( + Math.log1p(Math.log2(y)))) | 0); }); testMathyFunction(mathy0, [-0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -1/0, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 0x100000001, 0x100000000, 0x080000001, -0x0ffffffff, 1, 2**53, 42, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 0x07fffffff, 1/0, 0.000000000000001, 0x0ffffffff, 2**53+2, -0x080000001, -0x080000000, 0, -0, -(2**53), 0x080000000, 0/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1266; tryItOut("e1 = new Set(i0);");
/*fuzzSeed-94431925*/count=1267; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.ceil(Math.cbrt(((Math.fround(( - ( + y))) | 0) >= Math.atan2(( + (( + Math.pow(Math.fround(y), ( + 2**53+2))) << y)), Math.fround(x))))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0x100000000, Math.PI, 0x080000001, -0, -0x080000001, 2**53, -0x100000001, -Number.MIN_VALUE, -1/0, 2**53-2, 0.000000000000001, 1/0, -(2**53-2), 0x080000000, -0x100000000, 0, Number.MAX_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -(2**53+2), 0x0ffffffff, 0x07fffffff, 0/0, 42, 1, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -0x07fffffff, 0x100000001, -(2**53)]); ");
/*fuzzSeed-94431925*/count=1268; tryItOut("for (var p in e0) { try { Object.seal(i2); } catch(e0) { } try { t1[(yield x)] =  '' ; } catch(e1) { } try { Array.prototype.splice.call(o2.a0, NaN, 13, b2, t2); } catch(e2) { } ; }");
/*fuzzSeed-94431925*/count=1269; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow((Math.fround(Math.hypot(Math.fround(( - Math.round(mathy0(( ~ -Number.MAX_VALUE), y)))), Math.fround(Math.sqrt(( + Math.tanh((y >>> 0))))))) >>> 0), ( + ( ! (((( ! (( + mathy0(y, y)) | 0)) >>> 0) ? Number.MAX_VALUE : ((Math.max(Math.fround(x), Math.fround(x)) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [[0], 0.1, (function(){return 0;}), /0/, '\\0', NaN, (new Boolean(false)), 1, '/0/', (new Boolean(true)), [], null, (new String('')), '', objectEmulatingUndefined(), undefined, ({valueOf:function(){return 0;}}), true, 0, false, (new Number(-0)), ({toString:function(){return '0';}}), (new Number(0)), '0', -0, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-94431925*/count=1270; tryItOut("\"use strict\"; /*RXUB*/var r = /O|\\b.{3}|(?!(?!\\B|$?))/m; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); /*infloop*/do t0 = t0.subarray(v1, 13); while(w += \u3056);");
/*fuzzSeed-94431925*/count=1271; tryItOut("a0 = /*FARR*/[c <  \"\"  * x.yoyo(((Math.log1p(25)) >>= arguments)), .../*MARR*/[ /x/ , function(){}, (0/0), (0/0),  /x/ , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (0/0), function(){}, (0/0),  /x/ , function(){}, function(){},  /x/ , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/ , (0/0), (0/0), (0/0), (0/0), function(){}, function(){},  /x/ , function(){}, function(){},  /x/ , function(){},  /x/ , function(){},  /x/ , (0/0), (0/0),  /x/ , function(){}, (0/0), (0/0), function(){}, (0/0),  /x/ , (0/0),  /x/ , (0/0),  /x/ , (0/0),  /x/ , (0/0),  /x/ , function(){}, function(){}, (0/0), function(){}, function(){}, function(){}, function(){},  /x/ , (0/0), function(){}, function(){},  /x/ ,  /x/ ,  /x/ , (0/0),  /x/ , function(){}, function(){}, (0/0), function(){}, (0/0), function(){},  /x/ ,  /x/ , (0/0),  /x/ ,  /x/ ,  /x/ , function(){}, function(){}, (0/0), function(){}, (0/0),  /x/ , (0/0),  /x/ , (0/0), function(){}, (0/0), function(){}, (0/0), function(){}, function(){}, (0/0), function(){}, (0/0), function(){}, function(){}, (0/0), function(){},  /x/ ,  /x/ , function(){},  /x/ , (0/0)], x, ( ) = (/*UUV1*/(NaN.stringify = \"\\uC4B0\"))];");
/*fuzzSeed-94431925*/count=1272; tryItOut("i0.next();");
/*fuzzSeed-94431925*/count=1273; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 3.0;\n    var d6 = 36893488147419103000.0;\n    return +((+pow(((+(((i1)) >> (0x7da5c*(0x7ce7ec16))))), ((+((((Infinity) < (+(1.0/0.0))))>>>((0xff42148c)+(i2))))))));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var jffsbi = ((function factorial_tail(ahwudl, yftisa) { return  /x/g ;; if (ahwudl == 0) { ; return yftisa; } ; return factorial_tail(ahwudl - 1, yftisa * ahwudl); print(x); })(3, 1)); var rmlkfk = Date.now; return rmlkfk;})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53+2), 1, 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 0x080000001, 2**53+2, -0x080000001, Math.PI, -0x0ffffffff, 1.7976931348623157e308, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), 42, -(2**53-2), -0x100000000, 2**53, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, -0x100000001, 0.000000000000001, 0x080000000, 0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, -0x07fffffff, 0, -Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-94431925*/count=1274; tryItOut("for (var v of b2) { try { function f2(s0) \"\\u6F69\" } catch(e0) { } Object.preventExtensions(o2.t0); }\nt1 = new Uint8Array(v0);\n");
/*fuzzSeed-94431925*/count=1275; tryItOut("selectforgc(o1);");
/*fuzzSeed-94431925*/count=1276; tryItOut("mathy3 = (function(x, y) { return (mathy0((Math.max(Math.acosh(Math.fround(Math.exp(Math.hypot(( + Math.fround(( - Math.fround(x)))), x)))), (mathy0(((x | 0) && mathy2((x >>> 0), (-0x080000001 >>> 0))), ((( + (x >>> 0)) >>> 0) >>> 0)) >>> 0)) | 0), (( + ( + Math.fround(( + Math.pow((Math.fround(Math.pow(Number.MAX_SAFE_INTEGER, x)) & ( - y)), (y >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy3, [false, (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Number(0)), true, 0.1, undefined, (new Boolean(true)), /0/, NaN, null, (new Number(-0)), (new String('')), '/0/', ({toString:function(){return '0';}}), '', -0, '\\0', 0, [], '0', 1, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (new Boolean(false)), [0]]); ");
/*fuzzSeed-94431925*/count=1277; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! mathy1((( + (( ~ x) >> ( ! ( - ( + 42))))) | 0), (Math.exp((( + Math.round(((((y | 0) << x) | 0) | 0))) | 0)) | 0))); }); testMathyFunction(mathy5, [(function(){return 0;}), false, '', objectEmulatingUndefined(), 0, -0, null, (new String('')), '/0/', true, [0], '\\0', ({toString:function(){return '0';}}), /0/, ({valueOf:function(){return '0';}}), undefined, (new Boolean(false)), 0.1, (new Boolean(true)), '0', [], 1, ({valueOf:function(){return 0;}}), (new Number(0)), NaN, (new Number(-0))]); ");
/*fuzzSeed-94431925*/count=1278; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.imul(Math.fround((mathy0((( + Math.asin(((Math.ceil((2**53+2 >>> 0)) >>> 0) >>> 0))) >>> 0), (Math.fround(Math.atan2(Math.fround(Math.fround(((x >>> 0) | ( + Math.trunc((y >>> 0)))))), ( + ( + Math.fround(( ! y)))))) >>> 0)) >>> 0)), Math.fround(Math.atan((( - ((x ? (Math.imul(y, x) | 0) : ((Math.log1p((x >>> 0)) | 0) | 0)) ? Math.pow(Math.fround(Math.min(y, x)), Math.fround(x)) : (y + Math.fround(x)))) | 0)))) | 0); }); testMathyFunction(mathy3, [0x07fffffff, -0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 1.7976931348623157e308, -0x07fffffff, -(2**53), 0, -Number.MIN_VALUE, 1/0, 2**53, Number.MAX_VALUE, -(2**53+2), -1/0, -0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, 42, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000001, 1, -0, 0x100000000, 2**53+2, -0x100000000, -0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 0x100000001]); ");
/*fuzzSeed-94431925*/count=1279; tryItOut("print(x = (/*wrap1*/(function(){ f0.__iterator__ = (function(j) { if (j) { try { p0 + t2; } catch(e0) { } try { h0 = {}; } catch(e1) { } try { b1.__proto__ = o2.v1; } catch(e2) { } for (var v of a2) { try { m0.set(t2, i2); } catch(e0) { } try { g1.a0.splice(NaN, 17); } catch(e1) { } m1.get(e2); } } else { v0 = g1.eval(\"v2 = (b0 instanceof v1);\"); } });return Date.prototype.setUTCSeconds})()).call( \"\" , x = \"\\u0472\",  /x/ ));");
/*fuzzSeed-94431925*/count=1280; tryItOut("\"use strict\"; v2 = (g1.h0 instanceof o2);");
/*fuzzSeed-94431925*/count=1281; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy1((((Math.fround(Math.hypot(Math.fround((y , Math.hypot(( - x), x))), Math.max(y, mathy2(Math.fround(Math.imul(Math.fround(x), x)), Math.max(y, -0x080000001))))) >>> 0) , (( ~ ((Math.hypot((x - y), ( ~ (((x ? Number.MAX_SAFE_INTEGER : y) * (Number.MAX_SAFE_INTEGER | 0)) | 0))) >>> 0) | 0)) >>> 0)) >>> 0), ( + (Math.atan2(Math.hypot((x >>> 0), ( + ( ! Math.fround(( + (x | 0)))))), ((mathy1(-(2**53+2), y) >>> 0) >= (mathy2(y, y) === (mathy1((x >>> 0), (Math.max(0x07fffffff, (-0x080000000 | 0)) >>> 0)) >>> 0)))) >>> 0))) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[2, 2, function(){}, function(){}, 2, 2, 2, function(){}]); ");
/*fuzzSeed-94431925*/count=1282; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.pow(( + (( - (Math.exp((y | 0)) | 0)) + Math.fround(Math.atan2((y | 0), y)))), Math.pow(Math.trunc(Math.fround(x)), (((((( ! Math.fround(1/0)) | 0) | 0) == Math.atan2(x, y)) >>> 0) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, 2**53+2, Number.MIN_VALUE, -0x100000000, 0.000000000000001, 0x080000001, 0x100000000, 0x080000000, 1/0, -0, -0x080000000, -0x100000001, 0x0ffffffff, -(2**53), -0x0ffffffff, -0x07fffffff, -(2**53-2), -Number.MAX_VALUE, 1, 0x07fffffff, -1/0, Number.MAX_VALUE, -0x080000001, 42, -(2**53+2), 0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, 2**53, Math.PI]); ");
/*fuzzSeed-94431925*/count=1283; tryItOut("/*ADP-2*/Object.defineProperty(a0, 11, { configurable: false, enumerable: (x % 10 != 0), get: (function() { try { a0.splice(NaN, 10); } catch(e0) { } try { o1.v0 = new Number(s1); } catch(e1) { } e0.add(p0); return i2; }), set: o0.f2 });a0 = arguments;");
/*fuzzSeed-94431925*/count=1284; tryItOut("\"use strict\"; ;");
/*fuzzSeed-94431925*/count=1285; tryItOut(" for  each(a in (4277)) for (var v of t2) { try { /*MXX1*/let o2 = g1.WeakMap.name; } catch(e0) { } g2.toString = (function() { for (var j=0;j<14;++j) { f0(j%2==0); } }); }");
/*fuzzSeed-94431925*/count=1286; tryItOut("x, x = x, e, x =  '' ;f2 + '';");
/*fuzzSeed-94431925*/count=1287; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      {\n        i1 = (!(i2));\n      }\n    }\n    i2 = (0xb0aac43c);\nf2(p2);    i0 = ((Float64ArrayView[(((imul(((((i0))|0)), (i2))|0))+((((i1))>>>((!((((0xf8c6c4ee))>>>((0x8f66bbc8))) != (((0xfa991190))>>>((-0x8000000))))))))) >> 3]));\n    return (((-0x8000000)))|0;\n    i0 = ((~((((((0x10bc563f) != (0x6d2216fd))*-0xfcb4a)>>>(((0xfc76269d) ? (0xfa86a6e8) : (0x6a4ea241))-(i2))))-(i0)+(i2))) == ((((((/*FFI*/ff(((-17592186044415.0)), ((549755813889.0)), ((-1.1805916207174113e+21)), ((-34359738369.0)), ((-6.044629098073146e+23)))|0))>>>((0xbb31b6d5)*0xc54ef)))-(i1)-(/*FFI*/ff(((+(1.0/0.0))), ((4277)), ((9.44473296573929e+21)), ((-295147905179352830000.0)))|0)) | (((~(((((-0x8000000)) >> ((0x79358b11))))+(i2))) > (abs((~~(+(-1.0/0.0))))|0)))));\n    return (((i2)*0x549ec))|0;\n  }\n  return f; })(this, {ff: ((function(x, y) { return -(2**53); })).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0, 1/0, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 1, 2**53, 0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, -0x100000001, 42, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, -(2**53+2), 0/0, 0.000000000000001, 0x100000001, -0x0ffffffff, -0x080000000, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, 1.7976931348623157e308, -1/0, 2**53+2, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-94431925*/count=1288; tryItOut("testMathyFunction(mathy0, [(new Boolean(false)), '0', ({valueOf:function(){return '0';}}), (new Number(0)), [0], undefined, [], false, objectEmulatingUndefined(), /0/, 1, '/0/', ({toString:function(){return '0';}}), (new Boolean(true)), (function(){return 0;}), -0, 0.1, (new Number(-0)), NaN, '\\0', ({valueOf:function(){return 0;}}), (new String('')), null, '', true, 0]); ");
/*fuzzSeed-94431925*/count=1289; tryItOut("mathy2 = (function(x, y) { return ( + Math.tanh(( + (Math.hypot(((((mathy1(Math.fround(mathy1(Math.fround((0x0ffffffff / -0x07fffffff)), Math.fround(x))), y) | 0) ? Math.fround(((y ? (0x100000001 | 0) : (x | 0)) | 0)) : y) | 0) >>> 0), (mathy0((Math.expm1(Math.hypot(y, (y >>> 0))) >>> 0), (( + y) | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), 1/0, 0x100000000, -(2**53-2), 2**53, -0x100000000, 2**53-2, -0, 1, 1.7976931348623157e308, -(2**53), 0/0, 0x080000001, 0x100000001, 0, -0x0ffffffff, 2**53+2, Number.MIN_VALUE, -0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, Math.PI, Number.MAX_VALUE, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1290; tryItOut("this.o2.a0.length = 10;");
/*fuzzSeed-94431925*/count=1291; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!\\\\2\\\\2+.|\\\\2*$)\", \"\"); var s = /^/gyi; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1292; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1293; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return Math.imul((( ~ ((( + ((Math.log2((x << x)) ? 0.000000000000001 : (Math.atan2((x >>> 0), Math.fround((Math.fround(Math.min(Math.fround(-(2**53)), Math.fround(y))) < x))) >>> 0)) | 0)) | 0) | 0)) | 0), Math.atan2((Math.hypot((Math.trunc(( ! Math.max(-0x080000000, x))) | 0), (Number.MIN_SAFE_INTEGER ? x : x)) | 0), Math.atan2((Math.abs(-Number.MAX_SAFE_INTEGER) * y), (((( ~ x) >>> 0) ? (x >>> 0) : (Math.pow((((y >>> 0) == ( + x)) >>> 0), (x < y)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [Math.PI, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0, -(2**53+2), 0x0ffffffff, -0x080000001, 0x080000000, 0.000000000000001, 42, 0, -0x100000001, -0x100000000, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 0/0, 0x100000001, -0x080000000, 1, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), -Number.MAX_VALUE, -0x07fffffff, 2**53-2, -1/0, 0x07fffffff, 2**53+2]); ");
/*fuzzSeed-94431925*/count=1294; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\nprint(x);    return (((i0)-((0x365baaff) <= (0x840b77c8))))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; s1 = '';; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [1.7976931348623157e308, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 1/0, 2**53+2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -(2**53+2), 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -0x080000000, 0/0, 0x100000000, 1, 2**53, 2**53-2, -Number.MAX_VALUE, -1/0, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 42, -0, Math.PI, -(2**53-2), 0, -0x100000000, 0x100000001]); ");
/*fuzzSeed-94431925*/count=1295; tryItOut("\"use strict\"; if(true) {g2 + f2;v2 = evaluate(\"function f2(a0)  { \\\"use strict\\\"; return d } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (void version(185)), sourceIsLazy: (x % 38 == 29), catchTermination: true })); } else  if (new null.throw(x)(\u000d({ set 2(x, \u3056 = this) { \"\\u1B59\"; } , \"463602225\": \n \"\"  }), Math.imul( /x/g , -27))) v2 = a2.length;");
/*fuzzSeed-94431925*/count=1296; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atan(((((( ! Math.fround(Math.fround(( ! Math.fround(Math.atan2(( + x), -0x100000000)))))) >>> 0) <= (((Math.imul((Math.clz32(( + x)) >>> x), (Math.fround(Math.cos(Math.fround(y))) >= -0)) >>> 0) ? y : Math.max((x ? x : y), ((((Math.acosh((y >>> 0)) >>> 0) | 0) >= (x | 0)) | 0))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-94431925*/count=1297; tryItOut("testMathyFunction(mathy5, [0x080000000, Math.PI, Number.MIN_VALUE, -(2**53), 0x100000001, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, 0.000000000000001, 2**53, -0x0ffffffff, 0x100000000, 2**53+2, 0x07fffffff, -0x100000001, 0x080000001, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 42, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, -1/0, -(2**53+2), 1, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1298; tryItOut("this.v1 = g2.runOffThreadScript();");
/*fuzzSeed-94431925*/count=1299; tryItOut("o2.v1 + a1;\n/* no regression tests found */\n");
/*fuzzSeed-94431925*/count=1300; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(((Math.log1p(y) & ( + ( ~ (( + y) ? y : (x | 0))))) ? ((Math.asinh((Math.cbrt(Math.fround(y)) >>> 0)) >= ( ! (y | 0))) | 0) : Math.hypot(Math.fround((-(2**53+2) ? Math.fround(( + y)) : Math.fround(y))), (Math.log10((x >>> 0)) >>> 0))), (( + ( ! ( + y))) >> Math.fround(Math.tan(Math.fround(( + ((( + 1/0) / Math.fround((((y | 0) * (x | 0)) | 0))) >>> 0))))))); }); testMathyFunction(mathy1, [Math.PI, 0x080000001, 0x100000000, 1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, -(2**53), 1.7976931348623157e308, 1, 0/0, 0x080000000, 2**53+2, Number.MIN_VALUE, -(2**53-2), -1/0, 0x0ffffffff, -0x100000000, -0x080000001, -0x080000000, -Number.MIN_VALUE, 0x100000001, 2**53, -(2**53+2), 2**53-2]); ");
/*fuzzSeed-94431925*/count=1301; tryItOut("mathy3 = (function(x, y) { return Math.atan2(( + ( + (( ! ((Math.min((y | 0), (y | 0)) | 0) | 0)) | 0))), ( + ( ~ ( ! ( + mathy1(Math.imul(x, x), Math.max(Math.min((x | 0), ( - x)), -(2**53+2)))))))); }); ");
/*fuzzSeed-94431925*/count=1302; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 262145.0;\n    var d4 = 262145.0;\n    return (((0xc385e124)-(0x2d9fcf80)))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, new Number(1.5), 0xB504F332, new Number(1.5), 0xB504F332, new Number(1.5), new String(''), 0xB504F332, new String(''), new String(''), new Number(1.5), 0xB504F332, new Number(1.5), 0xB504F332, new String(''), 0xB504F332, 0xB504F332, new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), 0xB504F332, 0xB504F332, 0xB504F332, new String(''), new Number(1.5), new Number(1.5), new String(''), 0xB504F332, new Number(1.5), new String(''), 0xB504F332, new String(''), new String('')]); ");
/*fuzzSeed-94431925*/count=1303; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(Math.sign((Math.hypot(( ! ( + Math.max(( + x), (Math.PI | 0)))), (Math.min(y, y) | 0)) >>> 0)), (( + (( + (Math.min(y, x) << Math.fround(Math.trunc(x)))) >= (Math.sin(Math.fround(Math.asin(x))) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-94431925*/count=1304; tryItOut("t1.valueOf = (function(j) { if (j) { try { this.h1 = ({getOwnPropertyDescriptor: function(name) { v1 = (v2 instanceof g0);; var desc = Object.getOwnPropertyDescriptor(m0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { e2.toSource = f2;; var desc = Object.getPropertyDescriptor(m0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw v0; Object.defineProperty(m0, name, desc); }, getOwnPropertyNames: function() { Array.prototype.pop.call(this.a1, o0);; return Object.getOwnPropertyNames(m0); }, delete: function(name) { this.a2.pop(e0, a1);; return delete m0[name]; }, fix: function() { s2 += s1;; if (Object.isFrozen(m0)) { return Object.getOwnProperties(m0); } }, has: function(name) { Array.prototype.shift.call(a2, f0, this.t2, o1.o0.a2);; return name in m0; }, hasOwn: function(name) { throw this.i0; return Object.prototype.hasOwnProperty.call(m0, name); }, get: function(receiver, name) { h1 = t1[(delete e./(?:[^]{1,})|\\u0a9D*/gyi)];; return m0[name]; }, set: function(receiver, name, val) { a1[({valueOf: function() { let (a) {  for  each(let a in a) ( /x/g ); }return 13; }})] = (makeFinalizeObserver('nursery')) < b >  /x/  ? (void version(180)) : (void version(180));; m0[name] = val; return true; }, iterate: function() { Array.prototype.pop.apply(a2, []);; return (function() { for (var name in m0) { yield name; } })(); }, enumerate: function() { ;; var result = []; for (var name in m0) { result.push(name); }; return result; }, keys: function() { throw a1; return Object.keys(m0); } }); } catch(e0) { } a1 = /*FARR*/[.../*FARR*/[], .../*MARR*/[-(2**53), new Number(1), new Number(1), new Number(1), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), -(2**53), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), -(2**53), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), new Number(1), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), -(2**53), -(2**53), -(2**53), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), ([] = (new (z)((makeFinalizeObserver('nursery')), w ^= x))), new Number(1), new Number(1), -(2**53), new Number(1)], ...new Array(1), [, \u3056, ] = (4277)]; } else { try { e0.has(g0.v1); } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } a1.reverse(a1); } });");
/*fuzzSeed-94431925*/count=1305; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1306; tryItOut("a2[v2];");
/*fuzzSeed-94431925*/count=1307; tryItOut("mathy4 = (function(x, y) { return Math.atan2(( + mathy1(( + ( + Math.imul(( - ( + ( ! Math.abs(x)))), Math.max((( - x) >>> 0), ((Math.fround(y) >> x) >>> 0))))), (Math.imul(Math.fround(( ~ Math.fround((( - (x >>> 0)) >>> 0)))), ( + Math.ceil(Math.fround((Math.acosh(( + -0x07fffffff)) < 0))))) | 0))), ( ~ Math.fround(mathy3(( ! Math.pow((y | 0), (x | 0))), Math.ceil(x))))); }); testMathyFunction(mathy4, [2**53-2, -(2**53+2), 0x100000001, 2**53+2, 1, -(2**53-2), 0x080000001, -0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0, 0x100000000, 0.000000000000001, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 0, 42, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53), -0x080000000, -0x100000001, 2**53, Number.MAX_VALUE, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1308; tryItOut("\"use strict\"; v1.__iterator__ = (function(j) { if (j) { try { v2 = (o0.f1 instanceof m1); } catch(e0) { } print(uneval(v1)); } else { try { ; } catch(e0) { } o2.o1.v0 = g1.eval(\"let a = (void shapeOf(((function fibonacci(fjlxso) { ; if (fjlxso <= 1) { ; return 1; } ; return fibonacci(fjlxso - 1) + fibonacci(fjlxso - 2); print(window); })(4))));print(x);\"); } });");
/*fuzzSeed-94431925*/count=1309; tryItOut("i0 = new Iterator(h1, true);\nif(-19) {; } else  if ([]) {{} }\n");
/*fuzzSeed-94431925*/count=1310; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(mathy4(((( + Math.pow((x < 2**53-2), y)) / 2**53-2) * Math.fround(Math.acosh((( + ( - (( - y) >>> 0))) | 0)))), (Math.fround(Math.clz32((Math.max((y >>> 0), (y >>> 0)) >>> 0))) | 0)), Math.atan2((Math.max(0.000000000000001, (x >>> 0)) >>> 0), (Math.min(Math.fround(mathy2(-0x080000000, Math.fround(x))), (x >= y)) || ( - y))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 0x080000001, Number.MAX_VALUE, 1/0, -0x07fffffff, -0x100000001, 2**53-2, -0x100000000, -0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000000, 0/0, Number.MIN_VALUE, -(2**53+2), 0x100000001, 0x0ffffffff, 1, -1/0, 1.7976931348623157e308, -0x0ffffffff, 0, -Number.MIN_VALUE, 2**53, 0x080000000, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53), 42, 0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001]); ");
/*fuzzSeed-94431925*/count=1311; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + ( - (Math.fround(Math.imul(((Math.fround(x) ? Math.fround(( + (x | 0))) : Math.fround(x)) >>> 0), (x >>> 0))) >>> 0))) >>> 0); }); ");
/*fuzzSeed-94431925*/count=1312; tryItOut("/*RXUB*/var r = /(?!([^])){1}|..((?:\\s){17179869184,})(?!\\B)\\B\\W\\2\\d{4,}*?/yi; var s = \"oaoa000000\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1313; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.max(Math.fround(( - ( + Math.fround(( ~ (( ~ y) >>> 0)))))), Math.fround((( + x) << ( + mathy1(( + Math.clz32(Math.fround(x))), (( + (( + ( + Math.imul((mathy2(y, x) >>> 0), Math.fround(y)))) > ( + y))) >>> 0))))))); }); testMathyFunction(mathy4, [-1/0, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53), Math.PI, -0x100000001, -0, 42, 0, Number.MAX_VALUE, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, -(2**53+2), -(2**53-2), 0x080000001, 1/0, 0.000000000000001, -0x080000001, 0x0ffffffff, -0x100000000, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, 2**53+2, -0x080000000, 2**53, 0x100000001]); ");
/*fuzzSeed-94431925*/count=1314; tryItOut("\"use strict\"; o1.o1.g2.a2 = arguments;");
/*fuzzSeed-94431925*/count=1315; tryItOut("m1.delete(f1);");
/*fuzzSeed-94431925*/count=1316; tryItOut("/*infloop*/for(this += \"\\uFFCE\" << ({})(null) in ((WebAssemblyMemoryMode)(new Object.getOwnPropertyNames(x instanceof (/*FARR*/[].sort), x)))){v0 = (b2 instanceof p1);r1 = /\\3{0,}|\\t+/y; }");
/*fuzzSeed-94431925*/count=1317; tryItOut("print(uneval(h1));");
/*fuzzSeed-94431925*/count=1318; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0, h2, e0, s0, s2, g0.g0, i2);");
/*fuzzSeed-94431925*/count=1319; tryItOut("mathy2 = (function(x, y) { return new Boolean(/\\3/yim, d); }); testMathyFunction(mathy2, [0.000000000000001, -Number.MIN_VALUE, 42, Math.PI, 2**53-2, Number.MIN_VALUE, 1/0, 0x100000000, -0x100000000, 0x080000001, 0x100000001, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, 2**53, 0x07fffffff, -0x080000001, 0/0, 0, -0x100000001, 0x080000000, -0, -0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1320; tryItOut("mathy4 = (function(x, y) { return ( - Math.fround((Math.min((Math.log10(Math.cbrt(0.000000000000001)) >>> 0), ((( + ( ~ (x - (x >>> 0)))) !== ( + Math.fround(( + Math.fround(0x100000001))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [-0, '/0/', '0', (new Number(0)), null, false, 0.1, undefined, (function(){return 0;}), ({valueOf:function(){return '0';}}), [], (new Number(-0)), (new Boolean(true)), 1, NaN, ({toString:function(){return '0';}}), 0, '', true, objectEmulatingUndefined(), [0], ({valueOf:function(){return 0;}}), '\\0', (new Boolean(false)), /0/, (new String(''))]); ");
/*fuzzSeed-94431925*/count=1321; tryItOut("Object.prototype.watch.call(t0, \"toGMTString\", (function() { try { v2.toSource = (function() { try { p0 + f1; } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(a0, a2); return o1.i0; }); } catch(e0) { } try { e2.has(o0.a2); } catch(e1) { } try { t2[/*UUV1*/(d.has = function(q) { \"use strict\"; return q; })]; } catch(e2) { } o1.toSource = (function() { /*ADP-3*/Object.defineProperty(a2, ((/*MARR*/[true, new Boolean(false), true, new Boolean(false), true, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), true, new Boolean(false), true, true, true, new Boolean(false), true, new Boolean(false), new Boolean(false), true, true, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), true, new Boolean(false), true, new Boolean(false), true, true, true, true, new Boolean(false), true, true, true, new Boolean(false), true, true, new Boolean(false), true, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), true, true, true, true, new Boolean(false), true, true, new Boolean(false), new Boolean(false), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new Boolean(false), new Boolean(false), new Boolean(false), true, true, true, true, new Boolean(false), new Boolean(false), true, new Boolean(false), true, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), true, true, true, true, new Boolean(false), new Boolean(false)].some((new Function(\"19;\"))))( /x/g (/(?:(((?![^]))(?=[^])+?)+?)/y),  /x/  || x)), { configurable: (void shapeOf((function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      {\n        {\n          d1 = (d0);\n        }\n      }\n    }\n    return +((((0xf9866716)-(!(0x36b8b4d)))));\n  }\n  return f; }))), enumerable: false, writable: false, value: o0.m1 }); return v2; }); return i1; }));");
/*fuzzSeed-94431925*/count=1322; tryItOut("v0 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: ((eval = (/*UUV2*/(x.substring = x.from)))), noScriptRval: b, sourceIsLazy: false, catchTermination: (x % 57 != 32) }));");
/*fuzzSeed-94431925*/count=1323; tryItOut("with({z: ((undefined))})Object.prototype.unwatch.call(o1, new String(\"1\"));");
/*fuzzSeed-94431925*/count=1324; tryItOut("this.a2.reverse();");
/*fuzzSeed-94431925*/count=1325; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ Math.fround(( - Math.fround(( + ((((( ~ (x >>> 0)) | 0) ? (x | 0) : ((( + Math.max(x, 0x100000001)) , x) | 0)) | 0) ? ( + ( + ( - y))) : ( - ( + (( + (0/0 << -Number.MIN_VALUE)) ? x : y))))))))) | 0); }); testMathyFunction(mathy0, [1, -0x080000000, -(2**53), 0x100000000, 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0, -1/0, -0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, -(2**53-2), 42, 0x0ffffffff, 2**53, -0x080000001, 0, -Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, -0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, Math.PI, 2**53-2, 0/0, 0x080000001, -0x100000000]); ");
/*fuzzSeed-94431925*/count=1326; tryItOut("mathy5 = (function(x, y) { return (Math.imul(((Math.fround(((( + ( + ( + y))) >>> 0) || x)) | 0) || Math.asinh(((((x || ( + ( + -Number.MAX_VALUE))) >>> 0) & ( + ( ~ ((Math.log((y >>> 0)) >>> 0) >>> 0)))) >>> 0))), (mathy0((( ~ ( + ( - ((x !== x) | 0)))) | 0), (((((x << (Math.sinh(mathy1(Math.hypot((x >>> 0), (x >>> 0)), Math.fround(x))) >>> 0)) | 0) >>> ( + Number.MIN_SAFE_INTEGER)) | 0) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [0, (new Number(-0)), (new Boolean(true)), '', null, (new Boolean(false)), ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), /0/, undefined, ({toString:function(){return '0';}}), NaN, (function(){return 0;}), -0, (new Number(0)), 0.1, [], '/0/', true, objectEmulatingUndefined(), '\\0', '0', [0], false, 1, (new String(''))]); ");
/*fuzzSeed-94431925*/count=1327; tryItOut("\"use strict\"; testMathyFunction(mathy4, [2**53-2, -1/0, 1, -0x100000000, -Number.MIN_VALUE, -(2**53+2), -0x100000001, -(2**53), 0x0ffffffff, 42, 0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, 2**53, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0x080000001, 1.7976931348623157e308, 0x100000001, -0x07fffffff, -0x080000000, -0x080000001, -0x0ffffffff, Math.PI, Number.MIN_VALUE, -0, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1328; tryItOut("\"use strict\"; m1 = m2.get(b0);");
/*fuzzSeed-94431925*/count=1329; tryItOut("\"use strict\"; /*bLoop*/for (var fbvedc = 0; fbvedc < 111; ++fbvedc) { if (fbvedc % 3 == 0) { print(eval(\"/*RXUB*/var r = r2; var s = \\\"000_0\\\"; print(s.split(r)); \", [z1,,])); } else { print(x); }  } ");
/*fuzzSeed-94431925*/count=1330; tryItOut("testMathyFunction(mathy1, [Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, 0x100000001, 0x080000001, -0x100000000, 0.000000000000001, 2**53, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, -0, 2**53-2, Math.PI, -(2**53+2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 1/0, -(2**53-2), 2**53+2, -0x080000001, 0x080000000, 0x07fffffff, -0x080000000, -0x100000001, 0, 1]); ");
/*fuzzSeed-94431925*/count=1331; tryItOut("testMathyFunction(mathy5, [-(2**53), 0x07fffffff, 1/0, 42, Math.PI, Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, -0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, -0x100000000, -1/0, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1, 0.000000000000001, -0x0ffffffff, 0x100000000, 0x0ffffffff, -0x080000000, 0, -(2**53-2), 0x100000001]); ");
/*fuzzSeed-94431925*/count=1332; tryItOut("print(m2);");
/*fuzzSeed-94431925*/count=1333; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(e2, e2);");
/*fuzzSeed-94431925*/count=1334; tryItOut("v1 = Object.prototype.isPrototypeOf.call(this.o1.e1, f2);");
/*fuzzSeed-94431925*/count=1335; tryItOut("this.zzz.zzz;");
/*fuzzSeed-94431925*/count=1336; tryItOut("\"use strict\"; L:if(false) c = x;(\"\\u24A9\"); else  if ( /x/g .throw(window)) print(({a2:z2}));\nthis.h2.hasOwn = f1;\n else Array.prototype.pop.apply(a1, []);\nv0 = evalcx(\" \\\"\\\" \", this.g2.g2);\n");
/*fuzzSeed-94431925*/count=1337; tryItOut("\"use strict\"; a2.reverse(g1);");
/*fuzzSeed-94431925*/count=1338; tryItOut("h1.iterate = this.f0;");
/*fuzzSeed-94431925*/count=1339; tryItOut("Array.prototype.shift.call(this.a1, o0.o0.f0);");
/*fuzzSeed-94431925*/count=1340; tryItOut("/*tLoop*/for (let z of /*MARR*/[]) { x = linkedList(x, 960); }");
/*fuzzSeed-94431925*/count=1341; tryItOut("/*oLoop*/for (let cenhtu = 0; cenhtu < 28; ++cenhtu) { (/[\\W\\s\\w]*\\\u008b|$|[^]{0,2}[^]*(?=(?=J1|[^]|[^]|[^]))/); } ");
/*fuzzSeed-94431925*/count=1342; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((Infinity));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[null, null, null, null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, objectEmulatingUndefined()]); ");
/*fuzzSeed-94431925*/count=1343; tryItOut("a2 + g2.a1;");
/*fuzzSeed-94431925*/count=1344; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\\\u4c82|${0,}\", \"gym\"); var s = \"\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-94431925*/count=1345; tryItOut("print(x);");
/*fuzzSeed-94431925*/count=1346; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max(Math.hypot((Math.log1p((( + Math.fround(( ! Math.min(Number.MIN_VALUE, x)))) >>> 0)) >>> 0), (( ! ( + x)) | 0)), ( ~ ( + Math.expm1(Math.sin((y | 0)))))); }); testMathyFunction(mathy1, [-0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -0, -0x080000001, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 0x100000000, 2**53, 42, 1.7976931348623157e308, Number.MAX_VALUE, -1/0, -0x100000001, 1/0, 0x080000001, 0, 0x07fffffff, -Number.MIN_VALUE, 2**53-2, 0.000000000000001, 0x0ffffffff, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53-2), 0/0, 2**53+2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1347; tryItOut("print(uneval(v0));function d(d)\"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (+abs(((((NaN)) % (((+((d1))) + (32767.0)))))));\n    }\n    return (((1)))|0;\n    i0 = (((((0x16191943))+(i0))>>>(((imul((i0), ((((0x21a507e4)) >> ((0xfe213fbb)))))|0) <= (((i0)+(0x126d7c41)) & ((0x8edabe31)+(0xffffffff)-(0xfc70f22c))))+((this +  '' )))));\n    d1 = (Infinity);\n    {\n      i0 = (0x9fa4fba8);\n    }\n    return (((1)+(0xab1cb29f)+(0xb89619cd)))|0;\n  }\n  return f;/*RXUB*/var r = \"\\u5C2A\"; var s = \"\"; print(r.exec(s)); print(r.lastIndex); a = ((((void options('strict'))()).delete(x, new new RegExp(\"(?:[^]\\u00e4)|[]+?|(?=(?!(.){0,}|\\\\s+[\\\\x21\\u00f2-\\u1317\\\\xD0-N\\\\cJ-\\\\xE0]|.|\\\\b*?))\", \"g\")())))((([]) = /*UUV2*/(x.asinh = x.getDate)));");
/*fuzzSeed-94431925*/count=1348; tryItOut("v0 = x;");
/*fuzzSeed-94431925*/count=1349; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((Math.fround(Math.fround(( - (( ~ -0x080000001) >>> 0)))) <= Math.min((( ! (((( + ( - ( + y))) >>> 0) * (y >>> 0)) >>> 0)) | 0), (Math.min(Math.PI, (Math.acos((y | 0)) | 0)) | 0))) ** Math.max((mathy3(Math.fround(( ~ Math.fround(y))), Math.fround(Math.exp(x))) | 0), Math.fround(mathy0(Math.hypot(-0x080000001, y), x)))) ^ ( + Math.min((( + (( ! Math.atanh(y)) + ((x ? y : Number.MIN_VALUE) ^ x))) >>> 0), (mathy3(( - ( + Math.fround(Math.atan2(Math.fround(y), Math.fround((Math.hypot(Math.fround(y), x) >>> 0)))))), Math.fround(((((( + y) >= (x >>> 0)) >>> 0) | 0) >= (Math.fround(2**53-2) ** Math.fround(x))))) | 0)))); }); testMathyFunction(mathy4, [-(2**53), 1/0, 0x0ffffffff, 2**53+2, 0x080000001, 2**53-2, -Number.MAX_VALUE, 0x100000001, 1, 1.7976931348623157e308, 0x07fffffff, 0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, 2**53, -1/0, Number.MAX_VALUE, Number.MIN_VALUE, 42, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, -0x080000001, 0.000000000000001, 0, 0/0, -0, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=1350; tryItOut("\"use strict\"; b2 = t0.buffer;");
/*fuzzSeed-94431925*/count=1351; tryItOut("switch(eval(\"\\\"use strict\\\"; throw e;\", y)) { default: a2.unshift(p1, g1.o0.s2, g0.o1); }");
/*fuzzSeed-94431925*/count=1352; tryItOut("testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, -1/0, 0x07fffffff, 0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, -0x0ffffffff, 0.000000000000001, 2**53+2, -0x080000000, 0x080000001, -0, 0x100000000, -(2**53+2), 1/0, Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, -0x100000001, -(2**53-2), 42, 0, 0x080000000, -0x07fffffff, 2**53, -(2**53), 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1353; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround(Math.sinh((Math.round(Math.imul(y, ( + Math.pow(( + x), x)))) | 0))) - Math.fround(( ~ Math.round(( - mathy0(( ! x), Math.asin(Number.MIN_VALUE)))))))); }); ");
/*fuzzSeed-94431925*/count=1354; tryItOut("\"use strict\"; Array.prototype.splice.call(a1, -13, 4, v0, t0);");
/*fuzzSeed-94431925*/count=1355; tryItOut("mathy5 = (function(x, y) { return Math.abs((Math.atan2((Math.hypot((( - Math.trunc(Math.PI)) >>> 0), Math.fround(( + Math.fround(-0x0ffffffff)))) >>> 0), (((mathy0((Math.atan2((x >>> 0), Math.fround(x)) | 0), x) >>> 0) >= ((Math.pow(y, ( - y)) ? 0x0ffffffff : -0) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -(2**53-2), 0x100000001, 2**53, -0x100000001, Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, -1/0, 0x080000000, 0.000000000000001, -(2**53), Math.PI, 0x080000001, -Number.MAX_VALUE, -0, 2**53+2, 42, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, 0/0, 0x07fffffff, -0x100000000, 0, 2**53-2]); ");
/*fuzzSeed-94431925*/count=1356; tryItOut("/*infloop*/M:do print(x|=eval); while(x);");
/*fuzzSeed-94431925*/count=1357; tryItOut("L:with({a: /*FARR*/[].some(function(y) { yield y; true;; yield y; }, (4277))}){print(a); }");
/*fuzzSeed-94431925*/count=1358; tryItOut("\"use strict\"; b0.toString = f1;");
/*fuzzSeed-94431925*/count=1359; tryItOut("mathy4 = (function(x, y) { return ( + Math.clz32(Math.fround((Math.tanh((( + Math.round(Math.fround(Math.cosh(2**53-2)))) >>> 0)) && Math.fround(Math.fround(Math.fround(-Number.MAX_SAFE_INTEGER))))))); }); testMathyFunction(mathy4, /*MARR*/[(1/0), new Boolean(false), undefined, undefined, (0/0), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), (0/0), undefined, (0/0), undefined, (0/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), undefined, (1/0), undefined, new Boolean(false), (0/0), undefined, new Boolean(false), (0/0), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), undefined, undefined, new Boolean(false), (1/0), (1/0), (1/0), new Boolean(false), undefined, new Boolean(false), (0/0), undefined, new Boolean(false), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), undefined, (1/0), new Boolean(false), (0/0), new Boolean(false), (0/0), (1/0), new Boolean(false), (0/0), new Boolean(false), (1/0), undefined, undefined, (0/0), new Boolean(false), undefined, undefined, (1/0), (1/0), (1/0), new Boolean(false), undefined, undefined, (0/0), (0/0), (1/0), undefined, new Boolean(false), undefined, (1/0), new Boolean(false), (1/0), (0/0), new Boolean(false), undefined, (1/0), (1/0), (1/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), (1/0), (0/0), undefined, (0/0), (0/0), new Boolean(false), (1/0), (0/0), (0/0), (0/0), new Boolean(false), undefined, undefined, (1/0), new Boolean(false), undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), (1/0), undefined, new Boolean(false), undefined, (1/0), (0/0), new Boolean(false), (0/0), (0/0), new Boolean(false), undefined, undefined, new Boolean(false), (1/0), (0/0), undefined, undefined, (1/0)]); ");
/*fuzzSeed-94431925*/count=1360; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var pow = stdlib.Math.pow;\n  var acos = stdlib.Math.acos;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.5111572745182865e+23;\n    var d3 = -65536.0;\n    var i4 = 0;\n    var d5 = 0.0078125;\n    d2 = (+abs(((-274877906945.0))));\n    {\n      {\n        d1 = (-((d3)));\n      }\n    }\n    d3 = (d2);\n    i4 = (((((d1) > (1.0009765625))) | ((0xcad1bba8) % ((-0x99a3d*((0x53ed6aff)))>>>((/*FFI*/ff(((((0.001953125)) % ((-2199023255551.0)))), ((-2049.0)), ((-549755813889.0)))|0))))) >= (abs(((((0xffffffff) > (((0xfc41caaa))>>>((0xf35bbf4a))))-(0xc5328c3)-((((0xcb370367))>>>((0xfd82edd6))))) >> ((0xffffffff)-(0xfbda45fb))))|0));\n    d0 = (((d1)) / ((d1)));\n    d2 = (((((((d0)) * ((+(0x2c176233))))) - ((d2))) <= (Infinity)) ? (d1) : (+((+/*FFI*/ff(((-((Float64ArrayView[2])))), (('fafafa'.replace(/a/g, decodeURI))))))));\n    {\n      return +((+pow((((1.015625) + ((d3) + (d1)))), ((-((+(1.0/0.0))))))));\n    }\n    d0 = (4503599627370497.0);\n    d3 = (+acos(((NaN))));\n    return +((Float32ArrayView[(((Uint16ArrayView[4096]))-(!(i4))) >> 2]));\n  }\n  return f; })(this, {ff: let (x) -18014398509481984}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x080000000, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, -(2**53+2), 0x080000001, -Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, 0x100000001, -0x080000001, 42, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -(2**53), Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, 0x080000000, 0, -0x100000001, -Number.MIN_VALUE, 2**53+2, 2**53, -0x100000000, Number.MIN_VALUE, -1/0, Math.PI]); ");
/*fuzzSeed-94431925*/count=1361; tryItOut("NaN;;\n/*RXUB*/var r = new RegExp(\"\\u2fc8|(?=(?:(?=[^])))\", \"im\"); var s = \"\\u2fc8\"; print(uneval(r.exec(s))); \n");
/*fuzzSeed-94431925*/count=1362; tryItOut("mathy5 = (function(x, y) { return (( + Math.imul(((0x100000000 | 0) >>> (Math.atan2(x, Math.atan2(Number.MAX_VALUE, ( + y))) | 0)), ( + Math.sqrt(( + mathy4(Math.fround((y ? y : (y ** Math.fround(-0x080000001)))), ( + (( + ( + Math.atan(y))) | ( + x))))))))) && (mathy0(Math.fround((((((y | 0) != (( ! Math.imul(x, x)) | 0)) | 0) | 0) ? ( + Math.log2(Math.pow(0x080000001, (y * Math.fround(x))))) : ((Math.imul((mathy4((Math.log(y) | 0), (y | 0)) | 0), ((((( + y) ? ( + x) : ( + x)) >>> 0) ^ (0x0ffffffff >>> 0)) >>> 0)) >= ((((y | 0) <= (( ! x) | 0)) | 0) >>> 0)) | 0))), (x ** Math.hypot(((y >>> 0) <= (x >>> 0)), y))) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[ \"\" ,  \"\" , x,  \"\" , x,  \"\" ,  \"\" ,  \"\" , x, x,  \"\" ]); ");
/*fuzzSeed-94431925*/count=1363; tryItOut("Object.prototype.unwatch.call(v0, \"call\");");
/*fuzzSeed-94431925*/count=1364; tryItOut("mathy1 = (function(x, y) { return (Math.atan(Math.fround((Math.fround(( ! (Math.cosh((( + Math.atan2(Math.max(x, 0x100000000), ( + Math.abs(x)))) | 0)) | 0))) + Math.fround(Math.fround(Math.imul(Math.fround(Math.hypot(Math.fround(Math.log10(( + -0x07fffffff))), Math.fround(( + ( + 0x07fffffff))))), Math.atan2(-(2**53+2), Math.pow((Math.fround(Math.imul(Math.fround(x), x)) >>> 0), y)))))))) !== ( + (( + Math.log10(y)) ^ ( + (((Math.fround(mathy0(y, ((Math.log1p((y | 0)) | 0) >>> 0))) >>> 0) ? ((( ~ 0x100000000) ? y : (( + Math.cbrt(( + y))) ? mathy0(-(2**53+2), x) : x)) >>> 0) : (Math.fround(Math.hypot((Math.fround(Math.trunc(x)) | 0), Math.fround(Math.fround(Math.asinh(Math.fround(( + Math.fround(y)))))))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [0x080000001, 0x080000000, -Number.MIN_VALUE, -0x100000001, -0x080000000, -(2**53), 1/0, Number.MAX_SAFE_INTEGER, 2**53+2, -0, 42, 0x100000001, -0x0ffffffff, 0x100000000, -0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, Math.PI, 0, -1/0, 0x07fffffff, -0x07fffffff, -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308]); ");
/*fuzzSeed-94431925*/count=1365; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.imul(Math.fround((Math.fround(Math.asinh((Math.hypot(x, ( + -0x100000001)) | 0))) , Math.fround(x))), ((Math.fround(Math.imul(Math.fround(y), Math.fround(y))) ? (Math.pow(x, (x | 0)) | 0) : (Math.atan2(0.000000000000001, x) >>> 0)) || x)) <= ( - Math.imul(Math.max(mathy0((Math.log1p(Math.fround(x)) | 0), (mathy1(y, x) >>> 0)), y), Number.MIN_VALUE)))); }); testMathyFunction(mathy3, [undefined, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), -0, 1, '\\0', true, [], 0, false, '/0/', ({toString:function(){return '0';}}), (new Number(0)), (new Boolean(false)), 0.1, (function(){return 0;}), (new Number(-0)), /0/, null, [0], NaN, (new Boolean(true)), '', ({valueOf:function(){return '0';}}), '0', (new String(''))]); ");
/*fuzzSeed-94431925*/count=1366; tryItOut("this.v0 = a0.some((function(j) { if (j) { Object.defineProperty(this, \"s0\", { configurable: false, enumerable: (x % 2 == 0),  get: function() {  return new String(h0); } }); } else { a0.push(o0.g1, o2.m1, v0, f0); } }), v2, t2);");
/*fuzzSeed-94431925*/count=1367; tryItOut("mathy5 = (function(x, y) { return mathy4(( + Math.imul((Math.log2(Math.fround((( + (mathy3(-0, x) >>> 0)) && Math.fround((y == ( + Math.asinh(( + 0x100000001)))))))) >>> 0), ((( + Math.imul(x, 0x080000000)) >>> 0) > y))), (Math.fround(Math.pow(Math.fround(Math.atan2(y, y)), Math.fround(y))) >> Math.pow(((1 + (Math.fround(Math.log2(0x07fffffff)) && y)) >>> 0), (Math.sinh((x >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [2**53-2, -0x07fffffff, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), 0, -0, 0/0, -0x080000001, 0x080000000, -0x100000000, -1/0, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, 2**53+2, 0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, 1, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -0x080000000, 2**53]); ");
/*fuzzSeed-94431925*/count=1368; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-94431925*/count=1369; tryItOut("mathy3 = (function(x, y) { return ( ! (Math.min(( + mathy2(Math.fround(Math.pow(x, Math.fround(Math.tan((y >>> 0))))), 0)), ( + (x && x))) >>> 0)); }); ");
/*fuzzSeed-94431925*/count=1370; tryItOut("a2 = t2[18];");
/*fuzzSeed-94431925*/count=1371; tryItOut("\"use strict\"; /*MXX3*/g1.Math.sin = this.o0.g1.Math.sin;");
/*fuzzSeed-94431925*/count=1372; tryItOut("\"use strict\"; m2[\"min\"] = v2;");
/*fuzzSeed-94431925*/count=1373; tryItOut("\"use strict\"; v2 = Array.prototype.reduce, reduceRight.apply(a0, [(function(j) { if (j) { m1.get(this.h1); } else { try { this.v1 = (s1 instanceof p2); } catch(e0) { } v0 = evalcx(\"/*vLoop*/for (cpcsri = 0; (/*MARR*/[function(){}, new Number(1), -0x100000001, new Number(1), false, function(){}, function(){}, function(){}, new Number(1)].sort) && cpcsri < 10; ++cpcsri) { const y = cpcsri; v0 = evaluate(\\\"e2.add(t1);\\\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: y, noScriptRval: true, sourceIsLazy: false, catchTermination: \\\"\\\\uEDC4\\\" })); } \", g1); } }), a2, t1, m0, x, t1]);");
/*fuzzSeed-94431925*/count=1374; tryItOut("\"use strict\"; Array.prototype.push.call(a0, b1, t0, v1);function x([], \u3056 = x, ...c)\"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      switch ((abs((b = Proxy.create(({/*TOODEEP*/})( \"\" ), null)))|0)) {\n        case 1:\n          d1 = (Infinity);\n          break;\n        case -2:\n          i2 = ((0x90c8ce34) > (0x4a5800ee));\n          break;\n      }\n    }\n    return (((!(i0))+(i2)))|0;\n  }\n  return f;m2.set(d >= b, i2);");
/*fuzzSeed-94431925*/count=1375; tryItOut("v1 = b0.byteLength;");
/*fuzzSeed-94431925*/count=1376; tryItOut("m1.set(p2, o1);");
/*fuzzSeed-94431925*/count=1377; tryItOut("/*RXUB*/var r = /((?!\\2))|[]?{2,5}/gyi; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1378; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + (y , Math.expm1(y))) !== (Math.tanh((Math.atan2(Math.fround((Math.fround(x) * Math.fround(( + Math.exp((y / Math.hypot(-(2**53+2), x))))))), (Math.pow(Math.atan2(( + Math.fround((x / (((x | 0) == ( + -0)) | 0)))), ( + (Math.log2(Math.fround(y)) | 0))), -Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [0, 0x0ffffffff, 1.7976931348623157e308, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0x080000000, 0x080000001, 0/0, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, 0x100000001, 0x100000000, Number.MIN_VALUE, 1/0, 1, 0x07fffffff, -0x080000000, -Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -1/0, 42, Math.PI, -0x080000001, -0, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1379; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1380; tryItOut("/*MXX1*/o0 = this.g1.g0.Number.NEGATIVE_INFINITY;");
/*fuzzSeed-94431925*/count=1381; tryItOut("v0 = (i1 instanceof v0);v1 = -Infinity;");
/*fuzzSeed-94431925*/count=1382; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, Number.MIN_VALUE, -(2**53), 0x0ffffffff, -0x0ffffffff, -0x100000000, 1.7976931348623157e308, 0x100000001, -0x07fffffff, 2**53-2, 42, -Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 0/0, 1, Math.PI, 0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, -0x100000001, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -1/0, 0x080000000, Number.MAX_VALUE, 2**53+2, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1383; tryItOut("\"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((Float64ArrayView[(((((i0)-(i0)) << ((0xf550ef)*-0x679ee)) > (imul((/*FFI*/ff()|0), (i1))|0))) >> 3]));\n  }\n  return f; })(this, {ff: function(y) { return  /x/  }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53-2), 0, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, -0x0ffffffff, 0/0, 0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, 0x0ffffffff, -0x100000001, -0, -(2**53+2), 0.000000000000001, 2**53, Number.MAX_VALUE, 1, 42, 2**53+2, -0x080000001, -Number.MIN_VALUE, -0x07fffffff, 1/0, 2**53-2, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -1/0, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1384; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 1/0, -0x080000000, 0x100000000, Number.MAX_VALUE, -(2**53+2), -0x080000001, 0/0, -(2**53-2), 2**53, -0x0ffffffff, 0x080000001, -0x100000001, -(2**53), 1.7976931348623157e308, 0x100000001, -1/0, 42, 1, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, 0, 0.000000000000001, 2**53-2, 0x0ffffffff, 0x080000000, Math.PI, -0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-94431925*/count=1385; tryItOut("mathy2 = (function(x, y) { return Math.sqrt(Math.fround(Math.hypot((Math.min((( + Math.atan2(Math.fround(((y >>> 0) | y)), Math.min(Math.log1p(y), (( + (( + -0x100000001) & Math.fround(x))) | 0)))) << ( + x)), Math.fround(Math.hypot(Math.fround(x), Math.min((x % (x != y)), ( + ( + Math.min(( + y), ( + x)))))))) | 0), (( + Math.exp(Math.imul(mathy0(y, (Math.min((-(2**53) | 0), (x | 0)) | 0)), (Math.min(1.7976931348623157e308, y) >>> 0)))) | 0)))); }); testMathyFunction(mathy2, [0x100000000, -0x100000001, -(2**53+2), 0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, -1/0, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -0x080000000, 1, 1/0, Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, -(2**53), -0, 2**53-2, -0x080000001, -Number.MAX_VALUE, 0.000000000000001, 0/0, 0x0ffffffff, 2**53, 0x100000001, Math.PI, 1.7976931348623157e308, 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-94431925*/count=1386; tryItOut("\"use strict\"; ");
/*fuzzSeed-94431925*/count=1387; tryItOut("\"use asm\"; ;y = x = NaN;");
/*fuzzSeed-94431925*/count=1388; tryItOut("f0.__proto__ = a1;");
/*fuzzSeed-94431925*/count=1389; tryItOut("v0 = a0.every((function(j) { if (j) { for (var v of b1) { try { a2.shift(); } catch(e0) { } try { ; } catch(e1) { } t1[13]; } } else { try { t2.__proto__ = this.m1; } catch(e0) { } i1 = new Iterator(g1.s0, true); } }), i2, h2);");
/*fuzzSeed-94431925*/count=1390; tryItOut("{ void 0; void relazifyFunctions('compartment'); } m2.set(f2, g0.m2);");
/*fuzzSeed-94431925*/count=1391; tryItOut("\"use asm\"; g0.a0.push(g2, h0, m1, ([, x, , x, w] = d -= \u3056));");
/*fuzzSeed-94431925*/count=1392; tryItOut("if(true) {print( \"\" ); } else  if ( \"\" ) e0.has(m0); else ;");
/*fuzzSeed-94431925*/count=1393; tryItOut("\"use asm\"; for(let [d, z] =  \"\"  in undefined) ( /x/g );");
/*fuzzSeed-94431925*/count=1394; tryItOut("mathy0 = (function(x, y) { return (Math.imul(Math.fround((( ! Math.fround((Math.fround((( - (y | 0)) | 0)) << Math.fround((Math.pow(y, 0x07fffffff) | 0))))) | Math.max(( + Math.cbrt(x)), x))), Math.sin(((( - Math.log1p(( + 1.7976931348623157e308))) | 0) / ((( - (Math.imul(x, ( + Math.hypot((0x07fffffff >>> 0), ( ~ x)))) >>> 0)) | 0) | 0)))) >>> 0); }); testMathyFunction(mathy0, [1/0, -0x080000000, 0, -Number.MIN_VALUE, 0x100000001, -(2**53+2), 42, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, -(2**53-2), 2**53-2, -1/0, 0x0ffffffff, 2**53, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -(2**53), 0x100000000, -0x100000001, 1, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1395; tryItOut("\"use strict\"; /*infloop*/for(w; (void shapeOf((new Math.min(({a1:1}).throw(true), 0/0)()))); \"\\uA9DF\") g1.v1 = this.a1.length;");
/*fuzzSeed-94431925*/count=1396; tryItOut("mathy4 = (function(x, y) { return (((Math.min(Math.sin(Math.fround(Math.tan(( - (x >>> 0))))), ( ~ Math.min(Math.cbrt(x), Math.fround(Math.cos(0x080000001))))) | 0) , ((((Math.expm1((( + (( + y) ? ( + x) : mathy2(y, Math.abs(x)))) >>> 0)) >>> 0) >>> 0) , ( + mathy2(( + Math.sin(x)), ( + Math.tanh((((Math.hypot(( + x), ( + y)) >>> 0) >>> 0) , y)))))) | 0)) >>> 0); }); testMathyFunction(mathy4, [42, Number.MAX_VALUE, 0x100000000, 0, 2**53+2, 2**53, -(2**53-2), 1.7976931348623157e308, -Number.MAX_VALUE, -0x07fffffff, 0/0, 0x100000001, 1/0, -(2**53+2), Number.MIN_VALUE, -0, -0x0ffffffff, 0x080000000, 0x0ffffffff, Math.PI, -0x100000001, 0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 1, -1/0, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-94431925*/count=1397; tryItOut("testMathyFunction(mathy0, [2**53-2, -0x100000001, 2**53+2, -0x07fffffff, -1/0, -(2**53), -0x080000001, 0.000000000000001, 0x07fffffff, -0, 0/0, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, 1, -(2**53+2), 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, Number.MAX_VALUE, -(2**53-2), 0, 0x100000000, 0x0ffffffff, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, 1/0, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1398; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1399; tryItOut("testMathyFunction(mathy2, [1.7976931348623157e308, 0x080000000, 0, -0x100000001, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, 2**53-2, 0x080000001, -0x080000000, 0x100000000, -Number.MAX_VALUE, 0/0, -0, 0x0ffffffff, 42, -0x07fffffff, -(2**53), -0x100000000, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, 0x100000001, 1/0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, 1, -(2**53+2), -0x080000001, 2**53]); ");
/*fuzzSeed-94431925*/count=1400; tryItOut("mathy1 = (function(x, y) { return (Math.atan2(((mathy0((Math.max(Math.fround((( - (( ! x) >>> 0)) >>> 0)), ((0x0ffffffff > x) | 0)) >>> 0), (( + mathy0(( + (Math.max((y | 0), Math.atan2(x, Math.fround((Math.fround(x) + x)))) | 0)), ( + (-Number.MIN_VALUE ? (x >>> 0) : (x >>> 0))))) >>> 0)) >>> 0) | 0), (( + ( ~ ( + (( ! (x , y)) , (( ~ (Math.log1p((Math.hypot(Math.fround(x), -(2**53+2)) >>> 0)) >>> 0)) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [-0x080000000, -(2**53+2), 2**53+2, 0.000000000000001, -0x100000000, 2**53, 1/0, 42, 0x080000000, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0x0ffffffff, -0x100000001, 0x100000001, 1, Number.MAX_VALUE, 0x100000000, 2**53-2, 0/0, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, -(2**53), -1/0, -0, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-94431925*/count=1401; tryItOut("mathy0 = (function(x, y) { return Math.sqrt(((Math.imul((((y ^ y) ? (y ? ( - -0x100000001) : x) : ( ~ Math.hypot(y, x))) >>> 0), (Math.max((((y | 0) || (0x0ffffffff | 0)) | 0), (( + (y >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 42, -Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, -0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -(2**53+2), 0x080000001, 2**53, -0x100000000, 0x100000001, 0x100000000, -Number.MAX_VALUE, -1/0, Number.MIN_VALUE, 2**53+2, -0, 0/0, -0x0ffffffff, -0x07fffffff, 0x07fffffff, 0, 2**53-2, -(2**53), 1, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1402; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1403; tryItOut("m1.set(g2, v2);");
/*fuzzSeed-94431925*/count=1404; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.fround((( - (Math.min(((y >>> y) == ((( + (x >>> 0)) >>> 0) | 0)), ( + ( + ( ! ( + y))))) >>> 0)) >>> 0)), ( + (Math.atan2(( + Math.pow(-(2**53+2), (Math.ceil(y) >>> 0))), (Math.min(Math.atan2(x, y), Math.max(( + (( + x) ? ( + y) : ( + x))), Math.cosh(mathy0(y, x)))) | 0)) | 0)))); }); testMathyFunction(mathy1, [0x0ffffffff, -0, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), -Number.MAX_VALUE, 0x100000000, 2**53+2, 0/0, -Number.MIN_VALUE, 1, -0x0ffffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, Math.PI, -0x07fffffff, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000001, 0, -(2**53), 0x07fffffff, -0x100000001, 2**53, -1/0, -0x100000000, 42, 0x100000001]); ");
/*fuzzSeed-94431925*/count=1405; tryItOut("g2.a1.valueOf = (function() { try { /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { g1.__proto__ = b1;return 18; }}), { configurable: true, enumerable: (x % 95 != 22), get: (function() { for (var v of h1) { try { v0 = g1.runOffThreadScript(); } catch(e0) { } try { a0.splice(NaN, 16, allocationMarker(), g2, e0); } catch(e1) { } try { a0 = Array.prototype.slice.call(a0, NaN, NaN); } catch(e2) { } g0.i1 = new Iterator(s2); } return m0; }), set: TypeError.prototype.toString.bind(this.f2) }); } catch(e0) { } try { m2.set((6)( '' , false), g0.t1); } catch(e1) { } try { e2.has(g2.g1); } catch(e2) { } b1 = new ArrayBuffer(11); return this.o1; });");
/*fuzzSeed-94431925*/count=1406; tryItOut("t0 = t2.subarray(19, v2);");
/*fuzzSeed-94431925*/count=1407; tryItOut("mathy3 = (function(x, y) { return mathy2((Math.hypot((Math.atan2((Math.fround(Math.atan2(Math.fround(0/0), Math.fround(y))) | 0), (x | 0)) | 0), ( + mathy2(Math.fround(x), Math.fround(Math.imul(-0x100000000, x))))) >>> 0), ( + Math.cosh(0x0ffffffff))); }); ");
/*fuzzSeed-94431925*/count=1408; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.log10((( ! ( ~ Math.fround(x))) + ( + Math.fround(-Number.MIN_SAFE_INTEGER))))); }); ");
/*fuzzSeed-94431925*/count=1409; tryItOut("/*tLoop*/for (let z of /*MARR*/[arguments.caller, new Number(1), new Number(1), arguments.caller, false, false, arguments.caller, arguments.caller, new Boolean(false), new Boolean(false), false, new Number(1), false, new Number(1), new Number(1), arguments.caller, false, new Number(1), arguments.caller, false, false, new Boolean(false),  /x/g ,  /x/g , new Number(1), new Number(1),  /x/g , arguments.caller,  /x/g , new Boolean(false),  /x/g , false,  /x/g , arguments.caller, new Number(1), arguments.caller, false,  /x/g ,  /x/g , false,  /x/g ,  /x/g , false, arguments.caller,  /x/g ,  /x/g , arguments.caller,  /x/g , false, new Boolean(false), new Number(1), new Number(1), false, new Boolean(false),  /x/g , false, false, false, false,  /x/g ,  /x/g , arguments.caller, new Boolean(false), false, new Boolean(false), false,  /x/g , arguments.caller, false, new Boolean(false),  /x/g , false, new Number(1), arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, new Number(1), new Number(1),  /x/g , false, new Boolean(false), arguments.caller,  /x/g , new Number(1), new Boolean(false), arguments.caller, arguments.caller, new Number(1), new Number(1),  /x/g , new Boolean(false), arguments.caller, false,  /x/g , arguments.caller, new Boolean(false), false, new Boolean(false), arguments.caller, arguments.caller,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Number(1), new Boolean(false), arguments.caller, false, false, false, false, false, false, false, false, false, false, false, false,  /x/g , new Number(1), new Number(1), arguments.caller, false, arguments.caller, false, false,  /x/g , false, false,  /x/g ,  /x/g ]) { s1 += 'x'; }");
/*fuzzSeed-94431925*/count=1410; tryItOut("v0 = r0.toString;");
/*fuzzSeed-94431925*/count=1411; tryItOut("\"use strict\"; for(let y in []);");
/*fuzzSeed-94431925*/count=1412; tryItOut("{t1[({valueOf: function() { Array.prototype.forEach.apply(o0.a0, [(function() { try { a2 = arguments; } catch(e0) { } try { s1 = new String; } catch(e1) { } try { m2.set(o2.o2.g0.o1, o0.b2); } catch(e2) { } Array.prototype.forEach.call(a2, (function() { try { e0.add(f0); } catch(e0) { } try { m0.delete(v2); } catch(e1) { } for (var v of s2) { try { v0 = evaluate(\"e0.has(b0);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: null, sourceIsLazy: true, catchTermination: false })); } catch(e0) { } Array.prototype.unshift.apply(a1, [o2, e2]); } return b1; })); return h0; }), g2.p2]);return 2; }})]; }");
/*fuzzSeed-94431925*/count=1413; tryItOut("\"use strict\"; \"use strict\"; for (var p in o2.p1) { try { g0 = this; } catch(e0) { } try { g1.p1.toSource = (function mcc_() { var lspmoo = 0; return function() { ++lspmoo; if (/*ICCD*/lspmoo % 6 == 3) { dumpln('hit!'); try { g2.g2.v1 = Object.prototype.isPrototypeOf.call(s1, g0.i2); } catch(e0) { } try { a1[v0] = window; } catch(e1) { } g1.a2.sort((function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+(((i1)+(0xe7187a9a)) & ((((i1)-(i1))>>>((i1)+((-0x8000000))+((0xffffffff) ? (0xc1dbae5) : (-0x38913b5)))) % ((((d0) > (-33554433.0)))>>>(((((0xfd811b56))|0))-((0x6aa044f9) ? (0x96ff99ab) : (0xfb414061)))))));\n    d0 = (-2.3611832414348226e+21);\n    return (((i1)*0x8000e))|0;\n    return ((((0xfffff*(i1)) | ((((0x4224ace7) / (0x514ec0b5))>>>(((imul((0x6a9ebcef), (0x657e6894))|0)))) / (0x484823ba))) % ((-(i1))|0)))|0;\n    i1 = (i1);\n    d0 = (((((i1)-(0x783a1860)+((0xb86b5830)))>>>((!(i1))+(0x6b80bad3)))) ? (-2097151.0) : (-1.001953125));\n    (Float32ArrayView[0]) = ((-590295810358705700000.0));\n    d0 = (d0);\n    return (((imul((-0x8000000), (i1))|0) / ((((d0) >= ((((0x93c2dd21) ? (-2049.0) : (-2251799813685248.0))) / (((0x2640af66) ? (-268435457.0) : (-257.0)))))) & (-0xe8626*(0xd1a13b3c)))))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return x; })}, new SharedArrayBuffer(4096)), b0, v0); } else { dumpln('miss!'); try { v0 = evaluate(\"function f2(i0) \\\"use asm\\\";   var atan2 = stdlib.Math.atan2;\\n  var abs = stdlib.Math.abs;\\n  var imul = stdlib.Math.imul;\\n  var floor = stdlib.Math.floor;\\n  var NaN = stdlib.NaN;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n;    i1 = (0xff11f06b);\\n    i1 = (-0x8000000);\\n    d0 = (+atan2(((d0)), ((Float64ArrayView[1]))));\\n    d0 = (d0);\\n    d0 = (d0);\\n    i1 = ((abs(((delete Math.imul(\\\"\\\\u4E73\\\", 11)) | (-(((Float64ArrayView[2])) >= (((0x5430ac7e)+(0xe843f100)-(-0x8000000))|0)))))|0) <= ((0xd0f68*((4277))) ^ (((((((-0x8000000)) >> ((0x4addfade))) % (imul((0xf29fc460), (0xb7bda80))|0)) | (((0x856991f5) == (0xffffffff))+(i1)-((-0x8000000) ? (0xd05144fa) : (0xf8fa2662))))))));\\n    d0 = (d0);\\n    d0 = (((1.0625)) / ((d0)));\\n    d0 = (+floor(((-140737488355327.0))));\\n    switch ((((0x7c8a7d17)-(0x25ee70cb)-(0xffffffff)) << ((0xe7e34a80)+(0x3d860367)+(0xfd066175)))) {\\n      case 1:\\n        d0 = (d0);\\n        break;\\n      case -2:\\n        d0 = (((~(((0x0)))) != (~((Uint32ArrayView[0])))) ? (d0) : (d0));\\n        break;\\n    }\\n    d0 = (18014398509481984.0);\\n    d0 = (((d0)) * (((!(i1)) ? (d0) : (+(((0x482b6301))>>>(-0xfffff*((281474976710655.0) < (-3.094850098213451e+26))))))));\\n    d0 = (+atan2(((72057594037927940.0)), ((Float32ArrayView[2]))));\\n    {\\n      i1 = (0xf8848ddd);\\n    }\\n    d0 = (NaN);\\n    i1 = (1);\\n    i1 = ((147573952589676410000.0) != (-((+(-1.0/0.0)))));\\n    return +((31.0));\\n  }\\n  return f;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 68 == 65), noScriptRval: true, sourceIsLazy: x, catchTermination: (x % 13 != 7) })); } catch(e0) { } try { v0 = a0.length; } catch(e1) { } try { /*MXX3*/o2.g1.RegExp.$5 = g1.RegExp.$5; } catch(e2) { } /*ODP-3*/Object.defineProperty(t1, 10, { configurable: false, enumerable: true, writable: true, value: o0.v1 }); } };})(); } catch(e1) { } try { m1.set(i1, h0); } catch(e2) { } g1.offThreadCompileScript(\"29\"); }");
/*fuzzSeed-94431925*/count=1414; tryItOut("mathy2 = (function(x, y) { return Math.pow(( + Math.hypot(( + Math.fround(( ~ Math.fround(y)))), ( + ( + ( + ( + (Math.pow((y >>> 0), (x >>> 0)) >>> 0))))))), (Math.max((( + Math.clz32(( + Math.exp((Math.min((mathy1(0x0ffffffff, ( + y)) | 0), (x | 0)) | 0))))) >>> 0), ((Math.fround(Math.pow(x, (Math.atanh(y) >>> 0))) , (y | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [-0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, 0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, 0, 42, 0/0, -1/0, 2**53+2, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, 0x080000001, -0x100000000, -(2**53-2), 0x100000000, 0x100000001, 0x07fffffff, Number.MIN_VALUE, -0, 2**53, -(2**53+2), Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000]); ");
/*fuzzSeed-94431925*/count=1415; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.tanh(( + mathy1(( ~ ( + Math.cbrt(Math.sign(1.7976931348623157e308)))), ( + (( + y) != x))))); }); testMathyFunction(mathy4, [1/0, 2**53+2, 0.000000000000001, 0, Number.MAX_VALUE, 0x100000000, -0x0ffffffff, 0x080000001, -0x100000001, 0x080000000, 42, 0/0, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, Number.MIN_VALUE, -0, 2**53-2, 0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, -0x100000000, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, 2**53, -Number.MIN_VALUE, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-94431925*/count=1416; tryItOut("\"use strict\"; this.g2.offThreadCompileScript(\"\\\"use strict\\\"; a2.valueOf = (function() { try { g0 + ''; } catch(e0) { } try { throw {};function x() { yield (4277) } o2 = {}; } catch(e1) { } t2 = new Uint16Array(2); return g0; });\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-94431925*/count=1417; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 576460752303423500.0;\n    return +((Float64ArrayView[((0xfb2692f6)-(/*FFI*/ff((((-0x8000000) ? (({ set 1(d)null, apply: (4277) })) : (+(-1.0/0.0)))), ((d0)), ((+sqrt(((d1))))), ((+(-1.0/0.0))))|0)-(0xe7817dab)) >> 3]));\n  }\n  return f; })(this, {ff: [,,z1]}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-94431925*/count=1418; tryItOut("mathy5 = (function(x, y) { return (Math.fround(Math.min(( - (( ! (Math.log10(Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0)), (( - Math.fround(Math.acos(y))) >>> 0))) ? (Math.fround((Math.fround(( + (( + Math.log10(( - x))) >> Math.fround(Math.cbrt(Math.fround(y)))))) != Math.fround(Math.max(((( + ( + ( + (Math.atan2(-Number.MAX_VALUE, (y | 0)) | 0)))) ** Math.fround(Math.min(y, (( ~ (-(2**53-2) <= (y | 0))) | 0)))) | 0), Math.acos(( + Math.atan2(( + -0x100000000), (( + (x >>> 0)) >>> 0)))))))) | 0) : Math.fround(Math.clz32(((0x07fffffff % (Math.imul(Math.tan(y), x) >>> 0)) | 0)))); }); testMathyFunction(mathy5, [-0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -(2**53+2), 1, 2**53-2, 0x080000000, Number.MAX_VALUE, 2**53, -0x100000000, Math.PI, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 42, 2**53+2, 0x0ffffffff, 0x080000001, -Number.MAX_VALUE, 0/0, -0x080000000, -0x080000001, Number.MIN_VALUE, -(2**53), 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1419; tryItOut("print(p0);");
/*fuzzSeed-94431925*/count=1420; tryItOut("\"use strict\"; /*infloop*/for(let arguments = Math.pow(-816583686, 2141522332); x * x; NaN **= z) {v1 = evalcx(\"o1.f2.valueOf = (function mcc_() { var dgypvu = 0; return function() { ++dgypvu; if (/*ICCD*/dgypvu % 11 != 1) { dumpln('hit!'); try { Object.seal(b1); } catch(e0) { } try { m1.get(s2); } catch(e1) { } m0.has(f1); } else { dumpln('miss!'); try { a0 = new Array; } catch(e0) { } try { /*RXUB*/var r = r0; var s = s0; print(uneval(s.match(r)));  } catch(e1) { } try { s2 += 'x'; } catch(e2) { } m1.set(s1, b2); } };})();\", g2);/* no regression tests found */ }");
/*fuzzSeed-94431925*/count=1421; tryItOut("{ void 0; void gc(); } i0 + o0;");
/*fuzzSeed-94431925*/count=1422; tryItOut("v0 = evaluate(\"(void options('strict')).__defineGetter__(\\\"c\\\", decodeURI)\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: yield /*UUV2*/(b.find = b.setDate), noScriptRval: false, sourceIsLazy: true, catchTermination: Object.defineProperty(x, 1, ({configurable: (x % 6 != 0)})).__defineSetter__(\"window\", this for (w in  \"\" ) if (window)) }));");
/*fuzzSeed-94431925*/count=1423; tryItOut("this.a0 = Array.prototype.map.call(a2, (function mcc_() { var zsokow = 0; return function() { ++zsokow; if (/*ICCD*/zsokow % 10 == 4) { dumpln('hit!'); try { v1 = g1.runOffThreadScript(); } catch(e0) { } for (var v of a2) { /*ADP-3*/Object.defineProperty(a2, 4, { configurable: true, enumerable: x = Proxy.createFunction(({/*TOODEEP*/})(\"\\uDF52\"), Uint16Array, (( /x/ ).bind()).apply), writable: (x = this.zzz.zzz), value: a0 }); } } else { dumpln('miss!'); v2 = g1.runOffThreadScript(); } };})(), f0);");
/*fuzzSeed-94431925*/count=1424; tryItOut("this.v0 = Object.prototype.isPrototypeOf.call(this.g1.i1, v2);");
/*fuzzSeed-94431925*/count=1425; tryItOut("\"use asm\"; let d =  /x/ ;L:switch('fafafa'.replace(/a/g, decodeURI)) { case (d && e): v1.__proto__ = i0;break;  }");
/*fuzzSeed-94431925*/count=1426; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.asinh((( ! Math.fround(mathy1(( + (Math.clz32(mathy0(x, (-0x07fffffff >>> 0))) >>> 0)), (( + (mathy0((( + Math.atan2(( + y), (((y >>> 0) ? (0x0ffffffff >>> 0) : (x >>> 0)) >>> 0))) | 0), (Math.expm1(0) >>> 0)) >>> 0)) == y)))) | 0)); }); testMathyFunction(mathy2, /*MARR*/[-0x080000000, {}, arguments.caller, Math.PI, -0x080000000, {}, {}, {}, -0x080000000, -0x080000000, {}, true, {}, Math.PI, true, true, arguments.caller, {}, Math.PI, Math.PI, true, Math.PI]); ");
/*fuzzSeed-94431925*/count=1427; tryItOut("\"use strict\"; /*MXX3*/g2.Math.LOG10E = g1.Math.LOG10E;");
/*fuzzSeed-94431925*/count=1428; tryItOut("testMathyFunction(mathy1, /*MARR*/[this,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , this, objectEmulatingUndefined(), this,  /x/ ,  /x/ , objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ]); ");
/*fuzzSeed-94431925*/count=1429; tryItOut("testMathyFunction(mathy1, [0, -0x080000001, -0, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, -0x07fffffff, -(2**53-2), 1/0, 0.000000000000001, -(2**53+2), 0x07fffffff, 42, 0x100000001, -Number.MAX_VALUE, Math.PI, -0x080000000, -1/0, 0/0, 2**53, 0x100000000, -(2**53), -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, 1, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=1430; tryItOut("mathy1 = (function(x, y) { return (Math.fround(Math.asin((Math.imul((Math.acosh((mathy0(Math.asin((( ! Math.fround(1.7976931348623157e308)) | 0)), ( + (42 || Math.fround(0x100000001)))) | 0)) | 0), Math.min(Math.fround(Math.fround((Math.fround(x) ** y))), Math.fround(x))) >>> 0))) % Math.sinh(Math.fround(Math.imul(y, (((mathy0(x, y) > Math.log1p(x)) | 0) <= (y | 0)))))); }); ");
/*fuzzSeed-94431925*/count=1431; tryItOut("\"use strict\"; var mxhhmh = new ArrayBuffer(0); var mxhhmh_0 = new Uint32Array(mxhhmh); mxhhmh_0[0] = 18; var mxhhmh_1 = new Float64Array(mxhhmh); mxhhmh_1[0] = -24; var mxhhmh_2 = new Uint16Array(mxhhmh); print(mxhhmh_2[0]); mxhhmh_2[0] = 0; i1 = new Iterator(t0);h1 + '';h1.getOwnPropertyDescriptor = f2;\"\\u7913\";");
/*fuzzSeed-94431925*/count=1432; tryItOut("var eeilta = new SharedArrayBuffer(16); var eeilta_0 = new Uint16Array(eeilta); print(b = Proxy.create(({/*TOODEEP*/})([z1,,]), \"\\u3AA3\"));/*RXUB*/var r = new RegExp(\"(?:.)\", \"gim\"); var s = \"\\n\"; print(s.replace(r, '')); ");
/*fuzzSeed-94431925*/count=1433; tryItOut("mathy3 = (function(x, y) { return ( + ( ! ( + mathy1(( + ( ! Math.fround(Math.atan2((mathy0(x, -1/0) | 0), Math.fround(( + ( ~ Math.fround(((y <= y) | 0))))))))), ( + (Math.pow((Math.fround(( ! Math.fround(x))) | 0), (Math.atan2((( - (( + mathy2((x >>> 0), ( + (Math.min(x, (-(2**53+2) | 0)) | 0)))) >>> 0)) | 0), (x | 0)) | 0)) | 0)))))); }); ");
/*fuzzSeed-94431925*/count=1434; tryItOut("g0.e1 = new Set(this.a0);");
/*fuzzSeed-94431925*/count=1435; tryItOut("this.v0 = evaluate(\"function f0(m1) x\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 3 == 2), sourceIsLazy: (x % 4 == 0), catchTermination: false, sourceMapURL: s2 }));");
/*fuzzSeed-94431925*/count=1436; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.abs((Math.log2((Math.max(( ~ (Math.atan2(y, Math.fround(x)) >>> 0)), x) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[null, new Boolean(true), new Boolean(true),  /x/g , new Boolean(true), 2**53-2, new Number(1), new Number(1), new Number(1), new Boolean(true), new Boolean(true), new Number(1), null, new Number(1), new Boolean(true), null, 2**53-2, new Boolean(true), null, new Number(1), null, new Number(1),  /x/g , null, null, 2**53-2, new Number(1), new Boolean(true), null, 2**53-2, 2**53-2,  /x/g , 2**53-2, 2**53-2,  /x/g , new Boolean(true), 2**53-2, 2**53-2, 2**53-2, new Number(1),  /x/g , 2**53-2, null, null, 2**53-2,  /x/g ,  /x/g , null, null, 2**53-2, 2**53-2,  /x/g ,  /x/g , null,  /x/g , null, new Boolean(true), new Boolean(true), new Boolean(true), null]); ");
/*fuzzSeed-94431925*/count=1437; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.asin(Math.fround((Math.clz32(Math.fround((x ? mathy0((Math.pow((y | 0), (-0x080000001 ^ y)) | 0), ( ~ x)) : x))) ? (mathy1(-Number.MIN_SAFE_INTEGER, (Math.log2((( + Math.acosh(( + x))) | 0)) >>> 0)) >>> 0) : (mathy0(( ! 2**53+2), (-0x07fffffff >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [-1/0, -(2**53), 1/0, 0x0ffffffff, 0/0, 42, 2**53-2, -0x080000000, -0x100000001, -0x080000001, 2**53+2, -(2**53+2), Number.MAX_VALUE, -0x07fffffff, -0x100000000, -0, 0, -0x0ffffffff, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 0x080000001, -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 1, 1.7976931348623157e308, 0x100000001, 0x100000000, -Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1438; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"_\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-94431925*/count=1439; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = new RegExp(\"\\\\3{2}|(?=\\\\B)|(^(?:\\\\S))|(?!\\\\b)\", \"\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-94431925*/count=1440; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (Math.pow(Math.atan2(x, Math.min((Math.imul(Math.PI, Math.expm1(( + Math.fround(( + x))))) | 0), ( + ( + ( + Math.asinh(x)))))), (((Math.max(x, ( ~ x)) >= Math.pow(y, -0x07fffffff)) + ((Math.fround(Math.abs(Math.fround(y))) | (x >>> 0)) | 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [-0x080000000, -0x100000001, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, 0, -(2**53), 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, -(2**53+2), -0, 42, 0x100000001, 0x080000001, -Number.MIN_VALUE, 0/0, -0x0ffffffff, 1.7976931348623157e308, 1/0, -0x080000001, -0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1441; tryItOut("var c = (Math.round(8796093022207));print(eval(\"/* no regression tests found */\", true));");
/*fuzzSeed-94431925*/count=1442; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -1/0, 0x07fffffff, 0x100000000, 0/0, -(2**53-2), -0, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 1, 0x0ffffffff, 0x080000001, 42, 2**53-2, 0x100000001, -0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0x080000000, 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 2**53, 1/0, -0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-94431925*/count=1443; tryItOut("print(x);");
/*fuzzSeed-94431925*/count=1444; tryItOut("\"use strict\"; v1 = g1.runOffThreadScript();[z1];");
/*fuzzSeed-94431925*/count=1445; tryItOut("/*vLoop*/for (trlaua = 0; trlaua < 4; ++trlaua) { d = trlaua; (/\\3/m); } ");
/*fuzzSeed-94431925*/count=1446; tryItOut("\"use strict\"; h1.get = (function() { try { v0 = Object.prototype.isPrototypeOf.call(i2, f2); } catch(e0) { } try { p0 = t2[v1]; } catch(e1) { } s0 + a0; return b2; });");
/*fuzzSeed-94431925*/count=1447; tryItOut("g0.toString = Object.freeze.bind(s1);");
/*fuzzSeed-94431925*/count=1448; tryItOut("m0 + '';");
/*fuzzSeed-94431925*/count=1449; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atan2(Math.cbrt((Math.acosh(( + Math.fround((Math.fround(x) << Math.fround(Math.max(((y !== 0x100000001) >>> 0), y)))))) | 0)), ( + (((mathy0((((((( - (Math.fround(mathy0(Math.fround(0x080000000), Math.fround(x))) | 0)) | 0) >>> 0) ? (y >>> 0) : (y >>> 0)) >>> 0) | 0), ( + x)) | 0) >= ( + Math.asinh(( + (mathy0((Math.pow(y, ( + Math.log(x))) >>> 0), (x >>> 0)) >>> 0))))) > ( + (Math.sin((( ~ (( + Math.min(( + (x <= x)), ( + y))) >>> 0)) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-94431925*/count=1450; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.expm1((Math.atan2((x * Math.fround((( - (1 | 0)) | 0))), Math.max(x, x)) >>> 0)) | 0), ((( + Math.imul((Math.imul((Math.atan2((x >>> 0), (Math.log(Math.fround(y)) >>> 0)) >>> 0), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0), (( - (( ~ x) >>> 0)) >>> 0))) && ((Math.sin(y) < x) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-94431925*/count=1451; tryItOut("g0.offThreadCompileScript(\"h1 = o0.a1[18];\");");
/*fuzzSeed-94431925*/count=1452; tryItOut("this.m1.delete(g1.e1);");
/*fuzzSeed-94431925*/count=1453; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.imul((( + Math.tanh(Math.pow(y, x))) <= Math.atan2(Math.cos(x), ( + Math.max(( + x), ( + ( + ( ! ( + (y > y))))))))), (mathy3((mathy0(((y | 0) ? x : x), (y | 0)) | 0), y) ^ Math.fround((( + y) & (Number.MAX_VALUE | 0))))); }); testMathyFunction(mathy5, ['0', -0, 0, (new Number(0)), ({toString:function(){return '0';}}), (function(){return 0;}), [], true, 1, (new String('')), (new Boolean(true)), '\\0', ({valueOf:function(){return '0';}}), [0], /0/, '', objectEmulatingUndefined(), (new Boolean(false)), null, 0.1, '/0/', undefined, (new Number(-0)), ({valueOf:function(){return 0;}}), false, NaN]); ");
/*fuzzSeed-94431925*/count=1454; tryItOut("testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, 1/0, 0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, Number.MIN_VALUE, 0, -0x0ffffffff, 0x080000000, 2**53, 1.7976931348623157e308, -0x100000001, -0x07fffffff, -0x100000000, -0, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, -(2**53+2), 0x07fffffff, 0.000000000000001, 0/0, 1, -Number.MIN_VALUE, 0x0ffffffff, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 42]); ");
/*fuzzSeed-94431925*/count=1455; tryItOut("e0 = new Set(g2.o2);");
/*fuzzSeed-94431925*/count=1456; tryItOut("testMathyFunction(mathy4, [0x07fffffff, 2**53, 1/0, 0, -(2**53-2), -0x080000000, -0, 0x080000001, 0/0, -0x07fffffff, Number.MIN_VALUE, -0x0ffffffff, 0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, 1, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, Math.PI, 42, -1/0, 0x100000001, -0x100000000, -0x100000001, -(2**53), -(2**53+2), 0x080000000]); ");
/*fuzzSeed-94431925*/count=1457; tryItOut("b\nv1 = g2.runOffThreadScript();\n");
/*fuzzSeed-94431925*/count=1458; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?:[]\\s{549755813888}+)\\B|(?!.)+(?=${4,}|[^--\\u71F7\\S\\cG]){0})*?/; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-94431925*/count=1459; tryItOut("var ujfvfh = new SharedArrayBuffer(4); var ujfvfh_0 = new Float32Array(ujfvfh); print(ujfvfh_0[0]); var ujfvfh_1 = new Uint8ClampedArray(ujfvfh); print(ujfvfh_1[0]); ujfvfh_1[0] = null; a2[this.v0] = ([]);");
/*fuzzSeed-94431925*/count=1460; tryItOut("testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, -0x0ffffffff, -0x080000001, 0/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0x080000001, -(2**53+2), 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 2**53-2, -(2**53), 1.7976931348623157e308, 42, -0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, 1, 1/0, -(2**53-2), Number.MAX_VALUE, 0.000000000000001, -0x080000000, 0x0ffffffff, 0, -0, 0x07fffffff, 2**53]); ");
/*fuzzSeed-94431925*/count=1461; tryItOut("\"use asm\"; a1 = Array.prototype.map.apply(a2, [(function() { v0 = evalcx(\"((void options('strict')))\", g0); return t0; }),   = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })( /x/g ), x), i1]);");
/*fuzzSeed-94431925*/count=1462; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.pow(((Math.tan((((mathy1(( + Math.fround(Math.max(Math.fround(Math.atan2(y, y)), x))), ( + Math.max(( + (x | y)), ( + (( + Math.tan(y)) ? ( + Number.MIN_SAFE_INTEGER) : ( + ((y | 0) + y))))))) >>> 0) | 0) ** ((( + ((Math.fround(Math.max((Math.imul((Number.MAX_VALUE | 0), (y | 0)) | 0), (x & y))) === (x >>> 0)) >>> 0)) ? ( + y) : ( + x)) | 0))) | 0) >>> 0), ( + ( - 42))) >>> 0); }); testMathyFunction(mathy2, [0x080000000, 0/0, 1/0, 0x0ffffffff, 42, -0x100000000, -0x080000000, Math.PI, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, 0x100000001, 2**53-2, -(2**53), -1/0, 2**53, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, 1, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, -0, -0x100000001, 1.7976931348623157e308, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1463; tryItOut("switch(x) { case 1: break; print((x.watch(\"9\", x)));break;  }");
/*fuzzSeed-94431925*/count=1464; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (mathy2((( + ((Math.fround(( ~ Math.fround((Math.fround(y) << ( + x))))) && (Math.atanh((( - ( - -(2**53))) | 0)) | 0)) | 0)) >>> 0), ((Math.abs(( + Math.fround(Math.fround(Math.fround(Math.sign(Math.fround(-0x0ffffffff))))))) ^ Math.fround(( - Math.fround(1.7976931348623157e308)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x0ffffffff, 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, -0x080000001, Number.MAX_VALUE, 2**53+2, 2**53, -0, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, 0, 0.000000000000001, 1.7976931348623157e308, 42, -0x07fffffff, 1, 0/0, 0x07fffffff, 0x100000001, Number.MIN_VALUE, -(2**53-2), 0x100000000, -(2**53+2), -(2**53), 1/0, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff]); ");
/*fuzzSeed-94431925*/count=1465; tryItOut("/* no regression tests found */d = (makeFinalizeObserver('nursery'));");
/*fuzzSeed-94431925*/count=1466; tryItOut("Object.defineProperty(this, \"v0\", { configurable: (x % 64 != 21), enumerable: \u0009new ({/*TOODEEP*/})((uneval( /x/ ))).watch(\"repeat\", Math.cosh),  get: function() {  return t1.length; } });");
/*fuzzSeed-94431925*/count=1467; tryItOut("\"use strict\"; e0 + '';");
/*fuzzSeed-94431925*/count=1468; tryItOut("/*infloop*/ for  each(var String.prototype.blink in x) {v2 = g0.eval(\"Array.prototype.unshift.apply(g0.a0, [f1, g2.g2, a1, e2, this.g0]);\");print((void version(180))); }");
/*fuzzSeed-94431925*/count=1469; tryItOut("\"use strict\"; g1 = o0.a2[((uneval((x = window))))];");
/*fuzzSeed-94431925*/count=1470; tryItOut("\"use strict\"; e2.has((((function factorial_tail(hutnti, pvzalt) { ; if (hutnti == 0) { ; return pvzalt; } ; return factorial_tail(hutnti - 1, pvzalt * hutnti); NaN; })(45275, 1)) <= (new (-7)())));");
/*fuzzSeed-94431925*/count=1471; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return Math.atan2(( + Math.fround(Math.sign(Math.fround((Math.fround(y) , (x << ( - Math.fround(( - (2**53 ** y)))))))))), (Math.imul(Math.fround((Math.fround(Math.cbrt(y)) | (Math.min(Math.fround((Math.acosh((Math.hypot(-0x100000001, y) >>> 0)) >>> 0)), Math.fround(Math.hypot(((( + y) >>> 0) | 0), Math.fround((( + -0x0ffffffff) % ( + ( + Math.atan2(( + x), Math.fround(-0x100000000))))))))) | 0))), (( + ( ~ ( ~ (y | 0)))) + x)) | 0)); }); ");
/*fuzzSeed-94431925*/count=1472; tryItOut("testMathyFunction(mathy5, /*MARR*/[3/0, (1/0), objectEmulatingUndefined(), (1/0), x, 3/0, objectEmulatingUndefined()]); ");
/*fuzzSeed-94431925*/count=1473; tryItOut("g0.o1 + '';");
/*fuzzSeed-94431925*/count=1474; tryItOut("var NaN =  , qqytcz;a0 + a1;");
/*fuzzSeed-94431925*/count=1475; tryItOut("\"use strict\"; var gjxfrr = new ArrayBuffer(4); var gjxfrr_0 = new Uint16Array(gjxfrr); var gjxfrr_1 = new Float32Array(gjxfrr); print(gjxfrr_1[0]); gjxfrr_1[0] = -4; var gjxfrr_2 = new Int8Array(gjxfrr); print(gjxfrr_2[0]); gjxfrr_2[0] = 0; var gjxfrr_3 = new Uint8ClampedArray(gjxfrr); gjxfrr_3[0] = 5; Array.prototype.pop.apply(a1, [s2]);");
/*fuzzSeed-94431925*/count=1476; tryItOut("\"use asm\"; let(d) { this.zzz.zzz;}");
/*fuzzSeed-94431925*/count=1477; tryItOut("\"use strict\"; L\u000d: this.s2 = new String(i0);const w = yield arguments;");
/*fuzzSeed-94431925*/count=1478; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Int8ArrayView[((((0x0) / (0x4b88cd3c)) >> ((i1)-(i0))) % (((Int8ArrayView[4096])) >> (((0x518d724) > (0x0))))) >> 0]) = ((!(i1)));\n    i0 = (((-(i1))>>>(((((i1)) & ((/*FFI*/ff(((-65536.0)), ((-1025.0)), ((-6.044629098073146e+23)))|0))) >= (0x3f3a0220))*0x3c880)) > ((((+(0.0/0.0)))+(((+/*FFI*/ff(((4503599627370497.0))))))-((abs((((0xfe98b22f)) << ((0xffffffff))))|0) >= (((-0x7817493)) ^ ((0xffffffff)))))>>>(0x280f*((-8193.0) < (1025.0)))));\n    i1 = ((+(1.0/0.0)) == (-3.022314549036573e+23));\n    {\n      i0 = (i1);\n    }\n    (Float32ArrayView[(((0x399f265f) <= (((0x232b0f07)) | ((-0x8000000))))-(/*FFI*/ff(((((0x3c8e49da)+(0xc5b95e13)) | ((-0x8000000)*0xfffff))), ((((0x2804ac66)) ^ ((0xffffffff)))), ((((0x4955fcbf)) & ((0xffffffff)))))|0)-((-590295810358705700000.0) <= (-1.0625))) >> 2]) = ((((+(-1.0/0.0))) * ((33.0))));\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: ({a1:1})}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Math.PI, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 0x07fffffff, 1, 0x080000000, -(2**53), -0x080000000, 2**53-2, 0x100000000, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53, 0, 0x0ffffffff, -1/0, 0.000000000000001, -0, Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -(2**53-2), Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, 0x080000001, 2**53+2]); ");
/*fuzzSeed-94431925*/count=1479; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.asin(Math.clz32(( - ((( + ( - ( + Math.max(( + -0), y)))) , ( - ( - (Number.MAX_SAFE_INTEGER >>> 0)))) | 0)))); }); testMathyFunction(mathy1, [0x080000001, 0x0ffffffff, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, -0x0ffffffff, 1.7976931348623157e308, 0x100000001, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53-2, -0x100000001, -0x100000000, Number.MAX_VALUE, -0x07fffffff, -0, 0x080000000, -Number.MAX_SAFE_INTEGER, 42, 0, -Number.MAX_VALUE, Math.PI, -(2**53), -(2**53-2), 1, -(2**53+2), 1/0, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-94431925*/count=1480; tryItOut("/*infloop*/for(w; b <= eval; (/*RXUE*/new RegExp(\"(?![^]?){1023,1073742848}\", \"im\").exec(\"\"))) Array.prototype.splice.call(a1, NaN, ({valueOf: function() { Object.defineProperty(g2, \"v0\", { configurable: w.yoyo(x), enumerable: (x % 6 == 5),  get: function() {  return evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 4 != 1), catchTermination: false })); } });return 4; }}), o0, o0, o1);");
/*fuzzSeed-94431925*/count=1481; tryItOut("print(g1);\n/*RXUB*/var r = r2; var s = \"\\n 1aa \\n\\u00a21m\"; print(s.search(r)); print(r.lastIndex); \n");
/*fuzzSeed-94431925*/count=1482; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.log(( + ( + ( + (x ? ( + Math.min(( + Math.hypot((x | 0), (0.000000000000001 | 0))), Math.fround(( - y)))) : x))))); }); testMathyFunction(mathy4, [-(2**53+2), 42, 0, -0x100000000, 2**53-2, Number.MIN_VALUE, 0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, 0x080000000, 1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -1/0, Math.PI, -(2**53-2), 0/0, Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 0x0ffffffff, 0x100000001, 1, -0x0ffffffff, -0x080000001, 2**53, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1483; tryItOut("m1 + t2;");
/*fuzzSeed-94431925*/count=1484; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(( + Math.fround((Math.min((Math.imul((( ~ x) | 0), Math.fround(( + y))) >>> 0), Math.tanh(Math.fround(y))) || Math.sinh(x))))); }); ");
/*fuzzSeed-94431925*/count=1485; tryItOut("print(x);");
/*fuzzSeed-94431925*/count=1486; tryItOut("a1.sort((function() { s0 + ''; return f2; }));\n/*RXUB*/var r = r2; var s = (eval(c) = x).yoyo((new Function(\" /x/g ;let d = this;\"))); print(s.split(r)); \n");
/*fuzzSeed-94431925*/count=1487; tryItOut("\"use strict\"; v0 = (s0 instanceof o2);");
/*fuzzSeed-94431925*/count=1488; tryItOut("\"use strict\"; a2 = r2.exec(s1);");
/*fuzzSeed-94431925*/count=1489; tryItOut("this.g0.offThreadCompileScript(\"function f0(f2) [x, {get, f2}, [, {x: {d: {}, x: [w, ]}, c: [, eval, e], c: (({/*TOODEEP*/})).call(a|=new RegExp(\\\"(?:(?=[^]{1,4}))\\\\\\\\S|$*?\\\", \\\"\\\"), -28, 11), \\u3056: []}, {NaN}], [d, , [\\u0009(\\\"\\\\uB219\\\")], z, [, {z: [], c: x, z: {a: []}}]], , \\u0009] = [{}, f2, , , {f2: {a: [, {}], NaN: f2}, NaN: {NaN: x, d}, f2, /*MARR*/[undefined,  'A' ,  'A' , objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' ], x}, ]\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-94431925*/count=1490; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:$+)/gyi; var s = \"\\n\\ua3fa\\n\\n\\ua3fa\\n\"; print(r.exec(s)); ");
/*fuzzSeed-94431925*/count=1491; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.log2(Math.fround((Math.fround(-(2**53)) === Math.fround(Math.acos(( + -(2**53-2)))))))); }); testMathyFunction(mathy0, [0x100000001, 1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 2**53+2, 0/0, 42, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, 0x100000000, Math.PI, 1.7976931348623157e308, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, -1/0, 1, -0x100000000, 2**53-2, -Number.MAX_VALUE, -0, -0x080000001, -0x100000001]); ");
/*fuzzSeed-94431925*/count=1492; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.sqrt((((((((Math.imul(Math.atan2(y, Math.min(( + 0x07fffffff), ( + (y ? ( + x) : ( + y))))), (x | 0)) | 0) | 0) > ( + Math.cbrt(Math.fround(x)))) >>> 0) >>> 0) || mathy0((Math.asinh(Math.hypot(y, Math.fround(Math.log2(( + y))))) >>> 0), (x ? y : Math.fround(Math.tanh(x))))) | 0)); }); ");
/*fuzzSeed-94431925*/count=1493; tryItOut("delete h1.has;");
/*fuzzSeed-94431925*/count=1494; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.fround(( + Math.fround((( - Math.atan2(y, x)) >>> 0)))); }); testMathyFunction(mathy0, [0, 1, 2**53-2, -0x0ffffffff, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 2**53+2, 42, Math.PI, 1/0, 0x100000000, -0x080000000, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, -0, 0x080000001, 0x080000000, Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE, -0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, 0/0, -0x080000001]); ");
/*fuzzSeed-94431925*/count=1495; tryItOut("g0.__proto__ = g1.p1;");
/*fuzzSeed-94431925*/count=1496; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.asin(Math.fround(Math.cbrt((Math.log1p(Math.fround(Math.min(Math.fround((( ! (( + (y - y)) >>> 0)) >>> 0)), Math.fround(Math.atan2(Math.hypot(y, y), x))))) | 0))))); }); testMathyFunction(mathy3, [0x080000001, 2**53+2, 0x100000001, -0, 0, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, -1/0, -0x080000000, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, 0x100000000, 1, 42, 2**53-2, -0x080000001, 0x080000000, Number.MAX_VALUE, Math.PI, 0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 0/0, 1/0, -(2**53+2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1497; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.hypot((((Math.log10((Math.atan2((((0x080000000 >>> 0) != ( + Math.fround(( + y)))) >>> 0), y) | 0)) >>> 0) !== (Math.fround(Math.acos(Math.fround(Math.fround(mathy0((Math.imul(( + Math.pow(Math.fround(y), Math.fround(x))), (( - -(2**53)) | 0)) | 0), Math.atan2(( - -0x080000001), y)))))) >>> 0)) >>> 0), (Math.pow(((mathy0(-Number.MIN_VALUE, ((x != (Math.max(y, x) | 0)) | 0)) ? mathy0(42, y) : (( ~ (Math.hypot((( - ( + Math.max(x, y))) | 0), (y >>> 0)) | 0)) | 0)) >>> 0), (Math.pow(( ! (((Math.sin((0.000000000000001 >>> 0)) >>> 0) || x) | 0)), ( + (((y * Math.fround(y)) >>> 0) != ( + ( ! y))))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-94431925*/count=1498; tryItOut("h2.enumerate = (function() { try { this.f2(t0); } catch(e0) { } try { t2.toSource = (function(j) { f1(j); }); } catch(e1) { } s1 = s2.charAt(v0); return p2; });");
/*fuzzSeed-94431925*/count=1499; tryItOut("o0.s1 = '';");
/*fuzzSeed-94431925*/count=1500; tryItOut("\"use strict\"; ( \"\"  + ((let (e=eval) e)).call(null, ));");
/*fuzzSeed-94431925*/count=1501; tryItOut("var afunku = new ArrayBuffer(8); var afunku_0 = new Float32Array(afunku); afunku_0[0] = 25; var afunku_1 = new Int32Array(afunku); afunku_1[0] = -25; var afunku_2 = new Float64Array(afunku); afunku_2[0] = 14; var afunku_3 = new Float64Array(afunku); print(afunku_3[0]); afunku_3[0] = 27; var afunku_4 = new Int16Array(afunku); print(afunku_4[0]); var afunku_5 = new Float32Array(afunku); print(afunku_5[0]); var afunku_6 = new Uint8Array(afunku); var afunku_7 = new Float64Array(afunku); print(afunku_7[0]); afunku_7[0] = 8; var afunku_8 = new Int8Array(afunku); t1 = new Int8Array(b0);print(uneval(v0));const x, afunku = (0/0), afunku_7, gyjslz, x = undefined, NaN, getter, afunku_0[9], ldbaon;for (var p in h0) { try { this.v2 = new Number(4.2); } catch(e0) { } this.g1.a1 = a2.filter((function(j) { if (j) { v2 = t1.length; } else { try { for (var v of g2) { try { for (var v of a1) { try { o1.t2.set(t2, 2); } catch(e0) { } try { v2.__proto__ = t1; } catch(e1) { } Array.prototype.forEach.call(a1, (function() { try { o2 + ''; } catch(e0) { } t2.set(t1, \"\\u85F5\"); throw o1; })); } } catch(e0) { } try { g0.h2.keys = (function() { f0(e0); return v1; }); } catch(e1) { } try { t2[13] = h0; } catch(e2) { } for (var p in p0) { v2 = Object.prototype.isPrototypeOf.call(v0, a2); } } } catch(e0) { } v1 = e1[\"wrappedJSObject\"]; } }), i1); }");
/*fuzzSeed-94431925*/count=1502; tryItOut("t0 = t1.subarray(19);");
/*fuzzSeed-94431925*/count=1503; tryItOut("testMathyFunction(mathy3, [0x080000000, Number.MIN_SAFE_INTEGER, -1/0, 2**53, 2**53+2, -0x07fffffff, 1, 2**53-2, -Number.MIN_VALUE, -(2**53+2), 0x080000001, 0x100000001, 0.000000000000001, -Number.MAX_VALUE, -0x080000000, 1/0, -(2**53-2), Number.MIN_VALUE, 0x07fffffff, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -0x100000000, 0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, Math.PI, -0, -(2**53), 0/0]); ");
/*fuzzSeed-94431925*/count=1504; tryItOut("s1 = a1.join(s2);");
/*fuzzSeed-94431925*/count=1505; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), -0x100000000, -(2**53+2), 2**53-2, 1, Number.MAX_VALUE, -0, -0x07fffffff, 0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, 0x080000001, 0/0, 42, -1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, Number.MIN_VALUE, Math.PI, 0.000000000000001, 0, -0x0ffffffff, 1/0, 0x0ffffffff, 2**53+2, -Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1506; tryItOut("/*vLoop*/for (otbzst = 0; otbzst < 80; \"\\u1247\", ++otbzst) { const x = otbzst; /*RXUB*/var r = r0; var s = s0; print(s.match(r));  } ");
/*fuzzSeed-94431925*/count=1507; tryItOut(";");
/*fuzzSeed-94431925*/count=1508; tryItOut("/* no regression tests found */");
/*fuzzSeed-94431925*/count=1509; tryItOut("\"use strict\"; s1 + m2;");
/*fuzzSeed-94431925*/count=1510; tryItOut("this.v0 = false;");
/*fuzzSeed-94431925*/count=1511; tryItOut("{} = (NaN), x = w = \"\\uE18E\", pdtfcn, axtoah, w, x, y;(false);(window);");
/*fuzzSeed-94431925*/count=1512; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - ((Math.asinh(((( + Math.imul((1 ? x : y), (mathy2(y, ( + x)) | 0))) * Math.hypot(y, 1/0)) | 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1.7976931348623157e308, 2**53, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, Number.MAX_VALUE, 0.000000000000001, 0x100000001, 1/0, 2**53-2, Number.MIN_VALUE, 1, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -0, 42, -(2**53+2), -0x080000000, 0x100000000, -(2**53-2), 0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -0x07fffffff, -(2**53), 0x07fffffff, -1/0, 0, -0x100000001, 0/0]); ");
/*fuzzSeed-94431925*/count=1513; tryItOut("\"use strict\"; ");
/*fuzzSeed-94431925*/count=1514; tryItOut("t2.set(t2, 2);");
/*fuzzSeed-94431925*/count=1515; tryItOut("\"use strict\"; x;");
/*fuzzSeed-94431925*/count=1516; tryItOut("\"use strict\"; for(var e in (((void version(180)))((b) = Math.acos(-26)))){a2.reverse(a0); }");
/*fuzzSeed-94431925*/count=1517; tryItOut("modbpj(/*MARR*/[ /x/g ,  /x/ , new Number(1.5),  /x/ , new Number(1.5), {}, {},  /x/ , (-1/0),  /x/g , {},  /x/ , (-1/0), (-1/0), new Number(1.5), (-1/0), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), {},  /x/ , new Number(1.5), {}, {},  /x/ , (-1/0),  /x/g , new Number(1.5), (-1/0), new Number(1.5),  /x/ , {}, new Number(1.5),  /x/ ,  /x/ , {},  /x/ , {}, (-1/0), (-1/0), {},  /x/g ,  /x/g , new Number(1.5),  /x/g , (-1/0),  /x/g , {},  /x/g ,  /x/ , (-1/0),  /x/ ,  /x/g , new Number(1.5), {},  /x/g ].some(function shapeyConstructor(ricgqv){Object.preventExtensions(ricgqv);ricgqv[\"caller\"] =  /x/ ;Object.defineProperty(ricgqv, \"sqrt\", ({}));delete ricgqv[\"0\"];for (var ytqofjeyf in ricgqv) { }ricgqv[\"0\"] = [1].log;if (ricgqv) Object.freeze(ricgqv);ricgqv[\"0\"] = this;{ for (var v of g0) { try { print(g2); } catch(e0) { } try { s1.__proto__ = a1; } catch(e1) { } v2 + ''; } } return ricgqv; }/*tLoopC*/for (let d of []) { try{let etiwzu = new shapeyConstructor(d); print('EETT'); (this);}catch(e){print('TTEE ' + e); } },  '' ), (--w));/*hhh*/function modbpj(){/* no regression tests found */}");
/*fuzzSeed-94431925*/count=1518; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 1, -1/0, 1/0, 2**53, -0x080000000, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, 42, -0x100000000, 0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 0x07fffffff, 0x100000000, -0, -Number.MAX_VALUE, 0x0ffffffff, 2**53-2, -(2**53-2), 0/0, -0x080000001, 0x080000001]); ");
/*fuzzSeed-94431925*/count=1519; tryItOut("\"use strict\"; (d = window)if(false) {{for (var p in g2) { try { a0[12] = null; } catch(e0) { } try { g1.v0 = evaluate(\"function f1(m2)  { \\\"use strict\\\"; yield x } \", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: window, catchTermination: true })); } catch(e1) { } try { v0 = true; } catch(e2) { } v1 = evaluate(\"function f2(h2)  { \\\"use strict\\\"; \\\"use asm\\\"; (c\\u000c); } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval:  /x/ , sourceIsLazy: (x % 2 != 0), catchTermination: new RegExp(\"\\\\B+|((?!(?=\\\\b)))\", \"yim\"), elementAttributeName: s2, sourceMapURL: o1.s0 })); }print(g0); }/*tLoop*/for (let a of /*MARR*/[ /x/g , (void 0), x,  /x/g , x, x, (void 0),  /x/g ,  /x/g ,  /x/g , x, x,  /x/g , (void 0),  /x/g , x, (void 0), x,  /x/g , (void 0),  /x/g , (void 0),  /x/g , x, x,  /x/g ,  /x/g , (void 0), x, (void 0),  /x/g , x, x, x,  /x/g , x, x, x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (void 0),  /x/g ,  /x/g , (void 0), x,  /x/g ,  /x/g ,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g , (void 0), x,  /x/g ,  /x/g , (void 0),  /x/g , x, x, (void 0), x, x, (void 0), (void 0), (void 0), (void 0), (void 0), x, x,  /x/g , (void 0), x,  /x/g , (void 0),  /x/g ,  /x/g ,  /x/g , x,  /x/g , (void 0),  /x/g , x,  /x/g ,  /x/g , (void 0), x,  /x/g ,  /x/g , (void 0), (void 0), (void 0),  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g , x, (void 0), x,  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g , (void 0),  /x/g , (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x]) { a0.splice(-7, 7, a0, m1, this.h1, this.g0); }( \"\" ); } else  if (new RegExp(\"(?![\\\\W\\uab7f\\\\uEee0]{2})[^]*\", \"gim\") ? x : b) {do {;o1.h2.get = g0.f0; } while(([1]\u0009) && 0); }");
/*fuzzSeed-94431925*/count=1520; tryItOut("o2.g2.v2 = (t1 instanceof e2);");
/*fuzzSeed-94431925*/count=1521; tryItOut("\"use strict\"; function f2(f1) \"use asm\";   var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    i3 = (i1);\n    (Int8ArrayView[0]) = ((0xf8ca55e4)*-0x8a31c);\n    i1 = (0xf5feab26);\n    {\n      i2 = (i2);\n    }\n    (Float64ArrayView[0]) = ((-8796093022208.0));\n    return ((( /* Comment */Math.max(x, this)) instanceof  /x/  >= true))|0;\n  }\n  return f;");
/*fuzzSeed-94431925*/count=1522; tryItOut("/*ODP-3*/Object.defineProperty(e1, \"concat\", { configurable: false, enumerable: true, writable: false, value: b0 });");
/*fuzzSeed-94431925*/count=1523; tryItOut("mathy3 = (function(x, y) { return (Math.hypot((( ~ (( ! Math.fround(mathy0((y >>> 0), Math.fround(( + Math.atan2(y, (-0 >>> 0))))))) >>> 0)) | 0), ( + Math.min((( + ( + Math.hypot(( + (((Math.round(x) >>> 0) >= (42 | 0)) | 0)), 0x080000000))) ^ (((x | 0) + ( + (-0x100000001 < x))) ? x : x)), (-Number.MIN_SAFE_INTEGER < (x ? Math.imul((Math.fround(mathy0(Math.fround(x), Math.fround(x))) | 0), x) : y))))) | 0); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, 42, 2**53-2, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 0x07fffffff, -(2**53), -0x080000000, 0x0ffffffff, Math.PI, 2**53, 0x080000001, 0.000000000000001, 1/0, 0/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0, -0, 0x100000000, -1/0, -0x100000001, -(2**53+2), 1, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 0x080000000, -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1524; tryItOut("v0 = (t1 instanceof s1);");
/*fuzzSeed-94431925*/count=1525; tryItOut("b0.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) { var r0 = a10 - a8; a4 = a0 | x; a6 = x / a4; var r1 = 1 % 3; a1 = a6 * r0; a4 = a0 + a5; var r2 = 2 + a0; var r3 = a5 | 0; print(a7); return a0; });function x(...a) { \"use asm\"; print(x); } a0 = ((/((?:\\u266f)){1,}*?/gi).apply.prototype if (\"\\uFA9F\"));Array.prototype.shift.call(a1, v1);");
/*fuzzSeed-94431925*/count=1526; tryItOut("\"use strict\"; Array.prototype.pop.call(a0);\nfalse;function x()[]( \"\" );\n");
/*fuzzSeed-94431925*/count=1527; tryItOut("const a = allocationMarker(), eval = Math && Object.defineProperty(o1, \"o2\", { configurable: true, enumerable: false,  get: function() {  return {}; } }); += , a = /*UUV1*/(e.unshift = function shapeyConstructor(jjfnky){jjfnky[\"__proto__\"] = (DFGTrue).apply;jjfnky[\"__proto__\"] =  /x/g ;return jjfnky; }), c, x;Array.prototype.sort.apply(a1, [f1]);");
/*fuzzSeed-94431925*/count=1528; tryItOut("/*oLoop*/for (var zegzcq = 0; ((4277).unwatch(\"callee\")) && zegzcq < 0; ++zegzcq) { m0.set((4277), o1.t2); } ");
/*fuzzSeed-94431925*/count=1529; tryItOut("\"use strict\"; t0 = new Uint8Array(11);");
/*fuzzSeed-94431925*/count=1530; tryItOut("g0.offThreadCompileScript(\"a1 = [];\");");
/*fuzzSeed-94431925*/count=1531; tryItOut("mathy4 = (function(x, y) { return ((Math.trunc((((((x | 0) >= (( + Math.hypot(( + y), Math.fround(Math.pow(Math.fround(x), y)))) | 0)) | 0) === (((x | 0) * (mathy0((y | 0), ((mathy3((x | 0), (x | 0)) | 0) | 0)) | 0)) | 0)) >>> 0)) >>> 0) ? (Math.max((Math.max(((x ? x : ( ! x)) >>> 0), (( ~ (mathy1(Math.hypot(y, (-(2**53) >>> 0)), x) >>> 0)) | 0)) ? y : Math.cbrt(Math.atan2(x, ( ~ x)))), (( - ( + Math.imul(( + x), ( + ( ~ x))))) >>> 0)) >>> 0) : Math.imul(Math.expm1(( - y)), ((x <= ( + (((x >>> 0) > (y >>> 0)) >>> 0))) < y))); }); testMathyFunction(mathy4, [1, Number.MAX_SAFE_INTEGER, 2**53+2, 42, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 1/0, -0x080000001, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0x080000000, 0x07fffffff, -Number.MAX_VALUE, 2**53, 0x100000000, 2**53-2, 0x080000001, 0.000000000000001, -1/0, -0x0ffffffff, -(2**53-2), -0, Math.PI, -(2**53), 0x0ffffffff, -0x100000001, Number.MIN_VALUE, 0/0, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1532; tryItOut("\"use strict\"; v2 + p0;");
/*fuzzSeed-94431925*/count=1533; tryItOut("h0.keys = (function() { try { function f0(b2)  { yield new (encodeURIComponent)() }  } catch(e0) { } Array.prototype.sort.apply(a1, [(function() { try { delete o0.h1.fix; } catch(e0) { } try { s1 = ''; } catch(e1) { } try { this.b0 = new ArrayBuffer(30); } catch(e2) { } v0 = o1.g2.eval(\"s2 += s2;\"); return b1; }), o2.a1, v0]); return o0; });");
/*fuzzSeed-94431925*/count=1534; tryItOut("m2.get( /x/ );");
/*fuzzSeed-94431925*/count=1535; tryItOut("m1.delete(g1);");
/*fuzzSeed-94431925*/count=1536; tryItOut("NaN = linkedList(NaN, 5782);");
/*fuzzSeed-94431925*/count=1537; tryItOut("this.v2 = Object.prototype.isPrototypeOf.call(f2, t1);");
/*fuzzSeed-94431925*/count=1538; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.fround(Math.asinh((Math.abs((y >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, 2**53+2, -0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, 0/0, -1/0, 0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, 1, 0.000000000000001, 1/0, -(2**53), 1.7976931348623157e308, -(2**53-2), -0x080000001, 0x080000001, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 0, -0x0ffffffff, Number.MAX_VALUE, -0x100000001, 0x0ffffffff, 42, 2**53, Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-94431925*/count=1539; tryItOut("testMathyFunction(mathy2, [-0x07fffffff, 2**53-2, 0x0ffffffff, 0, -0x100000001, -0x080000000, Number.MAX_VALUE, 0x07fffffff, 0x080000001, -0x080000001, 2**53+2, 0x080000000, -1/0, -(2**53), 2**53, 0/0, -(2**53-2), 1, Math.PI, -Number.MAX_VALUE, 0.000000000000001, -0, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, -Number.MIN_SAFE_INTEGER, 42]); ");
/*fuzzSeed-94431925*/count=1540; tryItOut("print( /x/g );");
/*fuzzSeed-94431925*/count=1541; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.cosh(Math.fround(y))) ** (Math.min(Math.min(y, 0.000000000000001), ( ! x)) ? Math.cos(( + (((( + 0x0ffffffff) >> (0x100000001 | 0)) | 0) >>> 0))) : Math.fround(( - ( + y))))) !== (Math.max(( + (Math.asin(x) || Math.tanh(x))), ( + Math.max(x, (Math.fround((Math.fround(-(2**53-2)) / Math.fround(( + ((x >>> 0) * ( + Number.MIN_SAFE_INTEGER)))))) | 0)))) ** (y + Math.max(-Number.MAX_SAFE_INTEGER, (Math.pow(y, (y >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-94431925*/count=1542; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(g1, m0);");
/*fuzzSeed-94431925*/count=1543; tryItOut("");
/*fuzzSeed-94431925*/count=1544; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i2, a1);");
/*fuzzSeed-94431925*/count=1545; tryItOut("\"use strict\"; ");
/*fuzzSeed-94431925*/count=1546; tryItOut("/*ODP-2*/Object.defineProperty(f0, \"5\", { configurable: true, enumerable: (yield (new Uint16Array((( + ( ~ ( + -1/0)))).unwatch(\"wrappedJSObject\")))), get: (function() { try { m0.delete(g0); } catch(e0) { } t2 + f2; return t1; }), set: (function(j) { f2(j); }) });");
/*fuzzSeed-94431925*/count=1547; tryItOut("mathy1 = (function(x, y) { return (Math.acosh(Math.atan(mathy0((Math.trunc((Math.asinh(Math.fround(((x | 0) && y))) | 0)) | 0), Math.fround(Math.sinh((mathy0((Math.pow((Math.atanh(0) | 0), Math.fround(Number.MAX_VALUE)) >>> 0), 0) | 0)))))) | 0); }); testMathyFunction(mathy1, [0, -Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, 0.000000000000001, 2**53, -0, 1, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 0x100000000, 2**53-2, 2**53+2, -Number.MIN_VALUE, -(2**53-2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 0x100000001, 0x07fffffff, -0x0ffffffff, -(2**53), -0x080000000, 0/0, -1/0, 1.7976931348623157e308, -(2**53+2), 0x080000001, -0x100000001]); ");
/*fuzzSeed-94431925*/count=1548; tryItOut("testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-94431925*/count=1549; tryItOut("\"use asm\"; f2(o0);");
/*fuzzSeed-94431925*/count=1550; tryItOut("\"use strict\"; e1.delete(b1);");
/*fuzzSeed-94431925*/count=1551; tryItOut("\"use strict\"; testMathyFunction(mathy3, [1, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0/0, 1.7976931348623157e308, -0x0ffffffff, 0x0ffffffff, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, 42, -Number.MAX_VALUE, -0x100000000, 0x080000000, 0x080000001, 1/0, 0.000000000000001, -(2**53-2), -0x100000001, 0, 2**53-2, 2**53, -0x080000001, -0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-94431925*/count=1552; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow(mathy0(( + (Math.fround(mathy0(y, (Math.max(x, (x | 0)) | 0))) >>> Math.trunc(( + ( + Math.hypot(( + -0x07fffffff), ( + y))))))), (y ? (Math.pow((Math.expm1(Math.max(y, (y >>> 0))) | 0), (( ! y) | 0)) | 0) : (mathy0(Math.pow(y, y), Math.acos(x)) < (1.7976931348623157e308 || Math.fround((Math.cos((-Number.MIN_SAFE_INTEGER | 0)) | 0)))))), (Math.max((Math.cos((((Math.tanh((x | 0)) | 0) | 0) && ( + Math.min(y, x)))) >>> 0), (Math.sin(y) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0x080000000, -0x100000000, Math.PI, 1.7976931348623157e308, 2**53+2, 0x080000001, 0x0ffffffff, -0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, -(2**53-2), Number.MAX_VALUE, 1/0, 0x100000000, -0x080000001, 0x080000000, 1, -Number.MAX_VALUE, -0x0ffffffff, 42, 0/0, 0x100000001, 0x07fffffff, -1/0, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 0]); ");
/*fuzzSeed-94431925*/count=1553; tryItOut("\"use strict\"; ");
/*fuzzSeed-94431925*/count=1554; tryItOut("\"use strict\"; /*hhh*/function tcgkvf(){/*RXUB*/var r = new RegExp(\".\", \"im\"); var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); }tcgkvf();");
/*fuzzSeed-94431925*/count=1555; tryItOut("g1 = this;\n/*oLoop*/for (xwhdva = 0; xwhdva < 18; ++xwhdva) { Object.preventExtensions(b2); } \n");
/*fuzzSeed-94431925*/count=1556; tryItOut("\"use strict\"; /*oLoop*/for (sqbkqo = 0, y; sqbkqo < 56; ++sqbkqo) { { void 0; deterministicgc(true); } v0 = g2.eval(\"/*MXX3*/g0.URIError = g0.URIError;\"); } ");
/*fuzzSeed-94431925*/count=1557; tryItOut("\"use asm\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      (Float32ArrayView[0]) = ((d1));\n    }\n    d1 = (+/*FFI*/ff(((d1)), (x.unwatch(\"2\")), ((0x62915996)), ((d1)), ((-0.0078125)), ((d1)), ((d1)), (((Float64ArrayView[0]))), ((((-35184372088833.0)) - ((-1.888946593147858e+22)))), ((18014398509481984.0)), ((131073.0)), ((-590295810358705700000.0)), ((262143.0)), ((5.0)), ((-128.0)), ((262145.0)), ((268435455.0)), ((513.0)), ((-32769.0)), ((134217729.0)), ((32769.0)), ((-65537.0)), ((590295810358705700000.0)), ((-65.0)), ((140737488355327.0)), ((-3.094850098213451e+26)), ((-256.0))));\n    i0 = (-0x8000000);\n    return +(intern(window));\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: Promise.reject, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: undefined, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: e, keys: function() { return Object.keys(x); }, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -0, 0x100000000, -Number.MAX_VALUE, -1/0, 2**53-2, -0x07fffffff, -0x0ffffffff, -(2**53+2), -0x080000000, 0x07fffffff, 0x080000000, 2**53+2, 1, 2**53, 42, -(2**53-2), Math.PI, 1.7976931348623157e308, -(2**53), 0x100000001, -0x100000000, 0/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0, 0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1558; tryItOut("return;for (var p in o0) { try { Array.prototype.shift.apply(a2, [v0, e0, s1, v2]); } catch(e0) { } try { v1 = evalcx(\"x;\", g1); } catch(e1) { } function f0(f0)  { f2 + o0; }  }");
/*fuzzSeed-94431925*/count=1559; tryItOut("let xrrnfm, window, b, x, acwssu, catch;/*ODP-2*/Object.defineProperty(g0.a1, \"wrappedJSObject\", { configurable: (x % 5 != 4), enumerable: true, get: this, set: (function(j) { if (j) { try { Object.defineProperty(this, \"v2\", { configurable: false, enumerable: -21,  get: function() { s2 = ''; return evalcx(\"/* no regression tests found */\", g2); } }); } catch(e0) { } g1.v1 = o0.b1.byteLength; } else { try { ; } catch(e0) { } try { t2 = new Int8Array(t0); } catch(e1) { } try { g1.offThreadCompileScript(\"x = v2;\"); } catch(e2) { } e0.delete(g2); } }) });");
/*fuzzSeed-94431925*/count=1560; tryItOut("o1.v1 = evalcx(\"x\", g2.g0);");
/*fuzzSeed-94431925*/count=1561; tryItOut("a2.pop();");
/*fuzzSeed-94431925*/count=1562; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.tan(( + Math.fround(( ~ Math.fround(((( + (( ! x) != ( + -0x0ffffffff))) | 0) | 0x07fffffff))))))); }); testMathyFunction(mathy0, [-(2**53-2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, 0x100000001, -0x080000000, Number.MAX_VALUE, 0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -0x100000000, 0/0, 1/0, -(2**53), -Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, 2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 1, Math.PI, 2**53, 0x080000001, 0, -0x080000001]); ");
/*fuzzSeed-94431925*/count=1563; tryItOut("mathy5 = (function(x, y) { return ((( + Math.fround((y != (( + Math.pow(( + x), -0)) | 0)))) >>> 0) >>> (Math.cos(Math.pow(( + (y ? (x | 0) : (( + x) ? ( + 42) : x))), ( + (( + Number.MAX_SAFE_INTEGER) >>> Math.cos(Math.fround(( ~ Math.fround((Math.asinh((y | 0)) | 0))))))))) >>> 0)); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, 0x100000001, -0x100000001, 2**53+2, 0x080000000, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), 0x07fffffff, Math.PI, -0x080000001, 2**53, 1/0, Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, -0, -(2**53+2), 0x080000001, -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, -(2**53-2), 2**53-2, Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-94431925*/count=1564; tryItOut("s1 = Array.prototype.join.call(a2, this.s0, this.b1);");
/*fuzzSeed-94431925*/count=1565; tryItOut("Array.prototype.sort.apply(o2.a0, [(function(j) { if (j) { try { o1.s0 += 'x'; } catch(e0) { } try { o1 = a0[(4277)]; } catch(e1) { } o0.o0 = {}; } else { try { ; } catch(e0) { } Array.prototype.shift.apply(a1, [h2]); } }), a1]);");
/*fuzzSeed-94431925*/count=1566; tryItOut("m2.delete(s2);");
/*fuzzSeed-94431925*/count=1567; tryItOut("/*hhh*/function tnnalf(){m2 = new WeakMap;}tnnalf();");
/*fuzzSeed-94431925*/count=1568; tryItOut("\"use strict\"; v1 = (g0.m1 instanceof s2);");
/*fuzzSeed-94431925*/count=1569; tryItOut("v0 + '';");
/*fuzzSeed-94431925*/count=1570; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=.\\\\ufEbA{2}|\\\\2*?^)*|(?=(?!.|(?:.+)){4194305,})\\\\D\", \"yi\"); var s = \"\\n\\ufeba\\n\\ufeba\\u00da\\ufeba\\u00da\\ufeba\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-94431925*/count=1571; tryItOut("v0 = NaN;");
/*fuzzSeed-94431925*/count=1572; tryItOut("for (var v of g2) { ; }");
/*fuzzSeed-94431925*/count=1573; tryItOut("\"use asm\";  for (let w of (4277)) {yield; }");
/*fuzzSeed-94431925*/count=1574; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[(void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), (void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), (void 0), (void 0), (void 0), new Boolean(true), (void 0), (void 0), new Boolean(true), new Boolean(true), (void 0), (void 0), (void 0), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(true), (void 0), (void 0), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), (void 0), new Boolean(true), new Boolean(true), (void 0), (void 0), (void 0), (void 0), new Boolean(true), (void 0)]) { \"\\u0439\"; }");
/*fuzzSeed-94431925*/count=1575; tryItOut("mathy4 = (function(x, y) { return (((Math.pow((Math.atan2(Math.fround(-(2**53)), Math.fround(( ~ ( ~ 0/0)))) | 0), (y | 0)) | 0) ? Math.fround(mathy1(Math.fround(Math.max(0x100000000, (( ! (-(2**53-2) >>> 0)) >>> 0))), (((0x100000001 | 0) == (0x0ffffffff >>> 0)) | 0))) : ( + ( ~ ( + Math.min(x, y))))) || Math.fround(Math.fround(( + (Math.fround(Math.trunc(Math.fround(( + ( - ( + x)))))) >>> 0))))); }); ");
/*fuzzSeed-94431925*/count=1576; tryItOut("v2 = (g2 instanceof e0);");
/*fuzzSeed-94431925*/count=1577; tryItOut("\"use strict\"; s0 = s0.charAt(window.__defineGetter__(\"a\", function (x, this = null) /x/g ));");
/*fuzzSeed-94431925*/count=1578; tryItOut("\"use strict\"; if(false) {h2 + o2; } else switch(x) { default: yield (y &= y);break; case 6: print(x);case 0:  }");
/*fuzzSeed-94431925*/count=1579; tryItOut("m0 = new Map(t1);");
/*fuzzSeed-94431925*/count=1580; tryItOut("v2 = (p2 instanceof o0.f0);");
/*fuzzSeed-94431925*/count=1581; tryItOut("o1.t0 = t0.subarray((4277), x);");
/*fuzzSeed-94431925*/count=1582; tryItOut("mathy3 = (function(x, y) { return mathy2(mathy1(Math.atan2(y, (( - Math.sin(-Number.MIN_VALUE)) >>> 0)), (Math.min(((Math.round((((Math.atan2(Number.MAX_VALUE, (Math.ceil(-Number.MIN_SAFE_INTEGER) | 0)) | 0) == y) | 0)) | 0) | 0), ((x * ( ~ y)) >>> 0)) | 0)), ((Math.fround((Math.fround((( - (y | 0)) | 0)) / (( + 0/0) >>> 0))) | 0) != Math.fround(((Math.atan2((( + ( ! (( ~ y) >>> 0))) | 0), (((Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround((-0 & (x | 0))))) == Math.fround(x)) >>> 0) | 0)) << y) >>> 0)))); }); testMathyFunction(mathy3, [0x0ffffffff, 1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, 1, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, 0/0, 0x07fffffff, 2**53-2, -0x080000000, -(2**53), 0x100000001, -Number.MIN_VALUE, 2**53+2, 42, -0x100000001, -1/0, -0x100000000, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, Math.PI, 0.000000000000001, 2**53, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-94431925*/count=1583; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"return function(id) { return id };\");function x(...x) { yield (x.throw((b)%=Math.max(-14, x))) } /*vLoop*/for (var ssvihv = 0; ssvihv < 2; ++ssvihv) { let d = ssvihv; print(x); } ");
/*fuzzSeed-94431925*/count=1584; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!\\W*\\S)|(?!(?=(?![^\\b-\\cS\u008b-\\\u2f6f]{0,0}|(?!\\u005C)))|\u00e0|\\f+?)|(?!(?:(?=(([^\\r\\xCd\\D])))))(?!((?:[^\\x86-\\u759F\\S\u00a9]|\\\uf275)))|([^])/ym; var s = \"\"; print(s.replace(r, (s, e, ...w) => \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((((((((0x107c29f))>>>((0xb49b0e80))) % (((0xae32c32d))>>>((-0x8000000)))) << (((-0x7409b3a) <= (0x7194d768))))) ? (d0) : (((0x64b82dd4)+(0x18ee1063)))));\n  }\n  return f;)); ");
/*fuzzSeed-94431925*/count=1585; tryItOut("for (var v of e0) { try { for (var v of this.p2) { v1 = g1.runOffThreadScript(); } } catch(e0) { } try { function f1(i1)  { yield (({e: [[]], x: {b: [, [, [], ], {i1: [, this.y], z: [], i1: []}]}, i1: {a: [{window: d, NaN, eval}, a], z: getter, a, x: [, , [], x], b: window}} = {i1: []} = (4277) << OSRExit(3.141592653589793,  /x/g ))) }  } catch(e1) { } Array.prototype.shift.call(a1); }");
/*fuzzSeed-94431925*/count=1586; tryItOut("b0 = t2.buffer;");
/*fuzzSeed-94431925*/count=1587; tryItOut("");
/*fuzzSeed-94431925*/count=1588; tryItOut("\"use strict\"; Array.prototype.pop.call(this.a1);\nprint(x);\n");
/*fuzzSeed-94431925*/count=1589; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(( - Math.fround(Math.fround((((-0x080000001 || -(2**53)) >>> 0) + (( - Math.imul(x, y)) | 0)))))) & (( + (((y ? x : (( ~ Math.fround(y)) >>> 0)) | 0) >> (Math.asin(1.7976931348623157e308) | 0))) >>> 0)); }); testMathyFunction(mathy2, [-(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, 0, 0x0ffffffff, 2**53-2, -0, 2**53, 0x100000001, 2**53+2, -0x080000000, 0x080000001, Number.MAX_VALUE, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, Math.PI, 1, 42, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 0x100000000, -0x100000001, 0/0, -(2**53), 0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-94431925*/count=1590; tryItOut("mathy1 = (function(x, y) { return ( + ((Math.max((( + mathy0(-0x100000000, (1/0 <= y))) >>> ( ~ (Math.pow(y, (y >>> 0)) >>> 0))), mathy0(( + ( + 1/0)), ( + ( + (( + y) ** ( + y)))))) | 0) !== ((Math.pow((( + Math.fround(Math.atan2(Math.ceil(Math.hypot(x, y)), y))) >>> 0), ((Math.pow((( - x) / y), (y << x)) * Math.max(y, x)) >>> 0)) | 0) | 0))); }); testMathyFunction(mathy1, [-1/0, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, 1.7976931348623157e308, -0x0ffffffff, 42, 0x100000000, -0, 2**53, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0x080000001, 2**53+2, 1/0, 0/0, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, -(2**53-2), 0x080000001, 0x0ffffffff, -(2**53+2), -0x080000000, -0x07fffffff, 1, -0x100000001, -0x100000000, 2**53-2]); ");
/*fuzzSeed-94431925*/count=1591; tryItOut("mathy0 = (function(x, y) { return ((( ~ Math.fround(Math.imul(( + y), ( + x)))) > (( ~ Math.fround((0x07fffffff >> (y < y)))) >>> y)) ? Math.fround(Math.cosh((Math.max(Math.sinh(Math.pow(x, -(2**53))), ( + ( ! ( + y)))) ? ( + Math.hypot((Math.sign(y) | 0), ( + x))) : Math.hypot((x != Math.imul(y, x)), y)))) : (( + Math.acosh(((2**53 ? y : y) <= (Math.imul(x, (x >>> 0)) >>> 0)))) << (Math.fround(Math.trunc(Math.expm1((((x >>> 0) <= ((x ^ x) >>> 0)) >>> 0)))) != Math.fround(Math.atanh((((-0x07fffffff | 0) + -0x0ffffffff) | 0)))))); }); ");
/*fuzzSeed-94431925*/count=1592; tryItOut("v2 = g1.runOffThreadScript();");
/*fuzzSeed-94431925*/count=1593; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return ( + ( ! ( + (Math.round((( ~ Math.hypot(Math.fround(Math.pow(y, -0x07fffffff)), Math.atan2(Math.exp((Math.log1p((x | 0)) | 0)), y))) | 0)) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), new String('q'), new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), /(\\D?\\1)|(?:[^\\xC7\n-\uff7a])*\\t*/i]); ");
/*fuzzSeed-94431925*/count=1594; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-94431925*/count=1595; tryItOut("v2 = Object.prototype.isPrototypeOf.call(v0, b1);");
/*fuzzSeed-94431925*/count=1596; tryItOut("mathy4 = (function(x, y) { return ( + Math.hypot(Math.fround(( ! Math.pow((Math.sqrt(((0x07fffffff | 0) + Math.fround(-Number.MAX_SAFE_INTEGER))) >> ( ~ y)), (( + (Math.fround(y) , ( + Math.imul(2**53, Math.pow(mathy2(x, y), ((x >>> 0) !== x)))))) >>> 0)))), Math.fround((Math.asin(Math.fround(Math.exp(( - Math.max(Math.fround(1/0), Math.fround(42)))))) >>> 0)))); }); ");
/*fuzzSeed-94431925*/count=1597; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy5, [-0x07fffffff, 2**53, -(2**53-2), 1/0, -0x080000000, 0, 0x100000001, 2**53+2, -(2**53), 0x07fffffff, 0x080000001, 0x0ffffffff, 2**53-2, 42, 0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000000, 1, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, 0/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, -1/0, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-94431925*/count=1598; tryItOut("this;");
/*fuzzSeed-94431925*/count=1599; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:^){134217728}\", \"gyi\"); var s = \"\\n\\u0003\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(s.match(r))); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
