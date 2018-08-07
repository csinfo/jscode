

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
/*fuzzSeed-42369751*/count=1; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1/gy; var s = \"\"; print(s.replace(r, /*wrap1*/(function(){ this.v2[new String(\"19\")] = h2;return (function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: window > 21, keys: undefined, }; })})())); ");
/*fuzzSeed-42369751*/count=2; tryItOut("t2[this.g1.v2] = v0;");
/*fuzzSeed-42369751*/count=3; tryItOut("\"use asm\"; /*RXUB*/var r = r1; var s = s2; print(uneval(r.exec(s))); ");
/*fuzzSeed-42369751*/count=4; tryItOut("\"use strict\"; this.p0 = h1;\na2[14] =  \"\" ;\n");
/*fuzzSeed-42369751*/count=5; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x080000001, -(2**53-2), 0x080000000, -0x080000001, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 1/0, 2**53, 1, 0, 0.000000000000001, -0x080000000, -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, -1/0, -0, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 0/0, 2**53-2]); ");
/*fuzzSeed-42369751*/count=6; tryItOut("\"use strict\"; {/* no regression tests found */ }");
/*fuzzSeed-42369751*/count=7; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.log10(Math.fround(((Math.fround((Math.fround(x) <= Math.fround((( ~ -Number.MIN_SAFE_INTEGER) ** Math.tan(x))))) >>> 0) <= ((Math.atan2((x | 0), (Math.log(( + Math.fround(((x | 0) ^ x)))) | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, 1/0, 2**53, 1.7976931348623157e308, 0x07fffffff, -0x100000000, -Number.MAX_VALUE, 0, -(2**53-2), 1, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, Number.MIN_SAFE_INTEGER, -1/0, 0/0, 2**53+2, -Number.MIN_VALUE, -0x07fffffff, 0x080000000, Number.MIN_VALUE, 42, 0x080000001, -0x080000001, Number.MAX_VALUE, 0x100000001, -0x100000001, 2**53-2, 0x0ffffffff, Math.PI, 0.000000000000001, -0x080000000, -(2**53)]); ");
/*fuzzSeed-42369751*/count=8; tryItOut("\"use strict\"; o2 = s2.__proto__;");
/*fuzzSeed-42369751*/count=9; tryItOut("\"use strict\"; for (var p in h1) { try { f2 = Proxy.createFunction(h0, this.f2, f0); } catch(e0) { } a2.unshift(p0, ((uneval(x = /(?:.|(?=$|[^]^))/gy))), h2); }");
/*fuzzSeed-42369751*/count=10; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-42369751*/count=11; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.sinh(mathy0(Math.fround(mathy1(mathy0(y, (x % y)), (( ~ (mathy0(Math.fround(( - x)), (x && -Number.MIN_VALUE)) | 0)) | 0))), Math.fround(( - -(2**53-2))))); }); ");
/*fuzzSeed-42369751*/count=12; tryItOut("v2 = (s2 instanceof this.g2.s2);");
/*fuzzSeed-42369751*/count=13; tryItOut("mathy2 = (function(x, y) { return Math.acos(( + Math.atan2(( + Math.fround(Math.acosh(Math.fround(Math.hypot(y, ( - y)))))), (mathy1((( + Math.round(( + Math.fround(Math.trunc(( ! 1/0)))))) | 0), (Math.hypot(Math.fround(y), (x | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[(0/0), -(2**53+2), (0/0), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), (0/0), (0/0), (0/0), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), (0/0), (0/0), (0/0), -(2**53+2), (0/0), (0/0), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), -(2**53+2), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), -(2**53+2), (0/0), (0/0), -(2**53+2), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), (0/0), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), (0/0), -(2**53+2), (0/0), (0/0), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), (0/0), (0/0), (0/0), (0/0), -(2**53+2), (0/0), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), (0/0), (0/0), (0/0), (0/0), -(2**53+2), (0/0), (0/0), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), (0/0), (0/0), -(2**53+2), (0/0), (0/0), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), (0/0), (0/0), (0/0), -(2**53+2), (0/0), (0/0), (0/0), (0/0), (0/0), -(2**53+2), -(2**53+2), (0/0), -(2**53+2), (0/0), (0/0), -(2**53+2), (0/0), (0/0), (0/0), -(2**53+2), -(2**53+2), (0/0), (0/0), -(2**53+2), (0/0), (0/0), (0/0), -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=14; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-42369751*/count=15; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.hypot((Math.sqrt(mathy1((Math.log2(0x080000000) | 0), -0x080000001)) >>> 0), ((( ~ (((Math.fround(( ! (Math.expm1(( + x)) | 0))) | 0) === (Math.sign(x) >>> 0)) >>> 0)) >>> 0) | 0)) | 0) ? Math.fround(Math.exp(Math.fround(mathy1(y, Math.fround(Math.asinh(((( + mathy0(x, y)) >>> 0) < y))))))) : (( + Math.max((y ? y : ( + mathy0((( + ( + (-(2**53+2) >>> 0))) | 0), Math.ceil((( + (y >>> 0)) >>> 0))))), ( + Number.MAX_VALUE))) ? ((((y | 0) <= (Math.atanh(1) | 0)) | 0) === 0/0) : Math.atan(mathy0(((x >>> 0) , Math.fround(Math.max(y, ( + y)))), Math.fround(Math.atanh(Math.fround(x))))))); }); testMathyFunction(mathy2, [-0x0ffffffff, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, 42, 2**53, Math.PI, 0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0x07fffffff, -0x100000001, -0x080000000, -(2**53-2), -Number.MIN_VALUE, -0, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, Number.MAX_VALUE, -1/0, 1/0, 0x0ffffffff, 0x100000001, 1, 2**53+2, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 0, -0x07fffffff]); ");
/*fuzzSeed-42369751*/count=16; tryItOut("a1 = a1.map();");
/*fuzzSeed-42369751*/count=17; tryItOut("for (var v of g1.b2) { try { Object.defineProperty(this, \"a2\", { configurable: this, enumerable: false,  get: function() { h0 = x; return []; } }); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a1, v0, ({writable: true, enumerable: true})); } catch(e1) { } try { for (var v of f1) { v0 = Object.prototype.isPrototypeOf.call(this.g0, h1); } } catch(e2) { } m2.set(f0, b0); }");
/*fuzzSeed-42369751*/count=18; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((Math.atan2(( + (( - -0x080000000) | ( + x))), ( + ( + ( ! ( + -0x080000000))))) << (Math.acosh(((Math.hypot((Math.min((x | 0), (Math.min((y >>> 0), (x >>> 0)) >>> 0)) | 0), Number.MAX_VALUE) !== x) | 0)) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[ /x/g , arguments.callee,  /x/g ,  /x/g ,  /x/g , arguments.callee, arguments.callee, arguments.callee,  /x/g , arguments.callee,  /x/g ,  /x/g , arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee, arguments.callee,  /x/g , arguments.callee,  /x/g , arguments.callee,  /x/g , arguments.callee, arguments.callee, arguments.callee,  /x/g , arguments.callee, arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee,  /x/g , arguments.callee,  /x/g , arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee,  /x/g , arguments.callee, arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee, arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee, arguments.callee,  /x/g ,  /x/g , arguments.callee, arguments.callee,  /x/g , arguments.callee, arguments.callee,  /x/g ,  /x/g , arguments.callee,  /x/g , arguments.callee, arguments.callee,  /x/g , arguments.callee, arguments.callee, arguments.callee,  /x/g , arguments.callee,  /x/g ,  /x/g ,  /x/g , arguments.callee, arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee,  /x/g ,  /x/g , arguments.callee,  /x/g , arguments.callee, arguments.callee,  /x/g ]); ");
/*fuzzSeed-42369751*/count=19; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((i0)+(0xfd2d7063)+(i0)))|0;\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000000, 0x07fffffff, 0x080000001, -1/0, 1, 2**53-2, -(2**53), 42, -0x080000000, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, Number.MIN_VALUE, 0x100000001, -0, -0x0ffffffff, -0x100000001, 0/0, 0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, -(2**53+2), -0x080000001, Number.MAX_VALUE, 2**53+2, Math.PI, 0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-42369751*/count=20; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ( ~ ( - Math.pow(y, -0x080000001)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, 0x100000000, -1/0, 1/0, -0x100000001, Math.PI, Number.MAX_VALUE, 0x0ffffffff, 0x080000001, -(2**53), 1.7976931348623157e308, 0, 1, 2**53, 2**53+2, 0x100000001, 0.000000000000001, 0x07fffffff, 42, -0x07fffffff, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53+2), -0x080000001, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=21; tryItOut("/*infloop*/for(var w = x ** window; encodeURIComponent.prototype; y) return; /x/g ;");
/*fuzzSeed-42369751*/count=22; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.hypot(((( + Math.asinh((Math.hypot((42 | 0), y) | 0))) >>> 0) | 0), (Math.imul(Math.exp(x), (mathy0(((x ? (y | 0) : ((mathy0((y >>> 0), ( + x)) >>> 0) | 0)) | 0), (Math.abs(((x !== (-0x0ffffffff | 0)) >>> 0)) >>> 0)) >>> 0)) | 0)); }); ");
/*fuzzSeed-42369751*/count=23; tryItOut("\"use strict\"; v2 = false;");
/*fuzzSeed-42369751*/count=24; tryItOut("/*bLoop*/for (pfgxcm = 0; pfgxcm < 23; ++pfgxcm) { if (pfgxcm % 4 == 3) { print(new RegExp(\"\\\\W\", \"gyi\")); } else { e1.has(a0); }  } ");
/*fuzzSeed-42369751*/count=25; tryItOut("/*RXUB*/var r = r2; var s = this.s2; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=26; tryItOut("mathy5 = (function(x, y) { return ((Math.log2((Math.fround(( ~ (( ~ ( + mathy3(y, x))) >>> 0))) <= ((Math.log(( + x)) >>> 0) === x))) , mathy2((( + mathy2(( + x), ( + y))) / -Number.MAX_VALUE), Math.imul(x, y))) - (( ~ ( + Math.min(Math.max(( + ( + ( + y))), ( + 0x080000000)), Math.trunc(y)))) > (Math.abs(( + x)) | 0))); }); testMathyFunction(mathy5, [0x100000001, -0x100000000, Number.MIN_VALUE, -0, 0x07fffffff, Number.MAX_VALUE, -0x080000001, 1/0, 0x100000000, -Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0.000000000000001, -(2**53-2), 0x080000001, 0x080000000, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 42, Math.PI, -1/0, 0, 2**53, 1, 1.7976931348623157e308, -0x080000000, 0/0]); ");
/*fuzzSeed-42369751*/count=27; tryItOut("\"use strict\"; Array.prototype.push.call(a2, e2, e2);");
/*fuzzSeed-42369751*/count=28; tryItOut("v2.toSource = (function(j) { if (j) { try { for (var v of p0) { try { t2.set(a0, (let (b) b)); } catch(e0) { } try { o1.g2.a2.unshift(h2); } catch(e1) { } s1 = ''; } } catch(e0) { } try { r0 = /\\cR{2}|(?=[^])?{1,}/m; } catch(e1) { } try { this.g1.v0 = 0; } catch(e2) { } e0 + v2; } else { f2(this.p0); } });");
/*fuzzSeed-42369751*/count=29; tryItOut("\"use strict\"; (4277);");
/*fuzzSeed-42369751*/count=30; tryItOut("\"use strict\"; testMathyFunction(mathy0, [1.7976931348623157e308, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, 42, 0/0, -1/0, -0x07fffffff, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 0x080000001, 0x07fffffff, -0x100000001, -Number.MIN_VALUE, -0, Number.MIN_VALUE, -(2**53), Math.PI, -0x080000000, 0x100000001, -(2**53-2), 1, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=31; tryItOut("g1.offThreadCompileScript(\"/*hhh*/function yzorvs(d = x){v2 = g0.eval(\\\"a2 = a1.map((function mcc_() { var ckeshg = 0; return function() { ++ckeshg; f2(/*ICCD*/ckeshg % 9 == 0);};})(), this.m0, b0);\\\");}/*iii*/this.v2 = x;\", ({ global: g1.g2, fileName: null, lineNumber: 42, isRunOnce: {} = [], noScriptRval: (x % 3 != 1), sourceIsLazy: true, catchTermination: (makeFinalizeObserver('tenured')) }));");
/*fuzzSeed-42369751*/count=32; tryItOut("\"use asm\"; testMathyFunction(mathy3, [2**53+2, 0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, -Number.MAX_VALUE, 0x07fffffff, -0, -1/0, 2**53-2, -(2**53-2), Math.PI, 0.000000000000001, Number.MIN_VALUE, 1/0, -0x080000000, -(2**53+2), -0x100000001, -0x0ffffffff, 1.7976931348623157e308, 1, 0x080000001, Number.MIN_SAFE_INTEGER, 42, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, 0x100000000, -Number.MIN_VALUE, -0x100000000, 0, Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=33; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.log10((Math.pow(Math.log10(x), (( + (((( + x) === y) >>> 0) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy0, [-0x07fffffff, 1/0, -0x100000001, -(2**53), -0x080000001, 0.000000000000001, Math.PI, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 1, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -1/0, 0x080000001, -(2**53-2), 0/0, -0, -(2**53+2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, -0x080000000, 42, 2**53+2, 0x080000000, Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-42369751*/count=34; tryItOut("\"use strict\"; for (var p in v2) { try { Object.defineProperty(this, \"v1\", { configurable: true, enumerable: true,  get: function() {  return a2[\"d\"]; } }); } catch(e0) { } try { this.o1.o1 + v2; } catch(e1) { } try { this.g0.v1 = (this.s1 instanceof t0); } catch(e2) { } i1 + ''; }");
/*fuzzSeed-42369751*/count=35; tryItOut("mathy3 = (function(x, y) { return mathy1(Math.fround((Math.pow((((x + ((x ? (x | 0) : x) | 0)) >>> 0) ? -Number.MAX_SAFE_INTEGER : y), (( + (Math.hypot(( - y), ( + ((y | 0) >> x))) | 0)) / Math.max(Math.pow(Math.fround(x), Number.MAX_VALUE), (Math.log((y | 0)) | 0)))) !== (mathy1((Math.hypot((x | 0), y) | 0), (Math.sign(Math.fround(Math.atan2(Math.fround(Number.MAX_SAFE_INTEGER), ( + y)))) | 0)) | 0))), ((( + Math.pow(( + Math.fround(( ! Math.fround((( - ((Math.sign(-0x080000001) >>> 0) | 0)) | 0))))), ( + y))) | 0) <= Math.cos((( ~ (x << (x ** -0x0ffffffff))) ? (((Math.fround(Math.sqrt(Math.fround(y))) >>> 0) + x) , y) : (Math.fround(x) < Math.fround(2**53)))))); }); testMathyFunction(mathy3, [-0x080000000, -0x080000001, -0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, -(2**53+2), Number.MAX_VALUE, 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, 0x080000001, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, 0, 2**53+2, 0x07fffffff, 2**53, 0x100000000, -0x07fffffff, -0x100000001, 1, -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, -1/0, 42, -0x100000000, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-42369751*/count=36; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=37; tryItOut("\"use strict\"; e0.delete(o0.v1);");
/*fuzzSeed-42369751*/count=38; tryItOut("\"use strict\"; /*infloop*/for(let window in c = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: undefined, delete: function() { throw 3; }, fix: function() { return []; }, has: undefined, hasOwn: function() { return false; }, get: function() { return undefined }, set: undefined, iterate: z.toFixed, enumerate: undefined, keys: undefined, }; })(name), Math.sin(1))) {a2[y] = f1;m0 + ''; }");
/*fuzzSeed-42369751*/count=39; tryItOut("\"use strict\"; m1.get(o0);");
/*fuzzSeed-42369751*/count=40; tryItOut("t1[14] =  /x/ ;\u000c\no0 = g1.__proto__;\n");
/*fuzzSeed-42369751*/count=41; tryItOut("\"use strict\"; for(let z in /*MARR*/[let (b) (window)( '' , (function ([y]) { })()), let (b) (window)( '' , (function ([y]) { })()), arguments.callee, let (b) (window)( '' , (function ([y]) { })()), let (b) (window)( '' , (function ([y]) { })()), arguments.callee, arguments.callee, let (b) (window)( '' , (function ([y]) { })()), arguments.callee, new Number(1.5), arguments.callee, arguments.callee, let (b) (window)( '' , (function ([y]) { })()), let (b) (window)( '' , (function ([y]) { })()), let (b) (window)( '' , (function ([y]) { })()), arguments.callee, arguments.callee, new Number(1.5)]) with({}) { for(let w in []); } ");
/*fuzzSeed-42369751*/count=42; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(Math.fround(Math.pow(Math.fround(( + (( + Math.sign((Math.fround(Math.hypot(y, y)) | 0))) ? ( + ( ! ((Math.fround(( + x)) <= 0x100000000) | 0))) : y))), (Math.fround((( ~ (Math.sinh(x) | 0)) & (( + (( ~ Math.atan2(Math.fround(Number.MAX_SAFE_INTEGER), -1/0)) >>> 0)) | 0))) | 0))), ((((mathy0((Math.fround((Math.fround((((Math.fround(Math.atan2(Math.fround(x), Math.fround(( + Math.log10(Math.fround(x)))))) | 0) <= ((( ~ (x | 0)) | 0) | 0)) | 0)) >= ( + -0x080000000))) | 0), (mathy0((2**53+2 | 0), ((x ** ( + x)) | 0)) | 0)) | 0) >>> 0) ? ((( + ((((( + -Number.MIN_SAFE_INTEGER) | 0) ? ((y ? ( + mathy0(x, Math.fround(x))) : y) | 0) : (((Math.fround((x << y)) >>> 0) < (y >>> 0)) >>> 0)) | 0) | 0)) | 0) >>> 0) : Math.sinh((( + Math.imul(Math.fround(((Math.trunc((y >>> 0)) >>> 0) - x)), (y | 0))) , Math.sinh(y)))) >>> 0)); }); ");
/*fuzzSeed-42369751*/count=43; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      (Float32ArrayView[(((imul((0x9b1d1265), ((0x3d8fdd27) == (0x3bfbaf00)))|0))+((+(0x1756f012)) > (+(0.0/0.0)))+((((i2))>>>((0xbe050a5)-(0xa75ad9bc))))) >> 2]) = ((d0));\n    }\n    i2 = (0xfedeeebc);\n    return +((d0));\n    (Uint8ArrayView[4096]) = (((((((0xf6905812)-(0xffffffff)-(0xfcd79e58))>>>((0xef8cd11b)+(0xfb4edb8b)-(-0x8000000))))-(/*FFI*/ff(((((+/*FFI*/ff(((8193.0))))) * ((d1)))), ((((0xfe7ff21e)-(0x2cb0edc6)-(0xfd1b67e9))|0)), ((imul((0x2610ef03), (0x1282555f))|0)), ((-513.0)), ((-72057594037927940.0)), ((18446744073709552000.0)), ((-7.737125245533627e+25)))|0)-((((0x317f494a))>>>((0xf8178176))) > (((0xfde0eaf1))>>>((0xab808b01)))))>>>((-0x8000000))) / (0x6fded19));\n    i2 = (i2);\n    return +((((NaN)) * ((3.022314549036573e+23))));\n    d1 = (d1);\n    {\n      d0 = (d0);\n    }\n    i2 = (0xf94493f1);\n    {\n      return +((NaN));\n    }\n    d1 = ((2305843009213694000.0) + (+/*FFI*/ff((((0xfffff*(((0x1227f415) > (0xb12a304)) ? ((0xe1e5ddcf)) : ((0xb049c243) != (0xffffffff)))) << (((((-2.0)) * ((1152921504606847000.0))) == (d0))-(0xc1dc2774)-(0x5463b0b4)))))));\n    i2 = (0x42259d4a);\n    d1 = (NaN);\n    d0 = (+(abs((((((((0x1ca97101) ? (0x60cedecf) : (-0x8000000))*0xd65d0)>>>((0xfa269880)-(0xffffffff))) >= ((0xb818b*((0xffffffff)))>>>(((0x663010e))-((0x7fffffff)))))) | ((Int8ArrayView[0]))))|0));\n    (Uint8ArrayView[(x) >> 0]) = ((0xffffffff));\n    d0 = (1.03125);\n    {\n      return +((((\"\\u45F8\").call)()));\n    }\n    return +((+log(((-144115188075855870.0)))));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var krxzhv = /*MARR*/[function(){}, new Number(1.5), new Number(1.5), 0/0, function(){}, new Number(1.5), new Number(1.5), 0/0, 0/0, 0/0].filter(String.prototype.split, x); (offThreadCompileScript)(); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [1/0, 2**53, -(2**53), 0/0, 42, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, Math.PI, Number.MAX_VALUE, 1, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -0x080000000, 2**53-2, 0x07fffffff, 1.7976931348623157e308, 0x080000000, 0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -0, 0x100000000, -0x100000000, -1/0, 0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0, -0x100000001]); ");
/*fuzzSeed-42369751*/count=44; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.pow(Math.log(Math.fround(Math.atan2(( + (-0x07fffffff >>> y)), (Math.max(Math.imul((x | 0), ( + -0x080000000)), (-(2**53-2) >>> 0)) >>> 0)))), (Math.pow(Math.trunc(Math.fround(Math.cbrt(y))), ( + mathy2(( + ( ! Math.fround(Math.imul(Math.fround(x), Math.fround(x))))), ( + Math.fround(( - Math.fround(x))))))) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[ /x/g ]); ");
/*fuzzSeed-42369751*/count=45; tryItOut("{/*RXUB*/var r = /\\uf383((?![^]*?|\\x5d\\w(?:\\1)))|\\B\\2+?{3,6}/gy; var s = \"B]aB]aB]aB]a\\uf383\"; print(r.exec(s)); print(r.lastIndex); e1.delete(p2); }");
/*fuzzSeed-42369751*/count=46; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -140737488355327.0;\n    (Int8ArrayView[((0x22815259) / (0x932834d3)) >> 0]) = (((({}) = (\u3056 =  /x/ ))));\n    i0 = (!((0x990c8634)));\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: Math.floor}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0, (new Boolean(true)), ({valueOf:function(){return 0;}}), [], (new Number(0)), '\\0', /0/, '/0/', ({valueOf:function(){return '0';}}), 0.1, NaN, ({toString:function(){return '0';}}), [0], '', null, (new String('')), '0', objectEmulatingUndefined(), -0, (new Number(-0)), false, (new Boolean(false)), true, undefined, (function(){return 0;}), 1]); ");
/*fuzzSeed-42369751*/count=47; tryItOut("Array.prototype.forEach.call(a0, (function() { try { for (var p in this.h1) { try { h2.getOwnPropertyNames = f1; } catch(e0) { } for (var p in v0) { v2 = t0.length; } } } catch(e0) { } try { f0.toSource = (function() { for (var j=0;j<78;++j) { this.f0(j%4==0); } }); } catch(e1) { } e1 + ''; return b2; }));");
/*fuzzSeed-42369751*/count=48; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=49; tryItOut(" for (var z of \"\\uBFB4\") print( '' );\na2 = Array.prototype.slice.apply(a0, [g0, g0.b0]);\n");
/*fuzzSeed-42369751*/count=50; tryItOut("testMathyFunction(mathy0, [-1/0, 0.000000000000001, 1, 1.7976931348623157e308, 42, -0x100000000, -0x080000001, -(2**53+2), -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, 0x080000001, -0x0ffffffff, 0, Math.PI, 0/0, 0x080000000, 0x100000001, -(2**53-2), -(2**53), -0x100000001, -Number.MIN_VALUE, 2**53+2, 0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-42369751*/count=51; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul(( + (( + Math.clz32(Math.fround(((Math.tanh(Math.fround((((-0x080000001 >>> 0) >= (y >>> 0)) >>> 0))) | 0) % (-(2**53-2) | 0))))) ? (Math.fround(Math.hypot(Math.fround(( - y)), Math.fround(Math.cbrt(x)))) , Math.tanh(((((( + ( + (( + y) ? ( + Number.MAX_SAFE_INTEGER) : x))) ** x) >>> 0) !== (x >>> 0)) >>> 0))) : ( + (Math.asin((((((( + y) - Math.fround(y)) | 0) ? (y | 0) : (y | 0)) | 0) | 0)) | 0)))), ( ! (( ~ y) != ((y % y) % (x || Math.fround((Math.fround(( ! x)) << Math.fround(x)))))))); }); ");
/*fuzzSeed-42369751*/count=52; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log2(Math.fround(( + ( ! Math.min(Math.fround((Math.fround(x) & ( + ( ! ( + y))))), (Math.acosh((y >>> 0)) | 0)))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 2**53+2, 1, 0x07fffffff, 0, -1/0, 0x100000000, -(2**53-2), 0/0, 0x0ffffffff, Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, -(2**53), -0x100000000, -0x080000001, 0x080000001, -0x080000000, 0x100000001, 2**53-2, -Number.MAX_VALUE, -0, 0.000000000000001, -0x100000001, 1/0, -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=53; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=54; tryItOut("\"use strict\"; g0.s0 = s1.charAt(6);");
/*fuzzSeed-42369751*/count=55; tryItOut("/*infloop*/L:do {m0.get(v0); } while(('fafafa'.replace(/a/g, String.prototype.normalize)));");
/*fuzzSeed-42369751*/count=56; tryItOut("mathy2 = (function(x, y) { return Math.fround(( - (Math.max(mathy0(0.000000000000001, Math.imul(x, ( ~ y))), Math.sqrt(mathy0(( ! (x >>> 0)), Math.sqrt((x >>> 0))))) * ((Math.fround(Math.hypot(((y >>> ( ! 0x100000000)) >>> 0), (Math.min((x >>> 0), (y >>> 0)) >>> 0))) >> Math.atan2(Math.fround(( ~ Math.fround(x))), Math.fround(Math.round(Math.fround((y < -0x080000001)))))) & (Math.min((Math.log2(-0) >>> 0), ((y ? (Math.hypot(x, x) && x) : (x ** 2**53)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -(2**53+2), -0x0ffffffff, 0x080000001, -(2**53-2), -0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, -0x100000000, 2**53, Number.MIN_VALUE, 1, 0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, Math.PI, 2**53+2, -0x100000001, 0/0, 1/0, 0, -1/0, 42, -0x080000000, 0x100000000, 0x0ffffffff, -0x080000001, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=57; tryItOut("o2.s1 += s1;");
/*fuzzSeed-42369751*/count=58; tryItOut("\"use strict\"; Object.preventExtensions(s2);");
/*fuzzSeed-42369751*/count=59; tryItOut("\"use strict\"; 11;");
/*fuzzSeed-42369751*/count=60; tryItOut("g1.f1.__proto__ = g1;");
/*fuzzSeed-42369751*/count=61; tryItOut("\"use strict\"; const c = {} = [];s0 += 'x';");
/*fuzzSeed-42369751*/count=62; tryItOut("testMathyFunction(mathy2, [-(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 42, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, -0x07fffffff, -0x100000000, -0, 1/0, 2**53, 0, Number.MIN_VALUE, -0x100000001, -(2**53+2), 0x100000000, 0x080000000, -Number.MIN_VALUE, -(2**53), 1, 0x100000001, -0x080000001, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 0/0, 2**53+2, 2**53-2]); ");
/*fuzzSeed-42369751*/count=63; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( + (( + (( ! (Math.fround(Math.log1p(Math.fround((( ! (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))) | 0)) | 0)) << ( + (((Math.tan((Math.clz32(( + Math.hypot(-Number.MAX_SAFE_INTEGER, ( + x)))) | 0)) >>> 0) | 0) / Math.abs(( ! y)))))) << Math.exp((Math.expm1(y) | 0))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, 1, 0, -0x0ffffffff, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, 42, 2**53, -0x07fffffff, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), 2**53-2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, 1/0, -(2**53+2), -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 0x080000001, 1.7976931348623157e308, Math.PI, 2**53+2, -0x100000001, Number.MIN_VALUE, -1/0, 0/0, Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=64; tryItOut("neuter(b0, \"change-data\");");
/*fuzzSeed-42369751*/count=65; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=66; tryItOut(" for (var y of  /x/g ) Array.prototype.push.apply(a1, [o0.g0.a1, h1, p1]);");
/*fuzzSeed-42369751*/count=67; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + mathy1((( + ( - 0x07fffffff)) / ((( ! ( + Math.ceil(x))) | 0) > (( + 0x100000001) | 0))), Math.fround(mathy0(Math.fround((Math.fround(( + (( + (Math.hypot((x >>> 0), (((x ? (Math.max((y | 0), x) >>> 0) : (Number.MIN_VALUE >>> 0)) >>> 0) >>> 0)) >>> 0)) ? ( + Math.acosh(2**53)) : ( + x)))) >= Math.fround(y))), mathy0(x, x))))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), true, (new Boolean(true)), 0, 0.1, '', (new Number(0)), '0', -0, (new String('')), false, '/0/', [0], ({toString:function(){return '0';}}), [], ({valueOf:function(){return 0;}}), (new Number(-0)), (function(){return 0;}), undefined, (new Boolean(false)), '\\0', null, NaN, ({valueOf:function(){return '0';}}), 1, /0/]); ");
/*fuzzSeed-42369751*/count=68; tryItOut("e0.has(o2);");
/*fuzzSeed-42369751*/count=69; tryItOut("with({}) { g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: /(?:.*)/gy, sourceIsLazy: true, catchTermination: undefined })); } ");
/*fuzzSeed-42369751*/count=70; tryItOut("m0.set(o1,  \"\"  ? b = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: /*wrap1*/(function(){ v1 = a0.length;return window})(), defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: x, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(y) { \"use strict\"; yield y; ; yield y; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(false), encodeURI, ({/*TOODEEP*/})) : /\\S/y);");
/*fuzzSeed-42369751*/count=71; tryItOut("\"use strict\"; testMathyFunction(mathy2, [(new String('')), true, false, [0], 1, null, undefined, '/0/', (new Number(0)), ({toString:function(){return '0';}}), /0/, (new Number(-0)), '0', -0, ({valueOf:function(){return '0';}}), 0, 0.1, (new Boolean(false)), (new Boolean(true)), '\\0', (function(){return 0;}), '', NaN, [], ({valueOf:function(){return 0;}}), objectEmulatingUndefined()]); ");
/*fuzzSeed-42369751*/count=72; tryItOut("/*infloop*/for(var x; z = Math; (Object.isFrozen).call(new (x)(x), )) f2.toString = f0;");
/*fuzzSeed-42369751*/count=73; tryItOut("b1.toSource = this.f2;");
/*fuzzSeed-42369751*/count=74; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - (Math.hypot(x, (((( + ( + ( + ( + mathy0(( + y), ( + Math.PI)))))) | 0) | (Math.max(Math.fround(y), ( + x)) | 0)) | 0)) < y)) >= ( - Math.sin(( + (Math.fround(Math.round(Math.fround(x))) >>> 0))))); }); testMathyFunction(mathy1, [2**53+2, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 0/0, -0, -0x0ffffffff, -0x080000001, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, 0.000000000000001, 0x080000001, 0, 1, -Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, 0x100000000, 42, -(2**53), 1.7976931348623157e308, 1/0, 0x100000001, -0x07fffffff, Number.MIN_VALUE, -0x080000000, 0x080000000, -0x100000000, 2**53]); ");
/*fuzzSeed-42369751*/count=75; tryItOut("\"use asm\"; /*oLoop*/for (skkuba = 0, Math.min(3, -687276213.5); skkuba < 5; ++skkuba) { for (var v of p0) { v2 = a2.length; } } var c = {y: []\u0009, eval: x} = (4277);");
/*fuzzSeed-42369751*/count=76; tryItOut("\"use strict\"; for(let d in [[1]]) {print(x); }");
/*fuzzSeed-42369751*/count=77; tryItOut("\"use strict\"; (this);s2 = a1.join(s1, i2, a1, g0.s1, o0.t0, f2);");
/*fuzzSeed-42369751*/count=78; tryItOut("\"use strict\"; /*oLoop*/for (let cvpcyw = 0; cvpcyw < 19; ++cvpcyw) { e2 + s2; } ");
/*fuzzSeed-42369751*/count=79; tryItOut("i0 = new Iterator(h0, true);");
/*fuzzSeed-42369751*/count=80; tryItOut("(void schedulegc(o2.g0));\ni1.send(v1);\n");
/*fuzzSeed-42369751*/count=81; tryItOut("i0.toString = (function() { try { v0 = h0[new String(\"19\")]; } catch(e0) { } Object.defineProperty(this, \"o1.v2\", { configurable: \"2\" = ([] = x), enumerable: (x % 44 == 11),  get: function() {  return o0.a0.length; } }); return this.m1; });");
/*fuzzSeed-42369751*/count=82; tryItOut("a0.shift();");
/*fuzzSeed-42369751*/count=83; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.asin(Math.fround((Math.fround((((x | 0) | (Math.max(x, Math.fround(Math.min(( + x), Math.fround(1/0)))) | 0)) | 0)) === ( + Math.fround((Math.fround(2**53) ** Math.fround(-Number.MIN_SAFE_INTEGER)))))))); }); testMathyFunction(mathy5, /*MARR*/[ \"\" ,  \"\" ,  /x/g ,  \"\" ,  /x/g ,  \"\" ,  /x/g ,  \"\" ,  \"\" ,  /x/g ,  /x/g ,  /x/g ,  \"\" ,  /x/g ,  /x/g ,  \"\" ,  /x/g ,  \"\" ,  \"\" ,  /x/g ,  /x/g ,  /x/g ,  \"\" ,  /x/g ,  \"\" ,  /x/g ,  /x/g ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  /x/g ,  /x/g ,  /x/g ,  \"\" ,  /x/g ,  \"\" ,  \"\" ,  \"\" ,  /x/g ,  /x/g ,  \"\" ,  \"\" ,  /x/g ,  \"\" ,  \"\" ,  /x/g ,  \"\" ,  \"\" ,  \"\" ,  /x/g ,  \"\" ,  \"\" ,  \"\" ,  /x/g ,  /x/g ,  /x/g ,  \"\" ,  /x/g ,  \"\" ,  /x/g ,  /x/g ,  \"\" ]); ");
/*fuzzSeed-42369751*/count=84; tryItOut("mathy2 = (function(x, y) { return (Math.sqrt((( + Math.log1p(( + Math.fround(Math.atan2(Math.fround(( + Math.imul(( + Math.round(y)), ( + x)))), Math.fround(( + ( ~ ( + y))))))))) ? (( + ( + Math.pow(x, y))) ? ( + Math.sign(mathy0(x, y))) : (Math.cbrt((Math.fround(( - ( + Math.min(0x0ffffffff, (-(2**53) >>> 0))))) | 0)) | 0)) : Math.fround(((( ~ x) | 0) & Math.expm1(x))))) >>> 0); }); testMathyFunction(mathy2, [-(2**53+2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 0, -0, 1, Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, -0x07fffffff, 2**53+2, -(2**53), -1/0, 2**53, 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, 0x100000000, 0x080000001, 2**53-2, 0x0ffffffff, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, -0x100000000, -0x100000001, 0x07fffffff, -0x080000001, 42, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=85; tryItOut("g0.offThreadCompileScript(\"a2 = a2[7];\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-42369751*/count=86; tryItOut("Object.prototype.watch.call(this.v0, \"constructor\", (function() { try { /*MXX1*/o1 = g2.Date.prototype.getHours; } catch(e0) { } /*RXUB*/var r = r2; var s = s2; print(s.match(r)); print(r.lastIndex);  return o0; }));");
/*fuzzSeed-42369751*/count=87; tryItOut("/*RXUB*/var r = new RegExp(\"$\", \"ym\"); var s = \"\\n\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-42369751*/count=88; tryItOut("v0 = g2.runOffThreadScript();function c(NaN, d)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d0 = (d0);\n    }\n    return (((0xffffffff)+((~~(d0)))))|0;\n  }\n  return f;{/*MXX3*/g2.EvalError.prototype.name = g2.EvalError.prototype.name;e2.add(f0); }");
/*fuzzSeed-42369751*/count=89; tryItOut("with({b: 9 >= /*MARR*/[false, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, function(){}].some(decodeURIComponent,  /x/g )})return z;");
/*fuzzSeed-42369751*/count=90; tryItOut("\"use strict\"; let \u0009(e) { /*bLoop*/for (var camcjc = 0; camcjc < 43; ++camcjc) { if (camcjc % 5 == 4) { print(i2); } else { print(x); }  }  }");
/*fuzzSeed-42369751*/count=91; tryItOut("a1[8] = a2;");
/*fuzzSeed-42369751*/count=92; tryItOut("g1.a2.shift();");
/*fuzzSeed-42369751*/count=93; tryItOut("v2 = evalcx(\"e\", g0);v0 = g1.eval(\"m1 = new Map(this.a1);\");/*RXUB*/var r = /\\S.|(?:[^])[^\u00ab\u1dc0\\s]{2048}|.\\3*??(?=\\d+)/gy; var s = \"__0000000\"; print(s.replace(r, [] = e, \"im\")); ");
/*fuzzSeed-42369751*/count=94; tryItOut("mathy3 = (function(x, y) { return ( + (( - (( + Math.pow(Math.fround(((( - (y >>> 0)) >>> 0) >= Math.atan2(-(2**53-2), Number.MIN_SAFE_INTEGER))), Math.fround(Math.hypot(Math.round((Math.cosh(y) | 0)), y)))) | 0)) | 0)); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 2**53, -0x100000000, 0/0, -0x080000001, 0, -1/0, 0x07fffffff, 1/0, 2**53-2, 0x100000000, -0x0ffffffff, -0, -0x07fffffff, 42, 0x0ffffffff, -(2**53+2), 0x100000001, Number.MIN_VALUE, 1, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, -(2**53), -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-42369751*/count=95; tryItOut("\"use strict\"; \"use asm\"; L:while((Object.defineProperty(x, \"toExponential\", ({set: RangeError, enumerable: (x % 6 == 1)}))) && 0){e0 + ''; }function d(d, eval)\u0009\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((0x7fffffff))))|0;\n  }\n  return f;this.a2.splice(1, 17, t0, p2, a2, this.a2);");
/*fuzzSeed-42369751*/count=96; tryItOut("testMathyFunction(mathy3, /*MARR*/[x, x, arguments,  'A' , x, new Number(1), new Number(1), new Number(1),  'A' ,  'A' , arguments, x, arguments, new Number(1), arguments, new Number(1), new Number(1), new Number(1),  'A' , x, x,  'A' , new Number(1), x,  'A' , new Number(1), arguments, x, x, arguments, x, x, new Number(1),  'A' , new Number(1), x, arguments, new Number(1), new Number(1), arguments, new Number(1),  'A' ,  'A' , new Number(1),  'A' , arguments, x,  'A' , x, arguments, arguments, new Number(1), new Number(1), arguments, new Number(1), arguments, arguments, x, x, new Number(1), new Number(1), x,  'A' ,  'A' , new Number(1),  'A' , new Number(1), new Number(1), new Number(1), new Number(1), arguments, new Number(1), new Number(1), arguments, new Number(1), arguments, x, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, new Number(1), new Number(1), new Number(1), x, new Number(1), arguments,  'A' , x, arguments,  'A' , x, new Number(1), arguments, new Number(1), new Number(1)]); ");
/*fuzzSeed-42369751*/count=97; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.imul((( + (mathy0(Math.atan2(Math.log(Math.fround(Math.round(Math.fround(-0x07fffffff)))), ((Math.fround(Math.max(Math.fround(y), Math.fround(y))) & ((Math.exp((Number.MAX_VALUE >>> 0)) | 0) | 0)) >>> 0)), -Number.MAX_VALUE) >>> 0)) >>> 0), (Math.fround(( ! Math.trunc(((Math.acosh(( + Math.abs((x >>> 0)))) >>> 0) == mathy3(Math.atan(x), Math.trunc(Number.MIN_SAFE_INTEGER)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1, -(2**53+2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, 0x080000001, 1.7976931348623157e308, 1/0, 0x07fffffff, 0/0, 0x100000001, 42, 0x100000000, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 0x080000000, 2**53-2, Math.PI, -0, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, -0x080000001, -1/0, 2**53+2, -0x080000000, -0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=98; tryItOut("v2 = (f2 instanceof e2);");
/*fuzzSeed-42369751*/count=99; tryItOut("for (var p in m1) { try { for (var p in g2) { try { v2 = p1[\"valueOf\"]; } catch(e0) { } try { for (var v of p0) { m1.get(this.h0); } } catch(e1) { } try { /*ODP-2*/Object.defineProperty(h0, \"wrappedJSObject\", { configurable: true, enumerable: true, get: (function() { try { Array.prototype.pop.apply(a1, []); } catch(e0) { } try { o1 = Object.create(t0); } catch(e1) { } try { m1.has(o2); } catch(e2) { } g1.offThreadCompileScript(\"\\\"use strict\\\"; Array.prototype.shift.call(a0);\"); return s0; }), set: f2 }); } catch(e2) { } for (var p in g1) { try { Array.prototype.push.apply(this.a0, [t0, s0, v2, o0, e2, v0, this.g2.e0, o2.h1, h1]); } catch(e0) { } a2[8] = {} *=  '' ; } } } catch(e0) { } try { e1.add(g0); } catch(e1) { } try { (void schedulegc(g1)); } catch(e2) { } m1.__proto__ = h0; }");
/*fuzzSeed-42369751*/count=100; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(i2, i2);");
/*fuzzSeed-42369751*/count=101; tryItOut("\"use strict\"; s2 += s0;");
/*fuzzSeed-42369751*/count=102; tryItOut("e0.add(g0);m0.get(m0);");
/*fuzzSeed-42369751*/count=103; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=104; tryItOut("const x = x, thfgwh, d, a, awwjjz;m1.set(i2, f0);");
/*fuzzSeed-42369751*/count=105; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=106; tryItOut("Array.prototype.sort.apply(a0, [(function(j) { if (j) { try { h0.has = f2; } catch(e0) { } try { for (var p in o1) { for (var p in o0) { try { f2(a1); } catch(e0) { } a0.pop(); } } } catch(e1) { } try { v0 = (f2 instanceof h0); } catch(e2) { } Array.prototype.unshift.apply(a1, [e1, p0]); } else { try { m1.delete(f2); } catch(e0) { } a2.splice(6, 12, p0); } })]);\nh1.fix = f1;\n");
/*fuzzSeed-42369751*/count=107; tryItOut("/*MXX2*/g0.RegExp.$4 = g0.t2;");
/*fuzzSeed-42369751*/count=108; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( - ( + (((x ? (Math.asinh(y) | 0) : (x | 0)) | 0) >= ( + (( + ( - ( + y))) ? ( + Math.cosh(x)) : ( + ( - y))))))); }); testMathyFunction(mathy2, /*MARR*/[-Number.MAX_VALUE, function(){}, new String('q'), true, (-1/0), (-1/0), true, new String('q'), (-1/0), function(){}, -Number.MAX_VALUE, new String('q'), -Number.MAX_VALUE, new String('q'), true, new String('q'), new String('q'), -Number.MAX_VALUE, new String('q'), -Number.MAX_VALUE, (-1/0), true, new String('q'), new String('q'), (-1/0), -Number.MAX_VALUE, -Number.MAX_VALUE, function(){}, new String('q'), (-1/0), true, function(){}, -Number.MAX_VALUE, -Number.MAX_VALUE, new String('q'), true, -Number.MAX_VALUE, (-1/0), true, (-1/0), function(){}, true, function(){}, (-1/0), function(){}, (-1/0), new String('q'), new String('q'), (-1/0), true, true, new String('q'), function(){}, (-1/0), new String('q'), true, new String('q'), new String('q'), new String('q')]); ");
/*fuzzSeed-42369751*/count=109; tryItOut("\"use strict\"; let b2 = t2.buffer;");
/*fuzzSeed-42369751*/count=110; tryItOut("yield (((uneval((void shapeOf(-0))))) ? \n ''  :  '' .unwatch(10))\nb0.__proto__ = e0;");
/*fuzzSeed-42369751*/count=111; tryItOut("(((encodeURI).yoyo(((void options('strict'))).__defineGetter__(\"NaN\", function shapeyConstructor(uakxbb){if (uakxbb) delete this[new String(\"9\")];Object.defineProperty(this, new String(\"2\"), ({enumerable: false}));if (uakxbb) Object.defineProperty(this, new String(\"9\"), ({get: Function, configurable: /*FARR*/[true], enumerable: (x % 38 == 34)}));{ print(x); } return this; }))));");
/*fuzzSeed-42369751*/count=112; tryItOut("\"use strict\"; m0.set(g1, true);\nthis;\n");
/*fuzzSeed-42369751*/count=113; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -17179869185.0;\n    (Float64ArrayView[1]) = ((neuter)());\n    return +((d3));\n  }\n  return f; })(this, {ff: (x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(undefined), new null( \"\" )))}, new ArrayBuffer(4096)); ");
/*fuzzSeed-42369751*/count=114; tryItOut("\"use strict\"; Array.prototype.shift.call(a1);");
/*fuzzSeed-42369751*/count=115; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (((Math.min((-0x0ffffffff !== (Math.max((Math.max(x, x) >>> 0), Math.min(x, ( ! ( + Math.sign(( + y)))))) | 0)), Math.fround(((42 >>> 0) * Math.fround(Math.fround(Math.ceil(y)))))) >>> 0) ? ((((Math.fround(Math.pow(Math.fround(Math.pow(x, y)), Math.fround(((Math.asin(x) | 0) ? Math.fround((Math.fround(Math.ceil(Math.fround(Math.min(Math.fround(y), Math.fround(y))))) , Math.fround(y))) : Math.atan2(Math.log1p((x | 0)), x))))) >>> 0) || (Math.atanh(Math.fround(Math.log2(( + x)))) | 0)) | 0) >>> 0) : ((Math.atan((( + Math.min(Math.fround(( + (0x100000000 | 0))), (-0x100000000 - y))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-42369751*/count=116; tryItOut("mathy0 = (function(x, y) { return Math.imul((Math.clz32(Math.hypot(((Math.fround(( ~ (y === y))) ^ ( + (Math.fround(y) >>> Math.fround(y)))) | 0), ((Math.max((42 >>> 0), ( + Math.max(2**53-2, (((2**53+2 | 0) | (y | 0)) | 0)))) >>> 0) | 0))) >>> 0), Math.acos(( + ( + Math.max(( + (( + (y === ( + x))) - ( + Math.fround(((x | 0) - Math.fround(y)))))), y))))); }); testMathyFunction(mathy0, [(function(){return 0;}), (new Number(-0)), null, 0.1, true, (new Boolean(false)), NaN, '', '/0/', undefined, -0, (new Boolean(true)), 0, ({toString:function(){return '0';}}), [0], objectEmulatingUndefined(), /0/, (new Number(0)), [], '0', ({valueOf:function(){return '0';}}), '\\0', (new String('')), 1, ({valueOf:function(){return 0;}}), false]); ");
/*fuzzSeed-42369751*/count=117; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(a0, -0, { configurable: (x % 5 != 2), enumerable: a = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: /*wrap2*/(function(){ \"use strict\"; var wptvza = (makeFinalizeObserver('nursery')); var pcjnaq = ([, ], ...wptvza) =>  /x/ ; return pcjnaq;})(), fix: function() { return []; }, has: function() { return false; }, hasOwn: (\u3056, x, ...eval) => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((-((d1))));\n  }\n  return f;, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })(((-29)())), Object.defineProperty(x, \"__count__\", ({})).yoyo(x)), writable: (x % 3 != 2), value: this.g0 });");
/*fuzzSeed-42369751*/count=118; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=119; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + ( + ( + mathy0(x, Math.fround(Math.hypot((Math.imul((0x080000001 | 0), (Math.min(x, ( + Math.atan2(( + x), ( + 0x0ffffffff)))) | 0)) | 0), mathy0(0x0ffffffff, y))))))) , ( ! ( ~ Math.fround((/*RXUE*//(?=[\\u0070]|(?!.)+?){4,}[\\u0044-\\uB850\\xfe-\u001a\\D][^]*?{4}/gyim.exec(\"\").eval(\"continue ;\")))))); }); testMathyFunction(mathy1, [-0x080000000, 42, 0x080000001, -(2**53+2), -0x0ffffffff, 0x0ffffffff, -(2**53), 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0, -0x100000000, -0x100000001, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, 2**53, -0x07fffffff, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x100000001, 1, Number.MAX_SAFE_INTEGER, 0x100000000, -0, 0.000000000000001, 1/0, 0x07fffffff, 0/0, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=120; tryItOut("/*RXUB*/var r = /(?:\\1{4,8})/i; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-42369751*/count=121; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (((mathy1(Math.fround(((x | 0) && Math.fround((Math.imul((42 | 0), (mathy0(Math.fround(x), (1/0 >>> 0)) | 0)) | 0)))), (((mathy1(x, (( - (x | 0)) | 0)) >>> 0) || Math.fround(Math.acosh(Math.fround((((Number.MAX_SAFE_INTEGER >>> 0) | ( + y)) >>> 0))))) | 0)) >>> 0) >>> (((( - ((1/0 | x) | 0)) ^ (Math.pow((Math.fround(Math.acos(y)) | 0), (y >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [-(2**53+2), -0x0ffffffff, 1, Number.MAX_VALUE, -(2**53), 0x080000001, 2**53, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, -0, 0x07fffffff, -(2**53-2), 0x100000001, 0/0, 0.000000000000001, -0x080000001, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, 42, 0x080000000, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-42369751*/count=122; tryItOut("mathy0 = (function(x, y) { return (Math.abs(((Math.sqrt((x ? ( ! y) : ( + ((((x >>> 0) >> (y >>> 0)) >>> 0) >> y)))) >= Math.fround(( + ( + ((Math.fround(Math.fround(Math.cosh(Math.fround(x)))) << Math.fround((Math.abs((Math.cos((Math.hypot((0/0 | 0), (y | 0)) | 0)) >>> 0)) >>> 0))) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53), 0x100000001, Number.MIN_VALUE, 42, -0x07fffffff, -0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -0, -(2**53+2), 1, 0x080000000, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 0, Number.MAX_VALUE, 1/0, 0/0, 0.000000000000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53-2), 2**53-2, Math.PI]); ");
/*fuzzSeed-42369751*/count=123; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(?=(\\\\2$?)|\\\\w|[^]|(.)|(?:\\\\B*?)+|\\\\2{3,}(?=.+)|\\\\D\\\\d|[\\\\D\\\\u0021\\\\b-\\\\x61])){2,}\", \"ym\"); var s = \"a\\n\\n\\n\\naaa\\n\\n\\n\\naaa\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=124; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x100000001, -0, -0x100000000, 0x0ffffffff, -Number.MAX_VALUE, 0x100000000, 0/0, 0, 0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53-2, 1, 1/0, -0x0ffffffff, 0x100000001, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, Number.MAX_VALUE, 2**53, -1/0, -Number.MIN_VALUE, 2**53+2, 0x080000001, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=125; tryItOut("/* no regression tests found */print(x);");
/*fuzzSeed-42369751*/count=126; tryItOut("g2.g0.__proto__ = e0;");
/*fuzzSeed-42369751*/count=127; tryItOut("tknvwi(delete (4277).eval(\"NaN;\"), new function(y) { return undefined *= y }(x));/*hhh*/function tknvwi(...e){/* no regression tests found */}");
/*fuzzSeed-42369751*/count=128; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.log10((Math.expm1((Math.min(( ! (Math.round((y >>> 0)) | 0)), Math.imul(Math.fround(-(2**53-2)), Math.fround(Math.hypot(y, ( ~ y))))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy0, [-0, (new Boolean(false)), '/0/', [0], /0/, ({valueOf:function(){return 0;}}), (new Number(0)), true, false, '\\0', ({toString:function(){return '0';}}), null, (new Number(-0)), ({valueOf:function(){return '0';}}), 0.1, (new String('')), 0, '0', (new Boolean(true)), (function(){return 0;}), [], '', undefined, objectEmulatingUndefined(), NaN, 1]); ");
/*fuzzSeed-42369751*/count=129; tryItOut("for(let b in []);");
/*fuzzSeed-42369751*/count=130; tryItOut("g2.valueOf = (function(j) { if (j) { try { print(g0.e0); } catch(e0) { } try { m0 = new WeakMap; } catch(e1) { } try { t1[9] = o1.t0; } catch(e2) { } for (var v of o1) { try { e0.delete(h0); } catch(e0) { } let s0 = new String(t0); } } else { try { for (var p in m1) { m1.delete(m1); } } catch(e0) { } /*MXX1*/o1 = g0.Float32Array.name; } });");
/*fuzzSeed-42369751*/count=131; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.log(mathy2(( + Math.cbrt(Math.fround((Math.cosh(y) != 0/0)))), ( ! mathy2((x ^ -0x07fffffff), y)))); }); ");
/*fuzzSeed-42369751*/count=132; tryItOut("\"use strict\"; for(var b = (let (z) (4277) + this = []) in let (c = x, print(x);, oclmji, xxzkgs)  '' ) m1.delete(h1);");
/*fuzzSeed-42369751*/count=133; tryItOut("\"use strict\"; \"use asm\"; s0.valueOf = (function() { try { /*RXUB*/var r = r0; var s = s2; print(r.exec(s)); print(r.lastIndex);  } catch(e0) { } try { this.g1.a0.forEach((function() { try { a2 = /*FARR*/[.../*MARR*/[(1/0), new Boolean(false), function(){}, new Boolean(false), new Boolean(false), new Boolean(false), function(){}, function(){}, function(){}, function(){}, new Boolean(false), (1/0), function(){}, (1/0), (1/0), (1/0), function(){}, new Boolean(false), (1/0), new Boolean(false), (1/0), function(){}, new Boolean(false), (1/0), (1/0), function(){}, (1/0), new Boolean(false), (1/0), new Boolean(false), function(){}, function(){}, new Boolean(false), (1/0), new Boolean(false), (1/0), function(){}, new Boolean(false), (1/0), function(){}, new Boolean(false), function(){}, function(){}, function(){}, new Boolean(false), new Boolean(false), (1/0), (1/0), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), (1/0), (1/0), new Boolean(false), (1/0), new Boolean(false), function(){}, new Boolean(false), new Boolean(false), function(){}, new Boolean(false), (1/0), function(){}, function(){}, new Boolean(false), (1/0), function(){}, (1/0), function(){}, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), (1/0), function(){}, new Boolean(false), function(){}, (1/0), function(){}, new Boolean(false), (1/0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (1/0), new Boolean(false)]]; } catch(e0) { } try { for (var v of g1) { try { t2[5] = ([] = a); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(g1, t0); } } catch(e1) { } try { for (var p in p2) { try { v0 = t2.length; } catch(e0) { } try { i2.send(v0); } catch(e1) { } o0.g1.g0 = Proxy.create(h0, h1); } } catch(e2) { } g1.a0.shift(p0, h2, b1); return v0; }), this.o2); } catch(e1) { } v0 = evaluate(\"(null.eval(\\\"i0.next();\\\"))\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: this, noScriptRval: (x % 3 == 1), sourceIsLazy: true, catchTermination: true })); return s2; });");
/*fuzzSeed-42369751*/count=134; tryItOut("Object.prototype.watch.call(m1, \"startsWith\", (function mcc_() { var riojsl = 0; return function() { ++riojsl; if (/*ICCD*/riojsl % 10 == 3) { dumpln('hit!'); /*RXUB*/var r = r2; var s = \"\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u2908\\u2908\\u2908\\u000bU\\u2908\\u2908\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u000b\\n\\u2908\\u2908\\u2908\\u2908\\u2908\\u2908\\u2908\\u2908\\u2908\\u2908\\u2908\\u000bU\\u2908\\u2908\"; print(uneval(r.exec(s)));  } else { dumpln('miss!'); try { a0 = a2.slice(NaN, -15); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } /*MXX2*/o1.g1.Object.defineProperty = m2; } };})());");
/*fuzzSeed-42369751*/count=135; tryItOut("((/*FARR*/[\"\\u38C6\", false, ...[], , window].sort));");
/*fuzzSeed-42369751*/count=136; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ (mathy0(((( ! (( ! x) <= (( ! (( ! (x >>> 0)) >>> 0)) >>> 0))) >>> 0) >>> 0), (( - Math.fround(mathy0(mathy1(x, -0x100000001), Math.imul(x, ( + (y ? y : y)))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [42, 2**53-2, -1/0, -0x080000001, 2**53+2, Number.MIN_VALUE, -0x100000000, 1, 0x07fffffff, -Number.MIN_VALUE, -(2**53), 0x080000000, -0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, -0x07fffffff, 0x080000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 0, 0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, Math.PI, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=137; tryItOut("\"use strict\"; ((makeFinalizeObserver('tenured')));");
/*fuzzSeed-42369751*/count=138; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.tan((( - Math.fround(Math.trunc((( ! x) | 0)))) | 0)) | 0) ? ( ~ ( ! x)) : (Math.fround(Math.fround((Math.fround(( + (((( - Math.fround(0x07fffffff)) >>> 0) >= (y | 0)) | 0))) <= Math.atan2(Math.fround(x), Math.fround(y))))) | Math.fround(mathy0(mathy3(Math.fround(Math.acos(mathy0((y | 0), y))), (-0x100000001 >>> 0)), (mathy2(x, y) >>> 0))))); }); testMathyFunction(mathy4, [Math.PI, 0/0, -0x080000000, Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, 0x080000000, 2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, 0x07fffffff, -Number.MAX_VALUE, 1, -Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, 1/0, 42, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, 0x100000000, -(2**53+2), 0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, -0x100000000, 0.000000000000001, -0x100000001, -(2**53)]); ");
/*fuzzSeed-42369751*/count=139; tryItOut("mathy4 = (function(x, y) { return Math.pow((((((y >>> 0) ? (( ~ ((Math.fround((( + Math.fround((Math.fround(x) >>> Math.fround(x)))) <= (x | 0))) | Math.fround(y)) >>> 0)) | 0) : (Math.pow((Math.log10((Math.sign((0x07fffffff >>> 0)) >>> 0)) >>> 0), ((y === ( + Math.max(( + y), x))) >>> 0)) >>> 0)) >>> 0) << (((( ! -Number.MIN_SAFE_INTEGER) ? ( + mathy3(Math.abs((y >>> 0)), x)) : (( + Math.pow((x | 0), Math.log10(x))) >>> 0)) >>> 0) == 0)) >>> 0), ((((mathy3((Math.sqrt(x) >>> 0), 0.000000000000001) | 0) - ((((( + y) | 0) | 0) * -(2**53)) | 0)) === Math.fround((Math.fround(( + (x > ((( ! (-(2**53) | 0)) | 0) | 0)))) <= y))) == Math.max(-0x100000000, Math.tanh(( + ( - (y ^ ( + ((0x07fffffff | 0) ** y))))))))); }); testMathyFunction(mathy4, [Math.PI, -0x100000000, -(2**53-2), 42, -0x0ffffffff, 0, 1, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, -0x07fffffff, 0x07fffffff, 1/0, -0x080000000, 0x0ffffffff, -1/0, -0, -0x100000001, 0x100000001, 2**53+2, -0x080000001, 0.000000000000001, 0x100000000, 0/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), 2**53, -Number.MIN_VALUE, 2**53-2, 0x080000001]); ");
/*fuzzSeed-42369751*/count=140; tryItOut("\"use strict\"; a2.push(h1, x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: Math.imul, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: undefined, }; })(x((4277))), Math.asinh(new ((uneval(/(?:(?=(?=[^])*))**(?:.|(?=J){17,20})/y)))(this.__defineSetter__(\"y\", String.prototype.small), ((void version(170)))))), c-=(let (yield =  \"\" , xtbyuh, kuqmln, e) x));");
/*fuzzSeed-42369751*/count=141; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=142; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    switch ((((i1)+(i0)) | ((/*FFI*/ff(((((0x7610cef5)) ^ ((0x5e5b9876)))))|0)))) {\n      case -3:\n        return (((i1)-((-127.0) >= (2199023255553.0))))|0;\n    }\n    {\n      i0 = (i0);\n    }\n    {\n      {\n        i0 = (i1);\n      }\n    }\n    i1 = (((-0xfeb5a*(i0))>>>(((((0x541dcf33)-(-0x8000000)+(0xffffffff)) | ((0x0) % (0x3ba631e7))) <= ((/*UUV2*/(x.__lookupSetter__ = x.cbrt)) | ((i0)))))) > (new true()));\n    return (((/*FFI*/ff(((+((562949953421313.0)))), ((-0x8000000)), ((Infinity)), ((((9.0)) - ((Infinity)))), ((-1.03125)), ((Math.min(-14, x))), ((((0x24b35497)) >> ((-0x8000000)))), ((513.0)), ((257.0)))|0)-((((i0))>>>(((((0xfa9e61f2))>>>((0xfe39c27c))) <= ((i0)))-((((-7.0)) * ((2097153.0))) > (1073741825.0))-(!(i0)))))+(i1)))|0;\n  }\n  return f; })(this, {ff: (((function factorial(kuoupx) { a0.forEach((function() { try { s2 += s1; } catch(e0) { } e2.add(i1); return i2; }));; if (kuoupx == 0) { ; return 1; } ; return kuoupx * factorial(kuoupx - 1);  })(23434))).bind()}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [1, 2**53-2, 0x080000001, -Number.MIN_VALUE, -0x07fffffff, Math.PI, -0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 0x0ffffffff, -0x0ffffffff, 0x100000001, -(2**53-2), Number.MAX_VALUE, 2**53, Number.MIN_VALUE, 0.000000000000001, 0x080000000, 42, 0/0, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, -0x080000000, 0, -1/0, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -Number.MAX_VALUE, -(2**53), -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=143; tryItOut("var ilwiga = new ArrayBuffer(4); var ilwiga_0 = new Int16Array(ilwiga); ilwiga_0[0] = 12; var ilwiga_1 = new Int16Array(ilwiga); ilwiga_1[0] = 20; Array.prototype.splice.call(a2, NaN, b);return false;print(ilwiga_0[0]);this.e2.delete(s2);");
/*fuzzSeed-42369751*/count=144; tryItOut("b1.valueOf = (function(j) { if (j) { try { this.a0 = arguments; } catch(e0) { } try { s1 += g2.g2.s1; } catch(e1) { } m2.has(f2); } else { for (var p in p0) { try { (void schedulegc(g0)); } catch(e0) { } try { const b0 = t2.buffer; } catch(e1) { } g2 = this; } } });");
/*fuzzSeed-42369751*/count=145; tryItOut("\"use strict\"; h0 = g2;");
/*fuzzSeed-42369751*/count=146; tryItOut("\"use strict\"; v1 = evaluate(\"function f2(g1.p2)  { v2 = t1.byteOffset; } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: 4, sourceIsLazy: false, catchTermination: function (z) { \"use strict\"; (false); } .prototype }));");
/*fuzzSeed-42369751*/count=147; tryItOut("\"use strict\"; h2.toString = (function() { for (var j=0;j<2;++j) { f2(j%4==1); } });");
/*fuzzSeed-42369751*/count=148; tryItOut("/*RXUB*/var r = /(?!(?:(\\b\\t|\\B*?))+?)*|[]/ym; var s = \"\\ufb3f\"; print(s.match(r)); ");
/*fuzzSeed-42369751*/count=149; tryItOut("g0.offThreadCompileScript(\"{z: [, {a, b: x, window: {x, d: [, , ], \\u3056: {y: {x: [{}]}, y, x: [{x: NaN}\\u000d, (Math.imul(27, 20))((void shapeOf(this)))]}}, x: []\\u000c}], w: [, , [x, ], ], x: y, window: {a: w, eval, b, x: {eval: x, x: eval(\\\" /x/g \\\"), z: {a: {x: c}, x: x, w, window: {}}}}, this.NaN: NaN, window: [eval, {x: [x, , a, ]}, , x, {x: {}, NaN: [, [[, ], ], ], x, eval: [, a, , []], c: x}, []]} = (timeout(1800))\");");
/*fuzzSeed-42369751*/count=150; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=151; tryItOut("\"use strict\"; Object.seal(e1);\n{for (var v of g0.b1) { try { m0.set(b2, f2); } catch(e0) { } try { f2 + g1.a2; } catch(e1) { } try { v0 = evalcx(\"[z1]\", g0); } catch(e2) { } v1 = g1.runOffThreadScript(); } }\n");
/*fuzzSeed-42369751*/count=152; tryItOut("\"use strict\"; o1 = {};");
/*fuzzSeed-42369751*/count=153; tryItOut("mathy4 = (function(x, y) { return mathy2((Math.atan2(((Number.MIN_VALUE ** 42) >> x), (x && Math.fround(Math.fround(( ~ Math.fround(x)))))) >>> 0), Math.fround(( ! Math.fround(( + ( - ( + ( - Math.fround(x))))))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, -0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000000, 1, 2**53+2, 42, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, 0x100000000, 1.7976931348623157e308, -(2**53), 2**53, -0x080000000, Number.MAX_VALUE, 0/0, -(2**53+2), -(2**53-2), -0x07fffffff, 0x07fffffff, 0x0ffffffff, 2**53-2, Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, -0x080000001, 0, 0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=154; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, -0x100000000, -0x0ffffffff, 2**53-2, -0, -(2**53-2), 2**53, -(2**53+2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, 0x100000001, -0x080000001, Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, 42, Math.PI, -Number.MIN_VALUE, 0x080000001, 0x080000000, 1.7976931348623157e308, 2**53+2, 0/0, -Number.MAX_VALUE, 0.000000000000001, 0x07fffffff]); ");
/*fuzzSeed-42369751*/count=155; tryItOut("m2 + '';");
/*fuzzSeed-42369751*/count=156; tryItOut("mathy5 = (function(x, y) { return Math.fround(mathy3(Math.fround(Math.pow((( + Math.clz32(( ~ x))) < ( + (( - x) | 0))), Math.fround(Math.fround(( - y))))), Math.fround((Math.hypot((-1/0 ? -(2**53) : 42), ( + ( + y))) >= Math.hypot((mathy3(((( + 0x080000000) | 0) || ( + ( + (y >>> 0)))), (Math.sinh(y) | 0)) && y), x))))); }); testMathyFunction(mathy5, /*MARR*/[function(){}, function(){}, function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){},  /x/ ,  /x/g , {},  /x/ ,  /x/g , {},  /x/g ,  /x/g ,  /x/g , {},  /x/g , {},  /x/ , {}, function(){}, function(){}, {},  /x/g , {}, {}, {},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){}, {},  /x/ ,  /x/g ,  /x/g , {},  /x/ ,  /x/ ,  /x/g , {}, function(){},  /x/ , {}, {}, {},  /x/ ,  /x/ , {},  /x/ ,  /x/ ,  /x/ ,  /x/g , function(){}, {}, {},  /x/ , {},  /x/ ,  /x/ ,  /x/ ,  /x/ , {}, {}, function(){}, {}, function(){},  /x/g , {},  /x/ ]); ");
/*fuzzSeed-42369751*/count=157; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, 0/0, -0x100000000, -(2**53-2), -0, -1/0, -Number.MIN_VALUE, 42, 0, -0x080000001, 0x100000000, -(2**53), 2**53, 2**53+2, -0x07fffffff, -(2**53+2), 0x080000001, 1, Number.MAX_VALUE, 0x0ffffffff, -0x080000000, -0x0ffffffff, Math.PI, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-42369751*/count=158; tryItOut("\"use asm\"; testMathyFunction(mathy1, [-0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0, 1/0, -0x0ffffffff, -0x100000001, -0x07fffffff, 0x100000001, -Number.MIN_VALUE, Math.PI, -0x100000000, 42, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), 0, 0x07fffffff, -0x080000000, 0x080000000, 2**53+2, 0x080000001, -(2**53), 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -(2**53+2), 2**53-2, Number.MAX_VALUE, 1, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=159; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.fround(((((Math.abs(Math.cbrt(x)) | 0) >>> 0) - Math.pow(( ~ (Math.min(y, y) >>> 0)), mathy0(mathy3(Number.MAX_VALUE, 1/0), Number.MIN_VALUE))) < (Math.atan2(y, Math.sin(Number.MIN_VALUE)) ? x : x))) | ( + Math.atan2((( ~ (((y >>> 0) && ((( + (-(2**53+2) ? y : (y >>> 0))) >>> 0) ? Math.ceil(( + y)) : ( ! y))) >>> 0)) >>> 0), Math.fround((Math.pow((y >>> 0), Math.log2(x)) << Math.pow(y, (x ? x : x)))))))); }); testMathyFunction(mathy4, /*MARR*/[-Number.MAX_SAFE_INTEGER, new String(''), new String(''), [(void 0)], [(void 0)], new String(''), -Number.MAX_SAFE_INTEGER, new String(''), [(void 0)], new String(''), new String(''), [(void 0)], [(void 0)], -Number.MAX_SAFE_INTEGER, new String(''), -Number.MAX_SAFE_INTEGER, [(void 0)], -Number.MAX_SAFE_INTEGER, new String(''), new String(''), new String(''), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, [(void 0)], [(void 0)], -Number.MAX_SAFE_INTEGER, new String(''), new String(''), -Number.MAX_SAFE_INTEGER, new String(''), -Number.MAX_SAFE_INTEGER, new String(''), new String(''), [(void 0)], [(void 0)], new String('')]); ");
/*fuzzSeed-42369751*/count=160; tryItOut("mathy0 = (function(x, y) { return ( + (( + Math.pow((Math.sign(( + y)) | 0), ( + x))) != Math.log((( + x) !== ( ~ (( - x) | 0)))))); }); testMathyFunction(mathy0, /*MARR*/[({}), ({}), true, x, true, ({}), ({}), ({}), true, ({}), x, x, true, ({}), true, ({}), ({}), ({}), x, x, ({}), x, x, x, x, ({}), ({}), x, true, x, ({}), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, ({}), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, true, ({}), x, x, true, ({}), ({}), ({}), ({}), ({}), x, ({}), ({}), x, x, x, ({}), x, true, true, x, ({}), ({}), ({}), ({}), ({}), ({}), x, ({}), true, ({}), true, x, ({})]); ");
/*fuzzSeed-42369751*/count=161; tryItOut("e2 = new Set;");
/*fuzzSeed-42369751*/count=162; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=163; tryItOut("testMathyFunction(mathy1, [-0, '/0/', undefined, null, (new Number(0)), NaN, ({toString:function(){return '0';}}), (new Boolean(true)), true, false, (new Number(-0)), '\\0', objectEmulatingUndefined(), 1, '0', /0/, [0], 0, 0.1, (new Boolean(false)), ({valueOf:function(){return '0';}}), (function(){return 0;}), (new String('')), [], '', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-42369751*/count=164; tryItOut("/*vLoop*/for (uocdfe = 0, x; uocdfe < 153; (4277), ++uocdfe) { a = uocdfe; /* no regression tests found */ } ");
/*fuzzSeed-42369751*/count=165; tryItOut("mathy5 = (function(x, y) { return ( + Math.cosh(Math.fround((Math.max(Math.fround(( - (Math.clz32(( + x)) | 0))), y) == ( + 1/0))))); }); testMathyFunction(mathy5, /*MARR*/[new Boolean(false), x, (void 0), (void 0), (void 0), x, (void 0), new Boolean(false), (void 0), x, (void 0), new Boolean(false), (void 0), (void 0), (void 0), x, new Boolean(false), x, (void 0), (void 0), x, (void 0), new Boolean(false), (void 0), x, new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0)]); ");
/*fuzzSeed-42369751*/count=166; tryItOut("Array.prototype.push.call(a2, b0, h1);");
/*fuzzSeed-42369751*/count=167; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + ( + ( + Math.min((Math.pow((y >>> 0), (x >>> 0)) >>> 0), ((Math.tan(Math.fround(Math.max(Math.fround(-(2**53-2)), Math.fround(y)))) >>> 0) % (Math.fround((y && ( + Math.asin((Number.MAX_VALUE >>> 0))))) ? 0.000000000000001 : Math.pow(y, x))))))); }); ");
/*fuzzSeed-42369751*/count=168; tryItOut("\"use strict\"; Object.defineProperty(this, \"s1\", { configurable: true, enumerable: true,  get: function() {  return new String(f2); } });");
/*fuzzSeed-42369751*/count=169; tryItOut("mathy2 = (function(x, y) { return (( ~ ((mathy1(( + ( ! ( + 0x100000000))), Math.cos((Math.abs((x >>> 0)) >>> 0))) | 0) | 0)) | 0); }); testMathyFunction(mathy2, ['', '/0/', false, (new Number(0)), [], 0.1, null, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Boolean(false)), ({valueOf:function(){return 0;}}), NaN, true, '\\0', undefined, 0, -0, (new Number(-0)), (function(){return 0;}), (new String('')), objectEmulatingUndefined(), (new Boolean(true)), /0/, '0', [0], 1]); ");
/*fuzzSeed-42369751*/count=170; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0.1, [], ({toString:function(){return '0';}}), [0], '\\0', '/0/', ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Number(0)), true, undefined, objectEmulatingUndefined(), '0', (function(){return 0;}), ({valueOf:function(){return '0';}}), 0, (new String('')), null, (new Number(-0)), NaN, /0/, false, '', -0, 1, (new Boolean(true))]); ");
/*fuzzSeed-42369751*/count=171; tryItOut("\"use strict\"; /*vLoop*/for (igkvsk = 0; igkvsk < 107; ++igkvsk) { const d = igkvsk; this.o1 = {}; } ");
/*fuzzSeed-42369751*/count=172; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; bailout(); } void 0; } /* no regression tests found */");
/*fuzzSeed-42369751*/count=173; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround((( - (Math.pow((Math.min((x | 0), (Math.max(Math.PI, -(2**53-2)) | 0)) >>> 0), (( ~ y) == y)) >>> 0)) ** (Math.cos((((((((y | 0) ? (0x100000000 | 0) : (x | 0)) | 0) | 0) == Math.imul(x, y)) | 0) >>> 0)) ? ((Math.expm1((( + ( - Math.fround(x))) >>> 0)) | 0) >>> 0) : x))) ? Math.fround(Math.tanh(mathy0(( + Math.max(0x080000000, ( + ( + ( + (x , ( - (y | 0)))))))), ((( ! (Math.fround(((y >>> 0) + (( ~ 0x100000001) >>> 0))) | 0)) | 0) | 0)))) : Math.fround(( + Math.round(( - ( + Math.pow(y, x)))))))); }); testMathyFunction(mathy5, [0x080000001, Number.MIN_VALUE, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, -1/0, -Number.MIN_VALUE, 0.000000000000001, 42, -0, 1/0, -0x07fffffff, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -0x100000001, 0x080000000, 0/0, 1.7976931348623157e308, 0x100000001, -0x100000000, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=174; tryItOut("/*infloop*/for((Math.tan(-23)); Math.atan2(-0, 0); ((function fibonacci(ipagsy) { ; if (ipagsy <= 1) { Object.preventExtensions(b0);; return 1; } m1.delete(p2);; return fibonacci(ipagsy - 1) + fibonacci(ipagsy - 2); /*MXX3*/this.g2.Math.log1p = this.g0.Math.log1p; })(1))) if(length) Array.prototype.reverse.call(a2, b1); else  if (false) this.v1 = 4; else {for (var p in g2.b0) { try { b2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -576460752303423500.0;\n    d1 = (-129.0);\n    return +((Float64ArrayView[((i0)) >> 3]));\n    (Uint32ArrayView[(-0xfffff*((i0) ? ((4277)) : (0xfdeb72b0))) >> 2]) = ((0xf947b4dd)+(i0)+(0xfa537a4c));\n    d2 = (d1);\n    return +(((2147483649.0) + (d1)));\n  }\n  return f; }); } catch(e0) { } try { e1.delete(this.s2); } catch(e1) { } try { const v0 = g1.eval(\" '' \"); } catch(e2) { } a1 = r1.exec(s2); }v0 = Object.prototype.isPrototypeOf.call(p1, i1); }s1.toSource = (function mcc_() { var zlkzfz = 0; return function() { ++zlkzfz; f2(/*ICCD*/zlkzfz % 3 == 1);};})();");
/*fuzzSeed-42369751*/count=175; tryItOut("mathy3 = (function(x, y) { return ( + (( + ( - Math.fround(( ! Math.pow(2**53, -1/0))))) !== ( + ( + Math.sign(mathy0((( + (y | 0)) | 0), Math.fround(mathy0(2**53, Math.fround((( + -0x080000001) >>> 0)))))))))); }); testMathyFunction(mathy3, [-0, (new Boolean(false)), (new String('')), ({valueOf:function(){return '0';}}), NaN, ({toString:function(){return '0';}}), '\\0', /0/, 1, [0], objectEmulatingUndefined(), '/0/', null, true, (new Boolean(true)), (new Number(0)), undefined, '0', ({valueOf:function(){return 0;}}), false, 0, '', [], (new Number(-0)), (function(){return 0;}), 0.1]); ");
/*fuzzSeed-42369751*/count=176; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=177; tryItOut("b1 = o0.t0.buffer;");
/*fuzzSeed-42369751*/count=178; tryItOut("mathy4 = (function(x, y) { return Math.atan2(( + ( ! ( + Math.atan2(Math.fround(y), Math.fround(y))))), Math.log10(Math.log(x))); }); ");
/*fuzzSeed-42369751*/count=179; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-42369751*/count=180; tryItOut("v2 = Object.prototype.isPrototypeOf.call(s0, i2);");
/*fuzzSeed-42369751*/count=181; tryItOut("\"use strict\"; s2 + '';");
/*fuzzSeed-42369751*/count=182; tryItOut("for (var p in h2) { try { Array.prototype.splice.apply(a0, [8, 14, e1]); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(b0, v2); } catch(e1) { } try { v0 = g1.eval(\"a2 = Array.prototype.map.call(g1.a1, (function() { for (var j=0;j<1;++j) { f1(j%2==1); } }));\"); } catch(e2) { } m2.has(v0); }");
/*fuzzSeed-42369751*/count=183; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=184; tryItOut("/*tLoop*/for (let a of /*MARR*/[new Number(1), (0/0), new Number(1), (0/0), new Number(1), new Number(1), (0/0), new Number(1), (0/0), new Number(1), (0/0), new Number(1), (0/0), new Number(1), (0/0), (0/0), new Number(1), new Number(1), (0/0), new Number(1), (0/0), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (0/0), (0/0), new Number(1), new Number(1), new Number(1), (0/0), (0/0), new Number(1), new Number(1), (0/0), (0/0), (0/0), (0/0), (0/0)]) { v1 = Object.prototype.isPrototypeOf.call(o1, o1.o2.b1); }");
/*fuzzSeed-42369751*/count=185; tryItOut("v2 = Object.prototype.isPrototypeOf.call(t0, o1);");
/*fuzzSeed-42369751*/count=186; tryItOut("mathy0 = (function(x, y) { return (Math.max(((((( + Math.exp(( + Math.max(y, -0x080000001)))) >= Math.atan(( + -0x080000001))) !== Math.abs(x)) >>> 0) >>> 0), ((( ~ (Math.log2(y) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0x0ffffffff, 0x080000001, 0x080000000, 0, 0.000000000000001, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 42, -0x080000000, 2**53-2, -0, Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, -0x07fffffff, 2**53, 0/0, -0x100000000, 0x100000000, -0x0ffffffff, -(2**53-2), 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -Number.MIN_SAFE_INTEGER, 1, -0x100000001, 2**53+2]); ");
/*fuzzSeed-42369751*/count=187; tryItOut("mathy2 = (function(x, y) { return (( + (( + Math.max(( ! (2**53-2 >>> 0)), (Math.hypot(y, (x >>> 0)) >>> (Math.sinh((y | 0)) | 0)))) >>> ( + Math.cosh((Math.asinh((-0x080000001 | 0)) | 0))))) ? Math.fround(((( ~ x) >>> 0) ^ Math.hypot(x, Math.fround(Math.abs(( + Math.abs(-0x07fffffff))))))) : Math.fround((Math.clz32((( + (x / y)) | 0)) | 0))); }); ");
/*fuzzSeed-42369751*/count=188; tryItOut("\"use strict\"; a2.reverse();");
/*fuzzSeed-42369751*/count=189; tryItOut("g1.h0.has = (function() { try { v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 37 != 9), catchTermination: true })); } catch(e0) { } try { /* no regression tests found */ } catch(e1) { } try { f2 = [,,z1]; } catch(e2) { } this.t2.set(t0, ((d) = x)); throw o0; });");
/*fuzzSeed-42369751*/count=190; tryItOut("\"use strict\"; function  window (x)(String.prototype.sup\u000c)(x).prototype;");
/*fuzzSeed-42369751*/count=191; tryItOut("\"use strict\"; const x, x = this.__defineGetter__(\"x\", /*wrap1*/(function(){ ((4277));return new DFGTrue()})()), {x} = x > x.keys((4277), x), x = d, zsgcmo;for (var p in p0) { b0.__proto__ = f0; }");
/*fuzzSeed-42369751*/count=192; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -257.0;\n    var d3 = -17.0;\n    var d4 = 8388609.0;\n    {\n      i1 = ((0xa3fe0b11));\n    }\n    return +((d4));\n  }\n  return f; })(this, {ff: Map}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 0, -0x080000001, -0x07fffffff, 0x100000001, -(2**53), -0, Number.MIN_VALUE, -1/0, 0x080000000, -0x100000001, 2**53, 1, 1/0, 1.7976931348623157e308, 0x100000000, 42, -0x080000000, 0x0ffffffff, -(2**53-2), -0x0ffffffff, Math.PI, 0/0, 0.000000000000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-42369751*/count=193; tryItOut("g0.m1.set(i1, g1);");
/*fuzzSeed-42369751*/count=194; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - (Math.atanh(Math.fround(Math.fround(Math.max(( ~ 0x07fffffff), Math.fround((y , ( - (x >>> 0)))))))) | 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, -0x07fffffff, 0.000000000000001, 0x100000000, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -0, Number.MAX_VALUE, -(2**53+2), 2**53-2, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, 1, -Number.MAX_VALUE, 1.7976931348623157e308, 1/0, 2**53, -(2**53), -0x080000001, 0/0, 0x100000001, -0x100000000, -1/0, 0x07fffffff, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=195; tryItOut(" for  each(var b in \"\\uF86C\") {for (var p in g1) { try { s0.__iterator__ = (function(j) { if (j) { try { /*MXX1*/o0 = g2.URIError.prototype.constructor; } catch(e0) { } try { m2.set(g1, p0); } catch(e1) { } try { t1 = new Int32Array(a2); } catch(e2) { } /*ADP-2*/Object.defineProperty(a1, 4, { configurable: (b % 6 != 4), enumerable: 2251799813685249, get: (function() { try { g2.a2.length = 11; } catch(e0) { } try { g1.g1.offThreadCompileScript(\"this\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 34 != 23) })); } catch(e1) { } v2 = (x % 22 != 4); return t2; }), set: (function(j) { o2.f0(j); }) }); } else { try { m1.get(g1.g2); } catch(e0) { } try { s1 += s2; } catch(e1) { } try { for (var p in this.g2) { try { t1.__iterator__ = (function() { v0 = Array.prototype.some.apply(a0, [f1]); return b1; }); } catch(e0) { } try { /*RXUB*/var r = this.g2.r2; var s = \"\\u00b9\\u0017\\ua503\\u0017\\ua503\"; print(uneval(r.exec(s))); print(r.lastIndex);  } catch(e1) { } try { v2 = new Number(4); } catch(e2) { } g0 = this; } } catch(e2) { } v0 = g1.eval(\"mathy4 = (function(x, y) { return ((( + Math.pow(Math.tanh(Math.fround(Math.exp(y))), Math.fround(Math.hypot(Math.fround((Math.clz32(((Math.asinh((-0x07fffffff >>> 0)) >>> 0) >>> 0)) >>> 0)), Math.fround(x))))) , (Math.asinh((mathy2(x, (Math.sinh(( + 1/0)) >>> 0)) >>> 0)) !== Math.fround(Math.max(Math.fround((x >>> ( + Math.imul(( + y), ( + x))))), Math.fround((x && y)))))) >= ( - Math.atan2(-(2**53), Math.acosh(y)))); }); testMathyFunction(mathy4, [-0x100000001, 1/0, -0x100000000, 0x100000001, 2**53-2, 0x100000000, Math.PI, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -0, -(2**53), 0/0, Number.MIN_VALUE, 0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, 0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, -0x080000001, -1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53, 42, 0.000000000000001]); \"); } }); } catch(e0) { } try { o2.m2 + b1; } catch(e1) { } try { function g0.f1(g1.h2)  { return  ''  }  } catch(e2) { } /*RXUB*/var r = r2; var s = \"\\u00c7\"; print(uneval(s.match(r)));  } }");
/*fuzzSeed-42369751*/count=196; tryItOut("/*MXX3*/o1.g2.Promise.reject = g2.Promise.reject;");
/*fuzzSeed-42369751*/count=197; tryItOut("a2.reverse((4277), e2, this.i2);");
/*fuzzSeed-42369751*/count=198; tryItOut("f2 = Proxy.create(h2, g0);");
/*fuzzSeed-42369751*/count=199; tryItOut("\"use strict\"; a0.pop();");
/*fuzzSeed-42369751*/count=200; tryItOut("mathy3 = (function(x, y) { return mathy1(mathy1(( + (mathy2(( + ( ~ ( + x))), (( ! Math.fround(Math.atanh(Math.fround(Number.MAX_SAFE_INTEGER)))) | 0)) ? ( + (mathy2((x | 0), Math.atan(Math.clz32(x))) >>> 0)) : ( + Math.atan2(y, (( ~ ( + y)) | 0))))), Math.fround(((Math.atanh(mathy1(( + 42), ( ~ y))) | 0) ? ( + (Math.min(Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) % Math.fround((y && -0x0ffffffff)))), y) & (Math.imul((y | 0), (x | 0)) | 0))) : Math.fround(Math.atan2(x, x))))), (Math.pow((Math.pow(((Math.min(( - ( + Number.MIN_SAFE_INTEGER)), (0x080000000 >>> 0)) >>> 0) >>> 0), ( - (Math.trunc((y >>> 0)) >>> 0))) | 0), Math.max((-0 >>> 0), ( ~ (( - ( + Math.acos(-1/0))) | 0)))) >>> 0)); }); ");
/*fuzzSeed-42369751*/count=201; tryItOut("/*ADP-2*/Object.defineProperty(a1, 14, { configurable: (x % 29 == 17), enumerable: false, get: (function mcc_() { var htrlgs = 0; return function() { ++htrlgs; if (/*ICCD*/htrlgs % 4 == 2) { dumpln('hit!'); try { /*RXUB*/var r = r2; var s = new Int16Array().yoyo(([,] / [,,])); print(s.split(r)); print(r.lastIndex);  } catch(e0) { } try { g2.t2[2]; } catch(e1) { } a1 = (function() { yield ([]) = x; } })(); } else { dumpln('miss!'); try { Array.prototype.push.call(a1, b1, (let (b =  \"\" ) this)); } catch(e0) { } h2 + o1.e0; } };})(), set: let (x) x = (x = Proxy.createFunction(({/*TOODEEP*/})( '' ),  '' , Math.atan)).then });");
/*fuzzSeed-42369751*/count=202; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return mathy1(((( + (( + mathy0((mathy0(x, y) | 0), ( + Math.cosh(( + Math.fround((( + -Number.MIN_VALUE) > -0x0ffffffff))))))) * Math.fround(Math.fround(( - Math.fround(y)))))) ? (mathy1(Math.fround(Math.hypot(Math.fround(mathy0(Math.fround(x), 0x100000001)), y)), Math.atan2(Math.fround(x), Math.fround(-Number.MAX_VALUE))) | 0) : Math.PI) >= (Math.imul(((mathy0(x, (Math.min(Math.pow(y, y), y) | 0)) >>> 0) | 0), (( - (Math.pow(-0x080000000, (x | 0)) | 0)) | 0)) | 0)), ( + mathy1((((((Math.atan((y >>> 0)) >>> 0) == Math.fround((( + (2**53-2 << y)) | 0))) | 0) >>> ( + (x / (Math.max(Number.MAX_SAFE_INTEGER, y) | 0)))) | 0), (( + (Math.atanh(Math.fround(Math.tan((Math.expm1(( + -0x080000000)) | 0)))) | 0)) | 0)))); }); testMathyFunction(mathy2, [-0x0ffffffff, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, -0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, -0x080000000, 0x07fffffff, -Number.MIN_VALUE, Math.PI, 0x080000000, 2**53-2, 42, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0, 1, -1/0, 0x100000000, 1/0, 0/0, 0x080000001, -0x080000001, -(2**53), -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53+2), -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=203; tryItOut("mathy0 = (function(x, y) { return ( + ((( ~ (((( ~ x) ? (( + ( ~ x)) | 0) : x) >>> 0) , (Math.fround((y - y)) | 0))) | 0) !== ((Math.tanh(((Math.round((y | 0)) >>> 0) >>> 0)) >>> 0) ^ (( ~ x) >>> 0)))); }); testMathyFunction(mathy0, [1/0, -0x100000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x100000001, 0x100000001, -0x080000000, 2**53, 0x080000001, -(2**53+2), Number.MIN_VALUE, 42, -(2**53-2), -0x07fffffff, 0x100000000, 0x07fffffff, 0x0ffffffff, 0x080000000, -0, -(2**53), 0/0, 0, 2**53+2, 0.000000000000001, 2**53-2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -1/0]); ");
/*fuzzSeed-42369751*/count=204; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2|\\B/gy; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-42369751*/count=205; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log2((((Math.fround(Math.min(Math.fround(x), Math.fround(Math.log(y)))) ^ Math.hypot((Math.fround(Math.sinh(y)) - y), Math.fround(Math.asin((mathy0(y, y) | 0))))) >> Math.cosh(( + Math.fround(mathy1(Math.fround(( + ( ~ (y >>> 0)))), 0/0))))) >>> 0)); }); ");
/*fuzzSeed-42369751*/count=206; tryItOut("if((x % 6 != 2)) g0.h0.defineProperty = f0;\nt0 = new Uint16Array(t0);\n");
/*fuzzSeed-42369751*/count=207; tryItOut("a0[7];");
/*fuzzSeed-42369751*/count=208; tryItOut("\"use strict\"; print(x);/*MXX3*/g0.String.prototype.toLowerCase = g1.String.prototype.toLowerCase;");
/*fuzzSeed-42369751*/count=209; tryItOut("mathy2 = (function(x, y) { return (Math.imul(Math.fround(Math.hypot((Math.exp(-Number.MAX_VALUE) | 0), (Math.exp(Math.log1p(Math.pow(( + mathy1(( + y), ( + Number.MAX_VALUE))), y))) | 0))), (( + ((mathy1(Math.fround(( + ( + Math.fround(Math.hypot(((0x07fffffff >>> 0) >>> y), (Math.trunc(x) | 0)))))), Math.fround(Math.imul(Math.fround(Math.hypot(Math.fround(( + Math.log10(2**53-2))), Number.MAX_SAFE_INTEGER)), (x >>> 0)))) | 0) ? ( + ( ~ ( + mathy1(((x >>> 0) && (Math.clz32((-0 | 0)) | 0)), Math.atan(( + y)))))) : ( + (Math.hypot(( + ((((Math.log10((Math.fround(( - Math.hypot((2**53 >>> 0), x))) | 0)) | 0) >>> 0) * x) >>> 0)), ( + 0/0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy2, [1/0, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, 0.000000000000001, -0, -0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -1/0, -0x07fffffff, 0x100000000, -0x080000000, 0x100000001, 0/0, 2**53, 0x0ffffffff, 0x07fffffff, -(2**53-2), 1, -Number.MAX_VALUE, 0, -0x080000001, -(2**53), 42, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001]); ");
/*fuzzSeed-42369751*/count=210; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.imul(Math.fround(Math.tanh((((2**53-2 | 0) % (-0x100000000 | 0)) | 0))), Math.fround(Math.tanh(( ! Math.fround(Math.min((y >>> 0), (( + 0/0) >>> 0)))))))) << Math.tanh(( + Math.fround((Math.fround(Math.fround((Math.fround(( + ( ! y))) - Math.fround(x)))) == Math.fround(((Math.fround((Math.fround(y) | Math.fround((x < (((-0x100000001 | 0) * (x | 0)) | 0))))) === (Math.sign(Math.fround(Math.acos(Math.acos(y)))) >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy0, [0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, -1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 42, 0/0, -(2**53), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, -(2**53+2), 0, Math.PI, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, Number.MAX_VALUE, 2**53+2, 0x100000000, -0x0ffffffff, 0x080000000, 0x080000001, 1.7976931348623157e308, -0x080000001, -0x080000000, 1, -0x100000000, -0x100000001]); ");
/*fuzzSeed-42369751*/count=211; tryItOut("\"use strict\"; e1.add(g0);");
/*fuzzSeed-42369751*/count=212; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=213; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((((Math.ceil(( + Math.atan(x))) & ( ~ (Math.fround(x) >>> (( - (-Number.MIN_SAFE_INTEGER * y)) >>> 0)))) | 0) - (Math.fround(Math.clz32(Math.fround(Math.fround(Math.fround(Math.fround(x)))))) | 0)) >>> 0); }); testMathyFunction(mathy4, [0x080000000, 1, -1/0, 0x0ffffffff, 2**53-2, 1/0, 0.000000000000001, Number.MAX_VALUE, 0x07fffffff, -(2**53), -(2**53+2), -0x100000000, -0x07fffffff, -0, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, 0x100000000, -0x080000001, 2**53, 0x100000001, -0x080000000, 42, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308]); ");
/*fuzzSeed-42369751*/count=214; tryItOut("e0.has(m2);");
/*fuzzSeed-42369751*/count=215; tryItOut("switch(let (b) b) { case 4: /*infloop*/ for  each(b in x) {print( '' ); }break; break; default: break; break; case (function(id) { return id }.__proto__) = ({hasInstance: [z1,,] }): break;  }");
/*fuzzSeed-42369751*/count=216; tryItOut("/*infloop*/do {print(({a1:1}) << y);/*tLoop*/for (let a of /*MARR*/[false, NaN, false, true, true, false, true, NaN, NaN, false, true, true, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, false, NaN, false, false, NaN, NaN, true]) { this.v2 = Infinity; } } while((c = x));");
/*fuzzSeed-42369751*/count=217; tryItOut("mathy3 = (function(x, y) { return Math.hypot(( + mathy0(mathy2((Math.max(( + Math.max((0x080000000 >>> 0), Math.fround(Math.fround(( + ( + (y << Math.fround(2**53+2)))))))), -(2**53+2)) >>> 0), Math.max(((Number.MAX_VALUE != x) >>> 0), ( + ( ! y)))), ( + Math.clz32(( + (( - (Math.round((( + y) | 0)) >>> 0)) | 0)))))), ( ! (Math.max((( + mathy2(( + -0), ( + x))) >>> 0), (Math.expm1((y ? ( + Math.sin(x)) : 0x100000001)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0x07fffffff, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, -0, 2**53, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), 0x100000000, -0x080000001, 0x080000000, -1/0, -0x07fffffff, -0x100000000, 0.000000000000001, 42, -Number.MAX_VALUE, 2**53+2, -0x080000000, -0x100000001, 1.7976931348623157e308, -(2**53-2), 0x080000001, 0/0, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=218; tryItOut("for (var p in v0) { try { a2.reverse((4277) && (void shapeOf(({}) = undefined)), m2, f2, a0); } catch(e0) { } try { v1 = g0.runOffThreadScript(); } catch(e1) { } v2 = g0.eval(\"g1.offThreadCompileScript(\\\"function f0(a2)  { e = [,,], a2, sfkzwc;print(x); } \\\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 6 != 0), sourceIsLazy: (x % 32 != 8), catchTermination: true }));\\nb1 + ''\\nt1 = new Uint8ClampedArray(a2);\\n\"); }");
/*fuzzSeed-42369751*/count=219; tryItOut("/*RXUB*/var r = /[\\S\\S\\S]\\b{0,}\\b|(?:\\2{2})\\3/gym; var s = \"01_aa_aaaaa_aa\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-42369751*/count=220; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.pow(((((Math.asinh(Math.min(Math.fround(x), y)) >>> 0) / Math.hypot(( + Math.sqrt(( + Math.cbrt(y)))), Math.sign(1.7976931348623157e308))) | 0) >>> 0), ( + Math.cos(Math.pow((((y >>> 0) ^ Math.pow(y, x)) >>> 0), (x ? Math.fround((Math.fround(0x080000000) & Math.fround(y))) : y))))); }); testMathyFunction(mathy0, [Math.PI, 1, 0x080000001, 0x080000000, 0x100000000, -0x07fffffff, 1.7976931348623157e308, -(2**53+2), -0x080000001, 2**53, -Number.MAX_VALUE, 0/0, 42, -1/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -(2**53-2), -(2**53), Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, 0, 0.000000000000001, -0x0ffffffff, 1/0, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=221; tryItOut("t1.valueOf = (function() { for (var j=0;j<0;++j) { f0(j%5==1); } });");
/*fuzzSeed-42369751*/count=222; tryItOut("\"use strict\"; ");
/*fuzzSeed-42369751*/count=223; tryItOut("d = (uneval((\u000cNaN = Proxy.createFunction(({/*TOODEEP*/})(13), Uint8Array))(x >>>= ({d: w})))), rvoewh, x, e, {} = Object.defineProperty(a, \"__count__\", ({get: function(y) { (21); }, set: Date.prototype.setUTCSeconds})) >>= (\u3056 = Proxy.createFunction(({/*TOODEEP*/})(this), Math.imul)) + x, valumg, x, ufkgdr, d = this.eval(\"\\\"use strict\\\"; mathy1 = (function(x, y) { \\\"use strict\\\"; return Math.hypot(Math.fround(Math.sign(( ~ (Math.hypot(mathy0(( + -(2**53+2)), ( ! mathy0(Number.MAX_SAFE_INTEGER, x))), Math.exp(y)) >>> 0)))), Math.atanh(Math.fround(((x !== Math.fround(Math.cos(Math.fround(Math.pow(y, ( + y)))))) , ((Math.hypot(Math.fround(mathy0(Math.ceil(( ~ (y >>> 0))), x)), x) >>> 0) | 0))))); }); \"), y = -24;while((x) && 0)v2 = evalcx(\"g0.m2.delete(this.p2);\", g2);");
/*fuzzSeed-42369751*/count=224; tryItOut("mathy3 = (function(x, y) { return Math.trunc((((Math.fround(( + Math.sinh((mathy1(((((x | 0) | (y | 0)) | 0) >>> 0), (x >>> 0)) | 0)))) << (( ! (( + (Math.expm1(x) | 0)) | 0)) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[new String('q'), [], [], false, new String('q'), new String('q'), false, [], [], [], new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), false, new String('q'), [], false, new String('q'), new String('q'), [], [], false, new Boolean(false), new Boolean(false), false, new String('q'), [], [], new String('q'), [], new Boolean(false), [], false, [], [], [], new String('q'), new Boolean(false), new String('q'), new Boolean(false), [], new String('q'), new String('q'), false, [], new String('q'), false, new Boolean(false), new String('q'), false, false, [], new Boolean(false), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-42369751*/count=225; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.cbrt((mathy0((( + Math.exp(( + Math.imul((x ? x : Math.trunc(x)), Math.fround(( - y)))))) | 0), ((Math.round(((x && x) + Math.fround(x))) >>> 0) | 0)) | 0)) >>> 0); }); ");
/*fuzzSeed-42369751*/count=226; tryItOut(" for (let z of () => [x]) for (var v of f0) { try { e2.delete(b2); } catch(e0) { } try { a2.splice(NaN, 5); } catch(e1) { } try { a2.sort(); } catch(e2) { } v1 = evaluate(\"function f1(p0) 20\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 27 != 4) })); }function e(\u3056, x)(void options('strict'))a1 = Array.prototype.filter.apply(a0, [(function() { try { a2.unshift(s0, s2, p0); } catch(e0) { } try { this.v2 = Object.prototype.isPrototypeOf.call(g2, v2); } catch(e1) { } try { for (var v of e1) { try { o1.f2(this.b2); } catch(e0) { } try { s1 += this.s0; } catch(e1) { } try { a2 = a1.filter((function mcc_() { var yksdhx = 0; return function() { ++yksdhx; if (false) { dumpln('hit!'); try { /*ADP-2*/Object.defineProperty(a1, 8, { configurable: false, enumerable: (z % 3 == 0), get: f0, set: (function() { try { m1.has([]); } catch(e0) { } try { t0.valueOf = (function(j) { if (j) { try { Object.defineProperty(this, \"g2.v0\", { configurable: null, enumerable: true,  get: function() {  return r1.unicode; } }); } catch(e0) { } try { b1 + e2; } catch(e1) { } try { v1.toSource = f2; } catch(e2) { } i0.valueOf = o1.f0; } else { try { this.b2 = new SharedArrayBuffer(9); } catch(e0) { } try { Array.prototype.forEach.call(a1, (function() { try { /*ADP-2*/Object.defineProperty(a0, new RegExp(\"\\\\uA9CE\", \"ym\"), { configurable: true, enumerable: (x % 10 != 3), get: (function() { for (var j=0;j<13;++j) { f2(j%5==1); } }), set: (function() { a2.length = v0; return s1; }) }); } catch(e0) { } t2[undefined] = g2; return g0; }), window, s1); } catch(e1) { } f2 + ''; } }); } catch(e1) { } try { a2.unshift(p1); } catch(e2) { } delete b1[window]; return g0.g0; }) }); } catch(e0) { } m2.get(this.s2); } else { dumpln('miss!'); try { a1.reverse(); } catch(e0) { } try { s2.toString = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var tan = stdlib.Math.tan;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -2097153.0;\n    {\n      i0 = ((((((0xffffffff) ? (-281474976710655.0) : (1.015625))) - ((+(1.0/0.0)))) <= (1.9342813113834067e+25)) ? ((-262144.0) <= (-7.737125245533627e+25)) : (i1));\n    }\n    i1 = (i2);\n    i2 = (i2);\n    {\n      i2 = ((0xd1b33a9d));\n    }\n    {\n      d4 = (+abs(((+tan(((2.3611832414348226e+21)))))));\n    }\n    i1 = ((0x684df9ce) == ((0xfffff*(i0))>>>((i0))));\n    (Float32ArrayView[2]) = ((+((d4))));\n    return +((4.835703278458517e+24));\n  }\n  return f; }); } catch(e1) { } try { i1.send(this.s0); } catch(e2) { } s2 += s2; } };})()); } catch(e2) { } v0 + m1; } } catch(e2) { } g1.i2 = new Iterator(h1, true); return m0; }), i2, f2]);");
/*fuzzSeed-42369751*/count=227; tryItOut("\"use strict\"; var mavkhh = new SharedArrayBuffer(8); var mavkhh_0 = new Float64Array(mavkhh); print(mavkhh_0[0]); mavkhh_0[0] = -20; t2.set(t0, 7);a1 = arguments.callee.caller.caller.arguments;");
/*fuzzSeed-42369751*/count=228; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-1/0, Number.MIN_VALUE, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, 1, 0, 0.000000000000001, 2**53+2, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, -(2**53-2), 0x07fffffff, 0x080000000, -0x100000000, -0x0ffffffff, 0x0ffffffff, -(2**53+2), 2**53-2, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, Math.PI, 0x080000001, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 42, 2**53, 0x100000000, Number.MAX_SAFE_INTEGER, 1/0, -0x100000001]); ");
/*fuzzSeed-42369751*/count=229; tryItOut("\"use strict\"; /*RXUB*/var r = g2.o1.o1.r1; var s = let (x = (allocationMarker())) [, , {x, e, NaN}] = x; print(uneval(s.match(r))); ");
/*fuzzSeed-42369751*/count=230; tryItOut("/*iii*/for (var v of s2) { try { Array.prototype.unshift.call(a1, t1); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(p0, h2); } catch(e1) { } g2.g1.f2 + m2; }b = [let (y = \"\\u4960\", pavcag, x, zvkmhj, cqtzuo, uyliud, z, neyzme, ynsgmj) (y =  /x/g )];/*hhh*/function zvkmhj(...window){for(let [z, b] = ((Math)((4277))%= \"\" ) in x) {v1 + ''; }}");
/*fuzzSeed-42369751*/count=231; tryItOut("v1 = g1.t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-42369751*/count=232; tryItOut("\"use strict\"; { void 0; minorgc(false); }");
/*fuzzSeed-42369751*/count=233; tryItOut("\"use strict\"; a0 = new Array;");
/*fuzzSeed-42369751*/count=234; tryItOut("\"use strict\"; e2.has(z);");
/*fuzzSeed-42369751*/count=235; tryItOut("x = x, w = (void window = x *= ( /x/  < false.valueOf(\"number\")));var bdggmo, y, uauhnr, qvilal, window, eval, qsbpda;for (var p in o2.f0) { try { i0.send(this.f1); } catch(e0) { } o0.g1 = this; }");
/*fuzzSeed-42369751*/count=236; tryItOut("delete g1.s2[\"__proto__\"];");
/*fuzzSeed-42369751*/count=237; tryItOut("mathy3 = (function(x, y) { return ((Math.log(((( ! (( ! (((Math.tan(x) | 0) || (x | 0)) | 0)) >>> 0)) >>> 0) | 0)) | 0) / Math.fround(Math.log10((Math.fround(( ! ( + Math.min(( + ( + (Number.MAX_SAFE_INTEGER ** y))), Math.fround((( + Math.sqrt((-0x07fffffff >>> 0))) === x)))))) >>> 0)))); }); testMathyFunction(mathy3, [-1/0, 2**53, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53), 42, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x07fffffff, 0, -0x100000001, 0x080000001, 2**53-2, 1, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, 1/0, Math.PI, 0x080000000, 1.7976931348623157e308, -0, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=238; tryItOut("v2 = (g0 instanceof m0);");
/*fuzzSeed-42369751*/count=239; tryItOut("for(let d in null) print( /x/ );");
/*fuzzSeed-42369751*/count=240; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[Infinity, -Number.MIN_VALUE, Infinity, Infinity, Infinity, x, Infinity, Infinity, Infinity, -Number.MIN_VALUE, Infinity, Infinity, x, Infinity, x, Infinity, Infinity, Infinity, Infinity, -Number.MIN_VALUE, x, Infinity, -Number.MIN_VALUE, Infinity, -Number.MIN_VALUE, x, -Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=241; tryItOut("g2.m1.delete(e0);");
/*fuzzSeed-42369751*/count=242; tryItOut("\"use strict\"; h1.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-42369751*/count=243; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=244; tryItOut("\"use strict\"; ;");
/*fuzzSeed-42369751*/count=245; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=246; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( ~ (Math.fround(Math.pow(Math.fround((( + Math.tanh(y)) , (mathy0((mathy0(y, (y >>> 0)) | 0), Math.fround(x)) | 0))), Math.fround(Math.hypot(Math.imul(((Number.MIN_SAFE_INTEGER >>> 0) >> (((y >>> 0) - (x >>> 0)) | 0)), x), Math.min(( + (Math.fround(Math.hypot(-1/0, x)) != ( + y))), ( + Math.min(( + y), ( + x)))))))) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, -0, -0x100000000, -0x080000001, 1/0, 0x080000000, 0x07fffffff, -1/0, 1.7976931348623157e308, -0x07fffffff, 2**53, 42, Number.MIN_VALUE, 2**53+2, 0x080000001, -Number.MIN_VALUE, -(2**53), -0x080000000, 0x0ffffffff, 0, -Number.MAX_VALUE, -0x100000001, 1, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -(2**53+2), -(2**53-2), 2**53-2, 0.000000000000001, Math.PI]); ");
/*fuzzSeed-42369751*/count=247; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(h2, this.s0);");
/*fuzzSeed-42369751*/count=248; tryItOut("mathy2 = (function(x, y) { return (Math.fround((Math.fround((( + y) === Math.fround(-Number.MAX_VALUE))) > ((((Math.min((Math.ceil(x) >>> 0), (-0x0ffffffff | 0)) >>> 0) >>> 0) | ( + Math.pow(( + y), y))) >>> 0))) / Math.fround(Math.acos((Math.max((x | 0), (0 | 0)) | 0)))); }); ");
/*fuzzSeed-42369751*/count=249; tryItOut("mathy3 = (function(x, y) { return ( + Math.pow((Math.fround(y) >= (( - (x | 0)) | 0)), (mathy0((Math.fround(mathy1(x, Math.fround((( ! y) | 0)))) >>> 0), ((( ~ (x | 0)) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [-0x100000000, 0x100000001, 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 0x080000001, -0x080000000, 0x07fffffff, -0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, 1, 0x080000000, 42, -1/0, -0x0ffffffff, 0.000000000000001, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, -0x080000001, -0, -(2**53), 0x0ffffffff, 2**53, 0x100000000, -(2**53+2), 0/0, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=250; tryItOut("\"use strict\"; e0.delete(h2);");
/*fuzzSeed-42369751*/count=251; tryItOut("mathy4 = (function(x, y) { return (( ~ ( + (Math.hypot((mathy2(Math.hypot(y, Number.MIN_VALUE), ( + y)) >>> 0), mathy0((x | 0), ( ~ ((Math.ceil((-0 >>> 0)) >>> 0) >>> 0)))) + (((( ~ 1.7976931348623157e308) >>> 0) ? (Math.sin((Math.log2((( ~ (1 != Number.MIN_VALUE)) | 0)) | 0)) >>> 0) : (mathy3(x, -(2**53-2)) ? Math.imul(y, y) : y)) >>> 0)))) | 0); }); testMathyFunction(mathy4, [2**53-2, -(2**53-2), Number.MIN_SAFE_INTEGER, 0, -1/0, Number.MIN_VALUE, 0.000000000000001, 2**53, Number.MAX_VALUE, Math.PI, 1, 0x07fffffff, 0x100000000, 0x080000001, -0x07fffffff, 0x100000001, -0x080000000, -(2**53+2), 1/0, -0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 42, 0x080000000, 0/0, -0x100000001]); ");
/*fuzzSeed-42369751*/count=252; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.0078125;\n    var d3 = -18446744073709552000.0;\n    i1 = (/*FFI*/ff(((+(1.0/0.0))), ((+(0.0/0.0))), ((d0)), ((new RegExp(\"\\\\1\", \"im\") >> x)), (((((536870913.0) == (-262143.0))+((0x7fffffff) > (0x359e00eb))+(0xffffffff)) << (((uneval(x)) + (4277))))), ((abs((((i1)) | ((0x352fe7fd)*0xb2a0b)))|0)), ((imul((-0x8000000), (0xfe7cf5c6))|0)))|0);\n    d2 = (+(0.0/0.0));\n    i1 = (0xf71364e2);\n    d2 = (NaN);\n    d0 = (d2);\n    d0 = (d0);\n    return +((((((d3)) / (( /x/ ( '' , this))))) * ((+/*FFI*/ff(((d3)))))));\n  }\n  return f; })(this, {ff: function (b = ({a2:z2}).eval(\"/* no regression tests found */\"))((new Function(\"for (var p in a0) { m1.get(g0.h0); }\"))(new (131072)([,,])))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, 1/0, 2**53, 1, -1/0, 0x0ffffffff, 0/0, 0x100000000, -0x080000000, 1.7976931348623157e308, 0, -(2**53-2), 0.000000000000001, -0, -Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, -0x080000001, -0x100000001, 2**53+2, -0x0ffffffff, 42]); ");
/*fuzzSeed-42369751*/count=253; tryItOut("\"use strict\"; b2 + this.i1;");
/*fuzzSeed-42369751*/count=254; tryItOut("(let (c = eval < b) c <= w);");
/*fuzzSeed-42369751*/count=255; tryItOut("testMathyFunction(mathy4, [2**53-2, 2**53, -0x0ffffffff, -(2**53+2), 0x080000001, -Number.MAX_VALUE, 1, 2**53+2, 42, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, 0x100000001, -1/0, -0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, -Number.MIN_VALUE, 0x100000000, 0.000000000000001, -(2**53), 0, -0x100000000, Number.MAX_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=256; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ! (( + ( + ( + Math.min(( + y), ( + (((( + ( - Math.fround(x))) >>> 0) ** (( ! 0/0) >>> 0)) >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, 0x080000001, -(2**53+2), -0x0ffffffff, Math.PI, 0, 2**53, 0x100000001, 2**53-2, -0x100000001, -0, -0x080000000, 0x0ffffffff, 1/0, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000000, 1, 1.7976931348623157e308, 0.000000000000001, 0x080000000, 0x07fffffff, -(2**53-2), 42, -(2**53), -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-42369751*/count=257; tryItOut("\"use strict\"; e1.delete(o0);");
/*fuzzSeed-42369751*/count=258; tryItOut("a1[15] = h0;");
/*fuzzSeed-42369751*/count=259; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"e0 = new Set;\");");
/*fuzzSeed-42369751*/count=260; tryItOut("var lvkxwm = new ArrayBuffer(12); var lvkxwm_0 = new Uint8ClampedArray(lvkxwm); lvkxwm_0[0] = -17; var lvkxwm_1 = new Int32Array(lvkxwm); lvkxwm_1[0] = -13; ( /x/g );t2[o2.v0] = t2;");
/*fuzzSeed-42369751*/count=261; tryItOut("\"use strict\"; /*MXX2*/g0.RegExp.$7 = h1;m0.get(b1);");
/*fuzzSeed-42369751*/count=262; tryItOut("\"use strict\"; x, x = new (\"\\uF79A\")(), pdltnf, c, ykrskf, NaN = /*UUV1*/(x.setFloat64 = (1 for (x in []))), ieioel, ekudus;Array.prototype.reverse.call(a1, b1, m0, g1.o2, s0, g2, g1.o2.o1.o0.i1, b0);");
/*fuzzSeed-42369751*/count=263; tryItOut("\"use strict\"; g0.s2 = Array.prototype.join.call(a1, s0);");
/*fuzzSeed-42369751*/count=264; tryItOut("s0.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    (Float64ArrayView[((0x4dc1b250) % (((0xbe5312ce) / (0xcaeff0bd))>>>((0xfee41ba3)))) >> 3]) = ((Float32ArrayView[((0xfb9b9109)) >> 2]));\n    return ((length))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096));");
/*fuzzSeed-42369751*/count=265; tryItOut("\"use asm\"; /*ODP-1*/Object.defineProperty(f2, new String(\"12\"), ({get: \n(void options('strict')), configurable: false, enumerable: (x % 5 == 2)}));");
/*fuzzSeed-42369751*/count=266; tryItOut("mathy0 = (function(x, y) { return Math.pow(Math.fround(Math.imul((Math.fround(Math.atan2((Math.pow((x | 0), ((( ! 0) >>> 0) | 0)) | 0), Math.fround(Math.imul((( ! y) >>> 0), Math.fround(Math.fround((Math.fround((Math.log10((( + x) ? x : ( + x))) >>> 0)) | Math.fround(x)))))))) | 0), Math.fround(Math.pow((Math.clz32((x >>> 0)) >>> 0), ( + (( + ( ~ x)) !== ( + -Number.MIN_SAFE_INTEGER))))))), ( + Math.fround(( + ( - ( + Math.clz32(Math.acos((Math.max(( + y), x) | 0))))))))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), 0x0ffffffff, 2**53+2, 0.000000000000001, -(2**53-2), Number.MAX_VALUE, 2**53, -1/0, -(2**53+2), 0x080000000, -0x07fffffff, -0, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 42, -Number.MIN_VALUE, 1/0, -0x100000000, 0/0, 0, -0x080000000, Math.PI, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53-2, -0x100000001]); ");
/*fuzzSeed-42369751*/count=267; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.atan2((Math.trunc((Math.atan2(( + (x ? (( ~ ( + x)) >>> 0) : Math.tanh(-0x080000000))), ( + Math.atan2(( + x), ( + (( ! (x | 0)) | 0))))) >>> 0)) >>> 0), Math.pow((( + (x % mathy0((y >>> 0), y))) <= x), Math.log(((x ? ( + y) : Math.fround(Math.tanh(Math.max((Math.pow(y, x) | 0), (y | 0))))) | 0)))); }); ");
/*fuzzSeed-42369751*/count=268; tryItOut("m0.get(h2);");
/*fuzzSeed-42369751*/count=269; tryItOut("mathy3 = (function(x, y) { return mathy2((Math.sin(( + Math.pow(Math.fround(((Math.max(( + Math.expm1(( + (0x080000001 ? Math.fround(x) : y)))), (mathy0((x | 0), (x | 0)) | 0)) >>> 0) ? (0/0 >>> 0) : y)), -(2**53+2)))) | 0), (( + mathy2((((y ** ( + x)) % ((y | ((mathy2((y >>> 0), (x >>> 0)) | 0) * (-0x080000001 | 0))) | 0)) | 0), Math.atan2(y, ( + (Math.trunc((Math.fround(Math.tanh(y)) >>> 0)) >>> 0))))) >>> 0)); }); ");
/*fuzzSeed-42369751*/count=270; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.max((Math.atan2(Math.fround(Math.log2(Math.fround(Math.atan(Math.fround(y))))), Math.fround(Math.max(Math.fround(y), Math.fround(Number.MIN_SAFE_INTEGER)))) | 0), (Math.fround(Math.trunc((( + Math.log2(Math.fround((Math.fround(y) !== Math.fround(x))))) >= ( ~ ((Math.pow((x | 0), 0.000000000000001) >>> 0) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), new Number(1), new Number(1), 0x3FFFFFFE, null, objectEmulatingUndefined(), 0x3FFFFFFE, null, null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), null, null, new Number(1), 0x3FFFFFFE, objectEmulatingUndefined(), 0x3FFFFFFE, 0x3FFFFFFE, objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x3FFFFFFE, 0x3FFFFFFE, null, 0x3FFFFFFE, new Number(1), new Number(1), null, 0x3FFFFFFE, new Number(1), null, objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), 0x3FFFFFFE, objectEmulatingUndefined()]); ");
/*fuzzSeed-42369751*/count=271; tryItOut("L: {/*ODP-1*/Object.defineProperty(g0.v1, \"valueOf\", ({set: decodeURI, enumerable: false}));print(x); }");
/*fuzzSeed-42369751*/count=272; tryItOut("\"use strict\"; \"use asm\"; var cyihbt = new ArrayBuffer(4); var cyihbt_0 = new Uint8Array(cyihbt); var cyihbt_1 = new Float64Array(cyihbt); print(cyihbt_1[0]); cyihbt_1[0] = -8; v2 = this.g0.runOffThreadScript();");
/*fuzzSeed-42369751*/count=273; tryItOut("g0.v1 = (a0 instanceof b0);");
/*fuzzSeed-42369751*/count=274; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((0xf00ce*(((((0xa227b08f))+((4277))) >> ((i1))) < (imul(((-6.189700196426902e+26) <= (((Infinity)) - ((+atan2(((-1152921504606847000.0)), ((-4294967296.0))))))), ((-0x6a55dc0)))|0))))|0;\n  }\n  return f; })(this, {ff: Math.cos(-27)}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [42, 2**53+2, 1/0, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, -0x100000001, -0x0ffffffff, 0x100000001, -(2**53-2), -(2**53+2), -0, -0x07fffffff, 1.7976931348623157e308, Math.PI, -1/0, -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 2**53, 0x0ffffffff, 0x100000000, 0x080000001, -Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 0/0, Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-42369751*/count=275; tryItOut("/*vLoop*/for (var mdulan = 0; mdulan < 82; ++mdulan) { const y = mdulan; a0 = r2.exec(g0.s1); } ");
/*fuzzSeed-42369751*/count=276; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.sign(Math.hypot(y, x)) >>> (Math.atan2(( + x), ((mathy2((x >>> 0), (Math.max(( + y), y) >>> 0)) >>> 0) >>> 0)) | 0))); }); testMathyFunction(mathy4, [0x100000000, 0/0, -0, 42, -0x0ffffffff, 1, 2**53, -0x080000001, 0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, Number.MIN_VALUE, -(2**53+2), -(2**53), 0x07fffffff, 0.000000000000001, 1/0, -0x100000000, 1.7976931348623157e308, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, -0x100000001, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=277; tryItOut("i2.send(i2);");
/*fuzzSeed-42369751*/count=278; tryItOut("Array.prototype.reverse.call(a0);");
/*fuzzSeed-42369751*/count=279; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.cos(Math.fround((Math.imul(( + Math.trunc(y)), (x >>> 0)) >>> 0)))) << Math.fround(Math.sin(Math.fround(( - x))))); }); testMathyFunction(mathy0, [2**53+2, -0x080000000, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -0x100000001, -(2**53), -(2**53+2), -0x0ffffffff, 0x080000000, Number.MAX_VALUE, 0x080000001, 0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 1/0, 1, Number.MIN_VALUE, -0x07fffffff, -0x080000001, 0/0, 2**53-2, 42, 0, -Number.MIN_VALUE, -0, -1/0]); ");
/*fuzzSeed-42369751*/count=280; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=281; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ ( + Math.log2((( + ( - ( + (((( + Math.min(( + x), ( + x))) | 0) != ( + y)) | 0)))) >>> 0)))); }); testMathyFunction(mathy4, [1/0, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, 2**53, -0x100000001, 0x080000000, -0x07fffffff, -1/0, -(2**53-2), Math.PI, -(2**53+2), 0.000000000000001, -(2**53), -0, -0x080000000, 0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, 42, 0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-42369751*/count=282; tryItOut("if(b) o1.o0.v1 = r1.toString; else  if ((\"\\u60BF\" < 7)) selectforgc(o1); else {; }");
/*fuzzSeed-42369751*/count=283; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((Math.pow(Math.fround(Math.cbrt((Math.acosh(y) | 0))), Math.fround((Math.pow((Math.fround((Math.fround(2**53+2) , Math.fround((y / (x | 0))))) | 0), (Math.fround(Math.atan2(Math.fround(Math.imul(y, y)), Math.fround(x))) >>> 0)) >>> 0))) ^ (Math.atan2(((mathy1((0x100000001 | 0), ( + Math.round(Math.exp(Math.fround(y))))) | 0) >>> 0), ( + Math.sin(x))) >>> 0)) | 0) ? ( + ( - ( + Math.max(( + ( + mathy1(( + (Math.fround(Math.tan(Math.fround(Math.imul(y, x)))) | y)), 0/0))), ( + x))))) : Math.asin((Math.fround((( ! y) >= Math.hypot((( - (x >>> 0)) >>> 0), Number.MAX_SAFE_INTEGER))) | (x ^ y)))); }); testMathyFunction(mathy2, /*MARR*/[ '' , objectEmulatingUndefined(), true,  '' ,  '' ,  '' ,  '' , objectEmulatingUndefined(),  '' ,  '' , true, objectEmulatingUndefined(),  '' , true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(),  '' ,  '' , objectEmulatingUndefined(),  '' , objectEmulatingUndefined(),  '' , objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , objectEmulatingUndefined(),  '' ,  '' , true,  '' , true,  '' , objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , objectEmulatingUndefined(), objectEmulatingUndefined(),  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , true,  '' , objectEmulatingUndefined(), true, true, true, objectEmulatingUndefined(), objectEmulatingUndefined(),  '' ,  '' , true, true, true, objectEmulatingUndefined(), true, objectEmulatingUndefined(), true,  '' ,  '' , true, true, objectEmulatingUndefined(), true, true, true,  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), true,  '' , objectEmulatingUndefined(),  '' ,  '' ,  '' , objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , objectEmulatingUndefined(),  '' ,  '' , true,  '' , true, objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , true,  '' , objectEmulatingUndefined(),  '' ,  '' , true, true, objectEmulatingUndefined(),  '' ,  '' , objectEmulatingUndefined(), true, objectEmulatingUndefined(), true,  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, true,  '' , true,  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true,  '' ,  '' , objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true]); ");
/*fuzzSeed-42369751*/count=284; tryItOut("/*RXUB*/var r = /(?:(?!\\cM)\\b{1}+)|(?:(?=[\u8002-\\u8A65\\x7F\\D])|\\2)/gyim; var s = \"a\\n\\u000da\\na\\na\\na\\na\\n\"; print(r.exec(s)); ");
/*fuzzSeed-42369751*/count=285; tryItOut("\"use strict\"; Object.defineProperty(g1, \"v0\", { configurable: false, enumerable: ({a2:z2}),  get: function() {  return Infinity; } });c = x =  \"\" ;");
/*fuzzSeed-42369751*/count=286; tryItOut("\"use strict\"; v2 = o2.g2.runOffThreadScript();");
/*fuzzSeed-42369751*/count=287; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!.)\", \"i\"); var s = \"\\u0489\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-42369751*/count=288; tryItOut("v1.valueOf = (function() { try { this.s2 += s1; } catch(e0) { } try { a2.push((Math.imul(/*MARR*/[(c) = \u3056, (c) = \u3056, (c) = \u3056, (c) = \u3056, x, new String(''), (c) = \u3056, (c) = \u3056, new String(''), (c) = \u3056, new String(''), 3/0, 3/0, x, x, new String(''), (c) = \u3056, 3/0, 3/0, 3/0, new String(''), (c) = \u3056], -18)), i2); } catch(e1) { } o0.e1.has(false); return i1; });");
/*fuzzSeed-42369751*/count=289; tryItOut("testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, 0x080000000, 2**53-2, Number.MIN_VALUE, 0x07fffffff, 42, 2**53+2, -(2**53), 2**53, 0, -Number.MIN_VALUE, Number.MAX_VALUE, 1, -1/0, -0x100000001, 1/0, -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, -0x07fffffff, 0x100000001, 0.000000000000001, 0x080000001, -0x0ffffffff, 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=290; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.imul(( + ( ~ mathy2((Math.fround((( - ( + x)) | 0)) > Math.fround((Math.hypot((Math.min(x, (((y | 0) >= x) | 0)) | 0), (y | 0)) | 0))), ( + Math.fround(mathy3(Math.fround((Math.asinh((Math.max((Math.max((y | 0), (x | 0)) | 0), Math.atan(x)) >>> 0)) >>> 0)), Math.fround(( + (x >> 0x07fffffff))))))))), Math.atan(( + Math.max(( + (((Math.fround(Math.atan2(y, Math.fround(y))) == ( + ( ~ x))) >>> 0) - (x >>> 0))), ( + 0/0))))); }); ");
/*fuzzSeed-42369751*/count=291; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=292; tryItOut("v2 = Object.prototype.isPrototypeOf.call(this.a0, i2);");
/*fuzzSeed-42369751*/count=293; tryItOut("\"use strict\"; delete v2[\"apply\"];");
/*fuzzSeed-42369751*/count=294; tryItOut("t0[v0] = f2;");
/*fuzzSeed-42369751*/count=295; tryItOut("i0 = e1.values;");
/*fuzzSeed-42369751*/count=296; tryItOut("\"use strict\";  for (let w of (p={}, (p.z = [\"\\uE2FF\"])())) ((new Proxy((c+=\"\\u5431\" >>= (4277))))\u000d);");
/*fuzzSeed-42369751*/count=297; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround(( + ((( ! (( + Math.pow(x, 0.000000000000001)) | 0)) | 0) >>> 0))) ^ Math.fround((Math.fround((Math.fround(Math.fround((Math.fround(Math.asinh(( + x))) >= x))) ** Math.fround((( + 0x100000001) << ((( ~ (y | 0)) | 0) , x))))) ? Math.fround(( - -Number.MAX_VALUE)) : ( + ( ~ ( + Math.hypot(( + y), ( + Math.imul((0/0 | 0), (Math.min(y, Math.fround(Math.acosh(y))) | 0))))))))))); }); testMathyFunction(mathy0, [0/0, -0, 0, -0x080000001, 1.7976931348623157e308, -(2**53+2), -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, 0x0ffffffff, Number.MAX_VALUE, 0x100000001, 2**53, 0x07fffffff, 0.000000000000001, -0x07fffffff, -Number.MIN_VALUE, 1, 1/0, 2**53+2, -0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -0x100000000, -1/0, -(2**53)]); ");
/*fuzzSeed-42369751*/count=298; tryItOut("f0(o0.b2);");
/*fuzzSeed-42369751*/count=299; tryItOut("mathy0 = (function(x, y) { return (( ~ ( ~ (((Number.MIN_SAFE_INTEGER >> ( ~ Math.fround((Math.fround(x) && Math.fround(((x >>> 0) && (y >>> 0))))))) || Math.fround(( + Math.fround(x)))) >>> 0))) >>> 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, 0.000000000000001, 1, 42, -Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, 0x080000000, 0x0ffffffff, -0x0ffffffff, 2**53+2, -0x100000000, -0, 0/0, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, -1/0, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, 0, Math.PI, 2**53]); ");
/*fuzzSeed-42369751*/count=300; tryItOut("f0(a1);");
/*fuzzSeed-42369751*/count=301; tryItOut("\"use strict\"; a0.push(x, m1, function(y) { this.a2.sort(q => q); }(new (Math.atanh)(\n /x/g )));");
/*fuzzSeed-42369751*/count=302; tryItOut("/*oLoop*/for (var fesioe = 0; fesioe < 104;  /x/ , ++fesioe) { /*ADP-2*/Object.defineProperty(a1, 15, { configurable: (x % 2 == 1), enumerable: (x % 3 == 0), get: f2, set: (function() { for (var j=0;j<51;++j) { f1(j%3==1); } }) }); } ");
/*fuzzSeed-42369751*/count=303; tryItOut("s0 = Array.prototype.join.apply(a0, [s2, v0, g2.t0, s1, m1, (/*UUV1*/(b.acos = decodeURIComponent))]);");
/*fuzzSeed-42369751*/count=304; tryItOut("testMathyFunction(mathy0, [(new Number(0)), 1, true, '0', (new String('')), ({valueOf:function(){return 0;}}), null, ({valueOf:function(){return '0';}}), '/0/', /0/, (new Number(-0)), objectEmulatingUndefined(), '', (function(){return 0;}), (new Boolean(false)), false, 0.1, [], -0, NaN, [0], 0, undefined, '\\0', ({toString:function(){return '0';}}), (new Boolean(true))]); ");
/*fuzzSeed-42369751*/count=305; tryItOut("function shapeyConstructor(yickrr){delete this[\"eval\"];Object.preventExtensions(this);this[\"__count__\"] = 21;for (var ytqouifdt in this) { }Object.defineProperty(this, new String(\"14\"), ({}));this[\"__count__\"] = x;this[\"__count__\"] = Function;this[\"__count__\"] = objectEmulatingUndefined();this[\"__count__\"] = {};Object.defineProperty(this, \"eval\", ({configurable: (x % 3 == 0)}));return this; }/*tLoopC*/for (let c of /*PTHR*/(function() { for (var i of []) { yield i; } })()) { try{let dsfyrd = shapeyConstructor(c); print('EETT'); o0.v0 = Object.prototype.isPrototypeOf.call(p0, a0);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-42369751*/count=306; tryItOut("print(f1);");
/*fuzzSeed-42369751*/count=307; tryItOut("testMathyFunction(mathy4, [Number.MAX_VALUE, Math.PI, -0x07fffffff, -(2**53-2), Number.MIN_VALUE, -0x080000000, 0x07fffffff, -0x0ffffffff, 2**53, 2**53-2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, -(2**53), -0x100000000, -0x100000001, -0, 0x100000000, -(2**53+2), 2**53+2, Number.MAX_SAFE_INTEGER, 0/0, 0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 1, 42, -1/0, 1/0, 0x100000001]); ");
/*fuzzSeed-42369751*/count=308; tryItOut("e1.has(i1);");
/*fuzzSeed-42369751*/count=309; tryItOut("/*vLoop*/for (let meqthm = 0; meqthm < 98; ++meqthm) { x = meqthm; /*tLoop*/for (let b of /*MARR*/[-Infinity, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, -Infinity, -Infinity, (-0), (-0), (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, -Infinity, (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), (-0), /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, (-0), -Infinity, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y, -Infinity, /(?=\\w\\b\\x30{4,6}+|\\S\\b\\b+?|\\u0078+*)/y]) { g1.o0 = o1.__proto__; } } ");
/*fuzzSeed-42369751*/count=310; tryItOut("s2 += s2;/*tLoop*/for (let c of /*MARR*/['fafafa'.replace(/a/g,  /x/ ), 'fafafa'.replace(/a/g,  /x/ ), 'fafafa'.replace(/a/g,  /x/ ), -0x080000001, true, undefined, 'fafafa'.replace(/a/g,  /x/ ), true, undefined, -0x080000001, undefined, -0x080000001, 'fafafa'.replace(/a/g,  /x/ ), -0x080000001, 'fafafa'.replace(/a/g,  /x/ ), 'fafafa'.replace(/a/g,  /x/ ), 'fafafa'.replace(/a/g,  /x/ ), undefined, -0x080000001, 'fafafa'.replace(/a/g,  /x/ ), true, undefined, -0x080000001, 'fafafa'.replace(/a/g,  /x/ ), 'fafafa'.replace(/a/g,  /x/ ), true, true, true, undefined, -0x080000001, undefined, 'fafafa'.replace(/a/g,  /x/ ), -0x080000001, -0x080000001, 'fafafa'.replace(/a/g,  /x/ ), undefined, 'fafafa'.replace(/a/g,  /x/ ), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, true, undefined, -0x080000001, undefined, undefined, 'fafafa'.replace(/a/g,  /x/ ), true, 'fafafa'.replace(/a/g,  /x/ ), -0x080000001, -0x080000001, undefined, undefined, 'fafafa'.replace(/a/g,  /x/ ), 'fafafa'.replace(/a/g,  /x/ ), undefined, 'fafafa'.replace(/a/g,  /x/ ), true, undefined, undefined, 'fafafa'.replace(/a/g,  /x/ ), 'fafafa'.replace(/a/g,  /x/ ), undefined, -0x080000001, undefined, true, -0x080000001, -0x080000001, true, true, undefined]) { ((eval(\"/* no regression tests found */\") != (let (c, x, jpnzsb, qwothz, x, eval, oszrhg) this))); }o2 = new Object;");
/*fuzzSeed-42369751*/count=311; tryItOut("v1 = Object.prototype.isPrototypeOf.call(e2, v1);");
/*fuzzSeed-42369751*/count=312; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=313; tryItOut("/*RXUB*/var r = /(?!\\2)/gim; var s =  '' ; print(s.split(r)); ");
/*fuzzSeed-42369751*/count=314; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=315; tryItOut("M:while(((\"\\u2525\".eval(\"{}\")).tanh().atanh()) && 0){selectforgc(o0);(window);this.o1.valueOf = (function mcc_() { var oellwa = 0; return function() { ++oellwa; f2(false);};})(); }");
/*fuzzSeed-42369751*/count=316; tryItOut("mathy1 = (function(x, y) { return ( - Math.sqrt(( + Math.fround(Math.atan2(Math.fround(( + ((Math.imul(( - x), 0x100000000) >>> 0) << ( + x)))), Math.fround(( - Math.atan2(0x0ffffffff, Math.hypot(( + (x >>> 0)), x))))))))); }); testMathyFunction(mathy1, [-0x0ffffffff, 1/0, -0x100000001, 0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53, 1, 42, -(2**53-2), 0, 0.000000000000001, -(2**53+2), 0x0ffffffff, -Number.MAX_VALUE, -0, -0x080000000, 0x080000001, -0x080000001, -1/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, Number.MAX_VALUE, 0x07fffffff, -(2**53), 0x100000000, Math.PI, -0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=317; tryItOut("/*bLoop*/for (let gpocem = 0; gpocem < 9; ++gpocem) { if (gpocem % 11 == 4) { var vibpsl = new SharedArrayBuffer(0); var vibpsl_0 = new Uint8Array(vibpsl); v0 = evalcx(\"({a2:z2})\", g1); } else { Array.prototype.push.call(a2, o0.s2); }  } ");
/*fuzzSeed-42369751*/count=318; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.min(Math.min((((((((x != Math.PI) >>> 0) | 0) ** (mathy0(( ! x), Math.log10(( + y))) | 0)) | 0) >= mathy0(( + x), ( + y))) | 0), Math.imul(Math.imul(Math.trunc((Math.fround(Math.asin(( + y))) / -Number.MAX_SAFE_INTEGER)), (x - y)), ( - Math.pow(x, ( + Math.min(( + x), ( + y))))))), ( + Math.exp(( + mathy0(Math.fround(( + Math.log10(Math.pow(x, Math.max((-0x0ffffffff >>> 0), y))))), (( + x) && Math.hypot(x, ( ! x)))))))); }); testMathyFunction(mathy1, [-0x080000000, Number.MAX_VALUE, -0x100000001, -0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, 1, Math.PI, -(2**53), -Number.MAX_VALUE, 0x080000000, 0x0ffffffff, 2**53, 0.000000000000001, 0/0, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, -0x100000000, 1/0, -(2**53+2), 2**53-2, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, 42, 0x080000001, 0x100000000, 0, -0x07fffffff]); ");
/*fuzzSeed-42369751*/count=319; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(( + Math.log((Math.fround(Math.imul(Math.fround(Math.atanh(x)), Math.fround(( + ( + ( + Math.max(Math.hypot(x, 2**53+2), 0x100000000))))))) | 0))), (( ! mathy3(Math.fround(Math.exp(y)), Math.fround(x))) >>> 0)); }); testMathyFunction(mathy4, [-(2**53), 2**53-2, 2**53, 0x07fffffff, 0x100000000, 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -0x080000000, 0, 0.000000000000001, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, 42, -(2**53-2), 0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, -(2**53+2), 1, Math.PI, -0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-42369751*/count=320; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (( + (Math.fround((Math.fround((Math.fround(( + Math.max(( + (x && x)), ( + y)))) < Math.fround(Math.cosh(x)))) / Math.cosh(y))) ? mathy3(Math.fround(Math.cosh(y)), Math.fround(Math.sign(y))) : (( ! (Math.hypot((( + Math.atan2(( + x), ( + Math.atan2(( + Math.PI), ( + y))))) >>> 0), (( + Math.max(( + y), (Math.max((x >>> 0), (x >>> 0)) >>> 0))) >>> 0)) >>> 0)) | 0))) == ( + mathy4(( + Math.hypot(( + (Math.hypot(Math.imul((-Number.MIN_VALUE | 0), x), x) ? x : (Math.atan2(y, (((x == (( + Math.cos(1)) | 0)) | 0) >>> 0)) >>> 0))), (((x && x) ^ Math.atan2(y, x)) >>> 0))), Math.fround((( + (( + (((((y ^ Math.max(y, y)) >>> 0) | 0) && (x & y)) >>> 0)) >= ( + Math.imul(( + y), (x >>> 0))))) << ((Math.atan2((-Number.MIN_VALUE >= 2**53), (((( - x) >>> 0) | 0) ? -(2**53+2) : (2**53 | 0))) >>> 0) ? (mathy4((x >> x), (y | 0)) >>> 0) : Math.fround((Math.fround(( - y)) == Math.fround(y)))))))))); }); testMathyFunction(mathy5, [2**53-2, 2**53+2, 0.000000000000001, -(2**53), 1.7976931348623157e308, 0x07fffffff, -1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, 0, 1, -0x100000001, 1/0, -(2**53-2), -0x080000001, -Number.MIN_VALUE, 0/0, 2**53, Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -Number.MAX_VALUE, -0, -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, Number.MIN_VALUE, 0x080000001, Number.MAX_VALUE, -(2**53+2), -0x080000000, 42]); ");
/*fuzzSeed-42369751*/count=321; tryItOut("this.i1.send(i0)");
/*fuzzSeed-42369751*/count=322; tryItOut("/*tLoop*/for (let w of /*MARR*/[]) { this.v2 = Array.prototype.every.apply(g1.a0, [(function() { for (var j=0;j<4;++j) { f1(j%5==1); } })]); }");
/*fuzzSeed-42369751*/count=323; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( ! ( ! ( + ( + Math.fround(( ~ Math.fround(0x100000000))))))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[({}), (-1/0), ({})]); ");
/*fuzzSeed-42369751*/count=324; tryItOut("Array.prototype.forEach.apply(a0, [(function() { try { i0.send(this.h0); } catch(e0) { } try { v2 = a2.length; } catch(e1) { } g2.i2 = m1.keys; return g0; })]);");
/*fuzzSeed-42369751*/count=325; tryItOut("v1 = Object.prototype.isPrototypeOf.call(s0, g2);");
/*fuzzSeed-42369751*/count=326; tryItOut("Array.prototype.sort.apply(a0, [(function(j) { if (j) { Array.prototype.push.call(a2, t0, x, e1); } else { try { for (var v of m2) { try { this.s0 += s2; } catch(e0) { } v0 = (e1 instanceof p1); } } catch(e0) { } a2.splice(NaN, 15, m0, o2.o2); } }), o2, e2, i2, p2]);");
/*fuzzSeed-42369751*/count=327; tryItOut("testMathyFunction(mathy5, [0x0ffffffff, 1.7976931348623157e308, -0x100000000, 0x100000001, -(2**53+2), 0x080000001, Number.MAX_VALUE, 1, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, -0, 2**53-2, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, 2**53, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 42, -0x080000001, 1/0, 2**53+2, 0x080000000, -(2**53), Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, 0, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=328; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log2(( + (((y * ( + Math.ceil(mathy0(y, ( ! (((y >>> 0) || (y >>> 0)) >>> 0)))))) | 0) && ( + (Math.atanh((Math.pow(Math.fround(((x >>> 0) ? (y >>> 0) : (y >>> 0))), ((y & x) - -0x0ffffffff)) | 0)) | 0))))); }); testMathyFunction(mathy2, [-0, 0x080000001, 0, -0x080000001, -(2**53), 0x07fffffff, 0/0, -0x07fffffff, 42, Math.PI, 0x0ffffffff, Number.MIN_VALUE, -(2**53+2), 2**53-2, 0x100000001, -Number.MAX_VALUE, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0x100000000, Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-42369751*/count=329; tryItOut("mathy4 = (function(x, y) { return (Math.max(( + Math.imul(x, ( ~ ( + ( + (((Math.sign(x) | 0) >> Math.fround((Math.log(Math.fround(x)) | 0))) | 0)))))), (( ! (Math.imul(Math.ceil(((Math.max((mathy3(y, y) | 0), (x | 0)) | 0) >>> 0)), y) >>> 0)) >>> 0)) <= (mathy2(( + ( + ( + ( - ( + Math.max((0x100000001 | 0), Math.fround(( + Math.clz32(( + y)))))))))), (mathy1(1.7976931348623157e308, (( + (( + x) << ( + 0x0ffffffff))) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), '\\0', true, '', (new Number(-0)), '/0/', 0.1, 1, undefined, false, (function(){return 0;}), '0', ({toString:function(){return '0';}}), (new Number(0)), (new Boolean(false)), [], /0/, (new Boolean(true)), NaN, -0, null, [0], objectEmulatingUndefined(), (new String('')), ({valueOf:function(){return '0';}}), 0]); ");
/*fuzzSeed-42369751*/count=330; tryItOut("/*RXUB*/var r = new RegExp(\"((?=((?:[^]){1024,}.|[\\\\s\\u452e]+?)))\\\\1|(?!(?:(?=k+?)|\\\\b[^][\\ud3df]+?))((?=^\\\\d?){1,4097})*?{3,4}\", \"yim\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-42369751*/count=331; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 3.0;\n    i0 = (!((0xd9f13779)));\n    i0 = (0xfb16110e);\n    i2 = (0xff54c573);\n    return (((0xfa487e73)-((0x33f13f25) <= (abs((((0xfafe9757)) | ((/*FFI*/ff(((+log(((d1))))), (((b|=x))), ((-134217727.0)))|0)-(-0x42c922c))))|0))))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000000, 0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, 0/0, 0x080000001, -Number.MAX_VALUE, -(2**53-2), 2**53+2, -Number.MIN_VALUE, 0.000000000000001, -0x100000000, Math.PI, -1/0, 1, 1.7976931348623157e308, 42, 0x100000001, 1/0, -0x07fffffff, Number.MIN_VALUE, 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, 0, 2**53, -(2**53), -0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=332; tryItOut("s1 = new String(this.m2);");
/*fuzzSeed-42369751*/count=333; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a2, (neuter)(), { configurable: false, enumerable: (x *= arguments.callee.caller.caller), get: (function() { try { t1[15] = x; } catch(e0) { } try { o1.h2.hasOwn = f0; } catch(e1) { } try { this.a0 = (function() { yield /*RXUE*/new RegExp(\"[^]{15}\", \"gm\").exec(Math.asinh(0x080000001)); } })(); } catch(e2) { } Array.prototype.sort.call(a1, (function() { for (var p in o1.a2) { v2 = evaluate(\"Array.prototype.push.apply(o2.a2, [f0, m2, this.m1]);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 17 == 0), sourceIsLazy: x, catchTermination: (Math.hypot(19, -8)) /= false <<= new RegExp(\"(?:(?=(?=([^])){4})\\\\b)\\\\d?\\\\1[^]{3,}*|\\\\1+?\", \"m\") })); } return i2; }), o2.h1); return a1; }), set: f2 });");
/*fuzzSeed-42369751*/count=334; tryItOut("o2.g2.i1.next();");
/*fuzzSeed-42369751*/count=335; tryItOut("mathy1 = (function(x, y) { return Math.log2(Math.fround((( + ( + ( ~ (( ! mathy0(y, -0x080000001)) >>> 0)))) != (Math.imul((Math.fround(Math.imul((Math.fround((Math.fround(x) / Math.fround(Number.MAX_SAFE_INTEGER))) | 0), ((x + 42) | 0))) | 0), (( + (x <= Number.MIN_VALUE)) | 0)) | 0)))); }); testMathyFunction(mathy1, [0x080000001, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, 0, 1.7976931348623157e308, 2**53+2, -1/0, Number.MIN_VALUE, 0/0, -(2**53), 1/0, 42, 0x100000001, -0x0ffffffff, -(2**53+2), -0x100000001, -0x080000001, -0x100000000, 1, 0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, -(2**53-2), 2**53, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=336; tryItOut("false;");
/*fuzzSeed-42369751*/count=337; tryItOut("t0 = t1.subarray(11, 10);");
/*fuzzSeed-42369751*/count=338; tryItOut("\"use strict\"; e2.has(this.h1);");
/*fuzzSeed-42369751*/count=339; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0/0, 2**53-2, -(2**53-2), -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 42, 1, 1.7976931348623157e308, Number.MAX_VALUE, -0x07fffffff, 2**53+2, 0, -0x080000001, -(2**53), Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 2**53, 0x100000000, -(2**53+2), 0x0ffffffff, -1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0, 1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff]); ");
/*fuzzSeed-42369751*/count=340; tryItOut("\"use strict\"; v1 = (p1 instanceof o2);");
/*fuzzSeed-42369751*/count=341; tryItOut("let x = 1e+81;print( /x/ );");
/*fuzzSeed-42369751*/count=342; tryItOut("var eirxii = new ArrayBuffer(6); var eirxii_0 = new Uint8Array(eirxii); var eirxii_1 = new Int8Array(eirxii); eirxii_1[0] = 12; print(((Math.expm1(-3)) ? eirxii_1 : (y.valueOf(\"number\"))));;");
/*fuzzSeed-42369751*/count=343; tryItOut("e1.has(this.i1);");
/*fuzzSeed-42369751*/count=344; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=345; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ceil = stdlib.Math.ceil;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      (Float32ArrayView[1]) = ((d0));\n    }\n    return +((+(((0xb902c0cf) % (0xab7465c7)) | ((!(0xcf2b358b))))));\n    d1 = ((d0) + ((-4194304.0) + (+abs(((+(-1.0/0.0)))))));\n    d0 = (window);\n    i2 = (0xffa0ad10);\n    i2 = (((-0x8991c*(/*MARR*/[x, x, x, x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1.5), new String('q'), new String('q'), new String('q'), new String('q'), x, x, new String('q'), new String('q'), x, new Number(1.5), new Number(1.5), new String('q'), new String('q'), new String('q'), x, x, x, new Number(1.5), x, new Number(1.5), x, new String('q'), x, new Number(1.5), new Number(1.5), new String('q'), new Number(1.5), new String('q'), new Number(1.5), x, x, x, x, x, x, x, new String('q'), new String('q'), x, new Number(1.5), new Number(1.5), x, x, x, new Number(1.5), x, new Number(1.5), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1.5), x, new Number(1.5), x, new String('q'), new Number(1.5), new String('q')].filter(Date.prototype.setYear)))>>>((i2)+((((0x5d7bc989))>>>((0x88d11193))) <= (0xe6b2d691))+(/*FFI*/ff(((-4503599627370496.0)), ((~~(d1))), ((8796093022207.0)), ((-2305843009213694000.0)), ((-67108865.0)), ((17179869185.0)))|0))) > (((0x9422c8d6))>>>((0xffffffff)-(0xff6e835d))));\n    d1 = (((0x2cdbb27c) > (((0xfa51061d)-((0x5cd9a88b) < (0x1e7c1c81)))>>>(((((-0x8000000)) << ((0x81556dee))))))) ? ((+pow((((d0) + (+ceil(((2.3611832414348226e+21)))))), ((d1)))) + (((((0x82291018))>>>((0x80e80ebe)))) ? (-35184372088833.0) : (+((Infinity))))) : (+abs(((d1)))));\n    return +((+((((+((d1))) > (-6.044629098073146e+23))+(!(i2))) ^ (-0x1e0ac*((0xc3b46424) > (0x6519ccaa))))));\n    return +(((((0x89ffad90)))));\n  }\n  return f; })(this, {ff: /*UUV2*/(a.values = a.getUint16)}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Math.PI, 0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, -0x100000001, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, -(2**53), 1, -Number.MAX_VALUE, 0.000000000000001, -0x080000001, 1.7976931348623157e308, 0x080000001, 42, 0/0, -0x100000000, 2**53+2, -0x080000000, 1/0, 0x080000000, Number.MIN_SAFE_INTEGER, -0, -(2**53-2), 2**53, 2**53-2, -(2**53+2), -Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=346; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 42, -0x080000000, 1, 2**53+2, -0x0ffffffff, Number.MAX_VALUE, 1/0, -Number.MIN_VALUE, -(2**53), 2**53-2, -0, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, 1.7976931348623157e308, -(2**53+2), 0x100000001, Math.PI, -(2**53-2), -0x07fffffff, -0x100000001, -1/0, -0x080000001, Number.MIN_SAFE_INTEGER, 0, 0x100000000, 2**53, 0x07fffffff]); ");
/*fuzzSeed-42369751*/count=347; tryItOut("v0 = t2.length;");
/*fuzzSeed-42369751*/count=348; tryItOut("false;(x ? \"\\uB247\" : \"\\uF696\" %= ((x =  /x/ )));");
/*fuzzSeed-42369751*/count=349; tryItOut("\"use strict\"; v0 = a2.lengthprint(t0);");
/*fuzzSeed-42369751*/count=350; tryItOut("\"use strict\"; e1.add(g0);");
/*fuzzSeed-42369751*/count=351; tryItOut("\"use strict\"; a0.reverse(this.o1, o1, a1, g2.p1);");
/*fuzzSeed-42369751*/count=352; tryItOut("testMathyFunction(mathy4, [0.000000000000001, 0, 1.7976931348623157e308, Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, 0x080000001, -0x07fffffff, -(2**53+2), -0x100000000, Math.PI, -(2**53-2), 0x100000000, 1/0, 42, -(2**53), -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0, -0x100000001, -0x080000000, -Number.MAX_VALUE, 2**53+2, -0x0ffffffff, -0x080000001, 0/0]); ");
/*fuzzSeed-42369751*/count=353; tryItOut("yield;yield;");
/*fuzzSeed-42369751*/count=354; tryItOut("switch(((x)((Math.imul(-5, -12))))) { case yield: case (x && x): break; default: print(s2);break; break;  }");
/*fuzzSeed-42369751*/count=355; tryItOut("testMathyFunction(mathy0, [-0x080000000, 1.7976931348623157e308, -0x080000001, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, 1, 2**53, 0.000000000000001, 0x100000001, 0x100000000, 0x07fffffff, -1/0, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, -0x07fffffff, 42, Math.PI, 2**53-2, -0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -0, 0/0, -Number.MIN_VALUE, -0x100000001, -(2**53-2), 1/0, -(2**53)]); ");
/*fuzzSeed-42369751*/count=356; tryItOut("\"use strict\"; /*RXUB*/var r = g2.r1; var s = s2; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=357; tryItOut("mathy2 = (function(x, y) { return ( + Math.log1p(mathy0(((( ! x) | 0) < (x | 0)), ( + ( ! Math.imul(Math.fround((2**53-2 >>> Math.fround(Number.MAX_SAFE_INTEGER))), x)))))); }); testMathyFunction(mathy2, [-0x0ffffffff, 1.7976931348623157e308, -0x080000000, 0, Number.MAX_VALUE, 42, 0x080000000, -0x07fffffff, -0, 0x0ffffffff, -(2**53), -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, 1/0, 1, Number.MIN_VALUE, -0x100000000, -(2**53+2), Math.PI, 0x100000000, 2**53+2, -0x100000001, -(2**53-2), 2**53-2, 0/0]); ");
/*fuzzSeed-42369751*/count=358; tryItOut("e0.delete(f1);");
/*fuzzSeed-42369751*/count=359; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.min((( + (( + (( + Math.max(y, -Number.MIN_SAFE_INTEGER)) <= ( + y))) - ( + y))) % ((mathy0(Math.fround(Math.atanh((x | 0))), Math.min(x, ( + (-Number.MAX_VALUE | 0)))) | 0) === (( + (Math.pow(-(2**53+2), (x | 0)) | 0)) | 0))), ((((( + (y % (0x080000001 >> Math.fround((0.000000000000001 || 2**53-2))))) | 0) ** (( ~ (Math.fround(Math.min(( + x), x)) >>> (mathy2((-Number.MIN_VALUE >>> 0), (x >>> 0)) >>> 0))) ? (x ? ( - -0x080000001) : x) : y)) >>> 0) != Math.log10((Number.MIN_SAFE_INTEGER >>> 0)))); }); ");
/*fuzzSeed-42369751*/count=360; tryItOut("let (b = window, eval, \u3056, e = this, hnuhat, oliyky) { var v0 = false; }");
/*fuzzSeed-42369751*/count=361; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=362; tryItOut("function shapeyConstructor(kkqgmo){\"use strict\"; if (kkqgmo) for (var ytqvvnrko in this) { }if (kkqgmo) this[new String(\"-18\")] = (0/0);return this; }/*tLoopC*/for (let d of /*FARR*/[]) { try{let swgtrv = new shapeyConstructor(d); print('EETT'); const ndjmaw, x, window, y, mkqdwu, d, z, w, NaN, x;;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-42369751*/count=363; tryItOut("mathy2 = (function(x, y) { return Math.log2(((Math.fround(Math.tanh(x)) , ( + ( ! (( ! Math.fround(0x07fffffff)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy2, [0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, Math.PI, -0, 0x0ffffffff, 0.000000000000001, 0x100000000, 2**53-2, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, 2**53+2, 1, -(2**53+2), -0x080000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 42, -0x100000001, 0x080000000, -1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=364; tryItOut("g1.f1.toSource = (function() { Object.prototype.watch.call(b0, \"split\", (function() { try { s1.__proto__ = e1; } catch(e0) { } Object.defineProperty(this, \"h0\", { configurable: (x % 33 != 14), enumerable: ((Int8Array).apply((x ==  /x/ ))),  get: function() {  return ({getOwnPropertyDescriptor: function(name) { for (var p in t1) { try { for (var v of g2) { Object.preventExtensions(g2); } } catch(e0) { } try { m0.delete(i1); } catch(e1) { } try { a1 = a2.filter((function() { for (var j=0;j<140;++j) { this.f1(j%4==0); } }), y); } catch(e2) { } Object.defineProperty(this, \"v0\", { configurable: (x % 14 == 5), enumerable: true,  get: function() { g1.offThreadCompileScript(\"g1.v0 = (i1 instanceof e1);\", ({ global: g2.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 12 != 5), noScriptRval: (x % 71 != 49), sourceIsLazy: (x % 35 == 13), catchTermination: window })); return 0; } }); }; var desc = Object.getOwnPropertyDescriptor(o0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { throw a0; var desc = Object.getPropertyDescriptor(o0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a0 = Array.prototype.slice.apply(this.a0, [3, 8, (new ((window =  /x/g ))()) - 3 ? window : new RegExp(\"\\\\2\", \"gyim\")]);; Object.defineProperty(o0, name, desc); }, getOwnPropertyNames: function() { /*RXUB*/var r = this.r1; var s = s0; print(uneval(s.match(r))); print(r.lastIndex); ; return Object.getOwnPropertyNames(o0); }, delete: function(name) { a2[({valueOf: function() { /*infloop*/M:for(var arguments.callee.caller.arguments in (( '' )((Math.max( '' , 16)))))v1 = t1.length;return 11; }})];; return delete o0[name]; }, fix: function() { return g2.g0; if (Object.isFrozen(o0)) { return Object.getOwnProperties(o0); } }, has: function(name) { i2 + m2;; return name in o0; }, hasOwn: function(name) { print(uneval(m0));; return Object.prototype.hasOwnProperty.call(o0, name); }, get: function(receiver, name) { throw i0; return o0[name]; }, set: function(receiver, name, val) { a1.unshift(g1, g2);; o0[name] = val; return true; }, iterate: function() { x = a1;; return (function() { for (var name in o0) { yield name; } })(); }, enumerate: function() { h1 = ({getOwnPropertyDescriptor: function(name) { v1 = Array.prototype.some.call(o2.a1, (function() { g1.a1.push(g0.s2); return g0.g1.p0; }));; var desc = Object.getOwnPropertyDescriptor(a1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { p1 + '';; var desc = Object.getPropertyDescriptor(a1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw this.o2; Object.defineProperty(a1, name, desc); }, getOwnPropertyNames: function() { t2[5];; return Object.getOwnPropertyNames(a1); }, delete: function(name) { o1 = x;; return delete a1[name]; }, fix: function() { o0.v2 = NaN;; if (Object.isFrozen(a1)) { return Object.getOwnProperties(a1); } }, has: function(name) { h2.get = f0;; return name in a1; }, hasOwn: function(name) { v2 = a0.every((4277), m2, b1);; return Object.prototype.hasOwnProperty.call(a1, name); }, get: function(receiver, name) { v1 = r1.sticky;; return a1[name]; }, set: function(receiver, name, val) { Object.defineProperty(this, \"s2\", { configurable: \"\\uC41E\", enumerable: (x % 86 == 78),  get: function() {  return new String(a0); } });; a1[name] = val; return true; }, iterate: function() { i0 + '';; return (function() { for (var name in a1) { yield name; } })(); }, enumerate: function() { v2 = Object.prototype.isPrototypeOf.call(f1, e1);; var result = []; for (var name in a1) { result.push(name); }; return result; }, keys: function() { a2.shift();; return Object.keys(a1); } });; var result = []; for (var name in o0) { result.push(name); }; return result; }, keys: function() { Array.prototype.splice.call(a0, NaN, 8, [[1]]);; return Object.keys(o0); } }); } }); return g2.t0; })); return a0; });");
/*fuzzSeed-42369751*/count=365; tryItOut("let c = (4277), NaN, \u3056 = ({configurable: false}), z = -(2**53-2), [] = x, z = x, z = x, x, \u3056 = \"\\u82B4\", z; '' ;return  '' ;");
/*fuzzSeed-42369751*/count=366; tryItOut("{ void 0; disableSPSProfiling(); } const x = Math.hypot(-27, /\\2/gy), x = ({a1:1}), NaN;{v0 = a1.every((function() { try { s1 = g0.objectEmulatingUndefined(); } catch(e0) { } a2.pop(); return t0; }), o0.i1); }");
/*fuzzSeed-42369751*/count=367; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan(Math.fround(Math.min(Math.tanh(Math.imul(Math.hypot((x | 0), (y | 0)), y)), Math.asin(x))))); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), /0/, undefined, 0, [], [0], '\\0', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new String('')), (new Boolean(false)), NaN, null, (new Number(-0)), -0, true, false, (new Number(0)), '', 1, 0.1, (new Boolean(true)), (function(){return 0;}), '0', '/0/']); ");
/*fuzzSeed-42369751*/count=368; tryItOut("g0.h0 + i0;");
/*fuzzSeed-42369751*/count=369; tryItOut("\"use strict\"; g1.o2.e2.has(v2);");
/*fuzzSeed-42369751*/count=370; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-42369751*/count=371; tryItOut("var eozvhy, {x, 815208724, x: x, e: {c: [[, , ], , , ], e: window, w: {x}, x: c}} = true, xjwkcs, [{x: {NaN: {eval: {y}}, x}, eval: z}] = let (y =  '' ) \"\\u6F4E\", x = window, z, oolpaw;print(eval(\"[z1];\"));");
/*fuzzSeed-42369751*/count=372; tryItOut("(x = /(?!(?:(?!(?!.)))+?){4}/gi);");
/*fuzzSeed-42369751*/count=373; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\d{1,}\", \"yim\"); var s = \"__a\"; print(s.replace(r, '\\u0341')); \n");
/*fuzzSeed-42369751*/count=374; tryItOut("mathy0 = (function(x, y) { return ( - ( ~ ( + (Math.asin((Math.sqrt(y) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-42369751*/count=375; tryItOut("\"use strict\"; Array.prototype.shift.apply(a2, [g1, v1]);");
/*fuzzSeed-42369751*/count=376; tryItOut("/*oLoop*/for (var lvghtb = 0; lvghtb < 12; ++lvghtb) { print(NaN); } \n");
/*fuzzSeed-42369751*/count=377; tryItOut("var srczfc = new ArrayBuffer(6); var srczfc_0 = new Uint16Array(srczfc); var srczfc_1 = new Uint16Array(srczfc); srczfc_1[0] = -24; var srczfc_2 = new Float32Array(srczfc); srczfc_2[0] = -10; var srczfc_3 = new Uint8Array(srczfc); print(srczfc_3[0]); srczfc_3[0] = 10; print(\"\\u7A0F\");(window);for (var v of f2) { a1.unshift(v2); }a0 = arguments;var o2.v2 = g2.eval(\"e0.toString = (function(j) { if (j) { this.v2 = a2.length; } else { try { g2.v1.__iterator__ = (function() { try { v0 = (b0 instanceof o2.v2); } catch(e0) { } o1 = {}; return p1; }); } catch(e0) { } /*ODP-2*/Object.defineProperty(g0, -19, { configurable:  /x/g , enumerable: false, get: (function(j) { if (j) { try { i0 = g1.a2[17]; } catch(e0) { } try { t2 + o0; } catch(e1) { } v1 = this.g0.runOffThreadScript(); } else { h1.getOwnPropertyNames = (function(j) { if (j) { a0 = arguments.callee.caller.arguments; } else { try { o1 + ''; } catch(e0) { } try { print(h0); } catch(e1) { } s0 + ''; } }); } }), set: f2 }); } });\");i0.next();");
/*fuzzSeed-42369751*/count=378; tryItOut("\"use strict\"; f1 = Proxy.createFunction(h2, f1, g1.f2);");
/*fuzzSeed-42369751*/count=379; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.atan2(Math.atan2(y, x), (0x080000001 || Math.imul((Math.imul(y, x) >>> 0), x))) | 0) ? ( + ( + Math.fround(Math.hypot(Math.fround(( ~ Math.fround(y))), Math.fround(( ~ y)))))) : (Math.round(( + (((Math.imul(y, 0x07fffffff) | 0) , (Math.fround((Math.fround(x) << (((Math.fround(1/0) + Math.fround(x)) >>> 0) >>> 0))) | 0)) | 0))) | 0)) | 0); }); testMathyFunction(mathy3, [42, -0x100000000, 2**53-2, -(2**53-2), 0x080000001, 0.000000000000001, 0x100000001, 1/0, -0x080000000, 0, -0x100000001, -1/0, 0x080000000, 0x07fffffff, -0x080000001, -(2**53), 0x0ffffffff, 0/0, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, -(2**53+2), 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, -0x07fffffff, 2**53+2]); ");
/*fuzzSeed-42369751*/count=380; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.abs((Math.fround(Math.pow((-Number.MIN_SAFE_INTEGER & ( + ( ~ (Math.min(Math.fround(y), ( ! (0 >>> 0))) | 0)))), (Math.min(Math.fround((((y | 0) == ((Math.PI % y) | 0)) | 0)), ( + (x / Math.fround(mathy1(( + 1.7976931348623157e308), ( + (( ~ (y | 0)) | 0))))))) | 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-42369751*/count=381; tryItOut("v2 = a1.every();");
/*fuzzSeed-42369751*/count=382; tryItOut("{(x); }");
/*fuzzSeed-42369751*/count=383; tryItOut("\"use strict\"; for (var p in g2) { a0.shift(); }");
/*fuzzSeed-42369751*/count=384; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.fround(Math.acosh(( ~ (Math.fround((Math.fround(-0x100000001) === Math.fround(Math.imul((2**53+2 | 0), y)))) | 0)))); }); testMathyFunction(mathy5, [1/0, -0x100000001, 0x100000000, 0x080000000, -1/0, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, Math.PI, -0x080000001, -0, Number.MAX_VALUE, 42, -0x07fffffff, -0x0ffffffff, 2**53, -Number.MIN_VALUE, 0x0ffffffff, 0.000000000000001, -(2**53+2), 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, 1, -0x100000000, 0x07fffffff, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-42369751*/count=385; tryItOut("/*infloop*/ for  each(x in (4277)) /*infloop*/M:for(var d; w+=window < a; intern(false)) {print(18);this.g0.s2 += 'x'; }");
/*fuzzSeed-42369751*/count=386; tryItOut("mathy0 = (function(x, y) { return ( ! (Math.cosh((Math.hypot((Math.atan2(-0x100000001, x) | 0), (y | 0)) | 0)) >>> 0)); }); ");
/*fuzzSeed-42369751*/count=387; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! (Math.fround(Math.exp((mathy2(mathy0((( ~ y) ? x : (-0x080000000 != y)), ((y | 0) + (x | 0))), Math.fround(Math.imul(-Number.MAX_SAFE_INTEGER, (Math.sin(x) >>> 0)))) + x))) >>> 0)); }); testMathyFunction(mathy4, [(function(){return 0;}), 1, ({valueOf:function(){return '0';}}), 0, ({toString:function(){return '0';}}), (new String('')), '', [0], (new Boolean(false)), ({valueOf:function(){return 0;}}), null, (new Boolean(true)), undefined, (new Number(-0)), -0, objectEmulatingUndefined(), /0/, '0', false, true, NaN, 0.1, (new Number(0)), [], '\\0', '/0/']); ");
/*fuzzSeed-42369751*/count=388; tryItOut("a0[v0] = i1;");
/*fuzzSeed-42369751*/count=389; tryItOut("\"use asm\"; e2.has(e0);\nv2 = g2.runOffThreadScript();\n");
/*fuzzSeed-42369751*/count=390; tryItOut("const d = x, NaN = Math.atan2( /x/g , -29), window =  /x/g , oghrjo, NaN, lvdlvp;print(x = c);");
/*fuzzSeed-42369751*/count=391; tryItOut("/*ADP-3*/Object.defineProperty(this.a0, 14, { configurable: true, enumerable: (x % 4 != 1), writable: x, value: ((function sum_indexing(tqiuku, bohejf) { o0.v0 = Object.prototype.isPrototypeOf.call(e2, g0.v1);function window() { return this } \u000c/(?:\\b+?[^\\B-\\u008D\\d\\W]|(?:.)[^]|[^]{1,})*?/im;\u0009; return tqiuku.length == bohejf ? 0 : tqiuku[bohejf] + sum_indexing(tqiuku, bohejf + 1); })(/*MARR*/[ \"\" ,  \"\" , function(){}, function(){}, function(){}, arguments, arguments, arguments, arguments,  \"\" , function(){}, function(){}, arguments, arguments, arguments, arguments,  \"\" ,  \"\" ,  \"\" , arguments, arguments,  \"\" ,  \"\" , function(){},  \"\" , function(){}, function(){},  \"\" ,  \"\" ,  \"\" ,  \"\" , arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments,  \"\" , arguments,  \"\" , arguments, arguments,  \"\" ,  \"\" , arguments,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , function(){}, arguments, function(){},  \"\" ,  \"\" ,  \"\" , function(){}, function(){}, arguments,  \"\" , function(){}, arguments, function(){}, function(){}, arguments, arguments, arguments, function(){}, function(){}, function(){},  \"\" , arguments, function(){}, arguments, arguments, arguments, arguments,  \"\" , arguments, arguments, function(){},  \"\" , arguments, function(){},  \"\" , arguments,  \"\" ], 0)) });");
/*fuzzSeed-42369751*/count=392; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2(?!.|(+)(?:(?:\\\\B))*?\", \"gyi\"); var s = \"\\n\"; print(s.split(r)); ");
/*fuzzSeed-42369751*/count=393; tryItOut("mathy0 = (function(x, y) { return Math.max((( + Math.fround(Math.cos(Math.fround(Math.fround(( ~ Math.fround(( + (( + -(2**53)) & ( + x)))))))))) < Math.imul(( + Math.expm1(((y && ((-0 < x) >>> 0)) >>> 0))), Math.atan((((x >>> 0) , ((Math.imul((x | 0), (x | 0)) | 0) | 0)) >>> 0)))), Math.sign((Math.abs((Math.sqrt(( + ( + Math.pow((x ? x : Math.exp(x)), Number.MIN_VALUE)))) | 0)) | 0))); }); testMathyFunction(mathy0, [({toString:function(){return '0';}}), [], (new Number(0)), false, /0/, [0], '/0/', true, (new String('')), '', (new Boolean(false)), NaN, '\\0', 0, 1, (new Boolean(true)), (new Number(-0)), undefined, ({valueOf:function(){return '0';}}), '0', ({valueOf:function(){return 0;}}), -0, (function(){return 0;}), 0.1, objectEmulatingUndefined(), null]); ");
/*fuzzSeed-42369751*/count=394; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(this.a2, 5, { configurable: (x % 33 != 12), enumerable: (x % 3 != 2), get: (function() { try { i2.send(p2); } catch(e0) { } print(p2); return f0; }), set: (function(j) { if (j) { try { g1 = this; } catch(e0) { } try { m2.has(g0); } catch(e1) { } try { f0(g2); } catch(e2) { } h1.iterate = f1; } else { /*MXX2*/g0.Object.prototype.valueOf = g1.v1; } }) });");
/*fuzzSeed-42369751*/count=395; tryItOut("print(x);print(x);for (var v of e0) { v0 = a0.every((function() { for (var j=0;j<17;++j) { f0(j%4==1); } }), h0); }");
/*fuzzSeed-42369751*/count=396; tryItOut("var eval =  \"\" , eval, eval, [[]] = arguments, window;a1 = g0.a1.filter((function() { try { o1.s2 = new String; } catch(e0) { } try { Object.defineProperty(this, \"v2\", { configurable: (4277)\n, enumerable: (x % 2 == 0),  get: function() {  return g1.runOffThreadScript(); } }); } catch(e1) { } try { this.a0 + t1; } catch(e2) { } Object.seal(v2); throw v2; }), m1, f1);");
/*fuzzSeed-42369751*/count=397; tryItOut("this.t1[2] = o1.v1\n");
/*fuzzSeed-42369751*/count=398; tryItOut("/*iii*/v0 = a1.length;/*hhh*/function nooqis(x, y = /\\xA4|^{1,5}\\b+?|(?!\\1)\\x65(?:[^]){4,8}|[^]$|$+?[\\S\u0091]{0,}|\\3(?:(\\1)[^])/gy){v0 = t1.length;}");
/*fuzzSeed-42369751*/count=399; tryItOut("Object.freeze(p0);");
/*fuzzSeed-42369751*/count=400; tryItOut("a0 = Array.prototype.slice.apply(g2.a0, [NaN, NaN]);");
/*fuzzSeed-42369751*/count=401; tryItOut("print(e0);");
/*fuzzSeed-42369751*/count=402; tryItOut("v0 = evaluate(\"g0.v0 = Object.prototype.isPrototypeOf.call(s1, h1);\", ({ global: this.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (1 for (x in [])).prototype, sourceIsLazy: (({x: (4277)})), catchTermination: false }));var qiefwh = new SharedArrayBuffer(8); var qiefwh_0 = new Uint16Array(qiefwh); print(qiefwh_0[0]); qiefwh_0[0] = x; null;");
/*fuzzSeed-42369751*/count=403; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=404; tryItOut("\"use strict\"; /*infloop*/while(this.__defineSetter__(\"window\", offThreadCompileScript)()){for (var p in h0) { try { v1 = (g0.f0 instanceof o0.o0); } catch(e0) { } v1 = (g1.v2 instanceof g0); }f1.toString = Set.prototype.keys.bind(t0); }");
/*fuzzSeed-42369751*/count=405; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(g1, new String(\"8\"), { configurable: (x % 3 != 0), enumerable: ({ get constructor(...d)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d0 = (d1);\n    }\n    {\n      d1 = (d0);\n    }\n    return +((d1));\n  }\n  return f;, \"-16\": ( /x/  * y << this) }), writable: true, value: h2 });function yield(b, {d, e}, window, eval = (4277), {}, window = x <  '' , x, NaN, x = (uneval( /x/g )), x, d, a = false, NaN, d, x, x, NaN, w = [[1]], x = [z1], d, x, x, x, eval) { { void 0; void 0; } m1.get(i1); } selectforgc(o1);");
/*fuzzSeed-42369751*/count=406; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=407; tryItOut("testMathyFunction(mathy5, /*MARR*/[{}, new Boolean(true), new Number(1.5)]); ");
/*fuzzSeed-42369751*/count=408; tryItOut("s0 += s0;\n(function(id) { return id });\n");
/*fuzzSeed-42369751*/count=409; tryItOut("\"use strict\"; h2.set = (function() { try { delete h0.defineProperty; } catch(e0) { } try { v0.toSource = (function(j) { if (j) { try { a0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 6.044629098073146e+23;\n    var i3 = 0;\n    i0 = (i0);\n    return ((((i3) ? (!(!(i0))) : (i0))+((0x2653d456) >= (((((0x552f521e) >= (0x7fffffff)) ? ((([] = (void options('strict_mode'))))) : ((0x990ddbb0) ? (0xa265a579) : (0xfc7abce3))))>>>((0x0) % (0xae667d67))))))|0;\n    i3 = (((((((/*FFI*/ff(((~((i3)))))|0)) | ((Float64ArrayView[((i1)) >> 3]))))) & ((uneval(x)))) > (~~(d2)));\n    return ((((2305843009213694000.0) == (-131073.0))+(i0)))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); } catch(e0) { } try { i1.send(g1); } catch(e1) { } m0.get(g0.e2); } else { try { print(g2); } catch(e0) { } try { for (var v of a1) { try { Array.prototype.unshift.apply(a0, [e2]); } catch(e0) { } try { a1.reverse(); } catch(e1) { } try { a2 = [((x) = arguments) for (x of new RegExp(\"\\u80f7\", \"i\")) for (e of []) for each (x in [])]; } catch(e2) { } v0 = evaluate(\"var t0 = new Float32Array(t1);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 4 != 2) })); } } catch(e1) { } Array.prototype.splice.call(a1, 10, 9, this.v0, m0); } }); } catch(e1) { } try { a1.sort((function() { /*RXUB*/var r = this.r2; var s = x; print(r.exec(s)); print(r.lastIndex);  return o1; })); } catch(e2) { } Object.defineProperty(this, \"b1\", { configurable: (x % 4 != 2), enumerable: false,  get: function() {  return t2.buffer; } }); return this.o0; });");
/*fuzzSeed-42369751*/count=410; tryItOut("\"use strict\"; a0.reverse(o2, i2, s0);");
/*fuzzSeed-42369751*/count=411; tryItOut("var sbvlwv = new ArrayBuffer(4); var sbvlwv_0 = new Float64Array(sbvlwv); sbvlwv_0[0] = 22; var sbvlwv_1 = new Uint16Array(sbvlwv); var sbvlwv_2 = new Int16Array(sbvlwv); print(sbvlwv_2[0]); sbvlwv_2[0] = 4611686018427388000; i2.next();");
/*fuzzSeed-42369751*/count=412; tryItOut("mathy3 = (function(x, y) { return ( ! ((Math.hypot((Math.hypot((Math.fround(( + y)) >>> 0), y) >>> 0), ((( + ( - ( + Math.fround(Math.log10(y))))) && y) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[[], [], [], [], [], [], [], new Boolean(false), [], new Boolean(false), [undefined], new Boolean(false), new Boolean(false), [], [], [], new Boolean(false), [], [undefined], [undefined], [], new Boolean(false), [undefined], [], new Boolean(false), [], [undefined], [], new Boolean(false), new Boolean(false), [undefined], new Boolean(false), [undefined], [], [], [undefined], [], [undefined], new Boolean(false), new Boolean(false), [undefined], new Boolean(false), [undefined], [], [], [], [], [], [undefined], new Boolean(false), new Boolean(false), new Boolean(false), [undefined], new Boolean(false), new Boolean(false), [undefined], new Boolean(false), [undefined], [], [undefined], [], [], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), [undefined], [undefined], [undefined], [], [], []]); ");
/*fuzzSeed-42369751*/count=413; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy1(( + Math.hypot(( + ((( ! Math.trunc(((2**53+2 > (42 >>> 0)) | 0))) >>> 0) > ((((mathy0((y | 0), x) >>> 0) | 0) % x) | 0))), ( + Math.asinh((mathy1((x | 0), Math.fround(Math.hypot(x, x))) | 0))))), (( ~ mathy1(x, 0x080000000)) ** (( + Math.log1p((( + mathy1(( + y), ( + (mathy0(0.000000000000001, y) | 0)))) ^ x))) >>> 0))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[function(){},  '\\0' , NaN, x, x, function(){}, function(){}, NaN, new Number(1), x, x, new Number(1), NaN, new Number(1),  '\\0' , new Number(1), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x,  '\\0' , new Number(1),  '\\0' , function(){}, new Number(1), new Number(1), x, new Number(1), NaN, x,  '\\0' , x, x, new Number(1), NaN, function(){}, new Number(1), function(){}, function(){}, new Number(1),  '\\0' , x, new Number(1), NaN,  '\\0' , x, new Number(1), x,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , NaN, x,  '\\0' ,  '\\0' , NaN, x, new Number(1),  '\\0' , NaN]); ");
/*fuzzSeed-42369751*/count=414; tryItOut("\"use strict\"; v1 = g0.runOffThreadScript();");
/*fuzzSeed-42369751*/count=415; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.imul(Math.fround(Math.max((Math.imul(( + x), ( + Math.fround(Math.imul(Math.fround(Math.hypot(( + y), 0x100000000)), Math.fround(0x07fffffff))))) >>> x), Math.log(( ~ y)))), Math.imul(Math.fround((( + ( + ( - x))) >>> ( + mathy2((( - (x | 0)) | 0), y)))), Math.imul(Math.atan2(( ! y), y), (((( + y) | (((y >>> 0) >= 42) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy4, [-(2**53+2), -1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, 0x100000000, -0x07fffffff, 2**53-2, -Number.MAX_VALUE, Math.PI, 2**53, 0x100000001, 1/0, 0x0ffffffff, 0x07fffffff, 0.000000000000001, Number.MAX_VALUE, 0x080000000, 42, 0x080000001, -0x100000001, 0, 2**53+2, -0x080000000, 0/0, 1]); ");
/*fuzzSeed-42369751*/count=416; tryItOut("M:for([b, w] = (Math.asin(27) <<= ((a) = false)) in -28) /*RXUB*/var r = true ?  ''  :  '' ; var s = \"\"; print(s.replace(r, '')); ");
/*fuzzSeed-42369751*/count=417; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x100000000, 0x100000001, -0, 2**53+2, 0x07fffffff, -1/0, 2**53, 1, 0, 2**53-2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), 42, -0x080000000, Math.PI, -Number.MIN_VALUE, 0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, 0x100000000, 1.7976931348623157e308, -0x100000001, 0x080000000]); ");
/*fuzzSeed-42369751*/count=418; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((((Math.fround((( + (Math.asinh(( + mathy1(( + 1.7976931348623157e308), ( + x)))) | 0)) | 0)) | 0) | 0) >= ((mathy0(( + mathy1((( ~ ((Math.fround(x) | 0) ** Math.fround(mathy1(( + y), Math.fround(0))))) >>> 0), Math.sqrt(( ~ ( + y))))), (Math.fround(x) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x0ffffffff, Math.PI, -Number.MIN_VALUE, 2**53, -(2**53+2), -1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 0x0ffffffff, -Number.MAX_VALUE, -0, 0x080000001, 0x100000001, 2**53+2, 0x07fffffff, 42, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), 0, Number.MIN_VALUE, 2**53-2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1, 1/0, -0x07fffffff, 0x100000000, 0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=419; tryItOut("\"use strict\"; Object.defineProperty(this, \"a1\", { configurable: false, enumerable: false,  get: function() {  return Array.prototype.map.call(a0, f2); } });");
/*fuzzSeed-42369751*/count=420; tryItOut("/*RXUB*/var r = /\\2(?:\\W|(?:.))|(?:(?=\\\u6a06)?)/y; var s = new RegExp(\"(?:(?:(?:[\\\\B\\\\d\\u2820-\\u2e13\\\\B-\\ud023])))\", \"gm\"); print(uneval(r.exec(s))); ");
/*fuzzSeed-42369751*/count=421; tryItOut("mathy1 = (function(x, y) { return Math.atan2(((((Math.fround(Math.min(x, (Math.imul((y | 0), (y | 0)) | 0))) > (((x * ( ~ ( ~ y))) >>> 0) >>> 0)) >>> 0) && (Math.max(((mathy0(-0x0ffffffff, y) ** ( + y)) | 0),  get y y (\u000c) { return \"\\uE9FF\" ? new RegExp(\"\\\\w\", \"gym\") : 4; } ) >>> 0)) >>> 0), Math.exp(( + Math.acosh(((((Math.fround(Math.expm1(Math.fround(Math.atan(y)))) | 0) >= (Number.MIN_SAFE_INTEGER | 0)) | 0) >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=422; tryItOut("i0.send(o1);");
/*fuzzSeed-42369751*/count=423; tryItOut("const x = intern(undefined);o0.i1 + '';");
/*fuzzSeed-42369751*/count=424; tryItOut("mathy3 = (function(x, y) { return ( + (( + ( - (Math.pow((mathy0((mathy1(y, x) | 0), (-Number.MAX_VALUE | 0)) >>> 0), ( + Math.fround(Math.asinh((Math.sinh((Math.hypot((y | 0), x) >>> 0)) | 0))))) | 0))) - ( + Math.fround(Math.sinh(Math.fround(Math.trunc(-Number.MAX_SAFE_INTEGER))))))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), function(){}, x, -Infinity, objectEmulatingUndefined(), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, x, x, function(){}, function(){}, x, -Infinity, -Infinity, x, -Infinity, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, x, objectEmulatingUndefined(), -Infinity, x, objectEmulatingUndefined(), -Infinity, x, objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, -Infinity, -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), -Infinity, -Infinity, x, objectEmulatingUndefined(), -Infinity, function(){}, x, function(){}, -Infinity, function(){}, -Infinity, function(){}, -Infinity, objectEmulatingUndefined(), function(){}, x, -Infinity, objectEmulatingUndefined(), -Infinity, -Infinity, -Infinity, x, function(){}, x, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, -Infinity, function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), -Infinity, -Infinity, -Infinity, -Infinity, function(){}, -Infinity, -Infinity, x, objectEmulatingUndefined(), function(){}, -Infinity, function(){}, -Infinity, -Infinity, function(){}]); ");
/*fuzzSeed-42369751*/count=425; tryItOut("mathy3 = (function(x, y) { return (Math.log((( ! (( + ( ~ ( + Math.fround(((( ~ (Math.atan2(( ~ x), ( + y)) | 0)) | 0) & ( + ( + Math.pow(y, x)))))))) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy3, [-0x080000000, -0x0ffffffff, -(2**53+2), 2**53+2, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, Math.PI, 0x080000000, -0x100000000, 0x07fffffff, -0x100000001, 0x100000001, Number.MIN_VALUE, 0.000000000000001, 0x080000001, -(2**53-2), 1, -0x080000001, 2**53, -1/0, -Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 42, 1.7976931348623157e308, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=426; tryItOut("(18);");
/*fuzzSeed-42369751*/count=427; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=428; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-42369751*/count=429; tryItOut("\"use strict\"; v0 + '';let c = {x: [window, {d: {}, x: x, b: NaN}, , x, ], window: arguments, x: [, ], eval, window: {window, NaN: [[[[, [, {}]], {z: {z: \"16\"}, w: {x: y}}], , x], , , x], x: {a: [{name, x & ((makeFinalizeObserver('tenured'))), w}, , d, , x], b: {x: {\u3056: -25, \u3056, NaN, \u3056: (a)}, NaN: x}, x, a: window}, eval: [[, {x: c, b: a}, {x: x, \u3056: [, ], z: {x: a}}, , [, , , b]], , , , {z: b, b, z: {x: {window: x, NaN: {}, c}, x}, c: [, \u3056, x]}]}, x: x} = [];");
/*fuzzSeed-42369751*/count=430; tryItOut("\"use strict\"; let z = -18;(z);");
/*fuzzSeed-42369751*/count=431; tryItOut("print(uneval(s0));");
/*fuzzSeed-42369751*/count=432; tryItOut("m0.get(this.i1);");
/*fuzzSeed-42369751*/count=433; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(Math.pow(Math.fround(( + ( + Math.imul((( + Math.abs(( + y))) | 0), Math.min(Math.fround(y), (x & y)))))), ( + (x % mathy3(Math.fround((y >= Math.fround(y))), y)))))); }); testMathyFunction(mathy4, [-(2**53-2), Number.MIN_VALUE, -0x080000001, 0.000000000000001, -(2**53+2), 0, 2**53+2, 0x100000000, -Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, 0x07fffffff, 2**53, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, -0x100000000, -0x100000001, 0x080000001, -0x0ffffffff, -1/0, 1, 1/0, 42, 1.7976931348623157e308, 2**53-2]); ");
/*fuzzSeed-42369751*/count=434; tryItOut("let (x = allocationMarker(), x = (x ? x : (intern(delete b.x))), x = /*FARR*/[21, ...[], ...[], , function ([y]) { }, , this, , this,  /x/ , \"\\u6FCD\", , ...[], -11, ...[], ].map, y = x, [] = (let (a =  \"\" ) new RegExp(\"((?!([^])[^\\\\xC9-\\\\u4106\\\\b])+)\\\\u0045*\", \"g\")), x = delete eval.getter, mcqxaq, wpoela, this.x, jjmail) { o1.v1 = g2.eval(\"print(x);\"); }");
/*fuzzSeed-42369751*/count=435; tryItOut("o1.t1 = new Float64Array(16);");
/*fuzzSeed-42369751*/count=436; tryItOut("v2 = b0.byteLength;");
/*fuzzSeed-42369751*/count=437; tryItOut("this.v2 = evaluate(\"(/*MARR*/[].some(RegExp))\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 != 2), sourceIsLazy: false, catchTermination: Math.exp(-8)\n }));");
/*fuzzSeed-42369751*/count=438; tryItOut("/*tLoop*/for (let b of /*MARR*/[new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined()]) { s0.__proto__ = p0;\ns2 += 'x';\n }");
/*fuzzSeed-42369751*/count=439; tryItOut("\"use strict\"; { void 0; void relazifyFunctions('compartment'); } {let (NaN = [,], c, aruuij, b) { h0.toString = (function() { b0.toSource = (function() { for (var j=0;j<26;++j) { f1(j%2==0); } }); return h2; }); } }");
/*fuzzSeed-42369751*/count=440; tryItOut("/*hhh*/function wzdnts(x, x, z = new Array(), [], \u3056, x, x = -20, d, a, \u3056, x, window, a, x, x, x, x, x, x, x, x, d, a, eval, z = x, d, d, x, NaN = new RegExp(\"(?![^]|[^]{1}^*.\\u0007|(?![^]\\\\b)\\\\2\\\\2)\\\\u2C00\", \"m\"), \u3056, x, x =  /x/ , a, \u3056, b, this.x, x = \"\\u00B1\", e, x, x, a, this.x, d = false, b = -25, z, \u3056, c, x, w, d, x, window, window, window, x, window, \u3056 =  /x/g , x, a, x, eval, c, x, NaN, NaN, x, z, x, x, x, NaN,  \"\"  = 11, \u3056, d = w, c, x, x, x, c, e, x, eval, w, w, \u3056, x, c, b = \"\\u4BF8\", x){for (var v of p1) { try { for (var p in b2) { try { a0.toSource = (function() { for (var j=0;j<99;++j) { f1(j%2==0); } }); } catch(e0) { } for (var p in m2) { try { f0 + g0; } catch(e0) { } try { s2 = new String; } catch(e1) { } m0.get(f1); } } } catch(e0) { } try { v2 = evaluate(\"print(o0);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: [,,], sourceIsLazy:  /x/g , catchTermination: (x % 2 == 0), elementAttributeName: s0, sourceMapURL: s1 })); } catch(e1) { } s0 += s2; }}wzdnts();");
/*fuzzSeed-42369751*/count=441; tryItOut("mathy4 = (function(x, y) { return (mathy3((Math.log(( + (( + Math.pow((y > Math.atan2((y >>> 0),  \"\" ;)), Math.fround(Math.fround(( - Math.fround(x)))))) ^ ( + Math.max(y, ( + mathy3(Math.tanh(-(2**53)), Number.MIN_VALUE))))))) | 0), Math.imul((( + (( - x) | 0)) | 0), ( + Math.acosh(x)))) | 0); }); testMathyFunction(mathy4, [0x080000001, 1/0, -(2**53), 2**53, 0.000000000000001, 0x080000000, -1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, -0x100000000, 2**53-2, 0x100000001, -(2**53+2), 42, 2**53+2, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, 0/0, -0, 1, 0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-42369751*/count=442; tryItOut("\"use asm\"; v0 = (this.g2 instanceof g0.g1);");
/*fuzzSeed-42369751*/count=443; tryItOut("\"use strict\"; print(uneval(o0));");
/*fuzzSeed-42369751*/count=444; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((d1));\n  }\n  return f; })(this, {ff: (arguments.callee.caller.arguments++)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, ['\\0', 0.1, [], false, (new Number(0)), [0], true, 1, (new Number(-0)), 0, (new Boolean(true)), '/0/', null, '0', (new String('')), ({valueOf:function(){return '0';}}), '', /0/, ({toString:function(){return '0';}}), undefined, (function(){return 0;}), objectEmulatingUndefined(), NaN, (new Boolean(false)), -0, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-42369751*/count=445; tryItOut("i0 = new Iterator(f0, true);");
/*fuzzSeed-42369751*/count=446; tryItOut("mathy4 = (function(x, y) { return ( + ( + Math.fround(mathy0(Math.fround((y / (Math.atan2(( + x), (y >>> 0)) >>> 0))), Math.fround(Math.fround(( + Math.fround((Math.log10(( + Math.fround(Math.max((Math.sign(y) | 0), Math.fround((y ? Math.pow(y, y) : 1.7976931348623157e308)))))) | 0))))))))); }); testMathyFunction(mathy4, [({toString:function(){return '0';}}), false, ({valueOf:function(){return 0;}}), (new Boolean(false)), '0', 0, (new Number(-0)), objectEmulatingUndefined(), null, (new String('')), 1, '', [], ({valueOf:function(){return '0';}}), (new Boolean(true)), 0.1, (new Number(0)), '\\0', '/0/', undefined, -0, /0/, [0], true, NaN, (function(){return 0;})]); ");
/*fuzzSeed-42369751*/count=447; tryItOut("o0.v1 = evalcx(\"e2.add(e0);\", g1);");
/*fuzzSeed-42369751*/count=448; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-42369751*/count=449; tryItOut(";");
/*fuzzSeed-42369751*/count=450; tryItOut("i2.toSource = (function() { /*MXX1*/o0 = g0.WeakMap.prototype.set; return o1; });\nreturn;\n");
/*fuzzSeed-42369751*/count=451; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.reverse.call(a2, p1, o2, g0);");
/*fuzzSeed-42369751*/count=452; tryItOut("\"use strict\"; var yhfkao = new ArrayBuffer(16); var yhfkao_0 = new Float64Array(yhfkao); v1 = evaluate(\"v0 = Object.prototype.isPrototypeOf.call(p0, h2);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (yhfkao_0[0] % 4 == 2), sourceIsLazy: (yhfkao_0 % 6 != 4), catchTermination: false }));print(e0);v2 = (m2 instanceof g0.a1);print(m0);");
/*fuzzSeed-42369751*/count=453; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=454; tryItOut("this.t0 = new Uint8Array(15);");
/*fuzzSeed-42369751*/count=455; tryItOut("/*hhh*/function bdjenf([, {window: \u3056, x: w, NaN: x}, , [[], , , , {x: x}, ]], {window: {}, x, b: [, , , ], NaN: x, x, a: \u3056, eval}, ...a){;}/*iii*/if( /x/ ) {print(bdjenf);o0.__proto__ = v2; } else  if (((4277) | x)) {throw window;x; } else {return -0; }");
/*fuzzSeed-42369751*/count=456; tryItOut("a2 = arguments;");
/*fuzzSeed-42369751*/count=457; tryItOut("\"use strict\"; e1.add((timeout(1800)));");
/*fuzzSeed-42369751*/count=458; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=459; tryItOut("print((4277));return x;");
/*fuzzSeed-42369751*/count=460; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.fround(( ! (( + (y | 0)) | 0))) || (( ~ (Math.imul((((((Math.fround(Math.max(((((x | 0) ? y : Math.fround(x)) | 0) >>> 0), (y >>> 0))) | 0) == (( + Math.abs(Math.fround(x))) | 0)) >>> 0) + (-Number.MAX_VALUE >>> 0)) >>> 0), (Math.fround((Math.min(y, 1/0) ? x : -0x100000000)) | Math.fround(0x080000001))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, ['\\0', (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Boolean(true)), ({toString:function(){return '0';}}), 0, (new String('')), undefined, '0', true, null, 0.1, false, '', '/0/', [], (new Boolean(false)), (new Number(-0)), 1, NaN, /0/, objectEmulatingUndefined(), (new Number(0)), -0, ({valueOf:function(){return '0';}}), [0]]); ");
/*fuzzSeed-42369751*/count=461; tryItOut("let hluheb, b, this.x = NaN, {} = Math.imul(c, -1200730118.5), svbqge;( /x/ );function z(x, ...e) { return x } ;");
/*fuzzSeed-42369751*/count=462; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.log10(Math.fround(Math.log1p(((((Math.pow(((0x080000001 %  \"\" ) | 0), ((y | -0) | 0)) | 0) | 0) , (x | 0)) | 0))))); }); testMathyFunction(mathy5, [0, -(2**53+2), -(2**53), -0x100000001, 42, 0x080000000, 2**53+2, 0/0, 2**53-2, -(2**53-2), 2**53, -1/0, -Number.MAX_VALUE, 0x100000001, 1, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, -0x080000000, Math.PI, 1/0, -0, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, 0x080000001, 0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=463; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-42369751*/count=464; tryItOut("x = a2[3];");
/*fuzzSeed-42369751*/count=465; tryItOut("/*RXUB*/var r = /(((?![^])|^\\1((\\1)){0}|\\1\\3|(\\S|\\1)|(?:\ufedf)\\u0066{4,}|\\s+?(?=\\W).\\D*?))?/gm; var s = \u3056 = this.unwatch(\"__proto__\"); print(uneval(s.match(r))); ");
/*fuzzSeed-42369751*/count=466; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.atan2(Math.cbrt(((Math.fround(Math.atan2((( ! y) | 0), (mathy1((x | 0), (y >>> 0)) | 0))) !== Math.fround(y)) <= ( + (0x0ffffffff | 0)))), Math.imul(Math.exp(( + mathy2(Math.fround(y), ( + ((((Math.pow(y, x) | 0) >>> 0) == (( + (( + x) && ( + x))) >>> 0)) >>> 0))))), (Math.imul((x >>> 0), (( + (( + (Math.hypot((((x >>> 0) << y) | 0), (Math.min(x, Number.MIN_SAFE_INTEGER) | 0)) | 0)) - ( + mathy1(( + x), Math.fround(x))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x07fffffff, -0x080000000, Math.PI, -0x100000000, -0x0ffffffff, -(2**53+2), 0/0, 0, -(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, 42, -0x080000001, -0x07fffffff, 2**53, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000001, -1/0, 1, 1.7976931348623157e308, 0x080000000, 1/0, -0, 0x100000000, Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=467; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xab60a4ab)))|0;\n  }\n  return f; })(this, {ff: (yield  /x/ )}, new ArrayBuffer(4096)); ");
/*fuzzSeed-42369751*/count=468; tryItOut("testMathyFunction(mathy2, /*MARR*/[033, -0x07fffffff, 033, x, -0x07fffffff, -0x07fffffff, 033, 033, -0x07fffffff, x, -0x07fffffff, -0x07fffffff, x, 033, x, 033, 033, x, -0x07fffffff, x, 033, 033, x, 033, 033, 033, 033, x, x, 033, -0x07fffffff, 033, -0x07fffffff, 033, -0x07fffffff, x, x, x, -0x07fffffff, -0x07fffffff, x, 033, -0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-42369751*/count=469; tryItOut("i1 + this.t0;");
/*fuzzSeed-42369751*/count=470; tryItOut("[,];print(x);");
/*fuzzSeed-42369751*/count=471; tryItOut("");
/*fuzzSeed-42369751*/count=472; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((Math.fround((Math.fround(( + (Math.hypot((((2**53+2 | 0) <= (Math.fround(( - (y | 0))) | 0)) | 0), Math.max(y, (y >>> 0))) | 0))) ** Math.fround(Math.fround(( - Math.fround(y)))))) * (Math.pow(( - (( + (( ! 0.000000000000001) | 0)) | 0)), Math.fround(Math.imul(Math.fround(42), Math.fround(Math.fround(mathy1(Math.fround(mathy0(y, 0x100000000)), ( + Math.min(Math.expm1(2**53-2), x)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[(void 0), new String('q'), (void 0), new String('q'), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0)]); ");
/*fuzzSeed-42369751*/count=473; tryItOut("e0.has(g1.i1);");
/*fuzzSeed-42369751*/count=474; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.sqrt(Math.fround(Math.hypot((( ! Math.log2(( + ( + Math.atanh(( + 0x080000001)))))) ? Math.log(y) : Math.max((((x ^ ( + ( ~ ( + x)))) | 0) >>> 0), (x >>> 0))), ((((( + (y >>> 0)) >>> 0) * y) >>> 0) && Math.fround(Math.imul((-(2**53-2) >>> 0), ( + Math.log10(( + Math.asin(( ! x))))))))))); }); ");
/*fuzzSeed-42369751*/count=475; tryItOut("f0.toString = (function mcc_() { var yvxija = 0; return function() { ++yvxija; if (/*ICCD*/yvxija % 4 == 0) { dumpln('hit!'); v2 = undefined; } else { dumpln('miss!'); (void schedulegc(g2)); } };})();");
/*fuzzSeed-42369751*/count=476; tryItOut("M:switch(Math.hypot(c++, (void version(170)))) { case 7: break; case function ([y]) { }\n & y = window:  }");
/*fuzzSeed-42369751*/count=477; tryItOut("for (var p in s0) { for (var v of m2) { a2.reverse(o0.o0.p0); } }");
/*fuzzSeed-42369751*/count=478; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.ceil((( + mathy0(( + x), ( + ( - Math.fround(( - (Math.acos((2**53-2 >>> 0)) >>> 0))))))) <= Math.abs(Math.exp(Math.fround((((y >>> 0) & (y | 0)) >>> 0))))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 1, 42, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 2**53+2, 0.000000000000001, -0x100000000, -(2**53), 0, 0/0, -0, -0x080000000, 0x100000001, 0x07fffffff, 1.7976931348623157e308, -0x100000001, 0x080000001, Math.PI, 0x080000000, 0x0ffffffff, 1/0, -(2**53-2), 0x100000000, -0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0]); ");
/*fuzzSeed-42369751*/count=479; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ Math.fround(( ~ ( + Math.exp(Math.min(y, y)))))); }); testMathyFunction(mathy2, /*MARR*/[new String(''), new String(''), new String('')]); ");
/*fuzzSeed-42369751*/count=480; tryItOut("\"use strict\"; /*infloop*/L:for((({\u3056: {}, c: x} = eval(\"var suakuw = new ArrayBuffer(16); var suakuw_0 = new Uint8ClampedArray(suakuw); print(suakuw_0[0]); suakuw_0[0] = 27; v0 = a0.length;\"))); (w); ((void version(180)))) g2.t2[16] = s1;");
/*fuzzSeed-42369751*/count=481; tryItOut("\"use asm\"; /*hhh*/function oeevbe(e, x, eval = (makeFinalizeObserver('tenured')), x, [{x: []}], SyntaxError.prototype.constructor, a, \u3056,   = ( \"\" .throw( \"\" )), y, x, w = 7, eval, x, set, NaN, x, c, let, x = window, e, eval, window, \u3056, a, b, x, a, window =  /x/ , x, y = false, y, x = [[]], w, x = -3, w, window, NaN, e, y, x = new RegExp(\"(\\\\1)+|(?:[^]|[^]{0}|(?:(?:\\\\r))\\\\1)\", \"y\"), x, z, eval =  '' , x, x, x, b, y, x,   = 23, e, \u3056, y = z, x, NaN, x = \"\\uDD94\", x, x, z, x = ({a2:z2}), x = true, y, x, x = /((?!\\f*?))(?:\\b)[\u784f\\cM-\\\ue0b7\u23e3\\x35-{]+?/gyi, x, b = /[^]|((?=\\W{2}|(?:\\\u00ac)))/yi,  , x, \u3056, x, x, x, w, d, x, x =  \"\" , x, e, x, x, c, a, \u3056, y, x, x, w, b, x, eval, x, x, eval, NaN, x, x, window = /(?:(?=\\D?|^)?)/g){this.a2.forEach((function() { try { Array.prototype.forEach.call(a0, f1); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(o0, p0); } catch(e1) { } try { e2 = x; } catch(e2) { } v0 = g1.eval(\"function f2(e0)  { \\\"use asm\\\"; yield (x = ((makeFinalizeObserver('nursery')))) } \"); return o1; }));}oeevbe(x);");
/*fuzzSeed-42369751*/count=482; tryItOut("mathy4 = (function(x, y) { return (( ~ ( - Math.log1p(Math.min(( + (Math.cos((((y >>> 0) % y) >>> 0)) >>> 0)), x)))) >>> 0); }); ");
/*fuzzSeed-42369751*/count=483; tryItOut("s2.__proto__ = this.e2;");
/*fuzzSeed-42369751*/count=484; tryItOut("/* no regression tests found */;");
/*fuzzSeed-42369751*/count=485; tryItOut("s1 = new String(h2);const d = (4277);");
/*fuzzSeed-42369751*/count=486; tryItOut("v1 = new Number(o0);");
/*fuzzSeed-42369751*/count=487; tryItOut("\"use asm\"; /*iii*/function(y) { \"use asm\"; return  ''  }/*hhh*/function sdulin(){;}");
/*fuzzSeed-42369751*/count=488; tryItOut("\"use strict\"; for([c, e] = (function(y) { \"use strict\"; Array.prototype.sort.call(a2, (function() { try { g2.v2 = Object.prototype.isPrototypeOf.call(o0.e0, g1.p1); } catch(e0) { } try { m2.get(e1); } catch(e1) { } Array.prototype.splice.call(a1, 10, 6); return i1; })); })() in x) {o0.o0[new String(\"5\")] = m0; }");
/*fuzzSeed-42369751*/count=489; tryItOut("{M: for (let a of false) {v2 = o2.r2.global; }\ncontinue ;\ndo {throw  \"\" ; } while(( '' ) && 0); }");
/*fuzzSeed-42369751*/count=490; tryItOut("/*RXUB*/var r = \"\\u928E\"; var s = \"aa \\n1\\n\"; print(r.test(s)); ");
/*fuzzSeed-42369751*/count=491; tryItOut("\"use strict\"; v1 = (f2 instanceof p0);selectforgc(o2);");
/*fuzzSeed-42369751*/count=492; tryItOut("v1 = (o0.h1 instanceof g1);");
/*fuzzSeed-42369751*/count=493; tryItOut("\"use strict\"; e2 = new Set;");
/*fuzzSeed-42369751*/count=494; tryItOut("var c, x = (neuter)(), x = (4277), z =  '' , x = ((p={}, (p.z = undefined ? this : /$|(?=\\3{2,6})+/)()) * new RegExp(\"(?=\\\\1|[^]|.\\u07b2|.|\\\\B+\\\\2)\", \"g\")), x, \u3056 = let (x = (\u3056) = true) (function ([y]) { } **= c);{i2.send(s0);/*tLoop*/for (let b of /*MARR*/[Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER,  \"use strict\" , Number.MAX_SAFE_INTEGER,  \"use strict\" ]) { ( \"\" ); } }");
/*fuzzSeed-42369751*/count=495; tryItOut("for(var [y, a] = (4277) in new w => \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -17.0;\n    var d4 = -8388608.0;\n    var i5 = 0;\n    (this.__defineSetter__(\"x\", timeout(1800))) = ((Float64ArrayView[(-(i2)) >> 3]));\n    d1 = (d4);\n    return +((d3));\n  }\n  return f;( /x/ ,  \"\" ) ? /*MARR*/[-0x100000000, new Number(1), -0x100000000, new Number(1), null].filter(\"\\u7972\") : x) var htiamq = new SharedArrayBuffer(0); var htiamq_0 = new Int8Array(htiamq); print(htiamq_0[0]); e0 + a2;");
/*fuzzSeed-42369751*/count=496; tryItOut("\"use strict\"; s2 = t0[v2];");
/*fuzzSeed-42369751*/count=497; tryItOut("testMathyFunction(mathy0, ['\\0', ({valueOf:function(){return 0;}}), '/0/', (new String('')), (function(){return 0;}), '0', undefined, (new Number(0)), 0, (new Boolean(true)), (new Number(-0)), true, NaN, false, null, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), 0.1, objectEmulatingUndefined(), -0, [], (new Boolean(false)), /0/, 1, '', [0]]); ");
/*fuzzSeed-42369751*/count=498; tryItOut("/*infloop*/for(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function(name) { return delete x[name]; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(((function fibonacci(lpifyc) { ; if (lpifyc <= 1) { ; return 1; } for (var p in g0.e2) { try { function f1(g1.f2)  { yield window }  } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(this.o1, i2); } catch(e1) { } a2.__iterator__ = (function() { try { selectforgc(o2); } catch(e0) { } ; return s2; }); }; return fibonacci(lpifyc - 1) + fibonacci(lpifyc - 2);  })(1))), eval, encodeURI); d; x) {v2 = r2.ignoreCase; }");
/*fuzzSeed-42369751*/count=499; tryItOut("mathy4 = (function(x, y) { return (( + (Math.imul(Math.tanh(Math.fround(( ! Math.max(x, Math.fround(1))))), (Math.atan2(Math.fround((Math.imul((Math.log1p(0x080000000) | 0), ( + ( ~ ( + Math.asinh(x))))) | 0)), ( + ( ! ( + (( ~ x) | 0))))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [2**53-2, Number.MIN_VALUE, -(2**53), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0x100000001, 2**53+2, 1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 0x07fffffff, 0, 2**53, 0x080000001, -1/0, 1, -0, 0x080000000, 0/0, -Number.MAX_VALUE, -0x07fffffff, 0x100000000, -0x080000000, -(2**53+2), 42, -0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=500; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.acos(Math.hypot(((mathy1(((( - ( + Math.imul(Math.fround(x), y))) >>> 0) >>> 0), (Math.fround(Math.pow(Math.fround(((1/0 <= -Number.MIN_VALUE) && Number.MIN_VALUE)), ((( + (y | 0)) | 0) | 0))) >>> 0)) >>> 0) | 0), (( + (( + (-Number.MIN_SAFE_INTEGER === ((-Number.MAX_VALUE <= ( + mathy1(Math.fround(-Number.MIN_VALUE), ( + x)))) | 0))) ? Math.fround(( ! Math.fround(mathy2(y, x)))) : ( + -0))) | 0))) | 0); }); testMathyFunction(mathy3, [Math.PI, -0x080000001, 1.7976931348623157e308, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 1, 2**53, -1/0, -(2**53), -0x0ffffffff, 0.000000000000001, 0x100000000, -0x080000000, -(2**53-2), Number.MAX_VALUE, 42, -0x07fffffff, 2**53+2, 1/0, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, 0x100000001, 0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -0]); ");
/*fuzzSeed-42369751*/count=501; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( - Math.acos((( + Math.fround(mathy1(x, ( - x)))) | 0)))); }); testMathyFunction(mathy2, [-(2**53+2), -0, -0x100000001, 0/0, Math.PI, 0x100000001, 1, Number.MAX_VALUE, -0x100000000, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, 0, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, 2**53-2, -1/0, -0x080000001, -0x080000000, 0x080000001, 0x100000000, 1/0, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=502; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.min((Math.log10(Math.log10(((x ? ( + ( + -(2**53+2))) : x) >>> 0))) >>> 0), (Math.fround((( + mathy0(x, ( + (Math.fround(Math.atan(Math.exp(x))) && y)))) ? ( + Math.abs(Math.fround(Math.fround((-0 ? y : Math.fround(Math.fround(Math.min(0.000000000000001, Math.fround(y))))))))) : ( + (x ** ( + Math.pow(2**53-2, x)))))) % mathy0(( + (Math.max(Math.max(x, -Number.MIN_VALUE), y) | 0)), mathy0(y, -0x07fffffff))))); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 0x080000000, -0x080000000, -0, 2**53, 0x100000000, -0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), 2**53+2, 1/0, -1/0, -0x080000001, -0x100000001, 2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, Math.PI, 1, 0, Number.MAX_VALUE, 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 42, 0x080000001, -(2**53), -0x100000000, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-42369751*/count=503; tryItOut("\"use strict\"; o2.v2 = Object.prototype.isPrototypeOf.call(a1, m1);");
/*fuzzSeed-42369751*/count=504; tryItOut("mathy3 = (function(x, y) { return ( + ( + ( + Math.fround((Math.hypot((mathy2(Math.atanh(Math.fround(y)), (y | 0)) >>> 0), ( + mathy1(1.7976931348623157e308, 0x07fffffff))) >>> 0))))); }); testMathyFunction(mathy3, [2**53-2, Number.MAX_SAFE_INTEGER, -(2**53), -1/0, 0x100000000, -0x080000000, -0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, 1, 0x080000001, 1/0, -0, 0x07fffffff, -0x100000001, 2**53+2, 0, -0x07fffffff, -0x080000001, Number.MIN_VALUE, 0x080000000, -0x0ffffffff, 42, 1.7976931348623157e308, -(2**53-2), -Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, 0/0, 0x0ffffffff, 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=505; tryItOut("\"use asm\"; Array.prototype.reverse.apply(a1, [g2]);");
/*fuzzSeed-42369751*/count=506; tryItOut("v2 = b1[\"call\"];");
/*fuzzSeed-42369751*/count=507; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + ( - (( + (Math.atan2((( ~ (mathy1((Math.round(Math.fround(1.7976931348623157e308)) | 0), (x | 0)) >>> 0)) >>> 0), x) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [-1/0, -0x100000001, 1/0, 0/0, 42, -0, 0x100000000, -(2**53-2), -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, 0, 2**53-2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, Math.PI, -0x100000000, 0x07fffffff, Number.MAX_VALUE, 2**53+2, 0x080000000, 0x0ffffffff, 0x080000001, 0.000000000000001, -0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-42369751*/count=508; tryItOut("this.v0 = evalcx(\"this.h0.enumerate = (function() { try { b1.valueOf = (function mcc_() { var kbukhj = 0; return function() { ++kbukhj; if (kbukhj > 3) { dumpln('hit!'); try { print(uneval(this.o0.f2)); } catch(e0) { } try { b0 = new SharedArrayBuffer(20); } catch(e1) { } try { a2.forEach(m1); } catch(e2) { } v2 = -Infinity; } else { dumpln('miss!'); try { v2 = t1.length; } catch(e0) { } try { g2.m2.get(o0); } catch(e1) { } g0.valueOf = (function(j) { f2(j); }); } };})(); } catch(e0) { } Array.prototype.shift.call(a2); return p1; });\", g1);");
/*fuzzSeed-42369751*/count=509; tryItOut("/*MXX2*/g0.DataView.prototype.setFloat32 = s2;");
/*fuzzSeed-42369751*/count=510; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( - ((( + (( + x) === ( + ( + Math.cosh(( + Math.max(Math.asinh(x), x))))))) >>> 0) ? ( + Math.max(Math.atanh(y), y)) : ((Math.acosh((Math.log2((Math.atan(( ! y)) | 0)) >>> 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[(void 0), (void 0), {x:3}, .2, .2, .2, .2, .2, .2, {x:3},  /x/ , (void 0), {x:3}, (void 0),  /x/ ,  /x/ , {x:3}, (void 0), (void 0), {x:3},  /x/ ,  /x/ , {x:3}, (void 0),  /x/ , {x:3}, (void 0), .2, .2, .2, .2, .2, .2, (void 0),  /x/ , .2, {x:3}, (void 0), .2, (void 0), {x:3}, {x:3},  /x/ ,  /x/ ,  /x/ ]); ");
/*fuzzSeed-42369751*/count=511; tryItOut("/*bLoop*/for (var ammist = 0, \u3056 = (([]) =  /x/g ); ammist < 38; ++ammist) { if (ammist % 4 == 2) { g2.f2.__proto__ = g1.i2; } else { return ((function() { \"use strict\"; \"use asm\"; yield null; } })()); }  } ");
/*fuzzSeed-42369751*/count=512; tryItOut("Object.defineProperty(this, \"s2\", { configurable: let (e)  '' , enumerable: true,  get: function() {  return new String(b0); } });");
/*fuzzSeed-42369751*/count=513; tryItOut("for (var v of v0) { try { print(uneval(g0)); } catch(e0) { } try { e2.has(h2); } catch(e1) { } try { t0.set(t0, 8); } catch(e2) { } for (var v of o0.e2) { try { i2 + ''; } catch(e0) { } a0[4] = null; } }");
/*fuzzSeed-42369751*/count=514; tryItOut("return;for(let x in []);");
/*fuzzSeed-42369751*/count=515; tryItOut("yield  '' ;\n(17);\n\nv1 = a1.length;\n");
/*fuzzSeed-42369751*/count=516; tryItOut("v2 = a1.length;");
/*fuzzSeed-42369751*/count=517; tryItOut("\"use strict\"; o0 = g0.m0.__proto__;");
/*fuzzSeed-42369751*/count=518; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ! (Math.fround(( ~ (Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) ? Math.fround(Math.atan2(x, Math.fround(Math.min(y, x)))) : Math.fround(x))) , x))) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(false), -0, -0, new Boolean(false), let (e) e, new Boolean(false), new Boolean(false),  \"use strict\" , let (e) e, new Number(1), let (e) e, -0, -0,  \"use strict\" , new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), -0, -0, new Number(1), let (e) e, -0, let (e) e, let (e) e,  \"use strict\" ,  \"use strict\" , new Number(1),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Number(1),  \"use strict\" , -0, new Boolean(false),  \"use strict\" ,  \"use strict\" , new Boolean(false), new Boolean(false),  \"use strict\" , new Number(1), -0, let (e) e, new Boolean(false), -0, let (e) e, let (e) e, new Boolean(false), -0,  \"use strict\" , new Number(1), let (e) e, new Boolean(false),  \"use strict\" , let (e) e, -0, -0,  \"use strict\" , let (e) e,  \"use strict\" , let (e) e]); ");
/*fuzzSeed-42369751*/count=519; tryItOut("mathy1 = (function(x, y) { return (Math.atan(Math.fround(( - (mathy0(Math.fround(y), ( ~ Math.fround(x))) | 0)))) > Math.atan(( ~ y))); }); testMathyFunction(mathy1, [-(2**53), 1/0, 0/0, 42, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000001, 2**53-2, Number.MAX_VALUE, -0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, 0x0ffffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), Math.PI, -0x07fffffff, 2**53, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 0x080000000, -0x080000000, 0x100000001, Number.MIN_VALUE, 1, 0, -0x0ffffffff, 0.000000000000001, 2**53+2]); ");
/*fuzzSeed-42369751*/count=520; tryItOut("/*RXUB*/var r = new RegExp(\"(?![^]|\\\\b^|\\\\b*|\\\\s|($+?)|(?:(?:.))|(?=\\\\b){3,}|\\\\3(?:(?=\\\\1))+?)\", \"yim\"); var s = \"\\n\\n\\n\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=521; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1+?\", \"m\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=522; tryItOut("for(let e in []);");
/*fuzzSeed-42369751*/count=523; tryItOut("this;function x(e,  , ...x) { \"use strict\"; yield; } throw y\u000c;");
/*fuzzSeed-42369751*/count=524; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - Math.min((Math.fround(Math.fround(Math.ceil(x))) >= (mathy1(( + (Math.atan((0.000000000000001 >>> 0)) >>> 0)), (((Math.log((x >>> 0)) >>> 0) ? ( ! -Number.MIN_SAFE_INTEGER) : (x >> (((Number.MIN_SAFE_INTEGER | 0) >> (0x100000001 | 0)) | 0))) >>> 0)) >>> 0)), (Math.fround(((y >>> 0) , y)) == x))); }); testMathyFunction(mathy2, [-0x080000000, -(2**53), 1, 0x100000000, 0x07fffffff, 42, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, 0, -(2**53+2), -(2**53-2), -Number.MIN_VALUE, 1/0, 0x100000001, 0.000000000000001, 0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 0/0, Number.MIN_VALUE, -0x100000000, 2**53+2, 1.7976931348623157e308, 2**53, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-42369751*/count=525; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i0);\n    }\n    i1 = (((((0xc956f*(i1)) << ((i0))) % ((((((0x8b334761)) | ((0xe8eeb336))))-(i1)+((0x33d1be43) > (0x66df941e))) | ((/*FFI*/ff(((((0xf90095cb)) ^ ((0x2170be5b)))), ((+abs(((-129.0))))), ((576460752303423500.0)), ((1.015625)), ((-524289.0)), ((-72057594037927940.0)), ((7.737125245533627e+25)), ((6.044629098073146e+23)), ((549755813889.0)), ((1024.0)), ((-268435455.0)), ((295147905179352830000.0)), ((2.3611832414348226e+21)), ((1.888946593147858e+22)), ((0.0009765625)), ((-68719476735.0)), ((17592186044417.0)), ((3.094850098213451e+26)), ((549755813889.0)), ((36893488147419103000.0)), ((4.722366482869645e+21)), ((134217729.0)), ((4.835703278458517e+24)), ((17179869185.0)), ((3.022314549036573e+23)), ((-16385.0)), ((7.555786372591432e+22)), ((-288230376151711740.0)), ((1.888946593147858e+22)), ((8388607.0)), ((-4611686018427388000.0)), ((-295147905179352830000.0)), ((-17179869184.0)), ((295147905179352830000.0)), ((-2.4178516392292583e+24)), ((-68719476737.0)), ((-8193.0)), ((35184372088833.0)), ((35184372088833.0)), ((64.0)), ((-9223372036854776000.0)), ((9.44473296573929e+21)), ((8191.0)))|0)-(i1)))) & ((~~(3.8685626227668134e+25)) / (~~(147573952589676410000.0)))));\n    {\n      (Int16ArrayView[((0x9cd04df)-(i0)-((0x467a9e87) >= (abs((((-0x8000000)) << ((0xfdf4ae10))))|0))) >> 1]) = ((0xc1d7a84)-(i1)-(((-(i1)) & ((0x0) % (((0x30189461))>>>((0x1a5a4320))))) < ((((0xa621d0fa) > (((0x250e639e))>>>((0xba5ca7d2))))) | ((i1)-(i0)))));\n    }\n    i1 = ((i0) ? (i1) : (i1));\n    {\n      (Int16ArrayView[2]) = (((((/*FFI*/ff(((-32.0)), ((35184372088832.0)), ((-6.044629098073146e+23)), ((131073.0)), ((-562949953421313.0)), ((-3.094850098213451e+26)))|0)-(i1)+((0xfbc6670d) ? (0xefbfbb64) : (0x13c2b0f4))) ^ ((!(0xeb16baf0)))) == (((0xffffffff)) ^ (-0x184d5*(i0))))+(/*FFI*/ff(((+atan2(((-262144.0)), ((Float32ArrayView[((i0)) >> 2]))))), ((+sqrt(((((-1152921504606847000.0)) - ((2147483649.0))))))), ((Float32ArrayView[4096])), ((+(-1.0/0.0))), ((((0xf98c3857)+(0xbf514b49)) & (((0x2e10a5d2) != (-0x8000000))))), ((Math.hypot(-21, new RegExp(\"(?!\\\\W)\", \"gm\")))))|0)-(i1));\n    }\n    return ((((0x33def5f0))))|0;\n  }\n  return f; })(this, {ff: e =>  { return x } }, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), 0/0, 2**53+2, -0x100000000, -0, -0x07fffffff, Math.PI, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, -1/0, 2**53, 0x100000001, -0x080000000, -0x080000001, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 0, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 0x080000000, 0x0ffffffff, 0x080000001, 42, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=526; tryItOut("testMathyFunction(mathy0, [-0x100000000, 0, 1/0, -(2**53-2), 0x080000001, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000000, Math.PI, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -1/0, -(2**53), 2**53+2, -0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 2**53, Number.MAX_VALUE, -0x0ffffffff, 1, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 2**53-2, 42, Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-42369751*/count=527; tryItOut("mathy4 = (function(x, y) { return (Math.min(( + ( + (mathy1((Math.acosh(x) | 0), (x | 0)) | 0))), Math.fround(((( + (y >>> 0)) >>> 0) ? Math.fround(( ! Math.atanh(x))) : Math.fround(( + (( + y) >> ( + Math.fround((Math.cbrt(y) == (( - (Math.sinh(x) | 0)) | 0)))))))))) >> Math.fround((Math.imul(Math.fround(( + Math.fround(( ~ (0x100000001 !== 0x080000001))))), (Math.tanh(( + ( + Math.asin(( + Math.atan2(y, (x | 0))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [1, 0x080000001, -0x100000000, -(2**53+2), 0.000000000000001, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -Number.MIN_VALUE, 0/0, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 42, 0x0ffffffff, 0x080000000, -0x07fffffff, 2**53-2, -1/0, 0, Number.MAX_VALUE, 1/0, -(2**53-2), Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, Number.MIN_VALUE, -(2**53), 0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=528; tryItOut("for (var v of g1) { try { delete m1[17]; } catch(e0) { } Array.prototype.shift.apply(a0, [e0, o0]); }");
/*fuzzSeed-42369751*/count=529; tryItOut("\"use strict\"; /*iii*/o1.v1 = g2.runOffThreadScript();/*hhh*/function fuzmxj(x, ...a){print(new RegExp(\"((?=[^](\\\\b*){3,4099})\\\\u19b7|\\\\D+[^]\\\\b?+?)\", \"gim\"));}");
/*fuzzSeed-42369751*/count=530; tryItOut("\"use strict\"; a1 = [];");
/*fuzzSeed-42369751*/count=531; tryItOut("\"use strict\"; /*RXUB*/var r = /\\w*/ym; var s = \"a\"; print(s.match(r)); ");
/*fuzzSeed-42369751*/count=532; tryItOut("mathy5 = (function(x, y) { return Math.atan((mathy1(Math.min(x, Math.asinh(Math.fround(mathy2((-Number.MAX_VALUE | 0), ( + Math.min(Math.fround(y), Math.fround(x))))))), (( + Math.max(( ~ (( + Math.fround(x)) >>> 0)), Math.fround(y))) && y)) | 0)); }); ");
/*fuzzSeed-42369751*/count=533; tryItOut("v0 = t2.length;");
/*fuzzSeed-42369751*/count=534; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d0 = (NaN);\n    (Float32ArrayView[1]) = ((524289.0));\n    i2 = ((~~(+((((0x6bb12ac1) ? (0xf88220ae) : (0x3ac2556f)))>>>((0xc3e55079)-(i2)-((0x33cfab33) >= (0x7fffffff)))))) == (((((0xe67e85ea) % (0x0)) ^ (-0x6cf0b*(i2))) % (abs((((0xe67e0ecc)*-0x85dbc) & (((0x6997e508) == (0x2a0fb4a7)))))|0)) >> ((0x5240cf5a) / (0xe90de251))));\n    d0 = ((Float64ArrayView[4096]));\n    return +((Float32ArrayView[((0x6b6dffe)+((((0xfe0f8f58)+(x))>>>((((0x348783f3)) ^ ((0xbb41ca3c))) / (abs((((0xfcd4e989)) ^ ((0xffffffff))))|0))))) >> 2]));\n  }\n  return f; })(this, {ff: (offThreadCompileScript).call}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000000, -Number.MAX_VALUE, 0x0ffffffff, 0, 0x080000000, -0x100000001, 0/0, -1/0, 0x100000000, 1.7976931348623157e308, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 0.000000000000001, 1, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, 2**53-2, 42, Math.PI, Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, -0]); ");
/*fuzzSeed-42369751*/count=535; tryItOut("mathy3 = (function(x, y) { return Math.fround(((Math.pow((Math.min((Math.acosh(( ! Number.MAX_SAFE_INTEGER)) | 0), ((Math.acosh(Math.fround(Math.expm1(Math.fround((( ~ ( + y)) >>> 0))))) >>> 0) | 0)) | 0), (Math.fround(( - Math.fround(Math.fround(Math.log(Math.fround(y)))))) | 0)) | 0) * ( ~ ( + ( + Math.max(0, (( + ( + ( - ( + x)))) | 0))))))); }); testMathyFunction(mathy3, try { x.stack; } catch(a if (x = x)) { for(let d in []); } catch(z if (function(){let(c) ((function(){for(let b in []);})());})()) { return; } catch(c) { let(NaN) { with({}) { c.fileName; } } } finally { let(e) { this.zzz.zzz;} } ); ");
/*fuzzSeed-42369751*/count=536; tryItOut("");
/*fuzzSeed-42369751*/count=537; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (((mathy1((( + (( ! x) >>> 0)) >>> 0), ((Math.abs(Math.min(x, (Math.min((y | 0), Math.fround(-(2**53-2))) | 0))) | 0) >>> 0)) >>> 0) , (( + Math.sin((( + 0x100000000) | 0))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[function(){}, -0x080000001, -0x080000001, -0x080000001, function(){}, function(){}, -0x080000001, [1], function(){}, function(){}, [1], function(){}, function(){}, -0x080000001, function(){}, -0x080000001, [1], [1], [1], -0x080000001, [1], [1], -0x080000001, -0x080000001, [1], [1], -0x080000001, function(){}, -0x080000001, function(){}, function(){}, -0x080000001, [1], -0x080000001, [1], [1], function(){}, function(){}, -0x080000001, [1], [1], -0x080000001, function(){}, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, [1], function(){}, -0x080000001, -0x080000001, function(){}, function(){}, function(){}, function(){}, -0x080000001, -0x080000001, -0x080000001, function(){}, function(){}, function(){}, function(){}, function(){}, [1], -0x080000001, [1], -0x080000001, -0x080000001, -0x080000001, [1], [1], [1], -0x080000001, function(){}, -0x080000001, function(){}, [1], -0x080000001, function(){}, -0x080000001, [1]]); ");
/*fuzzSeed-42369751*/count=538; tryItOut("\"use strict\"; i2 + '';");
/*fuzzSeed-42369751*/count=539; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { /*oLoop*/for (ocklhg = 0; ocklhg < 2; ++ocklhg) { print(x); } return 10; }}), { configurable: new (z =>  { \"use strict\"; s0 += s0; } )((c = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: undefined, getOwnPropertyNames:  '' , delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function() { return undefined }, set: undefined, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( /x/ ), 2.setUTCDate, (x, \u3056) =>  {  \"\" ; } ))), enumerable: false, get: f2, set: (function(j) { if (j) { for (var p in o0) { try { m0.delete(s1); } catch(e0) { } try { for (var v of a2) { try { for (var p in h2) { try { print(a0); } catch(e0) { } s1 += 'x'; } } catch(e0) { } try { v0 = (i1 instanceof p1); } catch(e1) { } e1.has(f1); } } catch(e1) { } m2.get(g1); } } else { try { g2 = this; } catch(e0) { } m0.__proto__ = v1; } }) });");
/*fuzzSeed-42369751*/count=540; tryItOut("t0[17];");
/*fuzzSeed-42369751*/count=541; tryItOut("testMathyFunction(mathy2, ['0', (new Number(-0)), ({toString:function(){return '0';}}), null, '\\0', true, ({valueOf:function(){return 0;}}), 0, (new Boolean(true)), ({valueOf:function(){return '0';}}), '', objectEmulatingUndefined(), false, '/0/', 1, /0/, (new Boolean(false)), (new Number(0)), NaN, (function(){return 0;}), -0, [], [0], (new String('')), 0.1, undefined]); ");
/*fuzzSeed-42369751*/count=542; tryItOut("o2 + this.g2;");
/*fuzzSeed-42369751*/count=543; tryItOut("/*RXUB*/var r = new RegExp(\"(?=.)(?=(?:\\\\1)$|\\\\BZ\\u00c7)\", \"\"); var s = \"\\n:\\u00c7\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=544; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.round((( + (Math.fround(( + Math.fround((((x >>> 0) / ((( + y) / y) >>> 0)) >>> 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[ \"\" , 0x99, (0/0), 0x99,  \"\" , 0x99,  \"\" , 0x99,  \"\" , (0/0),  \"\" , 0x99,  \"\" ,  \"\" ,  \"\" , 0x99, 0x99,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , (0/0),  \"\" , (0/0), (0/0), 0x99, (0/0),  \"\" , 0x99, 0x99,  \"\" , (0/0),  \"\" , (0/0),  \"\" ,  \"\" , (0/0),  \"\" , 0x99, 0x99, (0/0), 0x99,  \"\" , (0/0), 0x99,  \"\" , 0x99, 0x99, (0/0), 0x99, (0/0), 0x99, (0/0), (0/0),  \"\" , 0x99, (0/0),  \"\" , 0x99,  \"\" ,  \"\" , (0/0), 0x99, (0/0), (0/0), (0/0), (0/0), 0x99, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), 0x99, (0/0),  \"\" , 0x99, 0x99, (0/0), 0x99,  \"\" ,  \"\" , 0x99,  \"\" ,  \"\" ,  \"\" ,  \"\" , (0/0), 0x99, (0/0), (0/0), 0x99,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, (0/0), (0/0), 0x99,  \"\" ,  \"\" , 0x99,  \"\" , 0x99,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 0x99, 0x99, (0/0),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 0x99,  \"\" , 0x99, 0x99, 0x99,  \"\" , (0/0),  \"\" , (0/0)]); ");
/*fuzzSeed-42369751*/count=545; tryItOut("");
/*fuzzSeed-42369751*/count=546; tryItOut("/*tLoop*/for (let y of /*MARR*/[new Boolean(true), {}, new Boolean(true), {}, {}, new Boolean(true), {}, {}, {},  '\\0' ,  '\\0' , {},  '\\0' , new Boolean(true), new Boolean(true), {}, new Boolean(true), new Boolean(true), {}, {}, new Boolean(true), {}, new Boolean(true), {}, new Boolean(true), {}]) { this.h1.get = f0; }");
/*fuzzSeed-42369751*/count=547; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.hypot(Math.cos(Math.max(((Math.fround((mathy1((x >>> 0), (Math.log(y) >>> 0)) >>> 0)) * ( ! -Number.MAX_SAFE_INTEGER)) >>> 0), Math.fround((Math.fround(( - (y >>> 0))) + Math.fround(0))))), (Math.ceil(mathy1((Math.atan2((( + Math.pow(( + -1/0), ( + y))) >>> 0), (y >>> 0)) >>> 0), ( ~ Math.sign(( + mathy0(Math.fround(x), ( + y))))))) >>> 0)); }); testMathyFunction(mathy2, [0x100000001, Number.MAX_VALUE, -(2**53-2), 0x100000000, 1/0, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, 1.7976931348623157e308, 2**53+2, 0x080000001, 0, Math.PI, -Number.MIN_VALUE, 42, 0.000000000000001, -0x100000001, -0x07fffffff, -0x080000001, 1, -0x0ffffffff, -0x100000000, 2**53, 0/0, Number.MIN_SAFE_INTEGER, -0x080000000, -0, -1/0, 0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=548; tryItOut("/*hhh*/function brtvdr(x, x, x, x, x, x, c, e, x, x, x, b, e, x, w, x, \u3056, w, z, x, w, x, x, x, x = \u3056, b, a, z, x =  /x/g , x, b = x, x, d, x, getter, b, eval, x, e, x = \"\\uD2CE\", a, x, x, \u3056, d, x, b, x, x = false, e, window, e, x){(void schedulegc(g0))}brtvdr((4277).cosh());");
/*fuzzSeed-42369751*/count=549; tryItOut("a2.valueOf = undefined;");
/*fuzzSeed-42369751*/count=550; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.clz32(Math.fround((( ! (((((( ! x) | 0) ? Math.hypot(((x === 1.7976931348623157e308) >>> 0), ( + y)) : (2**53+2 + Math.sqrt(x))) >>> 0) | 0) ^ ( ! Math.fround((x || 42))))) >>> 0))); }); testMathyFunction(mathy4, [undefined, (function(){return 0;}), '0', false, true, (new Boolean(true)), (new String('')), null, 0, -0, '\\0', NaN, [0], 0.1, (new Boolean(false)), 1, (new Number(-0)), /0/, ({valueOf:function(){return '0';}}), [], ({toString:function(){return '0';}}), '', (new Number(0)), ({valueOf:function(){return 0;}}), '/0/', objectEmulatingUndefined()]); ");
/*fuzzSeed-42369751*/count=551; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"^\", \"gym\"); var s = \"\"; print(s.replace(r, function(y) { return allocationMarker() })); ");
/*fuzzSeed-42369751*/count=552; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=553; tryItOut("Array.prototype.shift.call(a0, b2, h0, s2, i2, b0);");
/*fuzzSeed-42369751*/count=554; tryItOut("\"use asm\"; yield;(void schedulegc(g2));");
/*fuzzSeed-42369751*/count=555; tryItOut("/*oLoop*/for (var unmfuw = 0; unmfuw < 39; ++unmfuw) { const v0 = g2.eval(\"mathy4 = (function(x, y) { return (Math.min(Math.tanh(mathy0(mathy1(y, x), ((Math.fround((y && (x | 0))) , mathy0((y | 0), y)) >>> 0))), ( + (Math.max(((Math.sinh(x) ? y : Math.acosh(1)) >>> 0), Math.pow(( + mathy1(Math.fround(Math.max(Math.fround(y), Math.fround(y))), (y < 0x07fffffff))), ( + y))) >>> 0))) | 0); }); testMathyFunction(mathy4, [0x0ffffffff, 2**53, -Number.MIN_VALUE, 0x100000000, -0x100000001, 2**53+2, 1, 0x080000000, -(2**53-2), 0/0, 0.000000000000001, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, 42, 1/0, -(2**53), Number.MIN_VALUE, -0, -0x080000000, -0x07fffffff, 0, 1.7976931348623157e308, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, 2**53-2, -1/0, 0x100000001, Number.MAX_VALUE]); \"); } ");
/*fuzzSeed-42369751*/count=556; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(mathy1(((Math.fround(( + Math.fround((Math.fround(Math.fround(mathy0(Math.fround(x), Math.fround(((x | 0) >= x))))) > Math.fround(Math.hypot(1/0, mathy0(Math.atanh(x), y))))))) | Math.fround(mathy0(Math.fround(y), 2**53-2))) >>> 0), Math.fround(((x < y) + Math.atan2(Math.fround(mathy2((Math.atan2(Math.fround(0x100000000), ( - 0x07fffffff)) >>> 0), (Number.MIN_VALUE >>> 0))), Math.fround(Math.atan2(((y | 0) !== (x | 0)), x))))))); }); testMathyFunction(mathy3, [-0, -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 0/0, 0.000000000000001, -0x100000001, 2**53, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, -1/0, -0x0ffffffff, 2**53+2, -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, 1, 0x07fffffff, -0x080000000, 0, 1/0, 42, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=557; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.hypot(( + ( ! Math.log1p(Math.cbrt(( + ((Math.imul((Math.log(x) | 0), ((Math.fround(0.000000000000001) ? 2**53 : Math.fround(x)) | 0)) | 0) | 0)))))), mathy3(Math.tanh(Math.atan2((( - y) >>> 0), (Math.hypot(y, y) >>> 0))), Math.fround(Math.log2(mathy0(Math.abs(y), Math.ceil(y))))))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 0/0, -(2**53+2), 42, 0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 1/0, 2**53, -0x100000001, -0x07fffffff, 0, 2**53-2, -0x080000000, Math.PI, -1/0, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, -Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, 1, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -0, -Number.MAX_VALUE, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-42369751*/count=558; tryItOut("/*oLoop*/for (var nolzur = 0,  /x/g ; nolzur < 23; ++nolzur) { L:if((x % 5 != 0)) s1 += 'x'; } ");
/*fuzzSeed-42369751*/count=559; tryItOut("\"use strict\"; m0.get(t1);");
/*fuzzSeed-42369751*/count=560; tryItOut("\"use strict\"; v1 = b1.byteLength;");
/*fuzzSeed-42369751*/count=561; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=562; tryItOut("\"use strict\"; with({b: x}){delete o1.h1.delete; }");
/*fuzzSeed-42369751*/count=563; tryItOut("\"use strict\"; f1 = x;");
/*fuzzSeed-42369751*/count=564; tryItOut("mathy0 = (function(x, y) { return (( + (( + Math.log1p(( + x))) - Math.acosh((x | x)))) , (((y == (0/0 | 0)) << (( - ( + Math.max(( + -Number.MAX_VALUE), ( + Math.max(x, y))))) | 0)) / (((( ~ Math.atan2(x, (Math.fround((y != y)) === Math.fround((Math.fround(y) ? ( + Number.MIN_VALUE) : Math.fround(y)))))) | 0) | (Math.fround(Math.log2(((Math.fround((Math.asin((2**53 | 0)) | 0)) >>> 0) >>> 0))) | 0)) | 0))); }); testMathyFunction(mathy0, [0x100000001, 0x07fffffff, 0x080000000, 0, 2**53+2, 0x100000000, 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, 1.7976931348623157e308, 0.000000000000001, -Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, 0x080000001, -Number.MAX_VALUE, 2**53-2, -0x07fffffff, -0, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -0x080000001, -0x0ffffffff, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -0x100000000, 2**53, -(2**53+2), Math.PI]); ");
/*fuzzSeed-42369751*/count=565; tryItOut("eval(\"(uneval(({})))\");");
/*fuzzSeed-42369751*/count=566; tryItOut("v2 = false;");
/*fuzzSeed-42369751*/count=567; tryItOut("mathy3 = (function(x, y) { return Math.imul((Math.cbrt(( + Math.imul((( + ( - ((Math.round(Math.fround(x)) | 0) >>> 0))) >>> 0), ((Math.round((Math.hypot((x | 0), y) | 0)) | 0) | 0)))) | 0), Math.fround(( + (( + (Math.atan2((Math.min(0/0, (1/0 | 0)) >>> 0), (Math.asinh(Math.max(x, x)) >>> 0)) >>> 0)) << ( + mathy1(Math.fround(((Math.hypot(Math.fround(x), (Math.asinh((Math.fround(-(2**53)) ** (x >>> 0))) | 0)) | 0) == Math.fround((x ^ (Math.fround(( ! Math.fround(( ~ x)))) | 0))))), ( + ( - ( + x))))))))); }); testMathyFunction(mathy3, [-(2**53), 0, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), 1/0, -0, 0.000000000000001, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0x0ffffffff, -(2**53-2), 42, 0x100000000, 1.7976931348623157e308, -0x100000001, 2**53, 0x080000001, Number.MAX_VALUE, -0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, 1, 0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-42369751*/count=568; tryItOut("a0.sort((function mcc_() { var rzwxyc = 0; return function() { ++rzwxyc; f0(true);};})());");
/*fuzzSeed-42369751*/count=569; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return (( - (Math.min(mathy2(((((y | 0) << ((x == y) | 0)) | 0) >>> y), (Math.hypot(y, ( ! -0x080000001)) >>> 0)), (Math.atan2(x, ((( - ((x << y) | 0)) | 0) / x)) & (0/0 < (Math.expm1((x >>> 0)) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy4, [true, (new Boolean(true)), (function(){return 0;}), 0.1, [], 0, 1, '\\0', undefined, -0, (new Boolean(false)), '/0/', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), null, (new String('')), [0], '0', ({valueOf:function(){return '0';}}), (new Number(-0)), false, NaN, (new Number(0)), '', objectEmulatingUndefined(), /0/]); ");
/*fuzzSeed-42369751*/count=570; tryItOut("testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, -Number.MIN_VALUE, -(2**53), 42, Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, 1, 0x100000000, 1/0, -0, -0x080000001, Math.PI, 1.7976931348623157e308, 0.000000000000001, 0x0ffffffff, 2**53+2, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, 0x080000001, -(2**53+2), 2**53-2, -0x100000001, -0x07fffffff, -0x080000000]); ");
/*fuzzSeed-42369751*/count=571; tryItOut("mathy0 = (function(x, y) { return (( + Math.fround((Math.fround((Math.fround(x) | Math.fround(y))) ** Math.fround((Math.imul(Math.fround((Math.hypot(Math.hypot(( + Math.PI), x), ((x | 0) / ( + Math.exp(Math.fround(Number.MIN_VALUE))))) | 0)), Math.fround(y)) | 0))))) ? (Math.max((y - ((Math.clz32(((Math.fround(x) >> x) | 0)) >>> 0) | 0)), ( + Math.imul((((((y + (x | 0)) | 0) <= (Math.fround(( + y)) >>> 0)) >>> 0) | 0), (Math.fround(( + ((x ^ Math.fround(Math.acos(( + ( ~ Number.MAX_VALUE))))) >>> 0))) | 0)))) | 0) : ( + Math.fround(Math.hypot(Math.fround(( + Math.ceil(y))), (( - ((((Math.cosh(( + Math.atanh(( + x)))) | 0) << (-0x100000001 | 0)) | 0) | 0)) | 0))))); }); testMathyFunction(mathy0, [(function(){return 0;}), /0/, (new Boolean(false)), NaN, true, (new Number(-0)), (new String('')), [], ({valueOf:function(){return 0;}}), '\\0', 1, '0', null, ({valueOf:function(){return '0';}}), [0], false, 0.1, objectEmulatingUndefined(), '/0/', ({toString:function(){return '0';}}), -0, (new Boolean(true)), 0, (new Number(0)), '', undefined]); ");
/*fuzzSeed-42369751*/count=572; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?!(((?=\\W)|[\u0098\\?-\\uBB0C\\x48\\d]))+)(?=(?!(?!\\\u00f1)^{1,4}))|[^]|\uf9ba)+?/m; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=573; tryItOut("p2.__iterator__ = this.f1;");
/*fuzzSeed-42369751*/count=574; tryItOut("o2.v0 = true;");
/*fuzzSeed-42369751*/count=575; tryItOut("t1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 68719476737.0;\n    var i3 = 0;\n    var d4 = 18014398509481984.0;\n    var i5 = 0;\n    return +((-4.722366482869645e+21));\n  }\n  return f; });");
/*fuzzSeed-42369751*/count=576; tryItOut("/*RXUB*/var r = new RegExp(\"((\\\\2)(?:\\\\b*?)+|[^]|(?!\\\\D)(?=.)+?(?!\\\\B)+)\", \"\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); \ni1 + h0;\n");
/*fuzzSeed-42369751*/count=577; tryItOut("\"use strict\"; /*oLoop*/for (vznngb = 0; vznngb < 15; ++vznngb) { Array.prototype.pop.apply(a1, [o1.g1.v0, m0, this.p0]); } ");
/*fuzzSeed-42369751*/count=578; tryItOut("\"use strict\"; adrkka([(() =>  { return this } .prototype ^= x)], (new Uint8Array(x, null)));/*hhh*/function adrkka(){--x;}");
/*fuzzSeed-42369751*/count=579; tryItOut("\"use strict\"; Array.prototype.push.call(a0, arguments.callee.caller.caller.arguments = x, t0, a2, (4277));");
/*fuzzSeed-42369751*/count=580; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ (Math.clz32((Math.fround(Math.atan2(Math.fround(0.000000000000001), Math.fround(y))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[false, NaN, false, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, false, NaN, false, NaN, false, NaN, false, false, false, false, NaN, NaN, false, NaN, NaN, NaN, false, false, NaN, NaN, false, false, NaN, false, NaN, false, false, NaN, NaN, NaN, false, false, false, false, NaN, NaN, false, false, false, false, false, false, false, false, NaN, false, false, NaN, NaN, NaN, false, NaN, NaN, NaN, NaN, false, NaN, NaN, NaN, NaN, false, false, NaN, NaN, false, NaN, NaN, false, false, NaN, NaN, NaN, false, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, false, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, false, NaN, NaN, false, false, false, NaN, false, false, false, false, NaN, false, false, NaN, false, false, false, false, false, false, false, false, false, false, false, false, NaN, false, false, false, false, false, false, false, false, false, false, false, false, false, NaN, NaN, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, NaN]); ");
/*fuzzSeed-42369751*/count=581; tryItOut("v1 = evalcx(\"const a1 = [];\", g2);");
/*fuzzSeed-42369751*/count=582; tryItOut("testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -0x07fffffff, 0x07fffffff, 0x100000000, 2**53-2, 0, -Number.MIN_VALUE, 1, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, 1.7976931348623157e308, Math.PI, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 0x080000000, -(2**53), -0x080000001, -0x100000001, -(2**53+2), -0, 2**53, 0.000000000000001, 2**53+2, -(2**53-2), -0x080000000, -0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=583; tryItOut("a0.unshift(h0);");
/*fuzzSeed-42369751*/count=584; tryItOut("m0.delete(this.i1);function x(c = \"\\u9808\", w, NaN, b, a = 28, x, x, x, ...x) { return [,] } (function ([y]) { })();");
/*fuzzSeed-42369751*/count=585; tryItOut("f1 + '';");
/*fuzzSeed-42369751*/count=586; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.min((Math.cosh((((Math.atan2(((mathy1(( + x), ( + Math.log1p((x | 0)))) | 0) | 0), ( + ( - x))) | 0) && (((x | 0) < x) | 0)) >>> 0)) | 0), ( + Math.fround(Math.cbrt(Math.fround(mathy2(mathy1(x, Math.fround((Math.imul((x | 0), x) * Math.atan2(x, x)))), Math.fround(( + ( ~ Math.pow(y, y)))))))))) | 0); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, Math.PI, 0x0ffffffff, -0x080000001, -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 1.7976931348623157e308, -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 0/0, -0x080000000, 0x07fffffff, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, 0x080000001, -1/0, -0x100000001, 0x100000001, Number.MAX_VALUE, -(2**53-2), -Number.MIN_VALUE, 0x080000000, 42, 1/0, -0, Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-42369751*/count=587; tryItOut("v0 = evalcx(\"/*RXUE*/new RegExp(\\\".|(?:\\\\\\\\B+)+?\\\\\\\\3+{4,}\\\\\\\\s|\\\\\\\\W[\\\\u00e6-\\\\\\\\u00FA]$\\\\\\\\b+$+\\\", \\\"ym\\\").exec(\\\"\\\\na a \\\\naa a \\\\naa a \\\\na\\\\u1c561\\\\n\\\\u1c561\\\\naaa a \\\\naa a \\\\naa a \\\\na\\\\u1c561\\\\n\\\\u1c561\\\\naaj\\\\na\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na a\\\\n\\\\n\\\\u5382 \\\\na aa\\\\u00f6\\\\n\\\\u6a23\\\\n;^A\\\\u00f6\\\\n\\\\u6a23\\\\n;^A\\\\u00f6\\\\n\\\\u6a23\\\\n;^Ab\\\\n\\\\u008d\\\")\", g2);");
/*fuzzSeed-42369751*/count=588; tryItOut("/*tLoop*/for (let x of /*MARR*/[(-1/0), 0x99, (-1/0), length, new Boolean(false), new Boolean(false), 0x99, 0x99, (-1/0), 0x99, (-1/0), (-1/0), 0x99, new String(''), new String(''), length, 0x99, (-1/0), 0x99, 0x99, new Boolean(false), 0x99, length, length, new String(''), length, new Boolean(false), 0x99, length, length, 0x99, (-1/0), 0x99, new Boolean(false), new String(''), new Boolean(false), 0x99, length, new Boolean(false), 0x99, new String(''), length, new String(''), 0x99]) { /* no regression tests found */ }");
/*fuzzSeed-42369751*/count=589; tryItOut("testMathyFunction(mathy3, [0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE, -(2**53+2), 0, 1/0, 42, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -(2**53), -0x080000000, 0/0, -1/0, 0x0ffffffff, 0x100000001, -0, -(2**53-2), 0.000000000000001, -0x100000001, Number.MIN_VALUE, 0x100000000, -0x07fffffff, -0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=590; tryItOut("\"use strict\"; delete h2.getPropertyDescriptor;\na0[11] = o2.h2;\n");
/*fuzzSeed-42369751*/count=591; tryItOut("\"use strict\"; i2.send(o0);");
/*fuzzSeed-42369751*/count=592; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -3.094850098213451e+26;\n    var i3 = 0;\n    {\n      i3 = (0x98cd6d);\n    }\n    d2 = (d1);\n    {\n      d1 = (NaN);\n    }\n    return ((((((-72057594037927940.0)) - ((-1.5))) == (((+/*FFI*/ff()) == (((274877906943.0)) / ((-72057594037927940.0)))) ? (36893488147419103000.0) : (d1)))-(i3)+(0xc1b92393)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, -(2**53), -(2**53+2), 0x0ffffffff, -0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -Number.MIN_VALUE, 0/0, 0.000000000000001, 2**53-2, 1/0, -0x0ffffffff, 0x080000000, -0x100000000, -0x100000001, 0x07fffffff, -0x080000000, 42, -0x07fffffff, 0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53, Number.MIN_VALUE, 2**53+2, -1/0, -Number.MAX_VALUE, -0x080000001, 0x100000001]); ");
/*fuzzSeed-42369751*/count=593; tryItOut("testMathyFunction(mathy2, [-0x080000001, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -1/0, 0, -0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, 0/0, 2**53+2, 0x0ffffffff, 1.7976931348623157e308, 0x080000000, 0x100000000, -0x100000000, -0x100000001, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, 1, 0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, -0, 2**53, 42, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-42369751*/count=594; tryItOut("\"use strict\"; v0 = (4277);");
/*fuzzSeed-42369751*/count=595; tryItOut("\"use strict\"; v1 = (this.b2 instanceof i0);");
/*fuzzSeed-42369751*/count=596; tryItOut("\"use strict\"; var ogsafd = new SharedArrayBuffer(2); var ogsafd_0 = new Uint32Array(ogsafd); ogsafd_0[0] = -21; print(ogsafd_0[0]);function x(x, x, ...window) { yield ((uneval(x))) } a0 = a2.slice(9, 7);");
/*fuzzSeed-42369751*/count=597; tryItOut("s0 = Array.prototype.join.call(a0, g1.o1.f0, h2);");
/*fuzzSeed-42369751*/count=598; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"\\\"use strict\\\"; mathy4 = (function(x, y) { \\\"use strict\\\"; return Math.fround(Math.hypot(Math.fround((Math.max(Math.fround(Math.min((Math.sin(( ~ x)) | 0), Math.sqrt((Math.atan2((x | 0), Math.fround(((y >>> (Math.atanh(x) >>> 0)) >>> 0))) | 0)))), (x !== Math.fround(Math.sqrt(Math.fround(Math.fround(Math.imul(Math.fround(y), ( + (x / Math.fround(y)))))))))) | 0)), Math.fround(Math.min(( + ( ~ y)), (Math.atan2(((((x | 0) - (Math.fround(( ~ x)) & x)) | 0) >>> 0), ((Math.min(1, ( + ( + (((((x >>> 0) ? (0 >>> 0) : (y >>> 0)) >>> 0) | 0) | Math.pow((x | 0), y))))) >>> 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy4, [-(2**53-2), 0, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, -0x080000001, 2**53, 1, -Number.MAX_VALUE, 0/0, 0x080000001, 0x07fffffff, 0x100000000, 1.7976931348623157e308, 2**53-2, -1/0, 0x100000001, 1/0, Number.MIN_VALUE, 0x080000000, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 42, -Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, Math.PI, -0x0ffffffff]); \");");
/*fuzzSeed-42369751*/count=599; tryItOut("/*oLoop*/for (zlfqia = 0; zlfqia < 97; ++zlfqia) { v1 = (m1 instanceof g0.g1.h0); } ");
/*fuzzSeed-42369751*/count=600; tryItOut("t1[3] = e;");
/*fuzzSeed-42369751*/count=601; tryItOut("\"use strict\"; /*RXUB*/var r = \"\\u5F19\"; var s = \"\"; print(r.exec(s)); print(r.lastIndex); g2.v1 = g1.eval(\"h0 = g0.t1[13];\");");
/*fuzzSeed-42369751*/count=602; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), 2**53, objectEmulatingUndefined(), new Number(1.5), 2**53, new Number(1.5), 2**53, 2**53, 2**53, 2**53, 2**53, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 2**53, 2**53, new Number(1.5), 2**53, new Number(1.5), objectEmulatingUndefined(), 2**53, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5)]) { /*MARR*/[y, y, new String(''), new String(''), new String(''), y, new String(''), new String(''), y, y, y, y, y, new String(''), y, y, y, new String(''), new String(''), new String(''), new String(''), y, new String(''), new String(''), new String(''), new String(''), y, y, y, y, y, y, new String(''), new String(''), new String(''), new String(''), y, y, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), y, new String(''), new String(''), y, y, y, y, new String(''), y, y, new String(''), new String(''), new String(''), y, new String(''), y, new String(''), new String(''), y, new String(''), y, new String(''), y, new String(''), y, new String(''), new String(''), y, new String(''), new String(''), y, new String(''), y, y, y, y, new String(''), new String(''), new String(''), y, new String(''), new String(''), new String(''), new String(''), y, y, y, y, new String(''), new String(''), y, new String(''), y, new String(''), y, y, y, y, y, y, y, y, new String(''), new String(''), new String(''), y, y, new String(''), y, y, y, new String(''), y, new String(''), y, y, new String(''), new String(''), new String(''), new String(''), y, new String(''), y, new String(''), new String(''), y].map(function(q) { return q; });//h\n }");
/*fuzzSeed-42369751*/count=603; tryItOut("mathy1 = (function(x, y) { return ( - (((Math.atan2((Math.sin((x | 0)) | 0), (( + Math.hypot(( + Math.trunc(((( + ( + x)) >>> 0) ^ Math.fround(Math.round(x))))), ( + mathy0(y, x)))) >>> 0)) | 0) & (((x << x) ? x : (Math.round(( + x)) | 0)) | 0)) | 0)); }); ");
/*fuzzSeed-42369751*/count=604; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(Math.exp(y)) === Math.atanh(( - Math.pow(Math.atan2(y, x), ((x ? (y >>> 0) : Math.hypot((( ! (y >>> 0)) >>> 0), y)) >>> 0))))); }); ");
/*fuzzSeed-42369751*/count=605; tryItOut("\"use strict\"; /*iii*/print((a = ({})));/*hhh*/function ikahhq(x, x, y = [], z, z, eval, d, x, window, arguments, x = window, \u3056, x, x, x, d, yield = -23, c = \"\\uEF83\", z, window, y, b = \"\\uD164\", x = this, \u3056, x, y, x, c, a, w, x, x, x, b, a, \u3056, x = x, window, c, NaN, window =  \"\" , x, window, x, b = false, x =  \"\" , let, x = /*MARR*/[objectEmulatingUndefined(),  \"\" ], x = -28, eval, c, a, window, c =  \"\" , e, x, y, z, x, w, \"17\", x, b = \"\\u93A3\", window = window, w, NaN, eval =  /x/g , x, window, w){a2.forEach(f2, t1);}");
/*fuzzSeed-42369751*/count=606; tryItOut("v0 = this.g0.r0.multiline;");
/*fuzzSeed-42369751*/count=607; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x07fffffff, -Number.MIN_VALUE, -1/0, Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 2**53-2, Number.MIN_VALUE, -0x080000000, 2**53+2, 0x080000001, 42, -0x100000001, Number.MAX_VALUE, 0, 0/0, 1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, 0x100000000, 0x0ffffffff, -0x080000001, -(2**53), -(2**53-2), -Number.MIN_SAFE_INTEGER, -0, 0x080000000, -Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-42369751*/count=608; tryItOut("\"use strict\"; if(x) { if (x) s2 += 'x'; else v1 = o2.g0.eval(\"\\\"use strict\\\"; delete h2.getPropertyDescriptor;\");}");
/*fuzzSeed-42369751*/count=609; tryItOut("x = \"\\u8880\";");
/*fuzzSeed-42369751*/count=610; tryItOut("\"use strict\"; v1 = evaluate(\"\\\"\\\\u62E1\\\"\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 4), noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-42369751*/count=611; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-42369751*/count=612; tryItOut("s1.__proto__ = t1;");
/*fuzzSeed-42369751*/count=613; tryItOut("a2 + g1;");
/*fuzzSeed-42369751*/count=614; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s0; print(r.test(s)); ");
/*fuzzSeed-42369751*/count=615; tryItOut("g1.offThreadCompileScript(\"\\\"use strict\\\"; a1.reverse(p0);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: (x % 22 == 13), sourceIsLazy: ({x: (4277)}), catchTermination: true }));");
/*fuzzSeed-42369751*/count=616; tryItOut("\"use strict\"; p0 + this.h0;");
/*fuzzSeed-42369751*/count=617; tryItOut("var fpvjcg = new ArrayBuffer(2); var fpvjcg_0 = new Uint32Array(fpvjcg); print(fpvjcg_0[0]); fpvjcg_0[0] = 12; var fpvjcg_1 = new Uint32Array(fpvjcg); fpvjcg_1[0] = 29; var fpvjcg_2 = new Uint16Array(fpvjcg); fpvjcg_2[0] = 16; {}for (var v of t2) { t1 = new Uint16Array(g0.a2); }z;");
/*fuzzSeed-42369751*/count=618; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=619; tryItOut("\"use strict\"; h2 + this.b1;");
/*fuzzSeed-42369751*/count=620; tryItOut("print((4277));with({z: (delete a.e)})a1 = arguments.callee.arguments;");
/*fuzzSeed-42369751*/count=621; tryItOut("switch(x) { default: s2 += s0;case this.__defineGetter__(\"d\", (q => q)()): break; case y = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: undefined, defineProperty: (yield (void shapeOf(delete w.c))), getOwnPropertyNames: function() { throw 3; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(x), ((4277) <= (NaN -= a))): const e = x;for([e, z] = new RegExp(\".{4,4}(?:(?:[^])*)\", \"ym\") in (timeout(1800))) /[^\u4263]/yim;\nv1.valueOf = (function() { h2.set = (function mcc_() { var ketefa = 0; return function() { ++ketefa; f1(/*ICCD*/ketefa % 6 == 0);};})(); return i0; });\ncase 4: /*RXUB*/var r = new RegExp(\"[^\\\\\\\\-\\u0ecd\\\\cH](?!(?!(?=\\\\s))\\\\u005B.)|\\\\3+?[\\\\xEf-\\\\u2C2F\\\\u6092]{2,3}\", \"gy\"); var s = \"\"; print(r.test(s)); case (Math.min(1491792140.5, 25)): break;  }");
/*fuzzSeed-42369751*/count=622; tryItOut("\"use asm\"; g1 + '';");
/*fuzzSeed-42369751*/count=623; tryItOut("\"use strict\"; /*MXX1*/o2 = g1.RegExp.$*;");
/*fuzzSeed-42369751*/count=624; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.round(mathy0((( + ( + (Math.acosh((x >>> 0)) >>> 0))) >>> 0), (mathy2(x, x) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[true, true, Infinity, Infinity, true, -Infinity, -Infinity, true, Infinity, Infinity, Infinity, true, Infinity, Infinity, -Infinity, Infinity, true, -Infinity, true, -Infinity, true, true, -Infinity, true, true, true, true, true, true, true, true, true, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, Infinity, true, true, Infinity, true, -Infinity, true, Infinity, true, true, Infinity, -Infinity, -Infinity, Infinity, true, -Infinity, Infinity, -Infinity, -Infinity, Infinity, true, -Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, true, Infinity, Infinity, -Infinity, -Infinity, Infinity, Infinity, true, true, true, true, -Infinity]); ");
/*fuzzSeed-42369751*/count=625; tryItOut("mathy0 = (function(x, y) { return Math.min(( + (( + Math.pow(2**53+2, y)) * (Math.pow(y, Math.fround(0x080000000)) ? ( + (x | 0)) : Math.fround((y ? Math.imul(Math.max(y, x), y) : y))))), (Math.min((Math.fround(( ! Math.fround((Math.hypot((y | 0), x) | 0)))) >>> 0), Math.hypot(Math.fround(Math.min(Math.max(x, y), -0x100000001)), ( ~ 2**53+2))) + ( + ( ! (( ~ x) >>> 0))))); }); testMathyFunction(mathy0, [-1/0, -0x080000000, -0x100000001, -(2**53+2), 2**53, -0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x080000001, 0.000000000000001, 2**53-2, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 1, 0/0, 42, Math.PI, -0x07fffffff, -0, Number.MAX_VALUE, 0, 0x100000000, -(2**53-2), -0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=626; tryItOut("v0 = Object.prototype.isPrototypeOf.call(p2, p0);");
/*fuzzSeed-42369751*/count=627; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.sinh((Math.expm1(Math.fround(Math.log2(Math.fround(y)))) | 0))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, Math.PI, -0x07fffffff, 42, -0x100000001, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, 2**53-2, 2**53, 0/0, Number.MIN_SAFE_INTEGER, 0x080000001, 0x080000000, -0, 0, -0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, 1, 0.000000000000001, -1/0, -0x080000001, -(2**53)]); ");
/*fuzzSeed-42369751*/count=628; tryItOut("\"use strict\"; m2.has(o2);");
/*fuzzSeed-42369751*/count=629; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[ /x/g , false,  '' ,  /x/g ,  /x/g ,  /x/ ,  /x/ ,  /x/ ,  '' ,  /x/g ,  '' , false,  /x/g ,  /x/ ,  /x/g ,  /x/ , false, false,  '' ,  '' , false,  /x/g ,  '' ]) { g1 = this; }");
/*fuzzSeed-42369751*/count=630; tryItOut("{selectforgc(o1); }");
/*fuzzSeed-42369751*/count=631; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.abs(( + Math.acosh((Math.cosh(( + ( - (((x | 0) ^ (y | 0)) | 0)))) | 0)))); }); testMathyFunction(mathy1, [-(2**53), -0x080000000, 2**53+2, 0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 1, 2**53, 2**53-2, 42, -0, -0x100000000, -0x100000001, Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff, 0x0ffffffff, -(2**53-2), 0x080000001, 1.7976931348623157e308, -0x080000001, 1/0, -1/0]); ");
/*fuzzSeed-42369751*/count=632; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min(((((Math.pow((Math.max(Math.imul((( ~ x) >>> 0), (( - (y >>> 0)) >>> 0)), ( + Math.log(( + y)))) | 0), ( + (Math.pow((Math.sin(y) >>> 0), (Math.fround((( + Math.atan2(x, y)) , Math.fround(x))) >>> 0)) >>> 0))) >>> 0) >= (((y >>> 0) <= ((-0 * y) >>> 0)) >>> 0)) >>> 0) * Math.fround(Math.sign((Math.atan(( + y)) >>> 0)))), ( + (( ~ ( ~ ( ~ Math.atan(( - x))))) | 0))); }); ");
/*fuzzSeed-42369751*/count=633; tryItOut("\"use strict\"; a1.shift();");
/*fuzzSeed-42369751*/count=634; tryItOut("o2.t2.set(t1, 4);");
/*fuzzSeed-42369751*/count=635; tryItOut("s2 = t0[18];");
/*fuzzSeed-42369751*/count=636; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.asinh(Math.fround(( + Math.cosh(0x100000000))))); }); testMathyFunction(mathy4, /*MARR*/[function(){}, new Boolean(true), function(){}, function(){}, new Boolean(true), function(){}, function(){}, function(){}, new Boolean(true), new Boolean(true), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-42369751*/count=637; tryItOut("mathy1 = (function(x, y) { return (( + (Math.fround(Math.min(Math.fround((((x >>> 0) ? (((-0x080000000 & (y | 0)) | 0) >>> 0) : (Math.asinh((x | 0)) | 0)) >>> 0)), Math.fround(( ~ x)))) | mathy0(Math.fround(( - x)), Math.sin(Math.fround(mathy0(x, 0x0ffffffff)))))) >>> 0); }); ");
/*fuzzSeed-42369751*/count=638; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-42369751*/count=639; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=640; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Uint16ArrayView[(((~((0xfc8e0be4))) < (abs((((0x28f5094f)) ^ ((0xf933de74))))|0))-((0xffffffff) ? ((-0x8000000)) : (0xffffffff))-((((-0x8000000))>>>((0xffffffff))) != (0x259cae11))) >> 1]) = ((/*FFI*/ff(((d1)), ((NaN)), ((+(0.0/0.0))))|0)*0xca639);\n    d1 = (d0);\n    d0 = (+(1.0/0.0));\n    {\n      d0 = (d1);\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var ndiwvq = (makeFinalizeObserver('tenured')); var ammrsv = (Boolean).call; return ammrsv;})()}, new ArrayBuffer(4096)); ");
/*fuzzSeed-42369751*/count=641; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + Math.fround(( ! Math.fround(((x > Math.fround(( + ( + y)))) && x))))) > ( + ( + (Math.round(x) !== Math.fround(Math.log1p(Math.fround(( - Math.fround(((((Math.fround(( ~ Math.fround(-Number.MIN_VALUE))) / -(2**53)) | 0) <= (y | 0)) | 0))))))))))); }); testMathyFunction(mathy0, [-0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 0, -0x07fffffff, 0x100000001, Number.MIN_VALUE, Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, 2**53, -0x080000001, 1/0, 2**53-2, 0x080000000, 0.000000000000001, 1.7976931348623157e308, 1, -Number.MIN_VALUE, -0x100000000, 42, -1/0, -0x0ffffffff, -0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-42369751*/count=642; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-42369751*/count=643; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3?\", \"gi\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-42369751*/count=644; tryItOut("/*tLoop*/for (let w of /*MARR*/[4., 4., 4., 4., 4., [ \"\"  ==  \"\" ], new String('q'), 4., [ \"\"  ==  \"\" ], [ \"\"  ==  \"\" ], [ \"\"  ==  \"\" ], 4., [ \"\"  ==  \"\" ], 4., new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), 4., 4., new String('q'), [ \"\"  ==  \"\" ], new String('q'), [ \"\"  ==  \"\" ], new String('q'), new String('q'), new String('q'), 4., [ \"\"  ==  \"\" ], new String('q'), [ \"\"  ==  \"\" ], [ \"\"  ==  \"\" ], 4., new String('q'), new String('q'), [ \"\"  ==  \"\" ], 4., 4., new String('q'), [ \"\"  ==  \"\" ], 4., new String('q'), new String('q'), 4., [ \"\"  ==  \"\" ], new String('q'), 4., new String('q'), [ \"\"  ==  \"\" ], 4., new String('q'), 4., new String('q'), 4., 4., new String('q'), new String('q'), new String('q'), 4., new String('q'), [ \"\"  ==  \"\" ], 4., [ \"\"  ==  \"\" ], new String('q'), 4., new String('q'), 4., [ \"\"  ==  \"\" ], 4., [ \"\"  ==  \"\" ], 4., new String('q')]) { /*vLoop*/for (bibrok = 0; bibrok < 27; ++bibrok) { let a = bibrok; m2.set(t2, e2); }  }");
/*fuzzSeed-42369751*/count=645; tryItOut("/*RXUB*/var r = /((?:(\\1{0})))/gi; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-42369751*/count=646; tryItOut("\"use strict\"; /* no regression tests found */let z = (timeout(1800));");
/*fuzzSeed-42369751*/count=647; tryItOut("s0 += s2;");
/*fuzzSeed-42369751*/count=648; tryItOut("\"use strict\"; /*infloop*/for(let x = \"\\uD0D9\".unwatch(\"x\"); (null % 29); NaN ? eval : this) {print(x);print(-11); }");
/*fuzzSeed-42369751*/count=649; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(g1.o0.s1, \"x\", { configurable: false, enumerable: false, get: (function() { try { for (var v of t2) { try { /*MXX2*/g1.SharedArrayBuffer.prototype.slice = g0.s2; } catch(e0) { } for (var v of f2) { try { this.s2 += 'x'; } catch(e0) { } v2 = t1.BYTES_PER_ELEMENT; } } } catch(e0) { } Array.prototype.splice.apply(a2, [NaN, 1]); return a2; }), set: (function() { try { /*MXX3*/g0.WeakMap.prototype.get = this.g0.WeakMap.prototype.get; } catch(e0) { } try { for (var p in v1) { try { for (var p in s2) { Object.preventExtensions(v0); } } catch(e0) { } try { /*MXX3*/g1.Set.prototype.has = g2.Set.prototype.has; } catch(e1) { } e1 + ''; } } catch(e1) { } try { (void schedulegc(g0)); } catch(e2) { } Array.prototype.splice.call(this.a0, NaN, (Math.min(objectEmulatingUndefined(), new RegExp(\"(?=(?!(?:\\\\S+?))){2,}(?!$|(?!\\\\u33aD|\\\\d))|([\\\\n-\\\\0\\\\u0113-\\\\cU\\\\s]?)+|(\\\\w+?){1,2}\", \"y\"))), v0); return i1; }) });");
/*fuzzSeed-42369751*/count=650; tryItOut("\"use strict\"; let a = (x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: function(y) { \"use strict\"; return -3 }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: true, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })(/(?!\\x72[]{3,4})|\\w(?=\\S^\ubc92)+?{1,5}/im), String.prototype.search));arguments;");
/*fuzzSeed-42369751*/count=651; tryItOut("o0 + '';");
/*fuzzSeed-42369751*/count=652; tryItOut("Array.prototype.shift.call(a1);");
/*fuzzSeed-42369751*/count=653; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( + ((Math.max((y >= ((y ^ ( + y)) >>> 0)), Math.fround(y)) << Math.hypot(Math.pow(y, y), y)) >>> 0))) <= Math.pow(Math.pow(x, Math.pow(Math.fround(Math.cosh(( + ( ! ( + y))))), Math.fround(mathy2(Math.fround(y), Math.fround(Number.MIN_SAFE_INTEGER))))), mathy2((Math.round(((( + Math.fround(y)) | 0) >>> 0)) >>> 0), (y >>> 0))))); }); ");
/*fuzzSeed-42369751*/count=654; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2/gyi; var s = \"0\"; print(r.test(s)); ");
/*fuzzSeed-42369751*/count=655; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-42369751*/count=656; tryItOut("a0.reverse(e1);");
/*fuzzSeed-42369751*/count=657; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.pow((((( + (( + -0x100000000) % ( + this))) >>> 0) > (Math.acosh(( - ( - Math.fround((y % Math.round(y)))))) >>> 0)) >>> 0), Math.hypot(Math.fround(((Math.max(Math.fround((mathy0((x >>> 0), (x >>> 0)) >>> 0)), (( + (( - Math.fround(Math.hypot(x, y))) | 0)) | 0)) >>> 0) != ( + ((( ~ x) >>> 0) !== (Math.sqrt(y) >>> 0))))), (y || (((x | 0) >> (Number.MAX_VALUE | 0)) | 0)))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1), x, new Number(1), new Number(1), function(){}, function(){}, x,  '\\0' , function(){}, new Number(1), function(){}, x, x,  '\\0' , x, x,  '\\0' , new Number(1), new Number(1), new Number(1), function(){},  '\\0' , new Number(1), function(){},  '\\0' , function(){},  '\\0' , new Number(1), function(){}, x,  '\\0' ,  '\\0' , new Number(1),  '\\0' ,  '\\0' , x, function(){},  '\\0' ,  '\\0' ,  '\\0' , new Number(1), new Number(1), x, new Number(1), new Number(1), function(){}, function(){}, function(){}, x, x, x, function(){}, x, function(){}, x, function(){},  '\\0' , new Number(1), x, x, new Number(1),  '\\0' ,  '\\0' , x]); ");
/*fuzzSeed-42369751*/count=658; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.log10(( + Math.atan(Math.fround(( ~ ( + (Math.max(Math.round(( + -1/0)), (y ? (0x080000001 | 0) : y)) | 0)))))))); }); testMathyFunction(mathy1, [-0x100000000, -1/0, 0, 0x080000001, Math.PI, 0x100000001, 42, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, 2**53-2, 0x07fffffff, -(2**53-2), 1, -(2**53+2), -0x080000001, -0x080000000, -0x07fffffff, 2**53+2, 0x0ffffffff, Number.MAX_VALUE, 0x080000000, -(2**53), -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-42369751*/count=659; tryItOut("\"use strict\"; /*infloop*/for(w =  \"\" ; this; [1]) neuter(b1, \"change-data\");");
/*fuzzSeed-42369751*/count=660; tryItOut("\"use strict\"; g1.a1.unshift();");
/*fuzzSeed-42369751*/count=661; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atanh(Math.max(( + (Math.round((Math.min(x, (Math.exp(y) >>> 0)) >>> 0)) % (Math.fround(Math.log1p(x)) >>> 0))), (Math.sqrt(Math.fround(Math.acosh(( - x)))) >>> 0))) | 0); }); ");
/*fuzzSeed-42369751*/count=662; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=663; tryItOut("let ([] = (x < x), b = [], x = (4277), x = null, tvegvy, call = (4277), jlbpnj, lamxfr, x) {  for  each(let b in  '' ) { '' ;print(/[^]/gi); } }");
/*fuzzSeed-42369751*/count=664; tryItOut("\"use strict\"; o2.t0 = new Uint8Array(o0.b1, 8, (x) = (new OSRExit(this, \"\\u2B11\")));");
/*fuzzSeed-42369751*/count=665; tryItOut("\"use strict\";  for (let z of ((void options('strict_mode')))) {try { for(let b in []); } catch(c) { let(w) ((function(){this.i2 + '';})()); } finally { for(let c in /*FARR*/[, ...[], \"\\u897A\", , new RegExp(\"\\\\2\", \"gim\"), ...[], ...[], ...[], ]) Date.prototype.toLocaleDateString }  }");
/*fuzzSeed-42369751*/count=666; tryItOut("/*RXUB*/var r = /\\d\\s$|(\\S{3,})[\\xc7-\\S](?=\ubbd7{2,4}|[^]\\B)\\3(?:\\\u9008+\\b+{2})((?=e*))(^{3,})+?{0}/gim; var s = \"__1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa\\n\\n\\n\\u00e8__1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa1\\n aa\\n\\n\\n\\u00e8\"; print(s.match(r)); ");
/*fuzzSeed-42369751*/count=667; tryItOut("\"use strict\"; Array.prototype.push.call(o0.a0, g1.g2);");
/*fuzzSeed-42369751*/count=668; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -0x080000001, -0x080000000, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0x100000001, Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, 0x07fffffff, -(2**53-2), 0/0, -0x0ffffffff, -(2**53), 1, 0.000000000000001, 0x100000001, 0x080000001, 2**53+2, 1.7976931348623157e308, 0, 42, 0x080000000, -1/0, 1/0, -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=669; tryItOut("\"use strict\"; testMathyFunction(mathy0, [(new String('')), (function(){return 0;}), (new Number(0)), 0.1, (new Boolean(false)), null, [], 1, objectEmulatingUndefined(), [0], '\\0', '0', -0, '/0/', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Boolean(true)), undefined, (new Number(-0)), true, '', ({valueOf:function(){return '0';}}), 0, /0/, false, NaN]); ");
/*fuzzSeed-42369751*/count=670; tryItOut("mathy3 = (function(x, y) { return Math.min(Math.atan(( - Math.sin(0x07fffffff))), Math.ceil(( ! (-(2**53) == ( ~ 0x100000001))))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -(2**53-2), -0x080000001, Number.MAX_VALUE, 0x0ffffffff, -1/0, 0x100000000, -0, 0.000000000000001, 0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 0x080000000, -0x100000001, 0, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53, 0/0, Number.MIN_VALUE, 1, -Number.MAX_VALUE, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, 2**53+2, -0x0ffffffff, 1/0, 42, -0x080000000]); ");
/*fuzzSeed-42369751*/count=671; tryItOut("mathy3 = (function(x, y) { return ((mathy0((( - (Math.atan2((y | 0), ((Math.abs(x) >>> 0) | 0)) | 0)) >>> 0), ((( + Math.tan(x)) === Math.fround(x)) >>> 0)) >>> 0) ? (Math.exp((((((y | 0) ** (Math.max(Number.MIN_VALUE, Math.cosh(y)) | 0)) >>> 0) >= (y | 0)) >>> 0)) | 0) : ( + mathy2(Math.sqrt(( + mathy0(((( ! (y ? y : x)) | 0) >>> 0), y))), ( + Math.imul((( - (Math.pow(y, x) | 0)) >>> 0), x))))); }); ");
/*fuzzSeed-42369751*/count=672; tryItOut("for (var v of f0) { try { for (var v of g0) { try { v2 = true; } catch(e0) { } print(e1); } } catch(e0) { } try { let v2 = true; } catch(e1) { } try { t0 + this.b0; } catch(e2) { } h2.enumerate = f1; }s0.__iterator__ = DataView.prototype.getUint32.bind(h1);\nlet b =  '' ;/*RXUB*/var r = r1; var s = \"\\uac3f\\n\\u3a87\\n\\uac3f\\n\\u3a87\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); \n");
/*fuzzSeed-42369751*/count=673; tryItOut("/*infloop*/for(e = x instanceof a;  /x/g ; Math.cbrt(( + (Math.cbrt((Math.log10((Math.trunc((2**53+2 >>> 0)) >>> 0)) | 0)) | 0)))) {m0.get(this.a1);v0 = Object.prototype.isPrototypeOf.call(i2, b0); }");
/*fuzzSeed-42369751*/count=674; tryItOut("/*RXUB*/var r = new RegExp(\".\", \"g\"); var s = \"\\u3669\"; print(s.match(r)); ");
/*fuzzSeed-42369751*/count=675; tryItOut("this.g2.t1[({valueOf: function() { Array.prototype.forEach.apply(a1, [(function(j) { f2(j); }), this.g0.a1, t0, this.m2, this.g0.f0]);return 7; }})] = new RegExp(\"(?=(?=[^]+))*|\\\\x1E|(?:(?!(^+)))\\\\1|\\\\3\", \"y\");");
/*fuzzSeed-42369751*/count=676; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(( + Math.pow(( + ( ! Number.MAX_SAFE_INTEGER)), ( + Math.atan2(Math.pow(x, y), Math.hypot(Math.fround(( + Math.tanh(( + (1/0 | ( + Math.atan2(x, ( + y)))))))), Math.fround(Math.log1p(( + (x > ( + Math.asinh(x))))))))))), ( + Math.max(( + ( - ( + (Math.fround(Math.min(( + y), Math.fround(y))) ? y : (Math.sqrt((x >>> 0)) >>> 0))))), ((Math.fround(Math.fround(Math.imul(Math.fround((y != x)), Math.acos(x)))) * (Math.hypot((y | 0), (Math.max(x, Math.fround((y | y))) | 0)) | 0)) | 0)))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, -0x100000000, 1, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, 0/0, -0x100000001, -(2**53-2), 2**53-2, 2**53+2, -(2**53), -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 0, Number.MIN_VALUE, Math.PI, -1/0, 42, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -(2**53+2), 1/0, 0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=677; tryItOut("mathy1 = (function(x, y) { return (( ! (Math.min(Math.hypot(((x | 0) ^ Math.hypot(x, x)), (( + Math.cos(( + x))) | 0)), mathy0(Math.log10(x), ( ~ Math.acosh((y >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [0/0, 1/0, 0.000000000000001, 0x07fffffff, 1.7976931348623157e308, Math.PI, -0x07fffffff, 0x100000001, 0x080000001, -0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), 0x100000000, 0x0ffffffff, 2**53, -(2**53-2), 0x080000000, -(2**53), -0x100000001, -0, -0x080000000, -Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 1, 0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=678; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)))|0;\n    i1 = (!(/*FFI*/ff((((0x8dad413b)+(0x7c8b753a)+(i1))), (((((imul((i1), ((0xd36469e)))|0) == (((Int32ArrayView[4096])) | ((0xfb94bea3)+(0x46294e57)+(0xf98ca143))))-((0x2a044d3d)))|0)), (new RegExp(\"(?!\\\\S)\", \"im\") ^= c), ((((0xffeccbdd)) & ((i1)+(-0x8000000)))), ((0x7fffffff)))|0));\n    i1 = (i1);\n    return (((0xffffffff)+((0x2827ae05) ? (((-0xfffff*((0x45c6119a) == (0x58b449d))) | ((i1)))) : (i1))))|0;\n  }\n  return f; })(this, {ff: (new Function(\"s1 += s1;\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x080000001, 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, 42, 1/0, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, -Number.MIN_VALUE, 0, -Number.MAX_VALUE, -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -1/0, -(2**53), -0x080000000, 1, 2**53, Number.MAX_SAFE_INTEGER, -0, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=679; tryItOut("\"use strict\"; m1.set(t0, f2);");
/*fuzzSeed-42369751*/count=680; tryItOut("v2 = a2.reduce, reduceRight((function() { try { Array.prototype.shift.apply(a2, [t2, a0, o1, i1, v0, p2]); } catch(e0) { } g0.e2.has(o0.i2); return a0; }), h1, p2);");
/*fuzzSeed-42369751*/count=681; tryItOut("Array.prototype.forEach.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 4294967297.0;\n    var d6 = 8589934591.0;\n    var i7 = 0;\n    var i8 = 0;\n    var d9 = 8.0;\n    d1 = (-0.015625);\n    d9 = ((-((0x368b40c3) <= ((((((0x7d8a70d7))|0)))>>>((0xad266518)-(i0))))));\n    i7 = (i2);\n    return ((((0xd804d797) > (((i4)-(0xff1d9416))>>>(((0x260314a7) > (imul((i3), (0xa98a06f5))|0)))))+((0xde8df8e0))))|0;\n  }\n  return f; })]);");
/*fuzzSeed-42369751*/count=682; tryItOut("\"use strict\"; m2.set(g1.s0, e1);");
/*fuzzSeed-42369751*/count=683; tryItOut("yield -0;let(x) { x.stack;}");
/*fuzzSeed-42369751*/count=684; tryItOut("print(false);");
/*fuzzSeed-42369751*/count=685; tryItOut("/*vLoop*/for (let yuqkxq = 0; yuqkxq < 100; ++yuqkxq) { let z = yuqkxq; h2.defineProperty = f2; } ");
/*fuzzSeed-42369751*/count=686; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.pow(( + (Math.fround(((( ~ ( + (x >>> 0))) | 0) < Math.imul(( ! x), ( + Math.fround(((x >= x) !== Math.fround(Math.pow(x, x)))))))) <= Math.fround((mathy3(( + Math.max((0x07fffffff >>> 0), Math.fround(( ~ Math.fround(y))))), mathy0((Math.imul((Math.atan2(Math.max(1/0, x), 1.7976931348623157e308) >>> 0), (y | 0)) | 0), (( - ((Math.imul(0, ( - ( + 2**53+2))) >>> 0) >>> 0)) >>> 0))) >>> 0)))), ( + (((Math.fround(( ! (( + (y <= (mathy2(( + y), x) >>> 0))) | 0))) >>> 0) < ((Math.fround(Math.fround(((( ~ -Number.MAX_VALUE) >>> 0) * (Math.hypot(mathy1(x, x), (((x | 0) || (-0x080000001 | 0)) | 0)) | 0)))) - y) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0x100000001, -0x100000001, 2**53, -0, Number.MAX_VALUE, 1, 1/0, -Number.MIN_VALUE, -(2**53-2), -0x080000001, -Number.MAX_VALUE, 42, 2**53+2, 0x100000000, 0, -0x080000000, 0.000000000000001, 1.7976931348623157e308, Number.MIN_VALUE, -1/0, -(2**53+2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, -0x07fffffff, -0x100000000, 0/0]); ");
/*fuzzSeed-42369751*/count=687; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.tan(mathy1((((((Math.sin(Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround((Math.fround(x) ? Math.fround(x) : 0x080000001))))) | 0) ? (x | 0) : (y | 0)) | 0) ? ((y | 0) + ( + y)) : ((( ! (Math.sign(y) >>> 0)) >>> 0) | 0)) | 0), mathy1(Math.log2((x < ( ! y))), ( + Math.fround(x))))); }); testMathyFunction(mathy2, [-0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 1, Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, 0x080000001, 0x100000001, Math.PI, 2**53, 0x080000000, -0x100000000, -(2**53), -0x080000000, 42, 0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, 0/0, 0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, 1.7976931348623157e308, -(2**53-2), -0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=688; tryItOut("{var weytgo = new SharedArrayBuffer(6); var weytgo_0 = new Float32Array(weytgo); weytgo_0[0] = -11; var weytgo_1 = new Uint16Array(weytgo); weytgo_1[0] = -11; var weytgo_2 = new Float64Array(weytgo); weytgo_2[0] = 26; var weytgo_3 = new Int16Array(weytgo); print(weytgo_3[0]); weytgo_3[0] = -10; /*iii*/(\"\\uACFD\");/*hhh*/function odxxnh(a, weytgo_1[0]){print(weytgo_1);}print(weytgo_0[0]); }");
/*fuzzSeed-42369751*/count=689; tryItOut("\"use strict\"; s0 + '';");
/*fuzzSeed-42369751*/count=690; tryItOut("\"use strict\"; m1.has(g2);");
/*fuzzSeed-42369751*/count=691; tryItOut("\"use strict\"; a2[9] = x;");
/*fuzzSeed-42369751*/count=692; tryItOut("\"use strict\"; v2 = a1[\"ceil\"];");
/*fuzzSeed-42369751*/count=693; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ (( + ( + (1 - y))) > ( ! Math.fround(Math.pow(Math.fround((Math.hypot((x >>> 0), (x >>> 0)) >>> 0)), (Math.acosh(0/0) >>> 0)))))); }); testMathyFunction(mathy1, [-0x080000000, -Number.MAX_VALUE, 42, -0x0ffffffff, Math.PI, -(2**53+2), 0x080000000, 2**53, 1, -0x100000000, -(2**53), -0x100000001, 1.7976931348623157e308, -1/0, Number.MAX_VALUE, 2**53-2, 0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0, -(2**53-2), -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0x100000000, -0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, 0x07fffffff]); ");
/*fuzzSeed-42369751*/count=694; tryItOut(";");
/*fuzzSeed-42369751*/count=695; tryItOut("print(undefined);");
/*fuzzSeed-42369751*/count=696; tryItOut("\"use strict\"; with(new RegExp(\"(?!(?![\\\\d](?!((?=\\\\d)))))|((?=(\\\\D)*?))\", \"ym\").eval(\"/* no regression tests found */\") |= new (window).bind(x = Proxy.createFunction(({/*TOODEEP*/})(d), (function(x, y) { return x; }), (function shapeyConstructor(tktdbc){\"use strict\"; delete this[\"valueOf\"];Object.defineProperty(this, \"valueOf\", ({writable: true}));if (tktdbc) Object.defineProperty(this, \"values\", ({configurable: (x % 31 != 28)}));this[\"__lookupSetter__\"] = null;this[\"valueOf\"] = new String('q');{ break ; } if (tktdbc) Object.defineProperty(this, \"getMilliseconds\", ({configurable: null, enumerable: (x % 26 != 3)}));Object.preventExtensions(this);if (tktdbc) Object.defineProperty(this, \"1\", ({value: 16, enumerable: true}));Object.freeze(this);return this; }).call), x))o2 = new Object;");
/*fuzzSeed-42369751*/count=697; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atan2(( + Math.atan2(((Math.pow((y | 0), (x | 0)) | 0) >>> 0), ((Math.hypot(( + mathy1(( + -1/0), ( + x))), ( + (y && Math.asinh(-0x07fffffff)))) ? (Math.max((((y >>> 0) >> ((-Number.MIN_SAFE_INTEGER <= x) >>> 0)) >>> 0), ( - (Math.max(( + (Math.sign((2**53-2 >>> 0)) >>> 0)), (( + x) >>> 0)) | 0))) >>> 0) : (Math.exp(( + -Number.MAX_SAFE_INTEGER)) >>> 0)) >>> 0))), Math.hypot(( + ( ! ( + ( - -0x07fffffff)))), (( + (( + -0x100000000) === (y | 0))) << (( ! (Math.exp(((y | 0) == x)) | 0)) < (( + y) | 0))))) >>> 0); }); ");
/*fuzzSeed-42369751*/count=698; tryItOut("\"use strict\"; /*hhh*/function xvokxs(){/*RXUB*/var r = null; var s = 11; print(r.test(s)); print(r.lastIndex); }/*iii*/ /x/ ;");
/*fuzzSeed-42369751*/count=699; tryItOut("\"use strict\"; g0.v0 = (o0 instanceof h1);");
/*fuzzSeed-42369751*/count=700; tryItOut("for (var p in v1) { a0.forEach((function mcc_() { var duendv = 0; return function() { ++duendv; if (/*ICCD*/duendv % 3 == 0) { dumpln('hit!'); o2.valueOf = (function(j) { if (j) { try { v0 = t0.length; } catch(e0) { } try { v2 = Array.prototype.some.call(a1, f1); } catch(e1) { } g2.offThreadCompileScript(\"-26\"); } else { ; } }); } else { dumpln('miss!'); a0 = a2.map((function() { try { print(uneval(h0)); } catch(e0) { } try { a0.sort(); } catch(e1) { } try { v2 = Array.prototype.every.apply(g1.a2, [String.prototype.toLowerCase.bind(this.m1), f2]); } catch(e2) { } v2 = new Number(4.2); return p1; }), w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: undefined, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: offThreadCompileScript, hasOwn: function() { throw 3; }, get: function(y) { \"use strict\"; return /[^]/gm }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })([1,,]), Object.prototype.__defineSetter__, (new Function(\"i1.next();\"))), t1, t2, (delete x.x.unwatch(\"hypot\")), this.b0); } };})(), a1, f2, o2, b2); }");
/*fuzzSeed-42369751*/count=701; tryItOut("t2 = t2.subarray(({valueOf: function() { (this);/*MXX3*/g1.Object.defineProperties = g1.Object.defineProperties;return 6; }}), ({valueOf: function() { /*hhh*/function ntdnag(w, [{x: window}, {}, ], ...x){for (var p in this.e1) { try { o1.t0.set(t1, 16); } catch(e0) { } try { p2 + h0; } catch(e1) { } v1 = a2.length; }\nMath.pow\n}/*iii*/g2 = t2[this.v1];return 10; }}));");
/*fuzzSeed-42369751*/count=702; tryItOut("testMathyFunction(mathy0, /*MARR*/[false, objectEmulatingUndefined(), false, function(){}, x, objectEmulatingUndefined(), x, function(){}, false, function(){}, x, x, false, function(){}, false, false, function(){}, 1e81, function(){}, false, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, objectEmulatingUndefined(), objectEmulatingUndefined(), x, false, 1e81, objectEmulatingUndefined(), objectEmulatingUndefined(), x, function(){}, 1e81, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 1e81, objectEmulatingUndefined(), false, x, x, false, function(){}]); ");
/*fuzzSeed-42369751*/count=703; tryItOut("g0.g2.a1 = [];");
/*fuzzSeed-42369751*/count=704; tryItOut("\"use strict\"; e1.delete(v2);");
/*fuzzSeed-42369751*/count=705; tryItOut("\"use strict\"; \nthis;");
/*fuzzSeed-42369751*/count=706; tryItOut("\"use strict\"; print((set|=x));");
/*fuzzSeed-42369751*/count=707; tryItOut("m1.delete(this.g0.f1);");
/*fuzzSeed-42369751*/count=708; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + Math.log(( + ( ~ Math.expm1((0.000000000000001 ? Math.min(-0x100000001, x) : Math.pow((-Number.MIN_VALUE | 0), (2**53 | 0)))))))) * Math.fround((Math.fround(Math.atan2(( + Math.atan2(x, (Math.clz32((x | 0)) >>> 0))), ( + Math.imul(x, Math.imul((Math.fround(Math.pow(y, x)) >>> 0), y))))) * ( - mathy1((( ~ y) >>> 0), (y >>> 0)))))); }); testMathyFunction(mathy3, [0x100000001, 0.000000000000001, -0x100000001, 0x07fffffff, 0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 2**53+2, -0, 2**53, 0x080000001, -0x100000000, -0x080000000, 0, 1.7976931348623157e308, 1/0, 1, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 0x080000000, -(2**53-2), -0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -(2**53), 42]); ");
/*fuzzSeed-42369751*/count=709; tryItOut("a0.splice(NaN, 7, o1.m2);");
/*fuzzSeed-42369751*/count=710; tryItOut("e0.has(this.h0);");
/*fuzzSeed-42369751*/count=711; tryItOut("for (var p in o0.a2) { try { b2.valueOf = q => q; } catch(e0) { } m0.toSource = function ()x; }");
/*fuzzSeed-42369751*/count=712; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=713; tryItOut("v1 = (a1 instanceof e1);");
/*fuzzSeed-42369751*/count=714; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(mathy2(Math.fround(Math.hypot(Math.cbrt(Math.round(0/0)), (Math.sinh((( ~ Math.fround(mathy1(mathy0((x >>> 0), (x >>> 0)), x))) | 0)) | 0))), Math.fround(Math.exp(( + Math.sin(( + ( + mathy2(y, ( + Math.fround((Math.min(( + y), ( + 0/0)) <= y)))))))))))); }); testMathyFunction(mathy3, [(new Number(0)), objectEmulatingUndefined(), /0/, (function(){return 0;}), '0', [0], '', 0.1, NaN, 1, 0, '/0/', null, (new Number(-0)), -0, undefined, (new Boolean(true)), false, ({valueOf:function(){return '0';}}), [], true, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Boolean(false)), '\\0', (new String(''))]); ");
/*fuzzSeed-42369751*/count=715; tryItOut("yield;( \"\" );");
/*fuzzSeed-42369751*/count=716; tryItOut("\"use strict\"; e2.delete(g2.t0);");
/*fuzzSeed-42369751*/count=717; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (/*FFI*/ff(((~((/*FFI*/ff((x), (((0x52de8*(i0)) << (((((0xe89e8a15)) << ((0x5336cc0b))))))))|0)+(i0)-(-0x625cbe3)))), ((abs((((((4277).eval(\"mathy3 = (function(x, y) { return mathy0(Math.tanh((Math.hypot(Math.fround((((y >>> 0) || (Math.fround(( + Math.fround(x))) >>> 0)) >>> 0)), 2**53-2) | 0)), ((Math.cos((Math.asinh(mathy1((Math.imul(x, ((x || x) | 0)) | 0), (y << x))) >>> 0)) >>> 0) <= Math.pow(Math.atan2((( ! x) >>> 0), (-Number.MAX_VALUE >>> 0)), (y === Math.min(x, (x | 0)))))); }); testMathyFunction(mathy3, [1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0x100000001, 0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0, 42, 0x080000001, 2**53-2, 0x0ffffffff, 0x080000000, 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), -0, -1/0, -Number.MAX_VALUE, 2**53+2, -0x080000001, -Number.MIN_VALUE, -0x080000000, -0x100000001, -(2**53), Number.MAX_VALUE, -0x0ffffffff, 2**53, 0x07fffffff, 0, 1.7976931348623157e308, -0x07fffffff, Number.MIN_VALUE]); \")()))-(0xffffffff)) >> ((i0)*-0xfffff)))|0)), ((2.0)), ((imul(((+(0.0/0.0)) < (9.671406556917033e+24)), ((4398046511103.0) != (513.0)))|0)))|0);\n    i0 = (-0x8000000);\n    i0 = (0xfa96a034);\n    d1 = (d1);\n    {\n      i0 = ((~~(-4.835703278458517e+24)) < (~~(d1)));\n    }\n    {\n      return +((-262143.0));\n    }\n    d1 = (+(1.0/0.0));\n    (Int8ArrayView[((i0)-(-0x8000000)+((0x0) == (((0xffffffff))>>>((0x2179541a))))) >> 0]) = ((0x8a968162)+(i0));\n    return +((((((imul((/*FFI*/ff()|0), ((0x5fe72e07)))|0)) ? (-9.671406556917033e+24) : (-2.4178516392292583e+24))) - (((((((x = -4)).valueOf(\"number\")))) - ((d1))))));\n  }\n  return f; })(this, {ff: arguments.callee.caller.caller}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [NaN, (new String('')), false, null, -0, (new Boolean(true)), (new Number(0)), '/0/', 0.1, '0', objectEmulatingUndefined(), (new Number(-0)), true, '\\0', 1, ({valueOf:function(){return 0;}}), (function(){return 0;}), /0/, ({toString:function(){return '0';}}), [0], [], '', undefined, ({valueOf:function(){return '0';}}), (new Boolean(false)), 0]); ");
/*fuzzSeed-42369751*/count=718; tryItOut("\"use strict\"; /*RXUB*/var r = /[^](?:(?:\\u009D))($)|(?:\\2{1,5})|\\3*?.$|^{2}|(?:.){68719476736,68719476738}|\\2|.(?=(?:^{2})|[^])|(?:\\2)\\b\\0|$/ym; var s = (4277); print(s.replace(r, s)); ");
/*fuzzSeed-42369751*/count=719; tryItOut("/*oLoop*/for (var oifxbx = 0; oifxbx < 2; ++oifxbx) { {v2 + p1;function d(z =  \"\" , x, z, NaN, window, d, this.NaN, NaN =  /x/ , x, x, x = new RegExp(\"(?:(?=([^\\\\s\\\\u4904-\\ue066\\\\ue35F]|\\\\b)))*\\\\1\", \"\"), x, a, x, x, z = eval, b, b, \u3056, \u3056 = c, NaN, x, x, x, x, x, eval, \u3056, z, x, c, x, x, b, window =  \"\" , x, \u3056, b, w, delete, b, eval, y =  '' , c, b, name, x, eval, z, w, y, x, y, x, x, x, a, b, eval, z, \u3056, x, x, x, a, x, NaN, x = \"\\u96E5\", x, x = \"\\uF718\", d, x, c)\"\\u98CE\"print(uneval(t0));p2 = g1; } } ");
/*fuzzSeed-42369751*/count=720; tryItOut("\"use strict\"; let(y = (void options('strict')), y = x, x = , x =  '' , uzengp, fugurj, c =  '' , NaN = this = \"\\uEEAA\") ((function(){throw StopIteration;})());");
/*fuzzSeed-42369751*/count=721; tryItOut("\"use strict\"; { \"\" ;selectforgc(o0); }");
/*fuzzSeed-42369751*/count=722; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=723; tryItOut("let g1.o0 = {};");
/*fuzzSeed-42369751*/count=724; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(this.f1, \"constructor\", { configurable: (x % 10 == 6), enumerable: false, writable: [,], value: t0 });\n(window);\n");
/*fuzzSeed-42369751*/count=725; tryItOut("i0.send(i0);");
/*fuzzSeed-42369751*/count=726; tryItOut("t1 = t2.subarray(8, ({valueOf: function() { t2 = new Int32Array(t0);return 5; }}));");
/*fuzzSeed-42369751*/count=727; tryItOut("this.v0 = evalcx(\"/* no regression tests found */\", this.g0);");
/*fuzzSeed-42369751*/count=728; tryItOut("\"use strict\"; /*oLoop*/for (var ldabsm = 0; ldabsm < 110; ++ldabsm) { v1 = a0.length; } ");
/*fuzzSeed-42369751*/count=729; tryItOut("for(z in (( \"\" )(( /x/ .watch(\"defineProperties\", function(y) { return null })))))print([z1]);");
/*fuzzSeed-42369751*/count=730; tryItOut("/*iii*//* no regression tests found */\nb2 + a0;\n/*hhh*/function tzaehw(x = x, {\u3056: window, a, x}, eval, x, x, x, c, a, x, x, z, x, x, x, c, x, x, w, a, w, b = this, d, x, w, x, x, x, eval, x = window, eval, x, x, this.x = this, w = 13, z, NaN, x, x = this, a, z, x, \u3056, x = b, x, b, x, y = null, \u3056, eval = this, w, \u3056, x, x, x, y, x){s2 = h0;}");
/*fuzzSeed-42369751*/count=731; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.log1p(( + Math.cbrt((( ~ Math.pow((((( + x) - ( + x)) << y) >>> 0), -Number.MIN_SAFE_INTEGER)) >>> 0)))); }); testMathyFunction(mathy4, [1/0, 0x080000000, 0, -0x100000000, 2**53-2, 0.000000000000001, -0, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, 2**53+2, -Number.MIN_VALUE, 0x080000001, Math.PI, 1.7976931348623157e308, -(2**53+2), 42, -(2**53), -1/0, 0x07fffffff, -0x0ffffffff, 0/0, -Number.MAX_VALUE, -(2**53-2), 2**53]); ");
/*fuzzSeed-42369751*/count=732; tryItOut("mathy4 = (function(x, y) { return ( + Math.fround(( ~ Math.fround((( + (( + Math.fround(( ~ Math.fround(y)))) | 0)) | 0))))); }); testMathyFunction(mathy4, [2**53+2, 0, -0x100000000, -0x080000001, 0/0, 0x07fffffff, 42, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), -0x07fffffff, 1, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, 1/0, 0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, 2**53-2, -(2**53-2), -0x100000001, 0x080000001, 0.000000000000001, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, -0x080000000, Math.PI]); ");
/*fuzzSeed-42369751*/count=733; tryItOut("\"use strict\"; o2.a2.splice(-8, ({valueOf: function() { throw StopIteration;let(b) { try { 16384; } finally { yield  \"\" ; } }return 9; }}), m0);");
/*fuzzSeed-42369751*/count=734; tryItOut("mathy1 = (function(x, y) { return (((Math.clz32(Math.fround(( - x))) | 0) === ((( + Math.fround(Math.max(( + ( + (((( + Math.hypot(0x080000001, (y ^ x))) ? (Math.imul((y >>> 0), (Math.round(0.000000000000001) >>> 0)) >>> 0) : (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) | 0))), Math.acosh((( + ( + (Math.log10(( + x)) + (y || x)))) >>> 0))))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy1, [({valueOf:function(){return '0';}}), undefined, '0', objectEmulatingUndefined(), 0.1, '\\0', true, (new Boolean(false)), (new Number(-0)), (function(){return 0;}), [], (new Boolean(true)), (new String('')), ({toString:function(){return '0';}}), NaN, (new Number(0)), null, '', '/0/', /0/, ({valueOf:function(){return 0;}}), false, 1, [0], -0, 0]); ");
/*fuzzSeed-42369751*/count=735; tryItOut("\"use strict\"; o2 = {};");
/*fuzzSeed-42369751*/count=736; tryItOut("let b = ((decodeURI)/*\n*/.call(window, ));print(b);");
/*fuzzSeed-42369751*/count=737; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.sinh(mathy0(Math.exp((((Math.cbrt(Number.MIN_VALUE) >>> 0) ? x : (((y && x) | 0) >>> 0)) >>> 0)), ( + mathy1((Math.min((Math.fround(Math.fround((( + y) >>> (x | 0)))) != Math.fround(Math.atan2((y >>> 0), (-Number.MAX_SAFE_INTEGER >>> 0)))), (y , 0x100000001)) >>> 0), mathy0(y, x))))); }); testMathyFunction(mathy2, [-(2**53+2), 42, 0x100000000, 0x07fffffff, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, -0, -0x07fffffff, 2**53, -0x080000000, -0x0ffffffff, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, 2**53-2, 0/0, 1, -1/0, Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 1/0, -(2**53)]); ");
/*fuzzSeed-42369751*/count=738; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 2**53+2, 0x100000001, -0x080000000, 2**53-2, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, -0x080000001, -0, 0x100000000, -0x100000000, 0x0ffffffff, -0x0ffffffff, Math.PI, 42, -(2**53+2), 1/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, 0.000000000000001, -Number.MIN_VALUE, 0x080000000, -(2**53-2), 0, -0x100000001, -(2**53)]); ");
/*fuzzSeed-42369751*/count=739; tryItOut("m0.get(t2);");
/*fuzzSeed-42369751*/count=740; tryItOut("v0 = b2.byteLength;");
/*fuzzSeed-42369751*/count=741; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-42369751*/count=742; tryItOut("\"use asm\"; e2.add(p1);");
/*fuzzSeed-42369751*/count=743; tryItOut("\"use strict\"; t0[6] = -24;function w(x)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((0xffffffff)))|0;\n  }\n  return f;i2 + '';");
/*fuzzSeed-42369751*/count=744; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return ((((( - ((((((-Number.MIN_SAFE_INTEGER > x) >>> 0) & (y >>> 0)) | 0) > Math.atan2(Math.fround(x), x)) >>> 0)) >>> 0) >>> 0) | (Math.acos(( ~ ( + Math.sin(Math.imul(Number.MIN_SAFE_INTEGER, ( ! y)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0, NaN, null, '/0/', 0.1, -0, (new String('')), (new Number(0)), false, undefined, 1, (new Boolean(false)), ({valueOf:function(){return 0;}}), '\\0', /0/, ({toString:function(){return '0';}}), [0], '0', (new Boolean(true)), objectEmulatingUndefined(), true, (function(){return 0;}), '', [], (new Number(-0)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-42369751*/count=745; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + (( + (mathy2((Math.acos(Math.expm1((( + ((x >>> y) >>> 0)) >>> 0))) >>> 0), (( ~ ( + ( + ((y | 0) - ( ~ y))))) >>> 0)) >>> 0)) && Math.atan2(Math.fround(Math.min(Math.fround((x >> Math.fround((Math.fround(-0x07fffffff) , Math.fround((( ~ (Math.asin((y >>> 0)) >>> 0)) >>> 0)))))), Math.fround(( ~ y)))), Math.round(((( + ( + ( + Math.acos((y >>> 0))))) ** Math.min((mathy1(x, Math.atan(y)) | 0), Math.fround(( ~ Math.fround(Math.abs(0x080000000)))))) >>> 0))))); }); testMathyFunction(mathy4, [0, 1, -0x080000000, 0x100000000, -0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -0x100000001, 0x07fffffff, 1/0, 2**53+2, 42, Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 0x100000001, -(2**53+2), 0x0ffffffff, 2**53-2, 2**53, -0, -0x100000000, 0/0, -(2**53-2), -Number.MAX_VALUE, 0.000000000000001, -1/0, Number.MIN_VALUE, -(2**53), -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=746; tryItOut("mathy3 = (function(x, y) { return Math.atan2(((mathy0((x * Math.fround(Math.log10(( + ((-(2**53-2) ? x : -0x080000001) | 0))))), Math.atan2((((x ? y : 0.000000000000001) | (Math.sinh(y) | 0)) >>> 0), (( ! ( + (Math.min(x, x) | 0))) | 0))) >>> 0) - ((mathy1(( + Math.fround((Math.fround(( ! y)) != ( + y)))), Math.max(( + ( ~ ( + -Number.MIN_SAFE_INTEGER))), Math.cbrt(x))) | 0) >>> 0)), Math.fround(Math.atan((Math.log((y ? x : (mathy2(( ! 0x100000001), y) >>> 0))) ? Math.fround((Math.max((Math.fround(( - Math.fround(Math.abs(x)))) | 0), ((Math.min(Math.atan2(x, 0x100000000), (y >>> 0)) | 0) >>> 0)) >>> 0)) : (0 ? x : y))))); }); testMathyFunction(mathy3, [-0x080000000, 0x0ffffffff, -1/0, -(2**53+2), 1/0, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, 0, -(2**53-2), -0x100000001, 1, 0x080000001, -(2**53), 2**53-2, Number.MAX_VALUE, 0x100000000, 0x080000000, 2**53, -0x100000000, -0, 0.000000000000001, 2**53+2, Math.PI, -0x07fffffff, 42, 0/0, 1.7976931348623157e308]); ");
/*fuzzSeed-42369751*/count=747; tryItOut("v1 = a2.length;print(o0.v2);");
/*fuzzSeed-42369751*/count=748; tryItOut("Object.defineProperty(this, \"r2\", { configurable: (x % 4 != 0), enumerable: (x % 6 != 3),  get: function() {  return new RegExp(\".\", \"gim\"); } });");
/*fuzzSeed-42369751*/count=749; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (( + mathy0(( + ((Math.fround(mathy0(Math.fround(x), (( + Math.sign(( + (Math.fround(Math.imul((y | 0), (x | 0))) - (Math.pow((x >>> 0), Math.fround(x)) >>> 0))))) >>> 0))) ? (mathy0((Math.min((y >>> 0), (1/0 >>> 0)) >>> 0), ( + y)) || Math.abs(x)) : Number.MIN_VALUE) | 0)), ( + Math.min(( + mathy0((y | 0), 0.000000000000001)), (((((( - Math.fround(x)) | 0) | 0) != ((-(2**53+2) > Number.MIN_VALUE) | 0)) | 0) >> Math.fround(( + Math.atan2(( + -1/0), x)))))))) ? ( + Math.min(( + Math.min((( ! ((y ^ y) ? ( + Number.MAX_VALUE) : y)) & (Math.log2((( - -1/0) | 0)) | 0)), ( + Math.fround(Math.log2(Math.fround(((Math.imul(x, (y !== (y | 0))) < (y >>> 0)) >>> 0))))))), ( + Math.atan2(( + y), ((( + y) | 0) & (y | 0)))))) : ( + Math.exp((Math.imul(( + y), ((y | 0) <= (y | 0))) || Math.fround(Math.imul(Math.fround(Math.max(x, 0/0)), Math.fround(x)))))))); }); ");
/*fuzzSeed-42369751*/count=750; tryItOut("let (x) { print((timeout(1800))); }");
/*fuzzSeed-42369751*/count=751; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.hypot(((( + (mathy4(((y , -0x0ffffffff) >>> 0), ((((x >>> 0) ** (-0 >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0) > ( + (( + Math.sinh(y)) && Math.fround(x)))), ( ~ (( ~ Math.fround(Math.fround(Math.hypot(Math.fround((Math.ceil((Math.log(y) >>> 0)) >>> 0)), Math.fround(Math.fround((Math.fround((x < y)) != Math.fround(x)))))))) | 0))); }); testMathyFunction(mathy5, [-0x100000000, 1/0, 2**53-2, 0x07fffffff, -0x0ffffffff, 0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -(2**53), 2**53+2, Number.MIN_VALUE, 0x080000000, -0x080000000, -1/0, Math.PI, 1.7976931348623157e308, 0, 0x080000001, -(2**53-2), -0x080000001, 42, -(2**53+2), -Number.MIN_VALUE, 1, 0.000000000000001, 0/0, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-42369751*/count=752; tryItOut("testMathyFunction(mathy3, /*MARR*/[x,  /x/g ,  /x/g ,  /x/g , x, x, new String('q'), new String('q'), new String('q'),  /x/g , x, new String('q'),  /x/g ,  /x/g ,  /x/g , new String('q'),  /x/g , x, new String('q'), new String('q'),  /x/g , new String('q'), new String('q'),  /x/g , x,  /x/g , x,  /x/g , new String('q')]); ");
/*fuzzSeed-42369751*/count=753; tryItOut("/*iii*/print(idxqgt);/*hhh*/function idxqgt(){print(x);}");
/*fuzzSeed-42369751*/count=754; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.fround((Math.fround((( - Math.fround((Math.fround(y) ** -Number.MAX_VALUE))) != Math.fround(((Math.cosh((( ! y) >>> 0)) >>> 0) > Math.pow(y, -(2**53)))))) && Math.log10(Math.pow(x, Math.hypot(Math.sign(Math.fround(y)), 42)))))); }); testMathyFunction(mathy0, /*MARR*/[arguments, x, -0xB504F332, -0xB504F332, (void 0), -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, x, arguments, arguments, new Number(1.5), new Number(1.5), -0xB504F332, -0xB504F332, -0xB504F332, arguments, x, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, arguments, new Number(1.5), x, -0xB504F332, arguments, arguments, (void 0), arguments, new Number(1.5), x, x, x, x, new Number(1.5), new Number(1.5), arguments, (void 0), new Number(1.5), (void 0), arguments, -0xB504F332, x, -0xB504F332, (void 0), -0xB504F332, -0xB504F332, (void 0), x, x, -0xB504F332, new Number(1.5), arguments, x, -0xB504F332, (void 0), arguments, x, new Number(1.5), arguments, x, arguments, arguments, -0xB504F332, (void 0), new Number(1.5), -0xB504F332, -0xB504F332, x, (void 0), -0xB504F332, new Number(1.5), x, (void 0), arguments, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Number(1.5), (void 0), arguments, (void 0), x, -0xB504F332, x, x, -0xB504F332, -0xB504F332, new Number(1.5), -0xB504F332, x, new Number(1.5), -0xB504F332, -0xB504F332, x, new Number(1.5), (void 0), -0xB504F332, x, x, x, -0xB504F332, -0xB504F332, new Number(1.5), new Number(1.5), arguments, new Number(1.5), arguments, arguments, -0xB504F332, -0xB504F332, x, -0xB504F332, arguments, arguments, x, x, new Number(1.5), -0xB504F332, new Number(1.5), -0xB504F332, (void 0), -0xB504F332, x, -0xB504F332, x, x, x, new Number(1.5), new Number(1.5), arguments, new Number(1.5), arguments, (void 0), (void 0), x, -0xB504F332, x, (void 0), -0xB504F332, new Number(1.5), (void 0), arguments, (void 0), (void 0)]); ");
/*fuzzSeed-42369751*/count=755; tryItOut("([,,]);");
/*fuzzSeed-42369751*/count=756; tryItOut("var agppoo = new SharedArrayBuffer(12); var agppoo_0 = new Uint8Array(agppoo); /*ODP-3*/Object.defineProperty(t2, \"sort\", { configurable: ((yield false)), enumerable: new Math.acos(), writable: (agppoo % 2 == 1), value: b2 });delete t1[1];print(agppoo_0);/*RXUB*/var r = /\\b{0,0}/im; var s = \"\"; print(s.replace(r, 'x')); for (var p in g0) { try { /*RXUB*/var r = r1; var s = g2.s2; print(uneval(s.match(r)));  } catch(e0) { } try { this.v0 = Object.prototype.isPrototypeOf.call(this.m2, this.a1); } catch(e1) { } m1 + ''; }");
/*fuzzSeed-42369751*/count=757; tryItOut("\"use strict\"; e2.has(b1);");
/*fuzzSeed-42369751*/count=758; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -131073.0;\n    var d3 = 4294967297.0;\n    var i4 = 0;\n    i4 = (i4);\n    {\n      d3 = (+(0.0/0.0));\n    }\n    return (((/*FFI*/ff(((+(((i1)-(i0)-(i0)) ^ ((i4)+(((-(0xee89ac53)) | ((!(0x4c1fe845))*-0xfffff))))))), ((+log(((-33554433.0))))), ((((/*FFI*/ff()|0)-(i1)) & ((i1)+(i4)+((0xf2682489))))), ((((((-536870913.0) != (-1023.0)) ? ((2305843009213694000.0) >= (1.1805916207174113e+21)) : (/*FFI*/ff(((8388609.0)))|0))) & (((((0x8780a7e8))+((0xe2f6925d) > (0x0))))-(i4)+((((0x67ea1acb))>>>((-0x8000000))))))), ((+(0x8aeecd08))), ((((0xfaa2aadd)) & ((x)+(i1)))), ((x)), ((~~(+((-0.25))))), ((+(0x2acdae4b))))|0)))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, 1, -(2**53), 42, -0x07fffffff, Number.MAX_VALUE, 1/0, 2**53-2, 2**53, -Number.MIN_VALUE, 0, 0x080000001, 0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, Math.PI, -0x080000000, -1/0, 0/0, -0x100000001, 0x080000000]); ");
/*fuzzSeed-42369751*/count=759; tryItOut("a0.toString = (function(j) { if (j) { try { s1 = ''; } catch(e0) { } v2 = a1.every((function() { try { v1 = evalcx(\"x\", g0); } catch(e0) { } try { this.o1.a0.unshift(f2, this.p1, b0, f0,  '' , i2, i2, s2); } catch(e1) { } const \u3056;/*MXX2*/g1.String.prototype.endsWith = this.g2; return g0; })); } else { v0 = Object.prototype.isPrototypeOf.call(i0, o1.h0); } });");
/*fuzzSeed-42369751*/count=760; tryItOut("NaN = /*FARR*/[].sort(new (z = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { return []; }, has: runOffThreadScript, hasOwn: function() { return false; }, get: encodeURI, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(false), (void version(170))))()), x, eval = (/*RXUE*//[^]/g.exec(\"\\n\").watch(\"__parent__\", WeakMap.prototype.set)), x = \"\\uBB2D\" /= ((function(q) { return q; })() >>= (new (Date.prototype.setUTCFullYear)((makeFinalizeObserver('nursery')), x))), z;Array.prototype.push.call(a2);");
/*fuzzSeed-42369751*/count=761; tryItOut("print((this.__defineSetter__(\"x\", Set.prototype.clear)));\nfor (var v of a1) { f1 = Number.parseFloat; }\n");
/*fuzzSeed-42369751*/count=762; tryItOut("\"use strict\"; /*MXX3*/o2.g2.URIError.prototype.message = g2.URIError.prototype.message;");
/*fuzzSeed-42369751*/count=763; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.imul(( + ( + ((((( ! ( + -0x100000000)) >>> 0) >>> (mathy1(Math.fround((Math.fround(y) === Math.fround(( - y)))), ( + y)) >>> 0)) >>> 0) >>> 0))), (Math.fround(( - Math.fround(Math.fround(( + Math.fround((y - x))))))) >>> 0))); }); testMathyFunction(mathy5, [2**53, -0x07fffffff, -0, 1, 0x080000001, Math.PI, 42, 2**53+2, -0x080000000, -1/0, 0x0ffffffff, 1.7976931348623157e308, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 1/0, -(2**53), 0x100000000, 0x07fffffff, 0.000000000000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, 0x100000001, -0x0ffffffff, -0x100000001, 0/0, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000000, -0x080000001]); ");
/*fuzzSeed-42369751*/count=764; tryItOut("\"use strict\"; t1 = new Uint8Array(t2);");
/*fuzzSeed-42369751*/count=765; tryItOut("mathy0 = (function(x, y) { return ((( ~ ( - y)) >>> 0) !== Math.fround((Math.min(Math.fround((Math.fround(Math.pow((((y | 0) || (( - y) | 0)) | 0), x)) + Math.fround(1.7976931348623157e308))), y) < (Math.pow(( + ( ~ ((0.000000000000001 < y) / 0x100000001))), Math.fround(Math.cos(Math.fround(x)))) >>> 0)))); }); testMathyFunction(mathy0, [-0x080000000, 2**53, -1/0, -(2**53+2), 0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, 0x080000001, Math.PI, 0, -0x100000001, -Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 1, 2**53+2, 2**53-2, 1/0, -0x0ffffffff, -Number.MIN_VALUE, 0/0, 0x100000001, 0x07fffffff, 0x0ffffffff, -0x080000001, -(2**53), -0, 42, 0.000000000000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=766; tryItOut("t0 = new Uint8ClampedArray(b0, 12, 9);");
/*fuzzSeed-42369751*/count=767; tryItOut("v2 = r1.sticky;");
/*fuzzSeed-42369751*/count=768; tryItOut("with(x)this.e1.add(f2);");
/*fuzzSeed-42369751*/count=769; tryItOut("{M:for(let b = (x)((Date())) in (/*FARR*/[new (\"\\u7F80\")([1,,]), (delete  /x/g .throw(23)), ...28 if (e), (4277), eval, , .../*FARR*/[], let (b =  /x/ ) \"\\u325F\", Math.imul(-15, ({}))].sort({} = [], ((uneval((new (\"\\uFD1E\")(/(?!(?=[^]|\\cM^|.)+?|(?:([^\u92ed-\uf86f\\S\\A-\\B\\W]{3,})))/ym)))))))) h0 = {};/*vLoop*/for (hcsjwa = 0; (Math.hypot(-20, -27)) && hcsjwa < 0; ++hcsjwa) { var y = hcsjwa; o1.v1 = t0.length; } let (d) { d; } }");
/*fuzzSeed-42369751*/count=770; tryItOut("/*RXUB*/var r = /(?!(?:(?=[^])(\\xf3)[\\b-\u0081\\t-\\u0008]?\\s)){2}/gyi; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-42369751*/count=771; tryItOut("M:for(var e = (x = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), eval, /*wrap2*/(function(){ var fozpxn = 14; var wccdtv = Object.prototype.hasOwnProperty; return wccdtv;})())) in (4277)) {print(x);print(x); }");
/*fuzzSeed-42369751*/count=772; tryItOut("testMathyFunction(mathy2, [objectEmulatingUndefined(), (new Number(-0)), [], '0', (new Boolean(true)), true, -0, 0, '\\0', NaN, (new String('')), 0.1, undefined, false, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), null, 1, (new Boolean(false)), '', ({toString:function(){return '0';}}), (function(){return 0;}), /0/, [0], (new Number(0)), '/0/']); ");
/*fuzzSeed-42369751*/count=773; tryItOut("/*infloop*/for(x in \"\\uA230\") for (var p in p1) { try { v0 = a1.length; } catch(e0) { } try { s1 += s2; } catch(e1) { } Array.prototype.reverse.call(a2); }");
/*fuzzSeed-42369751*/count=774; tryItOut("e1 + b0;");
/*fuzzSeed-42369751*/count=775; tryItOut("\"use strict\"; s0 = new String;");
/*fuzzSeed-42369751*/count=776; tryItOut("selectforgc(this.o0);");
/*fuzzSeed-42369751*/count=777; tryItOut("while((x) && 0){e2.add(e0);o2.v0 = g0.g0.eval(\"function f2(i2) (\\\"\\\\uD80D\\\".sub())\"); }");
/*fuzzSeed-42369751*/count=778; tryItOut("this.m0.set(b1, t2);");
/*fuzzSeed-42369751*/count=779; tryItOut("\"use strict\"; let(amibwz, wmdapa, c =  '' , c, qumulb, w = (x.unwatch(\"setYear\")), mifzjw) ((function(){yield undefined;})());");
/*fuzzSeed-42369751*/count=780; tryItOut("\"use strict\"; a0.reverse();(x);");
/*fuzzSeed-42369751*/count=781; tryItOut("mathy4 = (function(x, y) { return Math.acos(( + (((((( ! ( + Math.log2(y))) >>> 0) >> (( ! ( + (( + Math.fround(mathy0(x, Math.fround((( ! x) >>> 0))))) ? ( + y) : ( + x)))) | 0)) | 0) >>> 0) >> ( + ( ~ y))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, 0x0ffffffff, 0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, 2**53, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 1, 2**53-2, 1/0, -0x100000000, Number.MIN_VALUE, Math.PI, 2**53+2, -0x080000000, 0x100000001, 42, 0x100000000, -(2**53), 0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, -(2**53-2), -1/0, -Number.MIN_VALUE, -(2**53+2), 0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=782; tryItOut("testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, 0x0ffffffff, -(2**53-2), Number.MIN_VALUE, 2**53, Math.PI, 42, 1.7976931348623157e308, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0/0, 1/0, -(2**53+2), 0x07fffffff, 2**53+2, -0x07fffffff, -0, -0x100000001, -Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, 0, -0x080000001, 1, 0x100000000, 2**53-2, -0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=783; tryItOut("print(uneval(g2.m1));");
/*fuzzSeed-42369751*/count=784; tryItOut("var savwit = new ArrayBuffer(4); var savwit_0 = new Uint32Array(savwit); print(savwit_0[0]); print(i1);");
/*fuzzSeed-42369751*/count=785; tryItOut("/*bLoop*/for (dvrptn = 0; dvrptn < 102; ++dvrptn) { if (dvrptn % 28 == 22) { eval = linkedList(eval, 474); } else { print(x);const y = /*FARR*/[ '' , ...[]].map(Map.prototype.delete, 1e4); }  } ");
/*fuzzSeed-42369751*/count=786; tryItOut("m2.delete(e1);");
/*fuzzSeed-42369751*/count=787; tryItOut("skpmnz();/*hhh*/function skpmnz(x){this.s0 += s0;}");
/*fuzzSeed-42369751*/count=788; tryItOut("Object.defineProperty(this, \"o0\", { configurable: true, enumerable: true,  get: function() { h1.getPropertyDescriptor = (function() { try { a0.sort((function() { for (var j=0;j<2;++j) { f2(j%4==1); } }), o1, i1); } catch(e0) { } o2.g0.s1 = s2.charAt(({valueOf: function() { ;return 13; }})); return a1; }); return {}; } });");
/*fuzzSeed-42369751*/count=789; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((( ! Math.imul((((Math.fround(mathy0((0x07fffffff % y), Math.fround((-0 !== y)))) | 0) ? (x | 0) : (y | 0)) | 0), ( + Math.sinh(y)))) >>> 0) == Math.asinh((Math.acosh(y) ? (( - ( + (((x >>> 0) ^ (y >>> 0)) >>> 0))) | 0) : ( - Math.clz32((y >>> 0)))))); }); testMathyFunction(mathy4, [-(2**53-2), Number.MIN_VALUE, 0x100000001, -0, 0x080000001, Number.MAX_VALUE, 2**53-2, -0x0ffffffff, 1, -1/0, -0x100000001, 0, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, 2**53+2, -Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 0x07fffffff, 0.000000000000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, -(2**53), 0x100000000, 1/0, 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=790; tryItOut("o0 = Object.create(e1);");
/*fuzzSeed-42369751*/count=791; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=792; tryItOut("g2 = Proxy.create(h0, o2.m2);");
/*fuzzSeed-42369751*/count=793; tryItOut("mathy0 = (function(x, y) { return (Math.atan2((Math.imul((( + x) >>> 0), ((( + x) > (( + (Math.fround((Math.fround(Math.fround(y)) !== Math.fround(( + Math.pow(( + Number.MAX_SAFE_INTEGER), ( + y)))))) >>> 0)) >>> 0)) >>> 0)) | 0), (Math.imul(Math.fround(( ! Math.fround(( + x)))), Math.imul(((( ~ (( + x) >>> 0)) | 0) ** Math.hypot((y >>> 0), x)), (((y | 0) == Math.max(x, ( + (( + x) ? ( + x) : ( + y))))) | 0))) | 0)) | 0); }); testMathyFunction(mathy0, [0x080000001, -0, -0x100000000, Math.PI, -(2**53), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, -(2**53-2), Number.MAX_VALUE, 0, -0x100000001, -0x07fffffff, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, 0x07fffffff, 0x080000000, 1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), 42, Number.MAX_SAFE_INTEGER, 1, 2**53, 0.000000000000001, 2**53-2, -1/0]); ");
/*fuzzSeed-42369751*/count=794; tryItOut("\"use strict\"; with({y: true **= window})var xeccdz = new SharedArrayBuffer(0); var xeccdz_0 = new Uint8Array(xeccdz); print(xeccdz_0[0]); xeccdz_0[0] = -13; print(null);b1 + '';return;(undefined);");
/*fuzzSeed-42369751*/count=795; tryItOut("o2.v0 = t0.length;");
/*fuzzSeed-42369751*/count=796; tryItOut("");
/*fuzzSeed-42369751*/count=797; tryItOut("this.zzz.zzz;throw StopIteration;");
/*fuzzSeed-42369751*/count=798; tryItOut("/*infloop*/for(let arguments in new RegExp(\"$|[]*|(\\\\B)|(?=[^\\\\u1c27\\\\u508C\\u5c03-\\u8393])|(?=\\\\S)|[\\\\u0068\\\\cP]+{137438953471,137438953475}\\\\2{4}\", \"g\")) for(let b = x in x) selectforgc(g2.o1.o1);\nprint(x);\n\no1.v0 = (g2.a2 instanceof b0);{print(uneval(m0));((c %= eval(\"( /x/ );\", x =  '' ))); }\n");
/*fuzzSeed-42369751*/count=799; tryItOut("Array.prototype.push.call(a1, g2, o0.p0);");
/*fuzzSeed-42369751*/count=800; tryItOut("v1 = t2.length;");
/*fuzzSeed-42369751*/count=801; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( - (( + ( + Math.fround((Math.fround(Math.ceil(x)) > ( + Math.sign((Math.atan2(( + (y >> x)), y) >>> 0))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 0x080000001, 2**53+2, -0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), -0x100000000, Math.PI, -0, -0x080000000, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, 1.7976931348623157e308, -(2**53-2), 2**53-2, 2**53, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, 0x080000000, 0/0, 0x0ffffffff, 0, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 42]); ");
/*fuzzSeed-42369751*/count=802; tryItOut("mathy4 = (function(x, y) { return (( + Math.max(((Math.fround(-0x07fffffff) ? (( + Math.asinh(( + -Number.MIN_SAFE_INTEGER))) >>> 0) : (y >>> 0)) * mathy2(Math.fround(y), 0x0ffffffff)), ((y | (((mathy3(y, Math.hypot(y, Math.fround(y))) >>> 0) || (( + y) >>> 0)) >>> 0)) | 0))) * Math.fround(Math.acos(Math.fround(( - ( + Math.asin((y ? ( ~ Math.fround(0x0ffffffff)) : y)))))))); }); testMathyFunction(mathy4, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-42369751*/count=803; tryItOut("g2.offThreadCompileScript(\"((uneval(([]) = x % x)))\");");
/*fuzzSeed-42369751*/count=804; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=805; tryItOut("v1 = (h2 instanceof s2);");
/*fuzzSeed-42369751*/count=806; tryItOut("hmrala();/*hhh*/function hmrala(x, a, x, y, d, x, set, y, z, x, c, x, this.d, x, c, x, x =  /x/g , c, c, x, x, x, window = \"\\u5C25\", x = \"\\u21AE\", x, x, this.\u3056, y, x = 10, x, undefined, x, b, y = [z1,,], z, b, x = /(?=.)/gi, NaN, false, w, w, \u3056, y, x, x = -23,  '' , x, NaN, x, e, \u3056, x = function(id) { return id }, this, x){s1 += s1;\n;\n}");
/*fuzzSeed-42369751*/count=807; tryItOut("m2 = new Map(g0.t2);");
/*fuzzSeed-42369751*/count=808; tryItOut("for (var p in e2) { try { o2.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { print(a16); var r0 = a8 ^ 8; a2 = 7 | a9; var r1 = a3 - a9; a16 = a4 | a19; var r2 = 2 ^ 0; var r3 = x | a17; var r4 = 0 * a9; r2 = r1 & a8; var r5 = 7 + 1; a16 = 5 + r4; r3 = a2 & a7; var r6 = 1 / a0; return a17; }); } catch(e0) { } /*MXX1*/o1.o2 = g1.Promise.name; }");
/*fuzzSeed-42369751*/count=809; tryItOut("\"use strict\"; a1.push(f2);");
/*fuzzSeed-42369751*/count=810; tryItOut("\"use strict\"; /*hhh*/function rybswi(a){e2.add(b1);}rybswi(\"\\u9AFD\", \"\\u5347\");");
/*fuzzSeed-42369751*/count=811; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=812; tryItOut("for (var v of this.h0) { try { g0.offThreadCompileScript(\"/*RXUE*/new RegExp(\\\"(?:\\\\\\\\B)\\\", \\\"m\\\").exec(\\\"k\\\\u000b\\\\nz\\\")\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 89 == 40), catchTermination: false })); } catch(e0) { } L:if(false) h2 + ''; else function(y) { \"use strict\"; return true } }");
/*fuzzSeed-42369751*/count=813; tryItOut("for (var v of this.f0) { try { a2 = a0[14]; } catch(e0) { } try { b1 = new SharedArrayBuffer(144); } catch(e1) { } try { o1 = m0.get(Object.defineProperty(b, \"trimRight\", ({configurable: (x % 5 != 0), enumerable: [z1]})).eval(\"\\\"use strict\\\"; mathy3 = (function(x, y) { return Math.log1p(((Math.asin((mathy2(((y ? y : mathy1(y, 2**53)) | 0), ( + y)) | 0)) | 0) ? Math.fround(( ~ ((((( + mathy1((Math.hypot((-(2**53+2) >>> 0), (Math.PI >>> 0)) >>> 0), ( + mathy0(x, y)))) >>> 0) > (x >>> 0)) >>> 0) >>> 0))) : ( + Math.sin(( + (Math.fround(x) ? Math.fround(0.000000000000001) : x)))))); }); testMathyFunction(mathy3, [0, (new Number(0)), 1, (new Boolean(true)), '0', '\\\\0', false, true, [0], '/0/', (new String('')), ({valueOf:function(){return '0';}}), 0.1, '', (new Number(-0)), ({toString:function(){return '0';}}), NaN, undefined, [], objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), (function(){return 0;}), (new Boolean(false)), /0/, -0, null]); \")); } catch(e2) { } b0 = f2; }");
/*fuzzSeed-42369751*/count=814; tryItOut("a0[18] = h0;");
/*fuzzSeed-42369751*/count=815; tryItOut("testMathyFunction(mathy0, [-0, -(2**53-2), 0/0, -Number.MAX_VALUE, -0x100000000, -1/0, 1.7976931348623157e308, -0x0ffffffff, 2**53+2, 0x080000000, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, -(2**53+2), -0x07fffffff, -(2**53), 2**53-2, -0x080000000, 2**53, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, Math.PI, -0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 42, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=816; tryItOut("v2 = new Number(t0);");
/*fuzzSeed-42369751*/count=817; tryItOut("e1 = new Set(i0);");
/*fuzzSeed-42369751*/count=818; tryItOut("g0.v1 = Object.prototype.isPrototypeOf.call(v1, i0);");
/*fuzzSeed-42369751*/count=819; tryItOut("h1.enumerate = (function() { Array.prototype.splice.apply(a0, [NaN, new RegExp(\"(.+?)\", \"gi\")]); return e2; });\nArray.prototype.shift.apply(this.a1, []);\n");
/*fuzzSeed-42369751*/count=820; tryItOut("\"use asm\"; s2 += 'x';");
/*fuzzSeed-42369751*/count=821; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; void schedulegc(this); } void 0; } ;");
/*fuzzSeed-42369751*/count=822; tryItOut("\"use strict\"; x = ((((makeFinalizeObserver('tenured'))))()), window, x, yiewjm, wzuqmb, [] = /*UUV2*/(NaN.reduceRight = NaN.big), eval, b = (new (arguments[\"call\"]|=x)(eval(\"/* no regression tests found */\", (4277))));g1 = this;");
/*fuzzSeed-42369751*/count=823; tryItOut("L:with(x)g0.v1 = Object.prototype.isPrototypeOf.call(f2, m1);");
/*fuzzSeed-42369751*/count=824; tryItOut("testMathyFunction(mathy4, [2**53-2, 1/0, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 42, -1/0, 2**53, 2**53+2, 0x080000001, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, -0, 0/0, Math.PI, 1, 0x100000000, 1.7976931348623157e308, 0.000000000000001, -0x07fffffff, 0x100000001, 0x080000000, 0x07fffffff, -(2**53-2), 0, -0x080000000, -0x100000001]); ");
/*fuzzSeed-42369751*/count=825; tryItOut("/*hhh*/function tqagll(){s0 += s2;}/*iii*/tqagll.constructor;yield ( /x/  ? [z1,,] : 11);");
/*fuzzSeed-42369751*/count=826; tryItOut("\"use strict\"; \"use asm\"; yield e | x;");
/*fuzzSeed-42369751*/count=827; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0.000000000000001, -0, -0x100000001, 0, -0x0ffffffff, 1/0, -Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -(2**53), 1.7976931348623157e308, 0/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -(2**53+2), -0x100000000, 2**53, 0x100000001, 2**53+2, -0x080000000, 0x080000000, 2**53-2, 0x07fffffff, 0x080000001, 0x0ffffffff, -1/0, 42]); ");
/*fuzzSeed-42369751*/count=828; tryItOut("try { \"\\u8762\"; } catch(a) { {} } ");
/*fuzzSeed-42369751*/count=829; tryItOut("t2 + e1;");
/*fuzzSeed-42369751*/count=830; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + Math.log(( + (Math.min(y, y) ? (Math.log10(Math.fround(( ! Math.fround(x)))) | 0) : ( ~ Math.max(Math.fround((Number.MAX_VALUE , Math.max((x | 0), (0 | 0)))), y)))))) && (Math.cosh((Math.sign((x | 0)) | 0)) ? ( + ( + x)) : (( + x) * y))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, -1/0, Number.MIN_VALUE, -0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 1/0, 0x100000001, -0x080000000, -(2**53-2), 0, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, Math.PI, 2**53-2, 0.000000000000001, -(2**53+2), 0x080000001, -Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 1, -(2**53), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-42369751*/count=831; tryItOut("\"use strict\"; with({x:  /x/g  , this}){new (-0.008)([,,]);g0.offThreadCompileScript(\"function f2(h1) (void shapeOf(window))\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval:  /x/g , sourceIsLazy: (x % 4 == 0), catchTermination: \"\\u1263\" })); }");
/*fuzzSeed-42369751*/count=832; tryItOut("\"use strict\";  for  each(var d in this) g1.v1 = (this.a2 instanceof a2);");
/*fuzzSeed-42369751*/count=833; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 0, 2**53-2, Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53-2), -Number.MAX_VALUE, -0, 0x080000001, 0x100000001, 1, 0.000000000000001, -0x100000000, Number.MIN_VALUE, 0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, 2**53, 1.7976931348623157e308, -(2**53+2), 42, 0/0, 1/0, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, Math.PI, -0x080000000, -0x080000001]); ");
/*fuzzSeed-42369751*/count=834; tryItOut("testMathyFunction(mathy3, [1/0, -(2**53+2), -1/0, -0x080000001, 1, -0x0ffffffff, 0x100000000, 0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, -0x07fffffff, 0x080000000, -(2**53-2), -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000001, -0x100000000, -Number.MIN_VALUE, 0x0ffffffff, -0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, 42, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-42369751*/count=835; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"h0.getOwnPropertyNames = f2;\");");
/*fuzzSeed-42369751*/count=836; tryItOut("for (var p in p1) { try { ; } catch(e0) { } try { s1.valueOf = function (a)\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (i0);\n    }\n    i1 = (i0);\n    i1 = (i0);\n    i1 = (i1);\n    (Float32ArrayView[0]) = ((1099511627776.0));\n    i1 = (((((-(i1)))+((((i1))|0))+((((-0x8000000))>>>((0x55a9fd97))) == (((0xff120212))>>>((0x80d464f3)))))>>>((i1))) != (((i0))>>>((i1)-((0x55de73b7)))));\n    return ((((i1) ? ((33554433.0) <= (-147573952589676410000.0)) : ((((Float32ArrayView[((-0x8000000)-(0x77045fb7)) >> 2])) % ((+atan2(((-((-562949953421311.0)))), (((-2.4178516392292583e+24) + (8589934593.0))))))) > (((0.5)) * ((((((-9007199254740992.0)) / ((7.555786372591432e+22)))) * ((0.5)))))))))|0;\n  }\n  return f;; } catch(e1) { } try { a1.unshift(this.v1, g0, a2); } catch(e2) { } for (var p in f2) { try { g1.g2.valueOf = (function() { for (var j=0;j<14;++j) { f0(j%5==0); } }); } catch(e0) { } try { v2 = r2.compile; } catch(e1) { } Array.prototype.push.call(this.a0, g1.h0); } }");
/*fuzzSeed-42369751*/count=837; tryItOut("\"use strict\"; ;");
/*fuzzSeed-42369751*/count=838; tryItOut("i1.send(o0.e0);");
/*fuzzSeed-42369751*/count=839; tryItOut("/*RXUB*/var r = /\\2|(?:^)+?|\\3+|$\\B|[^\\r]*??|(?=(?:\\b?))*|\\2\u2261{1}/i; var s = (makeFinalizeObserver('nursery')); print(s.replace(r, (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return []; }, delete: (([true] /= (Math.atan2(-6, ((b = undefined)).throw(this.__defineGetter__(\"z\", runOffThreadScript)))))).bind(), fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: (window).bind, }; }), \"gy\")); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=840; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.hypot((Math.min(Math.fround((( + Math.log2(( + ( + Math.pow(( + x), ( + y)))))) ? Math.hypot(Math.PI, x) : mathy0(x, Math.fround(( ! Math.fround(x)))))), (( + Math.fround(Math.tan(Math.fround(Math.atan2(2**53-2, (Math.atan2(y, Math.fround(x)) | 0)))))) | 0)) | 0), Math.fround(mathy3(( + (( ! (Math.fround(mathy1(Math.fround(((((Math.atanh((Number.MIN_VALUE | 0)) | 0) >>> 0) >> (y >>> 0)) >>> 0)), Math.fround(Math.cosh(1)))) >>> 0)) >>> 0)), (( + (x >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x100000001, -Number.MAX_VALUE, 1, -0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, 0, 0x080000000, Math.PI, 42, 2**53+2, 0.000000000000001, -(2**53), -0x0ffffffff, -1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -0x07fffffff, 0x07fffffff, -0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, 2**53-2, -Number.MIN_VALUE, 2**53, 1.7976931348623157e308, Number.MAX_VALUE, 1/0, 0/0, 0x0ffffffff, -(2**53+2), -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=841; tryItOut("[,,];( /x/g );");
/*fuzzSeed-42369751*/count=842; tryItOut("mathy3 = (function(x, y) { return ( ~ ((mathy0(( + ((y & ((Math.min(( ~ Number.MIN_SAFE_INTEGER), x) | 0) != ( + 1.7976931348623157e308))) | x)), ( - (Math.fround((x + Math.fround(y))) !== y))) >>> 0) >>> 0)); }); testMathyFunction(mathy3, [-(2**53+2), 0x100000000, -0, 2**53, 0x080000000, -1/0, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), Number.MIN_VALUE, 0x100000001, 0/0, 0.000000000000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, -0x07fffffff, 0x0ffffffff, Math.PI, 1, -(2**53), -0x100000001, 0x080000001, 2**53+2, 1/0, 1.7976931348623157e308, Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=843; tryItOut("\"use strict\"; /*bLoop*/for (uuqaox = 0; uuqaox < 32; ++uuqaox) { if (uuqaox % 2 == 1) { /* no regression tests found */ } else { { if (isAsmJSCompilationAvailable()) { void 0; setIonCheckGraphCoherency(false); } void 0; } }  } ");
/*fuzzSeed-42369751*/count=844; tryItOut("const this.i2 = new Iterator(f1);");
/*fuzzSeed-42369751*/count=845; tryItOut("t0[(x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: decodeURIComponent, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: mathy2, keys: undefined, }; })('fafafa'.replace(/a/g, Root)), let (z = (e = window)) x))] = o1.o2;");
/*fuzzSeed-42369751*/count=846; tryItOut("/*ODP-1*/Object.defineProperty(m0, \"constructor\", ({value: x, writable: false, configurable: true}));");
/*fuzzSeed-42369751*/count=847; tryItOut("/*MXX1*/o1 = this.g0.Uint16Array.BYTES_PER_ELEMENT;");
/*fuzzSeed-42369751*/count=848; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\xa1\", \"gim\"); var s = \"\\u28e2\"; print(r.test(s)); ");
/*fuzzSeed-42369751*/count=849; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=850; tryItOut("((x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: undefined, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })((void options('strict'))), x)));");
/*fuzzSeed-42369751*/count=851; tryItOut("\"use strict\"; with(Object.defineProperty(NaN, \"x\", ({value: x})))(true.__defineSetter__(\"e\", Float64Array));");
/*fuzzSeed-42369751*/count=852; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + (Math.cosh(( ~ y)) == ( - (((x >>> 0) === ((Math.atan2((( ~ Math.fround(-0x0ffffffff)) >>> 0), (x >>> 0)) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [-1/0, -(2**53), -0x100000000, Number.MAX_SAFE_INTEGER, 1, -0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, -(2**53-2), 0, -Number.MAX_VALUE, -0x07fffffff, 42, 1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, 0x100000000, -0x100000001, 0.000000000000001, Math.PI, 2**53+2, 0x080000000, 0x100000001, 1.7976931348623157e308, -0x080000001, -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=853; tryItOut("mathy4 = (function(x, y) { return (( - (((((( ! (Math.imul(Math.fround(x), Math.fround((Math.imul(((((y | 0) + x) | 0) >>> 0), (Number.MAX_SAFE_INTEGER | 0)) >>> 0))) | 0)) | 0) | 0) !== (Math.hypot(Math.fround((Math.fround(0x100000000) , Math.fround(x))), Math.fround(mathy3(y, Math.fround((mathy2(mathy1(y, Number.MAX_VALUE), x) !== Number.MIN_SAFE_INTEGER))))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MAX_VALUE, 0x080000001, 42, 0x100000000, -Number.MIN_VALUE, 0x0ffffffff, 0/0, 0, -0x100000001, -0x0ffffffff, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), -1/0, -0, 1.7976931348623157e308, 1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, -(2**53+2), -0x080000001, 0x07fffffff, 2**53+2, 2**53-2, 1, Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=854; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((Math.asin((Math.log(((((((x | 0) ? y : x) ? (x | 0) : Math.PI) >>> y) | 0) >>> 0)) >>> 0)) != (mathy1((x >>> 0), (Math.acos(( + y)) >>> 0)) >>> 0)) % Math.atan((Math.expm1(Math.expm1(( + y))) + -Number.MIN_VALUE))); }); testMathyFunction(mathy2, [-0x07fffffff, 2**53+2, Number.MIN_VALUE, Math.PI, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 0x0ffffffff, 0, 0/0, 2**53, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, -0x080000000, 1/0, -(2**53), -0x0ffffffff, -0x100000001, -(2**53+2), 0x07fffffff, 0.000000000000001, -(2**53-2), 42, 2**53-2, 1.7976931348623157e308, -0, -1/0, -Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-42369751*/count=855; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=856; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -1.25;\n    var d4 = 17.0;\n    i2 = ((((((((0x97343e27)))>>>(((0xee296d08) > (0x0))-(/*FFI*/ff(((d4)))|0))) > (((0x6981c81))>>>((0xffffffff))))) | ((-0x8000000))));\n    return (((/*FFI*/ff((((((0x55533eeb) == (0x0))) >> (0x26e0c*(-0x4cd7ff9)))), ((d4)), ((d0)), ((d0)), ((((d1)) / ((+/*FFI*/ff(((d1)), ((-1099511627777.0)), ((268435455.0)), ((-536870913.0)), ((-4398046511105.0)), ((-0.0625)), ((-0.03125))))))), ((d3)))|0)+((0x0) == (0x5c7c2cb5))))|0;\n  }\n  return f; })(this, {ff: String.prototype.toString}, new ArrayBuffer(4096)); ");
/*fuzzSeed-42369751*/count=857; tryItOut("\"use strict\"; let eval = /(?:^\\t?|(.){1,1}|\\2*)/yim.watch(\"a\", decodeURIComponent) ? e-- : let (x = true) ({a1:1}), d = ([]), x, jyrxtz, w =  /x/g , nzevzw;print(uneval(o0));");
/*fuzzSeed-42369751*/count=858; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.asinh(Math.fround(Math.tan(Math.fround(Math.fround((( + Math.atanh(Math.fround(x))) , Math.fround((mathy0(( + Math.hypot(y, Math.fround((((x >>> 0) != ( + 2**53-2)) | 0)))), ( + (Math.tanh(x) ? (Math.abs(x) | 0) : y))) | 0))))))))); }); testMathyFunction(mathy1, [1, -0, 2**53-2, 42, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -(2**53-2), 0, -0x080000000, 0x080000000, 2**53, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, 0/0, 0x100000001, Number.MIN_VALUE, -0x100000001, -1/0, 0x0ffffffff, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, 0x07fffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, 1.7976931348623157e308, Math.PI]); ");
/*fuzzSeed-42369751*/count=859; tryItOut("\"use asm\"; a0[17];v2 = g1.eval(\"this.t0[\\\"callee\\\"] = o2;\");");
/*fuzzSeed-42369751*/count=860; tryItOut("\"use strict\"; x.stack;");
/*fuzzSeed-42369751*/count=861; tryItOut("r1 = /.((?!$)|(?!.)+?)/g;");
/*fuzzSeed-42369751*/count=862; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(mathy1(Math.fround((Math.trunc(((((Math.min(x, (x >>> 0)) >>> 0) > Math.fround(Math.fround(( + Math.fround(( + Math.fround(x))))))) >>> 0) >>> 0)) >>> 0)), Math.fround(Math.min(Math.fround(Math.fround(mathy0(Math.fround(( + (Math.log((x | 0)) | 0))), Math.fround(0x100000001)))), Math.fround(Math.fround(((Number.MIN_SAFE_INTEGER / -0x080000000) === (Math.pow((( + Math.hypot(y, ( + y))) >>> 0), ((Math.abs(Math.hypot(Math.log1p(y), x)) >>> 0) | 0)) >>> 0)))))))); }); testMathyFunction(mathy2, [2**53+2, -(2**53-2), -0, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, 0x080000001, 2**53-2, -(2**53), -0x07fffffff, 1/0, 0x0ffffffff, 0.000000000000001, -0x080000000, 1, -0x0ffffffff, 0x080000000, Number.MAX_VALUE, 42, -Number.MAX_VALUE, 2**53, -0x080000001, 0, Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0]); ");
/*fuzzSeed-42369751*/count=863; tryItOut("\"use strict\"; b2 = t0.buffer;");
/*fuzzSeed-42369751*/count=864; tryItOut("print( ''  *= x);function NaN()(x(({a1:1}))) = x.valueOf(\"number\")print(x);");
/*fuzzSeed-42369751*/count=865; tryItOut("\"use strict\"; ");
/*fuzzSeed-42369751*/count=866; tryItOut("mathy3 = (function(x, y) { return (( ! Math.fround(Math.abs((( + Math.max(( + y), -(2**53+2))) / ( + Math.max(( + x), ( + x))))))) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -(2**53), 42, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, -(2**53-2), -0, Math.PI, 0, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, Number.MIN_VALUE, -0x0ffffffff, 1, 1/0, 0x100000001, -1/0, 0/0, 0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53, -0x100000000, 0x080000000, -0x080000000, Number.MAX_VALUE, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-42369751*/count=867; tryItOut("/*infloop*/for(var e = window; -3;  '' ) {print(e);print(e); }");
/*fuzzSeed-42369751*/count=868; tryItOut("mathy5 = (function(x, y) { return Math.max((mathy1(((Math.hypot(((x >>> 0) / -0x0ffffffff), (-Number.MIN_SAFE_INTEGER < Math.fround(1/0))) ? Math.imul(Math.pow(1.7976931348623157e308, Math.max(1.7976931348623157e308, x)), 2**53+2) : y) >>> 0), ((x - Math.atanh((((y , y) >>> 0) | 0))) | 0)) >>> 0), ((( + ( + y)) <= ( + y)) / Math.atan2(( + (( ! Math.fround(( + Math.log2(( + Math.pow(Math.fround(y), (x | 0))))))) >>> 0)), (x ? (Math.ceil(((Math.atan((y >>> 0)) >>> 0) | 0)) >>> 0) : (Math.acos((-0x100000000 | 0)) | 0))))); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-42369751*/count=869; tryItOut("/*RXUB*/var r = /(?=(?=((.[^][\u009f\\S]*?))|\\3+?))/gm; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-42369751*/count=870; tryItOut("for(var x in z) h1.valueOf = f2;");
/*fuzzSeed-42369751*/count=871; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.abs(( + ( + ( + ( - ( + y)))))); }); ");
/*fuzzSeed-42369751*/count=872; tryItOut("a1.__proto__ = a0;\nprint(x);\n");
/*fuzzSeed-42369751*/count=873; tryItOut("mathy4 = (function(x, y) { return ( + Math.imul(Math.cos((Math.pow(x, (y | 0)) | 0)), ( + (( ! Math.tanh(( + ( ~ ( + x))))) | 0)))); }); testMathyFunction(mathy4, [-0x07fffffff, -0x080000001, 2**53-2, 2**53, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, 0x0ffffffff, 0x07fffffff, 2**53+2, -(2**53+2), -(2**53-2), 0x080000000, Number.MAX_SAFE_INTEGER, 1, -0x080000000, Math.PI, Number.MAX_VALUE, -0x0ffffffff, -0, 0x080000001, 1.7976931348623157e308, -0x100000001, -Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -0x100000000, -1/0, 1/0, 0x100000000, 42]); ");
/*fuzzSeed-42369751*/count=874; tryItOut("with({z: /*UUV2*/(x.toLocaleString = x.pop)})print(x);");
/*fuzzSeed-42369751*/count=875; tryItOut("\"use strict\"; g1.a1.push(i1, h0, t1);\nv2 = (i0 instanceof a0);\n");
/*fuzzSeed-42369751*/count=876; tryItOut("r0 = /(?:([]^|^){3,6}|((?=\\B)))*?/y;");
/*fuzzSeed-42369751*/count=877; tryItOut("\"use asm\"; t0[10] = ((new RegExp(\"(?=(?!(?:[\\\\r\\\\s])|^|.{4,}){0,3})*?\", \"gym\") >>>= null).valueOf(\"number\"));");
/*fuzzSeed-42369751*/count=878; tryItOut("\"use strict\"; o2.a1 = Array.prototype.slice.apply(a1, [NaN, NaN, o2, h2]);");
/*fuzzSeed-42369751*/count=879; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.max(Math.fround((Math.fround((Math.fround(( - mathy3(y, y))) < Math.fround(Math.fround((Math.PI * x))))) ** (Math.pow((x >>> 0), (((((x ? x : x) >>> 0) ? ((mathy2((Number.MIN_VALUE >>> 0), (y >>> 0)) >>> 0) | 0) : (Math.fround(( + Math.tanh((y | 0)))) < Math.fround((( ! (1/0 | 0)) | 0)))) >>> 0) >>> 0)) >>> 0))), ( ! ( + ( ! ( + (Math.asinh(((y * y) >>> 0)) / ( + 1)))))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, -Number.MAX_VALUE, 2**53-2, 2**53+2, 0x100000000, 0.000000000000001, 1, 0/0, 1/0, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, 2**53, -(2**53), 0, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 42, 0x080000000, -(2**53-2), 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000000, -(2**53+2), -1/0, 0x07fffffff, -0x100000000, 0x100000001]); ");
/*fuzzSeed-42369751*/count=880; tryItOut("mathy5 = (function(x, y) { return ( + mathy2((mathy3((mathy3(Math.fround(y), (x >>> 0)) >>> 0), ((Math.pow((( ~ ( + (((-Number.MIN_SAFE_INTEGER ? (y | 0) : x) | 0) | 0))) | 0), ((Math.log10((y | 0)) >>> 0) | 0)) | 0) >>> 0)) >>> 0), Math.acosh((Math.expm1((Math.fround(y) && 0.000000000000001)) ^ Math.log(NaN))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -0x100000000, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, -0x080000001, 2**53-2, 1.7976931348623157e308, -(2**53-2), -0x100000001, -0x080000000, 2**53, 42, 0x100000000, Number.MIN_SAFE_INTEGER, -0, 0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 1/0, 0/0, -(2**53+2), 0x080000001, 1, 2**53+2, -Number.MAX_VALUE, -(2**53), -0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 0x080000000]); ");
/*fuzzSeed-42369751*/count=881; tryItOut("(new (Date.prototype.getDate)(x = [[1]], new function(q) { \"use strict\"; return q; }(x)));");
/*fuzzSeed-42369751*/count=882; tryItOut("v2 = a0.length;function [](\u3056, \u3056, a, x = x, {}, c, y, d = this, e = false, NaN, y, b, a, x, e, c, \u3056 = this, x, x, d, x, x, eval, x, window, x, 9 = \"\\u8C3E\", delete, x, window, set, window = 4278214340, e, e, z, x, x, \u3056, x, b, w, a, x, name, x = /(?:(\\b))*/, a, x, x, x, \u3056, x, x = new RegExp(\"(?=\\ue563){0}\", \"im\"), x, x, x, e, c, c, b, x = [,,z1], getter, \u3056, y, w, b, x = \"\\u5713\", b, window, x, x = new RegExp(\"\\\\2\", \"gy\"), eval, x, w, a, c, x, d, b = \u3056, z, z = /(?!([^]\\b|(?![^])\\b))|(?!\\cC^*?+?)+$/y, x, eval, x, d, a, x, e =  '' , \u3056 = true, w, w, x, w, x, x, x, x, x, x, ...eval)(4277)");
/*fuzzSeed-42369751*/count=883; tryItOut("i1 = Proxy.create(h2, i2);\n/*MARR*/[{}, {}, function(){}, {}, function(){}, {}, function(){}, {}, {}, {}, {}, {}]\n");
/*fuzzSeed-42369751*/count=884; tryItOut("M:if((x % 6 == 2)) { if ((4277)) s2 = ''; else {h2.set = (function() { for (var j=0;j<56;++j) { f1(j%2==1); } });g1.i1.next(); }\u000c}");
/*fuzzSeed-42369751*/count=885; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x07fffffff, 0x080000000, -0x07fffffff, 0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -0x080000001, 1.7976931348623157e308, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, 1, -Number.MAX_VALUE, -(2**53), 0x0ffffffff, 2**53+2, Math.PI, 2**53-2, 0x100000000, Number.MIN_SAFE_INTEGER, -0, -1/0, -(2**53+2), 0x100000001, -0x100000000, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, -0x100000001, 1/0, -0x080000000, 42]); ");
/*fuzzSeed-42369751*/count=886; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; selectforgc(this); } void 0; }");
/*fuzzSeed-42369751*/count=887; tryItOut("\"use strict\"; i0.send(g2);(\"\\u402B\");\nnew RegExp(\"\\\\b\", \"yi\");\n");
/*fuzzSeed-42369751*/count=888; tryItOut("for (var v of p2) { try { m1.set(m2, m2); } catch(e0) { } try { var v1 = null; } catch(e1) { } try { t0 = new Uint32Array(o0.b2, 8, 4); } catch(e2) { } e2.has(e0); }");
/*fuzzSeed-42369751*/count=889; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=890; tryItOut("\"use asm\"; /*bLoop*/for (spmwqm = 0; spmwqm < 62; ++spmwqm) { if (spmwqm % 18 == 13) { return let (a)  ''  <<= x; } else { /*ODP-3*/Object.defineProperty(b1, \"valueOf\", { configurable: -8, enumerable: true, writable: false, value:  /x/  }); }  } ");
/*fuzzSeed-42369751*/count=891; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.acosh(Math.pow(Math.log10(x), Math.imul((( ~ (Math.fround(Math.atan2((y >>> 0), -0)) | x)) >>> 0), Math.imul(Math.fround((2**53+2 | Math.min(y, y))), y)))); }); testMathyFunction(mathy0, [-0x100000001, -0x100000000, -0x0ffffffff, 2**53-2, Number.MIN_VALUE, 0/0, -0x080000001, Math.PI, -(2**53+2), 2**53, -(2**53), -0x080000000, 1/0, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, 0, -0, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, 0x080000000, 42, 0x100000000, Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, 1.7976931348623157e308, 2**53+2, -(2**53-2), Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=892; tryItOut("\"use strict\"; g0.g1.v1 = this.g1.eval(\"r2 = /\\\\2|${3,}*$((?=[^\\\\cN-\\u0083\\\\cK-\\u975c\\\\W\\\\u000d-\\u77d1])\\\\S|([^])*?)/yim;\");");
/*fuzzSeed-42369751*/count=893; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.asin((( - (y | 0)) ^ ( + mathy0(( + y), ( + (Math.tanh((Math.log1p(y) | 0)) << Math.hypot(x, 1/0))))))); }); ");
/*fuzzSeed-42369751*/count=894; tryItOut("\"use strict\"; Array.prototype.forEach.apply(o2.a0, [f2]);");
/*fuzzSeed-42369751*/count=895; tryItOut("\"use strict\"; delete o2.f1[\"toSource\"];v1 = g0.runOffThreadScript();");
/*fuzzSeed-42369751*/count=896; tryItOut("\"use strict\"; delete h2.has;");
/*fuzzSeed-42369751*/count=897; tryItOut("testMathyFunction(mathy4, [-0x07fffffff, Number.MAX_VALUE, -0x080000001, -0, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, -0x100000000, 1/0, 0x0ffffffff, -(2**53), -(2**53+2), -0x080000000, 0x100000000, 0x080000001, -0x100000001, -Number.MIN_VALUE, 0, 0x080000000, -1/0, 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-42369751*/count=898; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x100000001, 0, -0x080000001, -(2**53-2), 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, 0.000000000000001, 2**53-2, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 42, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1, Number.MIN_VALUE, 0x07fffffff, -0, 1/0, 2**53, -Number.MAX_VALUE, -(2**53), 0x080000001, 1.7976931348623157e308, 0x080000000, -0x080000000, -0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=899; tryItOut("v2 = Object.prototype.isPrototypeOf.call(p2, a2);");
/*fuzzSeed-42369751*/count=900; tryItOut("i1.send(h0);");
/*fuzzSeed-42369751*/count=901; tryItOut("mathy2 = (function(x, y) { return (( ~ ((( + ( + ( ~ ( + ( - Math.round(y)))))) || Math.cos(Math.fround(mathy1(Math.fround(Math.log1p((Math.max(x, (y ? y : x)) | 0))), Math.fround(x))))) | 0)) | 0); }); testMathyFunction(mathy2, [-0x0ffffffff, 0x080000000, 1, 0x080000001, -0x100000000, Math.PI, 0/0, -0x100000001, -0x080000001, -0x080000000, -0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 42, 1/0, 0x0ffffffff, 0, 2**53-2, -0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-42369751*/count=902; tryItOut("Object.defineProperty(this, \"m2\", { configurable: true, enumerable: Math.sinh(24),  get: function() {  return new Map(a1); } });");
/*fuzzSeed-42369751*/count=903; tryItOut("mathy0 = (function(x, y) { return (Math.ceil(Math.fround(Math.fround(( - Math.fround(((x != x) >= y)))))) | 0); }); testMathyFunction(mathy0, [false, undefined, '\\0', [], (new Number(0)), '', '/0/', ({toString:function(){return '0';}}), (new String('')), objectEmulatingUndefined(), /0/, -0, NaN, (new Boolean(false)), ({valueOf:function(){return '0';}}), true, 0, 1, (new Boolean(true)), '0', (new Number(-0)), ({valueOf:function(){return 0;}}), null, (function(){return 0;}), 0.1, [0]]); ");
/*fuzzSeed-42369751*/count=904; tryItOut("\"use strict\"; ");
/*fuzzSeed-42369751*/count=905; tryItOut("var r0 = 9 ^ x; var r1 = r0 * x; var r2 = 9 % r1; var r3 = r0 * r0; var r4 = r0 & x; x = 1 + r2; var r5 = r3 ^ 2; var r6 = r0 ^ r1; var r7 = r3 + r0; var r8 = r1 * r7; var r9 = r5 | r3; var r10 = r7 + x; var r11 = r5 & 2; var r12 = r0 * r3; var r13 = 0 % r5; var r14 = r12 - r7; var r15 = r6 ^ 3; var r16 = r7 * r3; r3 = r7 ^ 0; var r17 = r9 | x; r15 = 8 + r1; var r18 = r6 % r0; r2 = r9 * 3; var r19 = 3 / r0; var r20 = r18 | r1; var r21 = 6 + r5; var r22 = 6 | r14; var r23 = r8 / r5; var r24 = r2 % 3; var r25 = 6 / r3; var r26 = r10 & r7; r6 = r16 & r10; var r27 = r23 ^ 0; var r28 = x | r0; var r29 = x & r21; print(r7); var r30 = 5 % r26; var r31 = 6 / r26; var r32 = r25 - r4; var r33 = 6 * r13; var r34 = 6 * r8; var r35 = 6 + 9; print(r19); var r36 = r30 ^ r21; var r37 = r20 / 5; var r38 = 8 + r29; var r39 = r26 - 0; r21 = 2 / r21; var r40 = r30 + r24; r33 = r38 * 8; var r41 = r17 + r0; var r42 = 5 / 8; var r43 = r13 / r42; var r44 = r18 % r13; var r45 = 5 | r43; var r46 = r29 / r18; var r47 = 9 - r16; var r48 = r27 % r10; var r49 = r0 | 2; var r50 = r8 & r11; r27 = r4 - 3; r39 = r42 - r47; r12 = r5 / x; r4 = 5 * r41; var r51 = r49 ^ r48; var r52 = r13 & r33; var r53 = r8 | r39; var r54 = r0 * 5; var r55 = r12 / r22; var r56 = r31 & 6; var r57 = r53 * r11; r29 = r22 % 6; var r58 = 1 + r46; var r59 = 8 & r7; var r60 = r39 ^ r49; r39 = r20 | r59; r2 = r24 % r5; var r61 = r38 & r25; var r62 = r24 | r6; var r63 = r35 - r58; r55 = r17 ^ r26; var r64 = r17 / r62; r36 = r25 / 2; r45 = r4 % r1; r14 = 8 * 9; var r65 = r49 * 2; var r66 = 6 % 7; var r67 = 5 ^ r54; var r68 = r40 | r36; var r69 = 3 & 9; var r70 = 1 + 3; var r71 = 1 * r23; var r72 = r58 ^ 7; var r73 = r49 - r12; var r74 = r11 % r18; var r75 = 5 ^ r15; var r76 = 0 + 8; var r77 = r55 - 6; var r78 = r7 | r7; var r79 = 4 / 1; var r80 = r18 / 0; var r81 = 1 % r73; r20 = r45 % r73; var r82 = 9 - 4; var r83 = r57 - r13; r17 = r0 / r6; var r84 = 6 & 3; var r85 = r19 | 0; var r86 = 3 & r85; var r87 = r64 % 4; var r88 = r21 & r41; var r89 = r23 & 8; r77 = r83 + r88; var r90 = r50 + 2; var r91 = r66 ^ r9; r54 = 6 | r66; var r92 = 0 / r17; var r93 = 2 * 1; print(r54); var r94 = 1 / 5; var r95 = r9 / r57; r71 = 4 | r10; var r96 = 9 & 9; var r97 = r37 + r0; var r98 = 0 ^ 6; r69 = r79 * r51; r18 = r51 / 1; var r99 = 1 & r44; var r100 = r41 / 7; var r101 = r99 & 7; var r102 = r81 & r77; var r103 = r86 % r93; var r104 = 6 / r95; var r105 = r52 ^ 2; var r106 = r31 | r99; var r107 = r71 % r66; var r108 = r81 / r34; r46 = 4 + r99; var r109 = r27 / r93; var r110 = r75 & r84; r2 = r42 + 5; r106 = 6 * r66; var r111 = 2 ^ r16; var r112 = r29 / r44; var r113 = r14 % 2; var r114 = 9 & 7; r59 = r67 * r106; var r115 = r69 | r63; var r116 = 5 / r4; var r117 = r43 ^ r17; var r118 = r51 % r20; var r119 = 7 / r107; var r120 = 6 * r70; var r121 = r76 + r86; r119 = r68 * r92; var r122 = r54 / r11; r88 = r15 + r93; var r123 = r8 * r106; var r124 = r102 ^ 2; var r125 = 3 ^ r14; print(r78); r102 = r69 % 6; var r126 = r53 & r6; var r127 = 4 + 3; var r128 = 0 ^ r21; var r129 = 4 + r28; print(r36); var r130 = r29 + r112; ");
/*fuzzSeed-42369751*/count=906; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(s2, h1);");
/*fuzzSeed-42369751*/count=907; tryItOut("testMathyFunction(mathy2, [-0x07fffffff, -(2**53+2), 0x100000001, 42, 0/0, 1, -1/0, -0x100000001, 1.7976931348623157e308, 2**53, 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 2**53+2, -0x0ffffffff, -0x080000000, -0x100000000, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -Number.MAX_VALUE, -0, 1/0, -(2**53)]); ");
/*fuzzSeed-42369751*/count=908; tryItOut("print( /* Comment */((makeFinalizeObserver('tenured'))).valueOf(new RegExp(\"^\", \"gyi\"), yield window));");
/*fuzzSeed-42369751*/count=909; tryItOut("\"use strict\"; Array.prototype.splice.apply(a2, []);");
/*fuzzSeed-42369751*/count=910; tryItOut("v0 = (e0 instanceof b1);");
/*fuzzSeed-42369751*/count=911; tryItOut("var dbteef = new ArrayBuffer(12); var dbteef_0 = new Int16Array(dbteef); var dbteef_1 = new Uint16Array(dbteef); print(dbteef_1[0]); dbteef_1[0] = 477433125.5; var dbteef_2 = new Int16Array(dbteef); dbteef_2[0] = 13; var dbteef_3 = new Int32Array(dbteef); dbteef_3[0] = 0; var dbteef_4 = new Uint32Array(dbteef); dbteef_4[0] = -6; print(dbteef_1);a1.shift(e2, this.o1.o1.e1, i1);/*RXUB*/var r = /(?=(?:\\b)|(?=[\\u0055\\cH-\u2e1f\\u0078-\u9668\\w]){4,}(?!\\D){0}|\\t+?((.)|\\3)*?)|\\3/gyim; var s = \"\"; print(s.split(r)); for (var p in o0) { try { m2.get(s0); } catch(e0) { } try { for (var p in o0) { try { v2 = g0.objectEmulatingUndefined(); } catch(e0) { } try { for (var p in p0) { try { for (var p in this.b2) { try { t0.set(t1, v0); } catch(e0) { } try { v0 = evaluate(\"for (var p in i2) { try { m2.get(v1); } catch(e0) { } a1.shift(); }\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination:  /x/g  })); } catch(e1) { } g2.f1 = Proxy.createFunction(o0.o2.h1, o1.f2, f2); } } catch(e0) { } try { m1.has(a1); } catch(e1) { } s0 = Proxy.create(h0, h0); } } catch(e1) { } selectforgc(o1); } } catch(e1) { } try { i2.toString = (function(stdlib, foreign, heap){ \"use asm\"; switch(/\\3/gyim) { default: case x: for(let w in []);break; /*RXUB*/var r = /\\D/yi; var s = \"_\"; print(uneval(r.exec(s))); print(r.lastIndex); case 2: break; case (4277): break; g2.a1[8] = p2; }\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 18446744073709552000.0;\n    i0 = ((0x0));\n    (Float64ArrayView[2]) = ((-274877906945.0));\n    {\n      i1 = (((-0x37573*(0xffffffff))|0));\n    }\n    {\n      return (((i2)-((Int32ArrayView[1]))))|0;\n    }\n    return ((((x) =  \"\" ) % (0xbd887780)))|0;\n    return (((new String('')) / (((!(i2))+(i2)) << (-0xfffff*(i2)))))|0;\n  }\n  return f; }); } catch(e2) { } this.g2.s2 += 'x'; }/*RXUB*/var r = r2; var s = (Function.prototype.call).call(/*UUV1*/(w.toString = Map.prototype.delete), dbteef_0,  '' ); print(s.replace(r,  /* Comment */({} = dbteef_1[1]))); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=912; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=913; tryItOut("mathy1 = (function(x, y) { return (Math.fround(((((Math.hypot((y >>> 0), ( + ( ~ ( + 1.7976931348623157e308)))) >>> 0) ? (Math.fround(mathy0(( + (( + (Math.atan((Math.acosh(x) | 0)) | 0)) <= ( + ( + Math.hypot(( + (42 != x)), y))))), Math.fround((Math.fround(y) === x)))) >>> 0) : (( + (( + Math.sign(Math.imul(x, y))) >>> 0)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 1/0, 0x080000000, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, -(2**53), -1/0, 1, -0x100000001, -0x080000000, -(2**53+2), 1.7976931348623157e308, 2**53, -0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0, -0, Number.MAX_VALUE, 0x0ffffffff, 0x100000001, -0x100000000, Math.PI, 0x07fffffff, 2**53-2, -0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, 0x080000001, 2**53+2]); ");
/*fuzzSeed-42369751*/count=914; tryItOut("g0.v1 = evalcx(\"o1 + '';\", g0);");
/*fuzzSeed-42369751*/count=915; tryItOut("\"use strict\"; print(uneval(i2));");
/*fuzzSeed-42369751*/count=916; tryItOut("e1.add(v1);");
/*fuzzSeed-42369751*/count=917; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=\\2)/; var s = \"\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=918; tryItOut("mathy2 = (function(x, y) { return ( ! ( ! (Math.cosh(Math.fround(Math.asin((Math.hypot(y, Math.imul(-Number.MAX_SAFE_INTEGER, x)) | 0)))) >>> 0))); }); testMathyFunction(mathy2, [-(2**53+2), -0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, -(2**53-2), 0, 0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, 42, 2**53-2, 1/0, -Number.MIN_SAFE_INTEGER, -0, -0x080000000, 0x100000001, -1/0, -(2**53), 0.000000000000001, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -0x0ffffffff, Math.PI, -0x100000001, -0x07fffffff, 2**53]); ");
/*fuzzSeed-42369751*/count=919; tryItOut("testMathyFunction(mathy3, [[0], objectEmulatingUndefined(), '0', ({valueOf:function(){return 0;}}), (new String('')), (new Number(-0)), null, ({toString:function(){return '0';}}), true, '\\0', 0.1, 0, [], (new Number(0)), NaN, '', ({valueOf:function(){return '0';}}), /0/, 1, -0, (function(){return 0;}), '/0/', (new Boolean(false)), (new Boolean(true)), false, undefined]); ");
/*fuzzSeed-42369751*/count=920; tryItOut("\"use strict\"; testMathyFunction(mathy0, [1, 2**53-2, -0x080000000, Math.PI, 0x0ffffffff, 1/0, -0x07fffffff, 0.000000000000001, -(2**53+2), 0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), 0x100000000, 0x080000000, 0x07fffffff, -0x100000001, 0x080000001, -0x080000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 2**53, 1.7976931348623157e308, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -0x100000000, 42, -(2**53-2), -0, -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=921; tryItOut("m2.set(g2, window);");
/*fuzzSeed-42369751*/count=922; tryItOut("\"use strict\"; v1 = this.a2.reduce, reduceRight((function() { try { Array.prototype.reverse.apply(a1, [this.o2]); } catch(e0) { } try { a1.forEach((function() { for (var j=0;j<63;++j) { f2(j%2==0); } })); } catch(e1) { } for (var v of s0) { try { x = this.g1; } catch(e0) { } try { Array.prototype.reverse.apply(a1, []); } catch(e1) { } try { this.p2 = t2[12]; } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(e0, o2); } return p0; }), m2);");
/*fuzzSeed-42369751*/count=923; tryItOut("t2 = t1.subarray(12, 18);");
/*fuzzSeed-42369751*/count=924; tryItOut("/*RXUB*/var r = new RegExp(\"((?:.))+?\", \"im\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-42369751*/count=925; tryItOut("v1 = Object.prototype.isPrototypeOf.call(t0, o2.g0);");
/*fuzzSeed-42369751*/count=926; tryItOut("L:switch((eval).call) { case 0: /*tLoop*/for (let y of /*MARR*/[Infinity,  /x/g ,  /x/g ,  /x/g ,  /x/g , Infinity, Infinity, new Number(1), Infinity, Infinity, Infinity,  /x/g , Infinity, Infinity, Infinity, Infinity, new Number(1), Infinity, new Number(1),  /x/g , new Number(1),  /x/g ,  /x/g , new Number(1), Infinity,  /x/g , new Number(1),  /x/g , new Number(1), Infinity,  /x/g , Infinity,  /x/g , new Number(1),  /x/g , new Number(1), new Number(1), Infinity, Infinity, Infinity,  /x/g , Infinity, Infinity, Infinity, new Number(1), Infinity, new Number(1),  /x/g ,  /x/g , Infinity, Infinity, new Number(1), new Number(1), Infinity, Infinity, Infinity,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Number(1), Infinity, Infinity,  /x/g , Infinity, new Number(1), Infinity, new Number(1), new Number(1), new Number(1),  /x/g ,  /x/g , Infinity, Infinity, Infinity, Infinity, new Number(1), Infinity, Infinity, new Number(1), new Number(1),  /x/g , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  /x/g ,  /x/g ,  /x/g , Infinity, Infinity, Infinity, new Number(1), Infinity,  /x/g , Infinity,  /x/g , Infinity,  /x/g ,  /x/g , new Number(1), Infinity, new Number(1),  /x/g ,  /x/g , Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new Number(1), Infinity, Infinity, new Number(1),  /x/g , Infinity, Infinity,  /x/g , new Number(1),  /x/g ,  /x/g , Infinity, Infinity, new Number(1),  /x/g , Infinity, new Number(1),  /x/g , new Number(1),  /x/g ,  /x/g , new Number(1),  /x/g , Infinity, new Number(1),  /x/g , new Number(1), new Number(1), Infinity, Infinity, new Number(1), new Number(1), new Number(1), Infinity, new Number(1),  /x/g , Infinity, new Number(1),  /x/g , Infinity, new Number(1),  /x/g , new Number(1), Infinity, Infinity,  /x/g ]) { print( /x/ .valueOf(\"number\")); }break; v1 = Object.prototype.isPrototypeOf.call(i0, e2);break; case [] = (/*FARR*/[intern(x), x].map): m2.delete(x);(void schedulegc(g0)); }");
/*fuzzSeed-42369751*/count=927; tryItOut("testMathyFunction(mathy5, [-Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, 2**53, 0.000000000000001, 42, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 1/0, 0x07fffffff, -0x07fffffff, -(2**53), 0x100000000, 0x0ffffffff, 0, -0x080000001, 0/0, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 0x080000000, 2**53+2, Math.PI, 0x080000001, -(2**53-2), 0x100000001]); ");
/*fuzzSeed-42369751*/count=928; tryItOut("{;print(-17);r2 = new RegExp(\"(?:$)\", \"yi\"); }");
/*fuzzSeed-42369751*/count=929; tryItOut("v1 = (g1 instanceof h0);");
/*fuzzSeed-42369751*/count=930; tryItOut("Array.prototype.pop.call(a0, h1);");
/*fuzzSeed-42369751*/count=931; tryItOut("e2.delete(t1);");
/*fuzzSeed-42369751*/count=932; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((3.022314549036573e+23) < (+(((i1)-(/*FFI*/ff()|0)+((-67108865.0) < (-1125899906842624.0))) << ((!(i1))))));\n    i1 = (i1);\n    (Uint8ArrayView[((abs((abs((abs((abs((-0x8000000))|0))|0))|0))|0) % (~(((~~(9223372036854776000.0)))-((0x5d31ca4e) <= (0x29d72885))))) >> 0]) = ((i1)-((((i0)+(i1))>>>((0xeb2249aa)+(((((0xf4360f40) < (0x1c24ddaa))-(i0))>>>((-0x8000000)-(0xb0a1504b)+(0xfd7ae77f))))))));\n    return +((+(((i1)+(i0)) & (-(i1)))));\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MIN_VALUE, -0x080000001, 0x07fffffff, -0x080000000, 0.000000000000001, 2**53-2, 1/0, 1.7976931348623157e308, -1/0, 2**53+2, -0x100000001, -Number.MAX_VALUE, -0, -0x100000000, -(2**53), Number.MAX_VALUE, 1, -(2**53+2), 0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, -Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), Math.PI, 0x100000001, 42, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=933; tryItOut("mathy2 = (function(x, y) { return (( ~ Math.fround(Math.atan2(Math.fround((( + x) <= (Math.log2(( + Math.fround((((y >>> 0) , (x >>> 0)) >>> 0)))) >>> 0))), Math.fround(Math.fround((Math.fround(y) , y)))))) ? Math.cosh((((y & mathy1(y, 1)) >>> 0) | 0)) : ( ~ (Math.atanh(Math.fround((((Math.log(y) % (mathy1((x >>> 0), (x >>> 0)) >>> 0)) >>> 0) || (1.7976931348623157e308 >>> 0)))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[x, objectEmulatingUndefined(), x, Infinity, Infinity, [], objectEmulatingUndefined(), objectEmulatingUndefined(), [], objectEmulatingUndefined(), [], x, x, x]); ");
/*fuzzSeed-42369751*/count=934; tryItOut("/*RXUB*/var r = ((function a_indexing(xooaku, iinisa) { yield this;; if (xooaku.length == iinisa) { \u0009((new ( /x/g )(-7)));; return ({} = x); } var iqovty = xooaku[iinisa]; var mpmiqp = a_indexing(xooaku, iinisa + 1); /*infloop*/while((uneval(18.__defineGetter__(\"e\", objectEmulatingUndefined))))\"\\uA2FA\"; })(/*MARR*/[false, function(){}, false, .2, function(){}, null, .2, function(){}, false, .2, false, function(){}, function(){}, .2, .2, null, false, false, false, function(){}], 0)); var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=935; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.round(Math.cos(Math.atanh(( ! (((y >>> 0) >= (( - ( + (x ? ( + -Number.MAX_SAFE_INTEGER) : ( + y)))) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-42369751*/count=936; tryItOut("mathy4 = (function(x, y) { return (((Math.atan2(Math.sign(y), x) >>> 0) % (( + ( ! ((Math.pow((( - Math.min(0x080000000, y)) | 0),  /x/g ) >>> 0) | 0))) >>> 0)) > ( + (mathy2((mathy1(Math.trunc(0x07fffffff), (((x ^ ( + x)) >>> 0) >>> 0)) >>> 0), Math.fround(x)) / Math.fround(Math.pow(Math.fround(y), Math.fround(Math.imul(( + y), y))))))); }); testMathyFunction(mathy4, [0x100000000, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, Math.PI, -(2**53-2), 1/0, -Number.MIN_VALUE, -0x07fffffff, -(2**53), 0x080000000, 1, 2**53-2, -0x100000001, -0, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 2**53, Number.MAX_VALUE, 0x080000001, 0.000000000000001, 0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, 2**53+2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, -0x080000000, -0x080000001]); ");
/*fuzzSeed-42369751*/count=937; tryItOut("print(x);");
/*fuzzSeed-42369751*/count=938; tryItOut("{ void 0; void relazifyFunctions('compartment'); }");
/*fuzzSeed-42369751*/count=939; tryItOut("\"use strict\"; if(false) { if (true) {print((\"\\uB23A\" ? -9 : x)); } else print(x);}");
/*fuzzSeed-42369751*/count=940; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.exp(((x ? (( - (x >>> 0)) >>> 0) : Math.trunc(( ~ ( + ( - ( + ( + ( + x)))))))) | 0)) | 0) / ( + ( + ( + ((y >>> 0) < Math.fround(Math.min((x >>> 0), x))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, 2**53+2, 0x080000001, -0x080000001, 1, 0.000000000000001, 0x100000000, Math.PI, 1.7976931348623157e308, -(2**53+2), 0/0, 0x0ffffffff, 0x07fffffff, -1/0, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, -0, Number.MIN_VALUE, 2**53-2, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, -(2**53-2), -0x100000001, 0, 1/0]); ");
/*fuzzSeed-42369751*/count=941; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ (( + Math.log2(( + ( + ( + 0x080000000))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, -0x080000001, 0, 2**53+2, 2**53, 2**53-2, 0x0ffffffff, 0.000000000000001, -0x100000001, 0x100000000, -0, Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, -0x0ffffffff, 42, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -(2**53-2), -0x100000000, -1/0, -(2**53), Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-42369751*/count=942; tryItOut("mathy4 = (function(x, y) { return (( - ( + Math.imul(Math.fround(Math.imul(( + ( + ((Math.imul((y | 0), (x | 0)) >>> 0) | 0))), ( + Math.atan2(( + mathy2(0.000000000000001, y)), ( + x))))), Math.fround((( ! y) | Math.min(mathy1(( + Math.fround(( ! (x >>> 0)))), ( + Math.fround(( ~ x)))), ( + (( + y) && ( + x))))))))) | 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 42, Number.MAX_VALUE, 1, -0x07fffffff, 0x080000000, 1/0, -0x100000000, 2**53-2, -(2**53-2), 0/0, 2**53+2, -0, 0x100000001, -0x080000000, 0, -Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), 0x080000001, 2**53, 0.000000000000001, -0x080000001, -0x100000001, -(2**53), Math.PI, 0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=943; tryItOut("\"use strict\"; a2.reverse(o2.i1);");
/*fuzzSeed-42369751*/count=944; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.atan2(Math.fround(((((((y !== x) | 0) | 0) || (( + Math.acos(x)) | 0)) << ( - ((Math.cos((y >>> 0)) >>> 0) >>> 0))) * (y < ((x >>> 0) ^ Math.fround(( + 1)))))), (Math.sin((Math.ceil(y) | 0)) | 0)); }); testMathyFunction(mathy3, /*MARR*/[x]); ");
/*fuzzSeed-42369751*/count=945; tryItOut("x = g0.i2;");
/*fuzzSeed-42369751*/count=946; tryItOut("v0 = t1.byteLength;");
/*fuzzSeed-42369751*/count=947; tryItOut("a2.sort((function mcc_() { var wcqdri = 0; return function() { ++wcqdri; o2.f1(/*ICCD*/wcqdri % 4 == 0);};})());");
/*fuzzSeed-42369751*/count=948; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.asin(mathy0(( + ( ~ ( + Math.fround(Math.pow((x , (Math.sqrt(x) >>> 0)), Math.fround(y)))))), mathy0(( + Math.hypot((1 >>> 0), (( + (y >>> 0)) >>> 0))), ((((x > (Math.sinh(x) | 0)) | 0) > y) | 0)))); }); ");
/*fuzzSeed-42369751*/count=949; tryItOut("function f1(s0) \"use asm\";   var NaN = stdlib.NaN;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    i0 = ((0xb8e9b4dc));\n    {\n      i1 = (((((NaN) != (-4.835703278458517e+24))) >> ((((((0x5be91bfa) > (0xfafbd6b5))*-0xa7064) >> (((0xb64014e8) > (0x190df9d5))-(i0)-(i0))))-(i0)+(\u3056 = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: z => \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+((((Float64ArrayView[1])) % ((d1)))));\n    return +((Float32ArrayView[((((((((0xf97d09bb)) << ((((0x62480d87)) >> ((0x3a91c19e))))))+(0xb35c6a66)) << (((((0x95762db3))>>>((0x30dbe026))) == (0x37775f1c))-(0x29a13177)+(0xff027841))))) >> 2]));\n  }\n  return f;, keys: function() { return []; }, }; })( '' ), (new Function(\"print(uneval(f0));\")), offThreadCompileScript)))));\n    }\n    {\n      i0 = (0xfc5f00f2);\n    }\n    return +((Float32ArrayView[((0xff5b1570)+(i0)) >> 2]));\n  }\n  return f;");
/*fuzzSeed-42369751*/count=950; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.imul((function shapeyConstructor(brymwj){{ /*RXUB*/var r = /(?:(?:\\d)(?!\\3*)((?=$[^]))*|\\D.\\B+?|\ue0a3{4}|\\w*+?)/gim; var s = \"\"; print(s.split(r));  } Object.freeze(this);{ (null); } delete this[new String(\"16\")];delete this[new String(\"16\")];Object.defineProperty(this, new String(\"16\"), ({configurable: (4277), enumerable: false}));{ i1.send(g1); } return this; } | 0), ( + ( - ( + Math.log2(y))))) >>> 0); }); testMathyFunction(mathy1, [2**53, 2**53-2, Number.MIN_VALUE, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 0/0, -0x100000000, 0x100000000, 0x080000001, -0x07fffffff, 1, 42, -0x080000001, -1/0, -(2**53), -0, -0x100000001, -0x0ffffffff, -0x080000000, 0.000000000000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-42369751*/count=951; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ! Math.fround((((mathy0(x, ( + ((( + Math.fround(y)) >>> 0) <= (( + (Math.round(y) | 0)) >>> 0)))) | 0) ? y : (mathy0(y, y) >>> 0)) , (Math.pow(( + Math.log10(Math.fround(Math.imul(0x100000000, -0x07fffffff)))), x) >>> 0)))); }); testMathyFunction(mathy1, [-(2**53-2), -(2**53+2), 0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 0/0, 0x080000001, 42, 0x0ffffffff, 0x07fffffff, 2**53, 0, -(2**53), -0x100000000, 2**53+2, -0x100000001, 1, -Number.MAX_VALUE, -0x07fffffff, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -0, 1/0, Math.PI, 2**53-2, 0x080000000]); ");
/*fuzzSeed-42369751*/count=952; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ~ (Math.tanh(Math.fround((Math.fround(( + ( + (((y | 0) > (x | 0)) | 0)))) || x))) | 0)); }); testMathyFunction(mathy3, [-(2**53+2), 0x07fffffff, 0, -(2**53), Number.MIN_VALUE, 0x100000000, 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0x100000001, Math.PI, 0/0, 0.000000000000001, 0x0ffffffff, 2**53+2, -0x080000000, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, 1/0, 2**53-2, -0x0ffffffff, -Number.MAX_VALUE, 42, -(2**53-2), 2**53, -0x100000001, -1/0, -0x080000001]); ");
/*fuzzSeed-42369751*/count=953; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((0xffffffff)-(i0)))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var sfqkbl = z = x; (Int16Array)(); })}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [(new Number(-0)), ({toString:function(){return '0';}}), '\\0', ({valueOf:function(){return '0';}}), '/0/', (new Number(0)), [0], NaN, undefined, 0.1, (new String('')), (new Boolean(true)), /0/, (function(){return 0;}), false, true, 0, 1, (new Boolean(false)), '0', '', null, [], objectEmulatingUndefined(), -0, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-42369751*/count=954; tryItOut("\"use strict\"; var ribymg = new ArrayBuffer(16); var ribymg_0 = new Uint16Array(ribymg); ribymg_0[0] = 29; var ribymg_1 = new Int8Array(ribymg); print(ribymg_1[0]); var ribymg_2 = new Int32Array(ribymg); print(ribymg_1[10]);print(ribymg_1[0]);/*ADP-3*/Object.defineProperty(a2, 3, { configurable: true, enumerable:  '' , writable: true, value: i2 });this.f1 = Proxy.createFunction(h2, f2, f2);t2[0];a0.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = 2 & 1; var r1 = a5 & a5; ribymg_0[2] = a10 ^ r1; var r2 = ribymg_0 % 9; var r3 = 3 ^ r2; var r4 = ribymg_1[0] * a7; a1 = 0 / x; var r5 = ribymg_1[0] & a3; var r6 = ribymg_0[0] % a2; r5 = 1 | 6; var r7 = ribymg_1[0] | a8; var r8 = ribymg_0[2] % ribymg_2[0]; var r9 = r5 - 0; var r10 = ribymg_0[2] - 4; return ribymg; }), i0, f0, h2);offThreadCompileScriptthis.g0.v0 = o0.g0.eval(\"t2.__proto__ = m0;\");var v2 = evalcx(\"( \\\"\\\" );\", g0);v2 = -0;(\"\\u7771\");");
/*fuzzSeed-42369751*/count=955; tryItOut("o2 = {};");
/*fuzzSeed-42369751*/count=956; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.hypot(Math.fround(Math.max(( - (Math.min((x >>> 0), (y >>> 0)) | 0)), Math.fround((x >>> ( ! (x ** ( + ( + Math.min(( + x), ( + y)))))))))), Math.pow(( + Math.log2(Math.fround(Math.acosh(Math.hypot(0x080000000, (Math.fround(((Math.hypot((y | 0), (-0x100000001 | 0)) | 0) ** ( + x))) | 0)))))), Math.hypot(Math.pow((y | 0), (x | 0)), Math.sin(Math.asin(x))))); }); ");
/*fuzzSeed-42369751*/count=957; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=958; tryItOut("mathy1 = (function(x, y) { return Math.sqrt((Math.clz32((( + ((y > Math.acosh(mathy0(x, -0x100000000))) >>> 0)) >>> 0)) >>> (Math.hypot(Math.fround(Math.pow((y >>> 0), y)), Math.fround((Math.fround(Math.sinh(Math.fround(y))) < Math.fround((( + ( + y)) | 0))))) >>> 0))); }); testMathyFunction(mathy1, [-0x080000001, 1/0, 0/0, -(2**53-2), 0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0x07fffffff, 0, -Number.MAX_VALUE, 42, -(2**53), -0x080000000, -0, 0x080000000, 0x100000001, -1/0, 1, 2**53, Number.MAX_VALUE, 2**53-2, 0.000000000000001, -Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001]); ");
/*fuzzSeed-42369751*/count=959; tryItOut("testMathyFunction(mathy4, /*MARR*/[ /x/g ,  /x/g ,  /x/g , new Boolean(true), new Boolean(true),  /x/g ,  /x/g ,  /x/g ,  /x/g , null, null,  /x/g , null, null, null, new Boolean(true), new Boolean(true), null, new Boolean(true),  /x/g , new Boolean(true),  /x/g , new Boolean(true), new Boolean(true), new Boolean(true),  /x/g ,  /x/g , new Boolean(true), null,  /x/g , null,  /x/g ,  /x/g ,  /x/g , null, null, new Boolean(true), new Boolean(true), null, new Boolean(true), null, new Boolean(true), new Boolean(true), null, null, null, null, new Boolean(true),  /x/g , new Boolean(true),  /x/g , new Boolean(true),  /x/g ,  /x/g , new Boolean(true), null,  /x/g ,  /x/g , new Boolean(true),  /x/g , null, null, null, null,  /x/g , null, null]); ");
/*fuzzSeed-42369751*/count=960; tryItOut("\"use strict\"; m0 = new Map;");
/*fuzzSeed-42369751*/count=961; tryItOut("v1 = Object.prototype.isPrototypeOf.call(this.a2, v2);");
/*fuzzSeed-42369751*/count=962; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.pow(Math.max((Math.trunc(((((-1/0 | 0) | (x | 0)) & x) >>> 0)) | 0), x), ((( - Math.pow(-(2**53+2), x)) - ( + Math.fround(Math.max(Math.fround(Math.cos(1)), Math.fround(x))))) >= (Math.trunc(((Math.hypot(x, x) | 0) | 0)) | 0)))) | 0) ? ((Math.log1p(Math.fround(Math.log2(Math.fround(( ~ x))))) >>> 0) | 0) : ((Math.atan2(y, Math.fround(x)) ? Math.log2(Math.fround(( ~ (Math.tan((( ! x) >>> 0)) >>> 0)))) : ( + (( ~ Math.fround((Math.fround(Math.trunc(Math.fround(x))) >= (Math.fround(Math.cbrt(Math.fround(0x07fffffff))) == Math.fround(Math.fround(( ! Math.fround(-0x080000000)))))))) ? Math.min(Math.fround(( ! Math.hypot(y, y))), Number.MAX_SAFE_INTEGER) : ((y | 0) ** (Math.atan2((( + y) !== -1/0), Math.fround(Math.imul(Math.fround(y), Math.fround((Math.min((y >>> 0), Math.fround(y)) >>> 0))))) | 0))))) | 0)) | 0); }); ");
/*fuzzSeed-42369751*/count=963; tryItOut("testMathyFunction(mathy0, [0x080000001, 1.7976931348623157e308, -(2**53+2), 0x0ffffffff, -0x100000001, Number.MAX_VALUE, 0.000000000000001, -0x100000000, 0/0, 1, 0x100000000, -(2**53-2), 2**53, 0x07fffffff, -0, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 42, 1/0, -0x07fffffff, -0x0ffffffff, Math.PI, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0, 0x080000000, -1/0]); ");
/*fuzzSeed-42369751*/count=964; tryItOut("mathy1 = (function(x, y) { return (Math.fround(Math.cosh(Math.fround((((Math.ceil((Math.hypot(x, Math.fround(Math.tanh((x >>> 0)))) >>> 0)) >>> 0) | 0) ** (1 | 0))))) >>> Math.clz32(Math.tan(Math.fround(Math.cbrt(y))))); }); testMathyFunction(mathy1, /*MARR*/[true]); ");
/*fuzzSeed-42369751*/count=965; tryItOut("/*RXUB*/var r = /([^]{0}[^][\uf0d8-\u008d\u00f3-\\f\\B-\u008e\\t-\u5e42]{0}|(?!\\D+?)\\3*?|\\b?)/; var s = \"11\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=966; tryItOut("L: /*RXUB*/var r = /(?:\\3|(?![\\s]))/gy; var s = ({}); print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=967; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + ( ! ( ~ ( + ( ! ( + x)))))); }); ");
/*fuzzSeed-42369751*/count=968; tryItOut("for (var p in m2) { e2 + s2; }");
/*fuzzSeed-42369751*/count=969; tryItOut("a1.shift(g1, o1.o0.t1);");
/*fuzzSeed-42369751*/count=970; tryItOut("if((x % 32 != 22)) { if ((void options('strict'))) v1 = 4;} else {/*hhh*/function gbtpay(x, y){/*wrap2*/(function(){ var hckzwq =  /x/ ; var agyysf = hckzwq; return agyysf;})()}gbtpay( '' , false); }");
/*fuzzSeed-42369751*/count=971; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.imul(Math.fround((Math.hypot((( + Math.log(y)) >>> 0), Math.fround(( + Math.imul(mathy2(x, ((Math.fround(-(2**53+2)) ? (y >>> 0) : (x >>> 0)) >>> 0)), mathy0(mathy2((((y >>> 0) % y) | 0), ( + 0x100000001)), x))))) >>> 0)), Math.fround((( - ( + (( + ( + (( + y) ? ( + Math.fround(Math.imul(Math.fround(1.7976931348623157e308), y))) : ( + x)))) == ( + x)))) ? (-1.yoyo( /x/ ))\n : Math.hypot((y >>> 0), ( ~ (y | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[(0/0), (void 0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))),  /x/ , ((let (x = x) true)(Math.hypot( ''  in  '' , 28))), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))), ({}), (0/0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))),  /x/ , ((let (x = x) true)(Math.hypot( ''  in  '' , 28))), (0/0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))), (0/0), ({}), ({}), (void 0), (0/0), (void 0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))),  /x/ ,  /x/ , (void 0),  /x/ , (0/0), (void 0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))), (void 0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))),  /x/ ,  /x/ , (void 0), (void 0), (0/0), (void 0), (void 0), (0/0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))),  /x/ , (0/0),  /x/ ,  /x/ , (0/0), (0/0), ((let (x = x) true)(Math.hypot( ''  in  '' , 28))),  /x/ , ({}),  /x/ , ({})]); ");
/*fuzzSeed-42369751*/count=972; tryItOut("o2.m0.has(v1);");
/*fuzzSeed-42369751*/count=973; tryItOut("\"use strict\"; /*vLoop*/for (zgkuzx = 0; zgkuzx < 70; ++zgkuzx) { let d = zgkuzx; /*bLoop*/for (var exsaud = 0; exsaud < 30; ++exsaud) { if (exsaud % 5 == 0) { print(x); } else { ({a1:1}); }  }  } ");
/*fuzzSeed-42369751*/count=974; tryItOut("mathy4 = (function(x, y) { return Math.log1p(( ! ( + (Math.max(y, (-Number.MIN_SAFE_INTEGER | 0)) >>> 0)))); }); ");
/*fuzzSeed-42369751*/count=975; tryItOut("testMathyFunction(mathy5, [0x080000000, -(2**53-2), 0x080000001, 2**53-2, 0/0, -0x0ffffffff, 0x07fffffff, -0x080000000, 0x100000001, -0x100000000, Number.MAX_VALUE, 2**53, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -0x07fffffff, 1, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, -0, -(2**53+2), Math.PI, -1/0, -Number.MAX_VALUE, 0, 0.000000000000001, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=976; tryItOut("g2 + i1;");
/*fuzzSeed-42369751*/count=977; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (mathy1(((Math.sign(( + (( + x) ? Math.pow(42, ( - x)) : x))) ** (( + (( + ( + Math.atan2(( + 2**53-2), ( + ( ! -Number.MIN_VALUE))))) , ( + y))) + (Math.pow((Math.fround(( ~ Math.fround(x))) | 0), Math.fround(0x100000000)) | 0))) | 0), (mathy2(Math.atan2(y, (Math.log2(Math.fround((Math.expm1(((y + x) | 0)) | 0))) | 0)), Math.abs(x)) | 0)) | 0); }); testMathyFunction(mathy5, [2**53+2, -Number.MAX_VALUE, 0x07fffffff, -(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), -(2**53+2), 2**53, -0x07fffffff, 0x080000001, -0x080000001, 0x080000000, 0x100000000, -1/0, 0/0, 1, Math.PI, Number.MAX_SAFE_INTEGER, 2**53-2, -0, -Number.MAX_SAFE_INTEGER, 0x100000001, 0, -Number.MIN_VALUE, -0x100000000, -0x080000000, -0x100000001, -0x0ffffffff, 42, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=978; tryItOut("\"use strict\"; f0.valueOf = (function mcc_() { var zmrdew = 0; return function() { ++zmrdew; if (/*ICCD*/zmrdew % 7 == 5) { dumpln('hit!'); try { for (var v of a0) { try { for (var p in m2) { try { m0.get(b1); } catch(e0) { } v2.__proto__ = t1; } } catch(e0) { } o0.o1.e0.add(this.b1); } } catch(e0) { } try { print(uneval(b2)); } catch(e1) { } try { for (var p in p0) { try { for (var p in v0) { try { g0.i0.__proto__ = o0.s2; } catch(e0) { } try { print(s2); } catch(e1) { } try { v1 = Object.prototype.isPrototypeOf.call(s0, h2); } catch(e2) { } v1 = new Number(h1); } } catch(e0) { } try { t1 = t1.subarray( \"\" ); } catch(e1) { } try { s1 += s0; } catch(e2) { } this.f0.toSource = (function mcc_() { var tsduiv = 0; return function() { ++tsduiv; if (tsduiv > 5) { dumpln('hit!'); try { g1.g1.m0.set(o1, g2); } catch(e0) { } try { /*ODP-3*/Object.defineProperty(b0, \"isNaN\", { configurable: false, enumerable: (x % 52 == 21), writable: true, value: b1 }); } catch(e1) { } try { e1.has(o2.a0); } catch(e2) { } o1.p1.__proto__ = a0; } else { dumpln('miss!'); try { selectforgc(o2); } catch(e0) { } try { s0.__iterator__ = function (a)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((d1));\n  }\n  return f;; } catch(e1) { } o1.f2 = g0.objectEmulatingUndefined(); } };})(); } } catch(e2) { } for (var p in o0.h1) { try { f2 + o1; } catch(e0) { } try { g1.t1 = new Int32Array(a0); } catch(e1) { } v1 = evaluate(\"function f0(b2)  { yield false } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: false })); } } else { dumpln('miss!'); try { /*MXX2*/g2.SyntaxError.name = this.i2; } catch(e0) { } try { this.t2 = new Uint8ClampedArray(o0.a2); } catch(e1) { } e1.delete(b1); } };})();\nprint(x);\n");
/*fuzzSeed-42369751*/count=979; tryItOut("/*MXX3*/g0.WeakMap.prototype.delete = g1.WeakMap.prototype.delete;");
/*fuzzSeed-42369751*/count=980; tryItOut("\"use strict\"; v2 = (o1.t1 instanceof this.s2);");
/*fuzzSeed-42369751*/count=981; tryItOut("x = linkedList(x, 481);");
/*fuzzSeed-42369751*/count=982; tryItOut("testMathyFunction(mathy0, [-(2**53+2), 0/0, 0, -(2**53-2), Number.MAX_VALUE, -Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000000, -0, -0x080000000, 0x07fffffff, -0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, -0x080000001, -0x07fffffff, -1/0, -0x100000000, 2**53, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), Math.PI, 2**53-2, 0.000000000000001, 1/0, 1, -0x100000001, 0x100000000, 0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=983; tryItOut("Array.prototype.shift.apply(a0, [g2]);");
/*fuzzSeed-42369751*/count=984; tryItOut("v1 = (m2 instanceof o0);");
/*fuzzSeed-42369751*/count=985; tryItOut("\"use strict\"; for (var p in s2) { delete i0[\"__count__\"]; }");
/*fuzzSeed-42369751*/count=986; tryItOut("x;");
/*fuzzSeed-42369751*/count=987; tryItOut("\"use strict\"; t1[0] = w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: (let (e=eval) e), defineProperty: String.raw, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(x),  \"\" , Date.prototype.getUTCSeconds);");
/*fuzzSeed-42369751*/count=988; tryItOut("testMathyFunction(mathy0, [-0x080000000, -0x100000001, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 1/0, 2**53, 2**53-2, -(2**53-2), -0x080000001, 1, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, -(2**53), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, 0x100000001, 42, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0x0ffffffff, 0.000000000000001, -0, 0/0, -0x100000000, 0x100000000, 2**53+2, Math.PI]); ");
/*fuzzSeed-42369751*/count=989; tryItOut("testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, -(2**53), Math.PI, 42, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, -(2**53-2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -1/0, -0x0ffffffff, -(2**53+2), 0x080000000, -0x07fffffff, -0x100000001, 1.7976931348623157e308, 2**53, 2**53-2, -0, 1, 1/0, 0x100000000, 2**53+2, 0x100000001]); ");
/*fuzzSeed-42369751*/count=990; tryItOut("\"use strict\"; with((a) = (p={}, (p.z = x)())){v0 = Object.prototype.isPrototypeOf.call(this.t0, v0);/*RXUB*/var r = r0; var s = \"\"; print(s.replace(r, ''));  }");
/*fuzzSeed-42369751*/count=991; tryItOut("Array.prototype.unshift.apply(a1, [b0, a1]);function a(x) { \"use strict\"; return (x == (p={}, (p.z = /(?!(?=\\1).+)\\3\\3{0}/)())) } this.v1 = Object.prototype.isPrototypeOf.call(m2, v2);");
/*fuzzSeed-42369751*/count=992; tryItOut("/*vLoop*/for (hoimbe = 0; hoimbe < 34; ++hoimbe) { let e = hoimbe; s1 += 'x'; } ");
/*fuzzSeed-42369751*/count=993; tryItOut("\"use strict\"; (this.throw([z1,,]));");
/*fuzzSeed-42369751*/count=994; tryItOut("a0.sort((function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Float64ArrayView[2]) = ((268435456.0));\n    (Float32ArrayView[((i1)-(i1)-(i1)) >> 2]) = ((+pow(((8796093022209.0)), ((1.0)))));\n    i1 = (0x9e571b3b);\n    (Int8ArrayView[(-0x2c134*((0xc88e108b))) >> 0]) = ((0x4dc75361));\n    i2 = (1);\n    {\n      i2 = (i2);\n    }\n    return +((-((-1152921504606847000.0))));\n    i0 = (i2);\n;    (Float32ArrayView[0]) = ((-32769.0));\n    {\n      i2 = ((((1)) | (((((i1)+(i1)+(i2))>>>((!(i2))+((((0xffffffff))>>>((0xfdccc2f4))))+(1)))))));\n    }\n    (Int8ArrayView[((i0)) >> 0]) = (x);\n    i1 = (i2);\n    i1 = (((i0) ? (+(0.0/0.0)) : ((4277))) == (4.722366482869645e+21));\n    switch ((~((i2)+(i1)))) {\n      default:\n        i1 = (i2);\n    }\n    i0 = (((((x) >= ((-0xfffff*((0x79da255d)))>>>((i2)-(i1))))+(i1))>>>((i2))));\n    i2 = (i0);\n    return +(((+(0.0/0.0)) + (+((-1.1805916207174113e+21)))));\n  }\n  return f; }));");
/*fuzzSeed-42369751*/count=995; tryItOut("\"use asm\"; m1.get(b1);");
/*fuzzSeed-42369751*/count=996; tryItOut("this.a1.reverse();");
/*fuzzSeed-42369751*/count=997; tryItOut("\"use strict\"; Object.preventExtensions(i0);switch(this.__defineSetter__(\"z\", new RegExp(\"(?!\\\\1)\", \"gy\"))) { case 6: m0.has(e1); }e1.add(b2);");
/*fuzzSeed-42369751*/count=998; tryItOut("p0.__proto__ = i0;");
/*fuzzSeed-42369751*/count=999; tryItOut("\"use strict\"; e0.add(b1);");
/*fuzzSeed-42369751*/count=1000; tryItOut("mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return (( + (Math.fround((( ! Math.fround((Math.fround((((y | 0) + (0 | 0)) | 0)) < Math.fround(( ! Math.min(0x0ffffffff, y)))))) && Math.fround(( + ( ~ (( + (Number.MIN_SAFE_INTEGER >>> 0)) | 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [2**53-2, -(2**53), 0x07fffffff, 0, 1/0, 1.7976931348623157e308, -0x0ffffffff, -0x080000001, -(2**53-2), 0x100000001, -Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -0x080000000, 0/0, 2**53+2, 0x0ffffffff, -0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, 0.000000000000001, -0x07fffffff, 1, 0x100000000, 0x080000000, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-42369751*/count=1001; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.5111572745182865e+23;\n    return ((((0x7c6d7644) == (((0xffffffff)-(0xfe62d713))>>>((0xf856fa0a))))-(0xfb7e0564)))|0;\n    d2 = (+((d2)));\n    {\n      d2 = (d2);\n    }\n    d1 = (((0x7a0a3990)));\n    return ((((((0xd3ca32ad)-((abs((0x25012246))|0) < (((-0x8000000)+(0xffffffff)) | ((0x224605ed) / (0xa8f3c459))))) >> (((0xa5c799f))+((((0x4c8d05fc))>>>((0xf8099dfb))) >= (((0x2a2f5f2e))>>>((0xecc6ace9))))-(0xf9551d57))))-(0xbc494f9f)))|0;\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), (function(){return 0;}), 0.1, '\\0', null, -0, true, (new Number(0)), objectEmulatingUndefined(), (new Number(-0)), (new Boolean(false)), '', false, (new String('')), ({toString:function(){return '0';}}), [0], '/0/', ({valueOf:function(){return 0;}}), NaN, (new Boolean(true)), 0, [], /0/, '0', 1, undefined]); ");
/*fuzzSeed-42369751*/count=1002; tryItOut("/*oLoop*/for (emxhuj = 0; emxhuj < 7; ++emxhuj) { switch(/*RXUE*//(?:\\v(?![^]*){0}+)*?/.exec(\"\")) { case (this.__defineSetter__(\"a\", Array.prototype.join)): break; (new RegExp(\"(?=(?:\\\\W))\", \"gy\"));break; case new (Date.prototype.setMonth)([1,,], this): v1 = a2.length;break;  } } ");
/*fuzzSeed-42369751*/count=1003; tryItOut("mathy0 = (function(x, y) { return ( ~ (( + ( + ( - ( + x)))) | 0)); }); testMathyFunction(mathy0, [-0x07fffffff, 42, 2**53, 0x100000001, 1, Number.MIN_VALUE, -0x100000001, 0x100000000, 0/0, -(2**53+2), 0x07fffffff, -0x0ffffffff, 0x0ffffffff, -0x100000000, 1/0, -Number.MIN_VALUE, -1/0, Number.MAX_VALUE, 2**53+2, 0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, 2**53-2, -0, -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001]); ");
/*fuzzSeed-42369751*/count=1004; tryItOut("\"use strict\"; this.zzz.zzz;for(let w in /*MARR*/[(void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000000, (void 0), objectEmulatingUndefined(), -0x100000000, (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [(void 0)], objectEmulatingUndefined()]) w.lineNumber;");
/*fuzzSeed-42369751*/count=1005; tryItOut("\"use strict\"; ktjiob();/*hhh*/function ktjiob(\u3056, b = (4277)){s1 += s1;}");
/*fuzzSeed-42369751*/count=1006; tryItOut("mathy2 = (function(x, y) { return ( + Math.fround(mathy0(((Math.fround((Math.pow(x, (mathy1((Math.cosh(x) >>> 0), (( + Math.fround(( ~ (x | 0)))) >>> 0)) >>> 0)) >>> 0)) + Math.fround(mathy1(( + (-Number.MAX_VALUE ^ (y | 0))), (Math.max((-Number.MIN_SAFE_INTEGER | 0), ((y >> Math.atan2(0x100000001, x)) | 0)) | 0)))) >>> 0), Math.fround(Math.pow(( + mathy0(( + Math.pow(( + ( + mathy1(x, x))), (x | 0))), ( + (((-Number.MAX_SAFE_INTEGER * x) !== ((( + (x >>> 0)) >>> 0) >>> 0)) >>> 0)))), Math.sqrt(x)))))); }); testMathyFunction(mathy2, [2**53, 0x080000001, -0x080000001, 0x080000000, 0x100000001, 0.000000000000001, 2**53+2, 2**53-2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 42, -1/0, -Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, -(2**53+2), -0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, -0x100000001, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, 0, -(2**53-2), 0x07fffffff, 1/0, 1.7976931348623157e308, -0, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=1007; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( + (Math.pow((( ~ (Math.max(( + ( + ( - mathy4(x, 0x100000001)))), (( + ( ! ( + (Math.fround(Math.hypot(Math.fround(y), Math.fround(Number.MAX_VALUE))) === x)))) >>> 0)) | 0)) | 0), ((( - x) ? Math.acosh(Math.fround(x)) : Math.sqrt(Math.pow(( + 1/0), x))) | 0)) | 0)) - ( + (Math.cos(Math.fround((((( ! ( + x)) , ( + (x >>> 0))) >>> 0) ** ( ~ -0)))) ? Math.tanh(Math.expm1(Math.hypot(x, (mathy0(Math.cosh((x >>> 0)), -(2**53+2)) >>> 0)))) : ((Math.imul((x >>> 0), ((( + (( + (Math.pow((x >>> 0), Math.fround(Math.fround(Math.asinh(Math.fround(x))))) >>> 0)) == ( + x))) == (Math.cosh((( + Math.sqrt(( + 2**53-2))) | 0)) | 0)) | 0)) >>> 0) | 0)))) | 0); }); testMathyFunction(mathy5, /*MARR*/[({x:3}), ({x:3}), {}, ({x:3}), {}, (void 0), {}, (void 0), ({x:3}), {}, ({x:3}), {}, ({x:3}), (void 0), {}, (void 0), (void 0), {}, ({x:3}), ({x:3}), (void 0), {}, ({x:3}), {}, {}, {}, (void 0), (void 0), {}, (void 0), ({x:3}), (void 0), {}, (void 0), ({x:3}), ({x:3}), (void 0), ({x:3}), ({x:3}), ({x:3}), ({x:3}), (void 0), ({x:3}), {}, (void 0), (void 0), {}, {}, (void 0), {}, (void 0), {}, (void 0), {}, ({x:3}), {}, (void 0), {}, (void 0), {}, (void 0), (void 0), (void 0), ({x:3}), (void 0), (void 0), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), (void 0), {}, (void 0), ({x:3}), {}, {}, ({x:3})]); ");
/*fuzzSeed-42369751*/count=1008; tryItOut("mathy5 = (function(x, y) { return ((( + Math.atan(mathy1((( - Math.round(Math.fround(mathy1(Math.fround(y), x)))) !== Math.cosh(Math.fround((Math.fround(x) / Math.fround(((y | 0) || (Number.MAX_VALUE | 0))))))), (mathy2((x >>> 0), (0/0 >>> 0)) >> ((((0x080000001 | 0) > (x | 0)) | 0) >>> 0))))) >>> 0) ? (( ! (Math.pow((( ~ ( + (Math.min((Math.asin((mathy0(0x100000000, (x | 0)) | 0)) >>> 0), ((((y | 0) ? (0x080000000 | 0) : (1/0 | 0)) | 0) >>> 0)) >>> 0))) | 0), (Math.fround(Math.sqrt(x)) | 0)) | 0)) >>> 0) : ( + (Math.hypot(((Math.fround(( - y)) + (Math.hypot(Math.fround(Math.max(2**53+2, mathy2(x, 0x080000000))), 42) >>> 0)) >>> 0), (Math.imul(x, ( ! ( ~ (Number.MAX_VALUE >>> 0)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [2**53-2, Number.MIN_VALUE, 2**53+2, 0x0ffffffff, -0, Number.MAX_VALUE, -0x100000000, -0x07fffffff, -(2**53), 0x100000001, -1/0, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, 0, -(2**53-2), 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, -0x080000000, 0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0/0, -(2**53+2), 0x07fffffff, 0.000000000000001, Math.PI, 1, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=1009; tryItOut("p1.__iterator__ = f1;");
/*fuzzSeed-42369751*/count=1010; tryItOut("\"use strict\"; let (x) { print(x); }");
/*fuzzSeed-42369751*/count=1011; tryItOut("g2.offThreadCompileScript(\"e2.delete(h0);\");");
/*fuzzSeed-42369751*/count=1012; tryItOut("mathy0 = (function(x, y) { return Math.ceil(Math.imul((( + (( + Math.cbrt(( ~ (Math.fround(-0) ? Number.MIN_VALUE : (-(2**53) >>> -(2**53)))))) - Math.fround(((x >>> 0) ^ (((y ** y) && (x ^ (-0x07fffffff | 0))) ? ( ! -0x07fffffff) : (( ! (x >>> 0)) >>> 0)))))) | 0), Math.sinh(( - ( + Math.log2(Math.fround(y))))))); }); ");
/*fuzzSeed-42369751*/count=1013; tryItOut("\"use strict\"; \"\\u1EC3\";");
/*fuzzSeed-42369751*/count=1014; tryItOut("this.v0 = 4.2;");
/*fuzzSeed-42369751*/count=1015; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ~ (mathy1(Math.fround(( - Math.cos(x))), y;) | 0))); }); testMathyFunction(mathy4, [0.000000000000001, 42, -0x07fffffff, Number.MIN_VALUE, 0x080000001, 2**53+2, -(2**53+2), -1/0, 0x100000001, 2**53, 0/0, -(2**53-2), -0x100000001, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 0x100000000, Number.MAX_VALUE, 0x080000000, 0, 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, -0x100000000, -(2**53), -Number.MIN_VALUE, -0, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001]); ");
/*fuzzSeed-42369751*/count=1016; tryItOut("mathy1 = (function(x, y) { return (Math.sign(( ~ Math.cbrt((mathy0((mathy0((y | 0), (Math.pow((-(2**53-2) >>> 0), (y >>> 0)) | 0)) | 0), (( + (( ! x) >> mathy0(mathy0(y, x), x))) | 0)) | 0)))) | 0); }); ");
/*fuzzSeed-42369751*/count=1017; tryItOut("v1 = g1.runOffThreadScript();");
/*fuzzSeed-42369751*/count=1018; tryItOut("\"use strict\"; i1 = g0.m1.iterator;");
/*fuzzSeed-42369751*/count=1019; tryItOut("\"use strict\"; v1 = (g1 instanceof p1);");
/*fuzzSeed-42369751*/count=1020; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.hypot(Math.atan((( + mathy0((( + ( + ( + x))) | 0), ((((x < -Number.MIN_SAFE_INTEGER) >>> 0) & (( ~ y) | 0)) | 0))) >>> 0)), (Math.tanh((( + ( + mathy2(( + -0x080000001), ( + (x - y))))) >>> 0)) | 0)); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, Number.MIN_VALUE, 2**53-2, 0/0, 0x07fffffff, -0x0ffffffff, Math.PI, -0x100000000, 0.000000000000001, 2**53+2, -(2**53), -0x080000001, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, -0x080000000, Number.MAX_VALUE, -(2**53-2), 2**53, 0x080000000, 1.7976931348623157e308, -0x100000001, -1/0, 0x0ffffffff, 1/0, 0x080000001, -(2**53+2), 42, 1, 0x100000001, Number.MIN_SAFE_INTEGER, 0, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=1021; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.asin(Math.atanh(Math.fround((( + Math.atanh(Math.atan2(y, x))) , ( + y))))); }); ");
/*fuzzSeed-42369751*/count=1022; tryItOut("\"use strict\"; let w = (4277)\n;this.b0 + '';");
/*fuzzSeed-42369751*/count=1023; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ! Math.fround(Math.round(Math.fround((( ! ( ! ( + y))) >>> 0))))) | 0); }); testMathyFunction(mathy4, [42, -1/0, 0x080000001, 2**53, 1.7976931348623157e308, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -0x100000001, -0x0ffffffff, Number.MAX_VALUE, 1/0, 0, 1, -0, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 2**53+2, -(2**53+2), -0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, Math.PI, 0.000000000000001, 0x100000000, 2**53-2]); ");
/*fuzzSeed-42369751*/count=1024; tryItOut("");
/*fuzzSeed-42369751*/count=1025; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (d0);\n    return +((Float32ArrayView[2]));\n  }\n  return f; })(this, {ff:  /x/ }, new ArrayBuffer(4096)); ");
/*fuzzSeed-42369751*/count=1026; tryItOut("/*RXUB*/var r = window; var s = \"1\"; print(s.split(r)); ");
/*fuzzSeed-42369751*/count=1027; tryItOut("\"use strict\"; print(this);");
/*fuzzSeed-42369751*/count=1028; tryItOut("");
/*fuzzSeed-42369751*/count=1029; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.imul(Math.fround(( + (Math.log2(( + ((((-Number.MIN_SAFE_INTEGER >>> 0) != x) >>> 0) === Math.min(x, y)))) >>> 0))), (((Math.hypot(Math.fround((y / Math.fround((Math.acos(y) >>> 0)))), ( + (( + ( + ( ~ Math.max(x, ( + x))))) ? ( + Math.log(Math.max((x >>> 0), Math.fround(0.000000000000001)))) : (x >>> 0)))) >>> 0) != ((( - ((Math.min((Math.acosh(Math.fround(mathy0(Math.fround(x), ( + 1/0)))) >>> 0), (Math.tan(-0) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-42369751*/count=1030; tryItOut("neuter(b0, \"change-data\");");
/*fuzzSeed-42369751*/count=1031; tryItOut("/*MXX2*/g1.Number.MAX_VALUE = s0;");
/*fuzzSeed-42369751*/count=1032; tryItOut("mathy1 = (function(x, y) { return ((Math.imul((( + ( + (( ~ (Math.fround(Math.atanh(Math.fround((y << x)))) >>> 0)) >>> 0))) >>> 0), (mathy0(( + (Math.clz32(( + -0x0ffffffff)) >>> 0)), ( + y)) >>> 0)) >>> 0) - (( + ( ~ (this.x >>> 0))) | ( ! ( ~ y)))); }); ");
/*fuzzSeed-42369751*/count=1033; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=1034; tryItOut("\"use strict\"; { void 0; selectforgc(this); }");
/*fuzzSeed-42369751*/count=1035; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=1036; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.abs(( + ( ~ ( + ( + Math.cbrt(Math.atan(y))))))) | 0); }); testMathyFunction(mathy2, [-0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 0/0, -(2**53-2), 1, 1.7976931348623157e308, Math.PI, 2**53, 42, -Number.MAX_SAFE_INTEGER, -(2**53), 0, 0.000000000000001, 0x100000001, -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53-2, 2**53+2, 1/0, 0x080000001, -0, 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-42369751*/count=1037; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"yim\"); var s = \"\\udccf\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=1038; tryItOut("this.f1 = Float32Array.bind(this.g2);");
/*fuzzSeed-42369751*/count=1039; tryItOut("\"use strict\"; b0 = t1.buffer;");
/*fuzzSeed-42369751*/count=1040; tryItOut("mathy2 = (function(x, y) { return ( ! ( + Math.sin(Math.log10(( + Math.hypot(( + (((x >>> 0) > Math.hypot(x, x)) >>> 0)), (mathy0(x, y) >>> 0))))))); }); ");
/*fuzzSeed-42369751*/count=1041; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[Infinity,  'A' ,  'A' ,  'A' , Infinity,  'A' , new String('q'), new String('q')]); ");
/*fuzzSeed-42369751*/count=1042; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"\\\"use strict\\\"; mathy1 = (function(x, y) { return ( ~ mathy0(Math.fround(Math.sqrt(mathy0((( - (y | 0)) | 0), Math.sinh(Math.fround(Math.hypot(Math.fround(Math.fround(( ~ Math.fround(y)))), x)))))), ( + (Math.fround((Math.sqrt(( + x)) | 0)) ? (Math.pow(( ! y), (y | 0)) | 0) : Math.fround(2**53))))); }); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-42369751*/count=1043; tryItOut("mathy0 = (function(x, y) { return (( - Math.exp(Math.pow(2**53, 0/0))) && ((((( + Math.asin(( + ( + (y > (Math.fround(x) !== x)))))) === (( ~ x) >>> 0)) >>> 0) == (Math.min(Math.asin(((((( + ( + -0x0ffffffff)) | 0) >>> 0) <= Math.fround(Math.atan2((x % x), x))) >>> 0)), Math.atan2(y, Math.fround(Math.fround((Math.fround(Math.fround(Math.max(( + ( + Math.hypot((y | 0), x))), ( + y)))) ? Math.fround(Math.pow(0x080000001, 0x080000001)) : ( + (( + ( - Math.fround(x))) * ( + y)))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[.2, \n[] = [], \n[] = [], \n[] = [], .2, .2, false, \n[] = [], false, \n[] = [], \n[] = [], false, .2, false, false, .2, .2, \n[] = [], \n[] = [], false, \n[] = [], .2, false, \n[] = [], \n[] = [], \n[] = [], false, .2, \n[] = [], false, \n[] = [], false, false, .2, false, false, .2, .2, \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], \n[] = [], .2, false, \n[] = [], \n[] = [], \n[] = [], .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, \n[] = [], false, false, false, \n[] = [], .2, false, false, false, .2, \n[] = [], false, .2, false, false, false, false, false, false, false, false, false, false, \n[] = [], \n[] = [], false, .2, \n[] = [], \n[] = [], \n[] = [], .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, \n[] = [], false, false, .2, .2, .2, .2, .2, .2, .2, .2, .2, \n[] = [], \n[] = [], .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, .2, false, .2, false, \n[] = [], \n[] = [], .2, .2, .2, false, \n[] = [], .2, .2, false, .2, \n[] = [], false, false, false, false, .2, false, .2, .2, false, \n[] = [], \n[] = [], false, .2, \n[] = [], \n[] = [], false, \n[] = [], false, false, false, \n[] = [], \n[] = []]); ");
/*fuzzSeed-42369751*/count=1044; tryItOut("((eval(\"[\\\"\\\\uE39A\\\"]\")));");
/*fuzzSeed-42369751*/count=1045; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy1(( + Math.imul(( + Math.fround((Math.fround(Math.pow(mathy2(-(2**53-2), (mathy0(x, y) >>> 0)), y)) ? Math.sin(( ~ y)) : mathy1(y, ( ! Math.fround(y)))))), ( + ((( ! x) && (Math.atan2(( + -0), ( + (Math.fround(Math.min(Math.fround(y), y)) == x))) >>> 0)) >>> 0)))), (Math.fround(Math.fround(Math.log(( + mathy1(Math.cbrt(x), ( + Math.log10(( + Math.atan(y))))))))) ^ Math.fround(mathy2((x ? ( + x) : (( - (-1/0 >>> 0)) >>> 0)), Math.fround(((Math.cosh((y | 0)) | 0) * y)))))); }); testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), (new Boolean(false)), true, (new String('')), 0.1, ({valueOf:function(){return '0';}}), 1, (new Number(0)), (new Boolean(true)), ({toString:function(){return '0';}}), '/0/', undefined, (new Number(-0)), [0], 0, /0/, objectEmulatingUndefined(), false, '', [], -0, '0', (function(){return 0;}), '\\0', NaN, null]); ");
/*fuzzSeed-42369751*/count=1046; tryItOut("Array.prototype.splice.call(a0, NaN, 9);");
/*fuzzSeed-42369751*/count=1047; tryItOut("b.getMilliseconds([[1]]);");
/*fuzzSeed-42369751*/count=1048; tryItOut("testMathyFunction(mathy1, [-(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000000, Number.MAX_VALUE, 1, -0x080000001, 2**53+2, 0x100000001, -0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, 2**53, Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 42, 0x100000000, 1.7976931348623157e308, 0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 1/0, -(2**53), 0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-42369751*/count=1049; tryItOut("print(\"\\u4953\");function e(x) { v1 = g0.runOffThreadScript(); } print(x);");
/*fuzzSeed-42369751*/count=1050; tryItOut("mathy4 = (function(x, y) { return (mathy0((( - (( + ( ! Math.fround(((-1/0 >>> 0) / y)))) | 0)) | 0), (( + (x >>> 0)) >> (mathy3(y, Math.log(y)) * Math.log10((x * ( - ( + y))))))) | 0); }); testMathyFunction(mathy4, [0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 2**53, -(2**53-2), -Number.MAX_VALUE, -0, Math.PI, 2**53-2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, 0x100000001, Number.MAX_VALUE, 0, 0.000000000000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, -0x080000000, 2**53+2, 1, 1.7976931348623157e308, -(2**53+2), -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, 0x080000000, -0x0ffffffff, 1/0, -0x100000001, -0x100000000, 0/0]); ");
/*fuzzSeed-42369751*/count=1051; tryItOut("mathy4 = (function(x, y) { return (Math.cos(Math.fround(Math.hypot((Math.log((x >>> 0)) >>> 0), (Math.cos((Math.min(-Number.MIN_SAFE_INTEGER, (((y | 0) !== (-0 | 0)) | 0)) >>> 0)) >>> 0)))) >> (Math.max((((Math.acosh(((y << (Math.PI >>> 0)) >>> 0)) >>> 0) ? Math.round(Math.fround(y)) : (( + ( + ((0/0 | 0) !== (-Number.MAX_VALUE >>> 0)))) | 0)) >>> 0), (Math.max(x, 0/0) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [0.000000000000001, -0, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 0x07fffffff, 0x080000001, -1/0, 0x100000000, -0x100000001, -0x100000000, -0x0ffffffff, 0, -(2**53+2), 0/0, 1, -0x07fffffff, 0x0ffffffff, 0x080000000, -(2**53-2), 2**53+2, 42, Math.PI, -(2**53), 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-42369751*/count=1052; tryItOut("mathy4 = (function(x, y) { return ((Math.pow((Math.max((( + (( + ( + ( ~ Math.fround(Math.imul(( - (x >>> 0)), y))))) == (-0 >>> 0))) | 0), ((Math.imul(x, y) ? ( + Math.hypot(( + Math.max(Math.hypot(x, (x >>> 0)), y)), y)) : Math.PI) | 0)) | 0), ((((((x | 0) ? ( + ( ~ ( + y))) : Math.fround(mathy1(y, (y | 0)))) || y) | 0) >>> (x | 0)) | 0)) >= (Math.max(( ! (Math.clz32(x) !== x)), (Math.fround(( ! Math.hypot(0x0ffffffff, ( - ( + Math.hypot(y, ( + y))))))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -0x080000001, 2**53+2, 0, Number.MIN_VALUE, -(2**53+2), -0x100000001, 42, 1, -0x100000000, 2**53, -0x080000000, 0x080000000, -0, 0x100000001, -(2**53), Math.PI, 0.000000000000001, 1/0, 2**53-2, -(2**53-2), 0/0, 0x080000001, Number.MAX_VALUE, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=1053; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; fullcompartmentchecks(false); } void 0; }");
/*fuzzSeed-42369751*/count=1054; tryItOut("h0.getPropertyDescriptor = f2;");
/*fuzzSeed-42369751*/count=1055; tryItOut("o2.t2 = x;");
/*fuzzSeed-42369751*/count=1056; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan = stdlib.Math.atan;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -34359738369.0;\n    var d3 = 1.0625;\n    (Uint16ArrayView[((((0x1cd00c0e)-(0xffffffff)+(-0x8000000)) ^ (((0x6180387d) > (0x204ecd39))+(eval(\"/* no regression tests found */\", \"\\uC96F\")))) % (((-0x8000000)) << ((0x91188291)-(0xb1ff3546)-(0x9a5f6572)))) >> 1]) = (((((0xcc78afc2)-(0xf2a981d7))>>>(((0xf3855ffd) == (0xba8bb58e))+(0x43d4a039))) == (((0xa47e1fd2)-(0x3901d88f))>>>((0xdeeb2d6b))))*-0x54d88);\n    (Uint16ArrayView[0]) = ((0xea3a5dad)-(0x5afa762d)-((abs((0x2c6825f7))|0) != (abs(((((((0x666c50da))>>>((-0x62e6763))))-((((0x8a416b42))>>>((0xfaaa3ebf))))+(0xffffffff))))|0)));\n    {\n      d0 = (((((-18446744073709552000.0)) % ((d1)))) - ((d2)));\n    }\n    d2 = (d1);\n    d0 = (d3);\n    d1 = (+abs(((d1))));\n    d3 = (d3);\n    d0 = (d2);\n    (Uint16ArrayView[(((((0x8d26eba7)-((-0.0625) == (4294967297.0))) | ((0x3553bb8) / (0x45fdef3a))))+(0xea06c6e)) >> 1]) = (((((/*FFI*/ff(((+atan(((+(1.0/0.0)))))), ((d3)), ((+(1.0/0.0))), ((((0xd54b0c97)) | ((0xfd0519bb)))), ((9223372036854776000.0)), ((1.5111572745182865e+23)))|0)) & ((/*FFI*/ff(((d1)))|0)-(0x648ca51e))) < (0x7fffffff))-(0xfa3e361f));\n    return (((((((((((0xffffffff))>>>((0xffffffff))))-(0x2dc5c6c7)) & (((((0x6b81291))>>>((0xfbe2b005))))-(-0x8000000)))))>>>((-0x8000000)-((0xb96063b9) != (0x1af87162))-(0x3ddf3a0))) % ((-0xffa0d*(/*FFI*/ff(((d2)), ((d0)), ((((0xd3cb741f)) & ((0xf28fdf08)))), ((d1)), ((-9.671406556917033e+24)), ((-1.888946593147858e+22)), ((3.094850098213451e+26)), ((-18446744073709552000.0)))|0))>>>(((imul((0xcbc142a8), (-0x8000000))|0))-(0x3a10c2e8)+((imul(((0x31b7ce44)), ((0xb55387d5) != (0xaa0e3fd3)))|0))))))|0;\n  }\n  return f; })(this, {ff: function(y) { for (var v of f2) { try { a2.push(f1, f0); } catch(e0) { } try { (let (e=eval) e) } catch(e1) { } m2.has(this.g2); } }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -(2**53-2), 1, -0x100000000, -(2**53+2), 42, 1.7976931348623157e308, 0x080000000, -Number.MAX_VALUE, 0x07fffffff, 0x080000001, 2**53, -0x0ffffffff, -0x07fffffff, 0.000000000000001, 2**53+2, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, -1/0, 0x0ffffffff, -0, 0, 0x100000000, -0x100000001, -0x080000001, -0x080000000]); ");
/*fuzzSeed-42369751*/count=1057; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((Math.expm1(((( ! (Math.sign((( - ( - 0x100000001)) >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 42, -0, 0x080000000, Number.MAX_VALUE, 1/0, -(2**53-2), 0x080000001, 0/0, -Number.MIN_VALUE, 2**53+2, Number.MIN_VALUE, 2**53, 0x100000001, -0x07fffffff, -(2**53), -Number.MAX_VALUE, -0x0ffffffff, -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), 0, -0x100000000, 0.000000000000001, 0x100000000, 1.7976931348623157e308, -0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, 2**53-2]); ");
/*fuzzSeed-42369751*/count=1058; tryItOut("/*hhh*/function urpgpx(\u0009...x){print(b1);}/*iii*/Array.prototype.splice.apply(a1, [NaN, 3]);");
/*fuzzSeed-42369751*/count=1059; tryItOut("({});");
/*fuzzSeed-42369751*/count=1060; tryItOut("print([1,,]);");
/*fuzzSeed-42369751*/count=1061; tryItOut("\"use strict\"; t0.set(a1, 19);");
/*fuzzSeed-42369751*/count=1062; tryItOut("g1.g1.v1 = (i0 instanceof h1);\ni0 + '';\n");
/*fuzzSeed-42369751*/count=1063; tryItOut("function this.f2(a0)  { \"use strict\"; return new RegExp(\"\\\\1\", \"yim\") } ");
/*fuzzSeed-42369751*/count=1064; tryItOut("testMathyFunction(mathy4, [0.000000000000001, 2**53, -0, 1.7976931348623157e308, Number.MAX_VALUE, 1, -1/0, -0x080000000, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, Number.MIN_VALUE, -0x100000001, 0, -(2**53-2), 0x100000001, 42, 0x07fffffff, -0x100000000, Math.PI, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-42369751*/count=1065; tryItOut("\"use strict\"; this.e0.add(g2.e0);");
/*fuzzSeed-42369751*/count=1066; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.cosh((Math.max((( + ((y & ((Math.hypot(y, 0x100000001) >>> 0) ? x : ((y | y) == y))) | 0)) ** y), Math.fround((Math.clz32(Math.cosh(Math.fround(y))) < (mathy1(( + Math.atanh(( + x))), ( + (x === Math.min(( + ( ! ( + y))), 0x100000000)))) | 0)))) >>> 0))); }); testMathyFunction(mathy3, [0x100000000, 2**53-2, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, 0/0, -(2**53), -(2**53+2), 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, 2**53, -0x080000001, 0, 1.7976931348623157e308, -0x100000001, -(2**53-2), 0x07fffffff, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0x100000001, -0x07fffffff, Math.PI, -0x080000000, 42, 1]); ");
/*fuzzSeed-42369751*/count=1067; tryItOut("v2 = -Infinity;");
/*fuzzSeed-42369751*/count=1068; tryItOut("mathy1 = (function(x, y) { return (( - (Math.round(( ~ (Math.fround(x) << -1/0))) >>> 0)) ^ ((Math.min(2**53-2, ( + Math.fround(Math.max(((((x ? x : y) >>> 0) ? (x >>> 0) : (Math.fround(( ! (x | 0))) >>> 0)) >>> 0), x)))) | 0) | (Math.pow(( + x), (x ^ ( + x))) - mathy0(Math.sinh((Number.MIN_VALUE | 0)), Math.acosh(y))))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, Math.PI, 0x100000000, Number.MIN_VALUE, 0/0, -0x100000000, 2**53+2, 0x100000001, -1/0, 42, -(2**53), 2**53-2, -0, -(2**53+2), 1, 0x080000001, 1.7976931348623157e308, -0x100000001, Number.MAX_VALUE, 1/0, 2**53, 0x080000000, -0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-42369751*/count=1069; tryItOut("let p0 = m0.get(s0);");
/*fuzzSeed-42369751*/count=1070; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -140737488355329.0;\n    var i3 = 0;\n    return +((3.022314549036573e+23));\n  }\n  return f; })(this, {ff: DataView.prototype.setInt16}, new ArrayBuffer(4096)); ");
/*fuzzSeed-42369751*/count=1071; tryItOut("x");
/*fuzzSeed-42369751*/count=1072; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[x, function(){}, x, function(){}, x, function(){}, x, function(){}, function(){}, x, function(){}, x, x, x, function(){}, function(){}, x, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, x, function(){}, x, function(){}, x, function(){}, x, function(){}, x, x, function(){}, function(){}, x, function(){}, function(){}, x, function(){}, function(){}, x, x, x, x, function(){}, x, function(){}, x, x, x, function(){}, function(){}, function(){}, x, function(){}, x, x, x, x, function(){}, function(){}, function(){}, x, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x, x, function(){}, x, x, function(){}, x, x, x, x, function(){}, x, function(){}, function(){}, x, function(){}, function(){}, function(){}, x, x, function(){}, function(){}, function(){}, x, function(){}, function(){}, function(){}, x, function(){}, x, x, function(){}, x, x, x, x, function(){}, x, x, function(){}, function(){}, function(){}, function(){}, x, x, function(){}, function(){}, x, x, x, function(){}, x]) { let a, wgygyz, x, zunhfl, eval, uzpued, ayrgly;v1 = g1.eval(\"function this.f1(v1) a\");\no0 = Proxy.create(h0, s2);\n }");
/*fuzzSeed-42369751*/count=1073; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (((3.0)) * ((((+(-1.0/0.0))) / ((+((d0)))))));\n    d0 = (((d0)) - ((257.0)));\n    i1 = (/*FFI*/ff(((~(-(!(/*FFI*/ff(((+(1.0/0.0))), (((-(x)) << (((0x39aa6415) == (0xcfb5d247))-((8388609.0) >= (72057594037927940.0))))), ((+log(((Float32ArrayView[((0xf57a8687)) >> 2]))))), ((((0xa6c02ec7)) & ((0xffffffff)))))|0))))), (((((-0x5e50d10) ? (((x = x))) : (-0x8000000))+(-0x8000000)) << ((i1)))), ((d0)))|0);\n    {\n      d0 = (68719476737.0);\n    }\n    d0 = (-590295810358705700000.0);\n    return (((0xfc7e2794)-((((i1)+((d0) > (33554433.0))+(i1))>>>((0xf9f29ca4)-(i1)-(i1))) <= ((((((-0x8000000))>>>((0xf93d6cba))) != (0x6545739a))-(0x619cdf88))>>>((0xa2d2ad68)+((~(0x5328f*(0xc61979a2))) < (((0x701cfac)) >> ((0xfe3fddf3)))))))))|0;\n  }\n  return f; })(this, {ff: Array.prototype.pop}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MIN_VALUE, 2**53+2, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 0x080000000, 0, -(2**53), -0x080000000, 0x0ffffffff, -0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, 0/0, 2**53, 0.000000000000001, 1/0, -0x07fffffff, 0x100000000, 1, -Number.MAX_VALUE, 42, -1/0, -0, -Number.MAX_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-42369751*/count=1074; tryItOut("\"use strict\"; g2.o2 = new Object;");
/*fuzzSeed-42369751*/count=1075; tryItOut("print(a2);");
/*fuzzSeed-42369751*/count=1076; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.expm1(Math.log2(Math.hypot((( - Number.MAX_VALUE) >>> 0), Math.log10(Math.fround(Math.tan(x)))))); }); testMathyFunction(mathy3, ['', ({valueOf:function(){return '0';}}), 0, (function(){return 0;}), '\\0', (new Boolean(false)), (new Boolean(true)), '0', undefined, (new String('')), false, objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), -0, (new Number(0)), null, (new Number(-0)), [0], /0/, '/0/', ({toString:function(){return '0';}}), [], NaN, 1, true]); ");
/*fuzzSeed-42369751*/count=1077; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.sin(Math.fround(Math.fround(Math.asinh(Math.fround(Math.atan((Math.abs(x) >>> 0)))))))); }); testMathyFunction(mathy2, [-(2**53), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0x080000001, 42, 2**53-2, 0x100000001, -(2**53-2), -0x100000000, -0x0ffffffff, 0x0ffffffff, -0x080000000, 1, Math.PI, 0/0, -0x080000001, 0.000000000000001, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 1/0, -0x100000001, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, 0x080000000, -0, 2**53+2]); ");
/*fuzzSeed-42369751*/count=1078; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(e1, o0.e0);");
/*fuzzSeed-42369751*/count=1079; tryItOut("\"use strict\"; g2.g1.v0 = a1.reduce, reduceRight((function() { try { o2 = Object.create(m1); } catch(e0) { } try { m0.has(h1); } catch(e1) { } t2 = new Float64Array(o1.b0, 10, 15); throw t1; }), g0.t1, b1, a2, b0);");
/*fuzzSeed-42369751*/count=1080; tryItOut("s0 = g2.objectEmulatingUndefined();");
/*fuzzSeed-42369751*/count=1081; tryItOut("(-12);");
/*fuzzSeed-42369751*/count=1082; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s0; print(r.exec(s)); ");
/*fuzzSeed-42369751*/count=1083; tryItOut("mathy2 = (function(x, y) { return ((( ~ ((Math.sqrt((-1/0 | 0)) >> ((-0x080000000 >>> 0) - y)) >>> 0)) >>> 0) == (Math.fround(Math.max(((( ! ((Math.max(y, (y | 0)) | 0) | 0)) >>> 0) << (Math.atan2((Math.atanh(x) >>> 0), ((( + y) ? ( + -0x080000000) : ( + x)) >>> 0)) >>> 0)), ( + Math.sign(Math.fround(Math.fround(mathy1(Math.fround(Math.hypot(y, x)), Math.fround((x ? y : Math.fround(x)))))))))) && Math.sign(Math.exp(Math.sqrt(Math.fround(Math.pow(Math.fround(Math.fround(Math.hypot((y | 0), y))), x))))))); }); ");
/*fuzzSeed-42369751*/count=1084; tryItOut("/* no regression tests found */");
/*fuzzSeed-42369751*/count=1085; tryItOut("m2.get(g1);");
/*fuzzSeed-42369751*/count=1086; tryItOut("\"use strict\"; a1.push(m1);");
/*fuzzSeed-42369751*/count=1087; tryItOut("\"use strict\"; \"use asm\"; Object.freeze(o2.b0);");
/*fuzzSeed-42369751*/count=1088; tryItOut("testMathyFunction(mathy4, [-(2**53+2), -0x080000001, 0x080000000, Number.MAX_VALUE, -(2**53-2), -Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0x080000001, -0x07fffffff, -0x100000000, Math.PI, -0x080000000, 0x0ffffffff, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 0x07fffffff, 2**53-2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, -0, 1, 2**53+2, 0/0, -0x100000001, 42, 1.7976931348623157e308, 0, 0.000000000000001]); ");
/*fuzzSeed-42369751*/count=1089; tryItOut("\"use strict\"; ;");
/*fuzzSeed-42369751*/count=1090; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (i1);\n    d0 = (Infinity);\n    d0 = (-3.0);\n    i1 = (0xaca9e97e);\n    {\n      {\n        i1 = (0xbfdce3c2);\n      }\n    }\n    {\n      (Int32ArrayView[4096]) = (((-((abs((((-0x8000000)*0xfbc11)|0))|0) > (((Uint16ArrayView[2]))|0)))>>>((i1))) / (0xcab1a90a));\n    }\n    return (((0x6f41e886)))|0;\n    d0 = (-0.0009765625);\n    i1 = ((d0) <= (-33554431.0));\n    d0 = (5.0);\n    d0 = (((d0)) * ((-65537.0)));\n    d0 = (+(0.0/0.0));\n    d0 = (+((-(0x5e347535))>>>((i1)+(i1))));\n    {\n      d0 = (+(1.0/0.0));\n    }\n    switch ((~~(d0))) {\n      case -2:\n        switch ((((i1)) | (-(new RegExp(\"(?=((?!\\\\w)\\\\3\\\\3))\", \"\") >> 25)))) {\n        }\n        break;\n      case 1:\n        {\n          d0 = (+((-0x9db5e*((((!((0x406cbb0b))))>>>((0x4f4a53e0) % (0x1301dda7))) < (0xd3ff517e)))>>>((/*FFI*/ff((((i1))), ((((0xd17eaf25)-(0xbbe5e5a1)) >> ((Int8ArrayView[1])))), ((+(((0xfa0d57be)) ^ ((0xfa1ea45e))))), ((((0xc2132a2))|0)), ((1048577.0)))|0)-(i1)+(0xb1d452a3))));\n        }\n        break;\n      case 1:\n        i1 = ((~~(d0)));\n      default:\n        {\n          {\n            d0 = (+(((Int8ArrayView[2]))>>>((i1)-(0xfa5c23f4))));\n          }\n        }\n    }\n    {\n      (Int8ArrayView[((!(0x8b90005c))) >> 0]) = ((i1)+(i1)-((d0) != (+(-1.0/0.0))));\n    }\n    {\n      {\n        (Int8ArrayView[(-(!((((0x4f6cdf33) % (0x773ed6f7)) & ((/*FFI*/ff(((3.022314549036573e+23)), ((-70368744177665.0)), ((33.0)), ((1.001953125)), ((72057594037927940.0)), ((-17179869185.0)), ((17179869185.0)), ((8589934593.0)), ((-1.0078125)), ((1.5)), ((8193.0)), ((1.001953125)), ((35184372088831.0)), ((9.44473296573929e+21)), ((1099511627775.0)))|0)))))) >> 0]) = ((!((Int16Array( \"\" )) || [x]))-(0xc648aaef));\n      }\n    }\n    {\n      (Float64ArrayView[1]) = ((+(-1.0/0.0)));\n    }\n    {\nlet (c = /$(?=[^M-\u8e4b\u0a8b-\\uD3C3\\u0084-\\u00FC](?!\\b\\d))(?:\\3)|(?!\\d|\\B+)|[^\\d\\n\\u0042-\u5cae\\w]/gy) window;    }\n    d0 = (d0);\n    d0 = (((((abs((((0x1ed4bad2)-(0xe88599bc)) << ((0xca33e0f)*0xfffff)))|0))) | ((((( /x/g  >>> new RegExp(\"[\\u00d6--\\\\s\\\\0]\", \"y\"))*-0xd9ba4)>>>((i1)-(0x2467ec7f)-(/*FFI*/ff(((((9.44473296573929e+21)) % ((549755813887.0)))), ((imul((0x5465c87f), (0x976ac1ca))|0)), ((-144115188075855870.0)), ((9007199254740992.0)), ((-129.0)))|0)))))));\n    return (((/*FFI*/ff(((~(((~~(d0)) > (((!(i1))+(i1)) ^ ((/*FFI*/ff(((d0)))|0))))+(i1)))), ((~~(+pow(((-2251799813685249.0)), ((d0)))))), ((Infinity)))|0)))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, -(2**53+2), -0x100000000, 1, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 0x0ffffffff, 0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, 0, 0x080000001, -(2**53-2), -0x07fffffff, 42, 2**53-2, -0x0ffffffff, 0x100000000, Math.PI, 0x080000000, -0, -Number.MAX_VALUE, 0/0, -0x100000001, -(2**53), 1/0]); ");
/*fuzzSeed-42369751*/count=1091; tryItOut("/*bLoop*/for (rqczbc = 0; rqczbc < 13; ++rqczbc) { if (rqczbc % 34 == 4) { /*RXUB*/var r = /^/im; var s = \"\"; print(r.test(s));  } else { print(o0.m1); }  } ");
/*fuzzSeed-42369751*/count=1092; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((((((Math.fround(Math.min(mathy0(y, Math.asinh(Math.min(Math.fround(mathy0(x, y)), -(2**53+2)))), Math.fround(Math.fround(Math.imul(Math.fround(x), Math.fround(x)))))) | 0) <= Math.max(Math.abs((y >>> 0)), ( + Math.sqrt(Math.fround((( ! Math.atan2(-Number.MIN_VALUE, Math.fround(y))) | 0)))))) | 0) | 0) - (Math.max((Math.log1p(0.000000000000001) | 0), ((((Math.min(Math.imul(x, Math.fround(42)), (x >>> 0)) >>> 0) >>> 0) === ( ! Math.fround((Math.fround((y <= y)) ? Math.fround(y) : Math.fround(y))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[ /x/g , 0x2D413CCC, 0x2D413CCC,  /x/g , (1/0), 0x2D413CCC, 0x2D413CCC, (1/0), 0x2D413CCC,  /x/g , 0x2D413CCC,  /x/g , 0x2D413CCC, (1/0), 0x2D413CCC,  /x/g ,  /x/g , 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC,  /x/g , (1/0), (1/0), 0x2D413CCC, (1/0), 0x2D413CCC, 0x2D413CCC, (1/0), 0x2D413CCC, 0x2D413CCC,  /x/g , 0x2D413CCC, 0x2D413CCC, (1/0),  /x/g , (1/0), 0x2D413CCC,  /x/g , (1/0),  /x/g , 0x2D413CCC,  /x/g , 0x2D413CCC, 0x2D413CCC,  /x/g ,  /x/g , 0x2D413CCC,  /x/g , (1/0), (1/0),  /x/g , 0x2D413CCC,  /x/g , 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, (1/0), 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC,  /x/g , 0x2D413CCC, 0x2D413CCC,  /x/g ,  /x/g ,  /x/g , 0x2D413CCC, 0x2D413CCC,  /x/g , 0x2D413CCC, (1/0), (1/0), 0x2D413CCC,  /x/g , 0x2D413CCC, (1/0),  /x/g , (1/0),  /x/g ,  /x/g , (1/0),  /x/g , (1/0), (1/0), (1/0), (1/0),  /x/g ,  /x/g ,  /x/g , (1/0),  /x/g , (1/0), 0x2D413CCC,  /x/g ,  /x/g , (1/0), (1/0), (1/0), (1/0),  /x/g , 0x2D413CCC,  /x/g ,  /x/g , (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0),  /x/g , 0x2D413CCC, 0x2D413CCC,  /x/g , (1/0), (1/0),  /x/g ,  /x/g , 0x2D413CCC, 0x2D413CCC, (1/0), (1/0), 0x2D413CCC, 0x2D413CCC,  /x/g , 0x2D413CCC,  /x/g , (1/0), (1/0),  /x/g ,  /x/g , (1/0), (1/0), 0x2D413CCC, (1/0), 0x2D413CCC, 0x2D413CCC,  /x/g , (1/0),  /x/g , 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC,  /x/g , (1/0), (1/0),  /x/g ,  /x/g , (1/0),  /x/g , 0x2D413CCC,  /x/g ]); ");
/*fuzzSeed-42369751*/count=1093; tryItOut("v0 = t0.byteLength;");
/*fuzzSeed-42369751*/count=1094; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - ( + (((mathy0((( + (y << y)) >>> 0), y) >>> 0) >>> 0) === (( + (( + (x >> ( + mathy0(( + Math.fround(Math.max(Math.fround(-0x100000000), Math.fround(y)))), ( + y))))) ? ( + (( + y) >>> 0)) : ( + mathy0(Math.fround(Math.sqrt((y !== ( ! x)))), Math.fround(mathy0(Math.fround(y), Math.fround(y))))))) >>> 0)))) | 0); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-42369751*/count=1095; tryItOut("x = x;t2[({valueOf: function() { print(x);return 19; }})];e0.toSource = f0;");
/*fuzzSeed-42369751*/count=1096; tryItOut("function o0.f1(s2) \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -36893488147419103000.0;\n    {\n      return +((([] = e)));\n    }\n    return +((d1));\n  }\n  return f;");
/*fuzzSeed-42369751*/count=1097; tryItOut("/*tLoop*/for (let x of /*MARR*/[x, x, x, (1/0), x, x, (1/0), (1/0), (1/0), (1/0), x, x, x, (1/0), (1/0), x, x, (1/0), (1/0), (1/0), (1/0), (1/0), x, (1/0), x, x, x, (1/0), (1/0), (1/0), (1/0), (1/0), x, x, (1/0), (1/0), (1/0), x, x, (1/0), x, (1/0), (1/0), x, (1/0), (1/0), (1/0), (1/0), x, x, x, x, (1/0), (1/0), x, x, (1/0), (1/0), x, (1/0), (1/0), (1/0), x, x, (1/0), (1/0), x, (1/0), x, x, x, x, x, (1/0), x, x, x, (1/0), (1/0), x, (1/0)]) { a1[1] = x.valueOf(\"number\"); }");
/*fuzzSeed-42369751*/count=1098; tryItOut("mathy1 = (function(x, y) { return ((( + Math.min(( + Math.fround(Math.tanh((Math.max(((Math.pow(( + y), (y >>> 0)) >>> 0) | 0), (0x0ffffffff | 0)) | 0)))), ( + Math.log1p(((Math.hypot(( + (x <= (2**53 | 0))), (mathy0(Math.fround(mathy0(y, y)), ( - y)) >>> 0)) >>> 0) | 0))))) >>> 0) != Math.sin(Math.fround((Math.max(y, Math.fround((Math.fround(y) , -Number.MIN_VALUE))) === Math.fround(Math.max(Math.exp(Math.fround((( - y) >>> 0))), (Math.round((y | 0)) | 0))))))); }); testMathyFunction(mathy1, [0x100000000, 0x100000001, 0/0, Number.MIN_VALUE, -0x07fffffff, -0, -(2**53), 1/0, 1.7976931348623157e308, 2**53-2, Math.PI, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0x080000000, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -(2**53+2), 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0.000000000000001, 0x080000001, -0x100000001, -1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=1099; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((((Math.max(( + y), Math.fround(( - Math.pow(y, x)))) > ((((( ~ ((x ? x : -Number.MIN_VALUE) >>> 0)) ? x : x) === (((x | 0) >> (x | 0)) | 0)) >>> 0) === x)) >>> 0) < (((( + (( + (((( + Math.atan(x)) >>> 0) ** (Math.sqrt(( + y)) | 0)) | 0)) / ( + (Math.acos(x) >>> 0)))) >> (((Math.fround(mathy1(x, ( + 0x080000000))) | 0) || ( + mathy0(( + mathy1(( + 0x100000000), y)), (Math.hypot(y, Math.fround(Math.hypot(Math.fround(x), Math.fround(-0)))) | 0)))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x080000001, 42, 0x080000000, -1/0, -Number.MAX_VALUE, 0/0, -0x100000000, 1.7976931348623157e308, 0, 0.000000000000001, -0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), -0x080000000, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 1, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, 2**53+2, 0x07fffffff, -0, Math.PI, -(2**53), -0x080000001, 0x100000001, 2**53, Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-42369751*/count=1100; tryItOut("s0.toString = (function() { for (var j=0;j<41;++j) { f1(j%2==0); } });/* no regression tests found */");
/*fuzzSeed-42369751*/count=1101; tryItOut("\"use strict\"; e0.add(g1);\n/*RXUB*/var r = new RegExp(\"(?=([^]*?)?){0,4}(?=(?=\\uced0)+){3}\\\\3+?.{3}\", \"gyi\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\"; print(r.test(s)); \n");
/*fuzzSeed-42369751*/count=1102; tryItOut("g2 = fillShellSandbox(newGlobal({ cloneSingletons: \n '' , disableLazyParsing: true }));");
/*fuzzSeed-42369751*/count=1103; tryItOut("throw 524239682;e = window;");
/*fuzzSeed-42369751*/count=1104; tryItOut("t0[({valueOf: function() { /*tLoop*/for (let z of /*MARR*/[new Boolean(false), new Boolean(false), false,  'A' , new Boolean(false),  'A' ,  'A' , new Boolean(false),  'A' , undefined, new Boolean(false),  'A' , undefined, new Boolean(false), false, false, new Boolean(false),  'A' , new Boolean(false), new Boolean(false), new Boolean(false), undefined, new Boolean(false), false, undefined, undefined, false,  'A' , false,  'A' ,  'A' ]) { v0 = t0.length; }return 1; }})] = h1;");
/*fuzzSeed-42369751*/count=1105; tryItOut("\"use strict\"; print(Math.max(8, -11));");
/*fuzzSeed-42369751*/count=1106; tryItOut("\"use strict\"; const e = null, wzigdx, NaN = (let (x = \"\\u96BD\", w = x, ukjzuy) 745901285), ywtoca;v2 = a2.every();");
/*fuzzSeed-42369751*/count=1107; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (x === x %= {} = {}); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, 0x100000001, 2**53-2, 2**53+2, -0x080000001, -(2**53+2), 0x100000000, 0, 2**53, 42, -0x080000000, 0/0, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -0x100000000, 0x0ffffffff, 0x080000001, -0, Math.PI, -1/0, 1/0, 0x080000000, Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-42369751*/count=1108; tryItOut("var mvered = new SharedArrayBuffer(0); var mvered_0 = new Float64Array(mvered); mvered_0[0] = 17; var mvered_1 = new Int16Array(mvered); print(mvered_1[0]); mvered_1[0] = -21; var mvered_2 = new Int32Array(mvered); mvered_2[0] = -3691666319; var mvered_3 = new Int8Array(mvered); var mvered_4 = new Int16Array(mvered); var mvered_5 = new Int16Array(mvered); mvered_5[0] = 16; var mvered_6 = new Uint16Array(mvered); print(mvered_6[0]); mvered_6[0] = -5; var mvered_7 = new Uint16Array(mvered); mvered_7[0] = 29; var mvered_8 = new Uint8Array(mvered); var mvered_9 = new Uint32Array(mvered); mvered_9[0] = -2; (((void options('strict_mode'))));arguments;/*ADP-1*/Object.defineProperty(a0, 11, ({configurable: true, enumerable: false}));for(w = new \"\\u4D81\"( /x/ , null) in  /x/ ) {return;v0 = a0.some(o0); }Array.prototype.splice.call(a0, NaN, 5, b2);/*RXUB*/var r = new RegExp(\"(?!$(?=\\\\2*)})\", \"gym\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); print(Math.trunc(12));a1.reverse();");
/*fuzzSeed-42369751*/count=1109; tryItOut("mathy2 = (function(x, y) { return Math.fround(mathy1(Math.imul(((x | 0) ? Math.abs(( + ( + (( + y) == ( + Math.fround(Math.log2(Math.fround(1)))))))) : ( + ( + y))), Math.hypot(( + Math.log1p(( + ((x << Math.fround(x)) >>> 0)))), (Math.clz32(( + ((y ? ( + y) : ( + y)) >>> 0))) >>> 0))), Math.fround(Math.asinh(Math.max(Math.cos(-Number.MAX_SAFE_INTEGER), Math.atan2(1/0, Math.hypot((x & y), y))))))); }); testMathyFunction(mathy2, [0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -1/0, 1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 42, -0x0ffffffff, 0, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, -0x100000000, 2**53+2, 0x100000000, -Number.MAX_VALUE, Math.PI, 2**53, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, 0x100000001, 0x080000000, 2**53-2, Number.MIN_VALUE, 0x0ffffffff, 0/0, -(2**53+2), -0, Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-42369751*/count=1110; tryItOut("\"use asm\"; for (var v of b2) { print(e2); }");
/*fuzzSeed-42369751*/count=1111; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=1112; tryItOut("/*RXUB*/var r = /((?=[^]{3,7}|\\W[^\\s\\x06-\u9e75\\W]|.*?*?)+)*?/yim; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=1113; tryItOut("var micnvh = new ArrayBuffer(2); var micnvh_0 = new Int32Array(micnvh); micnvh_0[0] = 16; g0.valueOf = (function() { for (var j=0;j<89;++j) { f0(j%3==1); } });");
/*fuzzSeed-42369751*/count=1114; tryItOut("\"use strict\"; Object.prototype.watch.call(o2.o2.t2, \"__iterator__\", (function(j) { if (j) { try { v1 = (e1 instanceof h1); } catch(e0) { } try { i2.send(b2); } catch(e1) { } try { var h1 = ({getOwnPropertyDescriptor: function(name) { f2.__iterator__ = (function() { try { /*RXUB*/var r = r2; var s = s0; print(r.test(s)); print(r.lastIndex);  } catch(e0) { } try { for (var p in s0) { try { g1.o1.__proto__ = m2; } catch(e0) { } try { e0.has(this.m1); } catch(e1) { } m2 + e1; } } catch(e1) { } {(window); } return a2; });; var desc = Object.getOwnPropertyDescriptor(a2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { this.a2.splice(NaN, ({valueOf: function() { /*RXUB*/var r = /[^]/gy; var s = \"\\n\"; print(s.match(r)); return 2; }}));; var desc = Object.getPropertyDescriptor(a2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a0.splice(NaN, v2);; Object.defineProperty(a2, name, desc); }, getOwnPropertyNames: function() { g2.offThreadCompileScript(\"a1 = a1[10];\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: false }));; return Object.getOwnPropertyNames(a2); }, delete: function(name) { v0 = g1.runOffThreadScript();; return delete a2[name]; }, fix: function() { h2.has = (function() { this.s2 = new String(f2); return h0; });; if (Object.isFrozen(a2)) { return Object.getOwnProperties(a2); } }, has: function(name) { v2 = (o1 instanceof o1);; return name in a2; }, hasOwn: function(name) { a2 + '';; return Object.prototype.hasOwnProperty.call(a2, name); }, get: function(receiver, name) { a0.pop(g1.g1);; return a2[name]; }, set: function(receiver, name, val) { t2[3] = m0;; a2[name] = val; return true; }, iterate: function() { v0 = t2.byteLength;; return (function() { for (var name in a2) { yield name; } })(); }, enumerate: function() { Object.defineProperty(this, \"a1\", { configurable: x, enumerable: true,  get: function() {  return r2.exec(s1); } });; var result = []; for (var name in a2) { result.push(name); }; return result; }, keys: function() { e0.add(o0.b1);; return Object.keys(a2); } }); } catch(e2) { } g1.v1 = (p1 instanceof m0); } else { try { v2 = Object.prototype.isPrototypeOf.call(h0, f0); } catch(e0) { } try { this.p0.__proto__ = m1; } catch(e1) { } try { Array.prototype.sort.apply(a0, [(function(j) { if (j) { try { v0 = evaluate(\"a0.push(s2, t0, g0.b1, e0);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: this.__defineGetter__(\"window\", this), catchTermination: true })); } catch(e0) { } for (var v of o1) { try { Object.defineProperty(this, \"i1\", { configurable: (x % 49 == 18), enumerable: window,  get: function() {  return new Iterator(this.m0); } }); } catch(e0) { } g2.o1 = a2[({valueOf: function() { print(x);return 2; }})]; } } else { v2 + ''; } })]); } catch(e2) { } for (var v of v1) { try { v1 = (h2 instanceof h2); } catch(e0) { } try { this.e0.add(b1); } catch(e1) { } for (var p in t2) { try { v1 = g1.eval(\"function f1(f1) \\\"use asm\\\";   function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    return (((((((0xffffffff) != (0xd5a57e74))*-0x3ef2d)))))|0;\\n  }\\n  return f;\"); } catch(e0) { } try { m2.set(o1.g1, (p={}, (p.z = x)())); } catch(e1) { } v0 + ''; } } } }));");
/*fuzzSeed-42369751*/count=1115; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((Math.fround((Math.asin((( - (((( - ( + (Math.atanh(((y >>> x) >>> 0)) >>> 0))) >>> 0) === ((0/0 >>> ((y ? y : y) >>> 0)) | 0)) | 0)) >>> 0)) >>> 0)) <= Math.fround(Math.sqrt(( + Math.cosh(( + Math.fround(Math.log2(Math.fround(1/0)))))))))); }); testMathyFunction(mathy0, [1, -(2**53), 0x0ffffffff, 0x100000001, -0, Number.MAX_VALUE, -0x080000001, Math.PI, -0x100000000, 2**53, 42, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, 0/0, 0x080000001, -Number.MAX_VALUE, -0x100000001, -0x0ffffffff, -0x07fffffff, -0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, -(2**53+2), -1/0, 0, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000]); ");
/*fuzzSeed-42369751*/count=1116; tryItOut("\"use strict\"; /*bLoop*/for (let fsxoql = 0; fsxoql < 80; ++fsxoql) { if (fsxoql % 21 == 2) { t1[9] = g0.p0; } else { yield d; }  } ");
/*fuzzSeed-42369751*/count=1117; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.pow(Math.fround((( + (y != (Math.max((y | 0), x) | 0))) >> ( + y))), Math.max(y, Math.pow(((y >>> 0) >>> (((Math.atan2((x >>> 0), x) >>> 0) !== 0x07fffffff) >>> 0)), (( ~ ((Math.imul(Math.fround(1/0), (-1/0 | 0)) | 0) >>> 0)) >>> 0)))) >> Math.sin(((Math.sign((Math.trunc((( ~ y) >>> 0)) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy5, [(new Boolean(false)), 0, (new Boolean(true)), ({valueOf:function(){return 0;}}), -0, [], undefined, '\\0', ({toString:function(){return '0';}}), false, objectEmulatingUndefined(), null, 0.1, [0], '0', (new Number(-0)), 1, NaN, (function(){return 0;}), /0/, true, ({valueOf:function(){return '0';}}), '', (new String('')), (new Number(0)), '/0/']); ");
/*fuzzSeed-42369751*/count=1118; tryItOut("testMathyFunction(mathy2, [-0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), 0/0, 2**53+2, 0.000000000000001, -0x100000000, -0x080000000, 42, -0x0ffffffff, 0x07fffffff, -0x07fffffff, 2**53, 0x100000000, -(2**53), 0x080000000, -Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 1, -(2**53-2), 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, -1/0, 0x100000001, -0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0, Math.PI]); ");
/*fuzzSeed-42369751*/count=1119; tryItOut("/*tLoop*/for (let y of /*MARR*/[new String(''), NaN, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, Number.MAX_SAFE_INTEGER, NaN, new String(''), Number.MAX_SAFE_INTEGER, NaN, NaN, new String(''), NaN, Number.MAX_SAFE_INTEGER, NaN, new String(''), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), Number.MAX_SAFE_INTEGER, NaN, NaN, new String(''), Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, new String(''), new String(''), new String(''), Number.MAX_SAFE_INTEGER, NaN, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), 0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000000, new String(''), NaN, 0x080000000, new String(''), Number.MAX_SAFE_INTEGER, new String(''), new String(''), new String(''), new String(''), 0x080000000, new String(''), new String(''), 0x080000000, new String(''), NaN, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), NaN, new String(''), new String(''), 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, new String(''), 0x080000000, 0x080000000, NaN, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), 0x080000000, new String(''), new String(''), new String(''), NaN, Number.MAX_SAFE_INTEGER, 0x080000000, new String(''), 0x080000000, 0x080000000, 0x080000000, new String(''), Number.MAX_SAFE_INTEGER, new String(''), new String(''), NaN, new String(''), 0x080000000, 0x080000000, 0x080000000, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), NaN, NaN, 0x080000000, new String(''), NaN, NaN, NaN, NaN, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]) { \"\\u5B0B\"; }");
/*fuzzSeed-42369751*/count=1120; tryItOut("\"use strict\"; v1 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-42369751*/count=1121; tryItOut("g1.offThreadCompileScript(\"f0 = function(q) { \\\"use strict\\\"; return q; };\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: , noScriptRval: (x % 3 == 1), sourceIsLazy: \"\\u8DAF\", catchTermination: false, element: o1, elementAttributeName: s1, sourceMapURL: s1 }));");
/*fuzzSeed-42369751*/count=1122; tryItOut("");
/*fuzzSeed-42369751*/count=1123; tryItOut("mathy4 = (function(x, y) { return mathy1(Math.max((( ! (Math.ceil(y) >>> 0)) >>> 0), (Math.hypot(Math.fround(Math.fround(mathy0(((x >>> 0) || ( + Math.asinh(( + y)))), -(2**53+2)))), y) | y)), (mathy3(mathy2(x, ( ! (-0x07fffffff >>> 0))), (Math.min((Math.pow(Math.fround((x ? Math.fround(y) : Math.fround(-Number.MAX_SAFE_INTEGER))), x) >>> 0), (Math.fround((( + Math.exp((x >>> 0))) ^ y)) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [0/0, -Number.MAX_VALUE, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, 0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 2**53-2, 0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, 1, Number.MAX_VALUE, -0x100000000, Math.PI, -Number.MIN_VALUE, 1.7976931348623157e308, 1/0, 42, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, 2**53, 2**53+2, 0.000000000000001, -0x100000001, -(2**53+2), -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=1124; tryItOut("\"use strict\"; i2 + f0;");
/*fuzzSeed-42369751*/count=1125; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return (mathy1((Math.log2((((Math.atan2(x, Math.imul(x, ( ! x))) >>> 0) , Math.fround(Math.pow((x >>> 0), ( ! Math.min(2**53-2, Math.sin(y)))))) | 0)) | 0), ( ~ Math.pow(( + ( + Math.imul(1.7976931348623157e308, Math.min(x, (( ~ x) >>> 0))))), Math.pow(x, x)))) | 0); }); testMathyFunction(mathy3, [1/0, 1, -(2**53), -(2**53+2), 1.7976931348623157e308, 0, Number.MIN_VALUE, -0, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x080000001, 0x100000001, 0x080000000, 2**53+2, 42, -Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, -1/0, -(2**53-2), 0x0ffffffff, -0x0ffffffff, 2**53-2, -Number.MAX_VALUE, -0x100000000, 2**53]); ");
/*fuzzSeed-42369751*/count=1126; tryItOut("a0[g2.o1.v0] = x.replace(x, allocationMarker());");
/*fuzzSeed-42369751*/count=1127; tryItOut("mathy0 = (function(x, y) { return ((Math.sinh(Math.fround(Math.atan2(Math.fround(Math.pow(( + ( ~ ( + -(2**53+2)))), (x >>> 0))), Math.fround(x)))) !== (Math.asin(Math.fround(( ! Math.fround(Math.atanh(x))))) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[Infinity, Infinity, null, new Boolean(false), null, new Boolean(false), null, x, new Boolean(false), x, null, x, new Boolean(false), null, null, Infinity, x, Infinity, null, x, new Boolean(false), null, new Boolean(false), new Boolean(false), new Boolean(false), x, Infinity, null, null, x, x, null, new Boolean(false), new Boolean(false), new Boolean(false), Infinity, Infinity, null, Infinity, x, x, Infinity, new Boolean(false), Infinity, Infinity, new Boolean(false), null, x, Infinity, Infinity, Infinity]); ");
/*fuzzSeed-42369751*/count=1128; tryItOut("v1 = new Number(g2);");
/*fuzzSeed-42369751*/count=1129; tryItOut("s1 = this.a2[v0];");
/*fuzzSeed-42369751*/count=1130; tryItOut("testMathyFunction(mathy4, /*MARR*/[(void 0), (void 0),  /x/g , NaN, NaN, (void 0), arguments, (void 0), arguments]); ");
/*fuzzSeed-42369751*/count=1131; tryItOut("t2.set(a2, 0);try { /\\2*/ym; } finally { s2.valueOf = (function(j) { if (j) { m0.set(m1, g0.f2); } else { ( /x/ ); } }); } ");
/*fuzzSeed-42369751*/count=1132; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x0ffffffff, -0, 42, Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000000, 0, 0x100000000, 2**53, 2**53-2, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 1, 1/0, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MAX_VALUE, -0x100000000, 0x080000000, 0x100000001, 2**53+2, -0x100000001, Math.PI, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-42369751*/count=1133; tryItOut("mathy4 = (function(x, y) { return Math.pow(Math.fround((( + (x != Math.fround(Math.imul(Math.fround(( + Math.atan2(((Math.log(( + y)) >>> 0) | 0), ( + Math.log1p((Math.imul(-0x080000001, y) | 0)))))), Math.fround(((x ? (x > ( ! Math.fround(-0x07fffffff))) : x) | 0)))))) >> Math.fround(( - x)))), Math.fround(Math.imul(Math.fround(y), Math.fround((Math.fround(y) , Math.fround(y)))))); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '/0/', undefined, [0], -0, /0/, false, null, NaN, '0', (new Boolean(false)), true, (function(){return 0;}), 0.1, (new Boolean(true)), 1, (new Number(-0)), [], (new String('')), 0, objectEmulatingUndefined(), (new Number(0)), '\\0', '', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-42369751*/count=1134; tryItOut("testMathyFunction(mathy3, [1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 0/0, 2**53+2, -0x100000001, 1, -0x100000000, -(2**53), -0x07fffffff, 42, -0x0ffffffff, 2**53, -0x080000000, Math.PI, Number.MIN_VALUE, 0.000000000000001, 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -(2**53+2), 0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 0x0ffffffff, 0x080000000, -0, 2**53-2, -Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-42369751*/count=1135; tryItOut("print(c === \u3056);");
/*fuzzSeed-42369751*/count=1136; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(((mathy0((( + Math.max(( + x), Math.min(y, (-0x100000001 >>> 0)))) ? y : (((0x080000001 | 0) === (0/0 | 0)) | 0)), x) << Math.fround(Math.expm1(Math.fround(0x0ffffffff)))) >>> 0)), Math.fround((Math.tanh(Math.fround(Math.clz32(Math.imul((( + (x * 1)) | 0), ( + (((( ! ((x >= x) | 0)) >>> 0) | 0) % -Number.MAX_SAFE_INTEGER)))))) | 0)))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -0x0ffffffff, -(2**53), -0x080000001, 42, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, 2**53+2, -0, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, 0/0, -0x100000001, 1, 2**53, -(2**53-2), -0x080000000, -(2**53+2), -0x07fffffff, -1/0, Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, 0, 0x080000000, 0x100000000]); ");
/*fuzzSeed-42369751*/count=1137; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.acosh(( ! Math.fround(mathy1(Math.fround(y), -0x100000001)))) || Math.max(Math.atan2(Math.fround(( + Math.sqrt(Math.fround(x)))), (Math.atanh(( + (y | ( + y)))) >> (Math.log(( ! y)) >>> 0))), Math.tan(( + mathy2(y, ( + x)))))); }); testMathyFunction(mathy3, [2**53, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -0, -1/0, 0, 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, 1/0, 0x080000001, Number.MAX_VALUE, -0x100000000, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 42, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -(2**53), 2**53+2, -0x07fffffff, 1, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=1138; tryItOut("e2 + '';");
/*fuzzSeed-42369751*/count=1139; tryItOut("\"use strict\"; (/(?=\\1|\\1\\r{4,8})*|\u1e6a\\S?{2,}/g);( /x/ );");
/*fuzzSeed-42369751*/count=1140; tryItOut("return ((void shapeOf(27)));for(let x in /*MARR*/[new String(''), new Number(1.5), new Number(1.5), ['z'], new String(''), new String(''), x, ['z'], new Number(1.5), new Number(1.5), ['z'], x, ['z'], new Number(1.5), x, new String(''), new String(''), ['z'], x, new String(''), new String(''), new String(''), new String(''), new String(''), ['z'], new Number(1.5), x, ['z'], x, new Number(1.5), new String(''), new String(''), ['z'], x, new String(''), ['z'], x, ['z'], ['z'], new Number(1.5), new Number(1.5), ['z'], x, new String(''), new Number(1.5), new Number(1.5), new String(''), x, new Number(1.5), ['z'], new String(''), x, new String(''), x, x, new Number(1.5)]) return;");
/*fuzzSeed-42369751*/count=1141; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions('compartment'); } void 0; }");
/*fuzzSeed-42369751*/count=1142; tryItOut("testMathyFunction(mathy0, [Number.MAX_VALUE, 0/0, 1.7976931348623157e308, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, 2**53, 0x100000000, -0, 2**53+2, 0, -0x100000001, -(2**53+2), -Number.MAX_VALUE, -0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, 0x080000001, -1/0, -(2**53-2), 1/0, 0x0ffffffff, 1, 0x07fffffff, 0x080000000, Number.MIN_VALUE, -(2**53), -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2]); ");
/*fuzzSeed-42369751*/count=1143; tryItOut("g0.i2.valueOf = (function(j) { if (j) { try { for (var p in g2) { try { v0 = (g0.m2 instanceof g0.a1); } catch(e0) { } try { a0.sort((function() { t1[12] = -5; return m0; })); } catch(e1) { } try { v2 = o2[\"ceil\"]; } catch(e2) { } o2.e0 = t1[4]; } } catch(e0) { } i2.send(i2); } else { for (var p in a0) { try { m0.valueOf = (function() { try { v2 = t2.byteOffset; } catch(e0) { } try { h1.getPropertyDescriptor = o1.f0; } catch(e1) { } m0.get(x ? /.+|\\B{3,}([\\cB-\\cY\\ud34B-\\uC4Ff\\S\u5905])|(?!\\uCbC7)+?[\u0004]\\u4c24+/y : window | x); return s2; }); } catch(e0) { } try { Array.prototype.unshift.call(a0, b2); } catch(e1) { } selectforgc(o1); } } });");
/*fuzzSeed-42369751*/count=1144; tryItOut("mathy0 = (function(x, y) { return (Math.round(Math.pow(((( ~ (Math.max(Number.MAX_SAFE_INTEGER, Math.fround(Math.imul(Math.fround(y), (x | 0)))) >>> 0)) >>> 0) | 0), Math.round(Math.PI))) >>> 0); }); testMathyFunction(mathy0, [-0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, 2**53+2, 42, -0, 0x100000000, -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -(2**53), -(2**53-2), Number.MAX_VALUE, 1, Math.PI, Number.MIN_VALUE, 0, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, -0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, -0x07fffffff, 1/0, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-42369751*/count=1145; tryItOut("v0 = Object.prototype.isPrototypeOf.call(o1.m0, e2);");
/*fuzzSeed-42369751*/count=1146; tryItOut("a1 = arguments;");
/*fuzzSeed-42369751*/count=1147; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((/*FFI*/ff(((-9.671406556917033e+24)), ((((+(1.0/0.0))) - ((((4277)) % ((0x8d3c3871)))))), (((d1) + (-32768.0))), ((+(((0xd01254cb)+(0xfee59ff6)+(0xffffffff))>>>((0x437f8a42) % (0x5179bb5f))))), ((+abs(((d1))))), ((-1.0625)))|0)+(0xfe08df9a)))|0;\n  }\n  return f; })(this, {ff: Array.prototype.indexOf}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x080000001, 2**53+2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, -1/0, 0x07fffffff, 2**53-2, 0x100000001, 1/0, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, Number.MIN_VALUE, 1, 0x100000000, 42, -0x0ffffffff, -(2**53), -(2**53-2), Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 0, 0x080000001, 0x080000000, 0.000000000000001, 2**53, 0/0]); ");
/*fuzzSeed-42369751*/count=1148; tryItOut("this.v1 = this.g1.runOffThreadScript();");
/*fuzzSeed-42369751*/count=1149; tryItOut("g1 = a1[7];function z()\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ceil = stdlib.Math.ceil;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 1025.0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = -0.0078125;\n    var i6 = 0;\n    d2 = (+atan2(((( \"\"  -= null).eval(\"print(x);\"))), ((((d1)) / ((d2))))));\n    i3 = (0x485a9a1);\n    return +((((+ceil(((((d2))))))) / ((Float32ArrayView[((0xfb2a18d9)+(!((+(0.0/0.0)) >= (d1)))) >> 2]))));\n    i4 = (i4);\n    return +((Float64ArrayView[1]));\n  }\n  return f;if(true) print(18);");
/*fuzzSeed-42369751*/count=1150; tryItOut("\"use strict\"; \"use asm\"; m1.set((void version(180)), p0);");
/*fuzzSeed-42369751*/count=1151; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.cos(( ~ (Math.fround((Math.fround(Math.pow(Math.clz32(-0x0ffffffff), y)) << Math.fround(( + x)))) >>> 0))); }); testMathyFunction(mathy0, [0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, -Number.MAX_VALUE, 1, Math.PI, 1.7976931348623157e308, -(2**53), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, 0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 0x07fffffff, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, -0x100000000, 0.000000000000001, -(2**53-2), -0x080000001, 0/0, 42, 0x100000001, 1/0, -0x0ffffffff, -1/0, 0x080000000, 2**53+2]); ");
/*fuzzSeed-42369751*/count=1152; tryItOut("delete o2.t1[\"valueOf\"];");
/*fuzzSeed-42369751*/count=1153; tryItOut("v1 = g0.eval(\"e2.add(b2);\");");
/*fuzzSeed-42369751*/count=1154; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((4194304.0));\n    return +((-3.8685626227668134e+25));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); ");
/*fuzzSeed-42369751*/count=1155; tryItOut("\"use strict\"; for(let a in  ? (arguments[\"x\"]) = x : this.__defineSetter__(\"d\", mathy5) - x) {v2 = Object.prototype.isPrototypeOf.call(o2.a2, f1); }");
/*fuzzSeed-42369751*/count=1156; tryItOut("i1 = t0[x];");
/*fuzzSeed-42369751*/count=1157; tryItOut("\"use strict\"; try { window.eval = b; } catch(b) { y.constructor; } ");
/*fuzzSeed-42369751*/count=1158; tryItOut("\"use strict\"; for(let [y, x] = -13 in new RegExp(\"(?!\\\\D){4}\", \"\")) {print(x);/*MXX1*/o2 = g0.Date.name; }");
/*fuzzSeed-42369751*/count=1159; tryItOut("m0.get(i2);");
/*fuzzSeed-42369751*/count=1160; tryItOut("/*MXX1*/o1 = g1.Uint8ClampedArray;");
/*fuzzSeed-42369751*/count=1161; tryItOut("\"use strict\"; f1.toString = f0;");
/*fuzzSeed-42369751*/count=1162; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.min(Math.atan2(mathy2(( - 0x07fffffff), (Math.exp(Math.fround(42)) ** Math.fround(Math.pow(y, (( + y) < ( + (( + -0) >> y))))))), ( ! (( ! (Math.imul((y | 0), (Math.sin(Math.PI) | 0)) | 0)) >>> 0))), Math.asin(( + (( ! (( + Math.max(( + y), ( + ( + (( + ((x >>> 0) | Math.fround(42))) << Math.fround(mathy0(Math.fround(y), Math.fround(x)))))))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [2**53+2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, 1, -0x100000000, Math.PI, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 1/0, 2**53, -(2**53-2), 42, -1/0, -(2**53+2), 0, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff, 2**53-2, 1.7976931348623157e308, -0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, 0.000000000000001, 0x100000000, -0, 0/0, 0x080000000]); ");
/*fuzzSeed-42369751*/count=1163; tryItOut("mathy2 = (function(x, y) { return Math.fround((( + (((Math.hypot((-(2**53-2) | 0), (x | 0)) | 0) ? (( + y) ? Math.fround(y) : ( + y)) : (Math.expm1((Math.atan2((( + Math.fround(((y >>> 0) ? 42 : Math.fround(x)))) - -1/0), Math.cosh(x)) >>> 0)) >>> 0)) | 0)) || ( + Math.max(( + mathy0(Math.trunc((( + Math.tanh(y)) >>> 0)), (x | 0))), ( + (Math.asin(( + y)) ? Math.sign(y) : (Math.fround(Math.abs(Math.fround((0x080000001 ? Math.PI : y)))) >>> 0))))))); }); testMathyFunction(mathy2, [-0x080000001, Number.MAX_VALUE, 0x080000000, -1/0, -Number.MIN_VALUE, -(2**53), 2**53, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x100000001, 1, 0x0ffffffff, 0, 0/0, -(2**53-2), 0x100000001, 0.000000000000001, 0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, 1/0, -0x0ffffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, 2**53+2, -0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-42369751*/count=1164; tryItOut("/*bLoop*/for (let jgwtzq = 0; jgwtzq < 62 && ((4277)); ++jgwtzq) { if (jgwtzq % 3 == 0) { e0.add(m0); } else { o1.o2.v2 = evaluate(\"\\\"use strict\\\"; a1.push(g2.e2);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 6 != 0), noScriptRval: let (d) /(?:.)?/gyi, sourceIsLazy: true, catchTermination: true })); }  } ");
/*fuzzSeed-42369751*/count=1165; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.sqrt(((( ! (( + Math.imul(Math.atan2((x | 0), x), x)) >>> 0)) * Math.fround(Math.pow(( + (x & ( + -0x080000001))), Math.fround(y)))) | 0))); }); ");
/*fuzzSeed-42369751*/count=1166; tryItOut("testMathyFunction(mathy1, /*MARR*/[new Boolean(false), function(){},  /x/g , new Boolean(false), new Boolean(false),  /x/g , function(){}, function(){},  /x/g , function(){}, function(){}, function(){},  /x/g , new Boolean(false), new Boolean(false), function(){},  /x/g ,  /x/g , new Boolean(false),  /x/g , function(){},  /x/g ,  /x/g , new Boolean(false), function(){}, function(){}, new Boolean(false),  /x/g ,  /x/g , function(){}, function(){}, function(){},  /x/g , function(){}, new Boolean(false), function(){}, function(){}, new Boolean(false), function(){}, function(){}, function(){}, function(){}, new Boolean(false), function(){},  /x/g , new Boolean(false), function(){}]); ");
/*fuzzSeed-42369751*/count=1167; tryItOut("a0.forEach((function() { try { v1 = evaluate(\"mathy5 = (function(x, y) { return Math.fround((Math.fround(( + (( + mathy4(( + x), ( + x))) >>> ((x ** (Math.min((x >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)) & (Math.min(x, x) >>> 0))))) / Math.fround(Math.sinh(mathy2(Math.log1p(Math.min(( + x), y)), Math.cbrt((( ~ y) + y))))))); }); \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: new RegExp(\"(?:[\\\\s\\\\t-\\u00d1\\\\n])\", \"g\"), sourceIsLazy: (p={}, (p.z = this)()) &&  ''  % eval, catchTermination: false })); } catch(e0) { } i0.send(e0); return p1; }));");
/*fuzzSeed-42369751*/count=1168; tryItOut("e = linkedList(e, 360);");
/*fuzzSeed-42369751*/count=1169; tryItOut("\"use strict\"; a2 = Array.prototype.concat.apply(o2.a1, [a2, a0]);");
/*fuzzSeed-42369751*/count=1170; tryItOut("mathy2 = (function(x, y) { return (Math.log1p(((Math.acos(( + x)) > (Math.min(Math.exp(Math.max(( - mathy0(y, x)), x)), (mathy0(y, mathy1(Math.fround(-0x080000000), (Math.min(y, (Math.hypot(x, x) | 0)) >>> 0))) >>> 0)) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-42369751*/count=1171; tryItOut("this.e0 = new Set(t0);");
/*fuzzSeed-42369751*/count=1172; tryItOut("f2 = t1[this.o1.v2];");
/*fuzzSeed-42369751*/count=1173; tryItOut("\"use strict\"; const b = ({b: o0.e0 + this.e1});Array.prototype.forEach.apply(a2, [Math.round.bind(o0)]);");
/*fuzzSeed-42369751*/count=1174; tryItOut("a1.unshift(g2.f0);");
/*fuzzSeed-42369751*/count=1175; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return Math.sqrt(Math.fround(Math.max((( ! -Number.MAX_VALUE) >>> 0), (Math.ceil((( - ( + Math.pow((y | 0), ((Math.imul(y, Math.pow(y, y)) >>> 0) | 0)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[arguments.caller, arguments.caller, x, new Boolean(true), allocationMarker(),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x]); ");
/*fuzzSeed-42369751*/count=1176; tryItOut("o2.v2 = (e0 instanceof e1);");
/*fuzzSeed-42369751*/count=1177; tryItOut("v1 = t0.length;");
/*fuzzSeed-42369751*/count=1178; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log(( + Math.max(( - Math.log2(0x100000000)), Math.atan2(Math.fround(y), Math.fround(Math.cbrt(( + Math.fround(( ~ Math.fround(x)))))))))); }); testMathyFunction(mathy0, /*MARR*/[ /x/g ,  /x/g , (4277), (0/0), (0/0), this,  /x/g , (0/0), this, (4277), {}, this,  /x/g , {}, {}, (4277), (0/0), (0/0),  /x/g , this, (4277), this, {}, (4277), this, (0/0), {}, (4277), (0/0), {}, (0/0), {},  /x/g , (0/0),  /x/g , {}, (4277), (4277), (4277), (4277), {}, (0/0), (4277), {}, {}, (4277)]); ");
/*fuzzSeed-42369751*/count=1179; tryItOut("testMathyFunction(mathy2, /*MARR*/[0.1, 0.1, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], x, new Boolean(true), 0.1, [1], [1], 0.1, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], (0/0), [1], (0/0), (0/0), new Boolean(true), [1], new Boolean(true), x, [1], x, [1], new Boolean(true), (0/0), x, [1], (0/0), [1], [1], (0/0), x, new Boolean(true), new Boolean(true), new Boolean(true), x, [1], 0.1, [1], (0/0), (0/0), new Boolean(true), x, (0/0), (0/0), (0/0), x, (0/0), x, new Boolean(true), [1], 0.1, (0/0), 0.1, [1], [1], x, (0/0), 0.1, [1], 0.1, new Boolean(true), (0/0), new Boolean(true), (0/0), [1], 0.1, [1], x]); ");
/*fuzzSeed-42369751*/count=1180; tryItOut("mathy4 = (function(x, y) { return Math.log2((Math.log((Math.fround(( ! Math.fround(x))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [[], ({valueOf:function(){return '0';}}), '/0/', (new Boolean(false)), 0, '\\0', 1, undefined, null, false, -0, NaN, true, (new Number(-0)), (new String('')), objectEmulatingUndefined(), ({toString:function(){return '0';}}), '', ({valueOf:function(){return 0;}}), (function(){return 0;}), [0], (new Number(0)), 0.1, (new Boolean(true)), '0', /0/]); ");
/*fuzzSeed-42369751*/count=1181; tryItOut("\"use strict\"; e2.toString = (function(j) { o0.f2(j); });");
/*fuzzSeed-42369751*/count=1182; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=1183; tryItOut("/*RXUB*/var r = /.((?=\\1(?=[\\D\u588f\\s\\s]{1})|\\1))|(\\D)*?(?:(?:${4})){0}*/gyim; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-42369751*/count=1184; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; void gc(); } void 0; } 25;function x() { \"use strict\"; return  /x/g  } print(x);");
/*fuzzSeed-42369751*/count=1185; tryItOut("mathy0 = (function(x, y) { return (((( ! (((y + (Math.atan2(( + ( ! x)), ( + (-Number.MAX_VALUE ? y : x))) >>> 0)) | 0) | 0)) | 0) ? ((( - ( - x)) | 0) >>> 0) : (((Math.pow(Math.fround(x), Math.fround(( + Math.atan(y)))) >>> 0) < Math.pow((x | 0), ((Math.ceil((2**53+2 >>> 0)) >>> 0) | 0))) >>> 0)) ** ( - ( + Math.pow(Math.cbrt(y), x)))); }); ");
/*fuzzSeed-42369751*/count=1186; tryItOut("/*infloop*/for(var e = x; x; x) g0.v0 = g1.runOffThreadScript();");
/*fuzzSeed-42369751*/count=1187; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.log2(Math.fround((Math.fround(Math.fround(Math.max(Math.fround(( - mathy1(( ! -Number.MIN_SAFE_INTEGER), Number.MIN_SAFE_INTEGER))), Math.fround(((Math.asin(Math.PI) >>> 0) ? y : (( - Math.fround(y)) >>> 0)))))) ? Math.fround(Math.fround((Math.fround((Math.fround(mathy2(x, 0.000000000000001)) != (y ? (( + y) || x) : ( + 1/0)))) ** ( - (y || ((( - (1.7976931348623157e308 >>> 0)) >>> 0) | 0)))))) : Math.exp(Math.expm1(x))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, -0x100000001, -0x07fffffff, 42, -0, -0x080000000, -0x080000001, 1/0, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, 0x080000000, -(2**53), 1, -Number.MIN_VALUE, 2**53, 2**53-2, Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -0x0ffffffff, Math.PI, 0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=1188; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      return (((i0)+(((-((-1.5111572745182865e+23))) & ((i1)-(i1))))))|0;\n    }\n    return ((((0xdf7bae7f))+(i1)))|0;\n    (Float64ArrayView[2]) = (((((i0)-(i0)-(i1)) | ((i1)-((((i1))|0) < (((/*FFI*/ff(((-7.555786372591432e+22)), ((0.0625)), ((1.001953125)), ((-2251799813685249.0)), ((288230376151711740.0)), ((-7.555786372591432e+22)), ((-3.094850098213451e+26)), ((1.1805916207174113e+21)), ((-4.835703278458517e+24)), ((-68719476736.0)), ((-129.0)))|0)) & ((0x5426f315)+(0x8d94b528)+(0xfde3c24b)))))) == (((!((((function sum_slicing(syzpwk) { ; return syzpwk.length == 0 ? 0 : syzpwk[0] + sum_slicing(syzpwk.slice(1)); })(/*MARR*/[]))) <= (((0xfaddb1ac))>>>((0xb5be9ddc)))))*0x8f39e) | ((/*FFI*/ff(((-8796093022209.0)), ((~~(+(-1.0/0.0)))), ((((-67108865.0)) - ((-524289.0)))), ((-((3.8685626227668134e+25)))), ((1.888946593147858e+22)), ((-1.5474250491067253e+26)), ((32.0)), ((1.888946593147858e+22)), ((-7.555786372591432e+22)), ((-536870913.0)), ((-4097.0)), ((-0.0009765625)), ((-1.001953125)))|0)*-0x9bb2e))));\n    i1 = ((/*RXUE*//.|(?=\\b){1,3}|\\2+|$$|.{2,}\\D[\\u672B\\D\u35ac]{4,8}?\\2.*/yim.exec(\"\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\u008e\\ua752\\u08d5\\n\\n\\n\\n\\n0\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\u008e\\ua752\\u08d5\\n\\n\\n\\n\\n0\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\u008e\\ua752\\u08d5\\n\\n\\n\\n\\n0\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\ua752\\u08d5\\n\\n\\n\\n\\n\\u008e\\ua752\\u08d5\\n\\n\\n\\n\\n0\\n\")));\n    return (((0x75953db7) % (0xdfb6e198)))|0;\n  }\n  return f; })(this, {ff: (decodeURI).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0x0ffffffff, 2**53-2, -(2**53-2), 0x100000001, 0.000000000000001, 0x07fffffff, -0x07fffffff, Number.MAX_VALUE, 2**53+2, Math.PI, 1.7976931348623157e308, 1, 1/0, Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -(2**53+2), 42, -0x100000001, 0x080000000, 0x100000000, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 0/0]); ");
/*fuzzSeed-42369751*/count=1189; tryItOut("v2 = Object.prototype.isPrototypeOf.call(v1, o2.a1);");
/*fuzzSeed-42369751*/count=1190; tryItOut("print(x);const d =  '' ;");
/*fuzzSeed-42369751*/count=1191; tryItOut("i2.next();");
/*fuzzSeed-42369751*/count=1192; tryItOut("e0.add(o1.f0);");
/*fuzzSeed-42369751*/count=1193; tryItOut("x + x;");
/*fuzzSeed-42369751*/count=1194; tryItOut("testMathyFunction(mathy5, [-0x080000001, 1, 0/0, 2**53-2, 0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, -1/0, -0x07fffffff, 0x100000000, -(2**53+2), -(2**53), 0, -Number.MIN_VALUE, -0x0ffffffff, 1/0, -0x080000000, Number.MIN_VALUE, Math.PI, -0x100000001, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, 0x080000001, 0.000000000000001, -0x100000000, Number.MAX_VALUE, 0x080000000, 42, 2**53, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=1195; tryItOut("i1 = new Iterator(v2, true);");
/*fuzzSeed-42369751*/count=1196; tryItOut("v0 = (f2 instanceof b1);");
/*fuzzSeed-42369751*/count=1197; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + ((Math.asinh((( ! Math.fround((x ? (( + (x >>> 0)) >>> 0) : 0x080000001))) >>> 0)) >>> 0) >= ((( + ( - x)) ? (( + x) | 0) : ((Math.asin((0x080000000 | 0)) | 0) | 0)) | 0))); }); testMathyFunction(mathy1, /*MARR*/[null, [1], function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), function(){}, x, function(){}, [1], objectEmulatingUndefined(), null, x, x, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), [1], null, function(){}, [1], null, null, [1], null, x, x, function(){}, objectEmulatingUndefined(), null, [1], null, [1], objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], function(){}, x, objectEmulatingUndefined(), x, null, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, x, x, null, objectEmulatingUndefined(), function(){}, null, [1], function(){}, x, function(){}, function(){}, null, [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], x, null, [1], function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, [1], x, objectEmulatingUndefined(), x, [1], null, [1], [1], x, function(){}, x, [1], objectEmulatingUndefined(), null, x, function(){}, x]); ");
/*fuzzSeed-42369751*/count=1198; tryItOut("testMathyFunction(mathy2, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, -0x080000001, 0x100000000, -1/0, 0x0ffffffff, 2**53+2, Math.PI, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), 0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, -(2**53+2), Number.MAX_VALUE, -0, 0x080000000, -(2**53-2), 2**53, 42, 1, -0x100000001, 0, -0x080000000, -Number.MIN_VALUE, -0x07fffffff, 0x100000001, 1.7976931348623157e308, 1/0]); ");
/*fuzzSeed-42369751*/count=1199; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1/gyim; var s = \"0\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-42369751*/count=1200; tryItOut("\"use strict\"; with({z: let (x) \"\\u732C\"}){f0 + '';v0 = Object.prototype.isPrototypeOf.call(e1, h2); }");
/*fuzzSeed-42369751*/count=1201; tryItOut("f1(o2.g2.t0);");
/*fuzzSeed-42369751*/count=1202; tryItOut("\"use strict\"; m2.has(p0);");
/*fuzzSeed-42369751*/count=1203; tryItOut("a2[18];");
/*fuzzSeed-42369751*/count=1204; tryItOut("");
/*fuzzSeed-42369751*/count=1205; tryItOut("v0 = undefined;function NaN({}, ...x) { yield x } this.a2 = a2[v0];v0 = new Number(m1);");
/*fuzzSeed-42369751*/count=1206; tryItOut("\"use strict\"; zaoaln( /x/ , ([] = timeout(1800)));/*hhh*/function zaoaln(x = (({y: /*UUV2*/(y.replace = y.codePointAt)}))){this.g0.a2 = r1.exec(s0);}");
/*fuzzSeed-42369751*/count=1207; tryItOut("Array.prototype.sort.call(a2, (function mcc_() { var pdpybc = 0; return function() { ++pdpybc; if (/*ICCD*/pdpybc % 11 == 0) { dumpln('hit!'); p0.valueOf = (function() { try { v2 = g1.eval(\"/*UUV2*/(x.keyFor = x.toString)\"); } catch(e0) { } try { a1.push(m0, i1, g1, o2.h2, p0); } catch(e1) { } v1 = new Number(4.2); throw p2; }); } else { dumpln('miss!'); try { s2 += s1; } catch(e0) { } s2 + o0; } };})(), this.v0);");
/*fuzzSeed-42369751*/count=1208; tryItOut("mathy1 = (function(x, y) { return Math.max(( + ((( ! (Math.min(( - (( ~ (x >>> 0)) >>> 0)), x) >>> 0)) | 0) >= ( + (((((Math.max((x | 0), (-0x080000000 | 0)) | 0) | 0) & ( + mathy0(-0x080000000, (x - ( + -0x100000001))))) | 0) ? Math.round(Math.atan((x | 0))) : x)))), (Math.tan((Math.imul((Math.fround(Math.fround((((( + Math.asinh(( + y))) >>> 0) / (((x ^ (x >>> 0)) >>> 0) >>> 0)) >>> 0))) >>> 0), (((y ? ( + mathy0(x, ( + x))) : ( + x)) % y) >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy1, [42, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 2**53+2, 0.000000000000001, -(2**53), -1/0, -0, 0x100000000, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0x080000001, 0x0ffffffff, -0x100000000, 0x100000001, 2**53, -(2**53-2), 0/0, -0x080000001, 1/0, Math.PI, 0, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 0x07fffffff, -0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42369751*/count=1209; tryItOut("mathy0 = (function(x, y) { return ((Math.fround(Math.cbrt(((x && ( + ( ~ (x | 0)))) | 0))) >>> 0) | ((Math.hypot((Math.log2((Math.abs((-0 >>> 0)) >>> 0)) >>> 0), (Math.min(( + Math.pow(( + ( ! 2**53)), Math.min(-0x07fffffff, 1))), Math.fround(x)) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 2**53, 42, -0x100000001, -0x080000001, 1/0, Number.MAX_VALUE, -Number.MIN_VALUE, 1, 0, 0x0ffffffff, -0, 0x100000000, 0/0, 2**53+2, 0x080000000, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, 0x100000001, -0x100000000, -0x07fffffff, 1.7976931348623157e308, 0x080000001, -Number.MAX_VALUE, -1/0, 2**53-2, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, -0x080000000, 0.000000000000001]); ");
/*fuzzSeed-42369751*/count=1210; tryItOut("(void schedulegc(o1.g0));");
/*fuzzSeed-42369751*/count=1211; tryItOut("mathy1 = (function(x, y) { return Math.hypot(( + (Math.fround(( + ((( + (mathy0(Math.fround(x), ( - ( ~ y))) | 0)) < (-0x07fffffff >>> 0)) >>> 0))) | 0)), Math.abs(Math.fround(Math.min(Math.PI, (((mathy0(y, -0x0ffffffff) ? (( - y) >>> 0) : (( ~ y) >>> 0)) >>> 0) + Math.acos(y)))))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 1, -0x100000000, 1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, -1/0, 0, 0x080000001, 0x0ffffffff, 0.000000000000001, 0x080000000, -Number.MIN_VALUE, 0x07fffffff, -0, -0x100000001, 0x100000001, 0/0, -(2**53-2), -(2**53), 0x100000000, 1.7976931348623157e308, -0x07fffffff, Math.PI, 2**53+2, 42, Number.MAX_VALUE, 2**53-2, -0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-42369751*/count=1212; tryItOut("for (var p in v1) { for (var p in g1.b0) { try { o0.v0 = evalcx(\"/*RXUB*/var r = (void options('strict_mode')); var s = \\\"\\\"; print(r.test(s)); print(r.lastIndex); \", g1); } catch(e0) { } try { Array.prototype.sort.apply(a2, [String.prototype.lastIndexOf, v2, a2]); } catch(e1) { } try { h2.set = (function() { try { b1 = t1.buffer; } catch(e0) { } try { t0 = x; } catch(e1) { } const this.v2 = r1.sticky; return v1; }); } catch(e2) { } a1.__proto__ = o1.i0; } }");
/*fuzzSeed-42369751*/count=1213; tryItOut("this.m1.toString = (function(j) { if (j) { try { v1 = (o0.g1.o1.f1 instanceof o1); } catch(e0) { } try { Array.prototype.sort.apply(o0.a0, [(function() { g1 = a2[v2]; return h0; })]); } catch(e1) { } try { Array.prototype.sort.apply(a2, [(function() { try { for (var v of o1.h1) { try { v2 = g2.eval(\"this.e2.toSource = (function() { for (var j=0;j<51;++j) { o1.f1(j%5==1); } });\"); } catch(e0) { } try { o0.m2.set(a0, a2); } catch(e1) { } v0 = t0.length; } } catch(e0) { } try { g0.v2 = Object.prototype.isPrototypeOf.call(p1, v2); } catch(e1) { } try { Array.prototype.forEach.call(a2, (function(j) { if (j) { for (var v of t0) { v0 = g1.g2.runOffThreadScript(); } } else { /*MXX1*/this.o2 = g2.Date.prototype.getUTCMilliseconds; } }), (void options('strict_mode'))); } catch(e2) { } b1 = new ArrayBuffer(8); return f2; })]); } catch(e2) { } e2.delete(v0); } else { try { this.b1 + ''; } catch(e0) { } try { o1 + ''; } catch(e1) { } for (var v of this.a0) { try { m0.set(h2, e2); } catch(e0) { } a0.toString = (function() { try { s1 += 'x'; } catch(e0) { } v2 = evaluate(\"()\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 37 != 26), catchTermination: window })); return v0; }); } } });");
/*fuzzSeed-42369751*/count=1214; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, Number.MAX_VALUE, 1, 2**53, 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 0x0ffffffff, -(2**53), -(2**53-2), -0x100000000, 1.7976931348623157e308, 0x100000000, 0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 1/0, 42, -0x0ffffffff, -Number.MIN_VALUE, -1/0, 0x080000001, -0, -0x100000001, 2**53+2, -0x080000000, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, 0x080000000]); ");
/*fuzzSeed-42369751*/count=1215; tryItOut("function f2(s2) \"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xa9bfbaff)-(0x70dbdeea)))|0;\n    (Uint16ArrayView[1]) = ((0xffffffff)*-0x6e879);\n    d0 = ((+(-1.0/0.0)) + (+(1.0/0.0)));\ne2 = new Set;    return (((0x126c653c)))|0;\n  }\n  return f;v0 = (g0 instanceof p0);");
/*fuzzSeed-42369751*/count=1216; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i1 = (0x6cc54267);\n    }\n    d0 = (+(0.0/0.0));\n    d0 = (18014398509481984.0);\n    i1 = (i2);\n    return ((((~~(562949953421312.0)))-(i2)))|0;\n    i2 = ((((i1)-((abs((((0xffffffff)-(0xfda40619)-(0x1a171365)) ^ (((0x620a1777) >= (0x0)))))|0) != (~(((((0x83e71336))>>>((0xfdfa97e4))) != (0x69fc85c2))))))>>>((imul((/*FFI*/ff(((~~(d0))), ((((0xc27e5f88)) | ((0xfdb5da33)))))|0), (i2))|0) / (timeout(1800) -= [({})]))));\n    d0 = (-9.671406556917033e+24);\n    i2 = (0xf8595192);\n    d0 = (d0);\n    (Int32ArrayView[2]) = ((i1)+(0xffffffff)+((+((+(-1.0/0.0)))) > (d0)));\n    return (((i1)+(0xffffffff)))|0;\n  }\n  return f; })(this, {ff: mathy1}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x080000000, Number.MAX_SAFE_INTEGER, 42, 2**53-2, -0x080000001, -0x0ffffffff, -(2**53-2), 0x100000000, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, 0, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 2**53, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, 1, 0x100000001, 0x080000001, -0, 1.7976931348623157e308, 2**53+2, -0x080000000, 1/0, -(2**53), -0x100000001]); ");
/*fuzzSeed-42369751*/count=1217; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42369751*/count=1218; tryItOut("t0[16] = e0;");
/*fuzzSeed-42369751*/count=1219; tryItOut("g1.s2 += s2;");
/*fuzzSeed-42369751*/count=1220; tryItOut("\"use strict\"; a1 = a0.map((function() { try { selectforgc(g2.o0); } catch(e0) { } try { Object.prototype.unwatch.call(h1, \"apply\"); } catch(e1) { } a2 = Array.prototype.map.call(a1, (function() { try { h0 = ({getOwnPropertyDescriptor: function(name) { g1.valueOf = (function() { try { for (var v of f1) { try { Array.prototype.sort.apply(a2, [(function() { for (var j=0;j<2;++j) { f2(j%4==1); } })]); } catch(e0) { } try { m0.set(p1, i0); } catch(e1) { } m2.get(p1); } } catch(e0) { } v0 = (g2 instanceof e0); return s0; });; var desc = Object.getOwnPropertyDescriptor(v1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g2.offThreadCompileScript(\"function f0(g0.h2) 'fafafa'.replace(/a/g, (function (g0.h2)\\\"use asm\\\";   var NaN = stdlib.NaN;\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    d1 = (NaN);\\n    return +((((3.094850098213451e+26)) * ((((NaN)) - ((3.022314549036573e+23))))));\\n  }\\n  return f;).apply)\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 5), noScriptRval: (x % 55 == 54), sourceIsLazy: (x % 6 == 4), catchTermination: (x % 8 == 6) }));; var desc = Object.getPropertyDescriptor(v1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { g2.offThreadCompileScript(\"function f0(b1)  { v0 = evaluate(\\\"new RegExp(\\\\\\\"((?:[^])){3}\\\\\\\", \\\\\\\"im\\\\\\\")\\\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 29 != 2), sourceIsLazy: (b1 % 6 != 5), catchTermination: true })); } \", ({ global: this.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 14 != 0), catchTermination: (4277) }));; Object.defineProperty(v1, name, desc); }, getOwnPropertyNames: function() { f1.toString = (function() { Object.defineProperty(this, \"v1\", { configurable: false, enumerable: false,  get: function() {  return a2.length; } }); throw m2; });; return Object.getOwnPropertyNames(v1); }, delete: function(name) { g1.v1 = true;; return delete v1[name]; }, fix: function() { delete h0.keys;; if (Object.isFrozen(v1)) { return Object.getOwnProperties(v1); } }, has: function(name) { i1.next();; return name in v1; }, hasOwn: function(name) { this.v1 = t2.byteOffset;; return Object.prototype.hasOwnProperty.call(v1, name); }, get: function(receiver, name) { o0.v1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 1048577.0;\n    d1 = (+(0xe7027915));\n    i0 = (0xfe14a72e);\n    i0 = (0x9be3c1);\n    return +((d1));\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096));; return v1[name]; }, set: function(receiver, name, val) { throw v2; v1[name] = val; return true; }, iterate: function() { e0.has(g0.p2);; return (function() { for (var name in v1) { yield name; } })(); }, enumerate: function() { v2 = t1.length;; var result = []; for (var name in v1) { result.push(name); }; return result; }, keys: function() { a1 = Array.prototype.map.call(a2, (function() { g0.valueOf = objectEmulatingUndefined; return g2; }));; return Object.keys(v1); } }); } catch(e0) { } try { v1 = (i2 instanceof g2); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(s0, b2); } catch(e2) { } e2 = new Set(t0); return e2; })); return p0; }));");
/*fuzzSeed-42369751*/count=1221; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-42369751*/count=1222; tryItOut("if(x) { if ((void options('strict_mode'))) {m2 = g0.objectEmulatingUndefined();var a0 = []; } else /*MXX3*/g0.Date.prototype.setYear = g2.Date.prototype.setYear;}");
/*fuzzSeed-42369751*/count=1223; tryItOut("\"use strict\"; M:while(( /x/ ) && 0){o0 = new Object; }/*hhh*/function uampaz(x = x){print(-16);const z = \"\\u76AB\";}uampaz();");
/*fuzzSeed-42369751*/count=1224; tryItOut("const z, bjvnws, window = ((yield (/*wrap1*/(function(){ (\"\\uCA1D\");return arguments.callee.caller.caller})()).call((new (\"\\uA2A6\")(0,  /x/ )), ))), e = (x), wjvfvl, [] = (({x: [], b: true })), hdprfv;a1 = a0;var y = (makeFinalizeObserver('tenured'));");
/*fuzzSeed-42369751*/count=1225; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?=(?:(\\B){1073741825,})))/im; var s = \"  \"; print(s.split(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
