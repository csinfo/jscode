

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
/*fuzzSeed-244067732*/count=1; tryItOut("x = linkedList(x, 3240);");
/*fuzzSeed-244067732*/count=2; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=3; tryItOut("ewnlil(/*\n*/x);/*hhh*/function ewnlil(){var hvvbcb = new ArrayBuffer(2); var hvvbcb_0 = new Uint16Array(hvvbcb); hvvbcb_0[0] = 13; var hvvbcb_1 = new Uint16Array(hvvbcb); print(hvvbcb_1[0]); hvvbcb_1[0] = -19; var hvvbcb_2 = new Float32Array(hvvbcb); print(hvvbcb_2[0]); var hvvbcb_3 = new Uint16Array(hvvbcb); print(hvvbcb_3[0]); e0.has(o1.o1);true &= 7;print(this.__defineGetter__(\"hvvbcb_0[0]\", String.prototype.toLocaleUpperCase));h1.set = f2;this.f0.__proto__ = i2;Object.prototype.watch.call(t1, \"x\", arguments.callee);v2 = Infinity;(hvvbcb_1[0] !== this.hvvbcb_0[1]);}");
/*fuzzSeed-244067732*/count=4; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.imul(Math.fround(mathy1(Math.atan2((( ~ x) >>> 0), (x >>> 0)), ( + (( ! ( + Math.sinh(( + x)))) | 0)))), ((mathy0(Math.cos(x), (y && ( + mathy0((0 | 0), ( + Math.cbrt(Math.sin(0x080000001))))))) + ( + Math.clz32(( + ( + ((((Math.fround(-0x0ffffffff) != y) >> y) >>> 0) < ((((( + Math.fround(y)) >>> 0) | 0) | Math.fround(y)) | 0))))))) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=5; tryItOut("\"use strict\"; ;");
/*fuzzSeed-244067732*/count=6; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=7; tryItOut("\"use asm\"; for (var v of e1) { o1.g2.m1.has(this.f2); }");
/*fuzzSeed-244067732*/count=8; tryItOut("m0.has(o0.b1);");
/*fuzzSeed-244067732*/count=9; tryItOut("\"use strict\"; m0.get(f2);\ne1.has(v0);\n");
/*fuzzSeed-244067732*/count=10; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?!(?=\\\\3)){2}|(?!.)+?((\\\\B).$+?){1,})\", \"gyi\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-244067732*/count=11; tryItOut("\"use strict\"; testMathyFunction(mathy5, [(new Boolean(true)), null, 0.1, [], (new Boolean(false)), (function(){return 0;}), '/0/', /0/, (new Number(-0)), '\\0', '', undefined, ({valueOf:function(){return '0';}}), 0, -0, NaN, false, '0', objectEmulatingUndefined(), true, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 1, (new Number(0)), (new String('')), [0]]); ");
/*fuzzSeed-244067732*/count=12; tryItOut("mathy3 = (function(x, y) { return (Math.ceil(((Math.min(((Math.log1p((y >>> 0)) >>> 0) || Math.min((( ~ (( + Math.min(( + Math.fround((x ? x : ( + y)))), y)) | 0)) | 0), Math.fround(Math.log2((0x100000001 >>> 0))))), (( ~ y) | 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [2**53, 0x100000001, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), Math.PI, -(2**53+2), -0x080000001, -1/0, -0x07fffffff, 0x07fffffff, 1/0, -0, 0x080000001, 1.7976931348623157e308, 0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1, 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 42, -(2**53), -0x100000000]); ");
/*fuzzSeed-244067732*/count=13; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.asin(((((x ? Math.max((mathy2(x, y) | 0), y) : Math.max(Math.abs(x), mathy1(Number.MAX_VALUE, Math.cbrt((Math.imul((y | 0), (x | 0)) | 0))))) | 0) ? (( + ( + ( + mathy2((Math.fround((Math.fround(x) <= Number.MIN_VALUE)) | 0), (Math.cos(x) | 0))))) | 0) : (Math.pow(( + ( + Math.fround(( + y)))), mathy0(( ~ (Math.clz32(Math.fround(Math.imul(( + x), x))) | 0)), (( ! Number.MIN_SAFE_INTEGER) | 0))) >>> 0)) | 0)); }); testMathyFunction(mathy4, [-(2**53), -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -(2**53+2), -(2**53-2), -Number.MIN_VALUE, 2**53, -1/0, 1, -0x100000001, 2**53+2, -0x080000000, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000001, 0.000000000000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, 0x080000000, 2**53-2, -0x0ffffffff, 0/0, Number.MIN_VALUE, 0, 0x0ffffffff, 42, 0x100000001, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=14; tryItOut("return;");
/*fuzzSeed-244067732*/count=15; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.hypot(mathy0(Math.pow(x, 0/0), ((( - Math.min(((Math.fround(x) ? (x | 0) : Math.fround(x)) | 0), -(2**53))) | x) | 0)), Math.trunc(Math.hypot(Math.fround((x << Math.fround(( ! (x >>> 0))))), Math.sqrt(y)))) | 0) == ((Math.tan(Math.atan2(( + ( ! 1)), Math.imul(( + (y > y)), Number.parseFloat))) | 0) , mathy2(( ! mathy3(x, x)), Math.atan2(x, Math.ceil((x >>> 0)))))); }); testMathyFunction(mathy4, [-0, 0.000000000000001, 0x07fffffff, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x100000000, -(2**53), 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, -0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, 1, 42, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), Math.PI, -1/0, 0x100000001, 2**53, 0x100000000, Number.MIN_VALUE, -0x07fffffff, -0x080000000, 1/0]); ");
/*fuzzSeed-244067732*/count=16; tryItOut("p0.valueOf = f1;");
/*fuzzSeed-244067732*/count=17; tryItOut("/*RXUB*/var r = /[\\v-\\uC2a6\\d]+/y; var s = (void (Math.exp(27))); print(s.search(r)); ");
/*fuzzSeed-244067732*/count=18; tryItOut("f1.__proto__ = o0;");
/*fuzzSeed-244067732*/count=19; tryItOut("/*iii*/Object.defineProperty(this, \"v1\", { configurable: \"\\uB804\", enumerable: (twcnkz % 10 != 0),  get: function() {  return g0.runOffThreadScript(); } });/*hhh*/function twcnkz(y){( /x/g );}");
/*fuzzSeed-244067732*/count=20; tryItOut("o0.e0 = m1.get(g0);");
/*fuzzSeed-244067732*/count=21; tryItOut("var hisvzb = new ArrayBuffer(4); var hisvzb_0 = new Uint32Array(hisvzb); hisvzb_0[0] = -26; var hisvzb_1 = new Uint32Array(hisvzb); hisvzb_1[0] = -14; var hisvzb_2 = new Float64Array(hisvzb); print(hisvzb_2[0]); hisvzb_2[0] = -8; var hisvzb_3 = new Uint32Array(hisvzb); hisvzb_3[0] = 23; var hisvzb_4 = new Uint8Array(hisvzb); print(hisvzb_4[0]); hisvzb_4[0] = 18; e = hisvzb_0[6];g0 + '';v2 = Object.prototype.isPrototypeOf.call(e0, e2);\no2.v1.__iterator__ = (function() { try { s0 + b0; } catch(e0) { } try { for (var p in s1) { try { m1.delete(a0); } catch(e0) { } try { print(m0); } catch(e1) { } e0.__iterator__ = (function(j) { if (j) { try { print(uneval(h0)); } catch(e0) { } try { f1 = (function(j) { if (j) { v2 = (p2 instanceof a0); } else { try { s1 = Array.prototype.join.apply(this.o2.o1.a1, [s1, false]); } catch(e0) { } this.t0.set(t2, 19); } }); } catch(e1) { } try { this.s1 = ''; } catch(e2) { } /*MXX3*/g0.URIError = g2.URIError; } else { /*ADP-2*/Object.defineProperty(a0, /[^]|(?!^|[\\ud3Bb\\w-\ue6f6](?!\\b)$)|[^]*?(?=\\D|\\1|\\2)($)?(?![\\0]{1})?|(?!(?=[]))*?/gim, { configurable: this, enumerable:  \"\" , get: (function mcc_() { var rtxlap = 0; return function() { ++rtxlap; f1(/*ICCD*/rtxlap % 2 == 0);};})(), set: f1 }); } }); } } catch(e1) { } /*ADP-1*/Object.defineProperty(a0, 5, ({})); return t1; });\nthis.m0.has(o2.o0);print(hisvzb_2[0]);print(hisvzb_1[0]);");
/*fuzzSeed-244067732*/count=22; tryItOut("for (var p in g2) { try { v2 = true; } catch(e0) { } try { let t2 = new Uint16Array(a2); } catch(e1) { } try { o0.toSource = neuter; } catch(e2) { } a2.forEach(b2, e0, this.g2.g1); }print(x);");
/*fuzzSeed-244067732*/count=23; tryItOut("\"use strict\"; /*infloop*/M: for (this.zzz.zzz of true) Array.prototype.push.call(a0, m0, this.s0, m2);");
/*fuzzSeed-244067732*/count=24; tryItOut("g1.a1.forEach((function mcc_() { var wcxqlo = 0; return function() { ++wcxqlo; if (/*ICCD*/wcxqlo % 6 == 4) { dumpln('hit!'); try { selectforgc(o1); } catch(e0) { } i0 + f1; } else { dumpln('miss!'); try { a2[19] = this.h2; } catch(e0) { } try { Array.prototype.unshift.apply(a0, [f0]); } catch(e1) { } try { print(g0); } catch(e2) { } i2 = new Iterator(m2, true); } };})());");
/*fuzzSeed-244067732*/count=25; tryItOut(";");
/*fuzzSeed-244067732*/count=26; tryItOut("v1 = (v1 instanceof g0);");
/*fuzzSeed-244067732*/count=27; tryItOut("\"use strict\"; /*oLoop*/for (let fjcvqx = 0; fjcvqx < 46; ++fjcvqx) { this.v1 = evalcx(\"function f0(s2)  { yield  ''  } \", g2); } ");
/*fuzzSeed-244067732*/count=28; tryItOut("Object.defineProperty(this, \"f2\", { configurable: (x % 4 == 3), enumerable: (x % 2 != 0),  get: function() {  return Proxy.createFunction(h2, f0, f0); } });");
/*fuzzSeed-244067732*/count=29; tryItOut("e0.add(t0);");
/*fuzzSeed-244067732*/count=30; tryItOut("\"use strict\"; g2.v0 = a0.reduce, reduceRight((function(j) { f2(j); }));");
/*fuzzSeed-244067732*/count=31; tryItOut("\"use strict\"; var this.t1 = new Uint16Array(a1);");
/*fuzzSeed-244067732*/count=32; tryItOut("(function(x, y) { return x; })\nprint(window);\n\u000d");
/*fuzzSeed-244067732*/count=33; tryItOut("\"use strict\"; /*oLoop*/for (mpiebd = 0; mpiebd < 93; ++mpiebd) { function f1(this.o0)  { yield x }  } ");
/*fuzzSeed-244067732*/count=34; tryItOut("v0 = Object.prototype.isPrototypeOf.call(g2, v0);");
/*fuzzSeed-244067732*/count=35; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = /(?=(?!((\u33cb|$){2,}.(?=(.))*)))/gyi; var s = \"\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-244067732*/count=36; tryItOut("a1.splice();");
/*fuzzSeed-244067732*/count=37; tryItOut("/*RXUB*/var r = r0; var s = g1.o0.s2; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=38; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( ~ Math.fround(Math.log1p((Math.min((0x080000000 | 0), (((mathy1((y ^ 1), (( + Number.MIN_VALUE) >> x)) >>> 0) , (-(2**53-2) >>> 0)) >>> 0)) | 0))))); }); testMathyFunction(mathy2, [-0x07fffffff, 0.000000000000001, Number.MIN_VALUE, 2**53+2, 42, -Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -1/0, -0x100000001, 0, -0x080000001, Number.MAX_SAFE_INTEGER, 0/0, 1/0, 1, -(2**53+2), -0, -(2**53), -0x0ffffffff, 0x07fffffff, -0x080000000, Number.MAX_VALUE, 0x100000000, 2**53-2, 2**53, -Number.MIN_VALUE, 0x100000001, 0x080000001, 0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=39; tryItOut("/*RXUB*/var r = /(?:((?:.{0,549755813887}+?(?!(\\w)))+?)*)/gym; var s = \"000000000000000\"; print(r.exec(s)); ");
/*fuzzSeed-244067732*/count=40; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=41; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( - (( + Math.min(( + Math.max((Math.hypot(Math.atan2(Math.PI, -0x080000000), (1.7976931348623157e308 ? Math.pow(-Number.MIN_SAFE_INTEGER, x) : ( + Math.acosh(( + x))))) | 0), Math.fround((((((y >>> 0) ? (x | 0) : Math.fround(Math.acos(x))) >>> 0) >>> 0) == Math.fround(( + y)))))), (Math.sin(( + Math.pow(( + (0x0ffffffff % (-0x080000001 === ((y & (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))), (Math.min(y, ((( + x) ? x : ( + 1.7976931348623157e308)) >>> 0)) * (y >>> 0))))) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-244067732*/count=42; tryItOut("let(b) { let(b) { with({}) { x = b; } }}");
/*fuzzSeed-244067732*/count=43; tryItOut("\"use strict\"; o2.e0.add(e1);");
/*fuzzSeed-244067732*/count=44; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3+|(^)|\\\\u0032|[^].{511,}|.|\\\\u00e6(?![^]{0,3})+?|(?!(?!\\\\b*\\\\w))+?\", \"ym\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-244067732*/count=45; tryItOut("this.a0.shift();");
/*fuzzSeed-244067732*/count=46; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.imul((Math.pow((Math.fround(((y - 2**53+2) >>> 0)) >>> 0), (Math.log2(y) | 0)) ? ( - (((Math.atan2((x >>> x), 0) | 0) % ((( ~ Math.pow(x, x)) >>> 0) | 0)) | 0)) : Math.hypot(y, Math.fround(Math.atan2(Math.imul(( + -0x07fffffff), ( + x)), Math.fround(y))))), Math.cos(Math.fround(( - Math.fround(x)))))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, 0x0ffffffff, -(2**53-2), Math.PI, 42, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -1/0, 1, Number.MAX_VALUE, -0, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, -(2**53+2), 1/0, -0x100000001, -0x0ffffffff, -0x100000000, -(2**53), 0x080000001]); ");
/*fuzzSeed-244067732*/count=47; tryItOut("m0.get(o1);");
/*fuzzSeed-244067732*/count=48; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.sinh((Math.pow(x, ( + ( ~ y))) ? ( + (Math.max(-(2**53+2), 0x0ffffffff) != y)) : (Math.pow((x >>> 0), (-1/0 >>> 0)) >>> 0))), (Math.fround(Math.acosh(Math.asin(Math.fround(mathy1(Math.atan2(y, (x - x)), x))))) === mathy0(Math.sinh(Math.fround(y)), ( + Math.max(y, 0x07fffffff))))); }); ");
/*fuzzSeed-244067732*/count=49; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.min((((((Math.log2((( ~ ((Math.atan2((y | 0), (y | 0)) | 0) || Number.MIN_SAFE_INTEGER)) | 0)) | 0) >>> 0) >= Math.fround((Math.imul((( + ( ! ( + ( + Math.max(( + x), ( + Math.max(( + y), x))))))) >>> 0), (Math.atan2(( + x), (x | 0)) >>> 0)) >>> 0))) >>> 0) >> ( + Math.log((mathy2((Math.fround(Math.round(Math.fround(-Number.MIN_VALUE))) >>> 0), Math.abs(mathy0(( + x), (x >>> 0)))) | 0)))), (( + Math.atan2((Math.max((x ? (( + (x | 0)) >>> 0) : y), Math.fround(Number.MAX_VALUE)) | 0), (Math.atan2((Math.fround((-Number.MIN_VALUE ? ( + x) : 0x100000000)) >>> 0), (x >>> 0)) | 0))) ? ( + y) : ( - -Number.MIN_VALUE))); }); testMathyFunction(mathy4, [-0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 2**53-2, Math.PI, -0x0ffffffff, -0x07fffffff, 0x100000000, 42, 0x07fffffff, 0x080000001, -1/0, 0x100000001, -(2**53+2), 0x0ffffffff, 1/0, -(2**53), 1.7976931348623157e308, 0x080000000, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), -0, -Number.MAX_VALUE, -0x080000000, -0x100000000]); ");
/*fuzzSeed-244067732*/count=50; tryItOut("\"use strict\"; t2[12];");
/*fuzzSeed-244067732*/count=51; tryItOut("\"use strict\"; /*vLoop*/for (var wdybvr = 0; wdybvr < 28; ( /x/ .throw(true)), new (function(x, y) { \"use strict\"; return -0x080000000; })(/\\2|\\S??/ym), ++wdybvr) { const w = wdybvr; for(var y in 6) {this.v0 = a0.some((function() { m2.delete(t0); return f2; })); } } ");
/*fuzzSeed-244067732*/count=52; tryItOut("\"use strict\"; /*bLoop*/for (let ofjzmx = 0; ofjzmx < 90; ++ofjzmx) { if (ofjzmx % 20 == 0) { s0.toString = (function mcc_() { var udtxyk = 0; return function() { ++udtxyk; if (/*ICCD*/udtxyk % 10 == 6) { dumpln('hit!'); m2.get(t1); } else { dumpln('miss!'); a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } };})(); } else { print((\u3056 === x)); }  } ");
/*fuzzSeed-244067732*/count=53; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=54; tryItOut("mathy3 = (function(x, y) { return (Math.clz32((Math.max(Math.fround(Math.hypot(Math.fround(Math.min((Math.log10((( ~ y) | 0)) | 0), Math.fround(-0x07fffffff))), (Math.expm1((y ? -(2**53+2) : ( - y))) | 0))), Math.fround((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: window, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: Object.prototype.hasOwnProperty, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; }))) | 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 2**53, -0x080000000, 0x080000001, 0x100000001, Math.PI, -0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, 2**53+2, 0x07fffffff, 1/0, 0, 42, -(2**53+2), 0x080000000, 0/0, -0, Number.MAX_VALUE, -(2**53-2), -0x100000001, -(2**53), 1]); ");
/*fuzzSeed-244067732*/count=55; tryItOut("testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -0x080000001, -1/0, 0x0ffffffff, -0x100000000, -0x080000000, Number.MIN_VALUE, 1/0, 42, 0/0, 1, Number.MAX_SAFE_INTEGER, 0, 2**53+2, -(2**53-2), -0x07fffffff, -Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -(2**53), Math.PI, -0, 2**53, 0x080000000, -(2**53+2), 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=56; tryItOut("((function ([y]) { })());");
/*fuzzSeed-244067732*/count=57; tryItOut("yield length;(x);");
/*fuzzSeed-244067732*/count=58; tryItOut("/*RXUB*/var r = [{}, ] = --x; var s = \"\\n\\u00a2\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=59; tryItOut("if(new RegExp(\"(\\\\u008f.{2})(?:[^]\\\\d|\\\\D|.)*?|[\\\\cR-\\\\\\u00dc\\\\r-\\\\x25\\\\v-\\udff6\\\\D]*?*\", \"y\")) {([1,,]); }");
/*fuzzSeed-244067732*/count=60; tryItOut("\"use asm\"; m1.set((new (/*wrap1*/(function(){ \"use strict\"; t1[9];return (encodeURIComponent).bind()})())((p={}, (p.z = (void version(185)))()), x)), e1);");
/*fuzzSeed-244067732*/count=61; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\\\d(?:\\\\u5b88)|(?:(?!\\u00cd)\\\\s|\\\\b|(.){3}){2,3}?)\", \"gi\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=62; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy2(Math.max((Math.expm1(y) >>> 0), (Math.asin(x) >>> 0)), (Math.log2(y) ? Math.fround(( - Math.acosh((mathy2(x, x) | 0)))) : ( + Math.trunc(( + Math.fround(( + ((Math.cbrt(((y ? ( + Math.max(Math.fround(y), Math.fround(x))) : ( + x)) >>> 0)) >>> 0) | 0)))))))); }); testMathyFunction(mathy4, /*MARR*/[new Number(1), [], new Number(1), objectEmulatingUndefined(), [], [], [], objectEmulatingUndefined(), [], objectEmulatingUndefined(), new Number(1), [], [], [], new Number(1), [], new Number(1), new Number(1), [], new Number(1), [], objectEmulatingUndefined(), [], objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), [], objectEmulatingUndefined(), new Number(1), [], [], new Number(1)]); ");
/*fuzzSeed-244067732*/count=63; tryItOut("m1.get(f0);function NaN(w) { \"use strict\"; return /*UUV1*/(x.toLocaleTimeString = (new Function).apply) } {print(function(id) { return id }); }");
/*fuzzSeed-244067732*/count=64; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return (((Math.hypot(((Math.cos(x) !== y) | 0), (Math.min(( + Math.log2(x)), (( + 42) | 0)) | 0)) | 0) ^ (( + ( - Math.min((y >>> 0), (Number.MAX_VALUE >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy1, [2**53+2, -0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, -(2**53+2), 0/0, -Number.MIN_VALUE, -(2**53), 1, 2**53-2, 1.7976931348623157e308, 1/0, Math.PI, 0, -Number.MAX_VALUE, 0.000000000000001, 0x080000000, 0x07fffffff, -0x080000001, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -(2**53-2), 0x080000001, 2**53, -0x100000000, 42, Number.MIN_VALUE, 0x100000000, -0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=65; tryItOut("Array.prototype.push.call(this.g2.g1.a2, h2, o1.s0, v1, o1);");
/*fuzzSeed-244067732*/count=66; tryItOut("this.o2.v2 = g1.runOffThreadScript();");
/*fuzzSeed-244067732*/count=67; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=68; tryItOut("testMathyFunction(mathy3, [42, -0x100000000, -0x080000000, 0, -Number.MAX_VALUE, -(2**53-2), -0, -(2**53+2), -0x080000001, -(2**53), -0x100000001, Number.MAX_VALUE, 0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 2**53, 1/0, -1/0, 1.7976931348623157e308, -0x07fffffff, 1, 0.000000000000001, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 2**53+2, -Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -0x0ffffffff, Math.PI]); ");
/*fuzzSeed-244067732*/count=69; tryItOut("\"use strict\"; /*vLoop*/for (var zooyfj = 0; zooyfj < 30; ++zooyfj) { var e = zooyfj; print(x); } ");
/*fuzzSeed-244067732*/count=70; tryItOut(" for  each(let x in (4277)) { if (!isAsmJSCompilationAvailable()) { void 0; setIonCheckGraphCoherency(false); } void 0; }");
/*fuzzSeed-244067732*/count=71; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( ~ (( + (Math.hypot((x | 0), (1.7976931348623157e308 | 0)) | 0)) < ( + (Math.min(y, ((Math.min((y >>> 0), (Math.atan(( ~ 0x080000000)) >>> 0)) >>> 0) >>> 0)) % ((y >>> 0) >= Math.hypot(( ~ mathy0(y, y)), (Math.fround(Math.asinh(Math.fround(x))) | 0))))))) >>> 0); }); testMathyFunction(mathy2, [0x080000000, -(2**53-2), 1.7976931348623157e308, 0x100000001, Math.PI, 2**53, 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, 42, 1, 0x0ffffffff, -0, Number.MIN_VALUE, -(2**53+2), 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, 2**53+2, -0x080000001, -(2**53), 0.000000000000001, -Number.MIN_VALUE, -0x100000000, -1/0, 0x100000000, 0x080000001, -0x07fffffff, 2**53-2, -0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=72; tryItOut("\"use strict\"; a1 = new Array;");
/*fuzzSeed-244067732*/count=73; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.asinh(Math.imul((Math.min((y | 0), Math.exp(( + y))) | 0), (( ~ Math.expm1(Math.fround(( ~ ( + Math.min(y, y)))))) | 0))); }); testMathyFunction(mathy1, [-0x080000000, 0x100000001, 2**53-2, -(2**53-2), Math.PI, 2**53, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 0x080000000, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 42, 1/0, -1/0, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0.000000000000001, -(2**53+2), 2**53+2, -0x0ffffffff, 1, 0, -(2**53), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, 0x080000001]); ");
/*fuzzSeed-244067732*/count=74; tryItOut("i1.next();");
/*fuzzSeed-244067732*/count=75; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"(\\nx) ? (new (/*MARR*/[{}, null, {}, {}, (void 0), {}, {}, null, {}, -Infinity, {}, -Infinity, {}, {}, {}, {}, {}, -Infinity, -Infinity, (void 0), {}, (void 0), (void 0), (void 0), null, (void 0), {}, -Infinity, -Infinity, null, null, -Infinity, {}, {}, -Infinity, {}, (void 0), {}, (void 0), {}, -Infinity].some)(eval(\\\"/* no regression tests found */\\\"), new x())) : intern(window).__defineSetter__(\\\"x\\\", RegExp.prototype.test).valueOf(\\\"number\\\")\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 99 != 78), noScriptRval: (x % 55 == 40), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-244067732*/count=76; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(Math.fround(Math.atan2(( + ((Math.atan(x) , y) ^ ( + ( + Math.atan2(( + (Math.imul((Math.pow(1, x) | 0), (x | 0)) | 0)), ( ! (x >>> 0))))))), Math.imul(mathy1(( ! 42), -0x0ffffffff), ( + ( + x))))), Math.fround((Math.fround((Math.hypot((0.000000000000001 >>> 0), ( + Math.sqrt(0x080000001))) >>> 0)) & Math.fround(Math.exp(( + Math.acos(( + x)))))))) | 0); }); testMathyFunction(mathy2, /*MARR*/[objectEmulatingUndefined(), Number.MAX_SAFE_INTEGER, null, {x:3}, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, null, objectEmulatingUndefined(), {x:3}, null, null, null, objectEmulatingUndefined(), Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), null, {x:3}, objectEmulatingUndefined(), {x:3}, null, null, {x:3}, {x:3}, {x:3}, {x:3}, objectEmulatingUndefined(), {x:3}, null, Number.MAX_SAFE_INTEGER, {x:3}, {x:3}, Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), objectEmulatingUndefined(), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=77; tryItOut("e0.add(o1);");
/*fuzzSeed-244067732*/count=78; tryItOut("\"use strict\"; print( /x/g );");
/*fuzzSeed-244067732*/count=79; tryItOut("mathy1 = (function(x, y) { return ( + (( + ( + Math.sign(mathy0(y, ( ! (Math.acosh((y >>> 0)) >>> 0)))))) ? Math.fround((Math.fround(((x >= Math.min(y, y)) >>> 0)) !== Math.fround(Math.imul(mathy0(y, ( + (x | 0))), (y ^ x))))) : ( + (((Math.atan2(Math.fround(mathy0(( + x), Math.fround(-Number.MIN_VALUE))), Math.pow(Math.imul(( + x), y), y)) ? Math.cosh(y) : Math.cos((Math.min(( + Math.pow(( + y), ( + x))), -Number.MAX_SAFE_INTEGER) ? (Math.expm1(( + x)) >>> 0) : ( + y)))) - ((((( ! ((y | 0) <= (y | 0))) | 0) < ((y | 0) ^ x)) , (1.7976931348623157e308 + Math.fround((((0x080000001 | 0) , (y | 0)) | 0)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [2**53-2, 1/0, -(2**53-2), -0x080000000, -0x100000000, -Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 1, 1.7976931348623157e308, 0/0, Math.PI, Number.MAX_VALUE, 0x07fffffff, 2**53, Number.MIN_VALUE, -0x100000001, 0x080000001, -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, -1/0, 0x0ffffffff, 0, -0x080000001, -Number.MAX_VALUE, 0x100000000, -(2**53+2), -0x07fffffff, -(2**53), 0x100000001]); ");
/*fuzzSeed-244067732*/count=80; tryItOut("\"use strict\"; o2.v0 = r0.global;");
/*fuzzSeed-244067732*/count=81; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-244067732*/count=82; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((( ! (let (c)  /x/ )) | 0) * (( ~ ( + x)) | 0)) | 0); }); testMathyFunction(mathy3, [0x080000000, -0x080000000, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -(2**53-2), 0x07fffffff, -0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, Math.PI, 0/0, -0x0ffffffff, -0, -1/0, 42, 2**53+2, Number.MAX_VALUE, -0x100000001, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 1/0, 0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-244067732*/count=83; tryItOut("");
/*fuzzSeed-244067732*/count=84; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ (( + (( + y) !== ((mathy1(((x && y) | 0), (y | 0)) | 0) == ( + Math.pow((Math.fround((Math.fround(x) >> Math.fround(0x080000001))) || y), ( + y)))))) === mathy1(mathy0(y, Math.max(x, ( + y))), ( + Math.atanh(( + (mathy2((x && x), y) == x))))))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, -0x080000001, 1, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, 0, 2**53-2, 42, 2**53, -(2**53-2), 1/0, 2**53+2, -0x0ffffffff, Math.PI, 0x0ffffffff, -0x07fffffff, -1/0, -0x100000001, -(2**53), Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, 0x100000000, -0, -0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001]); ");
/*fuzzSeed-244067732*/count=85; tryItOut("e1.has(i1);");
/*fuzzSeed-244067732*/count=86; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.min((((Math.fround((Math.clz32(Number.MIN_SAFE_INTEGER) | 0)) < ( ! Math.fround(Math.acosh(y)))) | 0) | (Math.fround((Math.fround(( + x)) / Math.fround(y))) | 0)), (( ~ ( ~ ((Math.fround((Math.fround(Math.fround(Math.max(( + y), ( + ( - y))))) >>> Math.fround(-0x07fffffff))) >>> (Math.pow(x, Math.max(-0x080000000, ( + -0))) + x)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-1/0, -0x080000001, Number.MIN_VALUE, -(2**53), 1, 0x100000000, 42, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, -(2**53-2), Math.PI, 0x080000001, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, -(2**53+2), 0/0, -0x100000000, -0x0ffffffff, -0x080000000, 2**53+2, 0, -Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 1/0]); ");
/*fuzzSeed-244067732*/count=87; tryItOut("/*oLoop*/for (let ekoxxh = 0; ekoxxh < 50; ++ekoxxh) { for (var v of i0) { try { this.m0.get(f0); } catch(e0) { } try { e1 + ''; } catch(e1) { } t1.set(t1, v1); } } ");
/*fuzzSeed-244067732*/count=88; tryItOut("s2 = new String(v0);");
/*fuzzSeed-244067732*/count=89; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.cbrt(((( + (( + (Math.max(( + mathy0((y >>> 0), ( + y))), ((Math.fround(((y >>> 0) + Math.fround(Math.round(Math.fround(y))))) < ( + 0x100000000)) | 0)) >>> 0)) ? ( + ((( ! (x | 0)) | 0) & x)) : (mathy1(-(2**53), ((x < y) >>> 0)) >>> 0))) << mathy3(((( + ( ~ Math.fround((mathy4((Math.atan2(y, y) >>> 0), (y >>> 0)) >>> 0)))) , (((y >>> 0) % (x >>> 0)) >>> 0)) | 0), Math.atanh(Math.fround(mathy3((x ^ mathy0(1/0, y)), Math.acos(0x0ffffffff)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, /*MARR*/[[],  'A' , 0x20000000, [], [undefined], [undefined], {x:3},  'A' , [], [undefined], [], [], [],  'A' , {x:3}, [], [undefined],  'A' , [], {x:3},  'A' , {x:3}, [], [undefined]]); ");
/*fuzzSeed-244067732*/count=90; tryItOut("v2 = (this.a1 instanceof o0.m2);function c() { return Function.prototype } s0 += 'x';");
/*fuzzSeed-244067732*/count=91; tryItOut("(-0);const d = (4277);");
/*fuzzSeed-244067732*/count=92; tryItOut("do {continue M; } while((((void options('strict_mode')))) && 0);function window(y, x, ...x) { \"use strict\"; yield x } let NaN = (((this.zzz.zzz = /*FARR*/[].map(Int8Array))) instanceof (let (b) (\u0009new (encodeURIComponent).apply()) % allocationMarker() !== eval(\"(new RegExp(\\\"([^])?|[^]*\\\\\\\\1([\\\\\\\\w\\\\\\\\W]*?)(\\\\\\\\b)|$*|((?:\\\\\\\\x76+?)){0,}\\\", \\\"y\\\"));\"))), x = z, eval, tllrkl, zzizng, x = new \"\\uBA9A\"((4277), -6);;");
/*fuzzSeed-244067732*/count=93; tryItOut("/*infloop*/ for  each(let d in -26) e1.has(t1);");
/*fuzzSeed-244067732*/count=94; tryItOut("\"use strict\"; e0.add(b0);");
/*fuzzSeed-244067732*/count=95; tryItOut("var geyvjf = new ArrayBuffer(16); var geyvjf_0 = new Int8Array(geyvjf); geyvjf_0[0] = 22; var geyvjf_1 = new Uint32Array(geyvjf); var geyvjf_2 = new Uint8ClampedArray(geyvjf); print(geyvjf_2[0]); geyvjf_2[0] = -10; var geyvjf_3 = new Uint16Array(geyvjf); var geyvjf_4 = new Int16Array(geyvjf); geyvjf_4[0] = 15; var geyvjf_5 = new Int16Array(geyvjf); geyvjf_5[0] = 17; var geyvjf_6 = new Float64Array(geyvjf); var geyvjf_7 = new Uint8Array(geyvjf); print(geyvjf_7[0]); var geyvjf_8 = new Uint8Array(geyvjf); print(geyvjf_8[0]); geyvjf_8[0] = 13; print(geyvjf_2[5]);print(geyvjf_3[0]);/*tLoop*/for (let d of /*MARR*/[\"\\uF26A\", \"\\uF26A\", \"\\uF26A\", (-1/0), (-1/0), \"\\uF26A\", \"\\uF26A\", (-1/0), (-1/0), \"\\uF26A\", (-1/0), (-1/0), \"\\uF26A\", (-1/0), \"\\uF26A\", (-1/0), (-1/0), \"\\uF26A\", (-1/0), \"\\uF26A\", (-1/0), \"\\uF26A\", (-1/0), \"\\uF26A\", (-1/0), (-1/0), \"\\uF26A\", (-1/0), \"\\uF26A\", (-1/0), \"\\uF26A\", (-1/0), (-1/0)]) { s2 = this.s2.charAt(\"\u03a0\"); }/* no regression tests found */t2[9] = s2;v2 = g2.eval(\"this.e0.add(o1);\");(new RegExp(\"(?=(.))\", \"m\").bind( , false));m2.set(v1, this.a2);");
/*fuzzSeed-244067732*/count=96; tryItOut("Object.freeze(p2);");
/*fuzzSeed-244067732*/count=97; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ~ ((Math.hypot((( ~ (Math.asinh((x >>> 0)) >>> 0)) ** 0x100000000), ( + ( + (1/0 < (y | 0))))) == (Math.fround(Math.abs(mathy0(y, Math.min(( + mathy1(Math.fround(Math.tan((y | 0))), ( + (( ! (-(2**53) >>> 0)) >>> 0)))), (-0x100000000 > (( + x) >>> 0)))))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[[], null, null, new Boolean(false), [], null, 1.3, [], new Boolean(false), \u3056 = NaN, null, 1.3, [], new Boolean(false), null, 1.3, new Boolean(false), new Boolean(false), null, [], 1.3, \u3056 = NaN, [], \u3056 = NaN, new Boolean(false), 1.3, [], \u3056 = NaN, new Boolean(false), [], new Boolean(false), [], new Boolean(false), \u3056 = NaN, new Boolean(false), [], null, [], 1.3, 1.3, \u3056 = NaN, 1.3, \u3056 = NaN, [], 1.3, new Boolean(false), 1.3, [], [], \u3056 = NaN, null, null, null, new Boolean(false), 1.3, [], 1.3, null, \u3056 = NaN, [], \u3056 = NaN, 1.3, new Boolean(false), null, null, [], new Boolean(false), \u3056 = NaN, [], 1.3, new Boolean(false), null, new Boolean(false), new Boolean(false), \u3056 = NaN, null, new Boolean(false), null, [], \u3056 = NaN, \u3056 = NaN, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, null, [], [], null, null, \u3056 = NaN, [], [], null, new Boolean(false), [], 1.3, new Boolean(false), [], [], 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, [], \u3056 = NaN, new Boolean(false), \u3056 = NaN, 1.3, new Boolean(false), null, 1.3, null, [], 1.3, null, [], null, null, [], null, [], null]); ");
/*fuzzSeed-244067732*/count=98; tryItOut("mathy2 = (function(x, y) { return Math.fround(( + Math.fround(( ! ( ~ ( + Math.atan2(x, (Math.ceil(y) >>> 0)))))))); }); testMathyFunction(mathy2, /*MARR*/[ \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/ ,  \"use strict\" ,  /x/ ,  /x/ ,  \"use strict\" ,  /x/ ]); ");
/*fuzzSeed-244067732*/count=99; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - ((( ! (( - x) | 0)) | 0) < mathy0(y, ( + ( + ( - y)))))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), (new Number(-0)), 0.1, (new String('')), '', (new Boolean(false)), true, (function(){return 0;}), -0, null, (new Number(0)), objectEmulatingUndefined(), [0], (new Boolean(true)), ({toString:function(){return '0';}}), '0', NaN, [], 0, '\\0', '/0/', ({valueOf:function(){return 0;}}), false, undefined, /0/, 1]); ");
/*fuzzSeed-244067732*/count=100; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((Math.abs(Math.expm1((((Math.hypot(y, (( ! Math.acos(-0x080000001)) | 0)) >>> 0) ? (Math.min((Math.imul((y | 0), x) | 0), (Math.fround(Math.cbrt(Math.fround(Number.MIN_SAFE_INTEGER))) >>> 0)) >>> 0) : (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0))) | 0) !== (Math.abs((( ~ (( + Math.max(Number.MAX_VALUE, y)) * ( + ( + ( ! x))))) | 0)) | 0)); }); ");
/*fuzzSeed-244067732*/count=101; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -2305843009213694000.0;\n    var d4 = 281474976710657.0;\n    d0 = (d3);\n    return +((-1023.0));\n  }\n  return f; })(this, {ff: Array.prototype.some}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 0x100000001, 1/0, 42, -0x100000000, Math.PI, 0.000000000000001, 1.7976931348623157e308, -0x080000000, -1/0, 2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, -Number.MAX_VALUE, -(2**53), -0x0ffffffff, -(2**53+2), 0x07fffffff, -0x07fffffff, -0x080000001, 0x0ffffffff, -(2**53-2), 2**53, -Number.MIN_VALUE, -0x100000001, 0x080000000, -0]); ");
/*fuzzSeed-244067732*/count=102; tryItOut("testMathyFunction(mathy3, [1.7976931348623157e308, -0x080000000, 0x07fffffff, 1, 1/0, -0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, -(2**53), 0x100000001, 2**53+2, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -1/0, -(2**53+2), 0.000000000000001, 42, -0x080000001, 0x100000000, -0x100000001, Number.MIN_VALUE, 0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, 0, Math.PI, -0x100000000, 2**53-2, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0]); ");
/*fuzzSeed-244067732*/count=103; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((Math.fround(mathy0(-1/0, Math.fround(( ! Math.fround(y))))) | 0) & ( + ( ~ ( + Math.sinh(Math.cos(Math.pow(y, ( + Math.min(2**53, y))))))))); }); ");
/*fuzzSeed-244067732*/count=104; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (((( + ((( - ( + (Math.ceil(Math.fround((Math.fround(y) + Math.fround(-Number.MAX_SAFE_INTEGER)))) >>> 0))) >>> 0) ? ( + Math.max(mathy3((( + (y >>> 0)) != mathy0(y, Math.fround(x))), Math.tanh(Math.log2(x))), (( ~ (mathy1(-0x080000001, Math.fround(mathy0(( ! y), Math.fround(x)))) | 0)) | 0))) : ( + (( ! ((Math.asinh(-0) | 0) | 0)) | 0)))) >>> 0) ^ (( + ( + ( + Math.cbrt(( + (Math.asinh((x | 0)) | 0)))))) | 0)) | 0); }); testMathyFunction(mathy4, [2**53+2, Number.MAX_VALUE, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 1/0, 0x100000001, -(2**53+2), -Number.MAX_VALUE, -0x100000000, -0x07fffffff, -0x100000001, -0x080000000, 1, -0x080000001, 0x0ffffffff, -0, 0/0, 0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 42, -0x0ffffffff, 0x080000000, 2**53-2, 1.7976931348623157e308, 2**53, 0.000000000000001, 0x07fffffff, -(2**53-2), -Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=105; tryItOut("\"use strict\"; \"use asm\"; /*bLoop*/for (var pzzwqz = 0; pzzwqz < 16; ++pzzwqz) { if (pzzwqz % 3 == 0) { /*RXUB*/var r = r2; var s = \"\"; print(s.match(r));  } else { print(x); }  } ");
/*fuzzSeed-244067732*/count=106; tryItOut("o0.a2.shift();");
/*fuzzSeed-244067732*/count=107; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=((?=.)\\\\b)\\\\3|[^]{3,}|((^|[^\\\\u005e\\\\v-\\u00b2\\\\u00F1]${256}))|((?!(?!\\\\B)*?)?))|(?=\\\\1)|\\\\B\", \"m\"); var s = \"\\n\\n\\u001da 1\\n\\na\\n\\u001da 1\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-244067732*/count=108; tryItOut("for(let d in []);\n/*hhh*/function cylkyi(\u3056 = (yield (4277)), e, ...x){print((uneval(/*UUV2*/(\u3056.copyWithin = \u3056.toString))));}cylkyi(( '' (new RegExp(\"((?=\\\\s)+){4}\", \"g\"))), yield ++x);\n");
/*fuzzSeed-244067732*/count=109; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[1e81, 1e81, [], [], [], [], 1e81, 1e81, [], 1e81, 1e81, 1e81, [], 1e81, [], 1e81, [], [], 1e81, 1e81, 1e81, 1e81, [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], 1e81, [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], 1e81, 1e81, 1e81, 1e81, 1e81, [], [], 1e81, 1e81, [], [], 1e81, 1e81, [], [], [], [], [], [], [], 1e81, 1e81, 1e81]) { /*RXUB*/var r = /(?=($)(?=(?!\\w)).\\D\\BL+\\s{0,}|\\d{2}.??)\\u00A7${3,5}*(?:\\x8D\\w|\\p|\\x54+?|(?:$))+/i; var s = \"\"; print(r.test(s));  }");
/*fuzzSeed-244067732*/count=110; tryItOut("t1[10] = m0;");
/*fuzzSeed-244067732*/count=111; tryItOut("mathy5 = (function(x, y) { return mathy4(( + Math.cosh(( + (( + (((Math.atan2(x, y) <= ( + x)) | 0) >>> 0)) | 0)))), ( ! ( + ( + ( + Math.tan(Math.fround(( ~ y)))))))); }); ");
/*fuzzSeed-244067732*/count=112; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[(-1/0), Number.MAX_SAFE_INTEGER, (4277), Number.MAX_SAFE_INTEGER, -(2**53+2), x, x, -(2**53+2), Number.MAX_SAFE_INTEGER, (4277), x, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, (-1/0), (4277), x, -(2**53+2), -(2**53+2), Number.MAX_SAFE_INTEGER, (-1/0), Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53+2), Number.MAX_SAFE_INTEGER, (-1/0), x, x, (-1/0), x, -(2**53+2), x, (4277), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, x, (4277), x, (-1/0), Number.MAX_SAFE_INTEGER, (-1/0), Number.MAX_SAFE_INTEGER, x, x, x, x, -(2**53+2), Number.MAX_SAFE_INTEGER, x, -(2**53+2), (-1/0), -(2**53+2), Number.MAX_SAFE_INTEGER, (4277), Number.MAX_SAFE_INTEGER, x, (-1/0), (4277), (-1/0), (4277), -(2**53+2), -(2**53+2), x, (4277), -(2**53+2), (-1/0), (-1/0), -(2**53+2), (4277), x, (-1/0), x, (-1/0), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, (4277), (4277), Number.MAX_SAFE_INTEGER, (4277), (-1/0), (4277), (-1/0), (4277), (-1/0), (4277), -(2**53+2), Number.MAX_SAFE_INTEGER, x, (-1/0), (4277), -(2**53+2), (4277), (-1/0), x, -(2**53+2), x, (4277), (-1/0), -(2**53+2), (-1/0), Number.MAX_SAFE_INTEGER, (-1/0), (-1/0), (4277), (-1/0), Number.MAX_SAFE_INTEGER, -(2**53+2), (-1/0), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=113; tryItOut("/*vLoop*/for (var wujdxk = 0; wujdxk < 132; ++wujdxk) { const y = wujdxk; yield; } ");
/*fuzzSeed-244067732*/count=114; tryItOut("\"use strict\"; print(x);\n( /x/ );\n");
/*fuzzSeed-244067732*/count=115; tryItOut("mathy5 = (function(x, y) { return Math.atan2(((Math.fround(Math.fround((x >>> 0))) === (( + ((Math.fround(Math.min(0/0, x)) % -Number.MAX_SAFE_INTEGER) ? ((-0 ** y) | 0) : ((Math.min((( + (0x100000001 << -0x0ffffffff)) >>> 0), x) >>> 0) | 0))) >>> 0)) >>> 0), Math.fround(Math.log2(Math.log2(( + (( + Math.min(( + Math.sqrt(0/0)), ( + y))) | 0)))))); }); testMathyFunction(mathy5, [0x0ffffffff, 2**53-2, -0x0ffffffff, -0x080000000, 0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, Math.PI, 1, -0x080000001, -Number.MIN_VALUE, 0, 42, -0x100000001, 0/0, -(2**53+2), 2**53, -0x100000000, 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x100000001, 0x080000000, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, 0x080000001, -(2**53), -1/0]); ");
/*fuzzSeed-244067732*/count=116; tryItOut("mathy2 = (function(x, y) { return ( ~ Math.fround(mathy0(Math.log2(Math.fround(( ~ x))), (( ! (( - (( ! (Math.sign(y) >>> 0)) | 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-244067732*/count=117; tryItOut("let(window = undefined, cfrxiq) { \"\\uFEDF\";}for(let z in []);");
/*fuzzSeed-244067732*/count=118; tryItOut("g0.i1 = t2[6];");
/*fuzzSeed-244067732*/count=119; tryItOut("o0.e1.has(s0);");
/*fuzzSeed-244067732*/count=120; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ( + ( + (Math.round(( + Math.fround(Math.acosh((( + Math.atan(( + -0x100000001))) | 0))))) >>> 0))); }); testMathyFunction(mathy1, [0, null, (new Number(0)), false, (function(){return 0;}), ({valueOf:function(){return 0;}}), [], undefined, objectEmulatingUndefined(), '/0/', ({toString:function(){return '0';}}), true, 1, -0, [0], (new Boolean(false)), NaN, '\\0', (new Number(-0)), 0.1, (new String('')), (new Boolean(true)), ({valueOf:function(){return '0';}}), '', '0', /0/]); ");
/*fuzzSeed-244067732*/count=121; tryItOut("Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-244067732*/count=122; tryItOut("t0 = new Int32Array(b2);");
/*fuzzSeed-244067732*/count=123; tryItOut("mathy2 = (function(x, y) { return Math.hypot(Math.fround(Math.fround(Math.hypot(Math.fround(Math.cosh(( + ( - -0x07fffffff)))), ( + Math.fround(( ~ ( + ( - ((y || y) | 0))))))))), ( + (Math.fround(( + mathy1(( + ( + x)), ( + (y ^ y))))) !== (Math.min((( ~ x) >>> 0), ((y !== 2**53+2) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-1/0, -(2**53+2), Math.PI, 2**53+2, 0x100000001, 2**53, 0x07fffffff, -0, 0/0, -0x100000001, Number.MIN_VALUE, -(2**53), 1, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0x100000000, -Number.MIN_VALUE, 42, -0x080000001, -Number.MAX_SAFE_INTEGER, 0, 0x080000000, 0x080000001, -0x07fffffff, -0x080000000, 0x0ffffffff, 1/0, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=124; tryItOut("mathy0 = (function(x, y) { return Math.tanh(Math.fround(( ! Math.sinh((( ~ x) | 0))))); }); testMathyFunction(mathy0, [-0x100000000, -0x080000000, 0x07fffffff, -(2**53), -0x0ffffffff, 42, 0x100000000, Number.MIN_VALUE, -1/0, -Number.MIN_VALUE, -0, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, 0x080000001, 1, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 0x100000001, 2**53-2, 0/0, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0, -(2**53+2), 0.000000000000001, -0x100000001, -0x07fffffff, Math.PI, Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-244067732*/count=125; tryItOut("with(/*UUV1*/(c.getUTCMinutes = offThreadCompileScript) == (4277)){if((x % 2 != 0)) { if ( /x/ ) {e2.has(t1);print(window); }} else {print(x); } }");
/*fuzzSeed-244067732*/count=126; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-244067732*/count=127; tryItOut("\"use strict\"; this.g2 + this.t1;");
/*fuzzSeed-244067732*/count=128; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy4(( + ((( + Math.fround(Math.acosh(Math.fround(x)))) + ( + Math.log10((y >>> 0)))) | 0)), ( + Math.log1p(Math.max(Math.fround(mathy3(((Math.fround(x) ? Math.fround(2**53+2) : Math.fround(y)) | 0), ((( + Math.pow(mathy3(( + -(2**53-2)), ( + Number.MIN_VALUE)), -Number.MAX_VALUE)) != y) >>> 0))), (Math.max((Math.exp(x) | 0), y) | 0))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -0x0ffffffff, 0/0, -(2**53-2), 0, 42, 0x100000001, 1, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 2**53-2, 0x080000000, -0x080000000, 0x07fffffff, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, 2**53, -(2**53), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -(2**53+2), 0.000000000000001, -0x100000001]); ");
/*fuzzSeed-244067732*/count=129; tryItOut("\"use strict\"; eval = delete x.x, b = /\\cR|(?![^])|(?:(?!\\2)){4,}|(?:.){1}/ym, saiosb, z, \u3056;/*MXX1*/o1 = this.g0.Number.EPSILON;");
/*fuzzSeed-244067732*/count=130; tryItOut("a2.splice(NaN, ({valueOf: function() { print(x);return 7; }}));");
/*fuzzSeed-244067732*/count=131; tryItOut("\"use strict\"; ((4277));print(x);\u000ct2.set(t0, window);");
/*fuzzSeed-244067732*/count=132; tryItOut("m1.__proto__ = e0;");
/*fuzzSeed-244067732*/count=133; tryItOut("v1 = Object.prototype.isPrototypeOf.call(b1, i1);");
/*fuzzSeed-244067732*/count=134; tryItOut("\"use asm\"; var fwjski = new SharedArrayBuffer(16); var fwjski_0 = new Int8Array(fwjski); print(fwjski_0[0]); fwjski_0[0] = -28; var fwjski_1 = new Uint8ClampedArray(fwjski); print(fwjski_1[0]); fwjski_1[0] = 29; var fwjski_2 = new Float32Array(fwjski); fwjski_2[0] = 28; var fwjski_3 = new Uint16Array(fwjski); fwjski_3[0] = -5; new FunctionArray.prototype.sort.apply(g2.a2, [f2]);print(fwjski_1[0]);this.g2.e1.delete(b1);");
/*fuzzSeed-244067732*/count=135; tryItOut("\"use strict\"; \"use asm\"; print(\n\"\\uC413\");");
/*fuzzSeed-244067732*/count=136; tryItOut(";");
/*fuzzSeed-244067732*/count=137; tryItOut("\"use strict\"; v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 2 == 0), noScriptRval: false, sourceIsLazy:  /x/ , catchTermination: false }));");
/*fuzzSeed-244067732*/count=138; tryItOut("var r0 = 2 ^ 9; r0 = 1 * x; var r1 = x + 1; x = r0 / r1; r1 = 3 & r0; print(x); var r2 = r1 % r1; var r3 = 3 / r2; var r4 = x - r0; var r5 = x & r4; var r6 = r2 / x; var r7 = r0 * 7; var r8 = r2 + r6; r6 = r6 + r2; var r9 = x | r1; var r10 = 1 ^ r1; var r11 = r3 / r8; r8 = 3 / r0; r8 = 0 % r3; r7 = r3 % r6; var r12 = r4 | 9; var r13 = 5 - r7; var r14 = 6 * r6; print(x); var r15 = r2 % x; var r16 = r7 & r8; r2 = 6 + r15; r3 = r10 % r9; var r17 = r6 / r6; var r18 = r8 & r2; var r19 = r15 % r14; var r20 = 0 & 8; var r21 = 5 + r20; r1 = 3 % r12; var r22 = r5 % 3; var r23 = 9 * r16; var r24 = r20 * 4; var r25 = r16 + r9; r22 = r25 - r5; var r26 = r23 + 7; var r27 = 5 & 7; var r28 = r26 % 7; var r29 = 8 + r25; r29 = 3 / r3; r25 = r0 * r13; r7 = 6 * r20; var r30 = 3 * r29; var r31 = r16 ^ 3; var r32 = r22 & 4; var r33 = r30 + r8; var r34 = 4 / 3; var r35 = r19 - 6; r34 = r15 + 3; r18 = x + r13; var r36 = 3 + r30; var r37 = 1 ^ 2; r24 = r33 / 6; var r38 = 5 - r34; var r39 = r5 ^ r25; var r40 = 1 / 5; var r41 = 9 & r22; r9 = r11 * r39; var r42 = r8 & r31; var r43 = 6 % r2; var r44 = r22 | r37; var r45 = r27 | r34; var r46 = r43 - r35; var r47 = r14 - r23; var r48 = r1 | 7; var r49 = 1 * r36; var r50 = 1 % r49; var r51 = 9 + r23; var r52 = r3 / r51; var r53 = r2 | r26; r47 = 4 & r26; r37 = r17 ^ r44; var r54 = r10 + 7; var r55 = r35 | 2; print(r4); var r56 = r12 / 1; var r57 = 2 + 8; var r58 = 0 % r1; var r59 = r57 - 2; var r60 = r54 + r23; var r61 = 9 | 2; var r62 = 0 / 2; var r63 = r50 - 8; var r64 = r47 | r50; var r65 = r0 / 5; var r66 = r24 % r56; var r67 = r28 * r31; r16 = r20 % 5; var r68 = r15 & r56; var r69 = r34 / r5; var r70 = r34 / r47; var r71 = 4 ^ r32; var r72 = r55 | 5; var r73 = r52 ^ r23; var r74 = r54 + 9; var r75 = 1 - r71; var r76 = r49 ^ r2; print(x); r41 = 0 / 1; var r77 = 1 - 5; var r78 = r22 - r23; var r79 = 6 / r22; var r80 = 9 % r58; r46 = r65 ^ r34; var r81 = 6 * 3; var r82 = r7 / 7; var r83 = r35 - r15; var r84 = r5 & r27; var r85 = r58 & 6; var r86 = r65 / 7; r20 = r84 ^ r46; var r87 = r54 % r5; r59 = 3 * r16; var r88 = r68 / r73; var r89 = r66 | x; print(r68); print(r39); var r90 = r2 + r68; r60 = r71 / r41; var r91 = r40 | r54; var r92 = 3 % r87; var r93 = r10 * r59; r80 = 9 % 7; ");
/*fuzzSeed-244067732*/count=139; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (Math.tanh(((mathy1(y, ( + ((x >>> 0) << (-(2**53-2) >>> 0)))) * x) >>> 0)) % Math.exp(Math.fround(( + (( + y) ? x : ( + y))))))) << Math.atanh((( ~ (( ! (Math.fround(x) % x)) >>> 0)) | 0))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 42, 1/0, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 2**53+2, 1, -0, -0x080000001, -1/0, -0x100000000, -Number.MIN_VALUE, 0x080000001, -0x080000000, -0x100000001, 2**53-2, 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, -(2**53), 0/0, 0x100000000, -(2**53-2), 0x0ffffffff, -0x07fffffff, 0x100000001]); ");
/*fuzzSeed-244067732*/count=140; tryItOut("i2.send(b1);");
/*fuzzSeed-244067732*/count=141; tryItOut("e1.delete(b0);");
/*fuzzSeed-244067732*/count=142; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=143; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.fround(( ~ Math.fround(( ~ y)))) === Math.atan2(Math.fround(Math.fround(Math.min(((x > x) | 0), Math.log10(x)))), Math.imul(Math.hypot(-(2**53-2), x), (( - (Math.cos((y | 0)) >>> 0)) >>> 0)))) < ( + ( ! Math.fround(Math.cosh(Math.fround(Math.pow(Math.atan(y), y))))))) >>> 0); }); testMathyFunction(mathy3, [0.000000000000001, 2**53+2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), -0x100000000, 0x080000001, -0x080000001, Number.MIN_VALUE, 0, 2**53, 1.7976931348623157e308, 2**53-2, 42, -(2**53), -0, -Number.MIN_VALUE, 1/0, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, -0x100000001, 0x100000000, -1/0, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, 0x07fffffff, Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-244067732*/count=144; tryItOut("{{ void 0; minorgc(false); } {} }\n");
/*fuzzSeed-244067732*/count=145; tryItOut(";");
/*fuzzSeed-244067732*/count=146; tryItOut("e1.toString = f0\nnull;");
/*fuzzSeed-244067732*/count=147; tryItOut("let (oqtkjt, \u3056 = window) { print((4277)); }");
/*fuzzSeed-244067732*/count=148; tryItOut("\"use strict\"; Array.prototype.sort.call(a1);");
/*fuzzSeed-244067732*/count=149; tryItOut("\"use strict\"; m1.set(t1, g0);");
/*fuzzSeed-244067732*/count=150; tryItOut("a0 = new Array;");
/*fuzzSeed-244067732*/count=151; tryItOut("/*ADP-3*/Object.defineProperty(o1.a1, 10, { configurable: true, enumerable: (x % 5 != 0), writable: true, value: m2 });");
/*fuzzSeed-244067732*/count=152; tryItOut("mathy5 = (function(x, y) { return (Math.round(((Math.tan(y) && ( - Math.fround(Math.atan2(Math.fround(( ~ ( + Math.ceil(-0x080000001)))), Math.fround((-0x080000001 != Math.fround(Math.max(x, y)))))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-244067732*/count=153; tryItOut("mathy5 = (function(x, y) { return ( + ( + ( + Math.expm1(( + (( + ( + Math.trunc(( + y)))) >> ( + x))))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x100000001, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53-2), Number.MIN_VALUE, 2**53+2, 0, 1/0, -Number.MAX_VALUE, -0x100000001, 0x080000001, 0/0, -0x100000000, -0x080000000, 1, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0x07fffffff, 2**53, 1.7976931348623157e308, 2**53-2, 0.000000000000001, 42]); ");
/*fuzzSeed-244067732*/count=154; tryItOut("mathy0 = (function(x, y) { return ( ! ( ! Math.fround(Math.imul(((Math.atan2((-0x100000000 >>> 0), (x >>> 0)) >>> 0) | 0), Math.fround(Math.max(y, (Math.fround(Math.fround(Math.fround(x))) >>> 0))))))); }); testMathyFunction(mathy0, [0x07fffffff, -Number.MIN_VALUE, Math.PI, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, 0x100000001, Number.MIN_VALUE, 0/0, 2**53-2, 1, -(2**53+2), 0x080000001, -0, 2**53, -0x100000000, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0, -0x100000001, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53), 2**53+2, 42, 0x100000000, 1/0, -0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=155; tryItOut("v0 = Object.prototype.isPrototypeOf.call(a2, g2);");
/*fuzzSeed-244067732*/count=156; tryItOut("v1 = Object.prototype.isPrototypeOf.call(p0, h2);\nthis.i0.send(e2);\n");
/*fuzzSeed-244067732*/count=157; tryItOut("\"use strict\"; a0.push();");
/*fuzzSeed-244067732*/count=158; tryItOut("v1.__proto__ = h1;");
/*fuzzSeed-244067732*/count=159; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[[undefined], x, [undefined], x, [undefined], x, [undefined], [undefined], [undefined], x, [undefined], x, x, x, [undefined], x, x, x, [undefined], x, x, [undefined], [undefined], x, [undefined], x, [undefined], x, [undefined], x, [undefined], [undefined], [undefined], [undefined], [undefined], x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, [undefined], x, x, x, x, x, x, [undefined], x, [undefined], x, [undefined], [undefined]]) { print( /x/g ); }e = x;");
/*fuzzSeed-244067732*/count=160; tryItOut("v1 = this.g0.runOffThreadScript();");
/*fuzzSeed-244067732*/count=161; tryItOut("m0.set(a2, g1.t2);/*MXX1*/o2 = g2.WeakMap.prototype.has;{ if (!isAsmJSCompilationAvailable()) { void 0; setGCCallback({ action: \"minorGC\", phases: \"end\" }); } void 0; } h2 = ({getOwnPropertyDescriptor: function(name) { s0 += s0;; var desc = Object.getOwnPropertyDescriptor(e0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { m1.has(p2);; var desc = Object.getPropertyDescriptor(e0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v1.toSource = (function() { try { o0.s0 += o1.s1; } catch(e0) { } try { print(o2); } catch(e1) { } try { v1 = (this.e0 instanceof t2); } catch(e2) { } t0 = new Float64Array(b0); return f2; });; Object.defineProperty(e0, name, desc); }, getOwnPropertyNames: function() { return p1; return Object.getOwnPropertyNames(e0); }, delete: function(name) { this.h1.get = f0;; return delete e0[name]; }, fix: function() { print(uneval(this.f2));; if (Object.isFrozen(e0)) { return Object.getOwnProperties(e0); } }, has: function(name) { return i1; return name in e0; }, hasOwn: function(name) { m1.delete(h1);; return Object.prototype.hasOwnProperty.call(e0, name); }, get: function(receiver, name) { for (var v of o1) { Array.prototype.unshift.apply(a1, []); }; return e0[name]; }, set: function(receiver, name, val) { Array.prototype.push.apply(a2, [i1, m0, g2.s2]);; e0[name] = val; return true; }, iterate: function() { neuter(b0, \"change-data\");; return (function() { for (var name in e0) { yield name; } })(); }, enumerate: function() { ;; var result = []; for (var name in e0) { result.push(name); }; return result; }, keys: function() { e1.add(this.a0);; return Object.keys(e0); } });");
/*fuzzSeed-244067732*/count=162; tryItOut("v2 = (f0 instanceof a1);for(let x of WeakMap.prototype.get) /*ADP-3*/Object.defineProperty(a1, 8, { configurable: \"\\u4237\", enumerable: true, writable: \"\\uE201\", value: ( /x/g )( \"\" ) = x });with({}) throw StopIteration;");
/*fuzzSeed-244067732*/count=163; tryItOut("mathy2 = (function(x, y) { return (( - Math.fround(Math.imul(Math.fround((Math.fround(Math.atan2(x, Number.MAX_SAFE_INTEGER)) != Math.fround(( ! x)))), Math.fround(((( + (mathy1(x, Math.fround(x)) >>> 0)) ? Math.trunc(Math.acos(Math.fround(( ! (x | 0))))) : Math.fround(Math.acos(Math.fround(mathy0(y, ( + Number.MIN_VALUE)))))) * x))))) >>> 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, Math.PI, 2**53, 0x07fffffff, 0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 0, 0x100000001, 0.000000000000001, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 42, -0x080000000, -(2**53), Number.MIN_VALUE, -0x07fffffff, -0x100000001, -0x0ffffffff, 0x100000000, -(2**53-2), 1, -1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 2**53+2, -0x080000001]); ");
/*fuzzSeed-244067732*/count=164; tryItOut("a2.shift(v2, f1);");
/*fuzzSeed-244067732*/count=165; tryItOut("\"use strict\"; a0.splice(9, v1);");
/*fuzzSeed-244067732*/count=166; tryItOut("\"use asm\"; { void 0; void gc('compartment'); } m2.has(f0);");
/*fuzzSeed-244067732*/count=167; tryItOut("with()( '' \u0009);");
/*fuzzSeed-244067732*/count=168; tryItOut("for(let e of [/(?=\\3?|[\\u8C8a-\ub008\\d]?)?/gi for (x of x)]) e = window;let(x, w = ((4277) **= x | undefined), y = \n\"\\u4CBF\" != 0.1, d = x, eval = x, x, w = (yield window), gmkdto) { try { for(let e of (window\n) for ((y) in (yield this)) for (w of c >= z for each (z in \"\\u8AE1\") for (x of []) if (z)) for (d of /*FARR*/[ /x/g , , ...[]]) for each (this.x in [])) yield ((makeFinalizeObserver('tenured'))); } finally { y = x; } }");
/*fuzzSeed-244067732*/count=169; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0((( ! (Math.fround((Math.fround(y) > Math.fround((Math.hypot((y | 0), (y >>> 0)) | 0)))) >>> 0)) >>> 0), Math.fround(( - Math.fround(Math.min(y, Math.acosh((Math.imul((Math.ceil(x) >>> 0), x) >>> 0))))))); }); testMathyFunction(mathy1, [-0x100000001, 1/0, 2**53, -Number.MIN_VALUE, -(2**53), -0, 2**53-2, 0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, 0, 1.7976931348623157e308, 0x07fffffff, 1, 0x100000000, -0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 2**53+2, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 0/0, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=170; tryItOut("mathy4 = (function(x, y) { return ((( + (( ~ Math.round(((( + ( ~ mathy1(-0x080000001, y))) == (Math.log2(y) | 0)) | 0))) - ((Math.fround(( - (Math.fround(Math.max(( + Math.atan2(( + x), ( + -0))), x)) || (( ~ y) >>> 0)))) ? Math.min(((( + -0) | 0) >>> 0), (((( + y) ? (Math.imul(( + 0x100000001), y) | 0) : ((x + ( ! x)) | 0)) | 0) >>> 0)) : ( + (mathy1(y, x) ? Math.fround(((Number.MAX_VALUE >>> 0) === -0x080000000)) : y))) | 0))) | 0) == (Math.fround(Math.pow(Math.fround(Math.log(Math.log(x))), ( + (( ~ (-(2**53) | 0)) | 0)))) ? ((( - ((0x100000000 + (y >>> 0)) | 0)) < Math.fround(Math.log10(Math.fround(( - y))))) >>> 0) : ( - (( + mathy2(( + ((Math.cosh((( - x) >>> 0)) >>> 0) == y)), ( + -0x100000001))) | 0)))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -0x100000000, 0, -(2**53+2), 2**53-2, -Number.MAX_SAFE_INTEGER, Math.PI, 1, 0/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 0x100000000, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, 0x080000001, -(2**53), -1/0, Number.MIN_SAFE_INTEGER, -0, 0x080000000, 1/0, Number.MIN_VALUE, 2**53, -0x080000001, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 42, -(2**53-2), -0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=171; tryItOut("mathy5 = (function(x, y) { return (( + Math.max((Math.fround(Math.round(( + ( - ( + (Math.log10((-(2**53+2) | 0)) | 0)))))) | 0), (Math.atan2(((-0x0ffffffff == x) >>> 0), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))) ? Math.sqrt((Math.log((mathy3(y, (Math.trunc((( + (y >>> 0)) >>> 0)) | 0)) | 0)) | 0)) : mathy0(Math.imul(-(2**53-2), Math.fround(Math.min(Math.fround(y), Math.fround(x)))), Math.atanh((y , Math.fround((( ~ (Math.fround(Math.sqrt(Math.fround(-Number.MIN_VALUE))) | 0)) | 0)))))); }); testMathyFunction(mathy5, [2**53+2, 42, -0x100000001, -(2**53), -1/0, 2**53-2, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 0x080000001, 0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, -0x100000000, -(2**53+2), 0x100000000, 0/0, -0, 1, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0x07fffffff, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -0x080000000, 0.000000000000001, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=172; tryItOut("b1 = t2.buffer;");
/*fuzzSeed-244067732*/count=173; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( ~ (Math.min((( - Math.min(Math.fround(0x0ffffffff), 1/0)) >>> 0), Math.fround((((x >= (Math.asin(-0) , x)) >>> 0) ? ( ! ( + y)) : Math.cosh(mathy1(Math.fround(Math.fround(Math.fround(y))), ( + (2**53-2 , ( + x)))))))) | 0)) | 0); }); testMathyFunction(mathy3, [-1/0, 0.000000000000001, -(2**53), -0x100000000, 0x07fffffff, 1.7976931348623157e308, 0, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000001, 1, -0x080000001, 0x080000000, 0x0ffffffff, Math.PI, 2**53, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0, 1/0, Number.MAX_VALUE, 2**53-2, 2**53+2, -(2**53-2), 42, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=174; tryItOut("o1.m0.set(Math.ceil(-17), o2.v1);");
/*fuzzSeed-244067732*/count=175; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=176; tryItOut("\"use strict\"; /*vLoop*/for (let ugzmsl = 0, x = arguments[\"seal\"] = let (e)  /x/g , eval; ugzmsl < 7; ++ugzmsl) { z = ugzmsl; v1 = (m2 instanceof i2);o1.v0 = new Number(NaN); } ");
/*fuzzSeed-244067732*/count=177; tryItOut("(function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: new Function, has: function() { throw 3; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: undefined, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })((4277))");
/*fuzzSeed-244067732*/count=178; tryItOut("mathy3 = (function(x, y) { return Math.log2(Math.max(( + ( + Math.log10((Math.max(((( + y) & Math.fround((x != ( + 0x100000001)))) >>> 0), (Math.fround(Math.hypot(Math.fround(y), Math.fround(y))) >>> 0)) >>> 0)))), Math.pow(((((Math.max(( + 0x07fffffff), y) >>> 0) >> (Math.cosh((y >>> 0)) | 0)) >>> 0) <= Math.fround((Math.atan2(y, ((Math.round(-0x100000001) >>> 0) | 0)) | 0))), (mathy2((( + (( + x) ? x : ( + null))) | 0), (-1/0 | 0)) | 0)))); }); testMathyFunction(mathy3, [0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, -0x100000001, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, 0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, 0/0, 2**53+2, 1, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -0x07fffffff, -(2**53-2), -0, 1/0, 42, -1/0, -Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, 0.000000000000001, Math.PI]); ");
/*fuzzSeed-244067732*/count=179; tryItOut("mathy1 = (function(x, y) { return (( + ( ~ Math.max(x, Math.acos(x)))) || ( + Math.fround(( - Math.fround(Math.ceil(y)))))); }); testMathyFunction(mathy1, [2**53-2, -(2**53), 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0, 0, -0x100000000, Math.PI, -0x07fffffff, -(2**53+2), -0x080000000, 2**53, 0x080000001, -1/0, 0x100000000, 42, -0x080000001, 1, -0, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=180; tryItOut("\"use strict\"; /*infloop*/while(\"\\u3439\" !== a){v0 = g2.runOffThreadScript();v0 = t1.length;function \u3056(x, b) { yield -15 <<= w } [1,,]; }");
/*fuzzSeed-244067732*/count=181; tryItOut("Object.defineProperty(this, \"v2\", { configurable: true, enumerable: true,  get: function() {  return g1.g2.a0.some(o2.f2); } });");
/*fuzzSeed-244067732*/count=182; tryItOut("a0.unshift(g1, h0);");
/*fuzzSeed-244067732*/count=183; tryItOut("/*oLoop*/for (let zsimpu = 0; zsimpu < 12; ++zsimpu) { v2 = (b1 instanceof e0); } ");
/*fuzzSeed-244067732*/count=184; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.fround(Math.imul((Math.min(((Math.round((y >>> 0)) >>> 0) >>> 0), (Math.atan2(x, ( + -Number.MIN_VALUE)) >>> 0)) >>> 0), mathy1(y, Math.hypot(( + (Math.PI ? Math.fround(( ~ y)) : 42)), (x / y))))) >>> 0) * mathy1(Math.fround((Math.fround(Math.sqrt(y)) & Math.fround((Math.hypot((x | 0), Math.atanh(y)) >>> 0)))), Math.asinh((Math.ceil((0x100000001 != y)) >>> 0)))); }); testMathyFunction(mathy3, [-0x0ffffffff, 0x080000000, -1/0, -0, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, 42, -0x080000000, 0x100000001, 0, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 1, 0x080000001, 2**53+2, 0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, Math.PI, 2**53, 2**53-2, 0/0, 1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001]); ");
/*fuzzSeed-244067732*/count=185; tryItOut("\"use strict\"; ;");
/*fuzzSeed-244067732*/count=186; tryItOut("/*RXUB*/var r = /[^\\cO-\\u00B8\u6ddd\\B-\u1049]/gm; var s = \"\\u1048\"; print(s.replace(r, '', \"gyim\")); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=187; tryItOut("\"use strict\"; for (var p in t1) { o1.s0.__proto__ = a0; }");
/*fuzzSeed-244067732*/count=188; tryItOut("testMathyFunction(mathy1, [false, (new Boolean(false)), '0', -0, 0.1, 1, (new Boolean(true)), NaN, /0/, undefined, null, 0, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new String('')), '', (new Number(-0)), ({toString:function(){return '0';}}), (new Number(0)), '/0/', [0], [], (function(){return 0;}), ({valueOf:function(){return 0;}}), true, '\\0']); ");
/*fuzzSeed-244067732*/count=189; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( - ( - ( + ( + x)))) >>> 0); }); testMathyFunction(mathy0, [0/0, 2**53+2, Math.PI, -(2**53), -0x07fffffff, 0x080000001, 0.000000000000001, -0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, 2**53, 42, -(2**53+2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 1.7976931348623157e308, 0, -Number.MIN_VALUE, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 1, -0x100000001, -1/0]); ");
/*fuzzSeed-244067732*/count=190; tryItOut("mathy4 = (function(x, y) { return ( ~ Math.fround(Math.acos((( - ((((-0x100000001 >>> 0) == (x >>> 0)) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), delete w.y, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), delete w.y, delete w.y, objectEmulatingUndefined(), delete w.y, objectEmulatingUndefined()]); ");
/*fuzzSeed-244067732*/count=191; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53+2), 0.000000000000001, 0x0ffffffff, 1/0, 0x080000001, -0x07fffffff, 0/0, 42, 2**53+2, 0x100000000, -1/0, 1.7976931348623157e308, Number.MIN_VALUE, 1, Number.MAX_VALUE, Math.PI, 0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), -0x080000001, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0, 2**53-2, 0x080000000]); ");
/*fuzzSeed-244067732*/count=192; tryItOut("Object.preventExtensions(o0.o0);");
/*fuzzSeed-244067732*/count=193; tryItOut("\"use strict\"; Object.prototype.watch.call(e2, \"13\", this.f2);");
/*fuzzSeed-244067732*/count=194; tryItOut("\"use strict\"; with(x){print(new RegExp(\"[^\\u63b2-\\ua4a1\\\\W\\u008c-\\u8ec2\\\\u00C8]+?\\\\1\", \"g\"));/*RXUB*/var r = new RegExp(\"(?:\\\\3|\\\\2{2,}|\\\\2|(?!(?!\\\\D|\\ube54))|(?:[^\\\\w\\\\b\\u0081-\\u01e0\\\\D])+?)\", \"ym\"); var s = \"\\u0096\\n\"; print(s.match(r));  }function y([[, [], [, a, ], ]], x)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((Float64ArrayView[1]));\n  }\n  return f;s0[\"reject\"] = Math.min(-3, timeout(1800));");
/*fuzzSeed-244067732*/count=195; tryItOut("/*MXX2*/g2.g0.String.fromCodePoint = g1.a1;");
/*fuzzSeed-244067732*/count=196; tryItOut("print(p0);neuter(b2, \"same-data\");");
/*fuzzSeed-244067732*/count=197; tryItOut("t2 = new Int8Array(a0);");
/*fuzzSeed-244067732*/count=198; tryItOut("x = p2;Object.prototype.watch.call(m1, \"getOwnPropertyNames\", (function() { for (var j=0;j<51;++j) { f2(j%4==0); } }));");
/*fuzzSeed-244067732*/count=199; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[x, x, new String('q'), new String('q'), x, x, x, eval(\"(y);-27;\",  '' ), eval(\"(y);-27;\",  '' ), eval(\"(y);-27;\",  '' ), x, new String('q'), eval(\"(y);-27;\",  '' ), new String('q'), eval(\"(y);-27;\",  '' ), eval(\"(y);-27;\",  '' ), new String('q'), eval(\"(y);-27;\",  '' ), eval(\"(y);-27;\",  '' ), eval(\"(y);-27;\",  '' ), new String('q')]); ");
/*fuzzSeed-244067732*/count=200; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.cos((( ~ (mathy0((Math.sinh(x) ? y : ( + 0x07fffffff)), ( + Math.abs(( ! ( + Math.clz32(( + -Number.MIN_VALUE))))))) | 0)) | 0)); }); ");
/*fuzzSeed-244067732*/count=201; tryItOut("\"use strict\"; ");
/*fuzzSeed-244067732*/count=202; tryItOut("this.o0 = Object.create(m2);");
/*fuzzSeed-244067732*/count=203; tryItOut("e0.delete(g1.h2);");
/*fuzzSeed-244067732*/count=204; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: String.prototype.toLocaleLowerCase}, new ArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=205; tryItOut("testMathyFunction(mathy1, [0.000000000000001, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, 0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 1/0, -(2**53+2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, 42, -0x07fffffff, 0x100000001, 0/0, -Number.MIN_VALUE, -0, 0x100000000, Number.MIN_VALUE, 1, 0, 2**53, -1/0, -(2**53), -0x080000000, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=206; tryItOut("/*tLoop*/for (let z of /*MARR*/[objectEmulatingUndefined(), new Number(1.5),  '\\0' ,  '\\0' , new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), \"\\uE5C5\", objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(),  '\\0' , \"\\uE5C5\",  '\\0' , \"\\uE5C5\",  '\\0' , objectEmulatingUndefined(),  '\\0' , \"\\uE5C5\",  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), \"\\uE5C5\", \"\\uE5C5\", new Number(1.5),  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5), \"\\uE5C5\", \"\\uE5C5\"]) { m2.get(b2); }");
/*fuzzSeed-244067732*/count=207; tryItOut("o2.i0 = new Iterator(f2);");
/*fuzzSeed-244067732*/count=208; tryItOut("let (a) { this.v1 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 34 == 15), noScriptRval: true, sourceIsLazy: true, catchTermination: e, sourceMapURL: g2.s2 })); }");
/*fuzzSeed-244067732*/count=209; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return Math.pow((( ! (Math.atan(Math.tanh(Math.fround((y ** -1/0)))) >>> 0)) ^ (((((y >>> 0) | (Math.log1p((mathy0((2**53-2 >>> 0), ((( ~ (x >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)) >>> 0) >>> 0) * y)), Math.fround(Math.min((( + ( + ( - ( + ((y % (x >>> 0)) >>> 0))))) | 0), (Math.max(y, (( ! ( + x)) != x)) >= Math.pow(( - x), -0x080000000))))); }); testMathyFunction(mathy4, [42, -1/0, 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -0x100000000, -0x0ffffffff, 0, 2**53+2, Math.PI, -(2**53+2), Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, 0/0, 0x0ffffffff, 2**53, -0x07fffffff, -0x080000001, Number.MAX_VALUE, 1/0, 1.7976931348623157e308, 1, -(2**53-2), -0x080000000, -(2**53), 0x080000001, -Number.MIN_VALUE, 2**53-2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=210; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.fround(Math.cos((( + ((mathy0(x, ( + ( - ( + x)))) >>> 0) % y)) <= ( + (0.000000000000001 >= (y ? 1.7976931348623157e308 : Math.fround(y))))))) ? (((( + (( + (x <= (( + ( ! ( + y))) | 0))) < Math.fround(Math.max(Math.fround(((mathy0(( + x), x) >>> 0) <= y)), (y >>> 0))))) | 0) ** ((mathy0((y >>> ( ~ x)), ((( ~ x) != ( + (( + -0x080000000) ? ( ~ (y >>> 0)) : (Math.tan((x >>> 0)) >>> 0)))) | 0)) >>> 0) | 0)) | 0) : Math.expm1(Math.hypot(( + Math.atanh(y)), Math.fround((Math.acosh((Math.trunc((x | 0)) | 0)) <= Math.fround(x)))))); }); testMathyFunction(mathy1, [0.000000000000001, 2**53-2, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, -(2**53-2), -0x080000000, 2**53, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), -1/0, 0x100000001, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000001, -0, Number.MAX_VALUE, 0/0, -Number.MAX_VALUE, -0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, 1, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 0, 42, -0x080000001]); ");
/*fuzzSeed-244067732*/count=211; tryItOut("a2 = a0.map((function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { var r0 = 0 + x; var r1 = 6 + a4; var r2 = a5 % a4; var r3 = 1 & 8; var r4 = a7 % a5; print(a8); var r5 = 5 | a8; var r6 = 5 ^ r3; var r7 = a2 % x; var r8 = a6 + 4; r8 = r7 / x; var r9 = r8 - r6; a7 = a4 / r8; var r10 = 3 / 8; a7 = r5 & 8; var r11 = 0 & x; var r12 = r4 ^ r11; a1 = a1 & 4; var r13 = a3 + 2; var r14 = a4 & a7; var r15 = 1 - r8; print(r0); var r16 = a3 & 8; var r17 = r1 | a5; var r18 = 1 ^ 5; r10 = r8 / 5; var r19 = 2 + r12; return a4; }));");
/*fuzzSeed-244067732*/count=212; tryItOut("for (var v of this.v2) { try { m2.has(g2.m1); } catch(e0) { } try { Array.prototype.forEach.call(a2, (function() { for (var j=0;j<27;++j) { f0(j%5==0); } }), h2, g0.g0); } catch(e1) { } try { g0.offThreadCompileScript(\"function f1(t2)  { t0 = t2.subarray(12); } \"); } catch(e2) { } print(s1); }");
/*fuzzSeed-244067732*/count=213; tryItOut("mathy1 = (function(x, y) { return mathy0((( + Math.log2(( + y))) && ( ~ mathy0(Math.expm1((x | 0)), (( + y) | 0)))), ( + Math.ceil(( + mathy0(Math.fround(( ! (y | 0))), x))))); }); ");
/*fuzzSeed-244067732*/count=214; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.hypot(mathy0(Math.acos(mathy0(mathy0(42, x), (Math.log1p((x >>> 0)) | 0))), ((( - -Number.MIN_SAFE_INTEGER) | 0) + Math.fround(x))), ( + ( ~ ( ! (( + Math.fround((x ? y : (Math.pow(((Math.log2((-Number.MAX_SAFE_INTEGER | 0)) | 0) >>> 0), (x >>> 0)) >>> 0)))) != ((Math.pow(y, (y | 0)) ** y) >>> 0))))))); }); testMathyFunction(mathy1, /*MARR*/[new Number(1), false, new Number(1), (void 0), false, false, new Number(1), new Number(1), NaN, false, new Number(1), (void 0), new Number(1), false, false, (void 0), NaN, NaN, false, (void 0), NaN, false, (void 0), NaN, new Number(1), NaN, false, new Number(1), new Number(1), NaN, false, new Number(1), (void 0), false, new Number(1), (void 0), NaN, (void 0), NaN, false, false, (void 0), (void 0), false, false, false, NaN, (void 0), false, new Number(1), NaN, NaN, NaN, NaN, (void 0), false, false, new Number(1), new Number(1), new Number(1), new Number(1), false, false, new Number(1), false, NaN, false, false, NaN, (void 0), (void 0), false, new Number(1)]); ");
/*fuzzSeed-244067732*/count=215; tryItOut("\"use strict\"; m1.set(f0, f0);");
/*fuzzSeed-244067732*/count=216; tryItOut("o0.o1.v2 = a2.reduce, reduceRight(f0, v2, o1.o1);");
/*fuzzSeed-244067732*/count=217; tryItOut("mathy0 = (function(x, y) { return ((((Math.hypot(Math.imul(Math.imul(Math.fround(x), x), y), Math.atan2(Math.fround(Math.cosh((y != y))), y)) << ((x * ( + y)) >>> 0)) >>> 0) & (( - Math.fround(Math.log10(y))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[(void 0), Infinity,  /x/ , (void 0)]); ");
/*fuzzSeed-244067732*/count=218; tryItOut("\"use strict\"; f1 = (function() { for (var j=0;j<21;++j) { this.o2.g0.f1(j%3==1); } });");
/*fuzzSeed-244067732*/count=219; tryItOut("v2 = g1.runOffThreadScript();");
/*fuzzSeed-244067732*/count=220; tryItOut("\"use strict\"; o1.o1.a1.push(h0, v1);");
/*fuzzSeed-244067732*/count=221; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.min(Math.min(Math.fround(mathy0(Math.sin((( - (x >= x)) | 0)), Math.fround((Math.cbrt((Math.imul(y, Math.fround(( + Math.fround(x)))) >>> 0)) >>> 0)))), mathy3(mathy1(x, ( + ((y | 0) ** (( ~ -0) | 0)))), Math.fround(Math.hypot(Math.fround(Number.MAX_SAFE_INTEGER), Math.fround((Math.max((Math.atan2(y, y) | 0), (Math.fround((x / ( + Math.fround(y)))) | 0)) >>> 0)))))), ((((((x | 0) < (x | 0)) | 0) | 0) > ((Math.fround(((y >>> 0) >= Math.fround(x =  '' ))) < Math.fround((Math.min(y, (( ~ y) | 0)) | 0))) | 0)) | 0)); }); ");
/*fuzzSeed-244067732*/count=222; tryItOut("let (fzqkum, rfdics, x, [] = this <= (yield /.\\W{2,5}|\\B/gm), pxetex, y = 'fafafa'.replace(/a/g, (1 for (x in []))) %= this.__defineSetter__(\"b\", Function)) { /*bLoop*/for (let kklobh = 0; kklobh < 50; ++kklobh) { if (kklobh % 3 == 1) { /*oLoop*/for (gflqxp = 0,  \"\" ; gflqxp < 2; ++gflqxp, /([^]\\B{0,2}\\B+)?/gim) { print(null); }  } else { /*infloop*/L:for(null; Math; /(?!\\B|[^\\u0047-\\\u982c\\W\u00af][^]+|\uee36|[^]{4294967295,4294967296}*?|\\u0323\\B(?=\\B)*?)/g) v2 = evalcx(\"function o1.f2(v0) null\", g2); }  }  }");
/*fuzzSeed-244067732*/count=223; tryItOut("\"use strict\"; a1.sort(String.prototype.repeat.bind(m1), g1.g0);");
/*fuzzSeed-244067732*/count=224; tryItOut("\"use strict\"; L:with({a: x}){o2 + ''; }");
/*fuzzSeed-244067732*/count=225; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=226; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.abs(((Math.fround(( + Math.hypot(( + ( ! ( + ( + (y * ( ! x)))))), ( + Math.cbrt(y))))) ^ (( - ((((((x >>> 0) , (-0x080000000 >>> 0)) >>> 0) >> (Math.fround(Math.hypot(Math.fround(Math.atan2(-0x100000000, y)), Math.fround(Math.pow(0x07fffffff, (( ! (-1/0 >>> 0)) >>> 0))))) | 0)) | 0) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), -0x080000000, 2**53, 1, 2**53-2, -(2**53-2), 2**53+2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, 0.000000000000001, 0x100000000, 0x07fffffff, 0x080000001, 0/0, -0x0ffffffff, 42, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, -(2**53), -1/0, -0x07fffffff, 0, Number.MAX_VALUE, 1.7976931348623157e308, 1/0, 0x080000000, -0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=227; tryItOut("testMathyFunction(mathy2, [-(2**53), 2**53, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, 1.7976931348623157e308, 42, -0x100000000, 1, 0/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, -1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, 2**53+2, -(2**53+2), 0, -0x100000001, 0x080000001, 0x100000000, 0x0ffffffff, 0x100000001, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, -0x080000000, 0x07fffffff, 2**53-2]); ");
/*fuzzSeed-244067732*/count=228; tryItOut("o2.m2.has(h0);function x(x, a = x, x, window, w, z, window = length, x = this, eval, x = [,], e, eval, c, d, w, y = {}, x, a = x, x, window, x, d = \"\\u8881\", z, \u3056, x, x, x, e, this.b, NaN, \u3056 = x, c, b, d, y, NaN, window, a, z, w, x, NaN, a = \"\\u46C4\", e, a, c, x, x, x, x, b, w, x, getUTCHours, w = [z1], x, x = \"\\uDEB4\", window, c, a, window, x, NaN = -28, null, x, x, window, x, w, x, a, x, this.x, x, b, window, eval, d, x = new RegExp(\"(?!\\\\1)\", \"m\"), \u3056, this.x, e, z, b, x, x, x, a, eval, NaN, eval, b, x) { return ++Root } print(x);");
/*fuzzSeed-244067732*/count=229; tryItOut("this.v1 = evalcx(\"(x /= x)\", g2);");
/*fuzzSeed-244067732*/count=230; tryItOut("testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, 42, 0x07fffffff, -0x07fffffff, -(2**53), 1, Math.PI, -0x100000001, 2**53, 0x080000001, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, 2**53+2, 0, 2**53-2, -1/0, 0x0ffffffff, 0x080000000, -0x0ffffffff, 0/0, -0, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), -(2**53+2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=231; tryItOut("v1 = a1.reduce, reduceRight((function mcc_() { var inzyth = 0; return function() { ++inzyth; if (/*ICCD*/inzyth % 10 == 8) { dumpln('hit!'); Array.prototype.sort.apply(this.a2, [(function() { for (var j=0;j<7;++j) { f2(j%5==0); } })]); } else { dumpln('miss!'); try { this.s2 = new String(a1); } catch(e0) { } try { s2 += this.s0; } catch(e1) { } a2.sort((function() { for (var j=0;j<44;++j) { f0(j%4==0); } })); } };})(), h2, g0, g1.e2, g1);");
/*fuzzSeed-244067732*/count=232; tryItOut("h2.hasOwn = (function(j) { if (j) { a0[1]; } else { try { o2 = Object.create(b2); } catch(e0) { } v1 = (h2 instanceof o2.e0); } });");
/*fuzzSeed-244067732*/count=233; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.round((mathy0(Math.fround(x), mathy2(mathy0(0/0, Math.PI), (( + mathy3(( + Math.asinh(y)), ( + x))) >>> 0))) ? mathy1(((Math.fround(Math.trunc((( - (0.000000000000001 >>> 0)) >>> 0))) >>> 0) ^ Math.exp((((2**53 >>> 0) || (Math.hypot(x, x) | 0)) >>> 0))), ( + Math.fround(Math.abs(y)))) : (0.000000000000001 >>> ( + Math.min(( + (mathy2(Math.asin(x), ((x ? -Number.MIN_SAFE_INTEGER : -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)), ( + ((1 >> x) | 0))))))) | 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 0x080000001, -(2**53-2), 0x100000000, 1/0, 0/0, 0x100000001, -Number.MAX_VALUE, 0, 0x080000000, -0x100000000, 0.000000000000001, -(2**53), 42, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, Number.MAX_VALUE, -1/0, 1, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 1.7976931348623157e308, 0x07fffffff, -0x100000001, 2**53-2, Math.PI]); ");
/*fuzzSeed-244067732*/count=234; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.tanh(( - Math.atan(Math.sign((Math.cbrt((x | 0)) | 0))))); }); testMathyFunction(mathy2, [Math.PI, -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, 0.000000000000001, -0x080000000, 1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000000, 0x0ffffffff, 1.7976931348623157e308, 0, -Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, -(2**53-2), 2**53, -0, Number.MAX_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, 0x100000000, 0/0, 1, 0x100000001, -(2**53+2), 2**53-2, -1/0, 0x07fffffff, 0x080000001]); ");
/*fuzzSeed-244067732*/count=235; tryItOut("m2.valueOf = (function() { try { Object.defineProperty(this, \"a1\", { configurable: new (/*wrap1*/(function(){ print(x);return neuter})())( /x/g .eval(\" /x/g \"), 14), enumerable: (x % 6 != 5),  get: function() {  return a0.slice(NaN, NaN); } }); } catch(e0) { } try { t0 + ''; } catch(e1) { } try { /*ADP-3*/Object.defineProperty(a2, 11, { configurable: false, enumerable: true, writable: (((x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: Int8Array, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: function() { return []; }, keys: undefined, }; })(new RegExp(\"\\\\D{134217728}|(\\\\1){0,}\", \"gyim\")), (void version(170)))))), value: h0 }); } catch(e2) { } /*ADP-2*/Object.defineProperty(this.a0, v2, { configurable: false, enumerable: (a)++, get: (function() { try { e1 = new Set; } catch(e0) { } a1 = r0.exec(o1.s2); return a2; }), set: (function() { try { v1 = this.o1.o0.g2.eval(\"v1 = Object.prototype.isPrototypeOf.call(b2, a2);\"); } catch(e0) { } g1.v1 = Object.prototype.isPrototypeOf.call(b1, p2); return b0; }) }); return m0; });");
/*fuzzSeed-244067732*/count=236; tryItOut("/*RXUB*/var r = /(?:[^](\\b){0,3}|\\D|($)|((?=\\1{2,2}))\uf760|.*((?=(\\cV)*?)))/ym; var s = (makeFinalizeObserver('nursery')); print(s.match(r)); ");
/*fuzzSeed-244067732*/count=237; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=238; tryItOut("v2 = g1.r1.ignoreCase;");
/*fuzzSeed-244067732*/count=239; tryItOut("\"use strict\"; let x = (w = 11), x = x, iyaobk, x, d = new undefined( /x/ );e2 = new Set;");
/*fuzzSeed-244067732*/count=240; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.hypot(((( - Math.expm1(((x >= (( - Math.fround(( - x))) | 0)) | 0))) >>> 0) >>> 0), (( ! Math.acos((Math.fround(Math.atan2(Math.fround(x), Math.fround(x))) | 0))) >>> 0)); }); testMathyFunction(mathy4, [0x080000000, -(2**53), 42, -Number.MAX_VALUE, -0x080000000, 0.000000000000001, 0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, 0/0, -0x100000000, Number.MIN_VALUE, 0x07fffffff, -1/0, 1/0, 0, -0x07fffffff, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 2**53, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0, -0x100000001, -Number.MIN_VALUE, 2**53+2, -0x080000001, 1, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=241; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"_\"; print(r.test(s)); ");
/*fuzzSeed-244067732*/count=242; tryItOut("/*hhh*/function pvdggv(\u3056, c, b, x = ({a1:1}), c, d = x, x, b, w, NaN, x, NaN = x, x, x = true, w, x =  /x/g , c, b, c, eval, x, z, c, x, this.get, \u3056, x = new RegExp(\"(?=(?!(?!^)?|(\\\\s))?)\", \"y\"), c, y, z, x, x, x = [z1], window, x = undefined, x = \"\\u3880\", window = -11, e, NaN, w, y, z, d = 8, x, x, a, window, c = ({a2:z2}), d, x, x, x, prototype,  , \u3056, \u3056, x, w = \"\\u594E\", x, window, x, c =  /x/g , x, x, x, d, y, a, z, eval, \u3056){Array.prototype.reverse.call(a2, p2);}/*iii*/h2.delete = (function(j) { if (j) { try { v1 = g1.runOffThreadScript(); } catch(e0) { } try { o1 + p1; } catch(e1) { } try { o0 = {}; } catch(e2) { } a1.reverse(); } else { try { t0 = t1.subarray(12); } catch(e0) { } m1.has(o2.b0); } });");
/*fuzzSeed-244067732*/count=243; tryItOut(";");
/*fuzzSeed-244067732*/count=244; tryItOut("v0 = t0.length;");
/*fuzzSeed-244067732*/count=245; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x100000000, -Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, -0, -0x100000001, 2**53+2, 1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 42, 0x100000000, -0x07fffffff, 1.7976931348623157e308, 0x100000001, 2**53, 0x080000001, 2**53-2, -(2**53-2), -Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0, 0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, -(2**53), -0x080000000, Number.MAX_VALUE, 1, 0x080000000, 0.000000000000001, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=246; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.hypot(( + ( - (((Math.fround((((y >>> 0) === x) >> Math.sin(y))) === y) | 0) / Math.fround((y % y))))), ( + Math.trunc((( + (Math.fround((Math.hypot((Math.fround(Math.clz32(Math.fround(Math.max(x, y)))) | 0), (y | 0)) | 0)) / Math.min(y, (-Number.MAX_VALUE >>> 0)))) >>> 0)))); }); ");
/*fuzzSeed-244067732*/count=247; tryItOut("\"use strict\"; e2 = new Set(this.g2);");
/*fuzzSeed-244067732*/count=248; tryItOut("with({}) { return (x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor:  '' , getPropertyDescriptor: undefined, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: (WeakSet.prototype.has).call, has: function() { return false; }, hasOwn: runOffThreadScript, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { return []; }, }; })( \"\" ), x)); } throw w;");
/*fuzzSeed-244067732*/count=249; tryItOut("mathy3 = (function(x, y) { return mathy1(mathy0(Math.pow(( + (Math.pow(y, x) >>> 0)), ( ~ ( + (Math.sinh(y) >>> 0)))), Math.log(Math.min(x, Math.max(mathy2((-(2**53+2) | 0), x), y)))), (Math.trunc((( + Math.expm1(( + y))) | 0)) | 0)); }); testMathyFunction(mathy3, /*MARR*/[null, 0x40000001, true, function(){}, 0x40000001, 0x40000001, 0x40000001, function(){}, 0x40000001, true, function(){}, 0x40000001, true]); ");
/*fuzzSeed-244067732*/count=250; tryItOut("return x;yield (new false.yoyo()(null, (4277)));");
/*fuzzSeed-244067732*/count=251; tryItOut("let (//h\nc) { g1 + ''; }");
/*fuzzSeed-244067732*/count=252; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.atan2(Math.atan2(Math.expm1(-0), ( + Math.min(( + (((0 >>> 0) < ((-0x080000001 <= x) >>> 0)) >>> 0)), ( + (Math.atan2(-Number.MIN_SAFE_INTEGER, ( + (( + Math.pow(x, Number.MIN_SAFE_INTEGER)) / Math.atan2(x, (0x080000001 >>> 0))))) ? (Math.min(( + -(2**53-2)), (x >>> 0)) >>> 0) : y))))), Math.fround((( - Math.sin(y)) === Math.fround(Math.hypot(( + y), Math.fround(x)))))) | 0); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0, -(2**53+2), 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53), -0x080000000, -0x080000001, 1, -0x100000001, 0x100000000, -(2**53-2), 0, Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, 0x07fffffff, 2**53+2, 1/0, 0x080000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, 0/0, Number.MIN_VALUE, -Number.MIN_VALUE, 42, -1/0]); ");
/*fuzzSeed-244067732*/count=253; tryItOut("/*infloop*/for(let a in \"\\u1ED2\") t0.set(a0, 15);");
/*fuzzSeed-244067732*/count=254; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=255; tryItOut("mathy4 = (function(x, y) { return Math.acos(((Math.imul(((( - (Math.asin(Math.round(x)) | 0)) >>> 0) >>> 0), (( + Math.sinh((y | 0))) >>> 0)) >>> 0) % ( + Math.atan2(( + ((y >>> 0) & (Math.pow(Math.fround(-Number.MAX_SAFE_INTEGER), Math.fround(Number.MAX_SAFE_INTEGER)) >>> 0))), ( + Math.acos(((Math.fround(Math.pow(Math.fround(y), Math.fround(-0x100000000))) & ( + (y ? mathy3(y, -0x100000001) : ( + y)))) >>> 0))))))); }); testMathyFunction(mathy4, [objectEmulatingUndefined(), 0, true, (function(){return 0;}), '\\0', (new Number(0)), (new Number(-0)), (new String('')), '', undefined, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Boolean(true)), [], [0], 1, false, null, (new Boolean(false)), ({toString:function(){return '0';}}), /0/, '0', -0, NaN, 0.1, '/0/']); ");
/*fuzzSeed-244067732*/count=256; tryItOut("\"use asm\"; new WeakMap();");
/*fuzzSeed-244067732*/count=257; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((((d0) < (d1)) ? ((true)) : ((d0) != (+(-1.0/0.0))))-(((((((0x7c179d3a) / (0xeed3f36a)) | ((0xff5a4846))) != (imul((0xc0cab04f), (/*FFI*/ff(((+(abs((0x4378d745))|0))), ((+((-2199023255553.0)))), ((-9007199254740992.0)), ((-1.0078125)))|0))|0)))|0))))|0;\n  }\n  return f; })(this, {ff: (false).call(x,  /x/ .unwatch(\"0\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[{}, 1.2e3, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ]); ");
/*fuzzSeed-244067732*/count=258; tryItOut("mathy0 = (function(x, y) { return (( + (Math.fround(( - ((Math.max((( + Math.acosh(Math.hypot(Math.fround(y), y))) >>> 0), (Math.cbrt(y) >>> 0)) >>> 0) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1/0, 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x080000001, 42, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, 0x07fffffff, 0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 1, 1.7976931348623157e308, -0x100000000, -0x080000000, -(2**53-2), 0, 2**53-2, Number.MIN_VALUE, Math.PI, -0x100000001, -1/0, 0x080000001, -0x07fffffff, -(2**53+2), 0x0ffffffff, 0x080000000, 0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=259; tryItOut("o0.o2 = {};");
/*fuzzSeed-244067732*/count=260; tryItOut("\"use strict\"; v0 = g1.runOffThreadScript();");
/*fuzzSeed-244067732*/count=261; tryItOut("\"use strict\"; Array.prototype.push.call(a1, p0, b1);");
/*fuzzSeed-244067732*/count=262; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.5474250491067253e+26;\n    var i3 = 0;\n    i3 = ((imul(((abs((imul((0x60d6d95c), ((0x78891520)))|0))|0) > ((((/*FFI*/ff(((1152921504606847000.0)), ((-9007199254740992.0)), ((6.044629098073146e+23)), ((17179869183.0)), ((-1.0078125)))|0) ? (0xf8d11897) : (0xf956dce6)))|0)), ((0x63eb6e16) <= (((Uint8ArrayView[(((0x4e434b60) < (0x110b3dcd))) >> 0])) >> ((0xfd0b1bdb)))))|0));\n    i3 = (0xfcfe1ba5);\nvar ffzopx = new ArrayBuffer(4); var ffzopx_0 = new Uint8Array(ffzopx); for (var p in g2.o0) { a2.reverse(); }    d2 = (-1.5111572745182865e+23);\n    d1 = (+pow(((d2)), ((+((Infinity))))));\n    {\nv0 = (v2 instanceof m0);    }\n    {\n      return (((0xd8879f60)*0x55a2b))|0;\n    }\n    d0 = (-1.5474250491067253e+26);\n    return ((-(((-0x2c2875f) < ((((imul((0xe25641d5), (0xffffffff))|0)))|0)) ? (0x584a213c) : ((((0x860af6d9)) | ((!((Math.hypot(26, 13))))*0xcd040))))))|0;\n  }\n  return f; })(this, {ff: function  x ({b: c}, eval, x, e, window, x, eval =  '' , x, x, e, NaN = arguments, this.d) { return; } }, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=263; tryItOut("\"use strict\"; let x, pqvveo;print(\"\\u50D9\");");
/*fuzzSeed-244067732*/count=264; tryItOut("mathy0 = (function(x, y) { return Math.round(( + ( + (( ~ ( ! Math.atan2(( ! -Number.MIN_SAFE_INTEGER), x))) >>> 0)))); }); testMathyFunction(mathy0, [-0x080000001, 2**53+2, 2**53-2, 42, -0x080000000, -(2**53+2), Math.PI, 1.7976931348623157e308, Number.MAX_VALUE, 0, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, 0x07fffffff, 0x0ffffffff, 0x080000000, 0/0, 0.000000000000001, 0x100000001, -1/0, Number.MIN_VALUE, -0x100000000, -Number.MIN_VALUE, 0x080000001, -(2**53-2), -0, -Number.MAX_VALUE, 1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53]); ");
/*fuzzSeed-244067732*/count=265; tryItOut("\"use strict\"; h1.getOwnPropertyDescriptor = f2;");
/*fuzzSeed-244067732*/count=266; tryItOut("\"use strict\"; this.a0.unshift();");
/*fuzzSeed-244067732*/count=267; tryItOut("/*ADP-3*/Object.defineProperty(a0, new ((4277))(x), { configurable: false, enumerable: (x % 6 == 3), writable: (x % 2 != 0), value: g0 });");
/*fuzzSeed-244067732*/count=268; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-(2**53-2), 0x0ffffffff, -0x080000001, 2**53-2, 0x080000000, 0.000000000000001, 1/0, -Number.MAX_VALUE, 0/0, -0x100000001, 0x100000000, 2**53, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, -0, 0x07fffffff, 1.7976931348623157e308, 0, 2**53+2, 42, 1, Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, 0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53+2), 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=269; tryItOut("/*RXUB*/var r = /\\3/yim; var s = \"0\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=270; tryItOut("this.e0 = new Set(g0);");
/*fuzzSeed-244067732*/count=271; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.trunc((Math.min(((Math.min((Math.max(x, (2**53-2 | 0)) | 0), Math.pow(y, ( + 0x080000000))) | 0) >>> 0), (Math.trunc((y / y)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, -0x100000001, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, 0.000000000000001, 2**53, 1, -0x080000000, -(2**53-2), -(2**53+2), -0x07fffffff, 0x080000000, 1/0, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 42, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, -0, 0x07fffffff, -0x100000000, 0x080000001]); ");
/*fuzzSeed-244067732*/count=272; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"(4277)\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: /*UUV1*/(y.getUTCHours = decodeURIComponent), elementAttributeName: s1, sourceMapURL: o2.s0 }));");
/*fuzzSeed-244067732*/count=273; tryItOut("\"use strict\"; var g0.b0 = t1.buffer;");
/*fuzzSeed-244067732*/count=274; tryItOut("Object.freeze(g0.e0);");
/*fuzzSeed-244067732*/count=275; tryItOut("mathy5 = (function(x, y) { return ( - ((Math.acos(( + Math.atan2(-Number.MAX_SAFE_INTEGER, (Math.abs(y) >>> 0)))) >>> 0) == Math.fround((( + Math.exp(x)) >= x)))); }); testMathyFunction(mathy5, [0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -(2**53), -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, 0x080000000, -0x080000000, 42, 0/0, 1/0, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, -1/0, 0x0ffffffff, Math.PI, -0x100000001, -0, -(2**53+2), 2**53, -0x100000000, 0x100000000, 0.000000000000001, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=276; tryItOut("t0 = new Uint32Array(({valueOf: function() { g0.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    i0 = (0x568ae5c);\n    {\n      d1 = (+log(((8193.0))));\n    }\n    i3 = ((((i4)-(0xc628e0a8)+(i0))>>>((i4)-(i0))) == (0x9e388668));\n    return ((((((0xcb61749a)) & ((0x42ee93a0)+(0x61e4a5e2)+((-8589934593.0) >= (-9.671406556917033e+24)))) != ((((-((1.00390625))) > (+pow(((+((d1)))), ((73786976294838210000.0))))))|0))+(i0)))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new SharedArrayBuffer(4096));function x({this.b, d: c, y: {x}, w: [x]}, window) { print(x); } m1.has(({toLocaleDateString: \"\u03a0\" }));return 2; }}));");
/*fuzzSeed-244067732*/count=277; tryItOut("/*iii*//*tLoop*/for (let d of /*MARR*/[{}, {},  /x/ ,  /x/ , {x:3}, null, {x:3},  /x/ , null, {x:3}, null, {}, null,  /x/ , null, {}, {},  /x/ ,  /x/ , {x:3}, {}, {x:3}, {}, {x:3},  /x/ ,  /x/ ,  /x/ , {x:3},  /x/ , null]) { yield  '' ; }/*hhh*/function izqxxg(){if(true) {for (var v of v0) { m0 = new Map(m0); }print(x !== (this.__defineSetter__(\"b\", 21))); }}");
/*fuzzSeed-244067732*/count=278; tryItOut("v0 = this.g1.eval(\"function f0(o0)  { /*RXUB*/var r = r1; var s = o1.s2; print(s.replace(r, (function handlerFactory() {return {getOwnPropertyDescriptor: /*wrap2*/(function(){ \\\"use strict\\\"; var usyekf = allocationMarker()(); var tonspp = Array.from; return tonspp;})(), getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: undefined, delete: encodeURI, fix: function() { return []; }, has: undefined, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: undefined, }; }))); print(r.lastIndex);  } \");");
/*fuzzSeed-244067732*/count=279; tryItOut("Array.prototype.sort.call(a2, (function(j) { if (j) { try { /*ADP-3*/Object.defineProperty(a0, 16, { configurable: eval(\"([this]);\"), enumerable: (x % 4 != 2), writable: (x % 4 != 1), value: e1 }); } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } o0.h1.getPropertyDescriptor = f0; } else { try { a0[v0] = (((((x) = this))(x)) = x); } catch(e0) { } try { /*ODP-1*/Object.defineProperty(h2, \"atanh\", ({})); } catch(e1) { } this.v0 = (g2.i2 instanceof o2); } }), g0, g1, o0, m0);");
/*fuzzSeed-244067732*/count=280; tryItOut("\"use strict\"; print(f1);");
/*fuzzSeed-244067732*/count=281; tryItOut("/*vLoop*/for (let eotsjb = 0; eotsjb < 40; ++eotsjb) { let e = eotsjb; /*infloop*/for(y in (((4277))(false)))print(/*RXUE*/new RegExp(\"((?=(\\\\b)){511}(?=(?:\\\\S*))?)*?\", \"i\").exec(\"\")); } ");
/*fuzzSeed-244067732*/count=282; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.pow((mathy0(((mathy4((mathy4(Number.MAX_VALUE, Number.MIN_SAFE_INTEGER) >>> 0), y) % ( + ( ! (Math.atanh((x >>> 0)) >>> 0)))) | 0), (( + Math.tanh(( + y))) | 0)) | 0), Math.fround(mathy2(Math.sqrt(Math.asinh(Math.pow(x, x))), (Math.pow(mathy2((Math.fround((-1/0 | Math.fround(y))) | 0), (Math.expm1(1.7976931348623157e308) | 0)), (y >>> 0)) ^ Math.fround(Math.max(Math.fround(( + Math.cbrt(1/0))), Math.fround(Math.pow(Math.PI, x))))))))); }); testMathyFunction(mathy5, [0x080000001, 2**53, -0x0ffffffff, 0x100000000, -(2**53), -0x080000000, 0x07fffffff, -0x080000001, -0x100000000, -0, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, 1.7976931348623157e308, -(2**53-2), -Number.MAX_VALUE, -1/0, 0x100000001, Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -(2**53+2), 1, 0x080000000, 0/0, 0, -0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=283; tryItOut("with({}) throw y;");
/*fuzzSeed-244067732*/count=284; tryItOut("/*tLoop*/for (let x of /*MARR*/[ /x/g ,  /x/g ,  /x/g , -Infinity,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , -Infinity,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined()]) { var a = x;/* no regression tests found */ }");
/*fuzzSeed-244067732*/count=285; tryItOut("/*bLoop*/for (var tuooja = 0; tuooja < 16; ++tuooja) { if (tuooja % 2 == 0) { print(null); } else { print(()); }  } ");
/*fuzzSeed-244067732*/count=286; tryItOut("(makeFinalizeObserver('tenured')) | (4277) = a0[13];");
/*fuzzSeed-244067732*/count=287; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ! ( + ( ! ( + ( - (( + Math.hypot(Math.clz32((((y | 0) !== y) | 0)), Math.fround(Math.atan2(( - x), x)))) >>> 0)))))); }); testMathyFunction(mathy0, [0x100000001, 0x100000000, -Number.MAX_VALUE, 0/0, -(2**53), 1/0, 0x080000000, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, Math.PI, -(2**53-2), -(2**53+2), 2**53+2, -0x100000001, 0x080000001, 1, 0, -1/0, -0x080000001, 42, Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0x07fffffff, -0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=288; tryItOut("\"use strict\"; a0 = m0.get(f1);");
/*fuzzSeed-244067732*/count=289; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.min(mathy0((Math.sin(Math.fround(-Number.MIN_SAFE_INTEGER)) | 0), Math.fround(Math.atan2(Math.log(Math.imul(0x0ffffffff, y)), ( - Math.fround((( + ( + (( + x) << x))) > ( + x))))))), (( + mathy0(Math.fround(Math.sinh(Math.pow((Math.exp((x | 0)) | 0), Math.expm1(x)))), ( ~ ( + Number.MAX_SAFE_INTEGER)))) === x)) >= (Math.log(((mathy0(((Math.atanh((y <= (x | 0))) | 0) >>> 0), ((Math.asin(( + Math.asin((y >>> y)))) >>> 0) >>> 0)) >>> 0) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy1, [-0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000000, 42, 2**53-2, 0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, 0, -(2**53+2), 1, 2**53+2, 0.000000000000001, 1/0, Math.PI, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, 0x07fffffff, 2**53, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, -(2**53), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff, -0x100000001, 0x080000001, 0x080000000, 0x100000000]); ");
/*fuzzSeed-244067732*/count=290; tryItOut("/*oLoop*/for (var yaebkt = 0; (  === x) && yaebkt < 59; ++yaebkt) { g1.v1 = evaluate(\"function f0(s0)  { return false } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 == 1), noScriptRval: false, sourceIsLazy:  /x/g , catchTermination: false })); } ");
/*fuzzSeed-244067732*/count=291; tryItOut("f2(s2);");
/*fuzzSeed-244067732*/count=292; tryItOut("testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -(2**53+2), 42, -0x07fffffff, 0x080000000, -0x080000000, Math.PI, 0, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, 2**53, 0x07fffffff, Number.MAX_VALUE, 0x100000000, -(2**53-2), -0x100000001, -Number.MAX_VALUE, 0.000000000000001, -1/0, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 1, -0x100000000, 1/0, -0x080000001]); ");
/*fuzzSeed-244067732*/count=293; tryItOut("g2.o0 = new Object;this.o1.v0 = -0;");
/*fuzzSeed-244067732*/count=294; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ((((( + 2**53+2) >>> 0) && ( + Math.atan2(( + ( ~ Math.fround(-(2**53-2)))), ( + mathy1(Math.fround(( ~ (y | 0))), Math.asin(Math.fround(((x | 0) == (x | 0))))))))) >>> 0) ** ( ~ (((Math.ceil(Math.fround((Math.atan2(Math.acos(x), (Math.hypot(y, y) >>> 0)) >>> 0))) | 0) & Math.clz32((-0x080000001 >>> 0))) | 0))); }); testMathyFunction(mathy2, [-0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, Math.PI, -(2**53), -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), 0, -0x0ffffffff, -0x07fffffff, -0, 1/0, 0x07fffffff, 0x100000001, 42, 0/0, 0x080000001, -0x100000000, -1/0, -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 2**53+2]); ");
/*fuzzSeed-244067732*/count=295; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (-0x8000000);\n    {\n      d0 = (+(0.0/0.0));\n    }\n    {\n      {\n        {\n          d0 = (+pow(((+/*FFI*/ff(((((/*FFI*/ff(((d0)), ((((0x10fafa9d)) ^ ((0x48c0726a)))))|0)*0xafd6b) >> ((((0xa46d9b57))>>>((0xffffffff)+(0x558e1700))) / (((Int32ArrayView[2]))>>>((0xffffffff)+(0xf9dd1d87)+(0xeed4eeb4)))))), ((2097153.0)), ((((/*FFI*/ff(((16777217.0)), ((-1099511627777.0)), ((1.9342813113834067e+25)), ((0.0009765625)), ((3.777893186295716e+22)))|0)+((9.671406556917033e+24) != (65537.0))) | (((0x514f4a11) != (0x0))+(i1)))), ((~(((-(i1)))))), ((abs((((0x7ea8fa39)) >> ((0xa9042f78))))|0)), ((~(((0xffffffff))))), ((1099511627775.0)), ((-1.0)), ((-536870913.0)), ((-147573952589676410000.0)), ((-536870912.0)), ((-536870913.0)), ((1025.0))))), ((0.001953125))));\n        }\n      }\n    }\n    d0 = (((((Float64ArrayView[0])) * ((1.2089258196146292e+24)))) / ((9007199254740992.0)));\n    return +((d0));\n  }\n  return f; })(this, {ff: function (z, w)(4277)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [2**53, 0x0ffffffff, 2**53-2, -0x0ffffffff, 42, 0, Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 0/0, -Number.MIN_VALUE, -(2**53), 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -0x080000001, -Number.MAX_VALUE, 1, -(2**53-2), -0x100000000, 0x100000000, 1.7976931348623157e308, -0x100000001, -(2**53+2), -0, Number.MAX_VALUE, Math.PI, -1/0, 0x100000001]); ");
/*fuzzSeed-244067732*/count=296; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((/*FFI*/ff(((((1.0078125)) * (({caller: \"\\u7099\" })))), ((d0)), ((((((0x72e0a21)) | ((0xf8c59f9f))) / (((0x8b9c2b6f)) << ((0xcf4037dd)))) >> (((0x98722d9d) <= (0xc8bbcd6a))*0x6c19))), ((1.2089258196146292e+24)), (((((0x8bc8c98d))*0x7117d) | ((0xf90f6668)))))|0)*0xbdd74))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return false; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: z, keys: (function(y) { yield y; v2 = r2.sticky;; yield y; }).call, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 42, 1/0, 2**53+2, 1, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53), -(2**53-2), 0x080000001, -0, Number.MAX_VALUE, -0x100000001, 0x100000000, -Number.MIN_VALUE, -0x100000000, Math.PI, -0x080000001, -0x0ffffffff, 0/0, 0.000000000000001, 0, -0x080000000, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=297; tryItOut("mathy1 = (function(x, y) { return Math.hypot(Math.imul(mathy0(( + Math.min(( + Math.fround((Number.MAX_VALUE === ( + mathy0(( + (y % 1/0)), ( + -Number.MAX_SAFE_INTEGER)))))), (Math.atan2((2**53+2 >= x), x) | 0))), (y <= Math.fround(Math.trunc(( + ( - ( - x))))))), ( + Math.tanh(Math.trunc(Math.pow(( - ((( + -0x100000000) <= -(2**53-2)) | 0)), y))))), ( + ( + Math.exp((( + Math.acos(Math.round(( + Math.atan2(x, ( + x)))))) >>> 0))))); }); testMathyFunction(mathy1, [-0x080000001, Number.MAX_SAFE_INTEGER, 2**53, -(2**53), -Number.MIN_VALUE, 0x080000000, -(2**53+2), Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0, -0x100000000, -Number.MAX_VALUE, 1/0, 0x080000001, -(2**53-2), Number.MIN_VALUE, 42, -0x0ffffffff, -0x100000001, 0x0ffffffff, -0, 0x100000001, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, 2**53-2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, -0x07fffffff, 1.7976931348623157e308, 0/0, Math.PI]); ");
/*fuzzSeed-244067732*/count=298; tryItOut("v2 = true;");
/*fuzzSeed-244067732*/count=299; tryItOut("\"use strict\"; s1 += s0;");
/*fuzzSeed-244067732*/count=300; tryItOut("\"use strict\"; a0.pop(h2);");
/*fuzzSeed-244067732*/count=301; tryItOut("\"use strict\"; v1 = evalcx(\"(uneval(window ? w :  /x/ ))\", g1);");
/*fuzzSeed-244067732*/count=302; tryItOut("\"use strict\"; v0 = (b2 instanceof a0);");
/*fuzzSeed-244067732*/count=303; tryItOut("\"use asm\"; print(Math.acos(-13));");
/*fuzzSeed-244067732*/count=304; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0);");
/*fuzzSeed-244067732*/count=305; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-244067732*/count=306; tryItOut("zaarfx(x);/*hhh*/function zaarfx(x, z = true.eval(\"Math.hypot(-24, -1) >>= (void options('strict'))\"), ...z){Array.prototype.sort.apply(a2, [(function() { for (var j=0;j<8;++j) { f2(j%2==0); } })]);}");
/*fuzzSeed-244067732*/count=307; tryItOut("this.v0 = (this.e2 instanceof this.g2);");
/*fuzzSeed-244067732*/count=308; tryItOut("s2.toSource = /*wrap3*/(function(){ var ttxlmd = eval(\"x\", 0xB504F332); (function (this.e = ttxlmd, d)e = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: Math.acosh, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: (1 for (x in [])), getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; })(ttxlmd), (x.valueOf(\"number\"))))(); });");
/*fuzzSeed-244067732*/count=309; tryItOut("\"use strict\"; i1.valueOf = x = let (b) true.isFinite;");
/*fuzzSeed-244067732*/count=310; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.log1p((Math.fround((( ! (( - y) ? x : y)) ? Math.fround(( + Math.trunc(((( ~ (Math.fround(Math.min(( + y), (y >>> 0))) >>> 0)) >>> 0) | 0)))) : Math.log10(( ~ (( + Math.fround(( ! 2**53+2))) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy0, [0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000000, 2**53+2, -0x080000001, 2**53, Number.MAX_VALUE, 42, 0, -0, -0x07fffffff, -(2**53+2), 1, -(2**53-2), -Number.MAX_VALUE, 2**53-2, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -(2**53), -0x100000001, -1/0, 0/0, Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-244067732*/count=311; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Uint8ArrayView[4096]) = (((+(-1.0/0.0)) > (+((147573952589676410000.0))))-(((((((0xaa3902e1) ? (0xf8a75984) : (0xfe88422b))+(i0)) | ((0xff9434b6)-(0xffffffff)-(0x5c86d623))) % ((((0x73fc40ea))+(i0)) >> ((0xffffffff)+(0x3d94f1ec)-(-0x8000000))))|0) != (~~(8388609.0))));\n    return (((((((i1)-(-0x8000000))>>>((void  /x/g ))) >= (0x4c0c15df)) ? (/*FFI*/ff(((137438953472.0)), ((~~(-1125899906842624.0))), ((+(~~(+(1.0/0.0))))), ((+abs(((-9.0))))))|0) : ((+(-1.0/0.0)) >= (2305843009213694000.0)))-(i0)))|0;\n  }\n  return f; })(this, {ff: function(y) { return (4277) }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MAX_VALUE, 42, -0x080000001, 0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, -0x0ffffffff, 0/0, -0x100000000, -0x07fffffff, 2**53-2, -0, Math.PI, Number.MIN_VALUE, 1, 0x100000001, 1.7976931348623157e308, 0x100000000, -(2**53+2), 0x080000001, 2**53, -1/0, 2**53+2, -(2**53-2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-244067732*/count=312; tryItOut("\"use strict\"; e1.add(this.f0);let b = Math.min(/*UUV2*/(c.getFloat32 = c.floor).parse(delete eval.e) *= intern([1,,]), -2);");
/*fuzzSeed-244067732*/count=313; tryItOut("\"use asm\"; print((/\\B/ ? window :  '' ));");
/*fuzzSeed-244067732*/count=314; tryItOut("\"use strict\"; /*infloop*/for(var [x, [], []] = (delete c.y); SharedArrayBuffer(); null) {delete h1[\"2\"]; }");
/*fuzzSeed-244067732*/count=315; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.asinh(Math.fround(( + Math.fround(Math.hypot(Math.fround(( + ( + (x >>> 0)))), Math.fround((mathy0(Math.fround(x), Math.fround(Math.hypot(x, x))) >>> 0)))))))); }); testMathyFunction(mathy1, [-0x07fffffff, -(2**53), -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 2**53, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, 0, Number.MAX_VALUE, 2**53+2, Math.PI, -0x080000001, 1/0, -(2**53+2), 0x080000000, 0x100000000, 1.7976931348623157e308, 0/0, 42, 1, -Number.MIN_VALUE, -0x080000000, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, -0, 0x100000001, -0x100000000]); ");
/*fuzzSeed-244067732*/count=316; tryItOut("mathy4 = (function(x, y) { return (Math.exp((((((Math.asinh((((y >>> 0) * Math.fround(Math.pow(-Number.MAX_VALUE, 0x0ffffffff))) >>> 0)) >>> 0) << ( + Math.sinh(Math.fround(( ~ ( + x)))))) >>> 0) ? (( ~ (y >>> 0)) >>> 0) : ( + mathy3(((x >> y) | 0), mathy3(((1/0 >>> y) | 0), (((x | 0) | (y | 0)) | 0))))) | 0)) >>> 0); }); testMathyFunction(mathy4, [Math.PI, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -(2**53+2), -1/0, Number.MIN_VALUE, -0x080000000, 42, -0, 0x100000001, -(2**53-2), 2**53+2, -Number.MIN_SAFE_INTEGER, 1, 0/0, 2**53-2, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000001, 2**53, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, -0x100000001, 0, 0x080000001, -0x100000000, 1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=317; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.cbrt(Math.imul((Math.cos(-(2**53-2)) | 0), Math.cosh(Math.fround(Math.fround((Math.fround(y) ? (( - (x >>> 0)) >>> 0) : Math.fround((Math.tanh(-0x07fffffff) >>> 0)))))))); }); testMathyFunction(mathy2, [0x07fffffff, 0x100000000, 0/0, 1, 0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), -0, -0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000001, -(2**53+2), -0x080000001, 0x100000001, -0x100000000, 0, -0x080000000, 42, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, 2**53, 0.000000000000001, Math.PI, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=318; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((( ~ ((Math.fround(mathy0(Math.fround(x), (( + y) >>> 0))) >>> 0) === ( + Number.MIN_VALUE))) >>> 0) >>> ( + Math.min(( + ( ~ Math.log1p((x >>> 0)))), ( + Math.min((((mathy0(( + x), 0x0ffffffff) | 0) % Math.max(-0x07fffffff, y)) | 0), (( ~ (Math.atan2(Math.fround((y , y)), Math.asin(x)) >>> 0)) >>> 0)))))) | 0); }); testMathyFunction(mathy1, [-0x100000001, -0x07fffffff, Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, -1/0, Number.MIN_VALUE, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, 42, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 0x080000000, -(2**53), 0x080000001, 2**53, 0, -0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, -(2**53+2), -0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, 2**53+2, 1/0]); ");
/*fuzzSeed-244067732*/count=319; tryItOut("\"use strict\"; a1 = Array.prototype.filter.apply(a2, [(function mcc_() { var wdezun = 0; return function() { ++wdezun; f2(/*ICCD*/wdezun % 6 == 1);};})()]);");
/*fuzzSeed-244067732*/count=320; tryItOut("/*tLoop*/for (let a of /*MARR*/[function(){}, function(){}, function(){}, 0x99, 0x99, function(){}, 0x99, 0x99, function(){}, 0x99, function(){}, 0x99, 0x99, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, function(){}, 0x99, function(){}, function(){}, function(){}, function(){}, 0x99, function(){}, function(){}, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x99, 0x99, function(){}, 0x99, function(){}, 0x99, 0x99, function(){}, 0x99, 0x99, function(){}, 0x99, 0x99, function(){}, function(){}, function(){}, function(){}, 0x99, function(){}, function(){}, 0x99, 0x99, function(){}, function(){}, function(){}, 0x99, 0x99, 0x99, function(){}, 0x99, 0x99, function(){}, 0x99, 0x99, 0x99, 0x99, 0x99, function(){}, function(){}, function(){}, 0x99, 0x99, function(){}, function(){}, 0x99, 0x99, 0x99, 0x99, 0x99, function(){}, 0x99, 0x99, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}]) { return true; }");
/*fuzzSeed-244067732*/count=321; tryItOut("( '' );");
/*fuzzSeed-244067732*/count=322; tryItOut("testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), (new Boolean(true)), (new Number(-0)), [0], '0', null, /0/, -0, undefined, '', (new String('')), ({valueOf:function(){return '0';}}), (function(){return 0;}), NaN, [], '\\0', 0.1, true, objectEmulatingUndefined(), false, 0, ({toString:function(){return '0';}}), '/0/', 1, (new Number(0)), (new Boolean(false))]); ");
/*fuzzSeed-244067732*/count=323; tryItOut("v0 = new Number(a1);");
/*fuzzSeed-244067732*/count=324; tryItOut("var \u3056;h2.getPropertyDescriptor = g2.f0;");
/*fuzzSeed-244067732*/count=325; tryItOut("mathy1 = (function(x, y) { return (Math.asinh((4277)) >= Math.asinh(Math.clz32(( + ( + Math.pow(( + Math.trunc(y)), ( + 2**53-2))))))); }); testMathyFunction(mathy1, [-0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, Number.MIN_SAFE_INTEGER, 1, Math.PI, -(2**53-2), -(2**53+2), -Number.MAX_VALUE, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 42, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 0/0, 0x07fffffff, 0.000000000000001, 0x0ffffffff, -1/0, -0x100000000, 0, 0x080000001, 1.7976931348623157e308, 2**53+2, 2**53-2, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=326; tryItOut("\"use strict\"; r0 = new RegExp(\"(?:(?:(?!\\\\3)+?))\", \"gim\");function b(\"0\" = (([,].x).watch(-10, WeakSet.prototype.add))) { yield \u3056 = (a = /(\\1*)/y) } m1.delete(v1);");
/*fuzzSeed-244067732*/count=327; tryItOut("/*RXUB*/var r = /\\3|\\b(?:(?=\\B))*?|[^]{1}|^.[\u92f0]+[^]|(?:$\\b|(?=\\W)?(?=$)\\S*)|(?:^{2,})+?/gy; var s = \"\\u3026\\ub5a0\\u3026\\ub5a0\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=328; tryItOut("\"use strict\"; let(new (WeakSet.prototype.delete)() = \"\\uD24E\", nduwno, x, [] = (new RegExp(\"\\\\b(\\n).\\\\D?\\u79d9|(\\\\b).|\\\\d?+\", \"yi\") >>> \"\\u8B1E\"), window =  /x/g , x) { throw a;}return;");
/*fuzzSeed-244067732*/count=329; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((( ! x) >> (( - y) | 0)) ? Math.atan2((( - y) != y), x) : ( ~ (-Number.MIN_SAFE_INTEGER ? 2**53+2 : (-(2**53) << y)))) ? (Math.asinh(mathy1(y, Math.log1p(x))) || ( + mathy1(Math.fround(Math.atan2(Math.fround((y ? ( ! x) : Math.fround(Math.max(Math.fround(x), 1.7976931348623157e308)))), Math.fround(x))), ( + ( - ( + ( ~ y))))))) : Math.fround(((( ~ ((Math.fround((y ? 1/0 : -0x0ffffffff)) || Math.fround(y)) >>> 0)) % y) >> Math.fround(( ~ Math.max(Math.trunc(Math.fround(( ! (y | 0)))), (y >> ( - y)))))))); }); testMathyFunction(mathy3, [-(2**53-2), 0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -0, 0x080000001, 1, 1.7976931348623157e308, Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, 2**53+2, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, Number.MAX_VALUE, -0x080000000, 42, -Number.MIN_VALUE, -0x080000001, 1/0, -0x100000000, 0x100000001, 0, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff, -1/0, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=330; tryItOut("testMathyFunction(mathy4, [0x07fffffff, -0x100000001, 0, -(2**53-2), 2**53, -0x080000000, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), -(2**53+2), -Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, 0x080000000, 2**53+2, -1/0, Math.PI, -0x080000001, 1/0, -0x100000000, -0, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, 0/0]); ");
/*fuzzSeed-244067732*/count=331; tryItOut("m0.toString = (function() { try { this.s2 = new String; } catch(e0) { } try { g1.h2.enumerate = (function(j) { if (j) { try { Array.prototype.forEach.apply(this.a1, [(function() { try { g0.a0 = Array.prototype.concat.call(a1, a0, t2, t1, this.t2, a0); } catch(e0) { } try { b1 = t1.buffer; } catch(e1) { } a0 = r2.exec(this.o0.s0); return o1.t2; }), t1, o2]); } catch(e0) { } try { b1.toSource = (function() { try { o0 = new Object; } catch(e0) { } try { g1.m2.has(s0); } catch(e1) { } try { i1.next(); } catch(e2) { } v0 = new Number(0); return m1; }); } catch(e1) { } try { s1.toString = (function() { try { a0.length = 11; } catch(e0) { } for (var v of e1) { try { v0 = evaluate(\" '' \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: [,,z1], noScriptRval: (x % 41 == 23), sourceIsLazy: true, catchTermination: (x % 96 == 17) })); } catch(e0) { } try { i0.next(); } catch(e1) { } try { for (var p in v1) { try { f1 = Proxy.createFunction(h0, f1, f1); } catch(e0) { } try { x = g2; } catch(e1) { } try { delete h0.has; } catch(e2) { } for (var v of f1) { try { a2.forEach((function() { try { this.v0 = Array.prototype.every.call(a2, (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -0.25;\n    var i3 = 0;\n    d1 = (d2);\n    return +((-16384.0));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; selectforgc(o0); }}, new ArrayBuffer(4096)), m1); } catch(e0) { } t1[window]; return p2; }), v1); } catch(e0) { } try { /*MXX3*/g2.g1.String.prototype.toLocaleLowerCase = g1.String.prototype.toLocaleLowerCase; } catch(e1) { } /*ODP-2*/Object.defineProperty(t2, \"caller\", { configurable: (x % 3 == 1), enumerable: false, get: (function() { try { this.a2.shift(); } catch(e0) { } try { e1.delete(e2); } catch(e1) { } i0 = new Iterator(o0.i2); return f0; }), set: (function() { try { g2.o1.a2 = a0.filter((function() { try { a0.reverse(); } catch(e0) { } try { for (var p in g1) { Array.prototype.sort.call(g1.a0, f1); } } catch(e1) { } v2 = g0.runOffThreadScript(); return p1; }), s1); } catch(e0) { } try { v0 = this.g1.eval(\"print(new RegExp(\\\"(?![^\\\\\\\\\\\\u84cf\\\\\\\\s\\\\\\\\uDBD8\\\\\\\\r])?\\\", \\\"\\\"));\"); } catch(e1) { } try { /*RXUB*/var r = r0; var s = \"\\u00a4\\u00e5\\u00e5\\u00e5\\n\\u00e5\\u00e5\\u00e5\\n\"; print(r.exec(s));  } catch(e2) { } for (var p in v1) { try { a1.forEach((function(j) { if (j) { a0.shift(o2, g1, m1); } else { try { m1.delete(o2); } catch(e0) { } f1 + ''; } })); } catch(e0) { } try { this.i2.send(a2); } catch(e1) { } try { i1 + p1; } catch(e2) { } a1 = new Array; } return f2; }) }); } } } catch(e2) { } f2(v2); } return o1; }); } catch(e2) { } print(p2); } else { try { /*MXX2*/g0.EvalError.prototype.toString = m2; } catch(e0) { } e1.__iterator__ = (function() { o2.o2.f1.__proto__ = o1; return o2; }); } }); } catch(e1) { } try { g1.offThreadCompileScript(\"h0.has = (function() { try { a1 + h2; } catch(e0) { } try { f0 + ''; } catch(e1) { } a2 = /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, x, 0.1, function(){}, 0.1, x, x, function(){}, function(){}, function(){}, function(){}, 0.1, x, function(){}, function(){},  /x/ , function(){}, x, function(){}, function(){}, function(){}, 0.1, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, x, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, x, function(){}, x, function(){}, function(){},  /x/ , x, 0.1, x, x, x, x, function(){},  /x/ , 0.1, x, 0.1, x, 0.1, x, 0.1, function(){}, function(){}, function(){}, x, x, 0.1,  /x/ , x,  /x/ , x,  /x/ ,  /x/ , function(){},  /x/ ,  /x/ , 0.1, x, function(){}]; return b1; });\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 19 == 4), noScriptRval:  /* Comment */x, sourceIsLazy: true, catchTermination: (x % 3 == 1) })); } catch(e2) { } Object.prototype.watch.call(h1, \"map\", (function() { for (var j=0;j<12;++j) { f0(j%2==1); } })); return this.o1.f2; });");
/*fuzzSeed-244067732*/count=332; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x080000000, -(2**53-2), -1/0, -(2**53+2), 0x080000000, 0.000000000000001, -0x07fffffff, 0x080000001, Number.MAX_VALUE, 0, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, -0, 2**53+2, -0x100000000, -(2**53), -Number.MAX_VALUE, 0/0, Math.PI, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 1]); ");
/*fuzzSeed-244067732*/count=333; tryItOut("/*tLoop*/for (let b of /*MARR*/[new Number(1), [],  'A' ,  'A' , [],  'A' ,  'A' , new Number(1),  'A' ,  'A' ,  'A' , [], new Number(1), new Number(1),  'A' ,  'A' , new Number(1), [],  'A' , [], [],  'A' , new Number(1), [], [], new Number(1),  'A' ,  'A' ,  'A' , new Number(1), [],  'A' , new Number(1),  'A' ,  'A' ,  'A' , new Number(1), [], [], [],  'A' ,  'A' , [],  'A' ,  'A' , [], [], [], [], [], [], [], [], [], [], new Number(1), [], new Number(1), [], [], new Number(1),  'A' , new Number(1), [], [],  'A' , [], [],  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , new Number(1), new Number(1), [], [], [], [], [], [], [], [],  'A' ,  'A' ,  'A' , [], new Number(1), new Number(1), new Number(1), new Number(1), [],  'A' ,  'A' , new Number(1), [], [],  'A' , [], [],  'A' ,  'A' , new Number(1), new Number(1), [],  'A' ,  'A' , new Number(1), new Number(1),  'A' ,  'A' ,  'A' ,  'A' , [], new Number(1), new Number(1), [], [],  'A' , new Number(1), [],  'A' , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), [],  'A' ,  'A' ]) { g2.m0.set(o0, b0); }");
/*fuzzSeed-244067732*/count=334; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=335; tryItOut("this.o1.e0.add(o0);");
/*fuzzSeed-244067732*/count=336; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h1, g1.a2);");
/*fuzzSeed-244067732*/count=337; tryItOut("mathy5 = (function(x, y) { return (((Math.ceil((( - (y | 0)) >>> 0)) >>> 0) ? (mathy1(Math.sin(Math.fround(Math.acos(Math.hypot(x, y)))), Math.cos(( + Math.ceil(( + x))))) | 0) : (( ~ Math.hypot((Math.atan2(-0x100000000, y) === (y | 0)), (( + Math.atan2(( + (Math.sqrt(x) == y)), ( + y))) | 0))) | 0)) | 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x100000001, -0x080000000, 0.000000000000001, 42, -0, -1/0, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 0x0ffffffff, 0/0, 0x080000001, 1/0, Math.PI, 2**53-2, -(2**53+2), 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -0x100000000, -0x07fffffff, -0x080000001, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, Number.MIN_VALUE, 1, -(2**53), 0, -Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-244067732*/count=338; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((+(((((abs((imul((0xffffffff), (-0x8000000))|0))|0) >= (((0x5dadd8b9)) >> ((0xf9db444e)))) ? (0xf82e8804) : ((((0x95e30f4)-(0xfc3dd4fa)+(0xec4e9709)) ^ ((0x100e15f9)+(0xfaf5580e)+(-0x8000000))))))>>>((-0x8000000)*-0xe608d))));\n    return +((d0));\n    d1 = (d0);\n    d1 = (+abs(((d1))));\n    {\n      d0 = (d1);\n    }\n    d0 = (+((Infinity)));\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: function(y) { return \"\u03a0\" }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53-2, 0x100000001, 1, -(2**53+2), -Number.MAX_VALUE, -0x100000001, -1/0, 0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 1.7976931348623157e308, -(2**53), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, Number.MIN_VALUE, 0x100000000, 0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53, 1/0, 0, 0x07fffffff, Math.PI, -Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, 42]); ");
/*fuzzSeed-244067732*/count=339; tryItOut("mathy3 = (function(x, y) { return (( + ( + ( + ( + (( ! (Math.pow(x, Number.MAX_SAFE_INTEGER) | 0)) | 0))))) == ((Math.acos(Math.min(y, ( + Math.atan2(( + ((Math.max(Math.fround(x), (x | 0)) | 0) !== x)), x)))) >= ((( + Math.imul(mathy0(y, x), (Math.fround((y | 0)) || ( + Math.atan2(( + y), ( + y)))))) , (Math.atan2(x, y) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [(new Boolean(false)), (new Number(0)), '/0/', objectEmulatingUndefined(), ({toString:function(){return '0';}}), NaN, '\\0', -0, (new Boolean(true)), null, '', '0', ({valueOf:function(){return 0;}}), 1, (function(){return 0;}), [0], [], undefined, (new Number(-0)), 0, /0/, ({valueOf:function(){return '0';}}), 0.1, true, false, (new String(''))]); ");
/*fuzzSeed-244067732*/count=340; tryItOut("mathy2 = (function(x, y) { return ((( + (Math.asin(x) | 0)) | 0) ? (Math.pow((((y | 0) >> (Math.min(( - ((y >= ( + 2**53)) >>> 0)), (Math.min((( + Math.log10(Math.fround(-0x07fffffff))) >>> 0), ((Math.tanh(( + y)) < 42) >>> 0)) | 0)) | 0)) | 0), ( + Math.imul((( - x) !== mathy1(y, x)), Math.fround(Math.imul(Math.atanh(x), ( + ( + (Math.fround(1) >>> ( + Math.min(x, x)))))))))) >>> 0) : ( ~ ((( - (Math.fround(Math.pow((1 ? y : ( + 2**53)), y)) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy2, [-0x100000001, 0, -(2**53), Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, -1/0, 2**53-2, 0x100000000, Number.MAX_VALUE, 42, -Number.MIN_VALUE, 1, Math.PI, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, Number.MIN_VALUE, 1/0, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, 0/0, 0.000000000000001, -0x07fffffff, -0, -0x080000001, -(2**53-2), -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=341; tryItOut("\"use strict\"; testMathyFunction(mathy2, ['0', (new Boolean(false)), objectEmulatingUndefined(), undefined, (new Boolean(true)), '\\0', [0], (new Number(-0)), true, (new String('')), (new Number(0)), false, null, ({valueOf:function(){return 0;}}), '', 0, (function(){return 0;}), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), '/0/', -0, /0/, 1, 0.1, [], NaN]); ");
/*fuzzSeed-244067732*/count=342; tryItOut("mathy4 = (function(x, y) { return ( ~ Math.max((((( - y) | 0) != (0x080000000 | 0)) | 0), (Math.sinh(((Math.hypot(Math.fround(((( + Math.min(x, x)) && mathy1(y, x)) >>> 0)), Math.fround(( ! ((x % x) | 0)))) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, ['/0/', (new Boolean(false)), 1, [], (new String('')), NaN, objectEmulatingUndefined(), (new Number(0)), false, ({valueOf:function(){return 0;}}), 0.1, -0, [0], undefined, ({valueOf:function(){return '0';}}), (new Number(-0)), /0/, '\\0', null, 0, (new Boolean(true)), ({toString:function(){return '0';}}), '', true, '0', (function(){return 0;})]); ");
/*fuzzSeed-244067732*/count=343; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((( + (Math.log2(Math.fround(((y | 0) < ( + ((x >>> 0) === ( + ( ! y))))))) >>> 0)) | 0) | (Math.hypot(Math.fround((((x | 0) ? ( - 1.7976931348623157e308) : mathy0((Math.min(2**53+2, 0x0ffffffff) >>> 0), Math.asin(Math.fround(( + y))))) | 0)), (Math.fround((((((Math.abs(Math.log(y)) && (x !== x)) ? ( + Math.fround(mathy0(y, x))) : Math.fround(( - Math.fround(( ! Math.cos(x)))))) >>> 0) | 0) ? x : Math.fround(mathy0(Math.fround(-Number.MAX_SAFE_INTEGER), Math.fround(( - x)))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [1.7976931348623157e308, -Number.MIN_VALUE, -(2**53-2), 1/0, -(2**53+2), Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, 42, Math.PI, 0x100000000, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, 0/0, 2**53-2, -0x100000000, -0x080000001, 0x080000001, 0.000000000000001, -0x07fffffff, -0x100000001, -0, -0x0ffffffff, 1, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=344; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=345; tryItOut("\"use strict\"; with(x){/*RXUB*/var r = /(?:([\\s\\n-\\f]+?(?=[^])|(?!(?:[^]*{3,6}))|^|\\B{1}*?))/im; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.search(r));  }");
/*fuzzSeed-244067732*/count=346; tryItOut("M:if(false) a2[17] = this.m2;\n27;\n else  if ( '' ) {for (var v of h0) { try { o2.a2 + e2; } catch(e0) { } /*ADP-2*/Object.defineProperty(a2, length, { configurable: (x % 42 == 10), enumerable: true, get: (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((1099511627777.0));\n  }\n  return f; }), set: (function() { try { e2.add(g2); } catch(e0) { } f2 = Proxy.create(h1, m1); throw p2; }) }); } } else var muktaw = new ArrayBuffer(8); var muktaw_0 = new Uint8ClampedArray(muktaw); print(muktaw_0[0]); print([z1]);");
/*fuzzSeed-244067732*/count=347; tryItOut("i1.next();");
/*fuzzSeed-244067732*/count=348; tryItOut("Object.defineProperty(this, \"s1\", { configurable: false, enumerable: ({/*toXFun*/valueOf: function() { return delete y.window; } }),  get: function() {  return new String(v0); } });");
/*fuzzSeed-244067732*/count=349; tryItOut("\"use strict\"; /*bLoop*/for (ittdag = 0, yvlqhy; ittdag < 43; ++ittdag) { if (ittdag % 15 == 7) { g1.s2 += s1; } else { /*RXUB*/var r = r0; var s = \"\"; print(s.split(r));  }  } ");
/*fuzzSeed-244067732*/count=350; tryItOut("\"use strict\"; t2[7] = a0;");
/*fuzzSeed-244067732*/count=351; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.asin((( ~ ( - 0x100000000)) / Math.min(((y < ( + ( ! ( + y)))) | 0), ( + Math.sign(0))))) >>> 0); }); testMathyFunction(mathy0, [2**53+2, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_VALUE, 0/0, 0x080000001, Number.MIN_VALUE, -1/0, 0x100000001, -0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 42, Number.MAX_VALUE, 2**53, Math.PI, -0, -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, 0, -(2**53), -(2**53+2), -0x100000000, -0x080000000, -0x100000001, -0x07fffffff, 0x100000000, 0x0ffffffff, 1/0]); ");
/*fuzzSeed-244067732*/count=352; tryItOut("\"use strict\"; v0 = a2.length;");
/*fuzzSeed-244067732*/count=353; tryItOut("Array.prototype.reverse.apply(a2, [e0]);");
/*fuzzSeed-244067732*/count=354; tryItOut(";");
/*fuzzSeed-244067732*/count=355; tryItOut("\"use strict\"; g0.v2 = (o0 instanceof a0);");
/*fuzzSeed-244067732*/count=356; tryItOut("\"use strict\"; a1 = o2.a1.concat(this.t1, h2, i0, f0, i0, m0, (4277));");
/*fuzzSeed-244067732*/count=357; tryItOut("mathy3 = (function(x, y) { return ( - Math.fround((( - ((((y ? (x >>> 0) : (y >>> 0)) >>> 0) / Math.min(0.000000000000001, x)) | 0)) >= ( ~ ( + (( - ((( + (x >> Math.PI)) ? 0x07fffffff : ( + (y <= y))) | 0)) >>> 0)))))); }); testMathyFunction(mathy3, [-(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -Number.MIN_VALUE, -0, 0, 2**53+2, -0x080000001, 0x100000001, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_VALUE, -0x100000001, Math.PI, 0.000000000000001, -0x0ffffffff, 0/0, Number.MAX_VALUE, 42, 2**53-2, 0x080000000, -1/0, 0x07fffffff, -0x100000000, 1, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), 1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, -0x080000000]); ");
/*fuzzSeed-244067732*/count=358; tryItOut("\"use strict\"; i2.toString = (function(j) { if (j) { try { m0.delete(f0); } catch(e0) { } try { Array.prototype.unshift.apply(o2.a2, [m0]); } catch(e1) { } try { for (var p in p0) { try { s2 = Array.prototype.join.apply(a1, [s1]); } catch(e0) { } try { m0 = x; } catch(e1) { } ; } } catch(e2) { } t1 + ''; } else { g0.offThreadCompileScript(\"function g0.f0(g1.s2)  { yield (g1.s2 = x) } \", ({ global: this.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: false, sourceIsLazy: (void options('strict_mode')).__defineSetter__(\"x\", (function(y) { return window }).call), catchTermination: true })); } });");
/*fuzzSeed-244067732*/count=359; tryItOut("mathy2 = (function(x, y) { return ((Math.log2(( + ( - (x ? (Math.sign(((mathy0((0x080000001 >>> 0), (-0 | 0)) >>> 0) >>> 0)) >>> 0) : ( + (((y | 0) * (-0 | 0)) | 0)))))) ^ (((Math.pow((Math.log2(y) >>> 0), ((((Math.exp(Math.PI) >>> 0) , (( - y) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0) ? (Math.max(((( ! ( + x)) >>> 0) | 0), (( - -Number.MAX_SAFE_INTEGER) | 0)) | 0) : ((( + (Math.max(y, y) >>> 0)) >>> 0) >>> 0))) | 0); }); testMathyFunction(mathy2, [0.000000000000001, 2**53+2, 2**53-2, 0x0ffffffff, 1.7976931348623157e308, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, 0x080000000, -Number.MIN_VALUE, -0, -0x100000001, -0x0ffffffff, 0, -(2**53), Math.PI, 0x07fffffff, -1/0, -0x07fffffff, 1, 42, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -(2**53-2), -0x080000000, -0x100000000, 0x100000000]); ");
/*fuzzSeed-244067732*/count=360; tryItOut("/*MXX1*/o2 = g1.g0.URIError.name;\n/*infloop*/for(let x in /*FARR*/[window, -0,  '' ,  '' ].map) {print(x);v1 = Array.prototype.some.apply(o0.a1, [a0, p2]); }\n");
/*fuzzSeed-244067732*/count=361; tryItOut("with((/[\\u0003-\\u9f9e\\u00c0]|\\S|$?\\2|(?=\\D[^])+|\\B|(?![^])|\u00f0*\\2|\\2*?*{3}/m))/*oLoop*/for (var wvbjdy = 0; wvbjdy < 5; ++wvbjdy) { g0.offThreadCompileScript(\"function g2.f0(f1)  { yield false } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /\\2\\2|\uacca+?|(?!(^[\\D\\s])|.|\\D*)?/ym, noScriptRval: true, sourceIsLazy: (x % 59 != 14), catchTermination: true })); } ");
/*fuzzSeed-244067732*/count=362; tryItOut("/*RXUB*/var r = r1; var s = s0; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=363; tryItOut("/*tLoop*/for (let c of /*MARR*/[window, window, (0/0), (0/0), (0/0), window, new String('q'),  \"use strict\" ,  \"use strict\" , (0/0), (0/0), (0/0), (0/0), ['z'], ['z'], ['z'], new String('q')]) { v1 = g2.runOffThreadScript(); }");
/*fuzzSeed-244067732*/count=364; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    {\n      (Int32ArrayView[0]) = ((0xad6ab249)+(i0));\n    }\n    d1 = (-590295810358705700000.0);\n    return (((Uint16ArrayView[1])))|0;\n  }\n  return f; })(this, {ff: function  x (z, e = x, x, d, window, x, w, d, a, window = null, w, c, y, this, x, e, of, NaN, x, setter, x = x, a, b, x, x = /((?:[^])?|[^]^.|\\u00b8{1,5}|\\B\\B)*(?:\\S)\\b|(?=\\f*?)/y, x, x, NaN, z, b, window = 17, w, window, NaN, x, y, y, x, x = /\\s*(?:\\b)\u649e+(?!\\B){524289,}/gm, w, b, c = window, b =  /x/ , a, x = \"\\u759A\", x = window, e, window, x, b, NaN, c = this, x, z, x, x, x = function ([y]) { }, eval, x = 10, NaN, x = /(?!${2,})$|$|\\D?{1,5}/im, x = null, NaN, y, x, x, x, z, d, a, x =  '' , \u3056 = window, x, c, y =  \"\" , w = x, NaN, w = false, x)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((i2)-(i2)))|0;\n  }\n  return f;}, new ArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=365; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.pow((mathy0(mathy0(Math.fround(Math.max(Math.fround(y), Math.fround(y))), (Math.clz32(((Math.sinh((( - y) | 0)) | 0) | 0)) | 0)), Math.imul((Math.cbrt((y | 0)) | 0), ( + ( ~ x)))) | 0), Math.fround(Math.tan(( + (((((Math.min((y | 0), (x | 0)) | 0) | 0) >= (y | 0)) && ( ~ (( ! y) === Math.fround(x)))) | 0))))) | 0); }); testMathyFunction(mathy1, [-0x080000000, 0, 0/0, Number.MIN_VALUE, 0x07fffffff, 42, 0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0.000000000000001, 0x100000001, -0x080000001, -0x100000000, Number.MAX_VALUE, -1/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 0x080000001, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, 0x100000000, 2**53-2, -0x100000001, 2**53+2]); ");
/*fuzzSeed-244067732*/count=366; tryItOut("\"use strict\"; a0 = arguments.callee.caller.arguments;");
/*fuzzSeed-244067732*/count=367; tryItOut("o2.v2 = g1.eval(\"a0.sort((function mcc_() { var oyawdd = 0; return function() { ++oyawdd; f1(/*ICCD*/oyawdd % 11 == 3);};})(), o0);\");");
/*fuzzSeed-244067732*/count=368; tryItOut("/*tLoop*/for (let e of /*MARR*/[(0/0), (0/0), 0x080000000, (0/0), NaN, 0x080000000, (0/0), ({x:3}), NaN, (0/0), (0/0), (0/0), 0x080000000, NaN, NaN, ({x:3})]) { /*infloop*/while(e.__defineSetter__(\"a\", Array.prototype.fill)){/*infloop*/for(d = window; this; \"\\uA461\") /(?=.\\cY*)/y; } }");
/*fuzzSeed-244067732*/count=369; tryItOut("m1.get(m2);");
/*fuzzSeed-244067732*/count=370; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((((( + ( + (( + Number.MAX_VALUE) ** ( + Math.max(( + ( + (x < y))), Math.fround(Math.pow((y | 0), (y | 0)))))))) >= ( + (( + (Math.max(mathy2(Math.clz32(( + ( + ( + x)))), x), -1/0) | 0)) | 0))) >>> 0) >>> 0) == Math.fround(Math.fround((( + ( - ( + (x >>> Math.hypot(Math.PI, (( + y) ? 0x0ffffffff : y)))))) ? (( + (Math.fround(Math.sqrt(Math.atan2(x, (( + (x | 0)) | 0)))) | 0)) >>> 0) : (Math.abs((Math.fround(Math.pow(Math.fround(( - (Math.atan2((( + y) | 0), Math.fround(x)) | 0))), Math.fround(Math.atan(x)))) >>> 0)) | 0))))) >>> 0); }); testMathyFunction(mathy3, [1/0, -0x080000000, Number.MAX_VALUE, 0x100000000, -0x100000000, 0/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, Math.PI, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, 0, 0x07fffffff, 2**53-2, -0, 1, -(2**53-2), 0x080000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 42, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 2**53, -(2**53), -1/0]); ");
/*fuzzSeed-244067732*/count=371; tryItOut("s1 += 'x';");
/*fuzzSeed-244067732*/count=372; tryItOut("var this.v2 = o2.g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-244067732*/count=373; tryItOut("a0[\n((p={}, (p.z = -18)()))] = p0;");
/*fuzzSeed-244067732*/count=374; tryItOut("/*oLoop*/for (var bdqhac = 0; bdqhac < 14; ++bdqhac, new RegExp(\"\\\\1\", \"im\")) { a0.shift(); } ");
/*fuzzSeed-244067732*/count=375; tryItOut("testMathyFunction(mathy0, /*MARR*/[[1], [1],  'A' ,  'A' , 5.0000000000000000000000, null, [1], null, null, [1],  'A' , [1], false, [1], false, 5.0000000000000000000000, [1], 5.0000000000000000000000,  'A' , false, false, null, [1],  'A' ]); ");
/*fuzzSeed-244067732*/count=376; tryItOut("\"use strict\"; \"use asm\"; t0 = t2.subarray(v1);");
/*fuzzSeed-244067732*/count=377; tryItOut("this.m0.has(b1);");
/*fuzzSeed-244067732*/count=378; tryItOut("for (var v of v2) { try { v2 = Array.prototype.reduce, reduceRight.apply(g0.g1.a0, [(function(j) { f0(j); }), g0, a1, this.t0]); } catch(e0) { } h0.defineProperty = (Promise.resolve).bind(); }");
/*fuzzSeed-244067732*/count=379; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(^){2}\", \"yim\"); var s = \"\\n\\n\\n\"; print(s.replace(r, '')); ");
/*fuzzSeed-244067732*/count=380; tryItOut("{ void 0; disableSPSProfiling(); } print(\"\\u9D7F\");");
/*fuzzSeed-244067732*/count=381; tryItOut("\"use strict\"; h1 = {};");
/*fuzzSeed-244067732*/count=382; tryItOut("/*tLoop*/for (let y of /*MARR*/[2**53-2, [1], [1], [1], [1], [1], [1], 2**53-2]) { switch((Math.asin((new Date.prototype.valueOf())))) { case 6: break; break; break; break; case 0: Object.defineProperty(this, \"o1.v0\", { configurable: (y % 9 == 4), enumerable: z === x,  get: function() {  return g0.runOffThreadScript(); } });o1.v0 = g0.eval(\"/*ODP-3*/Object.defineProperty(g0.i1, \\\"parse\\\", { configurable:  \\\"\\\" , enumerable: new Float64Array(), writable: timeout(1800), value: this.a2 });\");break; default: {; }case ((new \"\\u0045\"()).throw(Math.cbrt(/(?=Q+|(\\d|(.))|(?:(?=\\w)$?))|\\w|(?=[^]|[^\\w]|\\s[^])+/gyim))): print(y);break; break; case 3: g1.s2 = new String;case 5: break; case 1: break; new RegExp(\"\\\\u6815((?=(?:$)))*|((?!\\\\s|\\\\d))|(?=^)|(?:$)*?|\\\\d\\uc7f8[^]+?(?:[^])+\", \"gim\") ^ window;case 3: break;  } }");
/*fuzzSeed-244067732*/count=383; tryItOut("Object.prototype.unwatch.call(i1, \"callee\");");
/*fuzzSeed-244067732*/count=384; tryItOut("a1 = arguments;");
/*fuzzSeed-244067732*/count=385; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + mathy2(( + Math.fround(Math.expm1(Math.fround((mathy3(Math.tanh((y >>> 0)), ( - (x >>> 0))) >>> 0))))), Math.pow(Math.fround(( ! (Math.log2(x) >>> 0))), (( + ( ~ ( + Math.sqrt(( + Math.max((Number.MAX_VALUE | 0), (Math.fround(( - y)) | 0))))))) ? ( + ( - ( + -(2**53)))) : ( + (Math.asinh((Math.fround(( - y)) | 0)) >>> 0)))))); }); testMathyFunction(mathy4, [2**53-2, 0x080000001, -(2**53-2), 0/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, -0x100000001, 0, -0x07fffffff, 0x07fffffff, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, 2**53+2, 0x100000001, -0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000, 0.000000000000001, -(2**53), 1/0, 0x080000000, 42, 1]); ");
/*fuzzSeed-244067732*/count=386; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return mathy1(( + (Math.tan((( + ( + ( + (Math.fround(Math.max(Math.fround(x), Math.fround(-Number.MIN_SAFE_INTEGER))) >>> y)))) | 0)) | 0)), ( + ( - ((Math.imul(x, Math.fround(mathy0(Math.fround(( + (( + Math.clz32(x)) | ( + ((-0x0ffffffff << Number.MAX_SAFE_INTEGER) >>> 0))))), Math.fround(( ! y))))) | 0) | 0)))); }); testMathyFunction(mathy2, [2**53, -0x0ffffffff, Number.MIN_VALUE, 0, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, -0x080000001, -1/0, 0x100000000, -0x100000000, -(2**53), -0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, -0x07fffffff, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, 0x0ffffffff, 42, 0x07fffffff, 0x100000001, 2**53-2, 1, Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=387; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(m1, g2.s0);");
/*fuzzSeed-244067732*/count=388; tryItOut("v2 = t0.length;");
/*fuzzSeed-244067732*/count=389; tryItOut("mathy5 = (function(x, y) { return ( - (Math.min(((((((0 && 0x080000000) >>> 0) | 0) / (Math.atan2(y, x) / Math.fround(( - Math.fround(-(2**53-2)))))) >= y) | 0), (((y ** y) | 0) | 0)) | 0)); }); testMathyFunction(mathy5, [0.1, (new Number(0)), ({toString:function(){return '0';}}), '0', ({valueOf:function(){return '0';}}), (new Boolean(true)), (new String('')), (new Boolean(false)), '\\0', /0/, '/0/', null, undefined, (function(){return 0;}), [0], -0, 1, (new Number(-0)), 0, [], false, '', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), NaN, true]); ");
/*fuzzSeed-244067732*/count=390; tryItOut("Array.prototype.shift.apply(o2.a2, [o1.h2]);");
/*fuzzSeed-244067732*/count=391; tryItOut("mathy4 = (function(x, y) { return Math.fround(mathy1(Math.fround(Math.imul(Math.fround(( + (x | 0))), Math.fround(( + Math.cbrt(Math.ceil(Math.fround((mathy3(y, x) / y)))))))), Math.fround(( + Math.atan2((( - mathy0(Math.fround(( ! y)), ((mathy3(-Number.MAX_SAFE_INTEGER, (x | 0)) | 0) >>> 0))) | 0), ( + (Math.log10((Math.fround(((( + x) + ((Number.MIN_VALUE | 0) >= y)) >>> 0)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy4, [-(2**53), -1/0, -0x0ffffffff, 0x080000000, -0, 42, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), 1, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, 0x080000001, Math.PI, Number.MAX_VALUE, -0x080000001, -0x07fffffff, 0x100000001, 2**53-2, -0x100000000, -Number.MAX_VALUE, 2**53+2, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=392; tryItOut("t0[this.v0] = v1;");
/*fuzzSeed-244067732*/count=393; tryItOut("for (var v of a0) { try { a2.sort((function() { try { v1 = (g2 instanceof e1); } catch(e0) { } try { t2.set(a1, 0); } catch(e1) { } v2 = (f2 instanceof v1); return t0; }), o1, m2, v1); } catch(e0) { } try { m0.get(v2); } catch(e1) { } Object.defineProperty(this, \"a2\", { configurable: true, enumerable: true,  get: function() {  return arguments; } }); }");
/*fuzzSeed-244067732*/count=394; tryItOut("\"use strict\"; a2.pop();");
/*fuzzSeed-244067732*/count=395; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"v2 = undefined;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: (x % 52 != 4), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-244067732*/count=396; tryItOut("Object.defineProperty(this, \"t0\", { configurable: (x % 39 != 8), enumerable: x /= w,  get: function() {  return new Float64Array(t1); } });");
/*fuzzSeed-244067732*/count=397; tryItOut("m0.set(a1, t2);");
/*fuzzSeed-244067732*/count=398; tryItOut("\"use strict\"; var x, csxilj, x, a, x, b, maswve, x;g1.o0.v1 = Object.prototype.isPrototypeOf.call(o2.m2, this.o2.e2);");
/*fuzzSeed-244067732*/count=399; tryItOut("\"use strict\"; yield;\n\n");
/*fuzzSeed-244067732*/count=400; tryItOut("g0.__proto__ = e1;");
/*fuzzSeed-244067732*/count=401; tryItOut("return {} = \"\\u74D6\"\n");
/*fuzzSeed-244067732*/count=402; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=403; tryItOut("mathy0 = (function(x, y) { return ( - (( + Math.log2((Math.acosh(x)))) >>> 0)); }); testMathyFunction(mathy0, [1.7976931348623157e308, 42, -0x0ffffffff, -0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, 1/0, 0/0, -0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 0, 2**53-2, 0.000000000000001, Math.PI, -0x080000001, 0x100000001, 0x080000001, -0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), -1/0, -(2**53-2), -0x080000000, 0x080000000]); ");
/*fuzzSeed-244067732*/count=404; tryItOut("v2 = t0.length;");
/*fuzzSeed-244067732*/count=405; tryItOut("w = x;o2 = m1.__proto__;");
/*fuzzSeed-244067732*/count=406; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + ( + ((( + ( + Math.imul(Math.fround(( + (x ? ( + mathy1(Number.MIN_VALUE, x)) : x))), (( + Math.ceil(( + -0x080000000))) < Math.abs(Math.fround(mathy1(Math.PI, (x | 0)))))))) | 0) < ( + mathy2(((((( + mathy1(( + ( ! y)), ( + y))) >>> 0) % (mathy1((x | 0), (0x0ffffffff | 0)) >>> 0)) >>> 0) | 0), (( + Math.abs(( + Math.imul(x, x)))) | 0)))))) >>> 0); }); ");
/*fuzzSeed-244067732*/count=407; tryItOut("var nsagcy = new SharedArrayBuffer(4); var nsagcy_0 = new Int32Array(nsagcy); print(nsagcy_0[0]); var nsagcy_1 = new Int8Array(nsagcy); nsagcy_1[0] = -13; var nsagcy_2 = new Uint8Array(nsagcy); nsagcy_2[0] = -19; h0.get = (function(j) { if (j) { try { o0 = Object.create(f0); } catch(e0) { } try { b1.toString = (function mcc_() { var fmvsrl = 0; return function() { ++fmvsrl; if (fmvsrl > 8) { dumpln('hit!'); try { m2.has(t0); } catch(e0) { } try { v0 = undefined; } catch(e1) { } this.a1 = arguments; } else { dumpln('miss!'); try { v2 = Array.prototype.reduce, reduceRight.apply(this.a1, [(function(j) { if (j) { f1 + ''; } else { h2.set = (function() { for (var j=0;j<1;++j) { f2(j%5==0); } }); } }), this.a0, t0]); } catch(e0) { } try { this.a0 = m0; } catch(e1) { } i0.valueOf = f2; } };})(); } catch(e1) { } e0.has(f1); } else { try { o0 = {}; } catch(e0) { } Object.defineProperty(this, \"a0\", { configurable: true, enumerable: false,  get: function() {  return a2.concat(a1, this.a2, 3); } }); } });v2.__proto__ = m1;");
/*fuzzSeed-244067732*/count=408; tryItOut("i2.send(o0);");
/*fuzzSeed-244067732*/count=409; tryItOut("v1 = undefined;");
/*fuzzSeed-244067732*/count=410; tryItOut("\"use asm\"; g1.m0.get(m2);");
/*fuzzSeed-244067732*/count=411; tryItOut("mathy3 = (function(x, y) { return ((Math.hypot(Math.acosh(y), Math.cos(( ~ y))) ? ( + (( + (Math.log1p(Math.log((0/0 >>> 0))) == (Math.acos(y) - (Math.tan((y >>> 0)) >>> 0)))) - ( + Math.sinh((Math.fround(x) ? Math.fround(-0x080000001) : y))))) : Math.fround(mathy1(Math.fround((mathy2((( ! Math.acos(x)) | 0), ((Math.pow((( ! Math.fround(y)) | 0), y) >>> 0) | 0)) | 0)), Math.exp(Math.hypot(Math.atan2(y, 42), Math.hypot(0, Math.asinh(y))))))) >>> 0); }); testMathyFunction(mathy3, [1, ({valueOf:function(){return 0;}}), false, (new Boolean(true)), -0, '0', 0, true, objectEmulatingUndefined(), '\\0', '/0/', (new String('')), null, (function(){return 0;}), (new Boolean(false)), '', ({valueOf:function(){return '0';}}), [], NaN, (new Number(-0)), ({toString:function(){return '0';}}), 0.1, undefined, [0], (new Number(0)), /0/]); ");
/*fuzzSeed-244067732*/count=412; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-244067732*/count=413; tryItOut("g0.f0 = Proxy.createFunction(h2, f0, o2.f2);");
/*fuzzSeed-244067732*/count=414; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.hypot(Math.sign(Math.clz32((( + ((y | 0) !== (Math.min(x, ((y >>> 0) >>> 2**53)) | 0))) >>> 0))), Math.pow(Math.log((Math.atan2(Math.fround(( + Math.ceil(( + Number.MAX_SAFE_INTEGER)))), x) | 0)), (Math.ceil(((( + ( - Math.fround(y))) - ( + Math.atan2((( + y) >>> 0), Number.MIN_VALUE))) | 0)) | 0)))); }); testMathyFunction(mathy0, [({valueOf:function(){return '0';}}), 0, (new Boolean(true)), true, 0.1, null, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Boolean(false)), '/0/', [0], undefined, -0, objectEmulatingUndefined(), '', (function(){return 0;}), [], /0/, 1, (new Number(-0)), false, '\\0', NaN, (new Number(0)), '0', (new String(''))]); ");
/*fuzzSeed-244067732*/count=415; tryItOut("\"use asm\"; testMathyFunction(mathy4, [2**53-2, 1.7976931348623157e308, -Number.MAX_VALUE, -0, 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, 0/0, 0x100000001, -0x100000000, 0, -Number.MIN_VALUE, Math.PI, -(2**53-2), 42, -0x080000000, 0.000000000000001, 0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1, 1/0, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, 2**53, 2**53+2, -(2**53+2), -(2**53), -1/0]); ");
/*fuzzSeed-244067732*/count=416; tryItOut("\"use strict\"; (b)/*\n*/ = d.unwatch(\"__count__\");");
/*fuzzSeed-244067732*/count=417; tryItOut("/*infloop*/L: for  each(let x in x) {print(x); }");
/*fuzzSeed-244067732*/count=418; tryItOut("\"use strict\"; t2[5] = g2.f1;");
/*fuzzSeed-244067732*/count=419; tryItOut("\"use strict\"; g1.t2.set(a2, 10);f1.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((+(((0xffffffff)*0x9fb5d)>>>(((0xf030872e) != (((0x21b8a74f)-(0xedbe5861)+(0xf96aab14))>>>((0xfee7d2c5)-(0x6c0a9859)-(0xec52c51e))))+((((0x34b70527) < (((-0x8000000))>>>((0x79ebef1a))))) < (((0xfcdb205f)) ^ ((0x7fffffff) % (0x1194ba81))))+(0xfee9f4c7)))));\n  }\n  return f; });");
/*fuzzSeed-244067732*/count=420; tryItOut("testMathyFunction(mathy4, [-(2**53), 2**53-2, -(2**53+2), -0x07fffffff, -0x100000000, 42, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 0x080000000, 1, 0x07fffffff, 2**53+2, 2**53, 0x080000001, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, -0x080000000, -(2**53-2), -Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, 0x100000001, Number.MIN_VALUE, 0/0, 0x100000000, 0x0ffffffff, Math.PI, -0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-244067732*/count=421; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + (Math.sinh(( + (Math.max(x, ( + Math.cos(x))) < ( + Math.hypot(Math.fround(y), Math.fround((Math.min((y | 0), ((Math.tan((x >>> 0)) >>> 0) | 0)) >>> 0))))))) < ( + Math.log2(((( + Math.cos(( + ((( ~ Math.fround(y)) >>> 0) ^ x)))) + (((Math.fround(mathy1(Math.exp(x), x)) % ((0x100000000 ? (( - y) >>> 0) : x) >>> 0)) >>> 0) | 0)) | 0))))); }); testMathyFunction(mathy2, [-(2**53-2), 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, -1/0, Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 0x080000000, 0, 0x080000001, Math.PI, -0x100000000, 2**53, -0x100000001, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -0x080000000, 0/0, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 2**53+2, -0x0ffffffff, 42, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), 0x07fffffff, 1]); ");
/*fuzzSeed-244067732*/count=422; tryItOut("testMathyFunction(mathy2, [Number.MIN_VALUE, 0x080000000, -0x07fffffff, -(2**53), -0x0ffffffff, 0/0, 0x07fffffff, 2**53, -Number.MIN_VALUE, -0, 0, 1.7976931348623157e308, 0x100000001, -0x080000000, -0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 42, -Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, -0x100000000, 1/0, 2**53-2, 1, 2**53+2]); ");
/*fuzzSeed-244067732*/count=423; tryItOut("testMathyFunction(mathy4, [Math.PI, Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 2**53+2, -0x100000001, -Number.MIN_VALUE, 2**53-2, 0x080000001, -1/0, -0x080000000, 1, 1.7976931348623157e308, 0x100000001, -0x080000001, -0x100000000, 1/0, 0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 0/0, 2**53, -0, -0x07fffffff, -(2**53), -Number.MAX_VALUE, 42]); ");
/*fuzzSeed-244067732*/count=424; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, -0x080000001, 0x100000000, 1/0, Number.MAX_VALUE, 0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, 2**53, -Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, -0x080000000, 0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0, 2**53+2, -Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, 42, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, 0x100000001, 0x0ffffffff, -(2**53-2), 1, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-244067732*/count=425; tryItOut("v2 = Object.prototype.isPrototypeOf.call(v1, p2);");
/*fuzzSeed-244067732*/count=426; tryItOut("mathy3 = (function(x, y) { return ( - ( - Math.imul(Math.fround((Math.fround(Math.max(0x0ffffffff, (x > Math.fround((Math.fround(y) || Math.fround(x)))))) + Math.fround(Math.fround(Math.max(Math.fround(-0x0ffffffff), Math.fround(-Number.MIN_VALUE)))))), Math.clz32(0/0)))); }); testMathyFunction(mathy3, [-0x07fffffff, Math.PI, -0x080000000, 0x080000000, -1/0, 0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x0ffffffff, -Number.MAX_VALUE, 0.000000000000001, -0, Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, -(2**53-2), 0/0, 1, Number.MAX_VALUE, 2**53-2, -(2**53), Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, 0]); ");
/*fuzzSeed-244067732*/count=427; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, 0/0, 0x100000000, 0x07fffffff, Number.MIN_VALUE, -0, 2**53, 0, 0x080000000, 2**53-2, Math.PI, -1/0, -(2**53-2), -Number.MAX_VALUE, 42, -(2**53+2), 0x0ffffffff, 2**53+2, 1, -0x080000001, 0.000000000000001, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, 1.7976931348623157e308, 1/0, -0x100000001, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=428; tryItOut("this.a1.unshift(v2, f2, (4277));");
/*fuzzSeed-244067732*/count=429; tryItOut("v0 = Object.prototype.isPrototypeOf.call(a1, t0);");
/*fuzzSeed-244067732*/count=430; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.abs((mathy3(Math.fround(( ~ Math.fround(( - (( + y) ? ( + y) : ( + mathy2(x, y))))))), Math.fround(mathy0(( + ((Math.fround((( + (x >>> 0)) >>> 0)) ? Math.fround(0/0) : Math.fround(Math.atan2(( + x), y))) >>> 0)), Math.imul(( - y), x)))) | 0)) / Math.cbrt(Math.min((y === x), (Math.fround((Math.fround(x) > Math.fround(2**53))) >> (Math.pow((-(2**53+2) >>> 0), ((Math.hypot(1, y) >>> 0) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-244067732*/count=431; tryItOut("this.e1.add( /x/g );function window()\"use asm\";   var imul = stdlib.Math.imul;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Float32ArrayView[((((((i1)-((x(x/*\n*/)) <= (((0xffffffff))>>>((0x6549b524))))+(1)))))) >> 2]) = ((+(imul((i1), ( /x/g ))|0)));\n    i2 = (i2);\n    return +((+(-1.0/0.0)));\n  }\n  return f;a0[8] = s2;");
/*fuzzSeed-244067732*/count=432; tryItOut("\"use strict\"; print(uneval(h1));");
/*fuzzSeed-244067732*/count=433; tryItOut("\"use strict\"; print(new new RegExp(\"((?=[\\\\u792f]\\\\S|\\\\r){0,3})\", \"gyim\") **  ''  / \"\\uA7CE\" >>> {}(/(\\D*)/gyim));");
/*fuzzSeed-244067732*/count=434; tryItOut("let x = ('fafafa'.replace(/a/g, String.prototype.localeCompare)), [] = \"\\u4044\", dfddpt, x, vufrnk, zasaaw, qsfqbn, abipck, ouqbva;print(p2);");
/*fuzzSeed-244067732*/count=435; tryItOut("\"use strict\"; this.a0.forEach(f0);");
/*fuzzSeed-244067732*/count=436; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.ceil(((((x | 0) + (((x !== -Number.MIN_VALUE) >>> 0) | 0)) | 0) >= (( - (-0 | 0)) | 0)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -0, 0/0, 0, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, -(2**53+2), -0x080000000, 0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), 1.7976931348623157e308, 0x080000000, -(2**53-2), -1/0, -0x100000000, 2**53-2, -0x0ffffffff, 42, 1, -0x080000001, -0x07fffffff, 2**53, -0x100000001, 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-244067732*/count=437; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((i1)+(i2)+(i2)))|0;\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 1/0, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 0, -Number.MAX_SAFE_INTEGER, 1, -0x100000001, -0x100000000, 2**53+2, 0x07fffffff, 0x100000001, 0x080000001, 0/0, 2**53, Math.PI, -(2**53-2), 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, 0x0ffffffff, 1.7976931348623157e308, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, 0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=438; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4((Math.imul((Math.hypot(y, -Number.MAX_VALUE) === y), ((((Math.acosh(((((( + Math.min(( + x), x)) >>> 0) + ((x / y) >>> 0)) | 0) >>> 0)) >>> 0) | 0) ? (Math.sign(((Math.max((mathy3((Math.min((y | 0), y) | 0), 0/0) >>> 0), (x >>> 0)) >>> 0) | 0)) | 0) : new q => q()) | 0)) | 0), ((((( ~ (( - x) | 0)) >>> 0) - Math.fround(((y > Math.fround(x)) >> (( - ( ! x)) >>> 0)))) | 0) >>> 0)); }); testMathyFunction(mathy5, [[0], (new String('')), '', ({valueOf:function(){return 0;}}), '0', objectEmulatingUndefined(), true, false, (function(){return 0;}), [], (new Number(0)), undefined, /0/, ({valueOf:function(){return '0';}}), (new Boolean(true)), -0, NaN, ({toString:function(){return '0';}}), (new Number(-0)), 0.1, '\\0', (new Boolean(false)), '/0/', 0, 1, null]); ");
/*fuzzSeed-244067732*/count=439; tryItOut("Array.prototype.splice.call(a1, -6, 5, (Math.tanh(let (w)  '' )) >>> let (z = 3)  '' );");
/*fuzzSeed-244067732*/count=440; tryItOut("switch((/*MARR*/[x, x, x, x, x, function(){}, x, function(){}, function(){}, x, function(){}, x, x, function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, function(){}, x, function(){}])) { default: delete a0[(p={}, (p.z = (makeFinalizeObserver('nursery')))())]; }");
/*fuzzSeed-244067732*/count=441; tryItOut("mathy3 = (function(x, y) { return Math.min(Math.fround((( - Math.fround(0x100000000)) * ( + Math.acosh(Math.min(x, (Math.atan2(x, (-Number.MAX_VALUE | 0)) | 0)))))), (( ! ((((x | 0) % (Math.atan2(x, x) | 0)) | 0) && Math.tanh(Math.trunc(x)))) | 0)); }); ");
/*fuzzSeed-244067732*/count=442; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((((( - ( + Math.hypot((1/0 >>> 0), x))) && Math.imul(mathy1((x | ( + x)), ( + ( - Math.sinh(x)))), ( ~ y))) >>> 0) - (((( - (y | 0)) | 0) & Math.atan2(( + Math.fround(Math.pow((y >>> 0), Math.fround(Math.asinh(x))))), (Math.asinh((Math.fround(Math.imul((((mathy2(x, x) % y) | 0) | 0), (x | 0))) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [NaN, /0/, (new Number(-0)), '0', ({valueOf:function(){return 0;}}), 1, -0, (new String('')), null, (new Boolean(false)), '\\0', 0.1, (new Number(0)), (function(){return 0;}), false, undefined, (new Boolean(true)), true, ({toString:function(){return '0';}}), 0, '/0/', '', objectEmulatingUndefined(), [0], [], ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-244067732*/count=443; tryItOut("mathy1 = (function(x, y) { return ( + Math.imul(( + Math.expm1(Math.fround((( + Math.acosh(( + Math.sinh(( + 0.000000000000001))))) ? Math.fround(Math.min((Math.fround(Math.pow((-(2**53+2) | 0), y)) >> y), ( + Math.atanh(( + x))))) : Math.fround((x + ( + (((( ~ 0x080000000) >>> 0) * (y >>> 0)) >>> 0)))))))), (((Math.tanh(x) + (Math.clz32(x) + (Math.sqrt(y) && 0))) | ( ~ Math.fround((( - y) ? (Math.cbrt((y >>> 0)) >>> 0) : (y >>> 0))))) >>> 0))); }); testMathyFunction(mathy1, [0x07fffffff, 2**53-2, Math.PI, 1.7976931348623157e308, -0x080000001, 0x080000000, -0x100000001, Number.MAX_VALUE, -0x080000000, -0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0, 0x100000001, 42, 0/0, 0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0, -Number.MAX_VALUE, 1/0, -(2**53), 0x080000001, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, 2**53, -(2**53-2), 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1]); ");
/*fuzzSeed-244067732*/count=444; tryItOut("this.a0.unshift(t2, m0);");
/*fuzzSeed-244067732*/count=445; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=446; tryItOut("");
/*fuzzSeed-244067732*/count=447; tryItOut("switch(((void options('strict_mode')))) { default: /*bLoop*/for (let sqtciu = 0; sqtciu < 16; ++sqtciu) { if (sqtciu % 13 == 6) { print(x); } else { e0.has(this.o1.h2); }  } break; case 1: if(/\\2(?=.)*?\\1|\\3/y) {print(x); } }");
/*fuzzSeed-244067732*/count=448; tryItOut("\"use strict\"; \"use asm\"; { void 0; void gc('compartment'); } Object.preventExtensions(e2);");
/*fuzzSeed-244067732*/count=449; tryItOut("v2 = evaluate(\"v1 = evalcx(\\\"\\\\\\\"use strict\\\\\\\"; yield;\\\", g1);\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 == 2), noScriptRval: true, sourceIsLazy:  \"\" , catchTermination: /$+/g }))\n");
/*fuzzSeed-244067732*/count=450; tryItOut("\"use strict\"; a0.shift(g2.p2);");
/*fuzzSeed-244067732*/count=451; tryItOut("\"use strict\"; t1 = new Int32Array(a0);function \u3056(...e)eval(\"(d = x)\", (({a: [1]})))h2.toSource =  /x/ ;");
/*fuzzSeed-244067732*/count=452; tryItOut("b0 + a0;");
/*fuzzSeed-244067732*/count=453; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - (Math.sign((Math.cbrt(((( + Math.cbrt(Math.fround(Math.asinh(y)))) < y) | 0)) | 0)) !== Math.fround((0/0 | Math.max(( + ( ! ( + y))), y))))); }); testMathyFunction(mathy1, /*MARR*/[new Boolean(false)]); ");
/*fuzzSeed-244067732*/count=454; tryItOut("var y = (yield intern(x)), a, mhjrko;/*MXX3*/g2.String.prototype.fontsize = g2.String.prototype.fontsize;");
/*fuzzSeed-244067732*/count=455; tryItOut("print(v0);");
/*fuzzSeed-244067732*/count=456; tryItOut("mathy5 = (function(x, y) { return Math.imul(( ! (( ! ((((Math.ceil(Math.fround(( ! (x | 0)))) >>> 0) && (y >>> 0)) >>> 0) >>> 0)) >>> 0)), (Math.fround(Math.acosh(( ! Math.fround(mathy2(mathy0(0/0, 42), y))))) | 0)); }); testMathyFunction(mathy5, [-0x0ffffffff, 0.000000000000001, -0x07fffffff, -(2**53), -Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, -0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, 1/0, 0, -0x080000001, 42, Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), Math.PI, 0x07fffffff, 1.7976931348623157e308, -(2**53-2), 2**53, -0x100000001, -0, 0x080000000, 0x100000000]); ");
/*fuzzSeed-244067732*/count=457; tryItOut("\"use strict\"; var window = (p={}, (p.z = x <<= \"\\u9E85\")()), x = e ||  '' .valueOf(\"number\"), crmykg, ubbnbd, a = ((void options('strict'))), x, this, c = (4277);s1 += s0;");
/*fuzzSeed-244067732*/count=458; tryItOut("v0 = Object.prototype.isPrototypeOf.call(v1, this.e2);");
/*fuzzSeed-244067732*/count=459; tryItOut("v2 = NaN;");
/*fuzzSeed-244067732*/count=460; tryItOut("Array.prototype.pop.apply(a0, [o2]);");
/*fuzzSeed-244067732*/count=461; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.fround((Math.fround(y) ? Math.fround(((x == x) ? Math.fround(Math.max(( + (x >>> 0)), Math.fround(Math.asinh(x)))) : ( + (Math.pow(Number.MAX_VALUE, x) ^ x)))) : -0)) | 0) >> ((Math.pow(Math.fround(( - Number.MAX_VALUE)), mathy2(Math.atan2(mathy2(x, Number.MAX_VALUE), Number.MIN_SAFE_INTEGER), ( + (( - Math.PI) | 0)))) >>> 0) , ( + Math.log(( + y))))) ** Math.fround((( ! ((Math.pow(((Math.fround((Math.atanh((Math.fround(x) / Math.fround(1.7976931348623157e308))) >>> 0)) >>> 0) >>> 0), ((( + Number.MIN_VALUE) | y) >>> 0)) >>> 0) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=462; tryItOut("v2 = (v2 instanceof e1);");
/*fuzzSeed-244067732*/count=463; tryItOut("L: {s1 += 'x'; }");
/*fuzzSeed-244067732*/count=464; tryItOut("/* no regression tests found */let e = (void shapeOf( /x/g ));");
/*fuzzSeed-244067732*/count=465; tryItOut("mathy4 = (function(x, y) { return (Math.atan(((mathy2(( - ( + ( - x))), eval) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MAX_VALUE, 0/0, 42, 2**53+2, 1, 0x0ffffffff, 2**53, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, 2**53-2, -0x07fffffff, -0, 0, -(2**53), -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, Number.MIN_VALUE, -0x100000001, -0x080000001, -(2**53+2), -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -0x100000000, 0x080000001, 0x100000000, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=466; tryItOut("mathy4 = (function(x, y) { return (( + Math.abs(Math.min(( ~ Math.fround(( ! x))), (y + Math.cbrt(x))))) != (Math.hypot(Math.atanh(y), Math.fround(Math.acosh(Math.fround((Math.log(((y | y) | 0)) | 0))))) ^ ( + Math.imul(( + (( ~ (x | 0)) | 0)), (mathy1((Math.atan2(( + y), (y << x)) >>> 0), (( + Math.atan2((x ? Math.fround(( ~ (0/0 >>> 0))) : (Math.asinh((0x100000001 >>> 0)) >>> 0)), x)) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-244067732*/count=467; tryItOut("g2.o0.t1.valueOf = (function mcc_() { var burdgi = 0; return function() { ++burdgi; if (burdgi > 7) { dumpln('hit!'); try { e1.toSource = (function() { m0.delete(p1); return a2; }); } catch(e0) { } try { e1.has(Math.expm1(ReferenceError)); } catch(e1) { } v1 = (this.v2 instanceof a0); } else { dumpln('miss!'); try { Array.prototype.splice.apply(a0, [18, v0]); } catch(e0) { } i0.send(t2); } };})();");
/*fuzzSeed-244067732*/count=468; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_VALUE, -(2**53+2), 0x080000000, -0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -0x100000000, Math.PI, -Number.MIN_VALUE, -0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 42, 0x080000001, 0x100000001, -1/0, -0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, -0x080000000, -(2**53-2), 0.000000000000001, 1/0, 0/0, Number.MAX_SAFE_INTEGER, 1, 0x100000000, -Number.MAX_VALUE, 2**53+2, -0]); ");
/*fuzzSeed-244067732*/count=469; tryItOut("m2.get(o0);");
/*fuzzSeed-244067732*/count=470; tryItOut("\"use strict\"; a2.valueOf = (function(j) { if (j) { try { v2 = this.a1[\"__proto__\"]; } catch(e0) { } try { g1.s1 += s0; } catch(e1) { } /*MXX2*/g2.String.prototype.slice = v0; } else { m0.set(m1, h1); } });");
/*fuzzSeed-244067732*/count=471; tryItOut("\"use strict\"; m1.set(i1, o0.m1);");
/*fuzzSeed-244067732*/count=472; tryItOut("this.v1 = evaluate(\"function f1(h2) x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { throw 3; }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: EvalError, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(({NaN: h2})), Date.prototype.getSeconds, encodeURI)\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 3 != 2), catchTermination: false }));");
/*fuzzSeed-244067732*/count=473; tryItOut("\"use strict\"; for (var v of g2.t2) { let a0 = a0.slice(0, NaN, o0, b1); }print(uneval(b0));\no2.v2 = (o0 instanceof f0);\n");
/*fuzzSeed-244067732*/count=474; tryItOut("p0.valueOf = (function() { try { g2.v0 = t1.length; } catch(e0) { } try { Array.prototype.sort.call(a2, Uint32Array.bind(t0), m1); } catch(e1) { } try { e1.add(e0); } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(e0, m2); return e2; });");
/*fuzzSeed-244067732*/count=475; tryItOut("o2 + '';m1.get(b2);");
/*fuzzSeed-244067732*/count=476; tryItOut("/*infloop*/do f2(v0); while((Set(x, \"\\uC6C0\")));function {x: {x, x}, c}(...e) { yield (makeFinalizeObserver('nursery')) } throw /*RXUE*/new RegExp(\"(?!(?:(?!\\\\d\\\\b){2}))+|(?:\\\\2)\", \"im\").exec(\"0 4\\u1cfb0\");");
/*fuzzSeed-244067732*/count=477; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1.0;\n    d2 = (d1);\n    i0 = (!(-0x8000000));\n    (Float64ArrayView[((((/*FFI*/ff(((-8388609.0)))|0)) & ((0x9ac7b069)-((-7.555786372591432e+22) >= (67108865.0)))) / (((0x17c42357)+(0x468c3817)+(0xa5d62b69)) >> ((!(0xfcca9560))*-0xbec49))) >> 3]) = ((x));\n    (Float32ArrayView[0]) = ((Float32ArrayView[2]));\n    return (((i0)+(((([[]] = e++)+(-0x54ce6c5)-(0xfe37078d))>>>(((0x6c2de125) ? (0xf25753b0) : (0xfa05e4d7))-(0x6fc6a8aa))) >= (0x4780ef4e))+((0x8bb0c22a) ? (0x5bcfd619) : (0xfa62c9f7))))|0;\n  }\n  return f; })(this, {ff: q => q}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, -0x0ffffffff, 1/0, -1/0, -0x080000001, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, -(2**53), 0x080000000, -0x100000001, -0x100000000, 1, -(2**53-2), 2**53, 0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, Math.PI, 0x100000000, 2**53-2, 0/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -0, 0x080000001]); ");
/*fuzzSeed-244067732*/count=478; tryItOut("\"use strict\"; function shapeyConstructor(eaixpl){delete eaixpl[\"caller\"];if (eaixpl) for (var ytqjrdphk in eaixpl) { }if (eaixpl) for (var ytqeobrre in eaixpl) { }Object.freeze(eaixpl);if (eaixpl) Object.freeze(eaixpl);eaixpl[\"x\"] = new Boolean(true);eaixpl[\"caller\"] = function(){};eaixpl[\"x\"] = (4277);if ((eval + NaN)) Object.preventExtensions(eaixpl);return eaixpl; }/*tLoopC*/for (let y of ((function sum_slicing(zetdvz) { (\"\\uE121\");; return zetdvz.length == 0 ? 0 : zetdvz[0] + sum_slicing(zetdvz.slice(1)); })(/*MARR*/[this, [], [], [], this, this, this, this, [], [], this, [], this, [], this, this, [], [], this, this, this, [], this, this, [], this, this, [], this, this, [], this, [], [], [], this, this, [], [], this, this, this, this, this, [], this, this, this, [], [], this, this]))) { try{let zlzute = new shapeyConstructor(y); print('EETT'); for(let x in (((z.valueOf(\"number\")))(((p={}, (p.z = (((Math.trunc((zlzute >>> 0)) | 0) | 0) << (( + Math.hypot(( + y), ( + Math.fround(Math.sinh(Math.fround(x)))))) | 0)))()))))){v2 = Object.prototype.isPrototypeOf.call(m2, a0); }}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-244067732*/count=479; tryItOut("mathy0 = (function(x, y) { return ((((( + (Math.fround(((Math.log(((Math.cosh(42) ? x : y) | 0)) | 0) >> -0x100000001)) | 0)) | 0) | 0) & (((((((Math.tanh(x) >>> 0) + 1.7976931348623157e308) | 0) >>> 0) - ((( - (Math.fround(Math.atan2(y, y)) | 0)) | 0) | 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, [(new String('')), true, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), undefined, 1, -0, (function(){return 0;}), ({toString:function(){return '0';}}), /0/, (new Boolean(false)), [0], (new Boolean(true)), null, (new Number(-0)), '0', 0, '/0/', ({valueOf:function(){return 0;}}), NaN, '\\0', '', [], (new Number(0)), false, 0.1]); ");
/*fuzzSeed-244067732*/count=480; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-244067732*/count=481; tryItOut("b1 = t0[7];");
/*fuzzSeed-244067732*/count=482; tryItOut("e1.has(f0);");
/*fuzzSeed-244067732*/count=483; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((((( + ( + mathy3(( + y), ( + (((( + Math.sqrt(0)) >>> 0) % (Math.hypot((Math.log10(y) >>> 0), x) >>> 0)) >>> 0))))) || ( + (y % Math.pow(x, ((-0x07fffffff / (Math.abs(y) > (Math.acos(x) | 0))) >>> 0))))) | 0) < (mathy2((Math.min((( + (( + (( + Math.sqrt(mathy3(y, 2**53))) * ( + x))) | 0)) | 0), (x % (y >>> 0))) | 0), ( + Math.fround(( - Math.fround(-0x0ffffffff))))) | 0)) | 0); }); testMathyFunction(mathy4, [-(2**53), Math.PI, 0x0ffffffff, 1/0, 1, -1/0, -0, Number.MAX_VALUE, 0x080000000, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, -(2**53+2), -Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, -(2**53-2), 0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 0x100000000, 0x100000001, -0x100000001, 2**53, 42, 0/0]); ");
/*fuzzSeed-244067732*/count=484; tryItOut("/*RXUB*/var r = r1; var s = ((x += NaN) >>= let (d)  /x/g ); print(s.replace(r, eval, \"gym\")); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=485; tryItOut("\"use strict\"; t1.set(t1, 4);");
/*fuzzSeed-244067732*/count=486; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-244067732*/count=487; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.hypot(Math.fround((Math.fround(Math.cosh(Math.fround(( + ( + ( + (Math.round(0x07fffffff) | 0))))))) === Math.fround(( - ( + Math.pow(x, (( ! 0/0) , ( + -1/0)))))))), Math.sqrt(((((Math.max(y, -0x080000001) ** ( + Math.pow(x, y))) != 2**53-2) ? Math.fround(Math.exp(((x ** ( + Math.min(( + y), ( + x)))) | 0))) : Math.max(x, ( + -Number.MIN_SAFE_INTEGER))) >>> 0))); }); testMathyFunction(mathy0, [42, 0, -(2**53), -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, -0x080000001, 0/0, 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, 0x07fffffff, Math.PI, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, 0x100000000, -0x100000001, 0x080000000, -(2**53+2), 1/0, 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=488; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((mathy2(Math.fround(Math.hypot((( + (( + ( + Math.sign(Math.fround(x)))) ? ( + y) : ( + x))) / (Math.asinh((Math.fround(Math.pow(Math.fround(y), Math.fround(x))) | 0)) >>> 0)), (mathy4((( + Math.atan2(Math.fround(Math.pow(Math.fround(y), y)), x)) | 0), (x | 0)) | 0))), ( ! (Math.pow((Math.log2(x) >= x), ( ~ x)) >>> 0))) % ( + ( + mathy1(mathy1(Math.fround(Math.atan2(Math.fround(x), y)), ( + ( + ( + y)))), ((((Math.atan2((x | 0), (( + Math.log10(x)) | 0)) | 0) << x) >>> 0) & Math.fround(( - Math.fround((y ? -0x07fffffff : ( + x)))))))))) | 0); }); testMathyFunction(mathy5, [0x080000000, 2**53-2, -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 0x080000001, -1/0, -(2**53-2), -0x0ffffffff, 0/0, 0x07fffffff, 0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 42, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, -0x07fffffff, -(2**53), -(2**53+2), 1, -Number.MAX_VALUE, 0, 1/0, 2**53, Math.PI, -0x080000001]); ");
/*fuzzSeed-244067732*/count=489; tryItOut("akzbuv(w, undefined);/*hhh*/function akzbuv(){x;}");
/*fuzzSeed-244067732*/count=490; tryItOut("/*infloop*/L:while(/*UUV2*/(x.setUTCHours = x.has)){/* no regression tests found */v1 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 3), noScriptRval: true, sourceIsLazy: false, catchTermination: window - 20 })); }");
/*fuzzSeed-244067732*/count=491; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=492; tryItOut("\"use strict\"; e0 + '';function d()new x((offThreadCompileScript)((x >>= e), /(?:[^]*)/gim))v1 = g0.a0.reduce, reduceRight(e0);");
/*fuzzSeed-244067732*/count=493; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=494; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x080000001, 0x07fffffff, 0x080000000, -0x100000001, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 0/0, -(2**53), -1/0, Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, 1, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, 0, 0x0ffffffff, -0x07fffffff, 0x080000001, -0x080000000, 0x100000000, -0, -Number.MAX_VALUE, Math.PI, -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=495; tryItOut("with({w: (decodeURIComponent)()}){print(uneval(t1));print(\"\\u4EE0\"); }function y() { h2.toSource = (function(j) { f2(j); }); } print(x);(\"\\u5142\");function x(x, x)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 68719476737.0;\n    var i3 = 0;\n    (Float32ArrayView[4096]) = ((((+(0.0/0.0))) * ((-281474976710657.0))));\n    d1 = (-1.001953125);\n    (Int16ArrayView[1]) = ((0xb22a62da)+(1)-((0x36d4057f) ? ((((0x50087bf5)+(i3)-(0x38ff4557))) <= ((0x3b38e*(-0x8000000))>>>(\u3056 = \u3056))) : (0x1994b7d3)));\n    return ((((((-0x8000000))) <= (~~(d2)))))|0;\n  }\n  return f;s0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((~~((((((Uint16ArrayView[1]))>>>(((0xf9df76c4) ? (0xffffffff) : (0xa3e0e473))-((-73786976294838210000.0) != (-134217729.0)))) < (((0x2a5bd90f) / (0x7fffffff))>>>((/*FFI*/ff()|0))))))))-(i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.setSeconds}, new ArrayBuffer(4096));");
/*fuzzSeed-244067732*/count=496; tryItOut("testMathyFunction(mathy1, [1/0, 0.000000000000001, -1/0, 2**53+2, Number.MIN_VALUE, 0x100000001, -0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -0x0ffffffff, -0x100000001, -(2**53+2), -(2**53-2), 1, -0x07fffffff, 0x100000000, 0x080000000, -0x100000000, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, 42, 0x0ffffffff, Number.MAX_VALUE, 0/0, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53]); ");
/*fuzzSeed-244067732*/count=497; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.max((( - -0x080000000) != Math.hypot((y > ((y ? (Math.sinh((x | 0)) | 0) : Math.sign((y >>> 0))) >>> 0)), (Math.fround((Math.fround(mathy0((x | 0), y)) != Math.fround(y))) | 0))), ( + (x > ( ~ y))))), ( + (((Math.fround(y) | 0) ? ( + x) : y) ? (-Number.MIN_VALUE << Math.log10((x | 0))) : Math.hypot(( ~ Math.fround((x || 1/0))), ( + ( ! ( + 0x100000000)))))))); }); ");
/*fuzzSeed-244067732*/count=498; tryItOut("mathy5 = (function(x, y) { return ( ~ ((Math.fround(Math.pow(Math.fround(y), (y >>> x))) || (Math.log1p(x) >>> 0)) >>> (Math.max((Math.trunc(y) >>> 0), ((( - (y >>> 0)) >>> 0) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=499; tryItOut("a1.shift(m0);");
/*fuzzSeed-244067732*/count=500; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; } g0 + '';");
/*fuzzSeed-244067732*/count=501; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(Math.fround(( + Math.imul(( + ((((( + ( + Math.PI)) / (Math.round(( + 0x080000001)) | 0)) >>> 0) | (( + Math.pow(( + Math.max(( + Math.fround(Number.MAX_VALUE)), x)), ( + (y >= y)))) >>> 0)) >>> 0)), ( + ((Math.fround(( + Math.fround(x))) | (mathy0((Number.MAX_SAFE_INTEGER | 0), (Math.cos(( + y)) >>> 0)) | 0)) >>> 0))))), mathy0((( - ( ! Math.max(Math.clz32(Math.min(-(2**53-2), (x | 0))), y))) | 0), ( + Math.pow(Math.fround((Number.MAX_SAFE_INTEGER === Math.fround(x))), ( + (( + x) / ( + (( ! x) >> x))))))))); }); testMathyFunction(mathy1, /*MARR*/[new Boolean(false), Number.MAX_SAFE_INTEGER, new Boolean(false), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new Boolean(false), new Boolean(false), Number.MAX_SAFE_INTEGER, new Boolean(false), new Boolean(false), Number.MAX_SAFE_INTEGER, new Boolean(false), Number.MAX_SAFE_INTEGER, new Boolean(false), Number.MAX_SAFE_INTEGER, new Boolean(false), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new Boolean(false), Number.MAX_SAFE_INTEGER, new Boolean(false), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=502; tryItOut("\"use strict\"; t0[({valueOf: function() { o2 = h1.__proto__;return 5; }})] = new RegExp(\"(?=\\\\2*)\", \"gyim\");");
/*fuzzSeed-244067732*/count=503; tryItOut("/*bLoop*/for (uobhhh = 0; uobhhh < 20; ++uobhhh) { if (uobhhh % 3 == 2) { g0 + t2; } else { g2.a2[3] = Math; }  } ");
/*fuzzSeed-244067732*/count=504; tryItOut("\"use strict\"; v0 = -Infinity;");
/*fuzzSeed-244067732*/count=505; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=506; tryItOut("\"use strict\"; f1 + f0;");
/*fuzzSeed-244067732*/count=507; tryItOut("mathy5 = (function(x, y) { return ( - ( + ((Math.tan(( - y)) | 0) ? ((Math.log((Math.imul((Number.MIN_VALUE >>> (mathy3(( + 0x100000001), ( + Math.atan2(x, 1/0))) | 0)), x) | 0)) | 0) >>> 0) : (Math.min(Math.max(Math.fround((((x | 0) ? (0x100000001 | 0) : (x | 0)) | 0)), (( - (Math.hypot(0x07fffffff, (x >>> 0)) >>> 0)) >>> 0)), Math.hypot(Math.fround(( ~ Math.fround((((x >>> 0) <= ( + x)) | 0)))), 0x0ffffffff)) >>> 0)))); }); testMathyFunction(mathy5, [42, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, -0, Math.PI, 2**53+2, 0.000000000000001, 0x080000000, -Number.MIN_VALUE, 2**53-2, -0x07fffffff, Number.MIN_VALUE, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, 1/0, -Number.MAX_VALUE, 2**53, -0x100000001, -(2**53), 0x100000000, -0x0ffffffff, 0x07fffffff, 0x080000001, -0x100000000, -0x080000000, -(2**53+2), -1/0, 0x100000001]); ");
/*fuzzSeed-244067732*/count=508; tryItOut("delete h2.getOwnPropertyNames;");
/*fuzzSeed-244067732*/count=509; tryItOut("testMathyFunction(mathy3, [0/0, Number.MAX_SAFE_INTEGER, 0x080000001, -0, -Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), 2**53, -0x080000000, 0x07fffffff, 0, -0x0ffffffff, 1, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000000, -(2**53), -1/0, 2**53+2, 0x100000001, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 2**53-2, -0x100000000, Math.PI, -0x07fffffff, 0x080000000, -0x080000001, 42, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=510; tryItOut("Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-244067732*/count=511; tryItOut("i1.next();");
/*fuzzSeed-244067732*/count=512; tryItOut("\"use strict\"; v2 = a1.length;");
/*fuzzSeed-244067732*/count=513; tryItOut("/*infloop*/for(arguments[\"add\"] in  /x/ ) {print(arguments.callee.caller); }g2.v0 = (g1.m0 instanceof b0);");
/*fuzzSeed-244067732*/count=514; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((0xfd7ca204) ? (i1) : (0xffffffff));\n    i1 = (i1);\n    return +((((+((+(-1.0/0.0))))) - ((Float64ArrayView[((i1)-(((((0x1e27cd5a))+((0x69b89cd0)))>>>((i1)+(i1))))) >> 3]))));\n  }\n  return f; })(this, {ff: (makeFinalizeObserver('tenured'))}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [42, -0x07fffffff, -0x100000001, 0x100000000, -0x080000000, 2**53, 0x100000001, -0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53+2), -0x080000001, Math.PI, 0.000000000000001, 0x07fffffff, 0, -0x100000000, -1/0, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, 1.7976931348623157e308, -(2**53-2), 1, -0, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 0/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=515; tryItOut("\"use strict\"; h0.get = (function() { for (var j=0;j<42;++j) { g0.f2(j%4==0); } });");
/*fuzzSeed-244067732*/count=516; tryItOut("o1 = g2.objectEmulatingUndefined();");
/*fuzzSeed-244067732*/count=517; tryItOut("\"use asm\"; (void schedulegc(g2));");
/*fuzzSeed-244067732*/count=518; tryItOut("m2.has(i0);");
/*fuzzSeed-244067732*/count=519; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    {\n      {\n        (Uint32ArrayView[(0xf89a5*(i2)) >> 2]) = (((((0x731da527)+((d1) > (d1))) << (0x2bea1*((Uint32ArrayView[(((0x4576f897) == (-0x8000000))+(-0x8000000)-((-0x8000000) >= (0x52a6c640))) >> 2])))))-(i3));\n      }\n    }\n    {\n      (Float64ArrayView[4096]) = ((2147483648.0));\n    }\n    {\n      {\n        {\n          d0 = (+/*FFI*/ff(((((i2))|0)), ((d0)), ((+((d1)))), ((~~(+(1.0/0.0)))), ((d0)), ((+(1.0/0.0))), ((d1)), ((Int32ArrayView[1])), ((~((0x9df4b481)))), ((1.888946593147858e+22))));\n        }\n      }\n    }\n    d1 = ((d1) + (+(0.0/0.0)));\n    i3 = (0x984bf926);\n    {\n      i2 = (i3);\n    }\n    return +((-1.0));\n  }\n  return f; })(this, {ff: \"\\u92EA\" <<= new RegExp(\"[]\", \"ym\")}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, -(2**53+2), 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 1/0, 0, 0x100000001, -0x080000000, 42, 2**53-2, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 1, 2**53, -0x080000001, -Number.MAX_VALUE, -0x07fffffff, -0x100000001, -1/0, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 0/0, -(2**53-2), 0.000000000000001, 0x0ffffffff, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=520; tryItOut("return window;");
/*fuzzSeed-244067732*/count=521; tryItOut("\"use asm\"; f2(o0);");
/*fuzzSeed-244067732*/count=522; tryItOut("testMathyFunction(mathy4, [Math.PI, -(2**53+2), 0x0ffffffff, 0x07fffffff, 0, -1/0, 0x080000000, 1/0, 0x100000001, 0.000000000000001, -Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, Number.MIN_SAFE_INTEGER, 1, 42, -0x0ffffffff, -(2**53), 0/0, 2**53-2, Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53-2), 2**53]); ");
/*fuzzSeed-244067732*/count=523; tryItOut("mathy3 = (function(x, y) { return ( + Math.atan2(( + (Math.clz32(Math.fround((((Math.max(y, x) | 0) ** (Math.max((x >>> 0), (Math.max(( + 0x100000001), (y | 0)) >>> 0)) | 0)) | 0))) << (Math.fround((Math.fround(( ~ x)) === ( + (( + y) === x)))) - ( + (Math.fround(mathy1((x >>> 0), (Number.MIN_VALUE >>> 0))) * mathy2(Math.fround((y * 0x100000000)), ( + x))))))), Math.hypot(((mathy0((0x080000001 >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) % Math.fround(mathy2(Math.fround(( + mathy0(( + (y & Math.clz32((x >>> 0)))), (0x080000000 >>> 0)))), Math.fround(x)))), Math.fround(( - Math.atan2(Math.fround(Math.ceil(( + x))), -Number.MAX_SAFE_INTEGER)))))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, 1/0, -0x07fffffff, -1/0, -0x0ffffffff, Number.MIN_VALUE, 2**53, -0x100000001, -0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, 0x080000001, 0, 0/0, 0x080000000, 0.000000000000001, -0, 2**53+2, 0x100000001, -(2**53-2), Math.PI, -(2**53), -0x080000000, 42, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, 2**53-2, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=524; tryItOut("\"use strict\"; /*MXX1*/o0 = g1.Function.name;");
/*fuzzSeed-244067732*/count=525; tryItOut("mathy4 = (function(x, y) { return ( ! Math.fround(Math.sinh(Math.tan(y)))); }); testMathyFunction(mathy4, [-1/0, 0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -0x100000001, 0x07fffffff, 0x080000000, -0, 0, 2**53, 2**53+2, -0x080000001, 1.7976931348623157e308, 42, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, Math.PI, 1/0, -0x0ffffffff, 0x0ffffffff, -0x100000000, 0x100000001, 0/0, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-244067732*/count=526; tryItOut("\"use strict\"; { void 0; void 0; }/*infloop*/for(var [] = 25; /*FARR*/[, ...[]].some(Date.prototype.setMonth); window &= true) v2 = Object.prototype.isPrototypeOf.call(h2, o1.o1);");
/*fuzzSeed-244067732*/count=527; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=528; tryItOut("break ;");
/*fuzzSeed-244067732*/count=529; tryItOut("x;\ng2 + this.e2;\n");
/*fuzzSeed-244067732*/count=530; tryItOut("\"use strict\"; for (var p in v0) { try { /*MXX1*/o0 = g2.String.prototype.indexOf; } catch(e0) { } try { Array.prototype.reverse.apply(a1, [h0, g2, m1, g2, f2, p1]); } catch(e1) { } ; }");
/*fuzzSeed-244067732*/count=531; tryItOut("mathy1 = (function(x, y) { return ((( + (((((Math.max((2**53-2 | 0), (Math.sign((1.7976931348623157e308 >>> 0)) >>> 0)) | 0) | 0) ? mathy0(Math.fround(x), ( + x)) : ( + Math.tanh(( + Math.fround((Math.fround(x) ? x : Math.fround(42))))))) | 0) ? Math.atan2(y, Math.fround(x)) : Math.atan(x))) == (Math.fround(Math.atan2((Math.atanh(x) >>> 0), ((Math.fround(mathy0(Math.fround(y), Math.fround(mathy0(y, x)))) != Math.cos(( + (( ! (y | 0)) | 0)))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy1, [0x0ffffffff, 0x100000000, 42, -(2**53+2), 2**53, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -0, -0x100000000, -0x0ffffffff, -Number.MIN_VALUE, -1/0, 2**53-2, 1, 1/0, 0/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000000, -0x080000001, Number.MAX_VALUE, -0x080000000, 2**53+2, Math.PI]); ");
/*fuzzSeed-244067732*/count=532; tryItOut("/*hhh*/function uqzwig(){print(x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: false, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: mathy4, enumerate: /*wrap1*/(function(){ a1.push(p2, \"\\u7E23\", e0, window, m2, m2, g2, g0, undefined);return (function(x, y) { return y; })})(), keys: function() { return Object.keys(x); }, }; })(\"\\uFB7B\"), function(y) { \"use asm\"; m2.get(); }));\n\"\\u4365\";/*oLoop*/for (let ibwotf = 0; ibwotf < 24; ++ibwotf) { /(?=^(?!\\1{3,7}))*?/; } \n}uqzwig();");
/*fuzzSeed-244067732*/count=533; tryItOut("\"use strict\"; x.stack;");
/*fuzzSeed-244067732*/count=534; tryItOut("testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0.000000000000001, -0x100000000, 2**53-2, 0x07fffffff, -(2**53-2), -Number.MAX_VALUE, Number.MAX_VALUE, 2**53+2, 0x100000000, -0x0ffffffff, 0x100000001, -0x100000001, 1/0, -1/0, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), 1, -0x080000000, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, -0x07fffffff, 0/0, 2**53, -0x080000001, 0, -0, 0x0ffffffff, Math.PI, -Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=535; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x100000001, -0x100000000, -0x080000000, 1/0, -(2**53+2), -0x080000001, 42, 0, 1.7976931348623157e308, -Number.MAX_VALUE, 0x0ffffffff, 1, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000001, 0x080000000, -(2**53), -0x0ffffffff, 2**53-2, 2**53, Number.MIN_VALUE, 0/0, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=536; tryItOut("x;");
/*fuzzSeed-244067732*/count=537; tryItOut("\"use strict\"; let (d) { /*oLoop*/for (var digepr = 0; digepr < 35 && (\"\\u1D74\" += \"\\uB989\"); ++digepr) { print((4277)); }  }");
/*fuzzSeed-244067732*/count=538; tryItOut("Object.defineProperty(this, \"i0\", { configurable: true, enumerable: (x % 5 == 4),  get: function() {  return new Iterator(g2, true); } });function x(x, b, a, eval(\"( /x/ );\", x), x, c, {}, y, x, x, \u3056, x, b = \"\\u8C2E\", a, x =  \"\" , e, a, eval, x, x, e, c, y = undefined, a, d = /\\3/, d = new RegExp(\"\\\\2\", \"gyim\"), c, d, let, x, x, c, \u3056, window, e, d, y, x, x, w, x, x, d =  /x/g , w, eval, z, NaN, getter, a, x, x, NaN, w, w, x = c, x, x, d, NaN, w, NaN, eval, x, w = undefined, window, \u3056, z, a, w, \"-18\" = new RegExp(\"(?!(?=(?=([^]))^|[\\u51d3])(?:(?:[^]))|(?=\\\\u006C))\", \"yim\"), window) { \"use strict\"; return  /x/g .unwatch(\"lastIndexOf\") - \"\\u4677\" } \u000c(4277);");
/*fuzzSeed-244067732*/count=539; tryItOut("\"use asm\"; v1 = NaN;");
/*fuzzSeed-244067732*/count=540; tryItOut("mathy4 = (function(x, y) { return mathy1(( + Math.fround(( ! Math.fround(( + Math.min(Math.expm1(( + ( + Math.cosh(( + ( + y)))))), ( + (Math.cosh(Math.fround(-Number.MAX_SAFE_INTEGER)) + Math.pow(mathy3(y, (y || 0x07fffffff)), ((x >>> 0) << x)))))))))), Math.fround(Math.acos(Math.fround(( - Math.atan2(((y ? Math.fround(y) : x) >>> 0), x)))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, 1, 0.000000000000001, -(2**53+2), 0x080000000, 0x080000001, -0, 0x100000001, Number.MIN_VALUE, 0x07fffffff, 42, Math.PI, -0x0ffffffff, 0, -(2**53), -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, 0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0/0, -0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=541; tryItOut("t0 = new Int32Array(19);");
/*fuzzSeed-244067732*/count=542; tryItOut("with({d: (void version(185))}){s2 += s2; }");
/*fuzzSeed-244067732*/count=543; tryItOut("Object.defineProperty(this, \"v1\", { configurable: (4277), enumerable: Math.sinh( /x/ ),  get: function() {  return 4; } });");
/*fuzzSeed-244067732*/count=544; tryItOut("mathy3 = (function(x, y) { return Math.min(Math.fround(Math.asinh(( - ( ! ( ! Math.log1p(x)))))), Math.fround(Math.fround(Math.asinh((((x ? 0 : (x >>> 0)) >> ( + ( - mathy0(Math.atanh(x), mathy0(-0, (Math.acosh((x >>> 0)) >>> 0)))))) >>> 0))))); }); ");
/*fuzzSeed-244067732*/count=545; tryItOut("v2 = Object.prototype.isPrototypeOf.call(v1, o2.a1);");
/*fuzzSeed-244067732*/count=546; tryItOut("yevktt(null);/*hhh*/function yevktt(x = x, e){print(mathy2.prototype);}");
/*fuzzSeed-244067732*/count=547; tryItOut("");
/*fuzzSeed-244067732*/count=548; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=549; tryItOut("mathy1 = (function(x, y) { return ( + Math.tanh((Math.round((Math.log2((mathy0(y, x) >>> 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=550; tryItOut("Array.prototype.splice.apply(a0, [NaN, ({valueOf: function() { e1.add(p0);return 12; }})]);");
/*fuzzSeed-244067732*/count=551; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.atan2((Math.sqrt(((y ** y) / ((mathy0(0x0ffffffff, y) | 0) ** (y >>> 0)))) >>> 0), (((Math.ceil(Math.atan(y)) >>> 0) >> mathy1(y, (x | 0))) >>> 0)); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -(2**53+2), 1/0, -(2**53), -0x080000001, 0x080000000, 0, 1, 2**53-2, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, 0/0, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -(2**53-2), 0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0x07fffffff, -1/0, Math.PI, 0x100000001, 2**53+2, -0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=552; tryItOut("\"use strict\"; v2 = b2.byteLength;");
/*fuzzSeed-244067732*/count=553; tryItOut("mathy3 = (function(x, y) { return ( + Math.min(((( + mathy1(Math.round(y), ( + (( ! ((y >= Math.hypot(0x080000001, y)) >>> 0)) | 0)))) && (Math.acosh((( - y) | 0)) , ( + (( + y) ? ( + mathy0((( + y) !== x), ( + -(2**53)))) : ( + mathy0(( + Math.max(mathy2((-(2**53-2) >>> 0), Math.fround(x)), ( + y))), y)))))) >>> 0), (( ! ( + (Math.expm1(x) >>> 0))) >>> 0))); }); testMathyFunction(mathy3, [42, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, -(2**53-2), 2**53, 1, Number.MIN_VALUE, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 1/0, 0x100000001, 0/0, Number.MAX_VALUE, 0, -0x0ffffffff, 0x080000001, -0, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 2**53+2, -(2**53), 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0x100000000, -0x100000001]); ");
/*fuzzSeed-244067732*/count=554; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.cbrt(Math.fround(((( + y) <= Math.fround(Math.trunc(Math.fround((Number.MAX_SAFE_INTEGER & ( ! Math.tan(y))))))) | 0))); }); testMathyFunction(mathy0, /*MARR*/[new RegExp(\"(\\\\B)\", \"m\"), new String('q'), [undefined], new String('q'), [undefined], new RegExp(\"(\\\\B)\", \"m\"), new RegExp(\"(\\\\B)\", \"m\"), [undefined], new String('q'), new RegExp(\"(\\\\B)\", \"m\"), function(){}, function(){}, [undefined], [undefined], new RegExp(\"(\\\\B)\", \"m\"), new String('q'), new RegExp(\"(\\\\B)\", \"m\"), [undefined], [undefined], new String('q'), new String('q'), [undefined], new RegExp(\"(\\\\B)\", \"m\"), [undefined], function(){}]); ");
/*fuzzSeed-244067732*/count=555; tryItOut("/*tLoop*/for (let e of /*MARR*/[function(){}, function(){}, (-1/0), (void 0), -0x07fffffff, function(){}, -0x07fffffff, function(){}, function(){}, (void 0), function(){}, (-1/0), (-1/0), -0x07fffffff, function(){}, -0x07fffffff, -0x07fffffff, (-1/0), (void 0), -0x07fffffff, (void 0), function(){}, (void 0), -0x07fffffff, (void 0), function(){}, function(){}, (void 0), function(){}, -0x07fffffff, -0x07fffffff, function(){}, (-1/0), (-1/0), function(){}, (void 0), (-1/0), function(){}, (void 0), (-1/0), (void 0), function(){}, (-1/0), (void 0), (-1/0), (-1/0), (void 0), function(){}, -0x07fffffff, (void 0), function(){}, function(){}, -0x07fffffff, (void 0), (-1/0), (-1/0), (void 0), (-1/0), function(){}, function(){}, -0x07fffffff, (-1/0), (void 0), function(){}, -0x07fffffff, (void 0), (void 0), (-1/0), (void 0), (void 0), (void 0), (void 0), -0x07fffffff, (void 0), (-1/0), (void 0), function(){}, (-1/0), function(){}, -0x07fffffff, (void 0), (-1/0), (-1/0), (void 0), function(){}, -0x07fffffff, -0x07fffffff, (void 0), -0x07fffffff, function(){}, (-1/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0)]) { s2 = new String; }");
/*fuzzSeed-244067732*/count=556; tryItOut("\"use strict\"; i0 = new Iterator(this.i2);");
/*fuzzSeed-244067732*/count=557; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=558; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=559; tryItOut("m0.get(e1);");
/*fuzzSeed-244067732*/count=560; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul(( + ( - ( + (Math.pow(((Math.min(y, y) * x) >>> 0), (Math.log2(Math.atan2(x, (x >>> 0))) >>> 0)) >>> 0)))), Math.abs(Math.pow(( + Math.log(( + ( + (-0 >>> 0))))), ( + ( ~ y))))); }); testMathyFunction(mathy0, [-0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, 2**53-2, 0x07fffffff, 0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, 42, -0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -0x080000001, 1, 1/0, 2**53, -0x100000001, 1.7976931348623157e308, 2**53+2, -0x0ffffffff, -1/0, 0/0, 0, 0x080000001, -0x07fffffff, 0x080000000]); ");
/*fuzzSeed-244067732*/count=561; tryItOut("testMathyFunction(mathy5, [-Number.MIN_VALUE, -0x100000000, 42, -(2**53+2), -0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 0x080000000, 0.000000000000001, 2**53+2, Math.PI, 2**53-2, 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, -(2**53), -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, 0/0, -0x080000000, 1.7976931348623157e308, 0, 0x100000001, 1, -0, 2**53]); ");
/*fuzzSeed-244067732*/count=562; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; verifyprebarriers(); } void 0; } print((void options('strict'))\u0009 ? \"\\uECB4\" -= /\\S/m : this);");
/*fuzzSeed-244067732*/count=563; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.fround((((( ! (Math.sqrt(x) | 0)) !== Math.min((Math.hypot(y, 0x100000000) | 0), (((-0 !== Math.fround(x)) | 0) >>> 0))) - Math.fround((((( ! x) | 0) ? (( + ( ! ( + mathy3(y, ( + Math.PI))))) | 0) : (Math.fround(mathy1((Math.fround(Math.imul((y ? y : y), Math.fround(-0x100000000))) >>> 0), (Math.fround(Math.imul(x, y)) >>> 0))) | 0)) | 0))) | 0)))); }); testMathyFunction(mathy4, [0, Math.PI, 0x100000001, -0x080000001, 0x100000000, 0.000000000000001, 2**53-2, 0x0ffffffff, -(2**53-2), 1, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, Number.MIN_VALUE, -(2**53+2), -0x100000001, -0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, -(2**53), -0x100000000, 2**53+2, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, -0]); ");
/*fuzzSeed-244067732*/count=564; tryItOut("mathy3 = (function(x, y) { return Math.atan2(Math.min(( + Math.min(Math.imul(Math.fround(mathy1(x, Math.sqrt(x))), y), (( - x) >= ( + (( + Math.pow(-Number.MIN_SAFE_INTEGER, x)) / (-0x100000000 | 0)))))), (Math.atan(Math.fround(Math.exp(Math.fround(Math.cos(-(2**53+2)))))) >>> 0)), ((Math.expm1(Math.atan2(Math.min(y, y), -Number.MAX_SAFE_INTEGER)) % (( ~ (Math.imul(Math.fround((-0x07fffffff - ( ! ( + x)))), mathy0(y, ( + Math.cos(( + 2**53-2))))) >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy3, [-0, Number.MIN_VALUE, -Number.MAX_VALUE, 42, 1/0, 0x080000001, -0x080000001, Math.PI, 2**53+2, 0, 0x100000000, -0x100000001, 0x080000000, 0x0ffffffff, 2**53, -0x0ffffffff, 1, -0x100000000, -(2**53+2), -0x07fffffff, -(2**53-2), -1/0, -(2**53), 1.7976931348623157e308, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2]); ");
/*fuzzSeed-244067732*/count=565; tryItOut("var r0 = x * x; var r1 = x & x; var r2 = 1 | 3; var r3 = 3 / 5; var r4 = 6 ^ 2; var r5 = 4 - 9; r1 = r2 * 0; var r6 = x - 4; var r7 = r0 / r2; var r8 = 5 | 7; var r9 = r3 - r0; var r10 = r1 * r4; var r11 = r10 | r6; x = 3 | 8; var r12 = r8 + r4; print(r4); r5 = x - 4; var r13 = r1 * 2; var r14 = r9 * r12; r4 = 6 & x; r3 = r5 % 6; var r15 = r11 & r11; var r16 = r14 / r1; var r17 = r8 % 9; var r18 = r3 & r5; print(r5); ");
/*fuzzSeed-244067732*/count=566; tryItOut("const e = /*UUV1*/(x.find = Function.prototype.apply);let(x) { true;}");
/*fuzzSeed-244067732*/count=567; tryItOut("\"use strict\"; ;const e = x = this.__defineSetter__(\"a\", x);");
/*fuzzSeed-244067732*/count=568; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=569; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=570; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\1|$)\", \"y\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=571; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return ( - ( + (Math.fround((( + Math.atan2(( + Math.fround((Math.fround(x) >> Math.fround(y)))), x)) ** ( + x))) ? Math.fround(Math.hypot(x, Math.asinh(Math.pow((Math.cos((Number.MIN_VALUE >>> 0)) >>> 0), Math.acosh((x >>> 0)))))) : ( + (Math.min(( + ( + ( + -(2**53-2)))), mathy1(Math.trunc(y), Math.asinh((Math.fround(( + (x | 0))) >>> 0)))) | 0))))); }); ");
/*fuzzSeed-244067732*/count=572; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x080000001, Math.PI, 1/0, 1.7976931348623157e308, 0x100000000, 0x0ffffffff, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, -0, -(2**53-2), -(2**53+2), -1/0, -0x0ffffffff, 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, -0x080000000, 1, -Number.MIN_VALUE, 0, 0x080000001, -0x07fffffff, 0x100000001, -(2**53), 2**53+2]); ");
/*fuzzSeed-244067732*/count=573; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((( - ( + Math.log2((( + (y ** x)) ^ (mathy1(Math.fround((0x07fffffff ? 42 : ( + Math.imul(( + x), -Number.MAX_VALUE)))), ((((x >>> 0) !== (y >>> 0)) >>> 0) | 0)) >>> 0))))) | 0) >> Math.acosh(Math.fround(Math.cos(((Number.MIN_VALUE >= Number.MIN_SAFE_INTEGER) >>> 0))))); }); testMathyFunction(mathy2, [-(2**53+2), -0, 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0, 0/0, -0x080000000, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x080000001, 0x100000001, 0x080000000, Number.MAX_VALUE, -0x100000000, 0x07fffffff, 1.7976931348623157e308, -0x100000001, 0.000000000000001, 1/0, -1/0, -Number.MIN_SAFE_INTEGER, 1, 0x080000001, Math.PI, 0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-244067732*/count=574; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (!(0xc0a2e4dc));\n    d0 = (d0);\n    i1 = (0xe8b7894f);\n    return (((0x45843a84)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53+2), 0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, 0x100000001, 0/0, -1/0, 2**53, -Number.MIN_VALUE, -0x100000001, 1/0, -0x080000000, 1, 2**53+2, 0x080000001, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, 0, -(2**53), -Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, -0x100000000, 0x080000000, 2**53-2, Math.PI, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, 0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=575; tryItOut("this.v0 = (e1 instanceof o0.g2.p1);");
/*fuzzSeed-244067732*/count=576; tryItOut("for(a in ((function(y) { \"use strict\"; return delete x.a })((c = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(-4 , (set != \"\\u88A3\")), String.fromCodePoint, Date.prototype.setUTCMinutes)))))v2 = (o0.o2.f1 instanceof v0);a = window;\u0009");
/*fuzzSeed-244067732*/count=577; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - (Math.hypot(Math.fround(mathy0(x, Math.fround(Math.imul(y, ( ~ y))))), ((-0x0ffffffff === Number.MIN_VALUE) != -(2**53+2))) | Math.pow(( + Math.sign(Math.fround(x))), ((Math.asinh((( + mathy0(( + 1.7976931348623157e308), ( + x))) | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy1, [0.1, (function(){return 0;}), -0, (new Boolean(false)), [], 1, true, '\\0', NaN, false, ({valueOf:function(){return 0;}}), (new String('')), ({valueOf:function(){return '0';}}), (new Number(-0)), null, (new Boolean(true)), [0], (new Number(0)), '/0/', '', 0, /0/, ({toString:function(){return '0';}}), undefined, objectEmulatingUndefined(), '0']); ");
/*fuzzSeed-244067732*/count=578; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MIN_VALUE, 0/0, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, 1.7976931348623157e308, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), -0, -(2**53-2), -Number.MIN_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, 42, -0x080000000, Number.MAX_VALUE, Math.PI, 2**53+2, 1/0, -Number.MAX_VALUE, 0x080000000, 0x07fffffff, 0x100000000, -0x100000001, -0x080000001, -(2**53+2), -1/0, 0x080000001, 1, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=579; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(mathy0((Math.pow(Math.fround(Math.ceil(Math.fround(x))), mathy2(( + mathy2(x, ( + y))), Math.fround(y))) >>> 0), ((( + mathy3(( - (Math.fround(((mathy3(-1/0, (x | 0)) >>> 0) % Math.fround(y))) >>> 0)), Math.acos(Math.sin((( - -0x0ffffffff) - Math.PI))))) ? (-0x0ffffffff >>> ( + Math.pow(( + y), x))) : (mathy0(Math.fround(Math.fround(( - Math.fround(x)))), Math.fround(((Math.fround(x) | (((x | 0) ? (x | 0) : y) | 0)) >>> 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [0, 0x100000001, 0x0ffffffff, 0/0, 1, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, -(2**53+2), 1/0, -(2**53-2), -0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, 0.000000000000001, 2**53+2, -1/0, Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, 2**53-2, -(2**53), 42, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, Math.PI, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=580; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (({\u000919: x })), sourceIsLazy: x, catchTermination: false }));");
/*fuzzSeed-244067732*/count=581; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((((Math.cbrt((Math.fround(Math.imul((Math.hypot(((x << y) * ( + -(2**53-2))), -0) >>> 0), ( + ( ~ ( + Math.fround(( ! ((Math.ceil(Math.fround(Math.log10(y))) | 0) | 0)))))))) | 0)) >>> 0) | 0) | (( + (( + (Math.min((((((y >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0) | 0) << ((Math.min(-0x100000001, 1/0) >>> 0) | 0)), (x | -0x080000000)) >>> 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, Math.PI, 1/0, -(2**53), -0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0/0, 2**53, -Number.MIN_VALUE, 0x080000000, 2**53-2, -0, 0.000000000000001, 0x07fffffff, -0x100000000, 1, -(2**53-2), 0x100000001, 0, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, -1/0, Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), Number.MAX_VALUE, 2**53+2, 42, 0x100000000, 0x080000001]); ");
/*fuzzSeed-244067732*/count=582; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ~ Math.fround(( - mathy3(Math.fround(Math.min(Math.fround(-Number.MIN_SAFE_INTEGER), ( + Math.atan2(y, ( ~ (x | 0)))))), ( ~ x))))) ? Math.imul((Math.max(((Math.hypot(y, x) >>> 0) | 0), x) | 0), (Math.abs(Math.max(y, (x | 0))) | 0)) : Math.min(Math.pow(( + Math.fround(( ~ ( + y)))), y), (( + ( ! ( + 0x100000000))) * (0 ? ((y >>> (42 | 0)) >>> 0) : (Math.hypot((x | 0), (-0x07fffffff | 0)) | 0))))); }); ");
/*fuzzSeed-244067732*/count=583; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x100000001, -0, 1.7976931348623157e308, -0x100000001, 0, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, Math.PI, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, 2**53+2, 0x080000001, -0x080000000, -0x080000001, -1/0, 2**53, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -(2**53+2), 0x100000000, 0x07fffffff, 0x0ffffffff, 1, -0x100000000, -Number.MAX_VALUE, -(2**53), -0x07fffffff, 2**53-2, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=584; tryItOut("\"use strict\"; with(--z)var hopcqa = new ArrayBuffer(1); var hopcqa_0 = new Uint16Array(hopcqa); var hopcqa_1 = new Int32Array(hopcqa); hopcqa_1[0] = -5; var hopcqa_2 = new Uint8Array(hopcqa); var hopcqa_3 = new Uint8Array(hopcqa); print(hopcqa_3[0]); hopcqa_3[0] = -13; var hopcqa_4 = new Uint32Array(hopcqa); hopcqa_4[0] = 17; h2 = {};print(hopcqa_4);/*RXUB*/var r = new RegExp(\"(?:(?!\\\\d?))\", \"gyi\"); var s = \"\"; print(s.replace(r, [,,z1], \"\")); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=585; tryItOut("Array.prototype.forEach.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((32769.0)))|0;\n    i0 = (i0);\n    i1 = ((0x2a528df7));\n    return (((((((((0xab2fad2f))>>>((0xffffffff))))+(!((0xd52da31d) ? (0xf803d3b6) : (0xf9b0a3b7)))+(((3.8685626227668134e+25)))) >> ((((0xf787b29f)-(0xdb30b5)-(0xf83574b2)) >> ((0xffffffff)-(0xfb3fc2d6)-(0xe490c5a6))) % (((0x5916475b) % (0x1e294967))|0))) < (imul((i2), ((0x6c18319b)))|0))+((abs((0x3a1472f0))|0))))|0;\n    return (((i0)+(i0)))|0;\n  }\n  return f; }), i1]);");
/*fuzzSeed-244067732*/count=586; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(([^]|(?!.+)))\\u00db(\\\\1)+|(.)\", \"gyi\"); var s = \"\\n\\n\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=587; tryItOut("/*MARR*/[-Number.MAX_SAFE_INTEGER, {x:3}, -Number.MAX_SAFE_INTEGER, (void 0), (void 0), {x:3}, (void 0), (void 0), (void 0), {x:3}, -Number.MAX_SAFE_INTEGER, (void 0), -Number.MAX_SAFE_INTEGER, (void 0), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, (void 0), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, (void 0), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, {x:3}, (void 0), (void 0), -Number.MAX_SAFE_INTEGER, {x:3}, {x:3}, {x:3}, (void 0), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, {x:3}, {x:3}, (void 0), -Number.MAX_SAFE_INTEGER, (void 0), -Number.MAX_SAFE_INTEGER, (void 0), (void 0), {x:3}, {x:3}, (void 0), -Number.MAX_SAFE_INTEGER, {x:3}, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, (void 0)]");
/*fuzzSeed-244067732*/count=588; tryItOut("this.v2 = Object.prototype.isPrototypeOf.call(g2, s2);");
/*fuzzSeed-244067732*/count=589; tryItOut("");
/*fuzzSeed-244067732*/count=590; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(mathy4(Math.fround((Math.tanh((( ! Math.imul(y, (( - mathy4(x, y)) | 0))) | 0)) | 0)), Math.fround(mathy3(( - Math.fround((Math.fround(Math.fround(y)) != Math.fround(mathy2(y, 0x080000001))))), Math.trunc(( ! x)))))); }); testMathyFunction(mathy5, [-0x080000000, 0.000000000000001, -0x080000001, -0x07fffffff, Number.MIN_VALUE, -(2**53+2), Math.PI, -0x100000001, 1/0, 0x080000000, -1/0, 0x0ffffffff, 2**53, 0x100000000, 0x07fffffff, 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, -0x100000000, 1, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 42, -0, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=591; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=592; tryItOut("\"use strict\"; p1.__proto__ = e2;");
/*fuzzSeed-244067732*/count=593; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^](?!\\u2b4e{0,}|[^\\\\W\\\\s\\\\cD-\\\\cO\\ua4d8][^]|[\\\\S].+(?!\\\\v)*|(?!.?.|.|[^\\\\x15K-\\u461b]|[^]|\\\\3((?!$)^|[^]{0,4})))\", \"gim\"); var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=594; tryItOut("\"use strict\"; \"use asm\"; /*hhh*/function lyigit(e, x, c, x, \u3056, c, x =  '' , x, \"-8\", x, b, x = window, x =  /x/ , y, d, x, x, x =  '' , x, e, x, window, x, d, this, x, w, x = this, x, e, z, x, x, x, window, x, this.window = new RegExp(\"($){2,6}\", \"im\"), e, x = /(?!\\W{2,32769})|\\1*(?:.)*?|\\w{3,6}/im, window, b, d, b, c, \u3056, y, b, x, eval =  \"\" , a = this, x, x, e, window, x, x, e, a = Math, window = /./i, ...window){/*RXUB*/var r = r2; var s = s1; print(uneval(r.exec(s))); }/*iii*/m2 = new Map(p0);");
/*fuzzSeed-244067732*/count=595; tryItOut("mathy5 = (function(x, y) { return (Math.imul((y >> Math.round(( + -1/0))), ( + Math.cosh(( + y)))) * (mathy0((mathy3(( + ( + (Math.max(x, y) << (Math.round(x) >>> 0)))), mathy3(x, x)) ? Math.fround(Math.atan2(0x07fffffff, Math.fround(x))) : Math.atan(Math.fround(y))), ( + (Math.max((Math.min(x, (Math.acosh((x | 0)) | 0)) >>> 0), ((( + -Number.MAX_VALUE) ? (( ! y) >>> 0) : Math.fround(( - Math.fround(x)))) >>> 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy5, [(new Number(-0)), [0], [], 0, 1, undefined, -0, NaN, false, null, objectEmulatingUndefined(), '0', (new Boolean(true)), /0/, '', (new Number(0)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), 0.1, (new String('')), '/0/', ({valueOf:function(){return 0;}}), true, (function(){return 0;}), '\\0', (new Boolean(false))]); ");
/*fuzzSeed-244067732*/count=596; tryItOut("\"use strict\"; for(a in x.lastIndexOf((/*RXUE*//(?:(?=(?=^|\\s)${0}+?{4,549755813891}))/gym.exec(\"___\")), x)) /*oLoop*/for (zeecfw = 0, kpnmkg; zeecfw < 107; ++zeecfw) { for (var v of m1) { try { a0 = Array.prototype.concat.call(this.a0, t0, o1.t2, a0, t0, v2, this, p1); } catch(e0) { } try { a1.splice(5, window, h0,  /x/g ); } catch(e1) { } s1 += s2; } } ");
/*fuzzSeed-244067732*/count=597; tryItOut("g2 + '';");
/*fuzzSeed-244067732*/count=598; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Uint8ArrayView[((abs((((0xa5e689ab)*-0x126bc) ^ ((!(0xf9b0e654)))))|0) / (((0x5479a912) / (0x490e702f)) >> (((void options('strict')) /= /*UUV1*/(x.call = \"\\uBAAA\"))))) >> 0]) = ((0xfe1e6a84));\n    return (((0xfbced1ce)))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MIN_VALUE, 2**53-2, -0x100000000, -0x07fffffff, 1/0, 1.7976931348623157e308, 42, Math.PI, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), 0x100000000, -1/0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, 0x080000001, Number.MAX_VALUE, 0/0, 0.000000000000001, 2**53, -0, -0x080000000, 0, 1, 2**53+2, Number.MIN_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-244067732*/count=599; tryItOut("/*infloop*/for(x in ((q => q)( ? (4277) : (new ( /x/  /=  /x/ )((4277))))))Array.prototype.shift.apply(a2, [b0]);");
/*fuzzSeed-244067732*/count=600; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=601; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.fround(mathy3(Math.fround(( ~ (Math.sinh(y) | 0))), Math.fround(Math.atan2(( - Math.fround(y)), y)))) - Math.fround(Math.log10(Math.fround(Math.fround(( ~ Math.fround(Math.fround((Math.fround(y) === (( + ( ! ( + x))) | 0)))))))))); }); testMathyFunction(mathy4, /*MARR*/[ /x/g , x, x, x, x, x, x, x,  /x/g , x, x, x,  /x/g , x, x,  /x/g , x, x,  /x/g ,  /x/g , x, x, x, x, [1], x, x, x,  /x/g , x,  /x/g , [1], x,  /x/g , x, x, x, x, x, x]); ");
/*fuzzSeed-244067732*/count=602; tryItOut("testMathyFunction(mathy4, [-0x100000001, -0x080000001, -1/0, -(2**53), Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 2**53, 42, 0x100000001, 1, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, -0, 0x07fffffff, 1/0, -0x07fffffff, Math.PI, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, 0, 0/0, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=603; tryItOut("m1.has(g2);");
/*fuzzSeed-244067732*/count=604; tryItOut("\"use strict\"; print(Math.imul((Object.defineProperty(e, x + new RegExp(\".|${17179869185,}{0,4194304}|(?=\\\\3)\", \"yim\"), ({}))), x));let x = /*MARR*/[[1], [1], Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new String('q'), [1], new String('q'), new String('q'), [1], objectEmulatingUndefined(), [1], new String('q'), new String('q'), Infinity, Infinity, new String('q'), new String('q'), new String('q'), [1], objectEmulatingUndefined(), new String('q'), [1], objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], new String('q'), [1], new String('q'), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), new String('q'), Infinity, Infinity, new String('q'), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new String('q'), objectEmulatingUndefined(), new String('q'), [1], Infinity, new String('q'), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), [1], new String('q'), Infinity, Infinity, Infinity, [1], Infinity, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), Infinity, objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), [1], new String('q'), objectEmulatingUndefined(), [1], Infinity, Infinity, new String('q'), Infinity, new String('q'), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), [1]].some(q => q);");
/*fuzzSeed-244067732*/count=605; tryItOut("");
/*fuzzSeed-244067732*/count=606; tryItOut("\"use strict\"; a1.unshift(g0.t2, v1);");
/*fuzzSeed-244067732*/count=607; tryItOut("b1 = new ArrayBuffer(48);");
/*fuzzSeed-244067732*/count=608; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4(Math.imul((( + ( + y)) | 0), ( ~ Math.min(y, Math.imul(y, Math.fround(-Number.MAX_VALUE))))), (Math.min(x, ((x / (-Number.MAX_SAFE_INTEGER ? ( + x) : y)) + ( + mathy3(( + 0x0ffffffff), Math.imul(y, x))))) || Math.pow((( - x) - Math.fround(( ! Math.fround(x)))), (( ! ( + mathy0(( + y), ( + ( + Math.imul(( + y), 0x100000000)))))) | (Math.sign(( + -(2**53))) | 0))))); }); testMathyFunction(mathy5, [1/0, 2**53, -0, 1, 0x080000001, -0x080000000, -0x07fffffff, -1/0, 2**53+2, 0x100000001, 42, -Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53-2), Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, 0x080000000, -0x100000000, Math.PI, -0x080000001, 0/0, -Number.MIN_VALUE, 2**53-2, -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=609; tryItOut("\"use strict\"; { void 0; void gc('compartment'); }");
/*fuzzSeed-244067732*/count=610; tryItOut("mathy1 = (function(x, y) { return ((((((((( ~ 1/0) ? 0x080000001 : -0x0ffffffff) | 0) == (y | 0)) / ( + Math.atan(( + ( + Math.log(( + x))))))) | 0) && ( + Math.sinh(( + ( ! (( ! (y >>> 0)) >>> 0)))))) | 0) != (Math.atan((Math.min(Math.fround(Math.tanh((0x080000001 && Math.expm1(x)))), x) | 0)) | 0)); }); testMathyFunction(mathy1, [[0], -0, NaN, [], undefined, '0', ({valueOf:function(){return '0';}}), (new Number(0)), objectEmulatingUndefined(), (new String('')), 0.1, 1, ({toString:function(){return '0';}}), (new Number(-0)), true, null, (function(){return 0;}), false, (new Boolean(true)), /0/, '', 0, '\\0', (new Boolean(false)), '/0/', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-244067732*/count=611; tryItOut("((4277));");
/*fuzzSeed-244067732*/count=612; tryItOut("mathy4 = (function(x, y) { return (((Math.atan((( + mathy1(x, (Math.cos((x >>> 0)) >>> 0))) >>> 0)) >>> 0) << (Math.expm1(Math.fround(( + ( ~ ( + ((y === (Math.hypot(mathy0(x, ( + (( + -Number.MIN_VALUE) ? ( + y) : ( + x)))), x) | 0)) | 0)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-244067732*/count=613; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.clz32(( + Math.cbrt(Math.asinh(Math.min(y, Math.hypot(( + ( - y)), ( + x)))))))); }); testMathyFunction(mathy4, [2**53, -0x080000000, 0.000000000000001, -(2**53+2), 0x080000001, 42, -0x100000000, 0x07fffffff, -0x080000001, -1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000001, 1/0, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, 2**53-2, 1, 0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 0/0, -Number.MAX_VALUE, -0, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-244067732*/count=614; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ! ( + (Math.sinh(( + ( + ( + x)))) | 0))) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[new String('q'),  '' , new String('q'),  '' , new String(''), new String(''), new String(''),  '' , new String('q'), new String('q'), new String('q'), new String(''), new String(''),  '' ,  '' , new String('q'), new String(''), new String(''), new String('q'), new String('q'), new String(''), new String('q'), new String('q'), new String('q'),  '' ,  '' , new String('q'),  '' , new String('q'), new String('q'), new String('q'), new String('q'), new String(''),  '' , new String('q'), new String(''), new String('q'), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''),  '' , new String('q'), new String(''), new String('q'), new String(''),  '' ,  '' , new String(''), new String(''), new String(''),  '' , new String(''),  '' , new String('q'), new String(''), new String(''), new String('q'), new String(''), new String('q'), new String(''),  '' ,  '' , new String('q'), new String('q'),  '' , new String('q'), new String('q'), new String('q'),  '' ,  '' , new String('q'),  '' , new String(''), new String('q'), new String(''), new String('q'), new String('q'), new String('q'),  '' , new String(''),  '' , new String('q'), new String(''),  '' ,  '' , new String(''),  '' ,  '' , new String(''), new String(''),  '' , new String('q'), new String(''),  '' , new String('q'), new String('q'), new String('q'), new String('')]); ");
/*fuzzSeed-244067732*/count=615; tryItOut("mathy0 = (function(x, y) { return ( + ( + (( + (y > y)) - (( + Math.sqrt(( + (Math.fround((Math.cos(y) ? (( - (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) : x)) <= Math.fround(x))))) >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[(-1/0),  /x/g ,  /x/g , undefined, -3/0, undefined, -3/0]); ");
/*fuzzSeed-244067732*/count=616; tryItOut("let (ujrxrb, e = print(x);, amddun, d = (e >= NaN), jzovor, c =  /x/g , kmybhx, window) { v1 = (o0 instanceof h2); }");
/*fuzzSeed-244067732*/count=617; tryItOut("\"use strict\"; testMathyFunction(mathy4, [42, 1/0, 0.000000000000001, -0x080000000, -0x080000001, 0x0ffffffff, Math.PI, -0, -1/0, 0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, Number.MAX_VALUE, 0x080000001, -0x100000000, -(2**53-2), 0x080000000, 0x07fffffff, 0, Number.MIN_VALUE, 2**53, -0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), 1, 0/0, 2**53-2, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=618; tryItOut("/*vLoop*/for (let odsdca = 0; odsdca < 22; x, ++odsdca) { let w = odsdca; (null); } ");
/*fuzzSeed-244067732*/count=619; tryItOut("{g1.offThreadCompileScript(\"x\");\u000d }");
/*fuzzSeed-244067732*/count=620; tryItOut("mathy0 = (function(x, y) { return Math.asinh(Math.sin(Math.fround(Math.fround((Math.fround(Math.atan((((Number.MIN_VALUE | 0) ? y : x) >>> 0))) === (Math.tan(y) && (Math.log10((x >>> 0)) | 0))))))); }); testMathyFunction(mathy0, [2**53+2, Number.MAX_VALUE, 1, 0x080000000, 0x0ffffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, Number.MIN_VALUE, 1/0, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), 42, -0, -0x080000001, 0x080000001, 0, 0x100000000, 0x07fffffff, -(2**53-2), -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, -0x100000001, 0/0]); ");
/*fuzzSeed-244067732*/count=621; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = ((~(((((0xe7b8a5bb)+(0xd34f9794)+(0x16681cd4)) << ((0x2433a906)*0x93cc1)) < (((/*FFI*/ff()|0)) >> ((0x5f5a3c91) % (0x638a99a1))))+(let (a)  /x/g )-(i2))));\n    i0 = (0x8a7e3173);\n    i0 = ((0xa1ad1b76));\n    i2 = ((-0x5b69865) > (~((((Float32ArrayView[1]))))));\n    {\n      {\n        i2 = (i2);\n      }\n    }\n    i2 = (0xff7b0a31);\n    {\n      d1 = (2.0);\n    }\n    {\n      return +((-33554431.0));\n    }\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: function shapeyConstructor(ndfqdu){delete ndfqdu[\"valueOf\"];Object.defineProperty(ndfqdu, \"constructor\", ({enumerable: (x % 15 != 9)}));return ndfqdu; }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[/*UUV1*/(x.getMonth = new Function), 2**53,  \"use strict\" , 2**53, 2**53, 2**53, /*UUV1*/(x.getMonth = new Function), 2**53,  \"use strict\" , /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), (1/0),  \"use strict\" , /*UUV1*/(x.getMonth = new Function),  \"use strict\" , /*UUV1*/(x.getMonth = new Function),  \"use strict\" ,  \"use strict\" , /*UUV1*/(x.getMonth = new Function), (1/0), (1/0), 2**53, 2**53, 2**53, 2**53, 2**53, (1/0), /*UUV1*/(x.getMonth = new Function), 2**53, function(){}, function(){}, /*UUV1*/(x.getMonth = new Function), 2**53, 2**53, /*UUV1*/(x.getMonth = new Function), function(){}, function(){}, 2**53, /*UUV1*/(x.getMonth = new Function), (1/0), /*UUV1*/(x.getMonth = new Function), function(){}, /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function),  \"use strict\" ,  \"use strict\" , /*UUV1*/(x.getMonth = new Function), 2**53, 2**53, 2**53, (1/0), /*UUV1*/(x.getMonth = new Function), (1/0), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), (1/0), (1/0), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), (1/0),  \"use strict\" , /*UUV1*/(x.getMonth = new Function),  \"use strict\" , 2**53,  \"use strict\" , function(){}, 2**53, (1/0), 2**53, function(){}, (1/0), 2**53, /*UUV1*/(x.getMonth = new Function), 2**53, 2**53, /*UUV1*/(x.getMonth = new Function), 2**53, 2**53, 2**53, (1/0), function(){},  \"use strict\" , 2**53,  \"use strict\" , (1/0), function(){}, 2**53, /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), function(){}, 2**53,  \"use strict\" , /*UUV1*/(x.getMonth = new Function),  \"use strict\" , /*UUV1*/(x.getMonth = new Function),  \"use strict\" , /*UUV1*/(x.getMonth = new Function), (1/0), /*UUV1*/(x.getMonth = new Function),  \"use strict\" , (1/0), function(){}, /*UUV1*/(x.getMonth = new Function), (1/0),  \"use strict\" , function(){}, /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), (1/0),  \"use strict\" , function(){}, /*UUV1*/(x.getMonth = new Function), 2**53, function(){}, (1/0), 2**53, /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function), /*UUV1*/(x.getMonth = new Function),  \"use strict\" , (1/0), function(){}, (1/0), function(){},  \"use strict\" , function(){}]); ");
/*fuzzSeed-244067732*/count=622; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=623; tryItOut("/*MXX3*/g1.Object.keys = g2.Object.keys;");
/*fuzzSeed-244067732*/count=624; tryItOut("/*RXUB*/var r = /(?:((\\B+?^|[\\w\u00eb\u00e4\\f-\ubaf9])))[^]{32767,32770}.[^\u96a2-\ue6c3\\cI-\u3217\\u00fA-\\u2c5C\\d]|$[\\w]+?+\\B|$^{3,}(?:\\B*(?!(.{4095,4099})){4})/gym; var s = \"\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-244067732*/count=625; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=626; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(a2, v0);");
/*fuzzSeed-244067732*/count=627; tryItOut("testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, -Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, -1/0, 2**53-2, -(2**53), 1, 1.7976931348623157e308, 0x100000000, -0, -0x100000001, -0x080000000, 0x0ffffffff, 42, Number.MAX_VALUE, 0, -0x0ffffffff, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, Math.PI, 0x07fffffff, -0x100000000, 2**53, -0x07fffffff, 1/0, -(2**53-2), Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-244067732*/count=628; tryItOut("s2 += s0;");
/*fuzzSeed-244067732*/count=629; tryItOut("/*infloop*/for(var x; x; (Number.parseFloat())) {{ void 0; void relazifyFunctions('compartment'); } h0.enumerate = (function mcc_() { var xoycgs = 0; return function() { ++xoycgs; if (/*ICCD*/xoycgs % 11 == 2) { dumpln('hit!'); try { new RegExp(\"(((?!.)[^]|\\\\B|$)*?)|([\\\\s\\u739b-\\\\uD1E5\\\\s]|[^]?\\\\W)|.\\\\B(?!.)+?\\\\b[^]\", \"gim\"); } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } p0 + g0.t2; } else { dumpln('miss!'); try { selectforgc(this.o2); } catch(e0) { } try { ; } catch(e1) { } try { v1 = (f1 instanceof o2.f2); } catch(e2) { } o1 = a1[0]; } };})();this.a2 = /*MARR*/[0/0, true,  '\\0' , function(){}, x,  '\\0' ]; }");
/*fuzzSeed-244067732*/count=630; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=631; tryItOut("\"use strict\"; m0.get(g0.b2);");
/*fuzzSeed-244067732*/count=632; tryItOut("\"use strict\"; g0.e2.add(a1);");
/*fuzzSeed-244067732*/count=633; tryItOut(" for  each(var a in -15) {(window);a2.length = 15; }");
/*fuzzSeed-244067732*/count=634; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.pow(( + Math.imul(Math.fround(Math.pow(Math.fround(-(2**53-2)), Math.fround(( - (y | 0))))), ( + (Math.fround(42) ? Math.fround((y > ( + 1))) : Math.fround(x))))), (Math.imul((x ^ 2**53-2), ( + Math.imul((Math.sqrt((0x0ffffffff >>> 0)) >>> 0), ( + Math.imul(Math.PI, y))))) >>> 0)) | ( + mathy4(( + ((Math.min(Math.fround(( ~ ( + Math.max(0x100000001, ( + x))))), Math.pow(x, Math.min(y, ( + x)))) >>> 0) && (Math.fround(Math.asin(y)) >>> 0))), ( + Math.fround(Math.pow(Math.fround(( ! 0x080000000)), Math.fround(((y !== x) ? y : ( + Math.sinh(( + ( + Math.sign(( + 2**53+2)))))))))))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -1/0, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, -0, -Number.MAX_VALUE, 0/0, 0x080000000, 0.000000000000001, 1.7976931348623157e308, 42, 2**53, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53), 1, Math.PI, 0x07fffffff, Number.MAX_VALUE, -0x100000001, -0x07fffffff, 1/0, -0x100000000, 2**53-2, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, 0x100000000]); ");
/*fuzzSeed-244067732*/count=635; tryItOut("testMathyFunction(mathy1, [2**53-2, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, -(2**53), 1/0, -0x07fffffff, 0x080000000, -0, Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, 0/0, -(2**53+2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1, 0, -0x100000000, 0x07fffffff, 0x080000001, 2**53]); ");
/*fuzzSeed-244067732*/count=636; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-244067732*/count=637; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[(0/0), (0/0), (1/0), function(){}, function(){}, function(){}, [(void 0)], (0/0), [(void 0)], false, false, false, (0/0), [(void 0)], (1/0), (1/0), (1/0), function(){}, function(){}, [(void 0)], [(void 0)], [(void 0)], (0/0), [(void 0)], function(){}, (1/0), [(void 0)], (0/0), function(){}, [(void 0)], (1/0), function(){}, (0/0), (1/0), false, (1/0), (0/0), [(void 0)], (1/0), [(void 0)], [(void 0)], false, (0/0), function(){}, false, (0/0), [(void 0)], [(void 0)], [(void 0)], false, [(void 0)], [(void 0)], false, (1/0), (1/0), (1/0), false, [(void 0)], (1/0), false, (1/0), function(){}, function(){}, false, false, false]) { yield; }");
/*fuzzSeed-244067732*/count=638; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.acos(Math.fround(Math.hypot((Math.acosh(mathy1(((y % (( + Math.fround(x)) >>> 0)) >>> 0), Math.sqrt(y))) ? (Math.max(x, y) | 0) : y), ((((( + ( ! ( + x))) | 0) ** (0x100000001 | 0)) | 0) * ( + (( + Math.pow(Math.clz32((Math.fround(Math.tanh(Math.fround(y))) | 0)), (Math.exp((y | 0)) | 0))) == y))))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -(2**53+2), Math.PI, -1/0, 1/0, 0x0ffffffff, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, 1.7976931348623157e308, -0x100000001, 0.000000000000001, 0x080000001, 0x100000000, 1, -Number.MAX_VALUE, -0x080000000, 0x080000000, -0x100000000, 0x100000001, -0, 2**53+2, -0x07fffffff, -(2**53-2), 2**53, 0, -0x080000001]); ");
/*fuzzSeed-244067732*/count=639; tryItOut("mathy1 = (function(x, y) { return (( ~ ( + (( + Math.hypot(Number.MAX_SAFE_INTEGER, Math.atan2((((-0x100000000 | 0) ** (y | 0)) | 0), Math.min(Math.fround(Math.fround(Math.log1p(Math.fround(y)))), Math.fround((1/0 ? y : ( + x))))))) || ( + (( ~ (Math.fround(Math.max(Math.fround(-0), y)) | 0)) ? Math.log10(Math.fround((y !== Math.fround(x)))) : ( + x)))))) | 0); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 0.000000000000001, -0x100000001, 0x07fffffff, 42, Number.MAX_VALUE, 0x100000000, -(2**53), 0x080000000, -0x100000000, 0/0, 0, 2**53-2, -Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 1.7976931348623157e308, -0, 1/0, -Number.MAX_VALUE, -(2**53-2), -0x080000001, -(2**53+2), -0x0ffffffff, -0x07fffffff, -0x080000000, 1]); ");
/*fuzzSeed-244067732*/count=640; tryItOut("\"use strict\"; if(true) {delete i0[\"9\"];this.g0.m1.has(p0); } else  if (function(id) { return id }) v1 = Object.prototype.isPrototypeOf.call(o0, p1);");
/*fuzzSeed-244067732*/count=641; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[(0/0), true, (0/0),  ''  ? /\\w\\s/gim : true]) { v0 = (s0 instanceof b2); }");
/*fuzzSeed-244067732*/count=642; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.min(Math.fround((((Math.acosh(((( ~ (-(2**53) | 0)) | 0) << -Number.MIN_SAFE_INTEGER)) <= (( ~ (x | 0)) | 0)) >>> 0) * ( + ( + ( + ( + y)))))), Math.fround((( + ((Math.pow((( - -1/0) >>> 0), (Math.max((-1/0 >>> 0), Math.sign(0x07fffffff)) >>> 0)) >>> 0) | 0)) / ( + ( ! ( + Math.max((( + ( ~ y)) ? (y | 0) : Math.fround(( ~ Math.fround(x)))), x)))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, 1, 0/0, 0x0ffffffff, 0x100000001, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 42, -Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), 0x080000000, -0, 0.000000000000001, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000000, -0x080000000, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, -1/0, Number.MAX_VALUE, 0x07fffffff, 0, -0x100000000, -(2**53), -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=643; tryItOut("g1.v0 = evalcx(\"b1 = new ArrayBuffer(136);\", g0);");
/*fuzzSeed-244067732*/count=644; tryItOut("testMathyFunction(mathy3, /*MARR*/[ /x/g , -(2**53-2), -(2**53-2), true, -(2**53-2), new Boolean(true), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), true, true]); ");
/*fuzzSeed-244067732*/count=645; tryItOut("let y, z, vzvefe, b =  '' , b = x, eval, bhlnwa, nzppee, vplpnb;{ void 0; fullcompartmentchecks(false); }");
/*fuzzSeed-244067732*/count=646; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(( ! Math.round(( + x))), Math.fround(( + Math.round(( + Math.ceil(( + x)))))))); }); testMathyFunction(mathy1, [-(2**53), -0x0ffffffff, 0/0, -1/0, 2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 1/0, 0x100000000, 0x080000000, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, 42, -0, 1, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -0x080000001, -(2**53+2), 2**53-2]); ");
/*fuzzSeed-244067732*/count=647; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[null, null, new String('q'), -Number.MAX_VALUE, new String('q'), -Number.MAX_VALUE, -Number.MAX_VALUE, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, -Number.MAX_VALUE]) { (void schedulegc(g2)); }");
/*fuzzSeed-244067732*/count=648; tryItOut("mathy0 = (function(x, y) { return (Math.max(Math.pow(x, ( + (( - ((2**53-2 + x) >>> 0)) >>> 0))), Math.fround(((((x !== x) | 0) , (Math.fround(Math.tan(Math.fround((Math.imul(( + -(2**53)), x) >>> 0)))) | 0)) | 0))) == ( + (Math.fround((Math.fround(Math.min(( + (( + x) !== ( + y))), (Math.max((0x0ffffffff | 0), (( + ( ! Math.fround(-Number.MIN_SAFE_INTEGER))) | 0)) | 0))) ? ( + (( + x) && y)) : Math.exp(y))) - ( + (Math.cosh(Number.MIN_VALUE) ? x : y))))); }); testMathyFunction(mathy0, [(new Boolean(false)), (new String('')), (new Number(-0)), 1, false, -0, (new Number(0)), 0.1, '/0/', ({valueOf:function(){return '0';}}), true, '', [], [0], undefined, null, objectEmulatingUndefined(), ({toString:function(){return '0';}}), (function(){return 0;}), 0, ({valueOf:function(){return 0;}}), /0/, (new Boolean(true)), '\\0', '0', NaN]); ");
/*fuzzSeed-244067732*/count=649; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-244067732*/count=650; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -0x100000000, 0x100000000, 42, -0x080000000, -0x100000001, 0, Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -Number.MAX_VALUE, 0x0ffffffff, 0x080000000, -0x0ffffffff, -1/0, 2**53-2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -(2**53-2), 0/0, -Number.MIN_VALUE, -0, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, -(2**53), 1/0, 0.000000000000001, 1]); ");
/*fuzzSeed-244067732*/count=651; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?:(?!\\\\2|$?+?)))\", \"im\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-244067732*/count=652; tryItOut("h1.delete = f2;\na2[8] = f1;\n");
/*fuzzSeed-244067732*/count=653; tryItOut("testMathyFunction(mathy2, /*MARR*/[4.]); ");
/*fuzzSeed-244067732*/count=654; tryItOut("mathy1 = (function(x, y) { return Math.imul((Math.log(( ~ y)) | 0), Math.hypot((Math.max(x, ( ~ (( + mathy0(( + x), ( + y))) | 0))) | 0), ( ! 0x07fffffff))); }); testMathyFunction(mathy1, [0x0ffffffff, 0x080000001, 42, Number.MIN_VALUE, -(2**53-2), 2**53-2, -Number.MIN_VALUE, 0, -0x080000001, 2**53+2, -0x100000000, 1, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, -(2**53+2), -0x080000000, -1/0, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0/0, -Number.MAX_VALUE, 0x07fffffff, 2**53, -0x100000001, 0x100000000, Math.PI, Number.MAX_VALUE, 0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=655; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((Math.exp((( ! ( ~ Math.fround(Math.acos(Math.fround((Math.max((y >>> 0), (x >>> 0)) >>> 0)))))) | 0)) | 0) ? (mathy1(Math.hypot(x, ((Math.log10(y) | 0) >>> 0)), (Math.sin(x) | 0)) | 0) : (mathy1(((Math.fround(Math.atanh(x)) === Math.fround(mathy1(Math.fround(y), (x | 0)))) ? Math.sign(Number.MIN_VALUE) : (((y < -(2**53)) ? (( ! (-(2**53+2) >>> 0)) >>> 0) : Math.trunc(x)) | 0)), (((y >>> 0) ? (( - (( ~ ( + 0x080000000)) , Math.tanh(y))) >>> 0) : ( + mathy0(( + y), (mathy1(x, 1.7976931348623157e308) | 0)))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy2, [-0, 0x0ffffffff, 0/0, Math.PI, 0, 2**53+2, 1.7976931348623157e308, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 1/0, 2**53, -0x100000000, -0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000000, 0x100000000, 42, 0x100000001, 1, -1/0, -0x100000001, 2**53-2, Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=656; tryItOut("\"use strict\"; i1 + '';");
/*fuzzSeed-244067732*/count=657; tryItOut("/*MXX1*/o2 = g2.RangeError.prototype;");
/*fuzzSeed-244067732*/count=658; tryItOut("t2[7] = o0;");
/*fuzzSeed-244067732*/count=659; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=660; tryItOut("\"use strict\"; m1.get(m0);a2.unshift(a2);");
/*fuzzSeed-244067732*/count=661; tryItOut("i2.send(s1);function x(c = window, ...d)\"use asm\";   var NaN = stdlib.NaN;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      i0 = (i0);\n    }\n    i2 = (0x9305f4db);\n    {\n      i2 = ((i2) ? (i0) : (i0));\n    }\n    switch ((((1)) >> (((0x4201329e) >= (0x3b6883ba))+(0x7907f8e6)))) {\n      case 1:\n        i2 = ((i0) ? (0x44ed1e44) : ((0x67e1d8fe) > (((0xb1aa1f5a)-(0xfc5498f3)+(1))>>>((({w: x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: arguments.callee, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: objectEmulatingUndefined, keys: function() { return Object.keys(x); }, }; })(y), window - {}),  get x(x, x) /x/g  }))))));\n        break;\n      default:\n        d1 = (((1.03125)) / (((i2) ? (NaN) : (d1))));\n    }\no2 + e2;    return (((((i2))>>>((i2))) / (0xffffffff)))|0;\n  }\n  return f;a1.splice(-5, 18);");
/*fuzzSeed-244067732*/count=662; tryItOut("testMathyFunction(mathy1, [Number.MAX_VALUE, 0x100000000, 0x080000001, -0x080000001, -(2**53-2), -(2**53+2), 0x100000001, 0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, 0/0, -0x100000000, 2**53, 2**53-2, Number.MIN_VALUE, Math.PI, -0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -0x080000000, 42, 2**53+2]); ");
/*fuzzSeed-244067732*/count=663; tryItOut("var kzqyrr = new SharedArrayBuffer(16); var kzqyrr_0 = new Uint32Array(kzqyrr); print(kzqyrr_0[0]); kzqyrr_0[0] = 25; g0.o1.v0 = Object.prototype.isPrototypeOf.call(h0, v1);");
/*fuzzSeed-244067732*/count=664; tryItOut("/*hhh*/function dcalke(){this.s2 += s2;}/*iii*/Object.preventExtensions(o1.t0);");
/*fuzzSeed-244067732*/count=665; tryItOut("\"use asm\"; m0.set((e = (let (gjnngj) window)), this.t2);");
/*fuzzSeed-244067732*/count=666; tryItOut("o2.v0 = null;");
/*fuzzSeed-244067732*/count=667; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! ( + (Math.hypot((( + ( - (( + ( + ( + x))) | 0))) >>> 0), (( + Math.imul(( + y), ( + -0))) >>> 0)) | 0))); }); testMathyFunction(mathy0, [42, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -(2**53-2), -0, -0x100000000, -Number.MIN_VALUE, 1, -(2**53), -0x080000001, -0x100000001, -0x0ffffffff, 0, 0x100000001, -1/0, 2**53, -(2**53+2), 1.7976931348623157e308, 2**53-2, 2**53+2, 0x080000001]); ");
/*fuzzSeed-244067732*/count=668; tryItOut("mathy4 = (function(x, y) { return Math.cosh((( + Math.min(-(2**53), x)) < ( + Math.hypot(x, (Math.cos(( + y)) | 0))))); }); testMathyFunction(mathy4, /*MARR*/[null, new Boolean(true), new String('q')]); ");
/*fuzzSeed-244067732*/count=669; tryItOut("var w = Math.fround(((Math.imul((x | 0), (-0x100000000 | 0)) | 0) >>> 0));a1.valueOf = (function() { try { a0.push(e1); } catch(e0) { } f1.__iterator__ = (function() { t0 = new Int8Array(b2); return m0; }); return this.p2; });");
/*fuzzSeed-244067732*/count=670; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + (((Math.sqrt(Math.fround((Math.clz32(x) - Math.tanh(Math.fround((Math.sqrt((x | 0)) | 0)))))) | 0) | 0) >= (((((Number.MIN_SAFE_INTEGER ** Math.imul((y >>> 0), y)) >>> 0) << (mathy0(( + -0x100000001), (Math.fround(Math.imul((Math.imul(y, (y | 0)) >>> 0), Math.fround(Math.fround(( ! y))))) | 0)) | 0)) >>> 0) ** ( ! (Math.fround(x) << Math.fround(Math.cbrt((x | 0)))))))); }); ");
/*fuzzSeed-244067732*/count=671; tryItOut("g1.offThreadCompileScript(\"this.s1 += o1.s0;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: [z1], noScriptRval: (x % 6 != 5), sourceIsLazy: true, catchTermination: (x % 3 == 2) }));");
/*fuzzSeed-244067732*/count=672; tryItOut("b");
/*fuzzSeed-244067732*/count=673; tryItOut("mathy5 = (function(x, y) { return Math.abs(Math.min((Math.sqrt((Math.ceil(y) >>> 0)) >>> 0), (Math.abs(x) === ( + Math.exp(( + Math.atan2(0, (-(2**53-2) | 0)))))))); }); ");
/*fuzzSeed-244067732*/count=674; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ceil = stdlib.Math.ceil;\n  var atan2 = stdlib.Math.atan2;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1125899906842623.0;\n    return (((/*FFI*/ff(((((0xfa1b75e5)*-0x4dddd) | (((imul(((-0x8000000) ? (0xfabf5a5f) : (0xfea2e080)), (/*FFI*/ff()|0))|0) != (~((0xf8fcc5d5)-((0xbe8d4f12) ? (0xf00ed42f) : (0x9ea0ebb3)))))))), ((0x7fffffff)), ((((Infinity)) / ((d0)))), ((d2)), ((abs((((-0x8000000)) | ((0xeb03c0b1))))|0)), (((((-140737488355329.0)) - ((7.555786372591432e+22))) + (((9.671406556917033e+24)) * ((576460752303423500.0))))), ((+ceil(((d2))))), ((+((d0)))), ((Infinity)))|0)))|0;\n    d2 = (-1099511627776.0);\n    d0 = ((Uint16ArrayView[((0xfdb2e5d8)) >> 1]));\n    d1 = (+((Float64ArrayView[4096])));\n    d1 = (+abs(((d1))));\n    d1 = (+atan2((((d0) + (+pow(((d1)), ((Infinity)))))), ((x))));\n    return ((((d0) < (d1))+(b = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: z => function(id) { return id }, delete: function() { throw 3; }, fix: function() { throw 3; }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate:  '' , keys: undefined, }; })( '' ), objectEmulatingUndefined))))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [(new Number(-0)), '0', true, '', 0, ({toString:function(){return '0';}}), [], false, ({valueOf:function(){return '0';}}), (function(){return 0;}), (new Boolean(false)), /0/, null, -0, [0], undefined, 0.1, NaN, 1, (new String('')), (new Boolean(true)), (new Number(0)), '/0/', ({valueOf:function(){return 0;}}), '\\0', objectEmulatingUndefined()]); ");
/*fuzzSeed-244067732*/count=675; tryItOut("for (var p in g1) { try { v2 = Object.prototype.isPrototypeOf.call(t1, this.h2); } catch(e0) { } Object.prototype.watch.call(v2, \"__proto__\", f0); }\n \"\" \n");
/*fuzzSeed-244067732*/count=676; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy1(((Math.tan(( + ( + Math.fround(( + Math.fround(Math.fround((Math.fround(y) === Math.fround(x))))))))) >= Math.asinh(( ~ y))) >>> 0), (( + (( + Math.atan2((Math.acosh((( + (( + ( + ( - Math.fround(x)))) & x)) | 0)) | 0), 1/0)) , ( + ( ! y)))) | 0)) >>> 0); }); ");
/*fuzzSeed-244067732*/count=677; tryItOut("");
/*fuzzSeed-244067732*/count=678; tryItOut("t1[6] = eval(\"v2 = this.a1.length;\", x);");
/*fuzzSeed-244067732*/count=679; tryItOut("arguments.callee");
/*fuzzSeed-244067732*/count=680; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"((?!\\\\b+?))\", \"gm\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-244067732*/count=681; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (((Math.atan2(Math.fround(Math.fround(Math.imul((( ! ((Math.fround(((x < -0x100000001) | 0)) , (x >>> 0)) >>> 0)) >>> 0), ((mathy1(((((Math.atan2(x, (x >>> 0)) >>> 0) % ( - -Number.MIN_VALUE)) >>> 0) | 0), -0x080000001) | 0) >>> 0)))), Math.fround(( + Math.asin(x)))) >>> 0) !== (Math.fround(Math.fround(Math.fround(Math.fround(( + (Math.fround(mathy4(Math.fround(mathy1(( + y), ( + ((-(2**53) | 0) === y)))), Math.fround(y))) >>> 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1.7976931348623157e308, 42, 0x080000000, -1/0, -Number.MAX_VALUE, 0x100000000, -(2**53), -0x07fffffff, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53, Math.PI, 0/0, -Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, -0x0ffffffff, 1/0, 0x080000001, -0x080000000, 2**53-2, 0x100000001, -(2**53-2), -0x080000001, -0, Number.MIN_VALUE, 0, 0x07fffffff, 2**53+2]); ");
/*fuzzSeed-244067732*/count=682; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy1(Math.fround(((Math.imul(mathy2((((Math.exp((y >>> 0)) ** x) ? y : x) | 0), Math.fround(Math.ceil(( + x)))), (Math.fround(mathy0(( + y), ( + (mathy2((x | 0), (Math.PI | 0)) | 0)))) >>> 0)) > ((-0x0ffffffff | 0) === ( + (Math.fround(Math.cos(Math.fround((Math.imul((y | 0), (y | 0)) | 0)))) === ( ~ ( ~ 0x100000001)))))) >>> 0)), (Math.sign((( + Math.imul((((Math.fround((( + y) == -0x07fffffff)) | 0) ** (x | 0)) | 0), x)) >>> 0)) * (( ~ (((x >>> 0) <= (Math.pow((y < (x >>> 0)), (y > x)) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0x0ffffffff, -1/0, -0, 0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, Math.PI, 0x080000001, 0x07fffffff, 0x100000000, -0x100000000, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 1, 2**53+2, -(2**53+2), 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -0x07fffffff, -Number.MAX_VALUE, 1/0, -0x100000001, -0x0ffffffff, 2**53, -(2**53-2), -(2**53), -Number.MIN_SAFE_INTEGER, 42, -0x080000001]); ");
/*fuzzSeed-244067732*/count=683; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.imul(Math.fround(( - Math.fround(Math.min(((Math.sign(x) >>> 0) >>> 0), -0)))), Math.fround(Math.fround(( ! (Math.PI >>> ( + y))))))); }); testMathyFunction(mathy4, [0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, -0x080000001, -0x0ffffffff, -1/0, 0x080000001, Number.MIN_VALUE, -(2**53+2), 2**53+2, 0.000000000000001, -0x07fffffff, 2**53-2, -0, 1, Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, 42, 0x080000000, 0x07fffffff, -0x100000000, -0x100000001, -(2**53), -Number.MIN_VALUE, -0x080000000, 0/0, 1/0]); ");
/*fuzzSeed-244067732*/count=684; tryItOut("throw  \"\" ;");
/*fuzzSeed-244067732*/count=685; tryItOut("testMathyFunction(mathy3, [0x080000000, 0.000000000000001, 0x0ffffffff, -0x100000001, -0x07fffffff, 1.7976931348623157e308, -(2**53-2), 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 0x07fffffff, -0x100000000, -0, 0x100000001, 0, -0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, Math.PI, Number.MAX_VALUE, 1/0, -Number.MAX_VALUE, 0x100000000, 0x080000001, Number.MIN_VALUE, -1/0, 2**53+2, 1, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=686; tryItOut("\"use strict\"; o0.v2 = t2.byteOffset;");
/*fuzzSeed-244067732*/count=687; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  var NaN = stdlib.NaN;\n  var exp = stdlib.Math.exp;\n  var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        i1 = (!(i1));\n      }\n    }\n    d0 = (1.888946593147858e+22);\n    {\n      i1 = ((((i1)*-0xfffff)>>>((i1)*0x420c1)) == (((0x5c6bc292))>>>((i1)*0x2c8a8)));\n    }\n    return (((!((delete c.window).eval(\"mathy0 = (function(x, y) { return ((((( ~ ((Math.atan2(x, Math.fround((( + y) === y))) ? ((x <= 0x080000001) >>> 0) : (y >>> 0)) | 0)) > Math.fround(Math.acos((Math.hypot(((Math.fround(( + Math.fround(( ~ x)))) ^ x) | 0), (Math.fround(Math.cbrt((Math.asinh(Math.fround(Math.imul(Math.fround(x), (-0x0ffffffff | 0)))) >>> 0))) | 0)) | 0)))) | 0) ? ((((( + (y || (Math.fround(x) || (-Number.MAX_SAFE_INTEGER >>> 0)))) | 0) | 0) == ((Math.min((( ~ Math.log2((y >>> 0))) | 0), ((( ~ (Math.imul(x, 0x080000000) | 0)) | 0) | 0)) | 0) != Math.max((x >>> 0), (x >>> 0)))) | 0) : ((( + Math.atan2((y ? Math.fround(y) : ((((x >>> 0) | (x >>> 0)) >>> 0) >>> 0)), Math.fround(Math.fround(Math.asin(y))))) ? (Math.fround(( ~ x)) | 0) : Math.fround((( + Math.fround((Math.fround(-0x080000001) % Math.fround(Math.round(( + ( ! y))))))) <= ((( + Math.ceil(( + y))) & ( + Math.exp(( + (((y < -Number.MAX_SAFE_INTEGER) >>> 0) > Math.cbrt(Math.fround(x))))))) >>> 0)))) | 0)) | 0); }); \").yoyo(({NaN: y}))))*-0x18d3))|0;\n    d0 = (((+sin(((((((d0)) % ((d0)))) - ((-((+((-32769.0))))))))))) - ((-70368744177664.0)));\n    d0 = (-34359738369.0);\n    d0 = (NaN);\n    d0 = (-70368744177665.0);\n    return ((((((0xbc7321aa) ? ((0x61b689ba)) : (i1))+((0x12aa9*(i1)))+(0xffffffff)) >> (-0xf0758*(/*FFI*/ff(((+exp(((+pow(((Float64ArrayView[2])), ((1.1805916207174113e+21)))))))), ((abs((((-0x5ef7788)) & ((0xb874995d))))|0)), ((((0x443cde74)) << ((0xf5809484)))), ((+(0xc1313e14))), ((-34359738367.0)), ((0.125)), ((-2.0)), ((-256.0)), ((-1.001953125)), ((36028797018963970.0)), ((2048.0)), ((562949953421312.0)), ((1.125)), ((-1073741823.0)), ((262145.0)), ((33554432.0)), ((1.2089258196146292e+24)), ((-36028797018963970.0)), ((36028797018963970.0)), ((9223372036854776000.0)), ((-262145.0)), ((1152921504606847000.0)), ((2.0)), ((-2.4178516392292583e+24)), ((-70368744177665.0)), ((-4611686018427388000.0)), ((-590295810358705700000.0)), ((2199023255553.0)), ((3.022314549036573e+23)), ((-8796093022209.0)), ((6.044629098073146e+23)), ((6.044629098073146e+23)), ((8796093022209.0)))|0))) % ((((d0) > (+(1.0/0.0)))) ^ (((~~(((-1.888946593147858e+22)) / (((Float64ArrayView[2]))))) > ((((0x6683b325) > (0x656a6bed))-(0xdc133068)) << (((4277))+(i1))))))))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=688; tryItOut("mathy4 = (function(x, y) { return (((( + (( + mathy3(((y != x) | 0), mathy1(mathy0(x, x), ( + x)))) % Math.max(Math.fround((Math.fround((Math.imul((Math.fround(mathy3(( + y), ( + Math.max(( + x), ( + y))))) | 0), ((( ~ (( + Math.imul(( + -(2**53-2)), x)) >>> 0)) >>> 0) | 0)) | 0)) == Math.fround(Math.min(Math.acosh(( + x)), (Math.min((( + y) | 0), (x | 0)) | 0))))), (( + ( + x)) | 0)))) | 0) && ((Math.max((((Math.fround((Math.fround(Math.hypot(Math.fround(x), (x >>> 0))) ** x)) ? y : Math.fround(Math.atan(x))) == Math.fround(Math.atanh(x))) | 0), (Math.max((Math.tan(( + -1/0)) >>> 0), (( + (mathy0((-0x100000000 >>> 0), ( + mathy2(( + x), ( + ( ~ 0x100000001))))) | 0)) >>> 0)) | 0)) | 0) | 0)) | 0); }); ");
/*fuzzSeed-244067732*/count=689; tryItOut("/*MXX2*/g2.Set.prototype.delete = m2;");
/*fuzzSeed-244067732*/count=690; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xf9947f80);\n    i1 = (0x6d0374e9);\n    d0 = (+(-1.0/0.0));\n    d0 = (-8388607.0);\n    return ((((((d0) <= (2097153.0))-((0xf14259f0))+(i1))>>>((i1))) % (0x37cfe15c)))|0;\n    return (((/*FFI*/ff((((((i1) ? (i1) : ((((0xfea557a1)) ^ ((0x20e0510a)))))+(0x2d2fb406)-(i1)) >> ((i1)))), ((d0)), ((-2147483648.0)), ((~((0x67bcd279)))), ((~~(+((-3.777893186295716e+22))))), ((-2049.0)), ((d0)), ((-512.0)), ((((0xcf41b45d)) ^ ((0xeaaef0d9)))))|0)))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new ArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=691; tryItOut("g1.h2 + '';");
/*fuzzSeed-244067732*/count=692; tryItOut("");
/*fuzzSeed-244067732*/count=693; tryItOut("testMathyFunction(mathy2, [-(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 2**53-2, 2**53, -0x07fffffff, -Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -0x080000000, 1/0, -1/0, 0x100000001, 0x07fffffff, -(2**53), Math.PI, -0x0ffffffff, 1, -0x100000000, 0, -0x080000001, -0x100000001, 0x080000000, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, -0, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-244067732*/count=694; tryItOut("mathy4 = (function(x, y) { return Math.round(Math.pow((((x >>> 0) ? (((( + ( ! x)) | 0) - (x % (0x100000000 >>> 0))) >>> 0) : ((y <= x) | 0)) >>> 0), (Math.max((0/0 | 0), (( - (Number.MAX_VALUE >>> 0)) >>> 0)) | 0))); }); ");
/*fuzzSeed-244067732*/count=695; tryItOut("\"use strict\"; \"use asm\"; delete h1.defineProperty;");
/*fuzzSeed-244067732*/count=696; tryItOut("mathy2 = (function(x, y) { return ( + (( + Math.min(( + Math.fround(Math.asin(Math.fround((mathy0(Math.atan2(y, ( + ( - Math.fround(x)))), ((( ~ Math.fround((((mathy1(x, x) | 0) >= (Math.PI | 0)) | 0))) | 0) | 0)) | 0))))), ( + Math.hypot(( + Math.fround(((Math.cosh((y | 0)) | 0) ? (x | 0) : mathy0(Math.exp(y), y)))), mathy0((mathy1((0.000000000000001 | 0), (( ~ y) | 0)) | 0), (y !== Number.MIN_SAFE_INTEGER)))))) != ( + (Math.atan2(((Math.min(((Math.sin((y | 0)) | 0) >>> 0), (( ~ Math.cos(( + (( - Math.fround(Number.MIN_SAFE_INTEGER)) | 0)))) >>> 0)) | 0) | 0), (((0x07fffffff | 0) !== (( + Math.hypot((x | 0), ( + Math.fround(Math.log(y))))) | 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-244067732*/count=697; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.atan2(((Math.fround(Math.max(( + -(2**53+2)), ( + ( + ( + Math.min((Math.min((-Number.MIN_SAFE_INTEGER >>> 0), (y >>> 0)) >>> 0), Math.fround(x))))))) * Math.hypot((mathy2(x, ((1 ? Math.min(y, x) : (y / 0x07fffffff)) | 0)) | 0), -Number.MAX_SAFE_INTEGER)) >>> 0), (( - (Math.min(y, x) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0x080000000, 0x0ffffffff, -(2**53), 0x100000001, -0x100000000, -(2**53-2), -Number.MAX_VALUE, -0x100000001, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, 42, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, 2**53, -0x0ffffffff, -0, 1, 0.000000000000001, 1/0, 0x100000000, Number.MAX_VALUE, 0]); ");
/*fuzzSeed-244067732*/count=698; tryItOut("mathy3 = (function(x, y) { return ( + ( ! ( + Math.sign((( - Math.atan2(y, x)) == ( ! y)))))); }); testMathyFunction(mathy3, ['', objectEmulatingUndefined(), NaN, true, 0.1, (new Number(-0)), (new Boolean(true)), [0], '/0/', -0, '0', null, ({valueOf:function(){return 0;}}), (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(0)), false, (new String('')), [], (function(){return 0;}), undefined, 0, 1, '\\0', /0/, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-244067732*/count=699; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+(((((((0xc3645c58)) << ((0xbe3b90eb)))) ? (/*FFI*/ff((((1048577.0) + (281474976710656.0))), ((d1)), ((-36028797018963970.0)))|0) : (0x155802a))*-0xe9790) | ((0x428bda54))));\n    return +((Float32ArrayView[(((0xcb690649) == (0xa48bf3a8))-((d0) != (d1))) >> 2]));\n  }\n  return f; })(this, {ff: true}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), '\\0', objectEmulatingUndefined(), 0, 0.1, true, 1, [0], NaN, ({toString:function(){return '0';}}), (new Boolean(true)), (function(){return 0;}), null, '0', /0/, ({valueOf:function(){return '0';}}), '/0/', [], '', false, (new String('')), (new Boolean(false)), (new Number(-0)), undefined, -0, (new Number(0))]); ");
/*fuzzSeed-244067732*/count=700; tryItOut("m2.has(i0);");
/*fuzzSeed-244067732*/count=701; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[\\u0081-\\\\x83\\\\v\\\\D]*?\", \"gym\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-244067732*/count=702; tryItOut("\"use strict\"; ;");
/*fuzzSeed-244067732*/count=703; tryItOut("\"use strict\"; e0 + a0;");
/*fuzzSeed-244067732*/count=704; tryItOut("m0.has(o1.f1);");
/*fuzzSeed-244067732*/count=705; tryItOut("i1.next();");
/*fuzzSeed-244067732*/count=706; tryItOut("mathy4 = (function(x, y) { return (((((mathy2(Math.hypot(x, Math.pow(y, x)), Math.max(Math.acosh(y), Math.fround((Math.fround(y) ** Math.fround(0x0ffffffff))))) && Math.fround(y)) >>> 0) ? (Math.fround(Math.hypot(Math.fround(((( ~ (Math.fround((Math.fround(y) | Math.fround(x))) | 0)) | 0) || mathy3(x, Number.MIN_VALUE))), Math.fround(Math.acos(( + y))))) >>> 0) : ((((Math.max(-0x100000001, (Math.imul(0x07fffffff, ((x | 0) % (y | 0))) | 0)) >>> 0) ? ( ~ x) : Math.expm1(((( - (( + ( + ( + ( + Math.hypot(( + y), Math.fround(x)))))) | 0)) >>> 0) | 0))) >>> 0) >>> 0)) >>> 0) , ( - (Math.trunc((mathy0((x >>> 0), (0x100000000 >>> 0)) >>> 0)) + y))); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), x, x, {}, {}, objectEmulatingUndefined(), {}, x, {}, objectEmulatingUndefined(), {}, x, {}, {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), {}, x, {}, {}, x, {}, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, x, x, {}, x, x]); ");
/*fuzzSeed-244067732*/count=707; tryItOut("testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, -Number.MAX_VALUE, 0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 1, -0x100000001, -0x0ffffffff, 2**53, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, -0, 2**53+2, -1/0, -0x080000000, 0x07fffffff, 42, 0, -Number.MIN_VALUE, 1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, -0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 0/0, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=708; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.cbrt(Math.fround(Math.abs(( + Math.fround(Math.atan2(Math.fround(( + (((Math.pow(0, y) >>> 0) | 0) ? (0.000000000000001 | 0) : (Math.atan2(Math.sin(x), ( - ( + Math.max(( + x), ( + y))))) | 0)))), Math.fround(y))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, 0.000000000000001, 0, 0x100000001, -(2**53+2), -(2**53), -0x080000000, 0/0, 0x0ffffffff, 2**53, 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -Number.MAX_VALUE, -(2**53-2), -0, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, Math.PI, 1, Number.MAX_VALUE, 2**53+2, -0x100000000, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x080000001, 42]); ");
/*fuzzSeed-244067732*/count=709; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - Math.hypot(( - ((x | 0) < (((Math.fround(( - (( + -Number.MAX_SAFE_INTEGER) >>> 0))) === Math.sinh(-(2**53+2))) | 0) | 0))), (Math.pow(( + ( + (Math.fround(Math.min(Math.fround(x), ( + ( ! x)))) >> Math.sqrt(x)))), ( + ( ! Math.abs(Math.fround(Math.exp(0x100000001)))))) | 0))); }); testMathyFunction(mathy0, [-1/0, Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0.000000000000001, 0x080000001, -0x100000001, -0, 42, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), Math.PI, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), 0x0ffffffff, 2**53+2, 0/0, -(2**53+2), 0x100000001, 0x100000000, -0x0ffffffff, Number.MAX_VALUE, 1, 1/0, Number.MIN_VALUE, -0x100000000, -0x080000001, -0x080000000, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-244067732*/count=710; tryItOut("if((x % 2 == 0)) o0 = new Object; else  if ((yield x)) g2 = m2.get((({ get push x (x)(Math.pow(4, 10).__defineGetter__(\"{}\", /*wrap1*/(function(){ \"use strict\"; yield  \"\" ;return encodeURI})())) })));");
/*fuzzSeed-244067732*/count=711; tryItOut("testMathyFunction(mathy1, [0x080000000, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53, 0x0ffffffff, 0x100000001, 1/0, -(2**53), Number.MIN_VALUE, Math.PI, 1, 42, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, 0/0, -0x07fffffff, 0x080000001, 0.000000000000001, 0x07fffffff, 1.7976931348623157e308, -(2**53-2), -(2**53+2), -0x080000000, -0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 2**53-2, -1/0, -0x080000001, 0, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-244067732*/count=712; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.ceil((Math.imul((mathy1(( + ( - ( + ((x | 0) | (y | 0))))), Math.imul(y, ((Math.pow(2**53+2, x) >>> 0) & (x >>> 0)))) | 0), (( + ((( + Math.acosh(( + ( - ( ! y))))) && 0x07fffffff) >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy2, [0/0, 2**53, 2**53-2, 0x080000000, -0x080000001, 1, -0x080000000, 0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, -(2**53), -Number.MAX_VALUE, 2**53+2, -0, 0x080000001, -(2**53+2), 0x100000000, 1/0, Number.MIN_VALUE, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0]); ");
/*fuzzSeed-244067732*/count=713; tryItOut("mathy4 = (function(x, y) { return ( - (( + Math.imul(((y + ( + ( + ( + x)))) % Math.fround(Math.pow(-0, ( + (y ? (1.7976931348623157e308 >>> 0) : x))))), ( + ( - Math.hypot(Math.min(x, -(2**53)), y))))) >>> 0)); }); testMathyFunction(mathy4, [-0, 0, -0x100000000, -1/0, 1.7976931348623157e308, -(2**53+2), 1/0, -0x07fffffff, 2**53, Number.MAX_VALUE, 0/0, -0x080000000, 0.000000000000001, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), 0x100000001, -(2**53), -0x100000001, 0x07fffffff, 42, 1, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 0x0ffffffff, 2**53-2, -Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-244067732*/count=714; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=715; tryItOut("print((4277));");
/*fuzzSeed-244067732*/count=716; tryItOut("var gxundl = new SharedArrayBuffer(32); var gxundl_0 = new Float32Array(gxundl); gxundl_0[0] = 14; var gxundl_1 = new Float32Array(gxundl); var gxundl_2 = new Uint8Array(gxundl); var gxundl_3 = new Uint16Array(gxundl); gxundl_3[0] = 27; var gxundl_4 = new Float64Array(gxundl); var gxundl_5 = new Float64Array(gxundl); print(gxundl_5[0]); gxundl_5[0] = 10; var gxundl_6 = new Float64Array(gxundl); print(gxundl_6[0]); var gxundl_7 = new Int16Array(gxundl); gxundl_7[0] = -6; var gxundl_8 = new Float64Array(gxundl); var gxundl_9 = new Int16Array(gxundl); gxundl_9[0] = -29; this.e0.has(g1);print(gxundl_5[8]);a0[allocationMarker()];v2 = Object.prototype.isPrototypeOf.call(o0.i0, b0);i1 = e1.iterator;t0.set(o0.a0, 15);for (var p in m2) { this.v0 = g2.eval(\"function f2(m0)  { t0.toSource = (function() { for (var j=0;j<21;++j) { this.f2(j%2==0); } }); } \"); }");
/*fuzzSeed-244067732*/count=717; tryItOut("/*RXUB*/var r = new RegExp(\"(?!^)+\", \"gim\"); var s = \"\"; print(r.test(s)); do {/*ADP-3*/Object.defineProperty(a1, x, { configurable: false, enumerable: /*UUV2*/(x.isFinite = x.min), writable: (4277), value: h0 });e2.delete(x); } while((--x) && 0);");
/*fuzzSeed-244067732*/count=718; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    switch (((((0xa8e975c2) <= (0xe2a53682))) | ((0x5009c123) / (-0x5df1ae0)))) {\n      default:\n        i2 = (!(i1));\n    }\n    i1 = (i2);\n    return +((16777217.0));\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0, -(2**53), 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 1, 1/0, 0x100000000, -Number.MAX_VALUE, 2**53+2, -0x100000001, Math.PI, -1/0, 0x080000001, 2**53-2, -0x080000000, -(2**53-2), -(2**53+2), -0x080000001, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-244067732*/count=719; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"\\\"use strict\\\"; mathy3 = (function(x, y) { return Math.hypot(Math.imul(( - Math.fround((((( ~ (y | 0)) | 0) <= x) >>> 0))), ( + ( - ( + y)))), ( ! ((( ~ (((((Math.ceil(y) | 0) >>> 0) ^ (y >>> 0)) >>> 0) | 0)) | 0) >>> 0))); }); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: let (x = this() >>= /(\udc59)\\3/gim) this, noScriptRval: /*FARR*/[...[], ...[],  /x/g , ...[], 28, 29, ...[], this, c, ...[], \"\\u7C62\", \"\u03a0\", ...[],  '' ].sort, sourceIsLazy: x, catchTermination: false, element: o2, sourceMapURL: s1 }));");
/*fuzzSeed-244067732*/count=720; tryItOut("ysvjyu(x, /(?!\\S{1,4})\\cW\\B+(?!^)\\b+??{0}|(?:[^\\0-\\\u7832\\uCbA9\\s\\n]+?|\\cJ){1}/gyi);/*hhh*/function ysvjyu(x, x =  /x/ , x, eval =  \"\" , \u3056, b, window =  /x/ , x, constructor, x, d, x, x, e, c, y, b, NaN, x, x =  /x/g , c, x, NaN, b, x, x = \"\\u4E56\", y = this, window, c, x = undefined, \u3056, \u3056, x, a, w, \u3056, window =  \"\" , x, c, window, b, x, b =  /x/ , x = length, eval, e, d, x, x = x, get, c, z = false, x, e, c, y = [z1], x, a, \u3056, NaN, d, eval, x, NaN, y = undefined, x = -2, x, w, y, x =  /x/g ){-Number.MAX_VALUE;}");
/*fuzzSeed-244067732*/count=721; tryItOut("if(false) {o0 = Object.create(p2);v1 = a1.length;m2.set(a0, [,,]); } else  if ((/*wrap3*/(function(){ var sqsfyc = (void shapeOf(window)); (String.prototype.trim)(); })(Math.imul( /* Comment */-28, -23), x)) &= (void version(185))) {v2 = a2.length;Array.prototype.push.call(a1, this.i0, g1.m0, m0); } else {v0 = o0.t2.byteOffset;a2.push(g2, t0, a0, m2, o2); }");
/*fuzzSeed-244067732*/count=722; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ ( + mathy1(( + ( - y)), ( + ((Math.fround(Math.acosh(x)) == (Math.cbrt(2**53+2) | 0)) | 0))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 42, -0x0ffffffff, 0/0, -(2**53-2), Math.PI, 2**53+2, -0x07fffffff, 1, 2**53, 0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), -0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000001, 1/0, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, 0x080000000, Number.MIN_VALUE, 0x100000000, 0, -0x100000000, 0x07fffffff]); ");
/*fuzzSeed-244067732*/count=723; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.acosh(((( - (( + (Math.fround(x) >>> 0)) >>> 0)) >>> 0) - (( + Math.max((Math.cbrt((-0x0ffffffff >>> 0)) >>> 0), ( ~ (Math.cos(((Math.atan2((x | 0), x) >>> 0) >>> 0)) >>> 0)))) >>> 0))) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){},  '\\0' ,  '\\0' , objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(),  '\\0' , false, function(){}, function(){},  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), function(){},  '\\0' , objectEmulatingUndefined(), false, function(){}, false, false, false, false, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, false, false, false, false, false, false, false, false, false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){},  '\\0' , function(){}, objectEmulatingUndefined(), function(){},  '\\0' , function(){}, function(){}]); ");
/*fuzzSeed-244067732*/count=724; tryItOut("");
/*fuzzSeed-244067732*/count=725; tryItOut("mathy2 = (function(x, y) { return (((Math.expm1(( ! x)) >>> 0) ? (Math.fround(Math.atan2((Math.fround((Math.fround((Math.imul((x | 0), Math.expm1((Math.log(-(2**53)) | 0))) | 0)) === Math.fround(Math.fround(Math.hypot(((Math.acos((x >>> 0)) >>> 0) >>> 0), Math.fround(x)))))) | 0), (mathy0((( + ( - (Math.fround(mathy1(Math.fround(-Number.MAX_SAFE_INTEGER), Math.fround(Math.fround(Math.hypot(Math.fround(x), x))))) >>> 0))) | 0), ( - Math.min((y | 0), -0x080000001))) >>> 0))) | 0) : (Math.atan2(Math.fround((Math.imul((x >>> 0), y) / (mathy0(x, (((Math.fround(y) | 0) > (x | 0)) | 0)) >>> 0))), (Math.fround(( + Math.min(( + 0x07fffffff), ( + -(2**53+2))))) ^ ( + Math.max(Math.fround((((y | 0) != (x | 0)) | 0)), x)))) | 0)) | 0); }); testMathyFunction(mathy2, ['/0/', 1, 0.1, (new Boolean(true)), (function(){return 0;}), NaN, ({valueOf:function(){return 0;}}), false, (new Boolean(false)), (new String('')), (new Number(0)), [], (new Number(-0)), ({toString:function(){return '0';}}), '', -0, true, '0', 0, null, [0], objectEmulatingUndefined(), /0/, undefined, ({valueOf:function(){return '0';}}), '\\0']); ");
/*fuzzSeed-244067732*/count=726; tryItOut("\"use strict\"; e2.__iterator__ = (function() { for (var j=0;j<51;++j) { g2.f2(j%3==1); } });");
/*fuzzSeed-244067732*/count=727; tryItOut("mathy0 = (function(x, y) { return (((( ! ( + ( ~ (( + ( + 0/0)) >>> 0)))) >>> 0) <= Math.fround(( ! Math.cbrt(-(2**53+2))))) >>> 0); }); ");
/*fuzzSeed-244067732*/count=728; tryItOut("\"use strict\"; this.v0 = Object.prototype.isPrototypeOf.call(s1, g1.a1);");
/*fuzzSeed-244067732*/count=729; tryItOut("v1 = (a0 instanceof m0);");
/*fuzzSeed-244067732*/count=730; tryItOut("mathy5 = (function(x, y) { return ( - ((((( ! (Math.max(Math.fround(( - (x << y))), x) | 0)) | 0) >>> 0) + (((Math.fround((Math.fround(y) || (( + Math.acos(( + Math.sinh(y)))) | 0))) >>> 0) * (Math.pow(y, ( ! ( + (( + x) , ( + y))))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [2**53-2, -Number.MAX_VALUE, 1, -1/0, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, 0, -0x080000001, 0x080000000, Math.PI, Number.MIN_VALUE, 2**53, 1/0, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -0, -0x080000000, 0x080000001, 2**53+2, -0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -0x100000001, -(2**53), -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=731; tryItOut("\"use strict\"; o0.g0.v1 = r1.toString;");
/*fuzzSeed-244067732*/count=732; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), -1/0, 0x080000000, 2**53, 1/0, -0x080000001, 0, 2**53-2, 42, -0x100000001, 0x100000001, 0.000000000000001, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x100000000, -0x100000000, -0, -0x0ffffffff, 2**53+2, Math.PI, -0x080000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=733; tryItOut("i1 = a0[v1];");
/*fuzzSeed-244067732*/count=734; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ! (mathy1(((((( + Math.min(( + Math.sqrt((Math.imul((y >>> 0), (mathy0(x, 0) >>> 0)) >>> 0))), ( + y))) >>> 0) === (-Number.MIN_VALUE >>> 0)) >>> 0) >>> 0), ((Object.defineProperty(y, \"constructor\", ({value: [[1]], writable: (x % 5 == 3), configurable: false, enumerable: true}))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[(void 0), (void 0), (void 0), (void 0), (void 0), (void 0), null, (void 0), (void 0), null, null, (void 0)]); ");
/*fuzzSeed-244067732*/count=735; tryItOut("v1 = g0.eval(\"(delete w.eval)\");");
/*fuzzSeed-244067732*/count=736; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.exp((Math.exp(((Math.pow((y | 0), (x >>> 0)) >>> 0) >>> 0)) < ((Math.fround(Math.fround((Math.fround(y) < y))) ** (Math.fround(Math.pow(Math.fround(Math.ceil(( ! (-0x080000000 < x)))), Math.fround(0x07fffffff))) | 0)) >>> 0))) | 0); }); testMathyFunction(mathy4, [1/0, Number.MAX_VALUE, -(2**53-2), -0, Math.PI, -(2**53+2), 0.000000000000001, -0x080000001, Number.MIN_VALUE, 2**53+2, -Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, 2**53, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, 0x100000000, 0x080000000, 0/0, -Number.MAX_VALUE, 2**53-2, -0x100000001, -0x100000000, -1/0, 0, 0x100000001, -(2**53), -0x080000000]); ");
/*fuzzSeed-244067732*/count=737; tryItOut("/*RXUB*/var r = new RegExp(\"(?![\\ude8d]*|(?:\\\\b{3,})(?!(?=$))+?(?![^]?)$?\\\\2^)|\\\\w|(?:(?=(?=\\\\x5E)*))+*??\", \"yi\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-244067732*/count=738; tryItOut("Object.defineProperty(this, \"r2\", { configurable:  \"\" , enumerable: false,  get: function() {  return /\\2|\\b+|(^|^*)|[^]\\b+(.)*?.{0,}/yim; } });");
/*fuzzSeed-244067732*/count=739; tryItOut("\"use strict\"; o2.a2[({valueOf: function() { /*infloop*/M:for(true.eval in ((encodeURIComponent)((y = Proxy.create(({/*TOODEEP*/})(d), this))))){/*MXX1*/o1 = g1.Date.prototype.getSeconds; }return 15; }})];");
/*fuzzSeed-244067732*/count=740; tryItOut("/*iii*/s0 = Array.prototype.join.call(a0, s1);/*hhh*/function qwgdxt(d, \u3056, ...x){print( ''  > this);}");
/*fuzzSeed-244067732*/count=741; tryItOut("x = linkedList(x, 2310);");
/*fuzzSeed-244067732*/count=742; tryItOut("a1.shift(f1, m2, v1, p0);");
/*fuzzSeed-244067732*/count=743; tryItOut("delete f2[\"revocable\"];");
/*fuzzSeed-244067732*/count=744; tryItOut("mathy3 = (function(x, y) { return ( - Math.pow(((mathy0(( + Math.imul(x, ( ! x))), ( + (Math.imul((Math.atan(x) | 0), ((Math.sign((y | 0)) | 0) | 0)) | 0))) >>> 0) >> y), (( ~ y) * Math.cbrt(x)))); }); testMathyFunction(mathy3, [-0x0ffffffff, 0x080000001, 2**53-2, -1/0, Number.MIN_VALUE, 1/0, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), -0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -0, -(2**53-2), 0x07fffffff, Number.MAX_VALUE, Math.PI, 2**53+2, 0x080000000, 42, 0/0, -0x080000000, 0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, 0x100000000, -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=745; tryItOut("mathy3 = (function(x, y) { return Math.log(Math.pow(Math.pow((Math.hypot(((y ^ ((x ^ (-(2**53-2) / x)) | 0)) | 0), (y | 0)) | 0), ( + ( + ( + ( + (( + Number.MAX_SAFE_INTEGER) ? ( + x) : ( + -0x080000000))))))), Math.fround((( + Math.fround(mathy2(Math.fround(Math.trunc((x * Math.fround(x)))), Math.fround((Math.min((y >>> 0), (x >>> 0)) >>> 0))))) < ( ~ ( ~ ( + (( + -(2**53+2)) ? y : x)))))))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, -0, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, -0x080000000, 0x07fffffff, 0x080000000, -0x07fffffff, 0x100000001, 0x100000000, -(2**53+2), 2**53-2, -(2**53), 2**53, -0x100000000, 42, 2**53+2, -Number.MIN_VALUE, -(2**53-2), 1/0, -Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 0, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=746; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - ( - (mathy4(( + Math.imul(x, 0x100000001)), ((y ? y : y) ? Number.MAX_VALUE : Math.fround(( - Math.fround(y))))) >>> Math.atan2(2**53+2, Math.fround((Math.fround(x) - -Number.MIN_SAFE_INTEGER)))))); }); testMathyFunction(mathy5, [0x080000000, -(2**53+2), -0x07fffffff, Number.MAX_SAFE_INTEGER, 1, 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, -0, 42, 2**53, Math.PI, 2**53-2, -0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, 0x080000001, -0x080000000, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, 0, 1/0, 0.000000000000001, 0x0ffffffff, 0x100000000, -1/0, -(2**53), 1.7976931348623157e308, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=747; tryItOut("a0.pop();");
/*fuzzSeed-244067732*/count=748; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    /*FFI*/ff();\n    return +((-6.189700196426902e+26));\n  }\n  return f; })(this, {ff: a}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [2**53-2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 2**53, -1/0, Math.PI, 0x07fffffff, -(2**53), 0x0ffffffff, -0x100000000, 0/0, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 1, 0.000000000000001, 0x080000000, -0x080000000, -Number.MAX_VALUE, -(2**53+2), -0, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, 1/0, -0x080000001, Number.MIN_VALUE, -0x100000001, 0x100000000]); ");
/*fuzzSeed-244067732*/count=749; tryItOut("\"use strict\";  '' ;\nprint((4277));\n");
/*fuzzSeed-244067732*/count=750; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.max(( + ((1/0 / (Math.pow(Math.fround((mathy0((y | 0), Math.clz32(y)) | 0)), -0x100000000) >>> 0)) >= (( + (( + (( ! (x >>> 0)) >>> 0)) * Math.fround(Math.log1p(( + Math.cosh(x)))))) ? (Math.round(( + x)) >>> 0) : Math.fround(Math.asinh(x))))), (((Math.atan2(mathy0(Math.fround(Math.atan(y)), Math.log10(x)), Math.fround(( ! Math.fround(y)))) >>> 0) ? (( + ( ! Math.fround(Math.fround(Math.tan(Math.fround(x)))))) >>> 0) : (Math.hypot((( ~ (Math.fround(Math.hypot(( + y), (( + x) | 0))) / Math.fround(-Number.MAX_VALUE))) | 0), (x - Math.clz32((y >>> 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0x100000001, 0, -0x080000000, 0x07fffffff, Number.MAX_VALUE, -(2**53), 2**53+2, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), -(2**53+2), Math.PI, 0x0ffffffff, 0x080000000, -1/0, 0.000000000000001, -0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 0x080000001, Number.MIN_VALUE, 0/0, -0, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-244067732*/count=751; tryItOut("x.fileName;");
/*fuzzSeed-244067732*/count=752; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ((Math.tanh(((Math.atan2(( + (y != ( + x))), (((y | 0) !== (x | 0)) | 0)) < x) | 0)) | 0) !== ( + (Math.min((Math.cosh(( - Math.PI)) != (x | 0)), mathy0((((Math.abs(( ! (0 | 0))) | 0) ? 0x100000001 : Math.imul((1.7976931348623157e308 | 0), (x | 0))) >>> 0), (-0 | 0))) | Math.fround(Math.sqrt(( + Math.log(( + y)))))))); }); ");
/*fuzzSeed-244067732*/count=753; tryItOut("\"use strict\"; testMathyFunction(mathy5, [2**53-2, -0x07fffffff, 0x0ffffffff, 2**53, -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, 1, Number.MAX_VALUE, 1/0, 0, -0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, -1/0, -(2**53+2), 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, 42, -0x100000001, -0x080000000, 0.000000000000001, -0, 0x080000000, -0x080000001, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-244067732*/count=754; tryItOut("\"use strict\"; t1.set(a1, v1);");
/*fuzzSeed-244067732*/count=755; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return (Math.max(Math.asinh(( + (-(2**53-2) <= Number.MAX_SAFE_INTEGER))), (( - Math.fround(mathy0((x === x), Math.fround(0x080000000)))) >>> 0)) - ((Math.min((((( + mathy0(( + ( + Math.atan2(( + -0), ( + x)))), x)) >>> 0) ? (( ! y) >>> 0) : (((x == x) & y) >>> 0)) | 0), Math.fround(((y >>> 0) & y))) | 0) ? (( + (y ^ ( + x))) >>> (y - Math.fround((( + (x >>> 0)) ? x : ( + ( ~ y)))))) : ( + (Math.sign(( - Math.acos(-0x07fffffff))) >>> 0)))); }); ");
/*fuzzSeed-244067732*/count=756; tryItOut("s2 += 'x';");
/*fuzzSeed-244067732*/count=757; tryItOut("/*MXX2*/g2.Int8Array.name = g2.f0;");
/*fuzzSeed-244067732*/count=758; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=759; tryItOut("\"use strict\"; Object.defineProperty(this, \"v0\", { configurable: x, enumerable: Math.atan,  get: function() {  return evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: this.__defineGetter__(\"x\", function (d) { Array.prototype.pop.call(o1.a2, s1);m1.set(this.p0, p0); } ), element: o0, elementAttributeName: s1, sourceMapURL: s2 })); } });");
/*fuzzSeed-244067732*/count=760; tryItOut("mathy3 = (function(x, y) { return Math.min(((( + Math.atan(( + y))) ? (Math.sin(Math.ceil((x | 0))) | 0) : Math.cos(Math.asinh(Math.atanh(y)))) >>> 0), ( + (Math.cbrt(((Math.min(Math.clz32(y), (x | 0)) | 0) >>> 0)) | 0))); }); testMathyFunction(mathy3, [0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), 0/0, -0x100000000, -Number.MAX_VALUE, -0x080000000, 0x100000001, 2**53, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -1/0, 0.000000000000001, 0x0ffffffff, 1, 0x100000000, -0x080000001, -0x07fffffff, -(2**53+2), 0x080000000, -0, Number.MAX_VALUE, -Number.MIN_VALUE, 0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -0x0ffffffff, 42, 2**53+2]); ");
/*fuzzSeed-244067732*/count=761; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\"; s1.__proto__ = v2;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d0 = (Infinity);\n    }\n    d1 = (Infinity);\n    d0 = (d0);\n    {\n      d1 = (((d1)) / ((+(0.0/0.0))));\n    }\n    (Int32ArrayView[((0xffffffff) % (((0x557052c4) % (0x3adc7796))>>>(0x5a804*((0x437ae2de))))) >> 2]) = ((-0x8000000)*0xf3ffe);\n    d1 = (d0);\n    return ((((((0xfd8348f2)-((d1) < (d0))) ^ (-((/*FARR*/[/*FARR*/[].some(Math.cbrt, this), , Math.imul( '' , y), .../*MARR*/[0x20000000, (void 0), undefined, undefined, (void 0), undefined, undefined, (void 0), undefined, (void 0), undefined, undefined, undefined, (void 0), undefined, 0x20000000, (void 0), (void 0), (void 0), undefined, 0x20000000, undefined, (void 0), 0x20000000, 0x20000000, (void 0), 0x20000000, (void 0), 0x20000000, 0x20000000, undefined, (void 0), undefined, 0x20000000, undefined, (void 0), (void 0), 0x20000000, 0x20000000, (void 0), undefined, (void 0), 0x20000000, (void 0), 0x20000000, 0x20000000, 0x20000000, undefined, 0x20000000, (void 0), (void 0), (void 0), undefined, 0x20000000, undefined, 0x20000000, undefined, 0x20000000, undefined, undefined, (void 0), (void 0), undefined, (void 0), undefined, 0x20000000, 0x20000000, 0x20000000, undefined, 0x20000000, (void 0), 0x20000000, (void 0), (void 0), 0x20000000, undefined, undefined, 0x20000000, 0x20000000, undefined, (void 0), (void 0), 0x20000000, undefined, (void 0), (void 0), undefined, undefined, (void 0), (void 0), (void 0), 0x20000000, undefined, undefined, 0x20000000, undefined, (void 0), undefined, 0x20000000, 0x20000000, 0x20000000, undefined, 0x20000000, undefined, (void 0), undefined, undefined]].sort)))))+((((((0x29962cff) / (0x4a1da98a)) ^ (({x: delete x.d}))) / ((((Float64ArrayView[2]))+((0xfc144d54) ? (0xce5ae2aa) : (0xd15a85bd))) >> ((0xb09718ae) / (0xd56a5a51)))) & ((0x5a995100)+(0x9f5539b))))))|0;\n  }\n  return f; })(this, {ff: 6\u0009()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [1/0, -Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 42, 0, -0x0ffffffff, -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), 0x0ffffffff, 0x080000000, -0x080000001, 0x100000000, -1/0, -0, 2**53+2, 1.7976931348623157e308, -0x100000001, 0x080000001, 0x07fffffff, 2**53-2, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, Math.PI, -Number.MAX_VALUE, 0/0, 1, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=762; tryItOut("switch(new (Math.max(9, SimpleObject(new RegExp(\".?(?!(?=[\\\\W\\u089d]*))|\\\\1+|\\\\b\\\\B*${3,}\", \"y\"), \"\\uC3E1\")))()) { case 3: break; case 8: /*tLoop*/for (let a of /*MARR*/[objectEmulatingUndefined(), new String('q'), (void 0), -(2**53-2), -(2**53-2), new String('q'), -(2**53-2), objectEmulatingUndefined(), objectEmulatingUndefined(), -(2**53-2), (void 0), -(2**53-2), new String('q'), (void 0), objectEmulatingUndefined(), new String('q'), new String('q'), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), new String('q'), new String('q'), new String('q'), -(2**53-2), (void 0), -(2**53-2), new String('q'), -(2**53-2), (void 0), new String('q'), -(2**53-2), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), (void 0), new String('q'), new String('q'), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -(2**53-2), -(2**53-2), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), -(2**53-2), (void 0), new String('q'), (void 0), -(2**53-2), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), -(2**53-2), -(2**53-2), objectEmulatingUndefined(), objectEmulatingUndefined(), -(2**53-2), new String('q'), -(2**53-2), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), -(2**53-2), objectEmulatingUndefined(), -(2**53-2), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), -(2**53-2), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), -(2**53-2), objectEmulatingUndefined(), -(2**53-2), -(2**53-2), -(2**53-2), objectEmulatingUndefined(), new String('q'), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), objectEmulatingUndefined(), -(2**53-2), (void 0), (void 0), new String('q'), (void 0)]) { (ReferenceError.prototype.toString.prototype); }break; break; case 3: v1 = g2.eval(\"this.__defineGetter__(\\\"NaN\\\", (allocationMarker()))\"); }");
/*fuzzSeed-244067732*/count=763; tryItOut("\"use strict\"; this.p2 + '';\nlet v0 = g0.eval(\"function f0(a1)  { \\\"use strict\\\"; switch(a1) { case (window ** b): let s2 = new String;case (eval = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: undefined, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(\\\"\\\\u71A4\\\"), Date.prototype.setDate, String.prototype.toString)): (((4277) >>= /*MARR*/[ /x/g ,  /x/g , false, ({x:3}), ({x:3}),  /x/g , false, false, ({x:3}), ({x:3}), false,  /x/g , ({x:3}),  /x/g , ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), false,  /x/g , ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}),  /x/g , ({x:3}), ({x:3}),  /x/g , false, ({x:3}),  /x/g ,  /x/g ,  /x/g , false, false, ({x:3}), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,  /x/g , ({x:3}), false, ({x:3}), ({x:3}), false,  /x/g , ({x:3}), ({x:3}), ({x:3}), false,  /x/g ,  /x/g , ({x:3}), ({x:3}), ({x:3}), false, false, false, false, false, false, false, false,  /x/g , ({x:3}), false, ({x:3}),  /x/g ,  /x/g , false, false, false,  /x/g ,  /x/g , ({x:3}), false, ({x:3})].map(function(q) { return q; })));default: break; break;  } } \");\n");
/*fuzzSeed-244067732*/count=764; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[[undefined], [undefined], [undefined], 0x100000000, [undefined], [undefined], [undefined], [undefined], 0x100000000, [undefined], [undefined], [undefined], [undefined], [undefined], 0x100000000, 0x100000000, 0x100000000]) { return; }");
/*fuzzSeed-244067732*/count=765; tryItOut("/*vLoop*/for (var blzoly = 0; blzoly < 49; ++blzoly) { const x = blzoly; { void 0; void relazifyFunctions(); } } ");
/*fuzzSeed-244067732*/count=766; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.cos(Math.fround(Math.imul(Math.pow(Math.hypot((Math.cbrt(x) >>> 0), x), x), ( + Math.fround(mathy4(Math.fround(x), Math.fround(( + ( + x)))))))))); }); testMathyFunction(mathy5, [({valueOf:function(){return '0';}}), true, 1, (new Boolean(false)), ({toString:function(){return '0';}}), [0], (new String('')), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), 0, '', undefined, /0/, '/0/', (function(){return 0;}), [], '0', null, (new Number(0)), (new Boolean(true)), (new Number(-0)), '\\0', NaN, -0, 0.1, false]); ");
/*fuzzSeed-244067732*/count=767; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( - ((Math.fround(x) ? ( + ( + Math.min(y, -Number.MAX_VALUE))) : ((Math.imul((Math.clz32(Math.fround(y)) | 0), x) | 0) !== Math.hypot(Math.atan(1), 0x100000000))) ** (( ~ (Math.fround((Math.fround(Math.log((Math.atanh(Math.PI) >>> 0))) ** Math.fround(( + Math.pow(1.7976931348623157e308, 2**53+2))))) | 0)) | 0)))); }); testMathyFunction(mathy0, [1/0, 2**53-2, 0/0, -0, -0x07fffffff, -(2**53+2), 0x100000001, 0x07fffffff, 42, 1.7976931348623157e308, 0x0ffffffff, 2**53+2, -0x080000001, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -0x100000000, -1/0, 0, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), -(2**53-2), -Number.MIN_VALUE, 0x080000001, 1, 2**53, -0x080000000]); ");
/*fuzzSeed-244067732*/count=768; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 1, 0x100000001, -0x080000000, -(2**53-2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x080000001, 0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0, -0x0ffffffff, 2**53, 0x0ffffffff, 0.000000000000001, 0x100000000, -(2**53), -0x100000000, 2**53-2, -Number.MAX_VALUE, 0x07fffffff, -0, 0/0, -1/0, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=769; tryItOut("/*RXUB*/var r = new RegExp(\"(^*?(?=(?![\\\\d\\ue330\\\\x96-\\\\u009F\\\\f-\\\\\\u00ef])\\\\u3F79))(?=(?!\\\\w))(?=\\u8303)[^]|\\\\cD|(?:\\\\1+?)|(?=(?:\\\\cF)*?)\", \"yim\"); var s = \"a\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=770; tryItOut("g2.b0 + '';");
/*fuzzSeed-244067732*/count=771; tryItOut("\"use strict\"; /*infloop*/M:while(x){print( '' ); }\nfor(let x in  /x/ ) {a0.pop();v1 = t0.length; }\n");
/*fuzzSeed-244067732*/count=772; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( ~ mathy0(( - 0/0), (mathy2((mathy3((Math.log((( ~ Math.fround(( + Math.fround(x)))) | 0)) >>> 0), (Math.pow(x, x) >>> 0)) >>> 0), x) >>> 0)))); }); ");
/*fuzzSeed-244067732*/count=773; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.abs(((x === (((y | 0) ** (2**53-2 | 0)) | 0)) > ((( + Math.log2(( + Math.exp(-0x100000000)))) | 0) * (Math.fround(( + Math.fround(Math.cbrt((2**53 >>> 0))))) | 0)))); }); ");
/*fuzzSeed-244067732*/count=774; tryItOut("with({}) (window);let(jczivt, bzerve, c, nmahvv, vfyhai, iwajxx) ((function(){print(x);})());");
/*fuzzSeed-244067732*/count=775; tryItOut("e1.add(e1);");
/*fuzzSeed-244067732*/count=776; tryItOut("a2 = arguments;");
/*fuzzSeed-244067732*/count=777; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.fround((Math.clz32(0.000000000000001) | 0)) >>> 0) | (((Math.acosh(Math.tanh((Math.imul((( + Math.sign(x)) >>> 0), (y >>> 0)) >>> 0))) | 0) && ((( ! Math.fround(( + Math.max(Math.fround(( ~ -(2**53))), Number.MAX_VALUE)))) >>> 0) | 0)) | 0)); }); ");
/*fuzzSeed-244067732*/count=778; tryItOut("mathy3 = (function(x, y) { return Math.atan2(mathy2((( - ( + ( - ( ! ( + 0))))) < Math.atan2(x, Math.fround(mathy2(Math.fround(Math.fround(mathy1(( + 0x080000001), y))), Math.fround((Math.sqrt((x >>> 0)) >>> 0)))))), Math.fround(Math.round(Math.log(x)))), (Math.max(( ~ y), ((Math.min(( + ( + Math.asinh(x))), (x | 0)) || ((Math.tanh((x >>> 0)) >>> 0) | 0)) ? y : (( ! mathy2(y, Number.MIN_SAFE_INTEGER)) >>> 0))) == Math.fround(mathy1(Math.fround(Math.fround(( ! ((x > ( + y)) | 0)))), (((x >>> 0) / (Math.expm1(x) | 0)) | 0))))); }); testMathyFunction(mathy3, [-1/0, -Number.MIN_SAFE_INTEGER, 1, 0x080000001, -0x100000001, -0x080000001, -0, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 0/0, Math.PI, 0x100000001, 0, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53, Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, 2**53+2, 42, 0x07fffffff, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-244067732*/count=779; tryItOut("\"use strict\"; let b = (yield window), z = /\\cJ/gm, qjoiwd, lxnbni, xkxexn, a, maletn, c, b, bvvshu;yield new RegExp(\"\\\\2\", \"yi\");");
/*fuzzSeed-244067732*/count=780; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! (Math.fround((Math.acosh(y) ? Math.fround(( - ( ~ mathy0(( + y), ( + (Math.max((y | 0), Math.fround(1/0)) | 0)))))) : Math.fround((Math.tan(Math.atan2(Math.fround(x), Math.fround(x))) >>> 0)))) | 0)); }); testMathyFunction(mathy2, [-(2**53), 0x080000000, -0x07fffffff, 1.7976931348623157e308, -1/0, -0, 0x100000000, 0x080000001, 0.000000000000001, -0x080000001, 0, -(2**53-2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, -(2**53+2), 2**53+2, 1, 42, 1/0, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, 0x0ffffffff, -0x100000001, 0x07fffffff, 0/0, 0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=781; tryItOut("\"use strict\"; e2.delete(t2);");
/*fuzzSeed-244067732*/count=782; tryItOut("a1 = [];");
/*fuzzSeed-244067732*/count=783; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((((((( + Math.fround(Number.MAX_SAFE_INTEGER)) >> (( ~ Math.fround(x)) >>> 0)) | 0) !== ((Math.imul((x | 0), y) | 0) | 0)) | 0) >>> Math.atan2(( ! Math.imul(Math.fround(Math.max((Math.max((x >>> 0), (x >>> 0)) >>> 0), -0x0ffffffff)), x)), Math.ceil(Math.log2(x)))) > Math.hypot((x ? Math.tan(((Math.log10(y) % x) | 0)) : Math.min(x, ( + ( - Math.fround(x))))), ( + ( - (x >>> 0))))); }); ");
/*fuzzSeed-244067732*/count=784; tryItOut("\"use strict\"; /*oLoop*/for (let eiardc = 0; eiardc < 106; ++eiardc) { (let (mpeqxo, x, ohfvut, wpitqb, hmcnmh, y, lqzwem) window); } ");
/*fuzzSeed-244067732*/count=785; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ Math.min((x <= (y <= (( - Math.fround(Math.min((x >>> 0), y))) | 0))), Math.fround(Math.round(Math.fround(Math.hypot(Math.fround(( ~ x)), Math.fround(y))))))) >>> 0); }); testMathyFunction(mathy0, [-(2**53+2), -0x100000000, Math.PI, 1/0, 0, 0x0ffffffff, -0, 0x100000001, -Number.MIN_VALUE, -1/0, -0x0ffffffff, 1.7976931348623157e308, -0x080000001, 42, 1, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 0.000000000000001, 0x100000000, 0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 2**53, -(2**53), -(2**53-2), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=786; tryItOut("for (var v of m1) { try { g1.offThreadCompileScript(\"function g1.f1(f0) \\\"use asm\\\";   function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    return ((((i1))))|0;\\n  }\\n  return f;\"); } catch(e0) { } /*MXX2*/g2.SimpleObject.length = h2; }");
/*fuzzSeed-244067732*/count=787; tryItOut("selectforgc(o2);");
/*fuzzSeed-244067732*/count=788; tryItOut("/*RXUB*/var r = /\\3{2,}/gyim; var s = \"1a_\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=789; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; gcslice(591); } void 0; }");
/*fuzzSeed-244067732*/count=790; tryItOut("with({}) { with({}) { Date.prototype.constructor = e; }  } with({}) { for(let x in []); } ");
/*fuzzSeed-244067732*/count=791; tryItOut("{v0 = this.r0.global;/*oLoop*/for (rehgem = 0, grvcvt; rehgem < 21; ++rehgem) { /*bLoop*/for (let cperqp = 0; cperqp < 30; ++cperqp) { if (cperqp % 112 == 75) { ; } else { print(x); }  }  }  }");
/*fuzzSeed-244067732*/count=792; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround((Math.fround(( ! Math.atan2(Math.tanh(x), x))) / (Math.max((Math.hypot(x, Math.min((( ! (0x080000001 | 0)) >>> 0), (-0 - (0/0 | 0)))) >>> 0), Math.fround(( - x))) >>> 0))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, -(2**53-2), Math.PI, -0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, -0, 0x100000000, -(2**53+2), 42, Number.MIN_VALUE, 1, -(2**53), 2**53, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, 2**53-2, 1.7976931348623157e308, 0x07fffffff, 0x080000000, Number.MAX_VALUE, 2**53+2, 0/0, 0.000000000000001, 0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-244067732*/count=793; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 281474976710656.0;\n    var d3 = -549755813889.0;\n    return +((+pow(((((+((16.0)))) / ((-((Float32ArrayView[(-(0xfbbf186a)) >> 2])))))), ((+(((/*FFI*/ff(((((0xad87cde6)+(-0x8000000)-(0x52a96538)) ^ (-((-((1099511627775.0))))))), (((((0x938beb3d))*-0x67217)|0)), ((imul((0x11a5cd67), (0xfd206599))|0)), ((~~(-2.3611832414348226e+21))), ((-131073.0)), ((-3.8685626227668134e+25)), ((1.888946593147858e+22)), ((4194304.0)), ((-67108865.0)))|0))>>>((0xfaa047f3)-((((0xf3f38945)-(0x7c75b90b)) >> ((0xf8ea3ff5)-(-0x8000000)))))))))));\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0, 0x100000000, -0x0ffffffff, 0x0ffffffff, -1/0, 0x100000001, Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -(2**53), -0x100000000, 0/0, 1, -0x100000001, -0x080000000, 1.7976931348623157e308, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, -0, 0x07fffffff, 0.000000000000001, 2**53+2, 0x080000000, -(2**53+2), -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=794; tryItOut("e1.add(this.s0);let d = (x.__defineSetter__(\"this.\\u3056\", /*wrap2*/(function(){ var zlrmrs = (4277); var dtmaog = /*wrap3*/(function(){ var dmsnpe = x; (RegExp.prototype.test)(); }); return dtmaog;})()));var z = (Math.round(this));this.g0.m0 = new WeakMap;");
/*fuzzSeed-244067732*/count=795; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?=\\\\3{2,}))+?|(?:(?:(?!([^])+?)\\\\2?))\", \"\"); var s = \"\\n\\n1a_1a_\"; print(r.test(s)); ");
/*fuzzSeed-244067732*/count=796; tryItOut("\"use strict\"; for (var v of s0) { try { g0.offThreadCompileScript(\"function o2.f1(m0)  { yield ((void shapeOf(new new RegExp(\\\"\\\\\\\\b\\\", \\\"i\\\")(new (\\\"\\\\u1EF4\\\")(-8) >>= (void options('strict_mode')) , window, ({} = b = false))))) } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 != 1), noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 3 == 2) })); } catch(e0) { } v2 = this.t1.byteOffset; }");
/*fuzzSeed-244067732*/count=797; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var sin = stdlib.Math.sin;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -2.0;\n    (Uint8ArrayView[((0xa4fb02f8)*0xfffff) >> 0]) = ((abs((imul((-0x8000000), (0xfa518825))|0))|0) / ((((((0xa6f1185) ? (0xf1039a44) : (0xffffffff)) ? (-((-4503599627370495.0))) : (+sin(((-4.835703278458517e+24))))) <= (d1))-(0xf9684773))|0));\n    d1 = (d1);\n    return ((((~((0x2a46bbb7))))+(/*FFI*/ff(((+/*FFI*/ff(((+(1.0/0.0))), ((0x4b68b84b)), ((Uint16ArrayView[4096])), ((NaN)), ((((-0x8000000)+((0x75dc9070) != (0x69029de0)))|0)), ((((0x1f39df55)) | ((0x501a4d26)))), ((d2))))), ((d0)))|0)))|0;\n  }\n  return f; })(this, {ff: Uint16Array}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x0ffffffff, 2**53+2, 0x100000001, 2**53-2, 0x080000000, -(2**53-2), 0x100000000, -0, 2**53, -1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 42, 1, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, 0x080000001, 1/0, Number.MAX_VALUE, 0x07fffffff, -0x100000000, -0x100000001, 0/0, -Number.MAX_VALUE, -0x080000000, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-244067732*/count=798; tryItOut("v0 = e1[9];");
/*fuzzSeed-244067732*/count=799; tryItOut("mathy4 = (function(x, y) { return Math.max(( + ( ~ ( ! (Math.hypot((y | 0), ((Math.max(y, 2**53) ? x : Number.MAX_VALUE) | 0)) | 0)))), (((x - ( + Math.atan2(-1/0, ( + y)))) >>> 0) ? ( + Math.log1p(x)) : decodeURIComponent)); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, 1/0, 0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, -0, 2**53+2, 0x100000001, 0/0, 2**53-2, -0x100000000, 0x0ffffffff, -0x080000000, Math.PI, -(2**53+2), Number.MIN_VALUE, -0x0ffffffff, -0x080000001, Number.MAX_VALUE, -0x100000001, -(2**53-2), 2**53, 0, 0x100000000, 0x080000001, -Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-244067732*/count=800; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (((Math.expm1(((Math.cos((( ~ ( + Math.min(( + x), ( + x)))) | 0)) | 0) | 0)) | 0) || (( + mathy0(Math.fround(Math.hypot(Math.round((y && y)), ((0x100000000 >> x) >>> 0))), Math.ceil(y))) >>> 0)) ? (Math.atan2((Math.clz32(( - Math.fround((Math.hypot((0 | 0), (y | 0)) | 0)))) >>> 0), Math.fround(Math.fround(Math.atan2((( - (y >>> 0)) >>> 0), (Math.fround(( + (Math.fround(y) >= ( + Math.sin(Math.trunc(y)))))) <= Math.fround(( - Math.fround(y)))))))) >>> 0) : ((Math.pow((Math.fround(Math.imul(Math.fround(mathy1(y, (Math.cosh(x) >>> 0))), ( + x))) >>> 0), (( ! Math.expm1((Math.log(Number.MAX_SAFE_INTEGER) >>> 0))) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy4, [0, -0x100000001, -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, -Number.MAX_VALUE, -0x0ffffffff, 1/0, 0x07fffffff, -(2**53+2), 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, 2**53+2, 0/0, 0x0ffffffff, 0x080000000, -0x080000000, 1, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53-2), -0x07fffffff, -0, -Number.MIN_VALUE, 42, -(2**53)]); ");
/*fuzzSeed-244067732*/count=801; tryItOut("window;");
/*fuzzSeed-244067732*/count=802; tryItOut("\"use strict\"; m1.delete(i0);");
/*fuzzSeed-244067732*/count=803; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.abs(( + mathy0(Math.fround(Math.max(Math.fround(Math.fround(mathy0(Math.fround(y), Math.fround(( - (x | 0)))))), Math.fround(( + ( ~ ( + -0x0ffffffff)))))), ( - Math.max(Math.fround(( ~ Math.fround(y))), x)))))); }); ");
/*fuzzSeed-244067732*/count=804; tryItOut("testMathyFunction(mathy1, [0.1, '0', (new String('')), (new Number(-0)), null, [0], /0/, '/0/', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), ({toString:function(){return '0';}}), NaN, ({valueOf:function(){return '0';}}), '', (new Boolean(false)), 0, (new Number(0)), -0, true, (new Boolean(true)), false, [], (function(){return 0;}), 1, undefined, '\\0']); ");
/*fuzzSeed-244067732*/count=805; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=\\cV*\\s(?!(\\uf3cF))|\\cF.+[^]|^{2,2}|(?:\\W\\b(?!\\w\\b))|\u00f2*(?!\\2))/m; var s = \"\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=806; tryItOut("print(uneval(i0));");
/*fuzzSeed-244067732*/count=807; tryItOut("\"use asm\"; print(x);");
/*fuzzSeed-244067732*/count=808; tryItOut("if(false) { if (++x) t1.set(t1, 16);} else {; }");
/*fuzzSeed-244067732*/count=809; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, -0x100000000, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, 1, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, 1.7976931348623157e308, -(2**53), 2**53-2, 1/0, -0x080000000, 0x080000000, Math.PI, 42, -0x080000001, -(2**53-2), -0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 0x0ffffffff, 2**53, -0x100000001, -Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-244067732*/count=810; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + Math.sign(Math.fround(Math.atanh(Math.fround(Math.fround((Math.fround(x) >>> Math.fround(y)))))))) >> ( + Math.min(( - ((Math.hypot((mathy1(( ! x), Math.ceil(x)) | 0), ((( + x) <= (((((x | 0) % (y | 0)) >>> 0) ? x : Math.fround(y)) >>> 0)) >>> 0)) | 0) >>> 0)), (( ~ x) ? (((x >>> 0) != ((( + (Math.fround(( ! y)) | 0)) >>> 0) >>> 0)) >>> 0) : Math.atan2(( ! x), ((-Number.MAX_VALUE , x) ** ( + Math.min(( + y), ( + x)))))))))); }); testMathyFunction(mathy4, [0/0, 1.7976931348623157e308, -0x100000001, 0x0ffffffff, -1/0, 2**53, 42, -Number.MIN_VALUE, 2**53+2, -0x07fffffff, 1, 0, Math.PI, 0x080000000, Number.MAX_VALUE, 2**53-2, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), 0x100000000, -Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, -0x100000000, -0x080000000, -(2**53), -(2**53+2), 0x100000001]); ");
/*fuzzSeed-244067732*/count=811; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ( + ( - ( - ( + ( ~ ( + Math.sin(( + x))))))))) | 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 0, 1, -Number.MIN_VALUE, 2**53, -0x080000000, 1/0, -0x100000001, 0x07fffffff, 0.000000000000001, 1.7976931348623157e308, 0x080000000, Math.PI, 0x0ffffffff, 0x100000000, 0x080000001, Number.MAX_VALUE, -1/0, 2**53-2, 2**53+2, 42, -(2**53+2), -(2**53-2), 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, -0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=812; tryItOut("{ void 0; void gc('compartment'); }");
/*fuzzSeed-244067732*/count=813; tryItOut("/*RXUB*/var r = /(?=\\2*)(((?=\\D))((?:${128})){4}|(?:$|[^]|\\b))(?:\\D{536870912,536870916}(?:\\S)|[^]|[^]{1,}{4,}|(?=\\B)[^]*?)*?/gy; var s = \"a\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=814; tryItOut("\"use strict\"; t0[(((Math.max((( ! Math.max(Math.fround(Math.max((x >>> 0), Math.fround(Math.fround(( ~ Math.min(x, x)))))), ( + Math.min(( + Math.fround(Math.cos(x))), ( + 0x100000001))))) >>> 0), ((( + (((Math.pow(x, (x | 0)) | 0) | 0) >>> Math.fround(( + Math.pow(( + Math.atan2(Math.fround(( + x)), ( + Math.hypot(x, Number.MIN_VALUE)))), ((((Math.pow(((x , Math.fround(x)) >>> 0), 1.7976931348623157e308) >>> 0) - ((Math.min(((-Number.MAX_VALUE >> Math.fround(( ! Math.fround(x)))) | 0), (x | 0)) | 0) >>> 0)) >>> 0) | 0)))))) > ( + (Math.sin(Math.fround((( - Math.pow((Math.sign((0 | 0)) | 0), Math.max(x, (Math.atan((x | 0)) | 0)))) >>> 0))) ? (( ~ 2**53-2) == (Math.fround(Math.ceil(x)) << (x , x))) : Math.pow((Math.tanh((Math.sqrt(-0x080000000) | 0)) | 0), (((-(2**53-2) >>> 0) ? (Math.hypot(x, x) >>> 0) : (x >>> 0)) >>> 0))))) >>> 0)) >>> 0)))] = h1;");
/*fuzzSeed-244067732*/count=815; tryItOut("\"use strict\"; o1.a1.length = 13;");
/*fuzzSeed-244067732*/count=816; tryItOut("\"use asm\"; ");
/*fuzzSeed-244067732*/count=817; tryItOut("testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0/0, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, 1.7976931348623157e308, 0.000000000000001, Number.MAX_VALUE, 42, 1/0, 0, -0x080000001, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), -(2**53-2), -1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, 2**53+2, 2**53-2, Math.PI, -0, 0x100000001, 0x080000001, 0x100000000, -0x100000000, -0x080000000, -0x0ffffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=818; tryItOut("\"use strict\"; a1.sort((function mcc_() { var nkwalr = 0; return function() { ++nkwalr; if (nkwalr > 1) { dumpln('hit!'); try { a2 = a1.concat(t1, a0, e0); } catch(e0) { } try { e0 + ''; } catch(e1) { } v1 = Object.prototype.isPrototypeOf.call(m1, this.a1); } else { dumpln('miss!'); try { v0 = (f1 instanceof m2); } catch(e0) { } try { this.e2.add((Math.atanh(1))); } catch(e1) { } m0 = x; } };})(), h2, i2);");
/*fuzzSeed-244067732*/count=819; tryItOut(";");
/*fuzzSeed-244067732*/count=820; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=821; tryItOut("\"use asm\"; throw StopIteration;");
/*fuzzSeed-244067732*/count=822; tryItOut("\"use strict\"; var lehzxp = new SharedArrayBuffer(2); var lehzxp_0 = new Uint16Array(lehzxp); lehzxp_0[0] = 20; this.a2.forEach((function() { try { e2 + h0; } catch(e0) { } try { g0 = this; } catch(e1) { } a1.splice(NaN, 3, t2); throw g0; }));print(lehzxp_0);");
/*fuzzSeed-244067732*/count=823; tryItOut("\"use strict\"; if((x % 93 == 59)) { if (Math.atan2(d | y.valueOf(\"number\"), 8)) /*RXUB*/var r = new RegExp(\"(?=\\\\u602B\\\\d{2,}+?)^+?|.\", \"yim\"); var s = \"\\u00db\"; print(r.test(s));  else x, nfzykj, x, x, \u3056;print(f1);}");
/*fuzzSeed-244067732*/count=824; tryItOut("m1 = new Map;");
/*fuzzSeed-244067732*/count=825; tryItOut("M:for(let e = x in (Math.sign(\"\\u10FD\")) == (makeFinalizeObserver('tenured'))) {m0.has(e0);print(e); }");
/*fuzzSeed-244067732*/count=826; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-244067732*/count=827; tryItOut("\"use strict\"; b1 + '';");
/*fuzzSeed-244067732*/count=828; tryItOut("mathy1 = (function(x, y) { return ((((mathy0(Math.fround(Math.tanh(Math.fround(( ! Math.fround(Math.log(x)))))), Math.fround((Math.min(x, (Math.atan(Math.fround(Math.tan((y >>> 0)))) | 0)) ? Math.fround(( + x)) : Math.fround(Math.pow((Math.hypot(x, 0x080000001) / Math.fround(Math.trunc(Math.fround(Math.sign(x))))), y))))) | 0) >>> 0) << (Math.fround(Math.max(Math.fround((Math.log2(Math.fround(Math.cos((( + (( + (( ! (x >>> 0)) >>> 0)) <= ( + y))) >>> 0)))) | 0)), Math.fround(Math.fround(Math.pow(Math.fround(x), Math.fround(( - ( + (( + mathy0((x >>> 0), ( + Number.MIN_SAFE_INTEGER))) && ( + ( ! ( + Math.pow(( + x), ( + y)))))))))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[ '\\0' , [undefined],  '\\0' ,  '\\0' ,  '\\0' , [undefined], [undefined]]); ");
/*fuzzSeed-244067732*/count=829; tryItOut("mathy5 = (function(x, y) { return ( - ( + Math.fround(Math.hypot(Math.fround(Math.log1p(-(2**53+2))), ( + mathy3(( + (x | 0)), y)))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, 42, Number.MIN_VALUE, 2**53+2, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, -0, 0/0, -0x0ffffffff, 0x100000000, 1, -1/0, 0x080000001, 0, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), 2**53, -0x080000001, 0.000000000000001, 0x080000000, -(2**53), 0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 0x100000001]); ");
/*fuzzSeed-244067732*/count=830; tryItOut("g1.m2 + this.o0;");
/*fuzzSeed-244067732*/count=831; tryItOut("/*bLoop*/for (var ldizmm = 0; ldizmm < 45; ++ldizmm) { if (ldizmm % 3 == 0) { v1 = a2.length; } else { /*infloop*/for(let e = ({-24: new RegExp(\"[^]|\\\\b\", \"gim\"), eval: window }); (4277); /\\D/gyi) yield; }  } ");
/*fuzzSeed-244067732*/count=832; tryItOut("(function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -16777217.0;\n    var d3 = 1.5;\n    var i4 = 0;\n    d2 = (9.671406556917033e+24);\n    d3 = (d3);\n    {\n      {\n        {\n          {\n            i4 = (0xa8afd590);\n          }\n        }\n      }\n    }\n    d3 = (d2);\nArray.prototype.unshift    d3 = (d1);\n    (Float64ArrayView[(((((0xfa88137b))>>>((-0x671709))) > (0x33914fca))-((((0x4d7458b9))>>>((0xa7051bc8))) < (0xffffffff))-((0xb4e5131d))) >> 3]) = ((-1.5));\n    (Int8ArrayView[((/*FFI*/ff(((+abs((((Int32ArrayView[((0x5bb89647)) >> 2])))))), ((((0xfd498785)) ^ ((0x5be6d01d)))), ((d1)), ((6.044629098073146e+23)), ((0.015625)))|0)-(i4)-(0x73a760c7)) >> 0]) = ((0x441c6fa7));\n    d1 = (d2);\n    return ((0x3c60d*((0xffffffff))))|0;\n  }\n  return f; })(this, {ff: x.__defineGetter__(\"b\", this |  '' )}, new ArrayBuffer(4096))");
/*fuzzSeed-244067732*/count=833; tryItOut("mathy5 = (function(x, y) { return Math.pow((((Math.cbrt(y) >>> 0) ? ((Math.fround(Math.ceil(Math.fround((Math.log((2**53+2 | 0)) | 0)))) == mathy1(-0x07fffffff, Math.fround((( ! ( + (( + 0x0ffffffff) > 1))) ** y)))) >>> 0) : Math.fround(( + Math.fround((Math.sinh((Number.MAX_VALUE | 0)) | 0))))) >>> 0), Math.atan2(( + Math.pow((((y >>> 0) >= (mathy2(mathy2(y, Math.imul(x, x)), 0x0ffffffff) >>> 0)) >>> 0), ( + Math.log(( + y))))), ( + (Math.min((( + Math.pow(( + Math.log(Math.atanh(y))), Math.atan2((Math.sign(y) | 0), (Math.fround(( - (x >>> 0))) | 0)))) >>> 0), mathy3(y, (x ? ( + y) : ( + (( + x) != ( + Math.min(x, x))))))) >>> 0)))); }); ");
/*fuzzSeed-244067732*/count=834; tryItOut("print(w %= e);");
/*fuzzSeed-244067732*/count=835; tryItOut("\"use strict\"; Array.prototype.splice.apply(o1.a2, [NaN, g2.v0, f2, o0.g2]);s0[\"__iterator__\"] = e0;");
/*fuzzSeed-244067732*/count=836; tryItOut("while(( '' ) && 0){print(o0); }");
/*fuzzSeed-244067732*/count=837; tryItOut("\"use strict\"; t2 = t2.subarray(({x: (makeFinalizeObserver('tenured'))}), x);");
/*fuzzSeed-244067732*/count=838; tryItOut("/*vLoop*/for (sppkli = 0; sppkli < 50; ++sppkli) { w = sppkli; a1.length = 19; } ");
/*fuzzSeed-244067732*/count=839; tryItOut("neuter(b2, \"same-data\");");
/*fuzzSeed-244067732*/count=840; tryItOut("\"use strict\"; a0 = new Array(14);");
/*fuzzSeed-244067732*/count=841; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), new Boolean(true),  '\\0' ]); ");
/*fuzzSeed-244067732*/count=842; tryItOut("\"use strict\"; L: s2 = new String;");
/*fuzzSeed-244067732*/count=843; tryItOut("/*vLoop*/for (ysrasi = 0, (new (4277)(new RegExp(\"[^\\u0004-\\\\t\\\\s\\ubbfd\\\\cZ]{4,}\\\\xA4?\", \"gm\"), -27)).__defineGetter__(\"w\", (b) =>  { \"use asm\"; ( \"\" ); } ); ysrasi < 6; ++ysrasi) { let c = ysrasi; /*bLoop*/for (ziobww = 0; ziobww < 5; ++ziobww) { if (ziobww % 119 == 66) { print(x); } else { /*bLoop*/for (var xkvycy = 0; xkvycy < 16; ++xkvycy) { if (xkvycy % 3 == 0) { (\"\\u4139\"); } else { g2.g0.offThreadCompileScript(\"function f0(this.m1) \\\"\\\\u0F09\\\"\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: NaN })); }  }  }  }  } ");
/*fuzzSeed-244067732*/count=844; tryItOut("m0.delete((4277));");
/*fuzzSeed-244067732*/count=845; tryItOut("while(( /x/g ) && 0)var dxqdgr = new SharedArrayBuffer(16); var dxqdgr_0 = new Uint16Array(dxqdgr); dxqdgr_0[0] = 13; var dxqdgr_1 = new Float64Array(dxqdgr); print(dxqdgr_1[0]); dxqdgr_1[0] = 4611686018427388000; t2[9] = e0;");
/*fuzzSeed-244067732*/count=846; tryItOut("testMathyFunction(mathy4, [0x100000001, 1, Number.MAX_VALUE, 2**53+2, -(2**53), 0x080000000, 0x0ffffffff, 0, -(2**53+2), 0.000000000000001, 1.7976931348623157e308, 42, Number.MIN_VALUE, 0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, 1/0, -1/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, -0x080000001, 0x07fffffff, -0x080000000, -(2**53-2), -0, 0x100000000, -0x100000000, Math.PI, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, -0x100000001]); ");
/*fuzzSeed-244067732*/count=847; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.expm1(Math.expm1((( ! ( + x)) | 0))); }); testMathyFunction(mathy4, [-(2**53-2), -0x080000001, -0x100000001, -(2**53), 1/0, 1, 2**53-2, 2**53+2, -Number.MIN_VALUE, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, 0x07fffffff, 0, 0x100000001, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, -Number.MAX_VALUE, 0x080000000, -0]); ");
/*fuzzSeed-244067732*/count=848; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=849; tryItOut("\"use asm\"; print(d);function eval(e, ...\u3056) { yield d } for (var v of a0) { try { for (var p in s0) { try { m2.get(g1); } catch(e0) { } for (var v of s2) { try { o1 + ''; } catch(e0) { } Array.prototype.shift.apply(a0, []); } } } catch(e0) { } ; }d = /*FARR*/[...(13 for (y of timeout(1800)) for (this.\u3056 of (d = Proxy.createFunction(({/*TOODEEP*/})(z), (1 for (x in [])),  /x/ ))) for each (z in (((makeFinalizeObserver('tenured'))) for (b of  /x/ ) for (w of  '' ) if (Math))) for each (a in /*MARR*/[/(?=[\\u0053-\\u3e00\\W]){2,2}/y, true, true, true,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true, true, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true,  '' , true,  '' ,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' ,  '' , true,  '' ,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' ,  '' , true,  '' ,  '' , true, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' ,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' ,  '' ,  '' , true,  '' , true,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true, true, /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' , true,  '' ,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true, /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true, true,  '' ,  '' , true, true, /(?=[\\u0053-\\u3e00\\W]){2,2}/y,  '' ,  '' , true, true, true, true, true,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true,  '' , true,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true,  '' ,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true,  '' , /(?=[\\u0053-\\u3e00\\W]){2,2}/y, /(?=[\\u0053-\\u3e00\\W]){2,2}/y, true, /(?=[\\u0053-\\u3e00\\W]){2,2}/y]) for (x of b &= c) for each (y in []) for (this.c of \"\\u1AA8\") for each (x in [])), (x = x), .../*FARR*/[], .../*FARR*/[\nnew RegExp(\"(?!\\\\u00ef{256,259})|(?:\\\\3|\\\\B|\\\\b)$[^\\u00e0-\\\\u3B41][^]+?\", \"yim\") ? new RegExp(\"\\\\b{16384,16388}|\\\\2|(?=\\\\s){2}*?\", \"i\") : ((WeakSet.prototype.has)())], , , new (yield x)(/*FARR*/[].map(encodeURIComponent), let (NaN, gmbdlw, this.this.x, aptaxz, x, acdcfg, qriboe, x) \"\\u0E9A\"), , (4277), this.__defineSetter__(\"y\", x++)].filter(arguments.callee, (new x()));");
/*fuzzSeed-244067732*/count=850; tryItOut("/*bLoop*/for (let mhfdcn = 0; mhfdcn < 17; ++mhfdcn) { if (mhfdcn % 2 == 1) { v1 = g2.runOffThreadScript(); } else { i1.send(g0); }  } ");
/*fuzzSeed-244067732*/count=851; tryItOut("o2.v1 = new Number(s0);");
/*fuzzSeed-244067732*/count=852; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?!\\\\1?(?:[^])*?{0,})){2,35}\", \"g\"); var s = \"_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n\"; print(s.search(r)); ");
/*fuzzSeed-244067732*/count=853; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"function f0(b1) \\\"use asm\\\";   var pow = stdlib.Math.pow;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d0 = (+(-1.0/0.0));\\n    d1 = (d1);\\n    {\\n      d1 = (+((d0)));\\n    }\\n    d1 = (+(((0xa5af248c) / (0xe8d1cdd9))>>>((0x127b759)+(!(0xfb3ac238)))));\\n    d0 = (((d1)) - ( /x/g ));\\n    d0 = (d0);\\n    d1 = (+pow(((d0)), ((((d0)) / ((d0))))));\\n    (Float32ArrayView[(((0x45b6b3ce) ? ((0xb1d9f4b)) : (0x8f65de65))+(0xfbd1ce2f)+(x)) >> 2]) = ((d1));\\n    (Float64ArrayView[2]) = ((d0));\\n    {\\n      d0 = (d0);\\n    }\\n    d0 = (+pow(((-((+(0x86f8c6b))))), ((+((d0))))));\\n    return +((+(((((((32769.0) + (-8388608.0)) > (+((9.671406556917033e+24))))) | ((0xffffffff)-(0xfef48582)-(0x438f1d19))) / (~((0xc61f0d4f)*-0xfffff))) << ((0x66cb0c22)))));\\n  }\\n  return f;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 59 == 43), sourceIsLazy: false, catchTermination: true }));function w(this.d, eval = allocationMarker(), c, z, y, [], a, x, b, x, c, y, c, NaN, c, x =  /x/ , w, x, x, x, y, this.y, eval, \u3056, a, z, \u3056 = \u3056, \u3056, b =  /x/g , x, e = new RegExp(\"(?:\\\\1(?=\\\\3)?[^\\\\S\\\\w\\\\n-\\\\u0041]{2}|\\\\b*)[^\\\\D\\\\t]\", \"gym\"), w, x, window, NaN, w, w, x, window, b, y, window, x, x, x, e = [1], x, x, \"25\", a, x, b, x, x, x = this, x =  /x/ , x, x, x, x, x, callee = \"\\u76CA\", x, window, x, x, x, x =  \"\" , b = eval, d, w, w, eval = 28, e, x, w, w, x, x = true, z = new RegExp(\"\\\\B\", \"gi\"), x = window, x, x, x, b, x, w, x, e, x, c, NaN, x, x = false, b, c, \u3056, window, \u3056 = /^|[\\d\u672f\\cU\u8b8a]{3,6}|((?!\\w))(?:\\S)|[;\u00d4]*?|(?=(?!${0,1})*?)(\\D\\u4107{2,}).{4}\\b|\\W[^]|[^]{0}|($[^]|\\b{1,5})+?/yim, ...x) { return x } (this);function x(x, window =  '' , d = /(?!$)|\\2+/, x, eval, eval, a, x, \u3056, x = x, eval, y, eval, x, x, NaN, \u3056, a, a, z, a, x, -8, x, y =  /x/ , e, a, \u3056, c, \u3056, b = x, d, w, w, x, x, c, b, x, a, a = /\\2+/gy, w, x, x, z, x, window, x, get, x, x, x, c, x, e) { yield  ''  } ( /x/ );");
/*fuzzSeed-244067732*/count=854; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a2, 11, ({enumerable: false}));");
/*fuzzSeed-244067732*/count=855; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return ( ! Math.log2(Math.fround((((Math.ceil(( + mathy1(-Number.MAX_VALUE, Math.cos(( + x))))) | 0) ? (y | 0) : ((((y >>> 0) && (Math.atan2(y, ( + x)) >>> 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy4, /*MARR*/[undefined, (1/0),  /x/g , (1/0), function(){}, undefined,  /x/g , (1/0), undefined,  /x/g , (1/0), function(){}, function(){},  /x/g , function(){}, (1/0),  /x/g , (1/0),  /x/g , (1/0), (1/0),  /x/g , function(){}, undefined, (1/0),  /x/g , function(){},  /x/g , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, undefined, undefined, function(){}, undefined,  /x/g , (1/0), (1/0), undefined, (1/0), function(){},  /x/g , undefined,  /x/g , undefined, function(){}, undefined, undefined, undefined,  /x/g ,  /x/g , function(){}, (1/0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (1/0), (1/0), undefined, undefined,  /x/g , undefined, (1/0), (1/0), (1/0), (1/0), undefined, function(){},  /x/g , undefined, undefined, (1/0), (1/0),  /x/g ,  /x/g , undefined]); ");
/*fuzzSeed-244067732*/count=856; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan(Math.fround((((Math.max(x, Math.trunc(Math.log(((x | 0) , (x | 0))))) | 0) == (( ~ ( ~ ( + Math.pow(( + mathy2(( + x), ( + -Number.MIN_VALUE))), Number.MIN_SAFE_INTEGER)))) | 0)) | 0))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, -0x0ffffffff, -0, -(2**53), 1, 0x100000000, 0, -Number.MIN_VALUE, -0x080000000, 1/0, 0x080000000, 42, 0x100000001, 0/0, 0x080000001, -0x07fffffff, 0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, 2**53, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000]); ");
/*fuzzSeed-244067732*/count=857; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.hypot(Math.sign(( + (mathy0((Math.atan2(((Math.tanh((Math.log10(y) | 0)) | 0) * ( + ( + Math.clz32(( + x))))), Math.sinh((y === Math.log10(x)))) | 0), (( + Math.imul(( + ( ! y)), ((Math.hypot(-Number.MIN_VALUE, (x | 0)) | 0) ** x))) | 0)) | 0))), ((Math.max(( + ( + (y && x))), Math.fround(Math.pow(Math.fround(-Number.MAX_SAFE_INTEGER), Math.fround(Math.fround(((Math.sign(Math.fround(2**53+2)) >>> 0) === Math.fround(( + y)))))))) | 0) ? ( ~ (Math.pow(( + x), ((( ~ ((x | 0) ** (x | 0))) >>> 0) >>> 0)) >>> 0)) : Math.sinh(( + Math.acosh(Number.MIN_VALUE))))); }); testMathyFunction(mathy1, /*MARR*/[(-1/0), new String(''), new String(''), new String(''), [], new String(''), new String(''), (-1/0), [], new String(''), new String(''), [], (-1/0), [], new String(''), [], new String(''), new String(''), (-1/0), (-1/0), new String(''), (-1/0), [], new String(''), (-1/0), new String(''), (-1/0), (-1/0), new String(''), new String(''), (-1/0), new String(''), (-1/0), [], (-1/0), (-1/0), new String(''), new String(''), new String(''), new String(''), [], [], (-1/0), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), [], new String(''), [], [], new String(''), [], new String(''), (-1/0), new String(''), [], new String(''), [], (-1/0), (-1/0), new String(''), (-1/0), (-1/0), [], [], []]); ");
/*fuzzSeed-244067732*/count=858; tryItOut("/*MXX3*/g0.WeakMap = g1.g2.WeakMap;");
/*fuzzSeed-244067732*/count=859; tryItOut("Array.prototype.forEach.call(a0, ((arguments.callee.caller).apply).bind(x, (x)));");
/*fuzzSeed-244067732*/count=860; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var acos = stdlib.Math.acos;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -590295810358705700000.0;\n    {\n      d2 = (-((-((((((-274877906945.0)) / ((+abs(((({x: (Math.log(this))})))))))) / ((d1)))))));\n    }\n    {\n      i0 = (0xffffffff);\n    }\n    d1 = (134217729.0);\n    i0 = (0x985c32b5);\n    i0 = ((-295147905179352830000.0) > (+(1.0/0.0)));\n    return (((0x61e5cce2)+(i0)))|0;\n    (Uint32ArrayView[2]) = ((0xb24aee29));\n    i0 = (0xd0751f8f);\n    d2 = (+acos(((NaN))));\n    {\n      {\n        d2 = (d1);\n      }\n    }\n    {\n      (Uint16ArrayView[2]) = (0x56477*(!(!(!(x())))));\n    }\n    return (((0xb21063a)-((((i0)) ^ ((0xffffffff))))))|0;\n  }\n  return f; })(this, {ff: (void options('strict'))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53+2, -0, 42, -0x100000000, -0x0ffffffff, 1/0, -1/0, 0/0, 0x080000001, 0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -0x07fffffff, 0, Math.PI, 0x0ffffffff, -Number.MIN_VALUE, -0x080000001, -0x080000000, 1, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53, 0x100000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), 2**53-2, 0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=861; tryItOut("v2 = (a2 instanceof p1);");
/*fuzzSeed-244067732*/count=862; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ! Math.max(( + ( - (( + mathy2(( + ( + ( + (x | 0)))), x)) | 0))), x)) , (( ! ( + Math.exp((( + mathy0(y, (Math.sign(y) | 0))) >>> 0)))) >>> 0)); }); testMathyFunction(mathy5, [0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -1/0, Math.PI, 2**53-2, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -0x100000000, 2**53+2, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, 0/0, -0x080000001, -(2**53-2), 1.7976931348623157e308, -0, -(2**53), 42, 1, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -0x100000001, -(2**53+2), 0x07fffffff, -0x080000000, 1/0, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=863; tryItOut("b = x;/*RXUB*/var r = r2; var s = \"\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u00ec\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\\u7c1c\"; print(uneval(s.match(r))); ");
/*fuzzSeed-244067732*/count=864; tryItOut("");
/*fuzzSeed-244067732*/count=865; tryItOut("for (var v of v0) { try { b0.toString = Symbol.for; } catch(e0) { } try { this.m1 + ''; } catch(e1) { } if(true) { if (Date(/*wrap1*/(function(){ e2.delete(a1);return WeakMap.prototype.get})()() != (x << ), 'fafafa'.replace(/a/g, function shapeyConstructor(edwjbr){\"use strict\"; if (edwjbr) this[\"arguments\"] = false ,  \"\" ;Object.defineProperty(this, \"__count__\", ({writable: true, configurable: (x % 4 != 0), enumerable: false}));this[\"__count__\"] = \"\\uCB85\".unwatch(\"d\");for (var ytqfypdmt in this) { }for (var ytqwiowfw in this) { }Object.freeze(this);{ t2.set(g1.a2, v1); } this[\"-11\"] = x;if (edwjbr) Object.defineProperty(this, \"arguments\", ({configurable: false}));Object.preventExtensions(this);return this; }))) {(\"\\u7307\");\na0.shift();\nprint(x); }} else m0.has(g1); }");
/*fuzzSeed-244067732*/count=866; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return Math.min(Math.imul(Math.log1p(x), (( + Math.asinh(Math.max(( + Math.max(x, ( + x))), mathy0(x, Math.asin(-0x080000000))))) >>> 0)), ( - ( + (Math.fround(Math.fround(Math.sign(Math.fround(y)))) <= Math.fround(( + (Math.fround(42) === ( + (( - Math.fround(( - -(2**53)))) | 0))))))))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -0x080000000, 2**53, 0x0ffffffff, -Number.MIN_VALUE, -0x100000000, 0x07fffffff, 0x080000001, 0, Number.MIN_VALUE, -(2**53), 0/0, -(2**53+2), -1/0, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 2**53+2, -0x07fffffff, -0x080000001, Math.PI, -0, 1, 1/0, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=867; tryItOut("m1.has(e1);");
/*fuzzSeed-244067732*/count=868; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=869; tryItOut("\"use strict\"; \"use asm\"; a1 + v1;");
/*fuzzSeed-244067732*/count=870; tryItOut("mathy2 = (function(x, y) { return Math.hypot((Math.asinh(( ~ y)) != Math.fround(Math.pow(Math.fround(0x080000000), Math.fround(( + (( + x) == y)))))), (Math.atan2((Math.fround(Math.cbrt(((((( + ( ! ( + y))) >>> 0) == (y >>> 0)) >>> 0) >>> 0))) >>> 0), (Math.fround((y === y)) << (( ! ((x , x) >>> 0)) >>> 0))) ** Math.expm1(Math.max((((( ! x) | 0) >>> (Math.pow(( + x), x) | 0)) | 0), x)))); }); testMathyFunction(mathy2, [-1/0, 0x080000000, 2**53, 0x07fffffff, -0x080000000, -0x100000001, 1/0, -Number.MIN_VALUE, -0, 0x100000001, -0x100000000, 0x080000001, 2**53+2, 0/0, -(2**53-2), Math.PI, -Number.MAX_VALUE, -0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 0, 0.000000000000001, 0x0ffffffff, 1, -0x080000001, -(2**53+2), -0x0ffffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-244067732*/count=871; tryItOut("t1[14] = o1;");
/*fuzzSeed-244067732*/count=872; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! Math.fround((( ~ (mathy1((y != (Math.abs((y | 0)) | 0)), (y ? Math.sqrt((y >>> 0)) : (x <= Math.hypot(y, ((x > y) | 0))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, 1/0, 0x07fffffff, 0x080000001, 0.000000000000001, -0x080000000, 2**53, 0, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000001, 0x100000000, -(2**53-2), 42, 0x100000001, -0x0ffffffff, 1, -0, -Number.MIN_VALUE, -(2**53), 0x080000000, -(2**53+2), 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0/0, -0x100000000, -0x080000001]); ");
/*fuzzSeed-244067732*/count=873; tryItOut("Array.prototype.shift.apply(a1, [p1, t0]);/*ODP-2*/Object.defineProperty(i1, \"wrappedJSObject\", { configurable: true, enumerable: (x % 2 == 1), get: f1, set: (function() { Array.prototype.reverse.call(a0); return t2; }) });");
/*fuzzSeed-244067732*/count=874; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      {\n        (Float32ArrayView[0]) = ((d1));\n      }\n    }\n    i0 = (0x15f1b700);\n    return (((((((/*FFI*/ff(((16385.0)), ((-7.737125245533627e+25)), ((4294967295.0)), ((-7.555786372591432e+22)), ((3.8685626227668134e+25)))|0) ? (0xa6c4322) : ((-4194305.0) != (-8388608.0)))+((NaN) > (((-17592186044417.0)) * ((-2147483649.0)))))>>>(-0xdd3b8*(0xffffffff))) < (0x4df074eb))-(i2)))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ a1[13];return Promise.prototype.catch})()}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [/0/, true, 0.1, false, objectEmulatingUndefined(), '', -0, (new String('')), (new Boolean(true)), NaN, ({valueOf:function(){return 0;}}), '\\0', 1, null, 0, (function(){return 0;}), undefined, [0], (new Number(-0)), ({toString:function(){return '0';}}), '/0/', (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(0)), [], '0']); ");
/*fuzzSeed-244067732*/count=875; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\b?`{1,}?[^]\\3.+)|\\3(?!([^]))|\\x0e+/gi; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=876; tryItOut("v2 = Object.prototype.isPrototypeOf.call(v0, this.h0);");
/*fuzzSeed-244067732*/count=877; tryItOut("{ void 0; validategc(false); } s0 += 'x';");
/*fuzzSeed-244067732*/count=878; tryItOut("for (var v of h1) { try { var t2 = t0.subarray((4277)); } catch(e0) { } a2 = []; }");
/*fuzzSeed-244067732*/count=879; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((( ! (((( ! 0x0ffffffff) >>> 0) , ((( ! ( - y)) >>> 0) >>> 0)) || y)) | 0) ** (( ! ( + Math.acosh(((((Math.hypot(Number.MAX_VALUE, y) >>> 0) <= Math.fround(Math.pow((x | 0), (( + ( + (x | 0))) | 0)))) | 0) | 0)))) | 0)) | 0); }); testMathyFunction(mathy0, [2**53-2, Math.PI, 1.7976931348623157e308, 0x100000001, 0.000000000000001, -0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, -1/0, Number.MIN_VALUE, 2**53+2, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 1, -(2**53), -Number.MAX_VALUE, -(2**53-2), 0, 2**53, 0x100000000, Number.MAX_VALUE, 1/0, -0x07fffffff, 0x07fffffff, 0/0, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=880; tryItOut("g0[\"min\"] = g2.g1;");
/*fuzzSeed-244067732*/count=881; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.imul(((( - (( + y) === ( + -0x080000000))) | 0) >>> 0), (Math.fround(Math.pow(Math.fround(Math.sinh(( ! Number.MAX_SAFE_INTEGER))), Math.pow(( - y), (( + Math.atan2(0/0, Math.fround(x))) | y)))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[[] = (+this), [] = (+this), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [] = (+this), x, x]); ");
/*fuzzSeed-244067732*/count=882; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy2(Math.sqrt((( + (Math.imul((y >>> 0), (x >>> 0)) >>> 0)) + (Math.atan2(Math.fround(mathy2(Math.fround(x), Math.fround(Math.fround(mathy2(Math.fround(y), Math.fround(Math.log1p(y))))))), (mathy0(0x080000001, y) && ( + Math.log2(x)))) | 0))), Math.fround((( - ( + ( ~ y))) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=883; tryItOut("\"use strict\"; for(c in (((this).call)(/(?!(?=(?:\\3))*?)|\\1+?/gy)))print(c);");
/*fuzzSeed-244067732*/count=884; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.atan2(mathy1(Math.fround(( + (Math.max(((((x | 0) == (( + (2**53 + x)) | 0)) | 0) >>> 0), (y >>> 0)) >>> 0))), Math.pow(( ! ( + Math.log1p(( + (Math.pow((x | 0), -Number.MIN_VALUE) | 0))))), (x >>> Math.tanh(x)))), Math.imul(mathy1((( + ( - ( + 1))) ^ y), Math.fround((Math.log10((Math.pow(y, (x == x)) >>> 0)) | 0))), mathy1(Number.MAX_SAFE_INTEGER, (( + Math.acos(Math.log1p(( + Math.min(Number.MIN_VALUE, x))))) >>> 0)))); }); testMathyFunction(mathy2, [-0, 0.1, objectEmulatingUndefined(), '', (new Boolean(false)), false, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 0, '\\0', (new Number(0)), true, (new String('')), (function(){return 0;}), ({valueOf:function(){return '0';}}), NaN, [], undefined, [0], (new Number(-0)), '0', /0/, 1, '/0/', (new Boolean(true)), null]); ");
/*fuzzSeed-244067732*/count=885; tryItOut("var mfyhtp = new ArrayBuffer(0); var mfyhtp_0 = new Int16Array(mfyhtp); print(mfyhtp_0[0]); var mfyhtp_1 = new Int32Array(mfyhtp); mfyhtp_1[0] = -8; var mfyhtp_2 = new Int32Array(mfyhtp); print(mfyhtp_2[0]); mfyhtp_2[0] = -15; var mfyhtp_3 = new Int8Array(mfyhtp); var mfyhtp_4 = new Float32Array(mfyhtp); print(mfyhtp_4[0]); mfyhtp_4[0] = -1; e0.toSource = (function() { for (var j=0;j<125;++j) { f2(j%5==1); } });");
/*fuzzSeed-244067732*/count=886; tryItOut("\"use strict\"; /*bLoop*/for (uwrcji = 0; uwrcji < 46; ++uwrcji) { if (uwrcji % 33 == 27) { g0.g0.g2.toSource = f2; } else { print(x); }  } ");
/*fuzzSeed-244067732*/count=887; tryItOut("/*RXUB*/var r = /($){4,}/gy; var s = \"\\n\\n\\n\\n\\n\\u994c\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=888; tryItOut("\"use strict\"; /*RXUB*/var r = o0.r2; var s = s1; print(s.replace(r, offThreadCompileScript, \"gi\")); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=889; tryItOut("mathy2 = (function(x, y) { return (Math.fround(Math.pow(Math.fround(((( + ( ~ Math.fround(0.000000000000001))) || x) | 0)), Math.fround(Math.cbrt(Math.sqrt(0.000000000000001))))) <= (mathy0((( ! Math.fround(mathy0(Math.fround(x), Math.fround((Math.asinh(((Math.cos(Math.fround(y)) | 0) >>> 0)) >>> 0))))) | 0), (Math.fround(Math.hypot(Math.fround(Math.trunc(( + Math.ceil(( + y))))), Math.ceil(Math.fround(y)))) | 0)) | 0)); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, -0x0ffffffff, 0x100000000, Math.PI, -0x100000001, 0.000000000000001, 42, 1.7976931348623157e308, 0x080000000, 2**53-2, -Number.MAX_VALUE, 2**53, 0x0ffffffff, -1/0, -0x080000000, 0, 1/0, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, 2**53+2, -(2**53+2), -0x07fffffff, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, -0, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=890; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-244067732*/count=891; tryItOut("\"use strict\"; m1.delete(h1);");
/*fuzzSeed-244067732*/count=892; tryItOut("Array.prototype.pop.call(a0);");
/*fuzzSeed-244067732*/count=893; tryItOut("mathy3 = (function(x, y) { return Math.cosh(( + Math.min(( + (( - (x | 0)) | 0)), ( + mathy0(Math.fround(Math.fround(Math.atan2(Math.fround(Math.fround((Math.fround(x) !== Math.fround(Math.sign((( + (-Number.MAX_VALUE >>> 0)) >>> 0)))))), -0x080000000))), Math.fround(( + ( - (x >>> 0))))))))); }); testMathyFunction(mathy3, /*MARR*/[new String(''), false, false]); ");
/*fuzzSeed-244067732*/count=894; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( + Math.fround(Math.expm1(((((( + ( - (y >>> 0))) >>> 0) >> ( + ( - x))) >>> 0) >>> 0)))) | 0); }); testMathyFunction(mathy4, [0/0, -(2**53), 0x080000000, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, 42, 0x100000000, -(2**53-2), 0.000000000000001, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, 1, -0x0ffffffff, 1.7976931348623157e308, 0x080000001, -0x080000000, 0, Number.MIN_VALUE, 1/0, 2**53-2, -0, -0x100000001, -(2**53+2), 2**53]); ");
/*fuzzSeed-244067732*/count=895; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i0);\n    }\n    switch ((((i0)) ^ ((0x1c74dd17) % (-0x8000000)))) {\n      case 1:\n        {\n          i1 = ((imul((i1), ((+(-1.0/0.0)) >= ((262144.0) + (576460752303423500.0))))|0) >= ((((i1) ? ((-1.0009765625) > (2251799813685247.0)) : (i1))-(i0)) >> (((0x2d7446d4) != (((i0)-((4294967297.0) == (1.001953125)))>>>((0x93b97a5) / (0x3ee9c442)))))));\n        }\n        break;\n    }\n    i0 = (i0);\n    i1 = (i0);\n    i1 = (i1);\n    i1 = (((6.189700196426902e+26)));\n    {\n      {\n        i0 = ((((i0)+(/*FFI*/ff(((0.125)))|0))>>>((((((abs((((0x2a63b2ee)) ^ ((0x4011ac91))))|0)))>>>((((0xfce266cb))>>>((0x68af852a))) % (((0x37a0a296)))))))) >= (((i0)-(i0)-(!(i1)))>>>((i1))));\n      }\n    }\n    (Float32ArrayView[1]) = ((+abs(((-9223372036854776000.0)))));\n    return (((/*FFI*/ff(((0x16adef5e)), ((-35184372088832.0)), ((((0x0) % (((0x94f346df) % (0xcdbd4a87))>>>((0xffffffff)+(0xfe35da56)-(-0x8000000)))) & ((i0)*-0xfffff))), ((9223372036854776000.0)), ((0x24933e98)))|0)))|0;\n    i0 = (i1);\n    {\n      i1 = ((((i1)) >> ((i0))));\n    }\n    (Float32ArrayView[((/*FFI*/ff(((-144115188075855870.0)), ((~((i1)*-0xc1671))), ((~~(-513.0))), ((abs((-0xc495ed))|0)), (((0x58afa790) ? (-131072.0) : (1.0))), ((4097.0)), ((295147905179352830000.0)), ((-16777216.0)), ((549755813889.0)), ((33.0)))|0)) >> 2]) = ((-9.0));\n    return (((((0x1182f7b4) % (imul((i0), ((-134217729.0) <= (140737488355329.0)))|0)) << ((i0)+((0.5) <= (-1048577.0)))) / (~((!(i0))*-0x57765))))|0;\n  }\n  return f; })(this, {ff: -18446744073709552000}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -0x100000001, 0/0, 0x0ffffffff, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, -1/0, 1/0, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53, 1, Math.PI, Number.MIN_VALUE, -0, 2**53-2, -(2**53-2), -0x080000001, 42, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -(2**53+2), -0x100000000, 0, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=896; tryItOut("mathy1 = (function(x, y) { return (mathy0(( + Math.asin(((Math.asin(( ~ y)) * x) >>> 0))), Math.abs(Math.min(x, (0x080000000 | 0)))) ** Math.min(Math.fround((Math.fround(( - ( - x))) - Math.fround((y >= 2**53+2)))), mathy0(( + Math.atan(((((y >>> 0) == (-Number.MAX_VALUE >>> 0)) >>> 0) >>> 0))), (( ! y) >>> 0)))); }); testMathyFunction(mathy1, [0x080000001, -(2**53+2), -(2**53), Number.MIN_SAFE_INTEGER, -1/0, -0, -0x080000001, 0, 0x100000001, -Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x100000000, -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, 1/0, 0.000000000000001, -0x080000000, Number.MAX_VALUE, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, 0x080000000, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, -0x07fffffff, 1, 0/0]); ");
/*fuzzSeed-244067732*/count=897; tryItOut("a2[13] = t1;");
/*fuzzSeed-244067732*/count=898; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.expm1(Math.fround((( - (Math.fround(( - ((( ~ mathy1((x | 0), (x | 0))) | 0) | 0))) | 0)) | 0))); }); ");
/*fuzzSeed-244067732*/count=899; tryItOut("mathy5 = (function(x, y) { return (mathy0(Math.round(Math.imul(Math.imul(x, Math.fround(( ! ( + -Number.MIN_SAFE_INTEGER)))), ( + Math.ceil(( - (x | 0)))))), (( + (Math.fround(Math.imul((Math.hypot(((((x >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0) | 0), ( + x)) | 0), ( + (( + (Math.atan2((0x080000000 | 0), (x >>> 0)) | 0)) ? ( + (y || Math.atan(0x080000001))) : ( + (Math.fround(mathy3(Math.fround(x), Math.fround(x))) ? (x | 0) : 0/0)))))) << (Math.atan2((0.000000000000001 << y), (Math.asin((y >>> 0)) | 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy5, [0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 2**53, 0x07fffffff, 1.7976931348623157e308, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, -(2**53-2), 1, -(2**53+2), -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, 0.000000000000001, Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, 2**53+2, -0x080000000, -Number.MAX_VALUE, 42, 1/0, -(2**53), 2**53-2, 0x0ffffffff, -0x0ffffffff, Number.MIN_VALUE, 0, 0/0, -0x07fffffff, -0]); ");
/*fuzzSeed-244067732*/count=900; tryItOut("\"use strict\"; testMathyFunction(mathy2, [NaN, ({valueOf:function(){return 0;}}), 0.1, (new Boolean(true)), ({toString:function(){return '0';}}), '0', true, '/0/', undefined, (new Boolean(false)), '\\0', (new Number(0)), ({valueOf:function(){return '0';}}), (new Number(-0)), null, 1, -0, /0/, (function(){return 0;}), (new String('')), [0], objectEmulatingUndefined(), '', [], false, 0]); ");
/*fuzzSeed-244067732*/count=901; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-244067732*/count=902; tryItOut("\"use strict\"; g1 + '';");
/*fuzzSeed-244067732*/count=903; tryItOut("{for (var v of s0) { a1[19] = a0; } }");
/*fuzzSeed-244067732*/count=904; tryItOut("s2 = s2.charAt(new ([] = NaN = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: Date.prototype.getTime, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: function() { throw 3; }, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(\"\\u0552\"), e))());");
/*fuzzSeed-244067732*/count=905; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.max(((Math.asinh((Math.fround(Math.pow(Math.fround(x), (x - ( + mathy1(( + ( + Math.min((0x0ffffffff | 0), (x | 0)))), ( + y)))))) | 0)) | 0) | 0), ((Math.fround(mathy0(Math.pow(Math.fround((Math.fround(y) !== Math.fround(Math.fround((Math.fround(x) == (y >>> 0)))))), 2**53+2), x)) - (( + Math.asinh(((y >>> 0) << Math.fround(Math.fround((Math.fround(Math.log10(y)) ** Math.fround(x))))))) ? (Math.fround(( ~ (Math.acos(x) >>> 0))) | 0) : Math.cos(( - (Math.round((y >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy2, [-1/0, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 2**53+2, 0x100000001, 0, 2**53, -0x100000001, -0x080000001, -0x07fffffff, -Number.MIN_VALUE, -0x080000000, 2**53-2, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, -0, Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), 1, 0.000000000000001, -(2**53), 0x100000000, -0x0ffffffff, 0x080000001, 0/0, Math.PI, 1/0, -0x100000000]); ");
/*fuzzSeed-244067732*/count=906; tryItOut("\"use strict\"; var zjqwvt = new ArrayBuffer(16); var zjqwvt_0 = new Uint16Array(zjqwvt); zjqwvt_0[0] = -24; var zjqwvt_1 = new Uint8Array(zjqwvt); zjqwvt_1[0] = -20; this.o1.g1.t1[19] = window;");
/*fuzzSeed-244067732*/count=907; tryItOut("\"use asm\"; /*hhh*/function ycnezy(c, [{}, , [, , , , {eval: [x], x}, ], , {x, x: [{}, {yield, x: \u3056, x: {x}}, {this.b: [], a: x, x: [{x: [d]}, , of, x, c], e}, , ], x, x, e: [{}, {a: [, , x, , []], eval: {NaN: x, x: [{x, x, this.z}, , \n, ], x: NaN, w: [[, []]], x}, x}, a, {z: [, c], c: {z: a}, eval, \u3056: b, x: [, [, [], , [x, a, {}]], \u3056, {}, ], eval}, ], window, \"\u03a0\"}, x]){/* no regression tests found */}/*iii*/this.zzz.zzz;let(e) { throw StopIteration;}");
/*fuzzSeed-244067732*/count=908; tryItOut("\"use strict\"; a2.pop(s2);");
/*fuzzSeed-244067732*/count=909; tryItOut("/*vLoop*/for (let fkamfl = 0; fkamfl < 26; ++fkamfl) { a = fkamfl; L:for(c in z) g2.a1 = /*FARR*/[(void version(185)), , .../*PTHR*/(function() { \"use strict\"; \"use asm\"; for (var i of eval(\"/* no regression tests found */\")) { yield i; } })(),  /* Comment */c]; } ");
/*fuzzSeed-244067732*/count=910; tryItOut("throw StopIteration;this.zzz.zzz;");
/*fuzzSeed-244067732*/count=911; tryItOut("\"use strict\"; i2 = new Iterator(this.m2);");
/*fuzzSeed-244067732*/count=912; tryItOut("b2 = t0.buffer;");
/*fuzzSeed-244067732*/count=913; tryItOut("for(let w = /.+?0|(?=\\3)(?:[\\t-o\\D])/m in [1]) {h2.fix = (function(j) { if (j) { try { a1 = a2.slice(NaN, NaN, g2.g0); } catch(e0) { } f1(b0); } else { try { /*RXUB*/var r = r1; var s = s0; print(s.split(r));  } catch(e0) { } let a2 = a0.slice(1, 5); } });t1.set(t1, this); }");
/*fuzzSeed-244067732*/count=914; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.round(((Math.imul((-(2**53+2) >>> 0), Math.fround(Math.atan2(( + (1.7976931348623157e308 != -0x07fffffff)), Math.asin(x)))) / (Math.sign(Math.fround((Math.max(( - x), (2**53+2 | 0)) | 0))) >>> 0)) | 0)); }); ");
/*fuzzSeed-244067732*/count=915; tryItOut("t1[1];");
/*fuzzSeed-244067732*/count=916; tryItOut("print(y ^ z);print(x);");
/*fuzzSeed-244067732*/count=917; tryItOut("this.e0.delete(p2);");
/*fuzzSeed-244067732*/count=918; tryItOut("(/[^\\cY\\x7f\\u7343]|(?=[^]|.+?|[\uc932-\\cFJ-\ubfa8]){2,5}\\s[]\\3{2,3}/y);");
/*fuzzSeed-244067732*/count=919; tryItOut("v1 = (i2 instanceof b1);");
/*fuzzSeed-244067732*/count=920; tryItOut("o0.toSource = (function() { for (var j=0;j<23;++j) { f2(j%2==1); } });");
/*fuzzSeed-244067732*/count=921; tryItOut("x = o0;");
/*fuzzSeed-244067732*/count=922; tryItOut("print(x);\nprint(x);Array.prototype.pop.apply(a1, []);\n");
/*fuzzSeed-244067732*/count=923; tryItOut("\"use strict\"; \"use asm\"; throw window;return (this.zzz.zzz) = x;");
/*fuzzSeed-244067732*/count=924; tryItOut("/*MXX2*/o0.o1.g2.TypeError = v1;");
/*fuzzSeed-244067732*/count=925; tryItOut("\"use asm\"; v1 = g0.a1.reduce, reduceRight(f1, i1, g2);");
/*fuzzSeed-244067732*/count=926; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-244067732*/count=927; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -32767.0;\n    i0 = (!(0x3f940b9c));\n    d2 = (d2);\n    {\n      i1 = (0xfd4443a2);\n    }\n    switch ((((0xf8a94fb0)-(0xf908bd38)+(0x473403e1)) << ((-0x8000000) / (0x1e6d08b9)))) {\n      case 0:\n        {\n          d2 = (+abs(((d2))));\n        }\n    }\n    d2 = ((x) % ((d2)));\n    d2 = (-3.0);\n    (Float32ArrayView[((0x885140d8)-((imul((i0), ((0xb29691c2) ? (0xfc4e9754) : (0xf8233f00)))|0) >= (((0xb1480278)+(0xffffffff)) ^ ((4277))))) >> 2]) = ((+(abs((((d2)) << ((((Uint8ArrayView[((0xfc6f559c)) >> 0]))>>>(((0x48983f42))-(-0x8000000))) / (((x))>>>((i0)-(0xf865533f))))))|0)));\n    return +((16385.0));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 1/0, -0, -0x100000000, -Number.MIN_VALUE, 42, 2**53-2, 0x0ffffffff, -Number.MAX_VALUE, 0x100000001, Math.PI, 0x07fffffff, -(2**53+2), -0x080000001, -0x07fffffff, -0x080000000, Number.MAX_VALUE, 0.000000000000001, 1, 0, -(2**53), 1.7976931348623157e308, -0x0ffffffff, 2**53, 0x100000000, 0x080000001, 0/0, -1/0]); ");
/*fuzzSeed-244067732*/count=928; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + (( + Math.trunc((Math.pow(y, x) | 0))) / ( + ((y & (((x | 0) <= (Math.fround(Math.max(Math.fround((y << x)), x)) | 0)) | 0)) < 1.7976931348623157e308)))); }); testMathyFunction(mathy0, ['0', (new Number(0)), (function(){return 0;}), '\\0', null, false, /0/, objectEmulatingUndefined(), (new Number(-0)), true, 0, (new Boolean(false)), ({toString:function(){return '0';}}), NaN, (new String('')), -0, [], ({valueOf:function(){return 0;}}), [0], (new Boolean(true)), 0.1, undefined, '/0/', '', 1, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-244067732*/count=929; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.min(( + Math.imul(((( - Math.clz32((Math.acosh(x) >>> 0))) | 0) | 0), ( - Math.fround(( + Math.log10((x <= ( + y)))))))), ( + Math.max((( ! ( + Math.fround(Math.pow(Math.fround(Math.log2(y)), Math.fround((Math.fround(( ! -Number.MIN_VALUE)) || y)))))) | 0), Math.fround(( + mathy1((Math.pow(((Math.fround(x) ? Math.fround(0.000000000000001) : y) >>> 0), (x >>> 0)) >>> 0), (x >> ( - y)))))))); }); testMathyFunction(mathy5, [0x100000000, 0, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -0, 2**53+2, Number.MIN_SAFE_INTEGER, 42, -1/0, Math.PI, -0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, 0x080000001, -(2**53), 1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, Number.MAX_VALUE, -0x100000000, 1, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, -(2**53+2), 0x07fffffff, -0x100000001, 2**53]); ");
/*fuzzSeed-244067732*/count=930; tryItOut("\"use strict\"; v1 = (e2 instanceof t2);");
/*fuzzSeed-244067732*/count=931; tryItOut("\"use strict\"; var xffkcy = new ArrayBuffer(6); var xffkcy_0 = new Uint8ClampedArray(xffkcy); xffkcy_0[0] = 20;  /x/g ; /x/g ;(false);( /x/ );window;print(xffkcy_0[0]);");
/*fuzzSeed-244067732*/count=932; tryItOut("mathy2 = (function(x, y) { return Math.fround((Math.atan2(((Math.cosh((Math.asin(y) | 0)) | 0) >>> 0), (( ! (Math.fround(mathy0(Math.log((Math.atan2(x, x) >>> 0)), x)) * (Math.min((y >>> 0), Math.fround(Math.imul(y, y))) >>> 0))) | 0)) ? ( + Math.exp((Math.fround(Math.abs(( + ( + mathy1(Math.expm1(x), x))))) | 0))) : ( + (mathy0((Math.ceil((Math.hypot(Math.max(y, -0), 0x100000001) >>> 0)) | 0), (( ! ( + y)) | 0)) | 0)))); }); ");
/*fuzzSeed-244067732*/count=933; tryItOut("\"use strict\"; /*MXX3*/g0.Array.from = g2.Array.from;");
/*fuzzSeed-244067732*/count=934; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((((( ! (y | 0)) | 0) === ((mathy1(y, (Math.fround((Math.fround(x) ** Math.fround(Math.min(Math.min(x, x), y)))) | 0)) ? x : y) | 0)) < Math.cos(Math.fround((( ~ x) >= Math.sign(Math.trunc(y)))))) | 0); }); testMathyFunction(mathy3, [0x0ffffffff, 0x07fffffff, -0x100000001, -(2**53+2), 2**53+2, 0x100000000, 0x100000001, 0.000000000000001, Math.PI, -Number.MAX_VALUE, 1, 2**53-2, -0x080000001, Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -(2**53), -0x100000000, -0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, -0, -Number.MIN_VALUE, -0x080000000, 0/0, 0, 2**53, -1/0]); ");
/*fuzzSeed-244067732*/count=935; tryItOut("\"use strict\"; a2[v2] = o0;");
/*fuzzSeed-244067732*/count=936; tryItOut("\"use asm\"; w = timeout(1800);this.s0 + '';");
/*fuzzSeed-244067732*/count=937; tryItOut("s0 = new String(v1);");
/*fuzzSeed-244067732*/count=938; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - Math.fround((Math.fround(Math.sqrt(x)) ** (( + Math.fround(Math.hypot(y, y))) | 0)))); }); testMathyFunction(mathy3, [1/0, -1/0, -0, 0x07fffffff, 42, -Number.MIN_VALUE, -0x0ffffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, 0x100000000, -0x080000000, 0, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 0/0, 0.000000000000001, 1, 0x100000001, -0x100000001, 0x0ffffffff, -(2**53+2), -(2**53), -Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-244067732*/count=939; tryItOut("\"use strict\"; a0.shift();");
/*fuzzSeed-244067732*/count=940; tryItOut("\"use strict\"; for (var p in t0) { try { s0 + g2.s0; } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { a1.pop(o2.g2, o1); } catch(e2) { } g2.a0.splice(-11, 0); }");
/*fuzzSeed-244067732*/count=941; tryItOut("\"use strict\"; true;let(e) ((function(){for(let y of new Array(6)) ( '' );})());");
/*fuzzSeed-244067732*/count=942; tryItOut("\"use strict\"; ");
/*fuzzSeed-244067732*/count=943; tryItOut("\"use asm\"; /*RXUB*/var r = /\\1|^+?.[\\\u0017-\u8914\udca1\\cT-\u8220\\u004d-\\u0062]{1,}{3,6}|(?:\\2*)+?[\\s\\cC\\cL]{1,5}/m; var s = \"\\u000b\\u000b\\u000b\"; print(uneval(s.match(r))); ");
/*fuzzSeed-244067732*/count=944; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.acosh((( + (( ! (( + ( + y)) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [-0x100000000, -0x100000001, 42, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 0x100000001, -0x080000000, -1/0, -(2**53), -0, 0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -(2**53-2), 0.000000000000001, 0x0ffffffff, -0x080000001, 2**53-2, 2**53+2, 1, Math.PI, -(2**53+2), 0/0, -0x07fffffff, 2**53, Number.MAX_VALUE, 1/0, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=945; tryItOut("function this.f0(t2)  { return x } ");
/*fuzzSeed-244067732*/count=946; tryItOut("e = 22, z, macrdb;g1.a1.reverse();");
/*fuzzSeed-244067732*/count=947; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return mathy1(mathy3(Math.hypot((y >>> 0), ((Math.min(Math.log10(Math.fround(x)), (Math.min(( + y), Math.tan(-0x100000001)) | 0)) >>> 0) >>> 0)), (Math.fround(((( ~ (y != ( + -Number.MAX_VALUE))) ** (( ~ (( - y) << x)) | 0)) | 0)) <= ( + y))), (mathy1(( + x), mathy2((( + (Math.sinh((x >>> 0)) >>> 0)) >>> 0), mathy1(x, ( - (( + Math.clz32(( + x))) | 0))))) >>> Math.fround(y))); }); ");
/*fuzzSeed-244067732*/count=948; tryItOut("testMathyFunction(mathy1, /*MARR*/[false, false, false, function(){}, -Number.MAX_SAFE_INTEGER, function(){}, -Number.MAX_SAFE_INTEGER, false, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER,  'A' , false, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER,  'A' , function(){}, function(){}]); ");
/*fuzzSeed-244067732*/count=949; tryItOut("print(x);");
/*fuzzSeed-244067732*/count=950; tryItOut("const z = x;this.a2.pop();");
/*fuzzSeed-244067732*/count=951; tryItOut("v2 = a2.length;");
/*fuzzSeed-244067732*/count=952; tryItOut("t0[9];");
/*fuzzSeed-244067732*/count=953; tryItOut("testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, Number.MIN_VALUE, 2**53+2, -0, Number.MAX_VALUE, Math.PI, 2**53, 2**53-2, 0x07fffffff, -(2**53), -0x0ffffffff, 0x0ffffffff, 0/0, -(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -0x080000001, 1.7976931348623157e308, -0x100000000, 0x080000001, 1/0, -(2**53+2), -0x080000000, 0.000000000000001, -Number.MAX_VALUE, -0x100000001, -0x07fffffff, 0x100000000, 0, 42]); ");
/*fuzzSeed-244067732*/count=954; tryItOut("a1.push(a1);\n/*RXUB*/var r = new RegExp(\"(?!(?!\\\\W))\", \"gym\"); var s = \"_\"; print(r.exec(s)); print(r.lastIndex); \n");
/*fuzzSeed-244067732*/count=955; tryItOut("m1 + a2;");
/*fuzzSeed-244067732*/count=956; tryItOut("\"use asm\"; h1.set = (void version(170));");
/*fuzzSeed-244067732*/count=957; tryItOut("/*MXX3*/g1.TypeError.prototype.toString = g0.TypeError.prototype.toString;");
/*fuzzSeed-244067732*/count=958; tryItOut("testMathyFunction(mathy1, [-0, 0x07fffffff, 0, -(2**53), 0/0, 0x100000001, -0x07fffffff, -0x080000001, -(2**53+2), -1/0, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 2**53, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, -0x100000001, 0x080000000, -0x100000000, 2**53+2, 2**53-2, 1.7976931348623157e308, -Number.MAX_VALUE, 1/0, 0x100000000, 0x080000001, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=959; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return Math.pow((Math.hypot(Math.pow(mathy2(Math.max((((0 | 0) >>> (x | 0)) | 0), -Number.MAX_SAFE_INTEGER), (mathy1((y >>> 0), (y >>> 0)) >>> 0)), (Math.fround(( + 0.000000000000001)) >>> y)), ( + Math.log10((x | 0)))) === ( + ((Math.fround(( + Math.fround(y))) >>> 0) - (y >>> 0)))), (( ! ( ! (Math.atan2(Math.expm1(Math.clz32(( + Number.MIN_VALUE))), x) >>> 0))) | 0)); }); testMathyFunction(mathy4, [2**53, -1/0, -(2**53), 0x080000001, -0, -0x080000000, 1, 0x100000001, 0x0ffffffff, -Number.MIN_VALUE, 0x080000000, 1/0, -0x0ffffffff, -(2**53+2), 0x07fffffff, Number.MIN_SAFE_INTEGER, 0, 0/0, 2**53-2, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 2**53+2, Math.PI, -Number.MAX_VALUE, -0x080000001, 42, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 0x100000000]); ");
/*fuzzSeed-244067732*/count=960; tryItOut("o1.s0 += 'x';");
/*fuzzSeed-244067732*/count=961; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-244067732*/count=962; tryItOut("\"use strict\"; var r0 = x + x; r0 = r0 | x; var r1 = r0 * x; r1 = 2 & x; var r2 = 0 % r1; var r3 = r2 & r1; x = x * r2; var r4 = x + r2; var r5 = r0 % r0; r3 = r2 | 0; r1 = r3 ^ r2; r5 = r2 - r4; print(r2); var r6 = r5 ^ r5; ");
/*fuzzSeed-244067732*/count=963; tryItOut("mathy0 = (function(x, y) { return Math.min((Math.tan((-Number.MIN_SAFE_INTEGER >>> (Math.min((( - Math.tan(( - (y >>> 0)))) | 0), (Math.fround((2**53-2 ? ( + (( + 0x080000000) ** ( + x))) : y)) | 0)) | 0))) | 0), Math.atan2(Math.min(Math.fround((Math.fround(Math.tan((y >>> 0))) ? Math.fround(y) : ( + y))), ( + ( ~ ( + ( - Math.pow(-Number.MIN_VALUE, y)))))), (Math.acos(( + (( + (Math.log2(((( + Math.fround(42)) | 0) >>> 0)) >>> 0)) <= ( + Math.fround(( + Math.fround(-0x080000001))))))) >>> 0))); }); testMathyFunction(mathy0, [Math.PI, 0x0ffffffff, 0x07fffffff, 1, -(2**53+2), -0x080000001, -1/0, 0x080000000, 2**53+2, 1/0, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, -0x100000001, 0.000000000000001, 0, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 0/0, 0x080000001, -0, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, Number.MAX_VALUE, -0x07fffffff, 42]); ");
/*fuzzSeed-244067732*/count=964; tryItOut("mathy0 = (function(x, y) { return Math.asinh(Math.fround(Math.tanh(( ! (( + (y >>> 0)) | 0))))); }); testMathyFunction(mathy0, [-0x080000000, -(2**53+2), -Number.MIN_VALUE, 0, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), Number.MAX_VALUE, 0x100000000, 0/0, 2**53-2, -Number.MAX_VALUE, 0x080000000, -0x100000000, 0.000000000000001, Number.MIN_VALUE, 42, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, 1, -0x07fffffff, -0x0ffffffff, 0x080000001, 2**53+2, 0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, -(2**53-2), 1.7976931348623157e308, 1/0, -1/0]); ");
/*fuzzSeed-244067732*/count=965; tryItOut("var xywozj = new ArrayBuffer(16); var xywozj_0 = new Uint16Array(xywozj); xywozj_0[0] = -23; /*RXUB*/var r = new RegExp(\"\\\\b\", \"\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=966; tryItOut("mathy3 = (function(x, y) { return ((( ~ (( + ((Math.imul((y | 0), ((x < Math.fround(Math.round(2**53))) >>> 0)) | 0) ? Math.pow(setHours, x) : 0x07fffffff)) ? Math.fround((1.7976931348623157e308 < Math.fround(x))) : Math.pow((x | 0), x))) | 0) ? (Math.sinh(Math.asinh(mathy0(( + (Math.atan(y) >= Number.MIN_VALUE)), (Math.abs(( + x)) | 0)))) | 0) : (( + (Math.acos(((y >>> Math.atan2(((Math.min(y, x) , x) >>> 0), (( + ( + (y | 0))) ? 1 : ( + x)))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy3, [2**53-2, Number.MIN_SAFE_INTEGER, -0x080000000, 0, 42, -0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, 0/0, 1, -(2**53), 2**53+2, 0x080000000, 1/0, 1.7976931348623157e308, 0x100000001, Number.MAX_VALUE, -0x100000000, -0x080000001, -(2**53-2), -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 0x07fffffff, -0x07fffffff, -1/0, -0x100000001]); ");
/*fuzzSeed-244067732*/count=967; tryItOut("v2 + '';");
/*fuzzSeed-244067732*/count=968; tryItOut("/*RXUB*/var r = /(?!(?![^\\v\\0-\\cZ\\cG]|\\B[^\\u6017\\t-\\0\\s\\t-\\u26fe]))+|(?=(?:\\d){3}\\w{2})[^]{0,}?/gym; var s = x ** \u3056 === (4277); print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=969; tryItOut("g2.m2.set(a2, a2);/*RXUB*/var r = /(?!((?=\\b|[])+)((\\b)?)*|.){3,}/i; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=970; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.min(mathy1(mathy2(y, Math.sqrt(x)), ((x ? ( + ( + ( ! y))) : ( + (y | 0))) | 0)), ( ~ ( + (Math.fround(( + Math.clz32(( + mathy2(( + x), ( + x)))))) >>> ( ~ (( ! 2**53) | 0)))))); }); testMathyFunction(mathy3, ['\\0', [0], (function(){return 0;}), '/0/', null, ({valueOf:function(){return '0';}}), (new Number(0)), 1, true, -0, (new Number(-0)), false, ({toString:function(){return '0';}}), (new Boolean(true)), undefined, ({valueOf:function(){return 0;}}), NaN, '0', [], (new Boolean(false)), objectEmulatingUndefined(), '', /0/, (new String('')), 0, 0.1]); ");
/*fuzzSeed-244067732*/count=971; tryItOut("mathy3 = (function(x, y) { return ( ! (Math.imul(((x <= ( + ( ! ( + y)))) | 0), ((((( + (x << ( + (Math.fround(Math.hypot(y, x)) % Math.log1p(( ~ y)))))) >>> 0) <= (Math.atan2(((y >>> y) >>> 0), (-3.eval(\"for (var v of t2) { try { (-8); } catch(e0) { } try { print(uneval(o1.g2)); } catch(e1) { } try { Object.prototype.unwatch.call(this.a1, \\\"__proto__\\\"); } catch(e2) { } t2[17]; }\"))) >>> 0)) >>> 0) | 0)) | 0)); }); ");
/*fuzzSeed-244067732*/count=972; tryItOut("f0 + g2;");
/*fuzzSeed-244067732*/count=973; tryItOut("\"use strict\"; const {d, \u3056} = intern(/(?=\\u05eE)/gm), x, icbomk, x = Math.acos(11), c = z = false, NaN = (Math.cos(20)), let = Object(), rkwmuo, a = yield /*RXUE*/new RegExp(\"(\\\\2){2,}(?!(..+?))|(?=[^])*|\\\\1*?{4,8}\", \"\").exec(\"\\ud6ce\\n\\n\\n\\n\\n\\n\\ud6ce\\n\\n\\n\\n\\ud6ce\\n\\n\\n\\n\\n\\n\\ud6ce\\ud6ce\\n\\n\\n\\n\\n\\n\\ud6ce\\ud6ce\\n\\n\\n\\n\\n\\n\\ud6ce\\ud6ce\\n\\n\\n\\n\\n\\n\\ud6ce\");a1.pop(p1);");
/*fuzzSeed-244067732*/count=974; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!\\\\s)*?([^\\\\x8C-\\\\xB5\\\\d]{4,}\\\\D{0})($+)(?!\\\\3)|^(?=(?=(\\\\d))|\\\\b{0})*?\", \"gy\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=975; tryItOut("v1 = (p2 instanceof g1.v2);");
/*fuzzSeed-244067732*/count=976; tryItOut("\"use strict\"; Array.prototype.unshift.call(o2.a0, f1, t0);");
/*fuzzSeed-244067732*/count=977; tryItOut("testMathyFunction(mathy2, [-0x080000001, 2**53-2, 0x0ffffffff, 1, -(2**53), -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, 2**53+2, -(2**53+2), Math.PI, Number.MIN_VALUE, -0x100000000, 0x080000000, 42, 1/0, 0x07fffffff, -0, -0x0ffffffff, -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, 0x100000001, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 2**53, -1/0]); ");
/*fuzzSeed-244067732*/count=978; tryItOut("Math.max(17, (-1262904962.5\u0009.x = z **= \u3056));");
/*fuzzSeed-244067732*/count=979; tryItOut("mathy0 = (function(x, y) { return (( + Math.tanh(Math.fround(Math.pow(0, x)))) | 0); }); ");
/*fuzzSeed-244067732*/count=980; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sin(( ! (Math.imul((Math.tanh(x) | 0), (x !== (Math.pow(((x ? x : x) | 0), (y | 0)) | 0))) >> ((x ? (( + (Math.atan((y >>> 0)) >>> 0)) << ( + Math.min((x >>> 0), Math.atan2(x, x)))) : ((((x | 0) < (Math.tanh(y) | 0)) | 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 42, -(2**53), Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, -0x07fffffff, -0, -Number.MAX_VALUE, 1, -(2**53+2), -(2**53-2), -1/0, 2**53+2, Number.MIN_VALUE, 0x0ffffffff, 0, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, 2**53-2, 0x080000001, 0x100000000, -0x100000001, 0.000000000000001, 0/0, 1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=981; tryItOut("mathy0 = (function(x, y) { return x; }); testMathyFunction(mathy0, [-0x080000000, 1, 0/0, 0x07fffffff, -0, 0x100000000, -(2**53-2), Number.MAX_VALUE, -(2**53+2), -Number.MAX_VALUE, -(2**53), -0x100000000, 0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, 1.7976931348623157e308, Math.PI, 0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, 2**53+2, -0x080000001, -0x0ffffffff, 42, -0x07fffffff, 2**53-2, -1/0]); ");
/*fuzzSeed-244067732*/count=982; tryItOut("\"use strict\"; v1 = evalcx(\"function g2.f1(v1)  { yield /*UUV2*/(e.delete = e.setPrototypeOf) } \", g1.g1);");
/*fuzzSeed-244067732*/count=983; tryItOut("\"use strict\"; /*infloop*/for(var z = yield; (4277); window) {/*ODP-1*/Object.defineProperty(o0.g1.a1, \"toString\", ({configurable: true, enumerable: false}));/*MXX1*/o2 = g1.Int8Array.prototype.BYTES_PER_ELEMENT; }");
/*fuzzSeed-244067732*/count=984; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((i0)-((((0xffffffff)+(i2)) << (((+exp(((+(0.0/0.0))))) <= (+(1.0/0.0)))+((~((0x435cff19)-(0xa3a8b9fc)+(0xfeaea8fd))) == (((0xffffffff)) << ((0xfa76d9b8))))-((((-9223372036854776000.0)) / ((-2049.0))) < (+(0.0/0.0))))))))|0;\n    i2 = (i0);\n    i2 = ((imul((((/*FFI*/ff()|0)-(((-68719476737.0))))), ((0x4d11d121)))|0) >= (imul((i1), (i0))|0));\n    i2 = (i1);\n    i0 = (i2);\n    switch ((-0x20b8fc4)) {\n      case 0:\n        i0 = ((((i2)-(i2))>>>((i2)+(((1/0))))) > ((-(i0))>>>((i0)+(i1)-(((-0x8000000) ? (0xd1f60b94) : (0x3819dffe)) ? ((-8191.0) <= (2.0)) : ((0x95ee3b7))))));\n    }\n    return ((((((i0)+(0x4102399a))>>>((i2))))-((((i2))>>>((i1)+(i0))) >= (0x0))))|0;\n  }\n  return f; })(this, {ff: Number.prototype.toLocaleString}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MAX_VALUE, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 42, 1, 0x07fffffff, 2**53-2, 0x080000000, -0x0ffffffff, 0.000000000000001, -(2**53+2), -0, -0x080000000, -(2**53-2), -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, Math.PI, Number.MIN_VALUE, 0x0ffffffff, -(2**53), 0]); ");
/*fuzzSeed-244067732*/count=985; tryItOut("{ void 0; validategc(false); } /*RXUB*/var r = new RegExp(\"\\\\1\", \"ym\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-244067732*/count=986; tryItOut("\"use strict\"; for (var v of f0) { try { ; } catch(e0) { } /*MXX3*/g1.Date.prototype.toString = g0.Date.prototype.toString; }");
/*fuzzSeed-244067732*/count=987; tryItOut("o2.g2.v0 = (g2.a1 instanceof o2.f0);function {a, e, x: String.prototype.toLocaleLowerCase, x, eval: [], x: [[, [{}, ]], c, [{}, , {x: []}], x, b]}(x, eval = ((function factorial(vcnkbu) { g0.v1 = Object.prototype.isPrototypeOf.call(o1.i0, e1);; if (vcnkbu == 0) { ; return 1; } ; return vcnkbu * factorial(vcnkbu - 1);  })(0)).watch(2, (-29).call) === intern((p={}, (p.z = 11)())), c, w, e, z, d = Math.min(0, x)\n, y, z, e, window, x, setter =  '' , e, NaN, w = length, a, x, x = window, d, x) { yield [c = Proxy.createFunction(({/*TOODEEP*/})( '' ), Map.prototype.has)] } const a1 = (function() { \"use asm\"; yield  /x/  >>=  '' ; } })();");
/*fuzzSeed-244067732*/count=988; tryItOut("switch(((eval) = 4)) { case 4: return;break; s2 = '';break; default: break;  }");
/*fuzzSeed-244067732*/count=989; tryItOut("const x = this.__defineSetter__(\"a\", TypeError), e = eval(\"t0[5];\", -2), [e, , ] = (e = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function() { throw 3; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: undefined, keys: function() { throw 3; }, }; })( /x/g ), y < {})), \u3056 = (let (e=eval) e)((Math.abs(-1)));var dkvhji = new SharedArrayBuffer(24); var dkvhji_0 = new Int8Array(dkvhji); print(dkvhji_0[0]); var dkvhji_1 = new Uint8Array(dkvhji); var dkvhji_2 = new Float64Array(dkvhji); print(dkvhji_2[0]); var dkvhji_3 = new Int32Array(dkvhji); dkvhji_3[0] = 27; /*hhh*/function rnwbap([] = eval(\"mathy3 = (function(x, y) { \\\"use strict\\\"; return (Math.tanh((Math.fround((Math.max((Math.atan2(((((x >>> 0) , -0x080000000) >>> 0) >>> 0), y) >>> 0), (((y >>> 0) != (x >>> 0)) >>> 0)) ? (Math.fround(mathy0(( + Math.imul(x, 0x100000001)), y)) | Math.fround(mathy2(Math.fround(x), Math.fround((((x ^ (y >>> 0)) >>> 0) ? x : y))))) : Math.min(-(2**53), Math.fround(Math.imul(( + (( - (x | 0)) | 0)), x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -0x100000000, -0, 0/0, -1/0, 1, -Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, -(2**53), 2**53+2, 1/0, -0x0ffffffff, 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, -0x100000001, 1.7976931348623157e308, 0x100000001, -Number.MAX_VALUE, Math.PI, -(2**53-2), -0x080000001, Number.MIN_VALUE, 0, -0x080000000, 42]); \")){e0 + m2;}/*iii*/lvscyg();/*hhh*/function lvscyg(19){v0 + '';}s0 += s2;");
/*fuzzSeed-244067732*/count=990; tryItOut("\"use strict\"; return;yield (Int16Array).call( /x/g  *= -3, \u0009(4277), d);");
/*fuzzSeed-244067732*/count=991; tryItOut("mathy2 = (function(x, y) { return ( - Math.imul(mathy1((Math.imul(y, (mathy1(x, x) >>> 0)) >>> 0), Math.atanh(0x100000000)), ( + Math.min(((x && (x << x)) > ( + ((((x >>> 0) ? (y >>> 0) : (-Number.MIN_VALUE >>> 0)) >>> 0) ? (Math.min(-Number.MIN_SAFE_INTEGER, x) | 0) : ( + Math.log1p(-Number.MAX_SAFE_INTEGER))))), -0x07fffffff)))); }); testMathyFunction(mathy2, [/0/, [0], (new Boolean(false)), false, 0.1, 0, objectEmulatingUndefined(), -0, '/0/', (new String('')), ({toString:function(){return '0';}}), undefined, '0', ({valueOf:function(){return 0;}}), (new Number(-0)), NaN, (new Number(0)), (function(){return 0;}), ({valueOf:function(){return '0';}}), 1, null, [], (new Boolean(true)), true, '\\0', '']); ");
/*fuzzSeed-244067732*/count=992; tryItOut("g0.v0 = new Number(-0);");
/*fuzzSeed-244067732*/count=993; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\1)+/gy; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=994; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.log2(Math.fround(( ~ y)))); }); testMathyFunction(mathy5, [-0x100000000, 0/0, 0x07fffffff, Number.MAX_VALUE, -(2**53-2), -0x080000001, -Number.MIN_SAFE_INTEGER, 0, Math.PI, 0x100000001, 1, 0x0ffffffff, Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, -(2**53+2), -(2**53), Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, -1/0, 42, -0, 1/0, 0x080000001, -0x080000000, 2**53+2, -0x07fffffff, 1.7976931348623157e308, -0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=995; tryItOut("let(NaN, x = ({setFloat64: x }), x, vaoalp, x) { let(zcpqfd, d = timeout(1800), ejfzvk, skrnei, x = window) ((function(){x.stack;})());}");
/*fuzzSeed-244067732*/count=996; tryItOut("b1 = t1.buffer;");
/*fuzzSeed-244067732*/count=997; tryItOut("\"use asm\"; Object.defineProperty(this, \"s0\", { configurable:  \"\" , enumerable: (x % 5 == 4),  get: function() {  return new String(o2.p0); } });");
/*fuzzSeed-244067732*/count=998; tryItOut("x;");
/*fuzzSeed-244067732*/count=999; tryItOut("for (var p in s0) { try { m0.has(o1); } catch(e0) { } try { this.a0[({valueOf: function() { o2 + '';return 15; }})] = x; } catch(e1) { } try { a2 = new Array; } catch(e2) { } p1.toString = (function(j) { if (j) { try { v1 = g2.runOffThreadScript(); } catch(e0) { } t1 = new Int16Array(t1); } else { try { v0 = t2.length; } catch(e0) { } m0.has(o0.h1); } }); }");
/*fuzzSeed-244067732*/count=1000; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.tanh(( + Math.min(( + Math.pow(Math.pow(0.000000000000001, (x | 0)), (((y >>> 0) * Math.fround(Math.round(0.000000000000001))) | 0))), ( + (( + ( + Math.atan2(y, x))) || (Math.atan2((Math.fround(y) >>> 0), (-0x07fffffff >>> 0)) >>> 0)))))); }); testMathyFunction(mathy4, ['/0/', /0/, ({toString:function(){return '0';}}), (new Boolean(true)), undefined, objectEmulatingUndefined(), -0, (new String('')), (function(){return 0;}), NaN, null, false, (new Boolean(false)), 0.1, true, 1, ({valueOf:function(){return 0;}}), [0], (new Number(0)), (new Number(-0)), '\\0', ({valueOf:function(){return '0';}}), '', 0, [], '0']); ");
/*fuzzSeed-244067732*/count=1001; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( ~ (( ~ (Math.sin((mathy0((-(2**53+2) >>> 0), Number.MAX_VALUE) | 0)) | 0)) >>> 0)) | 0); }); ");
/*fuzzSeed-244067732*/count=1002; tryItOut("mathy3 = (function(x, y) { return Math.abs(( - (Math.atan2((Math.cos(Math.fround(x)) | 0), ((x == (mathy1((( ! x) >>> 0), y) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[arguments.caller, arguments.caller, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), arguments.caller, arguments.caller, arguments.caller, arguments.caller, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-244067732*/count=1003; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.atan2(( + ( ~ (Math.sign((( ! Math.fround(-(2**53-2))) | 0)) | 0))), Math.fround(((Math.fround(( ! Math.fround(Math.cbrt((y == ( + Math.max(( + x), ( + 42)))))))) , ( + x)) | 0))); }); testMathyFunction(mathy3, [1, '0', '\\0', ({valueOf:function(){return 0;}}), false, undefined, true, null, (new Boolean(false)), ({valueOf:function(){return '0';}}), -0, objectEmulatingUndefined(), (function(){return 0;}), NaN, '', 0, '/0/', 0.1, [], /0/, (new Number(0)), (new Number(-0)), ({toString:function(){return '0';}}), [0], (new String('')), (new Boolean(true))]); ");
/*fuzzSeed-244067732*/count=1004; tryItOut("let x = \"\\u3803\", dluuyg, x = (4277), x, e = intern(-29), eval = x, tnulxu;L:for(var c in ((23)(\"\\u5A1A\"))){h2.toString = (function() { try { g2.v1 = a1.length; } catch(e0) { } try { m0.delete(m0); } catch(e1) { } a1.sort(f2); return v0; }); }");
/*fuzzSeed-244067732*/count=1005; tryItOut("var nigahc = new ArrayBuffer(6); var nigahc_0 = new Int32Array(nigahc); /*vLoop*/for (let utlhjx = 0; utlhjx < 4; ++utlhjx) { w = utlhjx; Array.prototype.shift.apply(a0, [e1, s2]); } function eval(y, ...e) { \"use strict\"; yield (4277) } Array.prototype.shift.call(a0, b1, i0);");
/*fuzzSeed-244067732*/count=1006; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\".{2,2}\", \"m\"); var s = \":\"; print(uneval(s.match(r))); ");
/*fuzzSeed-244067732*/count=1007; tryItOut("Array.prototype.unshift.apply(a2, [a2, b2, o2.s2]);");
/*fuzzSeed-244067732*/count=1008; tryItOut("\"use strict\"; let (x = x, lgcipk, x = (Symbol()), y = Math.min(3, 9), dlvdtr, a = -1, e = (! /x/g ).watch(\"e\", neuter), z = String.prototype.startsWith(new RegExp(\"\\\\w*(?!(?:\\\\1){4,5})+\", \"gyim\")), get = this) { Array.prototype.splice.call(a0, -7, 9); }");
/*fuzzSeed-244067732*/count=1009; tryItOut("/*infloop*/do o1 + v1; while([1]);");
/*fuzzSeed-244067732*/count=1010; tryItOut("/*bLoop*/for (nwrkvx = 0; nwrkvx < 72; ++nwrkvx) { if (nwrkvx % 3 == 0) { print(false); } else { v0 = Object.prototype.isPrototypeOf.call(p1, g0); }  } ");
/*fuzzSeed-244067732*/count=1011; tryItOut("with({}) { let(x) ((function(){for(let z of ReferenceError) this.zzz.zzz;})()); } ");
/*fuzzSeed-244067732*/count=1012; tryItOut("/*iii*/print(kobjst);/*hhh*/function kobjst(){print(x);}");
/*fuzzSeed-244067732*/count=1013; tryItOut("o0.__proto__ = o2;let b = ((void options('strict_mode')));");
/*fuzzSeed-244067732*/count=1014; tryItOut("mathy3 = (function(x, y) { return (Math.pow(( + Math.max((Math.fround(Math.pow((Math.max(y, Math.max((Math.fround(Math.sinh(Math.fround(y))) >>> 0), (x !== y))) | 0), ((y <= Math.atan2(y, ( + ( + x)))) >>> 0))) ** -0x080000001), ( ~ ( + (((mathy0((-1/0 | 0), (y | 0)) | 0) | 0) >>> (y === (( + y) % x))))))), ( + (((mathy0(( + (( + ((Math.cosh(0) * x) | 0)) ? ( + 0x100000000) : y)), (( + ( ~ Number.MIN_VALUE)) >>> 0)) | 0) , (Math.min(( + ( + (( ~ (y | 0)) | 0))), ( + (( ~ x) >>> 0))) | 0)) | 0))) | 0); }); testMathyFunction(mathy3, [-0x080000000, -Number.MIN_VALUE, 42, 1.7976931348623157e308, 0.000000000000001, 2**53+2, Number.MAX_VALUE, 1, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53+2), 2**53, -1/0, -0, -0x100000000, -0x100000001, 0x100000000, -Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -0x07fffffff, 0x07fffffff, 0, -(2**53-2), 0x080000001, Math.PI, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -0x080000001]); ");
/*fuzzSeed-244067732*/count=1015; tryItOut("i1.send(o0.g0.s1);");
/*fuzzSeed-244067732*/count=1016; tryItOut("/*RXUB*/var r = /(?!\\B)|(?:(?:(\\s))(\\w)|\\S*?(^){1,3}(?!.)\u00f5\\B|\u009d|[^]|.+?)*/; var s = \"\"; print(s.replace(r, Map.prototype.values)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1017; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-244067732*/count=1018; tryItOut("\"use strict\"; o2.e0.add(f1);");
/*fuzzSeed-244067732*/count=1019; tryItOut("mathy3 = (function(x, y) { return ( + Math.imul(( + ( + Math.pow((Math.fround(Math.asin(Math.fround((mathy0((x | 0), ( + Math.round(( + Math.fround((x >>> 0)))))) | 0)))) >>> 0), (( - ( + ( + Math.max(( + Math.log1p(( + x))), x)))) >>> 0)))), Math.min(( + (( + Math.asin(((mathy1((x | 0), (0x100000000 | 0)) | 0) | 0))) || ( + Math.imul(Math.fround(( + ( - ( + -0x100000000)))), (y >> (x , ( + y))))))), (( + (( + ( ~ Math.hypot((-0x100000000 >>> 0), (y >>> 0)))) << ( + Math.fround((Math.pow(y, Math.pow((y & 0x0ffffffff), ( + x))) ? ((Math.pow(y, y) != y) | 0) : y))))) >>> 0)))); }); testMathyFunction(mathy3, [2**53+2, -0x0ffffffff, 1/0, -0x07fffffff, Math.PI, -0, 0x100000001, -(2**53-2), 2**53, 0x080000000, 0x0ffffffff, -Number.MAX_VALUE, 42, 0x100000000, Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, -(2**53), 1.7976931348623157e308, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, 1, 0.000000000000001, -(2**53+2), 0, -0x100000000, 0/0, Number.MIN_VALUE, -0x100000001, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1020; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.imul((Math.fround(Math.fround(((x <= x) >>> 0))) | 0), Math.log10(Math.fround((Math.fround(mathy1(( - x), (Math.pow((0x0ffffffff | 0), (-(2**53-2) | 0)) | 0))) ? Math.fround(x) : Math.fround(( + ( + ( + 42)))))))); }); testMathyFunction(mathy3, [0x07fffffff, -0x100000001, -0x080000001, 42, 0x100000000, 2**53+2, -0x07fffffff, 0x080000001, -Number.MIN_VALUE, -(2**53), 0x0ffffffff, -1/0, Number.MIN_VALUE, 0, -Number.MAX_VALUE, 1/0, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -0x080000000, -0x100000000, 0/0, -0, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1021; tryItOut("testMathyFunction(mathy2, [0x0ffffffff, Math.PI, 1, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0, 0x100000000, 0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, 2**53+2, 0/0, Number.MIN_VALUE, 0x100000001, -0x080000000, -(2**53), -1/0, 1/0, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, 0x080000001, -0x100000000]); ");
/*fuzzSeed-244067732*/count=1022; tryItOut("t1[0] = v1;");
/*fuzzSeed-244067732*/count=1023; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.asin(((Math.fround(((Math.atanh((Math.tan(Math.fround(x)) | 0)) | 0) === ((mathy0(x, mathy0(Math.fround(0x07fffffff), x)) ^ (x >>> 0)) | 0))) % Math.fround(Math.log(Math.expm1(Math.imul(0x080000001, y))))) | 0)) ** Math.fround((Math.fround(\"setUTCHours\") || Math.fround(( + ( ~ (( ~ (( - ( - y)) | 0)) | 0))))))); }); testMathyFunction(mathy1, [42, Math.PI, -(2**53-2), 0x100000000, 0x100000001, -0x0ffffffff, 1.7976931348623157e308, -0x080000001, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, 1, -(2**53+2), 0x080000000, -1/0, -0x100000001, 0x0ffffffff, -(2**53), 0x080000001, -0x080000000, -Number.MAX_VALUE, 0x07fffffff, 2**53+2, 0, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53]); ");
/*fuzzSeed-244067732*/count=1024; tryItOut("\"use strict\"; try { return x << Math.hypot(-14, ({a1:1})); } catch(w) { x = w; } finally { print( '' .unwatch(\"18\")); } ");
/*fuzzSeed-244067732*/count=1025; tryItOut("a2.shift(runOffThreadScript, this.e1);");
/*fuzzSeed-244067732*/count=1026; tryItOut("v0 = (g0.o0 instanceof v1);");
/*fuzzSeed-244067732*/count=1027; tryItOut("if(true) {new RegExp(\"\\\\1\", \"gyim\");objectEmulatingUndefined } else print(26);");
/*fuzzSeed-244067732*/count=1028; tryItOut("mathy2 = (function(x, y) { return ((((Math.pow((( + ( + ( + y))) >>> 0), (Number.MIN_SAFE_INTEGER >>> 0)) << (( + (( + Math.abs(((mathy0((y >>> 0), (y >>> 0)) >>> 0) | 0))) | ( + Math.imul((Math.cosh(((( - y) | 0) >>> 0)) >>> 0), Math.round((x | 0)))))) | 0)) >>> 0) & (mathy0(((0x080000001 >>> 0) / (Math.round(y) | 0)), (mathy0(((x || x) | 0), (x | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [[0], '\\0', true, '', [], '/0/', 0, (new String('')), (function(){return 0;}), null, ({toString:function(){return '0';}}), 1, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), false, ({valueOf:function(){return '0';}}), '0', -0, NaN, undefined, (new Number(-0)), (new Boolean(false)), (new Boolean(true)), /0/, 0.1, (new Number(0))]); ");
/*fuzzSeed-244067732*/count=1029; tryItOut("unntfi, y, wopdqw, x, x, mmuqba, tahrnk, dgwgtk, x, kxksed;(-0);");
/*fuzzSeed-244067732*/count=1030; tryItOut("\"use strict\"; let(e) { ((NaN = e));}throw window;");
/*fuzzSeed-244067732*/count=1031; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1032; tryItOut("M:for(let b in (((void options('strict')))('fafafa'.replace(/a/g, offThreadCompileScript)))){s2 = '';print(x); }");
/*fuzzSeed-244067732*/count=1033; tryItOut("\"use strict\"; x = linkedList(x, 572);");
/*fuzzSeed-244067732*/count=1034; tryItOut("/*hhh*/function sujmah(){f2 = Proxy.createFunction(h2, f2, f0);}/*iii*//*infloop*/for(let b; this; NaN = new String()) (\"\\u83EA\");continue L;");
/*fuzzSeed-244067732*/count=1035; tryItOut("mathy1 = (function(x, y) { return ( + mathy0(( + (((( ! (Math.hypot((y >>> 0), ((Math.hypot((Math.PI | 0), Number.MIN_VALUE) | 0) | 0)) | 0)) >>> 0) / (Math.hypot((y | 0), y) >>> 0)) ^ ( ! ( + Number.MIN_SAFE_INTEGER)))), ( + mathy0(Math.fround((Math.tan((Math.pow((x | 0), Math.fround(( ! Math.fround(Math.exp(0x080000000))))) | 0)) >>> 0)), Math.fround(( - ( + Math.expm1(x)))))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, Math.PI, 0x080000000, 0x0ffffffff, 0/0, -Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, -(2**53+2), -Number.MAX_VALUE, -(2**53-2), 0, -0x100000001, 2**53+2, -0x07fffffff, 2**53, 1/0, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000001, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1036; tryItOut("let (y) { /*MXX3*/this.g0.String.prototype.strike = g2.String.prototype.strike; }");
/*fuzzSeed-244067732*/count=1037; tryItOut("b2 = new SharedArrayBuffer(72);");
/*fuzzSeed-244067732*/count=1038; tryItOut("/*RXUB*/var r = r0; var s = \"\\u3c59>a1\\u46b9\\n\\n\\n\\n\\n\\n\\n\\n\\u3c59>a1\\u46b9\\u3c59>a1\\u46b9\\n\\n\\n\\n\\n\\n\\n\\n\\u3c59>a1\\u46b9\"; print(uneval(s.match(r))); ");
/*fuzzSeed-244067732*/count=1039; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-244067732*/count=1040; tryItOut("\"use strict\"; h1.defineProperty = f2;");
/*fuzzSeed-244067732*/count=1041; tryItOut("testMathyFunction(mathy4, [-Number.MAX_VALUE, -0x07fffffff, 1/0, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -(2**53-2), -0, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, -0x100000001, 1.7976931348623157e308, -1/0, 2**53+2, 42, Number.MIN_SAFE_INTEGER, 1, 0, 2**53, 0x080000000, 0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000001, -(2**53), 0x080000001, -(2**53+2), -0x100000000, Number.MIN_VALUE, Math.PI, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1042; tryItOut("\"use strict\"; \"use asm\"; s2 = new String(g1);");
/*fuzzSeed-244067732*/count=1043; tryItOut("mathy5 = (function(x, y) { return (((Math.cosh(((y >>> 0) >>> 2**53+2)) >>> 0) % (Math.tanh(( + (Math.pow(((( ! (((mathy2(( + (( + x) - ( + x))), y) << (Math.asin(( + y)) | 0)) | 0) | 0)) | 0) >>> 0), x) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, -0x0ffffffff, Math.PI, -Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, 0, -0x080000000, -0x100000000, 1/0, 0x080000000, Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0/0, 0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, 1, 2**53+2, 0x07fffffff, -(2**53-2), -0x100000001, -1/0]); ");
/*fuzzSeed-244067732*/count=1044; tryItOut("g1.__proto__ = this.i2;");
/*fuzzSeed-244067732*/count=1045; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround((( + ((Math.fround(((((Math.atan2(y, Number.MAX_VALUE) >>> 0) ? y : x) >= ( + (( ! (mathy0((Math.atanh((y >>> 0)) >>> 0), x) >>> 0)) >>> 0))) >>> 0)) ? ((((((x | 0) == y) << ((Math.max((-Number.MAX_SAFE_INTEGER | 0), (x | 0)) | 0) >>> 0)) >>> 0) | (( + (( + mathy0(( ~ Math.cosh(x)), Math.hypot(x, y))) * ( + Math.log(y)))) >>> 0)) >>> 0) : ( + Math.abs(( + ( + (( + ((Math.fround(y) / (mathy3(x, y) >>> 0)) >>> 0)) & (x >>> 0))))))) | 0)) !== ( + Math.expm1(Math.ceil(((y ? ( + Math.min(( + (-0x080000000 | (Math.expm1(y) | 0))), ((x - x) | 0))) : (Math.hypot((Math.max((y | 0), ( + x)) | 0), 1) | 0)) | 0)))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 2**53+2, 2**53-2, 1, 0/0, Math.PI, 2**53, 0x100000000, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -1/0, -0x100000001, -Number.MIN_VALUE, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -(2**53), 1/0, Number.MIN_SAFE_INTEGER, -0, -(2**53+2), 0x07fffffff, 0, -0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 0x080000001, 0x080000000, -0x100000000]); ");
/*fuzzSeed-244067732*/count=1046; tryItOut("testMathyFunction(mathy2, [1/0, 0, -0, -0x080000001, 0/0, -1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, -0x0ffffffff, 2**53, 1, -(2**53+2), 0x080000001, -0x080000000, -(2**53), -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -0x100000001, Math.PI, 0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, -0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1047; tryItOut("\"use strict\"; ");
/*fuzzSeed-244067732*/count=1048; tryItOut("\"use strict\"; /*bLoop*/for (eiinjh = 0; eiinjh < 4; ++eiinjh) { if (eiinjh % 2 == 1) { var a2 = Array.prototype.concat.call(a0, a1, ([]) ?  /x/ .getFloat32(window) : x, a2, g1.h2, h1,  /* Comment */function(y) { yield y; print(/((\\d$|(?=[^]*)(?!(?:.)))?)/yi);; yield y; }()); } else { ; }  } ");
/*fuzzSeed-244067732*/count=1049; tryItOut("\"use asm\"; ");
/*fuzzSeed-244067732*/count=1050; tryItOut("testMathyFunction(mathy5, [1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), NaN, [0], null, objectEmulatingUndefined(), (function(){return 0;}), '0', -0, (new Boolean(true)), 0.1, '', (new String('')), false, '/0/', (new Number(-0)), '\\0', (new Number(0)), 0, (new Boolean(false)), undefined, true, ({valueOf:function(){return 0;}}), /0/, []]); ");
/*fuzzSeed-244067732*/count=1051; tryItOut("o0.a0.shift();");
/*fuzzSeed-244067732*/count=1052; tryItOut("a0.shift(g2, g2.m2);");
/*fuzzSeed-244067732*/count=1053; tryItOut("L:switch(x = (( \"\"  ? new RegExp(\"\\\\b|$*?\\\\3|(?:[^]){0,}\", \"yi\") : this()).__defineSetter__(\"d\", Function))) { case 7: /*bLoop*/for (var towmlq = 0; towmlq < 7 && (window ^ true != ({arguments: \"\\uEB9B\" })\u000c); ++towmlq) { if (towmlq % 50 == 44) { this.t1[17];\n(new ((function(x, y) { return y; })).apply(-13));\n } else { L:if((x % 47 != 7)) {print(x instanceof c >>= b = (x)(x, function(id) { return id })); } else Array.prototype.pop.call(a2); }  } break; default: break; h1.delete = f0;break; o1.g1.a2 = Array.prototype.slice.call(a1, NaN, NaN);break; t0[8] = v0;break; case 3: v0 = new Number(o2);case 7: for (var v of e0) { try { e1.delete(i0); } catch(e0) { } try { Array.prototype.sort.apply(this.a1, [(function() { for (var j=0;j<8;++j) { f1(j%5==0); } }), f1]); } catch(e1) { } try { a1.reverse(a0, o0); } catch(e2) { } Array.prototype.reverse.call(this.a1); }break; /*infloop*/L:for(w; 1; new RegExp(\"(?!(?!(?!\\\\b)))|(?=\\\\u00A5){4}|(?!\\\\d)\", \"m\")) /*infloop*/for(new RegExp(\"(\\\\B|\\\\2*?)\", \"yi\"); new RegExp(\"\\\\D\", \"yim\");  \"\" ) {g2.f0 + s1; }break; case ({\u3056: (window.toLocaleUpperCase(eval))}):  }");
/*fuzzSeed-244067732*/count=1054; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1/im; var s = \"\\u8d06\"; print(uneval(r.exec(s))); print(r.lastIndex); var d = null || /\\2\\u007C{2,}/gi;");
/*fuzzSeed-244067732*/count=1055; tryItOut("mathy0 = (function(x, y) { return (Math.exp(( + Math.fround(Math.tan(( + Math.imul((x ^ -(2**53)), -(2**53+2))))))) !== ( + (Math.hypot(Math.max(Math.clz32((x | 0)), (Math.atan2(( + ((0x07fffffff | 0) != (x >>> 0))), x) | 0)), ((( ~ (( ~ (-0x080000001 >>> 0)) >>> 0)) >>> 0) | 0)) | 0))); }); ");
/*fuzzSeed-244067732*/count=1056; tryItOut("\"use strict\"; const [] = (4277), crcfjr, x = ((-10)( \"\" )++), azyplk, w = [[]];Array.prototype.forEach.apply(a1, [(function() { v1 = new Number(-0); return g2; })]);");
/*fuzzSeed-244067732*/count=1057; tryItOut("if((x % 2 != 1)) {(new RegExp(\"(?:.)|(\\\\s\\u0089|(?=\\\\2){0,})\", \"yim\"))(\"\\u7600\", c); } else  if (((makeFinalizeObserver('nursery')))) let (y = NaN, pxipvh, e, \u3056 =  '' , jhtqhi) { (x); } else /*tLoop*/for (let w of /*MARR*/[true, undefined, true, undefined, new Number(1), null, null, null, true, null, undefined, true, true, true, undefined, undefined, null, new Number(1), undefined]) { i1 + ''; }");
/*fuzzSeed-244067732*/count=1058; tryItOut("o0.a1.splice(NaN, 0, this.s2, g1);");
/*fuzzSeed-244067732*/count=1059; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.cosh((Math.fround(mathy0(Math.sinh(x), Math.fround(Math.fround(Math.max(y, x))))) ? mathy0(mathy0(y, y), Math.imul(y, x)) : mathy0((mathy0((( - ( ! Math.fround(y))) >>> 0), (x >>> 0)) >>> 0), ( - Math.log10(x))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -0x080000000, -0x07fffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 0x080000000, 42, -0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0, -1/0, 0, 2**53+2, 0x100000001, 1/0, -(2**53), -Number.MIN_VALUE, 1, 0x0ffffffff, -0x100000001, -0x100000000, -(2**53-2), 2**53, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1060; tryItOut("M:with(x\u000d)for (var v of s1) { try { a0.reverse(t1); } catch(e0) { } try { for (var v of h1) { try { t0 = t0.subarray(2, 28); } catch(e0) { } try { a0.unshift(); } catch(e1) { } v0 = Object.prototype.isPrototypeOf.call(h1, h1); } } catch(e1) { } try { o2 = {}; } catch(e2) { } s2 += o2.g1.g2.s1; }");
/*fuzzSeed-244067732*/count=1061; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=1062; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 16384.0;\n    return +((-((+(0.0/0.0)))));\n  }\n  return f; })(this, {ff: encodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x100000000, -Number.MAX_VALUE, 1/0, -1/0, 0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, 2**53+2, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, Math.PI, 42, -0, -(2**53-2), -(2**53+2), 2**53, Number.MIN_SAFE_INTEGER, 1, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, 0, -(2**53), Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-244067732*/count=1063; tryItOut("/*infloop*/while(let (y = ( \"\" .__defineGetter__(\"x\", window)()) ^= 033.unwatch(\"endsWith\")) (NaN = 4) ? (z >> w) ? x : (mathy5)(null,  /x/ ).yoyo((makeFinalizeObserver('nursery'))) || /${3}/gy : (4277)){o2.o1.v2 = evalcx(\"mathy5 = (function(x, y) { return ( + (((( ~ ( + -1/0)) >>> 0) | 0) < ( - y))); }); \", g0);a2.unshift(b0, this.__defineGetter__(\"e\", function(y) { yield y; return;; yield y; }), g1.s2);\nprint((\neval(\"new RegExp(\\\"(?=(?![^]|(?=^)*?(?:[^])\\\\\\\\cP+?)){1}\\\", \\\"yim\\\")\", window)));\n }");
/*fuzzSeed-244067732*/count=1064; tryItOut("let (e) { a1.toString = (function() { try { b1 = t0.buffer; } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(b2, t1); return this.s0; }); }");
/*fuzzSeed-244067732*/count=1065; tryItOut("print(\neval - \u3056);print(x = true);");
/*fuzzSeed-244067732*/count=1066; tryItOut("");
/*fuzzSeed-244067732*/count=1067; tryItOut("mathy4 = (function(x, y) { return Math.acos((Math.min((( + Math.max((x | 0), ( - ( + ( ! (y >>> 0)))))) >= ( + (Math.trunc(((y || y) | 0)) | 0))), Math.ceil(mathy0((( + y) | ( + y)), mathy3(Math.fround(0.000000000000001), (Math.min((x | 0), (y | 0)) | 0))))) | 0)); }); ");
/*fuzzSeed-244067732*/count=1068; tryItOut("mathy1 = (function(x, y) { return ( ! ((Math.atan2(mathy0(((x >>> 0) ? y : (y | 0)), Math.log1p(( ~ Math.atan2(y, x)))), Math.atan2(Math.fround(-Number.MAX_SAFE_INTEGER), Math.fround((mathy0((( - (x | 0)) >>> 0), x) | 0)))) >>> 0) > ( + ( ~ Math.fround((Math.sinh(Math.fround(( ~ x))) >>> 0)))))); }); testMathyFunction(mathy1, /*MARR*/[null, null, null, null, (1/0), (-1/0), -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, (-1/0), objectEmulatingUndefined(), (1/0), -Infinity, -Infinity, (-1/0), objectEmulatingUndefined(), (-1/0), (-1/0), -Infinity, null, objectEmulatingUndefined(), (1/0), null, (1/0), -Infinity, (1/0), null, null, objectEmulatingUndefined(), (-1/0), (1/0), null, -Infinity, objectEmulatingUndefined(), null]); ");
/*fuzzSeed-244067732*/count=1069; tryItOut("t2 = new Uint16Array(b1, 88, v1);");
/*fuzzSeed-244067732*/count=1070; tryItOut("a0[9] = g1;");
/*fuzzSeed-244067732*/count=1071; tryItOut("/*vLoop*/for (var khkhxo = 0; khkhxo < 93; ++khkhxo) { const a = khkhxo; g2.h2.valueOf = (function() { try { (25); } catch(e0) { } try { g0.toString = f2; } catch(e1) { } b2.__proto__ = t0; return o0; }); } \n/* no regression tests found */\n");
/*fuzzSeed-244067732*/count=1072; tryItOut("\"use strict\"; m1.get(g2.g2);");
/*fuzzSeed-244067732*/count=1073; tryItOut("Array.prototype.sort.apply(a0, [(function() { try { g2.a1.push(a1, t2); } catch(e0) { } for (var v of g1) { try { h1.getPropertyDescriptor = f2; } catch(e0) { } try { g0.__proto__ = e1; } catch(e1) { } try { v1 = Array.prototype.every.call(a1, (function(j) { if (j) { try { a1[(new (((1 for (x in []))).apply)(this))] = new  '' (window) >>>= [,,]; } catch(e0) { } try { this.g0.m2 = new WeakMap; } catch(e1) { } this.t1 = new Uint16Array(6); } else { try { print(e0); } catch(e0) { } try { v0 = (g0 instanceof a1); } catch(e1) { } try { m1.delete(this.m0); } catch(e2) { } (void schedulegc(g1.g2)); } }), a0, e1, i1, o0, 29); } catch(e2) { } f1.toSource = f2; } return o1.o1; })]);");
/*fuzzSeed-244067732*/count=1074; tryItOut("mathy3 = (function(x, y) { return (Math.acos((Math.fround(( ! Math.fround(( + (( + ( + Math.tanh((( - Math.fround((((((x - (x >>> 0)) >>> 0) >>> 0) , (y >>> 0)) >>> 0))) >>> 0)))) > ( + -1/0)))))) | 0)) | 0); }); testMathyFunction(mathy3, [2**53+2, 0x100000001, 0x080000001, 2**53, Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 42, -0x100000001, 1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2, -(2**53+2), 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -0, -(2**53-2), -Number.MAX_VALUE, 0/0, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000000, 1, 0x080000000, -0x080000001, 0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1075; tryItOut("v2 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-244067732*/count=1076; tryItOut("m0.has(b1);");
/*fuzzSeed-244067732*/count=1077; tryItOut("for (var p in o2) { try { v1 = r1.exec; } catch(e0) { } try { this.v2 = g2.eval(\"mathy3 = (function(x, y) { return (((((Math.pow(y, (Math.max(mathy0(Number.MAX_SAFE_INTEGER, (y >>> 0)), Math.imul(( + x), ( + ((y | 0) | (y >>> 0))))) | 0)) > ( - ((Math.sqrt((0x100000000 | 0)) | 0) && (Math.max((Math.cosh(( + x)) | 0), (-(2**53-2) | 0)) | 0)))) | 0) | 0) >> (Math.fround(Math.cbrt((( - (Math.fround(Math.max((( ! 0x100000001) | 0), Math.fround(Number.MIN_VALUE))) >>> Math.fround(Math.max(Math.fround(x), Math.fround(y))))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [0.000000000000001, 1/0, 1.7976931348623157e308, -0, -0x080000000, -(2**53-2), 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, 2**53-2, 0x100000000, -1/0, 0/0, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff, -0x100000001, Math.PI, 42, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53), 0x080000001, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 0, 0x080000000, 0x100000001, 2**53+2, -0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); \"); } catch(e1) { } try { /*MXX3*/o0.g1.g2.Symbol.prototype.toString = g1.Symbol.prototype.toString; } catch(e2) { } this.a1.push(o0.v1); }");
/*fuzzSeed-244067732*/count=1078; tryItOut("\"use strict\"; throw x;let(y) ((function(){x = y;})());");
/*fuzzSeed-244067732*/count=1079; tryItOut("mathy4 = (function(x, y) { return (( ! Math.pow((( - (Math.min((Math.min((Math.fround(y) !== Math.fround(x)), x) >>> 0), Math.fround(x)) | 0)) | 0), ( + ( ~ (( + (y <= x)) | 0))))) / ( + Math.ceil((x > y)))); }); testMathyFunction(mathy4, [[], NaN, objectEmulatingUndefined(), undefined, 0.1, ({toString:function(){return '0';}}), '/0/', (new String('')), false, ({valueOf:function(){return '0';}}), 0, 1, '0', null, (new Boolean(true)), (new Number(-0)), (new Number(0)), -0, '\\0', ({valueOf:function(){return 0;}}), '', /0/, true, (function(){return 0;}), [0], (new Boolean(false))]); ");
/*fuzzSeed-244067732*/count=1080; tryItOut("testMathyFunction(mathy1, [1, 0/0, 0, 0x07fffffff, -0x0ffffffff, 0x0ffffffff, 0x080000001, -Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, -0x080000000, 2**53+2, Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -Number.MIN_VALUE, 42, 1/0, -0x100000000, 1.7976931348623157e308, -0x100000001, 0x100000000, -(2**53), -0, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1081; tryItOut("e1.has(g0);");
/*fuzzSeed-244067732*/count=1082; tryItOut("\"use strict\"; /*MXX1*/o2 = g2.Array.prototype.join;");
/*fuzzSeed-244067732*/count=1083; tryItOut("a2.splice(2, ({valueOf: function() { Array.prototype.reverse.apply(a0, []);return 10; }}), g1);");
/*fuzzSeed-244067732*/count=1084; tryItOut("mathy1 = (function(x, y) { return (((( + (Math.log2(Math.fround(Math.max(Math.fround(x), Math.fround(x)))) >>> 0)) >>> 0) <= ((( + Math.atan2((( + ( + ( ! y))) + ( + (y != y))), (Math.atan2((mathy0(42, y) >>> 0), (mathy0(y, y) >>> 0)) >>> 0))) ^ (Math.asinh((Math.abs((Math.fround(( - Math.fround(( ~ 1)))) | 0)) | 0)) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-244067732*/count=1085; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1086; tryItOut("s0 += s1;");
/*fuzzSeed-244067732*/count=1087; tryItOut("\"use strict\"; \"use asm\"; b = new Root((x >> x), x);var gzcjba = new ArrayBuffer(1); var gzcjba_0 = new Uint8Array(gzcjba); gzcjba_0[0] = 7; var gzcjba_1 = new Float32Array(gzcjba); gzcjba_1[0] = -15; x");
/*fuzzSeed-244067732*/count=1088; tryItOut("/*tLoop*/for (let z of /*MARR*/[({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), Number.MIN_SAFE_INTEGER, ({}), ({}), ({}), ({}), ({}), ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), ({}), ({}), ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), Number.MIN_SAFE_INTEGER, ({}), Number.MIN_SAFE_INTEGER, ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) { h0.__proto__ = o1.v1; }");
/*fuzzSeed-244067732*/count=1089; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround((Math.abs(Math.fround(( + Math.fround(( - ( ~ y)))))) ? (Math.asinh(( - mathy2(( ! x), ( + mathy2(( + (((2**53-2 | 0) ** y) | 0)), ( + y)))))) >>> 0) : ((Math.exp(Math.cos((x >>> 0))) >>> 0) | 0))); }); ");
/*fuzzSeed-244067732*/count=1090; tryItOut("/*tLoop*/for (let b of /*MARR*/[Math.PI, new String(''), Math.PI]) { /*infloop*/L:for(var arguments.callee.caller.arguments = function ([y]) { }; this.__defineSetter__(\"b\", /*wrap2*/(function(){ \"use strict\"; var quecmx =  \"\" ; var gvxqug =  /x/ ; return gvxqug;})()); /[^]/gym &  /x/ ) /*MXX2*/o0.g1.Float64Array.BYTES_PER_ELEMENT = o0; }");
/*fuzzSeed-244067732*/count=1091; tryItOut("try { let(a = x) { x.stack;} } catch(x) { for(let z in /*MARR*/[3, 3, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 3, 3, 3, 3, 2**53+2, 3, 3, 3, 2**53+2, 2**53+2, 3, 3, 3, 3, 2**53+2, 3, 3, 2**53+2, 3, 3, 2**53+2, 2**53+2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 3, 2**53+2, 3, 2**53+2, 3, 3, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 3, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 3, 2**53+2, 3, 2**53+2, 3, 2**53+2, 3, 3, 3, 3, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 3, 3, 3, 3, 3, 2**53+2, 3, 3, 2**53+2, 2**53+2, 2**53+2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2**53+2, 3, 3, 2**53+2, 3, 3, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 3, 2**53+2, 3, 2**53+2, 2**53+2, 3, 3, 3, 3, 3, 3, 2**53+2, 2**53+2, 3, 3, 3, 3, 2**53+2, 2**53+2, 3, 2**53+2, 3, 2**53+2, 3, 3, 3, 2**53+2, 3, 2**53+2, 3, 3, 2**53+2, 2**53+2, 3, 2**53+2, 3, 3, 3, 3, 3, 3, 2**53+2, 3, 3, 2**53+2, 2**53+2, 2**53+2, 3, 3, 3, 3, 3, 3, 2**53+2, 3, 2**53+2, 2**53+2, 2**53+2, 3, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 3, 2**53+2, 2**53+2, 3, 3, 3, 3, 3, 3]) x = z; } finally { DataView = x; } x.name;");
/*fuzzSeed-244067732*/count=1092; tryItOut("\"use asm\"; testMathyFunction(mathy3, [false, '0', '/0/', 0, /0/, '', (new Number(-0)), (new Boolean(false)), [0], (new Boolean(true)), true, 1, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new String('')), null, 0.1, ({toString:function(){return '0';}}), [], (function(){return 0;}), (new Number(0)), NaN, ({valueOf:function(){return 0;}}), -0, '\\0', undefined]); ");
/*fuzzSeed-244067732*/count=1093; tryItOut("\"use strict\"; m1.get(/((?:([\\S\\r]){4096,4100}.*|(?=[^\\cS]){2,}\\b))/gyim);");
/*fuzzSeed-244067732*/count=1094; tryItOut("mathy3 = (function(x, y) { return (Math.max(((Math.min(( - ( ! Math.fround(y))), Math.imul(Math.fround(Math.fround(Math.hypot(x, (-0x07fffffff >> -(2**53+2))))), ( + ( ! 0.000000000000001)))) >> ( + (( + (( + ( + ( - ( + y)))) | 0)) | 0))) | 0), ((Math.tanh((( + x) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [-1/0, 0x100000001, 0, 1, -0x080000001, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -0, 1.7976931348623157e308, 0.000000000000001, 0x080000001, -0x100000000, -(2**53+2), 0x080000000, 2**53+2, 0/0, Math.PI, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, 2**53, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, -0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, 42, -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1095; tryItOut("g1.offThreadCompileScript(\"Math.min((mathy2)(767023247), 9)\");");
/*fuzzSeed-244067732*/count=1096; tryItOut("testMathyFunction(mathy4, [-1/0, -Number.MAX_SAFE_INTEGER, 0/0, 0, 1.7976931348623157e308, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, -(2**53), 2**53-2, -0x100000001, Number.MAX_VALUE, -0, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), 0x080000000, 0x07fffffff, 2**53+2, -0x080000000, 0x100000001, Math.PI, 0x100000000, 42, -0x100000000, 1, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1097; tryItOut("f0(i0);");
/*fuzzSeed-244067732*/count=1098; tryItOut("s2 + f2;");
/*fuzzSeed-244067732*/count=1099; tryItOut("\"use strict\"; yield /*RXUE*/new RegExp(\"(?=[^\\\\n-\\\\u0058])?(\\\\w|(?=.)\\\\2|\\\\b|\\\\B){0}\", \"gym\").exec((new (intern(new RegExp(\"[^]\", \"gyi\")))((--y))));this.zzz.zzz;");
/*fuzzSeed-244067732*/count=1100; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ! ( + Math.max((Math.asin(Math.fround(( - Math.fround(x)))) | 0), Math.pow((( + Math.min(y, ( + 0x0ffffffff))) >>> 0), (Math.asin(y) >>> 0))))); }); testMathyFunction(mathy0, [0, 42, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x080000000, 1, 1.7976931348623157e308, 2**53-2, 0x100000000, -0x07fffffff, -0x080000001, 0.000000000000001, Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, 0/0, -Number.MAX_VALUE, -0, 0x100000001, -(2**53-2), Number.MIN_VALUE, -1/0, 0x080000000, 2**53, 0x080000001, -(2**53+2), Math.PI, 2**53+2]); ");
/*fuzzSeed-244067732*/count=1101; tryItOut("testMathyFunction(mathy3, [0x100000000, -0x07fffffff, 0x080000001, 2**53-2, 0/0, 42, -1/0, Math.PI, Number.MIN_VALUE, -(2**53-2), -0x100000000, -(2**53), 0.000000000000001, -0x0ffffffff, 1, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -0, -0x100000001, -0x080000001, 2**53+2, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, 0x07fffffff, 0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1102; tryItOut("testMathyFunction(mathy4, [1, 2**53-2, 0x080000000, 0/0, 0, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -(2**53-2), 2**53+2, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, 0x100000001, -0x080000001, 1/0, -(2**53+2), -1/0, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, -0x0ffffffff, 42, 0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-244067732*/count=1103; tryItOut("\"use asm\"; m0 + f1;");
/*fuzzSeed-244067732*/count=1104; tryItOut("/*vLoop*/for (let ydzxrc = 0; ydzxrc < 4; ++ydzxrc) { var c = ydzxrc; ( \"\" );o0.toSource = (function() { g0.a1.push(m1, s0, a1, b2, o2, m1); return s2; }); } ");
/*fuzzSeed-244067732*/count=1105; tryItOut("\"use strict\"; M:with(x)print(x);");
/*fuzzSeed-244067732*/count=1106; tryItOut("print(this.e1);");
/*fuzzSeed-244067732*/count=1107; tryItOut("\"use strict\"; print(m1);");
/*fuzzSeed-244067732*/count=1108; tryItOut("(window.eval(\"false\"));");
/*fuzzSeed-244067732*/count=1109; tryItOut("m0.get((4277));");
/*fuzzSeed-244067732*/count=1110; tryItOut("e1.delete(b0);");
/*fuzzSeed-244067732*/count=1111; tryItOut("/*hhh*/function vuxbil(this.this.z, x = x, ...x){for (var v of i0) { e1.has(t1); }}vuxbil((uneval(new DFGTrue())),  /* Comment */\"\\u5FE4\".eval(\"Math\"));");
/*fuzzSeed-244067732*/count=1112; tryItOut("const goqqdc, mbzxgl, xdnhyd, eval, x =  /x/ ;Array.prototype.splice.call(a2, NaN, v1, z => \"use asm\";   var asin = stdlib.Math.asin;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (((+(1.0/0.0))) % ((new (new RegExp(\"[\\\\t-\\\\u009c\\\\\\u4d4f\\\\d](?=\\\\s)(^|(?:(^))(\\\\s|\\\\b\\\\cA){0})\", \"im\").throw(\"\\u7C2F\"))(undefined.throw(false)))));\n    d0 = (d1);\n    d1 = (+asin(((d1))));\n    d0 = (((d0)) / ((+(1.0/0.0))));\n    return (((0xfff590b2)+(((('fafafa'.replace(/a/g, mathy2)) / ((d1))) | ((0x4636e8a0)+(0xa31c570b)+(1))))-(0xfccad000)))|0;\n  }\n  return f;.prototype, b0, a1, b0, o1.f1, h1);");
/*fuzzSeed-244067732*/count=1113; tryItOut("testMathyFunction(mathy5, [0, -0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0, 2**53, -0x100000000, 1.7976931348623157e308, -(2**53-2), Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, -0x0ffffffff, -0x100000001, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, 42, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, -(2**53+2), 0x100000001, 0/0, 1, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, 2**53-2, 0x080000001, 1/0]); ");
/*fuzzSeed-244067732*/count=1114; tryItOut("/*MXX2*/g1.Error.prototype.constructor = o0;");
/*fuzzSeed-244067732*/count=1115; tryItOut("a0.unshift(this.a0);m0.get(e2);\n/*tLoop*/for (let d of /*MARR*/[]) { print(d); }\n");
/*fuzzSeed-244067732*/count=1116; tryItOut("\"use strict\"; const v2 = evalcx(\"e0.toString = function(y) { yield y; m0.has(h1);; yield y; };\", g2);");
/*fuzzSeed-244067732*/count=1117; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + Math.asin(( + Math.max(( + Math.fround((Math.fround((( + y) * ( + y))) && Math.fround(y)))), ( + Math.max(( ! ((Math.clz32((y >>> 0)) | 0) | ((( + (Math.tanh(Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0) | 0))), ( + x))))))); }); testMathyFunction(mathy1, [0x100000000, 1, 2**53-2, -(2**53+2), -0x100000000, 0x080000000, Number.MAX_VALUE, 0, 42, 0x07fffffff, -0, -0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, -1/0, -0x080000000, 1/0, 0x100000001, -(2**53), 0.000000000000001, -(2**53-2), Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, 0/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-244067732*/count=1118; tryItOut("mathy3 = (function(x, y) { return Math.acos(Math.pow((x ^ Math.fround(mathy0((Math.max((x | 0), ( + (y ? (y | 0) : (( + mathy0(( + y), ( + -(2**53+2)))) | 0)))) | 0), y))), mathy0((Math.fround(Math.round(( + (((x | 0) <= (y >>> 0)) >>> 0)))) < Math.log(( + ( - y)))), mathy1((((mathy1(Math.fround(-0x080000001), (y >>> 0)) >>> 0) >>> 0) ^ (x >>> 0)), y)))); }); testMathyFunction(mathy3, /*MARR*/[arguments.callee, function(){}, arguments.callee,  \"use strict\" , arguments.callee, arguments.callee, arguments.callee, function(){}, function(){},  \"use strict\" , function(){}, function(){}, arguments.callee,  \"use strict\" ,  \"use strict\" , function(){}, arguments.callee, arguments.callee, arguments.callee,  \"use strict\" , function(){}, function(){}, function(){}, function(){}, arguments.callee, function(){},  \"use strict\" , function(){}, function(){}, arguments.callee,  \"use strict\" , function(){}, arguments.callee, arguments.callee, arguments.callee, function(){}, function(){},  \"use strict\" , arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, function(){},  \"use strict\" , function(){}, function(){},  \"use strict\" , function(){}, function(){}, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, function(){},  \"use strict\" ]); ");
/*fuzzSeed-244067732*/count=1119; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1120; tryItOut("f0(b2);");
/*fuzzSeed-244067732*/count=1121; tryItOut("\"use asm\"; continue L;\nreturn;\n");
/*fuzzSeed-244067732*/count=1122; tryItOut("let z = (4277);print(false);");
/*fuzzSeed-244067732*/count=1123; tryItOut("s0 += 'x';");
/*fuzzSeed-244067732*/count=1124; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.tanh((Math.imul(mathy4(Math.fround(( + ( + (( + x) / Math.fround(x))))), ( + 42)), ( - Math.log2(y))) % (( ! (y >>> 0)) ? (Math.hypot((Math.sqrt(x) | 0), x) >>> 0) : (Math.ceil((( + Math.pow(( + Math.PI), ( + mathy2(y, x)))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, /*MARR*/[[1], [1], false, [1], [1],  /x/ , false,  /x/ , false,  /x/ ,  /x/ , [1],  /x/ ,  /x/ , [1], new Boolean(true), new Boolean(true),  /x/ , [1], false,  /x/ , [1], [1], new Boolean(true), false, [1], false, new Boolean(true), [1], [1], false,  /x/ , new Boolean(true), [1], new Boolean(true), false, false, [1], false, new Boolean(true),  /x/ , false, new Boolean(true), [1],  /x/ , [1],  /x/ ,  /x/ , [1], false, new Boolean(true),  /x/ , new Boolean(true), [1], new Boolean(true), false,  /x/ , [1],  /x/ , [1],  /x/ , [1], [1],  /x/ , new Boolean(true), [1],  /x/ , [1], false, [1], new Boolean(true), [1], new Boolean(true), false, [1], new Boolean(true), new Boolean(true),  /x/ ,  /x/ , [1], new Boolean(true), [1],  /x/ , [1], [1], [1],  /x/ , new Boolean(true), false, [1],  /x/ , false, false, new Boolean(true), new Boolean(true), false, new Boolean(true), false, new Boolean(true)]); ");
/*fuzzSeed-244067732*/count=1125; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+(~~(+((((DFGTrue(((Function)( '' ))))) / ((Float32ArrayView[((-0x8000000)-(0xd7a3db9b)) >> 2])))))));\n    d0 = (d1);\n    (Float64ArrayView[(-0xf1dbc*(0x5d105a74)) >> 3]) = ((d0));\n    return ((0xfffff*(0x2dd1d255)))|0;\n  }\n  return f; })(this, {ff: \"\\u1B44\"}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=1126; tryItOut("\"use asm\"; e1.has(f0);");
/*fuzzSeed-244067732*/count=1127; tryItOut("\"use strict\"; (\"\\uE478\");(undefined);");
/*fuzzSeed-244067732*/count=1128; tryItOut("s1 += 'x';");
/*fuzzSeed-244067732*/count=1129; tryItOut("\"use strict\"; o1.t1.set(a1, (new Element((/*\n*/{/*toXFun*/valueOf: (function() { try { for (var v of a2) { try { Array.prototype.sort.apply(a2, [(function() { for (var j=0;j<88;++j) { this.f1(j%4==0); } })]); } catch(e0) { } try { o1.t2 + this.g2; } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(v2, i0); } catch(e2) { } print(uneval(a1)); } } catch(e0) { } a2.shift(t1, v0, this.t2, b0); return f2; }) }), (4277))));");
/*fuzzSeed-244067732*/count=1130; tryItOut("(Math.max(\"\\uD4CB\", -19))[\"atan\"] = ((e =>  { yield -19 } )( /x/ ) >= false instanceof  '' ).eval(\"e != z\");");
/*fuzzSeed-244067732*/count=1131; tryItOut("\"use strict\"; (void schedulegc(g0));");
/*fuzzSeed-244067732*/count=1132; tryItOut("\"use strict\"; var cdhinq = new ArrayBuffer(4); var cdhinq_0 = new Float64Array(cdhinq); print(cdhinq_0[0]); const v2 = Array.prototype.every.apply(a0, [WeakSet, g1, m2]);");
/*fuzzSeed-244067732*/count=1133; tryItOut("this.m0 = new Map;");
/*fuzzSeed-244067732*/count=1134; tryItOut("\"use strict\"; v1 = (f1 instanceof a2);window;");
/*fuzzSeed-244067732*/count=1135; tryItOut("");
/*fuzzSeed-244067732*/count=1136; tryItOut("var r0 = x / x; var r1 = 1 & 2; var r2 = r1 | r1; ");
/*fuzzSeed-244067732*/count=1137; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.log((Math.imul(( + (( + ( + ( + y))) >> Math.asinh(Math.fround((Math.min((x | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0))))), ( + ( ~ ( + Math.fround(( ! Math.fround(0x100000001))))))) | 0)); }); testMathyFunction(mathy5, [-(2**53-2), -Number.MIN_VALUE, -0x100000001, 1, 42, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, -0x07fffffff, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, 1/0, 2**53, 0, 0.000000000000001, Math.PI, 0x100000000, 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 0/0, Number.MIN_VALUE, -0x0ffffffff, 0x080000001, -(2**53), -(2**53+2), 0x100000001, 0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1138; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(((((Math.cbrt(Math.fround((( - (x >>> 0)) >>> 0))) >>> 0) >>> 0) ** ((( + Math.fround(Math.max(Math.fround((Math.min((Math.imul(y, (x >>> 0)) | 0), ((((( - x) | 0) !== (y | 0)) | 0) >>> 0)) >>> 0)), ( + ( + ( ~ (((y || (-(2**53+2) | 0)) | 0) | 0))))))) - ( + ((y | 0) <= (Math.min(y, ( - Math.PI)) | 0)))) | 0)) !== ( ! (Math.log10(Math.pow(x, Math.imul(y, ( + y)))) | 0)))); }); ");
/*fuzzSeed-244067732*/count=1139; tryItOut("mathy2 = (function(x, y) { return Math.imul(( + Math.fround(( + y))), (( - (((((x >>> (( + Math.max(( + ( + (( + x) <= (Math.fround(( ! ( + y))) >>> 0)))), ( + ( + Math.atan2(( + ( + Math.imul(( + x), Math.fround(0x080000000)))), ( + 1)))))) | 0)) | 0) | 0) == (( + ( + ((Math.hypot((x >>> 0), (-(2**53-2) >>> 0)) >>> 0) >>> 0))) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy2, [-0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 1, 42, 2**53-2, -(2**53+2), -0x080000000, 1.7976931348623157e308, -(2**53), 0.000000000000001, 0/0, 0, 0x080000001, 2**53, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, 0x100000000, -0x100000001, -Number.MAX_VALUE, 0x100000001, -0, -0x0ffffffff, 1/0, 0x080000000, 2**53+2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1140; tryItOut("v0 + '';\nfor (var p in s1) { try { h0.defineProperty = (function() { try { g2.v1 = Object.prototype.isPrototypeOf.call(g2.m2, h2); } catch(e0) { } v2 = (s2 instanceof v0); return t0; }); } catch(e0) { } try { s2.__iterator__ = (function() { try { g1.a0 + v1; } catch(e0) { } try { for (var p in a1) { m1.has(e2); } } catch(e1) { } try { b2 = this.a2[({valueOf: function() { Object.seal(o0.a2);return 16; }})]; } catch(e2) { } a2 = g2.objectEmulatingUndefined(); return v1; }); } catch(e1) { } try { t0[this.v1]; } catch(e2) { } v1 + h0; }\n");
/*fuzzSeed-244067732*/count=1141; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(((( + Math.min(( + (((-(2**53+2) >>> 0) ** ( + (( ! ((y >= x) >>> 0)) | 0))) >>> 0)), ( + (x ? y : (((-0 <= x) >>> 0) >>> 0))))) ^ ( + Math.atan2(( + Math.fround(Math.hypot((x >>> 0), x))), ( + (0/0 << (4277)))))) | 0)), mathy0((Math.log2(( + x)) | 0), ( ! y))); }); testMathyFunction(mathy2, [0x100000001, 0, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 1.7976931348623157e308, 2**53-2, 0x080000000, -(2**53-2), -0x080000001, 0x100000000, Number.MAX_VALUE, -0x100000000, 1/0, 42, -(2**53+2), 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -0x100000001, 2**53, -(2**53), 0.000000000000001, Math.PI, Number.MIN_VALUE, -0, 0x07fffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-244067732*/count=1142; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; gcPreserveCode(); } void 0; } s1 += 'x';");
/*fuzzSeed-244067732*/count=1143; tryItOut("\"use strict\"; v2 = null;");
/*fuzzSeed-244067732*/count=1144; tryItOut("m2.set(s1, f0);function c()\"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (d1);\n    {\n      {\n        d0 = (d1);\n      }\n    }\n    return (((!((((Uint16ArrayView[(0xbbeda*((-2.3611832414348226e+21) <= (-70368744177665.0))) >> 1]))|0) <= (0x4d8d72fc)))-(0xfd64becc)))|0;\n  }\n  return f;v0 = (g0.o1.h0 instanceof this.b1);");
/*fuzzSeed-244067732*/count=1145; tryItOut("/*bLoop*/for (var rhfcie = 0; rhfcie < 36; ++rhfcie) { if (rhfcie % 5 == 1) { {}; } else { ([[1]]); }  } ");
/*fuzzSeed-244067732*/count=1146; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1147; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[ /x/g , x, allocationMarker().throw([1,,]),  /x/g ,  /x/g ,  /x/g , new Boolean(true), ({x:3}),  /x/g , new Boolean(true),  /x/g , new Boolean(true), allocationMarker().throw([1,,]), new Boolean(true),  /x/g , ({x:3}),  /x/g , allocationMarker().throw([1,,]), ({x:3}),  /x/g , allocationMarker().throw([1,,]), new Boolean(true), new Boolean(true), x,  /x/g ,  /x/g , x, ({x:3}), allocationMarker().throw([1,,]), new Boolean(true), new Boolean(true), x, new Boolean(true), allocationMarker().throw([1,,]), ({x:3}), new Boolean(true), allocationMarker().throw([1,,]), x, x, allocationMarker().throw([1,,]), x, allocationMarker().throw([1,,]), x, ({x:3}), ({x:3}), ({x:3}), allocationMarker().throw([1,,]), ({x:3}),  /x/g , x, allocationMarker().throw([1,,]), ({x:3}), allocationMarker().throw([1,,]), allocationMarker().throw([1,,]),  /x/g , x, x, new Boolean(true), allocationMarker().throw([1,,]), x, ({x:3}), ({x:3}), new Boolean(true), new Boolean(true), new Boolean(true), allocationMarker().throw([1,,]), new Boolean(true),  /x/g , ({x:3}), allocationMarker().throw([1,,]),  /x/g , ({x:3}), ({x:3}),  /x/g ,  /x/g , x, ({x:3}), x, new Boolean(true)]); ");
/*fuzzSeed-244067732*/count=1148; tryItOut("\"use strict\"; ");
/*fuzzSeed-244067732*/count=1149; tryItOut("let (dwdxge, a = /\\3/im) { this.e2.has(x); }");
/*fuzzSeed-244067732*/count=1150; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.max(( - ( ~ (y >>> 0))), ((( + (Math.min((Math.pow(y, y) * Math.acos(0)), (x >>> 0)) > Math.fround((x >>> x)))) ? (Math.hypot((mathy2(Math.fround(( + (x ? y : y))), x) >>> 0), (( + Math.log(Math.fround(y))) ? (y | 0) : (( + Math.imul(( + mathy0(( + x), ( + Math.min(0x07fffffff, (-Number.MIN_SAFE_INTEGER >>> 0))))), ( + -(2**53)))) | 0))) | 0) : (mathy0(y, Math.fround(( + Math.fround(-0x080000000)))) | 0)) | 0)); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 1, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, 0x100000001, 2**53-2, 0x07fffffff, Math.PI, 0x080000000, -1/0, -Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, 1/0, -0x100000001, -(2**53-2), 0, -0, 42, 0/0, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, -0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1151; tryItOut("L:if((x % 4 != 3)) g1.a1[3] = \"\\u04B4\"; else  if (x\u0009) {\"\\u8328\"; } else print(this);");
/*fuzzSeed-244067732*/count=1152; tryItOut("b0.__proto__ = e0;");
/*fuzzSeed-244067732*/count=1153; tryItOut("v2 = r0.source;");
/*fuzzSeed-244067732*/count=1154; tryItOut("\"use strict\"; /*hhh*/function nhcdnm(x, [[{x}, w, , []], , , w], ...NaN){/*RXUB*/var r = new RegExp(\"(?=[^])|[\\\\S\\\\b-\\\\r\\\\f-\\u81f5\\\\~]?((?=\\\\1*?))\", \"yi\"); var s = \"\"; print(s.search(r)); }nhcdnm();return (-(2**53+2));return;");
/*fuzzSeed-244067732*/count=1155; tryItOut("\"use asm\"; e1.__iterator__ = (function mcc_() { var sixgxe = 0; return function() { ++sixgxe; f1(/*ICCD*/sixgxe % 7 == 5);};})();");
/*fuzzSeed-244067732*/count=1156; tryItOut("s2 += 'x';");
/*fuzzSeed-244067732*/count=1157; tryItOut("e2.add(f2);");
/*fuzzSeed-244067732*/count=1158; tryItOut("mathy1 = (function(x, y) { return (Math.sign(Math.fround(Math.pow(Math.fround(( + Math.abs(Math.log2(x)))), Math.fround(Math.atan2((Math.max(Math.fround(x), ( + Math.fround(x))) >> Math.imul(0/0, 2**53+2)), Math.fround(Math.cos(Math.fround(( - Math.max(y, (mathy0(Math.fround(y), Math.fround(-0x100000000)) >>> 0))))))))))) >>> 0); }); testMathyFunction(mathy1, [2**53, Math.PI, -0, -0x100000000, Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, Number.MIN_SAFE_INTEGER, 1/0, 0, 2**53-2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, 0x0ffffffff, -(2**53+2), -1/0, -0x080000000, 0x100000001, -0x07fffffff, -0x080000001, 2**53+2, 0x080000001, -Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, Number.MIN_VALUE, 42, 0/0, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1159; tryItOut("\"use strict\"; /*vLoop*/for (var kncmzp = 0; kncmzp < 17; ++kncmzp) { const z = kncmzp; o2.__proto__ = v0; } ");
/*fuzzSeed-244067732*/count=1160; tryItOut("\"use strict\"; ((uneval(true)));");
/*fuzzSeed-244067732*/count=1161; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d0));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 2**53, Number.MIN_SAFE_INTEGER, -(2**53), -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, -0x100000001, 1, 0.000000000000001, 1.7976931348623157e308, 0x100000001, 42, -Number.MAX_VALUE, 0/0, -1/0, 0x07fffffff, 0x080000000, 1/0, 2**53-2, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 0, -0, -0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1162; tryItOut("\"use strict\"; a0.push((yield  /x/ ), e1, this.e2, o0);");
/*fuzzSeed-244067732*/count=1163; tryItOut("\"use strict\"; var a = \"\\u9DCE\";Array.prototype.push.apply(a1, [g1.g2.e2, s2, this.g0, this.b2]);");
/*fuzzSeed-244067732*/count=1164; tryItOut("mathy1 = (function(x, y) { return (Math.fround(( + (Number.MIN_SAFE_INTEGER / -(2**53+2)))) ? mathy0((4277), ( ~ ( + ((-(2**53+2) >>> 0) % ( + x))))) : (Math.cosh((Math.clz32(( + mathy0(Math.cbrt(Math.fround(( ! -0x07fffffff))), x))) | 0)) | 0)); }); testMathyFunction(mathy1, ['0', (new Boolean(true)), ({toString:function(){return '0';}}), -0, true, NaN, (new Number(-0)), (new Number(0)), null, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), [], undefined, [0], '\\0', false, /0/, 0, ({valueOf:function(){return '0';}}), 0.1, 1, (function(){return 0;}), (new Boolean(false)), '', '/0/', (new String(''))]); ");
/*fuzzSeed-244067732*/count=1165; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.fround((Math.imul((Math.hypot(y, y) | 0), (Math.fround(Math.trunc(Math.fround((x & (y != Math.fround(x)))))) >>> 0)) >>> 0)) || mathy0(Math.tanh(Math.fround(Math.sin(Math.fround(( ! x))))), mathy0((0/0 && ((((x >>> 0) << (( + (( + 1) | ( + y))) >>> 0)) >>> 0) | 0)), (x | ((( - 0) >>> 0) && Math.cbrt(y)))))); }); testMathyFunction(mathy1, [0x080000001, -0x080000001, -0x100000000, -(2**53), 0x100000000, -0x0ffffffff, Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000000, 42, Math.PI, 2**53+2, -0x100000001, -(2**53-2), 0, 1/0, 0/0, -0, 0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1166; tryItOut("mathy2 = (function(x, y) { return ( + (Math.fround(Math.imul(Math.fround(x), (( + Math.imul(( + 1.7976931348623157e308), ( + x))) < ( + (( + -0x07fffffff) === ( + y)))))) === ( ! (( + Math.abs(((( ~ ((x ? x : y) | 0)) | 0) | 0))) | 0)))); }); testMathyFunction(mathy2, [-0, [], (new Number(-0)), false, ({valueOf:function(){return 0;}}), 1, ({valueOf:function(){return '0';}}), '0', '', /0/, (new Boolean(false)), [0], 0, (new Number(0)), ({toString:function(){return '0';}}), undefined, (function(){return 0;}), objectEmulatingUndefined(), NaN, (new String('')), 0.1, null, '\\0', true, (new Boolean(true)), '/0/']); ");
/*fuzzSeed-244067732*/count=1167; tryItOut("while((\"\\u8A8F\"\n) && 0)a2[v2] = a0;");
/*fuzzSeed-244067732*/count=1168; tryItOut("m0 = new Map(s1);");
/*fuzzSeed-244067732*/count=1169; tryItOut("g2.a1.forEach((function() { for (var j=0;j<59;++j) { f2(j%4==1); } }));");
/*fuzzSeed-244067732*/count=1170; tryItOut("print(x);");
/*fuzzSeed-244067732*/count=1171; tryItOut("o2 = Proxy.create(this.h2, g2);");
/*fuzzSeed-244067732*/count=1172; tryItOut("\"use strict\"; x;");
/*fuzzSeed-244067732*/count=1173; tryItOut("\"use strict\"; i0 = new Iterator(a0, true);");
/*fuzzSeed-244067732*/count=1174; tryItOut("print(s0);");
/*fuzzSeed-244067732*/count=1175; tryItOut("a1.pop();v2 = (v0 instanceof i0);yield  \"\" ;");
/*fuzzSeed-244067732*/count=1176; tryItOut("\"use strict\"; o0.v0 = o2.a1.reduce, reduceRight(s2, g2);print(x);");
/*fuzzSeed-244067732*/count=1177; tryItOut("\"use strict\"; v1 = t0.byteLength;");
/*fuzzSeed-244067732*/count=1178; tryItOut("\"use strict\"; g0.toSource = f1;");
/*fuzzSeed-244067732*/count=1179; tryItOut("/*MXX1*/o2 = g2.RegExp.lastParen;");
/*fuzzSeed-244067732*/count=1180; tryItOut("a1.reverse();");
/*fuzzSeed-244067732*/count=1181; tryItOut("mathy1 = (function(x, y) { return (( - (mathy0(Math.max(Math.fround(( ! Math.max((( + ( ! -0x100000001)) >>> 0), y))), ( + ( ! (y >>> 0)))), (((((x | 0) >>> (Math.max((y | 0), y) | 0)) >>> 0) != ( ~ ((Math.pow(( + 0.000000000000001), (Math.log(x) | 0)) | 0) / Math.max(( ! y), x)))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [false, '', ({toString:function(){return '0';}}), null, objectEmulatingUndefined(), true, 0.1, 1, (new Number(-0)), 0, -0, (new Boolean(false)), (new Number(0)), (function(){return 0;}), [], ({valueOf:function(){return '0';}}), [0], /0/, (new Boolean(true)), '0', undefined, '/0/', ({valueOf:function(){return 0;}}), '\\0', (new String('')), NaN]); ");
/*fuzzSeed-244067732*/count=1182; tryItOut("for (var p in s0) { try { g1.o2.g2.e1 + s2; } catch(e0) { } this.a0.shift(); }");
/*fuzzSeed-244067732*/count=1183; tryItOut("while((this.__defineSetter__(\"x\", /\\b/gyi)) && 0)v0 = Array.prototype.every.apply(a1, [(function mcc_() { var bwtnpk = 0; return function() { ++bwtnpk; f2(/*ICCD*/bwtnpk % 4 == 2);};})(), g2.g0]);");
/*fuzzSeed-244067732*/count=1184; tryItOut("\"use strict\"; m1 = new Map(e2);var a = (((x != (x >>> 0)) , x));");
/*fuzzSeed-244067732*/count=1185; tryItOut("testMathyFunction(mathy1, /*MARR*/[ 'A' , null, null,  'A' ,  'A' ,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null,  'A' ,  'A' , objectEmulatingUndefined(),  'A' , null,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null,  'A' ,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(),  'A' ,  'A' , objectEmulatingUndefined(), null,  'A' , null,  'A' ,  'A' , null, objectEmulatingUndefined(),  'A' ,  'A' , null, null, null, null,  'A' ,  'A' ,  'A' , objectEmulatingUndefined(),  'A' ,  'A' , null, objectEmulatingUndefined(), null,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' ,  'A' , objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' ,  'A' , objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, objectEmulatingUndefined(),  'A' , null, null,  'A' ,  'A' ,  'A' ,  'A' , objectEmulatingUndefined(),  'A' ,  'A' , null,  'A' ]); ");
/*fuzzSeed-244067732*/count=1186; tryItOut(";v0 = 4;");
/*fuzzSeed-244067732*/count=1187; tryItOut("\"use strict\"; /*vLoop*/for (sqazah = 0; sqazah < 27; ++sqazah) { c = sqazah; Object.defineProperty(o1, \"v2\", { configurable: false, enumerable: (x % 6 == 3),  get: function() {  return false; } }); } ");
/*fuzzSeed-244067732*/count=1188; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 68719476737.0;\n    var d3 = 65.0;\n    {\n      d3 = (d2);\n    }\n    {\n      {\n        return ((-(0xffd771f2)))|0;\n      }\n    }\n    {\n      d2 = (+(0.0/0.0));\n    }\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x080000000, 0x080000000, 2**53+2, 0x100000000, -0x0ffffffff, -Number.MAX_VALUE, -(2**53), 2**53-2, 1/0, -0x100000001, 2**53, -0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, -(2**53+2), -0x100000000, -0x07fffffff, -1/0, Number.MAX_VALUE, 0/0, 0x100000001, 0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, Number.MIN_VALUE, -Number.MIN_VALUE, 1, 42]); ");
/*fuzzSeed-244067732*/count=1189; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    /*FFI*/ff(((~~(1.0009765625))), ((-0x8000000)));\n    d1 = (+((((d1) < (d1)))>>>((!(i0))-(i0))));\n    {\n      {\n        (Uint16ArrayView[1]) = ((0x22349d2e)+((0x8a47c14e) > (((!(0x634cf4b2))+((-0x8000000) ? (0xc677bc48) : (0xff9bff35))+((0xe312aeda) ? (0xffffffff) : (0xb83ead22)))>>>((\"\\uE1D7\" in window == x)+(0x21840448)+(i0))))+(/*FFI*/ff(((((+/*FFI*/ff(((((((((0xa6a14c5a) <= (0xa316b577)))>>>((0x93144c3f)-(0x5ab24758))))) & (((0xe10b2cf)))))))))), ((((~((0xffffffff))) / (~~(1099511627777.0)))|0)), ((8193.0)), (((0xfc472c38) ? (+(-1.0/0.0)) : (-6.044629098073146e+23))))|0));\n      }\n    }\n    switch ((~~(+((Float64ArrayView[4096]))))) {\n      case 1:\n        i0 = (/*FFI*/ff(((d1)), (((({}) , window))), ((+tan(((Float64ArrayView[((0xf8098186)) >> 3]))))), (((Float64ArrayView[4096]))), (( /x/g )), (((((0x7cc85c54))) << ((0xb9ca1362)+(0xffffffff)+(0xffffffff)))), ((d1)), (((((-0x8000000)) | ((0x74849b4))))), ((imul((0x6ac7d242), (0x533518b5))|0)), ((4611686018427388000.0)), ((-1.0625)), ((33.0)), ((-4503599627370495.0)), ((2.3611832414348226e+21)), ((-4194305.0)), ((-281474976710657.0)), ((-1.001953125)))|0);\n        break;\n    }\n    return (((0x9eb35e31) / (0x4d6c4b87)))|0;\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x07fffffff, Math.PI, -0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, -0, -0x080000000, -Number.MAX_VALUE, 2**53, 1/0, -1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -(2**53+2), 0, 0x100000001, -(2**53), 1, 0.000000000000001, 42, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, -(2**53-2), -Number.MIN_VALUE, -0x0ffffffff, 0x080000000, 2**53+2, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001]); ");
/*fuzzSeed-244067732*/count=1190; tryItOut("for (var p in o1.g1) { try { a0 = []; } catch(e0) { } try { for (var v of s2) { try { v1 = x; } catch(e0) { } try { b2[\"arguments\"] = s2; } catch(e1) { } m2.set(this.o0.g2, o0.a0); } } catch(e1) { } try { i0 = a0.iterator; } catch(e2) { } g0 = this; }");
/*fuzzSeed-244067732*/count=1191; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1192; tryItOut("\"use strict\"; v2 = this.g1.g0.runOffThreadScript();function window() { b2.toString = (function() { for (var j=0;j<0;++j) { f2(j%3==1); } }); } /*MXX3*/g2.Number.prototype.toLocaleString = g0.Number.prototype.toLocaleString;");
/*fuzzSeed-244067732*/count=1193; tryItOut("\"use strict\"; v2 = b2.byteLength;");
/*fuzzSeed-244067732*/count=1194; tryItOut("if(false) f2 = Uint16Array.bind(h2); else {this.t1[1] = s0;v0 = Object.prototype.isPrototypeOf.call(t1, p2); }");
/*fuzzSeed-244067732*/count=1195; tryItOut("s2 += s2;");
/*fuzzSeed-244067732*/count=1196; tryItOut("mathy4 = (function(x, y) { return Math.tan(Math.sign(( - Math.fround(( + Math.abs(( + (((((( + x) == ( + x)) >>> 0) >>> 0) ** (x >>> 0)) >>> 0)))))))); }); ");
/*fuzzSeed-244067732*/count=1197; tryItOut("b1 = t0.buffer;");
/*fuzzSeed-244067732*/count=1198; tryItOut("Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-244067732*/count=1199; tryItOut("\"use strict\"; x = this.b0;function eval(x) { \"use strict\"; yield (new WeakSet(((undefined &  /x/g .__proto__ = (/*MARR*/[].filter))), yield x)) } print(x);");
/*fuzzSeed-244067732*/count=1200; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(\\\\b)?\", \"\"); var s = \"\"; print(s.replace(r, '')); ");
/*fuzzSeed-244067732*/count=1201; tryItOut("/*RXUB*/var r = new RegExp(\"(?=[^\\\\n-\\u6d8f\\\\S]|\\\\3|\\\\2)((?!\\\\S)*?|\\\\b{1})|.+(?:(?=\\\\3)?)+\", \"ym\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-244067732*/count=1202; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(s2, b0);");
/*fuzzSeed-244067732*/count=1203; tryItOut("mathy3 = (function(x, y) { return ((( - Math.fround(Math.atan2(Math.fround(mathy0(Math.tanh(( + ( ~ 0x07fffffff))), Math.trunc(x))), Math.fround(( ! Math.fround(x)))))) & ( + Math.min(( + ( - (Math.fround((Math.fround(Math.exp(-Number.MAX_VALUE)) ? x : (Math.sinh(( + (y / x))) | 0))) >>> 0))), ( + (( + mathy2(Math.fround(2**53), x)) + ( + x)))))) | 0); }); testMathyFunction(mathy3, [2**53, 0.000000000000001, 0x100000001, -0x0ffffffff, 2**53-2, 0/0, 0x07fffffff, -0x080000001, 0x080000000, 2**53+2, -0x07fffffff, -0x080000000, -(2**53-2), 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, 0x100000000, 0, -0x100000000, -0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), 42, 0x0ffffffff, -(2**53), 0x080000001, 1, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1204; tryItOut("\"use strict\"; {/*RXUB*/var r = new RegExp(\"(?!\\\\b|$|\\\\b|\\\\S{3,4}?|\\\\1[^][^\\uaacd\\\\f-\\u00ff\\\\u00F9]+$)\", \"gym\"); var s = \"\\n\\uf324\"; print(uneval(s.match(r))); Array.prototype.sort.call(a2, f0); }");
/*fuzzSeed-244067732*/count=1205; tryItOut("/*RXUB*/var r = new RegExp(\"(?:.|\\\\W|${3,}{3}(?:\\\\u0033){0}|(\\\\B\\\\B*).{4,}(?:\\u6798)|(?![^])((?=[^])){0,4}){0}\", \"\"); var s = \"\"; print(uneval(s.match(r))); \nfunction shapeyConstructor(cidjeo){Object.freeze(this);delete this[\"has\"];Object.freeze(this);this[\"has\"] =  /* Comment */x;for (var ytqwjsdke in this) { }if (/./gym) delete this[\"cbrt\"];return this; }\n");
/*fuzzSeed-244067732*/count=1206; tryItOut("m2 = new WeakMap;");
/*fuzzSeed-244067732*/count=1207; tryItOut("/*tLoop*/for (let y of /*MARR*/[0x100000001, function(){}, function(){}, false, false, 0x100000001, function(){}, function(){}, 0x100000001, 0x100000001, false, false, false, 0x100000001, false, 0x100000001, 0x100000001, 0x100000001, false, 0x100000001, function(){}, 0x100000001, 0x100000001, 0x100000001, false, false, 0x100000001, false, false, false, false, false, false, false, false, function(){}, function(){}, function(){}, false, 0x100000001, 0x100000001, function(){}, function(){}, function(){}, function(){}, 0x100000001, false, 0x100000001, false, 0x100000001, false, function(){}, false, function(){}, function(){}, function(){}, false, 0x100000001]) { /*RXUB*/var r = new RegExp(\"(?=\\\\d)\", \"gym\"); var s = \"\"; print(s.replace(r, x, \"i\"));  }");
/*fuzzSeed-244067732*/count=1208; tryItOut("/*RXUB*/var r = /(?:(?!\\b\\1{3,}\\u4a8F|[^\\v]|[^\\B-\\u23C5]|[^].}*?)*)*?/m; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1209; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow(mathy3(((Math.pow((Math.pow(0, -(2**53-2)) >>> 0), (( + (( + x) || x)) >>> 0)) >>> 0) < Math.pow(( + x), y)), ( ! ( + Math.min(( + y), ( + Math.hypot(y, 1.7976931348623157e308)))))), mathy3(( ~ Math.imul(y, Math.atan2(( + Math.log1p((x >>> 0))), x))), ( ~ Math.sin(( + y))))); }); ");
/*fuzzSeed-244067732*/count=1210; tryItOut("print(x);");
/*fuzzSeed-244067732*/count=1211; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1212; tryItOut("e2.delete(b0);");
/*fuzzSeed-244067732*/count=1213; tryItOut("/*iii*/Object.defineProperty(this, \"this.v2\", { configurable: true, enumerable: [,],  get: function() {  return NaN; } });\nprint(27);\n/*hhh*/function xcwgbn(){for (var v of o1.t1) { a2[({valueOf: function() { o2 = {};return 11; }})] = (void shapeOf(x)); }}");
/*fuzzSeed-244067732*/count=1214; tryItOut("\"use strict\"; this.t1.toString = (function(j) { if (j) { try { ; } catch(e0) { } i0 + a2; } else { try { p1.toSource = (function() { e0.delete(v1); return o1.o2; }); } catch(e0) { } this.s1.__iterator__ = (function() { try { i0 = g2.objectEmulatingUndefined(); } catch(e0) { } print(b0); return a2; }); } });");
/*fuzzSeed-244067732*/count=1215; tryItOut("h1 = {};");
/*fuzzSeed-244067732*/count=1216; tryItOut("\"use strict\"; for(let e in []);throw x;");
/*fuzzSeed-244067732*/count=1217; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (/*FFI*/ff(((549755813888.0)), ((abs((~~(-7.555786372591432e+22)))|0)), ((+abs(((+(0x277bd18a)))))), ((imul(((function shapeyConstructor(flfhye){Object.defineProperty(this, \"assign\", ({configurable: false}));if (window) Object.freeze(this);for (var ytqlhfzah in this) { }this[ /x/g ] = [1];if (x) delete this[\"apply\"];Object.preventExtensions(this);this[\"callee\"] = new Boolean(true);return this; }.__defineGetter__(\"w\", (1 for (x in []))))), (i1))|0)), ((abs((((i0)+(!(0xffffffff))) >> (((0x44bbaa2f) ? (0xc15c8906) : (0xfa6175bf)))))|0)))|0);\n    }\n    i1 = ((+(-1.0/0.0)) < (-9.0));\n    i1 = (i0);\n    i0 = (0x60460d09);\n    i0 = (i0);\n    i1 = (i0);\n    return (((((7.555786372591432e+22)))))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 0x100000001, -0x080000001, -0x100000001, 2**53+2, Math.PI, 1, Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -(2**53+2), -Number.MAX_VALUE, -0x100000000, 0x100000000, 0.000000000000001, 2**53-2, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -0x080000000, -0, 0x080000000, 0x07fffffff, -(2**53), -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-244067732*/count=1218; tryItOut("[];");
/*fuzzSeed-244067732*/count=1219; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"o0.h2 = ({getOwnPropertyDescriptor: function(name) { for (var p in v0) { try { o2.f2.valueOf = (function() { for (var j=0;j<14;++j) { g0.g1.f1(j%2==0); } }); } catch(e0) { } try { for (var p in this.o0.b1) { g2.s1 = s0.charAt( '' ); } } catch(e1) { } try { a1 = Array.prototype.slice.apply(a0, [NaN, NaN, p1]); } catch(e2) { } e1.add(g0); }; var desc = Object.getOwnPropertyDescriptor(this.t0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { for (var v of f2) { this.s1.valueOf = (function mcc_() { var uookno = 0; return function() { ++uookno; if (/*ICCD*/uookno % 6 == 0) { dumpln('hit!'); x = m2; } else { dumpln('miss!'); for (var p in h1) { try { let v2 = evaluate(\\\"h1.toSource = (function(stdlib, foreign, heap){ \\\\\\\"use asm\\\\\\\";   var ff = foreign.ff;\\\\n  function f(i0, d1)\\\\n  {\\\\n    i0 = i0|0;\\\\n    d1 = +d1;\\\\n    return (((0xfe848e29)))|0;\\\\n    return (((i0)))|0;\\\\n  }\\\\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096));\\\", ({ global: o2.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 58 != 32), noScriptRval: true, sourceIsLazy: this, catchTermination: (x % 68 != 54) })); } catch(e0) { } try { b0.__iterator__ = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    (Float32ArrayView[4096]) = ((+(1.0/0.0)));\\n    (Uint32ArrayView[((0x6cc6c71f)) >> 2]) = ((~~(3.094850098213451e+26)) / (((0xbb6f7ee5)) << ((((!(-0x8000000)))>>>(-0x984e4*(i1))) % (((0x143e82b5) / (0x6f2dba23))>>>((0xe31de4ee)-(0xffffffff)+(0x87fd2bed))))));\\n    return +((Float64ArrayView[2]));\\n  }\\n  return f; }); } catch(e1) { } try { a1 = Array.prototype.slice.apply(a1, [NaN, NaN]); } catch(e2) { } e0.delete(b1); } } };})(); }; var desc = Object.getPropertyDescriptor(this.t0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(this, \\\"m0\\\", { configurable: true, enumerable: false,  get: function() {  return new Map; } });; Object.defineProperty(this.t0, name, desc); }, getOwnPropertyNames: function() { print(uneval(p1));; return Object.getOwnPropertyNames(this.t0); }, delete: function(name) { v0 = (g0 instanceof s0);; return delete this.t0[name]; }, fix: function() { this.a1[v1] = x;; if (Object.isFrozen(this.t0)) { return Object.getOwnProperties(this.t0); } }, has: function(name) { b0 = m2;; return name in this.t0; }, hasOwn: function(name) { for (var p in this.p1) { try { a2 = arguments; } catch(e0) { } Object.defineProperty(this, \\\"this.v2\\\", { configurable: false, enumerable: ({x: /\\u0089|[\\\\u08D3\\u001f-\\\\u9590]|(\\\\3\\uee3d^{1,1}([^\\\\x90-\\\\u0522\\\\r-\\ua819\\\\\\u36a0]A+))/gim }),  get: function() {  return evaluate(\\\"a2.reverse();\\\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: eval(\\\"/([\\\\\\\\r\\\\\\\\q-\\\\u00c0\\\\\\\\S\\\\u57a8])|(?!(?=[^]?|(?!$)))+/gim\\\", ((void 0))), noScriptRval: (4277).throw(x), sourceIsLazy: true, catchTermination: (x % 20 == 17) })); } }); }; return Object.prototype.hasOwnProperty.call(this.t0, name); }, get: function(receiver, name) { throw h2; return this.t0[name]; }, set: function(receiver, name, val) { print(this.b2);; this.t0[name] = val; return true; }, iterate: function() { for (var p in g0.s2) { try { g2.v2 = (b0 instanceof f1); } catch(e0) { } try { s1.toSource = (function() { e2.delete(t0); return b2; }); } catch(e1) { } v0 = evaluate(\\\"([] = (new (\\\\\\\"\\\\\\\\u08EC\\\\\\\")()) ? \\\\nc -= x : let (c = \\\\\\\"\\\\\\\\u202F\\\\\\\") true)\\\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 != 3), noScriptRval: false, sourceIsLazy: false, catchTermination: true })); }; return (function() { for (var name in this.t0) { yield name; } })(); }, enumerate: function() { m0.set(e0, this.f2);; var result = []; for (var name in this.t0) { result.push(name); }; return result; }, keys: function() { for (var v of h0) { try { /*ODP-3*/Object.defineProperty(i0, \\\"delete\\\", { configurable: true, enumerable: true, writable: false, value:  /x/g  }); } catch(e0) { } try { v0 = b2.byteLength; } catch(e1) { } try { v2 = a0.some((function() { for (var j=0;j<66;++j) { f2(j%2==0); } })); } catch(e2) { } /*MXX2*/o1.g1.String.prototype.lastIndexOf = b2; }; return Object.keys(this.t0); } });\");");
/*fuzzSeed-244067732*/count=1220; tryItOut("mathy4 = (function(x, y) { return (Math.pow(Math.fround(Math.max((((((x >>> 0) ? (x | 0) : ((( - Math.fround(y)) >>> 0) | 0)) | 0) | 0) | (Math.max((( + (y | 0)) | 0), x) | 0)), (2**53+2 >>> 0))), Math.fround(Math.fround(Math.acosh(Math.fround((0 <= y)))))) ? (((((Math.asin((Math.imul((Math.fround(y) == (y | 0)), x) >>> 0)) >>> 0) >>> 0) ? ((( - (mathy1(( + Math.hypot(( + Math.log(x)), y)), y) | 0)) | 0) >>> 0) : -0x080000001) ? (((Math.abs(y) >>> 0) <= ((Math.max(( - (0x0ffffffff >>> 0)), ( + y)) / (((2**53 >>> 0) ** x) >>> 0)) >>> 0)) | 0) : (((Math.trunc(y) , (y | 0)) | 0) >> Math.cbrt(Math.expm1(x)))) | 0) : ( ! Math.asin((mathy3((( + 0) | 0), Math.fround((mathy3((0 | 0), ((mathy3((Math.acosh(x) | 0), 0.000000000000001) | 0) | 0)) | 0))) | 0)))); }); testMathyFunction(mathy4, [0, -1/0, -Number.MIN_VALUE, -0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, 0x080000001, 2**53+2, -(2**53-2), Number.MIN_SAFE_INTEGER, 42, -0x080000000, -(2**53), 1, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, 0x080000000, 0x0ffffffff, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, -0x080000001, Math.PI, 0x100000000, 0x100000001, 2**53, -0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1221; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Math.PI, -Number.MAX_VALUE, 0x07fffffff, 2**53+2, 2**53, -0x100000001, -(2**53+2), 0x080000000, 1.7976931348623157e308, 0, 42, -0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53-2), -(2**53), -0, -0x080000000, Number.MIN_VALUE, 1, 1/0, -0x080000001, -0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, -Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=1222; tryItOut("");
/*fuzzSeed-244067732*/count=1223; tryItOut("\"use strict\"; e0.add(h2);");
/*fuzzSeed-244067732*/count=1224; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1225; tryItOut("v0 + '';");
/*fuzzSeed-244067732*/count=1226; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; selectforgc(this); } void 0; }");
/*fuzzSeed-244067732*/count=1227; tryItOut("selectforgc(o1);");
/*fuzzSeed-244067732*/count=1228; tryItOut("o0.s0 += 'x';yield ((function sum_indexing(szidlg, kguqsu) { \"\\u01B2\";; return szidlg.length == kguqsu ? 0 : szidlg[kguqsu] + sum_indexing(szidlg, kguqsu + 1); })(/*MARR*/[(void 0), new String(''), -(2**53+2), (void 0), -(2**53+2), undefined, -(2**53+2), new String(''), ({x:3}), ({x:3}), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, -(2**53+2), new String(''), ({x:3}), ({x:3}), undefined, (void 0), new String(''), undefined, new String(''), new String(''), -(2**53+2), new String(''), (void 0), new String(''), undefined, new String(''), new String(''), undefined, -(2**53+2), undefined, new String(''), new String(''), new String(''), undefined, -(2**53+2), undefined, ({x:3}), (void 0), new String(''), new String(''), (void 0), -(2**53+2), ({x:3}), undefined, undefined, -(2**53+2), -(2**53+2), undefined, undefined, ({x:3}), new String(''), undefined, (void 0), new String(''), (void 0), ({x:3}), new String(''), (void 0), ({x:3}), undefined, undefined, undefined, undefined, -(2**53+2), (void 0), undefined, ({x:3}), ({x:3}), undefined, ({x:3}), undefined, -(2**53+2), -(2**53+2), -(2**53+2), undefined, -(2**53+2), undefined, -(2**53+2), (void 0), ({x:3}), undefined, ({x:3}), ({x:3}), new String(''), undefined, (void 0), undefined, ({x:3}), new String(''), -(2**53+2), (void 0), new String(''), ({x:3}), (void 0), new String(''), new String(''), undefined, (void 0), -(2**53+2), -(2**53+2), ({x:3}), (void 0), -(2**53+2), undefined, (void 0), undefined, (void 0), ({x:3}), new String(''), -(2**53+2), (void 0), (void 0), undefined, (void 0), (void 0), new String(''), ({x:3}), ({x:3}), (void 0), undefined, ({x:3}), new String(''), ({x:3}), ({x:3}), new String(''), ({x:3}), ({x:3}), (void 0), ({x:3}), (void 0), new String(''), new String(''), new String(''), ({x:3}), new String(''), undefined, ({x:3}), ({x:3}), (void 0), new String(''), undefined, (void 0), ({x:3}), -(2**53+2), ({x:3}), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('')], 0));");
/*fuzzSeed-244067732*/count=1229; tryItOut("with((ArrayBuffer.prototype.slice).call(new let (b) [z1](((function factorial_tail(frmexo, leafsx) { ; if (frmexo == 0) { ; return leafsx; } ; return factorial_tail(frmexo - 1, leafsx * frmexo);  })(0, 1))), this.__defineGetter__(\"d\", function (e) { return 20 } ), /*FARR*/[null, ...[z1,,] if (z), ((Date.prototype.getHours).call(true, ))].filter(function(y) { yield y; ; yield y; })))/* no regression tests found */");
/*fuzzSeed-244067732*/count=1230; tryItOut("o0.a0 = arguments;");
/*fuzzSeed-244067732*/count=1231; tryItOut("\"use strict\"; /*infloop*/for(var /*UUV2*/(NaN.toTimeString = NaN.toString).d in Math.ceil(0.146)) {let w = \u3056 = Proxy.createFunction(({/*TOODEEP*/})(e), function (d = window) { print(this.p1); } , [,]);\u000dprint(w);with({w: /*UUV1*/(x.isExtensible = Array.prototype.find)})Object.seal(p1); }");
/*fuzzSeed-244067732*/count=1232; tryItOut("b0.valueOf = this.f0;");
/*fuzzSeed-244067732*/count=1233; tryItOut("{ void 0; void gc(); } v1 = g0.eval(\"Array.prototype.reverse.call(a2);\");");
/*fuzzSeed-244067732*/count=1234; tryItOut("v2 = new Number(NaN);");
/*fuzzSeed-244067732*/count=1235; tryItOut("\"use strict\"; p1.valueOf = (function mcc_() { var prqjjx = 0; return function() { ++prqjjx; f2(/*ICCD*/prqjjx % 6 == 4);};})();");
/*fuzzSeed-244067732*/count=1236; tryItOut("mathy5 = (function(x, y) { return Math.fround(( + Math.fround((mathy3(Math.fround(mathy4(Math.fround(Math.fround(mathy2((Math.fround(((Math.log10((y | 0)) | 0) < x)) << (( + (( + 2**53+2) << ( + 0x080000001))) - y)), (Math.acosh(y) | 0)))), Math.fround(Math.abs(( - -(2**53-2)))))), ( + Math.imul(( ~ Math.fround(mathy2(Math.fround(-Number.MAX_SAFE_INTEGER), Math.fround((( ! (x >>> 0)) | 0))))), Math.imul(((((x >>> 0) + (mathy2(y, ( + ( ~ y))) >>> 0)) >>> 0) >>> 0), (Math.sin(y) >>> 0))))) | 0)))); }); testMathyFunction(mathy5, [-(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, 42, 1, 2**53+2, 0x100000001, 1/0, -1/0, 0, -0x07fffffff, 0x07fffffff, -(2**53), 0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -0x080000001, 0.000000000000001, 2**53, 0/0, -0x100000000, -0, -0x100000001, -Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1237; tryItOut("Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-244067732*/count=1238; tryItOut("h0 = g1.objectEmulatingUndefined();");
/*fuzzSeed-244067732*/count=1239; tryItOut("f0 + '';");
/*fuzzSeed-244067732*/count=1240; tryItOut("for (var v of p2) { try { t0 + a0; } catch(e0) { } try { print(p2); } catch(e1) { } try { /*RXUB*/var r = r2; var s = s0; print(r.test(s));  } catch(e2) { } s0 += s1; }\nprint(-28);\n");
/*fuzzSeed-244067732*/count=1241; tryItOut("function shapeyConstructor(mvoupj){Object.freeze(mvoupj);mvoupj[\"call\"] = new x.round((function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ceil = stdlib.Math.ceil;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((((i1)-(i1))>>>(((0.015625) >= (-576460752303423500.0)))) >= (((i0)-(-0x8000000)-((-549755813887.0) == (562949953421313.0)))>>>(((i1) ? (this) : (i1))-((~(-((0xc2e52805))))))));\n    i1 = ((0x0) >= (((i1)+((imul(((140737488355327.0) == (-67108865.0)), (i0))|0))-(i0))>>>(((0xf4c57fc1)))));\n    i1 = (i0);\n    switch ((((Uint32ArrayView[((0xfe6b8bec)) >> 2])) ^ ((0x3af8c91a)-(0x8055ad8e)-(0x90eb94)))) {\n      case -3:\n        {\n          {\n            (Uint32ArrayView[1]) = ((0x4886f543) / (0xe902191b));\n          }\n        }\n        break;\n    }\n    {\n      i0 = (i1);\n    }\n    {\n      i1 = (i0);\n    }\n    return +((+ceil(((137438953473.0)))));\n    i0 = ((Float64ArrayView[((i0)) >> 3]));\n    i1 = (i0);\n    i1 = ((0x582826c1) != (((((!((0x7fffffff)))) ^ ((0x8c3a0161) % (0x0))) / (((0x5554dce6) % (0xba2c89b8)) ^ (((68719476737.0) < (1.001953125)))))>>>((((0x4046a3b9)+(0xf68839f6)-(0xfed5f6db))>>>((0x0) % (0xaea24a9e))) % (((0xf9ad2e36)+(0xf87f8e34)+(0x89706793))>>>(-(i1))))));\n    i1 = (0x724656c4);\nprint((x = Proxy.create(({/*TOODEEP*/})(null), window)));d = (this.__defineGetter__(\"w\", \"\\uE51B\".has));    i1 = (!(i1));\n    i0 = (i0);\n    return +((Float32ArrayView[4096]));\n  }\n  return f; }), (this.__defineSetter__(\"x\", new RegExp(\"(\\\\2)\", \"im\"))));if (/*FARR*/[new RegExp(\"[^]\", \"gym\"), -16,  /x/g ,  '' ,  /x/ , , mvoupj].sort(Math.floor)) mvoupj[(4277)] = offThreadCompileScript;return mvoupj; }/*tLoopC*/for (let b of /*MARR*/[(0/0), (0/0), Number.MIN_VALUE, Number.MIN_VALUE, x, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), x, x, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, x, (0/0), Number.MIN_VALUE, (0/0), (0/0), (0/0), x, (0/0), (0/0), (0/0), Number.MIN_VALUE, x, Number.MIN_VALUE, (0/0), (0/0), (0/0), Number.MIN_VALUE, x, x, x, x, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, (0/0), x, x, Number.MIN_VALUE, x, Number.MIN_VALUE, (0/0), Number.MIN_VALUE, (0/0)]) { try{let lkkogp = new shapeyConstructor(b); print('EETT'); p0.__proto__ = h0;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-244067732*/count=1242; tryItOut("\"use strict\"; neuter(b1, \"same-data\");");
/*fuzzSeed-244067732*/count=1243; tryItOut("a1 = o1.r0.exec(s0);");
/*fuzzSeed-244067732*/count=1244; tryItOut("h0 + '';");
/*fuzzSeed-244067732*/count=1245; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.min(( + (( + Math.atan2((( ~ (x | 0)) | 0), ( + ( - ( + (x >> mathy0(Number.MIN_SAFE_INTEGER, Math.fround(-0x080000001)))))))) != (y || mathy0(Math.fround(Math.fround(( + x))), (x | 0))))), ( + ( ! (mathy0(Math.fround(-Number.MAX_SAFE_INTEGER), (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [-0x100000001, -0x080000001, 0x0ffffffff, -0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), -Number.MIN_VALUE, 42, Number.MAX_VALUE, 1/0, 0x080000000, -(2**53), 0x07fffffff, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53, 0/0, -0x100000000, 2**53-2, 2**53+2, -0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, 0x100000001, -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=1246; tryItOut("{/*RXUB*/var r = r1; var s = s0; print(s.replace(r, eval = Proxy.createFunction(({/*TOODEEP*/})( /x/g ), function shapeyConstructor(gzzqno){gzzqno[\"-18\"] = function ([y]) { };gzzqno[\"-18\"] = {};gzzqno[\"0\"] = s;for (var ytqfxcihq in gzzqno) { }gzzqno[\"setPrototypeOf\"] = Uint8ClampedArray;if (gzzqno) gzzqno[\"-18\"] = (void 0);if (new RegExp(\"\\\\B(?:\\\\b$[^])|(?!$|\\\\B*?){4,4}\\\\B+?|\\\\b((?!\\\\d|[\\\\v-\\\\u9267]))*?[\\\\cX-\\\\\\u00b85-\\\\u4CA0\\uaa42-\\\\\\uc850\\\\D]?|[^]$|([^]|[^](?:\\\\B))(?![^])\", \"gi\")) Object.defineProperty(gzzqno, \"setPrototypeOf\", ({enumerable: (x % 2 == 0)}));return gzzqno; },  /x/ ), \"i\")); print(r.lastIndex);  }");
/*fuzzSeed-244067732*/count=1247; tryItOut("");
/*fuzzSeed-244067732*/count=1248; tryItOut("this.p1.valueOf = (function() { for (var j=0;j<2;++j) { f2(j%3==0); } });");
/*fuzzSeed-244067732*/count=1249; tryItOut("var t1 = new Int8Array(b0, 34, new RegExp(\"(?:$\\\\b*)[^](?:.)(?:[^])*[^\\\\s\\\\0\\u0998-\\\\\\u9a82]\\\\w?|(?:(?![^\\\\u0091-\\ubed3\\\\d\\\\cT-\\\\x6B\\\\x30-\\\\B])).|^+|(?:[^])+?|.[\\\\w\\\\s\\\\d\\\\d]{0,}+|\\\\B|\\\\u5F34(?!$){3,}\", \"m\"));/*\n*/t0[({valueOf: function() { g2.offThreadCompileScript(\"\\\"\\\\u90CA\\\";\");return 15; }})] = ({\u3056: (Math.cos(12))});");
/*fuzzSeed-244067732*/count=1250; tryItOut("print( /x/ );\ni0.__proto__ = t0;\n");
/*fuzzSeed-244067732*/count=1251; tryItOut("-25 = a2[2];");
/*fuzzSeed-244067732*/count=1252; tryItOut("\"use strict\"; h2 = ({getOwnPropertyDescriptor: function(name) { print(uneval(h0));; var desc = Object.getOwnPropertyDescriptor(g0.s1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { o0.t2.valueOf = g1.f0;; var desc = Object.getPropertyDescriptor(g0.s1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { let t1 = t1.subarray(3, v2);; Object.defineProperty(g0.s1, name, desc); }, getOwnPropertyNames: function() { throw t0; return Object.getOwnPropertyNames(g0.s1); }, delete: function(name) { m0.set(o2, p1);; return delete g0.s1[name]; }, fix: function() { Object.prototype.watch.call(f2, \"__iterator__\", (function() { try { s2 += s0; } catch(e0) { } try { h2.getOwnPropertyDescriptor = o0.f0; } catch(e1) { } try { e2.add(s1); } catch(e2) { } v2 = (p1 instanceof g1); return b0; }));; if (Object.isFrozen(g0.s1)) { return Object.getOwnProperties(g0.s1); } }, has: function(name) { b2 = t1.buffer;; return name in g0.s1; }, hasOwn: function(name) { v0 = Object.prototype.isPrototypeOf.call(o2, o2.s1);; return Object.prototype.hasOwnProperty.call(g0.s1, name); }, get: function(receiver, name) { s0 = Array.prototype.join.call(a0, s2, g2.o0.f1, t1);; return g0.s1[name]; }, set: function(receiver, name, val) { v0 = evalcx(\"function f2(m2)  \\\"\\\" .throw(((4277) = -19 != 3)).yoyo(x)\", g2);; g0.s1[name] = val; return true; }, iterate: function() { v2 = g2.eval(\"h2.enumerate = (function mcc_() { var mmzgpm = 0; return function() { ++mmzgpm; if (/*ICCD*/mmzgpm % 7 == 5) { dumpln('hit!'); try { this.t2[12] = o0.g1; } catch(e0) { } try { o2.__iterator__ = () => new (DataView.prototype.setInt8)((this.throw(this)\\u0009), [1,,]); } catch(e1) { } try { /*MXX2*/this.g2.Array.prototype.entries = f0; } catch(e2) { } o2.a0 + ''; } else { dumpln('miss!'); try { o1.o0.i0.__proto__ = t0; } catch(e0) { } try { /*RXUB*/var r = this.g2.r2; var s = \\\"\\\"; print(s.match(r)); print(r.lastIndex);  } catch(e1) { } v2 = g0.g2.eval(\\\"function o1.f2(this.s2)  { \\\\\\\"use strict\\\\\\\"; this.s2 += 'x'; } \\\"); } };})();\");; return (function() { for (var name in g0.s1) { yield name; } })(); }, enumerate: function() { this.g2.a0 = this.r2.exec(s2);; var result = []; for (var name in g0.s1) { result.push(name); }; return result; }, keys: function() { throw f0; return Object.keys(g0.s1); } });");
/*fuzzSeed-244067732*/count=1253; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1254; tryItOut("s2 = new String(g0);");
/*fuzzSeed-244067732*/count=1255; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.imul((Math.tan(Math.hypot(Math.fround(x), ( + Math.min((( ~ ((y , -(2**53)) >>> 0)) >>> 0), -0x100000000)))) ? Math.pow(Math.fround((Math.max((( + mathy1(-0x0ffffffff, ((x >> y) | 0))) >>> 0), ((( ! Math.fround(x)) === y) | 0)) | 0)), Math.fround(x)) : (mathy4((y >>> Math.fround(Math.atan2(Math.fround((Math.log2((0.000000000000001 | 0)) | 0)), Math.fround(x)))), Math.cbrt(-(2**53))) | 0)), ( - ((((( ! ((Math.imul((x >>> 0), (Math.atan2((Math.tan(( + -(2**53-2))) | 0), x) >>> 0)) >>> 0) | 0)) | 0) >>> 0) || (( ! 1) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, -(2**53-2), -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, 2**53, 0x080000000, 2**53+2, -0, 0, Number.MAX_VALUE, -0x080000000, 42, 0x080000001, -0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -0x0ffffffff, 0x100000000, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 0/0, -(2**53+2), 0.000000000000001, -1/0, 1, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1256; tryItOut("\"use strict\"; e2.has(e2);\nyield;\n");
/*fuzzSeed-244067732*/count=1257; tryItOut("Array.prototype.unshift.call(a1, p2);");
/*fuzzSeed-244067732*/count=1258; tryItOut("/*vLoop*/for (var hsurwz = 0; hsurwz < 67; ++hsurwz) { let b = hsurwz; print(b); } ");
/*fuzzSeed-244067732*/count=1259; tryItOut("m0.set(this.b0, this.t1);");
/*fuzzSeed-244067732*/count=1260; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-244067732*/count=1261; tryItOut("testMathyFunction(mathy3, [0, 0x080000001, 0x100000000, -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, -0x100000000, 0x0ffffffff, -(2**53-2), 2**53, 2**53-2, -Number.MIN_VALUE, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, 1/0, 42, -0x07fffffff, -0x080000001, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 0/0, -(2**53+2), -0x100000001, 1]); ");
/*fuzzSeed-244067732*/count=1262; tryItOut("/*vLoop*/for (cakakg = 0; cakakg < 26; ++cakakg) { let x = cakakg; print(this ? false :  '' .watch(\"z\", encodeURIComponent)); } ");
/*fuzzSeed-244067732*/count=1263; tryItOut("\"use strict\"; for (var v of o2) { try { let g0.v1 = evalcx(\"Array.prototype.forEach.apply(a2, [f2]);\", g0); } catch(e0) { } try { h1.fix = f0; } catch(e1) { } g2 + h2; }");
/*fuzzSeed-244067732*/count=1264; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, 1, 42, -0, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x0ffffffff, 0.000000000000001, 0x100000001, -0x07fffffff, 0, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), 2**53, 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, Math.PI, 0x080000001, -(2**53+2), 2**53+2, -0x080000000, 0x100000000, 0/0]); ");
/*fuzzSeed-244067732*/count=1265; tryItOut("\"use asm\"; testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, 0/0, 0x07fffffff, 2**53-2, 0x100000001, -0x100000001, -0x0ffffffff, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000000, 42, -0x080000001, -1/0, -0x100000000, Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, 2**53, 0x080000001, 1, 0x100000000, 2**53+2, 0, -0, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=1266; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.max((Math.fround(( ~ Math.fround(((( + x) + Math.fround(x)) | 0)))) | 0), ( ~ (Math.imul(Math.atan2(( + ((y - Number.MIN_SAFE_INTEGER) >>> Math.fround(x))), (( ! (y >>> 0)) >>> 0)), ((x || Math.pow((2**53 | 0), ((y ? x : y) | 0))) | 0)) | 0))) | 0) << ( + mathy0(( + Math.imul((Math.fround(Math.cbrt(y)) ? ((x << (Math.atan2(( + x), (((0/0 >>> 0) + (y >>> 0)) >>> 0)) >>> 0)) >>> 0) : (( - (( + Math.atan2(y, x)) >>> 0)) >>> 0)), Math.fround(Math.pow(Math.fround(( + Math.asinh(( + x)))), Math.fround(mathy0((x , y), 0/0)))))), ( + Math.fround(Math.hypot(Math.fround((Math.fround((Math.hypot((Math.min(x, (Math.max(y, (Number.MIN_SAFE_INTEGER | 0)) | 0)) >>> 0), Math.fround(( + y))) >>> 0)) === Math.fround(x))), Math.fround(x))))))); }); testMathyFunction(mathy1, [objectEmulatingUndefined(), (new Boolean(true)), undefined, (new String('')), 0.1, [], ({valueOf:function(){return '0';}}), false, '/0/', '', [0], /0/, (new Number(-0)), (function(){return 0;}), (new Number(0)), ({toString:function(){return '0';}}), true, '\\0', ({valueOf:function(){return 0;}}), null, (new Boolean(false)), NaN, '0', 0, 1, -0]); ");
/*fuzzSeed-244067732*/count=1267; tryItOut("p0 + '';");
/*fuzzSeed-244067732*/count=1268; tryItOut("\"use strict\"; a2[19];");
/*fuzzSeed-244067732*/count=1269; tryItOut(";Math;");
/*fuzzSeed-244067732*/count=1270; tryItOut("/*infloop*/ for (let w of \"\\uBBA0\") {v0.__iterator__ = (function mcc_() { var mlnpwg = 0; return function() { ++mlnpwg; if (false) { dumpln('hit!'); this.o0.o1 = o0.a0.__proto__; } else { dumpln('miss!'); try { a0.pop(o1.g1.f0, t2, t1, e2, o2.a1, s1); } catch(e0) { } this.s1 = ''; } };})();g0.v2 = r2.global; }");
/*fuzzSeed-244067732*/count=1271; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.abs(mathy0(( + ( + ( + ( + (( - Math.PI) && y))))), Math.imul(Math.fround((((-Number.MAX_VALUE === x) >>> 0) | 0)), x))); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x07fffffff, 0x100000001, 42, -(2**53+2), -1/0, 0x080000001, 0, 1, Number.MIN_SAFE_INTEGER, 0/0, Math.PI, -Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, -(2**53-2), 2**53-2, Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000000, 0x080000000, 2**53, 0.000000000000001, -0x100000000, -Number.MIN_VALUE, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53), -0, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1272; tryItOut("mathy4 = (function(x, y) { return Math.atan(mathy0((( ~ ( + mathy1((mathy2(x, x) >>> 0), ( + (y || ( + Math.fround((Math.fround(-(2**53-2)) ** Math.fround(y))))))))) >>> 0), (Math.sin(( + Math.ceil(( + ( + y))))) >>> 0))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 1, -1/0, 0x0ffffffff, -(2**53-2), 0/0, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000000, 42, 0x080000001, 1/0, 0, 0x100000000, -0x0ffffffff, 0.000000000000001, 2**53+2, Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, -0, 0x080000000, -(2**53), 2**53, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, 0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=1273; tryItOut("t0[({valueOf: function() { var a0 = a1.map(f2, o0, e2);return 13; }})] = e2;");
/*fuzzSeed-244067732*/count=1274; tryItOut("/*RXUB*/var r = (4277); var s = c; print(uneval(r.exec(s))); print(r.lastIndex); var this.a1 = Array.prototype.concat.call(a1, t0, t2, a0, g0.m2);");
/*fuzzSeed-244067732*/count=1275; tryItOut("\u3056 = (4277), NaN, x = /(?!$)*?[^](?!\\u03EB)(\\B)|(?:\\D)|\\0{1,1}{4}/gi !=  /x/ , x = (4277), w = new RegExp(\"(?=.|(?!$)+?){3}\", \"gyim\") !=  \"\" , e = false, e, NaN, w, dojlum;v0 = g1.runOffThreadScript();\nv1 = t1.BYTES_PER_ELEMENT;\n");
/*fuzzSeed-244067732*/count=1276; tryItOut("mathy3 = (function(x, y) { return ( + mathy2(((Math.cos(Math.sinh(x)) >>> 0) >>> 0), (((Math.max((( ! Math.atan2(-Number.MIN_VALUE, x)) | 0), (Math.fround((y ? -Number.MIN_VALUE : (mathy0(0x100000001, y) === (( ~ Math.fround(x)) | 0)))) | 0)) | 0) ? Math.pow(((( ! y) >>> 0) ? x : (Math.fround(Math.asin(( + x))) >>> 0)), Math.cosh((y | 0))) : (( + Math.fround((Math.fround((mathy1(0/0, x) >>> 0)) != Math.fround(Math.min(x, Math.fround((( + x) & Math.fround(x)))))))) | 0)) >>> 0))); }); testMathyFunction(mathy3, [2**53-2, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, 0x080000000, 2**53, -1/0, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), 42, 2**53+2, Number.MAX_VALUE, -0x080000000, Math.PI, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, 1, -0, -(2**53), 1/0, 0x100000001, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=1277; tryItOut("testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, -0x100000001, -(2**53+2), 2**53+2, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, 0x100000001, 42, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, 1, 0/0, 0x080000001, 1/0, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, -(2**53-2), 0x07fffffff, 1.7976931348623157e308, -0x07fffffff, -0, -(2**53), -1/0, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 2**53-2, -0x100000000]); ");
/*fuzzSeed-244067732*/count=1278; tryItOut("\"use strict\"; m2.toString = (function() { try { f1 = Proxy.createFunction(this.h2, f2, f0); } catch(e0) { } try { /*ODP-1*/Object.defineProperty(v2, \"3\", ({})); } catch(e1) { } try { v2 = evalcx(\"a1.reverse();\", g2); } catch(e2) { } t2 + ''; throw g0.f0; });");
/*fuzzSeed-244067732*/count=1279; tryItOut("\"use strict\"; x = f0;");
/*fuzzSeed-244067732*/count=1280; tryItOut("\"use strict\"; /* no regression tests found */\na0.sort((function() { for (var j=0;j<2;++j) { f1(j%2==0); } }), b0);\n");
/*fuzzSeed-244067732*/count=1281; tryItOut("mathy3 = (function(x, y) { return ( ! ( + Math.log(Math.hypot((( - (Math.clz32(42) | 0)) | 0), mathy0(( + x), Math.imul(( + ((x < y) | 0)), Math.cos(x))))))); }); testMathyFunction(mathy3, [0x100000001, -1/0, 0x100000000, 1/0, 2**53+2, -(2**53+2), -0x100000001, 1, -0x07fffffff, -(2**53), 2**53, 0.000000000000001, -Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, 0x080000001, -0, -Number.MIN_SAFE_INTEGER, 42, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, -(2**53-2), -Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1282; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh(((Math.asin(y) < (y ? Math.acosh((-0 | 0)) : (Math.tanh(Math.fround(Math.max(Math.fround(y), y))) | 0))) | 0)); }); testMathyFunction(mathy0, [Math.PI, 0x100000001, -Number.MAX_VALUE, 0x080000000, 2**53+2, 2**53-2, -0x07fffffff, -0x0ffffffff, -(2**53-2), 0x0ffffffff, 1/0, -(2**53), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, 42, 0x100000000, -0x080000000, 1, -0x100000000, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -0x100000001, 0x080000001, Number.MIN_VALUE, 0/0, 2**53, -0]); ");
/*fuzzSeed-244067732*/count=1283; tryItOut("var tdhilu, tupjyh, cjtuze, d = (4277), xrnzwb, NaN, x = (e => \"use asm\"; x = Proxy.createFunction(({/*TOODEEP*/})(18), /*wrap1*/(function(){ g1 = g1.objectEmulatingUndefined();return  /x/g })(), Object.prototype.toLocaleString)  var pow = stdlib.Math.pow;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (-((+pow(((2147483649.0)), ((-2.3611832414348226e+21))))));\n    {\n      {\n        d0 = (((d0)) - ((d0)));\n      }\n    }\n    return +((d0));\n  }\n  return f;)( /x/g , window);o1 = new Object;");
/*fuzzSeed-244067732*/count=1284; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.log2(((Math.pow(Math.fround(mathy0(2**53+2, Math.fround((( + ((((-Number.MIN_VALUE | 0) ** ((x == (y >>> 0)) | 0)) | 0) | 0)) | 0)))), ( ~ (0x0ffffffff >= (x | 0)))) | 0) | 0)) >>> 0); }); testMathyFunction(mathy1, [1/0, -(2**53), 0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, 1, 2**53-2, Math.PI, 2**53, 0x100000000, 2**53+2, 0x07fffffff, 0, 0/0, 42, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -(2**53-2), -1/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, -0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, -0x100000001, Number.MIN_VALUE, -0x0ffffffff, -0x080000000, 0.000000000000001, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=1285; tryItOut("\"use strict\"; b2 = new ArrayBuffer(8);/*RXUB*/var r = r0; var s = s0; print(r.test(s)); ");
/*fuzzSeed-244067732*/count=1286; tryItOut("a2.pop(i2, (allocationMarker()), v2);");
/*fuzzSeed-244067732*/count=1287; tryItOut("this.o2.a1 = m1.get(e0);");
/*fuzzSeed-244067732*/count=1288; tryItOut("/*hhh*/function yampns(){f2 = x;}/*iii*/ for (let y of false) this.e0.has((Math.pow(0, 28)));\nv1 = (this.e0 instanceof h1);\n");
/*fuzzSeed-244067732*/count=1289; tryItOut("g0.offThreadCompileScript(\"(x);\");function eval(x, x) { yield c-- } i0 + '';");
/*fuzzSeed-244067732*/count=1290; tryItOut("m2.get(h0);");
/*fuzzSeed-244067732*/count=1291; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0/0, 1/0, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 0x07fffffff, -(2**53), 0x0ffffffff, 0x080000001, 0x100000001, 2**53+2, 0x100000000, 2**53, 1, -Number.MIN_VALUE, -0x0ffffffff, -0x080000000, 42, Number.MAX_VALUE, Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, 2**53-2, -0x100000001, 0, 0.000000000000001, -0x07fffffff, -0]); ");
/*fuzzSeed-244067732*/count=1292; tryItOut("/*oLoop*/for (var wlndkz = 0, x; wlndkz < 51; ++wlndkz) { /* no regression tests found */ } ");
/*fuzzSeed-244067732*/count=1293; tryItOut("mathy0 = (function(x, y) { return Math.atanh(((Math.fround(( + ((Math.max((x | 0), ((0x100000000 >> (1.7976931348623157e308 >>> 0)) | 0)) >>> 0) % (y | 0)))) , (0x100000000 - x)) < ( ~ Math.imul(y, ( + Math.round(( + ( + x)))))))); }); testMathyFunction(mathy0, [1, -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, 0x100000000, 2**53+2, -0x080000000, 2**53-2, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -0x080000001, 0x07fffffff, Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -0x100000001, 0/0, 0x100000001, 0, Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, 1/0, 0x080000000, -Number.MIN_VALUE, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 42, -Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-244067732*/count=1294; tryItOut("mathy3 = (function(x, y) { return ( - (( ~ ( + 1)) , ((Math.max((y > Math.hypot(y, y)), (y >>> 0)) >= Math.fround(Math.hypot((Math.pow(Math.fround(( + (y | 0))), (Math.max(y, x) >>> 0)) >>> 0), Math.fround(((x ? (x | 0) : x) | 0))))) | 0))); }); testMathyFunction(mathy3, [0x080000001, 0.000000000000001, 0x100000001, -Number.MIN_VALUE, -0x080000000, 0/0, -(2**53+2), 2**53, 2**53-2, 2**53+2, -0x080000001, -0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -(2**53-2), Number.MAX_VALUE, 0x100000000, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -1/0, 1, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, -Number.MAX_VALUE, -0x100000001, 0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=1295; tryItOut("(/*FARR*/[(function ([y]) { })(), \"\\u69B9\", window, function ([y]) { }, ...[]].filter(eval));");
/*fuzzSeed-244067732*/count=1296; tryItOut("m1.set(a1, h2);");
/*fuzzSeed-244067732*/count=1297; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -262145.0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = -65536.0;\n    var i6 = 0;\n    switch ((imul((((((i3))))), (i3))|0)) {\n      case -1:\n        d5 = (d1);\n        break;\n      case -1:\n        i6 = (0xa47118be);\n      case -2:\n        i3 = ((0xd2f332fb));\n        break;\n      default:\n        {\n          d0 = (4095.0);\n        }\n    }\n    {\n      (Float64ArrayView[((i3)-(((d2)))) >> 3]) = ((-(((d2) + (((d1)) / (((arguments.callee.prototype))))))));\n    }\n    d2 = (+(0x6f8a3f53));\n    return (((0xfa7a9c7b)-(/*FFI*/ff(((~~(1.888946593147858e+22))), ((-129.0)))|0)-((0xe0bc4b26) != (((0xfaf8a09)-(i3))>>>((0xfde7b1d2)*0x6bd50)))))|0;\n  }\n  return f; })(this, {ff:  /x/ }, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=1298; tryItOut("t0.toSource = (function(j) { if (j) { try { M:if((x % 29 != 15)) {m0.has(g2);(\"\\u8223\"); } else  if (x) return this;\n/*vLoop*/for (let qolsfa = 0; qolsfa < 21; ++qolsfa) { const z = qolsfa; return new RegExp(\"[\\\\s\\u04bf9-\\\\\\u00b7\\\\S]|(?=[^]*)+\", \"y\"); } \n } catch(e0) { } try { for (var p in this.p0) { try { this.v2 = g0.eval(\"Object.defineProperty(this, \\\"o2.t0\\\", { configurable: (x % 5 == 2), enumerable: false,  get: function() {  return t1.subarray(19); } });m2.get(i0);\"); } catch(e0) { } print(uneval(g1.o2)); } } catch(e1) { } try { print(uneval(g0.h0)); } catch(e2) { } /*MXX2*/o1.g2.Promise.reject = o1; } else { try { v0 = g0.runOffThreadScript(); } catch(e0) { } o1.a2.toSource = String.prototype.bold.bind(v2); } });");
/*fuzzSeed-244067732*/count=1299; tryItOut("");
/*fuzzSeed-244067732*/count=1300; tryItOut("\"use strict\"; Array.prototype.pop.call(a0);");
/*fuzzSeed-244067732*/count=1301; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xf99685e9);\n    d0 = (d0);\n    d0 = (-36893488147419103000.0);\n    return +((d0));\n  }\n  return f; })(this, {ff: Date.parse}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53-2), -0x0ffffffff, 0/0, 2**53, 1.7976931348623157e308, -Number.MAX_VALUE, 1/0, 0x080000001, -0x07fffffff, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), -0x100000000, 0x080000000, -0, -1/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -0x080000000, Number.MAX_VALUE, -0x100000001, Math.PI, 0x100000001, 0.000000000000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, 42, 0, 0x07fffffff, 1]); ");
/*fuzzSeed-244067732*/count=1302; tryItOut("for(let x in []);");
/*fuzzSeed-244067732*/count=1303; tryItOut("v1 = a2.some((function() { try { b0 = a1[7]; } catch(e0) { } /*RXUB*/var r = o1.r1; var s = s0; print(s.search(r));  return t1; }), p2, this.o2.e1, h0, o2);");
/*fuzzSeed-244067732*/count=1304; tryItOut("mathy1 = (function(x, y) { return (( ! (mathy0(( + (((x | 0) != (-(2**53-2) >>> 0)) >>> 0)), ((mathy0(Math.fround(y), Number.MAX_SAFE_INTEGER) >>> 0) !== x)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, -(2**53+2), 1/0, 1, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, 42, 2**53+2, -0, 0.000000000000001, Math.PI, 0, 2**53, 2**53-2, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), -Number.MIN_VALUE, -0x080000001, 0x07fffffff, 0x0ffffffff, 0x100000001, Number.MIN_VALUE, 0x080000000, 0x080000001, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=1305; tryItOut("testMathyFunction(mathy1, /*MARR*/[-12, -12, null, objectEmulatingUndefined(), function(){}, -12, null, -12, -12,  '' , function(){}, objectEmulatingUndefined(), -12, objectEmulatingUndefined(), objectEmulatingUndefined(), null,  '' , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, null, null, -12, function(){}, -12, objectEmulatingUndefined(),  '' ,  '' ,  '' , objectEmulatingUndefined(), function(){},  '' , -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, -12, function(){}, objectEmulatingUndefined(), -12, function(){},  '' , null, objectEmulatingUndefined(),  '' , objectEmulatingUndefined(), function(){}, null, null,  '' , objectEmulatingUndefined(),  '' , objectEmulatingUndefined(),  '' ,  '' , -12, -12, function(){}, objectEmulatingUndefined(), function(){}, function(){}, null, function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, -12, objectEmulatingUndefined(), null, function(){},  '' , null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, -12, null, function(){},  '' , -12, null,  '' , objectEmulatingUndefined(),  '' ,  '' , objectEmulatingUndefined(), null, function(){}]); ");
/*fuzzSeed-244067732*/count=1306; tryItOut("\"use strict\"; var nakzco = new ArrayBuffer(4); var nakzco_0 = new Uint32Array(nakzco); print(nakzco_0[0]);");
/*fuzzSeed-244067732*/count=1307; tryItOut("for (var p in p1) { try { Array.prototype.unshift.call(a2, g0, m0, f1, x, v0); } catch(e0) { } try { s1 += 'x'; } catch(e1) { } try { print(f0); } catch(e2) { } p0 + ''; }selectforgc(o0);");
/*fuzzSeed-244067732*/count=1308; tryItOut("/*RXUB*/var r = new RegExp(\"(?:.|\\\\x0B|([^])\\\\B[^]+?*+)|\\\\1*(?!(?:(?:[^])))((?:(?=(\\\\2))))|\\\\W[^\\\\uAA79\\\\W\\\\d]\\\\B.\\\\S*?\\\\B{0}\\\\W{2,}((?=\\\\b))\\\\ubeAF?+\", \"im\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-244067732*/count=1309; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (mathy0(( + mathy0(((( ! ((Math.hypot(x, Math.fround(Math.atan(Math.fround(y)))) ? x : x) | 0)) | 0) >>> 0), ( - x))), Math.fround((mathy0(y, ( + Math.tanh(Math.fround((Math.fround(-0x100000000) ? (( + ((y | 0) == (-0x07fffffff | 0))) >>> 0) : x))))) >>> Math.fround(Math.max((-(2**53+2) >>> 0), (Number.MAX_SAFE_INTEGER / Math.min(2**53, (Math.pow(y, x) >>> 0)))))))) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[false, false, false, function(){}, false, false, (1/0), false, false, false, function(){}, false, false, false, function(){}, (1/0), function(){}, (1/0), function(){}, function(){}, (1/0), (1/0), (1/0), false, function(){}, (1/0), function(){}, (1/0), false, (1/0), (1/0), (1/0), false, false, false, false, function(){}, function(){}, function(){}, function(){}, false, false, (1/0), function(){}, false, false, (1/0), (1/0), (1/0), function(){}, (1/0), false, (1/0), function(){}, function(){}, (1/0), function(){}, false, (1/0), function(){}, function(){}, function(){}, (1/0), (1/0), function(){}, (1/0), (1/0), function(){}, false, (1/0), (1/0), false, function(){}, (1/0), function(){}, false, false, false, (1/0), false, (1/0), (1/0), (1/0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, false, false, function(){}, false, false, function(){}, false, (1/0), (1/0), (1/0), (1/0), false, (1/0), (1/0), false, false, function(){}, (1/0), function(){}, function(){}, false, (1/0), (1/0), (1/0), (1/0), false, false, false, false, (1/0), function(){}, function(){}]); ");
/*fuzzSeed-244067732*/count=1310; tryItOut("testMathyFunction(mathy2, [-0, 0x07fffffff, 0, 0.000000000000001, 0x080000001, -0x100000000, -0x080000000, -(2**53), -0x100000001, Math.PI, 0x100000000, 1, -0x0ffffffff, 2**53-2, 1.7976931348623157e308, 42, -0x080000001, -1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 0/0, 2**53, Number.MIN_VALUE, 1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-244067732*/count=1311; tryItOut("x = new RegExp(\".|\\\\b|(?!\\\\S)\\\\cI*\", \"im\"), a, lolzzc, x, x, lgrmxa, d;v0 = Object.prototype.isPrototypeOf.call(p2, t1);");
/*fuzzSeed-244067732*/count=1312; tryItOut("a1 = a1.map((function() { for (var j=0;j<14;++j) { f2(j%3==0); } }));");
/*fuzzSeed-244067732*/count=1313; tryItOut("testMathyFunction(mathy5, [0/0, -0x0ffffffff, 1/0, 2**53+2, -0, -0x080000000, 0x080000001, 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 42, 2**53-2, -0x100000000, 0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1, -0x100000001, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), -0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, Math.PI, -1/0, 1.7976931348623157e308, 2**53, 0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1314; tryItOut("\"use asm\"; const e = (4277);v2 = a2.length;");
/*fuzzSeed-244067732*/count=1315; tryItOut("mathy4 = (function(x, y) { return Math.hypot(Math.fround(Math.sign(mathy2(( + Math.fround((y * x))), ((Math.log2((x >>> 0)) >>> 0) - ( + mathy0(( + x), x)))))), Math.trunc(Math.fround((( + Math.trunc(( - -0))) & Math.fround(Number.MIN_VALUE))))); }); testMathyFunction(mathy4, [1/0, 0.000000000000001, 2**53-2, 2**53, 2**53+2, 0x080000000, 0x07fffffff, 0x100000001, -0, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -(2**53+2), 0, 0x080000001, -(2**53-2), 1.7976931348623157e308, -(2**53), -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, 42, -Number.MAX_VALUE, 1, -0x080000001, 0/0, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, Math.PI, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1316; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.fround((mathy3(Math.fround(Math.fround((Number.MIN_VALUE % Math.fround(mathy3(((Math.sqrt((x >>> 0)) >>> 0) && x), Math.min(y, y)))))), ( + Math.hypot(y, ( ~ Math.max(mathy2((x - ( + y)), Math.fround(Math.pow(y, -0x0ffffffff))), 0x100000001))))) >>> 0)), Math.fround(Math.pow(Math.clz32((( ! (y >>> 0)) >>> 0)), Math.cbrt((( + ( - ( + Math.fround(((y >>> 0) ? Math.fround(y) : x))))) | 0))))); }); testMathyFunction(mathy4, [1, -0x0ffffffff, 2**53+2, -(2**53-2), -(2**53), -0x07fffffff, Number.MAX_VALUE, 0/0, 0.000000000000001, Math.PI, -(2**53+2), -0x100000000, -Number.MAX_VALUE, -0x080000001, 0x080000001, Number.MIN_VALUE, -0x100000001, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x07fffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0, 0x080000000, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53, 1/0, -0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1317; tryItOut("\"use asm\"; testMathyFunction(mathy1, [1.7976931348623157e308, -0, 0x080000000, 42, 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x0ffffffff, -1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1, 0x100000001, 2**53-2, -Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, 2**53, Number.MIN_VALUE, -(2**53), 0x0ffffffff, 0.000000000000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), -0x080000000, 0, 1/0, -0x080000001]); ");
/*fuzzSeed-244067732*/count=1318; tryItOut("t0 = new Uint8Array(b2);");
/*fuzzSeed-244067732*/count=1319; tryItOut("\"use strict\"; a1.forEach((function() { try { g1.offThreadCompileScript(\"\\\"use strict\\\"; /*bLoop*/for (gngksi = 0; gngksi < 51; ++gngksi) { if (gngksi % 3 == 2) { print([,,]); } else { print(x); }  } \", ({ global: this.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (4277), noScriptRval: (e =>  { yield \"\\u2932\" } ).call( \"\" , this, undefined).abs(new (function  x (a, x) { yield new RegExp(\"(?:\\\\B)\", \"m\") } )(/(?=(?=\\s)+?.[\\d\\B-\u6269]{1,}[^])|[^]|(?=(\\B|(?![^\\D\\u00d4-\\xcC\\w])?)+?)/gym, /\\2/g), x), sourceIsLazy: true, catchTermination: (x) = this })); } catch(e0) { } try { let v1 = a1.length; } catch(e1) { } try { print(uneval(e2)); } catch(e2) { } o0 + t0; return a1; }), this.a0, h0, g0.v0, o2.o0);");
/*fuzzSeed-244067732*/count=1320; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[(1/0), new Number(1), ({}), (1/0), new Number(1), new Number(1), (1/0), new Number(1), ({}), new Number(1), ({}), (1/0), new Number(1), (1/0), ({}), ({}), (1/0), new Number(1), new Number(1), (1/0), (1/0), ({}), new Number(1), (1/0), (1/0), new Number(1), (1/0), new Number(1), new Number(1), new Number(1), new Number(1), ({}), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (1/0), (1/0), ({}), ({}), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new Number(1), new Number(1), (1/0), (1/0), ({}), (1/0), new Number(1), new Number(1), (1/0), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (1/0), new Number(1), (1/0), ({}), (1/0), (1/0), new Number(1), ({}), new Number(1), new Number(1), new Number(1), new Number(1), (1/0), new Number(1), (1/0), (1/0), ({}), ({}), new Number(1), new Number(1), new Number(1), (1/0), ({}), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (1/0), new Number(1), (1/0), ({}), ({}), (1/0), new Number(1), (1/0), new Number(1), (1/0), ({}), (1/0), new Number(1), ({}), new Number(1), (1/0), new Number(1), ({}), (1/0), new Number(1), (1/0), (1/0), new Number(1)]) { for([e, b] = () in NaN) {v1 = true;a1.__proto__ = e0; } }");
/*fuzzSeed-244067732*/count=1321; tryItOut("\"use strict\"; /*MXX2*/g0.String.prototype.link = i1;/* no regression tests found */");
/*fuzzSeed-244067732*/count=1322; tryItOut("/*hhh*/function lldenv(x, \u3056){/*MXX1*/o1 = g2.Array.from;}/*iii*//*infloop*/for(let b in x) /*RXUB*/var r = /(?=(\\B{0,})|\\B\\xca|\\d|\\D{3,}(?:.\\D)*?|.*?)+?/gim; var s = /(?=(?=^)*?){4,8}/gyim; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1323; tryItOut("/*infloop*/for(let b = window; this; 10) {print(-16);print(x); }");
/*fuzzSeed-244067732*/count=1324; tryItOut("/*infloop*/for(b; z = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: (1 for (x in [])), enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(z), encodeURI,  /x/ .raw); (4277)) Object.defineProperty(this, \"v0\", { configurable: false, enumerable: true,  get: function() {  return evalcx(\"t0 = new Int8Array(a0);\", g1); } });");
/*fuzzSeed-244067732*/count=1325; tryItOut("\"use strict\";  \"\" ");
/*fuzzSeed-244067732*/count=1326; tryItOut("\"use strict\"; throw undefined;");
/*fuzzSeed-244067732*/count=1327; tryItOut("\"use asm\"; testMathyFunction(mathy3, [0x080000000, Math.PI, 0/0, -(2**53), 1/0, 2**53+2, -0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), 42, -0x100000001, -0x0ffffffff, Number.MAX_VALUE, 0, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, -0x080000000, 2**53-2, -0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, 2**53, 1, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1328; tryItOut("\"use strict\"; b1 + this.v1;");
/*fuzzSeed-244067732*/count=1329; tryItOut("a0.splice(8, 6);");
/*fuzzSeed-244067732*/count=1330; tryItOut("mathy1 = (function(x, y) { return ((Math.max(Math.fround(( + Math.pow(( + Math.fround((Math.fround(y) && Math.fround(Math.PI)))), y))), (((y ** ( - (Math.sqrt(( + -0x07fffffff)) >>> 0))) | 0) | 0)) | 0) & ( + Math.imul(((mathy0(Math.fround(Math.imul(Math.fround(x), y)), ((Math.log((( + x) ? Math.fround(y) : mathy0(y, -0x07fffffff))) >>> 0) >>> 0)) >>> 0) | 0), ( + 0.000000000000001)))); }); testMathyFunction(mathy1, [2**53, -1/0, 1, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, 0x100000000, -0, Number.MIN_VALUE, 0x07fffffff, -0x080000001, -0x080000000, -0x0ffffffff, 0x100000001, 0/0, 2**53+2, -0x07fffffff, -(2**53), -0x100000000, -(2**53-2), 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, -0x100000001, 0x080000001, 0x080000000, Math.PI, 1.7976931348623157e308, 1/0]); ");
/*fuzzSeed-244067732*/count=1331; tryItOut("testMathyFunction(mathy0, [0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, -0, 0x080000000, -(2**53-2), 0/0, -0x100000001, 1/0, -0x07fffffff, -0x080000001, Number.MAX_VALUE, 0, -0x0ffffffff, -0x100000000, 0x07fffffff, -0x080000000, 0x080000001, 0x100000000, -1/0, 2**53-2, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, Math.PI, 42]); ");
/*fuzzSeed-244067732*/count=1332; tryItOut("with({c: Set.prototype.keys})s2 = Array.prototype.join.call(o2.a0, s2);v1.toSource = (function() { for (var j=0;j<67;++j) { f1(j%5==1); } });");
/*fuzzSeed-244067732*/count=1333; tryItOut("i0.send(a0);");
/*fuzzSeed-244067732*/count=1334; tryItOut("i1 + s2;");
/*fuzzSeed-244067732*/count=1335; tryItOut("mathy4 = (function(x, y) { return Math.fround(( + Math.fround(( ~ (( - ( ~ (Math.cos(Math.PI) | 0))) | 0))))); }); testMathyFunction(mathy4, [-0x100000000, 0, -Number.MIN_VALUE, -(2**53), 0/0, -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, -0x0ffffffff, 1/0, Math.PI, 2**53-2, 2**53+2, 1, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, 0x080000001, -1/0, 0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, 2**53, -0x080000000]); ");
/*fuzzSeed-244067732*/count=1336; tryItOut("\"use strict\"; Array.prototype.push.apply(a2, [m2]);");
/*fuzzSeed-244067732*/count=1337; tryItOut("\"use strict\"; g0.v1 = (o1 instanceof i0);");
/*fuzzSeed-244067732*/count=1338; tryItOut("mathy2 = (function(x, y) { return Math.cbrt(Math.cbrt((Math.hypot(((Math.atan2(( + Math.hypot(Math.fround(y), mathy1(y, 1))), (x >>> 0)) >>> 0) | 0), (Math.sqrt(Math.imul(-0x100000001, 1.7976931348623157e308)) | 0)) | 0))); }); testMathyFunction(mathy2, [0/0, Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, -1/0, 42, -(2**53), 0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1, -0x0ffffffff, -0x100000000, 1.7976931348623157e308, Math.PI, -(2**53-2), -0, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, -0x080000001, 0.000000000000001, 0x07fffffff, 2**53+2, 0x100000000, -(2**53+2), 2**53-2, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1339; tryItOut("((yield  /x/ ));");
/*fuzzSeed-244067732*/count=1340; tryItOut("v0 = g2.eval(\"x\");");
/*fuzzSeed-244067732*/count=1341; tryItOut("/*vLoop*/for (nmbrin = 0; nmbrin < 64; ++nmbrin) { b = nmbrin; /*RXUB*/var r = r2; var s = s0; print(s.match(r));  } ");
/*fuzzSeed-244067732*/count=1342; tryItOut("v2 = o0.g1.runOffThreadScript();");
/*fuzzSeed-244067732*/count=1343; tryItOut("b1 + '';");
/*fuzzSeed-244067732*/count=1344; tryItOut("\"use strict\"; /*hhh*/function aiqpvs(x){print(undefined);}/*iii*/(/\\uEc23+|.^/gyim);");
/*fuzzSeed-244067732*/count=1345; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[arguments.callee, (1/0), arguments.callee, (1/0), arguments.callee, (1/0), (1/0), arguments.callee, (1/0), (1/0), arguments.callee, arguments.callee, arguments.callee, (1/0), (1/0), (1/0), arguments.callee, (1/0), arguments.callee, (1/0), arguments.callee, arguments.callee, (1/0), (1/0), (1/0), (1/0), (1/0), arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee]) { /*tLoop*/for (let b of /*MARR*/[-0x0ffffffff, -0x0ffffffff, (1/0)]) { print(a); } }");
/*fuzzSeed-244067732*/count=1346; tryItOut("i0.next();\nprint(Math.expm1( \"\" ));\n");
/*fuzzSeed-244067732*/count=1347; tryItOut("/*vLoop*/for (var jimsqp = 0; jimsqp < 47; ++jimsqp) { let e = jimsqp; o2.t1 = new Float32Array(6);/*iii*/new RegExp(\"(?![^]|(?=.^)(?!${4,}){3,}?)\", \"gim\") **=  '' ;/*hhh*/function sygyyl(NaN,  , NaN, z, a, x, x, a, NaN =  \"\" , NaN, e, e, NaN = undefined, x, c, y){print(x);} } ");
/*fuzzSeed-244067732*/count=1348; tryItOut("switch(new eval()) { case 2: t0[({valueOf: function() { yield;return 6; }})] = v1;break; a2[4] = [];break; default: break;  }");
/*fuzzSeed-244067732*/count=1349; tryItOut("this.g0.m0.set(e2, m1);");
/*fuzzSeed-244067732*/count=1350; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.1805916207174113e+21;\n    i1 = (i1);\n    d0 = (NaN);\n    d0 = (+atan2(((d0)), (((let (e=eval) e)).call((void options('strict')), ))));\n    i1 = ((((0x4672510c))>>>((void options('strict_mode')))));\n    {\n      return (((0x49b5460)-((Float64ArrayView[(((i1))-(0x371231af)+(0x90c11302)) >> 3]))))|0;\n    }\n    return (((((!((((0x1b39e65)) ^ ((0xc5250edb))) > (((0xb02177b8)) >> ((0xfa193c95)))))+((d0) < (d0))-(i1))>>>(((((d0)))))) / (0x7fca5f5d)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, 0x100000001, -0x100000001, 0/0, -(2**53-2), -0x0ffffffff, 0x07fffffff, 2**53-2, -1/0, 0x080000001, -0x080000001, 0x0ffffffff, 0x080000000, -(2**53+2), Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 0, -0x100000000, Math.PI, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 42, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -(2**53), Number.MIN_SAFE_INTEGER, 2**53, -0, 1, -0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1351; tryItOut("/*infloop*/for(let arguments.callee.caller.arguments in (/*UUV1*/(b.atanh = function (e) { \"use strict\"; return -2 } )))  \"\"  <= x;\nprint(x);\n");
/*fuzzSeed-244067732*/count=1352; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2{2}|(?=(?!\\\\d*?)|(?=(?:[^\\u965f\\\\v-\\\\u00Ac\\\\u00F9].)))*?\", \"i\"); var s = \"\\u3819\\u3819\\u3819\\u3819\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1353; tryItOut("testMathyFunction(mathy3, /*MARR*/[0x080000000, (-1/0), 0x080000000, 0x080000000, (-1/0), 0x080000000, (-1/0), 0x080000000, (-1/0), 0x080000000, 0x080000000, 0x080000000, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), 0x080000000, (-1/0), (-1/0), 0x080000000, (-1/0), 0x080000000, 0x080000000, function(){}, 0x080000000, function(){}, function(){}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), function(){}, 0x080000000, function(){}, (-1/0), 0x080000000, function(){}, (-1/0), 0x080000000, 0x080000000, 0x080000000, function(){}, 0x080000000, (-1/0), function(){}, function(){}, (-1/0), (-1/0), function(){}, 0x080000000, function(){}, 0x080000000, 0x080000000, function(){}, 0x080000000, 0x080000000, function(){}, (-1/0), function(){}, (-1/0), (-1/0), function(){}, function(){}, (-1/0), (-1/0), (-1/0), 0x080000000, 0x080000000, (-1/0), 0x080000000, (-1/0), function(){}, 0x080000000, 0x080000000, 0x080000000, 0x080000000, function(){}, function(){}, (-1/0), (-1/0), 0x080000000, function(){}, (-1/0), 0x080000000, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (-1/0), (-1/0), 0x080000000, 0x080000000, function(){}, (-1/0), 0x080000000, (-1/0), function(){}, 0x080000000, (-1/0), (-1/0), 0x080000000, function(){}, (-1/0), (-1/0), (-1/0), function(){}, (-1/0), 0x080000000, (-1/0), (-1/0)]); ");
/*fuzzSeed-244067732*/count=1354; tryItOut("mathy0 = (function(x, y) { return (Math.fround((Math.imul((( + ( ~ ( + Math.cosh(-0)))) >>> 0), ((( ! ( + Math.log2(y))) >>> 0) + ((Math.cosh(-Number.MAX_SAFE_INTEGER) | 0) | 0))) >>> 0)) == ((((( ~ ((2**53+2 | 0) == (y ? Number.MIN_VALUE : y))) >>> 0) + ((Math.asinh(((y ? ( ~ (Math.atan2(y, x) >>> 0)) : (1/0 >> 0x080000000)) >>> 0)) >>> 0) | 0)) | 0) | 0)); }); testMathyFunction(mathy0, ['\\0', null, 0.1, false, (new Boolean(false)), '/0/', 0, -0, '', [], (new Boolean(true)), true, (new Number(0)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), undefined, NaN, 1, (function(){return 0;}), '0', /0/, (new String('')), [0], ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-244067732*/count=1355; tryItOut("\"use strict\"; this.v2 = Object.prototype.isPrototypeOf.call(f0, v1);");
/*fuzzSeed-244067732*/count=1356; tryItOut("var meazdo = new SharedArrayBuffer(0); var meazdo_0 = new Uint8ClampedArray(meazdo); print(meazdo_0[0]); return /./gyi;a1.unshift();o0.g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination:  /x/g  }));for (var p in p2) { try { t2.set(a2, v0); } catch(e0) { } try { m2.delete(p0); } catch(e1) { } try { Array.prototype.pop.apply(o2.a0, [f1]); } catch(e2) { } this.f2 = (function mcc_() { var mxqwmd = 0; return function() { ++mxqwmd; if (/*ICCD*/mxqwmd % 7 == 4) { dumpln('hit!'); try { a0 = Array.prototype.map.apply(o0.a1, [f2, this.f2, v1, b0]); } catch(e0) { } try { v1 = evaluate(\"function f1(h2)  { return window } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  \"\" , noScriptRval: (x % 4 != 3), sourceIsLazy:  '' , catchTermination: new RegExp(\"\\\\2?\", \"gm\") })); } catch(e1) { } try { o2.toString = (function() { try { a0.sort(); } catch(e0) { } s2 += s0; throw b2; }); } catch(e2) { } v1 = null; } else { dumpln('miss!'); try { t2 = new Float32Array(b1, 12, 5); } catch(e0) { } try { a1.shift(g1, i0, a1, g1.g0.o1, o1, v0, s2, new RegExp(\"(?:(\\\\r))\", \"gm\")); } catch(e1) { } f0.valueOf = (function() { try { o2.s1 = Proxy.create(h2, i0); } catch(e0) { } try { this.i0.send(g1); } catch(e1) { } o2.v2 = t0.length; return e2; }); } };})(); }");
/*fuzzSeed-244067732*/count=1357; tryItOut("v2 = undefined;");
/*fuzzSeed-244067732*/count=1358; tryItOut("\"use strict\"; v1 = t1.length;");
/*fuzzSeed-244067732*/count=1359; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy1(( + (Math.sqrt((Math.fround(( ! 2**53-2)) | 0)) | 0)), Math.fround(Math.max((Math.cosh(Math.cos(( + ( - y)))) | 0), ((((Math.fround(Math.hypot(Math.fround(Math.imul(x, -0x080000000)), (((y | 0) !== (( ~ y) === -0)) | 0))) >>> 0) >>> (-0x080000001 >>> 0)) >>> 0) >>> 0)))) >>> 0); }); testMathyFunction(mathy2, [0, 2**53+2, 0/0, Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -0, Math.PI, -1/0, 1/0, 2**53, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1, -0x07fffffff, -Number.MIN_VALUE, 2**53-2, 0x07fffffff, 0x100000001, 0.000000000000001, -(2**53), 1.7976931348623157e308, -(2**53+2), -0x100000000, -0x080000000, 0x080000001, 0x080000000, 0x100000000, Number.MAX_VALUE, 42]); ");
/*fuzzSeed-244067732*/count=1360; tryItOut("mathy5 = (function(x, y) { return ((((Math.acos(Math.fround((( + (x >>> 0)) >>> 0))) >> mathy3(Math.fround(Math.hypot(( + y), ( ~ x))), mathy0(Math.hypot(x, y), Math.fround((y & Math.fround(x)))))) ? ((( ~ ( ! (Math.asin((x | 0)) | 0))) ? Math.max(y, 0x080000000) : y) >>> 0) : Math.fround(Math.acos(Math.fround((((Math.clz32(-0x100000001) | 0) && (Math.clz32(x) | 0)) | 0))))) | 0) ? (( + Math.fround(((y ? y : (Number.MIN_SAFE_INTEGER ? (y | 0) : (y | 0))) || Math.fround(Math.round(Math.fround(Math.max((mathy4(y, (1 << y)) >>> 0), y))))))) >>> 0) : ( ~ (( + mathy0(( + (mathy1(((( + x) >>> 0) >>> 0), Math.round((x ** (( ~ -(2**53-2)) | 0)))) >>> 0)), ( + ( + Math.max(((mathy1((x | 0), ( + ( + (0x080000000 ? ( + y) : Math.fround((( + (y >>> 0)) >>> 0)))))) >>> 0) >>> 0), ( + Math.fround(Math.imul(2**53-2, (x | 0))))))))) | 0))); }); testMathyFunction(mathy5, [0x100000001, -1/0, 0.000000000000001, 0x080000000, 0/0, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53+2), -(2**53), -0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, 0, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 1/0, 2**53, -0x100000001, -0, -0x100000000, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, -(2**53-2), 0x07fffffff, 1, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-244067732*/count=1361; tryItOut("s0 += this.s1;");
/*fuzzSeed-244067732*/count=1362; tryItOut("\"use strict\"; Array.prototype.pop.call(a1, m0, o0, o0);");
/*fuzzSeed-244067732*/count=1363; tryItOut("\"use strict\"; ");
/*fuzzSeed-244067732*/count=1364; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.log1p(((( ! ((Math.sin(((( + (( + x) * ( + (( ! y) | 0)))) | 0) * Math.fround(Math.fround(Math.acos((y >>> 0)))))) >>> 0) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 1.7976931348623157e308, 1/0, -0x100000000, -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, -(2**53), -(2**53+2), 0/0, 0, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 42, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 1, -1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, Math.PI, 0x080000001, -0, 0x07fffffff, -0x080000000, 0.000000000000001, -0x100000001, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1365; tryItOut("for([c, b] = (new ((\"\u03a0\".unwatch(\"1\")))( /x/ )) in new 24()) \n{{ void 0; void relazifyFunctions(this); } }");
/*fuzzSeed-244067732*/count=1366; tryItOut("g2.v2 = (p2 instanceof f2);");
/*fuzzSeed-244067732*/count=1367; tryItOut("mathy1 = (function(x, y) { return (Math.imul(Math.fround(Math.imul(Math.fround(Math.fround(( + ( + Math.max(( + x), ( + Math.ceil(( + y)))))))), Math.fround(( + (((y << (( + -(2**53-2)) >>> 0)) >>> 0) - 0x080000000))))), Math.cos(Math.fround(( ! Math.fround(( + Math.sqrt(x))))))) >>> 0); }); testMathyFunction(mathy1, [0x0ffffffff, -(2**53-2), Math.PI, 2**53+2, 2**53-2, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -0x07fffffff, 0x100000001, 1.7976931348623157e308, -0x080000000, 0x100000000, 42, -1/0, -0, 0, 0.000000000000001, 0/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), 2**53, 0x080000000]); ");
/*fuzzSeed-244067732*/count=1368; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! Math.fround(Math.sign((mathy2(((( + Math.atan2(( + x), ( + ((Math.pow((x | 0), (x | 0)) | 0) ? Math.trunc(y) : y)))) + ( + y)) >>> 0), (2**53+2 >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-(2**53), -Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, 2**53-2, 0/0, -0x100000000, 0, -0x0ffffffff, -0x07fffffff, 0x0ffffffff, 0x080000001, 0x080000000, -1/0, Math.PI, -0x080000000, 0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53+2, -0, 0.000000000000001, 1, Number.MAX_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -0x080000001, 42, -0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1369; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-244067732*/count=1370; tryItOut("v1 = a2[v2];");
/*fuzzSeed-244067732*/count=1371; tryItOut("a1.reverse();");
/*fuzzSeed-244067732*/count=1372; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min((Math.hypot(Math.hypot(Math.cosh(x), Math.tanh(x)), ( + mathy4(Math.fround(Math.imul(Math.fround(0.000000000000001), Math.fround(Math.cbrt(-0)))), Math.max(Math.sin((Math.pow((x | 0), (y | 0)) | 0)), mathy3(x, Math.fround(( ! y))))))) >>> 0), (Math.hypot((Math.hypot(( ~ (( + y) | 0)), Math.fround((Math.atan((y | 0)) | 0))) | 0), Math.max(Math.fround(mathy0(Math.fround(Math.trunc(y)), Math.fround(y))), (-0x100000001 | 0))) | 0)); }); testMathyFunction(mathy5, [2**53, 42, 0x080000001, -1/0, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -0x07fffffff, -(2**53-2), -0x0ffffffff, -0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, Math.PI, 0x100000000, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, -0x080000001, -0x080000000, 0, 2**53+2, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, -0, 1/0, 2**53-2, -0x100000001]); ");
/*fuzzSeed-244067732*/count=1373; tryItOut("mathy3 = (function(x, y) { return Math.fround(((Math.log2(mathy1(( + Math.max(Math.fround(mathy0(x, Math.log2(x))), ( - (y != -(2**53))))), ( + mathy0(Math.fround((Math.fround(y) >= Math.fround(x))), Math.fround(Math.max(0x080000001, Math.fround(-(2**53-2)))))))) | 0) ^ (Math.abs((((Math.hypot(( + Math.imul(Math.fround((Math.fround(2**53) >>> Math.fround(x))), (y - y))), ( + (( ! (((x | 0) === ( + -0x0ffffffff)) | 0)) | 0))) >>> 0) === (Math.fround(Math.sinh(Math.fround(( ! y)))) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy3, [2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 2**53, 0x080000000, 0x080000001, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, -0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, 1, 42, -0x100000001, -(2**53+2), 0x100000000, 0x0ffffffff, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, 0x07fffffff, 2**53-2, 0x100000001, 0, -0, -1/0]); ");
/*fuzzSeed-244067732*/count=1374; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(b2, i1);");
/*fuzzSeed-244067732*/count=1375; tryItOut("Array.prototype.push.call(a1, v1);");
/*fuzzSeed-244067732*/count=1376; tryItOut("print(x <= a);");
/*fuzzSeed-244067732*/count=1377; tryItOut("/*RXUB*/var r = new RegExp(\"((?:[^\\\\ub3F5]|$\\\\B?)|\\\\w+{2,}\\\\2{0,})\", \"gyi\"); var s = \"\\u834f\\u834f\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1378; tryItOut("const v0 = g2.runOffThreadScript();");
/*fuzzSeed-244067732*/count=1379; tryItOut("\"use strict\"; e2.has(g1.i2);\n\n");
/*fuzzSeed-244067732*/count=1380; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(g0.a0, Math.cos(-21), ({get: x.isSealed}));");
/*fuzzSeed-244067732*/count=1381; tryItOut("for (var p in p1) { p1.__proto__ = o1; }");
/*fuzzSeed-244067732*/count=1382; tryItOut("\"use strict\"; a2.push(i0, e1);");
/*fuzzSeed-244067732*/count=1383; tryItOut("\"use strict\"; (void schedulegc(g0));");
/*fuzzSeed-244067732*/count=1384; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\".|\\\\cT++|(?=(?:\\\\2))|$(?:\\\\B)\\\\S+\\\\B+?{4}|(?!(\\\\b){0})|(?:.)+\\\\2\\ubd1d*\", \"gyi\"); var s = \"\\u3819\\u5859\\u5859\\u5859\"; print(r.test(s)); ");
/*fuzzSeed-244067732*/count=1385; tryItOut("\"use strict\"; /*hhh*/function stakxb(d = (4277), x){/*tLoop*/for (let y of /*MARR*/[objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), null, new Number(1.5), null, new Number(1.5), objectEmulatingUndefined(), null, new Number(1.5), null, new Number(1.5), null, null, objectEmulatingUndefined(), null, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, new Number(1.5), null, new Number(1.5), null, objectEmulatingUndefined(), null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), null, new Number(1.5), new Number(1.5), new Number(1.5), null, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, null, null, null, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5)]) { print((4277)); }}stakxb(this, ({x: null}));");
/*fuzzSeed-244067732*/count=1386; tryItOut("Array.prototype.reverse.call(a0);");
/*fuzzSeed-244067732*/count=1387; tryItOut("mathy4 = (function(x, y) { return (Math.abs((( - ((Math.round(((0x080000000 >>> 0) ^ (Math.cos(1.7976931348623157e308) >>> 0))) | 0) << ( ~ Math.round(y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -(2**53+2), 1/0, -0, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, -0x100000000, Math.PI, 42, 2**53, -0x100000001, 1, 2**53+2, -(2**53), 0x100000000, 0x07fffffff, -0x080000000, -0x080000001, -Number.MIN_VALUE, 0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 0, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, -(2**53-2), 0/0, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1388; tryItOut("\"use strict\"; m0.get(g0);");
/*fuzzSeed-244067732*/count=1389; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.min(((( + ( + ( + (Math.cbrt((Math.fround(Math.min(Math.fround(Math.log2(x)), y)) >>> 0)) >>> 0)))) || ( + ( ~ ( + -(2**53-2))))) | 0), (Math.fround(Math.sign(Math.fround((Math.fround(( + mathy0(( + y), ( + y)))) ? Math.fround((mathy0((( ! (0x080000000 ? ( + (Math.fround(1.7976931348623157e308) != -Number.MAX_VALUE)) : (x >>> 0))) >>> 0), ( + Math.abs((x | 0)))) >>> 0)) : ( + Math.abs(( + y))))))) | 0)) | 0); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -0, Math.PI, 0x0ffffffff, -0x0ffffffff, 2**53-2, 2**53, -(2**53-2), 1/0, -0x07fffffff, -0x100000001, -0x100000000, 0x100000001, 0x080000001, -0x080000001, -(2**53+2), 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -0x080000000, 0.000000000000001, 2**53+2, -1/0, -(2**53), 0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, -Number.MAX_VALUE, 42, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1390; tryItOut("mathy4 = (function(x, y) { return Math.imul((( + Math.log2(( + ( + (( + Math.min(Math.fround(Math.pow(Math.PI, y)), Math.fround(Math.fround((Math.fround(-Number.MIN_SAFE_INTEGER) % x))))) ? ( + Math.min(Math.trunc(x), -Number.MIN_VALUE)) : ( + y)))))) < mathy2(( + (Number.MIN_VALUE ? ( + 1/0) : ( + 1/0))), (((y | 0) ? (Math.max(Math.log1p(x), ( + -(2**53))) | 0) : ( + ( + (x | ( + (Math.hypot((Math.max(y, -0x080000000) >>> 0), (x >>> 0)) >>> 0)))))) | 0))), ((((Math.fround(Math.acosh((Math.asin(-0x080000000) | 0))) >>> 0) ? (Math.imul(( + Math.trunc(( + (mathy3(0x100000000, (y | 0)) | 0)))), (Math.acos(Math.fround(Math.tanh((( + x) % 2**53-2)))) | 0)) >>> 0) : (( ! 0x100000000) >>> 0)) >>> 0) | 0)); }); ");
/*fuzzSeed-244067732*/count=1391; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.log((( ~ Math.fround((Math.fround((mathy1((( ~ y) | 0), ((Math.fround(Math.atan2(Math.fround(Math.log1p(y)), Math.fround(( ! y)))) - x) | 0)) | 0)) ? Math.fround(Math.imul((x === Math.hypot(mathy2(y, y), x)), Math.fround(x))) : Math.fround(( ! (Math.sqrt((Math.fround(( + y)) >>> 0)) >>> 0)))))) | 0)); }); testMathyFunction(mathy3, [1.7976931348623157e308, 0/0, -0x080000001, 1, 0x100000000, -1/0, 2**53-2, Number.MAX_SAFE_INTEGER, 2**53, -0, -(2**53+2), 0x07fffffff, -(2**53-2), -Number.MIN_VALUE, 0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), -0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -0x080000000, 42, 0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x0ffffffff, 0, 2**53+2, 0x080000001, Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1392; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy4(Math.sqrt(((( ~ (0x080000001 >>> 0)) >>> 0) | 0)), ( - ((x && ( + (((Math.log10((( + -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0) / ((((y | 0) === ((Math.hypot(((mathy3((x >>> 0), (0x07fffffff >>> 0)) >>> 0) >>> 0), ( + ( ! ( + x)))) >>> 0) | 0)) | 0) | 0)) >>> 0))) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=1393; tryItOut("s0.__proto__ = f0;");
/*fuzzSeed-244067732*/count=1394; tryItOut("const d = ( /x/g \n);/*infloop*/for(var  '' .x in (((let (e=eval) e))(((x) = this)))){o1.m2 = x; }");
/*fuzzSeed-244067732*/count=1395; tryItOut("h1.enumerate = f1;");
/*fuzzSeed-244067732*/count=1396; tryItOut("this.h2.getOwnPropertyNames = f0;");
/*fuzzSeed-244067732*/count=1397; tryItOut("a2 = arguments;function a(x, ...x)new RegExp(\".(?:(?:\\\\W))|[^]\", \"i\")t1.set(a1, 6);");
/*fuzzSeed-244067732*/count=1398; tryItOut(";for (var p in m2) { try { e2.add(e2); } catch(e0) { } try { a0[v1] = g2; } catch(e1) { } try { g1.i0 = m1.get(f1); } catch(e2) { } f0 = Proxy.createFunction(h0, f1, f0); }");
/*fuzzSeed-244067732*/count=1399; tryItOut("/*RXUB*/var r = /(?!\\3)|(?:([^]|[^\\w]+?))|.|\\B|(?=\\b)*?(\\w){1}(?:\\B[^\\cM\\t-\u1110]{3}+?|(\\d)\\b){32}+/y; var s = \"\\u0095ss\\u0095ssa\\u698711\\n a1 \\n\\u345a y\\u0095ss\\u0095ssa\\u698711\\n a1 \\n\\u345a y\\u0095\\u1111\\u0095\\u1111a\\u8ff4 \\u0095\\u1111\\u0095\\u1111\\u0095ss\\u0095ssa\\u698711\\n a1 \\n\\u345a y\\u0095ss\\u0095ssa\\u698711\\n a1 \\n\\u345a y\\u0095ss\\u0095ssa\\u698711\\n a1 \\n\\u345a y\\u0095ss\\u0095ssa\\u698711\\n a1 \\n\\u345a y\\u0095ss\\u0095ssa\\u698711\\n a1 \\n\\u345a y\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-244067732*/count=1400; tryItOut("var cdbiba = new ArrayBuffer(6); var cdbiba_0 = new Uint32Array(cdbiba); cdbiba_0[0] = 18; t0 = new Uint32Array(2);a2.sort((function mcc_() { var viscox = 0; return function() { ++viscox; if (/*ICCD*/viscox % 6 == 4) { dumpln('hit!'); try { o0.a0.reverse(); } catch(e0) { } try { v0 = g1.eval(\"length\"); } catch(e1) { } this.s1 += s0; } else { dumpln('miss!'); a1.splice(); } };})(), o1.f0);");
/*fuzzSeed-244067732*/count=1401; tryItOut("m0.has(v2);");
/*fuzzSeed-244067732*/count=1402; tryItOut("for (var v of a1) { try { v2 = Object.prototype.isPrototypeOf.call(s2, f1); } catch(e0) { } for (var v of o1) { try { s0 + h1; } catch(e0) { } try { x = t1[2]; } catch(e1) { } try { h0.keys = f1; } catch(e2) { } Object.defineProperty(this, \"v2\", { configurable: true, enumerable: /*FARR*/[window, ].some(Function, new (decodeURIComponent)(this)),  get: function() {  return evaluate(\"\\\"use asm\\\"; var bfybdu = new SharedArrayBuffer(2); var bfybdu_0 = new Float32Array(bfybdu); print(bfybdu_0[0]); bfybdu_0[0] = -26; var bfybdu_1 = new Uint32Array(bfybdu); var bfybdu_2 = new Int8Array(bfybdu); bfybdu_2[0] = 23; print(false);window;{}\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: (makeFinalizeObserver('nursery')) })); } }); } }");
/*fuzzSeed-244067732*/count=1403; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ~ Math.hypot((mathy1((( ~ (x >>> 0)) | 0), (mathy1(Math.fround(((y | 0) ? Math.fround(y) : Math.fround(x))), y) >>> 0)) | 0), Math.fround(Math.pow(y, Math.fround(y))))) ? Math.asinh((Math.atan2(Math.fround(mathy3((Math.log(y) ? x : (( + y) !== (y >>> 0))), y)), mathy1(Math.atan2(y, -Number.MIN_SAFE_INTEGER), ( + Math.log2(( + Math.tanh(y)))))) | 0)) : Math.imul((-(2**53+2) >= (x >>> 0)), (mathy4(Math.sqrt(y), (( + Math.fround(Math.fround(Math.imul(Math.fround(1), x)))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=1404; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.hypot(( + Math.trunc(( + ( + Math.cosh((x >>> 0)))))), ( ! ((((( + Math.log10((mathy0((x >>> 0), (y >>> 0)) >>> 0))) << ((Math.min(x, -0x080000001) ^ y) >>> 0)) | 0) ? (y | 0) : Math.cosh(y)) >>> 0))); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 0x0ffffffff, 0, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, -(2**53+2), -(2**53), -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, -1/0, 0x080000001, 2**53+2, 2**53-2, 0x080000000, 42, 1.7976931348623157e308, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, 0x100000001, -0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), 0/0, -0x100000001, 2**53, 0.000000000000001, -0x100000000, -0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1405; tryItOut("mathy4 = (function(x, y) { return ((mathy3(Math.min(( ~ (Math.imul((x | 0), (-0x080000001 | 0)) | 0)), x), Math.imul(Math.hypot(( + Math.sin(y)), (Math.round(-0x0ffffffff) | 0)), Math.fround(mathy3((Math.cbrt(Math.max(x, Math.pow(-(2**53+2), y))) >>> 0), (Math.sinh(((2**53+2 > y) >>> 0)) >>> 0))))) >>> 0) % ((Math.acosh(mathy1(Math.fround(Math.fround(Math.atan2((Math.fround(Math.pow((x ? x : y), ( + mathy2(x, ( + y))))) | 0), Math.fround(x)))), Math.fround(( + ( + y))))) >>> 0) & (Math.log10(Math.fround(Math.ceil(((( + x) >>> 0) >>> 0)))) >>> 0))); }); testMathyFunction(mathy4, [0x080000001, -(2**53+2), 1, 0, 1.7976931348623157e308, 0.000000000000001, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x100000000, -(2**53), -0x100000001, -0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, 42, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, 0x07fffffff, 2**53-2, 2**53+2, -0x0ffffffff, 2**53, -0x080000000, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1406; tryItOut("\"use strict\"; print(o0.v2);");
/*fuzzSeed-244067732*/count=1407; tryItOut("e0.has(b2);");
/*fuzzSeed-244067732*/count=1408; tryItOut("\"use strict\"; if(b, z, \u3056, NaN, window, c, x, window, y, y, NaN, x, x, x, e, x = window, eval, x, e, x = this, eval) {print(x); } else  if ( /x/ ) print(/(?:[^]|$*?)*\\b|(?=(\\D|\\2+|[^]))/im);\n\n");
/*fuzzSeed-244067732*/count=1409; tryItOut("/*RXUB*/var r = new RegExp(\"(?![^])\", \"yim\"); var s = (void shapeOf(new RegExp(\"(?:^|\\\\1**)+?(?!\\\\S)\", \"gy\"))); print(s.search(r)); print(r.lastIndex); throw undefined;s2 += 'x';");
/*fuzzSeed-244067732*/count=1410; tryItOut("var umgazz = new ArrayBuffer(0); var umgazz_0 = new Int16Array(umgazz); t2.set(a1, 9);( '' );x = g2.s1;");
/*fuzzSeed-244067732*/count=1411; tryItOut("27;");
/*fuzzSeed-244067732*/count=1412; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.tan((Math.pow((((Math.atan2(Math.fround(mathy1((Math.acos(( + y)) >>> 0), Math.fround(-0x100000001))), 1/0) >>> 0) ? ( + (x ** x)) : ((Math.tanh((y | 0)) >>> 0) != y)) >>> 0), ((Math.asin(( + Math.fround(( ! Math.fround((x , ( + -0x0ffffffff))))))) | 0) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[x, x, new String(''), x, new String(''), x, new String(''), x, new String(''), x, x, x, x, new String(''), x, new String(''), x, x, x, x, x, x, new String(''), new String(''), x, new String(''), x, x, new String(''), new String(''), x, x, new String(''), x, x, x, new String(''), x, x, x, x, x, x, x, x, x, x, new String(''), x, new String(''), x, x, x, x, new String(''), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String(''), x, new String(''), x, new String(''), new String(''), x, new String(''), new String(''), new String(''), x, x, x, new String(''), new String(''), new String(''), x, x, x, new String(''), new String(''), x, x, x, new String(''), x, new String(''), new String(''), x, x, new String(''), new String(''), x, new String(''), new String(''), new String(''), x, new String(''), x, new String(''), x, x, x]); ");
/*fuzzSeed-244067732*/count=1413; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ! (( + Math.ceil((( ! x) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, -0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53), -1/0, 1, 42, 2**53-2, Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, -0x07fffffff, 0x100000001, -(2**53-2), -Number.MAX_VALUE, -0x080000000, -0x100000000, -Number.MIN_VALUE, 0.000000000000001, 2**53+2, 0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 0, 1/0, 0x07fffffff, -0x0ffffffff, 2**53, -0, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-244067732*/count=1414; tryItOut("\"use strict\"; v1 = (a0 instanceof b0);");
/*fuzzSeed-244067732*/count=1415; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=1416; tryItOut("\"use strict\"; /*RXUB*/var r = /$|\ubb1c+(?!(?=(?:\\s\ud40d)+)(.*)\\3){4,}/gi; var s = \"\\ubb3c\\uaec6\\ubb3c\\uaec6\\ubb3c\\uaec6\\ubb3c\\uaec6\\ubb3c\\uaec6\\ubb3c\\uaec6\\n\\n\\ubb3c\\uaec6\\ubb3c\\uaec6\\ubb3c\\uaec6\"; print(s.search(r)); ");
/*fuzzSeed-244067732*/count=1417; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x080000001, -Number.MIN_VALUE, 42, -0x0ffffffff, 0, 1/0, 0x100000001, -0x080000000, 1.7976931348623157e308, -0x07fffffff, -1/0, -0x100000001, 0x080000001, 0x080000000, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 0.000000000000001, -0, 2**53-2, 0x07fffffff, 0/0, 1, 2**53, 2**53+2, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1418; tryItOut("mathy0 = (function(x, y) { return (((( + Math.imul(Math.clz32((Math.max(y, Number.MAX_VALUE) / Math.exp((Math.log1p((-(2**53-2) >>> 0)) >>> 0)))), ( + (( ! (Math.acosh(Math.fround(y)) | 0)) | 0)))) | 0) * (Math.tanh((((Math.fround((Math.atan2(0x100000001, ( - 1.7976931348623157e308)) >>> 0)) !== Math.fround(Math.fround(Math.atan2(( + Math.atan2(y, ( + 0.000000000000001))), Math.fround(( + Math.fround(x))))))) >>> 0) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy0, [-0x100000000, -0x0ffffffff, 0, -0, -Number.MAX_VALUE, Math.PI, -1/0, 2**53+2, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 2**53-2, 2**53, -0x100000001, 0x100000001, 0/0, Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 42, 0x100000000, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -(2**53+2), 1, 0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1419; tryItOut("\"use strict\"; print(y);let y = [z1,,];");
/*fuzzSeed-244067732*/count=1420; tryItOut("\"use strict\"; var nkxrdq, z = 29, d, x, kbgtdy, ezckwu, d;for (var p in a2) { try { for (var v of i0) { try { o2 = i0.__proto__; } catch(e0) { } try { /*MXX2*/g0.Date.prototype.getUTCHours = g0.p0; } catch(e1) { } try { Object.freeze(s0); } catch(e2) { } this.o2.e2.has(v1); } } catch(e0) { } try { var this.g1.s0 = m0.get(g1.h2); } catch(e1) { } g2.o0.h2.toSource = (function() { try { a1 = []; } catch(e0) { } t0.set(t1, window); throw v0; }); }");
/*fuzzSeed-244067732*/count=1421; tryItOut("\"use asm\"; a0 = a2.filter(f2);");
/*fuzzSeed-244067732*/count=1422; tryItOut("/*oLoop*/for (wbvfem = 0; wbvfem < 0; ++wbvfem) { this.t1.toSource = f0; } ");
/*fuzzSeed-244067732*/count=1423; tryItOut("mathy1 = (function(x, y) { return (Math.min(( + Math.tan(x)), mathy0(x, (( + ( - ((((x | 0) + 0) | 0) >>> 0))) % ( + ( ~ Math.atan2((x >>> 0), (x >>> 0))))))) === (((Math.hypot(((y >>> 0) % (( + y) | 0)), ((y != ( + x)) < Math.sign(mathy0(Math.sqrt(x), x)))) >>> 0) + (Math.imul((((((( ! y) ? 0x100000001 : 0x080000000) >>> 0) % (Math.fround(Math.expm1(Math.fround(y))) | 0)) | 0) >>> 0), (Math.abs((( ~ (x | 0)) | 0)) >>> 0)) | 0)) >>> 0)); }); testMathyFunction(mathy1, ['0', null, (new Boolean(false)), NaN, [], objectEmulatingUndefined(), '/0/', /0/, -0, (function(){return 0;}), (new Boolean(true)), ({toString:function(){return '0';}}), '', 0, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Number(-0)), [0], (new Number(0)), (new String('')), undefined, '\\0', true, 1, 0.1, false]); ");
/*fuzzSeed-244067732*/count=1424; tryItOut("a2.toSource = f1;");
/*fuzzSeed-244067732*/count=1425; tryItOut("\"use strict\"; p1 + '';");
/*fuzzSeed-244067732*/count=1426; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x0ffffffff, 0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 42, Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, Number.MIN_VALUE, -0, -Number.MIN_VALUE, 0.000000000000001, 0x100000001, 1.7976931348623157e308, 0/0, -0x100000001, -(2**53), -(2**53+2), -1/0, 0, 2**53-2, Math.PI, 1, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1427; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((~~(d0)) < (abs((0x6fd24f96))|0));\n    {\n      d0 = ((((d0) + (+(0xffffffff)))) * ((+abs(((7.737125245533627e+25))))));\n    }\n    d0 = (1099511627775.0);\n    {\n      d0 = (+(1.0/0.0));\n    }\n    return (((/*FFI*/ff(((abs(((\"\\uE521\")))|0)), ((-((+(-1.0/0.0))))), ((((((0xf886f492))>>>((0xffffffff))) % (((0xffffffff))>>>((0xfe2bac2e)))) << (((0x42fbd01b) > (-0x8000000))-((0x43f3247b))+(0xf8f762e4)))), ((1073741823.0)), ((i1)), ((d0)), ((+(-1.0/0.0))), ((d0)), ((-140737488355328.0)))|0)-((((+abs(((+(((0xe228b8f2) % (0x516c9fc6)) | ((/*FFI*/ff(((-4.722366482869645e+21)), ((549755813889.0)))|0)))))))) / ((d0))) <= (Infinity))))|0;\n  }\n  return f; })(this, {ff: (neuter).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x080000001, 0/0, 0x080000000, 1.7976931348623157e308, Math.PI, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, 2**53+2, 1, -0x0ffffffff, 0x100000000, 2**53, -(2**53+2), -0x080000000, -(2**53-2), 42, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -0x100000001, -1/0, -(2**53), 2**53-2, 0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -0x07fffffff, 0, -0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1428; tryItOut("o1.s2 += 'x';");
/*fuzzSeed-244067732*/count=1429; tryItOut("\"use strict\"; h2.delete = f1;");
/*fuzzSeed-244067732*/count=1430; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s1; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1431; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 576460752303423500.0;\n    {\n      {\n        i3 = (0xa151c557);\n      }\n    }\n    d1 = (-0.25);\n;    return (((0xd16dfdd8) % ((function(y) { \"use strict\"; 28; }))))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new ArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=1432; tryItOut("mathy0 = (function(x, y) { return ((( + ( + (Number.MAX_SAFE_INTEGER ? ( + (Math.pow(( + Math.PI), ( + x)) >>> 0)) : x))) === ( + (Math.pow(( + Math.max((x | 0), x)), ( - Math.fround(( + ( ~ ( + Math.min((y === x), (x >>> 0)))))))) == ( + Math.ceil(( + Math.cos(Math.min(((y >>> 0) ^ ( + ((x ** (x >>> 0)) >>> 0))), ( + Math.min(Math.max((y | 0), Number.MIN_VALUE), 0/0)))))))))) | 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, -Number.MIN_VALUE, -0x080000001, 2**53+2, 0x080000001, 0x100000001, -Number.MAX_VALUE, -(2**53-2), -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 1.7976931348623157e308, 42, -0x100000001, 1/0, 0x100000000, -0x07fffffff, -0, -0x080000000, 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -0x0ffffffff, 1, Number.MIN_VALUE, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 0]); ");
/*fuzzSeed-244067732*/count=1433; tryItOut("f0 = (-1/0);");
/*fuzzSeed-244067732*/count=1434; tryItOut("mathy3 = (function(x, y) { return Math.sign(Math.fround(( - ( - ((mathy0((( + Number.MAX_VALUE) & Number.MIN_VALUE), x) | 0) >= Math.fround((( + Math.fround(Math.log(x))) - (x === y)))))))); }); testMathyFunction(mathy3, [-0x07fffffff, Math.PI, -0, -1/0, 2**53, 1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000001, 0x080000001, 42, 0x080000000, -Number.MIN_VALUE, -(2**53-2), -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 1, -(2**53), -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, 0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, 0/0, 0x100000000, 0.000000000000001, -0x100000000]); ");
/*fuzzSeed-244067732*/count=1435; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=1436; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((( + ((((Math.fround((x ^ ( + ( - y)))) >>> 0) !== (( + Math.min(( + y), ( + x))) >>> 0)) | 0) <= (Math.min((( ! Math.ceil(x)) >>> 0), ((Math.min(Math.fround(Math.sin(( + x))), Math.fround(Math.acosh(y))) >>> 0) & ( - x))) >>> 0))) >>> 0) / (((Math.hypot(x, ( ! ( + Math.pow(Math.acos(x), x)))) | 0) || (( + Math.max(Math.exp(y), ( + ( ! y)))) | 0)) | 0)); }); testMathyFunction(mathy0, [-0x0ffffffff, 0x080000001, Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, 0, 0.000000000000001, -Number.MIN_VALUE, 2**53+2, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), -0x100000001, 1.7976931348623157e308, 0x100000001, -1/0, Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -Number.MAX_VALUE, -(2**53-2), -0x100000000, 0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, 0/0, -(2**53+2), -0x07fffffff, 0x080000000, -0x080000000, 1]); ");
/*fuzzSeed-244067732*/count=1437; tryItOut("h0 = m2.get(new (/*UUV2*/(z.add = z.clear))());");
/*fuzzSeed-244067732*/count=1438; tryItOut("\"use strict\"; with({}) { let(x, e, svdmer, sbdjtz, xepkzh, z, x) { this.zzz.zzz;} } try { for(let x of (function() { \"use strict\"; yield  /x/  === new RegExp(\"(?:[^\\\\S]*(?!(?=$))\\\\\\u009a\\\\1)*?\", \"gi\"); } })()) for(let d of /*MARR*/[(0/0)]) for(let y in /*FARR*/[]) let(eajhio, y, ymoeyd, dllyet, c, window, x, x, y, tcxicc) ((function(){(-21);})()); } catch(x if let (c, qpoyoi, nkstrn)  /x/g ) { for(let w in []); } catch(a if (function(){e = NaN;})()) { throw \u3056;/*\n*/ } catch(x) { let(d) { (w) = this;} } ");
/*fuzzSeed-244067732*/count=1439; tryItOut("g1.offThreadCompileScript(\"-25\");");
/*fuzzSeed-244067732*/count=1440; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float64ArrayView[4096]) = ((-562949953421311.0));\n    i0 = ((i1) ? (i1) : (i0));\n    {\n      {\n        {\n          i1 = (/*FFI*/ff(((abs((~(intern(/*FARR*/[, , x,  \"\" , ,  /x/g , 9,  /x/ ,  /x/ , , ...[], d, x].map(Object.prototype.toLocaleString)))))|0)), ((-1.5)), ((((i1)-(i1)) << ((0xd7d48f1c)*0x8b784))), ((0.015625)), ((-2.3611832414348226e+21)), ((((i1)-(i1)) << (-(!(0x727ef4f4))))), ((((Int32ArrayView[2])) & ((0xf8aee9cc)+(0x4b1a53bc)))), ((((-33.0)) - ((-524289.0)))), (function  x ()\u000c\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((\"\\u9912\") ? (0xfae176cd) : (i0));\n    {\n      {\n        {\n          (Float64ArrayView[4096]) = ((d1));\n        }\n      }\n    }\n    {\n      d1 = (-((((18446744073709552000.0)) / ((+(0.0/0.0))))));\n    }\n    i0 = ((0xffffffff) != ((neuter).call(let (c, iobyhz, d) undefined, [-2])));\n    d1 = (d1);\n    d1 = (d1);\n    {\n      {\n        switch (((((((0xfafe00d5))|0))) & ((i0)))) {\n          default:\n            i0 = (0x7c916d84);\n        }\n      }\n    }\n    return ((((d1) >= (+(1.0/0.0)))))|0;\n  }\n  return f;.prototype), ((-1152921504606847000.0)), ((-3.0)))|0);\n        }\n      }\n    }\n    switch ((0x349fe3c3)) {\n      case -3:\n        i0 = (i0);\n    }\n    i0 = (!(i1));\n    i1 = (i0);\n    i0 = (i1);\n    i1 = (i0);\n    i1 = (0x66d1548f);\n    return (((i0)))|0;\n    i1 = (i0);\n    {\n      {\n        i1 = (i0);\n      }\n    }\n    i1 = (/*FFI*/ff((((-17592186044417.0))), (((((i0) ? (i1) : (i1))) | ((0x13d23a52) % (-0xcfa93b)))))|0);\n    i1 = (null);\n    switch ((((i1))|0)) {\n      case -1:\n        i0 = ((0x37c85bdb));\n        break;\n      default:\nfalse || 2;    }\n    {\n      i1 = (/*FFI*/ff((((((i1) ? (0xffffffff) : (i1))) ^ (((0xffffffff) > (((i0)-(i0))>>>((0xf8c1eadd))))))), (((-0x60d69*(i0)) >> (-0x74da4*(i1)))), ((((((+abs(((NaN))))) / ((-2.0)))) % ((Float32ArrayView[(((0xa3e68a5b))) >> 2])))))|0);\n    }\n    return (((((i1)+(i0)-(i1))|0) / (abs((((((x.yoyo(/*UUV2*/(w.exec = w.toExponential)))) ? (!(i0)) : (i1))) ^ ((((i1))>>>((0xba7b6d50)-(0x8acf2d24))) / (0x3833f450))))|0)))|0;\n  }\n  return f; })(this, {ff: mathy0}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[true, false, false, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], false, true, true, [1], [1], false, false]); ");
/*fuzzSeed-244067732*/count=1441; tryItOut("a0 = Array.prototype.slice.call(a2, NaN, NaN);");
/*fuzzSeed-244067732*/count=1442; tryItOut("mathy5 = (function(x, y) { return Math.fround((Math.fround(Math.fround((( + Math.log2(y)) % ((x | 0) ? (Math.acos((Math.sign((42 | 0)) | 0)) | 0) : ( ~ (((-(2**53-2) | 0) ? (Math.sign(Math.fround(Math.log(y))) >>> 0) : (Math.log10((Math.exp((y >>> 0)) >>> 0)) >>> 0)) >>> 0)))))) === Math.fround(Math.asinh(Math.max(Math.fround(( - ( + (((y >>> 0) , (Math.tan(( + y)) >>> 0)) >>> 0)))), Math.atan2(y, ( + Math.fround((Math.fround(x) !== Math.fround(0x080000001)))))))))); }); testMathyFunction(mathy5, [-0x07fffffff, -(2**53), Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -0, -0x080000001, -Number.MIN_VALUE, -1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, -Number.MAX_VALUE, 1, 2**53-2, -0x100000000, -0x0ffffffff, -0x080000000, 42, 0x0ffffffff, 0x100000001, -0x100000001, Number.MIN_VALUE, 1/0, 2**53+2, 0x100000000, 0/0, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-244067732*/count=1443; tryItOut("testMathyFunction(mathy2, [({toString:function(){return '0';}}), true, 0, (function(){return 0;}), [0], NaN, [], 0.1, false, -0, undefined, /0/, '\\0', ({valueOf:function(){return 0;}}), (new Number(-0)), (new Boolean(true)), '/0/', (new Boolean(false)), (new String('')), ({valueOf:function(){return '0';}}), null, (new Number(0)), '', '0', objectEmulatingUndefined(), 1]); ");
/*fuzzSeed-244067732*/count=1444; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.fround(Math.pow(((2**53+2 - x) >>> 0), (( + x) >>> ( + Math.log1p(( + ((y | 0) ? x : Number.MIN_SAFE_INTEGER))))))) ? ((( - (Math.log1p((((Math.sign(( + (( - (y | 0)) | 0))) >>> 0) != Math.abs(Number.MIN_SAFE_INTEGER)) | 0)) | 0)) | 0) >>> 0) : Math.fround(( ! ((( + x) | 0) ? ( + Math.min(y, y)) : Math.atan(( + 1.7976931348623157e308)))))); }); testMathyFunction(mathy0, [0/0, 1, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, 2**53, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -0x100000001, Number.MIN_VALUE, 2**53+2, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, 0.000000000000001, -0x07fffffff, -0, 0x080000000, 0x100000000, 1.7976931348623157e308, -0x080000000, -(2**53+2), -(2**53), 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, 42, 0, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=1445; tryItOut("for (var p in this.h1) { try { h0.set = f1; } catch(e0) { } try { delete h2.set; } catch(e1) { } try { for (var v of f1) { Array.prototype.push.call(a0, (arguments[\"bold\"]\u0009) = x, f1); } } catch(e2) { } g0 = this; }");
/*fuzzSeed-244067732*/count=1446; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.hypot(((( ~ Number.MIN_VALUE) >> (((((Math.fround(x) !== x) * ( - Math.log10(x))) > Math.min(x, Math.PI)) >>> 0) >>> 0)) >>> 0), (( + (( ! x) <= Math.fround((Number.MIN_VALUE != x)))) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[true, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], true, true, [1], true, [1], true, [1], [1], [1], true, true, true, [1], true, [1], [1], true, true, true, [1], [1], [1]]); ");
/*fuzzSeed-244067732*/count=1447; tryItOut("if(true) {m2.set(p0, p1);i1.__proto__ = h0;var c =  /x/g ; } else  if ((makeFinalizeObserver('tenured'))) print(x); else {var r0 = 9 + 7; var r1 = r0 + 7; var r2 = 6 + x; var r3 = r2 % 6; r3 = r3 / r3; var r4 = r3 | 0; r4 = x * r1; var r5 = r0 ^ r0; var r6 = 2 ^ 0; print(r1); var r7 = r6 - 1; var r8 = r5 % r0; var r9 = r1 ^ 2; var r10 = r1 | r6; var r11 = 8 * 8; var r12 = r4 / r10; ;g1.m0.get(x); }");
/*fuzzSeed-244067732*/count=1448; tryItOut("t0[(URIError(\"\\u2FFB\").__defineSetter__(\"c\", Object.isExtensible))] = p2;");
/*fuzzSeed-244067732*/count=1449; tryItOut("\"use asm\"; f0 + e0;");
/*fuzzSeed-244067732*/count=1450; tryItOut("/*oLoop*/for (lpynbe = 0, (Math.atan2(window, -3) > [].__defineSetter__(\"x\", RangeError)); lpynbe < 26; ++lpynbe) { for (var p in g0.a1) { try { this.v2 = new Number(4.2); } catch(e0) { } for (var v of g1.i2) { try { p2.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -2049.0;\n    return +((1152921504606847000.0));\n  }\n  return f; })(this, {ff: function  a (y) { return window } }, new SharedArrayBuffer(4096)); } catch(e0) { } try { s1 += s0; } catch(e1) { } a1 + ''; } } } ");
/*fuzzSeed-244067732*/count=1451; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + Math.log((Math.atan2((x < Math.fround(mathy1(x, x))), (x >>> 0)) | 0))) % ( + Math.atan(( + ( + Math.cbrt(( + (x >> Math.fround((y ? 0 : Math.cosh(x))))))))))); }); ");
/*fuzzSeed-244067732*/count=1452; tryItOut("\"use strict\"; var zqgleo, x, osnztf, mavkbx;m0.set(b1, m1);");
/*fuzzSeed-244067732*/count=1453; tryItOut("x = x;");
/*fuzzSeed-244067732*/count=1454; tryItOut("\"use strict\"; /*RXUB*/var r = [1]; var s = \"_\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1455; tryItOut("print(uneval(f1));");
/*fuzzSeed-244067732*/count=1456; tryItOut("\"use strict\"; testMathyFunction(mathy2, [1, 0x07fffffff, 0x080000000, -0x0ffffffff, 42, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000001, 0, -Number.MIN_VALUE, -0x100000001, -0x07fffffff, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 0/0, 1/0, Math.PI, -0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, 2**53-2, 0x100000001, Number.MAX_VALUE, -0x100000000, -Number.MAX_VALUE, -0, -1/0, 0.000000000000001, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1457; tryItOut("mathy1 = (function(x, y) { return ((((Math.clz32(Math.fround(Math.max((Math.sqrt(Math.log1p(-1/0)) | 0), Math.log2((((x | 0) && Math.fround(x)) | 0))))) >>> 0) >>> 0) >= (Math.min(( + Math.atan2(( + ((( + ( - Number.MAX_VALUE)) * x) + ( - -0x100000000))), Math.fround(Math.cbrt((Math.imul(x, (Math.sinh(y) | 0)) >>> 0))))), (Math.trunc(( + -0x0ffffffff)) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-244067732*/count=1458; tryItOut("\"use strict\"; e1.has(f2);");
/*fuzzSeed-244067732*/count=1459; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(( ~ ( + (( + ( - (( + (((y >>> 0) && (x >>> 0)) >>> 0)) % 0x0ffffffff))) ** y))), Math.fround((( ! (( + (( + Math.clz32(x)) % ( + ( ! y)))) | 0)) | 0))); }); ");
/*fuzzSeed-244067732*/count=1460; tryItOut("/*tLoop*/for (let z of /*MARR*/[false, false, false, \"\u03a0\", false, false, \"\u03a0\", false, false, false, false, \"\u03a0\", \"\u03a0\", \"\u03a0\", \"\u03a0\", false, false, \"\u03a0\", false, false, false, \"\u03a0\", \"\u03a0\", false, false, \"\u03a0\", \"\u03a0\", false, \"\u03a0\", false, \"\u03a0\", \"\u03a0\", false, \"\u03a0\", false, false, \"\u03a0\", \"\u03a0\", \"\u03a0\", \"\u03a0\", false, \"\u03a0\", \"\u03a0\", false, \"\u03a0\", \"\u03a0\", \"\u03a0\", \"\u03a0\", false, \"\u03a0\", false, false, false, false, \"\u03a0\", \"\u03a0\", false, false, false, \"\u03a0\", \"\u03a0\", false, \"\u03a0\", \"\u03a0\", false, false, \"\u03a0\", false, false, \"\u03a0\", false]) { for (var p in o1.b1) { try { for (var v of this.b1) { try { this.v2 = -0; } catch(e0) { } v1 = (s1 instanceof o2.b1); } } catch(e0) { } try { Object.defineProperty(o2, \"v2\", { configurable: false, enumerable: \"\\uD0CE\",  get: function() { o0.a0.splice(NaN, new RegExp(\"(?=(?:(?!\\\\w)))\", \"yi\"), f2); return evaluate(\"\\\"use strict\\\"; mathy3 = (function(x, y) { \\\"use asm\\\"; return Math.cosh(( ! ( + (( + (( ~ (Math.fround(( ! Math.fround(y))) >>> 0)) >>> 0)) * ((Math.fround((Math.min((x | 0), (( + ( ! ( ! y))) | 0)) | 0)) > Math.log2(y)) >>> 0))))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), (new String('')), '/0/', [0], (new Number(0)), false, NaN, (new Boolean(false)), undefined, 0, 0.1, null, /0/, [], (new Number(-0)), -0, (new Boolean(true)), objectEmulatingUndefined(), '0', ({valueOf:function(){return '0';}}), true, '\\\\0', (function(){return 0;}), '', 1, ({valueOf:function(){return 0;}})]); \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 != 3), noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 2 == 1), element: this.o1, elementAttributeName: o2.s1, sourceMapURL: s1 })); } }); } catch(e1) { } try { v1 = t0.byteOffset; } catch(e2) { } Array.prototype.unshift.call(a1, f1, g1); } }");
/*fuzzSeed-244067732*/count=1461; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    return +((d1));\n    return +((d1));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=1462; tryItOut("\"use strict\"; e1.has(p1);");
/*fuzzSeed-244067732*/count=1463; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Int16ArrayView[((imul((i0), (-0x8000000))|0) / (((0x25829821)*-0xb0ee9)|0)) >> 1]) = (((7.555786372591432e+22) > (((d1)) * (((-((+(((0xebdce167)) << ((0xfa0e278a)))))) + (new !x))))));\n    i0 = (i0);\n    (Uint16ArrayView[(-0x8ecaa*(i0)) >> 1]) = ((0xddb5e8bd));\n    return +((((d1)) * ((+(-1.0/0.0)))));\n  }\n  return f; })(this, {ff: Set.prototype.clear}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [1, false, '/0/', objectEmulatingUndefined(), (new Boolean(true)), '', '0', (new Number(0)), -0, true, null, /0/, ({toString:function(){return '0';}}), (new Number(-0)), (function(){return 0;}), ({valueOf:function(){return '0';}}), '\\0', (new String('')), NaN, 0.1, [], (new Boolean(false)), undefined, 0, [0], ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-244067732*/count=1464; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((((Math.log10(( + (Math.fround((x , y)) != x))) ** ((Math.asin(Math.cosh((y | 0))) >>> 0) >>> 0)) >>> 0) >>> 0) ** (Math.atan2(( ! Math.fround(Math.fround((( + y) * Math.fround((y * ( + (( + x) ? ( + x) : ( + x))))))))), (Math.log(y) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-244067732*/count=1465; tryItOut("mathy1 = (function(x, y) { return (Math.max(((( ! ((Math.max((((( + x) === (( ! ( + x)) >>> 0)) >>> 0) >>> 0), (( ~ y) >>> 0)) >>> 0) >>> 0)) | 0) | 0), (( ! (Math.pow(( + (-0x07fffffff , ( + y))), x) << y)) | 0)) | 0); }); testMathyFunction(mathy1, [-0x100000000, 0, -0x0ffffffff, 1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x0ffffffff, 1, -(2**53+2), 0x100000000, 0x100000001, 2**53-2, 0x07fffffff, 0x080000000, Math.PI, -0x080000001, -1/0, -0, -(2**53), 2**53+2, 0/0, Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000001]); ");
/*fuzzSeed-244067732*/count=1466; tryItOut("h2.iterate = (function() { Object.preventExtensions(s2); return o1; });");
/*fuzzSeed-244067732*/count=1467; tryItOut("\"use strict\"; /*vLoop*/for (nsaxsv = 0; nsaxsv < 49; ++nsaxsv) { const w = nsaxsv; o2 + '';print( '' ); } ");
/*fuzzSeed-244067732*/count=1468; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; deterministicgc(false); } void 0; }");
/*fuzzSeed-244067732*/count=1469; tryItOut("mathy0 = (function(x, y) { return (( ! Math.fround((Math.fround(y) * Math.fround(( + Math.sin(( + -(2**53-2)))))))) > Math.atan2((( ! Math.min(((( ~ (x | 0)) | 0) >>> 0), Math.atan2(y, x))) | 0), (Math.log2(((((-0 >>> 0) == (( + Math.cosh(( + x))) >>> 0)) >>> 0) | 0)) | 0))); }); ");
/*fuzzSeed-244067732*/count=1470; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atanh(Math.exp(( ~ x))); }); testMathyFunction(mathy1, [-1/0, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, -(2**53), 1/0, 0/0, -(2**53-2), 0x080000000, 2**53+2, -0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, 0, 0x100000000, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, -0, 0x100000001, 0x0ffffffff, 2**53, -0x100000001, -0x080000000, 0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 42, 0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1471; tryItOut("this.t2[({valueOf: function() { print((function ([y]) { })());return 7; }})] = eval(--y, x);");
/*fuzzSeed-244067732*/count=1472; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.fround(Math.atanh(Math.fround(Math.pow(Math.fround(Math.min(y, y)), Math.fround(Math.pow(Number.MIN_SAFE_INTEGER, (-Number.MIN_SAFE_INTEGER ? ( + (( - ((0.000000000000001 & Math.fround(x)) >>> 0)) | 0)) : Math.atan2(0, ( + (Math.max(Math.fround(x), Math.fround(0/0)) >>> 0))))))))))); }); testMathyFunction(mathy3, [true, (new Number(0)), -0, null, '0', (new Boolean(true)), undefined, '', (new Number(-0)), (new String('')), [0], ({valueOf:function(){return '0';}}), /0/, 0, 0.1, 1, (function(){return 0;}), [], NaN, '/0/', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '\\0', (new Boolean(false)), false, objectEmulatingUndefined()]); ");
/*fuzzSeed-244067732*/count=1473; tryItOut("m1.set(g0.p1,  /x/g );");
/*fuzzSeed-244067732*/count=1474; tryItOut("\"use strict\"; v2 = a2.length;");
/*fuzzSeed-244067732*/count=1475; tryItOut("if(false) {m1.set(g1.b2, t0);/*RXUB*/var r = new RegExp(\"(?=\\\\B)?(?!\\\\1)[\\\\S]{4,6}|\\\\2^$|.?|.|\\\\3{1,4}\", \"y\"); var s =  '' ; print(r.test(s));  } else  if (let (a = function(id) { return id }) (4277)) {/*vLoop*/for (whokhn = 0, eval(\"24\", [z1,,]); whokhn < 10; ++whokhn) { var y = whokhn; s0 += 'x'; }  } else yield (void options('strict'));");
/*fuzzSeed-244067732*/count=1476; tryItOut("\"use strict\"; for (var p in v0) { try { this.v2.__iterator__ = (function() { e0 + ''; return o0; }); } catch(e0) { } try { s0 += g1.o0.s0; } catch(e1) { } e2.has(o1.h1); }");
/*fuzzSeed-244067732*/count=1477; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1478; tryItOut("mathy4 = (function(x, y) { return Math.hypot(( + ((( ! (((( + (y || y)) >>> 0) >> (y >>> 0)) >>> 0)) >> Math.exp(y)) ? (Math.fround(( ~ Math.sqrt(((Math.sinh(2**53+2) != (mathy1(x, y) >>> 0)) >>> 0)))) >>> 0) : Math.max((( ! (x >>> 0)) >>> 0), (Math.ceil((x > (y >>> 0))) | 0)))), Math.fround((Math.fround(Math.fround(mathy3(Math.fround(y), Math.fround(x)))) | ((((Math.fround(Math.hypot(Math.fround(2**53), Math.fround((( ! (Math.ceil(( + 0x100000001)) >>> 0)) >>> 0)))) >>> 0) << (mathy0(-Number.MAX_SAFE_INTEGER, ( + Math.min(( + x), ( + Number.MIN_SAFE_INTEGER)))) | 0)) | 0) | 0)))); }); testMathyFunction(mathy4, [-0x0ffffffff, Math.PI, 0x080000000, 0/0, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -0, 1, -1/0, 0x0ffffffff, 1/0, 0, -(2**53+2), -Number.MIN_VALUE, 1.7976931348623157e308, 42, 0.000000000000001, -0x100000000, -0x100000001, Number.MAX_VALUE, 0x07fffffff, -0x080000001, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -(2**53), -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 2**53, 0x100000000]); ");
/*fuzzSeed-244067732*/count=1479; tryItOut("/*infloop*/for(var \ne = objectEmulatingUndefined; x; ({})) {print(g2.t0);return ((void options('strict'))); }");
/*fuzzSeed-244067732*/count=1480; tryItOut("\"use strict\"; {function ([y]) { }; }{ void 0; void schedulegc(this); }");
/*fuzzSeed-244067732*/count=1481; tryItOut("testMathyFunction(mathy2, [42, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), Number.MAX_VALUE, 0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), -0x0ffffffff, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, -0x100000001, 0, 0x080000000, -0, 0.000000000000001, 0/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, 1.7976931348623157e308, 0x100000001, 2**53-2, -Number.MIN_VALUE, -1/0, 1, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-244067732*/count=1482; tryItOut("s1 = new String;");
/*fuzzSeed-244067732*/count=1483; tryItOut("\"use strict\"; \"use asm\"; print(x);\nt2.set(t2, Math.min(-16, 22));\n");
/*fuzzSeed-244067732*/count=1484; tryItOut("");
/*fuzzSeed-244067732*/count=1485; tryItOut("mathy4 = (function(x, y) { return ( + Math.imul((( + (((Math.log(y) | 0) >>> 0) , (( + (( + Math.atan2(Math.fround(Math.cosh(Math.fround(Math.fround(( ! x))))), ( ! 2**53-2))) ? ( + (((Math.imul((0x0ffffffff | 0), (y | 0)) | 0) | 0) != y)) : ( + Math.fround(( ! Math.fround(-Number.MAX_SAFE_INTEGER)))))) >>> 0))) | 0), ( + ( - Math.hypot((( - x) | 0), Math.pow((Math.acosh((x >>> 0)) >>> 0), x)))))); }); testMathyFunction(mathy4, [-(2**53+2), -(2**53), -Number.MIN_VALUE, 0x100000000, -0, -(2**53-2), -0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, 2**53+2, 0x080000001, Math.PI, Number.MIN_VALUE, 0x07fffffff, 2**53, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, 0.000000000000001, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 2**53-2, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, -0x080000001, 0/0, 0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE]); ");
/*fuzzSeed-244067732*/count=1486; tryItOut("a0.splice(NaN, 16, x\n);");
/*fuzzSeed-244067732*/count=1487; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1488; tryItOut("\"use strict\"; a1 = arguments.callee.caller.caller.arguments;");
/*fuzzSeed-244067732*/count=1489; tryItOut("v1 = t2.length;");
/*fuzzSeed-244067732*/count=1490; tryItOut("\"use strict\"; try { throw null; } finally { null; } ");
/*fuzzSeed-244067732*/count=1491; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.atan2(( + mathy1((( - ( + (0x0ffffffff % ((Math.pow((x >>> 0), (y >>> 0)) | 0) <= x)))) | 0), ( + mathy1(Math.sinh(x), mathy0((y | 0), ( + y)))))), (Math.fround((y || ( + ( + ( + (Math.asinh((y | 0)) | 0)))))) ? Math.trunc((mathy1((( + Math.acosh(( + y))) >>> 0), (y >>> 0)) >>> 0)) : (Math.fround(x) ? Math.asinh(y) : x))) >>> 0), ( + (( + y) | 0))) | 0); }); testMathyFunction(mathy2, [0, 2**53+2, 1, 0/0, -0x080000001, -0x0ffffffff, 2**53, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, -0, 42, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, -0x100000001, 1/0, Number.MAX_VALUE, 2**53-2, -(2**53), 0x100000001, -0x07fffffff, 0x07fffffff, 0x0ffffffff, 0x080000000, -(2**53+2), Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), Math.PI, 1.7976931348623157e308]); ");
/*fuzzSeed-244067732*/count=1492; tryItOut("selectforgc(o1);");
/*fuzzSeed-244067732*/count=1493; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.hypot((Math.atan2((Math.fround(Math.acosh(Math.fround(Math.atan2(y, (x ? ( + ( ~ 1/0)) : (y << ( + y))))))) >>> 0), Math.round(x)) >>> 0), ( + (Math.atanh(Math.fround((( + (( ~ 0x080000000) <= (Math.log1p(y) | 0))) * Math.fround(x)))) >>> (Math.cosh(( + ((Math.fround(( ~ Math.fround(Math.min((y | 0), (y | 0))))) | 0) | y))) >>> 0)))); }); testMathyFunction(mathy0, [-0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, 2**53, -0, 2**53+2, 1/0, -(2**53+2), 1.7976931348623157e308, -0x080000000, -(2**53-2), 0.000000000000001, 0/0, -Number.MAX_VALUE, 0x07fffffff, 0x100000000, Math.PI, -0x100000000, -1/0, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 2**53-2, -Number.MIN_VALUE, 42, 0, 0x080000001, 0x100000001, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1494; tryItOut("/*MXX1*/o1 = g2.Object.isSealed;function x(w) { yield this } o2 = new Object;");
/*fuzzSeed-244067732*/count=1495; tryItOut("do s2 = ''; while(((Math.pow(new RegExp(\"(\\\\3).\\\\W|(?!.|([^\\\\b]))|(?=\\u0080[\\\\s\\u7533\\uce4c-\\u81b1\\\\s]\\\\u0099.)*?+\", \"gyim\"), -1863621736.5))) && 0);");
/*fuzzSeed-244067732*/count=1496; tryItOut("\"use strict\"; v0 = (g1.b0 instanceof this.h0);");
/*fuzzSeed-244067732*/count=1497; tryItOut("true;\nv0 = (o0.a1 instanceof this.g1.s1);\n");
/*fuzzSeed-244067732*/count=1498; tryItOut("/*RXUB*/var r = /(?:(?!(?:.){2,2})|\\S|(?!.)${4,5}){3,}/gy; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-244067732*/count=1499; tryItOut(";");
/*fuzzSeed-244067732*/count=1500; tryItOut("/*RXUB*/var r = r1; var s = s2; print(s.split(r)); ");
/*fuzzSeed-244067732*/count=1501; tryItOut("m1.has(o0.i2);");
/*fuzzSeed-244067732*/count=1502; tryItOut("\"use strict\"; e1.add(v2);");
/*fuzzSeed-244067732*/count=1503; tryItOut("\"use strict\"; let (a) { m0.get(b0); }");
/*fuzzSeed-244067732*/count=1504; tryItOut("/*MXX1*/o1 = g1.Object.length;");
/*fuzzSeed-244067732*/count=1505; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0/0, 0x100000000, 2**53-2, 0, 0x080000001, -1/0, -(2**53), -Number.MIN_VALUE, 0.000000000000001, -0x080000001, 0x0ffffffff, -0x080000000, 2**53+2, Math.PI, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, -(2**53-2), 42, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), Number.MAX_VALUE, 1, 1.7976931348623157e308, -0x100000000, -0x100000001, 0x07fffffff, -0x07fffffff, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1506; tryItOut("\"use strict\"; { void 0; try { (voiddisableSingleStepProfiling()) } catch(e) { } } ");
/*fuzzSeed-244067732*/count=1507; tryItOut("this.zzz.zzz;throw d;");
/*fuzzSeed-244067732*/count=1508; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-244067732*/count=1509; tryItOut("testMathyFunction(mathy3, [0x100000001, 0, 0/0, Math.PI, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, 0x080000000, 0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, 0x07fffffff, -1/0, 2**53-2, -0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, 2**53+2, 0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -0x080000001, -(2**53), 1/0, 1, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), -0x0ffffffff, 42, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1510; tryItOut("let (y) { /*iii*/t2.set(a2, 4);/*hhh*/function bfdbxf(NaN = -1.x = (null.throw(-17)), eval, d, y, y, w, b, yield, b = window, yield, b, a = window, e = \"\\u173F\", c = this, NaN, \u3056, eval, d, x = function ([y]) { }, this, y = [,,z1], x, y, x, x, y, b, z, NaN, b, c, y = this){m1.set(i2, this.o0);} }");
/*fuzzSeed-244067732*/count=1511; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"function f0(v1)  { g1.offThreadCompileScript(\\\"/*ADP-3*/Object.defineProperty(a2, 4, { configurable: (v1 % 16 != 12), enumerable: (v1 % 4 == 1), writable: true, value: p2 });\\\", ({ global: o1.g2.g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 4 == 2), sourceIsLazy: (v1 % 13 != 8), catchTermination: w() })); } \");");
/*fuzzSeed-244067732*/count=1512; tryItOut("\"use strict\"; let (d) { for (var v of f1) { try { m1.has(this.s0); } catch(e0) { } print(uneval(e1)); } }");
/*fuzzSeed-244067732*/count=1513; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + (( + ((Math.round(-0x100000000) ? ( - ( + (((y | 0) % (x | 0)) | 0))) : ( + ( - Math.fround(x)))) + Math.fround((x >> (Math.fround(mathy4(Math.fround(y), Math.fround(x))) && Math.asinh(y)))))) != ( + (( ! (Math.asin(( + (( + 0) ? y : (y <= (Math.sinh(x) | 0))))) >>> 0)) << ( ~ (( ~ Math.fround((Number.MIN_VALUE ? ( + -(2**53+2)) : x))) | 0)))))); }); testMathyFunction(mathy5, [-0x100000000, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -0x100000001, 0.000000000000001, -0x07fffffff, -0x080000000, -(2**53), 0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, Math.PI, 0x100000001, 1/0, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 1, 0/0, -0x080000001, -0x0ffffffff, -(2**53+2), 2**53-2, Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0, -(2**53-2), -Number.MAX_VALUE, 42, 2**53]); ");
/*fuzzSeed-244067732*/count=1514; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 0.5;\n    var i5 = 0;\n    var i6 = 0;\n    var d7 = 1.5;\n    return (((!(i6))+((imul(((0xca466*(0x1fad68ff))), (!(0xfbde3efa)))|0))+((0x8fb3793))))|0;\n  }\n  return f; })(this, {ff: \"\\u58AD\"}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53), Number.MAX_VALUE, 42, 2**53-2, -0x080000001, 1, 0x080000001, 0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, -0x100000000, 0x100000001, -1/0, -(2**53-2), -0, -0x080000000, 0x07fffffff, 1/0, 1.7976931348623157e308, 0x100000000, Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 0/0, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1515; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.asinh((Math.min((( + ( ! ( + Math.pow(Math.pow(x, x), (( + ( ! x)) | 0))))) | 0), (((((((( ~ (y >>> 0)) >>> 0) * Math.fround(y)) >>> 0) ? (( - -0x080000000) >>> 0) : (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) == ( + Math.tan(Math.fround(( + Math.acosh(( + (( + x) ? x : 1.7976931348623157e308)))))))) | 0)) >>> 0)); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -1/0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0, -(2**53-2), 2**53, -(2**53+2), Math.PI, 2**53-2, -(2**53), 0x07fffffff, -0x07fffffff, 0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, 42, Number.MAX_VALUE, 2**53+2, -0x080000000, -0x080000001, -Number.MAX_VALUE, 0x080000001, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, -0x100000000, 0/0, 1]); ");
/*fuzzSeed-244067732*/count=1516; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround((Math.atan((Math.asin(Math.log10(Math.atan2(y, x))) == Math.sinh(((x ? x : x) | 0)))) ? Math.fround(mathy3((( ~ ( + (((x | 0) / (y | 0)) | 0))) >>> 0), Math.fround(((Math.fround(Math.abs(((Math.fround(Math.pow(( + x), ( + (((y | 0) - (x | 0)) | 0)))) === Math.fround(y)) | 0))) & (y | 0)) | 0)))) : (Math.fround(Math.hypot(( + Math.asinh(( + (Math.pow(Number.MIN_SAFE_INTEGER, (Math.pow(y, x) | 0)) | 0)))), mathy1(( + Math.log10(( + ( + ( + y))))), y))) | 0))); }); testMathyFunction(mathy4, [Math.PI, 1/0, 0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, 0x080000001, -1/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 2**53, 0x080000000, 0.000000000000001, -0x07fffffff, 0, -(2**53+2), -(2**53), -(2**53-2), -0x080000001, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, -0x100000000, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, -0x100000001, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1517; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.pow((x != Math.imul(Math.exp(y), Math.hypot((((y | 0) % (1.7976931348623157e308 | 0)) | 0), Math.clz32((y | 0))))), ((mathy0((2**53 | 0), ( + Math.hypot(( + Math.asinh(( + y))), ((y - (-Number.MAX_VALUE | 0)) | 0)))) << (mathy0(x, Math.trunc(Math.fround((Math.fround(y) !== Math.fround(x))))) >>> 0)) | 0))) >>> 0) == (mathy0(Math.log10(-0x100000000), ( ~ ((((x >>> y) | 0) | -Number.MIN_SAFE_INTEGER) | 0))) >>> 0)); }); testMathyFunction(mathy1, [0x07fffffff, Number.MAX_VALUE, Math.PI, -(2**53+2), 0.000000000000001, -(2**53), -Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, 1, -0, -0x100000000, 0x080000000, -(2**53-2), -0x0ffffffff, 0x080000001, -0x080000000, 42, 2**53+2, 1/0, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -1/0]); ");
/*fuzzSeed-244067732*/count=1518; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul((Math.asin(x) & Math.max(((x << 1/0) | 0), (x | 0))), Math.min(Math.ceil((2**53 < Math.clz32(x))), ( - (Math.expm1(-Number.MAX_VALUE) >>> 0)))); }); testMathyFunction(mathy0, [(new Number(0)), [0], NaN, '', objectEmulatingUndefined(), /0/, (new Boolean(false)), '0', ({valueOf:function(){return 0;}}), (new Boolean(true)), true, -0, null, (new Number(-0)), 1, ({valueOf:function(){return '0';}}), 0.1, undefined, ({toString:function(){return '0';}}), 0, (new String('')), false, [], (function(){return 0;}), '/0/', '\\0']); ");
/*fuzzSeed-244067732*/count=1519; tryItOut("/*tLoop*/for (let d of /*MARR*/[false, false, false,  /x/g ,  '' ,  /x/g ,  '' , null, false,  /x/g ,  /x/g , false,  '' ,  /x/g ,  '' , null,  '' ,  /x/g , false,  '' ,  '' ,  /x/g ,  /x/g , false,  /x/g ,  '' ,  /x/g ,  /x/g , null,  '' ,  /x/g , false, null, false,  '' , false, false,  '' , null, null, false,  '' ,  '' ,  '' , false,  /x/g ,  /x/g ,  /x/g ,  '' ,  /x/g , null,  '' ,  '' ,  '' ,  /x/g ,  /x/g , null]) { /*MXX1*/Object.defineProperty(this, \"o0\", { configurable: new 7( '' , window), enumerable: true,  get: function() {  return g2.URIError.length; } }); }");
/*fuzzSeed-244067732*/count=1520; tryItOut("\"use strict\"; b2 + '';");
/*fuzzSeed-244067732*/count=1521; tryItOut("print(uneval(h0));print(null);");
/*fuzzSeed-244067732*/count=1522; tryItOut("\"use strict\"; b0 = a1[9];");
/*fuzzSeed-244067732*/count=1523; tryItOut("mathy5 = (function(x, y) { return Math.sign((Math.fround(Math.pow(((mathy1((mathy3(( - y), x) >>> 0), (Math.imul(Math.imul(Math.fround(x), ( + (( + -Number.MAX_VALUE) / y))), (2**53 ? (( - (Math.sign(x) | 0)) | 0) : mathy2(y, y))) >>> 0)) >>> 0) | 0), (Math.cbrt(Math.clz32(x)) | 0))) >>> 0)); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), (new Number(-0)), /0/, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), true, (new String('')), '/0/', undefined, (new Number(0)), null, 1, false, (new Boolean(true)), 0.1, [], (function(){return 0;}), ({valueOf:function(){return 0;}}), [0], -0, '\\0', '', '0', NaN, (new Boolean(false)), 0]); ");
/*fuzzSeed-244067732*/count=1524; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.sqrt(Math.fround(Math.cosh(( + Math.atan(y))))), ((( + (( + (Math.asinh(-Number.MIN_VALUE) | 0)) + ( + (mathy0(Math.fround(Math.fround(( ! (y >>> 0)))), (( - ( + ( + ( ~ ( + (( + (x >>> 0)) >>> 0)))))) >>> 0)) >>> 0)))) >> Math.atan2(Math.fround(( + Math.max(( + mathy0(y, Math.min(((mathy0((y >>> 0), y) >>> 0) | 0), ((0x100000000 % x) | 0)))), ( + (Math.pow(Math.fround(( + ( ! ( + y)))), Math.fround(y)) < x))))), (mathy0(((((x >>> 0) ? (y >>> 0) : (( + Math.max(y, x)) >>> 0)) >>> 0) >>> 0), (y | 0)) >>> 0))) | 0)); }); testMathyFunction(mathy1, /*MARR*/[ /x/g , x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Boolean(false)]); ");
/*fuzzSeed-244067732*/count=1525; tryItOut("\"use strict\"; t0.set(o0.o1.g1.o2.a1, v2);");
/*fuzzSeed-244067732*/count=1526; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ((( + (mathy1(Math.fround(( + y)), ( + (x && Math.sinh(Math.clz32(( + Math.tanh(Math.PI))))))) >>> 0)) >>> 0) & ( - ( ~ ( + (mathy1((Math.atan2(( - (y >>> 0)), 1.7976931348623157e308) >>> 0), Math.fround(y)) ** x))))); }); testMathyFunction(mathy4, [-0x07fffffff, -0x080000001, -0x080000000, 0x07fffffff, 0.000000000000001, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 42, 0, 0/0, 0x100000000, 0x0ffffffff, 1, 1.7976931348623157e308, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, -1/0, -0x0ffffffff, 2**53, Math.PI, 1/0, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1527; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.cos(((( ! x) < (Number.MAX_SAFE_INTEGER ? Math.fround(Math.min(-1/0, Math.trunc(-Number.MAX_VALUE))) : y)) == Math.fround((Math.imul(( + -Number.MAX_VALUE), (( + Math.fround(( + ( ! x)))) | 0)) | 0)))); }); testMathyFunction(mathy0, [-(2**53), Number.MIN_VALUE, 1, -0x080000000, 0x080000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 0x100000000, 2**53-2, -0x0ffffffff, 2**53+2, 42, 1.7976931348623157e308, -0x100000000, 0x07fffffff, -0, Math.PI, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -(2**53-2), 0/0, -1/0, -(2**53+2), -0x100000001, 0x080000000, -0x080000001, 0x0ffffffff, 2**53, 1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1528; tryItOut("a0.shift(({/*toXFun*/valueOf: function() { return this; } }));");
/*fuzzSeed-244067732*/count=1529; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -8191.0;\n    i0 = ((0xffffffff) ? (((((1152921504606847000.0) != (-((4.0)))))>>>((i1)+(0xf82a1f13))) > (0x0)) : (i1));\n    i1 = (0xd6a8752f);\n    i0 = (0x9685827e);\n    return +((-1025.0));\n    d2 = (-4097.0);\n    return +((((Float64ArrayView[2])) / ((d2))));\n    switch (((((0x25f19a5b) != (0x23d6a577))-(0xfb17b90b)) | ((0xfc8ec45c)+(0xffffffff)-(0xffffffff)))) {\n      default:\n        i1 = ((0x54ae98e6) != (((/*FFI*/ff(((abs((~~(((x)) % ((-((-16777217.0)))))))|0)))|0))>>>(((d2) >= (-288230376151711740.0))-(i0)-((((0x66cf975c)*0x1a528)|0)))));\n    }\n    (Uint16ArrayView[(((((0x7aee0900)-(0xfce098bb))>>>((i0))) > (((0x84b7767b)-(0xfe7a76eb))>>>(((0x7fffffff) > (0xb7477a7)))))*-0xcc3c1) >> 1]) = ((0x85c2654c));\n    d2 = (-0.015625);\n    d2 = (8589934592.0);\n    (Float32ArrayView[0]) = ((-1.888946593147858e+22));\n    {\n      (Float64ArrayView[((i1)) >> 3]) = ((Float64ArrayView[4096]));\n    }\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: (({caller: 11,  get a()\"use asm\";   var imul = stdlib.Math.imul;\n  var atan = stdlib.Math.atan;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -4.835703278458517e+24;\n    var d4 = -562949953421313.0;\n    var d5 = -513.0;\n    var i6 = 0;\n    var i7 = 0;\n    {\n      d5 = (-4.0);\n    }\n    i7 = (0x257a41d7);\n    {\n      switch (((((~~(-1.125)))) >> (((0x54047b60) ? (-0x1d126ec) : (0xf445d469))))) {\n        case -1:\n          {\n            d4 = (((17.0)) % ((+(-1.0/0.0))));\n          }\n          break;\n        case 0:\n          {\n            i6 = (!(0xee36ef50));\n          }\n      }\n    }\n    (Uint8ArrayView[1]) = ((0x49cbb158)+(0xfdce1369)-(0xfb185b71));\n    {\n      {\n        (Float64ArrayView[((0xcc73b165)+(1)+(0x64db7609)) >> 3]) = (((d4) + ((i7) ? (-((-536870912.0))) : (((d3)) - ((+(0.0/0.0)))))));\n      }\n    }\n    d5 = (+(0.0/0.0));\n    {\n      (Uint16ArrayView[0]) = (-((((((0xeede518b)))>>>((Int8ArrayView[((0x9e8a545e)+(0x9ecf10b0)+(0x121f8bd4)) >> 0])))) ? (i2) : (i2)));\n    }\n    d4 = (+(imul((i7), (0x35d8d8ac))|0));\n    i6 = (-0x638150f);\n    (Int16ArrayView[(((d4) < (+atan(((1152921504606847000.0)))))) >> 1]) = ((0x205437cb) / (0x354ffa7e));\n    i7 = (0xfa99db20);\n    return (((+(-1.0/0.0))))|0;\n  }\n  return f; }\u0009))}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53+2), -(2**53), -0x07fffffff, 0x100000000, -1/0, 0x0ffffffff, 1.7976931348623157e308, 2**53-2, 42, -0, -0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, 0, -Number.MAX_VALUE, 0.000000000000001, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, 1, Number.MAX_VALUE, 0x100000001, 0x07fffffff, -0x080000001, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, 0/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2]); ");
/*fuzzSeed-244067732*/count=1530; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, -(2**53-2), 0x080000000, 0.000000000000001, 0x100000001, 0/0, 42, 1.7976931348623157e308, -0x100000000, 2**53-2, 0x100000000, -(2**53), -Number.MAX_VALUE, 2**53, -(2**53+2), 0, -1/0, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, -Number.MIN_VALUE, 0x0ffffffff, -0x080000001, 1/0, Number.MAX_VALUE, -0x080000000, 0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1531; tryItOut("/*bLoop*/for (var nmmogs = 0; nmmogs < 27; ++nmmogs) { if (nmmogs % 2 == 0) { window; } else { a2[7] = o2; }  } , x, \u3056 =  '' , qnxfyi, qsqlfy, syaqlu, lanezq, hjsfax, truxtr;this.v1 = t2.length;");
/*fuzzSeed-244067732*/count=1532; tryItOut("\"use strict\"; v0 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (function (z = x) { a1 = Array.prototype.slice.apply(a1, [NaN, -2, i0]); } ), sourceIsLazy: /\\B[^]|\\w[]*|(?:\\cV)|[^]\\W(?!(?:\\cQ(?:[^\\d\\T-\u1879\\\u5adb]))K)\\B|\\cA.|(?:\\x61)|(?:.)?/, catchTermination: true }));");
/*fuzzSeed-244067732*/count=1533; tryItOut("const o0 = Object.create(x);");
/*fuzzSeed-244067732*/count=1534; tryItOut("\"use strict\"; \"use asm\"; v0 = Object.prototype.isPrototypeOf.call(b2, g0);");
/*fuzzSeed-244067732*/count=1535; tryItOut("try { true; } catch(x) { throw \"\\u73DC\"; } finally { print(-16); } with({}) { this.zzz.zzz; } ");
/*fuzzSeed-244067732*/count=1536; tryItOut("return;v0 = Object.prototype.isPrototypeOf.call(e2, g1.o0);");
/*fuzzSeed-244067732*/count=1537; tryItOut("\"use asm\"; print(uneval(h0));");
/*fuzzSeed-244067732*/count=1538; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy0((( + Math.hypot(( + (((Math.cbrt(((((y / y) ? (Math.pow((x >>> 0), Math.fround(y)) >>> 0) : y) << y) >>> 0)) >>> 0) >>> 0) ? 1.7976931348623157e308 : ( + y))), ( + Math.abs(42)))) >>> 0), (Math.pow(mathy0((( ~ (( + ( + ( + -Number.MIN_VALUE))) | 0)) >>> 0), ( + (Math.fround(Math.pow(Math.fround(y), (Math.log1p(Math.fround(x)) | 0))) >>> 0))), Math.fround(mathy1(Math.fround((((y >>> 0) && 0) >>> 0)), Math.fround((y ** (-0x0ffffffff | 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, 2**53-2, 1/0, -0x0ffffffff, Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, 0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, -0x100000000, 0.000000000000001, 0, -Number.MIN_VALUE, 0x100000000, -0x080000001, 42, Number.MIN_SAFE_INTEGER, 1, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000, -(2**53-2), Math.PI, -0x100000001, -0, 2**53, -1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1539; tryItOut("v1 = g0.runOffThreadScript();");
/*fuzzSeed-244067732*/count=1540; tryItOut("/*hhh*/function csooph(...y){v1 = (a2 instanceof m2);}/*iii*/const ywcuvn;[[1]];");
/*fuzzSeed-244067732*/count=1541; tryItOut("\"use strict\"; v1 = g2.eval(\"function f2(g2) \\\"use asm\\\";   function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var d2 = -129.0;\\n    var d3 = -144115188075855870.0;\\n    return +((((((-0x300a34a)-(1)) ^ (((0x6a0fbfd) >= (0x1b636bcc))-((/*RXUE*//(?!\\\\3)|[^]?/yi.exec(\\\"\\\"))))) < ((-((0xffffffff) == (0xfed98819)))|0)) ? (d3) : (-8388609.0)));\\n  }\\n  return f;\");");
/*fuzzSeed-244067732*/count=1542; tryItOut("iwwnqy, woxdur, gkhgpp;for (var v of o1.h2) { try { this.g2.o0.s1 = this.o0.g1.m1.get(e1); } catch(e0) { } try { g0.v2 = evaluate(\"s2 + '';\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 3), noScriptRval: \"\\u31D5\", sourceIsLazy:  '' , catchTermination: 5 })); } catch(e1) { } try { b2 = t2.buffer; } catch(e2) { } o2.m2 = new Map(p1); }");
/*fuzzSeed-244067732*/count=1543; tryItOut("a0 = arguments;");
/*fuzzSeed-244067732*/count=1544; tryItOut("const \u3056;{ void 0; abortgc(); }");
/*fuzzSeed-244067732*/count=1545; tryItOut("\"use strict\"; for (var v of m1) { try { g0.offThreadCompileScript(\"\\\"use strict\\\"; this.h2.iterate = f1;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 3), noScriptRval: true, sourceIsLazy: false, catchTermination: true })); } catch(e0) { } Object.defineProperty(this, \"o0\", { configurable: false, enumerable: false,  get: function() {  return {}; } }); }");
/*fuzzSeed-244067732*/count=1546; tryItOut("\"use strict\"; o2.s1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    switch ((imul((0xfca5d99a), ((0x1092d8fa) >= (0xa272560f)))|0)) {\n      default:\n        return +((((+(1.0/0.0))) * ((-16777217.0))));\n    }\n    d1 = (1.5474250491067253e+26);\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: Math.trunc}, new ArrayBuffer(4096));");
/*fuzzSeed-244067732*/count=1547; tryItOut("/*RXUB*/var r = /.*|([\\v\\S])*|\\s{1,3}{2,4}|(?:[^])?/ym; var s = (); print(s.search(r)); ");
/*fuzzSeed-244067732*/count=1548; tryItOut("mathy2 = (function(x, y) { return ( + Math.asin(( + (( + (Math.pow(( + Math.atan((Math.atan2(y, 2**53) >>> 0))), ((x / 42) | 0)) >>> 0)) + ( + (((mathy0(Math.fround(x), y) ** Math.fround(Math.round(( + y)))) | 0) ^ -0x080000000)))))); }); testMathyFunction(mathy2, [0x07fffffff, -0, 0x0ffffffff, 0.000000000000001, 0x100000000, -(2**53-2), 2**53+2, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 1/0, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, -(2**53+2), -0x100000001, -1/0, -(2**53), 0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 42, 0x080000001, 0, -0x07fffffff, 1, -Number.MAX_VALUE, 0/0, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1549; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1550; tryItOut("\"use strict\"; e1.toSource = Math.log2;");
/*fuzzSeed-244067732*/count=1551; tryItOut("\"use strict\"; /*infloop*/M:for(var z; this; w =>  { return (4277) } .prototype) print(2);function z(x, d) { s2 = Array.prototype.join.apply(a0, [s1, this.o1.f0]); } Array.prototype.unshift.apply(o1.a2, [s1, v0]);");
/*fuzzSeed-244067732*/count=1552; tryItOut("{if((x % 4 != 1)) {ihecmc(\"\\u36EA\",  \"\" );/*hhh*/function ihecmc(...z){print(this);} } }");
/*fuzzSeed-244067732*/count=1553; tryItOut("this.o2.v0 = g0.runOffThreadScript();");
/*fuzzSeed-244067732*/count=1554; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a1, [(function() { for (var j=0;j<45;++j) { f1(j%5==0); } })]);");
/*fuzzSeed-244067732*/count=1555; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(( + Math.log(( + Math.atan2(Math.fround((Math.hypot(( + Math.hypot(((y ? -1/0 : (y >>> 0)) | 0), x)), ( + y)) | 0)), Math.fround(((2**53-2 != (x >>> 0)) !== -0x100000001))))))) > (( ~ (Math.atan(x) | 0)) | 0)) !== (( - ((Math.sinh(-0x080000000) >>> 0) * y)) >>> 0)); }); testMathyFunction(mathy1, [[], undefined, (function(){return 0;}), ({toString:function(){return '0';}}), 0.1, 0, '\\0', (new String('')), (new Boolean(false)), -0, /0/, '/0/', (new Number(0)), '0', (new Number(-0)), null, '', [0], objectEmulatingUndefined(), NaN, false, true, ({valueOf:function(){return 0;}}), 1, (new Boolean(true)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-244067732*/count=1556; tryItOut("mathy0 = (function(x, y) { return ( + Math.expm1((((( + Math.clz32(( + ((y >>> 0) ? (Math.fround(Math.min((x >>> 0), ( + x))) >>> 0) : (Math.fround(Math.expm1(x)) >>> 0))))) | 0) ? (Math.fround((Math.fround(Math.fround(Math.tan(( + ((( + Math.atanh(( + (( - (x >>> 0)) >>> 0)))) >>> 0) + ( + ( + x))))))) ** Math.fround(( + ((y + ( + Math.round(( + -0x07fffffff)))) && ( + Math.fround(Math.log((Math.clz32(x) | 0))))))))) | 0) : ( + (Math.abs(( + (y > Math.log(Math.fround((Math.fround(y) ? Math.fround(y) : Math.fround(-Number.MIN_SAFE_INTEGER))))))) | 0))) >>> 0))); }); testMathyFunction(mathy0, [0x100000001, 0x080000000, 1, 2**53-2, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE, 2**53, 0x0ffffffff, 0, -(2**53), -(2**53-2), 0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, -0x080000000, -0x0ffffffff, -0, 42, -Number.MIN_VALUE, 0.000000000000001, -0x100000001, 0x100000000, 0/0, 1/0, -0x100000000, -1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1557; tryItOut("mathy5 = (function(x, y) { return (Math.hypot(( + (((Math.imul((x >>> 0), ( + Math.cos((0x080000000 >>> 0)))) | 0) ? (Math.atan(mathy1(y, x)) | 0) : (((x == ( ~ (x >>> 0))) && ( + Math.pow(Math.PI, (0x0ffffffff && y)))) | 0)) | 0)), ( + ( ~ ( + ( + 42))))) | (mathy3(((Math.fround(y) != (mathy3(((y !== -0x07fffffff) >>> 0), (((( + (x | 0)) | 0) + (x >>> 0)) >>> 0)) >>> 0)) >>> 0), ( ~ (Math.fround(-Number.MAX_VALUE) ? Math.fround(Math.fround(Math.atan(Math.fround(-Number.MIN_SAFE_INTEGER)))) : y))) >>> 0)); }); testMathyFunction(mathy5, [-(2**53), 0.000000000000001, 0x100000000, -0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 42, 1, -(2**53-2), -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000001, 1/0, Number.MIN_VALUE, 2**53+2, -0x100000000, 0, -1/0, -0, 0/0, -0x07fffffff, -0x0ffffffff, Math.PI, 0x080000000, -0x100000001, 1.7976931348623157e308, 0x07fffffff, -0x080000001, 2**53, -(2**53+2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1558; tryItOut("\"use strict\"; let(y) { with({}) g0.m1 = t1[6];}");
/*fuzzSeed-244067732*/count=1559; tryItOut("o1.v2 + '';function w()xi0.next();");
/*fuzzSeed-244067732*/count=1560; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MAX_VALUE, 2**53+2, -0x100000000, 0x0ffffffff, 1, -Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 0x080000001, -0, Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 0x100000000, 1/0, -Number.MAX_VALUE, 0x080000000, 0x100000001, 42, -0x080000001, -(2**53-2), 2**53-2, 0/0, 1.7976931348623157e308, -1/0, 2**53, 0x07fffffff, -0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 0.000000000000001, 0]); ");
/*fuzzSeed-244067732*/count=1561; tryItOut("for(let z in (objectEmulatingUndefined).apply) \u3056.lineNumber;arguments = e;");
/*fuzzSeed-244067732*/count=1562; tryItOut("mathy2 = (function(x, y) { return ( ! (Math.max(( + ((((mathy1((Math.tan((Number.MAX_SAFE_INTEGER >>> 0)) >>> 0), mathy1(x, y)) >>> 0) | 0) & ((x >> (x >> y)) | 0)) | 0)), Math.fround(Math.atan(Math.atan2(x, Math.fround((Math.fround(x) & Math.fround(y))))))) | 0)); }); ");
/*fuzzSeed-244067732*/count=1563; tryItOut("let(x = -20, thaslq, NaN = Math.hypot(16, -14), z = (void version(180)), xsgvif, b = eval(\"\", -14)) { for(let z in /*MARR*/[null, {}, null, objectEmulatingUndefined(), objectEmulatingUndefined(), WeakSet(-19), WeakSet(-19), WeakSet(-19), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), null, [(void 0)], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, null, [(void 0)], WeakSet(-19), objectEmulatingUndefined(), WeakSet(-19), [(void 0)], objectEmulatingUndefined(), WeakSet(-19), [(void 0)], null, null, {}, objectEmulatingUndefined(), {}, [(void 0)], WeakSet(-19), {}, WeakSet(-19), [(void 0)], WeakSet(-19), {}, objectEmulatingUndefined(), null, WeakSet(-19), WeakSet(-19), [(void 0)], null, objectEmulatingUndefined(), {}, {}, objectEmulatingUndefined(), null, WeakSet(-19), WeakSet(-19), WeakSet(-19), {}, {}, WeakSet(-19), WeakSet(-19), {}, {}, {}, null, [(void 0)], objectEmulatingUndefined(), null, WeakSet(-19), null, objectEmulatingUndefined(), {}, null, null, objectEmulatingUndefined(), {}, WeakSet(-19), null, WeakSet(-19), [(void 0)], [(void 0)], objectEmulatingUndefined(), {}, WeakSet(-19), null, WeakSet(-19), null, null, WeakSet(-19), [(void 0)], objectEmulatingUndefined(), WeakSet(-19), WeakSet(-19), WeakSet(-19), {}, objectEmulatingUndefined(), [(void 0)], {}, null, {}, [(void 0)], objectEmulatingUndefined()]) return;}let(z) { with({}) for(let x in /*FARR*/[, , ((p={}, (p.z = /*UUV1*/(e.repeat = Float32Array))())), Math.imul(x, 15)]) try { try { print(x); } finally { with({}) { with({}) this.zzz.zzz; }  }  } finally { with({}) { w = a; }  } }");
/*fuzzSeed-244067732*/count=1564; tryItOut("yield ((function factorial_tail(itvgfr, ihibtv) { ; if (itvgfr == 0) { window;; return ihibtv; } m2.has(s2);; return factorial_tail(itvgfr - 1, ihibtv * itvgfr); o1.o0.v2 = (o1 instanceof o0.o1); })(1, 1));");
/*fuzzSeed-244067732*/count=1565; tryItOut("\"use strict\"; /*iii*/const c = kjhibl;a1.push(t0, o0.p0);/*hhh*/function kjhibl(c = x, x, a, d, x, a, d, eval, x = --x, x, NaN, x, a, x, w, x = x, window, \u3056, e, x = -20, \u3056 = [1,,], eval, d, w, x, c, x, w, x, y, x, x, x = x, x, d, x = x, x = x, e, x = \"\\u7919\", eval, x, y, b, y, x = /(.\\ud8D0{2,})*?(?=(([\\xCf\\D\\xc5-\u12a3])+?))(?:(\\3)|\\B|[\\cU\\t-\u00f1\\\u5d1e-\ue6d9](?=$))/im, x, window, NaN, a, y, eval, x, w, z, x, x = length, y, w, a, x = Math, e, window =  \"\" , x, this.x = window, a, a = false){with(null){h0.valueOf = (function(j) { f0(j); }); }}");
/*fuzzSeed-244067732*/count=1566; tryItOut("mathy3 = (function(x, y) { return Math.acosh((Math.hypot(( + ( + ( + -0))), (Math.fround(Math.asinh(Math.fround(mathy1((42 | 0), 1/0)))) | 0)) | 0)); }); testMathyFunction(mathy3, [objectEmulatingUndefined(), ({toString:function(){return '0';}}), 0.1, (new Number(0)), '', false, undefined, (function(){return 0;}), NaN, (new Boolean(true)), [], [0], (new Boolean(false)), '\\0', ({valueOf:function(){return 0;}}), (new Number(-0)), null, 1, true, /0/, (new String('')), ({valueOf:function(){return '0';}}), -0, 0, '/0/', '0']); ");
/*fuzzSeed-244067732*/count=1567; tryItOut("for (var v of e2) { try { o1.a2 + a1; } catch(e0) { } e0.delete(a1); }");
/*fuzzSeed-244067732*/count=1568; tryItOut("mathy3 = (function(x, y) { return (( + (mathy2(((Math.sign((Math.pow(-0x0ffffffff, (x ** Math.atan2(y, (Math.cos((y | 0)) | 0)))) | 0)) | 0) >>> 0), (Math.expm1(((( + y) | 0) == (Math.ceil(x) >>> 0))) >>> 0)) >>> 0)) && (( ~ ((Math.pow((( + Math.fround(2**53)) | 0), (x | 0)) | 0) | 0)) | 0)); }); testMathyFunction(mathy3, [2**53+2, -0x080000001, 0x0ffffffff, 2**53-2, Math.PI, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, Number.MIN_VALUE, 42, -0x100000000, 0x07fffffff, 0x100000000, -0, -0x0ffffffff, 1, -(2**53-2), -0x07fffffff, 0x080000001, -(2**53), 0x080000000, 1/0, Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 0x100000001, -0x100000001, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-244067732*/count=1569; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Int32ArrayView[2]) = (((Uint32ArrayView[2]))+(i2));\n    i1 = (((((((0x49b80cd5)) | (((0xffffffff) > (0x928a811b)))) <= (((0x1eb2d36c) % (0x9ff99cff)) >> ((0xc6a09c04)+(0x6a8485be)+(0x5a2517d7))))-(i2)) & ((Int16ArrayView[((i1)) >> 1]))));\n    {\n      {\n        i2 = ((+abs((z | eval))) > (d0));\n      }\n    }\n    i1 = ((~~((+(1.0/0.0)) + (129.0))) == ((((((-0x8000000)-(/*FFI*/ff(((+(-1.0/0.0))), ((1.1805916207174113e+21)), ((9007199254740992.0)))|0)-(i1))|0))) >> (-((~((i1))) > (~(((-0x8000000) ? (0xbeebcf54) : (0xfe94af51))+((0xa6bd2b63))))))));\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: function ()x}, new ArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=1570; tryItOut("");
/*fuzzSeed-244067732*/count=1571; tryItOut("\"use strict\"; print(new (objectEmulatingUndefined)(\"\\u80EF\", ({a1:1})));");
/*fuzzSeed-244067732*/count=1572; tryItOut("mathy5 = (function(x, y) { return ((( + mathy0(( + (mathy3(((Math.pow(y, x) <= ( + mathy2(( + y), ( + x)))) >>> 0), (mathy2(( + ( + mathy1(( + y), x))), ( + x)) >>> 0)) >>> 0)), ( + x))) ? ( + (( + y) !== (( + -Number.MIN_SAFE_INTEGER) === x))) : (Math.pow(x, Math.atan(mathy4((( ~ x) >>> 0), Math.fround(Math.PI)))) | 0)) < (( ! ( + (( + (( ~ (y | 0)) | 0)) === ( + (Math.fround(y) - Math.fround(( + (( + y) | 0)))))))) != (( ~ ( + y)) != (((Math.hypot((42 >>> 0), x) >>> 0) | 0) !== x)))); }); testMathyFunction(mathy5, [1, -(2**53+2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, 42, 2**53, Math.PI, 0x100000001, 0x07fffffff, -(2**53), 2**53+2, 0/0, -0x100000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, -0x100000001, -0x080000000, 0x080000000, 0x080000001, 1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -0x0ffffffff, 2**53-2, -0x080000001, 0x100000000, -0x07fffffff, Number.MIN_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1573; tryItOut("g0.e2.has(b2);");
/*fuzzSeed-244067732*/count=1574; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((( ! (( + Number.MAX_VALUE) << ( + x))) / Math.fround(( + Math.clz32((((x << -1/0) >>> 0) ? (x ? Math.fround(Math.fround(Math.atan2(Math.fround(x), y))) : -0x100000000) : Math.PI))))) >>> 0) && (Math.pow((Math.atan2((Math.acosh(Math.fround(Math.acosh((x | 0)))) >>> 0), Math.max(0.000000000000001, y)) | 0), (( - Math.pow((Math.min(Math.tan(( ! y)), ((( ! x) >>> 0) | 0)) | 0), (x >>> 0))) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[ \"use strict\" ,  '\\0' ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  \"use strict\" ,  '\\0' ,  '\\0' , new Boolean(false), (void 0),  \"use strict\" ,  \"use strict\" , (void 0), new Boolean(false),  '\\0' , new Boolean(false), (void 0), (void 0), (void 0),  \"use strict\" ,  '\\0' ,  '\\0' , (void 0),  '\\0' ,  \"use strict\" , (void 0),  \"use strict\" , (void 0), (void 0),  '\\0' ,  \"use strict\" ]); ");
/*fuzzSeed-244067732*/count=1575; tryItOut("print(p0);");
/*fuzzSeed-244067732*/count=1576; tryItOut("/*hhh*/function wottjz(e, ...z){/*ADP-2*/Object.defineProperty(this.a1, v1, { configurable: true, enumerable: (+\u0009[,]), get: (function() { for (var j=0;j<66;++j) { this.f2(j%3==1); } }), set: (function() { try { /*MXX3*/g0.Math.asin = g1.Math.asin; } catch(e0) { } a0.splice(NaN, 13); return h0; }) });}/*iii*/((4277));for(let z of /*FARR*/[(null.__defineSetter__(\"c\", (wottjz, c, wottjz = this, w, wottjz, b, wottjz =  /x/ , x, e, window, x, c, x, wottjz, b, y, wottjz =  /x/g , wottjz, wottjz = 22, eval, x, y, x, NaN, x, y, \u3056, eval, window, d, wottjz, \u3056, x = this, window, eval, c = x, e = -12, x = wottjz, c = window, this =  \"\" , d = (function ([y]) { })(), c, window, d, y = ({}), x = wottjz, c, c, wottjz, \u3056, d = function(id) { return id }, window, x, wottjz, NaN, x, wottjz = null, wottjz, a, x, z, x, c, x, x =  '' , window) => \"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    switch ((((0x70494ae7)) ^ ((i2)-(0xfc9e8a32)))) {\n      case 1:\n        {\n          {\n            {\n              {\n                d1 = (-0.00390625);\n              }\n            }\n          }\n        }\n        break;\n      case -1:\n        i2 = ((((Uint16ArrayView[((0xf4ea7d20)-(0xfcae0d43)+((65.0) == (1.5))) >> 1]))>>>((0xfcb5d651))) == ((0xbf56e*((0x223c036)))>>>(((((i2)+((0xb45583b0))) >> ((0xfedf7b08))) < (~(-(-0x8000000)))))));\n        break;\n      case -3:\n;        break;\n      case -1:\n        return ((-(0xf30e2ce4)))|0;\n        break;\n      default:\n        i2 = (x);\n    }\n    (Int8ArrayView[(((((0x52d83392))>>>((0xd43c2fe4))) > (((-0x8000000))>>>((0xd377c685))))-(1)-(!(0x1e2a4a09))) >> 0]) = ((0x0) / ((((+(~~(1.5474250491067253e+26))) < (+(~~(-2097153.0)))))>>>((0xfc44991f)-(!(0xcf140af2)))));\n    return (((((0x44cd7*(i2))>>>((i3))) >= (((1)+(0xc63d41e5))>>>((0x86659212) % (((-0x7097333)*0xfffff)>>>((0xff3f5048)*0xfffff)))))-((i2) ? (0xfb256671) : (!(1)))))|0;\n  }\n  return f;))]) let(wottjz, a, rvfaej, celekl, mxsyjc, khvtzw, ppfowd, e) ((function(){;})());");
/*fuzzSeed-244067732*/count=1577; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + ( ! ( + (((((x << ( ! y)) | 0) % 1) | 0) <= x)))) >>> (((((( + Math.acosh(( - 0x080000000))) ^ (y | 0)) <= mathy0((mathy0(x, Math.min(y, x)) >>> 0), (Math.PI ? ( - 1/0) : ( ~ y)))) >>> 0) >> (Math.atan2(y, ( ! mathy0(((((y ^ Number.MIN_SAFE_INTEGER) >>> 0) ** (x >>> 0)) >>> 0), 0x0ffffffff))) | 0)) | 0)); }); ");
/*fuzzSeed-244067732*/count=1578; tryItOut("/*tLoop*/for (let w of /*MARR*/[(4277), new Boolean(false), (4277), new Boolean(false), new Boolean(false), new Boolean(false), (4277), (4277), (4277), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (4277), (4277), (4277), (4277), new Boolean(false), new Boolean(false), new Boolean(false), (4277), (4277), new Boolean(false), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), new Boolean(false), new Boolean(false), (4277), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (4277), new Boolean(false), (4277), (4277), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (4277), new Boolean(false), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), new Boolean(false), (4277), (4277), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (4277), (4277), (4277), new Boolean(false), (4277), (4277), (4277), new Boolean(false), (4277), new Boolean(false), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), new Boolean(false), (4277), new Boolean(false), new Boolean(false), new Boolean(false), (4277), new Boolean(false), new Boolean(false), (4277), new Boolean(false), new Boolean(false), new Boolean(false), (4277), new Boolean(false), (4277), (4277), (4277), (4277), (4277), (4277)]) { Array.prototype.reverse.apply(this.a1, [t0, p2, b1, v1]); }");
/*fuzzSeed-244067732*/count=1579; tryItOut("\"use asm\"; { void 0; bailout(); } for (var p in t2) { m1.set(i2, i2); }");
/*fuzzSeed-244067732*/count=1580; tryItOut("\"use strict\"; [1,,];a1[10];");
/*fuzzSeed-244067732*/count=1581; tryItOut("{ void 0; setGCCallback({ action: \"majorGC\", depth: 1, phases: \"begin\" }); } Array.prototype.forEach.apply(this.a0, [(function() { try { print(uneval(v1)); } catch(e0) { } try { m0.delete(this.v0); } catch(e1) { } try { /*RXUB*/var r = r1; var s = \"\"; print(uneval(s.match(r)));  } catch(e2) { } v2 = g1.t2.BYTES_PER_ELEMENT; throw v1; })]);");
/*fuzzSeed-244067732*/count=1582; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( ! (Math.min(Math.exp(y), Math.max(Math.fround((mathy1((y | 0), y) | 0)), ( + Math.log2(Math.max(-Number.MAX_VALUE, ((Math.sin(y) >>> 0) === x)))))) | 0))); }); testMathyFunction(mathy3, [[], '\\0', (new Boolean(false)), '/0/', (new Number(0)), -0, undefined, (new Number(-0)), (function(){return 0;}), '', '0', NaN, [0], 1, false, 0, ({toString:function(){return '0';}}), /0/, 0.1, ({valueOf:function(){return 0;}}), null, (new String('')), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(true)), true]); ");
/*fuzzSeed-244067732*/count=1583; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(Math.fround(( ! Math.fround(Math.atan2(( + Math.log2(Math.atan2(( ~ ( + Math.imul(( + -(2**53)), Number.MAX_SAFE_INTEGER))), (((x >>> 0) < ((Math.pow((x | 0), x) >>> 0) >>> 0)) >>> 0)))), ( + (( ~ Math.fround(Number.MAX_VALUE)) | 0))))))), Math.fround(Math.abs(mathy1(y, (Math.trunc(((Math.min((x >>> 0), y) >>> 0) | 0)) | 0)))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 0x0ffffffff, 2**53, Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, Math.PI, -0x080000001, -0x0ffffffff, 0x100000000, 0x080000001, -0x100000000, 0/0, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 1, 0x080000000, 2**53-2, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), -0x07fffffff, -1/0, -(2**53), 0x100000001, 42]); ");
/*fuzzSeed-244067732*/count=1584; tryItOut("for (var p in i1) { try { (void schedulegc(g1)); } catch(e0) { } try { e1.has(Math.max(++ '' .__proto__, -9)); } catch(e1) { } try { b2 + a2; } catch(e2) { } for (var p in t1) { try { i0.send(o2.v1); } catch(e0) { } try { h2.delete = f1; } catch(e1) { } m0.has(this.o1.p1); } }");
/*fuzzSeed-244067732*/count=1585; tryItOut("/*RXUB*/var r = r0; var s = s0; print(s.match(r)); print(r.lastIndex); function x(x, x, {\u3056: arguments.callee.arguments, x, x: x}, x, NaN, NaN, a, window, x, b, 3, y, a = x, z = false, y, window, a, x, e, x = /(?!.)/, a, c, a, y, e, x, window, x, \u3056 = \"\\uBCF6\", w, x = /(?=\\1*?){2,}/gm, x = this, \u3056, x, x = -25, x, window, w = -24, x, x, x, z, x = x - x; var r0 = x ^ x; var r1 = r0 ^ r0; r0 = 9 | x; var r2 = 2 ^ 0; var r3 = x * x; var r4 = 7 & r0; r1 = r4 * r0; var r5 = r1 % 2; print(r4); print(r2); r3 = x | x; var r6 = r4 / r5; r5 = r1 + 4; var r7 = 5 / r3; var r8 = 4 % 3; var r9 = r4 & 9; var r10 = r7 / x; var r11 = r0 | r2; r0 = r0 - r10; var r12 = 3 | 2; var r13 = 2 * r7; r1 = 0 | 7; , c, d = z, b, window, eval, y, x, a, b, of, x, e, name, \u3056, x, x = x, a, x, y, x = [,,z1], x, z, a = undefined, y, x, c,  /x/ , c, window, x, x = window, c =  /x/ , x, d, c = a, w, c = /(?!$|(?:[^]|\\b+){68719476737})+?/m, w, x, this, z = this, e, x = \"\\u3450\", w, a, x, x, x, x, c, x, x =  /x/ ) { v0 = (s0 instanceof s1); } g1.offThreadCompileScript(\"v1 = a2.length;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: 2, sourceIsLazy: Math.imul(new Int8Array(null, -22), -2), catchTermination: (x % 37 != 36) }));");
/*fuzzSeed-244067732*/count=1586; tryItOut("mathy2 = (function(x, y) { return (Math.tan(Math.fround((( + (( - x) >>> 0)) ? (((( + Math.log10(( + y))) | 0) + (x | 0)) | 0) : x))) | 0); }); ");
/*fuzzSeed-244067732*/count=1587; tryItOut("\"use strict\"; \"use asm\"; wzaapm( /x/g .__defineSetter__(\"x\", 16), [,,]);/*hhh*/function wzaapm(x = Infinity){print(x);}");
/*fuzzSeed-244067732*/count=1588; tryItOut(";");
/*fuzzSeed-244067732*/count=1589; tryItOut("a0.forEach((function() { try { Array.prototype.unshift.apply(a0, [b0, p2]); } catch(e0) { } try { /*MXX3*/g0.Boolean.prototype.constructor = o2.g0.Boolean.prototype.constructor; } catch(e1) { } m1.delete(b2); return o1; }));");
/*fuzzSeed-244067732*/count=1590; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! Math.max((Math.max(Math.fround(Math.fround(mathy1((( + y) >>> 0), (x >>> 0)))), x) * ( - -0)), Math.hypot(mathy3(( - (( ~ (-Number.MAX_VALUE | 0)) | 0)), (( + ( - ((Math.sinh((0x080000000 >>> 0)) >>> 0) >>> 0))) >>> 0)), (mathy2(((((( ~ ( + x)) | 0) || ( + ( ! 0.000000000000001))) | y) | 0), (Math.fround(Math.sinh(Math.fround(Math.atan2(Math.max(x, -(2**53+2)), y)))) | 0)) | 0)))); }); ");
/*fuzzSeed-244067732*/count=1591; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((0x181df5f6));\n    d1 = (+abs(((4611686018427388000.0))));\n    (Int16ArrayView[((/*FFI*/ff(((~((0xba197caf)+((0x827fb871) ? (0x3e6f60c0) : (0xf6ff5e47))))))|0)) >> 1]) = (((0x4880ef9f) <= (((i0)-((-1048577.0) != (+(1.0/0.0)))+(0xd8685db2)) & ((0xfa61c647)+((+(1.0/0.0)) < (+/*FFI*/ff(((134217729.0)), ((-70368744177665.0)), ((-18446744073709552000.0)))))-(0xf8823dcf))))*-0x25f55);\n    (Float64ArrayView[((-0x8000000)) >> 3]) = ((+(((0x0) % (0x412e81ed))>>>((0xdd129ec5)))));\n    d1 = (+(-1.0/0.0));\n    return +((d1));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, x, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, x, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, Infinity, x, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity]); ");
/*fuzzSeed-244067732*/count=1592; tryItOut("/*infloop*/L:while((Math.max(-14, new RegExp(\"(?=(?=.)|[^])\", \"\"))))with( /x/g )m2 + '';");
/*fuzzSeed-244067732*/count=1593; tryItOut("M:switch(void ((c = \"\\uE780\")).throw(x)) { case x: g0.h1.defineProperty = (function() { e1 + f2; return h1; });break; default: case \"\\u853D\" **  /x/g : /*infloop*/while( /x/ )print(x);break; break;  }");
/*fuzzSeed-244067732*/count=1594; tryItOut("\"use strict\"; const x = ((uneval(yield )));(x && new x());");
/*fuzzSeed-244067732*/count=1595; tryItOut("g0.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: {} = (27.eval(\"print(x);\")), noScriptRval: (x % 3 == 2), sourceIsLazy: Math.cosh(-28), catchTermination: true }));");
/*fuzzSeed-244067732*/count=1596; tryItOut("e2.toString = (function(j) { if (j) { try { a0 = r2.exec(s0); } catch(e0) { } try { Array.prototype.unshift.apply(a2, [a2]); } catch(e1) { } try { o2 = a0[16]; } catch(e2) { } print(m0); } else { try { e2.add(a0); } catch(e0) { } try { function f2(o0)  { \"use strict\"; return //h\no0 }  } catch(e1) { } try { v0 = o0.r0.constructor; } catch(e2) { } selectforgc(o1); } });");
/*fuzzSeed-244067732*/count=1597; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Int16ArrayView[0]) = ((i1));\n    return ((((0x1b288157) > (0x849c8156))-(i1)-(0xffffffff)))|0;\n  }\n  return f; })(this, {ff: this}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[-(2**53-2), (1/0), new String('q'), -(2**53-2), (1/0), (1/0), -(2**53-2), (1/0), (1/0), new String('q'), (1/0), (1/0), -(2**53-2), -(2**53-2), (1/0), new String('q'), (1/0), new String('q'), new String('q'), (1/0), (1/0), -(2**53-2), -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=1598; tryItOut("\"use strict\"; e2.toSource = (function(j) { if (j) { try { t2.__iterator__ = (function(j) { f2(j); }); } catch(e0) { } try { m0.set(f2, h2); } catch(e1) { } try { i0 = new Iterator(this.b0); } catch(e2) { } m1.set(b0, s2); } else { try { a1.sort(decodeURIComponent); } catch(e0) { } try { m0 = s0; } catch(e1) { } try { for (var v of this.i2) { try { a2.length = 11; } catch(e0) { } m1 + f2; } } catch(e2) { } m2.has(b2); } });b2.toString = (function() { try { (void schedulegc(g2)); } catch(e0) { } h2.has = o1.f2; return m0; });");
/*fuzzSeed-244067732*/count=1599; tryItOut(";");
/*fuzzSeed-244067732*/count=1600; tryItOut("for([c, a] = [] === -18 ? (makeFinalizeObserver('nursery')) : \n3/0 in false) Array.prototype.push.call(a0, m1);");
/*fuzzSeed-244067732*/count=1601; tryItOut("testMathyFunction(mathy1, [-0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 0x080000001, 0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53+2, 0x07fffffff, -Number.MAX_VALUE, -0x07fffffff, -(2**53), -0x080000001, 0, Number.MIN_VALUE, 42, 1, -1/0, -0x0ffffffff, 0x100000000, 1.7976931348623157e308, 2**53, Math.PI, -(2**53-2), 0x0ffffffff, 1/0, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, -0, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1602; tryItOut("\"use strict\"; \"use asm\"; print(b);(d);");
/*fuzzSeed-244067732*/count=1603; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log(( + Math.fround((Math.min((((Math.fround(((0x07fffffff >>> 0) ^ Math.fround(y))) >>> 0) ? 1.7976931348623157e308 : x) >>> 0), (( ~ -1/0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [42, Math.PI, -(2**53), 1/0, -0x100000001, -0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 1, -0x100000000, 0x080000000, -(2**53+2), 0x100000001, 0.000000000000001, 0/0, 0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, 2**53, 0x0ffffffff, 2**53-2, 0x100000000, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, -1/0, 0, -(2**53-2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-244067732*/count=1604; tryItOut("mathy1 = (function(x, y) { return Math.max(mathy0((( + (Math.cosh(((Math.hypot((y >>> 0), ( + (mathy0((0/0 | 0), (x | 0)) | 0))) >>> 0) >>> 0)) | 0)) | 0), (Math.asin((Math.fround(( + Math.fround(Math.pow(x, ((Math.sinh(y) | 0) | 0))))) >>> 0)) >>> 0)), Math.sign((((((Math.fround((mathy0(x, ( + x)) | 0)) >>> y) | 0) >>> 0) || (Math.fround(mathy0(Math.fround(y), Math.fround(y))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=1605; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( ! (Math.fround(mathy0(Math.sinh(Math.log10(-0x080000000)), ( ! ( + Math.imul(( + (Math.min((( ! y) >>> 0), (0x080000000 >>> 0)) >>> 0)), ( + 2**53+2)))))) >>> 0)) | 0); }); testMathyFunction(mathy2, [0/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 0x100000000, -0x0ffffffff, 0.000000000000001, 2**53-2, 0x080000001, -0x080000000, -(2**53+2), 2**53+2, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, -(2**53), -0, 2**53, 0x0ffffffff, 1/0, 1, 42, 0x07fffffff, -0x080000001, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-244067732*/count=1606; tryItOut("mathy1 = (function(x, y) { return ((( + ( ! Math.min(2**53-2, x))) % ((mathy0((Math.atan2((((Math.hypot((0.000000000000001 | 0), ((Math.min((y | 0), (0 | 0)) | 0) | 0)) | 0) ? Math.log10(x) : (((x >>> 0) && (y >>> 0)) >>> 0)) >>> 0), (( + Math.fround(Math.abs((y >>> 0)))) & ( + Math.hypot(y, y)))) | 0), (Math.imul(Math.abs(x), Math.fround(Math.imul(Math.fround(( - x)), Math.fround(x)))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy1, [0x080000000, -0x100000000, -(2**53), 0.000000000000001, 2**53, -0x07fffffff, 2**53-2, 0, 0x07fffffff, -Number.MIN_VALUE, 1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 1, 0/0, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -1/0, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, -0, Number.MAX_VALUE, 0x0ffffffff, 0x080000001, 1.7976931348623157e308, -(2**53-2), -0x080000000, -0x080000001]); ");
/*fuzzSeed-244067732*/count=1607; tryItOut("\"use strict\"; M:with({c: new (eval)(this).x = (x)})m2.set(b0, (((y) =  /x/g (new (\u3056.getUint32)([[]], new RegExp(\"\\\\3|.|(?!\\\\1)\", \"gyim\")))) !== ('fafafa'.replace(/a/g, decodeURI))));");
/*fuzzSeed-244067732*/count=1608; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1609; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=1610; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1611; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((i0)*-0xfffff))|0;\n  }\n  return f; })(this, {ff: DataView.prototype.setInt32}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[-0x5a827999, 0x40000000, -0x5a827999, 0x40000000, 0x40000000, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, 0x40000000, -0x5a827999, -0x5a827999, 0x40000000, -0x5a827999, 0x40000000, -0x5a827999]); ");
/*fuzzSeed-244067732*/count=1612; tryItOut("mathy4 = (function(x, y) { return ( + ( + ( + ((Math.cos(( ! (Math.imul(y, -0x080000001) | 0))) >>> 0) >> ( - Math.pow(( ! (x && Math.fround(x))), (x > x))))))); }); testMathyFunction(mathy4, [true, (new String('')), '\\0', false, NaN, (new Boolean(true)), '', '0', 0.1, -0, ({valueOf:function(){return '0';}}), (new Boolean(false)), undefined, /0/, (function(){return 0;}), ({toString:function(){return '0';}}), (new Number(0)), null, 1, (new Number(-0)), [0], objectEmulatingUndefined(), 0, ({valueOf:function(){return 0;}}), [], '/0/']); ");
/*fuzzSeed-244067732*/count=1613; tryItOut("(/*RXUE*/new RegExp(\"$|\\\\2|(?:\\\\B)\", \"gyim\").exec(\"\\n\\n\\n\"));\u000d");
/*fuzzSeed-244067732*/count=1614; tryItOut("mathy3 = (function(x, y) { return (((Math.expm1((((( ! (0x080000001 > y)) | 0) & (Math.atan2(( + ( + (-Number.MAX_SAFE_INTEGER ** Math.min((((x | 0) ? (x | 0) : (y | 0)) | 0), x)))), ( + Math.log2(x))) | 0)) | 0)) >>> 0) << (mathy2(((Math.imul(((Math.acosh((( - y) | 0)) >>> 0) | 0), mathy1(x, x)) | 0) | 0), (Math.tanh(( + (( + Math.atanh(y)) == x))) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, -Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 2**53, Math.PI, 1.7976931348623157e308, 0, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 0x100000000, -(2**53), 0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, 0/0, 0x080000000, 42, 0x0ffffffff, -(2**53-2), -0x0ffffffff, -0x100000001, 2**53+2, 0x100000001, 1/0, -0x080000001]); ");
/*fuzzSeed-244067732*/count=1615; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return ( + (( + (( + (mathy3((( ~ (x >>> 0)) >>> 0), Math.imul(((x / (1/0 | 0)) | 0), Math.fround(y))) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [1, false, NaN, 0, undefined, '0', [0], '/0/', '\\0', true, null, (new String('')), (new Boolean(false)), [], 0.1, /0/, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), (new Number(0)), (new Number(-0)), (function(){return 0;}), '', -0, objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new Boolean(true))]); ");
/*fuzzSeed-244067732*/count=1616; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.max((mathy0(( + (Math.log10(Math.fround(Math.max(x, ( + Math.hypot(( + x), y))))) | 0)), (Math.fround(x) << Math.fround((Math.fround(Math.sign(( + Math.min(( + x), Math.fround(x))))) << Math.fround(Math.pow(x, x)))))) >>> 0), (mathy0(( + Math.log(((Math.atan2((Math.max(y, 0x100000000) | 0), y) >>> 0) >>> 0))), (( ~ Math.fround(Math.cos(x))) | 0)) | 0)) | 0) , (( + (mathy0(y, y) > ( + (Math.min((mathy0(( + x), (0x080000000 | 0)) >>> 0), ((Math.imul((x >>> 0), (Math.imul(Math.fround(x), y) >>> 0)) >>> 0) | 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy1, [-0x100000000, Number.MAX_VALUE, 0/0, -(2**53), -0x100000001, 1/0, -Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, Math.PI, -0x080000000, 0x080000000, -Number.MAX_SAFE_INTEGER, -1/0, 2**53, 2**53-2, -0, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, 0x080000001, 0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 42, 0x07fffffff, 1.7976931348623157e308, -0x07fffffff, -(2**53-2), -0x080000001]); ");
/*fuzzSeed-244067732*/count=1617; tryItOut("v0 = g2.eval(\"{selectforgc(g0.g0.o2); }\");");
/*fuzzSeed-244067732*/count=1618; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.atan2(Math.fround(Math.fround(Math.atanh(y))), Math.fround(Math.ceil(Math.atan2(Math.imul((x >>> 0), y), (( ~ (y >>> 0)) >>> 0)))))) << ( + ((Math.fround(( ~ Math.fround(Math.acosh(x)))) >= (Math.max(x, (x | 0)) | 0)) | 0))) < Math.sinh((Math.trunc(Math.sqrt((y << x))) ? (( + ( ! y)) >>> 0) : (( ~ Math.fround(y)) >>> 0)))) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, {}, -0x0ffffffff, (void 0),  /x/ ,  /x/ , objectEmulatingUndefined(), {}, (void 0), objectEmulatingUndefined(),  /x/ , {}, (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), {},  /x/ , {},  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), -0x0ffffffff,  /x/ , (void 0), {}, {},  /x/ , -0x0ffffffff, (void 0), objectEmulatingUndefined(),  /x/ ]); ");
/*fuzzSeed-244067732*/count=1619; tryItOut("/*RXUB*/var r = /[^\\0-\\n]|(\\2){3,7}|.|((?:(?=.(?:.)))|[^]+?)|(?:$+?)\\3|(?:.+?$){4}+/gm; var s =  \"\" ; print(r.exec(s)); e2.delete(s0);");
/*fuzzSeed-244067732*/count=1620; tryItOut("\"use strict\"; var hsetoj = new SharedArrayBuffer(16); var hsetoj_0 = new Int8Array(hsetoj); print(hsetoj_0[0]); hsetoj_0[0] = 26; var hsetoj_1 = new Int16Array(hsetoj); print(hsetoj_1[0]); hsetoj_1[0] = 8; var hsetoj_2 = new Uint16Array(hsetoj); hsetoj_2[0] = -12; /*RXUB*/var r = new RegExp(\"\\\\2|\\\\2?|\\\\2\", \"i\"); var s = \"\"; print(s.replace(r, this, \"gym\")); print(r.lastIndex); /*tLoop*/for (let b of /*MARR*/[hsetoj_1, hsetoj_1, hsetoj_1, {}, {}, {}]) { t2 + ''; }s2 = this.g1.a1[11];{; }this.g2.v0 = (t1 instanceof this.v0);/*RXUB*/var r = new RegExp(\"\\\\1|(?!(?=$|(?:^)*?|\\\\b(?=\\\\b)*){3})\", \"g\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1621; tryItOut("m1.has(h0);");
/*fuzzSeed-244067732*/count=1622; tryItOut("\"use strict\"; if(false) {for (var p in i2) { Object.seal(this.o0.o1); }print( \"\" ); } else  if (((String.prototype.toUpperCase)(\"\\uC942\", undefined))) x = m1;");
/*fuzzSeed-244067732*/count=1623; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, '', [], (function(){return 0;}), (new Boolean(true)), /0/, (new String('')), undefined, true, 1, ({valueOf:function(){return '0';}}), (new Boolean(false)), [0], (new Number(0)), '\\0', 0.1, '0', false, NaN, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), objectEmulatingUndefined(), '/0/', (new Number(-0)), 0, null]); ");
/*fuzzSeed-244067732*/count=1624; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.imul(( - Math.min(( + mathy1(( ~ x), Math.fround((mathy0((1/0 | 0), (( ~ x) | 0)) | 0)))), y)), (Math.pow(Math.fround(mathy1((Math.imul(( + mathy0(( + -Number.MAX_SAFE_INTEGER), ( + Math.tan(y)))), (-Number.MIN_VALUE | 0)) | 0), -0x080000000)), (Math.pow(( + mathy0(x, ( + y))), (x >= (Math.atan2(x, (-Number.MAX_VALUE >>> 0)) >>> 0))) >>> 0)) > (((Math.min(Math.abs(( + 1.7976931348623157e308)), (-0x100000001 | 0)) >>> 0) << (y >>> 0)) ? ( + Math.fround(mathy1(Math.fround(Math.max((Number.MAX_SAFE_INTEGER >>> 0), x)), Math.fround(Math.fround(Math.atan2((x >>> 0), (2**53+2 >>> 0))))))) : mathy1(Math.abs(Number.MIN_VALUE), mathy1(0.000000000000001, -0x080000000))))) >>> 0); }); ");
/*fuzzSeed-244067732*/count=1625; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\nprint(h2);    }\n    i0 = (-0x8000000);\n    d1 = (d1);\n    return +((+((((((Int32ArrayView[((-0x8000000)-(i0)) >> 2]))>>>((0x5db757de))))) << ((0xf361187)+(0xffffffff)))));\n  }\n  return f; })(this, {ff: new RegExp(\".\", \"m\") * window}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000000, 2**53, 0x0ffffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 0, -Number.MAX_VALUE, Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000000, -0x0ffffffff, -0x100000001, 2**53-2, -0x080000000, 2**53+2, -1/0, 0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 1, -(2**53), Number.MAX_VALUE, 1/0, -0, Number.MIN_VALUE, -0x07fffffff, 0/0]); ");
/*fuzzSeed-244067732*/count=1626; tryItOut("\"use strict\"; \"use asm\"; g0.i1.send(m0);");
/*fuzzSeed-244067732*/count=1627; tryItOut("b = x, lizsjh;while((-25) && 0){a2.pop(i1);print(\"\\u5E48\"); }");
/*fuzzSeed-244067732*/count=1628; tryItOut("f1 + a0;");
/*fuzzSeed-244067732*/count=1629; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[objectEmulatingUndefined(),  /x/g , false,  '\\0' , objectEmulatingUndefined(),  /x/g , false, objectEmulatingUndefined(),  /x/g , 0x080000000, objectEmulatingUndefined(),  '\\0' , 0x080000000, 0x080000000,  '\\0' , objectEmulatingUndefined(),  /x/g , 0x080000000, objectEmulatingUndefined(),  /x/g ,  '\\0' , objectEmulatingUndefined(), false,  '\\0' , 0x080000000]) { v1 = o1.t2.length; }");
/*fuzzSeed-244067732*/count=1630; tryItOut("o0.v2 = this.f0[\"z\"];z = (eval(\"Object.prototype.unwatch.call(b1, \\\"y\\\");\"));");
/*fuzzSeed-244067732*/count=1631; tryItOut("mathy4 = (function(x, y) { return (( + Math.min(( + (Math.fround(( ~ Math.fround(x))) ** ((-Number.MIN_VALUE % y) | 0))), ( + Math.max((Math.fround(( + Math.fround(Math.fround(mathy2((x | 0), Math.fround(( ! x))))))) != Math.fround(((x >>> 0) | y))), y)))) === ( + (( + (Math.hypot(( + (( ! (y >>> 0)) >>> 0)), Math.log10(x)) | 0)) != ( + (Math.hypot(x, ( + ((x !== (mathy3((x >>> 0), ((( + y) >>> 0) >>> 0)) >>> 0)) >>> 0))) === Math.fround(Math.cbrt(Math.fround(Math.pow(x, x))))))))); }); ");
/*fuzzSeed-244067732*/count=1632; tryItOut("Array.prototype.shift.apply(a1, [this.f1, o0]);");
/*fuzzSeed-244067732*/count=1633; tryItOut("\"use strict\"; \u3056.lineNumber;with({}) { yield (void options('strict_mode')) && x = Proxy.createFunction(({/*TOODEEP*/})(/(?=\\B{8193,8194}|\\B+?[\\cI\\W]+?\\2\\cC+??)/gm), neuter, offThreadCompileScript); } ");
/*fuzzSeed-244067732*/count=1634; tryItOut("p2[new String(\"-1\")] = b2;");
/*fuzzSeed-244067732*/count=1635; tryItOut("v2 = t1.BYTES_PER_ELEMENT;function c()(4277)((void options('strict')));");
/*fuzzSeed-244067732*/count=1636; tryItOut("testMathyFunction(mathy1, [({toString:function(){return '0';}}), true, [], ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), undefined, 0.1, 0, (function(){return 0;}), 1, '\\0', '', NaN, /0/, (new Boolean(false)), (new Number(-0)), '0', -0, false, (new String('')), '/0/', [0], (new Boolean(true)), (new Number(0)), ({valueOf:function(){return 0;}}), null]); ");
/*fuzzSeed-244067732*/count=1637; tryItOut("g0.h1 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.unshift.apply(a1, [s1]);; var desc = Object.getOwnPropertyDescriptor(o0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { a0.shift();; var desc = Object.getPropertyDescriptor(o0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw b2; Object.defineProperty(o0, name, desc); }, getOwnPropertyNames: function() { m1.delete(t1);; return Object.getOwnPropertyNames(o0); }, delete: function(name) { for (var p in t0) { try { g0.h0 = ({getOwnPropertyDescriptor: function(name) { h1.iterate = (function() { try { v1 = Object.prototype.isPrototypeOf.call(e1, m0); } catch(e0) { } try { ; } catch(e1) { } try { for (var v of o2.e1) { try { h1.hasOwn = (function() { try { /*MXX3*/g2.Object.prototype.__proto__ = g0.Object.prototype.__proto__; } catch(e0) { } try { ; } catch(e1) { } v0 = a1.every((function() { for (var j=0;j<166;++j) { f2(j%2==0); } }), b2); return v0; }); } catch(e0) { } try { /*ODP-1*/Object.defineProperty(this.v2, \"apply\", ({})); } catch(e1) { } v0 = evaluate(\"a0.reverse();\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: let, noScriptRval: (x % 24 != 20), sourceIsLazy: /(?:[^\\S\\d])|\\s|\\b|[\\W\\W\\u000C][^]?(?:\\x70)|\\w+?|(?=\\2){4,}/ym, catchTermination: true })); } } catch(e2) { } a0.unshift(t0, a1); return p1; });; var desc = Object.getOwnPropertyDescriptor(g0.s0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { /*MXX3*/g1.String.prototype.trimLeft = g0.String.prototype.trimLeft;; var desc = Object.getPropertyDescriptor(g0.s0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e1.add(e1);; Object.defineProperty(g0.s0, name, desc); }, getOwnPropertyNames: function() { v2 = undefined;; return Object.getOwnPropertyNames(g0.s0); }, delete: function(name) { o2 = Object.create(h2);; return delete g0.s0[name]; }, fix: function() { /*ODP-2*/Object.defineProperty(h0, \"__iterator__\", { configurable: (x % 2 == 1), enumerable: (x % 14 != 12), get: (1 for (x in [])), set: (function() { try { m2.has(e2); } catch(e0) { } try { g1.v2 = Array.prototype.some.call(a0, (function() { try { h2.hasOwn = f2; } catch(e0) { } try { ; } catch(e1) { } try { v2 = -0; } catch(e2) { } v1 = g2.eval(\"function f0(h1) \\\"use asm\\\";   function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    d1 = (+(-1.0/0.0));\\n    return +((d1));\\n  }\\n  return f;\"); return m2; }), i1, a0); } catch(e1) { } try { f1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 2305843009213694000.0;\n    var i3 = 0;\n    (Float32ArrayView[((((i3)+(i3)+((((0x25bf7af6))>>>((-0x8000000))))) & ((0xb934de01)))) >> 2]) = ((+((((1))-((((0x54dbe027) % (0xec867ae))>>>((0x5bb0db0b))))-((d2) < (d0)))>>>(((-1125899906842625.0) == ((295147905179352830000.0) + (d1)))))));\n    d1 = (((-131073.0)) * (((1) ? (-257.0) : (Infinity))));\n    {\n      return +((d1));\n    }\n    {\n      i3 = (0xf6a7fc4c);\n    }\n    return +((+((Infinity))));\n  }\n  return f; }); } catch(e2) { } m1.delete(this); return p2; }) });; if (Object.isFrozen(g0.s0)) { return Object.getOwnProperties(g0.s0); } }, has: function(name) { m0.has(i1);; return name in g0.s0; }, hasOwn: function(name) { print(uneval(h2));; return Object.prototype.hasOwnProperty.call(g0.s0, name); }, get: function(receiver, name) { Array.prototype.splice.call(a2, NaN, v0, this.s2, m1);; return g0.s0[name]; }, set: function(receiver, name, val) { throw f0; g0.s0[name] = val; return true; }, iterate: function() { b1 = g1.t2.buffer;; return (function() { for (var name in g0.s0) { yield name; } })(); }, enumerate: function() { m1.set(m1, this.v0);; var result = []; for (var name in g0.s0) { result.push(name); }; return result; }, keys: function() { ;; return Object.keys(g0.s0); } }); } catch(e0) { } try { e0.has(h1); } catch(e1) { } try { print(f0); } catch(e2) { } Array.prototype.pop.call(a1); }; return delete o0[name]; }, fix: function() { o1 = o0.f2;; if (Object.isFrozen(o0)) { return Object.getOwnProperties(o0); } }, has: function(name) { /*ADP-1*/Object.defineProperty(a1, 0, ({value: Math.sqrt(-11), configurable: false, enumerable: (([]) = Math.tanh(12))}));; return name in o0; }, hasOwn: function(name) { const h1 = ({getOwnPropertyDescriptor: function(name) { t1 = new Uint32Array(t0);; var desc = Object.getOwnPropertyDescriptor(o0.f1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g1.i2.next();; var desc = Object.getPropertyDescriptor(o0.f1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw i1; Object.defineProperty(o0.f1, name, desc); }, getOwnPropertyNames: function() { for (var p in this.o2) { try { o0 = {}; } catch(e0) { } this.g1.offThreadCompileScript(\"for (var p in m0) { try { a2.reverse(t2); } catch(e0) { } try { for (var v of p2) { m2.has(({})); } } catch(e1) { } try { /*MXX3*/g1.ArrayBuffer.prototype = this.g1.ArrayBuffer.prototype; } catch(e2) { } i1.toSource = (function() { for (var j=0;j<16;++j) { this.f2(j%2==0); } }); }\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 11 == 4), catchTermination: true })); }; return Object.getOwnPropertyNames(o0.f1); }, delete: function(name) { throw o0.h0; return delete o0.f1[name]; }, fix: function() { this.g0.offThreadCompileScript(\"m0 = new WeakMap;\", ({ global: g2.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: x = Proxy.createFunction(({/*TOODEEP*/})(\"\\uC7A9\"), (1 for (x in [])), /*wrap2*/(function(){ \"use strict\"; var jmirsu =  \"\" ; var nekhbf = Math.trunc; return nekhbf;})()), catchTermination: true }));; if (Object.isFrozen(o0.f1)) { return Object.getOwnProperties(o0.f1); } }, has: function(name) { Object.preventExtensions(i2);; return name in o0.f1; }, hasOwn: function(name) { v1 = g2.runOffThreadScript();; return Object.prototype.hasOwnProperty.call(o0.f1, name); }, get: function(receiver, name) { g1.v2 = (v2 instanceof h2);; return o0.f1[name]; }, set: function(receiver, name, val) { Array.prototype.push.apply(a1, [this.v0, (void options('strict')) < x, this.o2, v0]);; o0.f1[name] = val; return true; }, iterate: function() { v0 = this.o2.a1.length;; return (function() { for (var name in o0.f1) { yield name; } })(); }, enumerate: function() { t0 = new Int8Array(a2);; var result = []; for (var name in o0.f1) { result.push(name); }; return result; }, keys: function() { v2 = false;; return Object.keys(o0.f1); } });; return Object.prototype.hasOwnProperty.call(o0, name); }, get: function(receiver, name) { h0 = g2.objectEmulatingUndefined();; return o0[name]; }, set: function(receiver, name, val) { selectforgc(o1);; o0[name] = val; return true; }, iterate: function() { h1 + '';; return (function() { for (var name in o0) { yield name; } })(); }, enumerate: function() { v1 = evaluate(\"/*ODP-1*/Object.defineProperty(h2, \\\"link\\\", ({get: Date.prototype.getMonth, set: encodeURI, configurable: (x % 99 == 74)}));\", ({ global: this.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 2), noScriptRval: (x % 3 == 0), sourceIsLazy: false, catchTermination: yield x = this.x }));; var result = []; for (var name in o0) { result.push(name); }; return result; }, keys: function() { Object.defineProperty(this, \"i0\", { configurable: true, enumerable: false,  get: function() {  return a1.iterator; } });; return Object.keys(o0); } });");
/*fuzzSeed-244067732*/count=1638; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0, -0x080000001, Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), 1/0, 0/0, -(2**53+2), 0.000000000000001, -0x100000000, 1, 42, 0, -Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, 2**53+2, 0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, -0x07fffffff, -1/0, 0x0ffffffff, -0x0ffffffff, 0x07fffffff, -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1639; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1640; tryItOut("\"use strict\"; let y = x, w, fxkewo, b = x, x = Object.is, \"-25\" = (yield \"\\uB82D\").eval(\"[,,z1]\"), x, eval, x =  /x/g ;Array.prototype.push.apply(a2, [o0, a2]);");
/*fuzzSeed-244067732*/count=1641; tryItOut("\"use strict\"; this.zzz.zzz;\nthis.v0 = t2.length;\n");
/*fuzzSeed-244067732*/count=1642; tryItOut("o1 = f0.__proto__;");
/*fuzzSeed-244067732*/count=1643; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.tan(Math.fround(mathy0((Math.max(mathy0((mathy0(y, Math.fround(-0)) | 0), (-Number.MIN_VALUE | 0)), 2**53) * ((y ? (( + x) | 0) : (x | 0)) | 0)), (Math.sqrt(y) | 0)))) != Math.fround(Math.clz32((( + 2**53-2) ? Math.sinh(( + Math.atan(y))) : (x | 0))))); }); testMathyFunction(mathy1, /*MARR*/[1.3, 1.3, 1.3, new Boolean(true), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), 1.3, (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), new Boolean(true), new Boolean(true), 1.3, 1.3, new Boolean(true), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), 1.3, 1.3, (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), 1.3, 1.3, 1.3, (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), new Boolean(true), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), 1.3, 1.3, (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), new Boolean(true), 1.3, new Boolean(true), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), 1.3, (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), new Boolean(true), new Boolean(true), (x = \"\\u0CEB\"[\"valueOf\"] = z %= x\u000c), 1.3]); ");
/*fuzzSeed-244067732*/count=1644; tryItOut("g1.a2 = r2.exec(s2);");
/*fuzzSeed-244067732*/count=1645; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-244067732*/count=1646; tryItOut("t2[13] =  /x/g ;/*RXUB*/var r = new RegExp(\"(?!.){0,1}\", \"ym\"); var s = \"\\n\\n\"; print(s.replace(r, (makeFinalizeObserver('nursery')))); ");
/*fuzzSeed-244067732*/count=1647; tryItOut("\"use strict\"; i1.next();");
/*fuzzSeed-244067732*/count=1648; tryItOut("mathy0 = (function(x, y) { return ( + ( + (( + Math.abs(Math.exp(Math.cbrt(x)))) - ( + Math.abs(Math.fround(( + Math.fround(x)))))))); }); ");
/*fuzzSeed-244067732*/count=1649; tryItOut("/*RXUB*/var r = /\\b\\2+?.|[^](\\W)\\W.(?!.|.){4,4}(?!\\xC0|\\D)|(?!.)|[^]+?{2}|(?!(?:\\1)){2,6}/y; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-244067732*/count=1650; tryItOut("Object.seal(f0);");
/*fuzzSeed-244067732*/count=1651; tryItOut("mathy4 = (function(x, y) { return mathy2(mathy3((Math.cos(( ~ ( + mathy0(x, 0x100000001)))) >>> 0), Math.hypot((y << 0), Math.fround(((x ? y : (Math.atanh((x | 0)) | 0)) >>> 0)))), (Math.pow(( + ( ~ ( + y))), ( + Math.fround(Math.asin(Math.fround(((((( + Math.sign(Math.cos(/*MARR*/[{}, {}, null, {}, {}, {}, {}, {}, null, new String('q'), new String('q'), null, {}, null, null, new String('q'), new String('q'), {}, new String('q'), new String('q'), {}, {}, {}, -0.482, null, -0.482, new String('q'), new String('q'), -0.482, -0.482, -0.482, {}, {}, new String('q')]))) | 0) * (0.000000000000001 ? x : (x | 0))) | 0) % ( + ( - ( + x))))))))) | 0)); }); testMathyFunction(mathy4, /*MARR*/[new Boolean(false), function(){}, eval, new Boolean(false), function(){}, true, function(){}, function(){}, eval, eval, true, eval, function(){}, new Boolean(false), true, eval, true, eval, true, true, eval, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), true, true, new Boolean(false), function(){}, new Boolean(false), eval, new Boolean(false), new Boolean(false), eval, eval, new Boolean(false), function(){}, eval, function(){}, function(){}, function(){}, new Boolean(false), true, true, eval, new Boolean(false), true, function(){}, eval, true, true, function(){}, true, new Boolean(false), eval, eval, function(){}, new Boolean(false), new Boolean(false), function(){}, function(){}, eval, new Boolean(false), eval, true, eval, true, function(){}, new Boolean(false), eval, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new Boolean(false), function(){}, eval, true, eval, true, function(){}, eval, true, eval, eval]); ");
/*fuzzSeed-244067732*/count=1652; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      switch ((0x5ded323)) {\n        case -3:\n          i0 = (((0xbb4916a1)) ? ((17179869185.0) != (-2048.0)) : ((d1) <= (1073741823.0)));\n          break;\n        case -1:\n          i2 = (i2);\n          break;\n        case -3:\n          {\n            i0 = (!(i0));\n          }\n          break;\n      }\n    }\n    d1 = (+ceil(((d1))));\n    return ((0x993de*(((((d1) >= ((Float64ArrayView[1])))) & (((let (urxphb, x, objhyx, qfntwy, w, x, x, wztsbc) Math.min( /x/g , 18)))-(0xbcd3fba0)-(i0))))))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ Array.prototype.forEach.apply(a2, [(function() { try { s0 += 'x'; } catch(e0) { } this.f0 = Proxy.createFunction(o2.h1, f1, f2); return i2; }), p1]);return Date.prototype.getUTCFullYear})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000001, -Number.MIN_VALUE, -0x080000000, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, Math.PI, Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, 1/0, -1/0, -0x07fffffff, -(2**53), 0, 0/0, 0.000000000000001, -(2**53+2), 2**53, 0x07fffffff, 0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), -0x080000001, 0x100000000, 1.7976931348623157e308, -0x100000000, 42]); ");
/*fuzzSeed-244067732*/count=1653; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + mathy1(( + (( + Math.round(( + x))) , (x >>> (mathy0((( - ( + y)) | 0), (x | 0)) | 0)))), (Math.trunc((( + ( ~ ( + ( ~ x)))) | 0)) | 0))); }); testMathyFunction(mathy3, /*MARR*/[ '\\0' ,  '\\0' , (void 0)]); ");
/*fuzzSeed-244067732*/count=1654; tryItOut(" for  each(let x in (/*FARR*/[true].map(a =>  { return false.throw(26) } ))) {/*tLoop*/for (let a of /*MARR*/[function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}]) { s0 + i0; } }");
/*fuzzSeed-244067732*/count=1655; tryItOut(";");
/*fuzzSeed-244067732*/count=1656; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( ! mathy2((Math.pow(((( + Math.cos(( + Math.fround(( ~ Math.fround(x)))))) - x) | 0), ((( - ( ~ y)) >>> 0) | 0)) | 0), ( ~ ( + ( - ( + ( + Math.pow(y, 0x080000000))))))))); }); testMathyFunction(mathy4, [-(2**53), -0x07fffffff, 0.000000000000001, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, -(2**53+2), Number.MAX_VALUE, -0x100000000, 1/0, -0x100000001, 0x100000001, 0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 2**53-2, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, 1.7976931348623157e308, 1, 0x07fffffff, 0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -0, -1/0, 0/0, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-244067732*/count=1657; tryItOut("{ void 0; minorgc(true); } var fgtlhb = new SharedArrayBuffer(2); var fgtlhb_0 = new Uint32Array(fgtlhb); fgtlhb_0[0] = -29; this.g0.v1 = Object.prototype.isPrototypeOf.call(m0, h0);selectforgc(o2);");
/*fuzzSeed-244067732*/count=1658; tryItOut("\"use strict\"; y, x, \u3056, z;a0.reverse();");
/*fuzzSeed-244067732*/count=1659; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.sqrt(Math.atan2(0x07fffffff, Math.log10(Math.log2((y * -0x07fffffff))))) || Math.atan(( + (Math.pow(((( ! Math.fround(Math.imul((x >>> 0), -(2**53-2)))) >>> 0) !== x), y) > ( + (x == mathy0(Math.pow(((x >>> 0) ** (x | 0)), x), (y % x)))))))); }); testMathyFunction(mathy3, [42, -(2**53-2), -0x100000000, 0x100000000, -0x080000001, Number.MIN_VALUE, -0x080000000, 2**53-2, -0x100000001, 0x07fffffff, Number.MAX_VALUE, Math.PI, 0/0, 1/0, 0x100000001, 0x080000000, -(2**53), 2**53, 1, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -0, -0x07fffffff, 0.000000000000001, 0x0ffffffff]); ");
/*fuzzSeed-244067732*/count=1660; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((+((d0))) < (-3.094850098213451e+26));\n    d0 = (+(1.0/0.0));\n    return +((d0));\n  }\n  return f; })(this, {ff: Promise.all}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x0ffffffff, 0x0ffffffff, 0, 0/0, 0x100000000, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0, -0x100000000, -(2**53+2), -0x080000000, 42, 1, 2**53-2, 1/0, 0x07fffffff, 2**53, 0x100000001, -1/0, -0x07fffffff, 0x080000000, -Number.MIN_VALUE, 0x080000001, -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0.000000000000001, -0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-244067732*/count=1661; tryItOut("\"use strict\"; with({}) { this.zzz.zzz; } return [,];");
/*fuzzSeed-244067732*/count=1662; tryItOut("\"use strict\"; /*hhh*/function mjupqd(...z){Array.prototype.pop.call(a2, this.h1, a2, h2, g1.o2);}mjupqd(Math.imul((4277), ({ set 9(\"\\uC960\".x) { \"use strict\"; return (w = (-17 >  '' )) } , \"-6\": (this.yoyo(new RegExp(\"\\\\3\\\\D|$|$+\\\\2+|\\\\B{3,3}\", \"im\"))) })), x);");
/*fuzzSeed-244067732*/count=1663; tryItOut("");
/*fuzzSeed-244067732*/count=1664; tryItOut("");
/*fuzzSeed-244067732*/count=1665; tryItOut("testMathyFunction(mathy5, [[0], (new Number(-0)), /0/, null, ({toString:function(){return '0';}}), -0, (new String('')), false, objectEmulatingUndefined(), NaN, [], '/0/', '\\0', ({valueOf:function(){return 0;}}), undefined, 0.1, (new Boolean(true)), (new Boolean(false)), '0', (new Number(0)), true, ({valueOf:function(){return '0';}}), 1, 0, '', (function(){return 0;})]); ");
/*fuzzSeed-244067732*/count=1666; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-244067732*/count=1667; tryItOut("testMathyFunction(mathy1, [0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53-2, -(2**53+2), Number.MAX_VALUE, 1.7976931348623157e308, 42, -0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, -0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x100000000, 1, -(2**53-2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), Number.MIN_VALUE, 2**53+2, -0x100000001, 0x080000000, -Number.MAX_VALUE, 0, 2**53, -Number.MIN_VALUE, -0x100000000, 0x07fffffff, 0x080000001, 1/0]); ");
/*fuzzSeed-244067732*/count=1668; tryItOut("\"use strict\"; return;");
/*fuzzSeed-244067732*/count=1669; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2(Math.fround((mathy0((Math.fround(Math.max(( + (( ~ ( ! y)) | 0)), ( + Math.pow(Math.hypot(Math.fround(Math.max(Math.fround(y), Math.fround(( ! 0x100000000)))), ( ! ( + mathy0(( + x), Number.MIN_VALUE)))), ((Math.sign((x >>> 0)) >>> 0) >>> 0))))) | 0), Math.hypot(( + y), (((( + ((Math.fround(x) << ((( ~ x) >>> 0) | 0)) | 0)) >> x) | 0) ? x : ( ~ (y | 0))))) | 0)), Math.fround((Math.abs((Math.acosh((((x >> Math.fround(y)) <= Math.hypot(y, x)) >>> 0)) >>> 0)) & Math.hypot(Math.fround(x), (((-0x07fffffff * y) ? ( + -0) : 0x080000000) >>> 0)))))); }); ");
/*fuzzSeed-244067732*/count=1670; tryItOut("mathy0 = (function(x, y) { return ( + (( ! (Math.min(( + ((( + ((0x0ffffffff ? (x >>> 0) : x) | 0)) | 0) ? x : x)), (x >>> 1)) >>> 0)) , ( + Math.cos((( + Math.fround((x >>> x))) >>> 0))))); }); testMathyFunction(mathy0, [-(2**53+2), 0, -0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0x080000000, 0x100000000, 1, 2**53-2, 1.7976931348623157e308, -0x07fffffff, -(2**53-2), 2**53, 42, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, -0x080000000, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, Math.PI, Number.MAX_VALUE, 2**53+2, -0x100000001, 0.000000000000001]); ");
/*fuzzSeed-244067732*/count=1671; tryItOut("const x.\u3056 = (ReferenceError(window, (new  /x/ (x >>= x)))), hsiqgn;v0 = Object.prototype.isPrototypeOf.call(m0, a2);");
/*fuzzSeed-244067732*/count=1672; tryItOut("/*MXX3*/g1.Object.length = g0.Object.length;");
/*fuzzSeed-244067732*/count=1673; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1674; tryItOut("var hwvduf = new ArrayBuffer(16); var hwvduf_0 = new Uint8ClampedArray(hwvduf); hwvduf_0[0] = 24; var hwvduf_1 = new Float32Array(hwvduf); hwvduf_1[0] = 4; var hwvduf_2 = new Uint16Array(hwvduf); var hwvduf_3 = new Int8Array(hwvduf); hwvduf_3[0] = 14; var hwvduf_4 = new Uint16Array(hwvduf); hwvduf_4[0] = 25; m0.set(h2, b1);f1(f1);t2.set(this.a0, 10);print(hwvduf_0);print(\nhwvduf_0[2]);(-6);");
/*fuzzSeed-244067732*/count=1675; tryItOut("g1.i2.send(o2);");
/*fuzzSeed-244067732*/count=1676; tryItOut("for (var v of f1) { try { print(uneval(m2)); } catch(e0) { } try { v1 = g1.runOffThreadScript(); } catch(e1) { } v1 = evalcx(\"print(-11);\", o2.g0); }");
/*fuzzSeed-244067732*/count=1677; tryItOut("\"use strict\"; testMathyFunction(mathy4, [1/0, 0x100000000, -0, 42, 0x0ffffffff, 0/0, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -0x080000001, 0x080000000, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 2**53+2, -0x07fffffff, 2**53, 1, Number.MAX_VALUE, Math.PI, -1/0, 0, -(2**53), 0x07fffffff, -0x100000001, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1678; tryItOut("b0 + '';");
/*fuzzSeed-244067732*/count=1679; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i1 = ((i0) ? ((0xddc9cc71)) : (((((0xd330b5a0) ? (0xffffffff) : (0x39d2a239))-((0x7fffffff) <= (0x40cd5ce1))) >> ((Uint32ArrayView[1]))) >= (((i0)+(i0)-(i1)) ^ ((i0)))));\n    i0 = (((((~((((((0x58d6faa9))|0) != (((0xffffffff)) << ((0xf9e99841)))))-(i0)))))>>>((/*MARR*/[function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()].sort(runOffThreadScript, return \"\\u70F1\"))-(i1)+((+(0.0/0.0)) < (NaN)))) > ((((Int8ArrayView[((!(i1))) >> 0])))>>>((i1)+(i1))));\n    switch ((((i0)-(i0))|0)) {\n      case -2:\n        return +((-2199023255553.0));\n        break;\n      case -3:\n        i0 = (i0);\n      case 1:\n        i1 = (i0);\n      case 0:\n        {\n          i0 = ((((new ({\"20\": this })((makeFinalizeObserver('nursery'))))(\u0009(intern( /x/ )).fill(undefined, this)))) == (0x3605f485));\n        }\n      case -1:\n        /*FFI*/ff();\n      case -2:\n        i0 = (i1);\n        break;\n    }\n    return +((-33.0));\n    i1 = ((~((i0))) == (((((4277)) == (0x75867c7b))+(i0)-(0xebc36609))|0));\n    i1 = (((-0x2ccae*(!((x))))>>>((i0))) >= (0xb891943e));\n    {\n      i1 = ((-2.4178516392292583e+24) < (-1.888946593147858e+22));\n    }\n    return +((+((new -7(new RegExp(\"(.{16777215,16781312}^+?\\\\W).|\\\\1{3,259}\", \"im\"))))));\n  }\n  return f; })(this, {ff: function shapeyConstructor(wagroy){this[7] = (Math.cbrt).bind();if (wagroy) this[\"arguments\"] = (/(?!(?!$)+|.)|(?!^|\\B)+?|(?:\\uB975|.)|\\B|[^]|\\B?+?/yi).__defineGetter__(\"wagroy\", decodeURIComponent);{ print(wagroy); } return this; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [2**53, 0x080000000, -(2**53), -0x07fffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 1, 0, 0/0, 2**53+2, 42, Number.MIN_VALUE, 0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, -0x0ffffffff, Math.PI, -0, 0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -0x100000001, -0x080000000]); ");
/*fuzzSeed-244067732*/count=1680; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.imul(((((mathy0((Math.hypot((((0/0 | 0) ? Math.fround((Math.cos((y >>> 0)) >>> 0)) : Math.trunc(-0x080000001)) >>> 0), -Number.MIN_SAFE_INTEGER) | 0), (((mathy0((( - x) >>> 0), (y >>> 0)) >>> 0) << x) | 0)) | 0) >>> 0) ? Math.fround((Math.fround((((Math.round(( + (Math.fround(x) - Math.fround(-0x0ffffffff)))) >>> 0) + Math.fround(x)) >>> 0)) ** y)) : Math.fround((Math.fround(2**53) >>> Math.fround(y)))) | 0), (( - (Math.log10(Math.trunc(y)) >>> 0)) & ((y % (y | 0)) | 0))), Math.atan2(Math.fround((y ^ ( - (Math.cos(x) >>> 0)))), (mathy0(( + ( + (( + ( + ((Math.sinh(-0x0ffffffff) | 0) || (y >>> 0)))) % ( + (( + Math.hypot(( + y), ( + y))) === (x >>> 0)))))), ( + ((( + ( ! ( + x))) > (x >>> 0)) >>> 0))) >>> 0))); }); ");
/*fuzzSeed-244067732*/count=1681; tryItOut("a1.toString = (function(j) { if (j) { try { this.v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 12 == 8), noScriptRval: (x % 4 != 0), sourceIsLazy: (x % 27 == 7), catchTermination: true, sourceMapURL: s1 })); } catch(e0) { } try { a1.toSource = (function() { try { v0 = evaluate(\"\\\"use asm\\\"; mathy3 = (function(x, y) { return (4277); }); \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: true, sourceIsLazy: (x % 2 != 1), catchTermination: false })); } catch(e0) { } g0.offThreadCompileScript(\"/*bLoop*/for (var tqrruw = 0, bwbkzu; tqrruw < 139; ++tqrruw) { if (tqrruw % 4 == 0) { throw true; } else { print(-10); }  } \", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: (x % 44 != 20), noScriptRval: (x % 6 == 0), sourceIsLazy:  /* Comment */Math.atan2(26, 27), catchTermination: (x)([]) })); return e1; }); } catch(e1) { } a1.forEach((function() { try { v2 = Object.prototype.isPrototypeOf.call(h2, b2); } catch(e0) { } m2.set(t1, i0); return o2.e0; }), h0); } else { try { m1 + ''; } catch(e0) { } try { this.v0 = evalcx(\"function this.f2(o0.f2) (4277)\", g0); } catch(e1) { } print(a2); } });");
/*fuzzSeed-244067732*/count=1682; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.hypot(( + (Math.imul((mathy1((((Math.imul(-1/0, (Math.ceil((x | 0)) | 0)) >>> 0) ? (((( + ( + Math.imul(( + -0x080000000), ( + 1/0)))) >>> 0) * -Number.MIN_SAFE_INTEGER) >>> 0) : (((42 | 0) * (y | 0)) | 0)) >>> 0), Math.fround(Math.hypot(mathy1(x, x), (y , Math.hypot(x, x))))) >>> 0), (( - ( + (1 & (y | 0)))) >>> 0)) >>> 0)), ( + (( ! y) && mathy1(Math.log(Math.hypot(Math.fround(( ! 2**53+2)), ( + (Math.fround(x) >= ( + x))))), y))))); }); testMathyFunction(mathy2, [1, -0, 42, -(2**53-2), 0.000000000000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0x100000000, 0x080000001, -0x080000001, 0/0, Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 0, 2**53-2, 2**53+2, -1/0, 0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), 0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, Math.PI, 0x0ffffffff, -0x100000001, -0x100000000, -0x07fffffff]); ");
/*fuzzSeed-244067732*/count=1683; tryItOut("var y = \"\\u06CA\";/*MXX2*/o2.g0.Array.prototype.push = o2;");
/*fuzzSeed-244067732*/count=1684; tryItOut("mathy4 = (function(x, y) { return (Math.cosh((Math.atan(Math.cbrt((Number.MAX_SAFE_INTEGER > x))) | 0)) | 0); }); testMathyFunction(mathy4, [-(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, 1/0, 0x07fffffff, -1/0, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53-2), 0, 0x100000000, 0.000000000000001, -0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000001, 0/0, -(2**53+2), 0x0ffffffff, Number.MIN_VALUE, -0x080000000, 2**53+2, -0x100000001, -0x100000000, 0x080000000, 2**53, -0x07fffffff, 1, -0, Number.MAX_VALUE, -0x0ffffffff, 0x080000001, 2**53-2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1685; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions('compartment'); } void 0; } var szcuwx = new SharedArrayBuffer(2); var szcuwx_0 = new Float32Array(szcuwx); szcuwx_0[0] = -18; var szcuwx_1 = new Int8Array(szcuwx); print(szcuwx_1[0]); g0.s2 += s0;o0.v2 = (h0 instanceof a0);");
/*fuzzSeed-244067732*/count=1686; tryItOut("this.s1 = this.s2.charAt(8);");
/*fuzzSeed-244067732*/count=1687; tryItOut("kibrfx(({-29:  \"\"  }));/*hhh*/function kibrfx(){print(o0);}");
/*fuzzSeed-244067732*/count=1688; tryItOut("s2.toSource = (function() { try { a2.push(a1, b2, v2, b2); } catch(e0) { } delete g2[\"w\"]; return o2; });");
/*fuzzSeed-244067732*/count=1689; tryItOut("/*ADP-2*/Object.defineProperty(a1, 16, { configurable: false, enumerable: true, get: f2, set: (function() { a2.splice(-7, x(null)++, t0, h2); return this.v2; }) });");
/*fuzzSeed-244067732*/count=1690; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\s{2,4}|(?=(\\\\3)|.{4,7})|(?!$*){3,7}*\\\\S{4}|.$|\\\\b|[\\\\uA81E\\\\D\\\\D\\\\x9C]\\u3a85{2,}\\\\2?(?:[\\\\W])?|[\\u0084-\\\\uEC7b\\\\s\\\\cE\\\\S]|(?!.|\\\\u00de+*)\", \"\"); var s = x; print(s.replace(r, neuter)); print(r.lastIndex); ");
/*fuzzSeed-244067732*/count=1691; tryItOut("\"use asm\"; svsrhs, ijqlcf, d = this, d = x, x =  '' , ljnmmy, gzjuic, qtpmqr, x, qyyohb;g1.v1 = o0.g1.eval(\"p2 + a0;\");");
/*fuzzSeed-244067732*/count=1692; tryItOut("const w = (4277);{}");
/*fuzzSeed-244067732*/count=1693; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[-0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, false, -0x100000001, false, -0x100000001, false, false, -0x100000001, false, false, false, -0x100000001, -0x100000001, false, false, -0x100000001, -0x100000001, false, -0x100000001, -0x100000001, false, -0x100000001, false, -0x100000001, -0x100000001, false, -0x100000001, false, -0x100000001, -0x100000001, -0x100000001, -0x100000001, false, false, false, false, false, -0x100000001, -0x100000001, -0x100000001, -0x100000001, false, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, false, false, -0x100000001, false, false, -0x100000001, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, -0x100000001, -0x100000001, -0x100000001, false, -0x100000001, -0x100000001, false, -0x100000001]) { t1 = Proxy.create(h0, o2.g1.g1); }");
/*fuzzSeed-244067732*/count=1694; tryItOut("\"use strict\"; \"use asm\"; b = x, bcvlnm, wzqxxf, mzwbnk, a = (4277);/*MXX1*/o0 = g1.Math.max;");
/*fuzzSeed-244067732*/count=1695; tryItOut("\"use strict\"; o1.h0 + '';");
/*fuzzSeed-244067732*/count=1696; tryItOut("while((false) && 0){i2 = t2[ /x/g ]; }");
/*fuzzSeed-244067732*/count=1697; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-244067732*/count=1698; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + (( + ((Math.sin(Math.fround(Math.atan2(mathy0((Math.fround(y) + Math.fround(x)), y), (( ~ Math.fround(y)) | 0)))) | (( ! ((((x >>> 0) , (y ** y)) >>> 0) - ( + Math.fround(( ~ Math.fround(0)))))) | 0)) >>> 0)) * ( + ( + (Math.fround(mathy1(Math.min((((( + y) | 0) ** y) >>> 0), (Number.MAX_SAFE_INTEGER >>> 0)), Math.max(-0x100000001, Math.ceil(Math.fround(y))))) % ( + (Math.abs(1/0) >>> 0))))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0, 1, Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0, -(2**53-2), -(2**53), 2**53, 1.7976931348623157e308, -0x100000000, Math.PI, -(2**53+2), -0x080000001, 0x100000001, 0x0ffffffff, 0x080000000, -0x07fffffff, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 2**53+2, -0x100000001, 0/0, -0x080000000, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-244067732*/count=1699; tryItOut("testMathyFunction(mathy0, [null, false, -0, [], ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), '0', 0.1, '', (new String('')), 0, [0], ({toString:function(){return '0';}}), 1, /0/, (new Boolean(true)), (new Number(0)), (new Number(-0)), (new Boolean(false)), ({valueOf:function(){return '0';}}), (function(){return 0;}), undefined, true, NaN, '/0/', '\\0']); ");
/*fuzzSeed-244067732*/count=1700; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"${4}\", \"gm\"); var s = \"\\u73eb\\n\\u73eb\\n\\u73eb\\n\"; print(r.exec(s)); ");
/*fuzzSeed-244067732*/count=1701; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -1.0625;\n    d3 = (d1);\n    return (((((0xec2058ca)-(0x44841374)-(0xffffffff))>>>(((((-0x8000000)*-0x4f1ec)>>>((0xfce75373)))))) / (((!(0xffffffff))+(i2))>>>((i2)-(0xb8cf8e0a)-((NaN) <= (d1))))))|0;\n  }\n  return f; })(this, {ff: function  e (x, x, x, w, this.c, x, e, eval, x, x =  , NaN, \u3056, x, eval, e, x, window, x, z, x, x, c, eval, b, x, w, window, z, x, w, \u3056, d = 16, x = a, a =  /x/g , y, x = false, y, e, y = window, \u3056, let, y, d, x, x, c, x, window, x, x, a, x, c = \"\\uA791\", x, x, x, \u3056, d, \u3056, NaN, NaN, x = /\\B/m, \u3056, x, x, x = true, NaN, x, x, z, x, eval, x = null, w, x, x, x = ({a2:z2}), b, x, eval, x = \"\\u82E8\", d = \"\\u25FE\", e, z, b, window, \u3056 = undefined, w =  /x/g , c, NaN, y, x) { v0 = evaluate(\"e1.delete(g2.o2);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: \"\\u521B\" })); } }, new ArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=1702; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"function f0(f1) (4277)\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: new ReferenceError(((makeFinalizeObserver('tenured'))), x), noScriptRval: (x % 6 != 0), sourceIsLazy: /*UUV2*/(window.setUTCDate = window.cos), catchTermination: x }));");
/*fuzzSeed-244067732*/count=1703; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ! (Math.clz32((( + ( - (Math.cosh(((( + Math.atan2(( + x), ( + x))) < y) >>> 0)) >>> 0))) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-244067732*/count=1704; tryItOut("mathy5 = (function(x, y) { return (((mathy2(((((2**53+2 | 0) << (( - Math.log1p(( + mathy2((x >>> 0), x)))) | 0)) | 0) >>> 0), (mathy2(( + ( + ( + Math.fround(( + (y >>> 0)))))), Math.hypot((Math.imul((x >>> 0), (y >>> 0)) >>> 0), (Math.min(Math.hypot(y, x), 1.7976931348623157e308) | 0))) >>> 0)) >>> 0) | 0) ? Math.acos(( + (( + mathy0(Math.clz32(( + mathy4(Math.fround(( + (x >>> 0))), Math.min(y, Math.fround(x))))), x)) << (Math.abs((Math.tanh((x >>> 0)) >>> 0)) | 0)))) : (( ! mathy1((mathy0((1/0 % ( + Math.round((y | 0)))), mathy2(y, x)) >>> 0), 2**53-2)) >>> 0)); }); testMathyFunction(mathy5, [2**53+2, 0x100000000, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 0, 0x080000001, 0x100000001, 0.000000000000001, 2**53, 0x080000000, 2**53-2, -0x100000001, -Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 0/0, 42, 0x07fffffff, -0x080000000, Number.MIN_VALUE, -1/0, -0, 1/0]); ");
/*fuzzSeed-244067732*/count=1705; tryItOut("\"use strict\"; /*infloop*/for(var d; (d = d); x) /*infloop*/do (window); while(\"\\u46D9\");");
/*fuzzSeed-244067732*/count=1706; tryItOut("\"use strict\"; t2.set(g1.t1, 6);");
/*fuzzSeed-244067732*/count=1707; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(( ! ( + (((((Math.tanh((1.7976931348623157e308 | 0)) | 0) | 0) ** (Math.acosh(Number.MIN_SAFE_INTEGER) | 0)) | 0) ? Math.hypot(y, ( + mathy0(( + y), ( + (Math.min((x >>> 0), (x >>> 0)) >>> 0))))) : y))), (Math.atan2((((y >>> 0) > (Math.abs(Math.sin(mathy0(x, (y | 0)))) >>> 0)) >>> 0), ( - x)) !== Math.fround((Math.fround(mathy0((((Math.log10(Math.fround(y)) | 0) >>> (( + Math.atan2(( + x), Math.fround(y))) | 0)) | 0), mathy1(( + -1/0), ( + 0x080000001)))) - Math.fround(Math.fround((Math.fround(mathy0(-0x100000001, y)) === Math.fround(( ~ y))))))))); }); testMathyFunction(mathy2, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 0, 2**53-2, 2**53, -0x0ffffffff, Math.PI, -(2**53+2), -0, Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, -Number.MIN_VALUE, 0x080000001, 0x07fffffff, Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, 0.000000000000001, 1, 42, -(2**53-2), -1/0, 1/0, 0/0, -0x080000001, Number.MAX_VALUE, -0x080000000, 0x100000001]); ");
/*fuzzSeed-244067732*/count=1708; tryItOut("testMathyFunction(mathy0, [0x0ffffffff, 2**53+2, Math.PI, 0x100000001, Number.MIN_VALUE, 42, 0.000000000000001, 0x080000001, -0x080000000, -Number.MAX_VALUE, 2**53-2, 2**53, 1, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, 0, -(2**53+2), 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, -(2**53), -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -0x080000001, -0, 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-244067732*/count=1709; tryItOut("testMathyFunction(mathy2, [0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, -Number.MAX_VALUE, -0x100000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0, 2**53-2, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, -(2**53), -Number.MIN_VALUE, 2**53+2, 0.000000000000001, Math.PI, 0x0ffffffff, 0/0, 42, 0x100000001, 0x080000001, 0x100000000, -1/0, Number.MIN_SAFE_INTEGER, 1/0, -0]); ");
/*fuzzSeed-244067732*/count=1710; tryItOut("with({b: ({x: /*RXUE*/x.exec(\"\\u00a41\\n1\\u3ff6\") })}){this.b0.__proto__ = t2; }");
/*fuzzSeed-244067732*/count=1711; tryItOut("xzrcld((9.valueOf(\"number\") -= w.eval(\"/* no regression tests found */\")));/*hhh*/function xzrcld(a, w){/*infloop*/for((window)(window) in allocationMarker()) ;\u0009}");
/*fuzzSeed-244067732*/count=1712; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-244067732*/count=1713; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2(Math.min((Math.min(Math.fround(Math.trunc(Math.fround(((x ^ (y | 0)) | 0)))), Math.imul(x, (Math.abs(x) | 0))) | 0), (Math.pow(( + Math.imul(( + Math.fround(Math.clz32((( + Math.atanh(y)) >>> 0)))), ( + y))), (x >>> 0)) | 0)), (Math.max(( + (x === x)), ((x || Math.atan2((( - x) >>> 0), y)) | 0)) == ( + mathy0((Math.atan(( + (( + Math.max(0x07fffffff, x)) << ( + Number.MIN_VALUE)))) | 0), (( + ((y + 0x07fffffff) != ( + y))) | 0))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0x080000001, 2**53, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, 2**53+2, -0x080000001, 42, Math.PI, 2**53-2, -0x07fffffff, 0x080000000, -(2**53-2), 0/0, 0x100000001, 0.000000000000001, -0x100000001, 1, 1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0, 0x07fffffff, -0, Number.MAX_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, 0x100000000, -0x100000000]); ");
/*fuzzSeed-244067732*/count=1714; tryItOut("print((({delete: let (e = \"\\u45C9\")  ''  })));");
/*fuzzSeed-244067732*/count=1715; tryItOut("a1 = Array.prototype.concat.call(a2);function window(x, let = Math.clz32((w++)), x, z, x, x, \u3056, y = window, \u3056 = (-0x07fffffff), w,   = (4277), z, x, x, w, z, c, \u3056, w, d, x, z, NaN = -4, this.window, \u3056, w, e, w, w = \"\\uEAFE\") { return w } p1.__iterator__ = (function() { for (var j=0;j<76;++j) { this.f0(j%3==1); } });w = Math.max(/[^]/, -17);");
/*fuzzSeed-244067732*/count=1716; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.atan2((x , y), ( + (0.000000000000001 | 0)))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined()]); ");
/*fuzzSeed-244067732*/count=1717; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-244067732*/count=1718; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-244067732*/count=1719; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-244067732*/count=1720; tryItOut("\"use strict\"; g0.g1 + '';");
/*fuzzSeed-244067732*/count=1721; tryItOut("mathy5 = (function(x, y) { return ((( ! ( + ( ! ( + Math.fround(mathy3((y >>> 0), ( + 0))))))) === Math.imul(((Math.hypot((0x07fffffff | 0), (Math.max(y, x) | 0)) >>> 0) | 0), (y | 0))) ? Math.fround(( + (( + Math.fround(( + (Math.ceil((42 >>> 0)) >>> 0)))) !== ( + Math.clz32(Math.min(( ! mathy2(Math.cos(x), 0x080000000)), Math.fround(Math.acos(((mathy1(( + 42), Math.fround(Math.log2(Math.PI))) | 0) >>> 0))))))))) : (Math.sinh(Math.atan2(Math.log1p(( + y)), Math.fround((Math.fround(Math.pow(Math.sinh(y), x)) >= Math.fround(Math.hypot(Math.fround(x), Math.fround(y))))))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[NaN, NaN, ({}),  /x/g , new Boolean(false),  /x/g , NaN, NaN,  /x/g , ({}), new Boolean(false), ({}), NaN, NaN, NaN, ({}), new Boolean(false)]); ");
/*fuzzSeed-244067732*/count=1722; tryItOut("Array.prototype.pop.call(g2.a0, f2, a2);");
/*fuzzSeed-244067732*/count=1723; tryItOut("testMathyFunction(mathy1, [0x0ffffffff, 1, -0x0ffffffff, 0x080000001, 0/0, 0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, -(2**53), 42, 2**53-2, 0, -0x080000000, -1/0, -0x080000001, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, Math.PI, -0, 0x07fffffff, 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-244067732*/count=1724; tryItOut("\"use strict\"; testMathyFunction(mathy2, [[0], 0.1, '/0/', '', ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), [], (new Boolean(true)), null, -0, (new Boolean(false)), (new String('')), ({toString:function(){return '0';}}), (new Number(0)), (function(){return 0;}), ({valueOf:function(){return 0;}}), 0, undefined, (new Number(-0)), NaN, false, 1, /0/, true, '\\0', '0']); ");
/*fuzzSeed-244067732*/count=1725; tryItOut("((this.__defineSetter__(\"\\u3056\", Number.isNaN)));");
/*fuzzSeed-244067732*/count=1726; tryItOut("\"use strict\"; L: m1.get(g2);");
/*fuzzSeed-244067732*/count=1727; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.hypot((Math.expm1(Math.log(x)) | 0), Math.atan2(( ! Math.fround(Number.MAX_SAFE_INTEGER)), y)) <= Math.cos(Math.imul(((( + y) ? 2**53 : Math.hypot(mathy4((2**53 >>> 0), y), x)) | 0), (0x080000000 | 0)))); }); ");
/*fuzzSeed-244067732*/count=1728; tryItOut("a1.pop(p1);");
/*fuzzSeed-244067732*/count=1729; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy1(( ~ (x ? (x >>> 0) : Math.log1p((x | 0)))), Math.fround(Math.max(((Math.sin(( + ( ! ( + 0/0)))) >>> 0) !== y), (( + Math.fround(Math.atan2(Math.fround(x), ( + x)))) >>> 0)))); }); testMathyFunction(mathy3, [-0x080000001, 2**53+2, 2**53-2, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 1/0, Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, Number.MIN_VALUE, -0, 0.000000000000001, 0x100000001, -0x100000001, 0/0, -0x0ffffffff, 0, 1, -0x07fffffff, Math.PI, 0x07fffffff, 0x080000000, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, 42, 0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-244067732*/count=1730; tryItOut("m1.set(p0, o1.a0);");
/*fuzzSeed-244067732*/count=1731; tryItOut("/*RXUB*/var r = r1; var s = \"\\u6ab1\\u6ab1a\"; print(r.test(s)); ");
/*fuzzSeed-244067732*/count=1732; tryItOut("\"use strict\"; g1.o0.v0 = evaluate(\"neuter(b0, \\\"change-data\\\");\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 14 == 2), noScriptRval: (x % 12 != 2), sourceIsLazy: true, catchTermination: (4277), elementAttributeName: s2 }));");
/*fuzzSeed-244067732*/count=1733; tryItOut("this.t2 = o1.t1.subarray(15, 2);");
/*fuzzSeed-244067732*/count=1734; tryItOut("m1.set(a0, g0.p0);");
/*fuzzSeed-244067732*/count=1735; tryItOut("Array.prototype.push.apply(a0, [o2, e2]);");
/*fuzzSeed-244067732*/count=1736; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xfab89356);\n    return (((0xfd4ca764)-(0xfa8168e8)))|0;\n    {\n      i0 = (0x173db33b);\n    }\n    {\n      (Uint32ArrayView[1]) = ((0xf83171e5)+(i0));\n    }\n    d1 = (+/*FFI*/ff(((d1)), ((+(0.0/0.0))), ((((((((0x793e7eb) > (0x1f90080))+(0xfd57e480))>>>((0xfe92d3b8))))-(0x6555f48b))|0))));\n    d1 = (((1048577.0)) % ((-16777215.0)));\n    d1 = (-1.9342813113834067e+25);\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [1/0, 0x080000000, -Number.MIN_VALUE, -(2**53+2), 0x080000001, -0x080000001, Number.MIN_VALUE, -0x07fffffff, -(2**53), Math.PI, 0.000000000000001, -(2**53-2), 2**53+2, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, 0/0, 0x100000001, -0, 42, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, -1/0, 1.7976931348623157e308, 1, 0x100000000, -0x100000001]); ");
/*fuzzSeed-244067732*/count=1737; tryItOut("\"use asm\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +(((!((Int32ArrayView[((((0xffffffff)) ^ ((0xf423ccad))) % (abs((((0xf0e0e972)) >> ((0xf9128999))))|0)) >> 2]))) ? (d1) : (d1)));\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); ");
/*fuzzSeed-244067732*/count=1738; tryItOut("wpgigt(((x).eval(\"/* no regression tests found */\")));/*hhh*/function wpgigt(z, x, ...\u3056){g2.t1 + g1.b0;}");
/*fuzzSeed-244067732*/count=1739; tryItOut("/*RXUB*/var r = x; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-244067732*/count=1740; tryItOut("\"use strict\"; this.b1 = g2.a0[18];");
/*fuzzSeed-244067732*/count=1741; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.log2(Math.sqrt((Math.fround(Math.max(Math.fround(mathy0(-Number.MIN_VALUE, Math.pow(Math.fround(x), 1))), Math.fround(( + (( + Math.min((x >>> 0), (y >>> 0))) & ( + ( + (mathy1((((y >>> 0) || (x >>> 0)) >>> 0), x) << (mathy0(x, x) >>> 0))))))))) >>> 0))); }); testMathyFunction(mathy2, [0.000000000000001, -0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -(2**53+2), 1/0, -0x080000001, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, -1/0, -(2**53), -0x080000000, Math.PI, 42, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, 0x0ffffffff, 0x100000001, Number.MIN_VALUE, 0, -0, -(2**53-2), 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2]); ");
/*fuzzSeed-244067732*/count=1742; tryItOut("e2.has(g2);");
/*fuzzSeed-244067732*/count=1743; tryItOut("/* no regression tests found */");
/*fuzzSeed-244067732*/count=1744; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy3(Math.fround((mathy3(x, Math.log1p((Math.imul((x >>> 0), (x >>> 0)) >>> 0))) - ((x >>> 0) ? ((( + ( + x)) && x) >>> 0) : (y >>> 0)))), Math.fround((Math.atan((Math.hypot(( + ( + ( - ( + Math.fround(( ! Math.fround(( + ( - ( + 42)))))))))), (( + x) / ( + ( + (Math.fround(Math.max(Math.fround(((0x080000001 >>> 0) == (y >>> 0))), Math.fround(x))) % 2**53))))) | 0)) | 0))); }); testMathyFunction(mathy4, [null, -0, (function(){return 0;}), ({valueOf:function(){return '0';}}), '/0/', '0', objectEmulatingUndefined(), true, /0/, (new Number(0)), '', (new Number(-0)), 1, ({toString:function(){return '0';}}), undefined, (new String('')), false, [], (new Boolean(false)), NaN, [0], 0, (new Boolean(true)), '\\0', ({valueOf:function(){return 0;}}), 0.1]); ");
/*fuzzSeed-244067732*/count=1745; tryItOut("M: for  each(z in new RegExp(\"\\\\s|\\\\s??\", \"gyi\")) {const a = (void options('strict_mode'));print(-7); }");
/*fuzzSeed-244067732*/count=1746; tryItOut("\"use strict\"; v2 = a0.length;");
/*fuzzSeed-244067732*/count=1747; tryItOut("/*RXUB*/var r = /(?:(?=[\\v-(\u7acf-\u00e4]+(?=\\u39C5|\\B)*)|$|\\s*\\2{1,3})/m; var s = \"_\\n\\n\\n\\n\\n\\n\\n\\n\\n\\na\"; print(s.match(r)); ");
/*fuzzSeed-244067732*/count=1748; tryItOut("/*tLoop*/for (let b of /*MARR*/[ 'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , false, false,  'A' ,  'A' , false, false,  'A' ,  'A' , false, false,  'A' , false]) { /*RXUB*/var r = new RegExp(\"(?!(?=(.|^+?|.{4,8}){1}){2})*\", \"gi\"); var s = \"\"; print(r.exec(s));  }");
/*fuzzSeed-244067732*/count=1749; tryItOut("mathy4 = (function(x, y) { return ( + ( + Math.max((Math.atanh(Math.hypot(Math.acos((y == Number.MAX_SAFE_INTEGER)), -Number.MIN_SAFE_INTEGER)) | 0), Math.fround(Math.hypot((-0x080000001 ? x : x), Math.hypot(((x | 0) ** ((y >>> 0) ? (x >>> 0) : (y >>> 0))), Math.min(x, (-0x07fffffff >>> 0)))))))); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, new Boolean(false), x, new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new Boolean(false), x, x, new Boolean(false), objectEmulatingUndefined(), new String(''), new String(''), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, new String(''), new String(''), new String(''), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), x, new Boolean(false), objectEmulatingUndefined(), x, x, objectEmulatingUndefined()]); ");
/*fuzzSeed-244067732*/count=1750; tryItOut("h1.enumerate = f0;");
/*fuzzSeed-244067732*/count=1751; tryItOut("/*RXUB*/var r = /(?:(?=[^])){67108863}/yim; var s = \"\\n\"; print(r.test(s)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
