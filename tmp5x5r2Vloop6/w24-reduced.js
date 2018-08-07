

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
/*fuzzSeed-221406266*/count=1; tryItOut("\"use strict\"; Array.prototype.push.apply(a2, []);");
/*fuzzSeed-221406266*/count=2; tryItOut("\"use strict\"; L:with(((void options('strict'))))h2.defineProperty = f0;");
/*fuzzSeed-221406266*/count=3; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?=(?:\\\\b)(?=(?!.|^))+{4}))\", \"\"); var s = [] = function ([y]) { }.prototype; print(uneval(s.match(r))); ");
/*fuzzSeed-221406266*/count=4; tryItOut("\"use strict\"; v0 = o0.g0.eval(\" /x/g \");");
/*fuzzSeed-221406266*/count=5; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=6; tryItOut("h0 = {};");
/*fuzzSeed-221406266*/count=7; tryItOut("/*infloop*/for(var x in ((Object.values)(Math.hypot( '' , 15))))t2.__proto__ = f0;");
/*fuzzSeed-221406266*/count=8; tryItOut("x instanceof false;\nfunction eval(\"mathy2 = (function(x, y) { \\\"use strict\\\"; return (((Math.min(0x100000001, Math.fround(( + Math.fround(x)))) + Math.pow(((Math.hypot((Math.pow((-0x100000001 | 0), -0x080000000) >>> 0), (Math.tan((((-0x0ffffffff >>> 0) ^ (y >>> 0)) >>> 0)) | 0)) | 0) / 1), ( + Number.MAX_VALUE))) >>> 0) % Math.fround(Math.hypot(Math.fround(((( ~ (x | 0)) | 0) >> ( + ( + Math.pow(0, Math.fround(y)))))), mathy1(Math.pow((((x >>> 0) >> x) | 0), Math.fround((Math.acosh((x | 0)) | 0))), ( + Math.log10(( + Math.atan2((x | 0), (y | 0))))))))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000000, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, -0x100000001, 0x080000001, 2**53+2, 1/0, -(2**53-2), -(2**53), 2**53-2, Math.PI, 0x080000000, 0.000000000000001, 42, -0x100000000, -0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -1/0, -0x080000001, -0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, 1, 0x100000001, -0x0ffffffff]); \")(x, this.eval)x/* no regression tests found */");
/*fuzzSeed-221406266*/count=9; tryItOut("\"use asm\"; g1.g0.a2.toSource = Math.tanh.bind(v1);h0[1] = v2;");
/*fuzzSeed-221406266*/count=10; tryItOut("i0.toSource = (function(j) { if (j) { try { e0.add(([]) >>>= this); } catch(e0) { } try { a0.toSource = (function() { try { e2.has(v0); } catch(e0) { } this.v1 = evaluate(\"function f0(t0)  { yield (4277) } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (this.__defineGetter__(\"a\", String.prototype.trimRight)), noScriptRval: false, sourceIsLazy: (x % 2 == 1), catchTermination: true, element: g0.o2, sourceMapURL: s0 })); return i2; }); } catch(e1) { } try { this.e1.delete(this.g2); } catch(e2) { } Array.prototype.pop.apply(g0.a1, [v0, this.g1.o0, s0]); } else { t1 = o0.t1.subarray(({valueOf: function() { b2.__proto__ = h0;function a(z) { \"use strict\"; yield x } throw \u0009((c)());return 5; }})); } });");
/*fuzzSeed-221406266*/count=11; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[null, null, arguments.caller, new Number(1), arguments.caller, (void 0), null, new Number(1), (void 0), arguments.caller, (void 0), new Number(1), (void 0), new Number(1), null, arguments.caller, (void 0), arguments.caller, arguments.caller, null, new Number(1), arguments.caller, arguments.caller, (void 0), null, (void 0), (void 0), (void 0), (void 0), (void 0), new Number(1), new Number(1), null, (void 0), new Number(1), arguments.caller, new Number(1)]) { h2.getPropertyDescriptor = (function() { try { /*ADP-2*/Object.defineProperty(a1, ({valueOf: function() { t1 = new Uint8Array(a0);return 15; }}), { configurable: w, enumerable: [[1]] +  /x/g , get: (function(j) { if (j) { v1 = Object.prototype.isPrototypeOf.call(this.g0, a2); } else { try { f1 + this.e0; } catch(e0) { } m0.delete(e2); } }), set: (function mcc_() { var eurffw = 0; return function() { ++eurffw; if (/*ICCD*/eurffw % 10 == 5) { dumpln('hit!'); try { s1 += g2.o2.s2; } catch(e0) { } i0 = new Iterator(g1.a1, true); } else { dumpln('miss!'); Object.prototype.watch.call(b1, \"\\u1033\", (function() { try { let v0 = g2.runOffThreadScript(); } catch(e0) { } try { v0 = evalcx(\"a2.reverse();\", g2); } catch(e1) { } v1 = evalcx(\"function f0(e1)  { \\\"use strict\\\"; yield  ''  } \", g0); return v2; })); } };})() }); } catch(e0) { } try { a0 = arguments.callee.caller.arguments; } catch(e1) { } try { o0.f0 = Proxy.createFunction(h1, f2, f0); } catch(e2) { } e0.add(b2); return v1; }); }");
/*fuzzSeed-221406266*/count=12; tryItOut("var z = -0x100000001;a0.length = this.g1.v2;");
/*fuzzSeed-221406266*/count=13; tryItOut("testMathyFunction(mathy4, [-1/0, -0x07fffffff, 2**53, 0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, Number.MIN_VALUE, -0x080000001, 0x07fffffff, -0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, Number.MAX_VALUE, -0, -0x100000000, Math.PI, 0x0ffffffff, -(2**53+2), -0x100000001, 0, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), 1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 42, -(2**53), 1]); ");
/*fuzzSeed-221406266*/count=14; tryItOut("g2.i1 = Proxy.create(h0, this.o2.h1);");
/*fuzzSeed-221406266*/count=15; tryItOut("this.g0.toString = (function(j) { if (j) { try { m2.set(g0.i2, h0); } catch(e0) { } try { for (var v of o0) { i0.send(this.t0); } } catch(e1) { } try { v1 = (p2 instanceof e2); } catch(e2) { } for (var v of o1.p2) { try { t0[({valueOf: function() { /*tLoop*/for (let a of /*MARR*/[[(void 0)], [(void 0)], x, x, [(void 0)], x, [(void 0)], x, x, [(void 0)], x, [(void 0)], x, x, x, [(void 0)], x, [(void 0)], [(void 0)], [(void 0)], x, x, [(void 0)], [(void 0)]]) { t1.toString = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (NaN);\n    }\n    return (((!(1))*0xfffff))|0;\n  }\n  return f; }); }return 16; }})] = (void version(185)); } catch(e0) { } try { v0 = t0.byteLength; } catch(e1) { } var o0 = {}; } } else { try { h0.enumerate = f0; } catch(e0) { } for (var p in g1) { for (var v of o0) { try { a1.sort((function() { m1 = new WeakMap; return o2; }), g2.o1); } catch(e0) { } g0.e0.delete(f2); } } } });");
/*fuzzSeed-221406266*/count=16; tryItOut("x = linkedList(x, 1159);");
/*fuzzSeed-221406266*/count=17; tryItOut("\"use strict\"; this.b0 = a1[v2];");
/*fuzzSeed-221406266*/count=18; tryItOut("a2[13];");
/*fuzzSeed-221406266*/count=19; tryItOut("var bnalyf = new SharedArrayBuffer(8); var bnalyf_0 = new Uint8Array(bnalyf); var bnalyf_1 = new Uint8ClampedArray(bnalyf); bnalyf_1[0] = 27; g0.a0.push();print( '' );this.h2.hasOwn = f2;print(yield  \"\"  ? bnalyf_0[2] : (this.__defineSetter__(\"bnalyf\", /*wrap2*/(function(){ var sydclv = \u3056; var tipyrd = (RegExp.prototype.test).apply; return tipyrd;})())));g2.offThreadCompileScript(\"print(bnalyf_1[1]);\");v2 = evaluate(\"v2 = (a0 instanceof m0);\", ({ global: this.g1, fileName: null, lineNumber: 42, isRunOnce: (bnalyf_0[0] % 10 != 8), noScriptRval: (bnalyf_1[1] % 41 != 16), sourceIsLazy: false, catchTermination: true }));a0[10] = bnalyf_1[0];print(bnalyf);/* no regression tests found */");
/*fuzzSeed-221406266*/count=20; tryItOut("a0.pop();");
/*fuzzSeed-221406266*/count=21; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.log1p(Math.fround((Math.max((Math.sign(( - ( + Math.fround(Math.pow(y, x))))) >>> 0), ( + (( + ( ~ (Math.min((-(2**53) | 0), y) | 0))) | 0))) | 0))); }); testMathyFunction(mathy2, [0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, 2**53, 0, -0x100000001, -(2**53+2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 1/0, Math.PI, Number.MAX_VALUE, 0x100000001, 0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -(2**53), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1, 2**53-2, 0x0ffffffff, 0x07fffffff, -0, 0x080000000, -0x080000000, -(2**53-2), -0x080000001, 42, -1/0]); ");
/*fuzzSeed-221406266*/count=22; tryItOut("\"use strict\"; (this.__defineGetter__(\"x\", runOffThreadScript));");
/*fuzzSeed-221406266*/count=23; tryItOut("\"use strict\"; t1[0] = this;;\nthrow NaN;let(window, x) ((function(){\u3056 = x;})());\n");
/*fuzzSeed-221406266*/count=24; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.atan2(( + Math.asin(Math.fround(Math.log10(Math.fround((Math.tan(Math.fround(Math.abs((( + (x >>> 0)) >>> 0)))) | 0)))))), (( ~ Math.round(y)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [2**53, 0x100000000, -0x080000001, -0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, -1/0, 0x080000000, -(2**53), 0/0, 0x07fffffff, Number.MAX_VALUE, 0.000000000000001, 2**53-2, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), 0x100000001, 1, 1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 0, 0x080000001, 42]); ");
/*fuzzSeed-221406266*/count=25; tryItOut(" for (var y of (function ([y]) { })()) (void schedulegc(g0));");
/*fuzzSeed-221406266*/count=26; tryItOut("a0.push(i0, m2, e1);");
/*fuzzSeed-221406266*/count=27; tryItOut("\"use strict\"; Object.defineProperty(this, \"o2.a1\", { configurable: x, enumerable: (this.__defineGetter__(\"b\",  \"\" )).valueOf(\"number\"),  get: function() {  return this.r0.exec(s2); } });");
/*fuzzSeed-221406266*/count=28; tryItOut("s2 += s2;");
/*fuzzSeed-221406266*/count=29; tryItOut("/*MXX3*/o0.g0.Float32Array.prototype.BYTES_PER_ELEMENT = g2.o0.g0.Float32Array.prototype.BYTES_PER_ELEMENT;");
/*fuzzSeed-221406266*/count=30; tryItOut("var tgxurq = new SharedArrayBuffer(0); var tgxurq_0 = new Uint16Array(tgxurq); var tgxurq_1 = new Uint8ClampedArray(tgxurq); tgxurq_1[0] = 4.; var tgxurq_2 = new Uint8ClampedArray(tgxurq); tgxurq_2[0] = -1519250743; a1 = a1.concat(t2, a1);a0 = new Array;print(tgxurq_0[4]);/*MXX1*/Object.defineProperty(this, \"o1\", { configurable: unshift, enumerable: \"\\uA54D\",  get: function() {  return g0.Float32Array.length; } });p2 + g0;");
/*fuzzSeed-221406266*/count=31; tryItOut("b2 = t0.buffer;\n( \"\" );\n");
/*fuzzSeed-221406266*/count=32; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\1)${3,}|\\B|^([^])*/gyim; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=33; tryItOut("mathy5 = (function(x, y) { return (Math.max((Math.fround(( ! Math.fround(mathy1((2**53 | 0), ((x & Math.log10(x)) | 0))))) | 0), (Math.pow(Math.imul(Math.log2(y), ( ~ (Math.log(( ~ x)) ^ 1))), ( ! ( + (x * (( + y) % Math.pow(x, (y >>> 0))))))) | 0)) | 0); }); testMathyFunction(mathy5, [false, null, ({toString:function(){return '0';}}), (function(){return 0;}), (new Number(-0)), (new Number(0)), '0', NaN, '/0/', (new Boolean(true)), ({valueOf:function(){return 0;}}), true, objectEmulatingUndefined(), [0], 0.1, /0/, -0, (new Boolean(false)), '\\0', '', [], undefined, 1, (new String('')), ({valueOf:function(){return '0';}}), 0]); ");
/*fuzzSeed-221406266*/count=34; tryItOut("/*tLoop*/for (let z of /*MARR*/[function(q) { return q; }.prototype, function(q) { return q; }.prototype,  /x/g ,  /x/g , function(q) { return q; }.prototype, function(q) { return q; }.prototype,  /x/g , arguments.caller, function(q) { return q; }.prototype, arguments.caller, arguments.caller, function(q) { return q; }.prototype, function(q) { return q; }.prototype, arguments.caller, arguments.caller,  /x/g , function(q) { return q; }.prototype,  /x/g ,  /x/g , function(q) { return q; }.prototype, function(q) { return q; }.prototype]) { for (var p in s0) { try { o2 = o0.i0.__proto__; } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(v2, o1); } catch(e1) { } /*ODP-3*/Object.defineProperty(g1, \"delete\", { configurable: false, enumerable: new RegExp(\"(?!\\\\1){4194304}|(?:(?![\\\\u006B\\\\xB9\\u00e7-\\\\u0a42\\\\S])|\\\\3)\", \"gim\"), writable: true, value: e2 }); } }");
/*fuzzSeed-221406266*/count=35; tryItOut("M:while((new (((function sum_indexing(xdyyhu, ybejqe) { ; return xdyyhu.length == ybejqe ? 0 : xdyyhu[ybejqe] + sum_indexing(xdyyhu, ybejqe + 1); })(/*MARR*/[[], [], (void 0), (void 0)], 0)))((w.from()))) && 0)a2 = [];");
/*fuzzSeed-221406266*/count=36; tryItOut("mathy3 = (function(x, y) { return mathy2(Math.fround(Math.ceil(Math.fround(( + mathy1((Math.clz32((x >>> 0)) >>> 0), ( + Math.fround(Math.fround(y)))))))), mathy2(((Math.log1p(((-0x0ffffffff ? 0x0ffffffff : (0 | 0)) >>> 0)) >>> 0) >= ( + ( ~ ( + y)))), (( + -0x07fffffff) | 0))); }); testMathyFunction(mathy3, [-(2**53-2), 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, 0x080000001, 0x100000001, Number.MAX_VALUE, -0x080000001, 2**53, -0x0ffffffff, 2**53-2, Number.MIN_VALUE, 0x100000000, 0, -0x07fffffff, -0x100000001, 1/0, -0, -0x100000000, 1.7976931348623157e308, 0.000000000000001, -(2**53), -(2**53+2), 1, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=37; tryItOut("o1.a0.pop(f0);");
/*fuzzSeed-221406266*/count=38; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a1, x, { configurable: timeout(1800), enumerable: (x % 4 != 0), writable: (4277), value: g1 });");
/*fuzzSeed-221406266*/count=39; tryItOut("v1 = Array.prototype.reduce, reduceRight.apply(a1, [f0, (Math.hypot(46957999.5, ({NaN: {}}) = ( /* Comment */Math))), p2]);");
/*fuzzSeed-221406266*/count=40; tryItOut("\"use strict\"; g0.v2 = r0.ignoreCase;");
/*fuzzSeed-221406266*/count=41; tryItOut("v2 = (p0 instanceof this.a0);function x(this.null, x) { \"use strict\"; return false } v0 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-221406266*/count=42; tryItOut("this.zzz.zzz;with({}) throw y;");
/*fuzzSeed-221406266*/count=43; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( + ( + (( + Math.fround(Math.max(Math.log10(x), y))) ^ (Math.log1p(((((x | 0) % (((( + mathy1(y, x)) == (x | 0)) >>> 0) | 0)) | 0) | 0)) | 0))))); }); testMathyFunction(mathy2, [0x100000000, -0x080000000, 0x0ffffffff, 2**53, 0x080000001, 0, 0.000000000000001, 1, 0x07fffffff, 0x080000000, 0/0, 42, -(2**53-2), -0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0x100000001, -0x0ffffffff, 2**53-2, -(2**53), -0x080000001, Math.PI, -0x100000000, 1/0, -0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=44; tryItOut("testMathyFunction(mathy0, [0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000000, -0, 0x100000000, 1, -0x07fffffff, -0x100000001, -Number.MAX_VALUE, 0x07fffffff, 0, 0x0ffffffff, Number.MIN_VALUE, Math.PI, -0x080000001, 0/0, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, 42, 1/0, -1/0, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, 2**53+2, 0.000000000000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -(2**53), -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=45; tryItOut("testMathyFunction(mathy0, [1.7976931348623157e308, Number.MAX_VALUE, -0, Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, -0x080000000, 0x100000000, 2**53, 2**53-2, 0.000000000000001, 0/0, 0x080000001, 0, 1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, -0x07fffffff, -Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, -(2**53), -(2**53-2), 0x080000000, 2**53+2, -1/0]); ");
/*fuzzSeed-221406266*/count=46; tryItOut("");
/*fuzzSeed-221406266*/count=47; tryItOut("b1 = t2.buffer;");
/*fuzzSeed-221406266*/count=48; tryItOut("/*infloop*/M: for (  of /(?=\\x83\\1)/yi) {v0 = Object.prototype.isPrototypeOf.call(o2.o0.e0, f0);v2 = (v2 instanceof t0); }");
/*fuzzSeed-221406266*/count=49; tryItOut("print(i0);");
/*fuzzSeed-221406266*/count=50; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return ( - (Math.imul((Math.sqrt(((Math.fround(x) | -Number.MAX_VALUE) | 0)) | 0), ((( + Math.hypot(y, Math.cbrt((x === x)))) >>> 0) < ( - y))) | 0)); }); testMathyFunction(mathy5, [0x100000000, -Number.MAX_SAFE_INTEGER, 1, 2**53-2, -0x080000000, Number.MIN_SAFE_INTEGER, 0/0, 0, -Number.MAX_VALUE, -0, -0x080000001, 2**53, -(2**53-2), -0x100000001, 0x080000001, 42, -0x07fffffff, 0x080000000, 1/0, 0x0ffffffff, 0x100000001, -0x0ffffffff, Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, -0x100000000, 0.000000000000001, -1/0, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=51; tryItOut("\"use strict\"; v1 = evalcx(\"RangeError.prototype.toString.prototype\", g1);");
/*fuzzSeed-221406266*/count=52; tryItOut("/*MXX3*/g0.Root.length = g1.Root.length;");
/*fuzzSeed-221406266*/count=53; tryItOut("/*RXUB*/var r = r1; var s = \"\\n\\n\"; print(s.search(r)); ");
/*fuzzSeed-221406266*/count=54; tryItOut("e2.add((x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: JSON.parse, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })(Math.asin( /x/ )), (new ((e = -19))()))));");
/*fuzzSeed-221406266*/count=55; tryItOut("m1.has(i2);");
/*fuzzSeed-221406266*/count=56; tryItOut("/*RXUB*/var r = /(?!(?:(^|(?=[^]?){4,5})))(^\\B{1,1})*/ym; var s = \"\"; print(uneval(s.match(r)));  \"\" ;");
/*fuzzSeed-221406266*/count=57; tryItOut("-12;function x(a, ...x) { yield let (d) function ([y]) { } } e2.add(p1);");
/*fuzzSeed-221406266*/count=58; tryItOut("\"use strict\"; a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; /*MXX3*/g0.WebAssemblyMemoryMode.name = g2.WebAssemblyMemoryMode.name;");
/*fuzzSeed-221406266*/count=59; tryItOut("/*tLoop*/for (let w of /*MARR*/[x, x, arguments, x, arguments, arguments, x, arguments, arguments, arguments, x, x, arguments, x, x, x, arguments, x, arguments]) { print(w); }\n");
/*fuzzSeed-221406266*/count=60; tryItOut("g1.h2 + '';");
/*fuzzSeed-221406266*/count=61; tryItOut("\"use strict\"; print(h1);");
/*fuzzSeed-221406266*/count=62; tryItOut("mathy4 = (function(x, y) { return mathy0(Math.fround(Math.atan2(Math.fround(( + Math.fround(Math.min(( + Math.max(( + y), ( + Math.log(42)))), Math.cosh(0x0ffffffff))))), Math.fround(Math.imul(y, (((Math.fround(x) || Math.fround(y)) >>> 0) < y))))), Math.min(Math.max((((mathy2(x, Math.fround(( + Math.fround(-Number.MIN_VALUE)))) >>> 0) ? (y >>> 0) : (Math.log2(((( + (y / Math.fround(x))) * ( + y)) >>> 0)) >>> 0)) >>> 0), (( ! (( ! Math.fround(Math.max(Math.fround(-(2**53)), Math.fround(x)))) >>> 0)) >>> 0)), Math.sinh(Math.pow(-(2**53), ((42 | 0) - -Number.MIN_SAFE_INTEGER))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 0x080000001, -0x07fffffff, -0x080000001, 0.000000000000001, 0x080000000, Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0x100000001, -0x080000000, 0/0, 0x100000000, -(2**53-2), Number.MAX_VALUE, 0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -0, 0x0ffffffff, 1.7976931348623157e308, 0, -0x0ffffffff, -(2**53), 42, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, 1/0]); ");
/*fuzzSeed-221406266*/count=63; tryItOut("\"use strict\"; t1 + '';");
/*fuzzSeed-221406266*/count=64; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.tanh(Math.pow(Math.sinh((Math.hypot(( + Math.fround(Math.asin(Math.pow(0x0ffffffff, x)))), ( + y)) | 0)), (Math.abs(((Math.fround((( + (y >>> 0)) >>> 0)) , Math.fround((( - (x | 0)) | 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0.1, 0, NaN, ({valueOf:function(){return '0';}}), (new Boolean(true)), null, true, '\\0', '', (function(){return 0;}), false, [0], [], (new Boolean(false)), '/0/', '0', /0/, 1, objectEmulatingUndefined(), -0, (new Number(0)), (new Number(-0)), undefined, ({toString:function(){return '0';}}), (new String('')), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-221406266*/count=65; tryItOut("for (var v of g2.a1) { a1.splice(NaN, (void options('strict'))); }");
/*fuzzSeed-221406266*/count=66; tryItOut("v2 = null;");
/*fuzzSeed-221406266*/count=67; tryItOut("v2 = (o2.p2 instanceof o1);");
/*fuzzSeed-221406266*/count=68; tryItOut("yield eval(\"true\").__defineSetter__(\"eval\", false);function x() { \"use strict\"; return eval(\"r2 = new RegExp(\\\"(?:(^)|$?)\\\", \\\"im\\\");\", [1,,]) } o0.m2.has(p2);");
/*fuzzSeed-221406266*/count=69; tryItOut("h2.has = (function() { for (var j=0;j<59;++j) { f1(j%5==0); } });");
/*fuzzSeed-221406266*/count=70; tryItOut("\"use strict\"; v0 = g1[\"isNaN\"];");
/*fuzzSeed-221406266*/count=71; tryItOut("v1 = (g1 instanceof e1);");
/*fuzzSeed-221406266*/count=72; tryItOut("\"use strict\"; [, , (4277).b, , {b: x, y}, x] = (this <<= window), y = this, x = x;with({d: /*UUV2*/(a.forEach = a.defineProperties)}){g2.t0 = a1[2]; }");
/*fuzzSeed-221406266*/count=73; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ! mathy1(mathy4(( + ( ~ ( + x))), ( ~ x)), (((y >>> 0) , (2**53+2 >>> 0)) <= (mathy3((Math.imul((0.000000000000001 | 0), (0x100000001 | 0)) | 0), ( ~ x)) | 0)))) >>> 0); }); testMathyFunction(mathy5, [0.000000000000001, 0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 1, 1.7976931348623157e308, -(2**53-2), 0, 42, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, -0x080000000, -Number.MAX_VALUE, 0x080000000, -0x080000001, 0x07fffffff, 2**53-2, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 2**53, -0x100000000, 0x100000000, 2**53+2, -0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, 0/0, -0, -0x07fffffff, -0x100000001, -1/0]); ");
/*fuzzSeed-221406266*/count=74; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return (Math.cos((Math.atan2((( ! (-0x07fffffff >>> 0)) >>> 0), Math.atanh(Math.fround(Math.abs((Math.cos((( + Math.cos(Math.fround(y))) | 0)) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, -0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, -1/0, 0x07fffffff, 1, -0x0ffffffff, 0/0, 0.000000000000001, -(2**53), 1.7976931348623157e308, 0, 0x080000001, 2**53, -0x080000001, -0x100000000, 42, 0x100000001, -(2**53-2), Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, 1/0, -0, -Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-221406266*/count=75; tryItOut("\"use strict\"; f1.toSource = f0;");
/*fuzzSeed-221406266*/count=76; tryItOut("e1.add(e0);Array.prototype.shift.call(a0, m1, p1, undefined, a1);");
/*fuzzSeed-221406266*/count=77; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow(( + (((( + ( ~ (Math.max((-0x100000001 | 0), 0x100000001) | 0))) >>> 0) ^ Math.trunc(x)) >>> 0)), ( + mathy0(Math.fround(( + (Math.cos(y) ? mathy0(Math.imul(y, (Math.imul((y | 0), -0x0ffffffff) | 0)), x) : Math.fround(Math.clz32(Math.fround(Math.min((Math.fround((Math.fround(x) != Math.fround(Math.acos(x)))) | 0), -1/0))))))), ( + new RegExp(\"[^]\", \"m\"))))); }); testMathyFunction(mathy1, [0, -(2**53+2), 0.000000000000001, 0x080000000, -(2**53-2), 1/0, 1, 2**53-2, -(2**53), Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000000, -0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 42, Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0x07fffffff, -0x100000000, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 2**53, -1/0, 1.7976931348623157e308, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, -0x080000001, 0x080000001]); ");
/*fuzzSeed-221406266*/count=78; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.cos(( ! ( - ( + x)))) | 0); }); testMathyFunction(mathy0, [[0], ({valueOf:function(){return '0';}}), '', (new Number(-0)), NaN, '0', undefined, '/0/', ({toString:function(){return '0';}}), (new Number(0)), objectEmulatingUndefined(), 1, true, 0.1, (new String('')), (new Boolean(true)), ({valueOf:function(){return 0;}}), (function(){return 0;}), [], (new Boolean(false)), -0, null, 0, /0/, false, '\\0']); ");
/*fuzzSeed-221406266*/count=79; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.pow(( + Math.pow(( + y), ( + ( + Math.sinh(( + ( + Math.atan(( + 0x0ffffffff))))))))), ( + ( - Math.hypot(Math.fround(( ! ( + Math.cosh(x)))), Math.fround(Math.log2(Math.fround((y <= Math.log2(Math.fround(y)))))))))) >>> 0); }); testMathyFunction(mathy0, [[0], undefined, 0.1, ({valueOf:function(){return 0;}}), (new Boolean(true)), '\\0', '0', NaN, false, (new Number(-0)), (new String('')), '/0/', 0, (function(){return 0;}), 1, ({toString:function(){return '0';}}), true, objectEmulatingUndefined(), /0/, -0, (new Boolean(false)), (new Number(0)), [], ({valueOf:function(){return '0';}}), null, '']); ");
/*fuzzSeed-221406266*/count=80; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=81; tryItOut("b0.toSource = (function() { for (var j=0;j<33;++j) { f2(j%2==1); } });");
/*fuzzSeed-221406266*/count=82; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return Math.hypot(Math.sqrt(( ~ ( ~ ( + (Math.cos(( - y)) | 0))))), (mathy1(((Math.log((x | 0)) | 0) >>> 0), (((y == Math.fround(( ~ Number.MAX_VALUE))) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 2**53+2, -0x0ffffffff, 2**53, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 1/0, 0x080000000, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 0x100000000, -1/0, -0x100000000, 42, Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, 0/0, -0, -(2**53+2), -Number.MIN_VALUE, -0x080000001, 0.000000000000001, 0x080000001, 0, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=83; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.cosh(( ~ (Math.ceil((( ~ ( + ( ! ( + Math.min(x, (Math.PI >>> 0)))))) | 0)) | 0))); }); ");
/*fuzzSeed-221406266*/count=84; tryItOut("i2 + b1;");
/*fuzzSeed-221406266*/count=85; tryItOut("x, x, khyzue, x = x, pixfgb, delete, x, yielhb, rncitw, lxuyfd;v2 = (b0 instanceof e2);");
/*fuzzSeed-221406266*/count=86; tryItOut("\"use strict\"; a1.push(h0, s2, g1, p2, a2, m0, a1);");
/*fuzzSeed-221406266*/count=87; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, (new Boolean(false)), '/0/', '', objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new String('')), true, (new Boolean(true)), 1, '\\0', undefined, false, [0], (function(){return 0;}), null, '0', 0.1, NaN, ({valueOf:function(){return '0';}}), [], (new Number(0)), ({valueOf:function(){return 0;}}), /0/, (new Number(-0)), 0]); ");
/*fuzzSeed-221406266*/count=88; tryItOut("mathy4 = (function(x, y) { return ( + Math.hypot(Math.fround((((( + Math.fround(Math.log1p(Math.fround((Math.atan2((1 >>> 0), Math.fround(Math.pow(-Number.MIN_VALUE, x))) >>> 0))))) | 0) ? ( + ( ~ ( + x))) : (Math.imul((Math.pow(y, ((((Math.expm1(Math.fround(((x | 0) ? (x | 0) : (0x07fffffff | 0)))) >>> 0) | 0) ? (y | 0) : Math.max(x, y)) | 0)) | 0), ( + ( - {i0 = new Iterator(g0.v2); }))) | 0)) | 0)), Math.cos((( + (Math.trunc(y) , y)) , ( + (( + Math.atan(( + x))) < ( + mathy3(( + -0x100000001), Math.fround((0x100000000 ? (x | 0) : (y >>> 0))))))))))); }); testMathyFunction(mathy4, [0x080000001, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 42, 2**53, 0x100000000, 0, 0/0, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -0x0ffffffff, 1/0, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, -(2**53+2), 2**53-2, 0x07fffffff, -0, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=89; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return (Math.fround(Math.atan2(Math.fround(Math.pow((Math.max(Math.hypot(1, (( - (Math.fround(mathy0(Math.fround(x), Math.fround(-(2**53)))) >>> 0)) | 0)), Math.hypot(y, y)) | 0), ((((Math.log2(( + y)) >>> 0) | (0x0ffffffff >>> 0)) | 0) & ( ! x)))), ( ~ mathy0(Math.fround(Math.asinh(( + y))), y)))) ^ Math.fround((Math.fround(mathy0(Math.fround(Math.fround((( + 21\n) == ( + (( - y) % Math.fround(( ! ( + Math.fround(x))))))))), y)) ^ Math.fround(( - Math.max(x, ( + 1))))))); }); ");
/*fuzzSeed-221406266*/count=90; tryItOut("mathy3 = (function(x, y) { return Math.imul(( - ( + ( - Math.fround(( ! (x & (x >>> 0))))))), Math.abs(Math.fround(Math.abs(((Math.expm1(Math.fround(Math.hypot(Math.fround(y), Math.fround(Math.PI)))) >>> 0) | 0))))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), (new Boolean(true)), (new Number(0)), undefined, -0, true, '0', [0], (new String('')), null, (function(){return 0;}), 0.1, NaN, [], false, /0/, ({valueOf:function(){return 0;}}), '\\0', objectEmulatingUndefined(), 1, ({toString:function(){return '0';}}), '/0/', (new Number(-0)), '', (new Boolean(false)), 0]); ");
/*fuzzSeed-221406266*/count=91; tryItOut("\"use strict\"; Object.prototype.watch.call(g0.m0, \"toSource\", f2);");
/*fuzzSeed-221406266*/count=92; tryItOut("try { return; } finally { for(let a in [/*wrap1*/(function(){ o1 = f0.__proto__;return function(q) { return q; }})() for ((p={}, (p.z = x)()) in Math) for each (this.y in new Array(-16)) for ((/(?=(?!(?![\\D\ue967\\x76-\u00a9]|\u76db))?$+?)+?/im.eval(\"v1 = g0.eval(\\\"Array.prototype.splice.call(a0);\\\");\"))((4277)) in (\u0009let (z = new ([z1,,])((( /x/g )()))) z)) for (window of x) for each (x in (function() { yield x; } })()) for (Symbol.search in (new window())) if ((function (x, this.w, x =  /x/ , x, y, x, NaN, x, x, x, x, c, y, y, b = window, x, eval =  \"\" , x,  , \u3056, z, eval, x = true, window, c, x = /[^]+?/, z, x, x = /.|[^\\cH-\\\u00a1]{0}/yi, eval, x, z, x, e, x, window, x, x, y, e =  \"\" , e = true, x, window, d = this, x) { (new RegExp(\"(((?=\\\\u62c8{4})))+?|^|\\\\n[^]\\\\2+{34359738368,}\", \"i\")); } ).call(\"\\uCC91\", ))]) break ; } ");
/*fuzzSeed-221406266*/count=93; tryItOut("for (var p in s0) { t1 = new Uint16Array(g1.b0, 12, v0); }");
/*fuzzSeed-221406266*/count=94; tryItOut("Array.prototype.unshift.call(a1, b0, f1, m0);");
/*fuzzSeed-221406266*/count=95; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=96; tryItOut("");
/*fuzzSeed-221406266*/count=97; tryItOut("\"use strict\"; /*vLoop*/for (wtrwdw = 0; wtrwdw < 25; ++wtrwdw) { let d = wtrwdw; s1 += 'x'; } ");
/*fuzzSeed-221406266*/count=98; tryItOut("with({}) { const a0 = arguments; } ");
/*fuzzSeed-221406266*/count=99; tryItOut("\"use strict\"; /*RXUB*/var r = x; var s = \"\\u90fc\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=100; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.ceil(Math.fround((mathy1(((Math.min(( + x), ( + ((y | 0) >> (Math.min(x, x) >= 1)))) | 0) >>> 0), (Math.cbrt(Math.atan2(( + ( + Math.fround(-Number.MIN_VALUE))), (( ~ 2**53) >>> 0))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [0x100000001, 0.000000000000001, 0x07fffffff, -0x100000000, 2**53+2, 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 0/0, 1, 0x080000000, -(2**53+2), 1/0, 0x100000000, -0x080000001, -(2**53), -0x07fffffff, -0, 2**53, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, -1/0, 42, 0, -0x080000000]); ");
/*fuzzSeed-221406266*/count=101; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ ((( - ( ! (Math.tan(((( + (x | 0)) | 0) >>> 0)) >>> 0))) | 0) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[[undefined], function(){}, function(){},  \"\" \n, [undefined],  \"\" \n, [undefined], function(){},  \"\" \n,  \"\" \n,  \"\" \n, [undefined], [undefined],  \"\" \n,  \"\" \n, function(){},  \"\" \n, function(){}, function(){},  \"\" \n,  \"\" \n,  \"\" \n, [undefined], function(){}, function(){}, [undefined],  \"\" \n, function(){},  \"\" \n,  \"\" \n, function(){}, [undefined],  \"\" \n, [undefined], function(){},  \"\" \n, [undefined], [undefined], [undefined], [undefined], [undefined], function(){},  \"\" \n, [undefined], [undefined]]); ");
/*fuzzSeed-221406266*/count=102; tryItOut("v1 = this.g1.runOffThreadScript();");
/*fuzzSeed-221406266*/count=103; tryItOut("");
/*fuzzSeed-221406266*/count=104; tryItOut("\"use strict\"; t2[7] = (function(y) { s1.valueOf = (function mcc_() { var zwyvav = 0; return function() { ++zwyvav; f1(/*ICCD*/zwyvav % 3 == 1);};})(); })();");
/*fuzzSeed-221406266*/count=105; tryItOut("mathy4 = (function(x, y) { return ( ! Math.fround((Math.trunc(Math.hypot(( + Math.tan((y >>> 0))), ( + Math.asin(( + mathy0((( + Math.imul((y / Number.MIN_SAFE_INTEGER), 0x0ffffffff)) >>> 0), (x >>> 0))))))) | 0))); }); testMathyFunction(mathy4, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, -(2**53-2), 0/0, 2**53-2, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, Math.PI, 2**53+2, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 1, -0x07fffffff, 1/0, 0x080000001, -0, -(2**53), Number.MAX_VALUE, -(2**53+2), 2**53, 0.000000000000001, -0x0ffffffff, 0x080000000, -0x100000001, -1/0, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=106; tryItOut("g2.g0.e2.delete(g0.g2);");
/*fuzzSeed-221406266*/count=107; tryItOut("t0[11];");
/*fuzzSeed-221406266*/count=108; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy1((((Math.cbrt((( ! mathy0((0x100000000 >>> 0), (x >>> 0))) >>> 0)) | 0) > ((((( + x) && (-0x080000001 | 0)) >= y) >>> 0) | 0)) | 0), ((( ~ x) || (( + Math.hypot(( + x), ( + Math.hypot(( + (mathy0((x | 0), (y | 0)) | 0)), ( + x))))) | 0)) | 0)); }); ");
/*fuzzSeed-221406266*/count=109; tryItOut("for (var p in p2) { try { Object.defineProperty(this, \"a2\", { configurable: true, enumerable: false,  get: function() {  return o1.g0.a1.slice(14, NaN, Function.prototype); } }); } catch(e0) { } for (var p in t0) { try { v2 = new Number(-Infinity); } catch(e0) { } i0.send(i0); } }");
/*fuzzSeed-221406266*/count=110; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=111; tryItOut("\"use strict\"; o0 = Proxy.create(h0, p1);");
/*fuzzSeed-221406266*/count=112; tryItOut("f1(g2);");
/*fuzzSeed-221406266*/count=113; tryItOut("f0 + '';");
/*fuzzSeed-221406266*/count=114; tryItOut("\"use strict\"; o1 = {};");
/*fuzzSeed-221406266*/count=115; tryItOut("testMathyFunction(mathy2, [-0x080000000, -0x07fffffff, 0.000000000000001, 0x100000001, 0x0ffffffff, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, -1/0, -(2**53-2), -0, 1, -Number.MAX_SAFE_INTEGER, 1/0, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -0x100000000, Math.PI, 0, 2**53-2, 1.7976931348623157e308, -(2**53), -0x100000001, -0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, 2**53, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, 0/0]); ");
/*fuzzSeed-221406266*/count=116; tryItOut("\"use strict\"; this.a0.pop(s1);function eval(w, eval, x, x, NaN, x, NaN =  \"\" , b, x, b, x = x, x, y = this, x, x = x, c, this.NaN, eval = [,,], x, b, e, y, x = /(?=\\f^[^\\u519B-\\u5971](?![]*?){4,6})/yim, x = \"\\u0703\", e, x, y, x, x = e, c, x, x, a, x, w, \u3056 = this, x = new RegExp(\"(?:[^])\", \"gyi\"), \u3056, d, x = true, x) { \"use strict\"; /*infloop*/for(let x; /(?!([^]))|(?=[^\u00d8-\\u0d93\\W\u9157\\s]\u8286|^*?+?)(?=(?=\\b){0,})\\B*?+/gi.unwatch(\"x\"); (4277)) o1.a1 = Array.prototype.slice.apply(a1, [NaN, NaN, t0]); } for (var v of o2) { try { for (var v of p0) { try { e2 = g2.objectEmulatingUndefined(); } catch(e0) { } try { i2 = new Iterator(o2); } catch(e1) { } try { a2.length = 1; } catch(e2) { } o1.e0 + t1; } } catch(e0) { } try { m0.has(a2); } catch(e1) { } try { g2.h0 + ''; } catch(e2) { } print(a0); }");
/*fuzzSeed-221406266*/count=117; tryItOut("mathy1 = (function(x, y) { return ((( + Math.atan2(( + ( - ((Math.fround(mathy0(Math.fround(y), ((y >= 2**53-2) | 0))) << x) | 0))), ( + Math.exp((Math.fround(((( ! ((( ! (x >>> 0)) >>> 0) | 0)) | 0) ^ x)) >>> 0))))) | 0) != ( + mathy0(Math.pow((( + (Math.fround(((Math.pow(y, (x | 0)) | 0) ? (x | 0) : y)) % Math.fround(y))) >>> 0), Math.fround(\"25\": (makeFinalizeObserver('tenured')))), ((((( + (Math.imul(0.000000000000001, (( ~ x) | 0)) | 0)) | 0) | 0) / (x | 0)) | 0)))); }); testMathyFunction(mathy1, [42, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, Number.MAX_VALUE, Math.PI, 0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 2**53, -0x100000001, -0x0ffffffff, 0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, 0, -(2**53), -1/0, 0/0, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, 0x0ffffffff, 0x07fffffff, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, -0x080000001, -0x100000000, -0, 0x100000000, 1]); ");
/*fuzzSeed-221406266*/count=118; tryItOut("(Math.pow(-15, x) &= /*UUV1*/(x.toISOString = z));");
/*fuzzSeed-221406266*/count=119; tryItOut("mathy5 = (function(x, y) { return ( + Math.min((Math.cbrt(Math.acosh(Math.fround(Math.sinh(((((-Number.MAX_VALUE == 2**53-2) >>> 0) === y) >>> 0))))) >>> 0), ((( - ( ~ Math.fround((((((x | 0) , ((y > Math.fround(y)) | 0)) >>> 0) >>> (( + x) >>> 0)) >>> 0)))) | 0) >>> 0))); }); testMathyFunction(mathy5, [Math.PI, -1/0, 1, 0x080000001, 42, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, 2**53-2, Number.MIN_VALUE, 0x07fffffff, 1/0, -0x0ffffffff, 0, -0x080000001, -Number.MIN_VALUE, -(2**53-2), -0x100000000, 2**53+2, 0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, 1.7976931348623157e308, 0/0, -0, 0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=120; tryItOut("\u3056 = linkedList(\u3056, 860);");
/*fuzzSeed-221406266*/count=121; tryItOut("\"use strict\"; a0.pop();print(x);");
/*fuzzSeed-221406266*/count=122; tryItOut("\"use strict\"; p1 + o1.g1.s1;function d(c, x) { return ((void options('strict'))) } var t2 = this.t0.subarray(13, 4);");
/*fuzzSeed-221406266*/count=123; tryItOut("this.zzz.zzz = x;let(d, gqckuc, gjaojs) ((function(){let(x = /((?=.?))/gy.valueOf(\"number\"), x = (void options('strict')) instanceof ({x: window}), [] = (/*MARR*/[new String(''),  /x/ , new String(''), new String(''),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()].some), y, npycpt, w, bxoaur, x) { with({}) { for(let b in []); } }})());");
/*fuzzSeed-221406266*/count=124; tryItOut("\"use strict\"; e0.has(this.i0);");
/*fuzzSeed-221406266*/count=125; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.sin((( - (Math.fround(( + Math.sqrt(y))) <= (( ~ (Math.hypot((x ? ( + y) : ( + y)), y) << Math.atan2(x, x))) >>> 0))) | 0)); }); testMathyFunction(mathy1, [0x100000001, 2**53, 0/0, 42, 0x080000000, -0x100000000, 0x07fffffff, -0x080000000, 1/0, -(2**53), -1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 0, 0x100000000, 2**53-2, 1, 0x0ffffffff, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, 0x080000001, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=126; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-221406266*/count=127; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var cos = stdlib.Math.cos;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -65537.0;\n    var i5 = 0;\n    var d6 = 4294967297.0;\n    var d7 = 2097151.0;\n    var d8 = -1.1805916207174113e+21;\n    var i9 = 0;\n    (Float64ArrayView[(( /x/ )) >> 3]) = ((d7));\n    return +((Infinity));\n    i3 = ((((0x98bfdcd1)-(i5)+(0xf8ca9726))>>>((Int8ArrayView[1]))));\n    i1 = (i1);\n    {\n      i9 = (/*FFI*/ff(((((0xfdf955a4)*-0xfffff) >> ((0x5a572a10)))), ((((i3)+(i5)) ^ (0x95fb8*((0x4f1812d7))))), ((((~((0xfe77db50)-((-0x8000000) ? (0xfeff3017) : (0x88179a47)))) / (~((0x964569c3)-(i3)))) | ((([,,].eval(\"h0.iterate = f2;\")))))), ((+abs(((-295147905179352830000.0))))), (((((~~((-17179869185.0) + (-9007199254740992.0))))) & ((i2)))))|0);\n    }\n    i9 = (0xfcf31f8f);\n    {\n      i3 = ((((0x6de3a2c))|0));\n    }\n    return +((+cos(((((+(~~(2147483649.0)))) / ((((-9.44473296573929e+21)) * ((((((d4)) / ((32768.0)))) - ((((-1152921504606847000.0)) - ((+atan2(((1023.0)), ((-1.5))))))))))))))));\n  }\n  return f; })(this, {ff: function(y) { return [z1,,] }}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x0ffffffff, 42, 0x080000001, Math.PI, Number.MIN_VALUE, 0, 0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, -0x100000001, 0.000000000000001, 0x07fffffff, -0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, 1/0, -(2**53), -0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, -(2**53-2), -0x100000000, 2**53+2, -Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, 1, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2]); ");
/*fuzzSeed-221406266*/count=128; tryItOut("/* no regression tests found */\ns0 += 'x';\n");
/*fuzzSeed-221406266*/count=129; tryItOut("i1 = m2.entries;");
/*fuzzSeed-221406266*/count=130; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.min(( - Math.fround(Math.max((y ? Math.ceil(Math.acosh(( + Number.MAX_VALUE))) : x), Math.fround(x)))), ( + Math.trunc(( + mathy0(x, 1))))) <= mathy2(( + Math.hypot(( + y), ((( - (( ~ (( + x) - -(2**53-2))) | 0)) | 0) >>> 0))), Math.fround(Math.hypot(Math.fround(x), Math.fround(y))))) >>> 0); }); testMathyFunction(mathy3, [-(2**53-2), Math.PI, 0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, -0x080000001, 0.000000000000001, 0x080000001, -(2**53+2), -0, -0x100000000, 2**53, 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000, 0x080000000, -1/0, Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, 0, 2**53+2, -(2**53), 42, 2**53-2]); ");
/*fuzzSeed-221406266*/count=131; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var exp = stdlib.Math.exp;\n  var ff = foreign.ff;\n( - ( + (( + (Math.fround(( ~ Math.fround(( ~ Math.sign(x))))) ? Math.max((Math.fround(-(2**53-2)) * Math.fround(Number.MIN_VALUE)), Math.fround(Math.min((( + Math.imul(( + Math.trunc(x)), ( + x))) | 0), Math.fround(( ! ( + Math.fround(((( ~ ( + 2**53-2)) >>> 0) == x)))))))) : Math.pow(((((Math.fround((Math.fround(x) > Math.fround(-0))) + x) , ( + (( + Math.max((x | 0), (x | 0))) <= ( + (-Number.MIN_VALUE !== 0x080000000))))) ? (Math.pow(( + x), (x >>> 0)) >>> 0) : (((x | 0) ? ((Math.expm1((x | 0)) | 0) | 0) : (Math.hypot((x | 0), 42) | 0)) | 0)) >>> 0), ( ! ((((x >>> 0) ? (Math.expm1(Math.fround(((x | 0) ** (x | 0)))) >>> 0) : (0x100000001 | 0)) >>> 0) === ( ! (( ! x) >>> 0))))))) >>> ( + (( + ( ! ( + (Math.min(((x / ( + Math.min(( + -Number.MAX_VALUE), Math.fround((Math.fround(Math.trunc(x)) !== x))))) | 0), (Math.max(((Math.fround(x) || x) ? (x >>> 0) : Math.trunc((-0x0ffffffff >>> 0))), Math.max(x, (( + (x | (( + (( + x) != -Number.MIN_VALUE)) | 0))) | 0))) >>> 0)) >>> 0)))) | (Math.log1p((Math.asinh(Math.log(((x | 0) << (42 | 0)))) | 0)) >> ((Math.ceil(((((x < -0x100000000) >>> 0) ? (x >>> 0) : (x >>> 0)) | 0)) ? ( + ((x >>> 0) / ( + ( + ( + ( + x)))))) : (Math.exp(( + x)) >>> 0)) , (Math.min((Math.asinh(x) >>> 0), (x >>> 0)) >>> 0))))))))  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -16385.0;\n    var d5 = 0.00390625;\n    i1 = (/*FFI*/ff(((((i1)-(0xfc2a2c9a)) << (((0x32e947c5)-((!(0xf9d76ecd)) ? (0xb9bead9d) : ((4277))))))), ((d0)), ((d0)), ((abs((abs((~~(NaN)))|0))|0)), ((134217728.0)), (((((0x7dc96ea1))*0xa899e) << (0xfffff*(i3)))))|0);\n    d4 = ((NaN) + (+exp(((+(0xda86af39))))));\n    return +((Float32ArrayView[((0xfdd69104)) >> 2]));\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x0ffffffff, 1.7976931348623157e308, 1, 1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 0x0ffffffff, Math.PI, Number.MIN_VALUE, -1/0, -(2**53-2), 0, -0x100000001, 2**53, Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 2**53+2, -0x080000000, -0x080000001, 0x100000001, -0, 0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, 0x080000001, -0x100000000, 0/0, 0x080000000, -(2**53), -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=132; tryItOut("mathy1 = (function(x, y) { return Math.asinh((Math.log2(Math.min(Math.atanh(y), ( + y))) >>> 0)); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -1/0, 2**53-2, -0, 1/0, 0.000000000000001, 0x080000000, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -0x100000000, 0x100000000, 0x100000001, -Number.MAX_VALUE, -0x080000001, 42, -0x100000001, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x080000001, -(2**53+2), 2**53, 2**53+2, 0x0ffffffff, Number.MIN_VALUE, 0, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-221406266*/count=133; tryItOut("\"use strict\"; Array.prototype.push.call(a2, g1.v2, g2.a2);");
/*fuzzSeed-221406266*/count=134; tryItOut("this.o0.e2.add(t0);\nm2.get(v0);\n");
/*fuzzSeed-221406266*/count=135; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.pow(Math.fround((( + ( - (((x >>> 0) , (Math.sqrt(Math.hypot((Math.expm1(( + -Number.MAX_SAFE_INTEGER)) >>> 0), (x | 0))) >>> 0)) >>> 0))) !== Math.min(Math.fround(y), (Math.atanh(y) / y)))), Math.fround(Math.tanh(( + Math.sinh(( - ((Math.min(Math.hypot(-Number.MAX_VALUE, x), x) | 0) && Math.fround(Math.max(( + y), ( + 42)))))))))) >>> 0); }); testMathyFunction(mathy4, [0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, Math.PI, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 42, -0x100000001, -(2**53+2), 0, -(2**53), 0x080000000, 0x080000001, 0.000000000000001, 0x100000001, 0/0, -0x07fffffff, 2**53, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 2**53+2, 0x100000000, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -0x0ffffffff, -0]); ");
/*fuzzSeed-221406266*/count=136; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (((Infinity)) * ((-32769.0)));\n    d0 = (-3.094850098213451e+26);\n    d0 = (d0);\n    i1 = (0x2c6246cb);\n    d0 = (+(1.0/0.0));\n /x/g ;\nprint(\"\\u1EC1\");\n    d0 = (+atan2(((+(-1.0/0.0))), ((513.0))));\n    d0 = (+(0.0/0.0));\n    return (((((Float64ArrayView[((((0xe7d34efb) % (0xfb31fa38)) & ((i1))) / (((0xf81482b4)-(-0x8000000)+(0xfe01765f)) ^ ((0xc23ffe5c)-(0x441326d7)))) >> 3])) >= (~(0x75ef7*(0xfa185db2))))*-0x3c413))|0;\n    return (((0xf833db54)))|0;\n  }\n  return f; })(this, {ff: function(y) { a0[16] = b1; }}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [({toString:function(){return '0';}}), (new Number(0)), [], false, '\\0', objectEmulatingUndefined(), [0], /0/, (new Boolean(true)), '/0/', ({valueOf:function(){return '0';}}), 0.1, 1, NaN, (new String('')), undefined, null, '0', (function(){return 0;}), true, -0, 0, ({valueOf:function(){return 0;}}), (new Number(-0)), '', (new Boolean(false))]); ");
/*fuzzSeed-221406266*/count=137; tryItOut("for (var v of i1) { Object.defineProperty(this, \"v2\", { configurable: true, enumerable: false,  get: function() {  return evaluate(\"mathy0 = (function(x, y) { return Math.sign((( ! Math.atan(Math.log10((x <= (x >= (y | 0)))))) >>> 0)); }); testMathyFunction(mathy0, [2**53-2, -(2**53-2), 0x0ffffffff, -0x0ffffffff, 0x07fffffff, -(2**53+2), 42, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53), 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0, 2**53, -1/0, -0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, Math.PI, 1, 0x080000000, 1/0, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000]); \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: w = (4277), catchTermination: true })); } }); }");
/*fuzzSeed-221406266*/count=138; tryItOut("/*MXX3*/g2.RegExp.$3 = g2.RegExp.$3;");
/*fuzzSeed-221406266*/count=139; tryItOut("s2 += s0;");
/*fuzzSeed-221406266*/count=140; tryItOut("delete h2.has;\n((void version(180)));\n");
/*fuzzSeed-221406266*/count=141; tryItOut("v0 = new Number(t1);");
/*fuzzSeed-221406266*/count=142; tryItOut("mathy3 = (function(x, y) { return ( + Math.cos(Math.fround((( + (( + mathy2(x, (( + (( ! ( + y)) >>> 0)) >>> 0))) & y)) > Math.fround((Math.clz32(Math.atanh(0x080000001)) ? ( + Math.hypot(( + Number.MIN_VALUE), ( + x))) : ((Math.min((y >>> 0), (Math.min(y, x) >>> 0)) >>> 0) >> ((mathy1((Number.MIN_VALUE | 0), y) > Math.fround(y)) | 0)))))))); }); testMathyFunction(mathy3, [2**53-2, 0/0, 0.000000000000001, 0x07fffffff, 1.7976931348623157e308, 42, 2**53, -0, -0x080000000, 0, -(2**53+2), Number.MIN_VALUE, -0x0ffffffff, 1/0, 0x0ffffffff, 1, -1/0, Math.PI, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0x100000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53+2, 0x100000000]); ");
/*fuzzSeed-221406266*/count=143; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    switch ((((0x91f1725)) ^ (-(0xdfbb7e7d)))) {\n      case -3:\n        d1 = (d1);\n      case 0:\n        d0 = (d0);\n        break;\n      case 1:\n        {\n          d0 = (d0);\n        }\n        break;\n    }\n    d1 = (d0);\n    d0 = (d0);\n    d0 = (NaN);\n    d0 = (+(abs((((x)) & ((0x333640f8)+(0xac008239))))|0));\n    d0 = (d1);\n    d0 = ((d0));\n    {\n      d0 = (d1);\n    }\n    d0 = (d1);\n    return +((Float64ArrayView[2]));\n  }\n  return f; })(this, {ff: Map.prototype.forEach}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [1, -(2**53+2), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 2**53, 0x080000000, -0x080000000, -0x07fffffff, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 1/0, 0x07fffffff, -0x080000001, -1/0, 0x080000001, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x100000001, -(2**53), 0/0, Number.MAX_VALUE, 0, 0x100000000, 42, -0x0ffffffff, Number.MIN_VALUE, -0]); ");
/*fuzzSeed-221406266*/count=144; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2(((Math.ceil(mathy0((x - 1), ( + Math.imul(Math.fround((Math.imul((Math.cosh(y) >>> 0), y) | 0)), ( + Math.fround(( + Math.fround(( + (( + (Number.MAX_VALUE < x)) << ( + x))))))))))) >>> 0) >>> 0), (Math.fround((((Math.sin(Math.cbrt(x)) >>> 0) | (Math.expm1(Math.fround(Math.imul((-0x100000000 >>> 0), 2**53))) >>> 0)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0x080000001, 0x100000001, 1/0, 2**53-2, 2**53+2, Math.PI, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, 1, 0, -0x080000001, 0x080000000, 1.7976931348623157e308, -(2**53+2), -0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 0/0, -0x080000000, 42, -0x07fffffff, 0x0ffffffff, -(2**53), -0, Number.MIN_VALUE, 2**53, 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=145; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=\\1)/i; var s = \"\\u62c8\\u62c8\\u62c8\\u62c8\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=146; tryItOut("\"use strict\"; o0.v2 = o0.g1.eval(\"function f2(p0) \\\"use asm\\\";   var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    return ((((+(((0x43167196) % (((0xfbda5806))>>>((0xffffffff))))>>>(((Float64ArrayView[0]))-(i0)+(i0)))) == (36028797018963970.0))+(0xc784484e)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-221406266*/count=147; tryItOut("for (var p in g2) { try { o1.v2 = evalcx(\"o0.toSource = f1;\", g0); } catch(e0) { } try { v0 = (a2 instanceof b0); } catch(e1) { } m1 + f0; }");
/*fuzzSeed-221406266*/count=148; tryItOut("print(uneval(v0));");
/*fuzzSeed-221406266*/count=149; tryItOut("testMathyFunction(mathy5, [2**53-2, -0x100000000, 0.000000000000001, 0x080000000, 0x0ffffffff, 0/0, 2**53, -0x080000000, 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53), -1/0, 0x080000001, 42, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 1, 0x100000001, -(2**53-2), -0, 2**53+2, Number.MIN_VALUE, Math.PI, 0]); ");
/*fuzzSeed-221406266*/count=150; tryItOut("\"use strict\"; t2 = new Int16Array(b0);");
/*fuzzSeed-221406266*/count=151; tryItOut("\"use strict\"; ;");
/*fuzzSeed-221406266*/count=152; tryItOut("/*oLoop*/for (var lyrcme = 0; lyrcme < 114; ++lyrcme, 6) { g1.m2.delete(v1); } ");
/*fuzzSeed-221406266*/count=153; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( + ((Math.hypot(((( + x) / 2**53+2) | 0), ((Math.atan(Math.fround((((-Number.MAX_VALUE | 0) ? (Math.fround(Math.imul(Math.fround(x), Math.fround(y))) >>> 0) : (y | 0)) | 0))) >> Math.clz32(((x <= (y | 0)) | 0))) | 0)) | 0) - (Math.log2((Math.fround(mathy0(Math.fround(( ! (Number.MAX_SAFE_INTEGER | 0))), ( + ( + Math.min((y >>> 0), (x >>> 0)))))) | 0)) | 0))) >>> Math.pow((( + ( ~ x)) >>> 0), (mathy2((( ~ x) | 0), ( + Math.ceil(((((x >>> 0) - (y >>> 0)) >>> 0) >>> 0)))) == (0 / (-Number.MAX_VALUE >>> 0))))); }); testMathyFunction(mathy3, [2**53+2, -0x0ffffffff, 0x080000000, 0/0, -0x080000000, -Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 1/0, 2**53, 0x0ffffffff, 0x07fffffff, 42, -(2**53-2), Math.PI, 1.7976931348623157e308, -(2**53), 2**53-2, -0x100000001, Number.MAX_VALUE, -0, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, 1, 0]); ");
/*fuzzSeed-221406266*/count=154; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (mathy0(Math.fround(( ! ((((0x100000000 ^ Math.atanh(0/0)) | 0) ^ ( + (( ~ ( + Math.max(( + y), y))) >>> Math.trunc((mathy2((2**53 | 0), (x | 0)) | 0))))) >>> 0))), (Math.asinh((Math.sinh(Math.asin(( ! y))) ? x : ((y >> Math.pow((y >>> 0), (y >>> 0))) | 0))) >>> 0)) | 0); }); testMathyFunction(mathy5, [-(2**53+2), -Number.MAX_VALUE, 1/0, 0x0ffffffff, -0x07fffffff, 2**53+2, -0, -0x080000000, -0x100000001, 0x100000000, -0x0ffffffff, 0x080000000, 0, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, 1.7976931348623157e308, -0x080000001, -(2**53-2), 2**53-2, -(2**53), Number.MIN_VALUE, 42, Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, 2**53, Math.PI, -Number.MAX_SAFE_INTEGER, -1/0, 1, 0.000000000000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=155; tryItOut("Array.prototype.pop.call(a0, i2);");
/*fuzzSeed-221406266*/count=156; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-221406266*/count=157; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=158; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(b2, g1.g2.b1);");
/*fuzzSeed-221406266*/count=159; tryItOut("o0.h1.has = f1;");
/*fuzzSeed-221406266*/count=160; tryItOut("\"use strict\"; { void 0; minorgc(false); } L:switch( /x/g ) { default:  }");
/*fuzzSeed-221406266*/count=161; tryItOut("a0.pop();");
/*fuzzSeed-221406266*/count=162; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( - ( + (Math.fround(Math.cbrt(( + ((Math.atan(( + (( + x) >> ( + -(2**53+2))))) >>> 0) >= -Number.MAX_SAFE_INTEGER)))) >= Math.fround(Math.cbrt((x ? -(2**53+2) : y))))))); }); testMathyFunction(mathy3, /*MARR*/[new Number(1.5),  '' ,  '' , 0x07fffffff, {x:3}, 0x07fffffff, false, 0x07fffffff, {x:3}, new Number(1.5), {x:3}, new Number(1.5)]); ");
/*fuzzSeed-221406266*/count=163; tryItOut(";Array.prototype.shift.call(a2, s0, this.a0, v2, t1, b2, i2);");
/*fuzzSeed-221406266*/count=164; tryItOut("g0.m0.delete(s2);print(x);");
/*fuzzSeed-221406266*/count=165; tryItOut("v1 = t0.length;");
/*fuzzSeed-221406266*/count=166; tryItOut("\"use strict\";  for  each(let z in  \"\" .watch(\"wrappedJSObject\",  /x/ )) ;");
/*fuzzSeed-221406266*/count=167; tryItOut("this.e1 + p2;");
/*fuzzSeed-221406266*/count=168; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.pow(mathy4(Math.atan2(Math.cbrt((Math.min((x | 0), (2**53+2 | 0)) | 0)), y), mathy2((((Math.sinh(-0x07fffffff) | 0) ^ (mathy4(( + y), ( + Math.fround(mathy4(Math.fround((0x0ffffffff & Number.MAX_VALUE)), Math.fround(y))))) | 0)) | 0), Math.fround(Math.ceil(Math.fround((mathy0(2**53-2, x) >>> 0)))))), Math.min((Math.max((-Number.MIN_SAFE_INTEGER >>> 0), (( ~ (Math.ceil((y | 0)) | 0)) >>> 0)) >>> 0), (Math.min(( + Math.fround(( + Math.fround(( + Math.fround(-0x100000001)))))), (Math.hypot(y, (y * ((mathy3((x | 0), ( + x)) | 0) + x))) | 0)) | 0))); }); testMathyFunction(mathy5, /*MARR*/[true, true, true, true, true, true, true, true, true, true, true, (void 0), (void 0), (4277).\u0009throw(x), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, (4277).\u0009throw(x), true, true, (void 0), (4277).\u0009throw(x), (void 0), true, true, (void 0), true, true, (void 0), true, true, (void 0), (void 0), (4277).\u0009throw(x), (void 0), (void 0), (4277).\u0009throw(x), (4277).\u0009throw(x), true, (4277).\u0009throw(x), (void 0), (4277).\u0009throw(x), (4277).\u0009throw(x), true, (void 0), (void 0), (4277).\u0009throw(x), (void 0), (4277).\u0009throw(x), (4277).\u0009throw(x), (void 0), (4277).\u0009throw(x), (4277).\u0009throw(x), (4277).\u0009throw(x), (void 0), (void 0), (void 0), true, (4277).\u0009throw(x), (4277).\u0009throw(x), (void 0), (void 0), true, true, (void 0), true, (void 0), true, (void 0), true, (4277).\u0009throw(x), (void 0), (4277).\u0009throw(x), (void 0), (void 0), (void 0), (void 0), true, true, (void 0), true, (4277).\u0009throw(x), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), true, true, true, true, true, (4277).\u0009throw(x), (4277).\u0009throw(x), true, (4277).\u0009throw(x), true, (void 0), (4277).\u0009throw(x), true, (4277).\u0009throw(x), (void 0), true, (4277).\u0009throw(x), (void 0), true, (4277).\u0009throw(x), (4277).\u0009throw(x), (void 0), true, true, (void 0), true, true]); ");
/*fuzzSeed-221406266*/count=169; tryItOut("o2.h1.hasOwn = this.f1;");
/*fuzzSeed-221406266*/count=170; tryItOut("/*infloop*/M:for((4277); (false >> \"\\u279A\"); Math.max(15, Math.min(1,  /x/ ))) {this.o1.v1 = Object.prototype.isPrototypeOf.call(a1, h2); }");
/*fuzzSeed-221406266*/count=171; tryItOut("\"use strict\"; for (var p in i2) { try { t1[11]; } catch(e0) { } try { v1 = Array.prototype.reduce, reduceRight.apply(a0, [(function() { v1 = (s0 instanceof h0); return f2; })]); } catch(e1) { } e0.add(b2); }");
/*fuzzSeed-221406266*/count=172; tryItOut("t2 = t1.subarray(2);");
/*fuzzSeed-221406266*/count=173; tryItOut("v2 = a2.length;");
/*fuzzSeed-221406266*/count=174; tryItOut("\"use strict\"; a0.splice(NaN, 15, x);");
/*fuzzSeed-221406266*/count=175; tryItOut("/*vLoop*/for (exhjdd = 0; exhjdd < 86; ++exhjdd) { d = exhjdd; i0.next(); } ");
/*fuzzSeed-221406266*/count=176; tryItOut("t1 = new Int8Array(o2.b1, 112, ({valueOf: function() { const v1 = o1.t2.length;return 4; }}));Array.prototype.forEach.apply(g2.a1, [(function() { try { /*MXX2*/o1.g2.Date.UTC = g1; } catch(e0) { } try { a0.forEach(f2); } catch(e1) { } o1.t1 = new Uint32Array(16); return g1; }), x]);");
/*fuzzSeed-221406266*/count=177; tryItOut("\"use strict\"; /*RXUB*/var r = this.r0; var s = s2; print(uneval(r.exec(s))); ");
/*fuzzSeed-221406266*/count=178; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy3((Math.min((((( + Math.atan2(( + ( - (((x >>> 0) | (y >>> 0)) ? y : Math.fround(Math.max(x, 0x07fffffff))))), ( + y))) | 0) , x) | 0), ((mathy2((Math.cosh(( + Math.cosh(Math.fround(x)))) << y), (x | 0)) | 0) | 0)) | 0), mathy2(( + Math.imul(( + Math.min(((x || ( + ( + ( + x)))) ? ( - -0x080000001) : (Math.sqrt(y) | 0)), (x & x))), ( + y))), (Math.min((( + mathy0(( + Math.imul(0/0, Math.tanh(x))), Math.fround((Math.fround(Math.atanh(x)) > Math.fround(x))))) >>> 0), ((((x >>> 0) - ((x * ( + (x >= ( + x)))) >>> 0)) | 0) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-221406266*/count=179; tryItOut("\"use strict\"; s2 = g0.s2.charAt( '' );function window(x = (4277), x =  /x/g , c, a, w, x, x =  \"\" , x, b, d, x, y = [z1,,], x, w, \u3056 = new RegExp(\"(.)\", \"gyi\"), c, x, x, y = \"\\uB6DD\", z, x, c, x, x, x, x = x, b, a, b = x, eval, x =  \"\" , x = new RegExp(\".\", \"i\"), x, x, \u3056) { \"use strict\"; return (arguments[\"length\"] = 19) } for (var p in b0) { try { /*MXX3*/this.g1.WeakMap.name = g2.WeakMap.name; } catch(e0) { } this.o2.e1.has(new RegExp(\"[\\\\cV-\\\\u0db1\\\\S\\\\d]+\", \"ym\")); }");
/*fuzzSeed-221406266*/count=180; tryItOut("function f1(m2) \n(window).__defineGetter__(\"eval\", decodeURIComponent)");
/*fuzzSeed-221406266*/count=181; tryItOut("\"use strict\"; v1 = t1.length;");
/*fuzzSeed-221406266*/count=182; tryItOut("mathy0 = (function(x, y) { return ( ! ( + Math.imul(( + (Math.pow(Math.fround(Math.cbrt(x)), Math.fround((( + y) & Math.min((( ~ (y >>> 0)) >>> 0), (( - Math.fround(Math.atanh(0.000000000000001))) >>> 0))))) | 0)), ( + Math.max(Math.fround(( ! Math.fround(Math.sqrt(y)))), ( - ( + ( ~ ( + ( ! ( + Math.atan2(( + x), ( + x))))))))))))); }); testMathyFunction(mathy0, [-0, Math.PI, 1.7976931348623157e308, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, 0x100000000, 0/0, Number.MAX_VALUE, 2**53-2, 2**53, 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 0x100000001, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), 42, -0x0ffffffff, 2**53+2, -(2**53), -(2**53-2), Number.MIN_VALUE, 0, 0x0ffffffff, 1, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 0x080000000]); ");
/*fuzzSeed-221406266*/count=183; tryItOut("o2.valueOf = (function(j) { f2(j); });function x(b, ...window) { yield (4277) } for (var v of s1) { try { a1.pop(); } catch(e0) { } selectforgc(o1); }v0 = 0;a2[v2] = g1.s2;");
/*fuzzSeed-221406266*/count=184; tryItOut("this.zzz.zzz;");
/*fuzzSeed-221406266*/count=185; tryItOut("mathy5 = (function(x, y) { return (( - Math.atan2(Math.sin(x), mathy3(y, y))) >>> 0); }); testMathyFunction(mathy5, [1, -1/0, 0, 42, Number.MIN_VALUE, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, -0x100000001, 0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0x07fffffff, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -0x080000000, Math.PI, 0x080000001, -(2**53), 0x100000001, Number.MAX_VALUE, 2**53+2, 1/0, 0.000000000000001, 0x080000000, -(2**53+2), 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=186; tryItOut("\"use strict\"; i0.send(e1);");
/*fuzzSeed-221406266*/count=187; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Int16ArrayView[(((i1) ? (this) : (i0))) >> 1]) = ((i1)-(/*FFI*/ff()|0)-((((((0x32e83dee)) >> ((0xffffffff))) % (((0xfd16b610)) >> ((0xff6c3589)))) << ((i1)+(i0))) < ((((-134217729.0) != (-1.9342813113834067e+25))+(i1)+(i0)) ^ (((0xa585fbb) < (0x7fffffff))-(i0)+(i0)))));\n    return ((((0x54883b39) != (0xb544be6c))))|0;\n  }\n  return f; })(this, {ff: Uint16Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000001, 1.7976931348623157e308, 0.000000000000001, -0x080000000, 2**53+2, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, -0x07fffffff, 0x100000001, 2**53, -(2**53-2), -1/0, -0x100000001, 1, -Number.MAX_VALUE, -(2**53), Number.MIN_VALUE, 0/0, 0x07fffffff, -0, 0x080000000, 0x100000000, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 0, -(2**53+2), 42, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-221406266*/count=188; tryItOut("selectforgc(o0);");
/*fuzzSeed-221406266*/count=189; tryItOut("\"use strict\"; yield x;");
/*fuzzSeed-221406266*/count=190; tryItOut("\"use strict\"; /*RXUB*/var r = /[^]/gim; var s = \"\\n\"; print(s.replace(r, arguments)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=191; tryItOut("this.h0.defineProperty = (function(a0, a1) { var r0 = 4 ^ x; var r1 = x + r0; var r2 = r0 + 1; r2 = r0 + r2; print(r1); var r3 = 9 / 5; var r4 = r1 | x; x = x * 3; var r5 = x - r3; var r6 = x / 2; var r7 = a0 * x; var r8 = r1 * r5; var r9 = r7 - 0; var r10 = 0 & r3; var r11 = 6 * r0; var r12 = a0 ^ 7; var r13 = a1 ^ r2; var r14 = r8 + r9; var r15 = 5 + r1; var r16 = r11 % 2; var r17 = r6 ^ r7; r0 = r13 | 2; var r18 = r0 ^ r10; var r19 = r5 + a1; var r20 = r15 | r18; var r21 = 3 / r18; var r22 = r14 & r20; var r23 = 6 | 3; var r24 = r10 ^ r23; var r25 = r17 ^ 9; r11 = r22 & r8; print(r1); var r26 = r12 | 8; var r27 = 4 % 4; r24 = r7 / 2; var r28 = r24 + r21; r7 = 5 | a0; var r29 = a0 & 8; print(r5); var r30 = r29 + a1; var r31 = 6 ^ r12; r8 = r24 + r11; r5 = 7 | 6; r15 = 5 & 2; var r32 = r20 % r6; r14 = r16 % r2; var r33 = r14 | 5; var r34 = 9 - r20; var r35 = 0 / 5; var r36 = 9 ^ r4; var r37 = r1 | 5; var r38 = 0 ^ 2; var r39 = r4 % 7; var r40 = 1 + 3; var r41 = r25 / r39; r37 = r33 & a1; var r42 = r40 + r1; var r43 = r4 ^ 1; r24 = 6 % r19; var r44 = 0 & 4; var r45 = r12 % r34; var r46 = r39 - 9; r3 = 1 - 1; var r47 = 2 + 5; r40 = 8 * 2; var r48 = r0 & 2; var r49 = 6 | 8; var r50 = 8 * 1; var r51 = 6 - r47; print(r41); var r52 = 9 + r34; r43 = r7 ^ 4; r12 = 9 & r18; var r53 = 5 * r16; var r54 = r18 / r5; var r55 = 4 * r7; var r56 = r37 | r21; var r57 = r18 / x; var r58 = r51 % r47; print(r36); var r59 = r51 & 0; var r60 = 8 % r12; var r61 = 6 % a1; var r62 = r61 - r28; var r63 = 1 + r4; r26 = r33 * r31; var r64 = r48 & 7; var r65 = r58 - r2; print(r10); var r66 = r11 | r23; r41 = r47 + 1; var r67 = 3 / r3; var r68 = r25 / 2; var r69 = r22 ^ 4; r44 = 1 + 6; a1 = 8 % r43; var r70 = 7 * r29; print(r52); r61 = r60 | r53; r28 = r18 & 1; var r71 = r27 & r14; var r72 = r19 ^ r3; var r73 = r29 % r6; var r74 = 5 & r37; r10 = 9 ^ r20; r31 = r21 % r21; r25 = r51 | r49; var r75 = 0 / 7; var r76 = r22 - r29; var r77 = r64 & 5; var r78 = r25 * r19; var r79 = r76 + 3; var r80 = 2 & r2; r63 = 2 ^ r28; var r81 = a1 * r33; r62 = 9 / r3; var r82 = 6 | r52; print(r45); r44 = 5 & 2; var r83 = r82 ^ r80; var r84 = r8 - r70; var r85 = r55 % r55; var r86 = r45 - r0; print(r60); r43 = r13 & 9; var r87 = 4 / r42; print(r16); a0 = r32 / r50; var r88 = r20 / r14; r84 = 0 & r52; var r89 = 9 ^ r29; r10 = r32 / 8; var r90 = 4 & r54; r64 = 0 - 3; print(r67); r23 = 0 / r48; var r91 = r17 + r90; var r92 = 1 * r38; var r93 = 3 | r4; var r94 = r21 | r41; var r95 = a0 & r0; a0 = r77 ^ x; print(r65); r6 = r83 - 3; var r96 = r75 | 0; var r97 = r88 % 7; var r98 = r34 - 5; var r99 = r75 * a1; var r100 = r17 - 7; var r101 = r31 * 0; var r102 = 8 & r37; var r103 = 4 % r85; var r104 = r54 % r87; r51 = 5 / r89; r54 = r83 % r59; var r105 = r16 ^ r22; var r106 = 4 % r25; var r107 = r0 * r57; r4 = r78 | 1; var r108 = 4 | r30; var r109 = 5 % 0; var r110 = r70 + 7; var r111 = r40 % 5; var r112 = r97 + 3; var r113 = r2 + 6; var r114 = r10 / 1; var r115 = r1 + r58; var r116 = r29 & 6; var r117 = 9 / 6; var r118 = r1 - r39; var r119 = 4 + 6; print(r117); var r120 = r58 & r1; var r121 = r20 - r54; var r122 = r81 + 3; var r123 = r34 + r105; var r124 = r40 + 3; var r125 = r81 | 0; var r126 = r64 & 5; var r127 = r115 - r36; var r128 = r115 - 6; var r129 = r117 + r67; var r130 = 7 | r115; var r131 = r126 & 2; var r132 = r98 ^ 0; var r133 = r92 * 3; var r134 = r18 % r117; var r135 = 6 * 0; var r136 = 8 / r21; var r137 = r98 & r70; var r138 = r84 | r22; var r139 = r18 ^ r92; var r140 = 1 ^ r50; var r141 = 6 | r43; var r142 = 2 / 6; var r143 = r135 & 3; print(r56); r50 = r20 ^ r25; var r144 = r31 - a0; var r145 = r0 * 3; r83 = r40 * r102; var r146 = r96 ^ r18; var r147 = 1 | 8; var r148 = r142 & r61; var r149 = r15 ^ 6; r62 = 6 + 8; var r150 = r29 * r104; var r151 = 0 & r133; r137 = 5 + 5; var r152 = r105 - 9; var r153 = r69 * 6; var r154 = r113 / r129; var r155 = 6 ^ r120; var r156 = 8 & r124; r121 = r135 & r13; var r157 = 7 * r26; var r158 = r49 ^ 6; r124 = r84 - 8; var r159 = r6 * r83; var r160 = 0 + r81; var r161 = r38 / r35; var r162 = r79 * r47; var r163 = r37 % r129; var r164 = r128 % r0; var r165 = 5 - 4; var r166 = 9 - 2; r78 = r83 ^ r65; var r167 = r94 % 2; var r168 = r71 | 0; r107 = r18 + 3; var r169 = r156 | r146; var r170 = r87 - r54; var r171 = r12 + 1; var r172 = r100 % 5; var r173 = r94 * r24; var r174 = 6 % r55; r173 = 2 | 3; var r175 = 7 * 5; var r176 = r140 & 1; r5 = r170 - r126; var r177 = 3 / r44; r34 = 7 - r14; var r178 = r112 | r42; r61 = r134 * 3; var r179 = r100 | r52; var r180 = r28 % r12; var r181 = r35 ^ r102; var r182 = r8 - r129; var r183 = r58 + r160; var r184 = r135 & 5; var r185 = 9 | r163; var r186 = 2 - 6; r157 = 1 & r30; r123 = r45 * 8; var r187 = r129 % r114; var r188 = r172 / 5; r5 = 1 + r47; var r189 = r164 / r184; r138 = r143 ^ r125; var r190 = r151 + r154; var r191 = 3 / r76; var r192 = r141 ^ r65; var r193 = r136 * 1; var r194 = 4 & r102; r84 = 1 ^ 2; var r195 = 4 ^ r39; r35 = r89 / r173; var r196 = r172 - 6; var r197 = 2 - r149; var r198 = r51 * 1; var r199 = r15 % 5; var r200 = r26 & r43; var r201 = 9 / 3; var r202 = r20 % r102; var r203 = 4 | r50; print(r71); var r204 = r35 * 0; r161 = r183 & r99; var r205 = 2 % 6; var r206 = 7 | r184; r48 = r125 / r44; var r207 = r135 & a1; var r208 = 9 / 9; var r209 = r55 ^ r135; r84 = 4 ^ 5; r91 = r141 / r112; r117 = 4 / r124; r113 = r197 * r101; var r210 = 7 | 1; r59 = r146 * 6; var r211 = 9 ^ 9; r162 = r207 & r202; var r212 = r157 | 0; var r213 = r52 - r101; r3 = 8 % r55; var r214 = 7 + 0; var r215 = r129 - 0; var r216 = 4 - r93; var r217 = 5 | 4; var r218 = r117 - r48; r128 = r152 / r35; var r219 = 0 & 9; var r220 = r99 % r154; var r221 = r217 ^ r128; var r222 = r159 | 9; var r223 = 7 / r201; return x; });");
/*fuzzSeed-221406266*/count=192; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=193; tryItOut("var txxseu = new SharedArrayBuffer(16); var txxseu_0 = new Uint8Array(txxseu); print(txxseu_0[0]); var txxseu_1 = new Int32Array(txxseu); txxseu_1[0] = 10; (new RegExp(\"(?:(?:\\\\2)*){3,7}\\\\1{3}\", \"gyim\"));(true);");
/*fuzzSeed-221406266*/count=194; tryItOut("\"use strict\"; const e, x = (new ((eval(\"[z1]\")))()), xrezqr, gwping, qmtvtz;/*MXX1*/o1 = g2.Math.cbrt;");
/*fuzzSeed-221406266*/count=195; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.exp(Math.fround(( ! (Math.fround(Math.expm1(Math.fround(( + x)))) | 0)))); }); testMathyFunction(mathy0, [0/0, 0x080000000, -1/0, 0, -0, 1.7976931348623157e308, 2**53-2, 0x100000001, -0x080000001, 0x07fffffff, 2**53+2, 42, Math.PI, 1, -0x100000000, -0x07fffffff, 0x100000000, 1/0, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -(2**53-2), 0.000000000000001, 0x0ffffffff, 0x080000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, Number.MIN_VALUE, -(2**53+2), 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=196; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\", \"im\"); var s = \"\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=197; tryItOut("/*hhh*/function yqthtb(x, x, window, x, e, \u3056, d, c, w, x = \"\\u7FCC\", x, \u3056, b, x, \u3056, a, NaN, x, x = -2, b, \u3056, [,,z1], x, e, get, x, true, x = Math, x, y = -24, eval, z, y, NaN = \"\\u7BBA\", z, z, a, a, a, window, eval, x = x, x = \"\\u30BC\", x, x, x, a, d, y, d, x, e, y, x = \"\\uF66B\", x, b, x, x, z = y){print(x);}yqthtb(x);");
/*fuzzSeed-221406266*/count=198; tryItOut("/*vLoop*/for (let wzzcbp = 0,  /x/ ; wzzcbp < 47; ++wzzcbp) { e = wzzcbp; s2 += 'x'; } let w = new ((1 for (x in [])))();");
/*fuzzSeed-221406266*/count=199; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ (Math.min(( + ( ! (-0x0ffffffff - ((y >>> 0) + (Number.MIN_VALUE >>> 0))))), Math.max(x, y)) ? ( + mathy0((Math.pow(0x080000000, 42) >>> 0), Math.fround(Math.min(( - ( + Math.fround(( ! ( + x))))), (Math.fround(( ~ ( + x))) % x))))) : ((((( - ( + Math.min(((x << y) | 0), ( + ( - (x >>> 0)))))) >>> 0) | 0) ** (x | 0)) | 0))); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), new String('q'), true, new String('q'), x, new String('q'), new String('q'), x, true, x, x, x, x, x, x, x, x, x, x, x, true, x, true, x, x, true, x, true, x]); ");
/*fuzzSeed-221406266*/count=200; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( - ( + (( + Math.fround(Math.fround(Math.atan(Math.fround(x))))) | Math.hypot(( + (( + ( + (( + y) != ( + (mathy0((y >>> 0), Math.fround(x)) >>> 0))))) ? ( + y) : (Math.fround((Math.fround(y) !== Math.fround(mathy0(Math.fround(x), Math.fround(-(2**53+2)))))) >>> 0))), Math.trunc(-0x07fffffff)))))); }); ");
/*fuzzSeed-221406266*/count=201; tryItOut("print(3);print(this);\nthrow \"\\uAC34\";\n");
/*fuzzSeed-221406266*/count=202; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=203; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.acos(( + (( + ((Math.hypot((Math.log1p((mathy1(y, Math.log1p(-0x080000000)) | 0)) >>> 0), (Math.pow((( ! (x | 0)) | 0), (Math.cosh((2**53 >>> 0)) | 0)) >>> 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy2, [Math.PI, 0x080000000, -0x0ffffffff, -0, 0/0, -0x080000000, -0x07fffffff, 0x0ffffffff, 0, -(2**53+2), 2**53, 0x07fffffff, 42, 2**53+2, -Number.MIN_VALUE, 0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, Number.MAX_VALUE, 2**53-2, -1/0, 1, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), 0x100000001]); ");
/*fuzzSeed-221406266*/count=204; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround((( + Math.fround(Math.tan(( - mathy0(y, Math.asinh([])))))) == Math.fround(Math.fround(mathy3((Math.fround(Math.pow(Math.fround(Math.fround(( + Math.asinh(Math.exp(-0))))), ((y >>> 0) * -0x080000001))) | 0), (((( - (Math.log10((( + Math.imul((Math.hypot(y, y) | 0), ( + 2**53))) | 0)) >>> 0)) >>> 0) >>> Math.fround(mathy4(Math.fround(Math.tan(-0x07fffffff)), Math.fround(( + (y | 0)))))) | 0)))))); }); testMathyFunction(mathy5, [NaN, undefined, 0, ({valueOf:function(){return 0;}}), '', '\\0', [0], (new Number(0)), true, false, ({valueOf:function(){return '0';}}), '0', (function(){return 0;}), objectEmulatingUndefined(), [], (new String('')), 0.1, (new Boolean(false)), '/0/', null, 1, /0/, (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(true)), -0]); ");
/*fuzzSeed-221406266*/count=205; tryItOut("(this);");
/*fuzzSeed-221406266*/count=206; tryItOut("a0.unshift(p2, this.i0, p2);\nm0.__proto__ = m2;\n");
/*fuzzSeed-221406266*/count=207; tryItOut("v0 = t1.length;");
/*fuzzSeed-221406266*/count=208; tryItOut("testMathyFunction(mathy2, [({toString:function(){return '0';}}), [0], (new Number(-0)), '', '\\0', ({valueOf:function(){return 0;}}), -0, (function(){return 0;}), '0', 0.1, (new Boolean(false)), /0/, 0, '/0/', NaN, (new String('')), ({valueOf:function(){return '0';}}), (new Boolean(true)), undefined, null, [], true, 1, (new Number(0)), objectEmulatingUndefined(), false]); ");
/*fuzzSeed-221406266*/count=209; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-221406266*/count=210; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(( + Math.tan(( + Math.imul((y % ((-Number.MIN_SAFE_INTEGER ? Math.asinh(( + x)) : (Math.abs((Number.MAX_VALUE | 0)) | 0)) | 0)), Math.imul(Math.clz32((y > x)), (( + (Math.fround(Math.pow(Math.fround((Math.cos(Math.fround(y)) >>> 0)), y)) >>> 0)) >>> 0))))))) >>> Math.fround(Math.fround(Math.imul(Math.fround(Math.max(y, ((( + yield this) || ( + ( ~ y))) | 0))), Math.fround(( + Math.hypot(( + y), ( + Math.imul(Math.fround(Math.fround(( ~ ((Math.fround(x) << (0x080000000 | 0)) | 0)))), (x | 0)))))))))); }); testMathyFunction(mathy0, [-0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -(2**53+2), 1.7976931348623157e308, 2**53-2, 0x07fffffff, 42, Number.MIN_SAFE_INTEGER, 0, 0x100000001, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -0x080000001, 1, -Number.MAX_VALUE, Math.PI, 2**53+2, 2**53, -0x100000000, 0/0, 0x080000000, 0x100000000, 1/0, 0x080000001, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-221406266*/count=211; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.pow(Math.log10((Math.fround(Math.sign(Math.fround(-0x0ffffffff))) && Math.fround(( + (( + Math.fround((1/0 > ( + ( + mathy1(y, x)))))) === ( + 2**53-2)))))), (mathy4((Math.fround(Math.imul((( + Math.log(( + Math.tan(x)))) | 0), (Math.atan2(Math.fround(Math.atanh(( + Math.tanh(( + Math.fround((-0x100000000 >>> 0))))))), (2**53-2 % 0x080000000)) >>> 0))) | 0), ((Math.sqrt(Math.max(x, (y >>> 0))) ? (x | 0) : ( + x)) | 0)) | 0)); }); testMathyFunction(mathy5, [Math.PI, -0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, -0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1, 2**53-2, -0, 1.7976931348623157e308, 0x080000000, -(2**53+2), 0x100000001, 0.000000000000001, 0/0, 42, -0x100000001, Number.MIN_VALUE, 0, 2**53+2, 0x100000000, 0x0ffffffff, 1/0, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=212; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.fround(Math.imul(( ! (Math.atan2((y >>> 0), (y >>> 0)) >>> 0)), (( - (y >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-221406266*/count=213; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = new RegExp(\"((?!\\\\B){1}{1}\\\\d(?:[^\\\\D\\\\d])){2}|.+\\\\3|(?=\\\\B){2}([^])|[^]{1}?\\\\D*\", \"im\"); var s = \"_a1\\ua733a \\u66d4\\u7b8a1\\ua733a \\u66d4\\u7b8aa0\"; print(s.match(r)); ");
/*fuzzSeed-221406266*/count=214; tryItOut("\"use strict\"; t1 = t2.subarray(16, 11);");
/*fuzzSeed-221406266*/count=215; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=216; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=217; tryItOut("delete x.eval;");
/*fuzzSeed-221406266*/count=218; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.min(Math.clz32(Math.fround(Math.log1p(Math.fround(((Math.fround(Math.fround(( ! x))) << Math.fround(x)) === 0x080000001))))), (mathy0(( + Math.max(( + Math.sin(( + (x < Math.log(y))))), ( + (Math.log10((-0x100000000 == y)) >>> 0)))), Math.hypot(( + Math.asin(( + ( + ( ! Math.fround(( + -(2**53-2)))))))), ( + Math.asin(0)))) >>> 0)); }); testMathyFunction(mathy1, [1.7976931348623157e308, 1, Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, 0, 0x100000000, 1/0, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0, -0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, 42, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, Math.PI, 2**53-2, -0x100000000, -1/0, -(2**53), -0x100000001, -0x080000001]); ");
/*fuzzSeed-221406266*/count=219; tryItOut("\"use strict\"; print(i0);");
/*fuzzSeed-221406266*/count=220; tryItOut("/*ADP-1*/Object.defineProperty(a2, 9, ({get: String.prototype.slice, set: (new Function(\"g0.g0.v0 = r0.compile;\")), configurable: (x % 3 == 0)}));");
/*fuzzSeed-221406266*/count=221; tryItOut("mathy2 = (function(x, y) { return (Math.sqrt((( ! (Math.acos(((( ! (Math.log2(y) | 0)) | 0) >>> 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[(void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-221406266*/count=222; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy1((Math.asinh(( + Math.max((Math.pow(Math.sqrt(-0x07fffffff), y) | 0), ((Math.imul(( + Math.imul(( + -0x080000001), x)), (0x0ffffffff | 0)) | 0) | 0)))) >>> 0), ( ~ ( + Math.acosh(x)))); }); ");
/*fuzzSeed-221406266*/count=223; tryItOut("([] = 10);");
/*fuzzSeed-221406266*/count=224; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=225; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"function f0(s1)  { /*tLoop*/for (let w of /*MARR*/[ '\\\\0' ,  /x/ , -0,  /x/ ,  /x/ ,  /x/ , new Boolean(true),  '\\\\0' , new Boolean(true),  '\\\\0' , -0,  '\\\\0' ,  '\\\\0' , new Boolean(true),  '\\\\0' ,  '\\\\0' , -0, new Boolean(true), -0,  '\\\\0' , new Boolean(true),  /x/ , -0, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), -0,  /x/ , new Boolean(true), -0,  '\\\\0' ,  /x/ ,  /x/ ,  '\\\\0' ,  /x/ ]) { /* no regression tests found */ } } \");");
/*fuzzSeed-221406266*/count=226; tryItOut(";");
/*fuzzSeed-221406266*/count=227; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - (Math.expm1(( ~ Math.fround(((Math.fround(mathy3(Math.fround(y), Math.fround(mathy2(-0x080000001, Math.fround(( ~ y)))))) >>> 0) === ((( + ((42 > -0x100000001) | 0)) >>> 0) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [2**53+2, -0x100000001, -(2**53+2), 1, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -Number.MAX_VALUE, 42, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, -0x080000000, 0x080000001, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, -0x080000001, 0/0, -(2**53-2), 0, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x100000001, 2**53, -0x0ffffffff, Number.MIN_VALUE, -0, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=228; tryItOut("testMathyFunction(mathy2, [-0x080000001, 0x100000000, 2**53+2, 0.000000000000001, -(2**53+2), 0/0, 0x080000001, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000001, -0x080000000, -Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, 2**53, 1/0, 1.7976931348623157e308, 0x080000000, 0, Math.PI, -(2**53-2), -0, -0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53)]); ");
/*fuzzSeed-221406266*/count=229; tryItOut("/*bLoop*/for (let xyxcpl = 0; xyxcpl < 74 && (x); ++xyxcpl) { if (xyxcpl % 2 == 1) { a1.forEach((function() { try { o1 + ''; } catch(e0) { } try { g2.__proto__ = g0.g1.g2.t2; } catch(e1) { } try { for (var v of b0) { try { g1.a2 = Array.prototype.concat.call(this.a1, a0); } catch(e0) { } try { this.h0 + f1; } catch(e1) { } this.s0.__iterator__ = (function() { try { s2 += 'x'; } catch(e0) { } try { this.o2.v2 + ''; } catch(e1) { } ; return p1; }); } } catch(e2) { } ; return this.o1.e0; }), a2, this.g0.g0, window, b0, p1, a1); } else { v1 = evalcx(\"print(w =  /x/ );\", g0); }  } ");
/*fuzzSeed-221406266*/count=230; tryItOut("\"use strict\"; /*vLoop*/for (var yedfkq = 0; yedfkq < 58; ++yedfkq) { const w = yedfkq; print(x); } ");
/*fuzzSeed-221406266*/count=231; tryItOut("/*RXUB*/var r = /(?=\\W)/im; var s = \"0\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=232; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=233; tryItOut("\"use strict\"; h0 + h1;");
/*fuzzSeed-221406266*/count=234; tryItOut("/*infloop*/M:for(((x)((x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: Map, getOwnPropertyNames: undefined, delete: eval, fix: function() { return []; }, has: function() { return false; }, hasOwn: a, get: undefined, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(-1), d = Proxy.create(({/*TOODEEP*/})( '' ), \"\\u2046\")))).yoyo(c = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function (e) { \"use strict\"; return ({prototype:  \"\"  }) >> (void version(185)) } , getPropertyDescriptor: x, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return false; }, iterate: undefined, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(let (dwdkpe, x = [z1], fmwwkd, x, qqcnxa, z, miwers, x, ndzjnr, buqgxp) new (\"\\uB652\")(x)), (([])) = (({a1:1}).valueOf())))); ((function too_much_recursion(qprcxp) { ; if (qprcxp > 0) { /*RXUB*/var r = r2; var s = s0; print(s.split(r)); ; too_much_recursion(qprcxp - 1);  } else {  }  })((/*RXUE*//\\W/gim.exec(x)))) |= (4277);  /x/ ) {print(\"\\u7C54\"); }");
/*fuzzSeed-221406266*/count=235; tryItOut("/*RXUB*/var r = /(?=(^)(?=.){4}*?|^?)+/yi; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-221406266*/count=236; tryItOut("mathy5 = (function(x, y) { return (( + Math.max(mathy2(Math.fround(Math.pow((y | 0), Math.fround(( + Math.max(x, ( + Math.sin((y | 0)))))))), x), ((x | 0) && (0x100000000 | 0)))) , (Math.hypot((( ! Math.fround(Math.min((x ? x : (0x100000001 >>> 0)), Math.min((y | 0), ( + Math.sin(x)))))) | 0), ((Math.expm1((x ? Math.max(y, (mathy3((( + Math.log(( + x))) >>> 0), (y >>> 0)) >>> 0)) : Math.fround(( + Math.fround((Math.sqrt((x | 0)) | 0)))))) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy5, [-(2**53-2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, 2**53, 2**53-2, -0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, 0x07fffffff, -(2**53+2), -(2**53), 1, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, -0, 0x080000001, Math.PI, 1.7976931348623157e308, -0x100000001, 0, Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, -0x07fffffff, 0x100000001, 0x0ffffffff, 1/0, 0/0]); ");
/*fuzzSeed-221406266*/count=237; tryItOut("i1 + i2;");
/*fuzzSeed-221406266*/count=238; tryItOut("a0[(new DataView(\"\\u1B4A\"))] = b.cosh(~(window|=true) - (1 for (x in []))() > window);");
/*fuzzSeed-221406266*/count=239; tryItOut("\"use strict\"; t1[({valueOf: function() { for(var d = \"\\u580C\" in window) {v1 = g0.runOffThreadScript();p0 + a1; }return 0; }})] = d == e;var z = x;");
/*fuzzSeed-221406266*/count=240; tryItOut("\"use strict\"; h2.delete = f0;function window() { \u000cyield (makeFinalizeObserver('tenured')) } a1 = Array.prototype.slice.apply(this.o2.a2, [3, -1]);");
/*fuzzSeed-221406266*/count=241; tryItOut("/*RXUB*/var r = new RegExp(\"^\", \"gm\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-221406266*/count=242; tryItOut("for (var v of v0) { try { o0.v1 = g1.runOffThreadScript(); } catch(e0) { } try { s1 + ''; } catch(e1) { } o0 = Object.create( '' ); }");
/*fuzzSeed-221406266*/count=243; tryItOut("\"use strict\"; v2[\"getMinutes\"] = m1;");
/*fuzzSeed-221406266*/count=244; tryItOut("/*ODP-2*/Object.defineProperty(f2, \"NaN\", { configurable: [ /x/ ], enumerable: true, get: f1, set: (function() { t1 = new Uint16Array(b0, 152, 5); return g1.g0; }) });");
/*fuzzSeed-221406266*/count=245; tryItOut("mathy4 = (function(x, y) { return Math.exp(( - ( ! y))); }); testMathyFunction(mathy4, [0/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, 0x07fffffff, 0x100000000, 2**53+2, 1.7976931348623157e308, -(2**53-2), -0, Number.MAX_SAFE_INTEGER, 0x080000001, 42, -0x080000001, Number.MIN_VALUE, 0x100000001, -(2**53+2), -Number.MAX_VALUE, Number.MAX_VALUE, 2**53, -(2**53), 2**53-2, 0x080000000, 0, -0x100000000, 0.000000000000001, -1/0, 1/0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-221406266*/count=246; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=247; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.abs((Math.pow(((-Number.MAX_VALUE ? (y >>> 0) : (x >>> 0)) >>> 0), (Number.MAX_VALUE ** y)) ? ( + Math.hypot(x, x)) : 2**53))) + Math.tanh(( + (( + (Math.atan2((0.000000000000001 | 0), (Math.hypot(x, Math.pow(2**53, x)) | 0)) | 0)) % ( + x))))) <= ( + (Math.sqrt(Math.fround(( + ( + -Number.MIN_VALUE)))) > ( + Math.expm1(( + x)))))); }); ");
/*fuzzSeed-221406266*/count=248; tryItOut("\"use strict\"; /*infloop*/for(\"\\uDEA5\"; ({/*toXFun*/toSource: function() { return ((4277) % /[^]/gy); }, __parent__: null.__defineSetter__(\"x\", function(y) { return true }) }); ({y: x, abs:  \"\"  })) print(new  /x/ ( /x/ , this));");
/*fuzzSeed-221406266*/count=249; tryItOut("\"use strict\"; print(((p={}, (p.z = d)())));/*hhh*/function pfaley(){(/\\2/m);}/*iii*/print(pfaley);");
/*fuzzSeed-221406266*/count=250; tryItOut("for (var v of f1) { try { f0 = Proxy.createFunction(h0, f0, f0); } catch(e0) { } t2.set(a1, ([] = eval(\"/* no regression tests found */\", (new WebAssemblyMemoryMode(-20, 4))))); }");
/*fuzzSeed-221406266*/count=251; tryItOut("\"use strict\"; v1 = g0.eval(\"function f2(g1)  { \\\"use strict\\\"; yield  /x/g  } \");");
/*fuzzSeed-221406266*/count=252; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=253; tryItOut("M:do m0.has(h0); while((19) && 0);");
/*fuzzSeed-221406266*/count=254; tryItOut("mathy1 = (function(x, y) { return Math.min((( + Math.fround(Math.max(( + Math.round(( + x))), ( + (Number.MAX_VALUE ? (-0x0ffffffff | 0) : y))))) % (( + (( + y) , Math.imul((Math.atan2(y, 0x0ffffffff) >>> 0), y))) >>> 0)), ((( - (Math.hypot((2**53 >>> 0), x) >>> 0)) >= (x >= ( - x))) | 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x100000000, 0x100000001, -(2**53+2), -0, 1, 0.000000000000001, 0/0, 2**53-2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -(2**53-2), -0x07fffffff, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, 2**53+2, -(2**53), Math.PI, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, 1/0, 2**53, 0x080000001, 0, -1/0]); ");
/*fuzzSeed-221406266*/count=255; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x07fffffff, 2**53, 0/0, -0, 1, 1/0, 0x080000000, -0x100000000, 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000001, -(2**53-2), 0, Math.PI, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -1/0, -(2**53+2), 0x100000000, -(2**53), -Number.MAX_VALUE, -0x080000000, -0x0ffffffff, 42, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-221406266*/count=256; tryItOut("\"use strict\"; h0.fix = WeakSet.prototype.delete.bind(a1);");
/*fuzzSeed-221406266*/count=257; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    switch ((0x10b126c9)) {\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x0ffffffff, 2**53-2, -(2**53), Number.MIN_SAFE_INTEGER, 1, -0x080000000, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, -1/0, -0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), 0.000000000000001, 0x100000001, -0x100000000, 0x080000001, Number.MIN_VALUE, 2**53+2, 1/0, -0, 0, -Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, -0x100000001, -0x07fffffff, 2**53, 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-221406266*/count=258; tryItOut("t2 = t2[x];");
/*fuzzSeed-221406266*/count=259; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( + Math.fround(Math.hypot(Math.fround((Math.log2(((y == ((y ? y : ((Math.acosh(Math.PI) | 0) >>> 0)) | 0)) >>> 0)) >>> 0)), Math.fround(mathy2(y, (Math.pow((y | 0), (1.7976931348623157e308 | 0)) | 0)))))) <= ((Math.fround((Math.fround(Math.max(Math.fround(y), Math.fround(x))) == ( + Math.hypot(( + ( ~ Math.pow(((( + x) & ( + -Number.MIN_VALUE)) | 0), y))), Math.fround((((Math.asinh(( + y)) >>> 0) / ((((x >>> 0) || (y | 0)) | 0) >>> 0)) >>> 0)))))) < Math.fround(((Math.trunc(Math.fround(mathy3(Math.fround(( + (0x0ffffffff ? ( + 0x0ffffffff) : y))), Math.fround(Math.atan((mathy0(x, (x >>> 0)) >>> 0)))))) | 0) + x))) >>> 0)) | 0); }); testMathyFunction(mathy4, [0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, 1/0, -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, 0, -0, 2**53, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE, 42, -1/0, -0x080000000, -(2**53-2), -0x100000000, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 1, 2**53-2, 0/0, -(2**53+2), 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-221406266*/count=260; tryItOut("\"use strict\"; /*oLoop*/for (let fktsyo = 0; fktsyo < 35; ++fktsyo) { g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 5 == 4), catchTermination: true })); } ");
/*fuzzSeed-221406266*/count=261; tryItOut("mathy4 = (function(x, y) { return Math.hypot((Math.atanh((Math.fround(Math.pow(Math.log1p(x), Math.fround(( ~ y)))) | 0)) | 0), ( - (Math.max(( + (( + x) % (Math.abs(y) >>> 0))), Math.min(Math.fround(y), Math.fround(y))) >>> 0))); }); ");
/*fuzzSeed-221406266*/count=262; tryItOut("/*hhh*/function kbgyxx(){let (pmoeju, [, eval, , , []] = window, b = (4277), vjzrjz, agguzg, x) { /*oLoop*/for (let xcdwfe = 0; xcdwfe < 61; ++xcdwfe) { m2.get(h1); }  }}kbgyxx(x);");
/*fuzzSeed-221406266*/count=263; tryItOut("/*infloop*/for(x in (((eval = \"\\uB897\")(x) = (\"\\u59E1\" >= eval)))) {print( '' ); }");
/*fuzzSeed-221406266*/count=264; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ! Math.exp((( + (( + ( + Math.imul(Math.fround(y), (1.7976931348623157e308 | 0)))) | ( + Math.cosh(Math.acosh(x))))) ^ Math.atan2(y, (x & ( - Math.fround(( ~ Math.fround(Number.MAX_SAFE_INTEGER))))))))) | 0); }); testMathyFunction(mathy0, [-0x100000001, 1, 2**53+2, -0x0ffffffff, Math.PI, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, 0x100000000, 0x080000001, -0x080000000, 0, Number.MAX_VALUE, 0x080000000, -0x080000001, 0/0, 1/0, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0x100000001, 2**53, -(2**53), -1/0, Number.MIN_VALUE, -0, 0.000000000000001, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=265; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.sign(Math.fround(( + Math.sign((( + Math.trunc(y)) | 0)))))); }); testMathyFunction(mathy3, [0x0ffffffff, 2**53-2, 0x100000000, -Number.MAX_VALUE, 0.000000000000001, 2**53+2, 0x100000001, 0x080000001, 2**53, 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, -0x100000001, 0, -(2**53+2), 0/0, 0x080000000, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0, 1.7976931348623157e308, -0x080000001, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, -0x07fffffff, -0x0ffffffff, 42]); ");
/*fuzzSeed-221406266*/count=266; tryItOut("\"use strict\"; this.v1 = r2.toString;");
/*fuzzSeed-221406266*/count=267; tryItOut("/*oLoop*/for (let mwfkrr = 0; mwfkrr < 47 && ((x--)); ++mwfkrr) { for (var v of t2) { try { for (var p in t0) { try { /*RXUB*/var r = this.r1; var s = this.s2; print(r.exec(s));  } catch(e0) { } try { g0.v0 = (g2.o0 instanceof i1); } catch(e1) { } o0 + ''; } } catch(e0) { } try { o2.h0.toSource = Array.bind(o2); } catch(e1) { } Object.defineProperty(this, \"s1\", { configurable:  \"\" , enumerable: true,  get: function() {  return new String; } }); } } ");
/*fuzzSeed-221406266*/count=268; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( ! Math.fround(mathy0(Math.tan(Math.min(-0, y)), (Math.fround(Math.atan2(Math.fround(x), Math.fround(x))) + (( ! y) >>> 0)))))); }); testMathyFunction(mathy3, [-0, Math.PI, -(2**53+2), -(2**53-2), 0x0ffffffff, 1/0, Number.MIN_VALUE, 2**53-2, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, 0x080000000, 2**53, -0x100000001, 0.000000000000001, 0x100000001, 0, -(2**53), Number.MAX_VALUE, -0x100000000, -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 42, 2**53+2, 0/0, Number.MAX_SAFE_INTEGER, 0x080000001, 1, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=269; tryItOut("testMathyFunction(mathy0, [Math.PI, -0x080000001, -0x07fffffff, -(2**53), 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, 2**53-2, 0x07fffffff, 42, 0x0ffffffff, 0.000000000000001, -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, 0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0/0, 0, 1, Number.MIN_SAFE_INTEGER, -0, 0x080000000, -(2**53+2), -Number.MAX_VALUE, 1/0, 2**53+2, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=270; tryItOut("\"use strict\"; let y = x;return -15;");
/*fuzzSeed-221406266*/count=271; tryItOut("\"use strict\"; if((x % 45 == 27)) new RegExp(\"\\\\W|(?=\\\\B|\\\\2?\\\\2[2-\\u00ba\\\\n-\\u9084\\\\D\\\\S]|$+)\", \"g\") else {this.a2 = a0.slice(NaN, NaN); }");
/*fuzzSeed-221406266*/count=272; tryItOut("\"use strict\"; v1 = (h1 instanceof f0);\nfor (var v of o0.g0.e2) { try { this = a2[({valueOf: function() { print(x);return 1; }})]; } catch(e0) { } try { neuter(b1, \"change-data\"); } catch(e1) { } try { selectforgc(o0); } catch(e2) { } for (var v of s1) { try { f1 + ''; } catch(e0) { } try { v2 = r2.ignoreCase; } catch(e1) { } try { Array.prototype.shift.apply(a0, [o2.m2, h2, h2]); } catch(e2) { } i2.send(p1); } }\n");
/*fuzzSeed-221406266*/count=273; tryItOut("/*oLoop*/for (cmbsxh = 0; cmbsxh < 20; ++cmbsxh) { e1.has(null); } ");
/*fuzzSeed-221406266*/count=274; tryItOut("\"use strict\"; g1.h1.hasOwn = (function(j) { f2(j); });");
/*fuzzSeed-221406266*/count=275; tryItOut("\"use strict\"; m2.set(f2, t0);/*infloop*/for(var [] = z = arguments; w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: function() { return true; }, get: Object.preventExtensions, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: Object.prototype.__defineSetter__, }; })(new RegExp(\"(?!.?)|\\\\u0059|[^]\", \"yi\")), function(q) { return q; }); (makeFinalizeObserver('tenured'))) (/.(?:\\d{1,}[\\s\\w]{3,4})+?/gyim);");
/*fuzzSeed-221406266*/count=276; tryItOut("t1 + a0;");
/*fuzzSeed-221406266*/count=277; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x100000001, 0x100000000, 2**53, -0x07fffffff, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), 0.000000000000001, 0/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0x080000000, -0, 2**53+2, -0x080000000, -0x100000000, 0, 0x080000001, -Number.MIN_VALUE, Math.PI, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, -0x100000001, 1, 42, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), -(2**53), -1/0]); ");
/*fuzzSeed-221406266*/count=278; tryItOut("Object.freeze(p2);");
/*fuzzSeed-221406266*/count=279; tryItOut("\"use strict\"; c = x;{s0 = ''; }");
/*fuzzSeed-221406266*/count=280; tryItOut("\"use strict\"; for(var x = x in x) {h1.getOwnPropertyDescriptor = f2;/*tLoop*/for (let d of /*MARR*/[x, (void 0), x, x, new Number(1.5), x, (void 0), x, new Number(1.5), x, (void 0), (void 0), x, x, x, x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5)]) { Array.prototype.reverse.apply(a0, [i2, g1, b0, o0.i2]); } }");
/*fuzzSeed-221406266*/count=281; tryItOut("f0(p0);\no1 = o1.__proto__;\n");
/*fuzzSeed-221406266*/count=282; tryItOut("mathy4 = (function(x, y) { return Math.log1p(Math.atan2((((Math.pow(--e, ( ~ (x >>> 0))) >>> 0) <= ((mathy3(( + Math.min(( + y), ( + 0x100000000))), (Math.min(( + (x | 0)), x) | 0)) | 0) >>> 0)) >>> 0), Math.log2(( + Math.atan2(( + Math.hypot(Math.fround(Math.clz32(( + mathy1((y | 0), (Math.PI | 0))))), 0x080000000)), ( + (((y >>> 0) ? (2**53+2 >>> 0) : (((-0x07fffffff !== (Math.cbrt((-0x100000001 >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy4, [0/0, 0x100000000, -0x0ffffffff, -0x100000000, 0x080000000, -(2**53+2), Number.MAX_VALUE, 2**53, -1/0, -Number.MAX_VALUE, 1/0, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -0, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 2**53+2, 1, -0x07fffffff, -(2**53-2), 0, 0.000000000000001, 0x07fffffff, 2**53-2, 0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-221406266*/count=283; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul((Math.log10((Math.asin(( - y)) | 0)) | 0), ( + ( + ( ~ (( ~ (Math.acosh((( + Math.asinh((y | 0))) | 0)) >>> 0)) | 0))))); }); testMathyFunction(mathy2, [-(2**53-2), 42, Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0, 0.000000000000001, 0x100000001, 0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 0/0, 1.7976931348623157e308, -0, -0x080000000, -0x07fffffff, -(2**53), 1/0, 1, -(2**53+2), 0x0ffffffff, 2**53-2, -Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, Math.PI]); ");
/*fuzzSeed-221406266*/count=284; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1/; var s = \"0\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=285; tryItOut("o0.i1 + t2;\nprint(z);\n");
/*fuzzSeed-221406266*/count=286; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3{3,4}|[\\\\cA-d\\\\S]*?\", \"yi\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=287; tryItOut("mathy5 = (function(x, y) { return ((Math.pow(y, x) << Math.imul(Math.fround(y), (x || y))) > (Math.atan2(((Math.imul(((Math.fround(x) < (mathy2(Number.MIN_VALUE, (0.000000000000001 | 0)) | 0)) >>> 0), (( + mathy2(Math.imul(-0, x), ( + y))) >>> 0)) >>> 0) | 0), Math.fround((-0x100000001 >>> (x | 0)))) / Math.max(Math.log1p(( + (( + Number.MIN_SAFE_INTEGER) - ((-0x080000000 / y) >>> 0)))), ( + Math.sqrt(( + Math.fround(mathy1(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround(x))))))))); }); ");
/*fuzzSeed-221406266*/count=288; tryItOut("o2.g1.a0.splice(-1, 15);");
/*fuzzSeed-221406266*/count=289; tryItOut("\"use strict\"; var NaN = true, patgsc, c, fnwnia, kevhci, fochhc, kmlnqm, w, covfrp, hanqav;o2.g0.offThreadCompileScript(\"for (var p in b2) { try { e2.toString = f2; } catch(e0) { } try { b2 = t2.buffer; } catch(e1) { } v0 = evalcx(\\\"s2 = new String(o2.p1);\\\", g0); }\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 10 != 6), noScriptRval: (x % 20 != 8), sourceIsLazy: (x % 31 == 14), catchTermination: \"\\uE964\", elementAttributeName: s2 }));");
/*fuzzSeed-221406266*/count=290; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.clz32(( + ((Math.imul(y, 2**53+2) / Math.max(Math.acosh(((Math.imul(Math.hypot(( + x), x), y) >>> 0) >>> 0)), x)) || Math.fround((Math.fround(Math.fround((Math.fround(x) > Math.fround(( + ((0x0ffffffff >>> 0) == (1.7976931348623157e308 >>> 0))))))) > ( ~ ( ~ (( + Math.trunc(Math.fround(x))) ? x : (( ! (y >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy2, [1/0, 1, -0x080000000, -0x0ffffffff, 0x080000001, 0x100000001, -0x080000001, Number.MIN_VALUE, 0, -0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, Math.PI, -(2**53-2), Number.MAX_VALUE, 0x080000000, 42, 2**53-2, 2**53+2, -Number.MAX_VALUE, 2**53, 1.7976931348623157e308, -(2**53), -0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, 0.000000000000001, -1/0, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=291; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.max(((Math.min(( + Math.sqrt(x)), ( + ( + mathy0(Math.max(x, y), (( + ( + ((0x07fffffff >>> 0) + 0/0))) | ( + (( ~ y) >>> 0))))))) <= Math.hypot((( ~ ((y + y) | 0)) | 0), x)) | 0), (( + (( + (((((( + Math.hypot(( + x), ( + ( + ( - ((Math.cbrt((0x07fffffff | 0)) | 0) | 0)))))) >>> 0) ? (y >>> 0) : ((Math.imul(((( ! -(2**53-2)) | 0) | 0), (Math.fround((Math.fround((y % -0x080000000)) * Math.fround(y))) | 0)) | 0) >>> 0)) >>> 0) ? (Math.imul(( + y), (( + y) % Math.log10(( + -0)))) >>> 0) : ((-Number.MIN_SAFE_INTEGER >= ( + (Math.log10(y) | 0))) >>> 0)) >>> 0)) ? ( + (Math.imul(y, y) && mathy0(y, mathy0((x | 0), (Math.fround(Math.atan2((Math.asinh(x) >>> 0), ( ! Math.fround(y)))) | 0))))) : Math.fround(Math.sign(y)))) | 0)) | 0); }); testMathyFunction(mathy1, [-0x0ffffffff, -0x080000001, 0x100000001, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 42, -Number.MIN_VALUE, 0, -(2**53-2), -0x07fffffff, -(2**53+2), 2**53+2, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, Math.PI, 0/0, 0x080000000, 0x0ffffffff, Number.MAX_VALUE, 0x100000000, 1/0, -(2**53), -0x100000001, -0x100000000, -1/0, 1, Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-221406266*/count=292; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-221406266*/count=293; tryItOut("M:if(x) { if (window) {e0.delete(t0);print(window); } else { }}");
/*fuzzSeed-221406266*/count=294; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 295147905179352830000.0;\n    var i3 = 0;\n    var i4 = 0;\n    {\n      {\n        {\n          i3 = ((((i3))|0));\n        }\n      }\n    }\n    {\n      d1 = (-36028797018963970.0);\n    }\n    (Int8ArrayView[((i3)) >> 0]) = ((((((0xb35c38cf) / (0xd953ba55))>>>(((0x7d17337e) > (0x2f3b0152))-(/(?:(?=(\\2)))/yi))) != (0x4fa63c11)) ? (0x3ddc4db6) : ((~((x || x)-((-0x245f48) ? (0xf9b30e23) : (-0x2b19a95)))) == (-0x8000000)))-((((0xfab80745)-((((0x4fe1e2c3)) >> ((0x71ae74b2)+(0x509759ab)+(0x8ea89e6f))))) >> ((Uint32ArrayView[((4277)) >> 2])))));\n    d0 = (-1025.0);\n    return +((1.5));\n  }\n  return f; })(this, {ff: Float64Array}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[x, new String('q'), x, (void 0), new String('q'), x, (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new String('q'), new String('q'), (void 0), x, (0/0), x, x, x, new String('q'), (0/0), (void 0), x, new String('q'), (0/0), (void 0), (void 0), (0/0), new String('q'), (0/0), new String('q'), x, x, new String('q'), new String('q'), x, new String('q'), new String('q'), x, (void 0), (void 0), x, (void 0), new String('q'), x, (void 0), (void 0), x, x, new String('q'), (void 0), x, x, x, new String('q'), x, (0/0), (0/0), (0/0), (0/0), x, (void 0), (void 0), x, (0/0), new String('q'), (void 0), (0/0), (0/0), new String('q'), (0/0), (void 0), (0/0), (void 0), x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, new String('q'), (void 0), (0/0), x, (void 0), x, new String('q'), new String('q'), (void 0)]); ");
/*fuzzSeed-221406266*/count=295; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=296; tryItOut("mathy4 = (function(x, y) { return Math.hypot(Math.min(Math.asin(((( ! y) === Math.max(((( + Math.fround((( + x) > (y >>> 0)))) << ( + y)) >>> 0), y)) >>> 0)), (( + 0x080000001) == ( + (( + Math.fround((Math.fround(Math.min(42, (x >>> 0))) === y))) >>> Math.fround((((( + Math.cbrt(( + y))) | 0) && 1.7976931348623157e308) | 0)))))), Math.fround(mathy2((Math.max(Math.tanh(y), ( + ( + ( ~ ( + Math.pow(x, y)))))) >>> 0), (( ~ (Math.fround(Math.pow((mathy0((-(2**53-2) | 0), Math.fround(1/0)) | 0), (Math.cbrt((x | 0)) | 0))) ? Math.fround(( + Math.sinh(( + y)))) : Math.fround(Math.hypot(x, 2**53-2)))) | 0)))); }); testMathyFunction(mathy4, [0/0, -Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, -(2**53-2), -0x100000001, -0x0ffffffff, 0x100000000, -Number.MIN_VALUE, 1, -0x100000000, -(2**53), -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, 2**53, 0.000000000000001, 0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0, Math.PI, -(2**53+2), -0, Number.MAX_SAFE_INTEGER, 42, -0x080000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53-2, 1/0, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000001, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=297; tryItOut("if((x % 6 == 3)) { if (x +  /x/ ) { void 0; bailAfter(8640); } break ; else {this.v2 = Object.prototype.isPrototypeOf.call(p1, s1); }}");
/*fuzzSeed-221406266*/count=298; tryItOut("mathy2 = (function(x, y) { return Math.atanh(( + (( + (mathy1((Math.sin((( ~ ( + (( + y) ^ ( + -Number.MIN_VALUE)))) | 0)) | 0), Math.fround(y)) | 0)) < ( + Math.trunc(x))))); }); testMathyFunction(mathy2, [2**53, 1.7976931348623157e308, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), 2**53-2, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, -1/0, -(2**53-2), -0x0ffffffff, 0x080000001, Math.PI, Number.MAX_VALUE, -0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -0x080000000, 1/0, -0x100000001, 0, 42, -Number.MAX_VALUE, 0x080000000, -(2**53)]); ");
/*fuzzSeed-221406266*/count=299; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -576460752303423500.0;\n    var d4 = 1.03125;\n    return (((i1)*-0xfffff))|0;\n  }\n  return f; })(this, {ff: Math.atanh}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, ['', -0, null, [0], 0.1, '/0/', objectEmulatingUndefined(), (function(){return 0;}), ({toString:function(){return '0';}}), 0, 1, (new Number(-0)), false, undefined, true, (new Boolean(true)), (new String('')), '0', ({valueOf:function(){return '0';}}), (new Boolean(false)), /0/, (new Number(0)), [], '\\0', ({valueOf:function(){return 0;}}), NaN]); ");
/*fuzzSeed-221406266*/count=300; tryItOut("/*oLoop*/for (roscvy = 0; roscvy < 0; ++roscvy) { g1.h0.keys = f2; } ");
/*fuzzSeed-221406266*/count=301; tryItOut("for (var v of f0) { try { t0[2] = b1; } catch(e0) { } try { g2.r2 = new RegExp(\"[^]\", \"yim\"); } catch(e1) { } /*ODP-3*/Object.defineProperty(m0, \"19\", { configurable: (x % 45 == 36), enumerable: true, writable: true, value: Math.min( /x/g , 0) }); }");
/*fuzzSeed-221406266*/count=302; tryItOut("/*infloop*/ for (var arguments.callee.arguments of x) this.m1 = new WeakMap;/* no regression tests found */");
/*fuzzSeed-221406266*/count=303; tryItOut("mathy2 = (function(x, y) { return (( ! (Math.max(Math.fround(Math.fround((Math.fround(( - Math.fround(( + (( + y) << ( + ( ! Math.imul(x, y)))))))) >>> 0))), ( + 0x0ffffffff)) | 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, 2**53+2, Number.MIN_VALUE, 1/0, 0x0ffffffff, -1/0, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, -0x07fffffff, -0x0ffffffff, Math.PI, Number.MAX_VALUE, 0x100000000, -(2**53-2), -0, 0x100000001, -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), 42, 1, 2**53, 0x07fffffff, 0, 0x080000000]); ");
/*fuzzSeed-221406266*/count=304; tryItOut("a1.forEach();function e() { return window !== undefined } g0.m1.delete(g1);");
/*fuzzSeed-221406266*/count=305; tryItOut("\"use strict\"; /*bLoop*/for (let uaoqzk = 0; uaoqzk < 11 && ((Object.defineProperty(a, \"x\", ({enumerable:  /x/ })))); ++uaoqzk) { if (uaoqzk % 4 == 1) { Array.prototype.push.apply(a2, [this.m0, i0, s2, a0, h2]); } else { print(x); }  } ");
/*fuzzSeed-221406266*/count=306; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=307; tryItOut("g1.h2.keys = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float64ArrayView[(((imul((!(-0x8000000)), (0xffdb7acb))|0) != (((0xa7cd082e)+(0xf937cd61)) ^ (((0x4cc32e69)))))+((Float64ArrayView[1]))) >> 3]) = ((((((+((x)>>>((0xffffffff)-(0x9179c601)-((0xffffffff)))))) - ((+(1.0/0.0))))) % ((+(1.0/0.0)))));\n    return +((NaN));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ \"use strict\"; var uesoma = (4277); var cyprhz = Function; return cyprhz;})()}, new ArrayBuffer(4096));");
/*fuzzSeed-221406266*/count=308; tryItOut("b1 + o1;");
/*fuzzSeed-221406266*/count=309; tryItOut("\"use strict\"; f0 = g0.objectEmulatingUndefined();");
/*fuzzSeed-221406266*/count=310; tryItOut("mathy1 = (function(x, y) { return Math.min(( + Math.abs(( + (( + (( + Math.sign(( + -(2**53)))) >= ( + x))) >> Math.clz32((Math.imul((Math.hypot(0/0, (Number.MIN_VALUE ? x : 42)) | 0), (42 | 0)) | 0)))))), (Math.fround((Math.fround(Math.hypot(( + Math.max(( + y), ( + ( + Math.round(( + x)))))), Math.fround(((Math.exp((-0x07fffffff | 0)) | 0) % y)))) >> Math.fround(( - (mathy0((y | 0), (Math.fround(( ~ -0)) | 0)) | 0))))) >>> 0)); }); ");
/*fuzzSeed-221406266*/count=311; tryItOut("mathy5 = (function(x, y) { return Math.cos(Math.sign(Math.fround(( + ((Math.acos(( + (y && x))) % Math.fround(y)) === (( + y) ? Math.min(-0x100000001, x) : (Math.log10((x || x)) | 0))))))); }); ");
/*fuzzSeed-221406266*/count=312; tryItOut("if((\n/*FARR*/[x, Math.max([[1]], 12), , .../*MARR*/[[], [], [], ({}), [], ({}), (1/0), (1/0), [], (-1/0), [], (1/0), (-1/0), ({}),  '' ,  '' , ({}), ({}), (-1/0),  '' , [], (1/0), ({}), (1/0), (-1/0), (1/0), (1/0), (-1/0), ({}),  '' ]])) { if (x) v1 = a1.every((function mcc_() { var pvauzd = 0; return function() { ++pvauzd; if (/*ICCD*/pvauzd % 6 == 3) { dumpln('hit!'); try { m0.has(g1.e0); } catch(e0) { } try { b2 = t1.buffer; } catch(e1) { } h0.getOwnPropertyNames = f1; } else { dumpln('miss!'); try { m1.delete(f2); } catch(e0) { } try { o0 + a0; } catch(e1) { } try { print(s1); } catch(e2) { } for (var v of g1) { try { for (var p in g2.s0) { try { e0.delete(a1); } catch(e0) { } try { /*ODP-3*/Object.defineProperty(this.p1, \"toSource\", { configurable: (x % 24 != 10), enumerable: /[^]/gim, writable: (x % 19 == 4), value: g0 }); } catch(e1) { } try { this.s0 += 'x'; } catch(e2) { } this.t1[3]; } } catch(e0) { } for (var p in p0) { function g2.f2(g1)  { yield this }  } } } };})());y = x;} else {return 14;function w() { \"use strict\"; return  /x/  } v1 = Object.prototype.isPrototypeOf.call(o1, a1); }");
/*fuzzSeed-221406266*/count=313; tryItOut("f1 = (function() { for (var j=0;j<11;++j) { f0(j%3==1); } });");
/*fuzzSeed-221406266*/count=314; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ! Math.pow(Math.fround((Math.fround((y ** ( + Math.fround(( + (y >>> 0)))))) >= Math.fround(Math.ceil(( + y))))), Math.max((Math.fround(Math.asinh(Math.fround(x))) | 0), Math.fround(Math.fround(((2**53-2 | 0) === Math.fround(( ~ ( + x))))))))); }); testMathyFunction(mathy1, [-0x080000001, -0x07fffffff, 2**53, 0x100000000, -0x080000000, -Number.MIN_VALUE, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0x080000000, Math.PI, 2**53-2, -0x100000000, -(2**53), 0/0, Number.MIN_VALUE, 1, -0x0ffffffff, -(2**53-2), -0, 0x07fffffff, -Number.MAX_VALUE, 1/0, 0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-221406266*/count=315; tryItOut("/*ODP-1*/Object.defineProperty(t2, \"caller\", ({value: (new  \"\" ()), enumerable: (x % 5 == 3)}));");
/*fuzzSeed-221406266*/count=316; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\D\", \"gim\"); var s = \"a\"; print(s.replace(r, '\\u0341', \"gy\")); ");
/*fuzzSeed-221406266*/count=317; tryItOut("M:with({b: let (y = x) b || NaN}){((timeout(1800)));/*RXUB*/var r = g1.r0; var s = \" 1\"; print(uneval(r.exec(s)));  }");
/*fuzzSeed-221406266*/count=318; tryItOut("/*oLoop*/for (var oevuil = 0; oevuil < 38 && (/*vLoop*/for (var ttbbvb = 0; ttbbvb < 108; ++ttbbvb) { var b = ttbbvb; (undefined.throw(this)); } ) && (eval(\"/* no regression tests found */\")); ++oevuil) { v2 = r0.compile; } ");
/*fuzzSeed-221406266*/count=319; tryItOut("var gecojq = new ArrayBuffer(2); var gecojq_0 = new Float64Array(gecojq); gecojq_0[0] = -18; var gecojq_1 = new Int16Array(gecojq); print(gecojq_1[0]); gecojq_1[0] = -19; var gecojq_2 = new Float32Array(gecojq); print(gecojq_2[0]); gecojq_2[0] = -9; var gecojq_3 = new Float64Array(gecojq); gecojq_3[0] = 6; v1 = b1.byteLength;print(/*UUV1*/(gecojq_1[0].setUTCMonth = (let (e=eval) e)));");
/*fuzzSeed-221406266*/count=320; tryItOut("mathy5 = (function(x, y) { return (Math.fround(( ! Math.fround(Math.exp(-Number.MIN_VALUE)))) - (( - (Math.max(Math.fround(( + Math.PI)), Math.fround(( ~ Math.fround(mathy0((Number.MAX_VALUE ? (y | 0) : x), Math.pow(x, x)))))) | 0)) >>> 0)); }); testMathyFunction(mathy5, [-1/0, -Number.MIN_VALUE, 1/0, -0x100000001, 2**53, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 1.7976931348623157e308, -0x07fffffff, -0x100000000, 0x100000000, 42, 0x0ffffffff, 0.000000000000001, 2**53-2, 1, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), -0x080000001, -(2**53), -0, 0x080000000, 0/0, 0x07fffffff, 0]); ");
/*fuzzSeed-221406266*/count=321; tryItOut("a.message;");
/*fuzzSeed-221406266*/count=322; tryItOut("\"use strict\";  for  each(e in new Boolean().unwatch(\"valueOf\")) {g0.toSource = (function() { for (var j=0;j<54;++j) { o1.f2(j%3==0); } });(({ set d \u3056 ()\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = (i2);\n    return +((1.03125));\n  }\n  return f; })); }");
/*fuzzSeed-221406266*/count=323; tryItOut("v1 = t0.byteOffset;");
/*fuzzSeed-221406266*/count=324; tryItOut("\"use strict\"; var sfneyv = new SharedArrayBuffer(4); var sfneyv_0 = new Float64Array(sfneyv); sfneyv_0[0] = 22; var sfneyv_1 = new Float64Array(sfneyv); sfneyv_1[0] = -22; var sfneyv_2 = new Uint8Array(sfneyv); const nrbzyq, tdqxhc, window;this.m2.get(v1);e0 = new Set;m1.delete(o1);print(sfneyv_0[0]);");
/*fuzzSeed-221406266*/count=325; tryItOut("h2 + '';function x() { \"use strict\"; \"use asm\"; yield this.__defineGetter__(\"x\", mathy1) } e2 = new Set(this.p1);");
/*fuzzSeed-221406266*/count=326; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return Math.trunc((Math.fround((Math.fround((Math.round(x) + (y === (y ** (y | 0))))) >> Math.fround(( ~ ( ! (y ? y : Math.fround(-0x080000000))))))) >>> 0)); }); ");
/*fuzzSeed-221406266*/count=327; tryItOut("\"use strict\"; o2.v1 = (t1 instanceof o0);");
/*fuzzSeed-221406266*/count=328; tryItOut("v0 = (g1 instanceof this.h0);");
/*fuzzSeed-221406266*/count=329; tryItOut("g1.offThreadCompileScript(\"v1 = t2.length;\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x !== (y = x = {}), noScriptRval: false, sourceIsLazy: true, catchTermination: (((makeFinalizeObserver('tenured'))) >>>= (Object.defineProperty(w, \"x\", ({writable: true, configurable: true, enumerable: false})))) }));");
/*fuzzSeed-221406266*/count=330; tryItOut("/*tLoop*/for (let x of /*MARR*/[(-1/0),  'A' , \"\\uD862\",  'A' , \"\\uD862\",  'A' , \"\\uD862\", (-1/0),  'A' , \"\\uD862\", (-1/0), new Boolean(true), arguments.callee, (-1/0), \"\\uD862\", arguments.callee, new Boolean(true), new Boolean(true), new Boolean(true)]) {  /x/ ; }\nx = \u3056;(\"\\u673E\");\n");
/*fuzzSeed-221406266*/count=331; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(Math.fround((Math.atanh(Math.abs((mathy1(( + Math.atan2(y, x)), (-0x080000000 | 0)) ^ x))) <= Math.imul(y, Math.exp(Math.expm1(y))))), Math.trunc((Math.log(Math.max(Math.hypot(((x || y) > (y | 0)), (Math.sqrt((y >= y)) | 0)), (( - (Math.PI >>> 0)) >>> 0))) >>> 0)))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 2**53-2, -0x080000000, -(2**53), Number.MAX_VALUE, 1/0, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, -0x100000001, -0x080000001, 0x080000000, Number.MIN_VALUE, 2**53+2, 0/0, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, -(2**53+2), 1.7976931348623157e308, 0x080000001, -0x07fffffff, 0x07fffffff, 0x100000000, -0, -1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, 0.000000000000001, -0x100000000, -0x0ffffffff, 0x100000001, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=332; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.ceil(( - (Math.fround(y) + ( + (y >>> 0))))); }); testMathyFunction(mathy0, [2**53+2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, 42, -0x0ffffffff, -0x100000001, Number.MIN_VALUE, Math.PI, 0x0ffffffff, 0x100000001, 2**53, -0x080000000, -0, 0/0, 1/0, 2**53-2, 0x080000001, -0x07fffffff, 1, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, -(2**53+2), -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, 0]); ");
/*fuzzSeed-221406266*/count=333; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-221406266*/count=334; tryItOut("\"use strict\"; m2.has(m2);");
/*fuzzSeed-221406266*/count=335; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\D\", \"y\"); var s = \"a\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=336; tryItOut("e1.has(this.h0);");
/*fuzzSeed-221406266*/count=337; tryItOut("/*RXUB*/var r = r1; var s = g1.s1; print(s.split(r)); ");
/*fuzzSeed-221406266*/count=338; tryItOut("/*infloop*/L:for(x; let (y = ((p={}, (p.z = \"\\uE1C6\")()))) timeout(1800); x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: OSRExit, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { return []; }, keys: function() { return Object.keys(x); }, }; })( /x/ ),  \"\" )) {v2 = a1.length;p0 + a0; }");
/*fuzzSeed-221406266*/count=339; tryItOut("\"use strict\"; e1.has(o2);");
/*fuzzSeed-221406266*/count=340; tryItOut("mathy3 = (function(x, y) { return Math.imul(Math.atan(mathy2(mathy2(y, ( + y)), x)), Math.atan2(( + ((x <= (((( ~ Math.atan(Math.fround(y))) | 0) , Math.log1p((x >>> 0))) | 0)) == (Math.fround((Math.max(((x ? y : y) >>> 0), y) <= y)) >>> 0))), (Math.hypot(y, (Math.fround((Math.ceil(-1/0) | 0)) % Math.fround(Math.clz32(Math.fround(x))))) | 0))); }); testMathyFunction(mathy3, [-1/0, 0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, 0/0, -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 0x100000001, 1, -0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, 0x0ffffffff, -0x100000000, -(2**53-2), -(2**53+2), 2**53, 0.000000000000001, -0x07fffffff, -0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, 42, -0x080000001, 2**53+2, 1/0, -Number.MAX_VALUE, 0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=341; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.acosh(( + (Math.log10(( - (((x | 0) ? (x | 0) : (-0x100000000 | 0)) | 0))) >>> 0)))); }); testMathyFunction(mathy4, [(function(){return 0;}), true, 1, '\\0', (new Boolean(false)), [], (new Number(-0)), (new Number(0)), (new Boolean(true)), -0, undefined, 0.1, false, (new String('')), 0, ({valueOf:function(){return '0';}}), '0', /0/, '', ({toString:function(){return '0';}}), objectEmulatingUndefined(), NaN, '/0/', ({valueOf:function(){return 0;}}), [0], null]); ");
/*fuzzSeed-221406266*/count=342; tryItOut("\"use strict\"; print(x);function e(eval)Math.imul(-14, x)v2 = false;");
/*fuzzSeed-221406266*/count=343; tryItOut("\"use strict\"; /*infloop*/while((4277));");
/*fuzzSeed-221406266*/count=344; tryItOut("b2 = t1.buffer;");
/*fuzzSeed-221406266*/count=345; tryItOut("false\n");
/*fuzzSeed-221406266*/count=346; tryItOut("mathy5 = (function(x, y) { return ((( ~ Math.fround(( ! (Math.hypot(((x ^ x) >>> 0), x) | 0)))) | 0) && Math.sinh(( + ( ~ Math.sin((((y | 0) / (Math.fround(Math.hypot(Math.fround(y), x)) | 0)) | 0)))))); }); ");
/*fuzzSeed-221406266*/count=347; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0.000000000000001, 1.7976931348623157e308, -0x100000001, -(2**53-2), -0, 42, -0x080000000, -0x080000001, 0x080000001, 2**53, -Number.MAX_VALUE, -(2**53+2), 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0, 2**53-2, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, 2**53+2, 1, 0x0ffffffff, 1/0, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 0x100000001]); ");
/*fuzzSeed-221406266*/count=348; tryItOut("if(true) {e0 = new Set; }");
/*fuzzSeed-221406266*/count=349; tryItOut("a1.unshift(e2, g0, f1, g1);");
/*fuzzSeed-221406266*/count=350; tryItOut("/*iii*/print(\"\\uB52C\");/*hhh*/function hsvxfk(NaN, e, ...x){print(true);}");
/*fuzzSeed-221406266*/count=351; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.pow(( + mathy3(( + Math.atan2(Math.fround(Math.fround(Math.sin((Math.fround(Math.fround(0x0ffffffff)) / x)))), ((Math.min(Math.fround(Math.fround(( + (x | 0)))), Math.fround(y)) ? y : Math.fround(( ~ Math.fround(Math.fround((Math.fround((( ! Math.fround(1)) | 0)) - Math.fround(( - x)))))))) >>> 0))), ( + Math.fround((( + (( + y) < ( + ( ~ (-Number.MIN_SAFE_INTEGER ? -Number.MIN_SAFE_INTEGER : -(2**53-2)))))) >> Math.fround(x)))))), Math.fround(Math.sin((mathy1(((Math.sinh(y) | 0) % ( + Math.atan2(( + ((((y >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0) >> (y >>> 0))), ( + x)))), ( + x)) | 0))))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -(2**53-2), -0, 0.000000000000001, 0x100000000, 1.7976931348623157e308, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, 0, -0x100000000, -Number.MAX_VALUE, -0x0ffffffff, 2**53-2, Number.MAX_VALUE, 0x07fffffff, -(2**53), 0x100000001, -0x080000000, -0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 42, 1, 1/0, -1/0, -0x100000001, 0x080000001, 0x0ffffffff, -(2**53+2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=352; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.min(( + Math.log10(( + Math.tanh((( + (x >>> 0)) | 0))))), Math.fround((( ~ y) + (x / Math.pow((( + Math.log2(( + Math.imul(Math.fround(x), Math.fround(x))))) >>> 0), y))))); }); ");
/*fuzzSeed-221406266*/count=353; tryItOut("h1.getOwnPropertyNames = f2;");
/*fuzzSeed-221406266*/count=354; tryItOut("\"use strict\"; o2.t2[v0];");
/*fuzzSeed-221406266*/count=355; tryItOut("\"use strict\"; for (var p in i2) { try { /*MXX1*/o0 = g0.Object.getOwnPropertyNames; } catch(e0) { } for (var p in p2) { try { /*MXX3*/o2.g1.Set.prototype.delete = g0.Set.prototype.delete; } catch(e0) { } try { a0.sort(f0, b0); } catch(e1) { } try { const v2 = evaluate(\"a2.toString = (1 for (x in []));\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: true })); } catch(e2) { } Array.prototype.forEach.apply(a0, []); } }");
/*fuzzSeed-221406266*/count=356; tryItOut("e1 = new Set;");
/*fuzzSeed-221406266*/count=357; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ! ( + Math.fround(Math.clz32(Math.fround(( + ( + Math.fround({ void 0; void gc(this, 'shrinking'); })))))))); }); testMathyFunction(mathy0, [-0x07fffffff, -1/0, 0x080000000, 0x07fffffff, 1.7976931348623157e308, -0, 2**53+2, 0x080000001, 2**53, 1/0, 0, -Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 0x0ffffffff, -0x0ffffffff, 42, -(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -Number.MIN_VALUE, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, -0x100000000]); ");
/*fuzzSeed-221406266*/count=358; tryItOut("e2.has(e2);");
/*fuzzSeed-221406266*/count=359; tryItOut("\"use strict\"; a2 = arguments;");
/*fuzzSeed-221406266*/count=360; tryItOut("selectforgc(o2);");
/*fuzzSeed-221406266*/count=361; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.atanh((Math.sqrt(( + ( ~ ( + x)))) | 0)) | (( ! ( + ( + Math.cosh((Math.imul(((y - x) >>> 0), (y >>> 0)) >>> 0))))) || ((( ! (x | 0)) >> Math.fround(((y | 0) ? Math.fround(x) : Math.fround(-0x07fffffff)))) | 0))); }); testMathyFunction(mathy3, [2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000001, Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), 0x100000000, 1.7976931348623157e308, 0x080000000, 0x080000001, -0x080000001, -Number.MIN_VALUE, 0x0ffffffff, 1, 2**53-2, -0x07fffffff, Number.MAX_VALUE, 0, 0x100000001, -1/0, 1/0, 0.000000000000001, Math.PI, -0x100000000, -(2**53), 0/0, -0x080000000, -(2**53-2), 2**53, -0]); ");
/*fuzzSeed-221406266*/count=362; tryItOut("a2.forEach(f1);");
/*fuzzSeed-221406266*/count=363; tryItOut("\"use strict\"; Array.prototype.push.call(a1, this.__defineGetter__(\"b\", Uint32Array), i0);");
/*fuzzSeed-221406266*/count=364; tryItOut("\"use strict\"; /*hhh*/function mjytug(x, \"-3\", z, z, y, a, y, b, of = [1], x, e, y = \"\\u8C74\", e, x = \"\\u1F97\", x, x, eval, e, x, x, \u3056, x, x, NaN, x, y, z, d, x, x, eval, d, x, a, y, NaN, d, x, x, c, x, \u3056, x, x, z, x, e = 1, e =  '' , w, \u3056 = this, d, x, b, x, a, this, \u3056, x, x, x, NaN = \"\\u717F\", x = x, e, y, x = window, x, e =  \"\" , x, y, e, x, d = /^/gyi, this.x, x, x = \"\\u4D7F\", \u3056 =  \"\" , d, x, x, NaN = this, x, x, y, x, z, \u3056){this.a2.reverse();}mjytug((4277), (yield Math.atan2(24, window)));");
/*fuzzSeed-221406266*/count=365; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.cosh(((Math.fround(( ! Math.fround(( + Math.imul(( + (mathy2(((((2**53-2 | 0) % (Number.MIN_VALUE | 0)) | 0) | 0), (x | 0)) | 0)), ( + Math.asinh(y))))))) !== ( + Math.pow(( + Math.atan2(( + (( + x) >> ( + -1/0))), ( + Math.pow((0x080000000 | 0), (Math.max(y, x) | 0))))), ( + Math.cosh(Math.hypot(0x100000001, 0x080000000)))))) | 0)); }); testMathyFunction(mathy5, [2**53, 0/0, 0.000000000000001, -(2**53+2), -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, 0, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x07fffffff, 0x0ffffffff, 0x080000000, 2**53+2, 42, -0x080000001, Math.PI, 1.7976931348623157e308, 2**53-2, -0x100000001, -(2**53), 1/0, -0, -(2**53-2), Number.MAX_VALUE, 0x100000000, 0x080000001, Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=366; tryItOut("s1.__proto__ = m0;");
/*fuzzSeed-221406266*/count=367; tryItOut("mathy5 = (function(x, y) { return (Math.cosh((mathy2(( + (( + (( + (( ! (x >>> 0)) >>> 0)) ? ( + ( ~ ( + ( ~ (x >>> 0))))) : ((( ! ((((Number.MIN_SAFE_INTEGER >>> 0) != x) >>> 0) | 0)) | 0) >>> 0))) >= ((((( ! Math.fround(Math.atan2(-(2**53-2), Math.fround(y)))) >>> 0) >>> 0) >> Math.imul(y, y)) >>> 0))), (Math.acosh(Math.fround(y)) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-221406266*/count=368; tryItOut("neuter(b0, \"change-data\");v2 = new Number(a2);");
/*fuzzSeed-221406266*/count=369; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return ( ~ ((Math.fround(Math.log1p(Math.fround(Math.fround(Math.pow(Math.fround(2**53+2), Math.fround(y)))))) | 0) == Math.log1p(( + (Math.fround(-0x07fffffff) / y))))); }); testMathyFunction(mathy3, [-(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, 42, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, Number.MAX_VALUE, 0x100000001, 0/0, Number.MIN_SAFE_INTEGER, 0, -0x100000001, -0x0ffffffff, 0x0ffffffff, -0x100000000, 0x080000001, -1/0, 0x07fffffff, -(2**53), -(2**53+2), 0.000000000000001, 0x080000000, 2**53-2, -0, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, 1, 2**53+2, -0x080000000]); ");
/*fuzzSeed-221406266*/count=370; tryItOut("a2 = r1.exec(s2);");
/*fuzzSeed-221406266*/count=371; tryItOut("\"use strict\"; ");
/*fuzzSeed-221406266*/count=372; tryItOut("\"use strict\"; if(/(?![^](?=(?:[^]\u5fc3-))+?)/m) {s2 + ''; } else {for([x, z] = \"\\u81FF\" in new RegExp(\"\\\\3\", \"gyim\")) {v2.toSource = f1;print( \"\" ); } }");
/*fuzzSeed-221406266*/count=373; tryItOut("\"use strict\"; v2 = (v2 instanceof v0);");
/*fuzzSeed-221406266*/count=374; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    (Int16ArrayView[2]) = ((i2)+(i0));\n    switch (((((0xffffffff) ? (0x66a59577) : (0xf8a3d94d))-((0xaaa36521) < (0xffffffff))) << ((0xff409df6)-(-0x1598f56)+(0x98dc31cd)))) {\n      case -1:\n        (Float64ArrayView[((-0x8000000)*-0xa339b) >> 3]) = ((-9.671406556917033e+24));\n        break;\n      case 1:\n        d1 = (+(1.0/0.0));\n        break;\n      default:\n        i3 = (i3);\n    }\n    i3 = ((((0xdada1239)-(0x10745ed2)) ^ ((0xe4761e1b) / (((0xe723a3ef) % (0xffffffff))>>>((/*FFI*/ff(((536870911.0)))|0)*-0x857df)))) >= (((0x21d9944f) / (0xd6abe346)) ^ (0xfffff*(0x94b01bb4))));\n    i3 = (0xfcf9cff0);\n    i3 = (i3);\n    {\n      i2 = (((((0x9ef4610b))|0)) ? ((((i0))>>>(-0xfffff*(i3))) >= ((((z) = allocationMarker())-(-0x8000000))>>>((0x232dacc9)-(i0)))) : (0x7d20d04a));\n    }\n    i2 = (0xfca35533);\n    i0 = ((0x77ebc15));\n    {\n      (Float64ArrayView[((i3)+(0x6948423f)) >> 3]) = ((4.0));\n    }\n    {\n      d1 = ((i3) ? ((((((0x2a91aae0)))) < ((let (c) (true.watch(\"imul\", decodeURIComponent)))>>>(((~~(-8192.0)) > (((0xffffffff)) << ((0x8681173c)))))))) : ((new /*wrap1*/(function(){ this.h1.keys = f1;return eval})()\u000c((runOffThreadScript)())) ? (+(0.0/0.0)) : (+(0.0/0.0))));\n    }\n    return +((((d1)) % ((x.yoyo(((void version(170))))))));\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [(new String('')), [0], ({valueOf:function(){return 0;}}), false, (new Number(-0)), '', '0', (new Number(0)), true, -0, null, 0.1, '/0/', '\\0', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), 1, objectEmulatingUndefined(), undefined, 0, (new Boolean(true)), /0/, (new Boolean(false)), NaN, (function(){return 0;}), []]); ");
/*fuzzSeed-221406266*/count=375; tryItOut("mathy5 = (function(x, y) { return ( + ( - ( + Math.cos(( ~ ((( ! 1.7976931348623157e308) < ((-(2**53+2) >>> 0) ? ((( ~ (x | 0)) | 0) >>> 0) : ( + Math.ceil(-0x100000001)))) >>> 0)))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, 2**53+2, 2**53-2, -1/0, -0x0ffffffff, -(2**53), 0/0, Number.MIN_VALUE, 0x080000000, 2**53, 0x100000001, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, 0x080000001, -0x080000001, -0, Math.PI, 0.000000000000001, -0x100000001, 1, -0x080000000, 0, Number.MAX_VALUE, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-221406266*/count=376; tryItOut("NaN = b;");
/*fuzzSeed-221406266*/count=377; tryItOut("\"use strict\"; a2.__proto__ = m1;");
/*fuzzSeed-221406266*/count=378; tryItOut("testMathyFunction(mathy5, [(new Number(0)), objectEmulatingUndefined(), 0, ({valueOf:function(){return '0';}}), [0], 0.1, /0/, '', '/0/', null, [], (new Number(-0)), (new Boolean(true)), undefined, (new Boolean(false)), NaN, 1, ({toString:function(){return '0';}}), (new String('')), (function(){return 0;}), true, false, '0', -0, '\\0', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-221406266*/count=379; tryItOut("i0 = a0[v0];");
/*fuzzSeed-221406266*/count=380; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=381; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min(( + Math.max(( + ( + y)), Math.fround(( - (Math.fround((Math.fround(-0x100000001) && Math.fround(x))) , Math.fround(y)))))), (( - (( ~ (( ! y) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [0.1, (function(){return 0;}), -0, /0/, '0', (new String('')), '', (new Boolean(true)), (new Boolean(false)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '\\0', false, 1, ({toString:function(){return '0';}}), (new Number(0)), NaN, true, [], ({valueOf:function(){return 0;}}), null, 0, (new Number(-0)), '/0/', [0], undefined]); ");
/*fuzzSeed-221406266*/count=382; tryItOut("g0.v2 = this.b2.byteLength;");
/*fuzzSeed-221406266*/count=383; tryItOut("\"use strict\"; throw b;this.zzz.zzz;");
/*fuzzSeed-221406266*/count=384; tryItOut("for (var v of i1) { try { b2 + s2; } catch(e0) { } try { i0.send(e1); } catch(e1) { } try { this.a0 = []; } catch(e2) { } for (var p in v1) { t1.toString = (function() { try { m0.get(h0); } catch(e0) { } try { i2.send(i1); } catch(e1) { } try { /*RXUB*/var r = r0; var s = \"\"; print(s.split(r));  } catch(e2) { } o1.a2[x] = b2; throw e2; }); } }");
/*fuzzSeed-221406266*/count=385; tryItOut("v1 = evaluate(\"function f2(p0) \\\"use asm\\\";   function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d0 = (d0);\\n    return (((0xf886f4a0)+(0x519c304d)))|0;\\n  }\\n  return f;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  /x/ , noScriptRval: (x % 6 != 2), sourceIsLazy: false, catchTermination: false }));var d\u0009 = new RegExp(\".\", \"gi\");");
/*fuzzSeed-221406266*/count=386; tryItOut("mathy3 = (function(x, y) { return ( - ((((Math.atan2(( - (x ? Math.fround(mathy1(Math.fround(x), Math.fround(x))) : 0x0ffffffff)), (Math.sinh(Math.atan2(y, x)) >>> 0)) ? Number.MIN_VALUE : Math.sqrt((x | 0))) >>> 0) < Math.imul(Math.min(x, x), x)) >>> 0)); }); ");
/*fuzzSeed-221406266*/count=387; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.imul(Math.fround((Math.atan2((Math.hypot(Math.imul((((mathy3((Math.min(x, x) >>> 0), x) >>> 0) , y) | 0), (( + Math.pow(( + y), ( + 0x100000000))) >>> 0)), ((( + x) ? y : (x | 0)) | 0)) >>> 0), (((Math.min((Math.log(y) >>> 0), ((mathy3(-0x0ffffffff, (y ? Number.MIN_SAFE_INTEGER : y)) | 0) >>> 0)) >>> 0) , y) >>> 0)) >>> 0)), Math.fround(( ! mathy3(Math.fround(( - y)), (( - (( + Math.expm1(x)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy4, [-0x100000000, -Number.MIN_VALUE, 2**53+2, 0x100000000, 0.000000000000001, Number.MIN_VALUE, -(2**53), -0x07fffffff, 1, 2**53-2, -0x100000001, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0x0ffffffff, -0, 0x080000001, -1/0, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, -0x080000001, 0, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 42, 2**53, 0/0, 0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=388; tryItOut("a2.__iterator__ = (function() { try { v0.valueOf = (function mcc_() { var eippjr = 0; return function() { ++eippjr; if (true) { dumpln('hit!'); try { /*MXX2*/g1.Math.ceil = b2; } catch(e0) { } try { m1.delete(s0); } catch(e1) { } r1 = new RegExp(\"(?=(\\\\S|[^]))|\\u47b2(?:\\\\xa3{1}){2}|\\\\v|[^]|\\\\b[^\\\\W\\u00c2-\\u18b4\\\\S\\\\S].|${3,}(?!(?![^\\\\w\\u000b-\\\\\\u00e3]){0})|(^+|$)\\u00bf\", \"gm\"); } else { dumpln('miss!'); try { (void schedulegc(g0)); } catch(e0) { } a1 = []; } };})(); } catch(e0) { } try { v0 = evaluate(\"function f2(b0)  { \\\"use strict\\\"; yield let (c) window >>= x } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 != 0), noScriptRval: true, sourceIsLazy: true, catchTermination: true, element: o0, sourceMapURL: s2 })); } catch(e1) { } try { for (var v of p0) { try { v1 = Object.prototype.isPrototypeOf.call(p0, a1); } catch(e0) { } try { t1 + o0; } catch(e1) { } try { /*RXUB*/var r = g0.r2; var s = s2; print(r.exec(s));  } catch(e2) { } m2 = new WeakMap; } } catch(e2) { } Array.prototype.unshift.apply(a0, [o1.s2, a0]); return h1; });");
/*fuzzSeed-221406266*/count=389; tryItOut("for(var y in ((runOffThreadScript)(-12 ? \u0009([]) = x < (4277) : this.__defineSetter__(\"a\", (let (e=eval) e))))){this.h0 = ({getOwnPropertyDescriptor: function(name) { h0.keys = (function() { try { a2.sort((function() { for (var j=0;j<38;++j) { f0(j%2==1); } })); } catch(e0) { } try { v2 = a0.length; } catch(e1) { } try { g2.toString = (function(j) { if (j) { try { Object.prototype.unwatch.call(h0, \"length\"); } catch(e0) { } try { t1[15] = this; } catch(e1) { } s2 = ''; } else { this.v1.valueOf = f2; } }); } catch(e2) { } ; return h1; });; var desc = Object.getOwnPropertyDescriptor(a1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return o2; var desc = Object.getPropertyDescriptor(a1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { return this.m0; Object.defineProperty(a1, name, desc); }, getOwnPropertyNames: function() { v1 = t1.length;; return Object.getOwnPropertyNames(a1); }, delete: function(name) { for (var p in b2) { try { for (var p in i2) { try { v2 = t1.BYTES_PER_ELEMENT; } catch(e0) { } for (var v of b0) { this.v0 = m0.get(true); } } } catch(e0) { } v1 = g1.runOffThreadScript(); }; return delete a1[name]; }, fix: function() { print(uneval(e1));; if (Object.isFrozen(a1)) { return Object.getOwnProperties(a1); } }, has: function(name) { f2.toString = f0;; return name in a1; }, hasOwn: function(name) { v0 = new Number(m0);; return Object.prototype.hasOwnProperty.call(a1, name); }, get: function(receiver, name) { v2 = Array.prototype.some.call(a1, (function() { for (var j=0;j<7;++j) { f0(j%4==1); } }));; return a1[name]; }, set: function(receiver, name, val) { const this.t1 = new Int8Array(t0);; a1[name] = val; return true; }, iterate: function() { v1 = Object.prototype.isPrototypeOf.call(o0.g2.p2, f2);; return (function() { for (var name in a1) { yield name; } })(); }, enumerate: function() { Object.freeze(p1);; var result = []; for (var name in a1) { result.push(name); }; return result; }, keys: function() { return o1; return Object.keys(a1); } });function a(w, x)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -18014398509481984.0;\n    var d3 = -562949953421313.0;\n    return +((((4277)) + (+(-1.0/0.0))));\n  }\n  return f;/*RXUB*/var r = /(?!\\B){0,0}/g; var s = \"\\n\\n\"; print(r.exec(s)); print(r.lastIndex); print( /x/  ?  /x/g  : window); }");
/*fuzzSeed-221406266*/count=390; tryItOut("if(false) let h0 = Proxy.create(h1, h2); else s1.valueOf = f0;");
/*fuzzSeed-221406266*/count=391; tryItOut("\"use strict\"; g0.m2.has(m1);function a(x = \"\\u1F56\", \u3056, ...a) /x/g x;");
/*fuzzSeed-221406266*/count=392; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000, 1.7976931348623157e308, -(2**53+2), 0/0, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, -0x080000001, 2**53-2, -(2**53), -0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53-2), Math.PI, 0, 1, 0x0ffffffff, -0x0ffffffff, 2**53+2, 42, 1/0, -0, Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-221406266*/count=393; tryItOut("a0 = new Array;");
/*fuzzSeed-221406266*/count=394; tryItOut("testMathyFunction(mathy5, [-Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53), 1, 2**53+2, -0x080000001, 42, -0x080000000, 1/0, 0x080000000, 0x100000001, -(2**53-2), -0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, -0x100000000, -(2**53+2), -0x100000001, 0.000000000000001, 2**53-2, Math.PI, -0x07fffffff, 0x0ffffffff, -1/0, -0, 0, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-221406266*/count=395; tryItOut("switch((function ([y]) { })()) { case  \"\" .__defineGetter__(\"a\", (1 for (x in []))): v0 = Object.prototype.isPrototypeOf.call(v1, a2);function x(x, eval, \u3056, x =  \"\" , b, x, x, NaN, NaN =  \"\" , a = -27, x, d, x, a, \u3056, x, e = x, x, b, b = (function ([y]) { })(), y, eval, NaN, \u3056, a = \"\\u19D5\", c, y, NaN, x, z, z, e, e, x, x, c, x, w = this, w, b, d = x, d, d, NaN, x, \u3056, x, x = this, x = function ([y]) { }, eval, b, window, b, x, y, x, z, b, x, NaN = this, b = (function ([y]) { })(), eval, this.a, d, x, x, a, b, b, x, x = -10, x, x = \"\\uAD24\", x = ({a1:1}), e) { f0.__proto__ = a1; } ;case new RegExp(\"(?!(?=\\\\u28E6){1,}){1,}(?!(?![^\\\\S\\u8244L-\\\\u118a]|\\\\B))|.\\\\xBD|[^]{4,8}*\", \"gym\")\n: return;let c = x;break;  }");
/*fuzzSeed-221406266*/count=396; tryItOut("/*ADP-2*/Object.defineProperty(o1.a0, 5, { configurable: false, enumerable: true, get: (function mcc_() { var flezqi = 0; return function() { ++flezqi; g0.f2(/*ICCD*/flezqi % 3 == 0);};})(), set: (function() { try { i2.send(b2); } catch(e0) { } try { g0.t2 = new Float64Array(b0, 38, ({valueOf: function() { let x = window, w;/*ODP-1*/Object.defineProperty(v0, \"prototype\", ({writable: this, configurable: \"\\u2548\", enumerable: (x % 6 != 4)}));return 7; }})); } catch(e1) { } v2 = b2.byteLength; return p2; }) });");
/*fuzzSeed-221406266*/count=397; tryItOut("\"use strict\"; (void schedulegc(g1));function yield(e, e, eval, x, \u3056, w, x, d, y = (function ([y]) { })(), x, x, -8, z, y = this, e, e, z, x, z, w, window, window, w, x, e, \u3056, eval, x, window, x, e, y = /(?=(?!(?:.{524288,}[^\u00a9-\\\u00a7\\cO\\u0053-\u68e8]+?.[\\d])))/g, x, z, w =  '' , x, d, x, \u3056 =  /x/ , x, x, \"-6\", y, this.x, NaN, x, NaN, x, x, c, x, d, x, x, d, NaN, x, e, w, x, x, x, x, x =  /x/ , x, b, this, length, e = /(\\B[^]+?|(?=(?!v))|\\s+|\\W{0,}*?)$/ym, x, x, d, w, NaN, \u3056, NaN, x, w, NaN = undefined, window, x, a, x, w, z, d, e, c, d, x =  '' , w)(/*RXUE*/x.exec(\"\\n\") *= \"\\u67EE\")for([a, d] =  /x/g  /=  /x/g  in (x.__defineSetter__(\"y\", Array.prototype.toLocaleString) | (4277))) g0.v2 = Object.prototype.isPrototypeOf.call(f1, t2);");
/*fuzzSeed-221406266*/count=398; tryItOut("w = Proxy.create(({/*TOODEEP*/})(\"\\uC701\"), \"\\uE7CB\");");
/*fuzzSeed-221406266*/count=399; tryItOut(" for  each(a in 29) {o1.a2.length = 16; }");
/*fuzzSeed-221406266*/count=400; tryItOut("\"use strict\"; v0 = t1.byteLength;");
/*fuzzSeed-221406266*/count=401; tryItOut("let (e) { Array.prototype.unshift.call(a0, t2, p1); }");
/*fuzzSeed-221406266*/count=402; tryItOut("testMathyFunction(mathy1, [-0x080000000, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, 0, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0x100000000, 0/0, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, 0x07fffffff, 0x080000000, 2**53-2, Number.MIN_VALUE, -0, -0x100000001, 1, 2**53+2, -(2**53-2), Math.PI]); ");
/*fuzzSeed-221406266*/count=403; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( ! (( + ( - (mathy1((x >>> 0), (x >>> 0)) < Math.imul(Math.fround(Math.hypot(((mathy2((y | 0), (y | 0)) | 0) >>> 0), -0x080000000)), Math.fround(( - ( + Math.expm1(( + -(2**53)))))))))) | 0)) | 0); }); testMathyFunction(mathy4, [0x080000001, -0x080000000, -(2**53-2), Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, -1/0, -0x07fffffff, -0, 0x0ffffffff, 1, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, 42, -0x080000001, -0x0ffffffff, 2**53+2, 0.000000000000001, -(2**53), 2**53, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-221406266*/count=404; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = s1; print(uneval(r.exec(s))); ");
/*fuzzSeed-221406266*/count=405; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x100000000, 0, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0/0, -(2**53+2), 1, -(2**53), Number.MIN_VALUE, 2**53+2, -0x080000000, -0x080000001, 1/0, Number.MAX_VALUE, Math.PI, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, -(2**53-2), 2**53, 2**53-2, 0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, -0, -Number.MIN_VALUE, 42, -0x100000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000001]); ");
/*fuzzSeed-221406266*/count=406; tryItOut("o0.t0.set(a2, 10);");
/*fuzzSeed-221406266*/count=407; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.pow(Math.fround(mathy0(Math.abs(( + (( + Math.min(-0x080000001, mathy0(2**53, y))) < y))), (Math.fround(Math.log10(( ~ Math.max(y, y)))) | 0))), ( - ((((Math.fround(mathy0(Math.fround(2**53-2), Math.fround(x))) < Math.trunc(1.7976931348623157e308)) >>> 0) > (( + Math.exp(y)) | 0)) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -0x100000000, -(2**53), 0.000000000000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), -Number.MIN_VALUE, Math.PI, 0x07fffffff, 2**53-2, 0/0, 1/0, 42, -0x080000001, Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, -1/0, -0x07fffffff, -0x100000001, -(2**53+2), 0x100000000, 0x080000000, 1, -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, -0x080000000]); ");
/*fuzzSeed-221406266*/count=408; tryItOut("/*hhh*/function vbknvd(){(((function fibonacci(ikpnot) { ; if (ikpnot <= 1) { ; return 1; } ; return fibonacci(ikpnot - 1) + fibonacci(ikpnot - 2);  })(3)));}vbknvd();");
/*fuzzSeed-221406266*/count=409; tryItOut("\"use strict\"; v0 = evalcx(\"e1.__iterator__ = f0;\", this.g1);");
/*fuzzSeed-221406266*/count=410; tryItOut("\u000c for  each(var w in 2**53) v1 = Object.prototype.isPrototypeOf.call(s0, g2.b1);");
/*fuzzSeed-221406266*/count=411; tryItOut("\"use strict\"; o1.a2 = a1.filter((function() { g0.__proto__ = b2; return s0; }), g2, v2);");
/*fuzzSeed-221406266*/count=412; tryItOut("mathy1 = (function(x, y) { return (( + Math.sign(mathy0((((y | 0) ? Math.fround(( ! Math.fround(0x100000000))) : (Math.ceil(Math.max(x, 0x100000000)) >>> 0)) | 0), -Number.MAX_VALUE))) || (Math.fround(Math.pow(Math.fround(Math.asin(Math.cosh(Math.fround(( ~ x))))), Math.fround((Math.min((0x100000000 | 0), ((Math.abs((( + ( - 0x080000000)) >>> 0)) >>> 0) | 0)) | 0)))) >>> 0)); }); ");
/*fuzzSeed-221406266*/count=413; tryItOut("mathy1 = (function(x, y) { return ( - Math.hypot(Math.atanh(Math.fround(((x | 0) | ( + ( + ( + ((Number.MAX_VALUE ? -0x100000001 : x) | 0))))))), Math.clz32(2**53))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 2**53+2, -(2**53+2), 2**53-2, 0/0, 0x100000000, -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -1/0, -0, 0x0ffffffff, 2**53, 0x100000001, 0x080000001, -0x100000001, Math.PI, 0x080000000, 42, -Number.MAX_VALUE, 0, -0x100000000, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, 1/0, 0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=414; tryItOut("/*iii*/new ((void version(170)))(skwxum, w != skwxum);/*hhh*/function skwxum({x: {b: [], c, e: \u3056}, \u000cx: [], x: [], x: [, [, z, {this.y: y, window: {eval: x}}, ], {z, a: {}, \u3056}]}){\"use strict\"; g1.g0.f1.toString = (function() { try { e2 = o2; } catch(e0) { } v2 = (f2 instanceof a0); return o0.o0; });}");
/*fuzzSeed-221406266*/count=415; tryItOut("with((NaN = (delete x.x)) =>  { \"\\u2498\"; } (new (e) = \"\\u1C9E\"((4277), length), ( /x/ (new RegExp(\"(?:[^])\", \"gym\"))))){(-3); }");
/*fuzzSeed-221406266*/count=416; tryItOut("mathy5 = (function(x, y) { return ( - ( + mathy1(( + ((Math.min(Math.fround(42), (Math.pow(Math.log10(( + x)), Math.atan2(y, x)) | 0)) | 0) + ( - (Math.fround(Math.pow(( + -0x0ffffffff), 2**53)) ? x : ((((Number.MAX_VALUE | 0) - Math.PI) | 0) | 0))))), ((Math.fround(Math.cosh((mathy1(1.7976931348623157e308, (((y | 0) * y) >>> 0)) >>> 0))) | 0) < -(2**53+2))))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, -0x080000000, 0, -(2**53+2), Number.MAX_VALUE, Math.PI, 1, -0x0ffffffff, 0/0, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -0, -Number.MIN_VALUE, 0x080000000, 2**53, 1.7976931348623157e308, 42, -(2**53), -0x07fffffff, -(2**53-2), 0x100000000, 2**53+2, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=417; tryItOut("Array.prototype.push.call(a0, p1, f0, x, this.s2, this.s0, a0, (timeout(1800)));");
/*fuzzSeed-221406266*/count=418; tryItOut("testMathyFunction(mathy3, [0x100000000, -0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 0, 0x100000001, 1/0, 0x0ffffffff, 2**53-2, Math.PI, -1/0, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, -0, -0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, 0x080000001, Number.MAX_VALUE, 42, 0x080000000, -0x100000000, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=419; tryItOut("var eeihnl = new SharedArrayBuffer(4); var eeihnl_0 = new Int8Array(eeihnl); e0.toSource = (function() { for (var j=0;j<25;++j) { f2(j%3==1); } });v1 = evalcx(\"for (var p in b2) { try { s2 = a0[9]; } catch(e0) { } try { m1.set(m1, v0); } catch(e1) { } try { for (var v of a2) { try { g0.v1 = (o0.p1 instanceof a0); } catch(e0) { } try { this.g1.g2.h1.set = (function() { for (var j=0;j<16;++j) { f1(j%5==1); } }); } catch(e1) { } for (var p in m1) { selectforgc(o1); } } } catch(e2) { } g0.offThreadCompileScript(\\\"/* no regression tests found */\\\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: undefined, sourceIsLazy: false, catchTermination: (x % 3 == 1), sourceMapURL: s0 })); }\", o1.g0);h0.getPropertyDescriptor = f2;");
/*fuzzSeed-221406266*/count=420; tryItOut("\"use strict\"; const x = x, bxsvsb;v2 = (p0 instanceof s0);");
/*fuzzSeed-221406266*/count=421; tryItOut("\"use asm\"; e2 = this.g0.objectEmulatingUndefined();");
/*fuzzSeed-221406266*/count=422; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:\\\\2)*?\", \"g\"); var s = \"\\n\\n\\n\"; print(s.replace(r, x)); ");
/*fuzzSeed-221406266*/count=423; tryItOut("/*tLoop*/for (let x of /*MARR*/[({a: this.eval(\"yield /(?!\\\\1)/gyim;\")}), \"\\uD5E6\", NaN, ({a: this.eval(\"yield /(?!\\\\1)/gyim;\")}), \"\\uD5E6\", ({a: this.eval(\"yield /(?!\\\\1)/gyim;\")}), ({a: this.eval(\"yield /(?!\\\\1)/gyim;\")}), NaN, \"\\uD5E6\", NaN]) { /*hhh*/function hepwqd(window){a2[11];}hepwqd(Math.atan2(/((?:\\2+?){2,4})+/i, 22)); }");
/*fuzzSeed-221406266*/count=424; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy0((Math.fround((Math.fround(Math.atan2(x, (Math.hypot((Math.sinh((0 | 0)) | 0), (y | 0)) % ( + Math.max(( + Math.fround((Math.fround(y) ^ (x >>> 0)))), ( + x)))))) * ( + ( ! ( + (x - Math.PI)))))) | 0), ((mathy1(((Math.atan(Math.fround(Math.max(x, ((Math.fround((0/0 / x)) < Math.fround(x)) >>> 0)))) | 0) >>> 0), ( + Math.clz32(Math.fround(Math.fround(Math.max(Math.fround((y % x)), ((Math.log10((y | 0)) | 0) >>> 0))))))) | 0) | 0)) | 0); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), '/0/', (new String('')), /0/, (new Number(0)), '0', 1, NaN, null, [], ({valueOf:function(){return 0;}}), '', 0.1, false, objectEmulatingUndefined(), undefined, '\\0', 0, (new Boolean(true)), (new Boolean(false)), (new Number(-0)), true, -0, [0], (function(){return 0;}), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-221406266*/count=425; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x0ffffffff, 0x100000001, 1, -(2**53+2), Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, 42, 2**53, -Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, Number.MAX_VALUE, -0, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), 1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, 0, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, -0x080000001, -(2**53), Math.PI]); ");
/*fuzzSeed-221406266*/count=426; tryItOut("v1 = t2[({valueOf: function() { L: g1 = a1[12];return 16; }})];");
/*fuzzSeed-221406266*/count=427; tryItOut("mathy5 = (function(x, y) { return Math.hypot((Math.log10(Math.fround((Math.fround(Math.log2((Math.fround(( - Math.fround(1.7976931348623157e308))) >>> 0))) || -(2**53-2)))) > Math.atan(Math.min(Math.max(y, ( - (y >>> 0))), (mathy2(0x100000001, (y >>> 0)) | 0)))), Math.sign(( ~ ( ~ (Number.MAX_VALUE | 0))))); }); testMathyFunction(mathy5, [-(2**53+2), Math.PI, 0x07fffffff, 0x080000000, -(2**53), 0, -0, 2**53+2, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 1, -1/0, -Number.MAX_VALUE, 0.000000000000001, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), Number.MIN_VALUE, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, -0x07fffffff, 1/0, 2**53, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, -0x080000000, -0x100000001, -0x080000001]); ");
/*fuzzSeed-221406266*/count=428; tryItOut("t1 = new Uint32Array(b2, 48, 0);");
/*fuzzSeed-221406266*/count=429; tryItOut("\"use strict\"; { void 0; bailAfter(1); }");
/*fuzzSeed-221406266*/count=430; tryItOut("o0.t0[4] = (/*RXUE*//(?:\\3)(?:(?!\\2\\f{2047,}))/yim.exec(\"\\n\"));");
/*fuzzSeed-221406266*/count=431; tryItOut("\"use strict\"; /*RXUB*/var r = function(y) { yield y; print(y);; yield y; }.prototype; var s = \"\\u87c3\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=432; tryItOut("/*RXUB*/var r = o2.r2; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-221406266*/count=433; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=434; tryItOut("mathy4 = (function(x, y) { return (Math.exp(Math.fround(Math.min((( ! x) >>> 0), y))) ** (((Math.max(((x >>> ( ~ (x | 0))) | 0), Math.sqrt(x)) >>> 0) != (Math.min((( ~ Math.cosh(y)) | 0), mathy3((( ! Math.fround(y)) >>> 0), Math.cbrt(mathy3(x, y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 2**53, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -0x080000001, Math.PI, 1, 0x080000001, -1/0, 2**53-2, 0/0, -0x100000001, -(2**53+2), -0x07fffffff, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, -(2**53), 0x080000000, -0x080000000, -0x100000000, 0x0ffffffff, 0, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=435; tryItOut("\"use strict\"; /*hhh*/function issjub(z, ...w){Object.defineProperty(this, \"v0\", { configurable: (x % 5 != 3), enumerable: true,  get: function() {  return evaluate(\"s0 += s1;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 6 != 2), noScriptRval: (/(?!(?:\\w+){4,8})/gi)(\"\\uB065\") = NaN, sourceIsLazy: (x % 2 != 1), catchTermination: true })); } });}/*iii*/o2.__proto__ = o2;");
/*fuzzSeed-221406266*/count=436; tryItOut("v2 = a0.some();");
/*fuzzSeed-221406266*/count=437; tryItOut("/*tLoop*/for (let z of /*MARR*/[ /x/ ]) { print(z); }");
/*fuzzSeed-221406266*/count=438; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x07fffffff, -0x100000001, 1.7976931348623157e308, 2**53+2, 0x0ffffffff, 0.000000000000001, 42, -0, 1/0, -(2**53), -(2**53-2), 0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 2**53-2, 1, Number.MAX_VALUE, -0x080000000, 0x100000001, -0x080000001, 0x080000000, -(2**53+2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000001, 0, 2**53, Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=439; tryItOut("/*vLoop*/for (odpray = 0; odpray < 84; ++odpray) { var b = odpray; v1 = (this.p0 instanceof v1); } ");
/*fuzzSeed-221406266*/count=440; tryItOut("/*vLoop*/for (bbnrae = 0; bbnrae < 42; (~x), ++bbnrae) { b = bbnrae; switch(x) { default: var ixntrx = new SharedArrayBuffer(8); var ixntrx_0 = new Uint8ClampedArray(ixntrx); /*MXX2*/g0.ArrayBuffer.prototype.constructor = h2;delete p0[\"caller\"];v1 = o1.t0.length;break; break; case (timeout(1800)):  } } ");
/*fuzzSeed-221406266*/count=441; tryItOut("mathy3 = (function(x, y) { return ( - ( + Math.max(Math.hypot(((y * ( - Math.fround(Math.imul(( + mathy1(( + y), 0x080000000)), (y | 0))))) >>> 0), ( + Math.exp(Math.pow(x, ( + mathy0((y >>> 0), ( + y))))))), Math.fround(( + (((x | 0) - x) >>> 0)))))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), function(){}, function(){}, function(){}, ['z'], function(){}, new Boolean(false), function(){}, new Boolean(false), function(){}, ['z'], function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), ['z'], objectEmulatingUndefined(), new Boolean(false), function(){}, ['z'], function(){}, ['z'], objectEmulatingUndefined(), function(){}, function(){}, new Boolean(false), objectEmulatingUndefined(), ['z'], function(){}, objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), ['z'], function(){}, ['z'], function(){}, new Boolean(false)]); ");
/*fuzzSeed-221406266*/count=442; tryItOut("s1 += s0;( '' );");
/*fuzzSeed-221406266*/count=443; tryItOut("\"use strict\"; g1.o2.t2 = new Float64Array(a1);");
/*fuzzSeed-221406266*/count=444; tryItOut("\"use strict\"; a1.push(m1, i2, t0, f0, i2);");
/*fuzzSeed-221406266*/count=445; tryItOut("(let (b, ouhgol)  /x/ );");
/*fuzzSeed-221406266*/count=446; tryItOut("b1.toString = (function() { for (var j=0;j<9;++j) { f1(j%5==0); } });");
/*fuzzSeed-221406266*/count=447; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.clz32(( + (( + ( + (( + Math.atanh(y)) << ( + y)))) >> ((mathy0(((Math.PI ? y : Math.fround((Math.max((y >>> 0), (y >>> 0)) >>> 0))) >>> 0), (y >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, -0x0ffffffff, 1.7976931348623157e308, 1, Number.MAX_SAFE_INTEGER, 2**53+2, 0x07fffffff, 0.000000000000001, 2**53-2, Math.PI, -Number.MIN_VALUE, 2**53, -(2**53-2), 1/0, -Number.MAX_VALUE, 0x0ffffffff, -0, 0x100000000, 0x100000001, -0x100000001, -0x100000000, 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 0/0, -1/0, Number.MIN_VALUE, 42, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=448; tryItOut("selectforgc(o2);");
/*fuzzSeed-221406266*/count=449; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + mathy1(Math.sinh((( - (Math.sqrt(x) >>> 0)) | 0)), (( ~ y) % y))); }); testMathyFunction(mathy2, ['0', undefined, NaN, (new Boolean(true)), 0.1, [], '', objectEmulatingUndefined(), 1, /0/, (new Number(-0)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), false, '\\0', (function(){return 0;}), (new String('')), [0], null, (new Number(0)), true, '/0/', ({valueOf:function(){return 0;}}), -0, 0, (new Boolean(false))]); ");
/*fuzzSeed-221406266*/count=450; tryItOut("h2 = x;");
/*fuzzSeed-221406266*/count=451; tryItOut("\"use asm\"; /(?:\\b|[^])/gm;throw  '' ;");
/*fuzzSeed-221406266*/count=452; tryItOut("\"use strict\"; s2 += 'x';a0.push(p0,  /x/g .__defineGetter__(\"x\", new Function), e1);");
/*fuzzSeed-221406266*/count=453; tryItOut("var hubdir = new ArrayBuffer(4); var hubdir_0 = new Uint32Array(hubdir); hubdir_0[0] = 8; var hubdir_1 = new Uint16Array(hubdir); var hubdir_2 = new Uint32Array(hubdir); print(hubdir_2[0]); a2.sort((function() { this.h2.get = f0; return m2; }));Array.prototype.shift.call(this.a2);/*oLoop*/for (let bjbics = 0; bjbics < 140; ++bjbics) { a1 = arguments.callee.caller.arguments; } print(undefined.__defineGetter__(\"entries\", function  set (b)this));v1 = Object.prototype.isPrototypeOf.call(t0, o1);this.v1 = (v1 instanceof g0.a2);");
/*fuzzSeed-221406266*/count=454; tryItOut("x\n/* no regression tests found */");
/*fuzzSeed-221406266*/count=455; tryItOut("testMathyFunction(mathy1, [(new Number(0)), 0, /0/, '', (new Number(-0)), '/0/', (new Boolean(false)), '0', [], true, ({valueOf:function(){return '0';}}), (new String('')), (new Boolean(true)), false, ({valueOf:function(){return 0;}}), 1, null, NaN, ({toString:function(){return '0';}}), -0, undefined, objectEmulatingUndefined(), 0.1, (function(){return 0;}), '\\0', [0]]); ");
/*fuzzSeed-221406266*/count=456; tryItOut("t2 = g1.objectEmulatingUndefined();");
/*fuzzSeed-221406266*/count=457; tryItOut("mathy3 = (function(x, y) { return ((((mathy1((Math.log10(((Math.fround(Math.min(( + y), x)) ? ( + (1 <= ( + x))) : (y | 0)) >>> 0)) | 0), ( + (Math.min(((Math.fround(( + Math.fround(x))) == (y >>> 0)) | 0), (x | 0)) | 0))) & (Math.min((x && -(2**53+2)), Math.atan(Math.sinh(0))) >>> 0)) >>> 0) < (Math.asin(((Math.atan2((Math.tanh(( + Math.asinh(( + (( - y) | 0))))) >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [1/0, 0x100000001, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 0, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, -0x080000001, 1, -0x080000000, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -1/0, 0/0, 1.7976931348623157e308, 0x080000000, -(2**53-2), 42, 2**53, -Number.MAX_SAFE_INTEGER, -0, 0x100000000, -Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, 0x080000001, Math.PI, 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=458; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -36028797018963970.0;\n    var d3 = -34359738369.0;\n    var i4 = 0;\n    var i5 = 0;\n    i4 = ((295147905179352830000.0) > (-((d2))));\n    d2 = (-67108864.0);\n    return ((((((+/*FFI*/ff()))) <= (abs((((0x4ce09340)+((~((0xd3ac8acd))) == (((0x9a3f549b)) << ((0xd9b25ad2))))+(-0x8000000))|0))|0))*0xcbdb5))|0;\n  }\n  return f; })(this, {ff: \"\\u75B6\"}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, 0/0, Number.MAX_VALUE, Math.PI, 0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 1/0, 2**53, Number.MIN_VALUE, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, 1, -0x07fffffff, -0, -(2**53), -(2**53+2), 0x0ffffffff, 0x080000001, -0x080000000, 1.7976931348623157e308, -0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000001, 42, 0x07fffffff, 2**53+2, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=459; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=460; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan2((Math.atan2(((Math.cbrt((Math.fround(Math.atan2(Math.fround(Math.sin(0)), Math.fround(Math.hypot(0x080000001, Math.fround(y))))) >>> 0)) >>> 0) >>> 0), (((((mathy1((( ~ x) >>> 0), ((x ? -(2**53) : 0x0ffffffff) >>> 0)) >>> 0) | 0) ? ( ~ Math.fround(x)) : ( + (x ? Math.abs(y) : y))) >>> 0) >>> 0)) >>> 0), ((mathy0((mathy1(Math.acos(Math.fround(mathy0((y >>> 0), x))), ( + y)) >>> 0), (mathy3((( + ( ! x)) | 0), y) | 0)) | 0) | 0)); }); testMathyFunction(mathy4, [-(2**53), -0x080000001, 0x100000001, 0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, 1, 0/0, Math.PI, Number.MAX_VALUE, 2**53-2, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 0, -0x100000001, 0x080000001, 0x07fffffff, -0x07fffffff, 1/0, -1/0, -0x100000000, -(2**53-2), 1.7976931348623157e308, -0x0ffffffff, -0]); ");
/*fuzzSeed-221406266*/count=461; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ (Math.asinh(Math.atan2(Math.fround(Math.hypot((Math.max(( + 42), Math.fround((Math.max((-0x07fffffff >>> 0), (1.7976931348623157e308 >>> 0)) >>> 0))) >>> 0), (x >>> 0))), Math.fround(((((Math.imul((x | 0), (x | 0)) | 0) >>> 0) ? (Math.min(x, x) | 0) : ( + Math.imul(( + -0x100000000), ( + Math.fround(( + Math.fround(y))))))) >>> 0)))) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[(1/0), new Number(1), (1/0), x, new Number(1), new Number(1), (1/0), (1/0), x, (1/0), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), x, (1208796933.5.__defineSetter__(\"x\", x && NaN)), x, (1/0), x, new Number(1), new Number(1), new Number(1), new Number(1), x, x, (1208796933.5.__defineSetter__(\"x\", x && NaN)), new Number(1), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1/0), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN)), (1208796933.5.__defineSetter__(\"x\", x && NaN))]); ");
/*fuzzSeed-221406266*/count=462; tryItOut("mathy5 = (function(x, y) { return ( + Math.cbrt(( + ( ~ Math.max(Math.fround((Math.fround(-(2**53-2)) ? Math.fround((y , y)) : x)), Math.fround(Math.log((-Number.MIN_SAFE_INTEGER === (Math.atan2(( + y), x) | 0))))))))); }); testMathyFunction(mathy5, /*MARR*/[function(){}, function(){}, {}, function(){}, function(){}]); ");
/*fuzzSeed-221406266*/count=463; tryItOut("\"use strict\"; print(b0);");
/*fuzzSeed-221406266*/count=464; tryItOut("v1 = a0.length;");
/*fuzzSeed-221406266*/count=465; tryItOut("for (var p in v1) { try { m2 + m0; } catch(e0) { } try { e1.add(e0); } catch(e1) { } for (var v of o0) { /*ODP-3*/Object.defineProperty(g2, \"wrappedJSObject\", { configurable:  \"\" , enumerable: false, writable: false, value: i2 }); } }");
/*fuzzSeed-221406266*/count=466; tryItOut("\"use strict\"; b2 = new ArrayBuffer(0);");
/*fuzzSeed-221406266*/count=467; tryItOut("/*ODP-2*/Object.defineProperty(b0, \"__lookupSetter__\", { configurable: (x % 5 != 0), enumerable: x, get: (function mcc_() { var qtsfua = 0; return function() { ++qtsfua; if (/*ICCD*/qtsfua % 10 == 8) { dumpln('hit!'); a1.splice(NaN, 3, undefined, o2); } else { dumpln('miss!'); try { o0.valueOf = f0; } catch(e0) { } try { t2.set(t2, 11); } catch(e1) { } try { (void schedulegc(g2)); } catch(e2) { } a0.unshift(i0); } };})(), set: (function(j) { if (j) { try { a1 + e2; } catch(e0) { } v1 = evalcx(\"g0.v0 = (b0 instanceof this.t1);\", g2); } else { try { h0.defineProperty = (function() { try { v1 = Object.prototype.isPrototypeOf.call(b1, o1); } catch(e0) { } try { a2 = Array.prototype.map.apply(a2, [(function(j) { if (j) { try { v0 = b2.byteLength; } catch(e0) { } r2 = /(?:(?=((?=[\\W\\d])|(?=.))[\u0001\\xc0\u0005\\u00C3-\\\u66f7]))/gyi; } else { try { h2.get = [[]]; } catch(e0) { } try { v2 = g1.runOffThreadScript(); } catch(e1) { } s1 = new String(h1); } }), o0.i1, p2, b1, o1]); } catch(e1) { } t1.set(a2, 0); return m0; }); } catch(e0) { } try { v0 = (h1 instanceof t2); } catch(e1) { } o0 = new Object; } }) });\nprint(\n(Function(length)));\n");
/*fuzzSeed-221406266*/count=468; tryItOut("delete h1.has;");
/*fuzzSeed-221406266*/count=469; tryItOut("\"use strict\"; t0.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 9.671406556917033e+24;\n    var i3 = 0;\n    var d4 = -4.722366482869645e+21;\n    {\n      switch ((((0x9262ede)*0x2d312) & ((0x6b870701) % (0x798b3de4)))) {\n      }\n    }\n    d0 = (d1);\n    d1 = (((+(0.0/0.0))) - ((-1.1805916207174113e+21)));\n    d0 = (9.44473296573929e+21);\n    return (((((i3)+(1))>>>((((Float32ArrayView[((0xe25244e2)*0x6ae62) >> 2]))))) / (0x421f6587)))|0;\n  }\n  return f; });");
/*fuzzSeed-221406266*/count=470; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.pow(Math.fround((Math.fround(((( + ( - x)) ^ Math.hypot(x, y)) / (x & x))) <= (Math.max((mathy0(((( + ( ~ 2**53+2)) == (y ^ 0x100000001)) | 0), y) >>> 0), ( + Math.hypot(( + Math.fround(0x080000001)), Math.fround(0x100000001)))) >>> 0))), Math.fround(( + (( + Math.tan(x)) | ( + Math.hypot((Math.atan2((Math.imul((y >>> 0), (y | 0)) | 0), 1/0) != (((((x | 0) | y) | 0) < (0 | 0)) | 0)), Math.cosh(Math.atanh(x))))))))); }); testMathyFunction(mathy1, [-0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, 1/0, 0, -0x080000000, -0x100000001, 2**53+2, -(2**53+2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 1.7976931348623157e308, 0/0, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), -Number.MIN_VALUE, 0x080000001, -0, 2**53-2, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000000, 2**53, -(2**53), 0x0ffffffff, 0x080000000, 1, 42]); ");
/*fuzzSeed-221406266*/count=471; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MAX_VALUE, -(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, -0, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), 1, 1/0, -0x080000000, 2**53-2, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53), -1/0, -0x100000001, 42, 0.000000000000001, Math.PI, -0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 0x07fffffff, 2**53+2, -0x080000001, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=472; tryItOut("v2 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-221406266*/count=473; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=474; tryItOut("testMathyFunction(mathy0, [2**53-2, Number.MIN_VALUE, 0/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000001, -0x07fffffff, -(2**53+2), -0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, 0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), 0x0ffffffff, 0x100000000, -(2**53), 2**53, 0, -1/0, 0x100000001, 0.000000000000001, 42, 0x080000000, 2**53+2, -0x100000001, 1]); ");
/*fuzzSeed-221406266*/count=475; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.cos(Math.fround(Math.max(( + Math.atan2(( + Math.log1p(( + y))), Math.hypot(Math.atan(( + (( + ( - ( + x))) != y))), (-(2**53-2) > ( + (-(2**53+2) > x)))))), Math.cbrt(( + Math.cos(( + (Math.fround(-0x080000001) ? ( + (Math.fround(x) == ( + -1/0))) : Math.min(y, ( + ( - ( + y)))))))))))); }); ");
/*fuzzSeed-221406266*/count=476; tryItOut("\"use strict\"; a1.forEach((function() { try { Array.prototype.splice.apply(a1, [NaN, 9, o0, m0, g1.a2]); } catch(e0) { } f2 + g1.i1; return i2; }));");
/*fuzzSeed-221406266*/count=477; tryItOut("testMathyFunction(mathy3, [-(2**53), -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 42, 2**53+2, -0x080000000, -1/0, Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -0, 1, 0x0ffffffff, 2**53, -Number.MIN_VALUE, -0x07fffffff, Math.PI, 0.000000000000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000000, -0x080000001, 0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 0/0, 0]); ");
/*fuzzSeed-221406266*/count=478; tryItOut("for (var v of t1) { try { /*RXUB*/var r = r2; var s = s2; print(s.match(r));  } catch(e0) { } try { m2.delete(g2.s0); } catch(e1) { } try { Object.prototype.watch.call(i0, \"setUTCFullYear\", f1); } catch(e2) { } v2 = r2.source; }");
/*fuzzSeed-221406266*/count=479; tryItOut("Array.prototype.forEach.call(a2, (function(j) { if (j) { for (var p in f2) { g0.v0 = new Number(b1); } } else { try { g1.h0.valueOf = o2.o2.f0; } catch(e0) { } f0 = (function() { try { e0.add(e1); } catch(e0) { } try { a2 = Proxy.create(h0, this.g1.o2); } catch(e1) { } try { g2.e2.has(v2); } catch(e2) { } a2.sort((function() { for (var j=0;j<20;++j) { f2(j%4==1); } }), v2, o0, i1, window); throw p0; }); } }));");
/*fuzzSeed-221406266*/count=480; tryItOut("\"use strict\"; /*toXFun*/valueOf: function() { return (4277); }s1 = s1.charAt(11);");
/*fuzzSeed-221406266*/count=481; tryItOut("\"use strict\"; with((4277))delete h2.has;");
/*fuzzSeed-221406266*/count=482; tryItOut("testMathyFunction(mathy0, [2**53+2, 2**53, 0x0ffffffff, -(2**53+2), 0, -0x07fffffff, 0x100000001, 0x080000000, -0x100000000, -0x080000001, -0x080000000, 0/0, -(2**53-2), 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -1/0, -0x100000001, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 42, 1/0, -(2**53), -0, 1, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=483; tryItOut("v2 = evaluate(\"/* no regression tests found */\", ({ global: o1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 8 != 1), sourceIsLazy: false, catchTermination: (x % 14 == 10) }));\ndelete t1[\"arguments\"];\n");
/*fuzzSeed-221406266*/count=484; tryItOut("g1.v2.valueOf = f0;");
/*fuzzSeed-221406266*/count=485; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\"; /*vLoop*/for (var hbwyxu = 0; hbwyxu < 40; ++hbwyxu) { let x = hbwyxu; v1 = (g2.s1 instanceof p2); } \n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      return +((d0));\n    }\n    {\n      d0 = (d0);\n    }\n    return +((+(0x20f5640b)));\n    return +((d1));\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -0x0ffffffff, 42, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, 0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, 1.7976931348623157e308, -0x100000000, 2**53+2, -0x080000001, 1/0, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, -0x080000000, Math.PI, 1, 0.000000000000001, -0, 2**53-2]); ");
/*fuzzSeed-221406266*/count=486; tryItOut("\"use strict\"; for(let w in new Root()) /*ODP-2*/Object.defineProperty(m0, \"x\", { configurable: true, enumerable: window, get: function(y) { yield y; ;; yield y; }, set: (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((+(((i1)*0x34006)>>>((i1)))));\n  }\n  return f; }) });function y(x, y, y, eval, e, c, e, x, a, x = window, x, eval, eval =  /x/g , d, z, x = 3, b = false, x, eval = ({a1:1}), c, NaN, w, x, \u3056, window, \u3056, z, d, z, x, x = [1], d, \u3056, w, x, false, y = ({a1:1}), c, x, w =  /x/g , x, x =  \"\" , eval = x, x, \u3056 =  /x/ , e, x, a, x, NaN, y) { \"use strict\"; print(w); } this.a1.sort((function() { try { Array.prototype.sort.call(o1.o1.a1, i0); } catch(e0) { } try { /*RXUB*/var r = g2.r1; var s = \"\\n\"; print(s.search(r)); print(r.lastIndex);  } catch(e1) { } try { /*RXUB*/var r = r1; var s =  /x/g ; print(s.replace(r, '\\u0341', \"y\"));  } catch(e2) { } t2 = new Uint8Array(4); return g2.m2; }), b2, this.s1);");
/*fuzzSeed-221406266*/count=487; tryItOut("mathy0 = (function(x, y) { return (( ~ (c | 0)) | 0); }); testMathyFunction(mathy0, [-0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 42, 0x07fffffff, -0x080000000, -1/0, 2**53-2, -0x0ffffffff, 0.000000000000001, 0x100000001, Math.PI, 0x080000001, -0x080000001, 1/0, 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, 0, -(2**53+2), Number.MAX_VALUE, -0x100000001, 0x0ffffffff, 0x100000000, 2**53+2, 1, -(2**53), 0/0, -0]); ");
/*fuzzSeed-221406266*/count=488; tryItOut("\"use asm\"; var t2 = new Int32Array(a0);");
/*fuzzSeed-221406266*/count=489; tryItOut("v2 = -Infinity;");
/*fuzzSeed-221406266*/count=490; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.fround(( ! Math.fround((((Math.fround(Math.hypot(-0x100000001, Math.fround(Math.exp(((((x >>> 0) ** (x >>> 0)) >>> 0) | 0))))) | 0) >= ((Math.pow(-0x080000001, -0) & x) | 0)) | 0)))) >>> 0), (Math.hypot(Math.fround(Math.cosh((-(2**53-2) | 0))), Math.sinh(0.000000000000001)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, Math.PI, -0, -(2**53), -(2**53-2), 2**53+2, 2**53, Number.MIN_VALUE, 0, 0x07fffffff, -0x080000001, 1.7976931348623157e308, 0/0, 42, -0x100000001, 1, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, 0.000000000000001, 1/0, -1/0, 2**53-2, -(2**53+2), Number.MAX_VALUE, -0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=491; tryItOut("i0 + '';");
/*fuzzSeed-221406266*/count=492; tryItOut("testMathyFunction(mathy3, [2**53, -0x080000001, 1, Math.PI, -0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, 2**53-2, Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, 0, -(2**53), 0/0, 1/0, -0x07fffffff, -0x080000000, 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 42, 2**53+2, -0, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=493; tryItOut("/*oLoop*/for (var ktynhz = 0; ktynhz < 83; ++ktynhz) { /*MXX2*/g2.String.prototype.fixed = g0.h1; } ");
/*fuzzSeed-221406266*/count=494; tryItOut("let (\u3056, x, z, c = x, d( \"\" ) = (4277)) { (selectforgc(o2)); }");
/*fuzzSeed-221406266*/count=495; tryItOut("a2 = a0.concat(g1.a1, t1, a1, t0);");
/*fuzzSeed-221406266*/count=496; tryItOut("mathy4 = (function(x, y) { return (((( + ((( + Math.abs(( + (-Number.MAX_SAFE_INTEGER | 0)))) == (Math.log1p(( + Math.max(mathy1(x, x), ((Math.sign(y) >>> 0) <= (Math.fround((Math.fround(y) ** Math.fround(y))) >>> 0))))) >>> 0)) >>> 0)) | 0) + ((( + Math.pow(Math.fround(y), Math.fround(((x >> ( ~ x)) <= (Math.sin((Math.acos(Math.atan2(y, Number.MAX_VALUE)) >>> 0)) >>> 0))))) | 0) | 0)) | 0); }); testMathyFunction(mathy4, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, 42, 0.000000000000001, -(2**53), -0, Number.MIN_VALUE, -Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 2**53-2, 1.7976931348623157e308, -0x100000001, 2**53, 0x100000001, 0x080000001, 0, 0/0, -0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, 0x07fffffff, -Number.MIN_VALUE, 1/0, -(2**53+2), -0x080000000]); ");
/*fuzzSeed-221406266*/count=497; tryItOut("\"use strict\"; e1.delete(v2);");
/*fuzzSeed-221406266*/count=498; tryItOut("\"use strict\"; [x, {x}, ] = eval(\"s2 += s2;\");/*MXX3*/g1.Number.MIN_VALUE = g2.Number.MIN_VALUE;function a() { yield Math.max(x >>>= x,  /* Comment */1) } for(let e in [,,z1]) {print(x); }let a = x;");
/*fuzzSeed-221406266*/count=499; tryItOut("/*ADP-3*/Object.defineProperty(a2, ({valueOf: function() { /*tLoop*/for (let d of /*MARR*/[ /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), x,  /x/ , x,  /x/ , objectEmulatingUndefined(),  /x/ , x, x, x,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(), x,  /x/ , objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x,  /x/ ,  /x/ , x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(),  /x/ , x,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , x, x,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , x, x,  /x/ ,  /x/ , x, objectEmulatingUndefined()]) { print(d); }return 5; }}), { configurable: true, enumerable: (x % 55 != 18), writable: true, value: t0 });");
/*fuzzSeed-221406266*/count=500; tryItOut("mathy1 = (function(x, y) { return (( + (( ~ ( + y)) !== ((Math.cos(( - Math.fround(( ! (x | 0))))) ** (Math.fround((Math.fround(( + (( + Math.sin(-Number.MAX_SAFE_INTEGER)) ? ( + x) : ( + x)))) & Math.fround(-0))) >>> 0)) | 0))) | ( + Math.atan2(Math.imul(( + Math.fround(y)), ( + Math.fround(Math.min(Math.fround(-0x080000000), 0x080000001)))), ( + Math.max(( + Math.clz32(Math.fround(Math.asinh(Math.fround(1/0))))), ( + Math.pow(((((0x0ffffffff >>> 0) ? ( + (Math.pow((x | 0), (((x ? ( + -0x0ffffffff) : x) >>> 0) | 0)) | 0)) : 0.000000000000001) | 0) | 0), Math.min(-(2**53-2), ( + x))))))))); }); testMathyFunction(mathy1, [0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, 0.000000000000001, 0/0, -0x080000000, 1, -1/0, Math.PI, -(2**53+2), 0x100000001, 42, 2**53, Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, 0x07fffffff, -(2**53-2), 0, 1/0, -0x0ffffffff, -(2**53), 2**53-2]); ");
/*fuzzSeed-221406266*/count=501; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[ \"\" ,  \"\" ,  \"\" , null,  \"\" ,  \"\" ,  \"\" ,  \"\" , null,  \"\" , null, null, null, null]) { g2.a0.splice(NaN, ({valueOf: function() { Array.prototype.push.call(a1, b0, g2.h2, i1, m1);return 5; }})); }");
/*fuzzSeed-221406266*/count=502; tryItOut("mathy0 = (function(x, y) { return Math.expm1(( ~ ((( + Math.acosh(x)) <= (Math.cos(Math.log1p(x)) | 0)) | 0))); }); testMathyFunction(mathy0, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0x100000001, 1/0, Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001, 0, -0x100000000, 1, -0x080000000, Math.PI, 0x100000000, 0x0ffffffff, 2**53+2, -(2**53-2), 2**53-2, -1/0, -0x100000001, 42, 0/0, -0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, -0, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=503; tryItOut("\"use strict\"; a0 = r0.exec(g2.s0);");
/*fuzzSeed-221406266*/count=504; tryItOut("\"use strict\"; e2.add(h1);");
/*fuzzSeed-221406266*/count=505; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, 0/0, 0x100000000, -0x07fffffff, 0, 0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 1/0, 42, 0x07fffffff, -0x080000000, -Number.MAX_VALUE, Math.PI, -(2**53), 2**53, 0x080000000, -1/0, -(2**53+2), 0x0ffffffff, 2**53-2, 0.000000000000001, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=506; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( - (Math.asin((y | (Math.round(Math.fround(Math.acosh(x))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x07fffffff, 2**53, 1, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0x100000000, -Number.MAX_VALUE, 0, Number.MAX_VALUE, 0x100000000, 0/0, -0x080000001, -0x100000001, 1/0, -(2**53), 0x100000001, -0x080000000, 0.000000000000001, 2**53+2, 0x080000000, -Number.MIN_VALUE, 2**53-2, -0x07fffffff, 0x0ffffffff, Math.PI, -0, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-221406266*/count=507; tryItOut("a0.forEach((function() { try { m1.delete(t0); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(o1, i2); } catch(e1) { } v2 = evaluate(\"var g0.o2.s2 = '';\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 77 == 0), noScriptRval: (SimpleObject = (4277)), sourceIsLazy: (x % 23 == 3), catchTermination: true })); return g0.o2; }));");
/*fuzzSeed-221406266*/count=508; tryItOut("mathy0 = (function(x, y) { return (Math.max(( - (((Math.trunc(( + Math.trunc(Number.MIN_SAFE_INTEGER))) | 0) ? Math.atan2(Math.hypot(y, (y >>> 0)), y) : (x | 0)) | 0)), (( + ( - ( + ( ~ x)))) | 0)) | 0); }); testMathyFunction(mathy0, [-0x100000000, 1/0, -0x080000000, 0/0, Math.PI, Number.MAX_VALUE, -(2**53), -0x0ffffffff, 0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 1, Number.MIN_VALUE, -Number.MIN_VALUE, -0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -(2**53-2), 0x100000000, 1.7976931348623157e308, -0x07fffffff, -(2**53+2), 0x080000001, 2**53, -1/0, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0, 42, 2**53-2, 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=509; tryItOut("testMathyFunction(mathy5, [0x07fffffff, Math.PI, 0, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, 1, Number.MAX_VALUE, 0x100000001, -0x0ffffffff, -0x080000001, 0/0, -0x100000000, -Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, -(2**53+2), -(2**53), 42, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, -0, 2**53+2, 0x100000000, Number.MIN_VALUE, -0x100000001, -1/0, 0x080000000, -0x080000000]); ");
/*fuzzSeed-221406266*/count=510; tryItOut("\"use strict\"; testMathyFunction(mathy1, [2**53, -(2**53-2), -0x080000001, -Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, 42, 0/0, 0x100000000, -0, Math.PI, 2**53-2, 2**53+2, -0x0ffffffff, 0x100000001, -0x100000001, -(2**53+2), -1/0, Number.MIN_VALUE, 0, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 1, 0x080000000, -0x080000000, 0.000000000000001, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=511; tryItOut("\"use strict\"; L:with({x: (x)(\"\\u2BAF\")}){o1.m2.get(a2); }");
/*fuzzSeed-221406266*/count=512; tryItOut("mathy4 = (function(x, y) { return (Math.fround(mathy1(Math.fround(( + Math.min(( + ( + (( + Math.ceil(Math.fround(x))) >= ( - ( + y))))), -Number.MAX_SAFE_INTEGER))), Math.fround(( + ((x << ((((Math.min((0x0ffffffff >>> 0), (y >>> 0)) >>> 0) >>> 0) == (y >>> 0)) >>> 0)) == ((0x100000000 || (x >>> 0)) | 0)))))) ? ( + Math.clz32((Math.min((Math.cos((Math.min(( + y), Math.fround(x)) | 0)) | 0), (( ! y) >>> 0)) >>> 0))) : ( + ((( ~ (((Math.acos(((0x0ffffffff ? x : Number.MAX_VALUE) | 0)) >>> 0) ^ (y >>> 0)) >>> 0)) >>> 0) ? (Math.fround(Math.sinh(( + (x >> 0x080000000)))) | Math.fround(Math.pow(( + y), x))) : ( + Math.fround(y))))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, 1, 0x080000000, -Number.MIN_VALUE, 0x0ffffffff, 42, 0.000000000000001, Math.PI, -0x100000000, -0, 1.7976931348623157e308, -0x100000001, -(2**53), 0/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, 0x07fffffff, 0, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, 2**53+2, -0x0ffffffff, 2**53, -Number.MAX_VALUE, 0x080000001, -(2**53-2), -0x080000000, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=513; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.imul(Math.fround(mathy2((( - Math.fround(Math.pow((Math.fround(Math.sin(y)) >>> 0), ( + ( + Math.atan2(( + Math.round(-(2**53-2))), ( + mathy2(x, x)))))))) >>> 0), ( + Math.sinh((((((Math.fround(mathy0(y, mathy2(-0, 0x100000001))) ? ( - y) : (1.7976931348623157e308 | 0)) | 0) | 0) >>> (( + x) | 0)) | 0))))), Math.fround(Math.sqrt((( ~ (y != Math.atan2(y, x))) >>> 0))))); }); testMathyFunction(mathy3, [42, -0x080000001, 0x080000001, -0x100000000, -1/0, -0x07fffffff, 0, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, Math.PI, -0, Number.MIN_VALUE, -(2**53+2), -Number.MIN_VALUE, 1, 0x080000000, 1.7976931348623157e308, 0x100000000, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), 1/0, -0x080000000, 0x100000001, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=514; tryItOut("t2 = t1.subarray(19);");
/*fuzzSeed-221406266*/count=515; tryItOut("testMathyFunction(mathy2, [-0x100000001, -Number.MAX_VALUE, 2**53+2, 2**53-2, 0x080000001, -0, 0/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 42, 0, -0x080000000, -(2**53+2), -0x080000001, 1/0, 0x100000001, 0x07fffffff, 1.7976931348623157e308, 2**53, Math.PI, 0.000000000000001, -Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 0x100000000, 1]); ");
/*fuzzSeed-221406266*/count=516; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(e0, f0);");
/*fuzzSeed-221406266*/count=517; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.atan2(( + ( ! ( + Math.min((-Number.MAX_VALUE | 0), Math.fround(Math.fround(Math.atan2(Math.fround(((( - (-0x100000000 >>> 0)) >>> 0) + y)), Math.fround(x)))))))), ((mathy1(Math.hypot(y, (y & -(2**53-2))), Number.MAX_VALUE) >>> 0) > Math.fround(Math.ceil(Math.fround(x))))); }); testMathyFunction(mathy3, [0x0ffffffff, -0, -Number.MAX_VALUE, -1/0, 0x100000000, -0x080000000, Number.MIN_VALUE, 0x080000001, 2**53, 0.000000000000001, 0/0, 2**53-2, -(2**53), -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, 1, 0, -0x100000000, 42, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53-2), 1/0, 2**53+2, Math.PI, 0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=518; tryItOut("\"use strict\"; e0.add(h2);");
/*fuzzSeed-221406266*/count=519; tryItOut("\"use strict\"; t0 = new Uint8ClampedArray(12);");
/*fuzzSeed-221406266*/count=520; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-221406266*/count=521; tryItOut("a0 = Proxy.create(h1, this.f2);\nh1 = {};\n");
/*fuzzSeed-221406266*/count=522; tryItOut("\"use strict\"; f1.__proto__ = o1;");
/*fuzzSeed-221406266*/count=523; tryItOut("v0.__proto__ = this.a1;");
/*fuzzSeed-221406266*/count=524; tryItOut("\"use strict\"; s2 = s2.charAt(10);");
/*fuzzSeed-221406266*/count=525; tryItOut("testMathyFunction(mathy0, [42, -0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x080000001, 0x07fffffff, Math.PI, -(2**53+2), Number.MIN_VALUE, 2**53, 0x100000001, 2**53-2, 1, 0, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 0/0, -0x100000000, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), 0x100000000, 2**53+2, -1/0]); ");
/*fuzzSeed-221406266*/count=526; tryItOut("mathy1 = (function(x, y) { return Math.atan((Math.min((Math.max(x, mathy0(( + x), mathy0(y, y))) >>> 0), (Math.imul((((Math.fround(( ~ Math.fround(y))) >>> 0) / (x >>> 0)) | 0), y) >>> 0)) | 0)); }); testMathyFunction(mathy1, [-0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -1/0, 0x080000000, -0x080000000, 2**53+2, -Number.MAX_VALUE, -(2**53+2), -0, -(2**53-2), -0x100000001, 2**53, 0x0ffffffff, -0x0ffffffff, 0x100000001, 1.7976931348623157e308, 0x100000000, 0, 1, 1/0, 0/0, 0x080000001, Math.PI, 2**53-2, -(2**53), 0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001]); ");
/*fuzzSeed-221406266*/count=527; tryItOut("mathy0 = (function(x, y) { return ( ~ ( + Math.imul(( + (Math.sqrt((x | 0)) | 0)), Math.hypot(Math.fround(( ! y)), Math.fround(Math.min(-Number.MAX_SAFE_INTEGER, y)))))); }); testMathyFunction(mathy0, /*MARR*/[ /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , new String('q'),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), (neuter.prototype),  /x/ , (neuter.prototype)]); ");
/*fuzzSeed-221406266*/count=528; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ (( ! (( ~ Math.expm1(Math.fround(1.7976931348623157e308))) | 0)) | 0)) , Math.fround(Math.fround(Math.max(Math.fround((Math.atanh(Math.fround(( + (Math.fround(((y >>> 0) / Math.fround(Math.log((x >>> 0))))) | 0)))) / x)), Math.fround((Math.fround(Math.atan2(Math.fround((Math.fround((Math.atan2(y, (x | 0)) | 0)) ? Math.fround(x) : Math.fround(x))), (-0 | ( + (0x07fffffff | 0))))) >= Math.hypot(y, x))))))); }); testMathyFunction(mathy0, [0x080000000, -Number.MIN_VALUE, 0x0ffffffff, 0x080000001, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), -0, -(2**53+2), Number.MAX_SAFE_INTEGER, -1/0, 1, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, 2**53+2, -0x100000000, -(2**53), -0x07fffffff, 1/0, 1.7976931348623157e308, 0/0, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 2**53-2, 0.000000000000001, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, 0x100000001]); ");
/*fuzzSeed-221406266*/count=529; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (mathy1(Math.abs(-Number.MIN_VALUE), (Math.min(Math.fround((( + ((y - Math.fround(y)) >>> 0)) | 0)), (x | 0)) | 0)) == Math.fround(Math.cbrt(((26 += \"\\u5B47\") | 0)))); }); testMathyFunction(mathy5, [1/0, -Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, 0/0, -0x07fffffff, -0x100000000, 0x07fffffff, -(2**53-2), -0x0ffffffff, -0x100000001, -1/0, -0x080000000, 0.000000000000001, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, 0, 2**53-2, Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, 42, 2**53, -(2**53), 0x080000000, Number.MIN_VALUE, -0, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=530; tryItOut("mathy3 = (function(x, y) { return mathy2(((new (/*wrap1*/(function(){ return window;return (function(x, y) { return x; })})())(({a2:z2}), -4).eval(\"a0 + v2;\")) | 0), ((( + Math.max((( ! (( ! (y >>> 0)) >>> 0)) | 0), x)) << (Math.sign((Math.imul(( - ( + Math.imul(( + x), Math.hypot(0.000000000000001, x)))), Math.cos((((0x100000000 >>> 0) < x) >>> 0))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy3, [-(2**53), 1/0, 0x080000001, -0, 1.7976931348623157e308, -(2**53+2), 0x0ffffffff, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -Number.MIN_VALUE, -1/0, -0x080000000, 0.000000000000001, -(2**53-2), 2**53+2, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -0x080000001, 0/0, 0x100000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, Number.MAX_VALUE, 0x07fffffff, 0, 0x080000000, -0x100000000, 42, -Number.MAX_SAFE_INTEGER, 1]); ");
/*fuzzSeed-221406266*/count=531; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1/0, -0x100000000, -Number.MAX_VALUE, 1, 0/0, 0x100000001, 2**53, 0x080000001, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, 42, Math.PI, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0, -0, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0x100000001, Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), -(2**53+2), Number.MAX_VALUE, -0x07fffffff, -(2**53), 2**53+2]); ");
/*fuzzSeed-221406266*/count=532; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      (Uint8ArrayView[2]) = (((4277))+(/*FFI*/ff(((d0)))|0));\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: Array.prototype.concat}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-1/0, -0, 1.7976931348623157e308, 2**53, 0x080000001, 2**53-2, -0x080000001, -0x080000000, -0x07fffffff, 0, -0x0ffffffff, Number.MAX_VALUE, -0x100000001, Math.PI, 0x080000000, Number.MIN_VALUE, 1/0, -(2**53), 42, 1, 0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=533; tryItOut("testMathyFunction(mathy3, [(function(){return 0;}), ({valueOf:function(){return '0';}}), (new String('')), [0], ({valueOf:function(){return 0;}}), /0/, '0', -0, ({toString:function(){return '0';}}), [], '', null, 0.1, '\\0', (new Number(-0)), (new Boolean(true)), '/0/', 0, NaN, 1, (new Number(0)), (new Boolean(false)), true, false, undefined, objectEmulatingUndefined()]); ");
/*fuzzSeed-221406266*/count=534; tryItOut("v1 = t1.length;");
/*fuzzSeed-221406266*/count=535; tryItOut("\"use strict\"; ;");
/*fuzzSeed-221406266*/count=536; tryItOut("mathy0 = (function(x, y) { return ( ! Math.hypot(((Math.pow((42 | 0), (y | 0)) | 0) / (Math.log2((Math.imul((x ? y : x), Math.fround(x)) >>> 0)) >>> 0)), Math.log((y >>> 0)))); }); testMathyFunction(mathy0, [1/0, -Number.MIN_VALUE, 0x100000001, 1, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0, 0x100000000, -(2**53+2), -Number.MAX_VALUE, -0x080000001, 2**53, 0x080000001, -0x100000000, 0x0ffffffff, -1/0, -0x0ffffffff, Math.PI, -0x080000000, 0x07fffffff, -(2**53), 1.7976931348623157e308, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0, -0x100000001, -(2**53-2), 42, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-221406266*/count=537; tryItOut("\"use strict\"; Array.prototype.push.call(o1.a2, i1, t0);");
/*fuzzSeed-221406266*/count=538; tryItOut("\"use strict\"; var v0 = Array.prototype.reduce, reduceRight.call(a2, g1.g0);");
/*fuzzSeed-221406266*/count=539; tryItOut("\"use asm\"; o1.toString = (function() { try { v0 = a2.length; } catch(e0) { } m1.get((4277)); return m1; });");
/*fuzzSeed-221406266*/count=540; tryItOut("mathy3 = (function(x, y) { return Math.sin(((Math.log2((mathy0(( + ( + Math.asinh((((Math.atan2(x, ( + 0x080000001)) | 0) ? (0x07fffffff | 0) : Math.fround(-0x07fffffff)) | 0)))), (x || Math.fround((y < ( + y))))) | 0)) | 0) | 0)); }); testMathyFunction(mathy3, [(function(){return 0;}), ({valueOf:function(){return '0';}}), '\\0', [], (new Number(-0)), null, true, 0.1, (new String('')), ({toString:function(){return '0';}}), /0/, (new Boolean(true)), '/0/', 0, -0, false, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), '', (new Boolean(false)), [0], 1, NaN, undefined, '0', (new Number(0))]); ");
/*fuzzSeed-221406266*/count=541; tryItOut("if(true) {this.s1 += 'x';print(x); } else  if ('fafafa'.replace(/a/g, encodeURIComponent)) {this.t2[v0] = [z1];this; }");
/*fuzzSeed-221406266*/count=542; tryItOut("\"use strict\"; with({d: this = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(x), Object.defineProperty(x, 3, ({value: (4277), writable: (x % 8 == 0), configurable: x, enumerable: false})))})/* no regression tests found */");
/*fuzzSeed-221406266*/count=543; tryItOut("/*MXX3*/g2.String.prototype.padStart = g2.String.prototype.padStart;");
/*fuzzSeed-221406266*/count=544; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=545; tryItOut("mathy4 = (function(x, y) { return Math.imul(mathy3((mathy3(Math.hypot(-Number.MIN_VALUE, Math.atan2((y | 0), y)), (Math.fround((0x080000001 >>> 0)) >>> 0)) >>> 0), Math.fround(( + Math.fround(((( + Math.pow((y | 0), (y >>> 0))) , ( + y)) | 0))))), ((((Math.hypot((x >>> 0), (Math.fround(( ~ Math.fround(x))) | 0)) | 0) >>> 0) - (( ~ Math.fround(( + Math.tan(1/0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-1/0, -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, 0, 2**53+2, 2**53, 0x100000001, -Number.MIN_VALUE, 0.000000000000001, 0x07fffffff, -(2**53), -0x07fffffff, -(2**53+2), Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 42, 2**53-2, -0x080000000, 0x080000001, 1, -0x080000001, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, 0x080000000, Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-221406266*/count=546; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a2, v2, { configurable: false, enumerable: true, writable: (x % 5 == 4), value: o2.m2 });");
/*fuzzSeed-221406266*/count=547; tryItOut("\"use strict\"; /*infloop*/for(\u3056 = /*UUV2*/(b.sqrt = b.setHours); Math.hypot(-8, window); (yield new Map())) /*ODP-1*/Object.defineProperty(p1, \"x\", ({}));\nv2 = (e1 instanceof o0.b1);\n");
/*fuzzSeed-221406266*/count=548; tryItOut("Array.prototype.unshift.call(this.g2.a2, e1, h1, h1, o0.p0, g2);");
/*fuzzSeed-221406266*/count=549; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3\", \"gim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-221406266*/count=550; tryItOut("/*vLoop*/for (fdaalf = 0; fdaalf < 14; ++fdaalf) { var d = fdaalf; /*bLoop*/for (ujjvzo = 0; ujjvzo < 0; ++ujjvzo) { if (ujjvzo % 59 == 39) { print( \"\" ); } else { this.s1 = o0.m0; }  }  } ");
/*fuzzSeed-221406266*/count=551; tryItOut("/*vLoop*/for (var dawxlm = 0; dawxlm < 7; ++dawxlm, c) { e = dawxlm; print((Math.acos)); } function y(x = x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })( /x/g ), Math.tanh, runOffThreadScript), eval)(({eval: new RegExp(\"(?:\\\\2\\\\w?).\\\\2+\", \"yi\"),  get call(e, x)\"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    (Uint16ArrayView[((((1.0)))+(0xffffffff)) >> 1]) = ((((((((i0)) | ((i0)))))|0))-(-0x8000000));\n    return +((-2097152.0));\n    return +((((-0x8000000)-(0xf832d9e5))));\n  }\n  return f; }))print(x);");
/*fuzzSeed-221406266*/count=552; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -562949953421313.0;\n    var d3 = -513.0;\n    var i4 = 0;\n    var d5 = -0.0009765625;\n    var i6 = 0;\n    var i7 = 0;\n    d5 = (d5);\n    d5 = (d2);\nt0.set(a1, ({valueOf: function() { b1 = new ArrayBuffer(24);return 12; }}));    d0 = (274877906945.0);\n    return +((((0xffffffff)-(i4))));\n  }\n  return f; })(this, {ff: (Function).call}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000001, -0x100000000, 0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, -0, 0/0, Number.MIN_VALUE, 0, -0x080000000, -(2**53+2), -0x0ffffffff, 1.7976931348623157e308, 42, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -(2**53-2), -0x100000001, 0x100000001, 0.000000000000001, 1/0, 0x100000000, 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, -(2**53), 1, -1/0]); ");
/*fuzzSeed-221406266*/count=553; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + ((((( - Math.fround(0.000000000000001)) | 0) >>> 0) << (( + Math.round(Math.fround((((Math.cosh(((mathy3((1 >>> 0), 42) * y) | 0)) >>> 0) === (x >>> 0)) >>> 0)))) >>> 0)) >>> 0)) !== ( ~ (((y <= (y | 0)) | 0) >>> 0))); }); testMathyFunction(mathy5, [-0x07fffffff, -1/0, 1, 1.7976931348623157e308, 1/0, 0x100000001, 0x080000000, -0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, -(2**53+2), -0, 0, 0x100000000, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, 0/0, 2**53+2, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=554; tryItOut("\"use strict\"; /*RXUB*/var r = /./; var s = \"\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=555; tryItOut("/*MXX2*/this.g0.String.prototype.toLocaleUpperCase = i0;\ns2 = new String(m2);\n");
/*fuzzSeed-221406266*/count=556; tryItOut("for (var v of t0) { this.b1 = new ArrayBuffer(30); }\n/*bLoop*/for (kwtiqy = 0; kwtiqy < 11; ++kwtiqy) { if (kwtiqy % 5 == 1) { /*oLoop*/for (var bquxac = 0; bquxac < 50; ++bquxac) { i1.next(); }  } else { v0 = g0.eval(\"function f0(o1)  { \\\"use asm\\\"; return 'fafafa'.replace(/a/g, /*wrap2*/(function(){ \\\"use strict\\\"; var xldryr = o1 = window >>> new SharedArrayBuffer( \\\"\\\" ); var ntanca = this = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: Array.prototype.map, delete: function() { throw 3; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function  a (NaN) { return -10 } , hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function(y) { \\\"use strict\\\"; yield y; v1 = evaluate(\\\"testMathyFunction(mathy5, [0x100000001, 1.7976931348623157e308, 1/0, 0.000000000000001, -0x100000001, 0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, -0x100000000, 42, 0x080000001, -(2**53), 2**53, Number.MAX_VALUE, 0x07fffffff, -1/0, 2**53+2, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, 1, 0x100000000, 0/0, -0x0ffffffff, Math.PI, Number.MIN_VALUE]); \\\", ({ global: o1.g2, fileName: null, lineNumber: 42, isRunOnce: (xldryr % 5 != 1), noScriptRval: true, sourceIsLazy: true, catchTermination: this, elementAttributeName: s1 }));; yield y; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })( \\\"\\\" ), q => q, mathy4); return ntanca;})()) } \"); }  } ");
/*fuzzSeed-221406266*/count=557; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.atanh(( ~ ( + (( + (mathy1(Math.fround(mathy1((-Number.MAX_VALUE >>> 0), Math.fround((((x >>> 0) * y) >>> 0)))), (1 >>> 0)) >>> 0)) ** ( + x))))) / (((Math.hypot(((((( + (( + x) + (y ? y : (y >>> 0)))) >>> 0) & Math.fround((Math.fround(( + (y !== (x >>> 0)))) && Math.fround(y)))) | 0) >>> 0), (Math.tan(y) >>> 0)) | 0) | 0) + ( + (( + (mathy1((mathy1(0x07fffffff, ( + ( ~ x))) >>> 0), (x ? (( + (x | 0)) | 0) : 1.7976931348623157e308)) >>> 0)) == ( + 0x080000001))))); }); testMathyFunction(mathy2, [2**53+2, 0x07fffffff, -0x0ffffffff, 0x0ffffffff, -1/0, 42, 1, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, -(2**53+2), -0x100000001, 0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000000, 0x100000000, 0/0, -0x07fffffff, 2**53, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, Number.MIN_VALUE, 2**53-2, -0, -0x080000000]); ");
/*fuzzSeed-221406266*/count=558; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy4(Math.fround(( ! Math.fround(( + ( + ( - (Math.fround(x) < Math.fround(x)))))))), Math.fround(mathy4(( + (y | 0)), ( + (Math.min(-0x0ffffffff, Math.sqrt((y >>> 0))) || 1.7976931348623157e308))))); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-221406266*/count=559; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (mathy1(( + (Math.exp(( + Math.log1p(-(2**53+2)))) ? mathy2(Math.log10(( + ( + Math.atan2(((mathy0((x | 0), (y | 0)) | 0) >>> 0), ( + ( + (y <= x))))))), ( + x)) : (Math.min(y, ( + (((y | 0) ** (mathy3(x, ( + x)) | 0)) | 0))) / (Math.sign(x) >>> 0)))), (Math.atanh((Math.round(-(2**53-2)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [2**53+2, -1/0, 0x080000001, -0x080000001, Math.PI, Number.MAX_VALUE, 0, 0x100000000, 0x100000001, 1.7976931348623157e308, -(2**53-2), 0x07fffffff, 0/0, -0x07fffffff, -0x080000000, -(2**53+2), 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, -0x100000000, 1, 0x0ffffffff, 2**53-2, -Number.MAX_VALUE, -0x100000001, 2**53, -(2**53), 0.000000000000001, 42, 0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=560; tryItOut("\"use strict\"; do ((arguments.callee.caller.caller).call(-18,  /x/ ).yoyo(Object.defineProperty(x, \"0\", ({configurable: true})))); while(((4277)) && 0);");
/*fuzzSeed-221406266*/count=561; tryItOut("\"use strict\"; var ndbhxq = new SharedArrayBuffer(16); var ndbhxq_0 = new Int8Array(ndbhxq); print(ndbhxq_0[0]); ndbhxq_0[0] = 1523799585.5; f2(o0.g0);e0.add(i2);\n/*RXUB*/var r = r1; var s = s2; print(r.exec(s)); print(r.lastIndex); \n");
/*fuzzSeed-221406266*/count=562; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.sin(mathy0((Math.clz32((( + ( + ( + x))) >>> 0)) | 0), ((( + ( ! ((y - Math.fround(0x080000001)) >>> 0))) ? Math.log10((((x >>> 0) != y) >>> 0)) : ((Math.max(((x * 1.7976931348623157e308) >>> 0), Math.fround(((-0 | 0) ? Math.fround(x) : Math.PI))) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[new Number(1), new Number(1), [1], new Number(1), 1e+81, new Number(1), new Number(1), new Number(1), 1e+81, 1e+81, 1e+81, [1], [1], new Number(1), (void 0), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (void 0), [1], [1], new Number(1)]); ");
/*fuzzSeed-221406266*/count=563; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    return +((-9.0));\n  }\n  return f; })(this, {ff: (new Function(\"print(x >>> /(?:[\\u0093\\\\w])/ym.indexOf());\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_VALUE, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, 2**53, 2**53+2, 0/0, 42, -0, 0x080000001, 0x07fffffff, -(2**53), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, -(2**53-2), 1/0, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, 1, 0, 1.7976931348623157e308, -(2**53+2), -0x080000000, -0x100000001, 0x100000001, 0x0ffffffff, -0x100000000, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=564; tryItOut("t0 = new Int8Array(b1);");
/*fuzzSeed-221406266*/count=565; tryItOut("m2.has(i1);");
/*fuzzSeed-221406266*/count=566; tryItOut("\"use strict\"; o1 = a1[4];");
/*fuzzSeed-221406266*/count=567; tryItOut("testMathyFunction(mathy0, /*MARR*/[true, new String('q'), false, x, x, x, new String('q'), new String('q'), x, new String('q'), x, false, new String('q'), x, x, x, new String('q'), false, new String('q'), new String('q'), true]); ");
/*fuzzSeed-221406266*/count=568; tryItOut("Array.prototype.sort.call(o2.o1.a0, (function() { try { --([, , , ]) = t2[2]; } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(o2.s1, o1); } catch(e1) { } try { i1.send(a2); } catch(e2) { } (void schedulegc(g0)); return s2; }), f1);");
/*fuzzSeed-221406266*/count=569; tryItOut("/*infloop*/ for (arguments[\"blink\"] of /$[^]\\3*??/yi) {this.g0.g2.offThreadCompileScript(\" /* Comment *//\\\\S/yim\"); for  each(var c in (Date.prototype.getUTCMonth).call(\"\\u6A99\", )) (this. /x/g ); }");
/*fuzzSeed-221406266*/count=570; tryItOut("\"use strict\"; a0 = (Math.imul((Math.min((Math.atan(x) | 0), ( + Math.imul(Math.fround(x), x))) ? (( + Math.fround(x)) | 0) : Math.acosh(-Number.MIN_SAFE_INTEGER)), ( + (Math.max(Math.hypot(( + Math.hypot((Math.fround(Math.imul(Math.fround(2**53-2), Math.fround(x))) >>> 0), x)), (x >>> 0)), ((( - Math.fround((Math.fround(x) & ( + ( ! x))))) >>> 0) >>> 0)) >>> 0))));");
/*fuzzSeed-221406266*/count=571; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(mathy2(Math.asin(Math.fround(( ~ (( + ( ! (( ~ Math.hypot((x | 0), (-0x100000001 | 0))) >>> 0))) && y)))), Math.fround(Math.atanh((mathy1(((Math.PI && (( ~ ( ! x)) | 0)) >>> 0), (( ~ y) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, /*MARR*/[new RegExp(0.572, ((makeFinalizeObserver('tenured')))), new Number(1), new RegExp(0.572, ((makeFinalizeObserver('tenured')))), new Number(1), new Number(1), new RegExp(0.572, ((makeFinalizeObserver('tenured')))), new RegExp(0.572, ((makeFinalizeObserver('tenured')))), new Number(1), new RegExp(0.572, ((makeFinalizeObserver('tenured')))), new Number(1), new RegExp(0.572, ((makeFinalizeObserver('tenured')))), new Number(1), new Number(1)]); ");
/*fuzzSeed-221406266*/count=572; tryItOut("mathy3 = (function(x, y) { return Math.imul(( + ((( + Math.fround(mathy1(mathy2(mathy2(y, y), x), y))) ** (( ! Math.fround(Math.imul(y, x))) * ( + Math.hypot((x | 0), -Number.MIN_VALUE)))) >>> 0)), ( + ( + (( ! (x ? Math.min(-0x07fffffff, ((Math.fround(x) ^ x) | 0)) : x)) >= (Math.fround(Math.min(Math.sinh((Math.fround(( + mathy1(y, Math.hypot(Math.fround(y), y)))) >>> 0)), Math.fround(Math.max(Math.fround(Math.fround(Math.max(( + Math.min(( + ((Math.fround(y) | (0x07fffffff >>> 0)) >>> 0)), ( + y))), (( ~ x) | 0)))), Math.fround(Math.atan2(x, ( ! Math.fround((( + (x >>> 0)) >>> 0))))))))) >>> 0))))); }); testMathyFunction(mathy3, [2**53, -Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, -0, -Number.MAX_VALUE, Number.MAX_VALUE, 0.000000000000001, 1, 1/0, 2**53-2, -0x100000001, -0x07fffffff, 0/0, -0x080000001, 0x0ffffffff, 0x080000001, 0x100000001, Number.MIN_VALUE, -(2**53+2), -1/0, -(2**53-2), 42, -0x100000000, 0x07fffffff, 2**53+2, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-221406266*/count=573; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.log2(( + ( - ( + Math.trunc(-Number.MAX_SAFE_INTEGER)))))); }); ");
/*fuzzSeed-221406266*/count=574; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ! ( + ( - Math.fround(y)))); }); testMathyFunction(mathy3, [true, 1, ({valueOf:function(){return '0';}}), [], NaN, ({valueOf:function(){return 0;}}), (new Boolean(true)), '', '/0/', '0', ({toString:function(){return '0';}}), (function(){return 0;}), -0, (new Number(-0)), null, objectEmulatingUndefined(), [0], 0.1, (new Number(0)), false, (new Boolean(false)), '\\0', undefined, 0, (new String('')), /0/]); ");
/*fuzzSeed-221406266*/count=575; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + Math.fround(( + (Math.tan((mathy0((mathy0(( + y), -0) | 0), Math.fround(( - Math.fround(y)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [0x080000000, 0x080000001, 2**53, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -(2**53), -1/0, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, -0, 0x07fffffff, -0x080000000, 42, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 1/0, 0x0ffffffff, 1, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), -0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001]); ");
/*fuzzSeed-221406266*/count=576; tryItOut("mathy0 = (function(x, y) { return Math.log10(( ! (Math.acosh((( - x) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [Math.PI, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000000, 0.000000000000001, -0, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 1/0, 2**53-2, 0x07fffffff, -(2**53), -0x080000001, 1, 0x0ffffffff, -0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 0x100000000, -(2**53+2), 0, 42]); ");
/*fuzzSeed-221406266*/count=577; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(( + Math.sqrt(Math.sin(Math.trunc((x ? Math.fround(x) : Math.fround(0x080000001)))))), Math.min((( ~ Math.fround(Math.imul(Math.fround(0x100000000), ((( ~ (-(2**53-2) >>> 0)) >>> 0) | 0)))) | 0), ( + (((( ~ ( ~ (Math.log2(x) >>> 0))) >>> 0) && (((Number.MIN_SAFE_INTEGER | 0) , (x | 0)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [-0x080000001, 0.000000000000001, Number.MIN_VALUE, 1/0, -Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, -(2**53), 2**53-2, -0x100000001, 0x0ffffffff, Number.MAX_VALUE, 1, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, 2**53+2, -0, 0x07fffffff, -(2**53+2), -Number.MAX_VALUE, Math.PI, 0/0, -1/0, -0x0ffffffff, 0x080000000, 42, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x100000001, 0]); ");
/*fuzzSeed-221406266*/count=578; tryItOut("\"use strict\"; /*vLoop*/for (let ghamlo = 0; ghamlo < 17; ++ghamlo) { w = ghamlo; print(\"\\u8917\"); } ");
/*fuzzSeed-221406266*/count=579; tryItOut("\"use strict\"; L: for  each(let b in /[^]/gim) {return \"\\u9038\"; }");
/*fuzzSeed-221406266*/count=580; tryItOut("{for (var p in o0) { try { o2 = t2[({valueOf: function() { print(( \"\" ));return 12; }})]; } catch(e0) { } try { for (var p in f1) { try { e0.has(this.h2); } catch(e0) { } try { s2 = new String(e0); } catch(e1) { } v0 = evalcx(\"function f2(h2) [z1,,]\", g2); } } catch(e1) { } m1.has(g1.h0); } }");
/*fuzzSeed-221406266*/count=581; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.log((( ~ (Math.imul((Math.atanh(( + (( + Math.cbrt(Math.fround(x))) , ( + ((-(2**53-2) >>> 0) <= x))))) >>> 0), ((((x | 0) ? Math.imul(( + Math.fround((x == ( + 2**53)))), ( + y)) : (y | 0)) | 0) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -(2**53), Number.MIN_VALUE, -0x100000000, -0x100000001, 0x080000000, -0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, 2**53, -(2**53-2), 1/0, -0, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1, -Number.MAX_VALUE, -1/0, 2**53+2, 0.000000000000001, 0x07fffffff, -0x07fffffff, 2**53-2, 0x080000001, 0x100000000, Math.PI, 0, 0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=582; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.trunc(Math.atanh(((Math.fround((y < Math.fround(mathy1(Math.fround(2**53+2), Math.fround(Math.pow(((( + y) ^ y) | 0), (0/0 | 0))))))) ? Math.fround(y) : Math.fround(( - ( + ( + Math.min(( + 1.7976931348623157e308), y)))))) | 0))); }); testMathyFunction(mathy3, [-0x100000001, -0x080000001, -0x100000000, 0x080000000, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, 2**53, -(2**53+2), 0x07fffffff, 2**53+2, Math.PI, 1, -(2**53-2), -(2**53), 2**53-2, 0x100000000, 1/0, Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=583; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[(\u3056) = (++y), new Number(1.5), (\u3056) = (++y), new Number(1.5), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), new Number(1.5), new Number(1.5), new Number(1.5), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), new Number(1.5), (\u3056) = (++y), new Number(1.5), (\u3056) = (++y), (\u3056) = (++y), new Number(1.5), (\u3056) = (++y), new Number(1.5), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), new Number(1.5), new Number(1.5), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), new Number(1.5), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), (\u3056) = (++y), new Number(1.5), new Number(1.5), new Number(1.5), (\u3056) = (++y), new Number(1.5), new Number(1.5), (\u3056) = (++y)]) { b0 + f2; }");
/*fuzzSeed-221406266*/count=584; tryItOut("\"use strict\"; {print(x <<= x);i2.next(); }");
/*fuzzSeed-221406266*/count=585; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log10(( + ( + (mathy1(((((((y | 0) & Math.fround(y)) | 0) & (Math.imul(( + (x << ( + x))), (y >>> 0)) >>> 0)) >>> 0) | 0), (( ! (((( + y) | 0) * (Math.acos(( - y)) | 0)) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy2, [-0x080000001, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -(2**53), -0, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, -0x080000000, -0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 42, 0, 0/0, Math.PI, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), 0.000000000000001, 1.7976931348623157e308, 0x080000000, 0x100000000, 0x100000001, 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-221406266*/count=586; tryItOut("var oypcyo, {} =  \"\" , x = (\"\\u1A41\" /=  \"\" ), x, \u3056, x, NaN, x;print(x);");
/*fuzzSeed-221406266*/count=587; tryItOut("mathy3 = (function(x, y) { return ( ~ (( - Math.fround((Math.atan2(Math.atan2(Math.max((mathy0(y, x) | 0), (y | 0)), x), ((Math.fround((Math.fround(x) >>> Math.fround(x))) < ((( ! ((x & x) >>> 0)) >>> 0) | 0)) | 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy3, [42, 0x100000000, 0x100000001, -0x07fffffff, -0x0ffffffff, 2**53+2, 0x080000001, 0, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 0x080000000, 0.000000000000001, 0x0ffffffff, 2**53-2, Number.MIN_VALUE, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, 1, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, -(2**53+2), 2**53, 0/0, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000000, 1/0, -0x100000001]); ");
/*fuzzSeed-221406266*/count=588; tryItOut("(undefined.yoyo( /x/ ));");
/*fuzzSeed-221406266*/count=589; tryItOut("\"use strict\"; var v1 = b0.byteLength;");
/*fuzzSeed-221406266*/count=590; tryItOut("Object.prototype.unwatch.call(s0, \"d\");");
/*fuzzSeed-221406266*/count=591; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.cosh((mathy1(( + y), ( + y)) < ( + 0x080000000))); }); ");
/*fuzzSeed-221406266*/count=592; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 17592186044417.0;\n    return +((+/*FFI*/ff(((+abs(((-288230376151711740.0))))), (((((((i0)-((((0x98896e6a))>>>((0xffffffff)))))>>>((i1)+((0xb856d600)))))) ^ (((((i1))>>>(((0xae733d88)))))+(!(SharedArrayBuffer()))+(((0xf90444bf) ? (0x44cf0528) : (0xfbebae88)) ? (i0) : (0xb2cd8e9c))))), (((-(function(id) { return id })) << (0x7ada*(i0)))), ((((i1)) & (((((0xfa7d4afd)) << ((0xfb7543c9))))+(i0)))), (((Infinity) + (+(((0xfbef7faf)) << ((0xffffffff)))))), ((+((-1.0009765625)))))));\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 1, 2**53-2, Number.MIN_VALUE, -0x07fffffff, 0, -(2**53-2), -Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 0x080000000, -1/0, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 2**53+2, 0x080000001, 42, 0x07fffffff, 1/0, 0.000000000000001, -(2**53+2), -0, 2**53, 0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), -0x100000001]); ");
/*fuzzSeed-221406266*/count=593; tryItOut("let(window = (void options('strict_mode')), c = ( /* Comment */true), [[], , , ] = /*UUV2*/(y.__defineSetter__ = y.codePointAt)) ((function(){for(let x in []);})());with({}) for(let w in []);");
/*fuzzSeed-221406266*/count=594; tryItOut("");
/*fuzzSeed-221406266*/count=595; tryItOut("\"use strict\"; L:if(true) v0 = m0.get((4277));");
/*fuzzSeed-221406266*/count=596; tryItOut("\"use strict\"; for (var v of o1.m2) { try { h0.defineProperty = (function() { try { g2.__proto__ = o2.m2; } catch(e0) { } try { Array.prototype.shift.apply(a0, [s2, s1, o2.g1, h1]); } catch(e1) { } try { for (var p in m1) { try { m1.get(i1); } catch(e0) { } try { m2[\"apply\"] = a0; } catch(e1) { } s0 += g1.s0; } } catch(e2) { } h2 = ({getOwnPropertyDescriptor: function(name) { /*MXX1*/o2 = g0.EvalError.prototype.toString;; var desc = Object.getOwnPropertyDescriptor(s2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v2 = Array.prototype.reduce, reduceRight.apply(a1, [/*wrap2*/(function(){ var mjqqxe = [z1]; var hktstx = runOffThreadScript; return hktstx;})(), t1, p1, v1]);; var desc = Object.getPropertyDescriptor(s2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { h1.keys = g0.f1;; Object.defineProperty(s2, name, desc); }, getOwnPropertyNames: function() { h2.set = (function(j) { if (j) { try { a1.pop(t0, null); } catch(e0) { } this.b2.__proto__ = this.g1; } else { try { m1.get(t2); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(o0.o2, m2); } });; return Object.getOwnPropertyNames(s2); }, delete: function(name) { g1.e1.add(p0);; return delete s2[name]; }, fix: function() { v1 = evalcx(\"v1 = Object.prototype.isPrototypeOf.call(t2, b2);\", g0);; if (Object.isFrozen(s2)) { return Object.getOwnProperties(s2); } }, has: function(name) { Object.defineProperty(this, \"v2\", { configurable: (x % 72 == 17), enumerable: false,  get: function() {  return new Number(s1); } });; return name in s2; }, hasOwn: function(name) { Object.defineProperty(this, \"v1\", { configurable: (x % 4 == 3), enumerable: false,  get: function() {  return evaluate(\"\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 == 2), noScriptRval: true, sourceIsLazy: Math.hypot((function(stdlib, foreign, heap){ \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (2048.0);\n    }\n    {\n      (Float64ArrayView[2]) = ((d0));\n    }\n    return +((-7.737125245533627e+25));\n  }\n  return f; }), -4), catchTermination: (x % 19 == 1), element: o1 })); } });; return Object.prototype.hasOwnProperty.call(s2, name); }, get: function(receiver, name) { o2.a2[11] = ([\u3056 &= Math]);; return s2[name]; }, set: function(receiver, name, val) { o0 + e2;; s2[name] = val; return true; }, iterate: function() { a1 = new Array;; return (function() { for (var name in s2) { yield name; } })(); }, enumerate: function() { g1.valueOf = (function() { try { e0.valueOf = (function() { for (var j=0;j<46;++j) { f0(j%3==1); } }); } catch(e0) { } try { v2 = evalcx(\"function f0(t2)  { \\\"use asm\\\"; h0.getPropertyDescriptor = (function mcc_() { var lqddxq = 0; return function() { ++lqddxq; if (/*ICCD*/lqddxq % 2 == 1) { dumpln('hit!'); try { t0[6]; } catch(e0) { } try { g2.offThreadCompileScript(\\\"function f0(this.e1)  { \\\\\\\"use strict\\\\\\\"; yield -29 } \\\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 2 == 1), noScriptRval: true, sourceIsLazy: (t2 % 10 == 7), catchTermination: null })); } catch(e1) { } try { g0.v1.__proto__ = b0; } catch(e2) { } Array.prototype.splice.apply(a2, [NaN, 13, p2]); } else { dumpln('miss!'); try { v1 = (f1 instanceof g0.o2); } catch(e0) { } try { Array.prototype.sort.call(a1, (function() { try { (void schedulegc(g2)); } catch(e0) { } /*RXUB*/var r = r1; var s = \\\"\\\\u135c\\\\n\\\\u135c\\\\n\\\\u135c\\\\n\\\\u135c\\\\n\\\\u135c\\\\n\\\\u135c\\\\n\\\\u135c\\\\n\\\"; print(r.exec(s)); print(r.lastIndex);  return v0; }), p1, t0, s2, m1); } catch(e1) { } g1.v0 = t2.BYTES_PER_ELEMENT; } };})(); } \", this.g0); } catch(e1) { } a2.shift(p0, e2, b2); return m1; });; var result = []; for (var name in s2) { result.push(name); }; return result; }, keys: function() { Array.prototype.sort.apply(this.a1, [(function mcc_() { var lcknmx = 0; return function() { ++lcknmx; if (/*ICCD*/lcknmx % 8 == 1) { dumpln('hit!'); try { v2 = (v2 instanceof this.a1); } catch(e0) { } try { Array.prototype.forEach.call(a0, f2, g2, h1); } catch(e1) { } m2.get(-21); } else { dumpln('miss!'); try { this.a0.unshift(); } catch(e0) { } try { v0 = this.g0.eval(\"/((?:\\\\2\\u001f){2,})/i;\"); } catch(e1) { } a2.forEach((function(j) { f0(j); }), g2); } };})(), h1, f1, o0.o1, b2]);; return Object.keys(s2); } }); return m0; }); } catch(e0) { } try { i2.send(this.v0); } catch(e1) { } try { g1.a1.forEach((function() { try { t0 = t0.subarray(12); } catch(e0) { } try { m0.set(i0, Object.defineProperty(z, \"valueOf\", ({value: (window , \"\\u4268\"), configurable: false, enumerable: undefined}))); } catch(e1) { } i0.next(); return v1; }), h2, this.a1, g0); } catch(e2) { } for (var v of p2) { try { Array.prototype.splice.apply(a0, [NaN, v0, o0.v2]); } catch(e0) { } Array.prototype.unshift.call(a2, t2, t2, a1, /*UUV1*/(c.getDate\u0009 = eval(\"/* no regression tests found */\", false))); } }");
/*fuzzSeed-221406266*/count=597; tryItOut("p0.__proto__ = i1;");
/*fuzzSeed-221406266*/count=598; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + Math.acosh(Math.hypot(Math.fround(y), y))) - Math.min(mathy0(mathy0((( + Math.log(( + (Math.fround(1) , x)))) < x), x), ( + y)), (Math.atan2((( + ( + (( + mathy0(( + y), ( + y))) !== ( ! (x >>> 0))))) >>> 0), ((Math.log(( + (( + x) || Math.fround(mathy0(( + x), 0x100000001))))) | 0) | 0)) | 0))); }); ");
/*fuzzSeed-221406266*/count=599; tryItOut("");
/*fuzzSeed-221406266*/count=600; tryItOut("\"use strict\"; /*RXUE*/new RegExp(\"(?!.\\u9f0d|\\\\b?(?:(?:\\\\w))|(?:(?=[\\u6dca-\\\\b])){4}|(?:\\\\D.)+{0})\", \"gm\").exec(\"\");");
/*fuzzSeed-221406266*/count=601; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: (x % 3 == 0), enumerable: (x % 18 != 10),  get: function() {  return evalcx(\"x.__defineSetter__(\\\"x\\\", (arguments = /(?=(?:\\\\2){1}[\\\\u00A4\\\\\\u00ee\\u00a5]|.)/m))\", g2); } });");
/*fuzzSeed-221406266*/count=602; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.imul((Math.fround(Math.clz32(( + Math.expm1(( + Math.asin(((x & y) | 0))))))) >>> 0), (( + Math.imul(((Math.cos(Math.atan2(( + x), y)) + Math.hypot((( + (y == Number.MIN_SAFE_INTEGER)) , -(2**53-2)), (( ! y) | 0))) == y), (((( ~ ((Math.hypot((x | 0), (x | 0)) | 0) >>> 0)) >>> 0) - ( + -0x080000000)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[x, true, true, x, x, true, true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, true, x, objectEmulatingUndefined(), x, x, true, x, x, x, x, x, x, x, x, x, x, x, x, x, x, true, x, x, true, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, true, x, x]); ");
/*fuzzSeed-221406266*/count=603; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.pow(( + Math.sin((Math.atanh(( + (Math.acosh(((Math.fround(Math.clz32(-0)) ** ( + ( + Math.tan(( + 0x080000001))))) >>> 0)) >>> 0))) | 0))), (( ~ Math.fround(( - Math.max(mathy0(Math.imul(y, Number.MIN_SAFE_INTEGER), (x < x)), (( + Math.min(( + Math.hypot(( + y), y)), ( + y))) | 0))))) >>> 0))); }); testMathyFunction(mathy1, [-0x100000000, -0x0ffffffff, 0x080000000, 0/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 42, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 2**53-2, 0x080000001, -0x080000001, -(2**53+2), -0x080000000, 0x07fffffff, -(2**53), 1, Math.PI, Number.MAX_VALUE, 2**53+2, 0x100000001, 0x100000000, -0, -1/0, 2**53, 1.7976931348623157e308, -0x07fffffff, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=604; tryItOut("{/*MXX3*/g0.Function.prototype.caller = g0.Function.prototype.caller;/* no regression tests found */ }");
/*fuzzSeed-221406266*/count=605; tryItOut("switch(x) { case 7: break;  }");
/*fuzzSeed-221406266*/count=606; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=607; tryItOut("mathy5 = (function(x, y) { return (Math.sqrt((( ~ ((((( + y) | 0) > 2**53-2) || Math.fround((Math.hypot((x | 0), (y | 0)) | 0))) >>> 0)) >>> 0)) / Math.fround(( ! (Math.sin((Math.hypot(y, (y <= 0x100000000)) | 0)) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[function(){}, true, function(){}, new Number(1.5), function(){}, new Number(1), true, true, true, new Number(1), new Number(1), true, true, new Number(1), new Number(1.5), function(){}, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), function(){}, new Number(1), function(){}, new Number(1.5), true, new Number(1.5), true, new Number(1), true, true, function(){}, new Number(1.5), new Number(1), new Number(1.5), new Number(1.5), function(){}, function(){}, new Number(1.5), true, new Number(1), true, new Number(1.5), new Number(1), true, new Number(1.5), function(){}, function(){}, new Number(1), function(){}, true, true, true, function(){}, function(){}, new Number(1.5), true, function(){}, new Number(1), true, new Number(1.5), new Number(1), new Number(1), new Number(1), new Number(1), function(){}, function(){}, new Number(1.5), new Number(1.5), true, new Number(1), function(){}, new Number(1), true, function(){}, function(){}, function(){}, function(){}, true, new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-221406266*/count=608; tryItOut("(1 for (x in []))(x);");
/*fuzzSeed-221406266*/count=609; tryItOut("\"use asm\"; let (x, z, uijeod, xqlqzy, hepfrn, nzgcwh, w) { t1.set(a0, o1.v0); }");
/*fuzzSeed-221406266*/count=610; tryItOut("let (wxdigb, z, hxajhj, x, ofjavr) { f0.toSource = (function mcc_() { var vkyjvu = 0; return function() { ++vkyjvu; if (/*ICCD*/vkyjvu % 8 == 1) { dumpln('hit!'); try { a2[0]; } catch(e0) { } try { for (var v of o1.f2) { try { e1.add(e2); } catch(e0) { } for (var v of e0) { try { g0.h1.hasOwn = (function() { t1 = x; return this.p2; }); } catch(e0) { } try { m2.delete(g2.t2); } catch(e1) { } try { ; } catch(e2) { } print(t2); } } } catch(e1) { } h1.getOwnPropertyNames = f2; } else { dumpln('miss!'); m2 + o2; } };})(); }");
/*fuzzSeed-221406266*/count=611; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1*?|(\\\\f)(?!(?:\\\\b|[\\u00ec]){3})|(\\\\3{3,})\\\\1+?*\", \"gyim\"); var s = \"\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\"; print(s.split(r)); ");
/*fuzzSeed-221406266*/count=612; tryItOut("\"use asm\"; Array.prototype.unshift.apply(a2, [b2, h2, a2]);");
/*fuzzSeed-221406266*/count=613; tryItOut("/*infloop*/while((/*FARR*/[.../*FARR*/[false,  \"\" , ]].filter((p={}, (p.z =  '' )()), x))){t0[17] = x = this; }");
/*fuzzSeed-221406266*/count=614; tryItOut("s2 += g1.g1.s2;");
/*fuzzSeed-221406266*/count=615; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\".\", \"yim\"); var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-221406266*/count=616; tryItOut("\"use strict\"; return;y = c;");
/*fuzzSeed-221406266*/count=617; tryItOut("m2.set(p2, t0);for (var p in g0) { try { i0.next(); } catch(e0) { } try { g1.v0 = g1.g1.eval(\"x\"); } catch(e1) { } try { p2 = Proxy.create(h1, t1); } catch(e2) { } m0.get(h1); }");
/*fuzzSeed-221406266*/count=618; tryItOut("\"use strict\"; /*infloop*/for(var y = (4277); ((function sum_indexing(dpckec, huuvkh) { ; return dpckec.length == huuvkh ? 0 : dpckec[huuvkh] + sum_indexing(dpckec, huuvkh + 1); })(/*MARR*/[0.1, 0.1, new String(''), 0.1, new String(''), 0.1, new String(''), new String('')], 0)); x ** NaN) print(y);");
/*fuzzSeed-221406266*/count=619; tryItOut("mathy3 = (function(x, y) { return Math.sinh(((( ~ ( ! Math.fround(( + y)))) | 0) | 0)); }); testMathyFunction(mathy3, [(new String('')), 0, ({toString:function(){return '0';}}), (new Boolean(false)), [0], ({valueOf:function(){return '0';}}), (new Number(0)), /0/, 1, '/0/', '', 0.1, objectEmulatingUndefined(), -0, [], true, '\\0', NaN, ({valueOf:function(){return 0;}}), false, '0', undefined, (new Boolean(true)), (new Number(-0)), (function(){return 0;}), null]); ");
/*fuzzSeed-221406266*/count=620; tryItOut("/*RXUB*/var r = r2; var s = \"\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\n\\u001f\\n\\u001f\\n\\u001f\\n\\u001f\\n\\u001f\\n\\u001f\\n\\u001f\\n\\u001f\\n\\u001f\\n\\u001f\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\u135c\\n\\n\\n\\n\\u001f\\n\\n\\n\\u001f\\n\\n\\n\\u001f\"; print(s.replace(r, 'x', \"im\")); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=621; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( + Math.sin(( + ( + (( + ((((x >>> 0) >= (y >>> 0)) >>> 0) ? (Math.pow((y | 0), (mathy0((0.000000000000001 >>> 0), (x >>> 0)) | 0)) | 0) : ( ! (x | 0)))) , ( + Math.min(( ~ y), (Math.fround(((-0x07fffffff ** ( + x)) >>> 0)) ? Math.fround(y) : Math.fround(y)))))))))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53-2), -1/0, -0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -0, -0x07fffffff, 0x100000001, 0x080000000, Number.MIN_VALUE, 0, 1, -(2**53), 42, 2**53+2, 2**53-2, 0/0, Math.PI, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=622; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Math.PI, -0x100000001, 0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -0, -Number.MIN_SAFE_INTEGER, 0/0, 1, 1/0, -0x100000000, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 0x100000000, 0x07fffffff, -(2**53), -(2**53+2), Number.MIN_VALUE, 2**53+2, -0x07fffffff, -0x080000000, -0x0ffffffff, -1/0, 42, -0x080000001]); ");
/*fuzzSeed-221406266*/count=623; tryItOut("mathy5 = (function(x, y) { return Math.fround((Math.fround(Math.acos(((Math.min(-Number.MAX_SAFE_INTEGER, ( + ( ! Math.fround(Math.fround(x))))) >>> 0) ** Math.fround((mathy2((y | 0), (-0x07fffffff >>> 0)) | 0))))) >>> ( + ( - ( + ((( + ( + (((Number.MAX_VALUE | 0) >= (y | 0)) | 0))) % (Math.hypot(1, x) | 0)) | 0)))))); }); testMathyFunction(mathy5, [0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000001, -(2**53+2), 2**53+2, -1/0, Math.PI, 1/0, Number.MIN_VALUE, 2**53-2, 0/0, 0x100000000, -0x07fffffff, -0x0ffffffff, 0x0ffffffff, 42, 0x080000001, 0, -(2**53), 1, Number.MAX_VALUE, -0, -0x080000000, 0x080000000, 0x100000001, 2**53, -0x080000001, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=624; tryItOut("h0.toSource = (function() { for (var j=0;j<10;++j) { f2(j%3==1); } });v2 = evalcx(\"function f1(i0)  { yield  /x/  } \", g2);");
/*fuzzSeed-221406266*/count=625; tryItOut("\"use strict\"; /*hhh*/function ekfmbh(NaN, {(x--), \u3056: []}){/*tLoop*/for (let y of /*MARR*/[Infinity, Infinity, (-1/0), Infinity, x, x, Infinity, (-1/0), (-1/0), Infinity, Infinity, x, (-1/0), Infinity, x, x, x, x, x, x, Infinity, x, (-1/0), Infinity, x, x, (-1/0), Infinity, x, Infinity, x, Infinity, x, (-1/0), Infinity, x, (-1/0), Infinity, (-1/0)]) { f1 = x; }}/*iii*/print(ekfmbh);");
/*fuzzSeed-221406266*/count=626; tryItOut("a0 = r0.exec(s2);");
/*fuzzSeed-221406266*/count=627; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.pow(Math.log10(( - Math.fround(mathy2(Math.fround((((-0x07fffffff | 0) ? (mathy3(((x | 0) , x), y) | 0) : ( + (((y | 0) >>> y) >>> 0))) | 0)), Math.fround(Math.round(mathy3(y, mathy1(y, y)))))))), Math.fround(Math.fround(Math.ceil((Math.max((Math.min(x, Math.fround(Math.cos(( ~ Math.fround(( - ( + y))))))) >>> 0), (Math.log1p(( ! ( + y))) >>> 0)) >>> 0))))) >>> 0); }); testMathyFunction(mathy5, [-1/0, Math.PI, -(2**53+2), -0x07fffffff, 0x080000001, 1, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), Number.MIN_SAFE_INTEGER, 0, 2**53+2, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, -(2**53-2), -0x100000001, -0x0ffffffff, 0.000000000000001, 2**53, -Number.MAX_VALUE, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, 42, 0/0, 0x0ffffffff, 2**53-2, 0x080000000, Number.MAX_VALUE, 0x07fffffff, 0x100000001, 0x100000000]); ");
/*fuzzSeed-221406266*/count=628; tryItOut("/*ADP-3*/Object.defineProperty(this.a2, 17, { configurable: false, enumerable: ((p={}, (p.z = ({\"17\": undefined }))())((window = new RegExp(\"(?=^|$|(^[^\\\\cV\\\\D\\\\S]|(?=.*))(?!(?:\\\\B))(\\\\B)+?^|\\\\S\\u00ab|([^\\\\s\\u00f1][^])[^\\\\w\\\\b-\\\\\\u00e2`]\\\\2?)\", \"gim\")) ? this.valueOf(\"number\") : x)), writable: (yield x), value: b0 });");
/*fuzzSeed-221406266*/count=629; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var asin = stdlib.Math.asin;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+/*FFI*/ff((((((((((0xc1489370)) & ((0xc7c92891))) % (imul((0x18ba4246), (-0x8000000))|0)) << (((-0x8000000) ? (0x5d9c4bf8) : (0x5c557f20))+((-0x8000000) == (0x16995e47))-((0x28c079ba) != (0x0)))) != (((((0xe777f039))>>>((0x6bb2bacb))) / (0x80d412c0))|0))) ^ ((0x147df22a)+(0x9e35b858)+((0x35edb03c) ? (-0x8000000) : (0xfb739519))))), ((~~(d1))), ((d1)), ((d1)), ((((-0x8000000)) << ((0xdccd4448)))), ((((0xc9b9d75e) % (0x5cc2a40f)) & ((0xfca94434)-(0x1ad76383)))), ((d1))));\n    d0 = (((d1)) * (((0x8db876ce) ? (d1) : (d0))));\n    {\n      d1 = (d0);\n    }\n    d1 = ((((/*FFI*/ff(((Infinity)), (((0xf1e8b5c) ? (d1) : (+(0x0)))), ( /* Comment */x), ((((0xf82186d3)) << ((0xffffffff)))), ((0x322fd058)), ((~~(d1))), ((((0x75fd507f)) << ((0xfa84a0de)))), ((-295147905179352830000.0)), ((-1.00390625)), ((6.044629098073146e+23)), ((-1073741823.0)))|0))) % ((d0)));\n    d0 = (+asin(((+(-1.0/0.0)))));\n    d1 = (18014398509481984.0);\n    {\n      {\n        d1 = (d1);\n      }\n    }\n    d1 = (NaN);\n    return (((Int16ArrayView[2])))|0;\n  }\n  return f; })(this, {ff: Math.max((4277), 27)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000001, Number.MIN_VALUE, 2**53-2, 0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1/0, -(2**53-2), 2**53+2, -1/0, -Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, 0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, 2**53, -0, -(2**53), 0x100000001, -0x100000001, Math.PI, 0.000000000000001, -0x080000000, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -0x100000000, -0x080000001]); ");
/*fuzzSeed-221406266*/count=630; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3|((?=(?!(\\\\B\\\\n+|$)*?)))\", \"g\"); var s = \"a\\n  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*  \\uad581\\n*\"; print(uneval(s.match(r))); ");
/*fuzzSeed-221406266*/count=631; tryItOut("for (var p in h1) { try { i1 = e2.values; } catch(e0) { } try { i2.send(g1); } catch(e1) { } try { for (var v of o1.i1) { try { s2 = s0.charAt(({valueOf: function() { /*RXUB*/var r = /((\\2)|\\b|\\cT|.|(?!([^])){4,}(?!${3}){2,5}.{0})/g; var s = \"\"; print(s.search(r)); return 8; }})); } catch(e0) { } try { Array.prototype.pop.call(a1); } catch(e1) { } try { v1 = g0.runOffThreadScript(); } catch(e2) { } s2 += 'x'; } } catch(e2) { } Object.defineProperty(this, \"t1\", { configurable: true, enumerable: true,  get: function() {  return new Int8Array(new (Symbol.prototype.toString)( \"\" , undefined) ? x = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"(?=(?=\\u00bc*?\\\\B*?)+)*\", \"g\")), mathy5, function shapeyConstructor(jqfohj){\"use asm\"; if (undefined) for (var ytqyjgooc in this) { }this[true] = this;this[true] = ({/*TOODEEP*/});if (jqfohj) delete this[\"toISOString\"];Object.defineProperty(this, true, ({get: function(y) { this.g2.offThreadCompileScript(\"Array.prototype.unshift.call(a0, a1, i0, p2);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (y % 7 != 6), catchTermination:  /x/g  })); }, set: (( /x/g ).bind).call, enumerable: true}));delete this[\"15\"];Object.preventExtensions(this);if ( '' ) delete this[\"length\"];return this; }) : x); } }); }");
/*fuzzSeed-221406266*/count=632; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=633; tryItOut("testMathyFunction(mathy5, [1.7976931348623157e308, 1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -0, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, 0x080000000, 0x0ffffffff, 2**53+2, 0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 0x100000000, 0/0, 2**53, 42, 1, 0x07fffffff, -(2**53+2), -Number.MIN_VALUE, -0x100000001, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, -0x080000000, -1/0, Math.PI, -(2**53)]); ");
/*fuzzSeed-221406266*/count=634; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + mathy1(((Math.fround(Math.fround((y - Math.fround(( ~ x))))) ^ Math.atan2(( + Math.imul(((Math.atan2(y, y) > Math.tan(Number.MAX_SAFE_INTEGER)) | 0), ( + Math.imul((y | 0), Number.MAX_SAFE_INTEGER)))), ( + Math.pow(x, Math.pow(( ! Number.MIN_VALUE), x))))) >>> 0), (Math.min(( - x), ((mathy1(mathy1(y, Math.fround(x)), mathy2(x, Math.atan2(y, (y != y)))) ? Math.fround((mathy0(x, Math.max(x, -(2**53-2))) >>> 0)) : (Math.pow(x, x) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 42, 2**53, -0x100000001, 2**53-2, 0x080000000, -0x080000001, -Number.MIN_VALUE, 0, -Number.MAX_VALUE, 2**53+2, 1, -0x07fffffff, 0/0, -0x080000000, -0, -(2**53+2), -(2**53-2), -(2**53), -0x100000000, 0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, 0x080000001, 0x100000001, -0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=635; tryItOut("\"use strict\"; /*vLoop*/for (jhuhrl = 0; jhuhrl < 41; ++jhuhrl) { let y = jhuhrl; /*infloop*/for(let (e) (\n(4277));  /* Comment */[,,].throw((makeFinalizeObserver('tenured'))); (yield /(?!(?:\\2)?)*?/gyim = y , y)) var c = (yield null / /\\B|\\b\\cI[]*|[^](?=(?!\\b{32769,})\\S\\xE9)|(?!\\W^|[^]+?*)?/g);{} } ");
/*fuzzSeed-221406266*/count=636; tryItOut("g0.s1 += s0;function z(e, e = (false ?  /x/g  : window) >>> []) { return ({\"12\": new (let (e=eval) e)(x, (w)), \"-12\": x }) } y;");
/*fuzzSeed-221406266*/count=637; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-221406266*/count=638; tryItOut("/*vLoop*/for (lvjgmj = 0, (4277), throw window ? d : this; lvjgmj < 42 && ((x instanceof x)); ++lvjgmj) { const b = lvjgmj; /*RXUB*/var r = r1; var s = \"_\\n\\n_\\n_\\n\"; print(s.split(r));  } ");
/*fuzzSeed-221406266*/count=639; tryItOut("v2 = -0;");
/*fuzzSeed-221406266*/count=640; tryItOut("v2 = (b2 instanceof this.p2);");
/*fuzzSeed-221406266*/count=641; tryItOut("p2.__proto__ = m1;");
/*fuzzSeed-221406266*/count=642; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.acos(Math.fround(Math.acosh(((((( + Math.fround(x)) >>> 0) >>> 0) & (( + Math.atan2(( + 0x100000001), (x | 0))) >>> 0)) >>> 0))))) ? Math.fround(( - Math.fround((( - (( + ( + (x !== Math.fround(x)))) >>> 0)) ? x : x)))) : (Math.min(Math.pow(((( - (Math.min(Math.fround(x), ( + ((y | 0) < (y >>> 0)))) | 0)) | 0) | 0), (Math.imul(0x07fffffff, (Math.trunc(( + y)) >>> 0)) | 0)), Math.tan(Math.sin((Math.imul(Math.fround((Math.fround(y) ? y : Math.fround(y))), y) | 0)))) > (Math.imul(((( ~ (y | 0)) | 0) | 0), -0x07fffffff) | 0))); }); testMathyFunction(mathy0, [0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, 0/0, 0x07fffffff, -(2**53-2), 2**53+2, Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 0x100000000, 42, -0x080000000, 0x080000001, 1, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0, Math.PI, Number.MIN_VALUE, 2**53-2, 0, -0x0ffffffff, -0x100000001, -(2**53), 1/0, -0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=643; tryItOut("v1 = Object.prototype.isPrototypeOf.call(s0, v0);/*RXUB*/var r = this.r1; var s = s0; print(uneval(s.match(r))); ");
/*fuzzSeed-221406266*/count=644; tryItOut("var oijabi = new ArrayBuffer(4); var oijabi_0 = new Int32Array(oijabi); oijabi_0[0] = -5; var oijabi_1 = new Int8Array(oijabi); oijabi_1[0] = 20; a2 = [];/*MXX2*/g0.Map.prototype.size = o2;throw  /x/g  ? x : this;");
/*fuzzSeed-221406266*/count=645; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=^{3}){3,}\", \"im\"); var s = \"\\n\\n\\n\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=646; tryItOut("b2[\"12\"] = g2.m2;");
/*fuzzSeed-221406266*/count=647; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.max((( - mathy3((Math.round(( ! y)) >>> 0), (Math.hypot(((( - ( + x)) >>> 0) >> (( - 0/0) >>> 0)), ( ~ Math.fround(-0x100000001))) >>> 0))) >>> 0), ( + Math.atanh(mathy1((Math.asinh((y | 0)) | 0), ( + Number.MIN_SAFE_INTEGER))))); }); ");
/*fuzzSeed-221406266*/count=648; tryItOut("/*vLoop*/for (let lxgjmk = 0; lxgjmk < 3; ++lxgjmk) { a = lxgjmk; /*RXUB*/var r = /(?!(?!\\1*?))/yim; var s = \"\"; print(r.test(s));  } ");
/*fuzzSeed-221406266*/count=649; tryItOut("g2.offThreadCompileScript(\"function f0(m0)  { yield \\\"\\\\uE548\\\" } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: Object.defineProperty(d, \"arguments\", ({get: (\"\\u103C\").apply, set:  /x/ , configurable: false, enumerable: true})).throw(Math.atanh(18)), sourceIsLazy: false, catchTermination: (x % 5 == 3) }));");
/*fuzzSeed-221406266*/count=650; tryItOut("with(NaN , x){/*RXUB*/var r = r2; var s = s0; print(uneval(s.match(r))); print(r.lastIndex); for (var v of e1) { try { /*RXUB*/var r = r1; var s = \" a \\n  a \"; print(s.search(r)); print(r.lastIndex);  } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(a1, i1); } catch(e1) { } try { print( /x/g ); } catch(e2) { } o2.a0.splice(-5, 5); } }");
/*fuzzSeed-221406266*/count=651; tryItOut("\"use strict\"; if( /x/ ) { if (new RegExp(\"\\\\1\", \"im\")) {(undefined); } else {print([z1,,]);( \"\" ); }}");
/*fuzzSeed-221406266*/count=652; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + ((((( ! Math.fround(0.000000000000001)) && ((Math.imul(Math.hypot((x >>> 0), x), ( + Math.atan2(x, Math.min((x | 0), 2**53)))) >= Math.fround((x | Math.fround(Math.fround((Math.fround(x) , Math.fround(-0))))))) | 0)) >>> 0) >>> 0) | ( + (mathy2((( + Math.atan2(y, ( + ( - y)))) >>> 0), (x >>> 0)) >>> 0)))) | 0); }); testMathyFunction(mathy4, [0x100000000, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -0, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, 0x0ffffffff, -0x080000000, 0, 0/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), -1/0, 1, 0x080000001, 42, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), -0x100000000, Number.MIN_VALUE, 0x080000000, 2**53, 2**53+2, -(2**53+2), -0x100000001, Math.PI]); ");
/*fuzzSeed-221406266*/count=653; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.exp(Math.fround(( ! (Math.fround((x | 0)) | 0))))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -(2**53), -0x100000001, 0x100000000, 0/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, -0, 0x080000000, 1.7976931348623157e308, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, Math.PI, 0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, 0x100000001, 0.000000000000001, -0x0ffffffff, 1/0, -Number.MAX_VALUE, 2**53, 42, -(2**53-2), 2**53-2, 0x080000001, 1]); ");
/*fuzzSeed-221406266*/count=654; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 67108865.0;\n    var i3 = 0;\n    return ((((0xa1ba*(i3)) >> (0x8f573*([[]] ? \"\\u6670\" : w)))))|0;\n  }\n  return f; })(this, {ff: (((true = this.__defineSetter__(\"x\", (function(x, y) { \"use strict\"; return x; })))).__defineSetter__(\"x\", (Function).bind((false)(function ([y]) { }, a))))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [2**53+2, -0x080000000, 0x100000001, 0x080000000, 2**53, 42, 0.000000000000001, Number.MIN_VALUE, -(2**53+2), 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, -0, 1.7976931348623157e308, 2**53-2, 1, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, -0x080000001, 0x0ffffffff, 1/0]); ");
/*fuzzSeed-221406266*/count=655; tryItOut("\"use strict\"; t0 = new Int16Array(a1);");
/*fuzzSeed-221406266*/count=656; tryItOut("mathy0 = (function(x, y) { return Math.acos(((Math.log10(Math.sqrt(x)) < Math.cos(Math.fround((( ~ y) === x)))) > ( + (Math.max((Math.pow((Math.atan2((Math.fround((x ** Math.fround(x))) >>> 0), (( ~ 2**53-2) >>> 0)) >>> 0), Math.max(((y + (x >>> 0)) | 0), (x >> x))) >>> 0), (( - x) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[[], [],  /x/ , [],  /x/ , [],  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , [],  /x/ , [],  /x/ , [], [],  /x/ , [],  /x/ ,  /x/ , [], [], [],  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , [],  /x/ ,  /x/ ,  /x/ , [], [], []]); ");
/*fuzzSeed-221406266*/count=657; tryItOut("mathy1 = (function(x, y) { return Math.asin(( + (((Math.clz32(x) , -(2**53)) | 0) ? -Number.MAX_SAFE_INTEGER : Math.min(( ~ ( + x)), (( + Math.pow(x, ( + Math.max(( + x), y)))) | ( + Math.hypot(Math.fround(1.7976931348623157e308), Math.fround(y)))))))); }); ");
/*fuzzSeed-221406266*/count=658; tryItOut("this.v0 = evalcx(\"/* no regression tests found */\", g0);");
/*fuzzSeed-221406266*/count=659; tryItOut("mathy4 = (function(x, y) { return ( + (((Math.tanh(Math.abs(Math.fround(y))) | 0) >> Math.max(-Number.MAX_SAFE_INTEGER, (( + Math.max((Math.log(42) | 0), Math.fround(y))) >>> 0))) | 0)); }); testMathyFunction(mathy4, [0/0, 2**53, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, 42, Number.MAX_VALUE, 0x080000001, -(2**53-2), -0x080000001, -(2**53+2), -0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 1, -Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, -0, 0x100000000, 0x0ffffffff, -1/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, -(2**53), 0x080000000, 0.000000000000001, 1/0]); ");
/*fuzzSeed-221406266*/count=660; tryItOut("\"use strict\"; this.v1 = false;");
/*fuzzSeed-221406266*/count=661; tryItOut("\"use strict\"; \"use strict\"; /*MXX3*/this.g1.g2.Array.of = g1.Array.of;");
/*fuzzSeed-221406266*/count=662; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.sin(Math.fround(Math.min(Math.fround(( + ((Math.log2((-Number.MAX_VALUE ? 2**53-2 : Math.tan(Math.fround(-1/0)))) | 0) >>> mathy0((-0x07fffffff | 0), (Math.exp(Math.asin(0x100000001)) >>> 0))))), ( ~ ( + Math.hypot(( + ( ! (y >>> 0))), ( + y)))))))); }); testMathyFunction(mathy1, [-0x100000001, 0x07fffffff, 0x100000001, 0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0, -(2**53-2), 0x100000000, -Number.MIN_VALUE, 42, Number.MIN_VALUE, -(2**53), -1/0, -0x080000000, 0x080000000, 0.000000000000001, 1/0, Math.PI, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0/0, 0x080000001, 2**53-2, -0, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -0x100000000, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=663; tryItOut("testMathyFunction(mathy0, [-0, (new Boolean(true)), (new Number(-0)), NaN, [0], 0, false, objectEmulatingUndefined(), 1, true, 0.1, '', (new Boolean(false)), (new Number(0)), ({valueOf:function(){return '0';}}), (function(){return 0;}), undefined, '\\0', ({valueOf:function(){return 0;}}), (new String('')), [], null, '/0/', '0', /0/, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-221406266*/count=664; tryItOut("mathy5 = (function(x, y) { return Math.imul((Math.atan2(Math.fround(Math.log2(Math.trunc((Math.pow(( + Math.atan2(x, y)), x) >>> 0)))), ( - Number.MAX_VALUE)) | 0), (((Math.fround((x >> Math.fround((((((((y >>> 0) != (y >>> 0)) >>> 0) >>> 0) ^ (0 >>> 0)) >>> 0) === 0x0ffffffff)))) | 0) !== ((Math.fround(Math.pow((((x >>> 0) & (x >>> 0)) >>> 0), y)) ? y : ( ~ Math.log2(Math.asin(y)))) % mathy3(-1/0, y))) >>> 0)); }); testMathyFunction(mathy5, [1, 0x100000001, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, -0, -0x080000001, -(2**53), 2**53+2, 1.7976931348623157e308, 0.000000000000001, -1/0, 42, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, -0x07fffffff, Number.MAX_VALUE, -(2**53+2), -(2**53-2), -0x0ffffffff, 0/0, 2**53-2, Math.PI, -0x100000001, Number.MIN_VALUE, 0x0ffffffff, 1/0, 0x080000000, 0x080000001]); ");
/*fuzzSeed-221406266*/count=665; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53-2), -0, 0x07fffffff, 2**53, Number.MIN_VALUE, 0x0ffffffff, Math.PI, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -0x080000001, 42, 2**53+2, 1, 1/0, -Number.MIN_VALUE, 0x080000001, -0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, -1/0, -(2**53), -Number.MAX_VALUE, 2**53-2, 1.7976931348623157e308, -0x100000001, -0x100000000, 0x100000000]); ");
/*fuzzSeed-221406266*/count=666; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=667; tryItOut("/*RXUB*/var r = r1; var s = \"\\uaa9ea_\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=668; tryItOut("h0.iterate = f0;\nprint(x);\n");
/*fuzzSeed-221406266*/count=669; tryItOut("\"use strict\"; o2.e0.toSource = (function() { for (var j=0;j<4;++j) { o1.f2(j%3==1); } });");
/*fuzzSeed-221406266*/count=670; tryItOut("testMathyFunction(mathy2, [0x07fffffff, 1/0, -0x100000001, 0x100000001, 42, -0x080000001, -Number.MAX_VALUE, -0, -0x0ffffffff, 0x0ffffffff, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, 1, 0/0, 2**53-2, 0x080000000, -0x07fffffff, -0x080000000, -0x100000000, -(2**53), -1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=671; tryItOut("M: for  each(let w in this.__defineGetter__(\"x\", x => \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d1);\n    d0 = (d0);\n    return +(((((d0)) * ((d0))) + (((d1)) - ((Float32ArrayView[((0xf93edbdc)-(0xff8d5050)+(!((0x646dd25e) > (0x20fa9cc6)))) >> 2])))));\n  }\n  return f;)) {\u000ch0.getOwnPropertyNames = (function(j) { if (j) { try { p1.valueOf = (function() { try { v2 = t2.byteLength; } catch(e0) { } o2.o1 = h1.__proto__; return b1; }); } catch(e0) { } try { p0.__iterator__ = (function() { try { g2.v0 = evalcx(\"/*MXX3*/g0.g0.Function.prototype = g0.Function.prototype;\", g2.g1); } catch(e0) { } try { v0 = (this.b1 instanceof s0); } catch(e1) { } print(this.a2); return this.v0; }); } catch(e1) { } try { b0 + ''; } catch(e2) { } a1.sort(f2, v1, v1); } else { try { v2 = a2.length; } catch(e0) { } v1 = g2.eval(\"function g0.f2(m0)  { \\\"use strict\\\"; print(function ([y]) { }); } \"); } });/*RXUB*/var r = /\\u8FaA/m; var s = \"\\u8f8a\"; print(uneval(s.match(r)));  }");
/*fuzzSeed-221406266*/count=672; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((0xe542c680)))|0;\n    d0 = (17592186044417.0);\n    d0 = (+/*FFI*/ff());\n    {\n      d0 = (d0);\n    }\n    return ((((+(1.0/0.0)) < (-((-1.5111572745182865e+23))))-(0x89d74ebc)))|0;\n  }\n  return f;print(x);\n })(this, {ff: /*wrap1*/(function(){ \"use strict\"; v0 = Object.prototype.isPrototypeOf.call(v0, s0);return /*wrap2*/(function(){ var rvafso = this; var rxwtms = ((function(x, y) { return x; })).apply; return rxwtms;})()})().prototype.throw(x)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Math.PI, -Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0x080000000, -(2**53+2), -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 0x0ffffffff, -0x100000001, 0x080000001, 0, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -0, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 2**53-2, 42, 1, 0x07fffffff, -Number.MIN_VALUE, -1/0, -0x07fffffff, 1/0, 2**53]); ");
/*fuzzSeed-221406266*/count=673; tryItOut("with({}) { let(x) { return timeout(1800);} } ");
/*fuzzSeed-221406266*/count=674; tryItOut("\"use strict\"; /*RXUB*/var r = g2.g0.g0.r1; var s = this.o2.s1; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=675; tryItOut("\"use strict\"; /*infloop*/for(\u3056 in window) f1 + '';");
/*fuzzSeed-221406266*/count=676; tryItOut("\"use strict\"; { void 0; void gc(); }");
/*fuzzSeed-221406266*/count=677; tryItOut("a1 = g1.objectEmulatingUndefined();");
/*fuzzSeed-221406266*/count=678; tryItOut("Array.prototype.unshift.call(a0, this.o2, t2, (4277), f0, this.h2, e1);");
/*fuzzSeed-221406266*/count=679; tryItOut("mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return (((( ! Math.fround(( ~ Math.min(y, y)))) | 0) | (( + Math.max(((-Number.MAX_SAFE_INTEGER * ((((mathy2((Math.sin((y | 0)) >>> 0), y) >>> 0) >>> 0) << (x >>> 0)) >>> 0)) >>> 0), (Math.fround((Math.pow((Math.min(y, y) >>> 0), (Math.hypot(y, Math.fround(x)) | 0)) <= Math.fround(1))) ? (((y >>> 0) ? ((mathy1(y, (-0x07fffffff - x)) | 0) >>> 0) : (( - ( - mathy1((0/0 >>> 0), -Number.MIN_SAFE_INTEGER))) >>> 0)) >>> 0) : Math.fround(( + ( ! ( + (Math.sqrt(y) | 0)))))))) | 0)) | 0); }); testMathyFunction(mathy3, [[], (new Number(-0)), objectEmulatingUndefined(), false, 0.1, (new Boolean(true)), ({valueOf:function(){return '0';}}), null, '', 0, -0, [0], (new String('')), '/0/', (function(){return 0;}), ({valueOf:function(){return 0;}}), 1, NaN, true, /0/, '\\0', undefined, (new Number(0)), ({toString:function(){return '0';}}), '0', (new Boolean(false))]); ");
/*fuzzSeed-221406266*/count=680; tryItOut("\"use strict\"; Object.defineProperty(this, \"v0\", { configurable: true, enumerable: false,  get: function() {  return evaluate(\"function f2(this.v0) let (a) (4277)\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 37 == 13), noScriptRval: false, sourceIsLazy: (x % 4 == 3), catchTermination: (x % 2 == 1) })); } });");
/*fuzzSeed-221406266*/count=681; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=682; tryItOut("g0.v2 = evalcx(\"v1 = new Number(o0);\", g0);");
/*fuzzSeed-221406266*/count=683; tryItOut("g2.s2 = s0.charAt(3);");
/*fuzzSeed-221406266*/count=684; tryItOut("v0 = evaluate(\"let v2 = g1.eval(\\\"((function factorial_tail(okdxfh, rzzbrd) { ; if (okdxfh == 0) { String.prototype.sup; return rzzbrd; } ; return factorial_tail(okdxfh - 1, rzzbrd * okdxfh);  })(1, 1))(window = Proxy.createFunction(({/*TOODEEP*/})(false), (let (e=eval) e), function shapeyConstructor(otyfns){Object.defineProperty(this, \\\\\\\"now\\\\\\\", ({enumerable: \\\\\\\"\\\\\\\\u308D\\\\\\\"}));if ( \\\\\\\"\\\\\\\" ) { o0.i1.send(p2); } for (var ytqepggnj in this) { }this[\\\\\\\"has\\\\\\\"] = new String('');Object.preventExtensions(this);if (otyfns) this[\\\\\\\"x\\\\\\\"] = decodeURIComponent;if (otyfns) this[\\\\\\\"wrappedJSObject\\\\\\\"] =  \\\\\\\"\\\\\\\" ;this[\\\\\\\"call\\\\\\\"] = new Number(1.5);for (var ytqlxkpuz in this) { }Object.freeze(this);return this; }), eval)\\\");\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-221406266*/count=685; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!([^\\\\xb0-\\uad83\\\\x60-\\\\u0077])*)(((?:(?=[^\\\\l-\\\\u4f55\\\\u00bc]+))))+?\", \"y\"); var s = \"\\u00b1\\u1d0b\\u1d0b\\u1d0b\\u1d0b\\u61e2\\u1d0bLddddddd\"; print(s.match(r)); function a(eval, c) { \"use strict\"; /*RXUB*/var r = (Int16Array()); var s = \"\\ua596\\n\"; print(s.replace(r, String.prototype.substr)); print(r.lastIndex);  } Array.prototype.forEach.call(this.a1, f1, g0.v2, p0, g0);");
/*fuzzSeed-221406266*/count=686; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.hypot(Math.atanh((( ~ x) >>> 0)), ((( ~ (( ! (Math.min(( + (( ~ -Number.MIN_SAFE_INTEGER) >>> 0)), ( + ( + mathy2(x, ( + Math.acosh(y)))))) >>> 0)) | 0)) | 0) | 0)); }); testMathyFunction(mathy5, [-(2**53), 0x0ffffffff, 0, 42, 1, -0x07fffffff, -0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0x100000000, -(2**53-2), 2**53, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, 2**53-2, Math.PI, 0x080000001, 0x07fffffff, -0x080000000, -0x080000001, -Number.MAX_VALUE, 0/0, 2**53+2, Number.MIN_SAFE_INTEGER, -0, 0x100000001]); ");
/*fuzzSeed-221406266*/count=687; tryItOut("\"use strict\"; i1 = t2[v2];");
/*fuzzSeed-221406266*/count=688; tryItOut("a2 + g1.h2;");
/*fuzzSeed-221406266*/count=689; tryItOut("");
/*fuzzSeed-221406266*/count=690; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.acos(( ~ (Math.trunc(((( ! (x >>> 0)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy3, [1, 0x080000000, -(2**53-2), -1/0, -0x080000000, 0, 2**53-2, 2**53, -Number.MIN_VALUE, -0x100000000, -(2**53+2), Number.MIN_VALUE, 42, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, -0x080000001, -0x0ffffffff, 2**53+2, -0x100000001, 0x100000001, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, -(2**53), 1.7976931348623157e308, 0x100000000]); ");
/*fuzzSeed-221406266*/count=691; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new Boolean(false)), [], NaN, '0', objectEmulatingUndefined(), [0], '/0/', (new Boolean(true)), 0, undefined, (new Number(0)), (new String('')), ({valueOf:function(){return 0;}}), 1, /0/, null, false, '\\0', (function(){return 0;}), 0.1, true, -0, (new Number(-0)), ({toString:function(){return '0';}}), '', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-221406266*/count=692; tryItOut("\"use strict\"; /*oLoop*/for (var uwqaty = 0, c = eval(\"( - (Math.fround(Math.atan(x)) | 0))\", eval(\"\\\"use strict\\\"; h1.getPropertyDescriptor = this.f0;\", function(id) { return id })); uwqaty < 14; ++uwqaty) { Array.prototype.reverse.apply(a0, [e0, p1]); } ");
/*fuzzSeed-221406266*/count=693; tryItOut("\"use strict\"; ;");
/*fuzzSeed-221406266*/count=694; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((((( + ( + (( + y) / Number.MIN_SAFE_INTEGER))) ? Math.fround(Math.clz32(x)) : (y | 0)) | 0) >>> ( + Math.imul(y, ( + ( + Math.pow(x, x)))))) >>> ((Math.hypot((( + (( + ( + Math.atan2(y, y))) >= ( + Math.PI))) | 0), (( ! Math.atanh(y)) | 0)) | 0) << ((Math.pow((( + ( - ( + x))) >>> 0), (y >>> 0)) < Math.atan2(Math.sqrt((y >>> 0)), x)) > (( ~ (Math.fround(Math.atan2((((y >>> 0) & (x >>> 0)) >>> 0), Math.fround((-1/0 ? ( + Math.fround(( ! ( + y)))) : x)))) | 0)) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[[], false, new String('q'), [1], false,  'A' , false, false, [], false, [1], [1], new String('q'), new String('q'), false, false, false, new String('q'), new String('q'), [1], [], new String('q'), [], [], [1], [1], [], new String('q'), [1], new String('q'), false,  'A' , false, new String('q'), [1], false,  'A' ,  'A' , [], [1], false,  'A' , false,  'A' , [], new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'),  'A' , new String('q'), [1], [1], [], [1], false,  'A' , [1], false, [], new String('q'), new String('q'), new String('q'), false, false, [1], new String('q'), new String('q'), [], false, false, false,  'A' , [], new String('q'), [1], [], [], new String('q'), new String('q'), false, [1], [1]]); ");
/*fuzzSeed-221406266*/count=695; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    (Int8ArrayView[((i2)) >> 0]) = ((0x9692e893));\n    d0 = (-1048577.0);\n    switch ((((0x673e9a11)+(0x678eab52)-(0xfc130a9f)) << ((i3)+((0x1b362692) != (-0x1046bba))))) {\n      case -1:\n        (Float32ArrayView[0]) = ((1.0));\n        break;\n      case -2:\n        return +((d0));\n        break;\n      case 0:\n        (Int16ArrayView[4096]) = (((i3) ? (0x3f3066f0) : ((+(-1.0/0.0)) < (-68719476737.0)))+(i3));\n        break;\n      case 1:\n        i3 = (i2);\n        break;\n      case -2:\n        i2 = (i3);\n        break;\n      case 0:\n        (Float64ArrayView[4096]) = ((d1));\n        break;\n      case -1:\n        d1 = (+atan2(((Float32ArrayView[1])), ((-4097.0))));\n        break;\n      case 0:\n        {\n          /*FFI*/ff(((abs((~~(d1)))|0)), ((134217728.0)), ((~~(4398046511105.0))), ((get)));\n        }\n        break;\n      default:\n        (Int8ArrayView[((!((((0x8207a04a)) & ((0xfb5865a4)))))+(0x47cb2ad1)-(i3)) >> 0]) = ((/*FFI*/ff(((d0)), ((((!(0xf9cd91af))) & ((((0x7a6b6ef0) / (0x4cab477)) & (-(0x3064491e))) / (((0xfecb32cd)+(0xfb5a061a)) >> ((0x764e9836)-(0x19b50e36)))))), ((~~(-17179869183.0))), ((d0)), ((0x1d598b7b)), ((d1)), ((imul((0xbfcbf346), (0xfafb6b8c))|0)), ((-((70368744177665.0)))), ((4.835703278458517e+24)), ((-2097153.0)), ((17179869185.0)), ((36028797018963970.0)), ((8796093022207.0)), ((1.001953125)))|0)+(i2));\n    }\n    {\n      i2 = (i2);\n    }\n    d1 = (d1);\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: ++arguments}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, -(2**53+2), 0x0ffffffff, -0, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), Number.MIN_VALUE, -1/0, 0.000000000000001, 2**53, Math.PI, -0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1, -(2**53-2), 0x080000000, 42, 2**53-2, -0x0ffffffff, 0x100000000, 2**53+2, 0x080000001, -0x080000001, 0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=696; tryItOut("s2 = s2.charAt(14);");
/*fuzzSeed-221406266*/count=697; tryItOut("\"use strict\"; print(s0);");
/*fuzzSeed-221406266*/count=698; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return ( ! Math.asinh((( + (x >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-(2**53+2), 0, 0/0, -0x100000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -0, 2**53-2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 1/0, -0x07fffffff, -0x080000001, 2**53, Number.MAX_VALUE, 42, -0x0ffffffff, -(2**53-2), 0.000000000000001, 2**53+2, -0x080000000, -Number.MAX_VALUE, Math.PI, 0x100000000, -Number.MIN_VALUE, -(2**53), 0x07fffffff, 0x080000000, -1/0, 0x100000001]); ");
/*fuzzSeed-221406266*/count=699; tryItOut("for (var p in this.p2) { Object.defineProperty(this, \"s0\", { configurable: (/*FARR*/[[,,z1], .../*FARR*/[...[], , []], ...Float64Array].some(eval, ((1 for (x in []))).call(this, length, -12))) >>> (makeFinalizeObserver('tenured')), enumerable: x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: encodeURIComponent, defineProperty: arguments[-4], getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return true; }, get: Set.prototype.forEach, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(String.prototype.trim( '' )), x),  get: function() {  return new String(o1); } }); }");
/*fuzzSeed-221406266*/count=700; tryItOut("\"use strict\"; /*vLoop*/for (let cvoxnv = 0; cvoxnv < 21; ++cvoxnv) { const e = cvoxnv; this.v1 = g0.eval(\"g0 = this;\"); } ");
/*fuzzSeed-221406266*/count=701; tryItOut("mathy0 = (function(x, y) { return (Math.fround(((((Math.pow(x, x) >>> 0) == ( + ( + Math.pow(Math.fround((Math.fround(x) ? (x | 0) : y)), y)))) >>> 0) >>> (Math.fround(Math.pow((Math.imul((Math.max(( + Math.atanh(( + y))), x) | 0), 0x100000000) | 0), Math.fround(Math.max(Math.fround(x), y)))) % ( + x)))) ** (( - ( + Math.atan2((Math.atan2(y, Math.fround(( + x))) | 0), (( + y) | 0)))) != (( + Math.hypot(y, (( + y) >> ( + y)))) / ( + Math.fround(Math.abs(Math.fround(Math.hypot(Number.MIN_SAFE_INTEGER, y)))))))); }); testMathyFunction(mathy0, [-0x100000000, 2**53, 2**53+2, 2**53-2, 0x0ffffffff, 0x080000001, 0x080000000, -(2**53+2), -Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, -(2**53), 0x100000001, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, -1/0, 1/0, 0x100000000, Number.MAX_VALUE, -0x0ffffffff, -0, 0/0, -Number.MIN_SAFE_INTEGER, 42, 1, 1.7976931348623157e308, Number.MIN_VALUE, 0x07fffffff, -0x080000000]); ");
/*fuzzSeed-221406266*/count=702; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -17179869185.0;\n    d2 = (d0);\n    d0 = (+pow(((d2)), ((d2))));\n    (Float64ArrayView[((!(/*FFI*/ff(((((d2)) - ((Float64ArrayView[1])))))|0))-(/*FFI*/ff(((((0xff064a96)-(0xfe1155cb)+(0xffffffff)) & (((0x98c8eb9) < (0x262c738f))+(-0x8000000)))), ((((0x20bdbf6e)+(-0x8000000)) | ((0xa3d0a8c4)))))|0)) >> 3]) = (((d2) + (4611686018427388000.0)));\n    d2 = (d0);\n    i1 = ((~(((({d:  \"\" , \"-11\": [,] })) < ((~((((0xcd5c8800))>>>((/*FFI*/ff(((2049.0)), ((-1.125)), ((9.0)), ((9.671406556917033e+24)))|0)-(0x267e88a2))) / (((/*FFI*/ff()|0)-(i1))>>>((0xfbd1d0b7))))))))));\n    return +((Float32ArrayView[((0xffffffff)) >> 2]));\n    return +((d0));\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: undefined, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: undefined, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: new Function, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0, (new String('')), [0], (new Number(-0)), false, '\\0', (new Boolean(true)), NaN, (new Number(0)), objectEmulatingUndefined(), /0/, ({valueOf:function(){return '0';}}), '', ({valueOf:function(){return 0;}}), (new Boolean(false)), 1, null, 0.1, -0, true, '/0/', undefined, (function(){return 0;}), ({toString:function(){return '0';}}), '0', []]); ");
/*fuzzSeed-221406266*/count=703; tryItOut("testMathyFunction(mathy2, /*MARR*/[0x99, NaN, 0x99, 0x99, arguments.caller, arguments.caller, 0x99, NaN, NaN, NaN, 0x99, arguments.caller, NaN, null, NaN, null, 0x99, 0x99, 0x99, NaN, null, null, 0x99, NaN, 0x99, null, null, null, NaN, 0x99, 0x99, 0x99, 0x99, NaN, NaN, NaN, 0x99, null, NaN, NaN, null, arguments.caller, null, 0x99, 0x99, arguments.caller, 0x99, NaN, arguments.caller, NaN, null, arguments.caller, NaN, null, arguments.caller, NaN, 0x99, NaN, 0x99, 0x99, 0x99, NaN, arguments.caller, NaN, null, 0x99, null, arguments.caller, arguments.caller, arguments.caller, NaN, NaN, NaN, arguments.caller, NaN, 0x99, arguments.caller, arguments.caller, arguments.caller, NaN, 0x99, 0x99, NaN, NaN]); ");
/*fuzzSeed-221406266*/count=704; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! (( ! x) ^ ( ~ ( ~ Math.fround(Math.max(((( + Math.atan2(Math.fround(-0x100000000), x)) | ( + y)) >>> 0), y)))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -0x07fffffff, 1/0, -(2**53-2), -0x0ffffffff, -0x100000001, Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, Math.PI, 42, 0.000000000000001, Number.MAX_VALUE, 2**53-2, 0x080000001, 1, 0x0ffffffff, 0, -(2**53), -0, Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 2**53+2, 0x100000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=705; tryItOut("g2 + '';");
/*fuzzSeed-221406266*/count=706; tryItOut("b0.__iterator__ = String.fromCharCode.bind(e1);");
/*fuzzSeed-221406266*/count=707; tryItOut("mathy1 = (function(x, y) { return (Math.acos(Math.sinh(( + (( + Math.log10(((y & Math.fround(( + Math.fround((( - (y >>> 0)) >>> 0))))) >>> 0))) + ( + ( ~ (Math.fround(Math.sign(Math.fround(y))) >>> 0))))))) >>> 0); }); testMathyFunction(mathy1, [-0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -0x080000001, Number.MIN_VALUE, -(2**53-2), -1/0, -Number.MAX_VALUE, 0x100000000, -0x0ffffffff, 0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -0x100000000, -Number.MIN_VALUE, 2**53-2, 2**53, 0x0ffffffff, Math.PI, -0x080000000, -0x07fffffff, 0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, 0, 2**53+2, 42, -(2**53), 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=708; tryItOut("o0.b2 = t2.buffer;");
/*fuzzSeed-221406266*/count=709; tryItOut("mathy3 = (function(x, y) { return Math.pow(( + ( + ( ! ( + ( ! ( + (Math.hypot(Math.fround(0x100000001), (( ~ x) >= Math.fround(y))) | 0))))))), Math.fround(Math.tan(Math.fround(( ~ (Math.ceil((mathy2(y, 42) | 0)) | 0)))))); }); testMathyFunction(mathy3, [-0x100000000, 0x07fffffff, 0.000000000000001, 42, -Number.MIN_VALUE, 0x080000000, 1, 0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, 0, Number.MAX_VALUE, -0x100000001, -0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, -1/0, -Number.MIN_SAFE_INTEGER, -0, 2**53-2, 0/0, 0x100000000, 2**53, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), -0x080000001, 1/0, -Number.MAX_VALUE, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=710; tryItOut("mathy5 = (function(x, y) { return Math.trunc(( - Math.fround(Math.fround(Math.fround(( + Math.fround(x))))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, 0/0, -0, -0x100000000, -(2**53+2), Math.PI, 0, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 2**53-2, -0x080000000, 1/0, 0x100000000, Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, -0x080000001, -0x0ffffffff, 0x080000001, 0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -Number.MIN_VALUE, -1/0, 2**53, 0x100000001, Number.MIN_VALUE, 1]); ");
/*fuzzSeed-221406266*/count=711; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-(2**53+2), 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 1, 0x100000000, 0x080000001, -0x0ffffffff, 1.7976931348623157e308, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, Math.PI, 42, -(2**53-2), -0, -Number.MIN_VALUE, -0x07fffffff, 2**53+2, -0x080000001, Number.MIN_SAFE_INTEGER, -1/0, 1/0, -0x100000001, 0x07fffffff, -(2**53), -0x100000000, 0.000000000000001, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0]); ");
/*fuzzSeed-221406266*/count=712; tryItOut("\"use strict\"; /*MXX1*/o0 = g1.Array.prototype.slice;");
/*fuzzSeed-221406266*/count=713; tryItOut("testMathyFunction(mathy0, [-(2**53), 2**53+2, 1.7976931348623157e308, 0x080000001, -(2**53+2), 0x100000000, 1, -0x100000000, 0/0, -0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, -Number.MAX_VALUE, -(2**53-2), 0, Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -0x080000001, -0x07fffffff, -1/0, 42, Math.PI, 0x07fffffff, 1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000000]); ");
/*fuzzSeed-221406266*/count=714; tryItOut("\"use strict\"; ");
/*fuzzSeed-221406266*/count=715; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=716; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (((Float64ArrayView[((((((let (w = \"\\u2B90\")  \"\" )))>>>(-0xaa14*((0x56be7216)))))-(0xfa073e3b)) >> 3])) * ((147573952589676410000.0)));\n    d0 = (d0);\n    d1 = (((d1)) - ((+atan2(((+(0xcd75325d))), ((d0))))));\n    d0 = (d1);\n    {\n      {\n        return (((((((-0x8000000)))>>>((0xfbf975da)-((0x4774ca0b))-((d1) == (((void version(185))) ^ (Object.is))))))+((~((/*FFI*/ff(((~((Int16ArrayView[((0x408d6eba)) >> 1])))), ((+pow(((-3.0)), ((-1025.0))))), ((~~(524289.0))), ((-4194304.0)), ((-33554432.0)), ((36893488147419103000.0)), ((73786976294838210000.0)), ((-1.5)))|0)+(0x630a938b))) == (~~(+(((!(0x3bc16a86))*-0xfffff)>>>((0x52ce9cd4) % (0x7fffffff))))))-(-0x8000000)))|0;\n      }\n    }\n    return (((0x29cc1a52)-((0xd64b2d1c) < (((0x8a42bde1)-(0xf9bfd28a)+((0x1dc44b0c)))>>>((0x40ea761c)-(0xfd8bf4a1))))+(0x6c54a80f)))|0;\n  }\nv1 = Object.prototype.isPrototypeOf.call(v1, p1);\n  return f; })(this, {ff: function(y) { return undefined - /[^\\u008D\u7c7f\u00e7-\u00a9]?(?:((?=(?!.)))|\\t\\w)$/m }}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [2**53-2, -0x07fffffff, 0.000000000000001, -(2**53), -0x100000001, -0x080000001, -0, 1, 0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 0x0ffffffff, -(2**53+2), -(2**53-2), 2**53, -Number.MIN_VALUE, 0/0, -0x100000000, 0, 0x07fffffff, Number.MAX_VALUE, -0x080000000, 0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 42, Number.MIN_VALUE, 0x080000001, 1/0, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-221406266*/count=717; tryItOut("/*RXUB*/var r = r2; var s = o2.s1; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=718; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( + mathy2(( ! (Math.min(( ~ y), ( + mathy0(y, ( ! x)))) | 0)), (Math.sqrt(mathy1((( + (( + (x ** x)) ^ ( + Number.MAX_SAFE_INTEGER))) / (x - Math.fround(Math.hypot(Math.fround(y), Math.fround(x))))), y)) | 0)))); }); ");
/*fuzzSeed-221406266*/count=719; tryItOut("\"use strict\"; for (var v of t2) { delete h0.set; }");
/*fuzzSeed-221406266*/count=720; tryItOut("\"use strict\"; Array.prototype.forEach.call(a0, (function() { for (var j=0;j<53;++j) { f2(j%5==1); } }));");
/*fuzzSeed-221406266*/count=721; tryItOut("\"use strict\"; a2.unshift(a0, v1);");
/*fuzzSeed-221406266*/count=722; tryItOut("Object.preventExtensions(g0.g0.i1);");
/*fuzzSeed-221406266*/count=723; tryItOut("const y, w, y = function(y) { \"use strict\"; return  \"\"  }, ezwult, w = \"\\u805E\", z = (uneval(window = x)), x;/*RXUB*/var r = new RegExp(\"[\\u0082-\\\\x5dV\\\\u00ae]\", \"gy\"); var s = \"\\u00a2\"; print(s.replace(r, true)); ");
/*fuzzSeed-221406266*/count=724; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=725; tryItOut("var rhxkmf = new ArrayBuffer(8); var rhxkmf_0 = new Int32Array(rhxkmf); rhxkmf_0[0] = 2; var rhxkmf_1 = new Uint8ClampedArray(rhxkmf); print(rhxkmf_1[0]); var rhxkmf_2 = new Uint8Array(rhxkmf); rhxkmf_2[0] = -2; var rhxkmf_3 = new Float64Array(rhxkmf); print(rhxkmf_3[0]); rhxkmf_3[0] = -14; v0 = undefined;");
/*fuzzSeed-221406266*/count=726; tryItOut("\"use strict\"; /*MXX2*/g0.String.prototype.concat = o2;");
/*fuzzSeed-221406266*/count=727; tryItOut("\"use strict\"; t0 = new Int8Array(b1, 11, 0);");
/*fuzzSeed-221406266*/count=728; tryItOut("mathy5 = (function(x, y) { return (Math.fround(((Math.clz32(mathy0(Math.fround((y <= (y >>> 0))), (Math.acosh(y) >>> 0))) >>> 0) ? Math.fround((Math.fround((((( ~ (y >>> 0)) >>> 0) + 0x100000000) >>> 0)) - Math.fround(( - y)))) : Math.fround(( ! (Math.max((Math.max(x, x) >>> 0), (x >>> 0)) >>> 0))))) >= Math.atan(( ~ ( + ( ! x))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x080000001, 2**53+2, 2**53-2, 1, -0x07fffffff, -0, 42, Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001, 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000000, 0, 0x07fffffff, Number.MAX_VALUE, 1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 0/0, -1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, 0x080000000, 1.7976931348623157e308, -(2**53), -0x100000000, -(2**53-2), 0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=729; tryItOut("\nnull;\na1.sort((function(stdlib, foreign, heap){ \"use asm\";   var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Int32ArrayView[4096]) = (((((((0x427c6f21)-(-0x8000000)-(0xf98420e0)) >> (-0x83875*(-0x8000000))) / (((0x951e2900) / (0xa37c5aae))|0))>>>((0x328f9030)-(0x5f073a2a))))*-0xf86d0);\n    (Uint32ArrayView[0]) = ((0xf8502c77));\n    {\n      d1 = (((Math.sqrt(-27))) * ((d0)));\n    }\n    return +((d1));\n    return +((((0xfaf4bc47)+((0xffffffff) == (((0xd44f0c35)-(-0x8000000))>>>((0xfe8a968e)))))));\n  }\n  return f; }));\n");
/*fuzzSeed-221406266*/count=730; tryItOut("\"use strict\"; for (var p in this.v2) { m2.set(this.o0, g2); }");
/*fuzzSeed-221406266*/count=731; tryItOut("\"use strict\"; return;");
/*fuzzSeed-221406266*/count=732; tryItOut("utzhyi;h1.delete = f0;");
/*fuzzSeed-221406266*/count=733; tryItOut("\"use strict\"; /*bLoop*/for (ppawxe = 0; ppawxe < 144; ++ppawxe, delete y.x) { if (ppawxe % 60 == 52) { Array.prototype.reverse.apply(a1, []); } else { for (var v of v0) { try { for (var v of o1) { v1 = t0.BYTES_PER_ELEMENT; } } catch(e0) { } try { a2.forEach((function() { v2 = Object.prototype.isPrototypeOf.call(b2, this.h2); return i0; }), m2, t1, o2.m0, p1, o2); } catch(e1) { } v1 = evaluate(\"/* no regression tests found */\", ({ global: this.g1.o2.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 83 == 41), catchTermination: (x % 19 != 16) })); } }  } \nprint(x);break ;\n");
/*fuzzSeed-221406266*/count=734; tryItOut("\"use asm\"; v2 = r2.toString;");
/*fuzzSeed-221406266*/count=735; tryItOut("o1.a2.shift();");
/*fuzzSeed-221406266*/count=736; tryItOut("x = --NaN, fiqteb, eval = x, window = ++x, NaN = (let (d = 27) \"\\uCFB2\"), d, c = x, x = this;a0[2] = o2.o2.e2;");
/*fuzzSeed-221406266*/count=737; tryItOut("v2 = a0.length;");
/*fuzzSeed-221406266*/count=738; tryItOut("\"use strict\"; a0.toSource = f2;");
/*fuzzSeed-221406266*/count=739; tryItOut("let(b) ((function(){for(let x in []);})());");
/*fuzzSeed-221406266*/count=740; tryItOut("/*RXUB*/var r = /(?=^.{2}(\\b))*?|\u4728(\\D)+(?!\\b)|\\uD590|[^]|(?=(?!(\\b\\B|\\b{0,})|(?:(?!.)*))){4}/im; var s = \"\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=741; tryItOut("\"use strict\"; a2.unshift(p1);");
/*fuzzSeed-221406266*/count=742; tryItOut("testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -0x080000000, 1/0, 2**53-2, -0x100000001, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -0x100000000, 0.000000000000001, -(2**53-2), 0, Number.MAX_SAFE_INTEGER, 1, Math.PI, -0, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, -(2**53), -(2**53+2), -0x07fffffff, 0x080000000, 0x0ffffffff, -0x0ffffffff, 0x100000000, -Number.MAX_VALUE, 2**53, 0x080000001, 0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-221406266*/count=743; tryItOut("/*infloop*/M:for(var y = (4277); arguments.callee.caller.arguments =  /x/  ^= -12;  \"\" ) {print(this.g2);print(delete x.a); }");
/*fuzzSeed-221406266*/count=744; tryItOut("var w = \"\\uE6C8\";{print(new RegExp(\"[^\\\\w\\\\cS-\\\\xf5\\\\B-\\\\u00fa\\\\f-\\u00e2]\\u001b+?|[^\\\\sI]|\\\\b{2}|$(?:(\\\\2)){4,}\", \"gym\").yoyo([1]));Array.prototype.sort.call(a2, (function() { try { m0.delete([1]); } catch(e0) { } try { /*RXUB*/var r = r1; var s = \" 11\\u0083\\u9537a\\na\\u00ff1 11\\u0083\\u9537a\\na\\u00ff1 11\\u0083\\u9537a\\na\\u00ff1 \\u689f  11\\u0083\\u9537a\\na\\u00ff1\\n\\u00d5j a 11\\u0083\\u9537a\\na\\u00ff1\"; print(r.test(s));  } catch(e1) { } print(uneval(t2)); return o1.o2; })); }");
/*fuzzSeed-221406266*/count=745; tryItOut("v0 = Object.prototype.isPrototypeOf.call(o0.t1, g2.b2);");
/*fuzzSeed-221406266*/count=746; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.hypot((Math.fround(Math.fround(Math.acosh((((mathy0((0 >>> 0), x) >>> 0) == ( + x)) ^ ( ! (( - y) >>> 0)))))) ^ (Math.max(Math.log1p(( + mathy0(( + x), x))), ( + ( + x))) | 0)), Math.log10(( ! -Number.MIN_SAFE_INTEGER)))); }); testMathyFunction(mathy1, [1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, 2**53, -0x100000001, -Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, 0x080000001, 0x0ffffffff, Math.PI, 0, -0x080000000, -0x100000000, -0x080000001, 0x100000001, 0/0, 1/0, -(2**53+2), 0.000000000000001, 1, 0x07fffffff, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, -0, -1/0, -(2**53-2), -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=747; tryItOut("/*bLoop*/for (xxrodq = 0; xxrodq < 2; ++xxrodq) { if (xxrodq % 5 == 0) { let (x = x.__defineGetter__(\"getter\", (undefined).bind), y, eval = this.__defineSetter__(\"x\", function(y) { \"use strict\"; yield y; (((({/*TOODEEP*/})).bind()).call(x, \"\u03a0\", this));; yield y; }), c = \"\\u06AE\", y) { with({z:  \"\" }//h\n)e2.toString = (function(j) { if (j) { try { (void schedulegc(g2)); } catch(e0) { } try { b1[\"x\"] = f1; } catch(e1) { } try { g1.offThreadCompileScript(\"function f0(v1)  { yield this } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: -6, element: o2, elementAttributeName: s2 })); } catch(e2) { } Array.prototype.shift.call(a0, h0, i0, s1, v2, a1, t2); } else { try { h1.enumerate = f2; } catch(e0) { } t0 = m1.get(b1); } }); } } else { this.v1 = (t1 instanceof i0); }  } ");
/*fuzzSeed-221406266*/count=748; tryItOut("\"use strict\"; var mxblen = new ArrayBuffer(16); var mxblen_0 = new Int16Array(mxblen); print(mxblen_0[0]); var mxblen_1 = new Int32Array(mxblen); mxblen_1[0] = 8; var mxblen_2 = new Int32Array(mxblen); mxblen_2[0] = 29; var mxblen_3 = new Int8Array(mxblen); mxblen_3[0] = -20; var mxblen_4 = new Int8Array(mxblen); var mxblen_5 = new Float32Array(mxblen); mxblen_5[0] = 1364543339; var mxblen_6 = new Int16Array(mxblen); mxblen_6[0] = -18; /*RXUB*/var r = /(?!.+?)|(?!^)\u0092[^]+|(?!\\s){1}|([7-\\\u00f9\\d\\x80\u00db-\u4caf]|$[^]^*)+?|\\cL[^\u733d\\s]|^^{4,}*?(?=$)|(?=\\S)+?.*|\\2/gi; var s = \"\\n\\n\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=749; tryItOut("s1.__proto__ = m1;");
/*fuzzSeed-221406266*/count=750; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return (( + (Math.imul((Math.log((( - -0x100000001) >>> 0)) >>> 0), (Math.asinh(x) >>> 0)) - (Math.fround(Math.atan2(Math.fround(x), Math.fround(0x100000001))) >>> 0))) >>> mathy2(Math.acosh(((x % ((Math.atan2((Math.hypot((x >>> 0), (-1/0 >>> 0)) >>> 0), (mathy2(2**53+2, y) >>> 0)) >>> 0) >>> 0)) >>> 0)), Math.hypot(Math.min(( + x), Math.imul(Math.fround(-(2**53+2)), y)), Math.sign((( + y) ? Math.fround((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { var r0 = a17 / a14; var r1 = a14 + a9; var r2 = 4 * a10; var r3 = a5 | a8; var r4 = r0 + 9; var r5 = a9 / 1; var r6 = r3 / a15; var r7 = r5 + 2; var r8 = 9 - a1; var r9 = a13 ^ a9; var r10 = r9 * a1; var r11 = a11 / r2; var r12 = r6 + r8; var r13 = 0 ^ 8; var r14 = a12 * 7; a6 = a1 / r5; a19 = a10 / 4; var r15 = a7 & r9; var r16 = r10 & r9; var r17 = 0 - 7; var r18 = 4 / 2; var r19 = 8 / r17; var r20 = a7 * r17; var r21 = 3 ^ r4; var r22 = 5 | r19; var r23 = 9 % r21; a1 = a0 ^ a16; var r24 = r2 / r23; a0 = r15 | 3; var r25 = r20 / x; r14 = r2 - 2; var r26 = r9 & 2; var r27 = 3 % 0; var r28 = 4 ^ 3; var r29 = 4 & 4; var r30 = a5 % 3; print(r23); r18 = 0 * a8; var r31 = 2 % r28; r4 = r11 - r3; print(r6); var r32 = 6 ^ r15; var r33 = r11 ^ r7; var r34 = r10 & a5; var r35 = 3 + 4; a17 = r22 / r12; var r36 = r12 & r21; return a16; })) : Math.fround(Number.MIN_SAFE_INTEGER)))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, 2**53-2, 0x080000000, -0x100000001, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), 1.7976931348623157e308, 1, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, 2**53+2, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, -0x080000000, Math.PI, 42, -0x07fffffff, -(2**53), -0, -0x080000001, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=751; tryItOut("mathy3 = (function(x, y) { return ( + Math.clz32(((((( ~ ( + Math.cos(Math.round(x)))) ? ( + Math.imul(( + ((Math.log10((y >>> 0)) >>> 0) && Number.MAX_VALUE)), ( + Math.round((( ~ x) >>> 0))))) : x) >>> 0) >>> 0) , Math.min(( + Math.ceil((((y >>> y) | 0) >>> 0))), x)))); }); testMathyFunction(mathy3, [-0x080000001, 1, 0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -0x080000000, 0x080000000, -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, -0x100000001, 0x0ffffffff, -1/0, 0, -Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, 2**53+2, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, 2**53, -0, -0x100000000, 1/0, -0x07fffffff, 42]); ");
/*fuzzSeed-221406266*/count=752; tryItOut("");
/*fuzzSeed-221406266*/count=753; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.acosh(Math.log10(Math.min(Math.max(x, x), x))); }); testMathyFunction(mathy1, [2**53+2, 1, -(2**53+2), 0, 0x080000001, -Number.MAX_VALUE, -(2**53), -0x080000001, -0x0ffffffff, Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, 0x0ffffffff, -0x080000000, -1/0, 42, Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, -0x100000001, -(2**53-2), 1.7976931348623157e308, 0.000000000000001, -0x07fffffff, 1/0, Math.PI, 2**53-2, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-221406266*/count=754; tryItOut("var jvjmna = new ArrayBuffer(6); var jvjmna_0 = new Uint8Array(jvjmna); print(jvjmna_0[0]); jvjmna_0[0] = 28; var jvjmna_1 = new Uint32Array(jvjmna); jvjmna_1[0] = -9; var jvjmna_2 = new Int32Array(jvjmna); print(jvjmna_2[0]); Array.prototype.push.apply(a2, [p1]);print(jvjmna_1[9]);yield [1];;");
/*fuzzSeed-221406266*/count=755; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=756; tryItOut("M:switch((4277)\n) { case 8: break; default: break;  }");
/*fuzzSeed-221406266*/count=757; tryItOut("\"use strict\"; switch(window) { default: break; break;  }");
/*fuzzSeed-221406266*/count=758; tryItOut("mathy0 = (function(x, y) { return (Math.sign((((( - Math.min(( - x), ( + (Math.fround(Number.MAX_VALUE) << (x >>> 0))))) >>> 0) + ((Math.sqrt((Math.atan(Number.MIN_VALUE) | 0)) | 0) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-221406266*/count=759; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ Math.imul(((((x * y) >>> ( + ( ! ((((x | 0) ? Math.fround(x) : (x | 0)) | 0) | 0)))) < ( + Math.fround(( + (y ? y : Math.expm1(( - y))))))) >>> 0), Math.fround((mathy0(Math.imul(Math.imul(x, 42), ( + ((Math.hypot(x, (x | 0)) | 0) ** y))), (( - ( + -Number.MAX_VALUE)) | 0)) / ( + Math.min(x, Math.fround(y))))))); }); ");
/*fuzzSeed-221406266*/count=760; tryItOut("mathy1 = (function(x, y) { return (Math.pow((((((Math.fround(( - y)) , (mathy0(( + x), Math.pow(y, (Math.acos((y | 0)) | 0))) >>> 0)) ? Math.fround((( + Math.fround((Math.fround(x) / (Math.max(y, x) >>> 0)))) <= Math.fround((( + 0x100000001) !== ( + -0x0ffffffff))))) : Math.fround((Math.fround((( + y) >>> ( + 1/0))) ^ ( + x)))) | 0) + (((( - (Math.fround(2**53) ^ Math.fround(x))) >>> 0) + Math.atan2(y, ( + (( + (Math.tan((x | 0)) | 0)) >= ( + x))))) | 0)) | 0), ((( + Math.log(( + (((Math.atan2(((mathy0(x, x) | 0) ^ ( + x)), ( - ( + -0x100000000))) >>> 0) > (mathy0((Math.asinh(y) | 0), Math.trunc(y)) >>> 0)) >>> 0)))) / (Math.fround(( - 0x080000001)) ? Math.min(x, ((-1/0 | 0) >= ( + ( - y)))) : Math.pow(Math.fround(-Number.MIN_SAFE_INTEGER), ( ~ x)))) | 0)) | 0); }); testMathyFunction(mathy1, [0x080000001, -0, 0x100000001, 2**53+2, -Number.MIN_VALUE, -0x100000001, -(2**53-2), 0x0ffffffff, Math.PI, 1, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, 2**53, Number.MIN_VALUE, 0x07fffffff, 1/0, -(2**53+2), -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, 42, 2**53-2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0, -0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=761; tryItOut("\"use strict\"; g0.m1.set(this.v2, v1);");
/*fuzzSeed-221406266*/count=762; tryItOut("v0 = evaluate(\"v1 = (i2 instanceof v0);\", ({ global: g1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: x.valueOf(\"number\"), sourceIsLazy: true, catchTermination: x }));");
/*fuzzSeed-221406266*/count=763; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=764; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max((mathy0((( ! y) < ( - y)), (-0x080000001 >>> 0)) ** ( + (Math.fround((( ! ((Math.min(0/0, (Math.sin(x) >>> 0)) | 0) >>> 0)) | 0)) << ((Math.max(( + Math.fround(Math.trunc(Math.fround(x)))), x) , ( + (y + ( + x)))) | 0)))), (mathy0(((Math.fround(Math.min((x , x), y)) | 0) >>> 0), ((( ! (Math.sin(( ! -0x080000001)) >= ( ! (y >>> 0)))) >>> 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-221406266*/count=765; tryItOut("v1 = g0.runOffThreadScript();");
/*fuzzSeed-221406266*/count=766; tryItOut("print(x);v2 = r0.sticky;");
/*fuzzSeed-221406266*/count=767; tryItOut("a1 = a0.slice(4, -7);");
/*fuzzSeed-221406266*/count=768; tryItOut("e1.delete(o2.v0);");
/*fuzzSeed-221406266*/count=769; tryItOut("\"use strict\"; m2 + e1;");
/*fuzzSeed-221406266*/count=770; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.imul(( + Math.fround((Math.fround(( ! y)) < Math.fround(Math.min((( ! (( + Math.asin(( + Math.trunc(( + y))))) | 0)) | 0), mathy1(y, y)))))), mathy1(Math.hypot((0 + 42), (Math.imul((y >>> 0), (x >>> 0)) >>> 0)), Math.min(Math.max(x, Math.imul(Math.pow(2**53-2, x), y)), ( ~ Math.fround(( + ( + (y ? Math.PI : Math.fround(mathy1(Math.fround(-(2**53)), Math.fround(x))))))))))); }); testMathyFunction(mathy3, [null, undefined, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '/0/', /0/, ({toString:function(){return '0';}}), [0], 0.1, (function(){return 0;}), (new Number(-0)), NaN, objectEmulatingUndefined(), (new Number(0)), (new Boolean(true)), 1, -0, (new Boolean(false)), true, '\\0', false, (new String('')), 0, [], '', '0']); ");
/*fuzzSeed-221406266*/count=771; tryItOut("e1.add(s0);");
/*fuzzSeed-221406266*/count=772; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = s1; print(s.search(r)); ");
/*fuzzSeed-221406266*/count=773; tryItOut("\"use strict\"; for (var v of e2) { e1.toSource = (function() { try { v0 = (g1.e1 instanceof i0); } catch(e0) { } Array.prototype.reverse.apply(o2.a0, []); return g1; }); }");
/*fuzzSeed-221406266*/count=774; tryItOut("\"use strict\"; /*infloop*/for(Math.atan2((Math.sin(((Math.atanh(((Math.imul((Math.sin((Number.MIN_VALUE != x)) | 0), ((Math.fround(Math.ceil(Math.pow(-1/0, Math.fround(x)))) | 0) % (((x >>> 0) / x) | 0))) || Math.fround(( ~ Math.fround(((( + x) >>> 0) < (( ! (x >>> 0)) >>> 0)))))) | 0)) | 0) >>> 0)) >>> 0), (Math.atan2(Math.pow(( + ((( + Math.sqrt((Math.fround((-(2**53-2) != x)) <= x))) >= Math.acosh(Math.fround(((Math.fround(x) > (( - ( + Math.fround((x + (x | 0))))) | 0)) | 0)))) % (4277))), Math.sqrt((((x < x) % x) === ( ! (-0x080000001 | 0))))), Math.fround(Math.sin(Math.fround(Math.pow((( - (Math.pow(x, (x >>> 0)) >>> 0)) ? ( + Math.min(( + (Math.hypot(( + x), ( + x)) >>> 0)), Math.fround(x))) : (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var tan = stdlib.Math.tan;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((((!(i1))+(i1)) ^ (((i1) ? (i1) : ((0x7099f260) == (0x721e46c3)))*0x7f529)) >= ((-(!(!(i1)))) ^ ((~((imul((i0), (i1))|0))) % (((!(0xcb7d5850))+((0xc3ea886b))) & (((140737488355327.0) != (590295810358705700000.0))-(i0))))));\n    i0 = (/*FFI*/ff(((((i0)+(((0xfffff*(0x6c5aa177))>>>((i1))) < ( ''  ? (4277) : 'fafafa'.replace(/a/g, undefined)))-(i0)) >> ((i0)))), ((((((((-513.0)) * ((((Infinity)) % ((+tan(((513.0)))))))))) / (0xffffffff))|0)), ((Math.imul(({ get \"-18\"(x) { \"use strict\"; yield \"\\uFE92\" }  }), -12))), ((imul(((18014398509481984.0) > (2049.0)), (25))|0)), ((((33554433.0)) % ((((-1.1805916207174113e+21)) % ((-4.722366482869645e+21)))))), ((0x18f2213d)), ((imul(((0x50af345d) != (0xb91bd397)), (i0))|0)), ((1125899906842625.0)), (((-0x8000000) ? (-15.0) : (-134217727.0))), ((-1.888946593147858e+22)), ((-36028797018963970.0)), ((-1.5)))|0);\n    (Uint8ArrayView[((!([]))-(x|=mathy3(/[^]*?/gy))) >> 0]) = (((0x3a40f2bf))+(0xe030be27)-(i1));\n    return +((+(((((i1)) & (((0xf8460926) ? (0x1c17965a) : (0xd8d33913)))) / ((((((0xf874e1b6)+(0xb13884e6))>>>(0xfffff*(-0x8000000)))))|0))>>>((/*FFI*/ff(((+sqrt(((-1025.0))))), ((((i1)) << ((0x80f85229)+(i1)))))|0)))));\n  }\n  return f; })(this, {ff: function (window, x)null}, new SharedArrayBuffer(4096))), ((Math.hypot((Math.fround((( + Math.atan2((-Number.MIN_VALUE >>> ( ~ 0x080000000)), 42)) & x)) | 0), (Math.max(x, Math.fround(( + ( + x)))) | 0)) | 0) >>> 0)))))) * (Math.log(( + Math.log(Math.fround((Math.fround(( - Math.fround(( + ( - Math.fround(Math.expm1(Math.fround(x)))))))) | Math.fround((Math.max(x, Math.fround(( - 0))) + ( + Math.pow(( + ( + Math.trunc(( + Math.fround(Math.trunc(Math.fround(x))))))), ( - ( + Math.hypot(Math.fround(x), (Number.MIN_VALUE | 0))))))))))))) >>> 0))); (void options('strict')); x) {o1.s0 = m1.get(t1);g2[\"concat\"] = h1; }");
/*fuzzSeed-221406266*/count=775; tryItOut("\"use strict\"; (x);\nt0[7] = b2;\n");
/*fuzzSeed-221406266*/count=776; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=777; tryItOut("\"use asm\"; /*oLoop*/for (let kyechg = 0; kyechg < 138; ++kyechg) { ; } ");
/*fuzzSeed-221406266*/count=778; tryItOut("mathy4 = (function(x, y) { return ((((( + (( - Math.fround(( + (( ! x) ? -1/0 : ( ! ( + (x ** y))))))) >>> 0)) >>> 0) | 0) >> (( ~ Math.trunc(-0x0ffffffff)) | 0)) | 0); }); testMathyFunction(mathy4, [-0x100000000, 2**53+2, 0, 0.000000000000001, 42, -Number.MAX_VALUE, 0x07fffffff, 0x080000000, -1/0, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, 1.7976931348623157e308, -0x080000000, Number.MIN_VALUE, -0, -(2**53-2), 0x080000001, -0x07fffffff, -(2**53+2), 0/0, 1/0, -0x080000001, 0x100000001, -Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), 2**53-2, 0x0ffffffff, 1]); ");
/*fuzzSeed-221406266*/count=779; tryItOut("\"use strict\"; v0 = t1.byteOffset;");
/*fuzzSeed-221406266*/count=780; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.imul(Math.pow(( + ( + ( + -Number.MAX_VALUE))), Math.imul(( ~ Math.atan(( + mathy1(x, x)))), ( ~ Math.tanh(y)))), Math.fround((Math.atan2((Math.log(Math.imul(y, y)) >>> 0), (( + ( ! Math.fround((( + x) >= y)))) >>> 0)) >>> 0))) | 0); }); ");
/*fuzzSeed-221406266*/count=781; tryItOut("mathy0 = (function(x, y) { return ( ~ ( ! Math.atan2(y, Math.PI))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, (4277), function(){}, function(){}, function(){}, (4277), (4277), (4277), (4277), (4277), (4277), function(){}, function(){}, (4277), function(){}, function(){}, (4277), function(){}, function(){}, (4277), function(){}, (4277), function(){}, function(){}, (4277), function(){}, (4277), (4277), (4277), (4277), (4277), function(){}, function(){}, (4277), function(){}, function(){}, (4277)]); ");
/*fuzzSeed-221406266*/count=782; tryItOut("mathy0 = (function(x, y) { return ( ~ (( + Math.tanh(( + Math.fround(( ~ ( + ( ! x))))))) ** ( + x))); }); testMathyFunction(mathy0, [1, '', -0, [0], (new Number(-0)), true, ({toString:function(){return '0';}}), '0', /0/, undefined, (new String('')), (new Boolean(true)), false, 0.1, '/0/', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), '\\0', null, NaN, 0, ({valueOf:function(){return '0';}}), (new Boolean(false)), (new Number(0)), (function(){return 0;}), []]); ");
/*fuzzSeed-221406266*/count=783; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.015625;\n    var d3 = 288230376151711740.0;\n    (Float64ArrayView[1]) = ((d3));\n    {\n;    }\n    d0 = (+(1.0/0.0));\n    (Uint8ArrayView[((0x373d3b0c)) >> 0]) = ((0x71a028e8));\n    d2 = (d3);\n    d1 = (d0);\n    d0 = (d0);\n    {\n      d2 = (-((+abs(((d1))))));\n    }\n    return (((/*FFI*/ff()|0)))|0;\n    return (((0x8c774aba)))|0;\n  }\n  return f; })(this, {ff: Uint16Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [1/0, 1.7976931348623157e308, 0/0, -(2**53-2), -0x0ffffffff, Math.PI, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000001, -0x080000000, 0x100000001, 2**53, 0, -(2**53), -0x100000000, -0x100000001, -1/0, -0, -0x07fffffff, Number.MIN_VALUE, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 1, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=784; tryItOut("while((x) && 0)/*ODP-2*/Object.defineProperty(f2, \"valueOf\", { configurable: false, enumerable: \"\\u0B20\", get: (function(j) { if (j) { for (var p in g2) { try { m0.set(g0, g0.t0); } catch(e0) { } try { h1.getOwnPropertyDescriptor = f1; } catch(e1) { } try { /*MXX2*/g1.SyntaxError.length = e1; } catch(e2) { } f2 = a0[9]; } } else { try { this.s1 += s0; } catch(e0) { } try { Array.prototype.pop.apply(a1, [f2]); } catch(e1) { } v2 = g0.runOffThreadScript(); } }), set: (function(a0, a1, a2, a3, a4, a5, a6) { var r0 = a2 | a3; a0 = 6 % a4; var r1 = 8 + 1; var r2 = a3 % 0; var r3 = a0 - 2; var r4 = r2 + 8; r3 = a4 % r1; var r5 = r3 - 8; var r6 = a3 / a2; var r7 = 3 % a3; var r8 = 6 ^ a2; r6 = a2 % 5; var r9 = 0 / r4; var r10 = r1 - r7; var r11 = a4 % r4; r4 = a6 + r3; var r12 = r9 / r10; var r13 = 9 / r9; var r14 = 0 & a2; var r15 = a6 | 9; var r16 = r6 / r13; var r17 = 8 - a5; var r18 = 0 % r17; r1 = a6 * a1; var r19 = a5 ^ 7; var r20 = 6 % r17; var r21 = 6 / r4; r10 = 1 * 1; var r22 = 3 / a0; var r23 = a6 & r4; print(a6); var r24 = r17 & r13; r7 = r3 * 9; x = r9 % r6; var r25 = 9 ^ r11; var r26 = r19 ^ a0; var r27 = r25 ^ a0; a6 = r2 - 2; var r28 = 1 ^ r1; var r29 = r3 | 2; return a3; }) });");
/*fuzzSeed-221406266*/count=785; tryItOut("\"use strict\"; if(false) {/* no regression tests found */v0 = g0.eval(\"function f2(g2) (x = (void shapeOf( /x/ )))\"); }");
/*fuzzSeed-221406266*/count=786; tryItOut("mathy5 = (function(x, y) { return ((Math.min(Math.fround(( + Math.exp((mathy0((y | 0), (Math.exp(Math.fround(0x100000001)) | 0)) | 0)))), Math.fround((Math.atan2((Math.atan2(Math.pow(y, Number.MIN_SAFE_INTEGER), ( - x)) | 0), (y | 0)) | 0))) >>> 0) || mathy3(Math.fround((Math.fround(x) + Math.fround((Math.fround((this >= Math.fround(Math.acosh(Math.fround(y))))) >= ( ! -0x080000001))))), (((Math.hypot(( - x), ( + x)) | 0) !== ((Math.log(((Math.asin((x | 0)) | 0) | 0)) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-(2**53), 0x07fffffff, -0x100000000, 1, -(2**53-2), -(2**53+2), -0x100000001, 0x080000001, 0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0/0, 0x0ffffffff, 2**53-2, 1/0, -0x080000001, -0x080000000, 0x100000000, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -0, 0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x0ffffffff, 2**53, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=787; tryItOut("/*tLoop*/for (let d of /*MARR*/[{}, ({}), {}, {}, {}, ({}), {}, {}, {}, {}, ({}), {}, ({}), {}, ({}), {}, {}, {}, {}, ({}), {}, ({}), {}, {}, ({}), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, ({}), {}, ({}), ({}), ({}), ({}), ({}), {}, ({}), {}, {}, {}, ({}), ({}), {}, ({}), {}, ({}), {}, ({}), ({}), ({}), ({}), ({}), {}, {}, ({}), {}, ({}), ({}), {}, {}, {}, ({}), {}, ({}), ({}), {}, {}, ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), {}, ({}), {}, {}, {}, {}, ({}), {}, ({}), {}, ({}), {}, ({}), {}, {}, ({}), {}, {}, {}]) { throw x; }");
/*fuzzSeed-221406266*/count=788; tryItOut("/*RXUB*/var r = /\\w|(?=((?=\\b\\w){4})\\b+?+?)|(?:\u00f3|\\b|\\b*?.*)\\b|\\B|.(?:(?:\u00b1))/gyi; var s = \"11\\u8353\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=789; tryItOut("\"use strict\"; \"use asm\"; print(x);");
/*fuzzSeed-221406266*/count=790; tryItOut("\"use strict\"; o2 + '';");
/*fuzzSeed-221406266*/count=791; tryItOut("testMathyFunction(mathy4, [-1/0, Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, -0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 42, -0x100000001, -(2**53-2), 0/0, 2**53, 2**53+2, -(2**53), -0x07fffffff, 1, 0x080000000, -Number.MIN_VALUE, -(2**53+2), 0x080000001, Math.PI, 0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -0x080000000, 0, Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=792; tryItOut("mathy3 = (function(x, y) { return Math.asin((Math.cos((( ~ Math.pow((Math.hypot((x | 0), (x | 0)) | 0), Math.fround((y ** x)))) | 0)) + ( + Math.fround(Math.imul(Math.fround(y), Math.fround((x / y))))))); }); testMathyFunction(mathy3, [0x100000000, Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 2**53, 1, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, 2**53+2, -0x100000001, -(2**53), 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, 0/0, -Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -1/0, 1/0, -0x080000001, 2**53-2, -0x100000000, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=793; tryItOut("throw  '' ;");
/*fuzzSeed-221406266*/count=794; tryItOut("testMathyFunction(mathy1, [2**53+2, 0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 2**53, 2**53-2, -Number.MAX_VALUE, 0x080000000, 0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, Number.MIN_VALUE, 1, -Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, 0x100000001, 0x100000000, -(2**53-2), -0x100000001, -1/0, 1/0, 42, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, Math.PI, 1.7976931348623157e308, -0x080000000, -(2**53)]); ");
/*fuzzSeed-221406266*/count=795; tryItOut("mathy2 = (function(x, y) { return Math.min(Math.fround(Math.sign(Math.fround(Math.hypot((((mathy0((y >>> 0), 0x080000000) >>> 0) ? (Math.pow(y, ( ! -(2**53))) | 0) : (1/0 | 0)) | 0), ( ! x))))), (Math.imul(( + (x * y)), mathy1((1.7976931348623157e308 + (( + Math.fround(-(2**53))) >>> 0)), Math.abs(y))) - ( + (mathy1(Math.max(y, (( - Math.fround(( ~ ( + (-0x080000000 | 0))))) | 0)), (y | 0)) | 0)))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -Number.MIN_VALUE, -0x100000001, 1, 0x0ffffffff, -0x080000001, 1/0, 2**53+2, 2**53-2, 0x080000001, -1/0, -0x07fffffff, 0x07fffffff, 42, Number.MAX_VALUE, 2**53, 0/0, 0x100000000, 0.000000000000001, 0x100000001, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000000, -Number.MAX_VALUE, -0]); ");
/*fuzzSeed-221406266*/count=796; tryItOut("if(\"\\u21C5\") {v1 = evalcx(\"[1,,]\", g0); } else  if (( /x/g  >>=  \"\" )) {} else {(new RegExp(\"(?:(?!\\\\1*?)(?:^|(?:\\\\s)\\\\b))\", \"i\")); }");
/*fuzzSeed-221406266*/count=797; tryItOut("\"use strict\"; print(uneval(g2));");
/*fuzzSeed-221406266*/count=798; tryItOut("M:switch(this) { default: break; case 0: break; case 5: true;break; case 6: print(x);Object.defineProperty(this, \"v1\", { configurable: (x % 40 != 1), enumerable: (x % 16 != 0),  get: function() {  return true; } });break;  }");
/*fuzzSeed-221406266*/count=799; tryItOut("mathy4 = (function(x, y) { return (Math.tanh((( ! (( ~ x) >>> 0)) >>> 0)) && Math.fround(( - (Math.fround((Math.fround(y) | 0x080000001)) >> y)))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, -0, -1/0, 0/0, 42, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53, -(2**53-2), -0x0ffffffff, -(2**53+2), 0x07fffffff, -(2**53), -Number.MAX_VALUE, 0x080000001, Math.PI, 1, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 0, -0x100000001, -0x100000000, 0.000000000000001, -0x080000001, 1.7976931348623157e308, 1/0, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-221406266*/count=800; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (((-0xfffff*((((i1)+(0xfbb2e945)) | ((i1))) != (((!((~((0xfca0cd68)))))*0x38c95))))>>>(((((+(1.0/0.0))) / ((Infinity))) != (+abs(((+/*FFI*/ff(('fafafa'.replace(/a/g\u000c, DataView.prototype.getInt32)), ((imul((0x2915965d), (0x3cf465a6))|0)), ((-262145.0)), ((268435457.0))))))))*-0xfffff)));\n    /*FFI*/ff(((d0)), (((0xffffffff) ? ((0x3b9e80e) ? (-2147483648.0) : (0.0009765625)) : (+abs(((d0)))))), ((((0x64f43de9)-(i1)+(!(0xff5bf05f))) | (0xf3f88*((0x76a0c048) == (0x577eeae6))))), (((((0x1e81cc3d) < (0x3c0c5938))+((-4398046511105.0) == (-72057594037927940.0))) & (((0x0))*-0x4058e))));\ni1 + '';    i1 = (0xffffffff);\n    {\n      d0 = (-1099511627777.0);\n    }\n    i1 = (/*FFI*/ff()|0);\n    (Float32ArrayView[((/*FFI*/ff()|0)+((0xb544de3d))) >> 2]) = ((d0));\n    d0 = (-9223372036854776000.0);\n    d0 = (+(0.0/0.0));\n    return (((0x7b99abdf) % (~(0x9fa4f*(0x5b8c91c5)))))|0;\n  }\n  return f; })(this, {ff: (new Function(\"g2.t2[4] = b0;\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0, -0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, -0x100000000, 2**53-2, 0.000000000000001, 0/0, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000000, 42, -(2**53+2), 0x100000001, -0x080000000, -0x100000001, -1/0, Number.MAX_SAFE_INTEGER, Math.PI, 1, 0x080000000, -Number.MIN_VALUE, 2**53, 2**53+2, -0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -(2**53-2), 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=801; tryItOut("/*oLoop*/for (pvzlec = 0; pvzlec < 7; ++pvzlec) { for (var p in b2) { try { i1.send(m0); } catch(e0) { } try { v0 = g1.runOffThreadScript(); } catch(e1) { } Array.prototype.push.apply(a1, [b, o1.v0, [1,,], \"\\u3644\", g2]); } } ");
/*fuzzSeed-221406266*/count=802; tryItOut("m1.set(e1, v0);");
/*fuzzSeed-221406266*/count=803; tryItOut("let x, x = (4277), x = ( /* Comment */x[6]-=({eval: (intern(this)) })), ebqtcx, w = x, \u3056 = (Math.imul(29, 11)), NaN = x, c = delete w.z;Array.prototype.sort.call(a2, (function() { try { v0 = a1[18]; } catch(e0) { } try { Array.prototype.forEach.apply(a2, [(function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { var r0 = 2 ^ 9; var r1 = a6 ^ a1; var r2 = a4 - a3; print(a1); var r3 = a4 % a1; var r4 = a7 ^ a1; var r5 = r0 + a5; var r6 = a4 & a3; var r7 = a3 & r4; var r8 = a7 / a0; var r9 = r1 ^ 1; var r10 = r3 & r4; var r11 = 2 * a8; var r12 = r1 ^ a3; var r13 = a8 / 2; a5 = 3 | a4; r0 = r3 | a3; var r14 = r3 + a3; var r15 = r6 / a8; var r16 = r8 * r3; var r17 = 1 * r16; var r18 = r5 + r13; var r19 = a1 - r18; a4 = x + a8; var r20 = r2 ^ 5; var r21 = r14 / 0; var r22 = 7 / r12; var r23 = r9 ^ r6; var r24 = 8 + r15; a4 = r9 % r0; var r25 = a1 - r6; var r26 = r9 % r19; a5 = 8 & 0; var r27 = 7 & a3; var r28 = 2 + r19; var r29 = 1 ^ x; var r30 = r27 / 9; var r31 = a0 * a4; r1 = a7 ^ 9; var r32 = 0 * 0; r20 = 1 + r18; r14 = a0 + 2; var r33 = x & r25; var r34 = a7 ^ r31; var r35 = r18 % 8; var r36 = r17 * 1; var r37 = r31 / 5; var r38 = 1 / r6; var r39 = 5 ^ a4; var r40 = r24 & r23; var r41 = r40 / r32; r26 = r32 - r41; var r42 = r5 ^ 7; var r43 = 6 ^ r17; var r44 = r42 ^ a5; var r45 = 8 % a2; var r46 = 6 / 9; var r47 = 3 / 9; var r48 = a2 % r21; var r49 = r32 + r20; var r50 = r1 + r41; var r51 = a3 + 2; var r52 = r44 / r47; var r53 = a6 - 2; var r54 = a4 + 9; var r55 = 1 * r51; var r56 = r10 / 8; var r57 = 4 * a2; print(r42); var r58 = 1 * r49; var r59 = r52 & r22; var r60 = r40 - 1; var r61 = r11 | r49; r39 = r22 / 5; var r62 = a1 ^ r47; var r63 = r43 + a2; return a5; })]); } catch(e1) { } v0 = evaluate(\"function o0.f1(p1) delete c.eval\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: ({lastIndexOf: \"\\u6E2B\",  set \"17\" w (x) { yield 5 }  }), noScriptRval: false, sourceIsLazy: true, catchTermination: false })); return b0; }), m0);");
/*fuzzSeed-221406266*/count=804; tryItOut("\"use strict\"; i2 + '';");
/*fuzzSeed-221406266*/count=805; tryItOut("mathy4 = (function(x, y) { return mathy2(Math.fround(Math.max((Math.max((y ? ( + Math.fround(mathy1(Math.fround(y), Math.fround(y)))) : (((Math.fround(( - Math.log2(y))) >>> 0) ? (x >>> 0) : (( + Math.asin(( + y))) >>> 0)) >>> 0)), -(2**53+2)) | 0), (Math.log10(Math.sin(y)) | 0))), ( + ((Math.fround(mathy1(Math.fround(0x100000000), Math.fround(Math.round(mathy3(( + y), x))))) && -0x100000001) >>> 0))); }); testMathyFunction(mathy4, /*MARR*/[new String(''), new Boolean(false), (1/0), new Boolean(false), (1/0), new String(''), -0x5a827999, new Boolean(false), new String(''), new Boolean(false), new Boolean(false), (1/0), new String(''), new String(''), (1/0), new Boolean(false), new String(''), new Boolean(false), new Boolean(false), new String(''), (1/0), (1/0), -0x5a827999, new String(''), new String(''), new String(''), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), new String(''), new String(''), -0x5a827999, new String(''), -0x5a827999, (1/0), new Boolean(false), -0x5a827999, new String(''), (1/0), new Boolean(false), (1/0), -0x5a827999, -0x5a827999, new Boolean(false), (1/0), new String(''), (1/0), -0x5a827999, (1/0), (1/0), new String(''), (1/0), new Boolean(false), new String(''), new String(''), new String(''), (1/0), new String(''), new String(''), -0x5a827999, -0x5a827999, -0x5a827999, (1/0), new Boolean(false), -0x5a827999, -0x5a827999, -0x5a827999, (1/0), -0x5a827999]); ");
/*fuzzSeed-221406266*/count=806; tryItOut("\"use strict\"; \"use asm\"; g0.offThreadCompileScript(\"if(x) { if (new x) {o2.a2.unshift(t0, o0);a1 = arguments.callee.caller.caller.caller.caller.caller.caller.arguments; } else {g0.__proto__ = e1; }}\", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: (null - new ((4277))(false, c%=-13)((4277), (allocationMarker()))), noScriptRval: false, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-221406266*/count=807; tryItOut("/*vLoop*/for (let yiuwyp = 0; yiuwyp < 36; ++yiuwyp) { var z = yiuwyp; {for (var p in f2) { try { a1 = arguments.callee.arguments; } catch(e0) { } v2 = new Number(-Infinity); } } } ");
/*fuzzSeed-221406266*/count=808; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + (( + (mathy1((Math.abs(x) >>> 0), (( - Math.trunc((y | 0))) >>> 0)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[new Number(1), x, x, new Number(1), x, new Number(1), objectEmulatingUndefined(), x, new Number(1), new Number(1), x, objectEmulatingUndefined(), x, x, x, new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1), new Number(1), x, objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), x, x, new Number(1), new Number(1), objectEmulatingUndefined(), x, new Number(1), x, new Number(1), x, objectEmulatingUndefined(), x, x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, new Number(1), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), x, new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), x, new Number(1), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), x, objectEmulatingUndefined(), x, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, new Number(1), new Number(1), x, x, new Number(1), x, new Number(1), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1), x, new Number(1), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), x, new Number(1), objectEmulatingUndefined(), x, x, new Number(1), new Number(1), objectEmulatingUndefined(), x, new Number(1), new Number(1), x, objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-221406266*/count=809; tryItOut("mathy1 = (function(x, y) { return (Math.asinh(mathy0(Math.min(y, y), (( ~ ( + Math.fround(Math.min(x, ((Math.pow(x, -0x080000000) % y) >>> 0))))) | 0))) >>> 0); }); ");
/*fuzzSeed-221406266*/count=810; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(?!\\\\\\u0087(?=[^\\\\x3f-\\\\\\ud6be\\\\d]|\\\\u345B[^]))?|.(?=.)|[]{32768,32771}+?*)\", \"\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-221406266*/count=811; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -17592186044417.0;\n    return (((i2)-(c = z)-(!(!(i1)))))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-221406266*/count=812; tryItOut("/*infloop*/do {var icmkay = new SharedArrayBuffer(8); var icmkay_0 = new Uint32Array(icmkay); var icmkay_1 = new Uint8ClampedArray(icmkay); icmkay_1[0] = 0; var icmkay_2 = new Uint32Array(icmkay); icmkay_2[0] = -7; i1.send(o1.e0);f0(i0);a1.splice(NaN, v2, o0, i1, -0);\n(undefined);\nb1.__proto__ = v1; } while(\"\\uEA15\");");
/*fuzzSeed-221406266*/count=813; tryItOut("\"use strict\"; Object.preventExtensions(i1);function c(y, x) { return (void shapeOf(x)) } (4277);");
/*fuzzSeed-221406266*/count=814; tryItOut("\"use strict\"; x.message;");
/*fuzzSeed-221406266*/count=815; tryItOut("\"use strict\"; switch(x) { case 1: for (var v of m1) { try { s0 += s0; } catch(e0) { } try { g2.e2.add(g2); } catch(e1) { } try { v2 = evalcx(\"m2.set(b2, o1.g0.i2);\", o1.o2.g2.g0); } catch(e2) { } f2(h1); }break; case 1: e0.has(this.g0.p2);break; default: (\"\\u0685\");break; g0.offThreadCompileScript(\"o1 + h0;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 != 0), noScriptRval: true, sourceIsLazy: (x % 6 == 0), catchTermination: this }));case this: break; (\"\\uF466\");break; case 4: print(x);case 9: break; print(x);break; break; case x: case 0: break; break; new RegExp(\"[^]|[\\\\W6-\\ufef9]\\\\b{1,}|(?=[^])?*|(?=^)\", \"gyim\");break; case 5: break L;break; break; print(null);break;  }");
/*fuzzSeed-221406266*/count=816; tryItOut("\"use strict\"; /*infloop*/do {/*RXUB*/var r = /(?!(?:(?=^\\A+([^]|\\B)+\\D{3,}+)))/m; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); p2 + i1; } while(yield 1);");
/*fuzzSeed-221406266*/count=817; tryItOut("a0 + e1;");
/*fuzzSeed-221406266*/count=818; tryItOut("/*infloop*/for(let w; new RegExp(\"($)?\", \"i\") ? \"\u03a0\" :  '' ; ) {i1.next(); }");
/*fuzzSeed-221406266*/count=819; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-221406266*/count=820; tryItOut("with('fafafa'.replace(/a/g, (function ([y]) { })())){h0 = {};let c = x;Object.defineProperty(this, \"s0\", { configurable: false, enumerable: false,  get: function() {  return new String(this.e1); } }); }");
/*fuzzSeed-221406266*/count=821; tryItOut("e2.add((makeFinalizeObserver('tenured')));");
/*fuzzSeed-221406266*/count=822; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.pow(Math.cos((mathy0(((Math.min(( + x), ( + Math.sinh((y % Number.MAX_VALUE)))) | 0) >>> 0), (((y ? Math.fround(mathy2(x, Math.atan2(y, Math.fround(( ~ Math.fround(x)))))) : (x | 0)) | 0) >>> 0)) >>> 0)), (Math.fround(Math.asinh(( ! x))) >= (Math.sign(y) , (y * mathy0(-Number.MIN_VALUE, x))))); }); ");
/*fuzzSeed-221406266*/count=823; tryItOut("a1 = arguments;");
/*fuzzSeed-221406266*/count=824; tryItOut("\"use strict\"; a1.forEach(f0);function a(NaN, w) { v1 = Object.prototype.isPrototypeOf.call(s2, this.h1); } for(\u3056 =  /x/g  in new RegExp(\"(.?){4,8388612}|\\\\3*+?\", \"\")) {Array.prototype.splice.call(a0, 17, 8); }");
/*fuzzSeed-221406266*/count=825; tryItOut("o1 = t1[v0];");
/*fuzzSeed-221406266*/count=826; tryItOut("var r0 = x + x; var r1 = r0 % 1; var r2 = x - x; var r3 = r0 % 8; x = x + r2; var r4 = 4 ^ x; r3 = r0 + x; var r5 = 3 * r4; r5 = 1 / x; var r6 = x & r1; var r7 = r1 ^ x; var r8 = r1 & r3; r8 = r0 ^ r4; var r9 = r1 * r4; var r10 = 3 % 6; var r11 = 2 ^ r0; var r12 = 4 + r4; r5 = 8 * r9; var r13 = r0 * r4; var r14 = r6 * 4; var r15 = r5 ^ r2; r10 = r9 - r14; var r16 = r7 - r14; print(r12); r11 = r16 * r12; var r17 = 4 + 8; var r18 = r9 * 8; r13 = 6 * r17; var r19 = r7 * r8; var r20 = 7 - r10; var r21 = 1 & r17; var r22 = 5 & 2; var r23 = r17 & r3; var r24 = r7 + x; var r25 = r2 | r15; var r26 = 5 + 9; var r27 = r0 - r19; var r28 = r0 * r2; var r29 = r27 / r10; print(r18); var r30 = 8 + 3; var r31 = 7 & r23; var r32 = 3 ^ r18; r20 = 9 % r11; r15 = r31 - r16; r20 = r26 & r1; var r33 = r30 + r20; var r34 = r14 + 3; var r35 = 1 | 1; var r36 = r4 | 1; r2 = 5 ^ r23; var r37 = 0 / 2; var r38 = r30 - 3; var r39 = r26 ^ r18; r4 = 9 + r1; var r40 = 2 % r22; var r41 = r34 * r22; var r42 = r37 % 5; r12 = 0 / 8; r4 = r23 | r22; var r43 = r32 + 9; ");
/*fuzzSeed-221406266*/count=827; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.max(( + (Math.fround(((y ? Math.log2(( + Math.log(-(2**53+2)))) : 0/0) >>> 0)) === Math.fround(mathy2(( + ( ! Math.fround((Math.ceil((0x07fffffff >>> 0)) >>> 0)))), ( + mathy0(x, -0)))))), Math.log1p(((Math.acosh((Math.fround(x) >>> Math.fround((y ? -Number.MAX_VALUE : (2**53-2 >>> 0))))) >>> 0) === y))); }); testMathyFunction(mathy3, /*MARR*/[{}, new String('q'),  '' , new String('q'), new String('q'),  '' , {}]); ");
/*fuzzSeed-221406266*/count=828; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      return ((-(0xe51f2895)))|0;\n    }\n    return ((-0x4207b*(0x2df8c53)))|0;\nv0 = a0.reduce, reduceRight((function() { for (var j=0;j<37;++j) { o1.f0(j%4==0); } }), c);    {\n      d1 = (+((((0xffffffff) ? (0x6687d0c7) : (!(0x80aee74)))) >> ((!(0x2996893d))-(((((0x8d32ed1)*-0xbf919)) & ((0x1d3279ec) % (0xc0960289))) >= (((0x2177e997) % (0x5533ef5c))|0))+((((((new RegExp(\"[\\\\u0093-\\\\u7050\\\\d\\\\w]\", \"gi\") = Math.imul(this, \"\\u5A0B\"))))+(0x45673ff3)) >> ((0x34e0019a) % (0x745b105d)))))));\n    }\n    return ((((/*FFI*/ff(((~~(+pow(((-((+pow(((-17179869183.0)), ((17592186044417.0))))))), ((d1)))))), ((d1)), ((d1)), ((((0x68ea1d3))|0)), ((imul((-0x8000000), (0xdb67b6ee))|0)))|0) ? (/*FFI*/ff(((((Int8ArrayView[1])) << (((((0xb860dae4))>>>((0xd872a1ff))))-(0xdf12582e)))), (((((-36893488147419103000.0) > (-137438953473.0))-(-0x8000000)) & (0x14b4f*(-0x8000000)))), (((Uint8ArrayView[4096]))), ((d0)), ((makeFinalizeObserver('tenured'))), ((((0x5a8f67e1)))), ((1.2089258196146292e+24)), ((-1099511627776.0)), ((-9007199254740992.0)), ((129.0)), ((-7.555786372591432e+22)), ((-281474976710657.0)), ((0.0009765625)), ((1025.0)), ((4611686018427388000.0)), ((73786976294838210000.0)))|0) : ((Int8ArrayView[((/*FFI*/ff((((Float32ArrayView[4096]))))|0)+(0xedd40176)-(-0x8000000)) >> 0])))))|0;\n  }\n  return f; })(this, {ff: String.prototype.toLocaleLowerCase}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000001, 0.000000000000001, -0, Math.PI, 0x07fffffff, 1, 0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 42, -(2**53), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53+2, -0x100000000, 2**53-2, -Number.MIN_VALUE, 0/0, 0x0ffffffff, -0x080000000, 1/0, -0x0ffffffff, 0, -0x080000001, -0x07fffffff, 2**53, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-221406266*/count=829; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=830; tryItOut("with(x)/*vLoop*/for (uwuixi = 0; uwuixi < 29; ++uwuixi) { var c = uwuixi; print(c); } ");
/*fuzzSeed-221406266*/count=831; tryItOut("\"use asm\"; /*RXUB*/var r = /(?:[^])/gym; var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-221406266*/count=832; tryItOut("a2.splice(NaN, v2);");
/*fuzzSeed-221406266*/count=833; tryItOut("o2.a0 = a0.filter((function() { for (var j=0;j<11;++j) { f1(j%4==1); } }), g0);");
/*fuzzSeed-221406266*/count=834; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?!.\\\\B|[^]{3,5}+)(?![\\\\cI\\\\D\\\\n][^]{0,3}|\\\\B\\\\1+?|\\u5aef|(?=\\\\B^){3}))\", \"i\"); var s = \"\\u001d \\u0019\\n\\n\\n\\n\\n \\u0019\\n\\n\\n\\n\\n \\u0019\\n\\n\\n\\n\\n\"; print(uneval(s.match(r))); \nprint((z instanceof a));\n");
/*fuzzSeed-221406266*/count=835; tryItOut("return x;");
/*fuzzSeed-221406266*/count=836; tryItOut("g0.toString = (function() { v2 = r0.toString; return t2; });");
/*fuzzSeed-221406266*/count=837; tryItOut("\"use strict\"; //h\nprint( '' );\na2 = new Array;\n");
/*fuzzSeed-221406266*/count=838; tryItOut("\"use strict\"; break L;(\"\\u9E4A\");");
/*fuzzSeed-221406266*/count=839; tryItOut("/*infloop*/L:for(x; (void version(185)); intern([1])) print(x);");
/*fuzzSeed-221406266*/count=840; tryItOut("e2.delete([z1]);\nprint(x);\n");
/*fuzzSeed-221406266*/count=841; tryItOut("{ void 0; fullcompartmentchecks(false); }");
/*fuzzSeed-221406266*/count=842; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=843; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! ( + (Math.fround(Math.sin(( ! (Math.fround(x) >> Math.fround(x))))) !== Math.fround(Math.fround(( ! ((( + Math.acos(( + x))) / Math.clz32(( + ( ~ y)))) | 0))))))); }); testMathyFunction(mathy3, [null, (new Number(-0)), objectEmulatingUndefined(), false, 0.1, [0], '\\0', ({valueOf:function(){return 0;}}), NaN, (new Boolean(true)), /0/, (new Number(0)), (new Boolean(false)), [], '', 0, 1, undefined, -0, '/0/', true, (new String('')), '0', ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (function(){return 0;})]); ");
/*fuzzSeed-221406266*/count=844; tryItOut("for (var v of g2) { try { s0 += s2; } catch(e0) { } a2 = r0.exec(this.s1); }function x(...b)\"use asm\";   var abs = stdlib.Math.abs;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((abs(((0x31dda*(0x78b8a446)) ^ (-0xacb8d*(-0x8000000))))|0))))|0;\n  }\n  return f;g2.offThreadCompileScript(\"e2 + '';\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: -19, noScriptRval: false, sourceIsLazy: false, catchTermination: true }));\n/*tLoop*/for (let e of /*MARR*/[new Boolean(false), -Number.MIN_VALUE, new Boolean(false), new Boolean(false), (4277), (4277), -Number.MIN_VALUE, -Number.MIN_VALUE, (4277), (0/0), new Boolean(false), -Number.MIN_VALUE]) { e1.add(m2); }\n");
/*fuzzSeed-221406266*/count=845; tryItOut("\"use strict\"; \"use asm\"; t1 = new Int16Array(b1);");
/*fuzzSeed-221406266*/count=846; tryItOut("let d =  /x/g ;Object.defineProperty(this, \"v0\", { configurable: (d % 3 != 1), enumerable: true,  get: function() { Object.prototype.watch.call(e2, \"toSource\", (function() { for (var j=0;j<13;++j) { f2(j%5==1); } })); return r1.toString; } });");
/*fuzzSeed-221406266*/count=847; tryItOut("\"use strict\"; sruyug;g1.v2 = g0.runOffThreadScript();");
/*fuzzSeed-221406266*/count=848; tryItOut("\"use strict\"; /*MXX1*/o2 = g1.ReferenceError;print(\"\\uB7A4\");");
/*fuzzSeed-221406266*/count=849; tryItOut("switch(\u000c(4277) >= Math.hypot(2501635172, z)) { case ((throw \"\\uA8D7\").yoyo('fafafa'.replace(/a/g, function(y) { \"use strict\"; yield y; this.o2.__proto__ = m0;; yield y; }))): Array.prototype.splice.apply(a2, [NaN, 3]);break; case (4277): v1 = (f1 instanceof t2);print(x);default: (void schedulegc(o2.g2));h0 + '';break; case 5: break; case (arguments = x): print(x);print(x);break; case 4: break; case (4277): let (x, x = \"\\u28EE\", akrqdi, hujnpr, qestug) { (window >= z); }break; case 6: case 2:  }");
/*fuzzSeed-221406266*/count=850; tryItOut("b1 + i2;");
/*fuzzSeed-221406266*/count=851; tryItOut("/*RXUB*/var r = /\\3/m; var s = \"0\"; print(s.replace(r, window)); ");
/*fuzzSeed-221406266*/count=852; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.sign(((Math.min(mathy1((Math.atan2((uneval(window)), -7)), y), (Math.atan2(( ! Math.fround(y)), x) ? ( ~ Math.max(y, 0x100000001)) : Math.imul(x, (Math.min(Math.asin(y), Math.atan2((x = new (objectEmulatingUndefined)() >>> 0), (x >>> 0))) | 0)))) | 0) | 0))); }); ");
/*fuzzSeed-221406266*/count=853; tryItOut(";\na2.shift();\n");
/*fuzzSeed-221406266*/count=854; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var sin = stdlib.Math.sin;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -1025.0;\n    i2 = (0x5486e7fa);\n    d1 = (+pow(((Float64ArrayView[((/*FFI*/ff(((\n-4)))|0)) >> 3])), ((-((+(-1.0/0.0)))))));\n    {\n      {\n        d1 = (((d3)) % ((+((d3)))));\n      }\n    }\n    return +((+sin(((+(~((((((2305843009213694000.0) < (8796093022208.0))+(!(/*FFI*/ff()|0)))>>>((Int8ArrayView[1]))) == (0xffffffff)))))))));\n    (Float64ArrayView[((/*FFI*/ff()|0)+(/*FFI*/ff((((((0x0) == (0xedee26b0))) | ((0x778f92ce) % (0x15abf911)))), ((((-1.1805916207174113e+21)) - ((-9.0)))), ((+((-140737488355329.0)))), ((-147573952589676410000.0)), ((6.044629098073146e+23)), ((-1.888946593147858e+22)))|0)+(0x9e9607f4)) >> 3]) = ((+/*FFI*/ff(((d1)), ((d3)))));\n    i2 = ((0x5caa536c) < (abs((imul((0x1d5f40f2), (!(0x5bba0f3e)))|0))|0));\n    /*FFI*/ff(((((((0xb245e0e5) ? (-8388609.0) : (-4.835703278458517e+24)) < (d3))-(-0x3100d57)) ^ ((i2)))), ((imul((0xac74a81e), ((0x9f24beaa) ? ((0xbdf5484f) == (0xd9166508)) : ((0xa41d6a98) != (0x5ff7ec91))))|0)), (((((-8193.0) == (-7.737125245533627e+25))+(0xffffffff)) >> ((((0xfea931bc))>>>((0xe63eb264))) % (((-0x8000000))>>>((0x8c3afac9)))))));\n    (Float64ArrayView[((i2)-(0x926cbba4)) >> 3]) = ((((\u3056 -= x)((y) = false, true))));\n    {\n      {\n        d3 = (-64.0);\n      }\n    }\n    return +((d3));\n  }\n  return f; })(this, {ff: Array.prototype.forEach}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53+2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, 0x07fffffff, 2**53+2, Math.PI, 1, -0x100000000, -0x080000000, Number.MAX_VALUE, 2**53-2, 0/0, -(2**53), 2**53, 0x100000000, 1/0, -0x100000001, 0, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -(2**53-2), -0, -0x080000001, -1/0, 0x080000000]); ");
/*fuzzSeed-221406266*/count=855; tryItOut("/* no regression tests found */\n(let (a =  /x/g ) window);");
/*fuzzSeed-221406266*/count=856; tryItOut("/*RXUB*/var r = /[^\\s\\u00fd-\\ub45A]/gm; var s = \"\\ub45a\"; print(s.search(r)); ");
/*fuzzSeed-221406266*/count=857; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.max(((Math.imul(Math.fround(( - Math.max(mathy1((Math.asinh(1) | 0), y), (x % y)))), (Math.max(Number.MAX_VALUE, ( + Math.sin(x))) <= ((Math.hypot(Math.fround(Math.expm1(x)), y) ** Math.hypot(Math.fround(Math.fround(((y | 0) ? x : x))), Math.imul(( ! (y | 0)), y))) >>> 0))) >>> 0) >>> 0), ( + Math.atan2(Math.fround(Math.fround(( - Math.fround((Math.atan2(( + y), (mathy1(y, 0.000000000000001) | 0)) | 0))))), ( ~ -Number.MAX_SAFE_INTEGER)))) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 1/0, 0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 42, -(2**53-2), -Number.MIN_VALUE, -0x100000001, 0, 0x0ffffffff, -0x0ffffffff, -(2**53), 0x07fffffff, -0, 2**53, Number.MAX_VALUE, -0x100000000, -1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, 0/0, Math.PI, -0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 1, 2**53+2, -(2**53+2), 0.000000000000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-221406266*/count=858; tryItOut("\"use strict\"; /*oLoop*/for (let ijlkxh = 0; (new String((void options('strict')).unwatch((let (x) \"\\u36FF\")),  /* Comment */ '' )) && ijlkxh < 4; ++ijlkxh) { /*infloop*/for(let (/(?!(?=(?:.)?)){3,6}/yim)(false) in ((String.prototype.padStart)((uneval(Object.defineProperty(x, \"0\", ({}))))))){return a + window; } } ");
/*fuzzSeed-221406266*/count=859; tryItOut("\"use strict\"; /*hhh*/function isfmog(...w){t2 = new Uint8ClampedArray(t0);function e(x, x) { return new RegExp(\"\\\\2\", \"ym\") } for (var v of g1.v1) { try { this = g0.a0[ '' ]; } catch(e0) { } g0.a0.sort((function() { a0 = []; return o1; })); }}/*iii*/m2.has(s2);");
/*fuzzSeed-221406266*/count=860; tryItOut("ueqfsq(x, (/*UUV2*/(y.resolve = y.codePointAt)));/*hhh*/function ueqfsq(x){return x;}");
/*fuzzSeed-221406266*/count=861; tryItOut("h1.enumerate = f0;");
/*fuzzSeed-221406266*/count=862; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.pow(Math.ceil(y), Math.pow(Math.min((x | 0), (( + (-(2**53-2) | 0)) | 0)), ((((Math.fround(Math.sign(Math.fround(0x080000001))) >>> 0) ? (-Number.MAX_VALUE >>> 0) : (y >>> 0)) >>> 0) | 0))) * new \"\\uE7A2\"(\"\\u760E\", -6)((y++), new RegExp(\"\\\\3{0,}\", \"\"))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 1.7976931348623157e308, 0/0, Number.MIN_VALUE, 2**53-2, 0x07fffffff, 42, -0x100000000, -1/0, Math.PI, 0x0ffffffff, -0x080000000, 0, -0x080000001, 1/0, -(2**53), 0x100000000, -(2**53+2), 0x080000000, 0.000000000000001, 0x100000001, 2**53, Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, 1, 0x080000001, -0x07fffffff, -Number.MIN_VALUE, -(2**53-2), 2**53+2]); ");
/*fuzzSeed-221406266*/count=863; tryItOut("testMathyFunction(mathy5, [-0, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -1/0, 1, 0x080000000, 42, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -0x080000001, 2**53, -0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -0x07fffffff, -(2**53), 2**53-2, 0, -0x100000001, 2**53+2, 0x0ffffffff, 0x07fffffff, Math.PI]); ");
/*fuzzSeed-221406266*/count=864; tryItOut("\"use strict\"; v2 = this.t2.length;");
/*fuzzSeed-221406266*/count=865; tryItOut("\"use strict\"; for (var v of m2) { /*MXX1*/o1 = g1.Object.prototype.__lookupGetter__; }");
/*fuzzSeed-221406266*/count=866; tryItOut("\"use asm\"; testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), -0, ({toString:function(){return '0';}}), (function(){return 0;}), (new Number(-0)), '/0/', '\\0', 0, undefined, true, 1, [0], false, objectEmulatingUndefined(), 0.1, null, (new Number(0)), /0/, (new String('')), [], (new Boolean(false)), (new Boolean(true)), '', ({valueOf:function(){return 0;}}), NaN, '0']); ");
/*fuzzSeed-221406266*/count=867; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return ((((0x4ea1a0d5) != (0xbaca2612))))|0;\n    i0 = (/*FFI*/ff(((NaN)), ((((i0)-((d1) < (d1))) & ((((i0))|0) / (~~(((Float64ArrayView[0])) % ((+(-1.0/0.0)))))))), ((-0xc0cb6*(i0))), ((131073.0)), ((1073741823.0)), ((d1)), ((d1)))|0);\n    return (((Int8ArrayView[0])))|0;\n    (Uint8ArrayView[((0x126f0d5e)) >> 0]) = (((0x9748d254)));\n    (Int16ArrayView[((Uint8ArrayView[0])) >> 1]) = (((~((i0)))));\n    {\n      i0 = (-0x8000000);\n    }\n    {\n      {\n        (Int8ArrayView[0]) = ((i0));\n      }\n    }\n    d1 = (+(-1.0/0.0));\n    return ((((((0xd806255f)) ^ ((/*FFI*/ff(((((-3.094850098213451e+26)) % ((Float64ArrayView[1])))), ((-2199023255553.0)), ((-2251799813685249.0)), (((33554431.0) + (-4.722366482869645e+21))), ((-72057594037927940.0)), ((-0.125)), ((-1.1805916207174113e+21)))|0)+(0x8d8915ee))))+((+/*FFI*/ff(((+abs(((+(-1.0/0.0)))))), ((NaN)), ((-1.015625)), ((d1)), ((((0x91a188d0)) >> ((0xa66ee971)))), ((d1)), ((9223372036854776000.0)))) != (((-2097153.0)) - ((d1))))))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, -1/0, 42, Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, -(2**53), -0x100000000, 0x080000001, 2**53-2, -(2**53-2), -0x080000001, -0x100000001, -Number.MAX_VALUE, 0, 0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, 1, 0.000000000000001, -0, Math.PI, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=868; tryItOut("testMathyFunction(mathy0, [Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -1/0, 0/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, 0x080000001, 1.7976931348623157e308, -0x080000000, 2**53-2, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -0x080000001, 1, -0x100000000, 2**53, -(2**53-2), -0, 0x080000000]); ");
/*fuzzSeed-221406266*/count=869; tryItOut("\"use strict\"; false <= false;");
/*fuzzSeed-221406266*/count=870; tryItOut("mathy4 = (function(x, y) { return ( + ( ! ( + ( - (Math.trunc((Math.atan2(( + mathy2(( + 2**53-2), ( + y))), -1/0) | 0)) | 0))))); }); ");
/*fuzzSeed-221406266*/count=871; tryItOut("\"use strict\"; v2 = r1.toString;\n/*infloop*/while(Math){a0 = [];(19); }\n");
/*fuzzSeed-221406266*/count=872; tryItOut("mathy4 = (function(x, y) { return Math.sign(Math.imul(Math.asin(( + ( ! ( + mathy3(( + x), ( + x)))))), ( + Math.min(Math.fround((Math.fround(x) + Math.fround(x))), Math.fround(Math.max((x >>> Math.fround(Math.max(Math.fround(y), ( + -Number.MIN_VALUE)))), x)))))); }); testMathyFunction(mathy4, [2**53, Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, -0x0ffffffff, 42, 0x080000001, -Number.MIN_VALUE, 2**53-2, -0, -0x07fffffff, -0x100000000, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 1, 0x07fffffff, 1/0, 0x0ffffffff, 0x080000000, 0, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), Number.MAX_VALUE, -0x100000001, 0/0, 1.7976931348623157e308, -0x080000001, -0x080000000, Math.PI]); ");
/*fuzzSeed-221406266*/count=873; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=874; tryItOut("\"use strict\"; r0 = /(?!(?!\\w\\W{4}))?/g;");
/*fuzzSeed-221406266*/count=875; tryItOut("/*vLoop*/for (rnzcmj = 0; rnzcmj < 6; ++rnzcmj) { z = rnzcmj; for (var p in o0) { try { m1.get(p0); } catch(e0) { } v0 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: (x / d), element: g0.o2, sourceMapURL: s0 })); } } ");
/*fuzzSeed-221406266*/count=876; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Math.PI, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -(2**53+2), 2**53-2, -0x07fffffff, 2**53, 0x100000001, 1/0, 0x07fffffff, -0x080000001, -(2**53-2), 0/0, 0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 42, -0, 0x080000001, 1.7976931348623157e308, -1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, 2**53+2, -(2**53), 0x100000000, 0.000000000000001, -Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-221406266*/count=877; tryItOut("with({x:  /x/g .watch(\"cbrt\", ({a2:z2}))})Array.prototype.forEach.call(a0, (function() { try { var o1.v2 = t1.BYTES_PER_ELEMENT; } catch(e0) { } try { o2.i2 + i1; } catch(e1) { } this.v1 = g1.a0.length; return g1; }), a = Proxy.createFunction(({/*TOODEEP*/})({}), Math.cos,  /x/ ));");
/*fuzzSeed-221406266*/count=878; tryItOut("a0[({valueOf: function() { for (var v of h0) { try { a1 + ''; } catch(e0) { } try { for (var v of v0) { try { i0.send(e1); } catch(e0) { } try { v0 = t2.length; } catch(e1) { } try { /*RXUB*/var r = r0; var s = g1.s2; print(r.test(s)); print(r.lastIndex);  } catch(e2) { } s2 += 'x'; } } catch(e1) { } v0 = 4.2; }return 0; }})] =  /x/g \n;function w(...x)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n;;    return (((!(0x16fdb1c))-((((i1)+((0x359e50f0) == (((0x9b6427ea) / (0x523ee207))>>>((i1))))) >> (((~~(d0)))-(i1))))))|0;\n  }\n  return f;m0.has(f2);");
/*fuzzSeed-221406266*/count=879; tryItOut("/*RXUB*/var r = new RegExp(\"[]?\", \"yim\"); var s = \"\\ud502\"; print(r.test(s)); ");
/*fuzzSeed-221406266*/count=880; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 4.835703278458517e+24;\n    {\n      d1 = (((-((x)))) % ((Float32ArrayView[((0xffffffff)) >> 2])));\n    }\n    return +((uneval(intern(function ([y]) { }))));\n  }\n  return f; })(this, {ff: Uint8ClampedArray}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-221406266*/count=881; tryItOut("/*vLoop*/for (let nfjtwx = 0; nfjtwx < 2; ++nfjtwx) { const e = nfjtwx; g1.offThreadCompileScript(\"h1.toString = (function() { try { Object.prototype.unwatch.call(o0.h2, \\\"0\\\"); } catch(e0) { } try { g1.v0 = evalcx(\\\"\\\\\\\"\\\\\\\\u61D0\\\\\\\";\\\", o1.g1); } catch(e1) { } i2 = a0.values; return this.s2; });\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce:  \"\" , noScriptRval: (e % 3 != 0), sourceIsLazy: false, catchTermination: false })); } ");
/*fuzzSeed-221406266*/count=882; tryItOut("a2.sort((function() { for (var j=0;j<123;++j) { f2(j%3==0); } }), this.m2);");
/*fuzzSeed-221406266*/count=883; tryItOut("Array.prototype.splice.call(this.a1, 2, 10);");
/*fuzzSeed-221406266*/count=884; tryItOut("\"use strict\"; o0.m2.has(p1);");
/*fuzzSeed-221406266*/count=885; tryItOut("e1.add(t1);");
/*fuzzSeed-221406266*/count=886; tryItOut("Array.prototype.push.call(a0, b0);");
/*fuzzSeed-221406266*/count=887; tryItOut("for (var v of o0) { t0 = new Uint8Array(13); }");
/*fuzzSeed-221406266*/count=888; tryItOut("testMathyFunction(mathy1, /*MARR*/[ /x/ , function(){}, function(){}, function(){}, false,  /x/ , function(){},  /x/ , function(){}, function(){},  /x/ , false, false, false,  /x/ , function(){}, false,  /x/ , false, false, false, false, false, false, false, false, false, false, false,  /x/ , function(){}, function(){}, function(){},  /x/ , function(){},  /x/ ,  /x/ ,  /x/ , false, function(){}, function(){}, false, false, false, false, false, false, false, false, false,  /x/ ,  /x/ , function(){}, false, false, function(){}, false,  /x/ ,  /x/ , false, function(){}, function(){}, function(){},  /x/ ,  /x/ ,  /x/ , false, false, false,  /x/ , function(){}, function(){}, false,  /x/ , function(){}, function(){},  /x/ , function(){}, false,  /x/ ,  /x/ , false, function(){},  /x/ , function(){},  /x/ ,  /x/ , function(){}, function(){}, function(){}, false, function(){},  /x/ , function(){}, function(){}, false, false, function(){}, false, function(){},  /x/ , false, function(){}, false, function(){}, false, false, false, function(){}, function(){}, function(){},  /x/ , false, function(){},  /x/ , function(){}, false, function(){}, function(){}]); ");
/*fuzzSeed-221406266*/count=889; tryItOut("o1.o2 = {};");
/*fuzzSeed-221406266*/count=890; tryItOut("a2.splice(10, v1, g0);");
/*fuzzSeed-221406266*/count=891; tryItOut("/*vLoop*/for (mafjwc = 0, a, x; mafjwc < 66; ++mafjwc) { let d = mafjwc; return this; } ");
/*fuzzSeed-221406266*/count=892; tryItOut("switch(Math.imul((p={}, (p.z = (new (Boolean)(this)))()), 3826796120)) { default: case 6: erjzor();/*hhh*/function erjzor(){print(x);}break; case 3:  }");
/*fuzzSeed-221406266*/count=893; tryItOut("/*RXUB*/var r = /(?!\\1\\2{1073741823}(?:[]){4}[^\\n\\W]*[\\\ubb7d\\\uf02b\\f-\\u2E67\u00e7-\ub953]{3,6}){1,1}/gi; var s = \"\"; print(s.replace(r, '', \"gyi\")); ");
/*fuzzSeed-221406266*/count=894; tryItOut("\"use strict\"; selectforgc(o2.g0.o1);");
/*fuzzSeed-221406266*/count=895; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -4611686018427388000.0;\n    return (((i1)+(i2)))|0;\n  }\n  return f; })(this, {ff: undefined}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53), 0x0ffffffff, 2**53-2, -0x080000000, 1/0, -Number.MIN_VALUE, 0x080000000, 2**53+2, 0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, 0/0, -1/0, -0x080000001, Math.PI, 0, -0, 0x080000001, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0x100000001, 1, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, 2**53, Number.MIN_VALUE, -(2**53-2), -0x100000000]); ");
/*fuzzSeed-221406266*/count=896; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    return +((+(0x2333041f)));\n  }\n  return f; })(this, {ff: Array.prototype.some}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, -0, 0x100000000, 2**53, 0x100000001, 0x07fffffff, 1.7976931348623157e308, 2**53-2, -0x07fffffff, -(2**53-2), 1, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, -(2**53+2), 0x080000000, 0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 0x080000001, 0.000000000000001, -0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, -1/0, 0/0, 42, -0x100000000, 2**53+2, 1/0, -0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=897; tryItOut("\"use strict\"; b2 = new ArrayBuffer(144);");
/*fuzzSeed-221406266*/count=898; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3+?\", \"gim\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=899; tryItOut("\"use strict\";  for  each(let c in 'fafafa'.replace(/a/g, mathy4)) {L:if(true) { if (w = Proxy.create(({/*TOODEEP*/})(true), ({a2:z2}))) {print(c); } else {print(c);a2.push(p0, v0, undefined, b0, o1); }} }");
/*fuzzSeed-221406266*/count=900; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var exp = stdlib.Math.exp;\n  var asin = stdlib.Math.asin;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var sqrt = stdlib.Math.sqrt;\n  var ceil = stdlib.Math.ceil;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Int16ArrayView[(((Infinity) != ((d1) + (d1)))*-0x7da9e) >> 1]) = ((abs(((/*FARR*/[true].filter) in (4277)))|0) % ((((+exp(((d1)))) >= (((((-0x8000000)-(0x81c40d7e)))) % ((2251799813685249.0))))*0x45a2c) & (-0x5406f*(i0))));\n    return (((i0)+((+asin(((d1)))) <= (+pow(((-4097.0)), ((Float32ArrayView[2])))))))|0;\n    i0 = (0xb52ee58f);\n    d1 = (((((524289.0)) / ((d1)))) % ((d1)));\n    return ((((((0xb4f7fea3)-(i0))|0) > (~~(-17592186044417.0)))))|0;\n    i0 = (0x878582d5);\n    i0 = (i0);\n;    {\n      (Uint8ArrayView[((i0)) >> 0]) = ((0xfcd8816f));\n    }\n    d1 = (d1);\n    i0 = (i0);\n    {\n      (Float32ArrayView[((((0xffffffff)*-0xbf607)>>>((0xb9761a25)+(0x923072cf)-(-0x8000000))) % ((-0xfffff*(0xfd87f41d))>>>((i0)))) >> 2]) = ((-1.1805916207174113e+21));\n    }\n    d1 = (d1);\n    {\n      i0 = (i0);\n    }\n    d1 = (d1);\n    {\n      (Int32ArrayView[1]) = ((Int16ArrayView[(-0xaf5b8*(0x78604f2c)) >> 1]));\n    }\n    (Float32ArrayView[((abs((((i0)) ^ ((0x30b1a54d) / (0xfa2b607))))|0) % ((((((0x1007bb69))>>>((0xa67d09bb)))))|0)) >> 2]) = ((+(((0x38dccf7d)+(i0))>>>(0x3e8e9*((d1) >= (((NaN)) / ((1.0625))))))));\n    i0 = ((~((((-(!((1.00390625) != (-36028797018963970.0)))) & ((0x37714eba) % (0x0))) < (((0x6dd8e530)-((0x6b41f0ff) >= (0x59c1b988))-(0xfaaa0ff9)) >> ((-0x8000000)+((0x7fffffff))))))) != ((((abs((((0x5d063773)) >> ((0xf140f206))))|0) < (0x3de42f78))+(i0)) << ((i0))));\n    switch ((((0xfc05b35c))|0)) {\n      case -3:\n        d1 = (((-6.044629098073146e+23)) * ((+(-1.0/0.0))));\n        break;\n      case -2:\n        d1 = (((1.1805916207174113e+21)) / ((+(((~(-0xfc4fd*(0x7668682d))) / (((0x0) % (0x79b1efe5)) | ((0x3d7622f0) % (0x7fffffff)))) | ((i0)*0xe0127)))));\n        break;\n      case -1:\n        d1 = (+/*FFI*/ff(((((+sqrt(((Float32ArrayView[(((-0x745e103) ? (0x3ed75917) : (0xf9700af7))-(i0)) >> 2])))) + (d1)) + ((+(1.0/0.0)) + (-17592186044415.0)))), ((~(((abs((~((0xa95bf6ed) / (((0x526d0589))>>>((0x2e5e9c72))))))|0) != (((i0)+((-1.25) == (268435457.0))) | (((NaN) > (+ceil(((-134217728.0))))))))))), ((-4.835703278458517e+24)), ((((((0xde9f62eb))>>>((0x51f3bc3d)))) ? (d1) : (35184372088833.0)))));\n        break;\n    }\n    {\n      i0 = ((((i0))>>>((i0)+(((new x()))))) <= (((0xc21e0cc1)-((0xff735db6) ? (i0) : (i0)))>>>((/*FFI*/ff(((+atan2(((((/*FFI*/ff(((d1)))|0)+(((+(((0x610af3f4))>>>((0xffffffff))))))))), ((590295810358705700000.0))))))|0))));\n    }\n    (Math.cbrt(-1)) = ((-1.00390625));\n    i0 = (0xfa890c6d);\n    d1 = (140737488355327.0);\n    return (((((((0xff909676)) | ((0xfb16b77c)-(0xf9c24050))) >= (abs((((0x9d4e0e8f)-(0xfc24bff4))|0))|0)) ? ((((Uint8ArrayView[2])) >> ((i0)+(0x64a035df)))) : (i0))-(0x58514348)+((0xffffffff))))|0;\n  }\n  return f; })(this, {ff: ({ get prototype(this = [[1]], w) { return \"\\u513B\" } , -26: [,,z1]/*\n*/ })}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-221406266*/count=901; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.pow(( + ( + Math.pow(mathy0(Math.fround(0x100000000), mathy0(Math.fround(( ~ Math.fround(x))), ((( - y) >>> 0) | (x >>> 0)))), ( + ( + (((((x | 0) >= (Math.min(Math.fround(y), y) | 0)) | 0) >>> 0) ? (Math.fround(Math.max(Math.fround(x), ( + (( + (Math.hypot(( + y), ( + x)) | 0)) + Math.hypot(x, (x >>> 0)))))) >>> 0) : (x >>> 0))))))), ( + (4277))) >>> 0); }); testMathyFunction(mathy2, [Math.PI, -0x07fffffff, 0x100000001, -1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 0x100000000, 0/0, -(2**53+2), -0x080000001, 2**53-2, -Number.MAX_VALUE, -0, -(2**53), 2**53+2, 0, -0x100000000, 0.000000000000001, 1.7976931348623157e308, 1, 42, 1/0, Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 0x07fffffff, 0x080000000, -0x100000001, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=902; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=903; tryItOut("{}\nObject.prototype.unwatch.call(a1, \"expm1\");\n");
/*fuzzSeed-221406266*/count=904; tryItOut("/*infloop*/L:while(((eval) = null))print(\"\\uFB45\");");
/*fuzzSeed-221406266*/count=905; tryItOut("\"use strict\"; Object.defineProperty(this, \"v2\", { configurable: true, enumerable: true,  get: function() {  return g0.o0.t2.length; } });");
/*fuzzSeed-221406266*/count=906; tryItOut("testMathyFunction(mathy4, [({toString:function(){return '0';}}), (new Number(0)), undefined, '\\0', null, '0', '/0/', 1, objectEmulatingUndefined(), true, (function(){return 0;}), 0, 0.1, (new Number(-0)), false, -0, NaN, (new Boolean(false)), (new String('')), ({valueOf:function(){return 0;}}), /0/, ({valueOf:function(){return '0';}}), (new Boolean(true)), [], [0], '']); ");
/*fuzzSeed-221406266*/count=907; tryItOut("\"use strict\"; for (var p in i0) { try { g1.offThreadCompileScript(\"function f0(m2) x\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: (x % 76 == 60), noScriptRval: (4277), sourceIsLazy: false, catchTermination: (x % 37 != 9) })); } catch(e0) { } try { Array.prototype.push.call(a0, (makeFinalizeObserver('tenured')), h0, m1); } catch(e1) { } v0 = evalcx(\"/* no regression tests found */\", g2); }");
/*fuzzSeed-221406266*/count=908; tryItOut("this.v2 = g2.runOffThreadScript();");
/*fuzzSeed-221406266*/count=909; tryItOut("let (a, lqjsyr, a = /(?!(?:\\xAC{1,})|(?!\\S)?|(?:[^])+)/, xlodgr, x, x, x, d) { this.v0 + p2; }c = x;");
/*fuzzSeed-221406266*/count=910; tryItOut("a1 = [];");
/*fuzzSeed-221406266*/count=911; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x100000000, 0x080000001, 1, 0x080000000, -1/0, 1.7976931348623157e308, 2**53, Math.PI, -0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -0, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, -Number.MIN_VALUE, -0x080000001, 0x100000000, 0, 2**53+2, 0x07fffffff, 2**53-2, Number.MIN_VALUE, 42, -Number.MAX_VALUE, -(2**53+2), -(2**53), 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=912; tryItOut("\"use strict\"; Array.prototype.push.call(o0.a1, v2, g0);");
/*fuzzSeed-221406266*/count=913; tryItOut("with(x){v2 = g0.runOffThreadScript();print(uneval(v2)); }");
/*fuzzSeed-221406266*/count=914; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ mathy0(Math.cbrt(y), (( + Math.expm1(( + -0x080000000))) != ( + Math.fround(( + Math.fround((Math.hypot(y, y) >> (Math.acos((y | 0)) | 0))))))))); }); testMathyFunction(mathy1, [0.000000000000001, -0x07fffffff, 1/0, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 0, -0, 0x080000001, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 42, -0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 1, 2**53-2, Number.MIN_VALUE, -(2**53), -Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, 0x100000001, -0x100000001, 0x080000000, 2**53, -0x080000001, -1/0]); ");
/*fuzzSeed-221406266*/count=915; tryItOut("mathy5 = (function(x, y) { return mathy2(( + Math.fround(Math.expm1(Math.fround((Math.fround(Math.trunc(( + x))) | 0))))), (( ! (( + y) | 0)) | 0)); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -0, -0x100000000, 0x100000001, 2**53, 0x100000000, -0x100000001, -0x080000001, 0x080000001, Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, -(2**53+2), Math.PI, 0/0, 0, -1/0, 0x080000000, 0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 42, -0x080000000, 2**53+2, -Number.MAX_VALUE, -0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 1/0, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=916; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ~ ( + ( + Math.max(( + (( ! -0x080000001) != 0x100000000)), ( + mathy1(Math.fround((Math.fround(Math.tanh((y , x))) >>> Math.fround(( ~ x)))), x)))))) >= (( - Math.cosh(x)) >= ( + (( ! Math.sign((x >>> 0))) | 0)))); }); testMathyFunction(mathy5, [-0x100000001, -(2**53+2), -1/0, 1, -Number.MAX_SAFE_INTEGER, 42, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 0/0, 0.000000000000001, 2**53-2, -0, 0x080000001, 0x100000001, -Number.MAX_VALUE, -0x080000001, 1/0, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, 2**53, 0x080000000, Math.PI, -0x07fffffff, -(2**53), Number.MIN_VALUE, 2**53+2, 0x0ffffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=917; tryItOut("/*MXX3*/g2.DataView.name = g2.DataView.name;");
/*fuzzSeed-221406266*/count=918; tryItOut("mathy2 = (function(x, y) { return Math.fround(mathy1((Math.atan2((x % Math.min(y, Math.sqrt(((0/0 ? -0x080000000 : y) + y)))), ((( + (( + x) | 0)) ^ (x >>> 0)) | ( ~ x))) | 0), (( ! ( + (( ! ((( + (mathy0(Math.expm1(y), 1.7976931348623157e308) >>> 0)) >>> 0) >>> 0)) >>> 0))) | 0))); }); testMathyFunction(mathy2, [0x080000001, -(2**53), 42, -0x100000000, Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, -1/0, 0.000000000000001, 2**53+2, 0x07fffffff, 1/0, 2**53, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0, 0x080000000, 0x100000000, 1, -0x07fffffff, -(2**53+2), -0x0ffffffff, 0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 2**53-2]); ");
/*fuzzSeed-221406266*/count=919; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[new String('q'), 2, new String('q'), new String('q'), new Number(1.5), 2, new Boolean(false), 2, new Boolean(false), new Boolean(false),  '' , new Boolean(false), new Boolean(false), new Number(1.5), new Number(1.5), 2, 2, new String('q'), 2, 2, new String('q'), new Boolean(false),  '' , 2, new String('q'), new String('q'), new Number(1.5), 2, new Boolean(false), new String('q')]) { true; }");
/*fuzzSeed-221406266*/count=920; tryItOut("this.f0(g1.e0);function eval([])'fafafa'.replace(/a/g, String.prototype.toUpperCase)for(x = ((makeFinalizeObserver('nursery'))) in (intern((4277)))) this.t2 + g2;");
/*fuzzSeed-221406266*/count=921; tryItOut("\"use strict\"; t1 + p1;");
/*fuzzSeed-221406266*/count=922; tryItOut("var ersxjt = new SharedArrayBuffer(0); var ersxjt_0 = new Float64Array(ersxjt); print(ersxjt_0[0]); ersxjt_0[0] = -0.852; var ersxjt_1 = new Int32Array(ersxjt); ersxjt_1[0] = 12; var ersxjt_2 = new Float32Array(ersxjt); print(ersxjt_2[0]); var ersxjt_3 = new Int32Array(ersxjt); ersxjt_3[0] = 11; var ersxjt_4 = new Uint32Array(ersxjt); ersxjt_4[0] = -7; selectforgc(g1.o2);print(this.f1);/*ODP-2*/Object.defineProperty(s0, \"0\", { configurable: (ersxjt_1[0] % 5 == 2), enumerable: length, get: (function() { for (var j=0;j<87;++j) { f2(j%3==1); } }), set: (function(j) { if (j) { try { for (var v of e2) { try { yield \"\\u43D5\"; } catch(e0) { } g1.offThreadCompileScript(\"{}\"); } } catch(e0) { } g2.f2 + this.g2.f2; } else { h0.getOwnPropertyNames = f0; } }) });g1.v0 = Array.prototype.reduce, reduceRight.apply(a1, [(function() { try { i1 = new Iterator(p0, true); } catch(e0) { } try { function f1(v1)  { delete h2.iterate; }  } catch(e1) { } m0.set(g2.i1, g0.g1); return g1.m2; }), m1, this]);Array.prototype.push.call(a2, p0);v2 = evalcx(\"\\\"use strict\\\"; (1980965997);\", g2);");
/*fuzzSeed-221406266*/count=923; tryItOut("t2 = g2.t1.subarray(({valueOf: function() { e1.add(i2);return 18; }}));");
/*fuzzSeed-221406266*/count=924; tryItOut("false;");
/*fuzzSeed-221406266*/count=925; tryItOut("h0.__proto__ = g1.m1;");
/*fuzzSeed-221406266*/count=926; tryItOut("mathy4 = (function(x, y) { return (Math.imul((((( + (y >>> 0)) >>> 0) ? Math.imul((x ? Math.fround(( + Math.fround(-0x0ffffffff))) : x), ((((y | 0) ** (-0x100000000 | 0)) | 0) || Math.ceil(Math.fround(Math.expm1(x))))) : (-0x100000001 >>> (Math.sign(Math.fround(Math.PI)) * x))) >>> 0), (Math.tan((Math.atan2((Math.log10(Math.asinh(mathy3(y, 0.000000000000001))) | 0), (y >>> 0)) | 0)) >>> 0)) | 0); }); testMathyFunction(mathy4, [0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 0.000000000000001, 42, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, -1/0, 1/0, 0x07fffffff, -0x07fffffff, -0, 0x100000001, Number.MIN_VALUE, 0x080000000, 0, -(2**53+2), 0/0, -0x100000000, Math.PI, -Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, 1, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, 2**53-2, -0x100000001]); ");
/*fuzzSeed-221406266*/count=927; tryItOut("mathy4 = (function(x, y) { return (( ~ (Math.hypot(Math.fround((( ~ -0x080000000) !== Math.atan2((mathy1(Math.pow(-0x080000000, x), y) | 0), y))), Math.fround(Math.imul(( ! Math.log10(Math.max(x, y))), ( + ( ~ x))))) | 0)) | 0); }); testMathyFunction(mathy4, [0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 42, -(2**53+2), 0.000000000000001, 0, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000001, 1, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, Math.PI, 0x07fffffff, 0x100000001, -1/0, 0x100000000, -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, -0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, 0/0, -0, 1/0, 1.7976931348623157e308, -0x080000001, Number.MIN_VALUE, -0x100000001]); ");
/*fuzzSeed-221406266*/count=928; tryItOut("\"use strict\"; /*infloop*/for(var RegExp.rightContext in \"\\u2B97\") /*RXUB*/var r = g1.r2; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.match(r)); print(r.lastIndex); \n/*oLoop*/for (qcqvhl = 0; (/(?!([])*?)/gy.toString(new RegExp(\"\\\\3|\\\\B+|\\\\W\\u00b7{3,4}.{15,19}{2,130}\", \"\") ** false)) && qcqvhl < 22; ++qcqvhl) { a0.reverse(); } \n");
/*fuzzSeed-221406266*/count=929; tryItOut(";");
/*fuzzSeed-221406266*/count=930; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=931; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: true}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-221406266*/count=932; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=933; tryItOut("for (var p in a1) { try { /*ODP-1*/Object.defineProperty(b1, \"fromCharCode\", ({get: (mathy2).call, set: (new Function(\";\")), enumerable: (x % 82 == 81)})); } catch(e0) { } try { g0.valueOf = f0; } catch(e1) { } s1 = s2.charAt(-0.339()); }");
/*fuzzSeed-221406266*/count=934; tryItOut("print((SimpleObject));");
/*fuzzSeed-221406266*/count=935; tryItOut("g1.f2 = Proxy.createFunction(o1.h2, this.o1.f1, f0);");
/*fuzzSeed-221406266*/count=936; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -64.0;\n    var d3 = -8388609.0;\n    return +((+(imul((( /* Comment */x) >= (((i1)) ^ ((/*FFI*/ff()|0)-((0x7fffffff) <= (0x5385a81a))))), (0x60c8ea73))|0)));\n  }\n  return f; })(this, {ff: (runOffThreadScript).bind(new RegExp(\"[^\\\\f]\", \"gym\"),  /x/ )}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x080000001, -0x100000000, -(2**53-2), 0x07fffffff, 0x100000001, 0x080000000, Math.PI, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 0, Number.MIN_VALUE, 0/0, -(2**53+2), -Number.MAX_VALUE, 1, 0x080000001, 0.000000000000001, -0, Number.MAX_VALUE, -0x0ffffffff, 1/0, -1/0, 1.7976931348623157e308, 2**53-2, 42, -Number.MIN_VALUE, -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=937; tryItOut("v1 = (a2 instanceof m0);");
/*fuzzSeed-221406266*/count=938; tryItOut("\"use strict\"; if(intern(window)) {/*infloop*/for(let w; let \u000c(x, ysmqhi, c, xfkims, NaN, x, alsnrh, x)  /x/g ; (4277)) {\n/*MXX3*/g1.WeakSet.prototype.add = g0.WeakSet.prototype.add; }Object.defineProperty(d, \"toSource\", ({get: Math.cosh, set: (new Function(\"a0[({valueOf: function() { a0.reverse();return 6; }})];\"))})); } else  if (new Error( '' ).yoyo(x)) /*MXX2*/g2.Array.prototype.shift = this.v2;");
/*fuzzSeed-221406266*/count=939; tryItOut("\"use strict\"; {s0 += s0; }");
/*fuzzSeed-221406266*/count=940; tryItOut("for (var v of h1) { try { m0.set((4277), (e = Math.atan([,,z1]))); } catch(e0) { } try { v1 = t0.byteOffset; } catch(e1) { } try { a1[3] = g0.e1; } catch(e2) { } selectforgc(o0); }");
/*fuzzSeed-221406266*/count=941; tryItOut("this.g1.a1.length = 11;");
/*fuzzSeed-221406266*/count=942; tryItOut("\"use strict\"; m2 = g0.objectEmulatingUndefined();");
/*fuzzSeed-221406266*/count=943; tryItOut("\"use strict\"; /*vLoop*/for (let neclfj = 0; neclfj < 25; ++neclfj) { let d = neclfj;  '' ; } ");
/*fuzzSeed-221406266*/count=944; tryItOut("for(e in e =  /x/ ) {/*vLoop*/for (let wloeqa = 0; wloeqa < 36; ++wloeqa) { d = wloeqa; this.h2.getOwnPropertyNames = f0; } m2.has(e2); }");
/*fuzzSeed-221406266*/count=945; tryItOut("mathy2 = (function(x, y) { return Math.atan2(( ~ (( ! Math.fround(Math.cbrt(x))) >>> 0)), mathy0(Math.fround(mathy0((0x100000000 | 0), y)), Math.fround((x >> ((x | 0) ? x : mathy1(y, Math.fround(( - Math.fround(-1/0))))))))); }); testMathyFunction(mathy2, [-0, 1, Math.PI, Number.MIN_VALUE, 2**53, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), 0, 0x07fffffff, -1/0, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, -(2**53-2), -0x100000001, 42, -0x080000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -0x080000001, 2**53-2, -0x07fffffff, 0.000000000000001, 0x100000000, -Number.MAX_VALUE, 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=946; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-((3.022314549036573e+23))));\n  }\n  return f; })(this, {ff: function  x (w)null}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [42, -(2**53), 2**53, 1, -1/0, 0, 2**53+2, 1.7976931348623157e308, 0x080000001, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, -Number.MIN_VALUE, 0.000000000000001, 2**53-2, Number.MAX_VALUE, -0, 0x07fffffff, 0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, -0x080000001, 0x100000001, 1/0, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=947; tryItOut("selectforgc(o0);const e = (x) = (makeFinalizeObserver('tenured')) ^= NaN = Proxy.createFunction(({/*TOODEEP*/})(\"\\u89E0\"), function(y) { return undefined }, function  x (z) \"\" );");
/*fuzzSeed-221406266*/count=948; tryItOut("b0 + '';");
/*fuzzSeed-221406266*/count=949; tryItOut("{g0.m0.set(g1, s1);v1 = Object.prototype.isPrototypeOf.call(g1.m2, g1.v1); }\nprint(x);\n");
/*fuzzSeed-221406266*/count=950; tryItOut("\"use strict\"; o0.v1 = o1.g0.runOffThreadScript();");
/*fuzzSeed-221406266*/count=951; tryItOut("\"use strict\"; (void schedulegc(o0.g2));");
/*fuzzSeed-221406266*/count=952; tryItOut("\"use asm\"; t2.set(t2, 11);");
/*fuzzSeed-221406266*/count=953; tryItOut("g2.v1 = false;");
/*fuzzSeed-221406266*/count=954; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=955; tryItOut("\"use strict\"; let (a) {  /x/ function a()\"use asm\";   var pow = stdlib.Math.pow;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    d1 = (((d1)) / ((d0)));\n    d1 = (+pow(((d0)), ((((d1)) - (((this.__defineGetter__(\"window\", String.prototype.toLocaleUpperCase))))))));\n    {\n      d0 = (+((+(((!(0xfd3ecc18))-(0xffffffff))>>>((0x2887cb75)+((((0xfe7d9f4f)+(!(0xfb745d4b))) ^ (0xc7f4b*((\n '' ))))))))));\n    }\n    return ((((((((((0x33dcdd29))+(0xfea708b6))>>>(-0x1870a*((0x87e17660) != (0x47e24372))))))) ? (0xfed22176) : (0x9db4a17))+(0x162423e8)))|0;\n  }\n  return f;a1 + ''; }");
/*fuzzSeed-221406266*/count=956; tryItOut("{ void 0; minorgc(true); } /*tLoop*/for (let e of /*MARR*/[(void 0), true, true, (void 0), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, true, -0x5a827999, -0x5a827999, (void 0), true, -0x5a827999, (void 0), -0x5a827999, -0x5a827999, true, -0x5a827999, -0x5a827999, (void 0), -0x5a827999, (void 0), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, (void 0), true, -0x5a827999, true, -0x5a827999, true]) { ([,,]); }");
/*fuzzSeed-221406266*/count=957; tryItOut("/*RXUB*/var r = /((?=(?:^))+)/i; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-221406266*/count=958; tryItOut("mathy1 = (function(x, y) { return Math.clz32(Math.imul((mathy0(Math.atan2(x, x), (Math.fround(Math.min((y | 0), x)) + x)) === (Math.fround(mathy0(Math.fround(Math.min((0 | 0), (0/0 | 0))), Math.fround(Math.fround(Math.atan((y >>> 0)))))) ? (( + ( ~ ( + ((((x ? x : y) >>> 0) !== y) >>> 0)))) >>> 0) : (-(2**53) >> x))), Math.log2(Math.fround(( ! Math.fround(((x >>> 0) ? (42 | 0) : (Math.log2(x) >>> 0)))))))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 0, -0, 0/0, 1, 2**53, 0.000000000000001, -(2**53+2), -1/0, Math.PI, 1/0, 2**53-2, -0x080000001, 0x080000000, -0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, -(2**53), 2**53+2, -0x07fffffff, -0x080000000, 0x100000000, 0x080000001, 42, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=959; tryItOut("\"use strict\"; /*infloop*/for(var /(?:[^]{2,}(\\2|^|\\D|\\d(?=$)$|\\b))/gi.__proto__ in ((Array.prototype.shift)(x & \"\\uB227\"))){v0 = undefined;a2.forEach(Number.isSafeInteger.bind(v2)); }");
/*fuzzSeed-221406266*/count=960; tryItOut("mathy2 = (function(x, y) { return ( + mathy0(Math.max((mathy1(( + (((Math.fround(Math.min(( + x), Math.ceil(-Number.MIN_SAFE_INTEGER))) > Math.fround(( + mathy1(y, 42)))) | 0) ^ x)), ( ~ y)) | 0), Math.tan(Math.abs(-Number.MIN_VALUE))), ( + (mathy0(Math.min(y, y), Math.fround(x)) << ( - ( - -0x07fffffff)))))); }); testMathyFunction(mathy2, [-0x100000001, 1, 2**53-2, 2**53+2, -0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0x080000001, 0x100000000, 0.000000000000001, 0, 0x0ffffffff, 0/0, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53, 42, Number.MIN_VALUE, 0x100000001, -0, -(2**53), -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, Math.PI, 1.7976931348623157e308, -0x080000000, -0x07fffffff, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=961; tryItOut("o2 = Object.create(o2);");
/*fuzzSeed-221406266*/count=962; tryItOut("\"use strict\"; d =  /x/ ;return;");
/*fuzzSeed-221406266*/count=963; tryItOut("print((4277));let z = this.__defineGetter__(\"x\", (/*RXUE*//(.|(?=\\1)*?{4,5})/gm.exec(-0))).throw(null);");
/*fuzzSeed-221406266*/count=964; tryItOut("v2 = a2.length;");
/*fuzzSeed-221406266*/count=965; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    switch ((((0x32bd4bcf)+((4097.0) > (281474976710657.0))) >> ((-0x8000000)))) {\n    }\n    {\n      {\n        (Uint8ArrayView[4096]) = (((((imul((0xbb109ec), (0xcc01a19f))|0) > (((0xfd3d3aad)+(0x4300628d)) ^ ((0xf9109fc1)-(0xbf26d6f3))))-(0xffffffff))>>>(-(((d0))))) % (0xb3d073));\n      }\n    }\n    {\n      d1 = ((NaN) + (d1));\n    }\n    d1 = (((+(((0xffffffff) % (((!(-0x8000000)))>>>((0xcf8b639a)-(0x288017b0)))) >> ((0xfb27e4b4)+((0x24e28d8d))+(0xfd6b4eea))))) % ((Float32ArrayView[(((Uint32ArrayView[4096]))) >> 2])));\n    {\n      d1 = (-1125899906842623.0);\n    }\n    return ((((void options('strict_mode')))))|0;\n  }\n  return f; })(this, {ff: (this, x) => ({x: (4277),  set \u3056() { \"use strict\"; print( '' ); }  })}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-221406266*/count=966; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( ! Math.fround((Math.fround(mathy0((x < Math.asin(( + -0x080000000))), Math.log(y))) & Math.fround((Math.imul(((Math.cosh(Math.fround(Math.round(Math.fround(x)))) >>> 0) | 0), ( + ( + ( ~ Math.pow((x >>> 0), y))))) | 0)))))); }); testMathyFunction(mathy2, [1, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000000, Number.MIN_VALUE, 2**53, -1/0, Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, 0x0ffffffff, 0/0, -0x100000000, -0x100000001, -(2**53+2), 0x100000001, -0x0ffffffff, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, -0x080000001, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, 0x080000000, 2**53+2, -0, 0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=967; tryItOut("v1 = t1.byteLength;");
/*fuzzSeed-221406266*/count=968; tryItOut("a0.push(p1);");
/*fuzzSeed-221406266*/count=969; tryItOut("/*bLoop*/for (var nvkmkg = 0, a = --(e); nvkmkg < 75; ++nvkmkg) { if (nvkmkg % 44 == 36) { h1.fix = g0.g1.f0; } else { Array.prototype.shift.apply(this.a2, [h1]); }  } ");
/*fuzzSeed-221406266*/count=970; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ Math.pow((Math.log2((Math.tan(Math.atan2(-(2**53+2), (mathy0(Number.MIN_SAFE_INTEGER, Math.hypot(y, Math.fround(y))) >>> 0))) >>> 0)) | 0), (Math.cosh(( + (( ! y) >>> 0))) >>> 0))); }); testMathyFunction(mathy5, [-(2**53-2), Number.MAX_SAFE_INTEGER, 0, -0x100000001, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, -(2**53), -0x100000000, 2**53+2, -0x07fffffff, -(2**53+2), -1/0, 0x100000000, -0, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, 1.7976931348623157e308, -0x080000001, 42, 0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, Math.PI, -Number.MIN_SAFE_INTEGER, 1, 0/0, 0x07fffffff, 0x080000000, 1/0]); ");
/*fuzzSeed-221406266*/count=971; tryItOut("/(?=(?!\\B))/gm;");
/*fuzzSeed-221406266*/count=972; tryItOut("\"use strict\"; \"use asm\"; /*vLoop*/for (ijnprq = 0; ijnprq < 13; ++ijnprq) { w = ijnprq; /*RXUB*/var r = r2; var s = \"\\n\\n\\n\\n\\n\"; print(s.split(r));  } ");
/*fuzzSeed-221406266*/count=973; tryItOut("this.t2 = this.t0[v1];");
/*fuzzSeed-221406266*/count=974; tryItOut("mathy2 = (function(x, y) { return Math.sqrt(( + ( + Math.sin(( ~ y))))); }); testMathyFunction(mathy2, [-0x080000001, 2**53-2, 0x080000000, 0x07fffffff, -0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, Number.MAX_VALUE, 42, -0x100000001, 0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -0, -Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, -(2**53-2), 0x100000001, 0.000000000000001, 0x0ffffffff, 2**53, Math.PI, 1, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, 0]); ");
/*fuzzSeed-221406266*/count=975; tryItOut("\"use strict\"; M:do {e2.add(o1.v1); } while(( /x/g ) && 0);");
/*fuzzSeed-221406266*/count=976; tryItOut("/*RXUB*/var r = /\\S{0,1}/im; var s = \"_\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=977; tryItOut("Array.prototype.forEach.call(a2, f0, g2, v2);");
/*fuzzSeed-221406266*/count=978; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    return +((1073741825.0));\n  }\n  return f; })(this, {ff: (void version(170))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [false, 1, (new Number(-0)), [0], (new Number(0)), '0', '/0/', (function(){return 0;}), /0/, '\\0', ({toString:function(){return '0';}}), 0, (new String('')), objectEmulatingUndefined(), '', -0, (new Boolean(true)), ({valueOf:function(){return 0;}}), true, undefined, 0.1, [], (new Boolean(false)), NaN, ({valueOf:function(){return '0';}}), null]); ");
/*fuzzSeed-221406266*/count=979; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=980; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.asin((Math.pow(Math.exp((y >>> 0)), Math.asinh((Math.atanh(0x080000000) | 0))) >>> 0))); }); testMathyFunction(mathy0, [-0x100000000, -(2**53), -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 1.7976931348623157e308, 0x080000000, 2**53+2, -0x100000001, 2**53-2, Math.PI, 1, -Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000000, 0, -0x080000001, 2**53, 0/0, 0x07fffffff, -0, 0x0ffffffff, 0x080000001, -1/0, 1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=981; tryItOut("a1 = arguments;");
/*fuzzSeed-221406266*/count=982; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[new String('q'), new Number(1), new Number(1), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'),  \"\" , new Number(1), new Number(1)]) { Object.prototype.watch.call(o2, window, this.f0); }");
/*fuzzSeed-221406266*/count=983; tryItOut("v1 = a2.length;");
/*fuzzSeed-221406266*/count=984; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (i1);\n    return +((16385.0));\n    return +((((makeFinalizeObserver('tenured'))) - ((((+(-1.0/0.0))) / ((+(-1.0/0.0)))))));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [42, -Number.MIN_VALUE, 0/0, 0, 0x080000000, -(2**53+2), 1.7976931348623157e308, 0x100000001, 1, -(2**53-2), -0x07fffffff, Math.PI, -0x100000001, -0x080000001, -0x0ffffffff, -0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, -0x100000000, 1/0, 0x080000001, 2**53, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-221406266*/count=985; tryItOut("for (var p in g2) { try { m0.delete(v1); } catch(e0) { } try { /* no regression tests found */ } catch(e1) { } a1 + s2; }");
/*fuzzSeed-221406266*/count=986; tryItOut("/*RXUB*/var r = /^*(?:\\1)|(?!\\b|[^])|\\u009D|([^])\ubb40+?|.\\0\\s\\1|\u00d8|\\s++?*/gyi; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=987; tryItOut("testMathyFunction(mathy4, [-0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 2**53-2, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, -(2**53), -Number.MIN_VALUE, 0, 42, -0x080000001, 0x0ffffffff, 0x100000001, 1, -(2**53-2), 0x100000000, 0x080000000, 0x080000001, 1.7976931348623157e308, -0x100000000, 2**53, -0, 1/0, -0x100000001, 0.000000000000001, -0x0ffffffff, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-221406266*/count=988; tryItOut("/*MXX3*/g0.Math.LN2 = g2.Math.LN2;\nh2.set = (function mcc_() { var cqkipu = 0; return function() { ++cqkipu; f0(/*ICCD*/cqkipu % 11 == 10);};})();\n");
/*fuzzSeed-221406266*/count=989; tryItOut("mathy0 = (function(x, y) { return (((( - ( + Math.atan2((Math.imul((x | 0), (y | 0)) | 0), Number.MAX_VALUE))) >>> 0) == (((Math.fround((Math.fround(y) & Math.fround((( + Math.hypot(Math.fround(Math.log10(y)), x)) >>> 0)))) && (Math.imul(((Math.fround(x) < Math.fround(x)) | 0), Math.fround((y > Math.fround(y)))) || ((( - 2**53) >>> 0) ? (x >>> 0) : ((( ! ( + y)) >>> 0) >>> 0)))) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, 0.000000000000001, 2**53-2, -0x100000001, -1/0, -0x07fffffff, -(2**53-2), 0x100000001, -0, 0x100000000, 0/0, 2**53+2, 0x080000001, 1, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x100000000, 0x080000000, 1.7976931348623157e308, 42, 0x07fffffff, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=990; tryItOut("\"use strict\"; var kqcihk = new ArrayBuffer(0); var kqcihk_0 = new Int32Array(kqcihk); kqcihk_0[0] = -27; var kqcihk_1 = new Uint16Array(kqcihk); var kqcihk_2 = new Float32Array(kqcihk); kqcihk_2[0] = 14; Array.prototype.reverse.call(a0, this.g0);return b;o1.g0.offThreadCompileScript(\"new RegExp(\\\"\\\\\\\\B\\\", \\\"gim\\\")\");print(let (y = new RegExp(\"(?=(?=\\\\xB8)+)*|\\\\2*?\", \"\")) [z1]);");
/*fuzzSeed-221406266*/count=991; tryItOut("\"use strict\"; f1.toString = (function mcc_() { var wilxiu = 0; return function() { ++wilxiu; if (/*ICCD*/wilxiu % 8 == 4) { dumpln('hit!'); t0[11]; } else { dumpln('miss!'); h2.enumerate = f0; } };})();");
/*fuzzSeed-221406266*/count=992; tryItOut("\"use strict\"; o0.toString = f0;");
/*fuzzSeed-221406266*/count=993; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=994; tryItOut("mathy2 = (function(x, y) { return ( + Math.pow(((mathy1((( ! (Math.fround((Math.fround(( + Math.atan2(( + (-0x100000000 === y)), x))) ? ( + (( + mathy0((y >>> 0), ( + x))) - ( + y))) : Math.fround(Math.pow((y >>> 0), ( - -0x080000001))))) | 0)) | 0), (((Number.MAX_SAFE_INTEGER , ( + Math.hypot(y, Math.tanh((Math.log(Math.fround(y)) | 0))))) ^ ( + mathy1(Math.fround(( ~ Math.fround(x))), -(2**53-2)))) | 0)) | 0) >>> 0), ( + (Math.asinh(x) / Math.fround(Math.cos(y)))))); }); ");
/*fuzzSeed-221406266*/count=995; tryItOut("\"use strict\"; const a2 = a2.filter((function mcc_() { var gqacrl = 0; return function() { ++gqacrl; if (/*ICCD*/gqacrl % 2 == 1) { dumpln('hit!'); try { Array.prototype.unshift.call(this.a0, g2, f2, o1.g0.b2); } catch(e0) { } try { m1.get(e0); } catch(e1) { } try { a2.forEach(); } catch(e2) { } v0 = (o2.g0 instanceof p2); } else { dumpln('miss!'); try { Object.defineProperty(this, \"v0\", { configurable: x, enumerable: false,  get: function() {  return g0.runOffThreadScript(); } }); } catch(e0) { } try { o2.o2 + ''; } catch(e1) { } try { h2.toSource = g2.o2.o1.f2; } catch(e2) { } this.a2.splice(); } };})(), h2);");
/*fuzzSeed-221406266*/count=996; tryItOut("mathy4 = (function(x, y) { return (mathy3(( + (mathy0(y, Math.min(Math.fround(-Number.MAX_SAFE_INTEGER), y)) < 2**53+2)), Math.max(( + ((x >>> 0) < x)), Math.cos((Math.tanh(((Math.hypot((x >>> 0), ((x ? -0 : x) >>> 0)) >>> 0) | 0)) | 0)))) <= (Math.fround(Math.imul(Math.fround(Math.fround(((( ~ (Math.fround(mathy3(x, y)) >>> 0)) >>> 0) <= Math.fround((mathy2((x >>> 0), (x >>> 0)) >>> 0))))), Math.fround(x))) > (Math.trunc(Math.asinh(Math.pow(x, y))) | 0))); }); testMathyFunction(mathy4, [-0, 0x0ffffffff, 0.000000000000001, 0x100000001, 0x07fffffff, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), -0x100000000, 0x080000001, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 2**53-2, -(2**53), Number.MAX_VALUE, -1/0, 2**53+2, -0x080000001, 42, 0/0, 1, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 0x100000000, -0x080000000, Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=997; tryItOut("{t1[v0] = window <<  /x/ ; }");
/*fuzzSeed-221406266*/count=998; tryItOut("\"use strict\"; a1 = Array.prototype.map.apply(g0.a2, [f0]);");
/*fuzzSeed-221406266*/count=999; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xff179174);\n    return (((abs((((i1)+(!((((-1073741825.0)) % ((128.0))) <= (-1.015625)))) & ((i1))))|0) % (imul((i1), ((((0xa392e9d0)*-0xfffff) >> ((0xe0f92127)*-0x724d)) == (((0xbcbc69db)+(0x83eaf6)-(0xc4956de2)) & ((0x6b67e56f) % (0x69eb02f2)))))|0)))|0;\n  }\n  return f; })(this, {ff: b => ('fafafa'.replace(/a/g, q => q).__defineGetter__(\"z\", Object.prototype.hasOwnProperty)).unwatch(\"sup\")}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0, 2**53, 2**53+2, 0x080000001, 0/0, 0.000000000000001, Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, -0x080000000, 1/0, 1.7976931348623157e308, -(2**53-2), -0x100000001, -1/0, 0, -0x100000000, 0x100000001, 42, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, Math.PI, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, 0x100000000, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=1000; tryItOut("this.s2 = '';");
/*fuzzSeed-221406266*/count=1001; tryItOut("\"use strict\"; /*MXX2*/g0.Object.seal = e2;");
/*fuzzSeed-221406266*/count=1002; tryItOut("print(x);function x()27a1.push(this.a2, b2, a2, o2.a2, a0, o2);");
/*fuzzSeed-221406266*/count=1003; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2*?\", \"gym\"); var s = \"\\u0808\"; print(s.split(r)); for (var p in v0) { try { Array.prototype.reverse.call(a0); } catch(e0) { } try { /*RXUB*/var r = o2.r0; var s = \"\\u7c78\"; print(r.exec(s)); print(r.lastIndex);  } catch(e1) { } try { f0 + e2; } catch(e2) { } x = b1; }");
/*fuzzSeed-221406266*/count=1004; tryItOut("\"use strict\"; this.m1.has(t0);");
/*fuzzSeed-221406266*/count=1005; tryItOut("for (var p in v0) { try { g2.a0 = []; } catch(e0) { } try { h1.toString = (function() { s0.__iterator__ = (function() { for (var j=0;j<62;++j) { f0(j%3==0); } }); return g1.e2; }); } catch(e1) { } try { s2 + ''; } catch(e2) { } a0.splice(-7, 14, f1, i2, i2, f0, g0); }");
/*fuzzSeed-221406266*/count=1006; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.min(mathy1(Math.fround(( + (Math.sqrt((2**53+2 | 0)) | 0))), (( ! (Math.fround(Math.min((y / ((-Number.MIN_VALUE - (42 >>> 0)) >>> 0)), ( + Math.hypot(Math.fround(2**53-2), Math.fround(y))))) | 0)) | 0)), Math.log(((Math.pow(( + Math.cbrt(( + Math.atan((-0x100000001 >>> 0))))), (Math.log2(y) | 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy2, [-0x07fffffff, Number.MAX_VALUE, 2**53+2, -(2**53+2), -0x080000001, 2**53, -1/0, 42, -0x100000000, 0.000000000000001, -0x0ffffffff, -0x100000001, 0x07fffffff, 0/0, 0, 0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, 1, 0x100000000, 0x080000000, -0, -0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53-2, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1007; tryItOut("e0 = f1;");
/*fuzzSeed-221406266*/count=1008; tryItOut("\"use strict\"; L:for(var b = ({\u3056} = (void version(185))) in  '' ) {a1.sort(f1);for (var v of v0) { try { m2 + g1; } catch(e0) { } h0.delete = f0; } }");
/*fuzzSeed-221406266*/count=1009; tryItOut("/*infloop*/M:for(var e; x; \u000cthis) {selectforgc(o0); }");
/*fuzzSeed-221406266*/count=1010; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var tan = stdlib.Math.tan;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 16384.0;\n    var d3 = 3.022314549036573e+23;\n    var i4 = 0;\n    (Float64ArrayView[((/*FFI*/ff(((((-(((3.022314549036573e+23) + (-1099511627777.0))))) - ((+(-1.0/0.0))))), ((((({} = \u3056 = \nfalse))) | ((0xa6ddc92f) % (0xffffffff)))), ((abs((~~(+(0x8665aae4))))|0)), ((((0xf851fe4f)) << ((0xe806d0a0)))), ((abs((0x452664c6))|0)), ((-511.0)), ((-9007199254740992.0)))|0)) >> 3]) = ((-1152921504606847000.0));\n    (Uint8ArrayView[2]) = ((((((0x6b05e3dd) == (~~(+(0x13e77e02))))+((-73786976294838210000.0) == (+tan(((+tan(((+(-1.0/0.0))))))))))>>>(((0x98de76da) >= (0xc510fecf)))))+(0xfb663bd3));\n    {\n;    }\n    return +((+/*FFI*/ff(((abs((((0xbf1bdca6) % (0xb6768f64)) & ((i1)-(0xfa269618))))|0)), ((((((((0x0) != (0xa50d7115))+(0x84f9e04a)) & (((524289.0) != (-1.03125))-(0x41c66263))) <= ((imul(((0x20b7191a) == (0x76c35595)), ((((0xffffffff))>>>((0x3d1210e5)))))|0)))) >> (0x84794*(0xc62d314)))), ((~(((i1) ? ((((-0x8000000))>>>((0xd96439ab))) > (0xc20ee755)) : (i0))))), ((32767.0)), ((((d3)) * ((Float32ArrayView[1])))), ((1.1805916207174113e+21)), ((~~(-17179869185.0))), ((x)), ((d2)), ((-140737488355329.0)), ((-17179869185.0)), ((-36028797018963970.0)))));\n  }\n  return f; })(this, {ff: function  window (x) { yield (4277) } }, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x080000000, -(2**53), 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, 2**53+2, 0/0, Number.MAX_VALUE, -0x07fffffff, -0x100000000, 42, 0x080000001, 0, 1.7976931348623157e308, -Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 1, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, 1/0, -1/0, Number.MIN_VALUE, -0, -0x0ffffffff, -0x100000001, 0x0ffffffff, -(2**53-2), 2**53]); ");
/*fuzzSeed-221406266*/count=1011; tryItOut("\"use strict\"; for (var v of e1) { try { m1.get(b2); } catch(e0) { } try { m0.has(a0); } catch(e1) { } e2.delete(i0); }");
/*fuzzSeed-221406266*/count=1012; tryItOut("p0.__iterator__ = (function() { try { a0 = r1.exec(s0); } catch(e0) { } try { this.v0 = (h2 instanceof p2); } catch(e1) { } try { Object.defineProperty(this, \"v1\", { configurable: false, enumerable: (x % 3 == 2),  get: function() {  return this.t0.length; } }); } catch(e2) { } o2.a0.length = 19; throw f0; });");
/*fuzzSeed-221406266*/count=1013; tryItOut("\"use strict\"; /*bLoop*/for (let yhbdqt = 0; yhbdqt < 104; ++yhbdqt) { if (yhbdqt % 2 == 1) { s1 = ''; } else { (d); }  } ");
/*fuzzSeed-221406266*/count=1014; tryItOut("\"use strict\"; testMathyFunction(mathy2, [/0/, 1, ({valueOf:function(){return 0;}}), (new Number(0)), (new String('')), -0, [0], '', true, (new Boolean(true)), ({valueOf:function(){return '0';}}), 0.1, '\\0', [], '0', NaN, false, undefined, ({toString:function(){return '0';}}), (new Boolean(false)), (new Number(-0)), 0, '/0/', (function(){return 0;}), null, objectEmulatingUndefined()]); ");
/*fuzzSeed-221406266*/count=1015; tryItOut("/*hhh*/function yhryne(x){function f2(v2) -24}yhryne();");
/*fuzzSeed-221406266*/count=1016; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -6.044629098073146e+23;\n    var d4 = 144115188075855870.0;\n    (Int16ArrayView[0]) = (((/*FFI*/ff(((imul(((d0) == (d4)), (-0x8000000))|0)), ((+/*FFI*/ff(((+((4277)))), ((-9.671406556917033e+24)), ((imul((-0x8000000), (0xf9db79b9))|0)), ((140737488355328.0)), ((36028797018963970.0)), ((2097151.0)), ((1099511627777.0)), ((-1.888946593147858e+22)), ((1.0078125))))), ((+(0.0/0.0))), ((((-0x8000000)) | ((0xfc657142)))), ((((0xffffffff))|0)), ((562949953421312.0)))|0) ? ((0x83d6a3c1) ? ((0xf920c7df) ? (0xfb9b1f85) : (-0x8000000)) : ((d0))) : ((i2) ? (0xffda3cc5) : (i2)))+((+(0x609f6b2c)) < (d0)));\n    i2 = (i2);\n    d4 = (+(0.0/0.0));\n    return ((((d4) > (+abs(((-1.888946593147858e+22)))))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [objectEmulatingUndefined(), null, -0, NaN, '/0/', (function(){return 0;}), 0.1, '\\0', (new Number(0)), 0, true, [], ({toString:function(){return '0';}}), '', ({valueOf:function(){return '0';}}), (new Number(-0)), undefined, [0], '0', (new Boolean(true)), /0/, (new Boolean(false)), false, (new String('')), 1, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-221406266*/count=1017; tryItOut("o1.m0.has(e0);\n/*tLoop*/for (let w of /*MARR*/[]) { s0 = Array.prototype.join.call(a2, s2, b2, p0); }\n");
/*fuzzSeed-221406266*/count=1018; tryItOut("\"use strict\"; v0.toString = (function() { for (var j=0;j<13;++j) { f0(j%5==0); } });");
/*fuzzSeed-221406266*/count=1019; tryItOut("/*infloop*/L:for(this;  \"\" ;  /x/ ) {e2.add(b1);g0.g1.offThreadCompileScript(\"/* no regression tests found */\"); }");
/*fuzzSeed-221406266*/count=1020; tryItOut("/*RXUB*/var r = /(?=(?:[\\0-\\cG])|(?!\\D){4,}|(?!(^))|\\W|(?!(\\b${2}))*+?)+?/gy; var s = ((e = window)); print(r.exec(s)); ");
/*fuzzSeed-221406266*/count=1021; tryItOut("testMathyFunction(mathy2, [0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), 0x080000000, Number.MAX_VALUE, 0/0, 0, -(2**53+2), 0x100000001, -1/0, 1, 2**53, -0x100000000, 42, -Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), Math.PI, 1/0, -0x07fffffff, 2**53-2, 0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-221406266*/count=1022; tryItOut("/*bLoop*/for (let kuwzqh = 0, x; kuwzqh < 17; ++kuwzqh) { if (kuwzqh % 3 == 1) { this.p1 + ''; } else { print(((void version(185)))); }  } ");
/*fuzzSeed-221406266*/count=1023; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x0ffffffff, 2**53, -0x07fffffff, -(2**53+2), -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, -0x080000000, 0x080000001, 42, 2**53-2, 0x100000000, 0x0ffffffff, 1, Math.PI, 0x07fffffff, Number.MIN_VALUE, 2**53+2, 0, Number.MAX_VALUE, -1/0, -0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, 0/0, -(2**53), -Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1024; tryItOut("o2.e1.delete(this.o1);");
/*fuzzSeed-221406266*/count=1025; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.fround((Math.fround(( ! Math.fround((( ! ((Math.max((( ! (x >>> 0)) >>> 0), 0) >>> 0) | 0)) >>> 0)))) | Math.fround(Math.atan(Math.min((y | 0), Math.fround(1)))))) - Math.fround(Math.hypot((( ! ( ! Math.atan2((Math.tanh(-Number.MIN_VALUE) >>> 0), (((x | 0) , (( ~ -0x080000000) | 0)) | 0)))) >>> 0), ((Math.fround(Math.exp(x)) ? (y ? ( + (Math.cosh(y) | 0)) : Math.fround(( ! Math.max(( + 0), ( - (x >>> 0)))))) : Math.sin(Math.acosh(x))) >>> 0)))); }); testMathyFunction(mathy0, [-1/0, 42, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, 1.7976931348623157e308, -0x07fffffff, 0, 1/0, 0.000000000000001, -(2**53), 1, Number.MAX_SAFE_INTEGER, 2**53, 0x0ffffffff, 2**53+2, 0x080000001, -Number.MAX_VALUE, -0, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, Number.MIN_VALUE, 0x100000000, 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -0x080000001, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), 2**53-2]); ");
/*fuzzSeed-221406266*/count=1026; tryItOut("mathy2 = (function(x, y) { return (Math.max(((Math.min((Math.max((x >>> 0), (((x | 0) - (x | 0)) | 0)) >>> 0), ( ! 1)) >= Math.exp(Math.atan2(( + mathy1((Math.cbrt(0x07fffffff) >>> 0), ( + ( ! (y >>> 0))))), ( + ( + y))))) >>> 0), ( + ( + ( + Math.min((((y >>> 0) > ((y < y) >>> 0)) >>> 0), ( + (Math.tan((( ~ 0x100000001) | x)) >>> 0))))))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[arguments.caller, arguments.caller, NaN,  '\\0' ,  '\\0' ,  '\\0' , new Number(1), arguments.caller, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  '\\0' ,  '\\0' , new Number(1), NaN, arguments.caller,  '\\0' , new Number(1), NaN, new Number(1), arguments.caller, arguments.caller,  /x/g , NaN, new Number(1),  '\\0' , NaN,  /x/g , new Number(1),  /x/g ,  '\\0' , arguments.caller,  '\\0' , NaN, new Number(1),  '\\0' , new Number(1), NaN,  '\\0' , new Number(1),  '\\0' , NaN, arguments.caller,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Number(1), NaN, NaN, new Number(1), NaN,  '\\0' ,  '\\0' , arguments.caller, arguments.caller,  '\\0' , arguments.caller, NaN,  /x/g , arguments.caller, NaN,  '\\0' , arguments.caller, arguments.caller, arguments.caller, NaN,  /x/g , NaN, NaN,  '\\0' ,  /x/g ,  '\\0' , arguments.caller,  '\\0' , NaN, arguments.caller,  /x/g , arguments.caller,  /x/g , new Number(1), new Number(1), NaN,  /x/g ,  /x/g , arguments.caller,  '\\0' ,  '\\0' , NaN]); ");
/*fuzzSeed-221406266*/count=1027; tryItOut("\"use strict\"; h2 + '';print(p2);");
/*fuzzSeed-221406266*/count=1028; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2\\\\cK.{3,}*??\\\\0|.[^]${2}{0,2}|(\\\\b[\\\\s]|\\\\W{2}|(?=[^]|\\u00e4)*?){1}(?:(?:(?=\\\\2)?|[^\\\\S\\\\S])|(\\\\b$|.|$))\", \"yi\"); var s = \"\\uF9A2\"; print(s.split(r)); ");
/*fuzzSeed-221406266*/count=1029; tryItOut("/*infloop*/L:for(arguments.callee.arguments in x) Array.prototype.pop.call(a1);{ void 0; verifyprebarriers(); }");
/*fuzzSeed-221406266*/count=1030; tryItOut("print(uneval(a2));");
/*fuzzSeed-221406266*/count=1031; tryItOut("mathy3 = (function(x, y) { return ((Math.fround(Math.atan2(y, Math.fround((Math.atan(0) | 0)))) != (Math.fround((Math.abs(( + 1.7976931348623157e308)) !== (Math.cbrt((-Number.MAX_VALUE >>> 0)) >>> 0))) === Math.fround(Math.fround((Math.imul(( + y), Math.pow(y, 0x100000001)) ? ((Math.asin((Math.sinh(Number.MIN_VALUE) | 0)) >>> 0) | 0) : x))))) ^ mathy1(( + Math.max(Math.fround(mathy0(Math.fround(y), Math.fround(Math.atanh(( + 0))))), (Math.log10((-0x080000000 >>> 0)) >>> 0))), Math.atanh(( + (Math.atan2(Math.fround(( ! Math.fround(2**53+2))), (Math.atan2(2**53-2, -0x100000001) | 0)) >>> 0))))); }); ");
/*fuzzSeed-221406266*/count=1032; tryItOut("s2 += 'x';");
/*fuzzSeed-221406266*/count=1033; tryItOut("/*oLoop*/for (var wdbzul = 0; wdbzul < 73; ++wdbzul) { g2.offThreadCompileScript(\"for (var v of b2) { try { /*MXX1*/o1 = g1.Math.cos; } catch(e0) { } try { for (var v of p2) { try { /*MXX1*/g1.o0 = g0.Date.prototype.toUTCString; } catch(e0) { } ; } } catch(e1) { } var a0 = r2.exec(s2); }\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: \"\\u9514\", noScriptRval: (x % 18 != 5), sourceIsLazy: false, catchTermination: false })); } ");
/*fuzzSeed-221406266*/count=1034; tryItOut("\"use strict\"; g0.s1 + e0;");
/*fuzzSeed-221406266*/count=1035; tryItOut("/*tLoop*/for (let a of /*MARR*/[ \"\" ]) { ( '' ); }");
/*fuzzSeed-221406266*/count=1036; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.atan2((mathy0(( ! -0x080000000), Math.max(-0x080000001, -0)) >>> 0), ((( + -0x0ffffffff) && (Math.atan2(x, x) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-221406266*/count=1037; tryItOut("t0 = new Uint16Array(t1);");
/*fuzzSeed-221406266*/count=1038; tryItOut("for (var v of o2) { try { v2 = Object.prototype.isPrototypeOf.call(g2.s0, o1.a2); } catch(e0) { } try { g1.o2.h0.set = a =>  { yield (4277).watch(\"fontsize\", decodeURIComponent) } ; } catch(e1) { } try { h2 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.forEach.apply(a0, [x]);; var desc = Object.getOwnPropertyDescriptor(s2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return m1; var desc = Object.getPropertyDescriptor(s2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e2.delete(t1);; Object.defineProperty(s2, name, desc); }, getOwnPropertyNames: function() { return p0; return Object.getOwnPropertyNames(s2); }, delete: function(name) { o2.t2 = g0.objectEmulatingUndefined();; return delete s2[name]; }, fix: function() { v1 = (v0 instanceof a2);; if (Object.isFrozen(s2)) { return Object.getOwnProperties(s2); } }, has: function(name) { return o0.v1; return name in s2; }, hasOwn: function(name) { for (var v of g1.m2) { try { m2.get(o2); } catch(e0) { } try { s0 = new String(f1); } catch(e1) { } b2 + ''; }; return Object.prototype.hasOwnProperty.call(s2, name); }, get: function(receiver, name) { /*MXX2*/g0.g1.Map.name = t0;; return s2[name]; }, set: function(receiver, name, val) { v0 = (a2 instanceof o2.p2);; s2[name] = val; return true; }, iterate: function() { ;; return (function() { for (var name in s2) { yield name; } })(); }, enumerate: function() { i2.send(a2);; var result = []; for (var name in s2) { result.push(name); }; return result; }, keys: function() { Object.defineProperty(this, \"v1\", { configurable: false, enumerable: true,  get: function() {  return b0.byteLength; } });; return Object.keys(s2); } }); } catch(e2) { } t2 = new Int8Array(b2, 32, 2); }");
/*fuzzSeed-221406266*/count=1039; tryItOut("\"use strict\"; /*MXX3*/g0.g2.RegExp.$` = g0.RegExp.$`;");
/*fuzzSeed-221406266*/count=1040; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + (( + y) | 0)) | 0)); }); testMathyFunction(mathy0, [2**53-2, 2**53+2, -0x080000000, -0x07fffffff, 0x100000000, -Number.MIN_VALUE, -(2**53+2), -0x100000001, 2**53, 0x100000001, -0x100000000, Number.MIN_VALUE, 1/0, 0/0, 0x080000001, 1, -Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 42, -0, 1.7976931348623157e308, -0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1041; tryItOut("\"use strict\"; e0.__proto__ = v0;");
/*fuzzSeed-221406266*/count=1042; tryItOut("\"use strict\"; a1.__iterator__ = (function() { m0 + ''; return b0; });");
/*fuzzSeed-221406266*/count=1043; tryItOut("mathy0 = (function(x, y) { return ((Math.imul(0x0ffffffff, (Math.trunc((( + Math.hypot(( + (Math.cosh((x | 0)) >>> 0)), y)) | 0)) >>> 0)) && Math.trunc(Math.asin(( ~ ( + 1/0))))) % ( + (Math.cbrt(0/0) !== (x ? Math.fround(y) : Math.sin(Math.cos(y)))))); }); ");
/*fuzzSeed-221406266*/count=1044; tryItOut("\"use strict\"; do for (var p in p0) { try { e1.delete(e2); } catch(e0) { } try { a1.forEach((function(j) { if (j) { g1.i0.valueOf = (function(j) { if (j) { try { s1 += 'x'; } catch(e0) { } try { v0 = evaluate(\"\\\"use strict\\\"; print(x);\", ({ global: this.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 11 == 3), sourceIsLazy: true, catchTermination: (x % 2 != 1), element: o2, elementAttributeName: s2 })); } catch(e1) { } try { o1 + b0; } catch(e2) { } p0 + ''; } else { try { Object.defineProperty(this, \"v2\", { configurable: (x % 2 != 0), enumerable: false,  get: function() {  return r1.global; } }); } catch(e0) { } try { t0 = this.t1.subarray(({valueOf: function() { e2 = new Set;return 13; }}), 19); } catch(e1) { } try { /*RXUB*/var r = r0; var s = s2; print(uneval(s.match(r)));  } catch(e2) { } print(uneval(b1)); } }); } else { h1 + g2; } })); } catch(e1) { } h0.valueOf = f2; } while((this) && 0);");
/*fuzzSeed-221406266*/count=1045; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.atan2((mathy0(x, mathy0((2**53+2 | 0), (Math.atan2(( + x), ( + y)) >>> 0))) ? x : Math.atanh(( + Math.sqrt((x | 0))))), ((( ! Math.trunc(( + x))) | 0) >>> 0))) != Math.fround(Math.fround(Math.expm1(Math.fround(((Math.atan2(( ! (x ** (x >>> 0))), y) | (( + 0/0) ? y : x)) >>> 0))))))); }); testMathyFunction(mathy1, [0x100000000, -0x0ffffffff, Math.PI, Number.MAX_VALUE, -(2**53-2), -0x080000001, -0x100000000, 1, 0x080000001, -(2**53), -0x100000001, Number.MIN_VALUE, -0, 2**53+2, 1.7976931348623157e308, -(2**53+2), 0.000000000000001, 2**53, 0x080000000, -0x080000000, 0x07fffffff, 2**53-2, 0, -Number.MAX_SAFE_INTEGER, -1/0, 0/0, 42, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1046; tryItOut("m2.has(t1);");
/*fuzzSeed-221406266*/count=1047; tryItOut("testMathyFunction(mathy1, [-(2**53-2), 2**53+2, 1.7976931348623157e308, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, -(2**53), 1/0, 0, -0x080000001, 42, 0x100000000, -(2**53+2), -0x080000000, -Number.MAX_VALUE, -0x100000000, Number.MAX_VALUE, -0, Number.MIN_VALUE, -0x100000001, -0x07fffffff, 0x07fffffff, Math.PI, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, 0x0ffffffff, 0x100000001, 0.000000000000001, 1, 0x080000001]); ");
/*fuzzSeed-221406266*/count=1048; tryItOut("mathy1 = (function(x, y) { return ( + ( + (Math.min((Math.imul((Math.hypot((( + (y >> x)) <= ((y & x) <= Math.fround(1.7976931348623157e308))), (y >>> 0)) | 0), (( ! (Math.log2((x >>> 0)) | 0)) | 0)) | 0), ( ! (mathy0(( + ( + Math.log1p(y))), (Math.atan2(y, Math.PI) | 0)) >>> 0))) >>> 0))); }); testMathyFunction(mathy1, [0x100000000, -(2**53), -0, 2**53+2, 0x080000000, -Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, 0.000000000000001, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -Number.MAX_VALUE, 0x080000001, -0x100000000, -1/0, -0x100000001, 0, -(2**53+2), 0/0, 1/0, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), 2**53, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=1049; tryItOut("/*tLoop*/for (let y of /*MARR*/[0x3FFFFFFE, 0x3FFFFFFE, \"\\u7B92\", true, true, 0x3FFFFFFE, \"\\u7B92\", 0x3FFFFFFE, function(){}, true, \"\\u7B92\", \"\\u7B92\", null, 0x3FFFFFFE, function(){}, true, null, 0x3FFFFFFE, true, \"\\u7B92\", 0x3FFFFFFE, 0x3FFFFFFE, null, \"\\u7B92\", true, function(){}, function(){}, 0x3FFFFFFE, true, function(){}, true, null, \"\\u7B92\", null, true, \"\\u7B92\", null, \"\\u7B92\", function(){}, 0x3FFFFFFE, null, 0x3FFFFFFE, \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", null, null, function(){}, null, true, true, null, null, \"\\u7B92\", 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", \"\\u7B92\", function(){}, 0x3FFFFFFE]) { Array.prototype.pop.call(a1); }");
/*fuzzSeed-221406266*/count=1050; tryItOut("g2.m0.delete(g2);");
/*fuzzSeed-221406266*/count=1051; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-221406266*/count=1052; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.round(Math.fround((Math.log10((((Math.expm1(x) | 0) ? x : Math.min(x, Math.imul(( + Math.fround(Math.imul(( + (x << 0x100000001)), Math.fround(0x100000000)))), ( + x)))) | 0)) | 0)))); }); testMathyFunction(mathy2, [0, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), -0x100000000, Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, 0/0, Math.PI, -(2**53), 2**53, -(2**53+2), 1/0, -1/0, -Number.MIN_VALUE, -0x100000001, 0x100000000, 0x0ffffffff, 2**53-2, -0, 0x080000000, 42, 0x080000001, 0x100000001, 0x07fffffff, -0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1053; tryItOut("t2 = new Uint8Array(({valueOf: function() { v1 = Object.prototype.isPrototypeOf.call(this.f0, b2);return 13; }}));");
/*fuzzSeed-221406266*/count=1054; tryItOut("mathy3 = (function(x, y) { return ( - Math.asinh(( ! x))); }); ");
/*fuzzSeed-221406266*/count=1055; tryItOut("a0.splice(15, (4277), a2);");
/*fuzzSeed-221406266*/count=1056; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((( + (( - 42) | 0)) >>> 0) >> ( + ( + (Math.imul(Math.cos(Math.hypot(x, (Math.PI >>> 0))), Math.acosh(Math.atanh(x))) * Math.atan2(-0x080000001, x))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -0x07fffffff, 1/0, 0x100000001, -Number.MAX_VALUE, -(2**53-2), 1, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53), -0x100000001, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, 0x080000001, -0x080000000, 0x100000000, -0x100000000, 0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, 2**53, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 0x0ffffffff, -0, 42, 0, -0x080000001]); ");
/*fuzzSeed-221406266*/count=1057; tryItOut("(((({window: Object.defineProperty(eval, \"2\", ({enumerable: false}))}))(x(Math.ceil(-17)) = new function(y) { yield y; [1];; yield y; }(x = {}))))\u0009;");
/*fuzzSeed-221406266*/count=1058; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + (( + (( + ((Math.min(( ! 2**53+2), x) / Math.exp(mathy2((x | 0), -0x07fffffff))) >>> 0)) << ( + (Math.imul((Math.log(y) | 0), (Math.pow(( + ( ~ (( ~ y) >>> 0))), (( ~ -0x07fffffff) >>> 0)) >>> 0)) | 0)))) | 0)); }); testMathyFunction(mathy5, [Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, -(2**53-2), 0/0, -0x080000000, 0, -0x07fffffff, 2**53+2, 0.000000000000001, 2**53-2, -0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, Number.MAX_VALUE, -0x0ffffffff, -(2**53), 0x100000001, 42, 0x080000001, -0x100000001, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 1, 0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=1059; tryItOut("v2 = g0.eval(\"function f1(b0)  { return (/*UUV1*/(get.now = function shapeyConstructor(oqitwg){\\\"use strict\\\"; Object.defineProperty(this, 10, ({enumerable: oqitwg}));delete this[\\\"setTime\\\"];Object.freeze(this);this[\\\"__count__\\\"] = window = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: (new Function(\\\"return \\\\\\\"\\\\\\\\u33C4\\\\\\\";\\\")), enumerate: function() { return []; }, keys: function() { return []; }, }; })( /x/g ), oqitwg);Object.freeze(this);for (var ytqmxpqzg in this) { }return this; })) } \");");
/*fuzzSeed-221406266*/count=1060; tryItOut("\"use strict\";  for \u000c(var c of x) {g0.__iterator__ = (function() { try { v0 = (o0 instanceof g1); } catch(e0) { } try { v1 = t1.length; } catch(e1) { } try { o2 = Object.create(f0); } catch(e2) { } o2 = Object.create(new RegExp(\"$[^\\\\m-\\u8937\\\\\\u00d5]^{0}+(?!\\\\b)|([^\\\\w\\u5d14-\\\\x18]{4})+\", \"y\")); return g0; });{} }");
/*fuzzSeed-221406266*/count=1061; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:\\\\b)|\\\\2[^]{1048577,1048580}\\\\uF8A3|(?=\\\\B+))\", \"yi\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-221406266*/count=1062; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1063; tryItOut("Array.prototype.shift.call(a1, /*RXUE*/new RegExp(\"\\\\1{4,}|([\\\\l-\\\\u35FB\\u7044](?=.))|(?:\\\\3+)+|(?=.*)\", \"im\").exec(\"\"), g0);");
/*fuzzSeed-221406266*/count=1064; tryItOut("");
/*fuzzSeed-221406266*/count=1065; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy0(((mathy0(-0x080000000, y) >>> ((Math.cos((((mathy0(x, (x | 0)) | 0) == -0) | 0)) | 0) >>> 0)) >>> 0), (Math.imul((((( ~ -0x080000001) ^ (( + Math.sin(( + Math.fround(( ~ Math.fround(x)))))) >>> 0)) >>> 0) | 0), (Math.log10(((y ^ Number.MAX_VALUE) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy2, [2**53+2, Math.PI, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -0x0ffffffff, -0, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 42, 0, -0x07fffffff, 0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000000, -(2**53), 0x100000000, 1/0, -0x080000001, 1, -0x100000001, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 2**53, -(2**53+2), 2**53-2, 0x100000001, -0x100000000]); ");
/*fuzzSeed-221406266*/count=1066; tryItOut("\"use strict\"; v0 = (a0 instanceof i2);");
/*fuzzSeed-221406266*/count=1067; tryItOut("\"use strict\"; function shapeyConstructor(pvlzvv){delete pvlzvv[\"toSource\"];delete pvlzvv[\"toSource\"];delete pvlzvv[\"toSource\"];if ( /x/g ) pvlzvv[\"toSource\"] = (function(x, y) { \"use strict\"; return x; });pvlzvv[\"toSource\"] = window >>> e;return pvlzvv; }/*tLoopC*/for (let b of x) { try{let grrdoe = shapeyConstructor(b); print('EETT'); for (var v of a1) { g1.v1 = (this.m2 instanceof g1.o2.t1); }}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-221406266*/count=1068; tryItOut("/*infloop*/M:while((4277))yield b;function x(x)\"use asm\";   var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0x77a9285d);\n    i1 = (1);\n    (Int16ArrayView[((i1)*0xfffff) >> 1]) = ((0xf5e56c5d));\n    i1 = (0x719eb4b2);\n    (Float32ArrayView[4096]) = ((+(0xc49157e9)));\n    return +((Float64ArrayView[((i1)-(i1)) >> 3]));\n  }\n  return f;(w);");
/*fuzzSeed-221406266*/count=1069; tryItOut("mathy5 = (function(x, y) { return (Math.log2(((( ~ y) ? (((y >>> 0) & (( + ( ~ Math.fround(x))) >>> 0)) >>> 0) : x) >>> 0)) , mathy4(( + ((Math.atanh(y) | 0) ? y : x)), ( + (((-1/0 >>> 0) != ((mathy1((( + (( + y) ? y : (Math.PI >>> 0))) >>> 0), (x >>> 0)) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, /*MARR*/[this, x, x, this, this, x, x, x, x, this, x, x, x, this, this, x, this, this, this, x, this, this, this, this, this, this, this, x, this, x, x, this, this, this, this, this, this, this, x, this, x, x, this, x, this, this, x, this, x, x, x]); ");
/*fuzzSeed-221406266*/count=1070; tryItOut("\"use strict\"; e1 + '';");
/*fuzzSeed-221406266*/count=1071; tryItOut("b2 + o0;");
/*fuzzSeed-221406266*/count=1072; tryItOut("h0.__proto__ = v2;");
/*fuzzSeed-221406266*/count=1073; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=1074; tryItOut("\"use strict\"; L:with((\"\\u26F7\" ? -19 : window)){/*ADP-2*/Object.defineProperty(this.a2, ({valueOf: function() { a0.valueOf = (function() { for (var j=0;j<17;++j) { f2(j%4==1); } });return 19; }}), { configurable: (x % 6 != 4), enumerable: false, get: (function() { try { p2 + ''; } catch(e0) { } try { m2.has(h0); } catch(e1) { } try { g1.offThreadCompileScript(\"Object.defineProperty(this, \\\"a2\\\", { configurable: true, enumerable: true,  get: function() { s0 = ''; return []; } });\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 != 0), noScriptRval: false, sourceIsLazy: new RegExp(\"(?!(?!(?:\\\\d|\\\\b))|(?=[-\\ubb29\\u008c\\\\w\\\\b-\\uc0c1]))(?=(?:[\\\\x2d-\\\\x94]))\", \"gyim\"), catchTermination: /(.)/yim })); } catch(e2) { } ; return a2; }), set: (function() { for (var j=0;j<38;++j) { this.f1(j%4==1); } }) });print(x); }");
/*fuzzSeed-221406266*/count=1075; tryItOut("\"use strict\"; ;");
/*fuzzSeed-221406266*/count=1076; tryItOut("g1.g1 = this;");
/*fuzzSeed-221406266*/count=1077; tryItOut("\"use strict\"; print(this.g2);");
/*fuzzSeed-221406266*/count=1078; tryItOut(";");
/*fuzzSeed-221406266*/count=1079; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1080; tryItOut("\"use strict\"; var w, \u3056, x, bnhwfb, pdvtjm, xgdann, window = Math.atan2(true, 10);(void schedulegc(g2));");
/*fuzzSeed-221406266*/count=1081; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan(mathy2(( + Math.min(-0x07fffffff, mathy3(Math.fround((((y >>> 0) ? ( + y) : ( + Math.fround(Math.ceil(y)))) | 0)), ((( + -(2**53)) >>> 0) >>> 0)))), ((Math.fround(Math.hypot(( + -Number.MAX_VALUE), y)) | (( ~ (( - y) | 0)) | 0)) >>> 0))); }); ");
/*fuzzSeed-221406266*/count=1082; tryItOut("{e2.has(s2); }");
/*fuzzSeed-221406266*/count=1083; tryItOut("\"use asm\"; testMathyFunction(mathy1, /*MARR*/[new String(''),  \"\" , new String(''), new String(''), new String(''), function(){}, new String(''),  \"\" , function(){}, new String(''),  \"\" , new String(''), function(){}, function(){},  \"\" , new String(''),  \"\" , new String(''), new String(''), new String(''), new String(''), new String(''),  \"\" , new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), function(){}, new String(''), function(){},  \"\" , new String(''), new String(''), function(){}, new String(''),  \"\" ,  \"\" ,  \"\" ,  \"\" , new String(''), new String(''), new String(''),  \"\" , new String(''), new String(''),  \"\" , function(){},  \"\" ,  \"\" , new String(''),  \"\" , new String(''),  \"\" , new String(''),  \"\" , function(){},  \"\" ,  \"\" , new String(''),  \"\" ,  \"\" , new String(''), new String(''), new String(''),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new String(''), new String(''), function(){}, function(){}, function(){}, function(){}, function(){}, new String(''),  \"\" , new String(''),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new String(''), new String(''), new String(''), new String(''),  \"\" , function(){},  \"\" , new String(''), new String(''),  \"\" , function(){}, function(){},  \"\" , new String('')]); ");
/*fuzzSeed-221406266*/count=1084; tryItOut("neuter(b1, \"change-data\");");
/*fuzzSeed-221406266*/count=1085; tryItOut("/*RXUB*/var r = /(?:(?:[^]))[^]\\b*?|(?=\\b)+?|[\u2161]*?*?{3,}((?:(?!\\D)))+(?:\\B(?=.)^*??)*?/g; var s = \"\\u0011\\u00111K  \\u0014\"; print(s.split(r)); ");
/*fuzzSeed-221406266*/count=1086; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.atan2(mathy1(( ~ y), (Math.fround(Math.log2(Math.fround(x))) << (Math.fround(Math.sqrt((x | 0))) ? (Math.fround(Math.min(x, x)) >>> 0) : (-0x100000001 >>> 0)))), Math.imul(( + ((( + ( - (Math.asin(Math.fround(Math.atan(y))) >>> 0))) != ((( + (2**53+2 << y)) >>> 0) % x)) / ( ~ (( ~ x) >>> 0)))), (( + (Math.cbrt(( + -0x0ffffffff)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-221406266*/count=1087; tryItOut("\"use asm\"; m2.has(s2);print(this);");
/*fuzzSeed-221406266*/count=1088; tryItOut("\"use strict\"; /*oLoop*/for (giqybl = 0; giqybl < 52; ++giqybl) { o2.f2(e2); } ");
/*fuzzSeed-221406266*/count=1089; tryItOut("/*tLoop*/for (let z of /*MARR*/[new String(''), -Infinity, ({}), ({}), new String(''), -Infinity, new String(''), -Infinity, ({}), new String(''), -Infinity, new String(''), new String(''), ({}), -Infinity, new String(''), -Infinity, -Infinity, ({}), -Infinity, ({}), new String(''), -Infinity, new String(''), ({}), ({}), new String(''), new String(''), ({}), -Infinity, new String(''), new String(''), -Infinity, -Infinity, new String(''), ({}), -Infinity, new String(''), new String(''), new String(''), new String(''), -Infinity, new String(''), -Infinity, new String(''), ({}), new String(''), new String(''), new String(''), -Infinity, new String(''), new String(''), ({}), ({}), ({}), -Infinity, new String(''), -Infinity, -Infinity, new String(''), -Infinity, ({}), new String(''), ({}), -Infinity, new String(''), -Infinity, new String(''), -Infinity, ({}), new String(''), new String(''), -Infinity, -Infinity, ({}), -Infinity, -Infinity, -Infinity, new String(''), new String(''), -Infinity, ({}), -Infinity]) { f2.__proto__ = p1; }");
/*fuzzSeed-221406266*/count=1090; tryItOut("/*RXUB*/var r = /(?!(?=\\2)|\\3)+/gyim; var s = \"\"; print(s.split(r)); \nprint(o2.s2);\n");
/*fuzzSeed-221406266*/count=1091; tryItOut("\"use strict\"; t0 = new Int16Array(b0);");
/*fuzzSeed-221406266*/count=1092; tryItOut("v0 = Object.prototype.isPrototypeOf.call(this.a2, m0);");
/*fuzzSeed-221406266*/count=1093; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.log10(( + Math.imul((( + Math.pow((y <= x), (( + y) ^ ( + (Math.tan((x >>> 0)) >>> 0))))) >>> Math.tan(x)), Math.sin(x)))); }); testMathyFunction(mathy0, [undefined, objectEmulatingUndefined(), '/0/', 1, (new Boolean(false)), true, (new Number(-0)), NaN, [0], [], (function(){return 0;}), (new String('')), /0/, '0', '', ({valueOf:function(){return '0';}}), (new Number(0)), false, -0, null, (new Boolean(true)), 0.1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '\\0', 0]); ");
/*fuzzSeed-221406266*/count=1094; tryItOut("let (z) { (\"\\u04EE\"); }\n/*vLoop*/for (let hvoycn = 0; hvoycn < 31; ++hvoycn) { let z = hvoycn; m0.get(h2); } \n");
/*fuzzSeed-221406266*/count=1095; tryItOut("b0 = Proxy.create(h1, s1);");
/*fuzzSeed-221406266*/count=1096; tryItOut("mathy4 = (function(x, y) { return ( - (( ~ Math.fround((Math.atan((( + Math.sign(mathy1(Math.acos(0/0), y))) | 0)) | 0))) | 0)); }); testMathyFunction(mathy4, ['/0/', 0, false, 1, '0', 0.1, '', (new Boolean(true)), (new Number(-0)), ({valueOf:function(){return 0;}}), undefined, [0], '\\0', ({toString:function(){return '0';}}), (new String('')), -0, (new Number(0)), objectEmulatingUndefined(), /0/, (new Boolean(false)), null, ({valueOf:function(){return '0';}}), [], NaN, (function(){return 0;}), true]); ");
/*fuzzSeed-221406266*/count=1097; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ((( + mathy2((Math.atan((( ! x) >>> 0)) << Math.log2((x , -(2**53-2)))), (x % x))) >>> 0) + (mathy2((Math.abs((Math.fround(mathy2(Math.fround(x), (( ! (x ? Math.fround(Number.MAX_VALUE) : ( + x))) | 0))) | 0)) | 0), Math.pow(x, mathy1(( + Math.min((x && x), ( ! y))), y))) >>> 0))); }); ");
/*fuzzSeed-221406266*/count=1098; tryItOut("\"use strict\"; testMathyFunction(mathy1, [42, 1.7976931348623157e308, 0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -(2**53+2), -1/0, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 2**53+2, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53), -0x080000000, -Number.MIN_VALUE, -0, -(2**53-2), 1/0, -0x07fffffff, 0x080000001, 0x100000000, -Number.MAX_VALUE, 0, 0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, Math.PI, -0x100000001, -0x100000000, 2**53]); ");
/*fuzzSeed-221406266*/count=1099; tryItOut("/*vLoop*/for (let tofmtk = 0; tofmtk < 134; ++tofmtk) { var b = tofmtk; return; } ");
/*fuzzSeed-221406266*/count=1100; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s1; print(s.match(r)); ");
/*fuzzSeed-221406266*/count=1101; tryItOut("var c = (makeFinalizeObserver('tenured')) >= /*UUV1*/(c.find = function(q) { return q; });print(delete y.a);");
/*fuzzSeed-221406266*/count=1102; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ( ! ( + Math.fround(Math.trunc(Math.fround((( ! (( + (y && ( + Math.sinh(( + Number.MIN_SAFE_INTEGER))))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy4, [0x0ffffffff, -Number.MIN_VALUE, 0/0, -0x100000001, -(2**53-2), -(2**53), Math.PI, -0, 1, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, 0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, 1/0, -0x100000000, 2**53-2, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, 2**53, 0, 1.7976931348623157e308, 0.000000000000001, 42, 0x100000000]); ");
/*fuzzSeed-221406266*/count=1103; tryItOut("((yield /*UUV2*/(e.isFinite = e.exp)));");
/*fuzzSeed-221406266*/count=1104; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -140737488355329.0;\n    d2 = (+((-0.0625)));\n    return ((((0x61a1e419) ? ((+((+pow(((+(0.0/0.0))), ((Float32ArrayView[0])))))) < (d2)) : (0x6b55ed56))))|0;\n  }\n  return f; })(this, {ff: arguments.callee.caller.caller.caller.caller.caller}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0, ({toString:function(){return '0';}}), false, /0/, null, (new String('')), '', ({valueOf:function(){return 0;}}), 1, (new Boolean(false)), '0', '\\0', [], (new Number(0)), (new Boolean(true)), ({valueOf:function(){return '0';}}), 0.1, '/0/', -0, NaN, (function(){return 0;}), objectEmulatingUndefined(), [0], true, (new Number(-0)), undefined]); ");
/*fuzzSeed-221406266*/count=1105; tryItOut("\"use strict\"; /*hhh*/function weefie(){Array.prototype.unshift.call(a1, x, this.o1, p2, f2, b2, this.v2, f2, f2, a2, this.s2, b2, g0, g1.v1);}/*iii*/");
/*fuzzSeed-221406266*/count=1106; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(( ! ( ~ x))) & Math.fround(Math.fround((Math.fround(Math.log10((((((Math.trunc(( + x)) + y) >>> 0) >>> 0) % (Math.fround(Math.sqrt(Math.fround(x))) >>> 0)) >>> 0))) - Math.fround(((Math.acosh((Math.imul((y | 0), (y >>> 0)) | 0)) >>> 0) << mathy0(x, ( ! Math.fround(1))))))))); }); testMathyFunction(mathy3, [-0x100000001, 1, 0x0ffffffff, -Number.MIN_VALUE, 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, -0x100000000, -(2**53), -0, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, 0, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, 0x100000000, 1/0, -(2**53-2), -Number.MAX_VALUE, 0x080000000, 0x07fffffff, 2**53-2, 42, Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1107; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[ /x/ , true, (0/0)]); ");
/*fuzzSeed-221406266*/count=1108; tryItOut("g2.v1 = a0.reduce, reduceRight((function() { for (var j=0;j<15;++j) { f0(j%4==0); } }), \"\\u29C1\");");
/*fuzzSeed-221406266*/count=1109; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, -0x100000001, 0x100000000, -1/0, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, -0x07fffffff, -(2**53-2), 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, Math.PI, 1, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53), -0x100000000, -(2**53+2), 0.000000000000001, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -0x080000000, 0x100000001, -Number.MIN_VALUE, 2**53, 0]); ");
/*fuzzSeed-221406266*/count=1110; tryItOut("v2 = t1.length;");
/*fuzzSeed-221406266*/count=1111; tryItOut("\"use strict\"; i1.toSource = (function() { for (var j=0;j<129;++j) { f1(j%4==1); } });");
/*fuzzSeed-221406266*/count=1112; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[function(){}, function(){}, null]); ");
/*fuzzSeed-221406266*/count=1113; tryItOut("\"use strict\"; /*oLoop*/for (let noaqyh = 0; noaqyh < 14; ++noaqyh) { for(var \u0009[z, d] = new RegExp(\"(.|((\\\\W[\\\\n-\\\\cG\\\\cO-\\\\cA].))|(?!.)|\\\\2{4,6})\", \"yim\") in  /x/g ) {for (var p in o1) { try { v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: [1,,], sourceIsLazy: [1], catchTermination: (d % 6 != 1), sourceMapURL: s0 })); } catch(e0) { } try { v2 = t0.byteOffset; } catch(e1) { } m2 + e0; }(new RegExp(\"\\\\2?\", \"gi\")); } } ");
/*fuzzSeed-221406266*/count=1114; tryItOut("\"use strict\"; Object.defineProperty(this, \"o0\", { configurable: true, enumerable: y == x,  get: function() {  return Object.create(m2); } });");
/*fuzzSeed-221406266*/count=1115; tryItOut("e2.has(e1);");
/*fuzzSeed-221406266*/count=1116; tryItOut("\"use asm\"; var pldxwj = new ArrayBuffer(8); var pldxwj_0 = new Int16Array(pldxwj); print(pldxwj);");
/*fuzzSeed-221406266*/count=1117; tryItOut(";");
/*fuzzSeed-221406266*/count=1118; tryItOut("\"use strict\"; this.zzz.zzz;return (arguments.callee.caller.arguments) = Math.expm1(-15);");
/*fuzzSeed-221406266*/count=1119; tryItOut("\"use strict\"; wjdoxj(x);/*hhh*/function wjdoxj(d, ...x){throw length;}");
/*fuzzSeed-221406266*/count=1120; tryItOut("/*infloop*/for(a; (eval(\"/* no regression tests found */\", this.__defineGetter__(\"e\", (this.trimRight).apply))); (x = -23)) for (var v of this.e2) { try { v1 = Object.prototype.isPrototypeOf.call(p1, s0); } catch(e0) { } try { h0.keys = (function() { for (var j=0;j<68;++j) { f0(j%5==1); } }); } catch(e1) { } /*MXX2*/g1.Date.prototype.setUTCFullYear = h0; }");
/*fuzzSeed-221406266*/count=1121; tryItOut("testMathyFunction(mathy0, /*MARR*/[0x100000000, (void 0), \"\\u7D18\", (void 0), 0x100000000, \"\\u7D18\", \"\\u7D18\", (void 0)]); ");
/*fuzzSeed-221406266*/count=1122; tryItOut("v1 = new Number(0);s1.__iterator__ = (function(j) { if (j) { b0 = t1.buffer; } else { f0.toSource = (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return +((((d0) >= ((d0) + (+(1.0/0.0)))) ? (d0) : (-134217727.0)));\n  }\n  return f; }); } });");
/*fuzzSeed-221406266*/count=1123; tryItOut("if(false\u000c) {print(uneval(i0));(\u000c(0x100000001\n).entries(x, x)); } else  if ((p={}, (p.z =  /x/g )())) o2.m2.has(p2);");
/*fuzzSeed-221406266*/count=1124; tryItOut("this.v1 = g0.eval(\"(new mathy0({} = c =  \\\"\\\"  ?  /x/g  :  /x/g  & Object.defineProperty(x, this, ({})) | x%=2.valueOf(\\\"number\\\")))\");");
/*fuzzSeed-221406266*/count=1125; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (mathy2((( + (( + Math.imul(Math.expm1((y >>> 0)), (Math.imul(((2**53+2 , Math.fround(Number.MAX_SAFE_INTEGER)) >>> 0), (Math.cbrt(x) | 0)) >>> 0))) ? ( ~ mathy1(Math.fround((42 ** Math.fround((x == (((y | 0) << (x | 0)) | 0))))), y)) : (mathy1(Math.fround((((y >>> 0) << ((((x >>> 0) ? (x >>> 0) : (x | 0)) >>> 0) | 0)) | 0)), Math.max(( ~ y), Math.imul(( + (x >= -Number.MIN_SAFE_INTEGER)), x))) | 0))) | 0), Math.min(Math.pow(( - mathy1((y >>> 0), 1)), Math.hypot(( ~ Math.fround(y)), Math.log1p(mathy3(x, y)))), ( ~ Math.acos((0x0ffffffff >>> 0))))) | 0); }); testMathyFunction(mathy4, [[], ({valueOf:function(){return '0';}}), (new Number(-0)), 0.1, '/0/', false, [0], undefined, '\\0', NaN, (new Boolean(false)), (new String('')), (function(){return 0;}), null, -0, /0/, objectEmulatingUndefined(), 0, '0', ({valueOf:function(){return 0;}}), (new Boolean(true)), ({toString:function(){return '0';}}), true, 1, (new Number(0)), '']); ");
/*fuzzSeed-221406266*/count=1126; tryItOut("mathy2 = (function(x, y) { return Math.acosh(Math.min((Math.fround(( + Math.imul(( + y), ( + ( ~ x))))) >>> Math.fround(0.000000000000001)), (Math.sign(Math.hypot(( + mathy0(Math.atan2(( + y), ( + x)), y)), Math.imul(Math.fround(mathy1((y & Math.fround(0x080000001)), x)), Math.pow(y, (x >>> 0))))) >>> 0))); }); testMathyFunction(mathy2, [0x0ffffffff, 0.000000000000001, -1/0, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, 2**53-2, -0x0ffffffff, -(2**53+2), 42, 0x07fffffff, 2**53+2, 1.7976931348623157e308, -0x100000001, 0x080000001, -(2**53), -Number.MIN_VALUE, 2**53, 0x100000001, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, 0, -(2**53-2), 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -0, 0/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-221406266*/count=1127; tryItOut("/*ODP-3*/Object.defineProperty(o2.t1, \"prototype\", { configurable: false, enumerable:  '' , writable: w >= y, value: a0 });");
/*fuzzSeed-221406266*/count=1128; tryItOut("mathy3 = (function(x, y) { return Math.abs((Math.cos(Math.fround((( + Math.fround(y)) | 0))) | 0)); }); testMathyFunction(mathy3, [-0, 0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_VALUE, -0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, 1, 0x07fffffff, 0x100000000, Number.MIN_VALUE, 1/0, 0/0, 0x080000000, 2**53, 0, 0x0ffffffff, 42, Math.PI, -0x100000000, 0.000000000000001, -1/0, 2**53+2, 0x080000001]); ");
/*fuzzSeed-221406266*/count=1129; tryItOut("v1 = evalcx(\"/*infloop*/for(let y = x; (void shapeOf(false.eval(\\\"new RegExp(\\\\\\\"($[^\\\\\\\\\\\\\\\\d\\\\\\\\\\\\\\\\D\\\\\\\\\\\\\\\\v-\\\\\\\\u00b7\\\\\\\\\\\\\\\\u00c1]{4,}(\\\\\\\\\\\\\\\\1))|(?:((?:\\\\\\\\\\\\\\\\B{33554431,}))){17179869184,17179869184}{3,}\\\\\\\", \\\\\\\"gym\\\\\\\")\\\"))); ({1: (mathy0).call( /x/ ,  '' , 7) })) /*RXUB*/var r = new RegExp(\\\"(?=.)|\\\\\\\\d*?\\\", \\\"y\\\"); var s = \\\"__\\\"; print(r.test(s)); \", g1);");
/*fuzzSeed-221406266*/count=1130; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + (( + ( ! mathy0(Math.fround(Math.acosh((( + 0x080000000) | ( + x)))), (Math.fround(( ! Math.fround(Math.fround(mathy0(Math.fround(y), Math.fround(y)))))) | 0)))) !== Math.log(( + Math.max(y, (mathy1(Math.fround(Math.pow(x, x)), Math.clz32(( + y))) >>> 0)))))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0x0ffffffff, -0x07fffffff, 0, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, 1, 0x07fffffff, 2**53, -0x080000001, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53+2, -0x0ffffffff, -0x100000000, 0/0, -0, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0x100000000, 42, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -1/0, -(2**53+2), 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=1131; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=\\b|(?!\\S\\s\\s+?\\B{1,}|$\\s)*?{3,})[]/im; var s = \"\\ue19b\"; print(s.match(r)); ");
/*fuzzSeed-221406266*/count=1132; tryItOut("\"use strict\"; i2 = this.a1.entries;");
/*fuzzSeed-221406266*/count=1133; tryItOut("\"use strict\"; ;");
/*fuzzSeed-221406266*/count=1134; tryItOut("mathy4 = (function(x, y) { return ((Math.atanh(( + Math.cosh(( + Math.fround(Math.tan(-(2**53-2))))))) >>> 0) ? ( + Math.log(( + ( - (Math.fround(Math.imul(Math.fround(x), Math.fround(x))) ? (y ? ( ! x) : x) : (x | 0)))))) : Math.max((Math.atan((mathy0(x, Math.sqrt(x)) | 0)) | 0), (( ! Math.min((Number.MIN_VALUE == Math.hypot(Math.fround(Math.max(-0x07fffffff, x)), x)), ( - (x >>> 0)))) >>> 0))); }); testMathyFunction(mathy4, [0x080000000, 1, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, -0, 1.7976931348623157e308, 0.000000000000001, -(2**53), 0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 42, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -0x100000001, 0/0, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, 2**53-2, 2**53+2, -(2**53+2), -0x100000000, -0x07fffffff, 0x100000001, 0x100000000, 0x080000001, Math.PI, 0x07fffffff, -(2**53-2), Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-221406266*/count=1135; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1136; tryItOut("\"use strict\"; \"use asm\"; /*hhh*/function egvtvf(...eval){2;}egvtvf([\"\u03a0\"]);");
/*fuzzSeed-221406266*/count=1137; tryItOut("");
/*fuzzSeed-221406266*/count=1138; tryItOut("i1.next();");
/*fuzzSeed-221406266*/count=1139; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + mathy1(Math.fround((Math.tan((( + (((mathy1(( ! 0x100000000), (Math.abs(y) >>> 0)) >>> 0) - x) ? ( + (( + ( ~ (y !== y))) % ( + (Math.min((y | 0), (y | 0)) | 0)))) : (-0x0ffffffff & Math.fround(( ! Math.fround(( - ( ~ y)))))))) >>> 0)) >>> 0)), ( + ( ! ( + Math.sign(( + Math.tanh(Math.fround(Math.acosh(Math.fround(x))))))))))); }); testMathyFunction(mathy2, [2**53, -0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, 0x080000001, -0, 42, -0x07fffffff, 1/0, 0, -Number.MIN_VALUE, -0x080000000, 0x100000000, 1, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0/0, 0x0ffffffff, -0x100000000, -(2**53-2), 2**53+2, -0x0ffffffff, 0.000000000000001, -(2**53+2), 0x100000001, 0x080000000, 2**53-2, -1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1140; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\3*)\", \"gyim\"); var s = \"\"; print(s.replace(r,  '' , \"gym\")); ");
/*fuzzSeed-221406266*/count=1141; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1142; tryItOut("L: {v0 = evalcx(\"function f0(g2)  { \\\"use strict\\\"; print(x); } \", g0);a2.push(g0.b2); }");
/*fuzzSeed-221406266*/count=1143; tryItOut("testMathyFunction(mathy1, [-0, -0x100000001, 0x100000000, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -Number.MAX_VALUE, 0, Math.PI, 0x100000001, 0.000000000000001, -0x080000001, 2**53-2, 2**53, -1/0, 0/0, 1/0, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, -0x100000000, 42, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=1144; tryItOut("");
/*fuzzSeed-221406266*/count=1145; tryItOut("mathy0 = (function(x, y) { return (Math.min(( + ( ~ (Math.hypot(((((y | 0) ? (x >>> 0) : (x | 0)) | 0) >>> 0), Math.fround(y)) >>> 0))), Math.abs(((( ~ (x | 0)) | 0) / x))) >>> 0); }); testMathyFunction(mathy0, [-0x07fffffff, -Number.MAX_VALUE, 0x080000001, 0.000000000000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, 2**53, -(2**53), -0x080000001, -0x100000001, 42, 1.7976931348623157e308, 0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, 1, -0x100000000, Number.MAX_VALUE, Math.PI, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -(2**53-2), 0, -Number.MIN_VALUE, 2**53-2, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, 0x100000001]); ");
/*fuzzSeed-221406266*/count=1146; tryItOut("v2 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-221406266*/count=1147; tryItOut("Array.prototype.pop.call(a1);");
/*fuzzSeed-221406266*/count=1148; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=1149; tryItOut("v0 = (g2.m2 instanceof o2);\nx = this.m1;\n");
/*fuzzSeed-221406266*/count=1150; tryItOut("\"use strict\"; \"use asm\"; m2.get(m0);");
/*fuzzSeed-221406266*/count=1151; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var atan = stdlib.Math.atan;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -17592186044417.0;\n    var i4 = 0;\n    var i5 = 0;\n    i5 = (!(i2));\n    i1 = (!(0x8918d96c));\n    switch ((0x10f613b7)) {\n      case -3:\n        {\n          (Float64ArrayView[2]) = ((+sqrt(((((((((i4)-(!(i4)))>>>(-(x = /./gyi))))) >> ((/*FFI*/ff(((~((0xfd676160)+(i4)-(i5)))), ((Math.max(25, (p={}, (p.z = (b =  \"\" ))())))), ((d3)), ((abs((~~(+atan(((536870912.0))))))|0)), ((((-1025.0)) - ((295147905179352830000.0)))), ((d3)), ((16777217.0)), ((7.737125245533627e+25)), ((9223372036854776000.0)), ((-68719476737.0)), ((-18446744073709552000.0)), ((295147905179352830000.0)), ((6.189700196426902e+26)), ((-32769.0)), ((562949953421312.0)))|0))))))));\n        }\n        break;\n      case -3:\n        i4 = ((i4) ? (i2) : (i0));\n        break;\n      case 1:\n        i0 = ((0x247b273a) != (0x34304e1f));\n      case 1:\n        return +((NaN));\n      case 0:\n        (Float64ArrayView[0]) = ((-70368744177665.0));\n        break;\n      default:\n        i1 = ((-0x8000000) > (~((i0))));\n    }\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var dfcwee = -19; ((-3512101120).bind((Uint8ClampedArray)(/((?:(?=(?:\\b)+)?))/gm)))(); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-221406266*/count=1152; tryItOut("e0.has(e2);\nfor(x in [,,z1]) v2 = g0.runOffThreadScript();\n");
/*fuzzSeed-221406266*/count=1153; tryItOut("mathy3 = (function(x, y) { return (((Math.fround((Math.fround(((mathy0(0x0ffffffff, (Math.fround((Math.fround((y + y)) > Math.fround(x))) >>> 0)) >>> 0) !== 2**53+2)) , Math.pow(( + ( ! ( + ((Math.fround(-0x080000001) ? x : Math.fround(Number.MAX_SAFE_INTEGER)) | 0)))), (( + ((x ? x : x) | 0)) | 0)))) | 0) ? ((Math.hypot(((Math.imul(((mathy0(Math.fround(Math.max(Math.fround(Math.atan2(0, 2**53)), ( + y))), x) >>> 0) | 0), (( + (Math.acosh(((x >>> 0) || y)) >= mathy1((x >>> 0), -Number.MAX_SAFE_INTEGER))) | 0)) | 0) >>> 0), (((Math.fround((Math.round((Math.fround(Math.imul(( + x), Math.fround(x))) | 0)) | 0)) / Math.fround(0)) ? x : ((y >>> 0) !== ( + mathy0(( + (y >>> y)), (((x ? y : (x >>> 0)) >>> 0) , y))))) >>> 0)) >>> 0) | 0) : ((((Math.clz32(( + mathy0(( + y), x))) / x) >>> 0) ? Math.pow(((y / x) ** mathy2(Math.fround(Math.max(x, -(2**53))), Math.fround(0.000000000000001))), y) : Math.min(( + x), ((Math.hypot((mathy0(y, x) >>> 0), x) >>> 0) <= Math.pow((mathy1((Math.hypot(x, x) >>> 0), ((( - (0.000000000000001 | 0)) | 0) >>> 0)) >>> 0), (y | 0))))) >>> 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[0x20000000, new String(''), 0x20000000, {x:3}, (z = ((void options('strict')))), {x:3}, (z = ((void options('strict')))), 0x20000000, -Infinity, 0x20000000, new String(''), new String(''), 0x20000000, {x:3}, new String(''), new String(''), new String(''), -Infinity, (z = ((void options('strict')))), new String(''), {x:3}, new String(''), (z = ((void options('strict')))), {x:3}, -Infinity, (z = ((void options('strict')))), -Infinity, (z = ((void options('strict')))), 0x20000000, new String(''), {x:3}, {x:3}, -Infinity, 0x20000000, 0x20000000, (z = ((void options('strict')))), {x:3}, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, {x:3}, 0x20000000, -Infinity, {x:3}, 0x20000000, new String(''), (z = ((void options('strict')))), {x:3}, 0x20000000, new String(''), (z = ((void options('strict')))), new String(''), 0x20000000, new String(''), {x:3}, {x:3}, 0x20000000, {x:3}, -Infinity, 0x20000000, new String(''), new String(''), {x:3}, new String(''), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity]); ");
/*fuzzSeed-221406266*/count=1154; tryItOut("v2 = (e2 instanceof this.h0);");
/*fuzzSeed-221406266*/count=1155; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! Math.sqrt((( + Math.atan(Math.sin(-Number.MIN_SAFE_INTEGER))) + Math.fround(Math.pow(x, ( + x)))))); }); testMathyFunction(mathy3, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, 0.000000000000001, 2**53, -(2**53+2), 42, 2**53-2, 0/0, -0x080000001, 2**53+2, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, -0, 0x100000000, 0x100000001, Number.MAX_VALUE, 1/0, -0x080000000, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 1]); ");
/*fuzzSeed-221406266*/count=1156; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1157; tryItOut("this.o2 = Object.create(i1);");
/*fuzzSeed-221406266*/count=1158; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.max((( + (y === y)) < x), ( + (Math.fround(( ! y)) !== ((x ? y : ( + Math.min(( + x), ( + (1/0 === y))))) >>> x))))); }); testMathyFunction(mathy0, [0x100000000, 0x100000001, 0.000000000000001, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -0x07fffffff, 1/0, -0x100000001, 0x07fffffff, 2**53+2, -0, 1.7976931348623157e308, 0x0ffffffff, 1, -0x0ffffffff, 0, -Number.MIN_VALUE, 0x080000000, -0x080000000, 0/0, Math.PI, 42, -Number.MAX_VALUE, -1/0, 0x080000001, 2**53, -(2**53-2), Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-221406266*/count=1159; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(( - ( + Math.cos((Math.hypot((((x & x) | 0) | 0), (((((x + x) | 0) ** (y | 0)) | 0) | 0)) | 0))))); }); testMathyFunction(mathy0, [0x07fffffff, 2**53, Math.PI, 42, 0x080000000, 2**53+2, -(2**53+2), Number.MAX_VALUE, 0x080000001, 1/0, -0x07fffffff, 0.000000000000001, 0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0x100000000, 0x100000001, 1, 0/0, 2**53-2, -0x100000000, 0x0ffffffff, -0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, -Number.MIN_VALUE, -0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=1160; tryItOut("\"use strict\"; /*infloop*/for(arguments.callee.caller.caller.arguments in x) {g0.t0 = new Int16Array(this);e0 = new Set(a0); }");
/*fuzzSeed-221406266*/count=1161; tryItOut("mathy0 = (function(x, y) { return (( ~ Math.atan2(( + Math.cosh(-(2**53-2))), (( ~ (((-0x100000000 | 0) ** Math.cosh((Math.max(-(2**53+2), 0.000000000000001) | 0))) | 0)) >>> 0))) >>> ((((y ? Math.asinh(( + ( - ( + Number.MIN_VALUE)))) : ((( + ( - ( ~ x))) * ( + Math.log1p(1))) >>> 0)) | 0) >> ((( + Math.max(( + Math.max((Math.sqrt((0x100000000 | 0)) | 0), x)), ( + ((((Math.pow((( + ( + y)) >>> 0), Math.fround(x)) >>> 0) >>> 0) * y) >>> 0)))) ? ( + ( + (((((x >>> 0) ? (x >>> 0) : (1/0 >>> 0)) >>> 0) | 0) | ( + Math.hypot((y | 0), x))))) : ( + Math.pow(x, x))) | 0)) >>> 0)); }); testMathyFunction(mathy0, ['/0/', '0', false, 0, objectEmulatingUndefined(), undefined, [], 0.1, (new Boolean(true)), /0/, -0, NaN, ({toString:function(){return '0';}}), (new String('')), '', null, ({valueOf:function(){return 0;}}), (new Number(0)), (new Boolean(false)), '\\0', 1, (new Number(-0)), true, (function(){return 0;}), ({valueOf:function(){return '0';}}), [0]]); ");
/*fuzzSeed-221406266*/count=1162; tryItOut("f2(f1);");
/*fuzzSeed-221406266*/count=1163; tryItOut("mathy3 = (function(x, y) { return (Math.clz32(( + Math.fround(( ~ Math.fround(( ~ ( ~ (( - Math.asin((Math.hypot(-Number.MIN_VALUE, y) >>> 0))) | 0)))))))) | 0); }); testMathyFunction(mathy3, [-0, 2**53, -(2**53-2), -0x100000000, -(2**53), 1, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, 0, 0x100000000, 2**53-2, -1/0, -0x080000000, 0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, -0x080000001, -(2**53+2), -0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0x080000000, 1/0, 0x07fffffff, 42, 2**53+2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=1164; tryItOut("");
/*fuzzSeed-221406266*/count=1165; tryItOut("\"use strict\"; o1.valueOf = (function mcc_() { var gwpqyg = 0; return function() { ++gwpqyg; if (false) { dumpln('hit!'); try { v0 = g2.r1.test; } catch(e0) { } try { m1.has(a2); } catch(e1) { } v1 + ''; } else { dumpln('miss!'); try { g1.offThreadCompileScript(\"v0 = (s1 instanceof e1);\"); } catch(e0) { } a0.push(b1, g0, a0); } };})();");
/*fuzzSeed-221406266*/count=1166; tryItOut("v0 = Array.prototype.reduce, reduceRight.apply(a0, [(function(j) { if (j) { try { p2.valueOf = (function() { try { a0 = Array.prototype.concat.apply(this.a2, [this.a1, a2, o0.t0, a0, t1, t0]); } catch(e0) { } Array.prototype.reverse.call(a0, this.e0); return a0; }); } catch(e0) { } t2.valueOf = (function() { g1 + ''; return o0.o2.m2; }); } else { /*RXUB*/var r = r1; var s = s0; print(s.split(r));  } }), v0, v2, o1.p0, b0, i1, f1]);");
/*fuzzSeed-221406266*/count=1167; tryItOut("g2.offThreadCompileScript(\"function f0(a2)  { yield x } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 != 1), noScriptRval: (\nwindow), sourceIsLazy: (4277), catchTermination: x }));");
/*fuzzSeed-221406266*/count=1168; tryItOut("g1.v0 = a0.length;");
/*fuzzSeed-221406266*/count=1169; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 32.0;\n    return +((Float64ArrayView[(((0xff4a7f7a))) >> 3]));\n  }\n  return f; })(this, {ff: \u3056 = Proxy.createFunction(({/*TOODEEP*/})([[1]]), (function(y) { \"use strict\"; return this }).bind, encodeURIComponent)}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[x, (void 0), (void 0), -0x080000000, (-1/0), (-1/0), -0x080000000, x, (-1/0), (-1/0), (void 0), x]); ");
/*fuzzSeed-221406266*/count=1170; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (mathy1(Math.tan((((1/0 >= (Math.min(y, (mathy0(Math.fround(x), Math.fround(y)) >>> 0)) | 0)) | 0) | 0)), Math.fround(Math.fround(mathy2(Math.fround(Math.fround(Math.expm1(( + (Math.fround((mathy3(x, y) >>> 0)) >>> 0))))), Math.fround(( + (( + (Math.log1p((( + ( + ( + Math.pow(x, x)))) | 0)) >>> 0)) ? ( + ((((( + Math.tan(( + x))) << (y ? (-(2**53) >>> 0) : y)) >>> 0) ^ (y >>> 0)) >>> 0)) : ( + (( + (( ~ ((( + ( + x)) != y) | 0)) | 0)) < Math.fround(Math.sign(Math.fround(mathy2((y ? y : y), -1/0))))))))))))) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[x]); ");
/*fuzzSeed-221406266*/count=1171; tryItOut("\"use strict\"; h1 = o2.o0;");
/*fuzzSeed-221406266*/count=1172; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! ( + ((Math.log10((2**53 + Math.round(Math.fround(Math.min(Math.fround(y), x))))) | 0) << (( ! x) >>> 0)))); }); testMathyFunction(mathy3, [0x07fffffff, -1/0, Math.PI, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, 0, -0x100000001, -(2**53), -0x080000001, 1, 0/0, 42, 0x080000001, -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, 2**53+2, 0x100000000, -0x07fffffff, -0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000000, 1/0, -0, Number.MAX_VALUE, 0x080000000, -(2**53+2), 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=1173; tryItOut("o0 + this.h2;");
/*fuzzSeed-221406266*/count=1174; tryItOut("i1 = new Iterator(p1);");
/*fuzzSeed-221406266*/count=1175; tryItOut("h2 + f2");
/*fuzzSeed-221406266*/count=1176; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[0x0ffffffff,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), 0x0ffffffff,  '\\0' , 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, -Infinity, objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), 0x0ffffffff, objectEmulatingUndefined(), -Infinity, 0x0ffffffff,  '\\0' , 0x0ffffffff, -Infinity,  '\\0' , 0x0ffffffff,  '\\0' , 0x0ffffffff, 0x0ffffffff,  '\\0' , objectEmulatingUndefined(), 0x0ffffffff, -Infinity, -Infinity, 0x0ffffffff,  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(), -Infinity,  '\\0' ,  '\\0' , objectEmulatingUndefined()]) { for (var p in e1) { try { h1 + s0; } catch(e0) { } try { this.v0 = a1.length; } catch(e1) { } m1.has(m0); } }");
/*fuzzSeed-221406266*/count=1177; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?=\\W{1}))/ym; var s = \"aa\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=1178; tryItOut("\"use strict\"; v0 = g2.runOffThreadScript();");
/*fuzzSeed-221406266*/count=1179; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + ( - (Math.fround(( - Math.fround(( + (( + 0x080000001) | ( + ( + (Math.fround(Math.fround(Math.imul(y, Math.fround(y)))) ^ ( + Math.asin(-0)))))))))) >>> 0))); }); testMathyFunction(mathy5, [2**53-2, -0x080000001, -(2**53+2), -Number.MIN_VALUE, Number.MIN_VALUE, 1, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -0x07fffffff, 42, Math.PI, 1/0, 0, Number.MAX_VALUE, 0.000000000000001, -0x100000001, -0x100000000, 0x100000000, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, -0, -1/0, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), 1.7976931348623157e308, 2**53+2, 0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-221406266*/count=1180; tryItOut("\"use strict\"; v1 = (b0 instanceof m2);");
/*fuzzSeed-221406266*/count=1181; tryItOut("if((x % 6 != 5)) { if (w) this.g2.v2 = Array.prototype.some.apply(a2, [(function() { try { /*RXUB*/var r = r1; var s = s2; print(uneval(r.exec(s)));  } catch(e0) { } try { g0.f2.__proto__ = t2; } catch(e1) { } for (var v of s0) { try { g0.v0 = a1.reduce, reduceRight(v2); } catch(e0) { } Array.prototype.sort.apply(a0, [(function mcc_() { var khkjxy = 0; return function() { ++khkjxy; f1(/*ICCD*/khkjxy % 8 != 0);};})(), x, new b =>  { undefined; } (), t2, a1]); } return e0; }), t2]);} else {this.a1.length = 19;this;a = ({a: Math.imul(-10,  /x/g )}); }");
/*fuzzSeed-221406266*/count=1182; tryItOut("/*RXUB*/var r = g0.r2; var s = s1; print(uneval(s.match(r))); ");
/*fuzzSeed-221406266*/count=1183; tryItOut("var window = ({19: x, message: Math.log1p(-8) }), grlabi, x = x, y = window **= new RegExp(\"\\\\3|[^]\", \"m\"), a = (decodeURIComponent), x =  ''  ? ({}) : /((?!\u00ff\\n|[^]))/gim;;");
/*fuzzSeed-221406266*/count=1184; tryItOut("\"use strict\"; /*RXUB*/var r = /((?:^\\u6Ee3[^]^*?|\\B+?|([]*?){67108865}\\B.))/yim; var s = \"a\\ud053\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=1185; tryItOut("this.v1 = b0.byteLength;");
/*fuzzSeed-221406266*/count=1186; tryItOut("mathy5 = (function(x, y) { return Math.fround((( ! ( + ( ~ y))) / Math.fround(( + (( + (x + (Math.log2((x >>> 0)) >>> 0))) != ( + mathy4(((0x0ffffffff >>> 0) == x), ( + y)))))))); }); testMathyFunction(mathy5, /*MARR*/[(void 0), (0/0), (0/0), (void 0), (void 0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (0/0), (0/0), (0/0), (void 0), (void 0), (void 0), (0/0), (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (0/0), (0/0), (void 0), (void 0), (0/0), (void 0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (void 0), (void 0), (void 0), (0/0), (void 0), (void 0), (0/0), (0/0), (0/0), (0/0), (void 0), (0/0), (0/0), (void 0), (0/0), (0/0), (void 0), (void 0), (void 0), (0/0), (void 0), (0/0), (void 0), (0/0), (0/0), (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (0/0), (void 0), (0/0), (void 0), (void 0), (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (0/0), (void 0), (0/0), (0/0)]); ");
/*fuzzSeed-221406266*/count=1187; tryItOut("for (var p in this.f0) { try { v1 = (e1 instanceof g0); } catch(e0) { } try { for (var v of m2) { try { o0.g0.valueOf = (function() { try { i2.toString = (function() { try { v1 = (a2 instanceof this.o2); } catch(e0) { } try { /*RXUB*/var r = r1; var s = s1; print(s.match(r));  } catch(e1) { } a1 + ''; return f1; }); } catch(e0) { } ; return o1.a1; }); } catch(e0) { } ; } } catch(e1) { } b0 = new SharedArrayBuffer(80); }");
/*fuzzSeed-221406266*/count=1188; tryItOut("/*tLoop*/for (let c of /*MARR*/[x,  /x/ , x,  /x/ ,  /x/ , 1.7976931348623157e308,  /x/ , x,  /x/ , x, 1.7976931348623157e308, x, 1.7976931348623157e308, x, 1.7976931348623157e308, 1.7976931348623157e308, x,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  /x/ , x, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, x,  /x/ , x,  /x/ ,  /x/ ,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308, x,  /x/ , 1.7976931348623157e308,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308, x,  /x/ ,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  /x/ ,  /x/ , x, x,  /x/ ,  /x/ , x, 1.7976931348623157e308, x, 1.7976931348623157e308, x,  /x/ ,  /x/ , x, 1.7976931348623157e308, x,  /x/ ,  /x/ ,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, x,  /x/ ,  /x/ ,  /x/ , 1.7976931348623157e308,  /x/ , 1.7976931348623157e308,  /x/ , 1.7976931348623157e308,  /x/ , x, 1.7976931348623157e308,  /x/ , 1.7976931348623157e308, x,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308,  /x/ , x, x, x, x,  /x/ , x, x,  /x/ ,  /x/ , 1.7976931348623157e308, x, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  /x/ ,  /x/ , x, 1.7976931348623157e308, x,  /x/ , 1.7976931348623157e308,  /x/ , x,  /x/ , 1.7976931348623157e308,  /x/ ,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  /x/ , x, 1.7976931348623157e308,  /x/ , 1.7976931348623157e308]) { e1 = new Set(m1); }");
/*fuzzSeed-221406266*/count=1189; tryItOut("m0.get(h2);");
/*fuzzSeed-221406266*/count=1190; tryItOut("Array.prototype.splice.call(a0, NaN, 13);");
/*fuzzSeed-221406266*/count=1191; tryItOut("/*tLoop*/for (let a of /*MARR*/[function(){}, (0/0), function(){}, -0x07fffffff, (0/0), -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff]) { /* no regression tests found */ }");
/*fuzzSeed-221406266*/count=1192; tryItOut("mathy3 = (function(x, y) { return (mathy1((((Math.max((Math.round((x | 0)) | 0), (( + y) ** (( ! y) | 0))) | 0) !== Math.atan2(( ! ((y ? x : y) >>> 0)), Math.sqrt(Math.acos(Math.fround(Math.acos(Math.fround(y))))))) | 0), (Math.atan2((mathy0((y >>> 0), (y >>> 0)) >>> 0), (Math.max(x, Math.imul(( + ( + (y >>> 0))), x)) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy3, [0/0, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), -1/0, 0x07fffffff, 0, Math.PI, -0, 2**53-2, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -0x080000000, Number.MIN_VALUE, 1/0, -0x100000000, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, -0x080000001, 42, 0x080000001, -0x07fffffff, 2**53+2, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, -(2**53+2), 0x0ffffffff, -0x100000001, 0x080000000]); ");
/*fuzzSeed-221406266*/count=1193; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return (Math.max(( ! (Math.imul(y, x) >>> 0)), (((Math.max(2**53+2, y) == (Math.fround(Math.tan(Math.fround(Math.sign(y)))) ** y)) >>> 0) != (y | 0))) && Math.fround(Math.hypot(Math.fround(( ~ ( + Math.min(((( + Math.fround(x)) | 0) | 0), (y | 0))))), Math.fround(Math.fround(Math.imul(((x >>> 0) > y), Math.trunc(y))))))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, 0x07fffffff, -0, -(2**53+2), -0x100000001, 0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 2**53+2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_VALUE, 0x080000001, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, 42, 0x100000000, 0x0ffffffff, -(2**53), 0, -(2**53-2), -0x07fffffff, 1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000001, -1/0, Math.PI]); ");
/*fuzzSeed-221406266*/count=1194; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = (0x8d765bbd);\n    }\n    return ((((d0) == (3.777893186295716e+22))))|0;\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53-2, 1, -Number.MAX_VALUE, 0, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0x080000000, -1/0, 0x100000001, 0x100000000, -(2**53-2), 1.7976931348623157e308, -0, 42, 1/0, 0x07fffffff, -0x080000000, -(2**53+2), 0/0, -0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, -(2**53), 2**53+2, 2**53, Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1195; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( - Math.fround(( ~ Math.fround(Math.tanh((Math.asinh(x) === 0x100000000)))))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -0x0ffffffff, 0x100000000, 0.000000000000001, 0/0, -0, 0x080000001, 1/0, -(2**53+2), -0x100000000, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, 42, -1/0, -Number.MAX_VALUE, -(2**53), -(2**53-2), 0, -Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, -0x080000001, Number.MIN_VALUE, -0x100000001, -0x080000000, Math.PI, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=1196; tryItOut("a0[({valueOf: function() { if(true) {let this.v1 = evaluate(\"length\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: null, sourceIsLazy: false, catchTermination: true }));/*RXUB*/var r = r0; var s = \"\\n\\ufec9\\u6ef4\\n\"; print(uneval(r.exec(s)));  } else  if (/(?:[^])+\u4d9f/y) print(/([^]){0,}*?/gym);return 9; }})] = o1.g1.o0.a0;");
/*fuzzSeed-221406266*/count=1197; tryItOut("\"use strict\"; function shapeyConstructor(elvhye){{ f2 = Proxy.createFunction(h0, f1, f1); } this[\"match\"] = (Int16Array).call( /x/ , eval,  \"\" ).eval(\" '' \");this[\"match\"] = -Infinity;this[\"match\"] = ((this.valueOf(\"number\"))((function shapeyConstructor(vmeddt){delete this[\"getPrototypeOf\"];Object.freeze(this);delete this[ /x/g ];Object.defineProperty(this,  /x/g , ({configurable: true, enumerable: true}));Object.defineProperty(this, \"valueOf\", ({get: (x) =>  { \"use strict\"; return \"\\u1944\" } , set: (x, elvhye, ...e) => x, enumerable: (vmeddt % 4 != 2)}));for (var ytqwnyvgs in this) { }return this; }).call(this, /((?![\\\u00fd\u07a3-\\u004D]))+?/i, null)) = ((makeFinalizeObserver('tenured'))));for (var ytqxgqflm in this) { }if (x = Proxy.create(({/*TOODEEP*/})(this), /(?=[^\\u006d-\\xe0](?=.*))*/im).yoyo((--w))) { v1 = Object.prototype.isPrototypeOf.call(m0, g1.m0); } this[\"match\"] = new Set();return this; }/*tLoopC*/for (let a of /*MARR*/[objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g , function(){},  /x/g ,  /x/g ,  /x/g , function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){},  /x/g , function(){}, objectEmulatingUndefined(), objectEmulatingUndefined()]) { try{let mtfwcr = shapeyConstructor(a); print('EETT'); /*oLoop*/for (xjasbk = 0; xjasbk < 83; ++xjasbk) { e0 = new Set(v1); } }catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-221406266*/count=1198; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((Math.hypot(( + ((Math.fround(Math.min(Math.fround(Math.hypot(x, ((y , x) >>> 0))), Math.fround((((x !== (y | 0)) | 0) / (x | 0))))) == mathy1((( + Math.fround(y)) | 0), ((( ! ( + y)) >>> 0) | 0))) | 0)), (Math.max(0x080000000, y) * (Math.round(Math.fround((( + Math.pow(y, y)) >>> 0))) >>> 0))) ? Math.atan2(Math.fround((Math.fround((Math.fround((x <= x)) && (Math.fround(Math.cos(Math.fround(Math.fround(((-0x07fffffff >>> 0) == (y >>> 0)))))) <= -0))) ? Math.cbrt(Math.fround(Math.sinh(Math.asin(-Number.MAX_SAFE_INTEGER)))) : Math.fround(( - Math.min(y, ( + Math.cos(( + ((x | 0) >> x))))))))), (Math.sinh((y >>> 0)) >>> 0)) : Math.pow(( + (( + 0) >>> Math.fround(Math.fround((y >> Math.fround(Math.abs(Math.fround(( + (( + x) >= y)))))))))), ( + Math.pow((mathy1(((y == ( + x)) | 0), Math.hypot((Math.atan2(y, x) >>> 0), x)) | 0), Math.sign(((Math.pow(x, ( + Math.atan2(x, ( + ((y | 0) - 2**53))))) >>> 0) >>> 0)))))) >>> 0); }); ");
/*fuzzSeed-221406266*/count=1199; tryItOut("var (x)(Math.atan2(decodeURI(), -3)) = e = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: Date.prototype.toJSON, delete: function() { throw 3; }, fix: undefined, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { throw 3; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(e), (this.__defineSetter__(\"d\", Date.prototype.getUTCMonth))), fvqlll, x = /*oLoop*/for (var wurfnf = 0; wurfnf < 1; ++wurfnf) { i0.next(); } , c = ( /* Comment *//*MARR*/[objectEmulatingUndefined(), function(){}, Infinity, Infinity,  /x/g , function(){},  /x/g , objectEmulatingUndefined()].map(function(y) { yield y; s2 = s1.charAt([z1]);; yield y; }//h\n, NaN)), window = (Math.atan2((d = Proxy.createFunction(({/*TOODEEP*/})(\"\\uBF43\"), Math.sin)), (x) = (Math.atan(4)))), {\u3056: x, this.c, x: [z, , d, {c: \u000c{b: window, x}, x: {e: {x}}, NaN: {window: {y}}}], x: [, , e, {d: {x: {}, b: this.__proto__}, e: {y: [], x: []}}]} = new null(), y;g2.t2 = new Uint8Array(this.a0);");
/*fuzzSeed-221406266*/count=1200; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s2; print(s.replace(r, (/*FARR*/[.../*MARR*/[new Number(1.5), Infinity, new Number(1.5), new String(''), Infinity, new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new String(''), new Number(1.5), new String(''), new String(''), Infinity, new Number(1.5), Infinity, new Number(1.5), new String(''), new Number(1.5), new String(''), Infinity, new String(''), new String(''), new Number(1.5), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), Infinity, new Number(1.5), new String(''), new Number(1.5), new Number(1.5), Infinity, Infinity, Infinity, new Number(1.5), Infinity, new Number(1.5), Infinity, Infinity, new String(''), new Number(1.5), Infinity, new Number(1.5), new Number(1.5), new String(''), new String(''), Infinity, new String(''), new String(''), new Number(1.5), Infinity, Infinity, Infinity, new String(''), Infinity, Infinity, Infinity, new Number(1.5)]].some) |= (4277))); ");
/*fuzzSeed-221406266*/count=1201; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.max(( ~ (x >= x)), (((Math.fround(Math.min(Math.fround(((( - ((( - ( + y)) ** Math.fround(Math.imul((x >>> 0), x))) >>> 0)) >>> 0) >> ( - (x / x)))), Math.fround(mathy0(mathy2(Math.fround((Math.fround(Math.fround((x ? ( + x) : y))) != Math.fround(-0x100000001))), (x >>> 0)), (x | 0))))) | 0) !== ((Math.atan2(mathy0(x, Math.fround(Math.imul(Math.fround(y), x))), ( ~ Math.pow((x == ( + x)), ( + x)))) | 0) | 0)) | 0)) | 0); }); testMathyFunction(mathy3, [0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0.000000000000001, 0x100000001, -0x100000001, -0, -0x080000001, Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 0x080000000, 1/0, Number.MIN_VALUE, 42, 0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, 0x100000000, -(2**53+2), 0/0, -0x0ffffffff, -(2**53), -Number.MIN_VALUE, 0x080000001, 1, -0x100000000, -(2**53-2), -1/0]); ");
/*fuzzSeed-221406266*/count=1202; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[['z'], ['z'],  'A' , ['z'], ['z'],  'A' , ['z'], ['z'], ['z'],  'A' , ['z'], ['z'],  'A' , ['z'], ['z'],  'A' , ['z'],  'A' ,  'A' , ['z'], ['z'],  'A' , ['z'], ['z'],  'A' ,  'A' ,  'A' ,  'A' , ['z'],  'A' ,  'A' , ['z'],  'A' ,  'A' ,  'A' , ['z'], ['z'],  'A' , ['z'],  'A' ]); ");
/*fuzzSeed-221406266*/count=1203; tryItOut("/*infloop*/ for (this !== /\\B{2,2}/gi[\"atan\"] of -24)  /x/g ;");
/*fuzzSeed-221406266*/count=1204; tryItOut("mathy3 = (function(x, y) { return (Math.hypot(( ! (y - x)), (((((let (e=eval) e)).apply >>> 0) ^ ((Math.acos((0.000000000000001 | 0)) | 0) | 0)) >>> 0)) ? Math.sqrt(Math.exp(( + ( + Math.pow(Math.fround((( + 0.000000000000001) && (y >>> 0))), (((( ~ Math.atan2((x | 0), x)) >>> 0) % (Number.MIN_VALUE >>> 0)) >>> 0)))))) : ( + mathy0(( + ((((( ~ x) | 0) | 0) + ((( + -0x0ffffffff) & ( + (((x >>> 0) - (-0x100000000 >>> 0)) >>> 0))) | 0)) | 0)), ( + Math.atan((( - Math.fround((( + Math.round(x)) | 0))) >>> 0)))))); }); testMathyFunction(mathy3, [0x080000000, 1.7976931348623157e308, 0x07fffffff, -0x100000000, -0x0ffffffff, -0, 0.000000000000001, 2**53+2, 42, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 0x100000001, -0x080000001, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, -0x080000000, Number.MAX_VALUE, -0x100000001, 2**53, 0/0, Math.PI, -(2**53), -(2**53+2), -0x07fffffff, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1205; tryItOut(";\nprint(( \"\" ).call(x, length, (4277)));\n");
/*fuzzSeed-221406266*/count=1206; tryItOut(";");
/*fuzzSeed-221406266*/count=1207; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return Math.fround(mathy2(Math.fround(Math.hypot(Math.fround(Math.tanh(y)), ((( + Math.atanh(( + x))) === ((x === (-(2**53) | 0)) ? Math.pow((Math.tan((Number.MAX_SAFE_INTEGER >>> 0)) >>> 0), (Math.asin(-0x080000000) | 0)) : ( ~ y))) | 0))), (Math.fround(( ! y)) >>> 0))); }); testMathyFunction(mathy4, [0x0ffffffff, 0/0, 1/0, 42, Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), 0x080000000, 0x07fffffff, 0x080000001, -0, -(2**53+2), 2**53, -0x080000001, 0x100000001, -0x07fffffff, 1, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000000, -(2**53), -0x0ffffffff, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-221406266*/count=1208; tryItOut("\"use strict\"; testMathyFunction(mathy4, [1/0, Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), Math.PI, 0x100000000, -(2**53-2), -0x100000001, 0/0, 0x100000001, -0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, 2**53+2, -1/0, Number.MAX_SAFE_INTEGER, 1, -0, -0x080000001, -(2**53), 0x080000000, Number.MAX_VALUE, 0x080000001, 42, 2**53, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-221406266*/count=1209; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.hypot((mathy1(Math.fround(mathy0(( + x), Math.fround((Math.atan2(((mathy0(x, (y >>> 0)) >>> 0) >>> 0), (( + ( + y)) >>> 0)) >>> 0)))), Math.log1p(Math.fround(Math.atan2(y, -(2**53-2))))) | 0), (mathy1(-(2**53-2), Math.tan((x << y))) | 0)) | 0) ? (Math.min(( + (Math.fround((Math.fround(Math.sign(2**53)) >>> 0)) >>> 0)), (Math.min(( + (y % (Math.cos(y) * ( + Math.sqrt((0x100000000 >>> 0)))))), ( + Math.min(( + -(2**53+2)), ( + Math.round(( + Math.cbrt(( + Math.round(( + x)))))))))) | 0)) | 0) : Math.min(( + Math.imul(( + (( + (Math.fround((x + ( + ( - ( ! (x | 0)))))) | 0)) | 0)), ((Math.pow(-Number.MIN_SAFE_INTEGER, (Math.cos(x) >>> 0)) >>> 0) >>> 0))), Math.max(( + Math.atan2((y >>> 0), x)), mathy0(y, y)))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, -(2**53-2), -1/0, 0, 2**53, -(2**53+2), 1.7976931348623157e308, -0x080000001, Number.MIN_VALUE, 1, 0x07fffffff, -Number.MAX_VALUE, 0x080000000, -0x07fffffff, -0x100000001, 0x0ffffffff, 0x100000000, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 0x080000001, 42, -0x080000000, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), 1/0, -0x100000000]); ");
/*fuzzSeed-221406266*/count=1210; tryItOut("o1.t0[6] = g0.a1;");
/*fuzzSeed-221406266*/count=1211; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! Math.max(( + Math.fround(Math.atan2(y, Math.fround(Math.fround(Math.cosh((Math.clz32(y) | 0))))))), (Math.pow(-Number.MAX_SAFE_INTEGER, Math.fround(Math.hypot(Math.fround(-Number.MIN_VALUE), Math.fround(x)))) >>> Math.fround(Math.pow(Math.fround(Math.cos(Math.hypot(y, ( + ( + Math.log(x)))))), Math.fround(Math.pow(-Number.MAX_VALUE, ( ! y)))))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, -0x080000000, -Number.MIN_VALUE, 42, 0x080000000, -(2**53-2), -0, 0/0, Number.MIN_VALUE, -0x07fffffff, -0x080000001, 0x0ffffffff, -1/0, -0x0ffffffff, 0x100000000, 2**53-2, 1/0, -0x100000000, -(2**53), Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 1, 0x100000001, 0x080000001, 2**53, -0x100000001, 1.7976931348623157e308, 2**53+2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-221406266*/count=1212; tryItOut("e1 = a2[5];");
/*fuzzSeed-221406266*/count=1213; tryItOut("\"use strict\"; s2 + i1;window;\no2 = Object.create(v0);\u0009\n");
/*fuzzSeed-221406266*/count=1214; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; try { startgc(3836973378); } catch(e) { } } void 0; }");
/*fuzzSeed-221406266*/count=1215; tryItOut("g2.e1.toSource = (function() { try { a0[v2] = \nx; } catch(e0) { } try { g2.t2[o0.v1] = x; } catch(e1) { } s0 += 'x'; return e1; });\nfor (var p in a1) { try { Array.prototype.pop.call(a2, v2, i1, v1); } catch(e0) { } v0 = g0.g1.runOffThreadScript(); }\n");
/*fuzzSeed-221406266*/count=1216; tryItOut("mathy0 = (function(x, y) { return ((Math.sign(( - (( ! Math.fround(( - x))) >>> 0))) ** Math.abs(((( + (y , ( + x))) ** x) === ( - y)))) || ( - Math.cosh(Math.fround(Math.hypot(((x > y) >>> y), Math.fround(Math.hypot((-0x100000000 >>> 0), ( + (y === y))))))))); }); testMathyFunction(mathy0, [-(2**53-2), -0x080000000, 2**53-2, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 42, 0x0ffffffff, -0, 1, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 0.000000000000001, -1/0, -Number.MIN_VALUE, 0x080000000, Math.PI, 0x100000000, 0/0, -0x080000001, -0x07fffffff, 0x07fffffff, -(2**53), 0, 0x080000001, -0x100000000, 1/0, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=1217; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return ((((Math.fround(( - Math.fround(-(2**53)))) < ( ! ((((Math.min((y >>> 0), (Math.log2(y) >>> 0)) >>> 0) >>> 0) < x) >>> 0))) | 0) << (( + Math.ceil(((Math.atanh((Math.atan2(-0x080000000, x) | 0)) == Math.atan(x)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy0, [0/0, 0.000000000000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, -0x080000001, -0x100000001, 1, -0x100000000, -1/0, Number.MAX_VALUE, 0x100000001, 42, Math.PI, -(2**53-2), -Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, 2**53-2, -(2**53), 0x080000000, 0x07fffffff, 0x080000001, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53+2, 1/0]); ");
/*fuzzSeed-221406266*/count=1218; tryItOut("g0.offThreadCompileScript(\"v1 = Object.prototype.isPrototypeOf.call(o1, a2);\", ({ global: this.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 27 == 3), noScriptRval: true, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-221406266*/count=1219; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log2((( + (Math.imul(x, Math.hypot(( + ( + (y >>> 0))), Math.atan(0.000000000000001))) >>> 0)) & (Math.atan((( ~ ( - y)) | 0)) | 0))); }); ");
/*fuzzSeed-221406266*/count=1220; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\b[^](?=.[^]))\\\\1|(?!\\\\x9c)|(?!\\\\1{3,})|^[^]\\\\b?*?+\", \"gyi\"); var s = \"\"; print(r.exec(s)); \nprint( /x/g  < y);\n");
/*fuzzSeed-221406266*/count=1221; tryItOut("\"use strict\"; const x = Math.exp(( + Math.fround(Math.sqrt(x)))), x = new RegExp(\"(?=\\\\3)\", \"im\");print(x);");
/*fuzzSeed-221406266*/count=1222; tryItOut("\"use strict\"; o0.a0.unshift(b0);");
/*fuzzSeed-221406266*/count=1223; tryItOut("/*vLoop*/for (let vvkpgw = 0; vvkpgw < 62; ++vvkpgw) { var w = vvkpgw; e2.delete(s0); } ");
/*fuzzSeed-221406266*/count=1224; tryItOut("print(((function a_indexing(ucuhmu, tthnmy) { ; if (ucuhmu.length == tthnmy) { ; return tthnmy; } var iogiip = ucuhmu[tthnmy]; var jlslnm = a_indexing(ucuhmu, tthnmy + 1); return  /x/g ; })(/*MARR*/[(1/0), (1/0), -Infinity, -Infinity, -Infinity, (1/0), -Infinity, (1/0), -Infinity, (1/0), (1/0), (1/0), (1/0), -Infinity, -Infinity, (1/0), -Infinity, -Infinity, -Infinity, -Infinity, (1/0), -Infinity, (1/0), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, (1/0), (1/0), -Infinity, -Infinity, -Infinity, (1/0), -Infinity, (1/0), -Infinity, (1/0), -Infinity, -Infinity, -Infinity, (1/0), (1/0), -Infinity, (1/0), -Infinity, (1/0), (1/0), -Infinity, -Infinity, -Infinity, -Infinity, (1/0), (1/0), (1/0), (1/0), (1/0), -Infinity, -Infinity, (1/0), (1/0), (1/0), -Infinity, (1/0), -Infinity, (1/0), -Infinity, (1/0), (1/0), (1/0), (1/0), (1/0), -Infinity, (1/0), (1/0), -Infinity, (1/0), (1/0), (1/0), -Infinity, (1/0), (1/0), (1/0), -Infinity, -Infinity, (1/0), (1/0), -Infinity, -Infinity, (1/0), -Infinity, (1/0), (1/0), -Infinity, (1/0), -Infinity, (1/0), (1/0), (1/0), -Infinity, (1/0), -Infinity], 0)));");
/*fuzzSeed-221406266*/count=1225; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=1226; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53-2), 0x07fffffff, -0x0ffffffff, 1, 1.7976931348623157e308, 0x100000000, -0, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, 1/0, Number.MAX_VALUE, 0x100000001, -0x07fffffff, -(2**53), Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 0, 2**53-2, 0/0, -(2**53+2), 2**53+2, 42, -0x080000000, 0x080000000]); ");
/*fuzzSeed-221406266*/count=1227; tryItOut("try { with({}) let(b) ((function(){{}})()); } catch(x) { arguments.callee.caller.arguments.fileName; } finally { try { v1 = evalcx(\"v2 = o1.o1.g1.eval(\\\"true\\\");\", o2.g0); } catch(x if (function(){x;})()) { print(\"\\uD045\"); } catch(x if null.throw(undefined)) { [[]]; }  } throw StopIteration;\n\u000d/*hhh*/function gqqhaf(b){print(b);}gqqhaf((/*MARR*/[(1/0), (1/0), (1/0), (1/0), (1/0), new Boolean(false), (1/0), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), (1/0), (1/0), (1/0), new Boolean(false), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new Boolean(false), (1/0), (1/0), (1/0), (1/0), new Boolean(false), new Boolean(false), (1/0), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), (1/0), (1/0), new Boolean(false), (1/0), (1/0), (1/0), (1/0), (1/0), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), (1/0), new Boolean(false), (1/0), (1/0), new Boolean(false), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new Boolean(false), (1/0), (1/0), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), (1/0), (1/0), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false)].some(objectEmulatingUndefined, new RegExp(\"\\\\2\", \"g\"))), -11);\nM:with({d: \"\\u5302\"}){i1 = m0.entries;i2.toSource = (function mcc_() { var otwmyj = 0; return function() { ++otwmyj; if (otwmyj > 7) { dumpln('hit!'); try { v0 = evalcx(\"continue M;\", g1); } catch(e0) { } try { var this.v2 = evalcx(\"/* no regression tests found */\", g1.g1); } catch(e1) { } e1.delete(g2); } else { dumpln('miss!'); t1 = new Uint16Array(6); } };})(); }\n\n");
/*fuzzSeed-221406266*/count=1228; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[(-1/0), (-1/0),  /x/g , (-1/0), new Boolean(false), function(){}, function(){}]) { window; }");
/*fuzzSeed-221406266*/count=1229; tryItOut("\"use strict\"; s1.valueOf = (function(j) { if (j) { try { i1.valueOf = (function() { for (var j=0;j<5;++j) { f2(j%3==1); } }); } catch(e0) { } try { /*MXX3*/g0.Date.prototype.setTime = g2.Date.prototype.setTime; } catch(e1) { } try { /*ODP-3*/Object.defineProperty(b2, \"18\", { configurable: let (w = true) ({a1:1}), enumerable: false, writable: new Uint8ClampedArray(), value: a1 }); } catch(e2) { } ; } else { try { g2.v0 = this.g0.eval(\"o0.toSource = DataView.prototype.setUint8.bind(b1);\"); } catch(e0) { } o1.v1 = this.g0.eval(\"v1 = g1.a0.length;function x(...z) { break L; } print(x);\"); } });");
/*fuzzSeed-221406266*/count=1230; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot(((( - (Math.cbrt(((Number.MAX_VALUE > (Math.tan(Math.max(y, Math.sinh(x))) | 0)) >>> 0)) >>> 0)) | 0) | 0), (Math.fround(Math.atan2(Math.fround(( ~ (y * Number.MIN_VALUE))), (Math.min((Math.round(( + (( + -(2**53-2)) & ( + x)))) | 0), x) | 0))) ? Math.hypot(Math.max((y | 0), (2**53-2 | 0)), ((Math.fround(((y ? (x % ( + -Number.MIN_SAFE_INTEGER)) : (( - (y >>> 0)) >>> 0)) / y)) != Math.fround(Math.max(Math.fround(Math.tan(x)), Math.fround(0x080000000)))) >>> 0)) : ( + Math.min(( + ((( ! y) * x) >>> 0)), ( - y))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0, 2**53-2, 0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 0x080000001, -0x0ffffffff, 42, 0, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 0x100000000, 0/0, 0x100000001, -Number.MIN_VALUE, -0x100000001, 1, 2**53, -(2**53+2), 0x080000000, -1/0, -0x080000001, 0.000000000000001, -0x07fffffff, -(2**53), Number.MIN_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=1231; tryItOut("mathy0 = (function(x, y) { return Math.pow((Math.fround(( - (Math.max((Math.imul(( ! (y >>> 0)), (y | 0)) | 0), x) >>> 0))) | 0), Math.cos(( - ((Math.min((Math.fround(Math.pow((Math.fround(( ! Math.fround(0))) | 0), y)) | 0), (x | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy0, [({valueOf:function(){return 0;}}), null, -0, ({valueOf:function(){return '0';}}), '0', (new Boolean(false)), (function(){return 0;}), (new Number(-0)), undefined, NaN, [0], [], 1, /0/, 0, '', true, 0.1, false, '/0/', '\\0', objectEmulatingUndefined(), (new Boolean(true)), (new String('')), (new Number(0)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-221406266*/count=1232; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let b of /*MARR*/[function(){}, x, new String('q'), function(){},  \"use strict\" ,  \"use strict\" , x, x,  \"use strict\" , new String('q'), new String('q'), new String('q'), x, function(){},  \"use strict\" , 1e-81, new String('q'), 1e-81,  \"use strict\" , x, new String('q'),  \"use strict\" ,  \"use strict\" , function(){}, 1e-81, x,  \"use strict\" , function(){}, 1e-81, function(){}, x,  \"use strict\" , function(){}, 1e-81,  \"use strict\" , function(){}, new String('q'), 1e-81, x, x, new String('q'), new String('q'), 1e-81, function(){}, x, x, x, x, x, x, x, x, x, function(){}, 1e-81, 1e-81, function(){}, new String('q'), x, x, new String('q'),  \"use strict\" , 1e-81, x, x, new String('q'), 1e-81, 1e-81, function(){}, new String('q'),  \"use strict\" , function(){}, function(){}, x,  \"use strict\" ,  \"use strict\" , new String('q'), 1e-81]) { this; }");
/*fuzzSeed-221406266*/count=1233; tryItOut("const lfqjaj;v0 = Object.prototype.isPrototypeOf.call(t1, f0);");
/*fuzzSeed-221406266*/count=1234; tryItOut("mathy3 = (function(x, y) { return Math.min((Math.fround(( ~ Math.fround((y == Math.fround(Math.log10(y)))))) >>> 0), (Math.imul(Math.fround(( - (mathy1((x >>> 0), x) >>> 0))), Math.fround(Math.max((Math.sign(( + (y || x))) | 0), (mathy2((Math.hypot(( + y), ( + x)) >>> 0), Math.fround(( ! (Math.imul(( + y), x) | 0)))) >>> 0)))) | 0)); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, Math.PI, 0x07fffffff, 0/0, -0x07fffffff, -0, 1, 0, Number.MAX_VALUE, 2**53-2, 0x100000000, 2**53+2, -0x0ffffffff, 0x080000001, -0x100000001, 1/0, -1/0, -Number.MAX_VALUE, 2**53, 0x100000001, 1.7976931348623157e308, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 42, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1235; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return (((((((2**53 >= Math.imul(( + (( + y) !== y)), Math.atan2(x, Math.fround(x)))) | 0) && ( + Math.hypot(((-0x100000001 - ( - (-0x07fffffff | 0))) <= (x != y)), y))) | 0) >>> 0) || (((((((-0x0ffffffff ? x : y) | 0) ? (x | 0) : (( ~ Math.fround(x)) | 0)) | 0) <= Math.sign((mathy0((y | 0), ( + y)) >>> 0))) << ((((( + ( + (( + y) % ( + x)))) >>> 0) - (( + ( - ( + (Math.cbrt((x >>> 0)) >>> 0)))) >>> 0)) >>> 0) >= Math.hypot(Math.log1p(Math.pow((2**53-2 | 0), (y | 0))), y))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x080000001, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, 2**53-2, 0/0, -0x080000001, -0x080000000, -0x100000001, -0x0ffffffff, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), 1.7976931348623157e308, 0x080000000, 1/0, 42, Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, -0, 0, -Number.MIN_VALUE, 1, 0x100000000, -1/0, -(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-221406266*/count=1236; tryItOut("v0 = this.e1[\"constructor\"]");
/*fuzzSeed-221406266*/count=1237; tryItOut("Object.defineProperty(this, \"this.v0\", { configurable: (x % 70 == 45), enumerable: (x % 5 == 3),  get: function() {  return g2.t1.byteOffset; } });");
/*fuzzSeed-221406266*/count=1238; tryItOut("\"use strict\"; x.stack;");
/*fuzzSeed-221406266*/count=1239; tryItOut("");
/*fuzzSeed-221406266*/count=1240; tryItOut("\"use strict\"; f2.toSource = f0;");
/*fuzzSeed-221406266*/count=1241; tryItOut("e1.add(f0);");
/*fuzzSeed-221406266*/count=1242; tryItOut("");
/*fuzzSeed-221406266*/count=1243; tryItOut("testMathyFunction(mathy3, [-1/0, -(2**53+2), 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, 1/0, 2**53+2, 0.000000000000001, Math.PI, 2**53, 0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 42, -0x080000001, 0/0, -Number.MAX_VALUE, -0x0ffffffff, 0, -(2**53-2), -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, -0x100000001]); ");
/*fuzzSeed-221406266*/count=1244; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0/0, -Number.MIN_VALUE, 42, Math.PI, 2**53-2, -0x100000001, -0x100000000, 2**53+2, -(2**53), 1, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, 0x07fffffff, 0.000000000000001, 1.7976931348623157e308, 0x100000000, 1/0, 0, -0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, -0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, -0, Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1245; tryItOut("mathy1 = (function(x, y) { return (mathy0(( - ( ! ( + (Math.sin(Math.min(y, Number.MIN_SAFE_INTEGER)) >>> 0)))), (Math.fround((Math.fround(( - ( + Math.expm1((((-Number.MAX_SAFE_INTEGER >>> 0) !== -(2**53+2)) >>> 0))))) != Math.exp(Math.atanh((Math.max((Math.hypot(x, x) | 0), x) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, ['/0/', (function(){return 0;}), undefined, ({valueOf:function(){return 0;}}), null, '0', '', [0], ({valueOf:function(){return '0';}}), 1, 0, ({toString:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), (new Boolean(false)), 0.1, [], false, (new Boolean(true)), NaN, /0/, '\\0', (new String('')), (new Number(0)), -0, true]); ");
/*fuzzSeed-221406266*/count=1246; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=\\B\\2*?((?=[\\f-\\u00A6]))(?=\\b|^|\\B\\cX{3}))\\w/im; var s = \"aa a @_\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=1247; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1((Math.exp(mathy0((Math.sign((((y * y) >>> 0) | 0)) | 0), y)) | 0), ((((Math.acosh(( + (( + Math.atan2((x >>> 0), y)) <= Number.MIN_SAFE_INTEGER))) >>> 0) > (Math.tan((( + Math.sinh(y)) | 0)) | 0)) | 0) | 0)); }); ");
/*fuzzSeed-221406266*/count=1248; tryItOut("a2[1] = s2;");
/*fuzzSeed-221406266*/count=1249; tryItOut("g0.a0.pop(t2, t2, f1, o2, s0, o1.t1);");
/*fuzzSeed-221406266*/count=1250; tryItOut("mathy0 = (function(x, y) { return ( - ( + ( ! ( + y)))); }); testMathyFunction(mathy0, [Math.PI, 0x100000001, -0x100000000, 42, -1/0, 0x080000001, 2**53-2, 1/0, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, -0x080000001, -0x080000000, Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 2**53, Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -0, 0x080000000, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=1251; tryItOut("\"use strict\"; v0 = g2.runOffThreadScript();");
/*fuzzSeed-221406266*/count=1252; tryItOut("\"use strict\"; /*oLoop*/for (gmxrwg = 0; (window) && gmxrwg < 71; ++gmxrwg) { M:for(var z in \"\\u0D76\") {Array.prototype.forEach.call(a0, (function(j) { if (j) { try { a0.shift(i1); } catch(e0) { } try { v1 = null; } catch(e1) { } try { v2 + v1; } catch(e2) { } Array.prototype.forEach.apply(this.a2, [(function mcc_() { var tbrlys = 0; return function() { ++tbrlys; f2(/*ICCD*/tbrlys % 3 != 1);};})()]); } else { print(o0.p1); } }), e1);print(z); } } ");
/*fuzzSeed-221406266*/count=1253; tryItOut("v0 = (g2.o1.t2 instanceof m2);");
/*fuzzSeed-221406266*/count=1254; tryItOut("s1 = s1.charAt(({valueOf: function() { e2.has(g1.o1);return 9; }}));function c(x, d) { return  \"\"  } { if (!isAsmJSCompilationAvailable()) { void 0; bailout(); } void 0; }");
/*fuzzSeed-221406266*/count=1255; tryItOut("\"use strict\"; this.b0 = new ArrayBuffer(0);");
/*fuzzSeed-221406266*/count=1256; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        d1 = (+(((0xf86b0701)-(i0)-(0xf992477d)) << ((0x6a625c00)-(0xfa3a41ad))));\n      }\n    }\n    return (((i0)+(0xc672d1f)))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 0x100000001, 0x07fffffff, -(2**53-2), -0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, 1.7976931348623157e308, 1, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 2**53-2, -Number.MAX_VALUE, 0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 42, 0x0ffffffff, 0/0, 0, Number.MIN_VALUE, 2**53+2, 0x080000001, -0x0ffffffff, 0x100000000, 2**53, Math.PI]); ");
/*fuzzSeed-221406266*/count=1257; tryItOut("mathy4 = (function(x, y) { return (( + Math.imul(Math.fround((Math.fround(( + Math.trunc(( + y)))) ** Math.fround(( + Math.cbrt(( + y)))))), Math.atan2((( + -Number.MIN_SAFE_INTEGER) >>> 0), (x < (( + mathy1(( + y), ( + x))) >>> 0))))) ? ( ~ (( ~ (Math.max((x >>> 0), Math.fround(mathy0(Math.fround(( + (Math.pow(x, ( + x)) | 0))), ( + mathy3(Math.clz32(-Number.MAX_VALUE), x))))) >>> 0)) | 0)) : (( + ( - ( + (Math.min(Math.fround(x), (Math.round(( + x)) >>> 0)) <= (( + Math.sign(( + (y - y)))) | 0))))) * Math.tanh(( + -(2**53))))); }); testMathyFunction(mathy4, [0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 1, -0x100000000, 2**53-2, 1/0, -0, 2**53, -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -(2**53+2), 2**53+2, -1/0, -(2**53-2), 0x07fffffff, 0, -0x080000000, Number.MAX_VALUE, 0.000000000000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, Math.PI, -Number.MAX_VALUE, 0x100000000, -0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=1258; tryItOut("e1.delete(o0.p1);");
/*fuzzSeed-221406266*/count=1259; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + (( + (Math.cosh((Math.acos(x) | 0)) | 0)) ** ( + (Math.clz32(Math.fround(Math.exp(x))) >>> 0)))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x0ffffffff, -0x080000001, -(2**53+2), -0, 2**53+2, 1, 0/0, Math.PI, Number.MAX_VALUE, -Number.MAX_VALUE, 0, -0x080000000, -Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 0x100000000, -0x100000000, -0x100000001, -(2**53), 2**53-2, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 0x0ffffffff, 0x080000001, -0x07fffffff, -(2**53-2), 0x100000001, -1/0]); ");
/*fuzzSeed-221406266*/count=1260; tryItOut("\"use strict\"; o1.v2 = evaluate(\"v2 = Proxy.create(h2, t2);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 3 == 2), sourceIsLazy: (x % 5 == 3), catchTermination: true }));\n(x);\n");
/*fuzzSeed-221406266*/count=1261; tryItOut("mathy5 = (function(x, y) { return (( ~ (Math.fround(( + ( + Math.min(( + Math.hypot(x, x)), ( ! Number.MAX_VALUE))))) < ( - Math.pow(-0x080000000, (mathy3(y, Math.fround(-(2**53))) | 0))))) >>> 0); }); testMathyFunction(mathy5, [[0], (new Boolean(true)), (new Number(-0)), [], 0.1, undefined, ({valueOf:function(){return '0';}}), '', (new Number(0)), NaN, (new String('')), objectEmulatingUndefined(), '\\0', ({toString:function(){return '0';}}), false, (function(){return 0;}), 0, 1, '/0/', ({valueOf:function(){return 0;}}), null, -0, '0', (new Boolean(false)), /0/, true]); ");
/*fuzzSeed-221406266*/count=1262; tryItOut("mathy1 = (function(x, y) { return Math.atanh((( ~ (( + Math.asin(( + ( + (( + (((1/0 | 0) !== (0x0ffffffff | 0)) | 0)) ? ( + (Math.log(x) | 0)) : ( + ((y | 0) & (y >>> 0)))))))) <= y)) | 0)); }); testMathyFunction(mathy1, [-0x080000000, 0x07fffffff, -0, 1.7976931348623157e308, -(2**53), 0/0, -Number.MAX_VALUE, 42, 1, 1/0, -0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -1/0, 0x080000001, -0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, Math.PI, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 0x080000000, Number.MAX_VALUE, 0x100000000, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=1263; tryItOut("/*infloop*/for(var OSRExit in (4277)) ArrayBuffer");
/*fuzzSeed-221406266*/count=1264; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ Math.fround((Math.pow((( - (Math.cos((Math.log10(-0x100000000) >>> 0)) | 0)) >>> 0), Math.pow(Math.fround(( + (Math.log1p((Math.fround(( + (x | 0))) | 0)) | 0))), mathy0(( + x), (y >>> x)))) ? Math.log1p(Math.fround((Math.fround(0x100000000) , 0/0))) : Math.atan2((Math.fround(((( + x) | 0) ^ (Math.imul(y, -0x100000001) | 0))) >>> 0), ((Math.cosh((x >>> 0)) >>> 0) >>> 0))))); }); ");
/*fuzzSeed-221406266*/count=1265; tryItOut("a1.shift();");
/*fuzzSeed-221406266*/count=1266; tryItOut("a2[v0] = p0;");
/*fuzzSeed-221406266*/count=1267; tryItOut("function (window) { yield \"\\uE49C\" } function e() { return \"\\u066D\" } g1.a1 = new Array;");
/*fuzzSeed-221406266*/count=1268; tryItOut("/*RXUB*/var r = r2; var s = \"\\u0005\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-221406266*/count=1269; tryItOut("mathy3 = (function(x, y) { return Math.clz32(((((Math.tanh(y) | 0) && (Math.hypot(x, Math.atan2((Math.hypot(Math.hypot((Number.MAX_VALUE | 0), x), (y >>> 0)) >>> 0), Number.MAX_SAFE_INTEGER)) | 0)) | 0) < (((Math.hypot(y, Math.fround(((-1/0 | 0) >> ( + Number.MAX_VALUE)))) | 0) , (Math.abs(Math.ceil(y)) | 0)) | 0))); }); testMathyFunction(mathy3, [0x080000001, -0x07fffffff, Math.PI, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -0x100000001, -(2**53-2), 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -0, 2**53+2, -(2**53+2), 0.000000000000001, 0x100000001, 42, 1, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -(2**53), -0x080000000, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -1/0]); ");
/*fuzzSeed-221406266*/count=1270; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( + Math.fround((Math.fround(((((Math.fround(Math.clz32(Math.fround(-0x100000001))) | 0) ? Math.fround(( + y)) : y) | 0) << ( + Math.fround(Math.cbrt(( + Math.imul(Math.fround(x), x))))))) >= Math.fround((Math.fround(( + mathy3((x == (x | x)), Math.log1p(mathy3(-Number.MIN_VALUE, y))))) ? -Number.MAX_SAFE_INTEGER : (Math.fround(( ~ y)) >> x))))))); }); testMathyFunction(mathy5, [0, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 1, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, 1.7976931348623157e308, -(2**53), 0x080000001, -0x080000000, -0x0ffffffff, 0/0, -0x07fffffff, 1/0, -1/0, 0.000000000000001, 42, 2**53+2, -0x100000000, Math.PI, 0x0ffffffff, -0x080000001, -(2**53+2), -(2**53-2), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, 0x100000001, -Number.MAX_VALUE, 0x07fffffff, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1271; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let z of /*MARR*/[-Infinity,  /x/ , -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  /x/ ,  /x/ ,  /x/ , -Infinity, -Infinity, -Infinity,  /x/ , -Infinity, -Infinity, -Infinity,  /x/ ,  /x/ , -Infinity,  /x/ , -Infinity, -Infinity, -Infinity,  /x/ , -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  /x/ ,  /x/ ,  /x/ , -Infinity,  /x/ ,  /x/ , -Infinity,  /x/ , -Infinity, -Infinity,  /x/ , -Infinity,  /x/ , -Infinity,  /x/ , -Infinity,  /x/ , -Infinity,  /x/ , -Infinity, -Infinity, -Infinity,  /x/ , -Infinity, -Infinity,  /x/ ,  /x/ , -Infinity,  /x/ ,  /x/ ,  /x/ ]) { t0.set(a1, 14); }");
/*fuzzSeed-221406266*/count=1272; tryItOut("a1.shift(e1);");
/*fuzzSeed-221406266*/count=1273; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1274; tryItOut("bycdxd((4277), Math.pow(26,  /x/ ).throw(/*FARR*/[].sort(Math.sin, (new /*RXUE*//(${1,}|(?=^[\u57c6-\ue6fd\\S\u102b-\\u0090\\v-\\xfa][\\u005d-\\u00B6\\u00D7]+?)|(?=([^\\cJ])\\S|[^]+?)|(\\W[^\\0-\u00cb\\w\u00b9]{1,}){4,})/yim.exec(\"\\u008d\\ua341\")()))));/*hhh*/function bycdxd(x, eval = delete e.x){i0 = new Iterator(p0, true);}");
/*fuzzSeed-221406266*/count=1275; tryItOut("\"use strict\"; print(let ({e, w: [NaN]} = Map.prototype.clear.prototype, a, x = Math.exp(-9), x = ({/*toXFun*/toString: function(q) { return q; } }), cuqgdk, y) ((function sum_indexing(zumvdf, stsoyt) { ; return zumvdf.length == stsoyt ? 0 : zumvdf[stsoyt] + sum_indexing(zumvdf, stsoyt + 1); })(/*MARR*/[(void 0), (void 0), (void 0), (void 0), -(2**53), (this\n), new Boolean(false), ({x:3})], 0)));");
/*fuzzSeed-221406266*/count=1276; tryItOut("mathy4 = (function(x, y) { return ((( + Math.min(( + (( + Math.imul((y / ( - y)), Math.acos(2**53-2))) >>> Math.min(y, y))), (( + (x | 0)) | 0))) | 0) >> Math.fround(Math.abs(Math.fround(( + mathy2((x - (y && x)), ( + ( + Math.tanh(-(2**53-2)))))))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 1, 0, 2**53, 2**53+2, -0x080000001, -0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0x080000001, Number.MIN_VALUE, -(2**53+2), 0x100000000, Number.MAX_VALUE, -(2**53), 0/0, Math.PI, 0x07fffffff, -1/0, 42, -(2**53-2), 2**53-2, 0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -0, 0x080000000]); ");
/*fuzzSeed-221406266*/count=1277; tryItOut("/*vLoop*/for (var lfmrql = 0; lfmrql < 105; ++lfmrql) { let a = lfmrql; /* no regression tests found */ } ");
/*fuzzSeed-221406266*/count=1278; tryItOut("\"use asm\"; for (var v of f1) { try { b2 = t1.buffer; } catch(e0) { } try { /*infloop*/while([z1]){/*MXX3*/o0.g1.RangeError.name = g2.RangeError.name;for (var v of s0) { try { v1 = t0.length; } catch(e0) { } try { x = i1; } catch(e1) { } try { g1 = a0[17]; } catch(e2) { } for (var p in m2) { try { this.v1 = evaluate(\"29\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: window, noScriptRval: \"\\u026D\", sourceIsLazy: false, catchTermination: x, elementAttributeName: s0, sourceMapURL: s0 })); } catch(e0) { } try { /*RXUB*/var r = r1; var s = o0.s2; print(uneval(r.exec(s))); print(r.lastIndex);  } catch(e1) { } a0.unshift(e2, v0, i2, m0, t0); } } } } catch(e1) { } g2.toString = (function() { try { t0.__iterator__ = (function() { try { b2.toString = (function(j) { if (j) { try { v0 = Object.prototype.isPrototypeOf.call(e2, f1); } catch(e0) { } a2.toString = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -9.671406556917033e+24;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    i3 = (i3);\n    return (((0x1f83ee3)))|0;\n  }\n  return f; }); } else { t0 = x; } }); } catch(e0) { } /*MXX2*/g1.Map.prototype.keys = i0; return g0.i0; }); } catch(e0) { } try { s1 += 'x'; } catch(e1) { } this.v1 = Array.prototype.reduce, reduceRight.apply(this.a0, [m1]); return p2; }); }");
/*fuzzSeed-221406266*/count=1279; tryItOut("\"use strict\"; v0 = (p1 instanceof o0);p1 + o2.a2;");
/*fuzzSeed-221406266*/count=1280; tryItOut("for(var [b, d] = ({}) in -26) {m2.set(a0, o1.b2);Array.prototype.forEach.apply(a2, [f1, o0, i2]); }");
/*fuzzSeed-221406266*/count=1281; tryItOut("/*RXUB*/var r = (Math.atan2((\nx), -7)); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-221406266*/count=1282; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1283; tryItOut("while((x) && 0)/*RXUB*/var r = new RegExp(\"\\\\3+?\", \"gym\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=1284; tryItOut("\"use strict\"; testMathyFunction(mathy4, [1/0, 0, -0x080000001, Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, 42, 0/0, 2**53, -0, -Number.MAX_VALUE, -(2**53+2), 0.000000000000001, -0x0ffffffff, 2**53-2, -0x100000001, -(2**53-2), -0x100000000, 0x080000001, 0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53), 0x080000000, 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, 1]); ");
/*fuzzSeed-221406266*/count=1285; tryItOut("testMathyFunction(mathy1, [1, Math.PI, -1/0, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 1/0, -0x080000000, -0x080000001, -0x07fffffff, 2**53+2, 0.000000000000001, 0x07fffffff, -(2**53+2), -0, -Number.MAX_VALUE, -0x0ffffffff, 0, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53-2), 0x080000000, 1.7976931348623157e308, 0x100000001, 2**53, 0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 0x080000001]); ");
/*fuzzSeed-221406266*/count=1286; tryItOut("/*RXUB*/var r = r2; var s = s0; print(uneval(r.exec(s))); with({a: ((Symbol)(x))})/*vLoop*/for (let dwdscz = 0, /(?!\\u00d2|(^)|[^\\D]){1,4}/im; dwdscz < 31; ++dwdscz) { c = dwdscz; [1]; } ");
/*fuzzSeed-221406266*/count=1287; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul((( + Math.max(Math.fround(( - ( - y))), Math.fround(Math.fround(Math.pow(((x >>> 0) && (x >= (x | 0))), ( + ( + Math.hypot(( + x), (0x0ffffffff >>> 0))))))))) || ( ! y)), Math.atan2(((Math.atan2((((mathy0(( + 42), y) >>> 0) || ((Math.fround(x) & Math.fround(Math.min(y, x))) >>> 0)) >>> 0), Math.min((Math.expm1((x | 0)) | 0), Math.fround(Math.abs(y)))) >>> 0) | 0), ( - Math.fround((Math.fround(-(2**53+2)) !== Math.fround(Math.round((( ! x) >>> 0)))))))); }); ");
/*fuzzSeed-221406266*/count=1288; tryItOut("/*MXX2*/o0.o2.g2.Array.prototype.join = g0;");
/*fuzzSeed-221406266*/count=1289; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a0, [(function() { v1 = evaluate(\"((function fibonacci(xgqpnb) { Array.prototype.forEach.call(a2, f2, o1, this.v2, s2);; if (xgqpnb <= 1) { ; return 1; } ; return fibonacci(xgqpnb - 1) + fibonacci(xgqpnb - 2);  })(5))\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 85 == 20), noScriptRval: true, sourceIsLazy: (x % 55 != 16), catchTermination: (x % 49 != 19), element: o1, elementAttributeName: s0 })); throw this.o0.s0; })]);");
/*fuzzSeed-221406266*/count=1290; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-221406266*/count=1291; tryItOut("\"use strict\"; a1 = [];");
/*fuzzSeed-221406266*/count=1292; tryItOut("\"use strict\"; /*oLoop*/for (let flunln = 0; flunln < 4; ++flunln) { o0.o2 = {}; } ");
/*fuzzSeed-221406266*/count=1293; tryItOut("\"use strict\"; v1 = undefined;");
/*fuzzSeed-221406266*/count=1294; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -2147483647.0;\n    return (((Uint16ArrayView[((0xfea2a476)) >> 1])))|0;\n  }\n  return f; })(this, {ff: String}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0x100000001, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff, 2**53, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, Number.MIN_VALUE, 42, 1.7976931348623157e308, 0x080000001, -(2**53-2), -Number.MIN_VALUE, 1/0, -1/0, -0x080000000, 0x07fffffff, 0, 0x0ffffffff, 2**53-2, 1, Math.PI, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=1295; tryItOut("g1.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-221406266*/count=1296; tryItOut("for (var v of g1) { try { m2.set(o1, a2); } catch(e0) { } try { o1.v2 = (this.g0 instanceof o1.a1); } catch(e1) { } ; }");
/*fuzzSeed-221406266*/count=1297; tryItOut("/*bLoop*/for (let ehldok = 0, [] = (x)(x); ehldok < 29; ++ehldok, x) { if (ehldok % 33 == 14) { g0.offThreadCompileScript(\"(4277).__defineGetter__(\\\"x\\\", function(y) { this.h2.getPropertyDescriptor = f1; })\"); } else { x; }  } ");
/*fuzzSeed-221406266*/count=1298; tryItOut("\"use strict\"; s1 += this.s2;");
/*fuzzSeed-221406266*/count=1299; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.sqrt((Math.atan2(( ! Math.max(Number.MIN_SAFE_INTEGER, Math.log2(Math.fround((Math.fround(-0x100000000) ? Math.fround((x ? x : y)) : x))))), (Math.imul(( ~ y), (y >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -(2**53), 2**53-2, -(2**53-2), -1/0, 0, 0/0, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, Math.PI, -0x0ffffffff, -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000000, 0x100000000, 42, 2**53+2, 0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -0x080000000, -0, Number.MAX_SAFE_INTEGER, 1, -(2**53+2), 0x080000001, 2**53, 1/0, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-221406266*/count=1300; tryItOut("\"use asm\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -70368744177665.0;\n    var d3 = 67108865.0;\n    (Float32ArrayView[((Int16ArrayView[((Int8ArrayView[((0xfc914d05)*-0xfffff) >> 0])) >> 1])) >> 2]) = ((d1));\n    (Float32ArrayView[(((((Float32ArrayView[2]))>>>((((0xffaff948)) | ((0x669b8112))))))-((0xe95a449))) >> 2]) = ((Float32ArrayView[((0xfbbcc3dc)+(!((d2) <= (+(0.0/0.0))))) >> 2]));\n    {\n      d3 = (-0.015625);\n    }\n    d1 = (d2);\n    (Uint16ArrayView[0]) = (-0x234b2*(0x8526f294));\n    d3 = (d3);\n    d1 = (d3);\n    d0 = (NaN);\n    d2 = (d1);\n    d3 = (d1);\n    return (((0xffffffff)))|0;\n  }\n  return f; })(this, {ff: d =>  { \"use strict\"; s0.toSource = f2; } }, new ArrayBuffer(4096)); ");
/*fuzzSeed-221406266*/count=1301; tryItOut("\"use strict\"; v0 + '';");
/*fuzzSeed-221406266*/count=1302; tryItOut("o2.p1 + o2;function d(eval, d = x, eval, window, \u3056 =  /x/g  <<=  '' , b, \u3056, x, x =  '' , w, z = window, e, y, x, x, c, x, x, a, c, x, y = 0.923, a, x, x, y, x, w, NaN, window, b, window, window, x, eval, x, \u3056 =  /x/g , a, x, y, z, x =  /x/g , x, x =  /x/ , d = 14, c, eval, b, c, window = undefined, x, c, false, e, x, NaN, c = false, z, a, ...z)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((3.777893186295716e+22) <= (d1));\n    return +((Float64ArrayView[4096]));\n  }\n  return f;print(Math.max(x = -19\n, -26));");
/*fuzzSeed-221406266*/count=1303; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Int32ArrayView[2]) = ((0xff6569bb)-(!(0xffffffff)));\n    {\n      switch ((0x5210b0c3)) {\n        case 0:\n          (Int16ArrayView[1]) = ((0xfc40f7f4)-(i1));\n          break;\n        case -1:\n          d0 = (-16777217.0);\n      }\n    }\n    (Uint32ArrayView[1]) = (((0x4dd92112) >= (imul(((imul((0x89a04d36), (0x5e70a652))|0)), (i1))|0))-(0x266eb705));\n    switch ((~~((new String(''))))) {\n      case -2:\n        return +((-8796093022209.0));\n        break;\n    }\n    i1 = (0xfec48cfa);\n    d0 = ((4277));\n    return +((d0));\n  }\n  return f; })(this, {ff: DataView.prototype.setUint8}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0, 0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, 2**53, -0, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, -(2**53), 0/0, 0x080000000, -Number.MIN_VALUE, 0.000000000000001, 0x080000001, Number.MIN_VALUE, 1/0, 0x07fffffff, 1, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), -(2**53-2), -0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, 42, -1/0, 0x100000000, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1304; tryItOut("/*infloop*/M:for(var x in window) {p1 = m1.get(v1);yield; }");
/*fuzzSeed-221406266*/count=1305; tryItOut("this.f2(a0);");
/*fuzzSeed-221406266*/count=1306; tryItOut("a2 = [];");
/*fuzzSeed-221406266*/count=1307; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -1073741825.0;\n    var i5 = 0;\n    var i6 = 0;\n    var d7 = 32769.0;\n    i1 = (i3);\n    switch ((~~(17179869183.0))) {\n      case 0:\n        i2 = ((0xe79a4a39) ? (i5) : (i1));\n        break;\n      case -1:\n        (Float32ArrayView[2]) = ((d0));\n        break;\n      case 1:\n        {\n          (Uint32ArrayView[1]) = (((~(((+/*FFI*/ff()) < (d7))-(0xf8ab416b))) >= (~~(NaN)))+(i6)-(i1));\n        }\n        break;\n      default:\n        return ((((-590295810358705700000.0) <= (-1.0))-(i5)+(0x42ea11a4)))|0;\n    }\n    d4 = (-3.8685626227668134e+25);\n    i5 = (i6);\n    return (((i6)+((Uint8ArrayView[(0x4f142*(/*FFI*/ff(((-134217729.0)), ((0x12778*(i1))), ((((-2.4178516392292583e+24)) / ((-1.125)))), ((9.44473296573929e+21)))|0)) >> 0]))-(i5)))|0;\n    (Float32ArrayView[1]) = ((-((+(-1.0/0.0)))));\n    i1 = ((0xaea2355a));\n    return ((((0x0) <= ((((((0x73f94359)) >> ((0xeb221cd6)-(-0x8000000)-(-0x8000000))) >= (((0x6cf0db9b) % (0x774dd315)) ^ ((/*FFI*/ff(((-9.0)), ((295147905179352830000.0)), ((137438953472.0)))|0)))))>>>(((((0x6af04e1a) != (0x5fa8cf9)))>>>((0xc7a2f68a)+(0xebbb351d)+(0xf16ab2f9))) / ((-0xfffff*(0xfdd47fa5))>>>(-0x47ee8*(0xff4bb5f8))))))+(i3)))|0;\n  }\n  return f; })(this, {ff: Math.log1p}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, Math.PI, 0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, 0/0, 0, -(2**53-2), -1/0, -0x100000001, 0.000000000000001, 1, -0x080000001, 1/0, -0x080000000, -(2**53+2), Number.MAX_VALUE, 2**53+2, -0, -0x100000000, -0x07fffffff, -(2**53), 2**53-2, 0x100000001, Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1308; tryItOut("\"use strict\"; o1.m2.set(e2, o1.b0);");
/*fuzzSeed-221406266*/count=1309; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1125899906842625.0;\n    return +((((x)) * ((Float32ArrayView[(((this.__defineGetter__(\"b\", encodeURI)))-(i1)) >> 2]))));\n  }\n  return f; })(this, {ff: Symbol.prototype.valueOf}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -0, 2**53, 0x07fffffff, -(2**53-2), 0x100000000, -0x07fffffff, 1.7976931348623157e308, 0x080000001, 2**53+2, 1/0, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0x080000000, 1, 0/0, 42, Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, Math.PI, -0x080000000, 0, 0x0ffffffff, -(2**53), Number.MAX_VALUE, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=1310; tryItOut("const a, x, b, x = \"\\uB6AE\", window, zzrajo;h2.getPropertyDescriptor = f1;");
/*fuzzSeed-221406266*/count=1311; tryItOut("/*MXX2*/o0.g2.Math.atan2 = v1;");
/*fuzzSeed-221406266*/count=1312; tryItOut("\"use strict\"; const e = w;v1 = (o0 instanceof p1);w = function ([y]) { };\nArray.prototype.splice.call(a0, -6, 2);\n");
/*fuzzSeed-221406266*/count=1313; tryItOut("\"use strict\"; m1.valueOf = (function() { t2[v1] = g1.o1.p0; throw o2; });");
/*fuzzSeed-221406266*/count=1314; tryItOut("\"use strict\"; L: for  each(let b in ((makeFinalizeObserver('tenured')) >>= Math.max(10, \"\u03a0\"))) ;");
/*fuzzSeed-221406266*/count=1315; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sin((Math.fround(( ~ ( ~ x))) | 0)); }); testMathyFunction(mathy0, [0x0ffffffff, 1/0, -0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, Math.PI, -0x100000000, Number.MAX_VALUE, 42, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, 0, -(2**53+2), 1.7976931348623157e308, 2**53-2, 2**53, 1, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), -0x07fffffff, 0.000000000000001, 0/0, -0x080000001, 0x100000001, -Number.MIN_VALUE, 0x100000000, -1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -0x100000001]); ");
/*fuzzSeed-221406266*/count=1316; tryItOut("/*iii*/g2.offThreadCompileScript(\"function f0(f0) \\\"use asm\\\";   var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    (Int16ArrayView[0]) = (0x9abc3*((4194304.0) > (d0)));\\n    return (((0xa72d1890) / (0xae54ba06)))|0;\\n  }\\n  return f;\");/*hhh*/function twubjb(w, z, ...NaN){;new RegExp(\".(?!\\\\b{3,3})[^][^]|\\\\3*+|\\\\b(?![^]){1,}\", \"ym\");}");
/*fuzzSeed-221406266*/count=1317; tryItOut("Array.prototype.forEach.call(a1, (function() { for (var j=0;j<3;++j) { f2(j%5==0); } }), f0, i1);");
/*fuzzSeed-221406266*/count=1318; tryItOut("\"use strict\"; h2.set = f0;");
/*fuzzSeed-221406266*/count=1319; tryItOut("for(let a in /*\n*/[]) e1.has(m0);");
/*fuzzSeed-221406266*/count=1320; tryItOut("\"use strict\"; s0 + v2;");
/*fuzzSeed-221406266*/count=1321; tryItOut("\"use strict\"; ");
/*fuzzSeed-221406266*/count=1322; tryItOut("weawaq, udxqlj, x, gygdbw, ywicor, aefljl, window, eval, oldmvt;s0 += 'x';");
/*fuzzSeed-221406266*/count=1323; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1324; tryItOut("mathy4 = (function(x, y) { return (Math.atanh((((Math.log10(( + ( + Math.imul(( + y), ( + -0x07fffffff))))) >>> 0) << (( + Math.cos(( + Math.acosh((( ! (( + y) | 0)) >>> 0))))) >>> 0)) | 0)) >>> 0); }); testMathyFunction(mathy4, [2**53+2, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), 0x080000001, -1/0, Number.MIN_VALUE, 0, 0.000000000000001, 0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, 42, 2**53, -0, 0x0ffffffff, 2**53-2, -0x100000001, Math.PI, 1, -(2**53-2), 0x100000001, -Number.MIN_VALUE, 1/0, 0x080000000, Number.MAX_VALUE, -0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=1325; tryItOut("v0 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-221406266*/count=1326; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 16385.0;\n    return +((4.0));\n  }\n  return f; })(this, {ff: (x.eval(\"((function sum_indexing(ezsocr, bnnvzi) { e2.toSource = (function(j) { if (j) { g2.i1 + s1; } else { h0.fix = (function(a0, a1, a2, a3, a4) { a1 = a2 ^ x; var r0 = 5 - a2; var r1 = a1 & a0; var r2 = r1 - 9; var r3 = 3 * a2; a3 = r0 - 4; var r4 = r3 % r3; var r5 = 1 * 1; r1 = a4 % 4; var r6 = r4 + x; var r7 = r3 & r5; var r8 = 5 - 2; var r9 = 9 | 5; var r10 = r9 ^ r4; var r11 = 4 - r0; var r12 = r7 + a1; r6 = r1 % a4; var r13 = a1 + 9; var r14 = r8 % 6; var r15 = a3 + a1; var r16 = r7 & a0; var r17 = 1 - r10; r12 = 4 * r13; print(r7); var r18 = r13 - 0; x = r3 / a0; var r19 = r3 * r11; var r20 = a3 | r11; var r21 = r16 ^ r18; var r22 = a4 * r11; return a4; }); } });; return ezsocr.length == bnnvzi ? 0 : ezsocr[bnnvzi] + sum_indexing(ezsocr, bnnvzi + 1); })(/*MARR*/[(0/0), (0/0), (0/0), new String(''), new String(''), new String(''),  '\\\\0' , (0/0), new String(''), new String(''), (0/0),  '\\\\0' , (0/0), new String(''), new String(''),  '\\\\0' ,  '\\\\0' ,  '\\\\0' , new String(''), (0/0), (0/0), (0/0),  '\\\\0' ,  '\\\\0' , (0/0)], 0))\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53+2), -Number.MIN_VALUE, -(2**53-2), -0x080000001, 2**53-2, 0, -0x100000001, -0x080000000, 0/0, Number.MAX_VALUE, 1, 2**53+2, -Number.MIN_SAFE_INTEGER, 42, 2**53, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, -Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000001, Math.PI, -0x100000000, -1/0, -0x07fffffff, 1.7976931348623157e308, 0x07fffffff, Number.MIN_VALUE, 1/0, -0, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=1327; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2(( ! Math.pow((Math.sin(-0x100000000) >>> 0), ((((x >> Math.trunc(x)) >>> y) ^ (( ~ 0x080000001) | 0)) >>> 0))), Math.max(mathy2(( + ( + Math.cos(( + Math.atan(y))))), ( + Math.atan2(( + (( + mathy1(y, x)) > ( + (mathy2((0x080000001 | 0), (y | 0)) | 0)))), 2**53+2))), Math.fround(Math.max(Math.fround(x), Math.fround(( + (( ! ( + (Math.fround(2**53+2) != Math.fround(x)))) ** (Math.fround(Math.atan2((y | 0), (Math.tan(x) >>> 0))) ? x : y)))))))); }); testMathyFunction(mathy4, /*MARR*/[033, yield \u000cthis.\u3056 & (x%=(void options('strict_mode'))), 033, yield \u000cthis.\u3056 & (x%=(void options('strict_mode'))), yield \u000cthis.\u3056 & (x%=(void options('strict_mode'))), yield \u000cthis.\u3056 & (x%=(void options('strict_mode'))), yield \u000cthis.\u3056 & (x%=(void options('strict_mode')))]); ");
/*fuzzSeed-221406266*/count=1328; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 3.777893186295716e+22;\n    var i3 = 0;\nObject.defineProperty(this, \"g1.a2\", { configurable: true, enumerable: (x % 6 != 2),  get: function() {  return w.throw( /x/g ) for (c of this); } });    {\n      i1 = (!((abs((~(((0x1e6935dd) < (((0xfd063f3f))>>>((0xffffffff))))-(-0x8000000)-(/*FFI*/ff(((abs((((-0x8000000)) ^ ((0xfe1f8095))))|0)), ((+abs(((34359738369.0))))), ((-3.8685626227668134e+25)), ((8193.0)), ((-513.0)))|0))))|0) >= (((((/*FFI*/ff(((-2147483649.0)), ((-1.2089258196146292e+24)), ((128.0)), ((-1.2089258196146292e+24)), ((67108863.0)), ((1152921504606847000.0)), ((-2199023255553.0)), ((-513.0)))|0)) << ((0xfcd8eb18)+(-0x8000000)+(0xff30c710))) % ((-(/*FFI*/ff(((1025.0)), ((-1.03125)), ((536870913.0)))|0))|0)) | ((((((0x247f863e)+((0x455537cc))))|0))-(i3)))));\n    }\n    return ((0x6979f*(!(/*FFI*/ff(((((/*FFI*/ff()|0)) ^ ((0x9cd0e033)-(i0)))), ((~~(2305843009213694000.0))))|0))))|0;\n  }\n  return f; })(this, {ff: Symbol.for}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, -(2**53+2), 1, Number.MIN_VALUE, 0x080000001, 0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 0/0, -0, 0, 2**53-2, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 2**53, -0x080000000, 42, -0x0ffffffff, 1/0, 0x0ffffffff, 0x100000001, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, -0x100000001, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1329; tryItOut("/*infloop*/for(d = Math.pow(10, w = (/*MARR*/[new Number(1), new String(''), new Boolean(true), undefined, new Boolean(true), new Boolean(true), new Number(1), new Number(1), new Number(1), new Number(1), undefined, new String(''), new Boolean(true), new Number(1), undefined, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), undefined, new Number(1), new Number(1), undefined, new String(''), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new String(''), new Number(1), new String(''), undefined, new String(''), new Boolean(true), new Boolean(true), new String(''), new Boolean(true), new Boolean(true), undefined, undefined, undefined, new Number(1), new String(''), new String(''), undefined, new Boolean(true), new String(''), new Number(1), undefined, new Number(1), new String(''), new Number(1), undefined, new String(''), new Boolean(true), undefined, undefined, new String(''), new Number(1)].filter(Array.prototype.forEach,  '' )).__defineGetter__(\"x\", (uneval(/*MARR*/[new Number(1.5), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1.5), -Infinity, -Infinity, -Infinity, -Infinity, new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), new Number(1.5), -Infinity, -Infinity, -Infinity, -Infinity, new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), -Infinity, new Number(1.5), -Infinity, new Number(1.5), -Infinity, -Infinity, -Infinity, -Infinity, new Number(1.5), new Number(1.5), -Infinity, -Infinity, -Infinity, new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), new Number(1.5), -Infinity, -Infinity, new Number(1.5), -Infinity, -Infinity, -Infinity, new Number(1.5), new Number(1.5), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), -Infinity, -Infinity, new Number(1.5), -Infinity, -Infinity, -Infinity, new Number(1.5), -Infinity, -Infinity, new Number(1.5), new Number(1.5), -Infinity, new Number(1.5), new Number(1.5)].sort(Error, 0))))); new RegExp(\"((\\\\u0035|\\\\W\\\\2))((?![\\\\w\\\\v\\ub1bd\\\\cA-\\\\u73D6])\\u0019[^]*?)\", \"\") /= \"\\uD273\"; window) /*MXX3*/g2.g2.Float64Array = g2.Float64Array;");
/*fuzzSeed-221406266*/count=1330; tryItOut("mathy5 = (function(x, y) { return Math.imul(Math.atan(( + Math.pow(( + (y && Math.max((x * x), x))), Math.atan(Math.atan2(Math.fround((Math.max(-0x07fffffff, x) | 0)), x))))), (( + ((( + mathy2(Math.fround(y), ( + Math.asin(x)))) & y) - Math.log((Math.imul((y >>> 0), (( ~ -0x07fffffff) >>> 0)) >>> 0)))) && ( + (((Math.fround((Math.fround((( - (Math.max(y, y) | 0)) | 0)) || Math.imul(y, (y >>> 0)))) | 0) === (( ~ x) | 0)) | 0)))); }); testMathyFunction(mathy5, [false, objectEmulatingUndefined(), '/0/', /0/, 0.1, (function(){return 0;}), ({toString:function(){return '0';}}), '', ({valueOf:function(){return '0';}}), undefined, null, (new String('')), -0, [], [0], NaN, ({valueOf:function(){return 0;}}), '\\0', (new Number(0)), '0', 1, (new Number(-0)), (new Boolean(false)), (new Boolean(true)), true, 0]); ");
/*fuzzSeed-221406266*/count=1331; tryItOut("testMathyFunction(mathy3, /*MARR*/[-(2**53+2), -(2**53+2), -(2**53+2), new Number(1), x, x, [1], ({} = (4277)), x, -(2**53+2), -(2**53+2), new Number(1), -(2**53+2), new Number(1), new Number(1), ({} = (4277)), ({} = (4277)), new Number(1), [1], -(2**53+2), x, -(2**53+2), ({} = (4277)), [1], -(2**53+2), [1], -(2**53+2), x, -(2**53+2), x, ({} = (4277)), -(2**53+2), x, x, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Number(1), x, new Number(1), x, x, [1], x, ({} = (4277)), [1], [1], [1], -(2**53+2), ({} = (4277)), new Number(1), new Number(1), ({} = (4277)), -(2**53+2), -(2**53+2), [1], -(2**53+2), [1], x]); ");
/*fuzzSeed-221406266*/count=1332; tryItOut("mathy0 = (function(x, y) { return ( + Math.max((Math.fround(Math.log2(Math.fround((((Math.fround(Math.hypot(Math.hypot(Math.fround(( - Math.fround(Math.fround((x ? y : -Number.MAX_SAFE_INTEGER))))), ( ~ (((-0x100000001 | 0) <= (y | 0)) | 0))), Math.fround(( + (Math.min((2**53-2 >>> 0), y) | 0))))) >>> 0) && ( + Math.log2(0x100000000))) >>> 0)))) >>> 0), ((( + Math.fround(Math.min(y, x))) ? (Math.max((-0x07fffffff >>> 0), (( - Math.imul(-Number.MIN_SAFE_INTEGER, x)) >>> 0)) >>> 0) : ( + Math.min(( + y), y))) >>> 0))); }); testMathyFunction(mathy0, [0.000000000000001, -0x100000000, Number.MIN_VALUE, 0x0ffffffff, 1/0, -1/0, Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53+2), 1, 2**53, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0x080000000, 2**53+2, -(2**53), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, -Number.MIN_VALUE, -0, 0x080000001, 0x100000000, -0x07fffffff, 0, 2**53-2, -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-221406266*/count=1333; tryItOut("e1.has(o0.a1);");
/*fuzzSeed-221406266*/count=1334; tryItOut("mathy2 = (function(x, y) { return (( + ( + Math.min(( + (((( + x) == ( + Math.fround(Math.atan2(Math.fround(x), y)))) >>> 0) >>> 0)), (Math.atan2((x << y), (( + mathy1((y >>> 0), ( + y))) | 0)) ? y : (Math.hypot((y >>> 0), (( - y) >>> 0)) >>> 0))))) ^ (mathy0(((mathy0((Math.atanh(Math.fround(Math.min((x || Math.fround(x)), Math.pow(y, y)))) >>> 0), (Math.asinh((Math.max(x, 0x07fffffff) >>> 0)) >>> 0)) >>> 0) | 0), ((Math.max(( + ( + Math.hypot(Math.fround((x - y)), ( + x)))), (Math.atan2((-(2**53-2) | 0), ((((1 | 0) << (( + (( + (mathy1(y, y) | 0)) ? ( + Math.abs(( + x))) : Math.fround(x))) | 0)) | 0) | 0)) | 0)) | 0) | 0)) | 0)); }); testMathyFunction(mathy2, [-0, 0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 1/0, -(2**53), 42, -Number.MIN_VALUE, 0x080000000, -0x100000001, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, 0x100000000, 1, 2**53, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 2**53+2, 0x080000001, -0x100000000, 0, 0x07fffffff, -0x080000000, -0x0ffffffff, 0/0, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1335; tryItOut("\"use strict\"; a1.valueOf = (function() { for (var j=0;j<37;++j) { o1.f0(j%4==1); } });");
/*fuzzSeed-221406266*/count=1336; tryItOut("o1.o2.toSource = (function mcc_() { var zviljm = 0; return function() { ++zviljm; if (/*ICCD*/zviljm % 4 == 1) { dumpln('hit!'); try { Array.prototype.shift.apply(a0, []); } catch(e0) { } try { o1 = o0; } catch(e1) { } e0.delete(this.h2); } else { dumpln('miss!'); /*RXUB*/var r = o2.r1; var s = s0; print(s.search(r));  } };})();");
/*fuzzSeed-221406266*/count=1337; tryItOut("v2 = Object.prototype.isPrototypeOf.call(f1, o1.g0);");
/*fuzzSeed-221406266*/count=1338; tryItOut("\"use strict\"; /*vLoop*/for (let iffoyi = 0; iffoyi < 59; ++iffoyi) { var a = iffoyi; a1.forEach((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    (Float64ArrayView[0]) = ((+(-1.0/0.0)));\n    return +((0.00390625));\n  }\n  return f; })(this, {ff: function  NaN (z, x) { yield  \"\"  } }, new ArrayBuffer(4096)), a0, \"\\u5ACD\", v2,  /x/g ); } ");
/*fuzzSeed-221406266*/count=1339; tryItOut("h0 = ({getOwnPropertyDescriptor: function(name) { g2 = this;; var desc = Object.getOwnPropertyDescriptor(t2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { throw e2; var desc = Object.getPropertyDescriptor(t2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e0.add(this.p1);; Object.defineProperty(t2, name, desc); }, getOwnPropertyNames: function() { s2 = Array.prototype.join.call(a0, a1);; return Object.getOwnPropertyNames(t2); }, delete: function(name) { m1.get([z1,,]);; return delete t2[name]; }, fix: function() { h2.fix = f0;; if (Object.isFrozen(t2)) { return Object.getOwnProperties(t2); } }, has: function(name) { return g0; return name in t2; }, hasOwn: function(name) { /*ADP-1*/Object.defineProperty(a1, \nlet (c) undefined, ({enumerable: true}));; return Object.prototype.hasOwnProperty.call(t2, name); }, get: function(receiver, name) { ;; return t2[name]; }, set: function(receiver, name, val) { b2 = Proxy.create(h0, o0);; t2[name] = val; return true; }, iterate: function() { v1 = (g0 instanceof g2.h2);; return (function() { for (var name in t2) { yield name; } })(); }, enumerate: function() { print(f0);; var result = []; for (var name in t2) { result.push(name); }; return result; }, keys: function() { f1(o2);; return Object.keys(t2); } });");
/*fuzzSeed-221406266*/count=1340; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=1341; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( + (( - y) >>> 0)) ^ Math.atan2((Math.max(Math.trunc(x), (x >> 1/0)) >>> 0), (Math.sinh((x >>> 0)) >>> 0))) / (mathy3((Math.fround(Math.imul(Math.fround(Math.max(y, ( ~ \"\\u008C\"))), Math.fround((Math.max(Math.fround(Math.tanh(Math.fround(x))), x) >>> 0)))) | 0), ((Math.atan2(Math.fround((( + (x >>> 0)) >>> 0)), Math.fround(( ! Math.sin(x)))) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy5, [-(2**53-2), -Number.MAX_VALUE, 0.000000000000001, Math.PI, -0x100000000, 1, 0x0ffffffff, -1/0, 0/0, -0, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, 0, 0x100000000, -(2**53+2), 42, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 0x07fffffff, -0x07fffffff, -0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, -0x080000001, 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-221406266*/count=1342; tryItOut("testMathyFunction(mathy1, [0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Math.PI, 0, -Number.MIN_VALUE, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 1/0, 2**53, -0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, -(2**53-2), -0x100000000, 0x080000000, -Number.MAX_VALUE, -0x080000000, 0x100000001, -0x080000001, 0/0, -0x100000001, -(2**53), -1/0, 1, -0]); ");
/*fuzzSeed-221406266*/count=1343; tryItOut("testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), 0.1, 0, '', '/0/', ({valueOf:function(){return '0';}}), (new Boolean(false)), '\\0', null, undefined, (function(){return 0;}), '0', -0, (new String('')), ({toString:function(){return '0';}}), false, true, NaN, /0/, [], [0], (new Number(0)), objectEmulatingUndefined(), (new Boolean(true)), 1, (new Number(-0))]); ");
/*fuzzSeed-221406266*/count=1344; tryItOut("{ void 0; void gc(); }print(uneval(g1.b2));");
/*fuzzSeed-221406266*/count=1345; tryItOut("/*tLoop*/for (let d of /*MARR*/[new String(''), (-1/0), Infinity, Infinity, Infinity, Infinity,  /x/ , (-1/0), new String(''), (-1/0), (-1/0),  /x/ , Infinity, (-1/0), new String(''), Infinity, new String(''), Infinity, Infinity,  /x/ ]) { print(d); }");
/*fuzzSeed-221406266*/count=1346; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53, -Number.MIN_VALUE, Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 1/0, -0x080000001, -0x0ffffffff, 0x100000001, -(2**53), 0x07fffffff, -0x100000001, -0x07fffffff, 1, -1/0, Math.PI, 1.7976931348623157e308, Number.MAX_VALUE, 0, -0x080000000, 42, 2**53+2, 0/0, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1347; tryItOut("g0.v1 = a1.length;");
/*fuzzSeed-221406266*/count=1348; tryItOut("\"use asm\"; this.g1 + '';");
/*fuzzSeed-221406266*/count=1349; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"\\\"use strict\\\"; mathy4 = (function(x, y) { \\\"use strict\\\"; return Math.sin(mathy3(Math.trunc((( + x) << -(2**53))), Math.fround((Math.fround(y) , Math.max((-Number.MIN_VALUE !== x), (Math.sin((Math.atan(y) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy4, [0.1, -0, 1, (new Boolean(false)), ({toString:function(){return '0';}}), '/0/', NaN, undefined, [0], '', '\\\\0', ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), /0/, 0, null, false, [], (new Number(0)), (new String('')), (new Number(-0)), objectEmulatingUndefined(), '0', (function(){return 0;}), true, (new Boolean(true))]); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: ((-1/0)), noScriptRval: 18, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-221406266*/count=1350; tryItOut("\"use strict\"; ");
/*fuzzSeed-221406266*/count=1351; tryItOut("\"use strict\"; x = o2.a0;");
/*fuzzSeed-221406266*/count=1352; tryItOut("g1.i1.next();");
/*fuzzSeed-221406266*/count=1353; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x080000000, 1/0, Math.PI, 0.000000000000001, -0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, 0x080000001, 0/0, 1.7976931348623157e308, 42, 1, -Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, 2**53+2, -0x100000001, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -(2**53+2), 0, -(2**53-2), -Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -(2**53), -0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, 0x100000000, 0x100000001]); ");
/*fuzzSeed-221406266*/count=1354; tryItOut("/*MXX1*/o0 = g2.Function.prototype.arguments;");
/*fuzzSeed-221406266*/count=1355; tryItOut("\"use strict\"; t2[({valueOf: function() { g0.i1.send(f1);return 19; }})];");
/*fuzzSeed-221406266*/count=1356; tryItOut("/*oLoop*/for (wbesfu = 0; wbesfu < 15 && ((\"\\u0255\" > WebAssemblyMemoryMode([],  \"\" ))); ++wbesfu) { (x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: (let (e=eval) e), }; })(29), (-28 && d)) << x); } ");
/*fuzzSeed-221406266*/count=1357; tryItOut("\"use strict\"; ttfvzk, y = /*FARR*/[].some.throw(x), b = x, devgct, jcpyro, y = (4277), arguments, ycoczv;f0 + '';\n/*vLoop*/for (ttsmoy = 0; ttsmoy < 7; ++ttsmoy) { const e = ttsmoy; print(x); } \n");
/*fuzzSeed-221406266*/count=1358; tryItOut("mathy3 = (function(x, y) { return Math.hypot(Math.log2(((((x && (Math.fround(y) - ( - y))) | 0) || (Math.abs((Math.fround(Math.log2(Math.fround(x))) >>> 0)) | 0)) | 0)), ( + (Math.fround(((Math.fround(x) && Math.fround(y)) >>> 0)) !== (Math.log(mathy1((Math.expm1(( + -(2**53))) >>> 0), ( ! 0x080000001))) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), function(){}, Infinity, objectEmulatingUndefined(), x, x, new Number(1), Infinity, x, objectEmulatingUndefined(), new Number(1), function(){}, x, new Number(1), Infinity, objectEmulatingUndefined(), Infinity, Infinity, x, new Number(1), function(){}, Infinity, new Number(1), x, new Number(1), function(){}, function(){}, x, x, x, Infinity, function(){}, x, new Number(1), x, new Number(1), Infinity, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, new Number(1), objectEmulatingUndefined(), function(){}, function(){}, Infinity, new Number(1), x, Infinity, function(){}, Infinity, x, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, function(){}, x, objectEmulatingUndefined(), new Number(1), function(){}]); ");
/*fuzzSeed-221406266*/count=1359; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.max(((Math.acosh(( ~ (Math.log1p(2**53) >>> 0))) | 0) >>> 0), ( + (( ! ((Math.hypot((Math.atan(y) | 0), ((Math.tanh(Math.fround(Math.min(Math.fround(( ~ Math.fround(Number.MIN_VALUE))), x))) >>> 0) >>> 0)) >>> 0) | 0)) | 0)))); }); ");
/*fuzzSeed-221406266*/count=1360; tryItOut("o1.e2 + '';");
/*fuzzSeed-221406266*/count=1361; tryItOut("print(x);");
/*fuzzSeed-221406266*/count=1362; tryItOut("mathy5 = (function(x, y) { return ( + Math.sin(((Math.exp(Math.log1p(Math.fround(Math.atan2(( + mathy3(x, x)), (( + Math.max((Math.sign((x | 0)) | 0), ( + y))) >>> 0))))) | 0) | 0))); }); testMathyFunction(mathy5, [-0, 2**53+2, 0x100000001, -(2**53-2), -0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000000, 2**53-2, 0, -0x080000001, Math.PI, 0x080000000, 0x100000000, -(2**53+2), 0x0ffffffff, -0x100000001, -1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0/0, -Number.MAX_VALUE, 2**53, 42, 1, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=1363; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(mathy0(Math.fround(((((y | 0) ^ (Math.hypot((1/0 >>> 0), (( ! x) | 0)) | 0)) | 0) | ((( + y) ? ( + x) : ( + (( ~ Math.fround(x)) >>> 0))) >>> 0))), Math.fround((( + x) || x)))) >>> 0) * (Math.imul(( - Math.fround(x)), ( ~ ( ! (Math.max(y, y) | 0)))) >>> 0)); }); testMathyFunction(mathy1, [0, 42, Math.PI, -0x0ffffffff, -0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, -0x07fffffff, 0x07fffffff, -1/0, -0x080000000, -0x100000000, -(2**53+2), 2**53-2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -Number.MIN_VALUE, 1/0, 2**53, 0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), 1, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000001, -(2**53-2), 0x080000001, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=1364; tryItOut("\"use strict\"; t0 = o0.o1.t0.subarray(6);");
/*fuzzSeed-221406266*/count=1365; tryItOut("t0 = new Uint32Array(b2);m1 = new Map(f0);");
/*fuzzSeed-221406266*/count=1366; tryItOut("g0.s2 + '';");
/*fuzzSeed-221406266*/count=1367; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.abs(Math.fround(mathy1(((Math.max((x | 0), ( + ( + Math.pow(( + y), ( + x))))) | 0) ? Math.fround(Math.atan2(y, Math.fround(y))) : 0x080000001), Math.fround((((y ? (y >>> 0) : (0x07fffffff >>> 0)) >>> 0) >>> 0))))) - Math.sign(Math.trunc((( + ( ! ( + -Number.MAX_VALUE))) == ( + mathy0(Math.atan2(( + ( ~ y)), ( + 0.000000000000001)), x)))))) >>> 0); }); testMathyFunction(mathy2, [-0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 0x07fffffff, 2**53+2, Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -0x100000000, -0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, -0, 0x100000001, 1, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -0x080000001, 0x0ffffffff, 2**53, 0, 1/0, Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -(2**53), 0x080000001, 0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1368; tryItOut("/*oLoop*/for (let vhndav = 0; vhndav < 7 && (new RegExp(\"(?=(?:(?=([^\\\\xf3\\u0674\\\\u0492\\\\B]\\\\b\\u7693{2})\\u0322{2,6})))\", \"gy\")); ++vhndav) { a2.pop(b1, m0); } const x =  \"\" ;");
/*fuzzSeed-221406266*/count=1369; tryItOut("\"use strict\"; for(var [b, c] = (4277) in (intern('fafafa'.replace(/a/g, (let (e=eval) e))))) {print(x); }");
/*fuzzSeed-221406266*/count=1370; tryItOut("\"use strict\"; \"use asm\"; a1[4] = p2;");
/*fuzzSeed-221406266*/count=1371; tryItOut("if(true) { if (x) {print(x);print([z1]); }} else {return; }");
/*fuzzSeed-221406266*/count=1372; tryItOut("b2 = g2.t1.buffer;");
/*fuzzSeed-221406266*/count=1373; tryItOut("\"use strict\"; e0.toString = (function() { for (var v of b0) { try { /*RXUB*/var r = r2; var s = \"\\n\"; print(r.exec(s));  } catch(e0) { } /*MXX1*/o2 = g2.Promise.all; } return f0; });");
/*fuzzSeed-221406266*/count=1374; tryItOut("m2 + s2;function d(d = (4277), [])\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+((d1)));\n    d0 = (d1);\n    {\n      d0 = (d1);\n    }\n    d1 = (d1);\n    return +((Float64ArrayView[4096]));\n  }\n  return f;for (var p in g1.i0) { /*ADP-3*/Object.defineProperty(a1, 3, { configurable: (x % 6 == 5), enumerable: w, writable: false, value: h2 }); }");
/*fuzzSeed-221406266*/count=1375; tryItOut("mathy4 = (function(x, y) { return Math.expm1(( + (Math.fround(( ~ Number.MAX_VALUE)) * ((y < ( ! (x | 0))) ? (Math.sinh(x) >>> 0) : (((Math.min(0x07fffffff, ( + y)) >>> 0) && (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy4, /*MARR*/[(-1/0), x, (-1/0), x, x, new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), (-1/0), new Number(1.5), (-1/0), (-1/0), new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), (-1/0), x, (-1/0), x, (-1/0), new Number(1.5), x, x, x, (-1/0), (-1/0), new Number(1.5), new Number(1.5), (-1/0), new Number(1.5), x, new Number(1.5), x, x, x, (-1/0), (-1/0), x, new Number(1.5), x, x, (-1/0), x, new Number(1.5), (-1/0), x, (-1/0), x, x]); ");
/*fuzzSeed-221406266*/count=1376; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.imul((( ! ( ! ((Math.fround(Math.sign(Math.fround(((( + y) ? ( + y) : ( + y)) >>> 0)))) | 0) | x))) >>> 0), Math.imul(Math.fround(Math.log(Math.fround(( + Math.hypot((x | 0), mathy0((x >>> 0), (0x100000000 >>> 0))))))), (( ~ (Math.min(y, y) >>> 0)) | 0))) | 0); }); testMathyFunction(mathy2, [-1/0, 0x07fffffff, -0x0ffffffff, -0, -0x100000000, -0x080000000, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, 0x100000001, Math.PI, 2**53, 0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0x080000000, Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, -0x07fffffff, 2**53-2, 1, 0, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-221406266*/count=1377; tryItOut("");
/*fuzzSeed-221406266*/count=1378; tryItOut("mathy5 = (function(x, y) { return (((((((Math.pow(( + ( + ( + x))), y) == ( + Math.max(( + y), ( + (2**53+2 / 0))))) | 0) >>> 0) ? (Math.asinh((x >>> 0)) >>> 0) : ((Math.log(( + mathy1(( + (( + x) , ( + y))), ( + ((-Number.MIN_VALUE | 0) << y))))) ^ Math.fround(Math.acos(Math.fround(2**53-2)))) >>> 0)) >>> 0) | 0) - (Math.pow((Math.fround(Math.trunc(Math.fround(y))) , ( - x)), Math.fround((Math.fround(Math.expm1(Math.fround((Math.fround(-Number.MAX_VALUE) ** Math.fround(y))))) && Math.fround((mathy1((x >>> 0), (( ! Math.hypot(Math.log10(x), x)) >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[new Number(1), null,  '\\0' , false, null,  '\\0' , new Number(1), null, new Number(1),  '\\0' ]); ");
/*fuzzSeed-221406266*/count=1379; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((Math.round(( + Math.imul(( + Math.asinh(( + 0x080000001))), y))) << Math.max(x, (Math.round((( - -(2**53-2)) | 0)) | 0))) ** Math.pow(( + ( - ( + y))), ( + x))); }); ");
/*fuzzSeed-221406266*/count=1380; tryItOut("\"use strict\"; /*vLoop*/for (let qoeimy = 0; qoeimy < 2; ++qoeimy) { let z = qoeimy; m2.delete(g2.e0); } ");
/*fuzzSeed-221406266*/count=1381; tryItOut("const o1.s0 = s1.charAt(5);");
/*fuzzSeed-221406266*/count=1382; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1383; tryItOut("v2 = evaluate(\"m1.delete(p1);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 49 == 15), noScriptRval: true, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-221406266*/count=1384; tryItOut("\"use strict\"; (4277);");
/*fuzzSeed-221406266*/count=1385; tryItOut("\"use strict\"; o0.i2.send(m0);");
/*fuzzSeed-221406266*/count=1386; tryItOut("mathy3 = (function(x, y) { return Math.tan(mathy0(((mathy1(Math.expm1(y), (( + ( - y)) | 0)) != (0x0ffffffff >>> 0)) >>> 0), ((y ? x : y) > ( + x)))); }); testMathyFunction(mathy3, [-0x100000000, -0x080000000, 2**53, -0x07fffffff, 0x0ffffffff, -0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 42, 0x100000000, 0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0x080000000, 2**53-2, 0/0, Number.MIN_VALUE, -(2**53), -0x100000001, 1/0, Math.PI, -(2**53-2), 0, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 0.000000000000001, -0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1387; tryItOut("\"use strict\"; v0 = (b0 instanceof t2);");
/*fuzzSeed-221406266*/count=1388; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\1){17179869184,}|(?=[^])|[^\\\\d]{0}(?=\\\\W*?)|[^]*?\\\\cW{0}$\\\\B{2,2}(.|\\\\\\u6018){274877906943}\", \"yim\"); var s = \"\\u0b160\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-221406266*/count=1389; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1390; tryItOut("Array.prototype.forEach.apply(a2, [(function(j) { f2(j); }), g0.a1, (({x: (4277).__defineGetter__(\"c\",  /x/g )})), o1.m0, g0.t0, i2]);");
/*fuzzSeed-221406266*/count=1391; tryItOut("g0.a1.sort(o2.o1.f0);");
/*fuzzSeed-221406266*/count=1392; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.log10(x) < ( - ((( - (Math.max(x, (y >>> 0)) >>> 0)) | 0) >> -0x07fffffff))) != ((y > ( + Math.log1p(( + Math.fround(( ! Math.fround(-0x100000001))))))) ? (Math.imul(( + ((((x >>> 0) ** x) >>> 0) & ( + y))), y) >>> 0) : ( ! (( + (Math.sin(((Math.hypot((y >>> 0), (x >>> 0)) >>> 0) >>> 0)) ? x : (( + ( + (x | 0))) | 0))) >> ( + Math.imul(y, ( + Math.fround(x)))))))); }); testMathyFunction(mathy0, /*MARR*/[x, x,  /x/ , x,  /x/ , x,  /x/ ,  /x/ , x,  /x/ ,  /x/ , x, x, x,  /x/ , x, x, x,  /x/ , x, x, x, x,  /x/ ,  /x/ ,  /x/ ,  /x/ , x, x, x, x,  /x/ ,  /x/ ,  /x/ , x,  /x/ , x, x,  /x/ , x,  /x/ ,  /x/ , x,  /x/ ,  /x/ , x,  /x/ , x, x,  /x/ , x, x, x,  /x/ ,  /x/ , x,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , x,  /x/ , x, x,  /x/ ,  /x/ , x, x, x,  /x/ , x,  /x/ ,  /x/ , x, x, x, x,  /x/ , x,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , x,  /x/ ,  /x/ , x, x]); ");
/*fuzzSeed-221406266*/count=1393; tryItOut("v0 = Object.prototype.isPrototypeOf.call(f2, p2);");
/*fuzzSeed-221406266*/count=1394; tryItOut("\"use strict\"; a1.pop(i0, m1, b2, f1, /*FARR*/[, x, x, x, (void options('strict')), null, , .../*PTHR*/(function() { \"use strict\"; for (var i of /*FARR*/[]) { yield i; } })(), x].map(/\\B/gim), e0);");
/*fuzzSeed-221406266*/count=1395; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.min(Math.cosh(((( + x) % Math.clz32((Math.min(y, (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))) >>> 0)), (((Math.sinh(Math.pow(( + Math.sin((x >>> 0))), ( + x))) >>> 0) >= (((((((y >>> 0) ^ (( ~ y) >>> 0)) >>> 0) === ( + (( + y) ? Math.max(y, x) : ( + y)))) | 0) ^ ((( + ((Math.atan2((x >>> 0), x) & ( ! y)) >>> 0)) >>> 0) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-0x080000000, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, 1, -0x080000001, 42, 0x080000001, -0x100000000, -0x100000001, Math.PI, -0x0ffffffff, 0x100000000, 2**53, 1.7976931348623157e308, 0x100000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53), -(2**53-2), 0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, 2**53-2, -1/0, 1/0, -Number.MAX_VALUE, 0, 2**53+2]); ");
/*fuzzSeed-221406266*/count=1396; tryItOut("g2.o1 = v1.__proto__;");
/*fuzzSeed-221406266*/count=1397; tryItOut("testMathyFunction(mathy5, /*MARR*/[(0/0), (0/0),  /x/g , (0/0), (0/0), (0/0), (1/0),  /x/g ,  /x/g , (0/0), (0/0), (0/0), (0/0), (0/0),  /x/g , (0/0),  /x/g , (0/0), (0/0),  /x/g , (0/0), (0/0), (0/0),  /x/g , (1/0),  /x/g , (0/0), (1/0), (1/0), (0/0), (1/0),  /x/g , (0/0), (0/0), (0/0),  /x/g , (1/0), (0/0),  /x/g , (1/0), (0/0),  /x/g ,  /x/g , (0/0), (1/0), (0/0), (0/0), (0/0),  /x/g ,  /x/g , (0/0), (1/0), (1/0),  /x/g ,  /x/g ,  /x/g ]); ");
/*fuzzSeed-221406266*/count=1398; tryItOut("s2 += 'x';");
/*fuzzSeed-221406266*/count=1399; tryItOut("v1 = new Number(Infinity);");
/*fuzzSeed-221406266*/count=1400; tryItOut("null ||  /x/ ;with({}) { yield (4277); } ");
/*fuzzSeed-221406266*/count=1401; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(( ~ Math.fround((Math.sin((Math.log1p(Math.fround(Math.atan2((y >>> 0), x))) | 0)) === x)))), (Math.fround((Math.fround(Math.cos(Math.fround(Math.max(Math.fround(y), Math.fround(x))))) ? Math.fround(( - Math.fround(Math.max((Math.sign((Math.log2(y) >>> 0)) | 0), ( ''  >>> 0))))) : y)) ** Math.fround((2**53-2 > (Math.sign((x | 0)) | 0)))))); }); ");
/*fuzzSeed-221406266*/count=1402; tryItOut("o1.a1 = /*FARR*/[Object.defineProperty(w, \"apply\", ({configurable: true})), .../*MARR*/[objectEmulatingUndefined(),  'A' ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ ,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined()], -573042854, ...new Array(-0), , ((arguments.callee.caller.arguments = ({y: x})))];");
/*fuzzSeed-221406266*/count=1403; tryItOut("\"use asm\"; print(x);");
/*fuzzSeed-221406266*/count=1404; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a1, []);");
/*fuzzSeed-221406266*/count=1405; tryItOut("\"use strict\"; t0[12] = v2;");
/*fuzzSeed-221406266*/count=1406; tryItOut("v2 = evalcx(\"function f1(e0)  { \\\"use strict\\\"; return a|=(new (/*wrap1*/(function(){ \\\"use strict\\\";  '' ;return null})())()) } \", g0);");
/*fuzzSeed-221406266*/count=1407; tryItOut("/*RXUB*/var r = /(\\b{3,6})*/gi; var s = \"ua aa1\\u188dVla \\u85e51ua aa1\\u188dua aa1\\u188dua aa1\\u188d\"; print(s.split(r)); ");
/*fuzzSeed-221406266*/count=1408; tryItOut("mathy4 = (function(x, y) { return (Math.atan2((Math.imul(Math.asinh((((mathy0(((mathy0((Math.atanh(y) | 0), (( - x) >>> 0)) >>> 0) | 0), (0x100000001 | 0)) | 0) >>> 0) % ((y % x) >>> 0))), ((Math.round((( + (( + y) != Math.PI)) >>> 0)) >>> 0) / ( + (((y | 0) !== (x >>> 0)) >>> 0)))) | 0), ( + ( + Math.atan(((((y >>> 0) & y) >>> 0) , -Number.MIN_VALUE))))) >>> 0); }); testMathyFunction(mathy4, [objectEmulatingUndefined(), /0/, 0, '0', NaN, (function(){return 0;}), (new Boolean(true)), (new Number(0)), 0.1, ({valueOf:function(){return '0';}}), 1, [], (new Boolean(false)), '\\0', (new Number(-0)), -0, true, '/0/', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), [0], (new String('')), null, '', undefined, false]); ");
/*fuzzSeed-221406266*/count=1409; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround(((((( - ((x ? (x | 0) : (y | 0)) >>> 0)) >>> 0) * (Math.fround(( - (y >>> 0))) >>> 0)) >>> 0) === Math.acosh((( + Math.hypot(Math.cos((y >>> 0)), y)) | 0)))) <= Math.fround(((Math.imul(Math.fround(Math.cbrt(Math.fround(Math.atan2(Math.fround(-1/0), Math.fround(y))))), Number.MIN_VALUE) | 0) ** ( ! Math.pow(x, ( + Math.fround((Math.fround(x) + Math.fround(x)))))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, 2**53-2, 2**53, 0x080000001, 0/0, -Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, -0, Number.MAX_VALUE, -(2**53-2), -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, 0.000000000000001, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 0, -(2**53), 1, 42, -0x100000000, 0x0ffffffff, -0x100000001, 2**53+2]); ");
/*fuzzSeed-221406266*/count=1410; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1411; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return mathy0(Math.pow(Math.fround((0/0 !== (Math.cosh(Math.fround(-0x080000000)) | 0))), (((Math.min(Math.fround(mathy1(y, ( + (x >>> Math.fround(y))))), (((-0x080000001 ^ Math.log(y)) >>> 0) >>> 0)) | 0) << ((Math.log(( + (( + (mathy0(( + y), ( + Math.tan(Math.fround(2**53+2)))) >>> 0)) - ( + 2**53)))) | 0) >>> 0)) | 0)), ((Math.sqrt(Math.atan2((Math.sqrt((x | 0)) >>> 0), Math.fround(( + mathy0(( + (x || -Number.MAX_VALUE)), ( + ( + (y ^ y)))))))) > (( + mathy0(( + x), ( + ( + Math.min(Math.fround(( ~ Math.fround(Math.fround((/*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined()] ? Math.fround(x) : Math.fround(mathy0(0.000000000000001, Math.fround(x)))))))), ( + Math.exp(( + y)))))))) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[undefined, {}, undefined,  /x/ , {}, 2**53+2, {}, {}, 2**53+2,  /x/ , 2**53+2, undefined, {},  /x/ , 2**53+2, undefined,  /x/ , 2**53+2, undefined, 2**53+2, 2**53+2, {}, 2**53+2,  /x/ , 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2,  /x/ ,  /x/ , undefined, {}, 2**53+2,  /x/ , {}, undefined,  /x/ , 2**53+2, 2**53+2, {}, 2**53+2, 2**53+2, 2**53+2, {},  /x/ , undefined, 2**53+2, {}, undefined, 2**53+2, undefined, undefined, 2**53+2, 2**53+2, {},  /x/ , undefined,  /x/ , undefined, undefined, {}, undefined,  /x/ , undefined,  /x/ , 2**53+2,  /x/ , undefined, 2**53+2]); ");
/*fuzzSeed-221406266*/count=1412; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.cosh(Math.max(((y >= x) !== (Math.max(y, x) ? (((y | 0) | (x | 0)) | 0) : y)), ( + Math.sin((Math.max(Math.min(( + y), ( + x)), y) | 0)))))); }); ");
/*fuzzSeed-221406266*/count=1413; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -536870913.0;\n    var i3 = 0;\n    var i4 = 0;\n    i3 = (i4);\n    {\n      d1 = (65537.0);\n    }\n    d0 = (((((((0x40bd622c))-(/*FFI*/ff(((d2)))|0))>>>((((d1)))+(i3)-(!((0xf94f665b) ? (0x85f51525) : (0xf1c0190))))) <= ((((0xfec20317)))>>>((((36028797018963970.0) + (9.671406556917033e+24)) > (+/*FFI*/ff())))))+((abs((0x1c251e5b))|0))-((((0x9a8d3ee8) % (((0xfea4c133))>>>((0xf9a5834d)))) | ((0xffffffff))) > ((((Float32ArrayView[(((0x14e0a046))+((0x7fffffff) <= (0x2d82acd9))) >> 2]))) ^ (-(-0x8000000))))));\n    return (((0xd1295201)))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x080000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, 1.7976931348623157e308, -0, -0x080000000, -(2**53-2), 0.000000000000001, Number.MAX_VALUE, -(2**53), -0x0ffffffff, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, Math.PI, 0, 0x100000001, -(2**53+2), -1/0, 1, 42, 2**53-2, -Number.MIN_VALUE, -0x100000001, -0x100000000, 0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1414; tryItOut(";");
/*fuzzSeed-221406266*/count=1415; tryItOut("i0 = new Iterator(v1, true);");
/*fuzzSeed-221406266*/count=1416; tryItOut("print(e0);");
/*fuzzSeed-221406266*/count=1417; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return ( ~ (( + (( + ( + ( + y))) | ( + (Math.min(-0, ((-(2**53+2) && ( + ( ~ ( + x)))) >>> 0)) >>> 0)))) | 0)); }); ");
/*fuzzSeed-221406266*/count=1418; tryItOut("mathy1 = (function(x, y) { return Math.exp(mathy0(( + ( ~ mathy0((mathy0(Math.pow(x, x), (Math.cbrt(x) >>> 0)) >>> 0), (Math.atan(x) | 0)))), mathy0(mathy0(Math.max((Math.fround(Math.tan(Math.fround(-Number.MAX_SAFE_INTEGER))) | 0), ( + x)), Math.clz32(y)), ( + Math.pow(-1/0, Math.fround((y % Math.fround(y)))))))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x100000000, 42, 1, 0x080000000, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, -0x100000001, 0x100000001, -(2**53), -0x0ffffffff, -0, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, 0x07fffffff, -0x080000001, -0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 2**53+2, 0/0, 1/0, -(2**53-2), Math.PI, -1/0, 0]); ");
/*fuzzSeed-221406266*/count=1419; tryItOut("\"use strict\"; switch(function shapeyConstructor(paepyq){\"use strict\"; if (paepyq) Object.defineProperty(this, \"isArray\", ({writable: false}));if ( /x/g ) this[\"callee\"] = c;delete this[\"callee\"];this[\"callee\"] = new RegExp(\"(^)\\\\3{0,}|\\\\uA1b4+^|\\\\D+?(?:[^])[^]|[^\\\\w\\u0001-\\\\u00B9]|^|\\\\2*\", \"gyi\");for (var ytqxdwbop in this) { }if (paepyq) delete this[\"isSafeInteger\"];{ print(\"\\uDC77\"); } return this; }(x = x) && (x && x)) { default: break; break;  }");
/*fuzzSeed-221406266*/count=1420; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(( + mathy0(( + (Math.pow(Math.fround(Math.imul((x ? y : Math.imul(Math.trunc((x >>> 0)), (y | 0))), ((y | -0x100000000) | 0))), (( ! mathy0(y, ( - Math.fround(y)))) >>> 0)) >>> 0)), ((((Math.fround(x) === Math.max(Math.imul(y, x), y)) | 0) && ((x < (Math.sqrt(-Number.MAX_SAFE_INTEGER) >> -0)) | 0)) | 0))), Math.log10(( + Math.fround(( ! Math.fround(( + ( - x)))))))); }); testMathyFunction(mathy1, [-0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, -0, -0x0ffffffff, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 0/0, 1.7976931348623157e308, 0x07fffffff, 0x080000001, -0x080000001, -(2**53), Number.MIN_VALUE, Math.PI, 1, -1/0, 0, -(2**53+2), 42, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 1/0, -0x100000000, 0x100000001, 2**53-2, 2**53+2, 0.000000000000001, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1421; tryItOut("mathy4 = (function(x, y) { return (((( - -0x100000001) >>> 0) < (((Math.atan2(Math.fround(y), (mathy1((Math.clz32((( + x) | 0)) | 0), x) >>> 0)) >>> 0) ? (Math.atan(Math.fround(y)) >>> 0) : mathy1((Math.pow(( + x), (( + Math.atan2((x | 0), ( + x))) >>> 0)) >>> 0), y)) >>> 0)) / (Math.imul(mathy0((y >>> 0), y), ( ~ ( + ( + ( ! y))))) % (( + ( + ( ! (Math.sinh(y) | 0)))) ? (Math.cos((-(2**53) - (((-Number.MIN_SAFE_INTEGER >>> 0) >> (x >>> 0)) >>> 0))) >>> 0) : ( + Math.max(((x <= y) | 0), (((x >>> 0) , -0x07fffffff) >>> 0)))))); }); testMathyFunction(mathy4, [1/0, -0, 42, 2**53, -0x080000001, -(2**53+2), 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 2**53-2, Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, 0x07fffffff, Number.MIN_VALUE, -1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, -(2**53-2), 0x080000001, 0, 1, -0x100000001, -(2**53), Math.PI, 0/0, 0x0ffffffff]); ");
/*fuzzSeed-221406266*/count=1422; tryItOut("\"use strict\"; e2.has(b2);");
/*fuzzSeed-221406266*/count=1423; tryItOut("i1 = new Iterator(b0, true);");
/*fuzzSeed-221406266*/count=1424; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + ( ~ (( - Math.fround(y)) >>> 0))) | 0); }); testMathyFunction(mathy0, [0x0ffffffff, 2**53, -Number.MIN_VALUE, 1/0, 1, Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, 0x100000001, -(2**53+2), Number.MIN_VALUE, 0.000000000000001, 0x080000000, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 0x080000001, 2**53-2, 42, 0x07fffffff, -(2**53-2), 2**53+2, 0, -Number.MAX_VALUE, -0x100000001, -0x100000000, 0x100000000, -(2**53), Math.PI, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1425; tryItOut("testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, 0x40000000, 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-221406266*/count=1426; tryItOut("\"use strict\"; Object.defineProperty(this, \"this.v1\", { configurable: false, enumerable: false,  get: function() {  return Array.prototype.some.apply(this.a0, [(function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((0x539134af) >= (0xc49173ee));\n    return ((-((0xffffffff) <= ((((-35184372088832.0) > (4194305.0)))>>>((((0x8463a680) ? (0x71870f6f) : (-0x8000000)) ? (/*FFI*/ff(((-1.03125)))|0) : ((140737488355327.0) <= (-134217729.0))))))))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var wbfbsx = b < NaN; (String)(); })}, new ArrayBuffer(4096))]); } });");
/*fuzzSeed-221406266*/count=1427; tryItOut("/*oLoop*/for (var gyztwo = 0; gyztwo < 2; ++gyztwo) { t2[16] = b1; } ");
/*fuzzSeed-221406266*/count=1428; tryItOut("twocse([[]], \"\\u0797\");/*hhh*/function twocse(\u000cx){;}");
/*fuzzSeed-221406266*/count=1429; tryItOut("g2.offThreadCompileScript(\"for(let y in 26) this.i1.next();\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: timeout(1800) }));");
/*fuzzSeed-221406266*/count=1430; tryItOut("mathy4 = (function(x, y) { return Math.log2((( + (Math.clz32((( ! (x | 0)) | 0)) >>> 0)) | 0)); }); testMathyFunction(mathy4, [-(2**53), 2**53-2, -0x100000000, -1/0, 0x07fffffff, -(2**53+2), -Number.MAX_VALUE, 0x100000001, 2**53, 1.7976931348623157e308, 0x080000001, 1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, -(2**53-2), 1, Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, -0, -0x080000000, -0x07fffffff, 0.000000000000001, 0/0, 0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1431; tryItOut("testMathyFunction(mathy3, [0/0, 0, Math.PI, -0x100000001, -Number.MIN_VALUE, 2**53, -(2**53-2), 1, 1/0, 2**53-2, -1/0, 0x100000001, -0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, 0x080000000, 2**53+2, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, 42, -0, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -0x080000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-221406266*/count=1432; tryItOut("mathy4 = (function(x, y) { return ((( - Math.fround((((Math.hypot((y >>> 0), ( + x)) | 0) >>> 0) > y))) >>> 0) - Math.abs(mathy1(Math.sin((( + Math.imul(Math.fround((Math.max((x >>> 0), (x >>> 0)) >>> 0)), x)) | 0)), x))); }); testMathyFunction(mathy4, [0.000000000000001, 42, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 0x080000001, 0x07fffffff, Number.MAX_VALUE, -0x100000000, -0x0ffffffff, -0x080000001, 0x100000000, -0x100000001, 1.7976931348623157e308, 2**53, 0/0, -0, 2**53-2, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1, Math.PI, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 2**53+2, 0x080000000, -1/0, -(2**53), -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000000, -(2**53+2), 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1433; tryItOut("a0.shift(b2, t2, f2);");
/*fuzzSeed-221406266*/count=1434; tryItOut("\"use strict\"; m1.set(f1, o2);");
/*fuzzSeed-221406266*/count=1435; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.tan((Math.hypot(Math.cosh((( + Math.asinh(( + (Math.tan(2**53) || y)))) | 0)), Math.expm1(mathy3(( ! -(2**53-2)), (Math.max(Math.fround(Math.fround(Math.cos(Math.fround(y)))), 0x080000000) >>> 0)))) | 0))); }); testMathyFunction(mathy5, [-(2**53), 1, 1/0, 2**53, Math.PI, 0x100000001, -0x100000000, 0/0, 0x080000001, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, 2**53-2, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, -(2**53+2), Number.MIN_VALUE, -0x080000000, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, 0, 0.000000000000001, -0, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-221406266*/count=1436; tryItOut("mathy0 = (function(x, y) { return Math.tan(Math.min(Math.fround((((Math.exp(((Math.pow((x >>> 0), (x >>> 0)) >>> 0) | 0)) | 0) | Math.fround(Math.hypot(0x100000001, x))) >>> 0)), (((( + Math.imul(( + x), (((y || Math.fround(x)) | 0) | 0))) >>> 0) ? ((( + x) <= ( + Math.acos(y))) >>> 0) : ( + Math.sqrt((Math.clz32((Number.MIN_VALUE >>> 0)) >>> 0)))) >>> 0))); }); testMathyFunction(mathy0, [2**53+2, Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0x080000000, -0x07fffffff, -0x080000001, 42, 2**53, 0, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, -0x100000001, -0x080000000, -0x0ffffffff, -1/0, 0x07fffffff, Number.MAX_VALUE, 0.000000000000001, -(2**53+2), Math.PI, 0x100000000, -(2**53), 0x080000001, -0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1, 1/0, -Number.MIN_VALUE, -0, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-221406266*/count=1437; tryItOut("mathy2 = (function(x, y) { return ( + (( + Math.fround(((Math.max((Math.fround((Math.fround((mathy0(Math.fround(y), Math.fround(y)) | 0)) ? Math.fround(y) : Math.fround(-0x080000000))) >>> 0), (Math.fround(( ~ -0x0ffffffff)) >>> 0)) >>> 0) >> ((x ? ( + Math.fround(Math.pow(Math.fround(y), Math.fround(( + (Number.MIN_VALUE | ( - y))))))) : x) >>> 0)))) !== (mathy0(mathy1(( + Math.acos(( + x))), Math.imul(( + Math.tanh(( + y))), (((mathy1(((y << x) >>> 0), (-0x100000000 >>> 0)) >>> 0) >>> 0) | Math.log1p(y)))), Math.sqrt(Math.atan2((Math.hypot((Math.expm1(( + -Number.MAX_VALUE)) >>> 0), (y | 0)) | 0), ( + ( - x))))) | 0))); }); ");
/*fuzzSeed-221406266*/count=1438; tryItOut("let g2.e2 = new Set;");
/*fuzzSeed-221406266*/count=1439; tryItOut("mathy4 = (function(x, y) { return ( + ( ! ( + Math.atanh(Math.min(( + Math.fround(( ! ( + 0x0ffffffff)))), Math.atanh(Math.fround(Math.sign(Math.fround(( + Math.asinh(( + x)))))))))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 2**53, 0x080000001, Number.MAX_VALUE, -(2**53+2), -Number.MAX_VALUE, -0x100000000, 1, 2**53+2, 2**53-2, 0x0ffffffff, -(2**53), -0x07fffffff, 42, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, -(2**53-2), -0x080000001, 0x080000000, 0/0, -1/0, 0x100000000, 0.000000000000001, 1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1440; tryItOut("/*vLoop*/for (let ebwvko = 0, ( /x/ .__defineGetter__(\"d\", Math.tanh)); ebwvko < 50; ++ebwvko) { w = ebwvko; v0 = evaluate(\"/*ODP-1*/Object.defineProperty(f0, \\\"__proto__\\\", ({value: (4277), writable: false, configurable: true, enumerable: (x % 20 == 10)}));\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 57 == 56), noScriptRval: true, sourceIsLazy: (x % 2 != 1), catchTermination: (w % 2 != 0) })); } ");
/*fuzzSeed-221406266*/count=1441; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x080000001, -0x07fffffff, 0x0ffffffff, 2**53+2, 0/0, 42, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 1.7976931348623157e308, 1/0, -0, -1/0, -Number.MIN_VALUE, 0, Math.PI, -(2**53-2), -(2**53+2), 0x080000001, -(2**53), -0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, -0x0ffffffff, 0x07fffffff, 1, 2**53, Number.MAX_VALUE, 0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1442; tryItOut("mathy3 = (function(x, y) { return (mathy0(( + Math.max(Math.pow(Math.fround(( ~ (y | ( + Math.log10(Math.atan2(1, x)))))), ((( + Math.hypot(((x >>> 0) || (42 >>> 0)), Math.imul((y | 0), y))) >>> x) == Math.exp(x))), ( - (((y >>> 0) , ( + Number.MAX_VALUE)) >>> 0)))), (Math.log((Math.imul(((Math.fround((Math.fround(x) * Math.fround(( - x)))) | Math.atan((Math.tanh((x >>> 0)) | 0))) >>> 0), Math.ceil(Math.pow(( + 2**53), -(2**53-2)))) >>> 0)) | 0)) >>> 0); }); testMathyFunction(mathy3, [0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -0, 0, -Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, 0x080000000, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, 42, 0x100000001, 2**53-2, -1/0, 2**53+2, 1, 0/0, 0x07fffffff, Math.PI, -0x100000001, 0x0ffffffff, -(2**53+2), 0.000000000000001, 1/0, -0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=1443; tryItOut("o1.v1 = undefined;");
/*fuzzSeed-221406266*/count=1444; tryItOut("\"use strict\"; ");
/*fuzzSeed-221406266*/count=1445; tryItOut("/*hhh*/function ilmhwi(){null;}ilmhwi( /x/g );");
/*fuzzSeed-221406266*/count=1446; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(((( + (( + x) ^ ( + ( ~ ( + Math.hypot(x, Math.fround(Math.fround(y)))))))) <= ( - Math.atan(( + (-0x080000001 | 0))))) ? ( + Math.pow((( + 0) ** Math.trunc(Math.max((y >>> 0), y))), ( + mathy1(Number.MAX_VALUE, ( + (x | 0)))))) : Math.pow(( ~ x), Math.hypot((Math.fround((Math.fround(1) === Math.fround(( + Math.atan2(( + (Math.fround(-Number.MAX_SAFE_INTEGER) & (y ? -0x07fffffff : -0x0ffffffff))), ( + Math.log(x))))))) | 0), Math.tan(Math.fround((Math.fround(-(2**53)) && Math.fround(1)))))))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 0x07fffffff, -(2**53), -(2**53+2), -(2**53-2), -0x100000001, 0x080000000, -0x0ffffffff, -0x080000001, 1, 2**53, 0.000000000000001, 0x100000001, 0, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, -0, Math.PI, -Number.MAX_SAFE_INTEGER, 42, 0/0, -0x07fffffff, 0x080000001, 0x100000000, -0x080000000, 0x0ffffffff, -Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-221406266*/count=1447; tryItOut("g2 + '';");
/*fuzzSeed-221406266*/count=1448; tryItOut("x = (\u3056) = c &= x, x = (this).call( /x/g , false), vbgond, jvfogc, x;this.v2 = Object.prototype.isPrototypeOf.call(b1, f2);");
/*fuzzSeed-221406266*/count=1449; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return (Math.fround(Math.cosh(Math.fround(Math.min(y, Math.fround(Math.expm1(x)))))) % (Math.sinh((Math.asin((Math.fround(-(2**53)) || x)) <= Math.imul(Math.pow(y, ( + ((x | 0) % (( + (( + y) ** ( + -1/0))) | 0)))), ( - (0x100000001 >>> 0))))) >>> 0)); }); testMathyFunction(mathy5, [0x0ffffffff, -(2**53), 1.7976931348623157e308, 0, -Number.MAX_VALUE, -0x100000000, 0x07fffffff, 2**53, 0/0, 0.000000000000001, -0x080000000, 0x100000001, 1/0, 0x080000001, Number.MAX_VALUE, -0, 42, -0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, -0x100000001, -0x07fffffff, -0x080000001, 0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1450; tryItOut("\"use strict\"; ");
/*fuzzSeed-221406266*/count=1451; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - ( + (( - (( + y) >>> 0)) | 0))) >>> 0); }); testMathyFunction(mathy5, [-(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, -0x080000001, 1.7976931348623157e308, -(2**53+2), -Number.MIN_VALUE, 1, -0x080000000, 0x0ffffffff, 42, Number.MAX_VALUE, 2**53-2, Math.PI, -0x0ffffffff, -0x100000001, 0x07fffffff, -1/0, 2**53, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 1/0, 0/0, -(2**53-2), 0, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-221406266*/count=1452; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1453; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, -0x100000000, -0x080000000, -0x080000001, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, Number.MAX_VALUE, -1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 1, -0x100000001, 1/0, -(2**53-2), 0/0, 0x100000001, -Number.MIN_VALUE, 0x080000001, -0, 2**53+2, -(2**53), 2**53-2, 0, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 42, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1454; tryItOut("/*hhh*/function etmray(){a0.unshift(new RegExp(\"\\\\2|[^]+\\\\cC?\\u00a3*|\\\\B\", \"i\"));}/*iii*/Object.prototype.watch.call(i0, \"every\", (function() { try { o0.b1 = s2; } catch(e0) { } try { v0 = Array.prototype.reduce, reduceRight.call(a1, f0, i2, t2, g1); } catch(e1) { } a0.valueOf = (function() { try { i2.next(); } catch(e0) { } try { v2 = evaluate(\"a0 = Array.prototype.concat.apply(o2.a1, [this.a2, t0, g2.h0]);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 == 2), sourceIsLazy: eval, catchTermination: false })); } catch(e1) { } v1 = (p2 instanceof g0); return s2; }); return b2; }));");
/*fuzzSeed-221406266*/count=1455; tryItOut("\"use strict\"; v1 = evaluate(\"g2.v0 = (t1 instanceof g0);\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce:  \"\" , noScriptRval: true, sourceIsLazy: (x % 8 != 0), catchTermination: true }));function w(window, c)nullv2 = evaluate(\"this.a0.unshift(p0);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 3 == 0), noScriptRval: (x % 11 != 0), sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-221406266*/count=1456; tryItOut("\"use strict\"; e0.add(g2);");
/*fuzzSeed-221406266*/count=1457; tryItOut("\"use strict\"; let z = (4277);selectforgc(o2);");
/*fuzzSeed-221406266*/count=1458; tryItOut("print(x);print(y);");
/*fuzzSeed-221406266*/count=1459; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[new Number(1.5), new Number(1.5), function(){}, function(){}, new Boolean(true), function(){}, -0x07fffffff, new Boolean(true), function(){}, new Number(1.5), new Boolean(true), new Number(1.5), new Boolean(true), function(){}, new Boolean(true), new Boolean(true), new Boolean(true), -0x07fffffff, function(){}, {x:3}, new Boolean(true), -0x07fffffff, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), function(){}, -0x07fffffff, -0x07fffffff, new Number(1.5), function(){}, function(){}, new Number(1.5)]); ");
/*fuzzSeed-221406266*/count=1460; tryItOut("i1.next();");
/*fuzzSeed-221406266*/count=1461; tryItOut("e2.delete(h2);");
/*fuzzSeed-221406266*/count=1462; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy1((Math.sqrt(( + (Math.ceil(y) >= Math.fround(y)))) >>> 0), Math.acosh(( + (((x - Number.MIN_SAFE_INTEGER) - Math.fround(Math.hypot((mathy1(y, 0.000000000000001) | 0), -0x100000001))) | 0)))); }); ");
/*fuzzSeed-221406266*/count=1463; tryItOut("mathy2 = (function(x, y) { return (mathy1(((Math.sqrt((((((x >>> 0) % ((Math.max(x, -0x080000000) >> ((0x0ffffffff >>> 0) >>> (x >>> 0))) >>> 0)) | 0) ? (Math.max((Math.log(x) | 0), (( + (( + 0/0) ? ( + ( + y)) : x)) | 0)) | 0) : ((( ~ (Math.imul(((( - (x | 0)) | 0) >>> 0), x) >>> 0)) | 0) | 0)) >>> 0)) | 0) >>> 0), (Math.pow(Math.trunc(Math.hypot(x, ((x || x) << (((-Number.MAX_VALUE | 0) <= (y | 0)) | 0)))), Math.atan((x / Math.fround((Math.fround(-(2**53)) || Math.fround(y)))))) >>> 0)) | 0); }); testMathyFunction(mathy2, [2**53-2, Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, Number.MIN_VALUE, -0x080000001, -0, -Number.MIN_VALUE, 2**53+2, -(2**53), 0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0, 0x07fffffff, -0x100000000, 1/0, 2**53, 0/0, -(2**53+2), -1/0, -0x07fffffff, 0x080000001, -(2**53-2), Math.PI, 0x100000000, 42]); ");
/*fuzzSeed-221406266*/count=1464; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\nfor (var p in h0) { try { g2.offThreadCompileScript(\"function f1(f0)  { return f0 } \"); } catch(e0) { } try { v1 = g0.runOffThreadScript(); } catch(e1) { } try { selectforgc(o0); } catch(e2) { } m0.has((true.watch(new String(\"-17\"), function  z (b) { \"use strict\"; yield  /x/g  } ))); }\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -268435457.0;\n    {\n      i1 = (!(\u3056 = Proxy.createFunction(({/*TOODEEP*/})(true), \"\\uB370\")));\n    }\n    d2 = (d0);\n    return (((-0x775fc9c)-(-0x8000000)-((0x4d66f0d3))))|0;\n    d2 = (-1048577.0);\n    return (((0x8800af86)+((-0x8000000))-(0x268818d2)))|0;\n  }\n  return f; })(this, {ff: function(y) { t1 = x; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1, 42, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, 0x07fffffff, 2**53, -0, 0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), -Number.MAX_VALUE, 0, 1.7976931348623157e308, Math.PI, -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, Number.MIN_VALUE, -0x100000000, 0/0, 2**53+2, -(2**53), 0x080000001, 2**53-2, Number.MAX_VALUE]); ");
/*fuzzSeed-221406266*/count=1465; tryItOut("\"use asm\"; Array.prototype.pop.call(o0.g2.a1);");
/*fuzzSeed-221406266*/count=1466; tryItOut("testMathyFunction(mathy2, [undefined, (function(){return 0;}), '\\0', null, (new Number(-0)), /0/, '/0/', (new Number(0)), '', false, ({toString:function(){return '0';}}), (new String('')), 0, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), true, -0, '0', NaN, [0], 0.1, (new Boolean(true)), (new Boolean(false)), [], 1]); ");
/*fuzzSeed-221406266*/count=1467; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1468; tryItOut("(z);\nObject.defineProperty(this, \"this.v1\", { configurable: (x % 6 == 2), enumerable:  /x/g ,  get: function() {  return evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: false })); } });\n");
/*fuzzSeed-221406266*/count=1469; tryItOut("\"use strict\"; ;");
/*fuzzSeed-221406266*/count=1470; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1471; tryItOut("\"use strict\"; \"\\uD5F9\";");
/*fuzzSeed-221406266*/count=1472; tryItOut("/*RXUB*/var r = x; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-221406266*/count=1473; tryItOut("/* no regression tests found */");
/*fuzzSeed-221406266*/count=1474; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1475; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[let (z) \"\\uBEE2\", let (z) \"\\uBEE2\", x]) { var gflzzg = new SharedArrayBuffer(0); var gflzzg_0 = new Int32Array(gflzzg); gflzzg_0[0] = -27; var gflzzg_1 = new Uint8ClampedArray(gflzzg); gflzzg_1[0] = -6; v2 = Object.prototype.isPrototypeOf.call(t1, v2); }");
/*fuzzSeed-221406266*/count=1476; tryItOut("return;");
/*fuzzSeed-221406266*/count=1477; tryItOut("\"use asm\"; ");
/*fuzzSeed-221406266*/count=1478; tryItOut("\"use strict\"; ;");
/*fuzzSeed-221406266*/count=1479; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( + (((( + mathy1(-Number.MAX_VALUE, y)) | 0) / ( + (Math.sin(x) >>> 0))) | 0)) >>> 0) - ( + ((((((-Number.MAX_SAFE_INTEGER | y) >>> 0) <= (( + Math.atan(( + (( + y) ** y)))) >>> 0)) >>> 0) / ( ! (Math.log2(Math.acosh(y)) | 0))) >>> 0))); }); testMathyFunction(mathy3, [2**53, 0x080000000, -(2**53+2), -0x080000000, Number.MAX_VALUE, -0x080000001, 42, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, 0x080000001, 0, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, 2**53-2, -0x0ffffffff, -0, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308, Number.MIN_VALUE, 1, 0x0ffffffff, 0x100000000, 2**53+2]); ");
/*fuzzSeed-221406266*/count=1480; tryItOut("for (var p in h0) { a2 = []; }");
/*fuzzSeed-221406266*/count=1481; tryItOut("v0 = o0.a0.length;");
/*fuzzSeed-221406266*/count=1482; tryItOut("t1 = m1.get(a0);");
/*fuzzSeed-221406266*/count=1483; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.ceil(Math.fround(( ~ Math.fround(( ~ -Number.MIN_VALUE))))); }); ");
/*fuzzSeed-221406266*/count=1484; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul((( ~ (((( ! ((Math.cbrt(( + Math.acos(( + y)))) >>> 0) | 0x080000001)) >>> 0) % ((((Math.fround(Math.sin(x)) >>> 0) <= y) , (Math.sqrt(( + Math.cbrt(( + x)))) | 0)) | 0)) >>> 0)) >>> 0), ( + ( ~ ( + ( ~ (( ~ y) && x)))))); }); ");
/*fuzzSeed-221406266*/count=1485; tryItOut("\"use strict\"; M:with({d: \"\\u2F68\"}){x = g2; }");
/*fuzzSeed-221406266*/count=1486; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 4503599627370497.0;\n    var d4 = -9.44473296573929e+21;\n    d4 = (d4);\n    d4 = (d3);\n    {\n      (Float64ArrayView[((0xc409188a) % (0xc0c53db4)) >> 3]) = ((-((536870911.0))));\n    }\n    i1 = ((0x60b9dc41) ? (0x2d2bc063) : (i1));\n    return +((18014398509481984.0));\n  }\n  return f; })(this, {ff: ~this.__defineSetter__(\"w\", /(?!.{3,})?/i)\u0009.bold}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53+2), 0/0, -0x100000000, -Number.MAX_VALUE, -1/0, 0x0ffffffff, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 0x100000001, 0, -0x080000001, -0x0ffffffff, 2**53-2, 0x080000000, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -0, 1, -0x100000001, 1/0, -(2**53-2), 0x07fffffff]); ");
/*fuzzSeed-221406266*/count=1487; tryItOut("\"use strict\"; /*oLoop*/for (let drzrrx = 0,  /x/g ; drzrrx < 80; ++drzrrx) { v1 = t0.length; } \nh2.has = f2;\n");
/*fuzzSeed-221406266*/count=1488; tryItOut("testMathyFunction(mathy0, [Math.PI, -(2**53+2), 0x0ffffffff, 42, 2**53, -0x080000000, -Number.MAX_VALUE, 0x07fffffff, 0x100000001, 1/0, Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, 1, -(2**53), -(2**53-2), -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0.000000000000001, 2**53-2, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0x080000000, 0/0, 0, 0x080000001, -0x080000001, -0]); ");
/*fuzzSeed-221406266*/count=1489; tryItOut("\"use strict\"; h2.enumerate = (function() { try { /*MXX3*/g2.ArrayBuffer.prototype.slice = g0.ArrayBuffer.prototype.slice; } catch(e0) { } try { for (var p in p2) { try { h1.get = f0; } catch(e0) { } try { v1 = Infinity; } catch(e1) { } try { Array.prototype.reverse.apply(a2, [t0, o0.s2]); } catch(e2) { } v0 = g2.runOffThreadScript(); } } catch(e1) { } try { v0 = (e2 instanceof g1.i0); } catch(e2) { } for (var v of o2.e0) { m2.delete(m2); } return a1; });a1 = Proxy.create(h1, this.f1);this.g0.p0 + s1;");
/*fuzzSeed-221406266*/count=1490; tryItOut("b0 + o1.e2;");
/*fuzzSeed-221406266*/count=1491; tryItOut("mathy4 = (function(x, y) { return ((Math.fround((Math.fround((( ~ Math.fround((x | x))) | 0)) ** Math.fround((Math.max(y, (x >>> 0)) >>> 0)))) ? (Math.asinh((y * (Math.fround(y) & Math.fround(-Number.MAX_SAFE_INTEGER)))) >>> 0) : ( + (Math.log2(( + y)) | (y >>> 0)))) - ((Math.fround(Math.max(((( ~ y) / y) >>> 0), ( + Math.sinh(( + Math.min(y, (y != x))))))) >>> (Math.tan((y >>> (( + Math.hypot(( + y), ( + y))) >>> 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [0x080000000, 0.000000000000001, 2**53, -(2**53+2), -0x07fffffff, -1/0, -0, -0x080000001, 0/0, 1, Math.PI, Number.MIN_VALUE, -0x100000000, -(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -0x080000000, 0x100000000, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 1.7976931348623157e308, 2**53+2, -0x100000001, -Number.MAX_VALUE, 1/0, 0x080000001, -0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-221406266*/count=1492; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[((Uint8ArrayView[((/*FFI*/ff()|0)) >> 0])) >> 2]) = ((+(0.0/0.0)));\n/* no regression tests found */    {\n      d1 = (140737488355328.0);\n    }\n    d1 = (+(++\u3056));\n    d1 = (+((((((i0)+((((0xb012bfeb))>>>((0xfbd72551))))) ^ ((0x1b3aaf15)+(0xfc1b4673)+((~((0x3e06e851)))))))-(0xfb2996ce)) & ((((((-((262143.0))) < (((-524288.0)) / ((17.0)))))>>>((/*FFI*/ff(((+((536870911.0)))), ((16384.0)), ((-257.0)), ((-9223372036854776000.0)), ((1.2089258196146292e+24)), ((-17179869185.0)), ((-68719476735.0)), ((-2.0)), ((129.0)), ((-35184372088832.0)), ((-33554433.0)), ((-2305843009213694000.0)), ((-32769.0)), ((-4611686018427388000.0)), ((-129.0)), ((-0.0625)), ((-3.8685626227668134e+25)), ((-17592186044416.0)), ((6.189700196426902e+26)))|0)+(0xfafd78c7))))+(((((((0xfb38008e)) & ((0xf83223d7))) < (0x6e93d84))) ^ ((0x821889b0)+(i0)))))));\n    return +((function shapeyConstructor(sluygp){\"use strict\"; this[\"parseFloat\"] = encodeURIComponent;{ m1 + ''; } this[\"values\"] = new String('');for (var ytqzpngvh in this) { }if ((objectEmulatingUndefined).call(window, )) { { void 0; bailAfter(235); } ; } return this; }.prototype));\n  }\n  return f; })(this, {ff: Math.min(-0, 10).padEnd}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0, 2**53-2, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0, -(2**53), 0x080000000, -0x080000000, -1/0, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0x0ffffffff, 1/0, -0x100000001, -0x0ffffffff, 2**53, -(2**53-2), 0x080000001, -0x100000000, -0x080000001, 1, 42, -(2**53+2), 0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1493; tryItOut("mathy3 = (function(x, y) { return ( ~ mathy1(( + ((Math.min(( + y), (42 | 0)) | 0) ? x : (((y >>> 0) ** (((((-0x080000000 >>> 0) || (y >>> 0)) | 0) >>> (y >>> 0)) >>> 0)) >>> 0))), ( + ( + Math.imul(y, (( - Math.atan(( + y))) | 0)))))); }); ");
/*fuzzSeed-221406266*/count=1494; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.atan(Math.sinh((Math.imul((Math.pow(x, y) ? y : (((( - x) >>> 0) ? (Math.atan2(x, Math.clz32((Number.MAX_VALUE >>> 0))) >>> 0) : (y >>> 0)) >>> 0)), ( + ( + ( - ( + ( ! x)))))) | 0)))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 0x080000001, -1/0, 1/0, 0/0, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -0x0ffffffff, 0x100000000, -Number.MIN_VALUE, Math.PI, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), 1, -0, -0x080000000, 2**53+2, 0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -0x07fffffff, 0]); ");
/*fuzzSeed-221406266*/count=1495; tryItOut("a2.push(o1, o1, t1, p0);");
/*fuzzSeed-221406266*/count=1496; tryItOut("");
/*fuzzSeed-221406266*/count=1497; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy3(( + mathy4(( + Math.pow(( + (Math.atan2((y | 0), Math.asinh(2**53)) | 0)), Math.imul(x, ( + (( + Math.trunc(0x100000000)) !== y))))), (y >>> x))), (((Math.acos((( - (x | 0)) >>> 0)) | (Math.round(Math.atan2(0x080000001, Math.fround(Math.imul(x, x)))) | 0)) | 0) > (( + (( + ( - ((Math.imul(Math.max(mathy4(x, -0x07fffffff), Math.atan2(y, y)), (( ! 0.000000000000001) | 0)) | 0) >>> 0))) | 0)) | 0))); }); testMathyFunction(mathy5, [1, null, 0, ({toString:function(){return '0';}}), (new Number(0)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), NaN, '', '/0/', (new Boolean(false)), '0', [0], (new String('')), 0.1, ({valueOf:function(){return '0';}}), true, (new Boolean(true)), (new Number(-0)), /0/, [], (function(){return 0;}), undefined, false, '\\0', -0]); ");
/*fuzzSeed-221406266*/count=1498; tryItOut("a1.unshift((x = ({}.a = \"\\uA8D0\")), p2, h1);");
/*fuzzSeed-221406266*/count=1499; tryItOut("/*oLoop*/for (var cgpliv = 0; cgpliv < 66; ++cgpliv) { for (var p in o1.s0) { try { for (var p in f0) { try { /*MXX3*/g1.Array.prototype.unshift = g1.Array.prototype.unshift; } catch(e0) { } /*MXX3*/g0.g1.Set.prototype.entries = g1.Set.prototype.entries; } } catch(e0) { } try { a1 = a0.slice(11, NaN); } catch(e1) { } try { delete m0[\"substring\"]; } catch(e2) { } print(uneval(e0)); } } ");
/*fuzzSeed-221406266*/count=1500; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-(2**53-2), -Number.MAX_VALUE, -0x0ffffffff, 0/0, 42, -Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, 1.7976931348623157e308, 0x100000001, -0x100000001, 0x080000000, 0x100000000, 2**53+2, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -1/0, -(2**53), -0, Number.MIN_SAFE_INTEGER, Math.PI, 1, -0x080000001, 1/0, -0x100000000, -0x07fffffff, 0]); ");
/*fuzzSeed-221406266*/count=1501; tryItOut("\"use strict\"; /*vLoop*/for (jbzxos = 0; jbzxos < 2; ++jbzxos) { e = jbzxos; g2.a0.pop(o1.m0); } \nconst skcmje, x, {} = (x-= /x/ ), kplfhm, anwvmw, nxpwug, z, x, x, e;/*RXUB*/var r = o1.g0.r2; var s = \"\\n\\ne\\u0acaR\"; print(uneval(r.exec(s))); print(r.lastIndex); \n");
/*fuzzSeed-221406266*/count=1502; tryItOut("");
/*fuzzSeed-221406266*/count=1503; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(Math.tan(Math.fround((Math.abs(( + y)) * ( ~ x)))))); }); testMathyFunction(mathy0, [-0x100000000, -0x080000000, -0x0ffffffff, 0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, 1, 0x07fffffff, -1/0, 2**53-2, -(2**53+2), 0x100000000, Number.MIN_VALUE, -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 42, 0x100000001, -(2**53), -0, 2**53, 0]); ");
/*fuzzSeed-221406266*/count=1504; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround((( + ( ! ( + ( + Math.trunc(y))))) ? Math.fround(Math.fround(( + Math.fround(( ! y))))) : Math.fround(( + Math.pow(( + ( + ( ! ( + mathy2(y, ( ~ Math.clz32(x))))))), ( + (Math.fround(( ! (Math.cosh(x) >>> 0))) ? (((( + Math.round(( + x))) >>> 0) - ( + (Math.imul(x, y) | 0))) >>> 0) : ( + mathy1((-Number.MIN_VALUE ? y : (y == y)), (Math.pow(( + (((( + Math.pow(( + y), ( + x))) | 0) - (y | 0)) | 0)), (x | 0)) | 0)))))))))); }); testMathyFunction(mathy4, /*MARR*/[0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF]); ");
/*fuzzSeed-221406266*/count=1505; tryItOut("{( /x/g ); }");
/*fuzzSeed-221406266*/count=1506; tryItOut("Array.prototype.forEach.apply(a1, [DataView.prototype.getInt32.bind(this.m1), e1, v2, a1]);");
/*fuzzSeed-221406266*/count=1507; tryItOut("/*ODP-2*/Object.defineProperty(s2, \"sign\", { configurable: Math.ceil(intern((/*UUV2*/(window.setPrototypeOf = window.toString)))), enumerable: eval(\"\\\"use strict\\\"; mathy3 = (function(x, y) { return Math.fround(( - ( + ( ! ( + ( ~ ( + (y ** Math.tanh(-(2**53-2)))))))))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53-2), 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53), -0x080000000, 1, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 0x0ffffffff, 2**53+2, Number.MAX_VALUE, 0x100000001, 0x100000000, -0x100000000, 0.000000000000001, 0x080000000, -0x07fffffff, 0/0, -(2**53+2), 0x07fffffff, -0, 2**53-2, 42, -0x100000001]); \", (p={}, (p.z = (4277))())), get: (function() { try { e0.toSource = (function() { for (var j=0;j<8;++j) { f2(j%3==0); } }); } catch(e0) { } try { Array.prototype.forEach.apply(a2, [(function() { try { i0 = a1.values; } catch(e0) { } e2.add(o0); return h0; })]); } catch(e1) { } try { ; } catch(e2) { } ((x >>= x))(-5) = a0[2]; return i1; }), set: (function() { try { Array.prototype.shift.apply(a2, []); } catch(e0) { } try { v2 = (f0 instanceof s2); } catch(e1) { } try { v1 = Object.prototype.isPrototypeOf.call(b0, b0); } catch(e2) { } v0 = t1.length; return h0; }) });Object.preventExtensions(o0);");
/*fuzzSeed-221406266*/count=1508; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return ( ~ ( + Math.fround(Math.cbrt(Math.fround(( + x)))))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), 0x07fffffff, -1/0, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 0x080000000, Math.PI, 0x080000001, 0.000000000000001, -(2**53+2), -0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, -0, -0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, 1/0, 0/0, 0, Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 2**53, 0x100000001]); ");
/*fuzzSeed-221406266*/count=1509; tryItOut("const a = (( /x/  < /(?=\\3|([\\d\\x3e\\D])*+?|(?=$(?=[^]))|\\B{2})/i.e = (4277)));var r0 = 6 / a; var r1 = r0 & 1; x = 4 ^ r1; var r2 = r1 - r1; var r3 = x ^ r0; var r4 = r0 ^ r1; r1 = r2 % r4; r3 = r3 | a; var r5 = x + 0; var r6 = r4 | 7; var r7 = r6 + r0; var r8 = 6 | r0; var r9 = 6 / r0; var r10 = x % r1; var r11 = r9 ^ r10; r10 = 1 / r6; var r12 = 0 + r1; var r13 = 5 ^ r11; var r14 = a + r1; var r15 = r7 + 8; r6 = 9 * r4; var r16 = 5 % r11; var r17 = 3 + r2; var r18 = r17 % 5; var r19 = 8 - r18; r9 = r1 * r19; var r20 = r1 % r5; var r21 = r15 ^ 4; r1 = a + x; r9 = r12 % 2; var r22 = r8 | r6; var r23 = r21 + r6; var r24 = r12 / 3; r19 = r13 + r7; var r25 = r14 * 2; var r26 = 3 | r1; a = 2 & 2; r15 = 8 + 6; var r27 = 4 % r8; var r28 = r24 / r26; x = r20 - r23; var r29 = r21 & r8; var r30 = x + r18; var r31 = r7 / r7; var r32 = r3 | r0; var r33 = r21 * r14; r26 = 1 ^ r32; var r34 = r28 % r18; r8 = r32 + r0; var r35 = r32 & x; r23 = 1 - r12; var r36 = r27 % 0; var r37 = r20 - r3; var r38 = r8 + r14; var r39 = r15 * r21; r27 = 8 - r11; a = x | 2; r22 = r19 ^ 1; var r40 = r27 * r21; var r41 = r12 & r13; r9 = r21 - r41; var r42 = 1 % r29; var r43 = r19 | r35; var r44 = r42 * r37; var r45 = r32 + r26; r31 = r23 | r28; var r46 = 7 * r34; var r47 = 6 ^ 6; var r48 = r11 + r47; var r49 = r2 - r48; var r50 = 8 | 3; var r51 = r3 / 5; var r52 = r29 % 4; var r53 = 0 / r17; var r54 = r25 ^ r27; var r55 = 7 | a; var r56 = 2 & 3; var r57 = r9 | 0; print(r22); r19 = 8 % r29; r49 = r46 | r31; var r58 = 9 * r31; var r59 = r0 / 7; var r60 = 6 * r15; var r61 = 3 % 1; print(r49); var r62 = 9 * r43; r1 = 6 | r27; var r63 = 6 / 8; r46 = a * r5; var r64 = r10 ^ 2; var r65 = r55 - r14; var r66 = r25 | 0; var r67 = r64 * 6; var r68 = r4 % 0; r53 = 9 ^ r53; var r69 = r68 | r11; var r70 = r53 * 1; var r71 = r37 | r50; var r72 = r40 | r21; var r73 = r15 ^ r21; var r74 = r14 * r10; var r75 = r17 ^ r62; var r76 = 7 | 5; print(r47); var r77 = r30 - r57; var r78 = r4 ^ 6; var r79 = r63 / r60; r6 = 6 * 3; r6 = r9 ^ r2; var r80 = r29 & r38; var r81 = r8 - 9; print(r74); r52 = r76 % r40; var r82 = r14 | r28; var r83 = 6 % 5; var r84 = r31 & r81; a = r2 * r54; var r85 = r7 & r37; var r86 = r28 & r81; var r87 = 6 + 5; var r88 = 6 % r76; r57 = r31 * 1; var r89 = r43 | 8; var r90 = r73 | r10; r71 = 4 + r61; var r91 = r2 * r73; var r92 = r2 | r25; var r93 = r0 / 2; var r94 = 4 - r27; var r95 = r88 * r42; var r96 = 9 | r42; print(r6); var r97 = r35 % r66; r32 = 6 / 2; var r98 = 8 / r75; var r99 = 4 & 1; var r100 = 1 | r48; var r101 = 7 & 1; r76 = 5 / r73; var r102 = r61 - r98; r67 = r40 + 4; var r103 = 9 ^ r14; print(r12); ");
/*fuzzSeed-221406266*/count=1510; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0(((Math.atan2(( - x), Math.max(Number.MIN_SAFE_INTEGER, -(2**53+2))) >>> (Math.log1p((x >>> 0)) >>> 0)) | 0), (Math.clz32((((((Math.round((y | 0)) | 0) >>> 0) / (( ! -(2**53-2)) >>> 0)) >>> 0) >>> 0)) >>> 0)) && ( + mathy0(Math.asin(((((Math.atan2((y | 0), (mathy0((-0 | 0), (x | 0)) | 0)) | 0) | 0) == (y | 0)) | 0)), ( + x)))); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-221406266*/count=1511; tryItOut("this.v0.toSource = (function() { try { i2.valueOf = Object.prototype.__lookupGetter__; } catch(e0) { } v2 = g2.runOffThreadScript(); return g1; });");
/*fuzzSeed-221406266*/count=1512; tryItOut("\"use strict\"; testMathyFunction(mathy0, [true, (new Boolean(true)), /0/, objectEmulatingUndefined(), 0, (new Number(0)), ({valueOf:function(){return '0';}}), undefined, [], false, (new Boolean(false)), (function(){return 0;}), ({valueOf:function(){return 0;}}), NaN, 0.1, (new Number(-0)), '0', '\\0', -0, ({toString:function(){return '0';}}), [0], '/0/', (new String('')), null, 1, '']); ");
/*fuzzSeed-221406266*/count=1513; tryItOut("\"use strict\"; x = linkedList(x, 76);");
/*fuzzSeed-221406266*/count=1514; tryItOut("v0 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 63 == 42), noScriptRval: (((void version(185))))(( /x/g  + x)), sourceIsLazy: (x % 6 != 4), catchTermination: false, element: o0, elementAttributeName: this.s0 }));");
/*fuzzSeed-221406266*/count=1515; tryItOut("mathy3 = (function(x, y) { return ((((Math.fround(Math.hypot(Math.fround(x), -Number.MAX_SAFE_INTEGER)) > Math.fround(( ! ( + ( ~ Math.fround((1.7976931348623157e308 | Math.fround(x)))))))) == Math.fround(mathy2((( + Math.hypot(( + y), ( + Math.fround((Math.fround(x) , Math.fround(((x >>> 0) != x))))))) >>> 0), (mathy1(y, ( + Math.acosh(( + y)))) >>> 0)))) == ( + Math.hypot(( + (((Math.asinh(Math.round(x)) >>> 0) == (( + x) >>> 0)) >>> 0)), ( + Math.imul(Math.fround(x), ( + y)))))) >>> 0); }); testMathyFunction(mathy3, [42, -0x080000001, 1/0, 0x0ffffffff, 2**53, -1/0, -0x0ffffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, -(2**53), 0x100000000, 1, -Number.MIN_SAFE_INTEGER, 0x080000001, 0, 2**53+2, -Number.MAX_VALUE, 0x080000000, 2**53-2, 0.000000000000001, 0x100000001, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-221406266*/count=1516; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(mathy4(((Math.min(( + ( + Math.cosh(( + Number.MIN_VALUE)))), ( + x)) >= (Math.acosh(Math.pow(x, x)) | 0)) | 0), ( + Math.atan2(Math.pow(0.000000000000001, ( + Math.sqrt(( + Math.pow(x, x))))), (y >>> 0))))) | Math.fround(mathy3((Math.imul((mathy0(Number.MAX_SAFE_INTEGER, mathy3(((Math.atan2((x | 0), (( + Math.fround(( + y))) | 0)) >>> 0) >>> 0), y)) >>> 0), ((( + ( - Math.fround(Math.acos(y)))) <= ( + x)) | 0)) >>> 0), (Math.cbrt(Math.fround((( + (y >= -Number.MAX_SAFE_INTEGER)) , y))) >>> 0))))); }); testMathyFunction(mathy5, [0x080000000, 0.000000000000001, -0x100000001, 1.7976931348623157e308, -0x100000000, Number.MAX_VALUE, -(2**53), 0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, Math.PI, 1, 0, 0x0ffffffff, 0/0, 0x07fffffff, 2**53, 42, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, -0, -(2**53-2), -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, -0x080000000, 0x100000000, -1/0, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=1517; tryItOut("Array.prototype.push.apply(a0, [i1]);");
/*fuzzSeed-221406266*/count=1518; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-221406266*/count=1519; tryItOut("c = function(id) { return id };({a1:1});print(this + ({}));");
/*fuzzSeed-221406266*/count=1520; tryItOut("p1 + '';");
/*fuzzSeed-221406266*/count=1521; tryItOut("/*RXUB*/var r = /$/gyi; var s = \"\"; print(s.replace(r, '')); ");
/*fuzzSeed-221406266*/count=1522; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(( + (Math.fround((mathy1(x, ( + Math.min((Math.log2((y ? ( + y) : Math.fround(x))) >>> 0), ( + x)))) | 0)) | 0)), ( + ( - (Math.pow(( + Math.atan(( + 1/0))), Math.fround(Math.trunc(y))) >>> -Number.MAX_SAFE_INTEGER))))); }); ");
/*fuzzSeed-221406266*/count=1523; tryItOut("for (var v of f1) { e1.__proto__ = p0; }\nvar unpsbf = new ArrayBuffer(4); var unpsbf_0 = new Uint8Array(unpsbf); unpsbf_0[0] = 5; s1 += s2;\n");
/*fuzzSeed-221406266*/count=1524; tryItOut("Array.prototype.sort.apply(a2, [(function() { for (var j=0;j<20;++j) { f1(j%5==0); } }), a2]);");
/*fuzzSeed-221406266*/count=1525; tryItOut("print(b0);");
/*fuzzSeed-221406266*/count=1526; tryItOut("\"use strict\"; a2 = r0.exec(this.s2);");
/*fuzzSeed-221406266*/count=1527; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log2(( ~ Math.fround(( + Math.imul(Math.fround((Math.atan2(( ~ ( - 0x080000000)), -(2**53+2)) >>> 0)), (x % y)))))); }); testMathyFunction(mathy0, [-0x100000000, 0x07fffffff, -(2**53+2), 0.000000000000001, -(2**53), 42, 2**53, -Number.MIN_VALUE, 0x080000001, 0, 0x100000001, -1/0, Number.MAX_VALUE, 0x080000000, -0x080000001, -Number.MAX_VALUE, 2**53-2, 1, Math.PI, -0, 0/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, 0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-221406266*/count=1528; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan(((Math.max(x, (Math.PI >>> 0)) | 0) , (Math.acosh((Math.round(x) >>> 0)) | 0))); }); testMathyFunction(mathy4, ['\\0', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Number(-0)), 0.1, NaN, '', [0], '0', false, (function(){return 0;}), (new Boolean(true)), true, (new Boolean(false)), objectEmulatingUndefined(), null, (new Number(0)), (new String('')), 1, -0, /0/, ({valueOf:function(){return '0';}}), '/0/', undefined, [], 0]); ");
/*fuzzSeed-221406266*/count=1529; tryItOut("/*tLoop*/for (let a of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), x, new Boolean(true),  '\\0' , objectEmulatingUndefined(), x, new Boolean(true), x, new Boolean(true), \"\\uA366\", x, new Boolean(true), \"\\uA366\", \"\\uA366\", objectEmulatingUndefined(),  '\\0' ,  '\\0' , new Boolean(true), new Boolean(true), objectEmulatingUndefined(), \"\\uA366\", objectEmulatingUndefined(), x, \"\\uA366\", objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), \"\\uA366\", \"\\uA366\",  '\\0' , \"\\uA366\", x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true),  '\\0' , x, new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), \"\\uA366\",  '\\0' , new Boolean(true),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , new Boolean(true),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\uA366\", \"\\uA366\"]) { e2 + ''; }");
/*fuzzSeed-221406266*/count=1530; tryItOut("\"use strict\"; print((eval(\"f0(s0);\")));");
/*fuzzSeed-221406266*/count=1531; tryItOut("a0.forEach((function mcc_() { var snuebs = 0; return function() { ++snuebs; f2(/*ICCD*/snuebs % 4 == 1);};})());");
/*fuzzSeed-221406266*/count=1532; tryItOut("for(var d in eval(\"/* no regression tests found */\")) - '' ;");
/*fuzzSeed-221406266*/count=1533; tryItOut("this.a1.pop();\nthis.v0 = a2.length;\n\nthis.v1 = o0.a1.length;\n");
/*fuzzSeed-221406266*/count=1534; tryItOut("o1 + v2;");
/*fuzzSeed-221406266*/count=1535; tryItOut("\"use strict\"; /*MXX1*/o2 = g2.Function.prototype.constructor;");
/*fuzzSeed-221406266*/count=1536; tryItOut("a1.reverse();");
/*fuzzSeed-221406266*/count=1537; tryItOut("/*RXUB*/var r = new x(new (22)(), arguments); var s = \"\\u45b6\"; print(s.replace(r, '')); ");
/*fuzzSeed-221406266*/count=1538; tryItOut("\"use strict\"; print(t0);");
/*fuzzSeed-221406266*/count=1539; tryItOut("/*RXUB*/var r = (4277); var s = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"; print(r.exec(s)); ");
/*fuzzSeed-221406266*/count=1540; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((((Math.min(( + Math.pow(-Number.MAX_SAFE_INTEGER, ( ~ Number.MIN_VALUE))), ( + x)) | 0) | 0) ? ((x > Math.hypot((( ~ ( ! 2**53-2)) | 0), x)) | 0) : Math.atan2(Math.fround(y), Math.fround((mathy1(x, ( + y)) ? x : mathy0(y, x))))) ? /*RXUE*/new RegExp(\".[^\\\\\\uc8a5\\\\W\\u1176]\\\\u1c13+?\", \"gyim\").exec(\"\\n_\\u441f\\n_\\u441f\") : mathy2(mathy1((( + Math.log1p((Math.fround(( ! y)) >= x))) >>> 0), -(2**53+2)), (( - (mathy1(y, -0x0ffffffff) | 0)) | 0))); }); ");
/*fuzzSeed-221406266*/count=1541; tryItOut(";");
/*fuzzSeed-221406266*/count=1542; tryItOut(" for (let b of (false ? false : new RegExp(\"\\\\1\", \"gyi\"))) m0.set(g1, h0);");
/*fuzzSeed-221406266*/count=1543; tryItOut("\"use strict\"; /*MXX3*/g1.Number.MIN_VALUE = g2.Number.MIN_VALUE;");
/*fuzzSeed-221406266*/count=1544; tryItOut("g2.offThreadCompileScript(\"\\\"use strict\\\"; mathy1 = (function(x, y) { return (Math.imul((Math.atan2((Math.cbrt(x) | 0), ((Math.fround(( + Math.imul(Math.atan2(( ~ x), (mathy0(( ~ x), Number.MAX_VALUE) | 0)), ( + y)))) ? (Math.max((y >> 0x0ffffffff), Math.min((x | 0), y)) == ( + (( + x) ** ( + Math.fround(Math.pow(Math.fround(-1/0), y)))))) : 2**53+2) >>> 0)) >>> 0), (Math.min(Math.atan2(Math.fround((Math.fround(x) - (-1/0 | 0))), ( ! mathy0((2**53 * -(2**53+2)), ( + x)))), ( + (y ? ( - mathy0((((x >>> 0) > (y >>> 0)) >>> 0), y)) : ( + Math.hypot(( + Math.fround((Math.fround((0 === (-0x080000000 >>> 0))) >= Math.fround(Math.fround(mathy0(y, x)))))), ( + y)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0x100000000, -1/0, 0.000000000000001, -0x080000001, 0, -Number.MAX_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, Math.PI, -0x080000000, Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0x100000001, 0/0, 0x080000001, -(2**53+2), 1, -0, 2**53-2, 1/0, -(2**53), 2**53, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2]); \", ({ global: o0.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (void options('strict')), noScriptRval: (x % 61 != 9), sourceIsLazy: false, catchTermination: (4277) ? x = 3 : x, element: o1, sourceMapURL: s2 }));");
/*fuzzSeed-221406266*/count=1545; tryItOut("return;\na1 = [];function x(y, w = \"\\u596C\")/\\B]/ymv1 = Object.prototype.isPrototypeOf.call(o0.g1.g1, m2);\n");
/*fuzzSeed-221406266*/count=1546; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-221406266*/count=1547; tryItOut("s1 = s1.charAt(19);");
/*fuzzSeed-221406266*/count=1548; tryItOut(";");
/*fuzzSeed-221406266*/count=1549; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1550; tryItOut("a2.sort((function() { for (var j=0;j<27;++j) { f0(j%2==0); } }));");
/*fuzzSeed-221406266*/count=1551; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround((( + ((y >> (y | 0)) | 0)) && Math.fround(Math.imul(( + ( + Math.atan(x))), Math.min((Math.sqrt((y >>> 0)) >>> 0), ( + ((( + Math.fround(x)) >>> 0) != ( + x)))))))) < (Math.fround(Math.cos(Math.fround(y))) & (y == ( + (( + ( + ( ~ ( + Math.max(1, x))))) / ( + Math.fround(( ! (( + ( + Number.MIN_SAFE_INTEGER)) | 0))))))))); }); ");
/*fuzzSeed-221406266*/count=1552; tryItOut("/*MXX1*/o1 = g0.Array.prototype;");
/*fuzzSeed-221406266*/count=1553; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! Math.clz32((((Math.imul(y, y) >>> 0) ? (Math.tan(x) | 0) : (Math.min(( + (x , x)), x) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [2**53, -0x080000001, Math.PI, Number.MAX_VALUE, -(2**53-2), -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 0x100000000, 42, 0, 1, -Number.MIN_VALUE, -(2**53+2), -(2**53), 0x080000001, 1/0, -0, -0x100000000, 0x080000000, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1554; tryItOut("\"use strict\"; v2 = a0.every((function mcc_() { var dwlepc = 0; return function() { ++dwlepc; g1.f2(/*ICCD*/dwlepc % 10 == 7);};})());");
/*fuzzSeed-221406266*/count=1555; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( - Math.asinh(y)) >>> (( ~ 0x100000000) % Math.acos(x))); }); testMathyFunction(mathy2, /*MARR*/[ /x/g , new Boolean(false),  /x/g , new Boolean(false), new Boolean(false),  /x/g ,  /x/g ,  /x/g , new Boolean(false),  /x/g ,  /x/g ,  /x/g ,  /x/g , new Boolean(false),  /x/g ,  /x/g ,  /x/g ]); ");
/*fuzzSeed-221406266*/count=1556; tryItOut("m2.set(e1, t0);");
/*fuzzSeed-221406266*/count=1557; tryItOut("\"use asm\"; let(x) ((function(){for(let d in []);})());");
/*fuzzSeed-221406266*/count=1558; tryItOut("\"use strict\"; (([]) = delete d.x);");
/*fuzzSeed-221406266*/count=1559; tryItOut("mathy1 = (function(x, y) { return ((( ~ (x + Number.MIN_SAFE_INTEGER)) | 0) != Math.fround(( ~ (((((Math.min(x, x) | 0) >= ( + y)) >>> 0) & (y >>> 0)) ^ ( + Math.log1p(Math.atanh(y))))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, 0.000000000000001, -1/0, -(2**53+2), 2**53+2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0x100000000, 1, 0x07fffffff, -0, -(2**53-2), 0/0, 0, -(2**53), -0x100000000, 2**53, Number.MIN_VALUE, -0x080000000, 0x080000000, 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 1/0, 0x080000001, -0x07fffffff]); ");
/*fuzzSeed-221406266*/count=1560; tryItOut("this.i0[\"toString\"] = a2;");
/*fuzzSeed-221406266*/count=1561; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -2097153.0;\n    var d4 = -1.9342813113834067e+25;\n    var i5 = 0;\n    (Float32ArrayView[(((((0xa0dd9a0f))>>>((0xffcaa2c5))) != ((Uint32ArrayView[4096])))+(/*FFI*/ff(((-7.737125245533627e+25)), ((~~(d1))), ((a || x)), ((-281474976710657.0)), ((-4.835703278458517e+24)), ((-3.8685626227668134e+25)))|0)-(i5)) >> 2]) = ((Float32ArrayView[(0x21236*((0xffffffff) == (0x21a8ee94))) >> 2]));\n    {\n      i5 = (0xfbbf3dbf);\n    }\n    {\n      {\n        i0 = (0xfae650e1);\n      }\n    }\n    switch ((~(-((0xa0348999) < (0x50cd2c7))))) {\n      case 0:\n        i2 = (i2);\n        break;\n      case -2:\n        d1 = (d1);\n      case -2:\n        (Int32ArrayView[4096]) = (-0x22dde*(0x25036416));\n      case -1:\n        return +((d3));\n        break;\n      default:\n        switch ((imul((0xf999c788), (0x6515c347))|0)) {\n          case -1:\n            i0 = (0xfe611d5);\n            break;\n          default:\n            i2 = (i5);\n        }\n    }\n    i0 = ((/*FFI*/ff(((2305843009213694000.0)))|0) ? (i5) : (i0));\n    {\n      {\n        i2 = (0x3421c662);\n      }\n    }\n    d1 = (NaN);\n    i2 = (i0);\n    return +((((x)) / ((-((d4))))));\n  }\n  return f; })(this, {ff: (encodeURI).call}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, Math.PI, -(2**53-2), Number.MAX_VALUE, -0x07fffffff, -0x100000000, 0, 0x080000000, -0, 2**53, Number.MIN_VALUE, -0x100000001, 42, 0.000000000000001, 2**53+2, 0x080000001, -Number.MIN_VALUE, -1/0, 0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -(2**53)]); ");
/*fuzzSeed-221406266*/count=1562; tryItOut("t0 = t1.subarray(3, 18);");
/*fuzzSeed-221406266*/count=1563; tryItOut("\"use strict\"; let(e) ((function(){c = x;})());break L;");
/*fuzzSeed-221406266*/count=1564; tryItOut("e1.delete(i0);");
/*fuzzSeed-221406266*/count=1565; tryItOut("for (var v of h1) { try { a1 = a2.filter((function() { for (var j=0;j<26;++j) { f0(j%5==0); } }), this.v1); } catch(e0) { } try { v2 = new Number(Infinity); } catch(e1) { } print(o2.s2); }");
/*fuzzSeed-221406266*/count=1566; tryItOut("\"use strict\"; v2 = t0.length;");
/*fuzzSeed-221406266*/count=1567; tryItOut("\"use strict\"; testMathyFunction(mathy1, [(new Boolean(false)), true, [], -0, NaN, (new Number(-0)), /0/, (function(){return 0;}), ({toString:function(){return '0';}}), '', false, null, 1, '0', '/0/', ({valueOf:function(){return '0';}}), 0.1, undefined, (new Number(0)), (new String('')), 0, [0], ({valueOf:function(){return 0;}}), (new Boolean(true)), objectEmulatingUndefined(), '\\0']); ");
/*fuzzSeed-221406266*/count=1568; tryItOut("i0.send(this.s0);");
/*fuzzSeed-221406266*/count=1569; tryItOut("i2.send(e1);");
/*fuzzSeed-221406266*/count=1570; tryItOut("t1.__proto__ = f2;");
/*fuzzSeed-221406266*/count=1571; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-221406266*/count=1572; tryItOut("f2 + e2;");
/*fuzzSeed-221406266*/count=1573; tryItOut("g2.offThreadCompileScript(\"v1 = Object.prototype.isPrototypeOf.call(e1, e0);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: /(?:\\u2e8a|\\s|.*?)+?[^\\W\\xD2-\ucca4\\\u19fa-\\u00B3\\uF7C0]{0,4}(?!\\xc7|\\x62)|(?!.+?)+/im, noScriptRval: false, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-221406266*/count=1574; tryItOut("mathy1 = (function(x, y) { return (( ~ (Math.atan2(( + (Math.log(y) <= Math.fround((Math.fround(Math.asinh(y)) , x)))), Math.fround(( ! Math.fround(x)))) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[-Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, [1], -Number.MIN_SAFE_INTEGER, [1], -Number.MIN_SAFE_INTEGER, [1], -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, [1], [1], [1], -Number.MIN_SAFE_INTEGER, [1], -Number.MIN_SAFE_INTEGER, [1], [1], -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-221406266*/count=1575; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.expm1(Math.fround((( ~ (Math.max((((Math.max(Math.imul(2**53-2, 0x100000000), Math.fround(x)) >>> 0) & 2**53+2) | 0), ((y | 0) != ((Math.acos(x) >>> 0) ^ y))) | 0)) | 0)))); }); testMathyFunction(mathy4, [0, -0x100000001, Number.MAX_VALUE, 1, -0x100000000, -0x07fffffff, 0x100000000, 42, -(2**53-2), Number.MIN_VALUE, 2**53, 2**53-2, 0x0ffffffff, -Number.MAX_VALUE, -1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, 1/0, 0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x080000001, -0, 1.7976931348623157e308, 0x080000001, -(2**53), 2**53+2, -(2**53+2)]); ");
/*fuzzSeed-221406266*/count=1576; tryItOut("a0.push(v1);");
/*fuzzSeed-221406266*/count=1577; tryItOut("\"use strict\"; for (var v of e0) { try { ; } catch(e0) { } try { e1.delete(t1); } catch(e1) { } /*ODP-1*/Object.defineProperty(a0, \"length\", ({enumerable: false})); }");
/*fuzzSeed-221406266*/count=1578; tryItOut("this.v0 = evaluate(\"m0.get(o0);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (p={}, (p.z = x\n)()), catchTermination: {z: (eval(\"/* no regression tests found */\", x)).__proto__, x} = [\u000c[]] }));");
/*fuzzSeed-221406266*/count=1579; tryItOut("o0.g0.v1 = new Number(0);");
/*fuzzSeed-221406266*/count=1580; tryItOut("a1 = a2.concat(g2.t1, s1, b1);");
/*fuzzSeed-221406266*/count=1581; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.pow((Math.atanh(Math.fround(Math.clz32(Math.fround((x - -0))))) >>> 0), (Math.min(y, Math.asinh((( ~ -(2**53)) >>> 0))) !== ( + (Math.fround(x) <= ( + x))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, Math.PI, -0, Number.MAX_VALUE, -(2**53-2), -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0x100000001, 2**53+2, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), 1.7976931348623157e308, 0x07fffffff, -0x100000000, -0x0ffffffff, -0x080000000, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, -1/0, 0/0, 1/0, -0x100000001, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 1, 0.000000000000001]); ");
/*fuzzSeed-221406266*/count=1582; tryItOut("mathy5 = (function(x, y) { return Math.cosh(Math.log2(Math.fround(Math.max(Math.fround((Math.fround(( + ((y | 0) !== Math.fround(Math.expm1(1))))) != Math.fround(Math.atan2(y, x)))), y)))); }); ");
/*fuzzSeed-221406266*/count=1583; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy0((((Math.clz32(( + ( ~ Math.fround(( - Math.fround(0/0)))))) >>> 0) / ((((Math.min(( + Math.min(y, (2**53-2 >> (( + ( + y)) >>> 0)))), ((x ? (Math.fround((( + mathy3(Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE)) * ( + x))) >>> 0) : 0x100000000) >>> 0)) | 0) | 0) - (x | 0)) | 0)) >>> 0), Math.imul((( + Math.fround((Math.fround(x) >>> ( ! 0x100000000)))) >>> 0), Math.fround((((mathy2(x, y) | 0) === (y | 0)) >= mathy0(( + (( + 0x100000001) / ( + Math.fround((Math.fround(x) ? ( + ( ! x)) : ( + x)))))), (x | (x >>> 0))))))); }); testMathyFunction(mathy4, ['', undefined, objectEmulatingUndefined(), null, '0', false, '\\0', -0, /0/, 0, 1, (new String('')), 0.1, (new Boolean(false)), (new Number(-0)), ({valueOf:function(){return '0';}}), '/0/', (new Number(0)), true, (function(){return 0;}), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), [], [0], NaN, (new Boolean(true))]); ");
/*fuzzSeed-221406266*/count=1584; tryItOut("/*bLoop*/for (ojhwoa = 0; ojhwoa < 34; ++ojhwoa) { if (ojhwoa % 5 == 3) { s2 += s2; } else { Object.defineProperty(this, \"e0\", { configurable: x >= z in x, enumerable: true,  get: function() { v1 = Object.prototype.isPrototypeOf.call(o0, a1); return new Set; } }); }  } ");
/*fuzzSeed-221406266*/count=1585; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return (mathy2((( + Math.tan(( + Math.round(-0x0ffffffff)))) >>> 0), (( ~ (( ! y) & Math.pow(x, y))) % (Math.pow((Math.atan2(( + Math.min(x, x)), ((x >>> 0) - y)) | 0), (Math.cbrt(((((x | 0) ? (y | 0) : ( + x)) | 0) ? Math.fround(Math.asinh(y)) : (Math.asinh(y) >>> 0))) | 0)) | 0))) | 0); }); testMathyFunction(mathy3, [0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), -0x100000000, 0x080000000, 1/0, -0x07fffffff, -Number.MIN_VALUE, 0x100000000, -0x0ffffffff, 42, -(2**53-2), 0x0ffffffff, Number.MIN_VALUE, 2**53+2, 0x100000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, 1, -Number.MAX_VALUE, -(2**53+2), -0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -1/0, 0/0, 0, Number.MAX_VALUE, 0x080000001, 2**53]); ");
/*fuzzSeed-221406266*/count=1586; tryItOut("\"use asm\"; ");
/*fuzzSeed-221406266*/count=1587; tryItOut("/*MXX1*/o2 = g2.String.fromCodePoint;");
/*fuzzSeed-221406266*/count=1588; tryItOut("\"use strict\"; s1 += 'x'");
/*fuzzSeed-221406266*/count=1589; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(i1, f1);");
/*fuzzSeed-221406266*/count=1590; tryItOut("throw undefined;i1.next();");
/*fuzzSeed-221406266*/count=1591; tryItOut("v0.__proto__ = o2.o1;");
/*fuzzSeed-221406266*/count=1592; tryItOut("print(this.a2);print(x);");
/*fuzzSeed-221406266*/count=1593; tryItOut("with((eval(\"((function factorial_tail(frpmkj, fpukqf) { ; if (frpmkj == 0) { ; return fpukqf; } ; return factorial_tail(frpmkj - 1, fpukqf * frpmkj); i1 + b0; })(88660, 1))\")))print( /x/ );a1.splice();");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
