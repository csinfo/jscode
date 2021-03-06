

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
/*fuzzSeed-204645237*/count=1; tryItOut("mathy1 = (function(x, y) { return (mathy0(((Math.log2(Math.fround((( ! Math.fround(( ~ Math.fround(x)))) | 0))) | 0) | 0), ( + ((Math.acosh((( + ((( - x) >>> 0) && ( + (( - ( + x)) >>> 0)))) >>> 0)) >>> 0) + ( + (Math.cos((Math.fround((Math.fround((( + -1/0) < ( + x))) ** Math.trunc((y | 0)))) > ( + (( + (( + x) ? (x | 0) : (x | 0))) & ( + Math.fround(Math.fround(Math.fround(x)))))))) >>> 0))))) | 0); }); testMathyFunction(mathy1, [0x080000001, -0, 42, -1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, 0, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53, -0x07fffffff, -0x080000001, 1, 0x080000000, -0x0ffffffff, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -(2**53), 0x100000001, 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0]); ");
/*fuzzSeed-204645237*/count=2; tryItOut("this.h0 + b1;g2.e1.has(function ([y]) { });");
/*fuzzSeed-204645237*/count=3; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.min(Math.hypot(( ~ (((Math.fround((Math.fround(x) / Math.fround(-0))) ^ y) >>> 0) ? x : Math.sinh(x))), (( + Math.max(( + y), (( + ( + mathy1(x, (((x >>> 0) | (Math.atan2(( + x), -0x07fffffff) >>> 0)) >>> 0)))) !== ( + ( ~ x))))) >>> 0)), ((( ! (Math.fround(( + (Math.fround(Math.fround(( ~ y))) + ( + Math.tan(x))))) & (Math.max(( ! Math.fround(2**53+2)), y) >>> 0))) | 0) >>> 0))); }); testMathyFunction(mathy5, /*MARR*/[new Boolean(false), new Boolean(false),  /x/g , new Boolean(false),  /x/g ,  /x/g , new Boolean(false), new Boolean(false),  /x/g ,  /x/g , new Boolean(false)]); ");
/*fuzzSeed-204645237*/count=4; tryItOut("\"use strict\"; yield new RegExp(\"(?!(?!^))|[^][^]{3,}(?=\\\\u7bAD|^(?:(?:\\\\S))){4}\", \"gym\");\nm2 = Proxy.create(g2.h1, h2);\n");
/*fuzzSeed-204645237*/count=5; tryItOut("a2.reverse();");
/*fuzzSeed-204645237*/count=6; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + ( ! Math.fround(mathy0(Math.fround(( ! Math.sinh(( + Math.fround(mathy4(Math.fround(x), x)))))), (x >>> 0))))) * ((( + (( ~ (Math.fround(( - ( + Math.cosh((x >>> 0))))) >>> 0)) >>> 0)) >>> 0) << (( + ( - Math.atan2(Math.fround(x), Math.fround(x)))) | 0))); }); testMathyFunction(mathy5, [-0x100000000, 0x080000000, -0, 42, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -(2**53+2), 1/0, Math.PI, -Number.MIN_VALUE, 0, 1, 2**53-2, 2**53+2, 0/0, 0x100000001, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, Number.MAX_VALUE, 0x0ffffffff, 0x100000000, -0x07fffffff, 0x07fffffff, -1/0, -0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-204645237*/count=7; tryItOut("for (var p in t1) { try { /*RXUB*/var r = r2; var s = \"\"; print(s.match(r)); print(r.lastIndex);  } catch(e0) { } a0[3] = s0; }");
/*fuzzSeed-204645237*/count=8; tryItOut("print(x);m2.__iterator__ = (function mcc_() { var dclhiu = 0; return function() { ++dclhiu; f0(/*ICCD*/dclhiu % 3 != 1);};})();e0 + t2;");
/*fuzzSeed-204645237*/count=9; tryItOut("\"use strict\"; e2.add(i2);");
/*fuzzSeed-204645237*/count=10; tryItOut("\"use asm\"; e2 = this.t0[(((yield [,,])).unwatch(\"e\"))];");
/*fuzzSeed-204645237*/count=11; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((+pow((((+(0.0/0.0)) + (590295810358705700000.0))), ((+(-1.0/0.0))))));\n  }\n  return f; })(this, {ff: ((Int32Array).bind).bind((4277))}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [2**53, 0x07fffffff, 1, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 2**53+2, -1/0, -0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0, -(2**53-2), -0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -0x07fffffff, -0x100000000, 42, 0x080000001, 1/0, -0x080000001, -Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -(2**53), Math.PI, 0x100000000, 0, -(2**53+2), 1.7976931348623157e308]); ");
/*fuzzSeed-204645237*/count=12; tryItOut("g1 + '';");
/*fuzzSeed-204645237*/count=13; tryItOut("print( /x/ );\na1 = arguments.callee.arguments;\n");
/*fuzzSeed-204645237*/count=14; tryItOut("v0 = evalcx(\"for (var v of v1) { try { a2.splice(-4, 5, t2); } catch(e0) { } try { i2.next(); } catch(e1) { } o0.a1 = []; }\", g0);");
/*fuzzSeed-204645237*/count=15; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -562949953421313.0;\n    (Float64ArrayView[((0xb5ab85d3) % (0x9dfeb14b)) >> 3]) = ((d1));\n    d2 = (d1);\n    {\n      d2 = (+abs(((d1))));\n    }\n    {\n      (Int32ArrayView[1]) = ((/*FFI*/ff(((((i0)-(0x99bf7c07)) << ((-0x8000000)))), ((d2)), ((((((d2)))) & ((i0)*0xfffff))), ((((0xf88b75df)*0xc96ec) & (((0xd82c98f3))*-0x9d48d))), (((Uint8ArrayView[(((-0x8000000) < (-0x2aa6fd0))+((0x72be1c66))) >> 0]))), ((((0x4ecc879c)+(0xffffffff)) | ((0xc78fc89d)-(0xff9425bb)))), ((d1)), ((((0x7efe9cf6)) ^ ((0xffffffff)))), ((129.0)))|0)+(i0));\n    }\n    (Float64ArrayView[0]) = ((d2));\n    return +((Float64ArrayView[2]));\n    d1 = (((((i0)-(0x97a801d8)-(0x3ec455e2)) | ((0xffffffff)-((0xa8a2475f) != (((0xfe891c6b))>>>((0xffffffff))))-(((0xffb9583d) ? (0xfc023fda) : (0xffffffff)) ? ((+atan2(((-1.25)), ((-7.555786372591432e+22))))) : (i0))))));\n    {\n      {\n        i0 = (((0xc05e6*((imul(((0x78d04b56)), (0x5e21e40))|0))) | ((-0x8000000)-(i0)-(0xffffffff))) == (((((0x1a234fe8))|0) / (~(((0xc22b0dc2) != (0xb5b352b3))+((((0xefa57989))>>>((-0x8000000))))))) >> (((0x65db62d5))*-0x6c219)));\n      }\n    }\n    d1 = ((d1) + ((-0x8000000) ? (-8796093022208.0) : (d1)));\n    d2 = (+(1.0/0.0));\n    return +((d2));\n  }\n  return f; })(this, {ff: Int8Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, -1/0, 0, -Number.MAX_VALUE, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0x0ffffffff, 0x080000001, 0x0ffffffff, 0.000000000000001, 0x080000000, Math.PI, 2**53+2, 0x07fffffff, 1, -(2**53), Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, -0x100000000, 42, 2**53-2, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -0x080000000]); ");
/*fuzzSeed-204645237*/count=16; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=17; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((d0));\n  }\n  return f; })(this, {ff: function  NaN (y, {})(4277)}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53-2), Number.MIN_VALUE, -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, 42, -0x100000000, -(2**53), 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -0x100000001, 0x080000000, 0x07fffffff, -0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, -1/0, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 0, 2**53+2, -0x080000001, Math.PI, 0x080000001, 1, 1/0, 1.7976931348623157e308, 0/0]); ");
/*fuzzSeed-204645237*/count=18; tryItOut("((4277))(eval(\"v2 = o2.r0.unicode;\", /./g),  '' );");
/*fuzzSeed-204645237*/count=19; tryItOut("m1.has(new String.fromCodePoint((void options('strict'))));");
/*fuzzSeed-204645237*/count=20; tryItOut("\"use strict\"; o0.o2.toString = (function() { try { /*RXUB*/var r = r1; var s = \"\"; print(uneval(s.match(r)));  } catch(e0) { } try { s1 = s0.charAt(v2); } catch(e1) { } Array.prototype.splice.apply(a0, [NaN, g0.v0]); return f0; });");
/*fuzzSeed-204645237*/count=21; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=22; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-204645237*/count=23; tryItOut("/*iii*/(void schedulegc(g1));/*hhh*/function wdwtdz(w, d, x, z, x, [], x, b, NaN, c, window, x, x, x, z, c, a = new RegExp(\"${0,131071}\", \"gy\"), x = /[\\cO-\\xbC\u0092]\\b+|(?=[^\\cB-\\cK\\u225D\\u589e-\u89d9\u00f6])*?((?=(?:^|i)))\ue555+/, b, c, \u3056, x, z, x, x, \u3056, \"-13\" = [], y, x, y, d = c, \u3056, e, y, d, let, z = 2, w, window, window, window, x = -5, window, d, e, b =  '' , let, x, NaN = [,], w, x = x, x, x, a, e, x, w, \u3056, c, this.x = (function ([y]) { })(), d, e, x, NaN, b){g0.t1 = new Int8Array(t2);}");
/*fuzzSeed-204645237*/count=24; tryItOut("");
/*fuzzSeed-204645237*/count=25; tryItOut("testMathyFunction(mathy5, /*MARR*/[undefined, new Number(1), eval(\"/* no regression tests found */\"), eval(\"/* no regression tests found */\"), eval, new Number(1), new Number(1)]); ");
/*fuzzSeed-204645237*/count=26; tryItOut("mathy4 = (function(x, y) { return (Math.min((( - (-0x100000000 % mathy1(Math.fround(( ~ 0x07fffffff)), Math.log1p(( ! (-0 >>> 0)))))) >>> 0), (((( - (mathy1(Math.imul(Math.fround(( ~ x)), x), ( + Number.MIN_VALUE)) | 0)) | 0) * ( ~ Math.max(Math.max(Math.fround(Math.min(Number.MAX_SAFE_INTEGER, y)), (-1/0 | 0)), ((x ** Math.fround(0.000000000000001)) & (-(2**53+2) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, 0x080000000, 2**53+2, 0x100000000, -Number.MIN_SAFE_INTEGER, -0, 0x080000001, 0x07fffffff, 0x100000001, -(2**53), -0x07fffffff, 2**53, -0x080000000, -0x0ffffffff, 1/0, Math.PI, 42, -(2**53+2), 2**53-2, 1.7976931348623157e308, -0x080000001, Number.MIN_VALUE, 1, -(2**53-2), -Number.MAX_VALUE, 0, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-204645237*/count=27; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = \"11 \\n \\u97c7\\n\\n\\n\\n\\n\"; print(s.match(r)); ");
/*fuzzSeed-204645237*/count=28; tryItOut("v1 = a0.length;");
/*fuzzSeed-204645237*/count=29; tryItOut("testMathyFunction(mathy1, [0x07fffffff, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, -0x080000001, 1, 2**53-2, -Number.MIN_VALUE, -(2**53-2), -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, 0x100000001, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0x080000000, -0x0ffffffff, 0/0, 0x080000001, -(2**53+2), 0, Math.PI, -(2**53), 0x100000000, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, 1/0, -0, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=30; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + Math.log10(( + Math.max((x >>> 0), y)))) ? (mathy1((Math.imul((Math.tan(((( - (( + Math.atan2(( + x), x)) >>> 0)) >>> 0) | 0)) | 0), (Math.cosh(( + x)) == ( + (( + y) * x)))) | 0), ((( + ( ~ ( ~ y))) << ( + y)) | 0)) | 0) : ( ! Math.fround(mathy0(Math.fround((x === ( ! y))), Math.fround(( + ( + ( + y)))))))); }); testMathyFunction(mathy2, [-0x07fffffff, Math.PI, 0x100000001, 0x07fffffff, -(2**53-2), -Number.MAX_VALUE, -(2**53), 0.000000000000001, -0x100000000, 42, 0/0, 0, 0x080000001, 2**53-2, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, 1/0, -0x080000001, -0x100000001, -1/0, 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 2**53, -0x080000000, 0x100000000]); ");
/*fuzzSeed-204645237*/count=31; tryItOut("let (x, b) { /*RXUB*/var r = new RegExp(\".\", \"yi\"); var s = \"0\\u07aa\\n\\n\\n0\\u07aa\\n\\n\\n0\\u07aa\\n\\n\\n0\\u07aa\\n\\n\\n\"; print(s.split(r));  }");
/*fuzzSeed-204645237*/count=32; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x080000001, 0/0, 0, 1.7976931348623157e308, -0, 0x07fffffff, -1/0, -0x100000001, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, 0x100000001, 0.000000000000001, 0x080000000, 1, 2**53+2, 2**53, -0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 42, 1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -(2**53), -(2**53-2), -0x080000000, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=33; tryItOut("h2.getOwnPropertyDescriptor = (e = window);");
/*fuzzSeed-204645237*/count=34; tryItOut("v2 = (f0 instanceof o2.m2);");
/*fuzzSeed-204645237*/count=35; tryItOut("m0.get(m0);");
/*fuzzSeed-204645237*/count=36; tryItOut("v0 = o0.a2.reduce, reduceRight((function() { for (var j=0;j<5;++j) { f2(j%2==0); } }), t0, v1, x, v2);");
/*fuzzSeed-204645237*/count=37; tryItOut("testMathyFunction(mathy3, [1, Number.MAX_VALUE, -0x100000001, 0, Number.MAX_SAFE_INTEGER, Math.PI, -0, 2**53, 0/0, 2**53-2, 42, 0x100000001, 0x0ffffffff, 1/0, -Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), 0x07fffffff, 0x080000001, -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), Number.MIN_VALUE, -1/0, -(2**53), 0.000000000000001, -0x080000001, 0x080000000, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=38; tryItOut("\"use strict\"; v0 = a0.length;");
/*fuzzSeed-204645237*/count=39; tryItOut("v1 = (p0 instanceof o1.p0);");
/*fuzzSeed-204645237*/count=40; tryItOut("\"use strict\"; a1 = new Array;");
/*fuzzSeed-204645237*/count=41; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=42; tryItOut("mathy3 = (function(x, y) { return ((function(x, y) { return y; }).prototype & (y) = allocationMarker()); }); testMathyFunction(mathy3, [-0x080000000, 2**53, 0x100000000, 0x080000001, 0.000000000000001, 42, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, -0x0ffffffff, 0/0, -0x080000001, 2**53-2, -0x100000000, 1/0, 0, 0x080000000, 0x100000001, -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, -(2**53), 1, -Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=43; tryItOut("\"use strict\"; var d =  /* Comment */this;m1.delete(h0);");
/*fuzzSeed-204645237*/count=44; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\2){4}[^]{2,}\", \"ym\"); var s = \"\\u0089\\u0089\\u0089\\u0089\\u0089\\u0089\\n\\n\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-204645237*/count=45; tryItOut("e2.add(e1);");
/*fuzzSeed-204645237*/count=46; tryItOut("{(new RegExp(\"(?:\\\\S|\\u7616*|\\\\d+$)|(?!\\\\3^)|\\\\S(?=[])?\\\\x8C*?*?\", \"gyi\"));h2.iterate = f1;f2.__iterator__ = (function(j) { if (j) { t2.__iterator__ = (function() { try { o1.a0[8] = window; } catch(e0) { } e2.has(o1); throw g1.s1; }); } else { try { Object.prototype.unwatch.call(f2, \"parseInt\"); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(e1, i1); } catch(e1) { } try { a0.length = v2; } catch(e2) { } o0 = this.v1.__proto__; } }); }");
/*fuzzSeed-204645237*/count=47; tryItOut("\"use strict\"; testMathyFunction(mathy5, [NaN, '\\0', '/0/', ({valueOf:function(){return '0';}}), (new Number(0)), (new Boolean(false)), (new Number(-0)), false, ({toString:function(){return '0';}}), undefined, '0', true, (new String('')), objectEmulatingUndefined(), /0/, (new Boolean(true)), ({valueOf:function(){return 0;}}), -0, 0.1, [], 1, [0], '', (function(){return 0;}), null, 0]); ");
/*fuzzSeed-204645237*/count=48; tryItOut("g1.offThreadCompileScript(\"\\\"use strict\\\"; print(x);\");");
/*fuzzSeed-204645237*/count=49; tryItOut("\"use asm\"; testMathyFunction(mathy3, /*MARR*/[-0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, {x:3}, (-1/0), -0xB504F332, {x:3}, -0xB504F332, -0xB504F332, new Number(1.5), {x:3},  /x/g , -0xB504F332, (-1/0),  /x/g , {x:3},  /x/g , new Number(1.5),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , -0xB504F332, -0xB504F332,  /x/g , {x:3}, (-1/0), (-1/0),  /x/g ,  /x/g ,  /x/g , {x:3}, -0xB504F332,  /x/g , new Number(1.5),  /x/g , {x:3}, new Number(1.5),  /x/g , -0xB504F332, (-1/0),  /x/g , {x:3}, {x:3}, (-1/0), -0xB504F332, (-1/0), new Number(1.5), {x:3}, new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-204645237*/count=50; tryItOut("v2 = (v1 instanceof p0);");
/*fuzzSeed-204645237*/count=51; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:.{2,4}${0}{2,}){1}|\\\\B{4}((((\\u9b78{3,}))){1,4})+?\\\\d\", \"gim\"); var s = \"\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5\\u57f5a\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=52; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.sin(( ~ (Math.fround(Math.cbrt(this)) ^ Math.fround((( + (mathy0(Math.PI, ((-0x080000000 | 0) | mathy0(-0x100000000, y))) | 0)) | 0))))); }); ");
/*fuzzSeed-204645237*/count=53; tryItOut("mathy0 = (function(x, y) { return ((((( + Math.atan2((( + Math.imul(( + x), ( + y))) | 0), ( + Math.exp(Number.MIN_SAFE_INTEGER)))) << Math.fround((( + (( + y) < ( + x))) !== ( ~ ((Math.min((x | 0), (-Number.MIN_VALUE | 0)) | 0) >= -(2**53-2)))))) >>> 0) / (Math.fround(Math.pow(( - ( - y)), (x << (( + (( + -1/0) ** ( + x))) === y)))) ? ((((x | 0) > (Math.fround(( + Math.fround(y))) | 0)) | 0) <= x) : ( ! ( + Math.sin(( + Math.hypot((-(2**53) >>> 0), (( + ( + x)) >>> 0)))))))) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[arguments, 5.0000000000000000000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 5.0000000000000000000000, objectEmulatingUndefined(), function(){}, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, arguments, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, objectEmulatingUndefined(), function(){}, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments, objectEmulatingUndefined(), arguments, 5.0000000000000000000000, objectEmulatingUndefined(), function(){}, 5.0000000000000000000000, arguments, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, arguments, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, arguments]); ");
/*fuzzSeed-204645237*/count=54; tryItOut("\"use strict\"; m2 = new Map(this.m1);");
/*fuzzSeed-204645237*/count=55; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void schedulegc(this); } void 0; }");
/*fuzzSeed-204645237*/count=56; tryItOut("testMathyFunction(mathy5, [1.7976931348623157e308, 2**53-2, Number.MAX_VALUE, 1, 0, 0x0ffffffff, -(2**53+2), -1/0, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, 42, 2**53+2, Math.PI, -0x080000001, -0x07fffffff, 0x080000001, -0x0ffffffff, -0x100000000, 1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x100000000, 0x080000000, -0x080000000, 0/0]); ");
/*fuzzSeed-204645237*/count=57; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a2, 10, { configurable: (x % 4 != 1), enumerable: (4277), get: (function mcc_() { var ejrpaq = 0; return function() { ++ejrpaq; if (/*ICCD*/ejrpaq % 8 == 1) { dumpln('hit!'); try { Object.preventExtensions(i0); } catch(e0) { } try { t0.set(t0, 19); } catch(e1) { } try { Object.defineProperty(this, \"t0\", { configurable: Float64Array.prototype =  \"\" , enumerable: false,  get: function() {  return new Int16Array(b1, 32, new Function()/*\n*/); } }); } catch(e2) { } e0.has(v1); } else { dumpln('miss!'); try { var s2 = new String; } catch(e0) { } try { v0 = (m2 instanceof o1); } catch(e1) { } try { /*RXUB*/var r = r1; var s = \"\"; print(s.match(r));  } catch(e2) { } Array.prototype.shift.call(a1); } };})(), set: (function mcc_() { var tgjjte = 0; return function() { ++tgjjte; f2(/*ICCD*/tgjjte % 4 == 1);};})() });");
/*fuzzSeed-204645237*/count=58; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.min(( + Math.fround(mathy1(Math.fround(((Math.log1p(( + (((x | 0) * (Math.fround(( ~ Math.fround(0x080000001))) | 0)) | 0))) ^ (Math.log1p(x) === Math.fround(y))) | 0)), Math.fround((mathy1((( + ((x && y) | 0)) | 0), (-0x0ffffffff >>> 0)) >>> 0))))), ( + ( - Math.max(Math.hypot((Math.max(2**53, y) >>> 0), (Math.log2((y | 0)) | 0)), -0x080000001))))); }); testMathyFunction(mathy2, [1, 0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000001, 1/0, 0x100000001, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, 0x080000001, -0x080000001, -(2**53), 0.000000000000001, -0x080000000, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 2**53, 0/0, -0x100000000, 0, 0x07fffffff, 2**53-2, Math.PI, 0x080000000, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=59; tryItOut("print(x ? this.__defineGetter__(\"eval\", (x, x = ((void version(170))), x, x, x, y, y, c, x = window, x, x, x, window, a, x, w, x, c, a, x, eval, x, z, x, w, d, z, e, d, b, x = 28, this.x, x = \"\\u3671\", b = 25, NaN, x, c, x, x, \u3056, a = undefined, x, x, x, x, window, x, w, x, b, a = window, \u3056, b, NaN, eval, d, x, x) =>  { \"use strict\"; return 7.valueOf(\"number\") } ) : ());");
/*fuzzSeed-204645237*/count=60; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ((Math.fround((mathy1(( ! (Math.hypot(x, Number.MAX_SAFE_INTEGER) | 0)), (Math.log10(-Number.MIN_SAFE_INTEGER) | 0)) | 0)) * ((((Math.pow((x | 0), ((x % Math.pow(x, y)) | 0)) | 0) | 0) == ( - x)) | 0)) | 0)); }); testMathyFunction(mathy3, [0/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, 1/0, 0x0ffffffff, 0x100000000, 0x07fffffff, 1, 0x080000001, -0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -0x080000000, -0x100000000, 42, 2**53-2, Math.PI, 2**53+2, 2**53, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, -0x080000001, -0x100000001, -(2**53+2), -0, Number.MIN_VALUE, 0.000000000000001, 0, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=61; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-(2**53+2), 0/0, -0x080000001, -0x100000000, Math.PI, 0x080000000, 0x100000001, 0x080000001, -Number.MAX_VALUE, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53+2, 1, -0x100000001, 2**53-2, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, -0, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 42, 2**53, 0, -Number.MIN_VALUE, 1/0, -0x07fffffff, -1/0, -(2**53)]); ");
/*fuzzSeed-204645237*/count=62; tryItOut("/*oLoop*/for (let ifffgr = 0; ifffgr < 69; ++ifffgr) { for (var p in f2) { try { v1 = Array.prototype.every.call(a2, (function() { try { Array.prototype.pop.call(a2, g2.o1.b1, this, p2); } catch(e0) { } try { Object.defineProperty(this, \"v1\", { configurable: true, enumerable: (x % 13 != 2),  get: function() { t2 + f2; return g0.runOffThreadScript(); } }); } catch(e1) { } for (var p in g2.h0) { try { s1 += 'x'; } catch(e0) { } try { Array.prototype.shift.call(a2); } catch(e1) { } try { s0 += 'x'; } catch(e2) { } print(o0.v0); } return f0; })); } catch(e0) { } try { this.e2.delete(t0); } catch(e1) { } s2.valueOf = (function() { for (var j=0;j<113;++j) { f2(j%4==0); } }); } } ");
/*fuzzSeed-204645237*/count=63; tryItOut("\"use strict\"; ((makeFinalizeObserver('tenured')));");
/*fuzzSeed-204645237*/count=64; tryItOut("mathy5 = (function(x, y) { return (Math.fround(Math.fround((((Math.expm1((( ! y) | 0)) >>> 0) | 0) , Math.fround((Math.imul((Math.fround(Math.pow(x, Math.fround(y))) | 0), (( - ((Math.max(y, -0x07fffffff) , y) >>> 0)) | 0)) | 0))))) <= Math.fround((Math.atan2((Math.pow(-Number.MIN_SAFE_INTEGER, 0x100000000) | 0), (( + (Math.max(x, (( ! (2**53 | 0)) | 0)) >>> 0)) | 0)) | 0))); }); testMathyFunction(mathy5, [-0x100000000, -0x080000000, 0x100000001, -0x0ffffffff, 0x07fffffff, 0.000000000000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, -1/0, -(2**53), Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, 0/0, -(2**53+2), Number.MIN_VALUE, 0x080000001, -0x07fffffff, 0x080000000, 2**53+2, 0x0ffffffff, 1/0, 42, Math.PI, -Number.MIN_VALUE, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, 0, 0x100000000, 2**53-2]); ");
/*fuzzSeed-204645237*/count=65; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      /*FFI*/ff(((((!(i0))-((((0xf96489ea))>>>((0xb8cc2ec5))) >= (0xbf4d47e2))-(i1)) >> ((i0)-((0xfe60d246) ? (-0x8000000) : (0xd2d8f468))+(((i1)) != (2.0))))), ((imul((i1), ((Float32ArrayView[(((0x15deca1b) != (0x4805e737))*-0x72c3b) >> 2])))|0)));\n    }\n    i1 = ((-1.888946593147858e+22) <= (NaN));\n    i0 = ((((i1))>>>((/*FFI*/ff()|0)-((0xd3869571) != (0x16e9cac1)))) != (0xf6a1c276));\n    (Float64ArrayView[1]) = (x);\n    i0 = ((0x86082853));\n    i0 = ((~((imul(((NaN) < (+(1.0/0.0))), ((0x2200a160) == (0x0)))|0) / (~((0xffffffff) % (0x194c5926))))));\n    (Uint8ArrayView[0]) = ((i0)-(((~((i1)+((0x5c7b26b7) < (-0x8000000)))) <= (0x294d1333)) ? (/*FFI*/ff()|0) : (i1)));\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: Uint8Array}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=66; tryItOut("\"use strict\"; a0.forEach((function() { try { Array.prototype.shift.apply(a0, [v2]); } catch(e0) { } try { m1.delete(v1); } catch(e1) { } g1.offThreadCompileScript(\"function f0(this.i0) \\\"use asm\\\";   var Uint8ArrayView = new stdlib.Uint8Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    i1 = (0xe0ee6499);\\n    switch ((((i0)+(i0))|0)) {\\n    }\\n    i1 = (1);\\n    i0 = (i1);\\n    {\\n      {\\n        i1 = (i1);\\n      }\\n    }\\n    i0 = (i0);\\n    (Uint8ArrayView[4096]) = ((i0)+(i0));\\n    return (((i1)))|0;\\n    {\\n      i1 = (i1);\\n    }\\n    i1 = (i1);\\n    return (((0xc3dc18e3) % (new \\\"\\\\u5B6A\\\"())))|0;\\n  }\\n  return f;\", ({ global: o2.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 35 == 31), catchTermination: \"\\uD710\" })); return g0; }), g1);");
/*fuzzSeed-204645237*/count=67; tryItOut("\"use strict\"; this.t0 = new Float32Array(a0);");
/*fuzzSeed-204645237*/count=68; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( - Math.fround(((( ! (x >>> 0)) >>> 0) >= (( ! (x | 0)) / Math.min(Math.fround(-0x080000001), y))))) >>> 0) || Math.trunc((((( ! ( + y)) >>> 0) ? (Math.atan2(( + x), ( ! -0x100000001)) >>> 0) : (Math.fround(mathy2(Math.fround((Math.tan((x | 0)) | 0)), Math.fround((mathy2((x >>> 0), (y >>> 0)) >>> 0)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 0.000000000000001, -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, 1, 0x0ffffffff, 1.7976931348623157e308, Math.PI, -0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, -(2**53), -0x0ffffffff, -(2**53+2), -1/0, 0/0, Number.MAX_VALUE, -0, 2**53, -(2**53-2), 0x100000001, 2**53+2, -Number.MAX_VALUE, 1/0, 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-204645237*/count=69; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.hypot(((((Math.trunc(( + 2**53-2)) << x) | 0) == ((( + Math.max((( ! -0x100000001) | 0), y)) >>> (((Math.fround((Math.min(( + x), (0.000000000000001 >>> 0)) >>> 0)) ? Math.fround((((0x0ffffffff >>> 0) + (x | 0)) | 0)) : (Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) > Math.fround(Math.fround((Math.fround(x) == Math.fround(x)))))) >>> 0)) | 0) , (y + y))) | 0)) | 0), ( + (((Math.sinh((Math.fround((-1/0 ? x : ( + Math.fround((Math.fround(Math.max(Number.MIN_VALUE, y)) * 0.000000000000001))))) >>> 0)) >>> 0) | 0) != (mathy0(( + ((Math.asinh(y) | 0) % x)), (y >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [1, 1.7976931348623157e308, 0, 2**53-2, 2**53, -0x080000000, 0/0, 0x080000000, 0x07fffffff, 0x100000001, -0x100000001, 42, -0x080000001, Math.PI, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, -Number.MAX_VALUE, 0x0ffffffff, -(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, 2**53+2, -0x07fffffff, 0x100000000, -1/0, -(2**53+2), -0x0ffffffff, 0x080000001]); ");
/*fuzzSeed-204645237*/count=70; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g1, m1);");
/*fuzzSeed-204645237*/count=71; tryItOut("L: {var x = [[1]];/*ODP-2*/Object.defineProperty(h1, new String(\"7\"), { configurable: undefined, enumerable: (x % 3 == 2), get: (function() { try { t2 = new Uint32Array(g0.t1); } catch(e0) { } try { for (var v of m2) { try { for (var v of v0) { try { a2 = a0.map((function() { v2 = t2.byteLength; return p0; })); } catch(e0) { } try { for (var v of t2) { g2.offThreadCompileScript(\"v0 = (v0 instanceof f1);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: null, sourceIsLazy: (x % 2 != 0), catchTermination: true })); } } catch(e1) { } s1 = new String; } } catch(e0) { } try { Object.defineProperty(this, \"v1\", { configurable:  /x/ , enumerable: (x % 12 == 0),  get: function() {  return evaluate(\"-13\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 19 != 5), catchTermination: true })); } }); } catch(e1) { } t1 = new Int32Array(a0); } } catch(e1) { } a0.push(e1, o0, a2, f1); return v2; }), set: (function mcc_() { var tjsvir = 0; return function() { ++tjsvir; if (/*ICCD*/tjsvir % 3 == 1) { dumpln('hit!'); try { g2.offThreadCompileScript(\"{}\"); } catch(e0) { } h0.has = f0; } else { dumpln('miss!'); g1.m0 = new Map(h0); } };})() }); }");
/*fuzzSeed-204645237*/count=72; tryItOut("var c = (uneval(let (a = ((function fibonacci(plslpe) { ; if (plslpe <= 1) { print(window);; return 1; } ; return fibonacci(plslpe - 1) + fibonacci(plslpe - 2);  })(7)), hibvnx, window =  \"\" , vpogdq, dgmvqy, ashewi, y, mfzmns) NaN ? false : d));t2 = new Int16Array(t1);");
/*fuzzSeed-204645237*/count=73; tryItOut("\"use strict\"; a0 = a2[9];");
/*fuzzSeed-204645237*/count=74; tryItOut("const d = (allocationMarker() << Object.defineProperty(x, \"1\", ({value:  '' , writable: (x % 2 == 1), configurable: new RegExp(\"(?:\\\\t)\", \"gy\")})));p2.valueOf = (function() { try { a2[9] = this.g2; } catch(e0) { } this.e2.delete(this.o0.h2); return v1; });\nfor (var p in v0) { try { this.o0.m1.set(h1, a2); } catch(e0) { } try { i0.send(g0); } catch(e1) { } try { t0[3] = o0; } catch(e2) { } a0.splice(-1, 19); }\n");
/*fuzzSeed-204645237*/count=75; tryItOut("/*RXUB*/var r = /(?=.|(?=\\x08|\\uE02D+?){0,4}|$)/g; var s = \"\\n\\n\\n\\u69a4\\n\\u5d6c\"; print(s.split(r)); ");
/*fuzzSeed-204645237*/count=76; tryItOut("m1.has(this.o2);");
/*fuzzSeed-204645237*/count=77; tryItOut("{t0[18] = t2;/*oLoop*/for (cdesef = 0; cdesef < 37; ++cdesef) { print(x); }  }");
/*fuzzSeed-204645237*/count=78; tryItOut("/*infloop*/for(let [] = new (b.unwatch(14))(); (/*RXUE*/new RegExp(\"(?=(?:\\\\u0075\\\\b+.|.*))|[^]{2}\", \"y\").exec(\"\\n\\n\\n\\n\")); x) i0.send(o0);");
/*fuzzSeed-204645237*/count=79; tryItOut("let cdfsqv, a = 'fafafa'.replace(/a/g, Int32Array), x = x, svinrq, y, w = timeout(1800), window, d = false |=  /x/  >>>= x, y = x;s1 += 'x';");
/*fuzzSeed-204645237*/count=80; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=81; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -0x080000001, Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, -(2**53), 2**53+2, -Number.MAX_VALUE, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, -(2**53-2), -0, 0x080000001, 0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000001, 0, 0x100000001, -Number.MIN_SAFE_INTEGER, 42, 1.7976931348623157e308, -0x080000000, 2**53, 1, -0x100000000, 0x07fffffff, 0x080000000, 0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=82; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-204645237*/count=83; tryItOut("\"use strict\"; for (var p in o2.f1) { try { o2.__iterator__ = (function(j) { f0(j); }); } catch(e0) { } try { e1.toSource = Function.prototype.bind(v2); } catch(e1) { } t2.__iterator__ = (function() { for (var j=0;j<27;++j) { this.f0(j%2==1); } }); }");
/*fuzzSeed-204645237*/count=84; tryItOut("L:for(let x in ((new Function)(arguments+=e + e))){selectforgc(o0);v1 = (v2 instanceof this.m1); }");
/*fuzzSeed-204645237*/count=85; tryItOut("this.m1 + h0;");
/*fuzzSeed-204645237*/count=86; tryItOut("with((({a2:z2}) ? -18 :  /x/g ))continue M;");
/*fuzzSeed-204645237*/count=87; tryItOut("L:for(let y = x in (b) = (x)) {m0.get(i0); }");
/*fuzzSeed-204645237*/count=88; tryItOut("\"use strict\"; ([]);\nthis.t1.set(t1, v0);\n");
/*fuzzSeed-204645237*/count=89; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(e2, s0);");
/*fuzzSeed-204645237*/count=90; tryItOut("\"use strict\"; v2 = evaluate(\"return x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return []; }, delete: function() { throw 3; }, fix: (new Function(\\\"window\\\")), has: function() { throw 3; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: decodeURI, }; })(function(id) { return id }), (let (x = this) e)).unwatch(\\\"entries\\\");\", ({ global: g0.o0.g0, fileName: null, lineNumber: 42, isRunOnce: (x % 23 != 8), noScriptRval: (x % 27 == 24), sourceIsLazy: false, catchTermination: (Math.atan2(-10, 20)) >>> x, sourceMapURL: this.s2 }));");
/*fuzzSeed-204645237*/count=91; tryItOut("p1 + this.o1.o2.t0;");
/*fuzzSeed-204645237*/count=92; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (y , x);\n    (Int16ArrayView[(((1.5))+(i1)+(i1)) >> 1]) = (-0x38801*((((d0)) % ((Infinity))) < (9.671406556917033e+24)));\n    {\n      d0 = (+((x)>>>((i1)+((((0x12cb0475) % (((0xcbad97ad))>>>((0xfed334b9)))) ^ ((i1)))))));\n    }\n    (Float32ArrayView[((((((0x40b63e9f))>>>((0xe714ae90)))) ? (!(i1)) : ((0xfc4da627) ? (0x4920cc62) : (0x5a393881)))) >> 2]) = ((((Float64ArrayView[2])) * ((-129.0))));\n    {\n      {\n        i1 = (0xb58e517c);\n      }\n    }\n    i1 = (((((((i1))>>>((i1))) == (((0xf752835a)-(0x6942c4b2))>>>((i1))))) | ((0x8d77f99d)+((abs((((0x65404b27)) & ((0xfd4dafde))))|0))+(!((0x94c8d495) ? (0xfb344c6b) : (0xffffffff))))) < (((((i1)+((0x366db07b) > (((0x87861daf))>>>((0x3bd058dd))))) << ((i1)))) >> ((0x29cac038))));\n    return ((((0xbd27c82c))))|0;\n  }\n  return f; })(this, {ff: String.prototype.split}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [1.7976931348623157e308, -(2**53-2), -0, 42, 1, 0x100000000, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, Math.PI, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53+2, 0x0ffffffff, -(2**53+2), 0/0, -0x100000000, -0x0ffffffff, -(2**53), 0, 0x100000001, 0x080000001, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 2**53-2, 1/0, 2**53]); ");
/*fuzzSeed-204645237*/count=93; tryItOut("mathy1 = (function(x, y) { return (( - ( + Math.acosh(( + Math.log1p(( ~ x)))))) >>> 0); }); testMathyFunction(mathy1, ['\\0', undefined, [], (new Boolean(true)), /0/, ({valueOf:function(){return '0';}}), (function(){return 0;}), -0, false, NaN, (new String('')), null, ({valueOf:function(){return 0;}}), [0], objectEmulatingUndefined(), (new Boolean(false)), true, (new Number(0)), 0, (new Number(-0)), 1, '/0/', ({toString:function(){return '0';}}), 0.1, '', '0']); ");
/*fuzzSeed-204645237*/count=94; tryItOut("function shapeyConstructor(vsakea){Object.defineProperty(this, \"13\", ({}));if (vsakea) Object.preventExtensions(this);Object.defineProperty(this, new String(\"-16\"), ({configurable: false, enumerable: true}));this[\"values\"] = ( /x/g [\"valueOf\"] = vsakea);{ /*tLoop*/for (let y of /*MARR*/[null, eval, eval,  /x/ ,  /x/ ,  \"use strict\" ,  \"use strict\" ,  /x/ ,  /x/ , null,  \"use strict\" , null, eval, null]) { print(-25); } } if (vsakea) delete this[\"call\"];Object.defineProperty(this, \"13\", ({value: ((x).call((encodeURI).call([,], -9), )), writable: (let (y) \"\\u27AD\"), enumerable: false}));this[\"13\"] = /*wrap1*/(function(){ const vsakea, x;print(x);return Date.prototype.getSeconds})();return this; }/*tLoopC*/for (let c of /*FARR*/[/*UUV2*/(setter.sup = setter.toString),  '' , Float64Array, a = new RegExp(\"\\\\3\", \"gyim\"), (x+=this).yoyo((intern(window.unwatch(\"getInt8\")))), , x, ++x]) { try{let olmkou = shapeyConstructor(c); print('EETT'); g0.v1.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) { var r0 = 9 % a0; var r1 = a3 / 7; a2 = 0 / a7; var r2 = a0 | a6; var r3 = a2 * a7; var r4 = 0 % c; var r5 = a2 / a2; var r6 = 7 * a6; var r7 = r0 | 8; olmkou = 8 | a4; a7 = 9 + 1; a0 = 2 * 1; var r8 = a7 | a0; var r9 = x - r5; var r10 = 3 + 3; var r11 = 7 ^ a2; var r12 = r7 & 5; a2 = r11 % a9; var r13 = 5 * x; var r14 = a4 % 4; x = 8 | a4; var r15 = r0 * r0; var r16 = 1 & 7; var r17 = 7 / 0; var r18 = r5 - 9; var r19 = r6 + r16; var r20 = r14 ^ 5; var r21 = r14 ^ 3; var r22 = r12 - r19; return a9; });\nthis.s1 = '';\n}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-204645237*/count=95; tryItOut("let (Math.round(new RegExp(\"(?:\\\\x7d)|$[]?(?!\\\\3[])?{3,}\", \"y\")));delete g1[\"this\"];");
/*fuzzSeed-204645237*/count=96; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.sign((((( ! Math.fround((( + -0x100000001) >>> 0))) >>> 0) && ( + (( + (Math.imul((Math.hypot(( + ( ~ x)), ( + ( + Math.log2(( + Number.MAX_SAFE_INTEGER))))) >>> 0), (Math.fround(Math.sin(x)) >>> 0)) >>> 0)) === ( + x)))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), false, (void 0), false, (void 0), false, new Boolean(true), new Boolean(true), Number.MAX_VALUE, new Boolean(true), false, new Boolean(true), Number.MAX_VALUE, (void 0), (void 0), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), Number.MAX_VALUE, new Boolean(true), Number.MAX_VALUE, (void 0), (void 0), new Boolean(true), (void 0), (void 0), false, (void 0), Number.MAX_VALUE, (void 0), new Boolean(true), (void 0), new Boolean(true), false, false, (void 0), false, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, (void 0), new Boolean(true), false, (void 0), Number.MAX_VALUE, new Boolean(true), Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, false, new Boolean(true), (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, Number.MAX_VALUE, new Boolean(true), new Boolean(true), new Boolean(true), Number.MAX_VALUE, new Boolean(true), Number.MAX_VALUE, false, false, Number.MAX_VALUE, (void 0), false, false, Number.MAX_VALUE, new Boolean(true), (void 0), new Boolean(true), Number.MAX_VALUE, false, (void 0), false, false, (void 0), Number.MAX_VALUE, (void 0), false, new Boolean(true), false, (void 0), Number.MAX_VALUE, (void 0), (void 0), new Boolean(true), false, (void 0), new Boolean(true), Number.MAX_VALUE, new Boolean(true), new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-204645237*/count=97; tryItOut("\"use strict\"; { void 0; void gc(this); }");
/*fuzzSeed-204645237*/count=98; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( - ( ~ Math.fround(Math.acos(Math.fround(Math.fround(Math.fround(1/0))))))) | Math.asinh(Math.fround((y || (Math.pow((2**53 >>> 0), -(2**53-2)) !== x))))); }); testMathyFunction(mathy0, [-0, -1/0, 42, -0x080000000, -0x100000001, 1, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, -0x100000000, Math.PI, 0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, 2**53, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, 0x080000001, -(2**53), 0x07fffffff, 0, -0x080000001, 0x0ffffffff, 1/0]); ");
/*fuzzSeed-204645237*/count=99; tryItOut("\"use strict\"; function shapeyConstructor(lkygkh){Object.defineProperty(this, \"__count__\", ({enumerable: true}));return this; }/*tLoopC*/for (let w of e =>  { return ((window) = Object.defineProperty(c, \"filter\", ({value: [,], writable: false})\u000c)) ? (makeFinalizeObserver('nursery')) : e.watch(\"of\", (new Function(\"(25);\"))) } ) { try{let frykhu = new shapeyConstructor(w); print('EETT'); s1 += s0;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-204645237*/count=100; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(t2, new String(\"11\"), { configurable: true, enumerable: false, writable: (x % 6 != 0), value: t2 });");
/*fuzzSeed-204645237*/count=101; tryItOut("for(let c = \"\\uF03E\" in function ([y]) { }) a2 = arguments.callee.caller.arguments;");
/*fuzzSeed-204645237*/count=102; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.fround((Math.expm1(Math.min((( + Math.pow(( + x), (Math.fround(( + Math.fround(y))) , y))) << ( + Math.cosh((x | Math.fround(0x080000001))))), ( ! 1.7976931348623157e308))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[new Boolean(false), -0x100000001, -0x100000001, (-1/0), -0x100000001, (-1/0), (-1/0), (0/0), (-1/0), (-1/0)]); ");
/*fuzzSeed-204645237*/count=103; tryItOut("testMathyFunction(mathy0, [0x100000000, -1/0, Number.MAX_VALUE, 2**53+2, 0/0, 1.7976931348623157e308, 0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, 0x07fffffff, Number.MIN_VALUE, -0x080000000, -0, 2**53-2, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, 42, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, 0, -0x100000000, 0x080000001, -(2**53), -0x100000001, 2**53, -0x0ffffffff, -0x07fffffff, -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=104; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - ( + Math.max(( + Math.hypot((Math.min(y, y) | 0), y)), Math.sinh(Math.atan((42 >>> 0)))))); }); testMathyFunction(mathy0, [-1/0, 2**53+2, -0x0ffffffff, 0.000000000000001, 2**53, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, -Number.MAX_VALUE, 0x100000001, -0, 0, 2**53-2, 1.7976931348623157e308, 1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -(2**53+2), Number.MAX_VALUE, -Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, -(2**53-2), 0x07fffffff, Math.PI, Number.MIN_VALUE, 0x080000000, -0x100000000, -0x080000000, 1]); ");
/*fuzzSeed-204645237*/count=105; tryItOut("\"use strict\"; if(false) {/*bLoop*/for (fgfbcu = 0; fgfbcu < 34; ++fgfbcu) { if (fgfbcu % 40 == 14) { (window); } else { throw this; }  }  } else  if ((Object.defineProperty(x, \"10\", ({get: WeakMap, set: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: TypeError, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { return undefined }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: String.prototype.endsWith, }; })})))) {/*infloop*/for(c; (Promise()); ((function fibonacci(buhhxk) { \"\\u695F\";; if (buhhxk <= 1) { ; return 1; } ; return fibonacci(buhhxk - 1) + fibonacci(buhhxk - 2);  })(3))) Array.prototype.shift.apply(this.a2, []); }");
/*fuzzSeed-204645237*/count=106; tryItOut("s2 + '';");
/*fuzzSeed-204645237*/count=107; tryItOut("{ void 0; setIonCheckGraphCoherency(false); } Array.prototype.reverse.call(a0, m0);");
/*fuzzSeed-204645237*/count=108; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.fround((( + (mathy2(( + ( + y)), ( + (( + x) || ( + x)))) | 0)) % Math.fround((mathy1((Math.sign(((x , Math.hypot((0x100000000 >>> 0), y)) >>> 0)) | 0), (( ~ (Math.atan(Math.cbrt(x)) >>> 0)) | 0)) | 0))))); }); testMathyFunction(mathy4, [/0/, true, ({toString:function(){return '0';}}), null, ({valueOf:function(){return '0';}}), NaN, '', (new Number(-0)), -0, '\\0', (new String('')), (new Number(0)), (function(){return 0;}), 1, '0', false, 0.1, (new Boolean(true)), [0], [], (new Boolean(false)), 0, undefined, objectEmulatingUndefined(), '/0/', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-204645237*/count=109; tryItOut("mathy0 = (function(x, y) { return Math.hypot(Math.min((Math.asin((( ~ Math.imul(y, ( + x))) >>> 0)) >>> 0), Math.fround(Math.asin(Math.fround((( ! y) >>> 0))))), ((((Math.max(((x === y) ^ x), Math.acosh(Math.fround((Math.fround((Math.max(x, y) >>> 0)) ? Math.fround(( ! x)) : (( ~ ((Math.asinh((x >>> 0)) >>> 0) >>> 0)) >>> 0))))) >>> 0) | 0) , Math.pow((Math.min((-0 ? (x >>> 0) : (y >>> 0)), ((( + (Math.cbrt(( + ( + (-Number.MAX_SAFE_INTEGER & ( + x))))) >>> 0)) | 0) >>> 0)) >>> 0), ( - x))) | 0)); }); ");
/*fuzzSeed-204645237*/count=110; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -0x080000001, 2**53+2, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), -0x0ffffffff, -0x080000000, 0x080000001, -Number.MAX_VALUE, 1, Math.PI, 0/0, 2**53, Number.MAX_VALUE, 2**53-2, -(2**53-2), -1/0, 0x07fffffff, -0, 0x080000000, -0x07fffffff, 0x100000001, 42, 0x0ffffffff, -0x100000001, -0x100000000, 1.7976931348623157e308, 1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=111; tryItOut("\"use strict\"; for(let z = (uneval(window)) in ({a1:1})) v0 = this.b2.byteLength;");
/*fuzzSeed-204645237*/count=112; tryItOut("this.e0.has(this.f1);");
/*fuzzSeed-204645237*/count=113; tryItOut("mathy4 = (function(x, y) { return (( + ( ! ( ! Math.fround(x)))) < Math.cos((Math.tanh((y | 0)) | 0))); }); testMathyFunction(mathy4, [2**53-2, -(2**53+2), 0.000000000000001, 0/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0x100000000, -0x0ffffffff, 0x100000000, 1.7976931348623157e308, 1, 42, 2**53, -1/0, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 1/0, 0x080000001, 0x0ffffffff, -0x07fffffff, 2**53+2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0, -(2**53-2), 0, -0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-204645237*/count=114; tryItOut("s2 = '';");
/*fuzzSeed-204645237*/count=115; tryItOut("do for(a in -3) ( '' ); while((x) && 0);");
/*fuzzSeed-204645237*/count=116; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.exp(((((Math.min((( ~ (-Number.MAX_VALUE >>> 0)) >>> 0), y) ? Math.imul(y, x) : mathy4((y , x), Math.acos(( + (Math.max(x, ( + x)) | 0))))) >>> 0) ? (Math.pow((( + x) % y), Math.imul(x, Math.fround(( + Math.min((( + x) | 0), x))))) & Math.fround((Math.min(y, (-(2**53-2) || (( + ((1/0 && x) >>> 0)) >>> 0))) | 0))) : (Math.imul(x, mathy2((x ? y : ( + Math.max(( + 1.7976931348623157e308), 0x080000001))), x)) | 0)) >>> 0)); }); testMathyFunction(mathy5, [1/0, 2**53-2, 0x07fffffff, 2**53+2, -(2**53-2), 0x080000001, Number.MAX_VALUE, 0x0ffffffff, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0, -0, -(2**53+2), -Number.MIN_VALUE, -0x080000001, -0x100000001, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -0x100000000, -0x080000000, -0x07fffffff, Math.PI, 2**53, 0x100000000, 0x100000001, 0/0, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=117; tryItOut("/*bLoop*/for (var kosfyd = 0; kosfyd < 105; ++kosfyd) { if (kosfyd % 9 == 4) { /*RXUB*/var r = /(?=(?:($)))[\u0006-_\\s\\S]+\\d?/gyi; var s = \"\\u95da0000aaa\"; print(s.match(r));  } else { /*RXUB*/var r = new RegExp(\"(?!\\\\2*(?:^?))+?\", \"gi\"); var s = \"\\u00ac\\u00ac\\u00ac\"; print(s.search(r));  }  } ");
/*fuzzSeed-204645237*/count=118; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((( + Math.ceil(Math.fround(Math.fround(Math.clz32((Math.pow((Math.pow(( + Math.fround(( ~ Math.fround(Math.fround(mathy3(-Number.MIN_VALUE, 2**53)))))), y) >>> 0), Math.fround((( ! ( - x)) >>> 0))) >>> 0)))))) ? ( + (Math.hypot((( + ((x >= (y * 0x080000000)) <= mathy0(( + (Math.fround(( + y)) / y)), (Math.atan2(mathy1(y, ( + Math.max(-0x080000000, Number.MAX_VALUE))), Math.asinh(y)) | 0)))) | 0), (Math.fround(Math.max(( ~ (Math.sin(y) >>> 0)), Math.fround(Math.fround(Math.hypot((y && Math.atan(y)), Math.fround(( ~ -Number.MAX_SAFE_INTEGER))))))) | 0)) | 0)) : ( + ( ~ Math.fround(( ~ Math.fround(Math.atan(Math.hypot(( ! ( + ( + y))), Math.asin(y))))))))) | 0); }); testMathyFunction(mathy4, /*MARR*/[(((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), 4., (((d *= d)()))(), 4., (((d *= d)()))(), (((d *= d)()))(), 4., (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), 4., 4., (((d *= d)()))(), 4., (((d *= d)()))(), (((d *= d)()))(), 4., 4., (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), 4., (((d *= d)()))(), 4., 4., (((d *= d)()))(), 4., (((d *= d)()))(), 4., 4., (((d *= d)()))(), (((d *= d)()))(), 4., (((d *= d)()))(), 4., (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), 4., 4., 4., 4., (((d *= d)()))(), (((d *= d)()))(), (((d *= d)()))(), 4., (((d *= d)()))(), (((d *= d)()))(), 4., 4., (((d *= d)()))(), 4., 4., (((d *= d)()))(), 4., 4., 4., 4.]); ");
/*fuzzSeed-204645237*/count=119; tryItOut("\"use strict\"; const z = (4277), mmtpxr, \u3056 = (delete this.w.x), x = let (hzfwnu, window, ezruei, d, x, mxaore, dycefx) ((eval) = new RegExp(\"\\\\b|\\\\3{0}(?=(?!\\\\2))+?|(?:$)\\\\B([^]){1,}|$+\", \"gyim\")), x = x;f0 + e2;");
/*fuzzSeed-204645237*/count=120; tryItOut("\"use strict\"; print(a2);");
/*fuzzSeed-204645237*/count=121; tryItOut("t0 = t0.subarray(12);");
/*fuzzSeed-204645237*/count=122; tryItOut("Array.prototype.unshift.apply(a1, [m2, m0, t1, f0]);o1 = e2.__proto__;");
/*fuzzSeed-204645237*/count=123; tryItOut("x.message;");
/*fuzzSeed-204645237*/count=124; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    /*FFI*/ff(((d0)), ((imul((i4), (((Float64ArrayView[((-0x8000000)) >> 3])) > (147573952589676410000.0)))|0)), ((-70368744177665.0)), ((new WeakMap())));\n    switch ((imul((0xff627fd4), ((0x1dea7888) <= (0x4c58ec9a)))|0)) {\n      default:\n        {\n          return ((-(i2)))|0;\n        }\n    }\n    return (((i3)))|0;\n  }\n  return f; })(this, {ff: function (z) { yield z; } }, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Math.PI, 0, -0x07fffffff, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, 2**53+2, 0x100000000, -Number.MIN_SAFE_INTEGER, 1, -0x080000001, Number.MAX_VALUE, -0x100000000, -(2**53), 2**53, 42, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 1.7976931348623157e308, 0x100000001, -0x100000001, Number.MIN_VALUE, -0, -1/0, 0x0ffffffff, 0x080000001, -(2**53-2), 0.000000000000001, 2**53-2, 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=125; tryItOut("\"use strict\"; o0 = new Object;");
/*fuzzSeed-204645237*/count=126; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (/*FFI*/ff(((Infinity)), ((~~(-1.5))), ((+/*FFI*/ff((((4294967297.0))), ((-3.8685626227668134e+25)), (((i1) ? (262145.0) : (4095.0)))))), ((295147905179352830000.0)), ((-524289.0)))|0);\n    {\n      {\n        i2 = (((((x) < ((((0xa4ae694a) ? (0x7ab976bf) : (0xe84d54d0)))>>>((i1))))+(i0)) << ((undefined ? (Proxy()) : x)+((-2147483647.0) != (-3.022314549036573e+23))+((0xffffffff)))) == (~((i0))));\n      }\n    }\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53+2), 0/0, -(2**53-2), -(2**53), 0x0ffffffff, 2**53+2, 0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, Number.MIN_VALUE, -0x100000001, 0x080000001, 1, Math.PI, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, -1/0, 1/0, -0x07fffffff, 0.000000000000001, 2**53-2, -0x080000000, -0, 1.7976931348623157e308, 0x100000001, 42, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-204645237*/count=127; tryItOut("o0.v1 = Array.prototype.reduce, reduceRight.apply(a2, [(function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0x10c06448);\n    return ((((imul((1), (i1))|0) <= (0x35307e33))))|0;\n  }\n  return f; })]);");
/*fuzzSeed-204645237*/count=128; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (1.25);\n    i1 = (i1);\n    {\n      i1 = ((void options('strict')));\n    }\n    return ((-(((((d0) == (-7.0))+(0x829c47b9))>>>((0xad550adc)+((((0xffa97350))>>>((0x4d97d142))) == (((0xd429d184))>>>((-0x8000000)))))) >= (0xb6f516d3))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=129; tryItOut("\"use strict\"; v1 = o2.t2.byteOffset;");
/*fuzzSeed-204645237*/count=130; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    /*FFI*/ff(((+(1.0/0.0))));\n    return +((d0));\n  }\n  return f; })(this, {ff: (Map.prototype.forEach).bind(Uint8ClampedArray( \"\" \n))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [objectEmulatingUndefined(), NaN, '', true, (new Boolean(false)), '\\0', 0, false, '/0/', 1, -0, [0], (new Number(-0)), ({valueOf:function(){return '0';}}), undefined, null, ({toString:function(){return '0';}}), [], ({valueOf:function(){return 0;}}), (new Number(0)), 0.1, (new String('')), (function(){return 0;}), '0', (new Boolean(true)), /0/]); ");
/*fuzzSeed-204645237*/count=131; tryItOut("/*ADP-3*/Object.defineProperty(this.a2, 2, { configurable: (4277), enumerable: ([{x, d, x: [{e: {eval: [{e: {}}]}}, ]}, ] = [eval = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return false; }, fix: function() { }, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: (eval).bind, set: function() { return false; }, iterate: undefined, enumerate: function(y) { yield y; ; yield y; }, keys: function() { return Object.keys(x); }, }; })( \"\" ), /n+/gyi)]), writable: true, value: h2 });");
/*fuzzSeed-204645237*/count=132; tryItOut("(4277);let z = new RegExp(\"(?=((?!\\\\w|([^]))))|$\", \"yim\");function NaN(x, x) { yield (4277) } v0 = o2.g2.eval(\"a1.pop(v2, o2.f1);\");");
/*fuzzSeed-204645237*/count=133; tryItOut("mathy2 = (function(x, y) { return ( ! ((-Number.MIN_VALUE > Math.fround(y)) && Math.fround((((x >>> 0) | Math.fround((((x ? -0x080000000 : Math.min((mathy1((y | 0), (0x07fffffff | 0)) | 0), Math.fround(y))) > Math.fround(2**53-2)) | 0))) | 0)))); }); testMathyFunction(mathy2, [true, [], ({valueOf:function(){return 0;}}), undefined, NaN, '\\0', (new Boolean(true)), 0, (function(){return 0;}), [0], false, 1, null, '', objectEmulatingUndefined(), /0/, (new String('')), (new Boolean(false)), '/0/', (new Number(-0)), '0', ({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}}), -0, 0.1]); ");
/*fuzzSeed-204645237*/count=134; tryItOut("mathy3 = (function(x, y) { return ((( ~ (( + ( + (x | 0))) >>> 0)) >>> 0) ^ ( + ( + ( + Math.fround(( ! Math.fround(( ! y)))))))); }); testMathyFunction(mathy3, [-0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, -0, -0x07fffffff, Math.PI, -Number.MIN_VALUE, -(2**53-2), 2**53, -0x080000000, 2**53-2, -0x0ffffffff, 1, Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 0x100000000, 1/0, Number.MAX_VALUE, 0, 0.000000000000001, 0x0ffffffff, -1/0, 0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, 0x100000001, -0x100000001]); ");
/*fuzzSeed-204645237*/count=135; tryItOut("\"use strict\"; o0.v1 = g1.runOffThreadScript();");
/*fuzzSeed-204645237*/count=136; tryItOut("{o0.a2 = this.a2.map((function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var imul = stdlib.Math.imul;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (-1025.0);\n    d0 = (((Float32ArrayView[((i2)-(i1)) >> 2])) % (((i2) ? (((Float32ArrayView[((0xffffffff)*0xa0d98) >> 2])) % ((d0))) : (-((+(((Int8ArrayView[4096])) & ((i2)))))))));\n    i2 = (i1);\na1 = [];    i2 = (!(i1));\n    i2 = (i1);\n    i1 = ((0xa750496) < (((0x6b7f99b7)) << (0xb4cb1*(0xe6d2a3c4))));\n    (Int16ArrayView[0]) = ((0xf8e31958)-(i1));\n    i2 = (i2);\n    i2 = (i1);\n    {\n      return (((0x3c213d99)))|0;\n    }\n    d0 = (1.0);\n    (Float32ArrayView[0]) = ((+atan(((1.015625)))));\n    {\n      {\n        i1 = (i2);\n      }\n    }\n    i2 = (i1);\n    return ((((0x38d01f84) == ((((0xcd3f1134))-(0xdd284933))>>>((i1))))-(((/*MARR*/[/\\d+?/gim, /\\d+?/gim, null, /\\d+?/gim, /\\d+?/gim, /\\d+?/gim, /\\d+?/gim, /\\d+?/gim, 1e-81, /\\d+?/gim, null, 1e-81, 1e-81, null, /\\d+?/gim, 1e-81, null, 1e-81, null, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, null, /\\d+?/gim, null, 1e-81, null, null, 1e-81, 1e-81, /\\d+?/gim, 1e-81, null, /\\d+?/gim, /\\d+?/gim, null, /\\d+?/gim, 1e-81, null, 1e-81, /\\d+?/gim, 1e-81, null, 1e-81, null, null].filter(Math.atan2(-0, function ([y]) { })))) < (0x34906a5d))))|0;\n    i2 = (i1);\n    d0 = (+(((i2))));\n    (Float64ArrayView[4096]) = ((((0x965b4c09)) ? (274877906945.0) : (-8388607.0)));\n    d0 = (-4.835703278458517e+24);\n    {\n      switch ((0x637ccbcd)) {\n        case -3:\n          i2 = (((((((0x78e5d543)+(0xc3c98e10)-(0xfddc02ce)) ^ ((i1)+(i2))) == (0x41f2be83))*0x9aa4e) & ((i2))));\n          break;\n        default:\n          {\n            d0 = (d0);\n          }\n      }\n    }\n    (Int16ArrayView[((Uint32ArrayView[((!((73786976294838210000.0) != (-1024.0)))-(0xfa5c61d2)) >> 2])) >> 1]) = ((i1));\n    switch ((((i1)) & ((0xf8565f69)))) {\n      case -2:\n        i1 = (!((-0x1fcc870) ? (i2) : (i2)));\n        break;\n      case 1:\n        (Uint8ArrayView[((0x3320d4cd)) >> 0]) = (((x) > ((((imul((i2), (!(-0x8000000)))|0) != (((0x13dac2d8)+(-0x8000000)) >> ((-0x8000000)*0x29a58)))*0x48d07)>>>(((((i2))>>>((Uint8ArrayView[2]))) < (((((0x8a020021))>>>((0xffffffff))) % (0xffffffff))))+(i1)))));\n        break;\n    }\n    i1 = ((timeout(1800)));\n    d0 = (((imul((0x26001e09), (-0x8000000))|0) >= (((i2)) & ((i2)))) ? (9.671406556917033e+24) : (+(((0x7ef3*(0xc3329f5f))))));\n    {\n      (Float64ArrayView[((i2)) >> 3]) = ((d0));\n    }\n    return (((0x2e75c3a3)-(!(i1))-((((i2)) >> ((0x85b0a793))))))|0;\n  }\n  return f; }), e1); }");
/*fuzzSeed-204645237*/count=137; tryItOut("g1 + '';");
/*fuzzSeed-204645237*/count=138; tryItOut("/*RXUB*/var r = o1.r1; var s = \"\\uc282\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=139; tryItOut("\"use strict\"; let(x) { with({}) let(z, lkbsgk, jrvpnk, uopevp, x) ((function(){print(\"\\uCE0B\");})());}for(let z in []);");
/*fuzzSeed-204645237*/count=140; tryItOut("Array.prototype.forEach.call(g1.o0.a2, (function(j) { f0(j); }), e2, a1);");
/*fuzzSeed-204645237*/count=141; tryItOut("\"use asm\"; delete h2.get;");
/*fuzzSeed-204645237*/count=142; tryItOut("v2 = r1.compile;var mmwmxr = new SharedArrayBuffer(6); var mmwmxr_0 = new Int32Array(mmwmxr); print(mmwmxr_0[0]); var mmwmxr_1 = new Int16Array(mmwmxr); yield new RegExp(\"\\\\3|(?=(?:\\\\B)|[^\\\\uDCA3\\\\D\\\\cA-\\\\xAD\\ue49b]|\\\\0+?..)([^])\", \"yi\");");
/*fuzzSeed-204645237*/count=143; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((((Math.sqrt((x >>> 0)) | (((Math.fround(Math.fround(( + Math.asinh(Math.log(x))))) | 0) > ( + ( + (1.7976931348623157e308 , (x | 0))))) >>> 0)) >>> 0) ? (Math.imul((x | 0), ( + ( + (( + x) >= x)))) >>> 0) : Math.pow(0.000000000000001, Math.fround(mathy2((-(2**53-2) | 0), (((x >>> 0) < (y >>> 0)) >>> 0))))) === ( + mathy3((Math.imul(( + 0x080000000), Math.pow(x, Math.log1p(Math.atan2(Math.pow(1, y), x)))) | 0), ((Math.atanh((((Math.sqrt(Math.pow(y, y)) | 0) === (Math.min(-0x0ffffffff, ( + -1/0)) | 0)) | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy4, /*MARR*/[let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], function(){}, new Number(1.5), NaN, function(){}, function(){}, this, let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], new Number(1.5), new Number(1.5), this, new Number(1.5), this, function(){}, let (b) [new ( \"\" )(window)], function(){}, NaN, let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], NaN, function(){}, NaN, new Number(1.5), let (b) [new ( \"\" )(window)], function(){}, function(){}, NaN, let (b) [new ( \"\" )(window)], function(){}, NaN, let (b) [new ( \"\" )(window)], new Number(1.5), function(){}, new Number(1.5), this, this, function(){}, let (b) [new ( \"\" )(window)], NaN, let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], let (b) [new ( \"\" )(window)], new Number(1.5), function(){}, let (b) [new ( \"\" )(window)], this, new Number(1.5), let (b) [new ( \"\" )(window)], NaN, this, function(){}, this, new Number(1.5), function(){}, function(){}, new Number(1.5), let (b) [new ( \"\" )(window)], NaN, NaN, this, NaN, function(){}, NaN, NaN, function(){}, function(){}, new Number(1.5), let (b) [new ( \"\" )(window)], function(){}, NaN, new Number(1.5), NaN, function(){}, NaN, this, let (b) [new ( \"\" )(window)], this, this, let (b) [new ( \"\" )(window)], new Number(1.5), this, function(){}, new Number(1.5), let (b) [new ( \"\" )(window)], new Number(1.5), function(){}, function(){}, let (b) [new ( \"\" )(window)], NaN, NaN, this, this, NaN, new Number(1.5), this, NaN, new Number(1.5), let (b) [new ( \"\" )(window)], NaN, this, this, new Number(1.5), this, this, let (b) [new ( \"\" )(window)], NaN, function(){}, function(){}, NaN, this, this, this, this, this, let (b) [new ( \"\" )(window)], this, this, function(){}, function(){}, new Number(1.5), function(){}, this, new Number(1.5), new Number(1.5), NaN, this, this, function(){}, NaN, NaN, function(){}, let (b) [new ( \"\" )(window)], this, new Number(1.5), let (b) [new ( \"\" )(window)], NaN, NaN]); ");
/*fuzzSeed-204645237*/count=144; tryItOut("testMathyFunction(mathy5, [0x100000001, -0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 1, -0x100000000, 2**53, 0x100000000, 2**53+2, 1.7976931348623157e308, -0, -(2**53), 42, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, 0.000000000000001, 0x07fffffff, -0x080000001, Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 0/0, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=145; tryItOut("mathy1 = (function(x, y) { return Math.expm1(((mathy0(((Math.min((Math.fround(Math.min(Math.fround(Math.round((Math.atan2((Math.fround((-1/0 << y)) >>> 0), ( + y)) >>> 0))), ((( ! (x | 0)) | 0) < ( ! (( + Math.log1p(( + x))) | 0))))) >>> 0), (((0 - x) && 0/0) >>> 0)) >>> 0) | 0), ( + (( + y) & ( + x)))) | 0) | 0)); }); testMathyFunction(mathy1, [-0x100000000, 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 42, Number.MAX_VALUE, Math.PI, 0x080000001, -(2**53), 1/0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, -(2**53-2), 0/0, 2**53, -(2**53+2), -Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, -0, -0x07fffffff, -0x080000001, 1.7976931348623157e308, -0x080000000, 1, 0, 0.000000000000001, -0x100000001]); ");
/*fuzzSeed-204645237*/count=146; tryItOut("mathy3 = (function(x, y) { return ((Math.cbrt(Math.max(mathy1(( + Math.pow((1 | 0), ( + x))), (-Number.MIN_VALUE ** 0x080000000)), Math.fround(Math.asin((y | 0))))) >>> 0) >>> (mathy0(( + (Math.imul((2**53-2 >>> 0), (Math.fround(Math.fround(Math.fround(42))) >>> 0)) >>> 0)), ( + Math.atan(y))) >>> 0)); }); testMathyFunction(mathy3, [0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0x100000000, -(2**53-2), 0x100000001, -0x07fffffff, 1.7976931348623157e308, -0, -0x080000001, 2**53-2, 1/0, 0x07fffffff, -(2**53+2), -0x080000000, -0x100000000, 2**53+2, 1, 0x0ffffffff, 0, 0.000000000000001, -Number.MIN_VALUE, -1/0, Math.PI, -Number.MAX_VALUE, -0x100000001, 0/0, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-204645237*/count=147; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.trunc((Math.pow((Math.pow((y * (Math.expm1(((( - y) >>> 0) | 0)) | 0)), (( ~ (Math.fround((Math.fround(y) & Math.fround(Math.expm1(y)))) >>> 0)) | 0)) | 0), (Math.min(Math.log(y), y) & x)) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[-0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, new Boolean(true), new Boolean(true), -0x100000000, -0x100000000, -0x100000000]); ");
/*fuzzSeed-204645237*/count=148; tryItOut("/*ADP-1*/Object.defineProperty(this.a1, 19, ({value: delete \u3056.x}));");
/*fuzzSeed-204645237*/count=149; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.hypot(( + (( ! (( + (( + (-(2**53) < ((y >>> 0) > window))) << (y | 0))) | 0)) | 0)), ( + Math.fround((Math.fround((( ~ ( + mathy0(Math.fround((y > (( ! (x >>> 0)) >>> 0))), ( + x)))) >>> 0)) % Math.fround(( + Math.min((Math.fround((Math.fround((mathy0((2**53-2 >>> 0), (Math.clz32(Math.fround(y)) >>> 0)) >>> 0)) > Math.fround(0x100000000))) | 0), ((x ? (y | 0) : 2**53) | 0)))))))); }); ");
/*fuzzSeed-204645237*/count=150; tryItOut("with(x){s0 + '';Array.prototype.forEach.call(a1, (function() { try { e1.add(h2); } catch(e0) { } try { a0.toString = (function() { for (var j=0;j<49;++j) { f2(j%3==0); } }); } catch(e1) { } s2 + ''; return b1; }));\n/*vLoop*/for (var eqvetj = 0; eqvetj < 36; ++eqvetj) { const b = eqvetj; yield; } \n }");
/*fuzzSeed-204645237*/count=151; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=152; tryItOut("s0 = '';");
/*fuzzSeed-204645237*/count=153; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d1);\n    d0 = (d1);\n    return +((d1));\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0, -Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 42, 2**53, -0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x100000000, 0x080000001, -0x0ffffffff, 0x07fffffff, Math.PI, Number.MIN_VALUE, 0/0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 1.7976931348623157e308, -0, -(2**53-2), 0x0ffffffff, -(2**53+2), 0x100000001, 2**53+2, 1, -Number.MIN_VALUE, -0x080000000, 2**53-2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-204645237*/count=154; tryItOut("var fzfufw = new ArrayBuffer(4); var fzfufw_0 = new Float64Array(fzfufw); fzfufw_0[0] = -28; print(fzfufw);print((({/*toXFun*/toSource: function() { return true; }, prototype: 12\u000d })));");
/*fuzzSeed-204645237*/count=155; tryItOut("\"use strict\"; t2 = new Int32Array(3);");
/*fuzzSeed-204645237*/count=156; tryItOut("g0.v0 = t0.byteOffset;");
/*fuzzSeed-204645237*/count=157; tryItOut("testMathyFunction(mathy1, /*MARR*/[(0/0),  /x/ , (0/0), (0/0),  /x/ , (0/0), (0/0), (0/0),  /x/ , (0/0),  /x/ , (0/0),  /x/ ,  /x/ ,  /x/ ]); ");
/*fuzzSeed-204645237*/count=158; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.expm1(Math.imul(mathy1(0x07fffffff, ( ! x)), (Math.max(x, y) % (Math.acos(Math.fround((((x | 0) ** (x | 0)) | 0))) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, 1, 0x0ffffffff, 0, -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, -0x080000001, 1/0, 2**53, -0x100000001, 42, -0, 0x100000000, -Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 0.000000000000001, 0x080000001, 0x080000000, -(2**53-2), 2**53+2, 0/0]); ");
/*fuzzSeed-204645237*/count=159; tryItOut("v1 = evaluate(\"function f0(o1) (4277)\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (new this(x, 7))(), noScriptRval: true, sourceIsLazy: (x % 5 != 1), catchTermination: (void version(170)) }));\nv1 = true;\n");
/*fuzzSeed-204645237*/count=160; tryItOut("\"use strict\"; testMathyFunction(mathy0, [2**53, Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, 1, -0x080000000, 1.7976931348623157e308, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, -Number.MAX_VALUE, 0/0, 2**53+2, 0, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, -0, -(2**53-2), 0x100000001, -0x07fffffff, -Number.MIN_VALUE, 0x100000000, 0.000000000000001, 0x080000000, Number.MAX_VALUE, -0x080000001, -(2**53+2), 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=161; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000001, 2**53+2, 1.7976931348623157e308, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), -0, 2**53-2, -(2**53+2), 0x100000001, 0x080000000, -1/0, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x0ffffffff, -0x07fffffff, 2**53, 0x07fffffff, -(2**53-2), 0.000000000000001, 42, -0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, Math.PI, -0x100000001, 1, 0]); ");
/*fuzzSeed-204645237*/count=162; tryItOut("/*tLoop*/for (let b of /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  '' ,  '' ,  '' ,  '' , function(){},  '' ,  '' ,  '' ,  '' ,  '' , function(){}, function(){}, function(){}, function(){},  '' ,  '' ,  '' ,  '' , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  '' ,  '' ,  '' , function(){},  '' , function(){},  '' , function(){}, function(){},  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , function(){},  '' ,  '' , function(){}, function(){},  '' ,  '' , function(){}, function(){},  '' ,  '' , function(){},  '' , function(){}, function(){}, function(){}, function(){}, function(){},  '' , function(){}, function(){},  '' ,  '' ,  '' , function(){}, function(){}, function(){},  '' , function(){},  '' , function(){}, function(){}, function(){}, function(){}, function(){},  '' , function(){},  '' , function(){}]) { for (var v of a1) { neuter(b1, \"change-data\"); } }");
/*fuzzSeed-204645237*/count=163; tryItOut("for(let e = /*UUV2*/(y.cos = y.slice) in x) {var gogxjw = new ArrayBuffer(8); var gogxjw_0 = new Int16Array(gogxjw); print(gogxjw_0[0]); gogxjw_0[0] = -16; ; }");
/*fuzzSeed-204645237*/count=164; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"$+?|(?=(((.){4,}))(?!\\\\d){1}[^\\\\uB132\\uaf70]{4,7}|${1}|(?:(?=[^\\\\cZ\\u0004-\\ub500])+?))^\", \"gy\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-204645237*/count=165; tryItOut("mathy5 = (function(x, y) { return (((( + Math.fround((Math.fround(Math.hypot((x >>> 0), (( + Math.asin(2**53-2)) >>> 0))) | 0))) - ( + ( + ( + (Math.asin((( + x) | 0)) | 0))))) >>> 0) ** (Math.hypot(( + mathy1(( + Math.pow(y, 42)), (Math.fround((Math.fround(( + Math.sinh(Math.fround(y)))) <= Math.fround((( ~ x) | 0)))) >>> 0))), (Math.atanh((Math.hypot((Math.atan(y) | 0), Math.fround(x)) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [0.000000000000001, -0x080000001, -0x100000000, -(2**53-2), Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0, -(2**53+2), 0x080000000, 0x0ffffffff, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -0, -0x100000001, -1/0, -0x0ffffffff, 1, -Number.MAX_VALUE, 0x080000001, 42, -Number.MIN_VALUE, 0x100000000, 0x07fffffff, -0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), -Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=166; tryItOut("\"use strict\"; a = linkedList(a, 2050);");
/*fuzzSeed-204645237*/count=167; tryItOut("t0 = new Uint8ClampedArray(4);e = ( /* Comment */x);");
/*fuzzSeed-204645237*/count=168; tryItOut("\"\\u9DD4\";");
/*fuzzSeed-204645237*/count=169; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround((Math.fround(mathy1((x % ( ! x)), Math.pow(( + x), x))) != ( ! y))) || (( + ( + (( ! (y >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy2, [-(2**53+2), 0, -0, 0x080000000, -Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53+2, 0x07fffffff, 0x080000001, -0x0ffffffff, 0x0ffffffff, 1, Math.PI, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), 0.000000000000001, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, 2**53-2, -1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=170; tryItOut("m2.set(e2, this.g1);");
/*fuzzSeed-204645237*/count=171; tryItOut("mathy5 = (function(x, y) { return mathy3(Math.fround(Math.fround(mathy0(Math.imul(( + Math.sqrt(((0x080000001 || ((Math.min((-0x07fffffff | 0), x) | 0) & x)) | 0))), y), (( - ( + ( ! (y >>> 0)))) >>> 0)))), Math.fround((Math.fround((Math.round((Math.atanh((Math.min((( + Math.cbrt((x | 0))) | 0), Math.fround((y == 0x100000001))) | 0)) >>> 0)) >>> 0)) || Math.fround(Math.fround(( ! Math.min(x, y))))))); }); testMathyFunction(mathy5, [0x100000000, 0x080000001, 0/0, 0.000000000000001, 1.7976931348623157e308, 2**53, -0x100000000, -Number.MAX_VALUE, -(2**53+2), 2**53-2, -(2**53-2), 0x100000001, -0x080000001, -1/0, 0x07fffffff, Math.PI, -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, 0x0ffffffff, -0, -Number.MIN_VALUE, 1/0, -0x07fffffff, 0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 1]); ");
/*fuzzSeed-204645237*/count=172; tryItOut("for (var p in g2) { try { Array.prototype.splice.apply(a2, [NaN, 19, g1.g1.t2]); } catch(e0) { } o1.v0 = g0.runOffThreadScript(); }");
/*fuzzSeed-204645237*/count=173; tryItOut("mathy3 = (function(x, y) { return (Math.fround(( + Math.fround(Math.fround(Math.asinh(Math.fround(-0)))))) & mathy1((( ! y) | 0), (( + Math.atan2(Math.fround(mathy2((0x080000001 > y), Math.fround(-0x080000000))), (Math.imul(Math.hypot((Math.ceil((x | 0)) | 0), x), y) >>> 0))) | ( ! (mathy2(Math.fround(y), Math.fround(x)) | 0))))); }); ");
/*fuzzSeed-204645237*/count=174; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(Math.atanh(((((( + y) ? y : Math.pow(Number.MIN_SAFE_INTEGER, (Math.imul(y, y) != 0.000000000000001))) > (x | 0)) | 0) >>> 0))), ((( + ((( - (Math.hypot(( + Math.acos(( + x))), 1.7976931348623157e308) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy0, [-(2**53), 0/0, -1/0, 0x07fffffff, -0x100000000, Math.PI, 1/0, 0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, -Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, -(2**53-2), 2**53-2, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, -0x080000000, 0x080000000, 2**53+2, -0x080000001, -Number.MAX_VALUE, 0.000000000000001, 0x100000001, Number.MAX_VALUE, -0x0ffffffff, -0, -0x100000001, -(2**53+2), 42, 2**53]); ");
/*fuzzSeed-204645237*/count=175; tryItOut("wzoprd(/*wrap3*/(function(){ \"use strict\"; var magxju = arguments; (function(y) { h0.delete = f1; })(); })( \"\" ,  /x/g ));/*hhh*/function wzoprd(x){g2.offThreadCompileScript(\"function f1(h2)  { \\\"use strict\\\"; g0.v2 = new Number(4.2); } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 26 != 13), catchTermination: true, element: o2, sourceMapURL: s0 }));}");
/*fuzzSeed-204645237*/count=176; tryItOut("/*RXUB*/var r = /(?=\\B+){2,2}\\d|(((?=\\3{4}))){3}(?=(?:\u00e7))++?|\\B?[^]?/gyi; var s = \"_\\u00e7\\u00e7\\u00e7\\u00e7\\u00e7\\u00e7\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=177; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(((Math.hypot(-(2**53+2), ( ! x)) << (y >= Math.hypot(Math.round(0x100000000), ( + y)))) && (( + ( ~ ( + (((0x080000001 | 0) ? (Math.log((y | 0)) | 0) : ((Math.imul(( + x), (x >>> 0)) >>> 0) | 0)) | 0)))) >>> 0))) || Math.pow((((y >>> 0) && ( - ( + 0x080000001))) >>> 0), (mathy2((x | (x >>> 0)), ( + 0x080000000)) > Math.fround(x)))); }); testMathyFunction(mathy5, [42, 0x07fffffff, 1/0, -0x100000001, -0x080000000, 0x080000000, -Number.MIN_VALUE, -0x080000001, 0x100000000, -0x07fffffff, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -(2**53-2), 0/0, 0x0ffffffff, 0, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -0x100000000, 0x080000001, 0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -(2**53), -1/0, -Number.MAX_SAFE_INTEGER, 2**53, Math.PI, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=178; tryItOut("h1.toString = (function() { for (var j=0;j<28;++j) { f2(j%4==1); } });");
/*fuzzSeed-204645237*/count=179; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.hypot((((( + Math.fround(1)) | 0) >>> ( + (Math.expm1(( + Math.pow(x, y))) | 0))) | 0), ((( ~ Math.fround(mathy1(( + Math.fround(( - Math.pow((Math.pow(( + y), ( + y)) | 0), Math.fround(x))))), Math.pow((mathy4(x, y) >>> 0), ((Math.cosh((x >>> 0)) >>> 0) | 0))))) | 0) | 0)); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, Math.PI, 0x100000000, 0, -(2**53+2), 0x080000000, 1/0, -0x100000001, -0x080000001, 2**53-2, 42, -0, 2**53, -1/0, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, 0.000000000000001, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, -0x07fffffff, 0/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, -0x100000000, -(2**53)]); ");
/*fuzzSeed-204645237*/count=180; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.max((Math.fround(Math.pow(mathy0((y | 0), Math.acos(x)), ( + Math.atan2((((x >>> 0) - y) | 0), Math.asinh(( + ( ~ y))))))) >>> Math.imul(Math.cos((Math.round((x >>> 0)) >>> 0)), (y ** ( + (-0x080000001 ? ( + Math.cos(x)) : ( + ( + (Number.MIN_SAFE_INTEGER ? ( + 0x0ffffffff) : x)))))))), ( + Math.atan2(Math.log((((Math.max((( + Math.acosh(( + y))) >>> 0), Math.trunc(Math.pow(x, x))) | 0) && ((y - (Math.min((mathy0(2**53+2, Math.fround(1)) >>> 0), (x >>> 0)) >>> 0)) | 0)) | 0)), ( + Math.acos((mathy0(y, ( - Math.pow(x, ( + -0x100000001)))) | 0)))))) >>> 0); }); ");
/*fuzzSeed-204645237*/count=181; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return ( + mathy0(( + Math.imul(( + mathy1(( + (Math.fround(( + ( ! ( + Math.clz32(Math.log10(( + y))))))) ? Math.fround(mathy1(Math.fround(( ! 0x100000000)), Math.hypot(1/0, Number.MAX_VALUE))) : ( + ((Math.ceil((x >>> 0)) >>> 0) >>> 0)))), ( + (((Math.min(x, Number.MAX_SAFE_INTEGER) | 0) <= (( + ( + Math.ceil(( + x)))) | 0)) | 0)))), Math.cosh((Math.atan2((x | 0), (42 | 0)) | 0)))), ( + ((Math.hypot(-0x0ffffffff, ( + mathy2(( + x), x))) !== ((Math.sqrt((( - x) >>> 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy3, [0x07fffffff, 0x080000001, 1/0, 0.000000000000001, -0x100000000, -0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, 0x080000000, 0x0ffffffff, 2**53+2, -0x100000001, -Number.MAX_VALUE, -0x080000000, -1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, 0/0, -(2**53+2), 1.7976931348623157e308, 2**53-2, 0, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, Number.MAX_VALUE, -(2**53), 42, 1, -Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=182; tryItOut("v0 + '';");
/*fuzzSeed-204645237*/count=183; tryItOut("mathy3 = (function(x, y) { return Math.asin(((( + ((((x | 0) != (42 | 0)) | 0) ? x : -0x080000000)) !== ((x >>> 0) | (Math.imul(x, ((Number.MAX_VALUE >>> 0) || (x >>> 0))) >>> 0))) % (( + Math.log1p((x >>> 0))) | 0))); }); testMathyFunction(mathy3, [0x080000000, 0x0ffffffff, 0/0, Number.MAX_VALUE, 2**53+2, 0.000000000000001, -0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 1/0, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 0x07fffffff, 0x080000001, -Number.MAX_VALUE, -0, -0x100000001, 1.7976931348623157e308, 1, 0x100000001, 2**53-2, -1/0, Math.PI, -0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, 42, 0, -0x080000000, 0x100000000, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=184; tryItOut("testMathyFunction(mathy1, [1/0, -0x080000001, Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 42, Math.PI, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53), 2**53, 1, -0x100000000, 0x100000000, -Number.MAX_VALUE, -0x080000000, 0x080000001, 0x080000000, 0.000000000000001, -0x0ffffffff, -0, 0/0, -0x100000001, 1.7976931348623157e308, -(2**53+2), 0x0ffffffff, Number.MIN_VALUE, 0x100000001, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, 0x07fffffff]); ");
/*fuzzSeed-204645237*/count=185; tryItOut("Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-204645237*/count=186; tryItOut("testMathyFunction(mathy0, [Number.MIN_VALUE, 2**53, 1.7976931348623157e308, 0.000000000000001, 0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0x080000001, -1/0, -0, -0x0ffffffff, Math.PI, 0/0, 42, -Number.MIN_VALUE, 1/0, -(2**53+2), 1, 0x080000000, -0x100000000, -0x080000000, -0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x080000001, -0x100000001, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=187; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.imul(( + mathy0((mathy0((Math.fround((Math.fround((Math.sqrt((mathy0(Math.tanh(x), -0x0ffffffff) | 0)) | 0)) ? -Number.MAX_SAFE_INTEGER : (Math.expm1(Math.atan2(x, -0x100000000)) | 0))) | 0), ((( + Math.asin(x)) >= Math.fround(mathy0(Math.fround((Math.min(x, ( + y)) | 0)), Math.fround(Math.atan2(x, 2**53+2))))) | 0)) | 0), ( + ( - (y <= y))))), Math.log(( + (Math.round((Math.fround((2**53 + (Math.asin((-0x100000000 | 0)) | 0))) | 0)) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-204645237*/count=188; tryItOut("t2[16];");
/*fuzzSeed-204645237*/count=189; tryItOut("for (var v of o1) { this.s0.__proto__ = m1; }");
/*fuzzSeed-204645237*/count=190; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[objectEmulatingUndefined(), 0x100000001, 0x100000001, objectEmulatingUndefined()]); ");
/*fuzzSeed-204645237*/count=191; tryItOut("testMathyFunction(mathy4, [(new String('')), ({valueOf:function(){return '0';}}), (new Boolean(true)), [], '0', '', '/0/', (new Number(-0)), (new Boolean(false)), null, 0.1, objectEmulatingUndefined(), 1, false, '\\0', true, NaN, 0, -0, (new Number(0)), [0], /0/, undefined, ({toString:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-204645237*/count=192; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=193; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = \"\\n\\n\\n\\n\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=194; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.max(( + Math.ceil(Math.fround(Math.hypot((( + Math.round(( + ( + (y | 0))))) >>> 0), (Math.pow(Math.fround(-0x100000000), Math.fround(Math.max(x, -0x100000000))) >>> 0))))), (Math.fround(Math.atanh(( + ( ~ mathy4(Math.min(y, (y | 0)), x))))) ^ Math.atan2(Math.cos(((( + ((y > y) != x)) <= (((Math.fround(y) ^ x) | 0) >>> 0)) >>> 0)), (Math.trunc((Math.acosh((y >>> 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy5, [-0x080000000, 0.000000000000001, 0, -1/0, -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, 2**53-2, 0x080000000, 0x100000000, -0x100000000, -0, 0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), 1/0, 0x100000001, Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -(2**53-2), 0x07fffffff, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -0x080000001, Math.PI]); ");
/*fuzzSeed-204645237*/count=195; tryItOut("mathy0 = (function(x, y) { return ( - Math.sin(( + ( ~ ( + (( + x) / ( - y))))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 0x080000001, 2**53, 0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 1, 0x080000000, -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), -0, -0x0ffffffff, -0x080000000, 2**53-2, Number.MAX_VALUE, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, Number.MIN_VALUE, 0x07fffffff, 0/0, 2**53+2, -0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 42, -0x100000000, -(2**53-2), -(2**53+2), Math.PI]); ");
/*fuzzSeed-204645237*/count=196; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(m1, h0);");
/*fuzzSeed-204645237*/count=197; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(t0, g0);");
/*fuzzSeed-204645237*/count=198; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 144115188075855870.0;\n    d2 = (549755813888.0);\n    i1 = (!(i0));\n    d2 = (4503599627370496.0);\n    return ((((abs(((-(x++)) >> ((i1)+(((Float64ArrayView[4096])) == ((0x1edc6d0a) ? (9007199254740992.0) : (4097.0))))))|0) == (~~(+/*FFI*/ff(((Infinity)), ((4.722366482869645e+21)), ((Infinity)), ((((0x9367dfd5)) << ((0xfd088a50)))), ((((144115188075855870.0)) * ((6.044629098073146e+23)))), ((-2199023255553.0)), ((-1025.0)), ((-8191.0)), ((1048577.0))))))-(/*FFI*/ff((((((((0xdd8144c) ? (-0x8000000) : (0xfbb4e594))+(i1))>>>((/*FFI*/ff(((~((0xf86c17bb)))), ((3.0)), ((-262145.0)), ((-268435457.0)), ((-68719476737.0)), ((-3.022314549036573e+23)))|0))) / (((0x5697e1a9)-(0x549f345a)-(0xe517e73))>>>((0x9f890c84)+(0xf8239cd2)+(0x2e0981e7)))) ^ (((0xffffffff))+((0x5228f8a))))), ((~~(-35184372088833.0))), ((((0x52de9d60)-(i1)-(i1)) ^ (((2199023255553.0) == (+(0x34aa2dc2)))+(i0)))))|0)))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53, -0x07fffffff, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0x0ffffffff, -0x100000000, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, 1/0, Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, -0x100000001, -0x080000001, 1, 0, -Number.MAX_SAFE_INTEGER, 42, -0, -1/0, 2**53+2, -(2**53), -(2**53-2), 0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, -Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=199; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\3)\", \"yim\"); var s = \"\\n\\n\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-204645237*/count=200; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 1, -0x100000000, 0x100000000, 2**53+2, 42, -1/0, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, -(2**53+2), 0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, -0x080000001, 0x100000001, 0.000000000000001, 0/0, -(2**53), -Number.MAX_VALUE, -0, Number.MAX_VALUE, Math.PI, -0x080000000, 0]); ");
/*fuzzSeed-204645237*/count=201; tryItOut("/*ODP-3*/Object.defineProperty(i0, \"length\", { configurable: (x % 8 != 6), enumerable: true, writable: true, value: x });");
/*fuzzSeed-204645237*/count=202; tryItOut("\"use strict\"; M:switch(void Math.imul(((function factorial_tail(yszomf, kzdrsm) { /*hhh*/function khhkio(){m0 + f0;}khhkio(null);; if (yszomf == 0) { ; return kzdrsm; } ; return factorial_tail(yszomf - 1, kzdrsm * yszomf);  })(0, 1)), 19)) { default: case Math.min(Math.acos(Math.imul(Math.fround((Math.fround((x + ( + ( + Math.fround((Math.fround(x) ? (x >>> 0) : x)))))) << Math.fround(( + ((( ~ (Math.trunc(( + Math.round(( + x)))) >>> 0)) | 0) >>> 0))))), Math.fround(( ! Math.fround((Math.log10((Math.imul(x, 1.7976931348623157e308) >>> 0)) >>> 0)))))), Math.asin(Math.pow((Math.fround((((( ~ (Math.expm1(( - x)) >>> 0)) >>> 0) | 0) ? ( + Math.imul(( + (( + (-Number.MAX_VALUE ? 1.7976931348623157e308 : (x | 0))) | 0)), (Math.exp(x) | 0))) : (Math.fround((x ** (-Number.MIN_SAFE_INTEGER | 0))) % ( + ((( - x) | 0) ? ( + 0x080000000) : ( + x)))))) > Math.fround(Math.log(((((((x | 0) % (x | 0)) | 0) , x) | 0) - (Math.atan2(x, x) + (( + -Number.MAX_VALUE) & ( + x))))))), (Math.imul(Math.min(Math.abs(x), Math.atan(((Math.fround(( + x)) >>> 0) >>> 0))), 0.000000000000001) >= ( ~ Math.imul(x, Math.fround(Math.pow(Math.fround(Math.trunc(x)), Math.fround(x))))))))): t2.set(t2, 2);break;  }");
/*fuzzSeed-204645237*/count=203; tryItOut("mathy5 = (function(x, y) { return (Math.atan2(Math.fround(Math.min(Math.fround((Math.trunc(Math.min(y, y)) | 0)), (Math.min(-0x07fffffff, (Math.min(y, ( + y)) >>> 0)) >>> 0))), (Math.exp(((((Math.cbrt(1.7976931348623157e308) >>> 0) >> (( + mathy2(Math.imul(y, (mathy2(y, 1/0) | 0)), ( + (x >> x)))) >>> 0)) >>> 0) >>> 0)) >>> 0)) ? Math.fround(mathy3((Math.log(((-(2**53) ? ( + Math.fround(y)) : x) | 0)) | 0), ( + (( + x) << ( + Math.exp((42 | ( + x)))))))) : ( + Math.imul(( ! (mathy0(mathy0(y, y), y) ? x : 1/0)), ( + (Math.log10(y) >>> 0))))); }); testMathyFunction(mathy5, [1, Math.PI, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, Number.MAX_VALUE, 0x100000000, 2**53, -1/0, 0x080000001, 0x100000001, 0.000000000000001, -0x100000000, 0x0ffffffff, -(2**53+2), -0x0ffffffff, -(2**53-2), 2**53+2, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 0/0, 0x07fffffff, -0, 42, -Number.MIN_VALUE, -(2**53), 0, 1/0]); ");
/*fuzzSeed-204645237*/count=204; tryItOut("\"use strict\"; /*infloop*/for(var x =  /x/ ; (void version(185)); ((4277) >>= {} = {})) {f1(e1);\u0009 }");
/*fuzzSeed-204645237*/count=205; tryItOut("v1 = Object.prototype.isPrototypeOf.call(f0, this.s2);");
/*fuzzSeed-204645237*/count=206; tryItOut("\"use strict\"; /*vLoop*/for (eoiocg = 0; eoiocg < 99; ({window:  /x/ }), ++eoiocg) { b = eoiocg; /*bLoop*/for (let zpdosb = 0; zpdosb < 59; ++zpdosb) { if (zpdosb % 3 == 0) { (a); } else { t1 + ''; }  }  } ");
/*fuzzSeed-204645237*/count=207; tryItOut("\"use asm\"; print(uneval(m0));");
/*fuzzSeed-204645237*/count=208; tryItOut("\"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1048577.0;\n    var d3 = 72057594037927940.0;\n    var d4 = 262145.0;\n    d4 = (d3);\n    i1 = ((!((((0xdc2d8cf2)+((0x7fffffff) != (0x6c202fad)))>>>((/*FFI*/ff((((-0x254fb8f) ? (0.0078125) : (-4.722366482869645e+21))), ((-129.0)), ((8388609.0)), ((-32.0)), ((-9.671406556917033e+24)), ((-17.0)), ((-17592186044417.0)), ((-16385.0)), ((268435457.0)), ((-4398046511105.0)), ((4294967297.0)), ((9.0)), ((-8589934593.0)), ((1.5474250491067253e+26)), ((-17.0)), ((0.0009765625)), ((-0.03125)), ((-4503599627370497.0)), ((524289.0)), ((-0.125)), ((-281474976710657.0)))|0))) <= (0x0))) ? (((0xe2aa6*(i1)) << (-(-0x64911c9))) != (abs(((0x31cbe*(0x9c8be31)) | (-23)))|0)) : (0x92b2510));\n    d4 = (d3);\n    return +((d3));\n  }\n  return f; })(this, {ff: Set.prototype.has}, new ArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=209; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let a of /*MARR*/[ \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Number(1), undefined,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ]) { h2 + b0; }");
/*fuzzSeed-204645237*/count=210; tryItOut("mathy0 = (function(x, y) { return ( + ((Math.sqrt(( + Math.imul((y > (((x | 0) ? (Number.MIN_VALUE | 0) : ( + (x >>> 0))) | 0)), (x == (x >>> (y | 0)))))) | 0) * (((y | 0) % (Math.fround(Math.hypot(Math.fround(y), Math.pow(y, x))) | 0)) | 0))); }); testMathyFunction(mathy0, [0.000000000000001, 42, 1.7976931348623157e308, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0x100000000, 0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, -(2**53+2), 1, -0x100000001, -0x080000000, -0x100000000, 0x080000000, 0/0, 0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, -0x07fffffff, -(2**53-2), -(2**53), Math.PI]); ");
/*fuzzSeed-204645237*/count=211; tryItOut("\"use strict\"; var zwmxrz = new SharedArrayBuffer(1); var zwmxrz_0 = new Float64Array(zwmxrz); zwmxrz_0[0] = 14; var zwmxrz_1 = new Float64Array(zwmxrz); print(zwmxrz_1[0]); zwmxrz_1[0] = 22; var zwmxrz_2 = new Int16Array(zwmxrz); print(zwmxrz_2[0]); zwmxrz_2[0] = -1412779430; var zwmxrz_3 = new Float64Array(zwmxrz); zwmxrz_3[0] = -18; var zwmxrz_4 = new Uint16Array(zwmxrz); print(zwmxrz_4[0]); var zwmxrz_5 = new Int8Array(zwmxrz); print(zwmxrz_5[0]); zwmxrz_5[0] = -4; print(uneval(v1));print(zwmxrz_2[0]);for (var v of this.h1) { try { /*MXX3*/g2.Array.prototype.toLocaleString = g2.Array.prototype.toLocaleString; } catch(e0) { } try { Array.prototype.splice.apply(a2, [NaN, 4]); } catch(e1) { } p2.__iterator__ = (function() { try { for (var p in h1) { try { s2 += s2; } catch(e0) { } p1 + ''; } } catch(e0) { } o2.t0.__proto__ = o1.g0.e0; return m1; }); }v0 = (g1 instanceof a1);{}M:if(true\u0009) {(this); } else  if (NaN) {print(zwmxrz_4); }( \"\" );");
/*fuzzSeed-204645237*/count=212; tryItOut("\"use strict\"; /*vLoop*/for (yswneh = 0, chlnfc; yswneh < 63; ++yswneh) { let d = yswneh; v0 = evalcx(\"function f1(o0)  {  \\\"\\\" ; } \", g1);function window(d, ...b) { print( '' ); } m0.valueOf = (function(j) { if (j) { h1.iterate = (function mcc_() { var lrqlhn = 0; return function() { ++lrqlhn; f1(/*ICCD*/lrqlhn % 9 == 5);};})(); } else { t2[16]; } }); } ");
/*fuzzSeed-204645237*/count=213; tryItOut("m1.has(g2.f0);");
/*fuzzSeed-204645237*/count=214; tryItOut("x = linkedList(x, 2850);");
/*fuzzSeed-204645237*/count=215; tryItOut("");
/*fuzzSeed-204645237*/count=216; tryItOut("/*tLoop*/for (let e of /*MARR*/[NaN, NaN, ({1: (uneval(new  \"\" )) }), NaN, 0x2D413CCC, 0x2D413CCC, ({1: (uneval(new  \"\" )) }), NaN, NaN, NaN, ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), 0x2D413CCC, objectEmulatingUndefined(), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), 0x2D413CCC, NaN, ({1: (uneval(new  \"\" )) }), NaN, 0x2D413CCC, objectEmulatingUndefined(), ({1: (uneval(new  \"\" )) }), 0x2D413CCC, objectEmulatingUndefined(), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), NaN, NaN, ({1: (uneval(new  \"\" )) }), objectEmulatingUndefined(), 0x2D413CCC, 0x2D413CCC, NaN, ({1: (uneval(new  \"\" )) }), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), 0x2D413CCC, 0x2D413CCC, ({1: (uneval(new  \"\" )) }), ({1: (uneval(new  \"\" )) }), NaN, NaN, NaN, NaN, NaN, NaN]) { /*MXX3*/this.o2.g0.EvalError.prototype.toString = g1.g1.EvalError.prototype.toString; }");
/*fuzzSeed-204645237*/count=217; tryItOut("\"use strict\"; switch(var ogzopx = new SharedArrayBuffer(4); var ogzopx_0 = new Uint16Array(ogzopx); print(ogzopx_0[0]); ogzopx_0[0] = -17; var ogzopx_1 = new Int32Array(ogzopx); var ogzopx_2 = new Uint32Array(ogzopx); print(ogzopx_2[0]); var ogzopx_3 = new Int32Array(ogzopx); print(ogzopx_3[0]); ogzopx_3[0] = 3; this.i1 = o2.a0[v1];var s1 = new String(v1);) { default: m2 = new Map(this.a2);break; case 3: v2 = o2.t2.byteLength;break; case 8: Array.prototype.sort.apply(a0, [(function() { try { v0 = r0.unicode; } catch(e0) { } m1.get(i2); return this.v1; })]);break; case x: /*bLoop*/for (let loxfgu = 0; loxfgu < 14; ++loxfgu) { if (loxfgu % 6 == 0) { i0 = e2.keys; } else { i0 = this.t1[d]; }  } break;  }");
/*fuzzSeed-204645237*/count=218; tryItOut("v2 = (b2 instanceof v0);\n{v0 = Object.prototype.isPrototypeOf.call(p1, m1); }\n");
/*fuzzSeed-204645237*/count=219; tryItOut("return  '' ;const z = this;function e()[]for (var v of g0.v1) { try { g0.v1 = Object.prototype.isPrototypeOf.call(this.g1, v1); } catch(e0) { } try { e0 = new Set(m0); } catch(e1) { } f0(f1); }");
/*fuzzSeed-204645237*/count=220; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.fround(Math.expm1(Math.fround((( ~ ((Math.pow((Math.fround((( ~ (( ~ ( + (-0x080000000 !== x))) >>> 0)) | 0)) | 0), Math.cbrt(Math.fround(Math.cbrt(x)))) | 0) | 0)) | 0)))); }); testMathyFunction(mathy5, [-0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, 2**53+2, 0/0, 42, -(2**53+2), Number.MIN_VALUE, -0x100000000, -0x07fffffff, Math.PI, 1/0, -Number.MAX_VALUE, -0, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, 0x100000000, -0x100000001, 0.000000000000001, 0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff, -0x0ffffffff, 0, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 0x080000000, 0x080000001]); ");
/*fuzzSeed-204645237*/count=221; tryItOut("a1 = [];z = (/*FARR*/[].some(z, \"\\u433E\" /=  '' ));");
/*fuzzSeed-204645237*/count=222; tryItOut("mathy4 = (function(x, y) { return (((Math.hypot(Math.imul(y, ( ! x)), ( + Math.asinh(( ! y)))) | 0) << (Math.atan2(Math.fround(( + (( + y) || ( + x)))), Math.log2(Math.fround((Math.fround(x) | Math.fround(x))))) > (x ? Math.fround((Math.fround(x) ? x : Math.atan2(0x100000001, x))) : x))) - (Math.atan2(((((y >>> 0) + (Math.fround((Math.fround((( - (x | 0)) | 0)) ? Math.fround(x) : (((Math.atanh(y) << x) >>> 0) >>> 0))) | 0)) | 0) ? ( + (y == (( - -(2**53)) | 0))) : y), Math.fround(Math.max(( ~ (Math.tanh(-Number.MIN_SAFE_INTEGER) >>> 0)), ( + ( - (Math.atan2((y | 0), 0x080000001) | 0)))))) | 0)); }); testMathyFunction(mathy4, [-1/0, -Number.MAX_VALUE, -(2**53), -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, -Number.MAX_SAFE_INTEGER, 1, 2**53-2, -0, 0.000000000000001, 0, -0x0ffffffff, 0/0, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, 0x080000000, 0x080000001, 2**53, 1.7976931348623157e308, -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 1/0, 42, Number.MAX_VALUE, -0x080000000, -0x100000000]); ");
/*fuzzSeed-204645237*/count=223; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.hypot(((( + Math.cos((Math.trunc(Math.fround(( ~ mathy0(y, Math.log1p(y))))) | 0))) != mathy0((((( + Math.log2(y)) ^ (( - y) >>> 0)) >>> 0) ? y : y), (Math.ceil((Math.fround(0x080000000) ^ ( + -0x080000001))) >>> 0))) >>> 0), (Math.atan2(( + ( + Math.log(( + ( + mathy0(Math.fround(( ~ Math.fround(y))), y)))))), ( + ( ! mathy0((y | 0), (Math.fround(Math.min(Math.fround(y), Math.fround(x))) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x0ffffffff, 0, -0x0ffffffff, -(2**53-2), 0.000000000000001, -0x080000000, Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -(2**53+2), -Number.MAX_VALUE, 0x100000001, 2**53-2, 42, -0x100000000, -(2**53), -0x080000001, 2**53+2, -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000000, -0, 0x080000001, -1/0, 0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 1.7976931348623157e308, 0/0, -0x100000001]); ");
/*fuzzSeed-204645237*/count=224; tryItOut("\"use strict\"; a2.unshift(p1);");
/*fuzzSeed-204645237*/count=225; tryItOut("mathy4 = (function(x, y) { return Math.sin(( + ( ! ((( ! x) >>> x) ** (mathy3(Math.cosh(y), (Math.hypot(x, (Math.max(x, y) | 0)) | 0)) | 0))))); }); testMathyFunction(mathy4, [0.000000000000001, 1, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, -(2**53), -1/0, 0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 0x100000000, 2**53, -0x080000000, -0x100000001, 42, 2**53-2, -0x07fffffff, -0, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 0x080000000, -0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -0x0ffffffff, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-204645237*/count=226; tryItOut("\"use strict\"; /*infloop*/ for  each(let ([]) in x) /*MXX3*/this.g0.ReferenceError.prototype = g0.ReferenceError.prototype;");
/*fuzzSeed-204645237*/count=227; tryItOut("mathy4 = (function(x, y) { return Math.acos(( + Math.min(( + (Math.imul((-Number.MAX_VALUE >>> 0), ((mathy3(Math.expm1(y), (( ! (x >>> 0)) >>> 0)) | 0) | 0)) >>> 0)), (( + ( ! ((Math.ceil((x >>> 0)) >>> 0) >>> 0))) && y)))); }); ");
/*fuzzSeed-204645237*/count=228; tryItOut("\"use strict\"; Array.prototype.forEach.call(a0, f2);");
/*fuzzSeed-204645237*/count=229; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2(( - Math.fround(Math.atan2(Math.fround(Math.fround((Math.fround(( - x)) >= Math.fround(1)))), (( + mathy0((x , x), ( + (Number.MIN_SAFE_INTEGER & (Math.pow(Number.MIN_SAFE_INTEGER, x) | 0))))) | 0)))), (( ~ (( + mathy2(Math.fround(Math.cos(x)), ( + y))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), 1.7976931348623157e308, 1, 0, 0x100000001, -0, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, 0x100000000, -Number.MAX_VALUE, -0x080000000, 0x080000001, -0x0ffffffff, 42, -0x100000001, 2**53+2, 0x0ffffffff, -1/0, Number.MAX_VALUE, 2**53-2, 0x080000000, 2**53, Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), Math.PI]); ");
/*fuzzSeed-204645237*/count=230; tryItOut("let (a) { return; }");
/*fuzzSeed-204645237*/count=231; tryItOut("\"use strict\"; for (var p in m0) { try { v1 = (p2 instanceof s2); } catch(e0) { } print(i2); }");
/*fuzzSeed-204645237*/count=232; tryItOut("for (var p in o1.v2) { try { (void schedulegc(g0)); } catch(e0) { } for (var v of s0) { try { v0 = evalcx(\"s0 += 'x';\", g1.g1); } catch(e0) { } i0.send(a0); } }");
/*fuzzSeed-204645237*/count=233; tryItOut("mathy4 = (function(x, y) { return ( + Math.tan(( + Math.min((( + ( + (( + ( + (( + Math.atan2(-0x100000001, 0x080000001)) > ( + Math.fround(mathy1(Math.fround(-0x100000001), Math.fround(x))))))) != ( + Math.atanh((y | 0)))))) + ( ! ( + ( + x)))), Math.cbrt(x))))); }); testMathyFunction(mathy4, [-0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 2**53-2, 1, 42, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, -0x080000000, -1/0, -0x0ffffffff, Math.PI, 0x0ffffffff, 2**53+2, 0x07fffffff, 0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x100000000, 1/0, -(2**53), -0x100000001, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 0x080000001, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=234; tryItOut("o2.m1.set(m0, p2);");
/*fuzzSeed-204645237*/count=235; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x100000001, -0x100000000, -0x080000000, 0x07fffffff, Math.PI, 1/0, 0x080000001, 42, 2**53+2, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, -0, -0x080000001, -Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, 2**53-2, -0x100000001, -Number.MAX_VALUE, 0/0, Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, 1, 0.000000000000001, -1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=236; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=237; tryItOut("print(s2);");
/*fuzzSeed-204645237*/count=238; tryItOut("L:switch(null) { default:  }");
/*fuzzSeed-204645237*/count=239; tryItOut("\"use strict\"; {this.v0 = a0.length;/*ADP-3*/Object.defineProperty(this.a2, 13, { configurable: (x % 75 != 3), enumerable: false, writable: false, value: p1 }); }");
/*fuzzSeed-204645237*/count=240; tryItOut("\"use strict\"; print(b = \"\\u716E\");function c(x)(void version(185))/* no regression tests found */");
/*fuzzSeed-204645237*/count=241; tryItOut("this.v1 = g1.eval(\"a2[this.v2] = /*RXUE*//(?!\\\\B)(?:[\\u0003-\\uf0ab\\\\u004D\\\\W\\\\ua436]|(?=\\\\B)+?*?.?|\\\\d)/gyim.exec(\\\"\\\\ua436BBa\\\");\");");
/*fuzzSeed-204645237*/count=242; tryItOut("const y = x;L:if((\u3056) = (void options('strict_mode'))) {neuter(b1, \"same-data\"); } else  if (window) print(x);");
/*fuzzSeed-204645237*/count=243; tryItOut("v1 = a2.length;");
/*fuzzSeed-204645237*/count=244; tryItOut("\"use strict\"; for (var v of s1) { try { v1 = evaluate(\"function this.f1(t2) (d = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: b, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: Function, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: -21.valueOf, fix: undefined, has: function() { throw 3; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: Function.prototype, keys: function() { throw 3; }, }; })(d >> y), Int32Array))\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 6 != 3), sourceIsLazy: true, catchTermination: false })); } catch(e0) { } ; }");
/*fuzzSeed-204645237*/count=245; tryItOut("print(x);");
/*fuzzSeed-204645237*/count=246; tryItOut("\"use strict\"; \"use asm\"; v2 = (a1 instanceof f0);");
/*fuzzSeed-204645237*/count=247; tryItOut("");
/*fuzzSeed-204645237*/count=248; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ ((( - y) ? ((( + (( ~ ( ! y)) | 0)) + ((Math.max((x | 0), (y | 0)) | 0) | 0)) >>> 0) : (( + (( + Math.imul((Math.fround(Math.hypot(Math.fround(y), Math.fround(x))) >>> 0), ((-(2**53) && (x >>> 0)) | 0))) > ( + (Math.atan2((y | 0), ((((x | 0) / (y >>> 0)) | 0) | 0)) | 0)))) > (( - (x >>> 0)) >>> 0))) >>> 0)); }); ");
/*fuzzSeed-204645237*/count=249; tryItOut("a1 = Array.prototype.slice.call(a0, 7, NaN, h0, f2, m2, s1, this.i1, s1, v2);");
/*fuzzSeed-204645237*/count=250; tryItOut("i1 = o0.a1[19];");
/*fuzzSeed-204645237*/count=251; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = r0; var s = s2; print(r.exec(s)); ");
/*fuzzSeed-204645237*/count=252; tryItOut("\"use strict\"; ((Symbol.name = \"\\u7DE7\"));");
/*fuzzSeed-204645237*/count=253; tryItOut("\"use strict\"; s1.__proto__ = b0;");
/*fuzzSeed-204645237*/count=254; tryItOut("v1 = (o1 instanceof g2);");
/*fuzzSeed-204645237*/count=255; tryItOut("( \"\" .eval(\" /x/ \"));");
/*fuzzSeed-204645237*/count=256; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.min((( + (((Math.fround(Math.sin((x >>> 0))) | Math.fround(Math.max(( ! Math.clz32(x)), ( + ( + Number.MIN_SAFE_INTEGER))))) >>> 0) , (((((Math.asin((x | 0)) | 0) >>> 0) >= y) << Math.asinh(-0x100000000)) >>> 0))) | 0), ((Math.clz32(((y < ( + ( + y))) >>> 0)) || ( ! ( + Math.acos(x)))) | 0)) | 0); }); testMathyFunction(mathy0, [42, -1/0, -(2**53+2), 0x080000001, 1.7976931348623157e308, 0, 1/0, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0, 2**53, -0x080000001, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, -0x07fffffff, 0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, 0x080000000, 2**53-2, 1, -(2**53-2), Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, -0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=257; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xa96d59df);\n    d1 = (d1);\n    i0 = (((yield null)));\n    d1 = (+((+acos(((d1))))));\n    return ((((((i0)+(0xfb9b9b7d)) << ((((0xca6d8c3b)) | ((0xa7dad7c4))) / (~~(36028797018963970.0)))) < (0x23e2a35f))-((+(1.0/0.0)) < (-288230376151711740.0))-(i0)))|0;\n    return (((((i0)+(0xf916ec44)+(/*FFI*/ff(((((0xfd49e3dd)-(0xf8bd53b8)-(0xffffffff))|0)))|0)) << (((+(0xffffffff)) != (d1)))) % (~((i0)))))|0;\n  }\n  return f; })(this, {ff: function(y) { return [] }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_VALUE, 2**53, -(2**53-2), 2**53-2, 0x080000000, 1/0, Math.PI, -0x080000001, 42, Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, 0x07fffffff, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -0, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 0, 0x100000000, 0x100000001, 0x0ffffffff, -(2**53), -0x080000000, -0x07fffffff, -0x100000001, 0/0, -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=258; tryItOut("/*bLoop*/for (var skbaux = 0; skbaux < 21; ++skbaux) { if (skbaux % 8 == 5) { return -12; } else { Array.prototype.shift.call(o2.a1, x); }  } ");
/*fuzzSeed-204645237*/count=259; tryItOut("\"use strict\"; for (var p in t0) { try { Object.prototype.unwatch.call(s1, \"apply\"); } catch(e0) { } try { f1 = (function mcc_() { var ieueqz = 0; return function() { ++ieueqz; if (/*ICCD*/ieueqz % 11 == 6) { dumpln('hit!'); t1.set(t0, 10); } else { dumpln('miss!'); try { this.m0 = new Map; } catch(e0) { } try { Array.prototype.unshift.call(a0, v1, o0, window, s2); } catch(e1) { } try { a0 = new Array; } catch(e2) { } e0.__proto__ = this.g2; } };})(); } catch(e1) { } e0.has(m1); }");
/*fuzzSeed-204645237*/count=260; tryItOut("Array.prototype.pop.call(a2);");
/*fuzzSeed-204645237*/count=261; tryItOut("i2 + f0;");
/*fuzzSeed-204645237*/count=262; tryItOut("testMathyFunction(mathy5, [0, (new Number(0)), '/0/', (new String('')), '\\0', /0/, [], undefined, ({valueOf:function(){return 0;}}), (new Number(-0)), NaN, ({valueOf:function(){return '0';}}), '0', 1, (new Boolean(false)), 0.1, -0, null, false, (function(){return 0;}), true, objectEmulatingUndefined(), [0], (new Boolean(true)), ({toString:function(){return '0';}}), '']); ");
/*fuzzSeed-204645237*/count=263; tryItOut("testMathyFunction(mathy3, /*MARR*/[true, true, (e), undefined, true, (e), true, true, (e), undefined, undefined, undefined, undefined, (e), true, (e), undefined, (e), (e), true, true, true, undefined, true, (e), undefined, true, undefined, true, (e), undefined, (e), undefined, (e), (e), undefined, (e), true, true, (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), (e), true, (e), undefined, undefined, (e), undefined, undefined, true, undefined, (e), undefined, (e), true, true, true, undefined, (e), (e), undefined, true, true, undefined, (e), (e), undefined, true, undefined, (e), undefined, undefined, (e), undefined, (e), (e), (e), (e), true, true, (e), true, true, true, (e), true, undefined, true, (e), (e), (e), true, (e), undefined, undefined, undefined, true, true, (e), true, (e), (e), undefined, true, undefined, (e), true, true, (e), true, true, true, true, true, undefined, true, (e), true, undefined, undefined]); ");
/*fuzzSeed-204645237*/count=264; tryItOut("mathy0 = (function(x, y) { return ( ! Math.atanh((Math.min(Math.fround(((Math.atan((Math.hypot(y, y) | 0)) | 0) + (Math.acos(((( ! -0x0ffffffff) | 0) | 0)) | 0))), ( + (( + (x >>> 0)) >>> 0))) | 0))); }); testMathyFunction(mathy0, [-0x100000000, 0, -0x07fffffff, 1/0, 0/0, -(2**53), 0x080000001, 2**53, 1, 2**53-2, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, Math.PI, -0, 0x0ffffffff, 42, 0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 2**53+2, 0.000000000000001, Number.MIN_VALUE, -0x080000000, -0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=265; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.pow(((Math.fround(Math.fround((Math.fround(Math.fround(Math.fround(0x07fffffff))) / Math.imul(y, x)))) - (( + mathy0(Math.fround(mathy2(Math.fround(Math.pow(( ! y), ( + x))), Math.fround(((x | 0) - x)))), ( + Math.pow(Math.fround(y), Math.fround(y))))) | 0)) | 0), (((( + ( + (Math.atan2((Math.cbrt((0 | 0)) | 0), y) >>> 0))) >>> 0) ^ ((mathy2(0x07fffffff, (y >>> 0)) >>> 0) | 0)) >>> 0)) * Math.fround((mathy2(( ~ Math.fround(Math.hypot(Math.fround(y), Math.fround(x)))), 0x0ffffffff) ? Math.asinh(Math.atan2(( + ( ~ (y >>> 0))), Math.fround(Math.round(y)))) : (Math.round(0.000000000000001) ? y : ((Math.log2((x >>> 0)) >>> 0) != x))))); }); testMathyFunction(mathy3, [2**53, -1/0, -0x100000001, -0, 0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, 0x100000001, Number.MAX_VALUE, 1/0, -(2**53-2), 0x0ffffffff, 0.000000000000001, 0x07fffffff, 1, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, 2**53-2, 0x080000000, 42, -0x100000000, -0x080000001, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=266; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = s1; print(s.replace(r, '')); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=267; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( - (mathy0((mathy0(Math.fround((Math.fround((( + ( + (( + (Number.MAX_VALUE === 0x080000001)) ? ( + (( + x) | 0)) : (y | 0)))) !== -0x100000000)) || Math.fround(( + (( + Math.fround(Math.pow(Math.fround(0/0), y))) | ( + y)))))), (Math.sin(((((-(2**53+2) >>> 0) > (0 >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0), Math.fround((Math.fround(Math.pow(y, (((Math.hypot(-(2**53-2), y) | 0) % (y | 0)) | 0))) && ( + (( + (Math.acosh(((Math.fround((Math.fround(x) || Math.fround(y))) ? y : ( + (Math.fround(y) === y))) >>> 0)) >>> 0)) | 0))))) >>> 0)); }); ");
/*fuzzSeed-204645237*/count=268; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - ( + ( ~ ( + (Math.expm1(x) * ( + Math.atan2((Math.sqrt((x === (x >>> 0))) >>> 0), (y == 2**53)))))))); }); testMathyFunction(mathy4, [0x100000001, Number.MAX_VALUE, 1, 2**53, -0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x080000000, 0x080000001, -Number.MAX_VALUE, Math.PI, 42, -(2**53+2), 1/0, 2**53-2, 0x100000000, Number.MIN_VALUE, 0x080000000, -0x080000001, 0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 1.7976931348623157e308, 0/0, -(2**53), -0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-204645237*/count=269; tryItOut("print(x);(Math.atan2(/*FARR*/[new RegExp(\"(?!$(?![^]))\", \"yim\")].map(((new Function(\"{}\"))).bind), (makeFinalizeObserver('tenured'))));");
/*fuzzSeed-204645237*/count=270; tryItOut("for (var v of m2) { p1 + ''; }");
/*fuzzSeed-204645237*/count=271; tryItOut("\"use strict\"; this.v1 = g0.g0.g0.runOffThreadScript();");
/*fuzzSeed-204645237*/count=272; tryItOut("testMathyFunction(mathy5, [({toString:function(){return '0';}}), (new String('')), true, /0/, -0, 0, (function(){return 0;}), [0], NaN, null, ({valueOf:function(){return 0;}}), undefined, '\\0', '', 1, '/0/', (new Number(0)), objectEmulatingUndefined(), (new Boolean(true)), '0', ({valueOf:function(){return '0';}}), (new Number(-0)), (new Boolean(false)), [], 0.1, false]); ");
/*fuzzSeed-204645237*/count=273; tryItOut("this.s2 += 'x';");
/*fuzzSeed-204645237*/count=274; tryItOut("L:for(var [d, d] = x in \"\\uA505\") a1.shift(d);");
/*fuzzSeed-204645237*/count=275; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\s|(?=[^]*)|(?!(?!(.)))\\\\3*\\\\1{2}[^]\\\\d.\\\\3^++?\", \"gi\"); var s = \"_\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-204645237*/count=276; tryItOut("const window, this.x = eval(\"x ** new RegExp(\\\"\\\\ue509?\\\", \\\"y\\\") >>>= false\", Math.trunc(-3265075110) ? function shapeyConstructor(fptcwc){this[\"constructor\"] = false;return this; }(window = -10, w) : x = y), e = Math.atan2(17, 0), ummooh;/*oLoop*/for (icagmc = 0; icagmc < 1; ++icagmc) { (14); } ");
/*fuzzSeed-204645237*/count=277; tryItOut("\"use strict\"; y = linkedList(y, 260);(function(x, y) { \"use strict\"; return y; })");
/*fuzzSeed-204645237*/count=278; tryItOut("\"use strict\"; /*infloop*/for(let x(undefined -= true) in ((Math.exp)([,])))Object.defineProperty(this, \"a1\", { configurable: false, enumerable: this,  get: function() {  return (4277); } });");
/*fuzzSeed-204645237*/count=279; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-204645237*/count=280; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = c; var s = \"0\"; print(s.match(r)); ");
/*fuzzSeed-204645237*/count=281; tryItOut("/*RXUB*/var r = new RegExp(\"(?!((?=(?=\\\\D))){3}{0})(?:[^]){3,}|\\\\1?{17179869185,}\", \"m\"); var s = \"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"; print(s.search(r)); print(r.lastIndex); \nm1 = new Map(a0)\n");
/*fuzzSeed-204645237*/count=282; tryItOut("");
/*fuzzSeed-204645237*/count=283; tryItOut("\"use strict\"; /*vLoop*/for (var xnyacq = 0; xnyacq < 38; ++xnyacq) { const w = xnyacq; print(o1.f2); } \nv1 = evalcx(\"o0.m2 = new WeakMap;\", g0);\n");
/*fuzzSeed-204645237*/count=284; tryItOut("\"use strict\"; for (var p in o1) { e1.has(t1); }for(let b =  \"\"  in /*MARR*/[ \"use strict\" , new Number(1), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19), new Number(1), new Number(1), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19), new Number(1), new Number(1), new Number(1),  \"use strict\" , new Number(1), new Number(1), new Number(1), Math.atan2(({a2:z2}), 19),  \"use strict\" , new Number(1), Math.atan2(({a2:z2}), 19),  \"use strict\" , new Number(1), new Number(1),  \"use strict\" , new Number(1), new Number(1),  \"use strict\" ,  \"use strict\" , new Number(1), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19),  \"use strict\" , new Number(1), new Number(1),  \"use strict\" ,  \"use strict\" , Math.atan2(({a2:z2}), 19), new Number(1), new Number(1), new Number(1), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19),  \"use strict\" , Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19), new Number(1), new Number(1),  \"use strict\" , Math.atan2(({a2:z2}), 19),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Number(1), new Number(1), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Number(1), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19),  \"use strict\" , new Number(1), new Number(1), new Number(1),  \"use strict\" , Math.atan2(({a2:z2}), 19),  \"use strict\" , new Number(1), Math.atan2(({a2:z2}), 19), Math.atan2(({a2:z2}), 19), new Number(1)]) {throw StopIteration; }");
/*fuzzSeed-204645237*/count=285; tryItOut("mathy4 = (function(x, y) { return mathy0(( + Math.cbrt((Math.log((Math.fround(Math.round(Math.fround(x))) >>> 0)) >>> 0))), ( - (Math.imul((( + Math.pow((( - ((x >= x) | 0)) >>> 0), (y >>> 0))) | 0), ((Math.imul((( + Number.MIN_VALUE) & ((y | 0) ? x : y)), y) - Math.pow(( + Math.tanh(((Math.sqrt(x) | 0) >>> 0))), x)) | 0)) | 0))); }); testMathyFunction(mathy4, [0/0, -0x100000000, 0x07fffffff, 2**53-2, -(2**53-2), -1/0, 1.7976931348623157e308, 2**53+2, Number.MIN_VALUE, 0, -0, 1, 0x0ffffffff, -(2**53+2), 0x080000000, -0x100000001, Number.MAX_VALUE, -0x080000000, 0x100000000, 0x100000001, 2**53, 42, -(2**53), -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 0.000000000000001, Math.PI, 0x080000001, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=286; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 73786976294838210000.0;\n    (Float32ArrayView[4096]) = ((+/*FFI*/ff(((((d3)) / ((-2049.0)))), ((d3)), ((d0)), (((yield /*UUV1*/(x.hypot = (function(q) { return q; }).call)).throw((( - Math.fround((Math.fround(x) <= (( + (x / x)) >>> 0)))))))))));\n    return (((i1)-(((0x13d6e518) == (0xffffffff)) ? (i1) : ((((i2)-(i2))>>>((i1)+(/*FFI*/ff(((-4097.0)), ((147573952589676410000.0)), ((34359738367.0)), ((-1125899906842625.0)), ((-6.189700196426902e+26)), ((-1.888946593147858e+22)), ((274877906945.0)), ((73786976294838210000.0)), ((2199023255553.0)), ((1.0625)), ((-0.0009765625)), ((0.001953125)))|0))) > (((/*FFI*/ff(((0x641753c0)), ((-67108864.0)), ((0.5)), ((2147483649.0)), ((-2.4178516392292583e+24)), ((-16777215.0)), ((-67108864.0)), ((1.2089258196146292e+24)), ((1.9342813113834067e+25)), ((-70368744177665.0)), ((18014398509481984.0)), ((-1.25)), ((-17179869184.0)))|0))>>>((0x967311dd)-(-0x8000000)+(0xfc1ab69f)))))))|0;\n  }\n  return f; })(this, {ff: d}, new ArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=287; tryItOut("this.b1 = g2.t0[({valueOf: function() { d = linkedList(d, 2479);return 17; }})];let d = (makeFinalizeObserver('tenured'));");
/*fuzzSeed-204645237*/count=288; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1025.0;\n    var d3 = -9223372036854776000.0;\n    var i4 = 0;\n    d0 = (Infinity);\n    d3 = (d2);\n    {\n      d3 = ((+atan2(((+abs(( /x/g )))), ((d3)))) + (d1));\n    }\n    d2 = (d2);\n    i4 = (i4);\n    d1 = (d0);\n    d3 = (((Uint16ArrayView[((/*FFI*/ff(((~~(((d2)) / ((-262143.0))))), ((+(1.0/0.0))), ((d3)), ((d1)), ((((0xfb4b8fce)) | ((0x6de1b17d)+(-0x8000000)-(0xf847059c)))))|0)) >> 1])));\n    i4 = (0xf8966f8f);\n    d1 = (4.835703278458517e+24);\n    return (((/\\3+?/yim | ((function sum_indexing(ferhwa, byqsgb) { ; return ferhwa.length == byqsgb ? 0 : ferhwa[byqsgb] + sum_indexing(ferhwa, byqsgb + 1); })(/*MARR*/[x, (0/0), x, x, (0/0), x, (-1/0), (0/0), (-1/0), (-1/0), (-1/0), (-1/0), x, (-1/0), (0/0), (-1/0), x, (0/0), (-1/0), (0/0), x, (0/0), (0/0), x, x, (-1/0), (0/0), x, x, x, x, x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, x, (-1/0), x, (0/0), x, x, (-1/0), x, (-1/0), (0/0), (0/0), x, (0/0), (-1/0), x, (-1/0), (0/0), x, (-1/0), x, (-1/0), (-1/0)], 0)))))|0;\n  }\n  return f; })(this, {ff: function ([y]) { }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53+2), 42, -(2**53), -0x100000001, 0x0ffffffff, 0x100000000, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, -0x100000000, 2**53-2, -Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, -0x080000001, 2**53+2, 0/0, 0x100000001, 1, Number.MAX_VALUE, 0x080000000, -0x080000000, 1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, Math.PI, -1/0]); ");
/*fuzzSeed-204645237*/count=289; tryItOut("/*infloop*/for((x) = new RegExp(\"^\", \"gim\"); intern(28); (4277)) (-18);");
/*fuzzSeed-204645237*/count=290; tryItOut("L:if((x % 18 != 12)) { if ((x = x)) {m0.has(o0);print((4277)); }} else print(x);");
/*fuzzSeed-204645237*/count=291; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + mathy0(( + Math.clz32((Math.atan2(Math.atan2(((y >>> 0) ** (Math.pow(x, (Math.log10((y >>> 0)) >>> 0)) >>> 0)), y), x) >>> 0))), (Math.pow(Math.max((((Math.tanh(Math.atanh(x)) >>> 0) , (y ? (x | 0) : y)) >>> 0), ((( + y) >>> 0) > Math.acos((Math.sinh(0x080000000) + x)))), (mathy0((( + ((( + Math.log2(( + (Math.pow((Math.max(y, x) >>> 0), ( + 2**53)) >>> 0)))) | 0) !== Math.fround(Math.fround(Math.min(Math.fround(x), Math.fround(Math.atan(Math.fround(y)))))))) | 0), (((Math.sinh(x) | 0) || y) | 0)) | 0)) | 0))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 2**53-2, 42, 1/0, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0, 0.000000000000001, -0x080000000, 0x100000000, 0x100000001, 0x080000001, Math.PI, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), -0x100000000, 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, Number.MAX_VALUE, -1/0, -(2**53-2), 2**53+2, 0]); ");
/*fuzzSeed-204645237*/count=292; tryItOut(" for (var z of /\\B/yi) g2.toString = (function() { v0 = a2.length; throw g2; });");
/*fuzzSeed-204645237*/count=293; tryItOut("\"use strict\"; \"use asm\"; /*oLoop*/for (var cczttd = 0; cczttd < 69; ++cczttd) { t2.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) { var r0 = a3 * 7; a11 = a7 % 5; var r1 = a7 - a9; var r2 = a3 / a1; var r3 = a4 * 2; var r4 = a5 / a10; a0 = a1 | a6; a0 = 9 | a1; var r5 = 5 % 9; var r6 = x * a2; var r7 = 6 | a14; var r8 = 8 % a12; a11 = a0 / 3; var r9 = 9 + 8; var r10 = r8 + r9; var r11 = a2 & 5; var r12 = a9 % 3; var r13 = a2 * 0; a1 = 5 * 9; print(a14); var r14 = r4 ^ 9; print(r8); var r15 = 7 + 1; var r16 = r2 % r15; var r17 = r16 / r11; print(a2); var r18 = 9 & r1; var r19 = 5 + r6; var r20 = 7 & 0; r9 = r18 - r19; var r21 = a11 ^ a7; var r22 = 8 - a12; var r23 = r22 & a7; var r24 = r12 % 6; a11 = a13 ^ 4; var r25 = a6 | a9; print(a14); var r26 = a4 ^ r8; var r27 = x / r14; var r28 = r10 * 3; var r29 = a5 | a11; r16 = r28 + r8; var r30 = 6 * r14; r10 = 0 ^ a5; var r31 = 3 & 4; print(r20); r1 = a13 % r19; var r32 = a4 + a13; a13 = r22 + 0; var r33 = r16 * r0; var r34 = r0 ^ 5; r8 = 5 * 4; var r35 = r19 % 8; var r36 = a15 * r5; var r37 = 7 / r6; print(a3); a2 = 2 & r36; var r38 = 5 * r16; var r39 = r23 & r7; var r40 = 1 / r6; var r41 = 2 | a10; var r42 = r20 * r26; var r43 = r8 / 0; var r44 = r12 * r39; a11 = r12 % 3; var r45 = r22 ^ r38; var r46 = a16 | a8; a0 = r22 | r27; print(r44); var r47 = r13 | r18; var r48 = r19 * r23; r39 = a3 | a6; var r49 = 1 & a11; var r50 = a14 / 0; var r51 = r40 / 9; var r52 = r50 | r18; var r53 = 8 | a15; var r54 = r0 / r22; var r55 = 6 - r22; var r56 = r37 - a12; var r57 = r36 + r36; var r58 = r20 + r44; var r59 = 1 ^ r47; var r60 = 7 | r12; var r61 = a5 + r12; var r62 = 0 ^ r39; print(a11); var r63 = r13 % a12; var r64 = 6 % r59; var r65 = r48 * a9; r41 = 5 - r22; r58 = r59 % 1; var r66 = r54 + r58; var r67 = r1 % 4; var r68 = 5 / 1; var r69 = r65 | r19; var r70 = 3 / r0; r38 = r59 | 0; r50 = 9 | r60; var r71 = 2 ^ a6; var r72 = r10 | a9; var r73 = r40 ^ 0; print(r47); var r74 = r5 + r54; var r75 = r68 | r66; var r76 = 2 ^ r31; var r77 = 3 * r4; var r78 = r30 / r69; r18 = 2 - r15; var r79 = 1 * a11; r67 = a7 | r34; r79 = 4 - r21; var r80 = r46 ^ r6; var r81 = 0 - 9; var r82 = a16 & 2; var r83 = r20 & r28; r57 = r81 - a15; var r84 = r68 * r75; r82 = r67 % 1; r40 = r44 - 6; var r85 = r36 % r39; var r86 = a10 | r58; var r87 = r30 & r40; r29 = r44 / r69; var r88 = 8 + r35; a6 = 8 * r7; a16 = r9 % 7; var r89 = r27 % a6; var r90 = 1 + r84; r50 = x + r60; var r91 = r78 | r44; var r92 = r82 ^ a11; var r93 = r24 % r57; var r94 = r22 * 8; var r95 = 0 - r77; r52 = r66 + r26; var r96 = 5 % 3; print(r45); var r97 = 5 / r13; var r98 = 9 + 7; var r99 = 2 / r18; a7 = 3 + a7; r57 = 2 - r98; var r100 = 5 + 6; var r101 = r22 - 2; var r102 = r37 * 8; var r103 = 1 - 2; var r104 = r39 % 0; var r105 = r45 / 8; var r106 = r5 - 8; print(a10); var r107 = a6 + r15; var r108 = r6 | 9; var r109 = a4 | x; r30 = 9 & r30; var r110 = r108 * r96; var r111 = 3 ^ r110; r42 = r107 - r36; print(a15); var r112 = 5 - 5; var r113 = r24 * r82; var r114 = r71 % r15; r4 = r89 + a5; var r115 = r78 | r64; var r116 = r63 / 3; var r117 = 1 | r15; var r118 = 6 % 4; var r119 = a8 % r97; var r120 = 3 / 3; var r121 = r82 & 8; var r122 = r80 | r32; var r123 = 4 + r88; var r124 = 3 + 5; print(r18); var r125 = r11 * r105; r42 = r84 | r90; r4 = r39 | 6; var r126 = 1 ^ r22; var r127 = 1 & r56; r28 = 5 % r46; var r128 = r87 * r39; var r129 = r83 / 0; r66 = 8 & r18; var r130 = r15 % 0; r91 = r7 | r87; var r131 = r124 | 3; var r132 = 2 % a14; print(r40); var r133 = r65 * r68; r112 = 9 - r101; var r134 = 9 * r89; var r135 = 6 ^ a16; var r136 = a6 * r48; var r137 = r89 ^ r103; r82 = 4 + 1; r44 = 4 - r38; var r138 = 6 | r111; r129 = 8 | r122; var r139 = 3 ^ r115; print(r87); var r140 = r81 * a1; var r141 = a8 % 9; r49 = 4 ^ r141; r53 = r102 * r138; var r142 = r93 + a6; var r143 = 7 & r13; print(r120); var r144 = r7 * a8; var r145 = r2 % r102; var r146 = r78 * r41; var r147 = r120 * r88; var r148 = 3 * r128; var r149 = 7 + r73; var r150 = 4 - 2; var r151 = 9 % r15; return a6; }); } ");
/*fuzzSeed-204645237*/count=294; tryItOut("\"use strict\"; print(/*FARR*/[, [[]],  \"\" , [z1]].sort);");
/*fuzzSeed-204645237*/count=295; tryItOut("\"use strict\"; o2.v0 = 0;");
/*fuzzSeed-204645237*/count=296; tryItOut("\"use strict\"; \"use asm\"; print(x);");
/*fuzzSeed-204645237*/count=297; tryItOut("g1.f2.valueOf = f1;");
/*fuzzSeed-204645237*/count=298; tryItOut("\"use strict\"; var qqzxnr = new SharedArrayBuffer(16); var qqzxnr_0 = new Float64Array(qqzxnr); print(qqzxnr_0[0]); qqzxnr_0[0] = 19; var qqzxnr_1 = new Uint32Array(qqzxnr); qqzxnr_1[0] = -3; var qqzxnr_2 = new Int16Array(qqzxnr); qqzxnr_2[0] = -718700517.5; var qqzxnr_3 = new Uint16Array(qqzxnr); print(qqzxnr_3[0]); var qqzxnr_4 = new Int8Array(qqzxnr); qqzxnr_4[0] = 10; var qqzxnr_5 = new Int16Array(qqzxnr); /*RXUB*/var r = new RegExp(\"(?:(?:\\\\B)){3,}|(?=[^]{3}[^]|[^][^]*|.[\\\\\\u009d\\\\fn](?=[\\\\v\\\\0])++*)\", \"gy\"); var s = \"1\\n1\\n1\\n1\\n1\\n1\\n1\\n1\\nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn\\n\\n\\n\\n\\nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn\"; print(s.split(r)); h1.getPropertyDescriptor = (function mcc_() { var pxnsiq = 0; return function() { ++pxnsiq; if (/*ICCD*/pxnsiq % 4 != 0) { dumpln('hit!'); try { /*MXX3*/g0.Array.prototype.map = o2.g2.Array.prototype.map; } catch(e0) { } try { this.g2.t1[1]; } catch(e1) { } v2 = evaluate(\"o0.m2.get(e2);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (qqzxnr_1[0] % 2 != 0), noScriptRval: true, sourceIsLazy: new RegExp(\"\\\\w*?\", \"i\"), catchTermination: true, element: this.o2, elementAttributeName: s1 })); } else { dumpln('miss!'); try { v2 = Object.prototype.isPrototypeOf.call(h0, m0); } catch(e0) { } h2.getOwnPropertyNames = f0; } };})();\nlet qqzxnr_1[3];return /\\2(?=(\u00e2)*?)\\d+?{4,8388612}/yim;\n");
/*fuzzSeed-204645237*/count=299; tryItOut("w;");
/*fuzzSeed-204645237*/count=300; tryItOut("switch(((void shapeOf( /x/g )))) { default: break; /* no regression tests found */break; case 5: z = (4277);print( /x/ );print( /x/ );break; case 4: a1.unshift(e1, v1);break; h2.get = f0; }");
/*fuzzSeed-204645237*/count=301; tryItOut("\"use strict\"; print(g0.e0);");
/*fuzzSeed-204645237*/count=302; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (((((Math.imul(((Math.fround((Math.fround(mathy2((y >>> 0), (x >>> 0))) ? (x >>> 0) : y)) >>> 0) && (1/0 >>> 0)), mathy0(0x100000001, (Math.min((Number.MAX_SAFE_INTEGER | 0), Math.fround(x)) | 0))) | 0) ? ((Math.fround(Math.min(Math.fround(x), ((Math.min(y, (y >>> 0)) >>> 0) >>> 0))) <= x) | 0) : (mathy0(Math.imul(((y ? x : y) ^ x), -(2**53)), Math.sign((x >>> 0))) | 0)) | 0) >= (Math.imul((( + (( + -(2**53)) * ( + -Number.MAX_SAFE_INTEGER))) | 0), ((((Math.fround(x) || y) - y) >>> (y >> ( + Math.pow(y, x)))) | 0)) | 0)) | 0)); }); ");
/*fuzzSeed-204645237*/count=303; tryItOut("v2 = evalcx(\"\\\"use asm\\\"; v2 = g0.g1.runOffThreadScript();\", g1);");
/*fuzzSeed-204645237*/count=304; tryItOut("h1.valueOf = (function() { try { (void schedulegc(g0)); } catch(e0) { } try { p2.toSource = f0; } catch(e1) { } try { for (var v of m0) { try { m0.has(g2.m1); } catch(e0) { } try { s2 = new String(b1); } catch(e1) { } try { Object.prototype.unwatch.call(h2, \"preventExtensions\"); } catch(e2) { } for (var p in b0) { try { ; } catch(e0) { } /*ADP-1*/Object.defineProperty(a0, 5, ({writable: (yield let (e) e), configurable: true})); } } } catch(e2) { } this.a2 = Array.prototype.filter.call(a0, (function mcc_() { var qxgjbj = 0; return function() { ++qxgjbj; g2.f0(/*ICCD*/qxgjbj % 7 == 3);};})()); return f1; });");
/*fuzzSeed-204645237*/count=305; tryItOut("v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-204645237*/count=306; tryItOut("a1 + '';");
/*fuzzSeed-204645237*/count=307; tryItOut("m1.get(i2);");
/*fuzzSeed-204645237*/count=308; tryItOut("i0.next();");
/*fuzzSeed-204645237*/count=309; tryItOut("Array.prototype.sort.apply(a2, [(function() { try { s1 += s0; } catch(e0) { } try { h0.getOwnPropertyNames = f0; } catch(e1) { } /*RXUB*/var r = r1; var s = \"\"; print(uneval(r.exec(s)));  return p0; }), t0, e0, b1]);");
/*fuzzSeed-204645237*/count=310; tryItOut("\"use strict\"; v1 = (h2 instanceof p1);");
/*fuzzSeed-204645237*/count=311; tryItOut("/*ADP-2*/Object.defineProperty(a1, 0, { configurable: false, enumerable: (x % 35 == 16), get: (function(j) { f1(j); }), set: (new Function(\"v2 = a2.length;\")) });");
/*fuzzSeed-204645237*/count=312; tryItOut("\"use strict\"; i0.toSource = f2;");
/*fuzzSeed-204645237*/count=313; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.min((Math.fround(Math.log10(Math.fround(Math.atan2(Math.sinh(( + ( + (x <= -0x100000000)))), ((Math.fround(((( + Math.fround(( + Math.asin(x)))) >>> 0) >>> x)) * Math.atanh(( + 1.7976931348623157e308))) | 0))))) | 0), (( + Math.exp(( + ( + Math.log2(Math.fround(Math.imul((((x | 0) , (( + x) | 0)) | 0), x))))))) | 0)); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), -0x100000000, 1.7976931348623157e308, -0x07fffffff, -0x100000001, 0x07fffffff, 0, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, -0, Number.MAX_VALUE, -1/0, 42, -(2**53), -0x080000000, Number.MIN_VALUE, 0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 1, 0x100000000, -0x080000001, 2**53+2, 0.000000000000001, 2**53, -Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=314; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=315; tryItOut("\"use strict\"; /*iii*/switch(x) { default: s0 += s2; }/*hhh*/function spefsy(size, x){/*RXUB*/var r = o2.r1; var s = s2; print(r.exec(s)); }");
/*fuzzSeed-204645237*/count=316; tryItOut("testMathyFunction(mathy0, [2**53, -0x080000000, -Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 1, Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -1/0, 2**53-2, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53), 0x080000001, 1/0, -0x100000000, 0x07fffffff, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0, -(2**53-2), 0x100000001, 0/0, 0x100000000, 42, 0.000000000000001, Number.MIN_VALUE, Math.PI, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=317; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.log10((( ~ ( + Math.pow(( + (Math.atan2((y | 0), (y | 0)) | 0)), (Math.log1p(x) | ( - x))))) | 0)); }); ");
/*fuzzSeed-204645237*/count=318; tryItOut("a2.reverse(g0);");
/*fuzzSeed-204645237*/count=319; tryItOut("\"use strict\"; testMathyFunction(mathy5, [[0], (new Boolean(false)), NaN, '0', (new Number(-0)), objectEmulatingUndefined(), null, undefined, -0, ({valueOf:function(){return '0';}}), (function(){return 0;}), (new Boolean(true)), /0/, '/0/', '', 1, [], ({valueOf:function(){return 0;}}), '\\0', (new String('')), ({toString:function(){return '0';}}), false, 0, true, 0.1, (new Number(0))]); ");
/*fuzzSeed-204645237*/count=320; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.fround(Math.fround((Math.log1p(( + (mathy0((x >>> 0), (x >>> 0)) >>> 0))) | 0)))); }); testMathyFunction(mathy2, [42, 0x07fffffff, Math.PI, -(2**53-2), -(2**53+2), -Number.MAX_VALUE, 0x100000001, 2**53, -0, -0x100000000, 0/0, 0x0ffffffff, 1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, -0x100000001, -0x080000001, 1, Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, 0.000000000000001, 0x080000000, -0x07fffffff, -Number.MIN_VALUE, -0x0ffffffff, 0]); ");
/*fuzzSeed-204645237*/count=321; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i2 = (/*FFI*/ff(((+(-1.0/0.0))))|0);\n    return ((((0xdb84cca7))+(i3)+(!((524289.0) >= (+(1.0/0.0))))))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x07fffffff, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, 0x080000000, -0x080000001, 0x0ffffffff, 0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -(2**53), 42, 0x080000001, 0.000000000000001, 0, Number.MAX_VALUE, -(2**53+2), -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, 0x100000000, 2**53-2, -0x0ffffffff, Math.PI, -1/0, -0x080000000, 1]); ");
/*fuzzSeed-204645237*/count=322; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (new RegExp(\"(?=\\\\cH+?)\\\\S|.*?{1024,1025}|(?![^]){1,}(?:(?:\\\\s).*)\", \"ym\").__proto__%=(4277)); }); testMathyFunction(mathy2, /*MARR*/[x, -0, {}, -(2**53+2), x, -(2**53+2), x, x, x, -(2**53+2), x, -0, -(2**53+2), -(2**53+2), {}, -(2**53+2), -0, {}, -(2**53+2), x, -0, -0, -0, {}, {}, -0, {}, {}, -(2**53+2), x, -(2**53+2), -0, x, -0, x, -(2**53+2), -0, {}, -(2**53+2), -0, {}, x, x, -(2**53+2), -(2**53+2), -0, {}, x, {}, -(2**53+2), {}, -0, x, -(2**53+2), -(2**53+2), {}, -(2**53+2), x, -0, {}, -0, {}, {}, {}, x, -0, {}, x, {}, {}, x, {}, -(2**53+2), -0, {}, -0, {}, -(2**53+2), x, -0, {}, x, {}, -0, {}, x, x, -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), x, {}, -(2**53+2), -0, -(2**53+2), {}, -0, -(2**53+2), -0, -(2**53+2), {}, -(2**53+2), x, -(2**53+2), x, -(2**53+2), x, x, x, -0, -(2**53+2), -0, -0, -0, -0, -0]); ");
/*fuzzSeed-204645237*/count=323; tryItOut("\"use strict\"; Array.prototype.splice.apply(g1.o2.a2, [NaN, 4]);");
/*fuzzSeed-204645237*/count=324; tryItOut("v2 = evaluate(\"function f2(this.g0)  { (window); } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 30 != 6), sourceIsLazy: (x % 6 != 2), catchTermination: true }));");
/*fuzzSeed-204645237*/count=325; tryItOut("v0 = (f1 instanceof s2);");
/*fuzzSeed-204645237*/count=326; tryItOut("");
/*fuzzSeed-204645237*/count=327; tryItOut("v2 = a1.length;");
/*fuzzSeed-204645237*/count=328; tryItOut("");
/*fuzzSeed-204645237*/count=329; tryItOut("switch(new mathy4()) { true }");
/*fuzzSeed-204645237*/count=330; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(?:\\\\3h)[\\\\r-0]|[^k-\\\\u5639\\\\\\uffba\\\\cS]\\\\S*\\\\B?|(?:^){4,}|(?![^\\\\-\\uf9a0\\\\s])?{67108865,}\\\\S)\", \"gyi\"); var s = \"Laa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1Laa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1Laa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1Laa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1Laa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1aaLaa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1Laa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1Laa 1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\\u00f21a\\n1 \\n1\"; print(s.replace(r, function(y) { \"use strict\"; yield y; /* no regression tests found */; yield y; })); ");
/*fuzzSeed-204645237*/count=331; tryItOut("m0.set(a2, o0.i0);");
/*fuzzSeed-204645237*/count=332; tryItOut("a2.reverse();");
/*fuzzSeed-204645237*/count=333; tryItOut("\"use strict\"; for(let e of /*MARR*/[[1], ['z'], ['z'], ['z'], new String(''), ['z'], new String(''), new String(''), [1], [1], [1], [1], ['z'], [1], new String(''), new String(''), ['z'], new String(''), ['z'], new String(''), ['z'], ['z'], [1], [1], [1], [1], new String(''), new String(''), new String(''), ['z'], ['z'], [1], [1], [1], ['z'], ['z'], ['z'], new String(''), ['z'], [1], new String(''), [1], [1], [1], new String(''), [1], [1], ['z'], [1], new String(''), new String(''), ['z'], new String(''), ['z'], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new String(''), new String(''), ['z'], ['z'], ['z'], new String(''), new String(''), [1], ['z'], [1], new String(''), new String(''), [1], new String(''), [1], ['z'], ['z'], ['z'], [1], [1], ['z'], ['z'], new String(''), [1], new String(''), new String(''), [1], [1], [1], [1]]) with({}) { let(z) ((function(){return;})()); } ");
/*fuzzSeed-204645237*/count=334; tryItOut("do {t0[6] = i2; } while((w != x) && 0);");
/*fuzzSeed-204645237*/count=335; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.imul(( - ( + (x || y))), (( ~ (((y | (( ! (Math.tanh((-Number.MAX_SAFE_INTEGER | 0)) | 0)) <= -Number.MAX_SAFE_INTEGER)) >>> 0) >>> 0)) | 0))); }); testMathyFunction(mathy0, [1/0, 0x0ffffffff, 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, 0x100000000, -0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 0x07fffffff, -(2**53-2), 0x080000000, 42, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -0x100000001, -0x100000000, Number.MAX_VALUE, 2**53+2, -(2**53+2), Math.PI, 0/0, -0x07fffffff, 2**53, -Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=336; tryItOut("print(true);");
/*fuzzSeed-204645237*/count=337; tryItOut("const {x: [{x: x}], a: {x: {x: \u3056}}, e: [, let]} = (void options('strict_mode')), let;print(x);");
/*fuzzSeed-204645237*/count=338; tryItOut("\"use strict\"; /*oLoop*/for (dfbtjw = 0, jrlwxi; dfbtjw < 0; ++dfbtjw) { for (var p in h0) { try { m0.set(g2, a2); } catch(e0) { } try { t0.toSource = f1; } catch(e1) { } try { v2 = (a2 instanceof g0); } catch(e2) { } v1 = evaluate(\"print(o2);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: true })); } } ");
/*fuzzSeed-204645237*/count=339; tryItOut("\"use strict\"; for (var p in i1) { try { m0 + e1; } catch(e0) { } v1.toString = String.prototype.trimRight.bind(p2); }");
/*fuzzSeed-204645237*/count=340; tryItOut("/*tLoop*/for (let x of /*MARR*/[new Boolean(false), {}, x, {}, {}, x, new Boolean(false), x, new Boolean(false), {}, new Boolean(false), {}, x, x, new Boolean(false), new Boolean(false), {}, {}, -0x100000000, -0x100000000, -0x100000000, {}, new Boolean(false), new Boolean(false), new Boolean(false), -0x100000000, -0x100000000, {}, {}, new Boolean(false), {}, new Boolean(false), new Boolean(false), -0x100000000, new Boolean(false), {}, {}, {}, -0x100000000, {}, new Boolean(false), -0x100000000, -0x100000000, x, x, new Boolean(false), new Boolean(false), new Boolean(false), x, {}, x, {}, new Boolean(false), x, {}, new Boolean(false), new Boolean(false), x, {}, new Boolean(false), new Boolean(false), x, {}, -0x100000000, new Boolean(false), -0x100000000, -0x100000000, x, {}, {}, -0x100000000, {}, new Boolean(false), -0x100000000, -0x100000000, -0x100000000, new Boolean(false), -0x100000000, new Boolean(false), x, {}, {}, x, {}, {}, -0x100000000, {}, new Boolean(false), {}, {}, {}, x, x, -0x100000000, -0x100000000, -0x100000000, new Boolean(false), -0x100000000, -0x100000000, new Boolean(false), -0x100000000, -0x100000000, new Boolean(false), x, new Boolean(false), -0x100000000, -0x100000000, new Boolean(false)]) { a0.length = 9;\no1.s2 = new String(this.i1);\n }");
/*fuzzSeed-204645237*/count=341; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=342; tryItOut("/*RXUB*/var r = /(?=[\ued96\\d\u0098\\cE-M]{2})/im; var s = \"_\\u1243__\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=343; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0x430f827e);\n    i0 = (0x6139e471);\n;    return +((-16777216.0));\n  }\n  return f; })(this, {ff: Number.isSafeInteger}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0/0, 0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, 0, -1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, 1, -0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 1/0, 0x0ffffffff, 42, -0x100000001, -(2**53-2), Math.PI, 2**53+2, 0x100000001, -0x080000000, -(2**53+2), -0]); ");
/*fuzzSeed-204645237*/count=344; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=345; tryItOut("mathy5 = (function(x, y) { return ((mathy2(( - Number.MAX_SAFE_INTEGER), (Math.atan2((2**53 >>> 0), ((Math.fround(((Math.PI | 0) | ( ~ 0x07fffffff))) * Math.fround(Math.expm1((Math.cbrt((y | 0)) | 0)))) >>> 0)) >>> 0)) > (Math.sinh((Math.fround(( + (( + (y >>> 0)) | 0))) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy5, [-0x100000001, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, -0, -0x080000000, 42, 0/0, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -(2**53), 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, -(2**53-2), -0x100000000, 0, 2**53-2, 0.000000000000001, 0x100000001, 1, Math.PI, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 0x080000000]); ");
/*fuzzSeed-204645237*/count=346; tryItOut("/*vLoop*/for (let oacxgj = 0; oacxgj < 92; ++oacxgj,  \"\" ) { var z = oacxgj; this; } ");
/*fuzzSeed-204645237*/count=347; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.shift.call(a1);");
/*fuzzSeed-204645237*/count=348; tryItOut("a0[3] = o1;");
/*fuzzSeed-204645237*/count=349; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=350; tryItOut("if(x) { if (yield (w) = false) a0.length = Object.defineProperty(x, \"setHours\", ({configurable: false})); else (void schedulegc(g1));}");
/*fuzzSeed-204645237*/count=351; tryItOut("\"use strict\"; \"use asm\"; /*bLoop*/for (var nsxygs = 0; nsxygs < 21; ++nsxygs) { if (nsxygs % 5 == 2) { print(x); } else { (a); }  } ");
/*fuzzSeed-204645237*/count=352; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?=\\\\1|\\\\B*?[^]+{549755813887,549755813891}*?)(?=\\\\1|(?!(.{4}))){2}+?)\", \"yim\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=353; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(Math.ceil(( - Math.round(y))), (Math.acos((Math.atan2((x ? -Number.MIN_SAFE_INTEGER : (y | 0)), ( + y)) == Math.fround((Math.fround((Math.sqrt(x) >>> 0)) < ( + Math.atan2(( + ( + y)), Math.min((((x >>> 0) ? (x >>> 0) : (x >>> 0)) | 0), x))))))) | 0)); }); ");
/*fuzzSeed-204645237*/count=354; tryItOut("print((4277));\nsfbadg(this, [z1,,]);/*hhh*/function sfbadg(x){a1 + '';}\nv2 = a2.length;");
/*fuzzSeed-204645237*/count=355; tryItOut("mathy5 = (function(x, y) { return Math.atan2(( + ( - Math.sign(( + (( + y) >> ( + ( + x))))))), Math.cosh((( + (((y != ( + (Math.fround(x) >> Math.fround(0x07fffffff)))) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-0x07fffffff, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, -1/0, -0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, 0.000000000000001, 0/0, Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), -Number.MIN_VALUE, 0, 1, 1/0, 42, -0x0ffffffff, -Number.MAX_VALUE, -0, Number.MAX_VALUE, -0x080000001, -0x100000001, 0x100000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, 2**53+2, 2**53-2, 0x07fffffff]); ");
/*fuzzSeed-204645237*/count=356; tryItOut("testMathyFunction(mathy3, [-0x100000001, -1/0, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0, 0x07fffffff, -0x080000000, 0x0ffffffff, -0x080000001, -(2**53-2), -0, 1, 42, 2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, -0x0ffffffff, 2**53, 1.7976931348623157e308, 0x100000001, -(2**53), 0.000000000000001, -0x100000000, -0x07fffffff, 2**53+2]); ");
/*fuzzSeed-204645237*/count=357; tryItOut("M:with({x: x}){/* no regression tests found *//*RXUB*/var r = /(($){2}|$)|(.|\\b){3,3}|[^]*?\\W{3,}*(?:\\cE)|(\u00d5|\\B*?)\\b|[\\w\\w\\D\\t-;]{0,2}+?/y; var s = \"\"; print(uneval(s.match(r)));  }");
/*fuzzSeed-204645237*/count=358; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + mathy0((( + Math.atan2((y - ( + y)), (mathy1((((( ~ x) | 0) && (x | 0)) | 0), (y ^ Math.fround(x))) >>> 0))) <= Math.min((Math.fround(Math.sin(Math.fround((Math.log10((y >> y)) | 0)))) !== (( + Math.atan2(x, (((y >>> 0) == (Number.MIN_VALUE | 0)) >>> 0))) << x)), (1.7976931348623157e308 == (-0x0ffffffff | 0)))), ((( - (Math.min((Math.atan2(y, 2**53) >>> 0), y) | 0)) >>> Math.atan2(( + Math.pow(-Number.MIN_VALUE, y)), (( - ( + y)) | 0))) >>> 0))); }); testMathyFunction(mathy2, [-0x080000000, Number.MIN_SAFE_INTEGER, -0, 0/0, Number.MAX_VALUE, 0, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, 0x080000000, -0x100000001, -Number.MIN_VALUE, 2**53, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, 0x07fffffff, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, -0x0ffffffff, 0x100000001, 1, 0x100000000, -(2**53-2), 0.000000000000001, -0x100000000]); ");
/*fuzzSeed-204645237*/count=359; tryItOut("delete h1.getOwnPropertyDescriptor;");
/*fuzzSeed-204645237*/count=360; tryItOut("for (var v of g0) { try { s2 += 'x'; } catch(e0) { } try { h2 = ({getOwnPropertyDescriptor: function(name) { o0.g1.o1.o2.o2[\"x\"] = o2.o2;; var desc = Object.getOwnPropertyDescriptor(t0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v0 = Object.prototype.isPrototypeOf.call(h0, i1);; var desc = Object.getPropertyDescriptor(t0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Array.prototype.unshift.apply(a0, [g2, Math.imul(-29(), 4), p1]);; Object.defineProperty(t0, name, desc); }, getOwnPropertyNames: function() { Array.prototype.pop.call(a0);; return Object.getOwnPropertyNames(t0); }, delete: function(name) { h0 = ({getOwnPropertyDescriptor: function(name) { m1 = new WeakMap;; var desc = Object.getOwnPropertyDescriptor(g2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { m1.delete(h2);; var desc = Object.getPropertyDescriptor(g2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { h2.hasOwn = (function(j) { if (j) { try { t0 = new Uint8ClampedArray(b0); } catch(e0) { } try { a1[v0] = v1; } catch(e1) { } try { p2 = g2.g0.objectEmulatingUndefined(); } catch(e2) { } b2 = new SharedArrayBuffer(48); } else { try { Array.prototype.push.apply(a0, [g1.t2, g2.p1]); } catch(e0) { } try { for (var v of b2) { try { Array.prototype.push.call(a2, m2, p1, this.g2.s0, m2); } catch(e0) { } (void schedulegc(o0.g1)); } } catch(e1) { } b1 = o1; } });; Object.defineProperty(g2, name, desc); }, getOwnPropertyNames: function() { Object.seal(h1);; return Object.getOwnPropertyNames(g2); }, delete: function(name) { throw i1; return delete g2[name]; }, fix: function() { f0 = t1[18];; if (Object.isFrozen(g2)) { return Object.getOwnProperties(g2); } }, has: function(name) { o2.t2[16] = m2;; return name in g2; }, hasOwn: function(name) { o2.t0.toString = (function() { try { b0 = t0.buffer; } catch(e0) { } try { t2[v2] = a1; } catch(e1) { } s2 = ''; return g2.e2; });; return Object.prototype.hasOwnProperty.call(g2, name); }, get: function(receiver, name) { h0.valueOf = (function() { try { o0 = s1.__proto__; } catch(e0) { } try { ; } catch(e1) { } o2.m0 = new Map; throw v2; });; return g2[name]; }, set: function(receiver, name, val) { e2 = new Set;; g2[name] = val; return true; }, iterate: function() { /*MXX3*/g2.Date.prototype.setSeconds = g2.Date.prototype.setSeconds;; return (function() { for (var name in g2) { yield name; } })(); }, enumerate: function() { this.v1 = (h1 instanceof this.h1);; var result = []; for (var name in g2) { result.push(name); }; return result; }, keys: function() { g1.a2.push(h2, g0.t2, b0);; return Object.keys(g2); } });; return delete t0[name]; }, fix: function() { t2 = new Int16Array(9);; if (Object.isFrozen(t0)) { return Object.getOwnProperties(t0); } }, has: function(name) { return g0.f2; return name in t0; }, hasOwn: function(name) { v0 = r2.toString;; return Object.prototype.hasOwnProperty.call(t0, name); }, get: function(receiver, name) { i1.next();; return t0[name]; }, set: function(receiver, name, val) { ;; t0[name] = val; return true; }, iterate: function() { print(uneval(a0));; return (function() { for (var name in t0) { yield name; } })(); }, enumerate: function() { h1 = t1[10];; var result = []; for (var name in t0) { result.push(name); }; return result; }, keys: function() { v1 = g1.runOffThreadScript();; return Object.keys(t0); } }); } catch(e1) { } var v2 = 0; }/*MARR*/[ /x/ ,  /x/ , 2**53+2, (void 0),  /x/ , objectEmulatingUndefined(), 2**53+2, (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), 2**53+2, (void 0),  /x/ ,  /x/ , 2**53+2,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0),  /x/ , 2**53+2, objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), 2**53+2, (void 0),  /x/ , 2**53+2, 2**53+2,  /x/ , 2**53+2, 2**53+2, objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(),  /x/ , 2**53+2, 2**53+2,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , 2**53+2, 2**53+2].sort;");
/*fuzzSeed-204645237*/count=361; tryItOut("\"use strict\"; v0 = evalcx(\"function f1(g0.f2)  { \\\"use strict\\\"; yield delete e.g0.f2 } \", g2);");
/*fuzzSeed-204645237*/count=362; tryItOut("testMathyFunction(mathy3, [2**53, 2**53+2, -0, 1, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 0.000000000000001, -1/0, -Number.MIN_VALUE, 0, 42, Number.MIN_VALUE, 1/0, -(2**53), -0x080000001, 0x080000000, 0/0, 2**53-2, -(2**53+2), 0x100000000, -0x080000000, Math.PI, -0x100000000, 0x080000001, Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=363; tryItOut("s1 += s1;");
/*fuzzSeed-204645237*/count=364; tryItOut("var tqdnqn = new SharedArrayBuffer(16); var tqdnqn_0 = new Uint32Array(tqdnqn); tqdnqn_0[0] = 6; print(tqdnqn_0);");
/*fuzzSeed-204645237*/count=365; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-204645237*/count=366; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - Math.atan(Math.fround((Math.max(( + Math.fround((Math.fround(y) & y))), ( + (x ? ( + mathy1(x, ( + x))) : x))) | 0)))); }); testMathyFunction(mathy2, [42, -0x080000001, 0, 2**53-2, -0x07fffffff, 0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, -0, Number.MIN_VALUE, 1, -(2**53+2), -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, -Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -(2**53), 2**53+2, Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 0/0, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, Math.PI]); ");
/*fuzzSeed-204645237*/count=367; tryItOut("a0.forEach((function() { try { b2 = e1; } catch(e0) { } print(uneval(m1)); return h0; }), b2, g2);");
/*fuzzSeed-204645237*/count=368; tryItOut("for (var v of t2) { try { e0.has(this.o2.m0); } catch(e0) { } g2.t0.set(a2, \"\\u0578\"); }");
/*fuzzSeed-204645237*/count=369; tryItOut("v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: true, sourceIsLazy: (x % 43 != 38), catchTermination: (x % 3 != 0) }));");
/*fuzzSeed-204645237*/count=370; tryItOut("v1.toString = (function(j) { if (j) { try { t0[10] = ((timeout(1800)) ** Object.defineProperty(/*PTHR*/(function() { \"use strict\"; for (var i of (intern(y)) if (( /* Comment */window))) { yield i; } })(), \"toSource\", ({configurable: (x % 30 != 9), enumerable: (x % 2 != 1)})).__defineGetter__(\"z\", decodeURI)); } catch(e0) { } try { /*MXX1*/o0 = g0.String.prototype.big; } catch(e1) { } try { /*ODP-3*/Object.defineProperty(m1, 12, { configurable: false, enumerable: false, writable: false, value: o0.a0 }); } catch(e2) { } /*RXUB*/var r = r1; var s = g1.s2; print(s.match(r)); print(r.lastIndex);  } else { try { s1 = a1[4]; } catch(e0) { } try { this.o1.g2.m2.delete(this.t0); } catch(e1) { } try { for (var v of this.h0) { try { for (var v of this.p0) { h2.hasOwn = f1; } } catch(e0) { } try { m1.delete(this.o0); } catch(e1) { } try { Array.prototype.shift.apply(a0, [i0]); } catch(e2) { } this.m0.get(x); } } catch(e2) { } v2 = (o0 instanceof f1); } });");
/*fuzzSeed-204645237*/count=371; tryItOut("mathy3 = (function(x, y) { return ( + ((Math.atan2((( + Math.fround((y > Math.fround((Math.tan(Math.fround(Math.max(0x07fffffff, Math.fround(x)))) ** mathy0(0x07fffffff, x)))))) | 0), ((Math.imul(Math.min((Math.ceil(-0x080000001) | 0), y), (y || 2**53)) | (((x | 0) ** (Math.sin(( + Math.tan((x % -0x080000000)))) | 0)) | 0)) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy3, [-0, (new Number(-0)), '', [], 0.1, ({toString:function(){return '0';}}), (new String('')), /0/, 1, '0', undefined, 0, true, objectEmulatingUndefined(), false, (new Boolean(true)), null, (function(){return 0;}), '/0/', (new Number(0)), (new Boolean(false)), ({valueOf:function(){return 0;}}), '\\0', [0], NaN, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-204645237*/count=372; tryItOut("\"use strict\"; with({a:  /x/ }){(/*FARR*/[true, /\\B|\\B{2}($)|(\\S|[\\d\\\u0014]){2,4}|\\1{3,}|(?:(?:[^\\xEb])*?)*/gyi, a, , \u3056, ...[], x].map(c =>  { \"use strict\"; return new RegExp(\"(?:(?=(?=([^\\ua64b-\\u063f])|[^]+{1,5})))\", \"\") } , x));v0 = o2.g1.t2.length; }");
/*fuzzSeed-204645237*/count=373; tryItOut("\"use strict\"; t0 = new Uint8ClampedArray(g1.t1);");
/*fuzzSeed-204645237*/count=374; tryItOut("\"use strict\"; a0 = Array.prototype.slice.apply(a1, [0, NaN, p2, v1]);");
/*fuzzSeed-204645237*/count=375; tryItOut("\"use strict\"; p2.toSource = (function() { for (var j=0;j<27;++j) { f0(j%3==0); } });");
/*fuzzSeed-204645237*/count=376; tryItOut("print(uneval(a0));");
/*fuzzSeed-204645237*/count=377; tryItOut("i1.next();/*MXX2*/g1.RegExp.$+ = g0.h1;");
/*fuzzSeed-204645237*/count=378; tryItOut("m1.get(g2.i2);");
/*fuzzSeed-204645237*/count=379; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.log10((mathy3((mathy2(((Math.fround(y) >= ((Math.atanh((x >>> 0)) >>> 0) | 0)) >>> 0), (( + ( + ( + y))) >>> 0)) >>> 0), Math.hypot((((((x ? Math.fround(x) : y) <= ( ! x)) | 0) <= (y | 0)) | 0), (Math.sin(( + (x << y))) >>> 0))) >>> 0)); }); testMathyFunction(mathy4, [-0x0ffffffff, 1/0, 0x07fffffff, Math.PI, 42, 0, -0x07fffffff, 0x100000001, -1/0, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -(2**53+2), -(2**53), 1, 0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, -0x100000001, 0x080000001, -0, Number.MAX_VALUE, 2**53, -(2**53-2), Number.MIN_VALUE, 2**53-2, 2**53+2, -0x080000000, -Number.MIN_VALUE, -0x100000000, 0x080000000]); ");
/*fuzzSeed-204645237*/count=380; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ( - Math.log(( + ( ! (42 !== Math.fround(x)))))); }); testMathyFunction(mathy4, [2**53+2, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 0x080000000, Math.PI, -0x080000000, 0, 2**53, 0x080000001, -0x080000001, -(2**53-2), Number.MIN_VALUE, -(2**53), 2**53-2, 0x07fffffff, -0x0ffffffff, 0/0, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 1/0, -Number.MAX_VALUE, 42, 1.7976931348623157e308, 0x100000000, -0, -0x07fffffff, -(2**53+2), 0x100000001, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=381; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=382; tryItOut("mathy2 = (function(x, y) { return ( + Math.cos(( + (( ~ Math.fround(Math.atan2((y >>> 0), ((Math.tanh((( - (y | 0)) | 0)) | 0) >>> 0)))) <= ( ~ Math.hypot((x ? (Math.hypot((( + (x >>> 0)) >>> 0), (x >>> 0)) >>> 0) : x), ( + Math.imul(( + y), ( + 0))))))))); }); ");
/*fuzzSeed-204645237*/count=383; tryItOut("function eval(z) { yield x } print(x);");
/*fuzzSeed-204645237*/count=384; tryItOut("t0.__iterator__ = (function() { try { i0.next(); } catch(e0) { } s1 += s0; return m1; });\n{ void 0; void relazifyFunctions(); }\n");
/*fuzzSeed-204645237*/count=385; tryItOut("/*RXUB*/var r = new RegExp(\"((?![^\\uc994\\\\U]?))?|(?!(?=\\\\B|\\\\B|\\\\b))+??(?![^]?)|(?:\\\\3)\", \"g\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=386; tryItOut("\"use strict\"; \"use asm\"; v2 = Object.prototype.isPrototypeOf.call(e2, f0);");
/*fuzzSeed-204645237*/count=387; tryItOut("/*bLoop*/for (let vfvwee = 0; vfvwee < 50 && (new RegExp(\"(?!\\\\3$|\\\\1{2}|(?:(?![^]))+?)\", \"gi\")); ++vfvwee) { if (vfvwee % 45 == 2) { this.v2 = this.g0.eval(\"/* no regression tests found */\"); } else { print(x); }  } ");
/*fuzzSeed-204645237*/count=388; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x080000000, 0x080000001, -0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, -0x100000000, 42, -0x0ffffffff, 0x100000001, 0x0ffffffff, -(2**53-2), 0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 1/0, Math.PI, 0x07fffffff, -Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, 2**53, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 1, 1.7976931348623157e308, -0]); ");
/*fuzzSeed-204645237*/count=389; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(h1, s0);");
/*fuzzSeed-204645237*/count=390; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ~ ( + (( + (( + mathy1(( + x), ( + y))) - Math.fround(mathy1(Math.fround(Math.atan2(y, Math.imul((Math.hypot((x >>> 0), (y >>> 0)) >>> 0), y))), (x | 0))))) % ( + ( ~ (Math.min(mathy1(x, x), ( + (y >= (y >>> 0)))) >>> 0)))))); }); testMathyFunction(mathy2, [0x0ffffffff, 1/0, Number.MIN_VALUE, 1, 1.7976931348623157e308, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, 0.000000000000001, 0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 0, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), -Number.MIN_VALUE, -(2**53+2), -(2**53), 2**53, -0, 0x07fffffff, Math.PI, 2**53-2, 0x080000000, 2**53+2, -0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, -0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=391; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atan2((Math.acos(( + Math.min((((Math.fround((Math.fround(x) > Math.fround(((((( + x) & ( + -Number.MIN_SAFE_INTEGER)) | 0) >> x) | 0)))) >>> 0) < (y >>> 0)) >>> 0), (Math.sin(Math.imul(Number.MIN_SAFE_INTEGER, ((Math.hypot((y >>> 0), y) >>> 0) ** Math.fround(x)))) | 0)))) >>> 0), Math.fround(( ! Math.fround((Math.atanh(((0x100000000 == ( - x)) >>> 0)) / ( ~ y)))))) >>> 0); }); ");
/*fuzzSeed-204645237*/count=392; tryItOut("mathy2 = (function(x, y) { return (( ~ ( + (( + Math.fround(( + mathy0(-(2**53-2), Number.MAX_VALUE)))) ^ ( + Math.min(Math.fround(( ~ ((((-0 + y) | 0) ? y : ((( ~ Number.MIN_SAFE_INTEGER) && x) | 0)) >>> 0))), (Math.cosh(Math.fround(mathy0(Math.fround(y), Math.fround(Math.fround(mathy0(Math.fround(x), Math.fround(y))))))) >>> 0)))))) >>> 0); }); testMathyFunction(mathy2, [-0x100000001, 0.000000000000001, 0x080000001, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -1/0, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 2**53, 0/0, 0, 2**53-2, -(2**53+2), -0x07fffffff, -0x080000001, Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -0, -0x080000000, -(2**53), Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, 1, 42, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=393; tryItOut("{ void 0; minorgc(false); }");
/*fuzzSeed-204645237*/count=394; tryItOut("/*oLoop*/for (let kuckyb = 0; kuckyb < 35; ((function fibonacci(kafmjd) { ; if (kafmjd <= 1) { v0 = Object.prototype.isPrototypeOf.call(t1, b1);; return 1; } { void 0; try { gcparam('sliceTimeBudget', 50); } catch(e) { } } ; return fibonacci(kafmjd - 1) + fibonacci(kafmjd - 2);  })(3)), ++kuckyb) { v0 = Object.prototype.isPrototypeOf.call(i1, g2); } ");
/*fuzzSeed-204645237*/count=395; tryItOut("testMathyFunction(mathy3, [1.7976931348623157e308, 42, -(2**53), 0x07fffffff, 0.000000000000001, Math.PI, 0x100000000, -0x07fffffff, -0x100000001, 0/0, -0x080000001, 1/0, 0x0ffffffff, -1/0, 0x080000001, -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 1, -0, 0x100000001, -0x100000000, 0, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -(2**53-2), 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=396; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan2((Math.sqrt(((Math.pow((( - Math.fround(Math.round((y >>> 0)))) >>> 0), (x >>> 0)) >>> 0) | 0)) | 0), (((mathy0(Math.hypot(Math.imul(y, ( + ( - (x | 0)))), y), (Math.imul((x >>> 0), (x >>> 0)) | 0)) !== y) >>> 0) || Math.atan2(y, ((((((-0x100000001 | 0) >>> (( + (( + x) ? ( + y) : ( + x))) | 0)) | 0) >>> ( + Math.fround(( + (mathy0((x | 0), (1.7976931348623157e308 | 0)) | 0))))) >>> 0) >>> (x && y))))); }); testMathyFunction(mathy1, [-0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -0x07fffffff, -0x080000001, 2**53+2, -(2**53-2), -Number.MAX_VALUE, -0x080000000, 1/0, 0.000000000000001, 0, 0x100000001, 1.7976931348623157e308, 0x0ffffffff, 2**53-2, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), -(2**53), Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, 0x07fffffff, -1/0, -0x100000001, 0x080000000, 42, 0/0, -0x100000000]); ");
/*fuzzSeed-204645237*/count=397; tryItOut("with({e: (window = this)})function f2(v2) ({a1:1})function x(x = {} = [], w = this.__defineSetter__(\"NaN\", RegExp.prototype.toString)) { return yield new RegExp(\"(?=[^\\\\w\\\\cJ\\\\uD90A\\\\W])+?|^*?(.*|[^]{0,1}\\\\v|\\\\D)|(.+)+?+\", \"ym\") } (-28);");
/*fuzzSeed-204645237*/count=398; tryItOut("\"use strict\"; const yehqjn, hdbhkz;(\"\\uF94F\");");
/*fuzzSeed-204645237*/count=399; tryItOut("mathy0 = (function(x, y) { return ( - ( + (( ! (Math.min((Math.cos((y >>> 0)) >>> 0), Math.max(Math.PI, Math.atanh(x))) | 0)) >>> 0))); }); ");
/*fuzzSeed-204645237*/count=400; tryItOut("\"use strict\"; v1 = evaluate(\"v2 = Array.prototype.some.call(a1, f0);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 4), noScriptRval: true, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-204645237*/count=401; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.hypot((Math.imul((Math.trunc((x | 0)) | 0), ( ~ Math.fround(( ! Math.max(y, x))))) != (Math.clz32(( - (x | 0))) | 0)), (((( + (( + ( ! Math.pow(( + 2**53-2), x))) ** ( + ( - ( ! ((Math.pow((1.7976931348623157e308 | 0), -(2**53)) | 0) >>> 0)))))) | 0) ** (( + y) | 0)) >>> 0)); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x100000000, 0/0, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, -(2**53-2), -1/0, -(2**53+2), 2**53, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, 42, Math.PI, -0x07fffffff, 1, 2**53+2, 0x080000000, -Number.MIN_VALUE, -0x0ffffffff, -(2**53), -0x100000001, 0x100000000, -0x080000000, -0x080000001, -0, 0, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=402; tryItOut("for (var v of i0) { m1.delete(g1.t2); }");
/*fuzzSeed-204645237*/count=403; tryItOut("testMathyFunction(mathy3, [-1/0, -0x080000001, -(2**53-2), -0x080000000, Number.MAX_VALUE, 42, -Number.MIN_VALUE, Math.PI, -0x0ffffffff, -(2**53+2), 2**53+2, 0x0ffffffff, 0x100000001, -(2**53), -0x07fffffff, 1, Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, -0x100000001, 0x07fffffff, 0x080000001, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000000, 0, 0/0]); ");
/*fuzzSeed-204645237*/count=404; tryItOut("h0.iterate = f0;");
/*fuzzSeed-204645237*/count=405; tryItOut("for (var v of a1) { try { v2 = evaluate(\" '' \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: true, sourceIsLazy: true, catchTermination: (w = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { throw 3; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(true), Int32Array)) })); } catch(e0) { } try { t0[new Root()] = s1; } catch(e1) { } a2.pop(); }m2.has(i1);");
/*fuzzSeed-204645237*/count=406; tryItOut("\"use strict\"; for (var v of g1) { try { s2 += 'x'; } catch(e0) { } o2.g1.v1 = t2.length; }");
/*fuzzSeed-204645237*/count=407; tryItOut("\"use strict\"; g0.m1.delete(o2);");
/*fuzzSeed-204645237*/count=408; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=409; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.hypot((Math.abs(y) | (((( ~ ( + (( + (Math.sqrt((x | 0)) | 0)) == ( + y)))) | 0) % ( - ( ! (y >>> 0)))) >>> 0)), Math.pow(Math.fround((Math.expm1(((Math.fround(mathy0(Math.fround(42), Math.fround(y))) - -1/0) >>> 0)) | 0)), Math.fround(( ~ Math.fround(mathy0((Math.fround((Math.fround((x | x)) % Math.fround(-Number.MIN_SAFE_INTEGER))) | 0), Math.tan(Number.MAX_VALUE))))))); }); testMathyFunction(mathy1, [42, 0x080000000, 0x100000001, 2**53, 1.7976931348623157e308, -0x100000000, -0x080000000, 0.000000000000001, 0x100000000, -(2**53+2), -0x07fffffff, 0x080000001, Math.PI, -1/0, -0x0ffffffff, 2**53-2, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 2**53+2, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 1/0, -(2**53), 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 1, -Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-204645237*/count=410; tryItOut("mathy4 = (function(x, y) { return ((( + ((mathy3(((Math.pow(y, -0x100000000) >>> 0) != ( + Math.cbrt(y))), ( + ( ~ Math.imul(( + Math.pow(Math.fround(x), y)), 0x100000001)))) | 0) * ( + ( + (Math.fround(y) < ( + Math.min(mathy3((Math.imul((Math.pow((x | 0), (-(2**53+2) | 0)) | 0), y) >>> 0), Math.fround(x)), ( + (((y >>> 0) >> (Math.sign(( + (x | 0))) >>> 0)) >>> 0))))))))) | 0) ? (((Math.fround(Math.asinh(Math.hypot(y, (( + Math.imul(( + y), ( + x))) >>> 0)))) + Math.fround(Math.fround((Math.fround(0x07fffffff) ** (Math.min(2**53, (( ~ (x | 0)) | 0)) >>> 0))))) , Math.cbrt(Math.max(( + (Math.fround(( ~ (0x0ffffffff | 0))) >>> 0)), ( + Math.fround(y))))) | 0) : (Math.fround(Math.sin(Math.hypot(( ~ (Math.atan((x >>> 0)) >>> 0)), Math.atan2(2**53, (( + (Math.atan2((x >>> 0), (-(2**53-2) >>> 0)) >>> 0)) >> x))))) | 0)); }); ");
/*fuzzSeed-204645237*/count=411; tryItOut("\"use asm\"; testMathyFunction(mathy1, [42, 1/0, 0x100000000, -(2**53), -0x100000000, 2**53-2, Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, -0, -0x080000000, 0x0ffffffff, -(2**53+2), Math.PI, -1/0, 2**53, -(2**53-2), 0x080000000, -Number.MAX_VALUE, 1, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, 0, -0x080000001, 0x07fffffff, -Number.MIN_VALUE, 2**53+2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-204645237*/count=412; tryItOut("\"use strict\"; /*RXUB*/var r = /((?=(?:[\\D\\\u0003])*?))?(?!((?:[^])*?))|[^](?!(?!\\2|$|[^]+*?+)(\\B)*?)/gy; var s = \"\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=413; tryItOut("print(x);");
/*fuzzSeed-204645237*/count=414; tryItOut("\"use strict\"; (/[^]{0}/gm)");
/*fuzzSeed-204645237*/count=415; tryItOut("\"use strict\"; /*RXUB*/var r = /\\n+?|(?!(?=\\W(?!\\u00cD)))|[^](?!(?!\\cE))|\\D{2}+/m; var s = undefined; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=416; tryItOut("/*oLoop*/for (let irivra = 0; irivra < 36; ++irivra) { a0.unshift(o0.v1, g1, o1, v0); } ");
/*fuzzSeed-204645237*/count=417; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=418; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( ! (( + (mathy1((y - x), mathy0(x, -1/0)) >>> 0)) | 0)); }); testMathyFunction(mathy2, ['', null, (new Number(0)), 1, NaN, (new Boolean(true)), 0, /0/, -0, undefined, (new Boolean(false)), '0', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), '/0/', 0.1, true, (new Number(-0)), [], ({valueOf:function(){return '0';}}), false, (new String('')), [0], (function(){return 0;}), ({toString:function(){return '0';}}), '\\0']); ");
/*fuzzSeed-204645237*/count=419; tryItOut("\"use strict\"; v0 = g0.eval(\"/*oLoop*/for (let egsdlk = 0; egsdlk < 83; ++egsdlk) { /* no regression tests found */ } \");");
/*fuzzSeed-204645237*/count=420; tryItOut("\"use strict\"; t1 = t0.subarray(\"\\u7FB1\");");
/*fuzzSeed-204645237*/count=421; tryItOut("v0 = x;");
/*fuzzSeed-204645237*/count=422; tryItOut("\"use strict\"; /*oLoop*/for (tpqzeo = 0; tpqzeo < 117; ++tpqzeo) { ((Math.pow(24, -0.098))); } ");
/*fuzzSeed-204645237*/count=423; tryItOut("print(arguments[new String(\"3\")]|=x);");
/*fuzzSeed-204645237*/count=424; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x100000001, -1/0, 0.000000000000001, -0x080000000, 1/0, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 2**53, 1, Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 0x100000000, -0x080000001, -Number.MAX_VALUE, -(2**53-2), 2**53-2, 0x100000001, 0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, 2**53+2, 0x080000000, -0, 0/0, -0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=425; tryItOut("/*bLoop*/for (var bnehrj = 0; bnehrj < 76; ++bnehrj) { if (bnehrj % 37 == 12) { print(x); } else { i2.send(g2); }  } ");
/*fuzzSeed-204645237*/count=426; tryItOut("for (var p in g0.p1) { try { /*ODP-2*/Object.defineProperty(g2.i2, \"match\", { configurable: false, enumerable: false, get: (function() { try { print(p2); } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(o0, i2); throw o1.s0; }), set: (function mcc_() { var hdddrw = 0; return function() { ++hdddrw; f2(/*ICCD*/hdddrw % 5 == 3);};})() }); } catch(e0) { } try { a1.reverse(o2.o2); } catch(e1) { } try { e1.__proto__ = m0; } catch(e2) { } a2 = a1.filter((function() { this.m1.delete(s0); return g2; })); }");
/*fuzzSeed-204645237*/count=427; tryItOut("mathy4 = (function(x, y) { return Math.imul((Math.min((( + mathy0(x, Math.fround((x ? (-Number.MAX_VALUE | 0) : Math.max(y, Math.fround(Math.log(x))))))) + ( ~ Math.fround(Math.fround(Math.sign(Math.fround(((y | 0) ? y : Math.fround(y)))))))), ( + ((Math.fround(Math.fround(Math.trunc(Math.fround(y)))) <= x) >>> 0))) >>> 0), ( + Math.hypot(Math.fround(mathy0(Math.fround((Math.fround(Math.fround(( - (Math.cosh(42) | 0)))) ? Math.fround(Math.fround((( + y) | Math.fround(x)))) : Math.fround(0))), ( + Math.fround(( ~ (Math.atan((-(2**53-2) >>> 0)) >>> 0)))))), ( + ( ! (y != y)))))); }); testMathyFunction(mathy4, [(new Boolean(true)), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), undefined, (new Number(0)), ({valueOf:function(){return 0;}}), true, /0/, (new String('')), (new Number(-0)), (function(){return 0;}), NaN, [0], '\\0', '/0/', '0', (new Boolean(false)), [], -0, null, 0, 1, objectEmulatingUndefined(), false, '', 0.1]); ");
/*fuzzSeed-204645237*/count=428; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[[1], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Number(1.5),  'A' ,  'A' , [1], [1],  'A' ,  'A' ,  'A' , {}, new Number(1.5), new Number(1.5),  'A' , new Number(1.5), new Number(1.5), {}, new Number(1.5), {},  'A' ,  'A' , {},  'A' ,  'A' , {}, {}]) { print(i2); }");
/*fuzzSeed-204645237*/count=429; tryItOut("g0 = fillShellSandbox(evalcx('lazy'));");
/*fuzzSeed-204645237*/count=430; tryItOut("");
/*fuzzSeed-204645237*/count=431; tryItOut("/*RXUB*/var r = ((decodeURIComponent)(/$/yi, [,,])); var s = \";\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=432; tryItOut("\"use strict\"; t0 = new Float64Array(b0, 3, 15);");
/*fuzzSeed-204645237*/count=433; tryItOut("/*oLoop*/for (wovabs = 0; wovabs < 122; ++wovabs) { /*infloop*/for({y, setHours} = ((void options('strict')));  /x/g ; x =  \"\" ) v0 = t1.length;true; } ");
/*fuzzSeed-204645237*/count=434; tryItOut("e0.has(a1);");
/*fuzzSeed-204645237*/count=435; tryItOut("a1 = r2.exec(o0.s2);");
/*fuzzSeed-204645237*/count=436; tryItOut("/*RXUB*/var r = r0; var s = \"\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\\u00dd\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=437; tryItOut("mathy4 = (function(x, y) { return Math.ceil(( + Math.log2((Math.pow((Math.trunc(((2**53-2 | 0) & (-0x07fffffff | 0))) | 0), (Math.pow(Math.fround(y), Math.fround(y)) | 0)) | 0)))); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), '', (new Boolean(false)), null, 0.1, -0, (new Boolean(true)), [0], ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), objectEmulatingUndefined(), '/0/', false, NaN, undefined, '0', (new String('')), [], (function(){return 0;}), /0/, 1, 0, true, (new Number(-0)), '\\0', (new Number(0))]); ");
/*fuzzSeed-204645237*/count=438; tryItOut("\"use strict\"; v1 + '';");
/*fuzzSeed-204645237*/count=439; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=440; tryItOut("\"use strict\"; v2 = t2.byteOffset;");
/*fuzzSeed-204645237*/count=441; tryItOut("");
/*fuzzSeed-204645237*/count=442; tryItOut("selectforgc(o0);");
/*fuzzSeed-204645237*/count=443; tryItOut("testMathyFunction(mathy4, [-(2**53), 0x080000001, 42, 1.7976931348623157e308, 1, -1/0, 0.000000000000001, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, -0x080000000, Number.MIN_VALUE, -0, 0x100000000, -0x07fffffff, -(2**53-2), -0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, 1/0, 2**53, -Number.MAX_VALUE, 0, 2**53+2, Math.PI, -0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-204645237*/count=444; tryItOut("Array.prototype.pop.apply(a0, [e2]);for(let [w, c] = this in /\\S[^]|(\\W)|[^]|$+?|(?:\\D|\\w)\\2|^+?(?:\\d|$)|\\3\\b^{2}|[\\W\\W\\W]^\\B{1}($)|(?!.)/yim >= -16) {/*RXUB*/var r = new RegExp(\"[^]\", \"gyi\"); var s = \"\\n\"; print(s.split(r)); /*RXUB*/var r = r0; var s = s1; print(uneval(s.match(r)));  }");
/*fuzzSeed-204645237*/count=445; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.fround(( - Math.fround(( - ( ! (( + y) > (Math.tan((x | 0)) | 0)))))))) ? Math.fround(((((y != Math.fround(( + ( ~ Math.tan(y))))) | 0) >= (Math.sqrt(( + y)) | 0)) | 0)) : Math.fround((( - ( + mathy1(x, ((((Math.log10(Math.fround(Math.hypot(Math.fround(x), ( + 1.7976931348623157e308)))) | 0) | 0) ? y : (mathy2(((y % (Math.min(x, x) >>> 0)) >>> 0), (( ~ x) | 0)) | 0)) | 0)))) | 0)))); }); testMathyFunction(mathy5, [2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 0x100000001, 0x07fffffff, 42, 2**53, -Number.MAX_VALUE, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, -0x080000000, -0x080000001, -0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -0x100000001, -Number.MIN_VALUE, -1/0, Math.PI, 0x100000000, 0x080000001, 1/0, 0.000000000000001, 2**53+2, 0x0ffffffff, -(2**53), -0x07fffffff, 0, -0x100000000]); ");
/*fuzzSeed-204645237*/count=446; tryItOut("\"use strict\"; v2 = g1.eval(\"v2 = Object.prototype.isPrototypeOf.call(e0, a1);\");");
/*fuzzSeed-204645237*/count=447; tryItOut("/*MXX1*/o0 = g2.Map.prototype.constructor;");
/*fuzzSeed-204645237*/count=448; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.cosh(Math.pow(Math.fround(( ~ Math.tanh(( ! y)))), Math.round(Math.hypot(2**53-2, x)))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 1/0, -(2**53), -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, Math.PI, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, 2**53-2, 42, Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, -0x0ffffffff, -0x100000001, 1, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, 0, 0x080000000, 2**53, -0x080000001, 1.7976931348623157e308, 0x100000000, -1/0, -(2**53+2), 0/0]); ");
/*fuzzSeed-204645237*/count=449; tryItOut("i2 = new Iterator(o1);");
/*fuzzSeed-204645237*/count=450; tryItOut("/*RXUB*/var r = new RegExp(\"((?![^])|(?!\\\\b?)*??(?!(?=[^\\\\cV-\\ub30a\\\\S\\u6fed-\\u92bb]{1,})|[^]){0,0})(?!(?:(?![^]|[^])+|[^]*(\\ua794|[^]|((?:[])){2,4})))\", \"y\"); var s = \"\\ub30a\\ub30a\\ub30a\\n\\n\\n\\n\\n\\uc6b4\"; print(s.replace(r, (r = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(new RegExp(\"(?!(?:.))\", \"yi\")), Array.prototype.shift)), \"g\")); ");
/*fuzzSeed-204645237*/count=451; tryItOut("if(c) e0.has(f0); else  if ((4277)) v2 = a1.some((function() { for (var j=0;j<9;++j) { f0(j%5==1); } }));");
/*fuzzSeed-204645237*/count=452; tryItOut("/*RXUB*/var r = /.\\3/gm; var s = a; print(r.exec(s)); ");
/*fuzzSeed-204645237*/count=453; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = (d1);\n    }\n    d0 = (d0);\n    d0 = ((+/*FFI*/ff(((-((Float64ArrayView[((Uint32ArrayView[2])) >> 3])))), ((((((-0x8000000)) << ((0xfd9700b5))) % (((0xffffffff)) | ((0xfc560ee2)))) ^ ((Uint16ArrayView[((0xffffffff)+(0x15e2d1c3)+(0x1c3cd098)) >> 1])))), (((x) & ((/*FFI*/ff(((128.0)), ((1.0009765625)), ((2048.0)), ((2049.0)), ((65537.0)))|0)-((0x41af37d0) >= (0x0))+(0xfde3a96e)))), ((d1)), ((((((d1)))*-0x69e26)|0)), ((d0)), ((imul((-0x8000000), (0xfd64af8b))|0)), ((-262145.0)), ((-549755813889.0)), ((-33554433.0)), ((129.0)), ((-8589934592.0)), ((17592186044417.0)))) + (d0));\n    return +((-262145.0));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=454; tryItOut("v1 = t2.length;");
/*fuzzSeed-204645237*/count=455; tryItOut("mathy0 = (function(x, y) { return Math.abs((Math.min((( ! (( ! Math.log2((x >>> 0))) ? (( + Math.log1p(( + ( - -Number.MAX_VALUE)))) | 0) : x)) | 0), (Math.fround(Math.imul(Math.fround((Math.max((Math.log2(x) >>> 0), (x >>> 0)) >>> 0)), ( + Math.pow(x, 0.000000000000001)))) | 0)) | 0)); }); testMathyFunction(mathy0, [-(2**53+2), -0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, -0x100000000, 0x080000000, 0x07fffffff, 0.000000000000001, 0, -Number.MAX_VALUE, -0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53), 42, -0, 2**53, 0x080000001, 0x100000001, 1/0, 0/0, -Number.MIN_VALUE, 0x100000000, Math.PI, -0x0ffffffff, -1/0, -0x07fffffff, Number.MAX_VALUE, 1]); ");
/*fuzzSeed-204645237*/count=456; tryItOut("this.o1.f2(t2);");
/*fuzzSeed-204645237*/count=457; tryItOut("mathy3 = (function(x, y) { return (( + ( ~ Math.atan2((mathy0(((Math.imul((x | 0), (x | 0)) | 0) >>> 0), (x >>> 0)) >>> 0), ((( ! Math.imul(( ! 0.000000000000001), x)) | 0) | 0)))) % Math.tanh(( + (Math.fround((Math.min(mathy0((( ! (-0x100000000 >>> 0)) >>> 0), Math.atan2(x, Math.pow(y, x))), ( - (( ~ x) >>> 0))) | 0)) || (((((x | 0) ? x : (y | 0)) >>> 0) | 0) ** Math.round(( - y))))))); }); testMathyFunction(mathy3, /*MARR*/[new String('q'),  /x/ , objectEmulatingUndefined(),  /x/ , 2,  /x/ , new String('q'), 2, new String('q'), 2, 2, objectEmulatingUndefined(), 2,  /x/ ,  /x/ , new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), 2, 2, 2, new String('q'), new String('q'), 2, new String('q'), new String('q'), objectEmulatingUndefined(), 2, 2, 2, 2, 2,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , 2,  /x/ , objectEmulatingUndefined(), 2,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), new String('q'),  /x/ , objectEmulatingUndefined(), new String('q'),  /x/ , objectEmulatingUndefined(),  /x/ , 2, objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-204645237*/count=458; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, Math.PI, 0x080000000, 2**53-2, 0/0, 2**53, 1/0, 2**53+2, Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, -0x100000001, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, 0, -0, 1, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, -0x080000001, 42, -(2**53), 0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=459; tryItOut("\"use strict\"; h0 = a0[0];");
/*fuzzSeed-204645237*/count=460; tryItOut("\"use asm\"; /*tLoop*/for (let e of /*MARR*/[[],  /x/ , [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1],  /x/ ,  /x/ ,  /x/ , [1],  /x/ ,  /x/ , [], [1], [1], [],  /x/ , [], [],  /x/ ,  /x/ , [],  /x/ , [1], [1],  /x/ ,  /x/ , [1],  /x/ , [], [], [1], [1],  /x/ , [1],  /x/ , [1], [1], [1], [1], [1],  /x/ , [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1],  /x/ , [1], [1], [1], [], [1], [], [1], [1], [1]]) { h2.enumerate = f2; }");
/*fuzzSeed-204645237*/count=461; tryItOut("h0.getOwnPropertyDescriptor = f2;");
/*fuzzSeed-204645237*/count=462; tryItOut("\"use strict\"; h1 = {};");
/*fuzzSeed-204645237*/count=463; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[1, 0xB504F332, false, arguments.caller, 0xB504F332, 0xB504F332, (-1/0), 1, 1, 1, 0xB504F332, (-1/0), 1, (-1/0), 1, arguments.caller, 1, 1, false, (-1/0), (-1/0), 1, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), false, arguments.caller, (-1/0), (-1/0)]) { this.a0 = a2.concat(a0, a0, a0); }");
/*fuzzSeed-204645237*/count=464; tryItOut("/*RXUB*/var r = new RegExp(\"[\\\\D]*?\\\\2|\\\\3\", \"g\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=465; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 1.001953125;\n    (Float64ArrayView[1]) = ((~((-0x5b40490)-(((((-0x5b185d) ? (0x241aef4b) : (0xff95cbe9))*-0x3ec9)>>>((!((0x1295357d) >= (0x52d75d99)))-(i1)+(i1))))+((((0x6b79134a) % (0xe65c39cb)) << ((!(i1))-(0xfd952e8b)-(i2)))))));\n    (Uint16ArrayView[(((/*FFI*/ff()|0) ? (i2) : (0xe667239a))-(0xc5161eae)) >> 1]) = ((((i0)) | ((0x1ea6cdb4))) / (imul((!(0xff4013f3)), (((0.5) + (((-4.835703278458517e+24)) % ((9.0)))) != (d3)))|0));\n    return (((0xffffffff)-(0x75a3d98e)))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER, -0, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53), 0, 1, 0x07fffffff, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, 0x100000000, -0x080000000, -0x080000001, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, -(2**53-2), -0x0ffffffff, -(2**53+2), 0x0ffffffff, Math.PI, -0x100000001, 1/0, 42, 0x080000001, 0x080000000, -Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-204645237*/count=466; tryItOut("\"use strict\"; var b, x = (allocationMarker()), fagsww, NaN, x =  \"\" , ebrkon;f1 = Proxy.createFunction(h1, f1, f0);");
/*fuzzSeed-204645237*/count=467; tryItOut("print((/*MARR*/[(void 0), ({x:3}),  '' , ({x:3}), (void 0),  '' , ({x:3}), ({x:3}),  '' ,  '' ,  '' ,  '' ,  '' , (void 0), ({x:3}), (void 0),  '' , (void 0), ({x:3}), ({x:3}), ({x:3}), (void 0),  '' , (void 0), ({x:3}), (void 0),  '' ,  '' , (void 0), ({x:3}), ({x:3}),  '' , (void 0), (void 0),  '' ,  '' ,  '' , ({x:3}),  '' , (void 0), (void 0), (void 0), (void 0), (void 0),  '' ,  '' , (void 0),  '' , (void 0), (void 0), (void 0), (void 0),  '' , ({x:3}),  '' , ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}),  '' , (void 0),  '' , ({x:3}), ({x:3}), ({x:3}), ({x:3}), (void 0), ({x:3}),  '' ,  '' , (void 0),  '' ,  '' , (void 0),  '' , ({x:3}),  '' , (void 0), (void 0),  '' , ({x:3}),  '' , ({x:3}), ({x:3}), ({x:3})].filter(undefined, e) == (\"\\u8C2A\" ?  /x/  : x)));");
/*fuzzSeed-204645237*/count=468; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.acosh(Math.sqrt(( - mathy0(-(2**53-2), 0x100000001)))) + (Math.hypot(Math.max(y, x), (((Math.max(-1/0, -0x080000001) | 0) && ((((Math.fround(1.7976931348623157e308) >> ( + (Math.fround(0.000000000000001) == Math.atan2(( + -0x080000001), ( + x))))) | 0) ? x : (x | 0)) | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy3, [1, 2**53, 0x07fffffff, -0x100000001, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, -(2**53-2), 0, 1/0, -0x0ffffffff, 0/0, 2**53+2, 1.7976931348623157e308, -0x100000000, 0x100000000, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 0x080000001, 0x100000001, -0x080000000, -1/0, Number.MIN_SAFE_INTEGER, Math.PI, 42, -Number.MIN_VALUE, -0x07fffffff, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-204645237*/count=469; tryItOut("a0.push(t2, o1.g1.p1);");
/*fuzzSeed-204645237*/count=470; tryItOut("\"use strict\"; this.m1.delete(this.o0.a1);");
/*fuzzSeed-204645237*/count=471; tryItOut("ncthqk(x, []);/*hhh*/function ncthqk(){this.g0.t1[({valueOf: function() { /*RXUB*/var r = r1; var s = \"\\n\\n\"; print(s.replace(r, (4277))); return 8; }})] = this.o1.a2;}");
/*fuzzSeed-204645237*/count=472; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot(Math.fround(( + ( - (Math.fround(( ! ( + (x ? x : y)))) | 0)))), Math.log10(( - Math.sqrt(mathy1(x, x)))))); }); testMathyFunction(mathy3, /*MARR*/[ /x/g , NaN, false,  /x/g ,  /x/g ,  /x/g , (0/0),  /x/g ]); ");
/*fuzzSeed-204645237*/count=473; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ! Math.fround(( ~ mathy1(x, x)))); }); ");
/*fuzzSeed-204645237*/count=474; tryItOut("/*RXUB*/var r = /((?=\\B{1,})|(?!((?=\\b))*?)*?)*?/; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=475; tryItOut("mathy3 = (function(x, y) { return Math.atan2((mathy2((mathy2((Math.asin(Math.hypot(mathy1(Math.fround(y), (( - x) | 0)), y)) >>> 0), ((0x0ffffffff >>> 0) , x)) | 0), (( - (x & y)) | 0)) | 0), mathy0((mathy2((y >>> 0), (( - (( + ( - ( + Math.max(x, y)))) | 0)) >>> 0)) >>> 0), Math.clz32(-(2**53-2)))); }); testMathyFunction(mathy3, [false, (new Boolean(false)), '', '0', -0, null, (new Number(0)), true, [0], (new String('')), objectEmulatingUndefined(), '/0/', [], ({valueOf:function(){return '0';}}), (function(){return 0;}), undefined, (new Boolean(true)), '\\0', NaN, ({valueOf:function(){return 0;}}), 1, 0.1, ({toString:function(){return '0';}}), (new Number(-0)), /0/, 0]); ");
/*fuzzSeed-204645237*/count=476; tryItOut("\"use strict\"; i0 = t1;");
/*fuzzSeed-204645237*/count=477; tryItOut("a1 = a1.slice(-5, NaN);");
/*fuzzSeed-204645237*/count=478; tryItOut("\"use strict\"; testMathyFunction(mathy5, [2**53-2, -0, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, -1/0, -0x07fffffff, 0x0ffffffff, -0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0, -0x100000001, -Number.MAX_VALUE, 1, 0x100000001, -0x0ffffffff, 2**53+2, -(2**53+2), 2**53, -0x080000001, 0x080000000, 42, Number.MIN_VALUE, 0x07fffffff, 1/0, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=479; tryItOut("mathy2 = (function(x, y) { return ( - (Math.cosh(( + mathy0(Math.log2((( + ( + ( ~ 2**53+2))) | 0)), (Math.exp(x) >>> 0)))) | 0)); }); testMathyFunction(mathy2, [-0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, -1/0, -0x080000000, -(2**53-2), 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 0x080000001, Math.PI, -(2**53), -0x0ffffffff, 0, 0.000000000000001, 0x0ffffffff, -Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, 2**53, 1, 1/0, 2**53-2, -0x07fffffff, -Number.MIN_VALUE, 42, 2**53+2]); ");
/*fuzzSeed-204645237*/count=480; tryItOut("\"use strict\"; /*infloop*/ for (let ([]) of (4277)) {s2 += s2;print(x); }");
/*fuzzSeed-204645237*/count=481; tryItOut("t2.set(t0, ({valueOf: function() { d = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: this, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: Number.isNaN, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: undefined, keys: function() { throw 3; }, }; })(-20), (1 for (x in [])), String.prototype.slice);return 19; }}));");
/*fuzzSeed-204645237*/count=482; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=483; tryItOut("");
/*fuzzSeed-204645237*/count=484; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=485; tryItOut("let eval;Array.prototype.forEach.apply(a0, [(function(j) { if (j) { try { i0.toSource = (function() { try { f1(s1); } catch(e0) { } try { m1.get(((function fibonacci(uohrpz) { ; if (uohrpz <= 1) { ; return 1; } ; return fibonacci(uohrpz - 1) + fibonacci(uohrpz - 2); a1.reverse(o2.g0, this.g2); })(4))); } catch(e1) { } o2.a1.push(o2.s0, o1.v2, s1); return this.a1; }); } catch(e0) { } a0.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69, a70, a71, a72, a73, a74, a75, a76, a77, a78, a79, a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a90, a91, a92, a93, a94, a95, a96, a97, a98) { var r0 = a74 * a3; var r1 = 5 + a12; var r2 = 6 ^ a14; a14 = a45 - a47; var r3 = 3 % a20; var r4 = a21 - a56; a96 = a87 / 8; var r5 = a20 | a82; var r6 = a10 * 3; a84 = a55 | a59; var r7 = a7 ^ a27; var r8 = a73 - a58; var r9 = a57 + a95; var r10 = 3 & a26; a81 = a87 & a72; var r11 = a26 - a94; var r12 = 2 | a23; r10 = a14 % 1; var r13 = 8 + 8; var r14 = 7 * a79; var r15 = 1 / 7; var r16 = a77 | 7; var r17 = 6 * 4; a36 = a15 % 8; var r18 = a86 & a7; a17 = a47 % r12; var r19 = a32 | a56; var r20 = a55 * a50; var r21 = a0 | a12; var r22 = 9 & a34; var r23 = a36 | r6; var r24 = a32 | 2; var r25 = 7 | a55; var r26 = 8 - a41; var r27 = 7 | r17; var r28 = a15 | 6; var r29 = a75 + a20; var r30 = a42 % 5; a42 = a86 % 7; r5 = 2 ^ a90; var r31 = r0 * r8; var r32 = a80 % 9; var r33 = 9 % r7; var r34 = a6 * a94; var r35 = 8 & 3; var r36 = r16 | a86; var r37 = a82 % a8; var r38 = a87 * 5; var r39 = 4 + 4; a58 = 5 & 7; r20 = 5 | r21; a93 = r35 | a17; var r40 = a63 & a58; var r41 = a15 / a74; a82 = 9 % 0; var r42 = 6 / a69; print(a86); r33 = a14 + a8; var r43 = r39 + x; var r44 = a38 - a70; a12 = a3 ^ 6; var r45 = 6 - 2; var r46 = a84 ^ r14; a0 = 6 | r31; var r47 = r12 | a39; var r48 = a14 * a37; var r49 = a43 / 0; var r50 = r2 | 9; var r51 = r46 % r44; var r52 = a91 - x; var r53 = a14 / 7; var r54 = a16 | a35; a32 = r19 ^ a14; print(r38); var r55 = 8 | r16; var r56 = x % r12; var r57 = r48 | 3; var r58 = a94 & a7; var r59 = a71 ^ a44; var r60 = 4 % r36; a50 = 1 / r35; var r61 = 7 + a28; r40 = a79 & a68; var r62 = 7 ^ r55; var r63 = 8 ^ r4; var r64 = r63 + r2; var r65 = r48 * a20; var r66 = 5 | a28; a78 = r8 * a68; var r67 = a8 * a11; var r68 = 7 | 9; var r69 = 3 * r6; var r70 = r67 | r26; var r71 = 8 + a14; var r72 = a15 ^ 0; var r73 = 5 * r43; var r74 = r19 ^ a60; var r75 = 1 | r71; var r76 = a59 + 0; var r77 = a71 + a55; var r78 = a33 | 4; print(a80); var r79 = a12 - r20; var r80 = 1 * r77; r46 = 7 | a39; var r81 = 6 - a98; r6 = a39 * a84; var r82 = 1 - r28; r69 = a12 + a79; var r83 = r45 - 3; return a36; })); } else { try { for (var v of h2) { try { h2.delete = f1; } catch(e0) { } Array.prototype.splice.call(a1, NaN, ({valueOf: function() { return 10; }})); } } catch(e0) { } try { Array.prototype.forEach.call(a1, g0.h0, o2, a0); } catch(e1) { } try { v0 = a1.length; } catch(e2) { } f0 = t2[v1]; } })]);");
/*fuzzSeed-204645237*/count=486; tryItOut("eumkxl();/*hhh*/function eumkxl(x = ({} = x), ...b){i2 = new Iterator(s1, true);}");
/*fuzzSeed-204645237*/count=487; tryItOut("\"use strict\"; \"use asm\"; Object.prototype.unwatch.call(t0, \"fromCharCode\");");
/*fuzzSeed-204645237*/count=488; tryItOut("s0 = o1.a0.join(s0);function x() { return x } a0 = arguments.callee.arguments;/*\n*/");
/*fuzzSeed-204645237*/count=489; tryItOut("Array.prototype.pop.apply(a1, [])\n");
/*fuzzSeed-204645237*/count=490; tryItOut("for (var p in o0.g0) { try { v0 = (m2 instanceof g2.e0); } catch(e0) { } try { s2 += s1; } catch(e1) { } r1 = new RegExp(\"(?![^]|(\\\\W*?)\\\\b)\", \"gy\"); }print(x);");
/*fuzzSeed-204645237*/count=491; tryItOut("(/(?:.*)|(?!(([\\w\\cG\\v-\\u00B9\\u6440-\u80f5]))){3,}/yim);");
/*fuzzSeed-204645237*/count=492; tryItOut("\"use strict\"; m0.delete(p2);");
/*fuzzSeed-204645237*/count=493; tryItOut("tpkwpw(/(?!\\s[^])(?:\\W){0,}\\w$*?{3,4}(?!\\d)|[^]|\\2/gym != Math.tanh(( + Math.atan(( + Math.fround((Math.fround(Math.max(x, ( + Math.expm1(( + x))))) / Math.fround(( + Math.asinh(( + Math.imul(Math.sin(x), x))))))))))), Math.hypot(17, -25));/*hhh*/function tpkwpw(window, x){v2 = t0.length;}");
/*fuzzSeed-204645237*/count=494; tryItOut("this.t1.__proto__ = s1;");
/*fuzzSeed-204645237*/count=495; tryItOut("e2 = new Set(g0);");
/*fuzzSeed-204645237*/count=496; tryItOut("m0.set(s2, Math.sqrt(11));");
/*fuzzSeed-204645237*/count=497; tryItOut("Object.defineProperty(this, \"g2.v0\", { configurable: (x % 2 != 0), enumerable: false,  get: function() {  return evalcx(\"f2 = o0;\", g2); } });");
/*fuzzSeed-204645237*/count=498; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (( - ((Math.min((x | 0), ( + Math.min(0.000000000000001, ( + x)))) | 0) | 0)) | 0)); }); testMathyFunction(mathy0, [0x080000000, -0x100000001, -Number.MIN_VALUE, -(2**53+2), 0x100000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, -(2**53), 1, -(2**53-2), 0x080000001, 0x0ffffffff, 0x100000000, 0x07fffffff, -0x0ffffffff, Math.PI, 0/0, -Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, 2**53, -1/0, -0x100000000, Number.MAX_VALUE, 1/0, 42, -0, -0x080000000, 0.000000000000001, 0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=499; tryItOut("\"use strict\"; M:switch(x) { case (y = this): /*ADP-1*/Object.defineProperty(a1, 5, ({get: d =>  { return (new (Number.prototype.toLocaleString)(yield [,,z1],  /x/g )()) } , enumerable: (Math.exp(x))}));this.v2 = (s2 instanceof f2);break;  }");
/*fuzzSeed-204645237*/count=500; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+(imul((0xcf1e1f03), ((0x3be13034)))|0));\n    d0 = (+(0xecaeffce));\n    ((4277)) = ((-((d1))));\n    d1 = (d0);\n    d1 = (+abs(((d0))));\n    {\n      (Float32ArrayView[1]) = ((Float64ArrayView[((0x84f135fd)+(((+/*FFI*/ff(((((+pow(((d1)), ((d0))))) % ((+/*FFI*/ff(((imul((0xb6b2ea9c), (0xaf21ebba))|0))))))), (((((0x17fb0323))-((0x0) >= (0xef6756b5))) | (((0xc41e1c55) == (0xc60991e))+((0xffffffff))))), ((imul((0x344ea40c), (0xf99e394a))|0)), ((((0xda4978b3)) | ((0x144e42cf))))))))+((((((makeFinalizeObserver('nursery'))))-((0x0) < (0xffffffff))) ^ ((-0x8000000) / (0x4131b809))) > (((0x9d96570)+(0xf2af44e9)) >> (((0x38808c22) <= (0x737b0b)))))) >> 3]));\n    }\n    d1 = (d1);\n    d1 = (+/*FFI*/ff(((imul((0x6b1e5fcf), ((Uint16ArrayView[((-0x8000000)) >> 1])))|0)), ((~~(+atan2(((+(-1.0/0.0))), ((+abs((((-0x8000000) ? (d0) : (d1)))))))))), ((d1)), ((abs(((((0xf628af2e) ? (0xab9a3e6f) : (-0x8000000))) >> (((((0x4d5134e6))>>>((0xb272acd))))-((0xbd191a02) >= (0x83d419f3)))))|0)), ((((0xf5464236)) | (Math.imul(x, new (7)(false, w)))))));\n    switch ((((-0x8000000)+((0xdc1893f1) < (0x0))) << (((0x1d10afe6))+(0xffffffff)))) {\n    }\n    {\n      d1 = (+atan2(((d0)), ((d1))));\n    }\n    d0 = (8.0);\n    d0 = (d0);\n    d1 = (d0);\n    (Uint32ArrayView[((/[^]+?/g)*-0xaea5) >> 2]) = ((0x7c799161) % (((0x4c71a89c)) ^ ((/*FFI*/ff()|0)+(0xfabeb1e2)-((0x52843dac)))));\n    d1 = (d0);\n    d1 = (+((d0)));\n    {\n      {\n        (Int8ArrayView[2]) = (((~~(d1)))+(0xf97e4753));\n      }\n    }\n    return (((0xfb20437a)-(0x26147567)+(0x105fb3c2)))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(pkvmwt){Object.defineProperty(this, \"stringify\", ({value: x = new RegExp(\".+?|\\\\cM*?\", \"gyim\"), configurable: (pkvmwt % 7 != 4), enumerable: (pkvmwt % 6 == 3)}));this[\"15\"] = Map.prototype.forEach;this[new String(\"6\")] = (w = arguments).__defineGetter__(\"z\", arguments.callee);delete this[\"apply\"];this[\"apply\"] = Object.getOwnPropertyDescriptors;this[\"apply\"] = (-1/0);this[\"15\"] = /*wrap2*/(function(){ \"use strict\"; var qcgkbh = \"\u03a0\"; var dcbkkx =  '' \n; return dcbkkx;})();{ /*infloop*/for(let x; pkvmwt; b = [,]) {( /x/ ); } } delete this[\"15\"];{ /*RXUB*/var r = r1; var s = \"000\"; print(s.match(r));  } return this; }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, Number.MAX_VALUE, 42, 1, -0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53-2, -(2**53), 2**53, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, 0/0, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, 0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, 0x080000001, Math.PI, 0x080000000, 1/0, 2**53+2, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=501; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[arguments, 1e81,  /x/ , 1e81, 1e81,  /x/ ,  /x/ , 1e81, 1e81,  /x/ ,  /x/ ,  /x/ , arguments,  /x/ , arguments, 1e81, arguments, arguments, arguments, 1e81,  /x/ , arguments,  /x/ , 1e81, arguments,  /x/ , 1e81, arguments, arguments,  /x/ , 1e81,  /x/ , arguments, 1e81, arguments,  /x/ , 1e81, arguments, arguments,  /x/ , arguments, arguments, arguments,  /x/ ,  /x/ , 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81,  /x/ ,  /x/ ,  /x/ , arguments, 1e81, 1e81, arguments, 1e81, arguments, 1e81, arguments, 1e81, 1e81, arguments]) { a1 = r1.exec(s0); }");
/*fuzzSeed-204645237*/count=502; tryItOut("mathy5 = (function(x, y) { return ((Math.fround(( ! Math.fround((Math.asinh((( ! Math.log(-0x0ffffffff)) >>> 0)) >>> 0)))) | 0) !== ( ! Math.fround(( + Math.hypot(( + Math.expm1(x)), ( + mathy3(x, (y <= (x * -0x080000001))))))))); }); testMathyFunction(mathy5, /*MARR*/[new Boolean(false), new Boolean(false), (-1/0), (-1/0), new Boolean(false), ({}), (1/0),  \"use strict\" , (-1/0), new Boolean(false), new Boolean(false), new Boolean(false), (-1/0),  \"use strict\" ,  \"use strict\" , ({}), new Boolean(false), (1/0), (-1/0), new Boolean(false), (-1/0), ({}), (1/0), (-1/0), (1/0), (1/0), (1/0),  \"use strict\" , ({}), ({}), (-1/0), new Boolean(false), (1/0), (1/0), ({}), (1/0), ({}),  \"use strict\" ,  \"use strict\" , ({}),  \"use strict\" , new Boolean(false),  \"use strict\" , new Boolean(false), (1/0), (1/0),  \"use strict\" , ({})]); ");
/*fuzzSeed-204645237*/count=503; tryItOut("for(z in  /x/g ) {print(x); }");
/*fuzzSeed-204645237*/count=504; tryItOut("this.o0.o2 = a1[10];");
/*fuzzSeed-204645237*/count=505; tryItOut("for (var v of i2) { try { e0.has(s0); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a2, ({valueOf: function() { (\"\\u08EE\");return 9; }}), ({writable:  \"\" , configurable: true})); } catch(e1) { } try { a1 + i2; } catch(e2) { } s2 += 'x'; }\n/*RXUB*/var r = /(?!\\B)|^\\W+\\1|(?:\\2?$|\\2(?=(?:.|[^]\\n+?))){2,}/g; var s = \"\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\\uca84\\n\\na\\u721e\"; print(s.match(r)); \n");
/*fuzzSeed-204645237*/count=506; tryItOut("v2 = g2.eval(\"m2 + '';\");");
/*fuzzSeed-204645237*/count=507; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\B\", \"gyim\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-204645237*/count=508; tryItOut("\"use strict\"; this.s2 += s2;");
/*fuzzSeed-204645237*/count=509; tryItOut("mathy5 = (function(x, y) { return Math.fround((((( ~ ( ! y)) >>> 0) | 0) === (( ! Math.cos(( + (( ! ( + Math.fround(Math.round((Math.hypot(0x100000000, Number.MAX_SAFE_INTEGER) | 0))))) & (x >>> 0))))) | 0))); }); testMathyFunction(mathy5, ['', /0/, undefined, '\\0', (new Boolean(false)), [0], true, '0', 0.1, (new Number(-0)), 1, (function(){return 0;}), 0, ({valueOf:function(){return 0;}}), (new String('')), NaN, [], objectEmulatingUndefined(), -0, '/0/', false, (new Number(0)), (new Boolean(true)), null, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-204645237*/count=510; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=511; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (-1.9342813113834067e+25);\n    d0 = (144115188075855870.0);\n    i2 = ((((1025.0))));\n    i1 = (0x4baff445);\n    {\n      i1 = (((((i2)) | ((Int32ArrayView[4096])))) ? ((((0x86fa0984)+((((0xd9098fea))>>>((0x5fcf85f2))))) << ((0x75858a4b))) < (~(((0xc9181f14) ? (i2) : ((16385.0) >= (288230376151711740.0)))))) : (i1));\n    }\n    i1 = ((imul((0x44b058d4), (i1))|0) > (((0xf99ee9b0))|0));\n    return (((i2)+(0xe15265d9)-(i2)))|0;\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [(new Number(-0)), ({valueOf:function(){return '0';}}), '/0/', (new Number(0)), '\\0', (new Boolean(true)), ({valueOf:function(){return 0;}}), /0/, true, (function(){return 0;}), 0.1, (new String('')), -0, false, 1, '0', (new Boolean(false)), [0], 0, null, [], ({toString:function(){return '0';}}), objectEmulatingUndefined(), NaN, undefined, '']); ");
/*fuzzSeed-204645237*/count=512; tryItOut("M:with(this(\u0009)){this.v1 = r0.compile; }");
/*fuzzSeed-204645237*/count=513; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + mathy1(( + (( + (( + Math.fround(( - (0x080000000 >>> 0)))) | 0)) | 0)), ( + Math.fround((Math.fround(((( - (Math.acosh((x >>> 0)) >>> 0)) | 0) , (((( ! y) | 0) ? (( ! ( + mathy2((x | 0), (y | 0)))) | 0) : ( + Math.fround(Math.expm1((x | 0))))) | 0))) > Math.fround(Math.max(Math.fround(Math.log1p(Math.fround(Number.MIN_VALUE))), Math.hypot(x, Math.fround(( - (x , y))))))))))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1)]); ");
/*fuzzSeed-204645237*/count=514; tryItOut("testMathyFunction(mathy3, /*MARR*/[ /x/g , new Boolean(false), new Boolean(false),  /x/g ,  /x/g , new Boolean(false),  /x/g , new Boolean(false), new Boolean(false), new Boolean(false),  /x/g ,  /x/g ,  /x/g , new Boolean(false), new Boolean(false),  /x/g ,  /x/g , new Boolean(false),  /x/g ,  /x/g ,  /x/g ,  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  /x/g , new Boolean(false),  /x/g , new Boolean(false), new Boolean(false),  /x/g , new Boolean(false), new Boolean(false), new Boolean(false),  /x/g ,  /x/g ,  /x/g ]); ");
/*fuzzSeed-204645237*/count=515; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.max((Math.pow(( + Math.atan(( + y))), mathy0(mathy1(( + ( ! ( + Math.PI))), y), ( + ( ! x)))) >>> 0), (( + Math.log(( + ( + Math.fround((((Math.fround(Math.atan2(Math.fround(Math.trunc(-(2**53-2))), (y >>> 0))) >>> 0) * (x >>> 0)) >>> 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [1, 0x100000001, -0, 2**53-2, 42, 1/0, -1/0, -(2**53+2), -0x100000001, Number.MIN_VALUE, 0x0ffffffff, -(2**53), 0x080000001, -0x100000000, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 2**53+2, -0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, 0.000000000000001, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=516; tryItOut("\"use strict\"; g1.t1 = t0.subarray(3, 10);");
/*fuzzSeed-204645237*/count=517; tryItOut("wmhtcm, NaN, d = (4277);f1 = Proxy.createFunction(h0, f1, f1);");
/*fuzzSeed-204645237*/count=518; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log10(( ~ ( + ( + mathy0((Math.sinh((x | 0)) >>> 0), x))))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), 0x07fffffff, -3/0,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), -3/0,  /x/ , 0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), -3/0, objectEmulatingUndefined(), 0x07fffffff, objectEmulatingUndefined(), 0x07fffffff, -3/0, 0x07fffffff, -3/0,  /x/ ,  /x/ , objectEmulatingUndefined()]); ");
/*fuzzSeed-204645237*/count=519; tryItOut("\"use strict\"; v2 = evaluate(\"/* no regression tests found */\", ({ global: o1.g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: x }));");
/*fuzzSeed-204645237*/count=520; tryItOut("\"use strict\"; p1 + o2.o2.m2;");
/*fuzzSeed-204645237*/count=521; tryItOut("\"use strict\"; a1[6] = this.i0;");
/*fuzzSeed-204645237*/count=522; tryItOut("\"use strict\"; t0.valueOf = (function() { try { a2.pop(a2, h2); } catch(e0) { } try { const v1 = evaluate(\"Array.prototype.pop.call(g1.a0);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 != 1), sourceIsLazy: true, catchTermination: true, element: o2, elementAttributeName: s2 })); } catch(e1) { } try { (void schedulegc(g0.g0)); } catch(e2) { } a2 = r1.exec(s0); return a2; });");
/*fuzzSeed-204645237*/count=523; tryItOut("\"use strict\"; if((4277)) {/* no regression tests found */ } else  if ((true.valueOf(\"number\") -= ( /* Comment */let (w)  /x/ ))) this.t2 = a2[11];/*tLoop*/for (let y of /*MARR*/[]) { (yield (DataView.prototype.setInt8).call(25, )) < (TypeError.prototype = -12); }");
/*fuzzSeed-204645237*/count=524; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( - Math.hypot(Math.asin((Math.exp(y) | 0)), ( ! ( - (( + mathy0(( + Math.cosh(x)), ( + -0x07fffffff))) - (( + (42 >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, -0x080000001, -0x100000001, 42, 0x100000000, 2**53, 0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 1, 0x100000001, Math.PI, 2**53+2, 0.000000000000001, 0/0, -Number.MAX_VALUE, -(2**53), -(2**53+2), -0, 1/0, -(2**53-2), -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-204645237*/count=525; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ ((Math.fround((mathy3(( + Math.imul(y, ( + -0x07fffffff))), Math.cos(y)) >>> 0)) | 0) >> ( + (Math.asin((1 >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, /*MARR*/[['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], (void 0), \"\u03a0\", ['z'], \"\u03a0\", (void 0), true, \"\u03a0\", \"\u03a0\", (void 0), (void 0), ['z'], 1e+81, ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], 1e+81, 1e+81, (void 0), ['z']]); ");
/*fuzzSeed-204645237*/count=526; tryItOut("/*bLoop*/for (ltbfpr = 0; ltbfpr < 62; ++ltbfpr) { if (ltbfpr % 30 == 11) { a2.push(o1); } else { v1 = Object.prototype.isPrototypeOf.call(v0, h1); }  } ");
/*fuzzSeed-204645237*/count=527; tryItOut("\"use strict\"; (arguments.callee.caller.caller.caller.caller.caller.caller.caller.caller.arguments) = eval;");
/*fuzzSeed-204645237*/count=528; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return Math.fround((( + ( ! Math.fround(Math.sin(0.000000000000001)))) == Math.sign(Math.fround(Math.min(Math.fround(( ! y)), ((42 ** ((( - y) == x) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-204645237*/count=529; tryItOut("Array.prototype.reverse.apply(a1, [g1]);");
/*fuzzSeed-204645237*/count=530; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + Math.max(Math.atanh(x), (Math.fround(( + Math.asinh(( + -0x07fffffff)))) !== (( ~ x) ** x)))), Math.fround((((Math.sqrt((0x07fffffff | 0)) ? y : Math.atan2(y, Math.fround(Math.min((y >>> 0), (y >= x))))) | 0) / ((Math.atan((((y >>> 0) | ( + x)) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy0, [0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, -0, -0x080000001, 2**53-2, 0/0, 42, -(2**53+2), 1.7976931348623157e308, 2**53, 0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, -0x100000001, 2**53+2, 0x100000000, 0x080000001, -1/0, 0x0ffffffff, 1/0, 1, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, 0, -(2**53-2), -Number.MAX_VALUE, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-204645237*/count=531; tryItOut("b1 = t2.buffer;");
/*fuzzSeed-204645237*/count=532; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -2049.0;\n    (Float64ArrayView[((abs((((0xfba39105)+(0xd22eef82)-(0x6b317a47)) ^ ((0xfce39ba8)-(0xd1d3282c))))|0) % (-0x8000000)) >> 3]) = ((+(((-1.0) + (d2)))));\n    {\n      i1 = ((((i0)) | (((0x7ce245f8))+(0x6b077284)+(0x6755eaa6))) >= (((-0x8000000)-((67108865.0) <= (67108864.0))) & (((imul(((Uint16ArrayView[((-0x8000000)) >> 1])), ((0xfce054ce)))|0) < (((0x54e56342))|0)))));\n    }\n    d2 = (d2);\n    i0 = (i1);\n    return (((i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000001, 2**53+2, Math.PI, -Number.MAX_VALUE, 0x0ffffffff, 0/0, -(2**53), 0.000000000000001, -0x07fffffff, -0, 42, 0x080000000, 0x07fffffff, Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, Number.MAX_VALUE, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 2**53, -0x100000000, -0x080000001, 2**53-2, -1/0, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-204645237*/count=533; tryItOut("\"use strict\"; this.v1 = (this.g2.i2 instanceof this.v1);function x(a = (x)) { \"use strict\"; yield ((makeFinalizeObserver('nursery'))) } var x = new RegExp(\"(?!(?!.){1,}){3,7}\\\\2|[^]?\", \"\"), x = x++, window, sykokg, a, kamton, mrsqbd, y, z, window;m1 = new Map;");
/*fuzzSeed-204645237*/count=534; tryItOut("mathy4 = (function(x, y) { return Math.expm1(((((y & (Math.tan(((Math.max(y, x) >>> 0) >>> 0)) >>> 0)) | 0) ? ( + Math.abs(((Math.sqrt(Math.atan2(Math.fround(x), y)) ? Math.atan2(x, x) : ((((( + x) , -0x07fffffff) >>> 0) * 2**53+2) >>> 0)) | ( + ( - ( + y)))))) : (( ! (( ~ -Number.MIN_VALUE) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[0x080000001, 0x080000001,  '\\0' , 0x080000001, false, false, 0x080000001, false, false,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , 0x080000001,  '\\0' , 0x080000001, 0x080000001, 0x080000001, false, 0x080000001, false, false, 0x080000001,  '\\0' ,  '\\0' , false, false, 0x080000001,  '\\0' ,  '\\0' , false,  '\\0' , false, false,  '\\0' , false, 0x080000001, false,  '\\0' , 0x080000001, false,  '\\0' , 0x080000001,  '\\0' , false, 0x080000001,  '\\0' , false,  '\\0' , 0x080000001,  '\\0' ,  '\\0' ,  '\\0' , 0x080000001, false,  '\\0' ,  '\\0' ,  '\\0' , 0x080000001, 0x080000001, 0x080000001, false, false,  '\\0' ,  '\\0' , 0x080000001, 0x080000001, false, 0x080000001, false, false, 0x080000001,  '\\0' ,  '\\0' , false, false,  '\\0' , 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001,  '\\0' , false, 0x080000001, false,  '\\0' , false,  '\\0' , false, 0x080000001, false,  '\\0' , 0x080000001,  '\\0' , false, false,  '\\0' , false, 0x080000001, false, false, 0x080000001,  '\\0' ,  '\\0' , false,  '\\0' ,  '\\0' , 0x080000001, 0x080000001,  '\\0' , 0x080000001, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 0x080000001, 0x080000001,  '\\0' ,  '\\0' ,  '\\0' , false, 0x080000001,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , 0x080000001, 0x080000001,  '\\0' , 0x080000001, 0x080000001,  '\\0' ,  '\\0' , false,  '\\0' , false,  '\\0' ,  '\\0' ,  '\\0' , 0x080000001,  '\\0' , false, 0x080000001,  '\\0' , 0x080000001, false,  '\\0' ,  '\\0' , false, 0x080000001, 0x080000001, 0x080000001, 0x080000001, false, 0x080000001, 0x080000001, 0x080000001, 0x080000001, false, false,  '\\0' , 0x080000001,  '\\0' ]); ");
/*fuzzSeed-204645237*/count=535; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + Math.max(( ~ (( - (( + ( + -(2**53+2))) | 0)) | 0)), (Math.imul(Math.fround(( ~ (( + ( - y)) >>> 0))), y) != mathy0(Math.log2((( ! ((( + ( + x)) | 0) | 0)) | 0)), (( + Math.min((y >>> 0), 42)) ? Math.fround((Math.fround(x) === (x | 0))) : (( - -0x080000001) | 0)))))); }); testMathyFunction(mathy1, /*MARR*/[ 'A' ,  'A' , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (0/0), NaN, (0/0), NaN, function(){},  'A' ,  'A' , (0/0),  'A' ,  'A' , (0/0), (0/0), function(){}, NaN, (0/0),  'A' , NaN,  'A' , (0/0), NaN, (0/0), (0/0), (0/0), (0/0),  'A' ,  'A' , (0/0), NaN,  'A' , function(){}, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), function(){}, function(){}, function(){}, (0/0), (0/0), (0/0), NaN, NaN, NaN, NaN, (0/0), function(){}, function(){}, function(){}, NaN,  'A' ,  'A' , function(){}, (0/0), NaN,  'A' , NaN, function(){},  'A' , function(){}, NaN, (0/0),  'A' ]); ");
/*fuzzSeed-204645237*/count=536; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ! ((Math.round(Math.ceil(Math.fround((Math.tan((( - (((y ^ y) >>> 0) | 0)) | 0)) | 0)))) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, -0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, 2**53-2, -0x07fffffff, 0x080000000, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, -(2**53), -(2**53+2), 0/0, -1/0, -0x080000001, 0x07fffffff, 2**53, 2**53+2, 0x100000000, -0x0ffffffff, 0x0ffffffff, 0, -(2**53-2), Number.MAX_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-204645237*/count=537; tryItOut("b = linkedList(b, 4260);");
/*fuzzSeed-204645237*/count=538; tryItOut("h0.defineProperty = f0;function this(x = (this.__defineGetter__(\"eval\", /*FARR*/[.../*MARR*/[function(){},  /x/g , -0x5a827999,  /x/g ,  /x/g , -0x5a827999,  /x/g , -0x5a827999, -0x5a827999,  /x/g ,  /x/g ,  /x/ , function(){},  /x/g ,  /x/ , (-1/0),  /x/ ,  /x/ , (-1/0),  /x/ ,  /x/ , function(){}, function(){}, (-1/0),  /x/g , -0x5a827999,  /x/ ,  /x/g ,  /x/ , -0x5a827999, -0x5a827999, -0x5a827999, (-1/0),  /x/ , function(){}, function(){}, function(){}, function(){}, (-1/0),  /x/ ,  /x/ , -0x5a827999,  /x/g ,  /x/ , (-1/0),  /x/ , -0x5a827999, (-1/0), function(){}, (-1/0), (-1/0),  /x/g ,  /x/ ], .../*PTHR*/(function() { for (var i of /*MARR*/[false, (0/0), (0/0), false, false, false, false]) { yield i; } })(), this, x, x, , , undefined, ((uneval((Math.clz32(-13))))), [intern(this)], , , .../*MARR*/[Infinity, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, function(){}, Infinity, Infinity, function(){}], y + \u3056, , , Math.sinh(6), , -24, , /*wrap3*/(function(){ var tynvzs = /\\1/gyi; (z)(); }), (NaN-=-8388608) === timeout(1800), new ({/*TOODEEP*/})(/[^]/gi, window), , , ((uneval( /x/g  in -2))), null ? x : (4277), (void 0), .../*FARR*/[(4277), (this.__defineSetter__(\"x\", /*wrap2*/(function(){ var jckcsk = false; var chfjeo = (function(x, y) { return -0x0ffffffff; }); return chfjeo;})())), ((Function).bind())(), .../*FARR*/[...[], this, set, [,], ],  '' , /[^].*?|^{3,4}?/, new EvalError(this, false), .../*FARR*/[2, ], mathy2], /*MARR*/[null, (void 0), null, (void 0), null, (void 0), (void 0), null, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), null, (void 0), null, null, null, null, null, null, null, (void 0), (void 0), null, (void 0), (void 0), (void 0), null, null, (void 0), (void 0), (void 0), (void 0), null, null, (void 0), (void 0), null, null, (void 0), (void 0), (void 0), (void 0), (void 0), null, null, null, (void 0), (void 0), (void 0), (void 0), null, (void 0), (void 0), null, (void 0), null, (void 0), (void 0), (void 0), (void 0), null, null, (void 0), (void 0), null, null, (void 0), null, (void 0), (void 0), null, (void 0), (void 0), (void 0), (void 0), null, (void 0), (void 0), (void 0), (void 0), null, (void 0), (void 0), (void 0), (void 0), null, null, (void 0), null, (void 0), null, null, null, null, (void 0), (void 0), null, null, (void 0), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, (void 0), (void 0), null, (void 0), null, (void 0), (void 0), (void 0), null, (void 0), null, null, (void 0), null, null, (void 0), (void 0), null, (void 0), null, (void 0), null, (void 0), null, (void 0), null, null, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), null, null, (void 0), (void 0), (void 0), (void 0), null, (void 0), (void 0), (void 0)].sort, , (4277), (4277), , x])), x, x, w, e, x, c, x = (void shapeOf( \"\" )), b, a = \"\\uE90A\", d = -25, \u3056, x = 2, x, d, w, x, x, w, x, x, NaN, e = new RegExp(\"\\\\b\", \"gm\"), \u3056, \u3056 =  /x/g , eval, y, y, y, x, \u3056, x, window, z, x, x, x, w, window, c, y, w, c = window, d = b, c, x, c = \"\\uA44F\", d, window, e = new RegExp(\".*\", \"gyim\"), x, x, y, x, x, x, z, x, b, c, w, NaN =  \"\" , x, z, x, eval, x = arguments, x, x, x, NaN, x, a, x, x, y, NaN =  \"\" , x, d = true, x =  /x/g , x, x = 23, x, x, x, z, c = true, z, y, b, x, eval) { \"use strict\"; selectforgc(o0);d = ++arguments.callee.caller.caller.caller.arguments; } v1 = a1.length;");
/*fuzzSeed-204645237*/count=539; tryItOut("\"use strict\"; const eval = false;a2.reverse();m2.set(h0, h2);");
/*fuzzSeed-204645237*/count=540; tryItOut("mathy5 = (function(x, y) { return mathy1((Math.fround(Math.atanh(Math.fround((( ! (Math.pow((x | 0), (( + x) - ( + -0x100000001))) >>> 0)) >>> 0)))) | Math.fround(Math.atan((( - ((-Number.MIN_VALUE || 1) | 0)) | 0)))), ( + Math.sin(( + (Math.atan((( ~ ((Math.log10((x >>> 0)) >>> 0) >>> 0)) ? Math.fround(Math.pow(Math.fround(Math.log1p(x)), \"4\")) : Math.fround(Math.imul(( + ((x , x) * (x + y))), ( + x))))) >>> 0))))); }); testMathyFunction(mathy5, [0x080000000, -0x080000000, Number.MAX_VALUE, 0x07fffffff, -(2**53+2), Number.MIN_VALUE, 2**53, 0x100000000, -0x080000001, -0, 2**53+2, -0x07fffffff, 0x0ffffffff, Math.PI, 1/0, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1, 0x080000001, 0.000000000000001, 42, 0, 2**53-2, 0/0]); ");
/*fuzzSeed-204645237*/count=541; tryItOut("\"use strict\"; (/*UUV2*/(x.getUint32 = x.getUint32));");
/*fuzzSeed-204645237*/count=542; tryItOut("m0 = new Map(f2);");
/*fuzzSeed-204645237*/count=543; tryItOut("t0[1] = this.h1;");
/*fuzzSeed-204645237*/count=544; tryItOut("Object.defineProperty(this, \"t2\", { configurable: (x % 3 != 1), enumerable: c += x,  get: function() {  return new Uint32Array(18); } });");
/*fuzzSeed-204645237*/count=545; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x080000000, 0.000000000000001, 0x0ffffffff, -0x080000001, -0x100000000, Number.MAX_VALUE, -(2**53), 0/0, 42, -1/0, -Number.MAX_VALUE, 2**53, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 0, 2**53+2, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000001, -(2**53-2), 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 1.7976931348623157e308, Math.PI, -(2**53+2), 1, -0x0ffffffff, 0x080000001, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=546; tryItOut("v0 = eval(\"/* no regression tests found */\", /*UUV2*/(e.toLocaleString = e.pop));");
/*fuzzSeed-204645237*/count=547; tryItOut("\"use strict\"; for (var p in s2) { try { for (var p in this.b2) { try { a1[15] = ({ set wrappedJSObject()x }); } catch(e0) { } try { neuter(b1, \"same-data\"); } catch(e1) { } g1.offThreadCompileScript(\"v2 = -Infinity;\", ({ global: this.o1.g1, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: (URIError)(), sourceIsLazy: true, catchTermination: true })); } } catch(e0) { } e0.add(o2.v1); }");
/*fuzzSeed-204645237*/count=548; tryItOut("mathy5 = (function(x, y) { return ( - ( + Math.pow(( + (( - y) && (Math.fround(Math.pow((-0x07fffffff >>> 0), ( + x))) | 0))), ( + (mathy0(Math.fround((Math.fround(Math.fround(Math.log2(mathy2(x, ( + Number.MIN_SAFE_INTEGER))))) == Math.fround(-Number.MIN_SAFE_INTEGER))), ( + Math.atan2(( + mathy1(y, x)), ( + (((0/0 % Math.fround(x)) < ( ~ ( + Math.fround(Math.abs((x | 0)))))) >>> 0))))) | 0))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, 1/0, -(2**53), Number.MAX_VALUE, 0x080000000, -1/0, 2**53+2, 0x080000001, -(2**53-2), -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -0x07fffffff, 0, 42, 1, 2**53, 0/0, -0x0ffffffff, -0, -0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, -0x080000000, Math.PI]); ");
/*fuzzSeed-204645237*/count=549; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=550; tryItOut("\"use strict\"; \"use asm\"; v1 = (b0 instanceof h1);");
/*fuzzSeed-204645237*/count=551; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(mathy2(Math.fround((Math.pow(( - Math.log10(x)), (((( ! (Math.tanh(( + (Math.imul((x >>> 0), (y >>> 0)) >>> 0))) >>> 0)) / (x | 0)) | 0) | 0)) | 0)), Math.fround((Math.fround(Math.max(Math.imul(y, Math.PI), Math.fround(( ! Math.fround(x))))) < (mathy2((Math.cosh(Math.fround(x)) | 0), (( - ( ! (2**53-2 ** (y | 0)))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [-(2**53-2), -0x080000000, Number.MAX_VALUE, -0x100000001, Math.PI, 0x100000001, 0x0ffffffff, -1/0, 0, 0x080000000, 1, -(2**53+2), 0.000000000000001, -(2**53), 0/0, 2**53, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, -0x07fffffff, 2**53-2, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, 42, -0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=552; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.hypot(((( + ((( ~ ( + Math.max(( + (((Math.fround(x) % x) | 0) >> Math.fround(Math.log1p(-0x080000000)))), ( + Math.expm1(x))))) | 0) | 0)) | 0) | 0), Math.abs(( + (Math.expm1((x | 0)) | 0)))) >>> 0); }); testMathyFunction(mathy3, [-1/0, -(2**53), -0x07fffffff, -0x100000001, -0x080000001, -0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, 42, -0, 1.7976931348623157e308, -0x080000000, 2**53+2, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, 0x080000000, 0/0, 0x07fffffff, Number.MIN_VALUE, 0, Math.PI, 1, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=553; tryItOut("e0.add(f0);");
/*fuzzSeed-204645237*/count=554; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( ~ Math.fround((Math.acosh((( + Math.tan(( + ( + Math.fround(mathy0(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround((mathy0((y | 0), (y | 0)) | 0)))))))) | 0)) | 0))) == ( ! ( + (((Math.expm1(mathy0(Math.max((( - 0/0) >>> 0), Math.ceil(( + y))), x)) >>> 0) ? (( - ( + mathy0(( ! Math.fround(Math.imul(x, x))), ( + Math.clz32(-0x080000001))))) >>> 0) : mathy0(Math.fround(Math.acosh(y)), ( + Math.sqrt(y)))) >>> 0)))); }); testMathyFunction(mathy1, [1/0, -0x07fffffff, 0, 2**53-2, 1, -0x0ffffffff, 2**53, 2**53+2, Number.MIN_VALUE, -0x080000001, 0x080000000, -0x080000000, 0.000000000000001, Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, -(2**53), 0x080000001, -(2**53+2), Math.PI, 0x100000001, 0x07fffffff, -0x100000001, -Number.MIN_VALUE, 0x0ffffffff, 42, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=555; tryItOut("\"use strict\"; /.|(?=.){1,}|([^]?){64,}{2,}(?!(^|[^\\x02-\u00d1\\uF2B0\\f]?)*\u0094*?)/gi;\n/* no regression tests found */\n");
/*fuzzSeed-204645237*/count=556; tryItOut("function shapeyConstructor(psfnjp){Object.defineProperty(this, new String(\"16\"), ({}));for (var ytqqcosbe in this) { }this[\"apply\"] = (void 0);if (psfnjp) this[\"apply\"] = false;this[\"apply\"] = ArrayBuffer;return this; }/*tLoopC*/for (let e of ([x] for each (NaN in Math.atan2(false, 2)) for (b of x))) { try{let bpbjth = new shapeyConstructor(e); print('EETT'); delete h2.fix;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-204645237*/count=557; tryItOut("i1 = new Iterator(s2);");
/*fuzzSeed-204645237*/count=558; tryItOut("/* no regression tests found */\n/*ADP-2*/Object.defineProperty(a1, 2, { configurable: true, enumerable:  '' , get: (function(j) { o0.f0(j); }), set: e => \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (-0x8000000);\n    switch ((((!(0x2bf13e7b))+(!(0xf9c0b166))) & ((-0x8000000)-(0x7cd9d966)-(0xd08a0d1d)))) {\n      default:\n        (Float32ArrayView[((0xfaa8aa89)) >> 2]) = ((+atan2(((+((281474976710657.0)))), ((-17.0)))));\n    }\n    return (((((0x310b2*(i1))>>>((0x5c24338c))) >= (0x3d57d058))-(i1)))|0;\n    return (((0x75afc7ba)*-0x470b3))|0;\n  }\n  return f; });\n");
/*fuzzSeed-204645237*/count=559; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.min((((Math.abs(((Math.min(( + (( + y) << y)), Math.pow(( + ( ! (0.000000000000001 >>> 0))), ( ~ x))) | 0) | 0)) >>> 0) , (Math.max((mathy0(Math.fround((Math.sin((x >>> 0)) >>> 0)), Math.fround(( ~ Math.hypot((Math.trunc(Number.MIN_SAFE_INTEGER) | 0), (y | 0))))) | 0), ((Math.hypot(( ~ y), (mathy2((x >>> 0), (x >>> 0)) >>> 0)) >>> 0) | 0)) | 0)) | 0), ((Math.min(((( + ((y % y) >>> 0)) | 0) | 0), (Math.fround(Math.imul((Math.exp((( - Math.fround(-0)) | 0)) >>> 0), (( + (Math.min(y, ( + (mathy2(-0x100000001, -(2**53)) >>> 0))) ^ mathy3(( + x), -(2**53)))) >>> 0))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy4, [-(2**53), -0x100000000, -Number.MIN_VALUE, 0x080000001, 0/0, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, -0x080000001, Number.MIN_VALUE, 0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, -1/0, -(2**53-2), -0, -0x07fffffff, 2**53-2, 2**53+2, 0x100000000, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, 2**53, 0x0ffffffff, -(2**53+2), -0x080000000, 0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-204645237*/count=560; tryItOut("([x]);");
/*fuzzSeed-204645237*/count=561; tryItOut("\"use strict\"; gmwwjk(\u0009{});/*hhh*/function gmwwjk({x}, [[{z: {NaN: {}}, x}, , , NaN]]){b0 + '';}");
/*fuzzSeed-204645237*/count=562; tryItOut("t0[12] = b2;");
/*fuzzSeed-204645237*/count=563; tryItOut("var hqgenx = new SharedArrayBuffer(0); var hqgenx_0 = new Int16Array(hqgenx); print(hqgenx_0[0]); var hqgenx_1 = new Uint8ClampedArray(hqgenx); var hqgenx_2 = new Uint8ClampedArray(hqgenx); hqgenx_2[0] = -28; var hqgenx_3 = new Uint8ClampedArray(hqgenx); hqgenx_3[0] = -26; var hqgenx_4 = new Uint8Array(hqgenx); var hqgenx_5 = new Int8Array(hqgenx); hqgenx_5[0] = 8; var hqgenx_6 = new Int8Array(hqgenx); print(hqgenx_6[0]); hqgenx_6[0] = -12; var hqgenx_7 = new Uint8Array(hqgenx); var hqgenx_8 = new Uint8ClampedArray(hqgenx); var hqgenx_9 = new Int16Array(hqgenx); hqgenx_9[0] = 19; window; \"\" ;yield;o2.o1.i1.next();print(hqgenx_2[0]);i0.next();g2.offThreadCompileScript(\"for (var p in o2) { try { v1 = evaluate(\\\"this\\\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (hqgenx_4[6] % 4 != 1), noScriptRval: (hqgenx_1 % 50 != 25), sourceIsLazy: false, catchTermination: function ([y]) { } })); } catch(e0) { } try { Array.prototype.shift.call(a2, o1.v2); } catch(e1) { } v1 = (p1 instanceof this.o1.b0); }\");/*RXUB*/var r = /(?=(?=(?![^\\xD4-\uc43e\\W]|(?:[^]){1,5}{2,3}))+?)|((?!(?:\\B)*(?:\u00d6)|\uce57|[^\\d\\s]*?(\u00f8)|(?!(?:[^])*))){4,7}/gy; var s = \"\\u00f8\\u00f8\\u00f8\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=564; tryItOut("testMathyFunction(mathy0, [(new Number(-0)), -0, undefined, (new Number(0)), (new Boolean(true)), '\\0', ({valueOf:function(){return 0;}}), 1, true, [0], 0.1, '', /0/, '/0/', 0, (new Boolean(false)), (new String('')), [], NaN, ({toString:function(){return '0';}}), objectEmulatingUndefined(), null, ({valueOf:function(){return '0';}}), (function(){return 0;}), false, '0']); ");
/*fuzzSeed-204645237*/count=565; tryItOut("v0 = (b2 instanceof e0);");
/*fuzzSeed-204645237*/count=566; tryItOut("/*MXX2*/g2.Symbol.toPrimitive = g2.t0;\nprint(new (function(y) { \"use strict\"; return window })(eval(\"[,,]\")));\n");
/*fuzzSeed-204645237*/count=567; tryItOut("(1393416150.watch(\"call\", offThreadCompileScript));");
/*fuzzSeed-204645237*/count=568; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ! Math.round(Math.atan2(Math.fround(Math.cos(Math.fround(x))), x))); }); testMathyFunction(mathy4, [42, 1, 1.7976931348623157e308, 0x100000001, -0, -1/0, 0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 0, -0x100000001, 2**53+2, -0x080000001, 1/0, -(2**53+2), Number.MIN_VALUE, -(2**53), 2**53-2, -0x07fffffff, -Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff, 0/0, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=569; tryItOut("/*RXUB*/var r = /\\1/gym; var s = \"\\u00f8\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=570; tryItOut("\"use strict\"; h0.toString = f2;");
/*fuzzSeed-204645237*/count=571; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.imul(Math.fround(Math.max(Number.MAX_SAFE_INTEGER, ( - x))), ( + ( + mathy2(( + Math.abs(x)), x))))) >>> 0) > ( + ((Math.acos((( + -0x100000001) >>> 0)) >>> 0) | 0))) | 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 1, 0x07fffffff, 0x080000000, 2**53+2, 1/0, 2**53, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, -(2**53-2), 0/0, 1.7976931348623157e308, -0x07fffffff, 0x0ffffffff, -(2**53+2), 42, Number.MAX_VALUE, -0x080000001, -(2**53), -0, Number.MIN_VALUE, 0x080000001, Math.PI, -0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=572; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.asinh(mathy1((Math.pow(Math.fround(( + (( + Math.imul(( + (Math.min(y, x) ? 0 : Math.fround((x ? y : (-1/0 | 0))))), y)) ? ( + (Math.fround(( ~ y)) & -0x0ffffffff)) : ( + Math.clz32(y))))), Math.fround(( - y))) | 0), Math.pow(( ~ ((x ? (x >>> 0) : y) | 0)), Math.imul(x, (y >>> 0))))) | 0); }); testMathyFunction(mathy5, [objectEmulatingUndefined(), (new Number(0)), 0, 1, -0, false, true, [0], (new String('')), ({toString:function(){return '0';}}), [], '0', /0/, NaN, '\\0', ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), null, (new Boolean(false)), (function(){return 0;}), (new Number(-0)), (new Boolean(true)), undefined, '', '/0/', 0.1]); ");
/*fuzzSeed-204645237*/count=573; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.tan((Math.min((( + Math.sqrt(( + Math.atan2(Math.imul(0x07fffffff, y), y)))) >>> 0), (( + Math.exp(mathy0(y, Math.max(y, Math.cosh(2**53))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0/0, 1, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, -(2**53+2), 0x100000001, -(2**53), 0x080000001, -(2**53-2), -0x07fffffff, 42, 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, -1/0, Number.MAX_VALUE, -0, 0x100000000, 1/0, Math.PI, -Number.MAX_VALUE, -0x080000001, 0x080000000, -0x100000000, 0, Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-204645237*/count=574; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 2.3611832414348226e+21;\n    var d4 = -1.0009765625;\n    d1 = (d1);\n    d4 = (2147483648.0);\n    {\n      (Int32ArrayView[1]) = ((((Uint32ArrayView[0]))>>>((0xa323ac))) % (((0xfea3384a))>>>((((0x675ffd13)-(0xffffffff)+(0xf93c7afe))>>>((Int8ArrayView[2]))) % (((0x1c5e602b) % (0x4e5f81b9))>>>((0xfb091d7e))))));\n    }\n    {\n      {\n        i2 = ((0x5ee25312) != (((i2))>>>((Uint16ArrayView[((0x2cb5c16c)*-0xfffff) >> 1]))));\n      }\n    }\nf2 = (function() { try { v0 = t1.length; } catch(e0) { } try { h2.valueOf = this.f2; } catch(e1) { } try { print(uneval(g0)); } catch(e2) { } a0.forEach((function mcc_() { var ouywrf = 0; return function() { ++ouywrf; if (/*ICCD*/ouywrf % 9 == 4) { dumpln('hit!'); try { v2 = g1.g1.eval(\"print(x);\"); } catch(e0) { } try { v0 + v2; } catch(e1) { } try { Array.prototype.forEach.call(g1.a0, ({/*TOODEEP*/}), this.o1.v1); } catch(e2) { } b2 + g1.o0; } else { dumpln('miss!'); try { o2.v2 = a1.length; } catch(e0) { } try { t2.set(a2, 2); } catch(e1) { } g0.offThreadCompileScript(\"-7\"); } };})()); return v1; });    return +((d1));\n  }\n  return f; })(this, {ff: (new Function(\"print(Uint8ClampedArray());\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1.7976931348623157e308, 2**53+2, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 2**53-2, 2**53, 0x080000001, 42, -Number.MAX_VALUE, -(2**53+2), -1/0, -0x07fffffff, -0x0ffffffff, 0.000000000000001, 0x080000000, 0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), 1/0, Math.PI, -0x080000000, Number.MIN_VALUE, 0/0, -0x100000001, 1, 0x07fffffff, -0x100000000, -Number.MIN_VALUE, -0x080000001, 0x100000000]); ");
/*fuzzSeed-204645237*/count=575; tryItOut("/*oLoop*/for (jpqxkp = 0; jpqxkp < 52; ++jpqxkp) { /*infloop*/for(let eval in ((function  b (y) { yield new RegExp(\"(?:(?:[^])+?)+\", \"gy\") } )(/3{0,32769}/ym)))v0 = (o0.o2 instanceof g2.v2); } ");
/*fuzzSeed-204645237*/count=576; tryItOut("h1.getPropertyDescriptor = (function mcc_() { var vccikg = 0; return function() { ++vccikg; f1(/*ICCD*/vccikg % 8 == 1);};})();");
/*fuzzSeed-204645237*/count=577; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.acos((Math.imul(0x07fffffff, (mathy1(Math.fround((Math.atan2((Math.atanh((Math.sinh((y | 0)) | 0)) >>> 0), (( + Math.min(( + y), (-1/0 | 0))) >>> 0)) >>> 0)), ( ~ y)) >>> 0)) , Math.imul(mathy0(y, ((x << ( ! y)) >>> 0)), Math.fround(( + Math.imul(mathy1(((y - Math.exp(x)) | 0), (y | 0)), Math.sinh(0x07fffffff))))))); }); testMathyFunction(mathy3, [-(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, 1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -0x100000000, 0/0, -0x07fffffff, 0x07fffffff, 2**53+2, 42, Number.MIN_VALUE, 2**53, -0x0ffffffff, 0x0ffffffff, 1, -1/0, 0x080000000, 0x100000001, -(2**53), -0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, -0x100000001, -0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0, 0x080000001, 2**53-2]); ");
/*fuzzSeed-204645237*/count=578; tryItOut("print(x);\nprint(o0);\n");
/*fuzzSeed-204645237*/count=579; tryItOut("with({w: x}){s2 += 'x';function e(w, w, ...x) { this; } Array.prototype.pop.apply(a1, [this.p1, i1, t1, a2, p1]);m2 = new Map; }x = m0;");
/*fuzzSeed-204645237*/count=580; tryItOut("\"use strict\"; v2 = true;function z(x, x, a, x, z, x, a, NaN, {eval: {\u3056: {}, d: window}, x: []\u000c}, a, ((4277) < (x !== x)) = ((function ([y]) { })().unwatch(\"y\")), x, \u3056, x, x, x, eval, y, x, z = length, z, NaN, x, c, d, c, x = this, c = this, x, a, eval, z =  /x/ , c, e = ({a2:z2}), x, y =  /x/g , x = length, x, NaN, x, x, getter = window, NaN, eval = \"\\uBD19\", c = 3, c =  /x/g , x, eval, y = c, e, x, x = window, NaN, NaN, x, e,  '' , x, eval =  /x/ , \u3056 = x, x, x, x, x, x, this.b, x, x, w, eval, \u3056, \u3056, x, NaN, c, \u3056, eval, x, z, NaN, window = new RegExp(\"^\", \"im\"), x, x, ...\u3056) { \"use strict\"; return x } /*RXUB*/var r =  /x/ ; var s = \"\"; print(s.replace(r, function  r (w = new RegExp(\"(?:.+)\", \"im\"), d) { this.v1 = evalcx(\"mathy3 = (function(x, y) { return ( - Math.imul(( + ((Math.atan2(x, (y | 0)) << ( + 0)) || ((((1 != (Math.max(x, mathy1(Math.fround(y), Math.fround(0/0))) >>> 0)) ? x : 42) >>> 0) >>> 0))), (Math.hypot(Math.fround(((y >>> 0) != y)), ((x ? (y == (Math.abs((y | 0)) | 0)) : (( ! (mathy2(x, x) >>> 0)) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), [], new Boolean(false), [1], [1], new Boolean(false), new Boolean(false), [], [], new Boolean(false), [], [], [1], [], [1], new Boolean(false), [1], new Boolean(false), [1], [1], [1], new Boolean(false), [], [], [], [], [], [], [], new Boolean(false), [1], [1], [], [], new Boolean(false), [1], new Boolean(false), [], new Boolean(false), new Boolean(false), [], new Boolean(false), new Boolean(false), [], [], new Boolean(false), [], [1], [], [1], new Boolean(false), [1], [], [1], [1], [], [1], new Boolean(false), [], [], [], new Boolean(false), new Boolean(false), [], [], [1], [], new Boolean(false), [], [1], [], new Boolean(false), [], [], [], []]); \", g0); } , \"gm\")); ");
/*fuzzSeed-204645237*/count=581; tryItOut("/*infloop*/L:for(var z; window; x = function ([y]) { }\u0009) delete h2.defineProperty;");
/*fuzzSeed-204645237*/count=582; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((( + Math.fround(x)) >>> 0) == ( - (Math.round(x) >>> 0))) != ( + Math.imul(Math.round(Math.fround(( ! Math.fround(-0)))), Math.max(Math.fround(Math.log((y | 0))), Math.pow(( + Math.sinh(y)), (Math.log10((((x ? (x >>> 0) : 2**53+2) >>> 0) | 0)) , y)))))); }); testMathyFunction(mathy0, [-(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, 0.000000000000001, 42, 0x07fffffff, 1, -0, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, 0, -0x100000000, 2**53-2, -(2**53), -0x100000001, Math.PI, -0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -1/0, 2**53, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, 0x100000001, 0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=583; tryItOut("mathy5 = (function(x, y) { return ((( + Math.imul(Math.fround(Math.min((-1/0 , (((y | 0) !== ((((x >>> 0) , (0x080000000 >>> 0)) >>> 0) >>> 0)) >>> 0)), x)), ( + (Math.fround(Math.log10(((( + (((y >>> 0) <= (-0 >>> 0)) >>> 0)) > Math.fround(y)) >>> 0))) == Math.fround(( - Math.pow(y, x))))))) ? Math.sign(Math.imul((( + (( + (Math.tanh(y) / 2**53+2)) , ( + -(2**53+2)))) ? (( + Math.log1p(x)) !== ( + y)) : Math.fround(Math.tan(Math.fround(x)))), (x | 0))) : Math.expm1(( + Math.hypot(( + Math.max(( + y), (y >= (x >>> 0)))), Math.fround(y))))) >>> 0); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -(2**53+2), -0, 0, 2**53+2, 0/0, 1, Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, 42, -Number.MIN_VALUE, 0x100000000, -0x080000001, -0x080000000, 0x07fffffff, 1/0, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, -(2**53), 0x080000000, 0x080000001, -0x07fffffff, 2**53-2, Math.PI, 1.7976931348623157e308]); ");
/*fuzzSeed-204645237*/count=584; tryItOut("i2.next();");
/*fuzzSeed-204645237*/count=585; tryItOut("\"use strict\"; a1 = new Array;");
/*fuzzSeed-204645237*/count=586; tryItOut("i1 + '';");
/*fuzzSeed-204645237*/count=587; tryItOut("\"use strict\"; g1 = this");
/*fuzzSeed-204645237*/count=588; tryItOut("testMathyFunction(mathy0, /*MARR*/[ '' ,  '' ,  /x/g ,  /x/g ,  '' , function(){},  '' , function(){},  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , function(){}, (1/0),  /x/g ,  /x/g , (1/0), (1/0), function(){}, function(){}, function(){},  /x/g ,  /x/g , (1/0)]); ");
/*fuzzSeed-204645237*/count=589; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.pow((( - (Math.max(( ! x), Math.fround(x)) | 0)) | 0), (Math.min(( ~ x), (( ! y) >= (Math.atan2(Math.atan2(y, y), y) >>> 0))) | 0)) | 0) ^ ( ~ Math.sin(((( - (x >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy0, [-0, 42, -(2**53+2), 0x0ffffffff, 0x100000001, 2**53+2, 0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), 0x080000001, 1.7976931348623157e308, -0x100000000, Number.MIN_VALUE, 0.000000000000001, -0x100000001, -0x07fffffff, Math.PI, Number.MAX_SAFE_INTEGER, 0/0, 1, 2**53-2, 1/0, -1/0, 2**53, Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, -0x080000001]); ");
/*fuzzSeed-204645237*/count=590; tryItOut("v2 = true;");
/*fuzzSeed-204645237*/count=591; tryItOut("/*tLoop*/for (let d of /*MARR*/[-Number.MIN_SAFE_INTEGER, new Number(1.5), new Number(1.5), new Number(1.5), [1],  '' , [1]]) { /*RXUB*/var r = r2; var s = window--; print(uneval(r.exec(s))); print(r.lastIndex);  }");
/*fuzzSeed-204645237*/count=592; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(((( ~ Math.imul(x, Math.hypot(0x080000000, x))) | 0) | ( + (( + Math.fround(Math.imul(Math.fround(x), (-0x080000001 >>> 0)))) , ( + (((y >>> 0) ** Math.fround(Number.MIN_SAFE_INTEGER)) >>> 0)))))), Math.fround((((( + Math.fround(Math.imul(y, Math.hypot(1, (((0 >>> 0) !== (y >>> 0)) >>> 0))))) >>> 0) && ((Math.log2((Math.fround(Math.atanh(Math.fround(Math.sinh(Math.asin(-Number.MIN_VALUE))))) | 0)) | 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [1/0, 0x100000001, -0x100000000, -0x080000000, 0.000000000000001, 0x07fffffff, -0, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), -Number.MAX_VALUE, 1.7976931348623157e308, 42, Number.MAX_VALUE, Number.MIN_VALUE, -1/0, 0, -0x0ffffffff, 0x080000000, 2**53-2, 1, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, -Number.MIN_VALUE, -0x07fffffff, -0x080000001, -(2**53), 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=593; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(((Math.fround(Math.min((y | 0), Math.fround(0x080000001))) ? (( + Math.pow(( + x), -0x07fffffff)) >>> 0) : Math.fround(( - x))) | 0)) + Math.fround(( + mathy0(( + Math.atan2(x, ( ~ ((y | 0) & (y | 0))))), mathy0(Math.pow(y, x), Number.MIN_VALUE))))) && (( ! ((((-(2**53-2) | 0) === (y | 0)) | 0) | 0)) >> (Math.clz32(x) === y))); }); testMathyFunction(mathy1, [-(2**53-2), 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, 2**53, 2**53-2, 1, Number.MAX_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, -0x080000001, 0, 0x100000001, 0x0ffffffff, -Number.MAX_VALUE, -0x100000001, 0x080000000, -0x07fffffff, Number.MAX_VALUE, 0x080000001, -(2**53), -Number.MIN_VALUE, -0, 2**53+2, Number.MIN_VALUE, Math.PI, -(2**53+2), 1/0, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -1/0]); ");
/*fuzzSeed-204645237*/count=594; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x07fffffff, -Number.MAX_VALUE, -(2**53-2), 2**53, Number.MIN_VALUE, -(2**53), -Number.MIN_VALUE, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), 0x07fffffff, 0, 0/0, 0x100000001, 0x080000000, 2**53+2, 0.000000000000001, 1/0, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, 0x080000001, -0x0ffffffff, 1.7976931348623157e308, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, -0x100000000, -0x100000001]); ");
/*fuzzSeed-204645237*/count=595; tryItOut("\"use strict\"; print(g2.b2);");
/*fuzzSeed-204645237*/count=596; tryItOut("/*MXX3*/g0.Uint8Array.name = g2.Uint8Array.name;");
/*fuzzSeed-204645237*/count=597; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-204645237*/count=598; tryItOut("a1.pop(g0);/*MXX3*/g2.String.prototype.sub = g2.String.prototype.sub;");
/*fuzzSeed-204645237*/count=599; tryItOut("testMathyFunction(mathy1, [2**53+2, -(2**53), Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, 0x080000001, -Number.MIN_VALUE, 42, 0x100000001, 1, 0x080000000, -0, 0, 2**53-2, 1.7976931348623157e308, 0x07fffffff, -0x100000000, -(2**53+2), -0x080000001, 0x0ffffffff, -0x080000000, 2**53, -1/0, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-204645237*/count=600; tryItOut("/*RXUB*/var r = /(?!(?:(?:.?)(?!(?:\u2e23)\\b${4,})?\\D|(?:\\d).|\u000c\\B+?|\\b[^]\u3f7e?))/g; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-204645237*/count=601; tryItOut("mathy1 = (function(x, y) { return (mathy0((Math.fround(( + ( ! Math.fround((Math.fround(Math.sign(Number.MIN_VALUE)) || y))))) , Math.fround(0x07fffffff)), ((( + ((Math.fround(( - Math.fround(y))) >>> 0) - (mathy0((( + Math.pow(( + -(2**53+2)), x)) >>> 0), (( ~ y) >>> 0)) >>> 0))) ? (Math.fround(Math.pow(( + Math.max(x, -(2**53+2))), ( + (mathy0(y, ( ~ y)) >>> 0)))) >>> 0) : Math.fround((Math.fround(mathy0(x, x)) % Math.imul(y, x)))) >>> 0)) < ((( - ( + Number.MAX_SAFE_INTEGER)) >>> ((Math.max((( + x) >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0x0ffffffff, 0x0ffffffff, 2**53+2, 1, -(2**53), -Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, 2**53-2, Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, Number.MAX_VALUE, -(2**53-2), 0, -Number.MIN_SAFE_INTEGER, Math.PI, 1/0, 42, -0x080000001, -0, 0/0, 0.000000000000001, -1/0, 0x100000000, -0x100000000]); ");
/*fuzzSeed-204645237*/count=602; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ ( + (( + y) >= ((Math.fround(( ~ (x | 0))) >>> 0) ^ Math.fround(y))))) >>> 0); }); testMathyFunction(mathy0, [-0, 0x100000001, -(2**53), 0x080000000, 1, 0x080000001, 1/0, 0x07fffffff, -0x080000000, -0x07fffffff, 42, 2**53, 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), 0.000000000000001, -0x100000000, -(2**53+2), -1/0, Math.PI, -0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-204645237*/count=603; tryItOut("mathy5 = (function(x, y) { return ( + Math.acosh(( + (Math.exp((( ! (Math.max(x, -1/0) ? x : y)) >> x)) >>> 0)))); }); testMathyFunction(mathy5, [-0, -0x0ffffffff, 0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -1/0, 2**53-2, Math.PI, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 1, 0, -0x07fffffff, 1/0, 0x100000001, 0/0, -0x100000001, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, -0x100000000, 0x080000000, 2**53+2, -0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, -0x080000000]); ");
/*fuzzSeed-204645237*/count=604; tryItOut("\"use strict\"; fxelzt, x = /*MARR*/[ /x/ ,  '' ,  '' ,  '' , new Number(1)], gsjmcv;print(OSRExit());");
/*fuzzSeed-204645237*/count=605; tryItOut("\"use strict\"; /*infloop*/L: for  each(let (4277)().__proto__ in (a) =  '' ) {h2.keys = f0; }");
/*fuzzSeed-204645237*/count=606; tryItOut("\"use strict\"; let (x = NaN++) { g0.t0 = new Uint8ClampedArray(a0); }");
/*fuzzSeed-204645237*/count=607; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=608; tryItOut("\"use strict\"; var uoujfl = new SharedArrayBuffer(8); var uoujfl_0 = new Float64Array(uoujfl); uoujfl_0[0] = 9; var uoujfl_1 = new Float64Array(uoujfl); uoujfl_1[0] = 2; var uoujfl_2 = new Int16Array(uoujfl); print(uoujfl_2[0]); uoujfl_2[0] = -1024; var uoujfl_3 = new Uint8Array(uoujfl); var uoujfl_4 = new Uint8ClampedArray(uoujfl); var uoujfl_5 = new Uint32Array(uoujfl); print(uoujfl_5[0]); uoujfl_5[0] = -26; var uoujfl_6 = new Int8Array(uoujfl); uoujfl_6[0] = -10; uoujfl_4[0];/*iii*/(\"\\uA327\");/*hhh*/function cvwvsm(){print(uoujfl_6[3]);}let o1.a2 = Array.prototype.filter.apply(a1, [m2]);print( /x/ .__defineGetter__(\"uoujfl_1\", -22));a2.__iterator__ = (function() { g2.g2 + ''; return g1.b2; });");
/*fuzzSeed-204645237*/count=609; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"o0.a2 = Array.prototype.filter.apply(a0, [(function mcc_() { var zeixgm = 0; return function() { ++zeixgm; if (/*ICCD*/zeixgm % 9 == 6) { dumpln('hit!'); try { h0.keys = (function(j) { f1(j); }); } catch(e0) { } try { m0.has(g0); } catch(e1) { } for (var v of g1) { try { s2 += 'x'; } catch(e0) { } try { Object.freeze(f0); } catch(e1) { } a0 = arguments.callee.caller.caller.caller.caller.arguments; } } else { dumpln('miss!'); try { v0 = 4; } catch(e0) { } Object.prototype.watch.call(s1, new String(\\\"1\\\"), String.prototype.replace); } };})()]);\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 == 3), sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-204645237*/count=610; tryItOut("print(x);");
/*fuzzSeed-204645237*/count=611; tryItOut("o0.o2.valueOf = f2;");
/*fuzzSeed-204645237*/count=612; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.asinh(( ! Math.fround(( + Math.pow(( + mathy2(Math.fround(( ! x)), ( + mathy1(( + y), x)))), (Math.sign((Math.min(-(2**53), (( + Math.acos(x)) >>> 0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, /*MARR*/[-0x080000000, (-1), new Boolean(true), -0x080000000, -0x080000000, (-1), new Boolean(true), null, undefined, undefined, undefined, null, null, (-1), new Boolean(true), -0x080000000, null, null, undefined, (-1), -0x080000000, new Boolean(true), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), null, (-1), new Boolean(true), null, undefined, null, undefined, -0x080000000, undefined, null, -0x080000000, null, -0x080000000, -0x080000000, new Boolean(true), (-1), undefined, undefined, new Boolean(true), new Boolean(true), (-1), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1), -0x080000000, undefined, new Boolean(true), null, new Boolean(true), -0x080000000, undefined, (-1), new Boolean(true), undefined, new Boolean(true), -0x080000000, new Boolean(true), -0x080000000, new Boolean(true), null, new Boolean(true), (-1)]); ");
/*fuzzSeed-204645237*/count=613; tryItOut("\"use strict\"; print(uneval(t1));");
/*fuzzSeed-204645237*/count=614; tryItOut("mathy3 = (function(x, y) { return (((mathy1((mathy1(( ! (((( - Number.MIN_VALUE) >>> 0) < ( + (( + x) ? ( + x) : ( + x)))) | 0)), y) | 0), (Math.cosh((Math.fround(Math.clz32(y)) / Math.fround((((mathy2(y, Math.atanh((x >>> 0))) >>> 0) ? (( + y) >>> 0) : (y | 0)) >>> 0)))) | 0)) | 0) >>> 0) ^ (Math.acosh((Math.asin(( + ( + (x >>> 0)))) | 0)) >>> 0)); }); testMathyFunction(mathy3, [-1/0, 0/0, 0x100000001, -0x100000001, 2**53-2, 42, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, 0, 0x080000000, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, 1, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53), 0x100000000, 2**53, 1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, -0, -0x080000001]); ");
/*fuzzSeed-204645237*/count=615; tryItOut("for(var d in (((function shapeyConstructor(mrauyo){if (mrauyo) this[\"call\"] = new Boolean(false);if (c) Object.seal(this);Object.defineProperty(this, new String(\"18\"), ({configurable: true}));this[\"__count__\"] = objectEmulatingUndefined();return this; }).apply)(((makeFinalizeObserver('nursery')))))){(length);(\"\\uBD1F\"); }\nprint(uneval(p2));\n");
/*fuzzSeed-204645237*/count=616; tryItOut("testMathyFunction(mathy2, [1, false, 0.1, -0, '0', (new Number(-0)), [0], (new Boolean(true)), '', (function(){return 0;}), (new Number(0)), objectEmulatingUndefined(), (new String('')), undefined, /0/, ({valueOf:function(){return '0';}}), null, true, '\\0', '/0/', (new Boolean(false)), ({valueOf:function(){return 0;}}), NaN, [], ({toString:function(){return '0';}}), 0]); ");
/*fuzzSeed-204645237*/count=617; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-204645237*/count=618; tryItOut("/*oLoop*/for (var lxqqqv = 0, intern(x); lxqqqv < 39; ++lxqqqv) { var zxivmv = new SharedArrayBuffer(12); var zxivmv_0 = new Uint8Array(zxivmv); zxivmv_0[0] = 9; var zxivmv_1 = new Int16Array(zxivmv); var zxivmv_2 = new Float64Array(zxivmv); zxivmv_2[0] = -8; print(zxivmv_2[9]);print(window);zxivmv_2[0]; } ");
/*fuzzSeed-204645237*/count=619; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ( + (((((y | 0) < (Math.imul(y, Math.fround((Math.fround(Number.MAX_VALUE) && Math.fround(( + Math.max(Math.fround(-Number.MAX_SAFE_INTEGER), (Number.MAX_SAFE_INTEGER | 0))))))) | 0)) | 0) ? (Math.pow(x, ( + (Math.fround(Math.clz32(Math.fround(y))) <= (Math.acosh(Math.fround(Math.tanh(Math.fround(0x080000001)))) | 0)))) >>> 0) : (Math.ceil((y | 0)) >>> 0)) >>> 0))) & ( + (mathy2(( ~ 0x080000000), 0x07fffffff) === Math.cos(( - Math.cosh((y >>> 0))))))); }); testMathyFunction(mathy4, [0x100000001, -(2**53-2), -0x080000001, Number.MIN_SAFE_INTEGER, 1, -(2**53+2), 2**53, -0x07fffffff, -0x100000001, 0x07fffffff, 1/0, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), 0/0, 0x100000000, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, 42, -0x100000000, -1/0, 1.7976931348623157e308, 2**53+2, Math.PI, 0, 0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=620; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(((((( - (Math.hypot(( + (x <= x)), ( + mathy0(( + x), x))) | 0)) | 0) * (mathy1(Math.min(y, -Number.MIN_VALUE), (Math.hypot(1.7976931348623157e308, x) | 0)) ** x)) == ((( + x) - ( ~ (-(2**53+2) === ((((x | 0) ? (2**53-2 | 0) : (-Number.MAX_VALUE | 0)) | 0) ? 0x080000000 : y)))) >>> 0)) >>> 0), (( + Math.tanh(Math.fround((Math.ceil((0/0 | 0)) | 0)))) | 0)); }); testMathyFunction(mathy4, [({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Boolean(true)), 0.1, '0', null, objectEmulatingUndefined(), (new Boolean(false)), (new Number(0)), [0], (function(){return 0;}), undefined, ({valueOf:function(){return 0;}}), /0/, '/0/', '\\0', 0, true, (new Number(-0)), NaN, false, 1, (new String('')), [], -0, '']); ");
/*fuzzSeed-204645237*/count=621; tryItOut("a2 = [];function x(x, y, x = x, this.x, b, a, x = \"\\uE172\", x, b, \u3056, eval, c, x, x, ...this.e)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((i0)))|0;\n  }\n  return f;/*MXX2*/g0.Math.tan = v1;");
/*fuzzSeed-204645237*/count=622; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; bailAfter(354); } void 0; } b1 = new ArrayBuffer(16);");
/*fuzzSeed-204645237*/count=623; tryItOut("if(new RegExp(\"\\u0015\", \"gm\")) {o2.v0 = g2.g1.runOffThreadScript(); }");
/*fuzzSeed-204645237*/count=624; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log(( ! ( - ( ! -(2**53+2))))); }); testMathyFunction(mathy0, [-0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 0x100000000, 1/0, -(2**53-2), -0x080000001, -Number.MAX_VALUE, 0x080000000, -0x07fffffff, -0, 0x100000001, 2**53-2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 0/0, -1/0, 0x0ffffffff, -(2**53), 1.7976931348623157e308, 0, 0x080000001, 1, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, -0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, -0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=625; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((Infinity) <= (+(((0xffffffff)) >> ((0xfd803af0)))))+(0x1747301)))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [undefined, (new Boolean(false)), ({valueOf:function(){return '0';}}), 1, '', (new Boolean(true)), '\\0', null, 0.1, (new String('')), 0, NaN, '0', /0/, ({valueOf:function(){return 0;}}), [0], ({toString:function(){return '0';}}), '/0/', -0, [], (new Number(0)), (new Number(-0)), true, false, objectEmulatingUndefined(), (function(){return 0;})]); ");
/*fuzzSeed-204645237*/count=626; tryItOut("mathy5 = (function(x, y) { return Math.round(( + Math.asin(( + Math.fround(( + Math.fround(x))))))); }); ");
/*fuzzSeed-204645237*/count=627; tryItOut("p2.__iterator__ = SharedArrayBuffer.bind(o2.b0);");
/*fuzzSeed-204645237*/count=628; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var log = stdlib.Math.log;\n  var abs = stdlib.Math.abs;\n  var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (d0);\n    d0 = (d1);\n    d0 = (+/*FFI*/ff(((d1)), ((((0x57a27cc6)) ^ (0xfffff*(0x9ac60df0)))), ((d0)), ((d1)), ((~(((~~(d1)))-(!(/*FFI*/ff(((d0)), ((-513.0)), ((16385.0)), ((1.03125)), ((-16383.0)), ((513.0)), ((2.3611832414348226e+21)), ((-2305843009213694000.0)), ((590295810358705700000.0)), ((1.5)), ((274877906945.0)), ((0.0078125)), ((4.835703278458517e+24)), ((2.4178516392292583e+24)))|0))))), ((d0)), ((NaN))));\n    (Int32ArrayView[((0xfa8f9b48)) >> 2]) = (((0xfdc5ab00) ? (0xffffffff) : ((((0xffffffff))>>>((-0x8000000))) < (0x0)))-(0xf90dacab));\n    {\n      d0 = (((d1)) * ((d0)));\n    }\n    {\n      (Float32ArrayView[4096]) = (((x) ? (d1) : (+(-1.0/0.0))));\n    }\n    d1 = (d1);\n    (Int16ArrayView[(((~(-0xa4962*((((0x32c69aae))>>>((0xc7a7f002)))))))) >> 1]) = ((0x9626f08f)-((0x1707aa10))+(0xffffffff));\n    d1 = (d1);\n    return +((+/*FFI*/ff(((((0x6362902c)-((Uint32ArrayView[(((d0))+(0xfaf0d616)) >> 2]))) | ((0xffffffff)-(0xfd4da701)))), ((d1)), ((~~(+log(((+abs(((d1))))))))), ((((0xffffffff) / (((0xee538478))>>>((0xfc6ed04f)))) << ((0x6280ac1f)*-0x84ae7))), (((Float32ArrayView[2]))), ((((0xfcd36ad8)-(0x3b7bc728)) | (-0xfffff*((0xc7781dcf) > (0xa7a50736))))))));\n    d1 = (d0);\n    d0 = (+ceil(((+/*FFI*/ff((((Uint8ArrayView[((!(0x3471025))*-0xa8f66) >> 0]))))))));\n    d0 = (d1);\n    {\n      d1 = (d1);\n    }\n    {\n      {\n        {\n          d0 = (d0);\n        }\n      }\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: (({ get 0(b = new RegExp(\"(?!(?:[^\\\\u3f47])|(?!(?:.))|\\\\b)^|[^]+[^]+|[^\\\\u24CF-\\\\r]{2}|([]*?)+\", \"yi\")) { \"use strict\"; b2 + ''; }  })).atan()}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[x, 0x40000000, x, 0x40000000, x, function(){}, 0x40000000, 0x40000000, x, new Boolean(false), 0x40000000, function(){}, x, function(){}, new Boolean(false), new Boolean(false), function(){}, function(){}, new Boolean(false), new Boolean(false), function(){}, 0x40000000, new Boolean(false), function(){}, x, function(){}, function(){}]); ");
/*fuzzSeed-204645237*/count=629; tryItOut("\"use asm\"; print((eval(new Object.prototype.__defineSetter__(-7, 4048888443), \"\\u383B\")) <<= +this.throw(true).throw(let (y = /((?:(?=^*.{3}*?)){31})/gyi) undefined));");
/*fuzzSeed-204645237*/count=630; tryItOut("\"use strict\"; /*infloop*/for(var intern(this.__defineSetter__(\"x\"/*\n*/, decodeURI)).x in ((runOffThreadScript)(x))){(window);print(x);for(let d in []);try {  \"\" ; } finally { (z); }  }");
/*fuzzSeed-204645237*/count=631; tryItOut("g0.g0.a0 = Array.prototype.filter.call(o1.a0, (function() { try { neuter(b0, \"same-data\"); } catch(e0) { } e2.has(m1); throw v1; }), a1);");
/*fuzzSeed-204645237*/count=632; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( - ( + ((Math.fround(( ~ (((((( - x) >> ( ! y)) | 0) ? Math.imul(Math.fround(((x | 0) >= (x | 0))), y) : (Math.atan2(y, Math.PI) >>> 0)) >>> 0) | 0))) ** (( ~ (( + (( + ( + ( - y))) <= 0x080000000)) | 0)) | 0)) >>> 0))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 0, Math.PI, -0x100000000, 2**53+2, -0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -0x07fffffff, 0x080000001, 0/0, 0x100000001, 1, -0x100000001, 2**53-2, -(2**53-2), -0x080000001, -0x080000000, 0.000000000000001, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, 42, -(2**53), 0x100000000, -Number.MIN_VALUE, -1/0, 0x0ffffffff, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, -(2**53+2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=633; tryItOut("mathy5 = (function(x, y) { return (mathy1(((( + Math.sin(( + (y || (( + -0) || x))))) === Math.tan(x)) >>> 0), (Math.atan2((Math.min(( + ( ! x)), Math.pow((x ** (x | 0)), y)) | 0), (((Math.asin((((( + y) % (0.000000000000001 ? 0x080000001 : y)) >>> 0) | 0)) | 0) || Math.hypot(x, ( + 0))) >>> 0)) | 0)) - (Math.sin((Math.tanh(( - y)) >>> 0)) | 0)); }); testMathyFunction(mathy5, ['0', undefined, [0], (new Boolean(false)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), [], '\\0', (function(){return 0;}), false, 1, -0, (new Number(0)), true, (new String('')), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), null, '/0/', (new Boolean(true)), '', NaN, (new Number(-0)), /0/, 0, 0.1]); ");
/*fuzzSeed-204645237*/count=634; tryItOut("/*hhh*/function wnbueg(y, y = (this.zzz.zzz = x), \u3056, b = ((function too_much_recursion(umwgos) { ; if (umwgos > 0) { a1 = new Array(26);; too_much_recursion(umwgos - 1); Array.prototype.forEach.apply(a0, [(function() { try { o2.a1.length = (window <<  /x/ ); } catch(e0) { } try { /*MXX1*/o0 = g2.Proxy.length; } catch(e1) { } Array.prototype.splice.call(a1, 13, 4, b0, (++x), x, i2, b1); throw v1; })]); } else {  } s0 += 'x'; })(66934)), x = (z >>> e ? (uneval(eval(\"mathy5 = (function(x, y) { return (Math.log10((Math.log10(( + 0x07fffffff)) | 0)) >>> 0); }); \"))) : let (x, knlufd, window, dltfkg)  /x/g ), x, {valueOf: {x: [, ], x}, d}, w, d, x, b, eval = x, x, x, x, a = true, c, x, x, x =  '' , NaN, NaN =  /x/ , w, y, x, z = window, a, eval, x, e, x, d, x, \u3056, d = \"\u03a0\", window, x = -5, x, z, x, x, x, \u3056, x, e, x, z, a, \u3056, w =  /x/ , eval, x = new RegExp(\"[\\u0017-\\\\u0094]+\", \"y\"), y, e, x, x, z, c, window, w, \u3056, x, x, x, \u3056, c, window, e, d, x, \u3056, \u3056 = 11, e, window, ({/*TOODEEP*/})( \"\" ), z, this.eval, a = -28, x, x, x, y, window, b, ...d){/*tLoop*/for (let e of /*MARR*/[-Infinity, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, eval, eval, -Infinity, eval, eval, eval, -Infinity, eval, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, eval, -Infinity, eval, eval, -Infinity, -Infinity, -Infinity, eval, -Infinity, eval, -Infinity, eval, eval, eval, -Infinity, eval, -Infinity, eval, eval, -Infinity, -Infinity]) { print((makeFinalizeObserver('tenured'))); }v2 = Object.prototype.isPrototypeOf.call(p2, m1);}wnbueg( /x/g );");
/*fuzzSeed-204645237*/count=635; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"m2.has(f1);function c(b, eval) { return false } print(0);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: new function(q) { return q; }(x * undefined >>> x.eval(\"testMathyFunction(mathy1, [-0, 0.000000000000001, -1/0, -Number.MAX_VALUE, -0x07fffffff, 0x080000001, 0, -0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, 2**53+2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), -0x100000000, 0/0, 0x100000001, 42, 2**53-2, 1/0, 0x080000000, 0x100000000, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2)]); \")), noScriptRval: false, sourceIsLazy: true, catchTermination: x++, element: o0, elementAttributeName: s1, sourceMapURL: s1 }));");
/*fuzzSeed-204645237*/count=636; tryItOut("testMathyFunction(mathy2, /*MARR*/[(1/0), 0, function(){}, true, 0, (1/0), true, 0, function(){}, 0, 0, function(){}, true, true, true, 0, true, function(){}, true, function(){}, 0, true, function(){}, (1/0), (1/0), function(){}, function(){}, 0, 0, function(){}, 0, function(){}, true, function(){}, true, true, (1/0), function(){}, true, true, function(){}, (1/0), 0, 0, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0]); ");
/*fuzzSeed-204645237*/count=637; tryItOut("\"use strict\"; h2.getOwnPropertyNames = f1;");
/*fuzzSeed-204645237*/count=638; tryItOut("v0 = evalcx(\"mathy0 = (function(x, y) { return (Math.atan2(Math.fround((( + ((Math.log((( + Math.max(( + ( + Math.max(( + y), ( + x)))), ( + y))) >>> 0)) >>> 0) >>> 0)) >>> 0)), Math.fround(Math.max(( ! Math.fround(Math.max(( + ( ! (y > Math.fround(Math.pow(Math.fround(-0x100000001), 0/0))))), Math.abs(( ! x))))), (Math.fround((Math.fround(( - Math.fround(( + Math.fround(x))))) ? (x ? (Math.hypot(x, (y && Math.fround(0x0ffffffff))) | 0) : Math.sqrt(Math.abs(x))) : Math.fround((( - (((y >>> 0) === (x || Math.fround(( ~ Math.fround(y))))) >>> 0)) >>> 0)))) >>> 0)))) >>> 0); }); testMathyFunction(mathy0, [-(2**53-2), -(2**53), 0, -0x080000000, -(2**53+2), -0x080000001, -Number.MIN_VALUE, 0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, 0x07fffffff, Number.MIN_VALUE, 1, 1.7976931348623157e308, -0x07fffffff, 2**53, 2**53-2, -0, -0x0ffffffff, 1/0, -0x100000001, -Number.MAX_VALUE, -0x100000000, 0x0ffffffff, -1/0, 2**53+2, 0x080000000, 0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE]); \", g2);");
/*fuzzSeed-204645237*/count=639; tryItOut("\"use strict\"; o1 + t2;print(uneval(t2));");
/*fuzzSeed-204645237*/count=640; tryItOut("mathy3 = (function(x, y) { return Math.expm1(( + (Math.imul(Math.atan2(mathy1(( - Math.atanh(y)), Number.MIN_VALUE), ( + Math.min(( + y), ( + y)))), (Math.fround(Math.cosh(Math.fround((x / x)))) >> ( + ( + (( + x) >= ( + x)))))) != Math.log(mathy1(( ~ (mathy0((y | 0), Number.MAX_VALUE) | 0)), (x ? ((x >>> 0) || y) : x)))))); }); testMathyFunction(mathy3, /*MARR*/[new Number(1.5), new Number(1.5), 1.3, 1.3, 1.3, 1.3, new Number(1.5), new Number(1.5), 1.3, new Number(1.5), new Number(1.5), new Number(1.5), 1.3, new Number(1.5), 1.3, new Number(1.5), new Number(1.5), new Number(1.5), 1.3, 1.3, 1.3, 1.3, new Number(1.5), 1.3, new Number(1.5), 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, new Number(1.5), new Number(1.5), new Number(1.5), 1.3, 1.3, 1.3, 1.3, new Number(1.5), 1.3, new Number(1.5), new Number(1.5), new Number(1.5), 1.3, new Number(1.5), 1.3, 1.3, new Number(1.5), new Number(1.5), new Number(1.5), 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, new Number(1.5), 1.3, new Number(1.5), new Number(1.5), 1.3, new Number(1.5), new Number(1.5), 1.3, 1.3, 1.3, 1.3, new Number(1.5), new Number(1.5), 1.3, new Number(1.5), 1.3]); ");
/*fuzzSeed-204645237*/count=641; tryItOut("\"use strict\"; \"use asm\"; /*bLoop*/for (gqdfxl = 0, [{}] = ((null.yoyo(/(?!\\cB)|$*|\\\u2b90*^*|[^]|\\B(?=\\1)\u4f72|(?=.|(?=[^]?\\x95){0,4})/))).call(((p={}, (p.z = true)())), ); gqdfxl < 17; ++gqdfxl) { if (gqdfxl % 3 == 1) { /*oLoop*/for (let iuexrn = 0; iuexrn < 35; false, ++iuexrn) { print(x); }  } else { /*RXUB*/var r = new RegExp(\"(?!(([^\\\\s\\\\w\\\\cA-\\\\u0090L])|$*$|\\\\B\\\\1|\\\\b)){4,}(?=.(?:((?![^]|\\\\S)))){2,}\", \"gi\"); var s = \" 1a\\n\\n 1a 1a 1a 1a\"; print(r.exec(s)); print(r.lastIndex);  }  } ");
/*fuzzSeed-204645237*/count=642; tryItOut("Object.defineProperty(this, \"h1\", { configurable: (x % 6 != 2), enumerable: Math.max(z = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { return undefined }, set: Function.prototype, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( \"\" ), function (z) { yield print(true) } ), /*FARR*/[].sort(/*wrap2*/(function(){ var ewsltu = this; var altklq = Uint32Array; return altklq;})(), new RegExp(\"\\\\3(\\\\w(?:^).)|(?=\\\\u00AE|(?=$))+?\\\\b|^*?\", \"\"))),  get: function() {  return {}; } });");
/*fuzzSeed-204645237*/count=643; tryItOut("t0.set(g0.t2, 16);m2.toString = Object.getOwnPropertyDescriptor.bind(f2);");
/*fuzzSeed-204645237*/count=644; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=645; tryItOut("/*oLoop*/for (xmsgjl = 0; xmsgjl < 94; ++xmsgjl) { print(y);y = Math.atan2(this, \"\\uF6BC\"); } ");
/*fuzzSeed-204645237*/count=646; tryItOut("v2 = Object.prototype.isPrototypeOf.call(a2, i2);");
/*fuzzSeed-204645237*/count=647; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use asm\"; return (((Math.fround((( - ( + (Math.trunc(Math.fround(x)) + Math.fround(y)))) != Math.fround(( ~ Math.fround(Math.asinh(y)))))) | 0) << mathy2(( + Math.imul(( + (((y >>> 0) ? (y >>> 0) : (( - x) | 0)) >>> 0)), mathy2(y, -0x100000001))), (( ~ x) >>> 0))) <= ((Math.ceil(Math.fround(Math.clz32(x))) >>> 0) ? Math.fround(Math.min(x, Math.pow((Math.log10((y >>> 0)) >>> 0), Math.imul(Math.fround(Math.max(mathy2(y, x), 0x0ffffffff)), ( + (y ? y : x)))))) : Math.fround((( + ((Math.abs(y) >>> 0) !== Number.MIN_VALUE)) ^ ( + (Math.min((y | 0), (( + (x | x)) | 0)) | 0)))))); }); testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), -0, false, (new Boolean(false)), undefined, 0, (new Number(-0)), (new String('')), null, '\\0', '/0/', '0', NaN, 0.1, true, /0/, (new Number(0)), (new Boolean(true)), (function(){return 0;}), ({toString:function(){return '0';}}), 1, objectEmulatingUndefined(), [], ({valueOf:function(){return '0';}}), '', [0]]); ");
/*fuzzSeed-204645237*/count=648; tryItOut("{ void 0; void gc(); } print(x);");
/*fuzzSeed-204645237*/count=649; tryItOut("\"use strict\"; m2 = new WeakMap;");
/*fuzzSeed-204645237*/count=650; tryItOut("\"use strict\"; m0 + o0.v1;");
/*fuzzSeed-204645237*/count=651; tryItOut("/*RXUB*/var r = /\\2/ym; var s = \"0\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=652; tryItOut("f1.toString = (function() { try { for (var v of e1) { /*MXX2*/g1.RegExp.prototype.sticky = e2; } } catch(e0) { } try { this.a0.sort((function(j) { f1(j); }), f0, b0, g1, p1, this.t1, t1, m1); } catch(e1) { } v0 = Object.prototype.isPrototypeOf.call(e0, t2); return b2; });");
/*fuzzSeed-204645237*/count=653; tryItOut("mathy4 = (function(x, y) { return Math.atanh(((Math.cosh(( ~ ( - y))) | 0) || (( + Math.fround(Math.fround(Math.sqrt(((mathy3(((0x0ffffffff <= (Number.MIN_VALUE >>> 0)) >>> 0), Number.MAX_VALUE) >>> 0) | 0))))) | 0))); }); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), [0], 1, (new Number(0)), '\\0', [], /0/, '/0/', undefined, (new String('')), 0.1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 0, (new Boolean(false)), null, true, '0', (new Number(-0)), '', false, NaN, (function(){return 0;}), -0, (new Boolean(true)), objectEmulatingUndefined()]); ");
/*fuzzSeed-204645237*/count=654; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy1((( ~ (Math.imul(((Math.tanh(y) | 0) | 0), (( ! x) | 0)) | 0)) >= ( + y)), ((((Math.fround((Math.fround((mathy3((y >>> 0), y) >>> 0)) ^ mathy1(( + Math.hypot(-(2**53), x)), x))) >>> 0) >>> (((0x0ffffffff >>> 0) , ( + x)) >>> 0)) >>> 0) % Math.atan2(-1/0, (Math.cos((y >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x100000001, -0x080000001, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, 2**53-2, -0x100000000, -(2**53+2), -0x080000000, -0x100000001, -1/0, -0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, 42, Math.PI, -(2**53), 0.000000000000001, -0x07fffffff, 0, 0x0ffffffff, Number.MAX_VALUE, 0x080000001, -0, 0x07fffffff, 2**53, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-204645237*/count=655; tryItOut("\"use strict\"; m0.delete(s1);");
/*fuzzSeed-204645237*/count=656; tryItOut("mathy5 = (function(x, y) { return (( + mathy3(( + Math.min((Math.imul(Math.hypot((((x | 0) / (x >>> 0)) | 0), y), mathy0(Math.fround(x), x)) >>> 0), (( + Math.expm1((x | 0))) >>> 0))), ( + (( ! ((Math.tanh((x >>> 0)) | 0) >>> 0)) >>> 0)))) != Math.fround(( ! ( + ( + ( + (x % mathy3(y, (x | 0x100000001))))))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, 0x080000001, -0x100000000, 1/0, -(2**53-2), -1/0, 1.7976931348623157e308, 1, -0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_VALUE, 42, 2**53-2, -0, -0x0ffffffff, 0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 0x100000001, 0x0ffffffff, 0/0, -(2**53), Math.PI, -Number.MIN_VALUE, 0, -0x07fffffff, 2**53]); ");
/*fuzzSeed-204645237*/count=657; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=658; tryItOut("f1(m0);");
/*fuzzSeed-204645237*/count=659; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=660; tryItOut("/*RXUB*/var r = new RegExp(\"((?:\\\\b|.+))(?=(^|\\\\1[^]))*?|.\", \"g\"); var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-204645237*/count=661; tryItOut("var hpernr = new ArrayBuffer(2); var hpernr_0 = new Int8Array(hpernr); o0 = e0.__proto__;");
/*fuzzSeed-204645237*/count=662; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( ! Math.tanh(y)) | 0) ? (( + mathy3((Math.min((x | 0), (Math.clz32(Math.atan2(( + Math.fround(Math.clz32(x))), x)) | 0)) | 0), (( + Math.hypot(Math.asinh(( + (( + ( + 2**53)) >>> 0))), Math.fround(x))) >>> 0))) | 0) : ((((mathy2(y, Math.fround((Math.fround(-(2**53+2)) !== Math.fround(y)))) | 0) * Math.fround((Math.log((Math.expm1((Math.fround((Math.min(0, Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)) >>> 0)) != mathy3(((y ? (x >>> 0) : (y >>> 0)) >>> 0), y)))) | 0) | 0)); }); ");
/*fuzzSeed-204645237*/count=663; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    switch ((((/*FFI*/ff(((1.5111572745182865e+23)), ((-8192.0)))|0)-(0x282fe47b)) << (((0xb20bd81c))*0x60172))) {\n      case -1:\n        d1 = ((d0) + ());\n        break;\n    }\n    d0 = (d0);\n    return (((0xffc90040)))|0;\n  }\n  return f; })(this, {ff: String.prototype.localeCompare}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1/0, -1/0, 0x100000000, 0x100000001, -0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, 0, 2**53, 0/0, 2**53+2, Number.MIN_VALUE, -0, -0x0ffffffff, 2**53-2, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), 1, -Number.MIN_VALUE, 42, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 0x080000000, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=664; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var floor = stdlib.Math.floor;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1.00390625;\n    d2 = (+log((((+floor(((d0)))) + (+(-1.0/0.0))))));\n    d2 = (d0);\n    d0 = (-((d0)));\n    d0 = (-4.835703278458517e+24);\n    (Int16ArrayView[2]) = (-0xc6e93*(0xffffffff));\n    (Uint32ArrayView[(((((!(i1)))>>>(((0xffffffff)))))) >> 2]) = ((0xffb60f24)+(0xffffffff));\n    d2 = (d2);\n    i1 = ((((+((+(0.0/0.0)))))) ? (-0x8000000) : (i1));\n    d0 = (d2);\n    i1 = (0x85f54414);\n    d0 = (+((d2)));\n    return (((((~~(Infinity)))>>>(((((0xf873b217)) & ((0xfe340388)*0xfffff)) <= (((0x582158fd) / (0x2dcf0967)) << ((i1)))))) % (((i1))>>>(((d2) > (-9.0))*0x3f33e))))|0;\n  }\n  return f; })(this, {ff: (new Function(\"for (var v of m2) { try { this.g2.offThreadCompileScript(\\\"e2.has(h0);\\\"); } catch(e0) { } try { a2.sort(Date.prototype.setUTCMinutes.bind(h2), f1); } catch(e1) { } try { v2 = -Infinity; } catch(e2) { } v0.valueOf = f0; }\"))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=665; tryItOut("try { let(b) ((function(){let(e =  '' , z = window, mlmuzu, a, dkgecq, a, \u3056, bjdsii, gafiuy, ghlhvj) ((function(){let(b = window, uvyaqi) ((function(){return  \"\" ;})());})());})()); } catch(c if  /x/g  & this) { return \"\\u9503\"; } catch(c) { throw StopIteration; } finally { for(let w in []); } for(let w in /*FARR*/[w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: (/*wrap2*/(function(){ \"use strict\"; var xawuhr = \"\\uC028\"; var imnvkk = decodeURI; return imnvkk;})()).apply, getPropertyDescriptor: undefined, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: /*wrap3*/(function(){ var qgmpix = -8; (\"\\uA3C2\")(); }), get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })( '' ), String.prototype.split, /*wrap2*/(function(){ var klidxb = 1371973067; var oqetjb = Date.parse; return oqetjb;})()), x, , .../*FARR*/[(\"-5\" = x)], \"\\u135D\", .../*MARR*/[x, 2**53-2, x, x, -Infinity,  \"use strict\" , x,  \"use strict\" , -Infinity, x, 2**53-2, x, 2**53-2, x, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2,  \"use strict\" ,  \"use strict\" , x, -Infinity, -Infinity, -Infinity,  \"use strict\" , x, 2**53-2, x, 2**53-2, x,  \"use strict\" , 2**53-2, -Infinity, x, -Infinity, -Infinity, x, -Infinity, x, -Infinity, x,  \"use strict\" , 2**53-2,  \"use strict\" , 2**53-2, -Infinity, -Infinity, -Infinity, 2**53-2, x], , \"\\uA84A\", .../*MARR*/[ \"\" , x = window, x = window, 0x080000000, x = window, x = window, [(void 0)], x = window, (1/0), 0x080000000,  \"\" ,  \"\" , [(void 0)], (1/0), x = window, x = window,  \"\" , [(void 0)], 0x080000000, (1/0),  \"\" , [(void 0)], (1/0), [(void 0)], x = window, 0x080000000, (1/0), 0x080000000, [(void 0)], x = window, (1/0), 0x080000000,  \"\" , (1/0), x = window, 0x080000000, [(void 0)], [(void 0)],  \"\" , (1/0),  \"\" , 0x080000000,  \"\" , 0x080000000,  \"\" ,  \"\" , [(void 0)], (1/0),  \"\" ,  \"\" , (1/0), 0x080000000, x = window, x = window, (1/0), [(void 0)], (1/0), 0x080000000,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 0x080000000, x = window, [(void 0)],  \"\" , 0x080000000, (1/0), (1/0), (1/0), (1/0), 0x080000000, (1/0), 0x080000000, x = window, 0x080000000, (1/0), 0x080000000, 0x080000000, x = window, 0x080000000, 0x080000000, x = window, (1/0), [(void 0)], x = window,  \"\" , x = window, 0x080000000, 0x080000000, (1/0), x = window, (1/0), x = window,  \"\" , x = window, 0x080000000, (1/0), 0x080000000, [(void 0)], [(void 0)], [(void 0)],  \"\" , 0x080000000, (1/0), x = window, x = window, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), 0x080000000, x = window], ([((x = \"\\u9D6C\"))]), this, Int16Array(x), x, (4277), x ^ /*UUV2*/(x.fromCodePoint = x.toString) > z.unwatch(\"toString\"), ]) with({}) let(\u3056, NaN = x ? null : false, e = ((function fibonacci(njbcvq) { Array.prototype.splice.call(a0, NaN, 4, v0);; if (njbcvq <= 1) { v2 = false;; return 1; } ; return fibonacci(njbcvq - 1) + fibonacci(njbcvq - 2); Object.preventExtensions(g1.i2); })(4)), w = \"\\u0BBD\") ((function(){let(c, {} = Date.prototype.toTimeString(-25), xmuzvg, x) ((function(){with({}) { v0 = t2.length; } })());})());");
/*fuzzSeed-204645237*/count=666; tryItOut("mathy5 = (function(x, y) { return (Math.atan2((Math.fround(( - Math.fround((mathy2(Math.atanh(-Number.MAX_SAFE_INTEGER), ((((y ? x : -(2**53-2)) >>> 0) || ( + Math.atan2(y, ( - (x * x))))) >>> 0)) | 0)))) >>> 0), (((x << (( - Number.MAX_SAFE_INTEGER) >>> 0)) !== ((( ! mathy4(-(2**53+2), Number.MIN_VALUE)) | 0) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy5, [Math.PI, -0x080000000, 2**53+2, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -0x07fffffff, 1, -(2**53-2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, 0x080000001, 2**53, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, 0x080000000, -Number.MIN_VALUE, -0x080000001, -1/0, -0x100000000, 1.7976931348623157e308, 0x100000001, -0x0ffffffff, -(2**53+2), Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 0, -0, 0x07fffffff, 1/0]); ");
/*fuzzSeed-204645237*/count=667; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 2097152.0;\n    var d3 = -4.835703278458517e+24;\n    return ((((+atan(((d2)))))))|0;\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; print(timeout(1800)); }}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000000, 0/0, -1/0, 0, Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, 2**53-2, 0x080000000, 0.000000000000001, 1, 0x07fffffff, 0x0ffffffff, -(2**53+2), -0x080000000, -0x100000001, 2**53+2, Math.PI, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 0x080000001, 42, -Number.MAX_VALUE, -0, -(2**53), Number.MIN_VALUE, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=668; tryItOut("mathy2 = (function(x, y) { return (Math.max(((( - Math.fround(Math.trunc(-0))) >>> 0) >>> 0), (( ~ ( - y)) >>> 0)) | 0); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0.000000000000001, 1, -0x100000000, -1/0, -0x080000001, 0x100000001, -(2**53), 0x080000001, -0x080000000, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 2**53, 2**53-2, -(2**53+2), 42, -0, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 1/0, Math.PI, 0x100000000, 0/0, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=669; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.clz32((Math.log((( + ( ! ( + Math.atan(Math.pow((y > y), y))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy1, [/0/, (new String('')), [], '', ({valueOf:function(){return 0;}}), (new Boolean(false)), false, 1, ({toString:function(){return '0';}}), objectEmulatingUndefined(), null, '/0/', 0.1, [0], undefined, '0', ({valueOf:function(){return '0';}}), (function(){return 0;}), true, '\\0', (new Boolean(true)), (new Number(0)), (new Number(-0)), 0, NaN, -0]); ");
/*fuzzSeed-204645237*/count=670; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.fround(Math.fround(Math.atan2((( ! (Math.atanh(( + Math.max((x >>> 0), (mathy3((y >>> 0), (y >>> 0)) >>> 0)))) >>> 0)) | 0), Math.fround((Math.fround((Math.min(((( - ( - ( + x))) ? (mathy0(x, x) >>> 0) : y) >>> 0), (y >>> 0)) >>> 0)) | Math.fround(( - Math.fround(-0x080000000))))))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, Number.MAX_VALUE, -0x07fffffff, 2**53-2, 1, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, 0, -0, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, 0x0ffffffff, 0x080000000, -0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, -0x080000001, -0x100000001, -0x0ffffffff, 0x080000001, 0x100000001, Number.MIN_VALUE, 0x100000000, -(2**53+2), 2**53, 1/0]); ");
/*fuzzSeed-204645237*/count=671; tryItOut("a2.push(o0.b1, v2, m1, t1, g1, t1, b0, i2, b1);");
/*fuzzSeed-204645237*/count=672; tryItOut("m0.delete(e1);");
/*fuzzSeed-204645237*/count=673; tryItOut("\"use strict\"; \"use asm\"; g0.offThreadCompileScript(\"v0 = v0[\\\"link\\\"];\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (void shapeOf( /x/ )), noScriptRval: (x % 5 != 1), sourceIsLazy: false, catchTermination: false, element: o1 }));");
/*fuzzSeed-204645237*/count=674; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.pow(Math.fround((Math.cbrt((x >>> 0)) ^ Math.max(( + ( ~ x)), -(2**53)))), (Math.hypot(( + ( ! (( ! (x >>> 0)) >>> 0))), ( + Math.imul((Math.atan2(( + x), (-Number.MIN_SAFE_INTEGER | 0)) | 0), x))) | 0)) >> (((( + Math.pow(( + -0x080000001), ((( ! y) >>> 0) > ( - (mathy1(x, ( + x)) >>> 0))))) >>> 0) ? (( ! (Math.imul(( + (x >>> (( ~ (x >>> 0)) >>> 0))), y) | 0)) / x) : (mathy0(Math.sinh((y >> x)), (Math.fround(((0x07fffffff >> x) ? (( + (2**53+2 >>> 0)) >>> 0) : Math.fround(( + Math.fround(y))))) | 0)) >>> 0)) | 0)); }); testMathyFunction(mathy2, [-1/0, Math.PI, -(2**53-2), -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 0, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, 1/0, 0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), -Number.MIN_VALUE, -0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 42, -(2**53), 0x07fffffff, 1, 0x100000000, 2**53, 0/0, -0x0ffffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=675; tryItOut("h1.getOwnPropertyDescriptor = (function(j) { if (j) { s2 += 'x'; } else { try { i2.toString = (function() { for (var p in g2.i0) { try { a0.splice(NaN, 10); } catch(e0) { } g0.v0 = (p2 instanceof e2); } return g0; }); } catch(e0) { } try { Array.prototype.sort.apply(o2.a1, [(function(j) { f2(j); })]); } catch(e1) { } s2 += s1; } });");
/*fuzzSeed-204645237*/count=676; tryItOut("v1 = undefined;");
/*fuzzSeed-204645237*/count=677; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"y\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=678; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy1((Math.log2(Math.fround((-0x07fffffff <= Math.fround(x)))) >>> 0), (( + Math.clz32(( + ( + Math.pow(Math.trunc(Math.imul(y, x)), (x ? Math.log(Math.fround(Math.log10(y))) : -0x0ffffffff)))))) >>> 0)); }); testMathyFunction(mathy3, [-0x0ffffffff, 0, 0x100000001, -0x100000000, -(2**53), -Number.MAX_VALUE, -0x07fffffff, 1, 0x100000000, 1.7976931348623157e308, Math.PI, -0, 1/0, -0x080000001, 0x0ffffffff, 0x080000001, -0x080000000, 2**53-2, -(2**53+2), -(2**53-2), 0x080000000, 0.000000000000001, Number.MAX_VALUE, 0x07fffffff, 2**53, -0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 42, -Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=679; tryItOut("");
/*fuzzSeed-204645237*/count=680; tryItOut("\"use strict\"; v2 = Infinity;");
/*fuzzSeed-204645237*/count=681; tryItOut("\"use strict\"; g2.e0.delete(s1);");
/*fuzzSeed-204645237*/count=682; tryItOut("m1 = new WeakMap;");
/*fuzzSeed-204645237*/count=683; tryItOut("\"use strict\"; m2.has(s0);");
/*fuzzSeed-204645237*/count=684; tryItOut("\"use strict\"; v1 = r2.sticky;");
/*fuzzSeed-204645237*/count=685; tryItOut("/*bLoop*/for (alzutc = 0, c; alzutc < 163; ++alzutc) { if (alzutc % 10 == 7) { Array.prototype.pop.call(g2.a1); } else { v1 = t1.length; }  } ");
/*fuzzSeed-204645237*/count=686; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.log1p(( + Math.max(Math.pow((x != (y - -0)), Math.fround(( ! x))), y)))); }); testMathyFunction(mathy4, [(new Boolean(true)), (function(){return 0;}), (new Boolean(false)), /0/, '/0/', undefined, true, (new Number(0)), (new String('')), ({toString:function(){return '0';}}), 0.1, NaN, null, '\\0', 1, ({valueOf:function(){return 0;}}), '0', [0], objectEmulatingUndefined(), false, '', 0, -0, ({valueOf:function(){return '0';}}), (new Number(-0)), []]); ");
/*fuzzSeed-204645237*/count=687; tryItOut("a2.shift();");
/*fuzzSeed-204645237*/count=688; tryItOut("\"use strict\"; e1.has(x);");
/*fuzzSeed-204645237*/count=689; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy0(Math.min(Math.tan(((2**53-2 >>> 0) ? y : Math.pow(y, (Math.fround(y) ? Number.MIN_VALUE : x)))), Math.fround(mathy2(Math.fround(y), Math.fround(Math.fround((-1/0 * ( + ( - Math.fround(y))))))))), (( - ((mathy0(Number.MIN_VALUE, (((y >>> 0) - (x >>> 0)) | 0)) || y) | 0)) | 0)); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), (function(){return 0;}), 0.1, (new Boolean(true)), [], false, '\\0', true, (new Number(-0)), '', NaN, objectEmulatingUndefined(), ({toString:function(){return '0';}}), 0, (new Number(0)), ({valueOf:function(){return '0';}}), (new Boolean(false)), /0/, 1, -0, undefined, '0', [0], null, '/0/', (new String(''))]); ");
/*fuzzSeed-204645237*/count=690; tryItOut("a1.forEach((function() { for (var j=0;j<96;++j) { f1(j%5==0); } }));");
/*fuzzSeed-204645237*/count=691; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return ( + mathy0(( + Math.log2((( ~ Math.fround(Math.atanh((Math.hypot((x >>> 0), (Math.max(((mathy2((y >>> 0), Math.fround(y)) >>> 0) >>> 0), x) >>> 0)) >>> 0)))) >>> 0))), Math.sqrt(( + Math.ceil(( + ((y >>> 0) == ( + (Math.imul(y, x) | 0))))))))); }); testMathyFunction(mathy3, [-0x080000000, Number.MIN_VALUE, 0.000000000000001, Math.PI, 0x080000000, 1.7976931348623157e308, 2**53-2, 0/0, Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, 1, -(2**53-2), -0x07fffffff, -0, -(2**53+2), Number.MAX_VALUE, -1/0, 2**53+2, 1/0, 0x0ffffffff, 0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, -0x100000001, -(2**53), 0x100000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=692; tryItOut("\"use strict\"; o0 + '';");
/*fuzzSeed-204645237*/count=693; tryItOut("(x);");
/*fuzzSeed-204645237*/count=694; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! Math.tanh((Math.min(((mathy2(((( ~ 0x080000000) >>> 0) | 0), (-Number.MAX_VALUE | 0)) | 0) | 0), (y | 0)) | 0))); }); ");
/*fuzzSeed-204645237*/count=695; tryItOut("\"use strict\"; /*vLoop*/for (var ridhuu = 0; (('fafafa'.replace(/a/g, new Function))) && ridhuu < 53; ++ridhuu) { let z = ridhuu; o0.p1.__proto__ = o1.h2; } ");
/*fuzzSeed-204645237*/count=696; tryItOut("\"use strict\"; h1 = {};");
/*fuzzSeed-204645237*/count=697; tryItOut("const x = (([] = x)), a, NaN = (Math.pow(-26, 14)), x, NaN = x, z = (\u3056) = \"\\u7B2E\", \u3056 = this.yoyo(\"\\u1ED2\"), bvpqmn;a1.reverse();");
/*fuzzSeed-204645237*/count=698; tryItOut("var zxrghf = new ArrayBuffer(16); var zxrghf_0 = new Uint32Array(zxrghf); zxrghf_0[0] = -0; var zxrghf_1 = new Float32Array(zxrghf); zxrghf_1[0] = 11; {}");
/*fuzzSeed-204645237*/count=699; tryItOut("\"use strict\"; /*vLoop*/for (let csfivj = 0; (Math.fround.prototype) && csfivj < 26; ++csfivj) { let d = csfivj; v1 = t1.BYTES_PER_ELEMENT; } ");
/*fuzzSeed-204645237*/count=700; tryItOut("s1.toString = f1;");
/*fuzzSeed-204645237*/count=701; tryItOut("if((x % 2 != 1)) { if ((makeFinalizeObserver('nursery'))) yield;} else print( '' );");
/*fuzzSeed-204645237*/count=702; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=703; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ( ! (({}.yoyo(15)) >>> 0))); }); ");
/*fuzzSeed-204645237*/count=704; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (((Math.acos(Math.tanh(y)) >= ((( ! (Math.cos(x) >>> 0)) >>> 0) >>> 0)) >>> 0) | ( + Math.abs(Math.hypot(Math.fround((Math.fround(y) ^ Math.fround(y))), ( + (( + (((Math.atan2((x >>> 0), (0/0 >>> 0)) >>> 0) | 0) ? Math.fround(( + -(2**53))) : ( + y))) | (x & ( ~ -(2**53)))))))))); }); ");
/*fuzzSeed-204645237*/count=705; tryItOut("h1.get = (function() { for (var j=0;j<53;++j) { f1(j%5==0); } });");
/*fuzzSeed-204645237*/count=706; tryItOut("mathy0 = (function(x, y) { return Math.fround(((( + (( ~ y) | 0)) | 0) !== ((Math.fround(Math.hypot(Math.fround(( ~ ( + (( + x) ^ ( + Math.max(( + 0.000000000000001), y)))))), (( + Math.atanh(Math.fround(x))) ** ( + Math.fround(Math.imul(0x0ffffffff, Math.atan(Math.max(x, y)))))))) >>> 0) > (Math.fround((Math.fround(Math.atanh(y)) << Math.fround((Math.expm1(x) ? x : Math.fround(( ~ Math.log1p(x))))))) >>> 0)))); }); testMathyFunction(mathy0, [-0x080000000, 0, 0x080000001, Math.PI, 0x100000000, -Number.MIN_VALUE, -1/0, -(2**53), 1, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0x080000000, -(2**53-2), -0x100000001, 1.7976931348623157e308, 0x100000001, -0x07fffffff, Number.MAX_VALUE, 2**53+2, 0x07fffffff, 1/0, -0x100000000, 0x0ffffffff, 0.000000000000001, 42, 0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=707; tryItOut("\"use strict\"; let x = undefined, mzpsgo, kmzwqx, d, x, sivkyv, czpjla, erlwsw;Object.seal(a1);");
/*fuzzSeed-204645237*/count=708; tryItOut("mathy1 = (function(x, y) { return ((((( - ((Math.fround(Math.imul(Math.fround(-0x100000001), Math.fround(-(2**53-2)))) ? x : Math.hypot(Math.fround((Math.fround(y) >>> Math.fround(Math.cos(x)))), x)) >>> 0)) >>> 0) >>> 0) ^ ( + ( ~ Math.fround(Math.log10(Math.fround(Math.min(Math.fround(x), Math.fround(( ! x))))))))) || ((Math.max((Number.MIN_SAFE_INTEGER ? y : x), ((-(2**53-2) >= Number.MAX_SAFE_INTEGER) | 0)) << Math.log((Math.sqrt(Math.fround((Math.fround(y) || Math.fround(y)))) >>> 0))) >>> 0)); }); testMathyFunction(mathy1, [-0x080000001, -Number.MIN_VALUE, -(2**53-2), 1/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -0, -0x100000001, 0x07fffffff, Number.MAX_VALUE, -0x100000000, 1, 0x100000000, 0x080000000, -0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 42, 0, Math.PI, 2**53, 2**53-2, 2**53+2, 0x100000001, -1/0, -(2**53), Number.MIN_VALUE, 0x080000001, 0.000000000000001, 0/0, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=709; tryItOut("/*ODP-2*/Object.defineProperty(i2, \"1\", { configurable: true, enumerable: false, get: (function mcc_() { var iqvmbw = 0; return function() { ++iqvmbw; if (/*ICCD*/iqvmbw % 11 == 8) { dumpln('hit!'); try { for (var p in a0) { try { t0.set(t2, ({valueOf: function() { a1 = Array.prototype.slice.call(a0, -4, NaN);return 6; }})); } catch(e0) { } try { t1.set(t2, 13); } catch(e1) { } try { o2.v1 = Object.prototype.isPrototypeOf.call(a1, o1); } catch(e2) { } Object.prototype.watch.call(g1, \"-6\", (function() { for (var j=0;j<38;++j) { g1.f0(j%3==1); } })); } } catch(e0) { } const a0 = new Array; } else { dumpln('miss!'); try { for (var p in i1) { try { h2.hasOwn = (function() { for (var j=0;j<0;++j) { f1(j%5==0); } }); } catch(e0) { } o1.m0.has(a1); } } catch(e0) { } a2.pop(b0, i2, g0, f1, v0, b0, s0); } };})(), set: (function() { try { a0.push(o1.g2.t0, e2); } catch(e0) { } Array.prototype.forEach.call(a1, (function() { a1.forEach((function() { try { o2 + ''; } catch(e0) { } try { s0 = new String; } catch(e1) { } try { ; } catch(e2) { } e2.add(b0); return o0.p2; })); return e0; })); throw g1; }) });");
/*fuzzSeed-204645237*/count=710; tryItOut("mathy0 = (function(x, y) { return (( - (Math.expm1(( - Math.hypot((Math.fround(Math.pow((x ^ Math.abs(y)), y)) >>> 0), ( + 0)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-204645237*/count=711; tryItOut("s1 = new String(m1);");
/*fuzzSeed-204645237*/count=712; tryItOut("a1.pop(this.o1);");
/*fuzzSeed-204645237*/count=713; tryItOut("h0.toString = (function mcc_() { var flzgql = 0; return function() { ++flzgql; f0(false);};})();\nv1 = evaluate(\"t2[16] = x;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: (4277) }));\n");
/*fuzzSeed-204645237*/count=714; tryItOut("\"use strict\"; L: {mhatgc();/*hhh*/function mhatgc(){a0.push(e1, b0, a2);}/*RXUB*/var r = this; var s = \"\"; print(s.search(r));  }");
/*fuzzSeed-204645237*/count=715; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.imul((( ~ ((( + (( + ( ! y)) | 0)) | 0) >>> 0)) >>> 0), Math.fround((Math.imul(x, ( ! Math.imul((0x080000001 - (( ~ y) | 0)), (Math.fround((y > Math.fround(y))) >>> 0)))) , ( ~ ((Math.imul((x >= x), Math.log1p(Math.fround(mathy0(x, Math.fround(x))))) >>> 0) * x)))))); }); ");
/*fuzzSeed-204645237*/count=716; tryItOut("v1 = new Number(o1.a1);");
/*fuzzSeed-204645237*/count=717; tryItOut("this.e2.add(this.v2);t2.set(a1, 15);v1 = (i2 instanceof i1);");
/*fuzzSeed-204645237*/count=718; tryItOut("Array.prototype.forEach.apply(a1, [(function(j) { if (j) { try { p0.toString = (function mcc_() { var sonpcx = 0; return function() { ++sonpcx; if (true) { dumpln('hit!'); try { this.v1 = Object.prototype.isPrototypeOf.call(g2, g1.e2); } catch(e0) { } try { v2 = (t1 instanceof o1); } catch(e1) { } this.g0.toSource = (function(j) { f0(j); }); } else { dumpln('miss!'); this.v2 = g0.eval(\"function f1(p1) \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    var i3 = 0;\\n    var d4 = -1.0078125;\\n    var d5 = -17592186044416.0;\\n    var i6 = 0;\\n    var i7 = 0;\\n    d5 = (((((i1)) ^ ((Uint16ArrayView[((i2)-(i3)) >> 1])))) * ((+(((0xbac62f3b))>>>((imul((i3), ((0x5f3c7e48) != (0x50c08950)))|0) / (((0xae8cb07b)+(0x48a46a81)+(0xffffffff)) ^ ((0xf468b77c)+(0xc971e4a3))))))));\\n    return (((Uint16ArrayView[4096])))|0;\\n    return (((0xfda93c9e)))|0;\\n  }\\n  return f;\"); } };})(); } catch(e0) { } try { i1 + ''; } catch(e1) { } a0.unshift(g1, this.o1.f0); } else { try { s1 = ''; } catch(e0) { } v1 = new Number(a1); } }), f0, o2.g0, s0]);");
/*fuzzSeed-204645237*/count=719; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.hypot((Math.asinh(Math.fround(mathy0(Math.fround(y), Math.fround(Math.asin(y))))) | 0), ( + Math.acos((Math.hypot(((Math.hypot(y, ((Math.cos((-0x080000000 | 0)) >>> 0) | 0)) | 0) | 0), (y | 0)) | 0))))); }); testMathyFunction(mathy2, [-(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 0, -0, 1, -0x080000000, 2**53+2, 1/0, 0x100000001, -0x100000001, -(2**53), -0x07fffffff, 0.000000000000001, 0/0, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, 0x100000000, -(2**53-2), -0x100000000, -1/0, 0x080000000, 1.7976931348623157e308, 42, -Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=720; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (Math.min(Math.fround(Math.fround((y << Math.fround(( + y))))), Math.fround((Math.tan((-0x080000000 | 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy0, [null, 0, '\\0', '/0/', -0, /0/, NaN, (new String('')), [], (new Number(-0)), ({toString:function(){return '0';}}), 0.1, '', (new Number(0)), (new Boolean(false)), (function(){return 0;}), undefined, ({valueOf:function(){return '0';}}), false, [0], '0', objectEmulatingUndefined(), (new Boolean(true)), 1, ({valueOf:function(){return 0;}}), true]); ");
/*fuzzSeed-204645237*/count=721; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy0(Math.atan2((Math.max((Math.cosh(( + (( + mathy1(x, y)) << ( + 0x07fffffff)))) | 0), (mathy0(Math.fround(y), Math.fround(Math.trunc(Math.hypot(y, x)))) >>> 0)) | 0), ( + Math.tan(Math.imul(Math.trunc(y), Math.fround(mathy1(Math.fround(y), Math.fround(( + Math.hypot(y, ( + Math.atan2((y >>> 0), ( + x)))))))))))), ( + ( + (Math.max(Math.hypot(( + -Number.MIN_SAFE_INTEGER), ( + ( + mathy1(Math.fround(x), ( + Math.atan2(x, x)))))), Math.log10(Math.fround((x ? y : x)))) >>> 0)))) >>> 0); }); testMathyFunction(mathy2, [-(2**53+2), -0x100000000, 42, -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 2**53, Number.MIN_VALUE, Math.PI, -(2**53), 2**53-2, -Number.MIN_VALUE, -0, 1/0, 0.000000000000001, 0x080000001, 0x080000000, 0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, 0x0ffffffff, -1/0, Number.MAX_VALUE, -0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, 1, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001]); ");
/*fuzzSeed-204645237*/count=722; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.abs((( + Math.trunc(( + (Math.hypot(( + Math.max(Math.fround(y), Math.fround(0x100000001))), (y | 0)) | 0)))) + ((( + (Math.log2(( + Math.atan2(( + Math.PI), ( + x)))) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy2, [-0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 1/0, 0x080000001, -0x07fffffff, 2**53-2, -Number.MAX_VALUE, -(2**53), 0x100000000, 2**53+2, Math.PI, 1, 0x080000000, 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, 2**53, Number.MIN_VALUE, 0, 1.7976931348623157e308, -0x100000001, -0, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 42, 0x07fffffff, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=723; tryItOut("\"use strict\"; h0 = ({getOwnPropertyDescriptor: function(name) { Object.preventExtensions(p1);; var desc = Object.getOwnPropertyDescriptor(e0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { a1 = arguments;; var desc = Object.getPropertyDescriptor(e0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { print(x);; Object.defineProperty(e0, name, desc); }, getOwnPropertyNames: function() { i2.toSource = f1;; return Object.getOwnPropertyNames(e0); }, delete: function(name) { v0 = Proxy.create(h1, t2);; return delete e0[name]; }, fix: function() { /*MXX1*/o1 = g1.g0.Object.assign;; if (Object.isFrozen(e0)) { return Object.getOwnProperties(e0); } }, has: function(name) { m2.set(this.v2, g1.o2);; return name in e0; }, hasOwn: function(name) { Array.prototype.unshift.call(a2, o0, t2);; return Object.prototype.hasOwnProperty.call(e0, name); }, get: function(receiver, name) { Array.prototype.shift.apply(a2, [o1]);; return e0[name]; }, set: function(receiver, name, val) { m2.get(a0);; e0[name] = val; return true; }, iterate: function() { o2.s0 = new String(s1);; return (function() { for (var name in e0) { yield name; } })(); }, enumerate: function() { o2 = Object.create(v1);; var result = []; for (var name in e0) { result.push(name); }; return result; }, keys: function() { t1[2] = t1;; return Object.keys(e0); } });o0.m2 = new WeakMap;");
/*fuzzSeed-204645237*/count=724; tryItOut("/*RXUB*/var r = r1; var s = \"\\u7e9b0\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=725; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=726; tryItOut("testMathyFunction(mathy2, [1, 0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), 0x080000000, 0x100000000, -0x100000001, -0, Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_VALUE, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, 42, -0x080000001, 2**53+2, -0x080000000, -0x0ffffffff, 0, 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, 0x07fffffff, 0x080000001, -0x100000000, 0/0, 2**53-2]); ");
/*fuzzSeed-204645237*/count=727; tryItOut("\"use strict\"; /*infloop*/for(let e = e =  \"\" ; \"\\u1B00\".__defineSetter__(\"window\", function(q) { return q; }); f0.valueOf = f2) print(({}));var vcsegg = new ArrayBuffer(8); var vcsegg_0 = new Uint8ClampedArray(vcsegg); vcsegg_0[0] = -9; var vcsegg_1 = new Int16Array(vcsegg); this.f2(f1);");
/*fuzzSeed-204645237*/count=728; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.sin((Math.fround(Math.min(( ! Math.fround((((Math.sin((Math.hypot((x >>> 0), (x >>> 0)) >>> 0)) >>> 0) | 0) == Math.fround(mathy1((( - Math.fround(y)) >>> 0), x))))), ((y / (((Math.fround(Math.tan(Math.fround(( + -0x07fffffff)))) >>> 0) << ((x - (Math.trunc((y >>> 0)) >>> 0)) >>> 0)) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-204645237*/count=729; tryItOut("mathy4 = (function(x, y) { return (((( + ((y ^ Math.fround(0x080000001)) - y)) , ( + (( - (Math.fround(mathy1(Math.fround(Math.hypot(y, 0x080000001)), Math.fround(y))) >>> 0)) >>> 0))) >>> 0) >> ((Math.fround(Math.sign(Math.fround(x))) ? Math.fround(Math.asinh(( ! ( + (( + (y ? y : ( - (y | 0)))) > x))))) : Math.pow(Math.sqrt(( - x)), Math.imul(y, (mathy2(( + (0.000000000000001 << x)), y) >>> 0)))) >>> 0)); }); ");
/*fuzzSeed-204645237*/count=730; tryItOut("o2.v0 = 0;");
/*fuzzSeed-204645237*/count=731; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=732; tryItOut("const this.h2 = {};");
/*fuzzSeed-204645237*/count=733; tryItOut("\"use strict\"; \"use asm\"; for (var v of this.g2.t2) { v1 + t1; }");
/*fuzzSeed-204645237*/count=734; tryItOut("\"use strict\"; (\"\\u6C19\");");
/*fuzzSeed-204645237*/count=735; tryItOut("let (a =  \"\" ) intern(\"\\uE715\");");
/*fuzzSeed-204645237*/count=736; tryItOut("/*vLoop*/for (let hoihsu = 0, (x = Proxy.createFunction(({/*TOODEEP*/})(false), objectEmulatingUndefined)) ? \u000cx : arguments ** undefined; hoihsu < 69; ++hoihsu) { const w = hoihsu; for (var v of m2) { try { for (var p in o0.o1.s2) { try { /*RXUB*/var r = r1; var s = s1; print(s.split(r));  } catch(e0) { } try { Array.prototype.splice.apply(g0.a1, [10, 10]); } catch(e1) { } for (var p in p0) { try { e0 = new Set(a0); } catch(e0) { } try { a2.sort((function mcc_() { var mglror = 0; return function() { ++mglror; if (true) { dumpln('hit!'); try { v2 = t0.length; } catch(e0) { } try { o1 = Object.create(t2); } catch(e1) { } try { a2[13]; } catch(e2) { } f0 = (function() { try { e0.add(o2); } catch(e0) { } Array.prototype.shift.call(a0); return o1; }); } else { dumpln('miss!'); try { g1.t1 = new Int32Array(t1); } catch(e0) { } try { e0.add(({a2:z2})); } catch(e1) { } try { b2 = this.t0.buffer; } catch(e2) { } a2.forEach(Math.round); } };})()); } catch(e1) { } try { t1 = new Float32Array(b2, 0, 0); } catch(e2) { } a2 = a1.concat(a2, a1, i2, e1, f2, h0); } } } catch(e0) { } try { m1 + ''; } catch(e1) { } try { o1 = v0.__proto__; } catch(e2) { } t0[7] = b0; } } ");
/*fuzzSeed-204645237*/count=737; tryItOut("Object.defineProperty(this, \"f2\", { configurable: false, enumerable: x,  get: function() {  return (function() { for (var j=0;j<14;++j) { f1(j%3==1); } }); } });");
/*fuzzSeed-204645237*/count=738; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Float64ArrayView[2]) = ((d0));\n    return (((!(((((((-((d0))))) < (18446744073709552000.0))+(/*FFI*/ff(((((d0)) - ((((562949953421313.0)) % ((-0.03125)))))), ((((0xffffffff)) << ((0xeb21ee3d)))), ((((-0x8000000))|0)), ((1.9342813113834067e+25)), ((67108863.0)), ((65.0)), ((-576460752303423500.0)), ((-16777215.0)), ((35184372088833.0)), ((1.888946593147858e+22)), ((-67108865.0)), ((18014398509481984.0)), ((-3.094850098213451e+26)))|0)) ^ ((!(i2))-(i1)))))+(0xceac1413)))|0;\n    i1 = (i2);\n    d0 = (+((+/*FFI*/ff(((~~(-4398046511103.0))), ((((/*FFI*/ff(((d0)), (((((0x49dd5469))) & ((0x6daf742f)+(0x1adb2fd4)))), ((-18014398509481984.0)), ((+(0xfc41d7f))), ((-16777215.0)), ((2147483648.0)))|0)) | ((-0x8000000)))), (((Uint8ArrayView[1])))))));\n    return (((0x18b97fcf)-(i2)))|0;\n  }\n  return f; })(this, {ff: (yield Proxy.prototype)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, -0, -(2**53), 1, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 0x0ffffffff, 0x080000000, 42, 1/0, 2**53+2, -0x080000001, 0/0, 0.000000000000001, -(2**53+2), 2**53, -0x080000000, Math.PI, -1/0, -0x100000001, -0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, 1.7976931348623157e308, 2**53-2]); ");
/*fuzzSeed-204645237*/count=739; tryItOut("v2 = evalcx(\"a1.pop();\\nprint([] = {});\\n\", g1);");
/*fuzzSeed-204645237*/count=740; tryItOut("\"use strict\"; x;");
/*fuzzSeed-204645237*/count=741; tryItOut("b2 + '';print(14);");
/*fuzzSeed-204645237*/count=742; tryItOut("\"use strict\"; /*oLoop*/for (let yuakao = 0; yuakao < 4; ++yuakao) { e0.__proto__ = m0; } ");
/*fuzzSeed-204645237*/count=743; tryItOut("\"use strict\"; /*vLoop*/for (dvbbfk = 0; dvbbfk < 61; ++dvbbfk) { z = dvbbfk; g2.e1 = new Set(p2); } ");
/*fuzzSeed-204645237*/count=744; tryItOut("mathy0 = (function(x, y) { return Math.atan2(Math.fround(Math.hypot(Math.atan2(((0/0 ? (Math.sign(( ~ y)) | 0) : (Math.fround((( + y) % Math.fround(x))) | 0)) | 0), x), Math.fround((( - (Math.imul((( + (( + x) ? ( + ((-Number.MIN_SAFE_INTEGER ** -Number.MIN_VALUE) >>> 0)) : Math.min(x, (( - (x | 0)) | 0)))) >>> 0), (2**53-2 >>> 0)) >>> 0)) | 0)))), ( ~ Math.min(Math.ceil(Math.fround(2**53)), y))); }); testMathyFunction(mathy0, /*MARR*/[ /x/g , new Boolean(true),  /x/g , [], new Boolean(true),  /x/g , [], [1], [1], [1], [1],  /x/g , new Boolean(true), new Boolean(true),  /x/g , [],  /x/g , [], [1], [], [1], new Boolean(true),  /x/g ,  /x/g , []]); ");
/*fuzzSeed-204645237*/count=745; tryItOut("mathy4 = (function(x, y) { return ( - Math.fround((( + mathy3(( ~ ( ! (Math.log10(( + x)) | 0))), (-0x07fffffff , (Math.tan(x) | 0)))) - ( + -(2**53+2))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 2**53, 0x080000000, 42, -Number.MAX_VALUE, 2**53+2, Math.PI, -0x080000000, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -0x100000000, 1.7976931348623157e308, -(2**53+2), -0x100000001, -0x0ffffffff, -0x080000001, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0/0, 0, -1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, 1/0, Number.MAX_VALUE, 0x100000001, -0, 2**53-2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=746; tryItOut("testMathyFunction(mathy5, [1.7976931348623157e308, 1/0, -0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, -0, -(2**53), 0x07fffffff, -0x100000001, 2**53+2, 0x100000001, 0x080000001, 42, 0x0ffffffff, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 1, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -0x080000000, 0, 0/0, Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=747; tryItOut("/*RXUB*/var r = new RegExp(\"((?:\\\\3)|((?:.)|\\\\b|(?:(?=[^])[^]\\\\3+?|($)?)))\", \"gyi\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=748; tryItOut("f0 = (function() { try { h2.__iterator__ = (function() { for (var j=0;j<121;++j) { f2(j%2==1); } }); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(f2, v0); } catch(e1) { } try { a0.sort((function(j) { if (j) { try { m1.delete(o1); } catch(e0) { } try { Array.prototype.reverse.call(a1); } catch(e1) { } try { v2 = t2.byteLength; } catch(e2) { } print(uneval(o2.a2)); } else { try { m1.has(a2); } catch(e0) { } try { o0.a0.push(o0); } catch(e1) { } try { a2 = new Array; } catch(e2) { } Array.prototype.push.call(o0.a0, t2); } })); } catch(e2) { } m0.get(((4277) ? x : [[]] *= 8((DataView.prototype.getFloat32).call((4277), x), x += x))); return g2; });");
/*fuzzSeed-204645237*/count=749; tryItOut("\"use asm\"; testMathyFunction(mathy4, [-0x100000001, -Number.MAX_VALUE, 1/0, 2**53+2, 0x100000001, 0x0ffffffff, Math.PI, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), -0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000001, -0x080000001, -0x0ffffffff, -0x100000000, 0, -Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 1, 2**53, 1.7976931348623157e308, 0x080000000, 42, Number.MIN_VALUE, -1/0, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=750; tryItOut("\"use strict\"; this.v0 = Array.prototype.some.apply(a1, [eval]);");
/*fuzzSeed-204645237*/count=751; tryItOut("var gvdwbz = new ArrayBuffer(12); var gvdwbz_0 = new Uint8Array(gvdwbz); gvdwbz_0[0] = 6; var gvdwbz_1 = new Uint8Array(gvdwbz); print(gvdwbz_1[0]); gvdwbz_1[0] = -3; print((this.__defineGetter__(\"a\", (Date.prototype.toJSON).call)));{ void 0; gcslice(1); } /*MXX3*/g1.Promise.race = g1.Promise.race;g1 + g1;print(x);print(gvdwbz_1[1]);Array.prototype.sort.call(a2, function(y) { return \"\\u0D93\" }, b1);");
/*fuzzSeed-204645237*/count=752; tryItOut("\"use strict\"; i2.send(o2);");
/*fuzzSeed-204645237*/count=753; tryItOut("t0[6] = o0;");
/*fuzzSeed-204645237*/count=754; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy1((mathy0(((-Number.MAX_VALUE || (x >>> 0)) >>> 0), Math.fround(Math.log10(x))) >>> 0), (Math.min((Math.hypot(( + ( + mathy0((( ~ ( + (x ? y : x))) >>> 0), ( + Math.sqrt((( + ( ! Math.fround((mathy0((y >>> 0), (0x080000001 >>> 0)) >>> 0)))) >>> 0)))))), (Math.tanh((( + ( ! ( + x))) >>> 0)) >>> 0)) >>> 0), (( ! (y ? (( ~ x) >>> 0) : Math.fround((( ~ ( ! y)) | 0)))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0x100000000, -(2**53), -0, 0/0, Number.MIN_VALUE, 0x100000001, -(2**53-2), 0x080000000, -Number.MIN_VALUE, -0x07fffffff, -0x080000000, 0x07fffffff, -0x100000001, 2**53, Number.MAX_VALUE, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, -1/0, 2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, Math.PI, 42, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, 0, -0x100000000, -(2**53+2), 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=755; tryItOut("/*infloop*/do var duhpju = new SharedArrayBuffer(0); var duhpju_0 = new Float32Array(duhpju); print(duhpju_0[0]); duhpju_0[0] = 16; print(new Array(14,  /x/ )); while(window);");
/*fuzzSeed-204645237*/count=756; tryItOut("mathy2 = (function(x, y) { return (Math.clz32(((( ~ ((y << (y !== Math.atan2(0x100000000, mathy0(y, y)))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy2, [42, Number.MIN_VALUE, Number.MAX_VALUE, 0, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 0/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, 0x080000001, -1/0, -0x080000000, Math.PI, 1, -0x0ffffffff, 0x07fffffff, 0x080000000, 0x100000000, 1/0, -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000001, 2**53, -(2**53-2), 2**53-2, -0x100000000, -0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-204645237*/count=757; tryItOut("testMathyFunction(mathy5, [(new Number(0)), /0/, (new Boolean(true)), '', objectEmulatingUndefined(), '/0/', [0], undefined, ({valueOf:function(){return '0';}}), null, -0, ({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return 0;}}), (new Boolean(false)), 0, (function(){return 0;}), [], 1, 0.1, '\\0', NaN, true, '0', false, (new String(''))]); ");
/*fuzzSeed-204645237*/count=758; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=759; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.abs(Math.fround(( + mathy0(( + Math.min(( + x), x)), ( + Math.fround(Math.acosh(Math.tan(y)))))))); }); ");
/*fuzzSeed-204645237*/count=760; tryItOut("\"use strict\"; with({}) throw StopIteration;with({}) this.zzz.zzz;");
/*fuzzSeed-204645237*/count=761; tryItOut("i0.next();");
/*fuzzSeed-204645237*/count=762; tryItOut("testMathyFunction(mathy5, [-0x100000001, 0x100000001, 2**53, 2**53+2, -0x080000000, -0x080000001, -0x07fffffff, -1/0, 1/0, 0.000000000000001, 0/0, 1.7976931348623157e308, 2**53-2, 0x07fffffff, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 1, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 0x100000000, -(2**53+2), Number.MIN_VALUE, -0x100000000, 0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -0, Math.PI]); ");
/*fuzzSeed-204645237*/count=763; tryItOut("t2 = new Int32Array(11);\n/*bLoop*/for (let sqfzzw = 0; sqfzzw < 159; -6, ++sqfzzw) { if (sqfzzw % 6 == 1) { a2.shift(a1, s0, this.h1); } else { ( /x/ ); }  } \n");
/*fuzzSeed-204645237*/count=764; tryItOut("\"use asm\"; e2.delete(s2);");
/*fuzzSeed-204645237*/count=765; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=766; tryItOut("testMathyFunction(mathy3, [0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 0/0, 2**53+2, 2**53, -0, 0x0ffffffff, Number.MAX_VALUE, -0x080000001, -0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, 1, -0x080000000, 0, 0x100000000, -(2**53-2), 0x080000000, -0x100000001, 42, Math.PI, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, 2**53-2, -1/0, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-204645237*/count=767; tryItOut("/*hhh*/function eklzts(){print(x);}eklzts(new x = Proxy.createFunction(({/*TOODEEP*/})(this),  /x/ )(\"\\u2AC2\"[\"fill\"] = (makeFinalizeObserver('nursery'))), 'fafafa'.replace(/a/g, Root));");
/*fuzzSeed-204645237*/count=768; tryItOut("\"use strict\"; ciebpm, b = Math.hypot(-0, (function  d (z) { \"use strict\"; neuter(o0.b0, \"same-data\"); } .prototype)), d, NaN = (4277);/*vLoop*/for (var krwwlg = 0; krwwlg < 59; ++krwwlg) { c = krwwlg; v2 = evaluate(\"a0.pop(m2, o2);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: (c % 2 != 1) })); } ");
/*fuzzSeed-204645237*/count=769; tryItOut("\"use strict\"; const g1.a2 = a0.filter((function(j) { if (j) { try { /*ADP-2*/Object.defineProperty(this.a1, 6, { configurable: false, enumerable:  /* Comment */\"\\uC32E\", get: g0.f2, set: (function mcc_() { var suladt = 0; return function() { ++suladt; if (true) { dumpln('hit!'); try { i1.send(a0); } catch(e0) { } try { print(a1); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(g2.h0, o0); } catch(e2) { } g0 + e2; } else { dumpln('miss!'); try { g1.o0.g1.toString = (function(j) { f1(j); }); } catch(e0) { } h2.getOwnPropertyDescriptor = this.f1; } };})() }); } catch(e0) { } try { m1.delete(f0); } catch(e1) { } v0.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var tan = stdlib.Math.tan;\n  var exp = stdlib.Math.exp;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d1);\nthis.a2[g2.v1];    d0 = (d1);\n    d0 = (((((Int8ArrayView[4096])) >> ((0xd9161ccf)+((0x2e4f38ff) == (0xbd5eb42b))-(0xc1ca2caa)))) ? (+abs(((d1)))) : (+(0xe265c41)));\n    d0 = (((x)) % ((d1)));\n    {\n      switch ((0x7fffffff)) {\n        case -3:\n          d0 = (d1);\n          break;\n        case -1:\n          d0 = (d0);\n          break;\n        case -3:\n          d0 = (d1);\n          break;\n        case 0:\n          d1 = (d1);\n          break;\n        case 1:\n          d0 = (d0);\n          break;\n        case -1:\n          d1 = (d1);\n          break;\n        case -1:\n          d1 = (d0);\n          break;\n        case -2:\n          (Float64ArrayView[2]) = ((+(0.0/0.0)));\n          break;\n        case -3:\n          d1 = (+(1.0/0.0));\n          break;\n        case -1:\n          (Float32ArrayView[(((((0x981a5327)-(0x6308e8f8))>>>((0xffffffff))) >= (((0xffffffff)+(0x94a3a906)+(0xe46a861a))>>>((0xfffd7cf5)-(0xb61f7354)-(-0x16f295))))) >> 2]) = (((d1) + (d0)));\n          break;\n        case 0:\n          {\n            {\n              d1 = (d1);\n            }\n          }\n      }\n    }\n    switch ((0x78b0700)) {\n      case -1:\n        d1 = (+abs(((-((d1))))));\n        break;\n      case 1:\n        d1 = (+abs(((-((+/*FFI*/ff()))))));\n        break;\n      case -3:\n        d1 = (+tan(((d0))));\n        break;\n    }\n    d1 = (d1);\n    {\n      d0 = (d0);\n    }\n    d0 = (((d1)) / ((+exp(((/*FFI*/ff(((imul((0xfd3e799e), (0xdcb45616))|0)), ((d1)), (((-0xb1721*(0xe18c5ea1)) | (((0x3f3a245b) >= (-0x6cdf7ab))))), ((((0x54f07403)) ^ ((0xffffffff)))), ((d0)), ((((-0x8000000)) >> ((0xfc7cd91e)))), ((-281474976710656.0)), ((-1.0625)), ((-562949953421313.0)), ((147573952589676410000.0)))|0))))));\n    d1 = (d1);\n    return ((((-0xfffff*((0xd461ce86)))>>>(((((Uint16ArrayView[0])) | ((0xf969dcf1))))-(0xffffffff)-(0xfdad4749))) % (((0xff708fb9)*-0xe1c98)>>>(((~((0xd513c709)*-0x2d7dc)) <= (imul((-0x8000000), (0xf8ad26eb))|0))+(0xf8ce62b6)+(0xf863c43f)))))|0;\n  }\n  return f; })(this, {ff: EvalError}, new ArrayBuffer(4096)); } else { try { this.g2.i2 = new Iterator(h2); } catch(e0) { } try { s0 = new String; } catch(e1) { } this.p1.toSource = (function() { for (var j=0;j<25;++j) { f0(j%4==1); } }); } }));");
/*fuzzSeed-204645237*/count=770; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=771; tryItOut("v0 = evaluate(\"mathy2 = (function(x, y) { return Math.cosh(Math.fround(Math.fround(( - Math.pow((( + ( + Math.hypot(( + Math.asin(x)), (x - x)))) ? (x | 0) : (Math.hypot((( ~ mathy0(Math.fround(x), (x | 0))) >>> 0), ( + ( - x))) | 0)), Math.clz32(( + ( + (y | 0))))))))); }); testMathyFunction(mathy2, /*MARR*/[[1], new Number(1), new String('q'), [1], [1], new Number(1), [1], [1], new String('q'), [1], [1], new Number(1), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1)]); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (\"\\uF7B6\").call(/*UUV2*/(e.getUTCSeconds = e.keys), (4277), [[]]), noScriptRval: (4277), sourceIsLazy: false, catchTermination: /*MARR*/[objectEmulatingUndefined(), new String('q'),  '\\0' , objectEmulatingUndefined(), new String('q'), new String('q'),  '\\0' , objectEmulatingUndefined()].map(/*wrap3*/(function(){ \"use strict\"; var ysnqvn = -6; (x)(); })) }));");
/*fuzzSeed-204645237*/count=772; tryItOut("\"use asm\"; /*RXUB*/var r = /\\3/yim; var s = \"\\n\\n\\n\\n\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-204645237*/count=773; tryItOut("mathy0 = (function(x, y) { return Math.abs((( + (Math.pow((( ~ x) | 0), (((( + Math.atan2(y, y)) > y) <= y) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy0, [Math.PI, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, -Number.MIN_VALUE, 0x07fffffff, -0, -0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -(2**53), -(2**53-2), 1.7976931348623157e308, 0, -(2**53+2), 42, 2**53, 2**53+2, 0/0, 0x100000000, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 1/0, Number.MAX_VALUE, 1, -0x080000000]); ");
/*fuzzSeed-204645237*/count=774; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\nf0 = (function() { try { e1.has(o2); } catch(e0) { } try { print(t2); } catch(e1) { } try { a2[6] = h0; } catch(e2) { } this.v0 = t0.length; return o0.v1; });    i0 = (i1);\n    i1 = (i2);\n    i1 = (i1);\n    {\n      return (((!(0x91f32a99))+((0xa0da5ba5))))|0;\n    }\n    {\n      {\n        (Float32ArrayView[((i0)-((((0x94defcff))>>>((0x20363a9b))) < (((0xff3e6510))>>>((0x509c963c))))-(i1)) >> 2]) = ((129.0));\n      }\n    }\n    return ((-0xfffff*(0xfa3ccf7d)))|0;\n  }\n  return f; })(this, {ff: function (a)\"use asm\";   var imul = stdlib.Math.imul;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((0xfe165abe)-((imul((i2), (i0))|0) == (((i0)-((0x3c3e6b82))+(-0x536e0ec)) & (((((-0.25)) % ((295147905179352830000.0))) >= (d1)))))+(i2)))|0;\n  }\n  return f;}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [false, null, -0, undefined, '\\0', 0, (new Boolean(false)), /0/, objectEmulatingUndefined(), '/0/', 1, ({valueOf:function(){return '0';}}), (new Number(-0)), (function(){return 0;}), [], ({toString:function(){return '0';}}), '', [0], NaN, true, (new Boolean(true)), '0', (new Number(0)), 0.1, (new String('')), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-204645237*/count=775; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(\\\\S{1,3}){1,1}\", \"yi\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=776; tryItOut("print(o2.i0);");
/*fuzzSeed-204645237*/count=777; tryItOut("\"use strict\"; /*iii*/t1.__iterator__ = (function(j) { if (j) { try { Array.prototype.forEach.apply(o0.a1, [(function mcc_() { var wvahmo = 0; return function() { ++wvahmo; if (/*ICCD*/wvahmo % 2 == 0) { dumpln('hit!'); try { i2.send(i0); } catch(e0) { } try { f0 + a1; } catch(e1) { } v2 = t2.length; } else { dumpln('miss!'); try { f0 + g2; } catch(e0) { } try { g0.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e1) { } this.b1.toSource = (function() { for (var j=0;j<26;++j) { f0(j%5==1); } }); } };})(), length]); } catch(e0) { } try { this.a1.push(g1.o0.e2); } catch(e1) { } p0 + ''; } else { try { v2 = t2.length; } catch(e0) { } m2.toSource = (function(j) { if (j) { try { f2 = Proxy.createFunction(h0, f0, f2); } catch(e0) { } try { o1.e2.delete(v0); } catch(e1) { } try { /*RXUB*/var r = r2; var s = s2; print(r.test(s));  } catch(e2) { } Array.prototype.splice.apply(a0, [NaN, 7]); } else { try { print(uneval(g2)); } catch(e0) { } try { v0 = (o1.m2 instanceof p0); } catch(e1) { } try { h2 + ''; } catch(e2) { } this.v1 = Array.prototype.reduce, reduceRight.call(o0.a0, f0, t2, \"\\uCB55\", g1, e0); } }); } });/*hhh*/function svrnph(x, x =  \"\" ){m0.set(s1, a1);}");
/*fuzzSeed-204645237*/count=778; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( - mathy2(( + Math.exp((( + (y ? ((Math.atan(Math.fround(y)) >>> 0) >>> 0) : y)) >>> 0))), Math.sqrt(Math.pow(((2**53-2 | 0) << (x | 0)), Math.fround(( - Math.fround(( + mathy1(mathy1(x, y), -Number.MIN_SAFE_INTEGER))))))))); }); testMathyFunction(mathy3, [0, Math.PI, -0x0ffffffff, -(2**53-2), 0x080000000, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, 0x100000000, 1, -0, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, 0.000000000000001, 42, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -(2**53), 0/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, -Number.MIN_VALUE, -(2**53+2), 1/0]); ");
/*fuzzSeed-204645237*/count=779; tryItOut("if((x % 3 == 0)) {/*ODP-1*/Object.defineProperty(o0.t0, \"__parent__\", ({enumerable: true})); } else  if ( /x/g ) {p1 + ''; }");
/*fuzzSeed-204645237*/count=780; tryItOut("/*MXX1*/o2 = g1.EvalError;");
/*fuzzSeed-204645237*/count=781; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -281474976710655.0;\n    d3 = (d3);\n    return (((0xfc916730)-((0x14f3f04a))))|0;\n    switch ((0x535f15a8)) {\n      case 0:\n        {\n          (Int16ArrayView[1]) = (-(i1));\n        }\n        break;\n      default:\n        d3 = (72057594037927940.0);\n    }\n    d3 = (-1.25);\n    {\n      i1 = (i0);\n    }\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: Array.prototype.unshift}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0, ({valueOf:function(){return '0';}}), (function(){return 0;}), 0, true, 1, ({toString:function(){return '0';}}), (new Number(0)), (new Number(-0)), (new String('')), false, '/0/', '0', (new Boolean(true)), undefined, 0.1, '\\0', (new Boolean(false)), objectEmulatingUndefined(), '', NaN, [], null, ({valueOf:function(){return 0;}}), /0/, [0]]); ");
/*fuzzSeed-204645237*/count=782; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((((y << Math.pow(( + x), x)) >>> 0) ** (( + (( + Math.ceil((Math.sin((mathy2(42, y) >>> 0)) >>> 0))) , (( + mathy1(x, 0x07fffffff)) + y))) >>> 0)) >>> 0) && ( + Math.hypot((( + Math.imul(y, ( + (y - x)))) >>> 0), Math.abs(( + (Math.pow(Math.fround((Math.cbrt(y) >>> 0)), y) >>> 0)))))); }); testMathyFunction(mathy3, /*MARR*/[new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), x, x, x, x, x, x, new Number(1), objectEmulatingUndefined(), new Number(1), x, new Number(1), x, [], new Number(1), x, [], [], objectEmulatingUndefined(), [], objectEmulatingUndefined(), [], x, objectEmulatingUndefined(), x, x, x, x, x, x, x, objectEmulatingUndefined(), [], [], x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), [], x, x, []]); ");
/*fuzzSeed-204645237*/count=783; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(o1, e2);");
/*fuzzSeed-204645237*/count=784; tryItOut("\"\\u4581\";(\"\\uB60F\");");
/*fuzzSeed-204645237*/count=785; tryItOut("\"use asm\"; this.m1.__proto__ = t1;");
/*fuzzSeed-204645237*/count=786; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[[1], [1], 0x3FFFFFFE, 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, [1], [1], 0x3FFFFFFE, [1], 0x3FFFFFFE, [1], 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, [1], [1], 0x3FFFFFFE, [1], [1], [1], [1], 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, [1], 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, [1], 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, [1], [1], [1], [1], [1], [1], [1], [1], 0x3FFFFFFE, [1], [1]]); ");
/*fuzzSeed-204645237*/count=787; tryItOut("h1.fix = (function(j) { if (j) { a1.sort(); } else { try { Object.freeze(h2); } catch(e0) { } try { a1.unshift(a0, b2, a1, h1, i0, o1, e1, e0, (4277)); } catch(e1) { } a1.shift(b1, t1); } });");
/*fuzzSeed-204645237*/count=788; tryItOut("\"use strict\"; for (var p in e2) { try { v1 = g1.runOffThreadScript(); } catch(e0) { } try { a2.sort((function(j) { f1(j); }), i2); } catch(e1) { } ; }");
/*fuzzSeed-204645237*/count=789; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.round(((Math.tanh(( + (( + Math.min(x, -0x080000001)) << ( + y)))) / ((Math.max((((x | 0) || Math.fround(Math.log1p(y))) | 0), Math.atan(( + x))) >>> 0) | 0)) | 0)); }); ");
/*fuzzSeed-204645237*/count=790; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=791; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - ((Math.clz32(mathy0(( + mathy0(( + x), (y | 0))), (x ? (Math.hypot(-0, y) | 0) : (( + ( + x)) | 0)))) | Math.cos((mathy0(y, (Math.exp((Math.log1p((y | 0)) | 0)) | 0)) | 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-204645237*/count=792; tryItOut("e0 + '';");
/*fuzzSeed-204645237*/count=793; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2((mathy0(((Math.abs(( + ((((Math.atan2((2**53-2 >>> 0), y) >>> 0) | 0) * (( + ( ~ y)) | 0)) | 0))) | 0) <= ( ! y)), ( + ((x >>> 0) ? (( - Math.atan2(( ~ Math.fround(( - Math.fround(y)))), x)) >>> 0) : (Math.cos((( ~ (2**53+2 >>> 0)) >>> 0)) | 0)))) | 0), ( + ( + ( + Math.atan2(( + Math.fround(mathy2(Math.fround((( ! (mathy0((Number.MIN_VALUE >>> 0), y) | 0)) | 0)), (x >>> 0)))), ((x - (Math.fround(y) * x)) | 0)))))); }); ");
/*fuzzSeed-204645237*/count=794; tryItOut("/*tLoop*/for (let b of /*MARR*/[new String('q'), (0/0), (0/0), (0/0), (0/0), new String('q'), (0/0), (0/0), new String('q'), new String('q'), (0/0), (0/0), new String('q'), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), (0/0), (0/0), (0/0), (0/0), (0/0), new String('q'), (0/0), (0/0), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (0/0), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (0/0), new String('q'), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (0/0), (0/0), (0/0), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), (0/0), (0/0), new String('q'), new String('q'), (0/0), new String('q'), (0/0), (0/0), new String('q'), (0/0), new String('q'), (0/0), new String('q'), (0/0), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), (0/0), (0/0), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (0/0), new String('q')]) { for (var v of p0) { try { e2.delete(t0); } catch(e0) { } try { a0[13] =  \"\" ; } catch(e1) { } m2 + ''; } }");
/*fuzzSeed-204645237*/count=795; tryItOut("/*MXX2*/g1.Array.prototype.reverse = h2;");
/*fuzzSeed-204645237*/count=796; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(Math.min(Math.hypot(( + ((mathy1(Math.sinh(-Number.MIN_VALUE), x) >>> 0) ^ mathy1(Math.fround(x), Math.fround(Math.sin(( ~ x)))))), x), ((( + Math.fround(Math.imul(Math.hypot(y, Math.acos(x)), Math.fround((((x >>> 0) && Math.log10(Math.fround(( ! (y >>> 0))))) >>> 0))))) * ( + Math.log(x))) | 0))) || Math.fround(( + Math.pow(( + ( ~ ( + Math.log10(( + Math.cos(y)))))), ( + Math.clz32((( - y) >>> 0))))))); }); ");
/*fuzzSeed-204645237*/count=797; tryItOut("print(v2);");
/*fuzzSeed-204645237*/count=798; tryItOut("{ void 0; abortgc(); }");
/*fuzzSeed-204645237*/count=799; tryItOut("delete a1[\"reverse\"];");
/*fuzzSeed-204645237*/count=800; tryItOut("\"use strict\"; s0 = new String(p2);");
/*fuzzSeed-204645237*/count=801; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?![^\\\\S])\", \"yi\"); var s = \"a\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=802; tryItOut("mathy3 = (function(x, y) { return (mathy2(Math.fround((Math.atan2((Math.round(( - Math.tanh((x >>> 0)))) | 0), (mathy1((0x080000000 - Math.asinh((x % (( - Math.fround(1/0)) | 0)))), (Math.min((Math.imul(( - 2**53-2), Math.fround(x)) | 0), (( - ( + x)) >>> 0)) >>> 0)) | 0)) | 0)), (( ~ (Math.fround(mathy2(Math.fround((Math.fround((((-Number.MAX_VALUE >>> 0) ? (Math.pow(Math.fround(x), mathy2(Math.fround(x), 42)) >>> 0) : (Math.fround(mathy0(( + y), Math.exp((y | 0)))) >>> 0)) >>> 0)) ? Math.fround(( + (( + 0x07fffffff) << ( + x)))) : Math.fround(Number.MAX_SAFE_INTEGER))), Math.fround((Math.fround(y) ? ( + (Math.clz32((x >>> 0)) >>> 0)) : x)))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, Number.MAX_VALUE, 0x0ffffffff, 2**53, -(2**53), 0x07fffffff, -0x100000000, 2**53-2, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, 0, Math.PI, -0x0ffffffff, 2**53+2, 0x080000001, -0, 1/0, -0x100000001, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, 42, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=803; tryItOut("\"use strict\"; let w;g0.v2 = a2.reduce, reduceRight((function(j) { f1(j); }));var e = return x;");
/*fuzzSeed-204645237*/count=804; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.cosh(((Math.atan2(Math.fround(((Math.sign(0x07fffffff) > -(2**53-2)) ? y : ( + ( + (y | 0))))), (Math.fround((Math.cbrt(x) ? (Math.sqrt(Number.MAX_VALUE) > (Math.fround((( + y) ^ x)) ? x : x)) : -Number.MIN_SAFE_INTEGER)) >>> 0)) ? Math.fround(Math.atan(( + y))) : (Math.atan2((mathy4(Math.fround(Math.pow(Math.fround(y), ( + y))), Math.fround(Math.atan(y))) | 0), (0x100000001 | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[ '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  /x/ , new Boolean(true),  '' ,  '' , null,  '' ,  '' ,  '' , null, new Boolean(true), null, new Boolean(true),  /x/ , new Boolean(true), new Boolean(true),  '' ,  /x/ , new Boolean(true),  '' ,  '' , null,  '' ,  '' ,  /x/ , null, new Boolean(true), new Boolean(true),  '' ,  '' ,  /x/ ,  /x/ , null,  '' ,  /x/ ,  /x/ ,  /x/ , null, new Boolean(true), null,  /x/ ,  /x/ , new Boolean(true), null,  /x/ ,  /x/ ,  /x/ ,  '' ,  /x/ , null]); ");
/*fuzzSeed-204645237*/count=805; tryItOut("\"use strict\"; const v2 = g0.eval(\"function g2.f2(e0)  { yield (Math.sinh(15)) } \");");
/*fuzzSeed-204645237*/count=806; tryItOut("\"use strict\"; /*vLoop*/for (var nhxopb = 0; nhxopb < 129; ++nhxopb) { let z = nhxopb; a0.shift(); } ");
/*fuzzSeed-204645237*/count=807; tryItOut("a2.shift(true, s0);");
/*fuzzSeed-204645237*/count=808; tryItOut("v2 = o0.t2.byteOffset;");
/*fuzzSeed-204645237*/count=809; tryItOut("");
/*fuzzSeed-204645237*/count=810; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.cbrt(Math.fround(( ! ((( + (y >>> 0)) >>> 0) | (Math.cos((Math.atanh((Math.fround(Math.exp(Math.fround(x))) / y)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, 2**53+2, -(2**53), 1/0, 0/0, 2**53, 0x080000000, 2**53-2, -0x0ffffffff, -0x07fffffff, 42, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, -0, -1/0, 0x0ffffffff, Number.MAX_VALUE, -(2**53+2), 0, 0x080000001, 1, 1.7976931348623157e308, -(2**53-2), -0x080000000, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=811; tryItOut("var x, x = x, ohcioh, x =  '' ;Object.defineProperty(o0.o1, \"t0\", { configurable: window, enumerable: (x % 6 != 0),  get: function() {  return new Int8Array(v2); } });");
/*fuzzSeed-204645237*/count=812; tryItOut("testMathyFunction(mathy0, [-1/0, 1/0, 0x0ffffffff, 0x080000001, 2**53-2, 0/0, -(2**53), 0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, -0, 0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 0.000000000000001, 0x100000000, 0x100000001, 2**53+2, Math.PI, -(2**53+2), -0x100000000, 0x080000000, Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, -0x0ffffffff, -Number.MAX_VALUE, 1]); ");
/*fuzzSeed-204645237*/count=813; tryItOut("\"use strict\"; /*RXUB*/var r =  /x/g .yoyo(d /= y) ^= x; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-204645237*/count=814; tryItOut("\"use strict\"; v1 = (a2 instanceof t1);");
/*fuzzSeed-204645237*/count=815; tryItOut("(\"\\uD93B\");");
/*fuzzSeed-204645237*/count=816; tryItOut("testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, 0x080000000, 0x07fffffff, -Number.MIN_VALUE, -0, -0x080000001, Number.MIN_VALUE, 0/0, 2**53+2, 0x0ffffffff, 0x100000001, 0.000000000000001, Math.PI, 1, 1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, -Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, -1/0, 2**53-2, -(2**53+2), 42, -0x100000000]); ");
/*fuzzSeed-204645237*/count=817; tryItOut("mathy0 = (function(x, y) { return ((Math.asin(Math.imul(y, (( - (y >>> 0)) | ( + Math.max((x >>> 0), (Math.log2((x >>> 0)) >>> 0)))))) && ( + (((((y >>> Math.acos(((y >>> 0) < (y | 0)))) | 0) ^ (Math.min(y, y) | 0)) | 0) < Math.min((x || x), (( ! (( ! y) | 0)) >>> 0))))) >>> 0); }); ");
/*fuzzSeed-204645237*/count=818; tryItOut("/*RXUB*/var r = new RegExp(\"(?:([\\u0011-\\u00b8\\\\s\\\\xFF-\\\\\\u0891]|[^\\\\w])|(\\\\d)|$+?*)\", \"yim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-204645237*/count=819; tryItOut("\"use strict\"; i2.send(i1);");
/*fuzzSeed-204645237*/count=820; tryItOut("(Math);");
/*fuzzSeed-204645237*/count=821; tryItOut("\"use asm\"; ((void shapeOf(\"\\uA482\" **  /x/ )));function x(a)\"use asm\";   var pow = stdlib.Math.pow;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float64ArrayView[((0xfad2516c)-((((Int8ArrayView[((0x7e517794)) >> 0])) | ((0xbef3ac05) % (0x2d0d5ab6))))) >> 3]) = ((+pow(((+(1.0/0.0))), ((4294967297.0)))));\n    return ((-0x9e397*(i1)))|0;\n  }\n  return f;yield;");
/*fuzzSeed-204645237*/count=822; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=823; tryItOut("\"use strict\"; a1 = /*FARR*/[.../*FARR*/[(Element()), (makeFinalizeObserver('tenured')), , , ...eval(\"/* no regression tests found */\", (Math.atan2(9, window))) for (w in (4277)) for (z of [/*FARR*/[].sort for each (\u3056 in x)//h\n for (eval in  ''  <<  /x/ ) for (e of new Date()) for (d of /*MARR*/[0x20000000, 0x20000000, 0x20000000, [1], 0x20000000, [1], [1], [1], 0x20000000, 0x20000000]) if ((((/*wrap1*/(function(){ print(c);return undefined})())(x, [])).yoyo(NaN =  /x/g )))]) for each (x in ( '' ())) for (eval of (new (function(y) { \"use strict\"; return let (y) /*MARR*/[eval, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), eval, eval, new Boolean(false), new Boolean(false), eval,  \"\" , new Boolean(false),  \"\" ,  \"\" , eval, new Boolean(false),  \"\" , eval,  \"\" ,  \"\" ,  \"\" , eval, eval,  \"\" , new Boolean(false), eval,  \"\" , eval,  \"\" , new Boolean(false), new Boolean(false), eval, new Boolean(false), eval, new Boolean(false),  \"\" , eval, new Boolean(false), eval, eval, eval, eval, new Boolean(false),  \"\" ,  \"\" ,  \"\" , eval, new Boolean(false), eval, new Boolean(false),  \"\" ,  \"\" , eval,  \"\" , new Boolean(false),  \"\" ,  \"\" ,  \"\" ].sort })(([].valueOf(\"number\")), (/*UUV1*/(b.concat = /*wrap2*/(function(){ \"use strict\"; var xyqxuq = x; var utexur =  /x/ ; return utexur;})()))))) for (\u000cthis.z of Math.atan2(\"\\uCCEA\", (4277)) for each (y in /*MARR*/[null, new Boolean(false), new Number(1), null, null, null, new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), null, null, new Number(1), new Number(1), new Number(1), new Boolean(false), new Number(1), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), null, new Boolean(false), new Boolean(false), new Boolean(false), null, null, new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), null, new Number(1), new Number(1), new Boolean(false), new Boolean(false), null, new Boolean(false), null, new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), null, new Boolean(false), null]) for (x of this.__defineSetter__(\"\\\"-8796093022207\\\"\", Array.prototype.push)) for each (x in ({ get toString a (x)\"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float64ArrayView[2]) = ((Float32ArrayView[(((abs((~((0xf91e53fc))))|0))) >> 2]));\n    i0 = (!(i0));\n    i0 = (!(1));\n    return +((Float32ArrayView[((!(((0xa5830c0d)) ? (0x8c39d303) : (0xf992ffa4)))) >> 2]));\n  }\n  return f; })) for (a in c)) for each (window in yield = x) for (x of /*MARR*/[new Number(1.5), ({x:3}), ({}), true, ({x:3}), false, new Number(1.5), true, true, new Number(1.5), false, ({x:3}), ({}), true, ({}), true, new Number(1.5), new Number(1.5), new Number(1.5), false, true, new Number(1.5)]) for each (w in Array(w))], x, new ( \"\" )(), , .../*FARR*/[, ], ...Int16Array, ];");
/*fuzzSeed-204645237*/count=824; tryItOut("m1 = new Map;");
/*fuzzSeed-204645237*/count=825; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.tan(( + Math.max((mathy0(((y ** x) | 0), (((x >>> ( + (y ? -0x080000001 : y))) | 0) | 0)) | 0), Math.hypot(x, ((((y | 0) == (y | 0)) | 0) >> Math.fround(mathy0(y, (( - (y | 0)) | 0))))))))); }); testMathyFunction(mathy3, [-0, 1, -0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, Number.MAX_VALUE, 0x080000000, Math.PI, -0x0ffffffff, 1.7976931348623157e308, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -0x080000001, -0x080000000, 1/0, -1/0, 2**53+2, 0, -(2**53-2), 0x100000001, -0x100000000, 2**53-2, -Number.MIN_VALUE, 42]); ");
/*fuzzSeed-204645237*/count=826; tryItOut("\"use strict\"; g1.f2.valueOf = (function(a0, a1, a2) { a1 = a2 & a2; var r0 = x + 4; var r1 = a2 % r0; var r2 = 7 - 1; var r3 = 4 ^ 9; var r4 = a2 + r0; var r5 = 2 - 1; var r6 = a2 | 9; var r7 = 9 + 0; var r8 = 3 & a0; var r9 = 1 | x; var r10 = r8 | r2; var r11 = 3 - 3; var r12 = r3 & r5; r10 = 8 & r7; var r13 = 0 ^ r8; r11 = r8 | r4; var r14 = r13 / r6; var r15 = r4 & 2; r15 = r14 * r4; r15 = r1 | a0; var r16 = r15 & r3; r1 = r3 - 7; var r17 = r10 & r4; r5 = r8 - r0; r10 = 5 ^ 5; var r18 = r4 % 5; var r19 = 3 * r16; var r20 = 1 * r1; var r21 = 3 % 0; var r22 = r17 / r12; var r23 = a0 % 2; var r24 = r6 - r2; var r25 = r3 | r8; var r26 = r11 / r7; r5 = r4 & r3; print(r19); r18 = r19 | r24; var r27 = r19 - 4; var r28 = r19 ^ r11; var r29 = 4 + a2; var r30 = r20 - r0; var r31 = 9 % 0; var r32 = 3 | r27; r12 = 5 - r21; r1 = r29 % r21; r27 = r0 & r18; var r33 = 2 % 0; print(r27); var r34 = r11 - 4; var r35 = 9 % r11; r21 = r27 + 4; a2 = 6 * 3; r20 = x % r1; var r36 = 4 + r12; var r37 = 5 - r1; var r38 = 4 & r17; var r39 = r37 % r14; print(a2); print(r37); var r40 = r36 + 8; var r41 = r8 + 7; var r42 = 2 % r22; var r43 = 7 | a1; var r44 = r26 ^ r41; var r45 = r15 % r36; var r46 = 8 % r32; var r47 = 5 & r21; r8 = 5 | r38; var r48 = r45 & 6; r43 = r48 + 5; var r49 = 8 & r37; r28 = 0 * r43; print(r5); var r50 = r48 / r42; var r51 = r3 | a0; var r52 = 8 / r21; r10 = 7 % r38; var r53 = r20 + x; var r54 = 0 % 6; x = r13 + r47; r9 = r17 - r2; var r55 = 5 + r32; r34 = r36 * r18; r22 = 5 % r25; return a2; });");
/*fuzzSeed-204645237*/count=827; tryItOut("t2.valueOf = (function() { v0 = t1.length; return s0; });");
/*fuzzSeed-204645237*/count=828; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot(( + (Math.max(( ! Math.fround(( + Math.atan2(( + y), ( + (( - y) >>> 0)))))), ( ~ Math.fround(x))) > ( + Math.fround((y ? x : Math.fround(0x0ffffffff)))))), ( + Math.fround(Math.sign(Math.fround(Math.max(( + Math.cosh(Math.imul(x, x))), Math.fround((Math.fround(x) === ( - ((x | 0) * (y >>> 0))))))))))); }); testMathyFunction(mathy3, [-(2**53), 42, 1, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -(2**53-2), -(2**53+2), Number.MAX_VALUE, -0, 0x100000000, -0x07fffffff, -0x100000000, Number.MIN_VALUE, 0/0, 2**53, 0, 1/0, 0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x0ffffffff, 0x100000001, -0x100000001, -1/0, 1.7976931348623157e308, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-204645237*/count=829; tryItOut("this.zzz.zzz;const x = e **= a;");
/*fuzzSeed-204645237*/count=830; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1/0, 2**53, -0x07fffffff, 42, 0x100000000, -(2**53-2), -Number.MAX_VALUE, -0x0ffffffff, 2**53-2, 1, 0x080000001, 0x100000001, -(2**53+2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -1/0, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, 0x07fffffff, Number.MIN_VALUE, Math.PI, 0, -0x100000001, -0, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 0/0, -Number.MIN_VALUE, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=831; tryItOut("\"use strict\"; v2 = Infinity;");
/*fuzzSeed-204645237*/count=832; tryItOut("\"use strict\"; g2.e2.has(this.o1);");
/*fuzzSeed-204645237*/count=833; tryItOut("mathy5 = (function(x, y) { return (Math.clz32((( ~ Math.fround(( ~ (( + x) | 0)))) / Math.tanh((((Math.atan2(x, ((y && y) >>> 0)) >>> 0) || (x >>> 0)) >>> 0)))) >>> 0); }); testMathyFunction(mathy5, ['/0/', ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), null, [0], '0', ({toString:function(){return '0';}}), (new Number(0)), undefined, /0/, NaN, (function(){return 0;}), ({valueOf:function(){return 0;}}), 1, (new Boolean(true)), false, true, (new Number(-0)), -0, [], (new String('')), 0.1, '', '\\0', 0, (new Boolean(false))]); ");
/*fuzzSeed-204645237*/count=834; tryItOut("");
/*fuzzSeed-204645237*/count=835; tryItOut("mathy1 = (function(x, y) { return (Math.exp((( ~ ((((Math.asin(Math.fround(0x080000001)) | 0) % (Math.abs(((y & ( + (x <= x))) >>> 0)) | 0)) | 0) >>> 0)) >>> 0)) | 0); }); ");
/*fuzzSeed-204645237*/count=836; tryItOut("\"use strict\"; let (abapck, b = ((-9)()), a = x, qsakjo, usshuc, x, x, b) { o0.valueOf = (function() { for (var j=0;j<25;++j) { f1(j%5==1); } }); }");
/*fuzzSeed-204645237*/count=837; tryItOut("b0.toString = new ((1 for (x in [])))(/*UUV1*/(x.getUTCDay = \n((void options('strict_mode')))));");
/*fuzzSeed-204645237*/count=838; tryItOut("s1.valueOf = (function(j) { if (j) { try { b2 + o0.i0; } catch(e0) { } try { t0[3]; } catch(e1) { } g1.toSource = g2.o2.f2; } else { try { a0 = t1[Math.imul(new a(29, false), 8)]; } catch(e0) { } ; } });");
/*fuzzSeed-204645237*/count=839; tryItOut("\"use strict\"; h2 + h1;");
/*fuzzSeed-204645237*/count=840; tryItOut("for(let a of new Array(-18)) throw StopIteration;");
/*fuzzSeed-204645237*/count=841; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0, 0x100000000, 2**53+2, 2**53-2, -(2**53+2), 0, -Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 1/0, 0/0, 0.000000000000001, 0x0ffffffff, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000001, 42, Number.MIN_VALUE, 0x080000001, -0x100000000, -Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 2**53, Math.PI, -(2**53), 0x07fffffff, 1]); ");
/*fuzzSeed-204645237*/count=842; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh(Math.fround(Math.cbrt((Math.hypot((Math.acosh((y >>> 0)) >>> 0), Math.hypot(((y !== y) | 0), ( + ((y ** (y | 0)) < 0x100000001)))) >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[(void 0), -Number.MIN_SAFE_INTEGER, (void 0), function(q) { \"use strict\"; return q; }.prototype, function(q) { \"use strict\"; return q; }.prototype,  'A' , -Number.MIN_SAFE_INTEGER,  'A' , function(q) { \"use strict\"; return q; }.prototype, (void 0),  'A' ,  'A' ,  'A' , -Number.MIN_SAFE_INTEGER, function(q) { \"use strict\"; return q; }.prototype, -Number.MIN_SAFE_INTEGER, (void 0), function(q) { \"use strict\"; return q; }.prototype, -Number.MIN_SAFE_INTEGER, function(q) { \"use strict\"; return q; }.prototype, (void 0), -Number.MIN_SAFE_INTEGER,  'A' , (void 0), function(q) { \"use strict\"; return q; }.prototype,  'A' , function(q) { \"use strict\"; return q; }.prototype,  'A' , function(q) { \"use strict\"; return q; }.prototype, (void 0), function(q) { \"use strict\"; return q; }.prototype,  'A' , -Number.MIN_SAFE_INTEGER,  'A' , (void 0), (void 0), (void 0), -Number.MIN_SAFE_INTEGER,  'A' , -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=843; tryItOut("\"use strict\"; d = x++;m0.has(m0);");
/*fuzzSeed-204645237*/count=844; tryItOut("print(false);");
/*fuzzSeed-204645237*/count=845; tryItOut("mathy4 = (function(x, y) { return ( ! mathy2(( - (Math.sin(y) | 0)), Math.sqrt(Math.max((-0x100000001 >>> 0), (Math.pow(((mathy1((x >>> 0), (x >>> 0)) >>> 0) >>> 0), (y >>> 0)) * 0x0ffffffff))))); }); testMathyFunction(mathy4, [0.000000000000001, 0x07fffffff, 0/0, 2**53-2, -0x100000001, -0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, 0x100000001, 0, -0, 1, -0x080000001, Math.PI, 42, 2**53, -(2**53), 0x100000000, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), 0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-204645237*/count=846; tryItOut("Array.prototype.forEach.call(a0, this.b1, a1, t0);");
/*fuzzSeed-204645237*/count=847; tryItOut("\"use strict\"; /*infloop*/while(new RegExp(\"(?=(?:(?:.))*?)*|(?=([]))\\\\2([\\\\D\\u00e2\\\\w\\\\s]|(?=^)?)\", \"gyim\"))print(x);");
/*fuzzSeed-204645237*/count=848; tryItOut("for (var v of i1) { try { /*ADP-1*/Object.defineProperty(a1, v0, ({configurable: (x % 25 == 3)})); } catch(e0) { } try { v2 = Array.prototype.every.call(a1, (function() { try { Array.prototype.splice.call(this.a1, 3, yield (({__iterator__: Math.asin(16), x: (a = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"(?:[^\\u00fa\\\\\\u0081]|\\uc872\\u22ae)[\\\\\\u00da-\\u51d4]*.|(?:\\\\b)|\\\\B{3}+{4,7}\", \"im\")), (let (e=eval) e), decodeURIComponent)) })), m2); } catch(e0) { } try { g1.a2.shift(); } catch(e1) { } try { g1.h0 = ({getOwnPropertyDescriptor: function(name) { v0 = (s1 instanceof m2);; var desc = Object.getOwnPropertyDescriptor(s2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { /*RXUB*/var r = r0; var s = \"\"; print(s.search(r)); print(r.lastIndex); ; var desc = Object.getPropertyDescriptor(s2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { return a0; Object.defineProperty(s2, name, desc); }, getOwnPropertyNames: function() { i1.send(o1.i1);; return Object.getOwnPropertyNames(s2); }, delete: function(name) { throw g1.p1; return delete s2[name]; }, fix: function() { e0.delete(b1);; if (Object.isFrozen(s2)) { return Object.getOwnProperties(s2); } }, has: function(name) { throw s0; return name in s2; }, hasOwn: function(name) { e2 = s0;; return Object.prototype.hasOwnProperty.call(s2, name); }, get: function(receiver, name) { ;; return s2[name]; }, set: function(receiver, name, val) { /*MXX2*/g1.TypeError.prototype.toString = this.h1;; s2[name] = val; return true; }, iterate: function() { return i0; return (function() { for (var name in s2) { yield name; } })(); }, enumerate: function() { h2.getPropertyDescriptor = f0;; var result = []; for (var name in s2) { result.push(name); }; return result; }, keys: function() { this.a0.__proto__ = v1;; return Object.keys(s2); } }); } catch(e2) { } selectforgc(o1); return o2.p2; })); } catch(e1) { } try { Object.seal(this.g0); } catch(e2) { } g0.v1 = (this.b2 instanceof b0); }");
/*fuzzSeed-204645237*/count=849; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1{3}((?=\\\\B{2,2}))|(?:(?!\\\\uEacf{0,3}))(?=[^]|(?:.)|[^]+)(?=[^\\u0089-\\\\\\u00f0\\\\S]|\\\\b{3}\\\\d|[^]+)|(?=\\\\s\\\\b{3,})?\", \"yim\"); var s = \"XXXXXXXXXaaa\\n\\n\\n\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=850; tryItOut("s1 += 'x';");
/*fuzzSeed-204645237*/count=851; tryItOut("a0[9] = this.__defineGetter__(\"x\", Date.prototype.toLocaleString);");
/*fuzzSeed-204645237*/count=852; tryItOut("for (var p in o0.o0) { for (var v of b1) { o0.m2.set(f2, m1); } }");
/*fuzzSeed-204645237*/count=853; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(( - (( + Math.hypot(Math.fround(Math.fround(Math.sign(Math.fround(y)))), ( + mathy0((-0 >>> 0), ( + (((( + (Math.sqrt(x) >>> 0)) >>> 0) >>> 0) | (y >>> 0))))))) | 0))); }); ");
/*fuzzSeed-204645237*/count=854; tryItOut("v2 = x;");
/*fuzzSeed-204645237*/count=855; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.sign(mathy0(( + (Math.atan2(Math.cos(Math.fround(y)), (y >>> 0)) >>> 0)), Math.fround(( + Math.imul(( + Number.MIN_SAFE_INTEGER), ( + -0x080000001)))))) | 0), ((Math.atan2(((Math.imul((y >>> 0), (-(2**53) >>> 0)) > mathy0((x | 0), x)) | 0), (( + (( + ( + -0x080000001)) >> Math.fround(Math.log(((( - (y >>> 0)) >>> 0) | 0))))) | 0)) | 0) ? (mathy0(Math.fround(( ~ (( - (( + (( + 2**53) - ( + x))) >>> 0)) >>> 0))), Math.sinh(Math.fround((Math.fround(y) !== Math.fround(0))))) < Math.sqrt((( + -0x0ffffffff) >> ( + x)))) : Math.fround((Math.atan2(((Math.pow(((Math.round((x >>> 0)) >>> 0) >>> 0), ( + (( + x) == (x | 0)))) >>> 0) >>> 0), (y >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 0/0, -(2**53+2), 42, 0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 2**53, 1, 0x080000000, 0, -(2**53-2), Number.MIN_VALUE, -0, 1.7976931348623157e308, -0x080000001, -0x100000001, 0x07fffffff, 0.000000000000001, -0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000, 1/0, -0x100000000, 2**53-2, -Number.MAX_VALUE, -(2**53), -1/0, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=856; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1.001953125;\n    var d3 = 17592186044415.0;\n    var d4 = -1.1805916207174113e+21;\n    var d5 = -9.671406556917033e+24;\n    var i6 = 0;\n    {\n      {\n        d1 = (+((Infinity)));\n      }\n    }\n    return ((((((0x1b4b1535)))>>>((0x7b082be4) % (((void options('strict_mode'))) ^ ((0xab2d76c0))))) % (((0xfab6b62d)+(-0x8000000))>>>((0x725eb58c)))))|0;\n    d3 = (+((+/*FFI*/ff(((((i0)*-0xfffff) ^ ((0x82063da)))), ((d4)), ((((0x880d4767)+(-0x8000000)-((0x38e6ef40) ? (0xfa575b31) : (0xfb3ca541))) >> ((-0x8000000)))), ((+(1.0/0.0))), ((((0xfb2f9916)*0xfffff)|0)), ((0xd13a44e)), ((+atan2(((4194305.0)), ((4096.0)))))))));\n    return (((0xffffffff)+(0x20e74269)))|0;\n  }\n  return f; })(this, {ff: ((void options('strict')))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[(0/0), [undefined], [undefined], [undefined], (0/0), (0/0), [undefined], -0x080000001, [undefined], (0/0), [undefined], -0x080000001, [undefined], [undefined], -0x080000001, -0x080000001, (0/0), [undefined], -0x080000001, -0x080000001, -0x080000001, -0x080000001, (0/0), [undefined], (0/0), (0/0), (0/0), -0x080000001, -0x080000001, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, [undefined], [undefined], -0x080000001, [undefined], -0x080000001, -0x080000001, (0/0), -0x080000001, (0/0), [undefined], [undefined], [undefined], (0/0), [undefined], [undefined], -0x080000001, (0/0), -0x080000001, -0x080000001, -0x080000001, -0x080000001, [undefined], (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), [undefined], (0/0), -0x080000001, (0/0), [undefined], [undefined], [undefined], (0/0), (0/0), [undefined], [undefined], [undefined], -0x080000001, -0x080000001, -0x080000001, (0/0), [undefined], -0x080000001, (0/0), -0x080000001, -0x080000001, -0x080000001, (0/0), -0x080000001, [undefined], [undefined], (0/0), (0/0), (0/0), -0x080000001, [undefined], (0/0), (0/0), (0/0), [undefined], [undefined], (0/0), (0/0), -0x080000001, (0/0), -0x080000001, [undefined], [undefined], -0x080000001, (0/0), [undefined], [undefined], -0x080000001, [undefined], (0/0), -0x080000001, [undefined], -0x080000001, [undefined], -0x080000001, (0/0), [undefined], (0/0), (0/0), (0/0), [undefined], [undefined], (0/0), -0x080000001, (0/0), (0/0), -0x080000001, (0/0), -0x080000001, -0x080000001, -0x080000001, -0x080000001, (0/0), (0/0), (0/0), (0/0), -0x080000001, (0/0), -0x080000001, -0x080000001, [undefined], (0/0), [undefined], -0x080000001, -0x080000001, [undefined], (0/0), [undefined], [undefined]]); ");
/*fuzzSeed-204645237*/count=857; tryItOut("mathy0 = (function(x, y) { return ( + Math.pow(Math.fround((( - y) & Math.fround(Math.log2((( + y) | 0))))), (Math.atan2((( - (( + Math.round(( + (Math.sqrt((x | 0)) >>> 0)))) | 0)) | 0), Math.fround((y && ( + (Math.fround(Math.pow(Math.fround(x), Math.fround(x))) >= (Math.sinh((y >>> 0)) | 0)))))) | 0))); }); ");
/*fuzzSeed-204645237*/count=858; tryItOut("a2.push(a2);");
/*fuzzSeed-204645237*/count=859; tryItOut("mathy3 = (function(x, y) { return ((Math.atan(( + (( ! ((mathy1(Math.atan((Math.fround(Math.cos(2**53-2)) >>> 0)), Math.fround(Math.hypot(Math.fround(x), (x | 0)))) | 0) / (((((Math.hypot(1, -0x080000000) * x) | 0) ? y : y) >>> 0) | 0))) | 0))) >>> 0) && Math.fround(( + Math.fround(Math.min((Math.sign(y) ? ((Math.pow((-Number.MAX_SAFE_INTEGER >>> 0), (y >>> 0)) >>> 0) >>> 0) : ((x != Math.fround(x)) >>> 0)), (Math.sqrt((Math.asin((( ~ -0) | 0)) | 0)) | 0)))))); }); testMathyFunction(mathy3, [0.000000000000001, -(2**53), 0x07fffffff, -0x080000000, -0x080000001, 0x0ffffffff, 0/0, -0x0ffffffff, 1, -0, Number.MIN_VALUE, -(2**53-2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, 2**53, -Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, 1/0, 0x100000000, 2**53+2, -0x100000001, 1.7976931348623157e308, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 42]); ");
/*fuzzSeed-204645237*/count=860; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((Math.fround((Math.fround(Math.round(Math.atan2(y, ( + 0.000000000000001)))) == Math.hypot(x, (x >>> 0)))) / (Math.cosh(( + (( + x) || ( + mathy1(0x080000000, y))))) << y)) != mathy0(( - Math.fround(x)), ( ~ ((( + ( - ( + (x ? y : -0)))) && ( + (( ! ( + y)) >>> 0))) ** (( + Math.atan2((y >>> 0), y)) || ( + Math.hypot(Number.MIN_SAFE_INTEGER, ( + x)))))))); }); testMathyFunction(mathy4, [2**53-2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, -1/0, Number.MIN_VALUE, -(2**53+2), -(2**53), -0x0ffffffff, -0x07fffffff, 2**53+2, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 0x100000000, 1/0, Math.PI, Number.MAX_VALUE, 0x100000001, -(2**53-2), -0x100000000, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 0, -Number.MAX_VALUE, 2**53, -0, -0x080000001, 0x080000000, 0x0ffffffff, 0x07fffffff, -0x100000001, 42]); ");
/*fuzzSeed-204645237*/count=861; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float32ArrayView[0]) = ((Float32ArrayView[((!((0xffffffff)))+((0xfe89a660))) >> 2]));\n    i1 = (!(i1));\n    d0 = (((+abs(((((i1) ? (+(1.0/0.0)) : (+(imul((0xea4e3dac), (0xffffffff))|0))) + (d0)))))) / ((d0)));\n    switch ((((Int16ArrayView[((0xf8b4d59d)) >> 1])) ^ (((0x50183d5c) ? (0xffffffff) : (0xf451532b))+(i1)))) {\n      default:\n        (Int8ArrayView[(((0xc90e355b))+((((0xfe99b5e5)) >> (((0x78190d00))+((0x184eb075)))))) >> 0]) = (((+(1.0/0.0)) < (-32769.0))-((8589934591.0) <= (d0)));\n    }\n    {\n      {\n        d0 = (d0);\n      }\n    }\n    d0 = ((void options('strict')));\n    return ((-0xfffff*(0xff91aa30)))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 0/0, 2**53+2, 0x080000000, -Number.MIN_VALUE, 42, Number.MAX_VALUE, 0x07fffffff, Math.PI, 2**53, -0x100000001, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -(2**53), 1/0, 0x100000001, -(2**53-2), 1.7976931348623157e308, -0x0ffffffff, 2**53-2, -0x080000000, -0x07fffffff, 1, -(2**53+2), -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, 0, -Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-204645237*/count=862; tryItOut("testMathyFunction(mathy4, [0x080000001, 0, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -1/0, -(2**53-2), 1, 1/0, 2**53+2, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 0.000000000000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, -0x100000001, -(2**53), -0x080000001, 42, -0x100000000, 0x100000001, Math.PI, 0x100000000, 0x0ffffffff, -0, 2**53]); ");
/*fuzzSeed-204645237*/count=863; tryItOut("\"use strict\"; o1.e2.add(e2);function x(window = [1,,], x, x, x, \u3056, x, NaN, NaN, x, NaN, x, d, c, x, eval, x, x, \u3056 = /$/ym, b = NaN, z, x, a = false, w, x, x, x, x, x, set, y, a = \"\\uCCD7\", x, eval, y, eval =  '' , x = false, y, eval, b, window, b =  /x/ , x = \"\\uD551\", y = new RegExp(\"(\\\\W|[^])*?\\\\2\", \"gyi\"), x, y, e =  /x/ , a, x, \u3056 = 5.0000000000000000000000, x = \"\\uD486\", y, c, y, x, this.w, z, x = x, NaN, w, x, y, z, a, NaN, \u3056, x, window = b, window, x, x, b, \u3056, x, e, a, eval, x = ({a1:1}), d, x, x, x) { yield -23 } yield;function a(e, y)xthrow true;");
/*fuzzSeed-204645237*/count=864; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    {\n      i1 = (i0);\n    }\n/*infloop*/L:for(d = \u3056 = ( \"\" .small(x, -12)); new RegExp(\"\\\\cG+?\", \"g\"); window -  /x/ ) b2.__proto__ = g1;    i0 = (i0);\n    {\n      i1 = (0x2016520d);\n    }\n    i1 = (i1);\n    return +((((1.125)) % ((-4398046511105.0))));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1, '\\0', '0', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), /0/, 0.1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), undefined, 0, [0], true, (new Boolean(false)), -0, null, (new Number(-0)), '/0/', [], NaN, (new String('')), (new Number(0)), (function(){return 0;}), false, (new Boolean(true)), '']); ");
/*fuzzSeed-204645237*/count=865; tryItOut("\"use strict\"; let (tsmehc, x = new SharedArrayBuffer(d), x = x, e, ymcyzd, w = window) { g0.m2 = new Map(h0); }");
/*fuzzSeed-204645237*/count=866; tryItOut("");
/*fuzzSeed-204645237*/count=867; tryItOut("mathy0 = (function(x, y) { return (Math.max((Math.fround(Math.min(Math.fround((Math.imul(((0x0ffffffff != Math.round((Math.fround((Math.fround(y) % Math.fround(((Math.fround(x) < Math.fround(y)) >>> 0)))) | 0))) | 0), (Math.asin((Number.MIN_VALUE >>> 0)) >>> 0)) | 0)), Math.fround(( + Math.ceil(-Number.MAX_SAFE_INTEGER))))) >>> 0), (Math.atan((( - (-0x100000000 | 0)) | 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-204645237*/count=868; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + Math.exp(( + (mathy1(((Math.abs((( ~ -0) | 0)) ? ( + x) : Math.fround(x)) | 0), ( + Math.pow((Math.log1p(y) >>> 0), Math.asin(Math.fround(x))))) | 0)))) ** ((Math.fround((Math.hypot((x >>> 0), (y >>> 0)) >>> 0)) === Math.fround((((y >>> 0) / x) ? ( + Math.imul(( + x), ( + Math.fround(( ~ Math.fround(x)))))) : Math.fround((Math.hypot(y, (Math.fround(( ~ Math.fround(y))) | 0)) ? y : 2**53))))) | 0)); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 0/0, 42, -0x0ffffffff, -0x100000000, 0x080000001, 0, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, Number.MIN_VALUE, -(2**53-2), 0x100000001, 1.7976931348623157e308, 0x100000000, Number.MAX_VALUE, 1/0, -0x07fffffff, 2**53, 0x07fffffff, -1/0, Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000000, 0.000000000000001, 2**53-2, -0, -(2**53+2), 1]); ");
/*fuzzSeed-204645237*/count=869; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ~ ( + ( + ( + ( + Math.sin((( - (mathy3((y | 0), x) >>> 0)) >>> 0))))))) >>> 0); }); testMathyFunction(mathy5, [false, null, '\\0', '/0/', ({valueOf:function(){return 0;}}), 0, (new String('')), [0], NaN, (function(){return 0;}), ({toString:function(){return '0';}}), (new Number(0)), objectEmulatingUndefined(), -0, 0.1, (new Number(-0)), undefined, 1, ({valueOf:function(){return '0';}}), (new Boolean(true)), (new Boolean(false)), true, /0/, '', '0', []]); ");
/*fuzzSeed-204645237*/count=870; tryItOut("o2.g0.a2.unshift(g1.g0.f2, b2, i2);");
/*fuzzSeed-204645237*/count=871; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.acos(x) ^ Math.hypot(Math.round((x >>> 0)), Math.hypot(x, Math.hypot(Math.exp(x), 2**53+2)))) | 0) >> Math.tanh((Math.imul((( + y) | 0), (Math.log((Math.fround(Math.sqrt(y)) > Math.round(y))) | 0)) | 0))); }); testMathyFunction(mathy3, [1/0, 1.7976931348623157e308, -0x100000001, -(2**53-2), 0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, 2**53, 2**53+2, -Number.MIN_VALUE, 0/0, Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, -1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, -(2**53+2), -0x07fffffff, 0.000000000000001, Math.PI, -0x080000001, 42, 0x100000000, -0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-204645237*/count=872; tryItOut("\"use strict\"; a1.splice(NaN,  /x/g );");
/*fuzzSeed-204645237*/count=873; tryItOut("testMathyFunction(mathy2, [Number.MAX_VALUE, 0x07fffffff, 1/0, 0x080000001, 2**53+2, -Number.MAX_VALUE, 0, 1, 42, 2**53, -0x100000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, Math.PI, 0x100000001, 1.7976931348623157e308, 0x100000000, -0x100000000, -0x080000001, 0/0, -(2**53), -0, -1/0, 0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=874; tryItOut("/*infloop*/for(var y in ((yield (uneval(let)).eval(\"v0 = false;\"))((x)((makeFinalizeObserver('tenured')),  '' )))){/*RXUB*/var r = r2; var s = \"\"; print(s.split(r));  }");
/*fuzzSeed-204645237*/count=875; tryItOut("/*tLoop*/for (let c of /*MARR*/[x, function(){}, ({x:3})]) { f2(this.i1);{this.e2 + m2;/*hhh*/function omwzqf(y, z){yield;}omwzqf(new RegExp(\"(?!\\u00b0)\", \"im\"), \"\\u373A\"); } }");
/*fuzzSeed-204645237*/count=876; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.tan((( ~ (( + ((((((Math.asinh(y) | 0) & ((y && Math.max(0x0ffffffff, Number.MIN_VALUE)) | 0)) | 0) >>> 0) !== (Math.max(y, Math.cosh((Math.abs((y >>> 0)) >>> 0))) >>> 0)) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy3, [0x07fffffff, -(2**53-2), 2**53, -0x100000000, 0x100000000, Math.PI, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, 0/0, 0.000000000000001, 42, Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -0x0ffffffff, 2**53-2, Number.MIN_VALUE, 0, -(2**53), 0x080000001, -0, 0x0ffffffff, -0x080000001, -Number.MAX_VALUE, -1/0, 2**53+2, -(2**53+2), 0x100000001, 1, 0x080000000, Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=877; tryItOut("\"use strict\"; a2.__proto__ = a0;");
/*fuzzSeed-204645237*/count=878; tryItOut("mathy2 = (function(x, y) { return Math.min(( + Math.cos(Math.imul((1 >>> 0), (mathy1((((x >>> 0) ? (x | 0) : y) | 0), (y | 0)) | 0)))), (( ~ mathy1(y, ( + Math.min(( + (Math.exp((x | 0)) % Math.pow(y, (Math.hypot(Math.fround(y), -Number.MAX_SAFE_INTEGER) | 0)))), ( + ((((((y >>> 0) - (Math.PI >>> 0)) >>> 0) | 0) != ((Math.fround(x) < -0x080000001) | 0)) | 0)))))) | 0)); }); testMathyFunction(mathy2, [-0x07fffffff, -1/0, -(2**53-2), -0x100000000, 0x100000000, 1.7976931348623157e308, 2**53-2, 0x080000000, Math.PI, -(2**53+2), 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 1, 2**53+2, -0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -0x080000000, -0, 2**53, Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE, 0/0, 42, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=879; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return Math.fround(Math.tanh(Math.fround(((Math.asin(Math.min(mathy0(Number.MIN_SAFE_INTEGER, (0x080000001 | 0)), Math.fround((x || -Number.MIN_SAFE_INTEGER)))) >>> 0) || (( - (-(2**53-2) + Math.cosh(Math.fround(( - Math.fround(x)))))) >= x))))); }); ");
/*fuzzSeed-204645237*/count=880; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[y\\\\S]|\\\\1\", \"gyi\"); var s = \"\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=881; tryItOut("mathy4 = (function(x, y) { return (((( ~ (Math.exp(Math.fround(( + mathy2((-0x100000001 | 0), ( + (0x100000001 < x)))))) | 0)) | 0) | 0) , Math.min((Math.min((Math.max((( - (x >>> 0)) | 0), Math.PI) | 0), x) | 0), Math.sign((( ! (( - (-Number.MIN_VALUE | 0)) | 0)) | 0)))); }); testMathyFunction(mathy4, [1, 42, -Number.MIN_VALUE, -(2**53), -0x100000001, -Number.MAX_VALUE, -0x080000000, Number.MAX_VALUE, 0x100000000, 0, 0x080000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -1/0, Number.MIN_VALUE, -0x0ffffffff, 1/0, 2**53, 0.000000000000001, 0/0, -0x100000000, 0x100000001, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=882; tryItOut("g1.h1.getOwnPropertyNames = (function mcc_() { var ntzmiu = 0; return function() { ++ntzmiu; f1(/*ICCD*/ntzmiu % 8 == 3);};})();");
/*fuzzSeed-204645237*/count=883; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(( - (( + ((y | 0) || (( + (( + Math.fround((Math.fround(y) , Math.fround(-(2**53+2))))) === ( + ( + Math.log2(( + (-0x100000000 != (x >>> 0)))))))) >>> 0))) | 0))); }); testMathyFunction(mathy0, [({valueOf:function(){return '0';}}), false, '\\0', -0, /0/, null, [0], '0', (new Boolean(false)), true, '', 0, [], ({valueOf:function(){return 0;}}), (new Boolean(true)), (new Number(-0)), '/0/', ({toString:function(){return '0';}}), 1, objectEmulatingUndefined(), NaN, (new Number(0)), (function(){return 0;}), 0.1, undefined, (new String(''))]); ");
/*fuzzSeed-204645237*/count=884; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(v1, g2);");
/*fuzzSeed-204645237*/count=885; tryItOut("\"use strict\"; g0.v0 = null;");
/*fuzzSeed-204645237*/count=886; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ! Math.fround(mathy2((((Math.asinh((((Math.hypot(Math.fround(x), x) === (( + mathy2(( + -(2**53-2)), y)) | 0)) | 0) | 0)) | 0) >= Math.fround(mathy3(Math.fround(x), Math.fround(x)))) >>> 0), (( + Math.min(( + ( + Math.pow(( + x), ( + x)))), x)) ^ Math.imul(Math.hypot((Math.sqrt((y | 0)) | 0), Math.log1p(0x080000000)), mathy1(( + ( + (( + (((x >>> 0) === (x >>> 0)) >>> 0)) ? ( + y) : (y >>> 0)))), ( + y)))))))); }); testMathyFunction(mathy4, [0x100000000, 2**53, -0, 0, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 0x080000000, 1/0, -0x0ffffffff, 0.000000000000001, -0x080000001, 1, 0x080000001, -0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, -(2**53), 0x100000001, 42, 2**53-2, -0x080000000, -0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=887; tryItOut("mathy4 = (function(x, y) { return ((Math.log1p(((Math.log1p((y | 0)) <= (x * Math.fround(( + mathy3(y, y))))) < (Math.imul((( + ( + y)) | 0), 2**53+2) | 0))) | 0) ? mathy3((Math.pow(Math.fround((((mathy3(mathy0(y, y), x) | 0) >>> 0) | y)), ( + Math.fround(( ! Math.fround((( ~ Math.fround(mathy0((x >>> 0), (x >>> 0)))) >>> 0)))))) | 0), (Math.min(((x * y) | 0), x) | 0)) : (Math.atan2(mathy0(( + x), Math.asin(Math.hypot(y, (((y | 0) , x) | 0)))), (( + Math.cos(( + Math.round(( ! (Math.imul((y | 0), x) | 0)))))) | 0)) | 0)); }); testMathyFunction(mathy4, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, ({x:3}), 0, 0, 0, ({x:3}), x, x, 0, 0, ({x:3}), x, ({x:3}), ({x:3}), ({x:3}), x, ({x:3}), ({x:3}), ({x:3}), x, ({x:3}), 0, ({x:3}), x, ({x:3}), ({x:3}), 0, ({x:3}), ({x:3}), x, ({x:3}), 0, ({x:3}), ({x:3}), 0, 0, ({x:3}), 0, 0, ({x:3}), 0, x, 0, x, 0, ({x:3}), 0, ({x:3}), x, x, 0, ({x:3}), x, x, 0, 0, ({x:3}), ({x:3}), ({x:3}), ({x:3}), 0, ({x:3}), x, x, x, x, x, 0, ({x:3}), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, ({x:3}), x, x, 0, x, ({x:3}), 0, x, x, 0, ({x:3})]); ");
/*fuzzSeed-204645237*/count=888; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.cbrt((Math.min((( - (y | 0)) | 0), ((( ! Math.log1p((-0x100000001 >>> 0))) == (Math.fround((( + (x >>> 0)) ? (( ~ (y >>> 0)) >>> 0) : Math.tan(y))) ? (y | 0) : -0x0ffffffff)) | 0)) | 0)); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, -(2**53-2), 1/0, 0x100000001, 42, -0x07fffffff, 0x080000000, -0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0/0, -(2**53+2), 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, 1, 0x07fffffff, -1/0, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, -0, -0x0ffffffff, 0x080000001, 0, 2**53+2, Number.MAX_VALUE, 0.000000000000001, 2**53]); ");
/*fuzzSeed-204645237*/count=889; tryItOut("for (var v of this.v0) { try { print(undefined.throw\u000c( '' ) & x); } catch(e0) { } /*ODP-3*/Object.defineProperty(o2.o1.h0, new String(\"5\"), { configurable: (x % 20 == 0), enumerable: true, writable: (x % 9 == 8), value: this.t0 }); }arguments.callee.arguments = x;");
/*fuzzSeed-204645237*/count=890; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.sinh((( ! Math.min((0 | 0), x)) << ( + ( ! (mathy1(x, (( - x) >>> 0)) | 0))))) < ( - Math.trunc((( ~ ((2**53-2 < Math.sin(x)) | 0)) | 0)))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 42, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000001, 0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, -0x100000001, -0x080000000, -(2**53-2), 2**53, 0x07fffffff, Math.PI, -Number.MIN_VALUE, -0x100000000, -1/0, 0x100000001, 0/0, 0x080000000, -(2**53), 1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -(2**53+2), 0x080000001, Number.MIN_VALUE, -0, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=891; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + Math.asin(( ~ y))) ? ((Math.hypot(((( ! (y | 0)) | 0) >>> 0), (Math.hypot(( + mathy0(Math.atan2(x, y), ( + x))), 0.000000000000001) >>> 0)) >>> 0) & ((x | 0) >= (((Math.asinh((-Number.MAX_VALUE | 0)) >>> 0) , Math.atanh(-Number.MAX_VALUE)) !== Math.fround(Math.atan(Math.fround(y)))))) : Math.fround((Math.fround(( + (x | 0))) >= Math.fround(Math.atan2(((Math.max(((-0x07fffffff < ( + -Number.MIN_SAFE_INTEGER)) >>> 0), mathy3(x, x)) != x) >>> 0), ((mathy0(y, (Math.hypot((Math.trunc((x | 0)) | 0), ( + -(2**53-2))) | 0)) | 0) >>> 0)))))); }); testMathyFunction(mathy5, [1/0, 0.000000000000001, 2**53-2, 2**53, -(2**53+2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 42, -1/0, 0/0, 1.7976931348623157e308, 1, 2**53+2, 0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -0x100000001, -0x100000000, -0x07fffffff, 0, Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_VALUE, 0x0ffffffff, 0x080000001, -0x080000001, Math.PI]); ");
/*fuzzSeed-204645237*/count=892; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ! (( ~ Math.pow((mathy0((y >>> 0), ( ! y)) >>> 0), 1)) | 0)); }); ");
/*fuzzSeed-204645237*/count=893; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ((((Math.round(1.7976931348623157e308) >>> 0) ** ((( + x) , (Math.round(-(2**53-2)) | 0)) >>> 0)) >>> ( + ( + ( + Number.MAX_SAFE_INTEGER)))) | 0)); }); ");
/*fuzzSeed-204645237*/count=894; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.log10(((( + Math.exp(Math.min((y >>> 0), (y >>> 0)))) * ( + Math.hypot(( ! Math.fround(y)), Math.fround(( + Math.min(( + ( - Math.min(Math.fround(x), ( ! x)))), (Math.fround(Math.min((-0 | 0), (-0x080000000 >>> 0))) - -0x07fffffff))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x100000000, 0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 0.000000000000001, 0x080000000, -0x080000001, 0x0ffffffff, 2**53, -Number.MIN_VALUE, 0x100000001, -(2**53), -0, 0x07fffffff, 42, Math.PI, -0x07fffffff, 1/0, 2**53+2, Number.MIN_VALUE, 0, 1, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0x100000000, 0/0, -1/0, -(2**53-2), -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-204645237*/count=895; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.expm1(( ! y))) / Math.cos((Math.trunc(Math.fround((Math.hypot(Math.fround((Math.fround(y) ? (x | 0) : Math.fround(x))), (Math.hypot(Math.tan(Number.MIN_VALUE), x) >>> 0)) >>> 0))) | 0))); }); testMathyFunction(mathy0, [-0, -0x080000000, 0x07fffffff, 0x080000001, Math.PI, 1/0, -0x07fffffff, -1/0, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53-2, -0x100000000, 2**53, -0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), -(2**53+2), -Number.MAX_VALUE, 42, Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, -0x100000001, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=896; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[-19, {}, -19, arguments.callee, {}, arguments.callee]) { a1.sort((function() { try { print(p1); } catch(e0) { } try { a2 = r2.exec(s2); } catch(e1) { } try { g0.offThreadCompileScript(\"mathy4 = (function(x, y) { return Math.atanh(Math.max(( + Math.cosh(( + mathy3(x, x)))), (mathy3(Math.fround(Math.log10(( + 1))), Math.hypot(Math.sign(y), (mathy0((-0x100000001 | 0), (Math.atan2(y, Math.hypot(x, y)) >>> 0)) | 0))) >>> 0))); }); testMathyFunction(mathy4, [1, -1/0, -0x100000000, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0x100000001, -(2**53-2), 0/0, -Number.MAX_VALUE, 2**53+2, 0x080000001, 0x100000000, Number.MAX_VALUE, Math.PI, -0x100000001, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, 2**53, -0x080000001, 1/0, -0x07fffffff, 0x080000000, 42, -Number.MIN_SAFE_INTEGER, -(2**53)]); \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: w })); } catch(e2) { } this.v1 = a0[16]; return i2; })); }");
/*fuzzSeed-204645237*/count=897; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=898; tryItOut("\"use strict\"; f0 + '';");
/*fuzzSeed-204645237*/count=899; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.tanh(Math.fround(Math.expm1(Math.fround(Math.fround((-0x0ffffffff & mathy2(( + Math.hypot(y, ( + (Math.asin(Math.fround(1)) >>> 0)))), (Math.sign(y) >>> 0)))))))); }); testMathyFunction(mathy5, [0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -Number.MIN_VALUE, -0, 1.7976931348623157e308, 0/0, 0x0ffffffff, 0x100000000, Number.MAX_VALUE, 0, -(2**53), 42, Math.PI, -Number.MAX_VALUE, -0x07fffffff, 1, -0x100000000, 2**53, 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), 1/0, 0.000000000000001, 0x080000000, 0x080000001]); ");
/*fuzzSeed-204645237*/count=900; tryItOut("const y, c = /*MARR*/[0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, new Number(1), 0x0ffffffff, new Number(1), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, new Number(1), 0x0ffffffff, new Number(1), new Number(1), 0x0ffffffff, new Number(1), new Number(1), new Number(1), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, new Number(1), new Number(1), new Number(1), 0x0ffffffff, new Number(1), 0x0ffffffff, new Number(1), new Number(1), 0x0ffffffff, new Number(1), new Number(1), new Number(1), new Number(1), 0x0ffffffff, new Number(1), 0x0ffffffff].sort(((eval).apply).bind), x = \"\\uD69D\", x, hutrjj, mdogyr, var r0 = x ^ 7; var r1 = 5 & r0; var r2 = 8 / x; var r3 = r1 * r1; var r4 = x | r3; print(r2); var r5 = r4 | 5; var r6 = x + 8; r3 = x % 2; r0 = r4 + r1; var r7 = 3 ^ r0; r7 = 9 / 2; r3 = 0 - 8; r3 = r3 / 1; r0 = r2 | r7; r2 = r6 % 8; var r8 = 8 | 7; var r9 = r8 / r6; var r10 = 1 % r5; var r11 = r5 & 8; var r12 = 9 & r10; r10 = 9 & 2; print(r6); var r13 = r8 ^ r5; var r14 = r4 * 5; var r15 = r8 + 3; r8 = 3 + 7; var r16 = r12 - 1; r11 = 8 % 4; , ktxfws;print(x);");
/*fuzzSeed-204645237*/count=901; tryItOut("mathy2 = (function(x, y) { return (Math.min(( + Math.atanh(Math.tan(( + (y & Math.sqrt(y)))))), Math.fround(Math.pow(((((( + -Number.MIN_VALUE) ? ( + x) : ( + y)) | 0) && (x | 0)) | 0), (Math.max((Math.hypot(Math.atan2((Number.MIN_SAFE_INTEGER ** y), ( + (Math.fround((y >> x)) >= Math.fround(y)))), (Math.imul(0x100000001, y) << ((y >= x) >>> 0))) | 0), (Math.hypot(( + -0x100000000), (x | 0)) | 0)) | 0)))) | 0); }); ");
/*fuzzSeed-204645237*/count=902; tryItOut("t1 = a1[v0];");
/*fuzzSeed-204645237*/count=903; tryItOut("mathy1 = (function(x, y) { return ( + Math.log1p(Math.fround((Math.fround(y) >>> Math.fround(( + ( ~ ( + (mathy0(y, y) | 0))))))))); }); ");
/*fuzzSeed-204645237*/count=904; tryItOut("for (var p in e1) { try { v2 = t2.byteOffset; } catch(e0) { } /*ODP-2*/Object.defineProperty(i0, \"__parent__\", { configurable: true, enumerable: false, get: (function mcc_() { var cloiil = 0; return function() { ++cloiil; if (/*ICCD*/cloiil % 3 == 0) { dumpln('hit!'); try { s0 += s2; } catch(e0) { } try { i1 + ''; } catch(e1) { } print(g0.t2); } else { dumpln('miss!'); o0.v2 = true; } };})(), set: (function() { try { this.v2 = Object.prototype.isPrototypeOf.call(o2.b1, this.s1); } catch(e0) { } for (var v of this.a2) { try { b1.__proto__ = e2; } catch(e0) { } this.t2 = new Int8Array(g2.t2); } return this.e1; }) }); }");
/*fuzzSeed-204645237*/count=905; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[0]) = ((+(0.0/0.0)));\n    d1 = (d1);\n    {\n      return +((1025.0));\n    }\n    return +((Float32ArrayView[2]));\n  }\n  return f; })(this, {ff: Date.prototype.setFullYear}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53+2), -(2**53), -0, -Number.MIN_VALUE, -0x07fffffff, 2**53, 0x080000001, 0x080000000, 2**53-2, Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE, -(2**53-2), -0x100000000, 0x07fffffff, -0x080000000, 0, 0.000000000000001, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, 1/0, 1, 42, -0x0ffffffff, 0x0ffffffff, 2**53+2, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-204645237*/count=906; tryItOut("\"use strict\"; t1[x] = \"\\u7723\" = \"\\u4F90\";t2 = new Float64Array(this.o1.o1.a0);");
/*fuzzSeed-204645237*/count=907; tryItOut("L: o1.e0.add(o1.b2);");
/*fuzzSeed-204645237*/count=908; tryItOut("/*ADP-2*/Object.defineProperty(a2, 13, { configurable: true, enumerable: true, get: (function() { try { this.v0 = Object.prototype.isPrototypeOf.call(e1, o1.s2); } catch(e0) { } try { /*MXX2*/g0.JSON.stringify = this.m0; } catch(e1) { } a2.pop(); return this.t1; }), set: (function(j) { if (j) { v2 = evalcx(\"/* no regression tests found */\", g0); } else { try { t0 = new Uint8ClampedArray(t1); } catch(e0) { } try { a2.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { var r0 = a5 + a0; var r1 = 8 + a3; a7 = 8 ^ a5; var r2 = 2 + 6; var r3 = a2 + a6; var r4 = a6 - a7; var r5 = r3 | a6; var r6 = r2 * 6; a0 = 5 % r6; var r7 = 8 - a8; r2 = x | a8; var r8 = 5 % a2; var r9 = r4 * 5; a6 = a3 / r8; var r10 = 3 * r5; var r11 = r3 % a3; var r12 = 9 - r6; var r13 = 4 % r12; var r14 = r13 + 0; a4 = r5 + r14; r1 = r7 | r4; var r15 = 6 | 8; var r16 = r1 - r13; a3 = r4 / r14; var r17 = r16 + a5; var r18 = 2 + r2; var r19 = r15 * a3; a0 = r9 - r8; var r20 = r9 % r1; var r21 = 3 / a1; var r22 = r21 + 9; a2 = 5 / 8; var r23 = r4 ^ x; a1 = 5 | a5; var r24 = a0 % r16; var r25 = r11 - r3; var r26 = x & r10; var r27 = r22 * r20; var r28 = r5 & a5; var r29 = r23 - a8; print(a6); var r30 = r5 + r4; r4 = a0 - a4; var r31 = 1 + r21; var r32 = r0 + r7; var r33 = r8 % r4; var r34 = 6 & r13; var r35 = 5 | a3; var r36 = 3 ^ r6; var r37 = r29 ^ 1; var r38 = 0 + r11; var r39 = 6 * 2; var r40 = r35 / 8; var r41 = 4 / 7; var r42 = a3 % r38; r37 = a7 * r29; r21 = r13 % 0; var r43 = r3 & r13; print(a8); r20 = r5 & 3; var r44 = r0 / r27; var r45 = a1 / r3; var r46 = a4 * r6; var r47 = a6 | r43; r24 = 6 * 5; var r48 = r29 + 2; r34 = 0 & 1; var r49 = r13 % r44; var r50 = 9 ^ 7; var r51 = r26 + 1; var r52 = 3 & 6; var r53 = r32 & 1; var r54 = a5 / r15; r51 = r45 - r28; var r55 = 3 & r7; var r56 = r39 | r44; var r57 = r44 & r24; var r58 = r19 & r16; r9 = 0 / 8; var r59 = r5 | r48; var r60 = 8 - a2; var r61 = r13 * r7; var r62 = r7 ^ r4; var r63 = r43 & r9; var r64 = r59 | r50; print(r48); r41 = 1 ^ 9; var r65 = r9 - r17; var r66 = 8 & 7; var r67 = 7 - r64; var r68 = 8 * r17; var r69 = r24 - 2; print(r40); var r70 = r5 / 9; var r71 = r40 ^ r14; r70 = r25 ^ r32; var r72 = r51 | 0; return a8; }); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(f0, a2); } catch(e2) { } t1 = a0[6]; } }) });");
/*fuzzSeed-204645237*/count=909; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 1125899906842625.0;\n    return (((0x19cdf845)+(-0x8000000)+(!(-0x3f4a01d))))|0;\n  }\n  return f; })(this, {ff: (x, []) => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    return (((i0)+((((0xed38a6a4)-((((0x84dde0d7)-(0xfed62542))>>>((0xfb88b834)-(0xffffffff))) < (0x21825724)))>>>((!(0xfa7f7099))*-0x1401e)))))|0;\n  }\n  return f;}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [1/0, -0x080000001, 0/0, -Number.MAX_VALUE, 0x080000001, 1, 0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, -0, 2**53, Math.PI, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, Number.MIN_VALUE, 2**53+2, -0x07fffffff, 2**53-2, -(2**53-2), 0.000000000000001, -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 0x080000000, 0, 0x0ffffffff, 42]); ");
/*fuzzSeed-204645237*/count=910; tryItOut("x = p1;");
/*fuzzSeed-204645237*/count=911; tryItOut("mathy3 = (function(x, y) { return (Math.hypot(( + ( ~ (((Math.min(Math.fround(Math.expm1((y >>> 0))), mathy0((mathy2(Math.fround(y), x) >>> 0), 1.7976931348623157e308)) >>> 0) ? Math.fround(( ! Math.fround(Math.atan2(Math.fround(Math.sinh(y)), (Math.pow(y, y) ** y))))) : ( + mathy0((x | 0), ( - Math.atan2(x, y))))) | 0))), Math.fround(( + ( ~ ( + Math.fround(((( - (y >>> 0)) | 0) < Math.fround((((x << ( + ( ~ y))) >>> 0) % (x >>> 0)))))))))) >>> 0); }); ");
/*fuzzSeed-204645237*/count=912; tryItOut("\"use strict\"; print(v1);");
/*fuzzSeed-204645237*/count=913; tryItOut("mathy1 = (function(x, y) { return ( ~ ((((((Math.expm1(x) | 0) >= 0x080000000) | 0) > x) | 0) <= (((Math.fround(( ! (mathy0(Math.fround((-Number.MIN_SAFE_INTEGER > -Number.MIN_VALUE)), x) >>> 0))) / (mathy0((x >>> 0), ( + Math.acos((( + (Math.min(y, y) >>> 0)) >>> 0)))) >>> 0)) | 0) | 0))); }); testMathyFunction(mathy1, [0x080000001, -0x0ffffffff, -0, -(2**53), 42, Math.PI, 2**53, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -1/0, 0/0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, 0x100000000, -0x100000001, 1/0, 0, -(2**53+2), 0x080000000, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, 1, 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53-2]); ");
/*fuzzSeed-204645237*/count=914; tryItOut("a1 = /*FARR*/[\"\\uE590\", , , .../*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 4., 4., objectEmulatingUndefined(), 4., 4.], .../*MARR*/[new String('q'), new String('q'), new Number(1.5), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1.5), new String('q'), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5)], (q => q).call];");
/*fuzzSeed-204645237*/count=915; tryItOut("\"use strict\"; v1 = evaluate(\"a0.forEach(v1);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 == 0), sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-204645237*/count=916; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d1));\n    return +((d0));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=917; tryItOut("(void schedulegc(g0.g1))\n");
/*fuzzSeed-204645237*/count=918; tryItOut("p1 + a2;");
/*fuzzSeed-204645237*/count=919; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((Math.round(Math.fround(( - ( + ( + Math.acosh(( + y))))))) >= Math.cbrt(Math.atan2(( ~ Math.fround(x)), ( + ( + Math.ceil(Math.fround((Math.fround(-(2**53+2)) >= Math.fround(Math.fround(Math.pow(x, -0x07fffffff))))))))))) >>> 0); }); testMathyFunction(mathy2, [1, 2**53+2, -0, -1/0, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), -Number.MIN_VALUE, 0x07fffffff, Number.MIN_VALUE, 2**53, -0x0ffffffff, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, -(2**53+2), 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 42, 0x080000001, -0x100000000, -0x080000001, 0.000000000000001, Math.PI, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, 0/0, 2**53-2, 0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=920; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[objectEmulatingUndefined(), 0.1, objectEmulatingUndefined(), this, this, this, this, this, objectEmulatingUndefined(), this, 0.1, this, arguments.callee, this, arguments.callee, objectEmulatingUndefined()]) { v2 = t1.length; }");
/*fuzzSeed-204645237*/count=921; tryItOut("\"use strict\"; print(t2);");
/*fuzzSeed-204645237*/count=922; tryItOut("a1.sort((function mcc_() { var dpaqhi = 0; return function() { ++dpaqhi; if (/*ICCD*/dpaqhi % 10 == 5) { dumpln('hit!'); e2.toString = f2; } else { dumpln('miss!'); try { v0 = (v1 instanceof this.s0); } catch(e0) { } try { i2.send(o1.a2); } catch(e1) { } g0.t2[({valueOf: function() { /*vLoop*/for (var gxctkz = 0; gxctkz < 53; ++gxctkz) { const c = gxctkz; a1.sort((function() { try { e2.has(i2); } catch(e0) { } try { t0[3] = i0; } catch(e1) { } v1 = a0.reduce, reduceRight((function(a0, a1, a2, a3, a4, a5) { var r0 = 5 & 1; var r1 = r0 % a2; c = 9 % a5; var r2 = 9 * a0; var r3 = r1 - a0; var r4 = a0 + 9; var r5 = 2 ^ a4; a4 = r2 / c; var r6 = 9 ^ x; var r7 = 4 - r5; var r8 = r7 / 3; return a1; }), (delete c.c)); return this.i1; }), b2); } return 9; }})]; } };})());");
/*fuzzSeed-204645237*/count=923; tryItOut("\"use strict\"; i2 + '';");
/*fuzzSeed-204645237*/count=924; tryItOut("\"use strict\"; for (var v of v0) { try { a0.forEach((function() { for (var j=0;j<68;++j) { f2(j%4==0); } })); } catch(e0) { } m0.set((4277), v0); }");
/*fuzzSeed-204645237*/count=925; tryItOut("if((x % 6 == 0)) {print(x); } else  if (/*MARR*/[ /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/ ,  /x/g ,  /x/ ,  /x/g ,  /x/g , new String(''),  /x/ ,  /x/g ,  /x/g ,  /x/ , new String(''),  /x/g ,  /x/ ,  /x/ ,  /x/ , new String(''),  /x/g , new String(''),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new String(''),  /x/ , new String(''),  /x/g ,  /x/ , new String(''),  /x/ , new String(''), new String(''), new String(''), new String(''),  /x/ ,  /x/ , new String(''),  /x/g , new String(''), new String(''),  /x/ ,  /x/g ,  /x/g ,  /x/g ].some(function (d) { for (var v of m2) { try { m1 = new WeakMap; } catch(e0) { } Array.prototype.unshift.call(g0.a0, f2); } } , x ^ new EvalError.prototype.toString())) a2[12] = this.__defineSetter__(\"window\", (false).bind());");
/*fuzzSeed-204645237*/count=926; tryItOut("(10);function x(y = /*RXUE*//[^]{0,2}/g.exec(window)) { yield (void version(170)) } m0 = new Map(g1.o0.h2);");
/*fuzzSeed-204645237*/count=927; tryItOut("/*\n*/Array.prototype.sort.apply(o0.a2, [(function() { this.g2.f0.toSource = (function() { try { p2 + b0; } catch(e0) { } try { this.a2[4] = o2.s2; } catch(e1) { } /*MXX3*/g2.WeakMap = g1.WeakMap; return o2.h2; }); throw t0; }), m0, g1]);\nprint(x);\n");
/*fuzzSeed-204645237*/count=928; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-204645237*/count=929; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=930; tryItOut("\"use strict\"; /*RXUB*/var r = /.|\\s{4}|.|(?!(?:[^]){2,}){2,}|\\D|[\\t-\\'\udcc1\\d\\b-\\cW]*|\\b+?.|\\1|[^]+?\\3|\\B|(?=(\\r{0,}.*)[^\\u00B2\\w]\\b+)+?/m; var s = \"XXXXXXXXX\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-204645237*/count=931; tryItOut("Object.defineProperty(this, \"this.v2\", { configurable: (x % 54 != 36), enumerable: true,  get: function() {  return g2.eval(\"Array.prototype.splice.call(a1, 8, 10);\"); } });");
/*fuzzSeed-204645237*/count=932; tryItOut("/*RXUB*/var r = new RegExp(\"(?!.|(?:\\\\1)*?)\", \"yi\"); var s = \"\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-204645237*/count=933; tryItOut("mathy2 = (function(x, y) { return (Math.imul(( + (Math.sin(Math.fround(( ~ ( + (( + Math.fround(((y >>> 0) >= (mathy0((-0x080000001 >>> 0), ( + Math.fround(Math.cos(Math.fround(y))))) | 0)))) - ( + (x + Math.fround(( - y))))))))) >>> 0)), (Math.fround((Math.fround(( ~ ( + x))) ? Math.fround(( + (Math.hypot(( + Math.tan(( + x))), ( + Math.atanh(( + ( - y))))) >>> 0))) : Math.min(( + Math.hypot(Math.fround(x), ( + y))), ( + Math.imul(( + Math.hypot(x, -(2**53+2))), (Math.fround(mathy1(Math.fround(((( + x) ? ( + -Number.MIN_VALUE) : ( + -Number.MIN_SAFE_INTEGER)) >>> 0)), Math.fround(x))) >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy2, [-0x100000000, -(2**53+2), 2**53+2, 0x080000001, Math.PI, 2**53-2, -1/0, Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -(2**53-2), -0x080000001, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, 1, 0, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -(2**53), 0x100000001, 1/0, 0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, -0, -0x0ffffffff, 2**53, 0/0]); ");
/*fuzzSeed-204645237*/count=934; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -32769.0;\n    var d3 = -1.125;\n    var i4 = 0;\n    var d5 = 4.835703278458517e+24;\n    {\n      i0 = (i4);\n    }\n    d5 = ((0x523ce6cb) ? (d2) : (d3));\n    (Int32ArrayView[0]) = ((!((0xd137b543) < (0x780a5a0))));\n    i4 = (0xd7b5787a);\n    return +((-4611686018427388000.0));\n    {\n      (Uint16ArrayView[4096]) = ((i4)-((-70368744177665.0) >= (+atan2((((Float32ArrayView[((!(0xe64bf1b4))-((0x41c81367) > (0x3dc878a7))) >> 2]))), ((1.1805916207174113e+21)))))+(x.throw((/*FARR*/[, \"\\uEA20\", , new RegExp(\"\\\\3\", \"y\"), false, /[^]/gm, true, -8,  '' , , null, -4,  '' , ...[], [1,,], 7, x, , 26, , -2, ...[], ...[]].sort(Date.prototype.getUTCHours)).throw((yield window)))));\n    }\n    d5 = (+/*FFI*/ff(((d3)), ((abs((((!((((0xfb7c02ee)) << ((0xffffffff))) >= (((0x55c6d777)) | ((0x8d21b572)))))) ^ ((0x473a0054) % (0x509446a8))))|0))));\n    d5 = (d5);\n    d2 = (((NaN)) * ((Float32ArrayView[0])));\n    (Float64ArrayView[((0xffffffff)) >> 3]) = (((0xba5400bb) ? (281474976710655.0) : (+(0.0/0.0))));\n    d2 = (d3);\n    i4 = ((16.0) <= (Infinity));\n    {\n      d2 = (+/*FFI*/ff(((Int16ArrayView[(((NaN) <= (((d2)) / ((+(((-0x8000000))>>>((0xfb4c45d6)))))))*-0xaed06) >> 1]))));\n    }\n    {\n      i1 = (window);\n    }\n    i4 = (0xfd1d04c0);\n    d5 = (1.0);\n    {\n      switch ((~~(+(~((0xf83565fb)-(0xb41f9ea1)))))) {\n        case 1:\n          i1 = (0xfb1ab583);\n          break;\n        default:\n          return +((d5));\n      }\n    }\n    i0 = (i1);\n    d5 = (9.44473296573929e+21);\n    d2 = (+(1.0/0.0));\n    return +((+((d3))));\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 0, -Number.MIN_VALUE, -0x100000000, -(2**53), -Number.MAX_VALUE, 0x100000001, 1, Math.PI, 0x100000000, -0x07fffffff, -(2**53-2), 2**53-2, -(2**53+2), 0/0, -0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -0, 42, 1/0, -0x080000000, -0x100000001, 2**53, -1/0, 0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=935; tryItOut("o1.s0 += 'x';");
/*fuzzSeed-204645237*/count=936; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 4611686018427388000.0;\n    switch ((imul((0x1c475632), (i1))|0)) {\n      case -2:\n        i2 = ((0xf951a96d) ? ((((window = {}))|0)) : (0xf9961b91));\n        break;\n      case 0:\n        i1 = (0xce2b2df5);\n        break;\n      case 0:\n        i1 = (!(0xbf75388a));\n        break;\n      case -3:\n        (Float64ArrayView[((-0x8000000)-(0xd9ddb469)) >> 3]) = ((((3.8685626227668134e+25)) % ((+(Math.log2(( + Math.atan2((Math.tanh(Number.MAX_SAFE_INTEGER) | 0), Math.fround(( ! (Math.log1p((x >>> 0)) >>> 0)))))))))));\n      case 0:\n        (Float64ArrayView[(((-9223372036854776000.0) > (-((+(1.0/0.0)))))+(i2)) >> 3]) = ((d3));\n        break;\n    }\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: /*FARR*/[(function(x, y) { return (Math.pow(( ~ y), y) | 0); }), window, x,  /x/g , [,,]].map}, new ArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=937; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=938; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.imul(Math.fround(Math.max(Math.acosh(( ! Math.sin(Math.fround(1)))), y)), ( - ((Math.cbrt(-0x100000001) | 0) | 0)))), Math.fround((mathy1(((Math.sinh(((mathy0((y >>> 0), ( + mathy0(y, 0x07fffffff))) >>> 0) >>> 0)) >>> 0) >>> 0), ((x ** Math.pow(( + Math.max(x, (y >>> 0))), ( ~ Math.fround(Math.atan2(Math.fround(y), Math.fround(( + (( + y) ^ (-1/0 >>> 0))))))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[Math.PI, Math.PI, (void 0), (void 0), Math.PI, (void 0), new Boolean(true), new Boolean(true), new Boolean(true), Math.PI, Math.PI, new Boolean(true), (void 0), (void 0), (void 0), Math.PI, (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, (void 0), Math.PI, Math.PI, new Boolean(true), (void 0), Math.PI, Math.PI, Math.PI, new Boolean(true), (void 0), (void 0), (void 0), new Boolean(true), Math.PI, (void 0), new Boolean(true), Math.PI, new Boolean(true), new Boolean(true), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(true), Math.PI, (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(true), Math.PI, Math.PI, Math.PI, (void 0), new Boolean(true), (void 0), (void 0), Math.PI, (void 0), (void 0), new Boolean(true), (void 0), (void 0), new Boolean(true), new Boolean(true), Math.PI, new Boolean(true), new Boolean(true), new Boolean(true), Math.PI, (void 0), Math.PI, (void 0), (void 0), (void 0), Math.PI, (void 0), (void 0), new Boolean(true), Math.PI, (void 0), Math.PI, Math.PI, new Boolean(true), Math.PI, (void 0), Math.PI, new Boolean(true), Math.PI, new Boolean(true), Math.PI, (void 0), Math.PI, Math.PI, new Boolean(true), new Boolean(true), Math.PI, Math.PI, new Boolean(true), Math.PI, (void 0), (void 0)]); ");
/*fuzzSeed-204645237*/count=939; tryItOut("m1.delete(s1);");
/*fuzzSeed-204645237*/count=940; tryItOut("m1 = new Map(g2);");
/*fuzzSeed-204645237*/count=941; tryItOut("v0 = Object.prototype.isPrototypeOf.call(f1, h1);");
/*fuzzSeed-204645237*/count=942; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var tan = stdlib.Math.tan;\n  var exp = stdlib.Math.exp;\n  var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var sin = stdlib.Math.sin;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        {\n          i1 = (i1);\n        }\n      }\n    }\n    i1 = (0x3ff67453);\n    i1 = (0x896d0610);\n    {\n      i1 = ((((Uint16ArrayView[2])) << ((0xffe7f112))) != (~~(((d0)) * ((+/*FFI*/ff())))));\n    }\n    d0 = (((Float64ArrayView[((0x7830bdee)+(i1)) >> 3])) / ((d0)));\n    (Uint32ArrayView[4096]) = ((0x58bf640a) / ((((Float64ArrayView[4096]))-(0x25653f09))>>>(((-0x8000000) ? ((((0xf8ab31ef))>>>((-0x8000000)))) : ((0xfaf920a8) ? (0xff2c1513) : (-0x6afe660)))-(-0x8000000))));\n    (Float32ArrayView[((i1)-(0xffffffff)+((((i1))|0))) >> 2]) = ((+/*FFI*/ff(((((!((0xffffffff) == ((-0x68d4a*(i1))>>>((0x3865543d)-(0xffffffff)))))) ^ ((0xffdcc158)*0x3153a))), ((+(-1.0/0.0))), ((d0)), ((+/*FFI*/ff(((Int32ArrayView[1])), ((-32769.0)), ((295147905179352830000.0)), ((+abs(((Float64ArrayView[0]))))), ((~~(9223372036854776000.0))), ((-1.5)), ((-1099511627776.0)), ((-2097153.0)), ((-36893488147419103000.0)), ((-562949953421313.0))))), ((~~(+atan2(((Float64ArrayView[1])), ((d0)))))), ((1.00390625)), ((9.44473296573929e+21)), ((513.0)), ((+tan(((-4.835703278458517e+24))))))));\n    i1 = ((0x45b55918));\n    {\n      d0 = (((d0)) - ((+exp(((((+((((0x74ea8020)))>>>((0x12f85560) % (-0x8000000))))) - ((+(0x5cca2299)))))))));\n    }\n    d0 = (-4.722366482869645e+21);\n    (Uint8ArrayView[((i1)*0x72ec8) >> 0]) = ((Int16ArrayView[((/*FFI*/ff(((((0xffffffff))|0)), ((((-5.0)))), ((imul(((0xf997a790) ? (0xffffffff) : (0x1c94224)), (0x95507d15))|0)), ((+(((0xf998cbbc) ? (3.094850098213451e+26) : (4503599627370495.0))))), ((((Int32ArrayView[2])) >> ((-0x8000000)-(0xb6f5cf2b)+(0x43f2dd9d)))), ((+atan2(((4611686018427388000.0)), ((-36028797018963970.0))))))|0)) >> 1]));\n    d0 = ( /* Comment */eval(\"/\\\\2{8589934593}|[^\\\\x4d\\u000c-\\\\\\u93f7]|\\\\3*/gyi\"));\n    (Float32ArrayView[((((-2305843009213694000.0) < (1.001953125)) ? (((((-9.671406556917033e+24)) - ((-9.671406556917033e+24))))) : (0xff8cd938))-(((-0xa139f*(i1))|0))) >> 2]) = ((NaN));\n    i1 = (i1);\n    i1 = ((0xac9fb3d9));\n    i1 = (((-(((0x17e8702a) >= (0x4c2a2335)) ? (0xf9772857) : (i1)))>>>((0xffffffff) % (((-0x8000000) / (0x5bf057d9))>>>((0xde43214) % (0xb89b59ea))))) == (0xf889a401));\n    {\n      (Float32ArrayView[0]) = ((d0));\n    }\n    i1 = ((~(((0x778d1a7) == (((0x6a0ace9a) / (0x5481ed20))>>>((0xf84bed00))))-(/*FFI*/ff()|0)+((((0xb2073d9) % (0xffffffff))>>>((0xffffffff)*0x8737e)) > (((0xfffd1f75))>>>((0xfb3e2199)-(0xf892ec55)))))) > (((i1)+(0xffffffff)) >> (((+(-1.0/0.0)) == (+abs((((0xfb93c85e) ? (-3.022314549036573e+23) : (4611686018427388000.0))))))-((i1) ? (i1) : ((((0xf8c4236c)) >> ((0xff814033))))))));\n    i1 = ((/*FFI*/ff(((+((+(((/*FFI*/ff(((((-0x8000000)) | ((0xffffffff)))), ((-4.722366482869645e+21)), ((1.2089258196146292e+24)), ((1099511627777.0)), ((-281474976710655.0)), ((2.3611832414348226e+21)))|0))>>>((0x7020bda4)+(0xf99eb26a)+(-0x8000000))))))), ((+sin((((((0x377cf196) % (0x345cb5e0)) << ((0xbfbf7a35)))))))), ((1152921504606847000.0)), ((281474976710657.0)), ((((0xffffffff)) >> ((0x8d486303)))))|0) ? (/*FFI*/ff()|0) : (i1));\n    {\n      {\n        d0 = (+(((((Float64ArrayView[4096]))))>>>((/*FFI*/ff()|0)-((0xe5e9b239) < (((x)-(0xff034465))>>>((/*FFI*/ff()|0)))))));\n      }\n    }\n    {\n      d0 = (-((+(((i1)+((abs((0x5ab70ddf))|0) > ((0xffffffff)))) >> (-(0x2f782eb4))))));\n    }\n    {\n      i1 = ((0xfa98bc4c));\n    }\n    d0 = ((((i1)) << ((0x5d109994) / ((((/*MARR*/[x, ([]), ([])].map) == (+(-1.0/0.0)))+(0xd6494681))|0))));\n    d0 = (-4611686018427388000.0);\n    (Float64ArrayView[2]) = ((-3.022314549036573e+23));\n    d0 = (((x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: decodeURIComponent, }; })(21), String.prototype.italics))) ? (262145.0) : (d0));\n    d0 = (((d0)) % ((2251799813685249.0)));\n    i1 = (0xf92eae2a);\n    (Float64ArrayView[1]) = ((Float32ArrayView[((Int8ArrayView[2])) >> 2]));\n    {\n      i1 = (i1);\n    }\n    return ((((0xfaa0f61d) ? ((0x0) > (((i1)+((0x7fffffff)))>>>((0xc6da643d)+(0x3232534a)+(0xfe4df7ed)))) : (0xfb8c7a5e))*0x1bb3a))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=943; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; gcslice(435); } void 0; } t2.set(a0, ({valueOf: function() { m1 = new Map;return 2; }}));function window()\"use asm\";   var Infinity = stdlib.Infinity;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +(((Infinity) + (d1)));\n  }\n  return f;/*RXUB*/var r = ({\u3056: \"\\u3F0B\", \"-20\": NaN = Proxy.createFunction(({/*TOODEEP*/})( \"\" ), Array.prototype.reduce) }); var s = \"XXXXXXXXX\"; print(s.split(r)); ");
/*fuzzSeed-204645237*/count=944; tryItOut("\"use strict\"; if(false) m2.has(e2); else this.g2.e1.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (-((+(0.0/0.0))));\n    d0 = (d1);\n    d0 = (d0);\n    return +((d1));\n  }\n  return f; })(this, {ff: WeakSet.prototype.add}, new SharedArrayBuffer(4096));");
/*fuzzSeed-204645237*/count=945; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?!\\\\D)\\\\b|[^\\\\S\\\\cE-\\\\uC740]+|(?=$\\\\B){4095}|.((?=\\\\f|^))|(\\\\d)|(?:.)[\\u00da\\\\s\\u9159-\\ub5af-\\\\W]^((?:(?:\\\\s+))){3})\", \"m\"); var s = \"\\n\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-204645237*/count=946; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ( + Math.hypot(( + (Math.fround(( ! -Number.MAX_SAFE_INTEGER)) !== ( + Math.acosh(( + mathy0(( + x), ( + x))))))), ( + Math.atan2((Math.hypot(y, (((y >>> 0) / (( ~ ((y >> Math.round(x)) >>> 0)) >>> 0)) >>> 0)) | 0), Math.sinh(-Number.MAX_SAFE_INTEGER))))); }); testMathyFunction(mathy1, /*MARR*/[-Number.MIN_SAFE_INTEGER, new Number(1.5), new Number(1.5), undefined, -Number.MIN_SAFE_INTEGER, new Number(1.5), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, new Number(1.5), -Number.MIN_SAFE_INTEGER, new Number(1.5), this.__defineSetter__(\"x\", Function.prototype.toString), new Number(1.5), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, this.__defineSetter__(\"x\", Function.prototype.toString), -Number.MIN_SAFE_INTEGER, new Number(1.5), new Number(1.5), undefined, this.__defineSetter__(\"x\", Function.prototype.toString), new Number(1.5), new Number(1.5), -Number.MIN_SAFE_INTEGER, this.__defineSetter__(\"x\", Function.prototype.toString), undefined, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, new Number(1.5), new Number(1.5), -Number.MIN_SAFE_INTEGER, this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), new Number(1.5), -Number.MIN_SAFE_INTEGER, this.__defineSetter__(\"x\", Function.prototype.toString), undefined, new Number(1.5), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, this.__defineSetter__(\"x\", Function.prototype.toString), this.__defineSetter__(\"x\", Function.prototype.toString), undefined, -Number.MIN_SAFE_INTEGER, new Number(1.5), this.__defineSetter__(\"x\", Function.prototype.toString), new Number(1.5)]); ");
/*fuzzSeed-204645237*/count=947; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + (( - ((Math.exp((-0 >>> 0)) <= ((Math.fround(mathy1((x >>> 0), Math.fround(Math.fround(( + Math.fround(x)))))) >>> 0) ^ 0/0)) >>> 0)) <= ( + ( + Math.max((mathy0(Number.MIN_SAFE_INTEGER, Math.log10(y)) | 0), (Math.fround(Math.atan(Math.fround((Math.fround(y) && Math.fround(Math.PI))))) | 0)))))) == ( + ( + ( + ( ! (( ~ ((Math.fround(-(2**53+2)) !== (42 >>> 0)) | 0)) | 0)))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 1, 42, 0/0, 0, Number.MIN_VALUE, -0x0ffffffff, 0x080000000, 0x100000000, -(2**53), -(2**53+2), 0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x080000001, 2**53+2, 1/0, -0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 0x07fffffff, -0x080000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, Math.PI, -(2**53-2), 2**53-2, 2**53, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=948; tryItOut("\"use strict\"; e2.toString = (function() { try { e2 = new Set; } catch(e0) { } try { o0 + b2; } catch(e1) { } v2 = evaluate(\"\\\"use strict\\\"; v2 = evalcx(\\\"t2.set(a2, 17);\\\", g2);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: true, sourceMapURL: s0 })); return f1; });");
/*fuzzSeed-204645237*/count=949; tryItOut("\"use asm\"; eval.name;return \"\\u4AD2\";");
/*fuzzSeed-204645237*/count=950; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.max(Math.ceil(Math.atan2(( - Math.fround(x)), (Math.fround(( ~ Math.fround(Math.pow(y, x)))) >>> 0))), (Math.max(Math.fround(Math.exp(x)), mathy0(x, (Math.expm1(Math.cbrt(x)) || (x & y)))) >>> 0)); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 0x080000000, 0x0ffffffff, 0x100000001, 0x080000001, 2**53, 0x07fffffff, -Number.MIN_VALUE, 0, 42, -Number.MAX_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0, -0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, 0x100000000, 2**53-2, -(2**53), -0x07fffffff, 0/0, 1, -0x080000000, -1/0]); ");
/*fuzzSeed-204645237*/count=951; tryItOut("mathy2 = (function(x, y) { return Math.tanh(Math.fround(((Math.atanh(Math.fround((( + y) !== ( + y)))) >>> 0) >= ( ! (Math.max(Number.MAX_VALUE, Math.fround(Math.imul((Math.fround(Number.MIN_VALUE) * y), y))) | 0))))); }); testMathyFunction(mathy2, [0, null, false, 1, [0], -0, (new Boolean(false)), '', true, [], ({toString:function(){return '0';}}), objectEmulatingUndefined(), (function(){return 0;}), (new Number(-0)), NaN, '/0/', undefined, '\\0', (new String('')), /0/, '0', ({valueOf:function(){return 0;}}), 0.1, (new Boolean(true)), ({valueOf:function(){return '0';}}), (new Number(0))]); ");
/*fuzzSeed-204645237*/count=952; tryItOut("/*ADP-3*/Object.defineProperty(a1, 18, { configurable: true, enumerable: true, writable: false, value: v1 });");
/*fuzzSeed-204645237*/count=953; tryItOut("\"use strict\"; print(x);let a = ( \"\"  << -15.yoyo(/(?=\\u00aD)|\u9c65{4,}|((?=[^])).{0}|[^][^]|(?!\\B)|(\\cJ|[\\D\\u005e-\\uab41]|\\B{3})|(^){3,}(?:\\B)|\\b\\3(?![^])|.{4}/gim));");
/*fuzzSeed-204645237*/count=954; tryItOut("testMathyFunction(mathy0, [false, [0], '/0/', '0', (function(){return 0;}), '\\0', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), undefined, NaN, -0, (new Number(0)), true, 0, 0.1, [], (new String('')), 1, objectEmulatingUndefined(), (new Boolean(false)), (new Number(-0)), (new Boolean(true)), null, '', ({toString:function(){return '0';}}), /0/]); ");
/*fuzzSeed-204645237*/count=955; tryItOut("v1 = (s0 instanceof b0);function x() { \"use strict\"; return x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: Number.isInteger, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(x), x) } /*RXUB*/var r = new RegExp(\"^|(?!\\\\S){0,0}*{0,}(?!\\\\1|(?:[\\\\u72a0\\0\\\\w]?|(.){0,1073741823}))((?=\\\\b{2,2})*?)|..*?|(?=(?!.))+{1}\", \"gim\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=956; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.sign((( + ( + y)) >>> 0)) !== ( ~ ((((( ~ Number.MIN_VALUE) >>> 0) === y) >>> 0) ** ( + ( + ( + x)))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -0x100000000, -(2**53), Math.PI, -0x100000001, 0x080000000, -(2**53-2), 0.000000000000001, 1, -0x080000001, 2**53, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0, 2**53-2, -0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000001, 0x0ffffffff, -1/0, 42, -0x07fffffff, 1/0, -(2**53+2), Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=957; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, 0/0, 42, -(2**53-2), 1.7976931348623157e308, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 1/0, -(2**53), 2**53, Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, 1, 0x07fffffff, -Number.MAX_VALUE, -0, Number.MIN_VALUE, -0x07fffffff, Math.PI, 0x0ffffffff, 0x100000001, 0, 2**53-2, -1/0, 0x080000000]); ");
/*fuzzSeed-204645237*/count=958; tryItOut("for (var p in o0) { try { e2.add(a2); } catch(e0) { } this.a0[13] = a1; }");
/*fuzzSeed-204645237*/count=959; tryItOut("/*bLoop*/for (wucbmz = 0; wucbmz < 0; ++wucbmz) { if (wucbmz % 19 == 7) { /*hhh*/function tikozc(){print(x < null === new RegExp(\"(?=(\\\\2))|\\\\b\\\\3\", \"gim\"));}tikozc(); } else { e0.delete(t2); }  } ");
/*fuzzSeed-204645237*/count=960; tryItOut("mathy3 = (function(x, y) { return (( - Math.fround(Math.exp(((((0x0ffffffff >>> 0) != (Number.MIN_SAFE_INTEGER + Math.min(y, y))) >>> 0) | 0)))) + Math.hypot(Math.fround(( ~ Math.hypot((Math.min(( + y), (y >>> 0)) >>> 0), x))), (Math.fround(( ~ x)) != ( + x)))); }); ");
/*fuzzSeed-204645237*/count=961; tryItOut("for (var v of e2) { try { h1.valueOf = (function() { try { /*ODP-3*/Object.defineProperty(this.s1, \"apply\", { configurable: false, enumerable: false, writable: true, value: g1.b2 }); } catch(e0) { } try { v0 = evalcx(\"eval(\\\"(new RegExp(\\\\\\\"(?=[^]{0})\\\\\\\", \\\\\\\"gyi\\\\\\\"));\\\")\", g2); } catch(e1) { } v2 = evalcx(\"/* no regression tests found */\", g0.g0); return b1; }); } catch(e0) { } try { e1.delete(b1); } catch(e1) { } try { e1.add(a2); } catch(e2) { } a2.unshift(t1, f1); }");
/*fuzzSeed-204645237*/count=962; tryItOut("\"use strict\"; e0.has(g2);v2 = Object.prototype.isPrototypeOf.call(m0, o2);");
/*fuzzSeed-204645237*/count=963; tryItOut("m1.set(intern(x%= /x/g ) ? (((p={}, (p.z = true)())))() : x, f0);");
/*fuzzSeed-204645237*/count=964; tryItOut("\"use strict\"; var pqhung = new ArrayBuffer(16); var pqhung_0 = new Float64Array(pqhung); var pqhung_1 = new Float64Array(pqhung); print(pqhung_1[0]); var pqhung_2 = new Uint8ClampedArray(pqhung); print(pqhung_2[0]); pqhung_2[0] = 16; var pqhung_3 = new Int32Array(pqhung); pqhung_3[0] = 21; v1 = evalcx(\"(\\\"\\\\uC228\\\");yield  \\\"\\\" ;\", o0.g2);print(a = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: /*wrap3*/(function(){ \"use strict\"; var mgrphp = new RegExp(\"(?:(?:.)?)\", \"gym\"); (undefined)(); }), iterate: -20, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(\"\\uFE6A\"), []));v2 = a1.length;\ns2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  var atan2 = stdlib.Math.atan2;\n  var exp = stdlib.Math.exp;\n  var ceil = stdlib.Math.ceil;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 2097153.0;\n    d0 = (d2);\n    switch ((~((-0x8000000)))) {\n      case -1:\n        d2 = (+(0.0/0.0));\n        break;\n      default:\n        d1 = (x);\n    }\n    {\n      {\n        {\nfor (var v of g0) { g1.i0.next(); }        }\n      }\n    }\n    d2 = (+sin(((d0))));\n    d0 = (-5.0);\n    {\n      d2 = ((((0xa0aea0d6) ? (((d0)) / ((+((d1))))) : (d1))));\n    }\n    d0 = (d1);\n    d1 = (((d1)) - ((+atan2(((+(((0xffffffff)+(0x81daf0bd))>>>(((((yield window = (4277))) > ((9223372036854776000.0) + (-1.015625)))))))), ((+(1.0/0.0)))))));\n    d1 = (d0);\n    d1 = (d2);\n    {\n      d0 = (d0);\n    }\n    {\n      {\n        (Uint8ArrayView[2]) = (((((0xfd101983)-((((0xf57b6169))>>>((-0x2eb7eda))))-((+exp(((4097.0)))) < (d1))) >> ((~~(((d2)) * ((d0)))))) > ((yield new this)))+(-0x312b779));\n      }\n    }\n    d2 = (d0);\n    {\n      d2 = (d0);\n    }\n    d2 = (+((+(1.0/0.0))));\n    d0 = (+((d1)));\n    d0 = (+ceil((((0xa65ebb56) ? ((1.0) + (+((549755813887.0)))) : (((((0xffffffff) ? (-2.4178516392292583e+24) : (0.0078125))) / ((+(-1.0/0.0)))) + (NaN))))));\n    d0 = (d0);\n    return (((((!(0xfa365100)))>>>((-0x8000000)-((((-0x8000000)-(0xfc0a8fd4)) >> ((0x997ff4a1)-(0x2985f427))) > (((0x46bafdf6) % (0x64e08532)) & ((0x4d86f3b9) / (0x5e86b8ba)))))) % ((((((0x43573152)+(0xfb4e5fec)+(!(0xb54d6792)))|0) == (({y: let (npnqbz, a, e, x, nadabo, vzpphw, sgvisf) a}))))>>>((-0x8000000)+((imul((1), (0xfd62ce36))|0) < (((0x885e3939) % (0x294c068f)) ^ ((-0x8000000)-(0x9f77a31c))))))))|0;\n  }\n  return f; });\n/*RXUB*/var r = r2; var s = \"\"; print(s.match(r)); print(delete window.x);/*hhh*/function sjyqrk(x, d = \"\\u310C\"){a0.sort((function() { try { v1 = Object.prototype.isPrototypeOf.call(m1, s0); } catch(e0) { } try { a0.length = 1; } catch(e1) { } try { a0.forEach((function(j) { o2.f1(j); }), o1, t0,  '' ); } catch(e2) { } i0 + i2; return s2; }), o0.f0, o2, Math, i0);}/*iii*/b2 = t0.buffer;");
/*fuzzSeed-204645237*/count=965; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 1/0, 0x0ffffffff, -0x100000001, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000000, 0x07fffffff, 2**53+2, 0/0, 2**53, -0x080000000, -(2**53-2), -0x080000001, -1/0, -0x100000000, -0, 0x100000001, 0.000000000000001, 42, Number.MIN_VALUE, -Number.MIN_VALUE, 1, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, Math.PI, -(2**53), -(2**53+2), -0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=966; tryItOut("testMathyFunction(mathy0, [0, 1, '0', -0, null, true, objectEmulatingUndefined(), (new Number(0)), undefined, false, (new String('')), (new Number(-0)), 0.1, '', (new Boolean(false)), ({toString:function(){return '0';}}), /0/, ({valueOf:function(){return 0;}}), [], (new Boolean(true)), NaN, '/0/', [0], ({valueOf:function(){return '0';}}), '\\0', (function(){return 0;})]); ");
/*fuzzSeed-204645237*/count=967; tryItOut("{t1 = new Int32Array(t1); }");
/*fuzzSeed-204645237*/count=968; tryItOut("print(g2.p2);");
/*fuzzSeed-204645237*/count=969; tryItOut("t2[5] = ({call: ((void options('strict'))), /*toXFun*/valueOf: Uint8Array }\u000c);");
/*fuzzSeed-204645237*/count=970; tryItOut("Array.prototype.pop.apply(a0, [p1]);");
/*fuzzSeed-204645237*/count=971; tryItOut("\"use strict\"; /*RXUB*/var r = /(?![^])*?/g; var s = w; print(r.test(s)); ");
/*fuzzSeed-204645237*/count=972; tryItOut("print(m2);");
/*fuzzSeed-204645237*/count=973; tryItOut("i2.send(b0);");
/*fuzzSeed-204645237*/count=974; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((((Math.max(((x || 0x100000001) >>> 0), ( + x)) >>> 0) >>> (Math.ceil(x) | 0)) | 0) >>> (Math.pow(1, (Math.max((Math.fround(( - Math.fround(-Number.MIN_SAFE_INTEGER))) >>> 0), y) >>> 0)) - ( - ( ! x)))); }); testMathyFunction(mathy4, [0x080000001, 1.7976931348623157e308, 0x100000000, 0x080000000, Number.MIN_VALUE, -0, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, 0.000000000000001, -0x080000001, 2**53-2, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), 42, -1/0, Number.MAX_VALUE, 0, -0x100000001, 2**53, -0x0ffffffff, -0x07fffffff, 0x100000001, 2**53+2, 1/0, Math.PI, 0x0ffffffff, 1, -(2**53-2), -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=975; tryItOut("\"use strict\"; i2 = new Iterator(v0);");
/*fuzzSeed-204645237*/count=976; tryItOut("\"use asm\"; print(a | x & x);");
/*fuzzSeed-204645237*/count=977; tryItOut("\"use strict\"; a0[2];");
/*fuzzSeed-204645237*/count=978; tryItOut("(makeFinalizeObserver('tenured')) = t1[16];");
/*fuzzSeed-204645237*/count=979; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(h0, a2);");
/*fuzzSeed-204645237*/count=980; tryItOut("mathy4 = (function(x, y) { return ( + (Math.tanh((Math.imul(mathy1(y, -(2**53)), Math.log(Number.MIN_SAFE_INTEGER)) | 0)) | 0)); }); testMathyFunction(mathy4, [[], null, 1, '/0/', 0.1, ({valueOf:function(){return 0;}}), NaN, '\\0', -0, '', (new Boolean(false)), (new Number(0)), true, false, /0/, undefined, (new Number(-0)), '0', 0, objectEmulatingUndefined(), [0], (function(){return 0;}), ({toString:function(){return '0';}}), (new Boolean(true)), ({valueOf:function(){return '0';}}), (new String(''))]); ");
/*fuzzSeed-204645237*/count=981; tryItOut("var mqvimr = new SharedArrayBuffer(2); var mqvimr_0 = new Uint8ClampedArray(mqvimr); mqvimr_0[0] = 15; var mqvimr_1 = new Uint32Array(mqvimr); print(mqvimr_1[0]); mqvimr_1[0] = -24; var mqvimr_2 = new Uint8Array(mqvimr); mqvimr_2[0] = -8; print(x);a1.push(h1, v1);");
/*fuzzSeed-204645237*/count=982; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround((Math.max(((mathy1(( + 2**53+2), (x >>> 0)) >>> 0) >>> 0), (( ~ (( + Math.fround(mathy0(y, (((x | 0) == (( + Math.max(( + x), ( + y))) | 0)) | 0)))) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [-1/0, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53, -0x07fffffff, -0x100000001, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, -(2**53+2), Number.MAX_VALUE, -(2**53), 0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, 1/0, -0x0ffffffff, -0x100000000, 0.000000000000001, 0x07fffffff, 0/0, -0, -0x080000001, 42, 2**53-2, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, 0x100000000, Math.PI, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=983; tryItOut("testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 42, 0x080000000, 0x080000001, -1/0, Math.PI, Number.MAX_VALUE, 2**53, -0x0ffffffff, 2**53+2, -0x100000000, -Number.MIN_SAFE_INTEGER, 1, -0, 0x100000001, -(2**53), -0x100000001, -(2**53+2), -0x07fffffff, Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0x100000000, -0x080000001, -(2**53-2), 1.7976931348623157e308, 0, 1/0, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=984; tryItOut("\"use strict\"; v0 = g0.r2.constructor;\ne2.delete(o2);\n");
/*fuzzSeed-204645237*/count=985; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    switch ((((0x49845c87) / (0xc7ddf6bc)) >> (((0x7b34c094))))) {\n      default:\n        i1 = ((((!(0xffffffff))-(i1))>>>((i1)-(0x101d131d))) < (0x1c882e00));\n    }\n    return +((((2305843009213694000.0)) - ((+(((0xffbd8e84)-(0xffffffff))>>>((0x10f84579)-(i1)))))));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [42, 0, 1/0, -(2**53), -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, 0x100000000, 0.000000000000001, Math.PI, -0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, 1, 0x0ffffffff, -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -0, 0x100000001, 0/0, 2**53+2, 0x07fffffff, Number.MAX_VALUE, -0x100000000, -0x07fffffff, -(2**53+2), -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=986; tryItOut("\"use strict\"; let (b) { (\"\\u3BC6\");h2.get = g2.f0; }");
/*fuzzSeed-204645237*/count=987; tryItOut("mathy5 = (function(x, y) { return (Math.atanh(((Math.hypot(Math.hypot((y >>> 0), Math.fround((y ? Math.fround((mathy4((y >>> 0), ( + x)) >>> 0)) : Math.fround(x)))), mathy3((Math.pow(Math.asin(x), (y >>> 0)) >>> 0), Math.imul(x, Math.hypot(Math.fround(y), Math.fround(y))))) >>> Math.fround(mathy3(Math.fround(( + ( ! Math.fround(Math.atan2((y >>> 0), Math.fround((( - (((y | 0) << y) >>> 0)) >>> 0))))))), Math.fround(Math.PI)))) | 0)) | 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 2**53+2, -0x080000001, -0x100000000, 0, 2**53-2, -0x080000000, -Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, 1, -(2**53), -0x100000001, 1.7976931348623157e308, 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, -0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, -(2**53-2), 2**53, 42]); ");
/*fuzzSeed-204645237*/count=988; tryItOut("o2.h0.getOwnPropertyDescriptor = f0;");
/*fuzzSeed-204645237*/count=989; tryItOut("a2.reverse();");
/*fuzzSeed-204645237*/count=990; tryItOut("/*oLoop*/for (bkoobl = 0; bkoobl < 24; ++bkoobl) { print(/$\\3+?/gy); } ");
/*fuzzSeed-204645237*/count=991; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=992; tryItOut("\"use asm\"; v1 = (t1 instanceof b1);");
/*fuzzSeed-204645237*/count=993; tryItOut("\"use strict\"; Object.prototype.unwatch.call(p2, \"forEach\");\nreturn;\n");
/*fuzzSeed-204645237*/count=994; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ([] = (a = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: (function(x, y) { return -0x080000001; }), getPropertyDescriptor: b =>  { print(i2); } , defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function(y) { this.v0 = g0.runOffThreadScript(); }, has: function() { return false; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: Map, keys: function() { return Object.keys(x); }, }; })(x), String.prototype.sup, DataView.prototype.setInt8))); }); testMathyFunction(mathy1, [2**53, 0, 0.000000000000001, 1/0, 0x0ffffffff, 0/0, -0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 1.7976931348623157e308, 1, -0x100000000, 0x080000001, Number.MAX_VALUE, -0, 0x080000000, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000001, -0x080000001, -1/0, 0x100000000, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=995; tryItOut("\"use strict\"; o1.v0 = g1.runOffThreadScript();");
/*fuzzSeed-204645237*/count=996; tryItOut("mathy0 = (function(x, y) { return ( ~ (( ~ (( ~ x) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [42, -(2**53), -(2**53-2), -0, Number.MAX_SAFE_INTEGER, 2**53, 1, 1/0, 0x07fffffff, -0x100000001, Math.PI, 0x0ffffffff, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2, Number.MAX_VALUE, -0x080000000, 0x080000001, -1/0, 0, 0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-204645237*/count=997; tryItOut("a0.__proto__ = f0;");
/*fuzzSeed-204645237*/count=998; tryItOut("\"use strict\"; t1[10];");
/*fuzzSeed-204645237*/count=999; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MIN_VALUE, -0, Math.PI, 0x0ffffffff, -0x07fffffff, 2**53-2, 1.7976931348623157e308, -(2**53-2), -0x100000000, 0x080000001, 0, -Number.MAX_SAFE_INTEGER, -1/0, 1, 0x07fffffff, 1/0, -0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 0/0, 2**53, Number.MAX_VALUE, -0x080000000, 0x080000000, 42, -Number.MAX_VALUE, -(2**53+2), 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=1000; tryItOut("/* no regression tests found */function c([{}], \"(undefined.__defineGetter__(\\\"window\\\", new Function))\")(Math.cosh(undefined - 10))p1.toSource = f1;");
/*fuzzSeed-204645237*/count=1001; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=1002; tryItOut("({enumerable: (x % 51 == 24)})");
/*fuzzSeed-204645237*/count=1003; tryItOut("\"use strict\"; M:switch([] = []) { case 5:  }");
/*fuzzSeed-204645237*/count=1004; tryItOut("\"use strict\"; var ahbpil = new SharedArrayBuffer(0); var ahbpil_0 = new Uint32Array(ahbpil); ahbpil_0[0] = -11; var ahbpil_1 = new Uint16Array(ahbpil); print(ahbpil_1[0]); ahbpil_1[0] = 4; var ahbpil_2 = new Int32Array(ahbpil); print(ahbpil_2[0]); ahbpil_2[0] = 27; var ahbpil_3 = new Uint8ClampedArray(ahbpil); t1 = new Int16Array(a0);m1.delete(h1);a0 = \"\\u13CF\";");
/*fuzzSeed-204645237*/count=1005; tryItOut("\"use strict\"; q => q");
/*fuzzSeed-204645237*/count=1006; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[(void 0), new String(''), (void 0), new String(''), new String(''), (void 0), (void 0), (void 0), new String(''), (void 0), new String(''), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new String(''), (void 0), new String('')]); ");
/*fuzzSeed-204645237*/count=1007; tryItOut("/*ADP-2*/Object.defineProperty(this.a2, 7, { configurable: true, enumerable: false, get: (function(j) { if (j) { m0 = Proxy.create(h0, o0); } else { m1.get(s1); } }), set: (function() { try { for (var v of a1) { try { a1.reverse(); } catch(e0) { } e1.has(f0); } } catch(e0) { } f0.toString = objectEmulatingUndefined; return o0; }) });");
/*fuzzSeed-204645237*/count=1008; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1009; tryItOut("mathy0 = (function(x, y) { return (( ~ Math.atan2(( + (Math.min(((((( ~ (x | 0)) | 0) ^ (-1/0 | 0)) | 0) >>> 0), ( + (x - x))) >>> 0)), ( - y))) | 0); }); testMathyFunction(mathy0, [Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, -0x100000000, -(2**53-2), 1, -0x080000001, -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, Math.PI, 1/0, -0, 0/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53, -0x100000001, -(2**53), -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, -1/0, 0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=1010; tryItOut(" /x/ ;for (var p in a1) { try { /*ODP-1*/Object.defineProperty(i0, \"caller\", ({configurable: (x % 24 == 8), enumerable: true})); } catch(e0) { } i1.next(); }continue L;");
/*fuzzSeed-204645237*/count=1011; tryItOut("mathy2 = (function(x, y) { return ( ~ Math.fround(Math.max((Math.cbrt((( + ((y | x) >>> y)) | 0)) | 0), ( + (mathy1(Math.fround(y), (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [0/0, -0x100000000, 0x080000001, 2**53, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 1/0, -0x080000001, -1/0, 42, 1, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -0, -(2**53+2), -0x080000000, 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, 0, -0x07fffffff, 0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53-2), -0x100000001]); ");
/*fuzzSeed-204645237*/count=1012; tryItOut("var w = (x % \u0009w), x =  \"\" , [,,], NaN, gbzlet;a2.length =  '' ;");
/*fuzzSeed-204645237*/count=1013; tryItOut("m2.has(a2);");
/*fuzzSeed-204645237*/count=1014; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul((Math.min(x, ( + Math.asinh((x || (( - x) | 0))))) === Math.atan2(Math.acos(y), x)), (( + (Math.atanh(( + ((Math.min((2**53+2 | 0), (Math.atan(Math.hypot(x, -1/0)) | 0)) | 0) >>> 0))) | 0)) | 0)); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0/0, 2**53, Number.MAX_VALUE, 1.7976931348623157e308, 1, Number.MIN_VALUE, -0x080000001, Math.PI, -0x100000001, -0x080000000, 0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0.000000000000001, -0x0ffffffff, -0, -0x100000000, 0x0ffffffff, 2**53+2, 0, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, -0x07fffffff, 42, 2**53-2, 0x100000001, 0x080000000]); ");
/*fuzzSeed-204645237*/count=1015; tryItOut("g1.o0.s2 += 'x';");
/*fuzzSeed-204645237*/count=1016; tryItOut("a0.push(b2, g1.e1, s1, t1);");
/*fuzzSeed-204645237*/count=1017; tryItOut("{print(b);print(\"-0\"); }");
/*fuzzSeed-204645237*/count=1018; tryItOut("v1 = evaluate(\"print(uneval(this.t0));\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (void options('strict_mode')), sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-204645237*/count=1019; tryItOut("\"use strict\"; switch((4277)) { default: t2.set(a0, 8);break; v1 = g0.eval(\"function f1(o1)  { print(true); } \"); }");
/*fuzzSeed-204645237*/count=1020; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.pow((Math.trunc(( ! y)) | 0), (Math.sign((( + (Math.atan(x) | 0)) >>> 0)) | 0)) | 0) || Math.fround((Math.min(Math.fround(((((x * (x % (y | 0))) | 0) === (( - 0/0) | 0)) != ( + (( + (Math.log10((x | 0)) | 0)) * (y / 0x100000000))))), Math.fround(Math.pow(Math.fround(( - y)), y))) === ( + (-(2**53-2) == Math.fround(Math.fround(Math.atan2(x, ( ~ Math.hypot(x, y)))))))))); }); testMathyFunction(mathy3, [-0x07fffffff, 0x0ffffffff, -(2**53-2), 0x100000001, -0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, 42, -0x080000001, 0x07fffffff, -(2**53), 1/0, 2**53+2, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, Number.MAX_SAFE_INTEGER, 1, 0/0, 0x080000001, Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, -0x100000000, 2**53, 2**53-2, -Number.MIN_VALUE, Math.PI, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -0]); ");
/*fuzzSeed-204645237*/count=1021; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1022; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0, -(2**53-2), -Number.MAX_VALUE, 0, -0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), 0x080000000, 0/0, 2**53+2, 1/0, -0x0ffffffff, 42, 1, -0x07fffffff, -(2**53), 2**53-2, 0.000000000000001, -0x100000001, Math.PI, -0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, 0x100000000, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, 2**53, 0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1023; tryItOut("\"use strict\"; e2.toString = (function mcc_() { var lzqyos = 0; return function() { ++lzqyos; f1(/*ICCD*/lzqyos % 4 == 2);};})();");
/*fuzzSeed-204645237*/count=1024; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-204645237*/count=1025; tryItOut("\"use strict\"; Array.prototype.sort.call(a2, f2);");
/*fuzzSeed-204645237*/count=1026; tryItOut("testMathyFunction(mathy4, [(new Boolean(true)), '', (function(){return 0;}), '\\0', [], (new Number(-0)), 0, ({valueOf:function(){return 0;}}), (new String('')), null, objectEmulatingUndefined(), undefined, false, (new Boolean(false)), 1, /0/, NaN, '/0/', true, -0, '0', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Number(0)), [0], 0.1]); ");
/*fuzzSeed-204645237*/count=1027; tryItOut("mathy2 = (function(x, y) { return (( - (Math.log10(Math.fround(Math.ceil(( + mathy1(Math.fround(((x >>> 0) ? x : Math.atan2(( + x), ( + (((y >>> 0) !== (y >>> 0)) >>> 0))))), x))))) >>> 0)) | 0); }); testMathyFunction(mathy2, [-(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, Math.PI, -0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 2**53, 0x080000000, -0x0ffffffff, -1/0, 0.000000000000001, 0x0ffffffff, 1, -Number.MIN_VALUE, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, -(2**53), -0x080000000, -0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, 2**53-2, 0x100000000, 0x100000001, 0, 42, 0/0]); ");
/*fuzzSeed-204645237*/count=1028; tryItOut("v2 = t0.length;function NaN(eval, e) { \"use strict\"; return [,,z1] } v0 = evalcx(\"true\", g0);");
/*fuzzSeed-204645237*/count=1029; tryItOut("\"use strict\"; yield this.__defineSetter__(\"y\", Date.now);");
/*fuzzSeed-204645237*/count=1030; tryItOut("\"use strict\"; \"use asm\"; /*iii*/let (e) { s2 += 'x'; }/*hhh*/function mljrgi(){selectforgc(o1);}");
/*fuzzSeed-204645237*/count=1031; tryItOut("print(x);");
/*fuzzSeed-204645237*/count=1032; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[(void 0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0)]); ");
/*fuzzSeed-204645237*/count=1033; tryItOut("mathy2 = (function(x, y) { return ( ~ ( + (( + ( ! Math.atanh(( + ((y | 0) > (Number.MAX_SAFE_INTEGER | 0)))))) | ( + mathy1(( + Math.fround(( + ( - (( ! x) | 0))))), Math.fround((Math.fround(Math.atan(x)) != Math.fround(Math.asin(0x0ffffffff))))))))); }); testMathyFunction(mathy2, [42, 0x080000001, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0, -(2**53), 0x0ffffffff, 0x080000000, -0x100000000, 0x100000001, -0x080000000, Math.PI, -Number.MIN_VALUE, -0x100000001, -(2**53-2), 2**53+2, 1/0, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, -0x07fffffff, -(2**53+2), -0, 0x100000000, 2**53-2, Number.MIN_VALUE, 0.000000000000001, 0x07fffffff, 1, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1034; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.pow(( + ( ~ (((Math.asinh(x) >>> 0) || (mathy1(( - y), Math.cosh(x)) | 0)) >>> 0))), ( + Math.fround(Math.clz32((Math.cosh(Math.fround(( ! Math.fround(( ! Math.fround(x)))))) >>> 0)))))); }); ");
/*fuzzSeed-204645237*/count=1035; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -8388609.0;\n    var d3 = 1025.0;\n    var i4 = 0;\n    var d5 = -33.0;\n    return (((0xa2f158bb)))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, 0, Math.PI, 2**53, -(2**53-2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, -0x100000000, 2**53-2, 0x100000001, -Number.MAX_VALUE, -(2**53), 0x080000000, 0x080000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0, 42, 1.7976931348623157e308, 1/0, 0x07fffffff, 0/0, -0x080000001, -1/0, -(2**53+2), 1, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=1036; tryItOut("m2.get([x, {x, b, \u3056: {c: x, y, eval: y, x: z, y, e, d: {c: b, x, x: b}, NaN: {e, eval, x, x: {c: (c), \u3056, x: x, e: {x: [], x: [{x: [, {}], d}]}}}}, y, NaN}] = x);");
/*fuzzSeed-204645237*/count=1037; tryItOut("\"use strict\"; /*RXUB*/var r = /[\\d]/ym; var s = \"a\"; print(r.exec(s)); ");
/*fuzzSeed-204645237*/count=1038; tryItOut("\"use strict\"; x;");
/*fuzzSeed-204645237*/count=1039; tryItOut("print(uneval(g2.v1));");
/*fuzzSeed-204645237*/count=1040; tryItOut("o1.v0 = o1.g2.t2.length;");
/*fuzzSeed-204645237*/count=1041; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(g2.s0, this.s1);");
/*fuzzSeed-204645237*/count=1042; tryItOut("/*UUV2*/(x.asinh = x.toUpperCase);");
/*fuzzSeed-204645237*/count=1043; tryItOut("mathy2 = (function(x, y) { return Math.ceil(Math.fround(Math.max(Math.fround((( ~ ( + x)) >>> 0)), Math.fround(Math.fround(Math.ceil(( ! ((Math.imul(x, ( + (Math.max(x, Math.fround(-(2**53+2))) | 0))) >>> 0) ? Math.fround((Math.fround(-0x0ffffffff) <= (y | 0))) : (y >>> 0))))))))); }); testMathyFunction(mathy2, [-0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, 2**53-2, -0, 2**53+2, 0x080000001, 0x080000000, 42, 1.7976931348623157e308, 0.000000000000001, 0x100000000, 1, -1/0, -0x080000000, -Number.MAX_VALUE, 0x100000001, 0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -(2**53), Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -0x100000001, Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 0, Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=1044; tryItOut("a1[18] =  /x/g ;");
/*fuzzSeed-204645237*/count=1045; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.fround((Math.fround(y) <= Math.fround(x))) ? ( + (( - ( + (mathy2((-Number.MAX_SAFE_INTEGER >>> 0), ((( + (-(2**53+2) >>> 0)) >>> 0) >>> 0)) >>> 0))) + (( ~ Math.fround(( - ( ! x)))) >>> 0))) : mathy1(Math.tanh(x), (((y | 0) + Math.fround(0x07fffffff)) & 1/0)))); }); testMathyFunction(mathy4, [1, undefined, true, NaN, (new String('')), ({valueOf:function(){return '0';}}), '', null, (new Boolean(true)), '0', false, '/0/', (function(){return 0;}), 0.1, [], 0, '\\0', (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(false)), [0], (new Number(0)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), -0, /0/]); ");
/*fuzzSeed-204645237*/count=1046; tryItOut("/*vLoop*/for (var qxbgzn = 0; qxbgzn < 60; ++qxbgzn) { z = qxbgzn; f0 = (function(stdlib, foreign, heap){ \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 274877906945.0;\n    var i3 = 0;\n    var i4 = 0;\n    return +((Float64ArrayView[((0xfe37cec6)-((i0) ? (i0) : ((((0xffffffff)) << ((0x166071e))) < ((((Float32Array())))|0)))) >> 3]));\n  }\n  return f; }); } ");
/*fuzzSeed-204645237*/count=1047; tryItOut("i1.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14) { var r0 = 9 & a4; var r1 = a7 & a4; var r2 = a4 * a1; var r3 = 9 - 5; var r4 = x * r2; var r5 = r4 * a8; r4 = 4 * a1; a12 = 3 & a14; var r6 = a8 & a4; var r7 = a2 % r6; var r8 = a9 / 4; var r9 = a9 + a14; print(r8); var r10 = x ^ a5; r7 = a6 & a14; var r11 = a11 * r3; var r12 = r6 | a0; var r13 = r0 * r6; var r14 = 8 % a1; r5 = r5 / 6; var r15 = 1 * 5; var r16 = r6 - a9; var r17 = a8 ^ r11; var r18 = r1 & r9; r3 = a0 * r18; var r19 = a7 | r10; var r20 = r8 | 5; print(r16); var r21 = a12 | a13; var r22 = r15 * a7; return a13; });");
/*fuzzSeed-204645237*/count=1048; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?=(?=[^]|[^]))\\1|\\1{4,})*?/gyim; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1049; tryItOut("/*MXX3*/g1.Set.prototype = this.g1.Set.prototype;");
/*fuzzSeed-204645237*/count=1050; tryItOut("p2.toSource = f2;\n((4277));\n\n/*infloop*/while(x in x)x = \u3056;\n");
/*fuzzSeed-204645237*/count=1051; tryItOut("mathy2 = (function(x, y) { return mathy0(Math.fround(mathy1(mathy0(( + (( ~ (x >>> 0)) >>> 0)), ( ~ Math.min(x, y))), ( + Math.max(x, ((mathy1(0x0ffffffff, Math.fround(x)) | 0) ** x))))), mathy0(( + Math.exp(Math.fround(Math.expm1(Math.fround(x))))), Math.fround((( + mathy0(x, (mathy0(x, x) | 0))) % (y | 0))))); }); ");
/*fuzzSeed-204645237*/count=1052; tryItOut("g1.v1 = g0.eval(\"(Math.hypot(4,  /x/g ))\");");
/*fuzzSeed-204645237*/count=1053; tryItOut("o1 = new Object;");
/*fuzzSeed-204645237*/count=1054; tryItOut("mathy4 = (function(x, y) { return (Math.abs(( ~ ( + ( ~ (((2**53 % (y | 0)) >>> Math.min(x, Math.max(( + y), x))) | 0))))) ** mathy1(( + (Math.log10(y) | 0)), ( + (( + 0x100000001) >> ( + -1/0))))); }); testMathyFunction(mathy4, [0x080000000, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, -(2**53), -0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 1, 1.7976931348623157e308, 1/0, -Number.MIN_VALUE, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, 42, 2**53+2, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), 2**53, -(2**53+2), -1/0, 0x0ffffffff, -0x0ffffffff, -0x080000001, Number.MIN_VALUE, 0x100000000, 0, Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-204645237*/count=1055; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[0, undefined, 0, 0, 0, 0, undefined, 0, 0, undefined, 0, 0, undefined, 0, 0, undefined, 0, 0, 0, 0, 0, 0, undefined, 0, 0, 0, 0, 0, undefined, 0, 0, 0, undefined, 0, undefined, undefined, undefined, 0, undefined, 0, 0, undefined, 0, undefined, undefined, undefined, undefined, undefined, 0, 0, undefined, 0, undefined, undefined, 0, 0, 0, undefined, 0, undefined, undefined, undefined, undefined, 0, 0, 0, 0, undefined, undefined, undefined, undefined, 0, undefined, undefined, undefined, 0, undefined, 0, undefined, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undefined, 0, undefined, 0, undefined, 0, undefined, 0, undefined, 0, undefined, 0, undefined, undefined, 0, undefined, 0, 0, undefined, undefined, 0, 0, 0, undefined, undefined, 0, undefined, undefined, undefined, undefined, 0, 0, 0, undefined, 0, 0, 0, 0, undefined, undefined, undefined, undefined, 0]); ");
/*fuzzSeed-204645237*/count=1056; tryItOut("\"use strict\"; v1 = 0;");
/*fuzzSeed-204645237*/count=1057; tryItOut("with(x){Array.prototype.reverse.apply(a0, []); }");
/*fuzzSeed-204645237*/count=1058; tryItOut("\"use strict\"; this.s0 + m1;print(x);\n(new Function());\n");
/*fuzzSeed-204645237*/count=1059; tryItOut("mathy3 = (function(x, y) { return Math.sinh(Math.sinh(((( ! ((Math.tanh((x >>> y)) * 42) >>> 0)) | 0) >>> 0))); }); testMathyFunction(mathy3, [0.000000000000001, 0x07fffffff, 1, 0x080000000, 42, 2**53, 0x100000001, 1.7976931348623157e308, -0x100000001, -0x07fffffff, -0x080000000, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, -1/0, -Number.MIN_VALUE, -0, 0/0, 0, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0x080000001, 0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2]); ");
/*fuzzSeed-204645237*/count=1060; tryItOut("v1 + '';");
/*fuzzSeed-204645237*/count=1061; tryItOut("var yqdozz = new SharedArrayBuffer(0); var yqdozz_0 = new Uint8ClampedArray(yqdozz); print(yqdozz_0[0]); yqdozz_0[0] = -0; var yqdozz_1 = new Uint16Array(yqdozz); yqdozz_1[0] = -16; var yqdozz_2 = new Int16Array(yqdozz); yqdozz_2[0] = 22; var yqdozz_3 = new Uint8Array(yqdozz); yqdozz_3[0] = -0.147; var yqdozz_4 = new Uint32Array(yqdozz); yqdozz_4[0] = 17; var yqdozz_5 = new Float64Array(yqdozz); yqdozz_5[0] = 3; var yqdozz_6 = new Float32Array(yqdozz); yqdozz_6[0] = -11; var yqdozz_7 = new Uint8ClampedArray(yqdozz); yqdozz_7[0] = 5; var yqdozz_8 = new Uint8ClampedArray(yqdozz); print(yqdozz_8[0]); yqdozz_8[0] = 5; var yqdozz_9 = new Uint8Array(yqdozz); yqdozz_9[0] = 27; /*MXX2*/g2.Uint8Array.prototype.constructor = g2;let e, \u3056 = window, window, a;Array.prototype.push.call(a1, o1);print(yqdozz_3);this.o1.a1.sort((function mcc_() { var riimaw = 0; return function() { ++riimaw; if (/*ICCD*/riimaw % 8 == 6) { dumpln('hit!'); try { a0.shift(); } catch(e0) { } try { m2.get(s2); } catch(e1) { } try { /*RXUB*/var r = r2; var s = \"\"; print(uneval(r.exec(s)));  } catch(e2) { } (void schedulegc(g1)); } else { dumpln('miss!'); try { selectforgc(o1); } catch(e0) { } f0.toSource = (function() { try { Array.prototype.reverse.apply(a1, [g0]); } catch(e0) { } try { v1 + m1; } catch(e1) { } v0 = (h0 instanceof this.m1); return i2; }); } };})());v2 = evaluate(\"yqdozz_1[5]\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (yqdozz_6[10] % 3 == 2), sourceIsLazy: true, catchTermination: (yqdozz_8[4] % 2 == 1) }));/*tLoop*/for (let e of /*MARR*/[true, new String('q'), 0x50505050, Infinity, 0x50505050, true, true, Infinity, true, 0x50505050, true, Number.MIN_SAFE_INTEGER, new String('q')]) { f2 = (function(j) { if (j) { try { /*ADP-2*/Object.defineProperty(a2, 11, { configurable: new RegExp(\"$+([^\\\\ud83B-\\u6997\\\\B]).{3,5}[][^]+?\", \"ym\"), enumerable: (yqdozz_0[9] % 5 != 1), get: f2, set: (function() { o2.o0 = {}; return g1; }) }); } catch(e0) { } this.t1 + o2.o0; } else { (void schedulegc(g2)); } }); }print(yqdozz_1);o0.v1 = Object.prototype.isPrototypeOf.call(this.m0, a2);print((yqdozz_6[0](++yqdozz_8[4])));");
/*fuzzSeed-204645237*/count=1062; tryItOut("v2 = Object.prototype.isPrototypeOf.call(e2, f0);");
/*fuzzSeed-204645237*/count=1063; tryItOut("/*tLoop*/for (let y of /*MARR*/[x, x, -Infinity, (x ? (4277) : NaN >>= true), x, (x ? (4277) : NaN >>= true), -Infinity, -Infinity, -Infinity, -Infinity, x, (x ? (4277) : NaN >>= true), (x ? (4277) : NaN >>= true), -Infinity, (x ? (4277) : NaN >>= true), x, -Infinity, x, (x ? (4277) : NaN >>= true), x, -Infinity, x, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, (x ? (4277) : NaN >>= true), x, (x ? (4277) : NaN >>= true), x, (x ? (4277) : NaN >>= true), (x ? (4277) : NaN >>= true), -Infinity, x, (x ? (4277) : NaN >>= true), x, (x ? (4277) : NaN >>= true), (x ? (4277) : NaN >>= true), -Infinity, x, -Infinity, (x ? (4277) : NaN >>= true), x, -Infinity, (x ? (4277) : NaN >>= true), (x ? (4277) : NaN >>= true), -Infinity, x, -Infinity, x, -Infinity]) { for (var v of g2) { try { o1.e0.delete((yield x = Proxy.createFunction(({/*TOODEEP*/})(-21), Object.getPrototypeOf))); } catch(e0) { } t2[6] = (4277); } }");
/*fuzzSeed-204645237*/count=1064; tryItOut("\"use strict\"; a2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return +((((((3.8685626227668134e+25)) * ((((-2251799813685248.0)) - ((d0)))))) * ((-((11\n))))));\n  }\n  return f; })(this, {ff: function(q) { \"use strict\"; return q; }}, new ArrayBuffer(4096));");
/*fuzzSeed-204645237*/count=1065; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = ((makeFinalizeObserver('tenured'))); print(s.replace(r, /*wrap3*/(function(){ var yiwstj = {z: {NaN: [, {d: [, \u3056, ], x: [], r, w: [], this}, {eval, y: {\u3056, s: [{c: this.x}, x, , {s: {w: {}}, y: y, set: d}], d: s, s: r, b}, s: {}, x: (window)}, r, e]}, d: [, \u3056, [{x: b, r: {c: {r: [{}, ], eval: a, a, r: []}, s, window: [, ], y: {z: {c, a, eval: {}}, w}}, x, b, r: [[], [, [x, ], {every, x: [], NaN}], [, {}]], e: [, ]}, a, ], , , , {s: x, s: [x, , {s, let: {e\u000c: arguments}, {r: {eval: NaN}, y: x, a}: x, a: [, , {a: {a, y: []}, s: [], window}, ]}, ], s, NaN: {}, x: []}], eval: [eval, ], r, NaN: [s, z], r: [[, , z], [, , y, {y: [z, ], [(w instanceof w)({}), ], r:  \"\" , r: {s: {r, a: z}, NaN: [{eval: w, y, NaN: [{}]}], NaN: { : RegExp.prototype, x: {window}, x: z, x: {b: {}}}, r: [, , ]}, z}, [, , {}], ]], y, s: [, , {r: {b, x: {z: [], r, a: c, \u3056}, (new String('q')), x: {}}, d, \u3056: [], \nx: r}, [{}, , , \u3056, ], [{eval: r}, , [], {s, NaN: [, , [], , {w, x: [[]], eval: [, , {}]}], x: [, \u3056], a, r}, , [, , {x: [, {c: arguments.callee.caller.arguments}, {e: d, NaN}, {}], x: {x: [, x]}}, \u0009], ], d, , x]} = w; (\"\\uE6C4\")(); }))); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1066; tryItOut("/*iii*/o2.t1[7] = ( /x/g \n);/*hhh*/function qspvfe(NaN, x = x, d = /*RXUE*/ '' .exec(\"\\n\\n\\n\"), y, c, x =  \"\" , this.x, x, \u3056, y =  /x/ , -24 = [[]], d, z, x, e, x, e, x, x, NaN, window = [,], z = /(?!(?:(?!\\B[^]|[^]))|[^]*)/im, a, \u3056, x = b, x, w, x, x = b, a, y = window, z, x, this.x, x, x, x){v0 + '';}");
/*fuzzSeed-204645237*/count=1067; tryItOut("v1 = Object.prototype.isPrototypeOf.call(v0, s1);");
/*fuzzSeed-204645237*/count=1068; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.cosh((( + ( + (Math.round(( + x)) >> x))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[(void 0), Infinity, (void 0), Infinity, Infinity, 0x080000000, (void 0), Infinity, Infinity, 0x080000000, Infinity, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), 0x080000000]); ");
/*fuzzSeed-204645237*/count=1069; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, -0, 0, -0x0ffffffff, 0.000000000000001, 0x100000001, -1/0, -Number.MAX_VALUE, 42, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, 0x07fffffff, -0x100000001, 1, Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), 1.7976931348623157e308, 0/0, -(2**53), 2**53+2, Math.PI, Number.MAX_VALUE, 0x080000000, -0x07fffffff, -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=1070; tryItOut("{ void 0; validategc(false); }");
/*fuzzSeed-204645237*/count=1071; tryItOut("s0 += s1;");
/*fuzzSeed-204645237*/count=1072; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return mathy0(( ! (Math.cbrt(Math.hypot(Math.fround(((Math.ceil((mathy1(x, y) | 0)) | 0) == Math.imul(x, ( + y)))), y)) >>> 0)), (((Math.pow(x, ((Math.fround(Math.pow((( + Math.fround(0x100000001)) | 0), y)) | 0) >>> 0)) >>> 0) << ((((Math.trunc(mathy0((Math.imul(Math.fround(y), (x >>> 0)) >>> 0), x)) >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0) | 0)) | 0)); }); ");
/*fuzzSeed-204645237*/count=1073; tryItOut("Array.prototype.forEach.call(o0.o1.a2, (function() { try { m1.delete(i1); } catch(e0) { } this.t1 = new Int8Array(b1); return m2; }));");
/*fuzzSeed-204645237*/count=1074; tryItOut("i1.next();");
/*fuzzSeed-204645237*/count=1075; tryItOut("\"use strict\"; iirasd(delete x.x);/*hhh*/function iirasd(){Object.defineProperty(this, \"v0\", { configurable: false, enumerable: true,  get: function() {  return t0.length; } });}");
/*fuzzSeed-204645237*/count=1076; tryItOut("\"use strict\"; a2.__proto__ = f1;");
/*fuzzSeed-204645237*/count=1077; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - ( + Math.max(Math.max(0x080000000, (-0x100000001 + x)), ( + Math.hypot(( ~ y), y))))) + Math.fround((( ~ Math.hypot(( + ( + ( + (( + x) < (y | 0))))), (Math.fround(( - (x >>> 0))) >>> 0))) >> Math.fround(( + Math.imul(( + (( ! (x >>> 0)) / y)), ( + Math.pow(-(2**53-2), Math.fround(mathy0(y, ( + Math.min(( + Math.log1p(y)), ( + -(2**53-2)))))))))))))); }); ");
/*fuzzSeed-204645237*/count=1078; tryItOut("\"use strict\"; for(let NaN = x in x) {print(x);/*RXUB*/var r = /\\s\u0090+|(^){4,8}|\\1++?(\\1\\1)+/gyim; var s = \"\"; print(s.replace(r, '')); print(r.lastIndex);  }");
/*fuzzSeed-204645237*/count=1079; tryItOut("a0.toSource = (function() { try { for (var p in g1.t2) { try { v1 = p0[\"eval\"]; } catch(e0) { } try { g2.m1 = this.g0.objectEmulatingUndefined(); } catch(e1) { } try { this.h1 = s0; } catch(e2) { } this.t1[({valueOf: function() { ();return 4; }})] = a2; } } catch(e0) { } try { neuter(b2, \"same-data\"); } catch(e1) { } for (var p in p1) { t0.set(t2, (b === y << (p={}, (p.z = (void shapeOf(({a1:1}))))()))); } return f1; });");
/*fuzzSeed-204645237*/count=1080; tryItOut("v1 = t2.length\n");
/*fuzzSeed-204645237*/count=1081; tryItOut("mathy2 = (function(x, y) { return ( + Math.max(( + Math.fround(Math.min(( + ( + (Math.min((Math.max(( + x), (x | 0)) | 0), Math.fround(( + y))) | 0))), Math.fround(Math.imul(Math.fround(y), Math.fround(( ~ ( + ( ~ ( + (mathy1(( + y), (Math.clz32(2**53) | 0)) | 0))))))))))), ( + ((((Math.sin(mathy0(x, x)) >>> 0) | 0) , (Math.atan2(Math.min((( + y) >= ( + y)), ( + ( - Math.fround(Math.atanh(Math.fround(0/0)))))), y) | 0)) | 0)))); }); testMathyFunction(mathy2, /*MARR*/[(void 0), -(2**53-2), new Boolean(false), (void 0), (void 0), -(2**53-2), new Boolean(false), (void 0), (void 0), (void 0), (void 0), -(2**53-2), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0), new Boolean(false), (void 0), (void 0), -(2**53-2), new Boolean(false), new Boolean(false), new Boolean(false), -(2**53-2), -(2**53-2), (void 0), (void 0), -(2**53-2), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), -(2**53-2), (void 0), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0), (void 0), -(2**53-2), (void 0), new Boolean(false), -(2**53-2), (void 0), -(2**53-2), (void 0), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), -(2**53-2), -(2**53-2), (void 0)]); ");
/*fuzzSeed-204645237*/count=1082; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( - ( + (Math.cosh(0x100000000) + x))) / ((((Math.sqrt(((( ~ (y >>> 0)) * x) | 0)) | 0) > ( + Math.hypot(y, ( + ( + Math.fround(y)))))) ? (( - x) && Math.fround(Math.min(y, (Math.tan(y) | 0)))) : ((( + Math.imul(x, Math.fround(( + x)))) + (((mathy2(Math.trunc(-0x080000001), x) >> (( + ( ! x)) >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [42, -Number.MAX_VALUE, 1.7976931348623157e308, 0/0, 0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 1, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, 0x080000001, 1/0, -(2**53-2), -0x080000000, 0, -0, -(2**53), 2**53+2, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -0x100000001, 0x100000001, 0x100000000, 0.000000000000001, 2**53-2, 2**53, 0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1083; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-(2**53+2), 0, 42, 2**53-2, 2**53, -0x080000000, -0x080000001, -Number.MIN_VALUE, 1, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, Math.PI, 2**53+2, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 1/0, Number.MAX_VALUE, -(2**53-2), -(2**53), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 0/0, 1.7976931348623157e308, -0x100000001, -0]); ");
/*fuzzSeed-204645237*/count=1084; tryItOut("\"use strict\"; o2 + '';");
/*fuzzSeed-204645237*/count=1085; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ( ~ Math.fround(Math.hypot(Math.fround(((( ~ x) | 0) ** ( + (( + (y && 0)) ? ((x !== (( ~ y) >>> 0)) >>> 0) : ( + Math.imul(Math.fround(y), -0x100000001)))))), Math.pow(x, Math.pow((x >>> 0), (y != y))))))) != (Math.fround(Math.fround(Math.atanh(( + Math.abs(0x080000000))))) / Math.expm1(Math.imul(Math.log1p((((y >>> 0) && ((y ? x : x) >>> 0)) >>> 0)), (0 >>> 0))))); }); testMathyFunction(mathy4, ['0', false, NaN, undefined, 0, '/0/', (new Boolean(true)), /0/, ({valueOf:function(){return 0;}}), '', 1, null, (new Number(-0)), [], ({toString:function(){return '0';}}), (new Number(0)), [0], '\\0', true, ({valueOf:function(){return '0';}}), (new String('')), objectEmulatingUndefined(), (function(){return 0;}), (new Boolean(false)), -0, 0.1]); ");
/*fuzzSeed-204645237*/count=1086; tryItOut("e0.delete(i2);");
/*fuzzSeed-204645237*/count=1087; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(( + Math.max(( + ( ~ x)), ( + (( - ((mathy0((( + (( + x) ? ( + y) : ( + -0x100000001))) >>> 0), Math.pow(Math.fround(( + ( - x))), 0x0ffffffff)) >>> 0) >>> 0)) >>> 0)))), Math.hypot(Math.atan2(x, Math.fround(Math.imul(( + (( + mathy0(0x080000001, -(2**53))) ** ( + Number.MAX_VALUE))), ((mathy0(y, mathy0((x ^ y), x)) | 0) | 0)))), (Math.fround(Math.fround((( + -Number.MAX_SAFE_INTEGER) >>> x))) !== ( - ( + x))))); }); testMathyFunction(mathy1, [Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), 0x07fffffff, 0x080000001, 2**53-2, 0.000000000000001, 0x100000000, 1, -0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, -(2**53+2), 0/0, 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -0x100000000, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, 0, -0x0ffffffff, -0, 42, 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=1088; tryItOut("mathy4 = (function(x, y) { return (Math.min((Math.fround(( ! Math.fround((( + x) && (Math.atan2((( - (x | 0)) >>> 0), Math.tan(-1/0)) * Math.log(Math.fround(x))))))) >>> 0), ( + ( ! Math.fround(Math.imul((Math.fround((Math.exp(-0x100000001) ? Math.fround(y) : Math.fround(Number.MIN_VALUE))) >>> 0), (Math.pow(( - ( + (( + y) / ( + y)))), (y | 0)) >>> 0)))))) >>> 0); }); ");
/*fuzzSeed-204645237*/count=1089; tryItOut("o0.v1 = evaluate(\"let x = (uneval(({}) = x = Proxy.createFunction(({/*TOODEEP*/})( \\\"\\\" ), \\\"\\\\u2CE2\\\")));{ if (isAsmJSCompilationAvailable()) { void 0; void schedulegc(4); } void 0; } m0 + '';\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-204645237*/count=1090; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1091; tryItOut("\"use strict\"; f1(f0);");
/*fuzzSeed-204645237*/count=1092; tryItOut(";");
/*fuzzSeed-204645237*/count=1093; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(mathy1(Math.fround(( ~ Math.fround(Math.cos(Math.fround(Math.imul(((-(2**53+2) || x) ? Math.fround(Math.imul(-0x100000001, x)) : x), Math.atan2(y, x))))))), Math.fround(mathy1(Math.fround((mathy1((mathy1(( + (((Math.hypot(x, y) | 0) ** (y | 0)) | 0)), ( + ( + ( ! ( + y))))) | 0), (Math.acos(-0x080000001) | 0)) | 0)), Math.fround(( ! ((y | 0) | (( + Math.hypot(y, x)) | 0)))))))); }); testMathyFunction(mathy2, [-0x080000001, 2**53+2, 42, -0, -(2**53), 0.000000000000001, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 2**53, -1/0, 0, 0/0, 1, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 0x100000000, 2**53-2, 1/0, Math.PI]); ");
/*fuzzSeed-204645237*/count=1094; tryItOut("a2 = g0.objectEmulatingUndefined();");
/*fuzzSeed-204645237*/count=1095; tryItOut("mathy5 = (function(x, y) { return mathy1(mathy1((Math.fround((42 >>> 0)) >>> 0), ( + ((( + ( + (((( + (y | y)) >>> 0) / (Math.tan((x ? y : y)) >>> 0)) >>> 0))) >>> 0) >= ( + Math.hypot((-0 ** ( ! 0x080000001)), x))))), (( ! ((Math.round((mathy3(Math.fround(Math.exp((( ~ (0x100000000 | 0)) | 0))), Math.fround((mathy3(((Math.atan2((Math.fround(Math.min(x, Math.fround(x))) >>> 0), x) | 0) >>> 0), (Math.fround(Math.hypot(0x0ffffffff, Math.fround(( + (x | x))))) >>> 0)) >>> 0))) | 0)) | 0) >>> 0)) | 0)); }); testMathyFunction(mathy5, /*MARR*/[{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, 10, {}, {}, 10, 10, {}, {}, [1], 10, [1], [1], [1], {}, [1], [1], 10, {}, {}, {}, 10, [1], {}, {}, {}]); ");
/*fuzzSeed-204645237*/count=1096; tryItOut("\"use strict\"; p0.valueOf = (function mcc_() { var mcajbb = 0; return function() { ++mcajbb; f0(/*ICCD*/mcajbb % 10 == 6);};})();");
/*fuzzSeed-204645237*/count=1097; tryItOut("e0.add(v2);");
/*fuzzSeed-204645237*/count=1098; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, -(2**53-2), 2**53+2, 1, -Number.MIN_VALUE, 0x080000000, -(2**53), 2**53, 0x100000001, Number.MIN_SAFE_INTEGER, -0, -0x100000001, 0x07fffffff, 0x080000001, -0x07fffffff, -0x080000001, 0, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, -1/0, -(2**53+2), -0x0ffffffff, 42, -0x080000000, Number.MIN_VALUE, 0/0, Math.PI, 1/0]); ");
/*fuzzSeed-204645237*/count=1099; tryItOut("testMathyFunction(mathy2, [-(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x07fffffff, 1/0, 2**53+2, 1, 2**53-2, 0x100000001, -0x080000000, -0x080000001, 0x080000000, 0/0, 2**53, -(2**53-2), 0, -0x100000001, Math.PI, 42, 1.7976931348623157e308, -1/0, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1100; tryItOut("o2.v0 = new Number(m0);");
/*fuzzSeed-204645237*/count=1101; tryItOut("\"use strict\"; \u000dprint(null);const z =  \"\"  ?  /x/  : new RegExp(\"\\\\2(?!\\u8a26)|(?:[^])+|.|(.){0}\\\\W|[^]*|\\\\d|[^]{4,5}+?|[^]?{0,255}\", \"gyi\");");
/*fuzzSeed-204645237*/count=1102; tryItOut("\"use strict\"; selectforgc(o1);L: var sruwji = new SharedArrayBuffer(4); var sruwji_0 = new Int32Array(sruwji); sruwji_0[0] = 2; Array.prototype.sort.call(a0, (function mcc_() { var vjpzee = 0; return function() { ++vjpzee; f1(/*ICCD*/vjpzee % 7 == 4);};})());");
/*fuzzSeed-204645237*/count=1103; tryItOut("\"use asm\"; ");
/*fuzzSeed-204645237*/count=1104; tryItOut("mathy5 = (function(x, y) { return ((mathy4(((((( ~ (Math.PI >>> 0)) >>> 0) ^ Math.pow(((y | 0) + y), (Math.trunc((x | 0)) | 0))) | 0) ? (mathy4(Number.MAX_SAFE_INTEGER, x) | 0) : (x | 0)), ((Math.ceil((y >>> 0)) >>> 0) | 0)) >> (( + (mathy2(y, Math.fround(Math.acos(Math.acos((-0x100000000 >>> 0))))) >>> 0)) | 0)) > ( ~ Math.fround(( + y)))); }); testMathyFunction(mathy5, [0/0, -(2**53+2), 0x07fffffff, -0x080000001, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, -0, 0x080000000, 0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 42, -(2**53), -Number.MAX_VALUE, 0.000000000000001, Math.PI, -(2**53-2), -0x0ffffffff, -1/0, -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, 2**53-2, -0x100000000, 1/0, -0x080000000, 2**53+2, -Number.MIN_VALUE, 1, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=1105; tryItOut("\"use strict\"; return;");
/*fuzzSeed-204645237*/count=1106; tryItOut("testMathyFunction(mathy0, [Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 0, 0x07fffffff, -0x07fffffff, -0x080000001, 1/0, -0x080000000, -Number.MAX_VALUE, 42, -0, 1.7976931348623157e308, 0.000000000000001, -(2**53+2), 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -(2**53), -0x100000001, 0x080000001, 2**53, -Number.MIN_VALUE, 2**53-2, Number.MIN_VALUE, -0x100000000, 0x080000000]); ");
/*fuzzSeed-204645237*/count=1107; tryItOut("\"use strict\"; a2.pop((({ set \"13\" b (delete, x = x)\"use asm\";   var abs = stdlib.Math.abs;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((1)+(0xff549115)))|0;\n    {\n      d1 = (d1);\n    }\n    d1 = (+abs(((+(-1.0/0.0)))));\n    d1 = (-3.777893186295716e+22);\n    d0 = (d1);\n    d0 = (+((-590295810358705700000.0)));\n    return (((-0x8000000)))|0;\n  }\n  return f;, /*toXFun*/toString: function() { return x; } })).call(\"\\uA92E\", x, (4277)), (x = this));");
/*fuzzSeed-204645237*/count=1108; tryItOut("\"use strict\"; a0 = new Array;");
/*fuzzSeed-204645237*/count=1109; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2?\", \"gi\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-204645237*/count=1110; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (((d0)) - ((d1)));\n    d1 = (d1);\n    (Int16ArrayView[0]) = ((0xed5ab0df) % ((-(0xe53f4aa2))>>>(((((Int16ArrayView[1])) << ((-0x8000000)-((295147905179352830000.0) == (2305843009213694000.0))+(-0x8000000)))))));\n    d1 = (d0);\n    {\n      (Uint32ArrayView[4096]) = (((abs((~~(+/*FFI*/ff((((d1) + (-(x)))), ((((-0x8000000)+(0xfaff1c57)-(0x8be5dca7)) << ((0x7fffffff) / (0x668c2f12)))), ((((0x7edd0256)*0x9c541) >> ((0xfc9d24e5)+(0xffffffff)+(0x6c34ead0)))), ((Infinity)), ((((-2147483649.0)) - ((-524289.0)))), ((9.44473296573929e+21)), ((-128.0)), ((-34359738369.0)), ((33.0)), ((1.5111572745182865e+23)), ((-17592186044417.0)), ((549755813889.0)), ((2.4178516392292583e+24))))))|0))+(0x4b38fc3a));\n    }\n    switch ((abs(((-0xf2aa3*(0xfc9234b2)) << ((0x2b4ca051) / (-0x3bd0551))))|0)) {\n    }\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: Math.fround}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1.7976931348623157e308, -(2**53+2), 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, -0x0ffffffff, 1, -0x080000000, -0x100000001, -1/0, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MIN_VALUE, -(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, Math.PI, -0x100000000, 2**53, -0x080000001, -Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -(2**53), 0, 0/0, 0x100000000, -0, 0x080000000]); ");
/*fuzzSeed-204645237*/count=1111; tryItOut("\"use asm\"; ");
/*fuzzSeed-204645237*/count=1112; tryItOut("i0 + '';");
/*fuzzSeed-204645237*/count=1113; tryItOut("this.m2.set(b2, o2);");
/*fuzzSeed-204645237*/count=1114; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ((Math.pow(Math.max(y, ( + Math.clz32((Math.tan(y) >>> 0)))), Math.abs(x)) >>> 0) != ( - Math.hypot(y, y)))); }); ");
/*fuzzSeed-204645237*/count=1115; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=1116; tryItOut("mathy2 = (function(x, y) { return mathy1(( ! ((( ! Math.sqrt(Math.log10(x))) | 0) + x)), ( + Math.atan2(( + Math.min(((( ! Math.fround((-0x100000001 + 0/0))) | 0) >>> 0), Math.fround(( ~ Math.fround(Math.min((x + x), (Math.imul((y | 0), ( + x)) | 0))))))), mathy0(Math.fround((( ! ((Math.fround(Math.pow(Math.fround(( ! y)), ( + x))) >>> x) >>> 0)) | 0)), (mathy0(y, ( + Math.expm1(x))) >>> ( + -(2**53))))))); }); ");
/*fuzzSeed-204645237*/count=1117; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1118; tryItOut("print(o2);");
/*fuzzSeed-204645237*/count=1119; tryItOut("print(/*FARR*/[, , x].map(function(y) { yield y; a0[({valueOf: function() { (false);\u0009(\"\u03a0\");return 3; }})];; yield y; }, let (c) (4277)));");
/*fuzzSeed-204645237*/count=1120; tryItOut("f0(o1);");
/*fuzzSeed-204645237*/count=1121; tryItOut("\"use strict\"; h1.has = g0.f1;");
/*fuzzSeed-204645237*/count=1122; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1123; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0((Math.min((mathy0(Math.cbrt(y), Math.min(0x100000001, y)) | 0), Math.pow(mathy0(x, ( ! y)), Math.tanh(x))) | 0), ((Math.sign(( + (( + (Math.fround(((y | 0) | ((( ! (0/0 | 0)) | 0) | 0))) | 0)) | 0))) | 0) | 0)); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, -0x07fffffff, -0x100000001, 0x100000000, 0x080000001, 1, -(2**53), 2**53-2, -(2**53+2), 0x080000000, 1/0, -1/0, 0/0, 42, -0, 2**53, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, 0, 1.7976931348623157e308, Math.PI, Number.MAX_VALUE, -0x080000001, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=1124; tryItOut("\"use asm\"; for (var v of m1) { try { o0 + m0; } catch(e0) { } try { s0 = s1; } catch(e1) { } try { Object.defineProperty(this, \"i1\", { configurable: false, enumerable: (x % 12 != 7),  get: function() {  return a0.values; } }); } catch(e2) { } for (var v of o0) { try { this.a0.sort((function(j) { if (j) { try { a2 = this.r1.exec(s2); } catch(e0) { } try { this.v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (({prototype: undefined })), noScriptRval: ((a =  /x/ )), sourceIsLazy: (x % 3 != 2), catchTermination: true })); } catch(e1) { } try { e2.delete(o0); } catch(e2) { } o1.valueOf = (function() { s0 += 'x'; return f1; }); } else { try { s0 += 'x'; } catch(e0) { } h2.fix = f1; } })); } catch(e0) { } try { delete this.s1[\"delete\"]; } catch(e1) { } a1 = Array.prototype.filter.call(a2, (function() { for (var j=0;j<91;++j) { f2(j%4==0); } }), m2); } }");
/*fuzzSeed-204645237*/count=1125; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy4(Math.imul(((Math.log2(mathy4(mathy2(y, x), y)) | 0) | 0), (( ~ -0x100000001) | 0)), ( + Math.atanh(Math.fround(Math.cosh(Math.fround(0)))))); }); testMathyFunction(mathy5, [2**53, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 1, -0, -1/0, 0x100000001, 0x07fffffff, -0x080000000, 0/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), -0x100000000, -Number.MAX_VALUE, Number.MAX_VALUE, 0.000000000000001, 1/0, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, -0x0ffffffff, -0x100000001, 0, -(2**53), 0x080000001, -0x080000001, 2**53+2]); ");
/*fuzzSeed-204645237*/count=1126; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((-0x33b3f55)+(i0)))|0;\n    return (((0xc39fa494)-(0xbf76e970)))|0;\n  }\n  return f; })(this, {ff: (4277)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ ]); ");
/*fuzzSeed-204645237*/count=1127; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy1(Math.log2(Math.fround(( + (x ** ( + Math.min(-Number.MIN_SAFE_INTEGER, y)))))), Math.sin(( ! (Math.max((2**53 | 0), (Math.acos(Math.PI) | 0)) | 0)))); }); testMathyFunction(mathy3, [-0x100000000, Math.PI, 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, 2**53, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 42, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, -0, 2**53-2, 0x100000001, 0x100000000, 0x080000000, -0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 0, Number.MIN_VALUE, -0x080000001, 0/0, -1/0, -0x07fffffff, -Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-204645237*/count=1128; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.fround((mathy1((Math.fround((mathy0((Math.pow((( ! x) | 0), 0.000000000000001) >>> 0), Math.fround(y)) | 0)) ? (Math.fround(mathy0(Math.fround(x), y)) > (Math.imul(Math.acos((x | 0)), y) >>> 0)) : ( + ( ~ Math.fround(2**53-2)))), ( + (( + ((x | 0) == Math.tanh(Math.asin(y)))) == ( + ( ! ((Math.fround(Math.hypot(Math.fround(y), Math.fround(y))) ? y : y) >>> 0)))))) >>> 0)) ? Math.fround(Math.fround(( + Math.fround(mathy1(Math.max((-Number.MIN_SAFE_INTEGER >>> 0), ( + Math.min(( + x), ( + y)))), ( - y)))))) : Math.fround(((( ~ Math.fround((( + Math.atan2(2**53+2, Number.MAX_SAFE_INTEGER)) | 0))) | 0) < Math.min((Math.atan((Math.fround(Math.ceil(y)) >= Math.fround(( + x)))) | 0), ( + Math.imul(Math.ceil(y), ( ! x)))))))); }); ");
/*fuzzSeed-204645237*/count=1129; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return ( + (Math.acosh(( + Math.abs(( + (( + (x ? -0x100000000 : y)) - ( + (( - (-Number.MAX_VALUE >>> 0)) >>> 0))))))) || ( + (Math.imul(Math.hypot(Math.fround(((mathy2((x | 0), (y | 0)) | 0) ? Math.fround(mathy2(x, (( ! (x | 0)) | 0))) : Math.fround((Math.hypot(y, ( + y)) >>> 0)))), ( - Math.fround(y))), (Math.atan2(((( + (Math.max(-Number.MIN_VALUE, ( + y)) | 0)) | 0) | 0), ((Math.acosh((Math.hypot(0x080000001, Math.pow(-(2**53), ( + (( + (y | 0)) | 0)))) | 0)) | 0) | 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), -Number.MAX_VALUE, -1/0, 0x080000000, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, 0x100000001, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, Math.PI, 0x080000001, 0, -0x080000000, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, 2**53, -0x0ffffffff, 1/0, -0, 42, 0x100000000, -(2**53), 1, -0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=1130; tryItOut("s0 += s2;");
/*fuzzSeed-204645237*/count=1131; tryItOut("\"use strict\"; a2 + '';");
/*fuzzSeed-204645237*/count=1132; tryItOut("mathy2 = (function(x, y) { return (((( + Math.atanh(0x100000000)) >>> 0) ? (Math.clz32((((((x << (Math.sin(( + (x ? x : (x ? y : x)))) >>> 0)) >>> 0) | 0) ? ((( ! (y >>> 0)) >>> 0) | 0) : x) | 0)) | 0) : (( + Math.imul(((Math.fround((Math.exp((Math.log1p(x) | 0)) | 0)) ? y : Math.tanh((Math.exp(y) | 0))) >>> 0), ( + (((Math.log10((Math.fround((Math.fround(y) < Math.fround(Math.fround(( ~ Math.max(( + x), x)))))) >>> 0)) | 0) & Math.fround(y)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy2, [-(2**53-2), Number.MIN_VALUE, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, 1/0, 0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 0.000000000000001, 2**53+2, 2**53-2, -(2**53+2), 0x080000000, -Number.MAX_VALUE, -1/0, 2**53, Number.MAX_VALUE, 42, -0x080000000, Math.PI, -0x0ffffffff, -0, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, 0x100000001, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-204645237*/count=1133; tryItOut("mathy1 = (function(x, y) { return (( ! ((Math.fround((Math.fround((Math.pow(Math.imul((y && Math.fround(Math.exp(Math.fround(0)))), Math.atan2((y >>> 0), (y >>> 0))), x) | 0)) | (Math.log(Math.hypot(Math.pow(Math.fround(Math.atan2(x, -Number.MAX_VALUE)), Math.fround(y)), ( + Math.pow(( + y), y)))) >>> 0))) | 0) ** (Math.imul(y, ( + Math.asinh(( + ( + ( + ( + y))))))) | 0))) >>> 0); }); testMathyFunction(mathy1, [-0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 1, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0x080000000, 1/0, 0/0, -(2**53-2), -0, 0, -0x0ffffffff, 0x080000000, 0x080000001, -0x100000001, -1/0, 0x100000000, 2**53+2, 42, 2**53, Math.PI, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-204645237*/count=1134; tryItOut("v2 = t1.length;");
/*fuzzSeed-204645237*/count=1135; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1136; tryItOut("\"use strict\"; /*infloop*/L: for (let x of true.prototype) delete h2.keys;");
/*fuzzSeed-204645237*/count=1137; tryItOut("\"use strict\"; Object.defineProperty(this, \"o2\", { configurable: (x % 2 == 0), enumerable: (/*UUV1*/(x.clear = /*wrap3*/(function(){ var cbsxqz = (4277); ((4277))(); }))),  get: function() {  return {}; } });");
/*fuzzSeed-204645237*/count=1138; tryItOut("for (var p in v1) { try { v2 = Array.prototype.some.apply(a2, [(function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      (Uint32ArrayView[2]) = ((((0x81cf4286)-(0x8bf7cf8c))>>>((i0)+((0xf9c50b1f))-(i0))) % (((((((((0x5afefa75) / (0x9861868b)) & (0xd562*(0xfc3f5f59)))))|0)))>>>((0xfcfe217a)*0xb449c)));\n    }\n    (Uint32ArrayView[(((((0xffffffff))+(0x8c77e798))>>>((0x2dfd277) % (-0x8000000))) % (0x306d7e70)) >> 2]) = ((((0xffffffff) / (0x84249449)) >> (((0x12a0ad1d))+(1))) / (imul((((((((0xf8964cb9)) | ((0xfda1e8c7)))))>>>((i0)))), ((~~(d1))))|0));\n    d1 = (6.044629098073146e+23);\n    return +((NaN));\n  }\n  return f; }), t0, t0]); } catch(e0) { } try { print(x); } catch(e1) { } print(uneval(b1)); }function a(c, eval)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.9342813113834067e+25;\n    var i3 = 0;\n    {\n      d2 = (d2);\n    }\n    d1 = ((d1) + (((Float64ArrayView[1])) / ((-((+(((i3)*0x48f19)>>>((-0x7ac9d43)))))))));\n    d1 = (+((d2)));\n    (Float32ArrayView[1]) = ((d0));\n    {\n      switch ((~((0x11850e5d) % (~((0xca5a84ba)))))) {\n        case 0:\n          {\n            d0 = (1.001953125);\n          }\n          break;\n      }\n    }\n    i3 = (0xf1bc0753);\n    d0 = (-9.0);\n    return ((((((0xe7f23962)-(0xfefb5c34))|0))))|0;\n  }\n  return f;this.s2 += 'x';");
/*fuzzSeed-204645237*/count=1139; tryItOut("print(x);");
/*fuzzSeed-204645237*/count=1140; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! Math.hypot(Math.atan((((y >>> 0) === x) >>> 0)), Math.atan(( + Math.acos((x >= y)))))); }); testMathyFunction(mathy5, [0x07fffffff, 0x100000000, -0x07fffffff, Math.PI, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 1/0, -0, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 0, 0x080000001, -Number.MAX_VALUE, -(2**53), 1, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 42, -(2**53-2), 2**53, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 0x080000000, -0x080000000, Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-204645237*/count=1141; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=1142; tryItOut("/*infloop*/for(let w in ((String.prototype.split)(x++)))for (var v of e2) { try { e0.add(o1); } catch(e0) { } p1.__iterator__ = (function(j) { if (j) { try { o0.s0 += g0.s2; } catch(e0) { } try { a2.sort((function mcc_() { var wuaqnd = 0; return function() { ++wuaqnd; if (/*ICCD*/wuaqnd % 11 == 0) { dumpln('hit!'); g2.offThreadCompileScript(\"\\\"use strict\\\"; o2.v1 = evaluate(\\\"v2 = a2.length;\\\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: undefined, noScriptRval: false, sourceIsLazy: false, catchTermination: true }));\"); } else { dumpln('miss!'); try { h2.fix = f0; } catch(e0) { } try { h0.enumerate = (function(j) { if (j) { g1.s2 += s0; } else { a1.reverse(i0, t2, h2); } }); } catch(e1) { } try { v2 = evalcx(\"function f1(g1)  { yield this } \", this.g2); } catch(e2) { } a0[9] = v1; } };})(), s1); } catch(e1) { } Array.prototype.push.call(a1, e2, m1); } else { try { s1 += 'x'; } catch(e0) { } try { i0.toString = (function(j) { if (j) { try { Array.prototype.reverse.apply(g2.a2, [o2.h2, a2, g0]); } catch(e0) { } try { /*MXX1*/o1 = g1.String.prototype.sub; } catch(e1) { } g1.t2[5] = f1; } else { m0.set(s1, f0); } }); } catch(e1) { } try { this.a0 = r1.exec(s0); } catch(e2) { } a2 = arguments.callee.caller.arguments; } }); }");
/*fuzzSeed-204645237*/count=1143; tryItOut("g1 = t2[17];");
/*fuzzSeed-204645237*/count=1144; tryItOut("\"use strict\"; print((x = Proxy.create(({/*TOODEEP*/})([,,z1]), x)));");
/*fuzzSeed-204645237*/count=1145; tryItOut("t2 = new Uint32Array(b1, 16, 3);");
/*fuzzSeed-204645237*/count=1146; tryItOut("mathy3 = (function(x, y) { return Math.sqrt(Math.fround(( ! Math.max(y, ((Math.fround((( ! y) < Math.fround(Math.acosh(-Number.MIN_SAFE_INTEGER)))) - (mathy1(y, Number.MIN_SAFE_INTEGER) | 0)) >= x))))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), undefined, ({valueOf:function(){return '0';}}), '0', (new Number(0)), (new String('')), -0, /0/, [0], 1, '', [], (new Boolean(false)), ({valueOf:function(){return 0;}}), '/0/', false, (function(){return 0;}), 0, (new Number(-0)), objectEmulatingUndefined(), NaN, true, null, (new Boolean(true)), 0.1, '\\0']); ");
/*fuzzSeed-204645237*/count=1147; tryItOut("\"use strict\"; L:with({z: ((Math.hypot(-17, 26)) !== \nwindow) **= null--}){z = a2[v0];\na1[({valueOf: function() { print(x);return 10; }})] = this >=  '' ;\nswitch(((window ^  '' ) && x)) { case (delete = (p={}, (p.z = -12)())): break; break; break; default: break; case z: /* no regression tests found */break;  } }");
/*fuzzSeed-204645237*/count=1148; tryItOut("mathy2 = (function(x, y) { return (Math.max(Math.atan(( + Math.pow((x != y), Math.fround(x)))), ((((x >>> 0) , x) | 0) << ( - (Math.atanh(( + 0x080000001)) | 0)))) ? (Math.cosh((( + (Number.MAX_SAFE_INTEGER - ( + (((Math.fround(( ~ 0x07fffffff)) + (( + Math.fround(Math.clz32(Math.fround(x)))) == y)) | 0) | (0.000000000000001 ? ( + ( ! Math.fround(x))) : (x ** (( + Math.acos(y)) >>> 0))))))) | 0)) | 0) : Math.asinh(((((x | 0) || (( + (( + x) >> ( + (( ! y) >>> 0)))) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy2, [0/0, -Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, 2**53+2, 2**53-2, 1, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, 2**53, Number.MAX_VALUE, 0, -1/0, 0x100000001, -0x080000001, -0x0ffffffff, -(2**53-2), -0, 0x07fffffff, -Number.MIN_VALUE, 1/0, -0x100000001, 42]); ");
/*fuzzSeed-204645237*/count=1149; tryItOut("\"use strict\"; v1 = new Number(4);");
/*fuzzSeed-204645237*/count=1150; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i1)*0xeb973))|0;\n  }\n  return f; })(this, {ff: function  x (window =  '' ) { \"use strict\"; yield /*UUV2*/(z.resolve = z.bind) } }, new ArrayBuffer(4096)); testMathyFunction(mathy5, [[0], (new String('')), NaN, (new Boolean(true)), [], 0, ({valueOf:function(){return '0';}}), '/0/', ({valueOf:function(){return 0;}}), /0/, false, 1, objectEmulatingUndefined(), undefined, '', (function(){return 0;}), true, (new Number(-0)), '\\0', ({toString:function(){return '0';}}), '0', (new Number(0)), -0, (new Boolean(false)), 0.1, null]); ");
/*fuzzSeed-204645237*/count=1151; tryItOut("mathy0 = (function(x, y) { return (Math.hypot((Math.log(Math.tan(((Math.log2((y | 0)) | 0) ^ Math.hypot(((x >>> 0) !== x), y)))) | 0), Math.fround((( ! (((((( + 0) ? Math.fround(y) : (( + Math.hypot(( + x), ( + (y ** (y >>> 0))))) | 0)) | 0) | 0) ** (( - y) | 0)) | 0)) | 0))) | 0); }); ");
/*fuzzSeed-204645237*/count=1152; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(((( ~ Math.fround(Math.fround(Math.atanh(x)))) >>> 0) + Math.fround(Math.fround(Math.hypot(x, Math.fround(Math.max(Math.abs(y), Math.fround(Math.log1p(-Number.MIN_SAFE_INTEGER))))))))) < ( + Math.max(Math.max((Math.fround(Math.atanh(((Math.tanh((( ~ (y >>> 0)) >>> 0)) | 0) >>> 0))) <= x), x), ( + -(2**53+2))))); }); ");
/*fuzzSeed-204645237*/count=1153; tryItOut("mathy2 = (function(x, y) { return Math.pow(Math.trunc(Math.sign(Math.fround((( ! (x | 0)) | 0)))), ( ! ( + Math.fround(mathy0(Math.fround(mathy1(Math.fround(( + ( - (x >>> 0)))), Math.fround(Math.min(x, y)))), ( ! ( + ( - (( ! -(2**53-2)) >>> 0))))))))); }); testMathyFunction(mathy2, [-0, 0.000000000000001, -0x080000000, 0x080000001, 0x080000000, 0x0ffffffff, 1/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -0x080000001, 2**53-2, -0x100000001, 0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 2**53+2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -0x07fffffff, Math.PI, -0x0ffffffff, 1.7976931348623157e308, 0x100000000, -(2**53), -(2**53+2), -1/0, -(2**53-2), 0x07fffffff, 0/0, 1]); ");
/*fuzzSeed-204645237*/count=1154; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[ /x/g , true,  /x/g ]); ");
/*fuzzSeed-204645237*/count=1155; tryItOut("mathy3 = (function(x, y) { return Math.sinh(( + Math.max(((Math.sin(( ! (Math.asin(y) | 0))) | 0) | 0), (((x < (( + ( + ( + y))) >>> 0)) >>> 0) | 0)))); }); testMathyFunction(mathy3, ['0', (new Number(0)), undefined, ({valueOf:function(){return 0;}}), NaN, false, 0, [0], [], (new String('')), (new Boolean(false)), ({valueOf:function(){return '0';}}), '\\0', (new Number(-0)), true, ({toString:function(){return '0';}}), '', (function(){return 0;}), 1, /0/, 0.1, -0, objectEmulatingUndefined(), (new Boolean(true)), null, '/0/']); ");
/*fuzzSeed-204645237*/count=1156; tryItOut("\"use strict\"; with(((x.__defineSetter__(\"x\", arguments.callee.caller)) = intern( /x/ )))g1.f2 = Proxy.create(h1, m2);");
/*fuzzSeed-204645237*/count=1157; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i0 = (i1);\n    i1 = (0xb6e3a211);\n    {\n      i1 = (i1);\n    }\n    i1 = ((+((((+(-1.0/0.0))) % ((((+abs(((+atan2(((17.0)), ((0.0009765625)))))))) - ((-9007199254740992.0))))))) > (-562949953421313.0));\n    {\n      (Float64ArrayView[((Int32ArrayView[1])) >> 3]) = ((524289.0));\n    }\n    i1 = ((((NaN)) / (((-513.0) + (-8589934591.0)))) != (+((+/*FFI*/ff((((+/*FFI*/ff((((((1.25)) - ((-281474976710657.0))) + (8191.0))), ((1.03125)), ((0x43d4a46a)), ((-140737488355329.0)), ((4294967297.0)), ((0.0625)), ((36028797018963970.0)), ((9007199254740992.0)))) + ((72057594037927940.0) + ((-36028797018963970.0) + (-5.0))))), (((~((i0)-(i1))) <= (~~(-3.0)))))))));\n    {\n      return (((i1)+(i1)))|0;\n    }\n    return (((i0)-(((((function sum_slicing(hzyhaz) { ; return hzyhaz.length == 0 ? 0 : hzyhaz[0] + sum_slicing(hzyhaz.slice(1)); })(/*MARR*/[Infinity, true, 0x3FFFFFFF, true, true, 0x3FFFFFFF, Infinity, true, Infinity, true, x, Infinity, true, Infinity, x, x, Infinity, true, Infinity, Infinity, true, 0x3FFFFFFF, 0x3FFFFFFF, true, true, true, Infinity, Infinity, 0x3FFFFFFF, true, x, Infinity, true, 0x3FFFFFFF, true, x, 0x3FFFFFFF, true, true, true, true, 0x3FFFFFFF, Infinity, true, Infinity, Infinity, Infinity, true, 0x3FFFFFFF, 0x3FFFFFFF, true, true, Infinity, x, true, true, Infinity, x, true, true, Infinity, true, x, true, true, 0x3FFFFFFF, true, x, 0x3FFFFFFF, x, 0x3FFFFFFF, Infinity, Infinity, true, Infinity, x, true, Infinity, Infinity, Infinity, true, true, true, true, true, Infinity, Infinity, true, 0x3FFFFFFF, true, 0x3FFFFFFF, true, Infinity, x, x, Infinity, true, true, true, true, x, true, true, x, x, Infinity, true, Infinity, 0x3FFFFFFF, x, x, x, true, x, Infinity, true, 0x3FFFFFFF, true, true, true, Infinity, true, true, true, x, Infinity, 0x3FFFFFFF, x, true, 0x3FFFFFFF, Infinity, Infinity, x, true, true, Infinity, true, true, true, true, Infinity]))) | (((((0xfed13abc)*0x4c7d1) ^ ((0x6402e2cd) % (0x27360c4d)))))) < (0x31c30442))))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return ( + ( + ( + Math.pow(( + -Number.MAX_SAFE_INTEGER), 0x080000000)))); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0/0, -0, 1, -1/0, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, 0x07fffffff, -(2**53-2), 0x080000001, 1.7976931348623157e308, 42, 2**53, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, 1/0, -0x0ffffffff, 0x080000000, 0, 0x0ffffffff, -0x07fffffff, -0x080000000, -(2**53+2), -0x100000000, 0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1158; tryItOut("mathy1 = (function(x, y) { return ( - ( - Math.tanh((x && ( + (x / y)))))); }); testMathyFunction(mathy1, [-(2**53-2), 0x100000001, -0, Math.PI, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 0x100000000, -0x100000001, 2**53+2, -(2**53+2), 42, -1/0, 2**53, 0, Number.MIN_SAFE_INTEGER, -0x100000000, 1, 0x0ffffffff, -(2**53), -0x080000001, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, -0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, -0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=1159; tryItOut("mathy3 = (function(x, y) { return (( + ( + (Math.pow(((Math.max(y, ( + (( + y) & ( + y)))) | 0) | 0), ((( ! (y >>> 0)) >>> 0) | 0)) >>> 0))) + Math.log2(( ! ((Math.atan2(( + ( ~ x)), ((x & (( + y) >>> 0)) >>> 0)) !== x) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[function(){}, new Number(1.5), function(){}, arguments, arguments, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), arguments, function(){}, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, new Number(1.5), arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, new Number(1.5), function(){}, arguments, objectEmulatingUndefined(), arguments, function(){}, function(){}, new Number(1.5), arguments, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), new Number(1.5), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, new Number(1.5), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), arguments, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, new Number(1.5), arguments, function(){}, function(){}, new Number(1.5), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, arguments, arguments, new Number(1.5), arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, new Number(1.5), function(){}, new Number(1.5), new Number(1.5), function(){}, objectEmulatingUndefined(), function(){}, function(){}, arguments, objectEmulatingUndefined(), function(){}, function(){}, arguments, new Number(1.5), arguments, function(){}, arguments, function(){}, arguments, objectEmulatingUndefined(), new Number(1.5), function(){}, objectEmulatingUndefined(), function(){}, new Number(1.5), arguments, objectEmulatingUndefined(), arguments, function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, arguments, arguments, arguments, objectEmulatingUndefined(), arguments, new Number(1.5), arguments, function(){}, new Number(1.5), arguments, new Number(1.5), function(){}, function(){}, arguments, arguments]); ");
/*fuzzSeed-204645237*/count=1160; tryItOut("testMathyFunction(mathy4, [({toString:function(){return '0';}}), -0, 1, ({valueOf:function(){return '0';}}), [], true, (new Number(0)), null, /0/, NaN, undefined, (function(){return 0;}), 0, (new Boolean(false)), '/0/', ({valueOf:function(){return 0;}}), '\\0', (new String('')), '0', '', (new Boolean(true)), (new Number(-0)), objectEmulatingUndefined(), false, 0.1, [0]]); ");
/*fuzzSeed-204645237*/count=1161; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return Math.cos(Math.fround(( ! Math.atan2(Math.min(( + ( ! Math.fround(Math.fround((y + x))))), x), x)))); }); ");
/*fuzzSeed-204645237*/count=1162; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( + ( + mathy0(( + ((Math.fround(mathy1(x, 2**53+2)) && Math.fround((((y | 0) <= (y | 0)) | 0))) | 0)), ( + ( + Math.max(( + Math.cosh(Math.fround(Math.max((-(2**53-2) >>> 0), (x | 0))))), 0/0)))))) / ( ! Math.fround(Math.pow((-Number.MAX_SAFE_INTEGER >> 0.000000000000001), -0x100000001)))) / ( + ( + Math.max((Math.pow(Math.fround(((((((y | 0) ? (x | 0) : (y | 0)) | 0) | 0) >= (x | 0)) | 0)), Math.fround((Math.max(Math.fround((Math.fround(y) !== Math.fround(1))), ((Math.hypot(( + x), -0x0ffffffff) >>> 0) >>> 0)) >>> 0))) ? (Math.ceil((x | 0)) | 0) : (((y >>> 0) || (Math.acosh((Number.MIN_SAFE_INTEGER | 0)) | 0)) >>> 0)), Math.acos(x))))); }); testMathyFunction(mathy3, [-(2**53-2), -0x100000001, Number.MAX_VALUE, Math.PI, -0x100000000, -1/0, 0x07fffffff, -(2**53), 0/0, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, 0x080000001, 0x0ffffffff, -0x080000000, 1, 0x100000000, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 2**53-2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53, 42, -0, Number.MIN_VALUE, -Number.MAX_VALUE, 0, -Number.MIN_VALUE, 0.000000000000001, 1/0]); ");
/*fuzzSeed-204645237*/count=1163; tryItOut("for (var p in f0) { for (var p in i0) { try { v2 = r2.test; } catch(e0) { } a2.shift(h0, ({w: (Math.trunc(x))}), /*RXUE*//(?=r{4}|\\b\\s)*?/gim.exec(\"rrrrr\") ? x : ( ''  >>> 11)); } }");
/*fuzzSeed-204645237*/count=1164; tryItOut("\"use strict\"; a2.forEach((function mcc_() { var elqxbx = 0; return function() { ++elqxbx; f1(/*ICCD*/elqxbx % 5 == 3);};})());");
/*fuzzSeed-204645237*/count=1165; tryItOut("\"use strict\"; Array.prototype.push.call(a2, e2, this.o2, o0.s1, g0.t2, p1);");
/*fuzzSeed-204645237*/count=1166; tryItOut("\"use strict\"; h2 + a1;");
/*fuzzSeed-204645237*/count=1167; tryItOut("mathy2 = (function(x, y) { return ( + Math.fround(Math.sin((Math.expm1(Math.fround(( + ( + mathy0(-Number.MAX_VALUE, ( + (mathy0((y | 0), (mathy0(y, 2**53+2) | 0)) | 0))))))) >>> 0)))); }); testMathyFunction(mathy2, [-0x100000000, -0, 2**53+2, 2**53, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53), -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, 0x080000000, 2**53-2, 42, 1/0, 0, 1.7976931348623157e308, 0x100000001, 0/0, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 1, 0x100000000, 0x0ffffffff, -0x080000000, 0x080000001, -0x07fffffff, -Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-204645237*/count=1168; tryItOut("t2 + t1;");
/*fuzzSeed-204645237*/count=1169; tryItOut("mathy2 = (function(x, y) { return (( + Math.cbrt((( - ((Math.cbrt(-0x080000001) > x) ? x : Math.asinh((x ? x : x)))) >>> 0))) - ( - ((Math.pow(y, (( + 2**53) == y)) || (( + mathy0(Math.imul(Math.fround((((y >>> 0) , (x >>> 0)) >>> 0)), Math.abs(-0x080000001)), x)) | 0)) | 0))); }); testMathyFunction(mathy2, [0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -0x100000000, -(2**53+2), -0x100000001, -(2**53-2), 1, Math.PI, -0x0ffffffff, -(2**53), 0, -0x07fffffff, 42, 0x080000000, -0x080000001, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_VALUE, 0/0, 0x0ffffffff, 0x100000000, -0, -1/0, Number.MIN_VALUE, -0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, 2**53-2, 1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1170; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return mathy0(((mathy0(((Math.fround(Math.min(Math.fround(x), x)) >>> Math.fround(( ~ Math.fround(mathy1((x >>> 0), (y >>> 0)))))) | 0), ( + Math.max(( + Math.cosh(y)), ( + ( ! Math.fround(Math.atan2(Math.fround(( + Math.fround(Math.fround((y ? Math.fround(x) : ( + x)))))), Math.fround(y)))))))) | 0) >>> 0), Math.atan(Math.max(Math.pow((( + ( ! -0x100000000)) === Math.fround(y)), Math.min(Math.fround(y), Math.log(Math.pow(x, ( + y))))), x))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, 2**53+2, -1/0, 0, 1, 0x100000000, -0x080000000, -(2**53+2), 0x080000000, -0x100000001, Math.PI, 1.7976931348623157e308, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 42, -0x100000000, -0x080000001, 0x080000001, -0x0ffffffff, 0x100000001, -0, -Number.MAX_VALUE, 1/0, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=1171; tryItOut("vtuprb(window, new RegExp(\"((?=((?!.)|\\\\1)|(?=$|\\\\f{3,2052}))|\\\\cF|(?![]{1,})*?)\", \"gyim\"));/*hhh*/function vtuprb(window, ...w){a0.unshift( /x/ , e0, b0);}");
/*fuzzSeed-204645237*/count=1172; tryItOut("v2 = t2.length;");
/*fuzzSeed-204645237*/count=1173; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(b2, f2);function x(x, x) { yield ((function too_much_recursion(tifqyi) { ; if (tifqyi > 0) { ; too_much_recursion(tifqyi - 1);  } else { (\"\\u257C\"); } throw true; })(1)) } s1[new String(\"2\")] = i2;\ncontinue M;\n");
/*fuzzSeed-204645237*/count=1174; tryItOut("\"use strict\"; { void 0; bailAfter(8446); } /*tLoop*/for (let y of /*MARR*/[ \"use strict\" ,  \"use strict\" ,  \"use strict\" , (void 0), (void 0), (void 0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (void 0), (void 0),  \"use strict\" , (void 0), (void 0), (void 0),  \"use strict\" , (void 0), (void 0), (void 0), (void 0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (void 0), (void 0),  \"use strict\" ,  \"use strict\" , (void 0),  \"use strict\" , (void 0), (void 0), (void 0),  \"use strict\" , (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0),  \"use strict\" ,  \"use strict\" ]) { print(x); }");
/*fuzzSeed-204645237*/count=1175; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.fround(Math.cosh(( + ( + (((( ! (Math.fround((Math.fround(( + ( ! x))) & Math.fround(1.7976931348623157e308))) | 0)) >>> 0) >>> 0) & (mathy1(x, (Math.min((Math.fround(Math.min(Math.fround(x), Math.fround(x))) | 0), Math.fround(x)) | 0)) >>> 0)))))) > Math.fround(( + ( ~ ( + Math.expm1(( + mathy1(( + x), Math.fround(( - Number.MIN_VALUE)))))))))) >>> 0); }); testMathyFunction(mathy2, [Math.PI, -0x100000001, 0x100000001, 1, 0x100000000, 1.7976931348623157e308, -1/0, -0, 1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 0x07fffffff, 2**53, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 0x0ffffffff, Number.MIN_VALUE, -0x100000000, 42, -(2**53-2), 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, -0x080000001, 2**53+2, -Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=1176; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3((?!.|[^]*))|.{2,}|\\\\S*?(?:[^]{0})|\\\\3+(\\\\D+)+?(\\\\2{1,})\", \"gm\"); var s = \"\\u0086aa\"; print(s.split(r)); ");
/*fuzzSeed-204645237*/count=1177; tryItOut("/*oLoop*/for (synohv = 0; synohv < 89; ++synohv, x) { /*oLoop*/for (stetgj = 0; stetgj < 72; ++stetgj) { 3; }  } \nM:with({e: (arguments = x === (e) = x)})(void schedulegc(g0));\n");
/*fuzzSeed-204645237*/count=1178; tryItOut("this.a1.toString = this.f1;");
/*fuzzSeed-204645237*/count=1179; tryItOut("\"use asm\"; /*bLoop*/for (hotcji = 0; hotcji < 3; ++hotcji) { if (hotcji % 43 == 6) { v0 = Object.prototype.isPrototypeOf.call(b0, g2); } else { neuter(b2, \"change-data\"); }  } ");
/*fuzzSeed-204645237*/count=1180; tryItOut("t1 + p0;");
/*fuzzSeed-204645237*/count=1181; tryItOut("/*MXX3*/g2.g0.ReferenceError = g2.ReferenceError;");
/*fuzzSeed-204645237*/count=1182; tryItOut("Array.prototype.shift.apply(a1, [v2, g0, s0]);");
/*fuzzSeed-204645237*/count=1183; tryItOut("testMathyFunction(mathy2, [2**53, -0x0ffffffff, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, Math.PI, 1/0, Number.MAX_VALUE, -0x080000000, -(2**53+2), 0x07fffffff, 0.000000000000001, 1.7976931348623157e308, 0, -0x080000001, 42, -1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -0, 2**53+2, 0x100000000, -0x07fffffff, -0x100000001, 0/0, 0x080000000]); ");
/*fuzzSeed-204645237*/count=1184; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.min(( + Math.fround(Math.trunc(Math.fround((( - (x >>> 0)) >>> 0))))), ( + (( - Math.fround(Math.min((((Math.fround((( + Math.hypot(( + x), x)) ** y)) | 0) / ( - x)) >>> 0), ((((( + (x >>> 0)) >>> 0) || ( + x)) >>> 0) >>> 0)))) >>> 0)))); }); testMathyFunction(mathy3, [0x080000000, 42, Math.PI, 0, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -1/0, -0x0ffffffff, -0, -0x100000001, -0x080000001, 1.7976931348623157e308, 0x080000001, 1/0, -(2**53), 0x100000000, 0x0ffffffff, -0x100000000, -(2**53+2), Number.MAX_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=1185; tryItOut("/*tLoop*/for (let z of /*MARR*/[ '\\0' , (void 0),  /x/ , (void 0),  /x/ ,  /x/ , (void 0), Number.MIN_VALUE,  /x/ ,  '\\0' ,  '\\0' , [(void shapeOf((4277)))], Number.MIN_VALUE,  '\\0' , Number.MIN_VALUE,  '\\0' ,  '\\0' ,  /x/ , [(void shapeOf((4277)))],  '\\0' ,  '\\0' ,  /x/ , Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE,  /x/ , (void 0), Number.MIN_VALUE, (void 0), Number.MIN_VALUE,  '\\0' ,  '\\0' ,  /x/ ,  '\\0' , [(void shapeOf((4277)))],  '\\0' ,  /x/ ,  '\\0' ,  '\\0' , (void 0),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , Number.MIN_VALUE,  '\\0' ,  /x/ , [(void shapeOf((4277)))], Number.MIN_VALUE, Number.MIN_VALUE,  '\\0' , (void 0),  '\\0' ,  '\\0' ,  '\\0' , [(void shapeOf((4277)))], Number.MIN_VALUE, Number.MIN_VALUE, [(void shapeOf((4277)))], [(void shapeOf((4277)))], Number.MIN_VALUE,  '\\0' , Number.MIN_VALUE, (void 0),  '\\0' , [(void shapeOf((4277)))],  '\\0' , Number.MIN_VALUE, [(void shapeOf((4277)))], Number.MIN_VALUE,  /x/ , Number.MIN_VALUE, Number.MIN_VALUE,  '\\0' , Number.MIN_VALUE,  '\\0' ,  '\\0' ,  /x/ ,  /x/ ,  '\\0' ,  '\\0' , [(void shapeOf((4277)))], [(void shapeOf((4277)))], [(void shapeOf((4277)))],  '\\0' ,  /x/ ,  '\\0' , (void 0), (void 0),  '\\0' ,  /x/ , [(void shapeOf((4277)))],  '\\0' , Number.MIN_VALUE, (void 0),  /x/ ]) { o0.e0 = new Set(p1);\nthis.f1.valueOf = (function() { try { const b1 = new SharedArrayBuffer(48); } catch(e0) { } try { h2.has = f0; } catch(e1) { } Object.defineProperty(this, \"s2\", { configurable: new RegExp(\"\\\\S(?!(?:.|[^\\\\S\\\\W\\\\S\\\\x73-\\u00a8]{4,7}).|[\\\\t-\\\\r]{1,})*?\", \"gm\"), enumerable: false,  get: function() {  return s0.charAt(15); } }); return s1; });\n }");
/*fuzzSeed-204645237*/count=1186; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?=[\\v-\\\ubb3c\\t-\u5696]|\\B)|^{65}*?)|(?:[^])\\v|$|\u801e*?(?:(?=[^])|.\\B+\\2((?!\\cK\\x71))+){3,5}*?/ym; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-204645237*/count=1187; tryItOut("\"use strict\"; for (var v of this.s0) { try { Array.prototype.sort.call(this.a1, (function() { try { i2 + i1; } catch(e0) { } try { for (var v of o2) { try { h0.defineProperty = o2.f1; } catch(e0) { } h0 = ({getOwnPropertyDescriptor: function(name) { s1 + '';; var desc = Object.getOwnPropertyDescriptor(t0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v2 = new Number(t2);; var desc = Object.getPropertyDescriptor(t0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { g0.t0 = t1.subarray(16);; Object.defineProperty(t0, name, desc); }, getOwnPropertyNames: function() { b2.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    d1 = (d1);\n    {\n      {\n        d1 = (((+(-1.0/0.0))) % ((d1)));\n      }\n    }\n    i0 = (0xffffffff);\n    {\n      return +((((1.0)) * ((d1))));\n    }\n    (Int32ArrayView[((i0)*0x24211) >> 2]) = (((i0) ? (0xf1b9028e) : (1))-(0xc44abdc2));\n    return +((-8589934592.0));\n  }\n  return f; });; return Object.getOwnPropertyNames(t0); }, delete: function(name) { a2[({valueOf: function() { print(-20);return 5; }})] = i1;; return delete t0[name]; }, fix: function() { Array.prototype.shift.call(a0);; if (Object.isFrozen(t0)) { return Object.getOwnProperties(t0); } }, has: function(name) { o0.v1 = t0.length;; return name in t0; }, hasOwn: function(name) { a2.unshift(e1, g2, s1);; return Object.prototype.hasOwnProperty.call(t0, name); }, get: function(receiver, name) { i2 = new Iterator(this.f2, true);; return t0[name]; }, set: function(receiver, name, val) { Object.prototype.unwatch.call(a2, \"fround\");; t0[name] = val; return true; }, iterate: function() { i2 + s1;; return (function() { for (var name in t0) { yield name; } })(); }, enumerate: function() { throw t0; var result = []; for (var name in t0) { result.push(name); }; return result; }, keys: function() { Object.defineProperty(this, \"v1\", { configurable: (x % 12 == 11), enumerable: (x % 5 == 3),  get: function() {  return t1.BYTES_PER_ELEMENT; } });; return Object.keys(t0); } }); } } catch(e1) { } this.a2.unshift(timeout(1800), g1, p2); return v2; })); } catch(e0) { } try { for (var p in p1) { try { s2 = s2.charAt(0); } catch(e0) { } try { this.m1.delete(e0); } catch(e1) { } /*MXX2*/g1.String.prototype.replace = o0.o1.g1.m2; } } catch(e1) { } t1[5] = e1; }");
/*fuzzSeed-204645237*/count=1188; tryItOut("Object.prototype.unwatch.call(b2, \"b\");");
/*fuzzSeed-204645237*/count=1189; tryItOut("/*vLoop*/for (let rnqkgt = 0; rnqkgt < 1; ++rnqkgt) { d = rnqkgt; this.v2 = b0.byteLength; } ");
/*fuzzSeed-204645237*/count=1190; tryItOut("/*infloop*/L:do /*hhh*/function nkvsro(){return window;}nkvsro((timeout(1800)))\u000d; while(x);");
/*fuzzSeed-204645237*/count=1191; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.asin(Math.max(( ! ((Math.clz32(( + y)) >>> 0) << Math.fround(-0x080000001))), ( ! Math.fround(Math.atanh(Math.fround((Math.atan2(Math.fround(y), Math.fround(y)) == ( + (( + x) >>> -0))))))))); }); testMathyFunction(mathy3, [-0x07fffffff, 0.000000000000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 0x080000001, -Number.MAX_VALUE, -0x080000000, -(2**53+2), 1, Math.PI, -(2**53), 0, 0x100000001, Number.MAX_VALUE, -0x100000001, 0/0, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, -(2**53-2), 0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, -0, -1/0, Number.MIN_VALUE, 1/0, 0x07fffffff, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=1192; tryItOut("v1 = a0.reduce, reduceRight((function() { try { v0 = Object.prototype.isPrototypeOf.call(b1, m1); } catch(e0) { } try { this.e2.add(t1); } catch(e1) { } g1.a1.push(o0, m0); return f1; }), e0, a2, e1);");
/*fuzzSeed-204645237*/count=1193; tryItOut("return  /x/ ;\nprint((a) = x);\n");
/*fuzzSeed-204645237*/count=1194; tryItOut("\"use strict\"; g0.h2.fix = (function() { for (var j=0;j<33;++j) { f0(j%5==0); } });");
/*fuzzSeed-204645237*/count=1195; tryItOut("\"use strict\"; v1 = r1.multiline;");
/*fuzzSeed-204645237*/count=1196; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.atan2(( + (( ~ Math.hypot(( ! x), x)) != Math.fround((Math.pow(((( + ( + ( + Number.MIN_VALUE))) !== (Math.log1p(Math.fround(( ! Math.fround(x)))) > Number.MIN_SAFE_INTEGER)) >>> 0), (((Math.fround(( - Math.fround(y))) | 0) | (-(2**53+2) | 0)) | 0)) | 0)))), ( + Math.fround(Math.asinh(Math.fround(( + -0x080000001))))))); }); testMathyFunction(mathy0, /*MARR*/[new Number(1.5), eval, x, eval, x, x, x, x, new Number(1.5), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1.5), eval, new Number(1.5), eval, new Number(1.5), new Number(1.5), x, x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), eval, new Number(1.5), new Number(1.5), eval, new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), eval, new Number(1.5), eval, new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-204645237*/count=1197; tryItOut("\"use strict\"; v0 = t1.length;");
/*fuzzSeed-204645237*/count=1198; tryItOut("\"use strict\"; with(x)M:switch( /x/g  >>> new RegExp(\"(?=\\\\W)\", \"gyim\")) { default: let (jmoryc, cxpjim, oiokki, x, x, krxqtd, pnhxan, ixkewp) { {} }case x: break; case \"\\u448F\".unwatch(\"x\"): a1.push(b0);break; case (({NaN: \"\\u3846\" > -21})): print(x);break;  }");
/*fuzzSeed-204645237*/count=1199; tryItOut("for (var v of a0) { try { Array.prototype.splice.call(a0, NaN, 1, o0.m0); } catch(e0) { } try { v0 = a2.length; } catch(e1) { } try { for (var v of s1) { try { a0.forEach(Date.prototype.setMilliseconds); } catch(e0) { } try { g0.v2 = r2.compile; } catch(e1) { } try { o2.h0.defineProperty = f1; } catch(e2) { } s1 += 'x'; } } catch(e2) { } h2.fix = f2; }");
/*fuzzSeed-204645237*/count=1200; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( - (( ! ((((y || y) % (Number.MIN_VALUE !== y)) | 0) | 0)) >>> 0)); }); testMathyFunction(mathy2, [1, null, 0.1, (new Number(0)), ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Boolean(true)), (new String('')), '', objectEmulatingUndefined(), ({toString:function(){return '0';}}), /0/, 0, NaN, [0], ({valueOf:function(){return '0';}}), '\\0', -0, [], '0', (new Number(-0)), (function(){return 0;}), undefined, '/0/', true, false]); ");
/*fuzzSeed-204645237*/count=1201; tryItOut("a0[4];");
/*fuzzSeed-204645237*/count=1202; tryItOut("M:with({z: eval(\"\\\"\\\\u8330\\\"\", /*UUV1*/(eval.entries = this))}){/*tLoop*/for (let a of /*MARR*/[function(){}, 2**53-2, [], function(){}, 2**53-2, function(){}, 2**53-2, function(){}, 2**53-2, [], 2**53-2, new String('q'), new String('q'), [], new String('q')]) { print(NaN()); } }");
/*fuzzSeed-204645237*/count=1203; tryItOut("mathy4 = (function(x, y) { return (( - (Math.hypot((((-(2**53) >>> 0) && (( + Math.ceil(( + x))) >>> 0)) >>> 0), Math.hypot(Number.MIN_VALUE, ((((((x | 0) ? y : (x | 0)) | 0) ? 0 : y) | (-(2**53+2) | 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 1, 1/0, -0x080000000, -1/0, 42, -0, 0.000000000000001, -Number.MIN_VALUE, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 0x080000001, 0x07fffffff, 2**53, 0x0ffffffff, -(2**53+2), -(2**53), 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -0x100000001, 0x080000000, -0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, 0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=1204; tryItOut("g2.offThreadCompileScript(\"((eval = Proxy.create(({/*TOODEEP*/})(\\\"\\\\u4FA4\\\"), \\\"\\\\u415A\\\")) %  /x/ )\");");
/*fuzzSeed-204645237*/count=1205; tryItOut("\"use strict\"; a2.pop();");
/*fuzzSeed-204645237*/count=1206; tryItOut("s2 += 'x';");
/*fuzzSeed-204645237*/count=1207; tryItOut("/*infloop*/M: for  each(var eval in (4277)) {/*infloop*/ for (z of (4277)) {delete h1.fix;selectforgc(o2); } }");
/*fuzzSeed-204645237*/count=1208; tryItOut("mathy4 = (function(x, y) { return (Math.atanh(( + (( + Math.fround(Math.max(Math.sqrt((mathy3(x, (y | 0)) | 0)), Math.fround(( ! ((Math.fround(Math.fround(Math.cos((( + x) | x)))) | ((0x100000001 >> Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)))))) && ( + (( - (( ~ x) | 0)) && ( + (( + y) >> Math.fround(Math.sqrt((0x080000001 >>> 0)))))))))) >>> 0); }); ");
/*fuzzSeed-204645237*/count=1209; tryItOut("try { a = x; } catch(x) { window = d; } ");
/*fuzzSeed-204645237*/count=1210; tryItOut("\"use strict\"; a1[({valueOf: function() { v1 = Object.prototype.isPrototypeOf.call(a2, h0);return 18; }})];");
/*fuzzSeed-204645237*/count=1211; tryItOut("mathy5 = (function(x, y) { return (( ~ Math.fround(Math.acosh(( + (y ^ ( + ( - Math.sin(y)))))))) * ((Math.min(( + (y << (Math.abs((x >>> 0)) >>> 0))), (( - (mathy2((y | 0), (x >>> 0)) >>> 0)) | 0)) | 0) <= Math.atan2((( ! (Math.min(mathy1((((y >>> 0) && (y >>> 0)) >>> 0), (0x100000001 ? x : x)), (x < Math.fround(y))) | 0)) | 0), (( ~ (Math.log((( - (x | 0)) | 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_VALUE, 1, 0x07fffffff, -Number.MIN_VALUE, -(2**53), 2**53-2, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x080000000, 0, -0x07fffffff, -0x100000000, 1/0, 0x080000001, Number.MIN_VALUE, 0/0, Number.MAX_VALUE, 0.000000000000001, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, 2**53+2]); ");
/*fuzzSeed-204645237*/count=1212; tryItOut("\"use strict\"; { void 0; fullcompartmentchecks(false); } h2.iterate = (function() { try { o2.a1[7] = g1; } catch(e0) { } try { a2[\"call\"] = g1.t1; } catch(e1) { } a2.forEach((function() { b1 = t0.buffer; return v0; })); return this.o2; });");
/*fuzzSeed-204645237*/count=1213; tryItOut(" /x/ ;b;");
/*fuzzSeed-204645237*/count=1214; tryItOut("mathy1 = (function(x, y) { return Math.fround(( ~ ( + (x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { throw 3; }, set: function() { throw 3; }, iterate: (({/*TOODEEP*/})).call, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: \"\u03a0\", }; })(-1), w =>  { \"use strict\"; (e); } , this) >>> (((Math.min(( + Math.abs(( + x))), ( + Math.atan2(y, (( ~ -Number.MAX_VALUE) >>> 0)))) >>> 0) == (Number.MAX_VALUE >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, ['\\0', (new Boolean(false)), -0, objectEmulatingUndefined(), [0], (new String('')), [], '/0/', null, 0.1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Number(0)), false, true, 0, '0', (function(){return 0;}), ({valueOf:function(){return 0;}}), 1, undefined, /0/, (new Number(-0)), NaN, '', (new Boolean(true))]); ");
/*fuzzSeed-204645237*/count=1215; tryItOut("\"use strict\"; m0.get(h0);");
/*fuzzSeed-204645237*/count=1216; tryItOut("let NaN = x;/*MXX2*/g0.Float64Array.prototype = s0;");
/*fuzzSeed-204645237*/count=1217; tryItOut("v0 = Object.prototype.isPrototypeOf.call(v0, h1);\n/*infloop*/for(var w =  /* Comment */neuter() ? (new (/[^]|(?=^\u6830{127})|(((?:\\B|\\B)))?/y)()) : new Math.sin( /x/ ); ; ((arguments)())) f2(g0);\n");
/*fuzzSeed-204645237*/count=1218; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1219; tryItOut("mathy5 = (function(x, y) { return Math.pow(mathy1(( ~ Math.fround(x)), (Math.hypot((((( - (x >>> 0)) >>> 0) | Math.cbrt((Math.max(Math.fround(y), Math.fround((((y | 0) ? y : (y | 0)) | 0))) | 0))) | 0), -0) >>> 0)), ((Math.clz32(y) >>> 0) - ((Math.atan(y) || Math.max(-0x0ffffffff, Math.imul(x, x))) >>> 0))); }); testMathyFunction(mathy5, [Math.PI, 2**53, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, Number.MAX_VALUE, -0x100000000, -0x080000000, 1/0, 0x0ffffffff, -0x080000001, 0x080000001, Number.MIN_VALUE, -1/0, 0x100000000, 0x07fffffff, -(2**53-2), -0, 0/0, 2**53+2, -Number.MAX_VALUE, 0, -(2**53+2), -Number.MIN_VALUE, 2**53-2, -0x100000001, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 1, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1220; tryItOut("{print(x);print(\"\\u585E\"); }");
/*fuzzSeed-204645237*/count=1221; tryItOut("\"use strict\"; /*oLoop*/for (let hrroxl = 0; hrroxl < 12; ++hrroxl) { e0.delete(b1);this.a0.unshift(s0, e0, o1, i1, v1, o1, m2, this.v0, i0, e1, x, t2, m1, v0); } ");
/*fuzzSeed-204645237*/count=1222; tryItOut("s0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 268435455.0;\n    var d3 = 1073741825.0;\n    i1 = (0xffffffff);\n    d2 = (+acos(((+(((~((i0)+(0xff2e23ba)+((imul((0x16f324f9), (0x9df7df74))|0)))) / ((((0x24b4f0b9) == (0x42ab8a57))-(0xffffffff)) & ((((0xf9b35a85))>>>((0xd8b64a53))) % (0xead576f9))))|0)))));\n    {\n      d3 = (((-4.722366482869645e+21)) * ((-131073.0)));\n    }\n    i0 = (((0x0)) ? (0xff1db109) : (0xfe06ee3c));\n    i1 = (i1);\n    return +((((1.2089258196146292e+24)) - ((d3))));\n    return +((Float64ArrayView[2]));\n  }\n  return f; })(this, {ff: Date.prototype.getTimezoneOffset}, new ArrayBuffer(4096));");
/*fuzzSeed-204645237*/count=1223; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (268435455.0);\n    d1 = (((d1)) / ((+/*FFI*/ff(((d1)), ((NaN))))));\n    {\n      {\n        {\n          i0 = (i0);\n        }\n      }\n    }\n    (Float64ArrayView[((Uint16ArrayView[4096])) >> 3]) = ((-64.0));\n    (Float32ArrayView[((/*FFI*/ff(((imul(((Uint32ArrayView[1])), (i0))|0)), ((abs((~((0xea4a1ae2)+((0x4ecc051c)))))|0)), (((0xfdb60a8a) ? (-1.0009765625) : (9.44473296573929e+21))), ((((0xfd941d9d)) ^ ((-0x8000000)))), ((((0x74b465a6)) | ((0xffb76eb1)))), ((274877906943.0)))|0)) >> 2]) = ((Float64ArrayView[1]));\n    return ((((0x7585344c))))|0;\n  }\n  return f; })(this, {ff: eval(\"mathy5 = (function(x, y) { \\\"use strict\\\"; return Math.min(( + Math.min(( + ( + ( - -1/0))), ( + (Math.log1p(0x100000001) !== Math.hypot(0x100000000, ( + (((( ! Number.MIN_VALUE) >>> 0) | 0) >= (x | 0)))))))), ( + Math.tan(( + (((x | 0) > (Math.fround((Math.fround(( + ( - y))) ? Math.fround(y) : Math.fround(( + (( ~ x) | 0))))) | 0)) | 0))))); }); testMathyFunction(mathy5, [2**53+2, 0x100000000, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, -0x100000000, -1/0, -0x07fffffff, -0x100000001, -(2**53), 42, 0/0, -(2**53-2), -Number.MIN_VALUE, 1, 0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 0, Math.PI, -0, Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -0x080000000, -(2**53+2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER]); \")}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-1/0, 0x080000000, Number.MIN_VALUE, -0x07fffffff, 42, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, 0x100000000, 1/0, -0x080000001, -(2**53-2), 2**53, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, Math.PI, 0, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53+2), 1, 0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-204645237*/count=1224; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-204645237*/count=1225; tryItOut("\"use strict\"; this.e1.add(v0);function x()y = Proxy.create(({/*TOODEEP*/})( /x/g ),  /x/g ).throw((NaN = -0))([,,z1]);print(x);");
/*fuzzSeed-204645237*/count=1226; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! (((mathy3(Math.fround(((( ~ y) | 0) & x)), ((( + x) && ( + 0.000000000000001)) ? (( - x) | 0) : x)) | 0) - Math.log(( ~ Math.pow(mathy0(y, y), ( + Math.max((mathy4(y, (x | 0)) | 0), ( + y))))))) >>> 0)) | 0); }); ");
/*fuzzSeed-204645237*/count=1227; tryItOut("a2 = new Array;");
/*fuzzSeed-204645237*/count=1228; tryItOut("mathy3 = (function(x, y) { return (Math.min(Math.atan((Math.round((1/0 - y)) >>> 0)), ( + Math.fround(( + ( + ( + y)))))) ? (mathy0(Math.fround((Math.fround(Math.trunc(Math.fround(Math.asin(x)))) % Math.fround(( + ( - Math.fround(Math.pow(y, x))))))), ((y , ( + Math.min(Math.fround(x), y))) | 0)) | 0) : ( + mathy2(( + Math.tan(( + Math.pow((x ** x), Math.max(((x << (x | 0)) | 0), (Math.sinh((y >>> 0)) | 0)))))), (((Math.sqrt(x) >>> 0) , (Math.PI ^ ((Math.sin(( + (Math.expm1((y >>> 0)) >>> 0))) | 0) | 0))) < mathy1(Math.fround((y == Math.fround(y))), y))))); }); ");
/*fuzzSeed-204645237*/count=1229; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.imul((( ! Math.trunc(y)) | 0), (((Math.fround((( ~ (x | 0)) | 0)) * ((Math.asin((1.7976931348623157e308 >>> 0)) >>> 0) | 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, [-(2**53-2), 0.000000000000001, 1.7976931348623157e308, 1, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 0x100000001, 0x080000000, 0/0, 0, 0x07fffffff, 0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, -0, Math.PI, 2**53+2, -0x100000000, -Number.MAX_VALUE, -1/0, -(2**53), 0x100000000, -(2**53+2), -0x0ffffffff, -0x07fffffff, 2**53-2, 42, Number.MAX_VALUE, -0x100000001, 1/0]); ");
/*fuzzSeed-204645237*/count=1230; tryItOut("mathy3 = (function(x, y) { return ( ~ (Math.acosh(((Math.fround(Math.max(x, mathy2(Math.imul(0/0, y), y))) == y) ? Math.max(y, (Math.atan2(Math.fround(42), y) >>> 0)) : Math.pow(Math.imul(x, y), ((((Math.atanh(0x080000001) | 0) === (0x07fffffff | 0)) | 0) <= (( + (( + x) !== x)) * Math.fround(1.7976931348623157e308)))))) | 0)); }); testMathyFunction(mathy3, [-0x080000000, 1, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, -Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, 0x100000001, 1.7976931348623157e308, 0x0ffffffff, -(2**53), Number.MAX_VALUE, -(2**53-2), -0, 0/0, -(2**53+2), 2**53, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, Math.PI, 2**53-2, 0, 0x07fffffff, 0x080000001, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-204645237*/count=1231; tryItOut("m2.set(i1, g0);");
/*fuzzSeed-204645237*/count=1232; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(f0, a0);");
/*fuzzSeed-204645237*/count=1233; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(e2, s2);");
/*fuzzSeed-204645237*/count=1234; tryItOut("print(uneval(i1));\na1.push(x, (window) =  /x/g , g1, b1);\n");
/*fuzzSeed-204645237*/count=1235; tryItOut("let \u0009NaN = \"\\uE631\" != x, [] = (let (atbujn) x), x, b, w =  /x/ , feqwvh;for (var p in a1) { try { r1 = new RegExp(\"(?:(?:\\u00c6\\\\w|\\\\b+?))\\\\2[^]\\\\1.+^*?\", \"gim\"); } catch(e0) { } try { v1 = (v2 instanceof b1); } catch(e1) { } t1 = g2.objectEmulatingUndefined(); }");
/*fuzzSeed-204645237*/count=1236; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=1237; tryItOut("\"use strict\"; \"\u03a0\";\n\u0009v1 = Object.prototype.isPrototypeOf.call(h2, o0);\n");
/*fuzzSeed-204645237*/count=1238; tryItOut("switch(x) { case 7:  }");
/*fuzzSeed-204645237*/count=1239; tryItOut("for(let a in []);");
/*fuzzSeed-204645237*/count=1240; tryItOut("let w = (Math.imul(-25, -1));L: m1 = new Map;");
/*fuzzSeed-204645237*/count=1241; tryItOut("testMathyFunction(mathy0, /*MARR*/[(1/0), (1/0), new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(false), (1/0), new Boolean(true), NaN, (1/0), new Boolean(false), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, new Boolean(false), NaN, NaN, new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(true), NaN, new Boolean(false), NaN, new Boolean(true), NaN, NaN, NaN, new Boolean(true), new Boolean(false), NaN, NaN, NaN, NaN]); ");
/*fuzzSeed-204645237*/count=1242; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((Math.fround(( + Math.log(( + Math.hypot((x >>> 0), y))))) !== (( - Math.atan2(((((Math.clz32(x) >>> 0) & (x >>> 0)) | 0) >>> 0), ( + Math.tanh(x)))) >>> 0)) >>> 0) ? Math.fround(Math.fround(Math.asin(Math.fround(x)))) : Math.fround(Math.imul(Math.fround((Math.fround(( ! y)) + Math.atan((x | 0)))), (Math.cbrt((y >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, 2**53+2, -1/0, -0x080000000, -(2**53-2), 42, -Number.MIN_VALUE, 0x07fffffff, -(2**53+2), -0x080000001, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, 1, -(2**53), 1/0, 0x100000000, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0, 0, 0/0, 0x080000000, 2**53]); ");
/*fuzzSeed-204645237*/count=1243; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((((( + ( + (( + Math.pow(y, ( + y))) ? ( + Math.max(y, ((y % x) | 0))) : ( + y)))) | 0) | 0) === Math.fround(Math.min(Math.fround((Math.atan2(mathy1(x, y), (-(2**53) * (Math.fround(( ! Math.fround(x))) >>> 0))) | 0)), Math.tanh(Math.fround(Math.imul(( + ( ! -(2**53+2))), Math.pow(Math.sin(x), Math.cbrt(x))))))))); }); testMathyFunction(mathy2, [-0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, -0x080000000, Math.PI, 0x07fffffff, 1.7976931348623157e308, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, 0/0, 0x100000001, 0, -Number.MAX_VALUE, -1/0, -0, Number.MIN_VALUE, -Number.MIN_VALUE, 42, 2**53, -0x07fffffff, 0x080000001, -(2**53+2), 2**53-2, -0x0ffffffff, 0x0ffffffff, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-204645237*/count=1244; tryItOut("mathy2 = (function(x, y) { return (Math.pow(( + ( - ( + (mathy1(Math.cosh((y >>> 0)), y) > ( + ( + y)))))), (Math.atan2((Math.trunc(Math.fround(-0x100000001)) >>> 0), ( ~ Math.fround((x ** ((y + ( + (( + x) ** ( + y)))) >>> 0))))) ^ (Math.fround((Math.fround((( + ( + 2**53-2)) && (x ? x : ( + ( ! y))))) === (((Math.max((y | 0), (x | 0)) | 0) + (x | 0)) | 0))) >>> 0))) >>> 0); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, -(2**53), -(2**53-2), 1/0, -(2**53+2), -0, -0x080000000, 2**53+2, 0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, -0x080000001, -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -0x100000001, -0x100000000, -1/0, 2**53-2, 1, 0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, 0, 0x080000000, 2**53, 42]); ");
/*fuzzSeed-204645237*/count=1245; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1246; tryItOut("testMathyFunction(mathy5, [-0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, -0x0ffffffff, 1.7976931348623157e308, -(2**53+2), 0x100000001, 0x07fffffff, 2**53-2, 0x080000001, -0x100000000, -Number.MAX_VALUE, -0x080000001, 42, -(2**53), 1, Number.MIN_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, -0x100000001, -0x080000000, 0.000000000000001, 0, -1/0, Math.PI, 0x100000000, 0/0]); ");
/*fuzzSeed-204645237*/count=1247; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"\"); var s = \"\"; print(s.replace(r, '')); ");
/*fuzzSeed-204645237*/count=1248; tryItOut("for (var p in o1) { try { m2.has(timeout(1800)); } catch(e0) { } g0.o0 + ''; }");
/*fuzzSeed-204645237*/count=1249; tryItOut("o1.e2.add(this.v0);");
/*fuzzSeed-204645237*/count=1250; tryItOut("\"use strict\"; g1.a2.forEach(f1);");
/*fuzzSeed-204645237*/count=1251; tryItOut("/*vLoop*/for (otbqyq = 0; (x) && otbqyq < 27; ++otbqyq) { var d = otbqyq; /* no regression tests found */ } ");
/*fuzzSeed-204645237*/count=1252; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -35184372088832.0;\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: (/*wrap1*/(function(){ /*RXUB*/var r =  \"\" ; var s = \"\\u001b\"; print(uneval(r.exec(s))); return function(q) { \"use strict\"; return q; }})()).apply}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-204645237*/count=1253; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-204645237*/count=1254; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.max(((((Math.atan2(( + ( - (y | 0))), (( + (x ? mathy0(Math.fround(x), Math.fround(x)) : (Math.abs(y) | 0))) >>> 0)) | 0) / Math.fround(( + Math.pow(2**53-2, x)))) - Math.cos(Math.fround(Math.hypot(Math.fround((x ^ y)), Math.fround(( ! Math.PI)))))) >>> 0), Math.cos(( ~ Math.max(Math.fround(mathy2(Math.acos(y), 0x100000000)), Math.fround(Math.atan2((y >>> 0), (y | 0))))))) >>> 0); }); testMathyFunction(mathy3, [0.000000000000001, -0x100000001, 0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 0/0, -0, -0x080000001, 1, 0x07fffffff, 0x100000000, 0, 0x0ffffffff, Number.MIN_VALUE, 2**53, -(2**53), -1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 42, Math.PI, 1/0, -Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 1.7976931348623157e308, -(2**53-2), 0x080000000]); ");
/*fuzzSeed-204645237*/count=1255; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.cbrt((((Math.pow(((1 ? (Math.atan2(y, (Number.MIN_VALUE >>> 0)) >>> 0) : ( + mathy0(( ! ( + 2**53)), Math.min(x, y)))) >>> 0), (y >>> 0)) >>> 0) ** ((( - (Math.sqrt(2**53-2) | 0)) >>> 0) | 0)) | 0)) | 0); }); testMathyFunction(mathy1, [0x0ffffffff, 0x080000001, -0x080000001, Number.MAX_VALUE, -(2**53+2), 2**53, -0x07fffffff, Number.MIN_VALUE, 0/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53), 1.7976931348623157e308, 1, 2**53+2, 0x080000000, 0x07fffffff, 0, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000, -Number.MAX_VALUE, -1/0, -0x0ffffffff, 0x100000000, 42, 1/0, 0.000000000000001, -0x100000000, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-204645237*/count=1256; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 536870913.0;\n    var i3 = 0;\n    var d4 = -2.3611832414348226e+21;\n    var d5 = -4.835703278458517e+24;\n    var i6 = 0;\n    {\n      d2 = (33.0);\n    }\n    {\n      i3 = (0x92d3be0f);\n    }\n    {\n      d4 = (+abs(((4.0))));\n    }\n    i0 = (i3);\n    d1 = (d5);\n    (Float64ArrayView[(((0xffffffff) ? (/*FFI*/ff((((-576460752303423500.0) + (1048575.0))), ((1.9342813113834067e+25)), ((-18446744073709552000.0)))|0) : (0x1bdb15c))-(i3)) >> 3]) = ((3.0));\n    (Int16ArrayView[0]) = ((i3));\n    return (((i6)+(((0x1662afdb)) ? (/*FFI*/ff()|0) : ((0x4eff1342) < (((!(i3)))>>>((0x9d68d24) % (0x6961550)))))))|0;\n  }\n  return f; })(this, {ff: String}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0.1, (new Boolean(true)), objectEmulatingUndefined(), (function(){return 0;}), ({valueOf:function(){return 0;}}), '0', undefined, 0, null, -0, [0], 1, '/0/', (new Number(0)), [], (new Boolean(false)), ({toString:function(){return '0';}}), (new String('')), ({valueOf:function(){return '0';}}), false, (new Number(-0)), true, '\\0', NaN, /0/, '']); ");
/*fuzzSeed-204645237*/count=1257; tryItOut("mathy0 = (function(x, y) { return Math.atanh((Math.fround((Math.hypot(y, -Number.MIN_VALUE) >>> 0)) ? ( + Math.sign(( + x))) : ( - 2**53))); }); ");
/*fuzzSeed-204645237*/count=1258; tryItOut("/*tLoop*/for (let d of /*MARR*/[NaN, NaN, 1e-81, 1e-81, NaN, 1e-81, NaN, 1e-81, NaN, NaN, 1e-81, NaN, 1e-81, NaN, 1e-81, 1e-81, 1e-81, 1e-81, NaN, 1e-81, 1e-81, NaN, 1e-81, 1e-81, 1e-81, NaN, 1e-81, NaN, NaN, 1e-81, NaN, 1e-81, 1e-81, 1e-81, NaN, 1e-81, NaN, NaN, NaN, NaN, NaN, 1e-81, NaN, 1e-81, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, 1e-81, NaN, NaN, NaN, 1e-81, NaN, 1e-81, NaN, 1e-81, NaN, 1e-81, NaN, 1e-81, NaN, NaN, NaN, NaN, 1e-81, 1e-81, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, 1e-81, 1e-81, NaN, NaN, 1e-81, NaN, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, NaN, NaN, NaN, 1e-81, 1e-81, NaN, NaN, NaN, NaN, NaN, NaN, 1e-81, NaN, 1e-81, NaN, NaN, NaN, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, NaN, NaN, 1e-81, 1e-81, 1e-81, NaN, NaN, NaN, NaN, 1e-81, 1e-81]) { v1 = Object.prototype.isPrototypeOf.call(a1, g1); }");
/*fuzzSeed-204645237*/count=1259; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:((?:\\\\1)+?){2,3}))\", \"gyim\"); var s = \"\\n\\n\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=1260; tryItOut("a2.toSource = (function mcc_() { var pvyoef = 0; return function() { ++pvyoef; f0(/*ICCD*/pvyoef % 3 == 2);};})();");
/*fuzzSeed-204645237*/count=1261; tryItOut("\"use strict\"; /*oLoop*/for (ofcdvg = 0; ofcdvg < 97; new function(y) { yield y; a1 = [];; yield y; }(({-20: \"\\u2AF4\", arguments:  ''  })), ++ofcdvg) { var r0 = x - x; x = 2 + x; r0 = 1 | r0; var r1 = r0 ^ 6; var r2 = x ^ r1; var r3 = r0 * r0; r2 = r1 + r3; r0 = 2 | r1; var r4 = x | r0; var r5 = r3 / r1; var r6 = 7 - r0; var r7 = r4 | r4; var r8 = x | r0; var r9 = r6 - r8; var r10 = r3 | r4; r10 = 4 - r2; var r11 = r0 | r4; var r12 = r11 | r6; var r13 = r2 | r9; var r14 = 9 & 0; var r15 = r9 % r13;  } ");
/*fuzzSeed-204645237*/count=1262; tryItOut("r1 = /\\1/yi;");
/*fuzzSeed-204645237*/count=1263; tryItOut("mathy4 = (function(x, y) { return Math.tan((((( + mathy1(( + Math.sin(Math.fround(x))), ( + 2**53-2))) >>> 0) !== ( + Math.hypot(( ! Math.fround(( ~ y))), (mathy2(y, Math.fround(y)) | 0)))) | 0)); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, 2**53, -1/0, -0x100000000, 0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, 0/0, -0, -0x100000001, -0x080000000, -(2**53+2), 0x100000000, Number.MAX_VALUE, 42, 1, -0x0ffffffff, 2**53+2, -(2**53), 0x07fffffff, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, 0.000000000000001, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1264; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1265; tryItOut("h1 = {};\nv0 = t1.byteOffset;\n");
/*fuzzSeed-204645237*/count=1266; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ~ (( ~ Math.fround(mathy2(Math.hypot((x >= ( + ((x >>> 0) >> ((-(2**53) | 0) & x)))), 2**53), Math.min(( - y), 0x100000001)))) >>> 0))); }); testMathyFunction(mathy4, [-0x07fffffff, 0x100000000, 1.7976931348623157e308, -(2**53), -0x100000000, -Number.MIN_VALUE, Math.PI, -0x0ffffffff, -1/0, 1, -Number.MAX_VALUE, -0, 0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, 1/0, 0.000000000000001, 0x0ffffffff, 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53-2), -(2**53+2), 2**53, -0x100000001, 42, 0]); ");
/*fuzzSeed-204645237*/count=1267; tryItOut("with((4277))(void schedulegc(g0));");
/*fuzzSeed-204645237*/count=1268; tryItOut("for (var p in v0) { v2 = r1.multiline; }");
/*fuzzSeed-204645237*/count=1269; tryItOut("print(d);function x(this)\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -8589934593.0;\n    var d3 = -549755813889.0;\n    var d4 = 4194305.0;\n    var d5 = -1.2089258196146292e+24;\n    var i6 = 0;\n    d1 = (1073741825.0);\n    switch ((((Int32ArrayView[((0x9dd3612e)) >> 2])) | ((!(-0x8000000))+(!(0xf870c9b5))))) {\n    }\n    (Float64ArrayView[4096]) = ((+atan2(((+pow(((Float64ArrayView[((x) = /*wrap2*/(function(){ \"use strict\"; var kpvarf = false; var evvwfx = mathy0; return evvwfx;})()()) >> 3])), ((Infinity))))), ((+(-1.0/0.0))))));\n    (Float64ArrayView[2]) = ((d1));\n    d0 = (d0);\n    d1 = (d0);\n    d2 = (+(-1.0/0.0));\n    i6 = (i6);\n    return +(( /x/g  , /(?!(\\s{4}){1,3})/yim));\n  }\n  return f;Array.prototype.shift.call(a2);");
/*fuzzSeed-204645237*/count=1270; tryItOut("/*RXUB*/var r = r1; var s = s1; print(r.test(s)); ");
/*fuzzSeed-204645237*/count=1271; tryItOut("v1 = Object.prototype.isPrototypeOf.call(t0, p2);");
/*fuzzSeed-204645237*/count=1272; tryItOut("mathy5 = (function(x, y) { return Math.cosh(Math.log(( + (mathy2((Math.fround(((((x | 0) ^ (y | 0)) | 0) === Math.fround(Math.min(Math.fround(y), Math.fround(0x080000000))))) | 0), y) | 0)))); }); ");
/*fuzzSeed-204645237*/count=1273; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.min(((Math.clz32(( + x)) !== (( + ( + Math.imul(((Math.imul(x, y) | 0) | -1/0), (( + y) | 0)))) | 0)) | 0), Math.asin(( ~ Math.fround(Math.atanh(Math.fround(Math.atan2(y, x))))))); }); testMathyFunction(mathy0, [(new String('')), null, true, (new Number(0)), [], 1, '', '\\0', false, objectEmulatingUndefined(), (function(){return 0;}), ({toString:function(){return '0';}}), (new Boolean(true)), undefined, '/0/', ({valueOf:function(){return 0;}}), 0, [0], '0', (new Number(-0)), ({valueOf:function(){return '0';}}), NaN, /0/, 0.1, (new Boolean(false)), -0]); ");
/*fuzzSeed-204645237*/count=1274; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul((Math.hypot((( + ( ~ ( + Math.abs(x)))) >>> 0), ((((Math.fround(( ! Math.fround(-Number.MIN_SAFE_INTEGER))) >>> 0) !== ( + Math.min((( ! ( + Math.fround(( + Math.fround(1/0))))) | 0), Math.hypot(x, y)))) >>> 0) >>> 0)) >>> 0), Math.fround((Math.fround(Math.fround(Math.imul(Math.fround((Math.fround(y) != Math.fround(( + y)))), Math.fround(Math.atan(( + (( + ( ~ y)) || ( + Math.pow(x, y))))))))) ** Math.fround(((Math.log10(x) | (( ~ ((Math.round(Math.fround(Math.round((x >>> 0)))) ? (x >>> 0) : (y >>> 0)) >>> 0)) | 0)) >>> 0))))); }); testMathyFunction(mathy0, [0/0, -0x080000001, -(2**53), -0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), -1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 42, 2**53-2, Number.MIN_SAFE_INTEGER, 1, -(2**53-2), 0x080000001, 0x0ffffffff, 0, 2**53, -0x100000001, -0x080000000, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, 0.000000000000001, 1/0, -Number.MAX_VALUE, -0, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-204645237*/count=1275; tryItOut("Object.defineProperty(this, \"t1\", { configurable: NaN, enumerable: true,  get: function() {  return new Uint16Array(b2, 40, this.v2); } });");
/*fuzzSeed-204645237*/count=1276; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + (( + ( + ( + ( - Math.min(y, -0x080000001))))) == ( + Math.fround(Math.hypot(Math.asinh(( - Math.expm1((x | 0)))), (( + (Math.min(y, (((x | 0) * x) / x)) ? (y >>> 0) : (x >>> 0))) >>> 0)))))); }); testMathyFunction(mathy0, [0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, -0x100000000, -(2**53+2), -1/0, 0.000000000000001, 2**53+2, 0, 0x07fffffff, Math.PI, 0x080000001, 0x0ffffffff, 2**53-2, Number.MAX_VALUE, 1, 42, -0x07fffffff, -Number.MIN_VALUE, 1/0, -0, -0x080000001, 1.7976931348623157e308, -0x0ffffffff, -(2**53), -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1277; tryItOut("h0.has = this.g2.f2;");
/*fuzzSeed-204645237*/count=1278; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.min((( ~ ( + (mathy2(Math.cosh(((y && (-0x080000000 && -(2**53+2))) | 0)), (Math.max(x, (((-(2**53) | 0) ? (x | 0) : ((y + x) | 0)) | 0)) | 0)) | 0))) >>> 0), ( + ( + (( + Math.sqrt(y)) ? ( - Math.fround(Math.min((Math.fround(((y >>> 0) != (Math.fround(mathy1((y >>> 0), (y >>> 0))) >>> 0))) | 0), (x >>> 0)))) : ( + Math.fround(( ~ mathy2((x , ( + ((x >>> 0) === ( + x)))), Math.sin(Math.tanh(( + Math.trunc(-(2**53+2)))))))))))))); }); testMathyFunction(mathy3, [-0x100000000, -Number.MIN_VALUE, 0, -0, -0x100000001, -1/0, 0.000000000000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 1, 0/0, 2**53-2, -(2**53), 2**53, -0x07fffffff, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, 0x07fffffff, 1/0, -0x080000000, -(2**53+2), 0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 42, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, 0x100000001]); ");
/*fuzzSeed-204645237*/count=1279; tryItOut("\"use strict\"; for(let [a, z] = yield  /x/  in eval(\"(makeFinalizeObserver('tenured'))\").watch(\"stringify\", \"\u03a0\")) {a2 = r1.exec(g0.g2.s1);a2.push(g1.h0, o1.g1.a1, f2, h2); }");
/*fuzzSeed-204645237*/count=1280; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ mathy0(( + 1/0), ( + Math.expm1(( + 42))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, -0x0ffffffff, 2**53-2, 0x080000000, 2**53+2, 1, 42, 0, 0x07fffffff, 2**53, 0x0ffffffff, 1.7976931348623157e308, 1/0, -0x080000001, -0x080000000, Number.MIN_VALUE, 0x100000001, -0, 0/0, -(2**53+2), -(2**53), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, -1/0, 0x080000001, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1281; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ (((Math.tanh((Math.fround(Math.log10(Math.fround(y))) >>> 0)) >>> 0) & Math.max(Math.tanh(Math.imul(y, Math.fround(1))), x)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53-2), -1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -Number.MAX_VALUE, 0/0, -(2**53+2), -0x080000000, -0x080000001, 0x07fffffff, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, 0x080000001, 0x080000000, 0x100000001, -0x100000001, 0.000000000000001, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), -0, 1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 0, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, 2**53+2, 42, 2**53]); ");
/*fuzzSeed-204645237*/count=1282; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[new (--this.zzz.zzz)(), 2**53, false, new Boolean(true), function(){}, new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), 2**53, new Boolean(true), function(){}, function(){}, 2**53, function(){}, new Boolean(true), 2**53, 2**53, new (--this.zzz.zzz)(), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, function(){}, new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), 2**53, false, function(){}, new (--this.zzz.zzz)(), false, new (--this.zzz.zzz)(), false, function(){}, new (--this.zzz.zzz)(), new Boolean(true), 2**53, 2**53, new (--this.zzz.zzz)(), new Boolean(true), false, new Boolean(true), new Boolean(true), new Boolean(true), new (--this.zzz.zzz)(), 2**53, function(){}, new (--this.zzz.zzz)(), false, false, new (--this.zzz.zzz)(), function(){}, new Boolean(true), false, 2**53, function(){}, new Boolean(true), new (--this.zzz.zzz)(), function(){}, function(){}, new (--this.zzz.zzz)(), function(){}, new (--this.zzz.zzz)(), 2**53, false, new Boolean(true), 2**53, 2**53, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), false, function(){}, new (--this.zzz.zzz)(), false, new (--this.zzz.zzz)(), 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), false, 2**53, function(){}, 2**53, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(true), false, function(){}, new (--this.zzz.zzz)(), new Boolean(true), new Boolean(true), new (--this.zzz.zzz)(), new Boolean(true), 2**53, new (--this.zzz.zzz)(), 2**53, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, function(){}, 2**53, new (--this.zzz.zzz)(), new Boolean(true), function(){}, new Boolean(true), new Boolean(true), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new Boolean(true), false, function(){}, function(){}, function(){}, function(){}, new Boolean(true), new Boolean(true), function(){}, new Boolean(true), false, function(){}, 2**53, new (--this.zzz.zzz)(), new Boolean(true), new (--this.zzz.zzz)(), false, 2**53, false, new Boolean(true), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new Boolean(true), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), new (--this.zzz.zzz)(), false, new (--this.zzz.zzz)(), new Boolean(true), function(){}, function(){}, function(){}, new Boolean(true), new (--this.zzz.zzz)(), false, 2**53, function(){}, 2**53]); ");
/*fuzzSeed-204645237*/count=1283; tryItOut("\"use strict\"; (this.__defineSetter__(\"x\",  /x/g ));");
/*fuzzSeed-204645237*/count=1284; tryItOut("with(({a2:z2})){/*ODP-1*/Object.defineProperty(this.h0, \"valueOf\", ({}));; }");
/*fuzzSeed-204645237*/count=1285; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?=[^\\\\w])(?!.)){4,6}|(?:\\\\B{3,}|[^](?:(?:^)*?){3,})+?\", \"yi\"); var s = \"11 1\\n11 111 111 111 111 111 111 1\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\n\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\\uc832\\u0f65\\u00d1a\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1286; tryItOut("e0.add(g0);\n{}\nprint(x);\n\n");
/*fuzzSeed-204645237*/count=1287; tryItOut("o0.g2.t1.set(this.t0, this.v0);");
/*fuzzSeed-204645237*/count=1288; tryItOut("a0.sort((function(j) { f0(j); }), Math.pow(16, 1));");
/*fuzzSeed-204645237*/count=1289; tryItOut("\"use strict\"; const x = (4277), y, zewbzc, w, \u3056 =  \"\" .__defineGetter__(\"b\", [1]), c, x = true, window;print(\"\\u2113\");h0.get = (function() { try { delete h1.iterate; } catch(e0) { } try { g2.m2.set(o0, t2); } catch(e1) { } a2.pop(); return g0.e0; });");
/*fuzzSeed-204645237*/count=1290; tryItOut("\"use strict\"; v1 = 0;");
/*fuzzSeed-204645237*/count=1291; tryItOut("if(false) { if ( \"\" ) v2 = (i2 instanceof o0.g1); else {[,,]; }}");
/*fuzzSeed-204645237*/count=1292; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=1293; tryItOut("o0.v1 = (e0 instanceof f1);");
/*fuzzSeed-204645237*/count=1294; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1295; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\b|(?:(^){3,})|[\\\\u001b-\\\\x4fh\\\\\\u5c2f\\\\v-\\u8bca]|(?=(\\\\s))|(?!\\\\2)+?{0}|((\\\\B+)|[^]|\\\\S){2,}*?\", \"yi\"); var s = window; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=1296; tryItOut("for (var p in e2) { o1.m2.get(v2); }");
/*fuzzSeed-204645237*/count=1297; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( - ((Math.fround(( ~ Math.fround(x))) >>> 0) | Math.sqrt(y)))); }); testMathyFunction(mathy4, [-0x07fffffff, -(2**53), 2**53-2, -1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, -(2**53+2), 0x080000000, 2**53+2, -(2**53-2), 0/0, -0x080000001, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MIN_VALUE, 0x100000001, 0x080000001, 1.7976931348623157e308, -0x100000001, 0x100000000, 2**53, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1, 42, 0x0ffffffff, Math.PI, -Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=1298; tryItOut("/*tLoop*/for (let w of /*MARR*/[true, true, true, Infinity, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true]) { print(window); }");
/*fuzzSeed-204645237*/count=1299; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min((( + Math.fround(Math.tanh(Math.imul(( + ((-0x080000000 << (-Number.MIN_SAFE_INTEGER | 0)) >>> 0)), (Math.fround(Math.atanh(y)) || -Number.MAX_VALUE))))) % ( + Math.cosh((( ! x) | 0)))), ( + Math.min((Math.hypot(Math.pow(( - x), (y >= 0.000000000000001)), Math.min((x | 0), (( ~ ((Math.fround(x) < x) >>> 0)) >>> 0))) >>> 0), Math.fround(Math.asinh(x))))); }); testMathyFunction(mathy3, [-0x080000001, Math.PI, 2**53+2, -1/0, -0x080000000, 0x0ffffffff, 1/0, 42, -0, 2**53-2, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, -(2**53+2), 0x100000001, -0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, 2**53, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0, -(2**53), -0x100000000, 0x100000000, -(2**53-2), 0x080000001, Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=1300; tryItOut("for (var v of p0) { try { this.v1 = Object.prototype.isPrototypeOf.call(this.a0, s1); } catch(e0) { } try { a0.shift(); } catch(e1) { } try { a1.pop(g2); } catch(e2) { } o0.v1 = (x % 4 != 0); }");
/*fuzzSeed-204645237*/count=1301; tryItOut("mathy4 = (function(x, y) { return Math.min(( + (( + (((0x080000000 != (Math.cosh((x | 0)) | 0)) >>> 0) !== ((Math.atan2(y, (x >>> 0)) >>> 0) === (mathy1(Math.sinh(Number.MIN_VALUE), (x >>> 0)) >>> 0)))) ^ (( ~ ((Math.max((x | 0), y) | 0) | 0)) | 0))), (mathy3(((((Math.hypot(( + (( + y) <= Math.fround(Math.PI))), (-(2**53+2) != y)) >>> 0) << Math.fround(( + y))) >>> 0) >>> 0), (Math.fround(Math.imul(Math.fround(y), Math.fround(Math.log1p(Math.fround(Math.pow(Math.fround(x), Math.fround(y))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [0, (new Boolean(true)), 1, /0/, -0, [], (new Number(-0)), ({valueOf:function(){return '0';}}), '/0/', NaN, ({toString:function(){return '0';}}), 0.1, ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Number(0)), undefined, '', (new String('')), false, null, [0], '0', '\\0', true, objectEmulatingUndefined(), (function(){return 0;})]); ");
/*fuzzSeed-204645237*/count=1302; tryItOut("return;\no1.m1.set(p2, e1);\n");
/*fuzzSeed-204645237*/count=1303; tryItOut("/*MXX2*/g0.Array.prototype.every = s1;");
/*fuzzSeed-204645237*/count=1304; tryItOut("let (z =  \"\" , c = -10, x, x, x, x, w, tjaerz, hdegxq) { v2 = o1.g1.runOffThreadScript(); }");
/*fuzzSeed-204645237*/count=1305; tryItOut("mathy2 = (function(x, y) { return (Math.fround((( + Math.cosh((((y <= (Math.min(-(2**53-2), y) | 0)) | 0) | 0))) , Math.min(( + ((((y >>> 0) && (x >>> 0)) >>> 0) | 0)), Math.max(y, y)))) ? Math.fround(mathy1(Math.fround((Math.cos(( + Math.atan2(y, Math.fround(y)))) | 0)), Math.cos(( + Math.acosh(x))))) : mathy1((((Math.log2(y) != (Math.fround(( + Math.fround((Number.MAX_VALUE - (y || y))))) >>> 0)) ? Math.fround(Math.log10(Math.fround(42))) : ( + mathy1(Math.acosh(y), (y | 0)))) >>> 0), (Math.expm1((( ~ (0x080000001 | 0)) | 0)) ? ( + ( + mathy1((0x080000001 >>> 0), ( + Math.ceil((Number.MAX_SAFE_INTEGER | 0)))))) : (( ~ 1.7976931348623157e308) >>> 0)))); }); ");
/*fuzzSeed-204645237*/count=1306; tryItOut("");
/*fuzzSeed-204645237*/count=1307; tryItOut("\"use strict\"; t2[18] = v2;");
/*fuzzSeed-204645237*/count=1308; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.sin((mathy0((Math.log(mathy0(( ! x), Math.fround(Math.fround(Math.fround(x))))) | 0), ( + Math.log2(( + ( + Math.round(( + Math.fround((Math.fround(x) * Math.fround(y)))))))))) >>> 0)); }); testMathyFunction(mathy1, [-(2**53), -0, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, -0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -0x0ffffffff, -0x100000001, 2**53+2, 1.7976931348623157e308, 0/0, 0, -(2**53+2), -Number.MAX_VALUE, 2**53-2, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, 1/0, -(2**53-2), 1, 0.000000000000001, 0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=1309; tryItOut("testMathyFunction(mathy4, /*MARR*/[(/*UUV2*/(w.splice = w.lastIndexOf).watch(11, q => q)),  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , new Boolean(true), new Boolean(true), (/*UUV2*/(w.splice = w.lastIndexOf).watch(11, q => q)), (/*UUV2*/(w.splice = w.lastIndexOf).watch(11, q => q)), new Boolean(true), new Boolean(true), new Boolean(true),  '' , new Boolean(true), new Boolean(true), (/*UUV2*/(w.splice = w.lastIndexOf).watch(11, q => q)),  '' ,  '' ,  '' , (/*UUV2*/(w.splice = w.lastIndexOf).watch(11, q => q)), (/*UUV2*/(w.splice = w.lastIndexOf).watch(11, q => q))]); ");
/*fuzzSeed-204645237*/count=1310; tryItOut("\"use strict\"; switch(this.zzz.zzz--) { case 1: case (void version(170)): /*RXUB*/var r = new RegExp(\"\\\\2|(?![^]\\\\D{4,6}|(?=[^\\u00e0-\\\\7\\\\D\\\\x41-\\u00c4$-\\\\ud2dB]|^)|\\\\2)\\\\cF|\\\\d{1,}\", \"i\"); var s = \"\"; print(uneval(s.match(r))); break; /*MXX1*/let o0.o0.g2.g2.o1 = o0.g1.Math.fround;break; break;  }");
/*fuzzSeed-204645237*/count=1311; tryItOut("mathy5 = (function(x, y) { return (( + Math.fround((Math.fround((Math.atan2(((Number.MIN_VALUE >= y) >>> 0), (y >>> 0)) >>> 0)) % Math.fround(( - Math.fround(Math.min(Math.fround(x), Math.fround((( + x) < Math.fround(mathy4(Math.fround(x), Math.fround(y)))))))))))) + Math.asinh(((mathy3(mathy0((Math.max(Math.fround(y), ((( + (-0 | 0)) | 0) >>> 0)) >>> 0), Math.fround(Math.max(x, ( + -(2**53+2))))), (( + (( + Math.log10(x)) | 0)) >>> 0)) | 0) != ( ~ 0/0)))); }); ");
/*fuzzSeed-204645237*/count=1312; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1313; tryItOut("t0.toSource = (function() { o2.i0.next(); return v0; });");
/*fuzzSeed-204645237*/count=1314; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=1315; tryItOut("Array.prototype.sort.apply(a0, [String.prototype.slice.bind(o0), h1, v1, this.b2]);");
/*fuzzSeed-204645237*/count=1316; tryItOut("v1 = g2.runOffThreadScript();");
/*fuzzSeed-204645237*/count=1317; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 0x0ffffffff, -0x080000000, -0x100000001, Number.MIN_VALUE, -0x100000000, -1/0, 2**53+2, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, Math.PI, 0/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), -0x07fffffff, 0.000000000000001, -0x0ffffffff, 2**53-2, 0x080000001, 0x080000000, 0x07fffffff, 1.7976931348623157e308, 42, 0x100000001, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), 0]); ");
/*fuzzSeed-204645237*/count=1318; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot((Math.fround(mathy1(Math.fround((Math.hypot((-Number.MIN_SAFE_INTEGER | 0), (( ! (( ~ Number.MIN_VALUE) >>> 0)) | 0)) | 0)), (( ! Math.fround((y ? x : -Number.MAX_VALUE))) >> y))) >>> 0), Math.fround((Math.hypot(Math.hypot((( + ( - -0)) >>> 0), ( + ( + -0x080000000))), y) + Math.tanh(Math.atan2(Math.pow((y >>> 0), (( + (( + y) >> ( + x))) >>> 0)), Math.min(Math.cosh(Math.tanh(-(2**53))), y)))))); }); testMathyFunction(mathy4, [0/0, 42, 1, -Number.MAX_VALUE, -(2**53-2), -0x07fffffff, 0x080000000, 2**53+2, Math.PI, 0x100000000, 2**53, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, 0x100000001, 0x0ffffffff, 2**53-2, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -0x080000001, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), 1/0]); ");
/*fuzzSeed-204645237*/count=1319; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround((Math.fround(Math.fround(Math.atan2(( ~ (Math.min((x | 0), x) >>> 0)), Math.fround(mathy0(( + ( + ( + Math.fround(( ! Math.fround((Math.sinh((1/0 >>> 0)) | 0))))))), (Math.sign((Math.fround((0x080000000 / -0x100000001)) >>> 0)) | 0)))))) <= Math.fround(((Math.min(Math.imul(((mathy2((x >>> 0), ( + 2**53+2)) >>> 0) >>> 0), (Math.fround(((0x080000001 >>> 0) | Math.fround(y))) | 0)), (x | 0)) | 0) , Math.imul(Math.log2(Number.MIN_SAFE_INTEGER), (Math.sqrt(Math.fround(x)) >>> 0)))))); }); testMathyFunction(mathy3, [(new Boolean(false)), ({valueOf:function(){return 0;}}), -0, '0', 1, (function(){return 0;}), null, '\\0', (new String('')), 0, (new Boolean(true)), false, '', ({valueOf:function(){return '0';}}), (new Number(0)), objectEmulatingUndefined(), true, undefined, '/0/', 0.1, (new Number(-0)), NaN, [], /0/, ({toString:function(){return '0';}}), [0]]); ");
/*fuzzSeed-204645237*/count=1320; tryItOut("i1.send(h1);");
/*fuzzSeed-204645237*/count=1321; tryItOut("print(uneval(h2));\nprint([,,z1]);\n");
/*fuzzSeed-204645237*/count=1322; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.imul((( ~ Math.round(( + Math.asinh((mathy0(x, x) | 0))))) | 0), Math.fround(Math.sign((mathy0((x | 0), (Number.MIN_VALUE | 0)) | 0)))) >> Math.fround(Math.min((mathy0(Math.atan2(y, x), (Math.max((((y >>> 0) << ((Math.imul((y | 0), (0x080000001 | 0)) | 0) >>> 0)) | 0), ( + Math.max(( + Math.sinh(y)), ( + x)))) >>> 0)) >>> 0), ((( + ( - ( + x))) + ( + x)) | 0)))); }); testMathyFunction(mathy3, [2**53, 1, -Number.MAX_VALUE, -(2**53-2), 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -(2**53+2), 2**53+2, 0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, -0x100000000, -0x07fffffff, 0/0, 0x0ffffffff, -0x100000001, -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53), Math.PI, 2**53-2, 42, 0x080000001, 0, 0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=1323; tryItOut("/*MXX3*/g2.Symbol.length = g2.Symbol.length\n");
/*fuzzSeed-204645237*/count=1324; tryItOut("mathy1 = (function(x, y) { return ( + Math.imul((Math.hypot(Math.PI, (x * (((mathy0(x, y) >>> 0) - y) >>> 0))) === (1/0 >>> 0)), (Math.imul((Math.fround(((Math.imul((-0x080000001 | 0), (Math.fround(((x | 0) >= Math.fround(x))) | 0)) | 0) ? (Math.min((x >>> 0), (x >>> 0)) >>> 0) : (Math.min((Math.imul(0x080000000, y) >>> 0), (Math.clz32((y >>> 0)) >>> 0)) >>> 0))) >>> 0), Math.fround(Math.fround(Math.fround(Math.fround(y))))) >>> 0))); }); ");
/*fuzzSeed-204645237*/count=1325; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy1(Math.fround((( ~ Math.max(x, y)) || mathy0)), ( ! mathy1(Math.trunc(Math.fround(Math.log2(x))), ( - y)))) | 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 0x07fffffff, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, 1/0, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, 0x0ffffffff, -0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 1, 0/0, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, -(2**53), -1/0, 0.000000000000001, -0x080000000, 0x100000001, -0x080000001, -0x100000000, 0x100000000, -(2**53+2), -0x07fffffff, 0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=1326; tryItOut("o1 = new Object;");
/*fuzzSeed-204645237*/count=1327; tryItOut("\"use strict\"; i1.send(o2.o0);\n/*hhh*/function eupmul(){h1 = {};}/*iii*/m0 = new WeakMap;\n");
/*fuzzSeed-204645237*/count=1328; tryItOut("print(Math.atan2(undefined, (4277)));");
/*fuzzSeed-204645237*/count=1329; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((((Math.atan(Math.log1p(((( + x) > ( + (( - Math.max(y, x)) >>> 0))) >>> 0))) - (Math.abs(Math.fround(Math.cos(Math.fround(y)))) >>> 0)) | 0) ? ((( + (Math.atan2((( - Math.hypot(y, y)) >>> 0), Math.min(x, Math.fround(Math.log10(Math.fround(x))))) | 0)) | 0) / Math.fround(mathy3(Math.fround(( - x)), Math.fround(y)))) : ((mathy1(Math.hypot(Math.fround((Math.fround((( ! x) ** x)) * Math.fround(Math.atan2(mathy2(Math.fround(x), Math.fround(-0)), 0.000000000000001)))), ( + (Math.fround((Math.fround(x) !== Math.fround(Math.cos(( + y))))) >>> 0))), (Math.asinh((Math.sinh(y) >>> 0)) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy4, [1.7976931348623157e308, 0x080000001, 2**53+2, 0x0ffffffff, 0/0, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 0.000000000000001, 0x080000000, -(2**53-2), 2**53-2, -0x100000001, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 2**53, -Number.MIN_VALUE, -0x080000000, -(2**53), Number.MIN_VALUE, -0x07fffffff, -1/0, 1, 1/0, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -0x100000000, 0x100000000, 42, -0]); ");
/*fuzzSeed-204645237*/count=1330; tryItOut("\"use strict\"; let (z) { t0[15] = let (b) (/(?:(.){2147483647}|\\u0084){2}(?![^])|^|\\b{2,5}/gyim >= new RegExp(\"[^]\", \"im\"))\n.eval(\"g0.offThreadCompileScript(\\\"function f0(a2)  { return -0 } \\\");\"); }");
/*fuzzSeed-204645237*/count=1331; tryItOut("/*infloop*/for(var z; /*FARR*/[new RegExp(\"[\\u0593\\\\\\u9a4f-\\\\cO]|.[^]+??[]+\\\\B\\uade7.+?(\\\\B)?|${3,6}^{1048576}{3,4}\", \"im\")]; (window / x)) {i2.send(g0);t1.set(a2, z); }");
/*fuzzSeed-204645237*/count=1332; tryItOut("/*RXUB*/var r = /\\S|((?:\\w|\\f?)(?=.{1}))^?|$|(?:[^])|(?![]|v{3,}){3,}/m; var s = \"\\n\\n\\n\\u00c1\\n\\n\\n\\u00c1\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1333; tryItOut("\"use strict\"; v0 = (g2.o2.o0.p2 instanceof a2);");
/*fuzzSeed-204645237*/count=1334; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.asinh((Math.atan2((Math.atan(((Math.hypot((x | 0), (y | 0)) | 0) >>> 0)) | 0), ((Math.sqrt(((Math.pow((( - ( ~ x)) | 0), (( + Math.max(( + 1/0), y)) | 0)) | 0) >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy5, [-1/0, 0x080000001, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -(2**53-2), 2**53+2, 0.000000000000001, 0, 1/0, 0x07fffffff, 1.7976931348623157e308, 42, 2**53-2, -0x080000000, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x100000001, Math.PI, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000000, -0, 0x0ffffffff, 0/0, 0x100000001, -0x07fffffff, -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=1335; tryItOut("for (var v of m0) { try { v0 = g1.eval(\"/* no regression tests found */\"); } catch(e0) { } try { (void schedulegc(g1)); } catch(e1) { } v2 = g0.eval(\"/* no regression tests found */\"); }");
/*fuzzSeed-204645237*/count=1336; tryItOut("g1.v0 = Object.prototype.isPrototypeOf.call(a1, a0);");
/*fuzzSeed-204645237*/count=1337; tryItOut("/*infloop*/for(let arguments[\"toString\"] in x) {x = NaN; }");
/*fuzzSeed-204645237*/count=1338; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround((Math.fround((Math.fround((Math.fround((y * x)) > Math.fround(Math.PI))) & Math.fround(Math.trunc(((-Number.MIN_VALUE | 0) % ( ~ -Number.MAX_SAFE_INTEGER)))))) >> (x ^ (Math.pow(Math.fround(mathy1((y >>> 0), y)), (x | 0)) | 0)))) + mathy2(( + ( + (Math.fround((Math.fround((((y | 0) / y) | ( ~ x))) ? Math.fround((( + ( + x)) & x)) : Math.fround(((mathy1(( + x), ( + y)) >>> 0) | x)))) << ( + (( + ( - 42)) >> ( + x)))))), Math.atan2((Math.pow(Math.acosh(Math.pow(x, ( + (( + x) + (x | 0))))), ( - (x | 0))) | 0), (( + ( + (( + Math.fround(mathy1(2**53-2, x))) ? ( + ( - (-1/0 | 0))) : Math.fround(Math.fround(Math.fround(y)))))) | 0)))); }); testMathyFunction(mathy3, [-(2**53), -0x100000000, 2**53, -0, 1, -0x080000000, -0x0ffffffff, 0x080000001, 1.7976931348623157e308, -0x080000001, -0x100000001, 1/0, -Number.MAX_VALUE, 42, 0x080000000, 2**53+2, Math.PI, 0, -Number.MIN_VALUE, 0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, -(2**53-2), 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001]); ");
/*fuzzSeed-204645237*/count=1339; tryItOut("this.o1.a0 = Array.prototype.concat.call(a1, a0, o2.t1, p1, s0, o1);");
/*fuzzSeed-204645237*/count=1340; tryItOut("a0.forEach((function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = (0x2e4e8a68);\n    return (((0xad77284) % (((0x7c8138e0)+((1.0) < (d1)))>>>(((((abs((0x145336c4))|0) / (0x404b6540))|0) < ((((abs((-0x8000000))|0))) << (((0x7fffffff))+((0x8e3ff7bf) ? (-0x8000000) : (0xffffffff)))))))))|0;\n  }\n  return f; }), m2);");
/*fuzzSeed-204645237*/count=1341; tryItOut("v1 = g0.eval(\"g2.t1[({valueOf: function() { t2.__iterator__ = (function() { v1 = Object.prototype.isPrototypeOf.call(s0, t1); return g2; });return 11; }})] = (yield z = /\\\\b\\\\2\\\\2+/);\");");
/*fuzzSeed-204645237*/count=1342; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return (( + ((( + mathy2(((x - Math.fround(((x > x) >>> 0))) | 0), ((mathy1(( + mathy0(Math.fround(y), (mathy3(x, (x >>> 0)) && ( ! x)))), (((((x + (x | 0)) | 0) >>> 0) - (y >>> 0)) >>> 0)) >>> 0) | 0))) && ((Math.hypot(y, (Math.trunc(((-0x080000001 , Math.fround(Math.pow((x >>> 0), ((y % x) | 0)))) >>> 0)) >>> 0)) >>> 0) | 0)) | 0)) <= (((( ! (Math.pow(((y + Math.fround(x)) | 0), (-0x080000001 | 0)) | 0)) | 0) > (((((x | 0) << (x | 0)) >>> 0) % ((((x | 0) != (x | 0)) | 0) >>> 0)) >>> 0)) | ( + (( + Math.fround((Math.fround(( ! ( + x))) > Math.fround(x)))) & ( + x))))); }); testMathyFunction(mathy4, [-(2**53), 2**53-2, -(2**53+2), -0, -0x080000001, -1/0, 0x100000000, -0x0ffffffff, 1.7976931348623157e308, 2**53+2, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 0x0ffffffff, 0x100000001, 0x080000000, Number.MAX_VALUE, 0x07fffffff, -0x100000001, 0, -Number.MAX_SAFE_INTEGER, 0/0, Math.PI, 0x080000001, 42, 2**53, -0x100000000, 1, Number.MIN_VALUE, 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1343; tryItOut("const ylyxuy, yield = x, x = Math.log1p( \"\" ), arguments = \"\\u55E4\", x = (function(q) { return q; })(this), [] = new /*\n*/(Object.getOwnPropertyDescriptors)(), x, x, vpvawg, NaN;a0 = Array.prototype.concat.apply(a2, [a1, a0]);");
/*fuzzSeed-204645237*/count=1344; tryItOut("\"use strict\"; /*hhh*/function qdqvko(y, x){o0.a1 = new Array;}qdqvko();");
/*fuzzSeed-204645237*/count=1345; tryItOut("pxtagf");
/*fuzzSeed-204645237*/count=1346; tryItOut("/*RXUB*/var r = new RegExp(\"(?!$(?=(?![^])){1,}$+){3,17179869186}\", \"im\"); var s = \"\\n\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1347; tryItOut("testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, -(2**53), -(2**53-2), 2**53-2, 2**53+2, 0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, -0x0ffffffff, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0, 1.7976931348623157e308, -0x080000000, 0x080000001, 2**53, -Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, 1/0, Number.MAX_VALUE, -0, 0x080000000, -0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0/0, Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1348; tryItOut("v0 = (g0 instanceof v1);");
/*fuzzSeed-204645237*/count=1349; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.cosh(( ! (0x080000001 ? Math.pow(( + 0x100000001), ( + Math.log((x | 0)))) : (Math.min(Number.MAX_SAFE_INTEGER, (y >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [2**53, -0x0ffffffff, Math.PI, 0x080000000, -(2**53-2), 0x100000001, 0, Number.MIN_VALUE, 2**53+2, -0, -(2**53+2), 0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 1, 0.000000000000001, 0x080000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, 1/0, -0x080000000, 42, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, -1/0, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=1350; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.sqrt(Math.fround(Math.fround((( + Math.min(( + x), ( + (((Math.hypot(((Math.fround(( + x)) ? Math.fround(( + ( ~ ( + y)))) : Math.fround(y)) >>> 0), (Math.asinh(x) >>> 0)) >>> 0) | 0) >= 0/0)))) , Math.sign(x)))))); }); testMathyFunction(mathy0, [2**53-2, 0x07fffffff, 0/0, -(2**53), Math.PI, -0x080000000, 0, Number.MIN_VALUE, 1/0, 1, 0x080000000, 0x100000001, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 0x100000000, 2**53, 0.000000000000001, -(2**53-2), -1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, -0]); ");
/*fuzzSeed-204645237*/count=1351; tryItOut("");
/*fuzzSeed-204645237*/count=1352; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=1353; tryItOut("with(Math.expm1(-20))/*MXX1*/o2 = g2.Function.prototype.apply;");
/*fuzzSeed-204645237*/count=1354; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return (mathy2((( - Math.log1p((Math.fround((((( ~ (Math.trunc((y | 0)) | 0)) | 0) | 0) ? Math.fround((x === y)) : x)) << mathy2(Math.fround((x | y)), Math.fround(y))))) >>> 0), (Math.sin(((mathy1(((( + ( + mathy1(x, x))) / ( + 0.000000000000001)) | 0), (((Math.log1p(-(2**53+2)) , Math.fround(Math.hypot(Math.fround((Math.max((x >>> 0), 2**53) | 0)), Math.fround(y)))) >>> 0) | 0)) | 0) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, -0, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 2**53, 0x100000000, -(2**53+2), -Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, -(2**53), Number.MIN_VALUE, 0x080000001, -0x07fffffff, -0x080000000, 2**53-2, 0/0, 42, -0x100000000, 0x0ffffffff, 1, 0, -0x100000001, Math.PI, 0x080000000, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=1355; tryItOut("selectforgc(o1);");
/*fuzzSeed-204645237*/count=1356; tryItOut("mathy3 = (function(x, y) { return ( - Math.fround(Math.max(((((Math.imul(((0x080000001 && (-0x080000001 | 0)) | 0), (Math.fround(( + Math.trunc(x))) >>> 0)) >>> 0) | 0) % ((( + Math.hypot((0x0ffffffff ? (Math.fround(x) ? y : y) : mathy0(y, y)), -0x100000001)) * ( - y)) | 0)) | 0), (42 - Math.fround((( ! ( - -0)) / 0.000000000000001)))))); }); testMathyFunction(mathy3, [(new String('')), (new Number(-0)), undefined, 1, ({valueOf:function(){return '0';}}), (function(){return 0;}), [0], ({valueOf:function(){return 0;}}), -0, [], null, '\\0', (new Boolean(false)), '', '0', false, ({toString:function(){return '0';}}), /0/, objectEmulatingUndefined(), (new Boolean(true)), NaN, 0, (new Number(0)), 0.1, true, '/0/']); ");
/*fuzzSeed-204645237*/count=1357; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ~ ( + Math.fround(( ~ Math.pow(Math.atan2(Math.asinh((((y | 0) || ( + x)) | 0)), x), x))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0x080000001, 0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, 0x07fffffff, Number.MIN_VALUE, -1/0, 2**53-2, -0x100000001, -0x080000000, 0x100000000, -(2**53), Math.PI, 0x080000001, -0x100000000, -0x0ffffffff, 2**53+2, -0, 42, 0x100000001, -(2**53+2), -Number.MIN_VALUE, -(2**53-2), 2**53, 0.000000000000001, 1, Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1358; tryItOut("m1.has(p1);");
/*fuzzSeed-204645237*/count=1359; tryItOut("window;[1,,];");
/*fuzzSeed-204645237*/count=1360; tryItOut("if(/*MARR*/[[], null, 0x0ffffffff, [], 0x0ffffffff].sort((decodeURI).apply)) { if (((b) = this.__defineSetter__(\"eval\", OSRExit))) {return;/*MXX2*/g1.o2.g1.Object.prototype.constructor = g2; }} else /*RXUB*/var r = new RegExp(\"(?!(?:\\\\2)\\\\v|(?:\\\\D)|[^]?*?)+?\", \"gyi\"); var s = new RegExp(\"\\\\S\", \"gm\"); print(uneval(r.exec(s))); \u000c");
/*fuzzSeed-204645237*/count=1361; tryItOut("mathy3 = (function(x, y) { return (Math.imul(((((Math.max(((-(2**53+2) % Math.sign(x)) >>> 0), ( + ( + Math.asinh(x)))) >>> 0) >>> 0) < ((Math.fround(( - (Math.fround(Math.round(x)) >>> 0))) >= ((Math.fround(( ! -Number.MIN_VALUE)) + (Math.exp(Math.fround(Math.fround(( ~ (-0x0ffffffff | 0))))) | 0)) | 0)) | 0)) >>> 0), (mathy0(Math.acosh(( + Math.cosh(x))), Math.fround(Math.atan(Math.fround(x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x080000001, -Number.MIN_VALUE, 42, -(2**53+2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, -0x100000001, 2**53-2, -(2**53-2), -0, -0x07fffffff, 0x100000000, Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, 0x07fffffff, 0, -0x0ffffffff, 0x100000001, 0x0ffffffff, 2**53, 1, -0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, 2**53+2, -1/0, -0x080000000]); ");
/*fuzzSeed-204645237*/count=1362; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.expm1(Math.fround(Math.tanh(( - (( - (Math.fround(((y || (y | 0)) / x)) >= Math.fround(x))) >>> 0)))))); }); testMathyFunction(mathy2, [-0x080000000, Math.PI, -(2**53), -0, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x100000001, -0x0ffffffff, 0x07fffffff, -(2**53-2), -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 1, 0/0, -0x100000001, 0x100000000, 0x0ffffffff, 0.000000000000001, 2**53+2, Number.MIN_VALUE, 1/0, 42, 2**53]); ");
/*fuzzSeed-204645237*/count=1363; tryItOut("x;\nv1 = Object.prototype.isPrototypeOf.call(this.v1, o2.v0);\n");
/*fuzzSeed-204645237*/count=1364; tryItOut("\"use strict\"; /*oLoop*/for (czphaw = 0; czphaw < 11; ++czphaw) { ( \"\" ); } ");
/*fuzzSeed-204645237*/count=1365; tryItOut("selectforgc(o2);");
/*fuzzSeed-204645237*/count=1366; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\u00f6)/gym; var s = \"\\u00f6\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1367; tryItOut("with({x:  '' })o2.t0.valueOf = (function(j) { f1(j); });");
/*fuzzSeed-204645237*/count=1368; tryItOut("v1 = a1.length;");
/*fuzzSeed-204645237*/count=1369; tryItOut("testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -0x100000000, -0x07fffffff, 2**53, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 2**53-2, 0x080000001, -Number.MIN_VALUE, 0x0ffffffff, 0x100000000, 0, 2**53+2, -(2**53+2), 0.000000000000001, -(2**53-2), 0/0, -0x100000001, -Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, 1, -0x080000001, 0x07fffffff, 0x100000001, -(2**53), 1.7976931348623157e308, -0]); ");
/*fuzzSeed-204645237*/count=1370; tryItOut("\"use asm\"; testMathyFunction(mathy2, [-0x100000001, 0, Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 2**53-2, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), Math.PI, 2**53, 1/0, 0.000000000000001, 0x080000001, -(2**53+2), 42, 2**53+2, 0x100000001, 1.7976931348623157e308, -1/0, -0x080000001, 0x100000000, 0x080000000, -0x07fffffff, -0]); ");
/*fuzzSeed-204645237*/count=1371; tryItOut("x = linkedList(x, 4232);");
/*fuzzSeed-204645237*/count=1372; tryItOut("\"use strict\"; m1 + '';");
/*fuzzSeed-204645237*/count=1373; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\"; /*bLoop*/for (funxdt = 0, Math.pow((x & x), Array.prototype.find-=x); funxdt < 25; ++funxdt, /(?!\\2)/gyim) { if (funxdt % 46 == 8) { print(x); } else { this.o0.v2 = (b1 instanceof h1); }  } \n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)+(((((((0xf99dd78c))>>>((0xb6841812))) / (((0xffffffff))>>>((0xffffffff)))) & (0xfffff*(i1)))) < (0x59d7e9b6))-(i1)))|0;\n  }\n  return f; })(this, {ff: Math.round}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-204645237*/count=1374; tryItOut("\"use strict\"; /*RXUB*/var r = ((yield  '' )); var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-204645237*/count=1375; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"x\");");
/*fuzzSeed-204645237*/count=1376; tryItOut("\"use strict\"; /*vLoop*/for (var ndwvzx = 0; ndwvzx < 143; ++ndwvzx) { b = ndwvzx; print(x); } ");
/*fuzzSeed-204645237*/count=1377; tryItOut("\"use strict\"; v0 = b1.byteLength;");
/*fuzzSeed-204645237*/count=1378; tryItOut("this.zzz.zzz;");
/*fuzzSeed-204645237*/count=1379; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1380; tryItOut("a0 = Array.prototype.map.apply(a2, [(function() { try { /*RXUB*/var r = r2; var s = \"_______\\u88b2\"; print(uneval(s.match(r)));  } catch(e0) { } v0 = t1.length; return h2; })]);");
/*fuzzSeed-204645237*/count=1381; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o1, o1);");
/*fuzzSeed-204645237*/count=1382; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.fround(( ~ Math.hypot(Math.atan2(( + y), Math.trunc((-0x080000000 | 0))), ( - (( + Math.sign(( + x))) ? y : ( - Math.imul(x, x)))))))); }); ");
/*fuzzSeed-204645237*/count=1383; tryItOut("\"use strict\"; v2 = evaluate(\" /* Comment */\\u3056 = true\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: true, sourceMapURL: s0 }));");
/*fuzzSeed-204645237*/count=1384; tryItOut("x;");
/*fuzzSeed-204645237*/count=1385; tryItOut(";");
/*fuzzSeed-204645237*/count=1386; tryItOut("/*tLoop*/for (let x of /*MARR*/[(-1/0), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, (-1/0), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, (-1/0), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), (-1/0), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), (-1/0), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), (-1/0), objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, (-1/0), (-1/0), -Number.MAX_SAFE_INTEGER, (-1/0), (-1/0), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, (-1/0), (-1/0), objectEmulatingUndefined(), (-1/0), -Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, (-1/0), -Number.MAX_SAFE_INTEGER, (-1/0), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, (-1/0), (-1/0), (-1/0), -Number.MAX_SAFE_INTEGER, (-1/0), -Number.MAX_SAFE_INTEGER, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), -Number.MAX_SAFE_INTEGER, (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]) { neuter(b2, \"change-data\"); }");
/*fuzzSeed-204645237*/count=1387; tryItOut("a0 = Array.prototype.concat.apply(a0, [a1, t1, o1]);");
/*fuzzSeed-204645237*/count=1388; tryItOut("mathy5 = (function(x, y) { return mathy1(Math.fround(( + Math.sqrt(Math.fround(( - ( ~ (Math.asinh((-(2**53) | 0)) | 0))))))), ( + Math.trunc(( ~ ( ! (Math.pow((-(2**53-2) | 0), (x | 0)) | 0)))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 1, 0x080000001, -0, 0x07fffffff, 2**53-2, 0x100000001, 0/0, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 42, -Number.MAX_VALUE, 0x100000000, -1/0, 0x0ffffffff, Math.PI, 1/0, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), 0x080000000, -0x07fffffff, -0x100000001, -(2**53+2), 0, -0x0ffffffff, -0x100000000, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=1389; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((((( - Math.abs(0.000000000000001)) | 0) << (mathy0(y, x) | 0)) && Math.fround(( ~ Math.fround((Math.pow((mathy0(x, ((((Math.max(( + y), y) >>> 0) | 0) * (( ~ x) ^ x)) >>> 0)) >>> 0), Math.sign((Math.max((y >>> 0), (x >>> 0)) >>> 0))) | 0))))) >>> 0); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), 0x100000000, -1/0, -Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000001, 0/0, -(2**53), 1, -0x100000000, -0x0ffffffff, 0x0ffffffff, 0, 0.000000000000001, Math.PI, 0x080000001, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 2**53+2, 42, 2**53-2, 1.7976931348623157e308, Number.MAX_VALUE, 2**53, -0x080000000, -0x07fffffff, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=1390; tryItOut("/*MXX3*/g0.String.prototype.substring = g0.String.prototype.substring;");
/*fuzzSeed-204645237*/count=1391; tryItOut("switch(x) { case 8: default: print(x); }");
/*fuzzSeed-204645237*/count=1392; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1393; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1394; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\B(?!\\\\b|\\\\\\u4959+|(?=\\\\2)[\\\\u007A-\\\\cN\\\\D\\\\D\\\\x99]|\\\\b+)|[]*|.P.{1,}|.|\\\\n*?[^]|[^]?|[^]*|[^]{3,524292}|[^]+?\", \"y\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1395; tryItOut("\"use asm\"; a1.unshift('fafafa'.replace(/a/g, new RegExp(\"\\\\3\", \"m\")), t2, ({/*toXFun*/toString: function() { return window; },  set delete(window, window = /(^){0,1}(?!\\W)+{0,}|([\\D\\S])+?\\S{64}|$?*?/y, d, x = x, x, x, x, b, d, x, x, x, y, x, c, eval, e, x, 8, \u3056, d, y, x, x, x, b, d, e = /(?:\\B)|\\W^?|(?:\\s)((.))*/yim, b, z = [,,z1], c = this, a, x, x, x = undefined, \u3056 = ({}), x, b, x = window, eval,  , x = [], setter, x, x =  /x/ , x = x, this.x, x) { \"use strict\"; yield -21 }  }));v1.__proto__ = this.f1;");
/*fuzzSeed-204645237*/count=1396; tryItOut("");
/*fuzzSeed-204645237*/count=1397; tryItOut("\"use strict\"; a1 = /*MARR*/[false, false,  /x/ ,  /x/ , false, false,  /x/ ,  \"\" ,  /x/ ,  \"\" , 0x3FFFFFFF,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  \"\" ,  /x/ , 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF,  /x/ ,  \"\" , false, 0x3FFFFFFF,  \"\" ,  /x/ ,  \"\" , false,  \"\" ,  /x/ ,  \"\" ,  /x/ , 0x3FFFFFFF,  \"\" , 0x3FFFFFFF, 0x3FFFFFFF, false, false, false,  \"\" ,  /x/ ,  /x/ , false,  /x/ ,  \"\" ,  /x/ ];");
/*fuzzSeed-204645237*/count=1398; tryItOut("this.v2 = (o0 instanceof g2.a1);");
/*fuzzSeed-204645237*/count=1399; tryItOut("a0.splice(5, 3, t1, m2, p1);");
/*fuzzSeed-204645237*/count=1400; tryItOut("var udfwoy = new SharedArrayBuffer(6); var udfwoy_0 = new Int32Array(udfwoy); var udfwoy_1 = new Int8Array(udfwoy); print(udfwoy_1[0]); udfwoy_1[0] = 0; for (var p in o0) { /*ODP-1*/Object.defineProperty(m1, \"__parent__\", ({configurable: true, enumerable: true})); }print(udfwoy_1[0]);");
/*fuzzSeed-204645237*/count=1401; tryItOut("for (var v of h1) { try { g2 + ''; } catch(e0) { } try { print(uneval(v0)); } catch(e1) { } b0 = g2.objectEmulatingUndefined(); }");
/*fuzzSeed-204645237*/count=1402; tryItOut("\"use strict\"; f1 = x;");
/*fuzzSeed-204645237*/count=1403; tryItOut("\"use strict\"; /*bLoop*/for (let muaukr = 0; muaukr < 4; ++muaukr) { if (muaukr % 17 == 13) { v2 = g0.runOffThreadScript(); } else { switch(() => \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -6.044629098073146e+23;\n    var i4 = 0;\n    var i5 = 0;\n    var d6 = 68719476737.0;\n    var i7 = 0;\n    d3 = ((d1));\n    return (((imul(((+((((67108863.0)) * ((1.2089258196146292e+24))))) >= (-281474976710657.0)), (0x59a3578))|0) / (abs((imul((i2), (((-3.0) != (+pow(((+atan2(((4.0)), ((590295810358705700000.0))))), ((72057594037927940.0)))))))|0))|0)))|0;\n    {\n      i4 = ((4277));\n    }\n    i2 = ((abs((((0xfa54d966)) >> ((i0))))|0));\n    return (((0x92eef69e)-(i4)))|0;\n  }\n  return f;.prototype.yoyo(intern( '' ))) { default: break; /*infloop*/for(var d; ([]) = undefined; (z = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: Int16Array, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: undefined, }; })(true), decodeURI, function (x, x = [z1,,], x, w, z =  /x/g , x, x, x, eval = 0, x = 8, z, eval, w, \u3056, NaN = ({a2:z2}), x, a, w, this.x, x, c, x, x, z, z, \u3056 = window, window, NaN, x =  /x/ , x, a, x, b, x, w, b, e, window, x, x, ...b) { return new window(x) } ))) (4277);x = o2;break;  } }  } ");
/*fuzzSeed-204645237*/count=1404; tryItOut("for (var v of s0) { try { ; } catch(e0) { } ; }");
/*fuzzSeed-204645237*/count=1405; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53), 2**53+2, 0x0ffffffff, -(2**53+2), -0x080000001, 2**53, 1, -Number.MAX_VALUE, 2**53-2, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, 0, 0x100000000, 0x07fffffff, -0, -1/0, 1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 42, -(2**53-2), -0x07fffffff, -0x100000001, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=1406; tryItOut("h2.valueOf = (function() { for (var j=0;j<29;++j) { f1(j%3==1); } });function eval() { \"use strict\"; o0.g0.a0.unshift(s0, e2); } v1 = Object.prototype.isPrototypeOf.call(v0, p1);");
/*fuzzSeed-204645237*/count=1407; tryItOut("\"use strict\"; for (var v of g1) { try { g1.v2 = g2.runOffThreadScript(); } catch(e0) { } this.o2.g2.g1.offThreadCompileScript(\"a2.sort((function() { try { /*MXX3*/g2.WeakMap.prototype = this.g0.WeakMap.prototype; } catch(e0) { } try { this.m1.has(t2); } catch(e1) { } try { v2 = r2.constructor; } catch(e2) { } Object.defineProperty(this, \\\"v1\\\", { configurable: false, enumerable: false,  get: function() {  return t2.BYTES_PER_ELEMENT; } }); return f0; }), b1, o2.b0, let (x)  '' .watch(\\\"valueOf\\\", x));\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: x, catchTermination: (x % 3 == 0) })); }");
/*fuzzSeed-204645237*/count=1408; tryItOut("v2 = Array.prototype.some.apply(a2, [(function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    {\n      return (((i0)))|0;\n    }\n    switch ((((i0)) >> (-0xfffff*(0xfdf68009)))) {\n      case 1:\n        d1 = (d1);\n      case -3:\n        {\n          {\n;          }\n        }\n    }\n    d1 = (d1);\n    d1 = ((((i0) ? (d1) : (+((p={}, (p.z = Date( \"\" ))()))))) / ((d1)));\n    return (((/*FFI*/ff(((0x53b019fb)), ((0x76ef8cf)), ((-((Float64ArrayView[2])))), ((((0xffffffff)-((((0x68be9c41)) ^ ((0xe95c20ed))) >= (~~(-17592186044417.0)))) ^ (((0x1148511) < (((0x8f6a73b1))>>>((0x7cf941ae))))-((-6.189700196426902e+26) > (((!(0xffffffff)))))))))|0)))|0;\n  }\n  return f; })(this, {ff: undefined}, new ArrayBuffer(4096))]);");
/*fuzzSeed-204645237*/count=1409; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1410; tryItOut("e2.delete(i1);");
/*fuzzSeed-204645237*/count=1411; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.log(( + Math.ceil(Math.exp(( - (Math.asin((( + (( + Number.MIN_SAFE_INTEGER) || Math.fround((x ? y : Math.PI)))) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy5, [[], (new Number(0)), 1, objectEmulatingUndefined(), true, 0, false, (new Boolean(true)), '0', (new Number(-0)), '/0/', -0, ({valueOf:function(){return '0';}}), [0], '', (new String('')), /0/, ({valueOf:function(){return 0;}}), (new Boolean(false)), undefined, ({toString:function(){return '0';}}), NaN, '\\0', 0.1, null, (function(){return 0;})]); ");
/*fuzzSeed-204645237*/count=1412; tryItOut("\"use strict\"; m0.get(h2);/*RXUB*/var r = r1; var s = s2; print(r.test(s)); function (b, ...b)/[]|\\d/yim");
/*fuzzSeed-204645237*/count=1413; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.cbrt(Math.fround(( ! (( ! (( + mathy1(( + ( + mathy0(Math.min(-Number.MAX_SAFE_INTEGER, x), Math.fround(x)))), ( + y))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), new String('q'), new String(''), new String('q'), x, new String(''), new String('')]); ");
/*fuzzSeed-204645237*/count=1414; tryItOut("Array.prototype.forEach.call(a2, (function(a0, a1, a2, a3) { var r0 = a3 % a0; var r1 = a1 - r0; var r2 = 1 - a3; var r3 = a2 | 7; var r4 = r0 | r3; var r5 = 0 | a3; var r6 = r0 | 7; var r7 = 9 & r1; var r8 = a3 % 0; var r9 = r0 / r2; var r10 = r2 | a1; var r11 = 8 | x; var r12 = 3 / r2; print(r0); var r13 = a1 + r4; var r14 = r6 % 0; var r15 = r10 ^ r1; var r16 = r9 % a2; var r17 = r3 - r16; var r18 = r8 | 8; var r19 = r3 + 5; var r20 = r17 / 4; var r21 = r19 & 3; var r22 = r8 % 2; var r23 = r19 % r7; var r24 = 5 - 5; var r25 = a1 & a3; var r26 = r6 ^ 3; var r27 = r26 / r16; var r28 = r21 / 9; r25 = x * r4; var r29 = r28 - r3; var r30 = r16 / r17; var r31 = 9 + r17; var r32 = r10 ^ r0; var r33 = r32 * 4; var r34 = 7 / r21; var r35 = r34 ^ r19; print(r3); var r36 = r35 / r31; var r37 = r20 * a1; var r38 = r8 % r22; r37 = 9 | 1; var r39 = r31 + x; r7 = r29 | r11; return a2; }));");
/*fuzzSeed-204645237*/count=1415; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( - Math.asinh((Math.fround(x) || Math.fround(( - (( - (Math.cos((y | 0)) | 0)) | 0)))))) >>> 0); }); testMathyFunction(mathy4, [-0x080000001, 0/0, 2**53-2, -(2**53), -(2**53+2), -0x0ffffffff, -0x080000000, 0x07fffffff, -0x100000000, -0x100000001, 0x080000001, 0x100000000, Math.PI, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 0x0ffffffff, 0, 42, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, -(2**53-2), -0, -0x07fffffff, Number.MAX_VALUE, 1/0, 1, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-204645237*/count=1416; tryItOut("testMathyFunction(mathy3, [-(2**53+2), 1/0, -0x07fffffff, 1, 0x080000000, 42, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), 0x07fffffff, -0x0ffffffff, 0x100000000, -0x080000001, -Number.MIN_VALUE, Math.PI, -0x100000000, 0.000000000000001, 2**53+2, 0x100000001, 0, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, 0x0ffffffff, -Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-204645237*/count=1417; tryItOut("print(x);\nprint(x);\n");
/*fuzzSeed-204645237*/count=1418; tryItOut("p1 = a2[v0];");
/*fuzzSeed-204645237*/count=1419; tryItOut("\"use strict\"; L:if(true) { if (eval(\"\\\"use strict\\\"; mathy0 = (function(x, y) { return Math.hypot(Math.max((Math.max(((((Math.round((Math.imul(Number.MAX_VALUE, -Number.MIN_VALUE) | 0)) | 0) << (( + Math.tan(( + Math.fround(Math.pow(Math.fround(y), Math.fround(y)))))) | 0)) >>> 0) | 0), ((Math.cbrt(y) !== -Number.MIN_VALUE) | 0)) | 0), Math.fround(Math.fround(Math.max(Math.fround(( ! ( + Math.round((( - (x | 0)) >>> 0))))), Math.max(2**53-2, Math.imul(y, 0x100000000)))))), Math.pow(Math.hypot(( + Math.pow(Math.expm1(x), ( - x))), Math.fround(Math.pow(( ! (Math.sinh(y) >>> 0)), Math.fround(0x080000000)))), ((Math.fround(x) >> Math.fround(Math.fround((Math.fround(Math.asinh(Math.asinh(Math.fround(x)))) <= Math.fround(-0x100000000))))) | 0))); }); testMathyFunction(mathy0, /*MARR*/[0xB504F332, (-1/0), 0xB504F332]); \")) print(-29 -= [z1,,]); else print(a2);}");
/*fuzzSeed-204645237*/count=1420; tryItOut("\u000c/*hhh*/function lqtfgh(){/*MXX2*/g1.Math.PI = s2;}/*iii*/t0 + '';");
/*fuzzSeed-204645237*/count=1421; tryItOut("\"use strict\"; return 14;");
/*fuzzSeed-204645237*/count=1422; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, o1);");
/*fuzzSeed-204645237*/count=1423; tryItOut("\"use strict\"; dqwnck;if(true) {/\\2{4,8}\\b(?=\\W|[^]+?\u9be4{0,1})\u00b2|\\B{0}\\r?/gyi; } else selectforgc(o1);");
/*fuzzSeed-204645237*/count=1424; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s0; print(r.exec(s)); ");
/*fuzzSeed-204645237*/count=1425; tryItOut("mathy1 = (function(x, y) { return Math.max(Math.pow(( + ( - Math.fround(( + ((x | 0) === (y | 0)))))), ( + Math.hypot(( + Math.tanh((x >>> 0))), ( + x)))), Math.min(Math.log10(( ~ x)), ( + ( ~ ((Math.atan2(((( + x) | 0) >>> 0), (( + mathy0(x, Math.fround(Math.fround(Math.log1p(Math.fround(x)))))) >>> 0)) >>> 0) | 0))))); }); ");
/*fuzzSeed-204645237*/count=1426; tryItOut("s2 += s0;");
/*fuzzSeed-204645237*/count=1427; tryItOut("mathy1 = (function(x, y) { return (( + Math.pow(Math.hypot(mathy0((( + ( ! -0x100000001)) <= ( + y)), Math.fround(Math.sqrt(( + (y * y))))), x), mathy0(y, (( ! 0x080000000) | 0)))) == (((x | ( + Math.log10(( + (((x | 0) === ((x / x) | 0)) | 0))))) ? (( + Math.ceil(x)) + x) : y) + Math.fround((( - Math.hypot(Math.imul(y, y), Math.fround(mathy0(( ! y), -Number.MAX_VALUE)))) | 0)))); }); ");
/*fuzzSeed-204645237*/count=1428; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy2(Math.max(Math.fround((Math.fround((Math.atan2((y | 0), (Math.trunc((x | 0)) | 0)) | 0)) % Math.fround(Math.fround(Math.min(Math.cosh(Number.MAX_VALUE), Math.min(-(2**53-2), Math.fround(y))))))), (( + (( + (( + 0.000000000000001) % ( + x))) | 0)) | 0)), ( + (( ~ ((( + (( - y) , x)) ? 1/0 : (( + Math.max(( ! y), (y >>> 0))) >>> 0)) | 0)) >>> 0))); }); testMathyFunction(mathy4, [0, ({valueOf:function(){return 0;}}), (new Boolean(true)), (new Number(-0)), ({valueOf:function(){return '0';}}), NaN, (new Number(0)), (new String('')), objectEmulatingUndefined(), '0', [0], (function(){return 0;}), '\\0', '/0/', (new Boolean(false)), undefined, ({toString:function(){return '0';}}), '', /0/, null, true, 1, 0.1, -0, false, []]); ");
/*fuzzSeed-204645237*/count=1429; tryItOut("Array.prototype.sort.call(a1);");
/*fuzzSeed-204645237*/count=1430; tryItOut("/*infloop*/L:for(var arguments in (let (x, x, eval, frlfuw, x) NaN--)( /x/ , /*FARR*/[[[]]].some(offThreadCompileScript, (4277)))) with({}) for(let w in []);");
/*fuzzSeed-204645237*/count=1431; tryItOut("\"use strict\"; print(s2);");
/*fuzzSeed-204645237*/count=1432; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\b)*?\\d\\s(?!(?!\\d){2,2}^{3,7}+?*)(?:\ua8cc(?=.[]|(?:\\B\\B)))+?/ym; var s = NaN =  /x/g  * x; print(s.match(r)); ");
/*fuzzSeed-204645237*/count=1433; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    return ((((0xffffffff) != (((i2)+((((0xcb5aeb90))>>>((0xffffffff))))+((((0xff35ce16))>>>((0xa2ece809)))))>>>(-0x41f11*(/*FFI*/ff(((~~(+atan2(((-281474976710656.0)), ((131073.0)))))))|0))))+(i2)-(i4)))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[[], [], -0x5a827999, [], -0x5a827999, -0x5a827999, [], [], x, [], x, x, -0x5a827999, x, x, -0x5a827999, -0x5a827999, [], x, [], -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, [], [], [], [], [], x, -0x5a827999, [], x, [], -0x5a827999, x, [], [], x, x, x, -0x5a827999, -0x5a827999]); ");
/*fuzzSeed-204645237*/count=1434; tryItOut("\"use asm\"; print({} = {});");
/*fuzzSeed-204645237*/count=1435; tryItOut("this.a1 = o1.a2.slice(NaN, NaN, g2);");
/*fuzzSeed-204645237*/count=1436; tryItOut("{ void 0; try { startgc(3732, 'shrinking'); } catch(e) { } } a1 = new Array;");
/*fuzzSeed-204645237*/count=1437; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = g1.s1; print(s.match(r)); ");
/*fuzzSeed-204645237*/count=1438; tryItOut("z = (x);Object.prototype.watch.call(e1, 0, this.o0.f2);");
/*fuzzSeed-204645237*/count=1439; tryItOut("\"use strict\"; print(null);");
/*fuzzSeed-204645237*/count=1440; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - (( + ( + ( + Math.cbrt(x)))) | 0)); }); testMathyFunction(mathy2, [Math.PI, -(2**53-2), -1/0, Number.MIN_VALUE, 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, 42, -0x080000001, -(2**53+2), 2**53-2, 1.7976931348623157e308, -0, -0x080000000, 1/0, -(2**53), -0x0ffffffff, 1, Number.MAX_VALUE, -0x100000000, -0x07fffffff, 0x07fffffff, 2**53+2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, -0x100000001]); ");
/*fuzzSeed-204645237*/count=1441; tryItOut("\"use strict\"; m0.has(b2);");
/*fuzzSeed-204645237*/count=1442; tryItOut("v1 = 4.2;");
/*fuzzSeed-204645237*/count=1443; tryItOut("\"use strict\"; t1[19] = this.__defineGetter__(\"e\", (eval =  \"\" ));");
/*fuzzSeed-204645237*/count=1444; tryItOut("testMathyFunction(mathy2, [-0x100000001, Number.MAX_VALUE, 0x0ffffffff, 0/0, 0, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53+2, 2**53, -(2**53+2), -0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, 0x080000001, 0x100000000, 1.7976931348623157e308, 1, -0x080000000, -0x080000001, 0x080000000, -(2**53-2), -0x0ffffffff, -(2**53), 0.000000000000001, -0x100000000, -Number.MIN_SAFE_INTEGER, 42]); ");
/*fuzzSeed-204645237*/count=1445; tryItOut("t2 = g0.t0.subarray(10);");
/*fuzzSeed-204645237*/count=1446; tryItOut("i0.send(v1);");
/*fuzzSeed-204645237*/count=1447; tryItOut("var vkrcvw = new ArrayBuffer(16); var vkrcvw_0 = new Uint32Array(vkrcvw); print(vkrcvw_0[0]); vkrcvw_0[0] = 929670067.5; var vkrcvw_1 = new Uint8ClampedArray(vkrcvw); print(vkrcvw_1[0]); vkrcvw_1[0] = 3; var vkrcvw_2 = new Uint8Array(vkrcvw); vkrcvw_2[0] = -3; var vkrcvw_3 = new Int16Array(vkrcvw); for (var p in b0) { try { Array.prototype.reverse.call(a1); } catch(e0) { } try { this.o0.valueOf = (function() { try { i1 + ''; } catch(e0) { } try { b1.__proto__ = m1; } catch(e1) { } try { t1 = new Uint32Array(b2); } catch(e2) { } Array.prototype.unshift.call(a1, f2,  \"\" , a0, o0, b0); return f0; }); } catch(e1) { } try { b0 = new ArrayBuffer(24); } catch(e2) { } h1 = o2; }print((vkrcvw_2[7] = [,]));print(e);o0.a0.pop(a1);print(vkrcvw);");
/*fuzzSeed-204645237*/count=1448; tryItOut("v0 = t0.length;");
/*fuzzSeed-204645237*/count=1449; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1|(?![^])?\\d/gyi; var s = \"\\u5e3d\\n\\u0006\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-204645237*/count=1450; tryItOut("mathy3 = (function(x, y) { return (((((Math.fround(Math.imul(( ! Math.acosh(x)), Math.fround(Math.hypot(y, Math.hypot(y, x))))) | 0) >>> (mathy0((( ! Math.fround((Math.fround(y) <= y))) | 0), (Math.max(( - x), (y | 0)) | 0)) | 0)) | 0) >= Math.fround((( + Math.fround(mathy1((y | 0), ( + x)))) & ( + ( ! (Math.hypot(y, Math.max((mathy0((y | 0), x) | 0), 0x0ffffffff)) >>> 0)))))) | 0); }); testMathyFunction(mathy3, [0.1, false, true, -0, '\\0', '0', [], (new Number(0)), ({valueOf:function(){return '0';}}), 0, (new Number(-0)), (new Boolean(false)), (function(){return 0;}), '', null, NaN, '/0/', /0/, (new Boolean(true)), [0], (new String('')), objectEmulatingUndefined(), ({toString:function(){return '0';}}), undefined, ({valueOf:function(){return 0;}}), 1]); ");
/*fuzzSeed-204645237*/count=1451; tryItOut("\"use strict\"; let (ttbvyr) { e2.add(this.e1); }");
/*fuzzSeed-204645237*/count=1452; tryItOut("function shapeyConstructor(wrrxrd){this[ '' ] = decodeURIComponent;this[\"getUTCMonth\"] = WeakMap;delete this[\"0\"];return this; }/*tLoopC*/for (let y of (true ? (function ([y]) { })() : -12)) { try{let skddft = new shapeyConstructor(y); print('EETT'); (new RegExp(\"([^\\\\W\\u00b0]\\\\B..{1,}|\\\\b**)\", \"\"));}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-204645237*/count=1453; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Math.PI, 0x100000000, 0x07fffffff, 1.7976931348623157e308, 0x080000001, -0x07fffffff, 2**53-2, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, Number.MAX_VALUE, -0x080000001, -(2**53), -0x100000001, 42, 0/0, -(2**53+2), 2**53, Number.MIN_SAFE_INTEGER, 1/0, -0, 0.000000000000001, -(2**53-2), 0, -0x100000000, 1, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=1454; tryItOut("a2.push(this.g1, p0, g0, m2, o1.f2, h1);");
/*fuzzSeed-204645237*/count=1455; tryItOut("for (var v of m2) { try { h2.hasOwn = (function() { try { for (var p in t2) { try { /*RXUB*/var r = r2; var s = \"\\n\"; print(r.test(s));  } catch(e0) { } try { for (var p in o1) { try { o0.t2.__proto__ = t0; } catch(e0) { } try { t2 + ''; } catch(e1) { } v0 = undefined; } } catch(e1) { } try { h0.delete = f1; } catch(e2) { } v2 = evalcx(\"for (var p in a1) { v2 = evalcx(\\\"function o2.f0(b2)  { yield (b2 = Proxy.createFunction(({/*TOODEEP*/})(\\\\\\\"\\\\\\\\uD72A\\\\\\\"), (function(x, y) { return -Number.MIN_SAFE_INTEGER; }), mathy2)) } \\\", g0); }\", g1); } } catch(e0) { } try { this.t0 = new Uint8Array(g1.t2); } catch(e1) { } a1[10] = (window >>= x); return e1; }); } catch(e0) { } t1[x]; }");
/*fuzzSeed-204645237*/count=1456; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1457; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (67108865.0);\n    d0 = (-524287.0);\n    i1 = (i1);\n    i1 = (-0x8000000);\n    (Float32ArrayView[((0x59958cf7)) >> 2]) = ((-1.001953125));\n    i1 = (((Float32ArrayView[((!(((((0x87b972aa)*0xfffff)>>>((/*FFI*/ff(((262145.0)), ((1.5474250491067253e+26)), ((3.094850098213451e+26)), ((1.5111572745182865e+23)), ((1.888946593147858e+22)), ((3.022314549036573e+23)), ((16777215.0)), ((-70368744177665.0)), ((536870912.0)), ((257.0)), ((-8589934591.0)))|0)))) ? ((imul((0xe2743e3c), (0xe7af0ab7))|0) < (-0x8000000)) : (((i1)) ? (0xffffffff) : ((2251799813685248.0) <= (-0.0078125)))))) >> 2])));\n    d0 = (2.3611832414348226e+21);\n    d0 = (-((+abs(((d0))))));\n    return +((d0));\n  }\n  return f; })(this, {ff: WeakMap.prototype.delete}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, -0x080000000, -0, -0x0ffffffff, 0x080000001, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, Number.MAX_VALUE, 1, 2**53, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, 0x07fffffff, 42, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 1.7976931348623157e308, 2**53+2, 0/0]); ");
/*fuzzSeed-204645237*/count=1458; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + ( ! (( + Math.min((Math.imul(Math.fround((Math.fround(x) >> ( ~ y))), ((Math.fround(x) >> (mathy1(x, 0x100000000) >>> 0)) >>> 0)) >>> 0), (( + ( + ( + ((Math.exp((x | 0)) | 0) - mathy1(x, y))))) >>> 0))) | 0))); }); testMathyFunction(mathy2, [-0x080000001, -1/0, 1/0, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), 1, 0, Math.PI, 0x080000000, 0x100000000, Number.MIN_VALUE, 0.000000000000001, 2**53, 0/0, 42, -0x100000000, -Number.MAX_VALUE, 2**53+2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), -0x07fffffff, -0x080000000, 0x100000001, 0x0ffffffff, -0, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-204645237*/count=1459; tryItOut("\"use strict\"; let (wtypfu, d = (/*MARR*/[new Boolean(false), true, {}, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), {}, new Boolean(false)].some)) { print(( ''  && x)); }");
/*fuzzSeed-204645237*/count=1460; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=1461; tryItOut("print(x);");
/*fuzzSeed-204645237*/count=1462; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.atan2((( + ((Math.cos((y >>> 0)) >>> 0) >>> 0)) >>> 0), ( ! Math.fround(Math.log10((Math.hypot(( + (((((( + ( + ( - -(2**53)))) / ( + x)) | 0) | 0) >> x) | 0)), x) >>> 0))))); }); ");
/*fuzzSeed-204645237*/count=1463; tryItOut("\"use asm\"; g1 = this;");
/*fuzzSeed-204645237*/count=1464; tryItOut("for(z =  /x/  in \"\\uF22B\") {v1 = NaN;/*wrap2*/(function(){ var yhfrax =  /x/ ; var pjyjrn =  /x/g ; return pjyjrn;})() }");
/*fuzzSeed-204645237*/count=1465; tryItOut("\"use strict\"; const x = (allocationMarker()).throw((void options('strict'))), [, , x, ] = eval >= z, x = x, w = timeout(1800), [\u3056, x] = x, haivqd, bxyveb, z = \u3056 = Proxy.createFunction(({/*TOODEEP*/})(-27), \"\u03a0\"), aivdek, e;o1.v1 = o2.g2[\"parseInt\"];");
/*fuzzSeed-204645237*/count=1466; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x080000001, -(2**53+2), -0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, 2**53-2, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 1, Number.MIN_VALUE, -0x080000001, -0x100000001, 42, 2**53+2, Math.PI, -1/0, 2**53, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, 0, 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -(2**53-2), -0x080000000]); ");
/*fuzzSeed-204645237*/count=1467; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.acosh((( + (Math.PI >>> 0)) | ( + ( + Math.fround((( + ( + (x | 0))) ? Math.fround(y) : Math.fround(Math.pow(-0x080000001, y))))))))); }); testMathyFunction(mathy2, [0, 1, Number.MAX_VALUE, 0x0ffffffff, -0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), 2**53, 1/0, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, 0x07fffffff, -(2**53), -Number.MIN_VALUE, -0x080000001, 2**53+2, -0x080000000, 0x100000000, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, -Number.MAX_VALUE, 2**53-2, 1.7976931348623157e308, 0/0, -0, 0x080000000]); ");
/*fuzzSeed-204645237*/count=1468; tryItOut("mathy4 = (function(x, y) { return (( + ( ! Math.fround(Math.log1p(( - ( + Math.sinh(x))))))) ? (( ~ (( - Math.max(x, Math.acosh(Math.fround(x)))) >>> 0)) >>> 0) : Math.max((x <= Math.max((( - ( + ( ~ ( + y)))) | 0), (1 | 0))), (Math.min(x, ((( - x) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy4, [false, ({valueOf:function(){return '0';}}), -0, [0], 1, '', ({valueOf:function(){return 0;}}), true, (new Boolean(true)), undefined, (new Number(-0)), (function(){return 0;}), objectEmulatingUndefined(), 0, '0', (new Boolean(false)), [], /0/, (new String('')), NaN, 0.1, '\\0', (new Number(0)), null, '/0/', ({toString:function(){return '0';}})]); ");
/*fuzzSeed-204645237*/count=1469; tryItOut("\"use asm\"; /*infloop*/do m1.set(h2, eval(\"/* no regression tests found */\", null)); while((4277));");
/*fuzzSeed-204645237*/count=1470; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + ( + Math.acosh((Math.hypot((Math.min(x, x) , x), (mathy0((Math.imul(y, x) | 0), x) | 0)) >>> 0)))) >= ( + Math.max(( + Math.pow(Math.tan((Math.cosh((y | 0)) | 0)), (( + (Math.min((Math.atan2(x, ( + Math.fround(Math.max(x, x)))) >>> 0), (Math.log2(0) >>> 0)) >>> 0)) >>> 0))), mathy1((Math.min(((Math.hypot(y, x) | 0) ^ y), (( ! (( + y) ? ( + Math.atan(x)) : Math.fround(( ! x)))) >>> 0)) >>> 0), ( + mathy1(( + mathy0((Math.fround(( - ( + (Math.expm1(y) >>> 0)))) >>> 0), x)), ((x | 0) == (( ! ( + y)) | 0))))))))); }); testMathyFunction(mathy2, [2**53+2, -0x080000000, -0, 0x07fffffff, Number.MAX_VALUE, 2**53, 0.000000000000001, 42, -0x080000001, -Number.MIN_VALUE, 1/0, 0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, -0x100000001, 0, -Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0x080000000, 0x080000001, -0x100000000, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -(2**53-2), Math.PI, 0x0ffffffff]); ");
/*fuzzSeed-204645237*/count=1471; tryItOut("\"use strict\"; v1 = (t2 instanceof e0);");
/*fuzzSeed-204645237*/count=1472; tryItOut("mathy1 = (function(x, y) { return (Math.expm1((Math.fround(Math.tanh(Math.fround((((((((Math.hypot(x, x) >>> 0) | 0) != Math.pow(Math.fround(( - (y >>> 0))), -0x0ffffffff)) | 0) >>> 0) ? (Math.fround((Math.fround(mathy0(x, ((Math.min((Number.MIN_SAFE_INTEGER | 0), y) | 0) >>> 0))) , (Math.min(y, x) | 0))) >>> 0) : (-1/0 >>> 0)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0.000000000000001, Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, Math.PI, 2**53-2, 0x07fffffff, -Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, -0x07fffffff, 0x080000001, 2**53, -0, 0x0ffffffff, 1, 0x100000001, -0x080000001, 0/0, -1/0, 0x100000000, 1/0, 1.7976931348623157e308, Number.MAX_VALUE, 2**53+2, 42, -(2**53-2)]); ");
/*fuzzSeed-204645237*/count=1473; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"gi\"); var s = \"\\n\\u00c8\\n\"; print(s.match(r)); ");
/*fuzzSeed-204645237*/count=1474; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.fround((mathy0((Math.sin(Math.sqrt(1)) | 0), (((( ~ (-0x080000000 >>> 0)) | 0) && Math.fround(Math.sign((Math.fround((y >>> 0)) >>> 0)))) | 0)) | 0)), Math.fround((((( + Math.fround(mathy0((mathy0(y, y) << y), -0x100000000))) >> (y >>> 0)) >>> 0) | Math.fround(Math.hypot(Math.fround(Math.ceil(( + (mathy0(((Number.MIN_SAFE_INTEGER >= (y >>> 0)) | 0), (y | 0)) | 0)))), ( ~ ((Math.pow(y, (x >>> 0)) >>> 0) > Math.log(x)))))))); }); testMathyFunction(mathy1, [0x100000001, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0x100000001, -(2**53+2), 1/0, -0x0ffffffff, 1.7976931348623157e308, 1, 0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x07fffffff, -0, 2**53, Number.MIN_SAFE_INTEGER, -(2**53), 42, Math.PI, 2**53+2, 2**53-2, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, 0x100000000, -Number.MIN_VALUE, -0x080000000, 0x080000001, -0x100000000]); ");
/*fuzzSeed-204645237*/count=1475; tryItOut("\"use strict\"; /*RXUB*/var r = /((?:(?![^]+?|\\3^?(?:$){33554432,})))/gy; var s = \"\"; print(s.replace(r, null(s, /*MARR*/[r, r, r, r, r, r, function(){}, r, function(){}, function(){}, r, r, function(){}, r, r, r, r, function(){}, function(){}, function(){}, r, r, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, r, function(){}, function(){}, r, function(){}, function(){}, function(){}, function(){}, r, r, r, r, function(){}, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, function(){}, r, r, r, function(){}, r, r, function(){}, function(){}, r, r, function(){}, r, r, r, r, r, r, function(){}, function(){}, function(){}, function(){}, r, function(){}, function(){}, function(){}, function(){}, r, function(){}, function(){}, r, r, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, r, function(){}, r, function(){}, function(){}, function(){}, function(){}].map))); ");
/*fuzzSeed-204645237*/count=1476; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x080000001, -0x100000001, 42, Number.MIN_VALUE, 1/0, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000000, 0x100000001, 0.000000000000001, 0x080000000, -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 2**53+2, -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, -0, Math.PI, 0, -0x07fffffff, 0x0ffffffff, 2**53-2, 0x07fffffff, 0/0, -(2**53+2), 1]); ");
/*fuzzSeed-204645237*/count=1477; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[(-0), (-0), (-0), x, x, (-0), (-0), x, x, (-0), (-0), (-0), x, (-0), x, (-0), (-0), x, x, x, x, x, x, x, (-0), (-0), x, x, x, (-0), x, x, x, (-0), x, (-0), (-0), x, x, x, (-0), x, x, x, x, (-0), (-0), x, x, (-0), x, (-0), x, (-0), x, (-0), x, (-0), x, x, (-0), x, (-0), x, x, (-0), x, x, (-0), x, x, x, (-0), x, x, x, (-0), x, x, (-0), (-0), (-0), (-0), (-0), (-0), (-0), x, x, (-0), (-0), (-0), x, (-0), (-0), (-0), x, x, (-0), x, (-0), x, (-0), (-0), x, x, (-0), x, x, (-0), x, x, (-0), x, (-0), (-0), (-0), (-0), x, x, (-0)]); ");
/*fuzzSeed-204645237*/count=1478; tryItOut("\"use strict\"; e2 = new Set(f0);");
/*fuzzSeed-204645237*/count=1479; tryItOut("mathy4 = (function(x, y) { return (Math.atan2((( ! ( - (((Math.log1p(Math.tan(-1/0)) | 0) <= x) | 0))) | 0), (Math.log10(( ! -0x100000000)) | 0)) | 0); }); testMathyFunction(mathy4, [2**53-2, -0x080000001, -(2**53-2), 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, 0, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff, 0x100000001, 0x07fffffff, Math.PI, -Number.MIN_VALUE, 0x100000000, 1, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -1/0, 0x080000001, Number.MIN_VALUE, -(2**53+2), -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 42, 2**53, Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-204645237*/count=1480; tryItOut("arguments = x;");
/*fuzzSeed-204645237*/count=1481; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, Number.MIN_VALUE, 0x100000001, Math.PI, 0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, -(2**53+2), -0x100000001, 1/0, -1/0, 2**53+2, -Number.MAX_VALUE, 0x080000000, 42, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, 0, -0x100000000, 2**53-2, -(2**53-2), -0x07fffffff, 0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53), -0, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, 0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1482; tryItOut("for (var v of v1) { try { for (var v of e1) { /*ODP-1*/Object.defineProperty(v0, \"9\", ({value: window.watch(16, String.prototype.toString), writable: true, configurable: (x % 2 == 0), enumerable: true})); } } catch(e0) { } try { o0[\"wrappedJSObject\"] = g2; } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(v0, o1); } catch(e2) { } s2 += 'x'; }");
/*fuzzSeed-204645237*/count=1483; tryItOut("v0 = evaluate(\"mathy3 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var ff = foreign.ff;\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    return +((-67108864.0));\\n  }\\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); \", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: (x % 29 == 17), noScriptRval: (x % 86 != 19), sourceIsLazy: window, catchTermination: true }));\nprint((Math.log1p((Math.fround(Math.max((x >>> 0), (42 >>> 0))) | 0)) | 0));\n");
/*fuzzSeed-204645237*/count=1484; tryItOut("\"use strict\"; ");
/*fuzzSeed-204645237*/count=1485; tryItOut("/* no regression tests found */");
/*fuzzSeed-204645237*/count=1486; tryItOut("\"use strict\"; m0.has(g0.a0);");
/*fuzzSeed-204645237*/count=1487; tryItOut("g1.o2.m0.get((makeFinalizeObserver('tenured')));");
/*fuzzSeed-204645237*/count=1488; tryItOut("delete h2.set;");
/*fuzzSeed-204645237*/count=1489; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0.000000000000001, -0x080000000, 0x0ffffffff, 0x100000001, 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1, -(2**53), 0/0, 2**53, 0x080000001, -0x100000001, Math.PI, -0x0ffffffff, 0x080000000, -0x080000001, 2**53-2, 42, 0x07fffffff, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, -0x07fffffff, 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-204645237*/count=1490; tryItOut("g0.e0.add(a1);");
/*fuzzSeed-204645237*/count=1491; tryItOut("mathy3 = (function(x, y) { return Math.pow(( + ( + Math.fround(((Math.min(mathy2(y, x), ( + ( ! y))) >>> 0) == Math.fround((Math.min((x | 0), mathy0(( + (-(2**53-2) >>> ( + -Number.MAX_VALUE))), 0.000000000000001)) | 0)))))), ((( ! (( + mathy2((( - ((( ! x) >>> 0) === Math.log10(0.000000000000001))) >>> 0), ((x !== x) >>> 0))) | 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy3, [0x080000001, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), 0x0ffffffff, -0x100000001, 1/0, 42, 0x100000000, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, Math.PI, 0x100000001, -Number.MIN_SAFE_INTEGER, 0/0, -0, -1/0, Number.MIN_VALUE, -0x07fffffff, 2**53, 0x07fffffff, -(2**53-2), -0x080000000, 2**53-2, 0x080000000, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, 0.000000000000001, 1, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE]); ");
/*fuzzSeed-204645237*/count=1492; tryItOut("testMathyFunction(mathy4, [objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 0.1, '', (new String('')), NaN, (new Number(-0)), 1, (new Boolean(true)), ({valueOf:function(){return '0';}}), null, undefined, false, ({toString:function(){return '0';}}), /0/, '/0/', -0, 0, [], '0', (new Boolean(false)), (function(){return 0;}), (new Number(0)), [0], '\\0', true]); ");
/*fuzzSeed-204645237*/count=1493; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( + Math.sin((Math.log1p(( + (Math.sin(( - x)) || (( + mathy2(Math.fround(mathy3(x, x)), (((y >>> 0) >> Number.MAX_VALUE) >>> 0))) >>> 0)))) >>> 0))) >>> 0) ? ( + ( + ( + Math.log(x)))) : (Math.max(Math.fround(Math.expm1(Math.fround(Math.min(Math.log1p(0.000000000000001), ( + Math.imul((x | 0), Math.fround(Math.round(-0x080000000)))))))), ( + ((x | 0) || ( + Math.pow((x ? ( + x) : (( + x) || -0x100000001)), 0x080000000))))) | 0)); }); testMathyFunction(mathy4, [-0x080000000, 0x0ffffffff, 1/0, 0x080000000, -0x080000001, 1.7976931348623157e308, 0/0, 0x100000000, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0, -0x100000000, 0.000000000000001, 2**53-2, -0x07fffffff, 0x080000001, 2**53+2, Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, 1, -0x100000001, -Number.MAX_VALUE, 0x100000001, 2**53]); ");
/*fuzzSeed-204645237*/count=1494; tryItOut("\"use strict\"; h0.__iterator__ = (function(j) { if (j) { try { v0 = evaluate(\"d = x;/*tLoop*/for (let z of /*MARR*/[(-1/0)]) { \\\"\\\\u7331\\\"; }\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce:  '' , noScriptRval: false, sourceIsLazy: false, catchTermination: true })); } catch(e0) { } /*MXX1*/o2 = g0.Object.setPrototypeOf; } else { try { /*MXX1*/this.o1 = this.g1.Map.prototype.entries; } catch(e0) { } try { a1 = a1.map((function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var tan = stdlib.Math.tan;\n  var imul = stdlib.Math.imul;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1099511627776.0;\n    {\n      d1 = (d0);\n    }\n    {\n      d2 = (d2);\n    }\n    d0 = (((-129.0)) - ((-0.001953125)));\n    d0 = (-147573952589676410000.0);\n    d2 = (+log(((+(1.0/0.0)))));\n    {\n      d0 = (d1);\n    }\n    {\n      {\n        d1 = (d0);\n      }\n    }\n    (Uint32ArrayView[1]) = (-0x90364*(-0x175b79d));\n    {\n      d0 = (((+tan(((+(-1.0/0.0)))))) * (((d1) + (d0))));\n    }\n    (Float64ArrayView[0]) = ((d1));\n    d1 = (d0);\n    return (((imul((0xffc6afe9), (0xffffffff))|0) % (\n(4277))))|0;\n  }\n  return f; }), o1); } catch(e1) { } s1 += 'x'; } });");
/*fuzzSeed-204645237*/count=1495; tryItOut("a0.shift(h1, v1);");
/*fuzzSeed-204645237*/count=1496; tryItOut("var mjaycz = new SharedArrayBuffer(16); var mjaycz_0 = new Uint8Array(mjaycz); mjaycz_0[0] = 1; (17);");
/*fuzzSeed-204645237*/count=1497; tryItOut("f2 = t1[({valueOf: function() { ;return 19; }})];");
/*fuzzSeed-204645237*/count=1498; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.imul(( + Math.imul(( + (Math.trunc(Math.log(x)) | 0)), ( + Math.fround(x)))), Math.max((y && x), ( ! ( + (y + 2**53-2)))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, -1/0, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 2**53-2, -(2**53), 42, -0x07fffffff, -0x080000000, 0, 0x080000000, 0x100000000, -Number.MIN_VALUE, -0x100000001, -(2**53+2), -Number.MAX_VALUE, 2**53+2, -0x080000001, -(2**53-2), 1.7976931348623157e308, 0.000000000000001, Math.PI, -0, 1, 0x100000001, Number.MAX_VALUE, 2**53, 0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1499; tryItOut("\"use strict\"; a2 = a1.filter((function() { a1.unshift(o1.i1); throw t0; }));");
/*fuzzSeed-204645237*/count=1500; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + mathy4(( + ( - ( + ( + ( + ( + Math.clz32(( + (Math.sin((Math.atan2(Math.PI, y) | 0)) | 0))))))))), ( - (Math.sqrt((Math.min((( ~ Math.fround(x)) | 0), (Math.imul((( ~ x) >>> 0), (x >>> 0)) >>> 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy5, [(new Number(0)), /0/, 1, '', ({valueOf:function(){return 0;}}), 0.1, (new String('')), NaN, objectEmulatingUndefined(), '/0/', '0', [0], [], 0, false, ({valueOf:function(){return '0';}}), null, (new Boolean(false)), undefined, ({toString:function(){return '0';}}), (new Number(-0)), (new Boolean(true)), (function(){return 0;}), -0, true, '\\0']); ");
/*fuzzSeed-204645237*/count=1501; tryItOut("/*RXUB*/var r = /\\2{0}/gym; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-204645237*/count=1502; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(mathy1((Math.fround((( + Math.trunc(( + x))) == Math.fround(( + (( ! Math.fround(y)) < ( + -0x100000001)))))) ^ y), (mathy0(Math.sqrt(mathy1(y, (Math.round(x) >>> 0))), y) ? mathy0(Math.trunc(Math.acos(x)), y) : mathy1(((( ! Math.fround(42)) >>> 0) | 0), (Math.pow((x ? y : 42), x) | 0))))) > Math.hypot(( + Math.log(( ! ((mathy1(y, y) >= (( ~ Math.max(y, y)) >>> 0)) >>> 0)))), (( + (( + (Math.min(( - y), ((( + (y | 0)) | 0) | 0)) | 0)) >= ( + Math.min(((x ** (y | 0)) | 0), -Number.MIN_SAFE_INTEGER)))) >>> 0)))); }); testMathyFunction(mathy2, [-0x080000001, 0x080000001, Math.PI, -0x080000000, 2**53, 0x080000000, 42, 0x100000000, 1/0, 1, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, -Number.MAX_VALUE, -(2**53-2), 0, -Number.MAX_SAFE_INTEGER, -0, 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, -Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, -0x100000000, 0/0, 0.000000000000001, -(2**53), -1/0]); ");
/*fuzzSeed-204645237*/count=1503; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ! (Math.imul((((y ** Math.max(Math.fround(mathy0((2**53 | 0), Math.fround(-Number.MIN_VALUE))), 0x0ffffffff)) == Math.fround(Math.atan2(Math.fround(Math.min(-0x080000001, Math.imul(y, Math.fround(y)))), Math.exp(( + -0x100000001))))) >>> 0), (Math.fround(Math.atan((y | 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0x07fffffff, 0/0, 2**53, -(2**53), -0x080000000, 0x07fffffff, 0, -(2**53-2), 0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, -(2**53+2), 0.000000000000001, -0x100000000, 1, 2**53+2, -0x0ffffffff, 0x080000000, 0x080000001, -0, 2**53-2, Number.MIN_VALUE, 1/0, Math.PI, -Number.MAX_VALUE, 42, 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1504; tryItOut("\"use strict\"; /*oLoop*/for (mgqkoy = 0; mgqkoy < 14 && (true); ++mgqkoy) { y; } ");
/*fuzzSeed-204645237*/count=1505; tryItOut("x = linkedList(x, 284);");
/*fuzzSeed-204645237*/count=1506; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log1p((Math.fround(Math.pow(Math.fround(mathy1(mathy1(x, Math.max((( ~ (y | 0)) | 0), y)), ((y ? (x / x) : Math.fround((Math.fround(x) > Math.fround(x)))) | 0))), Math.fround(-Number.MIN_VALUE))) | Math.fround(( + Math.fround((mathy1((( + mathy1((( ! ( + x)) | 0), ( + x))) | 0), ((mathy2(Math.min(Math.expm1(( + x)), -0x07fffffff), (x >>> 0)) | 0) | 0)) >>> 0)))))); }); ");
/*fuzzSeed-204645237*/count=1507; tryItOut("\"use strict\"; print(s1);");
/*fuzzSeed-204645237*/count=1508; tryItOut("sumyzv();/*hhh*/function sumyzv({y}, x){/*RXUB*/var r = /\\u0085|(?:\\u006C\\\u242e)?|(?=.+?.)+\\1+?|\\u00b5+?[\u00d0-\u0088\\cJ]+?|[^]*?/gyi; var s = \"\"; print(s.search(r)); }");
/*fuzzSeed-204645237*/count=1509; tryItOut("((makeFinalizeObserver('tenured')));");
/*fuzzSeed-204645237*/count=1510; tryItOut("\"use strict\"; v2 = true;");
/*fuzzSeed-204645237*/count=1511; tryItOut("b = -Infinity;g1.a0 = this.r0.exec(s0);");
/*fuzzSeed-204645237*/count=1512; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround((Math.fround((x >>> Math.fround((Math.fround(0x080000001) ? 0/0 : Math.fround(( ! y)))))) ? ( + (( + (Math.fround((Math.log10((x | 0)) | 0)) / ( + (( + x) >>> 0)))) ? mathy1((y !== y), 1) : ( + (((((x >>> 0) ? mathy0(( + Math.fround(( + x))), y) : (x >>> 0)) >>> 0) + (y >>> 0)) >>> 0)))) : (Math.abs(y) | 0))) ** Math.fround((Math.fround(( - Math.fround((( + y) == Math.fround(mathy1((Math.fround((y & Math.fround(2**53-2))) | 0), Math.hypot((0x0ffffffff | 0), (x | 0)))))))) * ( - (((x > x) , Math.fround(y)) >>> 0))))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1), -0x080000000, undefined, undefined, new Number(1), undefined, -0x080000000, undefined, {x:3}, new Number(1), undefined, -0x080000000, undefined, -0x080000000, {x:3}, {x:3}, undefined, undefined, {x:3}, {x:3}, new Number(1), -0x080000000, -0x080000000, -0x080000000, {x:3}, new Number(1), {x:3}]); ");
/*fuzzSeed-204645237*/count=1513; tryItOut("f1.toSource = (function(j) { f1(j); });");
/*fuzzSeed-204645237*/count=1514; tryItOut("m0.has(f0);");
/*fuzzSeed-204645237*/count=1515; tryItOut("\"use strict\"; a0.forEach();");
/*fuzzSeed-204645237*/count=1516; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\S\", \"gm\"); var s = \"0\"; print(r.test(s)); ");
/*fuzzSeed-204645237*/count=1517; tryItOut("\"use strict\"; f0 = f0;");
/*fuzzSeed-204645237*/count=1518; tryItOut("\"use strict\"; s0 += s1;");
/*fuzzSeed-204645237*/count=1519; tryItOut("\"use strict\"; for (var v of o2.t2) { try { a1 = a0.filter((function(j) { if (j) { try { t0[8] = x; } catch(e0) { } g1.i1 + o1.g2; } else { try { a2.unshift(a1, g0, p0, f1); } catch(e0) { } try { o2.o2.s0 = Array.prototype.join.apply(a0, [s2, o2.t2, o0, h1, o2.b1, v1, e2, o1]); } catch(e1) { } try { v2 = -0; } catch(e2) { } g1 + ''; } }), h1, a2); } catch(e0) { } try { a1 = a2.concat(this.t1, this.a0); } catch(e1) { } try { o0.a0.length = 12; } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(o1.o0.v1, h2); }");
/*fuzzSeed-204645237*/count=1520; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -4503599627370497.0;\n    d2 = (d2);\n    switch ((abs((~((i1))))|0)) {\n      default:\n        i1 = (0xf3be1184);\n    }\n    {\n      d2 = (-295147905179352830000.0);\n    }\n    return (((0xf24aca05) % (0xe492e052)))|0;\n    i1 = (0x857f0124);\n;    i1 = ((0xd8c9cc5d) > ((((4277))-(0xfb2bfd1e))>>>((((0xffd4a1ff)-(0x517851fd)-(0xe715be3e))>>>(((0xeae8f89) == (0xb4ddea04)))) % (((i1)-(-0x2cc1037))>>>((0x9a62bbb8) / (0xf9de35a8))))));\n    return (((0xffffffff) % ((-((Uint16ArrayView[4096])))>>>(((new function(y) { yield y; v1 = (i1 instanceof p0);; yield y; }(x, this)))))))|0;\n  }\n  return f; })(this, {ff: ((function(x, y) { \"use strict\"; return Math.pow(-0x080000001, -(2**53-2)); })).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), false, false, false, objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), false, new String('q'), new String('q'), new String('q'), new String('q'), false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), new String('q'), false, new String('q'), new String('q'), false, objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), false, new String('q'), false, new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), false, false, new String('q'), new String('q'), new String('q'), false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), false, new String('q'), new String('q'), false, false, new String('q'), false, new String('q'), new String('q'), false, new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), false, objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), false, new String('q'), false, false, new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), false, new String('q'), objectEmulatingUndefined(), new String('q'), false, new String('q'), false, false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, new String('q'), false, objectEmulatingUndefined(), new String('q'), false, false, false, objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), false, false, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), false]); ");
/*fuzzSeed-204645237*/count=1521; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    switch (((((Float32ArrayView[1]))-((0x8947e3d5))) ^ (((0x251ec387))+((0xbbf3884c))))) {\n      case -3:\n        (Float64ArrayView[((((function a_indexing(heasbk, pikbys) { ; if (heasbk.length == pikbys) { ; return ((heasbk) = window =  '' ); } var qihqae = heasbk[pikbys]; var lmjvfj = a_indexing(heasbk, pikbys + 1); return /*MARR*/[-3, new Boolean(false), new Boolean(false), -3, new Boolean(false), new Boolean(false), -3, new Boolean(false), -3, -3, new Boolean(false), -3, -3, -3, new Boolean(false), -3, -3, new Boolean(false), new Boolean(false), -3, new Boolean(false), -3, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -3, -3, -3, -3, -3, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -3, -3, -3, -3, new Boolean(false), new Boolean(false), new Boolean(false)]; })(/*MARR*/[(void options('strict')), (void options('strict')), w * z, (void options('strict')), w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, w * z, function(){}, (void options('strict')), w * z, w * z, function(){}, function(){}, w * z, (void options('strict')), function(){}, function(){}, function(){}, (void options('strict')), function(){}, function(){}, function(){}, w * z, function(){}, function(){}, function(){}, w * z, function(){}, function(){}, w * z, w * z, function(){}, (void options('strict')), w * z, (void options('strict')), (void options('strict')), w * z, function(){}, w * z, (void options('strict')), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, w * z, function(){}], 0)))+(i0)) >> 3]) = ((+atan2(((NaN)), ((+(((-0x8000000)) << ((w = \"\\u8DC0\"))))))));\n        break;\n    }\n    (Uint8ArrayView[(((((0xfba1cf08)+(0xf6da5358)-(0x49898dcb)) << ((Int32ArrayView[0]))))+(/*FFI*/ff(((((0x57b9bb60)))), ((-0x8000000)), ((((0xfb37fba6)) | ((0xee7d4ae6)))), ((1.0078125)), ((-137438953473.0)))|0)+(i0)) >> 0]) = ((i0)+(!(-0x8000000)));\n    d1 = (4611686018427388000.0);\n    /*FFI*/ff(((abs((imul((0x7f2a34de), (i0))|0))|0)));\n    d1 = (72057594037927940.0);\n    return (((((~~(d1)) % (~~(-((-4398046511105.0))))))+((0xd93366d7) ? (0xbaf3fd7f) : (0xeb126750))-((0xf023dbed) >= (0x83b678f9))))|0;\n  }\n  return f; })(this, {ff: (Object.values).bind(x, x = Proxy.createFunction(({/*TOODEEP*/})( '' ), runOffThreadScript) - a =  /x/g )}, new ArrayBuffer(4096)); testMathyFunction(mathy0, \"25\"); ");
/*fuzzSeed-204645237*/count=1522; tryItOut("/*oLoop*/for (vsetpt = 0; vsetpt < 27; ++vsetpt) { i0 = new Iterator(a0, true); } ");
/*fuzzSeed-204645237*/count=1523; tryItOut("t2[2];");
/*fuzzSeed-204645237*/count=1524; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204645237*/count=1525; tryItOut("\"use strict\"; e2.delete(p1);");
/*fuzzSeed-204645237*/count=1526; tryItOut("\"use strict\"; i0.send(a1);");
/*fuzzSeed-204645237*/count=1527; tryItOut("-0.937.eval(\"selectforgc(o2);\");/*");
/*fuzzSeed-204645237*/count=1528; tryItOut("mathy5 = (function(x, y) { return Math.atanh(((((( + (( + y) - ( + -0x100000001))) | 0) != (mathy3(( ~ y), y) >>> 0)) | 0) >>> 0)); }); testMathyFunction(mathy5, [-0, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -(2**53+2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, 42, 0.000000000000001, 0x07fffffff, -(2**53), 0x100000000, 1/0, -0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, 0x080000001, 0/0, 2**53-2, 0x100000001, -0x080000001, Number.MIN_VALUE, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, 2**53+2]); ");
/*fuzzSeed-204645237*/count=1529; tryItOut("mathy1 = (function(x, y) { return (Math.abs(Math.fround(Math.trunc(Math.fround(x)))) && (Math.imul(((mathy0(y, x) ? (Math.max((mathy0((( + ( ~ -0x080000001)) >>> 0), Math.fround((Math.fround(y) * y))) >>> 0), y) | 0) : ( ~ Math.cos((0x100000001 <= -0x0ffffffff)))) | 0), (Math.fround(mathy0(Math.trunc(x), Math.fround((x >= ( + x))))) | 0)) | 0)); }); testMathyFunction(mathy1, [-(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 42, 0.000000000000001, 0x080000001, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, -0x080000000, -(2**53-2), 1, 2**53-2, Math.PI, Number.MAX_VALUE, 1/0, -1/0, 2**53, 1.7976931348623157e308, -0x07fffffff, 0x100000000, -0x0ffffffff, 0x0ffffffff, -0x100000001, 0x07fffffff, 0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, 2**53+2]); ");
/*fuzzSeed-204645237*/count=1530; tryItOut("mathy4 = (function(x, y) { return mathy1(Math.cos(Math.fround(( - (Math.max(x, ( + y)) | 0)))), (( ! Math.sinh(y)) + Math.fround(Math.log10(y)))); }); testMathyFunction(mathy4, [0x080000000, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, Number.MIN_VALUE, -0x080000001, -1/0, 0/0, 0.000000000000001, 2**53, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, Math.PI, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, 2**53+2, 0, 0x080000001, 1, -0x0ffffffff, -(2**53-2), 1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0]); ");
/*fuzzSeed-204645237*/count=1531; tryItOut("(true);");
/*fuzzSeed-204645237*/count=1532; tryItOut("t1 = new Uint8Array(b2, 120, ({valueOf: function() { var a = [1,,];print(o0.b1);return 5; }}));");
/*fuzzSeed-204645237*/count=1533; tryItOut("o0 = x;");
/*fuzzSeed-204645237*/count=1534; tryItOut("b1.__proto__ = o0;");
/*fuzzSeed-204645237*/count=1535; tryItOut("with(Math.min(/*MARR*/[ /x/ , function(){},  /x/ , function(){}, function(){}, function(){}, function(){}, (0/0),  \"use strict\" , function(){},  /x/ , function(){}, function(){}, function(){},  \"use strict\" , (0/0),  /x/ ,  /x/ , function(){},  \"use strict\" , (0/0), (0/0),  \"use strict\" ,  /x/ , (0/0), function(){},  /x/ , function(){},  /x/ ,  /x/ ,  /x/ , (0/0), (0/0), (0/0), function(){},  /x/ , function(){},  \"use strict\" , (0/0), (0/0), (0/0),  /x/ ,  \"use strict\" ,  /x/ , function(){},  /x/ , (0/0),  \"use strict\" ,  /x/ ,  /x/ ,  /x/ , function(){}, function(){},  /x/ ,  \"use strict\" , (0/0),  \"use strict\" ,  \"use strict\" , function(){}, (0/0), function(){}, function(){},  \"use strict\" ,  /x/ , (0/0), (0/0), function(){},  /x/ , (0/0)].sort(Uint16Array, z = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), Object, Function)), Math.min(0.049, x = Proxy.createFunction(({/*TOODEEP*/})(-1), String.prototype.small))))print(x);");
/*fuzzSeed-204645237*/count=1536; tryItOut(";for (var p in s2) { try { v0 = Object.prototype.isPrototypeOf.call(h2, i2); } catch(e0) { } try { function f0(f0)  { \"use strict\"; a1 = Array.prototype.concat.call(this.a1, t2, p2, o0, e0, p1); }  } catch(e1) { } a0.shift(h1, this.g2.e2, p2, this.f1, g1.v0, a0); }var z = ({x: (/*RXUE*/new RegExp(\"\\\\1\", \"yim\").exec(\"\\u0093#\\n\\u0093#\\u0093#\\u0093#\\n\\u0093#\\u0093#\\u0093#\\n\\n\\n\"))});");
/*fuzzSeed-204645237*/count=1537; tryItOut("for(let z in []);let(c) ((function(){return (function (eval, e, x, x = null, x, eval, w =  /x/g , x =  /x/ , d, a, eval, c, window, x =  /x/ , x, apply, c, d, c =  '' , d, z, x, w, x, x, b, e, NaN, x = true, x, c, window, y, c, c, \u3056, c, c, c = false, z, x, x, c, c, a, y, 27 = 29, c) { \"use strict\"; return \"\\uE049\" } ).call(/(?!.\u0088|[^]|.|(.)|[^]|[^]$\\B\\b*?)?|(\u330c|((?!^)){1,4})/yim, (function ([y]) { })());})());");
/*fuzzSeed-204645237*/count=1538; tryItOut("let c = -12.eval(\"\\\"\\\\u39F6\\\"\"), x, nxqjoi, eval, yrlawl, edpxwi, b, nqljbe, ogsudw, wighbq;print(window);");
/*fuzzSeed-204645237*/count=1539; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.max(Math.atanh(Math.hypot(Math.sinh(x), ( ~ y))), ( + (Math.fround(( + ( - mathy0(Math.fround(x), (0x100000000 | 0))))) === ( + ( ~ ( + Math.log2(Math.min(mathy2(Math.fround(y), 0x0ffffffff), x)))))))); }); testMathyFunction(mathy4, /*MARR*/[x,  /x/g , x,  /x/g , x, x, x,  /x/g , x, x,  /x/g , x, x, x, x,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g , x, x, x, x, x, x, x, x, x, x, x,  /x/g ,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g , x, x, x,  /x/g ,  /x/g ,  /x/g , x, x, x, x, x, x, x, x, x, x, x,  /x/g , x,  /x/g ]); ");
/*fuzzSeed-204645237*/count=1540; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot(((( ! y) <= Math.acosh(-0x080000000)) | 0), (Math.max(((Math.log((( ~ y) >>> 0)) | 0) ? Math.atan2(x, (x && Math.fround(x))) : mathy1(Math.asinh(y), Math.hypot(Number.MAX_VALUE, ((Math.pow((((y >>> 0) !== y) >>> 0), (x >>> 0)) >>> 0) >>> 0)))), Math.atan2((( + (0/0 | 0)) | 0), 1/0)) >>> 0)); }); testMathyFunction(mathy3, [null, '0', objectEmulatingUndefined(), undefined, 0.1, 0, NaN, ({toString:function(){return '0';}}), /0/, 1, '/0/', ({valueOf:function(){return 0;}}), (function(){return 0;}), true, (new Boolean(false)), -0, '', ({valueOf:function(){return '0';}}), (new Number(-0)), (new Boolean(true)), [], (new Number(0)), [0], false, (new String('')), '\\0']); ");
/*fuzzSeed-204645237*/count=1541; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return (Math.log1p(mathy1(Math.fround(((y * x) >= (Math.cos((y | 0)) | 0))), ((-(2**53-2) >= ( + x)) >>> 0))) >> (Math.acosh(y) / (Math.sign(Math.atan(( + x))) | 0))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, 2**53-2, 0x080000001, 1, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, -0, -(2**53+2), -0x080000001, -0x100000001, 2**53, 0x080000000, 2**53+2, -0x0ffffffff, 42, 0x100000001, Number.MAX_VALUE, Math.PI, -(2**53), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, -1/0, -(2**53-2), 1.7976931348623157e308, 0/0]); ");
/*fuzzSeed-204645237*/count=1542; tryItOut("M:if(false) { if (( /* Comment */(void version(170)))) {v0 = (i0 instanceof this.h2);x = h1; }} else {for (var p in g2.o0.h1) { try { v0 = g2.runOffThreadScript(); } catch(e0) { } f1 = Proxy.createFunction(h0, f0, f2); }print((new x(-23,  \"\" ))); }");
/*fuzzSeed-204645237*/count=1543; tryItOut("this.o2.i1.toSource = Array.prototype.every.bind(this.a2);");
/*fuzzSeed-204645237*/count=1544; tryItOut("\"use strict\"; /*infloop*/for(var z; (/*UUV1*/(x.toString = this.__defineSetter__(\"x\", function(y) { yield y; this.v1 = a2.length;; yield y; }))); (4277)) {v2 = t2.byteLength;yield; }");
/*fuzzSeed-204645237*/count=1545; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy1(Math.pow(( + (( + Math.pow(( ~ (arguments.callee.caller && y)), ( + Math.fround((Math.fround(x) ** Math.fround(x)))))) >>> 0)), (( - ( + ((( + Math.exp(x)) >> -(2**53+2)) && ( + y)))) >>> 0)), (Math.clz32((( + Math.sign(( + x))) >= ( + ( + (-(2**53+2) >>> 0))))) >>> 0)); }); testMathyFunction(mathy3, [42, -(2**53-2), 0, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0x0ffffffff, 2**53+2, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -0x080000001, 0x080000000, -0, -0x080000000, 0x100000001, Number.MIN_VALUE, 1, Math.PI, 2**53-2, 2**53, 0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, -(2**53+2), 0x07fffffff]); ");
/*fuzzSeed-204645237*/count=1546; tryItOut("mathy4 = (function(x, y) { return Math.expm1((Math.imul(Math.fround(Math.log((Math.fround(Math.sin(Math.atan2(y, ( ! (((y | 0) === (y | 0)) | 0))))) >>> 0))), (( + Math.fround((( + y) >>> 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, -0x100000000, -(2**53), 1/0, 2**53+2, 42, 0x080000001, -(2**53+2), Number.MAX_VALUE, -0x080000000, -0x080000001, Number.MIN_VALUE, -(2**53-2), 2**53-2, 2**53, -Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, -0x0ffffffff, -0, 0.000000000000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, 0x080000000, -0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 0, 0/0, Math.PI]); ");
/*fuzzSeed-204645237*/count=1547; tryItOut("mathy4 = (function(x, y) { return ( + (Math.log10((( + Math.cbrt(( + (Math.sinh((Math.hypot(x, x) | 0)) | 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-0x080000001, 2**53-2, 1.7976931348623157e308, 1/0, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 0x07fffffff, -(2**53-2), 0x080000001, 2**53+2, Number.MIN_VALUE, 0x100000000, -1/0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 2**53, 42, 1, -0, -(2**53), Math.PI, -Number.MAX_SAFE_INTEGER, 0, -(2**53+2), 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204645237*/count=1548; tryItOut("with({w: (4277)}){print(this.m2);print(w); }");
/*fuzzSeed-204645237*/count=1549; tryItOut("\"use strict\"; Object.prototype.watch.call(v0, \"toSource\", (function() { try { v0 = Object.prototype.isPrototypeOf.call(i2, a1); } catch(e0) { } Object.defineProperty(this, \"g2.g0.t2\", { configurable: false, enumerable: (x % 5 != 3),  get: function() {  return new Float32Array(b0); } }); return this.m0; }));\nh2.iterate = (function(a0, a1, a2, a3, a4, a5, a6) { a1 = a1 ^ 2; a1 = a1 % a4; var r0 = x / x; var r1 = a5 % x; var r2 = a5 | 0; a0 = 6 * 7; var r3 = 8 + a4; var r4 = a3 + 6; var r5 = r3 | r0; a0 = x & 8; print(a3); var r6 = 8 * r1; var r7 = a5 * r5; var r8 = a4 ^ 0; var r9 = a1 / a4; r7 = r3 / a3; var r10 = r8 % r2; var r11 = r0 / 6; a4 = a2 * r5; var r12 = a0 ^ a1; r9 = 5 | a1; var r13 = 6 + r3; var r14 = r1 + r6; r2 = r5 / a6; r11 = 0 - x; var r15 = r8 % r13; var r16 = r15 * r4; var r17 = r0 ^ a0; var r18 = r16 / r14; var r19 = 4 - r5; var r20 = 7 | r1; var r21 = a2 & r7; r4 = 9 + 0; var r22 = x / a1; var r23 = 2 * 6; var r24 = r18 / r14; r16 = 3 % 6; a4 = r20 - 0; var r25 = r22 ^ r6; var r26 = 9 & 8; var r27 = r16 * 6; r3 = 8 - a2; var r28 = r24 / 7; return a6; });\n");
/*fuzzSeed-204645237*/count=1550; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.pow(Math.pow((((( + (( - (-0x07fffffff >>> 0)) >>> 0)) || Math.min((Math.PI | 0), (y | 0))) / (Math.hypot(-0x080000001, Math.fround(( ! ( + ( + 1/0))))) >>> 0)) >>> 0), (Math.sin((((Math.hypot(Math.sin(x), x) ^ ( + y)) | x) | 0)) | 0)), Math.max(Math.exp(y), ( + Math.round(( + (( ~ y) ** x)))))); }); testMathyFunction(mathy4, [0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, Math.PI, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, -(2**53+2), -0x080000001, 1/0, -Number.MAX_VALUE, 0x080000001, 0/0, 2**53-2, -0x0ffffffff, -0x07fffffff, 0, 0.000000000000001, -0, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 0x07fffffff, 1, Number.MIN_VALUE, 2**53, -(2**53-2), 42, Number.MAX_VALUE, 0x100000001, -0x080000000]); ");
/*fuzzSeed-204645237*/count=1551; tryItOut("/*bLoop*/for (var xelyzy = 0, eval; xelyzy < 16; ++xelyzy) { if (xelyzy % 5 == 1) { Object.defineProperty(this, \"o0\", { configurable: \"\\uF8C0\", enumerable: false,  get: function() {  return {}; } }); } else { ; }  } ");
/*fuzzSeed-204645237*/count=1552; tryItOut(";");
/*fuzzSeed-204645237*/count=1553; tryItOut("mathy2 = (function(x, y) { return ( + ( + mathy0(x, ( + ((( ! x) >= (-Number.MIN_VALUE | 0)) | 0))))); }); ");
/*fuzzSeed-204645237*/count=1554; tryItOut("mathy1 = (function(x, y) { return (((( ~ (( + Math.fround(( + (Math.fround(Math.cosh(Math.asinh(-0x080000000))) >> ( + ( ! ( ~ x))))))) | 0)) | 0) <= ((Math.abs(Math.fround((Math.pow(x, (Math.sqrt(0x100000001) | 0)) >>> 0))) > Math.clz32(( + y))) | 0)) | 0); }); testMathyFunction(mathy1, [[0], '/0/', /0/, '\\0', '0', true, '', ({toString:function(){return '0';}}), 1, ({valueOf:function(){return 0;}}), 0.1, (function(){return 0;}), (new Boolean(true)), false, -0, (new Boolean(false)), (new Number(-0)), objectEmulatingUndefined(), NaN, [], 0, ({valueOf:function(){return '0';}}), (new String('')), undefined, (new Number(0)), null]); ");
/*fuzzSeed-204645237*/count=1555; tryItOut("\"use strict\"; \"\\u89A4\" / function(id) { return id };\nprint(x);\n");
/*fuzzSeed-204645237*/count=1556; tryItOut("this.a0.sort(v1, g0.f0, m0, b1, v0);g0.h0 + '';");
/*fuzzSeed-204645237*/count=1557; tryItOut("\"use strict\"; a0.shift(i2);");
/*fuzzSeed-204645237*/count=1558; tryItOut("mathy0 = (function(x, y) { return (Math.max(((( ! Math.expm1(Math.fround((Math.fround((( ~ y) | 0)) ^ Math.fround(x))))) | 0) >>> 0), (-13 >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, 2**53+2, 0x080000000, 0x0ffffffff, 2**53-2, -0x080000001, 0x07fffffff, 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, 1, -0x100000000, -0x0ffffffff, Math.PI, 1/0, 2**53, -(2**53-2), 0, 0x100000000, -0x080000000, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000001, -1/0, -(2**53), -0, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=1559; tryItOut("\"use strict\"; while((x >>> this) && 0)let (okyimv, b, NaN, \u3056, x, dgdydr) { Array.prototype.push.call(o2.a0, p2, this.g2, s1); }");
/*fuzzSeed-204645237*/count=1560; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.round(Math.acos((y ? ( ~ ( + Number.MIN_SAFE_INTEGER)) : Math.atan(mathy4(x, Math.min((Math.hypot((y | 0), (x | 0)) | 0), 0.000000000000001)))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, 0x100000001, 42, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x07fffffff, -(2**53+2), 0x080000001, 0/0, -Number.MAX_VALUE, -0x100000001, 1, -0x100000000, -1/0, 0x07fffffff, 1/0, Number.MAX_VALUE, 0x0ffffffff, 0, 0x080000000, 0.000000000000001, -(2**53), Math.PI, -0x0ffffffff, -0]); ");
/*fuzzSeed-204645237*/count=1561; tryItOut("/*ADP-1*/Object.defineProperty(a0, this.v0, ({set: x = y, configurable: false}));");
/*fuzzSeed-204645237*/count=1562; tryItOut("t1[2];");
/*fuzzSeed-204645237*/count=1563; tryItOut("h1.has = f1;m0.set(m0, v2);function x(d, x) { yield  ''  } ( \"\" );");
/*fuzzSeed-204645237*/count=1564; tryItOut("\"use strict\"; print(x);(yield null);");
/*fuzzSeed-204645237*/count=1565; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul(Math.hypot((Math.pow(( + (((Math.atan2(-0x080000000, Math.atan2(x, -Number.MAX_SAFE_INTEGER)) | 0) === ((( + (Math.tan(((( ~ (y >>> 0)) | 0) >>> 0)) >>> 0)) >= mathy1((( + (Number.MAX_VALUE | 0)) >>> 0), 2**53+2)) | 0)) | 0)), (( + (( + x) >>> ( + x))) >>> 0)) >>> 0), Math.atan(x)), Math.fround(Math.min(Math.fround(Math.log1p(Math.fround(( + ((( + y) / ( + y)) | 0))))), ( + Math.trunc(( + Math.atan2(Number.MAX_VALUE, Math.fround(Math.sin(Math.atanh(( + y))))))))))); }); testMathyFunction(mathy2, [0x100000000, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, -1/0, 2**53+2, 2**53, -(2**53-2), -(2**53), Math.PI, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, 0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 42, -0, -0x100000001, -0x080000001, -Number.MAX_VALUE, -0x080000000, 2**53-2, -(2**53+2), -0x0ffffffff, 1/0]); ");
/*fuzzSeed-204645237*/count=1566; tryItOut("b2.toString = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((((i1)+(i0)) << (((imul((i1), (!(0x24292180)))|0))-(i1))))-(!(0xf819ed1a))))|0;\n    {\n      {\n        i0 = (i1);\n      }\n    }\n    i0 = (i0);\n    i1 = (1);\n    {\n      (Int32ArrayView[((i1)+((((0x1dda2310) / (-0x8000000))>>>((0xbb9eb8cf)-(0xffffffff)-(0xfeb5cd56))) < (((i0))>>>((0xae4ad9e2) / (0x942b4ea0))))) >> 2]) = ((1)+(!(i1)));\n    }\n    return ((((imul((i1), ((0xcb177cbf) != (((0xbdda96c2) % (0x92e17cf8))>>>((i0)-(i0)))))|0))-(i1)))|0;\n  }\n  return f; });");
/*fuzzSeed-204645237*/count=1567; tryItOut("\"use strict\"; Array.prototype.splice.call(a1, NaN, ((makeFinalizeObserver('tenured'))));");
/*fuzzSeed-204645237*/count=1568; tryItOut("o2 = t0[v1];");
/*fuzzSeed-204645237*/count=1569; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + mathy2(Math.imul((y < Math.fround(x)), ( ! ( + Math.round(-(2**53+2))))), ( + Math.sign(Math.sinh(Math.fround(( + Math.asin((-0 | 0))))))))); }); testMathyFunction(mathy4, [NaN, -0, objectEmulatingUndefined(), (new Number(0)), null, (new Boolean(false)), /0/, '0', false, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), [], '\\0', undefined, true, 1, ({toString:function(){return '0';}}), 0, '/0/', (new Number(-0)), '', 0.1, (function(){return 0;}), (new String('')), [0], (new Boolean(true))]); ");
/*fuzzSeed-204645237*/count=1570; tryItOut("\"use strict\"; \"use asm\"; for (var v of s1) { try { (void schedulegc(g2)); } catch(e0) { } try { m0.has(b0); } catch(e1) { } try { v0 = evaluate(\"e1.add(b1);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: false, element: o0, elementAttributeName: s2 })); } catch(e2) { } delete o2[\"add\"]; }");
/*fuzzSeed-204645237*/count=1571; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\ne0.add(f0);    return (((/*FFI*/ff(((((i1)-(i1)) >> (((((0x62839ce8))>>>((0x3d2f0a79))) != (0x471d317d))+(!(0x15f2a943))-((~~(137438953473.0)) < (((0x7cbde13b)) & ((0xe0b69777))))))), ((~~(6.044629098073146e+23))), (((((0xff3f0c8c) ? (-0x8000000) : (0xa90cca6b))) >> ((/*FFI*/ff(((+(0.0/0.0))), ((70368744177665.0)), ((-3.8685626227668134e+25)), ((-9007199254740992.0)), ((16385.0)), ((-2.0)), ((-1099511627775.0)), ((36028797018963970.0)), ((524289.0)))|0)+(i1)))), ((x+=new RegExp(\"\\\\u00A7{0}\", \"im\"))), ((~(((-0.25) != (4.835703278458517e+24))))), ((abs((((0xaa946566)) & ((-0x8000000))))|0)), ((imul((-0x8000000), (0xa2f8a6ea))|0)))|0)-((Uint8ArrayView[0]))-(i1)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return Math.min((y % x), x); })}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[function(){}, function(){}, function(){}, (a) = (4277), function(){}, function(){}, (a) = (4277), (a) = (4277), (a) = (4277), function(){}, (a) = (4277), function(){}, (a) = (4277), (a) = (4277), function(){}, (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), function(){}, function(){}, function(){}, (a) = (4277), (a) = (4277), function(){}, function(){}, (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), function(){}, function(){}, function(){}, (a) = (4277), function(){}, (a) = (4277), (a) = (4277), function(){}, function(){}, (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), function(){}, function(){}, (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), (a) = (4277), function(){}, function(){}, (a) = (4277), (a) = (4277), function(){}, function(){}, (a) = (4277), (a) = (4277), function(){}, function(){}, (a) = (4277), function(){}, (a) = (4277), function(){}, function(){}, function(){}, (a) = (4277), (a) = (4277), function(){}, function(){}, function(){}, function(){}, (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), function(){}, (a) = (4277), (a) = (4277), (a) = (4277), function(){}, function(){}, (a) = (4277), function(){}, function(){}, (a) = (4277), function(){}, function(){}, function(){}, function(){}, (a) = (4277), (a) = (4277), function(){}, (a) = (4277), (a) = (4277), function(){}, function(){}, function(){}, (a) = (4277), (a) = (4277)]); ");
/*fuzzSeed-204645237*/count=1572; tryItOut("/*vLoop*/for (let kapqzb = 0; kapqzb < 6; ++kapqzb, x - a) { e = kapqzb; this.__defineGetter__(\"NaN\", c =>  { \"use strict\"; \"use asm\"; yield  \"\"  } ); } ");
/*fuzzSeed-204645237*/count=1573; tryItOut("e2.add(this.f2);\na1.toString = (function(j) { if (j) { try { /*RXUB*/var r = r0; var s = s2; print(s.match(r));  } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(m0, o0); } catch(e1) { } try { m0.delete(t1); } catch(e2) { } a2.reverse(10, e2); } else { t2.toSource = DataView.prototype.getUint32.bind(this.e2); } });\n");
/*fuzzSeed-204645237*/count=1574; tryItOut("clbzfv(x);/*hhh*/function clbzfv(x, b){f0 = Proxy.createFunction(h2, f1, f2);}");
/*fuzzSeed-204645237*/count=1575; tryItOut("print( /x/g .__defineGetter__(\"x\", function(y) { return null }) %=  /x/ );let a = x;");
/*fuzzSeed-204645237*/count=1576; tryItOut("Object.prototype.unwatch.call(o2, \"callee\");");
/*fuzzSeed-204645237*/count=1577; tryItOut("mathy5 = (function(x, y) { return (( + Math.imul(((( + ( + ( + ( ! (Math.imul(2**53-2, x) >>> 0))))) ? (Math.atan2(2**53+2, y) | 0) : Math.fround((( ! Math.atan2(x, ( + y))) >>> 0))) | 0), ( + ((Math.ceil((Math.fround(Math.imul(Math.fround(-Number.MAX_VALUE), Math.fround(x))) | 0)) | 0) ** Math.imul(((x << x) ? 2**53-2 : x), y))))) >> (((Math.atan2(((((0x080000000 | 0) > (y | 0)) | 0) | 0), y) >>> 0) >= (mathy2(Math.fround(((Math.pow(-0x080000001, ((Math.fround(y) >>> 0) >>> (y >>> 0))) | 0) - Math.fround( /x/g  =  /x/ ))), ( + Math.fround(Math.fround(Math.imul(Math.fround(x), y))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [undefined, ({valueOf:function(){return 0;}}), (new Number(0)), [], '0', false, (new String('')), (new Boolean(false)), 0.1, [0], '', (new Number(-0)), -0, 1, '\\0', /0/, (function(){return 0;}), 0, '/0/', ({toString:function(){return '0';}}), objectEmulatingUndefined(), null, NaN, ({valueOf:function(){return '0';}}), (new Boolean(true)), true]); ");
/*fuzzSeed-204645237*/count=1578; tryItOut("\"use strict\"; s0 += this.s1;x =  /x/ ;var nmjobm = new ArrayBuffer(4); var nmjobm_0 = new Uint8ClampedArray(nmjobm); print(nmjobm_0[0]); print( '' );");
/*fuzzSeed-204645237*/count=1579; tryItOut("/*infloop*/M:for((x) in (4277).unwatch(\"callee\")) {delete p1[new String(\"9\")];v2 = this.g1.objectEmulatingUndefined(); }");
/*fuzzSeed-204645237*/count=1580; tryItOut("Array.prototype.unshift.call(a0, p0, g1);");
/*fuzzSeed-204645237*/count=1581; tryItOut("s1 = '';");
/*fuzzSeed-204645237*/count=1582; tryItOut(";");
/*fuzzSeed-204645237*/count=1583; tryItOut("a2 = a0.slice(NaN, NaN, window);var c = timeout(1800);\nb1 = new SharedArrayBuffer(20);\n");
/*fuzzSeed-204645237*/count=1584; tryItOut("\"use strict\"; \"use asm\"; var dpnzjc = new ArrayBuffer(2); var dpnzjc_0 = new Int8Array(dpnzjc); dpnzjc_0[0] = 8; {}Object.prototype.watch.call(v0, new String(\"-0\"), o2.f1);");
/*fuzzSeed-204645237*/count=1585; tryItOut("a2 = Array.prototype.concat.call(this.a0, this.a2);");
/*fuzzSeed-204645237*/count=1586; tryItOut("\"use strict\"; y = (new Uint32Array());{print(this);a1.reverse(); }");
/*fuzzSeed-204645237*/count=1587; tryItOut("a1.splice(NaN, 18);");
/*fuzzSeed-204645237*/count=1588; tryItOut("/*RXUB*/var r = /(?=([^\u4328\\d]+|([^]|.)))^|[^]+|($\\b)(?![^\u00b0\u41c8\\S]|$){3,}\\3{1048576,1048579}/; var s = \"000000000000000000\\nv\\n\\u00f4\\n\"; print(r.exec(s)); print(r.lastIndex); print(x);");
/*fuzzSeed-204645237*/count=1589; tryItOut("\"use strict\"; Object.prototype.watch.call(e2, \"clear\", f0);");
/*fuzzSeed-204645237*/count=1590; tryItOut("\"use strict\"; v1 = t2.byteOffset;");
/*fuzzSeed-204645237*/count=1591; tryItOut("\"use asm\"; a1 = a1.filter(f0, o1.h2, v0, a1, p0);");
/*fuzzSeed-204645237*/count=1592; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[ /x/g ,  /x/g ,  /x/ ,  /x/ ,  /x/g ,  /x/g ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/g ,  /x/g ,  /x/g ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/g ,  /x/g ]) { print(a); }");
/*fuzzSeed-204645237*/count=1593; tryItOut("testMathyFunction(mathy3, [-0x100000000, 0x0ffffffff, -0, -(2**53-2), 0x080000000, 0x100000000, -0x080000001, -(2**53+2), 0/0, 0x080000001, 1/0, Math.PI, -1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, 2**53+2, -0x100000001, 0x07fffffff, 1.7976931348623157e308, 42, 1, 0x100000001, 2**53-2]); ");
/*fuzzSeed-204645237*/count=1594; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + ( - (Math.hypot((((Math.fround((x >>> 0)) >>> 0) == ( + ( + mathy2(( ~ 42), ( + ( ! (Math.fround(Math.atan2(Math.fround(-Number.MIN_SAFE_INTEGER), Math.fround(y))) >>> 0))))))) >>> 0), (x , Math.hypot(Math.fround(y), (((x / x) | 0) <= mathy3(y, -Number.MIN_SAFE_INTEGER))))) >>> 0))); }); testMathyFunction(mathy4, [null, (new Number(0)), '\\0', -0, (function(){return 0;}), '/0/', 0.1, (new Number(-0)), 0, 1, (new Boolean(true)), (new String('')), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), false, NaN, true, [], '0', [0], /0/, ({toString:function(){return '0';}}), (new Boolean(false)), '', undefined, objectEmulatingUndefined()]); ");
/*fuzzSeed-204645237*/count=1595; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.acos(Math.cbrt((Math.sqrt((1.7976931348623157e308 >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [0x100000001, Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, -0x0ffffffff, 0x100000000, 0x0ffffffff, -0x080000000, -(2**53-2), 42, 1.7976931348623157e308, 0.000000000000001, -0x080000001, 2**53, -0x07fffffff, 0, -0, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -0x100000001, 0x07fffffff, Number.MAX_VALUE, 2**53+2, 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, -Number.MAX_VALUE, -0x100000000, 1, -Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-204645237*/count=1596; tryItOut("\"use asm\"; v2 = g0.eval(\"y === d\");");
/*fuzzSeed-204645237*/count=1597; tryItOut("t2[7] = Math.exp(x);");
/*fuzzSeed-204645237*/count=1598; tryItOut("mathy4 = (function(x, y) { return (((((Math.imul((((Math.acosh(( - (( + mathy3(( + -0x080000001), x)) | 0))) >>> 0) % (Math.fround(Math.min(Math.fround(y), Math.fround((( ~ (Number.MAX_SAFE_INTEGER | 0)) | 0)))) >>> 0)) >>> 0), x) >>> 0) % Math.fround(( + Math.fround(Math.acos(Math.fround(mathy1(x, y))))))) | 0) !== (Math.atan(Math.fround((Math.max(( + Math.acos(( + ( - Number.MAX_VALUE)))), (Math.pow(Math.fround(Math.acosh(Math.fround(x))), x) ? 2**53-2 : x)) << ( + ( ! ( + x)))))) >>> 0)) | 0); }); testMathyFunction(mathy4, [NaN, (new Boolean(true)), 0, (new String('')), (function(){return 0;}), null, '', (new Number(-0)), '/0/', true, (new Boolean(false)), ({toString:function(){return '0';}}), 1, '\\0', 0.1, /0/, ({valueOf:function(){return '0';}}), [0], ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), false, -0, [], '0', (new Number(0)), undefined]); ");
/*fuzzSeed-204645237*/count=1599; tryItOut("\"use strict\"; v1 = evaluate(\"L: {print(x); }\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: x, sourceIsLazy: (x % 3 == 2), catchTermination: (x % 10 != 5), element: o0, elementAttributeName: s1 }));");
/*fuzzSeed-204645237*/count=1600; tryItOut("testMathyFunction(mathy2, [-Number.MAX_VALUE, -0x0ffffffff, -0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 2**53, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 2**53+2, 0x080000000, -0x100000001, -0x100000000, 1.7976931348623157e308, -(2**53-2), Number.MAX_VALUE, -0x080000000, 0x100000000, -(2**53+2), 0x07fffffff, 2**53-2, 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, 0x080000001, 0.000000000000001, 0, 42, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x100000001, Math.PI]); ");
/*fuzzSeed-204645237*/count=1601; tryItOut("mathy5 = (function(x, y) { return Math.sqrt(Math.clz32(( + (Math.hypot(( + ( ! x)), ((Math.hypot(\"\\uF074\", (y >>> 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), [], (new Number(-0)), ({valueOf:function(){return 0;}}), [0], NaN, objectEmulatingUndefined(), 0, '0', (function(){return 0;}), false, 1, (new Number(0)), -0, ({valueOf:function(){return '0';}}), 0.1, null, '', '/0/', true, /0/, (new Boolean(false)), undefined, (new String('')), (new Boolean(true)), '\\0']); ");
/*fuzzSeed-204645237*/count=1602; tryItOut("/*iii*/print(x);/*hhh*/function ienjiw(eval, eval, x, [], x, w, d = \"\\uEB79\", x = new RegExp(\"(\\\\D)\", \"g\"), e, a = x, a, x, y, window, x =  '' , \u3056){/*tLoop*/for (let w of /*MARR*/[ \"use strict\" , new String(''),  \"use strict\" ,  '\\0' , new String(''), new String(''), new String(''),  \"use strict\" ,  '\\0' ]) { return; }}");
/*fuzzSeed-204645237*/count=1603; tryItOut("v0 = Infinity;");
/*fuzzSeed-204645237*/count=1604; tryItOut("\"use strict\"; for(let z in []);");
/*fuzzSeed-204645237*/count=1605; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + ( + ( + mathy1((Math.sinh(y) % -Number.MIN_VALUE), ( + x))))) % Math.imul(Math.fround((Math.ceil(( + mathy1(( + y), ( + x)))) !== Math.fround(x))), Math.cbrt(Math.imul(x, x))))); }); testMathyFunction(mathy4, [-(2**53-2), 1, 2**53, -0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, -0x100000000, -0x100000001, 0x100000000, 0x080000000, 0, 1/0, 0x07fffffff, -(2**53), -0, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, 42, 0/0, 0x0ffffffff, -0x080000000, 2**53-2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -1/0, -(2**53+2)]); ");
/*fuzzSeed-204645237*/count=1606; tryItOut("\"use strict\"; print(x);\nprint(x);\n");
/*fuzzSeed-204645237*/count=1607; tryItOut("this.i0 = g1.a1.iterator;");
/*fuzzSeed-204645237*/count=1608; tryItOut("\"use strict\"; i2.next();");
/*fuzzSeed-204645237*/count=1609; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Float32ArrayView[1]) = ((-1.5474250491067253e+26));\n    return (((!((0x9a80ecdf)))-((0xdee47244))))|0;\n    return (((/*FFI*/ff()|0)))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: Symbol.prototype.valueOf, getOwnPropertyNames:  '' , delete: function() { return true; }, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: undefined, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000001, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 0, Number.MIN_VALUE, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -Number.MIN_VALUE, 0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 1/0, -0, -0x100000000, -1/0, -(2**53-2), -(2**53+2), -0x07fffffff, Number.MAX_VALUE, 1, 2**53+2, 2**53-2, 42, 0x0ffffffff, 0x100000001, -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-204645237*/count=1610; tryItOut("a2.splice(NaN, 19, e1);");
/*fuzzSeed-204645237*/count=1611; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (((Math.hypot((Math.imul(42, ( + ( ! y))) | 0), (Math.max(Math.fround(mathy3(( + x), ( + -Number.MAX_VALUE))), Math.sinh(Math.pow(-0, x))) | 0)) | 0) / Math.fround((((Number.MAX_VALUE >>> 0) ^ Math.sinh(Math.fround((Math.fround(( + Math.atanh((y >>> 0)))) && Math.fround(y))))) >>> 0))) & mathy2(((Math.fround((Math.fround(Math.max((( + Math.max(( + x), ( + y))) ** x), y)) << Math.fround(Math.acos(Math.PI)))) >>> 0) !== (Math.min(Math.max((Math.asin(x) >>> 0), (y | x)), x) | 0)), (Math.imul(x, (-0 >>> 0)) > y))); }); testMathyFunction(mathy5, /*MARR*/[[undefined], [undefined], new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), [undefined], [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], [undefined], [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), [undefined], [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], [undefined], [undefined], new Uint8ClampedArray(), new Uint8ClampedArray(), [undefined], [undefined], new Uint8ClampedArray(), [undefined], new Uint8ClampedArray(), [undefined], [undefined], [undefined], [undefined], [undefined]]); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
