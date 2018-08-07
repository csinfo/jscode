

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
/*fuzzSeed-42509072*/count=1; tryItOut("\"use strict\"; /*MXX3*/g1.Date.prototype.getFullYear = this.g0.Date.prototype.getFullYear;");
/*fuzzSeed-42509072*/count=2; tryItOut("\"use strict\"; x;");
/*fuzzSeed-42509072*/count=3; tryItOut("mathy0 = (function(x, y) { return ((( - Math.fround(( + ( ! ( + Math.tan(y)))))) ^ ((Math.fround(((Math.pow(x, (y | 0)) | 0) % x)) >>> 0) & (( + 0) >>> 0))) + ( ~ (( ~ Math.imul(( + (y !== x)), ( ! Math.atan2(y, y)))) >>> 0))); }); testMathyFunction(mathy0, [0x07fffffff, 0x080000001, -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, 0x100000000, 0.000000000000001, Number.MIN_VALUE, -(2**53+2), -0x100000001, 0, -0x080000001, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 1/0, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -1/0, -0, 2**53-2, 1, -(2**53), 0x0ffffffff, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-42509072*/count=4; tryItOut("\"use strict\"; a1.sort(v1);");
/*fuzzSeed-42509072*/count=5; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.acos(Math.max(Math.imul((mathy0(( + (( + 1) & x)), y) ** x), Math.fround((y ^ (x >>> 0)))), (( - (Math.min(y, ((Math.min(((Math.hypot(y, Math.max(y, -Number.MAX_SAFE_INTEGER)) >>> 0) | 0), x) | 0) | 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, /*MARR*/[new String('q'), new String('q'), new String('q'), new String('q'), -Infinity, -Infinity, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), -Infinity, -Infinity, -Infinity, -Infinity, new String('q'), new String('q'), -Infinity, new String('q'), -Infinity, -Infinity, -Infinity, -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), new String('q')]); ");
/*fuzzSeed-42509072*/count=6; tryItOut("\"use strict\"; m1.set(a1, o1);");
/*fuzzSeed-42509072*/count=7; tryItOut("mathy5 = (function(x, y) { return Math.acosh((( ~ (((Math.hypot((y >>> 0), (0x080000000 | 0)) + ((Math.sign((Math.min(y, y) | 0)) >>> 0) | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[-1, (-1/0), (0/0), (0/0), (0/0)]); ");
/*fuzzSeed-42509072*/count=8; tryItOut("this.g1 = x;");
/*fuzzSeed-42509072*/count=9; tryItOut("this.v0 = r2.ignoreCase;print((4277));");
/*fuzzSeed-42509072*/count=10; tryItOut("{L:if(false) {v1 = t1.length;(void schedulegc(g0)); }s2 = s0.charAt(19); }");
/*fuzzSeed-42509072*/count=11; tryItOut("v2 = (a2 instanceof g1);");
/*fuzzSeed-42509072*/count=12; tryItOut("s1 += s1;");
/*fuzzSeed-42509072*/count=13; tryItOut("mathy0 = (function(x, y) { return (( + (Math.log((Math.pow((Math.trunc(((Math.sign(x) > x) | 0)) >>> 0), (Math.PI >>> 0)) >>> 0)) | 0)) >= (Math.atan2(Math.fround(Math.log(( + (Math.sinh((x | 0)) >>> 0)))), (0x080000001 ? y : ((((y >>> 0) <= ((x >= (x | 0)) >>> 0)) >>> 0) >>> x))) <= Math.imul(Math.expm1(Math.log10(Math.max(x, y))), ((((Math.exp((y >>> 0)) | 0) >>> 0) != (Math.min(y, (Math.tanh((x | 0)) | 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [NaN, 1, false, null, (new String('')), (new Number(0)), (new Boolean(false)), true, [], /0/, ({valueOf:function(){return 0;}}), '0', 0.1, 0, '', (function(){return 0;}), -0, ({toString:function(){return '0';}}), '/0/', (new Number(-0)), objectEmulatingUndefined(), (new Boolean(true)), undefined, [0], ({valueOf:function(){return '0';}}), '\\0']); ");
/*fuzzSeed-42509072*/count=14; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.tan(( ~ Math.imul(mathy0(Math.trunc((( + Math.cbrt(( + (y , y)))) >>> 0)), ( + (( + x) | ( + y)))), (x >>> 0)))); }); ");
/*fuzzSeed-42509072*/count=15; tryItOut("mathy0 = (function(x, y) { return Math.cosh(((Math.acos(x) >= Math.fround(x)) ^ Math.fround(( ~ ( ! Math.fround((( - (y >>> 0)) << y))))))); }); testMathyFunction(mathy0, [2**53-2, -1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, -(2**53-2), Number.MIN_VALUE, -(2**53+2), 2**53, -0x07fffffff, -(2**53), 42, -0x0ffffffff, -Number.MAX_VALUE, 0x100000001, 0, -0, 0x080000001, 1.7976931348623157e308, Math.PI, 0x080000000, 2**53+2, -0x100000000, 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, -0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 1, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=16; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.atan2(Math.log(Math.imul((x , (x == y)), ( + ( + Math.trunc((-0x100000000 >>> 0)))))), (( + ( + Math.asin(( + ( + y))))) | 0)) | 0); }); ");
/*fuzzSeed-42509072*/count=17; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log10((Math.sin(Math.fround((( ! (x >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy0, ['', (new Number(-0)), undefined, (new Boolean(true)), -0, (new Number(0)), ({toString:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return '0';}}), null, 0, false, 0.1, (new String('')), true, ({valueOf:function(){return 0;}}), '/0/', '\\0', [0], '0', NaN, [], (new Boolean(false)), 1, /0/, objectEmulatingUndefined()]); ");
/*fuzzSeed-42509072*/count=18; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.fround((((((( + (0x080000001 >>> 0)) >>> 0) | 0) <= (-0 | 0)) | 0) ? (( ~ x) | 0) : ((( - ( ! x)) ^ mathy2(y, Math.acos(( ! y)))) >>> 0))), ( + (((( + Math.fround(0x080000000)) >>> 0) / Math.fround((Math.fround((((y >>> 0) ? (y >>> 0) : x) >>> 0)) <= Math.fround(0x080000001)))) >= Math.fround((Math.fround((Math.fround(mathy4(x, Math.PI)) ? ( + (( + mathy0(Number.MAX_VALUE, ( + Math.min(( + y), ( + x))))) ^ ((Math.hypot((( + (Math.fround(y) & Math.fround(x))) >>> 0), (-0x080000001 >>> 0)) >>> 0) >>> 0))) : Math.fround(( + x)))) ? (( ~ ( + mathy1(( + x), ( + y)))) >>> 0) : 0.000000000000001))))); }); ");
/*fuzzSeed-42509072*/count=19; tryItOut("\"use strict\"; a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-42509072*/count=20; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((((( - x) >>> 0) ? (Math.min((Math.fround(( ! Math.fround(y))) >>> (Math.pow((y | 0), -(2**53)) | 0)), ( + (x | 0))) >>> 0) : (x >>> 0)) << Math.fround(( - ( + Math.max(( + Math.min(( - x), 0x0ffffffff)), ( + (0x0ffffffff - ( + Math.sinh(y))))))))) | 0) && (Math.max(( ! Math.max(y, ((x !== Math.cos(Number.MIN_SAFE_INTEGER)) >>> 0))), Math.cosh(x)) | 0)); }); testMathyFunction(mathy4, [42, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, 1/0, 1.7976931348623157e308, Number.MIN_VALUE, -1/0, -0x080000001, 2**53, 0x0ffffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, 0x07fffffff, -0x07fffffff, -0x100000001, 2**53+2, 0.000000000000001, 0x080000001, 1, 0x080000000, Math.PI, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0, -(2**53-2), 0x100000001]); ");
/*fuzzSeed-42509072*/count=21; tryItOut("if(true) f2 = (function mcc_() { var eyjsod = 0; return function() { ++eyjsod; if (/*ICCD*/eyjsod % 8 == 3) { dumpln('hit!'); try { this.v2 = g1.eval(\"\\\"\\\\uE440\\\"\"); } catch(e0) { } try { v2 = (m1 instanceof m1); } catch(e1) { } Array.prototype.sort.apply(a1, [Map.prototype.entries.bind(g0)]); } else { dumpln('miss!'); try { Array.prototype.splice.apply(a2, [\"\\u7DDE\"]); } catch(e0) { } v2 = evalcx(\"/* no regression tests found */\", this.g2); } };})();");
/*fuzzSeed-42509072*/count=22; tryItOut("print(uneval(b2));");
/*fuzzSeed-42509072*/count=23; tryItOut("/*iii*/Array.prototype.pop.call(a2, s2);/*hhh*/function idauhv(x, x, c, eval, x, window, x, x, x, x, w, window, y, w =  /x/ , x, w, e, d, x, a, \u3056, x, eval =  /x/g , e = null, x, x, b, x = /(?=([^]))+(?=[^]^^$+){2}(?:\\1\\B{4,5}(\\b))/im, d, y, NaN, window, w, x, w, x, e, x = window, d, window = [1], x, x, x, z, a, eval, x, d, x = ({}), y, eval, eval = \"\\u7F21\", c, x = /(\\b)/i, eval = this, of, x){/*RXUB*/var r = new RegExp(\"((?:\\\\3+?(?:\\\\B)(?:(?=(?=\\\\s)*)){2}))\", \"i\"); var s = \"\"; print(uneval(r.exec(s))); }");
/*fuzzSeed-42509072*/count=24; tryItOut("b2 = a2[({valueOf: function() { v0 = v2[\"forEach\"];return 3; }})];");
/*fuzzSeed-42509072*/count=25; tryItOut("a1.shift(p0);");
/*fuzzSeed-42509072*/count=26; tryItOut("mathy0 = (function(x, y) { return (Math.max(Math.asin(x), Math.pow(42, ( ! Math.pow(x, 2**53-2)))) / Math.fround((Math.fround(Math.hypot((((Math.fround((Math.fround(42) == Math.fround(-1/0))) ? x : -Number.MIN_VALUE) ? -(2**53+2) : (0/0 >>> 0)) >>> 0), ( ~ ((Math.fround(Math.pow(y, Math.fround(y))) >>> 0) === (y >>> 0))))) >= (Math.clz32(Math.sign(y)) >>> 0)))); }); testMathyFunction(mathy0, [1, -Number.MIN_SAFE_INTEGER, -0, -(2**53), 0x080000000, Math.PI, -Number.MIN_VALUE, 0x080000001, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, 0, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -1/0, 0x100000001, 1/0, Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -0x080000000, -0x080000001, -0x0ffffffff, -0x07fffffff, 2**53-2, -(2**53+2), 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000001, -0x100000000, 0.000000000000001]); ");
/*fuzzSeed-42509072*/count=27; tryItOut("\"use asm\"; for (var v of e2) { try { /*RXUB*/var r = g1.r0; var s = \"\\u2561\"; print(s.split(r)); print(r.lastIndex);  } catch(e0) { } try { h1.iterate = g2.f0; } catch(e1) { } try { /*ODP-1*/Object.defineProperty(o1.g0, \"length\", ({value: Math.hypot(-22, 6), writable: true, enumerable: x-=((p={}, (p.z = new ( \"\" )(new RegExp(\"(?=[^\\\\D\\\\D\\\\w])|(?=(?!\\\\B)|e.\\\\3)(\\\\b)|[a\\\\cR-\\\\\\ue371\\\\uCfc5\\\\d]{2,}\", \"ym\"), window))()))()})); } catch(e2) { } Object.preventExtensions(e2); }");
/*fuzzSeed-42509072*/count=28; tryItOut("\"use strict\"; o1 = Object.create(m1);");
/*fuzzSeed-42509072*/count=29; tryItOut("\"use strict\"; g0.e0.has(g1.i0);function window(w)(({x:3})).__defineGetter__(\"w\", null)h1.getOwnPropertyDescriptor = (function(j) { if (j) { try { for (var p in s2) { try { p2.__iterator__ = (function(j) { if (j) { try { for (var p in o2.t1) { o2 = new Object; } } catch(e0) { } try { for (var v of a2) { try { g2.v2 = evalcx(\"/*MXX2*/g2.Array.length = t2;\", g1); } catch(e0) { } g1.s1 += s1; } } catch(e1) { } this.m1.valueOf = o0.o0.f1; } else { try { v2 = (t2 instanceof v1); } catch(e0) { } Array.prototype.splice.apply(o2.a1, [-13, 18, p0]); } }); } catch(e0) { } try { o2.t0 = new Float64Array(b2); } catch(e1) { } f1[\"caller\"] = this.p1; } } catch(e0) { } try { s1 = Array.prototype.join.call(a2, s2); } catch(e1) { } try { Array.prototype.forEach.call(g0.g2.a1, (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xffffffff);\n    i0 = (0xffffffff);\n    d1 = (-9.671406556917033e+24);\n    (Float32ArrayView[4096]) = ((d1));\n    {\n      {\n        (Int8ArrayView[((0xb274c1e7)+(0x7431e47e)) >> 0]) = ((((0x4c9fe57b) ? (-0x8000000) : (0xd4bc6b04)) ? ((((1.2089258196146292e+24)) % ((33554432.0)))) : (i0))*-0xca1d5);\n      }\n    }\n    (Int16ArrayView[0]) = ((((0xffffffff) ? (i0) : (/*FFI*/ff()|0)) ? (x) : (!(0xfda67684))));\n    d1 = (-2049.0);\n    d1 = (-2.4178516392292583e+24);\n    (Float64ArrayView[1]) = ((Float32ArrayView[((0xeb2de1a)) >> 2]));\n    return ((-0x539ce*(0xfec7f924)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; \"use asm\"; return x; })}, new ArrayBuffer(4096)), h1); } catch(e2) { } /*MXX3*/g1.g2.TypeError.prototype.toString = o1.g2.TypeError.prototype.toString; } else { try { let v1 = a2.length; } catch(e0) { } try { a2 + ''; } catch(e1) { } try { g2.v2 = a2.length; } catch(e2) { } s0 += 'x'; } });");
/*fuzzSeed-42509072*/count=30; tryItOut("mathy1 = (function(x, y) { return (mathy0((Math.fround(( ! Math.fround(( + ( ~ (( - x) || (Math.pow((0x100000000 >>> 0), (42 >>> 0)) >>> 0))))))) >>> 0), (( ~ Math.hypot(Math.fround(Math.max((Math.imul((Math.min((x >>> 0), 0x080000001) >>> 0), ( + ( + mathy0(42, ( + x))))) >>> 0), Math.fround(y))), y)) >>> 0)) !== mathy0(( ~ Math.min((( + mathy0(y, Math.max(Number.MIN_SAFE_INTEGER, y))) >>> 0), 2**53+2)), (Math.expm1(Math.sin(y)) | 0))); }); ");
/*fuzzSeed-42509072*/count=31; tryItOut("/*vLoop*/for (let uraghk = 0; uraghk < 32; ++uraghk) { var a = uraghk; t2[11] = -24; } ");
/*fuzzSeed-42509072*/count=32; tryItOut("\"use strict\"; x;");
/*fuzzSeed-42509072*/count=33; tryItOut("\"use strict\"; /*hhh*/function hckwkr(a = eval(\"(/*FARR*/[].filter(((function(x, y) { return 0; })).apply));\"), y){/*oLoop*/for (let jbdfzx = 0, uljcnn, \u3056; jbdfzx < 98; ++jbdfzx) { this; } \no0.g0 = this;\n}hckwkr(/*MARR*/[]);");
/*fuzzSeed-42509072*/count=34; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.fround(( - Math.fround((((Math.log(Math.pow(Math.fround(Math.ceil(Math.fround(-Number.MAX_VALUE))), (( - y) | 0))) | 0) ? Math.log(Math.hypot(Math.sign(y), y)) : (Math.atanh(( ~ Math.pow(((( + (y | 0)) | 0) >>> 0), y))) | 0)) | 0))))); }); testMathyFunction(mathy0, [(new Number(0)), false, ({valueOf:function(){return 0;}}), (new Number(-0)), 0.1, NaN, true, -0, [], (new Boolean(true)), 0, objectEmulatingUndefined(), '', (function(){return 0;}), undefined, ({valueOf:function(){return '0';}}), '\\0', (new Boolean(false)), /0/, ({toString:function(){return '0';}}), 1, '0', '/0/', null, (new String('')), [0]]); ");
/*fuzzSeed-42509072*/count=35; tryItOut("\"use strict\"; this.o0.g1.g0.b2 + e0;");
/*fuzzSeed-42509072*/count=36; tryItOut("\"use strict\"; a2 = r1.exec(g0.s1);");
/*fuzzSeed-42509072*/count=37; tryItOut("/*RXUB*/var r = this.__defineSetter__(\"x\", eval); var s = \"\"; print(s.replace(r, ((a)|=(uneval(s))).apply, \"gm\")); ");
/*fuzzSeed-42509072*/count=38; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42509072*/count=39; tryItOut("\"use strict\"; i2.send(p2);m2.delete(v2);");
/*fuzzSeed-42509072*/count=40; tryItOut("/* no regression tests found */v1 = b0.byteLength;break ;");
/*fuzzSeed-42509072*/count=41; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.atanh(Math.fround(Math.sin((((( ~ (((x | 0) >>> ( + x)) | 0)) | 0) !== ( - x)) | 0))))); }); testMathyFunction(mathy5, [0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, -0x0ffffffff, 2**53-2, Number.MAX_VALUE, 0x100000000, -0x07fffffff, 2**53+2, 0, -(2**53-2), -(2**53), -0x100000001, 1, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, 1/0, -0, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, Number.MIN_VALUE, -0x080000001, 0x07fffffff, Math.PI, 0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-42509072*/count=42; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=43; tryItOut("\"use strict\"; /*oLoop*/for (let fdqrgp = 0; fdqrgp < 30; ++fdqrgp) { o1 = Object.create(f2); } ");
/*fuzzSeed-42509072*/count=44; tryItOut("\"use strict\"; ");
/*fuzzSeed-42509072*/count=45; tryItOut("/*bLoop*/for (var vfkukw = 0; vfkukw < 14; ++vfkukw) { if (vfkukw % 5 == 1) { v0 = (g1.g1.f2 instanceof a2); } else { this.m1.set(m2, m0); }  } ");
/*fuzzSeed-42509072*/count=46; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( - ((( ! (( - x) >>> 0)) >>> 0) | 0)) >>> 0)); }); ");
/*fuzzSeed-42509072*/count=47; tryItOut("\"use strict\"; ;");
/*fuzzSeed-42509072*/count=48; tryItOut("\"use asm\"; (4277);\nv1 = r0.constructor;\n");
/*fuzzSeed-42509072*/count=49; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ((( ~ ( + ( - (y % (Math.sign(y) >>> 0))))) >>> 0) == (Math.expm1(Math.fround((Math.fround((y || (( - y) >>> 0))) ? Math.fround((( + 0x080000001) && ( + -0x07fffffff))) : ( + x)))) < ( + Math.fround(x)))); }); ");
/*fuzzSeed-42509072*/count=50; tryItOut("\"use strict\"; print(new (Boolean)(\"\\u27D4\"));function x(x, x, ...x) { \"use strict\"; yield x } for (var p in g0.g2) { try { f1.valueOf = f0; } catch(e0) { } try { m0.delete(a2); } catch(e1) { } m2.has(m2); }function x(a, x, c, c, x, arguments, e, x = (this.__defineSetter__(\"d\", (new Function(\"h2.enumerate = (function() { for (var j=0;j<1;++j) { this.f1(j%2==0); } });\")))), e = \"\\uFB8D\", b, \u3056 = length, c, x, x, x, window, x, c = x, x, c, x, x = function(id) { return id }, y, \u3056, x, x =  \"\" , e, x, w, e =  /x/g , \u3056 =  \"\" , \u3056, x) { return (4277) } m0.set(s2, p2)");
/*fuzzSeed-42509072*/count=51; tryItOut("mathy5 = (function(x, y) { return (Math.fround(( + ( ~ mathy4(Math.fround(1), (( ~ (x >>> 0)) >>> 0))))) , (((( - Math.fround(( + (((y != x) << mathy2((Math.atanh((x >>> 0)) >>> 0), x)) * -0x100000000)))) >>> 0) | (Math.atanh(Math.atan2(( + y), ( - y))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-42509072*/count=52; tryItOut("const d = (({call: undefined,  set b e (e, x) { return length }  }))(x, a / c);m2.delete(t1);");
/*fuzzSeed-42509072*/count=53; tryItOut("\"use strict\"; /*vLoop*/for (let kyuqzl = 0; kyuqzl < 35; ++kyuqzl) { const a = kyuqzl; a0.sort((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 17179869184.0;\n    {\n      {\n        return (((/*FFI*/ff(((d1)))|0)))|0;\n      }\n    }\n    return (((0xc444beb3)))|0;\n  }\n  return f; })(this, {ff: (x) =>  { \"use strict\"; return \"\\u9CD4\" } }, new ArrayBuffer(4096)), new RegExp(\"(.+?)+?\", \"gyi\").expm1(-7), b1, o1.h1); } ");
/*fuzzSeed-42509072*/count=54; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return mathy2(((Math.imul((( ~ (((((( + y) * x) | 0) | 0) * y) | 0)) >>> 0), ((y == -(2**53)) | 0)) >>> 0) - (Math.acos(((( ! Math.trunc(x)) ? (Math.trunc(Math.sin(y)) | 0) : ((( ! -0x100000000) && (((y | 0) == y) | 0)) >>> 0)) | 0)) | 0)), Math.sinh((( + Math.tan(( + (( + (-0x080000001 >>> 0)) >>> 0)))) | 0))); }); testMathyFunction(mathy4, [0x080000001, -(2**53), -0x0ffffffff, -Number.MIN_VALUE, Math.PI, -0x080000000, 42, 0/0, -0x080000001, 0x100000001, 1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, 0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -(2**53+2), Number.MAX_VALUE, -0x100000000, -1/0, 1, 0, 0x07fffffff, 0x080000000, 0x100000000, 2**53, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001]); ");
/*fuzzSeed-42509072*/count=55; tryItOut("let (w) { e0.has(-6); }");
/*fuzzSeed-42509072*/count=56; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=57; tryItOut("/*MXX3*/g1.Promise.reject = g0.Promise.reject;");
/*fuzzSeed-42509072*/count=58; tryItOut("\"use strict\"; Object.defineProperty(this, \"o0.s2\", { configurable: false, enumerable: (x % 5 != 0),  get: function() {  return new String(o0); } });");
/*fuzzSeed-42509072*/count=59; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + (((( + Math.acosh(( + x))) >>> 0) + mathy0(( + ( - (0/0 >> Math.max(x, y)))), Math.fround(( ! Math.fround(y))))) >>> 0)), (( + Math.exp(Math.fround(x))) || Math.fround((Math.fround(Math.max(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround(x))) * ( + Math.sign(( + (Math.atanh((-0x100000001 >>> 0)) | 0))))))))); }); testMathyFunction(mathy3, [-(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 42, -(2**53+2), 0, -Number.MAX_VALUE, Math.PI, -(2**53), Number.MIN_VALUE, 0x080000000, 0x100000001, -0x100000001, -Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, 0/0, 1, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -1/0, 2**53, -0x07fffffff, -0x100000000, -0x080000001, 0x07fffffff, 1/0, -0, 0x080000001, 0.000000000000001, 2**53+2, 2**53-2]); ");
/*fuzzSeed-42509072*/count=60; tryItOut("\"use strict\"; if((x % 2 == 0)) v0 = (p0 instanceof g2.g1); else {o2.b2[\"9\"] = t0;v0 = g2.eval(\";\");\ni1 = a2.iterator;\n }");
/*fuzzSeed-42509072*/count=61; tryItOut("\"use strict\"; /*MXX1*/this.o2 = g0.Date.prototype.toJSON;");
/*fuzzSeed-42509072*/count=62; tryItOut("{print(/*MARR*/[(void 0), null, null, null, (void 0), (void 0), null, null, null, null, null, null, (void 0), null, null, null, (void 0), (void 0), (void 0), null, null, null, (void 0), (void 0), null, (void 0), (void 0), (void 0), (void 0), null, (void 0), null, (void 0), null, null, null, (void 0), (void 0), null, null, (void 0), null, (void 0), null, (void 0), null, null, null, null, (void 0), (void 0), null].sort); }");
/*fuzzSeed-42509072*/count=63; tryItOut("this.i0 + t1;");
/*fuzzSeed-42509072*/count=64; tryItOut("h1.get = f1;");
/*fuzzSeed-42509072*/count=65; tryItOut("\"use strict\"; var vurofn = new SharedArrayBuffer(4); var vurofn_0 = new Float32Array(vurofn); print(vurofn_0[0]); vurofn_0[0] = -20; var vurofn_1 = new Uint32Array(vurofn); print(vurofn_1[0]); vurofn_1[0] = 16; var vurofn_2 = new Int16Array(vurofn); vurofn_2[0] = 28; h2.getPropertyDescriptor = f2;");
/*fuzzSeed-42509072*/count=66; tryItOut("\"use strict\"; r2 = new RegExp(\"(?=(?=(?:.+?)))\", \"gim\");");
/*fuzzSeed-42509072*/count=67; tryItOut("/*bLoop*/for (let cmgidv = 0; cmgidv < 0; ++cmgidv) { if (cmgidv % 7 == 5) { undefined;yield window; } else { m2.delete(f1); }  } ");
/*fuzzSeed-42509072*/count=68; tryItOut("/*RXUB*/var r = /[\\cD-\\x8A]((?:(?!\\B)[^]{1}(?=.)*?|((?!(.))|[\\d\\W\\t-u\\ufa2F]+?)*))/gy; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-42509072*/count=69; tryItOut("selectforgc(o0);");
/*fuzzSeed-42509072*/count=70; tryItOut("t2 = t2.subarray(10);\nt0 = t1.subarray(13);\n");
/*fuzzSeed-42509072*/count=71; tryItOut("\"use strict\"; \"use strict\"; this.a2.unshift(v0);\n/*oLoop*/for (var oqbcpd = 0; oqbcpd < 26; ++oqbcpd) { a2.shift(g1.o1); } \n\n/*hhh*/function oliwpa(x, e){p1 + g2;}/*iii*/yield;\n");
/*fuzzSeed-42509072*/count=72; tryItOut("mathy0 = (function(x, y) { return ( - (Math.acos((Math.pow((( + Math.pow(( + y), ( + ( + ( - y))))) >>> ( - Math.acos(Math.fround(Math.fround((Math.fround(y) , Math.fround(Number.MAX_VALUE))))))), ( ~ Math.fround(Math.imul((y >>> 0), -(2**53))))) | 0)) | 0)); }); testMathyFunction(mathy0, [[0], /0/, '0', ({valueOf:function(){return '0';}}), 0, (new Number(-0)), (new String('')), objectEmulatingUndefined(), NaN, ({toString:function(){return '0';}}), false, -0, null, (new Number(0)), [], (new Boolean(true)), '/0/', (new Boolean(false)), undefined, '', true, '\\0', 1, 0.1, (function(){return 0;}), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-42509072*/count=73; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, -0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 0, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, -0x07fffffff, -0x100000000, Math.PI, 1/0, -(2**53-2), -0x080000001, 0/0, 0x080000000, 2**53-2, 2**53, 1.7976931348623157e308, 42, 0x100000000, 0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1]); ");
/*fuzzSeed-42509072*/count=74; tryItOut("\"use strict\"; v1 = t1.length;");
/*fuzzSeed-42509072*/count=75; tryItOut("print(uneval(b2));");
/*fuzzSeed-42509072*/count=76; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (Math.max(Math.fround(Math.fround(mathy0(((Math.min((Number.MIN_SAFE_INTEGER >>> 0), (y >>> 0)) >>> 0) * y), (( + ( + ( + Math.tanh(( + y))))) | 0)))), ( - (( - ( + Math.asin(Math.sign(x)))) | 0))) ^ Math.tan(Math.min(x, y)))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), new Boolean(false),  /x/g , new Boolean(false),  /x/g , new Boolean(true), new Boolean(false), new Boolean(true), new String(''), objectEmulatingUndefined(), new String(''),  /x/g ,  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/g , objectEmulatingUndefined(),  /x/g ,  /x/g , new String(''), new String(''), objectEmulatingUndefined(),  /x/g ,  /x/g , new Boolean(false), new String(''), new Boolean(false),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new String(''), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new String(''), new Boolean(true), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g ,  /x/g , objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new String(''), new Boolean(true), new Boolean(false), new Boolean(false), new String(''), new Boolean(false), new Boolean(false), new String(''), new Boolean(true), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-42509072*/count=77; tryItOut("Array.prototype.reverse.call(a2);");
/*fuzzSeed-42509072*/count=78; tryItOut("\"use strict\"; s2 += s1;");
/*fuzzSeed-42509072*/count=79; tryItOut("mathy0 = (function(x, y) { return ( - Math.min(Math.pow(Math.acosh(( + x)), Math.atan2(-Number.MAX_VALUE, y)), (Math.sinh(( + (((( - 1) >>> 0) <= (x >>> 0)) != Math.sign((Math.cbrt(x) | 0))))) >> Math.asinh(x)))); }); testMathyFunction(mathy0, [0x07fffffff, -0x100000001, 2**53, -0x080000001, -(2**53+2), 42, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 1, 2**53+2, -(2**53), 0x100000001, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, 0x080000000, -(2**53-2), 2**53-2, 0x080000001, 1/0, 0/0, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000000, -0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=80; tryItOut("h2 = g0.objectEmulatingUndefined();");
/*fuzzSeed-42509072*/count=81; tryItOut("mathy4 = (function(x, y) { return ( + (Math.tan(1) / (( + ( ~ ( + Number.MIN_VALUE))) ^ ( + (( ! Math.max(Math.fround(Math.clz32(Math.fround(y))), 0)) != (Number.MAX_SAFE_INTEGER | y)))))); }); ");
/*fuzzSeed-42509072*/count=82; tryItOut("o0.b1.toString = (function() { for (var j=0;j<4;++j) { f2(j%4==1); } });");
/*fuzzSeed-42509072*/count=83; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return Math.fround((Math.fround(Math.fround(Math.atan2((Math.round(( ~ Math.fround((Math.fround(2**53-2) ? Math.fround(x) : y)))) | 0), ((Math.abs(x) >>> 0) | Math.atan2((y >>> 0), (x >>> 0)))))) & Math.fround(mathy1(( + Math.fround((Math.fround(Math.tanh(y)) << Math.fround(Math.pow(Math.fround((mathy1((-0x0ffffffff >>> 0), ((Math.hypot((y | 0), (2**53-2 >>> 0)) >>> 0) >>> 0)) >>> 0)), x))))), ( + Math.clz32(((Math.round(((Math.min((x >>> 0), (Math.fround(( - y)) >>> 0)) >>> 0) >>> 0)) >>> 0) ? -(2**53+2) : ( + Math.hypot(( + ( + Math.imul(( + 0.000000000000001), ( + y)))), ( + (Math.log1p((y >>> 0)) >>> 0))))))))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0x080000000, 0, -0x080000001, -Number.MIN_VALUE, -1/0, -(2**53), 0.000000000000001, -0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, 1, -Number.MAX_SAFE_INTEGER, -0, 2**53+2, -0x080000000, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, 0x100000001, 1.7976931348623157e308, 0/0, -(2**53+2), -(2**53-2), 0x100000000, 2**53-2, 2**53, Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-42509072*/count=84; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 295147905179352830000.0;\n    d1 = (((d2)) - ((Float64ArrayView[4096])));\n    d1 = (+(-1.0/0.0));\n    return (((/*FFI*/ff()|0)-(((((~((0x7fffffff) / (0xa4da3d3))) >= (0x228d2d95))) & ((0xffffffff))))+(0xd6e34941)))|0;\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [1.7976931348623157e308, 0x100000001, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, 0x100000000, -0x080000001, 2**53+2, Number.MAX_VALUE, -(2**53-2), 0.000000000000001, 1, 0x080000000, -0x100000000, -Number.MAX_VALUE, -(2**53), Math.PI, -0x100000001, 0/0, 1/0, -0x0ffffffff, 0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, 42, -(2**53+2), 0x080000001, 2**53-2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=85; tryItOut("this.v2 = (s1 instanceof m1);");
/*fuzzSeed-42509072*/count=86; tryItOut("/*tLoop*/for (let w of /*MARR*/[objectEmulatingUndefined(), function(){}, function(){}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, function(){}, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, function(){}, function(){}]) { (void shapeOf(\"\\u27AE\")); }");
/*fuzzSeed-42509072*/count=87; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(\\\\3)+|.?|.|\\\\u6A2c*)|(?:(\\\\2*?(?![\\\\t0\\\\xa3\\\\d]|(?!^\\\\B))))*?\", \"\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-42509072*/count=88; tryItOut("\"use strict\"; Array.prototype.forEach.apply(o0.a0, [f2])\n/*infloop*/M:for(var w; yield \u3056.c%=-22; ((Array.prototype.find(new RegExp(\"(?:[\\ub606])\\\\s+|(?=\\uf3bc)\\\\v\\\\B+*?\\\\b|.(?![^]+)*{0,1}\", \"im\"))) in  \"\" )) /*ADP-3*/Object.defineProperty(a2, 2, { configurable: (x % 13 == 8), enumerable: false, writable:  /x/g , value: this.a2 });");
/*fuzzSeed-42509072*/count=89; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=90; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul((Math.pow((( + Math.cos(( + Math.hypot(y, y)))) >>> 0), (( + (( + Math.atan(( + Math.log(y)))) >>> (x <= x))) >>> 0)) >>> 0), ( ! Math.ceil(Math.log(Math.fround(Math.fround(( - Math.acosh(1.7976931348623157e308)))))))); }); testMathyFunction(mathy3, [-0x0ffffffff, 0x080000000, 0x100000000, 0x100000001, -1/0, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, 0x080000001, -(2**53+2), 42, 1, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 0, -0, -Number.MIN_VALUE, 0x07fffffff, 2**53-2, 1/0, -0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, -(2**53-2), 2**53, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=91; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min(Math.atan2((( + ( - x)) >>> 0), Math.fround((((Math.fround(1) >>> 0) || (Math.fround((( + y) & (((y | 0) - y) | 0))) >>> 0)) >>> 0))), (( + (( + (x != ( + Math.max(( + y), ( + Math.fround(( - Math.fround(y)))))))) != ( + Math.cbrt(y)))) >>> 0)); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 2**53-2, 0.000000000000001, 1/0, -0x100000000, Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, -0x080000000, 0x080000001, -(2**53-2), Math.PI, -0x080000001, 0/0, -(2**53), 0x080000000, Number.MAX_VALUE, 0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, 42, 0, 2**53+2, 0x0ffffffff, 1, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, -0x0ffffffff, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-42509072*/count=92; tryItOut(";");
/*fuzzSeed-42509072*/count=93; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=94; tryItOut("/*infloop*/for(getter in b++) {this.g0.g2 + ''; }");
/*fuzzSeed-42509072*/count=95; tryItOut("for(let c in [ \"\"  for (NaN of Math.hypot(x, (x = \"\\u2CDF\") || (\"\\u7DCB\" instanceof \"\\uD7A4\") &= Math.round(\"\\u02B7\")).throw(true) >>>= ((makeFinalizeObserver('nursery'))))\u0009 for (window of x *= (void version(180))) for each (z in (function(x, y) { return (Math.pow(Math.fround((Math.fround(Math.fround(Math.min(( + (( + ( - y)) > x)), (Math.log1p(Math.fround(Math.acos(x))) >>> 0)))) !== Math.log10(Math.fround(Math.log(Math.fround(y)))))), Math.fround(( + (( ! (Math.atan2((x >>> 0), ((Math.cosh(x) >>> 0) >>> 0)) >>> 0)) == ( + ( ! ( + x))))))) >>> ( - ( - ((Math.pow(x, (Math.imul(y, (x >>> 0)) >>> 0)) >>> 0) % y)))); })) for (z of (4277)) for (arguments in ((void version(180)))) for (x of (new x())) for (x of x) for (eval of (new Function(\"print(x);\"))) for (b of x)]) throw (({__parent__: x,  set window\u000c() { \"use strict\"; print(uneval(o2.a0)); }  })) &= /*UUV1*/(y.getUint16 = function(y) { \"use strict\"; print(x); });");
/*fuzzSeed-42509072*/count=96; tryItOut("\"use asm\"; /*hhh*/function ezancj(){v1 = a2.reduce, reduceRight((function() { try { t0[16] = m1; } catch(e0) { } i1 = e2.keys; return e2; }), g2.b1, m0, f2, t1, v0);}/*iii*//*MXX2*/this.g1.Root = b1;");
/*fuzzSeed-42509072*/count=97; tryItOut("m0.delete(g0.f0);");
/*fuzzSeed-42509072*/count=98; tryItOut("Object.defineProperty(this, \"this.v0\", { configurable: true, enumerable: false,  get: function() {  return 0; } });");
/*fuzzSeed-42509072*/count=99; tryItOut("testMathyFunction(mathy0, [true, (new Number(-0)), (function(){return 0;}), false, [0], undefined, -0, (new String('')), [], (new Boolean(true)), /0/, ({valueOf:function(){return 0;}}), (new Boolean(false)), '\\0', objectEmulatingUndefined(), (new Number(0)), NaN, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '0', null, 0, 0.1, '/0/', 1, '']); ");
/*fuzzSeed-42509072*/count=100; tryItOut("\"use strict\"; s0 += s0;");
/*fuzzSeed-42509072*/count=101; tryItOut("mathy2 = (function(x, y) { return (Math.min((Math.pow((( + ( + (Math.fround(Math.atanh(Math.fround(y))) ? (y | 0) : (x | 0)))) >>> 0), (((((Math.hypot((0x07fffffff | 0), y) | 0) >>> 0) >>> x) >>> 0) ? Math.max((x >>> 0), y) : (((x >>> 0) ? Math.fround(y) : (0/0 | 0)) >>> 0))) >>> Math.asinh(Math.asinh(Math.round(Math.imul((x | ( + x)), y))))), Math.max(( + Math.hypot(y, Math.max(y, ((Math.acosh(x) / x) >>> 0)))), (( ~ (((Math.pow((y | 0), ( + (Math.fround(y) ** y))) | 0) | 0) - ((0.000000000000001 <= Math.min(((( + 2**53+2) == Math.fround(Math.PI)) >>> 0), (((y >>> 0) ? (y >>> 0) : Math.PI) >>> 0))) | 0))) >>> 0))) | 0); }); testMathyFunction(mathy2, [-0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -(2**53-2), 0.000000000000001, 2**53+2, 2**53-2, Number.MAX_VALUE, Math.PI, -0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0x100000000, 0x100000001, 42, 0x0ffffffff, 1/0, 0x080000000, 1.7976931348623157e308, 2**53, -0x080000001, Number.MIN_VALUE, -0x100000000, 1, -0x0ffffffff, -1/0, -Number.MIN_VALUE, -0, 0x07fffffff, 0/0, -(2**53)]); ");
/*fuzzSeed-42509072*/count=102; tryItOut("a1.shift(t1);");
/*fuzzSeed-42509072*/count=103; tryItOut("print(o2);");
/*fuzzSeed-42509072*/count=104; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[ /x/g , false, Infinity,  /x/g , false, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, Infinity, function(){}, -Infinity, false,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , false, false, function(){}, Infinity, false,  /x/g , false, Infinity,  /x/g , false, -Infinity, Infinity,  /x/g ,  /x/g , function(){}, Infinity,  /x/g , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, Infinity, false]) { g2.v2 = Object.prototype.isPrototypeOf.call(g1, g2); }");
/*fuzzSeed-42509072*/count=105; tryItOut("\"use strict\"; h2 = {};");
/*fuzzSeed-42509072*/count=106; tryItOut("Array.prototype.shift.call(a2, g2);");
/*fuzzSeed-42509072*/count=107; tryItOut("\"use strict\"; /*iii*/e0.has(i2);/*hhh*/function yhtiil(z = new RegExp(\"\\\\B\", \"im\"), x = x){return x;}\nxtfuwx();/*hhh*/function xtfuwx(eval, e){this.v1 = (o0 instanceof s2);}\n");
/*fuzzSeed-42509072*/count=108; tryItOut("f1(s0);");
/*fuzzSeed-42509072*/count=109; tryItOut("testMathyFunction(mathy3, [[0], (new Number(0)), '0', true, ({toString:function(){return '0';}}), '/0/', (new Number(-0)), (new Boolean(false)), null, undefined, (new String('')), '', 0.1, (function(){return 0;}), objectEmulatingUndefined(), NaN, [], -0, ({valueOf:function(){return 0;}}), 1, ({valueOf:function(){return '0';}}), '\\0', (new Boolean(true)), /0/, false, 0]); ");
/*fuzzSeed-42509072*/count=110; tryItOut("\"use strict\"; for(x in (4277)) {f1.__proto__ = e2;o0.o2.v1 = Object.prototype.isPrototypeOf.call(v0, b1); }var a = x;with({a: x}){throw x; }");
/*fuzzSeed-42509072*/count=111; tryItOut("a0[6] = e0;");
/*fuzzSeed-42509072*/count=112; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    {\n      i2 = (i0);\n    }\n    return (((i0)-((-0xfffff*(i3)))))|0;\n  }\n  return f; })(this, {ff: Date.prototype.setMinutes}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-42509072*/count=113; tryItOut("for (var v of b0) { try { a1.sort((function mcc_() { var dztsrk = 0; return function() { ++dztsrk; f1(/*ICCD*/dztsrk % 8 == 0);};})()); } catch(e0) { } t1 = t1.subarray(v2, 17); }");
/*fuzzSeed-42509072*/count=114; tryItOut("a0.forEach((function mcc_() { var xodtdw = 0; return function() { ++xodtdw; if (/*ICCD*/xodtdw % 3 == 1) { dumpln('hit!'); s1 = this.a2.join(s0, f2); } else { dumpln('miss!'); try { h2.toSource = (function(j) { f0(j); }); } catch(e0) { } try { selectforgc(o1); } catch(e1) { } try { i1.next(); } catch(e2) { } /*MXX3*/g2.Number.isSafeInteger = g0.Number.isSafeInteger; } };})());");
/*fuzzSeed-42509072*/count=115; tryItOut("mathy2 = (function(x, y) { return mathy1(Math.fround(Math.cbrt(Math.fround(( ! (Math.fround(((x * 0/0) / Math.fround(( + -Number.MAX_VALUE)))) | 0))))), Math.fround((( ! ((Math.fround(Math.pow((Math.cosh((0x100000001 | 0)) | 0), Math.fround(( - -0x07fffffff)))) >> Math.hypot(Math.log(( + ((x >>> 0) > (-(2**53-2) >>> 0)))), y)) | 0)) >>> 0))); }); testMathyFunction(mathy2, [2**53, Math.PI, 0.000000000000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -(2**53), 1.7976931348623157e308, -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0, -0x080000001, 0x07fffffff, -1/0, -0x100000000, 42, 0x080000000, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 1, -Number.MIN_VALUE, -0x080000000, -0, 1/0, 2**53-2, 0x100000000, -0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-42509072*/count=116; tryItOut("mathy5 = (function(x, y) { return (Math.imul((Math.sin((((( + Math.atan2(x, ( + (mathy1((x >>> 0), (0.000000000000001 >>> 0)) ? y : x)))) / ( + (Math.fround(Math.max(Math.fround(x), Math.fround(y))) ? (Math.atan2((1.7976931348623157e308 >>> 0), -0x100000001) >>> 0) : y))) >>> 0) <= ( + mathy3(Math.fround((Math.fround(( - x)) == Math.fround((Math.expm1(Math.fround(y)) | 0)))), ( + ( ~ x)))))) >>> 0), Math.min(Math.fround((Math.fround(0x080000000) >>> (x || y))), Math.fround(Math.fround((y ? (( ! (( ! y) % x)) | 0) : x))))) >>> 0); }); testMathyFunction(mathy5, [/0/, (new Boolean(false)), (function(){return 0;}), null, 0.1, undefined, false, 0, [0], (new Boolean(true)), (new Number(0)), (new String('')), NaN, '', '0', '/0/', ({valueOf:function(){return 0;}}), (new Number(-0)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), 1, true, '\\0', -0, [], ({toString:function(){return '0';}})]); ");
/*fuzzSeed-42509072*/count=117; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42509072*/count=118; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.tanh(( + Math.asinh(Math.fround(Math.atan(((Math.round(( + (Math.min(x, (Math.min(( + y), -0x0ffffffff) | 0)) >= ( + x)))) | 0) >>> 0))))))); }); ");
/*fuzzSeed-42509072*/count=119; tryItOut("function shapeyConstructor(mmcbln){for (var ytqgonpjm in mmcbln) { }delete mmcbln[new String(\"6\")];return mmcbln; }/*tLoopC*/for (let c of /*FARR*/[]) { try{let yvtwaj = shapeyConstructor(c); print('EETT'); v1 = this.r1.unicode;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-42509072*/count=120; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\W)|(?:$)\\\\W{4}\", \"ym\"); var s = \"0\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-42509072*/count=121; tryItOut("mathy2 = (function(x, y) { return ((( + Math.exp(( + Math.max(Math.fround(( ~ (((y | 0) >= (Math.fround(( ! -0x100000001)) | 0)) | 0))), ( + (mathy0(-Number.MAX_SAFE_INTEGER, (mathy1(y, Math.acos(Math.hypot(0, 0))) | 0)) >>> 0)))))) * ((((Math.acos(((Math.fround(mathy0(Math.fround((x & 2**53-2)), Math.fround((mathy0((y >>> 0), (y >>> 0)) >>> 0)))) === Math.max((x >= x), mathy0(y, Math.fround(Math.hypot(Math.fround(y), Math.fround(y)))))) | 0)) | 0) < ( + Math.log(y))) | 0) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[new (function () { return 1 } )(NaN), new (function () { return 1 } )(NaN), (-1/0), (-1/0), new (function () { return 1 } )(NaN), (-1/0), new (function () { return 1 } )(NaN), new (function () { return 1 } )(NaN), (-1/0), (-1/0), (-1/0), new (function () { return 1 } )(NaN), (-1/0), new (function () { return 1 } )(NaN), new (function () { return 1 } )(NaN), new (function () { return 1 } )(NaN), new (function () { return 1 } )(NaN), (-1/0), new (function () { return 1 } )(NaN)]); ");
/*fuzzSeed-42509072*/count=122; tryItOut("v0 + '';");
/*fuzzSeed-42509072*/count=123; tryItOut("let y = (new (/*RXUE*/ \"\" .exec(\"\\n\"))(/*FARR*/[...[]].some)).eval(\"(c);\");window, window, y = eval(\"for (var p in this.e2) { try { g1.o2.a1.reverse(); } catch(e0) { } try { o0.h1 + ''; } catch(e1) { } Array.prototype.shift.call(a2); }\"), \u3056, x =  /x/ , ipmlxl, e, bijtmb, x;print(Math.cbrt(String.prototype.anchor.prototype));");
/*fuzzSeed-42509072*/count=124; tryItOut("\"use strict\"; /*bLoop*/for (abspiy = 0, x = (function(y) { \"use strict\";  '' ; }).call(/(?!(?!(\\S)))/yim, ); abspiy < 64; ++abspiy) { if (abspiy % 2 == 1) { s1 = o0.o1.a1.join(h0); } else { /*RXUB*/var r = r2; var s = s1; print(s.search(r));  }  } ");
/*fuzzSeed-42509072*/count=125; tryItOut("mathy4 = (function(x, y) { return (((Math.log(mathy2(1, ( + x))) >>> 0) >= Math.fround((((Math.fround(Math.max(x, Math.fround((Math.atan2(x, x) != (Math.abs(x) >>> 0))))) ? x : ( + ( - ( + (x & Math.fround(x)))))) >>> 0) & Math.fround(Math.max(( + Math.atan2(0x0ffffffff, Math.fround(( ! (mathy0(y, (x | 0)) | 0))))), ( + Math.atan2(Math.fround(Math.imul(Math.fround((( ~ (x | 0)) | 0)), (x ** x))), 0x0ffffffff))))))) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[ /x/ ,  /x/ , objectEmulatingUndefined(), -2, objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ ,  /x/ , -2,  /x/ , -2, -2, objectEmulatingUndefined(), -2, objectEmulatingUndefined(),  /x/ ,  /x/ , -2,  /x/ , objectEmulatingUndefined(),  /x/ , -2, objectEmulatingUndefined(),  /x/ ,  /x/ , -2, -2,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , -2, -2, objectEmulatingUndefined(), -2, -2, -2,  /x/ , objectEmulatingUndefined(),  /x/ , -2, -2, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , -2,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), -2,  /x/ ,  /x/ , objectEmulatingUndefined(), -2, -2, -2, objectEmulatingUndefined(), -2,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), -2, -2,  /x/ ,  /x/ , objectEmulatingUndefined(), -2,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), -2, -2, objectEmulatingUndefined(),  /x/ , -2, -2, -2, objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), -2,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , -2, objectEmulatingUndefined(),  /x/ ]); ");
/*fuzzSeed-42509072*/count=126; tryItOut("mathy3 = (function(x, y) { return Math.log(Math.sign(Math.max(( + Math.ceil((-Number.MIN_SAFE_INTEGER | 0))), y))); }); testMathyFunction(mathy3, [-0x100000000, 1, 0, 2**53, 0x100000001, 1/0, 0x080000000, -1/0, -(2**53+2), -0, 0x07fffffff, 0/0, 42, -0x100000001, 2**53+2, 0x080000001, Number.MAX_VALUE, -0x080000000, 0x100000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -0x0ffffffff, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=127; tryItOut("\"use strict\"; i2 + '';");
/*fuzzSeed-42509072*/count=128; tryItOut("if((x % 8 == 4)) { if (-10) m2 = t0[v0]; else continue L;}");
/*fuzzSeed-42509072*/count=129; tryItOut("o0.o1.g0.m1.has((timeout(1800) ^= (({ get \"17\" a (this, w, ...x) { \"use strict\"; undefined; }  }))) ? ((makeFinalizeObserver('tenured')).watch(\"toSource\",  /x/g .unshift)) : Object.defineProperty(\n13\u000c, \"for\", ({})));");
/*fuzzSeed-42509072*/count=130; tryItOut("mathy5 = (function(x, y) { return ((Math.exp(( ~ (x ^ Math.pow(x, (y | 0))))) % (( - (Math.round(Math.fround(Math.fround((Math.fround(x) / ( + y))))) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-42509072*/count=131; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.acosh(Math.hypot(Math.ceil(Math.fround(x)), ( + ( - ( + (( + 1/0) || (x | 0)))))))); }); ");
/*fuzzSeed-42509072*/count=132; tryItOut("h0 = t1[({valueOf: function() { { void 0; minorgc(true); }const x = this & this;return 1; }})];");
/*fuzzSeed-42509072*/count=133; tryItOut("a0 = t0[0];");
/*fuzzSeed-42509072*/count=134; tryItOut("\"use strict\"; switch(x = x) { default: Object.defineProperty(this, \"g1.b2\", { configurable: -5, enumerable: true,  get: function() {  return new SharedArrayBuffer(2); } });function e({}) { yield  \"\"  } print(x);break; let b = (4277), w, swlfdk, z = (4277);a1.unshift(g0, i0);case 3: case 0: case ( /* Comment */null):  }\u000c");
/*fuzzSeed-42509072*/count=135; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=136; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.expm1(Math.fround(Math.max(-Number.MAX_SAFE_INTEGER, ( + ( + (( + x) <= ( + ( ~ Math.exp(y))))))))) || Math.log1p((( ! (Math.asinh(Math.fround(( ~ Math.fround(Math.PI)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [-(2**53), Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, 0, 1, 0.000000000000001, -1/0, 0x0ffffffff, -0x100000000, 42, 2**53+2, 0x07fffffff, 0x080000000, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, -0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 1/0, -0, 0/0, -Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, Number.MAX_VALUE, 2**53-2, -0x07fffffff, 0x080000001, Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-42509072*/count=137; tryItOut("this.zzz.zzz;");
/*fuzzSeed-42509072*/count=138; tryItOut("print(x);");
/*fuzzSeed-42509072*/count=139; tryItOut("a2 = arguments.callee.arguments;");
/*fuzzSeed-42509072*/count=140; tryItOut("testMathyFunction(mathy4, [1.7976931348623157e308, -0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -1/0, 2**53, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, -0x100000000, -0x080000001, 2**53-2, -Number.MIN_VALUE, -(2**53), -(2**53+2), 0x100000001, 0.000000000000001, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 2**53+2, -0, 0, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, 1/0, 0/0, 1]); ");
/*fuzzSeed-42509072*/count=141; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=142; tryItOut("");
/*fuzzSeed-42509072*/count=143; tryItOut("\"-25\" = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: undefined, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: Uint32Array, keys: function() { return Object.keys(x); }, }; })(a = --x), ((p={}, (p.z = ({x:  /x/g }))())), q => q);");
/*fuzzSeed-42509072*/count=144; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?=[^\\B-\\\u1764\\r-\\\\w\\xbB-\u00f5])*?)|\\B+\u00ce|\\b*/gym; var s = \"\\u00ee 9a\\u0094\\u00ee 9a\\u0094\\u7d85\\u00ee\"; print(s.replace(r, function  eval (x)\n({z: (window(new RegExp(\"(?!\\\\r)\", \"ym\")))}), \"gyim\")); ");
/*fuzzSeed-42509072*/count=145; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.atan2(Math.expm1(( ~ Math.hypot((-0x080000000 >> y), 0/0))), Math.hypot(( + (( ! Math.fround(y)) | 0)), ( + Math.hypot(( + x), ( + y))))); }); testMathyFunction(mathy5, [1/0, 0, -0x07fffffff, 0x100000001, 2**53-2, -0x080000000, 0x100000000, -(2**53-2), 2**53, 0.000000000000001, Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 42, 2**53+2, 1.7976931348623157e308, -0, -1/0, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -(2**53+2), Math.PI, -Number.MIN_VALUE, 1, -0x100000001]); ");
/*fuzzSeed-42509072*/count=146; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.acos(((( ! ((Math.expm1(Math.min(y, (x * Number.MAX_VALUE))) | 0) > ((( - (y | 0)) | 0) | 0))) | 0) | 0)) | 0); }); testMathyFunction(mathy2, [0, 42, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, -0x100000001, 1, -Number.MAX_VALUE, -0x080000000, 0.000000000000001, 1/0, 1.7976931348623157e308, 2**53, -0x07fffffff, 0x0ffffffff, 0x100000000, 0/0, 2**53-2, -(2**53), -1/0, 0x07fffffff, -(2**53+2), -0x080000001, -0x100000000, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, 0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=147; tryItOut("/*RXUB*/var r = /([\\cC-\\u0020\\w]+(?!\\2+?)*?)|\\3/i; var s = \"\"; print(s.split(r)); \ne1.__proto__ = h0;\n");
/*fuzzSeed-42509072*/count=148; tryItOut("\"use strict\"; const ogmzge, oaoudk, z = eval(\"for (var p in i0) { o0.f1 = Proxy.createFunction(h1, f1, f0); }\", NaN = 24);/* no regression tests found */");
/*fuzzSeed-42509072*/count=149; tryItOut("\"use strict\"; yield;print(x);");
/*fuzzSeed-42509072*/count=150; tryItOut("{ void 0; deterministicgc(true); } print([! '' ]);");
/*fuzzSeed-42509072*/count=151; tryItOut("mathy0 = (function(x, y) { return (Math.ceil((((Math.fround(((y >> Math.fround(-(2**53-2))) || x)) >> ((1 ? ((Math.atan2(y, (y >>> 0)) ? (y >>> 0) : (Math.fround(Math.pow(Math.asinh(Math.max(x, x)), y)) >>> 0)) >>> 0) : y) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[({}), ({}), this, ({}), this, ({}), ({}), this, ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), this, ({})]); ");
/*fuzzSeed-42509072*/count=152; tryItOut("testMathyFunction(mathy3, [-Number.MAX_VALUE, 1, Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, Math.PI, -0x080000000, 0x100000001, 0/0, -1/0, 0, Number.MAX_VALUE, 0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, 42, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 2**53-2, 2**53, -(2**53-2), -0, -0x100000000, 0x080000000, -(2**53+2), 0x100000000, -0x100000001, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-42509072*/count=153; tryItOut("for(let e of /*MARR*/[[], [], function(){}, function(){}, function(){}, eval, function(){}, function(){}, function(){}, eval, [], [], eval, function(){}, function(){}, eval, [], function(){}, function(){}, function(){}, eval, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, eval, [], eval, function(){}, function(){}, eval, [], eval, function(){}, function(){}, [], function(){}, function(){}, function(){}, function(){}, function(){}, eval, [], [], eval, [], function(){}, function(){}, eval, eval, function(){}, function(){}, [], [], [], function(){}, function(){}, eval, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, eval, function(){}, function(){}, [], function(){}, function(){}, function(){}]) print(e);throw x;");
/*fuzzSeed-42509072*/count=154; tryItOut("o0.e2.valueOf = (function() { try { this.g0 = this; } catch(e0) { } try { /*RXUB*/var r = o0.r0; var s = \"\"; print(s.search(r));  } catch(e1) { } try { e0.has(s0); } catch(e2) { } i0.next(); return t0; });");
/*fuzzSeed-42509072*/count=155; tryItOut("{ void 0; try { setJitCompilerOption('ion.enable', 0); } catch(e) { } } /* no regression tests found */");
/*fuzzSeed-42509072*/count=156; tryItOut("\"use strict\"; ;");
/*fuzzSeed-42509072*/count=157; tryItOut("neuter(this.b2, \"change-data\");");
/*fuzzSeed-42509072*/count=158; tryItOut(";");
/*fuzzSeed-42509072*/count=159; tryItOut("\"use strict\"; Array.prototype.sort.call(o1.a0, (function() { try { a2.pop(); } catch(e0) { } try { a2[(this = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: w =>  { \"use strict\"; v0 = a2.reduce, reduceRight((function() { try { Object.defineProperty(this, \"a2\", { configurable: false, enumerable: true,  get: function() {  return Array.prototype.map.call(a0, (function() { try { a1[({valueOf: function() { yield;return 9; }})] =  \"\" ; } catch(e0) { } try { a0 = a2[({valueOf: function() { return  \"\" ;return 19; }})]; } catch(e1) { } try { a1[v2]; } catch(e2) { } g0.a1.forEach((function(j) { if (j) { try { v2 = undefined; } catch(e0) { } v2 = (a0 instanceof o0.s1); } else { try { m0.has(b0); } catch(e0) { } m2 = new Map(o0); } }), \"\\uAACF\"); return a1; })); } }); } catch(e0) { } for (var v of m1) { try { t2.set(t0, 13); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(e0, o0.t2); } catch(e1) { } try { o1 = o1.a2; } catch(e2) { } t0 = t1.subarray(e, ({valueOf: function() { return 15; }})); } return v0; }), 67108863); } , iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(\"\\u769A\"), q => q))]; } catch(e1) { } v2 = g1.runOffThreadScript(); return f0; }), ((Object.getOwnPropertyDescriptor).call(eval(\"/* no regression tests found */\", ((window = x))), (void shapeOf(x)))));");
/*fuzzSeed-42509072*/count=160; tryItOut("g2.offThreadCompileScript(\"v0 = g1.g2.eval(\\\"for (var v of o0) { v2 = new Number(g0.e1); }\\\");\");");
/*fuzzSeed-42509072*/count=161; tryItOut("{(this);i1 + ''; }");
/*fuzzSeed-42509072*/count=162; tryItOut("/*RXUB*/var r = /(?!\\2(?=[\u463f]){4,}\\xBd\u3f81?){0,0}/gim; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-42509072*/count=163; tryItOut("for (var p in g2) { try { g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: Math.ceil((new (function(y) { \"use asm\"; yield y; o1.f2.valueOf = (function() { try { Array.prototype.sort.call(a1, f1, e2, b2); } catch(e0) { } try { Object.defineProperty(this, \"v1\", { configurable:  '' , enumerable: (y % 3 != 2),  get: function() {  return evalcx(\"function f2(this.a0)  { yield \\\"\\\\uBFA5\\\" } \", g0); } }); } catch(e1) { } print(uneval(m0)); return this.o2; });; yield y; })( /x/ ))), sourceIsLazy: (makeFinalizeObserver('tenured')), catchTermination: [1] })); } catch(e0) { } try { m1.has(g2); } catch(e1) { } try { t2 = t2.subarray(16, 14); } catch(e2) { } e0 = t2[11]; }");
/*fuzzSeed-42509072*/count=164; tryItOut("(([,,] / y).yoyo(\u3056 = null));\n/*tLoop*/for (let e of /*MARR*/[x, x, x, x, new Number(1.5), new Number(1.5), new Number(1.5), x, x, new Number(1.5), x, new Number(1.5), x, x, x, x, new Number(1.5), x, x, new Number(1.5), x, new Number(1.5), new Number(1.5), x, x, new Number(1.5), x, new Number(1.5), x, new Number(1.5), new Number(1.5), x, x, x, x, new Number(1.5), new Number(1.5), new Number(1.5), x, x, new Number(1.5), x]) { i1.send(o2.a1); }\n");
/*fuzzSeed-42509072*/count=165; tryItOut("f0 = Proxy.createFunction(h0, f1, o2.f0);");
/*fuzzSeed-42509072*/count=166; tryItOut("testMathyFunction(mathy3, [-1/0, 0x100000001, -Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), 0/0, -0x080000001, 0x080000001, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 2**53+2, 42, 2**53, -(2**53), -0x100000001, 1/0, Math.PI, -0x080000000, -0, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, -0x100000000, 1.7976931348623157e308, 0x100000000]); ");
/*fuzzSeed-42509072*/count=167; tryItOut("\"use strict\"; v0 = new Number(0);");
/*fuzzSeed-42509072*/count=168; tryItOut("{ /x/g ; }");
/*fuzzSeed-42509072*/count=169; tryItOut("\"use strict\"; selectforgc(o2);\n/* no regression tests found */\n");
/*fuzzSeed-42509072*/count=170; tryItOut("o2 + '';");
/*fuzzSeed-42509072*/count=171; tryItOut("/*bLoop*/for (zazxgj = 0, yield (Math.imul(22, 16)); zazxgj < 83; ++zazxgj) { if (zazxgj % 76 == 22) { ([] = NaN); } else { /*vLoop*/for (let okqrvi = 0; okqrvi < 19; ++okqrvi) { let b = okqrvi; print(x); }  }  } ");
/*fuzzSeed-42509072*/count=172; tryItOut("g1.a1.sort((function() { try { f1.toSource = f1; } catch(e0) { } try { delete o1[\"caller\"]; } catch(e1) { } try { e2.add((p={}, (p.z = x)())); } catch(e2) { } h0 + f2; return g0.m0; }), p2, b0, a0, h0, i1, b0, s1, t0);");
/*fuzzSeed-42509072*/count=173; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.fround(mathy2(( + ( ~ (( ~ 0x0ffffffff) | 0))), (Number.MIN_SAFE_INTEGER > Math.cbrt((-Number.MAX_VALUE | 0))))), Math.atan2(Math.atan2(((Math.tan(y) >>> 0) >>> (( + ( - (( + (( + y) + ( + (Math.log(y) >>> 0)))) | 0))) >>> 0)), Math.exp((y >>> 0))), ( + (( + ( + ((y | 0) | (x | 0)))) ^ Math.fround((Math.hypot(x, ( - Math.fround(((x >>> 0) > Math.fround(-Number.MIN_SAFE_INTEGER))))) >>> 0)))))); }); testMathyFunction(mathy4, ['/0/', ({valueOf:function(){return 0;}}), 1, 0, true, ({toString:function(){return '0';}}), (new Boolean(false)), (new Boolean(true)), '', /0/, false, [], ({valueOf:function(){return '0';}}), (new Number(0)), '0', (new String('')), (function(){return 0;}), objectEmulatingUndefined(), NaN, -0, (new Number(-0)), undefined, '\\0', 0.1, null, [0]]); ");
/*fuzzSeed-42509072*/count=174; tryItOut("i1.next();");
/*fuzzSeed-42509072*/count=175; tryItOut("-19//h\n;print(uneval(h1));");
/*fuzzSeed-42509072*/count=176; tryItOut("/*MXX3*/g1.Map.prototype.entries = g0.Map.prototype.entries;");
/*fuzzSeed-42509072*/count=177; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x07fffffff, -0, 2**53, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 1, 2**53+2, -0x100000000, -Number.MAX_VALUE, -0x100000001, -(2**53), 1.7976931348623157e308, 0x100000000, -(2**53+2), 0/0, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, 42, 0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, 2**53-2, 1/0, 0x100000001, -1/0, -0x080000000]); ");
/*fuzzSeed-42509072*/count=178; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\\u0083\"; print(s.search(r)); ");
/*fuzzSeed-42509072*/count=179; tryItOut("\"use asm\"; const x, eval, dkehev, csvvqr;g2.toSource = (function(j) { g2.f1(j); });");
/*fuzzSeed-42509072*/count=180; tryItOut("o2.i2 = new Iterator(o2.f0, true);");
/*fuzzSeed-42509072*/count=181; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!.)|[^]*?\\\\u00BD\\\\b*\\\\D{2,6}|^(?!((?:[^])+)+)|(?=\\\\3)(?=(?=\\\\1)*?)|\\\\B+\", \"gi\"); var s = \"\\n\\naaaaaaaaaaaa\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-42509072*/count=182; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xf8076eec);\n    i1 = ((((\n(x = function(id) { return id }) -= window = 0)+((0xd737943) != (0x71336a19))) >> (-0x95a23*(i1))));\n    {\n      d0 = (((Infinity)) / (((((((0xf9af7084)) ^ ((-0x8000000)))) ? (i1) : ((((0xf9379204)) ^ ((0xfb4fe78e))))) ? (+atan2((((-1.1805916207174113e+21) + (+abs(((32769.0)))))), ((NaN)))) : (d0))));\n    }\n    i1 = (i1);\n    i1 = (i1);\n    {\n      d0 = (d0);\n    }\n    {\n      d0 = (-((+((((null)) / (((-22) * ((d0)))))))));\n    }\n    i1 = (!((0x3f0a834a) < ((-((x)))|0)));\n    return (((~~(d0)) % ((((0x31fd433e))+(0xb46ba286)) << ((i1)))))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0, 1.7976931348623157e308, Number.MAX_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 1/0, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, 0x080000000, 0.000000000000001, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, -0, 42, 0x100000001, Number.MIN_VALUE, -(2**53-2), 1, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, -0x080000000, -0x07fffffff, -0x100000000, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, 0/0, 0x080000001]); ");
/*fuzzSeed-42509072*/count=183; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.hypot(((( + Math.fround((Math.fround((Math.PI + (Math.atanh((x >>> 0)) >>> 0))) - Math.pow(x, (Math.hypot(( + -(2**53-2)), ( + Number.MAX_SAFE_INTEGER)) | 0))))) % ((Math.pow(y, y) >>> 0) | 0)) | 0), Math.cbrt((y > Math.acos(Math.imul(( + Math.min(( + y), ( + x))), Math.atan2(y, y)))))) >>> 0) + Math.trunc(Math.fround(((Number.MAX_VALUE / Math.clz32(( + y))) ? ( + Math.atan2(x, ( + 0/0))) : Math.fround(Math.sqrt(( + 2**53+2))))))); }); testMathyFunction(mathy0, /*MARR*/[ /x/ ,  /x/ , 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  /x/ ,  /x/ ,  /x/ , 3, 3, 3,  /x/ , 3, 3,  /x/ ,  /x/ , 3, 3,  /x/ ,  /x/ , 3, 3, 3, 3,  /x/ , 3,  /x/ , 3,  /x/ , 3]); ");
/*fuzzSeed-42509072*/count=184; tryItOut("mathy2 = (function(x, y) { return Math.pow((((0x07fffffff , Math.fround(Math.cos((y | 0)))) >>> 0) & ( - ( + (( + Math.fround(( + Math.fround(Math.hypot(-Number.MIN_VALUE, x))))) >> x)))), ( + ( + ( + ( + ( - ( + x))))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, -(2**53), -0x07fffffff, 0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, 2**53+2, -0x100000000, 2**53-2, 1/0, Number.MIN_VALUE, 2**53, -0, -0x080000000, 0x100000001, 0, Number.MIN_SAFE_INTEGER, Math.PI, 42, -(2**53-2), -1/0, -Number.MAX_VALUE, 1, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001]); ");
/*fuzzSeed-42509072*/count=185; tryItOut("var metxol = new ArrayBuffer(4); var metxol_0 = new Float64Array(metxol); print(metxol_0[0]); var metxol_1 = new Uint8ClampedArray(metxol); print(metxol_1[0]); print(Math.pow(null, window));a2.length =  '' ;;");
/*fuzzSeed-42509072*/count=186; tryItOut("mathy1 = (function(x, y) { return ((mathy0(((Math.log(((((x >>> 0) == (0x0ffffffff >>> 0)) >>> 0) >>> 0)) >>> 0) / -0x100000000), x) >= ( + (y | 0))) < Math.expm1((( + (x === Math.fround(Math.min(Math.fround(( + Math.hypot((x | 0), ( + x)))), Math.fround(-(2**53-2)))))) >>> 0))); }); ");
/*fuzzSeed-42509072*/count=187; tryItOut("\"use strict\"; {m1.set( /x/ , p1);m1.has(e0); }");
/*fuzzSeed-42509072*/count=188; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let e of /*MARR*/[x, NaN, NaN, NaN, NaN,  \"\" , x, NaN, 0x100000001,  \"\" ]) { g2.t0.set(t0, 7); }");
/*fuzzSeed-42509072*/count=189; tryItOut(";");
/*fuzzSeed-42509072*/count=190; tryItOut("Object.prototype.watch.call(o1.e1, new String(\"12\"), let (y = new RegExp(\"(?=\\\\B)\", \"gim\"), e) x.getUint16);");
/*fuzzSeed-42509072*/count=191; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=192; tryItOut("v1 = evalcx(\"/*bLoop*/for (var xublew = 0; xublew < 59; ++xublew) { if (xublew % 29 == 2) { g1[\\\"italics\\\"] = m0; } else { print(\\\"\\\\uDD01\\\");\\ne2 = new Set(t0);\\n }  } \", g0);");
/*fuzzSeed-42509072*/count=193; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+ceil(((d0))));\n    (Int32ArrayView[((((((-6.189700196426902e+26) <= (8796093022209.0)))>>>((/*FFI*/ff(((-8796093022209.0)), ((-562949953421313.0)), ((-3.0)), ((-274877906943.0)), ((-281474976710657.0)), ((0.0009765625)), ((-134217729.0)), ((32769.0)), ((-524289.0)))|0)-((0x2978e92c) > (0x6c6ca59c)))))+((imul(((-0x8000000) ? (0x9f5e1f8f) : (0xf8981abe)), (0xfbf340f8))|0))) >> 2]) = ((0x7fffffff));\n    d0 = (+/*FFI*/ff(((+pow(((d0)), ((d0)))))));\n    return (((0x1444be58)-(0xffab388e)+(0x599a127)))|0;\n  }\n  return f; })(this, {ff: z => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return ((((((i0)) >> ((0x58c90571)+(((65536.0) > (-70368744177664.0)) ? (i0) : ((0x99858461)))+(((0x8a482698)) ? (0x5a5a4d08) : ((0xe59587af) ? (0x2fb933f0) : (0xeef65ae3))))))+(i0)))|0;\n  }\n  return f;\u0009}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0, -Number.MIN_SAFE_INTEGER, -0x080000000, 0, 0/0, -Number.MAX_VALUE, 0x100000000, -0x07fffffff, -Number.MIN_VALUE, 0x100000001, 2**53-2, 1/0, -0x0ffffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, 0x080000001, -(2**53), 1, -0x080000001, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 0x0ffffffff, 2**53, 0x080000000, Math.PI, -0x100000001, -0x100000000, 0.000000000000001, -(2**53+2)]); ");
/*fuzzSeed-42509072*/count=194; tryItOut("\"use strict\"; \"use asm\"; v1 = g1.eval(\"-16\");o2.a2.sort((function mcc_() { var khexft = 0; return function() { ++khexft; if (/*ICCD*/khexft % 4 == 3) { dumpln('hit!'); Array.prototype.pop.call(a1); } else { dumpln('miss!'); for (var p in s1) { this.a2[2] =  /x/ ; } } };})());a1 = r1.exec(s1);const x = (void options('strict_mode'));\n");
/*fuzzSeed-42509072*/count=195; tryItOut("\"use strict\"; let eval = let (x =  \"\" , x, x, window) x, x = window, piccya, y, x = \"\\uFCA5\", x, heughf, x, window, tjobuo;o2 = o0;");
/*fuzzSeed-42509072*/count=196; tryItOut("\"use strict\"; let a = (allocationMarker());print(this.f2);");
/*fuzzSeed-42509072*/count=197; tryItOut("for (var p in a0) { i1.send(a1); }");
/*fuzzSeed-42509072*/count=198; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((Math.hypot(Math.fround(( + Math.fround(((2**53-2 === y) | ((x >> y) | 0))))), Math.imul((Math.log2(x) | 0), Math.hypot(( + x), ( + Math.asinh(x))))) | 0) === ((Math.max(((Math.hypot((( + Math.fround(Math.min(( + x), ( ! Math.tan(x))))) >>> 0), ((Math.atan2(((( ~ (x >>> 0)) >>> 0) | 0), (( ~ (x | 0)) | 0)) | 0) >>> 0)) >>> 0) >>> 0), ( - (( ~ (-0x100000000 >>> 0)) >>> 0))) >>> 0) | 0)) | 0); }); ");
/*fuzzSeed-42509072*/count=199; tryItOut("x = -20, daaegf, x, y = x, wnqskz, rwqcmf, rhjwyw;vstetp, lzvazo, pqspvp, e, rkwwvt;a2.push(b1, v0, p0);");
/*fuzzSeed-42509072*/count=200; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((+(((i0)*0x475e9) << ((0x609de889)-(i0)))));\n  }\n  return f; })(this, {ff: y =>  { yield (/*RXUE*/new RegExp(\"\\\\\\u00d2\", \"gy\").exec(\"\\u00d2\")); } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0/0, Number.MIN_VALUE, -(2**53-2), 0x100000001, 0.000000000000001, -Number.MIN_VALUE, -(2**53), 0x080000001, Math.PI, -0x080000001, Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0x0ffffffff, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, -0, -0x100000000, 2**53+2, -Number.MAX_VALUE, -0x100000001, 0, 42, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, 1, -0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-42509072*/count=201; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min((Math.fround(( - ((Math.max(Math.acos(y), ( ! x)) != ((Math.fround(x) != x) ? -Number.MIN_SAFE_INTEGER : Number.MAX_VALUE)) >>> 0))) >>> 0), (( - ( ~ ((Math.imul(Number.MAX_VALUE, ( ! Number.MAX_VALUE)) , ((((( - Math.sinh(( + y))) | 0) ? (((y ? ( + (( + x) ? ( + x) : ( + x))) : (-1/0 | 0)) | 0) | 0) : (( + ( + x)) | 0)) | 0) | 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy0, [-0x100000000, Math.PI, 0x100000000, -Number.MIN_VALUE, 2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, Number.MIN_VALUE, 0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -0x080000001, 42, -Number.MAX_VALUE, 2**53, -0, -(2**53-2), 0x080000001, -1/0, Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -(2**53), -(2**53+2), 0x080000000, -0x080000000, 1/0]); ");
/*fuzzSeed-42509072*/count=202; tryItOut("for (var v of i0) { try { g2.t1 = new Uint8Array(g2.a2); } catch(e0) { } try { /*ADP-3*/Object.defineProperty(a1, 0, { configurable: true, enumerable: (x % 6 != 2), writable:  /x/g , value: g2 }); } catch(e1) { } v0 = Object.prototype.isPrototypeOf.call(s2, this.g0); }");
/*fuzzSeed-42509072*/count=203; tryItOut("this.g1.toString = (function() { try { selectforgc(o2); } catch(e0) { } try { Array.prototype.reverse.call(a2, g2, f2, o0.o0); } catch(e1) { } try { for (var p in h0) { try { v1 = t1.length; } catch(e0) { } try { e1.toSource = (function() { for (var j=0;j<7;++j) { f1(j%4==0); } }); } catch(e1) { } g2.h0.enumerate = f2; } } catch(e2) { } print(uneval(m0)); return v2; });");
/*fuzzSeed-42509072*/count=204; tryItOut("/*RXUB*/var r = /((?!\\s{1}))/y; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-42509072*/count=205; tryItOut("/*tLoop*/for (let z of /*MARR*/[false,  /x/g , false,  '\\0' , false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,  '\\0' , (void 0),  '\\0' , false, (void 0), false, (void 0),  '\\0' , (void 0), (void 0),  '\\0' ,  '\\0' , false, (void 0), false, false, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), false,  /x/g ,  '\\0' , (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g , (void 0), (void 0),  '\\0' , (void 0),  '\\0' , (void 0),  '\\0' ,  '\\0' , false, false,  '\\0' ,  /x/g , (void 0),  /x/g , (void 0),  /x/g ,  /x/g ,  '\\0' ,  '\\0' , false,  '\\0' ,  /x/g , (void 0),  /x/g ,  /x/g , (void 0), false, (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  '\\0' , false,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (void 0),  /x/g ,  '\\0' , (void 0),  '\\0' , false,  /x/g ]) { t2[v2] = b1; }");
/*fuzzSeed-42509072*/count=206; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return (( + (Math.imul(Math.sinh((( + Math.max((Math.expm1(x) ? 0.000000000000001 : x), -Number.MAX_VALUE)) | 0)), Math.atan2(Math.clz32(x), (( ! (((Math.fround(( - (-Number.MAX_VALUE > (x >>> 0)))) ^ x) >>> 0) | 0)) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, -1/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_VALUE, 0x100000000, -(2**53), 0x080000000, 0, 0/0, 0x0ffffffff, -0, -0x080000000, -(2**53-2), -0x0ffffffff, 1/0, -Number.MAX_VALUE, Math.PI, -(2**53+2), 1.7976931348623157e308, -0x07fffffff, 0x100000001, -0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0x080000001, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-42509072*/count=207; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return ( ~ ( ~ ( + ( ! x)))); }); testMathyFunction(mathy5, [-1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, Number.MIN_VALUE, -0x100000001, -(2**53-2), 2**53, 0, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, 0x080000000, -Number.MAX_VALUE, 0x080000001, -0, -0x080000000, 0.000000000000001, 0x07fffffff, 0x100000000, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, 0x100000001, 2**53-2, -0x0ffffffff, Math.PI, 2**53+2, -0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-42509072*/count=208; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.max(Math.fround((((x / (x > ( ! Math.sin(0x080000000)))) ? x : x) >> Math.atanh(x))), mathy2(((((Math.cosh((x >>> 0)) >>> 0) >>> 0) - mathy0((y >>> 0), (y >>> 0))) >>> 0), ( + ( ~ y)))); }); ");
/*fuzzSeed-42509072*/count=209; tryItOut("/*tLoop*/for (let y of /*MARR*/[new Number(1.5), new Number(1.5), undefined, new Number(1.5), undefined,  '\\0' , undefined, new Number(1.5), undefined, new Number(1.5), x, new Number(1.5),  '\\0' ,  '\\0' , new Number(1.5), new Number(1.5),  '\\0' , undefined, new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' , x, undefined, x, x, new Number(1.5), x, undefined, x, undefined, undefined, x, new Number(1.5), x,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , x, new Number(1.5)]) { h1.set = f0; }");
/*fuzzSeed-42509072*/count=210; tryItOut("v1 = this.a1.every((function(j) { f2(j); }));");
/*fuzzSeed-42509072*/count=211; tryItOut("mathy4 = (function(x, y) { return (Math.pow((Math.expm1(( + ( + Math.abs(( + Math.sqrt(( + ( - Math.fround(0x080000000))))))))) | 0), Math.min(Math.hypot((( + Math.atanh(x)) ? (x >>> 0) : ( + Math.pow(-0x080000000, Math.fround(Math.max(0/0, (( ! (x | 0)) | 0)))))), mathy1(( ~ x), Math.fround(Math.expm1(Math.fround(Math.fround((x >> x))))))), Math.fround(Math.sqrt(Math.fround(( ~ y)))))) | 0); }); testMathyFunction(mathy4, [0, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, -(2**53), 0x0ffffffff, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 0x100000000, 0x07fffffff, -Number.MAX_VALUE, 0/0, -0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -0, -Number.MIN_VALUE, 0x080000000, -0x080000000, Number.MAX_VALUE, 42, -0x07fffffff, -0x100000001, -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, -1/0, 2**53, 1]); ");
/*fuzzSeed-42509072*/count=212; tryItOut("for (var v of b0) { try { v0 = Array.prototype.every.apply(a2, [(function() { try { /*ADP-1*/Object.defineProperty(a0, 12, ({writable: true, configurable: (x % 19 == 4), enumerable: true})); } catch(e0) { } try { this.v2 = 4.2; } catch(e1) { } try { for (var v of f1) { try { m1.toSource = (function() { for (var j=0;j<30;++j) { f1(j%4==1); } }); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a2, (4277), ({set: function(y) { /* no regression tests found */ }, configurable: (x % 6 != 0)})); } catch(e1) { } o2.s0 += this.s0; } } catch(e2) { } Array.prototype.sort.call(o2.o0.a1); return e0; })]); } catch(e0) { } try { Array.prototype.splice.apply(a0, [o2]); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(f2, g1.a0); } catch(e2) { } print(g0.g2.f0); }");
/*fuzzSeed-42509072*/count=213; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((((Math.fround(( + (( ! y) <= y))) >> ( + Math.hypot(( + Math.fround(( + Math.fround((Math.hypot(0x100000000, 1.7976931348623157e308) >>> 0))))), Math.fround((x !== y))))) | 0) >>> 0) != (( ! (Math.hypot(Math.fround((Math.fround((Math.fround(x) >> Math.fround(Math.hypot(-(2**53+2), y)))) * x)), Math.fround((((( - x) >>> 0) ? (Math.asinh((x > x)) >>> 0) : ((Math.log10(0x07fffffff) < y) >>> 0)) >>> 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [1, 0.000000000000001, Number.MIN_VALUE, -0x100000001, 0x080000000, Number.MAX_VALUE, -0x0ffffffff, 0x100000001, 0, -1/0, -0x07fffffff, 2**53+2, 0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, -(2**53), -(2**53+2), -Number.MAX_VALUE, 42, 0x080000001, Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, 1.7976931348623157e308, 2**53, 0x100000000, Math.PI]); ");
/*fuzzSeed-42509072*/count=214; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var cos = stdlib.Math.cos;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i0 = ((abs((((/*FFI*/ff(((-4194303.0)), ((+cos(((+cos(((576460752303423500.0)))))))), ((((0xf8699b33)) & ((0xfa33cbc8)))), ((((0xf866b24b))|0)), ((-1.9342813113834067e+25)), ((-1.2089258196146292e+24)), ((4194305.0)), ((524289.0)), ((0.00390625)), ((1.2089258196146292e+24)))|0)) & ((i0))))|0) > (abs((((Int32ArrayView[(/*RXUE*/new RegExp(\"\\\\s|(?=[^\\\\u00DF-\\\\\\u0106\\\\D\\\\D])\\\\W?{4,6}|(?!^)|(?=.)|\\\\w{1,}\", \"g\").exec(\"aa\")) >> 2])) >> ((i3)-(i0))))|0));\n    return (((i3)+(i1)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53+2), 42, Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, -0, 0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53-2), -Number.MAX_VALUE, 2**53+2, 1/0, 0/0, 2**53-2, 0.000000000000001, -0x080000000, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 1, -0x080000001, -0x100000000, Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, 0x100000000, 0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, -0x0ffffffff, -1/0, -(2**53)]); ");
/*fuzzSeed-42509072*/count=215; tryItOut("\"use strict\"; return Math.expm1.prototype;");
/*fuzzSeed-42509072*/count=216; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround((Math.fround(( ~ ( + Math.pow(( + (Math.imul(( + y), Math.fround(y)) >>> 0)), ( + Math.sign(2**53)))))) < Math.fround(( ~ Math.fround(( ! (0x0ffffffff ? ( + 1) : (0x07fffffff ? Number.MAX_VALUE : Number.MAX_VALUE)))))))) - ((((Math.pow((mathy1((( ! (y >>> 0)) >>> 0), Math.atan2(x, y)) | 0), mathy0((y % -Number.MAX_SAFE_INTEGER), -0)) | 0) | 0) , (( + Math.hypot(( - y), ( + Math.cosh(x)))) | 0)) | 0)); }); testMathyFunction(mathy2, [2**53, Number.MAX_VALUE, 0x07fffffff, 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53-2), -0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, -0x07fffffff, -0x100000001, 0x100000000, 0/0, -(2**53+2), 0x080000001, -0x100000000, -0x080000001, -0x0ffffffff, 0, -1/0, Math.PI, Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, -(2**53), 1/0, -Number.MAX_VALUE, 1, 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=217; tryItOut("testMathyFunction(mathy5, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 2**53, 0x07fffffff, 0x0ffffffff, -0x0ffffffff, 0x080000001, Number.MIN_VALUE, -0, -1/0, 1/0, -(2**53), -0x100000000, 0x080000000, 1.7976931348623157e308, 42, -0x080000000, 0, Math.PI, 0.000000000000001, 2**53+2, 0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_VALUE, -(2**53+2), 0/0]); ");
/*fuzzSeed-42509072*/count=218; tryItOut("v1 = a2.length;");
/*fuzzSeed-42509072*/count=219; tryItOut("Array.prototype.sort.apply(a1, [(function mcc_() { var lwvevb = 0; return function() { ++lwvevb; f1(/*ICCD*/lwvevb % 8 == 5);};})(), o1, a0, s0, m0, m2]);");
/*fuzzSeed-42509072*/count=220; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      d0 = (2.3611832414348226e+21);\n    }\n    i2 = (i1);\n    {\n      i2 = (i2);\n    }\n    /*FFI*/ff(((+(-1.0/0.0))), ((d0)));\n    return ((((i2)+(0xda0b5209))))|0;\n  }\n  return f; })(this, {ff: (((function(x, y) { \"use strict\"; return y; })).bind()).bind}, new ArrayBuffer(4096)); ");
/*fuzzSeed-42509072*/count=221; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + Math.sin(y)) && (Math.ceil(((Math.log2((y | 0)) | 0) >> Number.MAX_SAFE_INTEGER)) ? ( ! (Math.fround(x) !== Math.fround(Math.fround(Math.imul((-(2**53+2) >>> 0), 1.7976931348623157e308))))) : (Math.max(( ~ Math.fround(Math.imul(x, y))), (Math.cosh(Math.fround(Math.abs(( + x)))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-42509072*/count=222; tryItOut("mathy4 = (function(x, y) { return (Math.cosh(Math.imul(Math.tan(( - Math.max(Math.imul(x, -0x07fffffff), Math.acosh(x)))), ( + Math.fround(Math.atan2(Math.fround(Number.MIN_VALUE), ( + ( + ( ! x)))))))) | 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 42, -(2**53+2), -(2**53-2), -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, 2**53+2, -(2**53), 0x080000001, -0x100000001, -Number.MIN_VALUE, -0, -0x080000000, 1, -0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, -0x080000001, Math.PI, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0x100000001, 0x100000000, 0.000000000000001, -1/0, 0/0]); ");
/*fuzzSeed-42509072*/count=223; tryItOut("/*vLoop*/for (let poepsu = 0; poepsu < 8 && (x.throw((4277) <<= undefined.eval(\"\\\"use strict\\\"; h2.iterate = f1;\"))); ++poepsu) { var y = poepsu; /* no regression tests found */ } ");
/*fuzzSeed-42509072*/count=224; tryItOut("t0 = t2[4];");
/*fuzzSeed-42509072*/count=225; tryItOut("v0 = (o0.o2 instanceof e2);");
/*fuzzSeed-42509072*/count=226; tryItOut("t2 = new Float32Array(({valueOf: function() { var r0 = x + 4; var r1 = 7 / x; var r2 = 7 - r0; var r3 = r0 * r2; var r4 = 6 ^ 7; var r5 = r0 - x; var r6 = 0 % r3; r2 = 6 * r5; var r7 = r5 % r5; var r8 = r1 ^ r0; var r9 = r4 * r0; var r10 = 8 * r8; var r11 = r5 ^ r9; print(r8); var r12 = 3 + x; var r13 = r8 * r5; print(r13); var r14 = r0 * r10; r0 = r0 / 3; r7 = r0 & r2; var r15 = r14 ^ 2; var r16 = r2 + r12; r4 = r9 - r7; var r17 = 5 * r12; var r18 = r14 & r8; var r19 = 6 + r16; r2 = 9 * r4; var r20 = r12 ^ 1; var r21 = r12 & r20; print(r0); var r22 = r1 - 9; var r23 = r3 ^ r14; r7 = 1 + 6; var r24 = r8 | 7; var r25 = r4 | r21; var r26 = r20 ^ r18; var r27 = r24 % r14; var r28 = r14 % r11; var r29 = 7 + r4; r27 = r29 * 4; var r30 = r14 - r19; var r31 = r24 * r16; var r32 = 6 & r10; var r33 = r27 - r23; var r34 = 8 ^ r8; var r35 = r32 - 0; print(r0); var r36 = r7 ^ 5; var r37 = r7 + r30; var r38 = r19 & r30; r0 = r35 * r26; r38 = r13 & r24; var r39 = r6 ^ 5; var r40 = r11 & x; r25 = 2 / r33; var r41 = 7 + r7; var r42 = r36 % r39; r16 = r11 ^ r21; var r43 = r6 & 6; var r44 = r28 ^ r11; var r45 = 6 + 8; var r46 = r18 & r4; r18 = 4 - 8; print(r17); r39 = r3 & r10; var r47 = 4 + r32; print(r44); var r48 = 6 + r14; var r49 = r15 - r34; var r50 = 4 * r37; var r51 = r20 % 7; var r52 = r46 * 4; var r53 = 5 & x; r5 = r5 * r52; var r54 = 8 % r33; var r55 = r27 + r48; var r56 = 4 * r9; r34 = r32 - 8; var r57 = r39 | r9; var r58 = r55 / r39; var r59 = r21 * r56; var r60 = r26 | r12; var r61 = x - 0; return 4; }}));");
/*fuzzSeed-42509072*/count=227; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((Math.atan2(y, Math.sign(y)) * ( ~ Math.atanh(Math.fround(Math.expm1(Number.MAX_SAFE_INTEGER)))))); }); testMathyFunction(mathy0, [-0x07fffffff, 0, -0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, -(2**53+2), -Number.MIN_VALUE, -0, 0x100000000, Math.PI, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, 0/0, -1/0, 2**53+2, -0x100000001, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, 42, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, 1, -0x080000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-42509072*/count=228; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.atanh(Math.sqrt(Math.abs((((y >>> 0) ? (x >>> 0) : -Number.MAX_VALUE) >>> 0)))); }); testMathyFunction(mathy1, [2**53, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -0, 0x07fffffff, -0x07fffffff, 42, 0x100000000, 2**53-2, -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, 0x100000001, 1/0, -0x080000001, 1, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, -0x100000001, Number.MIN_VALUE, -1/0, -Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-42509072*/count=229; tryItOut("testMathyFunction(mathy0, [2**53+2, 1, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 0.000000000000001, 2**53-2, Number.MAX_VALUE, 0x0ffffffff, -0x080000001, 0/0, 1.7976931348623157e308, -0x100000000, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), 0x07fffffff, -(2**53), -1/0, -0x07fffffff, 1/0, 42, -0x100000001, 0x080000001, 2**53, 0x100000000, 0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=230; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o1.f1, e1);");
/*fuzzSeed-42509072*/count=231; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"y\"); var s = \"\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-42509072*/count=232; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=233; tryItOut("g2.offThreadCompileScript(\"for (var v of t1) { try { m2.set(m0, a1); } catch(e0) { } try { v0 = evaluate(\\\"h0.__proto__ = e2;\\\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: ((neuter).call((delete x.NaN), x)), sourceIsLazy: false, catchTermination: (x % 13 == 1) })); } catch(e1) { } Object.prototype.unwatch.call(g0.p2, \\\"__parent__\\\"); }\", ({ global: g1.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (void shapeOf(x)), sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-42509072*/count=234; tryItOut("Array.prototype.reverse.apply(a2, []);");
/*fuzzSeed-42509072*/count=235; tryItOut("/*MXX1*/Object.defineProperty(this, \"o1\", { configurable: false, enumerable: (x % 9 != 8),  get: function() {  return g2.TypeError.name; } });");
/*fuzzSeed-42509072*/count=236; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\", \"yim\"); var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-42509072*/count=237; tryItOut("\"use strict\"; v0 = new Number(0);");
/*fuzzSeed-42509072*/count=238; tryItOut("for (var p in a2) { try { p2 = a0[16]; } catch(e0) { } i1.send(m2); }");
/*fuzzSeed-42509072*/count=239; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((( + (( + ( ! ( + x))) >>> 0)) >>> 0) ? (( ! (x >>> 0)) >>> 0) : ((Math.fround((Math.fround(mathy0(( + 1/0), Math.fround(Math.cosh(y)))) >>> 0)) >>> 0) >>> 0)) ** Math.cos(Math.abs(x))); }); testMathyFunction(mathy3, [2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x100000000, -Number.MAX_VALUE, 2**53, Number.MIN_VALUE, 2**53+2, 0x07fffffff, -0, -1/0, 0, -0x100000001, -(2**53+2), 0x080000000, 0x080000001, 0x0ffffffff, 0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), -0x100000000, -0x080000000, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, Math.PI, 0/0, 1.7976931348623157e308, -0x0ffffffff, 1/0, -0x07fffffff]); ");
/*fuzzSeed-42509072*/count=240; tryItOut("a2.pop(s0, h1, this.o1.e1);");
/*fuzzSeed-42509072*/count=241; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(\\\\1|(?=[])+?*))\", \"gyi\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-42509072*/count=242; tryItOut("\"use strict\"; p2.__iterator__ = (function() { t0[5] = this; return s0; });");
/*fuzzSeed-42509072*/count=243; tryItOut("this.i1.next();");
/*fuzzSeed-42509072*/count=244; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.fround(Math.imul(Math.abs(Math.fround((( + Math.log(x)) !== ( + Math.hypot(y, x))))), (Math.imul(((mathy2(x, y) <= ((x >>> 0) % (0.000000000000001 >>> 0))) >>> 0), x) >> (((( + (x | 0)) | 0) ? Math.fround((Math.fround(y) * Math.fround(x))) : -Number.MAX_VALUE) >>> 0))))), Math.fround(Math.pow(Math.cosh(Math.fround((-0x0ffffffff ? Math.max(( ! Math.atan(0x080000001)), (((y | 0) === (x | 0)) >>> 0)) : Math.expm1((Math.exp((x >>> 0)) >>> 0))))), ((Math.max((Math.clz32(y) | 0), (Math.sinh(Math.atan2(x, -Number.MAX_VALUE)) | 0)) | 0) === Math.fround(mathy0((( + ((/*wrap2*/(function(){ \"use strict\"; var tingpa = \"\\u56C3\"; var nckteq = String.prototype.valueOf; return nckteq;})() | 0) == ((( + (Math.PI >>> 0)) >>> 0) | 0))) >>> 0), y))))))); }); testMathyFunction(mathy3, [-0x100000001, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, -(2**53), 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0.000000000000001, -0, 0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, 42, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff, 1/0, 1, -(2**53-2), 0x080000000, 2**53, -0x07fffffff, 2**53+2, 0/0, -0x100000000, Math.PI, -1/0]); ");
/*fuzzSeed-42509072*/count=245; tryItOut("e0.toSource = (function() { g2.offThreadCompileScript(\"function f0(h1) /*MARR*/[new Boolean(true), function(){}, new Boolean(true), NaN, NaN, NaN, NaN, function(){}, new Boolean(true), NaN, new Boolean(true), new Boolean(true), function(){}, function(){}, function(){}, new Boolean(true), new Boolean(true), new Boolean(true), function(){}, function(){}, function(){}, function(){}, function(){}, NaN, function(){}, function(){}, function(){}, function(){}, NaN, NaN, NaN, function(){}, new Boolean(true), new Boolean(true), new Boolean(true), function(){}, NaN, NaN, new Boolean(true), new Boolean(true), NaN, NaN, new Boolean(true), function(){}, new Boolean(true), function(){}, new Boolean(true), NaN, function(){}, function(){}, NaN, NaN, function(){}, NaN, NaN, new Boolean(true), NaN, new Boolean(true), new Boolean(true), function(){}, new Boolean(true), function(){}, NaN, function(){}, function(){}, new Boolean(true), new Boolean(true), new Boolean(true), NaN, function(){}, new Boolean(true), function(){}].map\", ({ global: o1.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: Math.pow(\ndelete z.e, -26) })); return f0; });");
/*fuzzSeed-42509072*/count=246; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.fround((Math.fround((( - ( + Math.max(( + ( + Math.pow(( + (Math.max((y >>> 0), (x >>> 0)) >>> 0)), ( + Math.fround(( - x)))))), (x >= y)))) >>> 0)) || Math.fround(Math.cosh(Math.fround((( + Math.max(( + ( + y)), ( + x))) === ( + ( - (y >>> 0))))))))) | 0) - (Math.ceil(( ~ case 7: print((4277));break; default: break; )) | 0)); }); testMathyFunction(mathy5, [42, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 2**53-2, 2**53, 0.000000000000001, 0/0, 0x0ffffffff, -0x080000000, 2**53+2, 1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, -(2**53+2), 0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), -1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, 0x100000000, -0x100000001, 0, -0, -(2**53)]); ");
/*fuzzSeed-42509072*/count=247; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[[], new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), [], new Boolean(true), new Boolean(true), new Boolean(true), [], new Boolean(true), [], [], new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-42509072*/count=248; tryItOut("for(e = x >>>= -21 in eval = [z1]) print(e);");
/*fuzzSeed-42509072*/count=249; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - ( + ( ! ( + ( + Math.atanh(( + y))))))); }); testMathyFunction(mathy3, [0, 1/0, -1/0, 0x080000000, -Number.MAX_VALUE, -0, 2**53+2, 42, 2**53, -(2**53+2), 0x100000000, -0x080000000, -0x100000001, 1.7976931348623157e308, -0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 0x100000001, Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 1, -(2**53), 0/0]); ");
/*fuzzSeed-42509072*/count=250; tryItOut("this.s2 += 'x';");
/*fuzzSeed-42509072*/count=251; tryItOut("\"use strict\"; var r0 = x | x; var r1 = r0 * 4; var r2 = x * r0; var r3 = 4 + x; var r4 = r1 - 5; var r5 = r4 / r4; var r6 = r4 | r3; x = 1 + r5; var r7 = r1 / r2; x = r7 & r3; var r8 = r4 & r4; var r9 = r2 / r8; var r10 = r9 & r0; r6 = 4 % 1; var r11 = r9 - 3; print(r2); r9 = 0 - r9; var r12 = 6 & r3; var r13 = r0 * r3; r13 = r10 / r3; var r14 = r3 % 9; var r15 = r8 - r14; var r16 = r3 + r2; r2 = 6 * r2; var r17 = r13 / r5; var r18 = r3 % r1; var r19 = 6 ^ r18; var r20 = r8 * 9; r1 = r11 | r20; var r21 = r15 | r5; var r22 = r21 + 6; var r23 = 3 ^ r16; var r24 = 2 - r13; var r25 = 7 & r12; r14 = r6 | 7; print(r1); r13 = 8 & r2; r8 = 3 + 5; r19 = r12 / 0; var r26 = 7 | 4; r18 = r17 / r0; var r27 = r8 | r10; var r28 = 2 | r6; var r29 = r20 | r19; var r30 = r13 - r11; var r31 = 7 ^ r5; var r32 = 4 + 9; print(r29); var r33 = 6 * r28; var r34 = 3 - 3; var r35 = 7 & 1; var r36 = 7 % r5; r6 = r13 - 8; var r37 = 5 / r25; var r38 = r37 + r22; var r39 = r30 ^ r19; var r40 = r22 | r22; var r41 = 6 & r18; r28 = r13 % 0; var r42 = r24 & r18; var r43 = r8 * r21; var r44 = r27 + r7; var r45 = r25 ^ r3; print(r0); var r46 = r17 | r16; r14 = r30 % r42; var r47 = r40 ^ r16; var r48 = r19 ^ r3; var r49 = r16 ^ 5; print(r36); ");
/*fuzzSeed-42509072*/count=252; tryItOut("/*RXUB*/var r = /(?!(?:(?:(?=(?:[^]{524287}){4,})))?|\\2{1,3}|(?!\\B)|([\\x26-Q]|\\B[^]+?)?+?)/gyim; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-42509072*/count=253; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[function(){}, [undefined], undefined, [undefined], function(){}, [undefined], new String('q'), new Boolean(false), function(){}, new Boolean(false), function(){}, function(){}, new Boolean(false), new String('q'), function(){}, new Boolean(false), undefined, [undefined], [undefined], function(){}, [undefined], [undefined], new String('q'), new Boolean(false), new String('q'), new String('q'), function(){}, function(){}, [undefined], [undefined], [undefined], [undefined], function(){}, [undefined], new Boolean(false), new String('q'), [undefined], undefined, [undefined], new String('q'), function(){}, [undefined], new String('q'), [undefined], undefined, [undefined], function(){}, new Boolean(false), new String('q'), [undefined], [undefined], undefined, new Boolean(false), undefined, undefined, new String('q'), [undefined], new String('q'), [undefined], [undefined], new Boolean(false), function(){}, new Boolean(false), new Boolean(false), [undefined], new Boolean(false), undefined, function(){}, undefined, undefined, function(){}, undefined, undefined, new Boolean(false), [undefined], undefined, undefined, function(){}]); ");
/*fuzzSeed-42509072*/count=254; tryItOut("([]);");
/*fuzzSeed-42509072*/count=255; tryItOut("selectforgc(o0);");
/*fuzzSeed-42509072*/count=256; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42509072*/count=257; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=258; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.exp(((( + Math.fround((x >>> ( - (mathy1(-(2**53), Math.fround(( ! Math.fround(x)))) >>> 0))))) ? ( + Math.max(-(2**53+2), (x | 0))) : (((x ? (Math.log10(-0) >>> 0) : y) ? (Math.fround(x) < y) : Math.asin(Number.MAX_VALUE)) ? (Math.min(( + Math.imul(y, ( + y))), 0x080000001) >>> 0) : (Math.max(Math.fround(( ! Math.fround(Math.acos((x >>> 0))))), (( ~ -1/0) >>> 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [1.7976931348623157e308, 0/0, 0x100000001, 0, -0x100000000, Number.MIN_VALUE, -(2**53-2), Math.PI, 2**53-2, 42, -Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 0x080000000, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, -0x080000001, 0.000000000000001, 2**53+2, -0, -(2**53+2), 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -(2**53), -0x100000001, 2**53, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, -0x0ffffffff]); ");
/*fuzzSeed-42509072*/count=259; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?!^|\\\\\\ua21d)[\\u001c-\\\\cP\\\\cI\\\\cM]+?+.*)\", \"gi\"); var s = delete constructor.x; print(uneval(s.match(r))); ");
/*fuzzSeed-42509072*/count=260; tryItOut("\"use strict\"; s2 += s1;");
/*fuzzSeed-42509072*/count=261; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! ( ! (Math.acos((( + ( - (Math.fround(( - Math.tan((y >>> 0)))) >>> 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[[1], ({c: a instanceof x}), ({c: a instanceof x}), [1], [1], ({c: a instanceof x}), ({c: a instanceof x}), [1]]); ");
/*fuzzSeed-42509072*/count=262; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a0, ({valueOf: function() { /* no regression tests found */return 2; }}), { configurable: (x % 9 != 4), enumerable: true, writable: false, value: \u000c[ /x/g ] });");
/*fuzzSeed-42509072*/count=263; tryItOut("h0.get = (function(j) { if (j) { e2.has(s0); } else { try { /*MXX3*/this.g2.SharedArrayBuffer.length = g0.SharedArrayBuffer.length; } catch(e0) { } try { m1.delete(this.a1); } catch(e1) { } try { Object.prototype.watch.call(g0, \"reject\", arguments.callee); } catch(e2) { } /*MXX2*/g0.Object.prototype.isPrototypeOf = i0; } });");
/*fuzzSeed-42509072*/count=264; tryItOut("print(uneval(g0));");
/*fuzzSeed-42509072*/count=265; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.sinh(( + Math.max((( ~ mathy0(y, ( + ( ~ ( + y))))) | 0), ((Math.pow(((((0x100000001 | 0) || (-0x100000001 | 0)) | 0) >>> 0), ((mathy0((( ! x) >>> 0), (( ! Math.fround(Math.tan(x))) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0))))); }); testMathyFunction(mathy3, [-0x0ffffffff, -(2**53-2), 0/0, -Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, 0x080000000, 2**53, -0x100000000, 0x100000001, -0x080000000, 0x0ffffffff, 1/0, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 0x100000000, 0.000000000000001, Math.PI, -1/0, -0, 42, 0x07fffffff, 0x080000001, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-42509072*/count=266; tryItOut("testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -(2**53+2), -0, 42, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -1/0, Math.PI, 2**53-2, 0.000000000000001, -(2**53), -Number.MIN_VALUE, 2**53+2, -0x07fffffff, -0x100000001, -0x100000000, 1/0, -(2**53-2), 1.7976931348623157e308, 0x100000001, 0x080000001, 0, -Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, 2**53, 0/0, -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=267; tryItOut("this.o2.v0 = r0.exec;function b()new RegExp(\"(?![^\\\\s])\", \"gyim\")/*RXUB*/var r = r1; var s = s1; print(s.split(r)); ");
/*fuzzSeed-42509072*/count=268; tryItOut("o1.v2 = o2[\"fixed\"];");
/*fuzzSeed-42509072*/count=269; tryItOut("/*MXX2*/this.g0.Object.prototype.valueOf = g0;");
/*fuzzSeed-42509072*/count=270; tryItOut("\"use strict\"; s2 += s2;");
/*fuzzSeed-42509072*/count=271; tryItOut("\"use strict\"; print(x\n);yield;break L;");
/*fuzzSeed-42509072*/count=272; tryItOut("v2 = Object.prototype.isPrototypeOf.call(h2, this.g0);");
/*fuzzSeed-42509072*/count=273; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[true, objectEmulatingUndefined(), new Number(1.5), true, new Number(1.5), objectEmulatingUndefined(), x, (-0), new Number(1.5), objectEmulatingUndefined(), x, x, x, (-0), true, x, x, x, objectEmulatingUndefined(), (-0), true, true, true, true, objectEmulatingUndefined(), (-0), true, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), (-0), new Number(1.5), new Number(1.5), true, new Number(1.5), new Number(1.5), (-0), objectEmulatingUndefined(), true, true, (-0), x, objectEmulatingUndefined(), true, new Number(1.5), true, x, (-0), objectEmulatingUndefined(), x, new Number(1.5), (-0), true, x, new Number(1.5), true, new Number(1.5), objectEmulatingUndefined(), x, (-0), true, objectEmulatingUndefined(), x, new Number(1.5), x, x, x, (-0), x, (-0), objectEmulatingUndefined(), (-0), true, (-0), (-0), objectEmulatingUndefined(), objectEmulatingUndefined(), (-0), true, objectEmulatingUndefined(), (-0), objectEmulatingUndefined(), true, true, new Number(1.5), true, x, objectEmulatingUndefined(), x, true, (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), x, x, true, true, new Number(1.5), new Number(1.5), x, objectEmulatingUndefined(), (-0), objectEmulatingUndefined(), new Number(1.5), x, true, objectEmulatingUndefined()]); ");
/*fuzzSeed-42509072*/count=274; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((( ! Math.fround(( + Math.atan2((Math.cos(((( ~ ((Math.log((x >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0), Math.imul(Math.fround(Math.imul(Math.fround(x), Math.fround(x))), ( + y)))))) >>> 0) >= Math.log2((Math.sin(mathy1((x | 0), Math.imul(Math.fround(( + Math.hypot(( + y), ( + y)))), Math.fround(y)))) <= (((x | 0) ? Math.pow(Math.cbrt(Math.min(x, x)), y) : Math.log1p(2**53+2)) >>> 0)))); }); testMathyFunction(mathy4, [-0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, Math.PI, -(2**53), 0x080000000, 1/0, -0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, -0x07fffffff, 1.7976931348623157e308, 42, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -Number.MAX_VALUE, 1, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, 0x100000001, -0x080000001, 2**53, 0/0, 0, -0x100000000, 0x080000001]); ");
/*fuzzSeed-42509072*/count=275; tryItOut("print(uneval(h2));");
/*fuzzSeed-42509072*/count=276; tryItOut("(yield ({\"-13\":  \"\"  }));Object.defineProperty(this, \"v1\", { configurable: true, enumerable: \"\\uDA34\",  get: function() {  return this.o2.t2.length; } });");
/*fuzzSeed-42509072*/count=277; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.fround(( - Math.fround((( + (Math.log10(y) ^ y)) <= y)))) - (((x >>> 0) >= (mathy1(( + y), ( ~ -0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [-0x0ffffffff, -0x07fffffff, 0.000000000000001, -0x080000000, -0x080000001, -0x100000001, 0/0, 2**53-2, 0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -0, 0x080000000, 1, Number.MAX_VALUE, -(2**53-2), -(2**53+2), 0, -(2**53), -Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 42, 2**53, -Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, 0x080000001, -Number.MIN_VALUE, 0x100000001, -1/0, 0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=278; tryItOut("x;Array.prototype.unshift.call(a2, this.b1, g0.t0, e2);");
/*fuzzSeed-42509072*/count=279; tryItOut("\"use strict\"; this.v2 + '';");
/*fuzzSeed-42509072*/count=280; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(( ~ ((Math.fround((Math.fround(Math.log(Math.max(y, y))) / ( + y))) - Math.abs((x >>> 0))) >>> 0))); }); testMathyFunction(mathy4, /*MARR*/[-(2**53-2), -(2**53-2), ({}), -(2**53-2), new Number(1), -(2**53-2), new Number(1), ({}), ({}), new Number(1), ({}), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), new Number(1), ({}), -(2**53-2), ({}), new Number(1), -(2**53-2), ({}), -(2**53-2), new Number(1), -(2**53-2), new Number(1), -(2**53-2), new Number(1)]); ");
/*fuzzSeed-42509072*/count=281; tryItOut("/*tLoop*/for (let a of /*MARR*/[new Number(1), new Number(1), (void 0), [], 1e-81, new Number(1), new Number(1), (void 0), 1e-81, 1e-81, new Number(1), new Number(1), [], new Number(1), 1e-81, new Number(1), (void 0), new Number(1), [], new Number(1), [], 1e-81, [], new Number(1), (void 0), (void 0), new Number(1), 1e-81, new Number(1), new Number(1), 1e-81, [], new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], new Number(1), (void 0), 1e-81, 1e-81, [], 1e-81, (void 0), [], 1e-81, (void 0), [], new Number(1), new Number(1), 1e-81, (void 0), [], new Number(1), new Number(1), [], (void 0), [], new Number(1), (void 0), 1e-81, 1e-81, (void 0), (void 0), 1e-81, new Number(1), new Number(1), [], [], [], new Number(1), 1e-81, 1e-81, [], 1e-81, (void 0), new Number(1), 1e-81, new Number(1), [], new Number(1), 1e-81, new Number(1), [], 1e-81, new Number(1), new Number(1), (void 0), new Number(1), new Number(1), (void 0), (void 0), [], 1e-81, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (void 0), (void 0), new Number(1), [], new Number(1), (void 0), new Number(1), (void 0), 1e-81, (void 0), (void 0), 1e-81, (void 0), new Number(1), [], 1e-81, [], new Number(1), (void 0), [], new Number(1), [], new Number(1), [], new Number(1), 1e-81, (void 0)]) { t1 = new Float64Array(b1, 136, 18); }");
/*fuzzSeed-42509072*/count=282; tryItOut("i2.next();");
/*fuzzSeed-42509072*/count=283; tryItOut("mathy3 = (function(x, y) { return (Math.max(( + Math.pow(x, ( ~ y))), ( + Math.max(42, Math.fround(Math.expm1(y))))) ** (Math.exp((( ~ (x - ( + mathy1(( + x), ( + y))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [0x080000000, Number.MIN_VALUE, 0x100000000, 1/0, -(2**53-2), -Number.MIN_VALUE, -0x100000001, 42, -0x080000001, -0, -0x080000000, -0x100000000, -0x0ffffffff, 1.7976931348623157e308, 0x100000001, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_VALUE, 1, 0x0ffffffff, 0, 2**53, -1/0, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53+2, Math.PI, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-42509072*/count=284; tryItOut("\"use strict\"; v0 = evaluate(\"for (var v of s2) { try { Array.prototype.push.apply(a2, [o2, f2, e0, v0, g2.s1]); } catch(e0) { } try { g0.offThreadCompileScript(\\\"/\\\\\\\\2/gym\\\"); } catch(e1) { } try { o2.a1 = arguments.callee.caller.arguments; } catch(e2) { } ; }\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce:  /* Comment */(uneval((new (encodeURI)()))), noScriptRval: (x % 35 != 31), sourceIsLazy: ({} = x)[\"keys\"] = (Math.max([/\\1{3}|(?:(\\b+?)|[^]+?|(?=([^])[Q]))/g], (void version(180)))), catchTermination: true, element: o0, elementAttributeName: o2.s0, sourceMapURL: s1 }));");
/*fuzzSeed-42509072*/count=285; tryItOut("Array.prototype.pop.call(a0, s2, s2);");
/*fuzzSeed-42509072*/count=286; tryItOut("\"use strict\"; \"use asm\"; v2 = g0.runOffThreadScript();");
/*fuzzSeed-42509072*/count=287; tryItOut("mathy0 = (function(x, y) { return Math.sqrt(((( + ((( + ( + ( + Math.fround(Math.tan(( + y)))))) - x) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy0, [/0/, ({toString:function(){return '0';}}), '0', [0], (new Number(-0)), objectEmulatingUndefined(), undefined, '\\0', (new Boolean(true)), '/0/', null, 1, true, NaN, [], (new String('')), 0.1, false, (new Boolean(false)), -0, ({valueOf:function(){return '0';}}), '', (new Number(0)), 0, (function(){return 0;}), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-42509072*/count=288; tryItOut("/*infloop*/ for  each(y in \"\\uF198\") {print(x);m1 + ''; }");
/*fuzzSeed-42509072*/count=289; tryItOut("f1.toString = (function mcc_() { var kbnolc = 0; return function() { ++kbnolc; f2(/*ICCD*/kbnolc % 3 == 0);};})();");
/*fuzzSeed-42509072*/count=290; tryItOut("/*RXUB*/var r = /(?=.{2}|\\b+?[^]{3,}(?!(?!\u46af)|\\u5f09+?)){3,}|((\\u0028)?\\B){1}/y; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-42509072*/count=291; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.clz32((Math.acosh(Math.log(Math.fround(42))) >>> 0))); }); ");
/*fuzzSeed-42509072*/count=292; tryItOut("\"use strict\"; this.t1 = this.a1[11];");
/*fuzzSeed-42509072*/count=293; tryItOut("mathy0 = (function(x, y) { return Math.fround((((( ! (( + Math.pow(( - x), Math.max(x, y))) | 0)) | 0) + ( ! ( ~ Math.fround(( ! (( ~ y) >>> 0)))))) == ((Math.hypot((( + (( + Math.min(((y , y) | 0), ( + x))) | 0)) | 0), (((x | 0) ** y) | 0)) ? ( - -Number.MIN_VALUE) : (( + (x >>> 0)) >>> 0)) | Math.sinh(Math.fround(((y ? (x | 0) : (Math.atanh((Math.atanh(y) | 0)) | 0)) | 0)))))); }); testMathyFunction(mathy0, [-0x07fffffff, -0x100000001, -0x080000000, 0x100000000, Number.MIN_VALUE, 0x080000000, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, -1/0, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -0, -(2**53+2), -0x0ffffffff, 0x0ffffffff, 2**53+2, 1/0, 0/0, 0x080000001, -(2**53), 0x100000001, 1, Math.PI]); ");
/*fuzzSeed-42509072*/count=294; tryItOut("mathy4 = (function(x, y) { return (mathy3((Math.expm1((Math.fround(( ! Math.fround((mathy3(( + Math.pow(y, x)), y) > Math.hypot(Math.hypot(( + ((y >>> 0) + (y >>> 0))), Math.fround(x)), ((( + Math.imul(-0x080000001, x)) == y) | 0)))))) >>> 0)) | 0), (( + ( ~ ( + ( + Math.PI)))) > ( + mathy2(Math.hypot(Math.imul(x, ( + ( - (x | 0)))), y), (Math.clz32(Math.atan2(y, x)) | 0))))) | 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, 0x0ffffffff, -1/0, -Number.MIN_VALUE, 2**53+2, 1/0, 42, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, 0, 2**53-2, -0x080000000, 2**53, -0x07fffffff, -Number.MAX_VALUE, -0x100000001, 0x080000000, 1, -(2**53-2), 0/0, 0.000000000000001, -0x080000001, Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), -0, 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-42509072*/count=295; tryItOut("\"use strict\"; /*vLoop*/for (iuizwi = 0; iuizwi < 78; ++iuizwi) { var y = iuizwi; ; } ");
/*fuzzSeed-42509072*/count=296; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\3(?!\\cQ){4}|\\D|(?=(?:(\\w|\\s+)))*?[^])/im; var s = null; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-42509072*/count=297; tryItOut("/*oLoop*/for (dzupjy = 0, x; dzupjy < 124; ++dzupjy) { throw ([1,,].__defineSetter__(\"c\", eval)).unwatch(-20); } ");
/*fuzzSeed-42509072*/count=298; tryItOut("print(x);");
/*fuzzSeed-42509072*/count=299; tryItOut("testMathyFunction(mathy0, [0x07fffffff, 0x080000000, 0x100000000, -0x100000000, 2**53-2, 42, 0.000000000000001, 1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0/0, -1/0, -0, -0x100000001, Number.MAX_VALUE, 2**53+2, -0x080000001, -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -0x0ffffffff, -(2**53), Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-42509072*/count=300; tryItOut("testMathyFunction(mathy2, [0x100000001, 42, -0x100000001, 1/0, 0/0, 2**53-2, -0x100000000, -0x080000000, -0x080000001, -0x07fffffff, -Number.MAX_VALUE, 2**53, 0x0ffffffff, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, 0x07fffffff, 0x080000001, Math.PI, -0, 1.7976931348623157e308, 0.000000000000001, 0x100000000]); ");
/*fuzzSeed-42509072*/count=301; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.acos(Math.trunc(( + Math.atan2(y, (0.000000000000001 === Math.fround((Math.fround(-Number.MAX_SAFE_INTEGER) != x))))))); }); ");
/*fuzzSeed-42509072*/count=302; tryItOut("testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, -0x0ffffffff, -0x100000001, -0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, 0/0, 0x100000000, 0x100000001, Math.PI, -(2**53+2), 2**53+2, -Number.MIN_VALUE, 42, 1.7976931348623157e308, -0x100000000, -0, 0x0ffffffff, 0x080000000, -Number.MAX_VALUE, -(2**53-2), 1/0, 1, Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, 0]); ");
/*fuzzSeed-42509072*/count=303; tryItOut("(function ([y]) { })();function c()(new (\"\\u1AF9\".valueOf(\"number\")\u000c)(({d: function(id) { return id }}) ? /*UUV2*/(x.isArray = x.toPrecision) :  \"\" , null))print(x);");
/*fuzzSeed-42509072*/count=304; tryItOut("mathy5 = (function(x, y) { return (Math.asinh((Math.atan2(( + mathy1(Math.log(Math.exp((x | 0))), ( + (Math.min(Math.PI, (x >>> 0)) >>> 0)))), Math.fround((x >> (((((x >>> 0) ? y : x) >>> 0) << (( + Math.max(( + y), y)) >>> 0)) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-42509072*/count=305; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.imul(Math.hypot(( + Math.min(Math.min(( ! y), ( + x)), ( + ((( + -0x100000000) && ( + Math.tanh((x & (2**53-2 >>> 0))))) >>> 0)))), (Math.max((mathy1((( + Math.hypot(( + Math.abs(y)), (x >>> 0))) | 0), (Math.imul(x, (Math.atanh(x) | 0)) | 0)) >>> 0), ((Math.sin(( ! y)) | 0) | 0)) | 0)), Math.asin(Math.ceil(y))); }); testMathyFunction(mathy3, [-0x100000001, -0x080000000, 0x0ffffffff, -0x100000000, 1/0, Number.MIN_VALUE, -(2**53), 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x07fffffff, 1.7976931348623157e308, 2**53, -0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 0/0, -1/0, 42, -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, 2**53-2, 0x100000000, -Number.MAX_VALUE, 0, -(2**53-2), 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000001]); ");
/*fuzzSeed-42509072*/count=306; tryItOut("vkfiiv(x|=x, \"\\uCF2F\");/*hhh*/function vkfiiv(y = ( /x/g  << this)){v1 = e1[\"isArray\"];}");
/*fuzzSeed-42509072*/count=307; tryItOut("\"use strict\"; /*oLoop*/for (var hzwhod = 0; hzwhod < 21; ++hzwhod) { a0.unshift(t1, f2, e1,  'A' , e0, a1); } ");
/*fuzzSeed-42509072*/count=308; tryItOut("\"use strict\"; m0.set(s0, p1);");
/*fuzzSeed-42509072*/count=309; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[-Number.MAX_VALUE,  /x/g , -Number.MAX_VALUE,  /x/g ,  /x/g , x, x, x,  /x/g ,  /x/g , -Number.MAX_VALUE, x,  /x/g , x,  /x/g , x, -Number.MAX_VALUE, x, -Number.MAX_VALUE,  /x/g , x, x, x, x, x, x, x, x, x, x, x, -Number.MAX_VALUE,  /x/g ,  /x/g , -Number.MAX_VALUE,  /x/g , x,  /x/g , -Number.MAX_VALUE, x, x, -Number.MAX_VALUE, x, -Number.MAX_VALUE, -Number.MAX_VALUE,  /x/g , -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE,  /x/g ]); ");
/*fuzzSeed-42509072*/count=310; tryItOut("testMathyFunction(mathy3, /*MARR*/[undefined, [(void 0)],  \"use strict\" ]); ");
/*fuzzSeed-42509072*/count=311; tryItOut("print((/*UUV2*/(x.setTime = x.toGMTString)));");
/*fuzzSeed-42509072*/count=312; tryItOut("mathy2 = (function(x, y) { return (Math.tan((mathy0(( + -0x100000001), 0x07fffffff) & (((y , Math.acosh(y)) >>> 0) ^ ( + mathy1((Math.max(-0x100000001, y) >>> 0), x))))) >>> 0); }); testMathyFunction(mathy2, [0x080000000, 0.000000000000001, 0x080000001, -0x100000001, 0x0ffffffff, 2**53, -1/0, -(2**53), 0x100000001, 1, -Number.MIN_VALUE, 0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, -0x080000000, 0x100000000, -0, 42, Math.PI, 2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, 1/0, Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-42509072*/count=313; tryItOut("mathy4 = (function(x, y) { return Math.min(Math.fround(Math.asin(((( - (x / y)) == ( + y)) | 0))), (Math.acos(Math.expm1(Math.clz32((Math.imul((y | 0), ((Math.pow((x >>> 0), (mathy0(x, y) >>> 0)) | 0) | 0)) | 0)))) | 0)); }); testMathyFunction(mathy4, [1.7976931348623157e308, 0x0ffffffff, Number.MIN_VALUE, 0x080000000, 0x100000001, -Number.MAX_VALUE, -0x080000001, -0, -(2**53), -0x080000000, -1/0, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 1, -Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, 0.000000000000001, 42, -(2**53+2), -0x100000000, 2**53+2, 1/0, -0x07fffffff, 2**53, 0, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-42509072*/count=314; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - Math.hypot((Math.min(Math.atan2(( + x), 0x07fffffff), (((( ~ Math.fround(Math.ceil(( + y)))) | 0) <= y) | y)) | 0), ((( ~ ((x && 1.7976931348623157e308) >>> 0)) >>> 0) === y))); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), [0], objectEmulatingUndefined(), 1, -0, ({toString:function(){return '0';}}), (new String('')), (new Boolean(false)), '\\0', '', '/0/', NaN, 0, 0.1, (new Number(0)), [], /0/, undefined, (new Boolean(true)), (function(){return 0;}), true, false, (new Number(-0)), '0', ({valueOf:function(){return '0';}}), null]); ");
/*fuzzSeed-42509072*/count=315; tryItOut("\"use strict\"; this.m0 + v1;");
/*fuzzSeed-42509072*/count=316; tryItOut("v2 = r0.global;");
/*fuzzSeed-42509072*/count=317; tryItOut("e1.has(m2);");
/*fuzzSeed-42509072*/count=318; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.imul(( + Math.atan2(((( + Math.max(x, x)) >>> 0) != Math.fround(( ! Number.MIN_VALUE))), Math.atan2(y, Math.min(y, Math.clz32(Math.exp((y ^ y))))))), ( + (( + ( + ( + Math.pow((( ~ ( + x)) | 0), y)))) - ( + ((x >>> 0) + ((Math.imul(x, x) >>> 0) & y))))))); }); testMathyFunction(mathy0, [-(2**53+2), 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), 1, Number.MIN_VALUE, 1.7976931348623157e308, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 2**53, 0x080000000, -0x080000000, -0x0ffffffff, -0x100000000, 0/0, 0x100000000, -(2**53-2), -1/0, 42, 2**53-2, 1/0, 0.000000000000001, 0x100000001, 2**53+2, Math.PI, 0, -0x080000001, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-42509072*/count=319; tryItOut("\"use asm\"; M:while(((4277)) && 0)Object.defineProperty(this.o2, \"v0\", { configurable: (x % 6 != 0), enumerable: true,  get: function() {  return o2.g1.eval(\"(void schedulegc(g0));\"); } });");
/*fuzzSeed-42509072*/count=320; tryItOut("testMathyFunction(mathy2, [-(2**53+2), -(2**53), -0x0ffffffff, -0x080000001, 0x100000000, 0/0, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, Math.PI, -0, Number.MIN_VALUE, 1/0, 0, 0x080000001, -(2**53-2), 2**53, -1/0, -0x07fffffff, 0.000000000000001, 2**53+2, -0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 0x080000000, -0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, 1, 42]); ");
/*fuzzSeed-42509072*/count=321; tryItOut("\"use strict\"; for (var v of v2) { try { v0 = evalcx(\"/* no regression tests found */\", g0); } catch(e0) { } try { -13 = a1[x]; } catch(e1) { } try { e2.add(o1.a0); } catch(e2) { } t0 = new Int32Array(b1); }");
/*fuzzSeed-42509072*/count=322; tryItOut("e2 + '';");
/*fuzzSeed-42509072*/count=323; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(((((Math.sin(( + (y / Math.fround(Math.imul(Math.fround(x), ( + (y !== 42))))))) % Math.fround(mathy0(Math.fround(-0x080000000), Math.fround(( + Math.fround((( + (y ? y : x)) | 0))))))) | 0) < (((Math.sqrt(x) >>> 0) | x) != Math.min(( + Math.hypot(Math.fround(Math.log10(y)), x)), y))) | 0), ( + Math.fround(Math.abs(x)))); }); ");
/*fuzzSeed-42509072*/count=324; tryItOut("\"use asm\"; let (c) { var fyqgav = new SharedArrayBuffer(8); var fyqgav_0 = new Uint8ClampedArray(fyqgav); print(fyqgav_0[0]); fyqgav_0[0] = 2; (\"\\uC60B\"); }");
/*fuzzSeed-42509072*/count=325; tryItOut("\"use strict\"; NaN = \u3056;");
/*fuzzSeed-42509072*/count=326; tryItOut("\"use strict\"; let (d) { Function }");
/*fuzzSeed-42509072*/count=327; tryItOut("mathy2 = (function(x, y) { return mathy1((((Math.fround(Math.imul(Math.fround(Number.MIN_SAFE_INTEGER), Math.hypot(x, (((y | 0) && (y | 0)) | 0)))) | 0) ? (Math.log10(-Number.MAX_VALUE) | 0) : (((Math.atan2(y, (x | 0)) | 0) && (( ! (x >>> 0)) >>> 0)) | 0)) | 0), Math.hypot((Math.fround(Math.fround(y)) && x), Math.round(( + Math.imul(( + mathy0(y, ( + (x | x)))), x))))); }); testMathyFunction(mathy2, [(new Boolean(false)), 1, 0.1, [0], '', (new String('')), /0/, (function(){return 0;}), '0', true, 0, (new Boolean(true)), (new Number(0)), ({valueOf:function(){return 0;}}), '\\0', NaN, undefined, ({valueOf:function(){return '0';}}), null, false, [], (new Number(-0)), objectEmulatingUndefined(), ({toString:function(){return '0';}}), -0, '/0/']); ");
/*fuzzSeed-42509072*/count=328; tryItOut(" for (var z of x) t2.set(a0, v2);");
/*fuzzSeed-42509072*/count=329; tryItOut("var aceenc = new ArrayBuffer(6); var aceenc_0 = new Uint32Array(aceenc); print(aceenc_0[0]); aceenc_0[0] = -3/0; var aceenc_1 = new Uint8ClampedArray(aceenc); aceenc_1[0] = 19; var aceenc_2 = new Float32Array(aceenc); print(aceenc_2[0]); aceenc_2[0] = -21; m1.get(m1);");
/*fuzzSeed-42509072*/count=330; tryItOut("mathy0 = (function(x, y) { return Math.imul(Math.round(( + Math.atan2(( + x), (( + x) >>> 0)))), Math.fround(Math.acosh(Math.fround((Math.abs((Math.hypot((-0x080000000 <= -0x080000001), ( + (((y | 0) <= ((( ~ (y >>> 0)) >>> 0) | 0)) >>> 0))) | 0)) & (Math.expm1(x) ** ( + ( + Math.fround(Math.min(Math.fround(y), Math.fround(y))))))))))); }); ");
/*fuzzSeed-42509072*/count=331; tryItOut("testMathyFunction(mathy0, [-0x080000000, -Number.MIN_VALUE, 42, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, 0, 2**53+2, 0x080000001, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, -(2**53+2), 2**53, -0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, 1/0, -0x080000001, -(2**53), -0x100000000, Math.PI, 2**53-2, 0/0, 1.7976931348623157e308]); ");
/*fuzzSeed-42509072*/count=332; tryItOut("print(x);function window()\"use asm\";   var abs = stdlib.Math.abs;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = (i1);\n    }\n    {\n      d0 = (d0);\n    }\n    d0 = (+abs(((Float32ArrayView[0]))));\n    (Uint32ArrayView[((-0x8000000)) >> 2]) = ((i1));\n    i1 = (((((((0xba74969e)+(0x1999370b)-(0xeb85f4c2))>>>((0x2ef983a5)+((256.0) != (-3.8685626227668134e+25)))) > (0x0))-((new Int32Array(return))))>>>(((((i1)+(i1)) | (((0x0))+(i1)))))));\n    i1 = (!((((d0)) % ((((Float32ArrayView[4096])) % ((Float64ArrayView[4096]))))) < (-295147905179352830000.0)));\n    return +((-16384.0));\n    d0 = (9007199254740992.0);\n    d0 = (-((137438953471.0)));\n    return +((-4.0));\n  }\n  return f;m1.set(b2, e2);");
/*fuzzSeed-42509072*/count=333; tryItOut("f2.__proto__ = i2;");
/*fuzzSeed-42509072*/count=334; tryItOut("\"use strict\"; e1.delete(a2);");
/*fuzzSeed-42509072*/count=335; tryItOut("\"use strict\"; g1.g0.m1.delete(g1);");
/*fuzzSeed-42509072*/count=336; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\d)+(\\d)\\2+?{1}*/gm; var s = \"____\"; print(uneval(s.match(r))); ");
/*fuzzSeed-42509072*/count=337; tryItOut("\"use strict\"; Object.defineProperty(this, \"r1\", { configurable: false, enumerable: (4277),  get: function() {  return /(?=(?=\\B|.|\u8d53*{131073,})|(?!(?!\\uF3Cf{0,4})|\\b))*/gy; } });");
/*fuzzSeed-42509072*/count=338; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.abs((Math.min(((Math.round((Math.fround(Math.log1p(( + ( + Math.sinh(x))))) >>> 0)) >>> 0) | 0), (Math.fround(mathy0((x | 0), Math.fround((-(2**53-2) ^ y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, 0x080000000, -0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, -(2**53+2), 0x100000001, 0x080000001, 0x0ffffffff, -0x07fffffff, -0x100000000, 2**53, 2**53-2, 0x07fffffff, 0, -0, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), 0/0, 2**53+2, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -0x0ffffffff, 42, 1]); ");
/*fuzzSeed-42509072*/count=339; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy3(((( + ( + (Math.log(((Math.pow((0x100000000 | 0), (x | 0)) | 0) | 0)) >>> 0))) << Math.trunc((Math.imul((-(2**53-2) | 0), x) | 0))) | 0), (Math.imul(((-0x080000000 , mathy0(( + x), (x | 0))) | 0), (Math.cosh(Math.fround(Math.log2(( + Math.min(Math.imul(-0x100000001, x), Math.fround(( ! Math.fround(y)))))))) | 0)) | 0)); }); ");
/*fuzzSeed-42509072*/count=340; tryItOut("mathy1 = (function(x, y) { return mathy0((( - ((Math.hypot(y, (Math.hypot(((mathy0(Math.fround(Math.atanh(Math.fround(-0x080000000))), 0/0) | 0) | 0), ((x != ((Math.sin(x) | 0) | 0)) | 0)) | 0)) > Math.trunc(( - ((Math.fround(( + mathy0(( + x), ( + y)))) << Math.fround(y)) >>> 0)))) >>> 0)) >>> 0), mathy0(Math.cos(Math.sign((Math.min((Math.asinh(Math.fround(x)) | 0), (y | 0)) >>> 0))), ( ~ (Math.sign(Math.fround(( + Math.atan(x)))) >>> 0)))); }); testMathyFunction(mathy1, /*MARR*/[ /x/g , function(){},  /x/g , function(){},  /x/g , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/g ,  /x/g , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, -Infinity, -Infinity, -Infinity, -Infinity, function(){}, function(){}, function(){}, -Infinity,  /x/g , function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){},  /x/g , -Infinity, -Infinity,  /x/g , function(){}, -Infinity, function(){}, -Infinity,  /x/g , -Infinity, function(){},  /x/g , -Infinity, function(){}, function(){}, function(){}, -Infinity, -Infinity,  /x/g , -Infinity, function(){}, -Infinity, function(){}, function(){},  /x/g ,  /x/g , function(){}, function(){}, function(){}, function(){}, -Infinity, -Infinity, -Infinity, function(){}, -Infinity, function(){}, function(){}, function(){}, -Infinity, function(){}, function(){},  /x/g , function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/g , function(){}, function(){}, function(){}, -Infinity, function(){}, -Infinity, function(){}, function(){}, -Infinity, function(){}, function(){}, function(){},  /x/g , -Infinity, function(){}, function(){},  /x/g , function(){}, -Infinity, -Infinity, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, -Infinity, -Infinity, function(){}, function(){}, function(){}, -Infinity, function(){}, function(){},  /x/g ,  /x/g , function(){}, -Infinity, function(){},  /x/g , function(){}, function(){}, -Infinity, function(){}]); ");
/*fuzzSeed-42509072*/count=341; tryItOut("for (var p in t0) { /*ODP-1*/Object.defineProperty(b2, 12, ({writable: (x % 4 != 2), enumerable: (void shapeOf((Math.pow([], /(?:(?:${3}|\u00a9{2,5}.{4,6}{3,4}\ud1b4))|(?=(((?!\\s)))+)|\\1*|(?!(?=[^]))|[^\\u76DA-\u353e\\cN-\ub62b]|[\u0006-\\\u00eb\\u0010-\\\ufb70\u0081-\u1f1b]/gy)) >= (new RegExp(\"(?=(\\\\s))(?![^])\", \"\") ?  /x/g  : a).watch(\"valueOf\",  '' )))})); }");
/*fuzzSeed-42509072*/count=342; tryItOut("mathy3 = (function(x, y) { return Math.fround(((Math.acosh(y) + ((Math.sqrt((Math.log1p((( ! y) >>> 0)) | 0)) | 0) >>> 0)) | ( + Math.pow(( + Math.fround(Math.pow(Math.fround(x), Math.fround(((((x | 0) ? (x | 0) : (-Number.MAX_VALUE | 0)) | 0) === (Math.ceil(( ~ x)) | 0)))))), ( + ( - Math.log2(y))))))); }); testMathyFunction(mathy3, [-1/0, 0, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, 1, 0x100000001, 0.000000000000001, 2**53+2, 2**53-2, -0x080000001, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, 0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), 42, -(2**53-2), -0x100000000, -(2**53+2), -0x100000001, 0/0, 0x100000000, 0x080000000]); ");
/*fuzzSeed-42509072*/count=343; tryItOut("\"use strict\"; v0 = t0.length;");
/*fuzzSeed-42509072*/count=344; tryItOut("e1.has(e1);");
/*fuzzSeed-42509072*/count=345; tryItOut("m1.get(m1);");
/*fuzzSeed-42509072*/count=346; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=347; tryItOut("g0.a2.splice(NaN, 11, s2);");
/*fuzzSeed-42509072*/count=348; tryItOut("mathy2 = (function(x, y) { return Math.acosh((Math.pow(24, mathy1((( + Math.cbrt(( + -Number.MAX_SAFE_INTEGER))) / Math.min(0x0ffffffff, y)), Math.acosh((Math.ceil(((( ! x) >>> 0) >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy2, [({valueOf:function(){return '0';}}), undefined, '\\0', '/0/', true, -0, (new Boolean(true)), '0', ({valueOf:function(){return 0;}}), (new String('')), ({toString:function(){return '0';}}), /0/, 1, false, 0, [], objectEmulatingUndefined(), [0], (new Boolean(false)), NaN, 0.1, (function(){return 0;}), null, (new Number(0)), (new Number(-0)), '']); ");
/*fuzzSeed-42509072*/count=349; tryItOut("v2 = (x % 16 == 9);");
/*fuzzSeed-42509072*/count=350; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-42509072*/count=351; tryItOut("Array.prototype.forEach.apply(g1.a0, []);");
/*fuzzSeed-42509072*/count=352; tryItOut("testMathyFunction(mathy3, [Number.MIN_VALUE, 2**53-2, -0x080000001, -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, 2**53, 42, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, 0x080000000, -(2**53-2), -(2**53), 0, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, 1/0, 0/0, 1, 0x07fffffff, -(2**53+2), -0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -0x080000000, -0]); ");
/*fuzzSeed-42509072*/count=353; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = /*FARR*/[.../*MARR*/[arguments.caller, function(){}, (void 0), {}, (void 0), {}, (void 0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, function(){}, (void 0), arguments.caller, {}, function(){}, arguments.caller, {}, {}, {}, (void 0)], .../*MARR*/[x, x, x, function(){}, function(){}, Number.MAX_SAFE_INTEGER, x, Number.MAX_SAFE_INTEGER, function(){}]].filter(a => -7, (p={}, (p.z = let (y = true) new RegExp(\"\\\\3*|.\\\\B{2,3}+\", \"gm\"))())); print(uneval(s.match(r))); function b(x, ...d) { \"use strict\"; return 3.watch(\"toString\", this.y) } (-24);");
/*fuzzSeed-42509072*/count=354; tryItOut(" for  each(c in \"\\u19B5\") {print(c);var y = Math.log(-21); }");
/*fuzzSeed-42509072*/count=355; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(( ~ Math.fround((( + ( ! (y >>> 0))) > Math.fround(Math.abs((Math.imul(Math.fround(( - Math.fround(Math.atan2(x, y)))), (-0x100000001 | 0)) | 0))))))); }); testMathyFunction(mathy1, [0x080000001, -0x100000000, Number.MAX_VALUE, 2**53-2, -0x100000001, -0x080000001, -1/0, 0/0, -0x080000000, 0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -Number.MAX_VALUE, 0x100000001, 2**53+2, Math.PI, 0x0ffffffff, 0x080000000, 1.7976931348623157e308, -0, 0.000000000000001, -Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53, -0x07fffffff, -(2**53+2), 0, 42, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE]); ");
/*fuzzSeed-42509072*/count=356; tryItOut("var gvbyly = new SharedArrayBuffer(24); var gvbyly_0 = new Float32Array(gvbyly); print(gvbyly_0[0]); var gvbyly_1 = new Uint8Array(gvbyly); print(gvbyly_1[0]); gvbyly_1[0] = 17; var gvbyly_2 = new Uint32Array(gvbyly); print(gvbyly_2[0]); gvbyly_2[0] = -16; print(gvbyly_1);this.a2.forEach();v2 + p2;const sphqtr, ycfgiu, y = (void version(170));(window);v2 + '';print(gvbyly_1);print(uneval(e0));");
/*fuzzSeed-42509072*/count=357; tryItOut("mathy1 = (function(x, y) { return (Math.hypot((Math.fround(Math.pow(Math.fround(Math.hypot(( + y), (mathy0((y >>> 0), ( + Math.sin(( + ( + Math.acosh(( + x))))))) | 0))), ((((( ! Math.fround(((x | 0) > (Math.atan2(( ~ ( + y)), (-0x080000000 >> Math.fround(-0x080000000))) | 0)))) >>> 0) >>> 0) ? (( + Math.imul(( + (( + x) == ( + Math.trunc(Number.MIN_SAFE_INTEGER)))), ( + y))) >>> 0) : (x >>> 0)) >>> 0))) >>> 0), (( + mathy0(( + ( - Math.max(Math.round((( + Math.fround((Math.cos((y | 0)) | 0))) | 0)), (Number.MAX_SAFE_INTEGER >> 0x100000001)))), ( + Math.imul((Math.cosh(((Math.imul(Math.fround(y), Math.fround(( + Math.min((-(2**53-2) | 0), (x | 0))))) >>> 0) >>> 0)) | 0), ((((( ~ (Math.max(0x080000000, y) | 0)) | 0) + Math.fround(x)) | 0) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-(2**53), -Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, -0x080000000, -Number.MIN_VALUE, 0/0, Number.MAX_VALUE, -0x080000001, -0, -Number.MAX_VALUE, 0x080000001, 2**53-2, 0x07fffffff, 1/0, -0x100000001, 2**53+2, Number.MIN_VALUE, 0x100000001, 42, Math.PI, -1/0, 0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 1, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), -(2**53-2), 0x100000000, 0x0ffffffff, -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=358; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42509072*/count=359; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.log1p(Math.imul((( ~ x) || x), ( - y)))); }); testMathyFunction(mathy3, [-(2**53-2), Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, 0x100000001, 0x100000000, 0x0ffffffff, -0x080000000, 2**53+2, Number.MAX_VALUE, -0, 2**53-2, 0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, -0x100000001, 42, 0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, -0x100000000, -0x07fffffff, 1, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -Number.MIN_VALUE, -(2**53+2), 2**53, 0.000000000000001]); ");
/*fuzzSeed-42509072*/count=360; tryItOut("if(true) { if (({x: []} = (4277))) a2.shift(); else o1.v0 = a0.length;}");
/*fuzzSeed-42509072*/count=361; tryItOut("v2 = (h2 instanceof m1);");
/*fuzzSeed-42509072*/count=362; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atanh(( + (Math.expm1(( + (Math.fround(( - ( + -Number.MIN_SAFE_INTEGER))) ? ( + Number.MIN_VALUE) : Math.fround(( + x))))) >>> 0))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, 0x07fffffff, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, -0x080000001, 0x080000000, 1, 0x0ffffffff, -1/0, -(2**53), -0x100000001, 0/0, -(2**53-2), Number.MAX_VALUE, 42, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, 0x100000000, -0x07fffffff, -0, 0, 0.000000000000001, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-42509072*/count=363; tryItOut("r2 = /(?=(?:$))/gim;");
/*fuzzSeed-42509072*/count=364; tryItOut("testMathyFunction(mathy3, [0x0ffffffff, 0x080000000, -0x0ffffffff, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -1/0, -0x080000001, Math.PI, 0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 1, -0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 1/0, -0x07fffffff, -(2**53-2), 0x100000001, -(2**53+2), 42, 0, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, 0/0, -Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-42509072*/count=365; tryItOut("\"use strict\"; print(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })((x ? \"\\uB9DF\" <  /x/  : eval(\"mathy0 = (function(x, y) { \\\"use strict\\\"; return Math.max(Math.fround(Math.imul(( + ( + ( + (( + y) + y)))), Math.fround(Math.abs(( + Math.cos(y)))))), Math.trunc(( - (Math.atan2((( + ((y ? y : x) >>> 0)) >>> 0), (y ? x : y)) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, 2**53+2, 0.000000000000001, -0x080000001, 1, 0x0ffffffff, -0x100000001, Math.PI, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, -(2**53), 2**53-2, 0x080000001, 0, -Number.MAX_VALUE, 0/0, -0, 42, Number.MAX_VALUE, 0x100000000, -1/0, 0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, 1/0, -0x080000000, Number.MIN_VALUE, -(2**53-2), 0x07fffffff]); \")\u0009)), eval));");
/*fuzzSeed-42509072*/count=366; tryItOut("a1 = arguments.callee.caller.caller.arguments;");
/*fuzzSeed-42509072*/count=367; tryItOut("mathy2 = (function(x, y) { return mathy1(Math.fround(( + Math.hypot(( + (((( ! (( ! (0x0ffffffff % x)) >>> 0)) || Math.fround(Math.log10(Math.fround(( + mathy0(( + x), ( + -Number.MIN_SAFE_INTEGER))))))) | 0) && ((Math.atanh((x | 0)) | 0) | 0))), ( + (Math.abs(((Math.hypot(( + x), ( + y)) === (mathy0(2**53, x) >>> 0)) >>> 0)) >>> 0))))), Math.min(( ! Math.acos(y)), (Math.atan2((y >>> 0), ((Math.clz32((((y | 0) ? (y | 0) : (y | 0)) | 0)) ** (0x080000000 >>> 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-42509072*/count=368; tryItOut("\"use strict\"; let(a) ((function(){let(y) { x = d;}})());");
/*fuzzSeed-42509072*/count=369; tryItOut("/*RXUB*/var r = new RegExp(\"(?:.)+\\\\1\", \"gim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-42509072*/count=370; tryItOut("print(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: undefined, hasOwn: Object.prototype.__defineGetter__, get: undefined, set: undefined, iterate: function() { throw 3; }, enumerate: new Function, keys: function() { return Object.keys(x); }, }; })(x), Math.atan2, objectEmulatingUndefined));function x(a = this.__defineGetter__(\"x\", Array.prototype.values), e = x, x, x, {x, c}, x, mathy1 = (function(x, y) { return Math.max(Math.fround((mathy0((Math.imul((Math.max(Math.fround(x), Math.fround((Math.max((x >>> 0), (0x080000001 >>> 0)) >>> 0))) >>> 0), mathy0(y, y)) >>> 0), ((Math.fround((Math.fround(y) > ( + y))) >> y) >>> 0)) & (( + ( ! ( + (Math.min((-(2**53+2) | 0), (x | 0)) | 0)))) - y))), Math.fround(( ~ Math.hypot((((-0x100000000 >>> 0) ? (Math.pow(-Number.MIN_SAFE_INTEGER, x) >>> 0) : ((Math.cbrt((y | 0)) | 0) >>> 0)) >>> 0), Math.acos((Math.sin(mathy0(Math.fround(x), Math.fround(( ~ Math.fround(x))))) | 0)))))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, 0x100000001, -0x080000000, -Number.MIN_VALUE, 0/0, -0x100000000, 0, -0x0ffffffff, -(2**53-2), -0x100000001, 0x07fffffff, -0, 1, 0x100000000, 2**53, 2**53-2, 42, 2**53+2, 0x0ffffffff, 1/0, 0x080000000, 0.000000000000001, -0x07fffffff, Number.MAX_VALUE, -(2**53), -0x080000001]); , d = function(y) { yield y; e1.add(g1);; yield y; }((x =  /x/g ), window = x), e, eval, eval = (4277), [], a, x, x =  '' , x, e, b, x =  '' , x, \u3056 = true, this.x, \u3056, x, x, w = \"\\u84F1\", x = this, x, x, x = \"\\uA67E\", d = new RegExp(\"\\\\B{4,5}|\\u008a\", \"g\"), x = false, x = arguments, z, eval) { return -23 } this;");
/*fuzzSeed-42509072*/count=371; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.asin(( ! ( + Math.max((( ! Math.min(Math.atan2(x, x), -0)) ? y : ( ~ Math.fround(( - y)))), (((1 >>> 0) || (( + Math.asinh(( + x))) >>> 0)) >>> 0))))) >>> 0); }); ");
/*fuzzSeed-42509072*/count=372; tryItOut("/*MARR*/[{x:3},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , 1.3, {x:3}, {x:3},  /x/g ,  /x/g , {x:3}, 1.3, {x:3}, 1.3, {x:3}, 1.3, {x:3}, 1.3, {x:3}, {x:3}, {x:3},  /x/g , {x:3}, 1.3, {x:3}, {x:3}, {x:3}, {x:3}, 1.3,  /x/g ,  /x/g , 1.3,  /x/g , {x:3}, {x:3}, 1.3, 1.3, {x:3},  /x/g , {x:3}, 1.3, {x:3}, {x:3},  /x/g , {x:3}, 1.3, {x:3}, 1.3, {x:3},  /x/g ,  /x/g ,  /x/g , {x:3}, {x:3}, {x:3}, 1.3, {x:3},  /x/g , {x:3}, 1.3, {x:3}, {x:3},  /x/g , {x:3}, {x:3}];");
/*fuzzSeed-42509072*/count=373; tryItOut("\"use strict\"; v1 = Array.prototype.some.call(a1, (function() { v0 = this.a2.every(i0, g1, s1, o1, m0, b0); return o1.b0; }));");
/*fuzzSeed-42509072*/count=374; tryItOut("/*MXX1*/var o1 = o1.g0.Math.cosh;");
/*fuzzSeed-42509072*/count=375; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + (Math.imul((( + Math.imul(( + x), ( + ( + Number.MIN_VALUE)))) ? (((Math.fround(Math.abs((y >>> 0))) >>> 0) * (Math.PI >>> 0)) >>> 0) : y), (Math.pow(Math.fround(y), Math.hypot((( - (Number.MAX_SAFE_INTEGER | 0)) | 0), Math.expm1((0.000000000000001 - y)))) >>> 0)) ? ( + (( + Math.tanh(Math.hypot(y, 2**53-2))) === ( + (( ! Math.abs(x)) && x)))) : (( ~ mathy0(y, y)) , (Math.max((Math.acosh(Number.MIN_VALUE) | 0), ( ~ (((x >>> 0) << Math.cosh(x)) >>> 0))) >>> 0)))); }); testMathyFunction(mathy1, /*MARR*/[0x5a827999, new Number(1.5), ({}), 0x5a827999, new Number(1.5), new Number(1.5), 0x5a827999, ({}), 0x5a827999, ({}), new Number(1.5), 0x5a827999, 0x5a827999, new Number(1.5), ({}), ({}), ({}), ({}), 0x5a827999, 0x5a827999, new Number(1.5), 0x5a827999, 0x5a827999, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), ({}), new Number(1.5), ({}), ({}), 0x5a827999, ({}), 0x5a827999, ({}), 0x5a827999, new Number(1.5), new Number(1.5), ({}), new Number(1.5), ({}), new Number(1.5), new Number(1.5), 0x5a827999, new Number(1.5), 0x5a827999, ({}), ({}), ({}), new Number(1.5), new Number(1.5), ({}), 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, ({}), 0x5a827999, 0x5a827999, ({}), 0x5a827999, ({}), 0x5a827999, ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), 0x5a827999, ({}), 0x5a827999, ({}), ({}), ({}), ({}), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x5a827999, new Number(1.5), ({}), ({}), ({}), new Number(1.5), ({}), 0x5a827999, new Number(1.5), new Number(1.5), 0x5a827999, 0x5a827999, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), ({}), ({}), new Number(1.5), ({}), 0x5a827999, 0x5a827999, new Number(1.5), new Number(1.5), ({}), ({}), new Number(1.5), ({}), new Number(1.5), ({}), 0x5a827999, 0x5a827999, ({}), ({}), ({}), ({}), ({}), 0x5a827999, 0x5a827999, new Number(1.5), 0x5a827999, 0x5a827999, new Number(1.5), 0x5a827999, ({}), 0x5a827999, new Number(1.5), 0x5a827999, ({}), ({}), new Number(1.5), 0x5a827999, 0x5a827999, 0x5a827999, new Number(1.5), 0x5a827999, ({}), ({}), 0x5a827999, 0x5a827999, new Number(1.5), ({}), new Number(1.5), ({}), 0x5a827999, new Number(1.5)]); ");
/*fuzzSeed-42509072*/count=376; tryItOut("v2 = this.r2.flags;");
/*fuzzSeed-42509072*/count=377; tryItOut("mathy3 = (function(x, y) { return mathy2(( + Math.sqrt((y ? y : (Math.fround((((0x0ffffffff - (y | 0)) >>> 0) - -0x07fffffff)) << Math.fround(Math.atan((-0x07fffffff >>> 0))))))), ( + ( ~ ( + ((( - ( + Math.pow(( + Math.cos((( + (-Number.MAX_VALUE | 0)) >>> 0))), (x | 0)))) | 0) - (Math.pow(y, ((x | 0) % x)) | 0)))))); }); ");
/*fuzzSeed-42509072*/count=378; tryItOut("\"use strict\"; e0.delete(o2.e2);");
/*fuzzSeed-42509072*/count=379; tryItOut("h2 = {};const y = eval();");
/*fuzzSeed-42509072*/count=380; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: (c || y)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[-Infinity, [1], -Infinity, -Infinity, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], -Infinity, -Infinity, -Infinity, [1], -Infinity, -Infinity, [1], [1], -Infinity]); ");
/*fuzzSeed-42509072*/count=381; tryItOut("mathy2 = (function(x, y) { return Math.hypot(( ~ (Math.asinh((((y | 0) && (42 != y)) | 0)) >>> 0)), ( - ( + Math.pow((( + (( + (y >> y)) * x)) >>> 0), ((( + mathy1(Math.imul((0/0 | 0), (x | 0)), Number.MIN_SAFE_INTEGER)) / x) >>> 0))))); }); testMathyFunction(mathy2, [0x100000000, 0x07fffffff, -(2**53+2), -(2**53-2), Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, -0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, -(2**53), -1/0, 0x080000001, 0x080000000, 1, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, 0/0, 2**53, Math.PI, -0x080000001, 42, 0x100000001, -0, 1.7976931348623157e308, 0x0ffffffff]); ");
/*fuzzSeed-42509072*/count=382; tryItOut("/*MXX2*/g1.SharedArrayBuffer.prototype.constructor = t1;/*RXUB*/var r = r1; var s = s1; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-42509072*/count=383; tryItOut("M:while((x) && 0){new (Float64Array)();/* no regression tests found */ }");
/*fuzzSeed-42509072*/count=384; tryItOut("/*iii*/{print( /x/ );t2[0]; }/*hhh*/function nbeout(\u3056 = /*MARR*/[new String(''), [1], [1], [1], new String(''), [1], [1], new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Number(1), [1], [1], new String(''), [1], [1], new String(''), [1], [1], [1], new String(''), [1], new String(''), new String(''), [1], new Number(1), new String(''), new String(''), new String(''), new Number(1), [1], new String(''), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Number(1), [1], new String(''), new Number(1), new String(''), [1], new String(''), new Number(1), new Number(1), new String(''), new String(''), new String(''), new Number(1), new Number(1), new Number(1), new Number(1), new String(''), new Number(1), [1], new Number(1), [1], new String(''), new Number(1), [1], new Number(1), [1], new String(''), [1], new String(''), new String(''), [1], new String(''), [1], [1], [1], new Number(1), new String(''), new Number(1), new Number(1), [1], [1], new Number(1), new String(''), [1], new String(''), [1], new Number(1), new Number(1), new Number(1), new String(''), new Number(1), [1], new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new String(''), new Number(1), [1], new Number(1), new String(''), new String(''), new String(''), [1], new Number(1), [1], [1], [1], new String(''), new String(''), new String(''), new String(''), [1], [1], [1], [1], new Number(1), new String(''), [1], new String(''), new String(''), new Number(1), new Number(1), new String(''), new Number(1), new Number(1), [1], new String(''), new Number(1), new String(''), new String(''), [1], new String(''), new Number(1), new Number(1), [1], new String(''), [1], new Number(1), new Number(1), [1], [1], new String(''), [1], [1], [1], new String(''), new String(''), [1], new String(''), new String(''), [1], new String(''), [1]].map((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor:  '' , defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: function() { throw 3; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; }), \"\\uBBB2\")){f2(g2);}");
/*fuzzSeed-42509072*/count=385; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-42509072*/count=386; tryItOut("this.o1.s2 = new String;");
/*fuzzSeed-42509072*/count=387; tryItOut("\"use strict\"; testMathyFunction(mathy1, [2**53+2, -1/0, 0/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, 1, -Number.MAX_VALUE, -(2**53+2), 0x080000001, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, 0x080000000, Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, 42, 0x100000000, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0, -0x100000001, -0x100000000, 1/0, -(2**53), -0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, -0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=388; tryItOut("while((window%=x) && 0){pxvxzh, dlawey, \"\\u4F5E\";h2.valueOf = f2;o2.v2 = g0.runOffThreadScript(); }");
/*fuzzSeed-42509072*/count=389; tryItOut("g0.b0 + this.b2;");
/*fuzzSeed-42509072*/count=390; tryItOut("v1 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-42509072*/count=391; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.asinh(Math.min(-Number.MIN_VALUE, (((Math.log10(y) !== y) >> (x >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-42509072*/count=392; tryItOut("mathy2 = (function(x, y) { return ((Math.max(mathy1(( + (( ! ( - Number.MIN_VALUE)) | 0)), ( + -Number.MIN_SAFE_INTEGER)), ( ~ (( ~ (( - -(2**53)) | 0)) | 0))) | 0) ? ((((mathy1(x, Math.clz32(Math.fround(x))) * ((Math.clz32((x | 0)) | 0) ? y : ( + x))) >>> 0) << ( + Math.fround(( ! Math.fround(( + Math.atan2(( + (x >> ( + Math.hypot(y, x)))), ( + ( ~ x))))))))) | 0) : (mathy0((Math.pow((( + (( + x) > y)) ? (( ~ x) | 0) : y), x) | 0), (Math.acos(( ~ Math.hypot((y >>> 0), Math.min(x, ( + y))))) | 0)) | 0)); }); ");
/*fuzzSeed-42509072*/count=393; tryItOut("\"use strict\"; g2.f0(m1);");
/*fuzzSeed-42509072*/count=394; tryItOut("testMathyFunction(mathy4, [2**53+2, -0x080000001, -(2**53-2), 2**53-2, -0, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, -Number.MAX_VALUE, 42, -1/0, 0x07fffffff, 0.000000000000001, -0x07fffffff, 0x100000000, -0x080000000, -(2**53+2), 1/0, Number.MAX_VALUE, 2**53, 0x0ffffffff, 0/0, 1, 0, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=395; tryItOut("mathy1 = (function(x, y) { return Math.fround((( ~ Math.fround(( - Math.fround(( ~ (((y | 0) !== (-0x100000001 | 0)) | 0)))))) != ((Math.sign(( + Math.cosh(Math.fround(y)))) | 0) ? Math.fround(( ! Math.fround(Math.round(y)))) : Math.min(x, ( + mathy0(Math.fround(Math.sign(Math.fround(x))), (x >>> 0))))))); }); testMathyFunction(mathy1, /*MARR*/[1.2e3,  'A' , 1.2e3,  'A' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 1.2e3, new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), 1.2e3, 1.2e3, new Number(1.5), 1.2e3, (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), new Number(1.5),  'A' ,  'A' , (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )),  'A' , new Number(1.5),  'A' , (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )),  'A' , new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )),  'A' , new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), 1.2e3, (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), 1.2e3, 1.2e3, 1.2e3,  'A' , (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), new Number(1.5),  'A' , 1.2e3,  'A' , new Number(1.5), new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )),  'A' , (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), 1.2e3, new Number(1.5),  'A' , new Number(1.5), new Number(1.5), 1.2e3, (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )),  'A' , new Number(1.5), new Number(1.5),  'A' , 1.2e3, (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )),  'A' ,  'A' , 1.2e3, new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), 1.2e3, new Number(1.5), new Number(1.5),  'A' , 1.2e3, 1.2e3, new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), 1.2e3,  'A' ,  'A' ,  'A' , 1.2e3,  'A' , new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )),  'A' , 1.2e3,  'A' , 1.2e3, (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), 1.2e3,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , new Number(1.5),  'A' , new Number(1.5), 1.2e3, (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), new Number(1.5), (yield \u3056 = Proxy.create(({/*TOODEEP*/})(undefined),  '' )), new Number(1.5),  'A' ,  'A' ,  'A' , new Number(1.5), 1.2e3,  'A' ,  'A' , 1.2e3]); ");
/*fuzzSeed-42509072*/count=396; tryItOut("\"use strict\"; /*infloop*/L:for(false;  \"\" ; this) g1.offThreadCompileScript(\"function f2(m1)  { return undefined } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 == 2), sourceIsLazy: true, catchTermination: true }));\nselectforgc(o0.o2);\n");
/*fuzzSeed-42509072*/count=397; tryItOut("/*vLoop*/for (var yyphqw = 0; yyphqw < 1; ++yyphqw) { b = yyphqw; return \"\\uF799\"; } \nm0.has(b);print((allocationMarker()));\n");
/*fuzzSeed-42509072*/count=398; tryItOut("this.a1.toString = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      d1 = (-7.737125245533627e+25);\n    }\n    (Uint8ArrayView[1]) = (((((0x3c7b95dc)-(0xffffffff)) ^ ((0xffffffff) % (((0xf9dbb697)+((0x7fffffff)))>>>(0x2b901*((-9.44473296573929e+21) >= (1.001953125)))))) != (((imul(((-281474976710657.0) != (-1024.0)), (1))|0) / (~~(d0))) & (-(0x4b1a1015)))));\n    {\n      d0 = (562949953421313.0);\n    }\n    switch ((((1)-(0x2e6031ea)) >> ((0x8167c580)-(1)))) {\n    }\n    {\n      return +((+atan2(((+(abs((abs((((i2)) >> ((0xb13644f4)-((0x7fffffff) > (0x6a8c03b5)))))|0))|0))), ((-1048577.0)))));\n    }\n    return +(( \"\" ));\n  }\n  return f; });");
/*fuzzSeed-42509072*/count=399; tryItOut("print(this.h1);");
/*fuzzSeed-42509072*/count=400; tryItOut("v1 = a0.reduce, reduceRight((function mcc_() { var lymuqy = 0; return function() { ++lymuqy; f0(/*ICCD*/lymuqy % 3 != 1);};})(), v2);");
/*fuzzSeed-42509072*/count=401; tryItOut("mathy3 = (function(x, y) { return (Math.cos(Math.fround(Math.log((((( ~ y) * (x >>> 0)) >> y) / (( + Math.atan2((Number.MIN_VALUE >>> 0), ( + y))) > ( - ( + x))))))) | 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), 42, -0x07fffffff, 0, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000000, 0.000000000000001, 0x100000000, 1, -Number.MAX_VALUE, 2**53, -1/0, -0x080000001, 0x100000001, Number.MIN_VALUE, 0x080000001, -0, -0x0ffffffff, -0x100000000, -(2**53-2), 0x07fffffff, 0x080000000, 2**53-2, 2**53+2, Math.PI, -(2**53+2), 1/0]); ");
/*fuzzSeed-42509072*/count=402; tryItOut("x = 5 ^ x; var r0 = x / 6; var r1 = x | x; r1 = 4 % r0; x = r0 * x; print(r0); var r2 = r0 ^ x; var r3 = r2 / 0; var r4 = 5 | 7; print(r3); var r5 = 8 - 4; var r6 = r0 ^ r3; var r7 = r3 - r4; var r8 = 8 * 6; var r9 = 1 * r1; var r10 = 4 & 6; var r11 = r0 | r1; var r12 = r8 | r2; r5 = 4 * r6; var r13 = 8 % r6; var r14 = r12 + 2; var r15 = r9 ^ 4; var r16 = 7 + r15; var r17 = r5 % r11; var r18 = r15 / r11; r1 = r12 ^ 0; var r19 = r11 | r12; r12 = 0 & 4; var r20 = 2 + r11; var r21 = r14 / 1; var r22 = r19 + r21; var r23 = r10 + r14; var r24 = 5 + r22; var r25 = r9 ^ r0; var r26 = r24 & 8; r14 = 5 / r11; var r27 = r9 ^ x; var r28 = r11 | 4; var r29 = r14 ^ r28; var r30 = 9 | r10; var r31 = r2 + 9; r22 = x - 5; var r32 = r21 % r17; var r33 = r3 / r24; var r34 = r19 * 3; var r35 = r23 | r13; r13 = r7 / r2; x = r11 * r26; var r36 = r6 % r0; r15 = r31 / r34; print(r13); var r37 = 8 ^ r0; var r38 = 2 - 5; var r39 = 8 & r30; var r40 = r23 * r8; var r41 = r19 - r18; var r42 = r8 % 8; var r43 = r26 ^ r0; var r44 = r38 * r31; var r45 = r7 / r37; var r46 = r34 + 7; var r47 = r23 - r22; var r48 = r32 * 1; var r49 = r13 ^ r43; var r50 = 6 | r8; var r51 = r33 - 1; print(r37); var r52 = r44 / 9; print(r13); var r53 = 9 * 9; var r54 = r48 & r45; var r55 = r18 - r53; r54 = r21 + r20; var r56 = x + 1; var r57 = r20 % r6; var r58 = r45 | 0; var r59 = r27 | r0; r51 = r3 % r58; r0 = 5 | r19; var r60 = r15 + r57; var r61 = r60 % 9; var r62 = r10 / r51; var r63 = r54 / 4; r41 = r28 / r12; var r64 = 8 + 7; var r65 = r43 ^ r53; var r66 = 5 / 3; var r67 = r62 + r47; var r68 = r56 + 7; var r69 = 6 % r35; var r70 = r6 - 2; var r71 = 2 % r48; var r72 = r12 | r37; var r73 = r46 / 2; var r74 = 6 + 3; var r75 = r71 % r68; var r76 = r20 + 8; var r77 = 5 | r27; var r78 = r35 / 8; var r79 = 3 - 0; r10 = 5 & r18; var r80 = r49 | r48; var r81 = r34 * 3; var r82 = r15 * r22; var r83 = 0 & r17; print(r27); var r84 = r54 % 7; var r85 = r8 ^ 6; r9 = r12 + r28; var r86 = 4 % r75; ");
/*fuzzSeed-42509072*/count=403; tryItOut("{/*infloop*/for(\n(Math.min(29, 1607965813.5)) in (y = \"\\uB566\"); (p={}, (p.z = ((x))--)()); x) {f1 + f0; } }");
/*fuzzSeed-42509072*/count=404; tryItOut("\"use strict\"; print(p0);");
/*fuzzSeed-42509072*/count=405; tryItOut("mathy0 = (function(x, y) { return Math.expm1(Math.fround(Math.hypot(( ~ ( - 0x100000000)), Math.abs((Math.min(( + Math.asin((y >>> 0))), (y | 0)) >>> 0))))); }); testMathyFunction(mathy0, /*MARR*/[ /x/g , [],  /x/g , function(){}, [], function(){}, [],  /x/g , [],  /x/g , [], [], [], [], [],  /x/g ,  /x/g , function(){},  /x/g ,  /x/g , function(){}, [],  /x/g ,  /x/g , [],  /x/g ,  /x/g , [], function(){}, function(){},  /x/g ]); ");
/*fuzzSeed-42509072*/count=406; tryItOut("\"use asm\"; print(uneval(o0.a2));");
/*fuzzSeed-42509072*/count=407; tryItOut("\"use strict\"; {print(x); }");
/*fuzzSeed-42509072*/count=408; tryItOut("/*tLoop*/for (let c of /*MARR*/[x, [(void 0)], x, x, [(void 0)]]) { for (var v of g0.a1) { try { v0 = new Number(4.2); } catch(e0) { } try { this.e2 + ''; } catch(e1) { } try { g2.m0.set(t1, f2); } catch(e2) { } g1.o1 = {}; } }");
/*fuzzSeed-42509072*/count=409; tryItOut("o1.v2 = g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-42509072*/count=410; tryItOut("for (var v of o1) { try { s1 = a2.join(g2.s1); } catch(e0) { } try { /*hhh*/function erapoe({}, x){/* no regression tests found */}/*iii*/print(-12); } catch(e1) { } this.e0.add(i1); }");
/*fuzzSeed-42509072*/count=411; tryItOut("");
/*fuzzSeed-42509072*/count=412; tryItOut("v1 = this.a1.length;");
/*fuzzSeed-42509072*/count=413; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=414; tryItOut("v1 = (s1 instanceof s1);");
/*fuzzSeed-42509072*/count=415; tryItOut("testMathyFunction(mathy4, /*MARR*/[new Number(1), new Boolean(true), new Number(1), new Number(1),  '\\0' , new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), 0/0, new Number(1), 0/0, new Boolean(true), new String('q'), new String('q'), new Number(1),  '\\0' , 0/0,  '\\0' , 0/0,  '\\0' ,  '\\0' , 0/0, 0/0, 0/0, new Number(1), new String('q'), 0/0, 0/0, 0/0, new Boolean(true), new String('q'), 0/0, 0/0, new String('q'), 0/0,  '\\0' ,  '\\0' , new String('q'),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Boolean(true),  '\\0' , new Boolean(true), new Number(1), 0/0, new Number(1), new Number(1), new Number(1), new String('q'), new Number(1), new Number(1),  '\\0' , new Number(1), new String('q'), new Boolean(true), new String('q'), new Number(1), new Number(1), new Boolean(true),  '\\0' , 0/0, new Number(1), 0/0,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , 0/0, 0/0, 0/0, new Number(1), 0/0, 0/0, new String('q'),  '\\0' , new String('q'), 0/0, new Number(1), new Boolean(true), 0/0, 0/0, new String('q'), 0/0, new Boolean(true), 0/0, new Number(1), new Number(1), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  '\\0' ,  '\\0' , 0/0, 0/0, new Boolean(true),  '\\0' , new Number(1), new String('q'),  '\\0' , 0/0, new Boolean(true),  '\\0' , new Number(1), new String('q'), new Boolean(true), new Boolean(true),  '\\0' , 0/0, 0/0, new Number(1), new Boolean(true), new Number(1), new String('q'), new String('q'), new String('q'),  '\\0' ,  '\\0' , new Boolean(true), 0/0, new String('q'), new Number(1), new String('q'), new Number(1), 0/0, new Number(1), 0/0, new String('q'), 0/0, 0/0,  '\\0' , new String('q'), new Number(1), 0/0,  '\\0' , new Number(1), 0/0, new Boolean(true), new String('q'), new Boolean(true), 0/0, new String('q'), new Boolean(true), new String('q'), new String('q'), new Number(1), 0/0, 0/0,  '\\0' , new Number(1)]); ");
/*fuzzSeed-42509072*/count=416; tryItOut("\"use strict\"; h0 + ''\nm0.delete(g0);");
/*fuzzSeed-42509072*/count=417; tryItOut("testMathyFunction(mathy2, [-0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, -0x100000001, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x080000001, -(2**53), 0x0ffffffff, 0x07fffffff, 1, 0x100000000, -Number.MAX_VALUE, Math.PI, 2**53+2, 0, Number.MAX_VALUE, 0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -0x07fffffff, -0, 0.000000000000001, 2**53-2, 2**53, 0x080000000, -(2**53+2), -Number.MIN_VALUE]); ");
/*fuzzSeed-42509072*/count=418; tryItOut("var tdusyr = new ArrayBuffer(4); var tdusyr_0 = new Uint16Array(tdusyr); print(tdusyr_0[0]); var tdusyr_1 = new Int8Array(tdusyr); tdusyr_1[0] = 18014398509481984; var tdusyr_2 = new Uint16Array(tdusyr); tdusyr_2[0] = -10; (Root(-2, window));for (var v of g0) { for (var v of h0) { try { o2.g2.offThreadCompileScript(\"function f2(f1)  { yield  /x/g  } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval:  /x/g , sourceIsLazy: (tdusyr_1[0] % 43 == 38), catchTermination: true })); } catch(e0) { } try { this.g2.e2.add(o0.o2.g1); } catch(e1) { } a0.shift(); } }Array.prototype.reverse.apply(a2, [this.e2]);");
/*fuzzSeed-42509072*/count=419; tryItOut("/*vLoop*/for (mipxwd = 0; mipxwd < 15; ++mipxwd) { const w = mipxwd; Object.prototype.unwatch.call(o2, \"__proto__\"); } ");
/*fuzzSeed-42509072*/count=420; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.atan2((( ! Math.fround(Math.fround(Math.max(Math.fround(( ! (Math.cos(( + ( + (y | 0)))) >>> 0))), Math.fround(Math.fround((Math.fround(x) ? x : Math.fround((((x >>> 0) === (Number.MAX_SAFE_INTEGER | 0)) | 0))))))))) >>> 0), (( ! ( + (( + 0x07fffffff) >> ( + Math.hypot((Math.pow((-0x07fffffff | 0), (( ! (0/0 | 0)) | 0)) >>> 0), y))))) | 0)); }); testMathyFunction(mathy3, [0/0, 0.000000000000001, 2**53, 42, -(2**53), 2**53-2, 0x080000000, 1/0, Number.MAX_VALUE, 0x100000001, -0, 0, -(2**53+2), -0x100000001, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, 0x080000001, -0x080000000, 0x0ffffffff, -(2**53-2), -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 1, -0x080000001, Number.MIN_VALUE, Math.PI, 1.7976931348623157e308, -Number.MAX_VALUE]); ");
/*fuzzSeed-42509072*/count=421; tryItOut("v1 = (o1.g0.p2 instanceof g2.g0);");
/*fuzzSeed-42509072*/count=422; tryItOut("Array.prototype.pop.apply(a1, [f0, t2, e1, this.f1, o1, v1]);");
/*fuzzSeed-42509072*/count=423; tryItOut("\"use strict\"; /*infloop*/M: for  each(let RegExp.multiline in w) {print(x);this.a0 = arguments.callee.arguments;e2.add(g0); }");
/*fuzzSeed-42509072*/count=424; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2(Math.asinh((Math.min(((((( + Math.asinh((0/0 ^ (x >>> 0)))) | 0) ** 0x0ffffffff) | 0) >>> 0), ((( + (Math.fround(( + Math.fround(Math.tan(x)))) | 0)) | 0) >>> 0)) >>> 0)), (((Math.atan2(y, mathy0(-0x0ffffffff, x)) ** y) >>> 0) ** mathy0(((( - Number.MAX_SAFE_INTEGER) || x) >>> 0), Math.fround(( ~ (Math.fround(( - x)) >>> 0)))))) >>> 0); }); testMathyFunction(mathy3, [0x0ffffffff, -0x080000001, 2**53-2, 0x100000000, 1/0, 0/0, -0x080000000, -(2**53-2), 0x07fffffff, 0, 0x080000001, -0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1, -(2**53), -1/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, 2**53, 0x080000000, 0.000000000000001, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0, -0x0ffffffff, -(2**53+2), 1.7976931348623157e308]); ");
/*fuzzSeed-42509072*/count=425; tryItOut("g1.offThreadCompileScript(\"o2.f1 = (function() { for (var j=0;j<53;++j) { f2(j%4==1); } });\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 != 3), sourceIsLazy: true, catchTermination: x ** (4277), sourceMapURL: this.s0 }));");
/*fuzzSeed-42509072*/count=426; tryItOut("\"use strict\"; i0.toSource = (function() { try { a0 = Array.prototype.concat.apply(a1, [a1, a1, t0, g1.a2, this.t1, a1, a0, t0]); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(e2, p2); return this.e2; });");
/*fuzzSeed-42509072*/count=427; tryItOut("mathy0 = (function(x, y) { return ( ! ( + (( ~ (Math.atan2(x, Math.fround(Math.atan2(Math.fround((( + Math.sqrt(( + 42))) ** y)), Math.fround(y)))) | 0)) | 0))); }); ");
/*fuzzSeed-42509072*/count=428; tryItOut("\"use strict\"; (x ? new runOffThreadScript(Math.cosh(-1)) : typeof ({a:  /x/g })\n);");
/*fuzzSeed-42509072*/count=429; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(mathy0(Math.fround(Math.log10(( ~ ( ~ y)))), (Math.round(x) ? (mathy1((mathy2((Math.clz32(((x >= y) >>> 0)) >>> 0), x) >>> 0), (Math.fround(Math.round(Math.fround(( + ( ~ ( + (Math.ceil(x) >>> 0))))))) >>> 0)) >>> 0) : (mathy0(( - -0x080000000), y) | 0)))); }); testMathyFunction(mathy3, [0.000000000000001, 2**53, 1.7976931348623157e308, 0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, -0, -(2**53-2), 0x07fffffff, 0x080000000, 1/0, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000000, -0x080000001, -0x0ffffffff, -0x100000001, 0, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, 0x080000001, -Number.MIN_VALUE, -(2**53+2), 0/0, Number.MAX_VALUE, 42, Math.PI, 2**53+2]); ");
/*fuzzSeed-42509072*/count=430; tryItOut("\"use asm\"; testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MAX_VALUE, Math.PI, -0x100000000, 1.7976931348623157e308, 2**53, -0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 0x100000001, -0x0ffffffff, 0x0ffffffff, -(2**53), 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -0, 0, 2**53-2, Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, -0x100000001, 42, 0x080000000, 1/0]); ");
/*fuzzSeed-42509072*/count=431; tryItOut("testMathyFunction(mathy3, [-0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 0/0, 2**53, 1.7976931348623157e308, Math.PI, -0x100000001, -1/0, 1/0, 0x080000000, 2**53+2, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), 0x080000001, 0x07fffffff, -0, -0x0ffffffff, -(2**53+2), 0x100000000, -0x07fffffff, 1]); ");
/*fuzzSeed-42509072*/count=432; tryItOut("\"use strict\"; with({w: x}){g2.a0 = r0.exec(s2); }");
/*fuzzSeed-42509072*/count=433; tryItOut("\"use strict\"; o1.g1.e0.toSource = Object.prototype.__defineSetter__;");
/*fuzzSeed-42509072*/count=434; tryItOut("mathy1 = (function(x, y) { return Math.pow(Math.hypot(Math.fround(( ~ Math.fround(Math.hypot(( + ( + (((0x100000001 >>> 0) * (y >>> 0)) >>> 0))), 1/0)))), ((((Math.imul((y | 0), (( + y) | 0)) | 0) >>> 0) < Math.fround(Math.max(Math.abs((x !== x)), x))) >>> 0)), Math.clz32(( + mathy0((( ! (Math.min(0x0ffffffff, (y | 0)) | 0)) >>> 0), ( + Math.asin((x === y))))))); }); testMathyFunction(mathy1, [-0, 0x080000001, 0/0, -(2**53), -0x07fffffff, 2**53-2, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 1/0, 2**53, 42, Math.PI, -0x100000000, 0x100000001, -0x0ffffffff, 2**53+2, -0x080000000, 1.7976931348623157e308, 0.000000000000001, 1, -(2**53+2), 0x100000000, 0, 0x07fffffff, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-42509072*/count=435; tryItOut("o1 = a2.__proto__;");
/*fuzzSeed-42509072*/count=436; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.fround((( - ( ! ( ! Math.fround(Math.fround(Math.hypot(Math.fround(x), Math.fround((x >= (Math.atan2(y, x) >>> 0))))))))) | 0)) != Math.fround((Math.cos(Math.atanh(Math.acosh(( + ((x >>> 0) - (mathy0((x | 0), (( + y) > ( + x))) | 0)))))) | 0))); }); testMathyFunction(mathy5, [1/0, 0/0, -(2**53-2), -0, -Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, 2**53+2, -1/0, 0x07fffffff, -0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0x0ffffffff, -Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), -0x080000001, 1.7976931348623157e308, 0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, 0x100000001, -0x080000000, 42, 0x080000000, 0x080000001, -0x100000001]); ");
/*fuzzSeed-42509072*/count=437; tryItOut("let c, x = undefined, d = (neuter).call((Math.min(-25, length)), allocationMarker()), x, tpyrxc;{a1.splice(-13, 12, f2, t0);print(x); }");
/*fuzzSeed-42509072*/count=438; tryItOut("\"use strict\"; var bioslq = new SharedArrayBuffer(0); var bioslq_0 = new Uint8Array(bioslq); print(bioslq_0[0]); bioslq_0[0] = 17; v2 = g2.eval(\"print(x);\");\n\u0009with((WeakMap.prototype.set).call(window, )){print( \"\" ); }\n");
/*fuzzSeed-42509072*/count=439; tryItOut("/*MXX1*/o2 = g2.g0.Proxy.length;");
/*fuzzSeed-42509072*/count=440; tryItOut("mathy1 = (function(x, y) { return Math.round(Math.clz32(Math.tan(( + x)))); }); testMathyFunction(mathy1, [2**53-2, 1/0, -0x080000001, Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 42, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 0, -Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, 0x100000000, 0x100000001, -0x07fffffff, 0x07fffffff, 0x080000000, 2**53, -0, -0x100000001, 1.7976931348623157e308, 2**53+2, 0x0ffffffff, 0x080000001, 0.000000000000001, 0/0, -(2**53-2), Math.PI, Number.MIN_VALUE]); ");
/*fuzzSeed-42509072*/count=441; tryItOut("\"use strict\"; new RegExp(\"(?=($))\", \"gym\");g0.v0 = b2.byteLength;");
/*fuzzSeed-42509072*/count=442; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x07fffffff, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 0.000000000000001, -(2**53+2), 0x080000001, 1/0, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE, 0/0, -1/0, -0, -Number.MIN_SAFE_INTEGER, 1, -0x100000000, -0x080000001, -(2**53-2), -Number.MIN_VALUE, 0x100000000, Math.PI, 0x080000000, -(2**53), -0x0ffffffff, 0]); ");
/*fuzzSeed-42509072*/count=443; tryItOut("M:switch(true) { default: g0.offThreadCompileScript(\"Math.hypot(Math.log( '' ), this.zzz.zzz = ({x: /*RXUE*/new RegExp(\\\"$|(?!\\\\\\\\r{0}){2,5}|(?:[^])|[\\\\\\\\u00f4\\\\\\\\ua858\\\\\\\\W]{16777216,16777216}|\\\\\\\\B\\\", \\\"gyi\\\").exec(\\\"\\\")}))\");break;  }");
/*fuzzSeed-42509072*/count=444; tryItOut("\"use strict\"; \"use asm\"; a1.splice(NaN, 8);");
/*fuzzSeed-42509072*/count=445; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy1((( + Math.fround((Math.imul(x, Math.atanh(x)) > Math.fround(Math.abs(( ~ ( + x))))))) ? ( + (x | ( ~ x))) : ( + Math.hypot(x, -0x07fffffff))), Math.fround(mathy2(Math.fround(( + Math.round(Math.atan2(Math.asinh(Math.asinh(x)), mathy3(Math.fround(Number.MAX_SAFE_INTEGER), Math.atan2(2**53-2, x)))))), Math.fround((( ! ((-0x080000001 + x) | 0)) | 0))))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -(2**53), 0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 1, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, -(2**53+2), 0x100000001, 42, 0.000000000000001, -0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, 2**53, -(2**53-2), Math.PI, 0x080000001, 0x080000000, -0]); ");
/*fuzzSeed-42509072*/count=446; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(a0, m1);");
/*fuzzSeed-42509072*/count=447; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.clz32(( ~ (2**53 * ( - (y | 0)))))); }); testMathyFunction(mathy5, [-0x0ffffffff, -0x100000001, -0x100000000, 1, 0.000000000000001, 2**53, -0x07fffffff, 0x080000001, -(2**53-2), -1/0, -(2**53+2), -Number.MIN_VALUE, -0, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MAX_VALUE, 0x100000000, 0, 42, 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 0x100000001, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, 2**53+2, 0x0ffffffff]); ");
/*fuzzSeed-42509072*/count=448; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.acosh(((Math.clz32((( + Math.trunc(x)) * (( - (mathy2(y, ( + mathy1((-0x07fffffff >>> 0), (x >>> 0)))) | 0)) | 0))) >>> 0) != ((Math.pow(Math.fround((((y >>> 0) ? (x >>> 0) : (y >>> 0)) >>> 0)), Math.fround(( + (y | 0)))) == ( ! Math.fround((( - -0x0ffffffff) , y)))) | 0))); }); testMathyFunction(mathy3, [0x080000001, -(2**53), 0/0, 1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, 1.7976931348623157e308, -(2**53-2), 2**53-2, 0x100000000, Math.PI, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, -0x100000000, 42, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -0, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, -1/0, 0, 2**53, Number.MAX_VALUE, -0x100000001, 2**53+2]); ");
/*fuzzSeed-42509072*/count=449; tryItOut(";");
/*fuzzSeed-42509072*/count=450; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(Math.fround((Math.max((Math.atan2((Math.ceil((((x | -(2**53-2)) >>> 0) >>> 0)) >>> 0), mathy0(y, (0 | 0))) | 0), (( ~ ((Math.atan2(( + x), ( + 0)) >>> 0) | 0)) | 0)) << mathy0(( + Math.round(x)), ( + mathy0((x >>> 0), Math.min((1 >>> 0), Math.imul(y, y))))))), Math.atan(((Math.fround(Math.imul(Math.fround(( - x)), y)) | 0) < (Math.log(Math.fround(x)) >>> 0)))); }); testMathyFunction(mathy1, [2**53-2, -0, -0x080000000, -0x0ffffffff, -0x080000001, -0x100000001, Math.PI, 0.000000000000001, 1/0, 2**53, 0/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -(2**53+2), -Number.MAX_VALUE, 2**53+2, 1, -Number.MIN_VALUE, -(2**53), -0x100000000, 0, 42, Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, 0x100000001, 0x07fffffff]); ");
/*fuzzSeed-42509072*/count=451; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (mathy4((Math.atan2((Math.fround(Math.hypot(((Number.MIN_VALUE >>> Math.fround(x)) >>> 0), Math.fround(y))) !== mathy3(0, y)), Math.fround(Math.tanh(x))) < (Math.exp((0/0 >>> 0)) >>> 0)), Math.fround(Math.min(( ~ 0x07fffffff), ( ! ( + ((Math.fround(x) ? x : (x >>> 0)) | (y | 0))))))) ^ (((Math.log10((Math.sin(x) >>> 0)) >>> 0) ^ Math.log(y)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[ /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g ,  /x/g , objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined()]); ");
/*fuzzSeed-42509072*/count=452; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.log((( + Math.atan2((( ! Math.imul(y, x)) && ( + 0x080000001)), (( ~ (2**53 >>> 0)) >>> 0))) >>> 0))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000000, -0x080000000, 0, -(2**53), -0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), 42, 0x0ffffffff, -Number.MIN_VALUE, 0x080000001, -0x080000001, 1/0, -1/0, -0x0ffffffff, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, 0x100000000, -(2**53+2), 0x100000001, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x100000000, 2**53-2, -0, 0/0]); ");
/*fuzzSeed-42509072*/count=453; tryItOut("switch(window) { default: e0.__proto__ = t2;break;  }");
/*fuzzSeed-42509072*/count=454; tryItOut("{/* no regression tests found */print(x); }");
/*fuzzSeed-42509072*/count=455; tryItOut("a0.forEach((function() { try { a2.toSource = (function mcc_() { var byebvx = 0; return function() { ++byebvx; if (/*ICCD*/byebvx % 3 == 1) { dumpln('hit!'); try { s1 += 'x'; } catch(e0) { } try { t0[0] = \"\\u67B2\"; } catch(e1) { } a2.splice(NaN, o1.g2.g0.v0); } else { dumpln('miss!'); try { v0 = a0.length; } catch(e0) { } try { a0.splice(NaN, 6, g1); } catch(e1) { } print(this.p2); } };})(); } catch(e0) { } try { s1 + e0; } catch(e1) { } try { function f1(b1) \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (((1)-((0xcc1e2bef))-(0xf888dd19)));\n    return (((0xffffffff)+(i1)))|0;\n  }\n  return f; } catch(e2) { } v1 = this.g1.eval(\"/* no regression tests found */\"); return this.a2; }));");
/*fuzzSeed-42509072*/count=456; tryItOut("testMathyFunction(mathy4, [0/0, 1.7976931348623157e308, -0x100000000, Number.MIN_VALUE, 0x100000000, 2**53+2, -Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0x080000001, 0.000000000000001, Number.MAX_VALUE, -0x080000000, -0x0ffffffff, 2**53-2, Math.PI, -Number.MAX_VALUE, 1, -(2**53), 0x080000001, -0, -(2**53-2), -0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 0x0ffffffff, 42, -(2**53+2)]); ");
/*fuzzSeed-42509072*/count=457; tryItOut("/*RXUB*/var r = /\\B\\0+/gm; var s = \"\\uCAEF\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-42509072*/count=458; tryItOut("g2.g0.v0 = r2.global;");
/*fuzzSeed-42509072*/count=459; tryItOut("");
/*fuzzSeed-42509072*/count=460; tryItOut("with({x: -2})print(x);");
/*fuzzSeed-42509072*/count=461; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ~ (Math.fround(mathy4(( + Math.tanh(( + Math.log1p(x)))), (( - ( + Math.log10(( + x)))) | 0))) + mathy1(Math.fround(Math.imul(Math.hypot(( + (( + -(2**53-2)) != (x | 0))), 2**53), (((( - ( + ( ! ( + x)))) >>> 0) && (x | 0)) | 0))), x))); }); ");
/*fuzzSeed-42509072*/count=462; tryItOut("L:with((4277)){a1.reverse();a2 = arguments.callee.caller.caller.caller.arguments; }");
/*fuzzSeed-42509072*/count=463; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul(Math.imul(( - y), Math.imul(Math.fround(( + (Math.sinh(Math.fround(( + Math.pow(y, -Number.MIN_VALUE)))) >>> 0))), (mathy0(-0x100000001, ( + Math.ceil(y))) | 0))), Math.hypot(Math.fround(Math.atanh(y)), Math.cosh(( + x)))); }); testMathyFunction(mathy2, [0.000000000000001, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 42, -0, 0, 1, 0x0ffffffff, Number.MIN_VALUE, 0x100000000, -0x080000000, -0x07fffffff, -(2**53-2), -0x100000001, -0x080000001, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, 0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -1/0, -(2**53), 2**53, Math.PI, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=464; tryItOut("\"use strict\"; v1 = evalcx(\";var b = ((z) = ((void options('strict_mode'))));\", g0);");
/*fuzzSeed-42509072*/count=465; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( - (Math.sinh(( ~ (( + Math.atan2(y, ( ! ((Math.fround(Math.PI) >>> ( + x)) >>> 0)))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[1e4, 1e4, 0x40000001, -Number.MAX_SAFE_INTEGER, 0x40000001]); ");
/*fuzzSeed-42509072*/count=466; tryItOut("o0.a2.shift();");
/*fuzzSeed-42509072*/count=467; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.min((Math.hypot((-0 ** Math.min(Math.hypot(x, y), 0.000000000000001)), (( + (Math.fround((( + 0.000000000000001) ? Math.fround(y) : Math.fround(y))) >>> 0)) >>> 0)) | 0), (( + Math.fround(mathy1((( + (x >>> 0)) >>> 0), ( + arguments.callee.caller.caller.caller)))) >>> 0)); }); testMathyFunction(mathy4, [-0, ({valueOf:function(){return '0';}}), '0', null, ({valueOf:function(){return 0;}}), undefined, '/0/', ({toString:function(){return '0';}}), 0, false, /0/, '\\0', '', 0.1, (new Number(-0)), (new Number(0)), [0], NaN, (new String('')), (function(){return 0;}), (new Boolean(false)), 1, true, (new Boolean(true)), objectEmulatingUndefined(), []]); ");
/*fuzzSeed-42509072*/count=468; tryItOut("for (var v of v1) { f0 + h1; }");
/*fuzzSeed-42509072*/count=469; tryItOut("for (var v of e2) { f2.toSource = (function() { try { /*MXX2*/g2.Date.prototype.getMilliseconds = this.v0; } catch(e0) { } g2.m2 = new Map(t2); return f1; }); }");
/*fuzzSeed-42509072*/count=470; tryItOut(";");
/*fuzzSeed-42509072*/count=471; tryItOut("\"use strict\"; a0[9] = t0;");
/*fuzzSeed-42509072*/count=472; tryItOut("/*tLoop*/for (let e of /*MARR*/[2**53-2, 2**53-2, 2**53-2, false, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, false, false, 2**53-2, false, 2**53-2, false, 2**53-2, 2**53-2, 2**53-2, false, false, false, 2**53-2, false, 2**53-2, 2**53-2, false, false, false, 2**53-2, 2**53-2, false, false, 2**53-2, 2**53-2, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 2**53-2, 2**53-2, 2**53-2, 2**53-2, false, false, false, 2**53-2, 2**53-2, 2**53-2, 2**53-2, false, 2**53-2, 2**53-2, 2**53-2, false, 2**53-2, 2**53-2, 2**53-2, false, false, false, false, 2**53-2, 2**53-2, false, false, false, false, 2**53-2, false, 2**53-2, 2**53-2, false, 2**53-2, false, false, 2**53-2, 2**53-2, false, false]) { t0[0] = x; }");
/*fuzzSeed-42509072*/count=473; tryItOut("testMathyFunction(mathy0, [Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, -1/0, 0x0ffffffff, -0x080000000, -0x080000001, -(2**53+2), 0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, 0x100000000, -(2**53-2), 1, -Number.MIN_VALUE, 2**53, -(2**53), -0x0ffffffff, 1/0, -0x07fffffff, 0x080000000, -0x100000001, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, 2**53-2, 42, Math.PI, Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-42509072*/count=474; tryItOut("/*iii*/khfyzg = x;/*hhh*/function khfyzg(\u3056, getter)\u000d{g0.a0 = arguments.callee.arguments;}");
/*fuzzSeed-42509072*/count=475; tryItOut("/*oLoop*/for (let niiyst = 0; niiyst < 136; ++niiyst) { a1.shift(); } ");
/*fuzzSeed-42509072*/count=476; tryItOut("this.m2.delete(f2);");
/*fuzzSeed-42509072*/count=477; tryItOut("/*ODP-1*/Object.defineProperty(s1, \"call\", ({configurable: intern(((Math.pow(-14, -17))())), enumerable: (x % 6 == 1)}));");
/*fuzzSeed-42509072*/count=478; tryItOut("mathy5 = (function(x, y) { return mathy4(Math.fround(Math.max(mathy4(((Math.fround(Math.cosh(y)) , (( + ( + ( + -0))) >>> 0)) >>> 0), (( ! Math.fround(Math.min(Math.fround(x), Math.fround(x)))) < Math.fround(Math.clz32(y)))), (Math.pow(((((( ! y) & -0x07fffffff) & (mathy0(( + -(2**53)), x) >>> 0)) >>> 0) | 0), ( + ((((( ~ (Math.atan((2**53-2 | 0)) | 0)) | 0) - y) >>> 0) | ((y >= x) >>> 0)))) | 0))), mathy1((Math.hypot(((((mathy1(y, (2**53 >>> 0)) >>> 0) || -(2**53-2)) >>> 0) >>> 0), (x >>> 0)) >>> 0), ( + (( + Math.abs(( + ( ~ x)))) >>> 0)))); }); testMathyFunction(mathy5, [0, -0x07fffffff, 2**53-2, 0x100000001, -0x080000001, 2**53, 0x080000001, -(2**53-2), 2**53+2, 0.000000000000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, -(2**53), -0x0ffffffff, -0x100000000, -0x080000000, -Number.MAX_VALUE, 1/0, 0x100000000, 0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1, -0, -0x100000001, Number.MIN_VALUE, Math.PI, 0x080000000]); ");
/*fuzzSeed-42509072*/count=479; tryItOut("");
/*fuzzSeed-42509072*/count=480; tryItOut("\"use strict\"; zxpapc, ztvgbp, this.x, udvgnq;h2.valueOf = (function(j) { if (j) { try { v0 = t0[\"\\u4035\"]; } catch(e0) { } try { Object.defineProperty(this, \"a0\", { configurable: (x % 6 != 5), enumerable: false,  get: function() {  return []; } }); } catch(e1) { } try { i0 = m0.values; } catch(e2) { } g1.p1 = Proxy.create(h0, t1); } else { try { e1 + ''; } catch(e0) { } try { v2 = t1.BYTES_PER_ELEMENT; } catch(e1) { } m2.set(s1, this.o1.h0); } });a1 = arguments.callee.arguments;");
/*fuzzSeed-42509072*/count=481; tryItOut("g1.s1 += s0;");
/*fuzzSeed-42509072*/count=482; tryItOut("if((void options('strict_mode'))) \u000c/*MXX2*/g0.WeakMap.name = this.o2.i0; else  if (x) {Array.prototype.unshift.call(a0, o0.p0);/*tLoop*/for (let y of /*MARR*/[[undefined], (1/0), [undefined], [undefined], [undefined], (1/0), [undefined], (1/0), [undefined], [undefined]]) { this.p2.valueOf = (function() { try { g1.o2 = Object.create(o0); } catch(e0) { } try { g1.v0 = Array.prototype.reduce, reduceRight.apply(a1, [f2]); } catch(e1) { } o0.a1 + this.o0.g2.t0; return h2; }); } } else {{v2 = Object.prototype.isPrototypeOf.call(e0, e1); } }");
/*fuzzSeed-42509072*/count=483; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-42509072*/count=484; tryItOut("v2 = Object.prototype.isPrototypeOf.call(o1.o1, f2);");
/*fuzzSeed-42509072*/count=485; tryItOut("mathy0 = (function(x, y) { return (Math.log2(( + (((( + Math.clz32(( + 1/0))) | 0) ^ (( + ( - -Number.MIN_VALUE)) | 0)) | 0))) !== ( ! ((x | 0) - ((Math.atan2(x, (Math.min((Math.fround((Math.fround(0x080000001) + Math.atan2(y, x))) >>> 0), (x >>> 0)) | 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -1/0, 1/0, -(2**53+2), Math.PI, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, 2**53+2, Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -(2**53), -(2**53-2), -0x080000001, 0/0, 0x100000000, -0x080000000, 0, 1, 2**53, -0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 1.7976931348623157e308, 42]); ");
/*fuzzSeed-42509072*/count=486; tryItOut("\"use strict\"; \"use asm\"; /*bLoop*/for (let fjjaoi = 0; fjjaoi < 9 && (Math.log2(x)); ++fjjaoi) { if (fjjaoi % 5 == 1) { h1.iterate = (function() { for (var j=0;j<26;++j) { f2(j%2==0); } }); } else { for(let y in (function() { \"use strict\"; yield (({z: [[]]})); } })()) y.lineNumber; }  } ");
/*fuzzSeed-42509072*/count=487; tryItOut("v2 = evalcx(\"v1 = t0.length;\", this.g2);");
/*fuzzSeed-42509072*/count=488; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42509072*/count=489; tryItOut("Array.prototype.shift.apply(a1, []);");
/*fuzzSeed-42509072*/count=490; tryItOut("function shapeyConstructor(guhzvg){delete this[\"caller\"];if (guhzvg) { {print(x);m0.set(e0, this.b1); } } this[\"getUTCMilliseconds\"] = encodeURI;return this; }/*tLoopC*/for (let a of (x for (x in (x << 15)) for each (b in /*MARR*/[(void 0),  /x/ ,  /x/ , (void 0),  /x/ ,  '\\0' ,  '\\0' ,  /x/ ,  '\\0' , (void 0), (void 0),  /x/ , (void 0),  /x/ ,  '\\0' ,  /x/ ,  /x/ ,  '\\0' ]) for each (x in (p={}, (p.z = x)())))) { try{let drzjwj = new shapeyConstructor(a); print('EETT'); /*MXX2*/g1.SyntaxError = i2;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-42509072*/count=491; tryItOut("f0.toString = f0;");
/*fuzzSeed-42509072*/count=492; tryItOut("\"use strict\"; a1.toString = f0;g2 = this;");
/*fuzzSeed-42509072*/count=493; tryItOut("mathy4 = (function(x, y) { return Math.max(( + ((((((x - Math.log10((y | 0))) | 0) <= (Math.hypot(( ~ x), -(2**53-2)) | 0)) >>> 0) >>> 0) << (((Math.hypot((((((y | 0) !== (-0x100000001 | 0)) | 0) << -1/0) > y), Math.fround((Math.atanh((x | 0)) | 0))) >>> 0) % (0x100000000 >>> 0)) >>> 0))), ( + (((((( + Math.tanh(-(2**53-2))) | 0) , (Math.imul(( + (Math.min((y >>> 0), (x >>> 0)) >>> 0)), Math.fround(( ~ Math.fround(x)))) | 0)) >>> 0) >>> 0) === Math.fround(mathy3((( + ( + x)) >>> 0), (Math.fround(((y ? -0x100000001 : (-0x0ffffffff === y)) >= -0x0ffffffff)) | 0)))))); }); testMathyFunction(mathy4, /*MARR*/[ \"\" , x,  \"\" , x,  \"\" , x, [1], [1],  \"\" , [1], [1], [1], x, x, x, x,  \"\" ,  \"\" ,  \"\" , [1], x, x, x,  \"\" ]); ");
/*fuzzSeed-42509072*/count=494; tryItOut("s1 += 'x';function x(x, x, e, x, x, {}, a, y, w, getter, x, x, a = NaN, y, copyWithin, a, eval, a, x, x, window, c, b, x, x, x, w, x, e, d, z, x = this, x, e, x, x, x, eval, x, x, x = -3, x, y, x, x, x, false =  '' , x, x, a, x, this.x, x, d, y, x, \u3056, \u3056, x, w, d, NaN, x, c, x, z, window, x, c, w, x, let, x, x =  /x/ , x, c, x, x =  /x/ , a, e =  '' ) { Array.prototype.unshift.apply(a0, [this.h0, g0, t0]); } ((/*UUV2*/(eval.toLocaleUpperCase = eval.isArray) && ((x) = /*FARR*/[new RegExp(\"(?=(?=(?=\\\\v)){1})+[^\\\\S\\\\S\\\\d]|\\\\2+*\", \"i\"), 22,  \"\" , , x].some(null,  '' ))));");
/*fuzzSeed-42509072*/count=495; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; validategc(false); } void 0; } /*tLoop*/for (let z of /*MARR*/[\"\\u890E\", \"\\u890E\", [(void 0)], [(void 0)],  '\\0' ]) { for (var v of o1) { try { t2[17] = i1; } catch(e0) { } for (var p in p0) { try { h1.__iterator__ = (function() { h0.getOwnPropertyNames = g2.f0; return f0; }); } catch(e0) { } try { h1.getPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var sin = stdlib.Math.sin;\n  var tan = stdlib.Math.tan;\n  var ceil = stdlib.Math.ceil;\n  var atan2 = stdlib.Math.atan2;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    switch ((~~(+pow((((-1025.0) + (2097153.0))), ((Float64ArrayView[2])))))) {\n      case 1:\n        i0 = ((i0) ? (((i2) ? (d1) : (3.8685626227668134e+25)) < (-18446744073709552000.0)) : (!((i2))));\n        break;\n      case 0:\n/*UUV1*/(x.big = function(y) { return  /x/  });        break;\n      case -2:\n        d1 = (+((((0xcb441f28) != (0x32825a17))+(i0))>>>((i0)-((imul(((0x55e62f04) >= (((0xf954eefa)) ^ ((0x4c84619d)))), (i0))|0)))));\n      case -3:\n        {\n;        }\n        break;\n      case -2:\n        {\n          i0 = ((((abs((imul(((((0x38d140e5)+(0x5b22727c))>>>((i2)))), (/*FFI*/ff(((abs((((0xbcc11a4b)) >> ((-0x8000000))))|0)), ((abs((((0xffffffff)) >> ((0xffffffff))))|0)))|0))|0))|0))>>>((Uint16ArrayView[(((0xffffffff))) >> 1]))));\n        }\n      case -3:\n        {\n          return ((((((((0xffffffff)) ? (i2) : (i0))) & ((((0x75b579be)-(0xf8ac2bca))|0) % (((0x1195e46f)+(0xf1d64178))|0))) <= (0x62b6c482))-((((imul((!(0x143b877b)), ((0x20fd50ef) >= (0x354473b3)))|0) / (((0xff304174)-(0x255fea34)+(0xfa430fe2))|0)) << (([z1,,])+(i0))))-(0xef2de78f)))|0;\n        }\n        break;\n    }\n    i2 = (i0);\n    {\n      return ((((((-5.0) >= (+/*FFI*/ff(((0x7fffffff)), ((131071.0)), ((-512.0)), ((1.001953125)), ((137438953472.0))))) ? (NaN) : (+(-1.0/0.0))) >= (+/*FFI*/ff((((((0x859bc0a6) > (((+sin(((d1)))))))) ^ ((i0)-((0xfca1056f) ? (-0x8000000) : (0xfc2c0da1))+(i0)))))))+((~(((+(((0x88ad330b)*0x1f202)>>>((0xffffffff)*0xc7f0f))) < (-0.03125)))) <= ((((i2) ? (-0x8000000) : (0xbdec5fe3))+(-0x8000000)) >> ((/*FFI*/ff(((0x6f3dd525)), ((((0xf8c28edd)+(0xa204d2fb)) & ((0x9ee39f09)))), ((-134217729.0)))|0))))))|0;\n    }\n    {\n      {\n        d1 = ((+tan(((6.044629098073146e+23)))) + (+/*FFI*/ff(((d1)), ((+ceil(((((Float64ArrayView[((0x749ba72a)*0xfffff) >> 3])) - ((d1))))))), ((abs(((Int32ArrayView[((i0)+(i2)) >> 2])))|0)), ((+atan2(((-295147905179352830000.0)), ((+(0.0/0.0)))))))));\n      }\n    }\n    {\n{for (var p in o2) { try { this.m1.delete(f1); } catch(e0) { } try { o1.v1 = (f2 instanceof v1); } catch(e1) { } try { g0.a1 = []; } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(a2, i1); }x; }    }\n    return (((((((x)+((0x7fffffff) > (0x69837520))-((0xaff8de5) == (0x1a83dc8e)))|0) % (((Uint8ArrayView[2])) >> (((0x42076193) == (0x691c493f))))) << (((0xfffff*((0xfb273f31) ? (0x55e0ad95) : (0xef748f7c))) & (((0x17c698a8) ? (0xb4db5d01) : (0xf54b14ed))-((0x67b1b5) > (0xbfef95c5)))) % (~((i2))))) % (((/*FFI*/ff(((8589934593.0)), (((-0xdc8a1*(/*FFI*/ff()|0)) | ((0x2da531bb)-(-0x8000000)+(0xfaeb148b)))), ((-140737488355327.0)), ((-8589934591.0)), ((+floor(((-17592186044416.0))))), ((8193.0)), ((-34359738367.0)), ((-7.0)), ((-513.0)), ((-524289.0)), ((-147573952589676410000.0)), ((-1.125)), ((1.2089258196146292e+24)), ((6.189700196426902e+26)), ((1.125)), ((17592186044417.0)))|0)+((((i2)+(!(0xfafe3024))) | ((0xe84c6413)-(0xffffffff)+(0xcc74c838))) == (~~(((d1)) * ((-1.0078125))))))|0)))|0;\n  }\n  return f; })(this, {ff: Object.entries}, new ArrayBuffer(4096)); } catch(e1) { } s0 += g1.s0; } } }");
/*fuzzSeed-42509072*/count=496; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(a0, o1);");
/*fuzzSeed-42509072*/count=497; tryItOut("s1 + o1;");
/*fuzzSeed-42509072*/count=498; tryItOut("M:\nswitch((yield new RegExp(\"(?:(?:$))[^]|.{0,}\", \"gym\"))) { case 6: (this.yoyo( \"\" ));break;  }");
/*fuzzSeed-42509072*/count=499; tryItOut("\"use strict\"; /*infloop*/for(x = \"\\uF184\"; x; x * +(window + -23)) for([c, b] = x in [[1]]) this.g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: \"\\u6DF1\" }));");
/*fuzzSeed-42509072*/count=500; tryItOut(";print(h2);");
/*fuzzSeed-42509072*/count=501; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, -1/0, -0x080000001, 0x080000000, 2**53-2, -0x100000001, 1.7976931348623157e308, -0x080000000, Number.MIN_VALUE, 0x080000001, Math.PI, 0x07fffffff, -(2**53-2), -0x07fffffff, -0x100000000, 0x100000001, -Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 1/0, 0/0, 1, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 0, 42, 2**53+2, 2**53, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-42509072*/count=502; tryItOut("\"use strict\"; [[1]];return;");
/*fuzzSeed-42509072*/count=503; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! (Math.max((Math.sign((Math.min((Math.round((y >>> 0)) >>> 0), Math.PI) >>> 0)) | 0), (mathy3(( ! Math.abs(Math.fround(mathy1(Math.fround(y), Math.fround(1))))), (x - ( + Math.round(( + x))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, 42, 0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -(2**53-2), -Number.MAX_VALUE, -0x07fffffff, 0x100000000, 0x100000001, -Number.MIN_VALUE, 2**53, Math.PI, 0x0ffffffff, 0, 2**53+2, 1.7976931348623157e308, Number.MIN_VALUE, -0, 1, Number.MAX_VALUE, -0x080000000, 0.000000000000001, -(2**53+2), -(2**53), -0x0ffffffff]); ");
/*fuzzSeed-42509072*/count=504; tryItOut("x;");
/*fuzzSeed-42509072*/count=505; tryItOut("/*hhh*/function rbhqus(a, x){this.a1.reverse(g0.g2.o1.o0);}rbhqus(x, -14);");
/*fuzzSeed-42509072*/count=506; tryItOut("y = throw  /x/ .__proto__ = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: Array.prototype.slice, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: (4277), delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(((({/*toXFun*/toSource: ((function(x, y) { return x; })).call, window: [z1](x, 0) })) &= x)), Math.imul((4277), -4));g0.h0.fix = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      switch ((0xf6ff80)) {\n        default:\n          d0 = (d1);\n      }\n    }\n    (Float64ArrayView[(((+(~((0xd414841a)))) >= (((4398046511105.0)) % ((3.022314549036573e+23))))+(0xfd02cce3)-(!((0x7f73b693)))) >> 3]) = ((Int32ArrayView[4096]));\nt1 = t2.subarray(null);    (Float64ArrayView[((~(((0xa4400598) ? (0x93be0a3) : (0xce7314e2))*0x5b660)) / (imul((0xfc84c914), (0xf9bfbb99))|0)) >> 3]) = ((d1));\n    d0 = (+(1.0/0.0));\n    return (((0xffffffff)*-0xa8de6))|0;\n  }\n  return f; })(this, {ff: function(y) { /* no regression tests found */ }}, new SharedArrayBuffer(4096));");
/*fuzzSeed-42509072*/count=507; tryItOut("testMathyFunction(mathy1, /*MARR*/[function(){}, (-1/0), function(){}, function(){}, function(){}, [], function(){}, 0x99, 0x99, [], [], 0x99, (-1/0), undefined, 0x99, undefined, (-1/0), undefined, [], (-1/0), (-1/0), 0x99, (-1/0), function(){}, 0x99, 0x99, undefined, (-1/0), undefined, 0x99, undefined, 0x99, [], 0x99, function(){}, (-1/0), undefined, [], 0x99, 0x99, [], (-1/0), 0x99, 0x99, 0x99, undefined, undefined, (-1/0), (-1/0), [], function(){}, function(){}, function(){}, function(){}, [], 0x99, [], 0x99, function(){}, 0x99, [], function(){}, undefined, [], function(){}, (-1/0), undefined, function(){}, (-1/0), undefined, [], 0x99, (-1/0), 0x99, [], function(){}, function(){}, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, 0x99, [], [], [], undefined, undefined, function(){}, undefined, function(){}, 0x99, 0x99, 0x99, 0x99, [], function(){}, function(){}, undefined, function(){}, undefined, [], function(){}, function(){}, undefined, undefined, (-1/0), [], [], [], undefined, function(){}, (-1/0), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], (-1/0), undefined, (-1/0), (-1/0), (-1/0), [], 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99]); ");
/*fuzzSeed-42509072*/count=508; tryItOut("/*hhh*/function rixsrt(d, b, NaN, window, z, e, window, d = x, c, window, \u3056, NaN = 27, x, x, x, x = [[]], x, a = this, x, w, x, mathy3 = (function(x, y) { \"use strict\"; return (( - (( ~ Math.expm1(x)) | 0)) | 0); }); testMathyFunction(mathy3, [0x080000001, 0x07fffffff, -0x080000001, 1.7976931348623157e308, 0x100000000, 0.000000000000001, -0x07fffffff, -Number.MAX_VALUE, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, Math.PI, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0, 2**53+2, -0x100000001, 0/0, -(2**53), -0x0ffffffff, Number.MAX_VALUE, 0x100000001, 42, 1, -0x080000000, -(2**53-2), 0x080000000, 2**53-2, -0, -(2**53+2)]); , x, -7, y, y, x, a, e, x, b, x, x, \u3056, \u3056 = x, x, z = this, eval, c, \u3056, eval = \"\\uD23F\", y, let, y, x, x, z, x, e, x = c, pop, e, d, d, NaN, x, z, of, e, w, x = true, eval, x = [[1]], x, x){g0.v2 = a0.length;}/*iii*/e1.add(t0);");
/*fuzzSeed-42509072*/count=509; tryItOut("/*ODP-3*/Object.defineProperty(v2, \"isSealed\", { configurable: true, enumerable: (eval(\"((x = (void version(185))))\")), writable: false, value: e2 });");
/*fuzzSeed-42509072*/count=510; tryItOut("testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -0x100000000, -(2**53+2), -(2**53), 42, 2**53+2, 1/0, 0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, -0x080000000, 0/0, 0x080000001, Math.PI, -0x100000001, 0x080000000, -0x080000001, 0x07fffffff, -1/0, 2**53, 0.000000000000001, -0, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, 0x0ffffffff, -(2**53-2), 1]); ");
/*fuzzSeed-42509072*/count=511; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((((( + Math.log1p(Math.log10(Math.fround((Math.fround(Math.min(2**53, 1)) / Math.fround((( ~ (x >>> 0)) >>> 0))))))) | 0) | (( + x) | 0)) | 0) ^ ((((Math.fround(Math.fround(Math.fround(y))) | 0) | (Math.imul(x, Math.fround((Math.fround(Math.fround(( + Math.fround(y)))) << (x >>> 0)))) | 0)) | 0) > Math.min(((( ~ y) >>> 0) | y), (Math.imul(Math.fround(( - (y ? x : (y >>> 0)))), (x != -0)) | 0)))); }); testMathyFunction(mathy0, [0.000000000000001, 2**53+2, -1/0, -0x080000001, 0/0, -(2**53-2), 1, 2**53-2, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53, -0, -0x080000000, 0x100000000, -(2**53+2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, 0x080000001, -0x100000000, 0x080000000, 42, -0x100000001, 0, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=512; tryItOut("\"use strict\"; v1 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-42509072*/count=513; tryItOut("Object.prototype.watch.call(g2.i1, \"length\", (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13) { var r0 = 1 % 3; var r1 = a3 * a10; a8 = 6 & 3; var r2 = 0 & a11; var r3 = a13 - a4; var r4 = 6 ^ a4; var r5 = a0 - r2; var r6 = 8 * 6; var r7 = 8 / a0; a0 = r3 - 1; var r8 = a6 ^ a6; print(r7); var r9 = a8 | 9; var r10 = r7 + r7; var r11 = r8 - r9; a9 = a7 | a3; var r12 = r2 & r11; var r13 = r10 % 4; var r14 = r5 - 2; var r15 = 2 | 1; var r16 = a12 | a1; var r17 = a9 % 0; a4 = 9 + a10; var r18 = 8 + r17; print(r14); var r19 = r16 % a10; a6 = a3 + r7; var r20 = r1 & r3; var r21 = r20 & a4; var r22 = 3 * a10; r1 = 6 | a1; var r23 = r14 / a9; var r24 = r4 % a8; var r25 = x % r9; var r26 = a1 | a8; a5 = r1 - r17; var r27 = 6 ^ a8; var r28 = r23 ^ a8; print(r26); var r29 = 7 | 6; var r30 = r21 - r21; r3 = r29 + r9; var r31 = r26 + 2; var r32 = 7 * r17; var r33 = 2 ^ r30; var r34 = r9 / a10; r18 = a10 - r20; var r35 = 6 + r32; var r36 = r19 & r31; var r37 = 8 % 0; var r38 = a10 % r9; var r39 = r36 ^ r33; var r40 = a3 ^ r26; var r41 = r17 - r22; var r42 = 9 ^ a7; var r43 = 8 - 8; var r44 = r38 % 5; var r45 = r3 * r9; var r46 = a7 | 3; var r47 = r42 * r28; r32 = r46 ^ a11; a9 = r5 ^ 4; var r48 = a2 % r37; var r49 = x & 8; var r50 = r9 + 9; var r51 = r16 % r36; var r52 = r8 ^ 7; var r53 = r47 + 9; r49 = 6 + r44; var r54 = r41 % r17; var r55 = r5 | r48; var r56 = 3 - r47; var r57 = r56 / 5; var r58 = 5 % 6; var r59 = r32 * 6; var r60 = 1 - a2; var r61 = 8 | r1; var r62 = r38 + 8; var r63 = r0 * r57; r4 = 6 - r34; var r64 = r6 | a13; var r65 = 8 + r39; r18 = r31 | r17; var r66 = 3 + 4; var r67 = r3 & 5; var r68 = r21 & 7; var r69 = r6 ^ 6; var r70 = r4 ^ r12; var r71 = r0 | 7; var r72 = 3 * r59; r42 = 7 | r54; var r73 = 1 - 9; var r74 = 7 & 7; var r75 = r13 & a12; var r76 = r7 / r25; var r77 = 5 | r30; r24 = 6 & r70; var r78 = r3 | r67; r11 = r72 ^ r24; var r79 = r47 ^ r9; print(r18); var r80 = 0 ^ a3; var r81 = r51 / r2; var r82 = r59 - a1; r8 = 1 - 3; var r83 = r39 & 3; var r84 = r25 ^ r21; return a11; }));");
/*fuzzSeed-42509072*/count=514; tryItOut("this.a2.shift();");
/*fuzzSeed-42509072*/count=515; tryItOut("/*RXUB*/var r = /.|(?!\\2)+?|\\B|(?:\\3+?)?|\u00a5/gym; var s = \"\\u00c5\"; print(s.match(r)); ");
/*fuzzSeed-42509072*/count=516; tryItOut("mathy2 = (function(x, y) { return Math.min(((Math.cbrt(((((y | 0) ? Math.fround(( ~ Math.fround(0))) : ( + ((((x | 0) != (( + ( ! ( + y))) | 0)) | 0) | 0))) | 0) >>> 0)) >>> 0) >>> 0), (( - (( - -Number.MIN_SAFE_INTEGER) ? (( + Math.sin(x)) && y) : x)) >>> 0)); }); ");
/*fuzzSeed-42509072*/count=517; tryItOut("\"use strict\"; { void 0; void gc(); }");
/*fuzzSeed-42509072*/count=518; tryItOut("with({c: new eval(\"/* no regression tests found */\",  /x/g )(x, ([]) = /(?=(?=^\\2[\\s\\\u00bcX]|[^]))/y\n)}){yield; }");
/*fuzzSeed-42509072*/count=519; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2(Math.fround(Math.tan(Math.imul(((y != x) >>> (((Math.ceil((y >>> 0)) | 0) >>> 0) ** (x | 0))), Math.clz32(( + Math.fround(Math.atan2(( + y), Math.fround(y)))))))), Math.hypot((( + ( ~ 1/0)) | 0), Math.fround(Math.pow(Math.min((((y * 0x07fffffff) >>> 0) | 0), x), (Math.log(Math.fround(1/0)) | 0))))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), (new Number(-0)), null, (new Number(0)), 1, (new Boolean(false)), false, 0.1, ({valueOf:function(){return 0;}}), '', '\\0', (new Boolean(true)), objectEmulatingUndefined(), 0, /0/, NaN, '0', '/0/', -0, ({toString:function(){return '0';}}), true, (new String('')), undefined, [0], [], (function(){return 0;})]); ");
/*fuzzSeed-42509072*/count=520; tryItOut("testMathyFunction(mathy4, /*MARR*/[-0xB504F332, x, x, -0xB504F332, x, -0xB504F332, -0xB504F332, -0xB504F332, x, -0xB504F332, -0xB504F332, -0xB504F332, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, -0xB504F332, x]); ");
/*fuzzSeed-42509072*/count=521; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.sqrt(Math.hypot(( ~ y), ((((Math.min((0x07fffffff >= -Number.MAX_VALUE), Math.acos((( + Math.pow(( + Number.MIN_SAFE_INTEGER), y)) | 0))) | 0) < ((Math.pow(Math.fround(( + ( ~ y))), Math.fround(y)) >>> 0) | 0)) | 0) >>> ((mathy1((Math.fround(( + ( + Math.fround(Math.imul((x >>> 0), (1/0 >>> 0)))))) >>> 0), (x | 0)) >>> 0) , y)))); }); testMathyFunction(mathy4, [0.000000000000001, -1/0, 0x0ffffffff, -0x080000000, 42, Number.MIN_SAFE_INTEGER, 2**53-2, -0, Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), -Number.MAX_VALUE, 2**53, Number.MAX_VALUE, -(2**53+2), 0x07fffffff, -(2**53), 0x100000001, 0x080000000, -0x07fffffff, -0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, 1, -0x100000000, 0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, 2**53+2, -0x080000001]); ");
/*fuzzSeed-42509072*/count=522; tryItOut("\"use strict\"; let (c) { delete h2.iterate; }");
/*fuzzSeed-42509072*/count=523; tryItOut("e1 = new Set;");
/*fuzzSeed-42509072*/count=524; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.cos(( + (( + ( ~ Math.log10(x))) | 0))); }); testMathyFunction(mathy1, [-0x07fffffff, -0x080000001, Math.PI, 0x080000001, 1.7976931348623157e308, -0x100000001, 0/0, 0x0ffffffff, -Number.MAX_VALUE, 0x100000000, -0, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 42, -Number.MAX_SAFE_INTEGER, 1, -1/0, 0x080000000, 2**53+2, -Number.MIN_VALUE, 2**53, 2**53-2, Number.MIN_VALUE, -(2**53), -(2**53-2), Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, 1/0, Number.MAX_VALUE, 0]); ");
/*fuzzSeed-42509072*/count=525; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-42509072*/count=526; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-42509072*/count=527; tryItOut("a2.sort((function(j) { if (j) { try { g0 + ''; } catch(e0) { } try { e2.add(v2); } catch(e1) { } try { this.s0 = new String(g1); } catch(e2) { } a0 = Array.prototype.concat.apply(a2, [a1]); } else { try { v0 = (o2.i2 instanceof f1); } catch(e0) { } try { o1.h1.has = f2; } catch(e1) { } try { a2.push({y} = e, f0, p2); } catch(e2) { } Array.prototype.push.apply(a2, [t0]); } }), s0, o2.e1, v1);");
/*fuzzSeed-42509072*/count=528; tryItOut("a2.shift(e1);");
/*fuzzSeed-42509072*/count=529; tryItOut("/*RXUB*/var r = x; var s = \"a_a_\"; print(uneval(s.match(r))); ");
/*fuzzSeed-42509072*/count=530; tryItOut("\"use strict\"; print(o2.t2);");
/*fuzzSeed-42509072*/count=531; tryItOut("\"use strict\"; /*infloop*/L:for(let NaN in  '' ) {e2.add(v1);v0 = r2.compile; }");
/*fuzzSeed-42509072*/count=532; tryItOut("\"use strict\"; eval = x, NaN = (4277), x = x =  /x/g , hknkng, x = x, a = let (\u3056 = (4277), \u3056 = let (c) window -= -21 != true, x = (delete c.w), e = x, eval =  /x/  in -26) x, {b: []} = new 9().__proto__%=x--(true, /*MARR*/[new Number(1.5), this, this, new String(''), new Number(1.5), this, new Number(1.5), this]), eval = x, vwqxpb;/*ODP-3*/Object.defineProperty(a2, (\u3056 = \"\\u6848\"), { configurable: false, enumerable: false, writable: true, value: o2.g2 });");
/*fuzzSeed-42509072*/count=533; tryItOut("g2 = this;");
/*fuzzSeed-42509072*/count=534; tryItOut("mathy0 = (function(x, y) { return Math.fround(( + ((Math.acosh(((((((( + Math.cbrt(Math.fround(Math.log((Number.MIN_SAFE_INTEGER >>> 0))))) >>> 0) >> (-0x100000000 >>> 0)) >>> 0) !== (Math.acos((Math.cbrt((( ! (x | 0)) | 0)) >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 0x07fffffff, 0x100000000, 1.7976931348623157e308, 0.000000000000001, 0x100000001, -0, -0x0ffffffff, -0x100000001, -0x080000000, -0x100000000, -0x080000001, -0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53), Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, 2**53, Number.MIN_SAFE_INTEGER, 42, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53+2), 1, 1/0, 2**53-2, 0/0, 2**53+2]); ");
/*fuzzSeed-42509072*/count=535; tryItOut("/*RXUB*/var r = /\\2/gy; var s = \"\\n\"; print(r.test(s)); ");
/*fuzzSeed-42509072*/count=536; tryItOut("var gfxkiu = new SharedArrayBuffer(12); var gfxkiu_0 = new Int16Array(gfxkiu); gfxkiu_0[0] = 0.96; var gfxkiu_1 = new Float64Array(gfxkiu); print(gfxkiu_1[0]); var gfxkiu_2 = new Uint32Array(gfxkiu); var gfxkiu_3 = new Int8Array(gfxkiu); print(gfxkiu_3[0]); gfxkiu_3[0] = -36893488147419103000; var gfxkiu_4 = new Float32Array(gfxkiu); gfxkiu_4[0] = 0; var gfxkiu_5 = new Uint8Array(gfxkiu); print(gfxkiu_5[0]); var gfxkiu_6 = new Float64Array(gfxkiu); gfxkiu_6[0] = -18; var gfxkiu_7 = new Uint8Array(gfxkiu); var gfxkiu_8 = new Int32Array(gfxkiu); gfxkiu_8[0] = -13; a1 + '';a1.pop(this.b2,  /x/ );");
/*fuzzSeed-42509072*/count=537; tryItOut("o0.o1.f0.toSource = o2.f1;");
/*fuzzSeed-42509072*/count=538; tryItOut("/* no regression tests found */");
/*fuzzSeed-42509072*/count=539; tryItOut("h2.set = f2;");
/*fuzzSeed-42509072*/count=540; tryItOut("\"use strict\"; ;");
/*fuzzSeed-42509072*/count=541; tryItOut("/*vLoop*/for (egykhy = 0; egykhy < 55; ++egykhy) { z = egykhy; s2 += s2; } ");
/*fuzzSeed-42509072*/count=542; tryItOut("for(var c = x in (/*MARR*/[033, 2**53-2, x, 033, x, 2**53-2, x].some(Date.prototype.setFullYear, false) >>>= (/*UUV1*/(y.padEnd = ArrayBuffer.isView)(x = x,  '' )))) print(c);");
/*fuzzSeed-42509072*/count=543; tryItOut("\"use strict\"; var r0 = 8 ^ x; var r1 = 1 | x; var r2 = 3 - x; var r3 = 1 * 5; var r4 = r2 / r0; var r5 = r3 & r2; var r6 = 1 % r3; var r7 = x - 9; var r8 = r7 & 4; var r9 = 0 ^ r8; var r10 = r9 | r6; r9 = 4 % r2; var r11 = r9 ^ 4; var r12 = r4 % r9; var r13 = 1 & r11; var r14 = r9 | r9; r9 = r0 & 3; var r15 = r1 + r11; var r16 = r0 ^ r14; var r17 = r10 * 5; var r18 = r3 % r8; var r19 = r9 ^ 1; var r20 = r6 + 9; var r21 = 4 & 5; var r22 = 5 * 4; var r23 = r8 - r10; var r24 = r14 * r6; var r25 = r16 / r3; r20 = r5 + r25; var r26 = r3 | r13; var r27 = r14 - r5; var r28 = r14 - x; var r29 = r9 ^ r7; var r30 = r22 - r2; var r31 = r26 & r25; var r32 = r23 - r26; var r33 = 9 / r15; r7 = r23 * 6; var r34 = r12 * 2; var r35 = r4 ^ r25; r7 = r34 * r3; var r36 = r1 / 0; var r37 = r21 ^ r17; r26 = 2 | 1; var r38 = 5 ^ r9; var r39 = 7 & 0; r11 = r10 | 4; r14 = 0 ^ r26; var r40 = x % r39; r20 = 4 | 6; var r41 = r19 - r36; print(r7); var r42 = r5 ^ 1; var r43 = r42 + r4; var r44 = r34 & 6; print(r16); var r45 = 4 + r6; var r46 = r23 / r22; var r47 = r32 % 7; ");
/*fuzzSeed-42509072*/count=544; tryItOut("\"use strict\"; g0.m0.get(p0);");
/*fuzzSeed-42509072*/count=545; tryItOut("g1.offThreadCompileScript(\"((e = (let (window = a, gkaqof, ecellt) this)))\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-42509072*/count=546; tryItOut("testMathyFunction(mathy3, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, 0x0ffffffff, Math.PI, 0.000000000000001, -0x100000000, -0, -1/0, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, -0x100000001, -0x080000000, -(2**53+2), 1.7976931348623157e308, Number.MIN_VALUE, 0, 0x100000001, 0x100000000, -(2**53-2), -0x080000001, 1/0, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, 42, 0x080000000, -0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000001]); ");
/*fuzzSeed-42509072*/count=547; tryItOut("\"use strict\"; s0 += this.s0;");
/*fuzzSeed-42509072*/count=548; tryItOut("\"use strict\"; (void schedulegc(g1));function eval(b, ...\u3056) { yield (new String('')(yield this)) } var zdyihd = new SharedArrayBuffer(2); var zdyihd_0 = new Float64Array(zdyihd); zdyihd_0[0] = -7; var zdyihd_1 = new Uint16Array(zdyihd); zdyihd_1[0] = -5; for (var p in m1) { try { e0.__proto__ = this.i1; } catch(e0) { } try { for (var p in v2) { try { neuter(b1, \"same-data\"); } catch(e0) { } print(uneval(g1)); } } catch(e1) { } for (var v of this.g2) { try { Array.prototype.unshift.call(a1, a0, v2, b2); } catch(e0) { } try { const v1 = a2.reduce, reduceRight(f1, e2); } catch(e1) { } try { Array.prototype.sort.apply(a1, [f1, m1, s0]); } catch(e2) { } a2.shift(); } }var qkecfr, zdyihd_0[0], zdyihd_1[0], xqxnzc, e, gsabfb, dykoej;print( \"\" );");
/*fuzzSeed-42509072*/count=549; tryItOut("L:with({b: (let (z = 0x0ffffffff.yoyo(window))  /x/g )}){Array.prototype.pop.call(a0); }for (var p in g2) { try { Array.prototype.push.call(a1); } catch(e0) { } g0.o1 = a2.__proto__; }");
/*fuzzSeed-42509072*/count=550; tryItOut("/*tLoop*/for (let w of /*MARR*/[arguments.caller,  /x/g ,  /x/g , arguments.caller, (0/0), (0/0), (0/0),  /x/g , (0/0), arguments.caller, (0/0),  /x/g , arguments.caller, (0/0),  /x/g ,  /x/g , arguments.caller, (0/0), new Boolean(false), arguments.caller, new Boolean(false), (0/0), arguments.caller, (0/0), new Boolean(false), (0/0), new Boolean(false), (0/0), arguments.caller,  /x/g , arguments.caller, arguments.caller, (0/0),  /x/g , (0/0), (0/0),  /x/g , (0/0),  /x/g ,  /x/g , arguments.caller, arguments.caller, new Boolean(false), (0/0),  /x/g , arguments.caller, (0/0), (0/0),  /x/g , arguments.caller, new Boolean(false), arguments.caller, new Boolean(false), (0/0), arguments.caller, (0/0),  /x/g , new Boolean(false), (0/0), (0/0), new Boolean(false), (0/0), arguments.caller, new Boolean(false), new Boolean(false),  /x/g , (0/0),  /x/g ]) { for(let e in /*FARR*/[(Math.cosh(window)), w]) with({}) try { let(x, w = -6.__defineSetter__(\"\\u3056\", DataView.prototype.setFloat32)) { throw eval;} } catch(z if w) { o0.v2 = (o1 instanceof o2); } /* no regression tests found */ }");
/*fuzzSeed-42509072*/count=551; tryItOut("o1.a2.push(h0);");
/*fuzzSeed-42509072*/count=552; tryItOut("mathy0 = (function(x, y) { return (Math.min((Math.trunc((Math.pow(( ! -Number.MAX_VALUE), ( + Math.imul(( + (Math.log((y | 0)) | 0)), (Math.cosh(Math.fround(x)) | 0)))) ? Math.hypot(x, 2**53) : Math.cos(x))) >>> 0), (((( + Math.fround((((x | 0) && x) | 0))) ? (y !== -(2**53+2)) : y) >>> 0) / ((Math.sqrt(((Math.expm1(Math.fround(y)) >>> 0) >>> 0)) >>> 0) >>> 0))) >>> 0); }); testMathyFunction(mathy0, [-(2**53), -0x0ffffffff, 0x100000001, 42, 0x080000001, 1.7976931348623157e308, 0, -0x080000001, -(2**53-2), 0/0, 0x07fffffff, 1/0, -0x100000000, -0x100000001, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 1, -0, -0x07fffffff, Number.MAX_VALUE, 2**53, 0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-42509072*/count=553; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.log1p((( - Math.fround(Math.sinh((Math.hypot((((Math.asin((x | 0)) | 0) >>> 0) , (y >>> 0)), ((42 >>> 0) | (( + (y >>> 0)) >>> 0))) >>> 0)))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[ /x/ , false, ({}),  /x/ , ({}), false, false,  /x/ , ({}),  '' , false,  '' , false, false, false,  /x/ , false, ({}),  '' , ({}),  '' , false,  '' ,  /x/ ,  '' ,  /x/ , false,  /x/ ,  /x/ ,  /x/ ,  '' ,  /x/ ,  '' ,  '' , ({}), ({}), false,  /x/ , ({}), ({}), false, ({})]); ");
/*fuzzSeed-42509072*/count=554; tryItOut("/*RXUB*/var r = r2; var s = this.s2; print(uneval(s.match(r))); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
