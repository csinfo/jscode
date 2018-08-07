

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
/*fuzzSeed-28551573*/count=1; tryItOut("testMathyFunction(mathy0, [null, -0, objectEmulatingUndefined(), 0, 1, '/0/', (function(){return 0;}), true, '\\0', (new String('')), ({valueOf:function(){return '0';}}), /0/, (new Number(0)), [0], (new Number(-0)), NaN, (new Boolean(false)), [], false, ({toString:function(){return '0';}}), '0', 0.1, undefined, '', ({valueOf:function(){return 0;}}), (new Boolean(true))]); ");
/*fuzzSeed-28551573*/count=2; tryItOut("mathy5 = (function(x, y) { return (( + (( - ( ! (mathy4(((((y + (x >>> 0)) ? (y >> Number.MAX_SAFE_INTEGER) : Number.MAX_VALUE) | 0) | 0), x) | 0))) | 0)) >= (Math.atan2((mathy4((mathy2(0.000000000000001, y) >>> 0), (Math.atanh((Math.asinh(( ! (1.7976931348623157e308 >>> 0))) | 0)) >>> 0)) >>> 0), (( - (x >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-1/0, 0x080000000, Number.MAX_VALUE, 1/0, 0x100000001, -(2**53), 0, 2**53-2, -0x100000000, 0x0ffffffff, -0x07fffffff, -0x100000001, Number.MIN_VALUE, 1, -0x080000001, -0, 0x080000001, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, -(2**53+2), -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 0/0, 0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 42, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=3; tryItOut("print((({ set callee c (d) { return x = Proxy.create(({/*TOODEEP*/})(\"\\u1DCD\"), 17) }  })));");
/*fuzzSeed-28551573*/count=4; tryItOut("\"use strict\"; v1 = (g1 instanceof a1);");
/*fuzzSeed-28551573*/count=5; tryItOut("a1.sort((function() { for (var j=0;j<62;++j) { f1(j%4==1); } }));");
/*fuzzSeed-28551573*/count=6; tryItOut("/*infloop*/while(Math.pow(((uneval([z1]))), 22))v0 = r2.compile;");
/*fuzzSeed-28551573*/count=7; tryItOut("this.v1 = (t2 instanceof s1);function x(x, e, ...x)(\u3056 = y)p0 + '';");
/*fuzzSeed-28551573*/count=8; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void schedulegc(96); } void 0; } /*RXUB*/var r = new RegExp(\"(?:(\\\\2)|(?!\\\\d)|\\\\W(?!.{1}){1,}(?:[\\\\d\\\\b\\\\S]){1,}|(?:^)|[^]|([^])(?=^)\\\\B{0,2}\\\\\\u00d8+(.)+{3,5}?)\", \"gyim\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-28551573*/count=9; tryItOut("t0[window];");
/*fuzzSeed-28551573*/count=10; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((( + Math.min((Math.fround(Math.sinh(y)) >>> 0), ((Math.pow((y >>> 0), Math.fround(((0x0ffffffff >>> 0) !== (Math.sin((-(2**53-2) >>> 0)) | 0)))) >>> 0) >>> 0))) >>> 0) == (Math.pow(( + (( + Math.max(Math.sign((Math.fround(( ! Math.fround(y))) >>> 0)), (y << ((x >>> 0) <= Number.MAX_VALUE)))) % ( + Math.fround(((y % x) / ( + Math.max(-1/0, y))))))), Math.min(2**53+2, mathy1((y | 0), (Math.fround(Math.tan(Math.fround(( + (( + Math.acosh(( + y))) << ( + Math.fround(Math.pow(Math.fround(new RegExp(\"((?!.[\\\\B-\\\\u1c2D])(?!\\ue37e.)|(\\\\f){0})..*\\\\B+[\\\\D]|(?!\\\\b)*?(?=[^\\\\w\\u00fc\\u97af])\", \"gy\")), Math.fround(0x07fffffff))))))))) | 0)))) | 0)); }); testMathyFunction(mathy2, /*MARR*/[ /x/g , new Number(1), new Number(1), 1e-81, new Number(1),  /x/g , new Number(1), new Number(1), new Number(1), new Number(1), 1e-81, new Number(1), new Number(1),  /x/g , 1e-81,  /x/g , new Number(1), new Number(1), 1e-81, 1e-81, 1e-81, 1e-81,  /x/g , new Number(1),  /x/g , 1e-81, 1e-81, 1e-81, 1e-81,  /x/g , 1e-81,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Number(1),  /x/g ,  /x/g ,  /x/g , 1e-81, 1e-81, new Number(1), new Number(1), 1e-81, new Number(1), new Number(1),  /x/g , new Number(1), 1e-81, 1e-81,  /x/g , 1e-81, new Number(1), new Number(1),  /x/g , new Number(1),  /x/g , 1e-81, 1e-81, new Number(1),  /x/g , new Number(1),  /x/g ,  /x/g ,  /x/g , new Number(1),  /x/g , 1e-81, new Number(1), new Number(1)]); ");
/*fuzzSeed-28551573*/count=11; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, -0x07fffffff, Math.PI, 1, 0x100000000, 0x080000000, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -0x100000001, 1.7976931348623157e308, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, 2**53, 0.000000000000001, 0/0, -0x080000000, 1/0, -1/0, -0x080000001, -0x100000000, -(2**53+2), 42, 0, -(2**53-2), 2**53+2, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-28551573*/count=12; tryItOut("\"use strict\"; /*hhh*/function wnioji(x, this.w = (4277)\n){(x);}wnioji(/[^]/m);v1 = (o2.t2 instanceof e1);var x, x, d, qeddmq, ftjgxo, e, puziie, c, tivdcz;m1.set(h1,  /x/g );");
/*fuzzSeed-28551573*/count=13; tryItOut("speyop, cppbbx, orrnvx;f0 = (function() { a0 = arguments.callee.caller.arguments; return a2; });");
/*fuzzSeed-28551573*/count=14; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+(0.0/0.0));\n    (Uint16ArrayView[2]) = (((Uint16ArrayView[(((0xffffffff))-((i0) ? (i0) : ((-0x8000000) >= (0x7d482da9)))-(i0)) >> 1]))+(0xf9a5520c));\n    {\n      switch ((((/*FFI*/ff(((-35184372088831.0)), ((2.3611832414348226e+21)), ((4294967297.0)), ((-513.0)), ((-4611686018427388000.0)), ((9.44473296573929e+21)), ((17.0)), ((-268435457.0)), ((-67108865.0)))|0)+(/*FFI*/ff()|0)) ^ (-0xfffff*(0xf905eae9)))) {\n      }\n    }\n    d1 = (-2097153.0);\n    return +((d1));\n  }\n  return f; })(this, {ff:  /x/ }, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0, -(2**53), 2**53, 1, 1.7976931348623157e308, -0x100000001, -(2**53+2), 0x080000000, 0/0, -0x100000000, 0, -1/0, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, Math.PI, 42, 0x080000001, Number.MIN_VALUE, -0x080000000, -0x080000001]); ");
/*fuzzSeed-28551573*/count=15; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.max(Math.fround(Math.atan2(y, y)), Math.max(( + (Math.min(mathy2(Math.round(x), (y != (y | 0))), Math.pow(Math.cos((Math.fround(Math.atan2(y, y)) | 0)), y)) >>> 0)), mathy0(mathy1(-Number.MIN_VALUE, Math.fround(Math.round(x))), ( ! -(2**53-2))))) || ( - (( ! ( - y)) >>> 0))); }); testMathyFunction(mathy3, [(new Number(0)), 1, (new Number(-0)), null, ({valueOf:function(){return 0;}}), (new String('')), 0, 0.1, objectEmulatingUndefined(), [0], '\\0', [], ({toString:function(){return '0';}}), NaN, undefined, -0, true, '0', '', (new Boolean(false)), '/0/', (new Boolean(true)), false, /0/, ({valueOf:function(){return '0';}}), (function(){return 0;})]); ");
/*fuzzSeed-28551573*/count=16; tryItOut("testMathyFunction(mathy5, [-0x080000001, -0x080000000, 2**53, -0, -(2**53), 0x080000001, 0x100000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, 42, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 0, 0x080000000, 0x0ffffffff, Math.PI, 0.000000000000001, 0/0, 2**53+2, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000000, 1, -0x07fffffff, 0x100000000]); ");
/*fuzzSeed-28551573*/count=17; tryItOut("f2 = Proxy.createFunction(h0, f2, g0.f0);");
/*fuzzSeed-28551573*/count=18; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=19; tryItOut("\"use strict\"; a0.pop(f1);");
/*fuzzSeed-28551573*/count=20; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (!(0xfbef6477));\n    d1 = (-1.125);\n    return +((d1));\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-28551573*/count=21; tryItOut("\"use strict\"; switch(({\u3056: x = Proxy.createFunction(({/*TOODEEP*/})(this), mathy2, Date.prototype.getMilliseconds)})) { case 7: return -0; }");
/*fuzzSeed-28551573*/count=22; tryItOut("");
/*fuzzSeed-28551573*/count=23; tryItOut("for (var p in t2) { try { let b1 = new ArrayBuffer(12); } catch(e0) { } try { i0.send(v1); } catch(e1) { } this.g0.a1.splice(-2, 'fafafa'.replace(/a/g, Int8Array), t2, o2); }");
/*fuzzSeed-28551573*/count=24; tryItOut("Array.prototype.forEach.call(o1.g1.a2, (function(j) { if (j) { try { g1.g1.e0 + v0; } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(g2, p0); } else { try { x = m2; } catch(e0) { } s2.toSource = (function() { /*RXUB*/var r = r0; var s = s1; print(s.split(r));  return e0; }); } }), g0.o0, m2);function window(x) { o2.a2.forEach(JSON.stringify.bind(this.o1.v2)); } v1 = Object.prototype.isPrototypeOf.call(this.m0, v2);");
/*fuzzSeed-28551573*/count=25; tryItOut("mathy0 = (function(x, y) { return ( + (( + Math.acosh(( ~ Number.MIN_VALUE))) / ( + Math.log10(( + ( ~ ( + ( - (( - y) | 0))))))))); }); testMathyFunction(mathy0, [42, -0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -0, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, 2**53+2, -(2**53+2), -0x07fffffff, Math.PI, Number.MIN_VALUE, -1/0, 0x07fffffff, 0, 0x100000001, -(2**53-2), 0x080000000, -0x080000001, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, -0x080000000, 0/0, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000000, 1, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=26; tryItOut("m2.get(this.m0);");
/*fuzzSeed-28551573*/count=27; tryItOut("mathy0 = (function(x, y) { return ( - Math.clz32(((Math.pow((((((( ~ Math.fround(x)) | 0) | 0) || (y | 0)) | 0) >>> 0), (Math.min((-0x07fffffff | 0), (((y ? (((x >>> 0) / y) | 0) : (((Math.fround(Number.MIN_SAFE_INTEGER) % ( + -0x100000000)) >>> 0) | 0)) | 0) | 0)) >>> 0)) >>> 0) >= ( + Math.fround(Math.pow(Math.fround(((Math.expm1(( + x)) >>> 0) || (y >>> 0))), Math.fround(x))))))); }); testMathyFunction(mathy0, [true, NaN, '0', objectEmulatingUndefined(), [], '/0/', false, 0, null, 1, -0, '', (new Number(-0)), [0], (function(){return 0;}), (new Boolean(false)), undefined, '\\0', (new Boolean(true)), ({toString:function(){return '0';}}), 0.1, (new Number(0)), ({valueOf:function(){return 0;}}), (new String('')), ({valueOf:function(){return '0';}}), /0/]); ");
/*fuzzSeed-28551573*/count=28; tryItOut("a0 + '';");
/*fuzzSeed-28551573*/count=29; tryItOut("\"use asm\"; /*RXUB*/var r = r1; var s = \"L\"; print(uneval(s.match(r))); ");
/*fuzzSeed-28551573*/count=30; tryItOut("");
/*fuzzSeed-28551573*/count=31; tryItOut("e1.delete(g1.t0);");
/*fuzzSeed-28551573*/count=32; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Int32ArrayView[(((((-0x8000000) == (-0x8000000))*0xb5a62)>>>((-0x8000000)-(i1))) % (((0xffffffff))>>>((0x4cca7ccf)+(0xdb349bd)))) >> 2]) = ((0xac648d2d)-((0xfdff9c3d) ? (-0x8000000) : (-0x8000000)));\n    d0 = (Infinity);\n    (Uint8ArrayView[((w = (true.eval(\"/* no regression tests found */\"))).yoyo((uneval(new RegExp(\"\\\\S\", \"y\"))))) >> 0]) = ((((((((0xfa72e933))>>>((-0x8000000))) == (0x9759dc33))-(((4277)) >= (d0))) | ((i1)-(0xb4fee988)+(0x215b3564))) < ((((0xfdcc9c9b)) % (0x0)) ^ ((0x5ca276b6))))-(0xffffffff));\n    return +(((0x0) != (0x24d45340)));\n  }\n  return f; })(this, {ff: Set}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x080000000, 0x080000001, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -(2**53-2), -1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 1/0, 0x100000000, 0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, 0/0, -0x100000000, 0x0ffffffff, -0x080000001, -0, 0x100000001, 1, -(2**53), Math.PI, 1.7976931348623157e308, Number.MAX_VALUE, 42, 0.000000000000001]); ");
/*fuzzSeed-28551573*/count=33; tryItOut("v0 = evaluate(\"mathy5 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var pow = stdlib.Math.pow;\\n  var ff = foreign.ff;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = 1.0009765625;\\n    var d3 = 4.835703278458517e+24;\\n    var d4 = 137438953473.0;\\n    var i5 = 0;\\n    var i6 = 0;\\n    var i7 = 0;\\n    var d8 = 8191.0;\\n    var i9 = 0;\\n    var i10 = 0;\\n    (Float32ArrayView[0]) = ((+(1.0/0.0)));\\n    i1 = (((0x429117f3) <= (((i10)+((-0x8000000) > (0x6ad9490f)))>>>((0x8d5552ec) / (0xec67300)))) ? ((Infinity) < (+pow(((d3)), ((8796093022207.0))))) : (!(((9.44473296573929e+21) >= (d4)) ? (0x3b7eb9cd) : (i0))));\\n    return +((-33554433.0));\\n  }\\n  return f; })(this, {ff: function(q) { return q; }}, new SharedArrayBuffer(4096)); \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: let ({} = 'fafafa'.replace(/a/g, Number.isSafeInteger), window = ((void options('strict_mode')))) /*FARR*/[\"\\u6B80\",  /x/ ].filter(arguments.callee), noScriptRval: (x % 17 != 3), sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-28551573*/count=34; tryItOut("m0.set(o1, g1.o0);\no2 = Object.create(o2);\n");
/*fuzzSeed-28551573*/count=35; tryItOut("i0 + i0;");
/*fuzzSeed-28551573*/count=36; tryItOut("print(f1);");
/*fuzzSeed-28551573*/count=37; tryItOut("/*oLoop*/for (mmjcsk = 0, x =  \"\" ; mmjcsk < 76; ++mmjcsk) { /*ADP-1*/Object.defineProperty(a2, 3, ({get: function(y) { \"use strict\"; return  \"\"  }, enumerable: false})); } ");
/*fuzzSeed-28551573*/count=38; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-28551573*/count=39; tryItOut("");
/*fuzzSeed-28551573*/count=40; tryItOut("\"use strict\"; print( /x/  /=  \"\" );");
/*fuzzSeed-28551573*/count=41; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.min(Math.atan2((((0.000000000000001 | 0) && (y | 0)) | 0), Math.tan((((y | 0) << (Math.abs((Math.min((x >>> 0), (-0x080000001 | 0)) >>> 0)) | 0)) | 0))), Math.fround(( + Math.fround(( ! (Math.sign(Math.fround(( - Math.fround(-(2**53+2))))) >>> 0)))))) || ( ! (( + ( - ( + y))) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[x ? /((?=[\\v])[^\u5ebe\\d]\\B?)|(?![^]){4,}/gyi : (let (b) -27), x ? /((?=[\\v])[^\u5ebe\\d]\\B?)|(?![^]){4,}/gyi : (let (b) -27), objectEmulatingUndefined(), x ? /((?=[\\v])[^\u5ebe\\d]\\B?)|(?![^]){4,}/gyi : (let (b) -27), x ? /((?=[\\v])[^\u5ebe\\d]\\B?)|(?![^]){4,}/gyi : (let (b) -27), x, x ? /((?=[\\v])[^\u5ebe\\d]\\B?)|(?![^]){4,}/gyi : (let (b) -27), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-28551573*/count=42; tryItOut("a2.forEach((function(j) { if (j) { try { for (var p in o0.v2) { h2.enumerate = this.f1; } } catch(e0) { } try { /*ADP-3*/Object.defineProperty(this.a2, 10, { configurable: (x % 15 == 2), enumerable: false, writable: false, value:  /x/g  }); } catch(e1) { } m2.has(a0); } else { b1.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -6.189700196426902e+26;\n    {\n      i3 = (i1);\n    }\n    i1 = (i3);\n    return (((((-0x8000000)) ? (i3) : (i2))))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); } }), (this.__defineSetter__(\" /x/g \", encodeURIComponent)));");
/*fuzzSeed-28551573*/count=43; tryItOut("(d = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: Math.atan2, fix: undefined, has: function() { throw 3; }, hasOwn: ([[]]).bind, get: function() { return undefined }, set: Set.prototype.entries, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(z), function(q) { return q; }, \n '' )) == (let (y) y);");
/*fuzzSeed-28551573*/count=44; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.imul(((mathy2((( + (( + y) % ( + x))) | 0), ((( ~ mathy2(x, (x | 0))) | 0) | 0)) | 0) != Math.log(( + ( ! ( + Math.fround(mathy2(Math.fround(Math.sqrt(Number.MIN_VALUE)), Math.fround(Math.log2(x))))))))), ( + ((Math.fround(Math.hypot(Math.fround((( + (Math.log10((x | 0)) >>> 0)) / (y | 0))), Math.fround(((mathy2((y >>> 0), x) >>> 0) ? ((Math.fround(x) > Math.min(y, y)) >>> 0) : (( ! ( ! -Number.MIN_VALUE)) | 0))))) | Math.min(( ~ ( ~ (x | 0))), Math.min(x, ((( + ( - y)) || (Math.fround(( + Math.fround(y))) >>> 0)) >>> 0)))) | 0)))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, -0x080000001, 0x080000001, -0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, 2**53+2, -(2**53), -0x100000000, -(2**53+2), 0x07fffffff, Math.PI, 42, 0/0, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -0, Number.MAX_VALUE, 0x100000000, -1/0, -Number.MAX_VALUE, 1/0, -(2**53-2), 0, 0x100000001]); ");
/*fuzzSeed-28551573*/count=45; tryItOut("v0 = Object.prototype.isPrototypeOf.call(t1, b2);");
/*fuzzSeed-28551573*/count=46; tryItOut("f2.toSource = Date.prototype.setUTCMinutes.bind(o0);");
/*fuzzSeed-28551573*/count=47; tryItOut("\"use strict\"; a0.forEach(/*wrap3*/(function(){ var vplsdi = (void shapeOf(-3)); (() => /*FARR*/[, ...(function() { \"use strict\"; yield (c = Proxy.create(({/*TOODEEP*/})( /x/ ), [1])); } })(), , x, vplsdi ^= a, undefined, , , .../*PTHR*/(function() { for (var i of new Array(-13)) { yield i; } })(), .../*FARR*/[], ].sort(Date.prototype.setUTCFullYear, new (eval)((4277))))(); }), b1);");
/*fuzzSeed-28551573*/count=48; tryItOut("/*MXX2*/g1.Set.prototype.delete = g2;");
/*fuzzSeed-28551573*/count=49; tryItOut("g1.m1.set(v2, h0);");
/*fuzzSeed-28551573*/count=50; tryItOut("/*vLoop*/for (let pjokee = 0, e; pjokee < 26 && (window); ++pjokee) { let a = pjokee; print(x); } ");
/*fuzzSeed-28551573*/count=51; tryItOut("mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + (( + Math.imul(((y > ((x < Math.abs(y)) | 0)) >>> 0), ( + (Math.acosh(Math.cosh(y)) | 0)))) + ( + Math.pow((Math.fround(Math.min(x, y)) | 0), ( + (Math.hypot(Math.fround(Math.max(Math.fround(Math.atanh(x)), y)), x) | 0)))))); }); testMathyFunction(mathy3, [1/0, 0/0, 0x100000001, 1.7976931348623157e308, 0x080000001, 0x07fffffff, 42, -0, 0, 2**53-2, Math.PI, -1/0, 1, -(2**53-2), -0x0ffffffff, -0x080000000, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -0x100000001, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, -0x080000001, 0x0ffffffff, 2**53, 2**53+2]); ");
/*fuzzSeed-28551573*/count=52; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((( + (( + (Math.imul((( - (x !== x)) >>> 0), (( ~ ( ~ x)) >>> 0)) >>> 0)) ^ ( + (Math.trunc(((x ? ((x | 0) % Math.log1p(y)) : x) | 0)) | 0)))) >>> 0) > ((Math.pow(Math.min(-0x100000001, x), Math.tanh(Math.hypot(x, ( ~ Math.round(-(2**53)))))) | 0) ^ (Math.log((( - ((( + y) || ( + -1/0)) | 0)) >>> 0)) | 0))) >>> 0); }); testMathyFunction(mathy0, [0, -0x100000000, -1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, 0x100000000, -0x100000001, 0x080000000, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), -Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, 2**53, 0x07fffffff, 1.7976931348623157e308, -0x080000001, -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, -0x080000000, 1/0, 0/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 42, -0, 2**53-2, Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=53; tryItOut("\"use strict\"; var qpvisc = new SharedArrayBuffer(8); var qpvisc_0 = new Int32Array(qpvisc); qpvisc_0[0] = 21; var qpvisc_1 = new Int32Array(qpvisc); var qpvisc_2 = new Int8Array(qpvisc); print(qpvisc_2[0]); qpvisc_2[0] = -5; var qpvisc_3 = new Float32Array(qpvisc); print(qpvisc_3[0]); qpvisc_3[0] = -0.874; var qpvisc_4 = new Uint8ClampedArray(qpvisc); print(qpvisc_4[0]); qpvisc_4[0] = 20; var qpvisc_5 = new Uint32Array(qpvisc); print(qpvisc_5[0]); var qpvisc_6 = new Int32Array(qpvisc); print(qpvisc_6[0]); qpvisc_6[0] = 7; var qpvisc_7 = new Float32Array(qpvisc); qpvisc_7[0] = -0; var qpvisc_8 = new Uint16Array(qpvisc); print(qpvisc_8[0]); qpvisc_8[0] = x <<= x **= \u3056; var qpvisc_9 = new Float64Array(qpvisc); /*ADP-1*/Object.defineProperty(a0, 10, ({value:  '' , configurable: this}));a0 + '';-18;v1 = g2.eval(\"/* no regression tests found */\");t1.set(g2.g0.t0, ({valueOf: function() { (void schedulegc(g2));return 3; }})); /x/ ;this.v2 = Object.prototype.isPrototypeOf.call(this.v2, b1);-16;const d =  '' ;return this;print(-26);v2 = f1[\"__count__\"];");
/*fuzzSeed-28551573*/count=54; tryItOut("g0.offThreadCompileScript(\"let a0 = arguments;\");");
/*fuzzSeed-28551573*/count=55; tryItOut("\"use strict\"; e1 + i2;");
/*fuzzSeed-28551573*/count=56; tryItOut("a2.shift();");
/*fuzzSeed-28551573*/count=57; tryItOut("mathy2 = (function(x, y) { return Math.cosh(Math.pow(( + Math.round(Math.acos(x))), mathy1(Math.log2(Math.asinh(( + Math.log10(( + y))))), ((Math.fround(-Number.MIN_VALUE) !== ( + ( ! (Math.fround(( ! Math.fround(-0x080000001))) == y)))) | 0)))); }); testMathyFunction(mathy2, [-0, Number.MAX_SAFE_INTEGER, 2**53-2, 1, 2**53, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, -0x07fffffff, 42, -(2**53+2), Math.PI, 0.000000000000001, -0x100000000, 0x07fffffff, -0x080000000, 0, -(2**53-2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, -1/0, -0x080000001, Number.MIN_VALUE, -0x100000001, -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=58; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(( + (Math.fround(( + ( + ((y - Math.log1p(x)) != ( + y))))) != (( ! y) | 0))), Math.max((Math.fround(((mathy2((x | 0), (x | 0)) | 0) != x)) >> Math.fround(Math.fround((Math.fround(y) - Math.round(x))))), (mathy1(( - x), ( + Math.hypot((x >>> 0), x))) + Math.trunc(Math.sin(x))))); }); testMathyFunction(mathy4, [-0x080000000, 0x07fffffff, 0x080000000, -0x080000001, 2**53, Math.PI, -0x0ffffffff, -0, -0x100000000, 1.7976931348623157e308, 0x100000001, 42, 0x100000000, -Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, -0x100000001, Number.MIN_SAFE_INTEGER, 1, -1/0, -(2**53-2), 2**53-2, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, -(2**53), 0, 1/0, -0x07fffffff, 0x080000001]); ");
/*fuzzSeed-28551573*/count=59; tryItOut("\"use strict\"; e1 = new Set;");
/*fuzzSeed-28551573*/count=60; tryItOut("v2 = new Number(-0);");
/*fuzzSeed-28551573*/count=61; tryItOut("Array.prototype.sort.apply(a2, [i2, e2]);");
/*fuzzSeed-28551573*/count=62; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + ( ! Math.cos(((Math.max((x >>> 0), (-(2**53+2) >>> 0)) >>> 0) ? Math.imul((x < ((((x | 0) < Math.fround(x)) | 0) >>> 0)), y) : x)))); }); ");
/*fuzzSeed-28551573*/count=63; tryItOut("print(true);function c(\u3056)\"use asm\";   var abs = stdlib.Math.abs;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((((i1)) & ((0xfeb95575))) == (((i1))|0));\n    switch ((~~(+(abs((((0xe7294d3b)) << ((0xc2d0a0c9))))|0)))) {\n    }\n    i0 = (i0);\n    i0 = ((abs(((-0xc627a*(i1))|0))|0));\n    return +((1.00390625));\n  }\n  return f;");
/*fuzzSeed-28551573*/count=64; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (mathy2(Math.fround(( ! Math.max((Math.fround((0.000000000000001 / (Math.fround(Math.pow(Math.fround(x), 0)) | 0))) >>> x), y))), Math.fround((Math.min((y / x), (Math.hypot(0x100000000, (Math.atan2((x >>> 0), (x >>> 0)) >>> 0)) / ( + Math.sinh(( + y))))) | 0))) >>> 0); }); ");
/*fuzzSeed-28551573*/count=65; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ (Math.fround(mathy2(Math.fround(y), y)) | ((-1/0 ? Math.log(((x + y) >>> 0)) : x) | 0))); }); testMathyFunction(mathy3, [1, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, -0, -0x0ffffffff, 0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), Math.PI, 0, Number.MAX_SAFE_INTEGER, -0x100000000, 0/0, 2**53-2, 1/0, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -0x080000000, -(2**53+2), -Number.MIN_VALUE, 42, -(2**53-2), 2**53, -0x07fffffff]); ");
/*fuzzSeed-28551573*/count=66; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=67; tryItOut("this.f1 + s0;");
/*fuzzSeed-28551573*/count=68; tryItOut("mathy5 = (function(x, y) { return (( + ( + ( ~ ( + mathy1(-0x0ffffffff, Math.min(x, (Math.imul((-(2**53+2) >>> 0), (x >>> 0)) >>> 0))))))) >>> ( + ((( ! (-0x0ffffffff | 0)) | 0) , ((Math.max(mathy3(y, Math.fround(x)), Math.fround(( ~ Math.fround((Math.hypot((y >>> 0), (x >>> 0)) >>> 0))))) >>> 0) ? y : (Math.log(( + ( - (mathy2((y | 0), y) | 0)))) | 0))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1, -0, -(2**53+2), 0x080000001, -0x080000000, Math.PI, -0x100000000, -(2**53), -Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 0/0, -0x07fffffff, 42, 2**53-2, 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 0x07fffffff, -1/0]); ");
/*fuzzSeed-28551573*/count=69; tryItOut("mathy2 = (function(x, y) { return (( ~ ( + Math.expm1(( + (( + -0x100000001) - (y >= ( + Math.fround(Math.min(Math.fround(Math.fround(Math.tan((x | 0)))), Math.fround((x !== Math.PI))))))))))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[arguments.callee, (-1/0), arguments.callee, arguments.callee,  /x/g , (-1/0), arguments.callee, arguments.callee, (-1/0), (-1/0), arguments.callee,  /x/g ,  /x/g , (-1/0),  /x/g , arguments.callee,  /x/g , (-1/0), arguments.callee, (-1/0), (-1/0), arguments.callee, (-1/0), arguments.callee, (-1/0)]); ");
/*fuzzSeed-28551573*/count=70; tryItOut("\"use strict\"; print(t2);const c = (4277);");
/*fuzzSeed-28551573*/count=71; tryItOut("e2.add(new (eval = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: undefined, has: Date.prototype.getUTCDay, hasOwn: function() { throw 3; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(undefined in Math.sin(-24)), x))(x));");
/*fuzzSeed-28551573*/count=72; tryItOut("\"use strict\"; const flqawg, x, {x: {window: {}, x: {x: {x: {a: w, w}, e: x, x}, x, x: eval}}, x: (x), x, x: {/\\W|\\3{2}/ym: {\u3056: x, x, c: \u3056, c: {}, e: e}, x: {x: [], a: \u000c{}}, c: [, ]}} = encodeURIComponent.prototype, eval = window.yoyo(x), icdzbj, xlrbug, kqeqdu;while(((((function(x, y) { return x; })).call(\"\\u81A4\", ))) && 0)Array.prototype.sort.apply(a1, [p0]);");
/*fuzzSeed-28551573*/count=73; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1{1,5}\", \"gym\"); var s = \"l\\u5ebea\\n\\ue3b3a \\n\\u5ebea\\n\\ue3b3a \\nl\\u5ebea\\n\\ue3b3a \\n\\u5ebea\\n\\ue3b3a \\nl\\u5ebea\\n\\ue3b3a \\n\\u5ebea\\n\\ue3b3a \\n\\u6930l\\u5ebea\\n\\ue3b3a \\n\\u5ebea\\n\\ue3b3a \\nl\\u5ebea\\n\\ue3b3a \\n\\u5ebea\\n\\ue3b3a \\nl\\u5ebea\\n\\ue3b3a \\n\\u5ebea\\n\\ue3b3a \\n\"; print(s.search(r)); ");
/*fuzzSeed-28551573*/count=74; tryItOut("cnyaju();/*hhh*/function cnyaju(){v1 = evalcx(\"/* no regression tests found */\", o0.g2);}");
/*fuzzSeed-28551573*/count=75; tryItOut("m2.get(h2);");
/*fuzzSeed-28551573*/count=76; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.abs((((Math.max(0x100000000, ((( ! (Math.atan2(x, y) | 0)) | 0) === Math.max(( + Math.PI), x))) >>> 0) <= mathy2(mathy2(Math.fround((((( ! (y | 0)) | 0) > ( ! Math.fround(y))) >>> 0)), Math.fround(Math.log10(Number.MAX_SAFE_INTEGER))), Math.min(y, ( + -Number.MAX_VALUE)))) >>> 0))); }); testMathyFunction(mathy3, [2**53+2, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0/0, -0x100000001, 2**53-2, -(2**53-2), -0, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -(2**53), -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, 42, 0x100000001, 2**53, Number.MAX_VALUE, 0x080000001, Math.PI, -0x080000000, 1, 0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-28551573*/count=77; tryItOut("print(x);");
/*fuzzSeed-28551573*/count=78; tryItOut("\"use strict\"; /*infloop*/ for (var b of true) throw null;");
/*fuzzSeed-28551573*/count=79; tryItOut("\"use strict\"; g1.s1 += s2;");
/*fuzzSeed-28551573*/count=80; tryItOut("o0.valueOf = (function() { try { for (var p in g0) { this.v1 = this.a2.every((function() { try { print(uneval(o1)); } catch(e0) { } a2 = Array.prototype.filter.apply(a1, [(function() { try { m1 = new Map(g1); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(p2, e1); return h1; })]); return i1; })); } } catch(e0) { } m1.has(Math.imul(-27, ((x =  /x/g )))); throw b1; });");
/*fuzzSeed-28551573*/count=81; tryItOut("\"use strict\"; var dseans = new SharedArrayBuffer(16); var dseans_0 = new Float64Array(dseans); print(dseans_0[0]); var dseans_1 = new Uint32Array(dseans); print(dseans_1[0]); dseans_1[0] = -8; var dseans_2 = new Int8Array(dseans); dseans_2[0] = -23; var dseans_3 = new Float64Array(dseans); dseans_3[0] = -12; var dseans_4 = new Int32Array(dseans); dseans_4[0] = 658616323.5; var dseans_5 = new Uint32Array(dseans); dseans_5[0] = -2; var dseans_6 = new Float32Array(dseans); var dseans_7 = new Int8Array(dseans); dseans_7[0] = 7; /*MXX2*/g0.Object.prototype = e0;");
/*fuzzSeed-28551573*/count=82; tryItOut("Object.defineProperty(this, \"a0\", { configurable: true, enumerable: (x % 3 != 1),  get: function() {  return a2.slice(NaN, NaN); } });");
/*fuzzSeed-28551573*/count=83; tryItOut("v2 = g2.runOffThreadScript();");
/*fuzzSeed-28551573*/count=84; tryItOut("mathy2 = (function(x, y) { return ( + ( ~ ( + (Math.atanh((Math.min(Math.atan2(Math.fround(Math.acosh((y >>> 0))), Math.fround(x)), (( ~ y) | 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -0x080000000, -0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000001, 0x0ffffffff, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, 42, -(2**53-2), -1/0, 0x080000001, 2**53, 0x100000000, 1, 0/0, 0x080000000, Number.MAX_VALUE, 0, 2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, 1/0, -0]); ");
/*fuzzSeed-28551573*/count=85; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = o1.s0; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=86; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(((?:\\\\2)\\\\s)))*?\", \"g\"); var s = \"_\"; print(uneval(s.match(r))); ");
/*fuzzSeed-28551573*/count=87; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?!(?=[^\\u594f\\\\D]*|\\\\S\\\\S{128,}).|.*(?=.\\u320b){3,}|\\\\d)|\\\\w)\", \"im\"); var s = \"\"; print(uneval(s.match(r))); function z(w)\"use asm\";   var imul = stdlib.Math.imul;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\nprint(x);    {\n      (Float32ArrayView[1]) = ((-1.2089258196146292e+24));\n    }\n    {\n      d1 = (+(imul(((~~((imul((1), (!(0xffd9ba3e)))|0))) == (((Int32ArrayView[1])) ^ (-0x33200*(0xacb90888)))), (0xb921318a))|0));\n    }\n    {\n      return +((17179869185.0));\n    }\n    {\n      d1 = (+(0.0/0.0));\n    }\n    d1 = (-1.125);\n    return +((4277));\n    i0 = (0xc2dfd71b);\n    i0 = (0xf88d2846);\n    {\n      d1 = (+(0.0/0.0));\n    }\n    d1 = (((d1)) - ((-268435456.0)));\n    d1 = (-64.0);\n    d1 = ((i0) ? (4194304.0) : (+((Float64ArrayView[((!(0xbf649489))) >> 3]))));\n    return +((-262145.0));\n  }\n  return f;/*vLoop*/for (var ttnwim = 0; ttnwim < 46; ++ttnwim) { let d = ttnwim; print(uneval(e2)); } ");
/*fuzzSeed-28551573*/count=88; tryItOut("g2.a1 = o2.o2.o0.a1.concat(a1, t1);");
/*fuzzSeed-28551573*/count=89; tryItOut("\"use strict\"; o1.v2.__proto__ = a1;");
/*fuzzSeed-28551573*/count=90; tryItOut("/*RXUB*/var r = /(?!((?!\\1|[^]\\d{3}))|(?:((($))){2,4})|[^]{0,})/gim; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-28551573*/count=91; tryItOut("\"use strict\"; e1 = o0.a1[(4277)];");
/*fuzzSeed-28551573*/count=92; tryItOut("\"use strict\"; print(g0.h0);");
/*fuzzSeed-28551573*/count=93; tryItOut("mathy5 = (function(x, y) { return ( - Math.fround((( + (( + (( + y) === x)) ^ ( ~ ( ~ (Math.imul((x | 0), 0x07fffffff) ** x))))) || mathy4((-0x100000000 | 0), ((Math.acos(x) == (Math.imul(x, Math.fround((Math.fround(-0x080000000) == (( ! (1/0 | 0)) | 0)))) | 0)) | 0))))); }); testMathyFunction(mathy5, /*MARR*/[false, false, function(){}, {x:3}, false, false, function(){}, function(){}, function(){}, {x:3}]); ");
/*fuzzSeed-28551573*/count=94; tryItOut("\"use strict\"; h1 = ({getOwnPropertyDescriptor: function(name) { throw b1; var desc = Object.getOwnPropertyDescriptor(i0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { a0.unshift(p0, i0, f2, v1);; var desc = Object.getPropertyDescriptor(i0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { return g1.g0; Object.defineProperty(i0, name, desc); }, getOwnPropertyNames: function() { /*ODP-3*/Object.defineProperty(b2, 4, { configurable: (x % 26 != 11), enumerable: true, writable: (x % 2 == 0), value: b1 });; return Object.getOwnPropertyNames(i0); }, delete: function(name) { v0 = evalcx(\"/* no regression tests found */\", o0.g1.g2);; return delete i0[name]; }, fix: function() { o2.h2 + f0;; if (Object.isFrozen(i0)) { return Object.getOwnProperties(i0); } }, has: function(name) { return v1; return name in i0; }, hasOwn: function(name) { /*MXX2*/g2.JSON.stringify = v1;; return Object.prototype.hasOwnProperty.call(i0, name); }, get: function(receiver, name) { a1.shift(/(?!((?!\\s^){4,6}))\\1[^-\u00ed\\x49](?:^)+\\3{0,1}{4}/yim);\nx;\n; return i0[name]; }, set: function(receiver, name, val) { s2 += 'x';; i0[name] = val; return true; }, iterate: function() { this.v2 = evaluate(\"function f0(t0)  { yield t0 } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: ({} = intern(\"\\u9B87\")).watch(\"__parent__\", (x.__defineSetter__(\"setter\", (1 for (x in []))))), catchTermination: (x % 54 != 42) }));; return (function() { for (var name in i0) { yield name; } })(); }, enumerate: function() { Array.prototype.forEach.call(a0, (function() { try { /*MXX1*/o0 = g2.Array.prototype.indexOf; } catch(e0) { } i2 = new Iterator(v1); return g2; }), p2);; var result = []; for (var name in i0) { result.push(name); }; return result; }, keys: function() { o2.v0 = evalcx(\"a0.toString = (function() { for (var j=0;j<96;++j) { o2.f0(j%2==1); } });\", g2);; return Object.keys(i0); } });");
/*fuzzSeed-28551573*/count=95; tryItOut("\"use strict\"; m0 + b2;");
/*fuzzSeed-28551573*/count=96; tryItOut("b = linkedList(b, 2912);");
/*fuzzSeed-28551573*/count=97; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 2**53, 0, Number.MIN_SAFE_INTEGER, 42, -1/0, -(2**53), 0x080000000, 0/0, -Number.MIN_VALUE, -0x100000000, 1, 0.000000000000001, Number.MIN_VALUE, Math.PI, -0, Number.MAX_VALUE, -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, 2**53+2, -Number.MAX_VALUE, -0x100000001, 0x07fffffff, 0x0ffffffff, 0x100000000, 0x100000001, -0x080000000]); ");
/*fuzzSeed-28551573*/count=98; tryItOut("g0.offThreadCompileScript(\"(void options('strict_mode'))\");");
/*fuzzSeed-28551573*/count=99; tryItOut("mathy2 = (function(x, y) { return (Math.expm1((Math.min((( ~ ( ! (x | 0))) | 0), ( + x)) | 0)) + ( + ((( + x) / (Math.hypot((x >>> 0), y) | 0)) | 0))); }); ");
/*fuzzSeed-28551573*/count=100; tryItOut("{ void 0; void gc(); }");
/*fuzzSeed-28551573*/count=101; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + mathy1(( + Math.fround((( ! Math.max((mathy2(((x % y) / y), y) >>> 0), (mathy0(-Number.MIN_SAFE_INTEGER, (( + x) >> (((-1/0 | 0) > (y | 0)) | 0))) >>> 0))) ? Math.fround(Math.pow(Math.atan2(y, x), Math.tanh(( ! ( + y))))) : (Math.hypot((x >>> 0), (Math.fround((Math.fround(((( + y) && (( + ( - y)) | 0)) | 0)) == Math.fround(y))) | 0)) | 0)))), Math.max(( - y), Math.exp(Math.atanh(( + mathy2(y, ( + ( ! 0x100000000))))))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, 2**53+2, 1, 2**53, 0x080000001, 0x100000001, 1/0, 2**53-2, -(2**53-2), -(2**53), 0.000000000000001, -0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, -0x100000000, Math.PI, Number.MIN_VALUE, -0x100000001, -(2**53+2), 0x080000000, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-28551573*/count=102; tryItOut("\"use strict\"; t1 = new Uint8Array(b2);");
/*fuzzSeed-28551573*/count=103; tryItOut("\"use strict\"; \"use asm\"; a1 = Array.prototype.filter.apply(o1.a2, [f0]);");
/*fuzzSeed-28551573*/count=104; tryItOut("/*RXUB*/var r = /(?=(?!.+)([^\\x9d-\u04a0\\W]))/m; var s = 0; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-28551573*/count=105; tryItOut("a1.unshift(o1.m0);");
/*fuzzSeed-28551573*/count=106; tryItOut("/*RXUB*/var r = /(\\B){1,4}/; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-28551573*/count=107; tryItOut("\"use strict\"; i1 = new Iterator(b1, true);");
/*fuzzSeed-28551573*/count=108; tryItOut("\"use strict\"; const hywxdy, NaN, w, b;v1 = evaluate(\"p2 + v0;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-28551573*/count=109; tryItOut("print(e0);");
/*fuzzSeed-28551573*/count=110; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-28551573*/count=111; tryItOut("Array.prototype.pop.apply(this.a0, [/*RXUE*/new RegExp(\"(?:.\\\\v)\", \"gym\").exec(\"\")]);");
/*fuzzSeed-28551573*/count=112; tryItOut("\"use strict\";  \"\" ;");
/*fuzzSeed-28551573*/count=113; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((Infinity));\n    i1 = (-0x8000000);\n    {\n      d0 = (d0);\n    }\n    (Int16ArrayView[1]) = (((((-0xf2ae*((-1099511627777.0) <= (2305843009213694000.0)))>>>(-0xfcf54*(i1)))) ? (i1) : (({toString: (Number.MIN_SAFE_INTEGER) })))-(i1)-(((-17592186044417.0) + (d0)) != (-((d0)))));\n    {\n      d0 = (18446744073709552000.0);\n    }\n    /*FFI*/ff((((-0xfffff*(i1)) & ((0xffffffff)))), ((((i1)-((((0xfdf81de1))>>>((-0x8000000))))) >> ((0xffffffff)))), ((0x72008fdc)), ((((~((0x5fc46032)-(0xffffffff)))) ^ ((i1)+(i1)))), ((((0x0) / (0xffffffff)) >> ((-0x8000000)+(0x47cb7abd)+(0x3b8514e0)))), ((+(0.0/0.0))), ((-0x753e75d)), ((65537.0)), ((-3.0)), ((-1.9342813113834067e+25)), ((-16777217.0)));\n    (Uint8ArrayView[2]) = ((i1));\n    d0 = (d0);\n    return +((-17592186044415.0));\n  }\n  return f; })(this, {ff: (let (uygcaq, x, dxawfr, njfbql) window = Proxy.create(({/*TOODEEP*/})(null), \"\\u2C0C\"))}, new ArrayBuffer(4096)); ");
/*fuzzSeed-28551573*/count=114; tryItOut("h2.defineProperty = (function(stdlib, foreign, heap){ \"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+(0.0/0.0));\n    (Uint16ArrayView[1]) = ((-0x8000000)-(1)+((((~((0xffffffff)-(0xfcedb7e8))) / (~~(d0))) << (((((0xfdb0eba3)-(0x79e4a2db)) ^ ((0xa0b60504)))))) > (~~(d0))));\n    return (((0xe8cc75db)+((((((0x7929665b)-(0x238d63ec)) ^ ((0xfb506822)+(0xffffffff))) / (((0xfb0caf6e)-(0x1b531b70)) ^ ((-0x8000000)+(0xa00b2a11))))>>>(((0x45a85cbe) <= (((0x681fcb5a)) & ((0x30d1b4ad))))-(0x8bd6950e)-(0x4117538c))))-((0xa865272) < ((x)>>>((0x4c9c70c1))))))|0;\n  }\n  return f; });");
/*fuzzSeed-28551573*/count=115; tryItOut("\"use strict\"; h1.getOwnPropertyNames = f0;");
/*fuzzSeed-28551573*/count=116; tryItOut("for (var v of o1.s2) { try { m1.toSource = (function() { try { o2.v1 = t0.length; } catch(e0) { } /*RXUB*/var r = r0; var s = \"____\"; print(uneval(r.exec(s)));  return o0; }); } catch(e0) { } m2 = new Map; }");
/*fuzzSeed-28551573*/count=117; tryItOut("/*vLoop*/for (let uujavl = 0; ( /x/g ) && uujavl < 10; ++uujavl) { var z = uujavl; ; } ");
/*fuzzSeed-28551573*/count=118; tryItOut("\"use strict\"; b0 = new SharedArrayBuffer(80);\n(new RegExp(\"(?:(?=$+)|\\\\B|(?:\\\\s|^|\\\\S{3}){2,6})+?\", \"yim\"));\n");
/*fuzzSeed-28551573*/count=119; tryItOut("\"use strict\"; t2 = new Int8Array(a0);");
/*fuzzSeed-28551573*/count=120; tryItOut("m1 = new Map(g2)\n");
/*fuzzSeed-28551573*/count=121; tryItOut("print(uneval(p0));/*tLoop*/for (let z of /*MARR*/[null, new Number(1.5), ({x:3}), ({x:3}), null, null, new Number(1.5), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), null, ({x:3}), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), ({x:3}), new Number(1.5), new Number(1.5), null, new Number(1.5), new Number(1.5), ({x:3}), new Number(1.5), new Number(1.5), ({x:3}), new Number(1.5), null, null, ({x:3}), ({x:3}), new Number(1.5), null, null, null, ({x:3}), new Number(1.5), new Number(1.5), null, ({x:3}), ({x:3}), ({x:3}), ({x:3}), new Number(1.5), null, ({x:3}), new Number(1.5), ({x:3}), null, new Number(1.5), new Number(1.5), ({x:3}), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), ({x:3}), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), ({x:3}), null, ({x:3}), ({x:3}), null]) { yield window; }");
/*fuzzSeed-28551573*/count=122; tryItOut("i0 = new Iterator(o1, true);");
/*fuzzSeed-28551573*/count=123; tryItOut("(NaN || z);\nwith({b: (length << undefined)}){for (var p in f2) { v1 = undefined; }print(new Object.defineProperty(d, \"-9\", ({configurable: false})).__defineGetter__(\"d\", encodeURIComponent)); }\n");
/*fuzzSeed-28551573*/count=124; tryItOut(";");
/*fuzzSeed-28551573*/count=125; tryItOut("mathy5 = (function(x, y) { return (( + Math.atan2(( + ((-0x080000000 ? (Math.fround(y) === Math.fround(( ~ (y >> x)))) : x) <= (y ? x : -Number.MIN_VALUE))), ( + (Math.fround((mathy3(((x ? ((Math.hypot((x | 0), (x | 0)) | 0) | 0) : (y | 0)) | 0), y) && Math.fround(Math.pow(((x >>> 0) * -0x080000000), Math.fround(y))))) == ( - (y << x)))))) && (Math.asin(x) | ((Math.acos(y) >>> 0) / (( - Math.clz32((x > Math.fround(x)))) >>> 0)))); }); ");
/*fuzzSeed-28551573*/count=126; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.max(Math.sin(( + ( ~ 42))), ( ! (Math.hypot(( + Math.hypot(y, ((-0x07fffffff >>> 0) ? ( + 0x100000001) : ( + y)))), (x == (this.__defineSetter__(\"y\", /*wrap2*/(function(){ var liwwnj = w; var iinoeo = (new Function(\"b0 = new SharedArrayBuffer(112);\")); return iinoeo;})())))) | 0))); }); ");
/*fuzzSeed-28551573*/count=127; tryItOut("mathy2 = (function(x, y) { return (Math.atan2((Math.sign((( - 0x080000001) | 0)) | 0), ( + ( + Math.max(( + 2**53-2), ( ~ Math.atan2((Math.fround(Math.tanh(Math.fround(y))) | 0), ( + y))))))) >> ( ~ (.../*FARR*/[ get 4() { \"use strict\"; print(y); }  = 28, ...(eval(\"/* no regression tests found */\", (4277)) for (y in  \"\" ) for ((NaN) in this) for each (x in []))] >> (((Math.fround(Math.pow((y | 0), (x | 0))) == (Number.MIN_SAFE_INTEGER >>> 0)) | 0) * y)))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0/0, 2**53, -0x100000000, 42, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 2**53-2, -0x080000001, 2**53+2, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -(2**53+2), -1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 1, -0x0ffffffff, -(2**53), 0x100000000, 1/0, -0, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, 0x07fffffff, -0x100000001, 0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=128; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (/*FFI*/ff((((((~((i2)+((~~(-1.125))))))+(i2)) ^ ((((((0xfae011be) ? (0xfe391adf) : (0xf82a88a5))-(i2))>>>((Uint16ArrayView[4096]))))+(i1)))), ((((!((0xd4c8c83e) ? (0xf843e91c) : (0xff3f4ef2)))-(i1)-(0xafe8884f)) >> (((-549755813889.0) == ((+(-1.0/0.0)) + (-576460752303423500.0)))))))|0);\n    i0 = ((0xc2a33123));\n    {\n      return +((-35184372088833.0));\n    }\n    i2 = ((0xaa969a91));\n    {\n;    }\n    i1 = ((((((+(0.0/0.0)) + (-1.125)) > (-1125899906842623.0)))|0) > ((((0xc8e5439a) != (((0xa2336fc7)+(0xffffffff))>>>((0x6b4e6ef1)+(0x98d8663b))))+(i2)) >> (((((i2)-(i0))|0) != (abs(((Uint16ArrayView[4096])))|0))-(i0))));\n    return +((Float32ArrayView[((i1)+(i1)-(i1)) >> 2]));\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, Number.MIN_VALUE, 2**53, 2**53+2, 2**53-2, 0x07fffffff, 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, -0, -1/0, 1.7976931348623157e308, 0x080000001, 1, -Number.MAX_VALUE, -(2**53), -0x100000001, -Number.MIN_VALUE, 0, -0x080000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, 1/0, 42, 0x100000001]); ");
/*fuzzSeed-28551573*/count=129; tryItOut("testMathyFunction(mathy2, /*MARR*/[ \"\" , (void 0), new String('q'), new String('q'), (void 0),  \"\" , (void 0), (void 0),  \"\" , new String('q'),  \"\" , new String('q'), (void 0), (void 0), (void 0), new String('q'),  \"\" , new String('q'),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , (void 0),  \"\" , new String('q'),  \"\" , new String('q'), new String('q'), new String('q'), (void 0), new String('q'), new String('q'), (void 0),  \"\" , new String('q'), new String('q'), (void 0), new String('q'), new String('q'),  \"\" , (void 0), (void 0), new String('q'),  \"\" , new String('q'),  \"\" , new String('q'), (void 0), (void 0), new String('q'),  \"\" , new String('q'),  \"\" , (void 0), new String('q'), new String('q'),  \"\" , new String('q'),  \"\" ,  \"\" ,  \"\" , new String('q'), new String('q'),  \"\" , (void 0),  \"\" , (void 0)]); ");
/*fuzzSeed-28551573*/count=130; tryItOut("\"use strict\"; v2 = (o0.h1 instanceof this.m1);");
/*fuzzSeed-28551573*/count=131; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! ( ! mathy1(Math.fround(( - Math.fround(y))), (Math.sin(( + Math.PI)) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[(void 0), (void 0),  /x/g , (void 0),  /x/g , (void 0),  /x/g , (void 0), (void 0),  /x/g , (void 0),  /x/g , (void 0), (void 0), (void 0),  /x/g , (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0),  /x/g ,  /x/g , (void 0), (void 0),  /x/g ,  /x/g ,  /x/g , (void 0), (void 0)]); ");
/*fuzzSeed-28551573*/count=132; tryItOut("Array.prototype.splice.call(a0, NaN, 7);");
/*fuzzSeed-28551573*/count=133; tryItOut("selectforgc(o0);");
/*fuzzSeed-28551573*/count=134; tryItOut("testMathyFunction(mathy1, [0x100000000, -0x100000000, 0.000000000000001, Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, 0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 0x080000000, -0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, -0, 0/0, -Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), -(2**53-2), 0x07fffffff, 0x100000001, 0x080000001, -1/0, 2**53-2, 1/0, 1, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=135; tryItOut("(4277);d = new this.__defineGetter__(\"z\", decodeURI) |= x = Proxy.createFunction(({/*TOODEEP*/})( \"\" ), \"\\uC233\", \"\\uFC14\") + -18 , [,,];");
/*fuzzSeed-28551573*/count=136; tryItOut("/*oLoop*/for (let tfwlix = 0; tfwlix < 10; ++tfwlix) {  '' ; } ");
/*fuzzSeed-28551573*/count=137; tryItOut("\"use strict\"; (this);");
/*fuzzSeed-28551573*/count=138; tryItOut("\"use strict\"; /*oLoop*/for (let xkspgs = 0, sjtqpp, (null >= [,,]); xkspgs < 19; ++xkspgs) { Object.prototype.watch.call(m0, \"arguments\", (function() { try { a0[v0] = o1.o0.o2; } catch(e0) { } try { v1 = g1.runOffThreadScript(); } catch(e1) { } v1 = Object.prototype.isPrototypeOf.call(o0, p1); return g1; })); } ");
/*fuzzSeed-28551573*/count=139; tryItOut("\"use strict\"; Object.prototype.unwatch.call(g1, \"isSealed\");");
/*fuzzSeed-28551573*/count=140; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.min(Math.abs(Math.max(Math.tanh(1/0), (mathy0(Math.sqrt(x), Math.fround(y)) >>> 0))), ( + ((Math.hypot(( + Math.imul((mathy0((( - (y | 0)) | 0), y) << Math.atan2(y, y)), x)), ( + Math.hypot(Math.fround(x), (( - (0x0ffffffff >>> 0)) >>> 0)))) >>> 0) && Math.fround(Math.max((( ~ ((Math.atan2((y >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0), ((( - ((((Math.PI >>> 0) > (2**53-2 >>> 0)) >>> 0) | 0)) | 0) >>> 0)))))) | 0); }); ");
/*fuzzSeed-28551573*/count=141; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=142; tryItOut("mathy0 = (function(x, y) { return (Math.hypot(((( ! (Math.fround((Math.fround(x) + (( + ( + Math.hypot((x >>> 0), ( + Math.cosh((x ? (0x0ffffffff >>> 0) : 0.000000000000001)))))) | 0))) >>> 0)) | 0) >>> 0), ((Math.fround(Math.imul(Math.fround(y), Math.fround((Math.imul((x >>> 0), ( + Math.clz32(( + (Math.log(x) | 0))))) >>> 0)))) >>> Math.hypot(Math.fround(Math.pow((Math.round((x | 0)) >>> 0), ( + x))), x)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [42, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), -0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 1/0, 0, -Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), 2**53, -1/0, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 0x0ffffffff, 0x100000001, -0, Math.PI, 2**53-2, 0x07fffffff, 1, -0x100000000, -0x0ffffffff, -(2**53-2), 1.7976931348623157e308, 0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001]); ");
/*fuzzSeed-28551573*/count=143; tryItOut("\"use strict\"; \"use asm\"; print(x);");
/*fuzzSeed-28551573*/count=144; tryItOut("getter;[[1]];");
/*fuzzSeed-28551573*/count=145; tryItOut("\"use strict\"; /*RXUB*/var r = /[^\\x38]/gm; var s = \"\\ue995\"; print(s.search(r)); ");
/*fuzzSeed-28551573*/count=146; tryItOut("a2[(Math.max(a, this)).prototype] = o1;");
/*fuzzSeed-28551573*/count=147; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (mathy0((((((( ! mathy0(x, (( + ( + ( + x))) >>> 0))) >>> 0) >>> 0) ? ( - Math.fround((( + y) ? ( + Math.max((Math.max((Math.fround(((x >>> 0) >>> (y >>> 0))) | 0), y) | 0), (x | 0))) : ( ~ 0.000000000000001)))) : (((( + y) << ( + 0x100000000)) <= (Math.imul(Math.fround((Math.fround(x) >> Math.atan(y))), y) >>> 0)) >>> 0)) >>> 0) | 0), ((( + (Math.log1p(Math.cosh(Math.fround(x))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy1, [-1/0, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, 0, -0x080000000, -0x100000001, 1, -(2**53), 0x0ffffffff, 2**53, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff, -(2**53-2), 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -0x080000001, Math.PI, Number.MIN_VALUE, 2**53-2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -0x100000000, 2**53+2, 42, -0, 0x100000000]); ");
/*fuzzSeed-28551573*/count=148; tryItOut("m2.has(m0);print(x);");
/*fuzzSeed-28551573*/count=149; tryItOut("/*MXX3*/g0.Error.stackTraceLimit = g0.Error.stackTraceLimit;");
/*fuzzSeed-28551573*/count=150; tryItOut("a0.length = 16;");
/*fuzzSeed-28551573*/count=151; tryItOut("mathy4 = (function(x, y) { return (( - (Math.fround((Math.log((( + Math.clz32((Math.cosh((x >>> 0)) >>> 0))) | 0)) === Math.fround((Number.MAX_VALUE + (x && (y / y)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-28551573*/count=152; tryItOut("mathy5 = (function(x, y) { return Math.max(((Math.fround(Math.sinh(Math.sign(Number.MAX_SAFE_INTEGER))) << mathy4(( ! x), (( + y) >>> 0))) >>> 0), ((( ~ y) << (( ! (y == y)) === y)) <= (Math.fround(Math.acosh((Math.atan(x) | 0))) == ((mathy0((y >>> 0), (Math.min((-Number.MAX_VALUE ? y : ( + -0x080000000)), (Number.MAX_VALUE | 0)) >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy5, [null, ({valueOf:function(){return '0';}}), true, (new Boolean(false)), (new Number(-0)), 0.1, '', (function(){return 0;}), '0', 1, objectEmulatingUndefined(), [0], 0, ({toString:function(){return '0';}}), '/0/', (new Boolean(true)), undefined, (new String('')), '\\0', /0/, NaN, (new Number(0)), -0, [], false, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-28551573*/count=153; tryItOut("Object.preventExtensions(o1.b1);");
/*fuzzSeed-28551573*/count=154; tryItOut("mathy4 = (function(x, y) { return Math.tanh((Math.fround(Math.log(Math.fround(y))) <= ( ~ ( + 0x080000000)))); }); testMathyFunction(mathy4, [(new Number(-0)), /0/, (new String('')), -0, (new Number(0)), NaN, null, objectEmulatingUndefined(), undefined, (new Boolean(true)), '', [], 0.1, false, [0], '/0/', 0, (function(){return 0;}), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), 1, (new Boolean(false)), '\\0', '0', true]); ");
/*fuzzSeed-28551573*/count=155; tryItOut("g1.t0 = new Int16Array(b2, 11, 9);\nh1.iterate = f2;\n");
/*fuzzSeed-28551573*/count=156; tryItOut("z, c = new Date.prototype.setMinutes(yield = Proxy.createFunction(({/*TOODEEP*/})( '' ), window, function  eval (e)null));x;");
/*fuzzSeed-28551573*/count=157; tryItOut("mathy1 = (function(x, y) { return Math.imul((Math.log2((( + (y | 0)) | 0)) | 0), (Math.fround(Math.imul((( - (((x ? x : Number.MAX_SAFE_INTEGER) % ( ~ Math.fround(x))) >>> 0)) | 0), x)) === ( ! ( + (0x080000000 * x))))); }); testMathyFunction(mathy1, [0x080000000, 0x100000000, -Number.MIN_VALUE, -(2**53), -0x0ffffffff, -Number.MAX_VALUE, 1/0, 0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, 42, 1, Number.MAX_VALUE, 0, 2**53, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, 0x080000001, 2**53-2, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, Number.MIN_VALUE, -0x100000000, -(2**53-2), Math.PI, 0.000000000000001, -0x07fffffff, 0x0ffffffff, -0x080000001, -0, 1.7976931348623157e308]); ");
/*fuzzSeed-28551573*/count=158; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-28551573*/count=159; tryItOut("\"use strict\"; m2 = new Map(o2.h2);");
/*fuzzSeed-28551573*/count=160; tryItOut("\"use strict\"; h0.iterate = (function(j) { g1.f2(j); });");
/*fuzzSeed-28551573*/count=161; tryItOut("if((x % 2 == 1)) { if (d = w ^= (void shapeOf(x))) /*tLoop*/for (let a of /*MARR*/['fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), -(2**53+2), -(2**53+2), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), -(2**53+2),  /x/g , 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), -(2**53+2),  /x/g ,  /x/g , -(2**53+2), 'fafafa'.replace(/a/g, x), -(2**53+2), -(2**53+2), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x),  /x/g , -(2**53+2), -(2**53+2), 'fafafa'.replace(/a/g, x), -(2**53+2),  /x/g , -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x),  /x/g , -(2**53+2),  /x/g , 'fafafa'.replace(/a/g, x), -(2**53+2), -(2**53+2), 'fafafa'.replace(/a/g, x),  /x/g , -(2**53+2),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , 'fafafa'.replace(/a/g, x), 'fafafa'.replace(/a/g, x), -(2**53+2),  /x/g ,  /x/g , 'fafafa'.replace(/a/g, x), -(2**53+2), -(2**53+2), -(2**53+2), 'fafafa'.replace(/a/g, x),  /x/g , -(2**53+2), 'fafafa'.replace(/a/g, x), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2),  /x/g , -(2**53+2), -(2**53+2), 'fafafa'.replace(/a/g, x),  /x/g , 'fafafa'.replace(/a/g, x), -(2**53+2),  /x/g , -(2**53+2), 'fafafa'.replace(/a/g, x), -(2**53+2), -(2**53+2),  /x/g , 'fafafa'.replace(/a/g, x),  /x/g ,  /x/g , 'fafafa'.replace(/a/g, x), -(2**53+2), 'fafafa'.replace(/a/g, x), -(2**53+2), 'fafafa'.replace(/a/g, x),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ]) { Array.prototype.forEach.call(a1, (function() { a1[v2]; return t0; }), a0); } else a2 = Array.prototype.slice.call(a1, 13, -6);}");
/*fuzzSeed-28551573*/count=162; tryItOut("s1.toString = (function() { try { v0 + ''; } catch(e0) { } try { e0.add(f0); } catch(e1) { } try { for (var p in f1) { /*RXUB*/var r = r2; var s = \"\"; print(r.exec(s));  } } catch(e2) { } m0.has(this.h2); return m2; });\nv1 = evalcx(\"function f2(o1) \\\"\\\\u04D2\\\"\", g0);\n");
/*fuzzSeed-28551573*/count=163; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, 0, 1.7976931348623157e308, 42, -0, -(2**53), 2**53, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, Math.PI, 1/0, Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 2**53-2, 2**53+2, 1, Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, 0x0ffffffff, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, -(2**53+2)]); ");
/*fuzzSeed-28551573*/count=164; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 33554433.0;\n    d1 = (((+(((0xd563c903))))) - ((d1)));\n    d0 = (+(1.0/0.0));\n    return +((window));\n  }\n  return f; })(this, {ff: Proxy.revocable}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [1/0, -0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, 42, -0x0ffffffff, 0, -(2**53-2), 0x080000000, -0x07fffffff, 1, 2**53, -(2**53), 0x0ffffffff, 0x100000001, Math.PI, 0x07fffffff, 0.000000000000001, Number.MAX_VALUE, 0x100000000, -0, -0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, -0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, -0x080000001, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=165; tryItOut("print(i2);");
/*fuzzSeed-28551573*/count=166; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.sqrt(( + ( + Math.round(( + ( ~ (( + Math.hypot(( + 0x0ffffffff), ( + mathy0(Math.fround(x), y)))) >>> 0))))))); }); testMathyFunction(mathy1, [2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -1/0, 0x080000001, -0x100000001, 0x07fffffff, 1.7976931348623157e308, -(2**53), -0x07fffffff, 0x080000000, -(2**53+2), -0x100000000, Number.MIN_VALUE, 0x100000001, 0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, 42, -0, 0.000000000000001, 2**53-2, 2**53, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, 0x100000000, -0x080000001]); ");
/*fuzzSeed-28551573*/count=167; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return ((Math.pow(( + ((Math.tanh((y >>> 0)) | 0) % Math.fround(Math.imul(Math.PI, x)))), (( - ( - (x | 0))) | (( - (Math.acosh((Math.clz32(y) >>> 0)) | 0)) >>> 0))) <= ( ! ((((y <= y) | 0) ^ Math.atan2(x, ( + x))) | 0))) >>> 0); }); testMathyFunction(mathy2, [0x080000001, -0x100000000, -0, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 0/0, Number.MAX_VALUE, 1/0, 1, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, 0, -0x100000001, 0x07fffffff, -0x080000001, 2**53+2, 1.7976931348623157e308, 2**53, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), Number.MIN_VALUE, -0x080000000, -1/0, -0x07fffffff, -Number.MIN_VALUE, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=168; tryItOut("\"use strict\"; a2[x] = h2;");
/*fuzzSeed-28551573*/count=169; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.expm1(( + Math.acosh(( + Math.min(Math.fround(( + (( + x) / ( + 1)))), Math.fround(Math.fround(Math.pow(x, ((( ~ (((x >>> 0) === (Math.sin(x) >>> 0)) >>> 0)) >>> 0) >>> 0))))))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x100000001, 2**53-2, -0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, 0x100000000, -Number.MAX_VALUE, 0, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, 0x100000001, 42, 2**53+2, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, 2**53, Number.MAX_VALUE, 0x0ffffffff, -(2**53), -(2**53+2), -1/0, 0.000000000000001, -0, -0x0ffffffff, Math.PI, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=170; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float64ArrayView[1]) = ((-1099511627777.0));\n    return +((+((((d0) < (d0)))>>>((/*FFI*/ff((((-0xa305d*(0x6c3a71fb)) & ((0x1a15e6e5)+(0xfe68eb39)-(0xb88ef66c)))), ((0x32e2b4e4)), ((((d0)) / ((d1)))), ((((0xffffffff)) & ((0x3ce714fb)))), ((d0)), ((65537.0)), ((281474976710657.0)), ((8589934591.0)), ((-1048577.0)), ((4097.0)))|0)-(0xfe744e27)))));\n  }\n  return f; })(this, {ff: function  x (  = yield d = window, x, ...\u3056) { \"use strict\"; yield [[1]] } }, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0, -0x0ffffffff, 0.000000000000001, 0x080000001, 0x100000000, 42, -(2**53+2), -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0, -(2**53), 2**53+2, 2**53-2, -(2**53-2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, Math.PI, -0x100000000, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 1, 1/0]); ");
/*fuzzSeed-28551573*/count=171; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -262145.0;\n    var i3 = 0;\n    var i4 = 0;\n    {\n      {\n        {\n          i4 = (i4);\n        }\n      }\n    }\n    {\n      i4 = (!((0x77ff74bb) >= ((0xd2061*(i4))>>>((i4)))));\n    }\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: function  b () { /*\n*/return (( + (x | 0)) | 0) } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x100000001, 1.7976931348623157e308, -0x080000000, -(2**53-2), 2**53-2, -0x0ffffffff, -0x080000001, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE, -(2**53), 1, Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, Math.PI, 0, 0x100000000, -0, -(2**53+2), -0x07fffffff, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, 0x0ffffffff, 42]); ");
/*fuzzSeed-28551573*/count=172; tryItOut("mathy0 = (function(x, y) { return Math.pow(Math.max(Math.fround((Math.min((x | 0), (( ~ 0x07fffffff) | 0)) & (Math.max(Math.pow(y, y), (x - -0)) >>> 0))), (x * y)), ( + Math.fround(Math.acosh(Math.fround(( ~ Math.fround((( + ((y < y) >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy0, [0x080000001, 2**53-2, -(2**53-2), 0x07fffffff, Number.MIN_VALUE, 1, 2**53+2, -(2**53), -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, 0x100000000, 42, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, -0, 1/0, Number.MAX_VALUE, 0/0, -0x100000001, -0x0ffffffff, -1/0, Math.PI, -0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0x100000001, -0x080000001]); ");
/*fuzzSeed-28551573*/count=173; tryItOut("this.o1.o0.h1.set = f2;");
/*fuzzSeed-28551573*/count=174; tryItOut("\"use strict\"; Array.prototype.splice.call(a2, NaN, v1, h2);");
/*fuzzSeed-28551573*/count=175; tryItOut("a1[\"tanh\"] = s0;");
/*fuzzSeed-28551573*/count=176; tryItOut("m0.delete(v2);");
/*fuzzSeed-28551573*/count=177; tryItOut("m1.set(b1, b0);yield;");
/*fuzzSeed-28551573*/count=178; tryItOut("\"use strict\"; xpmniu();/*hhh*/function xpmniu(a, [], this.y, new (new Function)().__proto__, x, x, x = -390130393.5, x = length,  , NaN, w, x, x, x = -13, get = /[^]/gyim, x, z, getInt16, y, x, e, x, x, y, x, eval, x, x, e, d =  /x/ , NaN = -1427634692.5, NaN, x, a, b, eval,  , e, z = -200297313, x, z, window, a, ...x){a1.pop();}");
/*fuzzSeed-28551573*/count=179; tryItOut("\"use strict\"; /*hhh*/function rzayou(NaN, \u3056, [{z, c}, {}, , x, ], x, c, NaN, \u3056, x, [], [], window, x, y, x = this, x, e, window, x = x, e, x = -4, a, x, eval, d, x, eval, e, x, d, x, window =  /x/ , b = \"\\u1BA7\", c = [,,], window, x, NaN, eval, NaN, z, x = new RegExp(\"^|.+\", \"gyim\"), x, eval = -29, x, this.\u3056, y, x, NaN, c, w =  /x/ , eval, x, b, set, \u3056 = -4, \u3056, c, eval =  '' , x, (function ([y]) { })(), x, x, d, b, x = undefined, x, x, z = null, this.d, window =  \"\" , a, x, x, w, x = length, x =  \"\" , z, b, y, NaN = /[^]/gym, c, this.x, w, x = /^/gm, w, x = new RegExp(\"\\\\B\", \"m\"), b, y, x, w, c, w, x, d, x){for (var p in m0) { try { this.m1.get(this.t0); } catch(e0) { } for (var p in m1) { v2 = Object.prototype.isPrototypeOf.call(s2, t1); } }}/*iii*/;");
/*fuzzSeed-28551573*/count=180; tryItOut("\"use strict\"; var agebhv = new ArrayBuffer(12); var agebhv_0 = new Int16Array(agebhv); print(agebhv_0[0]); agebhv_0[0] = 0x99; var agebhv_1 = new Int16Array(agebhv); agebhv_1[0] = 0; print(agebhv);{}");
/*fuzzSeed-28551573*/count=181; tryItOut("r1 = /\\uae18{4,}/gim;");
/*fuzzSeed-28551573*/count=182; tryItOut("s2 += 'x';");
/*fuzzSeed-28551573*/count=183; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-28551573*/count=184; tryItOut("Array.prototype.pop.call(a2);");
/*fuzzSeed-28551573*/count=185; tryItOut("\"use strict\"; i1.send(t0);");
/*fuzzSeed-28551573*/count=186; tryItOut("print((4277) ^=  '' .__defineSetter__(\"a\", Uint8ClampedArray));");
/*fuzzSeed-28551573*/count=187; tryItOut("selectforgc(o2);");
/*fuzzSeed-28551573*/count=188; tryItOut("\"use asm\"; /*RXUB*/var r = /(?!\\3)+/ym; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-28551573*/count=189; tryItOut("mathy2 = (function(x, y) { return (( + Math.atan2(( + Math.log10(( - mathy1(Math.min(x, Math.cbrt(x)), y)))), (( + Math.imul(( + (((Math.clz32(x) | 0) ^ ((Math.min((x | 0), Math.fround(Math.sin(Math.fround(y)))) | 0) | 0)) | 0)), ( + (x + Math.acos((( - (y | 0)) >>> 0)))))) >>> 0))) ? (( - ( + Math.fround(Math.log2((y | 0))))) ? Math.min((Math.acos(( - (2**53+2 >>> y))) | 0), (( ~ Math.min(( + 2**53+2), y)) | 0)) : (((Math.sin(Math.fround(Math.cbrt(Math.fround(-0x100000001)))) | 0) || ((( - (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) >>> 0)) | 0)) : Math.atanh((((x | 0) & (Math.fround((( + (y / ( + (x , Math.PI)))) , Math.imul(y, y))) | 0)) | 0))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 42, -1/0, Number.MAX_VALUE, 0.000000000000001, -0x080000001, Number.MAX_SAFE_INTEGER, 1, 0, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, -0, -0x07fffffff, 0x07fffffff, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE, 2**53, 0x100000000, 0x080000000, 0x080000001, 0x100000001, -0x100000001, Math.PI, 0x0ffffffff, -0x080000000, 2**53+2]); ");
/*fuzzSeed-28551573*/count=190; tryItOut("\"use strict\"; this.m2.set(a0, f1);");
/*fuzzSeed-28551573*/count=191; tryItOut("f1 = t1[4];");
/*fuzzSeed-28551573*/count=192; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i3 = (/*FFI*/ff(((~~(+(0.0/0.0)))), ((((i3)) << ((abs((imul((i3), (i3))|0))|0) / (~(((0xaa124941) ? (0x8935e85c) : (0xfefd397d))))))), ((+(0.0/0.0))), ((((/*FFI*/ff()|0)*0xdea5b)|0)), ((+(1.0/0.0))))|0);\n    i0 = (!(i3));\n    (Int8ArrayView[2]) = (-(((i1))));\n    return (((i3)-(0xfd89c532)))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x07fffffff, 0x100000001, 1, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, 0/0, Math.PI, -(2**53), -Number.MAX_VALUE, 1/0, -1/0, 42, 2**53-2, 0x080000000, 0.000000000000001, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 0x100000000, 0, -0x080000001, -0x0ffffffff, -(2**53+2), -0x100000001, 0x07fffffff, -Number.MIN_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=193; tryItOut("Array.prototype.pop.apply(a2, []);print(o0.o2.p2);");
/*fuzzSeed-28551573*/count=194; tryItOut("/*RXUB*/var r = new RegExp(\"[\\\\D]\", \"ym\"); var s = \"0\"; print(s.match(r)); ");
/*fuzzSeed-28551573*/count=195; tryItOut("mathy2 = (function(x, y) { return (mathy1((mathy0((((42 >>> 0) !== (x >>> 0)) >>> 0), ((( + Math.min(Math.fround(Math.atan2(Math.hypot(x, x), (Math.max(((x | 0) / (x | 0)), y) >>> 0))), Math.round(( + ( ! 2**53+2))))) && (( + x) % x)) | 0)) | 0), ( + Math.asin(( + Math.min(Math.fround((Math.fround(( + Math.hypot(( + 0x0ffffffff), x))) == Math.fround(x))), ( + (( - x) ? (y >>> 0) : Math.fround((( ! (x | 0)) | 0))))))))) | 0); }); ");
/*fuzzSeed-28551573*/count=196; tryItOut("m2.has(b1);");
/*fuzzSeed-28551573*/count=197; tryItOut("\"use strict\"; for (var p in p0) { try { this.a0 = /*MARR*/[0x50505050, x, (-1/0), x, x, 0x50505050, true, true, {}, {}, true, {}, {}, true, true, 0x50505050, {}, 0x50505050, 0x50505050, true, x, x, 0x50505050, 0x50505050, true, 0x50505050, x, 0x50505050, true, {}, x, (-1/0), {}, {}, 0x50505050, (-1/0), true, (-1/0), {}, {}, (-1/0), true, (-1/0), {}, {}, true, {}, true, (-1/0), x, x, true, x, (-1/0), (-1/0), {}, (-1/0), {}, (-1/0), 0x50505050, true, x, 0x50505050, true, 0x50505050, {}, 0x50505050, true, {}, true, true, {}, true, (-1/0), {}, {}, 0x50505050, (-1/0), true, x, {}, x, (-1/0), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}]; } catch(e0) { } a1 = r2.exec(s2); }");
/*fuzzSeed-28551573*/count=198; tryItOut("\"use strict\"; this.g1.offThreadCompileScript(\"v1 = false;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: new (this -  \"\" )((4277), (\nMath.max(false, -29))), sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-28551573*/count=199; tryItOut("\"use strict\"; for (var v of o2.h2) { /*ODP-2*/Object.defineProperty(o0.g2, \"1\", { configurable: (4277), enumerable: false, get: (function mcc_() { var aagdvd = 0; return function() { ++aagdvd; f2(/*ICCD*/aagdvd % 2 != 1);};})(), set: (function() { ; return v0; }) }); }");
/*fuzzSeed-28551573*/count=200; tryItOut("x <= c;");
/*fuzzSeed-28551573*/count=201; tryItOut("/*RXUB*/var r = /(\\2)/g; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-28551573*/count=202; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0);");
/*fuzzSeed-28551573*/count=203; tryItOut("p2 + g1.s0;");
/*fuzzSeed-28551573*/count=204; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=205; tryItOut("e2.add(g0);");
/*fuzzSeed-28551573*/count=206; tryItOut("\"use strict\"; o1.v0 = Array.prototype.reduce, reduceRight.call(a2, f0, m0, p2, this.g0.e2);");
/*fuzzSeed-28551573*/count=207; tryItOut("g0.i2 = new Iterator(o2, true);");
/*fuzzSeed-28551573*/count=208; tryItOut("o1.v0 = g0.runOffThreadScript();const b = this;");
/*fuzzSeed-28551573*/count=209; tryItOut("\"use strict\"; g2.v0 = Array.prototype.reduce, reduceRight.call(a1, (function() { try { h0.__proto__ = f1; } catch(e0) { } try { v1 = a0.length; } catch(e1) { } a2[({valueOf: function() { yield x;let([, {}, , ] = {}, gsxqoh, e = (y = \"\\uBA8C\"), set = ((function factorial_tail(ekfscs, zffbtb) { i1.next();; if (ekfscs == 0) { o0.h0 = g1.objectEmulatingUndefined();; return zffbtb; } ; return factorial_tail(ekfscs - 1, zffbtb * ekfscs);  })(39956, 1)), x = x, \u3056, x = y, mwenmk) ((function(){for(let b of /*FARR*/[ \"\" ]) throw x;})());return 4; }})] = (4277); return b0; }), s1, g2.h2, e2, b1, v1);");
/*fuzzSeed-28551573*/count=210; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.log10(( + Math.atanh(( ~ (((y | 0) ? 0x080000000 : (x | 0)) | 0))))) | 0) >= ( + Math.min(( + ( + Math.max(Math.cos(y), (x >>> 0)))), Math.fround(Math.hypot((Math.abs(( + Math.hypot(x, ( + 0x100000001)))) | (( + x) << Math.fround(x))), ((((( ! (x === (0.000000000000001 | 0))) >>> 0) >>> 0) < (( ~ ( + ((-1/0 | 0) ** ( + y)))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [({valueOf:function(){return '0';}}), (new String('')), ({toString:function(){return '0';}}), undefined, '', '\\0', true, false, (function(){return 0;}), [], /0/, (new Boolean(true)), [0], -0, '/0/', ({valueOf:function(){return 0;}}), '0', objectEmulatingUndefined(), (new Number(-0)), 0.1, null, (new Boolean(false)), (new Number(0)), 0, 1, NaN]); ");
/*fuzzSeed-28551573*/count=211; tryItOut("v2 = (a0 instanceof t0);");
/*fuzzSeed-28551573*/count=212; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[0x40000000, function(){}, this, new Number(1.5), this, 0x40000000, 0x40000000, 0x40000000, new Number(1.5), 0x40000000, 0x40000000, 0x40000000]); ");
/*fuzzSeed-28551573*/count=213; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float64ArrayView[0]) = ((+/*FFI*/ff()));\n    switch ((~~(d0))) {\n    }\n    i1 = (/*FFI*/ff(((abs((((!(0xf99e9a9b)))|0))|0)), ((d0)), ((imul((-0x8000000), (i1))|0)), ((d0)), ((0xf24f1d0)), ((+(1.0/0.0))), ((-2199023255553.0)), ((0x5c46d48e)), ((d0)), ((-9007199254740992.0)), ((-144115188075855870.0)))|0);\n    i1 = (0x78cdaf1d);\n    i1 = (((((((0x64d18ae9))+(/*FFI*/ff(((-2097151.0)), ((-9007199254740992.0)), ((4503599627370496.0)), ((36893488147419103000.0)))|0)-(/*FFI*/ff(((-549755813888.0)), ((2.4178516392292583e+24)), ((-1.001953125)), ((-0.0625)))|0))>>>(((0x0))+(0x6d5ec08b)-(0x98f096e0))) % (0x4ceaf518))>>>((!((abs((((0xa678ab38) % (0x3f4fd39f)) & (((0x9d082d9a))-(i1))))|0))))));\n    switch (((-(i1)) >> ((!(0xfc07c38f))+(0x228bd032)))) {\n      case -3:\n        (Uint16ArrayView[0]) = (a+=x);\n    }\n    return +((-((4503599627370497.0))));\n  }\n  return f; })(this, {ff: Array.prototype.forEach}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x080000000, -Number.MAX_VALUE, 1, Number.MAX_VALUE, 2**53+2, 0x080000001, 42, -0, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -0x080000001, 0x100000001, -(2**53), 0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, -0x100000001, -(2**53+2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, 0.000000000000001, 0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, -Number.MIN_VALUE, 0/0, 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=214; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\1[^\\\\s\\\\n\\\\x20])|(?:[^\\\\cL-\\\\B]|\\\\n?(?:[^\\\\w\\\\S])^|\\\\b\\\\S\\u00aa+{3,}){3}\", \"gm\"); var s = \"\\n\"; print(s.split(r)); ");
/*fuzzSeed-28551573*/count=215; tryItOut("\"use asm\"; s0 += s0;");
/*fuzzSeed-28551573*/count=216; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (-0x11d1008);\n    {\n      return (((Uint32ArrayView[((!((((abs((((0xffffffff)) >> ((0xe35c6490))))|0) % (((-0x8000000)) >> ((-0x8000000))))>>>(((((0xf9b70260)) ^ ((0xf934bfec))) == (((makeFinalizeObserver('nursery'))) ? x : [z1,,] % /(?:(?!(?:.+?)?))/gym))*-0xfffff))))) >> 2])))|0;\n    }\n    i1 = (0x75f00800);\n    i1 = (0xfba0dadb);\n    d0 = (33.0);\n    d0 = (+(((0xfc098a5e)+(i1)-(0x36137508)) | (((0xffffffff)))));\n    /*FFI*/ff(((+(-1.0/0.0))), ((2199023255553.0)), ((Infinity)), ((-1.0009765625)), ((((0x237c1107)-(0xf1cef002)+(0x4c6f624a)) ^ ((0xb7e72313)*0x3a2c0))), ((((-0x8000000)) & ((0x67f40099)))), ((131073.0)), ((-16385.0)), ((-70368744177664.0)), ((-2097153.0)), ((-4097.0)), ((-7.555786372591432e+22)), ((-18014398509481984.0)), ((144115188075855870.0)), ((-1.5)), ((68719476737.0)));\n    d0 = ((Uint16ArrayView[2]));\n    return ((((abs(((((0x5514c11e))) >> ((!(i1))+(-0x8000000)-(0x181d18ee))))|0))))|0;\n  }\n  return f; })(this, {ff: intern(++c)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, -Number.MAX_VALUE, -0, -1/0, Math.PI, 1/0, -0x080000000, -(2**53+2), 1, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -0x100000001, 0x080000001, 0x100000001, 2**53-2, 0.000000000000001, -0x07fffffff, 42, 0x07fffffff, 2**53+2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=217; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    /*FFI*/ff(((-590295810358705700000.0)), ((abs((((i1)+(/*FFI*/ff(((-295147905179352830000.0)), ((-4398046511103.0)), ((1.0078125)), ((-274877906943.0)), ((-16777217.0)), ((-2049.0)), ((-35184372088833.0)), ((1152921504606847000.0)), ((1152921504606847000.0)))|0)-(i1))|0))|0)), ((-0x5cfd7a8)), ((16385.0)), ((0x175061b5)));\n    return (((Uint8ArrayView[((~((i1)+((((0x75551546))>>>((0xf9470478))))+((~((0x93405d25)-(0xf8a236db)))))) % ((0xfffff*(i0)) ^ ((0xb8d6f4bc) / (0xf71a436a)))) >> 0])))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x0ffffffff, 0, -0x100000001, Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, -1/0, 0x080000001, 1, 1/0, -(2**53), 2**53, 0x100000000, -0x07fffffff, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, 0x07fffffff, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 42, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, -0x080000001]); ");
/*fuzzSeed-28551573*/count=218; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ! (Math.asinh(( + Math.pow(( + Number.MIN_VALUE), ( + ((y >>> 0) ? ( + x) : (Math.clz32(( ~ 0/0)) >>> 0)))))) | 0)) >>> 0); }); testMathyFunction(mathy4, [(new Number(-0)), true, (new Boolean(true)), false, undefined, 0.1, (function(){return 0;}), NaN, [], (new Number(0)), '/0/', null, -0, '0', ({valueOf:function(){return '0';}}), 1, '\\0', ({toString:function(){return '0';}}), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), '', (new Boolean(false)), 0, [0], /0/, (new String(''))]); ");
/*fuzzSeed-28551573*/count=219; tryItOut("testMathyFunction(mathy2, [true, ({valueOf:function(){return '0';}}), NaN, ({toString:function(){return '0';}}), /0/, (new String('')), 1, -0, 0.1, null, false, '', (new Number(0)), undefined, (new Number(-0)), ({valueOf:function(){return 0;}}), [0], 0, (function(){return 0;}), '/0/', (new Boolean(true)), (new Boolean(false)), objectEmulatingUndefined(), '0', [], '\\0']); ");
/*fuzzSeed-28551573*/count=220; tryItOut("function shapeyConstructor(ycwfop){if (ycwfop) { print(ycwfop); } if (ycwfop) { f1(i0); } return this; }/*tLoopC*/for (let c of  /x/ ) { try{let olpwnt = shapeyConstructor(c); print('EETT'); v0 = a0.length;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-28551573*/count=221; tryItOut("var lirwoh = new ArrayBuffer(8); var lirwoh_0 = new Int32Array(lirwoh); print(lirwoh_0[0]); lirwoh_0[0] = 25; for (var v of o2) { try { m1 + e0; } catch(e0) { } try { a1.reverse(); } catch(e1) { } try { neuter(b0, \"same-data\"); } catch(e2) { } t1 + ''; }");
/*fuzzSeed-28551573*/count=222; tryItOut("s0.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14) { a11 = a13 - a1; var r0 = a10 * 0; var r1 = x / a13; var r2 = a6 * 4; var r3 = a0 & r2; var r4 = 2 | x; var r5 = a12 + a13; var r6 = a12 % a5; var r7 = 5 % r2; var r8 = 7 - 4; r5 = r5 - 5; print(r4); var r9 = 0 | 1; var r10 = r1 / 7; r4 = 8 + r5; var r11 = a12 % 7; var r12 = a12 ^ a10; var r13 = a7 * r4; var r14 = r2 / a14; var r15 = 8 / 2; var r16 = 7 / a4; var r17 = 3 / 6; r12 = a0 & 6; var r18 = 7 / r8; r15 = r0 + 4; var r19 = r15 - a4; a8 = 4 | 9; var r20 = r14 % r13; x = r8 % r4; var r21 = r12 * r15; var r22 = 3 % 3; var r23 = a12 % a7; var r24 = r6 ^ r9; var r25 = r15 + r18; r17 = 5 % 8; var r26 = r14 % a4; r17 = 1 - 4; var r27 = r1 ^ r16; var r28 = r9 % 2; var r29 = r18 + 6; var r30 = r21 ^ r24; var r31 = a11 ^ r10; var r32 = r19 | a2; var r33 = 2 | 3; var r34 = 8 & 9; r24 = r23 + 8; var r35 = 3 - 9; var r36 = r7 ^ r1; var r37 = r35 - 9; var r38 = a0 % r23; var r39 = 1 ^ r30; var r40 = r37 & a2; var r41 = a10 & 3; var r42 = r2 * r2; var r43 = r23 / 2; var r44 = 2 / r8; var r45 = r24 + 9; var r46 = 6 & 5; var r47 = 2 ^ 4; var r48 = a1 / 3; var r49 = a3 + a12; var r50 = r38 * r0; var r51 = 3 / r8; var r52 = 8 * r10; var r53 = r43 & 9; r49 = 7 ^ 6; var r54 = 6 - 9; a14 = r13 / r20; var r55 = r18 / 0; r51 = r20 ^ 0; var r56 = a11 % 7; var r57 = r19 / a12; var r58 = r55 | a12; var r59 = r51 ^ r16; var r60 = 1 % 6; var r61 = r40 + r25; var r62 = 6 ^ 1; print(r41); var r63 = r57 - r17; var r64 = x - r17; var r65 = r13 - r57; var r66 = 4 - r53; var r67 = r2 + 7; var r68 = r5 / r66; var r69 = r64 - r20; var r70 = r37 / a14; var r71 = 9 | 0; var r72 = r22 - r52; var r73 = r11 / r17; r62 = r0 & 2; var r74 = r39 & r59; r20 = 2 / r63; var r75 = a9 % r20; r40 = a11 / r12; r58 = r35 + r66; r9 = r24 ^ r17; var r76 = 1 * r22; var r77 = 8 + a0; var r78 = a11 ^ r50; var r79 = r22 * 7; var r80 = 3 ^ 7; var r81 = 9 - 9; r31 = r35 - a4; var r82 = 2 | a0; var r83 = r72 ^ r22; var r84 = 5 - r23; var r85 = r66 ^ a13; a7 = 3 + 9; var r86 = 1 * r53; r3 = r44 + r51; var r87 = 3 * r8; var r88 = r82 % 6; var r89 = a7 % r72; var r90 = a13 & r20; r4 = r67 % r33; print(r41); var r91 = a0 & 6; var r92 = 9 ^ 4; a1 = 7 | a0; var r93 = r3 - r49; var r94 = 2 / r74; var r95 = r54 | r72; var r96 = r66 & 6; var r97 = r11 & r57; var r98 = r24 % r32; a8 = r95 + r21; var r99 = r59 / r13; var r100 = r34 ^ r37; var r101 = 8 % 9; r51 = 2 % r49; r7 = r84 | r13; var r102 = 6 * r27; var r103 = r24 + r6; var r104 = 0 / r46; var r105 = r79 * r101; var r106 = a14 + r42; print(r52); var r107 = r21 | 7; var r108 = 2 ^ 8; var r109 = 0 | r47; var r110 = r19 | r77; var r111 = r80 % 1; r53 = r110 * r60; var r112 = r5 - r12; var r113 = r28 / a1; var r114 = r26 * r25; r75 = r1 / r13; var r115 = r54 | r60; var r116 = 2 & r62; var r117 = r78 / r12; print(r36); var r118 = r96 & r70; var r119 = a1 - 9; var r120 = 4 - 3; var r121 = 3 - r5; return a13; });");
/*fuzzSeed-28551573*/count=223; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((Math.asin((Math.cbrt(Math.max(x, (((x >>> 0) >= (x >>> 0)) | 0))) / ( + Math.log(( + y))))) | 0) - (( ~ (Math.sinh(( + y)) >>> 0)) | 0)); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, -1/0, -(2**53+2), 0/0, 2**53+2, 0x0ffffffff, 1, -0x080000000, Number.MIN_VALUE, -0x07fffffff, -(2**53), 1.7976931348623157e308, 0.000000000000001, -0, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, Math.PI, 1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, 0x080000001, -0x100000001, 0x100000001, -0x0ffffffff, 0]); ");
/*fuzzSeed-28551573*/count=224; tryItOut("/*hhh*/function jylzpm(){/*bLoop*/for (xflemu = 0; xflemu < 43; ++xflemu) { if (xflemu % 6 == 3) { print(x); } else { Array.prototype.push.call(a0, o0); }  } \nv0 = Array.prototype.some.call(a2, (function mcc_() { var msnbnn = 0; return function() { ++msnbnn; if (/*ICCD*/msnbnn % 5 == 1) { dumpln('hit!'); e1.add(f1); } else { dumpln('miss!'); try { t0 = new Float32Array(b2); } catch(e0) { } try { /*RXUB*/var r = r2; var s = \"\\u00c0\\u00c0\\u00c0\\u00c0\\u00c0\"; print(s.split(r)); print(r.lastIndex);  } catch(e1) { } try { Array.prototype.push.call(g0.a1); } catch(e2) { } m0.get(p2); } };})(), this.o0, m1, t2, e1);\n}/*iii*/o2 + '';");
/*fuzzSeed-28551573*/count=225; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=226; tryItOut("\"use asm\"; /*tLoop*/for (let e of /*MARR*/[]) { print(e); }");
/*fuzzSeed-28551573*/count=227; tryItOut("v0 = Object.prototype.isPrototypeOf.call(a1, g1);");
/*fuzzSeed-28551573*/count=228; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ! Math.imul((Math.imul((( + Math.atanh(( + Math.clz32(Math.fround((((Math.imul((-0x0ffffffff >>> 0), (y >>> 0)) >>> 0) + (x >>> 0)) >>> 0)))))) | 0), ((Math.min(( + (( + x) <= x)), ( + (( ~ (-Number.MIN_SAFE_INTEGER | 0)) | 0))) | 0) | 0)) | 0), ( ~ ( + y)))); }); testMathyFunction(mathy0, [0x100000000, -(2**53-2), Math.PI, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0, -Number.MAX_VALUE, -(2**53+2), 0.000000000000001, -0x080000000, 42, 0x080000000, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), 1, 2**53+2, 2**53, 0x07fffffff, 0x080000001, -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, -0, 0/0, 0x100000001, -0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -1/0]); ");
/*fuzzSeed-28551573*/count=229; tryItOut("/*bLoop*/for (var ayqgpa = 0; ayqgpa < 48; ++ayqgpa) { if (ayqgpa % 3 == 1) { for(var [e, z] = -6 in \"\\uD5D3\") {(get); } } else { g1.v2 = a2.every((function() { i0.next(); throw this.g0.g1.o1; })); }  } ");
/*fuzzSeed-28551573*/count=230; tryItOut("testMathyFunction(mathy2, ['/0/', (new Boolean(false)), undefined, 0.1, objectEmulatingUndefined(), /0/, (function(){return 0;}), '0', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), null, ({toString:function(){return '0';}}), (new Boolean(true)), '', 0, 1, -0, (new Number(0)), '\\0', (new Number(-0)), NaN, true, [0], false, [], (new String(''))]); ");
/*fuzzSeed-28551573*/count=231; tryItOut("--x.__defineSetter__(\" \", WeakMap);");
/*fuzzSeed-28551573*/count=232; tryItOut("{ void 0; void gc('compartment'); } print(x);");
/*fuzzSeed-28551573*/count=233; tryItOut("\"use strict\"; /* no regression tests found */function x(x, x) { \"use asm\"; yield (d -= x ? [1,,] : \u3056 | e) } /*RXUB*/var r = /(?=[^]+?|.?\\b$|(?=$){2,262146}\\B|[]|(?:\\3)[^]{0}|(?!.|\\u1291{4})){1}/gm; var s = false; print(s.match(r)); ");
/*fuzzSeed-28551573*/count=234; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (mathy2((Math.min(( + (Math.sinh((( + mathy3(( + ( + ( + y))), ( + Math.asinh((x >>> 0))))) | 0)) | 0)), ( ~ Math.imul(1.7976931348623157e308, (y ? ( + Math.round(1.7976931348623157e308)) : y)))) | 0), ( ! (( ~ x) >>> 0))) | 0); }); testMathyFunction(mathy4, [0x100000000, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, 0, 0x100000001, 1/0, -1/0, 0x0ffffffff, -0x07fffffff, 0x080000000, 1, -(2**53-2), Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), -0x080000000, Number.MIN_VALUE, 0.000000000000001, -0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, -0, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), 42]); ");
/*fuzzSeed-28551573*/count=235; tryItOut("m2 = new Map(this.g2.i1);");
/*fuzzSeed-28551573*/count=236; tryItOut("testMathyFunction(mathy0, [-(2**53+2), 42, -1/0, 0/0, 1/0, -(2**53), 0x100000001, -Number.MAX_VALUE, -0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, 1, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 0x100000000, Math.PI, -0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, -0, -(2**53-2), 0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, 2**53, 0x07fffffff, 2**53+2, 0x080000000, -0x07fffffff, 0]); ");
/*fuzzSeed-28551573*/count=237; tryItOut("m1.get(o0);");
/*fuzzSeed-28551573*/count=238; tryItOut("\"use strict\"; var v1 = true;");
/*fuzzSeed-28551573*/count=239; tryItOut("\"use strict\"; for (var v of i2) { try { for (var p in s1) { for (var p in g2.i2) { try { Array.prototype.reverse.call(o1.a0); } catch(e0) { } try { g1 = t0[5]; } catch(e1) { } a0.__iterator__ = (function(a0, a1, a2, a3, a4, a5, a6, a7) { var r0 = a6 & 1; var r1 = a1 - a7; var r2 = 6 ^ 2; var r3 = r2 - a6; var r4 = r2 + r0; a3 = 8 * r4; return a0; }); } } } catch(e0) { } v1 = evalcx(\"  in a\", g1); }");
/*fuzzSeed-28551573*/count=240; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=241; tryItOut("testMathyFunction(mathy0, [-0x080000000, 0, 0x0ffffffff, -(2**53+2), 1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0.000000000000001, -0x100000001, -0x07fffffff, -(2**53-2), -(2**53), -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 2**53, -Number.MAX_VALUE, 2**53-2, -0x080000001, -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -0, 1, 0x100000000, 42, Math.PI, Number.MIN_VALUE, -1/0, 0x080000001]); ");
/*fuzzSeed-28551573*/count=242; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( ~ ( - ( + ( - (-0x07fffffff | 0)))))); }); testMathyFunction(mathy3, [0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 42, 0.000000000000001, -0, 1/0, -1/0, 1, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, 2**53, -(2**53+2), 0, 0x0ffffffff, -0x100000000, 2**53+2, 1.7976931348623157e308, -0x0ffffffff, 2**53-2, -(2**53), 0x080000000, Math.PI, 0x100000001, 0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=243; tryItOut("/*RXUB*/var r = /(?:(?:(?=(?=(?!\\s)))))(?:(?!^\u0014{4,}\\3*.{4,5}(?:\u04ec|[^]*?)){262145})/gm; var s = \"_\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\na\\na\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n22\\n2222\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\na\\na\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n22\\n2222\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n22\\n2222\\n\\n\\n\\u0014\\n\\n\\n\\u0014\\n\\n\\n\\u0014FFFFFFFFFFFFmmmmmmmmmmmmmmmmmmmmFFFFFFFFFFFF\\n\\n\\n\\n\\n\\n\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\na\\na\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n22\\n2222\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\na\\na\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n22\\n2222FFFFFFFFFFFFmmmmmmmmmmmmmmmmmmmmFFFFFFFFFFFF\\n\\n\\n\\n\\n\\n\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\na\\na\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n22\\n2222\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\u0014\\na\\na\\n\\na\\na\\n\\na\\na\\n\\na\\na\\n22\\n2222FFFFFFFFFFFFmmmmmmmmmmmmmmmmmmmmFFFFFFFFFFFF\\n\\n\\n\\n\\n\\n\"; print(s.replace(r, (Number.prototype.toExponential).bind, \"gm\")); ");
/*fuzzSeed-28551573*/count=244; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.cos(Math.fround((( - ((( ! Math.imul(0x0ffffffff, x)) ? ( - Math.fround(( + ((Math.ceil(x) >>> 0) * ( + ( + -0)))))) : (Math.min(Math.fround(( - 0x100000000)), (Math.atanh(mathy2(Math.fround(Math.cosh(Math.fround(Math.PI))), x)) >>> 0)) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy3, [-(2**53+2), 1/0, 0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, 2**53+2, -(2**53), Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, 1, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, -0x100000001, -1/0, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, 0.000000000000001, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, 0, Math.PI, 2**53, 0/0, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=245; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 18446744073709552000.0;\n    var i6 = 0;\n    var i7 = 0;\n    var d8 = 9007199254740992.0;\n    var d9 = 1.001953125;\n    var i10 = 0;\n    return +((-1125899906842625.0));\n  }\n  return f; })(this, {ff: function(y) { return y }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53-2, 2**53, Math.PI, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, -0x0ffffffff, 1/0, 0.000000000000001, -(2**53), 0x080000000, 0/0, -(2**53+2), 1.7976931348623157e308, 0x07fffffff, 1, -1/0, -0x080000001, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, 42, -0, 0x100000001, -0x080000000]); ");
/*fuzzSeed-28551573*/count=246; tryItOut("Array.prototype.forEach.apply(a0, [f0]);");
/*fuzzSeed-28551573*/count=247; tryItOut("o1.v2 = evalcx(\"function f0(h2)  { \\\"use strict\\\"; return (/*RXUE*//[^W\\\\s]/gi.exec(\\\"W\\\")).valueOf(\\\"number\\\") } \", g0);");
/*fuzzSeed-28551573*/count=248; tryItOut("\"use strict\"; /*RXUB*/var r = x; var s = \"\\u5280\\u5280\\u5280\\u5280\\u5280\\u5280\\u5280\\u5280\\u5280\\u5280\\u5280\\u5280\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=249; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-28551573*/count=250; tryItOut("Object.prototype.unwatch.call(b2, 16);");
/*fuzzSeed-28551573*/count=251; tryItOut("/*ADP-3*/Object.defineProperty(a0, 17, { configurable: (x % 5 == 1), enumerable: true, writable: objectEmulatingUndefined(this), value:  ''  });");
/*fuzzSeed-28551573*/count=252; tryItOut("for(let a in ((Math.sign)(x))){(null);print(this); }");
/*fuzzSeed-28551573*/count=253; tryItOut("b1 + this.g2;");
/*fuzzSeed-28551573*/count=254; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.hypot((mathy3((((y | 0) !== (Math.sin(( + -0x0ffffffff)) | 0)) | 0), Math.fround((( + mathy2(Math.tanh(1.7976931348623157e308), y)) <= Math.fround((mathy0((( + Math.hypot(( + y), x)) | 0), (x | 0)) | 0))))) | 0), (Math.atan2(42, Math.fround(Math.fround(( ! x)))) >>> 0)) >>> 0) == (Math.pow(mathy3(( ~ Math.hypot(y, y)), ( ! Math.tan(y))), (mathy3((Math.asin(( ~ y)) | 0), (((y && (mathy1(y, (Math.hypot(y, Math.fround(2**53+2)) >>> 0)) | 0)) >>> 0) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy4, [-0x080000000, 1.7976931348623157e308, Math.PI, -Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, 0x100000001, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, Number.MAX_VALUE, 1, 0x07fffffff, -0x080000001, Number.MIN_VALUE, 2**53, 1/0, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, -Number.MAX_VALUE, 0x0ffffffff, -0x100000000, 0, -1/0, -(2**53+2), 0x080000000, -0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-28551573*/count=255; tryItOut("f1.toString = (function mcc_() { var pnupzm = 0; return function() { ++pnupzm; if (/*ICCD*/pnupzm % 3 == 2) { dumpln('hit!'); try { v1 = new Number(Infinity); } catch(e0) { } h2 + ''; } else { dumpln('miss!'); try { /*MXX3*/o2.g0.Symbol.isConcatSpreadable = this.g1.Symbol.isConcatSpreadable; } catch(e0) { } try { ; } catch(e1) { } try { Object.preventExtensions(g2); } catch(e2) { } Array.prototype.unshift.call(a0, t0, m1, f2); } };})();");
/*fuzzSeed-28551573*/count=256; tryItOut("\"use strict\"; t0 = new Int16Array(15);");
/*fuzzSeed-28551573*/count=257; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.asinh(( + (( + (( + Math.max(Math.fround(y), ((x >>> (y ? y : x)) >>> 0))) ? (((x | 0) || (x | 0)) | 0) : x)) && ( + (Math.sign((Math.sqrt(( ~ Math.fround(y))) | 0)) > ((Math.pow((y >>> 0), ((( - (y >>> 0)) >>> 0) | 0)) >>> 0) >>> 0)))))) >>> 0), Math.sign(Math.fround(Math.atanh(Math.pow(0x0ffffffff, Math.atan2(Math.tanh(y), Math.fround(mathy0(0x080000001, y)))))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 1/0, -0x07fffffff, -0x0ffffffff, 2**53+2, Number.MIN_VALUE, 0x100000000, -0x080000000, -Number.MIN_VALUE, 0, 0x080000000, -1/0, 0x07fffffff, -0, -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, -Number.MAX_VALUE, 42, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0/0, -(2**53-2), -0x100000001, 0x0ffffffff, 0x080000001, -(2**53), -0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=258; tryItOut("");
/*fuzzSeed-28551573*/count=259; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return Math.atan(Math.trunc(( + (Math.max((mathy2(Math.fround(x), ((Math.fround(Math.hypot(-Number.MAX_SAFE_INTEGER, y)) || Math.log1p(( + y))) | 0)) >>> 0), x) >>> 0)))); }); testMathyFunction(mathy4, /*MARR*/[[], [], new String(''), -0x080000000, [], new String(''), -0x080000000,  /x/ , new String(''), [], -0x080000000, -0x080000000, true, -0x080000000, -0x080000000, [], true, -0x080000000, [],  /x/ , -0x080000000, new String('')]); ");
/*fuzzSeed-28551573*/count=260; tryItOut("testMathyFunction(mathy0, [0x080000001, -(2**53+2), -0x07fffffff, 2**53, -(2**53-2), Math.PI, -0x100000000, 0.000000000000001, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, -(2**53), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, -0, 42, 2**53+2, 0x100000000, -0x080000000, -0x100000001, -Number.MAX_VALUE, -1/0, 1, -Number.MIN_SAFE_INTEGER, 0x100000001, 0, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=261; tryItOut("g1.toString = (function(j) { if (j) { try { this.i2.send(e1); } catch(e0) { } try { o1.g2.i1 = g2.m1.get(m2); } catch(e1) { } try { g1.g1.v1 = Object.prototype.isPrototypeOf.call(t1, b0); } catch(e2) { } for (var v of i2) { try { m0.set(this.o2, f1); } catch(e0) { } try { Array.prototype.forEach.apply(this.a2, [(function() { try { Array.prototype.forEach.call(a0, (function(j) { if (j) { g2.o2.b0 + ''; } else { for (var p in f0) { try { /*ADP-3*/Object.defineProperty(a1, v0, { configurable: false, enumerable: true, writable: true, value: a2 }); } catch(e0) { } try { e2.has(s1); } catch(e1) { } selectforgc(o0); } } }), i1, m0); } catch(e0) { } g0.offThreadCompileScript(\"\\\"\\\\u32B2\\\"\"); return s1; })]); } catch(e1) { } g0 = this; } } else { try { v0 = r2.multiline; } catch(e0) { } try { f1 + ''; } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(v0, h0); } catch(e2) { } i1.next(); } });");
/*fuzzSeed-28551573*/count=262; tryItOut("");
/*fuzzSeed-28551573*/count=263; tryItOut("\"use strict\"; Array.prototype.splice.call(this.a0, 8, ({valueOf: function() { /*RXUB*/var r = new RegExp(\"(.|.*|Q|(?:(?=$)*)[^]+|\\\\W*)\", \"yim\"); var s = \"\"; print(r.test(s)); return 16; }}), f2);");
/*fuzzSeed-28551573*/count=264; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=265; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.pow(((( ! (((( + Math.fround(Math.min(Math.fround((x < -Number.MAX_SAFE_INTEGER)), Math.pow(x, y)))) * (((( + Math.atan2(( ! 0x100000000), (x | 0))) >>> (Math.log2(Math.fround(mathy3((y >>> 0), y))) | 0)) | 0) | 0)) | 0) >>> 0)) >>> 0) | 0), (( - (Math.max(((((y >>> 0) >= ((x < (( ! (-0 | 0)) | 0)) >>> 0)) | 0) >>> 0), (Math.exp((y >> y)) | 0)) >>> 0)) | 0)) | 0); }); ");
/*fuzzSeed-28551573*/count=266; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return Math.asinh(( + (Math.fround(Math.fround((Math.fround(((mathy1(Math.fround(x), mathy2(x, x)) >>> 0) === x)) < Math.fround(Math.fround((Math.acosh(x) || 0.000000000000001)))))) - Math.exp((y >>> 0))))); }); testMathyFunction(mathy4, [-0x080000001, 0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, 0x080000001, 0x0ffffffff, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, -(2**53-2), Number.MIN_VALUE, 42, 1, -0x07fffffff, 2**53+2, 1/0, -1/0, 0.000000000000001, -0, 1.7976931348623157e308, -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 0/0, 0x100000000, -(2**53+2), 0x100000001, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=267; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=268; tryItOut("let axoztw, eval, x, vlhysw, x, jqdosy, xazlfn, x;;");
/*fuzzSeed-28551573*/count=269; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2\", \"gim\"); var s = \"q\"; print(r.test(s)); ");
/*fuzzSeed-28551573*/count=270; tryItOut("\"use strict\"; var omqdik = new ArrayBuffer(2); var omqdik_0 = new Uint32Array(omqdik); var omqdik_1 = new Float32Array(omqdik); omqdik_1[0] = -6; var omqdik_2 = new Float64Array(omqdik); t0[19];for (var p in i1) { try { this.a2 = []; } catch(e0) { } v2 = evaluate(\"function f0(o0.e1) undefined\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: true })); }");
/*fuzzSeed-28551573*/count=271; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return ((Math.min((( + ( + mathy0(( + (0 | 0)), ( + ( + Math.atanh(( + y))))))) | 0), (( + Math.fround(Math.pow(Math.fround(Number.MIN_VALUE), ( + y)))) | 0)) | 0) > Math.sign((( ! ( + ((Math.asinh(x) + ((((y >>> -(2**53-2)) >>> 0) || (x >>> 0)) >>> 0)) | Math.log(Math.max(y, x))))) | 0))); }); ");
/*fuzzSeed-28551573*/count=272; tryItOut("objectEmulatingUndefinedi0 = h0;");
/*fuzzSeed-28551573*/count=273; tryItOut("for([w, a] = a = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: /*wrap1*/(function(){ \"use strict\"; v1 = g0.runOffThreadScript();return q => q})(), defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: undefined, hasOwn: undefined, get: Float32Array, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(void this), new WebAssemblyMemoryMode()) in (/*UUV2*/(x.cosh = x.sup))) {a0.reverse(g1.h2);print((w = [{}]//h\n) >>= w = 12); }");
/*fuzzSeed-28551573*/count=274; tryItOut("g2.g2.a2.__proto__ = v1;");
/*fuzzSeed-28551573*/count=275; tryItOut("Array.prototype.unshift.apply(a2, [this.i2]);");
/*fuzzSeed-28551573*/count=276; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=277; tryItOut("\"use strict\"; { void 0; void gc(); }");
/*fuzzSeed-28551573*/count=278; tryItOut("m1 = new Map;");
/*fuzzSeed-28551573*/count=279; tryItOut("mathy3 = (function(x, y) { return (Math.fround(mathy1(Math.fround((Math.min(((( - (x >>> 0)) >>> 0) >>> 0), (Math.fround(( ! ( + Math.min(Math.hypot(Math.pow(y, x), y), (x >>> 0))))) >>> 0)) >>> 0)), Math.fround(x))) != (( + (( + y) - ( + (y ? ((Math.sinh((y | 0)) | 0) >>> 0) : Math.expm1((( + (x | 0)) | 0)))))) - (Math.atan2((( + Math.max(42, y)) | 0), (Math.fround(mathy1(x, x)) === Math.fround(Number.MIN_VALUE))) | 0))); }); testMathyFunction(mathy3, [42, -0x100000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, 1, 0x080000000, 0x080000001, -1/0, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x080000000, 1/0, -Number.MAX_VALUE, 0x100000001, -0x100000001, -0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, 0, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, 2**53, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -(2**53), -(2**53+2), 0/0]); ");
/*fuzzSeed-28551573*/count=280; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[(-0), (-0), NaN, (-0), (void 0), (-0), (void 0), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, (-0), -0x0ffffffff, (-0), (-0), NaN, (-0), (void 0), -0x0ffffffff, (void 0), -0x0ffffffff, (-0), (-0), NaN, (-0), (void 0), (void 0), NaN, (-0), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, (void 0), -0x0ffffffff, -0x0ffffffff, (-0), (-0), NaN, -0x0ffffffff, (void 0), -0x0ffffffff, NaN]); ");
/*fuzzSeed-28551573*/count=281; tryItOut("mathy2 = (function(x, y) { return Math.fround(( ! (mathy0(Math.fround(Math.min((Math.abs((Math.acos(0.000000000000001) | 0)) >>> 0), Math.fround(Math.round(0)))), mathy0(y, Math.imul((( + (mathy1((x >>> 0), y) | 0)) >>> 0), (Math.fround(Math.hypot(Math.fround(x), Math.fround(y))) ? 0x0ffffffff : (Math.hypot(Number.MIN_SAFE_INTEGER, (y >>> 0)) >>> 0))))) | 0))); }); ");
/*fuzzSeed-28551573*/count=282; tryItOut("Object.defineProperty(this, \"v1\", { configurable: false, enumerable: false,  get: function() {  return t0.length; } });");
/*fuzzSeed-28551573*/count=283; tryItOut("mathy2 = (function(x, y) { return ((Math.sinh(( - (x ? mathy0(( + Math.imul((x >>> 0), y)), y) : ( + ( + (y ? 1.7976931348623157e308 : (mathy1(Math.fround(y), Math.fround(-(2**53+2))) >>> 0))))))) , Math.imul(Math.fround(( + (( + ( + Math.tan(( + x)))) ^ Math.log2((x | 0))))), Math.fround((Math.sin(Math.fround(mathy0((0x100000001 >>> 0), Math.log10((x >>> 0))))) | 0)))) | 0); }); testMathyFunction(mathy2, [1, Math.PI, -0x07fffffff, 0x080000001, 0x100000001, 0.000000000000001, -0x080000000, -(2**53+2), 2**53, 1.7976931348623157e308, 2**53+2, 0x080000000, -0, 1/0, -0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, 0, -0x100000001, -1/0, 0/0, 2**53-2, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=284; tryItOut("\"use strict\"; M:do o1.b1.__proto__ = o0.v0; while(((/*MARR*/[ /x/g , x, x, x, x,  /x/g , x,  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g , x,  /x/g , x,  /x/g ,  /x/g , x,  /x/g , x,  /x/g ].sort)) && 0);");
/*fuzzSeed-28551573*/count=285; tryItOut("\"use strict\";  for  each(var z in this) print( /x/g );\nvar qwzadx = new SharedArrayBuffer(12); var qwzadx_0 = new Int32Array(qwzadx); var qwzadx_1 = new Uint8ClampedArray(qwzadx); qwzadx_1[0] = -24; var qwzadx_2 = new Int32Array(qwzadx); var qwzadx_3 = new Float32Array(qwzadx); print(qwzadx_3[0]); var qwzadx_4 = new Uint8ClampedArray(qwzadx); print(qwzadx_4[0]); qwzadx_4[0] = -14; /*RXUB*/var r = -7; var s = null; print(s.replace(r, '\\u0341', \"i\")); print(r.lastIndex); Array.prototype.reverse.apply(a0, []);Array.prototype.shift.call(a2);i2 + '';\n");
/*fuzzSeed-28551573*/count=286; tryItOut("testMathyFunction(mathy3, [1/0, -Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, 0, -0, 2**53+2, 42, 0x080000001, Math.PI, -0x100000000, -(2**53+2), -0x080000001, -0x080000000, Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -1/0, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 0x100000001, 2**53-2, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), 0x100000000]); ");
/*fuzzSeed-28551573*/count=287; tryItOut("/*MXX2*/g0.Int8Array.BYTES_PER_ELEMENT = i0;");
/*fuzzSeed-28551573*/count=288; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\b\\\\1*??(?:([\\\\n\\u5ef0\\\\w]+))|[^\\\\W\\\\u00ab\\u00bf](?:\\\\x5B{4})(\\\\2)|(^)|(.)+$[^](?=^)\", \"gi\"); var s = \"\"; print(s.replace(r, 'x')); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=289; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.sqrt(Math.fround((Math.pow(((( + (Math.expm1(Math.hypot(( + x), x)) >>> 0)) >>> 0) >>> 0), (mathy1(mathy1((y >>> 0), x), Math.cosh(Math.atan2(x, ( + (x ? x : y))))) >>> 0)) | 0)))); }); testMathyFunction(mathy3, [0x100000001, 0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, 0x080000000, 2**53, -Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, -0x080000000, 1/0, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, -0x100000001, 1.7976931348623157e308, 0x100000000, 1, 2**53-2, 0x080000001, 42, -(2**53), -0, -(2**53-2), -0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=290; tryItOut("\"use strict\"; /*infloop*/for(var b = window; ('fafafa'.replace(/a/g, eval)) |= (/*MARR*/[ /x/ , new String('q'),  /x/ , new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), false, false, false,  /x/ , new String('q'), false,  /x/ , false, new String('q'),  /x/ , false,  /x/ , new String('q'),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new String('q'), new String('q'), new String('q'), false,  /x/ , new String('q'),  /x/ , new String('q'), false,  /x/ , new String('q')].sort(offThreadCompileScript)); Math.max(19, -1)) /* no regression tests found */");
/*fuzzSeed-28551573*/count=291; tryItOut("s0 += s0;");
/*fuzzSeed-28551573*/count=292; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (-72057594037927940.0);\n    i1 = (0xfdb179fc);\n    return +((+((((0xfbec3ab9)))>>>((i1)+(i1)))));\n  }\n  return f; })(this, {ff: SharedArrayBuffer}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [2**53, 1.7976931348623157e308, 2**53+2, Number.MIN_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -(2**53+2), Math.PI, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, -0x100000000, 0, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, -Number.MAX_VALUE, 2**53-2, -1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 1, -(2**53-2), 0x0ffffffff, 0/0, 0.000000000000001, 0x07fffffff, 0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, -0]); ");
/*fuzzSeed-28551573*/count=293; tryItOut("(this.sqrt());");
/*fuzzSeed-28551573*/count=294; tryItOut("\"use strict\"; v1 = this.t1.length;");
/*fuzzSeed-28551573*/count=295; tryItOut("/*RXUB*/var r = new RegExp(\"(?=[^\\\\s\\\\cM-\\\\u2728\\\\x8C])(?!(?:$+?\\\\ue4cB+?))*?|[^\\\\d\\\\u9C1f-\\u1ea0\\\\s\\\\=-\\\\u5fC9].|.|\\\\b\\\\xAe|(?!\\\\B){3}|\\\\D.*?($)+(?![^])|.|,|(?!\\\\D)|(\\u3f1f){2,6}{4,4}{3}\", \"y\"); var s = [1]; print(uneval(s.match(r))); \n/*MXX2*/g1.g0.RegExp.prototype = g0.a2;\n");
/*fuzzSeed-28551573*/count=296; tryItOut("\"use strict\"; i2.__iterator__ = f1;");
/*fuzzSeed-28551573*/count=297; tryItOut("mathy4 = (function(x, y) { return (Math.imul(( + ( ~ ( + y))), (Math.asinh(Math.fround(( + ((Math.log2((Math.max(Math.trunc((x | 0)), ( + ( ! ( - -(2**53+2))))) >>> 0)) >>> 0) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-28551573*/count=298; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\", \"yim\"); var s = (Element.prototype); print(s.split(r)); ");
/*fuzzSeed-28551573*/count=299; tryItOut("((this.x = Proxy.create(({/*TOODEEP*/})(this), window)));");
/*fuzzSeed-28551573*/count=300; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    i0 = (i0);\n    i0 = (0x5740588b);\n    (Float32ArrayView[((i0)) >> 2]) = ((d1));\n    return ((-0x91f36*(i0)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [1, 0x080000000, -1/0, 2**53, 0.000000000000001, 2**53-2, -0x080000000, -(2**53+2), Math.PI, 0/0, 2**53+2, -0x080000001, 0x100000001, -0x07fffffff, 0x080000001, 0, -Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 1/0, -0, 0x07fffffff, 0x100000000, Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=301; tryItOut("\"use strict\"; v0 = evaluate(\"function f0(o2.i0)  { Array.prototype.push.apply(a1, [o0]); } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 == 0), noScriptRval: false, sourceIsLazy: [[1]], catchTermination: (this.zzz.zzz) }));");
/*fuzzSeed-28551573*/count=302; tryItOut("mathy0 = (function(x, y) { return (/*RXUE*/new RegExp(\"(?=\\\\s|.\\\\d*?){1,}(?:\\\\t+|\\\\b|\\\\b)+\", \"y\").exec(\"\")); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 0x100000000, 0x080000001, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 0x0ffffffff, 2**53-2, -0x100000000, 0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, -0, -Number.MAX_VALUE, 42, 2**53+2, -0x07fffffff, 1/0, 0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, 0, 2**53, 1, Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, -(2**53)]); ");
/*fuzzSeed-28551573*/count=303; tryItOut("\"use asm\"; v1 = r2.source;/*RXUB*/var r = /\\1/yi; var s = \"\\u3f1f\"; print(s.match(r)); ");
/*fuzzSeed-28551573*/count=304; tryItOut("\"use strict\"; {yield;z =  '' ;(({})); }");
/*fuzzSeed-28551573*/count=305; tryItOut("\"use strict\"; v1 = evaluate(\"function f2(h2)  { p0 + h1; } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 6 == 3) }));");
/*fuzzSeed-28551573*/count=306; tryItOut("\"use strict\"; i2.send(t2);");
/*fuzzSeed-28551573*/count=307; tryItOut("v0 = Infinity;");
/*fuzzSeed-28551573*/count=308; tryItOut("\"use strict\"; \"use asm\"; t0.set(o2.g1.t0, 17);");
/*fuzzSeed-28551573*/count=309; tryItOut("\"use strict\"; for (var v of m1) { try { h0.fix = (function mcc_() { var abscfz = 0; return function() { ++abscfz; f0(/*ICCD*/abscfz % 11 == 0);};})(); } catch(e0) { } try { (void schedulegc(g1)); } catch(e1) { } try { /*MXX3*/g0.Function = g0.Function; } catch(e2) { } this.h0.toSource = (function() { try { Array.prototype.sort.call(a2); } catch(e0) { } try { /*MXX2*/g1.Float64Array.BYTES_PER_ELEMENT = this.b2; } catch(e1) { } try { for (var p in t1) { try { v2 = o1.g1.eval(\"m0 = new WeakMap;\"); } catch(e0) { } a0.push(s0); } } catch(e2) { } v1 = NaN; throw this.p1; }); }");
/*fuzzSeed-28551573*/count=310; tryItOut("\"use strict\"; /*oLoop*/for (let jjypgb = 0; jjypgb < 4; ++jjypgb) { print(/(?=(?!.|\\S|(?:\\cR))(?=($)*?){3,7})+?/gim); } \nt2 + p0;");
/*fuzzSeed-28551573*/count=311; tryItOut("a2.forEach((function(j) { f2(j); }));");
/*fuzzSeed-28551573*/count=312; tryItOut("print(x);\nv0 = (t1 instanceof h2);\n");
/*fuzzSeed-28551573*/count=313; tryItOut("for (var v of o1.m1) { v2 = (a1 instanceof i1); }");
/*fuzzSeed-28551573*/count=314; tryItOut("f2(h2);");
/*fuzzSeed-28551573*/count=315; tryItOut("mathy5 = (function(x, y) { return (( + (( + ( ~ Math.fround(mathy0(Math.fround(( ! ((((mathy0(y, y) >>> 0) ? (y >>> 0) : ((Math.fround(x) >= y) >>> 0)) | 0) >>> 0))), (-0x100000001 >>> 0))))) == ( + ( ~ 0x080000000)))) && (mathy4(( + Math.hypot(Math.max(Math.atan2((x | 0), x), Math.fround(mathy0(Math.fround(y), Math.atan2(( + y), -0x07fffffff)))), ((y >>> 0) % x))), ( + Math.min(Math.cos(x), ( + y)))) >>> 0)); }); testMathyFunction(mathy5, [-0x0ffffffff, 0/0, -0x080000000, 1.7976931348623157e308, 0, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, 0x080000001, -(2**53+2), -0x100000000, Number.MAX_VALUE, 2**53+2, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, -1/0, -(2**53), 0x07fffffff, 2**53, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, -0, -(2**53-2), Math.PI, -Number.MIN_VALUE, -0x07fffffff, 42, -Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-28551573*/count=316; tryItOut("let(eval = (Math.hypot((new Boolean(new RegExp(\"((\\\\b\\\\d){1})|(?=\\\\b)^\", \"g\"), [1])), x)), c, qzqoyn, z = (x) = (4277), ReferenceError.name = Object.defineProperty(eval, \"toString\", ({value:  \"\" , configurable:  /x/g })\u000c),  , x = x <= get, rorkyg) ((function(){let(c) { let(x = (4277), c = c, c = c, pvtfxs, a = ((-12 *  /x/g ).throw(/*UUV1*/(c.log1p =  /x/g ))), x, \u3056, dvkpcr) { for(let b in /*FARR*/[c, new let (d = this) \"6\"\u000c(\u3056), .../*MARR*/[(0/0), (0/0), (0/0), new Number(1),  \"use strict\" , (0/0), new Number(1), (0/0), new Number(1),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Number(1), new Number(1),  \"use strict\" ,  \"use strict\" , (0/0), new Number(1), new Number(1), (0/0), (0/0), (0/0), (0/0), new Number(1), (0/0), new Number(1), new Number(1), new Number(1), new Number(1), (0/0), (0/0),  \"use strict\" , new Number(1),  \"use strict\" ]]) y = x;}}})());for(let w of /*MARR*/[function(){}, function(){}, function(){}, function(){}, /(?=\\2{1,}|(?!(?=(\\D)))|[\\r\\S]+?)/i, function(){}]) try { let(odrkmb) ((function(){let(x, ([]) = (void version(170)), Int16Array, w, x =  /x/ , window, dnucwc, msgvlz, rmxpey) ((function(){e = x;})());})()); } catch(e if (eval-=(x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(/[^]/gyi), Promise.reject, q => q)))) { with({}) { /*RXUB*/var r = /(?:((?![^])+?)*(?=[^]))/gy; var s = \"\\u1ea5\"; print(s.replace(r, /*wrap3*/(function(){ var bpojeb =  '' ; (Uint8Array)(); })));  }  } catch(w if (function(){x = z;})()) { for(let y of /*FARR*/[]) throw StopIteration; } catch(NaN if (function(){v0 = a0.reduce, reduceRight(f0, m1);})()) { for (var v of o0) { try { for (var v of m1) { v2 = evaluate(\"(void schedulegc(g1));\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 3), noScriptRval: false, sourceIsLazy: true, catchTermination: (w % 2 == 0) })); } } catch(e0) { } try { for (var v of f0) { try { /*RXUB*/var r = r0; var s = s2; print(uneval(r.exec(s)));  } catch(e0) { } try { a1.reverse(); } catch(e1) { } try { this.e2.__proto__ = a0; } catch(e2) { } t0 = new Float64Array(b2); } } catch(e1) { } b2 = t1.buffer; }print(NaN); } catch(w) { (( '' )()); } finally { w.constructor; } ");
/*fuzzSeed-28551573*/count=317; tryItOut("\"use strict\"; a0.forEach((Boolean()), 11);");
/*fuzzSeed-28551573*/count=318; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[ \"use strict\" , [1], ({x:3}), [1], [1], (-1/0), (-1/0), [1],  /x/ , ({x:3}),  /x/ , (-1/0),  \"use strict\" , ({x:3}),  \"use strict\" , [1], [1], [1], [1], (-1/0), ({x:3}), ({x:3}),  \"use strict\" , (-1/0),  /x/ ,  /x/ ,  \"use strict\" , [1],  \"use strict\" , [1],  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (-1/0),  /x/ , (-1/0), (-1/0), ({x:3}),  \"use strict\" ,  \"use strict\" , [1], [1],  /x/ ,  /x/ , [1],  \"use strict\" ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  \"use strict\" , (-1/0), [1], (-1/0),  /x/ , ({x:3}), [1],  \"use strict\" ,  \"use strict\" , ({x:3}), ({x:3}),  \"use strict\" ,  /x/ , [1], (-1/0),  /x/ , ({x:3}), [1], (-1/0),  /x/ , ({x:3}), (-1/0),  \"use strict\" , (-1/0), ({x:3}), (-1/0),  /x/ , ({x:3}), ({x:3}),  /x/ , ({x:3}), (-1/0),  /x/ , ({x:3}),  /x/ , (-1/0),  \"use strict\" , [1], [1],  \"use strict\" , [1],  \"use strict\" , [1], ({x:3}),  \"use strict\" , (-1/0),  /x/ ]) { /*RXUB*/var r = /(?=(?:(?![])|[\\uDf0B\\f-\u0ada\\D\\W]{0,3}|$[^]+|.{2097153,2097155}|.+))/gm; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(r.test(s)); print(r.lastIndex);  }");
/*fuzzSeed-28551573*/count=319; tryItOut("a1.toSource = (function() { try { v2 = Object.prototype.isPrototypeOf.call(t2, a2); } catch(e0) { } try { m1 + m2; } catch(e1) { } try { let t2 = new Uint8ClampedArray(a1); } catch(e2) { } for (var p in v2) { var s1 = new String(o1); } throw this.o1.a0; });");
/*fuzzSeed-28551573*/count=320; tryItOut("/*hhh*/function prlqxr(x, x = (4277)){b2 + s0;}/*iii*//*ODP-1*/Object.defineProperty(t2, \"0\", ({configurable: false, enumerable: prlqxr}));");
/*fuzzSeed-28551573*/count=321; tryItOut("print(\"\\u8D7E\");function \u3056(b, ...e)\"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d0 = (d0);\n    d0 = (((d0)) / ((33554433.0)));\n    d1 = (NaN);\n    d0 = (6.189700196426902e+26);\n    {\n      d0 = (34359738369.0);\n    }\n    {\n      (Float64ArrayView[0]) = ((d0));\n    }\n    return ((((imul((i2), (0xf1711ff2))|0) == (0xf7f4d))))|0;\n  }\n  return f;v1 = (o1.t1 instanceof m1);");
/*fuzzSeed-28551573*/count=322; tryItOut("\"use strict\"; b2 + v1;");
/*fuzzSeed-28551573*/count=323; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(m1, e0);");
/*fuzzSeed-28551573*/count=324; tryItOut("f2 = t1[({valueOf: function() { (void schedulegc(g2));return 14; }})];");
/*fuzzSeed-28551573*/count=325; tryItOut("{i1 + '';print(x);v0.toSource = f1; }");
/*fuzzSeed-28551573*/count=326; tryItOut("yield (++undefined[\"\\uA181\"]) ^= (x = x);v2 = (o1 instanceof this.p0);");
/*fuzzSeed-28551573*/count=327; tryItOut("Array.prototype.splice.call(a1, -1, 16, t1, m2);");
/*fuzzSeed-28551573*/count=328; tryItOut("g0.m0.has(i1);");
/*fuzzSeed-28551573*/count=329; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.fround((Math.atan(Math.ceil(Math.fround(Math.hypot(Math.fround(-0x100000000), Math.fround(( + (mathy0(Math.fround(x), Math.fround(x)) | 0))))))) | 0)))); }); testMathyFunction(mathy2, [1, Math.PI, -0x100000001, 0x0ffffffff, -0x0ffffffff, 2**53, -(2**53+2), -Number.MAX_VALUE, 0x080000000, -0x07fffffff, -0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, -0x080000001, -0, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 42, 0x07fffffff, 2**53+2, -Number.MIN_VALUE, 0x100000001, 0, 2**53-2, 1/0]); ");
/*fuzzSeed-28551573*/count=330; tryItOut("\"use asm\"; m1 = new Map(g1);function x()({toString: ([\"\\u6596\"]), 21: new RegExp(\"\\\\b|\\\\B|[^\\\\d\\\\x77-\\\\xC2]|[]{4}{3,}(?=(?=[\\uaaef\\\\u0001-\\u00f0]))+?((?!\\\\b[^]|[^]+|\\\\s[\\\\cU-\\u0092]*\\\\d))\", \"gy\") })yield x;String.prototype.blink");
/*fuzzSeed-28551573*/count=331; tryItOut("\"use strict\"; g0.t1 = t2.subarray(11, !this);");
/*fuzzSeed-28551573*/count=332; tryItOut("Array.prototype.unshift.call(a0, f2, g0, o1.s0);");
/*fuzzSeed-28551573*/count=333; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.fround((Math.ceil(( + (Math.fround(Math.sign((Math.hypot(y, ( ! ( + x))) | 0))) % Math.fround((( ! (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0))))) | 0)), Math.fround(( + ( - ( + ((((y | 0) ^ (0x0ffffffff | 0)) >>> 0) - Math.min(Math.pow(x, 1/0), ( ~ x))))))))); }); testMathyFunction(mathy0, [-1/0, 0x07fffffff, Math.PI, -0x080000000, 1.7976931348623157e308, -0x100000000, -(2**53), 0.000000000000001, 0x100000000, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -0x07fffffff, 2**53-2, 1/0, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 42, Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, 0x080000000, 1, Number.MIN_VALUE, 0x080000001, -(2**53-2), -0x100000001, 0x0ffffffff, -0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=334; tryItOut("mathy3 = (function(x, y) { return (Math.atan(( + Math.tanh(42))) >>> 0); }); testMathyFunction(mathy3, [0.000000000000001, Number.MAX_VALUE, 0x080000000, -0x100000000, -Number.MAX_VALUE, 0x100000001, 0x07fffffff, -0x0ffffffff, -(2**53+2), -0x100000001, 1/0, Math.PI, Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1, 0x100000000, 42, -Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 0x080000001, 0, 0x0ffffffff, Number.MIN_VALUE, 2**53-2, -(2**53), -(2**53-2), -0x080000001, 1.7976931348623157e308, -1/0, -0]); ");
/*fuzzSeed-28551573*/count=335; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround(Math.max(Math.cos(Math.fround((Math.fround(x) , Math.fround(y)))), ((Math.fround(( ~ y)) >> Math.fround((Math.atan2((((x >> y) ? (x ** (y | 0)) : -0x080000000) >>> 0), ((((( + y) >>> 0) >>> 0) >= ((0 ? 1/0 : y) >>> 0)) >>> 0)) >>> 0))) | 0))))); }); testMathyFunction(mathy2, [0.000000000000001, 2**53, Number.MIN_VALUE, 2**53-2, -Number.MIN_VALUE, 0, -0, -Number.MAX_VALUE, -(2**53-2), -1/0, -(2**53+2), 1/0, 0x100000001, -0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, 42, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -0x07fffffff, 0/0, 0x0ffffffff, -(2**53), 0x100000000, -0x100000001, 0x080000001, 1, 2**53+2, Number.MAX_VALUE, 0x080000000, 0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=336; tryItOut("g1.s2 += 'x';");
/*fuzzSeed-28551573*/count=337; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + (( + (Math.ceil(((Math.min(Math.fround(((y | 0) << (Math.max(-0x0ffffffff, ((x > ( + Math.PI)) | 0)) | 0))), Math.fround(( - y))) >>> 0) | 0)) | 0)) % ( + ((Math.log1p(((Math.max(Math.fround(( ! Math.fround(Math.acosh((-Number.MIN_VALUE | 0))))), Math.round((0x080000000 | 0))) >>> 0) | 0)) !== (mathy2((Math.pow(( + 0x100000001), ( + Math.sin(Math.PI))) >>> 0), ( + Math.atan2(Math.imul(Number.MIN_SAFE_INTEGER, x), y))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [(new Number(-0)), false, '0', NaN, /0/, [0], objectEmulatingUndefined(), '/0/', 0.1, true, ({toString:function(){return '0';}}), 0, undefined, [], (function(){return 0;}), (new Boolean(true)), -0, (new Number(0)), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '', (new String('')), '\\0', (new Boolean(false)), null, 1]); ");
/*fuzzSeed-28551573*/count=338; tryItOut("/*oLoop*/for (var pfygel = 0; pfygel < 18; ++pfygel) { h1.enumerate = g2.f0; } ");
/*fuzzSeed-28551573*/count=339; tryItOut("\"use strict\"; testMathyFunction(mathy0, [2**53+2, -Number.MIN_SAFE_INTEGER, 42, 0x100000000, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, -0x080000001, -0, 0x080000001, 1/0, Number.MIN_VALUE, Math.PI, 0x080000000, -0x080000000, -0x100000000, 2**53, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 0/0, 1, 0x100000001, -Number.MAX_VALUE, -(2**53+2), 0, -1/0, 0x07fffffff, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=340; tryItOut("/*tLoop*/for (let w of /*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ , null, {x:3}, arguments.caller, arguments.caller, null]) { /*MXX3*/g1.Uint8ClampedArray.name = g1.Uint8ClampedArray.name;\nprint(/\\d{4,11}/ym);\n }");
/*fuzzSeed-28551573*/count=341; tryItOut("testMathyFunction(mathy4, [1/0, 2**53, -0x100000000, -0x07fffffff, -0, 2**53-2, 0.000000000000001, 0/0, 0x100000000, 0x080000001, 0x0ffffffff, -0x0ffffffff, -(2**53-2), -0x080000001, -(2**53), Math.PI, 0x07fffffff, -1/0, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, 42, -Number.MIN_VALUE, 1.7976931348623157e308, 1, -(2**53+2), 0, -0x080000000]); ");
/*fuzzSeed-28551573*/count=342; tryItOut("\"use strict\"; print((() * new RegExp(\".|..{1,5}\", \"m\")()));");
/*fuzzSeed-28551573*/count=343; tryItOut("\"use strict\"; \"use asm\"; a1[timeout(1800)];");
/*fuzzSeed-28551573*/count=344; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=345; tryItOut("s2 += 'x';");
/*fuzzSeed-28551573*/count=346; tryItOut("v0 = Object.prototype.isPrototypeOf.call(s1, o0);");
/*fuzzSeed-28551573*/count=347; tryItOut("a2.reverse(g1.v2, g0.g1);");
/*fuzzSeed-28551573*/count=348; tryItOut("\"use strict\"; m2 = new Map(p2);");
/*fuzzSeed-28551573*/count=349; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - (( ~ ((Math.fround(( ~ ( ~ y))) , y) >>> 0)) >>> 0)) >= Math.asin(((( - ((Math.pow((x ** -(2**53-2)), (0x07fffffff >>> 0)) > (Math.log10(2**53) >>> 0)) >= (x >>> 0))) >>> 0) >>> 0))); }); ");
/*fuzzSeed-28551573*/count=350; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( - Math.acos((mathy1(((x >> 0/0) >>> 0), (( ! ( + y)) >>> 0)) >>> 0))) - Math.log1p((( + Math.acosh(( + mathy2(( + x), ( + (( - (y | 0)) | 0)))))) | 0))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 42, -(2**53+2), 2**53, -0x080000000, -0x0ffffffff, -0x07fffffff, 0/0, -1/0, 1.7976931348623157e308, 1/0, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000001, 1, Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, Number.MAX_VALUE, -0x100000001, 0, -0, -Number.MAX_VALUE, 0x100000000, -0x080000001, 0.000000000000001, 0x07fffffff, -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -0x100000000, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-28551573*/count=351; tryItOut("this.a2.length = ({valueOf: function() { /*RXUB*/var r = r2; var s = s1; print(r.test(s)); return 18; }});");
/*fuzzSeed-28551573*/count=352; tryItOut("\"use strict\"; p2.toString = this.f2;");
/*fuzzSeed-28551573*/count=353; tryItOut("mathy3 = (function(x, y) { return (((Math.cbrt(( + ( - (Math.fround((y << -0x080000000)) ** (Math.min(( + Math.imul(( + (( + x) + ( + y))), 0x07fffffff)), (Math.max(( + (x & x)), ( + x)) >>> 0)) >>> 0))))) >>> 0) & Math.fround(mathy2((Math.fround((Math.fround(Math.cos(Math.fround(Math.tanh((( + ( - y)) | 0))))) & (Math.atan(( ~ y)) | 0))) | 0), ((x < ( + ( ~ Math.fround(0/0)))) | 0)))) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[new String(''), objectEmulatingUndefined(), new String(''), new Number(1), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new String(''), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), new Number(1), new String(''), objectEmulatingUndefined(), new String(''), new Number(1), new Number(1), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new Number(1), new String(''), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new String(''), objectEmulatingUndefined(), new Number(1), new Number(1), new String(''), objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), new Number(1), new Number(1), new String(''), new String(''), new String(''), new Number(1), new String(''), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined()]); ");
/*fuzzSeed-28551573*/count=354; tryItOut("a2 = [];");
/*fuzzSeed-28551573*/count=355; tryItOut("\"use asm\"; /*oLoop*/for (sgrsal = 0; sgrsal < 16; ++sgrsal) {  } ");
/*fuzzSeed-28551573*/count=356; tryItOut("\"use strict\"; v2 = (this.h2 instanceof p0);");
/*fuzzSeed-28551573*/count=357; tryItOut("mathy0 = (function(x, y) { return (((( + ( + (Math.fround(( + ( + ( - ( + Math.fround(((x !== x) | 0))))))) >>> 0))) | 0) && (( ! (( + ( + ( + (( + (x ? y : y)) ? (x >>> 0) : ( + x))))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0x080000001, Number.MIN_VALUE, 1/0, -0x07fffffff, 0.000000000000001, 0x100000000, -(2**53-2), 2**53, -Number.MIN_VALUE, -(2**53), -0x100000001, 1, -0x100000000, 2**53-2, Math.PI, 0x080000000, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 2**53+2, -1/0, 0x100000001, -0, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, 0x07fffffff]); ");
/*fuzzSeed-28551573*/count=358; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.pow((Math.tan(( + ( + Math.atan2((( - (2**53 >>> 0)) >>> 0), (Math.max(y, Math.fround(y)) >>> 0))))) | 0), Math.atanh(Math.pow((Math.fround(((mathy2(x, y) >>> 0) + Math.fround(x))) >>> 0), x))) | 0); }); testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x50505050, objectEmulatingUndefined(), 0x40000000, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x40000000, 0x50505050, 0x50505050, 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x50505050, 0x50505050, 0x50505050, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x50505050, 0x40000000, objectEmulatingUndefined(), 0x40000000, 0x50505050, 0x50505050, 0x50505050, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x50505050, 0x50505050, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x50505050, 0x40000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-28551573*/count=359; tryItOut("g1.i2 = new Iterator(s0, true);");
/*fuzzSeed-28551573*/count=360; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=361; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-0.0078125));\n  }\n  return f; })(this, {ff: ([null])}, new ArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[ \"use strict\" ,  \"use strict\" , null, false, null, false, false, null,  \"use strict\" , false, null,  \"use strict\" ,  \"use strict\" , null, null, null]); ");
/*fuzzSeed-28551573*/count=362; tryItOut("/*RXUB*/var r = /[\\d\\t-d]\\3?|\\uEe04/gyi; var s = \"\\u015f\"; print(s.replace(r, ((void version(185)).valueOf(\"number\")))); ");
/*fuzzSeed-28551573*/count=363; tryItOut("mathy5 = (function(x, y) { return Math.imul(( + Math.max((mathy1((( ~ Math.max(( + x), ( + x))) | 0), ((x < x) ** ((((0x100000000 >>> 0) / (x >>> 0)) >>> 0) ? x : Math.fround(( + (( ! (-0x100000001 >>> 0)) >>> 0)))))) >>> 0), (Math.asinh((( + ( ! (mathy3((( + ( ~ Math.fround(x))) >>> 0), (0 >>> 0)) >>> 0))) | 0)) | 0))), ( ! mathy0(Math.hypot(( + 42), Math.hypot(Math.expm1((x >>> 0)), (x <= Math.fround(( ! Math.fround(x)))))), x))); }); testMathyFunction(mathy5, [0x080000001, -(2**53-2), -0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, 2**53, 2**53+2, Number.MAX_SAFE_INTEGER, 0, 0x100000001, -0x080000000, 0x0ffffffff, -1/0, -(2**53+2), Number.MIN_VALUE, 0x07fffffff, 1/0, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, 0.000000000000001, 2**53-2, -0, -0x080000001, 1, 0/0, 0x100000000, 42, -0x100000000, -0x0ffffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=364; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(((Math.atan2(y, Number.MAX_VALUE) | 0) ? Math.fround(( ~ x)) : (Math.hypot((x && y), ( + Math.log(( + ( ~ ( + x)))))) | 0)), ( + ( + ( + (( + x) ^ (( ! (y | 0)) | 0)))))); }); ");
/*fuzzSeed-28551573*/count=365; tryItOut("mathy4 = (function(x, y) { return Math.pow(( ! (( + -Number.MIN_VALUE) <= ( ! (mathy1(y, y) >>> 0)))), (((mathy3(Math.fround(( ! -0x100000000)), ( + Math.asinh(( + Math.max(( + (x ? ( + 0x100000000) : Number.MAX_SAFE_INTEGER)), y))))) | 0) - (( + Math.min(x, (-0x07fffffff ? (Math.cosh(((Math.atan(y) | 0) >>> 0)) >>> 0) : 2**53))) | 0)) | 0)); }); testMathyFunction(mathy4, [-0x080000001, -0, -0x100000001, 0x100000000, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 42, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -0x080000000, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), 1/0, 0, 0x080000000, 0.000000000000001, 0x07fffffff, 2**53-2, -1/0, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, 2**53, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=366; tryItOut("testMathyFunction(mathy2, [NaN, (new Boolean(true)), [], 1, undefined, null, (new String('')), [0], 0, '\\0', 0.1, true, '0', ({toString:function(){return '0';}}), objectEmulatingUndefined(), -0, (new Number(-0)), '', (new Boolean(false)), '/0/', false, (new Number(0)), ({valueOf:function(){return '0';}}), /0/, ({valueOf:function(){return 0;}}), (function(){return 0;})]); ");
/*fuzzSeed-28551573*/count=367; tryItOut("t0 = new Float32Array(g0.a0);");
/*fuzzSeed-28551573*/count=368; tryItOut("mathy0 = (function(x, y) { return (Math.asinh(((Math.tanh((( ~ 0x100000001) | 0)) | 0) >= ( + Math.expm1(( + Math.fround(( ~ Math.fround(x)))))))) | 0); }); testMathyFunction(mathy0, [-0x080000001, -Number.MIN_VALUE, -0, -Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0, 1/0, -(2**53+2), Math.PI, -0x0ffffffff, 0/0, 0x080000000, 2**53, Number.MAX_VALUE, 1, 0x0ffffffff, 2**53+2, -1/0, 0.000000000000001, 2**53-2, 0x100000000, -(2**53-2), 42, -(2**53), -0x080000000, -0x07fffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=369; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.min((Math.acos(y) >> (Math.tanh(( + (Math.asinh((x >>> 0)) >>> 0))) >>> 0)), (((Math.imul(x, Math.fround(((( + Math.cos((Math.min((Math.fround(Math.hypot(x, y)) >>> 0), ( + ((y | 0) && y))) >>> 0))) ? (y | 0) : (Math.pow((-Number.MIN_VALUE >>> 0), -0x100000000) | 0)) | 0))) != ((Math.imul((Math.expm1(Math.cbrt(( + x))) >>> 0), ((Math.min((Math.hypot(-Number.MIN_VALUE, Math.fround(Math.hypot(Math.PI, Math.fround(x)))) | 0), (Math.fround(Math.ceil(Math.fround(y))) | 0)) | 0) >>> 0)) >>> 0) >>> 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy0, [-0, -1/0, -0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -0x080000001, 0.000000000000001, -(2**53+2), 0x0ffffffff, Number.MAX_VALUE, -0x080000000, -0x100000001, 0, Number.MIN_VALUE, 2**53, -0x0ffffffff, 1, -Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, 1.7976931348623157e308, -(2**53), -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 42, 0x100000001, 0/0]); ");
/*fuzzSeed-28551573*/count=370; tryItOut("if(true) { if ((Uint32Array).call(++e({}), ((function(x, y) { \"use strict\"; return ( + Math.fround(y)); }))((function(x, y) { return y; }).prototype), ((function factorial(ddvmkk) { ; if (ddvmkk == 0) { ; return 1; } for (var p in m0) { try { i0.next(); } catch(e0) { } h2[new String(\"1\")] = p2; }; return ddvmkk * factorial(ddvmkk - 1);  })(1)))) var aondyu, x, cazstk, sjhkgi, nspwjz;o0.v2 = Object.prototype.isPrototypeOf.call(o0.e1, b1);} else {; }function x(x, y, ...y) { yield  \"\"  } e0.has(o2);");
/*fuzzSeed-28551573*/count=371; tryItOut("/*RXUB*/var r = /\\\u31de|Q*(.{3,5})/gim; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=372; tryItOut("\"use strict\"; /*hhh*/function nvxpez(x, y, x, b, window, x, x, b, e, e, x, x, z, x, c, x = new RegExp(\"(?:\\\\2)\", \"m\"), NaN = c, x, yield, x = this, e, y = this, a, d = false, x, w, window, x, x, eval, x, x, window, x = \"\\u3447\", x =  \"\" , \u3056, NaN, x = /(?!([^])){0,}/gy, \u3056, x, y, eval, window, b = eval, c, eval = new RegExp(\"(?=(?!\\\\3))+?\", \"gim\"), d, x, x, x, y, \u3056 = this, b, w, c, d, ...c){g1.offThreadCompileScript(\";\");}/*iii*/m0.set(g1, s2);");
/*fuzzSeed-28551573*/count=373; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=374; tryItOut("v1 = this.g2.runOffThreadScript();");
/*fuzzSeed-28551573*/count=375; tryItOut("mathy5 = (function(x, y) { return Math.sign(Math.acos((Math.log10(( + Math.imul(Math.fround(Math.atan2((x | 0), (-0 | 0))), Math.fround(( - Math.atan2(y, x)))))) >>> 0))); }); testMathyFunction(mathy5, /*MARR*/[1e4, function(){}, 1e4, 1e4, 1e4, 1e4, (-1/0), 1e4, function(){}, (-1/0), (-1/0), 1e4, function(){}, (-1/0), (-1/0), function(){}, 1e4, (-1/0), function(){}, (-1/0), 1e4, function(){}, 1e4, (-1/0), function(){}, 1e4, 1e4, 1e4, function(){}, 1e4, 1e4, (-1/0), function(){}, 1e4, 1e4, (-1/0), 1e4, function(){}, 1e4, function(){}, function(){}, 1e4, (-1/0), 1e4, function(){}]); ");
/*fuzzSeed-28551573*/count=376; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MIN_VALUE, 0x080000001, -0x100000000, 0, Math.PI, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -0, 1, -(2**53+2), -0x100000001, 2**53, 0/0, Number.MIN_VALUE, -(2**53-2), 0x100000001, 0.000000000000001, 2**53+2, Number.MAX_VALUE, 0x100000000, 0x080000000, 1/0, -0x07fffffff, -0x080000001, -0x0ffffffff, -(2**53), 2**53-2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-28551573*/count=377; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-28551573*/count=378; tryItOut("var gvarcq = new ArrayBuffer(4); var gvarcq_0 = new Int32Array(gvarcq); print(gvarcq_0[0]); gvarcq_0[0] = -29; print(({a1:1}));");
/*fuzzSeed-28551573*/count=379; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( - ( + ( ! (Math.fround((Math.fround((x , Math.fround((Math.fround(y) <= Math.fround(x))))) % Math.fround((( + Math.fround((x >>> 0))) ** -0x0ffffffff)))) | 0)))); }); testMathyFunction(mathy0, /*MARR*/[3, 3, -Infinity, -Infinity, -Infinity]); ");
/*fuzzSeed-28551573*/count=380; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a0, 0, ({value:  /x/  === this, writable: x, configurable: (x % 19 == 18)}));");
/*fuzzSeed-28551573*/count=381; tryItOut("(x);");
/*fuzzSeed-28551573*/count=382; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(e0, o2.a1);");
/*fuzzSeed-28551573*/count=383; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=384; tryItOut("e2.has(i2);const d = x;");
/*fuzzSeed-28551573*/count=385; tryItOut("selectforgc(o0);const x = [, , [, [, []], d, y, , c], [, , , eval, w, a], , [, , , , , x]] = timeout(1800);");
/*fuzzSeed-28551573*/count=386; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.log1p(((Math.min(( + mathy0(( + -(2**53)), ( + (((( + ( - ((Math.sqrt(y) | 0) | 0))) >>> 0) << (x >>> 0)) | 0)))), ( + ((( + (( + ( + Math.fround(( ! (-(2**53) >>> 0))))) && ( + Math.fround(mathy0(Math.fround(Math.PI), Math.fround(Number.MAX_SAFE_INTEGER)))))) > y) / ( + ( - Math.fround(x)))))) >>> 0) >>> 0))); }); ");
/*fuzzSeed-28551573*/count=387; tryItOut("o1.v0 = g0.runOffThreadScript();");
/*fuzzSeed-28551573*/count=388; tryItOut("\"use strict\"; s2 + e2;");
/*fuzzSeed-28551573*/count=389; tryItOut("mathy5 = (function(x, y) { return ( + Math.log(( + (Math.sin((Math.min(( + 2**53), y) | 0)) | 0)))); }); ");
/*fuzzSeed-28551573*/count=390; tryItOut("s2 += 'x';");
/*fuzzSeed-28551573*/count=391; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.max(Math.fround(Math.fround(( ~ Math.pow(( + mathy1(x, y)), -(2**53))))), ((1 == ( + Math.max(( + y), ( + y)))) >>> 0)), Math.asinh((Math.asinh((Math.hypot(Math.fround(mathy0(Number.MIN_SAFE_INTEGER, Math.fround(mathy4(y, Math.fround(Math.PI))))), Math.fround(x)) | 0)) >>> 0)))); }); testMathyFunction(mathy5, [-0x100000001, 0x07fffffff, -0, 0.000000000000001, 0x100000001, -0x080000000, 0x080000000, -0x100000000, 42, 0x100000000, -(2**53+2), 0, -1/0, -0x07fffffff, 1.7976931348623157e308, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, 2**53+2, 1, Number.MIN_VALUE, -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=392; tryItOut("mathy1 = (function(x, y) { return (Math.cos((mathy0(( + ( - ( + x))), Math.fround(Math.imul(Math.atan2(0x080000000, Math.fround(y)), Math.fround(( - Math.fround(y)))))) | 0)) | 0); }); ");
/*fuzzSeed-28551573*/count=393; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.imul(Math.fround(Math.exp(Math.fround(Math.hypot(Math.fround((( + Math.fround(x)) ^ (((x >>> 0) << ((x == ( + (( - (x | 0)) | 0))) >>> 0)) >>> 0))), Math.fround(( - ( + Math.fround((Math.fround(x) || Math.fround(x)))))))))), Math.fround((( ! Math.log2(Math.asinh((y | 0)))) >>> 0))); }); testMathyFunction(mathy1, [42, Number.MIN_VALUE, -0x100000000, -(2**53-2), -(2**53+2), -0x0ffffffff, 0x0ffffffff, Number.MAX_VALUE, 0x080000000, 0, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -1/0, Math.PI, -0x080000000, 2**53+2, -0x100000001, -0, -0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0x100000001, 2**53, 0/0, -0x080000001, 1]); ");
/*fuzzSeed-28551573*/count=394; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.atan2(((( + (( + (x & Math.fround((x && Math.fround(( + Math.fround(( ! y)))))))) ? ( + Math.pow(((y + (x !== y)) | 0), Math.min(mathy0(0x100000000, x), Math.hypot(0x080000001, Math.fround((Math.fround(42) ^ Math.fround(y))))))) : ( + ( - Math.min((y >>> 0), ( + (Math.hypot((x >>> 0), ( + ( ! ( + x)))) | 0))))))) ^ Math.max(( - Math.fround(x)), Math.fround(Math.min((2**53-2 ? (y | 0) : y), (mathy0((y >>> 0), (2**53+2 >>> 0)) >>> 0))))) >>> 0), ( + ((((Math.expm1(Math.fround(x)) | 0) , (mathy0(((x >>> 0) < ( + x)), y) | 0)) | 0) ** ( + Math.hypot(((Math.pow(((Math.sqrt((Math.cos(y) | 0)) | 0) | 0), (Math.fround(Math.asinh(x)) | 0)) | 0) >>> 0), (((y ? x : ( + Math.imul(-Number.MAX_VALUE, x))) >> Math.fround(x)) >>> 0)))))); }); testMathyFunction(mathy1, /*MARR*/[(void 0), (void 0), (void 0), (void 0), (void 0), (void 0)]); ");
/*fuzzSeed-28551573*/count=395; tryItOut("\"use strict\"; yield ();");
/*fuzzSeed-28551573*/count=396; tryItOut("((4277));");
/*fuzzSeed-28551573*/count=397; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=398; tryItOut("/*RXUB*/var r = /((?=\\B|(?:\\b+?)){1,4}|[\\D\\W])|(?!\\2|$|U|[^]\\D{0}){3,5}/ym; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-28551573*/count=399; tryItOut("v0 = r1.toString;");
/*fuzzSeed-28551573*/count=400; tryItOut("\"use asm\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 8388609.0;\n    {\n      i1 = (i1);\n    }\n    {\nprint(x);    }\n    return ((-0x683f1*((0x565e9762))))|0;\n  }\n  return f; })(this, {ff: (26)()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, 1.7976931348623157e308, 1, 2**53, -Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -(2**53), Math.PI, -0x100000001, 0x0ffffffff, -0x080000000, -1/0, 0x100000001, -(2**53-2), 0, 2**53+2, 2**53-2, -(2**53+2), -0x07fffffff, Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, -0x0ffffffff, -0x100000000, 42, 0x07fffffff, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=401; tryItOut("\"use strict\"; Object.defineProperty(this, \"t1\", { configurable: Array.prototype.toString = (function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; }), enumerable: true,  get: function() { Array.prototype.sort.apply(a0, [t0, this.o2.s2, m0]); return t1.subarray(15); } });");
/*fuzzSeed-28551573*/count=402; tryItOut("v1 = Object.prototype.isPrototypeOf.call(t1, v1);");
/*fuzzSeed-28551573*/count=403; tryItOut("\"use strict\"; x;const z = ((x)((\nx)) = (let (a) a));");
/*fuzzSeed-28551573*/count=404; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=405; tryItOut("a0 + e2;");
/*fuzzSeed-28551573*/count=406; tryItOut("testMathyFunction(mathy1, [Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, -0x100000001, 2**53, -(2**53-2), -0, -1/0, Number.MIN_VALUE, 0/0, 0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1, 0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 0x0ffffffff, 1/0, Math.PI, 42, -(2**53), -0x080000000, 0x080000000, 2**53+2, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=407; tryItOut("mathy2 = (function(x, y) { return Math.atanh(( + Math.log10(Math.imul(x, Math.pow(2**53+2, Math.max(x, ( + (y ** y)))))))); }); testMathyFunction(mathy2, [-0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 0x100000001, -1/0, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_VALUE, -0x080000001, -(2**53-2), 2**53, 1, 0x0ffffffff, Math.PI, 2**53-2, 42, 0.000000000000001, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, 0, 1/0, 0x07fffffff, -Number.MAX_VALUE, 0x080000000, 0/0]); ");
/*fuzzSeed-28551573*/count=408; tryItOut("mathy4 = (function(x, y) { return ( + ( + (mathy0(( + (( + x) / ( + -Number.MAX_VALUE))), x) <= ( ~ Math.imul(Math.fround(x), (x == y)))))); }); testMathyFunction(mathy4, [0x080000000, 0x080000001, -0x080000000, Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, 0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0, 1, 42, -0x100000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -Number.MAX_VALUE, -0x080000001, 2**53-2, -(2**53-2), 0x100000001, 0.000000000000001, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, -(2**53+2), 2**53, Number.MIN_VALUE, 0x0ffffffff, 0/0, 0x07fffffff]); ");
/*fuzzSeed-28551573*/count=409; tryItOut("testMathyFunction(mathy3, /*MARR*/[this, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, this, function(){}, this, function(){}, this, this, 0x100000001, this, this, function(){}, function(){}, 0x100000001, 0x100000001, 0x100000001, function(){}, this, function(){}, 0x100000001, this, 0x100000001, this, 0x100000001, this, function(){}, 0x100000001, function(){}, 0x100000001, 0x100000001, this, 0x100000001, 0x100000001, function(){}, 0x100000001, 0x100000001, this, this, 0x100000001, 0x100000001, this, 0x100000001, function(){}, this, function(){}, this, this, function(){}, function(){}, 0x100000001, 0x100000001, this, this, this, function(){}, 0x100000001, this, this, this, 0x100000001, function(){}, 0x100000001, 0x100000001, 0x100000001, this, this, function(){}, this, 0x100000001, this, 0x100000001, this, this, this, 0x100000001, this, 0x100000001, 0x100000001, function(){}, this, 0x100000001, this, function(){}, 0x100000001, function(){}, function(){}, function(){}, 0x100000001, function(){}, this, this, this, 0x100000001, this, this, 0x100000001, 0x100000001, 0x100000001]); ");
/*fuzzSeed-28551573*/count=410; tryItOut("\"use strict\"; r2 = new RegExp(\"(\\\\3)?\", \"\");");
/*fuzzSeed-28551573*/count=411; tryItOut("\"use strict\"; v2 = (p0 instanceof p2);");
/*fuzzSeed-28551573*/count=412; tryItOut(" for  each(let y in ((void version(180)))) {for (var p in o1.f0) { try { x = t1; } catch(e0) { } try { print(g2.o0.i2); } catch(e1) { } try { a0.sort((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { var r0 = a7 ^ a15; var r1 = a13 & x; a10 = a13 & 3; var r2 = a1 / a16; var r3 = a10 - a15; var r4 = a11 / r1; var r5 = r4 * 3; a18 = a8 ^ r0; var r6 = a3 - a10; var r7 = 2 - a5; var r8 = 1 % 4; var r9 = a16 & r7; a1 = 9 & a4; r8 = a10 + a14; var r10 = 3 & x; a9 = r4 & a10; a8 = y & y; var r11 = r8 | 3; var r12 = 1 ^ 0; var r13 = a12 | r1; a10 = 1 / r6; var r14 = a19 & 2; var r15 = a5 & 3; a5 = 8 - r0; var r16 = a8 - a15; var r17 = 2 / 2; var r18 = a2 / 8; var r19 = a18 * 0; a8 = a9 % 9; var r20 = r6 % 2; var r21 = 8 / r8; var r22 = a6 + 1; var r23 = 1 + a2; var r24 = 9 * r18; var r25 = a9 - a2; var r26 = a1 - y; var r27 = r1 + 8; var r28 = a2 % a16; var r29 = 2 % r0; r21 = r24 ^ r24; var r30 = 7 ^ r18; var r31 = r9 - r12; var r32 = a17 & r29; var r33 = r21 * y; var r34 = 6 - r18; var r35 = 5 | r23; var r36 = 2 | 0; var r37 = r2 / r6; r2 = 4 & r0; var r38 = 8 | a6; var r39 = r11 ^ a12; var r40 = 3 / a7; r26 = 4 + r0; var r41 = a19 ^ r18; var r42 = r27 % a10; var r43 = a4 * r19; print(r25); var r44 = a13 / 6; var r45 = 4 + r1; var r46 = r18 ^ r25; var r47 = r19 / r7; var r48 = r24 + 9; var r49 = r14 + 5; return a1; })); } catch(e2) { } t1 + ''; }/*RXUB*/var r = /(?:(?!\udc9c))/im; var s = \"\\udc9c\"; print(uneval(r.exec(s)));  }");
/*fuzzSeed-28551573*/count=413; tryItOut("if((x % 87 == 73)) { if (/*MARR*/[arguments.caller, ({}), ({}), ({}), arguments.caller, ({}), new String(''), ({}), new String(''), ({}), new String(''), new String(''), arguments.caller, arguments.caller, arguments.caller, ({}), new String(''), ({}), new String(''), new String(''), new String(''), ({}), new String(''), ({}), ({}), arguments.caller, new String(''), new String(''), arguments.caller, new String(''), arguments.caller, arguments.caller, ({}), new String(''), arguments.caller, arguments.caller, new String(''), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({})].map(DataView.prototype.getUint8)) /*\n*//*RXUB*/var r = new RegExp(\"(?!^){1073741823}\", \"gm\"); var s = \"\\n@\\n@\\n@\\n\\n\\uc8b7\\u60be\\u62af\\u00e1\\u6c05\\n@\\n@\\n@\\n@\\n@\\n@\"; print(s.match(r)); print(r.lastIndex);  else print(x);\n{ if (isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; }\n}");
/*fuzzSeed-28551573*/count=414; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (( + ((Math.fround(Math.max(Math.fround(Math.cbrt(Math.hypot((y >>> 0), (y >>> 0)))), Math.fround(y))) + Math.fround(((0x080000000 % 0) ^ Math.fround(Math.asinh(y))))) ? Math.min(( - Math.log(Math.cbrt((x >>> 0)))), (Math.sinh((Math.acos((y >>> 0)) >>> 0)) | 0)) : Math.tan((x | 0)))) * (Math.atan2((( + Math.log1p(((((Math.sqrt(0.000000000000001) >>> 0) >>> 0) >> (( ! ((y < y) >>> 0)) >>> 0)) >>> 0))) >>> 0), ((x != Math.acos(mathy2(x, x))) | 0)) >>> 0))); }); ");
/*fuzzSeed-28551573*/count=415; tryItOut("testMathyFunction(mathy5, [0, 0x080000001, 0x07fffffff, 2**53-2, 0x0ffffffff, -(2**53-2), 1/0, -0x100000000, Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -0x080000001, -0x080000000, 2**53, -(2**53+2), Number.MAX_SAFE_INTEGER, 42, -1/0, 0x100000000, 0/0, -0, 2**53+2, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, Number.MAX_VALUE, 0x080000000, 1, -Number.MIN_VALUE, 0.000000000000001, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=416; tryItOut("\"use strict\"; ((function too_much_recursion(ymuxtz) { ; if (ymuxtz > 0) { ; too_much_recursion(ymuxtz - 1);  } else {  }  })(3));");
/*fuzzSeed-28551573*/count=417; tryItOut("g2.t1 = t0.subarray(e = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(new (4)(//h\n)), runOffThreadScript), let (x = x) x.yoyo(new ({a1:1})()));");
/*fuzzSeed-28551573*/count=418; tryItOut("v0 = t2[\"setUTCDate\"];");
/*fuzzSeed-28551573*/count=419; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=420; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=421; tryItOut("\"use strict\"; /*iii*//*tLoop*/for (let c of /*MARR*/[new String('q'), (-1/0), (-1/0), 2**53-2, (-1/0), 0x5a827999, new String('q'), 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 0x5a827999, 2**53-2, 2**53-2, 2**53-2, (-1/0), 0x5a827999, 0x5a827999, 0x5a827999, new String('q'), 0x5a827999, new String('q'), 2**53-2, (-1/0), (-1/0), (-1/0), new String('q'), (-1/0), new String('q'), new String('q'), 2**53-2, new String('q'), 2**53-2, (-1/0), 0x5a827999, 2**53-2, new String('q'), (-1/0), new String('q'), new String('q'), (-1/0), (-1/0), new String('q'), (-1/0), 0x5a827999, 2**53-2, 2**53-2, 2**53-2, new String('q'), 2**53-2, 0x5a827999, (-1/0), (-1/0), 2**53-2, (-1/0), new String('q'), new String('q'), new String('q'), (-1/0), 2**53-2, 0x5a827999, 2**53-2, 0x5a827999, new String('q'), new String('q'), new String('q'), 0x5a827999, 0x5a827999, new String('q'), (-1/0), (-1/0)]) { for (var p in f2) { try { for (var v of this.g0) { try { for (var p in t0) { try { for (var v of g0) { try { s1 += g0.s1; } catch(e0) { } try { h2 + ''; } catch(e1) { } try { Array.prototype.shift.apply(a2, []); } catch(e2) { } t0 = t0.subarray(6, 16); } } catch(e0) { } r1 = new RegExp(\".{0}\", \"yim\"); } } catch(e0) { } try { m1.get(i0); } catch(e1) { } try { print(uneval(v1)); } catch(e2) { } i0.next(); } } catch(e0) { } try { i1 = new Iterator(m2, true); } catch(e1) { } undefined = a2[v0]; } }/*hhh*/function rjkqvk(window){/*vLoop*/for (langmz = 0, d, \"\\uB190\"; langmz < 86; ++langmz) { var x = langmz;  '' ; } }");
/*fuzzSeed-28551573*/count=422; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: ((4277).__defineGetter__(\"x\", z)), noScriptRval: true, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-28551573*/count=423; tryItOut("g2.p2.toString = f0;");
/*fuzzSeed-28551573*/count=424; tryItOut("mathy0 = (function(x, y) { return (( ~ (Math.min(Math.fround(Math.max((( + (Math.max(-0x080000001, y) ? y : ( ! ( + Math.abs(0x0ffffffff))))) | 0), Math.log2(( + ( ! x))))), Math.fround((( ~ (Math.exp((y | 0)) | 0)) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [[0], ({toString:function(){return '0';}}), (new Boolean(false)), -0, (new String('')), undefined, 0, (function(){return 0;}), /0/, [], true, 1, '0', (new Boolean(true)), (new Number(-0)), '', objectEmulatingUndefined(), '/0/', 0.1, '\\0', (new Number(0)), null, false, ({valueOf:function(){return 0;}}), NaN, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-28551573*/count=425; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.cosh(( ! x)) ? ( ~ (Math.log(((Math.expm1(( + x)) / ( + x)) | 0)) >>> 0)) : Math.imul((( + (( + y) || ( + ( ~ (( + (( + y) ^ y)) >>> 0))))) !== Math.fround(-Number.MAX_VALUE)), ((Math.hypot((Math.fround(( ! Math.fround(x))) >>> 0), ((Math.min((((x >>> 0) + (y >>> 0)) >>> 0), Math.PI) >>> 0) >>> 0)) >>> 0) | 0))) / ((( + (( + x) / ( + Math.pow(x, (x / y))))) >> (( ~ (( ~ Math.sign(-0x0ffffffff)) | 0)) >>> 0)) % Math.fround(Math.sign((((( + y) === ((((y >>> 0) <= ((x / Number.MIN_VALUE) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0))))); }); testMathyFunction(mathy3, [-(2**53+2), 1.7976931348623157e308, 2**53, -(2**53), 42, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x07fffffff, 2**53-2, Math.PI, -0x080000000, Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, -0x100000001, 0/0, -0x0ffffffff, Number.MIN_VALUE, 0, -Number.MAX_VALUE, -0, -Number.MIN_VALUE, 1, 0x100000000, -0x080000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-28551573*/count=426; tryItOut("while(([this]) && 0)i2 + '';");
/*fuzzSeed-28551573*/count=427; tryItOut("\"use strict\"; Array.prototype.sort.call(a2, (function mcc_() { var bdqbbi = 0; return function() { ++bdqbbi; f1(/*ICCD*/bdqbbi % 6 == 4);};})());");
/*fuzzSeed-28551573*/count=428; tryItOut("t1[13];e1.delete(p2);");
/*fuzzSeed-28551573*/count=429; tryItOut("i0.next();");
/*fuzzSeed-28551573*/count=430; tryItOut("\"use asm\"; var mmyooz = new SharedArrayBuffer(0); var mmyooz_0 = new Int8Array(mmyooz); mmyooz_0[0] = 24; var mmyooz_1 = new Int32Array(mmyooz); var mmyooz_2 = new Uint32Array(mmyooz); var mmyooz_3 = new Uint16Array(mmyooz); mmyooz_3[0] = 23; var mmyooz_4 = new Float32Array(mmyooz); mmyooz_4[0] = 19; var mmyooz_5 = new Float32Array(mmyooz); mmyooz_5[0] = -9; e0.has(b2);print(mmyooz_2);{}e0.__proto__ = o2;Array.prototype.splice.call(a2, -12, 7, f2, this.m1);print(mmyooz);(\"\\u031F\")\u0009;/*RXUB*/var r = r0; var s = \"\"; print(s.replace(r, w\u000c => \"use asm\";   var abs = stdlib.Math.abs;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    i1 = (i1);\n    d0 = (+abs(((+(~~(d0))))));\n    i1 = (!(i1));\n    {\n      i1 = (0x80686da4);\n    }\n    i1 = (i1);\n    (Uint16ArrayView[1]) = (((~~(-3.8685626227668134e+25)) < (0x4990520d)));\n    return +((1.001953125));\n  }\n  return f;)); print(r.lastIndex); v2 = Object.prototype.isPrototypeOf.call(v0, m0);");
/*fuzzSeed-28551573*/count=431; tryItOut("\"use strict\"; for(let w in []);b = Proxy.createFunction(({/*TOODEEP*/})( \"\" ), Uint8Array);");
/*fuzzSeed-28551573*/count=432; tryItOut("t0.set(a0, o0.v2);");
/*fuzzSeed-28551573*/count=433; tryItOut("mathy2 = (function(x, y) { return Math.tan(( - Math.atan2((Math.tan(( + Math.tan(Math.fround((-(2**53+2) && -Number.MIN_VALUE))))) | 0), (( + mathy1(( + -0x080000001), Math.clz32(1))) | 0)))); }); testMathyFunction(mathy2, [0.000000000000001, -(2**53+2), -0, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 0x100000001, 0/0, 42, 0, 0x0ffffffff, 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), 2**53, -0x080000000, -0x100000001, 0x100000000, 1/0, 1.7976931348623157e308, Number.MIN_VALUE, 2**53+2, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2]); ");
/*fuzzSeed-28551573*/count=434; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( - ( + (( + Math.asinh((Math.pow((x + Math.pow(x, ( + (2**53-2 - x)))), (Math.log10((y >>> 0)) - x)) >>> 0))) >= ( + Math.round(Math.clz32(y)))))); }); testMathyFunction(mathy0, /*MARR*/[ /x/ , new Boolean(false), new Boolean(false),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(false),  /x/ , new Boolean(false), 5.0000000000000000000000,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(false),  /x/ ,  /x/ ]); ");
/*fuzzSeed-28551573*/count=435; tryItOut("v2 = (p0 instanceof t0);");
/*fuzzSeed-28551573*/count=436; tryItOut("\"use strict\"; a1.shift();");
/*fuzzSeed-28551573*/count=437; tryItOut("\"use strict\"; a0.__iterator__ = Array.prototype.filter;");
/*fuzzSeed-28551573*/count=438; tryItOut("var idhytq, d, koqffs, vtmtyd, trhzcn, djuzqh, grolio, x;{}");
/*fuzzSeed-28551573*/count=439; tryItOut("Array.prototype.reverse.call(a0, t1);");
/*fuzzSeed-28551573*/count=440; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.pow(( + (( + ( + Math.imul(( + y), Math.fround(((((-Number.MAX_VALUE === ( + ( - x))) | 0) === (( - ( + (Math.imul(y, x) >>> 0))) | 0)) | 0))))) >> (( ! Math.exp(y)) >>> 0))), (Math.exp(( + Math.atanh(( + ((Math.atan2(Math.fround(y), (x | 0)) | 0) ? Math.fround(Math.sin((y >>> 0))) : (( + y) ? Number.MAX_SAFE_INTEGER : mathy1(-(2**53), Math.fround(y)))))))) < ( + Math.atan2((Math.min(-Number.MAX_VALUE, ( - x)) === y), Math.fround((Math.round(((((x >>> 0) < -Number.MIN_VALUE) | 0) | 0)) | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[(void 0), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (void 0)]); ");
/*fuzzSeed-28551573*/count=441; tryItOut("\"use strict\"; delete o1.g1.h2.get;");
/*fuzzSeed-28551573*/count=442; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[ '\\0' ,  '\\0' , ( /* Comment *//(\\b)/ym),  '\\0' , 0x5a827999, new Number(1), new Number(1), ( /* Comment *//(\\b)/ym), new Number(1), 0x5a827999,  '\\0' , 0x5a827999, 0x5a827999, 0x5a827999,  '\\0' , 0x5a827999, 0x5a827999, ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym),  '\\0' , ( /* Comment *//(\\b)/ym),  '\\0' , new Number(1), 0x5a827999, new Number(1), 0x5a827999, 0x5a827999, ( /* Comment *//(\\b)/ym), new Number(1), new Number(1), new Number(1), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), new Number(1), new Number(1), new Number(1), new Number(1),  '\\0' , ( /* Comment *//(\\b)/ym), 0x5a827999, 0x5a827999,  '\\0' , ( /* Comment *//(\\b)/ym),  '\\0' , 0x5a827999, 0x5a827999, ( /* Comment *//(\\b)/ym), new Number(1),  '\\0' , new Number(1), 0x5a827999,  '\\0' ,  '\\0' , ( /* Comment *//(\\b)/ym), new Number(1), 0x5a827999, ( /* Comment *//(\\b)/ym),  '\\0' , ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym),  '\\0' , ( /* Comment *//(\\b)/ym), 0x5a827999, 0x5a827999, ( /* Comment *//(\\b)/ym), 0x5a827999,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , ( /* Comment *//(\\b)/ym), 0x5a827999, 0x5a827999, ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), 0x5a827999,  '\\0' , new Number(1), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), new Number(1), 0x5a827999, 0x5a827999, ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym), ( /* Comment *//(\\b)/ym),  '\\0' , ( /* Comment *//(\\b)/ym),  '\\0' , 0x5a827999, new Number(1), 0x5a827999,  '\\0' ,  '\\0' , 0x5a827999, ( /* Comment *//(\\b)/ym),  '\\0' ,  '\\0' ,  '\\0' , new Number(1), new Number(1),  '\\0' , 0x5a827999,  '\\0' ]) { v1 = Array.prototype.some.call(a2, (function(j) { if (j) { try { h0 + ''; } catch(e0) { } o0.o1.v0 = Object.prototype.isPrototypeOf.call(g2, h0); } else { selectforgc(o1); } }), o1.o1, g2.g2); }");
/*fuzzSeed-28551573*/count=443; tryItOut("/*iii*/for(let c in []);/*hhh*/function coojtb(x = (4277), z, e, NaN, this.b, x, eval, b, x = window, b, w, window, w, w = true, y =  /x/ , x, a, w, x, z, w, a, x, NaN, \u3056 = 2, d, x, c, NaN, x, w, NaN, NaN, a, b, d, b, eval, y, x, e, x, eval, x, b, e, x, eval, x, x, z, x, window, x, a, w, x, x, eval, \"-17\", getter, b, x, x, x, x, NaN, \u3056){for(d = new mathy2()(x) in x) v1 = t2.byteLength;}");
/*fuzzSeed-28551573*/count=444; tryItOut("");
/*fuzzSeed-28551573*/count=445; tryItOut("\"use asm\"; print((makeFinalizeObserver('tenured')));");
/*fuzzSeed-28551573*/count=446; tryItOut("\"use strict\"; for (var p in m0) { try { v2 = (i0 instanceof this.a1); } catch(e0) { } m2.get(h0); }");
/*fuzzSeed-28551573*/count=447; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul(mathy1(Math.atan2(x, Number.MAX_SAFE_INTEGER), Math.asinh(((Math.max(Number.MAX_SAFE_INTEGER, y) >>> 0) >= y))), Math.fround(Math.hypot((Math.fround((Math.fround(( ! (y == x))) > Math.asin(Math.fround(((( + (( + x) ** ( + x))) | 0) - (x >>> 0)))))) >>> 0), (Math.pow(y, Math.trunc(y)) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[[], (-1/0), new Number(1.5), (-1/0),  /x/ , [], (-1/0), (-1/0),  /x/ , (-1/0),  /x/ , [], new Number(1.5), new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-28551573*/count=448; tryItOut("testMathyFunction(mathy5, [-1/0, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53), -0x080000001, 0x080000001, 0x080000000, 0.000000000000001, -0x080000000, 0, -0x100000000, 1, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, 2**53+2, 0x0ffffffff, 0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), Number.MIN_VALUE, 42, -0x100000001, 2**53-2, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=449; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-28551573*/count=450; tryItOut("a0 = o1.m2.get(this.v1);");
/*fuzzSeed-28551573*/count=451; tryItOut("");
/*fuzzSeed-28551573*/count=452; tryItOut("\"use strict\"; /*RXUB*/var r = x = Proxy.createFunction(({/*TOODEEP*/})(19), String.prototype.blink); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=453; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x100000000, -Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -(2**53), Number.MAX_VALUE, 0/0, -1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, -0x080000000, Math.PI, -0x080000001, -0x07fffffff, -(2**53-2), 0, 2**53-2, -0x100000001, 0x0ffffffff, 2**53, 0x080000000, 0x100000000, 2**53+2, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff, 1, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 1/0, -(2**53+2)]); ");
/*fuzzSeed-28551573*/count=454; tryItOut("\"use strict\"; g2 + '';");
/*fuzzSeed-28551573*/count=455; tryItOut("o1.o2 = {};");
/*fuzzSeed-28551573*/count=456; tryItOut("v1 = (this.t0 instanceof this.e0);");
/*fuzzSeed-28551573*/count=457; tryItOut("mathy3 = (function(x, y) { return (( ~ (( + (( - (Math.sin(y) / ( + Math.atan(( + Math.pow(x, (Math.expm1((2**53 | 0)) | 0))))))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[x, -0x2D413CCC, -0x2D413CCC, x, x, x, function(){}, -0x2D413CCC, x, x, -0x2D413CCC, function(){}, function(){}, x, x, -0x2D413CCC, function(){}, -0x2D413CCC, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, -0x2D413CCC, function(){}, function(){}, function(){}, function(){}, -0x2D413CCC, x, function(){}, function(){}, function(){}, function(){}, -0x2D413CCC, -0x2D413CCC, function(){}, function(){}, function(){}, x, function(){}, x, -0x2D413CCC, x, -0x2D413CCC, -0x2D413CCC, function(){}]); ");
/*fuzzSeed-28551573*/count=458; tryItOut("h0 = {};");
/*fuzzSeed-28551573*/count=459; tryItOut("/*infloop*/M:for((Int8Array)(new RegExp(\"\\\\d*|\\\\B(?:[^])*(\\\\B)**?\\\\b|(?!\\u119d)*\\\\B|(?=\\\\cA)|[^]+{524289}\", \"yim\")); (({x:  /x/ })); new true(\"\\u0132\")) {t1.__proto__ = o2;f1 + ''; }");
/*fuzzSeed-28551573*/count=460; tryItOut("this.zzz.zzz;");
/*fuzzSeed-28551573*/count=461; tryItOut("for (var p in g0.v2) { b0.toSource = (function() { v2 = new Number(4.2); return e0; }); }/*bLoop*/for (var qnemzd = 0; qnemzd < 44; ++qnemzd) { if (qnemzd % 21 == 8) { print(\"\\uF319\"); } else { print([1]); }  } ");
/*fuzzSeed-28551573*/count=462; tryItOut("m2.has((+(d = 13)));");
/*fuzzSeed-28551573*/count=463; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (( + (0x080000001 == y)) || ( + Math.atan2(((((x | 0) / (( ~ y) | 0)) | 0) >>> 0), (Math.fround(Math.round(mathy1(Math.imul((-1/0 >>> 0), y), Math.fround((Number.MIN_SAFE_INTEGER , (-0x0ffffffff | 0)))))) >>> 0))))) >= mathy0(( + Math.fround(Math.log2(y))), (( ! ((( + (Math.fround(Math.fround(( ! x))) >= Math.fround(42))) != ( + Math.pow(-Number.MIN_VALUE, y))) | 0)) | 0))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 1/0, -1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0x100000000, -0x100000001, 2**53, 0x080000001, Math.PI, -(2**53+2), Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, 0/0, 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, 0x100000001, -0, -(2**53), -0x080000000, -0x07fffffff, -0x080000001, -(2**53-2), 2**53+2, 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=464; tryItOut("mathy1 = (function(x, y) { return ( - ((Math.fround(( + (( + y) ? (x >> x) : ( + ( - (Math.imul(Math.fround(Math.fround(( ~ Math.fround(x)))), y) | 0)))))) || ( + Math.fround(( + ( + ( - ( + Math.atan2(y, (Math.fround(y) >>> y))))))))) | 0)); }); ");
/*fuzzSeed-28551573*/count=465; tryItOut("testMathyFunction(mathy3, [-0, 2**53, 0/0, -(2**53-2), -(2**53), 0x0ffffffff, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -1/0, -0x100000001, -0x100000000, 0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, 42, -Number.MAX_SAFE_INTEGER, 0, 0x100000001, 1/0, 0x07fffffff, -0x080000001, 2**53+2, 1]); ");
/*fuzzSeed-28551573*/count=466; tryItOut("mathy4 = (function(x, y) { return Math.imul((((Math.sqrt((Math.atanh(y) >>> y)) ? (Math.asin(y) >>> 0) : ((( + ( ! ( + -0x080000001))) * ( ! x)) ? x : x)) || Math.fround(Math.round(Math.fround(( + ( - ( + Math.PI))))))) / (((Math.cos(-(2**53)) >>> 0) + ( + ( ! ( + x)))) >>> 0)), Math.asin(Math.fround(( ~ ( + (Math.fround(-1/0) ? -Number.MIN_SAFE_INTEGER : (( + Math.fround(( - Number.MIN_VALUE))) + ( + Number.MIN_SAFE_INTEGER)))))))); }); testMathyFunction(mathy4, [null, (new Number(-0)), 1, true, /0/, '', ({valueOf:function(){return '0';}}), (function(){return 0;}), 0, (new String('')), '0', '\\0', (new Boolean(false)), undefined, (new Boolean(true)), objectEmulatingUndefined(), 0.1, -0, [], false, NaN, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Number(0)), '/0/', [0]]); ");
/*fuzzSeed-28551573*/count=467; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Math.PI, 2**53, 0, -0x080000000, Number.MIN_VALUE, 0x100000000, 1/0, -(2**53-2), -Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0x0ffffffff, 42, -0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x080000001, 0x100000001, 2**53+2, -(2**53+2), -1/0, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0x080000001, 2**53-2, -0x100000000, 1, -(2**53)]); ");
/*fuzzSeed-28551573*/count=468; tryItOut("s1 = new String(f1);");
/*fuzzSeed-28551573*/count=469; tryItOut("Array.prototype.unshift.call(a0, d = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), function(y) { return new RegExp(\"(?!(?!(?=\\\\S){2}){0,})|(?:(?:.+)[^]|\\\\b(?!.)*?)\", \"ym\") }) ? (yield (void shapeOf(x))) : (4277));");
/*fuzzSeed-28551573*/count=470; tryItOut(" for  each(var y in eval(\"/* no regression tests found */\")) {this.a1 = new Array;((decodeURIComponent)()); }");
/*fuzzSeed-28551573*/count=471; tryItOut("s1 += 'x';function /*PTHR*/(function() { for (var i of /*MARR*/[new Boolean(true), {}, {}, objectEmulatingUndefined(), (void 0), {}, (void 0)]) { yield i; } })()(...x)\"use asm\";   var ceil = stdlib.Math.ceil;\n  var Infinity = stdlib.Infinity;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -2049.0;\n    var i3 = 0;\n    var i4 = 0;\n    return ((((0x78c1b305))+(1)))|0;\n    i1 = (i3);\n    {\n      d2 = (+ceil(((((Infinity)) * ((144115188075855870.0))))));\n    }\n    i1 = ((i0) ? (i1) : (i1));\n    i0 = (0x3c91b091);\n    d2 = (+(((-0xf01ed1)+((0xd97e0123) ? ((-0x5ea10c5) ? (0xfc441886) : (0xfd46b2e2)) : ((((0xfff01c2d))>>>((0xe7c0737))) <= (0xa585cf5d)))) | ((0xffffffff))));\n    return (((i3)))|0;\n    i3 = (1);\n    return (((i3)+(i4)))|0;\n  }\n  return f;{ void 0; selectforgc(this); } Object.defineProperty(this, \"s2\", { configurable:  \"\" , enumerable: false,  get: function() {  return Proxy.create(h1, m0); } });");
/*fuzzSeed-28551573*/count=472; tryItOut("\"use strict\"; var w = Math.asinh((( - -0) | 0));v2 = evaluate(\"/* no regression tests found */\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 != 0), sourceIsLazy: this, catchTermination: false }));");
/*fuzzSeed-28551573*/count=473; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=474; tryItOut("v2 = this.a2.length;");
/*fuzzSeed-28551573*/count=475; tryItOut("mathy0 = (function(x, y) { return (((((Math.sign(x) - (Math.pow((y | 0), (Math.hypot(y, (x >>> 0)) >>> 0)) >> y)) & (( + Math.hypot(( + (( - (x | 0)) | 0)), ( + x))) ? Math.fround(Math.PI) : x)) >>> 0) & Math.tanh(((((y | 0) / (Math.atan2(( + Math.hypot(x, x)), Math.min(-0x080000000, (y >>> 0))) | 0)) | 0) >>> 0))) | 0); }); testMathyFunction(mathy0, [-(2**53+2), 0x100000001, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -0x080000000, 0/0, 1, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, Number.MAX_VALUE, 2**53, -(2**53-2), 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, 1/0, -0x100000000, 0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 42, 0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, 2**53+2, -(2**53), -0x100000001]); ");
/*fuzzSeed-28551573*/count=476; tryItOut("a1.unshift(e2, m0,  /x/ , t2);this.v1 = (t2 instanceof v2);");
/*fuzzSeed-28551573*/count=477; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.min(((Math.atan2(Math.min(y, y), y) ^ ( ! y)) >>> 0), ( ~ (Math.hypot(((Math.sinh(-1/0) | 0) >>> 0), -0x100000000) >>> 0))), ((Math.sqrt(( ~ Math.fround((Math.atan2(-1/0, y) * y)))) | 0) || ( + Math.sinh(Number.MIN_VALUE)))); }); ");
/*fuzzSeed-28551573*/count=478; tryItOut("r2 = /\\3|(?!((?=(?:\\u3514)|\\B){1,3}))/;");
/*fuzzSeed-28551573*/count=479; tryItOut("{Array.prototype.reverse.call(a1); }");
/*fuzzSeed-28551573*/count=480; tryItOut("/*MXX3*/g2.WebAssemblyMemoryMode.length = g1.WebAssemblyMemoryMode.length;");
/*fuzzSeed-28551573*/count=481; tryItOut("m0.get(f0);");
/*fuzzSeed-28551573*/count=482; tryItOut("mathy1 = (function(x, y) { return ((( + mathy0(( + mathy0((((y < x) + -0x0ffffffff) | 0), ((( ! (Math.cos(Math.pow((y | 0), y)) | 0)) | 0) | 0))), ( + (Math.max(Math.fround(mathy0(((1.7976931348623157e308 != ( + Math.cosh(x))) >>> 0), Math.pow(2**53-2, (x >>> 0)))), ((((y ? x : (mathy0(Math.fround(y), x) | 0)) | 0) >>> 0) - ( + y))) % ( ~ (Math.atan((y >>> 0)) | 0)))))) | 0) - (Math.pow((mathy0(Math.ceil(y), (( ~ ((Math.imul((-(2**53+2) >>> 0), (Math.log2(y) >>> 0)) >>> 0) >>> 0)) >>> 0)) | 0), Math.min(( + Math.acos(Math.hypot(( ! y), y))), Math.fround((y === -0x100000000)))) | 0)); }); ");
/*fuzzSeed-28551573*/count=483; tryItOut(";");
/*fuzzSeed-28551573*/count=484; tryItOut("const h1 = {};");
/*fuzzSeed-28551573*/count=485; tryItOut("a2.reverse(o1, o0.i1, this.e1, x, e0);");
/*fuzzSeed-28551573*/count=486; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return this.__defineSetter__(\"y\", decodeURIComponent); }); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1.5), function(){}, new Number(1.5), function(){}, function(){}, function(){}, new Number(1.5), function(){}, new Number(1.5), function(){}, function(){}, function(){}, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), function(){}, new Number(1.5), function(){}, function(){}, new Number(1.5)]); ");
/*fuzzSeed-28551573*/count=487; tryItOut("\"use strict\"; t2 + '';");
/*fuzzSeed-28551573*/count=488; tryItOut("\"use strict\"; for(z in ((Array.prototype.slice)(this)))z = z, z = (/*FARR*/[].map), w = eval, b, [] = Math.max(new RegExp(\"(?!(?:(.){3}|[^]\\\\W))(?=(.)\\\\B)\", \"m\"), -9), z, tplqyp, w = new RegExp(\"\\\\2\", \"gm\"), y, z;a0.reverse();");
/*fuzzSeed-28551573*/count=489; tryItOut("/*bLoop*/for (zkmoni = 0; zkmoni < 24; ++zkmoni) { if (zkmoni % 3 == 1) { v1 = g0.eval(\"s0 += s1\\nprint(x);\"); } else { h1.defineProperty = (function() { for (var j=0;j<10;++j) { f2(j%5==0); } }); }  } ");
/*fuzzSeed-28551573*/count=490; tryItOut("v1 = (e1 instanceof o2);");
/*fuzzSeed-28551573*/count=491; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=492; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return +((+(0x1100108b)));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0.000000000000001, 0x080000001, 42, -Number.MAX_VALUE, 1, 2**53+2, -(2**53-2), 0x0ffffffff, -0, -0x07fffffff, -0x100000000, Math.PI, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000001, 0x100000001, 0x080000000, 2**53-2, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, 0, 0x07fffffff, -(2**53), 0/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=493; tryItOut("mathy3 = (function(x, y) { return (Math.fround(Math.round(((Math.imul(( + y), Math.fround(Math.min((Math.imul(Math.fround(( - ( - (-Number.MIN_VALUE | 0)))), (Math.atan((x >>> 0)) >>> 0)) | 0), ((Math.acosh((y >>> 0)) >>> 0) | 0)))) >>> 0) >>> 0))) !== ( ! ((( ~ ( ~ y)) >>> 0) >>> 0))); }); testMathyFunction(mathy3, [2**53-2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, -1/0, 0, 0x100000001, -Number.MIN_VALUE, -(2**53), 0x080000000, 0x07fffffff, 42, 1, Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), Math.PI, 1/0, -0x0ffffffff, -(2**53-2), 2**53+2, 0x080000001, -0, -0x100000001]); ");
/*fuzzSeed-28551573*/count=494; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53+2), 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0, 1/0, 1.7976931348623157e308, 0, -(2**53), 0.000000000000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 0/0, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, 0x07fffffff, -0x100000001, 2**53, Number.MAX_VALUE, Math.PI, -0x080000000, -Number.MAX_VALUE, 0x0ffffffff, 42, 0x100000000, -0x100000000, -0x080000001, Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-28551573*/count=495; tryItOut("do {/*RXUB*/var r = r0; var s = \"\"; print(r.exec(s)); print(r.lastIndex);  }\n while((this) && 0);");
/*fuzzSeed-28551573*/count=496; tryItOut("x = timeout(1800), x =  '' , z = (({x: Math.pow(a, -3075763326)})), d =  /x/ , acgxfq;print(x);");
/*fuzzSeed-28551573*/count=497; tryItOut("testMathyFunction(mathy2, /*MARR*/[new String(''), new String(''), -Number.MAX_VALUE, objectEmulatingUndefined(), new String(''), null, objectEmulatingUndefined(), -Number.MAX_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MAX_VALUE, null, null]); ");
/*fuzzSeed-28551573*/count=498; tryItOut("\"use strict\"; var eisswn = new SharedArrayBuffer(0); var eisswn_0 = new Uint8ClampedArray(eisswn); eisswn_0[0] = 8; var eisswn_1 = new Int8Array(eisswn); var eisswn_2 = new Uint16Array(eisswn); eisswn_2[0] = -24; h0 = {};");
/*fuzzSeed-28551573*/count=499; tryItOut("\"use strict\"; /*RXUB*/var r = g1.r1; var s = \"\\u000b\"; print(s.search(r)); ");
/*fuzzSeed-28551573*/count=500; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.sin((Math.min(y, (Math.expm1(x) < (Math.acos((y >>> 0)) >>> 0))) >> ( ! Math.atan2(( ! (Math.cosh((y | 0)) | 0)), ((((( - (( + (( + y) - x)) >>> 0)) >>> 0) | 0) & (0/0 >>> 0)) | 0))))); }); testMathyFunction(mathy5, [0x080000000, Number.MIN_VALUE, 0, -0x080000000, -0x100000000, 1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 0x100000001, -1/0, Math.PI, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, 2**53, 2**53+2, 1, 0.000000000000001, 42, 1.7976931348623157e308, 0x100000000, 2**53-2, -Number.MAX_VALUE, -0, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=501; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=502; tryItOut("\"use asm\"; g1.v0 = t0.length;");
/*fuzzSeed-28551573*/count=503; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ~ Math.ceil((Math.max((((( + mathy0(( + x), ( + Math.cosh((y | 0))))) >>> 0) ? (x >>> 0) : (( + Math.cosh(Math.fround(((x | 0) | x)))) >>> 0)) >>> 0), ((( + Math.fround((2**53-2 * y))) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [-(2**53-2), 2**53, -(2**53), 0x080000001, -Number.MIN_VALUE, 1, -1/0, Number.MIN_VALUE, 0/0, Math.PI, -0x080000001, 0.000000000000001, -0x100000000, -0x0ffffffff, 0x07fffffff, -0x080000000, -(2**53+2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, 42, 1.7976931348623157e308, -0, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2]); ");
/*fuzzSeed-28551573*/count=504; tryItOut("mathy2 = (function(x, y) { return ( + ( - ( + Math.fround(( + ( ~ Math.fround(y))))))); }); ");
/*fuzzSeed-28551573*/count=505; tryItOut("for (var v of e2) { try { m1.has(v0); } catch(e0) { } try { g1.s1 = new String(m1); } catch(e1) { } try { a2 + ''; } catch(e2) { } Array.prototype.sort.apply(a0, [f1, g1, o0.o1.p1, s2]); }");
/*fuzzSeed-28551573*/count=506; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return +(((2147483647.0) + (2.0)));\n  }\n  return f;((4277));\n })(this, {ff: (function\u0009  \u3056 (w, eval, c, c, x, c = new RegExp(\"[\\u42d7\\\\cX-\\\\u0073]?\", \"gym\"), x, window, x) { \"use strict\"; this.v1 = r1.exec; } ).bind((4277), x)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 0x100000001, -0x07fffffff, -(2**53-2), -0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 42, 1/0, 2**53, -0, Math.PI, 0.000000000000001, 0, 0/0, 1, 1.7976931348623157e308, -1/0, 0x080000000, -(2**53+2), 0x100000000, -(2**53), Number.MAX_VALUE, 0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 2**53+2, -0x100000001, 0x07fffffff]); ");
/*fuzzSeed-28551573*/count=507; tryItOut("x <<= z;");
/*fuzzSeed-28551573*/count=508; tryItOut("var koxjjs = new ArrayBuffer(16); var koxjjs_0 = new Float64Array(koxjjs); print(koxjjs_0[0]); koxjjs_0[0] = -2199023255551; var koxjjs_1 = new Float64Array(koxjjs); koxjjs_1[0] = 16; var koxjjs_2 = new Int16Array(koxjjs); koxjjs_2[0] = 9; var koxjjs_3 = new Int16Array(koxjjs); koxjjs_3[0] = -18; var koxjjs_4 = new Float64Array(koxjjs); koxjjs_4[0] = 18; var koxjjs_5 = new Int8Array(koxjjs); print(koxjjs_5[0]); var koxjjs_6 = new Float32Array(koxjjs); koxjjs_6[0] = -8; var koxjjs_7 = new Uint16Array(koxjjs); koxjjs_7[0] = -15; var koxjjs_8 = new Int32Array(koxjjs); print(koxjjs_8[0]); koxjjs_8[0] = -9; /*oLoop*/for (let fmuhwd = 0,  '' ; fmuhwd < 78; ++fmuhwd) { this.a0[18] = e0; } v2 = a1.length;;a1.unshift(g0, this.a1);v0 = Object.prototype.isPrototypeOf.call(v0, a2);v1 = a0.length;const e = koxjjs_4[0], koxjjs_0[10], koxjjs_0[0] = koxjjs_4, [] = \"\\u236A\", taynav;for (var p in i1) { try { let t1 = new Float32Array(t1); } catch(e0) { } o0.i2.next(); }");
/*fuzzSeed-28551573*/count=509; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.asin(((Math.imul(y, Math.atan2((x ? ( + -1/0) : y), Math.fround(y))) << ((y ? (-(2**53-2) >>> 0) : (mathy1((Math.fround(Math.imul((( + -0x07fffffff) ? ( + y) : x), (y >>> 0))) | 0), Math.fround(Math.atan2(Math.fround(y), (y >>> 0)))) >>> 0)) >>> 0)) ? Math.fround(Math.fround(Math.hypot(Math.fround((Math.sqrt((Math.min(x, (Math.pow((y >>> 0), (Math.log2(Math.fround(y)) >>> 0)) >>> 0)) >>> 0)) >>> 0)), Math.fround(Math.atan2(y, x))))) : ( + ( ! ( + Math.expm1(((Math.acos(Math.fround(x)) >>> 0) >>> 0))))))); }); ");
/*fuzzSeed-28551573*/count=510; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - ( ~ (mathy1(mathy0(Math.hypot(0x0ffffffff, y), -(2**53)), y) >>> 0))) ** (Math.cos(Math.fround(( ~ Math.fround(Math.min(((( + x) >= (y == (y >>> 0))) | 0), x))))) , mathy1((Math.max(( + (-0x080000001 ^ x)), x) ? ( + Math.atan2(( + x), x)) : (y || Math.max(Number.MAX_SAFE_INTEGER, 0/0))), Math.hypot((( + x) % (x >>> 0)), 1.7976931348623157e308)))); }); testMathyFunction(mathy5, [0/0, -0, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -1/0, -0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, 0x100000000, -Number.MAX_VALUE, -(2**53), Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 0, -0x080000000, Number.MIN_VALUE, -0x080000001, 42, -0x07fffffff, 2**53+2, -0x100000000, 0x080000000, 1.7976931348623157e308, 1]); ");
/*fuzzSeed-28551573*/count=511; tryItOut("/*oLoop*/for (let tsdkkl = 0; tsdkkl < 56; ++tsdkkl) { print(-12); } ");
/*fuzzSeed-28551573*/count=512; tryItOut("var r0 = x ^ x; var r1 = 0 * x; var r2 = r1 ^ x; var r3 = r0 | 6; var r4 = x * r2; var r5 = r1 ^ r1; var r6 = r1 * r4; var r7 = r3 % x; r0 = r0 ^ 7; var r8 = r4 + r5; print(r7); var r9 = 2 % r5; var r10 = x | r1; var r11 = r10 ^ r7; var r12 = r1 ^ 8; var r13 = r2 ^ r8; var r14 = 1 * 6; var r15 = r14 * r10; var r16 = 4 - 6; var r17 = x + r7; var r18 = r8 ^ r11; var r19 = r4 % 3; r3 = r12 * r1; var r20 = r15 & 9; var r21 = r3 * r20; var r22 = r13 * r4; var r23 = r3 ^ 1; var r24 = r20 / r1; r16 = 9 ^ 6; r19 = r6 + r7; var r25 = r9 * 5; r17 = 3 * r20; var r26 = r7 % r10; print(r9); r12 = r22 % r5; var r27 = 1 & r12; var r28 = r21 ^ r22; var r29 = r16 % 1; r10 = r22 ^ r13; var r30 = r29 + 1; var r31 = r3 / r29; var r32 = 1 | r17; var r33 = r13 * 6; var r34 = r2 * 7; var r35 = 0 & r27; r15 = r15 % 6; var r36 = r2 / r18; var r37 = r29 % r32; var r38 = r31 % 7; r17 = r17 ^ r22; var r39 = r4 & 4; var r40 = r26 % r10; var r41 = r5 & 2; var r42 = r18 % r8; var r43 = r1 | r29; var r44 = 2 + 0; r27 = r40 | r6; var r45 = r42 % r26; var r46 = r1 & 4; var r47 = r26 * r23; r15 = r15 + r46; var r48 = 8 & 9; r7 = r45 ^ r46; var r49 = 2 * r28; var r50 = r44 & r48; var r51 = r45 / r42; r32 = 3 - r47; var r52 = 8 + 1; var r53 = r7 ^ 8; var r54 = r19 - r50; r53 = r12 % 0; var r55 = r22 - r32; print(r29); var r56 = r30 - r48; r12 = r49 - 7; var r57 = r45 - 8; var r58 = r16 - 3; var r59 = r18 ^ r41; r58 = r10 | 7; var r60 = 9 * 4; var r61 = r44 - r11; var r62 = r0 & r16; var r63 = 1 * 8; var r64 = 9 * 9; var r65 = 5 - 2; var r66 = 0 * x; r25 = 0 | 0; var r67 = r56 / r1; var r68 = r61 + r62; var r69 = 7 | r59; var r70 = r16 - r8; r5 = 4 * r26; r0 = 6 ^ r67; print(r27); var r71 = r26 - r19; var r72 = r32 | r2; r14 = r18 % r69; r10 = 5 - r50; var r73 = r33 + r34; var r74 = r11 | r51; var r75 = r8 & 7; var r76 = r2 | 6; var r77 = 8 % 7; var r78 = r48 % r23; var r79 = 7 - r77; var r80 = r15 - 7; var r81 = r79 ^ 4; var r82 = r24 % r73; var r83 = r71 ^ r40; r34 = r17 & 0; var r84 = 4 + 2; r31 = r8 - 7; print(r41); var r85 = r16 ^ r25; var r86 = r56 ^ r65; var r87 = r19 / r19; var r88 = r86 & 1; var r89 = r61 ^ 4; var r90 = r55 * r25; var r91 = r55 & r57; print(r72); var r92 = 8 / r20; var r93 = r66 % 3; var r94 = r11 % 9; var r95 = 1 / 5; var r96 = 4 ^ r42; var r97 = r35 / r11; var r98 = r85 / r70; var r99 = 5 | 7; var r100 = r87 | 0; var r101 = 1 + r48; var r102 = r60 & 5; var r103 = r25 % 9; var r104 = r64 & 7; var r105 = r77 - 5; var r106 = r36 / 3; r34 = 2 % r95; var r107 = r5 & r24; var r108 = r104 % r91; var r109 = r71 & r89; var r110 = r81 | r93; r89 = 9 & 2; var r111 = 9 % 8; var r112 = 0 + r78; var r113 = r57 - 3; var r114 = r63 * r82; var r115 = 6 - r1; var r116 = 3 + r18; var r117 = r84 % r90; r15 = r117 - 1; var r118 = r80 & r110; var r119 = r78 - 4; var r120 = r88 + 8; print(r62); var r121 = 9 - r74; r97 = r52 & 9; var r122 = r39 - r73; r78 = r106 ^ 4; var r123 = 3 - r65; r10 = 2 & r109; var r124 = r77 ^ r96; var r125 = r62 ^ r61; var r126 = r107 * 4; var r127 = 2 * r74; var r128 = r49 * r108; r13 = r54 ^ 4; var r129 = r82 ^ r78; var r130 = r9 | r65; var r131 = 0 & r17; var r132 = r90 | r15; var r133 = 6 + r62; r84 = 8 / r105; var r134 = 9 + r123; r28 = 1 | 2; var r135 = 8 - r11; r12 = r93 + r34; var r136 = 4 / r38; var r137 = r78 % r105; var r138 = r15 / 3; var r139 = r47 ^ r130; var r140 = r3 % 2; var r141 = 2 + r48; var r142 = r47 * 2; print(r86); print(r80); var r143 = r83 % r85; var r144 = 5 / 1; r71 = r134 | r80; var r145 = r103 * r131; var r146 = r118 % 5; r137 = r71 - r23; var r147 = 1 ^ r9; var r148 = r70 + r29; var r149 = r73 - 9; var r150 = 7 & r52; var r151 = r66 / r98; r112 = r12 - r122; print(r126); print(r58); var r152 = r142 | r124; var r153 = r40 + 6; var r154 = r67 / 8; var r155 = r18 % r114; var r156 = 7 - 0; var r157 = r88 - r123; var r158 = r30 & r68; r145 = r79 / 3; var r159 = r114 / 6; r137 = r106 % r10; r20 = r145 / r133; var r160 = r151 * 5; r123 = r5 / r12; var r161 = r69 & r127; var r162 = 1 / r60; var r163 = r88 + r140; var r164 = r40 + r26; var r165 = r131 * r103; var r166 = r117 + r129; print(r136); var r167 = r152 - 3; var r168 = r29 & r119; var r169 = 8 % 4; var r170 = r54 % r24; var r171 = 3 / r94; r55 = 4 & r26; print(r129); var r172 = r32 * r51; var r173 = r99 & r26; var r174 = 0 - r15; var r175 = 1 + 1; r165 = 1 - r154; print(r97); var r176 = r79 ^ r26; var r177 = r105 & r122; ");
/*fuzzSeed-28551573*/count=513; tryItOut("testMathyFunction(mathy1, [0, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, 0.000000000000001, 0x0ffffffff, -0x0ffffffff, Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 42, 0x100000000, -Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, 2**53+2, -0x07fffffff, Number.MIN_VALUE, 0x080000000, -(2**53-2), 2**53, -0x080000000, -0, -Number.MIN_VALUE, 1/0, 1, 2**53-2, -0x100000000, 1.7976931348623157e308, -0x100000001, -(2**53+2)]); ");
/*fuzzSeed-28551573*/count=514; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-28551573*/count=515; tryItOut("testMathyFunction(mathy4, /*MARR*/[arguments.caller, 0x100000000, true, ( ''  = window)\n, arguments.caller, true, ( ''  = window)\n, arguments.caller, ( ''  = window)\n, 0x100000000, 0x100000000, 0x100000000, arguments.caller, arguments.caller, arguments.caller, arguments.caller, true, 0x100000000, true, true, ( ''  = window)\n, 0x100000000, 0x100000000, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, 0x100000000, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, 0x100000000, ( ''  = window)\n, true, true, ( ''  = window)\n, true, true, true, true, true, true, true, true, true, true, 0x100000000, ( ''  = window)\n, true, ( ''  = window)\n, arguments.caller, arguments.caller, true, true, ( ''  = window)\n, ( ''  = window)\n, ( ''  = window)\n, ( ''  = window)\n, true, 0x100000000, ( ''  = window)\n, true, 0x100000000, 0x100000000, ( ''  = window)\n, ( ''  = window)\n, ( ''  = window)\n, ( ''  = window)\n, 0x100000000, 0x100000000, ( ''  = window)\n, ( ''  = window)\n, ( ''  = window)\n, arguments.caller, 0x100000000, ( ''  = window)\n, 0x100000000, ( ''  = window)\n, arguments.caller, ( ''  = window)\n, arguments.caller, 0x100000000, 0x100000000, true, 0x100000000, true, true, 0x100000000, ( ''  = window)\n, ( ''  = window)\n, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, arguments.caller, 0x100000000, 0x100000000, true, arguments.caller, arguments.caller, true, 0x100000000, 0x100000000, 0x100000000, arguments.caller, true, 0x100000000, 0x100000000, arguments.caller, arguments.caller, true, 0x100000000, true, ( ''  = window)\n, 0x100000000, ( ''  = window)\n, arguments.caller, 0x100000000, ( ''  = window)\n, 0x100000000, ( ''  = window)\n, ( ''  = window)\n, true, ( ''  = window)\n, ( ''  = window)\n, 0x100000000, arguments.caller, true, 0x100000000, arguments.caller, true, 0x100000000, arguments.caller, true, ( ''  = window)\n, ( ''  = window)\n, arguments.caller, 0x100000000, 0x100000000, 0x100000000, true, 0x100000000, arguments.caller]); ");
/*fuzzSeed-28551573*/count=516; tryItOut("m2 = new WeakMap;");
/*fuzzSeed-28551573*/count=517; tryItOut("\"use strict\";  for  each(let z in (Math.log2(21))) Array.prototype.push.call(a2, \ntrue,  /x/  && window);");
/*fuzzSeed-28551573*/count=518; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.asinh(Math.fround(Math.acos(( ! (Math.ceil(( + (y | 0))) >>> 0))))); }); ");
/*fuzzSeed-28551573*/count=519; tryItOut("g2.a2.sort(o0, p0, o0, h0, new Set(), b0);");
/*fuzzSeed-28551573*/count=520; tryItOut("/*oLoop*/for (let osvjia = 0; osvjia < 27; ++osvjia) { this.v1.__proto__ = m2; } ");
/*fuzzSeed-28551573*/count=521; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((Math.fround(( - Math.fround(( + (Math.acos((mathy0(Math.fround(x), (( - x) >>> 0)) >>> 0)) >>> 0))))) * Math.fround(Math.cos(Math.fround((Math.max((Math.pow((y >>> 0), Math.fround(x)) >>> 0), (x | 0)) | 0)))))); }); testMathyFunction(mathy2, [2**53, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -0x0ffffffff, 0x07fffffff, 2**53+2, 42, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 0x100000001, 0x100000000, 0/0, 0x080000000, -0x080000000, 0.000000000000001, 1.7976931348623157e308, -0x100000001, Number.MAX_VALUE, -1/0, -0x07fffffff, -0, 0x080000001, 0, 2**53-2, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 1]); ");
/*fuzzSeed-28551573*/count=522; tryItOut("var e = d;e1.add(g2);");
/*fuzzSeed-28551573*/count=523; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.pow(Math.fround(( - (((Math.imul(((y ? (Math.hypot(x, Number.MAX_SAFE_INTEGER) >>> 0) : ( + y)) >>> 0), y) >>> 0) ? (y >>> 0) : ((y <= ( + -Number.MIN_SAFE_INTEGER)) >>> 0)) >>> 0))), ( + ( ~ Math.min((( + x) == ( + x)), (Math.imul((1.7976931348623157e308 | 0), (x | 0)) | 0)))))); }); ");
/*fuzzSeed-28551573*/count=524; tryItOut("g0.r2 = /(?:(?!^.+|\\w+))*/gyi;");
/*fuzzSeed-28551573*/count=525; tryItOut("print(x);");
/*fuzzSeed-28551573*/count=526; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.asin(Math.fround(( + Math.imul(Math.hypot(Math.expm1(y), ( ! ( + Math.ceil(( + x))))), (((( + ( ! Math.fround(Math.sqrt(-0x080000001)))) >>> 0) ^ (((( + (-Number.MAX_VALUE << ( + Math.cbrt((x >>> 0))))) >>> 0) ? mathy3(x, x) : ( ! (y >>> 0))) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-28551573*/count=527; tryItOut("/*RXUB*/var r = new RegExp(\"(?=[^]+?)|[^][^\\\\u00EF\\\\x1d-\\\\ua87F\\\\b-\\\\\\u00a3\\\\v-\\\\u5065]{524289,524289}|([^]){3,4}{2}{0,1}\", \"gy\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-28551573*/count=528; tryItOut("h2.get = (function() { for (var j=0;j<96;++j) { f0(j%4==1); } });");
/*fuzzSeed-28551573*/count=529; tryItOut("if(false) {/*MXX3*/g2.DataView.BYTES_PER_ELEMENT = g2.DataView.BYTES_PER_ELEMENT;{} } else ( /x/g );");
/*fuzzSeed-28551573*/count=530; tryItOut("f2 = Proxy.createFunction(h0, f0, f0);");
/*fuzzSeed-28551573*/count=531; tryItOut("\"use strict\"; m1.delete(e2);");
/*fuzzSeed-28551573*/count=532; tryItOut("var x =  '' ;print(x);");
/*fuzzSeed-28551573*/count=533; tryItOut("/*infloop*/for((encodeURI()); ({}) >> \"\\u72B2\"; (/*MARR*/[({}), (0/0),  /x/g , 0/0,  /x/g , ({}), (0/0), (0/0), 0/0, ({}), (0/0), ({}), 0/0, 0/0, 0/0, ({}), 0/0,  /x/g , 0/0, 0/0, (0/0), 0/0, (0/0), 0/0, ({}), 0/0, (0/0), (0/0), ({}), 0/0,  /x/g , ({}), 0/0, 0/0, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), 0/0, (0/0), 0/0,  /x/g ].filter(decodeURIComponent, window))) {print((w = Proxy.create(({/*TOODEEP*/})(20),  \"\" ))); }\nv0 = 4.2;\n");
/*fuzzSeed-28551573*/count=534; tryItOut("var {x, \u3056: x, y: {x, d: z, a: {c: {y: y, a, c, b: {x, d: {}, eval: this.b}}, \u3056: z}, x, y: [], x: y}, z, x: [{x: x, x: Object.defineProperty(x, \"1\", ({get: decodeURI, set: Date.UTC, configurable: false})).b\u0009, z, this.x: []}, , , , {x, x: x, y: this, x, \u3056}, [y]], x, x} = (4277), c = x >> Object.defineProperty(x, -1, ({get: arguments.callee.caller}));v1 = g1.eval(\"(Math.sign(true == true))\");e2.delete(s0);");
/*fuzzSeed-28551573*/count=535; tryItOut("\"use strict\"; e2.delete((void options('strict_mode')));");
/*fuzzSeed-28551573*/count=536; tryItOut("mathy3 = (function(x, y) { return ( + ( - ( + (Math.imul((( + Math.imul(((Math.exp(x) - Math.fround((y * Math.fround(x)))) >>> 0), (Math.fround(Math.hypot(Math.fround(Math.pow(Math.atan2(y, (x >>> 0)), (1.7976931348623157e308 | 0))), Math.fround(x))) >>> 0))) | 0), (( + ((( + Math.fround(mathy0(Math.fround((Math.clz32((y >>> 0)) >>> 0)), Math.fround((( + (x >>> 0)) >>> 0))))) ** ( + y)) | 0)) >>> 0)) | 0)))); }); testMathyFunction(mathy3, /*MARR*/[new String('q'), new String('q'), arguments.caller, new String('q'), arguments.caller, arguments.caller, new String('q'), new String('q'), arguments.caller, arguments.caller, new String('q'), new String('q'), arguments.caller, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), arguments.caller, arguments.caller, arguments.caller, arguments.caller, new String('q'), new String('q'), new String('q'), arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, new String('q'), arguments.caller, arguments.caller, arguments.caller, arguments.caller]); ");
/*fuzzSeed-28551573*/count=537; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-28551573*/count=538; tryItOut("((encodeURIComponent).call(/*FARR*/[], this));");
/*fuzzSeed-28551573*/count=539; tryItOut("/*ADP-2*/Object.defineProperty(a0, {}, { configurable: (x % 8 != 4), enumerable: (x % 12 != 8), get: (function(j) { if (j) { try { this.g2.offThreadCompileScript(\"function this.f0(o2)  { yield length } \"); } catch(e0) { } try { h2 + ''; } catch(e1) { } try { e1 = new Set(o0); } catch(e2) { } o1.a1 = r2.exec(s2); } else { try { delete h2.getOwnPropertyDescriptor; } catch(e0) { } try { for (var v of a0) { /*MXX3*/g1.Math.atanh = g0.Math.atanh; } } catch(e1) { } /*MXX1*/o2 = g0.Date.prototype.setUTCSeconds; } }), set: f0 });\nconst d, x = print( \"\" ), \u3056 = \"\\u23F5\", dcqamq, gmlyon, c, nyqztd;a1.shift();\n");
/*fuzzSeed-28551573*/count=540; tryItOut("g0.a1.forEach(s2);");
/*fuzzSeed-28551573*/count=541; tryItOut("\"use strict\"; t0.set(o2.a0, Math.max(((((( + (Math.atan2((Math.clz32((Math.hypot(x, (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)) >>> 0), Math.pow(x, ( + ( ! x)))) >>> 0)) ? ( + Math.imul(( + Math.asinh(( + Math.expm1(x)))), ( + (( + ((x | 0) ** ( + Math.imul(0x100000000, -1/0)))) | ( + Math.acosh(x)))))) : ((( + Math.max(Math.fround((x || Math.fround(( + Math.cbrt(x))))), -Number.MIN_VALUE)) === (Math.max(x, Math.fround(0.000000000000001)) | 0)) >>> 0)) | 0) ? (Math.fround(( ! Math.fround((Math.ceil(( + (( ~ ( ! (( - (x | 0)) | 0))) && ( + (x <= Math.fround(( + ((x >>> 0) ? (Math.fround(Math.min(x, (x | 0))) >>> 0) : (-1/0 >>> 0))))))))) >>> 0)))) | 0) : (Math.tanh(Math.fround((( + (( ~ (Math.round(((Math.hypot((x >>> 0), (Math.sin((x | 0)) | 0)) | 0) | 0)) | 0)) * Math.pow((((((0x0ffffffff ^ x) >>> 0) <= (x >>> 0)) >>> 0) | 0), Math.fround((Math.pow(Math.fround(( ~ (x >>> 0))), Math.tan(x)) - Math.exp(x)))))) > Math.fround((((x >>> 0) ? (Math.min(Math.cosh(Math.fround(( - Number.MIN_SAFE_INTEGER))), x) | 0) : (Math.atanh(x) >>> 0)) >>> 0))))) | 0)) >>> 0), (Math.imul((( ! (Math.cosh((Math.fround((x && Math.fround(( - Math.fround(Math.trunc((x >= x))))))) != Math.log(Math.fround(x)))) | 0)) | 0), (Math.atan2(((Math.cbrt(Math.tan(x)) >>> 0) * ( + Math.atan(Math.fround((Math.fround(Math.fround(Math.pow(x, Math.fround(( - x))))) ? Math.fround(Math.abs(( + x))) : Math.fround(x)))))), ( + ( ! ( + Math.atanh((( ~ (x | 0)) | 0)))))) | 0)) | 0)));(x);");
/*fuzzSeed-28551573*/count=542; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var cos = stdlib.Math.cos;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (i1);\n    (Float32ArrayView[1]) = ((+cos(((+(-1.0/0.0))))));\n    i0 = (0xffffffff);\n    return +((1.1805916207174113e+21));\n  }\n  return f; })(this, {ff: Date.prototype.getUTCSeconds}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, -0, Number.MAX_VALUE, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 2**53, -0x0ffffffff, 0, -(2**53-2), Number.MIN_VALUE, -(2**53+2), -0x080000000, 0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, -0x100000000, 0/0, 0x100000001, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 1/0, -(2**53), 2**53+2, -0x07fffffff, -0x080000001]); ");
/*fuzzSeed-28551573*/count=543; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a0, [(function mcc_() { var vxwogh = 0; return function() { ++vxwogh; if (/*ICCD*/vxwogh % 11 == 4) { dumpln('hit!'); try { h0.iterate = (function() { try { g0.s0 += s0; } catch(e0) { } Array.prototype.sort.apply(a2, [i0, v0]); return a2; }); } catch(e0) { } this.v0 = t0.byteLength; } else { dumpln('miss!'); /*RXUB*/var r = /(?:\\1{274877906945,274877906949})|(?!(?=\\1{2})|(?:\\b))|((\\1))(?=(\\u00b9)[^A-\u9e07\\s\\w\\\u8f2a]?)|(?=(?:(?![^\\n-\\ub2cb\\d\\S]).*{2,2}|^|[^][\\x6A-\\u00Eb]+))/y; var s = \"\\ud522\\u00eb\\u00eb\\u00eb\\u00eb\\u00eb\\u00eb\"; print(uneval(s.match(r))); print(r.lastIndex);  } };})()]);");
/*fuzzSeed-28551573*/count=544; tryItOut("t1 = new Int16Array(g0.o0.b2, 88, 9);");
/*fuzzSeed-28551573*/count=545; tryItOut("s0 += o2.s1;\na0.forEach((function() { try { this.o0.t0[15] = null; } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { b0 = new ArrayBuffer(2); } catch(e2) { } i0 = new Iterator(g1.g1.a2); throw f0; }), a0);\n");
/*fuzzSeed-28551573*/count=546; tryItOut("a1 = Array.prototype.map.call(a0, (function(j) { if (j) { try { v2 = this.g0.g1.runOffThreadScript(); } catch(e0) { } try { v2 = b0.byteLength; } catch(e1) { } try { selectforgc(o2); } catch(e2) { } /*RXUB*/var r = r2; var s = \"\\n\\n\\n\\n\\n\\n\"; print(s.split(r));  } else { try { this.s2 += s2; } catch(e0) { } try { ; } catch(e1) { } v0 = evalcx(\"((void options('strict_mode')))\", g0); } }), m0);");
/*fuzzSeed-28551573*/count=547; tryItOut("/*bLoop*/for (ydgtzk = 0; ydgtzk < 116; ++ydgtzk) { if (ydgtzk % 67 == 23) { Array.prototype.reverse.call(o1.a2, p1, v1, p1); } else { undefined; }  } i0 = new Iterator(h2);");
/*fuzzSeed-28551573*/count=548; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy3(Math.fround(Math.atan2(((( + y) >>> Math.expm1(x)) % mathy1((x >>> 0), ( + 2**53+2))), Math.cbrt(( + (mathy0((((( - (x >>> 0)) >>> 0) ? y : ((0 | 0) * (y | 0))) | 0), (x | 0)) | 0))))), ( - (Math.min(Math.fround(( ! x)), Math.fround(Math.round(Math.fround(Math.fround(Math.atan(Math.hypot(Math.PI, Math.acos(x)))))))) | 0))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, 2**53+2, 0x080000001, 0x0ffffffff, -(2**53+2), 1/0, 0.000000000000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, 1.7976931348623157e308, 42, Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, -0, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, 0x080000000, Math.PI, -0x080000001, -0x0ffffffff, 0x100000000, -(2**53), 0/0, -0x080000000]); ");
/*fuzzSeed-28551573*/count=549; tryItOut("t2[x];");
/*fuzzSeed-28551573*/count=550; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul(Math.fround(( + Math.fround(( ! Math.hypot(Math.hypot(0x07fffffff, x), -(2**53+2)))))), ((((( + 0x07fffffff) !== ( + y)) >>> 0) > Math.PI) & Math.expm1((x >>> 0)))); }); testMathyFunction(mathy0, [1/0, -0x0ffffffff, 2**53-2, 2**53+2, 2**53, 0, -Number.MAX_VALUE, 0/0, -0x07fffffff, 1, 0x100000000, 0x100000001, -0x080000001, Number.MIN_VALUE, 42, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, 0.000000000000001, -0, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, 0x080000000, -Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, -0x100000000, 0x080000001]); ");
/*fuzzSeed-28551573*/count=551; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      (Float64ArrayView[0]) = ((2.4178516392292583e+24));\n    }\n    (Float64ArrayView[((((((-1.125) != (8589934592.0))+(-0x8000000))|0) > (~~(d0)))) >> 3]) = ((+(0x0)));\n    i1 = (((((+(1.0/0.0))) % ((((((-1073741824.0)) % ((524289.0)))) / ((9223372036854776000.0))))) >= (((d0)) % ((((+((-137438953473.0)))) / ((d0)))))) ? (i1) : (0xfea3199e));\n    (Uint16ArrayView[1]) = ((i1)+((((4095.0)) / ((((1125899906842625.0)) - ((d0))))) > (+(0xf992aef))));\n    i1 = ((0xffffffff));\n    i1 = (0x834716d1);\n    d0 = (d0);\n    i1 = (0xfb5e318c);\n    i1 = ((0xb5222bce) ? (-0x8000000) : (!((0xffffffff))));\n    i1 = (0xa7e5e59a);\n    return +((d0));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0, -Number.MAX_VALUE, 42, 0x07fffffff, -0, 2**53-2, -0x100000001, 2**53, -0x100000000, 1/0, -1/0, -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, Math.PI, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, -0x080000000, -0x07fffffff, 0.000000000000001, 1, 0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=552; tryItOut("urjcen();/*hhh*/function urjcen(w, b = w = new RegExp(\"\\u2381\", \"\"), x, d, x, eval, eval, x, x, x, \u3056, window, a, window = undefined, d =  \"\" , z, x, d, x, \u3056 = \"\\u9179\", w, x){m2.delete((new RegExp(\"(?![\\\\S]*)\", \"im\") |  '' ));}");
/*fuzzSeed-28551573*/count=553; tryItOut("\"use strict\"; print(i1);");
/*fuzzSeed-28551573*/count=554; tryItOut("print(h2);");
/*fuzzSeed-28551573*/count=555; tryItOut("f0 = g1.t1[12];");
/*fuzzSeed-28551573*/count=556; tryItOut("v2 = undefined;");
/*fuzzSeed-28551573*/count=557; tryItOut("\"use strict\"; if(true) (delete); else  if (x) {t0 = new Int32Array(t1);print(x); } else /(?!(\\S)+)/y;");
/*fuzzSeed-28551573*/count=558; tryItOut("testMathyFunction(mathy4, [-Number.MIN_VALUE, 0x080000001, -(2**53+2), -1/0, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff, -0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, -0x080000000, -0x080000001, -(2**53-2), Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 0x0ffffffff, -0, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 42, 0, -Number.MAX_VALUE, -0x07fffffff, 0/0, 2**53-2, 1/0, Math.PI, 0x080000000, 0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=559; tryItOut("/*infloop*/do {p1 = m1.get(g2); } while(x = ({a2:z2}));");
/*fuzzSeed-28551573*/count=560; tryItOut("\"use strict\"; v2 = evaluate(\"m2 = g2.objectEmulatingUndefined();\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 2 == 0), sourceIsLazy: true, catchTermination:  /x/g  }));");
/*fuzzSeed-28551573*/count=561; tryItOut("\"use strict\"; /*bLoop*/for (var uooiro = 0; uooiro < 34; ++uooiro) { if (uooiro % 6 == 3) { let (w) { return (void version(170)); } } else { e0 = g0.t0[4]; }  } ");
/*fuzzSeed-28551573*/count=562; tryItOut("mathy3 = (function(x, y) { return ( - Math.atan2(Math.fround(Math.ceil(x)), (((( ~ Math.cos(( + Math.min(( + x), (x | 0))))) >>> 0) >>> ( + Math.exp(Number.MAX_SAFE_INTEGER))) >>> 0))); }); ");
/*fuzzSeed-28551573*/count=563; tryItOut("\"use strict\"; /*infloop*/for(let d = {} = (makeFinalizeObserver('nursery')); (void shapeOf((4277))); Math.pow(new (/*UUV2*/(x.setUTCDate = x.values))((x || window)), (this.zzz.zzz) = new (new Function)(new RegExp(\"[^\\\\u0078\\\\u00de-\\u27dc\\\\W\\\\x49]+?\\\\W\", \"i\")))) {this.e0.add(g1);{ void 0; abortgc(); } }");
/*fuzzSeed-28551573*/count=564; tryItOut("this.v2 = a1.length;");
/*fuzzSeed-28551573*/count=565; tryItOut("Array.prototype.push.call(a1, p2, p1, g2, o2, e0, t1, e2, f1);");
/*fuzzSeed-28551573*/count=566; tryItOut("this.g0.o0.toString = (function() { a2 = a1.slice(9, NaN); return h2; });");
/*fuzzSeed-28551573*/count=567; tryItOut("\"use strict\"; i0 = new Iterator(p0);");
/*fuzzSeed-28551573*/count=568; tryItOut("/*infloop*/for(var new (x)() in (()(x))){/*MXX1*/o1 = g2.String.prototype.match; }");
/*fuzzSeed-28551573*/count=569; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! Math.hypot((( ! (((x | 0) / (Number.MIN_SAFE_INTEGER | 0)) | 0)) === (Math.fround((Math.fround(y) ? Math.fround(( + y)) : Math.fround(x))) | ( - x))), (mathy2((( ! x) || x), Math.fround(Math.fround(mathy0(Math.fround(y), Math.fround(Math.fround(( - Math.fround((Math.asin((x | 0)) | 0))))))))) >>> 0))); }); ");
/*fuzzSeed-28551573*/count=570; tryItOut("\"use strict\"; c = x;v2 = g0.eval(\"function f0(t0) new RegExp(\\\"(?=(?=([^]))+)|(?=\\\\\\\\b){4,}\\\", \\\"y\\\")\");");
/*fuzzSeed-28551573*/count=571; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a1, 1, ({configurable: false, enumerable: false}));");
/*fuzzSeed-28551573*/count=572; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.exp((((( - ((Math.min(-Number.MIN_SAFE_INTEGER, ( + ( ~ ( + x)))) ? (( ! Math.hypot(( + x), y)) >>> 0) : Math.sin((y | 0))) | 0)) | 0) ? Math.fround((Math.fround(y) && ((( ! x) >>> 0) <= y))) : ( + Math.atanh((( + (Math.hypot(x, x) | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy2, [0x080000001, -0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -(2**53+2), -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 0x100000000, 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 0, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -0, -0x100000000, -0x07fffffff, Math.PI, -0x080000000, 1/0, 0x080000000, 0x100000001, -1/0, 2**53+2, -(2**53)]); ");
/*fuzzSeed-28551573*/count=573; tryItOut("\"use strict\"; throw \u3056;let(x = x, [, ] = (4277), mxfdik, x = ([1,,].__defineSetter__(\"x\", \"\\uA264\").valueOf(\"number\")), b, x, wrmlsn, x, a) { throw StopIteration;}");
/*fuzzSeed-28551573*/count=574; tryItOut(";");
/*fuzzSeed-28551573*/count=575; tryItOut("/*infloop*/L:for(var x = x;  '' ; [[]]) {-8; }");
/*fuzzSeed-28551573*/count=576; tryItOut("a2[v1] = t2;let c = Math.imul(16, 21);");
/*fuzzSeed-28551573*/count=577; tryItOut("/*ODP-2*/Object.defineProperty(a1, (/*UUV2*/(x.getUTCDay = x.set)), { configurable: false, enumerable: (x % 3 != 0), get: (function(j) { if (j) { try { e2.toString = (function mcc_() { var yoptrd = 0; return function() { ++yoptrd; if (/*ICCD*/yoptrd % 2 == 1) { dumpln('hit!'); try { v1 = evaluate(\"e1 = new Set;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 == 0), noScriptRval: (x % 25 == 24), sourceIsLazy: (x % 19 == 8), catchTermination: ({ get includes c () { s1 += s1; } , valueOf: (4277) }) })); } catch(e0) { } try { h0 = t0[x]; } catch(e1) { } s2 = s1.charAt(({valueOf: function() { /* no regression tests found */return 4; }})); } else { dumpln('miss!'); g2.g1.o0.e2 = a1[({valueOf: function() { this.g0.s0 = new String(f2);return 16; }})]; } };})(); } catch(e0) { } Array.prototype.pop.call(a2, f2, i2); } else { try { g0.h0.__proto__ = o1; } catch(e0) { } try { /*MXX1*/this.o2 = g0.Symbol; } catch(e1) { } p1 + ''; } }), set: (function() { var e0 = new Set(f2); return s1; }) });");
/*fuzzSeed-28551573*/count=578; tryItOut("/*oLoop*/for (let phrbzs = 0; phrbzs < 4; ++phrbzs) { (let (d) d >> -12); } ");
/*fuzzSeed-28551573*/count=579; tryItOut("\"use strict\"; this.a0 = arguments.callee.caller.caller.caller.arguments;");
/*fuzzSeed-28551573*/count=580; tryItOut("Array.prototype.pop.call(a2, v0);");
/*fuzzSeed-28551573*/count=581; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    i1 = (/*FFI*/ff(((((0x8e360ddc) % (((/*FARR*/[...[], , length, , window, x].some))>>>((Uint32ArrayView[(((0x25d13abc) >= (0x2c9376af))) >> 2])))) | ((i1)+(0x12db8baa)))))|0);\n    return (((i1)))|0;\n    return ((-((0x0) >= (((void options('strict')))>>>((!((-137438953473.0) < (-1099511627777.0)))-(0xfcb2bc01)-(0xfaf045d2))))))|0;\n  }\n  return f; })(this, {ff: Array.prototype.values}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000001, 0.000000000000001, 0x0ffffffff, -1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 42, -(2**53), Number.MIN_VALUE, 0x100000000, -(2**53+2), Number.MAX_VALUE, 1, 0/0, -(2**53-2), 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, -0, 2**53+2, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, -Number.MIN_VALUE, -0x07fffffff, 2**53, 1/0, -0x100000000, 0]); ");
/*fuzzSeed-28551573*/count=582; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.min(((( - (Math.atan2((y | 0), ( ~ (Math.exp(x) | 0))) | 0)) >>> 0) >>> 0), ( + Math.abs((( + ( + (( + y) ^ ( + x)))) | ( + (Math.log1p((x >>> 0)) >>> 0))))))); }); testMathyFunction(mathy2, [1/0, -0, -(2**53), Number.MAX_VALUE, 42, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, 0x100000001, -0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 0x07fffffff, 2**53+2, 2**53-2, 0, 0x080000000, 0.000000000000001, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, -0x07fffffff, -0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=583; tryItOut("g2.v2 = Object.prototype.isPrototypeOf.call(o2, s0);");
/*fuzzSeed-28551573*/count=584; tryItOut("let(d, x, yalndp, kylckt, x, vsxxnp) { (/\\3/gi);}");
/*fuzzSeed-28551573*/count=585; tryItOut("\"use strict\"; v0 + '';");
/*fuzzSeed-28551573*/count=586; tryItOut("\"use strict\"; f1 + m2;");
/*fuzzSeed-28551573*/count=587; tryItOut("v0 = evaluate(\"(\\\"\\\\uE5C5\\\");\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: x.throw(x), catchTermination: (4277) }));");
/*fuzzSeed-28551573*/count=588; tryItOut("v1 = evalcx(\"function f0(f1)  { print(uneval(p0)); } \", g2.g1);");
/*fuzzSeed-28551573*/count=589; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( ! Math.fround((Math.max(( ~ x), x) << (( + Math.sign(y)) | 0)))) | 0) != mathy0((Math.sign((Math.sign((( + ( - 0)) | 0)) | 0)) | 0), ((( ! (mathy1((( ! (Math.ceil(x) | 0)) >>> 0), y) >>> 0)) | 0) | 0))); }); testMathyFunction(mathy3, [-0x100000001, 1/0, 0x07fffffff, Math.PI, 0x100000000, -Number.MAX_VALUE, 0, -(2**53-2), 1.7976931348623157e308, 42, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, -1/0, 0x080000001, 0x080000000, -(2**53+2), 0/0, -0x080000000, -0x100000000, -0, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 0x100000001, 2**53+2, 1, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-28551573*/count=590; tryItOut("\"use strict\"; let (a) { g2.o2.g1.s2 = new String; }");
/*fuzzSeed-28551573*/count=591; tryItOut("mathy0 = (function(x, y) { return Math.max(((( + (((0x0ffffffff | 0) | ((x % x) | 0)) | 0)) | Math.imul(( + ( ~ ( + Math.fround((Math.fround(x) >= Math.fround(x)))))), ( ! (((0.000000000000001 | 0) ? (y >>> 0) : (x >>> 0)) >>> 0)))) | 0), ( + (Math.ceil(Math.atan2((Math.fround(0/0) % y), Math.fround((y + Math.hypot((Math.imul((y >>> 0), (y >>> 0)) >>> 0), ((0 | 0) >>> (y | 0))))))) | 0))); }); ");
/*fuzzSeed-28551573*/count=592; tryItOut("\"use strict\"; v0 = evalcx(\"this.t0[18] = (false = -10.__defineSetter__(\\\"\\\\u3056\\\", Float64Array));\", g0);function e(a, [{}], e = this.__defineSetter__(\"x\", /*wrap3*/(function(){ var nzdqkf = /\\r*?\\2|$\\S(?:[^])|\\\ubfc4{1,}\\W+?\\w?+?/gym; (function(q) { return q; })(); })), x, z, x, x, c, x, x, w = this, x, x = \"\\u45EE\", d, setter, d =  \"\" , delete, b, e, x = -26, e, x, c, NaN = true, z, x, z = false, x, w, b =  /x/ , x, x, NaN, x, e, d = y, y, x, x, NaN, d, e, x, y, \u3056, x, b, x, x, x =  \"\" , x, NaN, e, c, d =  /x/ , b, x, x, getter, z, d, x = -15, z, x, get, e, z, x, b, x, x, x, y, w = undefined, c, x, x, w, d, x, c, a, w, z, NaN) { \"use strict\"; i2.next(); } print(x);");
/*fuzzSeed-28551573*/count=593; tryItOut("m2.set((\u000c(w))--, s1);");
/*fuzzSeed-28551573*/count=594; tryItOut(";");
/*fuzzSeed-28551573*/count=595; tryItOut("\"use strict\"; e1.has(e1);");
/*fuzzSeed-28551573*/count=596; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((({x: y}) == ( + Math.cbrt(( + (Math.expm1(( + y)) | 0))))) >>> 0); }); ");
/*fuzzSeed-28551573*/count=597; tryItOut("a2.push(v2, v0);");
/*fuzzSeed-28551573*/count=598; tryItOut("v2 = (v2 instanceof e2);");
/*fuzzSeed-28551573*/count=599; tryItOut("v2 = t2.length;");
/*fuzzSeed-28551573*/count=600; tryItOut("\"use strict\"; yield x;with({}) { try {  '' ; } catch(x) { (22); }  } ");
/*fuzzSeed-28551573*/count=601; tryItOut("");
/*fuzzSeed-28551573*/count=602; tryItOut("testMathyFunction(mathy5, [0.000000000000001, 2**53-2, -0x0ffffffff, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -0, -0x080000001, 42, 1.7976931348623157e308, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, 0x100000000, -(2**53-2), Number.MAX_VALUE, 0/0, -(2**53), -0x07fffffff, 0x07fffffff, 1, 0, 0x080000001, 1/0, Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, 0x080000000, -0x100000000]); ");
/*fuzzSeed-28551573*/count=603; tryItOut("\"use strict\"; this.i0 = this.a1.iterator;");
/*fuzzSeed-28551573*/count=604; tryItOut("m1 + o1;");
/*fuzzSeed-28551573*/count=605; tryItOut("a0.sort(Proxy.bind(i1), g2.e1, f0, t2);t1.toString = (function(j) { if (j) { try { o0.v0 = (m0 instanceof this.p0); } catch(e0) { } try { Object.defineProperty(this, \"v0\", { configurable: \"\\uB09E\", enumerable: true,  get: function() {  return r0.test; } }); } catch(e1) { } try { s2 = g1.objectEmulatingUndefined(); } catch(e2) { } for (var p in g1.o1.g0.v0) { try { Array.prototype.sort.apply(a2, [(function() { try { b0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      return (((0xdfad7993)))|0;\n    }\n    {\n      i1 = (i1);\n    }\n    d0 = (2.0);\n    d0 = (+atan((((0xfb91e7f2) ? (+(-1.0/0.0)) : (+(-1.0/0.0))))));\n    return ((0x46791*(0xffffffff)))|0;\n    return ((((((i1) ? ((0x36ab3131) ? (0xffffffff) : (-0x8000000)) : (0xf9bfa2c8))-((((0xfadab98f)-(0xffffffff)) | (0xbb705*(0x45614aa2))) != (-0x8000000)))>>>((i1)+((Uint32ArrayView[1])))) % (((0xffffffff))>>>((i1)-(!((0xd184dd51) != (0x6796e6e8)))))))|0;\n  }\n  return f; }); } catch(e0) { } try { o1.h1 + a1; } catch(e1) { } try { v0 = (a2 instanceof s2); } catch(e2) { } e1.has(e); return h2; }), g1.t2, o2]); } catch(e0) { } try { for (var v of v1) { Object.defineProperty(this, \"v1\", { configurable: true, enumerable: window,  get: function() {  return evalcx(\" '' \", this.g1); } }); } } catch(e1) { } a2.unshift(p2, i0, o1.o0.a1, a1); } } else { try { for (var p in a0) { try { v2 = (e2 instanceof o1.p2); } catch(e0) { } b0.__proto__ = a2; } } catch(e0) { } try { f2 = (function(j) { if (j) { try { e0 + b0; } catch(e0) { } try { b2.__proto__ = p2; } catch(e1) { } v2 = a0.every((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+(-1.0/0.0));\n    i1 = (0x4b129d9c);\n    {\n      d0 = (32769.0);\n    }\n    (Int16ArrayView[((0xad16ea8e) % ((-((0xffffffff) != (0xf6599aa2)))>>>((i1)+(!(0xbd416092))))) >> 1]) = ((i1)+(!(0xfcf86e3e)));\n    d0 = (new SimpleObject());\n    return +((-1.888946593147858e+22));\n  }\n  return f; })(this, {ff: e}, new ArrayBuffer(4096))); } else { try { p1.toSource = (function(j) { if (j) { try { a1.splice(NaN, 1, h2); } catch(e0) { } try { x = h0; } catch(e1) { } t1[11] = w; } else { try { g1.s0 += g2.s1; } catch(e0) { } o0.a0[({valueOf: function() { Array.prototype.pop.call(a2);return 16; }})]; } }); } catch(e0) { } o1.o2.g0.i2.next(); } }); } catch(e1) { } this.v0 = (h1 instanceof o2); } });");
/*fuzzSeed-28551573*/count=606; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.sin((mathy2((((x | 0) >= ( + (Math.max(Math.acosh(0x07fffffff), ( - ( + y))) >>> 0))) | 0), Math.max(y, y)) | 0)) || (4277)); }); testMathyFunction(mathy3, [-0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, -0x0ffffffff, 0x100000001, Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, 0x080000001, 1/0, 0x0ffffffff, 0x07fffffff, 0.000000000000001, -(2**53+2), -0, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, 0, 1, 0x100000000, -1/0, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, 0/0, -0x100000000, 2**53+2, 42]); ");
/*fuzzSeed-28551573*/count=607; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(Math.atan2(Math.fround(( - Math.fround((Math.fround(( + Math.log(( + x)))) , x)))), Math.fround(((Math.fround(Math.log10(x)) & Math.fround(x)) + (mathy1(Math.log(Math.log1p((Math.clz32((x >>> 0)) >>> 0))), Math.min(mathy0(x, y), ( ~ ( + x)))) >>> 0))))) >= Math.atan2(Math.tan(( + (Math.pow(((Math.fround(y) <= -Number.MAX_SAFE_INTEGER) | 0), (y < y)) ? mathy2(y, ( + x)) : x))), ( + ( ! ( + y))))); }); testMathyFunction(mathy3, [null, (new String('')), 0, 1, (new Boolean(false)), (new Number(0)), 0.1, '/0/', ({valueOf:function(){return '0';}}), undefined, '\\0', false, -0, (new Boolean(true)), NaN, (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Number(-0)), [0], '0', ({toString:function(){return '0';}}), [], '', /0/, true, objectEmulatingUndefined()]); ");
/*fuzzSeed-28551573*/count=608; tryItOut("{ void 0; void schedulegc(14); }");
/*fuzzSeed-28551573*/count=609; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround(( ~ -0)) < Math.fround(Math.imul(Math.fround(y), Math.fround(((-Number.MIN_VALUE ^ y) >>> ( + ( - (y && y))))))))); }); testMathyFunction(mathy0, [0.000000000000001, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, -(2**53-2), Number.MIN_VALUE, Math.PI, 0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, 1/0, -1/0, -Number.MAX_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_VALUE, 2**53, 1, 2**53-2, Number.MAX_VALUE, 0, -(2**53), 42, 0x080000000, -0x080000001, -0x0ffffffff, -(2**53+2), 1.7976931348623157e308, 0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=610; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2|\\\\3*\", \"yim\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=611; tryItOut("for (var v of m2) { try { t1.set(o1.a0, 6); } catch(e0) { } try { p1 = g1.objectEmulatingUndefined(); } catch(e1) { } /*RXUB*/var r = g0.r2; var s = \"\"; print(s.match(r)); print(r.lastIndex);  }");
/*fuzzSeed-28551573*/count=612; tryItOut("/*oLoop*/for (let tqlqqx = 0, \"\\u16A6\"; tqlqqx < 22; ++tqlqqx) { o2.a2[3]; } ");
/*fuzzSeed-28551573*/count=613; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - ( + Math.acosh(( + ((( + 2**53) >>> 0) << ( + Math.acos(((x ? ((Math.imul((Math.atan2(-Number.MIN_SAFE_INTEGER, 0x0ffffffff) | 0), (x | 0)) | 0) | 0) : Math.expm1(Math.fround(x))) | 0)))))))); }); testMathyFunction(mathy2, [false, [], null, -0, 0.1, (new Number(0)), true, '\\0', (new String('')), ({valueOf:function(){return '0';}}), [0], (new Boolean(false)), (function(){return 0;}), '', NaN, ({toString:function(){return '0';}}), undefined, (new Number(-0)), '/0/', /0/, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), 1, 0, (new Boolean(true)), '0']); ");
/*fuzzSeed-28551573*/count=614; tryItOut("print(x);");
/*fuzzSeed-28551573*/count=615; tryItOut("print(x);");
/*fuzzSeed-28551573*/count=616; tryItOut("v0 = a2.reduce, reduceRight((function() { for (var j=0;j<33;++j) { f2(j%3==1); } }), t1);");
/*fuzzSeed-28551573*/count=617; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=618; tryItOut("e1.delete(g0.t1);");
/*fuzzSeed-28551573*/count=619; tryItOut(";function \u3056(window = (w = []), a = x) '' {}");
/*fuzzSeed-28551573*/count=620; tryItOut("(this.eval = x);");
/*fuzzSeed-28551573*/count=621; tryItOut("\"use strict\"; (d || x);");
/*fuzzSeed-28551573*/count=622; tryItOut("\"use strict\"; L:with(null){print(x); }");
/*fuzzSeed-28551573*/count=623; tryItOut("\"use strict\"; m2 + b0;");
/*fuzzSeed-28551573*/count=624; tryItOut("for (var v of b1) { var s2 = a1.join(s0, o2.s0); }");
/*fuzzSeed-28551573*/count=625; tryItOut("/*RXUB*/var r = this.r1; var s = s0; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=626; tryItOut("\"use strict\"; m0 = new WeakMap;");
/*fuzzSeed-28551573*/count=627; tryItOut("\"use strict\"; for (var v of t1) { try { /*MXX1*/o0 = g2.Date.prototype.setUTCMonth; } catch(e0) { } try { t1.set(a2, this.__defineGetter__(\"NaN\", Error.prototype.toString)); } catch(e1) { } try { i0.next(); } catch(e2) { } {var xjxanq = new SharedArrayBuffer(4); var xjxanq_0 = new Float64Array(xjxanq); xjxanq_0[0] = 10; var xjxanq_1 = new Float64Array(xjxanq); print(xjxanq_1[0]); xjxanq_1[0] = 3; i0.send(f2); } }");
/*fuzzSeed-28551573*/count=628; tryItOut("Object.freeze(m1);");
/*fuzzSeed-28551573*/count=629; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return ( + ((Math.tan(( + (((x >>> 0) ? ((y , ( + (( + x) ^ ( + ( + ((y >>> 0) | (y >>> 0))))))) >>> 0) : (mathy0(Math.clz32(x), (Math.fround(Math.imul(x, Math.fround(y))) != ( + ((x >>> 0) , (y >>> 0))))) >>> 0)) >>> 0))) | 0) | 0)); }); testMathyFunction(mathy2, [-0x100000001, 2**53+2, -(2**53), -Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, 0.000000000000001, -0x100000000, 1/0, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 42, -0x080000000, 2**53-2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, -1/0, 0, -(2**53-2), -0x080000001, 2**53, 0x100000001, Math.PI, 0x100000000]); ");
/*fuzzSeed-28551573*/count=630; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MAX_VALUE, -(2**53-2), 0x100000000, 2**53-2, 1, -0x100000000, 2**53+2, 0, Number.MIN_VALUE, -(2**53+2), 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, -0, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, 0x100000001, -1/0, 42, 0/0, 0x080000001, -0x100000001, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 1/0, 2**53, Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=631; tryItOut("var dlyjev = new SharedArrayBuffer(1); var dlyjev_0 = new Uint8ClampedArray(dlyjev); dlyjev_0[0] = -6; var dlyjev_1 = new Uint32Array(dlyjev); dlyjev_1[0] = -23; var dlyjev_2 = new Uint32Array(dlyjev); print(dlyjev_2[0]); dlyjev_2[0] = 0; var dlyjev_3 = new Uint8ClampedArray(dlyjev); o0.s2 = new String(this.h1);g2.i2.next();e2.add(m2);g2.g2.t1 = new Int32Array(4);");
/*fuzzSeed-28551573*/count=632; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.max((Math.max((Math.fround(Math.min(( + x), (( ~ (y || y)) * Math.cosh(y)))) >>> ( + y)), (( ~ Math.fround(( ~ ( + ((mathy0(0x07fffffff, x) | 0) / ( + x)))))) | 0)) >>> 0), (Math.min((Math.pow(mathy3(Math.fround((Math.fround(x) << Math.fround(x))), (Math.cbrt((y | 0)) | 0)), Math.fround(Math.acos(y))) >>> 0), (( + Math.imul(( ~ ((( + Math.log(( + (42 >>> ( + Number.MIN_VALUE))))) || ( + x)) >>> 0)), ( + (y >= (mathy3(0x080000001, (x >>> 0)) >>> 0))))) | 0)) | 0)); }); testMathyFunction(mathy5, [0x100000000, 2**53-2, Number.MIN_VALUE, 0x100000001, -0x100000001, -0x0ffffffff, -0x080000001, 1/0, 0x080000000, 0, 42, -0, -(2**53+2), 2**53, 0x080000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -Number.MIN_VALUE, Math.PI, 0x0ffffffff, -0x07fffffff, -0x080000000, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 1, -(2**53)]); ");
/*fuzzSeed-28551573*/count=633; tryItOut("/*RXUB*/var r = r0; var s = s2; print(r.test(s)); ");
/*fuzzSeed-28551573*/count=634; tryItOut("a2.pop();");
/*fuzzSeed-28551573*/count=635; tryItOut("testMathyFunction(mathy5, [NaN, (new Boolean(true)), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), '0', false, (new Number(0)), '\\0', ({valueOf:function(){return '0';}}), undefined, [], true, (new String('')), (function(){return 0;}), 0.1, 0, null, (new Boolean(false)), [0], -0, ({toString:function(){return '0';}}), /0/, (new Number(-0)), 1, '/0/', '']); ");
/*fuzzSeed-28551573*/count=636; tryItOut("var b = [1,,] **= Math, x;/*RXUB*/var r = new RegExp(\"\\\\3\", \"gm\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-28551573*/count=637; tryItOut("/*hhh*/function cxqeay(b, z = \"\\u1201\", z, x, a, x, NaN = /(?=(?:(?:\\b)){16})|\\1?/gy, c, b, x, c =  '' , a, c, window, x, d, x, y = null, c, \u3056, b, NaN, this = 23, setter, x = this, x, x, x, x, a, e = /(?!\\W)|(?=\\b)*?|[](?:.)(?=^)?(?:.).$^*|\\S*?|\\cW|\\w{1}*?/m, window, e, NaN, z, window, z, e, x, w, b, x, delete, c, NaN, x,  , c, NaN, d, a, x, eval, x, of =  '' , window = undefined, x, x, e, \u3056, \u3056, b, c, x, z, y, x =  '' , e, NaN = window, x, x, x, x, x, e, a, a, z, w, x, w, y, window, eval, e, y, z, x = false, x, w, b, x, b = -513, b, x = [[]], NaN, ...getter){this.a1 + this.o2;}/*iii*/var v2 = evaluate(\"/(?:[^]{2,}){2}|(?=$?|([\\u00a5\\u00cc-\\\\ubD49\\\\S\\\\uee7f-\\ucaf5]))(?:\\u00a0)|((\\\\S)|^\\\\xdc[\\\\D]*)+?/gim\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce:  '' , noScriptRval: true, sourceIsLazy: true, catchTermination: -14 }));");
/*fuzzSeed-28551573*/count=638; tryItOut("mathy0 = (function(x, y) { return Math.max((Math.ceil(((y >> Math.fround(( + (( + Math.acos(y)) >= ( + ( ! x)))))) | 0)) >>> 0), Math.fround(Math.acosh((((((x >>> 0) / (Math.atan2((x >>> 0), (x >>> 0)) >>> 0)) >>> 0) && x) | 0)))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 0x080000001, 0x100000000, -Number.MIN_VALUE, -1/0, -(2**53-2), 0, 1.7976931348623157e308, -0, -0x080000001, -0x080000000, -(2**53+2), Number.MIN_VALUE, Math.PI, 2**53+2, -0x100000001, 0.000000000000001, 0x080000000, -0x0ffffffff, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 2**53-2, Number.MAX_VALUE, 1, -0x07fffffff, 1/0, 0x0ffffffff, 42, 0/0]); ");
/*fuzzSeed-28551573*/count=639; tryItOut("{for (var v of p0) { try { e0 + ''; } catch(e0) { } try { this.v1 = Object.prototype.isPrototypeOf.call(f0, a1); } catch(e1) { } r1 = new RegExp(\"\\\\b\\\\B|\\\\W^+?\", \"gym\"); } }");
/*fuzzSeed-28551573*/count=640; tryItOut("\"use strict\"; Array.prototype.pop.call(this.a2, this.s2);let a = x;selectforgc(o2);");
/*fuzzSeed-28551573*/count=641; tryItOut("v1 = Object.prototype.isPrototypeOf.call(p2, f0);");
/*fuzzSeed-28551573*/count=642; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x100000000, -0x07fffffff, 1.7976931348623157e308, 2**53, 1/0, 1, 0/0, Math.PI, 0x080000001, 42, 0x080000000, -1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 0x07fffffff, -(2**53-2), 2**53-2, -(2**53), -Number.MAX_VALUE, 0, 0x100000001, -0, 0x0ffffffff, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, 2**53+2, -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=643; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy4, [0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, 42, -Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, 1, Math.PI, -0x100000000, Number.MAX_VALUE, -0, 2**53+2, Number.MIN_VALUE, -(2**53+2), -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, 0.000000000000001, 2**53-2, 0, -0x080000001, 0x100000000, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, 0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-28551573*/count=644; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-28551573*/count=645; tryItOut("(function ([y]) { })();");
/*fuzzSeed-28551573*/count=646; tryItOut("/*oLoop*/for (var mxgcii = 0; mxgcii < 14; ++mxgcii) { m2.get(p2); } ");
/*fuzzSeed-28551573*/count=647; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.acosh((((((Math.atan2((Math.imul((((y | 0) <= mathy0(y, x)) | 0), x) | 0), (Math.cosh(x) | 0)) >>> 0) , Math.fround(Math.cosh(( + ( ! ( + y)))))) >>> 0) || Math.fround(( ~ Math.fround(Math.atan2(x, Math.atan(((y > y) ? x : y))))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-28551573*/count=648; tryItOut("for(let y in []);");
/*fuzzSeed-28551573*/count=649; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-28551573*/count=650; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a0, v2, ({set: (x%=(x ^= x = [z1]))}));");
/*fuzzSeed-28551573*/count=651; tryItOut("\"use strict\"; \"use asm\"; e1.delete(f0);print(null.defineProperties( /x/ ,  /x/g ));");
/*fuzzSeed-28551573*/count=652; tryItOut("testMathyFunction(mathy1, [0x100000000, -0x07fffffff, 0x080000001, -(2**53+2), -0x080000000, -0x100000000, 2**53-2, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000000, -0, -(2**53), -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, -1/0, Number.MIN_VALUE, Math.PI, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, 0, 2**53+2, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -Number.MIN_VALUE, 42, -0x080000001, 1, 0x0ffffffff, -0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=653; tryItOut("\"use strict\"; var qntpio = new ArrayBuffer(16); var qntpio_0 = new Int32Array(qntpio); print(qntpio_0[0]); qntpio_0[0] = -28; var qntpio_1 = new Uint16Array(qntpio); qntpio_1[0] = -7; var qntpio_2 = new Uint16Array(qntpio); print(qntpio_2[0]); var qntpio_3 = new Float64Array(qntpio); print(qntpio_3[0]); qntpio_3[0] = 20; a1[12] = [z1];g0.offThreadCompileScript(\"a1 = m0.get(g0.g1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (qntpio % 94 != 15), noScriptRval: false, sourceIsLazy: true, catchTermination: (qntpio_3[0] % 4 == 0) }));b1.toSource = (function() { try { t2 + t0; } catch(e0) { } for (var p in i1) { try { h1.iterate = f1; } catch(e0) { } s2 += 'x'; } return o0.p2; });print( /x/g );v2 = t2.byteLength;;s0 += 'x';print(uneval(s1));/\\3/gyim;/*bLoop*/for (var weoblv = 0; weoblv < 0; ++weoblv) { if (weoblv % 23 == 14) { g0.offThreadCompileScript(\"s1 += s1;\", ({ global: g0.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: this.eval, sourceIsLazy: -21, catchTermination: false })); } else { return -0; }  } ");
/*fuzzSeed-28551573*/count=654; tryItOut("\"use asm\"; var ffoeym = new SharedArrayBuffer(8); var ffoeym_0 = new Float32Array(ffoeym); print(ffoeym_0[0]); var ffoeym_1 = new Uint8Array(ffoeym); ffoeym_1[0] = -4; var ffoeym_2 = new Uint16Array(ffoeym); print(ffoeym_2[0]); ffoeym_2[0] = 1482901560; var ffoeym_3 = new Float64Array(ffoeym); print(ffoeym_2[0]);print(window ? new RegExp(\"(?!\\\\1{4,})*?\", \"gm\") : b); /x/g ;a2.push(new (Math.acos(3))(this), i0, b1, e1, a1, o2.h2, g0.o0.t0);");
/*fuzzSeed-28551573*/count=655; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.log2(((( + mathy3(( + x), ( + (( + 0x100000000) ** y)))) * (( ! (x >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [objectEmulatingUndefined(), [0], 0.1, false, (new Number(0)), '\\0', ({toString:function(){return '0';}}), [], NaN, 0, -0, '', ({valueOf:function(){return 0;}}), /0/, (new String('')), true, (new Boolean(false)), '0', (new Boolean(true)), (new Number(-0)), '/0/', 1, null, undefined, (function(){return 0;}), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-28551573*/count=656; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, 2**53, 42, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, Math.PI, 1, -(2**53), 0x07fffffff, 2**53-2, -0x080000001, 0x0ffffffff, -1/0, 1/0, 0x080000001, 1.7976931348623157e308, -(2**53-2), -0, -0x07fffffff, 2**53+2, -0x080000000, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 0x080000000, -(2**53+2), -0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=657; tryItOut("g0.v2 = eval(\"mathy4 = (function(x, y) { return (( ~ (( + mathy2(( + Math.sinh(x)), ( + ( + (( - (-(2**53) | 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[new Boolean(true), -Infinity, -Infinity, new Boolean(true), -Infinity, new Boolean(true), -Infinity, new Boolean(true), -Infinity, new Boolean(true), null, new Boolean(true), new Boolean(true), -Infinity, -Infinity, -Infinity, function(){}, function(){}, -Infinity, function(){}, null, null, function(){}, null, new Boolean(true), function(){}, new Boolean(true), -Infinity, -Infinity, null, new Boolean(true), null, -Infinity, function(){}, -Infinity, null, new Boolean(true), new Boolean(true), function(){}, new Boolean(true), null, null, new Boolean(true), null, new Boolean(true), -Infinity, null, new Boolean(true), function(){}, null, null, function(){}, new Boolean(true), -Infinity, -Infinity, function(){}, function(){}, new Boolean(true), new Boolean(true), -Infinity, function(){}, new Boolean(true), function(){}, null, null, -Infinity, null, new Boolean(true), -Infinity, -Infinity, null, null, null, new Boolean(true), new Boolean(true), null, new Boolean(true), new Boolean(true), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, null, function(){}, new Boolean(true), null, new Boolean(true), -Infinity, null, new Boolean(true), new Boolean(true), null, function(){}, function(){}, new Boolean(true), function(){}, function(){}, new Boolean(true), -Infinity, -Infinity, null, new Boolean(true), -Infinity, new Boolean(true), -Infinity, null, null]); \");");
/*fuzzSeed-28551573*/count=658; tryItOut("a0.length = ({valueOf: function() { this.a2.push(b2, o0, i1);return 12; }});");
/*fuzzSeed-28551573*/count=659; tryItOut("mathy3 = (function(x, y) { return Math.imul(( + (( + ((( + (y >>> ( + y))) % ( + ((x >>> 0) , ((Math.expm1((-Number.MIN_VALUE >>> 0)) >>> 0) >>> 0)))) | 0)) ? ((((x | 0) < (( + ((x | y) ^ ( + y))) | 0)) | 0) >>> 0) : mathy2(y, (Math.max(Number.MIN_SAFE_INTEGER, (Math.fround((Number.MIN_SAFE_INTEGER ? x : ( + y))) >>> 0)) >>> 0)))), (Math.asin(Math.asin(mathy2((((-Number.MAX_SAFE_INTEGER >>> 0) & (Math.imul(0x0ffffffff, x) | 0)) >>> 0), Math.PI))) >>> 0)); }); testMathyFunction(mathy3, [-(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 2**53, 0, 0x100000000, 0.000000000000001, 2**53+2, -(2**53-2), Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 1/0, -Number.MAX_SAFE_INTEGER, 0x100000001, -0, -0x100000001, 1, 0/0, 42, -0x07fffffff, 0x080000001, 1.7976931348623157e308, 0x07fffffff, 2**53-2, Number.MIN_VALUE, Math.PI, -0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000]); ");
/*fuzzSeed-28551573*/count=660; tryItOut("Object.seal(e0);");
/*fuzzSeed-28551573*/count=661; tryItOut("m2.get(this.o2);");
/*fuzzSeed-28551573*/count=662; tryItOut("\"use strict\"; w = (void options('strict')).__defineSetter__(\"x\", (1 for (x in [])));v0 + '';\ne1.delete(s1);\n");
/*fuzzSeed-28551573*/count=663; tryItOut("testMathyFunction(mathy5, [-0x100000000, 0x100000001, 0.000000000000001, -1/0, 2**53, 1.7976931348623157e308, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, -0x100000001, -0x080000001, 2**53+2, -(2**53), -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -0, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, -0x0ffffffff, 0x080000000, 1/0, 0, 42]); ");
/*fuzzSeed-28551573*/count=664; tryItOut("p2 = Proxy.create(h2, b2);");
/*fuzzSeed-28551573*/count=665; tryItOut("mathy5 = (function(x, y) { return (mathy2(( + (( + ((( + ( + y)) ^ (y >>> 0)) >>> 0)) >>> 0)), Math.acos((Math.atan(Math.imul(x, -0x080000000)) | 0))) == (Math.pow((( ! mathy4(Math.imul(( + ( + Math.sqrt(y))), ( + 0)), x)) | 0), ((y == ((Math.max(((( + Math.acosh(( + (1/0 << y)))) || Math.min(y, x)) | 0), (y | 0)) | 0) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy5, [0x080000000, 1/0, -0x080000000, 0x100000001, Math.PI, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0, -0x100000001, -0x080000001, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, -(2**53+2), Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, 0.000000000000001, -(2**53), Number.MAX_VALUE, 42, -(2**53-2), 2**53, -0x0ffffffff, -1/0, -0x07fffffff, 0/0, 0x080000001, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=666; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.abs(( + ((((( ! ((Math.imul(y, (y >>> 0)) >>> 0) | 0)) | 0) | 0) << Math.fround(Math.sin(2**53))) & ( ! Math.min(( ~ (((( ! (0x07fffffff | 0)) >>> 0) - x) >>> 0)), x))))); }); testMathyFunction(mathy5, /*MARR*/[this, [], [], this, [], this, [], [], this, this,  '' , this, this,  '' ,  '' , [], [], [], [], [], this,  '' , this, this, this,  '' , [], [], this, [], [],  '' ,  '' ,  '' , [], [], this, [],  '' , [], [], this, this,  '' ,  '' ,  '' , [], [], [],  '' , [], this, [], this, this, this, [], this,  '' , this, this,  '' ,  '' , [], this,  '' ,  '' , this, [], this,  '' , this, [], this, [], [],  '' ,  '' ,  '' , this,  '' , this, [], this, this,  '' , this, [],  '' , this, this,  '' , this, [], this,  '' , [],  '' , this, [],  '' , this, [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], this, [], [],  '' , this, this, [], [],  '' , this,  '' ,  '' , this,  '' , this,  '' ,  '' , [],  '' , [],  '' , [], this,  '' , this,  '' , this,  '' , [], this,  '' , [], this,  '' , this,  '' , [], this]); ");
/*fuzzSeed-28551573*/count=667; tryItOut("for (var v of o2) { try { this.e0.valueOf = (function mcc_() { var sfsglg = 0; return function() { ++sfsglg; if (/*ICCD*/sfsglg % 7 == 4) { dumpln('hit!'); try { e1 + f2; } catch(e0) { } try { h1.enumerate = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -72057594037927940.0;\n    var d3 = 3.0;\n    return ((-0xc9eb1*((-131073.0) >= (d1))))|0;\n  }\n  return f; })(this, {ff: Promise.prototype.then}, new SharedArrayBuffer(4096)); } catch(e1) { } b1 = new ArrayBuffer(5); } else { dumpln('miss!'); print(uneval(a0)); } };})(); } catch(e0) { } p2.__proto__ = b0; }");
/*fuzzSeed-28551573*/count=668; tryItOut("var wxcedo = new SharedArrayBuffer(4); var wxcedo_0 = new Uint16Array(wxcedo); print(wxcedo_0[0]); v0 = r2.global;for (var p in h1) { try { this.m1 = this.m1.get(i2); } catch(e0) { } try { print(g1); } catch(e1) { } v0 = (s0 instanceof h0); }");
/*fuzzSeed-28551573*/count=669; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + mathy0(( + Math.atan2(Math.max(x, x), ( + Math.pow(((mathy2((((Math.tan((x >>> 0)) >>> 0) ^ ( + Math.sinh(( + x)))) >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) | 0), (Math.log1p(Math.cosh(x)) | 0))))), ( + Math.min((( ! (( + x) | 0)) | 0), (mathy1(Number.MAX_SAFE_INTEGER, (Math.sinh(Math.fround(( ! (Math.max(Math.fround(y), x) | 0)))) | 0)) | 0))))); }); testMathyFunction(mathy3, [0x100000000, 0/0, 0x0ffffffff, -(2**53), -0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, Math.PI, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, -(2**53+2), 0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, -0x100000001, -0, -0x080000001, 1, 0x07fffffff, 0x080000001, -Number.MIN_VALUE, 2**53, 1/0, -Number.MAX_VALUE, 2**53-2, 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=670; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.trunc((Math.atan2(Math.tan(y), ( + Math.acosh(( + Math.sin(( + ( ! ( + (-Number.MAX_VALUE - (((x | 0) || (y | 0)) | 0)))))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [1, 0.000000000000001, -(2**53+2), -0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -(2**53), 2**53+2, -Number.MIN_VALUE, -0x100000001, 0, 0x080000001, -1/0, 2**53, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, Math.PI, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, 2**53-2, 1/0, 0/0, 0x100000000, -0x080000001, 0x080000000]); ");
/*fuzzSeed-28551573*/count=671; tryItOut("h1.delete = (function(j) { if (j) { try { o1 = o1.o2.i1.__proto__; } catch(e0) { } m0.has(i2); } else { this.a1.reverse(this.f1, b1, i1); } });");
/*fuzzSeed-28551573*/count=672; tryItOut("testMathyFunction(mathy0, [0x07fffffff, -Number.MIN_SAFE_INTEGER, 1, -1/0, 0x0ffffffff, 1/0, -(2**53-2), 2**53+2, -0, Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 0/0, 0.000000000000001, -0x07fffffff, -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x100000001, -0x080000000, 1.7976931348623157e308, 0x080000001, 2**53, -0x100000000, 2**53-2, Number.MAX_VALUE, -0x080000001, Math.PI, 0x100000000, 42]); ");
/*fuzzSeed-28551573*/count=673; tryItOut("\"use strict\"; var yheggk;/*RXUB*/var r = /\\3/im; var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-28551573*/count=674; tryItOut("i1.send(m0);");
/*fuzzSeed-28551573*/count=675; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((((((((0x25fd0eb7))) << (((0x68e5de8c) < (0x20afef36))+(0xfe2772ae))) <= (~~(d1))))>>>((0xffffffff)+(0xecd182dd))) == ((((0xfda9604e) ? ((140737488355328.0) > (-1.0078125)) : (!((0x207a7c95))))*0xfffff)>>>(((0xb9fa5b37))+(0xfb1e29f2)-((0x8bc89d6a)))))))|0;\n  }\n  return f; })(this, {ff: (new Function(\"v0 = g1.runOffThreadScript();\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[(-1/0), (-1/0), function(){}, function(){}, -0xB504F332, -0xB504F332, (-1/0), -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, function(){}, function(){}, (-1/0), function(){}, (-1/0), -0xB504F332, (-1/0), (-1/0), (-1/0), function(){}, function(){}]); ");
/*fuzzSeed-28551573*/count=676; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(?:^$+)*?|$^*?|(?=\\\\3)(?=\\\\W\\\\B)?)^+?(?=(?=\\\\x2A)|([^])|.{4,5})(?!\\\\b)(?=[^\\\\b-\\\\u00dF])?(?=((\\\\D){2,}))\", \"i\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-28551573*/count=677; tryItOut("mathy4 = (function(x, y) { return (Math.fround((mathy0(Math.fround(Math.asinh(((Math.atan2((2**53+2 >>> 0), ((Math.cosh((x | 0)) >>> 0) >>> 0)) >>> 0) >>> 0))), Math.imul(((y <= Math.tan((Math.acosh(-(2**53-2)) | 0))) | 0), (x | 0))) | 0)) >>> (Math.sin(Math.fround(Math.cosh(mathy3(Math.imul(y, y), Math.fround(x))))) | 0)); }); testMathyFunction(mathy4, [-0x080000001, 42, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 2**53, 0x100000000, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0, -0x0ffffffff, 0x080000000, -(2**53-2), -0, 0x100000001, -1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), Math.PI, -(2**53+2), 2**53-2, 0.000000000000001, -0x07fffffff, 0/0, 1/0, Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=678; tryItOut("\"use strict\"; v1 = new Number(b1);");
/*fuzzSeed-28551573*/count=679; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy0(( + Math.hypot(((Math.cosh((x >>> 0)) | 0) === x), (Math.imul((Math.expm1(((x % (mathy0((x | 0), ( + -0x080000000)) >>> 0)) >>> 0)) >>> 0), (( ~ y) >>> 0)) >>> 0))), mathy1(( + Math.log2(Math.fround(Math.pow((x >>> 0), y)))), (( ! x) % y))); }); testMathyFunction(mathy2, [({valueOf:function(){return '0';}}), 1, true, '/0/', (new Number(0)), [], '0', -0, '', (new Boolean(false)), (new Boolean(true)), 0, ({toString:function(){return '0';}}), null, undefined, (function(){return 0;}), (new String('')), NaN, 0.1, ({valueOf:function(){return 0;}}), '\\0', [0], /0/, objectEmulatingUndefined(), (new Number(-0)), false]); ");
/*fuzzSeed-28551573*/count=680; tryItOut("t1[13];");
/*fuzzSeed-28551573*/count=681; tryItOut("var yjbmql = new ArrayBuffer(0); var yjbmql_0 = new Float32Array(yjbmql); print(yjbmql_0[0]); yjbmql_0[0] = -6; var yjbmql_1 = new Uint8ClampedArray(yjbmql); yjbmql_1[0] = -11; var yjbmql_2 = new Float64Array(yjbmql); yjbmql_2[0] = -3; /*RXUB*/var r = r2; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-28551573*/count=682; tryItOut("mathy3 = (function(x, y) { return Math.hypot(Math.imul(( + (mathy2(( + x), ((((-0x07fffffff | 0) == -Number.MAX_VALUE) | 0) ? 2**53+2 : x)) >>> 0)), ( + (Math.atanh(-0x0ffffffff) >>> 0))), Math.fround((((Math.atanh(Math.fround(( ! Math.fround(y)))) ? ((( ~ (( - ( + Math.tan(y))) >>> 0)) | 0) >>> 0) : (Math.fround(Math.min(x, y)) == Math.max(x, -Number.MAX_SAFE_INTEGER))) | 0) ? (( + ( ~ ( + ( ! Math.fround(Math.imul(( + x), ( + y))))))) ? x : Math.sinh(x)) : (( - Math.pow((( ~ (x >>> 0)) >>> 0), Math.fround(( ! y)))) | 0)))); }); testMathyFunction(mathy3, [1, 0x100000001, Number.MAX_VALUE, 0.000000000000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -1/0, -0, -0x080000000, -Number.MIN_VALUE, 2**53, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, 1/0, -(2**53-2), 0x07fffffff, -0x100000000, -0x080000001, -(2**53+2), 0x080000000, 42, -0x07fffffff, 1.7976931348623157e308, 0x0ffffffff, 2**53-2, 0/0, -Number.MAX_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=683; tryItOut("mathy5 = (function(x, y) { return (( + Math.max((Math.asin(( ~ (Math.fround((((x | 0) / y) | 0)) !== y))) >>> 0), ( + (Math.atan2(Math.hypot(Math.fround(x), x), (mathy3(x, x) | 0)) ? Math.expm1(Number.MIN_SAFE_INTEGER) : Math.hypot((x >>> 0), Math.atan2(Math.fround(y), x)))))) != ((( ~ ((Math.fround(mathy2(Math.fround(-Number.MIN_SAFE_INTEGER), 42)) + ( ! y)) | 0)) | 0) ? ( + Math.min(mathy2(( - y), y), (( + x) ^ ( + x)))) : (( + Math.fround(( ~ ( + x)))) >>> 0))); }); testMathyFunction(mathy5, [1, 1.7976931348623157e308, 0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 0x100000000, 1/0, 0, -0x100000000, -(2**53-2), -(2**53+2), 42, 0/0, 0x0ffffffff, -0, 2**53+2, -Number.MAX_VALUE, -0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, -Number.MIN_VALUE, -0x07fffffff, 0x100000001, 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, Math.PI, 0x07fffffff, -(2**53)]); ");
/*fuzzSeed-28551573*/count=684; tryItOut("\"use strict\"; p0 + '';");
/*fuzzSeed-28551573*/count=685; tryItOut("g2.v2 = (o2 instanceof o2);");
/*fuzzSeed-28551573*/count=686; tryItOut("v1 = a1.length;");
/*fuzzSeed-28551573*/count=687; tryItOut("h1 + '';");
/*fuzzSeed-28551573*/count=688; tryItOut("\"use strict\"; /*vLoop*/for (var itiwbt = 0; itiwbt < 126; ++itiwbt) { const z = itiwbt; /*RXUB*/var r = /(?=(?!(?=(?=\\W))|[^]|\\2?)*\\2\\x2F?.|.|\u00a6|\\D*(?!\\B?)|[^])/gym; var s = \"\\u4141\"; print(r.test(s));  } ");
/*fuzzSeed-28551573*/count=689; tryItOut("\"use strict\"; m2.get(v2);");
/*fuzzSeed-28551573*/count=690; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1099511627775.0;\n    return (((0xf824a98c)+(((((((-0x6570b8a)+(0xae693e7c))>>>((0xefac551f)+(0xfac285f1))))-(0xffffffff))>>>(((0xfc147ac6)))))+((/*UUV1*/(a.getUTCMonth = (22).apply)))))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [42, 1/0, -0x080000001, Number.MIN_VALUE, 0x100000001, 2**53+2, -Number.MAX_VALUE, -(2**53), 0x0ffffffff, 0/0, 0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, Math.PI, -0, -1/0, -0x100000001, 0.000000000000001, 0, -Number.MIN_VALUE, -0x0ffffffff, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, 0x07fffffff, 0x100000000]); ");
/*fuzzSeed-28551573*/count=691; tryItOut("v1 = Object.prototype.isPrototypeOf.call(v1, f2);");
/*fuzzSeed-28551573*/count=692; tryItOut("testMathyFunction(mathy5, [0x080000001, 2**53-2, 1.7976931348623157e308, 2**53, 0x100000001, Number.MIN_VALUE, Math.PI, 0x0ffffffff, -0x080000000, -0, 0, -Number.MIN_VALUE, -(2**53), 1, 0/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, -0x07fffffff, -0x0ffffffff, 1/0, -(2**53+2), 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53-2), 42, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-28551573*/count=693; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"function g1.f1(h1) \\\"use asm\\\";   function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = 4503599627370497.0;\\n    return (((0x9e511e32)+(0xfd7eb1c4)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-28551573*/count=694; tryItOut("/*infloop*/for(var arguments.callee.arguments = [[1]]; x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { throw 3; }, fix: undefined, has: undefined, hasOwn: function() { return true; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(\"\\u9C6D\"),  /x/g  ? /(?=(?:.|^){1}|.{3,4}\\b+?\\1*?)|(?=(?:[^]){1,5})/gim : \"\\uADE0\"); (Math.asin(((void options('strict')).__defineGetter__(\"window\", window))))) {print(x); }");
/*fuzzSeed-28551573*/count=695; tryItOut("\"use strict\"; v1 = a2.length;");
/*fuzzSeed-28551573*/count=696; tryItOut("mathy3 = (function(x, y) { return ( - ( + Math.log1p(( ! Math.expm1(x))))); }); testMathyFunction(mathy3, [0x100000001, -0x100000001, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, Math.PI, 1/0, 0x100000000, 0x07fffffff, 0x080000000, -0x080000001, -0, -(2**53), 0x080000001, -0x0ffffffff, -0x080000000, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, -(2**53-2), 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, Number.MIN_VALUE, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-28551573*/count=697; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?=(?:[^\\f\\x31-\\x8B]{0,}\\u001F\\B{2,}))\\1+?)/y; var s = \"  \\u441f  \\u441f\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=698; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return (( + Math.fround(((mathy0((((y >>> 0) * (x >>> 0)) >>> 0), Math.hypot(( ~ ( + x)), ( ~ y))) ^ Math.fround(( ~ Math.fround(Math.tan(( + mathy0(( + y), (( ~ (-1/0 >>> 0)) >>> 0)))))))) >>> 0))) | 0); }); testMathyFunction(mathy1, [0x07fffffff, -0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, 0, -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, -0, 0x100000000, 2**53, 2**53+2, -1/0, 0.000000000000001, -0x07fffffff, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, Number.MIN_VALUE, -(2**53-2), -0x100000001, -0x080000000, 1, -0x100000000, 1.7976931348623157e308, 0x100000001]); ");
/*fuzzSeed-28551573*/count=699; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.sqrt(( + ( - ( - Math.hypot((( - y) + x), (x != y))))))); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(),  /x/g ]); ");
/*fuzzSeed-28551573*/count=700; tryItOut("o2.i2 = new Iterator(m0);");
/*fuzzSeed-28551573*/count=701; tryItOut("\"use strict\"; Array.prototype.unshift.apply(this.a1, [h2, p0, t2, this.m0]);");
/*fuzzSeed-28551573*/count=702; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a1, [m0]);");
/*fuzzSeed-28551573*/count=703; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=704; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.tan(( + Math.hypot(( + Math.acos((Math.fround((Math.pow((Number.MIN_VALUE >>> 0), (x >>> 0)) >>> 0)) >>> ( + 0x080000000)))), ( + (Math.ceil((( ~ (y >>> 0)) | 0)) | 0)))))); }); testMathyFunction(mathy3, [(new String('')), 0.1, [], /0/, -0, ({valueOf:function(){return 0;}}), (new Number(-0)), (new Number(0)), 1, [0], (new Boolean(true)), null, false, '/0/', (function(){return 0;}), (new Boolean(false)), NaN, true, '0', objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), '', '\\0', 0, undefined, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-28551573*/count=705; tryItOut("m0 = new Map(g0);");
/*fuzzSeed-28551573*/count=706; tryItOut("\"use strict\"; Array.prototype.sort.apply(a2, [(function() { try { m2.delete(Math.sin(x)); } catch(e0) { } try { o0.t2 = t2.subarray(({valueOf: function() { /*bLoop*/for (ovsqpl = 0; ovsqpl < 28; ++ovsqpl) { if (ovsqpl % 18 == 13) { e1 = new Set(g0.v0); } else { g2.v2 = Object.prototype.isPrototypeOf.call(o2.h2, s1); }  } return 8; }}), 13); } catch(e1) { } b0.toSource = (function() { try { for (var v of a2) { try { v0 = Array.prototype.reduce, reduceRight.apply(this.a1, [(function() { try { Array.prototype.pop.call(a2, e0, f2, t0); } catch(e0) { } f0 = (function mcc_() { var ebxmpc = 0; return function() { ++ebxmpc; f2(/*ICCD*/ebxmpc % 9 == 7);};})(); return f0; })]); } catch(e0) { } try { v2 = (s2 instanceof f1); } catch(e1) { } try { Array.prototype.sort.call(a2, (function() { for (var j=0;j<107;++j) { f0(j%2==0); } })); } catch(e2) { } m1.delete(m1); } } catch(e0) { } try { g1.e2.has(o1.f0); } catch(e1) { } m2 = g1.objectEmulatingUndefined(); return t0; }); throw g1; }), i2]);");
/*fuzzSeed-28551573*/count=707; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.max(((( - ( + Math.max(Math.fround(Math.min(x, y)), ((Math.atanh(((y || -Number.MAX_VALUE) >>> 0)) >>> 0) | 0)))) >>> 0) >>> 0), ((new Function(\"v0 = Object.prototype.isPrototypeOf.call(this.p1, h2);\")))()); }); testMathyFunction(mathy5, [1/0, 0x080000001, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -0x080000000, 42, Number.MAX_VALUE, 0/0, -0x0ffffffff, -0x100000000, 2**53-2, -0x080000001, 2**53, -0, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -1/0, Math.PI, 0x07fffffff, -(2**53+2), 0x080000000, -(2**53), 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 0x100000000, -0x100000001, -0x07fffffff, 0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-28551573*/count=708; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return (Math.abs(Math.acos(((( + mathy0(y, Math.fround((( ~ 0.000000000000001) >>> 0)))) === x) | 0))) ** Math.fround((Math.fround(((( ! x) >>> 0) ** ( + (( + ((( + x) >>> (y | 0)) ? Math.fround(x) : 0x100000001)) >> ((x >>> 0) == (( + Math.atan2(2**53-2, y)) >>> 0)))))) , Math.fround(( + (Math.fround(( ~ Math.fround((Math.fround(y) == Math.fround(y))))) <= ( + Math.min((((y + Math.fround((y >>> x))) >>> 0) >>> y), ((y >= y) | 0))))))))); }); ");
/*fuzzSeed-28551573*/count=709; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + Math.cbrt((( - (mathy3(Math.imul(Number.MAX_VALUE, -0x080000000), x) >>> 0)) >>> 0))) !== ((Math.fround((Math.log2((Math.fround((mathy3(x, x) >>> (Math.clz32((x | 0)) | 0))) >>> 0)) >>> 0)) , Math.fround(0x080000000)) != Math.fround(( + Math.acos(x))))); }); testMathyFunction(mathy5, [1, -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, 0x0ffffffff, -1/0, 0x100000000, 0x100000001, -(2**53), -0x080000001, -0, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -0x0ffffffff, 0x080000000, -(2**53+2), 1.7976931348623157e308, 0x080000001, -Number.MAX_VALUE, 0.000000000000001, 42, 1/0, -Number.MIN_VALUE, 0/0, 2**53+2, 2**53]); ");
/*fuzzSeed-28551573*/count=710; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + ( + ( + Math.ceil(Math.fround(Math.log1p(Math.fround(Math.pow(Math.exp((y | 0)), ( ! (Math.max((y | 0), (x | 0)) | 0)))))))))); }); testMathyFunction(mathy1, [undefined, NaN, '/0/', /0/, ({valueOf:function(){return 0;}}), -0, ({toString:function(){return '0';}}), '', (new Boolean(false)), [0], (new String('')), (new Number(-0)), 0, (function(){return 0;}), ({valueOf:function(){return '0';}}), true, 0.1, false, 1, [], (new Number(0)), (new Boolean(true)), '\\0', null, objectEmulatingUndefined(), '0']); ");
/*fuzzSeed-28551573*/count=711; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, 2**53+2, 1, 0/0, 0x100000001, -0, -(2**53), -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -(2**53+2), 0, 0x100000000, 42, Math.PI, 2**53-2, 0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 1/0, -1/0, Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -0x100000001, 0.000000000000001, Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -0x080000001]); ");
/*fuzzSeed-28551573*/count=712; tryItOut("function shapeyConstructor(parzsm){return parzsm; }/*tLoopC*/for (let w of /*FARR*/[x]) { try{let lixamf = shapeyConstructor(w); print('EETT'); print((new this(new RegExp(\"\\\\B|(?:(?=[\\\\s\\\\cJ-\\\\cT\\u00ab-\\\\x30\\u001c]*|\\\\W$*){3,})\", \"gm\"), \"\\uB57A\")));}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-28551573*/count=713; tryItOut("\"use strict\"; a1.pop(o0.m1);");
/*fuzzSeed-28551573*/count=714; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-28551573*/count=715; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x080000000, -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -0, 0x0ffffffff, -0x07fffffff, 1/0, 2**53-2, -0x080000000, 0x100000001, 1, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, 0x100000000, 42, 0, -(2**53), -Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, -0x100000001, -(2**53-2), 0x080000001, 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=716; tryItOut("\"use strict\"; t0 = t2.subarray(6);");
/*fuzzSeed-28551573*/count=717; tryItOut("\"use strict\"; t1[6] = x;");
/*fuzzSeed-28551573*/count=718; tryItOut("v2 = t2.length;");
/*fuzzSeed-28551573*/count=719; tryItOut("this.m1.has(m1);");
/*fuzzSeed-28551573*/count=720; tryItOut("e1.delete(a2);(void schedulegc(g1));");
/*fuzzSeed-28551573*/count=721; tryItOut("\"use strict\"; v0 = evalcx(\"this.f0 = f1;\", g2);");
/*fuzzSeed-28551573*/count=722; tryItOut("mathy5 = (function(x, y) { return ( + Math.min((( + Math.tanh(Math.fround((Math.round((x >>> 0)) >>> 0)))) != (Math.tan((Math.fround((y * Math.pow(x, x))) >>> 0)) >>> 0)), ((Math.fround(Math.asinh((( + Math.round(x)) >>> 0))) - (Math.hypot((mathy4(( + ( ~ y)), x) & ( + (Math.clz32(x) ^ (Math.fround(y) + Math.fround(x))))), (-0x080000001 >>> 0)) | 0)) | 0))); }); testMathyFunction(mathy5, [0x080000001, -0x100000001, 0x080000000, Number.MAX_VALUE, 0/0, -0, Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, -(2**53), 0, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, 1.7976931348623157e308, -0x080000001, 42, 1, 2**53, -0x0ffffffff, -(2**53-2), -0x100000000, 0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=723; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=724; tryItOut("const smauoa, b, clsoas;/*MXX3*/o2.g2.Symbol.prototype = g1.Symbol.prototype\n\nm2.toSource = (function() { ; return s0; });\n");
/*fuzzSeed-28551573*/count=725; tryItOut("print(uneval(e1));");
/*fuzzSeed-28551573*/count=726; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\nv2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: null, sourceIsLazy: true, catchTermination: false }));    }\n    switch ((((0xf474a073) % (0xf570de04)) << (((-131072.0) < (536870912.0))))) {\n    }\n    d0 = (5.0);\n    d0 = (536870913.0);\n    i1 = ((((!((0xe05ffec1) != ((window)>>>(((0x4b6ca630) == (0x51c245c0))))))-((0x7c867280))) >> ((((((0xffffffff))>>>((0x7770f6be))) < (0x82fe6c7c)) ? (0x1e575204) : (i1)))));\n    {\n      i1 = (0x367575d2);\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: function(y) { yield y; h0 + v0;; yield y; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x07fffffff, 1/0, -0x100000000, 1, -0x07fffffff, -0x080000000, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, -0, -Number.MIN_VALUE, 0x080000000, -1/0, -0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53, 42, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, -(2**53), 0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), 2**53+2, 0x0ffffffff, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=727; tryItOut("var jwasxl = new ArrayBuffer(8); var jwasxl_0 = new Float64Array(jwasxl); print(jwasxl_0[0]); var jwasxl_1 = new Float32Array(jwasxl); var jwasxl_2 = new Float32Array(jwasxl); print(jwasxl_2[0]); this.a1.shift(g0, s1, b2);h0.defineProperty = f1;");
/*fuzzSeed-28551573*/count=728; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-28551573*/count=729; tryItOut("o1 = Object.create(s1);\na2.unshift(h1, a2, i2, a2, a0, o0.v1, f0, this.m1, v1, t0, g2.v0, g0.v1, this.s2);\n");
/*fuzzSeed-28551573*/count=730; tryItOut("testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, 0/0, Number.MAX_VALUE, -1/0, -0x0ffffffff, 0x07fffffff, 1, 42, 0x0ffffffff, -0x07fffffff, 0, 0.000000000000001, 0x080000001, 0x080000000, 0x100000001, -0x080000000, Number.MIN_VALUE, 2**53, -(2**53-2), 1.7976931348623157e308, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -0, 2**53+2, -(2**53+2), 1/0, -(2**53), 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=731; tryItOut("\"use strict\"; { void 0; minorgc(false); } ( /x/g );e = Math.pow(9, -14)\n;");
/*fuzzSeed-28551573*/count=732; tryItOut("v1 = this.r2.constructor;");
/*fuzzSeed-28551573*/count=733; tryItOut("\"use strict\"; g2.m0.get(x);");
/*fuzzSeed-28551573*/count=734; tryItOut("{i1.send(o1); }");
/*fuzzSeed-28551573*/count=735; tryItOut("\"use strict\"; g1.v0 = g1.g0.runOffThreadScript();");
/*fuzzSeed-28551573*/count=736; tryItOut("b2.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    i1 = (0xfc2b911a);\n    i1 = ((((0xff8f1a8e))>>>((((i1))|0) / (~((0xfa08ea78)-(0xd2e15b8b)-((0x7fffffff) < (0x23f187ce)))))));\n    d0 = (+(0.0/0.0));\n    i1 = (0xfb22f697);\n    d0 = ((((((d0)) % ((-33554433.0)))) * (((Float64ArrayView[1])))) + (+abs(((d0)))));\n    (Uint32ArrayView[0]) = (((-0x9eee1*(0xffffffff)) | (-0xb0922*( \"\"  >=  /x/g  &= {}))) % (((0x2249ad0c)+((~((0x17ffc156)-((1099511627777.0) <= (-3.094850098213451e+26)))))) ^ ((0xfcf0a2be))));\n    (Uint32ArrayView[0]) = ((((!(i1))+(i1)-(0xbaf8894d))>>>(((w = x)))) % (0x84bb6e76));\n    return +((-8388609.0));\n  }\n  return f; });");
/*fuzzSeed-28551573*/count=737; tryItOut("\"use strict\"; e1.has(g2);");
/*fuzzSeed-28551573*/count=738; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?![^\\\\s\\\\cW-\\\\cU])*?\\\\W{2,}\\\\s|(?:\\\\2)\\\\3+?\", \"ym\"); var s = \"\\n0\\n0\\n0\\n0\\n0\\n0\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=739; tryItOut("const eval = (4277), mubvzn, a, c = intern( '' ), x = \"\\u6051\", x, window;i0.send(this.t2);");
/*fuzzSeed-28551573*/count=740; tryItOut("\"use strict\"; /*RXUB*/var r = /[^]?(?!\\B)|\\2|\\b|\\b|(?:(\\r\\b|\\d\\B){4,})x.|\\S|(?!$){3,}?/gyim; var s = \"\\u0901\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=741; tryItOut("\"use strict\"; g1 = o2;");
/*fuzzSeed-28551573*/count=742; tryItOut("o1.__proto__ = s0;");
/*fuzzSeed-28551573*/count=743; tryItOut("\"use strict\"; e1.delete(e1);");
/*fuzzSeed-28551573*/count=744; tryItOut("\"use strict\"; g2.toString = o0.f2;");
/*fuzzSeed-28551573*/count=745; tryItOut("");
/*fuzzSeed-28551573*/count=746; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.max((Math.tanh(((( ~ y) >>> 0) | 0)) | 0), ( + ( - (x ? ( + -Number.MAX_SAFE_INTEGER) : Math.imul(y, ( + y))))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), 0x080000001, Number.MAX_VALUE, -0, 42, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 0x07fffffff, 0x0ffffffff, 2**53, 0x100000000, 0/0, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -(2**53-2), 0x100000001, Math.PI, -0x080000000, 1/0, -0x100000000, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, -1/0, -0x07fffffff, 2**53+2, -0x100000001]); ");
/*fuzzSeed-28551573*/count=747; tryItOut("/*vLoop*/for (let wohmqz = 0, goagyu; wohmqz < 17; ++wohmqz) { const z = wohmqz; g0.h2 + f0; } ");
/*fuzzSeed-28551573*/count=748; tryItOut("\"use strict\"; g1.p1 = g0.objectEmulatingUndefined();");
/*fuzzSeed-28551573*/count=749; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.max((Math.ceil((Math.fround((Math.fround((mathy1(( + ((((y | 0) * Math.fround(x)) | 0) << Math.atanh(Number.MAX_VALUE))), Math.acosh(y)) >>> 0)) , ((((((x | 0) && (x | 0)) | 0) >>> 0) + (y >>> 0)) >>> 0))) >>> 0)) >>> 0), (Math.imul(( + Math.sign((( + ((y % 2**53+2) || Math.log1p(Math.fround(( + ( ~ ( + y))))))) | 0))), mathy0(Math.acosh(x), y)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-1/0, 0/0, -(2**53+2), Number.MAX_VALUE, 1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, -0x100000000, -Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, 0x080000001, -0x080000001, -(2**53-2), 0, 42, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, -0, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, 1.7976931348623157e308, 1, -0x100000001, 2**53+2]); ");
/*fuzzSeed-28551573*/count=750; tryItOut("\"use asm\"; v0 + '';");
/*fuzzSeed-28551573*/count=751; tryItOut("v1 = (v0 instanceof f0);");
/*fuzzSeed-28551573*/count=752; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[(makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')),  /x/g ,  /x/g ,  /x/g , (makeFinalizeObserver('nursery'))]) { for (var p in e1) { a0.reverse(); } }");
/*fuzzSeed-28551573*/count=753; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=754; tryItOut("testMathyFunction(mathy5, [-0x0ffffffff, 0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 1, 0x07fffffff, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, -0, 0/0, -(2**53+2), -(2**53-2), Number.MAX_VALUE, 2**53, 1.7976931348623157e308, 42, Number.MIN_VALUE, -0x080000001, 0x0ffffffff, -0x100000001, 1/0, 0, -0x080000000, -0x07fffffff, -1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-28551573*/count=755; tryItOut("testMathyFunction(mathy0, /*MARR*/[(void 0), 0x3FFFFFFE, (void 0), x, (void 0), 0x3FFFFFFE, 0x3FFFFFFE, x, x, 0x3FFFFFFE, 0x3FFFFFFE, x, x, (void 0), 0x3FFFFFFE, x, 0x3FFFFFFE, x, x, 0x3FFFFFFE, (void 0), 0x3FFFFFFE, 0x3FFFFFFE, (void 0), 0x3FFFFFFE, x, x, 0x3FFFFFFE, (void 0), (void 0), x, 0x3FFFFFFE, x, x, x, x, (void 0), x, (void 0), x, x, (void 0), (void 0), (void 0), (void 0), x, x, (void 0), x, 0x3FFFFFFE, x, 0x3FFFFFFE, (void 0), (void 0), x, 0x3FFFFFFE, 0x3FFFFFFE, (void 0), 0x3FFFFFFE, (void 0)]); ");
/*fuzzSeed-28551573*/count=756; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot(mathy0((Math.hypot(( + ( ! -Number.MIN_SAFE_INTEGER)), Math.imul((Math.fround(( + Math.fround(y))) | 0), (Math.fround(Math.sqrt(x)) | 0))) | 0), (Math.pow(( - x), Math.fround((( + (( + y) !== ( + ((( + 0x0ffffffff) + y) >>> 0)))) >= Math.fround((Math.sin((0x100000000 | 0)) | 0))))) >>> 0)), mathy0(Math.sign((( + y) | 0)), Math.fround(((Math.fround(( ! Math.fround(x))) | 0) | ( ! ( + ((2**53-2 | 0) === (Math.expm1((x >>> 0)) | 0))))))))); }); testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), /0/, '0', (new Number(0)), ({valueOf:function(){return '0';}}), '\\0', '/0/', (new String('')), NaN, 1, null, 0, (function(){return 0;}), '', [], 0.1, ({toString:function(){return '0';}}), true, undefined, (new Boolean(true)), (new Number(-0)), [0], -0, (new Boolean(false)), false, objectEmulatingUndefined()]); ");
/*fuzzSeed-28551573*/count=757; tryItOut("/*bLoop*/for (var enfswh = 0; enfswh < 22; ++enfswh,  /x/g ) { if (enfswh % 11 == 9) { t0 = t0.subarray(2); } else { g0.g2.offThreadCompileScript(\"m1.toSource = (function() { try { g2 = this; } catch(e0) { } try { this.v1 = undefined; } catch(e1) { } try { g1.offThreadCompileScript(\\\" '' \\\"); } catch(e2) { } Object.freeze(f0); return v0; });\"); }  } ");
/*fuzzSeed-28551573*/count=758; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-28551573*/count=759; tryItOut("\"use strict\"; this.e2.toString = (function() { Array.prototype.reverse.apply(a2, [g1]); return b1; });");
/*fuzzSeed-28551573*/count=760; tryItOut("for (var p in v1) { try { /*MXX3*/g0.Date.prototype.getDate = this.g2.Date.prototype.getDate; } catch(e0) { } try { a0.reverse((/*FARR*/[((x)((yield new true()),  '' )), , Object.defineProperty(z, \"fill\", ({set: mathy4, enumerable: (x % 63 != 51)})) ? ( /x/  += eval) : /*MARR*/[new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Number(1), new Number(1), new Boolean(false), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false)].filter(/*wrap1*/(function(){ print(new RegExp(\"(?![^]){2}|(\\\\1)|\\\\B$|[^\\u7568]+*|[^\\\\t]\", \"\"));return new RegExp(\"(?!(?:(?=\\\\s){3}(?!\\\\b).|.)).|(?!$[^].)*?(?=(\\\\2))\", \"y\")})()), .../*UUV2*/(x.toString = x.sign), (-17 ? \"\\u6723\" : length)].sort((function(x, y) { return Math.hypot(Math.sinh(((( - (Math.clz32(x) >>> 0)) >>> 0) | 0)), (((Math.sqrt((Math.sinh(Math.fround(Math.atan2(Math.fround(-(2**53-2)), Math.fround((Math.fround(y) < Math.fround(y)))))) | 0)) | 0) >= (Math.hypot(-0x080000000, ((y - Math.PI) >>> 0)) | 0)) | 0)); }), function ([y]) { } >>= (void options('strict')) << Math.atanh(11))), h0, this.p0); } catch(e1) { } try { m0.has(g0.a1); } catch(e2) { } g0.__iterator__ = (function mcc_() { var qfwowi = 0; return function() { ++qfwowi; f0(/*ICCD*/qfwowi % 5 == 2);};})(); }");
/*fuzzSeed-28551573*/count=761; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.imul((Math.fround(Math.imul(Math.fround(( ! y)), ( - Math.fround(y)))) | 0), ( + ( ~ ( + Math.abs((Math.min((x | 0), Math.fround(Math.log10(x))) | 0)))))); }); testMathyFunction(mathy4, [0, -(2**53-2), -(2**53+2), 1, Math.PI, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 1/0, 0x100000000, 2**53+2, -0x0ffffffff, -0x100000000, 2**53-2, 0x0ffffffff, -(2**53), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, -0x100000001, -Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -Number.MAX_VALUE, -1/0, -0x080000000, -0, 42, 0x07fffffff]); ");
/*fuzzSeed-28551573*/count=762; tryItOut("\"use strict\"; dxiguv, w, x, rvxzhe, x, c, x;;");
/*fuzzSeed-28551573*/count=763; tryItOut("\"use strict\"; m0.set(this.e2, s0);");
/*fuzzSeed-28551573*/count=764; tryItOut("\"use asm\"; print(new Boolean());");
/*fuzzSeed-28551573*/count=765; tryItOut("mathy0 = (function(x, y) { return ( + Math.hypot(Math.fround(Math.tanh(( + (( + (Math.hypot((Math.atanh((Math.atan2(Math.fround(((x >>> 0) ^ (-0x07fffffff >>> 0))), ( + -Number.MAX_VALUE)) >>> 0)) >>> 0), (Math.atan2(((Math.min(-0x100000001, (x | 0)) | 0) * y), x) >>> 0)) >>> 0)) * ( + x))))), ( + Math.fround(({ sameZoneAs: ([1,,] -= {}), disableLazyParsing: x } ? (((( + ((y >>> 0) === (y >>> 0))) | (x | 0)) | 0) | 0) : Math.fround(( ~ Math.fround(x)))))))); }); testMathyFunction(mathy0, [1/0, -(2**53+2), Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, 2**53-2, 42, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 0, -Number.MAX_VALUE, 2**53, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, Number.MIN_VALUE, 0x080000001, 0x100000001, 1, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, 0/0, 0x080000000, -0x0ffffffff, -0x100000001, -0, 0.000000000000001, 0x0ffffffff, -1/0, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-28551573*/count=766; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.fround((( + Math.hypot((Math.sqrt(((x >>> 0) - ( - x))) | 0), y)) >>> (( - (x | 0)) | 0))) ? Math.atan2(Math.min(( ~ Math.cos(x)), ( + (Math.fround(Math.atan(( + x))) << -1/0))), (((Math.ceil((x / y)) >>> 0) !== ((Math.tanh(((((y | (0.000000000000001 ^ y)) >>> 0) && (((-0 <= x) | ((x - x) >>> 0)) >>> 0)) >>> 0)) | 0) >>> 0)) >>> 0)) : Math.fround(Math.fround(( ~ Math.fround(Math.log(( ! 0x080000000))))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -Number.MAX_VALUE, 42, -0x07fffffff, 0x0ffffffff, 1, 0x100000000, -0, -(2**53+2), -0x080000001, 1/0, -0x100000001, 1.7976931348623157e308, -(2**53), 2**53-2, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, 0, 0.000000000000001, -(2**53-2), 0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, 0/0, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, 0x080000001, 0x07fffffff]); ");
/*fuzzSeed-28551573*/count=767; tryItOut("\"use strict\"; o2.h2 = ({getOwnPropertyDescriptor: function(name) { return s2; var desc = Object.getOwnPropertyDescriptor(this.g2.v2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { m2.has(this.b1);; var desc = Object.getPropertyDescriptor(this.g2.v2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a1 = new Array;; Object.defineProperty(this.g2.v2, name, desc); }, getOwnPropertyNames: function() { /*MXX2*/g0.DataView.prototype.setUint16 = o1;; return Object.getOwnPropertyNames(this.g2.v2); }, delete: function(name) { g2.o2 = s2.__proto__;; return delete this.g2.v2[name]; }, fix: function() { Object.freeze(this.h2);; if (Object.isFrozen(this.g2.v2)) { return Object.getOwnProperties(this.g2.v2); } }, has: function(name) { o2.a1.shift(i2, h0, f0, a1, p0);; return name in this.g2.v2; }, hasOwn: function(name) { Array.prototype.pop.apply(a1, [e1, \"\\u2496\"]);; return Object.prototype.hasOwnProperty.call(this.g2.v2, name); }, get: function(receiver, name) { t1 = new Int8Array(this.v1);; return this.g2.v2[name]; }, set: function(receiver, name, val) { m2.set(f1, e2);; this.g2.v2[name] = val; return true; }, iterate: function() { Object.defineProperty(this, \"this.g2.s2\", { configurable: this, enumerable: false,  get: function() {  return Array.prototype.join.call(a2); } });; return (function() { for (var name in this.g2.v2) { yield name; } })(); }, enumerate: function() { for (var p in v2) { try { m1 = a0[5]; } catch(e0) { } try { a0.push(e1); } catch(e1) { } try { o0.f0 = g2.g2.a2[15]; } catch(e2) { } a0 + ''; }; var result = []; for (var name in this.g2.v2) { result.push(name); }; return result; }, keys: function() { throw b2; return Object.keys(this.g2.v2); } });\nprint(g2);\n");
/*fuzzSeed-28551573*/count=768; tryItOut("\"use strict\"; M: for  each(x in let (NaN = (4277), x = ({//h\nkeys: /*FARR*/[...[], ...[], ].map, constructor: undefined }), b = (/*FARR*/[].map((function(y) { yield y; print(x);; yield y; }).bind)), y, x = (), [] = let (b) function(id) { return id }\u0009) Math.fround(9)) {/*MXX2*/g1.g2.SharedArrayBuffer.length = b1; }");
/*fuzzSeed-28551573*/count=769; tryItOut("s1 += 'x';");
/*fuzzSeed-28551573*/count=770; tryItOut("m0.set(p2, e0);");
/*fuzzSeed-28551573*/count=771; tryItOut("/*tLoop*/for (let x of /*MARR*/[new String(''), new String(''), x, x]) { /* no regression tests found */ }");
/*fuzzSeed-28551573*/count=772; tryItOut("e1 = new Set(s1);");
/*fuzzSeed-28551573*/count=773; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.pow((( + mathy0(Math.fround((Math.fround(((( - Math.fround(((x >> x) && Math.fround(y)))) >>> 0) ? ((y << -Number.MAX_VALUE) >>> 0) : (mathy1(x, x) >>> 0))) ? ( + ((x < (Math.atan2((0.000000000000001 | 0), (y | 0)) | 0)) | 0)) : x)), (x , mathy1((((y >>> 0) & (y >>> 0)) >>> 0), ((-1/0 | 0) - (( ~ y) | 0)))))) >>> 0), (( + (Math.fround(Math.min((2**53+2 | 0), y)) >= Math.fround(( + Math.acosh(0.000000000000001))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-28551573*/count=774; tryItOut("\"use strict\"; print(x)");
/*fuzzSeed-28551573*/count=775; tryItOut("t2 = t2.subarray(9, 11);");
/*fuzzSeed-28551573*/count=776; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 295147905179352830000.0;\n    {\n      i1 = (/*FFI*/ff(((imul((((+(-1.0/0.0)) + (-274877906945.0)) == (d2)), (0xffffffff))|0)), ((+/*FFI*/ff(((d2))))), ((imul((!((((0x5b33068b)-(0xffffffff)-(0x36d42e19)) ^ (((0x3dc666fc) != (-0x8000000)))))), (0x4a4c6791))|0)), ((+/*FFI*/ff())), ((+(1.0/0.0))), ((((Float32ArrayView[2])) % ((d2)))), ((d2)), ((~~(144115188075855870.0))), ((((0xaca6d050)) >> ((0x4dc5db34)))), ((1125899906842624.0)), ((9223372036854776000.0)), ((-17592186044417.0)), ((129.0)), ((1025.0)))|0);\n    }\n    i1 = (i1);\n    i0 = (/*FFI*/ff()|0);\n    i0 = (((((imul(((0xc8d838)), ((0x8f91efaf) != (0x476c95f0)))|0) >= (((0x7fce3b28) % (0x561ea9a5))|0))-( /x/g ))>>>(((((i0)-(0xff40caab))>>>((0x2cc692bb)))))));\n    i0 = (i1);\n    i1 = ((((i1)+(i1))>>>((0x17883867)+((0xd20cc01f) <= (([])>>>((0x1386b3e5)-(0xfceceb53)))))) > (0xf1ca6fbc));\n    return ((((((i1)+(0xb7ddaf5b))>>>((i1))) != (0x1b650a36))-(i0)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -0x07fffffff, 0x0ffffffff, 0x100000000, 0, 0/0, -0, Number.MIN_VALUE, 0.000000000000001, 0x080000001, 1, -0x100000001, -0x080000001, -(2**53+2), 1.7976931348623157e308, -Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x100000001, -(2**53), -(2**53-2), Math.PI, 2**53, Number.MAX_VALUE, 2**53-2, 2**53+2, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000]); ");
/*fuzzSeed-28551573*/count=777; tryItOut("e0.toString = (function(j) { f1(j); });");
/*fuzzSeed-28551573*/count=778; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.hypot((((( + Math.trunc(( + mathy0(y, ( ! Math.fround(y)))))) + ( ! x)) | 0) >>> 0), (Math.atan2(( + (( + 0.000000000000001) , ( + x))), (( + mathy0(( + ( + (Math.fround(y) % y))), ( + x))) / Math.fround(( + 1.7976931348623157e308)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, 0/0, 0.000000000000001, Number.MIN_VALUE, 0x080000000, -(2**53-2), 0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 2**53-2, 0, -0x0ffffffff, 1/0, 2**53, 1, 42, -1/0, 0x07fffffff, -0x100000001, -(2**53), Math.PI, Number.MAX_VALUE, -0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-28551573*/count=779; tryItOut("{}(((void shapeOf( '' )) /= /*FARR*/[new RegExp(\"(.|(?=$))(.|\\\\B)+?|([^])|[^\\u00a8\\u00d5\\\\w](?:^){0,}\", \"yim\"), , -0, -21, ...[], null, null].sort));");
/*fuzzSeed-28551573*/count=780; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return mathy0(Math.abs((mathy0(((( + (-0x100000001 | 0)) >>> 0) >>> 0), (Math.min(Math.fround(x), Math.fround(Math.trunc(Math.cosh((-1/0 ? x : x))))) >>> 0)) >>> 0)), (Math.max(( + (Math.fround(Math.imul(Math.fround(Number.MAX_VALUE), Math.fround(x))) !== Math.expm1(0))), Math.atan2((( - (Math.fround(x) | 0)) ? Math.atanh(0x080000000) : ( ~ x)), Math.fround(Math.expm1(Math.fround(Math.fround(Math.min(Math.fround(y), Math.fround(y)))))))) | 0)); }); ");
/*fuzzSeed-28551573*/count=781; tryItOut("m2.set(i2, t1);");
/*fuzzSeed-28551573*/count=782; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.log2(( ! (Math.hypot((( + Math.ceil((x ^ x))) >>> 0), Math.imul(Math.max((y | 0), y), x)) >>> 0))) >>> 0); }); testMathyFunction(mathy0, [-(2**53-2), 0.000000000000001, 0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -0x080000001, 1, 0/0, -(2**53), 1/0, -(2**53+2), 0x080000000, 2**53-2, -0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, 0x100000001, -0x07fffffff, 42, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, 2**53, 0x0ffffffff, -0]); ");
/*fuzzSeed-28551573*/count=783; tryItOut("testMathyFunction(mathy2, [-(2**53-2), -Number.MIN_VALUE, Math.PI, 0/0, 0x100000001, 0x0ffffffff, 1/0, 0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 2**53+2, -1/0, 0x100000000, -0x100000000, 2**53, Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, -0x080000001, 0.000000000000001, 0x080000000, -0, Number.MIN_VALUE, 1, 0x080000001, 2**53-2, -0x100000001, -(2**53+2), 42, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=784; tryItOut("\"use strict\"; let(d) ((function(){try { a2 = arguments; } catch(d) { /(?:\\w)+|(.)|[^\\s\\s](?![\u00cd-\u00b7\\d\\W])*|[S-\\u1249]{0,511}/gi; } finally { \"\\u67D4\"; } })());for(let a in (x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: this, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })(({})), Object.preventExtensions, ( \"\" ).bind))) throw StopIteration;");
/*fuzzSeed-28551573*/count=785; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=786; tryItOut("mathy1 = (function(x, y) { return mathy0(( + (Math.fround(Math.clz32(mathy0(( + (Math.trunc((y | 0)) | 0)), Math.sinh(x)))) ** (((x >>> 0) , (( + ( + ( + y))) >>> 0)) | 0))), ( + (( ~ (( + 1) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [-(2**53+2), 2**53+2, 0x080000001, -0x080000001, Math.PI, -0x0ffffffff, 42, -0x100000001, 2**53, 1.7976931348623157e308, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, 0, 2**53-2, 0x100000000, -0x07fffffff, 0.000000000000001, 0x100000001, Number.MIN_VALUE, -(2**53), 1, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -(2**53-2), -0, Number.MAX_VALUE, -Number.MAX_VALUE, -1/0, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=787; tryItOut("mathy0 = (function(x, y) { return Math.atanh(Math.fround(Math.fround((Math.fround(( + Math.imul((((-(2**53-2) | 0) | ( + y)) | 0), (( + (Math.fround(y) > ( + 0x07fffffff))) >= Math.log(x))))) << Math.fround(( - Math.acos((Math.min(0x07fffffff, 42) && Math.exp((Math.log2((y | 0)) | 0)))))))))); }); testMathyFunction(mathy0, [0x080000000, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -1/0, -0, 0x0ffffffff, 0x100000001, 0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, 2**53, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, -0x100000000, 2**53+2, -0x080000000, 0.000000000000001, -(2**53-2), -(2**53+2), 0]); ");
/*fuzzSeed-28551573*/count=788; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=789; tryItOut("\"use strict\"; let ({z: b, y: [, , , [, ], [], , [, a], [], {x, window, x: a, \u3056: x, x, x, x, x}], x: x} = x, {x: x, x, y: [c, {x: x, \u3056: [, [{}, {x: arguments[16], x: x, NaN: window}, {d, \u3056: [, [, {}]], z: {window, eval: {}}, y: [, {}]}], , Uint16Array.prototype, ], b: window}\u000d, , , [, , x, , , , ]]} = (void shapeOf((4277))), x, c = yield) { Object.preventExtensions(f0); }");
/*fuzzSeed-28551573*/count=790; tryItOut("\"use strict\"; print(v2);");
/*fuzzSeed-28551573*/count=791; tryItOut("\"use strict\"; /*MXX3*/g1.ReferenceError.prototype.message = g2.ReferenceError.prototype.message;");
/*fuzzSeed-28551573*/count=792; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((mathy1((((x >= ( + mathy1(( + Number.MAX_SAFE_INTEGER), (Number.MIN_SAFE_INTEGER | 0)))) != (( ! y) | 0)) <= ( + x)), Math.fround(Math.asin((Math.hypot((x >>> 0), ((y << y) >>> 0)) >>> 0)))) , Math.fround(mathy0(Math.fround(( - Math.cbrt(x))), Math.fround(Math.max(( + ((y << Math.atan2(((Math.fround(y) !== (x >>> 0)) >>> 0), x)) | 0)), (Math.fround(x) && Math.fround((( + x) >>> 0)))))))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[ \"\" , (0/0), (0/0),  \"\" , (0/0), (0/0), (0/0), (0/0), (0/0), (0/0),  \"\" ,  \"\" , (0/0), (0/0), (0/0),  \"\" ,  \"\" , (0/0),  \"\" , (0/0),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , (0/0), (0/0),  \"\" ,  \"\" , (0/0), (0/0), (0/0), (0/0),  \"\" , (0/0),  \"\" ,  \"\" , (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0),  \"\" ,  \"\" , (0/0), (0/0),  \"\" , (0/0), (0/0),  \"\" ,  \"\" , (0/0), (0/0),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , (0/0),  \"\" ,  \"\" , (0/0), (0/0), (0/0), (0/0),  \"\" , (0/0), (0/0), (0/0), (0/0), (0/0),  \"\" , (0/0), (0/0),  \"\" , (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0),  \"\" ,  \"\" ,  \"\" ,  \"\" ]); ");
/*fuzzSeed-28551573*/count=793; tryItOut("\"use strict\"; this.g1.offThreadCompileScript(\"\\\"use strict\\\"; ( \\\"\\\" );\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 66 != 14) }));");
/*fuzzSeed-28551573*/count=794; tryItOut("mathy1 = (function(x, y) { return Math.sinh(( + Math.log2(( ! Math.clz32(( ~ x)))))); }); testMathyFunction(mathy1, [(function(){return 0;}), '/0/', (new Boolean(true)), (new Number(-0)), '\\0', [], (new String('')), (new Number(0)), 0.1, undefined, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), NaN, '', 0, (new Boolean(false)), -0, null, false, /0/, 1, [0], true, '0']); ");
/*fuzzSeed-28551573*/count=795; tryItOut("m0.has(([z && x]));");
/*fuzzSeed-28551573*/count=796; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -32769.0;\n    var i4 = 0;\n    {\n      d3 = (+pow(((Infinity)), (((i2) ? (-3.777893186295716e+22) : ((((0xad400bbc) ? (268435457.0) : (3.8685626227668134e+25))) - ((((d3)) - ((-9007199254740992.0)))))))));\n    }\n    {\n      (Uint32ArrayView[2]) = ((0x764cc8a) % ((((set = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor:  '' , defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; })(20), (27).bind((makeFinalizeObserver('tenured'))), allocationMarker())))*0x6142e)>>>((Int32ArrayView[4096]))));\n    }\n    i1 = ((imul((!(i4)), (0xfa9af7c6))|0) < (({} = 2.__defineSetter__(\"e\", SharedArrayBuffer)) << (((((0xfb16d332)+(0xc2887c66)+(0xff25a83e)) >> ((0xf8529d86)+(0x7cba928d)-(0x632501d8))) >= (abs((~~((0xf92ae795) ? (3.094850098213451e+26) : (4.722366482869645e+21))))|0)))));\n    d3 = (-3.777893186295716e+22);\n    return +((((17179869184.0)) % ((-72057594037927940.0))));\n  }\n  return f; })(this, {ff: function  x (w) { yield  } }, new ArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[({a: ( /x/g )()}), this, this, this, this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), this, this, this, ({a: ( /x/g )()}), this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), this, this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), this, ({a: ( /x/g )()}), this, this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), this, this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), this, this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), this, ({a: ( /x/g )()}), this, this, this, this, ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()}), ({a: ( /x/g )()})]); ");
/*fuzzSeed-28551573*/count=797; tryItOut("v1 = true;");
/*fuzzSeed-28551573*/count=798; tryItOut("throw w;let(b) ((function(){for(let a in /*FARR*/[.../*MARR*/[(-0), (-0), (-0), new String('q'), ({}), new String('q'), (-0), new String('q'),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , (-0), new String('q'), (-0),  'A' , ({}),  'A' , new String('q'), ({}), ({}), ({}), ({}), ({}), (-0), ({}), (-0),  'A' , (-0), ({}), new String('q'),  'A' , ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), (-0), ({}), ({}),  'A' , (-0), new String('q'), new String('q'), (-0), ({}), ({}),  'A' , new String('q'), ({}), ({}), ({}), (-0), ({}), ({}),  'A' , (-0), new String('q'), ({}),  'A' , ({}), new String('q'), (-0), ({}), new String('q'), new String('q'),  'A' , (-0),  'A' , ({}), ({}), ({}), (-0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), ({}),  'A' , (-0), new String('q'), new String('q'), ({}), ({}), ({}), (-0), (-0),  'A' , (-0), new String('q'), (-0), ({}), (-0), ({}), new String('q'), new String('q'), ({}),  'A' , new String('q'), new String('q'),  'A' , ({}),  'A' ,  'A' ,  'A' , ({}),  'A' , (-0), ({}), new String('q'), ({}), (-0), (-0), new String('q'), new String('q'),  'A' ,  'A' ,  'A' ], true, (4277), (void options('strict')), , /*FARR*/[...[], , /\\2{0,}/yi, null, , \"\\uAD92\", -14, ...[], ,  /x/g ].filter, /*FARR*/[let (eval = -13, w, iwstel, eval, jodxyb, heiawl, x) window].sort(x => x), .../*FARR*/[(void shapeOf(x)), , (makeFinalizeObserver('nursery')), [x]], .../*FARR*/[]]) return () >>= e = undefined;})());");
/*fuzzSeed-28551573*/count=799; tryItOut("/*infloop*/for(let a; /*MARR*/[19, objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MIN_VALUE, 19, 17, 17, -Number.MIN_VALUE, objectEmulatingUndefined(), 19, 19, objectEmulatingUndefined(), -Number.MIN_VALUE, objectEmulatingUndefined(), -Number.MIN_VALUE].map(true); (void shapeOf( /x/g ))) {break L;o2.v2 = s1; }");
/*fuzzSeed-28551573*/count=800; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (i1);\n    i1 = ((((Uint8ArrayView[0])) ^ (((((0xced801e9)-(i1)) ^ (((0x872e23cc))*-0xae8db)) != (((0x450f5586)) | ((0xffffffff)-(0xfd10ca7d)+(0x87b629d6)))))) >= (0x2250885e));\n    return +((Float32ArrayView[2]));\n  }\n  return f; })(this, {ff: Object.prototype.propertyIsEnumerable}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [42, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 1, 0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, -0x080000000, Math.PI, 0x080000000, -1/0, -0x07fffffff, -0x0ffffffff, -0, 1.7976931348623157e308, 0/0, -0x080000001, 0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, 1/0, 0x0ffffffff, -(2**53-2), 0.000000000000001, 0, 0x07fffffff, 2**53]); ");
/*fuzzSeed-28551573*/count=801; tryItOut("\"use strict\"; \"use asm\"; h1.toSource = (function(j) { if (j) { try { v0 + g2; } catch(e0) { } try { Array.prototype.splice.call(g0.a2, 5, new ((new Function(\"v2 = g1.eval(\\\"function f2(m1)  { return \\\\\\\"\\\\\\\\u1677\\\\\\\" } \\\");\")))(\"\\u7C37\",  /x/g )); } catch(e1) { } try { f2 = Proxy.createFunction(h2, f1, f2); } catch(e2) { } a2 = /*MARR*/[false, [(void 0)], false, new String('q'), new String('q'), false, new String('q'), [(void 0)], [(void 0)], [(void 0)], new String('q'), false, false, false, new String('q'), false, [(void 0)], [(void 0)], new String('q'), new String('q'), false, [(void 0)], new String('q'), false, [(void 0)], new String('q'), new String('q'), false, false, [(void 0)], [(void 0)], new String('q'), [(void 0)], false, [(void 0)]]; } else { try { h1.enumerate = f1; } catch(e0) { } try { v0 = t0.length; } catch(e1) { } try { print(g2); } catch(e2) { } o0.m2.has(t1); } });");
/*fuzzSeed-28551573*/count=802; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (Math.expm1(( + Math.max(( + y), ( + Math.tan(Math.hypot(y, Math.pow(0x0ffffffff, Math.cbrt(Math.fround(x))))))))) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[new String(''), new String(''), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0x080000001, null, null, null, null, null, new String(''), null, 0x080000001, new String(''), new String(''), null, 0x080000001, 0x080000001, null, null, new String(''), new String(''), null, 0x080000001, new String(''), null, 0x080000001, null, null, null, null, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, new String(''), null, null, 0x080000001, null, null, 0x080000001, null, null, 0x080000001, new String(''), 0x080000001, new String(''), new String(''), null, null, null, new String(''), null, 0x080000001, 0x080000001, 0x080000001, new String(''), null, 0x080000001, null, new String(''), null, null, new String(''), null, null, null, new String(''), null, null, 0x080000001, null, new String(''), null, null, null, new String(''), null, null, null, null, new String(''), new String(''), null, new String(''), 0x080000001, null, null, null, null, 0x080000001, 0x080000001]); ");
/*fuzzSeed-28551573*/count=803; tryItOut("/*infloop*/for(x in ((Math.abs)(allocationMarker() ? b-- :  /x/g ))){i1.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34) { var r0 = a4 & a28; var r1 = 0 | 0; var r2 = 3 - a18; a27 = r1 + a14; print(r0); r0 = a22 % a7; var r3 = a17 | a23; var r4 = 9 * 6; a21 = 8 + a3; var r5 = a17 | 4; var r6 = 5 | a12; r1 = r4 / a17; var r7 = 1 | a3; var r8 = a8 | a14; var r9 = r7 ^ a18; var r10 = a3 / 3; var r11 = 9 / 5; var r12 = a15 / a6; var r13 = 3 * 0; var r14 = a28 + a31; a27 = 5 & a7; a31 = a8 % x; var r15 = a13 ^ a31; var r16 = r13 / r10; var r17 = r5 & 5; var r18 = a28 | 4; var r19 = a14 / 2; r2 = r10 & r10; print(a14); r14 = a21 * 4; var r20 = a10 - r18; var r21 = 9 % a14; var r22 = r18 * a9; r21 = a26 - 9; var r23 = 6 + 0; var r24 = a31 + a2; var r25 = a17 / 2; var r26 = r21 * r5; var r27 = a11 / r0; var r28 = a19 + a32; a30 = a26 | a18; var r29 = 7 / a25; var r30 = a31 - r29; var r31 = a3 ^ 9; var r32 = 0 + a2; r11 = 6 - a7; var r33 = r12 % r19; r18 = a27 | r28; a5 = a31 & 2; var r34 = r30 ^ 9; var r35 = r22 ^ 0; var r36 = r28 & r1; a3 = a23 | r23; var r37 = 3 * a0; var r38 = a14 ^ 5; var r39 = 5 * 1; var r40 = r1 & a25; r15 = a23 ^ 2; var r41 = r37 | a4; var r42 = r14 + a33; r5 = 0 ^ 4; var r43 = a33 | r36; var r44 = r31 + r17; var r45 = a6 - 3; var r46 = r22 + r12; r0 = r4 ^ r43; var r47 = r36 & 7; a15 = a24 & a11; var r48 = a1 + r18; var r49 = r46 / a23; var r50 = 8 | a5; var r51 = 8 % r44; var r52 = 3 & 7; return a18; }); }");
/*fuzzSeed-28551573*/count=804; tryItOut("a0.forEach();");
/*fuzzSeed-28551573*/count=805; tryItOut("{/* no regression tests found */ }");
/*fuzzSeed-28551573*/count=806; tryItOut("\"use strict\"; e1.toString = (function() { try { b1 + ''; } catch(e0) { } try { print(h1); } catch(e1) { } try { s2 = ''; } catch(e2) { } v1 = (i1 instanceof o1.h0); return this.g1; });");
/*fuzzSeed-28551573*/count=807; tryItOut("print(x);");
/*fuzzSeed-28551573*/count=808; tryItOut("a1.pop(g0, i1, o1.f1, (yield  /x/g ).unwatch(\"prototype\"));");
/*fuzzSeed-28551573*/count=809; tryItOut("/*vLoop*/for (let lmpueq = 0; lmpueq < 167; ++lmpueq) { const a = lmpueq; f1 = (function() { try { o1.i2 = new Iterator(o1.g2.s2, true); } catch(e0) { } try { print(uneval(i0)); } catch(e1) { } try { v1 = (v2 instanceof g2); } catch(e2) { } v1 + o2; throw s2; }); } ");
/*fuzzSeed-28551573*/count=810; tryItOut("M:if(((function sum_slicing(marbxt) { m2.toString = (function mcc_() { var zvwvfp = 0; return function() { ++zvwvfp; if (/*ICCD*/zvwvfp % 5 != 0) { dumpln('hit!'); try { o2 + ''; } catch(e0) { } try { t1.set(a1, ({valueOf: function() { Array.prototype.splice.call(a2, f2);return 12; }})); } catch(e1) { } neuter(b1, \"change-data\"); } else { dumpln('miss!'); h2.get = f2; } };})();; return marbxt.length == 0 ? 0 : marbxt[0] + sum_slicing(marbxt.slice(1)); })(/*MARR*/[null]))) L: {/*MXX1*/o0 = this.g2.DataView.prototype.setUint8;(({})); } else  if ((Math.imul((4277), (\u3056 = this)))) {/*ADP-2*/Object.defineProperty(this.a2, 17, { configurable: true, enumerable: false, get: f2, set: (function() { for (var j=0;j<72;++j) { o2.f0(j%4==1); } }) });print(true); }");
/*fuzzSeed-28551573*/count=811; tryItOut("/*RXUB*/var r = /([](?=(?:([^]|\\b)|[\\u009e-\ua3f0\\uD6EA\\cU-\\cE\u0083]*))|.(G))/y; var s = \"[\\u00d7\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=812; tryItOut("const v2 = undefined;print(x);");
/*fuzzSeed-28551573*/count=813; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 18446744073709552000.0;\n    (Float64ArrayView[((i1)-(i2)-(i1)) >> 3]) = (((0xf4aa9ded) ? (((d3) != (-1023.0)) ? (d0) : (+(0.0/0.0))) : (d0)));\n    i2 = (i2);\n    return +((-68719476736.0));\n  }\n  return f; })(this, {ff:  /x/ }, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [1.7976931348623157e308, -0x100000000, Math.PI, 2**53, -1/0, 0x0ffffffff, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0, -0x080000000, 1, Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, 2**53+2, -0x080000001, 0.000000000000001, -0x100000001, 42, -Number.MIN_VALUE, -(2**53-2), -(2**53), Number.MIN_SAFE_INTEGER, 0, 1/0, 0/0, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-28551573*/count=814; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return Math.min(Math.cos(( - (((x | 0) ? (42 >>> 0) : ( + 1/0)) | 0))), (mathy0(((Math.acosh(Math.fround(Math.sign((x >>> 0)))) ** Math.sign(Math.expm1(y))) | 0), ((( + (-0x100000001 == (x | 0))) - Math.fround((x != Number.MAX_SAFE_INTEGER))) | 0)) & (Math.log1p(Math.fround(y)) ** Math.fround(Math.exp(( ~ mathy2(Math.PI, 42))))))); }); testMathyFunction(mathy4, [1/0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 0x080000001, -0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, 1, 0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, -0x0ffffffff, -0, Math.PI, -(2**53-2), 1.7976931348623157e308, 0.000000000000001, -0x100000001, 0x100000000, 0, Number.MIN_VALUE, 0x07fffffff, -0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, -0x100000000, -0x07fffffff]); ");
/*fuzzSeed-28551573*/count=815; tryItOut("w = (Object.prototype.hasOwnProperty)();/*hhh*/function klkutm(w, eval = ((function too_much_recursion(ewplck) { ; if (ewplck > 0) { ; too_much_recursion(ewplck - 1);  } else {  }  '' ; })(56593)), ...x){print( \"\" );}klkutm(({a2:z2}));");
/*fuzzSeed-28551573*/count=816; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+abs((((0xfe0398b1) ? (-6.044629098073146e+23) : (+(0.0/0.0))))));\n    (Int8ArrayView[((0x608c6ae2)+(!(0x6e99dc1b))) >> 0]) = ((((((new ((uneval(x)))()))*0x4215)>>>((((d1) >= (+(0xffffffff))) ? (i0) : ((((0x5623890c)) ^ ((0xf8b70a65))) < (((0xff5af2c6))|0))))) >= ((((0xab9c0e22)))>>>(((imul((0x4627b1ca), (0xc26c87df))|0) < (0xc9c6e39))))));\n    (Int32ArrayView[((!(i0))) >> 2]) = ((/*FFI*/ff(((d1)), ((9.44473296573929e+21)), ((2047.0)), (((0xfb15*((0xfd8f3a6a) ? (0xdb9ed5b6) : (0x5dda470f))) & (((0xffcac4f8) ? (0xfc91be62) : (0x458269a3))+(!((0xc11af11)))+((0x7c6f1e96) < (0x82b461b8))))), ((16777217.0)), (((((0x1532ce5d))-(0xfed671a8)) ^ ((/*FFI*/ff(((147573952589676410000.0)), ((-17592186044417.0)))|0)+(!(0x6019b50d))))), ((((0x5576490e) / (0x555cc806)) | ((/*FFI*/ff(((-257.0)), ((-1125899906842625.0)), ((-2.4178516392292583e+24)), ((147573952589676410000.0)), ((3.094850098213451e+26)), ((-9223372036854776000.0)))|0)))), ((((0xf90bbdfd)) << ((0x7f128b44)))), ((7.555786372591432e+22)), ((-590295810358705700000.0)), ((1.0009765625)))|0));\n    i0 = (0xfc0e775d);\n    (Float64ArrayView[4096]) = ((36893488147419103000.0));\n    return +((((((i0)+(0xac4fc38d)+(0xf81be2c1))|0)) ? (36893488147419103000.0) : (d1)));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, -0x100000001, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, 2**53+2, 1/0, 42, -Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, -0x100000000, 1, Number.MIN_VALUE, 0x100000000, -0x07fffffff, 0x07fffffff, 0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, 0x080000000, 0.000000000000001, 0, -Number.MIN_VALUE, -(2**53), -0, Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=817; tryItOut("\"use strict\"; e0.toString = f0;{ if (!isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; }");
/*fuzzSeed-28551573*/count=818; tryItOut("this.g1.v2 = Array.prototype.reduce, reduceRight.apply(a0, []);");
/*fuzzSeed-28551573*/count=819; tryItOut("([,,z1]);( /x/g );print(c);");
/*fuzzSeed-28551573*/count=820; tryItOut("e0.has(b0);");
/*fuzzSeed-28551573*/count=821; tryItOut("Array.prototype.sort.apply(a0, [(function() { try { b1 = t2.buffer; } catch(e0) { } try { s1 + ''; } catch(e1) { } /*RXUB*/var r = r0; var s = s2; print(uneval(r.exec(s)));  return e1; }), m0, g2, h1]);");
/*fuzzSeed-28551573*/count=822; tryItOut("for(b in x) {L:with({y: undefined}){return  '' ;true; } }");
/*fuzzSeed-28551573*/count=823; tryItOut("let jhhone, y, z, x = let (y)  /x/ , x = (eval = x), x = x;this.e2.delete(t2);");
/*fuzzSeed-28551573*/count=824; tryItOut("this.a2 = arguments;function eval() /x/g Array.prototype.pop.call(a1);");
/*fuzzSeed-28551573*/count=825; tryItOut("mathy2 = (function(x, y) { return (( ! (( ~ Math.fround(x)) | 0)) / (((( - ( + ((mathy0((y >>> 0), (y >>> 0)) >>> 0) >>> 0))) != (Math.max((Math.fround((( + y) << ((x >>> (y | 0)) | 0))) >>> 0), Math.fround(Math.imul(y, (Math.fround(Math.max(( + -Number.MIN_VALUE), x)) !== y)))) | 0)) !== (( + ( + (( + ((( + x) / ( + ( ~ (Math.atanh((2**53+2 >>> 0)) >>> 0)))) | 0)) * (((x | 0) == (Math.cos(y) | 0)) | 0)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-28551573*/count=826; tryItOut("Array.prototype.forEach.apply(a0, [i0, v1, h1]);");
/*fuzzSeed-28551573*/count=827; tryItOut("\"use strict\"; (window(21));");
/*fuzzSeed-28551573*/count=828; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=829; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Int8ArrayView[2]) = (((((d0)) - (((+(1.0/0.0)) + (d0)))) > (d0))+(i1)+(0xfcaf566f));\n    i1 = ((0xb9eb123d) > (0xe76d6cd9));\n    return (((0x2d6d68d9)+((abs((((((-0x8000000)) << ((-0x8000000))) / (((-0x8000000)) ^ ((0xf844ef46)))) | (((NaN) >= (-16777215.0)))))|0) > (0x7ed94a8a))))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ let d = [[]], mqorhj, x, \u3056, ihrokr, x, z, \u3056;delete p1[9];return (DataView.prototype.getUint16).bind})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53-2), 0, 2**53-2, Math.PI, -1/0, 0/0, -0x100000000, 42, 0x07fffffff, 0x080000000, -0x100000001, 2**53+2, 0x080000001, -0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53), 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -Number.MIN_VALUE, -0, -Number.MAX_VALUE, 0x100000000, 1, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001]); ");
/*fuzzSeed-28551573*/count=830; tryItOut("o0 = e2.__proto__;");
/*fuzzSeed-28551573*/count=831; tryItOut("\"use strict\"; /*bLoop*/for (var tgpegl = 0; tgpegl < 41; ++tgpegl) { if (tgpegl % 14 == 13) { t0 = t1.subarray(6); } else { v0 = g1.eval(\"function this.f2(b0) (\\\"\\\\u9FF2\\\".prototype)\"); }  } ");
/*fuzzSeed-28551573*/count=832; tryItOut("\"use strict\"; a0.pop();");
/*fuzzSeed-28551573*/count=833; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.log(( + ((( ~ (Math.fround(( - Math.fround(y))) >>> 0)) >>> 0) > ( + ( ~ Math.pow(Math.atan2(x, x), 2**53)))))) >>> 0); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0/0, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, Math.PI, -0x100000000, 0x07fffffff, -1/0, -0, -0x080000001, -(2**53-2), -(2**53), -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), 0x0ffffffff, 42, -0x100000001, 0x080000001, 2**53, 2**53-2, -Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, 1/0, -0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-28551573*/count=834; tryItOut("mathy1 = (function(x, y) { return ( + Math.cosh((Math.sinh(Math.fround(Math.fround(Math.hypot(( + (mathy0(y, ( ! (y >>> 0))) > (x | 0))), Math.fround(Math.sqrt(-0x0ffffffff)))))) | 0))); }); testMathyFunction(mathy1, [0x0ffffffff, 0.000000000000001, -(2**53-2), -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, -Number.MAX_VALUE, 0/0, -0, -0x080000000, 1, -0x0ffffffff, -0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 0x07fffffff, -(2**53), -Number.MIN_VALUE, -0x100000000, 0, 0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, 1/0, 2**53-2, 2**53+2, -0x100000001, 2**53, -0x07fffffff, Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-28551573*/count=835; tryItOut("\"use strict\"; v1 = a1.length;");
/*fuzzSeed-28551573*/count=836; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (5.0);\n    }\n    (Uint32ArrayView[((Uint16ArrayView[((i1)) >> 1])) >> 2]) = ((i1)+(/*FFI*/ff((x), ((d0)), ((-36893488147419103000.0)), ((((((0x5c32c3c1))>>>((0x3777c7c7))) % (0xcfc5f0d8)) << (((0x9523bfd1))))), ((~~(d0))), ((((-0x8000000))|0)))|0));\n    return +((-31.0));\n  }\n  return f; })(this, {ff: RegExp.prototype.toString}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53, -0x07fffffff, 42, Number.MIN_VALUE, 0x0ffffffff, 0x100000000, -Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 0.000000000000001, -(2**53), 1.7976931348623157e308, -0x100000001, 0, 2**53+2, 2**53-2, 0x080000000, -0x080000000, -1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, 0x080000001, -(2**53+2), 1/0, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-28551573*/count=837; tryItOut("mathy1 = (function(x, y) { return Math.sqrt(( ~ Math.log(x))); }); testMathyFunction(mathy1, [null, (new Boolean(true)), 0, '', (new Number(0)), true, (new Boolean(false)), (function(){return 0;}), undefined, '0', [], [0], -0, /0/, ({valueOf:function(){return 0;}}), '/0/', objectEmulatingUndefined(), false, 1, (new Number(-0)), NaN, 0.1, ({valueOf:function(){return '0';}}), (new String('')), '\\0', ({toString:function(){return '0';}})]); ");
/*fuzzSeed-28551573*/count=838; tryItOut("/*hhh*/function kcxxbc([[[x]], , b, ], z, ...x){let (x) { g2.offThreadCompileScript(\"v2 = evaluate(\\\"/* no regression tests found */\\\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 3), noScriptRval: /*bLoop*/for (ztdvkk = 0; ztdvkk < 58; ++ztdvkk) { if (ztdvkk % 22 == 9) { print(x); } else { break ; }  } , sourceIsLazy: true, catchTermination: false, elementAttributeName: s1, sourceMapURL: s1 }));\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 3 != 1), noScriptRval: false, sourceIsLazy: true, catchTermination: false })); }}/*iii*/o1.s2 + this.f2;");
/*fuzzSeed-28551573*/count=839; tryItOut("mathy1 = (function(x, y) { return (( ~ ( + (( + ( + mathy0(( + x), ( + Math.fround(( ! Math.fround(y))))))) >= ( + Math.max(( + x), ( ~ y)))))) == (((Math.max(Math.fround(Math.sin(Math.fround(( ! (0x080000000 ? y : y))))), Math.imul(Math.fround(Math.sqrt(0x100000001)), ( + (Math.fround(x) || (( - (x >>> 0)) >>> 0))))) | 0) != (Math.pow((((Math.fround((( + x) + 0x080000000)) >>> 0) >> (Math.expm1(((y | (Math.max(( + y), x) >>> 0)) >>> 0)) >>> 0)) >>> 0), (-0x0ffffffff <= ( + ( + x)))) | 0)) | 0)); }); testMathyFunction(mathy1, [1.7976931348623157e308, -0x0ffffffff, Math.PI, -0x100000000, 0.000000000000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, 42, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, Number.MIN_VALUE, 1, -0x100000001, -0, 0x080000000, -(2**53), 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), -0x080000000, -1/0, -0x080000001, 0x100000000, -0x07fffffff, 0, -Number.MIN_VALUE, 0x080000001, 0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=840; tryItOut("v0 = (f1 instanceof o1.g2);");
/*fuzzSeed-28551573*/count=841; tryItOut("mathy1 = (function(x, y) { return (((((Math.imul(mathy0(Math.fround(y), y), ( + (( + x) >= Math.imul((x | 0), y)))) | 0) >>> (( ! (((-0x080000001 | 0) > Math.fround(y)) | 0)) | 0)) | 0) ? (Math.tanh(Math.fround(Math.imul(x, Math.fround(( + Math.tan(( - (0x100000000 && x)))))))) | 0) : (( + Math.fround(((((y > x) | 0) % ((mathy0((y | 0), (Math.sin(( + y)) | 0)) | 0) | 0)) << ( + Math.atanh((x <= y)))))) >> ((( + Math.ceil(x)) >= (Math.fround(mathy0(Math.fround(0x080000000), Math.fround(x))) >>> 0)) >>> 0))) | 0); }); ");
/*fuzzSeed-28551573*/count=842; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.pow(((Math.atan2(Math.round(((Math.hypot(y, y) >>> 0) ? Math.cbrt(y) : 1.7976931348623157e308)), y) >= (Math.fround(( + Math.max(( + ( ~ x)), (0x07fffffff && Math.acos((((y >>> 0) | (y >>> 0)) >>> 0)))))) | 0)) | 0), Math.imul(Math.ceil(( + ( ~ ( + Math.fround(Math.log1p(Math.fround(( - -Number.MIN_VALUE)))))))), Math.fround(( ~ Math.fround((Math.imul((y >>> 0), (((mathy2((Number.MAX_SAFE_INTEGER >>> 0), (x >>> 0)) >>> 0) === ( + Math.fround(Math.cos(x)))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [0x07fffffff, -(2**53+2), -0, 0x100000001, -0x100000000, 0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, -(2**53), Number.MAX_VALUE, 2**53, 1.7976931348623157e308, 0.000000000000001, Math.PI, -0x080000000, 0x080000001, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 0, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, -0x0ffffffff, -0x080000001, 1, 1/0, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=843; tryItOut("/*RXUB*/var r = /(.+?)?|(?!(?=\u001d))?[^]\ub9d1*?(?:[^])|.*?*?|\\D|.[l-\u5dc2\uaa3b]?/gyim; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-28551573*/count=844; tryItOut("print(a0);with(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })((\"\\u4FC9\")()), Function, Object.prototype.__lookupSetter__))h0.__iterator__ = o1.f1;");
/*fuzzSeed-28551573*/count=845; tryItOut("i2.next();");
/*fuzzSeed-28551573*/count=846; tryItOut("mathy4 = (function(x, y) { return ( ! (( + (Math.min(x, y) && Math.imul((Math.fround(y) ? -0x100000001 : x), x))) >>> 0)); }); testMathyFunction(mathy4, [-0x0ffffffff, 2**53+2, 1/0, -0, 0x100000000, 0/0, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 0, 1.7976931348623157e308, -(2**53), Number.MIN_VALUE, 2**53-2, -Number.MIN_VALUE, 0.000000000000001, 0x100000001, 0x080000001, -0x100000001, 0x080000000, 1, -(2**53+2), -0x100000000, 42, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=847; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 2**53, 0x07fffffff, -(2**53), 0x080000001, -(2**53-2), 0x0ffffffff, 1/0, -0x080000001, Number.MIN_VALUE, 0.000000000000001, -0, -0x100000001, 1, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, 0/0, -1/0, -0x07fffffff, -Number.MIN_VALUE, 0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 2**53-2, -(2**53+2)]); ");
/*fuzzSeed-28551573*/count=848; tryItOut("(c | w);");
/*fuzzSeed-28551573*/count=849; tryItOut("a0 = arguments.callee.caller.arguments;");
/*fuzzSeed-28551573*/count=850; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.max(mathy0(((( + ( + ( + 0x080000001))) | 0) == (((((Math.imul((x | 0), Math.atan(x)) | 0) >>> 0) - ((y ? (x >>> 0) : (Math.acosh((-0x100000001 >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0)), ( + Math.imul(((Math.cbrt(-Number.MAX_VALUE) | 0) >>> 0), (Math.imul((( - -0x100000001) | 0), ( + (-0x080000000 | 0))) >>> 0)))), ( + mathy2(( + (Math.max((( + x) >>> 0), Math.fround((Math.fround(( - ( ~ x))) ** Math.fround(( + (0/0 ? y : -0x080000000)))))) >>> 0)), ( + (( ! (( + (y >>> x)) !== (Math.log((-(2**53-2) | 0)) | 0))) | 0))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 2**53, 0.000000000000001, -0, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000000, 42, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, 0x07fffffff, -1/0, -0x100000001, Number.MIN_VALUE, -0x100000000, -(2**53-2), -(2**53+2), 0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, 1, Math.PI, -0x07fffffff, 0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, -(2**53), 0, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-28551573*/count=851; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ Math.acosh((Math.fround(Math.max(Math.fround(( ~ Math.log10(2**53+2))), Math.fround(Math.fround(( ~ ( + ( ~ ( + x)))))))) | 0))); }); ");
/*fuzzSeed-28551573*/count=852; tryItOut("\"use strict\"; Array.prototype.sort.apply(a2, [(function(j) { if (j) { try { h0.defineProperty = (function(j) { if (j) { try { this.m1 = new WeakMap; } catch(e0) { } (void schedulegc(g1)); } else { try { i0 = new Iterator(h2); } catch(e0) { } delete h1.set; } }); } catch(e0) { } for (var v of v0) { try { i0 = new Iterator(b2); } catch(e0) { } try { for (var v of p1) { b1 = new SharedArrayBuffer(20); } } catch(e1) { } try { s2 += s0; } catch(e2) { } m1.get(m1); } } else { b0.toSource = (function mcc_() { var vvaava = 0; return function() { ++vvaava; if (false) { dumpln('hit!'); try { Array.prototype.splice.apply(a2, [2, ({valueOf: function() { print(x);return 7; }}), v2]); } catch(e0) { } try { t2.set(a0, 3); } catch(e1) { } this.m2.get(g1.o1); } else { dumpln('miss!'); try { print(uneval(t1)); } catch(e0) { } try { neuter(b2, \"change-data\"); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(this.g1, h1); } catch(e2) { } v1 = 0; } };})(); } })]);");
/*fuzzSeed-28551573*/count=853; tryItOut("\"use strict\"; \"use asm\"; { if (!isAsmJSCompilationAvailable()) { void 0; void getLcovInfo(this); } void 0; } qtvzlq(/*UUV2*/(z.normalize = z.all));/*hhh*/function qtvzlq(x = new (a1.unshift(p0))(\nx, ((a) = this)), ...x){v2 = g2.runOffThreadScript();}");
/*fuzzSeed-28551573*/count=854; tryItOut("f2(h2);");
/*fuzzSeed-28551573*/count=855; tryItOut("/*vLoop*/for (deelrw = 0; deelrw < 69; ++deelrw) { let w = deelrw; \"\\u9BCC\"; } ");
/*fuzzSeed-28551573*/count=856; tryItOut("b1 = new ArrayBuffer(12);");
/*fuzzSeed-28551573*/count=857; tryItOut("/*bLoop*/for (var avqgkg = 0; avqgkg < 24; ++avqgkg) { if (avqgkg % 4 == 0) { /* no regression tests found */ } else { (void shapeOf(new RegExp(\"$\\\\1\", \"yim\").yoyo(\"\\uB190\"))); }  } ");
/*fuzzSeed-28551573*/count=858; tryItOut("\"use strict\"; M: for  each(let b in x) {s2 += 'x';print(b); }");
/*fuzzSeed-28551573*/count=859; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( ~ ((Math.cbrt(Math.fround(( ~ Math.fround(1.7976931348623157e308)))) | 0) ? (((Math.pow((Math.fround(( - x)) | 0), Math.fround(x)) == Math.pow((Math.atanh(Math.log1p(y)) >>> 0), Math.fround(( + y)))) ? (Math.log10((((Math.min((x >>> 0), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) , x) | 0)) | 0) : Math.fround(( + ( + (( + x) !== ( + y)))))) | 0) : (Math.max(( + ( + (Math.asinh((( + y) >>> (y >>> 0))) | 0))), Math.fround(Math.asinh(( + Math.imul((((y >>> 0) >= y) >>> 0), x))))) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0, 42, -0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, 0x0ffffffff, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000000, Math.PI, -(2**53-2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, 0, 1/0, 2**53, 0.000000000000001, 0/0, -0x100000001, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, -0x080000000, 0x080000000, Number.MAX_VALUE, 1, -(2**53), -(2**53+2), -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=860; tryItOut("throw StopIteration;let(x) ((function(){return;})());");
/*fuzzSeed-28551573*/count=861; tryItOut("mathy0 = (function(x, y) { return ((( - ((Math.tan(Math.log(x)) > Math.fround(( ~ Math.expm1(y)))) | 0)) | 0) | ( ! Math.log1p((2**53+2 ** ( + y))))); }); testMathyFunction(mathy0, [2**53+2, -Number.MAX_VALUE, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, 0x080000001, 0, 1, -Number.MIN_SAFE_INTEGER, -0, -1/0, 0x07fffffff, 2**53, 0/0, 0x100000000, 0x0ffffffff, Math.PI, -(2**53-2), -0x080000001, 1/0, 0.000000000000001, -Number.MIN_VALUE, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, -(2**53+2), Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, 0x100000001, 0x080000000]); ");
/*fuzzSeed-28551573*/count=862; tryItOut("\"use strict\"; /* no regression tests found */function ((y = Proxy.createFunction(({/*TOODEEP*/})(this.z), function (e)\"use asm\";   var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -2097153.0;\n    {\n      d0 = (d1);\n    }\n    (Int16ArrayView[((((1)*-0xfffff) << ((0xfe480b7c)-(0xffffffff))) / ((-(0x14f733c4)) ^ (((0x1b835af2) == (0x1a1f259d))))) >> 1]) = (-((d1) >= (+(-1.0/0.0))));\n    (Int32ArrayView[(((((0xffffffff))>>>((0x51a0862a)-(0x85e74aec)+(0xffdd20db))) != (0x26f70829))-(((281474976710655.0) != (-1.00390625)) ? ((0x43cf052c) == (0x7fffffff)) : (0xfb709c64))) >> 2]) = ((0xff14667e)+(0xe0499e3f)+(this.__defineGetter__(\"x\", decodeURIComponent)));\n    return (((0xfbb420ea)))|0;\n  }\n  return f;)) ? /*FARR*/[undefined, -8].map(Math.acosh,  '' ) : true).a(x, \u3056, d, getter = x , x ? (/*UUV1*/(x.compile = eval(\"/* no regression tests found */\", this))) : window, x, d, {}, e = (Math.sinh(\"\\u0DC5\")), valueOf, x = x, y, eval, d, y, a = /\\1/im, x, x, x = ({}), w, eval, \u3056, b, a = 2, x, x, eval, NaN, x, y, window, w, c, this.NaN, NaN, x, x, d, y, y =  /x/g , x =  '' , w, b = -18, x, ...x)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1.2089258196146292e+24;\n    return (((0x30515daa)))|0;\n  }\n  return f;((let (z) window));");
/*fuzzSeed-28551573*/count=863; tryItOut("m1.delete(v1);");
/*fuzzSeed-28551573*/count=864; tryItOut("let (x) { /*RXUB*/var r = /\\3{1,}((?!$|(^))|(\u00a9)).(?=(?!\\1{16777217}|.){0}\\1)/gyi; var s = \"\\n\\n\\n\\u441f\\n\\n\\n\\u00a9\\n\\u00a9\"; print(r.test(s)); \nm1.get(x);function d()xprint(-9);function x(w, x, \u3056, z, NaN = 16328342.5, this.e, x, \u3056, mathy3, NaN, x, d, \u3056 = -18, \u3056, x = -18, b, x = \"\\u21C2\", b, c, x, x, \"4\", d, w, w, window = x, w, x, x = -12, x, c, window, \u3056, window, x = -23, \u3056, b, x, x = x, w =  '' , b, this.d = window, window, w, x, x, x, x =  \"\" , x, a, d, a, setter, window =  '' , NaN, x, d, a, w, x, d, x, x =  /x/ , a, a, w, z, window, c, b, e, x, x, eval = \"\\u13A5\", eval, x = false, d, x, b =  '' , b, e, window, x, window, x, d, \u3056, x, c, y, x, x, x =  /x/ , \u3056, \u3056 = true, a, x)x == ag0.g0.a0[11] = 5;\n }");
/*fuzzSeed-28551573*/count=865; tryItOut("\"use strict\"; v0 = g2.eval(\"h0.hasOwn = f2;for (var p in g2.e2) { Array.prototype.pop.call(a1, v1); }\\nprint(x);\\n\");");
/*fuzzSeed-28551573*/count=866; tryItOut("g1.v1 = false;");
/*fuzzSeed-28551573*/count=867; tryItOut("/*RXUB*/var r = new RegExp(\"(?:((?:\\\\2)){4,}){2,}($)|\\\\b|\\\\b|\\\\2^+?\", \"gyi\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-28551573*/count=868; tryItOut("v2 = Object.prototype.isPrototypeOf.call(b1, o1);");
/*fuzzSeed-28551573*/count=869; tryItOut("h1.getPropertyDescriptor = f2;");
/*fuzzSeed-28551573*/count=870; tryItOut("\"use strict\"; f0.toString = (function() { g2.e1.has(true > x); return g2.t1; });");
/*fuzzSeed-28551573*/count=871; tryItOut("x;");
/*fuzzSeed-28551573*/count=872; tryItOut("e1.add(m2);");
/*fuzzSeed-28551573*/count=873; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x080000000, -0x0ffffffff, Number.MAX_VALUE, -0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -(2**53+2), 2**53-2, 0, 0x0ffffffff, -1/0, 2**53+2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, -0, 1, 1.7976931348623157e308, 0x080000001, 0.000000000000001, -(2**53), -0x080000000, 42, 0x100000000, -0x07fffffff, 0x100000001, 2**53]); ");
/*fuzzSeed-28551573*/count=874; tryItOut("/*infloop*/for(var arguments[\"-8\"] = x; ((eval) =  /x/g .y = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: neuter, }; })( /x/g ),  \"\" .valueOf(\"number\")).eval(\"/* no regression tests found */\")) ? x = Proxy.createFunction(({/*TOODEEP*/})(\"\\uF3DF\"), Uint8ClampedArray, Date.prototype.setUTCFullYear) : {}; x) {f0(g0);v2 = (o1 instanceof a0); }");
/*fuzzSeed-28551573*/count=875; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 18446744073709552000.0;\n    var i3 = 0;\n    var d4 = 9.44473296573929e+21;\n    {\n      d2 = (d0);\n    }\n    d4 = (+(-1.0/0.0));\n    return +((((+((d4)))) / ((d0))));\n    return +((131071.0));\n    return +((d4));\n  }\n  return f; })(this, {ff: let (eval, eval, x) x /= (4277)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, 0x080000001, 0/0, Number.MIN_VALUE, 0x07fffffff, 0, 0x100000001, 0x100000000, 1, -0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53), 2**53, 1.7976931348623157e308, 1/0, 42, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, -0x100000000, -0x080000001, Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, 0x0ffffffff, 2**53-2, -0x100000001]); ");
/*fuzzSeed-28551573*/count=876; tryItOut("\"use strict\"; this;function x(d, x, x, a, x, y, d, x, this.x, b, w, x, x, window, w, x, d =  \"\" , x, x = ({}), eval, x = \"\\uF337\", \u3056 =  \"\" , x, x, x, x = \"\u03a0\", y, x, \u3056, x, a, x, x, x, x, w, x, x, x, x, x, x, x, \u3056, x, c, a, y, d = window, x, x, y = (function ([y]) { })(), eval, a, setter = a, c, d =  /x/ , \u3056, x, c, a, x = null, x = 15, eval =  \"\" , b, x, x, e, eval = \"\\uD833\", e, x, x, x) { return (void version(185)) } print(x);");
/*fuzzSeed-28551573*/count=877; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-28551573*/count=878; tryItOut("this.t1 + h1;");
/*fuzzSeed-28551573*/count=879; tryItOut("\"use strict\"; /*bLoop*/for (xcundv = 0, x << window; xcundv < 103; ((void options('strict_mode')).__proto__), ++xcundv, (/*wrap1*/(function(){ \"use strict\"; g0.s0 + g0.p0;return Map.prototype.set})()).bind.prototype) { if (xcundv % 6 == 1) { v0 = (m1 instanceof g0.m0); } else { yield \u0009x; }  } ");
/*fuzzSeed-28551573*/count=880; tryItOut("v0 + '';");
/*fuzzSeed-28551573*/count=881; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (((+atan2((new ((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: Element, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: Date.prototype.toLocaleTimeString, get: function() { return undefined }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; }))(void (void shapeOf( '' )))), ((+pow(((+(1.0/0.0))), ((Float64ArrayView[(((0xffffffff) == (0x21a6aadd))-(i0)) >> 3])))))))) - ((Float64ArrayView[1])));\n    d1 = (((+(0.0/0.0))) / ((NaN)));\n    d1 = (4294967296.0);\n    d1 = (1.015625);\n    d1 = (((+(~~(NaN)))) % ((+(0.0/0.0))));\n    {\n      (Uint32ArrayView[4096]) = (0xfffff*(i0));\n    }\n    i0 = (0xf9b405a2);\n    {\n      (Int8ArrayView[((0x2996ff04) / (((i0)+(0x7f95ad4f))>>>(((0x7270d72f) > (0xad8f125c))))) >> 0]) = ((i0));\n    }\n    {\n      i0 = (!(i0));\n    }\n    d1 = (+(0x0));\n    return (((Uint8ArrayView[((Uint8ArrayView[4096])) >> 0])))|0;\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), function(){}, null, function(){}, function(){}, x, function(){}, x, x, function(){}, null, x, objectEmulatingUndefined(), x, null, function(){}, null, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, null, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-28551573*/count=882; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.imul(((( - (((Math.trunc(( ~ (y >>> 0))) + (x | 0)) | 0) >>> 0)) >>> 0) | 0), Math.log2(Math.log2(((Math.fround(x) > (x >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [-0x080000001, Number.MIN_VALUE, 0x080000000, -1/0, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE, Math.PI, 0x100000000, -(2**53+2), 2**53, -0x100000000, -Number.MIN_VALUE, 2**53+2, -0x080000000, -0x100000001, -0, 1.7976931348623157e308, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, 1, 0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 42, 0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -(2**53-2), -(2**53), 2**53-2]); ");
/*fuzzSeed-28551573*/count=883; tryItOut("\"use strict\"; v0 = g2.a2.every((function() { try { Array.prototype.push.apply(a2, [p2, new RegExp(\"((?:${0})(?!\\\\2))|\\\\3|\\\\3+?*?|.[^]+?\", \"i\"), g1]); } catch(e0) { } try { t1.set(o0.a0, v0); } catch(e1) { } Array.prototype.shift.apply(g2.a1, []); throw h2; }), p0);function \u0009x(x, x = \"\\uEEE1\") { yield /(((?:\\1(?:\\D)+))|\\f.*)/ } g0 = this;");
/*fuzzSeed-28551573*/count=884; tryItOut("print(x);v2 = g2[\"call\"];");
/*fuzzSeed-28551573*/count=885; tryItOut("mathy4 = (function(x, y) { return (( - (Math.log2(Math.fround((Math.atanh((( + (y > Math.atan2(y, x))) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-28551573*/count=886; tryItOut("Object.defineProperty(o0, \"o0.v0\", { configurable: false, enumerable: true,  get: function() {  return 4; } });");
/*fuzzSeed-28551573*/count=887; tryItOut("for (var p in b2) { a1.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18) { var r0 = 2 ^ a6; var r1 = 2 | a7; a12 = a17 ^ 4; print(a9); var r2 = a1 / a9; var r3 = a0 % r1; var r4 = a5 % a17; var r5 = a14 + a5; var r6 = 2 + a14; var r7 = a4 & a1; var r8 = r7 ^ a15; var r9 = a10 + r5; a6 = r0 + 5; var r10 = a7 ^ 0; var r11 = r0 ^ a18; var r12 = a9 * 5; var r13 = r11 - r4; r4 = 5 - 5; var r14 = 1 / r5; var r15 = r2 % r5; var r16 = 1 / a8; var r17 = a17 * r11; var r18 = 6 + x; var r19 = r11 & a2; var r20 = a5 - 8; var r21 = 0 + a0; r8 = a2 / a16; var r22 = a5 + 0; var r23 = 3 ^ a11; var r24 = a16 + r22; var r25 = a0 - 6; a17 = r5 % 8; var r26 = a17 / 1; var r27 = 4 / r15; var r28 = r8 ^ 6; print(r20); var r29 = 5 + r8; var r30 = r4 | r3; r20 = 3 / 8; r17 = 8 & 7; var r31 = r5 % 4; var r32 = 1 - 4; var r33 = 5 - 9; var r34 = a9 / r33; r10 = r8 & r11; var r35 = r33 - r14; var r36 = r21 / a10; var r37 = r32 / 9; var r38 = 8 / r20; var r39 = r30 - 1; r0 = r32 * 9; print(r12); r6 = a12 + a11; r18 = a8 % 1; var r40 = a12 % a6; var r41 = a18 - r33; var r42 = r27 % a8; var r43 = r34 ^ r30; var r44 = 6 + a9; var r45 = r26 & a11; var r46 = r41 * r14; var r47 = r9 % 0; var r48 = a18 / r7; r13 = r33 / a10; var r49 = r23 + a12; var r50 = 1 * a16; r3 = a7 * 8; r1 = r10 * r35; var r51 = 3 ^ r35; var r52 = a18 % r5; a5 = 1 * r9; var r53 = 5 * a7; var r54 = r36 + 4; var r55 = 8 * r15; print(r33); r35 = a10 % r2; r11 = 9 / r43; var r56 = r10 | a2; r54 = 0 | 9; var r57 = 0 | r21; var r58 = r30 | 8; var r59 = 0 + r6; var r60 = 1 & 0; var r61 = 1 + 2; var r62 = a15 ^ r52; a16 = 0 / r37; var r63 = 3 | r33; var r64 = r16 - 5; var r65 = r55 + 5; var r66 = r30 * a16; var r67 = 2 - 9; var r68 = a11 & a12; var r69 = r27 / r49; var r70 = r5 % 4; r61 = a5 * 8; var r71 = r14 % a4; var r72 = r64 | a3; var r73 = 7 - a16; var r74 = r52 | 3; a14 = r15 - r24; var r75 = 2 & 2; print(r74); var r76 = r58 / r6; r6 = r46 - r11; r42 = r20 & r63; var r77 = r8 - 7; a2 = r71 * 1; var r78 = a16 ^ a14; var r79 = 9 | r16; var r80 = r18 % r11; print(r68); var r81 = 3 & 7; var r82 = r65 + 0; print(r25); var r83 = r56 & 3; var r84 = 0 % r20; var r85 = 3 & r8; print(r66); var r86 = 0 ^ r49; var r87 = a3 - 4; var r88 = 3 ^ r0; var r89 = r35 | r71; var r90 = r60 | 4; var r91 = a6 / 8; var r92 = r82 | r69; var r93 = 3 | 9; var r94 = r8 % r75; r30 = 4 - r7; r42 = 5 ^ 4; return a16; }), this.v1); }");
/*fuzzSeed-28551573*/count=888; tryItOut("/*oLoop*/for (let hwqvmi = 0; hwqvmi < 108 && (x); ++hwqvmi) { ; } ");
/*fuzzSeed-28551573*/count=889; tryItOut("mathy3 = (function(x, y) { return ( + Math.tan(( + Math.fround(Math.trunc(Math.fround(Math.imul(( + ( + ( + Math.fround(Math.sqrt(Math.fround(x)))))), ( + y)))))))); }); ");
/*fuzzSeed-28551573*/count=890; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((((0x93eff8c4)) ? ((i0) ? (+ceil(((+(-1.0/0.0))))) : (8193.0)) : (+pow((length), ((Float32ArrayView[(((0x854f9287) != (0xfec7f879))) >> 2]))))));\n    {\n      d1 = (-32768.0);\n    }\n    return +((((+abs(((d1))))) * ((-127.0))));\n    return +((129.0));\n  }\n  return f; })(this, {ff: String.prototype.substr}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[new Number(1.5),  '' ,  '' , false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 0, new Number(1.5), new Number(1.5), 0,  '' , 0, new Number(1.5), x, 0,  '' ,  '' ,  '' , 0, x, new Number(1.5),  '' , 0, 0,  '' , 0, false, false, new Number(1.5), false,  '' , false, new Number(1.5)]); ");
/*fuzzSeed-28551573*/count=891; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! Math.acos(Math.max(( ! -0x100000001), ((( + (( + Math.min(mathy2(x, x), -0x100000001)) >= (( - (x | 0)) | 0))) >> Math.fround(x)) | 0)))); }); ");
/*fuzzSeed-28551573*/count=892; tryItOut("mathy0 = (function(x, y) { return (Math.acos((( + Math.pow(( + Math.cosh(Math.fround(x))), ( + Math.sqrt(1)))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, ['0', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), null, (new Number(-0)), '', (new Number(0)), NaN, (function(){return 0;}), [0], undefined, (new Boolean(false)), true, '\\0', '/0/', objectEmulatingUndefined(), 0, [], -0, 0.1, (new Boolean(true)), /0/, 1, ({valueOf:function(){return 0;}}), false, (new String(''))]); ");
/*fuzzSeed-28551573*/count=893; tryItOut("\"use strict\"; g2.a2 = Array.prototype.filter.apply(a1, [(function(a0, a1) { var r0 = x % 2; var r1 = a0 & 2; var r2 = r0 % 4; r0 = a1 + 0; var r3 = r2 * r1; r0 = r1 | r2; var r4 = r3 ^ 8; a0 = 6 * r4; var r5 = x - r3; var r6 = 5 + r2; a1 = 8 % a0; var r7 = 6 + r4; var r8 = r6 | 4; var r9 = 1 - r5; var r10 = a0 * a1; r3 = a0 & r0; var r11 = 2 | r2; var r12 = r7 + 4; var r13 = a0 & r12; var r14 = r0 % r7; var r15 = r11 - a1; var r16 = x % r12; var r17 = r15 / r4; var r18 = 6 | r17; r9 = r13 % 0; r9 = 6 + 3; var r19 = r16 % 1; var r20 = 2 | r3; print(r16); print(a0); r17 = r10 ^ r7; r9 = r12 % r18; var r21 = r4 + r2; r20 = r15 % 7; var r22 = r6 | r8; var r23 = a1 * 3; var r24 = 6 | r2; var r25 = r6 - r23; print(r1); var r26 = a0 & r7; r22 = r21 * r26; var r27 = r15 | r14; var r28 = a0 - 2; var r29 = 7 + r14; var r30 = r21 % r14; var r31 = r23 ^ 7; r3 = 6 * r0; var r32 = r17 * r15; r7 = r3 | 2; r9 = r16 + r9; var r33 = 3 ^ r14; var r34 = r4 - r4; var r35 = r2 & r23; r0 = r5 / r33; var r36 = 3 & r21; print(r9); var r37 = r10 & r3; var r38 = r28 ^ r10; var r39 = r7 ^ 6; var r40 = r8 & r28; r31 = 5 - r22; r1 = 9 + 8; var r41 = 7 + r3; var r42 = r18 % r18; r38 = 3 % 4; print(r8); var r43 = r23 & 4; var r44 = r21 | r26; var r45 = r26 / 1; print(r45); var r46 = 6 * 0; r7 = 6 ^ 4; var r47 = 5 ^ 0; r29 = r24 ^ 9; var r48 = a1 - 2; var r49 = r36 | 0; var r50 = 4 * r2; r35 = 4 ^ r44; var r51 = 2 | r22; r8 = r11 / r5; var r52 = r42 - r37; var r53 = r25 | x; var r54 = 5 % r50; r42 = r32 * r15; var r55 = 0 ^ r27; var r56 = r37 + r33; var r57 = 8 + r42; var r58 = r32 & r57; var r59 = r50 * 5; r24 = r16 - 1; r8 = 1 * 5; var r60 = 4 * r43; var r61 = r56 | r31; var r62 = r6 - r5; var r63 = r55 & r53; r12 = r50 + r36; var r64 = 6 + r15; var r65 = r31 | r60; var r66 = r60 | 5; var r67 = r21 ^ r11; var r68 = 8 * r59; r24 = r10 & 3; r22 = r25 & r51; var r69 = r51 + r0; var r70 = 2 % r47; var r71 = r60 % 7; var r72 = r25 + 0; var r73 = r31 * r29; var r74 = r37 * 7; var r75 = a1 & r5; var r76 = r74 / r58; var r77 = r71 | r14; var r78 = 9 - 1; var r79 = r29 - r4; r17 = r44 - 3; var r80 = 4 ^ r56; r5 = 8 & r2; var r81 = 3 * r70; var r82 = 4 + 4; var r83 = a1 ^ r13; var r84 = 4 & r13; var r85 = r34 + 1; r75 = 5 - x; var r86 = r22 & r53; print(r3); var r87 = r21 ^ r5; r45 = 1 - 5; r86 = r87 - r87; var r88 = 4 / 0; var r89 = r40 & r74; var r90 = 7 & 8; var r91 = 0 | r62; var r92 = r80 - r6; var r93 = 8 % r75; r67 = 7 + 5; r72 = r44 % r4; var r94 = 5 - 0; var r95 = r42 - r3; print(r59); var r96 = r71 * 6; var r97 = 2 | r52; var r98 = 4 | 2; var r99 = r29 ^ r11; var r100 = r82 & r29; var r101 = x / 3; r6 = 1 | 5; var r102 = r22 & r56; var r103 = r35 + r1; var r104 = r18 & 9; var r105 = r96 + r83; r10 = 5 % r98; var r106 = 7 & r41; var r107 = r89 | r31; print(r71); var r108 = r74 / 4; var r109 = r91 | r68; r9 = 5 * r30; var r110 = 4 ^ r10; var r111 = r33 / r9; r28 = r1 / r12; r22 = r8 - r41; r17 = 9 | r29; var r112 = r10 & r105; var r113 = r15 * r17; r101 = r7 / 2; var r114 = r60 - 5; var r115 = r39 ^ r61; var r116 = r110 - 6; r70 = r4 % r114; r72 = r98 & 8; var r117 = x - 0; var r118 = a0 / 4; r69 = r38 & r77; var r119 = r103 ^ r58; var r120 = x + r76; var r121 = r79 ^ r119; var r122 = 0 - r121; var r123 = r58 | 6; r64 = r20 + 7; r31 = r93 * r91; var r124 = r106 * r63; print(r58); var r125 = 1 % r84; var r126 = r120 % r109; var r127 = r82 & r107; var r128 = r77 % 9; var r129 = 9 & r94; r85 = r35 + r74; var r130 = r75 % 9; var r131 = r85 ^ r92; var r132 = r40 / r93; var r133 = r69 % 2; r101 = 0 & 0; var r134 = r101 ^ r52; var r135 = r3 | 1; var r136 = r111 - 2; r130 = r135 / 1; print(r136); var r137 = 8 - r118; var r138 = 4 % r70; var r139 = 2 & 6; var r140 = r16 / r118; r56 = r23 % r130; var r141 = r66 & r28; var r142 = 2 % r138; var r143 = r81 / 4; r29 = r141 * r46; r83 = 3 ^ r11; var r144 = 4 + r25; var r145 = 6 ^ 8; var r146 = r38 | r124; var r147 = r59 / r66; r120 = r121 & 1; var r148 = r143 & 7; r138 = r43 ^ 2; var r149 = r129 | 6; r79 = 5 | 4; print(r148); r16 = r147 | r96; var r150 = 8 / 3; r139 = r113 | r105; var r151 = r11 & r70; var r152 = r122 - r92; r96 = r45 ^ r97; var r153 = r51 & r77; var r154 = r112 + 8; r1 = 7 ^ r152; r96 = r97 + r83; var r155 = r75 + r77; var r156 = r38 | 6; var r157 = r55 & 5; var r158 = r77 ^ 5; var r159 = 3 % r114; var r160 = 8 - 4; var r161 = r160 * 1; var r162 = 7 ^ r115; var r163 = r105 ^ r117; r50 = r16 ^ 4; var r164 = r10 - 6; var r165 = r97 ^ r14; var r166 = r93 & r83; var r167 = r64 * 1; r7 = 9 * r86; r7 = r130 | r78; print(r0); var r168 = r11 % r109; var r169 = r94 - r76; var r170 = r76 * r84; var r171 = r127 & 5; var r172 = r124 | 7; var r173 = r75 * r111; r155 = 7 - r44; var r174 = 0 + r90; r17 = r68 % r105; r61 = r41 * r168; var r175 = r133 / r112; var r176 = 5 + r173; r77 = r173 % 7; var r177 = r50 % 8; var r178 = r0 / 5; var r179 = r6 / 3; var r180 = r120 - r25; print(r84); var r181 = 2 & r103; r70 = r124 - r133; var r182 = r142 + 7; var r183 = r108 + r94; print(r109); var r184 = 2 & r163; var r185 = r101 - 8; r159 = 4 | 8; var r186 = r165 & r124; var r187 = r152 | 9; var r188 = 2 * r70; var r189 = r151 - 0; print(r172); print(r84); r158 = 5 & r189; r171 = r176 / r65; var r190 = r145 ^ r47; r39 = r22 / 9; var r191 = 5 + r36; var r192 = 5 ^ r32; var r193 = r28 & r28; var r194 = r178 | r118; var r195 = r124 * 8; r181 = r6 * r64; var r196 = 7 - r4; var r197 = 3 / r51; return a0; }), v2, h1]);");
/*fuzzSeed-28551573*/count=894; tryItOut("(x);");
/*fuzzSeed-28551573*/count=895; tryItOut("\"use strict\"; for (var v of p2) { try { f0 = g0.h0; } catch(e0) { } h1.has = f1; }");
/*fuzzSeed-28551573*/count=896; tryItOut("mathy1 = (function(x, y) { return ( - Math.sign(mathy0((Math.fround((Math.fround((Math.fround(y) <= Math.fround(y))) >= y)) >>> 0), (Math.tan(0x0ffffffff) >>> 0)))); }); testMathyFunction(mathy1, /*MARR*/[NaN, function(){}, NaN, NaN, function(){}]); ");
/*fuzzSeed-28551573*/count=897; tryItOut("v0 = (e2 instanceof this.s1);");
/*fuzzSeed-28551573*/count=898; tryItOut("o1.a2 = Proxy.create(g1.h1, a0);");
/*fuzzSeed-28551573*/count=899; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000000, 42, -0x0ffffffff, -0x07fffffff, 2**53+2, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x100000001, Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, 0, 0x100000001, -(2**53), 2**53, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, 0x080000001, -0, -0x080000000, -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, 1, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-28551573*/count=900; tryItOut("i1.send(e1);const v2 = g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-28551573*/count=901; tryItOut("\"use strict\"; ;");
/*fuzzSeed-28551573*/count=902; tryItOut("/*vLoop*/for (let ugwrtg = 0; ugwrtg < 5; ++ugwrtg) { let b = ugwrtg; h2.fix = Date.prototype.toDateString; } ");
/*fuzzSeed-28551573*/count=903; tryItOut("mathy2 = (function(x, y) { return Math.hypot(Math.fround(Math.imul(Math.fround(Math.fround(Math.imul(y, ( - Math.fround(-0x080000001))))), Math.fround(Math.tan(Math.cos(y))))), Math.fround(Math.max(Math.fround(mathy1(( - y), Math.fround((mathy0((y >>> 0), (y >>> 0)) >>> 0)))), ( + Math.round((Math.fround((Math.fround(y) / Math.fround(x))) >>> 0)))))); }); testMathyFunction(mathy2, [-0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, -(2**53+2), -1/0, 0x100000000, Number.MAX_VALUE, 2**53-2, 1/0, -0x080000001, -0x07fffffff, 0x080000001, 0x080000000, 0/0, 1.7976931348623157e308, 0x100000001, 2**53, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 42, -Number.MAX_SAFE_INTEGER, -0, 0, -(2**53-2), 2**53+2, 0.000000000000001, -Number.MIN_VALUE, -(2**53), -0x080000000]); ");
/*fuzzSeed-28551573*/count=904; tryItOut("this.v0 = Array.prototype.reduce, reduceRight.apply(a0, [(function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15) { var r0 = a11 * 9; var r1 = a11 / 3; var r2 = a6 | a1; a5 = a0 ^ a14; var r3 = a13 | 1; var r4 = a15 * 3; var r5 = a6 & a10; return a6; }), v2]);");
/*fuzzSeed-28551573*/count=905; tryItOut("o2.a0.shift(i2);");
/*fuzzSeed-28551573*/count=906; tryItOut("\"use strict\"; ;");
/*fuzzSeed-28551573*/count=907; tryItOut("t1 + i2;");
/*fuzzSeed-28551573*/count=908; tryItOut("/*infloop*/while((4277))s0.toString = f0;");
/*fuzzSeed-28551573*/count=909; tryItOut("\"use strict\"; this.v0 = evalcx(\"function f0(f0)  { (new RegExp(\\\"(?=\\\\\\\\1)|(?:(?:([^\\\\\\\\B-\\\\u1eba]\\\\\\\\b))){255,256}[^#-\\\\\\\\x60\\\\\\\\S](?!\\\\\\\\w){4}(?:(?=\\\\\\\\D|\\\\\\\\D)){2,}\\\", \\\"gyi\\\")); } \", g0.g0);\n/*ODP-1*/Object.defineProperty(h1, \"c\", ({value:  /x/g }));\n");
/*fuzzSeed-28551573*/count=910; tryItOut("/*oLoop*/for (let rtbile = 0; rtbile < 11; ++rtbile) { g0 + p2; } ");
/*fuzzSeed-28551573*/count=911; tryItOut("\"use strict\"; let(b) ((function(){throw eval;})());");
/*fuzzSeed-28551573*/count=912; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.cbrt(Math.fround(( + ((((((Math.min((Math.exp(( + ( + Math.cosh(x)))) | 0), (Math.fround((y >>> y)) | 0)) | 0) >>> 0) ? (( ~ (Math.fround((Math.fround((y / x)) ^ x)) >>> 0)) >>> 0) : (Math.fround(0x080000001) >= ( + ( ! 2**53)))) >>> 0) >>> 0) - ( + Math.fround(Math.clz32((y >>> Math.fround((( + ((0x080000001 ? x : y) | 0)) | 0)))))))))); }); testMathyFunction(mathy4, [0, 2**53+2, -(2**53), Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, -Number.MIN_VALUE, 42, -Number.MAX_VALUE, 0x0ffffffff, 0x080000001, 1/0, -0x100000000, 0.000000000000001, 0/0, -1/0, Math.PI, 1, -0x080000001, 1.7976931348623157e308, 2**53-2, 0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -(2**53+2), -(2**53-2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, 0x100000001, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=913; tryItOut("mathy3 = (function(x, y) { return Math.max(Math.min(( + (42 >>> ( + Math.fround(Math.hypot((Math.log1p(y) >>> 0), ( + x)))))), Math.fround(Math.abs((mathy1(( + y), ( + Math.acosh(y))) >>> 0)))), Math.cosh(Math.hypot((Math.clz32((( - (y ? y : Math.fround(2**53-2))) | 0)) | 0), x))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0.000000000000001, -0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, 2**53, 1.7976931348623157e308, -(2**53+2), -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, -0x100000000, 1/0, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, 0x080000000, 42, 0x100000001, 0x0ffffffff, Math.PI, 0x100000000, -0x07fffffff, 0x080000001, 2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), 0x07fffffff, -0, 0, 2**53-2]); ");
/*fuzzSeed-28551573*/count=914; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.asin(Math.fround(Math.fround(mathy1(( ! ( + x)), y)))) >>> 0) >= Math.max((Math.clz32(Math.atan2(x, x)) ? Math.min(mathy0(((y ** x) >>> 0), (x >>> 0)), -(2**53)) : (mathy0(( + (Math.atan2((Math.sign(-0x080000001) >>> 0), (x >>> 0)) >>> 0)), ( + ((Math.fround(x) ? (( + Math.min(( + -Number.MIN_SAFE_INTEGER), ( + x))) >>> 0) : (x >>> 0)) >>> 0))) | 0)), Math.fround(Math.asin(Math.fround(Math.asinh(Math.fround(y))))))); }); ");
/*fuzzSeed-28551573*/count=915; tryItOut("for (var p in e2) { try { v1 = t2.length; } catch(e0) { } try { for (var p in f1) { try { g0.a0.pop(); } catch(e0) { } try { for (var p in m0) { s2 += o1.s2; } } catch(e1) { } v2 = (o1 instanceof o1); } } catch(e1) { } s0 += s1; }");
/*fuzzSeed-28551573*/count=916; tryItOut("s0.toSource = (function() { try { a0 = []; } catch(e0) { } try { f1.valueOf = (function(j) { if (j) { o1.v2 = evaluate(\"e1.delete(o0.t1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: /\\B/yi, sourceIsLazy: intern(Math.min(25, 11)), catchTermination: true })); } else { try { o0.a1.push(e1, this.m1); } catch(e0) { } try { v2 = (o2 instanceof h0); } catch(e1) { } /*ODP-1*/Object.defineProperty(a1, \"toLocaleString\", ({value: x, writable: true, enumerable: (x % 25 != 18)})); } }); } catch(e1) { } try { Object.prototype.unwatch.call(g1, new String(\"6\")); } catch(e2) { } g0.v2 + s0; return p2; });");
/*fuzzSeed-28551573*/count=917; tryItOut("o0.g2.offThreadCompileScript(\"x\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: true, sourceIsLazy: true, catchTermination: false, element: o1, elementAttributeName: s0, sourceMapURL: s0 }));");
/*fuzzSeed-28551573*/count=918; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy1((( + ( ! ( + Math.clz32(Math.asinh(x))))) >>> 0), ( + Math.atan2(( + Math.ceil(0x100000000)), Math.fround(Math.asin(Math.fround(((y >= ((y - 0x100000000) >>> 0)) + ( + Math.abs(( + mathy0(y, 2**53))))))))))) >>> 0); }); testMathyFunction(mathy3, [1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -0x100000000, 2**53+2, -0x100000001, 0x080000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 0x100000000, -0x080000000, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 0/0, -(2**53), 2**53-2, 1, Math.PI, 0x07fffffff, -1/0, -0x080000001, 1/0, -0, -0x07fffffff, 2**53]); ");
/*fuzzSeed-28551573*/count=919; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=920; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.acosh(Math.fround((Math.cbrt((Math.fround(Math.atan2(Math.fround(((Math.fround(Math.clz32(x)) == y) ** ( + -1/0))), Math.fround(y))) | 0)) | 0))) | 0); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 1, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -1/0, 2**53-2, 2**53+2, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, 2**53, 0, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53), Number.MIN_VALUE, 1/0, 0x080000000, 0/0, 0x100000000, -0x100000001, 0x07fffffff, -0x100000000, -(2**53-2), 0.000000000000001]); ");
/*fuzzSeed-28551573*/count=921; tryItOut("Object.freeze(m0);");
/*fuzzSeed-28551573*/count=922; tryItOut("testMathyFunction(mathy4, /*MARR*/[-Infinity, [(void 0)], [(void 0)], [(void 0)], [(void 0)], -Infinity, -Infinity, -Infinity, -Infinity, [(void 0)], [(void 0)], -Infinity, -Infinity, -Infinity, -Infinity, [(void 0)], -Infinity, [(void 0)], [(void 0)], [(void 0)], -Infinity, -Infinity, -Infinity, [(void 0)], -Infinity, -Infinity, [(void 0)], [(void 0)], [(void 0)], [(void 0)], -Infinity, -Infinity, [(void 0)], -Infinity, [(void 0)], -Infinity, -Infinity, -Infinity, [(void 0)], [(void 0)], -Infinity, -Infinity, -Infinity, [(void 0)], -Infinity, [(void 0)], -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, [(void 0)], -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, [(void 0)], [(void 0)], -Infinity, -Infinity, -Infinity, -Infinity, [(void 0)], -Infinity, [(void 0)], [(void 0)], [(void 0)], -Infinity, -Infinity, -Infinity, -Infinity, [(void 0)], -Infinity, -Infinity, -Infinity, -Infinity, [(void 0)], [(void 0)], -Infinity, [(void 0)], [(void 0)], -Infinity, -Infinity, [(void 0)], -Infinity, [(void 0)], -Infinity, [(void 0)]]); ");
/*fuzzSeed-28551573*/count=923; tryItOut("/*infloop*/while((makeFinalizeObserver('nursery')) %= {} ? \"\\u321E\" : \"\\uF096\")z, NaN =  '' , [] = (new  /x/ ());h1.delete = f0;");
/*fuzzSeed-28551573*/count=924; tryItOut("e0.has(m2);");
/*fuzzSeed-28551573*/count=925; tryItOut("");
/*fuzzSeed-28551573*/count=926; tryItOut("t0.set(a0, 17);");
/*fuzzSeed-28551573*/count=927; tryItOut("let (x = \"\\u2C74\", x, NaN, kbgoll, d, z, x, \u3056, pbzzlt, d) { print((/*UUV2*/(d.setMonth = d.valueOf))); }");
/*fuzzSeed-28551573*/count=928; tryItOut("/*infloop*/for(var c = (allocationMarker()); x; x) g0.t2 + f1;/* no regression tests found */");
/*fuzzSeed-28551573*/count=929; tryItOut("v2 = r2.sticky;");
/*fuzzSeed-28551573*/count=930; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    {\n      (Int8ArrayView[0]) = ((Int16ArrayView[0]));\n    }\n    d1 = (-1.0);\n    return (((i0)-(0xffffffff)+(/*FFI*/ff(((2097153.0)), ((-7.555786372591432e+22)), ((((d1)) * (\nset))), ((((i0)+((-1.1805916207174113e+21) == (-2049.0)))|0)), ((((0xfd81aff1)-(0x8b20763e)) ^ ((0x5eee27e) % (0x2fa1a00e)))), ((((0x1500c637)) >> ((0x6104a072)))))|0)))|0;\n    i0 = (0xe9ebca39);\n    d1 = (d1);\n    {\n      {\n        d1 = ((new (runOffThreadScript)()) ? (+(0.0/0.0)) : (NaN));\n      }\n    }\n    i0 = (/*FFI*/ff(((~(((((Float64ArrayView[0])) << ((0xffffffff))) < (~~((x >>>= x))))))), ((imul(((~~(NaN)) > (imul((0x44155eb2), (i0))|0)), (0xfd57ff06))|0)))|0);\n    return (((0x9936a7bf)+(0x10c757eb)))|0;\n  }\n  return f; })(this, {ff: x.resolve}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[[1], arguments, arguments, function(){}, {}, [1], [1], function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, arguments, function(){}, function(){}, arguments, [1], function(){}, arguments, arguments, function(){}, function(){}, function(){}, function(){}, function(){}, [1], arguments, function(){}, arguments, [1], {}, {}, function(){}, [1], arguments, arguments, function(){}, {}, function(){}, {}, {}, arguments, {}, {}, function(){}, [1], function(){}, arguments, [1], arguments, {}, arguments, [1], function(){}, arguments, {}, function(){}, function(){}, function(){}, [1], arguments, function(){}, {}, function(){}, [1], {}, function(){}, [1], [1], [1], function(){}, {}, function(){}]); ");
/*fuzzSeed-28551573*/count=931; tryItOut("\"use strict\"; t0 = new Float32Array(t2);function x(y, \u3056 = (yield [1,,]), b, x, this, x, y, window, x, x, x = [,], b =  '' , e, e = c, a, x, NaN =  /x/ , x, x, x, \u3056, z, x, x, e, x, x, this, w = /(.)(\\2)/, e, c, x = true, x, z, z =  /x/g , c, x, x, new RegExp(\"($|[^]+|\\\\u|[^\\\\xC4-\\\\u4460]+?)$\", \"gm\"), eval, x, w = ({a1:1}), x, y) { \"use strict\"; return  '' .unwatch(\"pop\") } print(x);");
/*fuzzSeed-28551573*/count=932; tryItOut("for (var p in o2.g1.v2) { try { v2 = a2.length; } catch(e0) { } try { this.o1.a2 = arguments.callee.caller.arguments; } catch(e1) { } m1.get(f0); }");
/*fuzzSeed-28551573*/count=933; tryItOut("\"use strict\"; m2.get(z += w);");
/*fuzzSeed-28551573*/count=934; tryItOut("\"use strict\"; var hnocqp = new ArrayBuffer(16); var hnocqp_0 = new Uint8ClampedArray(hnocqp); print(hnocqp_0[0]); hnocqp_0[0] = 11; var hnocqp_1 = new Uint32Array(hnocqp); print(hnocqp_1[0]); var hnocqp_2 = new Uint32Array(hnocqp); print(hnocqp_2[0]); hnocqp_2[0] = 20; var hnocqp_3 = new Float64Array(hnocqp); print(hnocqp_3[0]); hnocqp_3[0] = 1; var hnocqp_4 = new Int8Array(hnocqp); hnocqp_4[0] = -12; var hnocqp_5 = new Uint32Array(hnocqp); var hnocqp_6 = new Float64Array(hnocqp); s0 = '';var s0 = s0.charAt(((String.prototype.italics)(function ([y]) { })));");
/*fuzzSeed-28551573*/count=935; tryItOut("\"use strict\"; e1.delete(this.a0);");
/*fuzzSeed-28551573*/count=936; tryItOut("\"use strict\"; /*infloop*/for(c; /*UUV2*/(eval.trunc = eval.toString); (4277) * c = 26\n) {a2[v1];( '' ); }");
/*fuzzSeed-28551573*/count=937; tryItOut("print(x);yield (4277);");
/*fuzzSeed-28551573*/count=938; tryItOut("{ void 0; void gc(); }");
/*fuzzSeed-28551573*/count=939; tryItOut("\"use strict\"; /*infloop*/while([([]) = (({/*toXFun*/toSource: (let (e=eval) e) })) for (x of /*FARR*/[]) for each (z in new Array(-262143)) for (a of true = ({})) if (window)])selectforgc(o1.o0);");
/*fuzzSeed-28551573*/count=940; tryItOut("for (var p in i0) { try { /*ADP-1*/Object.defineProperty(a0, 9, ({configurable: true})); } catch(e0) { } try { v1.toString = (function() { try { v1 = Object.prototype.isPrototypeOf.call(a0, p2); } catch(e0) { } a2 = r1.exec(this.s0); return g0.g2; }); } catch(e1) { } try { for (var p in o2) { try { this.e0.add(this.__defineSetter__(\"y\", new Function)); } catch(e0) { } try { Object.freeze(f0); } catch(e1) { } try { f1.__proto__ = t0; } catch(e2) { } delete e2[\"callee\"]; } } catch(e2) { } g2.v2 = g0.runOffThreadScript(); }/*RXUB*/var r = ((e = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function () { \"use strict\"; return window } , getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function() { throw 3; }, set: function() { return true; }, iterate: window, enumerate: undefined, keys: undefined, }; })([[]]), Math.expm1, neuter)).getUTCMonth(x, (b = 21))); var s = \"a_\"; print(s.search(r)); function d(\u3056) { \"use strict\"; \"use asm\"; /*oLoop*/for (let bxcdjf = 0; bxcdjf < 12;  /x/ , ++bxcdjf) {  for  each(e in x) {print(e);/*tLoop*/for (let a of /*MARR*/[true, (-1/0), (-1/0), true]) { print(window); } } }  } v2 = a2.length;");
/*fuzzSeed-28551573*/count=941; tryItOut("{}/*tLoop*/for (let e of /*MARR*/[Infinity,  /x/g , Infinity,  /x/g ,  /x/g ,  /x/g ,  /x/g , Infinity,  /x/g , Infinity, Infinity,  /x/g ,  /x/g ,  /x/g ,  /x/g , Infinity,  /x/g , Infinity,  /x/g , Infinity,  /x/g ,  /x/g ,  /x/g , Infinity,  /x/g ,  /x/g ]) { print((new (mathy1)())); }");
/*fuzzSeed-28551573*/count=942; tryItOut("t2 = new Float64Array(b1);");
/*fuzzSeed-28551573*/count=943; tryItOut("print(uneval(f1));");
/*fuzzSeed-28551573*/count=944; tryItOut("with(x.watch(new (arguments.callee.caller.caller.caller.caller.caller)(\"\\u0BAE\"), function(y) { \"use strict\"; /*RXUB*/var r = /(?!\\b*){2}/ym; var s = \"a\\n\\u5a92 \\\\\\n11\\n1*a\\n\\u5a92 \\\\\\n11\\n1*\"; print(uneval(s.match(r))); print(r.lastIndex);  }))m0.has(p0);const c = x;");
/*fuzzSeed-28551573*/count=945; tryItOut("if(true) a1.pop(); else  if (x) Array.prototype.sort.call(o1.a1, arguments.callee, b1,  /x/ );b0 + ''; else for(let c in ((x)((x)))){print(x); }");
/*fuzzSeed-28551573*/count=946; tryItOut("\"use strict\"; x;");
/*fuzzSeed-28551573*/count=947; tryItOut("for(var w = (p={}, (p.z = /\\B/gym)()) in ({eval: eval(\"(\\n\\\"\\\\u76FF\\\")\", new DataView()), keys: (4277) })) {o0.v2 = (t1 instanceof s0);t1 = t0.subarray(15, 4); }");
/*fuzzSeed-28551573*/count=948; tryItOut("/*RXUB*/var r = /((?:[\\w\u00bc])*){0}/; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-28551573*/count=949; tryItOut("let i0 = e2.entries;");
/*fuzzSeed-28551573*/count=950; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return (( ! Math.fround(mathy1(Math.tanh(((mathy0(-Number.MAX_VALUE, ( + x)) / (Math.fround(mathy3(Math.fround(y), Math.fround(x))) >>> 0)) >>> 0)), ( - Math.min(Math.max((( ~ Number.MAX_VALUE) >>> 0), (x , -0x080000001)), (0/0 < x)))))) >>> 0); }); ");
/*fuzzSeed-28551573*/count=951; tryItOut("\"use strict\"; a0 = arguments.callee.caller.arguments;");
/*fuzzSeed-28551573*/count=952; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=953; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=954; tryItOut("/*infloop*/for(let a = \"\\uEFF4\"; (void version(185)); x) v1 = 4;");
/*fuzzSeed-28551573*/count=955; tryItOut("\"use asm\"; g2.e0.valueOf = f0;a2.push(h0);");
/*fuzzSeed-28551573*/count=956; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.cos(( + ( + ( + ((mathy1((((-0x100000000 | 0) ? 0x100000000 : x) >>> 0), (( + Math.log1p(( + y))) == y)) | 0) | (Math.fround((Math.fround(Math.fround(( ~ Math.fround(0)))) != Math.fround((Math.atan2((x >>> 0), (y >>> 0)) >>> 0)))) | 0))))))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -Number.MIN_VALUE, -0, 0x080000001, 0, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x080000001, -0x080000000, 1.7976931348623157e308, -0x0ffffffff, 0x100000001, Math.PI, -(2**53-2), 2**53-2, Number.MIN_SAFE_INTEGER, 2**53, 2**53+2, 0x07fffffff, -(2**53), 0/0, -1/0, 1/0, 0x080000000, 0x100000000, -(2**53+2), -0x07fffffff, 0.000000000000001, 1, -0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=957; tryItOut("o2.v2 = a1.length;");
/*fuzzSeed-28551573*/count=958; tryItOut("Array.prototype.forEach.apply(a1, [(function() { try { i0.next(); } catch(e0) { } try { a2 = this; } catch(e1) { } Array.prototype.forEach.apply(a1, [f1, m2, x, this.i0]); return o1; })]);");
/*fuzzSeed-28551573*/count=959; tryItOut("var asuerm = new SharedArrayBuffer(3); var asuerm_0 = new Int8Array(asuerm); asuerm_0[0] = -28; v1 = Object.prototype.isPrototypeOf.call(t0, v0);/*bLoop*/for (lyhfcd = 0; lyhfcd < 20; ++lyhfcd) { if (lyhfcd % 5 == 4) { s0 += 'x'; } else { Array.prototype.shift.call(a2, v0); }  } i2 = new Iterator(v1, true);");
/*fuzzSeed-28551573*/count=960; tryItOut("yield\nprint(x);");
/*fuzzSeed-28551573*/count=961; tryItOut("\"use strict\"; const x = x;/* no regression tests found */");
/*fuzzSeed-28551573*/count=962; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.hypot((( - (( + (y | 0)) >>> 0)) >>> 0), ((((( - ( + Math.log10(( - Number.MAX_VALUE)))) | 0) / (-0x080000000 | 0)) | 0) >>> 0)) / (Math.acos(Math.fround(( + Math.fround(1.7976931348623157e308)))) >>> 0)) ? Math.tan((( ! Math.fround(Math.atanh((y >>> 0)))) | 0)) : (( + (Math.fround(Math.sqrt(Math.fround((Math.imul((Math.pow(Math.cos(x), 0x080000001) | 0), ((Math.fround(( ! Math.fround(x))) !== -0x080000000) | 0)) | 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-0x07fffffff, 42, -Number.MIN_VALUE, -(2**53+2), Math.PI, 1/0, 2**53+2, 1.7976931348623157e308, -(2**53), 0/0, -0, 0, -0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, 0x080000000, 1, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, -0x0ffffffff, 0x0ffffffff, 0.000000000000001, -(2**53-2), 0x080000001, Number.MIN_VALUE, -0x100000000, 2**53, -Number.MAX_VALUE, 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-28551573*/count=963; tryItOut("\"use strict\"; p0 = Proxy.create(h0, o2);");
/*fuzzSeed-28551573*/count=964; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[ '' ,  '' , x, new Number(1),  '' , x, x, {},  '' , x, new Number(1), {},  '' , new Number(1), new Number(1), {}, new Number(1), x, {}, x, {},  '' , {}, {}, new Number(1),  '' , x,  '' ,  '' ,  '' ,  '' , {}, new Number(1), new Number(1), new Number(1),  '' , new Number(1), {}, {}, {},  '' , new Number(1), new Number(1), x, x,  '' , {}, new Number(1), x, x, new Number(1),  '' , new Number(1), new Number(1), {}, {}, x,  '' , x,  '' ,  '' , x, x, new Number(1), x, new Number(1), x, {}, x, new Number(1), new Number(1), x, {},  '' , x,  '' ,  '' , x, {},  '' , new Number(1), new Number(1), x, new Number(1),  '' , x, {}, {}, {}, {}, {}, x, x,  '' ,  '' , x, new Number(1), new Number(1), x, x, new Number(1),  '' , {},  '' , {}, {}, {},  '' ,  '' ]) { print(w); }");
/*fuzzSeed-28551573*/count=965; tryItOut("eval = linkedList(eval, 396);");
/*fuzzSeed-28551573*/count=966; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-28551573*/count=967; tryItOut("Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-28551573*/count=968; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0, s2, g0);");
/*fuzzSeed-28551573*/count=969; tryItOut("var e = 'fafafa'.replace(/a/g, (ArrayBuffer).apply);(eval = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: NaN, fix: undefined, has: function() { throw 3; }, hasOwn: Math, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(true), new RegExp(\"^|\\\\B{1,}.{4,}(?!\\\\s)|.+?+*?\", \"gy\").valueOf));");
/*fuzzSeed-28551573*/count=970; tryItOut("/*RXUB*/var r = r0; var s = s0; print(r.test(s)); ");
/*fuzzSeed-28551573*/count=971; tryItOut("\"use strict\"; /*bLoop*/for (rokppx = 0; rokppx < 113; ++rokppx) { if (rokppx % 75 == 61) { b2 + g0.b2; } else { /*ADP-1*/Object.defineProperty(a0, 0, ({value: x, configurable: true, enumerable: (x % 3 != 1)})); }  } ");
/*fuzzSeed-28551573*/count=972; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return Math.min(mathy0((((y << 0x080000000) < ( + ( + (y | 0)))) , ((Number.MAX_VALUE >>> 0) , Math.fround(x))), Math.fround(Math.max(Math.fround(Math.round(( + Math.PI))), Math.imul(x, 0)))), (Math.log1p(Math.imul(Math.fround(((y >> 0.000000000000001) ? y : x)), y)) * (Math.hypot((( + (mathy0(-Number.MAX_VALUE, (0x07fffffff < (x >>> 0))) | 0)) | 0), ( ! Math.max((x | 0), (Math.hypot(Math.asinh(x), y) | 0)))) | 0))); }); testMathyFunction(mathy1, [1, 0.000000000000001, 1/0, 0, -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, 1.7976931348623157e308, -0x0ffffffff, 0x080000000, 42, -0x100000001, 0/0, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -(2**53), -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, 2**53+2, 0x0ffffffff, -0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, -(2**53+2), Number.MAX_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=973; tryItOut("\"use strict\"; /*oLoop*/for (var ulmhlf = 0; ulmhlf < 57 && ((x = intern(new ( /x/g )(8, -6)))); ++ulmhlf) { v1 = Object.prototype.isPrototypeOf.call(o1.b0, t0); } ");
/*fuzzSeed-28551573*/count=974; tryItOut("/*vLoop*/for (var edjdqw = 0; edjdqw < 83; ++edjdqw) { w = edjdqw; v0 = b1.byteLength; } ");
/*fuzzSeed-28551573*/count=975; tryItOut("t2 = new Float64Array(a0);\n\"\\u81B7\";\n\n");
/*fuzzSeed-28551573*/count=976; tryItOut("\"use strict\"; /*infloop*/L:for(let b in (((Float32Array).bind)(eval(\"/*RXUB*/var r = r0; var s = \\\"a\\\"; print(uneval(r.exec(s))); \"))));");
/*fuzzSeed-28551573*/count=977; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + Math.fround(( + ( + (( ! Math.fround(x)) ? Math.trunc(x) : y))))), (((Math.fround(( + Math.atan(( + y)))) ? Math.fround(y) : x) >>> 0) !== (/*FARR*/[] | 0)))); }); testMathyFunction(mathy1, [-0, null, ({valueOf:function(){return 0;}}), 0.1, ({toString:function(){return '0';}}), objectEmulatingUndefined(), '', (function(){return 0;}), /0/, (new Boolean(true)), (new String('')), true, undefined, (new Number(-0)), NaN, (new Number(0)), [0], false, '/0/', ({valueOf:function(){return '0';}}), [], '0', 1, (new Boolean(false)), '\\0', 0]); ");
/*fuzzSeed-28551573*/count=978; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -34359738368.0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 68719476737.0;\n    var i6 = 0;\n    var d7 = 1125899906842623.0;\n    var d8 = 6.189700196426902e+26;\n    {\n      d7 = (257.0);\n    }\n    d0 = (+(0.0/0.0));\n    d7 = (((i3)));\n    {\n      (Float32ArrayView[((-0x8000000)+([z1] ** -19)) >> 2]) = ((((-524288.0)) / (((/*FFI*/ff()|0)+(/*FFI*/ff()|0)))));\n    }\n    (Int8ArrayView[(((((((0xfafa6228)) & ((0xfe7a7602))) / (((-0x8000000))|0))>>>((0xb5a6a15))))) >> 0]) = (((d0) > (d1)));\n    switch ((((-0x8000000)) | (((1.015625) >= (0.0625))+(i6)))) {\n      case 0:\n        i3 = (/*FFI*/ff()|0);\n      default:\n        (Float32ArrayView[((i4)-(i4)) >> 2]) = ((d0));\n    }\n    /*FFI*/ff();\n    return +((d0));\n  }\n  return f; })(this, {ff: (runOffThreadScript).call}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-28551573*/count=979; tryItOut("y = 0.000000000000001;this.a2.unshift(t1, v2);");
/*fuzzSeed-28551573*/count=980; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\3)(?=\\b){3}\\1{0,}\\d|\\B*|(?=\u00eb[^\u17a3\ufc6d\u125f]?)[^]|(?:(\u2cb2))(?!$|[^])(?!^[\\D\\cE])[^\\cZ]\\u0050|\\B(\\3)|(\\d){1}[^\\cF\\s]/gim; var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=981; tryItOut("mathy3 = (function(x, y) { return (mathy2(( ! x), Math.atan2(Math.fround(y), ((Math.asinh((1/0 | 0)) | 0) / x))) ? Math.fround(( - ( + (Math.imul((y | 0), ((y === Math.round(y)) | 0)) | 0)))) : ((( + (Math.abs(y) >> (x ** Math.fround(Math.max((( + ( ! ( + x))) | 0), x))))) << ( + Math.min(( + ( + (Math.fround((Math.min(x, x) ^ y)) >= Math.fround(Math.atan2((y >>> 0), (x | 0)))))), ( + Math.fround(Math.max(2**53-2, ( + y))))))) | 0)); }); testMathyFunction(mathy3, [1.7976931348623157e308, -Number.MAX_VALUE, 0x07fffffff, 0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 1, -(2**53+2), 0x080000000, 2**53, -0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, 42, Number.MAX_VALUE, 0.000000000000001, -1/0, Math.PI, 0, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, 0x100000000, -0, 0x100000001, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=982; tryItOut("this.o0.a0[9]\n");
/*fuzzSeed-28551573*/count=983; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ! (Math.atan(Math.fround(Math.max(Math.fround(Math.ceil(Math.fround((Math.min(( ~ y), -0x080000001) | 0)))), ( - (Math.sinh(Math.PI) >>> x))))) | 0)); }); testMathyFunction(mathy0, [42, 0x080000001, Number.MIN_VALUE, 2**53-2, -(2**53-2), -0x100000001, 1, Number.MAX_VALUE, 0, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, 0x0ffffffff, 0x07fffffff, -(2**53), 1/0, 2**53+2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, -Number.MIN_VALUE, 0.000000000000001, -(2**53+2), 1.7976931348623157e308, -1/0, -0, 0x100000000, 0x100000001, Math.PI]); ");
/*fuzzSeed-28551573*/count=984; tryItOut("/*hhh*/function twdslv(){Array.prototype.forEach.call(a1, f1);}/*iii*/s2 = new String(o2);");
/*fuzzSeed-28551573*/count=985; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - ((((y ? y : (( ! (x >>> 0)) >>> 0)) === 0x080000000) < (x >>> Math.fround(((mathy2(x, Math.fround(Math.max((-Number.MIN_SAFE_INTEGER >>> 0), (2**53+2 >>> 0)))) << y) - (Math.min(2**53-2, 2**53-2) > Math.fround((Math.imul(x, x) | Math.fround(((( + x) >> (x >>> 0)) >>> 0))))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -0x100000000, -(2**53+2), 0x080000000, 2**53+2, Number.MAX_VALUE, -(2**53), -0x080000000, -0x0ffffffff, -1/0, 2**53-2, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, -0, 0x0ffffffff, -0x100000001, Math.PI, 1, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -(2**53-2), -Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1/0, 0/0, 42, Number.MIN_VALUE, 0x080000001, 0]); ");
/*fuzzSeed-28551573*/count=986; tryItOut("L:switch(({a1:1})) { case (window = /[^]/gyim): case 1: if((x % 4 != 2)) {v0 = false; } else (this);break; default: /*vLoop*/for (var inbahc = 0; inbahc < 15; ++inbahc, delete = x) { var a = inbahc; o2.v1 = Object.prototype.isPrototypeOf.call(g1, t0); } break;  }");
/*fuzzSeed-28551573*/count=987; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (( + Math.asin(( ~ Math.min(( + Math.fround(( + Math.fround(Math.hypot(Math.fround(x), Math.PI))))), x)))) / ( + (Math.fround(Math.abs(Math.expm1(Math.PI))) ? ( + ((Math.pow(x, ((Math.imul(x, -(2**53)) & Number.MIN_SAFE_INTEGER) !== -(2**53-2))) >>> 0) ? y : x)) : Math.pow(Math.max(( + Math.min(( + x), ( + ( ! -(2**53+2))))), Math.pow(((0x100000001 && x) | 0), y)), Math.log(0x080000001)))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 2**53-2, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 2**53, 0/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 42, 1/0, -0x080000000, -0x100000001, 0x100000000, 1.7976931348623157e308, 0x07fffffff, -1/0, -0, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), 0x080000001, Math.PI, 1, 0, 2**53+2, -0x080000001]); ");
/*fuzzSeed-28551573*/count=988; tryItOut("/*infloop*/M: for (arguments[\"forEach\"] of (timeout(1800))) let(b) ((function(){yield b;})());");
/*fuzzSeed-28551573*/count=989; tryItOut(" /x/g ;");
/*fuzzSeed-28551573*/count=990; tryItOut("\"use strict\"; h1.delete = f0;");
/*fuzzSeed-28551573*/count=991; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.max(Math.hypot(((Math.imul((Math.fround(y) == (( + Math.max(y, ( + x))) >>> 0)), ( ! y)) >>> 0) ^ (y >>> 0)), (Math.clz32((Math.imul((Math.hypot(( + (Math.fround(y) ? y : ( ! 0x080000000))), ( + Math.min(((-0x0ffffffff >>> 0) ** (y >>> 0)), y))) | 0), y) >>> 0)) >>> 0)), ((( + (Math.atan(Math.exp(x)) | 0)) && mathy0((( ! y) ? (Math.max(y, 0x07fffffff) >> ((0x080000001 ? (((Number.MIN_SAFE_INTEGER | 0) + (x | 0)) | 0) : (Math.fround(Math.abs(y)) | 0)) | 0)) : y), (Math.imul((Math.log1p(( + y)) >>> 0), (y >>> 0)) >>> 0))) | 0)); }); ");
/*fuzzSeed-28551573*/count=992; tryItOut("t2 = new Int16Array(t1);");
/*fuzzSeed-28551573*/count=993; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x07fffffff, 2**53, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -Number.MAX_VALUE, -1/0, -0, -(2**53), 0, -0x080000001, 0x080000001, -0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), 42, Number.MIN_VALUE, -0x0ffffffff, Math.PI, 0.000000000000001, -0x080000000, -0x100000001, 0x0ffffffff, 2**53-2, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000]); ");
/*fuzzSeed-28551573*/count=994; tryItOut("\"use strict\"; /*vLoop*/for (let kgzoiw = 0; kgzoiw < 46; ++kgzoiw) { let w = kgzoiw; Array.prototype.pop.call(this.a0); } ");
/*fuzzSeed-28551573*/count=995; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.imul((( + ((mathy0(Math.fround(Math.log10(Math.fround(-0x07fffffff))), (mathy0((((y | 0) ? 0x080000000 : y) !== ( + x)), x) | 0)) | 0) * ((((Math.pow(y, 42) ** 2**53-2) ? ( + Math.pow(Math.fround((Math.fround((Math.fround(y) === Math.fround(x))) + x)), Math.log(Number.MAX_SAFE_INTEGER))) : (Math.pow(Math.fround(Math.hypot(( + ( - ( + 1.7976931348623157e308))), Math.fround(y))), ( + -Number.MIN_VALUE)) | 0)) | 0) | 0))) >>> 0), (((Math.asin(( + Math.pow(( + Math.fround(mathy0((Math.max((x | 0), (-0x0ffffffff | 0)) >>> 0), (Math.max(y, (y | 0)) >>> 0)))), ( + x)))) >>> 0) ? ((( + (Math.fround(Math.cos(y)) && ( + Math.fround(( - y))))) << x) >>> 0) : (( - (Math.PI | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 1, Number.MIN_VALUE, 0/0, 0x100000000, -1/0, -0x100000000, 0x07fffffff, 0.000000000000001, -(2**53), -0x080000001, 1/0, 0x080000000, -(2**53+2), 2**53-2, 42, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0, -0x080000000, -0, 0x0ffffffff, 2**53, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=996; tryItOut("/*bLoop*/for (siwwex = 0; siwwex < 74; ++siwwex) { if (siwwex % 3 == 0) { return; } else { print(x); }  } ");
/*fuzzSeed-28551573*/count=997; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:(?!\\\\\\u218b{4})))\", \"gi\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=998; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?=\\\\b)+?|.*)+?\", \"gi\"); var s =  /x/g  instanceof z = \"\\uF12C\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-28551573*/count=999; tryItOut("mathy1 = (function(x, y) { return (Math.max(( + ((( ! Math.min(Math.sinh(( + Math.fround((Math.fround(y) & Math.fround(y))))), Math.fround(Math.min(Math.fround(y), Math.fround(Math.max(0x100000001, x)))))) >>> 0) ? (((((Math.sinh((Math.hypot((2**53-2 >>> 0), (y >>> 0)) >>> 0)) - (x >>> 0)) >>> 0) | 0) * Math.fround((Math.fround((x < 2**53)) ^ Math.fround((Math.fround((( - x) || y)) >= Math.fround(y)))))) | 0) : ( ~ x))), (( + (( + (((Math.imul((( + mathy0(x, x)) >>> 0), ( + Math.fround((Math.fround(0x07fffffff) & Math.fround((( + (x | 0)) | 0)))))) | 0) < (Math.asinh(y) | 0)) | 0)) >>> (( ! ((( ! (x >>> 0)) >>> 0) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, -Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, 2**53, Number.MIN_VALUE, 0x100000000, -0, -0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 1, 0x080000001, 2**53+2, 1/0, -Number.MAX_VALUE, 0x080000000, -0x0ffffffff, 2**53-2, -(2**53), -1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 0, Math.PI, 0x100000001, 0.000000000000001, -(2**53+2)]); ");
/*fuzzSeed-28551573*/count=1000; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=1001; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((Math.tan((( ~ ( + Math.fround((-0x100000001 ? y : ((Math.fround(( + y)) | x) >>> 0))))) | 0)) >>> 0) - Math.exp(Math.fround(Math.fround((Math.fround(((x >>> 0) !== y)) >>> Math.fround((( ! ( ! (x >>> 0))) >>> 0))))))) % (Math.abs((( ~ (x | Math.hypot(y, x))) | 0)) >>> 0)); }); testMathyFunction(mathy0, [1, -0x0ffffffff, 0.000000000000001, 2**53-2, 0/0, 1.7976931348623157e308, 0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, -0, 2**53+2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 1/0, -0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 42, -0x07fffffff, -0x080000001, 2**53, -(2**53), 0x100000000, Math.PI, 0x0ffffffff, 0x07fffffff, -0x080000000, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1002; tryItOut("\"use strict\"; /*iii*//*iii*//*MXX3*/g0.Proxy = g0.Proxy;/*hhh*/function eoegec(){print(x);}/*hhh*/function xvwcgy(x = ({/*toXFun*/toString: /*wrap3*/(function(){ var ylkzvu =  /x/g ; (/*wrap1*/(function(){ a0.push(v1, i1, t1);return Array.prototype.concat})())(); }) }), window = (4277), y, x, y = x, \u3056, [], \u3056, c, x, x, w, x, x, a, x = d, x, x, e, x, x, x, \u3056, eval, a, x, window, x, c, x, x =  '' , a, x){if(false) {print(uneval(f2));return; }}");
/*fuzzSeed-28551573*/count=1003; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.sign(Math.fround(( + (Math.fround(( + (Math.sinh(x) & (( + y) | 0)))) % ( + ( + Math.max(Math.fround((((( ~ x) << Math.fround(( + Number.MAX_SAFE_INTEGER))) | 0) ? y : Math.log2((( + Math.tan(( + x))) >>> 0)))), Math.fround(x))))))))); }); testMathyFunction(mathy0, [-0x080000000, -(2**53), -(2**53-2), Math.PI, 0x080000000, -0x07fffffff, 1/0, -0, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, Number.MIN_VALUE, -0x0ffffffff, 0x100000001, 0, 0x07fffffff, 2**53-2, 1.7976931348623157e308, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, -0x080000001, -1/0, 0x0ffffffff, 0x100000000, -(2**53+2), -Number.MIN_VALUE, 2**53+2, 1, -0x100000000, 0x080000001]); ");
/*fuzzSeed-28551573*/count=1004; tryItOut("r0 = new RegExp(\".\", \"y\");");
/*fuzzSeed-28551573*/count=1005; tryItOut("mathy1 = (function(x, y) { return ( ! Math.min(Math.fround(( + Math.fround((((Math.fround((-0x080000000 + (((x >>> 0) + (y >>> 0)) >>> 0))) >>> 0) + ((Math.cos(( + ( ~ y))) ? Math.fround(x) : y) >>> 0)) >>> 0)))), Math.sign(( + ( ~ ( + ( - -0x100000001))))))); }); ");
/*fuzzSeed-28551573*/count=1006; tryItOut("v2 = o0.g1.runOffThreadScript();");
/*fuzzSeed-28551573*/count=1007; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( ~ ((0/0 < ( ~ (mathy2((Math.pow((x >>> 0), y) >>> 0), y) | 0))) && Math.atan2((mathy2(y, ( ! 1)) >>> 0), (mathy2(( + ((0.000000000000001 ? (y >>> 0) : (Math.asin(x) >>> 0)) >>> 0)), y) >>> 0))))); }); ");
/*fuzzSeed-28551573*/count=1008; tryItOut("testMathyFunction(mathy0, [-0x080000001, -(2**53-2), 0/0, 2**53+2, 0.000000000000001, Math.PI, -Number.MAX_VALUE, -(2**53+2), 2**53-2, 0x100000001, 2**53, 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, 0, -0x100000001, -1/0, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, 42, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -0x0ffffffff, -0x080000000, 1, -0, 0x080000000]); ");
/*fuzzSeed-28551573*/count=1009; tryItOut("\"use strict\"; print(x)");
/*fuzzSeed-28551573*/count=1010; tryItOut("with(String()) '' ;");
/*fuzzSeed-28551573*/count=1011; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, -(2**53-2), -0x07fffffff, -1/0, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, -0, 0, -0x080000000, 0x07fffffff, 1, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 1/0, 0x0ffffffff, 0x080000000, 2**53-2, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 0/0, 42, -0x100000000, 0x080000001]); ");
/*fuzzSeed-28551573*/count=1012; tryItOut("yqbjgb, x, \u3056, qzgdjj, get, fgrmks, \u3056, d, x;f0(i2);");
/*fuzzSeed-28551573*/count=1013; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=1014; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=1015; tryItOut("mathy3 = (function(x, y) { return ((Math.fround((((Math.tan(x) === (Math.tanh(Math.sinh((y ? y : 0.000000000000001))) | 0)) | 0) / Math.exp(( - y)))) | 0) + ((( - ( + Math.fround(Math.log10(Math.fround(x))))) >= Math.expm1((Math.acos(Math.sign(( + y))) | 0))) | 0)); }); ");
/*fuzzSeed-28551573*/count=1016; tryItOut("(Math.abs(-2));");
/*fuzzSeed-28551573*/count=1017; tryItOut("o2.v0 = evaluate(\"(4277)\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 3 == 2), sourceIsLazy: true, catchTermination: true }));let b = (4277);");
/*fuzzSeed-28551573*/count=1018; tryItOut("\"use strict\"; /*vLoop*/for (let fsllbb = 0; fsllbb < 11; ++fsllbb) { var a = fsllbb; continue ; } ");
/*fuzzSeed-28551573*/count=1019; tryItOut("mathy5 = (function(x, y) { return (Math.sign(Math.tanh((Math.max(Math.fround(Math.min(y, mathy3(( + -0x07fffffff), (x | 0)))), ( + (y === (( + Number.MIN_SAFE_INTEGER) ? x : (x >>> 0))))) < Math.tan(((Math.min((x >>> 0), ( ! ( + ( - Math.fround(x))))) >>> 0) | 0))))) | 0); }); ");
/*fuzzSeed-28551573*/count=1020; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-28551573*/count=1021; tryItOut("mathy2 = (function(x, y) { return ( - ( ! Math.fround((mathy0((y | 0), x) === ( + 0x100000000))))); }); ");
/*fuzzSeed-28551573*/count=1022; tryItOut("((q => q)(a = Proxy.createFunction(({/*TOODEEP*/})(\"\\uA2A8\"), RangeError.prototype.toString)));");
/*fuzzSeed-28551573*/count=1023; tryItOut("\"use strict\"; s1 += this.g0.s1;");
/*fuzzSeed-28551573*/count=1024; tryItOut("/*bLoop*/for (var unxjsd = 0; unxjsd < 52; ++unxjsd) { if (unxjsd % 5 == 3) { return  /x/g ; } else { s2 = this.s0.charAt(({valueOf: function() { v0 = Object.prototype.isPrototypeOf.call(e1, h1);return 6; }})); }  } \n");
/*fuzzSeed-28551573*/count=1025; tryItOut("/*tLoop*/for (let x of /*MARR*/[undefined,  \"\" , undefined, Infinity, arguments.caller,  \"\" , Infinity, undefined, undefined,  \"\" , Infinity,  \"\" , Infinity, Infinity, undefined,  \"\" , Infinity, Infinity, Infinity, arguments.caller, undefined, arguments.caller, undefined, arguments.caller]) { e2.add(h2); }");
/*fuzzSeed-28551573*/count=1026; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (mathy3(Math.fround((Math.acos((((-0 < (y | 0)) >>> 0) ? (y >>> 0) : ( + y))) >>> 0)), (Math.acos(((Math.atan2((Math.atan2(x, 0x100000000) | 0), ((Math.trunc(y) + (Number.MAX_VALUE ? y : 0x080000000)) >>> 0)) | 0) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy4, [-0, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53, 2**53-2, -1/0, Number.MIN_VALUE, 0x0ffffffff, 42, 0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1, 0x080000000, 0, 2**53+2, 0x100000000, -(2**53+2), -0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, 0/0, 1/0, 0x080000001, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=1027; tryItOut("\"use strict\"; print(x);\nthrow null;\n");
/*fuzzSeed-28551573*/count=1028; tryItOut("\"use strict\"; o2.v0 = a1.length;");
/*fuzzSeed-28551573*/count=1029; tryItOut("/*RXUB*/var r = /(?=(?!(?!(?=[^]|(?=[]\\D))(?=[^\\0-\u00d7])|(?![\u97d9\\t-\u01af\\uA1C2]))|(?!(?:(?=[^])|\u451a+?+?))\\b))/; var s = x; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-28551573*/count=1030; tryItOut("\"use strict\"; { void 0; minorgc(true); } this.a1 = [];");
/*fuzzSeed-28551573*/count=1031; tryItOut("Array.prototype.push.call(a2, x.watch(\"isFinite\", -7), b2, b1, b0, o2.f0);");
/*fuzzSeed-28551573*/count=1032; tryItOut("g1.f2 + this.s2;");
/*fuzzSeed-28551573*/count=1033; tryItOut("\"use strict\"; i0.next();( '' );");
/*fuzzSeed-28551573*/count=1034; tryItOut("/*hhh*/function pqujuj(eval, window = x, eval, x, x, y, \u3056, e, x, \u3056, x, c, x, x =  /x/g , b, x = \"\u03a0\", x, e, b = function(id) { return id }, window, w, x, z = \"\\uCA83\", eval, NaN, d, e = this, b, x, NaN, x, -19, \u3056, x, e, x, a, d, x, NaN = length, x, d, e = undefined, NaN, x, x =  /x/g , x, x, x = \"\\u7308\", x, c = new RegExp(\"(?=[^\\u0084]?)|\\\\1\\u00fd|[\\\\v\\\\s#]|(?:[^]+).+|(\\\\B)|q+?\", \"im\"), x, NaN, a = [,], x, e, e = [1,,], a =  /x/ , y, this, b, \u3056 = window, c = new RegExp(\"\\\\b*|\\\\3|(?=\\\\d[^\\u00f5\\\\cI\\u00b3-\\u19f6\\\\xA8-\\u775f])\\\\3{4}(((?![\\\\u0014-\\\\u5b55\\\\u002f-\\\\x66\\\\cD\\uc3e9])))*\", \"gyi\"), \u3056 = /\\3|[^]|^|.(?=\\D)*?|.{0,}/gm, \u3056, c, x, x, z, x, x, \u3056, c, y =  /x/g , NaN = /(((?:[^]+[^]+?)))+|[^]|\\b?/ym, window =  \"\" , x, b, set, y, x, x, window = false, x = null, c =  /x/ , z, \u3056 = false, \u3056, c =  \"\" , NaN = [,,], x, a, e, x, w, x, x){let gywmeo, yvnflb;\u000cswitch(new RegExp(\"\\\\2(?!\\\\B)?|(?:(?!\\\\d)|[^]\\\\d{8589934591,}){1,}\", \"gyim\")) { default: (new RegExp(\"\\\\u0068\", \"gim\"));break;  }}pqujuj([\u3056 || x]);");
/*fuzzSeed-28551573*/count=1035; tryItOut("mathy3 = (function(x, y) { return ((Math.acosh((Math.fround(( - Math.asinh((x >>> 0)))) >>> 0)) >>> 0) * Math.hypot((((( + (x | 0)) >>> ( + x)) >>> 0) | 0), ( + ( ~ ( + (Math.fround(Math.cos(y)) >= y)))))); }); ");
/*fuzzSeed-28551573*/count=1036; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(Math.imul(Math.hypot(((( - x) >>> 0) >>> (Math.cosh((( + (( + y) / ( + y))) | 0)) | 0)), ( ! (mathy1(Math.fround(Math.hypot(Number.MAX_VALUE, (x | 0))), (Math.sin((x >>> 0)) | 0)) | 0))), Math.atanh(( + ( + Math.clz32(( - (y | 0))))))), ((Math.asin((( + ( ! ((((Math.PI | 0) ? y : ((( - 2**53) | 0) | 0)) | 0) >>> 0))) >>> 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy2, [1/0, 0x080000000, Math.PI, 0/0, -(2**53), 2**53+2, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, 1, -Number.MAX_VALUE, 2**53, 2**53-2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, 0x080000001, -0x080000001, 0x100000000, -0, 0x07fffffff, -0x100000001, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-28551573*/count=1037; tryItOut("\"use strict\"; v2 = evalcx(\"\\\"use strict\\\"; m0.delete(o2.g2.p2);\", g0.g2);");
/*fuzzSeed-28551573*/count=1038; tryItOut("/*infloop*/L:for(b = /(?:(?=(?=(?=.))[\\D])(?=[^]))/gi; w *= window; x) {o0.h2 + ''; }");
/*fuzzSeed-28551573*/count=1039; tryItOut("return window;function x(z)\"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Uint16ArrayView[1]) = ((((((((0xfd2dcc65)-(-0x8000000))>>>((Int8ArrayView[4096]))) == (((0xac56b798) % (0xc084dc5f))>>>((0x28bacc85)-(0x9bf82393))))) & (((((0xfc30d04d))>>>((0xe85c4e54))) <= ( /x/ ))+((((0xa860bf8d)) >> ((0xf87f999c))) < (~~(1.0))))) >= ((((0xbbf797cf))) ^ ((((((0x83cef137) ? (0xbf3fe1c) : (0x9b537395)))>>>((0xfe791cee)-(0xca08f59c))) < ((0x85959*(0xe749abbd))>>>((0xe4b51e66)*-0xfffff))))))*0x3c8d);\n    {\n      i0 = (i0);\n    }\n    return ((((536870913.0) <= (+(~~(+(0.0/0.0)))))))|0;\n  }\n  return f;Array.prototype.shift.apply(a1, [o0]);");
/*fuzzSeed-28551573*/count=1040; tryItOut("mathy5 = (function(x, y) { return ((( - (Math.log10(((( - Math.fround((Math.sign(0/0) | 0))) | 0) >>> 0)) >>> 0)) >>> 0) ** Math.fround((( + (((( + (Math.acosh(2**53) / x)) == (Number.MAX_SAFE_INTEGER | 0)) | 0) % (Math.pow((Number.MAX_VALUE >>> 0), (0x100000001 >>> 0)) >>> 0))) % (Math.log(( + Number.MIN_VALUE)) !== ( + ( ! ( + Number.MAX_SAFE_INTEGER))))))); }); ");
/*fuzzSeed-28551573*/count=1041; tryItOut("\"use strict\"; r1 = new RegExp(\"(\\\\d)\", \"gm\");");
/*fuzzSeed-28551573*/count=1042; tryItOut("\"use strict\"; g1 = this;");
/*fuzzSeed-28551573*/count=1043; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.fround(Math.abs((( + y) > (Math.acos(x) | 0)))))); }); ");
/*fuzzSeed-28551573*/count=1044; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=1045; tryItOut("a1[19] = ({1: ({a2:z2}) /= new RegExp(\"([^\\\\W].{3,6}\\\\B|.*??)|\\\\2{3}\", \"ym\"),  get -20(x, x, c, \u3056, x, window, NaN = new RegExp(\"(?!(?:[\\u17c6\\\\d<=]?)|[\\\\0-\\\\cH\\u00f6\\\\ub47B\\\\u006f]+?)+\\\\w\", \"gim\"), x = /(?!\\\u00da{3})|(?![^]|\\3{1,})/yi, x =  \"\" , x, window, x, x, x =  /x/g , e, NaN, x, x, d, w = new RegExp(\"(?=\\\\3(^)|[^\\\\cS-\\\\xb4\\\\xAD\\u00e3-\\u00af]+?)(?!^?|\\\\w{2,}*?){0,0}(\\\\W+)\", \"gm\"), c = undefined, NaN, c, window, x, x, d, x, x)/*RXUB*/var r = new RegExp(\"(?=\\\\s|\\\\B)|(?!(?!\\\\2*?)+)(?=\\\\S*?)|\\\\3?|\\\\s\\\\w\", \"ym\"); var s = \"0\"; print(s.split(r)); print(r.lastIndex);  });");
/*fuzzSeed-28551573*/count=1046; tryItOut("\"use strict\"; v0 = new Number(t1);\nh0.keys = f1;\n");
/*fuzzSeed-28551573*/count=1047; tryItOut("{ void 0; selectforgc(this); }");
/*fuzzSeed-28551573*/count=1048; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((0xff9ffb2e)+(/*FFI*/ff(((d1)), (((((~((0x357a4ffb) / (0x3a721031))) % ((((Infinity))) & ((0xffffffff) / (0x59682513))))) & (((((0xde02c205))>>>((0xbf4b683c))) == (0xc5edd286))*-0x35853))))|0)))|0;\n    d1 = (16385.0);\n    d1 = (+(0.0/0.0));\n    return (((0x6c05fc0f)-(i0)))|0;\n    switch ((abs((((!(0xf80ec56d))) & ((0x7c593c2))))|0)) {\n      case -3:\n        d1 = (d1);\n        break;\n      case 1:\n        d1 = (-9.44473296573929e+21);\n        break;\n      case -3:\n        {\n          i0 = (-0x8000000);\n        }\n        break;\n      default:\n        i0 = ((0xcd79a6d8));\n    }\n    {\n      {\n        {\n          i0 = (0xc4840116);\n        }\n      }\n    }\n    (Uint16ArrayView[((i0)) >> 1]) = ((imul((0x96f5e85d), (i0))|0) % (0x145c5d6c));\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: new Function}, new ArrayBuffer(4096)); ");
/*fuzzSeed-28551573*/count=1049; tryItOut("\"use asm\"; f2 = Proxy.create(h0, f2);");
/*fuzzSeed-28551573*/count=1050; tryItOut("/*RXUB*/var r = /(?:($)+?)/yim; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-28551573*/count=1051; tryItOut("var awrvzl, y, d, c, csbaus, cfcfze, boqfpw, fhqckv;/* no regression tests found */");
/*fuzzSeed-28551573*/count=1052; tryItOut("\"use strict\"; if((x % 5 == 2)) g0 = o1.t0[17]; else  if ((makeFinalizeObserver('nursery'))) m1.delete(o0.i0); else t0.set(t2, 13);\nthis.t2 + o0.e0;\n");
/*fuzzSeed-28551573*/count=1053; tryItOut("testMathyFunction(mathy4, [0x100000001, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, 42, Number.MIN_VALUE, -0x080000000, 0x080000001, 2**53-2, 0/0, 0x0ffffffff, -0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -(2**53-2), 1, -0x0ffffffff, 0x080000000, 2**53, -0x07fffffff, -(2**53+2), 0x100000000, Math.PI, -1/0, -0, -(2**53), 1.7976931348623157e308, -0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1054; tryItOut("g1.g0 + '';");
/*fuzzSeed-28551573*/count=1055; tryItOut("\"use strict\"; t2[6] = (void options('strict_mode'));");
/*fuzzSeed-28551573*/count=1056; tryItOut("h2.get = f1;");
/*fuzzSeed-28551573*/count=1057; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-28551573*/count=1058; tryItOut("Array.prototype.sort.apply(a2, [(function() { try { var a1 = g0.a1.map((function(a0, a1, a2, a3, a4, a5, a6) { var r0 = a4 + a2; var r1 = a3 - 3; print(a4); var r2 = 1 ^ a2; var r3 = x + 7; var r4 = 8 % a4; a5 = r0 / r3; var r5 = a0 % 0; var r6 = r3 & 5; var r7 = a5 | a6; var r8 = 1 | 0; var r9 = 2 % a6; var r10 = r2 * a6; var r11 = 8 ^ r4; var r12 = 7 % 7; var r13 = a3 % 8; var r14 = r13 & r9; var r15 = x - 0; var r16 = r13 - a5; var r17 = 4 - r9; var r18 = r2 - r4; a1 = r16 + 8; print(x); var r19 = a2 | 6; var r20 = r9 | 8; var r21 = 4 + r8; var r22 = 2 - r21; var r23 = r4 % 3; var r24 = 1 * r11; r9 = 8 & r9; var r25 = r10 / r16; var r26 = 8 ^ 9; var r27 = 8 / 8; var r28 = r10 & r23; var r29 = 5 - r21; var r30 = r21 | r2; var r31 = a5 & r9; print(r13); var r32 = a6 ^ 5; var r33 = 2 % r25; var r34 = 1 | r18; var r35 = r3 & r13; var r36 = a5 - 0; var r37 = r21 - a3; r13 = r26 - r26; var r38 = r2 - r17; var r39 = r20 % r14; r38 = r33 + 7; r24 = r38 - 3; var r40 = r20 + r26; r3 = r9 ^ r37; var r41 = r12 ^ r27; r32 = r28 & 0; a5 = r26 / r12; var r42 = r2 % a3; r25 = r3 | r21; var r43 = r29 & 7; var r44 = r14 | r40; var r45 = r41 - r9; var r46 = 9 - a0; var r47 = r20 % r12; r32 = r42 - r19; var r48 = r27 / a5; var r49 = r32 | r17; var r50 = r42 | r25; var r51 = r18 % r26; print(r50); r19 = a4 & 7; r49 = 1 / 9; r48 = r5 * r39; var r52 = r36 ^ r9; var r53 = r31 - r14; var r54 = 5 + r2; var r55 = r13 - r12; var r56 = r12 ^ 5; var r57 = 9 & 8; var r58 = r53 / r51; var r59 = 4 % r28; var r60 = 0 & 1; var r61 = 2 / 6; var r62 = r44 % r38; var r63 = 0 * r6; var r64 = r17 * a4; var r65 = r24 ^ r2; var r66 = r18 - r20; var r67 = 4 / r56; var r68 = r13 & r55; return a4; })); } catch(e0) { } try { ; } catch(e1) { } print(uneval(g1)); return this.o0; }), v0]);");
/*fuzzSeed-28551573*/count=1059; tryItOut("mathy0 = (function(x, y) { return (Math.atan2(( + ( + Math.fround(Math.round((Math.fround(Math.asinh(Math.fround(Math.asin(-0x0ffffffff)))) | 0))))), (Math.min((Math.log2(-0x100000001) ? (((((( - y) | 0) >>> 0) ? y : (x >>> 0)) >>> 0) , Math.atan2(x, (0 != y))) : Math.fround(( - (Math.sin(y) | 0)))), (( - Math.fround((y , ( + y)))) ^ ((y & ( ~ Math.sqrt(Math.fround(x)))) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-28551573*/count=1060; tryItOut("mathy1 = (function(x, y) { return (Math.atan2((( - ( + (((((Math.hypot(x, (Math.fround((Math.fround(x) | Math.fround(x))) | 0)) ^ (( - ( + ( ~ (y >> 2**53+2)))) >>> 0)) >>> 0) | 0) || (Number.MAX_VALUE | 0)) | 0))) >>> 0), (Math.atan2((Math.hypot((0x07fffffff / (x > x)), Math.fround(Math.max(Math.fround((((y >>> 0) ? ((Math.atan2((2**53-2 | 0), (0x080000000 | 0)) | 0) >>> 0) : (Math.log2(Number.MAX_VALUE) >>> 0)) >>> 0)), Math.fround(y)))) >>> 0), (((Math.min(y, ( + Math.trunc(( + Math.tan((y ? x : x)))))) >>> 0) + Math.log2(( + x))) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-28551573*/count=1061; tryItOut("mathy3 = (function(x, y) { return Math.tanh((Math.round((( + ((y | 0) ** ( + Math.log((mathy0(Math.acosh(y), ((( ! (y | 0)) | 0) >>> 0)) >>> 0))))) | 0)) | 0)); }); testMathyFunction(mathy3, ['', true, 0.1, (new Boolean(true)), '0', (new String('')), '\\0', ({toString:function(){return '0';}}), /0/, [0], (new Boolean(false)), objectEmulatingUndefined(), (function(){return 0;}), (new Number(0)), NaN, false, ({valueOf:function(){return '0';}}), [], undefined, (new Number(-0)), ({valueOf:function(){return 0;}}), null, 0, 1, '/0/', -0]); ");
/*fuzzSeed-28551573*/count=1062; tryItOut("");
/*fuzzSeed-28551573*/count=1063; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + (Math.asin(Math.fround(mathy2((( + ( ~ ( + -1/0))) | Math.fround(( - (0x100000001 >>> 0)))), y))) >= Math.abs((y >> Math.fround(-Number.MIN_SAFE_INTEGER))))) && (Math.max(((Math.hypot(Math.max(Math.fround(Math.hypot(y, Math.fround(x))), y), 42) | 0) <= Math.fround(( ! Math.fround(((mathy1(y, y) | x) >>> 0))))), ((Math.fround(( ! ( + ( + y)))) % ((( + y) || 42) ^ y)) << (( ~ (((Math.imul((((x >>> 0) ** (x >>> 0)) >>> 0), (x | 0)) | 0) || Math.round((0x07fffffff >>> 0))) | 0)) | 0))) >>> 0)); }); testMathyFunction(mathy3, [-0x080000001, -Number.MIN_VALUE, -0x100000000, 0x080000000, -Number.MAX_VALUE, -0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, -1/0, 0/0, 0, 1/0, -0x100000001, -0, Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -(2**53+2), 0x07fffffff, -(2**53), 0x0ffffffff, 0x100000001, 2**53+2, 0.000000000000001, Math.PI, Number.MAX_VALUE, 1, 0x100000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, 0x080000001]); ");
/*fuzzSeed-28551573*/count=1064; tryItOut("\"use strict\"; \"use asm\"; a2[({valueOf: function() { o2.h0.get = f0;w = ((([]) = x)\n);return 16; }})] = null;");
/*fuzzSeed-28551573*/count=1065; tryItOut("mathy4 = (function(x, y) { return Math.hypot((Math.asin(( + mathy3(Math.fround(Math.max(y, ( + ( + (-Number.MAX_VALUE | Math.log(x)))))), Math.fround(42)))) | 0), (Math.sqrt((( ~ ((Math.imul(Math.fround(x), ((function handlerFactory() {return {getOwnPropertyDescriptor: window, getPropertyDescriptor: [[]], defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: arguments.callee, fix: function() { throw 3; }, has: function() { throw 3; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { return x[name]; }, set: Object, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(window) | 0)) | 0) | 0)) | 0)) , ( + ( + Math.max(( + ( + -Number.MIN_VALUE)), ( ~ y)))))); }); testMathyFunction(mathy4, [-0x080000000, Math.PI, 2**53-2, 42, 2**53, -(2**53-2), 0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 0x080000001, 0x100000000, -0x0ffffffff, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, -0x080000001, 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, 0, -1/0, 0/0, -0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-28551573*/count=1066; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.pow(Math.max(( ~ ( - Math.fround(( - Math.fround(x))))), Math.hypot(y, (Math.hypot((x >>> 0), (y >>> 0)) >>> 0))), ( ~ ( + ( + ((Math.log2((x | 0)) | 0) >>> 0))))); }); testMathyFunction(mathy2, [-(2**53+2), -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -Number.MIN_VALUE, -1/0, 2**53-2, 1.7976931348623157e308, 0x100000001, 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -Number.MAX_VALUE, -0x100000001, 1, -0x080000000, -0, 0x100000000, 2**53, 1/0, Number.MAX_VALUE, 2**53+2, 0/0, 0x080000000, 42, 0x0ffffffff, -(2**53), -0x100000000, -0x0ffffffff, 0x07fffffff, 0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1067; tryItOut("\"use strict\"; f0 = Proxy.create(h2, b0);");
/*fuzzSeed-28551573*/count=1068; tryItOut("\"use strict\"; /*vLoop*/for (ilednf = 0; ilednf < 5; ++ilednf) { let x = ilednf; g1.a1.sort(objectEmulatingUndefined); } ");
/*fuzzSeed-28551573*/count=1069; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (NaN);\n    d0 = (+((+(-1.0/0.0))));\n    /*FFI*/ff(((d0)));\n    d0 = ((!((0xc4d84ef5))) ? ((((0x90c7f*(0xea29f4eb)) << ((0xd67fc35)*0x3e2d1))) ? (d1) : (d1)) : (d1));\n    d1 = (d1);\n    return (((0xeff58f0c)))|0;\n  }\n  return f; })(this, {ff: timeout(1800)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-28551573*/count=1070; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.888946593147858e+22;\n    d0 = (Infinity);\n    return ((-0xfffff*(i1)))|0;\n  }\n  return f; })(this, {ff: (-22 >>>  '' )}, new ArrayBuffer(4096)); testMathyFunction(mathy1, ['/0/', ({valueOf:function(){return 0;}}), [], NaN, true, ({toString:function(){return '0';}}), '', 1, null, -0, (new Boolean(false)), '\\0', 0.1, '0', ({valueOf:function(){return '0';}}), (new Number(-0)), false, (new String('')), 0, [0], (function(){return 0;}), /0/, (new Boolean(true)), undefined, (new Number(0)), objectEmulatingUndefined()]); ");
/*fuzzSeed-28551573*/count=1071; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var tan = stdlib.Math.tan;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i1 = (i1);\n    }\n    d0 = (8388609.0);\n    d0 = (+atan2(((8796093022208.0)), ((8388607.0))));\n    {\n      {\n        i1 = (0xfe64d005);\n      }\n    }\n    switch ((((i1)) ^ ((-0x8000000) / (-0x8000000)))) {\n      case -3:\n        (Uint8ArrayView[((0xd8b46010)+(0xe1481948)-((NaN) == (d0))) >> 0]) = (-0xfffff*((((i2)+(i2))>>>(((+tan(((17179869184.0)))) <= (d0))+(/*FFI*/ff((((0xde965*(i1))|0)), ((2305843009213694000.0)))|0))) == (0xb8d57473)));\n        break;\n      case 1:\n        switch ((~~(((\"\\u5920\" &= new RegExp(\"(?!(?!(?!\\\\W)))(^|\\ub38d*(?=[^]\\u00bf\\\\b))|(?:[\\\\u005d](.)\\\\D{2}){2097151}|(?:u)\", \"gim\") ?  /x/g  : x)) % ((+(0xffffffff)))))) {\n          case 0:\n            d0 = (d0);\n            break;\n          case -3:\n            (Float32ArrayView[1]) = ((-73786976294838210000.0));\n            break;\n        }\n        break;\n      case -1:\n        i1 = ((~((i1))));\n        break;\n      case 0:\n        d0 = (2.0);\n      default:\n        i2 = (i2);\n    }\n    d0 = (d0);\n    i2 = ((Float32ArrayView[0]));\n    i2 = (i1);\n    return (((0xf8a9ddea)-((((i1)-(i1))>>>((0x728b7012))))))|0;\n    return (((i2)-(i1)))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  /x/ , new Boolean(false),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(false),  /x/ ,  /x/ ,  /x/ , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-28551573*/count=1072; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( ! ( + 0x080000001)) ? (( + Math.fround(Math.log1p(Math.fround((Math.tanh((mathy0(Math.pow((x >>> 0), ( + Math.pow(( + y), ( + -(2**53-2))))), y) >>> 0)) >>> 0))))) | 0) : mathy1(Math.log10(Math.imul(( ! ((( ~ ( + Math.fround((x != (Number.MAX_SAFE_INTEGER | 0))))) | 0) | 0)), Math.fround(Math.acosh(Math.fround(( + ( - ( + Math.atan2(Number.MIN_SAFE_INTEGER, x))))))))), mathy1(Math.hypot(Math.imul(y, Math.ceil(x)), (Math.atan(42) >>> 0)), ( - [])))); }); testMathyFunction(mathy2, [-(2**53+2), -Number.MIN_VALUE, -0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, Number.MAX_VALUE, 1/0, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, 0, 0/0, -0x100000000, 2**53+2, -1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, -(2**53-2), 1, 0x100000001, -0x100000001, Number.MIN_VALUE, -0x07fffffff, 42, 2**53, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-28551573*/count=1073; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n for (let b of ~( /x/g .__defineGetter__(\"y\", /*wrap1*/(function(){ v1 = o0.a0.length;return [1,,]})()))) {v1 = r0.multiline;v0 = evaluate(\"function o0.f2(g1)  { yield (void options('strict_mode')) } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (b % 2 != 1), sourceIsLazy: true, catchTermination: true })); }\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (i1);\n    }\n    return (((((i0)-(i0))|0) / ((-(new -3(x,  '' ))) >> (((((0xffffffff)-(0xd28dd2a0)+(0xf905941a)) << (-0x46989*(i1))) < ((/*FARR*/[...[], -4503599627370497, (function ([y]) { })(), undefined, window, x, ({a1:1}),  \"\" ].map)))))))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, -1/0, 0x080000000, 1.7976931348623157e308, -0x100000000, -0x100000001, 0x0ffffffff, Math.PI, Number.MIN_VALUE, 0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, 0x100000001, -(2**53-2), 2**53-2, -0x080000000, 2**53+2, -(2**53+2), 0x07fffffff, -0, -0x07fffffff, -0x080000001, -(2**53), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 1/0, 1, -0x0ffffffff, 0]); ");
/*fuzzSeed-28551573*/count=1074; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=1075; tryItOut("m2.has(t2);");
/*fuzzSeed-28551573*/count=1076; tryItOut("Array.prototype.unshift.call(this.a2, (/*UUV1*/(\u3056.match = x)));");
/*fuzzSeed-28551573*/count=1077; tryItOut("\"use strict\"; yield x;");
/*fuzzSeed-28551573*/count=1078; tryItOut("\"use strict\"; /*MXX1*/o0 = g2.Error.stackTraceLimit;");
/*fuzzSeed-28551573*/count=1079; tryItOut("\"use strict\"; a0 + '';\nconst efbvoe;print(-20);\nArrayBuffer\n\n");
/*fuzzSeed-28551573*/count=1080; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    /*FFI*/ff(((imul((i0), ((i0) ? (0x5ac7281c) : (!((0x59cd9e73) < (-0x8000000)))))|0)), ((-8589934593.0)));\n    i0 = ((-((d1))) > (6.044629098073146e+23));\n    i0 = (0x85c64cd4);\n    {\n      i0 = (!(i0));\n    }\n    /*FFI*/ff(((d1)), ((imul(((((-536870911.0)) / ((9.671406556917033e+24))) >= (d1)), (i0))|0)), (((((-2305843009213694000.0))-((-288230376151711740.0) < (2199023255553.0))+(0xed247b6d)) | (((\"\\uB191\")+(0xfb7b9a14))))), (((((0xffffffff))*0xfffff) | (((0xa2bf4c8f) ? (0x9ec1c74c) : (0xff14dd6c))+(i0)))), ((~~(-35184372088833.0))), ((((0xf92391a5)) >> ((0xfd4b1bc3)))));\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: function (w, window, y, \"21\", x = true, window, z, y, x, x, y, z, eval, eval, a, e, x = x, w, z, w, x = \"\\uB404\", eval = /^?/ym, z, x, b = x, x, \u3056 = [z1], x, b, x, c, x, x, d, x, x, x, x, d, b, window, get = x, c, w, x =  \"\" , y, x, d, window, e, x, x, w, eval, d, x, c =  \"\" , x, c, c = x, \u3056, x, x, window, e, x, eval, window, x = new RegExp(\"(\\\\S[^](\\\\b)|\\\\b\\uef43\\\\b[^]{2,4})\", \"gi\"), x, d, c, x, this.x, x, x, x, a = null, window, x, this, a, window =  \"\" , c, e = window, x = this, delete, w, a, a =  \"\" , e, x, x, NaN, y)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 562949953421312.0;\n    return +((Float32ArrayView[((1)+(i2)) >> 2]));\n  }\n  return f;}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x080000000, 2**53, 42, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0, -0x100000001, 2**53+2, -1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -(2**53-2), 0x100000001, -Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), -0x0ffffffff, -0, 0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, 0x0ffffffff, -0x07fffffff, 1/0, 0x080000001, 0x07fffffff, 0/0, 0.000000000000001, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=1081; tryItOut("mathy3 = (function(x, y) { return (Math.expm1(( + ( ~ (x >>> 0)))) < ( + (Math.fround(Math.atan2((Math.min((x >>> 0), (y >>> 0)) >>> 0), ( + (Math.fround(Math.acos(( + ( ! Math.fround(y))))) | 0)))) | 0))); }); ");
/*fuzzSeed-28551573*/count=1082; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 2049.0;\n    var i3 = 0;\n    (Uint32ArrayView[1]) = (((((i3)+((imul((0xbfc07da0), (0xffffffff))|0) != (-0x8000000))+(i3)) >> (((+(0.0/0.0)) < ((-33.0) + (+((9223372036854776000.0))))))))+(((i1) ? ((~((-0x8000000)))) : ((0xfa7e4e95) ? (-0x8000000) : (0xad6a8035))) ? ((((/*FFI*/ff(((((0xd09e1968)) & ((0x66178127)))), ((-34359738369.0)))|0))|0) <= (((0x4c8e1978) / (0x55a8ff62)) << ((i3)))) : (-0x8000000))-(i0));\n    i0 = (i0);\n    return +((2305843009213694000.0));\n  }\n  return f; })(this, {ff: ([] =  '' )}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [42, -0, Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, 0/0, 0, 1/0, -0x080000000, 2**53-2, 0x080000001, 0x100000000, 0x0ffffffff, -0x080000001, 0.000000000000001, 0x080000000, 2**53, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, 0x100000001, -(2**53), -0x07fffffff, -0x0ffffffff, Math.PI, -(2**53+2), -Number.MIN_VALUE, -0x100000000, -(2**53-2)]); ");
/*fuzzSeed-28551573*/count=1083; tryItOut("\"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -3.777893186295716e+22;\n    switch ((((0x7b4154c9) % (0xffffffff)) >> (true))) {\n      case 1:\n        return (((abs(((x) & (((((0xd9845b51)+(0xfa9e7898))>>>((0xfc23f0d2)-(0x193f46b9)-(0xf5291540))) < ((((0x6b216d3e)))>>>(0x8e40*(0x2859f962)))))))|0) / (imul((!((0x17225213) > (0xfae87915))), (((0xf8f8af3b) ? (0xfa9ebb23) : (0xfc837df3)) ? (0x7bba38db) : (0x2d3d2dc4)))|0)))|0;\n      case 0:\n        (Uint16ArrayView[((((((0xbb684d8b) / (((0xa5a65a09))>>>((0xff28e5f5))))>>>(((0x4a176835))-(0xfd50bc8f)+(-0x8000000)))))) >> 1]) = ((0xfcd7d43f));\n        break;\n      default:\n        return (((0xffffffff)+(x)))|0;\n    }\n    (Float32ArrayView[(((~~((-0x8000000) ? (3.777893186295716e+22) : (-1025.0))))+( /x/ )+((+(0.0/0.0)) < (d2))) >> 2]) = ((((+atan2(((d2)), ((d0))))) / ((d0))));\n    d0 = ((4277));\n    d0 = (((+sqrt((((/*FFI*/ff((((((0x5bdfc9da) != (0x49e28f0))) << ((0x8ad53fa9)+(-0x1e1b075)-(0x35702209)))))|0) ? (+(0.0/0.0)) : (d2)))))) * ((Float64ArrayView[4096])));\n    d0 = (d1);\n    d1 = (d0);\n    return (((imul((!((0x1141986e) ? (0xe12d2d51) : (0x2ebb33a8))), (((+(((0xfb2d8a56)-((0x1010b620) > (0x932fc5e1)))>>>(-0xfffff*((1.9342813113834067e+25) != (18014398509481984.0))))))))|0) / (~~(d2))))|0;\n  }\n  return f; })(this, {ff: String.prototype.link}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x080000001, -0, 0, 0x0ffffffff, 1, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, 0x080000000, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), -0x080000000, 0x100000000, 0x07fffffff, 0x100000001, 42, -0x100000000, 2**53+2, 1/0, 0x080000001, Number.MIN_VALUE, 2**53, Math.PI, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-28551573*/count=1084; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.expm1(Math.max(Math.max(x, (0x100000001 >= x)), y)) >>> 0) ? Math.fround(( - Math.fround((mathy0(Math.hypot((x >>> 0), x), (Math.log1p(((Math.fround(y) % (x >>> 0)) >>> 0)) >>> 0)) > 0x0ffffffff)))) : ( - ( + ( ~ ( - Math.log1p((-0x080000000 !== -0x080000000))))))); }); testMathyFunction(mathy2, [(new Boolean(true)), ({valueOf:function(){return '0';}}), (new Number(0)), /0/, null, true, (new Number(-0)), '/0/', (new String('')), -0, objectEmulatingUndefined(), 0, undefined, 1, [0], (function(){return 0;}), false, '\\0', NaN, '0', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), '', 0.1, (new Boolean(false)), []]); ");
/*fuzzSeed-28551573*/count=1085; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.pow(Math.fround(( + Math.atan2(( ! ( + Math.pow((x >= x), y))), ( + Math.min(x, (Math.PI >>> 0)))))), ( + Math.max(Math.tan(( - (( ~ ((y | 0) >>> (y | 0))) >>> 0))), Math.fround(( ~ Math.fround(((( ! (x >>> 0)) >>> 0) * y)))))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 0x100000001, -0x080000000, 0, -(2**53), 0x0ffffffff, 1/0, -0x080000001, 2**53+2, -0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, Math.PI, -Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, -0x100000001, 42, -(2**53+2), -0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 1, -0, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 0x080000001, 0/0]); ");
/*fuzzSeed-28551573*/count=1086; tryItOut("t0 = new Uint32Array(b1);");
/*fuzzSeed-28551573*/count=1087; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.hypot(mathy0((( + ((( - ((( ! (2**53+2 >>> 0)) >>> 0) >>> 0)) >>> 0) | 0)) | 0), ( ~ mathy1(y, (Math.asinh((( ! Math.fround(Math.sign(Math.fround(x)))) >>> 0)) >>> 0)))), (((Math.clz32(-(2**53+2)) >>> 0) == (( + (( + Math.max(mathy1(x, (( + ((y >>> 0) ** y)) !== x)), ( ! Math.atan(Math.fround(x))))) | ( + (( + 0x07fffffff) ? y : ( + Math.log1p(( + x))))))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-28551573*/count=1088; tryItOut("t2.set(a1, 15);");
/*fuzzSeed-28551573*/count=1089; tryItOut("\"use strict\"; b1 + '';");
/*fuzzSeed-28551573*/count=1090; tryItOut("a0.forEach((function() { try { h1.hasOwn = f0; } catch(e0) { } try { a0[9]; } catch(e1) { } try { t1.set(o2.t0, 12); } catch(e2) { } Array.prototype.forEach.call(a0, (WeakMap.prototype.get).call, v0); return this.b0; }));");
/*fuzzSeed-28551573*/count=1091; tryItOut("print(x);");
/*fuzzSeed-28551573*/count=1092; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + mathy0(( + Math.asin((Math.fround(Math.pow((( + ( ! ( + 42))) | 0), (y >= y))) ? -0x080000000 : Math.trunc(( ! ( + Math.atan2(( + x), ( + 0x100000000)))))))), ( + ((x && (y >> Math.atanh((y >>> 0)))) >>> 0)))) != (mathy1(Math.fround(Math.atanh((x | 0))), (( + (y >>> ( + Math.hypot((( + ((x >>> 0) % (y >>> 0))) | ( + 2**53)), (y === (y | 0)))))) < Math.log(mathy1(x, 2**53)))) | 0)); }); testMathyFunction(mathy2, [0x100000000, 0x080000000, -(2**53+2), -0x100000000, -1/0, 2**53-2, 0/0, 2**53+2, -0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, 42, 0, -0x0ffffffff, 1/0, Math.PI, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 1.7976931348623157e308, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -(2**53), 0x100000001, 1, 0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=1093; tryItOut("g0.g1.m1.has(t2);\nObject.seal(b0);\n");
/*fuzzSeed-28551573*/count=1094; tryItOut("print(s1);");
/*fuzzSeed-28551573*/count=1095; tryItOut("/*RXUB*/var r = r1; var s = s1; print(s.match(r)); ");
/*fuzzSeed-28551573*/count=1096; tryItOut("v2 = (h2 instanceof g2.h2);");
/*fuzzSeed-28551573*/count=1097; tryItOut("Array.prototype.pop.call(a0)");
/*fuzzSeed-28551573*/count=1098; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + Math.tanh((Math.round(((mathy0((mathy0(y, (y | 0)) | 0), Math.fround(( - ( + x)))) | 0) >>> 0)) | 0))); }); testMathyFunction(mathy1, [(new Boolean(false)), -0, 0, (new Number(-0)), ({valueOf:function(){return '0';}}), undefined, /0/, '\\0', null, (new Boolean(true)), ({valueOf:function(){return 0;}}), true, [0], (new Number(0)), NaN, '/0/', false, [], (new String('')), objectEmulatingUndefined(), 0.1, ({toString:function(){return '0';}}), (function(){return 0;}), '', 1, '0']); ");
/*fuzzSeed-28551573*/count=1099; tryItOut("{ void 0; bailAfter(7); }");
/*fuzzSeed-28551573*/count=1100; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=1101; tryItOut("\"use strict\"; i1 = new Iterator(o1);");
/*fuzzSeed-28551573*/count=1102; tryItOut("(new (Math.sqrt)(\"\\u5A81\", (function ([y]) { })()));");
/*fuzzSeed-28551573*/count=1103; tryItOut("\"use strict\"; g2.v1 = evalcx(\"v1 = t0.BYTES_PER_ELEMENT;\", g0);");
/*fuzzSeed-28551573*/count=1104; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( - (Math.sin((Math.expm1(Math.max(((y ^ x) >>> 0), ((y ** (y | 0)) | 0))) | 0)) * Math.fround((Math.fround(((Math.fround(( ! Math.fround(((x | 0) & y)))) ? y : ( ! (y | 0))) >>> 0)) * (( ~ (y | 0)) >>> 0))))); }); testMathyFunction(mathy0, /*MARR*/[ 'A' , new Number(1), new String('q'), new Number(1),  'A' , x, x,  'A' , new String('q'), new String('q'), [1], new Number(1), new Number(1), [1],  'A' , new String('q'), [1], new String('q'),  'A' , new String('q'), x,  'A' ]); ");
/*fuzzSeed-28551573*/count=1105; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( - ( ~ y)) >= ( ~ (Math.pow(-0x080000000, Math.sin(( + Math.pow(( + ( + ( ~ ( + y)))), ( + (((y >>> 0) < Math.fround(y)) >>> 0)))))) >>> 0))); }); testMathyFunction(mathy0, ['', (new Number(-0)), true, [0], ({toString:function(){return '0';}}), undefined, NaN, '0', (new Number(0)), 0, objectEmulatingUndefined(), (function(){return 0;}), /0/, (new String('')), (new Boolean(true)), null, '/0/', 1, false, [], ({valueOf:function(){return '0';}}), '\\0', (new Boolean(false)), ({valueOf:function(){return 0;}}), -0, 0.1]); ");
/*fuzzSeed-28551573*/count=1106; tryItOut("mathy0 = (function(x, y) { return Math.min(Math.imul(((Math.sinh((( + Math.atan2(( + ( + ((x | 0) | 42))), ( + (x + Math.fround(Math.hypot(x, 0x07fffffff)))))) | 0)) | 0) & ( ~ Math.fround(( - Math.PI)))), Math.fround(( ! Math.fround(x)))), (Math.pow(( ! (((( + ( + 0x07fffffff)) - (Math.log((x | 0)) | 0)) | 0) >>> 0)), (( ! (Math.clz32(x) < ( ~ ( + (y <= Number.MAX_SAFE_INTEGER))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), 42, 0x100000001, -0x100000000, -1/0, -0x080000000, -0, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_VALUE, -0x100000001, 0.000000000000001, 0x080000001, 0/0, 1/0, Number.MAX_SAFE_INTEGER, 2**53+2, 1, -0x07fffffff, 2**53-2, Math.PI, 1.7976931348623157e308, 0x07fffffff, -(2**53-2), 0x0ffffffff, 0x080000000, -Number.MIN_VALUE, -(2**53+2), 0, Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-28551573*/count=1107; tryItOut("\"use strict\"; o1.t2 = new Uint32Array(b0);");
/*fuzzSeed-28551573*/count=1108; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return (( + Math.log10(Math.fround(Math.asin(Math.fround(y))))) * (Math.min(Math.hypot(Math.hypot(mathy1(( + Math.fround(x)), -Number.MIN_VALUE), Math.fround(mathy0(Math.fround(x), Math.fround(-0x07fffffff)))), ( + Math.log(-(2**53)))), (Math.hypot((( ! x) | 0), (mathy0((((x , ( + y)) == (0/0 | 0)) | 0), ( + ( + (Math.cbrt((x | 0)) > x)))) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, 1, 0/0, -(2**53-2), -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, 0x100000001, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, -(2**53), -0x07fffffff, 0x100000000, 1/0, 0, -Number.MIN_VALUE, -0, -1/0, 2**53-2, Number.MIN_VALUE, -0x100000000, -0x080000001, 42, 2**53]); ");
/*fuzzSeed-28551573*/count=1109; tryItOut("/*MXX3*/g2.RegExp.prototype.multiline = g0.g2.RegExp.prototype.multiline;");
/*fuzzSeed-28551573*/count=1110; tryItOut("/*bLoop*/for (inldxk = 0; inldxk < 11; ++inldxk, (4277)) { if (inldxk % 2 == 0) { /*RXUB*/var r = /[^\\\u00b1-\udc9d\\d\\d]|\\1|\\3(\u819b*(?![^\u99c5-O6-\u0096])*?(?:\\u001b)[^]|[^\\S\\S\u00a2-\ua4ab]*){1,}+/yim; var s = \"\"; print(r.test(s));  } else { print(z);const z = arguments; }  } ");
/*fuzzSeed-28551573*/count=1111; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + ( ! ( + Math.atanh((((Math.fround(((( - x) | 0) + -0x07fffffff)) == x) % x) | 0))))); }); ");
/*fuzzSeed-28551573*/count=1112; tryItOut("for (var p in o0.f2) { try { i1.send(o0.s0); } catch(e0) { } Object.defineProperty(this, \"a1\", { configurable: true, enumerable: false,  get: function() {  return Array.prototype.filter.call(g1.a1, (function(j) { if (j) { try { p1 = m1.get(s1); } catch(e0) { } try { /*MXX2*/g2.Int16Array.prototype.constructor = t2; } catch(e1) { } try { f1 = Proxy.createFunction(h0, f1, f2); } catch(e2) { } g2.s0 = s0.charAt(18); } else { try { v1 = a0.every((function(j) { if (j) { try { /*ODP-3*/Object.defineProperty(this.v2, \"callee\", { configurable: false, enumerable: true, writable:  /x/ , value: g2 }); } catch(e0) { } Array.prototype.pop.apply(a2, []); } else { try { for (var v of g0) { for (var p in h0) { try { ; } catch(e0) { } try { h1.delete = (function mcc_() { var ufkdzz = 0; return function() { ++ufkdzz; if (/*ICCD*/ufkdzz % 6 != 0) { dumpln('hit!'); try { e1 + i0; } catch(e0) { } try { this.o0.t2.set(g0.a1, this.v1); } catch(e1) { } try { Array.prototype.unshift.apply(a2, [v0, a0, s0]); } catch(e2) { } Object.defineProperty(this, \"this.v0\", { configurable:  \"\" , enumerable: 9,  get: function() {  return r2.ignoreCase; } }); } else { dumpln('miss!'); try { m2 = new WeakMap; } catch(e0) { } try { Array.prototype.unshift.apply(a0, [g2, s0, f0]); } catch(e1) { } e0.has(m0); } };})(); } catch(e1) { } try { const v2 = r2.exec; } catch(e2) { } v1.toString = (function mcc_() { var obtshm = 0; return function() { ++obtshm; if (/*ICCD*/obtshm % 10 == 3) { dumpln('hit!'); a0 + e2; } else { dumpln('miss!'); try { /*MXX2*/g1.TypeError.name = v1; } catch(e0) { } try { this.v2.valueOf = o1.f2; } catch(e1) { } i0 = e1.iterator; } };})(); } } } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(v2, p1); } catch(e1) { } t0 = new Int32Array(o0.v0); } })); } catch(e0) { } v2 = (s1 instanceof h2); } })); } }); }\n /x/ ;\n");
/*fuzzSeed-28551573*/count=1113; tryItOut("\"use strict\"; v1 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 5 == 1), noScriptRval: (x % 5 == 1), sourceIsLazy: true, catchTermination: (x % 29 == 10) }));");
/*fuzzSeed-28551573*/count=1114; tryItOut("/*infloop*/for(z; (false)(); true) {h2 + '';; }");
/*fuzzSeed-28551573*/count=1115; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -144115188075855870.0;\n    var i3 = 0;\n    return +(((((x)) / ((d0))) + (((d0)) * ((+(-1.0/0.0))))));\n  }\n  return f; })(this, {ff: b =>  { yield  /x/g  } }, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x0ffffffff, 2**53-2, 2**53, 1/0, 0.000000000000001, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, -0, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, 0, 42, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53), -(2**53-2), 0x100000001, 0x100000000, 2**53+2, 0x080000000, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, -0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=1116; tryItOut("M:with({b: (4277)}){;([]); }");
/*fuzzSeed-28551573*/count=1117; tryItOut("for (var p in s2) { a1 + ''; }");
/*fuzzSeed-28551573*/count=1118; tryItOut("\"use strict\"; var x, x, x = x, window = ((function sum_indexing(qqwdky, ohzrnx) { ; return qqwdky.length == ohzrnx ? 0 : qqwdky[ohzrnx] + sum_indexing(qqwdky, ohzrnx + 1); })(/*MARR*/[function(){}, true], 0)), hrivvu, x = (intern(null)), x, x = window, oqxpkg, x;Array.prototype.splice.apply(g0.a1, [NaN, 7]);");
/*fuzzSeed-28551573*/count=1119; tryItOut("\"use strict\"; darguments.callee.arguments = NaN;");
/*fuzzSeed-28551573*/count=1120; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - Math.trunc((Math.sqrt(2**53-2) < x))); }); ");
/*fuzzSeed-28551573*/count=1121; tryItOut("\"use strict\"; let x = \u3056 = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: ((function(y) { Array.prototype.reverse.apply(a2, [g0, a0, s0, g2.b2, p2]); }).call).bind(\"\\uD739\"), getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: encodeURIComponent, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( /x/g ), Date.prototype.setDate, /*wrap2*/(function(){ var igsqvw =  /x/g ; var kxhqds = function(y) { (igsqvw); }; return kxhqds;})()), e, \u3056;v0 = (v0 instanceof p2);");
/*fuzzSeed-28551573*/count=1122; tryItOut("/*bLoop*/for (let nxacbe = 0; nxacbe < 83; a && this.y &= (4277), ++nxacbe, ((p={}, (p.z = x\u0009\n)()))) { if (nxacbe % 109 == 17) { /* no regression tests found */ } else { /*infloop*/M:for(var eval in ((arguments.callee.caller.caller)(typeof  '' )))x = h1; }  } ");
/*fuzzSeed-28551573*/count=1123; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; validategc(false); } void 0; }");
/*fuzzSeed-28551573*/count=1124; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[function(){}, true, true, function(){}, true, true, function(){}, function(){}, true, function(){}, function(){}, true, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}]) { s0 += g2.s0; }");
/*fuzzSeed-28551573*/count=1125; tryItOut("g1.v2 = (o2.m1 instanceof g2.i2);");
/*fuzzSeed-28551573*/count=1126; tryItOut("a2.unshift(g0.t0, b1, e0);");
/*fuzzSeed-28551573*/count=1127; tryItOut("o2.toString = g0.f2;");
/*fuzzSeed-28551573*/count=1128; tryItOut("v2 = evaluate(\"/*tLoop*/for (let e of /*MARR*/[3/0,  \\\"\\\" , Infinity, Infinity, Infinity, Infinity, Infinity, 3/0, Infinity, 3/0, 3/0, 3/0, function(){},  \\\"\\\" ]) { a0.push(o1, f0, m1, o1); }\", ({ global: this.g1, fileName: null, lineNumber: 42, isRunOnce: this, noScriptRval: [,,z1], sourceIsLazy: x, catchTermination: (x % 27 != 17), element: o2, elementAttributeName: s2, sourceMapURL: s2 }));");
/*fuzzSeed-28551573*/count=1129; tryItOut("/*bLoop*/for (let uhaiad = 0; uhaiad < 12; ++uhaiad) { if (uhaiad % 3 == 0) { m1.get(t2); } else { a0 = new Array; }  } ");
/*fuzzSeed-28551573*/count=1130; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new Number(-0)), ({valueOf:function(){return 0;}}), (new String('')), '', 0.1, '/0/', false, (new Number(0)), (new Boolean(true)), 1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), [0], NaN, '\\0', (new Boolean(false)), -0, objectEmulatingUndefined(), 0, undefined, [], true, (function(){return 0;}), null, '0', /0/]); ");
/*fuzzSeed-28551573*/count=1131; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=1132; tryItOut("mathy5 = (function(x, y) { return ((Math.asin((Math.fround(( ! (x | 0))) | 0)) | 0) || ( + ( + Math.imul(Math.min((Math.fround(( ! Math.fround(Math.fround(Math.min(Math.fround(Math.max(( + y), x)), Math.fround(x)))))) >>> 0), (( + Math.expm1((-(2**53-2) >>> 0))) >>> 0)), ( + Math.fround(mathy2(( + (Math.sinh((-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)), Math.fround(mathy4(Math.min(x, x), Math.fround(Math.cosh(x))))))))))); }); ");
/*fuzzSeed-28551573*/count=1133; tryItOut("with({}) for(let d of /*MARR*/[true, true, true, true, true, true, true, true, true, true, true, true, (0/0), (0/0), 0.000000000000001]) let(d) { throw StopIteration;}");
/*fuzzSeed-28551573*/count=1134; tryItOut("/*RXUB*/var r = /$/m; var s = (/\\S/gi)(); print(uneval(s.match(r))); ");
/*fuzzSeed-28551573*/count=1135; tryItOut("testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0x080000001, 1/0, -(2**53), -0x100000000, -0x080000000, -0x080000001, -1/0, 2**53, 0.000000000000001, 0x100000000, -(2**53-2), 1, 0x07fffffff, 2**53-2, 0x0ffffffff, -0x07fffffff, 0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, 0/0, -0x100000001, -0, 42, Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-28551573*/count=1136; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround((( ! ( + mathy0(mathy0((Math.max(y, ( + y)) & (( ! 0x100000000) | 0)), (2**53 | Math.log10((2**53+2 >>> 0)))), ( + ( ! y))))) | 0)); }); testMathyFunction(mathy3, [1/0, -0x080000000, 0.000000000000001, -0x100000000, 0x080000001, -(2**53+2), -(2**53), 1, -Number.MAX_VALUE, 42, 0x100000000, -0x080000001, -(2**53-2), 0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, Math.PI, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000001, -0, -0x0ffffffff, -1/0, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=1137; tryItOut("\"use asm\"; /*infloop*/for(((Object.defineProperty(x, \"constructor\", ({enumerable: true}))).x) in (((Math.ceil).bind)((({prototype: ((Function).bind( \"\" ))(\"\\u851B\") })))))s1 += 'x';");
/*fuzzSeed-28551573*/count=1138; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -0x080000000, 42, 0x100000001, -0x0ffffffff, -0x07fffffff, 0x080000000, -0x100000000, -Number.MAX_VALUE, -0, -0x100000001, 0x080000001, 2**53, 0, 0/0, -0x080000001, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -1/0, 0.000000000000001, 0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), 2**53+2, 2**53-2, 1, 0x100000000]); ");
/*fuzzSeed-28551573*/count=1139; tryItOut("testMathyFunction(mathy4, /*MARR*/[new String(''), (0/0), new String(''), [undefined], (0/0), x, new String('q'), new String(''), [undefined], new String('q'), new String(''), new String('q'), [undefined], (0/0), [undefined], new String(''), new String(''), new String(''), x]); ");
/*fuzzSeed-28551573*/count=1140; tryItOut("\"use asm\"; let(b) ((function(){b.lineNumber;})());");
/*fuzzSeed-28551573*/count=1141; tryItOut("mathy5 = (function(x, y) { return ((((x >= 0/0) && ( + Math.atan2(mathy3((x && 2**53), ( + (( + (y == (1.7976931348623157e308 | 0))) & ( + (x >>> x))))), ( + y)))) | ( + ((Math.fround(1/0) >>> 0) , (((Math.ceil(x) >>> 0) / (Math.pow(y, y) >>> 0)) >>> 0)))) ^ ( + (mathy0(( + (( ~ mathy0(y, ( + Math.clz32(0x100000000)))) , Math.trunc((0x07fffffff >>> 0)))), ( + ( + (x << y)))) < ( + mathy1(mathy4(Math.atanh(Math.imul(y, y)), ( + Math.fround((( ! Number.MAX_VALUE) * y)))), Math.fround(( ~ Math.fround(( + Math.cbrt(( + x))))))))))); }); testMathyFunction(mathy5, [-0x100000000, 0x0ffffffff, Number.MIN_VALUE, -0x100000001, 0x07fffffff, 42, -0x07fffffff, 0x080000000, 0x100000000, -0x0ffffffff, -(2**53), 2**53-2, 2**53, -0, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x100000001, 0.000000000000001, 1/0, 0, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), -1/0, 1, Math.PI, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1142; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.ceil((( ~ (Math.log10((( ! Math.trunc(-0x100000001)) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy4, [0.000000000000001, -Number.MAX_VALUE, 1/0, 42, 0x100000001, -(2**53), 2**53, Math.PI, -0, 0, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0x07fffffff, 0x100000000, 0x080000000, 0/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, 0x080000001, -0x100000001, -Number.MIN_VALUE, 2**53-2, -0x100000000, -0x07fffffff]); ");
/*fuzzSeed-28551573*/count=1143; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.clz32(((Math.fround(y) == ( + Math.atan2(x, x))) | 0))); }); testMathyFunction(mathy0, [1, -0x100000001, Number.MIN_VALUE, 0, 0x080000000, Math.PI, Number.MAX_VALUE, 0/0, 0x07fffffff, -Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, -Number.MIN_VALUE, 2**53, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -0, -0x080000000, -(2**53-2), -0x0ffffffff, -1/0, 42, -(2**53+2), 0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1144; tryItOut("g0.o0.toString = (function(j) { if (j) { for (var v of m2) { /*MXX2*/g0.Int32Array.prototype.BYTES_PER_ELEMENT = f1; } } else { try { m2.get(b1); } catch(e0) { } m2.has(b0); } });");
/*fuzzSeed-28551573*/count=1145; tryItOut("mathy3 = (function(x, y) { return mathy1((Math.fround(Math.round(( + (x ? y : (y >>> 0))))) | ( + Math.sign(Math.fround((((( - (x >>> 0)) >>> 0) >>> 0) ? ( + 0.000000000000001) : (( + Math.fround(( + (Math.asinh((y >>> 0)) >>> 0)))) , (mathy2(x, (-0 >>> 0)) >>> 0))))))), ((Math.fround(mathy2(Math.fround(Math.fround(((-0x080000000 >>> y) <= Math.fround(( - y))))), Math.fround(Math.fround(Math.cbrt(-0x080000000))))) ? (Math.imul(((( + (Math.fround(Math.hypot((x >>> 0), (x >>> 0))) | 0)) | 0) >>> 0), (-0x07fffffff >>> 0)) >>> 0) : (Math.sinh((( + y) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy3, [2**53, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0x100000001, 2**53-2, 2**53+2, 0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0x080000000, -(2**53-2), -0, 1/0, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, -1/0, 1.7976931348623157e308, 42, Number.MAX_VALUE, 0, 0/0, -(2**53+2), -Number.MIN_VALUE, 0x100000000, 0x07fffffff]); ");
/*fuzzSeed-28551573*/count=1146; tryItOut("t2[8];");
/*fuzzSeed-28551573*/count=1147; tryItOut("testMathyFunction(mathy4, [-0x0ffffffff, 2**53, 0x100000001, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, 0, 0x080000000, -0x100000000, 0x100000000, 1, -0x080000000, -0, 1.7976931348623157e308, 0/0, -0x07fffffff, 2**53+2, 0.000000000000001, 2**53-2, -0x100000001, -Number.MIN_VALUE, Math.PI, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, 42, -Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=1148; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-28551573*/count=1149; tryItOut("\"use strict\"; for (var v of g0) { o2.e0.delete(g0); }");
/*fuzzSeed-28551573*/count=1150; tryItOut("v1 = g2.eval(\"i0.send(b2);\");");
/*fuzzSeed-28551573*/count=1151; tryItOut("\"use asm\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    {\n      i0 = (i0);\n    }\n    {\n      {\n        return +(((+sin(((Float32ArrayView[0]))))));\n      }\n    }\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: function (d)(4277)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_VALUE, 1.7976931348623157e308, 1/0, 0x100000001, -0x080000001, Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, -(2**53-2), 0, 0.000000000000001, 0x100000000, 0x080000001, 0x07fffffff, 42, 2**53-2, Math.PI, 0x0ffffffff, -Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 0/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, -0x07fffffff, -0x100000000, 2**53]); ");
/*fuzzSeed-28551573*/count=1152; tryItOut("t2 = new Float32Array(a1);");
/*fuzzSeed-28551573*/count=1153; tryItOut("(new RegExp(\"\\\\2|(?:\\\\b|\\\\D{2,})*\", \"y\").throw([[]]));print(x);\u000c");
/*fuzzSeed-28551573*/count=1154; tryItOut("mathy1 = (function(x, y) { return (Math.cbrt(Math.sign((y | 1))) + mathy0(( ~ y), ( + (x ? (((y >>> 0) / ((Math.acos(x) | 0) | 0)) | 0) : (Math.abs((Math.pow(x, y) >>> 0)) / (mathy0(x, (x | 0)) | 0)))))); }); testMathyFunction(mathy1, [0x100000001, 0x080000001, 2**53, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -0, 0, 0.000000000000001, 42, Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0/0, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -(2**53+2), 0x100000000, 2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 2**53-2, 1/0, -Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -(2**53), 0x080000000]); ");
/*fuzzSeed-28551573*/count=1155; tryItOut("a0[10] = h2;");
/*fuzzSeed-28551573*/count=1156; tryItOut("v1 = (f2 instanceof g1);");
/*fuzzSeed-28551573*/count=1157; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-28551573*/count=1158; tryItOut("\"use strict\"; {b1.valueOf = Uint16Array.bind(g0); }");
/*fuzzSeed-28551573*/count=1159; tryItOut(";");
/*fuzzSeed-28551573*/count=1160; tryItOut("function shapeyConstructor(gdonhy){if (gdonhy) { /* no regression tests found */ } this[\"sqrt\"] = ({});this[\"x\"] = objectEmulatingUndefined;if (gdonhy) Object.defineProperty(this, \"wrappedJSObject\", ({value: (y !== x), enumerable: false}));if (-131072) this[19] = 3/0;return this; }/*tLoopC*/for (let z of /*MARR*/[ \"use strict\" , ({x:3}), ({x:3}), ({x:3}), true, true, ({x:3}), true,  \"use strict\" ,  \"use strict\" , ({x:3}), true, true, ({x:3}), ({x:3}), ({x:3}),  \"use strict\" , true, ({x:3}),  \"use strict\" , true,  \"use strict\" ,  \"use strict\" , ({x:3}),  \"use strict\" , true, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3})]) { try{let aqyuwl = shapeyConstructor(z); print('EETT'); p2.__proto__ = g1.a2;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-28551573*/count=1161; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(Math.imul(( + Math.fround(Math.sin((((( + (y <= x)) < ( + Math.fround(Math.atanh(Math.fround(y))))) >>> 0) < x)))), Math.imul(( + (( + Math.clz32(( + ((x | 0) <= ( + x))))) ^ 0.000000000000001)), (x >>> Math.sign(0x07fffffff)))), Math.cosh((Math.fround(Math.min(x, Math.fround(( + mathy0(y, ( + (Math.log10(( + x)) <= Math.fround(-1/0)))))))) >>> 0))); }); testMathyFunction(mathy2, [1/0, 1, 0, 2**53-2, -(2**53), 2**53+2, 0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 0x100000000, -1/0, -Number.MIN_VALUE, 42, 0/0, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, Math.PI, -0x100000001, 0x07fffffff, -0x080000000, 0x100000001, -0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -Number.MAX_VALUE, 2**53, 1.7976931348623157e308]); ");
/*fuzzSeed-28551573*/count=1162; tryItOut("c = ((x) => x)();x = this.g0;");
/*fuzzSeed-28551573*/count=1163; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        i0 = ((i0) ? ((((-9007199254740992.0)) - ((-262145.0))) != (+((Float64ArrayView[(((0x95279d26) ? (0xf982c446) : (0xfe184447))) >> 3])))) : (i0));\n      }\n    }\n    {\n      i0 = (i0);\n    }\n    return ((-0xfffff*((0xa17fb973) < ((Float32ArrayView[0])))))|0;\n  }\n  return f; })(this, {ff: timeout(1800)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x07fffffff, -(2**53), -(2**53-2), -0x080000001, 1, -Number.MIN_VALUE, -1/0, -(2**53+2), 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -0, 0, 0x0ffffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, 0.000000000000001, -0x0ffffffff, 2**53+2, 1/0, -0x100000001, Number.MIN_VALUE, 0x080000001, 0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-28551573*/count=1164; tryItOut("\"use asm\"; let (x, yrokku, eval = (let (e = (4277)) /*RXUE*//\\B/im.exec(\"\")), zqxstb, NaN = x = [z1], eval, x = Object.defineProperty(b, \"getter\", ({configurable: true, enumerable: (x % 6 != 0)})), adkjcs) { e2.has(g1); }");
/*fuzzSeed-28551573*/count=1165; tryItOut("print((this(undefined,  /x/g )));");
/*fuzzSeed-28551573*/count=1166; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + Math.imul(( ! ((mathy0(((2**53-2 || -0) | 0), (Math.fround(mathy0(Math.fround((mathy0((y >>> 0), (y >>> 0)) >>> 0)), y)) | 0)) | 0) | 0)), Math.atan2(Math.imul(Math.imul(Math.fround(( + 0.000000000000001)), y), (Math.acosh(( - x)) | 0)), y))) >>> 0); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -0x100000000, -(2**53+2), Math.PI, 42, 1, 0x080000001, 0/0, -0x080000000, -0, 0.000000000000001, 0x100000001, 1/0, -(2**53), 0x080000000, 2**53-2, -0x080000001, 0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), 0, -Number.MIN_VALUE, 2**53, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-28551573*/count=1167; tryItOut("\"use strict\"; testMathyFunction(mathy3, [2**53+2, Number.MIN_VALUE, 0/0, 1, -0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 1/0, -(2**53), 0x100000000, 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, 2**53, Number.MAX_VALUE, -0x100000001, -0, 0x080000000, 0x080000001, -0x07fffffff, -1/0, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-28551573*/count=1168; tryItOut("mathy3 = (function(x, y) { return (( + (Math.sin((Math.cbrt((mathy1(x, (Math.pow(-Number.MAX_SAFE_INTEGER, x) | 0)) | 0)) | 0)) | 0)) ? ( ~ ((Math.asinh(y) ? (x | ( - -Number.MIN_SAFE_INTEGER)) : -0x100000001) | 0)) : Math.fround(Math.max(mathy2((mathy0(mathy2(x, ( + x)), ((((x >>> 0) == (Math.fround(Math.pow(Math.fround(y), ( + Number.MIN_SAFE_INTEGER))) >>> 0)) >>> 0) >>> 0)) >>> 0), Math.fround(y)), (( - (Math.fround(((-(2**53) >>> 0) ? (( + (( + ( ~ Math.asinh(x))) != y)) >>> 0) : ((((Math.max(y, Math.fround(mathy2(y, x))) | 0) | 0) << mathy2(x, 1/0)) | 0))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [2**53+2, -Number.MIN_VALUE, 2**53, 0x100000001, 0/0, 1, 42, 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 1/0, -(2**53+2), -1/0, -0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -(2**53), Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, -0x100000000, -0, Number.MIN_VALUE, 2**53-2, 0x080000001]); ");
/*fuzzSeed-28551573*/count=1169; tryItOut("\"use strict\"; for (var p in o0.m0) { Object.prototype.watch.call(f1, \"reverse\", (function mcc_() { var riyior = 0; return function() { ++riyior; g2.f1(/*ICCD*/riyior % 11 != 2);};})()); }");
/*fuzzSeed-28551573*/count=1170; tryItOut("v0 = t2[v1];function x(...a) { Array.prototype.shift.call(g0.a2, o2.o2, s2); } Array.prototype.splice.call(a0, NaN, 12);");
/*fuzzSeed-28551573*/count=1171; tryItOut("\"use strict\"; delete w.x;");
/*fuzzSeed-28551573*/count=1172; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; abortgc(); } void 0; }");
/*fuzzSeed-28551573*/count=1173; tryItOut("g2.offThreadCompileScript(\"e1.has(v1);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 52 == 8), noScriptRval: true, sourceIsLazy: (x % 80 == 52), catchTermination: (4277), sourceMapURL: s2 }));");
/*fuzzSeed-28551573*/count=1174; tryItOut("\"use asm\"; s0 = new String(e1);");
/*fuzzSeed-28551573*/count=1175; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.sqrt((Math.pow(Math.fround(( ! (((( ! (x >>> 0)) === ( + (( + Math.hypot(1/0, y)) != ( + Number.MAX_VALUE)))) % Math.fround((y > Math.fround(Math.hypot(0x100000001, ( + x)))))) | 0))), Math.sign((( ! ((Math.atan2(0x07fffffff, (-0x100000001 >>> 0)) ** x) >>> 0)) , ( + ( - (Math.max(Math.fround(x), y) | 0)))))) | 0)); }); ");
/*fuzzSeed-28551573*/count=1176; tryItOut("e1.add(a0);function x([], window, ...a) { yield ((objectEmulatingUndefined)(([] = c) -= x\n)) } Object.defineProperty(this, \"i0\", { configurable: true, enumerable: true,  get: function() {  return new Iterator(o0, true); } });");
/*fuzzSeed-28551573*/count=1177; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( + Math.pow(( - Math.fround((( + Math.atanh(( + x))) << ( + y)))), Math.round(Math.fround(Math.max(Math.fround(y), Math.fround(y)))))) ? ((( + (((( - y) | 0) ** x) || ( + (((-0x080000001 & Math.fround(( ! y))) >>> 0) <= (( ! 2**53+2) | 0))))) & Math.fround(Math.min(( + -(2**53+2)), x))) | 0) : Math.fround((Math.fround(( + (( + Math.min((((((Math.pow((x >>> 0), x) | 0) | 0) - (x | 0)) | 0) / (Math.imul(y, Math.fround(Math.tan((x | 0)))) | 0)), ((y >>> 0) >>> Math.fround(( + (( + -0x080000001) === ( + (( ~ (x | 0)) | 0)))))))) | ( + ( ~ Math.tan(x)))))) << Math.fround((Math.pow((Math.max((x | 0), x) | 0), ( + ((Math.fround(Math.cos(Math.fround(Math.cbrt(x)))) | 0) >>> ((x >>> 0) ** (Math.fround((Math.fround(( ~ Math.fround(x))) >> ( + x))) >>> 0))))) | 0))))); }); testMathyFunction(mathy0, [0x07fffffff, 2**53-2, 0x080000000, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, 0.000000000000001, -(2**53+2), 0x100000000, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -0x080000001, 1/0, -0, -0x0ffffffff, 2**53, -1/0, -Number.MAX_VALUE, -0x100000000, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, -(2**53), -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, 1, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-28551573*/count=1178; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (NaN);\n    return +((Float32ArrayView[(((((/*FFI*/ff()|0))>>>(-0x88eaa*((((0x4a35a8d5))>>>((0x2bfbadfa)))))) >= (Math.max((p={}, (p.z =  /x/g )()), 511)))) >> 2]));\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ \"use strict\"; print(x);return objectEmulatingUndefined})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000001, 2**53-2, Number.MIN_VALUE, 0.000000000000001, -(2**53), 0, -0x100000000, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 0/0, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, Number.MAX_SAFE_INTEGER, 1/0, 0x07fffffff, -0x080000000, -(2**53+2), 0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, 1, 2**53+2, 0x080000000, -0, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=1179; tryItOut("\"use strict\"; for (var v of s0) { try { h0.get = (function() { try { t1 = t2.subarray(2, ({})); } catch(e0) { } try { neuter(b2, \"same-data\"); } catch(e1) { } Array.prototype.shift.call(a2); return o1.i1; }); } catch(e0) { } try { a1[1] = /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), [1], [1], [1], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [1], [1], new Number(1.5), new Number(1.5), [1], [1], [1], [1], new Number(1.5), new Number(1.5), new Number(1.5), [1], new Number(1.5), new Number(1.5), [1], [1], [1], [1], [1], new Number(1.5), [1], [1], new Number(1.5), [1], [1], [1], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [1], new Number(1.5), new Number(1.5), [1], new Number(1.5), new Number(1.5), [1], [1], new Number(1.5), [1], new Number(1.5), [1], [1], [1], new Number(1.5), [1], [1], new Number(1.5), new Number(1.5), [1], [1], new Number(1.5), new Number(1.5), new Number(1.5), [1], new Number(1.5), [1], new Number(1.5), new Number(1.5), [1], [1], [1], new Number(1.5), [1], [1], [1], [1], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [1], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [1], new Number(1.5), new Number(1.5), new Number(1.5), [1], [1], [1], [1], new Number(1.5), new Number(1.5), new Number(1.5)].sort((eval(\"/* no regression tests found */\", x))); } catch(e1) { } try { print(g1); } catch(e2) { } for (var v of e1) { h1 = ({getOwnPropertyDescriptor: function(name) { m1.has(x);; var desc = Object.getOwnPropertyDescriptor(t2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v2 = evalcx(\"function g0.g1.f2(b2) \\\"use asm\\\";   var pow = stdlib.Math.pow;\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var d3 = -549755813889.0;\\n    var d4 = -65537.0;\\n;    d4 = (((d4)) * (((((+((1.0)))) % ((d4))) + (+pow(((262145.0)), ((d4)))))));\\n    d0 = (+(0x3d8df8a8));\\n    return (((!((0xffffffff) != (undefined)))))|0;\\n  }\\n  return f;\", o2.g2);; var desc = Object.getPropertyDescriptor(t2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { /*MXX3*/g2.Math.E = o1.g0.Math.E;; Object.defineProperty(t2, name, desc); }, getOwnPropertyNames: function() { s2 = new String;; return Object.getOwnPropertyNames(t2); }, delete: function(name) { this.i1.toString = f1;; return delete t2[name]; }, fix: function() { /*RXUB*/var r = r0; var s = s2; print(s.search(r)); ; if (Object.isFrozen(t2)) { return Object.getOwnProperties(t2); } }, has: function(name) { v2 = g0.eval(\"(4277)\");; return name in t2; }, hasOwn: function(name) { o0.v2 = (g2 instanceof b2);; return Object.prototype.hasOwnProperty.call(t2, name); }, get: function(receiver, name) { v0 = (a0 instanceof g0);; return t2[name]; }, set: function(receiver, name, val) { v1 = (g2.o1.m1 instanceof t1);; t2[name] = val; return true; }, iterate: function() { v2 = g1.eval(\"h0.keys = this.f2;\");; return (function() { for (var name in t2) { yield name; } })(); }, enumerate: function() { var g1.t0 = t1.subarray(18);; var result = []; for (var name in t2) { result.push(name); }; return result; }, keys: function() { /*MXX3*/g0.Object.isExtensible = this.g0.Object.isExtensible;; return Object.keys(t2); } }); } }");
/*fuzzSeed-28551573*/count=1180; tryItOut("g1.toSource = f1;");
/*fuzzSeed-28551573*/count=1181; tryItOut("testMathyFunction(mathy1, [-(2**53), Math.PI, -(2**53+2), -0x100000001, 0x0ffffffff, 1, -0, -0x0ffffffff, -Number.MAX_VALUE, 0/0, -0x07fffffff, 2**53+2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000, -(2**53-2), 0, Number.MAX_VALUE, 1/0, 2**53-2, 42, 0x07fffffff, 2**53, Number.MIN_VALUE, -1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-28551573*/count=1182; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.max(Math.exp(Math.fround(Math.max(y, (( - (y | 0)) | 0)))), (( ~ (mathy1(Math.fround((Math.fround(( ! y)) + Math.fround(2**53-2))), (( ! ((y - y) >>> 0)) | 0)) != (Math.asin((x | 0)) | 0))) , (( + (((( + Math.pow(y, ( + x))) >>> Math.fround((( - (Math.log(y) >>> 0)) >>> 0))) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [1, 2**53+2, 0x100000000, 2**53-2, Number.MAX_VALUE, 0/0, -(2**53+2), Math.PI, -0x080000000, -Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, 0x07fffffff, 1/0, 1.7976931348623157e308, -0, 0, Number.MIN_VALUE, 0x080000001, 2**53, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, -(2**53), -0x100000001, 0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-28551573*/count=1183; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; void gc(); } void 0; }");
/*fuzzSeed-28551573*/count=1184; tryItOut("\"use strict\"; a2 = r1.exec(s2);");
/*fuzzSeed-28551573*/count=1185; tryItOut("\"use strict\"; /*bLoop*/for (var hqzdnd = 0; hqzdnd < 60; ++hqzdnd) { if (hqzdnd % 63 == 43) { print(x); } else { ( \"\" ); }  } ");
/*fuzzSeed-28551573*/count=1186; tryItOut("\"use strict\"; let ([, {c}] = \"\\u664C\", x, z = true, x = x, kkmfey, of =  '' , bkbyec, d, sicjxn, NaN) { \u0009{} }");
/*fuzzSeed-28551573*/count=1187; tryItOut("selectforgc(o0);");
/*fuzzSeed-28551573*/count=1188; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((((Math.fround(Math.expm1(( + (x ? y : (( ! (x >>> 0)) >>> 0))))) ? ( + ( + (( + ( + ( ~ x))) ^ ( + Number.MIN_SAFE_INTEGER)))) : (Math.fround(y) * Math.fround(Math.max((( + Math.pow(( + x), Math.fround(x))) >> -Number.MAX_VALUE), (Math.imul((x >>> 0), (x >>> 0)) >>> 0))))) % Math.atan2((((( ~ (y | 0)) | 0) ? ((Math.asin(Math.fround(-0x100000000)) >>> 0) | 0) : (Math.clz32(( + (Math.max((y >>> 0), (0x07fffffff | 0)) | 0))) | 0)) | 0), (( ! y) | 0))) | 0) == ((Math.tan((( + y) >>> 0)) >>> 0) !== ((((Math.trunc((y | 0)) | 0) | 0) * ((x & (( + Math.fround(y)) | 0)) | 0)) | 0))); }); testMathyFunction(mathy5, [-(2**53+2), -0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 42, 0x080000001, 0x080000000, 1/0, Math.PI, 0x07fffffff, -Number.MIN_VALUE, -0x080000000, -(2**53), 0x100000000, 2**53+2, 0, -(2**53-2), 0/0, Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -0x07fffffff, Number.MAX_VALUE, 2**53, 0.000000000000001, 2**53-2, 1.7976931348623157e308, 1, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1189; tryItOut("f2(s0);");
/*fuzzSeed-28551573*/count=1190; tryItOut("v2 = t1.byteLength;");
/*fuzzSeed-28551573*/count=1191; tryItOut("f1 + b1;");
/*fuzzSeed-28551573*/count=1192; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.fround(Math.acosh((mathy1((( + Math.fround(y)) >>> 0), (( + (y >= 0)) >>> 0)) >>> 0))), Math.fround(( + (( + ( + x)) || (Math.max((Math.exp(x) | 0), (Math.max((( + (2**53 > y)) | 0), Math.trunc(y)) | 0)) | 0)))))); }); ");
/*fuzzSeed-28551573*/count=1193; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.fround(Math.tanh(Math.fround(( ~ (((( + ((y >>> 0) ? (y >>> 0) : ( + (y >>> 0)))) >>> 0) ? (( ! (y >>> 0)) >>> 0) : Math.pow(x, y)) >>> 0))))), Math.max(Math.fround(( + ( - ( + (((y | 0) >= (((x | 0) ^ Math.fround(x)) | 0)) | 0))))), Math.fround(( ~ Math.max((x && x), 0x080000000))))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -0x0ffffffff, -0, Math.PI, -0x100000001, -0x080000001, 0.000000000000001, 42, -0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, 0x080000000, 2**53+2, 1.7976931348623157e308, 0x080000001, 1, Number.MAX_VALUE, 0x100000000, 2**53-2, -0x07fffffff, 1/0, 0/0, 0x100000001, -(2**53), 0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -1/0]); ");
/*fuzzSeed-28551573*/count=1194; tryItOut("o0 = new Object;");
/*fuzzSeed-28551573*/count=1195; tryItOut("s1 + s2;\u0009\nwith({d: /*UUV2*/(a.getInt16 = a.sub)}){for (var v of e0) { for (var p in f1) { try { /*ADP-3*/Object.defineProperty(a0, ({valueOf: function() { yield true;return 4; }}), { configurable: false, enumerable: length, writable: (d % 3 != 1), value: o2.s1 }); } catch(e0) { } for (var v of o0.g0) { g0.v2 = evaluate(\"function f2(h1)  { yield window } \", ({ global: g0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (d % 4 != 3), sourceIsLazy: true, catchTermination: true })); } } }v1 = t1.length; }\n");
/*fuzzSeed-28551573*/count=1196; tryItOut("");
/*fuzzSeed-28551573*/count=1197; tryItOut("m1.has(f2);d = \"\\uF392\";");
/*fuzzSeed-28551573*/count=1198; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=1199; tryItOut("\"use strict\"; ");
/*fuzzSeed-28551573*/count=1200; tryItOut("\"use strict\"; ;");
/*fuzzSeed-28551573*/count=1201; tryItOut("\"use asm\"; h0.set = f2;");
/*fuzzSeed-28551573*/count=1202; tryItOut("");
/*fuzzSeed-28551573*/count=1203; tryItOut("/*ADP-1*/Object.defineProperty(a0, (/*RXUB*/var r = /[^\u2489\ubf4c\\cC-\udc66\\S]/i; var s = \"\\u2c3b\"; print(s.match(r)); ), ({enumerable: false}));");
/*fuzzSeed-28551573*/count=1204; tryItOut("t2 = new Uint32Array(9);");
/*fuzzSeed-28551573*/count=1205; tryItOut("testMathyFunction(mathy2, [0/0, 0x080000000, -(2**53+2), -0x0ffffffff, 2**53-2, -(2**53), -0, 0x100000000, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, -1/0, 0x080000001, -Number.MAX_VALUE, 0x100000001, -0x080000000, 1.7976931348623157e308, 2**53, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, -0x080000001, Math.PI, 0.000000000000001, -0x100000000, -Number.MIN_VALUE, -(2**53-2), 42, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1206; tryItOut("\"use strict\"; o2.v2 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-28551573*/count=1207; tryItOut("print(intern(/$|\\B?[]|[^\\s\\u0091\u378d\\cU-\u032a]{8193}(\\3){2,}/im) >> this.__defineSetter__(\"a\", (function(x, y) { \"use strict\"; return y; })));");
/*fuzzSeed-28551573*/count=1208; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.min(( + Math.fround(Math.exp(Math.tanh(y)))), Math.fround(Math.fround(Math.hypot(( ~ ((((y | 0) > (x | 0)) >>> 0) >>> 0)), (( ~ (Math.fround((( + -0x100000000) >>> ( + y))) | 0)) ? Math.pow(Math.atan2(x, ( + Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround(x))))), Math.fround((y ? ( + x) : (Number.MAX_VALUE >>> 0)))) : (( + ( + Math.atan2(x, ((y ^ (x >>> 0)) >>> 0)))) | 0))))))); }); ");
/*fuzzSeed-28551573*/count=1209; tryItOut("valueOfreturn;");
/*fuzzSeed-28551573*/count=1210; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return Math.hypot(Math.fround(mathy1(Math.fround(( ! (Math.fround(((mathy1(( + y), Math.fround(mathy0(Math.fround(x), Math.fround(x)))) | 0) % Math.fround(Math.fround(Math.imul(( + x), Math.fround(Math.imul((( - Math.fround(y)) >>> 0), (y >>> 0)))))))) | 0))), ( + Math.hypot(( ~ (((0x100000001 >> y) ? ( + x) : ( + y)) >>> 0)), (Math.fround(Math.fround(( + 0x080000000))) ^ (Math.acos(y) >>> 0)))))), mathy2(Math.fround(Math.min((mathy0((( + (y | 0)) | 0), 42) * (y !== x)), ( + mathy2(-0x0ffffffff, ( - y))))), Math.log2((Math.hypot((( - ((x ^ 0) >>> 0)) | 0), (y | 0)) | 0)))); }); testMathyFunction(mathy4, [42, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, 0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), 0x080000001, -0x07fffffff, 0x0ffffffff, 0x100000000, 0x100000001, -0x080000001, -1/0, 2**53+2, -0x100000001, 0x07fffffff, -0x100000000, Math.PI, 0, 2**53, 1/0, -(2**53-2), 0/0, -(2**53), 2**53-2, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-28551573*/count=1211; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( - (( + Math.acos(Math.fround(Math.fround(Math.round((y <= ((( + Math.tan(Math.fround(x))) + y) >>> 0))))))) >>> 0)) / Math.imul(Math.fround(mathy3(( ~ (Math.expm1(y) | 0)), mathy2((x >>> 0), ((mathy3((mathy0(Math.fround(y), x) >>> 0), ((Math.log2(x) | 0) >>> 0)) >>> 0) >>> 0)))), ( + ( ! ( + Math.fround((Math.fround(Math.pow((Math.exp(y) >>> 0), (mathy1((y >>> 0), (y >>> 0)) >>> 0))) >= Math.fround((Math.hypot((Math.fround(Math.min(Math.fround(mathy1(y, y)), Math.fround(x))) | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0))))))))); }); testMathyFunction(mathy4, [undefined, (function(){return 0;}), /0/, [0], '/0/', null, 1, '0', ({valueOf:function(){return 0;}}), (new Boolean(false)), (new String('')), true, '', NaN, (new Number(0)), (new Boolean(true)), ({valueOf:function(){return '0';}}), false, '\\0', objectEmulatingUndefined(), [], -0, ({toString:function(){return '0';}}), (new Number(-0)), 0, 0.1]); ");
/*fuzzSeed-28551573*/count=1212; tryItOut("for (var v of t2) { try { s2 += 'x'; } catch(e0) { } try { Object.defineProperty(this, \"r2\", { configurable: false, enumerable: true,  get: function() {  return /(?:\\1|.\\B*)|(?:(?:\\b)|.{17179869183,17179869184}\\b^+)/gyi; } }); } catch(e1) { } /*RXUB*/var r = this.r1; var s = s1; print(s.replace(r, (function ([y]) { })(), \"\"));  }");
/*fuzzSeed-28551573*/count=1213; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy3(( ~ Math.fround(mathy4(Math.fround(Math.PI), (mathy2(y, x) === x)))), Math.imul((Math.hypot((( ! (y >>> 0)) == y), x) | 0), (( ~ y) | 0))); }); testMathyFunction(mathy5, [-(2**53-2), 2**53+2, -0x080000001, -0x080000000, 0x080000000, 2**53, -0x100000000, -(2**53+2), 0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 42, -1/0, 0x07fffffff, -0, 1, 0x100000001, Number.MIN_VALUE, 2**53-2, -0x100000001, 1/0]); ");
/*fuzzSeed-28551573*/count=1214; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; gcslice(197863200); } void 0; } v0 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-28551573*/count=1215; tryItOut("Array.prototype.shift.call(a1);");
/*fuzzSeed-28551573*/count=1216; tryItOut("mathy5 = (function(x, y) { return Math.hypot(( + ( + ( + mathy0(( + Math.fround(Math.abs((x | 0)))), Math.fround((Math.fround(x) === Math.fround(y))))))), ((Math.min(( - y), (( ~ ( + x)) >>> 0)) | 0) * Math.max(y, y))); }); testMathyFunction(mathy5, ['', ({valueOf:function(){return '0';}}), (new Number(-0)), [0], null, '/0/', ({valueOf:function(){return 0;}}), [], 1, 0.1, (new Boolean(false)), (function(){return 0;}), ({toString:function(){return '0';}}), /0/, '0', (new String('')), objectEmulatingUndefined(), (new Boolean(true)), '\\0', 0, -0, false, NaN, (new Number(0)), true, undefined]); ");
/*fuzzSeed-28551573*/count=1217; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( ! Math.tanh((( + ((Math.max((x >>> 0), x) || (-0x07fffffff ^ y)) ** 0)) >>> 0)))); }); testMathyFunction(mathy0, [[], (new String('')), 0, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new Number(0)), /0/, '', (new Boolean(true)), [0], 0.1, null, true, (new Boolean(false)), ({valueOf:function(){return '0';}}), (function(){return 0;}), '/0/', undefined, NaN, -0, false, 1, (new Number(-0)), '0', '\\0']); ");
/*fuzzSeed-28551573*/count=1218; tryItOut("print(x);v0 = Object.prototype.isPrototypeOf.call(t2, a1);");
/*fuzzSeed-28551573*/count=1219; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\t\\b*+)/i; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-28551573*/count=1220; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = s2; print(uneval(r.exec(s))); ");
/*fuzzSeed-28551573*/count=1221; tryItOut("for (var p in a0) { for (var p in g0.h0) { try { a2.splice(g0.g2.o1.g2.f1, p2, f2, {} = {}); } catch(e0) { } try { o2.t0 = new Uint32Array(b0); } catch(e1) { } a2.push(o2); } }");
/*fuzzSeed-28551573*/count=1222; tryItOut("mathy4 = (function(x, y) { return ((Math.atan2(( + (mathy0((x | 0), (y | 0)) ? Math.imul(( - -0x080000000), x) : ((y | (x , Math.PI)) | ( + 0.000000000000001)))), Math.atanh((Math.atan2(x, (( + (x , y)) >>> 0)) >>> 0))) | 0) / ((((mathy2(((((( ! (y > x)) | 0) >>> 0) <= (x >>> 0)) >>> 0), Math.hypot(( ! ( + -0x080000001)), y)) >>> 0) || (( ~ Math.ceil(x)) >>> 0)) >>> 0) === ( + ( ! (2**53 | 0))))); }); testMathyFunction(mathy4, [(new String('')), 0.1, '/0/', ({valueOf:function(){return 0;}}), 0, undefined, null, true, (new Number(-0)), (function(){return 0;}), (new Boolean(false)), '\\0', false, NaN, [0], [], '', '0', (new Boolean(true)), objectEmulatingUndefined(), /0/, (new Number(0)), ({toString:function(){return '0';}}), -0, 1, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-28551573*/count=1223; tryItOut("e1[\"exp\"] = h2;");
/*fuzzSeed-28551573*/count=1224; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.log10(Math.fround(( ~ y))) >>> 0) % Math.fround(Math.log(( ! (Math.acosh(mathy1((Math.sin((y | 0)) | 0), x)) | 0))))); }); testMathyFunction(mathy4, /*MARR*/[({x:3}), Infinity, Infinity, ({x:3}), Infinity, ({x:3}), ({x:3}), ({x:3}), ({x:3}), Infinity, Infinity, ({x:3}), ({x:3}), Infinity, ({x:3}), Infinity, Infinity, Infinity, Infinity, ({x:3}), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, ({x:3}), Infinity, Infinity, ({x:3}), Infinity]); ");
/*fuzzSeed-28551573*/count=1225; tryItOut("v0 = (h2 instanceof b0);");
/*fuzzSeed-28551573*/count=1226; tryItOut("h1 = {};function NaN(NaN, \u3056, NaN, d, this.a, eval, NaN, c = window, x, NaN, NaN, this, y, z = function(id) { return id }, x, y, \u3056)let (x) []m0.has(g1.o2);");
/*fuzzSeed-28551573*/count=1227; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.sin(Math.fround(Math.sign((Math.round((( + (Math.fround((Number.MIN_SAFE_INTEGER | 0)) | 0)) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-28551573*/count=1228; tryItOut("/* no regression tests found */");
/*fuzzSeed-28551573*/count=1229; tryItOut("/*RXUB*/var r = new RegExp(\"[^]{1}\", \"gm\"); var s = \"\\u10bc\\u10bc\"; print(uneval(s.match(r))); ");
/*fuzzSeed-28551573*/count=1230; tryItOut("{ void 0; validategc(false); } ({a2:z2}) in window;");
/*fuzzSeed-28551573*/count=1231; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.trunc(Math.hypot(y, Math.log1p(y)))) < Math.fround((Math.asin(((((Math.pow((Math.pow(Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE) | 0), (mathy0((y >>> 0), x) >>> 0)) >>> 0) | 0) + ( + Math.cos(x))) >>> 0)) >>> 0))) % (Math.acosh(Math.fround(Math.sinh((( + ( - Number.MIN_VALUE)) >>> ( + mathy0(((y | 0) ? x : x), y)))))) | 0)); }); testMathyFunction(mathy1, [Math.PI, 2**53, 0/0, -Number.MAX_VALUE, 2**53-2, -(2**53+2), Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, 2**53+2, -1/0, -0x07fffffff, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, -0x0ffffffff, 0, 42, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, -(2**53-2), 0x080000001, -0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0x100000001, -(2**53)]); ");
/*fuzzSeed-28551573*/count=1232; tryItOut("/*RXUB*/var r = r1; var s = g2.s0; print(s.match(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
