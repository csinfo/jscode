

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
/*fuzzSeed-116170070*/count=1; tryItOut("mathy4 = (function(x, y) { return ( + (( + Math.fround((Math.fround(((Math.fround(Math.fround(((mathy2((y | 0), (Number.MAX_VALUE | 0)) | 0) !== y))) >= Math.fround(Math.log2(x))) | 0)) >> Math.fround(( + ( ~ ( + Math.abs(Math.max(x, x))))))))) == ( - (y & y)))); }); ");
/*fuzzSeed-116170070*/count=2; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=3; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=4; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.abs(Math.min(( ! Math.fround(( ! (y ? 2**53-2 : x)))), ( + (x >> y)))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, -0x0ffffffff, 0x07fffffff, 0, -0x100000001, -(2**53+2), -0x07fffffff, 1/0, -(2**53-2), 1.7976931348623157e308, 0.000000000000001, -0, 0x080000001, 42, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, 0/0, Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, -Number.MAX_VALUE, -(2**53), 2**53+2, -Number.MIN_VALUE, -0x100000000, 0x080000000]); ");
/*fuzzSeed-116170070*/count=5; tryItOut("function shapeyConstructor(htlazg){\"use strict\"; delete htlazg[\"caller\"];htlazg[\"prototype\"] = /(?!\\b.(?!\\b)\u1cca|(?!\\3)*?)*/gyim;delete htlazg[\"caller\"];htlazg[\"getDay\"] = function(q) { return q; };htlazg[\"prototype\"] = decodeURI;for (var ytqpuznvj in htlazg) { }{ /*RXUB*/var r = /\\3/gyi; var s = \"\"; print(uneval(s.match(r)));  } htlazg[\"padEnd\"] = (4277);return htlazg; }/*tLoopC*/for (let x of /*MARR*/[new Number(1), 2**53+2, 2**53+2, new String(''), new Number(1)]) { try{let fddroz = shapeyConstructor(x); print('EETT'); this.v0 = Array.prototype.reduce, reduceRight.apply(a1, [(function() { for (var j=0;j<3;++j) { f2(j%3==1); } }), o0]);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-116170070*/count=6; tryItOut("/*infloop*/for(var w = (4277); (Math.tan(x)); ({e: allocationMarker(), /*toXFun*/toString: Number })) {g2 + a0;/* no regression tests found */ }");
/*fuzzSeed-116170070*/count=7; tryItOut("testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, Math.PI, 1/0, 1.7976931348623157e308, -0x07fffffff, -0x080000000, 0x080000000, 0x100000000, -(2**53+2), -(2**53), -Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, 1, 0, 2**53, -0x080000001, 42, -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -0, -Number.MIN_VALUE, -(2**53-2), 0/0, 0.000000000000001, 0x07fffffff, 2**53+2]); ");
/*fuzzSeed-116170070*/count=8; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.log(( + Math.fround(( ~ Math.fround((x >> Math.asin(y)))))))); }); testMathyFunction(mathy5, [0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 0x080000001, Number.MAX_VALUE, 0x0ffffffff, -(2**53+2), -(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, 0x100000000, 0x080000000, -Number.MAX_VALUE, -0, Number.MIN_VALUE, 0x07fffffff, -1/0, 42, 2**53+2, -0x100000001, 0, -0x07fffffff, -0x080000001, 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, -0x0ffffffff, -(2**53-2), 2**53-2, Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-116170070*/count=9; tryItOut(" for (let a of [\n/((.))/g , this]) {s2 + '';print(\"\\u70A0\"); }");
/*fuzzSeed-116170070*/count=10; tryItOut("v1 = o2.g2.eval(\"function f1(g0.m0)  { \\\"use strict\\\"; yield  /* Comment */(Object.defineProperty(x, \\\"arguments\\\", ({}))) for each (x in new RegExp(\\\"(?=(?:((?:$))){1,})\\\", \\\"gim\\\")) } \");\n/*bLoop*/for (bmgfxf = 0; bmgfxf < 114; ++bmgfxf) { if (bmgfxf % 4 == 1) { /* no regression tests found */ } else { (14); }  } \n");
/*fuzzSeed-116170070*/count=11; tryItOut("mathy2 = (function(x, y) { return (( + ((Math.cosh(y) >>> 0) , ( + ( + Math.exp((( ! Math.atan2(x, ( + Math.imul(( + y), ( + x))))) >>> 0)))))) ? ( + (( + ( + Math.round(((Math.fround(x) >> (Math.log10(y) >>> 0)) | 0)))) >>> Math.min(x, Math.fround(( - Math.fround(Math.asin(( + mathy1(x, (y | 0)))))))))) : ((Math.fround(Math.fround(Math.cbrt((Math.atan2((y | 0), (1 | 0)) | 0)))) === ((Math.fround(Math.atan2(Math.fround(-1/0), ( ! y))) ? Number.MIN_SAFE_INTEGER : Math.hypot((x | 0), ( + x))) | 0)) < Math.max(x, ( ! y)))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -0x080000001, 2**53-2, -(2**53-2), 1.7976931348623157e308, 0x100000001, 0x080000001, Number.MIN_VALUE, 1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, -(2**53+2), 0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, Math.PI, -(2**53), 0, 1, 0/0, 0x080000000, -Number.MIN_VALUE, -0x100000000, 42, -Number.MAX_SAFE_INTEGER, -0, -0x100000001]); ");
/*fuzzSeed-116170070*/count=12; tryItOut("mathy5 = (function(x, y) { return (( + ( + ( ~ ( + Math.fround(Math.max((y >>> 0), ((Math.tanh((Math.imul(-(2**53+2), y) | 0)) | 0) >>> 0))))))) <= ( + mathy0((Math.pow((Math.fround(( + x)) >>> 0), (Math.imul(Math.atan2(-Number.MAX_SAFE_INTEGER, -0x100000001), ((Math.max((Math.pow(x, y) | 0), (Number.MAX_SAFE_INTEGER | 0)) | 0) | 0)) | 0)) >>> 0), Math.fround((( ~ (Math.exp(x) % y)) && ( + Math.pow(( + ((Math.fround(Math.asin(x)) >>> 0) ? mathy4(0, -(2**53+2)) : 0.000000000000001)), ( + x)))))))); }); testMathyFunction(mathy5, [0x0ffffffff, -Number.MAX_VALUE, 1, 0x080000000, -0x07fffffff, 2**53+2, -0x0ffffffff, -(2**53), -(2**53-2), 1/0, 1.7976931348623157e308, 0x100000000, 2**53-2, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 2**53, 0x07fffffff, Math.PI, 0, 0.000000000000001, -0x100000000, -0, 0/0, -(2**53+2), -0x080000000, Number.MAX_SAFE_INTEGER, 42, -0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=13; tryItOut("/*RXUB*/var r = /(((?:($)|[^]))+){1,2}/gy; var s =  /x/g ; print(s.search(r)); ");
/*fuzzSeed-116170070*/count=14; tryItOut("\"use strict\"; Array.prototype.push.call(a1, g1);");
/*fuzzSeed-116170070*/count=15; tryItOut("\"use strict\"; a2.shift(e2, i0);");
/*fuzzSeed-116170070*/count=16; tryItOut("/*tLoop*/for (let x of /*MARR*/[x, x, x, x, x, x, new Number(1), x, x, x, new Number(1), x, new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), x, x, x, new Number(1), new Number(1), x, x, x, x, x, new Number(1), x, x, x, x, x, x, x, x, new Number(1), new Number(1), new Number(1), x, x, x, new Number(1), x, new Number(1), x, new Number(1), new Number(1), x, x, x, x, x, x, x, x, x, x, x, new Number(1), new Number(1), new Number(1), x, new Number(1), x, new Number(1), x, x, x, x, x, x, x, x, x, x, x, new Number(1), x, new Number(1), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1), x, x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, x, x, new Number(1), new Number(1), x, x, x, new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), x, x, x, new Number(1), x, new Number(1), x, x, new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), x, x, new Number(1), x, x, x, new Number(1), new Number(1), x, new Number(1), new Number(1), x, x, new Number(1), new Number(1), x, new Number(1), new Number(1), x, new Number(1), x, new Number(1), x, x, x, x, x, x, new Number(1), new Number(1), new Number(1), x, x, new Number(1), x, new Number(1), x, x, new Number(1), x, x, new Number(1), new Number(1), x, x, new Number(1), x, new Number(1), new Number(1), new Number(1), x]) { /*infloop*/for(var eval in ((WeakMap)(((uneval(false))))))Object.defineProperty(o2.g1, \"i2\", { configurable: function ([y]) { }, enumerable: \"\\u0ED0\",  get: function() {  return new Iterator(g0); } }); }");
/*fuzzSeed-116170070*/count=17; tryItOut("mathy3 = (function(x, y) { return ((( + (( ! ((mathy2(Math.fround(Math.fround(Math.pow(Math.fround(y), Math.fround(x)))), ( + mathy1((Math.fround(mathy1((Number.MIN_VALUE >>> 0), -1/0)) ? Math.log(-0x100000001) : mathy0((x >>> 0), y)), y))) | 0) >>> 0)) >>> 0)) | Math.trunc(Math.fround(Math.sin(Math.fround(( + (Math.fround(Math.atan(x)) && Math.fround(1/0)))))))) | 0); }); testMathyFunction(mathy3, [(new Number(-0)), -0, NaN, true, false, /0/, 0.1, (new String('')), ({valueOf:function(){return '0';}}), '/0/', null, [0], (new Boolean(false)), (new Boolean(true)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), [], '0', 1, '\\0', (new Number(0)), objectEmulatingUndefined(), (function(){return 0;}), undefined, '', 0]); ");
/*fuzzSeed-116170070*/count=18; tryItOut("for(let [e, e] = x in this) print(window);");
/*fuzzSeed-116170070*/count=19; tryItOut("const o2 = Object.create(g2.e2);");
/*fuzzSeed-116170070*/count=20; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (((0x4a16cb76) < (0x429400c5)) ? (i0) : (i1));\n    }\n    return +((-1.9342813113834067e+25));\n  }\n  return f; })(this, {ff: SharedArrayBuffer}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-116170070*/count=21; tryItOut("mathy0 = (function(x, y) { return (( - (Math.fround(Math.hypot(Math.fround(Math.max((Math.hypot(( + ((y >>> 0) >>> Math.fround(( + (( + x) <= ( + y)))))), ((y - -(2**53+2)) >>> 0)) >>> 0), ( + ( + Math.max(( ! y), (0 ? ( + y) : y)))))), Math.min(( + y), ((Math.min((( ! y) >>> 0), (y >>> 0)) >>> 0) | 0)))) | 0)) | 0); }); ");
/*fuzzSeed-116170070*/count=22; tryItOut("\"use strict\"; a2 = a1.slice();");
/*fuzzSeed-116170070*/count=23; tryItOut("\"use strict\"; with({z: x}){t2 = new Int32Array(this.b1); }\nfor (var p in h0) { try { v2 = new Number(a2); } catch(e0) { } a0 = /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, (void 0),  /x/g ,  /x/ , function(){}, (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/ , function(){}, objectEmulatingUndefined(),  /x/g , (void 0),  /x/ , function(){}, function(){}, objectEmulatingUndefined(), (void 0),  /x/g , (void 0), objectEmulatingUndefined(), (void 0)]; }\n");
/*fuzzSeed-116170070*/count=24; tryItOut("/*vLoop*/for (let ejjpei = 0; ejjpei < 67; ++ejjpei) { let x = ejjpei; throw StopIteration;[[{}, , {window(-0.154), this: x, x: {x: [], z}}, [, ]], [, x], [[]]] = a; } ");
/*fuzzSeed-116170070*/count=25; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?!(\\\\x8A)*?))\", \"yi\"); var s = \"\\ue001\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=26; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x07fffffff, 42, -0x100000001, -0, -0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, -Number.MAX_VALUE, 0x100000001, -0x080000001, 2**53+2, 0.000000000000001, -(2**53+2), 0x080000001, Number.MIN_VALUE, 0x07fffffff, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, -1/0, 1/0, -0x0ffffffff, 2**53, 0/0, 0x080000000, 0x100000000, 0x0ffffffff, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-116170070*/count=27; tryItOut("mathy3 = (function(x, y) { return Math.fround((Math.fround(Math.fround(( ! y))) ? Math.fround((Math.cos(Math.fround(Math.imul(Math.fround(( ~ Math.fround(( + mathy2(y, ( + y)))))), Math.fround(((Math.fround(x) >>> 0) & ((y >>> y) | 0)))))) >>> 0)) : Math.fround(( + Math.expm1(Math.atan2((mathy1((-0x0ffffffff | 0), 0x080000001) | 0), ( + Math.exp(( + y))))))))); }); testMathyFunction(mathy3, [-(2**53+2), 1/0, 2**53-2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -0, -0x080000000, 0x100000000, 1, 0.000000000000001, 0x080000001, 42, Math.PI, -(2**53-2), 0/0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -0x100000001, -(2**53), -Number.MAX_VALUE, -0x100000000, 0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -0x07fffffff, 2**53+2, 0, -1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=28; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.hypot(Math.fround(((Math.fround(( ~ (Math.imul((x | 0), y) | 0))) & Math.log2(Math.fround(y))) >>> 0)), ((((x + ( + x)) ? (( + Math.exp(( + (x ? ( + 0x100000000) : ( + (( ~ (x | 0)) | 0)))))) >>> 0) : mathy4(y, 2**53-2)) ^ (( ! (mathy0((x | 0), mathy0(Math.atan2(Math.fround(y), (Math.hypot(y, (1 >>> 0)) >>> 0)), x)) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-1/0, 1/0, 42, Math.PI, 0x07fffffff, 0x080000001, 2**53-2, -0x080000001, -0x080000000, 0x080000000, 2**53, -(2**53), -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, 1.7976931348623157e308, 2**53+2, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, -Number.MAX_VALUE, -0, 0x100000000, Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=29; tryItOut("\"\\u14B9\";print(x);");
/*fuzzSeed-116170070*/count=30; tryItOut("\"use strict\"; for (var p in g1.g0) { try { e0.has(g2); } catch(e0) { } e2.delete(a1); }");
/*fuzzSeed-116170070*/count=31; tryItOut("/*bLoop*/for (var spdprc = 0; spdprc < 75; ++spdprc) { if (spdprc % 4 == 2) { a2 = Array.prototype.slice.apply(a2, [-10, NaN, h2, ((makeFinalizeObserver('tenured'))), g1]); } else { return;for(let x in []); }  } ");
/*fuzzSeed-116170070*/count=32; tryItOut("this.s2 += s0;");
/*fuzzSeed-116170070*/count=33; tryItOut("Object.defineProperty(this, \"v1\", { configurable: false, enumerable: true,  get: function() {  return new Number(g2); } });");
/*fuzzSeed-116170070*/count=34; tryItOut("/*bLoop*/for (fapguo = 0; fapguo < 19 && (w = ({\u3056: x, let: 20 })); ++fapguo) { if (fapguo % 96 == 88) { a0 = arguments; } else { /*vLoop*/for (let apavnd = 0, eval; apavnd < 7; ++apavnd) { y = apavnd; print(a0); }  }  } ");
/*fuzzSeed-116170070*/count=35; tryItOut("g2.h1.set = (function(a0, a1, a2, a3) { var r0 = a0 / a1; var r1 = a0 * a1; var r2 = a2 - a0; var r3 = x - a2; print(a2); var r4 = a1 / r0; var r5 = r0 + a1; var r6 = r2 % 7; var r7 = a3 % r2; r6 = 2 / r7; var r8 = r2 ^ r7; var r9 = r2 * 4; var r10 = r4 + r8; var r11 = 9 - x; r9 = r0 ^ r3; var r12 = r7 & a2; var r13 = r11 + a1; var r14 = r7 | r0; r0 = 7 | a2; var r15 = a0 % r3; var r16 = 8 / r15; r1 = x ^ r11; print(r3); var r17 = 9 | a3; var r18 = r5 | 3; var r19 = 2 % 9; r10 = 7 / r8; var r20 = 5 & 6; var r21 = r12 - r5; var r22 = r19 * r1; r4 = 1 | r14; r1 = 2 * r22; var r23 = 4 - r21; var r24 = r7 & a1; var r25 = r17 & 9; r21 = r4 - r16; r25 = 1 - r16; var r26 = a0 * 1; var r27 = 6 % r25; var r28 = 5 | a3; var r29 = r17 + 8; var r30 = 3 * 6; var r31 = r20 & 6; r27 = r7 ^ a0; var r32 = r1 & r31; var r33 = 2 + 2; var r34 = 4 % 2; var r35 = r6 / r8; var r36 = r9 | r9; r20 = 1 * 7; var r37 = r26 & r4; var r38 = 1 - 7; r4 = 6 | 1; var r39 = r27 | r28; r24 = r13 & 8; r19 = 2 * a2; r21 = r5 % r1; r29 = r22 + r28; var r40 = r32 % 2; var r41 = 4 + 9; r11 = 8 + r8; var r42 = r36 % 7; r41 = r0 - 2; var r43 = 4 & r21; r28 = r11 - r31; a1 = a1 & r20; var r44 = r20 ^ r3; r43 = r1 - a0; var r45 = a0 ^ r24; return a2; });");
/*fuzzSeed-116170070*/count=36; tryItOut("\"use strict\"; M:switch((new ((1 for (x in [])))([,,]))) { default:  }");
/*fuzzSeed-116170070*/count=37; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.min(Math.fround((( ~ (Math.trunc((( - (Number.MIN_VALUE >>> 0)) >>> 0)) >>> 0)) >>> 0)), Math.fround(Math.sign(Math.imul(Math.tanh(Math.fround((y ? Math.fround(0x0ffffffff) : Math.fround(( + Math.imul(( + 0x100000000), Math.fround(x))))))), Math.asinh(((Math.acosh((Math.fround((Math.fround(Number.MIN_SAFE_INTEGER) || (y | 0))) | 0)) | 0) ? x : x))))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 42, -Number.MAX_VALUE, 0.000000000000001, -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, 0, 2**53-2, 0x100000000, Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, -0x100000001, -1/0, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 1/0, 0x080000001, -0x07fffffff, -(2**53), 0x100000001, 0x07fffffff, 2**53+2, -0x080000001, -0x100000000, -0, 1.7976931348623157e308]); ");
/*fuzzSeed-116170070*/count=38; tryItOut("let(x = delete x.x, e = x, b = (function  x () { \"use strict\"; yield /.^{4}|(?=\\3+){3,}\u00b3[^](.|\\b)\\3$\\u000a+?/i } ).call(this, ), ofdqpy, x = new ((new  /x/g ( /x/g ,  \"\" )))((makeFinalizeObserver('tenured'))), w = (new ((4277))(length.unwatch(\"d\"), x)), x = Math.hypot(-7, prototype), x = NaN >>> eval, \u3056) { 13[6] = a;}");
/*fuzzSeed-116170070*/count=39; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((mathy3((Math.max((Math.sinh(2**53-2) > ( + y)), Math.fround(( + Math.hypot(( + x), ( + x))))) | 0), Math.max(Math.fround(Math.imul(( + y), mathy2((Math.min((Math.hypot(( + x), 1.7976931348623157e308) >>> 0), Math.fround(y)) | 0), Math.imul((x | 0), ( + y))))), Math.fround(((y && ( + y)) | 0)))) != Math.fround(( + (y ? (Math.round(mathy0(mathy2(y, x), Math.atanh(x))) | 0) : Math.max(Math.fround((mathy3(Math.PI, Math.asinh(y)) | 0)), -1/0))))) | 0); }); testMathyFunction(mathy4, [1.7976931348623157e308, 1/0, -(2**53), -0x100000000, 2**53-2, 2**53, -1/0, 0x100000001, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, 42, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000001, -0, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, 0, 0x080000001, -0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, 0x100000000, -(2**53-2), -(2**53+2), 1]); ");
/*fuzzSeed-116170070*/count=40; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.min(Math.fround(( ! ((y * x) >= ( + Math.fround((Math.fround((-0x07fffffff ? Math.imul(y, 0/0) : Math.fround(( ~ x)))) != x)))))), ( + ( + ( + Math.max(( + (0x080000000 | ( + ((Math.sqrt(y) & -(2**53)) | 0)))), Math.fround(Math.round(( + y)))))))); }); ");
/*fuzzSeed-116170070*/count=41; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + (mathy0((( + ( + Math.min(( + Math.sinh(x)), ( + (( ~ (x >>> 0)) >>> 0))))) != Math.max(Math.fround((Math.atan2(Math.atan2(Math.fround(x), ( ! x)), Math.fround(Math.hypot((x | 0), Math.fround(mathy1(-0x0ffffffff, -(2**53+2)))))) | 0)), Math.fround(y))), (Math.tan(( + ((Math.cosh(y) === y) ? x : (Math.acosh(( + Math.fround(( + ((( + x) + ( + x)) >>> 0))))) | 0)))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), (new Boolean(true)), null, (new String('')), undefined, (new Boolean(false)), '\\0', (function(){return 0;}), '0', objectEmulatingUndefined(), '/0/', [0], /0/, (new Number(-0)), -0, '', ({valueOf:function(){return 0;}}), [], NaN, (new Number(0)), true, ({valueOf:function(){return '0';}}), 0.1, 0, 1, false]); ");
/*fuzzSeed-116170070*/count=42; tryItOut("\"use strict\"; for(var y in new (String.prototype.localeCompare)()) \u0009/*infloop*/ for (y of x) {print(window); '' ; }");
/*fuzzSeed-116170070*/count=43; tryItOut("o0.v2 = Object.prototype.isPrototypeOf.call(f1, s0);");
/*fuzzSeed-116170070*/count=44; tryItOut(" for  each(var y in x) {a1.reverse(g0); }");
/*fuzzSeed-116170070*/count=45; tryItOut("\"use strict\"; /*MXX2*/g2.Array.prototype.fill = m0;\nf1.__iterator__ = (function(j) { if (j) { try { v2 = (o2 instanceof f0); } catch(e0) { } for (var p in b1) { try { v2 = a0.reduce, reduceRight((function() { for (var j=0;j<4;++j) { g0.o1.f0(j%5==0); } })); } catch(e0) { } try { for (var v of g2.m1) { g1.o1 + b0; } } catch(e1) { } try { g2.s2 = s1.charAt(3); } catch(e2) { } r0 = /(?:.{4,5}|[]+?|^?)/gyim; } } else { try { o0 = new Object; } catch(e0) { } try { v2 = a1.length; } catch(e1) { } try { g1.g0.b0.__proto__ = o2; } catch(e2) { } h0.has = (function(j) { if (j) { v1 + ''; } else { try { v0 = evaluate(\"s0 += 'x';\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination:  /x/g  })); } catch(e0) { } try { a2 + this.i1; } catch(e1) { } try { this.v2 = this.t1.length; } catch(e2) { } for (var p in m0) { Array.prototype.pop.apply(a2, [t1, a1, o0, t2, m0]); } } }); } });\n");
/*fuzzSeed-116170070*/count=46; tryItOut("\"use strict\"; a2.toString = (function() { for (var j=0;j<26;++j) { f0(j%4==0); } });");
/*fuzzSeed-116170070*/count=47; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return ((((4.835703278458517e+24) == (-6.044629098073146e+23))))|0;\n    i2 = ((+(-1.0/0.0)) != (d0));\n    return (((Int8ArrayView[0])))|0;\n    return ((((((let (fuilwc, window = x) this.__defineGetter__(\"NaN\", function(y) { \"use strict\"; yield y; for (var v of o2) { try { i0.toSource = (function mcc_() { var avyolg = 0; return function() { ++avyolg; f2(/*ICCD*/avyolg % 6 == 3);};})(); } catch(e0) { } try { /*MXX2*/o2.g2.String.prototype.blink = o0.o0; } catch(e1) { } e0.add(i2); }; yield y; })\u000c))>>>((i2)-(i1))) >= ((((i2)) >> ((i1)+(i1)-(0xadab36f9)))))+(0x34eca0a4)))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ v2 = Array.prototype.reduce, reduceRight.apply(a2, [Map.prototype.entries.bind(h1)]);return objectEmulatingUndefined})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, 0/0, 2**53, -0x080000000, 0x07fffffff, -0, -(2**53), 0x0ffffffff, -(2**53+2), -1/0, 42, -0x100000001, 0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 2**53+2, Math.PI, 0x080000000, -0x07fffffff, 0x080000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53-2, 1/0, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=48; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(Math.fround(Math.log1p((( ~ (Math.hypot(( + Math.acosh(( + -0x07fffffff))), y) >>> 0)) | 0)))), Math.tanh(((((Math.pow((y | 0), (((y % y) >>> 0) >>> 0)) | 0) > (Math.clz32(((( + ( ! (-Number.MAX_VALUE >>> 0))) , x) | 0)) | 0)) | 0) | 0)))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -0x100000001, 42, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 0x080000000, 0x0ffffffff, 1/0, 2**53, Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, 0x07fffffff, 0/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 0.000000000000001, -(2**53-2), 1, 2**53+2, -(2**53+2), Math.PI, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 0, -0, -0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=49; tryItOut("/*infloop*/ for  each(var e in  \"\" ) g2.v0.toString = (function(j) { if (j) { try { v1 = Object.prototype.isPrototypeOf.call(a0, m0); } catch(e0) { } try { /*ODP-1*/Object.defineProperty(g0.b0, \"wrappedJSObject\", ({get: /*wrap2*/(function(){ \"use strict\"; var fabmri =  \"\" ; var wiwrbt = -12; return wiwrbt;})()})); } catch(e1) { } try { g2.v0 = Object.prototype.isPrototypeOf.call(i2, s0); } catch(e2) { } /*RXUB*/var r = this.r1; var s = s1; print(r.exec(s));  } else { a1.forEach(f0, this.g1.s1); } });");
/*fuzzSeed-116170070*/count=50; tryItOut("p1 = Proxy.create(h2, o2);var w = eval = eval(\"t2.set(a0, 9);\");");
/*fuzzSeed-116170070*/count=51; tryItOut("\"use strict\"; t0[true.__defineSetter__(\"eval\", (new Function(\"(window);\"))) |= function(id) { return id } in null] = s2;(void schedulegc(g2));");
/*fuzzSeed-116170070*/count=52; tryItOut("{ void 0; disableSPSProfiling(); }");
/*fuzzSeed-116170070*/count=53; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, 2**53-2, 42, 0x080000001, 0, -0x100000001, -0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_VALUE, -0, -1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -0x080000000, 0x100000001, 0x0ffffffff, 1, -(2**53), 0/0, -0x100000000, -0x080000001, 2**53, 0x100000000, 2**53+2, 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=54; tryItOut("t2 = new Int32Array(o2.a1);");
/*fuzzSeed-116170070*/count=55; tryItOut("M:switch([[]]) { case 2: break;  }");
/*fuzzSeed-116170070*/count=56; tryItOut("\"use asm\"; v2 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-116170070*/count=57; tryItOut("testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 0x080000001, -Number.MIN_VALUE, -0x100000001, -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0, -0x080000001, 0x100000001, 0x080000000, 0/0, Math.PI, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, 0x100000000, -0x0ffffffff, 0.000000000000001, 42, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, -(2**53-2), 1, 0x0ffffffff, 0x07fffffff, 2**53+2, Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-116170070*/count=58; tryItOut("\"use strict\"; v1 = (s2 instanceof t2);let a = -13;");
/*fuzzSeed-116170070*/count=59; tryItOut("Array.prototype.unshift.call(a1, o1, new (1 for (x in []))(runOffThreadScript, /(?=(?=(?!\\B+)){65})/im), f1);");
/*fuzzSeed-116170070*/count=60; tryItOut("delete g1.i1[\"__parent__\"];");
/*fuzzSeed-116170070*/count=61; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(mathy0(Math.fround(( + Math.fround(( + (( + ((-0x100000000 >>> 0) % ( - 0x0ffffffff))) , ( + x)))))), Math.min((( ! (((( ! Math.fround(x)) | 0) ? y : (y >>> 0)) | 0)) | 0), ( ~ -0x080000001)))), (( ~ (y || y)) ? Math.min(y, (((Math.hypot(( - (x >>> 0)), ((x | 0) ? Math.min(1/0, 2**53) : (Math.fround(-0x080000001) <= Math.fround(y)))) | 0) << Math.fround(Math.fround((-Number.MIN_SAFE_INTEGER >> x)))) | 0)) : ( + Math.atanh(Math.acos(( + Math.pow(y, ( + y)))))))); }); testMathyFunction(mathy1, [-0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, 0x100000001, 0/0, 0.000000000000001, Math.PI, -1/0, 1, -0x080000000, 1.7976931348623157e308, 0x07fffffff, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -(2**53+2), -0x100000001, -0x07fffffff, 0x100000000, 2**53-2, 42, -0, 0x0ffffffff, 0]); ");
/*fuzzSeed-116170070*/count=62; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-116170070*/count=63; tryItOut("/*ODP-3*/Object.defineProperty(this.g1, (new (function(y) { \"use asm\"; yield y; /*RXUB*/var r = /(?=\\2)+?(?!\\s)?/i; var s = undefined; print(uneval(r.exec(s))); ; yield y; })(x, true)), { configurable: false, enumerable: false, writable: (x % 6 != 2), value: t1 });");
/*fuzzSeed-116170070*/count=64; tryItOut("if((x % 3 == 1)) { if ((4277)) {let (jlvgap, smzyhb, x, waxrst, eval, eval, b, y, x, fbsinl) { print(x *= window); }e0.__proto__ = f2; }} else w+=14;");
/*fuzzSeed-116170070*/count=65; tryItOut("\"use strict\"; const v1 = g2.runOffThreadScript();");
/*fuzzSeed-116170070*/count=66; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=67; tryItOut("e1 = new Set(i0);");
/*fuzzSeed-116170070*/count=68; tryItOut("g1.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-116170070*/count=69; tryItOut("var r0 = x * x; x = x + r0; x = x - r0; r0 = r0 / r0; var r1 = 6 + r0; x = r0 - 2; var r2 = 8 - 8; var r3 = r2 - 7; var r4 = r0 % r3; var r5 = r3 | 7; var r6 = 6 - r2; var r7 = r1 - r2; var r8 = r3 % r7; var r9 = 0 + r5; r0 = r1 | r3; var r10 = r4 / 3; var r11 = r5 % 2; var r12 = r2 / r2; r5 = 4 | r4; var r13 = r3 - r10; var r14 = r6 ^ 7; var r15 = 5 % x; var r16 = 4 & r13; var r17 = r6 + 0; r0 = 3 - r1; var r18 = r15 + r15; var r19 = 4 & 6; var r20 = r12 ^ r16; var r21 = r3 % r12; var r22 = 5 / r7; var r23 = r1 ^ 0; var r24 = r13 ^ 4; var r25 = r17 * 1; var r26 = 8 % r24; var r27 = r0 * r26; var r28 = r18 * 0; var r29 = 0 / r2; var r30 = r27 % r21; r0 = r20 ^ 0; r2 = 1 / r12; r14 = 8 | r28; var r31 = r2 - r6; var r32 = r13 % r24; var r33 = r32 - r19; var r34 = 8 % x; var r35 = r12 ^ r1; var r36 = r23 / r30; var r37 = r32 & r28; r32 = r34 ^ 4; var r38 = r4 & r16; var r39 = r16 * r36; var r40 = r7 - r39; r35 = r27 + r25; ");
/*fuzzSeed-116170070*/count=70; tryItOut("print(new RegExp(\"$.*\", \"\"));");
/*fuzzSeed-116170070*/count=71; tryItOut("i1 = new Iterator(f0, true);");
/*fuzzSeed-116170070*/count=72; tryItOut("mathy0 = (function(x, y) { return (((Math.fround((( + ( + ((( + (( + y) >>> 0)) | 0) & ( + Math.fround((Math.fround(Math.max(( + (Math.imul((y | 0), (-0x100000000 | 0)) | 0)), ( + 1.7976931348623157e308))) === Math.fround(((((( ~ (x >>> 0)) >>> 0) >>> 0) ** ((Math.cos((x | 0)) | 0) >>> 0)) >>> 0)))))))) ^ ( + Math.atan(Math.sqrt(( + Math.pow(( + Math.pow(y, x)), ( + x)))))))) | 0) && (y === 0x100000001)) !== ( + (Math.fround(Math.max(-(2**53), ((( ! ((Math.atan2((y | 0), ( + y)) | 0) | 0)) | 0) || (( + 1) | 0)))) + ( ~ ((y ? Math.cos((0x080000001 >>> 0)) : y) >>> 0))))); }); testMathyFunction(mathy0, [0, 2**53-2, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, 0x100000001, 0/0, -(2**53), 2**53+2, -0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, -0x080000000, 1.7976931348623157e308, -0x100000000, -(2**53-2), -0x080000001, 1, -Number.MAX_VALUE, 2**53, -1/0, Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, Math.PI, -0, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0x080000001, 0x100000000]); ");
/*fuzzSeed-116170070*/count=73; tryItOut("testMathyFunction(mathy1, [2**53, 1/0, -0x080000001, -0, 0, -0x080000000, 0.000000000000001, 0x0ffffffff, Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, 1, 0/0, -(2**53), 2**53-2, -Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff, 42, 2**53+2, -0x100000001, 0x07fffffff, -0x100000000, 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=74; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.atan2((( + ( - ((Math.hypot(Math.fround(x), Math.fround(( - x))) >>> 0) < (Math.imul(0/0, 42) >>> 0)))) !== ( + ((Math.hypot(Math.cosh(( + (( + 2**53) ** ( + ( + Math.imul(x, ( + x))))))), y) | 0) != (Math.hypot((Math.fround((Math.fround(((x >>> 0) - (y >>> 0))) ? Math.fround((Math.pow(x, x) ? Math.PI : 0x080000001)) : Math.fround(x))) >>> 0), (Math.pow(0x100000001, ((((Number.MAX_VALUE < y) >>> 0) < (y >>> 0)) >>> 0)) >>> 0)) >>> 0)))), (( + Math.atanh(( - 0x080000000))) != ((y == y) | 0))); }); testMathyFunction(mathy0, [-1/0, -(2**53-2), Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, -(2**53), -0, -Number.MIN_VALUE, -0x100000000, 0x100000001, -(2**53+2), 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, 0x100000000, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, Number.MAX_VALUE, 0x0ffffffff, -0x100000001, 2**53+2, -0x07fffffff, 0x07fffffff, 1/0, 0, Math.PI, -0x080000000]); ");
/*fuzzSeed-116170070*/count=75; tryItOut("testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, -0x100000001, -0x100000000, 0/0, 0x07fffffff, 2**53-2, -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, -1/0, -(2**53+2), -(2**53-2), 1, 2**53+2, 0x080000001, 2**53, -0x080000001, -(2**53), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Math.PI, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_VALUE, -0, -0x0ffffffff, 0]); ");
/*fuzzSeed-116170070*/count=76; tryItOut("/*RXUB*/var r = r2; var s = s0; print(s.search(r)); ");
/*fuzzSeed-116170070*/count=77; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - ( + Math.log1p(( + Math.sin((Math.log2(y) | 0)))))); }); testMathyFunction(mathy1, [1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, -(2**53+2), Math.PI, 1.7976931348623157e308, -0, 2**53, -(2**53-2), Number.MAX_VALUE, 0.000000000000001, 0/0, 0x100000001, 0x07fffffff, -0x0ffffffff, 2**53+2, 0, 1, 42, -(2**53), 0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, 0x100000000, -0x100000000, -1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-116170070*/count=78; tryItOut("g2.v0.toSource = (function() { for (var j=0;j<22;++j) { f2(j%2==1); } });");
/*fuzzSeed-116170070*/count=79; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-116170070*/count=80; tryItOut("if(false) {zgelog();/*hhh*/function zgelog(window, eval, ...x){print(x);} } else {\"\\u641E\"; }");
/*fuzzSeed-116170070*/count=81; tryItOut("Array.prototype.sort.call(a2, (function(j) { if (j) { try { this.a0.reverse(); } catch(e0) { } v2 = t2.BYTES_PER_ELEMENT; } else { try { /*MXX2*/g2.URIError.prototype.name = m2; } catch(e0) { } a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = fillShellSandbox(newGlobal({ sameZoneAs:  /x/g , cloneSingletons: false })); f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } }), m2, i1, o2);s0 += s2;");
/*fuzzSeed-116170070*/count=82; tryItOut("o2.v2 = Object.prototype.isPrototypeOf.call(h0, g0.e0);");
/*fuzzSeed-116170070*/count=83; tryItOut("/*infloop*/L:for(z in Object.defineProperty(b, \"getDate\", ({get: Object.prototype.__lookupGetter__, configurable: false}))) {/* no regression tests found *//*infloop*/for(var x in /./gym) {this.g2.v1 = Object.prototype.isPrototypeOf.call(b2, b2); } }");
/*fuzzSeed-116170070*/count=84; tryItOut("v1 = g0.eval(\"t2 = new Int16Array(this.b2);\");");
/*fuzzSeed-116170070*/count=85; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116170070*/count=86; tryItOut("\"use strict\"; /*vLoop*/for (gdvsth = 0, x , x; gdvsth < 16; ++gdvsth) { let z = gdvsth; L:for(var c in Math.hypot(this, [,,])) b2.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) { a5 = a8 * a9; a1 = 4 | a4; var r0 = 1 / x; var r1 = 7 * z; a5 = a1 / a5; var r2 = a4 / 4; var r3 = a0 ^ 8; var r4 = r3 ^ 7; var r5 = a0 | a6; var r6 = a7 - 8; var r7 = a0 % r4; var r8 = 8 * 9; var r9 = 0 * 4; var r10 = c / r7; var r11 = r2 ^ 8; var r12 = 8 + 0; var r13 = 1 / 3; var r14 = a4 & r7; print(a2); r12 = a1 & z; var r15 = r0 + 1; var r16 = 8 + 5; var r17 = r0 % r15; a8 = r10 & a4; var r18 = a7 / r14; r3 = 8 | r1; var r19 = a4 & 4; var r20 = 1 % r17; var r21 = r5 - 9; var r22 = r10 + 8; var r23 = r7 + 3; var r24 = 3 ^ a7; var r25 = a4 | r0; var r26 = r21 - 8; r11 = 9 * a6; var r27 = r12 * r6; a1 = a5 & r9; var r28 = 1 ^ r5; var r29 = r12 ^ 5; var r30 = r23 | a5; var r31 = r1 / 2; r10 = a6 - 9; r8 = r5 % 6; var r32 = 9 + 8; var r33 = a3 * x; var r34 = r23 ^ r7; var r35 = r23 ^ 8; var r36 = r1 + c; var r37 = 9 ^ 9; r13 = r5 - r13; r10 = r33 & 9; r10 = a5 - r33; var r38 = r13 % r32; var r39 = r16 * r26; r20 = r22 % r35; var r40 = r34 ^ a5; var r41 = 0 - a0; return a1; }); } ");
/*fuzzSeed-116170070*/count=87; tryItOut("let (d) { /*MXX2*/g1.URIError.length = m2; }");
/*fuzzSeed-116170070*/count=88; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((( + (y != (( - Math.fround((( ! (Math.min(Math.sin(x), y) >>> 0)) >>> 0))) >>> 0))) & Math.atan2((mathy0(-Number.MAX_SAFE_INTEGER, y) | 0), Math.asin(y))) ? ( - Math.hypot(Math.fround(( + Math.fround(x))), mathy0(( + ( + ( + ( - Math.max(2**53+2, Math.fround(x)))))), x))) : (( + Math.min((Math.min((Math.sinh((Math.atan2((x >>> 0), y) >>> 0)) >>> 0), x) | 0), (y | 0))) | 0)) | 0); }); testMathyFunction(mathy1, [0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, 0x080000000, 0x100000001, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, 0, -0, 1/0, -0x100000000, 0x100000000, -0x07fffffff, -0x0ffffffff, -(2**53), Math.PI, 0x07fffffff, -0x080000000, 1.7976931348623157e308, -(2**53+2), 1, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, 42, 2**53, 2**53+2, 0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=89; tryItOut("\"use strict\"; Array.prototype.push.apply(a1, [o1, e2, this.o0, o2]);");
/*fuzzSeed-116170070*/count=90; tryItOut("v2 = Object.prototype.isPrototypeOf.call(a1, g1);");
/*fuzzSeed-116170070*/count=91; tryItOut("m0.delete(e1);");
/*fuzzSeed-116170070*/count=92; tryItOut("mathy3 = (function(x, y) { return (Math.sign((((Math.fround(Math.pow(Math.fround(x), Math.fround(42))) | 0) | ( ~ (( + (Math.PI | 0)) | 0))) | 0)) >>> 0); }); testMathyFunction(mathy3, [1/0, 0.000000000000001, -0x100000001, -(2**53), Number.MAX_VALUE, 0x080000000, 0x0ffffffff, 0, -(2**53-2), 0/0, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, 1, 42, 2**53, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53+2, -(2**53+2), -0x100000000, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x100000001, -0x07fffffff, 2**53-2, -0, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 0x07fffffff, 0x100000000]); ");
/*fuzzSeed-116170070*/count=93; tryItOut("testMathyFunction(mathy3, [-(2**53+2), Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, 0x100000000, 1, 0x080000000, 0.000000000000001, -Number.MAX_VALUE, -(2**53), Number.MAX_VALUE, 0x07fffffff, 42, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -0x080000001, -0, Math.PI, -(2**53-2), 0/0, -0x100000001, -0x0ffffffff, -0x100000000, -0x07fffffff, 2**53+2, 1/0, Number.MIN_VALUE, 0x080000001, 2**53-2, 0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=94; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (i0);\n    switch ((~((!((0xffffffff) ? (0xa2365342) : (0xfe2a8171)))))) {\n    }\n    i1 = (((((0xc2dd44f))-(i1))>>>(((((0x4ef3908c)+(-0x8000000)) >> ((-0x8000000)-(0xd02abd92))) == (imul((i1), ((0x8a160ae4)))|0))-((+(-1.0/0.0)) >= ((Float32ArrayView[1]))))) == (((((Int8ArrayView[((0x95652224)) >> 0])) | ((i1))) % (((0x4a40ead6) / (0x29077966)) | (-0xfffff*(i1))))>>>((0x577532cc) / (((0xa60f0fc)+(0x9b33927c)-(0x1101535f))>>>((0xfcfbe0c2))))));\n    i0 = ((((i1))>>>(((0xe803b353))+(i0))) <= (((0xbf7c2187) / (0xc13b1bc))>>>((i2)+((4097.0) < (2097151.0)))));\n;    switch ((((0x35987815) % (0x4fc671f2)) ^ (((((0x9fe1ab37))>>>((0xf885f9e8))))))) {\n      case -3:\n        i1 = (0xff4b278);\n        break;\n      case 0:\n        i0 = ((i1) ? ((+(~~(+pow(((+((268435457.0)))), ((((3.022314549036573e+23)) / ((-17592186044417.0)))))))) < (36893488147419103000.0)) : (i0));\n        break;\n    }\n    return (((i0)-(i0)+(i1)))|0;\n  }\n  return f; })(this, {ff: Object.create}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-1/0, 1, -(2**53-2), 0x07fffffff, Math.PI, 2**53+2, 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -0x080000001, 2**53-2, -0x080000000, -(2**53+2), 0.000000000000001, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, -0x0ffffffff, -Number.MIN_VALUE, 0x080000000, 2**53, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, 0x100000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 0]); ");
/*fuzzSeed-116170070*/count=95; tryItOut("var gxxwno = new SharedArrayBuffer(4); var gxxwno_0 = new Uint8Array(gxxwno); print(gxxwno_0[0]); print(gxxwno_0[0]);");
/*fuzzSeed-116170070*/count=96; tryItOut("m2.toSource = (function(j) { if (j) { t0 = new Uint8Array(b2, 17, 11); } else { try { h0 = g0.a2[14]; } catch(e0) { } this.e0.has(s2); } });");
/*fuzzSeed-116170070*/count=97; tryItOut("mathy0 = (function(x, y) { return (( + (( + (( - Math.fround(( + y))) >>> 0)) || (Math.atanh(((Number.MAX_SAFE_INTEGER - Math.cos(y)) >>> 0)) | 0))) === ( ! Math.pow((( ~ ( + -Number.MIN_SAFE_INTEGER)) + y), ((y <= y) ** (Math.sinh((y >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, /*MARR*/[true, objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, true, objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, objectEmulatingUndefined()]); ");
/*fuzzSeed-116170070*/count=98; tryItOut("var x, y, x;selectforgc(o1);");
/*fuzzSeed-116170070*/count=99; tryItOut("e0.delete(g1);");
/*fuzzSeed-116170070*/count=100; tryItOut("(x);");
/*fuzzSeed-116170070*/count=101; tryItOut("/*ADP-1*/Object.defineProperty(a0, 3, ({value: new Symbol(new RegExp(\"(?:[\\\\D\\\\cQ-\\\\\\u0a35\\\\W\\\\w])*|\\\\x03|\\\\xe2[^]*?|\\\\B|(?:^|(?!^+?)?)\\\\1|(?![^\\u00c8\\\\cH-\\\\\\ue93d\\u00ff]){0,}|(\\\\b*){3,}\", \"yim\")) || ( /* Comment */{})}));");
/*fuzzSeed-116170070*/count=102; tryItOut("\"use strict\"; for (var p in b0) { try { h2.enumerate = f1; } catch(e0) { } try { selectforgc(o0); } catch(e1) { } try { m1.get(s0); } catch(e2) { } a0 = Array.prototype.slice.call(a1, NaN, NaN); }");
/*fuzzSeed-116170070*/count=103; tryItOut("mathy4 = (function(x, y) { return ((mathy3((Math.fround((Math.fround(Math.min(( ! x), ((( ! x) | 0) | 0))) <= Math.fround(mathy1(x, Math.imul(x, y))))) >>> 0), ( + x)) >>> 0) >>> ( ! Math.fround((Math.imul(Math.fround((Math.atan(x) >>> 0)), Math.fround(( ! mathy0(( + mathy2(y, -(2**53-2))), ( + 2**53))))) >>> 0)))); }); ");
/*fuzzSeed-116170070*/count=104; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=105; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((Uint8ArrayView[((0xe70a2c7e)*0x93cfd) >> 0])))|0;\n    return (((i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: Array.prototype.reduce}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0.000000000000001, 2**53, 0x080000001, 0/0, 0, -1/0, 0x0ffffffff, -Number.MIN_VALUE, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0x0ffffffff, 1/0, Number.MAX_VALUE, -0x080000000, 0x100000000, 0x080000000, 0x100000001, 2**53+2, 42, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -(2**53-2), -0x100000000, -0x100000001, Math.PI, -(2**53), 1, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=106; tryItOut("testMathyFunction(mathy4, [false, ({valueOf:function(){return 0;}}), NaN, ({toString:function(){return '0';}}), [0], '', '/0/', ({valueOf:function(){return '0';}}), (new String('')), (new Boolean(true)), /0/, '0', (new Number(0)), (new Number(-0)), 0, [], -0, '\\0', 1, (new Boolean(false)), objectEmulatingUndefined(), undefined, 0.1, (function(){return 0;}), null, true]); ");
/*fuzzSeed-116170070*/count=107; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.pow(Math.imul((( ! ( + ((Math.pow((y >>> 0), (( + Math.fround(y)) >>> 0)) >>> 0) | 0))) >> (y % Math.asin((( - (Math.sign(x) | 0)) >>> 0)))), Math.log(( + ((y ? -(2**53+2) : (x >>> 0)) ? -0x07fffffff : x)))), ( + ( + ( - ( ! Math.fround(Math.atanh(-Number.MAX_VALUE))))))); }); testMathyFunction(mathy5, [-0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 42, Number.MIN_VALUE, 1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, 0x100000001, -0x080000001, 0, 2**53-2, -0x080000000, Math.PI, 2**53, 1, 2**53+2, 0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, 0/0, 0x080000001, -1/0, -0x100000001, -(2**53+2), 0x100000000, -(2**53-2)]); ");
/*fuzzSeed-116170070*/count=108; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.hypot((y >= Math.cosh((x <= Number.MAX_VALUE))), Math.fround(Math.log2(x))) === ((((y >>> 0) & ( + (x > mathy2(x, y)))) ? (y >>> 0) : Math.fround(Math.abs(Math.fround(Math.fround(Math.tan(Math.fround((mathy3(((x ** x) | 0), (y | 0)) | 0)))))))) + Math.clz32((Math.cos(( + (((0x0ffffffff | 0) % (x | 0)) | 0))) ? ( + ( ~ x)) : (y ? x : ( ! ( + 2**53+2))))))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 2**53, 1/0, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 0x0ffffffff, 0/0, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, 1, Number.MAX_VALUE, -(2**53), Math.PI, Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000000, 0x080000001, -Number.MAX_VALUE, -(2**53+2), -0, 0, 0x100000001, 0x080000000, -1/0, -0x100000001, 42, -0x080000001, 2**53+2, 2**53-2]); ");
/*fuzzSeed-116170070*/count=109; tryItOut("\"use strict\"; /*infloop*/L:for(var x; x; (4277)) {print((void options('strict')).eval(\"/* no regression tests found */\")); }");
/*fuzzSeed-116170070*/count=110; tryItOut("a2.sort((function() { try { ; } catch(e0) { } try { for (var p in t0) { print(uneval(t1)); } } catch(e1) { } h1.__proto__ = g2; return t1; }));");
/*fuzzSeed-116170070*/count=111; tryItOut("const x;;");
/*fuzzSeed-116170070*/count=112; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + Math.pow(( + ( + ( ~ ( + mathy0(Math.sqrt((y >>> 0)), mathy0(0x07fffffff, y)))))), ( + ( + ( ~ ( + y)))))) / (((( ~ y) | 0) ? ( + ( ~ (( - Math.sqrt(y)) | 0))) : ( + ( - (( + ( + (( + y) ** ( + ((( ! x) >>> 0) , (y >> y)))))) >>> 0)))) >>> 0)); }); testMathyFunction(mathy1, [-0x100000000, 0x080000000, 1, 0.000000000000001, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, -0, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, -(2**53+2), -0x07fffffff, 1.7976931348623157e308, 0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, 0/0, -0x080000001, Number.MAX_VALUE, 2**53, -0x100000001, 0x100000000, 42, -(2**53), 1/0, Math.PI, -Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=113; tryItOut("mathy5 = (function(x, y) { return (( ~ ( + ( + mathy4(Math.fround((((x >>> 0) ? Math.log10((Math.fround(mathy3(Math.fround(x), Math.fround(-0x080000000))) >>> 0)) : (((Math.atan2((y | 0), y) | 0) || (( + y) ? ( + 0/0) : ( + Math.fround(( + Math.fround(-0)))))) >>> 0)) >>> 0)), Math.fround(Math.atanh(y)))))) | 0); }); testMathyFunction(mathy5, ['', [0], /0/, [], ({toString:function(){return '0';}}), (new Number(0)), '/0/', objectEmulatingUndefined(), undefined, null, 0, '\\0', ({valueOf:function(){return 0;}}), (new Boolean(false)), NaN, false, 1, true, (new String('')), 0.1, ({valueOf:function(){return '0';}}), (new Boolean(true)), -0, (new Number(-0)), (function(){return 0;}), '0']); ");
/*fuzzSeed-116170070*/count=114; tryItOut("\"use strict\"; this.o2.g1.t0[2];");
/*fuzzSeed-116170070*/count=115; tryItOut("\"use asm\"; o0.e2 = new Set(e1);");
/*fuzzSeed-116170070*/count=116; tryItOut("m2.delete(m0);");
/*fuzzSeed-116170070*/count=117; tryItOut("\"use strict\"; i1 + '';");
/*fuzzSeed-116170070*/count=118; tryItOut("\"use strict\"; for (var p in t2) { try { this.g0.s2 += 'x'; } catch(e0) { } try { Object.prototype.watch.call(g0, z, (function mcc_() { var qvckbu = 0; return function() { ++qvckbu; if (/*ICCD*/qvckbu % 4 == 2) { dumpln('hit!'); v2 = r0.flags; } else { dumpln('miss!'); try { selectforgc(o0); } catch(e0) { } try { t0 + i2; } catch(e1) { } try { Object.defineProperty(g0, \"b2\", { configurable: (x % 3 != 2), enumerable: true,  get: function() {  return t0.buffer; } }); } catch(e2) { } Array.prototype.forEach.apply(a2, [(function() { try { v2 + v0; } catch(e0) { } try { b1 = new SharedArrayBuffer(16); } catch(e1) { } o0.v2 = r1.flags; return p0; }), x, new RegExp(\"$\", \"gm\")]); } };})()); } catch(e1) { } for (var v of o0.f0) { try { i1 + ''; } catch(e0) { } try { m1.get(b0); } catch(e1) { } try { a0 = []; } catch(e2) { } i1.next(); } }\nv1 = Array.prototype.every.apply(a2, [(function(j) { if (j) { try { s2 += 'x'; } catch(e0) { } try { g2.toString = (function() { for (var j=0;j<12;++j) { f1(j%5==1); } }); } catch(e1) { } Object.defineProperty(this, \"o0.a0\", { configurable: true, enumerable: false,  get: function() {  return Array.prototype.concat.apply(a1, [a1, t0, g0.t2, v2, t2, f2]); } }); } else { try { m2.has(b2); } catch(e0) { } m0.has(o1.s0); } }), g0]);\n");
/*fuzzSeed-116170070*/count=119; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=120; tryItOut("o1.t2 = new Float64Array(t2);");
/*fuzzSeed-116170070*/count=121; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; gcPreserveCode(); } void 0; }");
/*fuzzSeed-116170070*/count=122; tryItOut("a2 + o0.m1;");
/*fuzzSeed-116170070*/count=123; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.max(( ! (Math.atan2((Number.MAX_SAFE_INTEGER | 0), (Math.imul(mathy0(y, x), Math.exp(y)) | 0)) >>> 0)), (Math.sqrt(Math.pow(y, Math.min(Math.fround(x), (x >= y)))) | 0)) ? Math.fround(Math.sign(Math.fround(Math.imul(Math.fround(y), Math.sqrt(Math.fround(( ! y))))))) : Math.atan(Math.imul((Math.tan((-0 | 0)) | 0), y))) !== ( ! (((x >>> y) | 0) || y))); }); testMathyFunction(mathy1, [0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, 0x080000000, 1, 42, -0x07fffffff, 0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, -1/0, Math.PI, -(2**53-2), 0x100000000, 2**53+2, -0, 2**53, -(2**53+2), -0x080000000, Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-116170070*/count=124; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((((( + (( + Math.fround(( ! Math.fround(Math.fround(Math.exp(Math.fround(Math.max(Math.acosh(y), Math.fround(x))))))))) ? y : (( - Math.pow(Math.fround(Math.pow(-1/0, -Number.MIN_VALUE)), y)) | 0))) * Math.log10(Math.atan2(( ! y), x))) >>> 0) | 0) || (( + (mathy0(( + Math.fround((Math.fround(Math.acos(( + y))) ^ Math.fround(( - (Math.fround(Math.atanh(Math.fround(y))) | 0)))))), ( + x)) | Math.pow(Math.trunc(Math.fround((x || Math.fround(Math.atan2(y, x))))), Math.fround(( - Math.fround(y)))))) | 0)) | 0); }); ");
/*fuzzSeed-116170070*/count=125; tryItOut("\"use strict\"; v1 = (o0 instanceof f2);");
/*fuzzSeed-116170070*/count=126; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; } /*vLoop*/for (ccidjf = 0, x; ccidjf < 105; ++ccidjf) { e = ccidjf; (this); } ");
/*fuzzSeed-116170070*/count=127; tryItOut("uvmwpt();/*hhh*/function uvmwpt(w, w, ...\u3056){v1 = evalcx(\"/* no regression tests found */\", g1);}");
/*fuzzSeed-116170070*/count=128; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-116170070*/count=129; tryItOut("with({}) this.zzz.zzz;");
/*fuzzSeed-116170070*/count=130; tryItOut("\"use strict\"; v0 = a1.length;");
/*fuzzSeed-116170070*/count=131; tryItOut("mathy4 = (function(x, y) { return (( + ( ~ Math.fround((( + ( ! (x | 0))) | ( - (( + y) >>> 0)))))) > ( ~ Math.expm1(( + Math.fround(Math.log10(( + mathy2((( + (-0x100000001 >>> 0)) | 0), x)))))))); }); testMathyFunction(mathy4, [42, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, -Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, 0, -(2**53), -0x080000000, 0x0ffffffff, 0/0, -0x080000001, 1, 2**53+2, -0x100000001, 0x100000001, -0x07fffffff, -(2**53-2), -(2**53+2), -0x100000000, -0, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, 2**53, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=132; tryItOut("new Uint16Array(undefined);\ns2 = a1.join(s2);\n");
/*fuzzSeed-116170070*/count=133; tryItOut("for (var p in t1) { try { s2 += 'x'; } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(f1, g0); } catch(e1) { } try { print(p0); } catch(e2) { } for (var p in v2) { f1(e2); } }");
/*fuzzSeed-116170070*/count=134; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      (Uint8ArrayView[0]) = ((/*FFI*/ff(((((+((+/*FFI*/ff(((~((0xffffffff)+(0x85579cf8)+(0xffffffff)))), ((+(1.0/0.0))), ((~((-0x46aab5e)))), ((-65.0)), ((1.5111572745182865e+23)), ((281474976710657.0)), ((-1.5)), ((-524289.0)), ((1.5474250491067253e+26)), ((8589934593.0))))))) % ((+(0.0/0.0))))), ((+(-1.0/0.0))), ((abs((abs((imul((/*FFI*/ff()|0), ((0xf2736123) <= (0x73ba4b27)))|0))|0))|0)), ((abs((((0x0) / (0xa39dbe5a)) >> ((/*FFI*/ff(((36893488147419103000.0)), ((7.555786372591432e+22)), ((3.0)), ((0.00390625)))|0))))|0)))|0)-((5.0) == (-129.0))-(i0));\n    }\n    i1 = (i0);\n    {\n      i1 = (i0);\n    }\n    i0 = (!(i0));\n    i0 = (i1);\n    return +((Float32ArrayView[0]));\n    i1 = (i0);\n    i1 = (i1);\n    return +((-36028797018963970.0));\n  }\n  return f; })(this, {ff: TypeError.prototype.toString}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MAX_VALUE, -0x100000001, -0x0ffffffff, 1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, -(2**53), -0x080000000, 2**53, 0/0, 2**53-2, Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, 0x07fffffff, 42, -(2**53+2), -0x100000000, -0x080000001, -(2**53-2), 2**53+2, 0, 0x080000000, 0x100000000]); ");
/*fuzzSeed-116170070*/count=135; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.fround((Math.imul((Math.abs(( ! (((0x100000000 >>> 0) ? (y >>> 0) : x) >>> 0))) >>> 0), ( + x)) / (Math.imul(((Math.round((Math.log(( + mathy3((y | 0), ( + x)))) >>> 0)) >>> 0) | 0), (x >>> 0)) | 0))) ^ (Math.max(( + 1.7976931348623157e308), ( + ( - ( ! ( + ( ~ Math.max(y, x))))))) | 0)) | 0); }); testMathyFunction(mathy4, [2**53-2, Math.PI, 1.7976931348623157e308, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0x100000001, 0x0ffffffff, 0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 42, -(2**53+2), -Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, 2**53+2, -0x100000000, 1, Number.MAX_VALUE, -0x080000001, 0x100000001, 0/0, 0, -0x080000000, 0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=136; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((((( ! Math.sin(Math.fround(y))) >>> 0) >>> 0) << (Math.fround(Math.round(((Math.hypot(Math.PI, Math.round(Math.fround(Number.MAX_VALUE))) >>> 0) === (0 >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x100000001, -0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0x080000001, 0, 42, -0, 0x100000000, 1, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 2**53, 0/0, -1/0, 2**53-2, 0x07fffffff, -Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -0x07fffffff, -0x100000001, -0x100000000, -0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=137; tryItOut("mathy5 = (function(x, y) { return (((Math.fround(( + ( + Math.expm1(let (z) a)))) >>> 0) || (( + (((x >= Math.fround(Math.hypot(( + x), ( + -0x07fffffff)))) | 0) >>> ( + Math.fround(Math.asin(Math.fround(Math.sinh((((Math.acos(y) | 0) && (x | 0)) | 0)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x07fffffff, -0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0, 2**53, -(2**53+2), -0x080000000, Math.PI, 0x0ffffffff, 2**53+2, 0x100000000, -Number.MAX_VALUE, -(2**53), Number.MIN_VALUE, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, 0x080000000, -0x100000001, -Number.MIN_VALUE, -0x080000001, 0x100000001, 2**53-2, -1/0, 1/0, -0x0ffffffff, -0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-116170070*/count=138; tryItOut("\"use strict\"; /*vLoop*/for (gwfwrr = 0; gwfwrr < 23; ++gwfwrr) { let w = gwfwrr; print(let (b)  '' ); } ");
/*fuzzSeed-116170070*/count=139; tryItOut("print(g0.t2);");
/*fuzzSeed-116170070*/count=140; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (-524289.0);\n    (Float32ArrayView[4096]) = ((x));\n    return (((0xff22cb56)))|0;\n  }\n  return f; })(this, {ff: mathy2}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [2**53-2, 1.7976931348623157e308, -(2**53+2), -0x080000000, 2**53+2, 1, 0.000000000000001, -(2**53), Number.MAX_VALUE, -0, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, 1/0, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 42, 0/0, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, 0x0ffffffff, 0x080000001, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 0, -(2**53-2), -1/0, Math.PI]); ");
/*fuzzSeed-116170070*/count=141; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround((((Math.cosh(Math.fround(x)) | 0) && (( + Math.hypot(( + (Math.imul(( + ( ~ ( + 0x07fffffff))), 1/0) | (Math.max(((( + y) * ( + Math.atan2(x, x))) >>> 0), x) >>> 0))), Math.fround(Math.hypot(y, Math.clz32(( + Math.hypot(-(2**53-2), x))))))) >>> 0)) >>> 0)) / Math.fround((Math.pow(((Math.log10(y) >>> 0) < ( + x)), (( ~ (((( + (Math.PI | 0)) | 0) % ((x == x) >>> 0)) >>> 0)) >>> 0)) | 0)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, 42, -0x0ffffffff, 2**53+2, -(2**53-2), -0x100000001, 0x100000001, -0x080000001, -(2**53+2), 2**53-2, 0/0, -(2**53), 0x080000000, -0x080000000, -0x07fffffff, Number.MAX_VALUE, -0x100000000, 1/0, 0, 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, 0x080000001, 0.000000000000001, 0x100000000, -1/0, -0, 0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=142; tryItOut("mathy0 = (function(x, y) { return Math.cosh(( + (Math.min((x | 0), Math.fround((x >= x))) | 0))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 0x100000001, -(2**53+2), -(2**53-2), 0, -0x080000001, 1, 42, 0x0ffffffff, 0x080000000, -0x07fffffff, Math.PI, 2**53-2, 1.7976931348623157e308, 0x100000000, Number.MIN_VALUE, -0x100000000, -1/0, 0x080000001, 0x07fffffff, Number.MAX_VALUE, 0.000000000000001, -0x080000000, -0, 2**53+2, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=143; tryItOut("\"use strict\"; g2.p0 = p1;");
/*fuzzSeed-116170070*/count=144; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-116170070*/count=145; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((/*FFI*/ff(((((d0)) - ((Float32ArrayView[(((0xffffffff) ? (0x2c931bac) : (0x245affc1))+(0xd0028a34)) >> 2])))), ((imul((0xfda84e17), (0x41be97d7))|0)), (((+abs(((+atan2(((1.5111572745182865e+23)), ((2305843009213694000.0))))))) + ((0x231f3720) ? (72057594037927940.0) : (-2147483648.0)))), ((((-0x8000000)-(0xffffffff)) | ((Int8ArrayView[((0x65155337)) >> 0])))), ((((0x4db398c6) % (0x0)) & ((0xffffffff) / (0xadec5390)))), ((d1)), ((((0xfaf7471a)) ^ ((0xa835b75a)))), ((17.0)), ((-17592186044417.0)))|0)-(0xff2c943e)-(!(((((((0x99d7ab36)+(-0x8000000))>>>((-0x8000000)-(0x5fd46cc9)))))>>>((0xf8b3d540)+(0x4991e428)))))))|0;\n  }\n  return f; })(this, {ff: ('fafafa'.replace(/a/g, objectEmulatingUndefined))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [1.7976931348623157e308, 0x080000001, 2**53+2, 2**53-2, -0x080000001, 0/0, Math.PI, 0x080000000, 0x100000000, -(2**53), -0x080000000, -1/0, -0x100000000, 2**53, 1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), 42, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -0x100000001, 1, 0.000000000000001, -(2**53+2), -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-116170070*/count=146; tryItOut("mathy2 = (function(x, y) { return (mathy0(Math.fround(( - ( + ( ~ Math.fround((((( + -0x07fffffff) | 0) >>> 0) & ((0x080000000 >>> x) >>> 0))))))), (( + (Math.pow((Math.asin((Math.pow((( ~ ( + y)) | 0), (x | 0)) | 0)) >>> 0), (Math.asin(( - (( + (-0x080000001 >>> 0)) | 0))) >>> 0)) | x)) | 0)) | 0); }); testMathyFunction(mathy2, [0x100000001, 0x07fffffff, -0x0ffffffff, 0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53, 0/0, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), -0x080000000, 1, 0x100000000, Number.MAX_VALUE, 0, -0x07fffffff, -1/0, 42, Math.PI, 0.000000000000001, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, 0x080000000, -0x080000001]); ");
/*fuzzSeed-116170070*/count=147; tryItOut("\"use strict\"; v2 = g2.eval(\"o1.a0 = [];\");\nfalse;\n");
/*fuzzSeed-116170070*/count=148; tryItOut(";t0.__proto__ = p1;");
/*fuzzSeed-116170070*/count=149; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"Object.defineProperty(this, \\\"f2\\\", { configurable: true, enumerable: true,  get: function() {  return Proxy.createFunction(g0.h1, f0, f0); } });\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: ({} = x), noScriptRval: (x % 39 != 21), sourceIsLazy: false, catchTermination: (x % 53 == 10) }));");
/*fuzzSeed-116170070*/count=150; tryItOut("t2 = new Uint8Array(b2, 96, 18);");
/*fuzzSeed-116170070*/count=151; tryItOut("mathy2 = (function(x, y) { return Math.fround(((( ! ((Math.min((( + Math.sinh(( + x))) >>> 0), ( + Math.min(( + (Math.pow(x, x) ** x)), ( + mathy1(0x100000000, Math.imul((x | 0), (((( + x) !== x) >>> 0) >>> 0))))))) >>> 0) | 0)) | 0) , Math.fround((Math.max(Math.fround(Math.imul(((mathy1(( + ((( + y) <= Number.MIN_VALUE) | 0)), ( + ( + ( - x)))) * (mathy0((x >>> 0), (0x0ffffffff >>> 0)) >>> 0)) | 0), (Math.atanh((( + x) | 0)) | 0))), Math.abs(y)) | 0)))); }); testMathyFunction(mathy2, [-0x07fffffff, -0, 0/0, -0x080000000, -0x080000001, 0x080000000, 42, 0x0ffffffff, -1/0, -Number.MAX_VALUE, -0x100000001, 0.000000000000001, 0x07fffffff, 1/0, 0x100000000, -(2**53-2), 2**53-2, -(2**53+2), 0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 1, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, Math.PI, 2**53]); ");
/*fuzzSeed-116170070*/count=152; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy0(Math.round((Math.hypot(((y >> x) | 0), ((Math.pow((x >>> 0), (y | 0)) >>> 0) | 0)) | 0)), mathy1((mathy2((( + Math.hypot(x, Math.max((((y >>> 0) ? (0/0 >>> 0) : (x >>> 0)) >>> 0), 0x100000000))) >>> 0), (Math.fround(Math.tanh(Math.fround(mathy2(1/0, Math.max(Math.fround(y), x))))) >>> 0)) >>> 0), Math.fround(mathy0(Math.fround((Math.fround((( + y) - ( + ( + (x >>> 0))))) | (((Math.fround(Math.sign(x)) >>> 0) <= (( ~ x) >>> 0)) | 0))), Math.fround(( ! ( + y))))))); }); testMathyFunction(mathy3, [1, [], '/0/', ({valueOf:function(){return 0;}}), '0', -0, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), /0/, ({toString:function(){return '0';}}), false, '\\0', 0.1, (function(){return 0;}), undefined, (new Number(0)), (new String('')), null, [0], (new Boolean(true)), NaN, '', (new Boolean(false)), true, (new Number(-0)), 0]); ");
/*fuzzSeed-116170070*/count=153; tryItOut("print(o1);");
/*fuzzSeed-116170070*/count=154; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x080000000, -0x100000001, 1/0, -(2**53), Math.PI, 1.7976931348623157e308, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, 2**53, 0x100000000, 0/0, -1/0, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, -0x080000001, 0x080000001, -0x07fffffff, 0x100000001, -(2**53+2), 0, -0, Number.MIN_VALUE, 42, 0x0ffffffff, -(2**53-2), 2**53+2]); ");
/*fuzzSeed-116170070*/count=155; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy1, [-0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, -1/0, -0, 0.000000000000001, 2**53, 0x07fffffff, -(2**53+2), -0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -(2**53), Number.MIN_VALUE, 2**53-2, 0x080000000, 1, 1/0, -Number.MAX_VALUE, 0, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 2**53+2, Math.PI, 42, -0x080000000, 0x100000001, -0x100000001]); ");
/*fuzzSeed-116170070*/count=156; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan2((mathy2(( + Math.fround((Math.fround(y) && Math.fround(x)))), (Math.fround(Math.hypot(( + Math.log1p(Math.cos((0/0 >>> 0)))), (((y | 0) ^ (y | 0)) >>> 0))) >>> 0)) >>> 0), (Math.clz32((( + 42) >> ( ~ (y || Math.fround(Math.cos(Math.fround(y))))))) && new (Date.prototype.toLocaleDateString)('fafafa'.replace(/a/g, new Function)))); }); ");
/*fuzzSeed-116170070*/count=157; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.log(( + (Math.hypot((Math.atan2((mathy0((Math.max(y, x) >>> 0), ( + 0x07fffffff)) >>> 0), y) >>> 0), (Math.fround(Math.acos((((( + y) << ( + y)) | 0) >>> 0))) >>> 0)) >>> 0))) ? ( ! mathy0(Math.atanh(y), Math.atan2((( + Math.min(Math.fround((Math.atan2(x, Math.fround(y)) | 0)), ( + -(2**53)))) & (( + x) | 0)), x))) : Math.fround((Math.fround(Math.log2(-(2**53-2))) & Math.fround(((mathy1(((((0/0 - (Math.hypot(y, (y >>> 0)) >>> 0)) >>> 0) <= (x >>> 0)) >>> 0), ( + x)) >> ((Math.log10((y | 0)) | 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [0x07fffffff, 42, -(2**53-2), 0.000000000000001, 0x100000001, -0x100000000, 0x0ffffffff, -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, -(2**53+2), 1, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, 0/0, 0, 0x080000001, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 2**53, -0x0ffffffff, -1/0, -0x07fffffff, -(2**53), 2**53+2, -0]); ");
/*fuzzSeed-116170070*/count=158; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((Math.min((((mathy0((mathy0(( + y), ( + x)) >>> 0), (( + x) | 0)) >>> 0) >>> y) >>> 0), ((( ~ (Math.hypot((( + (Math.abs(y) << y)) >>> 0), (((( + x) | Math.fround(( + Math.round(( + 2**53+2))))) >>> 0) >>> 0)) | 0)) | 0) >>> 0)) >>> 0) >>> 0) ? ((((Math.fround(Math.min((mathy1((Math.max(y, x) >= x), ( + Math.max(( + x), ( + (Math.sinh(x) | 0))))) >>> 0), (Math.sign(mathy1(x, (Math.min((1/0 | 0), (( - y) | 0)) | 0))) | 0))) | 0) | Math.fround((((y | 0) / (x | 0)) | 0))) | 0) >>> 0) : (Math.max(Math.acos((( + ( + (Math.pow(y, (mathy0(x, 1/0) >>> 0)) >>> 0))) & ( + mathy1((((x | 0) ? (( ! y) | 0) : x) | 0), Math.min(y, x))))), (( ! y) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[[1], [1], [1], -0x07fffffff, [1], -0x07fffffff, [1]]); ");
/*fuzzSeed-116170070*/count=159; tryItOut("o1.m1.set(this.p0, x);");
/*fuzzSeed-116170070*/count=160; tryItOut("mathy2 = (function(x, y) { return ( + ( + Math.atan2((mathy0((( + (( + 0x100000001) > ( + -0))) >>> 0), y) >>> 0), Math.fround(x)))); }); testMathyFunction(mathy2, [-1/0, 2**53, 0x100000001, 0x080000000, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), 0, -0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 2**53-2, -0x080000000, 42, -(2**53+2), 0x0ffffffff, 0x100000000, Math.PI, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -0x100000000, 0/0, 0x080000001, -(2**53)]); ");
/*fuzzSeed-116170070*/count=161; tryItOut("/*infloop*/for(let y = x; (void options('strict')); let (y) /*FARR*/[...z, , (makeFinalizeObserver('tenured')), \n23, (eval(\"throw y;\", false)), ...(function() { yield (4277); } })()].filter) v2 = Array.prototype.some.apply(o2.g2.a0, [(function() { for (var j=0;j<34;++j) { f0(j%2==1); } }), m1]);");
/*fuzzSeed-116170070*/count=162; tryItOut("b, x, window = x, oweagc, mvtlip, x = x, tzaqyr;a0.__iterator__ = (function() { try { v0 = o1.a1.length; } catch(e0) { } try { function f0(g0.g1.g0.v1) x } catch(e1) { } try { g0.offThreadCompileScript(\"\\\"\\\\u72E4\\\"\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 != 3), sourceIsLazy: false, catchTermination: false })); } catch(e2) { } f2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (d1);\n    return +((+abs(((d1)))));\n  }\n  return f; })(this, {ff: function shapeyConstructor(dawqbh){\"use strict\"; this[\"parse\"] = {};if (dawqbh) delete this[\"call\"];if (dawqbh) this[\"y\"] = objectEmulatingUndefined();delete this[\"parse\"];this[\"call\"] = [(void 0)];delete this[\"call\"];{ print(/(?:\\B)|(?=(?!(?:\\S+)){2,5})/gi); } this[\"y\"] = \"\\uA814\";this[\"parse\"] = [];this[\"y\"] =  /x/ ;return this; }}, new SharedArrayBuffer(4096)); return t2; });");
/*fuzzSeed-116170070*/count=163; tryItOut("");
/*fuzzSeed-116170070*/count=164; tryItOut("/*bLoop*/for (acktld = 0, 7, \"\u03a0\"; acktld < 0; ++acktld) { if (acktld % 5 == 1) { throw {}; } else { print(\"\\uAC87\"); }  } ");
/*fuzzSeed-116170070*/count=165; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[new Number(1), -Infinity, new Number(1), -Infinity, -Infinity, new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), new Number(1), -Infinity, new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1), -Infinity, -Infinity, -Infinity, new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), new Number(1), -Infinity, -Infinity, -Infinity, new Number(1), -Infinity, -Infinity, new Number(1), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), new Number(1), -Infinity, -Infinity, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), -Infinity, -Infinity, new Number(1), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1), -Infinity, -Infinity, new Number(1), new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, -Infinity, new Number(1), new Number(1), new Number(1), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1), new Number(1), -Infinity, -Infinity, -Infinity, -Infinity, new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), new Number(1), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1), new Number(1), -Infinity, -Infinity, -Infinity, new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), new Number(1), new Number(1), -Infinity, -Infinity, -Infinity, new Number(1)]) { var arssdg = new SharedArrayBuffer(2); var arssdg_0 = new Uint8Array(arssdg); print(arssdg_0[0]); var arssdg_1 = new Uint8ClampedArray(arssdg); arssdg_1[0] = 0; var arssdg_2 = new Float64Array(arssdg); arssdg_2[0] = 0x07fffffff; var arssdg_3 = new Float32Array(arssdg); print(arssdg_3[0]); arssdg_3[0] = -1; var arssdg_4 = new Uint8ClampedArray(arssdg); h2 = x;a2.reverse();print(arssdg_0);false;print(arssdg_2[8]); }");
/*fuzzSeed-116170070*/count=166; tryItOut("mathy3 = (function(x, y) { return (Math.imul((( ! ((mathy0(((((y | 0) ** ((( ~ x) >>> 0) | 0)) | 0) >>> 0), (y >>> 0)) >>> 0) | 0)) | 0), (Math.pow(((Math.tan((x >>> 0)) >>> 0) >>> 0), (Math.acosh(( + Math.atan2(( + ( ~ Math.fround(-0x100000000))), ( + (y < Math.sign(x)))))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, [0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -1/0, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, 42, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, -(2**53+2), -0x100000000, 0, 0x07fffffff, 2**53-2, 1.7976931348623157e308, 1/0, -Number.MIN_VALUE, 0x100000001, Math.PI, -(2**53), 0x080000000, 0x080000001, -0x080000001, 0x100000000, 2**53+2, 2**53, -0x100000001, Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0]); ");
/*fuzzSeed-116170070*/count=167; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.clz32(Math.fround(Math.atan2(Math.fround(Math.pow(Math.imul(-0x07fffffff, x), x)), Math.fround(-0x07fffffff)))) & (Math.hypot(Math.log10(Math.fround(Math.cosh(Math.fround(mathy1(Math.fround(y), Math.fround(x)))))), Math.cbrt(Math.pow(Math.hypot(y, (( ! (( + (( + y) != ( + y))) | 0)) | 0)), (mathy0((Math.tanh(-0x100000001) | 0), (Math.fround(Math.imul(Math.fround(y), (0 >>> 0))) | 0)) | 0)))) | 0)); }); testMathyFunction(mathy2, [null, /0/, (new String('')), '', (new Boolean(true)), true, 1, ({valueOf:function(){return 0;}}), (new Number(-0)), objectEmulatingUndefined(), '/0/', [], (function(){return 0;}), '0', ({valueOf:function(){return '0';}}), undefined, 0.1, 0, (new Number(0)), NaN, false, '\\0', [0], (new Boolean(false)), -0, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-116170070*/count=168; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(( + (Math.cosh(( ~ 2**53)) >>> 0)), Math.fround(Math.fround(Math.hypot(( + ( + x)), ( + Math.pow(( + (( + x) * ( + Math.imul((-0x07fffffff >> Math.fround(( - x))), x)))), Math.fround(y))))))) >>> 0); }); testMathyFunction(mathy2, [1, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, 2**53-2, -(2**53), -0x07fffffff, Math.PI, Number.MAX_VALUE, 0x100000001, 0x080000001, 0/0, 0x100000000, Number.MIN_VALUE, 0x080000000, 42, -Number.MIN_VALUE, 0.000000000000001, -0x100000000, -1/0, -0, -0x080000001, 2**53, -(2**53-2), -0x0ffffffff, 0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, 2**53+2]); ");
/*fuzzSeed-116170070*/count=169; tryItOut("\"use strict\"; /*infloop*/for((4277); (x = eval).__defineGetter__(\"y\", x); x) {/*RXUB*/var r = r0; var s = \"\"; print(s.match(r)); print(x); }");
/*fuzzSeed-116170070*/count=170; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"[z1,,]\");");
/*fuzzSeed-116170070*/count=171; tryItOut("mathy0 = (function(x, y) { return (Math.hypot(( ! ( + Math.expm1(Math.asinh(y)))), ( + (( + ((( + x) - (( ~ Math.fround((((Math.pow((y | 0), (( - (1 | 0)) | 0)) | 0) - y) >>> 0))) >>> 0)) | 0)) >>> 0))) >>> 0); }); ");
/*fuzzSeed-116170070*/count=172; tryItOut("for (var v of m1) { try { g1.__iterator__ = (function mcc_() { var aywxrk = 0; return function() { ++aywxrk; f2(true);};})(); } catch(e0) { } try { v2 = t2.length; } catch(e1) { } g2.e1.has(b0); }");
/*fuzzSeed-116170070*/count=173; tryItOut("\"use strict\"; v0 = g0.eval(\"function f2(this.b2)  { \\\"use strict\\\"; return (4277) } \");");
/*fuzzSeed-116170070*/count=174; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=175; tryItOut("\"use strict\"; for (var p in g0.s2) { try { a1.reverse(e1); } catch(e0) { } try { g1.e1.toString = (function(j) { if (j) { try { v1 = Object.prototype.isPrototypeOf.call(b0, i0); } catch(e0) { } try { print(uneval(o0)); } catch(e1) { } try { m1.set(x, m1); } catch(e2) { } b1.toSource = (function() { try { a0 = a0.filter(v1); } catch(e0) { } try { v0 = true; } catch(e1) { } try { p0 + t2; } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(g1, o2); return m2; }); } else { try { v1 = Object.prototype.isPrototypeOf.call(a0, s0); } catch(e0) { } /*RXUB*/var r = o2.r2; var s = s2; print(uneval(r.exec(s)));  } }); } catch(e1) { } try { m1.delete(g1); } catch(e2) { } v1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (0xfef0e5cf);\n    i0 = (i1);\n    return +((-281474976710657.0));\n  }\n  return f; }); }");
/*fuzzSeed-116170070*/count=176; tryItOut("((/*MARR*/[1e4, new Boolean(true), new Boolean(true), 1e4, 1e4, 1e4, 1e4, 0x100000001, 1e4, 1e4, 0x100000001, new Boolean(true), 1e4, 0x100000001, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), 1e4, 1e4, 1e4, 0x100000001, 1e4, 0x100000001, 0x100000001, 1e4, new Boolean(true), 0x100000001, 0x100000001, new Boolean(true)].filter));");
/*fuzzSeed-116170070*/count=177; tryItOut("s2 += 'x';\nyield;\n");
/*fuzzSeed-116170070*/count=178; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround((( + Math.fround(( ! Math.fround(( + mathy1(y, Math.min(0, Math.pow(0x080000000, ((0x100000000 | 0) % x))))))))) >>> 0)) ? ((((Math.expm1(Math.clz32(y)) >>> 0) >>> ((mathy0((( - Math.atan2((x ? (Math.asinh((1.7976931348623157e308 | 0)) >>> 0) : x), Math.fround(x))) | 0), Math.PI) | 0) >>> 0)) >>> 0) >>> 0) : (( + (Math.tan((2**53+2 == Math.round(Math.max(y, x)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-0x100000000, -0x080000000, 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 0x080000001, 1/0, 1.7976931348623157e308, Number.MIN_VALUE, -1/0, -0x080000001, -(2**53-2), 2**53+2, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -0x100000001, 0x100000000, 2**53, 0x080000000, 0/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -0, 2**53-2, 42, -0x0ffffffff, -(2**53), -0x07fffffff, Math.PI]); ");
/*fuzzSeed-116170070*/count=179; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.trunc(Math.pow(Math.fround((Math.fround(Math.fround(( ! Math.fround(y)))) > Math.atan2((Math.atan2((( + -0x0ffffffff) >>> 0), (1.7976931348623157e308 >>> 0)) >>> 0), (mathy0((((0x080000001 >> y) !== (( ! ( + -0x100000001)) | 0)) >>> 0), ((y , 2**53) >>> 0)) >>> 0)))), (Math.trunc(Math.cbrt(( ~ Math.atan2(0.000000000000001, ((x != -0x100000001) | 0))))) | 0))); }); testMathyFunction(mathy1, [1, -Number.MAX_VALUE, -(2**53-2), -0x100000000, -0x080000001, Math.PI, -Number.MIN_VALUE, -1/0, 0/0, -(2**53+2), Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -0, -0x0ffffffff, -0x080000000, 1/0, 2**53, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, 2**53+2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 0, 42, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=180; tryItOut("/*RXUB*/var r = /(?:((?=$|.{0,2})){3,})+.{0,}\\3{32769,}*\\B|((?=(?:(?:.)))?)$/; var s = \"  \"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=181; tryItOut("\"use strict\"; f1(a0);");
/*fuzzSeed-116170070*/count=182; tryItOut("/*MXX3*/g1.Error.name = this.g0.Error.name;");
/*fuzzSeed-116170070*/count=183; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var acos = stdlib.Math.acos;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((((!(0x6939ce6d))-(((i1)-(0xffffffff))))>>>((0x7d47f8c1)+(-0x8000000)-(i1))));\n    i1 = ((((0xfff0698a))>>>((Int32ArrayView[0]))) <= (0x33e1065f));\n    switch ((((0x63614345)) & ((0xff25ce74)))) {\n      case 1:\n        i1 = (0x16aae854);\n        break;\n      case 0:\n        d0 = (-7.737125245533627e+25);\n        break;\n      case -1:\n        i1 = ((0xfa649156) ? ((0xb921b709)) : (0x84bffa73));\n        break;\n      case 1:\nprint(x);        break;\n      case -1:\n        {\n          {\n            i1 = (i1);\n          }\n        }\n        break;\n      case -3:\n        d0 = (3.8685626227668134e+25);\n      case -2:\n        switch ((abs((((0xb635bad0) / (0x7ba050bf)) >> ((0xb9059e68)+(0x4026f861))))|0)) {\n          case -1:\n            i1 = (i1);\n            break;\n          case -2:\n            {\n              (Float32ArrayView[((Uint16ArrayView[(((-0x2f417*((0xfd2a2c90) == (0x858be100))))-((134217727.0) < (3.8685626227668134e+25))+(0xa9a186ee)) >> 1])) >> 2]) = ((+acos((((Float64ArrayView[((true)) >> 3]))))));\n            }\n            break;\n          case 1:\n            {\n              i1 = (i1);\n            }\n            break;\n          case -2:\n            i1 = (i1);\n          case -2:\n            d0 = (-((+(1.0/0.0))));\n            break;\n          case -2:\n            {\n              i1 = (Math.max(-20, (let (z) 21)));\n            }\n            break;\n          case -1:\n            i1 = (-0x8000000);\n            break;\n          case -1:\n            i1 = ((((Uint16ArrayView[((0x5a07d5df)) >> 1]))>>>((i1)-(i1)-((!(0xbc0adf81)) ? ((0xffffffff) ? (0xbe92578e) : (-0x8000000)) : (0x838f544e)))) <= ((Float64ArrayView[((((((0x882e18bb)) << ((0xdf8ac0de)))) ? (0xffffffff) : (i1))-(0xcb294e32)) >> 3])));\n            break;\n          default:\n;        }\n        break;\n      case 1:\n        {\n          d0 = (+abs(((+abs(((d0)))))));\n        }\n      case -3:\n        d0 = (+(0.0/0.0));\n        break;\n      default:\n        d0 = (1.5474250491067253e+26);\n    }\n    (Uint16ArrayView[((-0x8000000)-(0xfc2c0767)) >> 1]) = ((/*FFI*/ff(((Infinity)), ((~~(+(0x2524fd10)))), ((-1.00390625)), ((-1025.0)), ((((0x60ab4f22) / (-0x7e617a4)) ^ ((0xf8e8f869)-(0xe4676b77)+(0xffffffff)))), ((~~(d0))), ((((0xffffffff)) >> ((0xb5a3e3ec)))), (((Float64ArrayView[1]))), ((-70368744177665.0)), ((-2.0)), ((-268435455.0)), ((-2.0)))|0)*-0x8519b);\n    {\n      (Float64ArrayView[((Float32ArrayView[((!((0x7d361a8d) ? (0x50a85dcf) : (0xff3b8bb7)))) >> 2])) >> 3]) = (((d0) + ((d0) + (d0))));\n    }\n    i1 = (i1);\n    return ((((((0x69160d1c)-((0xbc620828) ? (i1) : (0xf90a403a))) << ((undefined)-(0xdf427344)+(0xfce9d55b))) <= (~~(-9.44473296573929e+21)))))|0;\n    return ((((0x6db6d0c9))+(0x8a84f54)))|0;\n    return (((((makeFinalizeObserver('nursery'))) == (0x4d33756f))+(i1)+(i1)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53+2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -0, Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, 42, 0x080000001, 1, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, -(2**53), 2**53-2, 1/0, -0x07fffffff, -Number.MAX_VALUE, Math.PI, 0x100000001, 2**53+2, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -Number.MIN_VALUE, 2**53, 0x07fffffff, 0/0, -1/0, 0.000000000000001]); ");
/*fuzzSeed-116170070*/count=184; tryItOut("\"use strict\"; this.p1 + s1;");
/*fuzzSeed-116170070*/count=185; tryItOut("g0.a2 = /*FARR*/[\"\\uCB3D\", ...arguments.callee.caller.caller, ...[(4277)], x, .../*PTHR*/(function() { for (var i of /*FARR*/[(x **= x), (void options('strict_mode')), arguments ==  /x/g , ((eval(\"/* no regression tests found */\"))()), x.unwatch(\u000cnew String(\"11\")), x, x, x, , {}, this.__defineSetter__(\"x\", function (d) { return this.yoyo(1) } ), length, x, ,  '' , (4277), ...(x for (c of /*FARR*/[...[], -12]) for each (\u3056 in [z1,,])), w, (let (x, ubugri) true >>> Date.prototype.setUTCMinutes), -Number.MAX_SAFE_INTEGER, , .../*FARR*/[((-9)([[1]], window)), this.__defineGetter__(\"eval\", (function(x, y) { return (0/0 , x); })), x , e]]) { yield i; } })()];function b(x, [{x, e}, NaN, w(new window)], x, x = ((function factorial_tail(wuomil, mvchnb) { ; if (wuomil == 0) { ; return mvchnb; } ; return factorial_tail(wuomil - 1, mvchnb * wuomil); print(x);\nprint(x);\n })(0, 1)), x, a, window, z, x, w = this, x, \u3056, c, e = [,,], e, w, x, x, x, x, eval = \"\\u67B5\", y, x, z, a, c = this, x, x, window, d, x = true, c, x, NaN =  /x/ , eval, NaN, x, x, length, y, x = this, x, NaN, \u3056, y = -6, x = arguments, window) { \"use strict\"; yield  /x/g  } i1.send(this.o1);");
/*fuzzSeed-116170070*/count=186; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=187; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.cosh(Math.acosh(( + Math.max(Math.atan2(x, (y | 0)), x)))) === (( ! (Math.max(Math.abs(Math.fround((Math.fround((( ! (x | 0)) | 0)) !== Math.fround(( + (( + y) !== x)))))), (Math.hypot(Math.fround(Math.trunc((Math.cos(x) >>> 0))), Math.fround((x != (( + y) | 0)))) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [-0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -1/0, 0.000000000000001, 0x080000000, 1, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, -0x080000001, 0x0ffffffff, -(2**53+2), -0x07fffffff, 42, Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, 0x100000000, 0x07fffffff, 0, Number.MIN_VALUE, 0/0, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, 0x080000001, 0x100000001, -0x100000001, 2**53, -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=188; tryItOut("f0.__iterator__ = f0;");
/*fuzzSeed-116170070*/count=189; tryItOut("{ void 0; try { startgc(389671); } catch(e) { } }");
/*fuzzSeed-116170070*/count=190; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, 2**53+2, Math.PI, Number.MIN_VALUE, -0x100000001, 0x100000000, -(2**53+2), 1/0, -0, -Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, 2**53, -0x100000000, 0/0, 0x07fffffff, 42, -0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, -1/0, -(2**53-2), -(2**53), 1]); ");
/*fuzzSeed-116170070*/count=191; tryItOut("testMathyFunction(mathy5, [-(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0/0, 0x080000000, -(2**53-2), Number.MIN_VALUE, 2**53, -0x080000001, 2**53-2, -0, 0.000000000000001, -0x0ffffffff, 2**53+2, 0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 1/0, 0x100000001, -0x100000001, 1, -1/0, -(2**53), -0x07fffffff, -Number.MIN_VALUE, 0x080000001, 42, -0x100000000, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=192; tryItOut("testMathyFunction(mathy5, [-(2**53), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE, 2**53, -(2**53-2), 0x080000000, 0x0ffffffff, 0x080000001, -0, 0, 1, -(2**53+2), -0x100000000, 0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, 42, 1.7976931348623157e308, 2**53+2, -Number.MAX_SAFE_INTEGER, Math.PI, 0x07fffffff, 1/0, -0x07fffffff, -Number.MIN_VALUE, -0x080000000, -0x100000001]); ");
/*fuzzSeed-116170070*/count=193; tryItOut("\"use strict\"; (this.__defineSetter__(\"\\u3056\", ({/*TOODEEP*/})));function x(NaN, d = ((makeFinalizeObserver('nursery'))))\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((1)+(1)-(i2)))|0;\n  }\n  return f;a0 = new Array(-8);");
/*fuzzSeed-116170070*/count=194; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.cbrt(( ! (Math.hypot(((Math.hypot(((y - (x | 0)) >>> 0), (0x100000000 >>> 0)) >>> 0) | 0), (Math.atan2((y >>> 0), (x >>> 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-116170070*/count=195; tryItOut("\"use strict\"; var zbocqu = new SharedArrayBuffer(6); var zbocqu_0 = new Uint32Array(zbocqu); print(zbocqu_0[0]); zbocqu_0[0] = 0; var zbocqu_1 = new Float32Array(zbocqu); print(zbocqu_1[0]); zbocqu_1[0] = -13; var zbocqu_2 = new Uint16Array(zbocqu); zbocqu_2[0] = 9223372036854776000; Array.prototype.sort.apply(g2.a2, [(function() { try { Array.prototype.forEach.apply(a1, [(function() { try { g0 = x; } catch(e0) { } v2 = (m0 instanceof b2); throw b0; }), g0, b1]); } catch(e0) { } try { s2 += s0; } catch(e1) { } g1 = t2[14]; return o1.e1; }), m0, g0.f1]);v0 = t2.length;print(zbocqu_1);");
/*fuzzSeed-116170070*/count=196; tryItOut("if( \"\" ) true; else {s0 += 'x'; }");
/*fuzzSeed-116170070*/count=197; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 0.5;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = -2.3611832414348226e+21;\n    var d6 = 1.001953125;\n    /*FFI*/ff(((~~(d6))), ((~((0x8d2f603a)))), ((-4294967297.0)), ((((-16385.0)) % ((d2)))), ((((0xe714dc7f)-(0x7b4e7407)) >> ((-0x8000000)-(0xd76365ba)))), ((+/*FFI*/ff())));\n    d6 = (-((1.5474250491067253e+26)));\n    /*FFI*/ff();\nNaN    switch (((((0x2010f412) == (0x5903454f))+(0xadf0127c)) | ((0x408ee1f3) % (0x765f9d89)))) {\n      case -3:\n        i4 = ((~(((((Uint32ArrayView[1]))>>>(((0xb9eb5e9c) ? (0xffffffff) : (0x52f194a9))-((0x7fffffff) >= (0x618d0732))-(-0x8000000))) < (((i4)+((((((-0x8000000))>>>((0xfc8f8fef))) > (((0xf8af3035))>>>((0x846640e7)))))))>>>(((abs((((0xb711e3d2)) << ((0xf85b7782))))|0))))))));\n      case -3:\n        i0 = (((((Float32ArrayView[2])))|0) >= (0x79605e4c));\n      case -2:\n        d2 = (3.0);\n        break;\n    }\n    {\n      d6 = (d6);\n    }\n    {\n      d5 = (d1);\n    }\n    return (((/*FFI*/ff(((((((0xffffffff)+(0x6635abd9))>>>((0xfac0faf9)+(0x3be7d604)-(0xfaa1ed12))) % (0xc47e2ae1)) & ((0x82ce47b6) % (0x9dba49e1)))), ((~~(-140737488355328.0))), ((18446744073709552000.0)), ((NaN)), ((~~(((-2.4178516392292583e+24)) / ((4611686018427388000.0))))), ((~((0x912bcec)+(0x37ceb53d)+(0xabea111)))))|0)-(0xfcfcb092)+(i0)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return Math.fround(( ! ( + Math.pow(( + ( ! (y / y))), ( + (Math.sinh((y | 0)) | 0)))))); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53+2), 0x07fffffff, -0x0ffffffff, 0x0ffffffff, -(2**53), -0x100000000, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000001, 2**53-2, Number.MIN_VALUE, -0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, 0, -0x080000000, 42, -0, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 0/0, -1/0, 0x100000001, 0x100000000, 2**53, 0x080000001, 2**53+2, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=198; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(Math.clz32(x)), Math.fround(Math.imul((( + (x >>> 0)) >>> 0), (Math.asinh((Math.log1p(( - y)) >>> 0)) | 0)))); }); testMathyFunction(mathy5, [0x0ffffffff, -(2**53+2), 0/0, 0x100000000, 0.000000000000001, 1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, 1.7976931348623157e308, Math.PI, 2**53, -0, -Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, -0x100000001, 0, -1/0, 2**53-2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, -(2**53), -0x100000000, 0x100000001, 1]); ");
/*fuzzSeed-116170070*/count=199; tryItOut("e1.has(t1);");
/*fuzzSeed-116170070*/count=200; tryItOut("mathy2 = (function(x, y) { return (Math.sinh(((Math.atan2((mathy1((-(2**53) | 0), (Math.log10(Math.log(y)) | 0)) | 0), Math.fround((Math.fround(Math.log((( ! x) | 0))) ** Math.fround(2**53-2)))) ? ( + (( + ( + ( ~ (x >>> 0)))) ? ( + (( + (y >>> 0)) >>> 0)) : ( + y))) : (((Math.fround(( - -0)) | 0) === ((Math.cosh(Math.atan2(y, x)) ? ( + (y / -(2**53))) : Math.fround((( + y) , ( + (((x | 0) === (0/0 | 0)) | 0))))) | 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy2, ['', '/0/', true, ({valueOf:function(){return 0;}}), (new Boolean(true)), [], '\\0', (function(){return 0;}), (new Number(-0)), ({toString:function(){return '0';}}), undefined, 0, null, ({valueOf:function(){return '0';}}), (new String('')), (new Boolean(false)), 0.1, '0', [0], NaN, /0/, (new Number(0)), 1, false, -0, objectEmulatingUndefined()]); ");
/*fuzzSeed-116170070*/count=201; tryItOut("o1.v1 = (h1 instanceof v1);");
/*fuzzSeed-116170070*/count=202; tryItOut("nhzcpn(x);/*hhh*/function nhzcpn(this.e){s2 += s1;}function w() { \"use strict\"; \"use asm\"; return this.__defineSetter__(\"NaN\", offThreadCompileScript) } m0.set(s1, h2);");
/*fuzzSeed-116170070*/count=203; tryItOut("/*infloop*/L:for(let Map.prototype in (((encodeURI).bind)(x))){( /x/ ); }");
/*fuzzSeed-116170070*/count=204; tryItOut("\"use strict\"; d, gsjloe, w, x = window(), x = (4277), x, z, a, eval, ujicfb;print(x);");
/*fuzzSeed-116170070*/count=205; tryItOut("\"use strict\"; \"use asm\"; e2.delete(t2);");
/*fuzzSeed-116170070*/count=206; tryItOut("testMathyFunction(mathy5, [-0x080000000, 2**53, 1/0, Number.MIN_VALUE, 1, 2**53-2, -0, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0x07fffffff, 0x100000001, 0x100000000, 2**53+2, 0, -Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, -(2**53-2), Math.PI, 42, 0.000000000000001, -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, 0x080000000]); ");
/*fuzzSeed-116170070*/count=207; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; validategc(false); } void 0; } print(uneval(h1));");
/*fuzzSeed-116170070*/count=208; tryItOut("\"use strict\"; print( /x/g );");
/*fuzzSeed-116170070*/count=209; tryItOut("b0 + e2;");
/*fuzzSeed-116170070*/count=210; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return (Math.atan(Math.fround((Math.fround((( + (x >>> 0)) >>> 0)) === Math.fround((Math.min((x | 0), (Math.log1p(( + ( + ( + x)))) | 0)) | 0))))) ^ (Math.min(( + y), ( + Math.sinh(( + Math.atan2(y, Math.atan2(y, y)))))) ^ Math.fround(Math.max(( + (-Number.MIN_VALUE != ( + ( + ( ~ Math.fround(Math.imul((x >>> 0), y))))))), Math.fround(Math.trunc((Math.pow(( ~ y), ((x | 0) == Math.fround(0x080000000))) | 0))))))); }); testMathyFunction(mathy0, [2**53-2, -1/0, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, 2**53, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, -0x100000001, -0, 0/0, 42, Number.MIN_VALUE, 0x0ffffffff, Math.PI, 0, -(2**53-2), 1.7976931348623157e308, -0x080000001, 1, -0x07fffffff, 0x07fffffff, -0x080000000, 1/0, 0.000000000000001, -(2**53+2), 2**53+2, -Number.MAX_VALUE, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=211; tryItOut("mathy4 = (function(x, y) { return ( ~ (( ! ( - (((y >>> 0) ? y : ( + x)) >>> 0))) >= Math.max(( + (Math.tanh(((x ** Math.fround(( ! ( + x)))) >>> 0)) >>> 0)), 0x100000000))); }); ");
/*fuzzSeed-116170070*/count=212; tryItOut("/*ODP-1*/Object.defineProperty(e1, \"wrappedJSObject\", ({set: eval, enumerable: (4277)}));");
/*fuzzSeed-116170070*/count=213; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.asin(( + mathy1(Math.hypot(y, ( + (Math.fround(( + (( + -Number.MIN_VALUE) * Math.fround(y)))) , x))), ( + Math.cbrt(( + Math.fround(Math.log10(Math.fround(Math.trunc((x >>> 0))))))))))) >>> 0); }); testMathyFunction(mathy2, [0x0ffffffff, 1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, 0.000000000000001, -Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, 0x100000000, 0x080000000, -0, -0x080000001, -0x07fffffff, -(2**53-2), -0x100000001, 42, -0x100000000, -1/0, 0, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, 1, -0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=214; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + ( ! Math.fround(Math.asin(Math.fround(Math.imul((((Math.fround((Math.fround(y) % (x | 0))) >>> 0) ? (( - y) >>> 0) : Math.atan2(x, -0x080000000)) | 0), (((Math.asinh((1.7976931348623157e308 == y)) > (x >>> 0)) >>> 0) | 0))))))) >>> 0); }); testMathyFunction(mathy0, [0, 0x100000001, -(2**53), 2**53, 0x080000000, 0x080000001, 1.7976931348623157e308, -1/0, -(2**53+2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, 1, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, Math.PI, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, -0, 0x100000000, 0.000000000000001, -0x080000001, -(2**53-2), 2**53-2, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 1/0, 0/0, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=215; tryItOut("this.v1 = g1.eval(\"function f2(m2) \\\"use asm\\\";   var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var d2 = 4503599627370497.0;\\n    (Float32ArrayView[1]) = ((new arguments.callee()));\\n    return (((i0)-(0xd3fe019d)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-116170070*/count=216; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.asin(Math.fround((( ~ (Math.log1p((Math.atanh((Math.hypot(y, 0x07fffffff) | 0)) | 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-116170070*/count=217; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.imul(( ! Math.fround((((( ! ((( + x) && ( + 2**53-2)) | 0)) | 0) >>> 0) == (Math.imul((Math.acos(( + mathy2(-0x080000000, y))) >>> 0), Math.fround(Math.max(( ~ 0x07fffffff), x))) >>> 0)))), ( + Math.pow(-0x080000000, (Math.log2((mathy0(y, ( + ( - y))) ? -Number.MAX_SAFE_INTEGER : Math.pow(y, x))) >>> 0)))); }); testMathyFunction(mathy3, [-(2**53-2), 0x07fffffff, 2**53, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -0, 0, -0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, 2**53-2, 0x080000000, -0x100000000, 0/0, 42, -0x080000000, 0x100000000, 1, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53+2), -Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=218; tryItOut("let(y, y = new (this)(), d = x, e, eval, tqkimh) ((function(){x.fileName;})());");
/*fuzzSeed-116170070*/count=219; tryItOut("\"use strict\"; this.v2 = r0.source;");
/*fuzzSeed-116170070*/count=220; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((( ~ Math.expm1(((( + (Math.log(( + x)) >>> 0)) - ( + (( + (Math.sin((Math.atan2(0x0ffffffff, x) | 0)) | 0)) ? ( + (Math.atan2((x | 0), (y | 0)) | 0)) : ( + x)))) | 0))) / Math.fround((Math.atanh((Math.fround(( + ( + x))) | 0)) | 0))) >>> 0); }); ");
/*fuzzSeed-116170070*/count=221; tryItOut("mathy3 = (function(x, y) { return ( + (((Math.ceil((Math.fround(Math.log10(Math.fround(mathy0(Math.fround((mathy1(( + y), ( + x)) % Math.fround(Math.PI))), Math.trunc(0x080000000))))) | 0)) | 0) | 0) | Math.fround(( + ( ! Math.imul(Math.fround(((Math.clz32(y) | 0) ^ Math.fround((Math.expm1(0x080000000) >>> 0)))), ((Math.expm1(y) >>> 0) ? (( + Math.pow(( + x), ( + ( + y)))) >>> 0) : Math.fround(Math.atan2((y ? y : ( - 0x0ffffffff)), (x ** 1.7976931348623157e308)))))))))); }); testMathyFunction(mathy3, [2**53, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, 1/0, 0x080000000, 1.7976931348623157e308, 0x0ffffffff, -0x100000001, -0, -0x080000000, -0x080000001, -(2**53-2), 42, 0x100000001, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, 2**53-2, 1, -0x0ffffffff, 0x100000000, Math.PI, Number.MAX_VALUE, 0/0, Number.MIN_VALUE, 0, -Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-116170070*/count=222; tryItOut("\"use asm\"; for (var p in p0) { Object.defineProperty(this, \"o1\", { configurable: ((yield x)), enumerable: true,  get: function() {  return Object.create(f1); } }); }");
/*fuzzSeed-116170070*/count=223; tryItOut("Array.prototype.sort.call(a2, (function() { try { v1 = (g1 instanceof v0); } catch(e0) { } try { /*MXX3*/g1.g1.RegExp.$9 = g2.RegExp.$9; } catch(e1) { } try { this.v0 = Object.prototype.isPrototypeOf.call(a2, b1); } catch(e2) { } a2.reverse(m0, s0, e0); return o0.o2.i1; }));function e(x)WeakMap(window, undefined)print(x);");
/*fuzzSeed-116170070*/count=224; tryItOut("testMathyFunction(mathy3, [0x07fffffff, -0x080000001, 0.000000000000001, 42, -0x100000001, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53+2), -0x07fffffff, -(2**53-2), 0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, 2**53+2, 0, Number.MAX_VALUE, 2**53-2, 2**53, 0x100000000, -0x100000000, 0x100000001, 1, 0x080000000, -0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, Math.PI]); ");
/*fuzzSeed-116170070*/count=225; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\B[\\\\s\\u0086\\\\cF]?)|\\\\3{0,}\", \"\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=226; tryItOut("\"use strict\"; for (var p in b2) { a2.length = v0; }");
/*fuzzSeed-116170070*/count=227; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return Math.sinh(Math.ceil(Math.imul(Math.sinh((x | 0)), x))); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 2**53+2, 0/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, 0x07fffffff, -0, -0x100000001, -0x080000000, 2**53, 2**53-2, 0x080000001, -(2**53-2), 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, 0, -0x080000001, 1/0, -0x0ffffffff, 1, -1/0, 1.7976931348623157e308, 42, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=228; tryItOut("with(x)/* no regression tests found */");
/*fuzzSeed-116170070*/count=229; tryItOut("b2.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((((1.0) + (1.0)) < ((i1) ? (d0) : (NaN)))))|0;\n  }\n  return f; });");
/*fuzzSeed-116170070*/count=230; tryItOut("\"use strict\"; v1 = t0.length;");
/*fuzzSeed-116170070*/count=231; tryItOut("print(((void shapeOf(\"\\u7A43\"))));");
/*fuzzSeed-116170070*/count=232; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.hypot((( + (( + (mathy1((x | 0), (( + (( + x) ^ ( + ( ~ -(2**53+2))))) | 0)) | 0)) >>> 0)) >>> 0), Math.fround((Math.min((Math.pow(x, 1.7976931348623157e308) | 0), (x | 0)) ? (( - (x >>> 0)) >>> 0) : mathy4(( ! x), x))))); }); testMathyFunction(mathy5, /*MARR*/[(1/0), (1/0), (1/0), NaN, NaN, NaN, NaN, (1/0), NaN, NaN, NaN, NaN, NaN, NaN, (1/0), (1/0), NaN, NaN, NaN, NaN, NaN, (1/0), NaN, (1/0), NaN, (1/0), NaN, (1/0), (1/0), (1/0), NaN, NaN, (1/0), NaN, NaN, (1/0), (1/0), NaN, NaN, (1/0), (1/0), NaN, NaN, (1/0), NaN, (1/0), NaN, (1/0), (1/0), NaN, NaN, NaN, (1/0), NaN, (1/0), (1/0), NaN, NaN, NaN, NaN, (1/0), NaN, NaN, (1/0), (1/0), (1/0), NaN, (1/0), (1/0), NaN, NaN, NaN, NaN, NaN, (1/0), NaN, NaN, (1/0), (1/0), NaN, (1/0), NaN, (1/0), (1/0), NaN, NaN, NaN, NaN, (1/0), (1/0), (1/0), NaN, NaN, NaN, (1/0), (1/0), (1/0), (1/0), (1/0), NaN, NaN, NaN, NaN, NaN, (1/0), NaN, (1/0), NaN, (1/0), NaN, (1/0), NaN, (1/0), (1/0), NaN, (1/0), (1/0), NaN, (1/0), NaN, NaN, NaN, NaN, (1/0), (1/0)]); ");
/*fuzzSeed-116170070*/count=233; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.sinh(( + Math.fround(Math.ceil(( + y))))) >>> 0); }); testMathyFunction(mathy5, [0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, 0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -0x080000001, 0.000000000000001, -0x100000001, -(2**53), 2**53, 0, Number.MAX_VALUE, 2**53+2, 0/0, -0x07fffffff, Math.PI, 1/0, 0x07fffffff, -0x080000000, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, 1, -(2**53+2), -1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, -0, 2**53-2]); ");
/*fuzzSeed-116170070*/count=234; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=235; tryItOut("\"use strict\"; \"use asm\"; e2.delete(o1.v1);");
/*fuzzSeed-116170070*/count=236; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=237; tryItOut("\"use strict\"; a0.push(this.s0, x, m1);");
/*fuzzSeed-116170070*/count=238; tryItOut("m0 + '';");
/*fuzzSeed-116170070*/count=239; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var sin = stdlib.Math.sin;\n  var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -512.0;\n    var d3 = 1.9342813113834067e+25;\n    d2 = (NaN);\n    (Float32ArrayView[0]) = ((+sin(((+pow(((((d3)) - ((((0x2ab481e2)))))), ((-0.125))))))));\n    d1 = (d2);\n    d3 = ((((((-0x8000000))) ^ ((0xe72a98b0)))) * ((((+((d1)))) - ((((d3)) / ((d1)))))));\n    return (((0xe571f187)+((0x7fffffff))))|0;\n    {\n      i0 = ((0xa6129834) ? ((0xe526047e) > (((Int8ArrayView[2]))>>>(((+pow(((4194305.0)), ((-137438953473.0)))) > (((3.022314549036573e+23)) / ((-134217729.0))))))) : (-0x8000000));\n    }\n    switch ((~~(d1))) {\n    }\n    return (((!((0x36cbff1e) > ((((abs((~((0xfdea3f04))))|0))+((0x22c6157c))+(((i0)+(/*FFI*/ff(((abs((0xb6763a2))|0)), ((-1.001953125)), ((-0.00390625)), ((-73786976294838210000.0)), ((-1.0625)), ((1.0)))|0))))>>>((0xbf0c56cb)*0xfffff))))))|0;\n  }\n  return f; })(this, {ff: function () { \"use strict\"; t0.set(o1.t0, 6); } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), (function(){return 0;}), false, (new Boolean(false)), (new Number(0)), '/0/', 1, '', (new Boolean(true)), undefined, 0, (new Number(-0)), '\\0', true, ({valueOf:function(){return '0';}}), (new String('')), null, NaN, /0/, [], 0.1, ({toString:function(){return '0';}}), '0', [0]]); ");
/*fuzzSeed-116170070*/count=240; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + (((Math.fround(Math.min(( + ( - ( + ( + y)))), Math.fround(( ! ( ~ x))))) | 0) == (( + Math.min(Math.tan(Math.fround(( ~ ( + Math.fround((x + Math.PI)))))), ( + y))) | 0)) | 0)) < ((( ! ((Math.fround(( - Math.fround((Math.abs(Math.fround(x)) ** (( ~ Number.MIN_VALUE) >>> 0))))) > Math.fround(( ~ y))) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy1, [-0x100000001, 0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, 0, 2**53, 2**53+2, 0x0ffffffff, -0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, -0, 1, -0x080000000, -0x07fffffff, 1/0, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, -(2**53), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, Math.PI, -(2**53-2), 0x080000001, 0x100000000, 42]); ");
/*fuzzSeed-116170070*/count=241; tryItOut("Array.prototype.pop.apply(a0, [h1, t0, s1, t1, b2]);");
/*fuzzSeed-116170070*/count=242; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.imul(Math.min(Math.fround(( ~ -Number.MAX_SAFE_INTEGER)), 0x100000000), (( + (((Math.ceil(( + Math.min(( + 0), ( + -1/0)))) | 0) % ((2**53+2 < (y <= ( + ( + y)))) | 0)) | 0)) | (0.000000000000001 ** y)))); }); ");
/*fuzzSeed-116170070*/count=243; tryItOut("\"use strict\"; /*infloop*/for(let b = new (Float32Array)((4277)); (Array.prototype.map).call(x = x, ); x) {/*RXUB*/var r = new RegExp(\"\\\\s(?!(?!\\\\cS)+|(?!.)*?)|\\\\1|(?=(?!\\\\3{3})(?!\\ufa2b|\\\\B[^]{0,1})\\\\b|^(?:[^])*?)(?!\\\\2{0,0}.|\\\\b+?|^|(?!.)\\\\s*.?{2})^|^[^\\\\S\\\\D\\\\W].|\\\\d|(?:[^\\\\r-\\u00fa\\\\D]){15,16}|\\\\s\", \"yim\"); var s = \"\"; print(uneval(s.match(r))); /\\1|.*(?![^])?*?*?/gm; }");
/*fuzzSeed-116170070*/count=244; tryItOut("const d, z, z = (this.__defineSetter__(\"x\", (Date.prototype.getMonth()))), {x: {let: {x}, z}, window: {x: [], x: [, e, , ], x: \u0009{d: [], NaN, y: {z: [{}, ]\u000c, x: {x: []}}}, this.x: {NaN: {w}}, x: [/*\n*/{window, b: [[b]], NaN}, ]}, x} = b, c = arguments.callee.caller.arguments++, x, [] = ++({a1:1})[13];throw StopIteration;let(y) { (b) = window;}");
/*fuzzSeed-116170070*/count=245; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ ( + (( + (( + (Math.sinh((x >>> 0)) >>> 0)) >>> 0)) || mathy0(Math.exp(( ~ ( + y))), (Math.fround(( - Math.fround(Math.asinh(0x0ffffffff)))) * Math.max(( + y), x)))))); }); ");
/*fuzzSeed-116170070*/count=246; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max(( + Math.atan2(( + ( + ( - ( + y)))), ( - ( + (x != ( + (( ~ (-0x080000001 | 0)) | 0))))))), ( + Math.tanh((Math.imul(y, ( + Math.fround(((x >>> 0) ** y)))) != ((y >>> 0) <= Math.sinh((Math.sin(y) >>> 0))))))); }); testMathyFunction(mathy0, [-0x100000000, -0x07fffffff, 0x07fffffff, 2**53, Math.PI, Number.MAX_SAFE_INTEGER, -0, -0x080000001, 0/0, 0x100000001, 0x080000001, -0x0ffffffff, -(2**53-2), 1/0, -(2**53), -Number.MIN_SAFE_INTEGER, -0x080000000, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, 0, 2**53+2, 2**53-2, 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, -1/0, 42, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-116170070*/count=247; tryItOut("\"use strict\"; e1 = new Set(s2);");
/*fuzzSeed-116170070*/count=248; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul((( ! Math.fround(( ! ( + mathy0(x, -0x100000000))))) | 0), (( + ( - Math.atan2(Math.hypot((x | 0), y), x))) | 0)) | 0); }); testMathyFunction(mathy3, [1, 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 2**53, 0x100000000, -0x100000001, -Number.MAX_VALUE, 42, -0x080000001, -0x0ffffffff, 0/0, 0, 2**53+2, -1/0, 0x07fffffff, -(2**53+2), -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, 1/0, Number.MIN_VALUE, -(2**53), -Number.MIN_VALUE, -0x100000000, -(2**53-2), 1.7976931348623157e308, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, 0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=249; tryItOut("/*MXX1*/o0 = g1.String;");
/*fuzzSeed-116170070*/count=250; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return (((( + (( ! ((2**53-2 >>> 0) ? Math.min(( + mathy2((y >>> 0), (Math.PI >>> 0))), (( + y) ? ( + x) : y)) : y)) | 0)) | 0) & (( + ( - (((((y >= ( + ( - x))) / Math.fround(y)) >>> 0) , (x >>> 0)) >>> 0))) | 0)) >> (Math.sinh(( + Math.clz32((( - 0x100000001) | 0)))) >>> 0)); }); testMathyFunction(mathy3, [-0x080000001, 0x080000001, -1/0, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, -(2**53), 2**53+2, 1, -(2**53-2), 1/0, 0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, -(2**53+2), -Number.MAX_VALUE, 42, 0, 2**53, 0x0ffffffff, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, Math.PI, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-116170070*/count=251; tryItOut("\"use strict\"; for (var p in t1) { v1 = (g2 instanceof e0); }");
/*fuzzSeed-116170070*/count=252; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0(((mathy0(( + ( ! ( + x))), mathy0(((Math.log10(x) >>> 0) | 0), Math.fround(x))) ? (Math.pow(mathy0(x, -(2**53)), (Math.PI * x)) || (( + -(2**53)) ** y)) : Math.min(x, ( + (x * y)))) | 0), (Math.cbrt(( + (( + ((y * 0x080000000) ? -0x100000001 : Math.tan(x))) >>> 0))) | 0)); }); ");
/*fuzzSeed-116170070*/count=253; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=254; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.log2((((Math.fround(((Math.log2((mathy0(y, (y | 0)) | 0)) >>> 0) ? ( + x) : mathy4(x, y))) ** (Math.clz32((( + (( ~ y) << ( + x))) >>> 0)) >>> 0)) | 0) >>> 0)) | 0); }); testMathyFunction(mathy5, [-0x07fffffff, -0, 0x080000001, -0x080000001, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, -0x0ffffffff, -(2**53), 1.7976931348623157e308, -0x080000000, 42, 2**53+2, -(2**53-2), 2**53, 0/0, 0, 0x100000000, -(2**53+2), Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, 0x0ffffffff, 1]); ");
/*fuzzSeed-116170070*/count=255; tryItOut("\"use strict\"; a2.sort(f1, v1);");
/*fuzzSeed-116170070*/count=256; tryItOut("e0.add(f2);");
/*fuzzSeed-116170070*/count=257; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return mathy2(Math.asin((Math.min((y !== ( + 1.7976931348623157e308)), Math.fround(Math.imul(Math.fround((mathy2((-0x100000000 >>> 0), (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)), (((y | 0) ^ (-1/0 | 0)) | 0)))) >>> 0)), Math.fround(Math.log10(Math.pow(-Number.MAX_SAFE_INTEGER, (mathy3((x | 0), (x | 0)) | 0))))); }); testMathyFunction(mathy4, [-0x100000001, 0x080000001, -0x080000001, 1.7976931348623157e308, -0x07fffffff, 42, 2**53, Number.MAX_VALUE, 2**53+2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, 0, Math.PI, -0x0ffffffff, -(2**53), 2**53-2, 1, -(2**53-2), -0x080000000, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, -0, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-116170070*/count=258; tryItOut("var znqcwh, window, vntdrp, rknsdz;g2.v0 = a0.reduce, reduceRight((function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 0.25;\n    var i3 = 0;\n    var d4 = 17.0;\n    var d5 = -512.0;\n    var d6 = -255.0;\n    var d7 = 1.125;\n    var d8 = 18446744073709552000.0;\n    d2 = (((d8)) * ((Infinity)));\n    {\n      (Float32ArrayView[((0xc51b05da)+(0xd1ff8006)) >> 2]) = ((d4));\n    }\n    i1 = (((+(0.0/0.0)) >= (18446744073709552000.0)) ? (0x275c74b) : (i1));\n    return +((Float64ArrayView[((Int32ArrayView[1])) >> 3]));\n  }\n  return f; }), v1);");
/*fuzzSeed-116170070*/count=259; tryItOut("\"use strict\"; m1.has(g1);");
/*fuzzSeed-116170070*/count=260; tryItOut("v2 = Object.prototype.isPrototypeOf.call(e1, h1);");
/*fuzzSeed-116170070*/count=261; tryItOut("/* no regression tests found */\ng0.v2 = g0.runOffThreadScript();\n");
/*fuzzSeed-116170070*/count=262; tryItOut("v2 = evalcx(\"/* no regression tests found */\", this.g1.g2);");
/*fuzzSeed-116170070*/count=263; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g1, e1);");
/*fuzzSeed-116170070*/count=264; tryItOut("\"use strict\"; e1.has(b0);function x(\u3056, e) { o0.a1 + ''; } v1 = Array.prototype.reduce, reduceRight.call(a0, (function(j) { f1(j); }), g1.f2);function b([[[[], , {y: [{}, [, x(+ /x/g )], , d, {x: x, x}, ], x: {}, c,  /x/g [\"split\"], x}, [[[[z], [{}, {x: [], e: {}, window}\u000d, x]], {x: {x: {x: {e: {}}, w: a}}}, x(x)], x, , [x, {x, x: {c, NaN: [[], ]}, e: {w: {eval: []}, x, x: [, [], {a, \u3056: []}]}, x: [, NaN, , /*\n*/], this.zzz.zzz}, [, x, {eval: [], x: this, e: \"-26\", x: [, \u0009[], ]}], , , {c: x, NaN, x: [, ({})]}], , ], [{d, e: x}], , [, ]], [, {x: RangeError, \u3056: [TypeError.prototype.toString, {x, b: [, {}, {x: {b, \u3056: []}}, ], x: x, x: {x: \u000c{c: x, y: []}}}, x, , , d], window: [{}]}, , ], {y: e}, [z, , , ], , [, d], [], \u3056, x], {x, e: x, x: Math.sinh(-6).z, a: {x: y, NaN, x, \u3056, y: (a)}, x: x, eval: x, x: {x, x, x: {y: of, x: Object.prototype.isPrototypeOf, y}, x: [{a: {}, NaN: [, y, ], \u3056: a, x: {x: {x: {\u3056: x, x: {x: {}}}, w: [, , ], x: y(undefined),  }, x: x}}, {x}, , {w, \u3056: {x: {e: x, x: (-2 % \u000c \"\" )(/*FARR*/[...[], \"\\uFB6D\", ...[], false].sort((eval = window, w) =>  { return; } ))}, e: [[]], a, w: {x: [, ], x}}, NaN, a: {window: x, x: {window: x}, x, y, NaN: w}}, {x: [/*FARR*/[, \"\\uA0FC\",  '' , ...[], window].map(Uint8Array, x|= /x/ ).__proto__, [], x], x}], e, window: [, [y, [, , {b: x}, ]], [[[], , [, ], [{a: arguments, x: []}, []]], , [], ], [{/*RXUE*//[\\cQ\\u00bc-\\\u0d14\\D]/i.exec(\"a\"): {w: NaN, x: {}, x}, x}, ], , ], x, w: {print([,]); }}}, setter], eval = (b + (Object.freeze = decodeURIComponent(this\n)))) { a1 = new Array; } m1 = new Map;");
/*fuzzSeed-116170070*/count=265; tryItOut("");
/*fuzzSeed-116170070*/count=266; tryItOut("/*MXX2*/g0.Math.cos = p0;");
/*fuzzSeed-116170070*/count=267; tryItOut("v0 = new Number(-Infinity);");
/*fuzzSeed-116170070*/count=268; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.clz32(Math.fround((((( + Math.imul(Math.atan2((Math.atanh(((Math.max((1/0 | 0), (x | 0)) >= Math.asin((-0x100000000 | 0))) >>> 0)) >>> 0), Math.fround(( ! Math.fround((Math.ceil((x | 0)) | 0))))), ( + (((x & (y >>> 0)) >>> 0) < (Math.imul((Math.asinh(y) >>> 0), (y >>> 0)) >>> 0))))) >>> 0) & (( + ( - (Math.atan2(Math.fround(( - Math.fround(-0x080000001))), y) >>> 0))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-116170070*/count=269; tryItOut("Array.prototype.unshift.apply(a1, [x, s2, t2]);");
/*fuzzSeed-116170070*/count=270; tryItOut("\"use strict\"; Array.prototype.unshift.call(a0, v1, window, e2, i1, g2.v1);");
/*fuzzSeed-116170070*/count=271; tryItOut("");
/*fuzzSeed-116170070*/count=272; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ~ Math.fround(Math.fround((Math.fround(Math.sign(Math.fround(1))) | mathy0((Math.imul((Math.imul((y >>> 0), ((Math.max(x, x) >>> 0) | 0)) >>> 0), Math.fround(x)) >>> 0), Math.fround(Math.exp(( + (x ** 0x080000000)))))))))); }); testMathyFunction(mathy4, [0, -0x080000001, -0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -Number.MAX_VALUE, 1, -0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 2**53, 0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0x100000000, 0x100000001, -0x080000000, 2**53+2, 2**53-2, 42, -1/0, Number.MIN_VALUE, 1/0, Math.PI, -(2**53-2), 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-116170070*/count=273; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=274; tryItOut("function g2.f2(e0)  { if((4277)) { if (/*UUV2*/(e.trim = e.revocable)) {neuter(b0, \"change-data\"); } else print(f1);} } ");
/*fuzzSeed-116170070*/count=275; tryItOut("/*vLoop*/for (rgbskj = 0; rgbskj < 67; ++rgbskj) { const e = rgbskj; Object.prototype.unwatch.call(v0, \"toLocaleUpperCase\"); } ");
/*fuzzSeed-116170070*/count=276; tryItOut("mathy2 = (function(x, y) { return Math.fround((( + Math.cos(Math.imul(Math.log10(Math.fround(( ~ Math.fround(y)))), (y >>> 0)))) & ( + mathy1((( - x) | 0), mathy1(( - Math.fround(( + ( + x)))), Math.pow(Math.asin(Math.imul(y, Math.fround(x))), Math.fround(Math.imul(Math.fround(-Number.MIN_VALUE), (y >>> 0))))))))); }); testMathyFunction(mathy2, [[], ({valueOf:function(){return 0;}}), '\\0', NaN, '', '/0/', [0], 0.1, (new Boolean(false)), ({toString:function(){return '0';}}), (new String('')), (new Number(0)), (new Number(-0)), (function(){return 0;}), 0, true, /0/, ({valueOf:function(){return '0';}}), null, -0, 1, (new Boolean(true)), false, undefined, '0', objectEmulatingUndefined()]); ");
/*fuzzSeed-116170070*/count=277; tryItOut("v0 = o2.r2.test;");
/*fuzzSeed-116170070*/count=278; tryItOut("\"use strict\"; /* no regression tests found */Object.prototype.unwatch.call(f1, \"valueOf\");");
/*fuzzSeed-116170070*/count=279; tryItOut("/*tLoop*/for (let y of /*MARR*/[undefined, function(){}, function(){}, new Number(1.5), new Number(1.5), undefined, undefined, new Number(1.5), function(){}, function(){}, undefined, undefined, undefined, undefined, function(){}, function(){}, new Number(1.5), undefined]) { /*ADP-3*/Object.defineProperty(a0, v0, { configurable: false, enumerable: false, writable: (y % 5 == 2), value: f2 }); }");
/*fuzzSeed-116170070*/count=280; tryItOut("mathy0 = (function(x, y) { return Math.fround(((Math.fround(( - Math.cosh((( + ( ! Math.fround(-0x07fffffff))) || ( - x))))) >>> 0) & ( ! ( + (( ~ (Math.abs(y) >>> 0)) | 0))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 0x07fffffff, -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, -0, 2**53, 0x100000001, 0, -1/0, Math.PI, 2**53-2, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 1, -0x080000000, 42, 0x080000000, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x0ffffffff, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-116170070*/count=281; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.fround(( - Math.fround(Math.atan(Math.fround(mathy2((-0x080000000 % ( + x)), Math.fround(( + mathy0(( + x), ( + x)))))))))) ? ( + (( + mathy1((( - x) | 0), Math.atanh((Math.atan2(Math.abs(x), (x >>> 0)) + (( - Math.fround(x)) | 0))))) ? ( + ( + (( + ((( - Math.fround(1.7976931348623157e308)) - Math.PI) ? ( + (mathy1(-0x100000001, (( - (x | 0)) | 0)) << -Number.MAX_VALUE)) : Math.atan2(Math.fround(Math.min(y, 1/0)), Math.fround(( ! (Math.clz32(( + x)) >>> 0)))))) >>> (Math.min((Math.atan2(x, y) >>> 0), (y >>> 0)) >>> 0)))) : ( + Math.atanh((( - (( - ( + ( ! ( + y)))) | 0)) | 0))))) : ((( ! (Math.exp(Math.fround(Math.atan2(-0x100000001, y))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy5, [-0x0ffffffff, Number.MIN_VALUE, -0x100000001, 0.000000000000001, -0x080000000, 2**53+2, 2**53, 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, 1.7976931348623157e308, -(2**53+2), -0x080000001, 0x100000001, -0x100000000, 2**53-2, Number.MAX_VALUE, -0x07fffffff, 0x080000000, 0x07fffffff, 1, 0/0, -1/0, -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -(2**53-2), 1/0, -0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=282; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ~ ( + Math.max(( ~ ( + (mathy3((42 >>> 0), ((Math.expm1((-0x100000001 | 0)) | 0) >>> 0)) >>> 0))), ( ~ x)))) >>> 0); }); testMathyFunction(mathy5, [0x080000000, Math.PI, -0x080000001, -(2**53+2), -0x100000000, 0x100000001, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -0x080000000, 0x080000001, 0, 1, 2**53+2, 2**53-2, 0.000000000000001, 2**53, 1/0, Number.MAX_VALUE, -(2**53), -0x100000001, -(2**53-2), -0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 42]); ");
/*fuzzSeed-116170070*/count=283; tryItOut("/*RXUB*/var r = new RegExp(\"[^\\\\_\\\\W*-\\ub3a5#]\", \"g\"); var s = \")\"; print(r.exec(s)); ");
/*fuzzSeed-116170070*/count=284; tryItOut("\"use strict\"; v0 = g1.runOffThreadScript();");
/*fuzzSeed-116170070*/count=285; tryItOut("/*RXUB*/var r = new RegExp(\"((?:[])|(?=\\\\D?){2})?\", \"y\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-116170070*/count=286; tryItOut("a0.forEach(f1, h1, v0, this.g0);function x()/*FARR*/[].sort(/*wrap3*/(function(){ var jjejiz = ((function factorial(nhselc) { print(x);; if (nhselc == 0) { ; return 1; } ; return nhselc * factorial(nhselc - 1); /*RXUB*/var r = /(\\B\u2ee0*?{4}\\b){262143}|\\3(?=(?:[^]))|.?++?|(\\s){1,}/; var s = \"_\"; print(s.replace(r,  /x/ , \"yi\")); print(r.lastIndex);  })(59472)); (Promise.all)(); }), \"\\u3D88\")Array.prototype.forEach.apply(a2, [(function() { s0 += o0.o2.s1; return v1; })]);");
/*fuzzSeed-116170070*/count=287; tryItOut("mathy0 = (function(x, y) { return (( + Math.expm1(( + (Math.cosh((Math.min(Math.fround((y ? x : x)), Math.fround(y)) >>> 0)) >>> 0)))) * Math.fround(( + Math.max((Math.exp(x) >>> 0), (x === Math.fround(Math.fround(Math.fround(( + ( ~ ( + -(2**53-2)))))))))))); }); testMathyFunction(mathy0, [0x080000000, 42, 0/0, -0, Number.MIN_SAFE_INTEGER, 0, 0.000000000000001, 1.7976931348623157e308, -0x07fffffff, 2**53-2, 0x080000001, 0x0ffffffff, 0x100000000, 1/0, 1, Number.MAX_VALUE, -0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -0x100000000, -(2**53), -(2**53-2), 0x07fffffff, -0x0ffffffff, -1/0]); ");
/*fuzzSeed-116170070*/count=288; tryItOut("\"use strict\"; a2.forEach((function mcc_() { var rimhls = 0; return function() { ++rimhls; o2.f1(rimhls > 7);};})(), g2.g1);");
/*fuzzSeed-116170070*/count=289; tryItOut("/*RXUB*/var r = new RegExp(\"[\\\\x48\\u00b6-\\\\u000C]\", \"y\"); var s = \"H\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116170070*/count=290; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.imul(Math.sinh((Math.min((( + Math.fround(Math.fround((Math.round((y >>> 0)) >>> 0)))) >>> 0), Math.fround(Math.sqrt(Math.fround(Math.log1p((y | 0)))))) | 0)), Math.fround(Math.pow((Math.acosh(Math.expm1((Number.MIN_SAFE_INTEGER >>> 0))) ** ((( + (y | 0)) | 0) | x)), Math.sinh(x)))); }); testMathyFunction(mathy3, [0x07fffffff, 0x100000000, 0.000000000000001, -0, -1/0, -0x100000001, 42, 2**53-2, Math.PI, 0x100000001, Number.MAX_SAFE_INTEGER, 1, 1/0, -0x080000000, 1.7976931348623157e308, -0x07fffffff, 0x080000000, -(2**53-2), 0x080000001, 2**53+2, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000000, 0, 0/0, Number.MAX_VALUE, 2**53, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=291; tryItOut("mathy3 = (function(x, y) { return Math.ceil((( ! (Math.max((Math.fround((Math.fround(y) > ((((x >>> 0) ? x : (y >>> 0)) >>> 0) || x))) | 0), y) | 0)) | 0)); }); testMathyFunction(mathy3, [42, -0, -1/0, -0x100000000, -0x100000001, -(2**53+2), 1, Number.MAX_VALUE, -0x080000001, -Number.MAX_VALUE, 0x080000001, -0x07fffffff, 2**53+2, 0x100000000, -(2**53-2), 2**53-2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -0x080000000, Math.PI, -0x0ffffffff, 0x100000001, 0x0ffffffff, -Number.MIN_VALUE, 0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 0, 2**53, 0/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=292; tryItOut("do {e0 + i1;function(id) { return id }; } while((x) && 0);\n/* no regression tests found */\n");
/*fuzzSeed-116170070*/count=293; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - (( + ( ! ( + (x ^ ((y >> (Math.asin(Math.atan2(0x080000000, x)) | 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-116170070*/count=294; tryItOut("\"use strict\"; a0[0];");
/*fuzzSeed-116170070*/count=295; tryItOut("\"use strict\"; (/([\\xD9\uf7bc\\S])/g);");
/*fuzzSeed-116170070*/count=296; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( ! Math.atan(( + Math.fround(( - Math.fround(( - y)))))))); }); testMathyFunction(mathy0, [0x100000000, -0x100000001, 1, 0.000000000000001, 42, Math.PI, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, 0x080000000, 0/0, -0x080000001, Number.MAX_VALUE, 0x100000001, 2**53-2, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, 1/0, -Number.MAX_VALUE, 2**53+2, 0, -(2**53), -(2**53+2), -0x100000000, -(2**53-2), -1/0, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=297; tryItOut("mathy5 = (function(x, y) { return ( ! Math.atan(Math.expm1(( + (( + -(2**53-2)) % ( + -Number.MAX_VALUE)))))); }); testMathyFunction(mathy5, /*MARR*/[ '\\0' , x(), x(),  '\\0' ,  '\\0' ,  '\\0' , x(),  '\\0' , x(), x(),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , x(),  '\\0' ,  '\\0' , x(), x(), x(), x(), x(), x(), x(), x(), x(), x(), x(),  '\\0' , x(),  '\\0' ,  '\\0' , x(), x(),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ]); ");
/*fuzzSeed-116170070*/count=298; tryItOut("/*infloop*/for(w = \"\\u7F6E\"; ( /* Comment */ /x/  >>>= window)\n; b = {\u3056\u000c: {eval: {x: x, e: [window, , ], a, x: {z: {w, x, x: [[], [, {}]], x}, x, c}}},  : [-26 *= true[new String(\"-15\")], ], x: {eval, x: undefined.yoyo(w).__proto__, y, d: {x: {x}, a: [x, [, [[], {x, x}, {x: {}, x}], ], {NaN: c, x: -28[\"caller\"], a}, {d: {c, c: {z: e, NaN: setter}}}, {a: {NaN: {}, c}, x}]}, x: NaN, e, window: e}, setter: [[z, , ], [, ], , NaN, x, \u3056], e: []}) {h2.getOwnPropertyNames = (function() { m2.valueOf = (function() { v2 = (t1 instanceof o1); return p1; }); return a0; });for (var v of t2) { try { neuter(b0, \"same-data\"); } catch(e0) { } try { Object.prototype.unwatch.call(e1, \"prototype\"); } catch(e1) { } g1.valueOf = Int32Array.bind(p1); } }");
/*fuzzSeed-116170070*/count=299; tryItOut("false;");
/*fuzzSeed-116170070*/count=300; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; } for(z = 18 in (uneval((4277)))) /* no regression tests found */");
/*fuzzSeed-116170070*/count=301; tryItOut("\"use strict\"; /*bLoop*/for (var bcargt = 0; bcargt < 16; ++bcargt) { if (bcargt % 2 == 1) { h1.get = f0; } else { print(uneval(e1)); }  } ");
/*fuzzSeed-116170070*/count=302; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround(( + Math.round(Math.fround(Math.abs(Math.ceil((Math.max((y | 0), (y >>> 0)) >>> 0))))))) , ((Math.ceil(((( + Math.tan(( + x))) | 0) === 0x0ffffffff)) , ( + ( + Math.fround(Math.ceil((Math.trunc((x && x)) >>> 0)))))) | 0))); }); testMathyFunction(mathy0, ['', (new Number(-0)), -0, '0', '\\0', [0], (new Boolean(false)), undefined, 0.1, /0/, objectEmulatingUndefined(), [], (new String('')), (new Boolean(true)), 0, (function(){return 0;}), 1, '/0/', ({valueOf:function(){return 0;}}), NaN, false, (new Number(0)), null, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), true]); ");
/*fuzzSeed-116170070*/count=303; tryItOut("/*tLoop*/for (let x of /*MARR*/[function(){},  /x/g ,  /x/g , function(){}, function(){}, function(){},  /x/g , function(){}, function(){}, function(){}]) { m0 + ''; }");
/*fuzzSeed-116170070*/count=304; tryItOut("this.o1.a2 = arguments.callee.caller.arguments;");
/*fuzzSeed-116170070*/count=305; tryItOut("g1.toString = (function(j) { f1(j); });");
/*fuzzSeed-116170070*/count=306; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( - ((mathy0((Math.fround((Math.atanh(mathy2(y, -Number.MIN_SAFE_INTEGER)) >> 2**53)) | 0), ((( + -Number.MAX_SAFE_INTEGER) * x) | 0)) | 0) | 0)) | 0) <= ( + (( - Math.sinh(Math.atan2(y, Math.fround(y)))) | 0))); }); testMathyFunction(mathy5, [0x0ffffffff, 2**53, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -1/0, -0x07fffffff, 42, -Number.MIN_SAFE_INTEGER, 0x100000001, 1, -0x080000000, 0, -Number.MAX_VALUE, 0/0, -0, Math.PI, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 0.000000000000001, 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, 0x080000000, -0x100000001, -0x080000001]); ");
/*fuzzSeed-116170070*/count=307; tryItOut("\"use strict\"; h2.hasOwn = f1;");
/*fuzzSeed-116170070*/count=308; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.cosh((((((Math.pow(((((Math.fround(42) !== y) | 0) | 0) >> (x | 0)), ( + Math.tanh(-Number.MIN_VALUE))) * Math.min((( - (x >>> 0)) >>> 0), (Math.atan2(( + y), ( + y)) >>> 0))) ? Math.pow(0x080000000, Math.sign((x | 0))) : (((y >>> 0) == ( + Math.imul((y | 0), (1/0 | 0)))) | 0)) | 0) === (((((Math.min(Math.pow(mathy1(((-0x080000001 ? y : 0x100000000) >>> 0), x), Math.fround(((y >>> 0) ? (y | 0) : x))), (x | 0)) | 0) >>> 0) >= (y >>> 0)) >>> 0) | 0)) >>> 0)); }); ");
/*fuzzSeed-116170070*/count=309; tryItOut("testMathyFunction(mathy4, [2**53-2, Number.MAX_VALUE, -0x0ffffffff, -0x100000001, -1/0, 0x100000000, 2**53+2, -(2**53+2), -(2**53-2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 1, 1.7976931348623157e308, -0, 0x080000001, 0/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 0x100000001, -Number.MIN_VALUE, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, Number.MIN_VALUE, 0, 42]); ");
/*fuzzSeed-116170070*/count=310; tryItOut("v1 = (m2 instanceof v0);");
/*fuzzSeed-116170070*/count=311; tryItOut("/*tLoop*/for (let z of /*MARR*/[({x:3}), arguments.callee, ({x:3}), arguments.callee, ({x:3}), arguments.callee, ({x:3}), ({x:3}), arguments.callee]) { ( '' );; }");
/*fuzzSeed-116170070*/count=312; tryItOut("testMathyFunction(mathy3, [-Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, -0x080000000, 2**53+2, 0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, -0x07fffffff, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, 42, -(2**53+2), -0x100000001, 0x07fffffff, 1, -(2**53), 1.7976931348623157e308, 0x100000001, -(2**53-2), 0/0, -0x100000000, 0x080000001, 2**53, -1/0, -0, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-116170070*/count=313; tryItOut("s2 = new String;this.i2.__proto__ = this.g1.g2.g0.s1;function x(x = (4277))a << x/*infloop*/M: for  each(eval in \"\\u1DA6\") g2.offThreadCompileScript(\"this.m0 = o2.g2.objectEmulatingUndefined();\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 3), noScriptRval:  \"\" , sourceIsLazy: -19, catchTermination: false }));");
/*fuzzSeed-116170070*/count=314; tryItOut("");
/*fuzzSeed-116170070*/count=315; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.imul(( + ( - ( + Math.max(x, ((Math.fround(-Number.MIN_VALUE) + x) >= Math.acos(x)))))), (Math.hypot((( + ( ~ ( + (Math.abs((y | 0)) >>> Math.fround(Math.imul(y, Math.fround(x))))))) | 0), ( + ( + Math.min(( + y), y)))) >>> 0)), (Math.sqrt(Math.fround(( + Number.MIN_VALUE))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), null, new String('q'), new String('q'), 0x100000000, ({d: (4277) -= Object.preventExtensions.prototype}), ({d: (4277) -= Object.preventExtensions.prototype}), 0x100000000, 0x100000000, ({d: (4277) -= Object.preventExtensions.prototype}), new String('q'), new String('q'), null, new String('q'), new String('q'), 0x100000000, null, 0x100000000, 0x100000000, new String('q'), ({d: (4277) -= Object.preventExtensions.prototype}), 0x100000000, null, null, ({d: (4277) -= Object.preventExtensions.prototype}), new String('q'), 0x100000000, 0x100000000, 0x100000000, null, ({d: (4277) -= Object.preventExtensions.prototype})]); ");
/*fuzzSeed-116170070*/count=316; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(g0, b2);");
/*fuzzSeed-116170070*/count=317; tryItOut("\"use strict\"; a1[8] = let (e)  /x/g ;");
/*fuzzSeed-116170070*/count=318; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.cbrt(((((((( + Math.asin(( + (( + (( + ( + ( ! ( + y)))) ? y : y)) >>> ( + Math.imul(( + x), ( + (Math.fround(x) ? Math.fround(y) : Math.fround(y))))))))) | 0) << (x | 0)) | 0) / Math.fround(( - Math.sign(Math.fround(Math.expm1(y)))))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, [-1/0, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -(2**53+2), -0x100000000, -(2**53), 0.000000000000001, 0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 1/0, 0x0ffffffff, 2**53+2, -0x100000001, -(2**53-2), 1, 2**53-2, -0x07fffffff, 0x07fffffff, -0x080000001, -0x0ffffffff, 42, 0, -Number.MAX_VALUE, 0/0, 2**53, -0, Number.MIN_VALUE, -0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=319; tryItOut("testMathyFunction(mathy2, [-0x100000001, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, 0/0, -0x100000000, 1, 0x100000001, Number.MIN_VALUE, 0x07fffffff, 0, Math.PI, 2**53+2, 0.000000000000001, 42, Number.MAX_VALUE, 2**53-2, -(2**53), -(2**53-2), -(2**53+2), 1/0, -0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, 1.7976931348623157e308, -0x080000000, 2**53]); ");
/*fuzzSeed-116170070*/count=320; tryItOut("\"use asm\"; s2 + '';");
/*fuzzSeed-116170070*/count=321; tryItOut("\"use strict\"; e0.add(e2);");
/*fuzzSeed-116170070*/count=322; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\1\", \"gym\"); var s = \"a\"; print(r.exec(s)); ");
/*fuzzSeed-116170070*/count=323; tryItOut("\"use strict\"; delete o0[\"acosh\"];");
/*fuzzSeed-116170070*/count=324; tryItOut("throw  '' ;12;");
/*fuzzSeed-116170070*/count=325; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy1(( + ( + (Math.fround(mathy0(Math.fround(y), Math.fround(Math.max(y, Math.fround(Math.atan(0x080000000)))))) ? (( - ((Math.sign(( + x)) >>> 0) >>> 0)) >>> 0) : Math.fround(( - ( + mathy3((Number.MIN_VALUE || Math.fround(x)), mathy4(( + -0x100000000), y)))))))), ( ~ ( + ( - ( + (-(2**53-2) * Math.fround((( - y) < x)))))))); }); testMathyFunction(mathy5, /*MARR*/[[], function(){}, Infinity, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, Infinity, function(){}, Infinity, [], [], [], [], [], [], [], [], Infinity, new Boolean(false), [], Infinity, true, [], new Boolean(false), [], new Boolean(false), new Boolean(false), Infinity, true, function(){}, true, Infinity, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), Infinity, function(){}, function(){}, Infinity, true, function(){}, function(){}, function(){}, new Boolean(false), function(){}, [], [], true, true, new Boolean(false), true, [], function(){}, new Boolean(false), [], new Boolean(false), new Boolean(false), [], [], new Boolean(false), Infinity, true, true, Infinity, function(){}, true, true, Infinity, [], function(){}, [], new Boolean(false), Infinity, Infinity, true, true, true, Infinity, Infinity, Infinity, true, Infinity, Infinity, Infinity, new Boolean(false), true, Infinity, [], function(){}, new Boolean(false), true, Infinity, [], Infinity, function(){}, function(){}, [], Infinity, Infinity, Infinity, [], Infinity]); ");
/*fuzzSeed-116170070*/count=326; tryItOut("mathy3 = (function(x, y) { return (Math.max((( + Math.max(((Math.imul((( - (y >>> 0)) >>> 0), (y >>> 0)) >>> 0) >>> 0), ( + Math.log10(Math.fround(((y >>> 0) === y)))))) | 0), (( + Math.asin(( + Math.imul(( + ( ! ((y || Math.sin(-(2**53-2))) | 0))), ( + (( + ( ~ Math.fround(Math.exp(Math.fround(x))))) <= ( + x))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-1/0, 0, 0x100000000, Number.MAX_VALUE, -(2**53), 2**53-2, 0x080000000, 0.000000000000001, -Number.MIN_VALUE, 0/0, 0x080000001, 42, -Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1, 1.7976931348623157e308, 1/0, -0x100000000, -0x080000001, 0x07fffffff, -(2**53+2), 0x100000001, -0x100000001, 2**53+2, -0, Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, -0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=327; tryItOut("mathy5 = (function(x, y) { return ((( + ( ~ ( + ( - x)))) >= (((Math.imul(y, y) | 0) + Math.hypot((Math.sqrt(mathy2(x, ( + x))) >>> 0), x)) >>> ( + ( - ( + (((y | 0) != ( + ( ! Math.cosh(x)))) >>> 0)))))) | 0); }); testMathyFunction(mathy5, [-1/0, -(2**53), 0x080000000, 2**53-2, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, Math.PI, 1/0, -0x07fffffff, 42, -0x0ffffffff, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 1, Number.MIN_VALUE, -(2**53-2), -0x080000001, 0x07fffffff, 0x100000000, 0, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-116170070*/count=328; tryItOut("testMathyFunction(mathy5, [(new Boolean(true)), (new Number(0)), '\\0', 0.1, NaN, 1, '', (new String('')), '/0/', ({valueOf:function(){return '0';}}), [], objectEmulatingUndefined(), /0/, '0', ({toString:function(){return '0';}}), (function(){return 0;}), (new Number(-0)), true, 0, [0], undefined, false, -0, null, (new Boolean(false)), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-116170070*/count=329; tryItOut("g2.offThreadCompileScript(\"x\");");
/*fuzzSeed-116170070*/count=330; tryItOut("mathy4 = (function(x, y) { return Math.min(((Math.expm1(mathy1(Math.fround(x), Math.fround(y))) | (Math.fround((Math.fround(x) <= Math.fround(y))) >>> 0)) >>> 0), Math.atan2(mathy1((Math.fround((Math.fround(Math.fround((Math.fround(x) ** Math.fround(x)))) / (-0x100000001 , (x >>> 0)))) + Math.acos(y)), Math.cosh((x && mathy3(mathy0((x | 0), y), ( + -0x080000001))))), Math.fround(Math.clz32(0.000000000000001)))); }); ");
/*fuzzSeed-116170070*/count=331; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ (( - ( + Math.fround(Math.imul(Math.fround(Math.hypot((( + y) * y), Math.trunc(Math.imul(Number.MIN_VALUE, x)))), Math.fround((( ! (y >>> 0)) >>> 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 42, 0x080000001, 2**53+2, -0x07fffffff, 0x0ffffffff, -(2**53-2), 0x100000000, 1, 0x100000001, Number.MAX_VALUE, -(2**53), -0, 0x080000000, Math.PI, -0x080000001, -(2**53+2), 0.000000000000001, -0x100000000, 0, -1/0, 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=332; tryItOut("mathy5 = (function(x, y) { return ( + Math.min(( + Math.log2(( + (Number.MAX_SAFE_INTEGER ** Math.atan2(Math.fround(Math.atanh(((((( + (x >>> 0)) >>> 0) | 0) ? (-Number.MIN_SAFE_INTEGER | 0) : (y | 0)) | 0))), Math.fround(mathy1(( + Math.pow(( + y), ( + x))), y))))))), ( - Math.clz32(mathy1(Math.max(x, ( + Math.atan2(x, y))), Math.fround(x)))))); }); testMathyFunction(mathy5, [(new Number(-0)), (new Number(0)), (new Boolean(true)), ({toString:function(){return '0';}}), false, undefined, [0], '\\0', objectEmulatingUndefined(), -0, '/0/', [], ({valueOf:function(){return 0;}}), (new Boolean(false)), '', ({valueOf:function(){return '0';}}), true, '0', 0.1, (new String('')), 1, null, /0/, NaN, (function(){return 0;}), 0]); ");
/*fuzzSeed-116170070*/count=333; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul(Math.sin((Math.fround((( - y) > Math.fround(y))) | 0)), ( - (((mathy2(-Number.MIN_SAFE_INTEGER, (y >>> 0)) <= y) >>> 0) | 0))); }); testMathyFunction(mathy3, [42, 0x0ffffffff, 0, 0x100000001, 0x07fffffff, -Number.MIN_VALUE, -0x080000000, 2**53, 1, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 1/0, -0, -0x07fffffff, Number.MIN_VALUE, -0x100000000, -0x100000001, 0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, -Number.MAX_VALUE, Math.PI, 2**53+2, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=334; tryItOut("\"use strict\"; x = x;\n");
/*fuzzSeed-116170070*/count=335; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0, -(2**53-2), 0x080000001, -(2**53+2), 0x0ffffffff, 2**53, -0x07fffffff, 0, -0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, -0x080000000, 0x080000000, Number.MAX_VALUE, -(2**53), -0x100000000, 0/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -0x100000001, 0x100000000, 2**53-2, Number.MIN_VALUE, -Number.MAX_VALUE, 42, -0x080000001, -1/0, 1/0]); ");
/*fuzzSeed-116170070*/count=336; tryItOut("a0 = a1.slice(3, 6);");
/*fuzzSeed-116170070*/count=337; tryItOut("\"use strict\"; a1 = new Array;");
/*fuzzSeed-116170070*/count=338; tryItOut("mathy1 = (function(x, y) { return mathy0(( + ((((0 | 0) !== (Math.expm1(( + y)) | 0)) | 0) ** (mathy0((Math.pow((Math.fround(mathy0(Math.fround(0x080000001), y)) | 0), (Math.sqrt(x) | 0)) | 0), x) >>> 0))), Math.fround(Math.sinh(Math.pow(((Math.exp(( + (x / ( + Math.fround((Math.fround(Number.MIN_VALUE) % Math.fround(x))))))) | 0) | 0), Math.clz32(Math.fround(x)))))); }); testMathyFunction(mathy1, [-0, 2**53, 0x0ffffffff, Math.PI, 0.000000000000001, -(2**53), Number.MIN_VALUE, 0/0, -(2**53+2), 1.7976931348623157e308, -0x080000001, -1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, Number.MAX_SAFE_INTEGER, 0x100000001, 42, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, -0x080000000, 2**53+2, 1, 0x100000000, -Number.MAX_VALUE, -0x100000001, 0, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=339; tryItOut("\"use strict\"; throw StopIteration;w = x;");
/*fuzzSeed-116170070*/count=340; tryItOut("\"use strict\"; L:switch(window) { case 7: const g1.o0.i2 = new Iterator(i2);break; s0 += s1;default: break; case (x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(this.__defineSetter__(\"x\", (objectEmulatingUndefined).bind)), function  a ()\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 1.00390625;\n    var d3 = -0.03125;\n    d2 = ((d1) + (d1));\n    return +((d2));\n  }\n  return f;)): a0[v2];/*RXUB*/var r = /(?:\\3){1,}|[^]{1,}?(?:(?:($)|\\t|(?:[^])([^])\\S*))*?/y; var s = \"\"; print(r.test(s)); case 5: case \"\\uEF5F\" ** 1.throw(((function factorial(csdazn) { ; if (csdazn == 0) { ; return 1; } runOffThreadScript; return csdazn * factorial(csdazn - 1);  })(47996))): break; g0.t0 = new Uint8Array(b1);break; case x: break; case 1: a1.forEach(this.g1.f2, (-26.eval(\"null\")));a0 = a1.slice(NaN, 6);case 4: a0.unshift(x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: undefined, }; })( \"\" ), Math.imul, x =>  { yield  /x/ (window) } ), this.e2, f1, this.f0);L:if(false) (17); else  if (null) {v0 = Object.prototype.isPrototypeOf.call(this.i2, h2);/(?!(?!(?:^)?)+(?:([\u00d5\u0010-\u008c])|\\3))/i.slice }break; break;  }");
/*fuzzSeed-116170070*/count=341; tryItOut("m0 = new Map(v0);");
/*fuzzSeed-116170070*/count=342; tryItOut("\"use strict\"; t0 = new Uint8ClampedArray(t1);");
/*fuzzSeed-116170070*/count=343; tryItOut("Uint8ClampedArray = x;");
/*fuzzSeed-116170070*/count=344; tryItOut("Array.prototype.unshift.call(a2, h1, g1.o1.f2);");
/*fuzzSeed-116170070*/count=345; tryItOut("mathy1 = (function(x, y) { return ( + (Math.imul(( + ( - ( + x))), (((0/0 + 1/0) + ( + (( + ( + (( + ( + x)) | ((Math.abs(Math.fround((mathy0(y, (y | 0)) | 0))) | 0) >>> 0)))) ** (x | 0)))) | 0)) | 0)); }); testMathyFunction(mathy1, [0, Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -0x080000000, 2**53, -0x100000001, 0x100000001, -0x0ffffffff, 0/0, 0x07fffffff, 2**53+2, 1/0, 0x080000001, 1, 1.7976931348623157e308, -0x080000001, -(2**53+2), Math.PI, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -1/0, 0.000000000000001, -(2**53), 0x080000000]); ");
/*fuzzSeed-116170070*/count=346; tryItOut("\"use strict\"; e1.add(p0);");
/*fuzzSeed-116170070*/count=347; tryItOut("f2 = Proxy.createFunction(h2, g2.f2, f2);");
/*fuzzSeed-116170070*/count=348; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + Math.max(Math.pow(( + Math.expm1(( ! (0x080000001 | 0)))), ( + (( ! ( ~ x)) ? Math.imul(x, (((0x080000000 >>> 0) ** y) >>> 0)) : ( + Math.fround(( - 2**53)))))), ( ~ (Math.fround(Math.min(Math.min(x, x), Math.fround(y))) >>> 0)))) | 0); }); testMathyFunction(mathy0, [-0x0ffffffff, 0x100000001, 1, 2**53, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 0, -(2**53), 0x100000000, -1/0, 42, 0x07fffffff, -0x100000000, -(2**53-2), 2**53+2, -0, 0x080000000, 0x0ffffffff, -0x080000001, 0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -(2**53+2), 1/0, 2**53-2, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=349; tryItOut("v0 = Object.prototype.isPrototypeOf.call(g1.v2, g1);");
/*fuzzSeed-116170070*/count=350; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max((Math.min((((((y == Math.hypot(y, (( - (( ~ x) >>> 0)) >>> 0))) | 0) >> (Math.hypot((x >>> 0), Math.log(Math.fround((((y | 0) ? Math.pow(x, y) : (y | 0)) | 0)))) | 0)) >>> 0) >>> 0), ((((Math.cos(( - x)) | 0) | 0) % (Math.fround(( ~ Math.fround(x))) | 0)) >>> 0)) | 0), Math.max(Math.pow(Math.fround(y), Math.fround((Math.hypot((y << -0x080000000), (( + (x ? 0x100000000 : 0.000000000000001)) | 0)) | 0))), ( - y))); }); testMathyFunction(mathy0, [2**53+2, 1.7976931348623157e308, 2**53, 1, 2**53-2, 0.000000000000001, 0x100000000, Number.MIN_VALUE, -0, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 0x07fffffff, -0x100000000, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, 0/0, -0x0ffffffff, -(2**53+2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 1/0, 0x080000001, -0x100000001, 42, 0, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=351; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! (Math.abs(Math.fround(Math.imul(Math.fround((( ~ y) | 0)), Math.fround(( + Math.asin((Math.min(((( + y) & (y >>> 0)) | 0), x) | 0))))))) >>> 0)); }); testMathyFunction(mathy3, [0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x080000000, -0x080000000, 0.000000000000001, 2**53-2, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, -Number.MIN_VALUE, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, 42, -Number.MAX_VALUE, 1, 1.7976931348623157e308, 0x07fffffff, -0x100000001, Math.PI, 1/0, -0x080000001, Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, 2**53, -(2**53), 0]); ");
/*fuzzSeed-116170070*/count=352; tryItOut("m1.has(((void version(170))));\n\n");
/*fuzzSeed-116170070*/count=353; tryItOut("m2.delete(this.o2.e2);function window(eval, [[, , , ], {}, , x]) { g0.i2.next(); } print(uneval(i0));");
/*fuzzSeed-116170070*/count=354; tryItOut("mathy1 = (function(x, y) { return Math.cos((Math.atan((Math.atan2(((Math.atan2((y >>> 0), (( + Math.imul((y % Math.fround(mathy0((x >>> 0), x))), ( + y))) >>> 0)) >>> 0) >>> 0), mathy0(Math.fround(Math.acosh(-Number.MIN_SAFE_INTEGER)), Math.fround(Math.atan(( + Math.log1p(0x07fffffff)))))) >>> 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[ /x/g , new Boolean(true), (1/0),  /x/g ,  /x/g , x, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true),  /x/g , x, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x,  /x/g , (1/0), (1/0), x, (1/0), new Boolean(true), (1/0), new Boolean(true),  /x/g , new Boolean(true), (1/0), new Boolean(true), new Boolean(true),  /x/g , (1/0), (1/0),  /x/g , (1/0), new Boolean(true), x, (1/0), x, objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), x, new Boolean(true),  /x/g , (1/0),  /x/g ,  /x/g , (1/0), x, x, new Boolean(true),  /x/g , objectEmulatingUndefined(), new Boolean(true)]); ");
/*fuzzSeed-116170070*/count=355; tryItOut("this.m1.has(b0);");
/*fuzzSeed-116170070*/count=356; tryItOut("\"use strict\"; { void 0; gcslice(58115); }");
/*fuzzSeed-116170070*/count=357; tryItOut("mathy1 = (function(x, y) { return (Math.hypot((Math.ceil((Math.fround((Math.fround(Math.fround(Math.log10(Math.fround(0x100000000)))) / Math.fround(Math.atan2(Math.fround(Math.asinh(y)), Math.imul(x, x))))) , Math.fround((Math.fround((Math.log10((x | 0)) | 0)) & y)))) | 0), Math.sign(Math.fround(Math.asinh((Math.min((x | 0), Math.log1p(Math.acosh((Math.fround(( ~ Math.fround(x))) | 0)))) >>> 0))))) | 0); }); testMathyFunction(mathy1, [1.7976931348623157e308, 2**53, -0x07fffffff, -Number.MAX_VALUE, 0x080000001, 0/0, 0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, 2**53-2, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 0x07fffffff, -(2**53+2), -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, 0x100000001, 0x100000000, -0x080000000, 1, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, 0, 2**53+2, Math.PI, -0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -1/0, -0]); ");
/*fuzzSeed-116170070*/count=358; tryItOut("\"use strict\"; M:switch(({}) = c = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })((function ([y]) { })()), d = Proxy.createFunction(({/*TOODEEP*/})( '' ), String.prototype.codePointAt))) { case ( /* Comment */x): print(b1);break;  }");
/*fuzzSeed-116170070*/count=359; tryItOut("var i0 = new Iterator(h1);");
/*fuzzSeed-116170070*/count=360; tryItOut("mathy5 = (function(x, y) { return (Math.min(((Math.fround(Math.hypot(Math.fround((Math.pow(Math.pow((y | 0), y), Math.hypot(y, Math.imul(Number.MIN_VALUE, (x | 0)))) !== y)), Math.fround((( - ((( + Number.MIN_SAFE_INTEGER) != ( + x)) | 0)) >>> 0)))) >= Math.log10(x)) | 0), Math.fround((Math.fround(((Math.log1p(x) ? ( + (y | 0)) : Math.tan(Math.tan(((( ! (((x % (y >>> 0)) | 0) | 0)) | 0) >>> 0)))) >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy5, [({valueOf:function(){return 0;}}), -0, '0', true, [], '/0/', (new Number(-0)), '', false, (function(){return 0;}), /0/, undefined, (new String('')), 0, (new Boolean(true)), (new Boolean(false)), '\\0', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), 0.1, (new Number(0)), [0], 1, objectEmulatingUndefined(), NaN, null]); ");
/*fuzzSeed-116170070*/count=361; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! Math.imul(Math.fround(Math.atan2(x, ((Math.log2((mathy1(y, -0x07fffffff) | 0)) >>> 0) <= ( - y)))), ( + Math.min(Math.atan2(y, Math.fround(Math.atan2(x, Math.PI))), (Math.atanh((x >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-116170070*/count=362; tryItOut("mathy4 = (function(x, y) { return ( + Math.fround(Math.pow(Math.min((y == x), (y ^ ( + x))), Math.fround(Math.fround(Math.min((( + ( ! ( + ( + (0/0 ? 0x100000000 : ( + Math.log2((y >>> 0)))))))) | 0), (((y | 0) && (((y < y) * y) >>> 0)) | 0))))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 2**53-2, 0.000000000000001, Math.PI, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, -0x080000000, 0/0, -(2**53-2), -1/0, 2**53, -0x07fffffff, -(2**53), 2**53+2, 0x0ffffffff, 0x100000001, 1, Number.MIN_VALUE, 0, -Number.MIN_VALUE, -0x100000001, 0x080000001, 0x080000000, 42, -(2**53+2), -0, -Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=363; tryItOut("/*infloop*/for(c in (\u000c(Date.prototype.getMinutes)(x))){/*oLoop*/for (wjkwti = 0; wjkwti < 170 && (false); ++wjkwti) { selectforgc(o1); } var ryikse = new ArrayBuffer(0); var ryikse_0 = new Int8Array(ryikse); ryikse_0[0] = 11; var ryikse_1 = new Int32Array(ryikse); print(ryikse_1[0]); var ryikse_2 = new Int8Array(ryikse); ryikse_2[0] = 10; var ryikse_3 = new Uint32Array(ryikse); ryikse_3[0] = 18; print(ryikse_1[0]);(void schedulegc(g0));a2 = new Array;o0.s0.toString = (function() { try { v1 = Array.prototype.reduce, reduceRight.apply(a2, [f1]); } catch(e0) { } try { v1 = (b2 instanceof a0); } catch(e1) { } /*ODP-1*/Object.defineProperty(s0, 14, ({value: [,,z1], writable: (ryikse_3 % 6 == 5), enumerable: new RegExp(\"(?:\\\\b*?(?!\\ufd5f)[^]){8388609,}|((?=\\\\d))\", \"m\")})); return h2; }); }");
/*fuzzSeed-116170070*/count=364; tryItOut("\"use strict\"; v2 = t0.length;");
/*fuzzSeed-116170070*/count=365; tryItOut("\"use strict\"; v1 = g0.eval(\"v2 = (m2 instanceof p2);\");");
/*fuzzSeed-116170070*/count=366; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    i1 = (i1);\n    return +((2.0));\n  }\n  return f; })(this, {ff: URIError}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[new Number(1.5), 0x080000001, new Number(1.5), 0x080000001, 0x080000001,  \"\" , new Number(1.5), 0x080000001, new Number(1.5), new Number(1.5), new Number(1.5), 0x080000001]); ");
/*fuzzSeed-116170070*/count=367; tryItOut("\"use strict\"; o1.v2 = a1.length;");
/*fuzzSeed-116170070*/count=368; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( - ( + Math.max(( + ( + ( + (( + Math.asinh(( + x))) >>> 0)))), ( + Math.imul(( + Math.atan2((( - x) * Math.fround(Math.log(Math.fround((y >> 1.7976931348623157e308))))), ( ~ -(2**53+2)))), ( + ((y | 0) >> x))))))) | 0); }); testMathyFunction(mathy0, [2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1, -0x100000001, 0x0ffffffff, -Number.MAX_VALUE, 0, -1/0, 0x080000001, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, -0x080000000, 42, 0.000000000000001, 1/0, 0x07fffffff, -(2**53+2), 0x100000000, -(2**53), 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, -0x100000000, Math.PI, 0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, 0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=369; tryItOut("mathy3 = (function(x, y) { return ( + Math.pow(mathy1((( ~ (x >>> 0)) >>> 0), ( - Number.MIN_SAFE_INTEGER)), ( + ( + ( + ((Math.fround(Math.cbrt(Math.fround(Math.sin(-0x07fffffff)))) | 0) != ( - y))))))); }); ");
/*fuzzSeed-116170070*/count=370; tryItOut("(/*FARR*/[, , ...[], ,  /x/g , \"\\uD834\", \"\\uD76A\", -27].map);");
/*fuzzSeed-116170070*/count=371; tryItOut("g0.valueOf = (function() { g2.offThreadCompileScript(\"function o0.f2(g0) (yield window > new RegExp(\\\"\\\\\\\\3\\\", \\\"yim\\\"))\"); return h2; });");
/*fuzzSeed-116170070*/count=372; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.sin((Math.min(( + Math.max(( + x), ( + x))), (mathy0(((( + (x >>> 0)) >>> 0) , (Math.fround(Math.clz32(Math.fround(x))) + x)), (Math.round((y | 0)) | 0)) | 0)) | 0))); }); ");
/*fuzzSeed-116170070*/count=373; tryItOut("/*ODP-3*/Object.defineProperty(v2, new String(\"17\"), { configurable: false, enumerable: z = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: ReferenceError, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function(name) { return delete x[name]; }, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return []; }, }; })(window), function  z (z) { t2 = new Int32Array(b0, 6, \"\\uA3F7\"); } , Math.cbrt), writable: (4277), value: ++w });");
/*fuzzSeed-116170070*/count=374; tryItOut("p2.__proto__ = g0.h0;");
/*fuzzSeed-116170070*/count=375; tryItOut("\"use strict\"; \"use asm\"; e2.add(i1);");
/*fuzzSeed-116170070*/count=376; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((([/*RXUE*/new RegExp(\"\\\\b{0,4}|\\\\B{3,}\\\\B|\\\\2\", \"m\").exec(\"  1\\u39f31\\n\\n1\\u39f31\\n\\n\")])))|0;\n  }\n  return f; })(this, {ff: x.reverse}, new ArrayBuffer(4096)); testMathyFunction(mathy5, ['0', NaN, (new Number(-0)), 0.1, null, '/0/', -0, (new Boolean(false)), [], false, (new Number(0)), ({valueOf:function(){return 0;}}), undefined, 1, /0/, (function(){return 0;}), ({valueOf:function(){return '0';}}), 0, ({toString:function(){return '0';}}), '', (new String('')), '\\0', objectEmulatingUndefined(), (new Boolean(true)), true, [0]]); ");
/*fuzzSeed-116170070*/count=377; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=378; tryItOut("testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, Math.PI, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, 0, -(2**53+2), 0x07fffffff, 0x080000001, -0x07fffffff, 2**53+2, -(2**53), -0x100000001, 1.7976931348623157e308, 0/0, -1/0, -0, -0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0x080000000, 42, 1/0, -(2**53-2), 0.000000000000001, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 1, 0x100000000, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=379; tryItOut("a0 = a1.concat(a1, g0.t1, t1);");
/*fuzzSeed-116170070*/count=380; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ Math.imul((( - y) + Math.hypot(( + (y << (x === y))), x)), (Math.fround(y) % Math.fround(( ! (( + Math.imul(( + mathy0((x >> y), x)), ( + Math.acos(x)))) >>> 0)))))); }); testMathyFunction(mathy1, [-0x080000000, 1.7976931348623157e308, 0x100000000, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, 0/0, 0x080000001, -0x07fffffff, -(2**53+2), -1/0, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, -0, 1, 2**53-2, -0x100000001, -(2**53-2), 42, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0x080000000, -0x0ffffffff, 2**53+2, 0.000000000000001, 0x07fffffff, 0]); ");
/*fuzzSeed-116170070*/count=381; tryItOut("/*RXUB*/var r = /./im; var s = \"\\u384c\"; print(s.replace(r, '', \"gi\")); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=382; tryItOut("M:if(false) { if (((4277).eval(\"if(false) { if (new (true)( /x/g , c)) print(x); else print(x);}\"))) {let (gjsviq, ixxoyc, rkdrdp, eval = \"\\u582A\", x, dmqman, rvengq) (\"\\uBAC1\".yoyo(length));g0.v1 = o2.t1.length; } else ;;}");
/*fuzzSeed-116170070*/count=383; tryItOut("\"use asm\"; const kwmkcz, jvldjx;m1 = new Map;");
/*fuzzSeed-116170070*/count=384; tryItOut("\"use strict\"; let x = eval(\"/* no regression tests found */\");/*RXUB*/var r = g1.r2; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=385; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (Infinity);\n    switch ((((0x7a2e15e)-(i2)) ^ ((/*FFI*/ff(((1.888946593147858e+22)), ((147573952589676410000.0)), ((1.0625)), ((-288230376151711740.0)), ((549755813889.0)))|0)-(0xffffffff)))) {\n      case -3:\n        {\n          (Float64ArrayView[((!(0xf6243218))) >> 3]) = ((5.0));\n        }\n        break;\n      case 0:\n        {\n          {\n            return +((d0));\n          }\n        }\n        break;\n      case -3:\n        return +((Infinity));\n        break;\n      case -2:\n        (Uint32ArrayView[((0xff0c178b)+(0x4f376f1)+(0x5e217937)) >> 2]) = ((0xf055f1a1));\n        break;\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: ReferenceError}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116170070*/count=386; tryItOut("v0 = (a0 instanceof g1);");
/*fuzzSeed-116170070*/count=387; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=388; tryItOut("t2 = new Uint32Array(10);");
/*fuzzSeed-116170070*/count=389; tryItOut("this.e0.add(s2);");
/*fuzzSeed-116170070*/count=390; tryItOut("/*iii*/15;v2 = 4.2;/*hhh*/function mvoxmn(x = c, b){e1.toString = (function(j) { if (j) { try { for (var p in a1) { a2.unshift(s0, f2, p1); } } catch(e0) { } h0.delete = (function() { try { t1 = new Uint8ClampedArray(this.a1); } catch(e0) { } try { t2.set(a1, 4); } catch(e1) { } try { selectforgc(o0); } catch(e2) { } /*ODP-1*/Object.defineProperty(v0, \"some\", ({value: yield /((?:[^]{2,5}))/im, configurable: true})); return a2; }); } else { try { s2 = new String; } catch(e0) { } g2.s0.toSource = (function() { for (var j=0;j<78;++j) { f2(j%4==0); } }); } });}");
/*fuzzSeed-116170070*/count=391; tryItOut("\"use strict\"; this.t1 = t1.subarray(7);");
/*fuzzSeed-116170070*/count=392; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a2, 2, ({writable: (x % 59 != 29), configurable: true}));");
/*fuzzSeed-116170070*/count=393; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"end\" }); }");
/*fuzzSeed-116170070*/count=394; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( - ( - (Math.round(( + Math.fround(y))) | 0))) >>> 0); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0, 0/0, -Number.MAX_SAFE_INTEGER, 42, 0x080000001, 0x07fffffff, -(2**53-2), 2**53-2, 1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53+2, Number.MIN_VALUE, 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, -0x080000001, 1, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, 0x080000000, -(2**53+2), 1.7976931348623157e308, -(2**53), -0x07fffffff, -0x100000000, 0x0ffffffff, -0x080000000, -0x100000001, 0x100000001, -1/0]); ");
/*fuzzSeed-116170070*/count=395; tryItOut("mathy0 = (function(x, y) { return (Math.pow(( + Math.acos(y)), Math.min(((Math.tanh((Math.fround(( - Math.fround((y ** Math.fround(Math.min(-0x0ffffffff, x)))))) | 0)) >>> 0) >>> 0), (((y != x) | 0) | 0))) >>> 0); }); ");
/*fuzzSeed-116170070*/count=396; tryItOut("h2 = {};function x(x = null, get) { \"use asm\"; return new RegExp(\"$*?\", \"y\").__defineSetter__(\"this.d\", (Math.clz32).bind(\"\\u6BB6\", \"\\u970B\")) } for (var p in o1) { try { selectforgc(o2); } catch(e0) { } g1.v2 = (t2 instanceof b2); }");
/*fuzzSeed-116170070*/count=397; tryItOut("(new encodeURI() != x);Array.prototype.forEach.call(a0, (function() { for (var j=0;j<159;++j) { f1(j%4==0); } }), a0, g2.h2);/* no regression tests found */");
/*fuzzSeed-116170070*/count=398; tryItOut("a1.sort((function() { o0.v1 = evalcx(\"for (var p in s1) { /*MXX1*/o0 = g1.Int16Array.BYTES_PER_ELEMENT; }\", g0); return h2; }), v1, this.t1, p0);");
/*fuzzSeed-116170070*/count=399; tryItOut("mathy5 = (function(x, y) { return (Math.fround((Math.pow(((Math.tan((Math.log(Math.expm1(Math.fround(mathy0(-0x100000001, Math.fround(x))))) >>> 0)) >>> 0) >>> 0), (Math.pow(((Math.fround((( ~ ((( ! (( - x) | 0)) | 0) >>> 0)) >>> 0)) != Math.expm1(-0x080000001)) >>> 0), Math.asin(((x / Math.atanh((( + y) >>> y))) >>> 0))) >>> 0)) >>> 0)) ? Math.fround(((( + (y | ((((( + (x | 0)) | 0) | 0) % ((Math.cosh(((Math.cbrt((x >>> 0)) >>> 0) >>> 0)) >>> 0) | 0)) | 0))) | 0) !== ( + ((Math.max((x | 0), (Math.atan2(( + Math.fround(Math.log(x))), y) | 0)) | 0) > ( + ( + -0x080000001)))))) : Math.fround(( + Math.log(y)))); }); testMathyFunction(mathy5, [2**53, 0x07fffffff, -Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, -(2**53), -0x0ffffffff, 2**53-2, 0x080000001, 0.000000000000001, 0/0, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, 0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 1.7976931348623157e308, -0, -0x100000001, 2**53+2, -0x080000000, Number.MIN_VALUE, 0, -1/0, 0x100000000, Number.MAX_VALUE, 1/0, -(2**53+2), 0x080000000]); ");
/*fuzzSeed-116170070*/count=400; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=401; tryItOut("t1 = new Uint32Array(g2.a0);");
/*fuzzSeed-116170070*/count=402; tryItOut("L:if(((x) = x.valueOf(\"number\").eval(\"RangeError = ((x = new ((new Function(\\\"print(/(?!\\\\\\\\1)\\\\\\\\3*?/ym);\\\")))(\\u000d[,,z1])))\"))) { if (((arguments.callee).call(this ? [,] : \"\\u75A7\", {}).throw(eval(\"v0 = Object.prototype.isPrototypeOf.call(m1, o2.m1);\", ((function sum_indexing(dkdscz, zvdjho) { ; return dkdscz.length == zvdjho ? 0 : dkdscz[zvdjho] + sum_indexing(dkdscz, zvdjho + 1); })(/*MARR*/[new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, new String(''), Number.MIN_VALUE, new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), Number.MIN_VALUE, new String(''), Number.MIN_VALUE, new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), Number.MIN_VALUE, Number.MIN_VALUE, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), Number.MIN_VALUE, Number.MIN_VALUE, new String(''), Number.MIN_VALUE, new String(''), Number.MIN_VALUE, new String(''), new String(''), Number.MIN_VALUE, new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE], 0)))))) Array.prototype.push.apply(a0, [o2, b2, h1]); else {v1 + '';print(x); }}");
/*fuzzSeed-116170070*/count=403; tryItOut("L:for(d = true in this) \"\\uDB31\";");
/*fuzzSeed-116170070*/count=404; tryItOut("mathy4 = (function(x, y) { return (Math.imul((Math.atan2((Math.sin((y >>> 0)) >>> 0), ((((Math.log2((((y , (Math.cos(y) >>> 0)) >>> 0) | 0)) | 0) && (y | 0)) | 0) | 0)) | 0), (( + Math.max(( + Math.min((( ~ y) & (Math.hypot(x, (Math.fround(( ! y)) | 0)) | 0)), (Math.fround(( ~ Math.fround(2**53+2))) && Math.fround(( + ( + ( + Math.fround(Math.min(Math.fround(x), Math.fround(0x100000001)))))))))), ( + ( + Math.atan(( - ( + y))))))) | 0)) | 0); }); testMathyFunction(mathy4, [0x07fffffff, -(2**53), -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, -0, 1/0, 0x080000000, 0x080000001, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 2**53+2, -0x080000000, 2**53-2, -Number.MIN_VALUE, 1.7976931348623157e308, -1/0, Math.PI, 0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0/0, 0, -Number.MAX_SAFE_INTEGER, -0x100000001, 1, 0.000000000000001]); ");
/*fuzzSeed-116170070*/count=405; tryItOut("t1 = t1.subarray(17);");
/*fuzzSeed-116170070*/count=406; tryItOut("L:with(allocationMarker())/*RXUB*/var r = g0.g2.r0; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-116170070*/count=407; tryItOut("mathy3 = (function(x, y) { return Math.min(Math.fround(Math.sqrt(Math.imul((Math.tan(((y >>> x) >>> 0)) | 0), (Math.fround(y) >>> 0)))), Math.fround(Math.hypot((mathy1((Math.imul(Math.cbrt(Math.sinh(Math.fround((((x >>> 0) ? (x >>> 0) : (1 >>> 0)) >>> 0)))), (( + y) ? x : x)) >>> 0), (y >>> 0)) >>> 0), Math.imul(( ~ Math.round((y * x))), ( + (Math.asin(Math.fround(x)) | 0)))))); }); testMathyFunction(mathy3, [(function(){return 0;}), NaN, '\\0', 0, /0/, null, true, false, 0.1, (new Number(-0)), (new String('')), '0', '', (new Number(0)), [], ({valueOf:function(){return '0';}}), 1, ({valueOf:function(){return 0;}}), '/0/', objectEmulatingUndefined(), -0, undefined, (new Boolean(true)), ({toString:function(){return '0';}}), (new Boolean(false)), [0]]); ");
/*fuzzSeed-116170070*/count=408; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3|((?!$)){1,1}\", \"gim\"); var s = \"0\"; print(r.exec(s)); ");
/*fuzzSeed-116170070*/count=409; tryItOut("this.h2.__proto__ = o1.f2;");
/*fuzzSeed-116170070*/count=410; tryItOut("\"use strict\"; ;");
/*fuzzSeed-116170070*/count=411; tryItOut("for(var \u3056 = \"\\uC051\".throw( '' ) in  '' ) return;");
/*fuzzSeed-116170070*/count=412; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.tan(Math.log(Math.fround(( + Math.expm1(mathy0(( ! (x >>> 0)), mathy4(( + Math.atan2(Math.fround(x), (Math.ceil(( + 0.000000000000001)) >>> 0))), -1/0))))))); }); testMathyFunction(mathy5, [0.000000000000001, 0x080000000, -(2**53-2), Number.MIN_VALUE, -(2**53), -1/0, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, 1, Number.MAX_SAFE_INTEGER, 42, 2**53-2, 0x100000000, 2**53, -0x080000001, -0x100000001, 0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -0, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, 0, 0x080000001, Math.PI, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-116170070*/count=413; tryItOut("/*tLoop*/for (let e of /*MARR*/[objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0)]) { (window); }");
/*fuzzSeed-116170070*/count=414; tryItOut("mathy5 = (function(x, y) { return (((( + Math.hypot(( + ((x >>> 0) - (y >>> 0))), ( + (mathy3((y | 0), (Math.imul(((Math.tan((Math.min(y, -0x100000001) | 0)) | 0) == Math.atan2(x, y)), y) | 0)) | 0)))) >>> 0) ? (Math.asin(( + (Math.fround(Math.imul(Math.fround(( - ( + mathy1(0x100000001, y)))), ( - -0x0ffffffff))) ? Math.fround((( + (0x080000001 && Math.fround(-0x080000000))) ? ( ~ (Math.cbrt((x >>> 0)) >>> 0)) : Math.hypot(y, (Math.fround(Math.fround(Math.hypot(1/0, y))) << Number.MAX_VALUE)))) : ( + Math.atan((mathy0((x >>> 0), (( + (y || (y | 0))) >>> 0)) >>> 0)))))) >>> 0) : ((( + Math.pow(x, Math.log10(y))) ** Math.sign((( + Math.pow(( + x), ( + y))) === x))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x0ffffffff, 0x100000001, 1/0, -1/0, 1, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, 0, -Number.MIN_VALUE, 42, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000, -0, 0x100000000, -0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0/0, 1.7976931348623157e308, Math.PI, -Number.MAX_VALUE, -0x080000001, 0x080000000, -(2**53+2), 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-116170070*/count=415; tryItOut("\"use strict\"; t0.set(g0.t2, 18);");
/*fuzzSeed-116170070*/count=416; tryItOut("mathy5 = (function(x, y) { return Math.asin(((mathy0((Math.imul((y | 0), (mathy2(Math.fround((Math.fround(x) << Math.fround(y))), (Math.sqrt(x) >>> 0)) | 0)) | 0), ((( + (( ! ( ! (( + (x >>> 0)) >>> 0))) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy5, [-(2**53-2), 0, Number.MAX_VALUE, 2**53+2, 0x100000001, Math.PI, Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 1, -0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, -0x080000001, 2**53, 2**53-2, 0x100000000, 0.000000000000001, 0x07fffffff, 42, -Number.MIN_VALUE, -(2**53), -0x100000000, -Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000]); ");
/*fuzzSeed-116170070*/count=417; tryItOut("s2 += 'x';");
/*fuzzSeed-116170070*/count=418; tryItOut("if((x % 2 != 0)) { if (x ? ([[]].__defineGetter__(\"b\", (new Function).call)) : this = Proxy.create(({/*TOODEEP*/})(\"\\u083B\"), Math)) yield ({a2:z2}); else { }}");
/*fuzzSeed-116170070*/count=419; tryItOut("/*RXUB*/var r = /(?:\\b|[\\xb1-\\u3aFb\\u005F-\\x9e]\\1|(?:\\S?)\\b|\\s*?|[]\u6ddf{4294967297}+?)/ym; var s = \"111111111111111111111111111111111111111111111111111111\"; print(r.exec(s)); ");
/*fuzzSeed-116170070*/count=420; tryItOut("/*ODP-1*/Object.defineProperty(h0, \"1\", ({configurable:  '' }));");
/*fuzzSeed-116170070*/count=421; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( - Math.fround(Math.fround(Math.ceil(Math.hypot((((Math.acos(Math.fround(y)) >>> 0) && Math.fround(Math.imul(((y | 0) || (x | 0)), Math.cos(mathy4(x, Math.fround(Number.MIN_VALUE)))))) >>> 0), (( + (( - -0) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy5, [0x0ffffffff, Number.MIN_VALUE, 2**53+2, 0x07fffffff, 0, -0x080000001, -(2**53-2), 0/0, -1/0, 2**53-2, -0x080000000, 0x080000001, 0x100000000, 0x080000000, 2**53, -(2**53+2), Math.PI, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, -0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1, 42]); ");
/*fuzzSeed-116170070*/count=422; tryItOut(";");
/*fuzzSeed-116170070*/count=423; tryItOut("var dkasup = new SharedArrayBuffer(2); var dkasup_0 = new Int8Array(dkasup); print(dkasup_0[0]); dkasup_0[0] = -13; (-21);print(dkasup_0[9]);var zwrqdu = new ArrayBuffer(0); var zwrqdu_0 = new Uint32Array(zwrqdu); print(zwrqdu_0[0]); const o0.a0 = g2.a0.slice(-8, -6);mathy0t0[v1];");
/*fuzzSeed-116170070*/count=424; tryItOut("");
/*fuzzSeed-116170070*/count=425; tryItOut("/*RXUB*/var r = new RegExp(\"[^\\\\u00F9-\\\\cB\\\\f\\\\d}]+?\", \"gim\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=426; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((Float64ArrayView[((-0x8000000)) >> 3]));\n  }\n  return f; })(this, {ff:  '' }, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[-0x100000001, -0x100000001, -0x100000001, x, -0x100000001, -0x100000001, x, -0x100000001, -0x100000001, x, -0x100000001, x, -0x100000001, -0x100000001, x, x, -0x100000001, -0x100000001, -0x100000001, x, x, x, x, x, -0x100000001, -0x100000001, x, -0x100000001, -0x100000001, x, -0x100000001, -0x100000001, -0x100000001, -0x100000001, x, -0x100000001, -0x100000001, -0x100000001, x, x, -0x100000001, -0x100000001, x, -0x100000001, x, -0x100000001, -0x100000001, x, x, -0x100000001, x, -0x100000001, -0x100000001, x, -0x100000001, x]); ");
/*fuzzSeed-116170070*/count=427; tryItOut("\"use strict\"; t2.__proto__ = o1.b1;");
/*fuzzSeed-116170070*/count=428; tryItOut("\"use strict\"; const e2 = new Set(e1);");
/*fuzzSeed-116170070*/count=429; tryItOut("Array.prototype.pop.call(a1, a1, s2);");
/*fuzzSeed-116170070*/count=430; tryItOut("\"use strict\"; v2 = g2.eval(\"function f2(o2)  { a0.pop(); } \");");
/*fuzzSeed-116170070*/count=431; tryItOut("mathy1 = (function(x, y) { return ( ~ Math.cos(Math.fround(Math.abs(Math.max(((Math.sqrt(x) | 0) >>> 0), (y | 0)))))); }); testMathyFunction(mathy1, [-1/0, 0x0ffffffff, -0x100000001, 2**53+2, 1.7976931348623157e308, -0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), 0x080000000, -0x0ffffffff, 1/0, -(2**53+2), 0.000000000000001, 42, 0/0, Number.MAX_VALUE, Math.PI, -(2**53), 0, 0x07fffffff, 0x100000001, 0x100000000, -0x080000000, -0x100000000, 2**53, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1]); ");
/*fuzzSeed-116170070*/count=432; tryItOut("\"use strict\"; ;");
/*fuzzSeed-116170070*/count=433; tryItOut("/*RXUB*/var r = new RegExp(\"(?=[\\\\s\\\\f-\\u7631])\\\\B|\\\\2|\\\\cK+(\\\\b{1,4}){0,}|(?:(^|\\\\W))?+?*?\", \"gim\"); var s = \u3056 *= x; print(s.replace(r, 'x', \"gy\")); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=434; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return ((( + ((( ~ (x >>> 0)) >>> 0) | 0)) ? (Math.cos(x) != (Math.fround((Math.fround(x) && Math.fround((mathy0((y >>> 0), (x >>> 0)) >>> 0)))) >>> mathy0(Number.MIN_SAFE_INTEGER, y))) : Math.atan2(Math.sin((Math.pow((Math.atan2((Math.fround(( ! y)) | 0), (( + Math.asin(y)) | 0)) | 0), (Number.MAX_VALUE | 0)) | 0)), (((Math.sign(( + (y ? ( + (y == Math.max(x, x))) : Math.fround(y)))) >>> 0) & ( + Math.fround(Math.hypot(Math.fround(( - Math.fround(y))), Math.log10((y >>> 0)))))) >>> 0))) | 0); }); testMathyFunction(mathy3, [1/0, Number.MIN_VALUE, -(2**53-2), 0/0, 0, -Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, -0x100000000, 0x100000000, Math.PI, 0x080000000, Number.MAX_VALUE, -(2**53), 2**53, -Number.MAX_VALUE, 2**53+2, -0x0ffffffff, 0.000000000000001, -0, 2**53-2, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -Number.MIN_VALUE, 0x0ffffffff, 0x100000001, -0x100000001, -0x080000000, -0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-116170070*/count=435; tryItOut("o1 = a1.__proto__;");
/*fuzzSeed-116170070*/count=436; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy1((( - Math.fround(Math.sqrt(Math.fround(((( + Math.fround(( ! x))) != (x >>> 0)) >>> 0))))) >>> 0), (Math.cbrt((Math.cbrt(x) >>> 0)) || Math.fround(Math.fround(Math.max(Math.fround(y), x))))); }); testMathyFunction(mathy5, [0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, 2**53+2, 0x100000001, 1/0, 0x100000000, 0, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 0x080000000, -(2**53-2), -1/0, Number.MIN_VALUE, -0x100000001, -0x080000000, -0x07fffffff, -(2**53), 0x07fffffff, 42, -0, -(2**53+2), -0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, Math.PI, Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-116170070*/count=437; tryItOut("\"use strict\"; v1 = t1.byteOffset\n");
/*fuzzSeed-116170070*/count=438; tryItOut("\"use strict\"; { void 0; setGCCallback({ action: \"majorGC\", depth: 5, phases: \"both\" }); }");
/*fuzzSeed-116170070*/count=439; tryItOut("print(x);");
/*fuzzSeed-116170070*/count=440; tryItOut("selectforgc(o2);");
/*fuzzSeed-116170070*/count=441; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return Math.sqrt(Math.pow((( ! (((Math.hypot((y >>> 0), (Number.MAX_VALUE >>> 0)) >>> 0) !== x) >>> 0)) | 0), Math.fround((( + Math.acosh((x >>> 0))) ? Math.min((((Number.MAX_SAFE_INTEGER | 0) | (y | 0)) | 0), Math.fround(Math.pow(( + x), Math.fround(Math.atan2(x, y))))) : (Math.max(x, (Math.fround(Math.atan2(Math.fround(mathy0((x | 0), -0x100000000)), Math.fround(x))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[0x40000000, [1],  /x/g , [1],  /x/g , -Infinity, -Infinity, [1], 0x40000000, [1], [1], -Infinity, -Infinity, -Infinity, -Infinity, [1], [1], 0x40000000, 0x40000000, [1], 0x40000000, 0x40000000, [1], 0x40000000, -Infinity, 0x40000000,  /x/g , 0x40000000,  /x/g , [1],  /x/g ,  /x/g , 0x40000000, 0x40000000, 0x40000000, [1], 0x40000000, 0x40000000, -Infinity,  /x/g ,  /x/g , [1], -Infinity,  /x/g , [1],  /x/g , [1],  /x/g , [1], [1], -Infinity, [1], -Infinity, [1], [1], [1],  /x/g ]); ");
/*fuzzSeed-116170070*/count=442; tryItOut("a0 = Array.prototype.slice.apply(a1, [NaN, 5, b0]);");
/*fuzzSeed-116170070*/count=443; tryItOut("Array.prototype.splice.call(a1, 0, ({valueOf: function() { with({y: +\"\\u1077\".eval(\"/* no regression tests found */\")}){f0 + '';/*RXUB*/var r = r2; var s = this.s0; print(uneval(r.exec(s)));  }return 11; }}), b1);");
/*fuzzSeed-116170070*/count=444; tryItOut("t0.set(a0, Math.cosh(-19));");
/*fuzzSeed-116170070*/count=445; tryItOut("let (x = (Math.acos(\"\\u2356\")), x, z, x = ( /* Comment */this), NaN = (4277)) { m0 = new Map; }");
/*fuzzSeed-116170070*/count=446; tryItOut("(let (x = NaN) (window.valueOf(\"number\").yoyo(x)) += (new (/(?=\\f)|\\B/i)(x)));");
/*fuzzSeed-116170070*/count=447; tryItOut("mathy4 = (function(x, y) { return (( ~ (Math.max(((( ! y) | 0) >>> 0), ((Math.imul(((y | 0) | (x | 0)), ( + ( + ( + Math.max(0x080000001, -0x100000000))))) | 0) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-(2**53-2), 1/0, -Number.MAX_VALUE, 0/0, -1/0, Number.MAX_VALUE, -0x07fffffff, 2**53, 2**53-2, 0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 1, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, -0x100000000, 0x07fffffff, 0x100000001, -0x0ffffffff, 0x080000000, Math.PI, 0x100000000, -0x100000001, -(2**53), 2**53+2, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, 1.7976931348623157e308, 42, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-116170070*/count=448; tryItOut("\"use asm\"; for (var v of p1) { try { h2.get = f1; } catch(e0) { } m0.has(g0); }");
/*fuzzSeed-116170070*/count=449; tryItOut("testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, 0x080000001, -0x0ffffffff, Number.MAX_VALUE, 2**53, 2**53+2, 1.7976931348623157e308, -(2**53+2), 0, -Number.MAX_VALUE, 0x100000001, 0/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 1, 42, 1/0, -0x080000000, 0x0ffffffff, -(2**53), 0x100000000, 2**53-2, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -(2**53-2), -0x07fffffff, Math.PI, 0x07fffffff, -Number.MIN_VALUE, -0x100000001]); ");
/*fuzzSeed-116170070*/count=450; tryItOut("\"use strict\"; (void schedulegc(o2.g0));");
/*fuzzSeed-116170070*/count=451; tryItOut("{ void 0; disableSPSProfiling(); }");
/*fuzzSeed-116170070*/count=452; tryItOut("a0.push(e2, p2, i2, t0);");
/*fuzzSeed-116170070*/count=453; tryItOut("\"use strict\"; f1 + this.o1;");
/*fuzzSeed-116170070*/count=454; tryItOut("mathy3 = (function(x, y) { return (Math.max((( - Math.fround(x)) >>> 0), ( + Math.imul(Math.fround(mathy2(Math.fround(( ~ (Math.clz32(Math.fround(x)) | 0))), Math.fround(((mathy1(y, (-0x0ffffffff | 0)) / Math.PI) >>> 0)))), Math.fround(Math.fround(Math.asin(x)))))) << (mathy0((mathy0(( + (y + ((Math.min(42, (x >>> 0)) ^ (Math.hypot(2**53+2, y) >>> 0)) | 0))), -0x080000000) >>> 0), (( + ( + (((x | 0) - y) >>> 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[new String(''), new String(''), new String(''), function(){}, new String(''), function(){}, new String(''), new String(''), new String(''), new String(''), function(){}, function(){}, new String(''), new String(''), function(){}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), function(){}, new String(''), function(){}, new String(''), function(){}, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-116170070*/count=455; tryItOut("/*tLoop*/for (let d of /*MARR*/[(0/0), 0x080000001, (0/0), ({}), new Number(1.5)]) { print(x); }");
/*fuzzSeed-116170070*/count=456; tryItOut("Object.defineProperty(this, \"this.v0\", { configurable: x = eval(\"a0.toString = (function() { try { t0 = g1.t0.subarray(12); } catch(e0) { } try { h1.fix = (function() { for (var j=0;j<73;++j) { f2(j%2==1); } }); } catch(e1) { } for (var v of m0) { try { Object.defineProperty(g2.o1, \\\"v0\\\", { configurable: true, enumerable: false,  get: function() {  return g1.eval(\\\"print(uneval(o0));\\\"); } }); } catch(e0) { } try { g0.v2 = t2.byteLength; } catch(e1) { } try { m1 + o2; } catch(e2) { } o2 + ''; } return v1; });\"), enumerable:  '' ,  get: function() {  return evaluate(\"let (d = /*UUV1*/(x.getUint16 = runOffThreadScript)) allocationMarker()\", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: ([let (d) length.__defineSetter__(\"a\", (function(x, y) { return (Math.log2(Math.hypot((x >>> 0), x)) >>> 0); }))]), catchTermination: (x % 22 != 3) })); } });");
/*fuzzSeed-116170070*/count=457; tryItOut("\"use strict\"; v1.__proto__ = p0;");
/*fuzzSeed-116170070*/count=458; tryItOut("Array.prototype.sort.apply(a0, []);");
/*fuzzSeed-116170070*/count=459; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.abs(Math.fround(( - (Math.fround(Math.max(Math.fround(Math.atan2((x >>> 0), Math.hypot(x, x))), Math.fround((Math.imul((0x080000000 | 0), (Math.atanh(x) | 0)) | 0)))) >>> 0)))); }); testMathyFunction(mathy5, [0x07fffffff, -(2**53+2), 1.7976931348623157e308, 2**53-2, 42, 1/0, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, -0, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -0x100000000, -0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, 0x080000001, 0x080000000, -0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, 2**53, 0x100000000, 0, Math.PI, -(2**53-2)]); ");
/*fuzzSeed-116170070*/count=460; tryItOut("M:for(var y in ((function shapeyConstructor(boudnu){if (d) { v0 = g1.objectEmulatingUndefined(); } return this; })((p={}, (p.z = -15)())))){print(/\\B[^\\0]?(?=\\w)|[^]|\\3/gym);Array.prototype.unshift.call(a0, s2, o2.o0.m0, this.f0, v2,  /x/ , b1); }");
/*fuzzSeed-116170070*/count=461; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"($[^]|[\\\\u0009\\\\x04-\\\\f\\\\W\\u00b4]\\\\w\\\\u0056{1,}*?|(?=\\udced)*|[]\\\\b.{3,}{2,4}|([^\\\\s\\\\S])?|[\\\\s]*)\\\\s\", \"yi\"); var s = \"_\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-116170070*/count=462; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.fround(Math.fround(Math.atan2(Math.fround(Math.tanh(y)), Math.fround(mathy3(( + Math.expm1(( + x))), -0x080000000))))) | Math.acos(( ! ( + y)))) - (Math.sqrt((Math.fround(0x080000001) ** Math.round(x))) >>> 0)); }); ");
/*fuzzSeed-116170070*/count=463; tryItOut("e0.has(v0);");
/*fuzzSeed-116170070*/count=464; tryItOut("i0.send(i0);");
/*fuzzSeed-116170070*/count=465; tryItOut("Array.prototype.forEach.apply(a0, [(function mcc_() { var qhjfio = 0; return function() { ++qhjfio; f2(/*ICCD*/qhjfio % 7 != 6);};})(), s0]);");
/*fuzzSeed-116170070*/count=466; tryItOut("\"use strict\"; m0.delete(v2);/*MXX3*/g0.Uint8Array.name = g0.Uint8Array.name;");
/*fuzzSeed-116170070*/count=467; tryItOut("testMathyFunction(mathy5, [-0x080000000, 0x07fffffff, 1/0, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, 2**53+2, -1/0, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, 1.7976931348623157e308, 0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0, -(2**53-2), -0x080000001, 0x080000001, Number.MAX_VALUE, -(2**53), 0/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53, 42, -Number.MIN_VALUE, 0x100000000, -0x100000000, 2**53-2, -0]); ");
/*fuzzSeed-116170070*/count=468; tryItOut("intern([3]).watch(\"constructor\", x);");
/*fuzzSeed-116170070*/count=469; tryItOut("\"use strict\"; a0.sort((function() { for (var j=0;j<1;++j) { f1(j%4==0); } }));");
/*fuzzSeed-116170070*/count=470; tryItOut("\"use strict\"; e2.delete(i1);");
/*fuzzSeed-116170070*/count=471; tryItOut("a1 = a1.map((function(j) { if (j) { try { a1[v1] = [] = this; } catch(e0) { } try { g1.s1 += s2; } catch(e1) { } try { for (var v of h0) { try { v0 = Object.prototype.isPrototypeOf.call(v2, h1); } catch(e0) { } t1[0] = o2.g0.h1; } } catch(e2) { } g2.v2 = (m0 instanceof a2); } else { try { Array.prototype.unshift.apply(a1, [o2.p2, ( \"\" .valueOf(\"number\")) > new ( \"\" .forEach)(this, 24)]); } catch(e0) { } this.e0.add(e2); } }));");
/*fuzzSeed-116170070*/count=472; tryItOut("\"use asm\"; s1 += s1;");
/*fuzzSeed-116170070*/count=473; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = (((0x52ecd41)) ? (d0) : (d0));\n    }\n    /*FFI*/ff();\n    return +((+abs(((((+/*FFI*/ff())) * ((+(-1.0/0.0))))))));\n    d1 = (-8388607.0);\n    d0 = (d1);\n    d1 = (+pow(((+((d0)))), ((d1))));\n    (Uint32ArrayView[((Uint32ArrayView[1])) >> 2]) = ((0xfa892d98));\n    d1 = (NaN);\n    d0 = (d1);\n    return +(((((d0)) % ((+(-0x8000000)))) + (d1)));\n  }\n  return f; })(this, {ff: function(y) { yield y; s0 += s2;; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, Math.PI, Number.MAX_VALUE, -(2**53+2), -0x07fffffff, 0x07fffffff, 0x100000000, -Number.MAX_VALUE, -0x100000001, 0x100000001, -0, 0x080000001, 42, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53-2), 0, 2**53, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, 0/0, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=474; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (( + Math.imul(( + Math.log10((( - ( - (Math.min(y, x) >>> 0))) ^ ( ~ ( + mathy0(x, y)))))), Math.trunc((( + ( - (((Math.max(x, 0.000000000000001) >>> 0) % (x >>> 0)) >>> 0))) * (Math.log10(x) | 0))))) % ( + (((( + Math.acosh(( + (( - ( + ( ! (x >>> 0)))) + (2**53-2 | 0))))) | 0) * ((Math.min(Math.imul(Math.atan2((y << (Math.max((x >>> 0), (y >>> 0)) >>> 0)), y), Math.fround(Math.log(Math.fround((( + (Math.fround((y , Math.fround(y))) >>> 0)) >>> 0))))), ((Math.acosh(x) | 0) >>> 0)) >>> 0) | 0)) | 0)))); }); ");
/*fuzzSeed-116170070*/count=475; tryItOut("/*RXUB*/var r = /\\S/y; var s = \"a\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=476; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=477; tryItOut("\"use strict\"; g1 + f2;");
/*fuzzSeed-116170070*/count=478; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=479; tryItOut("\"use strict\"; v0 = t0.length;");
/*fuzzSeed-116170070*/count=480; tryItOut("/*RXUB*/var r = /\\1(?=(?!\\D[^](?!\\B|^\\b)|$\\3\\3+?(?:^|\\cC)|${2}))/gm; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=481; tryItOut("\"use strict\"; v1 + e2;");
/*fuzzSeed-116170070*/count=482; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ! ((((y && Math.fround(( + Math.fround(Math.log(-1/0))))) <= Math.acosh(Math.log((y != y)))) | 0) <= (( + (( + ( - ((( ~ ((( - ( + x)) >>> 0) | 0)) | 0) | 0))) !== x)) >>> 0))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, 0x100000001, 0/0, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, 1/0, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, 0, -(2**53+2), Number.MAX_VALUE, 2**53, 0x080000000, 0x100000000, 0x07fffffff, Math.PI, -0, -0x0ffffffff, -(2**53), 1, 0x080000001, -0x100000000, -0x07fffffff, 42, -0x080000001]); ");
/*fuzzSeed-116170070*/count=483; tryItOut("mathy5 = (function(x, y) { return (mathy1(mathy1(Math.fround(Math.atan2(x, Math.fround(y))), Math.cosh(0x080000001)), ( + Math.trunc((Math.tan(Math.imul(-0x100000000, ( + Math.log10(( + y))))) | 0)))) | 0); }); testMathyFunction(mathy5, [0.000000000000001, Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, 1, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53-2, 0, 0x080000001, -(2**53), 2**53+2, -0x100000000, Number.MAX_VALUE, 0x0ffffffff, -0, 42, -0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 0x07fffffff, -(2**53+2), 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, 0x100000000, -Number.MAX_VALUE, 0x100000001, 2**53, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-116170070*/count=484; tryItOut("v1 = g0.eval(\"((4277).w)\");");
/*fuzzSeed-116170070*/count=485; tryItOut("\nf2.valueOf = arguments.callee.caller.caller.caller;\n\u0009");
/*fuzzSeed-116170070*/count=486; tryItOut("\"use strict\"; /*RXUB*/var r = Math.hypot(-0, d); var s = \"_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n0\\na\\u2418a\\u2418a\\u2418a\\u2418a\\u2418a\\u2418_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n0\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na\\n\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na0\\na\\u2418a\\u2418a\\u2418a\\u2418a\\u2418a\\u2418\\n\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\n\\uffe0\\na\\udced\\udced\\udced\\udced\\udced\\udced\\udced\\udced\\udced\\udced\\udced\\u20bf\\udced\\udced\\udced\\u0013 \\u00ac\\u00dd\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n0\\na\\u2418a\\u2418a\\u2418a\\u2418a\\u2418a\\u2418_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n0\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n_\\n\"; print(r.test(s)); ");
/*fuzzSeed-116170070*/count=487; tryItOut("\"use strict\"; {window.name;L: print(x); }");
/*fuzzSeed-116170070*/count=488; tryItOut("");
/*fuzzSeed-116170070*/count=489; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116170070*/count=490; tryItOut("x, c = x, x, e = (makeFinalizeObserver('tenured')), c = ((( \"\" .entries).apply).call(x, )), e = /*MARR*/[ /x/ ,  /x/ ,  /x/g , this,  /x/ , this,  '' ,  /x/g , this,  \"use strict\" ,  '' ,  '' , this, this,  /x/g ,  /x/ , this,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/ ,  \"use strict\" ,  /x/g ,  \"use strict\" , this,  /x/ ];a0[v2];\ns2 += 'x';\n");
/*fuzzSeed-116170070*/count=491; tryItOut("testMathyFunction(mathy1, /*MARR*/[(0/0)]); ");
/*fuzzSeed-116170070*/count=492; tryItOut("\"use strict\"; /*bLoop*/for (let sslwru = 0; sslwru < 129; ++sslwru) { if (sslwru % 5 == 0) { /*RXUB*/var r = new RegExp(\"\\\\d\", \"gim\"); var s = \"0\"; print(s.match(r));  } else { /*MXX1*/o2 = g2.WeakMap.prototype; }  } ");
/*fuzzSeed-116170070*/count=493; tryItOut("if(false) \u000c/*infloop*/ for (var x of undefined) \"\\uBFF5\"; else  if (let (d = null)  /x/ ) {o0.m0 = new Map(o1); }");
/*fuzzSeed-116170070*/count=494; tryItOut("/*infloop*/for(var this.zzz.zzz in x) {s1 += g0.s1;s2 += o0.s0; }");
/*fuzzSeed-116170070*/count=495; tryItOut("window.lineNumber;");
/*fuzzSeed-116170070*/count=496; tryItOut("\"use strict\"; Array.prototype.sort.apply(a0, [(function() { for (var j=0;j<51;++j) { f0(j%2==1); } })]);");
/*fuzzSeed-116170070*/count=497; tryItOut("s1 += 'x';");
/*fuzzSeed-116170070*/count=498; tryItOut("\"use strict\"; yield x;yield /*RXUE*//(?=(?!\\1)|[\\d\\b]*?\\D.+?|(\\d?)|\\cQ*+)/i.exec(\"\");");
/*fuzzSeed-116170070*/count=499; tryItOut("m1.valueOf = (function(j) { if (j) { /*MXX1*/o1 = g1.Float64Array.prototype.BYTES_PER_ELEMENT; } else { Object.seal(g0); } });");
/*fuzzSeed-116170070*/count=500; tryItOut("M:switch((makeFinalizeObserver('nursery'))) { case new RegExp(\"\\\\r|((?:\\\\d){2,})*?|(?=(\\\\1{33554433,33554435}\\\\s))\", \"yim\"): v1 + '';case 6: for (var v of h1) { try { Object.freeze(g2.o1.g0); } catch(e0) { } try { v0.__proto__ = v2; } catch(e1) { } f0(o0.m0); }String.prototype.blinkfunction x() { return (uneval(window)) } /*tLoop*/for (let e of /*MARR*/[-Number.MIN_SAFE_INTEGER, (void 0), -Number.MIN_SAFE_INTEGER, (void 0), (void 0), (void 0), -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), -0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, (void 0), (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (void 0), (void 0), -Number.MIN_SAFE_INTEGER, (void 0), -Number.MIN_SAFE_INTEGER, (void 0), -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, (void 0), (void 0), (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, (void 0), -0x100000000, -Number.MIN_SAFE_INTEGER, (void 0), -0x100000000, -0x100000000, -0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000000, -0x100000000, (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (void 0), (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (void 0), (void 0), (void 0), -Number.MIN_SAFE_INTEGER, -0x100000000, (void 0), (void 0), (void 0), (void 0), -0x100000000, (void 0), -0x100000000, -0x100000000, (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000000, -0x100000000, (void 0), (void 0), -0x100000000, -0x100000000, (void 0), (void 0), -0x100000000, (void 0), (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (void 0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (void 0), -0x100000000, -0x100000000, -0x100000000, -0x100000000, (void 0), -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, (void 0), -0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, (void 0), (void 0), -0x100000000, -Number.MIN_SAFE_INTEGER, (void 0), -0x100000000, -0x100000000, (void 0), (void 0), -0x100000000, -0x100000000, (void 0), (void 0), (void 0), (void 0), -0x100000000, (void 0), (void 0), (void 0), -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000000, -0x100000000]) { return \"\\uFB58\"; }break; case 3: break;  }");
/*fuzzSeed-116170070*/count=501; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((( - Math.fround(((Math.max((Math.fround(((0x100000000 | 0) ^ (((x && y) >>> 0) | 0))) === Math.pow(0x080000001, (1/0 | 0))), (x | 0)) , (Math.pow((( - x) >>> 0), (Math.sign(((Math.fround(Math.log10(y)) === 0.000000000000001) >>> 0)) >>> 0)) >>> 0)) | 0))) | 0) ? Math.acos(mathy3(((((( ~ (y >>> 0)) | 0) | (Math.max(Math.tan(y), 0x100000001) | 0)) | 0) | 0), (mathy0(Math.fround(( ! (y || y))), Number.MIN_VALUE) | 0))) : (Math.sign(( + (Math.imul(Math.fround(Math.min((x ** y), (y == ( + (0x100000001 && mathy1(Math.fround(x), Math.fround(y))))))), Math.fround(mathy3(-0, (((((Math.max(( + y), (x >>> 0)) >>> 0) | 0) === (( - y) | 0)) | 0) , x)))) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-116170070*/count=502; tryItOut("mathy4 = (function(x, y) { return (( + ( + (( + x) >> ( + y)))) + Math.cos((((( ~ (Math.min(0x080000000, x) | 0)) | 0) || (x | 0)) | 0))); }); testMathyFunction(mathy4, [1.7976931348623157e308, Number.MIN_VALUE, 0/0, 42, 0x080000000, 0x100000000, -0x100000001, 0.000000000000001, -0x080000001, -Number.MAX_VALUE, -(2**53+2), Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 2**53-2, 0, -Number.MIN_VALUE, 2**53, 0x07fffffff, -0x100000000, 0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, -(2**53), 1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=503; tryItOut("testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, 0x100000001, -0x100000000, -0x100000001, 1.7976931348623157e308, 0x100000000, Math.PI, Number.MIN_VALUE, -(2**53-2), 2**53+2, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -0x080000001, -(2**53), 0/0, 42, -1/0, 0, 0.000000000000001, -Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, -(2**53+2), -0x0ffffffff, -0x080000000, 2**53, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-116170070*/count=504; tryItOut("m0.set(g1.t2, g0.a0);");
/*fuzzSeed-116170070*/count=505; tryItOut("\"use strict\"; if(true) { if (function ([y]) { }) {for (var v of s0) { f2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-((-6.189700196426902e+26))));\n  }\n  return f; })(this, {ff: (function(x, y) { return x; })}, new SharedArrayBuffer(4096)); }v2 = g2.g2.runOffThreadScript(); } else {{}\ncontinue ;\ni0.next(); }}");
/*fuzzSeed-116170070*/count=506; tryItOut("\"use strict\"; o1 + o2;");
/*fuzzSeed-116170070*/count=507; tryItOut("if(6) { if (/(?=\\3*)($)|.|[^]|\\1\\B+|\\S|\\n{0,2}(?!(?=(.)?)*?)/gim) f2 = String.prototype.valueOf; else throw function(id) { return id };}");
/*fuzzSeed-116170070*/count=508; tryItOut("var ottdtc = new SharedArrayBuffer(16); var ottdtc_0 = new Float64Array(ottdtc); ottdtc_0[0] = -23; var ottdtc_1 = new Uint8ClampedArray(ottdtc); print(ottdtc_1[0]); ottdtc_1[0] = -917612931; var ottdtc_2 = new Uint16Array(ottdtc); ottdtc_2[0] = 2; var ottdtc_3 = new Float64Array(ottdtc); print(ottdtc_3[0]); ottdtc_3[0] = 7; var ottdtc_4 = new Uint32Array(ottdtc); print(ottdtc_4[0]); ottdtc_4[0] = 13; var ottdtc_5 = new Int32Array(ottdtc); print(ottdtc_5[0]); var ottdtc_6 = new Int16Array(ottdtc); var ottdtc_7 = new Int8Array(ottdtc); var ottdtc_8 = new Int32Array(ottdtc); print(ottdtc_8[0]); ottdtc_8[0] = -4194304; var ottdtc_9 = new Int8Array(ottdtc); print(ottdtc_9[0]); ottdtc_9[0] = 0; ;print(ottdtc_4[5]);(ottdtc_5[5]);print(g2.b0);/*ODP-1*/Object.defineProperty(e1, \"trunc\", ({configurable: false, enumerable: true}));Array.prototype.unshift.call(o2.a2, g2, this.o2.v1, c, f2);Array.prototype.reverse.apply(a2, [t0]);print(Math.sign(-3/0));g0.v0 = evaluate(\"function f0(g2.o1)  { ( /x/ ); } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-116170070*/count=509; tryItOut("\"use strict\"; this.a0.shift();");
/*fuzzSeed-116170070*/count=510; tryItOut("print(x);");
/*fuzzSeed-116170070*/count=511; tryItOut("/*RXUB*/var r = (NaN++); var s = \"_______________________a_aaaaaa______a_aaaaaa__\\n__a_aaaaaa______a_aaaaaa__\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116170070*/count=512; tryItOut("\"use strict\"; return;function x(e, ...x) { (void schedulegc(g0)); } print(16);");
/*fuzzSeed-116170070*/count=513; tryItOut("\"use strict\"; v1 = evalcx(\"function f2(g0.h2)  { yield Math.min(d = this, (x + g0.h2)) } \", g2);");
/*fuzzSeed-116170070*/count=514; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.exp((Math.hypot((Math.hypot((Math.imul(y, -Number.MIN_VALUE) >>> 0), (Math.atan((mathy0((y | 0), (0x080000000 | 0)) | 0)) >>> 0)) >>> 0), (mathy0(Math.min(0x07fffffff, x), (0x080000000 | 0)) | 0)) >>> 0)); }); ");
/*fuzzSeed-116170070*/count=515; tryItOut("\"use strict\"; a1.shift();");
/*fuzzSeed-116170070*/count=516; tryItOut("/*tLoop*/for (let a of /*MARR*/[new Number(1), -(2**53), -(2**53), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -(2**53), -(2**53), new Number(1), new Number(1), -(2**53), -(2**53), new Number(1), -(2**53), -(2**53), -(2**53), -(2**53), new Number(1), new Number(1), -(2**53), new Number(1), new Number(1), new Number(1), -(2**53), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), -(2**53), -(2**53), -(2**53), new Number(1), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), new Number(1), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -(2**53), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -(2**53), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), -(2**53), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), -(2**53), new Number(1), new Number(1), new Number(1), -(2**53), -(2**53), new Number(1), new Number(1), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), new Number(1), -(2**53), -(2**53), new Number(1), new Number(1), -(2**53), -(2**53), new Number(1), new Number(1), -(2**53), -(2**53), new Number(1), -(2**53), new Number(1), new Number(1), -(2**53), new Number(1), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1)]) { /*MXX2*/g2.TypeError.length = i2; }x = (void options('strict_mode'));");
/*fuzzSeed-116170070*/count=517; tryItOut("\"use strict\"; v2 = r2.sticky;");
/*fuzzSeed-116170070*/count=518; tryItOut("\"use strict\"; if((x % 31 != 10)) for (var p in o0.o2) { m2 + g2.f2; } else /*RXUB*/var r = window; var s = \"\\n\\u3ed01\\n\\u3ed01\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=519; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a0, 0, { configurable: (4277).window = x, enumerable: (x % 4 != 2), get: (function() { for (var j=0;j<127;++j) { g1.f0(j%5==1); } }), set: (function(j) { if (j) { try { h2.enumerate = f0; } catch(e0) { } try { /*MXX3*/this.g0.Float32Array.BYTES_PER_ELEMENT = g2.Float32Array.BYTES_PER_ELEMENT; } catch(e1) { } m1 = new WeakMap; } else { a1.length = 2; } }) });");
/*fuzzSeed-116170070*/count=520; tryItOut("this.v0 = a2.length;");
/*fuzzSeed-116170070*/count=521; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.hypot(((((Math.hypot(x, Math.fround(y)) ? ((Math.log10((Math.exp(x) | 0)) | 0) >>> 0) : (((y <= (( ~ Math.fround(( ! Math.fround(y)))) >>> 0)) >>> 0) >>> 0)) >>> 0) >= ( + Math.log1p(( ~ -Number.MAX_SAFE_INTEGER)))) >>> 0), ( ! (( + Math.max((mathy3(y, 2**53+2) >>> 0), ( ! x))) != 0))); }); testMathyFunction(mathy4, [0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, -1/0, -(2**53+2), 0x07fffffff, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, -0, 0x080000000, 0/0, 0, 0.000000000000001, 0x0ffffffff, -(2**53-2), -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, 42, Number.MAX_VALUE, Math.PI, 0x100000001, 0x100000000, 1/0, -0x080000001, Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=522; tryItOut("\"use strict\"; { void 0; void schedulegc(149); } g1.b2.valueOf = (function() { try { h1.enumerate = f1; } catch(e0) { } const v1 = new Number(4.2); return h1; });");
/*fuzzSeed-116170070*/count=523; tryItOut("testMathyFunction(mathy2, [-(2**53+2), 1/0, -(2**53), Number.MIN_VALUE, 2**53+2, -0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 2**53, -0x080000001, -0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 0x100000001, 0x07fffffff, 0x080000000, -1/0, 0x0ffffffff, 2**53-2, -0x080000000, 0x100000000, 1, Math.PI, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, 0x080000001, -(2**53-2), 0/0, 0]); ");
/*fuzzSeed-116170070*/count=524; tryItOut("Array.prototype.shift.apply(a0, [h1, e1, b2, t0, o1, h1, h2]);");
/*fuzzSeed-116170070*/count=525; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n/* no regression tests found */\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (( '' .yoyo([1,,])));\n    i0 = ((abs((~((i0)-((Float64ArrayView[(((~((0xd22c1433))))+(i0)) >> 3])))))|0) < (((0x979a470)+(i0)) << (((-129.0) > (+abs(((Float64ArrayView[1]))))))));\n    return (((i1)+(!(i1))))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 2**53-2, -0, -0x07fffffff, 0x100000001, 0x080000000, -0x080000001, -0x100000000, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, 0, Math.PI, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, 2**53, -0x100000001, 1, Number.MIN_VALUE, 0x080000001, -(2**53), -0x0ffffffff, 2**53+2, -1/0, Number.MIN_SAFE_INTEGER, 42, -(2**53+2), 0/0, 1/0, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=526; tryItOut("/*tLoop*/for (let b of /*MARR*/[-0x07fffffff, -0x07fffffff, undefined, undefined, undefined, true, undefined, undefined, undefined, undefined, -0x07fffffff, true, -0x07fffffff, undefined, undefined, -0x07fffffff, -0x07fffffff, true, -0x07fffffff, undefined, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, true, true, -0x07fffffff, -0x07fffffff, -0x07fffffff]) { g2.a2.push((let (z = null)  /x/ ));\nFunction();\n }");
/*fuzzSeed-116170070*/count=527; tryItOut("t2.set(t0, 10);");
/*fuzzSeed-116170070*/count=528; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy0((((Math.atan2((( + (( + Math.hypot(-Number.MIN_VALUE, x)) !== ( + x))) >>> 0), ((((Math.asin(x) >>> 0) + (Math.min(x, Math.acos(-0x07fffffff)) | 0)) | 0) | 0)) >>> 0) >>> 0) >= ((x ^ (( + y) | 0)) | 0)), mathy0(Math.fround(Math.asinh(Math.fround(y))), ( + Math.hypot(((( ! x) >>> 0) >>> 0), (-0x080000001 - ( + (( + mathy1(( + y), ( + y))) == y))))))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), '', -0, null, true, (new Number(0)), objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), false, '0', 0.1, (function(){return 0;}), /0/, (new Number(-0)), 1, [0], (new Boolean(true)), [], NaN, ({valueOf:function(){return 0;}}), (new String('')), '\\0', (new Boolean(false)), 0, '/0/', undefined]); ");
/*fuzzSeed-116170070*/count=529; tryItOut("\"use strict\"; /*oLoop*/for (kwvbsn = 0; kwvbsn < 94; ++kwvbsn) { v2 = Object.prototype.isPrototypeOf.call(v2, g2); } ");
/*fuzzSeed-116170070*/count=530; tryItOut("/*tLoop*/for (let c of /*MARR*/[[(void 0)], 0x080000001, 0x080000001, function(){}, 0x080000001, 0x080000001, function(){}, 0x080000001, function(){}, 0x080000001, function(){}, 0x080000001, function(){}, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], 0x080000001, function(){}, [(void 0)], function(){}, [(void 0)], [(void 0)], [(void 0)], function(){}, 0x080000001, function(){}, function(){}, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, function(){}, [(void 0)], [(void 0)], [(void 0)], 0x080000001, 0x080000001, 0x080000001, function(){}, 0x080000001, [(void 0)], function(){}, function(){}, 0x080000001, function(){}, 0x080000001, 0x080000001, function(){}, 0x080000001, [(void 0)], function(){}, 0x080000001, 0x080000001, [(void 0)], [(void 0)], function(){}, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], function(){}, 0x080000001, function(){}, [(void 0)], 0x080000001, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], function(){}, function(){}, [(void 0)], 0x080000001, [(void 0)], 0x080000001, 0x080000001, function(){}, 0x080000001, [(void 0)], [(void 0)], [(void 0)], function(){}, [(void 0)], [(void 0)], [(void 0)], function(){}, function(){}, [(void 0)], function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x080000001, [(void 0)], 0x080000001, 0x080000001, [(void 0)], [(void 0)], 0x080000001, 0x080000001, [(void 0)], 0x080000001, [(void 0)], 0x080000001, 0x080000001, 0x080000001, function(){}, [(void 0)], 0x080000001, [(void 0)], 0x080000001, function(){}, 0x080000001, function(){}, function(){}, function(){}]) { /*bLoop*/for (let qxlcec = 0; qxlcec < 2; ++qxlcec) { if (qxlcec % 6 == 4) { break ; } else { for (var v of t0) { i1.next(); } }  }  }");
/*fuzzSeed-116170070*/count=531; tryItOut("/*oLoop*/for (var abjirr = 0; abjirr < 35; ++abjirr) { [1,,]; } function x(x) { yield x } m2.set(h0, p2);");
/*fuzzSeed-116170070*/count=532; tryItOut("\"use strict\"; i0 = new Iterator(g1.v0);");
/*fuzzSeed-116170070*/count=533; tryItOut("((4277));");
/*fuzzSeed-116170070*/count=534; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: false, enumerable: mathy3(),  get: function() {  return t2.byteLength; } });");
/*fuzzSeed-116170070*/count=535; tryItOut("\"use strict\"; /*vLoop*/for (let yzncrv = 0; yzncrv < 57; ++yzncrv) { var e = yzncrv; /*tLoop*/for (let z of /*MARR*/[ /x/g , new Number(1), new Number(1),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Number(1),  /x/g ,  /x/g , new Number(1), new Number(1),  /x/g , new Number(1),  /x/g ,  /x/g ]) { t1[14]; } } ");
/*fuzzSeed-116170070*/count=536; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.asinh((Math.fround((Math.fround(( - ( + ((( + ( + y)) >>> 0) ? x : ( + 2**53+2))))) ? Math.fround(Math.asinh(( + (y >>> 0)))) : Math.fround(Math.sign((((Math.tanh(x) >>> 0) ** (y >>> 0)) >>> 0))))) / Math.max(( + ( ~ ( + ( + Math.round((Number.MAX_VALUE | 0)))))), Math.hypot(y, y)))); }); ");
/*fuzzSeed-116170070*/count=537; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return Math.tan(((Math.fround((( ~ Number.MAX_VALUE) >>> 0)) ? Math.fround((Math.min(( + Math.hypot(( + ( + Math.cosh(((y ? ( + x) : y) | 0)))), Math.imul((x | 0), ((y , y) | 0)))), y) == Math.clz32(mathy0((Math.acos((0x100000000 | 0)) | 0), -0x07fffffff)))) : ((y | 0) << Math.log(( ! -0x100000001)))) >>> 0)); }); testMathyFunction(mathy2, [-(2**53+2), 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 1/0, 0x100000000, Number.MAX_VALUE, 2**53-2, 0x07fffffff, -Number.MIN_VALUE, -0x100000001, -0, -(2**53), -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, -(2**53-2), 0x100000001, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 42, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, 2**53+2, 0.000000000000001, 1, -0x100000000, -0x080000001]); ");
/*fuzzSeed-116170070*/count=538; tryItOut("mathy2 = (function(x, y) { return ( + Math.atan2(Math.fround(( - ( + (Math.fround((Math.cbrt(Math.fround(Math.min(Math.fround(x), Math.fround(y)))) | 0)) , ( + ((Math.fround(mathy0(( + 0x080000000), (x >>> 0))) >>> 0) == 0x100000001)))))), Math.fround((( + Math.log1p((y , (-Number.MAX_VALUE | 0)))) / (Math.hypot(y, Math.log2(Math.asinh((( + (0x080000001 >>> 0)) >>> 0)))) | 0))))); }); ");
/*fuzzSeed-116170070*/count=539; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, 2**53+2, -Number.MIN_VALUE, 0, 1.7976931348623157e308, -0x0ffffffff, -0x080000001, Number.MIN_VALUE, -0x080000000, -0x07fffffff, 1, 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -0x100000001, 42, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0, 1/0, -(2**53+2), -(2**53), Math.PI, 2**53, 0/0, -(2**53-2), 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=540; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return Math.fround(( ! Math.fround(Math.expm1(( + Math.log(( + mathy1(Math.max(mathy3(( + y), x), y), y)))))))); }); testMathyFunction(mathy5, [0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, Math.PI, 2**53, 0.000000000000001, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000000, -0, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, -(2**53-2), -(2**53), -Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -0x07fffffff, 0x0ffffffff, 0, 1.7976931348623157e308, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -(2**53+2), 0x100000001, 42, 0x080000001, 0x080000000, 2**53-2, -1/0]); ");
/*fuzzSeed-116170070*/count=541; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.min(( - (( + ( ~ (Math.pow(Math.fround((Math.fround(1.7976931348623157e308) >> Math.fround(x))), Math.fround(Math.max(( + (-Number.MAX_SAFE_INTEGER >>> 0)), ( + Math.atan(Math.fround(0x07fffffff)))))) | 0))) >>> 0)), ((Math.log2(Math.min(Math.PI, (mathy2(y, x) | 0))) >>> 0) < ( + (Math.fround(Math.ceil(x)) ** (Math.fround(Math.hypot(Math.fround(Math.pow(y, x)), Math.fround(x))) | 0))))); }); testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-116170070*/count=542; tryItOut("(void schedulegc(g0));\nObject.defineProperty(this, \"v2\", { configurable: (x % 19 != 5), enumerable: (x % 4 != 0),  get: function() {  return evaluate(\"function f2(a2) \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    i0 = ((d1) >= (-2251799813685249.0));\\n    {\\n      {\\n        d1 = (d1);\\n      }\\n    }\\n    (Uint16ArrayView[((0x1a913725) / ((((0xde1c2cde))*-0x75a6b)>>>((i2)-(0xfd258d6b)))) >> 1]) = ((0xffffffff) % (((i2))>>>(-(i0))));\\n    d1 = (d1);\\n    d1 = (1.0);\\n    d1 = (9.44473296573929e+21);\\n    switch (((((-0x1155453) ? (0x48c5f079) : (0xc907cd30))) >> ((0xffffffff) / (0x57f41f5a)))) {\\n      case -3:\\n        d1 = (1.0);\\n        break;\\n      case 1:\\n        (Float32ArrayView[((0xfa5dc4f7)-(i2)) >> 2]) = ((+(0.0/0.0)));\\n        break;\\n      case 1:\\n        {\\n          d1 = ((((0x9938aac5)) ^ (((((i0))>>>((0xffffffff))) < (0x88f1ef63)))));\\n        }\\n        break;\\n      case -3:\\n        return +((x , (4277)));\\n        break;\\n      default:\\n        (Int16ArrayView[((0xff2d9b42)) >> 1]) = ((1));\\n    }\\n    i2 = ((((((0x48a11407)-(1)-(0xf9a9bc9e))>>>((0x57a98171)+(i0)+(i0))) / ((((uneval(/*FARR*/[,  /x/g ].sort(TypeError)))) % ((allocationMarker())))>>>(((d1) > (((1.5111572745182865e+23)) % ((-9.0)))))))>>>((~((((0x10ab8e0a))>>>((0xd6560c96))) / (((0x6e45eccd))>>>((0xf877f9f7))))) % (((0xc3b98efd) / (((0xf3c99846))>>>((0xe3d3cd4b))))|0))));\\n    {\\n      d1 = (2305843009213694000.0);\\n    }\\n    i2 = (!((Infinity) > (+((d1)))));\\n    (Float32ArrayView[((i0)-(i0)) >> 2]) = ((+(0x4fec7e70)));\\n    {\\n      d1 = (-4503599627370495.0);\\n    }\\n    return +((+(0.0/0.0)));\\n  }\\n  return f;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (this)(), noScriptRval: false, sourceIsLazy: false, catchTermination: \"\\uD873\" in 6 })); } });\n");
/*fuzzSeed-116170070*/count=543; tryItOut("\"use strict\"; e2.add(e2);");
/*fuzzSeed-116170070*/count=544; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=545; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53+2), 0x100000000, 2**53, 0x100000001, 0x080000000, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000001, 0x07fffffff, -(2**53-2), 0/0, 0, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, -0x080000000, 1/0, -0x07fffffff, 42, -1/0, -0, -0x100000001]); ");
/*fuzzSeed-116170070*/count=546; tryItOut("testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, -(2**53-2), -(2**53), -0x100000000, 0, -0x080000000, 2**53+2, 0.000000000000001, 1, Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, -0x07fffffff, 1/0, 0x100000000, 0x07fffffff, -0x100000001, 2**53, 42, 2**53-2, 0/0, Math.PI, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, -(2**53+2), -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=547; tryItOut("mathy3 = (function(x, y) { return (Math.sinh(( + Math.pow((( - (-Number.MAX_SAFE_INTEGER >>> 0)) << (x + ( - Math.fround(((x >= (x | 0)) | 0))))), (( ~ ( + Math.imul(((y ^ y) , (Math.sqrt((y >>> 0)) >>> 0)), (mathy1(x, (y >>> 0)) >>> 0)))) | 0)))) >>> 0); }); ");
/*fuzzSeed-116170070*/count=548; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.pow(Math.sin(Math.fround((Math.fround(Math.tan(Math.fround(( ~ Number.MIN_VALUE)))) == Math.fround(x)))), Math.log1p(Math.fround(((x >>> 0) << (( ! ( + Math.asin((Math.fround(y) >> x)))) >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[arguments.callee, arguments.callee]); ");
/*fuzzSeed-116170070*/count=549; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=550; tryItOut("\"use strict\"; v0 = (m2 instanceof b1);");
/*fuzzSeed-116170070*/count=551; tryItOut("\"use strict\"; e0.has(this.v2);");
/*fuzzSeed-116170070*/count=552; tryItOut("f2 = (function() { v1 = t2.length; return h0; });");
/*fuzzSeed-116170070*/count=553; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"(?=3*?[^\\\\u9754\\\\n]|\\\\\\u5f73{0}|\\\\2?^(?:\\\\1))(?=(?=(?:\\u87bc[^\\\\W\\\\d])(\\\\B+).*(?:[\\u00f4-u\\\\u3871-\\ub4b3+])(^|\\\\B|[^\\\\uF2cf\\\\D\\u756a\\\\w]|.){1}))\", \"gy\"); var s = \"\\u0084\\u0084S\\n\\u87bc\\u70bb\\n\\u87bc\\u70bb\\n\\u87bc\\u70bb\\n\\u87bc\\u70bb\\n\\u87bc\\u70bb\\n\\u0014\\n\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=554; tryItOut("g0.a2.shift();");
/*fuzzSeed-116170070*/count=555; tryItOut("\"use strict\"; a0.pop(f2, o1, p2);");
/*fuzzSeed-116170070*/count=556; tryItOut("/*tLoop*/for (let w of /*MARR*/[(yield  /x/ ).unwatch(\"valueOf\"), [undefined], new Number(1), new Number(1), (yield  /x/ ).unwatch(\"valueOf\"), new Number(1), (yield  /x/ ).unwatch(\"valueOf\"), (yield  /x/ ).unwatch(\"valueOf\"), [undefined], [undefined], new Number(1), new Number(1), [undefined], new Number(1), new Number(1), [undefined], (yield  /x/ ).unwatch(\"valueOf\"), new Number(1), [undefined], (yield  /x/ ).unwatch(\"valueOf\"), (yield  /x/ ).unwatch(\"valueOf\"), new Number(1), [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], new Number(1), [undefined], new Number(1), new Number(1), (yield  /x/ ).unwatch(\"valueOf\"), new Number(1), [undefined], new Number(1), new Number(1), [undefined], [undefined]]) { selectforgc(this.o0); }");
/*fuzzSeed-116170070*/count=557; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x0ffffffff, Math.PI, -(2**53-2), 0, -0x100000000, -0x080000000, 2**53, 0x100000000, Number.MAX_VALUE, 42, -1/0, 2**53+2, 0/0, -(2**53+2), -0x100000001, Number.MIN_VALUE, -0x080000001, 1/0, 0x100000001, 1, 0x07fffffff, 0x080000001, 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 2**53-2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=558; tryItOut("/*ODP-3*/Object.defineProperty(o0.g0.p1, \"toSource\", { configurable: true, enumerable: false, writable: false, value: s0 });");
/*fuzzSeed-116170070*/count=559; tryItOut("var mhgymz = new SharedArrayBuffer(6); var mhgymz_0 = new Float32Array(mhgymz); var mhgymz_1 = new Int32Array(mhgymz); print(mhgymz_1[0]); mhgymz_1[0] = -3; let y = /*bLoop*/for (var hnitgu = 0; hnitgu < 23; ++hnitgu) { if (hnitgu % 4 == 0) { ; } else { m0.has(new RegExp(\"\\\\1{2,2}|(?=$)\", \"gyi\")); }  } ;yield false;");
/*fuzzSeed-116170070*/count=560; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.log10((Math.hypot(mathy3(Math.asinh(Math.fround(( ~ (Math.min(x, ( + mathy0(( + x), ( + x)))) >>> 0)))), x), (((Math.fround((y ? y : Math.fround(Math.min(Math.fround(x), ((( + (x | 0)) | 0) >>> 0))))) < Math.fround(y)) >>> 0) * (( + ( + Math.clz32(( + x)))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [Math.PI, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -0, -0x080000001, -(2**53-2), 0x100000000, -(2**53), 0, 0x07fffffff, -0x07fffffff, 0x100000001, 2**53+2, Number.MIN_VALUE, 1, -0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, -0x080000000, -(2**53+2), 2**53, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 0x080000000, 1/0, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=561; tryItOut("/*MXX2*/g1.String.fromCharCode = o1;");
/*fuzzSeed-116170070*/count=562; tryItOut("m1.set(t1, e2);");
/*fuzzSeed-116170070*/count=563; tryItOut("\"use strict\"; testMathyFunction(mathy4, [42, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 1, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 1/0, Number.MIN_VALUE, 2**53-2, 0, -0, 0.000000000000001, 0x100000000, -0x100000001, -0x100000000, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -(2**53-2), 2**53, -1/0, Number.MAX_VALUE, -(2**53), 2**53+2, -0x080000000, 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=564; tryItOut("\"use strict\"; let(b) { return;}with({}) { let(c) { window = w;} } ");
/*fuzzSeed-116170070*/count=565; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( ! Math.fround(Math.hypot(( + ( - ( + x))), ( + (Math.fround(mathy2((Math.max(y, y) >>> 0), Math.fround((((y >>> 0) << (Math.fround(Math.atan2(1/0, Math.fround(x))) >>> 0)) >>> 0)))) > (( ! (Math.acos(y) | 0)) | 0))))))); }); testMathyFunction(mathy5, [0x100000001, 0x100000000, 0x080000000, 1/0, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, -0, Number.MAX_SAFE_INTEGER, 0, -0x080000000, 1.7976931348623157e308, 2**53+2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 42, -Number.MAX_VALUE, Math.PI, Number.MAX_VALUE, 1, -0x100000001, 0x080000001, -0x100000000, Number.MIN_VALUE, -1/0, 0x0ffffffff, -0x07fffffff, -(2**53-2), 2**53, -0x0ffffffff, 2**53-2, 0.000000000000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=566; tryItOut("/*ADP-1*/Object.defineProperty(a1, 3, ({configurable: (x % 11 != 1), enumerable: true}));");
/*fuzzSeed-116170070*/count=567; tryItOut("\"use strict\"; print(f2);");
/*fuzzSeed-116170070*/count=568; tryItOut("\"use strict\"; var NaN = Math.hypot( /x/g , \"\\u1A38\"), xbbkxk, yjvbif, uiqnhf, otkjqc, jbbfmo, window, x, z;Array.prototype.forEach.apply(a1, []);");
/*fuzzSeed-116170070*/count=569; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot((( - Math.fround(x)) <= (Math.sinh(Math.imul(Math.fround(y), Math.fround((y - (-0x100000001 | 0))))) | 0)), Math.hypot(( + (y < ((x >> Math.fround(Math.fround(Math.imul(Math.fround(y), Math.fround(y))))) >>> 0))), ( + 0x07fffffff))) << (Math.tanh(((( ~ ((x / Math.pow((x >>> 0), Number.MIN_SAFE_INTEGER)) | 0)) >>> 0) >> ( + ( ! ( + Math.min(( + (y <= y)), ( ~ ( + x)))))))) << Math.min(((y | 0) !== Math.min((y | 0), x)), Math.min((y & y), -0x100000001)))); }); testMathyFunction(mathy0, [0/0, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, 1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, -(2**53+2), -0x100000000, 0x080000001, -0x080000000, 0.000000000000001, -1/0, 0x100000000, -(2**53-2), 0x080000000, 0x100000001, -(2**53), -0x080000001, 42, Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -0, 1, Number.MIN_VALUE, 2**53-2, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=570; tryItOut("\"use asm\"; Array.prototype.reverse.call(a0, g0.f1, v0, s2);");
/*fuzzSeed-116170070*/count=571; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.atan2((Math.hypot((((y >>> 0) % (mathy1(( + mathy0(( ! 1/0), 2**53-2)), Math.fround(x)) >>> 0)) >>> 0), (( - ( + ( ! y))) >>> 0)) >>> 0), Math.fround(( + ((((Math.fround(Math.exp(Math.fround((y , ((Math.expm1((-0x07fffffff >>> 0)) | 0) | 0))))) | 0) % ((( ~ ((Math.cosh(y) | 0) >>> 0)) >>> 0) | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy2, [0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 1, -0x0ffffffff, 2**53-2, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, 0x0ffffffff, 0/0, -0x080000000, 2**53+2, Number.MIN_VALUE, 0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 0x080000000, -0x100000000, 42, -0x100000001, 1/0, -0x07fffffff, -(2**53+2), -(2**53-2), 0x100000000, 0x080000001]); ");
/*fuzzSeed-116170070*/count=572; tryItOut("mathy4 = (function(x, y) { return ( + Math.fround((Math.fround((Math.fround(( ~ ( + (mathy2((Math.fround(Math.asin(y)) | 0), (-1/0 | 0)) >>> 0)))) | 0)) | 0))); }); testMathyFunction(mathy4, [-(2**53-2), -(2**53+2), -0x07fffffff, 1, -0x080000001, -(2**53), 2**53, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, Math.PI, 1/0, 42, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -0, Number.MIN_VALUE, 0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 0x080000000, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, 2**53-2, 0/0, -0x100000000]); ");
/*fuzzSeed-116170070*/count=573; tryItOut("mathy4 = (function(x, y) { return (Math.asinh((Math.log10(Math.fround((mathy0((42 >>> 0), ((y % x) >>> 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy4, [2**53-2, 1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 0x080000001, 0.000000000000001, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53+2), -0x080000001, 0/0, Number.MIN_VALUE, 0x100000001, -0, 0, -0x07fffffff, 2**53+2, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -0x100000001, 2**53, 42]); ");
/*fuzzSeed-116170070*/count=574; tryItOut("/*infloop*/for(let d\u000c = window; \u3056; new RegExp(\"[\\\\\\u548f-\\u00b3]?|(?=$){1,}{4}(${4,7}){4,5}\", \"ym\")) (\"\\u37FD\");");
/*fuzzSeed-116170070*/count=575; tryItOut("\"use strict\"; m0.has(f0);");
/*fuzzSeed-116170070*/count=576; tryItOut("M:if(true) if(undefined) {const e2 = new Set(i0); } else  if (\"\u03a0\") this;");
/*fuzzSeed-116170070*/count=577; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=578; tryItOut("v1 = Object.prototype.isPrototypeOf.call(v2, this.s2);");
/*fuzzSeed-116170070*/count=579; tryItOut("\"use strict\"; g0.a2 + '';");
/*fuzzSeed-116170070*/count=580; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -1.9342813113834067e+25;\n    return +((Float64ArrayView[0]));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53+2), -0, 0x100000001, 0x080000001, 0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, Math.PI, 1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 2**53, -0x080000001, 0x080000000, -1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, Number.MIN_VALUE, -(2**53), 0x0ffffffff, -Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, 0/0, 0x07fffffff, -(2**53-2), 0.000000000000001]); ");
/*fuzzSeed-116170070*/count=581; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + Math.imul((mathy0(y, ( + ( ~ ( + 0/0)))) | 0), (Math.fround(Math.atanh(Math.fround(Math.atan2((y | 0), (0 | 0))))) | 0))) == (Math.round((Math.imul(( + ( ! Math.fround((x == y)))), Math.min(1.7976931348623157e308, 2**53)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116170070*/count=582; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return ( + (( + ( + ( ! ( + (Math.log10((Math.fround(( - Math.fround(Math.fround(Math.imul(0x100000001, Math.fround(y)))))) >>> 0)) >>> 0))))) ? ( + Math.fround(Math.imul(Math.hypot(( + ( ! x)), ( + ((y >>> 0) || ( + y)))), (((((((y >>> 0) , (x >>> 0)) >>> 0) >>> 0) ? ( - Math.max(y, y)) : (( ~ ( + ( + ((x >>> Math.fround(y)) >>> 0)))) >>> 0)) >>> 0) | 0)))) : ( + (Math.tan((Math.min((y && Math.fround(Math.round(x))), (Math.pow(2**53, ((( - ( + y)) >>> 0) > x)) | 0)) | 0)) | 0)))); }); testMathyFunction(mathy2, [0x080000000, 0x080000001, 1/0, 2**53+2, -(2**53+2), 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -0x100000000, 0, -0, 0x100000000, 1, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0/0, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 42, 0.000000000000001, -Number.MIN_VALUE, 0x07fffffff, -0x080000000, -1/0, Number.MAX_VALUE, -0x100000001, -0x07fffffff, Math.PI]); ");
/*fuzzSeed-116170070*/count=583; tryItOut("if(false) { if (this) /*vLoop*/for (let zqcqje = 0; zqcqje < 137; ++zqcqje) { x = zqcqje; v2 = r2.exec; }  else {(void version(170)); }}");
/*fuzzSeed-116170070*/count=584; tryItOut("v1 = evalcx(\"function g0.f1(p0)  { return (let (b) ((yield new RegExp(\\\"[^]\\\", \\\"ym\\\")))) } \", o2.o2.g2);");
/*fuzzSeed-116170070*/count=585; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.imul(Math.fround(( + (( + Math.expm1(Math.fround((Math.fround(x) ** Math.fround(Math.atan2(y, y)))))) || Math.log2((Math.hypot(Math.acos(x), ( + y)) | 0))))), Math.fround((((Math.fround(Math.hypot(0.000000000000001, 2**53)) >>> 0) ? ((Math.min(((y ** Math.sinh(Math.fround(x))) | 0), (Math.cbrt(((42 ? Math.hypot(Math.max((x | 0), y), x) : ( ~ Math.asin(y))) >>> 0)) >>> 0)) | 0) >>> 0) : (Math.fround(Math.min(Math.fround((((Math.sign(y) | 0) != ((x < Math.min(-0x080000000, y)) | 0)) | 0)), y)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [42, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, -0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -0, -0x100000001, 0x07fffffff, 1/0, 2**53-2, -Number.MIN_VALUE, 2**53, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, -(2**53-2), Math.PI, Number.MAX_VALUE, 0/0, 0x0ffffffff, -(2**53+2), 0, -0x080000000, 2**53+2, 1, 0x080000000, -0x100000000]); ");
/*fuzzSeed-116170070*/count=586; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.trunc((Math.pow((Number.MIN_VALUE | 0), Math.fround(y)) & ((( + (Math.atan2((x | 0), (x >>> 0)) >>> 0)) <= ( + ((x | 0) , (Math.atan2((-0x100000000 >>> 0), ((mathy2(((Math.min((x >>> 0), (x >>> 0)) >>> 0) >>> 0), (y >>> 0)) >>> 0) | 0)) >>> 0)))) | 0))) | 0); }); testMathyFunction(mathy4, [0x100000000, -0x080000000, 1, Number.MAX_VALUE, -(2**53), -(2**53-2), -0, -1/0, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, Math.PI, -0x080000001, 42, -0x100000001, 0.000000000000001, 2**53, -(2**53+2)]); ");
/*fuzzSeed-116170070*/count=587; tryItOut("{ void 0; assertJitStackInvariants(); } /*oLoop*/for (var qvyyyf = 0; qvyyyf < 14; ++qvyyyf) { yield 7; } ");
/*fuzzSeed-116170070*/count=588; tryItOut("/*MXX1*/o0 = g1.String.prototype.replace;");
/*fuzzSeed-116170070*/count=589; tryItOut("\"use strict\"; with(let (\u3056) new RegExp(\"(?=\\\\1+)\", \"gim\")){a0.toSource = (function mcc_() { var akacar = 0; return function() { ++akacar; if (/*ICCD*/akacar % 10 == 1) { dumpln('hit!'); try { s2 += s1; } catch(e0) { } try { selectforgc(o2); } catch(e1) { } try { t1[17]; } catch(e2) { } v1 = evaluate(\"this.t0[17];\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: eval, catchTermination: false, element: o0, elementAttributeName: s1, sourceMapURL: s1 })); } else { dumpln('miss!'); try { Array.prototype.sort.apply(a1, [(function() { try { ; } catch(e0) { } try { e0.add(h2); } catch(e1) { } Array.prototype.sort.call(a2, (function() { try { /*RXUB*/var r = r1; var s = \"\"; print(s.match(r)); print(r.lastIndex);  } catch(e0) { } for (var v of t0) { try { g1.h2.delete = o1.f1; } catch(e0) { } try { m2.set(p2, e0); } catch(e1) { } for (var p in s1) { h2 = ({getOwnPropertyDescriptor: function(name) { a2.splice(t1);; var desc = Object.getOwnPropertyDescriptor(this.v2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { t0[\"x\"] = g0;; var desc = Object.getPropertyDescriptor(this.v2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a2.pop(g2);; Object.defineProperty(this.v2, name, desc); }, getOwnPropertyNames: function() { o0.v1 = Object.prototype.isPrototypeOf.call(i0, s1);; return Object.getOwnPropertyNames(this.v2); }, delete: function(name) { g2.v0 = evaluate(\"s2 = m1.get(b0);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: null, sourceIsLazy: false, catchTermination: (x % 6 != 5) }));; return delete this.v2[name]; }, fix: function() { a0.splice(0, 0, e0, o1);; if (Object.isFrozen(this.v2)) { return Object.getOwnProperties(this.v2); } }, has: function(name) { m0 = new WeakMap;; return name in this.v2; }, hasOwn: function(name) { a0.forEach((function(j) { if (j) { try { m1.get(i1); } catch(e0) { } try { Array.prototype.splice.call(a0, NaN,  /x/ , /\\S/gim,  /x/ ); } catch(e1) { } Array.prototype.sort.apply(a2, [(function() { try { for (var p in v2) { try { print(uneval(a0)); } catch(e0) { } try { v1 = o2.g2.eval(\"/* no regression tests found */\"); } catch(e1) { } e1.has(s2); } } catch(e0) { } Object.prototype.watch.call(f1, \"6\", (function mcc_() { var vkozsx = 0; return function() { ++vkozsx; if (/*ICCD*/vkozsx % 5 == 4) { dumpln('hit!'); try { e1[ \"\" ] = m0; } catch(e0) { } o2.a0.pop(o0); } else { dumpln('miss!'); try { a2.shift(a1); } catch(e0) { } try { this.t2 = t2.subarray(new RegExp(\"(\\\\d)|[^\\\\W\\\\f\\u00e1-\\\\u6C52]|[\\\\cL\\\\cT-\\\\uF1ef\\\\d\\\\xb6-\\u00e8]+?\", \"im\")); } catch(e1) { } /*MXX1*/Object.defineProperty(this, \"this.o2\", { configurable: (x % 2 != 1), enumerable:  \"\" ,  get: function() {  return g0.Date.prototype.valueOf; } }); } };})()); return this.s1; }), m2]); } else { try { Array.prototype.reverse.apply(a1, []); } catch(e0) { } try { m0.set(m1, i2); } catch(e1) { } 3; } }), this.h1);; return Object.prototype.hasOwnProperty.call(this.v2, name); }, get: function(receiver, name) { ;; return this.v2[name]; }, set: function(receiver, name, val) { return this.v0; this.v2[name] = val; return true; }, iterate: function() { for (var v of t1) { v2 = Object.prototype.isPrototypeOf.call(o0, i2); }; return (function() { for (var name in this.v2) { yield name; } })(); }, enumerate: function() { v0 = (g0.g2 instanceof o1.m2);; var result = []; for (var name in this.v2) { result.push(name); }; return result; }, keys: function() { a2.unshift(v1);; return Object.keys(this.v2); } }); } } return a2; }), f2); return this.f0; })]); } catch(e0) { } try { a1.splice(NaN, ({valueOf: function() { Array.prototype.splice.call(a2, 1, 14);return 14; }})); } catch(e1) { } try { i2.send(p1); } catch(e2) { } s2 += 'x'; } };})(); }");
/*fuzzSeed-116170070*/count=590; tryItOut("mathy2 = (function(x, y) { return Math.fround(( - Math.fround(( ! mathy1(function(y) { \"use strict\"; print([ /x/ ]); }, Math.atan2(Math.asinh(x), ( + Math.fround(( ! (-0 | 0)))))))))); }); testMathyFunction(mathy2, [-0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0, 1.7976931348623157e308, 1/0, -0, 0.000000000000001, 2**53+2, 2**53, 0/0, -Number.MAX_VALUE, -(2**53), -0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, -(2**53+2), 0x080000001, 1, 42, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, -1/0, Math.PI]); ");
/*fuzzSeed-116170070*/count=591; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=592; tryItOut("\"use strict\"; x.constructor;");
/*fuzzSeed-116170070*/count=593; tryItOut("\"use strict\"; ;");
/*fuzzSeed-116170070*/count=594; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + (Math.cos(( + (Math.hypot(x, y) ? (((x >>> 0) ? (y >>> 0) : (y >>> 0)) >>> 0) : ( + mathy1(x, ( + -0)))))) === ( + mathy0(x, ((( + (Math.max(( + x), ( + x)) | 0)) ^ ( + y)) >>> 0))))) << ( + mathy0((( + y) >>> 0), ( + (( - (Math.max(x, (Math.fround(((x ^ (y >>> 0)) >>> 0)) >>> ( + x))) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-116170070*/count=595; tryItOut("/*infloop*/L:for(let a; undefined; (new (4277)((delete x.eval)))) /*tLoop*/for (let b of /*MARR*/[(1/0), new Boolean(true), (1/0), new Boolean(true), x, (1/0), new Boolean(true), x, (1/0), new Boolean(true), new Boolean(true), (1/0), new Boolean(true), (1/0), new Boolean(true), (1/0), x, new Boolean(true), (1/0), (1/0)]) { i0.send(g0); }");
/*fuzzSeed-116170070*/count=596; tryItOut("v0 = (h2 instanceof a0);");
/*fuzzSeed-116170070*/count=597; tryItOut("o0.a0 = x;");
/*fuzzSeed-116170070*/count=598; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0x07fffffff, 0x0ffffffff, -0x080000001, Number.MIN_VALUE, -0x07fffffff, 42, 0x100000001, 0.000000000000001, -0x100000000, -(2**53-2), 0x080000000, 2**53-2, -0, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, -0x100000001, -0x0ffffffff, 2**53+2, 2**53, 0x080000001, 1.7976931348623157e308, 1, -Number.MAX_VALUE, -(2**53+2), -1/0, Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=599; tryItOut("Array.prototype.pop.apply(o2.a1, [this.m2, x]);");
/*fuzzSeed-116170070*/count=600; tryItOut("this.e1 = a0[6];");
/*fuzzSeed-116170070*/count=601; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.fround(Math.log(( - (Math.pow((( + 0x0ffffffff) >>> 0), (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, Math.PI, 0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 0x100000000, 0, -0x100000000, -0x080000000, 42, -Number.MIN_VALUE, -(2**53-2), 2**53-2, 0x100000001, -0, 1.7976931348623157e308, 0x07fffffff, -(2**53), -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, 0x080000000, 0x080000001, 2**53, 0/0]); ");
/*fuzzSeed-116170070*/count=602; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(((( + Math.max((x | 0), y)) != ( + Math.fround(( ~ ((-Number.MIN_SAFE_INTEGER !== Math.min(Math.fround(mathy0(Math.fround(y), Math.fround(( + ( ~ x))))), (-(2**53-2) >>> 0))) | 0))))) >>> 0), (( ! (Math.trunc(Math.exp(Math.log10(mathy0((y | 0), y)))) | 0)) >>> 0)); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -0x0ffffffff, -(2**53-2), -1/0, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 0, 0.000000000000001, 0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), -0, 1, 0x080000000, 2**53-2, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, 42, 0/0, -0x100000001, 2**53+2]); ");
/*fuzzSeed-116170070*/count=603; tryItOut("\"use strict\"; eval = linkedList(eval, 672);");
/*fuzzSeed-116170070*/count=604; tryItOut("\"use strict\"; let (c) { (x); }function concat() { return /*MARR*/[false, false, false,  '' , -(2**53-2), false, -(2**53-2), false, -(2**53-2), -(2**53-2), false,  '' , -(2**53-2), false,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , false, -(2**53-2), -(2**53-2), -(2**53-2),  '' , -(2**53-2), false, false].some } print((/*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, [], null, null, null, null, null, null, null, arguments, objectEmulatingUndefined(), null, arguments, null, arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), [], arguments, null, null, null, arguments, arguments, null, [], objectEmulatingUndefined(), null, objectEmulatingUndefined(), arguments, null, objectEmulatingUndefined(), arguments, null, arguments, [], arguments, [], [], [], objectEmulatingUndefined(), objectEmulatingUndefined(), arguments, objectEmulatingUndefined(), [], null, objectEmulatingUndefined(), [], arguments, objectEmulatingUndefined(), null, arguments, objectEmulatingUndefined(), [], [], arguments, objectEmulatingUndefined(), arguments, arguments, null, arguments, null, [], null, [], arguments, [], arguments, null, [], null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, [], arguments, objectEmulatingUndefined(), [], arguments, [], null, arguments, [], null, null, arguments, null, objectEmulatingUndefined(), objectEmulatingUndefined(), [], null, null, objectEmulatingUndefined(), null, [], objectEmulatingUndefined(), objectEmulatingUndefined(), [], null, arguments, objectEmulatingUndefined(), [], null, null, null, arguments, [], objectEmulatingUndefined(), arguments].filter));");
/*fuzzSeed-116170070*/count=605; tryItOut("e0.has(h0);");
/*fuzzSeed-116170070*/count=606; tryItOut("testMathyFunction(mathy3, [1, 0x080000000, 1/0, Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, 0x100000001, 0x080000001, 0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, -1/0, -0x100000000, 0.000000000000001, -0x0ffffffff, 42, 0, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -0, -0x080000000, Number.MIN_SAFE_INTEGER, 0/0, Math.PI, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -(2**53-2)]); ");
/*fuzzSeed-116170070*/count=607; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(this.m1, this.p2);");
/*fuzzSeed-116170070*/count=608; tryItOut("testMathyFunction(mathy5, [0x07fffffff, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, Number.MIN_VALUE, 1, 0x080000000, -0x0ffffffff, 1/0, 1.7976931348623157e308, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, 0x080000001, -1/0, 42, -(2**53-2), -0, -0x100000001, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -0x080000001, 0, 2**53-2, -0x07fffffff, -0x080000000]); ");
/*fuzzSeed-116170070*/count=609; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!([\\d]+|\\udC6c++)*|\\b*((?=\\2+?(?:^))){137438953473})/ym; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=610; tryItOut("t1[17] = a = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: (4277), defineProperty: ([] = (yield undefined)), getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: undefined, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(x), ArrayBuffer.prototype.slice, DataView.prototype.setInt8).yoyo((4277));");
/*fuzzSeed-116170070*/count=611; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xffbd929c)+((0xccfc3fc6) ? (((-((((+sqrt(((d1))))) - ((d0))))))) : (0xf78962d2))-(0xc912bf73)))|0;\n    d1 = (NaN);\n    (( /* Comment */\n(/*wrap1*/(function(){ v2 = g0.runOffThreadScript();return Date.prototype.getUTCHours})())((Function.prototype).call( /x/ , )))) = ((d0));\n;    return (((0xe40fe492)-(!(0x17f76de1))))|0;\n  }\n  return f; })(this, {ff: SimpleObject}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0, 0x0ffffffff, Number.MIN_VALUE, -1/0, 42, 0/0, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, -(2**53), -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 2**53+2, 2**53, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, -0x080000001, 0x100000000, -0x080000000, 0x100000001, -0x100000000, 1.7976931348623157e308, Math.PI, 0.000000000000001, -0x0ffffffff, 0x07fffffff, -(2**53-2), 0x080000001]); ");
/*fuzzSeed-116170070*/count=612; tryItOut("\"use strict\"; s0 = new String;");
/*fuzzSeed-116170070*/count=613; tryItOut("s0 = a1.join(s0, m2);");
/*fuzzSeed-116170070*/count=614; tryItOut("var x = 27, x, x = x, {} = x;s1 + v2;function eval(e, d)\"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Uint16ArrayView[1]) = (-(((((((1)-((0x0)))>>>((0xff1129cd)-(0xf8ebf472)+(-0x4df2765))))-(i0))>>>((i0)))));\n    return (((i1)))|0;\n  }\n  return f;Array.prototype.pop.call(g0.a2);");
/*fuzzSeed-116170070*/count=615; tryItOut("e2.add(s2);");
/*fuzzSeed-116170070*/count=616; tryItOut("v0 = (this.t0 instanceof this.v0);");
/*fuzzSeed-116170070*/count=617; tryItOut("this.a1[7] = null;\ng1.e1.has(g2.a0);\n");
/*fuzzSeed-116170070*/count=618; tryItOut("print(uneval(o2.p0));");
/*fuzzSeed-116170070*/count=619; tryItOut("mathy1 = (function(x, y) { return (( + Math.abs(Math.sin(( + Math.tan(( + (Number.MIN_VALUE * ( ! y)))))))) * ( + Math.pow((( ~ (Math.fround(Math.log10((( + Math.fround(Math.imul(x, Math.fround(x)))) >>> 0))) != y)) | 0), mathy0(( + Math.atan2(x, ( + 0x080000001))), (Math.sqrt((Math.atan((x | 0)) | 0)) | 0))))); }); testMathyFunction(mathy1, [1/0, -0x100000001, 0x0ffffffff, 0.000000000000001, -(2**53), 42, -Number.MAX_SAFE_INTEGER, 0/0, 2**53, -0x080000000, -Number.MIN_VALUE, -(2**53-2), 0x07fffffff, 0x100000001, 0x080000001, 0, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -0x0ffffffff, -0x080000001, 0x100000000, 2**53+2, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0, 1, -0x100000000]); ");
/*fuzzSeed-116170070*/count=620; tryItOut("var vdmbgv = new ArrayBuffer(8); var vdmbgv_0 = new Int16Array(vdmbgv); var vdmbgv_1 = new Uint16Array(vdmbgv); var vdmbgv_2 = new Uint8ClampedArray(vdmbgv); var vdmbgv_3 = new Uint8Array(vdmbgv); vdmbgv_3[0] = -2; print(vdmbgv_3);print(vdmbgv_0);\nlet d, rdngim;this.r1 = /(?!(?:(?!(?:.))))/gi;\n");
/*fuzzSeed-116170070*/count=621; tryItOut("\"use strict\"; a1.sort((function mcc_() { var qlndxf = 0; return function() { ++qlndxf; if (/*ICCD*/qlndxf % 11 == 7) { dumpln('hit!'); a1[19] = this.__defineGetter__(\"x\", /\\3([^])$\\cI*??*?/yi); } else { dumpln('miss!'); i1.send(h1); } };})(), x % 13, s1, this.f2);/*RXUB*/var r = g2.r1; var s = \"a\"; print(r.exec(s)); ");
/*fuzzSeed-116170070*/count=622; tryItOut("print(s0);function \u3056(window, ...eval)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      return ((((x))))|0;\n    }\n    i0 = (0xfbf79fef);\n    return (((i0)+(-0x8000000)))|0;\n  }\n  return f;/* no regression tests found */");
/*fuzzSeed-116170070*/count=623; tryItOut("mathy1 = (function(x, y) { return ( ~ ( + (( + ( + ( ~ Math.fround(( + (Math.cosh(Math.fround(Math.log10((Math.max(Math.fround(y), y) | 0)))) >>> 0)))))) == ( + ( + Math.log(x)))))); }); testMathyFunction(mathy1, /*MARR*/[true, true, true, function(){}, function(){}, function(){}, function(){}, function(){}, true, function(){}, function(){}, true, true, true, true, function(){}, function(){}]); ");
/*fuzzSeed-116170070*/count=624; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\x1d).*/yi; var s = \"=\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=625; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (((mathy0(Math.fround(((Math.pow(x, Math.fround(mathy0(-(2**53-2), Math.fround(x)))) >>> 0) >= (Math.cosh((Math.max((Math.fround(-(2**53+2)) >>> 0), (y >>> 0)) >>> 0)) >>> 0))), ( ~ (0.000000000000001 | 0))) >>> 0) ? Math.fround(Math.cos(( + x))) : ( + (Math.sin(x) >>> 0))) / ( + ( + mathy1(( + Math.fround(Math.hypot(Math.fround(mathy1(Math.pow(x, ( + y)), Math.acos(y))), Math.fround(-(2**53-2))))), ( + (Math.log10(x) >>> 0))))))); }); testMathyFunction(mathy2, [-0x100000000, 2**53-2, Number.MIN_VALUE, -0x07fffffff, 1, -0x100000001, 0x080000001, 0/0, 0x0ffffffff, 2**53, -0x080000001, Number.MAX_SAFE_INTEGER, 42, 0, 0.000000000000001, -1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, Number.MIN_SAFE_INTEGER, -0, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), 0x100000000, 0x100000001, Math.PI, 2**53+2, 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=626; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, -0x080000000, -0x0ffffffff, 2**53+2, -Number.MIN_VALUE, 42, -(2**53+2), -0x080000001, -(2**53-2), Number.MAX_VALUE, 0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, 1.7976931348623157e308, 0x080000000, 2**53, -(2**53), 0/0, 0x080000001, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0, Math.PI, Number.MAX_SAFE_INTEGER, 1]); ");
/*fuzzSeed-116170070*/count=627; tryItOut("mathy4 = (function(x, y) { return Math.clz32((( ! Math.atan2(Math.atan(( - Number.MAX_VALUE)), y)) >>> 0)); }); testMathyFunction(mathy4, [0.000000000000001, -1/0, -(2**53+2), -0x080000001, -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, -Number.MIN_VALUE, 0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, -0, -(2**53-2), 0x100000000, -0x080000000, 0x07fffffff, 0x080000001, 1.7976931348623157e308, 2**53, 2**53+2, -0x100000001, 0x0ffffffff, 1, Number.MAX_VALUE, 0/0, -Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=628; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + Math.atanh(Math.round(Math.fround(Math.pow(Math.fround(y), Math.fround((y <= y))))))) << ( - (Math.pow(y, (( + Math.atan2(2**53, 0x0ffffffff)) ? (-(2**53-2) >> y) : Number.MIN_VALUE)) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-116170070*/count=629; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=630; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x080000000, 1.7976931348623157e308, 0/0, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, 0x100000001, -0, -Number.MIN_VALUE, -(2**53), 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, Number.MAX_VALUE, 2**53, -1/0, -(2**53-2), 0x080000000, -(2**53+2), 1, 2**53-2, 0.000000000000001, 0x07fffffff, 2**53+2, -0x0ffffffff, 0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 0x100000000, 42, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=631; tryItOut("print(x);\n\u000dlet (b) { (this); }\n");
/*fuzzSeed-116170070*/count=632; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x100000001, Number.MAX_VALUE, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 2**53+2, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, 0.000000000000001, 0x080000000, -0x080000000, Math.PI, 0x080000001, Number.MIN_VALUE, 0x100000000, -1/0, 2**53, 0, 42, -0x100000000, 0x100000001, -Number.MIN_VALUE, -(2**53), 1/0, -(2**53-2), -0, -0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=633; tryItOut("\"use strict\"; ");
/*fuzzSeed-116170070*/count=634; tryItOut("g0.m0.set(m0, e0);");
/*fuzzSeed-116170070*/count=635; tryItOut("/*vLoop*/for (let mdlrkk = 0, x = (void options('strict')); mdlrkk < 68; ++mdlrkk) { let y = mdlrkk; for (var v of this.h2) { try { Array.prototype.push.apply(a0, [(let (x, x, x, khkufr, x, d, uoqzbz, window, cxocjf)  /x/ ), e2, b2]); } catch(e0) { } try { m2 = new Map; } catch(e1) { } o0.v1 = v1[(uneval(-16))]; } } ");
/*fuzzSeed-116170070*/count=636; tryItOut("do {/* no regression tests found */o2.t2 + ''; } while((x) && 0);");
/*fuzzSeed-116170070*/count=637; tryItOut("\"use strict\"; m0.get(i0);");
/*fuzzSeed-116170070*/count=638; tryItOut("\"use asm\"; testMathyFunction(mathy2, [2**53+2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -(2**53-2), 0x100000001, -0x100000000, -(2**53), 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, 0/0, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -Number.MAX_VALUE, 2**53-2, 1/0, 0x0ffffffff, 0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, 0, Number.MIN_VALUE, -0x080000001, 1, 1.7976931348623157e308, -1/0, -0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=639; tryItOut("\"use strict\"; (new (uneval(new RegExp(\"(?=((?:\\\\D)\\\\B+))|(?!$${2,})?\", \"yi\")))((p={}, (p.z = new RegExp(\"(?=(?!(?=[^])))\", \"gyim\"))()).unwatch(\"13\"), x));");
/*fuzzSeed-116170070*/count=640; tryItOut("a2 = arguments.callee.arguments;");
/*fuzzSeed-116170070*/count=641; tryItOut("\"use strict\"; const b0 = t0.buffer;");
/*fuzzSeed-116170070*/count=642; tryItOut("mathy5 = (function(x, y) { return (( + (( + Math.max(( + Math.hypot(mathy3(Math.fround(y), (x >>> 0)), Math.hypot(y, y))), ( + Math.atan2(Math.fround((-(2**53-2) - x)), y)))) , ( + (( + (x >>> 0)) >>> 0)))) != ( - mathy1(x, Math.fround((Math.fround((y || y)) % Math.fround(Math.fround(Math.imul((x * y), ( + 0x07fffffff))))))))); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-116170070*/count=643; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -134217729.0;\n    i0 = (0xf9015c90);\n    {\n      i0 = (-0x8000000);\n    }\n    d1 = (((d2)) / ((+((-5.0)))));\n    d2 = ((Int32ArrayView[2]));\n    {\n      d1 = (+(-1.0/0.0));\n    }\n    {\n      (Uint32ArrayView[(((d2) < (d1))) >> 2]) = ((i0)+(0xffffffff));\n    }\n    {\n      d2 = (+atan2(((+((((+(((0xe665b253))>>>((0xd40808d3)))) != (((65535.0)) * ((4398046511105.0)))) ? (d2) : (((Float32ArrayView[(0xcae1c*(0xe4cb48c3)) >> 2]))))))), ((+(0.0/0.0)))));\n    }\n    d1 = (+(((i0))>>>((((0xf93eb728)+(i0)) << ((0xffffffff)+(0x8e95f766))) / (((p={}, (p.z = (void options('strict_mode')))()))|0))));\n    return +((1.015625));\n  }\n  return f; })(this, {ff: function(y) { \"use asm\"; f2 + f2; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, 0/0, Math.PI, 0.000000000000001, 0, 0x0ffffffff, -(2**53), -Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 2**53+2, -(2**53+2), -0x080000001, 2**53-2, 1, 0x080000000, -0x100000000, 0x080000001, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 42, 2**53, -(2**53-2), -0x0ffffffff, -0]); ");
/*fuzzSeed-116170070*/count=644; tryItOut("mathy2 = (function(x, y) { return (Math.min(((( + Math.abs(( + (Math.min((y >>> 0), (( - (x >>> 0)) >>> 0)) >>> 0)))) / ((((x | 0) , ((( + ( + 2**53)) | 0) | 0)) ? x : ( + Math.acosh(((Math.max(( + y), (x | 0)) >>> 0) >>> 0)))) | 0)) >>> 0), Math.fround(Math.pow((Math.log(x) | 0), Math.fround(( - Math.expm1(x)))))) | 0); }); testMathyFunction(mathy2, [0.1, -0, (new Boolean(true)), 1, NaN, true, ({valueOf:function(){return 0;}}), (new Boolean(false)), '/0/', objectEmulatingUndefined(), (function(){return 0;}), false, (new Number(-0)), [], '0', [0], (new Number(0)), /0/, null, ({toString:function(){return '0';}}), 0, '\\0', '', undefined, (new String('')), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-116170070*/count=645; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (( + Math.abs(Math.fround(( ! Math.fround(x))))) ? ( + Math.fround(Math.min(( ~ ( ~ ( + (x , -Number.MAX_VALUE)))), Math.sin(Math.tan(Math.fround(( - Math.fround(y)))))))) : ( + ( + Math.pow(( + ( + Math.tan(( + x)))), ( + Math.asinh((Math.asin((x | 0)) | 0)))))))); }); ");
/*fuzzSeed-116170070*/count=646; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.cosh((( - ( + Math.max(( + mathy3(Math.expm1((( - 1/0) | 0)), (Math.max((((x | 0) >> (x | 0)) | 0), y) | 0))), ( + ( + (( + -Number.MIN_VALUE) | (((( ~ Number.MAX_VALUE) >>> 0) ^ (x >>> 0)) >>> 0))))))) | 0)); }); testMathyFunction(mathy4, [-0x0ffffffff, -1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, -0x080000001, 1, Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, -(2**53), 0x080000001, 2**53+2, 0/0, Math.PI, -0x080000000, 0x080000000, Number.MAX_VALUE, 0, 0x100000000, -0, 1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=647; tryItOut("/*infloop*/ for  each(let NaN--.x in x = ({x: true})) {v0 = Object.prototype.isPrototypeOf.call(o2.s0, o1.p1);(window); }");
/*fuzzSeed-116170070*/count=648; tryItOut("");
/*fuzzSeed-116170070*/count=649; tryItOut("mathy4 = (function(x, y) { return \"0\"; }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0, -0x100000001, 0x07fffffff, 1.7976931348623157e308, 0x100000001, 0x080000001, 0x100000000, -(2**53-2), -0x080000001, -Number.MAX_VALUE, 1, -Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), 0, -0x100000000, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, Math.PI, 2**53, 0x080000000, -1/0, -(2**53), Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-116170070*/count=650; tryItOut("this.v1 = Object.prototype.isPrototypeOf.call(o2.g2, m0);");
/*fuzzSeed-116170070*/count=651; tryItOut("\"use strict\"; d, [] = (/*wrap1*/(function(){ v2 = t0.byteOffset;return decodeURI})()).call((x < z), (x%=x));switch(x = -0.507) { default: break;  }");
/*fuzzSeed-116170070*/count=652; tryItOut("testMathyFunction(mathy3, /*MARR*/[ \"use strict\" , objectEmulatingUndefined(), {}, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), {}, {}, {},  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , {},  \"use strict\" ,  \"use strict\" , {}, objectEmulatingUndefined(),  \"use strict\" , {},  \"use strict\" ,  \"use strict\" , {},  \"use strict\" , objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, {},  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , {}, objectEmulatingUndefined(), {}, {}, {}, objectEmulatingUndefined(),  \"use strict\" , {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {},  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, {}, objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , {}, {},  \"use strict\" , {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), {},  \"use strict\" , {},  \"use strict\" ,  \"use strict\" , {}, objectEmulatingUndefined(), {}, {}, {},  \"use strict\" ,  \"use strict\" , {}, objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), {}, objectEmulatingUndefined(),  \"use strict\" , {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, {},  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , {},  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), {}, {}, objectEmulatingUndefined(),  \"use strict\" , {}, objectEmulatingUndefined(), {}, {},  \"use strict\" , {},  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), {},  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined()]); ");
/*fuzzSeed-116170070*/count=653; tryItOut("for (var p in b2) { try { v0 = t1.length; } catch(e0) { } try { m1.get(b0); } catch(e1) { } this.t1.set(t1, v1); }\nfor (var v of b0) { try { e2.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float64ArrayView[1]) = ((140737488355329.0));\n    {\n      i1 = (i1);\n    }\n    {\n      i0 = (i1);\n    }\n    return ((x))|0;\n    return (((0xe5d19d92)))|0;\n  }\n  return f; })(this, {ff: undefined}, new ArrayBuffer(4096)); } catch(e0) { } this.v1 = t0.length; }");
/*fuzzSeed-116170070*/count=654; tryItOut("\"use strict\"; t0 = new Float64Array(g2.a2);");
/*fuzzSeed-116170070*/count=655; tryItOut("\"use asm\"; for (var v of o1) { try { s0 += 'x'; } catch(e0) { } g0.o0.a0 = Array.prototype.map.apply(a2, [objectEmulatingUndefined]); }");
/*fuzzSeed-116170070*/count=656; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = r2; var s = s2; print(r.exec(s)); ");
/*fuzzSeed-116170070*/count=657; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.sinh((Math.atan2((Math.pow(( + (( + y) & ( + ( + (( + Math.sign(mathy0(x, 0x080000000))) + Math.fround(mathy0(Math.fround(mathy1(Math.fround(y), (x >>> 0))), x))))))), (Math.exp((((mathy0(y, (Math.acos(0x0ffffffff) | 0)) | 0) * (42 | 0)) >>> 0)) | 0)) >>> 0), (Math.fround(( ~ Math.fround((Math.fround((y ? (((y !== y) == -Number.MAX_SAFE_INTEGER) >>> 0) : y)) ^ Math.fround(y))))) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy2, [-0x0ffffffff, -0x080000000, 0.000000000000001, -0x080000001, 1.7976931348623157e308, -0, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0x080000001, 0, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), Number.MAX_VALUE, 0x100000000, 2**53-2, -1/0, -0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Math.PI, 0/0, 2**53, 42, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, -(2**53), 1, -0x100000000]); ");
/*fuzzSeed-116170070*/count=658; tryItOut("\"use strict\"; for (var v of m2) { try { h0.__iterator__ = (function() { for (var j=0;j<64;++j) { f0(j%5==1); } }); } catch(e0) { } try { /*RXUB*/var r = r0; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00bb\\u00bb\\u00bb\\u00e8\\u00bb\\u00bb\\u00bb\\u00e8\\u00bb\\u00bb\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00e8\\u00bb\\u00bb\\u00bb\\u00e8\\u00bb\\u00bb\\u00bb\\u00e8\\u00bb\\u00bb\"; print(s.search(r));  } catch(e1) { } try { g2 = this; } catch(e2) { } m2.set(b1, o0.g2); }x;");
/*fuzzSeed-116170070*/count=659; tryItOut("/*ODP-3*/Object.defineProperty(s1, \"atanh\", { configurable: false, enumerable: false, writable: (x % 53 == 50), value: h1 });");
/*fuzzSeed-116170070*/count=660; tryItOut("\"use strict\"; o2 = o2.e1.__proto__;");
/*fuzzSeed-116170070*/count=661; tryItOut("\"use asm\"; print(\"\\uE2A9\");");
/*fuzzSeed-116170070*/count=662; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.pow(Math.fround(Math.max((( ! Math.cos(x)) >>> 0), ( + ( ! ( + Math.imul((Math.fround(Math.atan2((x >>> 0), x)) >>> 0), ( + (( + x) ^ (( + ( ! Math.fround(1))) | 0))))))))), Math.min(((Math.atan2((y >>> 0), (( ! Math.min((Number.MIN_SAFE_INTEGER >>> 0), (x >>> 0))) >>> 0)) >>> 0) ? Math.sin((( ~ Math.pow(y, -0x080000001)) ** y)) : (( + (( + x) ? Math.hypot((y | 0), (y !== (x | 0))) : (x , x))) || x)), (( ! ((y ^ ((Math.sign((-(2**53) | 0)) | 0) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [0x080000001, 0x0ffffffff, -(2**53), -0, -0x100000001, 42, 1, 2**53-2, -(2**53+2), 0/0, -Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, 0, 2**53+2, -0x0ffffffff, 2**53, 0x07fffffff, Math.PI, -0x080000000, 0x100000000, -0x100000000, -Number.MIN_VALUE, -1/0, 1/0, 0x080000000]); ");
/*fuzzSeed-116170070*/count=663; tryItOut("var trjvbv = new SharedArrayBuffer(32); var trjvbv_0 = new Int8Array(trjvbv); trjvbv_0[0] = 13; var trjvbv_1 = new Uint16Array(trjvbv); print(trjvbv_1[0]); trjvbv_1[0] = 439324685; var trjvbv_2 = new Uint32Array(trjvbv); print(trjvbv_2[0]); trjvbv_2[0] = -16; var trjvbv_3 = new Int32Array(trjvbv); var trjvbv_4 = new Uint8Array(trjvbv); print(trjvbv_4[0]); trjvbv_4[0] = -857222589; var trjvbv_5 = new Uint16Array(trjvbv); print(trjvbv_5[0]); trjvbv_5[0] = 11; var trjvbv_6 = new Float32Array(trjvbv); trjvbv_6[0] = 14; var trjvbv_7 = new Uint8ClampedArray(trjvbv); trjvbv_7[0] = -17; var trjvbv_8 = new Float32Array(trjvbv); trjvbv_8[0] = -28; var trjvbv_9 = new Float32Array(trjvbv); print(trjvbv_9[0]); trjvbv_9[0] = -21; v0 = Object.prototype.isPrototypeOf.call(i1, o1.i0);/*bLoop*/for (var curoua = 0; curoua < 113; ++curoua) { if (curoua % 3 == 1) { print(trjvbv); } else { print(trjvbv_3); }  } f1 + o2.t0;e1.__proto__ = a0;v2 = Array.prototype.every.call(a2, (function() { try { t0 = new Float32Array(a1); } catch(e0) { } try { v0 = g2.runOffThreadScript(); } catch(e1) { } try { for (var v of b1) { try { h1.getOwnPropertyDescriptor = f0; } catch(e0) { } g2.offThreadCompileScript(\"a1[3] =  \\\"\\\" ;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: false })); } } catch(e2) { } a2.pop(b0, a1); throw o2.a1; }));(23);(\"\\u9FCD\");for (var v of o1.g2) { try { o0.g1.v0 = 4.2; } catch(e0) { } for (var p in o1) { a1.forEach((function mcc_() { var nrfyou = 0; return function() { ++nrfyou; if (/*ICCD*/nrfyou % 2 == 0) { dumpln('hit!'); try { b1.toString = f0; } catch(e0) { } try { /*MXX1*/o0 = g1.Number; } catch(e1) { } for (var v of m0) { try { g2.__proto__ = g1; } catch(e0) { } g0.toSource = (function() { try { null = t2[v1]; } catch(e0) { } i0 + s2; return t0; }); } } else { dumpln('miss!'); try { g2.g0 + ''; } catch(e0) { } try { a2.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { x = trjvbv_7[0] & 5; var r0 = trjvbv_1[0] ^ trjvbv_8[0]; var r1 = a1 ^ a7; var r2 = trjvbv_7[4] & trjvbv_7[0]; var r3 = trjvbv_8[3] ^ trjvbv_3[8]; var r4 = 0 - 0; trjvbv_4[10] = a3 ^ a7; var r5 = trjvbv_9[0] + trjvbv_5; var r6 = 4 ^ 6; var r7 = trjvbv_0 + 7; var r8 = r3 - 1; a9 = 7 ^ trjvbv_2[5]; print(trjvbv); trjvbv_8[3] = trjvbv_8[3] ^ 2; var r9 = r5 * trjvbv_7[0]; var r10 = trjvbv_8 / 7; print(trjvbv_8[0]); var r11 = 7 % 2; var r12 = trjvbv_4[0] * a11; var r13 = a3 * 0; var r14 = trjvbv_3[8] | 0; var r15 = trjvbv_8[0] - trjvbv_0[0]; var r16 = trjvbv_2 ^ 9; var r17 = 9 - a9; var r18 = r0 % trjvbv_5; var r19 = trjvbv_5[7] - 9; var r20 = trjvbv_1[10] + 9; trjvbv_4[0] = 4 & trjvbv_7[0]; var r21 = 4 & a4; var r22 = 3 + 4; var r23 = 7 & a9; var r24 = r14 & r22; trjvbv_5 = r3 - trjvbv_5[0]; trjvbv_5[7] = 2 / 9; var r25 = trjvbv_8[3] + 7; trjvbv_3 = 6 & r11; print(r11); var r26 = r22 ^ 4; var r27 = trjvbv_6 & r6; r11 = trjvbv_8[3] & r23; var r28 = 0 & a0; trjvbv_9[0] = trjvbv_6[1] ^ 2; var r29 = a1 * 8; var r30 = trjvbv_6[0] & trjvbv_7; var r31 = 0 * 9; var r32 = a2 ^ trjvbv_4; var r33 = trjvbv | r12; r18 = trjvbv_9[0] & trjvbv_3; var r34 = a5 | trjvbv_2[5]; var r35 = trjvbv_1[10] % r28; var r36 = r18 + trjvbv_2[5]; var r37 = 6 % r34; var r38 = trjvbv_8[0] - 8; var r39 = 6 % 9; var r40 = a6 - 1; r8 = r32 / r9; var r41 = r31 % 7; var r42 = 5 | 7; var r43 = trjvbv_5 | 3; var r44 = r30 + r16; var r45 = a10 % trjvbv_3[8]; var r46 = trjvbv_1[10] - 8; trjvbv_8 = r42 % 6; var r47 = r37 / r22; var r48 = trjvbv_2 / r15; var r49 = x + r11; r8 = 3 / 2; var r50 = 2 % 4; var r51 = trjvbv_5[0] & 7; var r52 = r41 & 8; var r53 = a9 * a3; var r54 = r14 | r25; var r55 = 8 - trjvbv_5[0]; var r56 = trjvbv_6[1] % 8; var r57 = 1 ^ a10; var r58 = r43 * r17; r50 = trjvbv_9[4] ^ r33; var r59 = trjvbv_1[0] ^ 8; var r60 = r17 + trjvbv_0; var r61 = 3 ^ trjvbv_6[1]; var r62 = 8 * trjvbv_0[0]; var r63 = trjvbv_3[8] - trjvbv_0[0]; var r64 = 0 + 9; var r65 = trjvbv_3[0] & r36; var r66 = r12 - trjvbv_8; var r67 = 3 - r55; var r68 = r53 % r44; var r69 = r41 & r51; print(r0); var r70 = r39 | 7; trjvbv_5[7] = r70 / r66; var r71 = trjvbv_8 - r63; var r72 = 4 ^ r64; r7 = r23 % 5; var r73 = 4 / 6; r67 = 2 / r28; var r74 = r36 | r67; var r75 = a0 - a0; var r76 = trjvbv_0[1] * r55; x = r24 % a11; var r77 = 5 / 3; var r78 = 9 | r35; var r79 = r37 / r72; r54 = r19 ^ r66; var r80 = trjvbv_5[0] / r76; var r81 = trjvbv_1[0] + 3; trjvbv_0 = r18 * r9; var r82 = trjvbv - r1; var r83 = a9 * 0; var r84 = r47 + r3; var r85 = r26 + r56; var r86 = 7 % r58; var r87 = r44 * r61; var r88 = 7 ^ r31; var r89 = r13 * 4; var r90 = a5 ^ r6; var r91 = 1 * a8; trjvbv_3[0] = r28 ^ r11; var r92 = trjvbv_3 * a9; trjvbv_2 = 3 ^ 1; trjvbv_5[7] = r31 & 7; var r93 = 7 ^ r28; r32 = 7 % r9; var r94 = r10 ^ trjvbv; var r95 = 3 / 2; var r96 = 3 | a9; print(a5); r76 = 8 - trjvbv_1[10]; var r97 = 1 * a3; var r98 = r80 & r11; r6 = 4 / 7; var r99 = 5 ^ 7; var r100 = r36 & r51; var r101 = r97 / r64; var r102 = trjvbv_4[10] & 8; var r103 = 4 + r62; var r104 = r74 | 1; var r105 = r69 ^ 4; r46 = r50 ^ 1; var r106 = 3 ^ r98; var r107 = 5 & trjvbv_6[0]; print(r50); var r108 = 6 % r60; var r109 = 1 - 7; var r110 = 4 ^ 4; r65 = 9 & r28; r78 = a9 ^ r5; var r111 = 5 % r16; var r112 = 6 + r61; var r113 = 5 + r3; var r114 = r1 - r85; print(r71); trjvbv_1 = 0 | r61; var r115 = r6 | 1; var r116 = r101 / r21; var r117 = r27 * r23; var r118 = 7 | r1; var r119 = r12 ^ 7; var r120 = trjvbv_0[1] % r23; r23 = 9 + trjvbv_5; r3 = r80 | r69; var r121 = r35 * 0; var r122 = r78 | r72; var r123 = r53 & 6; var r124 = 8 | r36; return a11; }), f2); } catch(e1) { } try { b0 = this.t0.buffer; } catch(e2) { } this.g2.v1 = (m1 instanceof f0); } };})(), m1); } }v1 = (m1 instanceof m0);");
/*fuzzSeed-116170070*/count=664; tryItOut("\"use strict\"; Array.prototype.sort.apply(a0, [String.prototype.trim.bind(i0), eval(\"m1 = new Map;\", (4277)), f0]);");
/*fuzzSeed-116170070*/count=665; tryItOut("/*MXX1*/o2 = g2.Array.prototype.map;");
/*fuzzSeed-116170070*/count=666; tryItOut("for (var p in e0) { selectforgc(o2); }");
/*fuzzSeed-116170070*/count=667; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul((( ! (Math.asin(( + (x >>> ( + Math.min(x, x))))) | 0)) ? Math.atan2(Math.fround(Math.fround(( + Math.fround(y)))), Math.fround((( - Math.fround(Math.imul(x, Math.imul(-0x100000001, -0x0ffffffff)))) >>> 0))) : ( ~ Math.fround(((y >>> 0) >= ( + (((-0x07fffffff | 0) & y) >>> 0)))))), Math.hypot(( + Math.atanh(( + Math.pow(( ! x), x)))), Math.hypot((((y >>> 0) ? (y >>> 0) : x) >>> 0), (((( + Math.fround(Math.atan2(Math.fround(x), (Number.MIN_SAFE_INTEGER >>> 0)))) >>> 0) > ((y == ( + ( + ( ~ ( + y))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [-(2**53), -0, 1.7976931348623157e308, 0x100000001, 2**53-2, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, Math.PI, -(2**53-2), 42, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, -0x080000000, -0x100000001, Number.MIN_VALUE, 2**53+2, 1, 0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 1/0, 2**53, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=668; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.exp((Math.max(Math.clz32(((( + (x | 0)) | 0) >>> 0)), ( + (( + x) > ( + y)))) | Math.abs(Math.atan2(Math.max(Math.fround((((Math.imul(y, y) >>> 0) >>> 0) < (y >>> 0))), Math.fround(-0x07fffffff)), 0x080000001)))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -0, 0x080000000, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -0x100000000, 0, 2**53-2, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, 1, -0x0ffffffff, -0x080000001, -0x080000000, -0x100000001, -(2**53-2), 1/0, -(2**53+2), 1.7976931348623157e308, 0x100000000, -1/0, 0x07fffffff, 0x080000001, Math.PI, 0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=669; tryItOut("a1.length = 4;");
/*fuzzSeed-116170070*/count=670; tryItOut("Array.prototype.pop.call(a0, t2);delete b2[\"1\"];");
/*fuzzSeed-116170070*/count=671; tryItOut("\"use strict\"; { void 0; gcslice(224896); } Array.prototype.push.call(a0, g0.m1);");
/*fuzzSeed-116170070*/count=672; tryItOut(";");
/*fuzzSeed-116170070*/count=673; tryItOut("/*infloop*/M:while([z1,,]){ void 0; try { startgc(331751); } catch(e) { } }");
/*fuzzSeed-116170070*/count=674; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return (( - (Math.fround(Math.cos(Math.fround((Math.min((y >>> 0), (Math.atan2(Math.fround(mathy0(x, (42 < y))), (mathy1((y | 0), (Number.MAX_SAFE_INTEGER | 0)) | 0)) >>> 0)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [2**53+2, -0, 0x100000001, Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, 42, -0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, Math.PI, -(2**53-2), 0/0, 2**53-2, -0x0ffffffff, -0x100000001, 0x07fffffff, -(2**53+2), -0x100000000, 2**53, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 1, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=675; tryItOut("v0 = g1.eval(\"function f0(s1) \\\"use asm\\\";   var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    return ((((Float64ArrayView[((((Uint32ArrayView[1])) == (((0xf7dc8fd5)) & ((0xffffffff))))+((1) ? (i1) : (0xfce58151))+(i1)) >> 3]))-(i1)+(0xf1b31e7d)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-116170070*/count=676; tryItOut("var gmpixd = new SharedArrayBuffer(8); var gmpixd_0 = new Float64Array(gmpixd); print(gmpixd_0[0]); a2 = [];for (var v of o0.f2) { try { ; } catch(e0) { } try { p1 + i1; } catch(e1) { } try { o0 + g1; } catch(e2) { } o1.o1 = x; }s2 = new String(t0);print(x);t1.set(t0, 7);");
/*fuzzSeed-116170070*/count=677; tryItOut("mathy4 = (function(x, y) { return ( + (( + ( - (mathy0(( ! ( + ( ~ ( + x)))), Math.fround(x)) ? ( - (( - (x >>> 0)) | 0)) : Math.fround(mathy0((mathy1((( ! (( ! (0/0 >>> 0)) | 0)) | 0), ((Math.max(y, (y >>> 0)) >>> 0) | 0)) | 0), ( - x)))))) / ( + (( ~ (Math.fround(( ~ Math.fround(y))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [({toString:function(){return '0';}}), '/0/', 0, '0', (function(){return 0;}), '\\0', ({valueOf:function(){return '0';}}), -0, [], 0.1, (new String('')), NaN, (new Number(-0)), 1, /0/, objectEmulatingUndefined(), true, false, null, ({valueOf:function(){return 0;}}), [0], (new Boolean(false)), (new Number(0)), (new Boolean(true)), '', undefined]); ");
/*fuzzSeed-116170070*/count=678; tryItOut("");
/*fuzzSeed-116170070*/count=679; tryItOut("testMathyFunction(mathy2, [2**53, 2**53+2, -(2**53), 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 42, -(2**53-2), -0x080000001, Math.PI, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, -0x080000000, -0x07fffffff, 0x080000001, -1/0, 1, Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, 0x100000000, 2**53-2, -0x0ffffffff, 0/0, 0x100000001, 1/0, -0x100000000, -0]); ");
/*fuzzSeed-116170070*/count=680; tryItOut("v0 = Object.prototype.isPrototypeOf.call(this.p0, this.m1);\nv0 = g2.runOffThreadScript();\n");
/*fuzzSeed-116170070*/count=681; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = ((1.0625) < (-1.0078125));\n    {\n      i2 = (0x69cf11c9);\n    }\n    {\nwindow;\n/(\\W|(?:([^])){1}^){4}/ym;\n    }\n    {\n      (Uint16ArrayView[2]) = (((Uint32ArrayView[1]))+(i2)-(((-0x913f4*((i1) ? (i0) : ((void shapeOf([[]] in \"\\u075B\"))))) ^ (((((0xc4798723)+(0xf886444c)+(0xfa692515))>>>((i1))))*-0x600f))));\n    }\n    i0 = ((((i1)*-0xfd21e)>>>((i2)-(i0))));\n    i2 = (i2);\n    i1 = ((0x9bdf353a));\n    switch ((((i2))|0)) {\n      case -1:\n        i1 = (i1);\n        break;\n      default:\n        i0 = ((0xfadcd1b5) >= (0xa91da125));\n    }\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ \"use strict\"; var yjgigi = (void shapeOf( /x/g )); var pbunqg = Uint8Array; return pbunqg;})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), -1/0, 0x080000001, -(2**53-2), 0x080000000, Number.MIN_VALUE, -(2**53), -0x0ffffffff, -0x07fffffff, -0, -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -0x080000001, Math.PI, 1, Number.MAX_SAFE_INTEGER, 2**53+2, 42, 0x100000001, Number.MAX_VALUE, 1/0, 0/0, 0, 0x0ffffffff, 2**53, 0.000000000000001]); ");
/*fuzzSeed-116170070*/count=682; tryItOut("mathy4 = (function(x, y) { return ( + Math.acos((mathy2(y, Math.abs((Math.abs(-Number.MAX_VALUE) >>> 0))) >>> 0))); }); testMathyFunction(mathy4, [-(2**53), 2**53, 1.7976931348623157e308, 2**53-2, Math.PI, 0x100000001, 0x100000000, -1/0, -0x0ffffffff, -0x100000001, 0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -(2**53-2), 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, -Number.MIN_VALUE, 2**53+2, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0x080000000, 1, Number.MIN_SAFE_INTEGER, 1/0, 0/0, 0x080000001, 0x07fffffff, -0x100000000, -0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=683; tryItOut("let a = (void options('strict'));/*vLoop*/for (qudilb = 0; qudilb < 30; ++qudilb) { let w = qudilb; (w); } ");
/*fuzzSeed-116170070*/count=684; tryItOut("\"use strict\"; /*oLoop*/for (wiqhbb = 0; wiqhbb < 41; ++wiqhbb) { M:if((x % 110 == 61)) { if (eval(\"( /x/g );\")) {g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: true }));v1 = this.r2.test; } else Object.defineProperty(this, \"t1\", { configurable: false, enumerable: true,  get: function() {  return new Float32Array(b2); } });} } ");
/*fuzzSeed-116170070*/count=685; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.fround(Math.sinh(Math.fround(((mathy2((Math.fround((Math.fround((y | x)) ? Math.atan2(( + -1/0), ( + ( + ( + x)))) : Math.imul((y >>> 0), Math.hypot(y, -Number.MIN_VALUE)))) | 0), (( + ( + ( + (Math.sinh(Math.fround((Number.MAX_VALUE ** Math.tan(x)))) | 0)))) | 0)) | 0) != Math.imul(Math.ceil((x ? x : Math.log1p(x))), (( + (y | 0)) | 0)))))); }); testMathyFunction(mathy5, [0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, 2**53-2, 2**53, 42, 0x080000001, 0x080000000, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 1, 2**53+2, 0/0, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), 0x100000001, 0, -(2**53), -0x0ffffffff, -0, -0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, -0x080000001, -0x080000000, 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=686; tryItOut("\"use strict\"; a1 + o1;");
/*fuzzSeed-116170070*/count=687; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=688; tryItOut("{ void 0; gcslice(31891708); }");
/*fuzzSeed-116170070*/count=689; tryItOut("g1.offThreadCompileScript(\"(p={}, (p.z = let (b) b)())\");");
/*fuzzSeed-116170070*/count=690; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.fround(Math.hypot(((mathy1((Number.MAX_VALUE >>> x), y) != ((y ? x : (x | 0)) === ( - Math.max(((x ** Math.fround(x)) | 0), (x | 0))))) >>> 0), ( + ( + y))))); }); ");
/*fuzzSeed-116170070*/count=691; tryItOut("a0 + m0;");
/*fuzzSeed-116170070*/count=692; tryItOut("\"use strict\"; var otginl = new SharedArrayBuffer(6); var otginl_0 = new Uint32Array(otginl); otginl_0[0] = -16; print(otginl_0);");
/*fuzzSeed-116170070*/count=693; tryItOut("t2 = new Uint8Array(b1, 20, 19);");
/*fuzzSeed-116170070*/count=694; tryItOut("/*infloop*/for(var x = (4277); (4277); ({eval: (4277)})) /*RXUB*/var r = /.+?|\\D*|(?=(?![\\s].)){4,}.\\3\\1(?!.)|.|.?+?|[^\\\u0018-\\t\uc6bb]|\\W|\\u00a3+?|[^\\W]\\b\\0*?|(\\B|.\\B\\b{0})|\\B?(?!\\cL{4,})|\\1*/; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-116170070*/count=695; tryItOut("\"use strict\"; print(\"\\u3DB4\");");
/*fuzzSeed-116170070*/count=696; tryItOut("mathy0 = (function(x, y) { return (( ! Math.atan((( - x) | 0))) >>> 0); }); testMathyFunction(mathy0, [0.000000000000001, -0x080000000, -0x07fffffff, 2**53-2, 0, 42, 0x080000000, -0, -(2**53-2), -0x100000001, 1.7976931348623157e308, 1, Math.PI, 0x0ffffffff, -(2**53), Number.MIN_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, -0x080000001, 2**53, -(2**53+2), -1/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, 0x100000001, Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-116170070*/count=697; tryItOut("/*infloop*/for(var e in window = [z1] *= -26) {i1.next();v2 = g0.eval(\"print(x);\"); }");
/*fuzzSeed-116170070*/count=698; tryItOut("var c, NaN = this.valueOf(\"number\"), ibckrk, eval = true, dmoimu, e, b = x, window = arguments, NaN, yrzcit;const NaN, jjeltc, d;a0.length = Math.asin(-21);");
/*fuzzSeed-116170070*/count=699; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2(Math.sin((( + (( - y) >>> 0)) >>> 0)), Math.hypot((( + y) <= ( + (Math.fround(( - Math.fround(Math.sin(x)))) <= Math.fround(Math.hypot(( + 0/0), ( + y)))))), Math.cosh(mathy3(Math.fround(Math.min((-0x07fffffff | 0), (Math.fround(Math.tan(Math.fround(x))) | 0))), (y ** x))))); }); testMathyFunction(mathy4, [(new Boolean(true)), true, '/0/', [0], ({valueOf:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), (function(){return 0;}), -0, /0/, 0, '\\0', '0', '', (new Boolean(false)), ({valueOf:function(){return 0;}}), false, ({toString:function(){return '0';}}), [], (new String('')), 1, 0.1, (new Number(0)), undefined, NaN, null]); ");
/*fuzzSeed-116170070*/count=700; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.acos((( + ( - Number.MIN_SAFE_INTEGER)) >>> 0)); }); testMathyFunction(mathy0, [({valueOf:function(){return 0;}}), [0], 0.1, false, (function(){return 0;}), '', true, NaN, (new Boolean(true)), 0, 1, [], '0', objectEmulatingUndefined(), -0, (new Number(-0)), (new Boolean(false)), /0/, '\\0', null, '/0/', (new Number(0)), undefined, ({valueOf:function(){return '0';}}), (new String('')), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-116170070*/count=701; tryItOut("v1 = evaluate(\"v2 = evalcx(\\\"/* no regression tests found */\\\", g0);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: (\u3056 = (new RegExp(\"\\\\2\", \"gyim\").throw((uneval(\"\\u3A1D\"))))) }));");
/*fuzzSeed-116170070*/count=702; tryItOut("\"use strict\"; print(uneval(this.f0));");
/*fuzzSeed-116170070*/count=703; tryItOut("v2 + '';function x(\u3056, z) { yield \u000cx } print(((void version(170))));\na => \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    switch ((imul((1), ((0x5c7b5bfa) < (0x703df064)))|0)) {\n      case -1:\n        {\n          i1 = ((0x170a1b32));\n        }\n      case -3:\n        {\n          d0 = (-268435457.0);\n        }\n        break;\n      case -1:\n        d0 = (-2251799813685249.0);\n        break;\n      case 0:\n/*iii*/Array.prototype.sort.apply(g0.a1, [String.prototype.strike.bind(o1.h1), e2, a2]);/*hhh*/function roerab(){g1.s1 = s1.charAt(6);}        break;\n      case -3:\n        i1 = (0xf8a77cd6);\n        break;\n      case -1:\n        d0 = (((-6.044629098073146e+23)) % ((d0)));\n        break;\n      case 0:\n        {\n          d0 = (-34359738367.0);\n        }\n        break;\n      case -3:\n        d0 = (1.0);\n        break;\n    }\n    d0 = ((Infinity) + (+(0.0/0.0)));\n    switch ((~~(-2097151.0))) {\n    }\n    (Uint32ArrayView[((i1)*0xd95b7) >> 2]) = ((((NaN)))-((-(i1)))-(i1));\n    return (((!(!(i1)))))|0;\n    (Float32ArrayView[((0xa609c599)+(\"\\u9E0A\".throw(eval(\"false;\")))) >> 2]) = ((d0));\n    return ((((0xfeae2704) ? ((((1)+(1))>>>((+(1.0/0.0))))) : (0xfde42062))-((d0) == (3.094850098213451e+26))))|0;\n  }\n  return f;function x(e = x++) { yield \n /x/  } t1 = new Float32Array(a1);\n '' ;\n\n");
/*fuzzSeed-116170070*/count=704; tryItOut("testMathyFunction(mathy4, [1/0, -0x080000001, 0, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff, -0x100000000, 0x100000000, 0x080000001, 0/0, -(2**53), 1, 2**53-2, -0x07fffffff, 42, 0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0x07fffffff, -0x080000000, Math.PI, 0x100000001, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-116170070*/count=705; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.abs((Math.fround(Math.log2(Math.fround((( ~ ( ~ Math.fround(Math.ceil(( + x))))) ^ ((2**53 ? (((Math.ceil((x >>> 0)) >>> 0) & (x | Math.clz32(Number.MIN_SAFE_INTEGER))) | 0) : ((Math.log10(( + ((y >>> 0) ? (x >>> 0) : (x >>> 0)))) | 0) | 0)) | 0))))) >>> 0)); }); testMathyFunction(mathy4, [-(2**53-2), 0x07fffffff, 2**53, 1/0, 42, 1, -(2**53+2), 0x080000000, 0x100000001, -0x07fffffff, 2**53-2, 0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, -1/0, 0x080000001, -0x100000000, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), 2**53+2, 1.7976931348623157e308, 0.000000000000001, -0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=706; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=707; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.imul(( + ( ! Math.fround(Math.clz32((( ! (y >>> 0)) >>> 0))))), Math.fround(( ~ Math.fround(Math.fround(mathy0(( ! -0x07fffffff), Math.fround(Math.imul((Math.fround(Math.log1p(Math.fround(x))) >= y), (( + Number.MIN_SAFE_INTEGER) | 0))))))))); }); testMathyFunction(mathy1, [-0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, 42, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 1/0, 0.000000000000001, -(2**53-2), 0, -0x100000000, 1, -Number.MIN_VALUE, Math.PI, 0x080000001, -0, 0x080000000, -0x0ffffffff, 0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), -(2**53+2), 0/0, Number.MAX_VALUE, 2**53+2, -0x080000001, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=708; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.expm1(( - (Math.hypot((Math.acosh(x) | 0), ((( ~ (( + ( ! ( + ( ! ( + x))))) >>> 0)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy2, [-0x080000001, 0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, 0x100000001, 0x080000000, -0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 2**53-2, 2**53, -Number.MAX_VALUE, 1/0, 0x080000001, -(2**53+2), 2**53+2, 1, Number.MAX_VALUE, -(2**53), -0, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, 0, 0/0, -0x080000000]); ");
/*fuzzSeed-116170070*/count=709; tryItOut("mathy1 = (function(x, y) { return ( + (( + (Math.exp(((((mathy0((Math.atan2((x >>> 0), (y >>> 0)) >>> 0), x) >>> 0) << (Math.hypot(x, Math.min(( ~ ( + y)), y)) >>> 0)) >>> 0) >>> 0)) >>> 0)) | 0)); }); ");
/*fuzzSeed-116170070*/count=710; tryItOut("m1.get(e1);");
/*fuzzSeed-116170070*/count=711; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        {\n          {\n            i0 = (i0);\n          }\n        }\n      }\n    }\n    i0 = (/*FFI*/ff(((~(((((~~(((129.0)) % ((268435457.0)))) % (((-0x4484f22)*0x8389a) >> (-(0x8bbbc30e))))>>>((/*FFI*/ff()|0)-(0xf8053ae4))))))), ((abs((((-0x8000000)) ^ ((0xfb1debdf))))|0)), ((+abs(((-7.737125245533627e+25))))))|0);\n    i0 = ((((0x9e6d4945)+(0xfbf3b540)) | (0x3a58b*((~~(576460752303423500.0))))) != (abs((0x64beaf93))|0));\n    return +((Float64ArrayView[((0x25857ec8)-(i0)) >> 3]));\n  }\n  return f; })(this, {ff: Set.prototype.clear}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[Number.MIN_SAFE_INTEGER, (1/0), (1/0), (1/0), (1/0), (1/0), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, new String(''), Number.MIN_SAFE_INTEGER, false, (1/0), (1/0), (1/0), (1/0), new String(''), new String(''), new String(''), (1/0), new String(''), (1/0), new String(''), (1/0), new String(''), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, (1/0), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, new String(''), new String(''), (1/0), (1/0), new String(''), (1/0), false, (1/0), false, Number.MIN_SAFE_INTEGER, (1/0)]); ");
/*fuzzSeed-116170070*/count=712; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Float32ArrayView[(((-0x6278ca8) < (0x7fffffff))) >> 2]) = ((d0));\n    (Float64ArrayView[4096]) = (((((0xaeed2c24)))));\n    i2 = ((0x795775aa));\n    return +((1.5474250491067253e+26));\n  }\n  return f; })(this, {ff: DataView.prototype.setInt16}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-116170070*/count=713; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return Math.fround(( ~ ( + Math.imul(-Number.MAX_SAFE_INTEGER, x)))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0x080000001, -0x100000000, 1/0, -Number.MIN_VALUE, 0x080000000, Number.MIN_VALUE, 2**53, -0x080000000, 42, -0, Math.PI, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 0, -1/0, -(2**53+2), 2**53+2, 0x100000000, -0x100000001, 0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1]); ");
/*fuzzSeed-116170070*/count=714; tryItOut("a2 + b0;");
/*fuzzSeed-116170070*/count=715; tryItOut("a1[6] = g0;");
/*fuzzSeed-116170070*/count=716; tryItOut("Object.prototype.watch.call(f0, \"__proto__\", f1);\ng0.o1 = Object.create(m1);\n");
/*fuzzSeed-116170070*/count=717; tryItOut("f0 = Proxy.createFunction(h0, f1, f1);");
/*fuzzSeed-116170070*/count=718; tryItOut("m2.__proto__ = m0;");
/*fuzzSeed-116170070*/count=719; tryItOut("o0 + e0;");
/*fuzzSeed-116170070*/count=720; tryItOut("\"use asm\"; ( '' );var z = ();");
/*fuzzSeed-116170070*/count=721; tryItOut("Array.prototype.unshift.call(a2, o0, m1, t1);");
/*fuzzSeed-116170070*/count=722; tryItOut("(x);");
/*fuzzSeed-116170070*/count=723; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.sin(((d, z != Math.max(y, (( + x) <= ( + ( ! x))))) >>> 0))) * Math.fround(( + Math.clz32(Math.fround(((Math.fround(((((y >>> 0) === (x >>> 0)) >>> 0) * (((x >>> 0) ? (y >>> 0) : (y >>> 0)) >>> 0))) ? (1/0 | 0) : ((Math.pow((Math.fround(( - (Math.max(x, (Math.pow(x, -0x080000001) | 0)) >>> 0))) | 0), (( + Math.round(0x080000000)) | 0)) | 0) | 0)) | 0))))))); }); testMathyFunction(mathy2, [-0x07fffffff, -0x100000000, 0x07fffffff, -(2**53), 42, 0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 1, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -1/0, 0x100000000, -0x0ffffffff, -(2**53+2), 0.000000000000001, 2**53+2, 1/0, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, 2**53, 0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, Number.MIN_VALUE, -0, -0x080000001]); ");
/*fuzzSeed-116170070*/count=724; tryItOut("for (var p in o0) { try { for (var v of f1) { try { ; } catch(e0) { } try { o0.a2.reverse(); } catch(e1) { } try { t1 = new Int8Array(b2, 32, v2); } catch(e2) { } for (var p in g1.a1) { try { /*MXX3*/g2.Symbol.for = g2.g0.Symbol.for; } catch(e0) { } try { p2 + b0; } catch(e1) { } try { this.h1.get = f2; } catch(e2) { } for (var v of i2) { try { o2.a1[({valueOf: function() { v1 = o1.g2.eval(\"\\\"use strict\\\"; mathy4 = (function(x, y) { return ( - (( + (( ! (x | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [2**53-2, 0, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_VALUE, -0x080000001, -(2**53+2), Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, Math.PI, 0x100000000, -0, -(2**53-2), -0x080000000, 0x07fffffff, -0x07fffffff, 0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, -0x100000001, 0/0, 2**53, 1, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 42, -0x100000000]); \");return 11; }})]; } catch(e0) { } try { m0.get(v0); } catch(e1) { } h1.valueOf = (function(a0, a1, a2, a3) { var r0 = 8 | a2; var r1 = 1 | a0; var r2 = a0 ^ 6; var r3 = r0 ^ r2; var r4 = a1 + 4; var r5 = 4 / 7; var r6 = 6 | 8; var r7 = r4 / a2; r4 = r0 | r2; a2 = 9 * 6; r3 = r6 * x; var r8 = 0 + r1; return a0; }); } } } } catch(e0) { } a0.shift(); }");
/*fuzzSeed-116170070*/count=725; tryItOut("a2.reverse();");
/*fuzzSeed-116170070*/count=726; tryItOut("mathy2 = (function(x, y) { return Math.hypot((Math.log1p((Math.fround(( + (( + ( + Math.hypot(( + Math.log(x)), ((y % 0x100000001) !== y)))) >> ( + Number.MAX_SAFE_INTEGER)))) >>> 0)) >>> 0), Math.fround(Math.hypot(mathy0((y >>> 0), Math.sign(x)), (( ! Math.max(Math.fround(( ~ Math.fround(y))), (x + Math.fround(y)))) >>> 0)))); }); testMathyFunction(mathy2, [1, true, '\\0', objectEmulatingUndefined(), '/0/', (new Boolean(true)), '0', [], (new Boolean(false)), ({toString:function(){return '0';}}), undefined, 0.1, false, [0], 0, (new Number(0)), (new String('')), /0/, NaN, -0, (new Number(-0)), (function(){return 0;}), ({valueOf:function(){return '0';}}), '', null, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-116170070*/count=727; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=728; tryItOut("mathy5 = (function(x, y) { return ((((( ! x) % Math.min((mathy4(( - 0), 0x080000001) | 0), (Math.asin(( + Math.trunc(x))) ? ( - ( + Math.PI)) : x))) | 0) <= (Math.atan2(Math.fround((Math.min(mathy0((Math.sinh(Math.fround(Math.sinh(Math.fround(x)))) | 0), (x | 0)), x) / Math.fround(Math.sign(((Math.trunc((x | 0)) | 0) >>> 0))))), Math.fround(( + ( ! (( ~ ( + (((x | 0) == ( + ( ! ( + Math.hypot((Number.MIN_SAFE_INTEGER | 0), (y | 0)))))) | 0))) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy5, [Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, 0x100000001, 0x080000001, -(2**53), -0x07fffffff, -0x080000000, 0x100000000, 0, -(2**53-2), -0, 1, -0x0ffffffff, -(2**53+2), 42, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x100000001, -1/0, 1.7976931348623157e308, 2**53+2, 0.000000000000001, 2**53-2, 0/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, Math.PI]); ");
/*fuzzSeed-116170070*/count=729; tryItOut("o0.e0.has(m1);");
/*fuzzSeed-116170070*/count=730; tryItOut("for (var v of m0) { try { v2 = t0.length; } catch(e0) { } try { g0.g1 + g1.o0.f0; } catch(e1) { } try { this.a0.forEach(offThreadCompileScript); } catch(e2) { } a1 = arguments; }");
/*fuzzSeed-116170070*/count=731; tryItOut("/*oLoop*/for (var zfdyej = 0; zfdyej < 40; ++zfdyej) { a1.reverse(); } ");
/*fuzzSeed-116170070*/count=732; tryItOut("t0[v2] = (4277);");
/*fuzzSeed-116170070*/count=733; tryItOut(";");
/*fuzzSeed-116170070*/count=734; tryItOut(";");
/*fuzzSeed-116170070*/count=735; tryItOut("{ void 0; void gc('compartment', 'shrinking'); }");
/*fuzzSeed-116170070*/count=736; tryItOut("mathy3 = (function(x, y) { return ((Math.sign(Math.cosh(Math.fround((Math.fround(Math.log(Math.hypot(Number.MIN_VALUE, Math.log10(y)))) === Math.fround(-(2**53)))))) ? Math.atan2(mathy1(( + y), (Math.min(Math.hypot(x, y), 2**53+2) ? Math.atan(( + (( + 0/0) - ( + x)))) : ( ~ x))), Math.pow(Math.pow(mathy1(x, x), y), Math.fround(Math.hypot(1/0, Math.hypot(1.7976931348623157e308, Math.acosh(-0x07fffffff)))))) : (( + Math.sqrt(Math.fround(DataView(eval)))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0/0, -(2**53+2), -0x100000000, 0.000000000000001, 0, -(2**53-2), -0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 42, Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, -0x080000001, 0x080000000, -1/0, Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, 0x080000001, 2**53, -0x0ffffffff, -0x100000001, 1/0, 1]); ");
/*fuzzSeed-116170070*/count=737; tryItOut("/*vLoop*/for (let uvcghi = 0; uvcghi < 4; ++uvcghi) { var w = uvcghi; x; } ");
/*fuzzSeed-116170070*/count=738; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.trunc(( + ( + (Math.imul(x, (x | 0)) >>> 0)))) >>> 0); }); ");
/*fuzzSeed-116170070*/count=739; tryItOut("testMathyFunction(mathy3, [-0x080000001, 0, Math.PI, 0x0ffffffff, 1.7976931348623157e308, -0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, -1/0, 0/0, 0.000000000000001, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, 42, -0x100000000, -(2**53+2), 1, Number.MAX_VALUE, 0x080000001, 2**53-2, 1/0, Number.MIN_VALUE, 0x07fffffff, -(2**53), 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -(2**53-2), 2**53]); ");
/*fuzzSeed-116170070*/count=740; tryItOut("mathy3 = (function(x, y) { return Math.sign(((Math.cbrt(Math.imul((Math.atanh(( + Math.exp(x))) >>> 0), Math.fround(Math.trunc((Math.imul(Math.fround(0x0ffffffff), Math.fround(( - Number.MIN_SAFE_INTEGER))) | 0))))) | 0) >>> 0)); }); ");
/*fuzzSeed-116170070*/count=741; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( ! ( + ( + ( + Math.round((y | 0)))))) >>> 0); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53, Math.PI, 0x080000000, 1, -0x080000000, -0x080000001, 0, -(2**53+2), 0/0, 0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 2**53-2, 0x100000000, 0x0ffffffff, -0x100000001, -0x0ffffffff, 0.000000000000001, -0x100000000, 0x07fffffff, 42, 1/0, -0, -(2**53), Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=742; tryItOut("testMathyFunction(mathy5, [-(2**53-2), -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -0, 1/0, 0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0x100000000, Number.MIN_VALUE, 0, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, 0.000000000000001, 0x100000001, 1, Math.PI, -0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -(2**53), -Number.MAX_VALUE, 2**53+2, -1/0, 0/0, -(2**53+2), 42, -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=743; tryItOut("this.s2 += s0;");
/*fuzzSeed-116170070*/count=744; tryItOut("const w, rozqam, w, c, c = (void version(170)), y;v1 = evalcx(\"function f0(i2) ((e = [window])(z)).eval(\\\"(4277);\\\")\", g0);const z = ((Math.cosh((2**53 == x)) >>> 0));");
/*fuzzSeed-116170070*/count=745; tryItOut("var qucntc = new SharedArrayBuffer(2); var qucntc_0 = new Float32Array(qucntc); qucntc_0[0] = 24; var rraxai, e, x = /(^)/ym;e2 = new Set(this.b1);for (var v of f1) { try { Object.seal(e1); } catch(e0) { } try { r2 = new RegExp(\".\\\\3(?=.[^]|\\\\b|\\\\W{1})\", \"yi\"); } catch(e1) { } try { Array.prototype.forEach.call(a1, (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((-((NaN))));\n  }\n  return f; }),  /x/g , v1, a1); } catch(e2) { } /*MXX3*/g0.Symbol.prototype = g0.Symbol.prototype; }\n[,,] +=  /x/ ;\n\n/*tLoop*/for (let x of /*MARR*/[]) { /*RXUB*/var r = /(?:(?:(?=.)*))/m; var s = \"\"; print(s.split(r));  }\n");
/*fuzzSeed-116170070*/count=746; tryItOut("/*RXUB*/var r = r0; var s = \"00V11a\\u0008\\n1a11 1\\n\"; print(s.match(r)); ");
/*fuzzSeed-116170070*/count=747; tryItOut("\"use strict\"; {(/*wrap1*/(function(){ print(x);return Array.prototype.unshift})()).callo1.e1 + p0; }for (var v of g2.i0) { try { i1.send(o0.b1); } catch(e0) { } a2 = new Array; }");
/*fuzzSeed-116170070*/count=748; tryItOut("mathy0 = (function(x, y) { return (Math.sin(Math.abs(y)) >>> (((( ! ((0.000000000000001 >>> (x >>> 0)) >>> 0)) << (y >>> 0)) >>> 0) == Math.sinh(( + 2**53)))); }); testMathyFunction(mathy0, [0x0ffffffff, 2**53, -0x080000001, Math.PI, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 42, 1/0, 0x080000001, 1.7976931348623157e308, -(2**53-2), -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, -(2**53), 0, -0x07fffffff, 0x100000000, -0, Number.MAX_VALUE, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x100000000, 0x100000001]); ");
/*fuzzSeed-116170070*/count=749; tryItOut("\"use strict\"; a2.length = 13;");
/*fuzzSeed-116170070*/count=750; tryItOut("\"use strict\"; let a = new RegExp(\"(?![\\\\\\u0008-\\\\cZ\\\\cQ\\\\S](?=.|\\\\W|.\\\\3)){3}\", \"gyim\") %= [];v0 = evaluate(\"function f2(h0)  { yield (4277) } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: !(void options('strict')), noScriptRval: true, sourceIsLazy: (a % 5 != 3), catchTermination: false }));");
/*fuzzSeed-116170070*/count=751; tryItOut("function f0(v1)  { return (4277) } ");
/*fuzzSeed-116170070*/count=752; tryItOut("print(x);");
/*fuzzSeed-116170070*/count=753; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=754; tryItOut("mathy4 = (function(x, y) { return (( ! ((((mathy1((( + (((0/0 >>> 0) == (Math.pow(x, y) >>> 0)) >>> 0)) ? Math.fround((( + (Math.atan2((x | 0), (y | 0)) | 0)) === y)) : (((y | 0) ? y : Math.fround(mathy1(x, x))) >>> 0)), Math.fround((y % Math.fround(x)))) | 0) ? (Math.max(( + y), ( + Math.hypot((Math.hypot(y, Math.hypot(x, y)) | 0), (Math.sinh((x >>> 0)) >>> 0)))) | 0) : (Math.fround(( + (Math.log2((y | 0)) | 0))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 0x0ffffffff, 1, 0x080000000, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, Math.PI, -0x080000000, 0, -0x07fffffff, -0x080000001, -0x0ffffffff, 2**53+2, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, 0x100000000, 0/0, Number.MIN_VALUE, -Number.MIN_VALUE, 42, -(2**53-2), 1/0, 2**53, -1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=755; tryItOut("\"use strict\"; var zqroxx = new SharedArrayBuffer(4); var zqroxx_0 = new Uint8ClampedArray(zqroxx); var zqroxx_1 = new Int8Array(zqroxx); print(zqroxx_1[0]); var zqroxx_2 = new Uint8ClampedArray(zqroxx); print(zqroxx_2[0]); a2.unshift(b ^ a, g2);v1 = o1.g2.runOffThreadScript();print(Object.defineProperty(a, \"16\", ({configurable: true, enumerable: (zqroxx_1[9] % 5 == 4)})));");
/*fuzzSeed-116170070*/count=756; tryItOut("b2 = t1.buffer;");
/*fuzzSeed-116170070*/count=757; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.trunc(Math.clz32(( + Math.fround((Math.fround(((mathy2((y | 0), y) | 0) || ( + (Math.log2(x) | 0)))) << Math.fround((Math.log1p((x >>> 0)) >>> 0))))))); }); testMathyFunction(mathy3, [-(2**53+2), 0, 42, -0x07fffffff, 0x080000001, -0, 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, -0x100000001, 2**53-2, 0.000000000000001, 2**53, 2**53+2, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, Math.PI, 0x100000001, 1/0, 1, 0x07fffffff, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_VALUE, 0x0ffffffff, -1/0, -(2**53-2)]); ");
/*fuzzSeed-116170070*/count=758; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.imul(( ! Math.max(( + Math.sqrt((((y != y) === (Math.fround(Math.acosh((x >>> 0))) >>> 0)) >>> 0))), -0)), ((Math.max((Math.imul(y, ( + Math.fround(Math.imul(Math.fround(y), Math.fround(y))))) >>> 0), (((y ^ x) ? y : y) >>> 0)) | 0) ? (((((Math.acos(Number.MIN_SAFE_INTEGER) | 0) | 0) ? (Math.hypot(Math.fround(/*MARR*/[new Number(1.5), new Number(1.5),  /x/ , new Number(1.5),  /x/ ,  /x/ , new Number(1.5), new Number(1.5),  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), new Number(1.5),  /x/ , new Number(1.5)]), Math.fround(Math.fround(Math.pow(Math.fround(Math.min(x, y)), Math.fround(x))))) | 0) : (y | 0)) | 0) | 0) : (Math.sinh((Math.cos((Number.MIN_SAFE_INTEGER | 0)) | 0)) >>> 0))); }); testMathyFunction(mathy4, /*MARR*/[ /x/ , objectEmulatingUndefined(), ({x:3}), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-116170070*/count=759; tryItOut("\"use strict\"; m1.set(m1, o0.o0);");
/*fuzzSeed-116170070*/count=760; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 1/0, 0x080000000, 2**53+2, 0x100000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -0x100000000, 1.7976931348623157e308, -0, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, Math.PI, -0x080000001, -Number.MAX_VALUE, -(2**53-2), 2**53-2, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, 0x080000001, -1/0, 0x0ffffffff, 0, 0/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53)]); ");
/*fuzzSeed-116170070*/count=761; tryItOut("mathy1 = (function(x, y) { return (( ! (Math.imul(mathy0(( + Math.fround(mathy0(y, Math.fround((Math.min(-0x100000001, (0x100000000 | 0)) | 0))))), ( + (Math.sin((y = y ^ y; var r0 = x & 5; print(x); var r1 = y | x; print(r1); var r2 = y | r1; var r3 = 2 / r0; r1 = r0 + 8; var r4 = 9 | r1; var r5 = 7 % r1; var r6 = x ^ r5; var r7 = 0 * r4; var r8 = x * r7; var r9 = r6 + 2; var r10 = 2 ^ 8; r3 = 8 / 0; var r11 = 3 | 6; r3 = r11 % r8; r7 = 1 | r6; var r12 = r11 | 2; var r13 = 4 + 0; var r14 = r3 * r6; var r15 = x / 6; r12 = 8 * 4; r6 = 4 / r12; var r16 = r13 + 5; x = r2 | r4; var r17 = r10 & 1; var r18 = 1 ^ r16; var r19 = r0 + 5; var r20 = 8 / r15; var r21 = r13 / 9; var r22 = r15 - 9; var r23 = 4 % r3; r17 = r2 - 3; var r24 = r13 ^ y; var r25 = 3 / r3; var r26 = r15 / 9; var r27 = r19 % r6; var r28 = r9 + 9; var r29 = r10 % r15; var r30 = r6 + r7; x = 5 | r8; print(r3); var r31 = r2 - 6; var r32 = 8 | 3; var r33 = r3 & r0; var r34 = 1 + r0; var r35 = r6 - r30; var r36 = r16 | r34; var r37 = r36 / r1; r25 = r35 - r24; r29 = r7 + r22; var r38 = r37 * r23; var r39 = r36 - r38; var r40 = r39 / 8; var r41 = 8 | r10; var r42 = 7 + r13; var r43 = 5 | r6; var r44 = 8 - 2; var r45 = r0 | 1; print(r35); var r46 = r9 & 5; var r47 = 9 * r28; var r48 = r47 / r20; var r49 = r8 ^ r38; var r50 = r22 & 6; var r51 = r48 ^ r11; r29 = 0 ^ 0; var r52 = 2 & r49; var r53 = r26 / 1; r0 = r45 ^ r21; r52 = 8 * 6; r19 = 5 | r50; var r54 = r10 / r17; r48 = 7 & 7; var r55 = 3 + r47; var r56 = r41 + 2; var r57 = r3 * 7; var r58 = r27 / r12; var r59 = r36 % r20; print(r16); r44 = r3 - r27; var r60 = r27 * 3; var r61 = r45 * r6; var r62 = r60 % 2; var r63 = r60 ^ r0; var r64 = r58 ^ 9; r11 = 5 * r9; var r65 = y - 7; var r66 = r52 * 1; var r67 = r23 + r60; var r68 = r13 ^ r44; var r69 = r50 | 8; var r70 = 8 % r53; print(r3); var r71 = r14 - r21; var r72 = r4 / 0; r34 = r53 + 6; var r73 = r62 ^ 9; var r74 = r69 * r8; r4 = r70 * r31; var r75 = 0 % r4; r67 = 2 | r9; var r76 = r58 | r18; var r77 = r18 - 9; var r78 = 8 | r24; var r79 = r38 * r34; r6 = r75 - r40; var r80 = 0 ^ 8; r47 = r68 % 2; var r81 = r60 - r24; r70 = 4 + r34; var r82 = r34 - r19; print(r42); var r83 = r17 & r31; r3 = 5 / y; r8 = 3 | r1; var r84 = r69 - r31; var r85 = 4 / r25; var r86 = r83 % r74; var r87 = r9 ^ r76; var r88 = r82 % 4; var r89 = r36 & 2; print(r27); var r90 = 8 ^ x; r31 = r30 + r81; var r91 = r8 % r85; print(r78); var r92 = r0 & r90; var r93 = r2 % r79; r77 = r93 | r23; r41 = 7 % r6; var r94 = r72 | r28; var r95 = r32 | r29; print(r1); var r96 = r11 | 2; var r97 = r31 ^ 2; var r98 = r30 * r63; var r99 = r80 ^ r20; var r100 = 6 - r82; r15 = 3 % r12; var r101 = r5 ^ r21; var r102 = r77 - r68; var r103 = r70 / r22; r67 = 2 % r83; var r104 = r27 * 5; var r105 = r20 | 1; var r106 = r41 & r71; x = r7 & r11; r15 = 6 * r65; r105 = 8 % r40; var r107 = r72 | 2; var r108 = r93 * r22; var r109 = 2 + r103; var r110 = r62 | 8; var r111 = r98 + 0; var r112 = r78 / r94; var r113 = r104 & 4; var r114 = r104 | r32; var r115 = r27 / r1; var r116 = r81 | r10; var r117 = r44 + 6; var r118 = r114 ^ r45; var r119 = r114 % r63; r45 = 6 - 3; var r120 = r110 / r115; var r121 = r95 * r62; var r122 = r16 & r4; var r123 = r33 - 2; var r124 = 4 + r93; var r125 = r120 - r82; var r126 = r40 % r36; var r127 = 4 % r19; var r128 = r48 / r101; var r129 = 0 - 9; var r130 = 0 | r70; r29 = r77 & r74; var r131 = 2 % 3; var r132 = r124 | r28; var r133 = r15 + r9; var r134 = r84 | r42; var r135 = r56 - r108; var r136 = 9 + 9; var r137 = r43 & 9; var r138 = 2 / r73; var r139 = r22 % r69; var r140 = 8 * 5; var r141 = r140 & r61; var r142 = 4 - r86; r133 = 6 ^ 3; var r143 = r92 | r74; var r144 = r57 * r92; var r145 = r94 | 4; var r146 = r54 & r49; var r147 = r29 ^ r8; var r148 = r98 * r43; var r149 = 1 | r64; r28 = r130 * r3; var r150 = 6 | 5; var r151 = r25 * r14; var r152 = r110 % r146; var r153 = r129 + r74; var r154 = 4 | 4; var r155 = r103 % 9; var r156 = r50 | 4; var r157 = r16 + r28; var r158 = r103 | r136; r79 = 4 / r125; var r159 = r27 + r93; var r160 = 4 - r132; r103 = r145 / 3; var r161 = 1 & r45; r6 = 0 ^ 4; var r162 = 9 + r108; r13 = 5 + 1; r16 = r13 - r16; var r163 = 6 - 1; var r164 = r70 & r9; r92 = r77 + r116; var r165 = 5 % r83; var r166 = r73 / 4; var r167 = r111 / r64; r93 = r2 + 7; print(r2); r68 = r129 % r1; r78 = r30 & 1; var r168 = r39 % r56; var r169 = r78 ^ 9; var r170 = r148 & r14; var r171 = r81 + r65; var r172 = r73 | r132; print(r38); var r173 = r64 - r11; var r174 = 7 - 3; r36 = r148 % r123; var r175 = r117 | 3; var r176 = 0 * 4; r9 = 3 * r162; r104 = r29 * 8; var r177 = r27 * r11; var r178 = r50 / 7; var r179 = r168 + 7; var r180 = 4 | r23; var r181 = r91 - r66;  | 0)) | 0))), (((x >>> 0) * (( ~ ( + ( ! (0/0 | 0)))) >>> 0)) >>> 0)) | 0)) | 0); }); ");
/*fuzzSeed-116170070*/count=762; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((( + ((Math.max(x, x) >>> 0) ? ((Math.min(-1/0, (y | 0)) >>> 0) >= Math.sqrt((mathy2(x, x) >>> 0))) : Math.hypot((( ~ Math.tanh(x)) >>> 0), (mathy4(Math.trunc(y), ( ~ y)) >>> 0)))) % Math.imul(Math.fround(Math.cbrt(Math.fround(( + mathy1(Math.fround(0x100000001), Math.tanh(2**53-2)))))), ( + y))) || ((((Math.round((( + Math.hypot(( + (((y >>> 0) ? (Math.max(y, -0x07fffffff) >>> 0) : (Math.max(x, y) >>> 0)) >>> 0)), ( + Math.hypot(y, 0.000000000000001)))) >>> 0)) >>> 0) >>> 0) >>> ((Math.imul(-0, y) > 2**53) | 0)) >>> 0)); }); ");
/*fuzzSeed-116170070*/count=763; tryItOut("Array.prototype.forEach.apply(a1, [g2, g2.s2])");
/*fuzzSeed-116170070*/count=764; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"\\\\w\", \"yi\"); var s = \"0\"; print(s.replace(r, 4.getUTCMonth)); ");
/*fuzzSeed-116170070*/count=765; tryItOut("testMathyFunction(mathy3, /*MARR*/[-7,  /x/g ,  /x/g , x,  /x/ , x, -7,  /x/g , x,  /x/ ,  /x/g , -7, -7,  /x/ , -7, x, x, x, -7, -7, -7, x, -7]); ");
/*fuzzSeed-116170070*/count=766; tryItOut("mathy4 = (function(x, y) { return ( ! Math.imul(( + Math.log(Math.fround(Math.atan2(( ~ ( + mathy0(Math.hypot(( + y), x), y))), y)))), Math.fround((Math.fround(( + 0x100000001)) >>> Math.fround(Math.pow(((-0x080000001 ? y : ( + (( ~ y) >>> 0))) >>> 0), ( + ( + ( + -Number.MIN_SAFE_INTEGER))))))))); }); testMathyFunction(mathy4, [-0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -0x080000000, 2**53, -0x0ffffffff, 0x100000001, -(2**53-2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, 0/0, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), -Number.MAX_VALUE, 0.000000000000001, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0, 1.7976931348623157e308, -1/0, 2**53-2, 0x080000001, 1, -(2**53+2), -0x07fffffff, 2**53+2, 0]); ");
/*fuzzSeed-116170070*/count=767; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (((((d0)) / ((-(((i1) ? (1.5) : (((-3.777893186295716e+22)) % ((-129.0))))))))) * ((d0)));\n    d0 = (Infinity);\n    i1 = (i1);\n    return (((0xff5a20e8)+(0x63da494a)-((+((((/*FFI*/ff(((-144115188075855870.0)), ((d0)), ((9.671406556917033e+24)), ((1.5474250491067253e+26)), ((-562949953421311.0)), ((-6.044629098073146e+23)), ((590295810358705700000.0)), ((-144115188075855870.0)), ((-68719476735.0)))|0)) << ((i1)+(0xffffffff))))) < (+((+(0.0/0.0)))))))|0;\n    {\n      (Float32ArrayView[((0x5eaa510f)-(i1)) >> 2]) = (([(4277)]));\n    }\n    return (((Uint32ArrayView[(((((i1)-(((d0))))|0))+(/*FFI*/ff(((257.0)), ((d0)), ((0xdfb6198)))|0)) >> 2])))|0;\n    (Float64ArrayView[((i1)+((((0xf88efc3d)+(0xfe2729db))>>>((0xfff76791)*0xc2346)) >= (( '' )>>>(-0xfffff*(0x1e7eaa39))))) >> 3]) = ((70368744177664.0));\n    (Float64ArrayView[((0xfc0766d7)) >> 3]) = ((d0));\n    {\n      d0 = (((d0)) / ((d0)));\n    }\n    i1 = (i1);\n    {\n      d0 = (d0);\n    }\n    return ((((window) != (-0xfa4d73))))|0;\n  }\n  return f; })(this, {ff: Object.prototype.isPrototypeOf}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [42, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0x100000001, 0.000000000000001, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x07fffffff, -Number.MIN_VALUE, 0x100000000, 0x07fffffff, -0, 1, Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 0, 2**53, 2**53-2, -0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 0x080000001, 0/0, -0x0ffffffff, Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-116170070*/count=768; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.fround(( + (Math.ceil(((Math.sin((Math.min(x, y) | 0)) | 0) >>> 0)) >>> 0))) - ((Math.max(y, Math.max((y && 0x0ffffffff), (x >= x))) | 0) || (( + ( ! ( + ( ! (Math.atan(y) >>> 0))))) | 0))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 2**53-2, 2**53+2, 0x0ffffffff, -(2**53-2), -0x080000000, 0x07fffffff, -0x100000000, 0, Number.MAX_VALUE, -(2**53), 0x080000000, 0/0, Math.PI, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, 2**53, -0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, -0, -Number.MIN_VALUE, 1.7976931348623157e308, 1, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-116170070*/count=769; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min(( + ( ~ (Math.pow(Math.expm1(y), ( + Math.sin((((x >>> 0) < (Math.ceil(y) >>> 0)) | 0)))) >>> 0))), Math.max(mathy2(Number.MAX_VALUE, Math.hypot(y, (( ! -Number.MIN_VALUE) | 0))), ((( ~ Math.abs(y)) | 0) * (Math.fround((Math.fround(Math.min(y, Math.log2(x))) * Math.fround(y))) | 0)))); }); testMathyFunction(mathy3, [-0x07fffffff, 0x100000000, -0, 2**53, -0x0ffffffff, 42, 1, Number.MIN_VALUE, Math.PI, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0x080000000, 0/0, 1/0, 2**53+2, 0x07fffffff, 0, 0.000000000000001, 0x080000001, -0x100000000, -(2**53-2), -0x080000000, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-116170070*/count=770; tryItOut("h0.set = (function mcc_() { var vdasfz = 0; return function() { ++vdasfz; if (/*ICCD*/vdasfz % 10 == 0) { dumpln('hit!'); try { for (var v of m2) { try { v2 = g1.eval(\"/* no regression tests found */\"); } catch(e0) { } try { m1 + h0; } catch(e1) { } try { h2.__proto__ = v0; } catch(e2) { } m0.set(o2, t1); } } catch(e0) { } try { v1 = t2.byteOffset; } catch(e1) { } p0 + m1; } else { dumpln('miss!'); g0.t1[15] = h1; } };})();");
/*fuzzSeed-116170070*/count=771; tryItOut("\"use strict\"; \"use asm\"; /*oLoop*/for (uowwhy = 0; uowwhy < 9; ++uowwhy) { g2.s1 += 'x'; } ");
/*fuzzSeed-116170070*/count=772; tryItOut("g0.m1.delete(e1);");
/*fuzzSeed-116170070*/count=773; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return (((Math.cos(((mathy0(((Math.log(((Math.atan(( + Math.atan2(( + x), ( + y)))) >>> 0) >>> 0)) | 0) >>> 0), (( - -0x0ffffffff) | 0)) | 0) >>> 0)) | 0) | 0) ** ((mathy1(((Math.imul(y, (Math.min(0, y) ? y : x)) | 0) >>> 0), (y >>> 0)) >>> 0) ^ (Math.exp(x) >>> ((Math.fround(Math.min(Math.fround(y), Math.fround(y))) % Math.tanh(Math.fround((((x | 0) > (Math.sign(Math.fround(y)) | 0)) | 0)))) | 0)))); }); ");
/*fuzzSeed-116170070*/count=774; tryItOut("o2 = new Object;o2.t1 = new Float64Array(a2);");
/*fuzzSeed-116170070*/count=775; tryItOut("var lvplpz, w = this, itktdk, this.x;(NaN);");
/*fuzzSeed-116170070*/count=776; tryItOut("m1 = t0[6];");
/*fuzzSeed-116170070*/count=777; tryItOut("L: for  each(w in (new function (...a) { \"use strict\"; yield this } ())) {/*oLoop*/for (mforlh = 0; mforlh < 54; ++mforlh) { b0 + ''; }  }");
/*fuzzSeed-116170070*/count=778; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116170070*/count=779; tryItOut("i2.next();");
/*fuzzSeed-116170070*/count=780; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.tanh(Math.fround(( + ( + ( + (((Math.max(Math.tan(Math.PI), 0.000000000000001) | 0) | (x | 0)) | 0)))))); }); testMathyFunction(mathy0, [0/0, 0x080000000, -(2**53+2), -1/0, -0x07fffffff, Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, 2**53+2, Math.PI, 0x100000001, Number.MAX_VALUE, 2**53, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), 0x080000001, -0x080000000, 0, -0x100000001, 0.000000000000001, 2**53-2, -(2**53-2), 0x07fffffff, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, 1]); ");
/*fuzzSeed-116170070*/count=781; tryItOut("mathy4 = (function(x, y) { return mathy0(Math.min(( + Math.sign((( ! (( + ( ~ ( + x))) >>> 0)) >>> 0))), (( + Math.max(( + Math.asin((y >>> 0))), (function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { var r0 = y + y; a2 = a1 % 9; var r1 = 4 - a7; var r2 = 0 % a5; a7 = 2 ^ r1; r0 = 9 / y; var r3 = 3 / a5; var r4 = r3 / r0; var r5 = 0 / a7; print(a8); x = a8 & 3; var r6 = 0 | r0; var r7 = a2 | 2; var r8 = a2 + a5; var r9 = 4 | a2; var r10 = 6 * 4; var r11 = a1 * 8; var r12 = 1 - a8; var r13 = r4 + x; var r14 = a0 - r5; var r15 = r9 + a4; var r16 = r11 - a0; var r17 = x - r11; var r18 = 4 - 8; var r19 = r4 & a5; var r20 = 4 / a4; var r21 = r17 & r0; var r22 = r8 % 1; a1 = r13 - r5; var r23 = r0 ^ r18; var r24 = r5 * 2; var r25 = r1 % a8; var r26 = r25 % 2; var r27 = r18 + a8; r17 = r7 / 5; var r28 = r17 * 2; var r29 = r27 | r13; var r30 = 7 & r14; var r31 = a0 + a3; var r32 = r24 + 8; r3 = 0 - 1; var r33 = 5 / r21; var r34 = r2 & 4; print(y); var r35 = r9 + r18; var r36 = r33 ^ r11; var r37 = 6 * r2; var r38 = a4 | x; var r39 = r11 ^ r34; var r40 = r13 ^ r39; var r41 = r3 & 2; var r42 = a0 % r4; var r43 = 1 ^ 9; r6 = r14 & 8; print(a1); var r44 = r18 ^ r34; var r45 = 6 | r11; var r46 = 9 + r10; r28 = r14 - 0; var r47 = r32 % r29; var r48 = 3 + r44; var r49 = r1 * 6; var r50 = r28 % r22; var r51 = r19 + x; r34 = r51 * r29; var r52 = r15 % 0; r43 = r8 - r7; r29 = r25 + a5; a3 = 5 % x; var r53 = a7 + 7; var r54 = r13 / r12; r40 = r15 * r8; var r55 = 9 | a4; var r56 = r21 / 3; print(x); var r57 = r35 % 7; var r58 = r26 * 7; r55 = r20 - 8; r42 = r47 - 2; print(r30); r32 = r41 + r32; r45 = r29 & r54; a6 = 5 / r28; var r59 = 9 ^ 3; var r60 = r51 - r15; var r61 = 3 + r30; var r62 = r3 + 9; r21 = r20 % r12; var r63 = 3 | 0; var r64 = r38 / r45; var r65 = r31 - r57; r16 = a1 * r12; r43 = r62 ^ r46; var r66 = a7 - r14; r58 = 5 ^ r19; var r67 = 3 % 2; var r68 = 4 & r53; var r69 = r41 / r59; var r70 = 1 & r62; var r71 = r36 - r39; var r72 = r44 & r42; var r73 = 8 * 9; r54 = r10 * r71; var r74 = 5 + 3; var r75 = r19 * 6; var r76 = r39 ^ r8; var r77 = 6 & r30; a2 = 0 / 4; var r78 = 1 - r0; print(a2); var r79 = r8 % 3; var r80 = a4 & r13; var r81 = r27 / r20; var r82 = r33 % r74; var r83 = r68 * r81; var r84 = 6 ^ r18; var r85 = r39 - r21; var r86 = 9 / 2; print(r31); print(r24); var r87 = r3 & r55; var r88 = r78 | r1; var r89 = 9 / 5; var r90 = r81 ^ 9; var r91 = 5 - r32; var r92 = r88 + r30; var r93 = r59 + r64; var r94 = r85 + 2; var r95 = r28 / 9; var r96 = r46 | r41; var r97 = 0 / r41; r91 = r3 & r80; var r98 = a7 & r14; var r99 = r30 % r78; r36 = r38 / 6; var r100 = r5 & 6; var r101 = r79 - r52; r91 = 3 ^ r96; var r102 = r47 * r48; var r103 = 4 & r37; var r104 = 8 * r55; r35 = 2 + a4; var r105 = a6 - r97; r79 = r93 * r69; var r106 = 0 ^ r81; var r107 = 1 / r0; var r108 = 7 + r38; var r109 = r7 + r45; var r110 = r6 | a7; var r111 = 1 / 2; var r112 = r6 & r46; var r113 = r16 * r69; var r114 = 8 % r37; r94 = 3 ^ r76; var r115 = r27 / 5; var r116 = r108 * r42; var r117 = 1 % r106; var r118 = 4 & r55; var r119 = 0 * 2; var r120 = r5 | r45; r35 = a0 % a2; var r121 = r57 % r6; var r122 = 1 & r79; r23 = 8 & 4; r79 = a8 & 4; var r123 = 0 + r93; r15 = r88 | r4; var r124 = r1 % a2; print(r42); var r125 = 1 % r14; var r126 = 4 - r53; var r127 = 1 ^ r57; var r128 = r107 ^ 7; var r129 = r3 & r6; a3 = 9 - r59; var r130 = r92 * r14; var r131 = r32 ^ 1; var r132 = r112 % x; var r133 = 8 & 3; var r134 = a6 ^ 2; var r135 = 4 & r36; var r136 = r89 * r28; r77 = 6 + 4; var r137 = r5 & r75; var r138 = r109 | r1; var r139 = r107 | r129; var r140 = r77 + 6; var r141 = r117 / r81; var r142 = r33 * 9; var r143 = 6 | r87; r137 = 0 + r9; var r144 = r59 & 9; var r145 = a2 / 9; var r146 = 1 | r104; var r147 = 2 / 4; var r148 = 0 * r64; var r149 = r87 & a4; var r150 = r59 + r49; return y; }))) <= ((Math.tan(( + x)) ? (Math.min((((y >>> 0) - (0 >>> 0)) >>> 0), (y >>> 0)) >>> 0) : mathy2(Math.expm1(( + (-0x100000001 / Number.MAX_SAFE_INTEGER))), 2**53)) >>> 0))), ( + (Math.log((( ~ ( ! ( ! 0x100000000))) , (x + 0))) >>> 0))); }); ");
/*fuzzSeed-116170070*/count=782; tryItOut("/*tLoop*/for (let z of /*MARR*/[new Number(1.5), new Number(1.5), function(){}, new Number(1.5),  /x/ , new Number(1.5), function(){},  /x/ , new Number(1.5), new Number(1.5), function(){},  /x/ , new Number(1.5),  /x/ , function(){}, function(){}, function(){},  /x/ , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1.5), function(){}, function(){},  /x/ , new Number(1.5), new Number(1.5), function(){}, new Number(1.5), function(){}, new Number(1.5),  /x/ , function(){}, function(){},  /x/ ,  /x/ , new Number(1.5), function(){}, new Number(1.5), function(){}, function(){}, function(){}, new Number(1.5),  /x/ , new Number(1.5), function(){}, new Number(1.5), function(){}, new Number(1.5), new Number(1.5), new Number(1.5),  /x/ , function(){},  /x/ ,  /x/ ,  /x/ , new Number(1.5), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1.5), new Number(1.5),  /x/ , function(){}, function(){}, function(){}, new Number(1.5), function(){},  /x/ , new Number(1.5),  /x/ ,  /x/ , new Number(1.5), function(){}, function(){}, function(){}, new Number(1.5), new Number(1.5), function(){}, function(){}, function(){}, new Number(1.5),  /x/ , function(){}, function(){}, function(){}, new Number(1.5), function(){}, function(){}, new Number(1.5), function(){},  /x/ , function(){}]) { print(x); }");
/*fuzzSeed-116170070*/count=783; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1((Math.asinh(( + Math.min(( + Math.min(-Number.MAX_SAFE_INTEGER, ( - ( + x)))), (Math.log2((( - x) | 0)) >>> 0)))) >>> 0), ( + ( - ( + Math.fround(Math.sqrt(Math.fround((y < 0x080000000)))))))); }); testMathyFunction(mathy2, [-0x07fffffff, -1/0, -Number.MIN_VALUE, -0x100000000, 0x100000001, -0x080000000, 2**53+2, 0x080000001, -(2**53+2), 2**53, 0x0ffffffff, Math.PI, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, 0.000000000000001, -0x100000001, 0x07fffffff, 0, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, -(2**53), Number.MIN_VALUE, 42, -0x0ffffffff, -0x080000001, 0/0, 1.7976931348623157e308, 0x080000000, -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-116170070*/count=784; tryItOut("Object.prototype.unwatch.call(m0, \"8\");");
/*fuzzSeed-116170070*/count=785; tryItOut("\"use strict\"; v2 = g1.eval(\"m1 = Proxy.create(h1, m0);\")\nprint(eval(\"\", Element()));");
/*fuzzSeed-116170070*/count=786; tryItOut("\"use strict\"; throw x;");
/*fuzzSeed-116170070*/count=787; tryItOut("/*infloop*/while((Object.defineProperty(x, \"setTime\", ({}))))Array.prototype.sort.apply(a2, [(function mcc_() { var sezftp = 0; return function() { ++sezftp; if (/*ICCD*/sezftp % 10 == 5) { dumpln('hit!'); try { o1.toSource = encodeURI; } catch(e0) { } try { a1.forEach(f2, o1); } catch(e1) { } f1 + ''; } else { dumpln('miss!'); try { m0 + v0; } catch(e0) { } o0.t0 + e2; } };})()]);");
/*fuzzSeed-116170070*/count=788; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.atan((Math.cbrt((mathy4((Math.atanh((Math.fround((Number.MIN_VALUE ? Math.fround(Math.clz32(-0x100000000)) : Math.fround(x))) | 0)) >>> x), Math.fround((Math.fround(Math.atan2(x, y)) === Math.fround(x)))) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [-(2**53+2), 2**53-2, -(2**53-2), -0, -0x07fffffff, -0x0ffffffff, 0/0, 0.000000000000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -(2**53), Math.PI, 0x080000000, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 1/0, 0x100000000, 0, Number.MIN_SAFE_INTEGER, 42, -1/0, Number.MIN_VALUE, 2**53+2, -0x100000000, -0x100000001, 1, -Number.MIN_VALUE, -0x080000001, 0x100000001]); ");
/*fuzzSeed-116170070*/count=789; tryItOut("mathy5 = (function(x, y) { return Math.expm1(Math.pow(((((( ~ (Math.fround(Math.min(Math.fround((((((y << (-Number.MIN_SAFE_INTEGER | 0)) | 0) >>> 0) != (y >>> 0)) >>> 0)), Math.fround((Math.acosh((y | 0)) | 0)))) | 0)) >>> 0) >>> 0) > (Math.fround(Math.asinh((( ~ (0x07fffffff | 0)) >>> 0))) >>> 0)) >>> 0), (( + ( - (y >>> 0))) ? ( + ( + Math.cosh(( + mathy3((y >>> 0), y))))) : ( + ( ! y))))); }); testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), 1.7976931348623157e308, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, 1.7976931348623157e308, 1.7976931348623157e308, 0x080000000, 0x080000000, 0x080000000, objectEmulatingUndefined(),  '\\0' , 1.7976931348623157e308,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), 0x080000000, arguments.caller,  '\\0' , 1.7976931348623157e308,  '\\0' , 1.7976931348623157e308, 1.7976931348623157e308, 0x080000000, 0x080000000,  '\\0' , 0x080000000, 1.7976931348623157e308, 0x080000000, 0x080000000,  '\\0' , arguments.caller, objectEmulatingUndefined(), 1.7976931348623157e308,  '\\0' , arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, 0x080000000, 0x080000000]); ");
/*fuzzSeed-116170070*/count=790; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( - ( + ( + ( + (Math.fround(( ! Math.asin(( + Math.hypot(( + 1), ( + (Math.fround(x) || y))))))) >>> 0))))) | 0); }); testMathyFunction(mathy1, [0, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 0.000000000000001, 42, Number.MIN_VALUE, 2**53+2, 2**53, 0x07fffffff, 0x080000000, -(2**53+2), -0, -(2**53), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, -(2**53-2), 2**53-2, -0x07fffffff, 1, -1/0, 0x080000001, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 0x100000001, 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-116170070*/count=791; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.fround(Math.asinh(Math.fround((((Math.atan2(( ! Math.fround(y)), (Math.hypot(y, (Math.pow(x, y) >>> 0)) >>> 0)) | 0) <= (( + (( ! x) | 0)) | 0)) | 0)))) >>> ( + ( + ( + (Math.asinh(((Math.atan2(mathy0(x, 1/0), -(2**53-2)) != Math.fround(Math.log1p(y))) | 0)) | 0))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -0x100000000, -(2**53), 1, -(2**53-2), 0, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, Math.PI, -0, 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, 0x100000000, 42, -0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, -Number.MAX_VALUE, 0x100000001, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -(2**53+2), 2**53-2, 0x07fffffff, -0x07fffffff, 0.000000000000001, 2**53+2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=792; tryItOut("a1.__proto__ = v0;");
/*fuzzSeed-116170070*/count=793; tryItOut("testMathyFunction(mathy5, [-0x080000000, 42, Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, 0, -(2**53-2), -0x07fffffff, -Number.MIN_VALUE, -0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 0/0, -0, -0x080000001, Number.MAX_VALUE, 1, 0x100000000, -0x0ffffffff, 2**53-2, -(2**53), Math.PI, 2**53+2, 0x100000001, 2**53, 0x07fffffff, 0.000000000000001, -1/0, 0x0ffffffff]); ");
/*fuzzSeed-116170070*/count=794; tryItOut("v2 = (h1 instanceof o1);");
/*fuzzSeed-116170070*/count=795; tryItOut("/*tLoop*/for (let x of /*MARR*/[new Number(1), Infinity, new Number(1), false, false, new Number(1), false, false, Infinity, Infinity, false, false, false, false, false, false, Infinity, new Number(1), new Number(1), new Number(1)]) { { void 0; try { gcparam('sliceTimeBudget', 99); } catch(e) { } } }");
/*fuzzSeed-116170070*/count=796; tryItOut("mathy4 = (function(x, y) { return Math.atan2(( + ( + ( + ( + Math.imul((x >>> 0), (x , x)))))), Math.imul(( ! x), (( ~ (mathy1(((-(2**53-2) & x) >>> 0), ((Math.fround(( + (( + y) !== 0.000000000000001))) | 0) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy4, [0.000000000000001, -0x080000000, 0, 42, -0, -0x080000001, 0x080000001, 0x080000000, 1.7976931348623157e308, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), 0x100000001, Number.MAX_VALUE, 0x0ffffffff, 2**53-2, -0x100000000, 0x100000000, -0x0ffffffff, 2**53+2, -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), 1/0, -0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-116170070*/count=797; tryItOut("\"use strict\"; f1(f2);");
/*fuzzSeed-116170070*/count=798; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.fround((mathy0(((1/0 || ((((Math.pow(y, 2**53+2) ? y : (-1/0 | 0)) | 0) && (Math.acos(Math.hypot((Math.fround(Math.atan2(( + x), Math.fround(y))) | 0), (Math.hypot(0x0ffffffff, y) | 0))) | 0)) | 0)) | 0), (( + (( + y) < Math.expm1((( ! Math.pow(x, 1)) >>> 0)))) | 0)) | 0)), (Math.fround((Math.fround((((y | 0) | (x | 0)) | 0)) / (-0 | 0))) & Math.fround(Math.fround(( + (Math.sqrt(mathy0(x, x)) | 0)))))); }); ");
/*fuzzSeed-116170070*/count=799; tryItOut("\"use strict\"; { void 0; void relazifyFunctions('compartment'); } g0.o2.v2 = (o2.s2 instanceof m0);");
/*fuzzSeed-116170070*/count=800; tryItOut("\"use strict\"; var dgiwga = new SharedArrayBuffer(3); var dgiwga_0 = new Float32Array(dgiwga); dgiwga_0[0] = -1758946252.5; var dgiwga_1 = new Uint8ClampedArray(dgiwga); dgiwga_1[0] = 6; var dgiwga_2 = new Uint8ClampedArray(dgiwga); print(dgiwga_2[0]); dgiwga_2[0] = 22; var dgiwga_3 = new Int16Array(dgiwga); dgiwga_3[0] = -14; var dgiwga_4 = new Uint8Array(dgiwga); print(dgiwga_4[0]); dgiwga_4[0] = 24; var dgiwga_5 = new Int8Array(dgiwga); print(dgiwga_5[0]); dgiwga_5[0] = -1; var dgiwga_6 = new Uint16Array(dgiwga); var dgiwga_7 = new Uint16Array(dgiwga); dgiwga_7[0] = -0; var dgiwga_8 = new Int8Array(dgiwga); dgiwga_8[0] = -15; x = t2;for (var v of p1) { try { v2 = g1.runOffThreadScript(); } catch(e0) { } (void schedulegc(g2)); }(new RegExp(\"(?=(?:.)+?|[^\\\\s][^]+?+){1,}\", \"g\"));print(uneval(this.e0));print(dgiwga_4[0]);(-17);m0 = new WeakMap;return b;");
/*fuzzSeed-116170070*/count=801; tryItOut("mathy3 = (function(x, y) { return (((Math.imul(Math.fround(Math.fround(Math.max(Math.fround(( + Math.acos((1/0 >>> 0)))), Math.fround(y)))), Math.fround(x)) >>> 0) >> ( + x)) ^ (( ~ Math.max(x, y)) >>> 0)); }); testMathyFunction(mathy3, [-0, 2**53-2, -(2**53), 0x080000001, 1/0, -0x080000001, -0x100000000, 0/0, Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, 2**53+2, 0, -0x07fffffff, 0x07fffffff, -(2**53+2), -0x100000001, Number.MIN_VALUE, 42, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 0x100000001, -Number.MIN_VALUE, 0x080000000, 0.000000000000001, Math.PI, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-116170070*/count=802; tryItOut("mathy3 = (function(x, y) { return ( + ( ! ( + (( + Math.expm1(( + mathy0(( + ( + ( + Math.fround((( + (( + y) % ( + x))) >> Math.fround((Math.cbrt(y) >>> 0))))))), ( + (((Math.atan2((-0x080000001 | 0), (0/0 | 0)) | 0) - -0x100000001) | 0)))))) <= ( + Math.fround(Math.max(Math.fround(x), (( + ( ~ ( + y))) >>> 0)))))))); }); testMathyFunction(mathy3, [0x07fffffff, 2**53, -1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, -0x080000000, 0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, Number.MAX_VALUE, -(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000000, -(2**53+2), Math.PI, 1.7976931348623157e308, 2**53-2, Number.MIN_VALUE, -0x080000001, -Number.MIN_VALUE, -0x100000001, 2**53+2, 42, 1, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, -0, 0/0, 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-116170070*/count=803; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot((( ~ x) | Math.fround(mathy1(Math.fround(mathy0(x, ( ~ Math.fround(0.000000000000001)))), Math.fround(( ! (( - (x >>> 0)) >>> 0)))))), Math.fround(( + ( ! ( ! ( + Math.tan(Math.fround(( ~ Math.fround(x)))))))))); }); testMathyFunction(mathy2, [0x080000000, 2**53+2, 1, 2**53, 0x07fffffff, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000001, 1.7976931348623157e308, Math.PI, -(2**53-2), -0x100000000, 0x100000000, 0/0, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, 0.000000000000001, -(2**53+2), 0, -0, Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 2**53-2, -(2**53), 42, -0x080000001, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=804; tryItOut("testMathyFunction(mathy4, [-0x0ffffffff, -0x07fffffff, 0, -(2**53), 2**53-2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, -1/0, -0, 1/0, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), 1, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, 2**53+2, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), -0x080000000, -0x100000001, 0x100000001, -0x080000001, 0/0, 0x100000000]); ");
/*fuzzSeed-116170070*/count=805; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.pow(Math.fround(Math.hypot(y, Math.fround(Math.min((( - Math.fround(Math.atanh(y))) | 0), (Math.fround((((-Number.MIN_SAFE_INTEGER | 0) == x) & Math.fround(x))) >>> 0))))), ( + Math.expm1(( + Math.cos(( + Math.round((Math.hypot((x >>> 0), y) >>> 0)))))))) | 0), (Math.fround(Math.hypot(((( - (x | 0)) | 0) >>> 0), ( + Math.max(Math.tan((x | 0)), Math.fround(Math.hypot(Math.fround(x), (Math.pow(y, Math.fround(( ! (x >>> 0)))) | 0))))))) | 0)) | 0); }); ");
/*fuzzSeed-116170070*/count=806; tryItOut("testMathyFunction(mathy5, [0x07fffffff, 2**53-2, -Number.MAX_VALUE, 1, 1/0, -1/0, Math.PI, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 0, 0.000000000000001, 0x100000001, 0x100000000, -(2**53+2), -(2**53), -0x080000000, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0, 0x080000001, 2**53+2, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 0x080000000, 2**53, -0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-116170070*/count=807; tryItOut("testMathyFunction(mathy1, [0x100000000, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, 0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53, 0, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, 1, Number.MIN_VALUE, -0x07fffffff, -0x080000000, 2**53-2, -0, 0.000000000000001, -0x100000001, -0x100000000, -(2**53), 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, 42, Math.PI]); ");
/*fuzzSeed-116170070*/count=808; tryItOut("v1 = g0.t0.length;");
/*fuzzSeed-116170070*/count=809; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=810; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return Math.log1p(Math.sqrt(((( + (( - (y >>> 0)) >>> 0)) & ( + (( ! 1/0) | 0))) | 0))); }); testMathyFunction(mathy2, [0x080000001, -0x080000000, -(2**53+2), 0x100000000, -0x100000000, -1/0, 0x0ffffffff, 0, -Number.MIN_VALUE, -0x100000001, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, 1.7976931348623157e308, 42, 2**53, Number.MIN_VALUE, 1/0, 2**53+2, -0x0ffffffff, 2**53-2, 0.000000000000001, 0/0, -(2**53), 0x100000001, -0x080000001, -(2**53-2), Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE, -0x07fffffff, -0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116170070*/count=811; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((Math.fround(( - Math.fround(( - Math.fround(Math.atan2(Math.fround(y), ( + y))))))) , ( + (Math.fround(( + Math.fround(Math.hypot(x, ( - ( + y)))))) >> Math.pow(( ~ ((( - -0x100000000) >>> 0) << y)), Math.round(Math.fround(x)))))) ^ (((( ~ (( + (( + (y ** x)) ^ Math.fround(x))) | 0)) | 0) >>> 0) << Math.fround(Math.log(( + ( - x)))))); }); testMathyFunction(mathy2, [-1/0, -0x080000001, -(2**53+2), -0x07fffffff, 0x080000001, -0x100000000, 1, -(2**53-2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 1/0, 0.000000000000001, 0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 42, 2**53, 0x100000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x0ffffffff, -0, 0x100000000, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, 0, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -(2**53), 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=812; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + (( - (Math.sin(Math.cbrt(x)) | 0)) << Math.clz32(((( - (((mathy3(y, -(2**53-2)) - y) != (-0 >>> 0)) >>> 0)) | 0) % ((Math.asinh((Math.fround((Math.fround(x) != Math.fround(x))) >>> 0)) >>> 0) ? Math.hypot(-0x100000000, ( + (Math.sinh(Math.fround(( ~ 0x080000000))) | 0))) : ( + y)))))); }); testMathyFunction(mathy5, [-0x07fffffff, 0x0ffffffff, 0x080000000, 42, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, 0, -(2**53), 2**53, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, -0x080000000, 0x080000001, 1.7976931348623157e308, -0x080000001, 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, -0, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, 1, 0.000000000000001, 1/0, -(2**53-2)]); ");
/*fuzzSeed-116170070*/count=813; tryItOut("s2 += s2;\nprint(x);\n");
/*fuzzSeed-116170070*/count=814; tryItOut("this.h0.iterate = f2;");
/*fuzzSeed-116170070*/count=815; tryItOut("\"use strict\"; Array.prototype.push.apply(a0, [o2.f2]);");
/*fuzzSeed-116170070*/count=816; tryItOut("\"use strict\"; if(\"\\u1705\") {print( \"\" );g1 = i0; }{; }");
/*fuzzSeed-116170070*/count=817; tryItOut("\"use strict\"; /*infloop*/M:while(Array.of(((-28 &&  \"\" ).eval(\"0\")), (4277))){(undefined); }");
/*fuzzSeed-116170070*/count=818; tryItOut("s1 = new String(o0.s0);");
/*fuzzSeed-116170070*/count=819; tryItOut("testMathyFunction(mathy2, /*MARR*/[[1], false, objectEmulatingUndefined(), false, true, false, false, true, new Number(1.5), [1], true, true, objectEmulatingUndefined(), new Number(1.5), true, false, false, true, new Number(1.5), false, objectEmulatingUndefined(), new Number(1.5), true, false, [1], new Number(1.5), [1], false, objectEmulatingUndefined(), false, new Number(1.5), new Number(1.5), [1], true, new Number(1.5), false, objectEmulatingUndefined()]); ");
/*fuzzSeed-116170070*/count=820; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -0.0078125;\n    i1 = (i2);\n    return (((i0)))|0;\n    /*FFI*/ff(((((!(((((-0x8000000) < (-0x8000000))) | ((Uint8ArrayView[2])))))) | ((0xfb62a073)))));\n    (Uint16ArrayView[(((0x6345a98b) <= (((0xfd5a6c4b)+(0xc07cb201))>>>((i0))))*-0x21e17) >> 1]) = (((0x21c789ef) != (((((0xffffffff)+(0xbdcf8983))>>>((0xffba13fe)+(0xa38c0aa6))) / (0x51841980))>>>(((((i1)*0x8b7ff)>>>(((((Int16ArrayView[2]))))))))))-((NaN) <= (4096.0)));\n    {\n      i0 = (i2);\n    }\n    {\n      return (((0xffffffff) / ((((0xffffffff) == (0xfa533eb5))+((((0xa7ab3c10) % (0x14bc2572))>>>(((3.022314549036573e+23) < (4503599627370497.0))+((0xffffffff))))))>>>(((((((0xda804622)) >> ((0xfb5e925f))) % (((0xfba28881)) & ((0x374369c5))))>>>(x)))))))|0;\n    }\n    d3 = (-147573952589676410000.0);\n    return (((Int32ArrayView[((i2)-(0xffe048fd)+((i2) ? ((0xfaa97fe4) ? (0xf8c701d1) : (0x382e8d5c)) : (i2))) >> 2])))|0;\n  }\n  return f; })(this, {ff: Element}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 0x080000001, -(2**53), 2**53+2, -1/0, -0x080000000, 0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, 1, -(2**53-2), -0x100000000, 0x0ffffffff, -0, 0x100000000, Number.MAX_VALUE, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, 42, -Number.MIN_VALUE, 1/0, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, 0, -(2**53+2), 2**53, 2**53-2, 0x100000001]); ");
/*fuzzSeed-116170070*/count=821; tryItOut("let (w) { a2[14] = s0; }");
/*fuzzSeed-116170070*/count=822; tryItOut("\"use strict\"; v0 = evaluate(\"function f0(f0)  { s0 = new String; } \", ({ global: o1.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 != 2), noScriptRval: (x % 5 == 2), sourceIsLazy: (x % 5 == 0), catchTermination: false }));");
/*fuzzSeed-116170070*/count=823; tryItOut("\"use asm\"; M:with((({configurable: (x % 2 == 0)}))){continue ;(undefined); }");
/*fuzzSeed-116170070*/count=824; tryItOut("");
/*fuzzSeed-116170070*/count=825; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.clz32((Math.sign(Math.max((mathy1(Math.fround((y >= -Number.MIN_VALUE)), Math.fround(( - (x >>> 0)))) === (Math.max((0x100000001 | 0), (Number.MAX_SAFE_INTEGER | 0)) | 0)), ( + ( + Math.log10(Math.fround(((-(2**53) >>> 0) && (-(2**53+2) >>> 0)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x100000000, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -(2**53), 0x100000001, -0x080000000, Math.PI, 0, 1.7976931348623157e308, -0, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, -0x0ffffffff, -Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0x07fffffff, 0x080000001, 42, -0x100000000, 2**53+2, 1, 2**53-2, 0/0, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0]); ");
/*fuzzSeed-116170070*/count=826; tryItOut("");
/*fuzzSeed-116170070*/count=827; tryItOut("e2.has(g1);");
/*fuzzSeed-116170070*/count=828; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\D\", \"ym\"); var s = \"a\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=829; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=830; tryItOut("L:for(x = x = \"\\uD2D4\" in ((function sum_indexing(uygupb, xutotg) { ; return uygupb.length == xutotg ? 0 : uygupb[xutotg] + sum_indexing(uygupb, xutotg + 1); })(/*MARR*/[ /x/g , (void 0), (void 0),  /x/g , (0/0),  /x/g , (0/0),  /x/g , (0/0), (void 0), (0/0),  /x/g , (0/0), (0/0),  /x/g , (void 0),  /x/g ,  /x/g , (0/0), (void 0),  /x/g ,  /x/g , (void 0), (0/0), (void 0), (0/0), (0/0), (0/0),  /x/g ,  /x/g ,  /x/g ,  /x/g , (0/0), (0/0), (0/0), (void 0), (void 0), (void 0), (void 0), (0/0), (0/0), (0/0), (0/0), (void 0), (void 0),  /x/g ,  /x/g ,  /x/g , (0/0), (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (0/0), (void 0),  /x/g , (void 0),  /x/g , (0/0),  /x/g , (void 0), (void 0), (0/0),  /x/g , (0/0),  /x/g ,  /x/g , (0/0), (0/0), (void 0), (void 0), (void 0), (0/0), (void 0), (void 0), (0/0), (0/0),  /x/g , (0/0), (void 0), (0/0), (void 0),  /x/g ,  /x/g , (0/0), (0/0), (0/0), (0/0), (0/0), (void 0), (0/0),  /x/g , (0/0), (void 0), (0/0), (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (0/0), (void 0),  /x/g , (void 0), (void 0), (void 0), (0/0), (void 0), (void 0),  /x/g , (void 0), (0/0), (0/0), (0/0),  /x/g , (0/0),  /x/g ], 0))) {v2 = g2.runOffThreadScript();g0.e2.add(o0); }");
/*fuzzSeed-116170070*/count=831; tryItOut("\"use strict\"; window;");
/*fuzzSeed-116170070*/count=832; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i1, p1);");
/*fuzzSeed-116170070*/count=833; tryItOut("\"use strict\"; {(\"\\u23CB\"); }");
/*fuzzSeed-116170070*/count=834; tryItOut("m2.get(b0);");
/*fuzzSeed-116170070*/count=835; tryItOut("do {a1.splice(-5, 19, (new (Int8Array)(x,  \"\" )));var ommpeg = new SharedArrayBuffer(16); var ommpeg_0 = new Float32Array(ommpeg); print(ommpeg_0[0]); ommpeg_0[0] = 0x07fffffff; v1 = a1.length; } while((x = x) && 0);");
/*fuzzSeed-116170070*/count=836; tryItOut("\"use strict\"; /*RXUB*/var r = /\\b/gim; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-116170070*/count=837; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.imul(Math.fround(mathy0(Math.fround((mathy0((mathy0(0x07fffffff, ( + ( - y))) >>> 0), (Math.atan((mathy0(y, y) | 0)) >>> 0)) >>> 0)), Math.fround(( + mathy0(Math.asin((Math.imul(Number.MAX_VALUE, (y >>> 0)) >>> 0)), Math.min((mathy0((y | 0), (x | 0)) | 0), ((Math.hypot((Math.fround((x * Math.fround(0x080000001))) >>> 0), (x >>> 0)) >>> 0) >>> 0))))))), Math.fround((Math.atan2(((( ! Math.imul(x, y)) >>> Math.fround(Math.atan2(Math.fround(((y >>> 0) === Math.fround(Math.atanh(( + x))))), y))) >>> 0), ((( ! ( + ( + x))) == (Math.sign((Math.min(0, x) | 0)) | 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 0/0, -0x100000001, -Number.MAX_VALUE, 0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, 42, 0.000000000000001, -0x0ffffffff, 0x07fffffff, -0x080000000, 1.7976931348623157e308, -0x100000000, -0, Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, Math.PI, 1, 2**53-2, -(2**53-2), 1/0, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 0x080000000, 0x080000001, -1/0, 2**53+2]); ");
/*fuzzSeed-116170070*/count=838; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ (Math.fround((Math.fround(Math.clz32(Math.sqrt(Math.fround(y)))) != (mathy3(Math.fround(mathy0(( + (( + 1.7976931348623157e308) / ( + y))), Math.fround((( - x) >>> y)))), Math.fround(Math.pow(((Math.fround(( + Math.fround(( + 0)))) / (Math.trunc(y) | 0)) | 0), Math.fround((Math.tan(x) | 0))))) | 0))) | 0)); }); testMathyFunction(mathy4, [-0, 0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, 42, 0x0ffffffff, -0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, 0/0, -0x07fffffff, 2**53, 1, 0x07fffffff, 0, 0x100000000, 2**53+2, -1/0, Math.PI, -0x080000001, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), 1/0]); ");
/*fuzzSeed-116170070*/count=839; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy2(Math.fround(Math.sin(Math.fround(Math.min(Math.fround(Math.ceil(Math.fround(y))), y)))), (Math.asin(((( + Math.clz32(( + Math.fround(( ~ -0x080000001))))) >>> 0) * ((Math.fround(-Number.MAX_VALUE) >> (Math.tanh(y) >>> 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy4, [0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, -0x100000000, -(2**53+2), -(2**53-2), 2**53, 0x080000000, -0x080000001, 2**53+2, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 1, -0x07fffffff, -Number.MAX_VALUE, 0x100000001, 0, 0x080000001, Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0.000000000000001, Math.PI, 0/0, Number.MAX_VALUE, 0x100000000, -1/0, 42]); ");
/*fuzzSeed-116170070*/count=840; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -35184372088833.0;\n    {\n      {\n        d1 = (+(((0xc709cb13)*0x173b6)|0));\n      }\n    }\n    return +((d1));\n    {\n      {\n        d1 = (Infinity);\n      }\n    }\n    d1 = (((Float64ArrayView[((0xb381c11b) / (0xffffffff)) >> 3])) % (((+/*FFI*/ff(((((0.0625) > (-9.44473296573929e+21)) ? (+(((0xee9c92f8))>>>((0x67269a80)))) : (NaN))))) + (-0.5))));\n    d1 = (d1);\n    d2 = (((+abs(((d1))))) - ((Float64ArrayView[1])));\n    return +(new (delete x.x)((4277)));\n  }\n  return f; })(this, {ff: Object.values}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -(2**53), -Number.MAX_VALUE, 0x100000000, 0x100000001, 42, -(2**53-2), 2**53+2, 0x080000000, -0x080000000, Math.PI, Number.MAX_VALUE, -0x0ffffffff, 1, 0x07fffffff, -(2**53+2), 0x080000001, 2**53-2, 0x0ffffffff, 1/0, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, -0, -0x100000000, 0, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=841; tryItOut("t0.__proto__ = s2;function \"15\"(of, {}, y, b, w, a, a, x, x, z, b = [1,,], x, x, d, window, window = undefined, a, y, z, eval, x, z, this.x, x, x = /(?=\\2{3,}|(\\s)|u|[^]*?[^](?:.)[^]*?{2,6})/gym, x, e = /(?=(?!\\3))/gyim, x, this.x, c, x, x, x = this, a, e =  \"\" , x, x, c, x, x, e, x, e, \u3056, b, x, x, c, NaN, x, y, x, x, b, x, y, \u3056, w, x, x, e, x, x, eval = -29, d, a, d, \u3056, c, NaN, c, e, w, window, w, x, z, b) { yield (true()) } x = h2;");
/*fuzzSeed-116170070*/count=842; tryItOut("Array.prototype.shift.apply(a0, [((p={}, (p.z = (4277))())), a1, h0, b1, p1, p0, g2.p2, a2, a1]);");
/*fuzzSeed-116170070*/count=843; tryItOut("with(({2: -29 }))this.h1 = {};");
/*fuzzSeed-116170070*/count=844; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((((((Math.atan2((Math.ceil((0/0 >>> 0)) >>> 0), Math.min(0x080000000, ( ~ y))) >>> 0) ** Math.fround(( ! Math.fround(Math.atan2(Math.fround(Math.fround((Math.fround(y) & x))), ( + ( ~ -0x080000001))))))) >>> 0) | 0) ? (Math.max(( + (Math.fround(( ! (Math.min(((Math.fround(x) ** y) | 0), Math.pow(x, (Math.sin((y | 0)) | 0))) >>> 0))) ? y : Math.clz32(Math.round(-0x080000001)))), ( - ( + (( + x) ** ( + 0x100000001))))) | 0) : Math.fround(Math.fround(Math.expm1(((( + Math.hypot(( + ((x ? ( + y) : ( - ( + x))) >>> 0)), ( + ((2**53+2 << Math.fround(x)) >>> 0)))) ** x) >>> 0))))) | 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, -(2**53+2), -(2**53-2), 0x100000000, -0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53, -0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0.000000000000001, 0/0, 2**53+2, 0, 42, 0x07fffffff, 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x100000001, Number.MIN_VALUE, -0x100000000, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, 0x080000000, -1/0, 1]); ");
/*fuzzSeed-116170070*/count=845; tryItOut("\"use strict\"; ;");
/*fuzzSeed-116170070*/count=846; tryItOut("m0.set(a2, v2);");
/*fuzzSeed-116170070*/count=847; tryItOut("a0[({valueOf: function() { var c = [--z];h2.set = f1;return 5; }})];");
/*fuzzSeed-116170070*/count=848; tryItOut("for (var p in e2) { e1.add(f1); }");
/*fuzzSeed-116170070*/count=849; tryItOut("\"use strict\"; /*MXX3*/g2.DataView.prototype.setUint32 = g1.DataView.prototype.setUint32;");
/*fuzzSeed-116170070*/count=850; tryItOut("h0.get = (function() { try { Array.prototype.splice.call(a0, -1, Math.ceil(-20), i0); } catch(e0) { } try { s1 += 'x'; } catch(e1) { } for (var p in this.e1) { h0.getOwnPropertyDescriptor = DataView.prototype.getUint32; } return m2; });");
/*fuzzSeed-116170070*/count=851; tryItOut("print( \"\" );");
/*fuzzSeed-116170070*/count=852; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return +((Float32ArrayView[((-0x8000000)) >> 2]));\n  }\n  return f; })(this, {ff: false}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1.7976931348623157e308, 0/0, -1/0, -0x100000000, 0x07fffffff, 0x100000001, 0x080000000, 42, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 2**53, -0x100000001, -Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -(2**53), 0x100000000, 0x080000001, Math.PI, -(2**53-2), -(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -0x080000001, 1/0, 0, -0, -0x080000000, 0x0ffffffff, 1]); ");
/*fuzzSeed-116170070*/count=853; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return ( - (((( - Math.expm1(y)) >>> 0) >>> (Math.fround(( ~ Math.fround((Math.hypot(((y === y) | 0), (x | 0)) | 0)))) | 0)) | 0)); }); testMathyFunction(mathy3, [2**53-2, 0, 0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, -0x100000000, -0, 1, Math.PI, Number.MIN_VALUE, 0x100000000, -0x080000001, 0.000000000000001, -(2**53), -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 42, 1/0, Number.MAX_VALUE, 2**53+2, -(2**53-2), 0/0, -1/0, 2**53, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=854; tryItOut("/*MXX2*/g2.WeakMap = e2;");
/*fuzzSeed-116170070*/count=855; tryItOut("yield x;function x(x, x, [, [], ], b, c, d, window, [], \u3056, a, a, x, y, x, x, a, x = 25, a, x = false, x, x, eval, x, y, NaN, w, NaN, e, w, x, w, e, b, x, e, z =  '' , y, d, x, w, a = 0xB504F332, eval, x, c, this.x, \u3056, a, x = [,,z1], \u3056, NaN, w, d, x, x, a, w, \u3056, \u3056, eval = 2, x, e, c, d, eval, window =  '' , d, c, x, window = new RegExp(\"(?!\\\\u0072([\\\\s]([^\\\\b\\\\u00BA\\\\s\\\\d])))*?\", \"gyim\"), a, window, x, x, x, y = this) { return  /x/g  } g2.g0.offThreadCompileScript(\"function f0(i2)  { /*infloop*/for(var b = /\\\\3/g; true; false) {({});(window); } } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 != 4), sourceIsLazy: true, catchTermination: false, elementAttributeName: s1, sourceMapURL: s2 }));");
/*fuzzSeed-116170070*/count=856; tryItOut("mathy0 = (function(x, y) { return Math.fround(( - Math.fround((( + Math.trunc(( + (( ! (((x !== y) != Math.min(-Number.MIN_SAFE_INTEGER, y)) | 0)) >>> 0)))) >= Math.fround(( ~ ((Math.min(Math.fround(Math.sign(( + y))), Math.fround(Math.fround(( ~ Math.fround((Math.fround(x) & Math.fround(x))))))) | 0) >>> 0))))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 1/0, 0/0, -0x100000000, -0, -0x080000001, Number.MIN_VALUE, -1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, -Number.MAX_VALUE, 42, Math.PI, -0x07fffffff, -(2**53+2), 1.7976931348623157e308, -0x080000000, 0x080000000, 0x100000001, -0x0ffffffff, 2**53, 0, 0x100000000, 2**53+2, 0.000000000000001, -(2**53), 0x0ffffffff, 1, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=857; tryItOut("\"use strict\"; Array.prototype.push.apply(a1, [t0, s1, s1, b2]);");
/*fuzzSeed-116170070*/count=858; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((mathy0(((((Math.hypot(Math.atanh((x >>> 0)), x) >>> 0) !== ((mathy2(( - y), ( + (x >> (((-1/0 | 0) ? (x | 0) : (Number.MIN_VALUE | 0)) | 0)))) >>> 0) >>> 0)) >>> 0) >>> 0), (( + (Math.sqrt(y) == y)) >>> 0)) >>> 0) ? (Math.sign((Number.MAX_VALUE ? (-Number.MAX_VALUE | 0) : Math.fround(((y | 0) & (y | 0))))) << ((Math.fround(mathy1(Math.fround(( + y)), Math.fround((( ~ (Math.fround((Math.fround(-0x080000001) % Math.fround(y))) >>> 0)) >>> 0)))) >>> 0) << (Math.tan(( + -(2**53+2))) >>> 0))) : Math.fround(Math.min(mathy1(Math.fround((( + ((Number.MAX_SAFE_INTEGER >>> 0) | (x ? Math.min(y, y) : -(2**53-2)))) ? ( + x) : ( + x))), Math.fround(Math.atan2(( - y), Math.hypot(mathy0(x, ( + x)), (x - Math.fround(Math.min(y, y))))))), mathy1(( + Math.cbrt(( + y))), ( + mathy1(( + Math.sinh(( + (mathy2((( + x) >>> 0), (Math.clz32(x) >>> 0)) >>> 0)))), x)))))); }); ");
/*fuzzSeed-116170070*/count=859; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a2, [(function() { try { m0.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 65537.0;\n    var d3 = -1.015625;\n    var i4 = 0;\n    d1 = (+(1.0/0.0));\n    return (((!(i0))-((((0x97d804c0)) & ((i4)+((~((-0x8000000)+(0xfd21116a)+(0xd0f7bc63)))))) <= (((((Uint16ArrayView[4096])))) & ((i0)+(/*FFI*/ff(((d1)))|0))))+((((0x3e3d137f)+(0x9b7a6404)) | (x)) <= (((0xfc8da626)) << (((0xfacf1c8f) == (((-0x8000000))>>>((0x164f53aa)))))))))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); } catch(e0) { } v1 = (m0 instanceof b1); return g0.b0; }), e1, this.v0]);");
/*fuzzSeed-116170070*/count=860; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -576460752303423500.0;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    return +((Float32ArrayView[((i5)-(i5)) >> 2]));\n  }\n  return f; })(this, {ff: DataView.prototype.setFloat64}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Math.PI, -0x080000001, -0x100000000, -Number.MAX_VALUE, 0x100000000, -(2**53-2), -0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, 0x080000001, 0x100000001, 2**53+2, 0x07fffffff, 1, -1/0, -0x100000001, 42, 1/0, 0, -0x07fffffff, 0x080000000, 0.000000000000001, 2**53-2, 0/0, -Number.MIN_VALUE, 2**53, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-116170070*/count=861; tryItOut("Object.defineProperty(this, \"t0\", { configurable: (x % 3 == 2), enumerable: true,  get: function() { e0.has(\"\\u0D83\"); return new Int8Array(a2); } });");
/*fuzzSeed-116170070*/count=862; tryItOut("\"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (1024.0);\n    }\n    {\n      (Uint8ArrayView[(Math.asin(((function ([y]) { })() /= x))) >> 0]) = ((!(i1))+((((~~((0xffe3929b) ? (-65.0) : (8589934593.0))) % (~((0xfcfcc702)-(0x1d76339d)))) >> (((~~(549755813889.0)) > (-0x706c553))-(i1))) <= (abs((((Int8ArrayView[((0x90ebab61)+(0x249fc65)) >> 0])) ^ (((-0x8000000))-((0x6f6ca96a))-((0xd4aecf39)))))|0))+(i1));\n    }\n    d0 = (+abs(((-4.835703278458517e+24))));\n    d0 = (d0);\n    i1 = (0x2e313f7f);\n    i1 = (i1);\n    d0 = (d0);\n    (Int32ArrayView[4096]) = ((i1)+(0xd026b053));\n    i1 = ((((Infinity))) < (+(~((Int8ArrayView[1])))));\n    {\n      {\n        (Float64ArrayView[((!((((((0xf9888c33)) >> ((0xe6d797c0))) % (((0x8be3e4e6))|0))|0)))) >> 3]) = ((+(((i1))>>>(((524288.0) < (arguments =  \"\" ))*-0x96e21))));\n      }\n    }\n    {\n      i1 = (i1);\n    }\n    i1 = (i1);\n    d0 = (+pow(((((-17592186044417.0)) * (((((4277))) * ((-1048577.0)))))), ((((NaN)) % (((0xf83dd9b1) ? (+/*FFI*/ff(((d0)), ((imul((-0x8000000), (-0x8000000))|0)), ((-140737488355329.0)))) : (d0)))))));\n    return (((!(i1))-(0xf95f51c8)))|0;\n  }\n  return f; })(this, {ff: Number.isNaN}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [(new Boolean(true)), 0.1, null, (new String('')), (new Boolean(false)), '/0/', '\\0', undefined, 0, true, [], ({valueOf:function(){return 0;}}), /0/, ({toString:function(){return '0';}}), 1, [0], objectEmulatingUndefined(), -0, (function(){return 0;}), '0', '', (new Number(-0)), NaN, ({valueOf:function(){return '0';}}), (new Number(0)), false]); ");
/*fuzzSeed-116170070*/count=863; tryItOut("function f1(f0)  { \"use asm\"; return c } ");
/*fuzzSeed-116170070*/count=864; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( - Math.abs((((((Math.atan2(y, ( + Math.expm1(( + y)))) | 0) * x) >>> 0) | 0) < Math.fround((((x || (Math.imul((x | 0), -0x080000001) | 0)) | 0) === ((( + x) ? Math.min(x, y) : x) >>> 0)))))); }); ");
/*fuzzSeed-116170070*/count=865; tryItOut("\"use strict\"; a0 = a1.slice(NaN, 0);");
/*fuzzSeed-116170070*/count=866; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0, (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Number(-0)), [], (new String('')), /0/, '', '0', objectEmulatingUndefined(), false, true, 1, [0], '/0/', (new Boolean(false)), 0, (new Boolean(true)), (new Number(0)), ({toString:function(){return '0';}}), '\\0', 0.1, NaN, ({valueOf:function(){return 0;}}), null, undefined]); ");
/*fuzzSeed-116170070*/count=867; tryItOut("\"use strict\"; a1.reverse();");
/*fuzzSeed-116170070*/count=868; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.acosh((( + (( + (Math.atan2(((0 ? 1.7976931348623157e308 : Math.fround((Math.fround(x) + Math.fround(y)))) >>> 0), (x >>> 0)) >>> 0)) ? Math.fround(x) : ( + ((Math.fround(( + 42)) / (((( + (((mathy0(Number.MAX_SAFE_INTEGER, y) | 0) | 0) >> x)) >= (0.000000000000001 >>> 0)) >>> 0) | 0)) | 0)))) & mathy3(( + Math.acos(x)), Math.min((Math.atan2(Math.fround(x), Math.fround(1/0)) >>> 0), Math.fround(Math.fround((Math.fround(y) ? Math.fround(Math.cosh(0x100000001)) : Math.fround(( + y))))))))) | 0); }); ");
/*fuzzSeed-116170070*/count=869; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(?=(([^]|\\\\w)))(?:(?:..)|\\\\B|.)|[^])|((?:.|([^])\\\\b))+{0,}\", \"gi\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116170070*/count=870; tryItOut("\"use strict\"; \"use asm\"; g1.m2.set(-4.yoyo(6), i1);");
/*fuzzSeed-116170070*/count=871; tryItOut("\"use strict\"; for(let x in x) t2[19];");
/*fuzzSeed-116170070*/count=872; tryItOut("/*infloop*/for(let [[, {d, a: x, getter, this.\u3056: [[], x], x: [, {e: {NaN: a, x, x: x}, x: [, ], c, this.x: d, b: [, , , {eval: [], w: {x: {a}}, d}]}, {b: (({d: null})), w: {x, c}, d: {x, NaN, a}, e}, , , ], window, w: [, , {\u3056: [, x], e: [], y, w, \u3056: x}]}, arguments.callee.arguments,  for each (d in [z1,,]) for each (\u3056 in []) for each (x in [])], , , , x, {}, , ] = undefined; /*FARR*/[ /x/g , ((function (x) { yield  \"\"  } ).apply).call(let, ), (makeFinalizeObserver('tenured')), , window]; new /((?=\\B){3})/yi(new RegExp(\"(?!(?!(?![^]|$+?))+)|[\\\\u0035]\\\\2\\u00a2((?!\\\\W))*{4,}\", \"gim\").toLocaleDateString( '' , -12) = x, x)) {var y = (4277);((uneval(window))); }");
/*fuzzSeed-116170070*/count=873; tryItOut("\"use strict\"; o1.o1.f0(b1);");
/*fuzzSeed-116170070*/count=874; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.cosh(Math.pow(mathy0((0x080000000 & ( + y)), y), ( + (( + (Math.log10(x) ? Math.cosh(0x080000000) : (-0x080000001 >>> 0))) + ( + (( ! (x | 0)) | 0)))))) >>> 0); }); testMathyFunction(mathy1, [0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000000, -0x100000000, -(2**53+2), -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, Number.MIN_VALUE, 0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0x100000001, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, Math.PI, -0x07fffffff, 1, -(2**53-2), 42, 1/0, -0x0ffffffff, -0, 0, 0/0, -1/0, 0x080000001, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-116170070*/count=875; tryItOut("\"use strict\"; g0.v2 = o2[new String(\"12\")];");
/*fuzzSeed-116170070*/count=876; tryItOut("mathy4 = (function(x, y) { return Math.imul((Math.fround(( + ((( + (Math.max((( + ( - x)) | 0), Number.MIN_SAFE_INTEGER) | 0)) ^ ( + Math.hypot(( + x), ( + 1)))) >>> 0))) >>> 0), (((Math.trunc((Math.log(x) | 0)) >>> 0) < (Math.imul(( + ( - ( + x))), x) | 0)) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[ \"use strict\" ,  \"use strict\" , new String(''), new String('')]); ");
/*fuzzSeed-116170070*/count=877; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy0(Math.sinh(Math.fround(Math.min(Math.fround(((Math.tanh(Math.fround((Math.fround(x) ? Math.fround(y) : Math.fround(y)))) - (0x0ffffffff >>> 0)) >>> 0)), (( + x) >>> 0)))), mathy1((x || x), -Number.MIN_VALUE)) & Math.atan2((( + Math.expm1((Math.atan2(x, y) | 0))) <= ( + Math.log1p((( + (Math.acos(x) | 0)) | 0)))), (Math.fround((((y >>> 0) ? ((((x >>> 0) >>> (-(2**53) >>> 0)) >>> 0) >>> 0) : (mathy1(x, y) >>> 0)) >>> 0)) - y))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), null, ({valueOf:function(){return 0;}}), '\\0', (new Number(0)), undefined, 1, true, false, (new Boolean(true)), 0, 0.1, [0], '0', /0/, (new String('')), (function(){return 0;}), '/0/', (new Boolean(false)), ({toString:function(){return '0';}}), '', ({valueOf:function(){return '0';}}), (new Number(-0)), NaN, -0, []]); ");
/*fuzzSeed-116170070*/count=878; tryItOut("delete h1.defineProperty;(c);");
/*fuzzSeed-116170070*/count=879; tryItOut("return;\no2 = {};\n");
/*fuzzSeed-116170070*/count=880; tryItOut("\"use strict\"; testMathyFunction(mathy3, [objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), -0, NaN, '/0/', true, /0/, '', (new Number(0)), '0', (new Number(-0)), ({toString:function(){return '0';}}), (new String('')), [0], null, false, (new Boolean(true)), 1, ({valueOf:function(){return 0;}}), 0.1, (new Boolean(false)), undefined, '\\0', (function(){return 0;}), [], 0]); ");
/*fuzzSeed-116170070*/count=881; tryItOut("/*infloop*/for(null; eval(\";\", y); (((p={}, (p.z =  /x/ )())) ? window.unwatch(\"__parent__\") : \n\"\\uE149\")) let eval, y, lfifjm, d;var zutylf = new SharedArrayBuffer(12); var zutylf_0 = new Uint8Array(zutylf); print(zutylf_0[0]); zutylf_0[0] = -3; Object.defineProperty(this, \"a1\", { configurable: true, enumerable: this,  get: function() {  return new Array; } });");
/*fuzzSeed-116170070*/count=882; tryItOut("/*RXUB*/var r = x|=null ? (Math.min(this, (function ([y]) { })())) : x; var s = ~z; print(s.match(r)); ");
/*fuzzSeed-116170070*/count=883; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + (( - (((( ! Math.imul(x, y)) | 0) != ((( - ( + Math.fround((Math.max(2**53+2, y) / x)))) >>> 0) | 0)) | 0)) >>> 0)) % ( + Math.min((( + Math.sqrt(Math.fround(( - x)))) | 0), ( + Math.max(( + (( - 1/0) , Math.fround(Math.min(((x | 0) & (( + ( ! y)) | 0)), (y | 0))))), ( + (Math.hypot(( ! Math.trunc(x)), (y % y)) & ( + (( + y) <= ( + 0/0)))))))))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, 0x100000000, Number.MAX_VALUE, -0x080000000, -0x100000001, -0, 2**53, 0x100000001, 0x080000001, -Number.MIN_VALUE, -0x100000000, -(2**53+2), -0x080000001, -Number.MAX_VALUE, 2**53+2, 0x080000000, 42, Math.PI, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -0x0ffffffff, -(2**53), -1/0, 0]); ");
/*fuzzSeed-116170070*/count=884; tryItOut("a1[17];");
/*fuzzSeed-116170070*/count=885; tryItOut("mathy0 = (function(x, y) { return (Math.sign(Math.log1p(Math.fround(y))) && Math.fround((Math.fround(Math.acosh((y | 0))) == ( ! ((Math.atan2(( + y), (y >>> 0)) >>> 0) >>> 0))))); }); testMathyFunction(mathy0, [0x07fffffff, 0x100000000, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 0/0, 0.000000000000001, 1/0, -0x07fffffff, -(2**53+2), 0x080000001, -0x080000001, 2**53-2, -0x0ffffffff, 0x100000001, -1/0, -Number.MAX_VALUE, 1, 0x080000000, Math.PI, 2**53+2, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, 2**53, 0, -0]); ");
/*fuzzSeed-116170070*/count=886; tryItOut("v1 = Object.prototype.isPrototypeOf.call(f1, i1);");
/*fuzzSeed-116170070*/count=887; tryItOut("\"use strict\"; /*vLoop*/for (ebkocx = 0; ebkocx < 34; ++ebkocx) { const z = ebkocx; (void schedulegc(g2)); } ");
/*fuzzSeed-116170070*/count=888; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan2((Math.log1p(Math.fround(((y | ( + y)) , ( ! y)))) !== ( + ( ~ ( + Math.pow(Math.hypot((y * ( + x)), 1/0), (( ~ (0.000000000000001 >>> 0)) >>> 0)))))), (((((( ~ 0x080000000) >>> 0) >= (Math.exp(Math.atan2(( + Math.atan2(( + x), ( + (( ! (x | 0)) | 0)))), x)) >>> 0)) >>> 0) ? (( + (((((Number.MAX_VALUE | (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) | 0) - (Math.fround(((( + (Math.sqrt(0/0) & x)) | 0) != Math.fround(Math.cosh(x)))) | 0)) | 0)) >>> 0) : (( + (Math.atan(x) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -0x080000001, -0x07fffffff, Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, 0/0, Math.PI, -0x0ffffffff, -(2**53+2), -0, -1/0, 0x080000000, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 42, 1/0, 2**53+2, Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -(2**53-2), 0x080000001, 0x100000000, 0x0ffffffff, 1.7976931348623157e308, 2**53-2, 0x100000001, -0x080000000]); ");
/*fuzzSeed-116170070*/count=889; tryItOut("/*ADP-2*/Object.defineProperty(a1, 9, { configurable: false, enumerable: (4277), get: f2, set: f1 });");
/*fuzzSeed-116170070*/count=890; tryItOut("/* no regression tests found */");
/*fuzzSeed-116170070*/count=891; tryItOut("t1 = new Uint8ClampedArray(a0);");
/*fuzzSeed-116170070*/count=892; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.asin(Math.fround(Math.log(( ~ x)))); }); testMathyFunction(mathy5, [-1/0, -Number.MIN_VALUE, 0x100000000, -(2**53+2), -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -0, -0x0ffffffff, 1/0, 0.000000000000001, 0x080000000, -0x080000001, 1.7976931348623157e308, 1, 0x0ffffffff, 2**53+2, 0x100000001, -0x100000001, 42, -0x100000000, Number.MAX_VALUE, 0/0, 2**53, 0x080000001, -Number.MAX_VALUE, Math.PI, 0x07fffffff, -(2**53-2), 0, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-116170070*/count=893; tryItOut("\"use strict\"; var mivpjp = new SharedArrayBuffer(0); var mivpjp_0 = new Uint32Array(mivpjp); print(mivpjp_0[0]); var mivpjp_1 = new Uint8Array(mivpjp); mivpjp_1[0] = -17; var mivpjp_2 = new Int16Array(mivpjp); mivpjp_2[0] = -25; var mivpjp_3 = new Float64Array(mivpjp); var mivpjp_4 = new Uint8ClampedArray(mivpjp); mivpjp_4[0] = -7; var mivpjp_5 = new Float32Array(mivpjp); var mivpjp_6 = new Float64Array(mivpjp); print(mivpjp_6[0]); mivpjp_6[0] = -8; var mivpjp_7 = new Float64Array(mivpjp); var mivpjp_8 = new Uint8Array(mivpjp); print(mivpjp_8[0]); mivpjp_8[0] = -21; ([1,,]);g0.g0 + t0;/*ADP-2*/Object.defineProperty(a2, 14, { configurable: false, enumerable: \"\\u57C2\", get: (function() { for (var j=0;j<8;++j) { f2(j%3==1); } }), set: (function() { for (var j=0;j<17;++j) { f2(j%4==1); } }) });s1 = a2.join(s1);e2.add(h0);selectforgc(o1);Array.prototype.shift.apply(a1, [t1, s0, m0]);{ void 0; validategc(false); }g0.offThreadCompileScript(\"window\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: (mivpjp_2 % 6 != 4) }));");
/*fuzzSeed-116170070*/count=894; tryItOut("\"use strict\"; \"use asm\"; ((function sum_indexing(pbbbuy, cnmzis) { ; return pbbbuy.length == cnmzis ? 0 : pbbbuy[cnmzis] + sum_indexing(pbbbuy, cnmzis + 1); })(/*MARR*/[new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Number(1), new Boolean(true), new Number(1), new Number(1), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Number(1), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Number(1), new Boolean(true), new Boolean(true), new Number(1), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1)], 0));");
/*fuzzSeed-116170070*/count=895; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.atan2(Math.fround(( ~ Math.fround(Math.min(y, (y >>> 0))))), ( + Math.atan(( + ( - ( + mathy0(( + ( ! ( + y))), y))))))); }); ");
/*fuzzSeed-116170070*/count=896; tryItOut("\"use strict\"; /(?!(?=[^\u8b82](?=[^]?){4}))/m;");
/*fuzzSeed-116170070*/count=897; tryItOut("m0[\"1\"] = g0.s2;");
/*fuzzSeed-116170070*/count=898; tryItOut("c = ((4277))(/(?=(?!.)(?:.)*?(?:(?![^]\ue75b))|.*)/g, (makeFinalizeObserver('tenured')));throw StopIteration;");
/*fuzzSeed-116170070*/count=899; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.fround(( ~ (( ! y) >>> 0))) && ( + (Math.fround(Math.min((y > ((x | 0) / x)), ( + ( + ( + x))))) > ( ~ Math.fround((Math.fround(Math.sinh(( + x))) !== Math.fround(( + Math.min(x, Math.atan2(((( + -(2**53-2)) >> -0x0ffffffff) >>> 0), x)))))))))); }); testMathyFunction(mathy0, [0, -0, -(2**53), -(2**53+2), -0x0ffffffff, -0x07fffffff, 2**53, 1/0, -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 1, 0x0ffffffff, -0x080000001, 2**53+2, 0x080000001, 1.7976931348623157e308, 0/0, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 42, 0x100000001, Math.PI, 0x080000000, -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 0x07fffffff]); ");
/*fuzzSeed-116170070*/count=900; tryItOut("v1 = r0.toString;");
/*fuzzSeed-116170070*/count=901; tryItOut("e1.has(y = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: RegExp.prototype.test, getPropertyDescriptor: undefined, defineProperty: \n[] = (4277), getOwnPropertyNames: function() { throw 3; }, delete: function() { return false; }, fix: (timeout(1800)), has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: mathy1, iterate: objectEmulatingUndefined, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })((4277)), yield [(\n '' )] ** (4277)));");
/*fuzzSeed-116170070*/count=902; tryItOut("\"use strict\"; /*vLoop*/for (let obauzb = 0; obauzb < 17; ++obauzb) { var x = obauzb; /*MXX1*/o1 = g0.DFGTrue; } ");
/*fuzzSeed-116170070*/count=903; tryItOut("o0.o2 = Object.create(a1);");
/*fuzzSeed-116170070*/count=904; tryItOut("let eval =  /x/ , x, oecfuz, eval;g2.a0.length = 19;\nObject.defineProperty(this, \"t2\", { configurable: x, enumerable: false,  get: function() {  return m2.get(g0.a0); } });\nf0(this.m0)\n/*RXUB*/var r = r1; var s = typeof null; print(r.exec(s)); ");
/*fuzzSeed-116170070*/count=905; tryItOut("\"use strict\"; a0 = Array.prototype.concat.apply(g0.a0, [a2]);");
/*fuzzSeed-116170070*/count=906; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.trunc((Math.pow(Math.atan2(Number.MIN_SAFE_INTEGER, y), -(2**53+2)) <= ( + ( - (x == ((y | 0) ^ (2**53+2 | 0))))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 0x100000001, -0x100000000, -(2**53), 0x0ffffffff, 0x080000000, -0x100000001, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, 0/0, 0x080000001, 2**53+2, 2**53-2, 0x07fffffff, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -0, 42, -Number.MIN_VALUE, -0x080000001, 0x100000000, -Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, 2**53, Math.PI]); ");
/*fuzzSeed-116170070*/count=907; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?=[^]*)){33554433,33554437}\", \"gy\"); var s = \"yyyyyyyyy\\n\\n\\n\\n\\n\\nyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\\n\\n\\n\\n\\n\\n\"; print(s.split(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
