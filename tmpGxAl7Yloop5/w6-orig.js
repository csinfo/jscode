

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
/*fuzzSeed-254361819*/count=1; tryItOut("\"use strict\"; Array.prototype.shift.call(a0);");
/*fuzzSeed-254361819*/count=2; tryItOut(" for (var w of [1,,]) {a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; m0.set(p2, v1); }");
/*fuzzSeed-254361819*/count=3; tryItOut("\"use strict\"; this.t0 + '';");
/*fuzzSeed-254361819*/count=4; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(^\\\\w)|\\\\d)|$|(?:[\\\\t-\\u65e4]){2,}\\\\u0087?\\\\b(?!\\\\S|.)[^]|[\\\\cI-\\\\u0019\\\\b](?:([^]))(?=(?!\\\\S*))\\\\b?(?:(?:[\\ueed0]|(?!(?:\\\\w)))^|\\ue7b3+?+?)+\", \"gyi\"); var s = \"\\u2e4c\\u2e4c\\u2e4c\"; print(uneval(s.match(r))); print(r.lastIndex); M:if(true) {g1.offThreadCompileScript(\"function f2(m2) this\", ({ global: o2.g2.g0, fileName: null, lineNumber: 42, isRunOnce: (x % 3 != 0), noScriptRval: [z1], sourceIsLazy: /\\b.$$((?=(?=\\b))*?){3}[\u00ad\\u006E-\\u6d9D\\xde\\S]/gyi, catchTermination: false })); } else  if (x) g0.v0 = undefined; else {print([1,,]);(7); }");
/*fuzzSeed-254361819*/count=5; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((Math.pow(Math.pow((( + mathy2(Math.fround(Math.atan2(Math.fround(y), Math.fround((( ! -(2**53-2)) >>> 0)))), Math.fround((Math.imul((y >>> 0), ( + y)) ? (0/0 | 0) : ( + ( - y)))))) | 0), ( + x)), (((y | 0) & (x | 0)) | 0)) | 0) << ((Math.fround(((Math.log10(x) >= x) > (Math.cos(Math.fround(( + Math.min((y | 0), ( + x))))) >>> 0))) * ( ! Math.fround(y))) | 0)) | 0); }); testMathyFunction(mathy4, [-0x100000000, Number.MAX_VALUE, 2**53, -(2**53), -0x100000001, 0x080000001, 0.000000000000001, Math.PI, 1.7976931348623157e308, 42, Number.MIN_VALUE, -(2**53-2), -Number.MIN_VALUE, 0, 0x07fffffff, -Number.MAX_VALUE, -(2**53+2), -0, 0x080000000, 0x100000000, 2**53-2, -0x080000001, -0x07fffffff, -0x0ffffffff, 2**53+2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, -1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-254361819*/count=6; tryItOut("Array.prototype.push.apply(a0, [t1, g2.a0, i2, b2]);");
/*fuzzSeed-254361819*/count=7; tryItOut("let(y) ((function(){let(d) { try { x((function ([y]) { })()) = y; } finally { yield y = /(?=^\\W)/gm; } }})());");
/*fuzzSeed-254361819*/count=8; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((((( + Math.hypot(-0x07fffffff, ( + y))) == Math.atanh((x >>> 0))) ^ Math.fround(Math.fround(( ! (y + ( ! Math.PI)))))) >>> 0) * (((-Number.MAX_SAFE_INTEGER | 0) & (( - Math.fround((Math.fround(y) ? Math.fround((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: Array.prototype.forEach, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: undefined, }; })(null)) : Math.fround((x & (x & 0x080000001)))))) | 0)) | 0)) + ((x , Math.fround(Math.trunc(Math.fround(x)))) ? Math.fround((-Number.MIN_SAFE_INTEGER , Math.fround((( ~ Math.atanh(y)) >>> -0x07fffffff)))) : Math.round((Math.cbrt(((Math.atan2(-Number.MAX_VALUE, x) != y) | 0)) | 0)))); }); ");
/*fuzzSeed-254361819*/count=9; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=10; tryItOut("a0.reverse();(x);");
/*fuzzSeed-254361819*/count=11; tryItOut("\"use strict\"; x = x;");
/*fuzzSeed-254361819*/count=12; tryItOut("var a1 = this.a1.concat(t0, g0.a2, t0, t0, o2, g0, b2);");
/*fuzzSeed-254361819*/count=13; tryItOut("mathy2 = (function(x, y) { return Math.sign((( ! ( - y)) << Math.atan2(( + Math.fround(mathy0(Math.fround(0/0), Math.fround(-0x100000001)))), ( + (( + ((Math.sqrt((Math.fround(( ~ Math.fround(x))) | 0)) | 0) >>> 0)) | 0))))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, -(2**53-2), 1/0, 0, -Number.MIN_VALUE, 1, 2**53, Number.MIN_SAFE_INTEGER, 42, -1/0, 0x080000001, -0x0ffffffff, -0x07fffffff, 0x07fffffff, 0x080000000, 2**53-2, -0, 0x100000000, -(2**53+2), Math.PI, 0/0, Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001]); ");
/*fuzzSeed-254361819*/count=14; tryItOut("f0 + '';");
/*fuzzSeed-254361819*/count=15; tryItOut("\"use asm\"; a0.length = 10;\n/*MXX3*/g1.String.prototype.substring = g2.String.prototype.substring;\n");
/*fuzzSeed-254361819*/count=16; tryItOut("var pwlexi = new SharedArrayBuffer(8); var pwlexi_0 = new Uint8Array(pwlexi); var pwlexi_1 = new Float64Array(pwlexi); pwlexi_1[0] = 20;  '' ;a2.__proto__ = s1;z = x;");
/*fuzzSeed-254361819*/count=17; tryItOut("/*MXX1*/o1 = g1.DFGTrue.length;");
/*fuzzSeed-254361819*/count=18; tryItOut("b0[\"__iterator__\"] = e2;");
/*fuzzSeed-254361819*/count=19; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-254361819*/count=20; tryItOut("with(objectEmulatingUndefined && this.__defineSetter__(\"x\", Math.fround(( - Math.fround(Math.asin(x)))))){e0.toString = f0;function shapeyConstructor(ipgvit){Object.defineProperty(ipgvit, \"getUTCSeconds\", ({value: (4277), writable: true}));Object.seal(ipgvit);if (ipgvit) Object.defineProperty(ipgvit, 7, ({}));ipgvit[\"__parent__\"] = Function.prototype.call;ipgvit[\"prototype\"] = Infinity;Object.defineProperty(ipgvit, \"delete\", ({value: (/*UUV2*/(x.getUTCSeconds = x.toString))}));{ Object.prototype.watch.call(b0, \"trimLeft\", (function() { for (var j=0;j<174;++j) { f0(j%3==1); } })); } Object.seal(ipgvit);return ipgvit; }/*tLoopC*/for (let e of /*FARR*/[]) { try{let pzdthm = shapeyConstructor(e); print('EETT'); v2 = Array.prototype.reduce, reduceRight.call(a0, (function() { Array.prototype.reverse.apply(a1, []); return this.e1; }), g0.g1);}catch(e){print('TTEE ' + e); } } }");
/*fuzzSeed-254361819*/count=21; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.fround((((Math.fround(( + ( ~ ( + (Math.atan2(-(2**53-2), Math.exp(-0x100000000)) ? x : x))))) >= (Math.pow(Math.fround(( - (Math.max((y | 0), (x >>> 0)) >>> 0))), ((( + Math.PI) , ( + ( + y))) | 0)) >>> 0)) >>> 0) || Math.fround(Math.log(Math.fround(Math.fround(Math.max(Math.hypot((-(2**53) >>> 0), 0), x)))))))); }); ");
/*fuzzSeed-254361819*/count=22; tryItOut("o2.g1.__proto__ = a1;");
/*fuzzSeed-254361819*/count=23; tryItOut("\"use strict\"; var fqppxi = new SharedArrayBuffer(0); var fqppxi_0 = new Int16Array(fqppxi); print(fqppxi_0[0]); var fqppxi_1 = new Int8Array(fqppxi); print(fqppxi_1[0]); o0.t0 = new Uint8ClampedArray(7);function y(b, z,  /x/ , window, x, w, y, fqppxi_1[0], x, fqppxi_1[0], c, a, window, \u3056, x, fqppxi_0, fqppxi_1[0], e, fqppxi_0 =  \"\" , x, d, x, fqppxi, x, e, e, e, c, fqppxi_0, c, w = /$[^](?!\u8365+?)+?^[^]\\2|(?=$[^\\n-\\x37]{4,}|[^]*?)|([^]$*([^]|.+{2,5}))/yim, this, c = fqppxi, y, b, a, fqppxi_0, fqppxi_0, e, delete, e, window, e, y, z, fqppxi_1 = d, fqppxi, fqppxi_0 =  \"\" , b, x) { print(({})); } print(fqppxi_1[0]);i0 = a1[14];");
/*fuzzSeed-254361819*/count=24; tryItOut("\"use strict\"; i2.send(g2.m2);");
/*fuzzSeed-254361819*/count=25; tryItOut("a0[({valueOf: function() { if(x) h1.iterate = (function() { /*RXUB*/var r = o1.r1; var s = \"\"; print(s.search(r)); print(r.lastIndex);  return p1; }); else  if (x) v1 = r1.compile; else {var x = \n /x/g , z = this, tkzpml, ybnfip, rjqipl, ldjqwb, eval, qokbgx, x;print((4277));(7); }return 8; }})] = f0;");
/*fuzzSeed-254361819*/count=26; tryItOut("i2.toSource = (function() { for (var j=0;j<38;++j) { f2(j%3==1); } });");
/*fuzzSeed-254361819*/count=27; tryItOut("/*RXUB*/var r = o1.r1; var s = \"\\ua458\"; print(s.search(r)); print(r.lastIndex); a1.shift();");
/*fuzzSeed-254361819*/count=28; tryItOut("print(x);(void schedulegc(g1));");
/*fuzzSeed-254361819*/count=29; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.888946593147858e+22;\n    d2 = (((NaN)) * ((+(((((/*FFI*/ff(((~~(d0))), ((((0x15b96fe5)) ^ ((0xbee75f9b)))), ((-6.044629098073146e+23)), ((-4398046511105.0)), ((-6.044629098073146e+23)), ((-134217728.0)), ((-1.0009765625)), ((-140737488355329.0)), ((-268435457.0)), ((-4503599627370495.0)), ((524289.0)), ((-262144.0)), ((-590295810358705700000.0)), ((-140737488355329.0)), ((73786976294838210000.0)), ((16384.0)), ((36028797018963970.0)), ((-4.835703278458517e+24)), ((-131071.0)), ((-2.3611832414348226e+21)), ((7.555786372591432e+22)))|0))) / (((i1)+(i1))|0))>>>((i1)-(0xffffffff)+(0xff6d2def))))));\n    {\n      {\n        i1 = (((d2) == (+(-1.0/0.0))) ? (0xffffffff) : ((+(0.0/0.0)) < (d0)));\n      }\n    }\n    return ((0x29a13*(0xff9fff33)))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 1/0, 0, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000001, 2**53-2, -Number.MAX_VALUE, 42, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, 1, -(2**53), 0/0, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000000, -0x100000000, -(2**53+2), Number.MIN_VALUE, 0x100000001, -0x080000001, -(2**53-2), 0x080000000, Math.PI, Number.MAX_VALUE, -1/0, -0x0ffffffff, -0x07fffffff, 0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-254361819*/count=30; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g1, v0);");
/*fuzzSeed-254361819*/count=31; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 2**53, 1, -1/0, 2**53+2, -(2**53), 1.7976931348623157e308, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, -0x100000001, 1/0, 2**53-2, Math.PI, -(2**53+2), 0x100000001, -0x080000000, -(2**53-2), 0, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 0x100000000, 0.000000000000001, 0x0ffffffff, 0x07fffffff, 0x080000000, -0x07fffffff]); ");
/*fuzzSeed-254361819*/count=32; tryItOut("for (var v of this.m1) { try { Array.prototype.forEach.apply(a0, [(function() { try { this.o2 = h0.__proto__; } catch(e0) { } try { for (var p in b2) { try { e0 + ''; } catch(e0) { } function f1(f1)  { a2 = a2.slice(); }  } } catch(e1) { } try { f2 + g1; } catch(e2) { } Object.prototype.watch.call(m1, \"lastIndexOf\", (function() { Object.defineProperty(this, \"e2\", { configurable: false, enumerable: (x % 4 != 3),  get: function() {  return new Set; } }); return h2; })); return t1; }), p2]); } catch(e0) { } i0.next(); }");
/*fuzzSeed-254361819*/count=33; tryItOut("h2.delete = f0;");
/*fuzzSeed-254361819*/count=34; tryItOut("mathy4 = (function(x, y) { return Math.fround(( + Math.fround((Math.fround((Math.fround(( ~ mathy1(Math.fround(Math.atan2(Math.fround((-0 == y)), Math.fround(Math.max(y, (0x0ffffffff >>> 0))))), y))) !== Math.fround((Math.trunc(Math.fround((Math.fround(Math.fround(( ! Math.fround(1/0)))) && Math.fround(Math.trunc(Math.fround(Math.max(Math.fround(y), -Number.MAX_SAFE_INTEGER))))))) >>> 0)))) < Math.fround(Math.log2(Math.fround(-Number.MIN_SAFE_INTEGER))))))); }); testMathyFunction(mathy4, [2**53, -(2**53-2), 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, -1/0, Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, 0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, 2**53-2, -Number.MAX_VALUE, 2**53+2, 1/0, 0x100000000, 42, -0x080000001, 0x0ffffffff, -0x080000000, -(2**53), 0x080000001, -0x07fffffff, 0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 0x100000001, Math.PI, Number.MIN_VALUE, 1]); ");
/*fuzzSeed-254361819*/count=35; tryItOut("o0 + '';\nv0 = m2.get(a2);\n");
/*fuzzSeed-254361819*/count=36; tryItOut("const e = NaN = {e: y};{Array.prototype.splice.apply(a2, []); }");
/*fuzzSeed-254361819*/count=37; tryItOut("\"use strict\"; var vyaygz = new ArrayBuffer(8); var vyaygz_0 = new Int8Array(vyaygz); print(vyaygz_0[0]); vyaygz_0[0] = 8; var vyaygz_1 = new Uint8ClampedArray(vyaygz); print(vyaygz_1[0]); vyaygz_1[0] = -8; /*MXX1*/Object.defineProperty(o0, \"o1\", { configurable: true, enumerable: new RegExp(\"(?=.*)|(?:\\\\w)\", \"g\"),  get: function() { v2 = g1.eval(\" '' \"); return g0.Date.UTC; } });");
/*fuzzSeed-254361819*/count=38; tryItOut("\"use strict\"; h0 = ({getOwnPropertyDescriptor: function(name) { o2.a1 = [];; var desc = Object.getOwnPropertyDescriptor(b2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { m1.has(i1);; var desc = Object.getPropertyDescriptor(b2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { m0.get(this.f1);; Object.defineProperty(b2, name, desc); }, getOwnPropertyNames: function() { a1 = arguments;; return Object.getOwnPropertyNames(b2); }, delete: function(name) { v1 = false;; return delete b2[name]; }, fix: function() { print(e2);; if (Object.isFrozen(b2)) { return Object.getOwnProperties(b2); } }, has: function(name) { delete g0.s0[\"__count__\"];; return name in b2; }, hasOwn: function(name) { m1 = Proxy.create(h2, p0);; return Object.prototype.hasOwnProperty.call(b2, name); }, get: function(receiver, name) { f1(g1.a1);; return b2[name]; }, set: function(receiver, name, val) { g2.m0.has(g1);; b2[name] = val; return true; }, iterate: function() { p1 + '';; return (function() { for (var name in b2) { yield name; } })(); }, enumerate: function() { g0.e2.has(this.e1);; var result = []; for (var name in b2) { result.push(name); }; return result; }, keys: function() { /*MXX2*/g2.o0.g2.Set.prototype.has = this.g0;; return Object.keys(b2); } });");
/*fuzzSeed-254361819*/count=39; tryItOut("\"use strict\"; print(x++);");
/*fuzzSeed-254361819*/count=40; tryItOut("mathy4 = (function(x, y) { return Math.min((Math.abs((Math.fround(( ! (Math.max(( + (x ^ Math.PI)), x) | 0))) | 0)) >> ((Math.min(x, (y ? x : x)) && Math.log1p((mathy2((((y >>> 0) - y) | 0), (x | 0)) | 0))) | 0)), Math.fround(Math.imul(Math.tan(( ~ (((Number.MIN_SAFE_INTEGER >>> 0) != (Number.MAX_VALUE >>> 0)) >>> 0))), Math.log10((Math.atan2((x | 0), (0x080000001 | 0)) | 0))))); }); testMathyFunction(mathy4, [0/0, -1/0, 0x100000001, 1/0, 0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -0, -(2**53-2), -0x100000001, -(2**53), 1, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, -0x080000000, 2**53-2, Math.PI, 0, 1.7976931348623157e308, 42, -Number.MIN_VALUE, -(2**53+2), 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, 2**53]); ");
/*fuzzSeed-254361819*/count=41; tryItOut("\"use strict\"; (new (e =>  { -4 } )(true, this));");
/*fuzzSeed-254361819*/count=42; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i1 = (i0);\n    (Int32ArrayView[(((((0xfecb731e)-(0x2c094b37))>>>((0xb5b8b19) / (-0x56996ae))) == (0xdfce0493))-((+(((0x7fd9fb97)) | ((0x4a1cc048)))) <= (8.0))) >> 2]) = (((((Int8ArrayView[((i0)+(i1)+((((0x64cf3f92))|0))) >> 0]))>>>((i1)+(i0)+(i1))) == (((((0xafb2f8cb)-(0xffffffff)+(0xf8a4bd31))>>>((!(0x55358720))-(i1))) % ((((0x59527986) > (-0x8000000))-(i0))>>>((0x0) / (0xc90df47a))))>>>((i1)))));\n    i1 = (((-0x5f17e*(i0)) & ((((0xffffffff) % (0x74dcdce0)) ^ ((0x96b82d1d)+(0xfe17cb7a)+(0xab77f120))) % ((((-67108865.0) != (-4611686018427388000.0))) >> ((i0))))) != ((((0xff0fa99b) <= (((0x5ee0b0bc) % (-0x7312833))>>>((Uint8ArrayView[4096]))))+(i0)) ^ ((i1)+(i0))));\n    {\n      return +((-6.189700196426902e+26));\n    }\n    {\n      {\n        i0 = (i0);\n      }\n    }\n    (Float64ArrayView[((i0)*0xf192f) >> 3]) = ((-65537.0));\n    return +((-2251799813685249.0));\n  }\n  return f; })(this, {ff: Uint32Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x100000000, -(2**53-2), -0x100000001, 2**53, 0x100000000, 0x080000000, 0x080000001, -0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1, 0.000000000000001, -1/0, Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, 0, 0/0, 0x07fffffff, -0x0ffffffff, -0x080000000, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 42, -(2**53), -0, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001]); ");
/*fuzzSeed-254361819*/count=43; tryItOut("mathy3 = (function(x, y) { return ( + Math.atan2(( + Math.asin((( + ( + x)) << Math.min((y ? y : ( + ( ~ ( + y)))), x)))), ( + (( + (( + Math.hypot(( + (Math.fround(y) ? -(2**53) : Math.fround((Math.max((x | 0), y) >>> 0)))), ( + Number.MIN_VALUE))) <= Math.fround(( ! Math.fround(( + x)))))) != ( + (Math.log10(Math.fround(((Math.fround(x) >>> 0) ? ((Math.min(x, x) >>> 0) >>> 0) : (x >>> 0)))) ** Math.fround(Math.hypot(x, Math.fround(Math.max(y, x)))))))))); }); testMathyFunction(mathy3, /*MARR*/[ /x/g ,  /x/g , new Boolean(true), new Boolean(true), new Boolean(true), function(){}, function(){},  /x/g ,  /x/g , x, new Boolean(true), new Boolean(true),  /x/g , new Boolean(true), function(){},  /x/g , new Boolean(true), function(){},  /x/g ,  /x/g , x, x,  /x/g , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x,  /x/g , new Boolean(true), new Boolean(true), x, new Boolean(true), function(){}, function(){}, new Boolean(true),  /x/g , new Boolean(true), new Boolean(true), new Boolean(true), function(){}, new Boolean(true),  /x/g , new Boolean(true),  /x/g , new Boolean(true), new Boolean(true), function(){}, new Boolean(true), function(){}, function(){}, new Boolean(true), function(){}, new Boolean(true), new Boolean(true),  /x/g , function(){},  /x/g , function(){}, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), function(){}, x, function(){}, function(){}, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/g , function(){}, new Boolean(true), new Boolean(true), new Boolean(true),  /x/g , new Boolean(true), function(){}, function(){}, new Boolean(true), new Boolean(true), function(){}, function(){}, new Boolean(true), new Boolean(true), new Boolean(true), x,  /x/g , x, function(){}, new Boolean(true), x,  /x/g , function(){},  /x/g , new Boolean(true), function(){}, function(){}, x, function(){}, new Boolean(true), x, new Boolean(true), new Boolean(true), function(){}, x, function(){}, new Boolean(true),  /x/g , new Boolean(true), new Boolean(true),  /x/g ,  /x/g ,  /x/g , function(){}, new Boolean(true)]); ");
/*fuzzSeed-254361819*/count=44; tryItOut("print(x);Array.prototype.splice.call(this.g2.a2, NaN, 11);");
/*fuzzSeed-254361819*/count=45; tryItOut("\"use strict\"; h2 + t0;");
/*fuzzSeed-254361819*/count=46; tryItOut("\"use strict\"; this.m0.has(h0);");
/*fuzzSeed-254361819*/count=47; tryItOut("let (oajavu, NaN, sgvzvb, fmuokh, qjxcoo) { Object.defineProperty(this, \"a1\", { configurable: (x % 4 == 3), enumerable: y,  get: function() { a1.reverse(i1); return arguments; } }); }");
/*fuzzSeed-254361819*/count=48; tryItOut("/*RXUB*/var r = /(?![^]{4,})/gyim; var s = window; print(s.match(r)); ");
/*fuzzSeed-254361819*/count=49; tryItOut("mathy4 = (function(x, y) { return ((Math.fround(Math.cbrt(Math.fround((Math.fround(( + (Math.imul((x >>> 0), (y >>> 0)) * Math.cos(y)))) - Math.fround(0x080000000))))) | 0) > (( + Math.min(( + ((( + (Math.log2((y >>> 0)) >>> 0)) ^ ((Number.MIN_VALUE < x) | 0)) | 0)), ( + Math.fround(Math.atanh(Math.fround(((Math.fround(-(2**53)) | -0x07fffffff) , Number.MIN_VALUE))))))) | 0)); }); ");
/*fuzzSeed-254361819*/count=50; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-254361819*/count=51; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((((y % Math.cosh(( - ( + Math.hypot((( ~ (0.000000000000001 >>> 0)) >>> 0), x))))) ? Math.max((mathy0(( + y), ;) + ( + (Math.atan2((y | 0), ( ! -Number.MAX_SAFE_INTEGER)) | 0))), (mathy0((y | 0), (y | 0)) | 0)) : (Math.fround(( ~ Math.fround(Math.hypot((-(2**53) >>> 0), y)))) == Math.fround((y < mathy0((Math.max((Math.fround(mathy0(Math.fround(0/0), Math.fround(y))) | 0), (y | 0)) | 0), -0))))) | 0) >= mathy0(Math.fround(mathy0(x, (( + (((mathy0((-0x100000000 >>> 0), (y >>> 0)) | 0) >>> 0) && (( ! (1 >>> 0)) >>> 0))) === Math.fround((Math.round((x | 0)) | 0))))), Math.fround(( ~ Math.fround(Math.atan2(Math.expm1(y), y)))))); }); testMathyFunction(mathy1, /*MARR*/[-0xB504F332]); ");
/*fuzzSeed-254361819*/count=52; tryItOut("let x = ( + (Math.fround((Math.tanh(x) , Math.max((( ! Math.imul((Math.min((x >>> 0), (Math.expm1(( + x)) >>> 0)) | 0), ((Math.min(( + x), 0x100000000) ? (0x080000000 | 0) : (0x0ffffffff | 0)) | 0))) >>> 0), (Math.PI >>> 0)))) >> Math.atan2(Math.acos((Math.hypot((x >>> 0), ( + x)) >>> 0)), (( - Math.imul(-1/0, (( ~ (Math.log1p(x) % x)) | 0))) | 0)))), x = window, x, ianpru, x = .yoyo(null), caller = -1827406869, [, ] = (c =  '' ), c, a, rteyis;print(x);");
/*fuzzSeed-254361819*/count=53; tryItOut("testMathyFunction(mathy1, [true, null, objectEmulatingUndefined(), '', ({valueOf:function(){return '0';}}), [], 1, ({toString:function(){return '0';}}), '\\0', (new Number(0)), (new Boolean(true)), false, (new Number(-0)), undefined, (new Boolean(false)), '0', 0.1, NaN, (new String('')), (function(){return 0;}), [0], ({valueOf:function(){return 0;}}), 0, '/0/', /0/, -0]); ");
/*fuzzSeed-254361819*/count=54; tryItOut("");
/*fuzzSeed-254361819*/count=55; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - ((( - (( ! ( - ( + 0))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 2**53-2, -0x07fffffff, -1/0, 0/0, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, 42, 0x100000000, -0x100000001, 0x07fffffff, -(2**53-2), 2**53, 0x100000001, 0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x080000001, -0x100000000, -0, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-254361819*/count=56; tryItOut("\"use strict\"; c;");
/*fuzzSeed-254361819*/count=57; tryItOut("with({a: x}){o2 = {};print(x); }");
/*fuzzSeed-254361819*/count=58; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; setGCCallback({ action: \"minorGC\", phases: \"both\" }); } void 0; }");
/*fuzzSeed-254361819*/count=59; tryItOut("s2 += s2;");
/*fuzzSeed-254361819*/count=60; tryItOut("\"use strict\"; v1 = (v2 instanceof t2);");
/*fuzzSeed-254361819*/count=61; tryItOut("print(o0);");
/*fuzzSeed-254361819*/count=62; tryItOut("\"use strict\"; for (var v of o0) { try { e0 = new Set(b1); } catch(e0) { } try { a1[4]; } catch(e1) { } i0.next(); }");
/*fuzzSeed-254361819*/count=63; tryItOut("testMathyFunction(mathy3, [0.000000000000001, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, -(2**53+2), -0x100000001, -Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), 1, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), 0x080000001, 1.7976931348623157e308, 2**53+2, 0/0, Math.PI, -0x07fffffff, 42, 0x100000001, -0, Number.MIN_VALUE, -0x100000000, 0, 0x07fffffff, -0x080000001, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-254361819*/count=64; tryItOut("/*tLoop*/for (let a of /*MARR*/[{}, {}, [(void 0)], null, [(void 0)], undefined, undefined, [(void 0)], null, [(void 0)], {}, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], undefined, null, {}, [(void 0)], undefined, {}, null, undefined, [(void 0)], null, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, undefined, undefined, undefined, {}, {}, {}, null, {}]) { print(a); }");
/*fuzzSeed-254361819*/count=65; tryItOut("");
/*fuzzSeed-254361819*/count=66; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-254361819*/count=67; tryItOut("testMathyFunction(mathy3, /*MARR*/[function(){}, function(){}, new Boolean(true), new Boolean(true), new String(''), new Boolean(true), new Boolean(true), new String(''), new Boolean(false)]); ");
/*fuzzSeed-254361819*/count=68; tryItOut("\"use strict\"; h0.valueOf = (function() { try { t1 = new Int8Array(t0); } catch(e0) { } try { v0 = (o2.m2 instanceof e2); } catch(e1) { } a0[({valueOf: function() { print(b);let b = -26;return 15; }})] = \"\\u7A87\"; return i0; });");
/*fuzzSeed-254361819*/count=69; tryItOut("e1.add(b2);");
/*fuzzSeed-254361819*/count=70; tryItOut("\"use strict\"; ");
/*fuzzSeed-254361819*/count=71; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.tan(((Math.tanh(Math.fround(( + (( + (((mathy0(y, x) ? ( + 0x080000000) : y) | 0) || ( + y))) ? ( + ( + Math.imul(Math.fround(Math.round(( + (( + -(2**53)) | x)))), Math.fround(Math.min(Math.fround(x), (((x | 0) ? (x | 0) : (y | 0)) | 0)))))) : ( + Math.fround(( ~ Math.fround(42)))))))) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0.000000000000001, 42, -0, 1/0, Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, -(2**53-2), Number.MIN_VALUE, 0x100000001, 2**53-2, 0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0x07fffffff, 0x080000000, 2**53, -(2**53), -0x07fffffff, -0x080000000, 0x0ffffffff, Math.PI, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 1.7976931348623157e308, 0x080000001, 1, -0x080000001]); ");
/*fuzzSeed-254361819*/count=72; tryItOut("\"use strict\"; ((e = x)) ^= (4277) = linkedList(((e = x)) ^= (4277), 1536);");
/*fuzzSeed-254361819*/count=73; tryItOut("\"use strict\"; g1.toString = (function() { this.h0 = {}; return h2; });");
/*fuzzSeed-254361819*/count=74; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow((( + Math.cbrt(( + Math.fround(((( + (Math.hypot(( + y), ( + x)) >>> 0)) | ( + Math.imul(0/0, ( + ( - (x | 0)))))) !== (0 > ( + (( + (y == ( ! 1/0))) && ( + y))))))))) >>> 0), (Math.tan((x | 0)) || Math.imul(( + Math.max(Math.atan2((y | 0x0ffffffff), (Math.min(0, (x != y)) | 0)), (( + Math.cos(Math.fround(y))) >>> 0))), ( + (Math.hypot(((-Number.MIN_SAFE_INTEGER ? 0x100000000 : y) | 0), y) % Math.pow(x, ((Math.tanh(x) >>> 0) - ( ~ y)))))))); }); testMathyFunction(mathy0, [0, -1/0, -0x07fffffff, 1, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, 2**53-2, -(2**53), 0x080000001, 0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), -Number.MIN_VALUE, -0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0, 1/0, -Number.MAX_VALUE, 2**53, 0.000000000000001, 0x080000000, -0, Number.MIN_VALUE, Math.PI, 0x07fffffff, 2**53+2, 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=75; tryItOut("\"use strict\"; ");
/*fuzzSeed-254361819*/count=76; tryItOut("{print(x); }");
/*fuzzSeed-254361819*/count=77; tryItOut("/*oLoop*/for (nvazjb = 0; nvazjb < 157; ++nvazjb) { yield; } ");
/*fuzzSeed-254361819*/count=78; tryItOut("\"use strict\"; gdzmwa(x, (Math.atan2(12, -0)));/*hhh*/function gdzmwa(e, ...d){/*infloop*/while(({a2:z2})){([,]);yield true; }}");
/*fuzzSeed-254361819*/count=79; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.sqrt((Math.atan2(( ! ((( + (Math.fround(x) ? Math.fround(x) : Math.fround(y))) === ( ! 0x100000000)) >>> 0)), Math.fround(mathy1(Math.fround(1), (Math.pow((x | 0), (x | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy4, [42, -Number.MAX_VALUE, 1.7976931348623157e308, 0/0, 1, 0.000000000000001, -0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, -0, 0x080000000, Number.MAX_VALUE, 2**53-2, 1/0, Number.MIN_VALUE, -0x080000000, -(2**53+2), 0x07fffffff, 2**53+2, -0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 0x080000001, Math.PI, 0, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=80; tryItOut("\"use strict\"; s2 + '';");
/*fuzzSeed-254361819*/count=81; tryItOut("mathy5 = (function(x, y) { return mathy3(Math.fround((Math.pow(y, Math.pow((y >= 1.7976931348623157e308), (Math.sign(Math.fround(Math.cosh(( + ((x * (x >>> 0)) >>> 0))))) >>> 0))) != ( + mathy1(mathy4(2**53+2, ( + ( + 0x07fffffff))), y)))), ( ~ (( ~ ( + (( + y) ** ( + y)))) ** x))); }); testMathyFunction(mathy5, [-0, -0x080000001, 0x100000001, -0x0ffffffff, -0x07fffffff, 0x080000001, Number.MIN_VALUE, -0x100000000, -(2**53+2), 0x0ffffffff, -0x100000001, 0x100000000, 2**53-2, -0x080000000, Number.MAX_VALUE, 1/0, 42, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, -Number.MIN_VALUE, Math.PI, 0/0, 0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_VALUE, 1, 2**53+2, 2**53, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0]); ");
/*fuzzSeed-254361819*/count=82; tryItOut("this.a1.shift(p1);");
/*fuzzSeed-254361819*/count=83; tryItOut("if(false) { if (x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: WeakMap.prototype.delete, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: undefined, keys: function() { throw 3; }, }; })(x), (z = (({\"27\": [,], find: /$/m }))))) {print(null); }} else {a2[\"now\"] = i2; }");
/*fuzzSeed-254361819*/count=84; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.hypot(( + (Math.hypot((( + Math.min(( ~ x), y)) >>> 0), ((mathy0((x >>> 0), x) <= (mathy1(( + x), x) >>> 0)) >>> 0)) >>> 0)), Math.fround(Math.imul((( + Math.exp(( + x))) >>> 0), ((( + Math.cbrt(x)) <= ( ! 2**53+2)) >>> 0))))); }); ");
/*fuzzSeed-254361819*/count=85; tryItOut("\"use strict\"; print(uneval(a2));");
/*fuzzSeed-254361819*/count=86; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-254361819*/count=87; tryItOut("\"use strict\"; with({a: (4277)}){v0 = evaluate(\"a0.push( \\\"\\\" , m0, o2, s1, e1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: new String('q'), sourceIsLazy: false, catchTermination: (a % 3 == 1) }));/*infloop*/for(let a(\"\\uF751\") in ((Int32Array)( \"\" ))){v2 = Object.prototype.isPrototypeOf.call(t2, s0); } }");
/*fuzzSeed-254361819*/count=88; tryItOut("mathy0 = (function(x, y) { return ( ! (Math.sin(((( + (( + Math.asin(0x0ffffffff)) & (Math.trunc((x | 0)) | 0))) ? Math.fround(Math.imul(y, (Math.PI << ( + (( + x) && ( + -1/0)))))) : ( - Math.fround(Math.PI))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, ['', (new Number(-0)), ({toString:function(){return '0';}}), '/0/', (new Boolean(false)), (function(){return 0;}), (new String('')), 0, [0], 0.1, (new Number(0)), true, ({valueOf:function(){return 0;}}), null, objectEmulatingUndefined(), [], undefined, ({valueOf:function(){return '0';}}), false, /0/, (new Boolean(true)), NaN, 1, '\\0', -0, '0']); ");
/*fuzzSeed-254361819*/count=89; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.fround((Math.fround(( ~ Math.fround((( + x) >>> 0)))) ^ Math.imul(-Number.MAX_VALUE, ((mathy0((y | 0), ((y , Number.MAX_VALUE) | 0)) | 0) | 0)))), Math.ceil(Math.cbrt((((Math.atanh((x >>> 0)) >>> 0) | 0) ? Number.MIN_SAFE_INTEGER : (x | 0))))); }); ");
/*fuzzSeed-254361819*/count=90; tryItOut("\"use strict\"; v0 = g0.runOffThreadScript();");
/*fuzzSeed-254361819*/count=91; tryItOut("testMathyFunction(mathy0, [(new String('')), (new Boolean(false)), '/0/', '', true, (new Number(0)), (function(){return 0;}), [], ({valueOf:function(){return '0';}}), /0/, '\\0', [0], NaN, undefined, ({toString:function(){return '0';}}), objectEmulatingUndefined(), 0, 0.1, false, 1, ({valueOf:function(){return 0;}}), '0', -0, null, (new Number(-0)), (new Boolean(true))]); ");
/*fuzzSeed-254361819*/count=92; tryItOut("\"use strict\"; v0 = t2.length;");
/*fuzzSeed-254361819*/count=93; tryItOut("print(a0);");
/*fuzzSeed-254361819*/count=94; tryItOut("\"use strict\"; s2 = this.g2.objectEmulatingUndefined();");
/*fuzzSeed-254361819*/count=95; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    i1 = (-0x8000000);\n    i1 = (i1);\n    i1 = ((0x5a3b7430));\n    (Float32ArrayView[((i1)-((+(0.0/0.0)) != (((-2199023255551.0)) * ((-70368744177665.0))))-(i1)) >> 2]) = ((-32769.0));\n    {\n      d0 = ((4277));\n    }\n    d0 = ((0x56c12640) ? (0.015625) : (-1.5));\n    i1 = (i1);\n    (Float64ArrayView[((i1)+(0xfdd05b1e)-(0xfa107282)) >> 3]) = ((Float64ArrayView[(-(i1)) >> 3]));\n    d0 = (d0);\n    i1 = (i1);\n    switch ((imul(((0x7c49bc5f) ? (0x6fd9e9d9) : (0xe5668782)), (i1))|0)) {\n      case 1:\n        d0 = (NaN);\n      case -1:\n        return (((i1)))|0;\n        break;\n      case 0:\n        (Float64ArrayView[1]) = ((d0));\n        break;\n      case -2:\n        d0 = (+/*FFI*/ff());\n      case -3:\n        i1 = ((((d0)) / ((+(-1.0/0.0)))) == (+((-0x16cd5*(((0x342e17b) ? (0x13f4b98f) : (0x8b10790c)) ? ((0x24c2ecd6) == (0x584aaf4c)) : (0xd7c854e)))>>>((Uint32ArrayView[((/*FFI*/ff()|0)*-0xf899f) >> 2])))));\n        break;\n      case -1:\n        /*FFI*/ff(((abs((((0xf6589423)) ^ ((i1)+(0x9eedd01))))|0)), ((Math.pow(22, ( /x/g  ? eval : \"\\u3D49\")))), ((((0xc4ca9e42)+(0xb69cc7df)) | (-0x91ccd*(-0x8000000)))), ((((d0)))));\n    }\n    i1 = (!((((i1)+((0x40fdcb40))) & ((i1)*-0xb4c9)) > (~~(1.0))));\n    return (((0xc7d5bbe0)))|0;\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[null, (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277),  /x/g ,  /x/g ,  /x/g , null]); ");
/*fuzzSeed-254361819*/count=96; tryItOut("x;");
/*fuzzSeed-254361819*/count=97; tryItOut("switch(3) { default: a1[11] = /*UUV2*/(x.toString = x.toString);break;  }");
/*fuzzSeed-254361819*/count=98; tryItOut("testMathyFunction(mathy0, [-0x0ffffffff, 42, 0/0, 0x07fffffff, -0x080000001, -0x100000000, -1/0, -(2**53+2), 0x100000001, -0x100000001, 1, 2**53-2, 1/0, Number.MIN_VALUE, Math.PI, 2**53+2, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 0, -0x07fffffff, -(2**53-2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000000, 0x080000001, -0, -(2**53)]); ");
/*fuzzSeed-254361819*/count=99; tryItOut("/*vLoop*/for (uynfos = 0; uynfos < 14; ++uynfos) { let b = uynfos; m1.get(v0); } ");
/*fuzzSeed-254361819*/count=100; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.round((Math.clz32(((( + ((Math.abs(y) ? Math.fround(Math.ceil(Math.fround(0x080000000))) : (Math.min(x, y) | 0)) , (Math.asinh((x | 0)) | 0))) / ( + Math.pow(x, ( + ( ! Math.fround(x)))))) >>> 0)) | 0)); }); testMathyFunction(mathy3, /*MARR*/[(void 0), (void 0),  /x/g , new Boolean(true)]); ");
/*fuzzSeed-254361819*/count=101; tryItOut("\"use strict\"; \"use asm\"; const wjvyiu, NaN;/* no regression tests found */");
/*fuzzSeed-254361819*/count=102; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a0, 4, ({get: arguments.callee, set: ((yield /(?!\\3?|\\1{2})+/m.__defineSetter__(\"x\", function ([y]) { })))}));");
/*fuzzSeed-254361819*/count=103; tryItOut("a1.pop();");
/*fuzzSeed-254361819*/count=104; tryItOut("t0 = new Int16Array(a1);");
/*fuzzSeed-254361819*/count=105; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.min(Math.fround((((Math.fround(( + Math.abs(( + -0x080000001)))) , Math.tan((x >>> 0))) >>> 0) >> ((Math.min(y, ( + Math.log2(( + x)))) ? (Math.cos(y) >>> 0) : ((Math.atan2((( + (x >>> 0)) >>> 0), x) | 0) | 0)) >>> 0))), Math.fround(Math.asin((Math.hypot(Math.fround(((2**53+2 ^ (Math.atan2(((-1/0 >>> 0) ? x : (y >>> 0)), 0x100000001) | 0)) === x)), (x | 0)) | 0))))); }); ");
/*fuzzSeed-254361819*/count=106; tryItOut("(\"\\u55BC\");{}");
/*fuzzSeed-254361819*/count=107; tryItOut("a0.pop(i0, h0);");
/*fuzzSeed-254361819*/count=108; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?!(?:(?!\\\\3)).|[\\\\u00ec-\\\\\\u00db\\\\w\\u0016-\\\\u79F1]?|\\\\3|(?!\\\\B{4,})*))\", \"yi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-254361819*/count=109; tryItOut("testMathyFunction(mathy5, [0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, Math.PI, 0x100000000, -0x080000001, Number.MIN_VALUE, 0, -Number.MIN_VALUE, 2**53, 0.000000000000001, 0/0, 2**53-2, Number.MAX_VALUE, 1/0, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -1/0, -0x07fffffff, 0x080000001, 42, 1, 0x0ffffffff, -(2**53-2), -0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 0x100000001]); ");
/*fuzzSeed-254361819*/count=110; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + mathy0(( + (( ~ Math.fround(( ! mathy1((((x >>> 0) & (y >>> 0)) >>> 0), Math.max(x, (y >>> 0)))))) | 0)), Math.hypot(Math.round(x), ( + mathy1(Math.exp(Math.fround(( ~ Math.fround(y)))), ( ~ ( + y))))))); }); testMathyFunction(mathy3, [1/0, 1.7976931348623157e308, 0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), -0x100000000, -(2**53+2), -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x100000001, Math.PI, -1/0, 0, 1, 2**53, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0, -Number.MAX_VALUE, 0x0ffffffff, 0/0, 0x100000001, 42, -0x080000001, 0x080000000, 2**53+2, Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=111; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 0x080000001, 0x07fffffff, 0x080000000, -0x07fffffff, -0x100000001, -(2**53-2), 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 0x100000000, 1/0, -0x0ffffffff, 0, -0x100000000, Math.PI, -1/0, 1, -0, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, 0/0, 2**53-2, 1.7976931348623157e308, Number.MAX_VALUE, 42, 0x100000001]); ");
/*fuzzSeed-254361819*/count=112; tryItOut("a0.pop();");
/*fuzzSeed-254361819*/count=113; tryItOut("mathy0 = (function(x, y) { return (Math.cos(((Math.tan(y) | 0) <= (((Math.ceil(Math.fround(Math.tanh(Math.fround(Number.MIN_VALUE)))) | 0) ? ((( ! y) > x) | 0) : ((( + ( - (Number.MAX_SAFE_INTEGER >>> 0))) ? 0 : Math.acos(Number.MAX_SAFE_INTEGER)) | 0)) | 0))) | 0); }); testMathyFunction(mathy0, [0, 0x100000001, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff, 2**53-2, -0x07fffffff, 0x0ffffffff, 1/0, Math.PI, Number.MIN_SAFE_INTEGER, 2**53, 1, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 0/0, 0.000000000000001, -(2**53+2), 1.7976931348623157e308, Number.MAX_VALUE, 42, 0x080000001, -(2**53), -0, -0x080000001, -0x100000001, 0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-254361819*/count=114; tryItOut("\"use strict\"; \"use asm\"; /*infloop*/ for (x of new function(y) { print(x); }(x, -3)) {(-1);\nfor (var p in t2) { try { v1 = Array.prototype.reduce, reduceRight.call(a0, (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+abs(((d0))));\n    d1 = (+(0x48565228));\n    (Float64ArrayView[((((!(0x8e8395bf))+(0xfa12817e))>>>((0x7757552b)-(0x980a64c3)-(0x899f2c0f))) % (((0xbdfcab34)+(!(0xa7fd5fec)))>>>((0xffed19be)+(0x888bcc99)))) >> 3]) = ((Float32ArrayView[1]));\n    (Float64ArrayView[(((imul((0xb96c77b9), ((-268435456.0) <= (-36028797018963970.0)))|0))+((((0xa14cf212)+(0xffffffff)+(0x434a82d1))>>>((0xfd8a5d3e)-(0xffffffff)-(0x74a7fb81))))+(((0x1b5952b5) <= (0x2c887945)) ? (0xbbc3cdad) : (0xf9f5050c))) >> 3]) = ((1.0));\n    d0 = (d1);\n    return +((+(((0xff65614e)) << ((0xffffffff)+((d0) <= (((+(0.0/0.0))) - ((d1))))))));\n  }\n  return f; }), f2); } catch(e0) { } try { this.b1.__proto__ = f0; } catch(e1) { } e0.has(p1); }\n }");
/*fuzzSeed-254361819*/count=115; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow((( ! ((Math.asinh((Math.fround(( ~ Math.fround(Math.pow(Math.fround(( + mathy1((y | 0), x))), Math.fround(x))))) >>> 0)) | 0) | 0)) | 0), Math.fround(Math.atan2(Math.fround(Math.max(Math.cos(y), Math.log10(Math.fround((y ? x : Math.fround(Math.tan(x))))))), Math.fround((( + (( + (-(2**53+2) != Math.abs(y))) >= ( + y))) & (Math.sqrt(((Math.fround(Math.hypot(Math.fround(-0x080000001), x)) ? (x >>> 0) : (x | 0)) >>> 0)) | 0)))))); }); testMathyFunction(mathy4, [-(2**53+2), -0, 1.7976931348623157e308, 2**53+2, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, 1, -(2**53-2), 2**53, -0x0ffffffff, -0x080000001, Math.PI, 0, 0x100000000, -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, -1/0, Number.MAX_VALUE, 2**53-2, -0x100000001, -Number.MAX_VALUE, 1/0, 0.000000000000001, 42]); ");
/*fuzzSeed-254361819*/count=116; tryItOut("t2 + '';var c = x;");
/*fuzzSeed-254361819*/count=117; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[0x3FFFFFFE, function(){}, 0x3FFFFFFE,  /x/ ,  /x/ ,  /x/ , x, function(){},  /x/ , []]) { print(x); }");
/*fuzzSeed-254361819*/count=118; tryItOut("mathy5 = (function(x, y) { return (Math.imul(Math.fround((( ~ ((( ~ (Math.atan2(((y & x) >>> 0), Math.atan2(Math.hypot(( + -0x0ffffffff), x), -0x080000001)) | 0)) | 0) | 0)) >>> 0)), (( + Math.hypot(Math.fround((Math.max(( + mathy0(( + y), ( + ( + Math.max(( + (x | x)), y))))), mathy1((Math.fround(( ~ Math.fround(y))) >>> 0), (y | 0))) >>> 0)), ( + Math.imul(Math.fround(Math.round(y)), Math.fround((((y | 0) ^ (x | 0)) >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, 0.000000000000001, 0x080000001, -(2**53+2), -Number.MAX_VALUE, -0, -1/0, -0x080000001, 2**53, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, 0, 1/0, 0x07fffffff, Number.MAX_VALUE, -(2**53), 2**53+2, 1, Number.MIN_VALUE, -0x100000001, Math.PI, -0x100000000, Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 0x100000001, 2**53-2, 1.7976931348623157e308, -0x07fffffff, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=119; tryItOut("\"use strict\"; t1[ /x/g ] = e0;");
/*fuzzSeed-254361819*/count=120; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.sin(Math.fround(Math.max(Math.atan(((((y >>> 0) <= (Math.max(y, (x >>> 0)) >>> 0)) >>> 0) >>> 0)), (Math.max((Math.imul(y, (y >>> 0)) >>> 0), Math.round(x)) && Math.fround(Math.abs(y))))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 2**53-2, 0/0, -0, 0.000000000000001, 0, -(2**53-2), 2**53, -Number.MIN_VALUE, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -0x100000000, -0x07fffffff, -0x080000001, 2**53+2, 0x080000000, Number.MIN_VALUE, -0x080000000, -(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-254361819*/count=121; tryItOut("delete g2.h2[\"__parent__\"];\nthis.e0.add(true);\n");
/*fuzzSeed-254361819*/count=122; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=123; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ ((Math.atan2((Math.max(Math.abs(Math.asinh(y)), ( ! ( + y))) >>> 0), (( ~ x) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, ['\\0', true, '0', '', (new Boolean(true)), NaN, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), [], [0], (function(){return 0;}), (new Number(-0)), (new Number(0)), 1, (new String('')), /0/, undefined, null, '/0/', ({toString:function(){return '0';}}), -0, false, objectEmulatingUndefined(), 0.1, 0, (new Boolean(false))]); ");
/*fuzzSeed-254361819*/count=124; tryItOut("throw this.y;");
/*fuzzSeed-254361819*/count=125; tryItOut("\"use strict\"; let (d) { for (var p in t0) { a2 = arguments; } }");
/*fuzzSeed-254361819*/count=126; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a1, [(function() { try { v2 = Object.prototype.isPrototypeOf.call(e1, m2); } catch(e0) { } try { s0.valueOf = (function() { v2 = a0.reduce, reduceRight(Promise.all, g0); return o1; }); } catch(e1) { } try { s0 += s0; } catch(e2) { } v1 = (o0 instanceof e1); return g2; }), a2]);");
/*fuzzSeed-254361819*/count=127; tryItOut("mathy2 = (function(x, y) { return ( ! Math.fround((Math.fround(( - Math.pow(0/0, Math.atan2(y, y)))) ? Math.fround(( + Math.imul(((mathy1(Math.fround((Math.fround(( + Math.tan(((x % y) >>> 0)))) > Math.fround(Math.min(y, Math.atan2(42, ( + y)))))), (Math.min(Math.cos(Math.min(y, Math.fround(y))), y) | 0)) | 0) >>> 0), (Math.imul(((y ? Math.pow(x, y) : -0x100000000) >>> 0), (-0x100000001 >>> 0)) >>> 0)))) : Math.pow(y, ( ! (1/0 ^ y)))))); }); testMathyFunction(mathy2, [({valueOf:function(){return '0';}}), (function(){return 0;}), ({toString:function(){return '0';}}), true, 0, [0], '0', (new Number(0)), [], '/0/', '', '\\0', ({valueOf:function(){return 0;}}), null, 0.1, -0, objectEmulatingUndefined(), (new String('')), NaN, (new Boolean(true)), (new Boolean(false)), 1, undefined, /0/, false, (new Number(-0))]); ");
/*fuzzSeed-254361819*/count=128; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: \"\\u7D8C\", enumerable: (function(y) { return (\u000c\"\\u84A0\" && new RegExp(\"\\\\B\", \"g\")).__defineSetter__(\"y\", Boolean) }).apply,  get: function() {  return a0.some((function() { o2 = new Object; throw this.e2; }), v0); } });");
/*fuzzSeed-254361819*/count=129; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = ((0xffffffff));\n    return +((-2147483649.0));\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [/0/, true, 1, -0, 0.1, (new Number(-0)), (new Boolean(true)), false, null, (new Boolean(false)), (function(){return 0;}), ({toString:function(){return '0';}}), undefined, '/0/', 0, objectEmulatingUndefined(), '', '0', NaN, [], (new Number(0)), (new String('')), ({valueOf:function(){return '0';}}), '\\0', [0], ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-254361819*/count=130; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=131; tryItOut("/*oLoop*/for (var akklll = 0; (arguments.callee.arguments = Uint16Array((() => [z1,,]).call(\"\\u4ED3\", window), x)) && ((void shapeOf(x))) && akklll < 22; ++akklll) { throw a; } ");
/*fuzzSeed-254361819*/count=132; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[this, false, 0/0,  /x/ , false, false, 0/0, 0/0, this,  /x/ ,  /x/ ,  /x/ , 0/0, false,  /x/ , 0/0, false, false, 0/0,  /x/ , 0/0, false, this,  /x/ , 0/0, false, false,  /x/ , false, 0/0, false, 0/0, false, this, false, this, this, false, 0/0, 0/0, false,  /x/ , this, false, this, 0/0]) { v2 = o2.g2.t2.length; }");
/*fuzzSeed-254361819*/count=133; tryItOut("var dcwayc = new SharedArrayBuffer(8); var dcwayc_0 = new Int8Array(dcwayc); print(dcwayc_0[0]); var dcwayc_1 = new Int8Array(dcwayc); dcwayc_1[0] = 17; var dcwayc_2 = new Float32Array(dcwayc); print(dcwayc_2[0]); dcwayc_2[0] = -18; var dcwayc_3 = new Int16Array(dcwayc); dcwayc_3[0] = 7; var dcwayc_4 = new Float32Array(dcwayc); dcwayc_4[0] = 4; var dcwayc_5 = new Uint8ClampedArray(dcwayc); print(dcwayc_5[0]); var dcwayc_6 = new Float32Array(dcwayc); var dcwayc_7 = new Uint32Array(dcwayc); /*tLoop*/for (let b of /*MARR*/[new Number(1)]) { print(dcwayc_6); }this.v2 = t0[4];(void schedulegc(g2.g1));v1 = this.g2.g1.runOffThreadScript();\nif(false) { if (\"\\u7C3C\"()) {print((Math.hypot(28, -23)));print(((window.repeat()) <= (4277))); } else print(s2);}\n");
/*fuzzSeed-254361819*/count=134; tryItOut("\"use strict\"; selectforgc(g0.o0);");
/*fuzzSeed-254361819*/count=135; tryItOut("print(g0);print(x);");
/*fuzzSeed-254361819*/count=136; tryItOut("e0.add(g1);");
/*fuzzSeed-254361819*/count=137; tryItOut("testMathyFunction(mathy1, [-0x100000001, 1, -1/0, -0x0ffffffff, 42, -0, 0x080000001, 2**53+2, -(2**53-2), 0.000000000000001, -(2**53+2), 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, 0/0, 0x0ffffffff, 0x100000001, Number.MIN_VALUE, 0x100000000, -(2**53), 2**53, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -Number.MIN_VALUE, 0x07fffffff, 0x080000000, -Number.MAX_VALUE, -0x100000000, Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-254361819*/count=138; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a2, 16, { configurable: (x % 22 != 17), enumerable: (x % 6 != 1), get: f2, set: (function() { t1 = t2[({a2:z2})]; return v0; }) });");
/*fuzzSeed-254361819*/count=139; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.max((((Math.ceil(-0x080000000) ** ( + (( + Math.tan(x)) - ( + Math.atan(x))))) !== (Math.hypot((((Math.sin(Math.log10(y)) | 0) ? (Math.fround((Math.fround(-0x080000001) >>> Math.fround(Math.max(x, y)))) | 0) : y) | 0), Math.pow(y, y)) >>> 0)) | 0), (( - (( ~ Math.fround((Math.fround(y) ? Math.fround(y) : Math.fround((((x >>> 0) >> (y >>> 0)) >>> 0))))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy0, [1, -0x100000000, -0x100000001, 0x080000001, -0, -(2**53+2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, Math.PI, -(2**53), -0x080000000, 2**53+2, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 0x100000001, 0x080000000, 0, -(2**53-2), 0x0ffffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 0/0, 1/0, 0.000000000000001, 42, -0x080000001]); ");
/*fuzzSeed-254361819*/count=140; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?![^])|.(?=(?:(?=\\\\1)*?))*\", \"g\"); var s = \"\\n\\na\\n\\na\\na1\\n\\n\\n\\na\\n\\na\\na1\\n\\na\\n\\na\\na1\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=141; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x080000000, 1.7976931348623157e308, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), 1/0, Number.MAX_VALUE, 0x100000000, -(2**53+2), 2**53+2, 0.000000000000001, 0/0, 0x100000001, -Number.MIN_VALUE, 0x080000001, -0x100000000, Number.MIN_VALUE, -1/0, 0, 42, -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, 1, -0x0ffffffff, 2**53, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-254361819*/count=142; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0, -(2**53), -0x080000000, -0x0ffffffff, 0x080000001, 2**53-2, 0x0ffffffff, Math.PI, 2**53, -0x07fffffff, -(2**53+2), 1, 1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 1.7976931348623157e308, -0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x100000000, 0x080000000, -1/0, -0x080000001, -0x100000000, Number.MIN_VALUE, 2**53+2, -(2**53-2), -0, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=143; tryItOut("Object.defineProperty(this, \"s0\", { configurable: (Map.prototype.values), enumerable: true,  get: function() {  return new String(o1); } });");
/*fuzzSeed-254361819*/count=144; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.max(Math.asin(Math.asin(Math.atan2(mathy0(x, ( - ( + (Math.tan(y) >>> 0)))), (Math.atan2(x, ( + y)) ^ y)))), ( ! Math.abs(Math.fround(Math.asinh(Math.fround(Number.MAX_SAFE_INTEGER)))))); }); testMathyFunction(mathy1, [-0x0ffffffff, 0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, Math.PI, 2**53-2, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, 0/0, -1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -Number.MIN_VALUE, 2**53+2, -(2**53), 42, 1, -0x100000001, 0.000000000000001, -0x100000000, 0x07fffffff, 1.7976931348623157e308, 0, -0, 1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=145; tryItOut("testMathyFunction(mathy2, [0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, 0x100000001, 0.000000000000001, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x0ffffffff, 2**53, 0x100000000, 1, 0, 42, -1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, 1.7976931348623157e308, -(2**53+2), Math.PI, Number.MIN_SAFE_INTEGER, -0, 0/0, 2**53-2, -Number.MAX_VALUE, -0x100000001, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-254361819*/count=146; tryItOut("g2.o1.o1.v0 = g0.runOffThreadScript();");
/*fuzzSeed-254361819*/count=147; tryItOut("\"use strict\"; print(\"\\uB1CF\");let d = /*UUV1*/(e.add = \"\\u56C9\");");
/*fuzzSeed-254361819*/count=148; tryItOut("i1 = new Iterator(m1);");
/*fuzzSeed-254361819*/count=149; tryItOut("/*RXUB*/var r = /$/ym; var s = \"\\n\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=150; tryItOut("\"use strict\"; ");
/*fuzzSeed-254361819*/count=151; tryItOut("Object.seal(o0);");
/*fuzzSeed-254361819*/count=152; tryItOut("switch(/*MARR*/[-0xB504F332, -0xB504F332, -0xB504F332].filter) { case 2: t1[({valueOf: function() { /*MXX3*/g1.RegExp.$' = g1.RegExp.$';return 18; }})];break; /*vLoop*/for (let opcoyo = 0, iyjhko; opcoyo < 79; ++opcoyo) { a = opcoyo; g0.b2 = new SharedArrayBuffer(88); } break; break; m1 = new WeakMap;case 6: v2 = g2.eval(\"/*bLoop*/for (lmuonv = 0, ({a1:1}); lmuonv < 40; ++lmuonv) { if (lmuonv % 109 == 14) { ( /x/ ); } else {  '' ; }  } \");break; case decodeURI((x%=\"\\u525B\")): a2 + h2;break; break; default: break;  }");
/*fuzzSeed-254361819*/count=153; tryItOut("Array.prototype.sort.apply(a2, [(function(j) { f1(j); })]);");
/*fuzzSeed-254361819*/count=154; tryItOut("h0.defineProperty = (function(j) { if (j) { try { h0.getOwnPropertyDescriptor = g0.f1; } catch(e0) { } try { this.a2[(function(x, y) { return y; }).unwatch(\"callee\")]; } catch(e1) { } /*RXUB*/var r = r2; var s = \"\\u00c3\"; print(s.search(r));  } else { try { a2[7] = (Math.asinh(29))[\"toLowerCase\"]--; } catch(e0) { } try { v0 = g1.eval(\"function f1(g2) \\\"use asm\\\"; /*oLoop*/for (var epvkbw = 0; epvkbw < 90; ++epvkbw) { v0 = g1.eval(\\\"(4277)\\\"); } \\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d0 = (d1);\\n    return +((1.9342813113834067e+25));\\n  }\\n  return f;\"); } catch(e1) { } Array.prototype.forEach.apply(a0, [(function mcc_() { var gpqazb = 0; return function() { ++gpqazb; f2(/*ICCD*/gpqazb % 6 == 3);};})(), o1.p1, b1]); } });");
/*fuzzSeed-254361819*/count=155; tryItOut("t2.set(a1, Math.max((4277), 0.866));");
/*fuzzSeed-254361819*/count=156; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.tan(( + ( + Math.hypot((( ! (Math.sinh((Math.round((Math.hypot(Number.MIN_VALUE, -Number.MIN_VALUE) ? (y >>> 0) : Math.fround(( + x)))) | 0)) >>> 0)) >>> 0), ( + (((Math.fround((Math.fround(( + ( ~ (( + Math.exp(0x080000001)) >>> 0)))) != (Math.pow((y | 0), (Number.MAX_SAFE_INTEGER | 0)) | 0))) | 0) % ((Math.fround(((Math.hypot((Number.MAX_VALUE >>> 0), (x >>> 0)) >>> 0) | ( + Math.pow(x, x)))) * Math.fround((Math.sinh(x) | 0))) | 0)) | 0))))))); }); testMathyFunction(mathy0, [-(2**53+2), -(2**53-2), -Number.MIN_VALUE, 0x0ffffffff, -(2**53), -0x0ffffffff, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, 0/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, Math.PI, -0x100000001, 0x080000001, 2**53-2, 0x100000000, 1.7976931348623157e308, 2**53, -1/0, 0x080000000, Number.MIN_VALUE, -0x080000001, 0.000000000000001, 0, -0x07fffffff, 1, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-254361819*/count=157; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[new Number(1), x, x, x, new Number(1), new Number(1), new Number(1), x, x, new Number(1), x, x, new Number(1), new Number(1), new Number(1), new Number(1), x, x, x, new Number(1), x, new Number(1), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1), x, new Number(1), x, x, x, x, new Number(1), x, x, x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, x, new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), x, x, new Number(1), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1), x, new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), x, x, x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, x, new Number(1), new Number(1), new Number(1), new Number(1), x, x, new Number(1), x, x, new Number(1), new Number(1), x, x, new Number(1), new Number(1)]) { arguments[\"min\"] = linkedList(arguments[\"min\"], 2622); }");
/*fuzzSeed-254361819*/count=158; tryItOut("");
/*fuzzSeed-254361819*/count=159; tryItOut("v2 = g0.eval(\"intern(/*UUV2*/(x.getSeconds = x.getUTCHours))\");");
/*fuzzSeed-254361819*/count=160; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1, (new Number(-0)), 0, '', -0, (new Boolean(false)), (function(){return 0;}), ({toString:function(){return '0';}}), '0', '\\0', ({valueOf:function(){return '0';}}), 0.1, /0/, '/0/', (new Boolean(true)), false, (new String('')), [], objectEmulatingUndefined(), [0], true, (new Number(0)), undefined, NaN, null, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-254361819*/count=161; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ ( + (Math.hypot((mathy0(mathy2(( + x), ( + x)), (( ~ y) | 0)) | 0), x) >> Math.pow(( + Math.atan2(( + (y || y)), ( + ( - y)))), Math.fround((((x | 0) && (Math.fround((Math.fround(Math.fround(Math.tan(Math.fround(Math.max(y, y))))) != Math.fround((y ? Number.MAX_SAFE_INTEGER : -0x0ffffffff)))) | 0)) | 0)))))); }); testMathyFunction(mathy5, [-1/0, Number.MIN_VALUE, -0x100000001, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, 1/0, -Number.MAX_VALUE, 0x080000000, 0.000000000000001, 1, -Number.MIN_VALUE, 2**53-2, -0, 0x100000000, -0x0ffffffff, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), 2**53, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, Number.MAX_VALUE, 42, -0x080000001, 0x100000001, 0/0, 2**53+2]); ");
/*fuzzSeed-254361819*/count=162; tryItOut("mathy1 = (function(x, y) { return Math.fround((((( + ( + y)) | 0) | 0) <= Math.fround((Math.imul(((( ~ (Math.hypot(Math.max(-0x100000000, ( + Math.fround(Math.max(( + x), Math.fround(y))))), ( + y)) | 0)) | 0) >>> 0), (( + (-Number.MAX_VALUE >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 1, 42, -Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, -0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 0/0, 1/0, -(2**53-2), 0x100000001, -0x100000001, -1/0, 2**53+2, -(2**53), -0x0ffffffff, 2**53, -0x080000000, 0, -0, Math.PI]); ");
/*fuzzSeed-254361819*/count=163; tryItOut("a2.splice(-11, 19);");
/*fuzzSeed-254361819*/count=164; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=165; tryItOut("mathy0 = (function(x, y) { return (( ! Math.max((( - Math.cos((Math.atan(x) | 0))) , ( - ( + Math.atan2(x, (1 >= (Math.fround((Math.fround(x) & (1.7976931348623157e308 | 0))) >>> 0)))))), (Math.log2((Math.max((( ~ ((0x080000001 || (0x0ffffffff >>> 0)) >>> 0)) >>> 0), ( + x)) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[-0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(true), -0x5a827999, new Boolean(true), -0x5a827999, -0x5a827999, new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), new Boolean(true), -0x5a827999, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999]); ");
/*fuzzSeed-254361819*/count=166; tryItOut("print(x);\no1.__iterator__ = o0.f2;\u0009\n");
/*fuzzSeed-254361819*/count=167; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.hypot(( + (( + Math.max(( + mathy0(y, y)), ( + ( + ( - (mathy0(y, ( + Math.pow(y, x))) | 0)))))) || (((Math.fround(((mathy1(Math.fround(Math.sin(Math.min(y, 0x080000000))), 0/0) | 0) * (-(2**53-2) | 0))) >>> 0) ^ (( ! Math.fround(Math.fround(Math.hypot((x >>> 0), Math.fround((x >>> x)))))) >>> 0)) >>> 0))), ( + (( + Math.abs((Math.sign(x) <= y))) + ( + ( ~ (( + y) >>> 0)))))) | 0); }); testMathyFunction(mathy2, [1, 0x100000000, -Number.MIN_VALUE, -(2**53-2), -(2**53), 0x0ffffffff, 2**53+2, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, 1/0, 0x080000000, 0x080000001, 0x100000001, -0x100000000, 0/0, Number.MIN_VALUE, Math.PI, 42, 0.000000000000001, 2**53, -0x080000001, -0, -(2**53+2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-254361819*/count=168; tryItOut("mathy2 = (function(x, y) { return (((( - (( ~ x) | 0)) | 0) >= ( + ( + (x === 0x080000000)))) >>> ( + (( + (( + ( - (mathy0(Math.fround(Math.log10((0x080000001 >>> 0))), (y | 0)) | 0))) | 0)) ? (( + (( + y) ? ( + x) : x)) * (mathy0(x, Number.MAX_VALUE) != ((Math.max(0x100000001, (( - Math.fround(x)) >>> 0)) >>> 0) * Math.tan(x)))) : (Math.sinh(Math.fround((Math.pow(1.7976931348623157e308, x) >>> 0))) ? ((y ? Math.fround((Math.pow(( + ( + ( + x))), (y | 0)) | 0)) : x) | 0) : ((mathy1(Math.fround(-Number.MAX_SAFE_INTEGER), (( + x) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy2, [0x100000001, Number.MAX_VALUE, -0x0ffffffff, 2**53, 2**53+2, 0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, 1/0, Math.PI, Number.MIN_VALUE, 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x07fffffff, 0x0ffffffff, -(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0x080000000, -0x100000001, -0x080000000, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, 1, 0/0, 0.000000000000001, 0x100000000, -1/0, -(2**53)]); ");
/*fuzzSeed-254361819*/count=169; tryItOut("mathy3 = (function(x, y) { return (( ~ (Math.min(Math.fround(((((Number.MIN_VALUE >>> 0) ? (y >>> 0) : Math.hypot(( + Math.sinh(( + y))), -Number.MIN_VALUE)) >>> 0) / ((Math.fround((x ^ y)) == -0x100000001) || x))), Math.fround(Math.atan2((x | 0), (Math.min((timeout(1800)), ( ! (( ! y) | 0))) | 0)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-254361819*/count=170; tryItOut("\"use strict\"; /*RXUB*/var r = ReferenceError(window, e); var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=171; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4(Math.fround(Math.max(( ! (Math.expm1(y) >>> 0)), (Math.trunc((( ! Math.sign(y)) >>> 0)) >>> 0))), ((Math.fround(( + Math.max(( + (Math.sin(Math.fround(y)) | 0)), ( + Math.fround(Math.cos(( + ( ~ y)))))))) > (Math.fround(Math.hypot(((Math.pow((y >>> 0), ( ~ y)) > y) | 0), ((Math.hypot((x === ((((Math.expm1(Math.fround(y)) >>> 0) >>> 0) ^ (x >>> 0)) >>> 0)), y) >>> 0) | 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [(new Number(-0)), ({valueOf:function(){return 0;}}), (new Boolean(false)), false, (new Boolean(true)), undefined, ({toString:function(){return '0';}}), true, -0, /0/, 1, '0', '', ({valueOf:function(){return '0';}}), NaN, (new String('')), 0.1, [], '/0/', [0], null, (function(){return 0;}), 0, objectEmulatingUndefined(), '\\0', (new Number(0))]); ");
/*fuzzSeed-254361819*/count=172; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.hypot(( + mathy1(( - x), ((mathy0(-0x100000001, Math.fround(Math.min(mathy0(x, y), ( + Math.fround(Math.asinh(Math.fround(1.7976931348623157e308))))))) | 0) != (y / y)))), ( + (((Math.imul((( - x) >>> 0), Math.max(-Number.MIN_VALUE, Number.MAX_SAFE_INTEGER)) | 0) != Math.fround(Math.atan2(( + Math.imul(x, (x >> x))), Math.log2((x | 0))))) >>> 0)))); }); testMathyFunction(mathy2, [0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, 0x080000000, -1/0, 0/0, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, 0x100000001, -0x100000000, -Number.MAX_VALUE, -(2**53-2), 2**53+2, Math.PI, 0, 2**53-2, Number.MAX_VALUE, -(2**53+2), 1, 1.7976931348623157e308, 42, -0x100000001, -(2**53), -0, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-254361819*/count=173; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log1p((Math.fround((Math.atan2(x, Math.log(x)) <= (Math.fround((Math.fround(( + ( + Math.log10(( + x))))) ^ Math.fround((mathy1(x, ( + x)) >>> 0)))) | 0))) == Math.fround(( - Math.fround(( + -0x0ffffffff)))))); }); testMathyFunction(mathy3, /*MARR*/[function(){}, function(){}, arguments.caller, arguments.caller,  \"use strict\" , function(){}, arguments.caller, function(){},  \"use strict\" , arguments.caller, arguments.caller,  \"use strict\" ,  \"use strict\" , arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, function(){},  \"use strict\" ,  \"use strict\" , function(){}]); ");
/*fuzzSeed-254361819*/count=174; tryItOut("Array.prototype.forEach.apply(a1, [Function.bind(this.g0)]);");
/*fuzzSeed-254361819*/count=175; tryItOut("\"use strict\"; window;true;");
/*fuzzSeed-254361819*/count=176; tryItOut("g2 = print((Math.unwatch(\"callee\").__defineSetter__(\"b\", Object.freeze)));;");
/*fuzzSeed-254361819*/count=177; tryItOut("for (var p in a1) { try { t0 = new Uint16Array(this.g0.t2); } catch(e0) { } try { v1 = evalcx(\"(4277)\", g1); } catch(e1) { } const e1 = new Set; }");
/*fuzzSeed-254361819*/count=178; tryItOut("testMathyFunction(mathy3, /*MARR*/[new Boolean(true),  '' , x, x, x,  '' , new Boolean(true), new Boolean(true),  '' , x, x, new Boolean(true), new Boolean(true), x, x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , x,  '' , new Boolean(true),  '' , x, x, new Boolean(true), new Boolean(true),  '' , x, new Boolean(true),  '' ,  '' ,  '' , new Boolean(true), x,  '' ,  '' , new Boolean(true), x, new Boolean(true), new Boolean(true), x,  '' , new Boolean(true), x,  '' , new Boolean(true), x,  '' ,  '' , x, x,  '' , x,  '' , new Boolean(true),  '' , new Boolean(true),  '' , x,  '' , x,  '' ,  '' , x, new Boolean(true),  '' , x, new Boolean(true),  '' , new Boolean(true), x,  '' ,  '' , x, new Boolean(true),  '' ,  '' , new Boolean(true), x,  '' ,  '' , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-254361819*/count=179; tryItOut("/*hhh*/function kzfriy(eval, \u3056, x, \u3056, a, x =  \"\" , x = x, x, x, b, NaN, e, b, x, e, x, x, x =  /x/g , b, x = undefined, x, NaN, c, x =  '' , delete, x, eval, x, window, x, x, window, eval, w, x,  , NaN, x, x, e, x, x =  /x/g , eval = x, x, NaN, x = a, window, d, x, a, x = \"\\u7DB9\", NaN, a, this.x, this, x, w, this, ...y){var nhuxpb = new ArrayBuffer(8); var nhuxpb_0 = new Uint16Array(nhuxpb); nhuxpb_0[0] = -22; v0 = r0.sticky;}kzfriy();");
/*fuzzSeed-254361819*/count=180; tryItOut("Array.prototype.unshift.call(a1, f0, f0);");
/*fuzzSeed-254361819*/count=181; tryItOut("Array.prototype.splice.apply(a1, [NaN, 3]);");
/*fuzzSeed-254361819*/count=182; tryItOut("/*RXUB*/var r = new RegExp(\"(?!((?:(?=[^\\\\d\\\\t\\uf28d\\\\x14-\\u4a90]))*?))\", \"ym\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=183; tryItOut("\"use strict\"; a1.forEach((function() { try { /*ODP-3*/Object.defineProperty(t1, new String(\"18\"), { configurable: (x % 4 != 0), enumerable: false, writable: new RegExp(\"(?:[^\\\\d\\u80e2])*?\", \"i\"), value: m1 }); } catch(e0) { } try { t1 = new Uint8ClampedArray(g1.a2); } catch(e1) { } s1 = x; return v1; }), g1.i0, o2.p0);\nt2[15] = undefined;\n([,,z1]);");
/*fuzzSeed-254361819*/count=184; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.asin(mathy2(Math.hypot((Math.exp(Math.imul(y, x)) != ( + mathy2((x >>> 0), (y | 0)))), (( ~ ( + Math.cbrt(Math.fround(Math.pow((y | 0), Math.fround(x)))))) >>> 0)), (Math.fround(Math.max(Math.fround(mathy1(0x07fffffff, y)), (y == y))) ? (y ? Math.fround((Math.imul(x, ((x !== Math.fround(x)) | 0)) * x)) : Math.pow(( + mathy2(( + x), ( ! x))), x)) : ( ~ mathy2(Math.fround(( ~ Math.fround(y))), x))))); }); testMathyFunction(mathy3, ['\\0', (function(){return 0;}), false, '', NaN, null, 0.1, objectEmulatingUndefined(), [], [0], true, /0/, (new String('')), ({valueOf:function(){return 0;}}), 1, (new Number(0)), '0', 0, '/0/', (new Boolean(true)), ({toString:function(){return '0';}}), -0, (new Boolean(false)), undefined, ({valueOf:function(){return '0';}}), (new Number(-0))]); ");
/*fuzzSeed-254361819*/count=185; tryItOut("L:switch(x) { case 6: /*RXUB*/var r = /(?:(?=\\1)\\2)|\\3?/i; var s = \"\"; print(s.split(r)); print(r.lastIndex); break; case 3: h0.toSource = f0; }");
/*fuzzSeed-254361819*/count=186; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.log10((( - (Math.imul(( + mathy4(-0, ( + Math.clz32(y)))), Math.cos(0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [(new Number(-0)), 0, '0', null, '/0/', false, (new Boolean(true)), 1, objectEmulatingUndefined(), '', true, (function(){return 0;}), '\\0', -0, (new Number(0)), /0/, NaN, [0], (new Boolean(false)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new String('')), [], ({valueOf:function(){return '0';}}), undefined, 0.1]); ");
/*fuzzSeed-254361819*/count=187; tryItOut("mathy2 = (function(x, y) { return Math.asin(Math.fround(Math.expm1(Math.abs((( + ( + Math.hypot(Math.fround(-Number.MIN_SAFE_INTEGER), ( + -0x080000000)))) + 0x100000000))))); }); testMathyFunction(mathy2, [false, ({valueOf:function(){return '0';}}), [0], '\\0', ({valueOf:function(){return 0;}}), '', ({toString:function(){return '0';}}), (new String('')), 1, /0/, (new Number(-0)), true, NaN, (new Boolean(true)), (new Number(0)), 0, undefined, null, (function(){return 0;}), -0, '0', 0.1, [], (new Boolean(false)), '/0/', objectEmulatingUndefined()]); ");
/*fuzzSeed-254361819*/count=188; tryItOut("\"use strict\"; b0 = new SharedArrayBuffer(40);");
/*fuzzSeed-254361819*/count=189; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( + Math.sqrt(( + ( + Math.min((( - (y | 0)) | 0), ( + -1/0))))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x080000000, 1, -Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), -0, 0, Math.PI, -0x07fffffff, 0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, -0x100000000, -0x100000001, -1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 2**53-2, 2**53+2, 1/0, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, -0x080000001, Number.MIN_VALUE, -(2**53), 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=190; tryItOut("if((x % 5 != 3)) {;print(x); } else  if (new ( '' )()) {Object.defineProperty(this, \"t0\", { configurable: (x % 27 == 11), enumerable: (x % 3 == 2),  get: function() {  return t2.subarray(19, 17); } });print(x); }");
/*fuzzSeed-254361819*/count=191; tryItOut("\"use strict\"; if(false) {this.f2(e1);i1.next(); }\u000c");
/*fuzzSeed-254361819*/count=192; tryItOut("for (var p in i0) { s2 = new String(p0); }");
/*fuzzSeed-254361819*/count=193; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[Object.defineProperty([], \"keys\", ({})), function(){}, objectEmulatingUndefined(), -0x2D413CCC, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, function(){}, Object.defineProperty([], \"keys\", ({})), Object.defineProperty([], \"keys\", ({})), function(){}, function(){}, Object.defineProperty([], \"keys\", ({})), objectEmulatingUndefined(), Object.defineProperty([], \"keys\", ({})), -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, objectEmulatingUndefined(), function(){}, -0x2D413CCC, -0x2D413CCC, Object.defineProperty([], \"keys\", ({})), -0x2D413CCC, -0x2D413CCC, objectEmulatingUndefined(), function(){}, Object.defineProperty([], \"keys\", ({})), function(){}, -0x2D413CCC, function(){}, function(){}, -0x2D413CCC, -0x2D413CCC, function(){}, Object.defineProperty([], \"keys\", ({})), function(){}, function(){}, Object.defineProperty([], \"keys\", ({})), Object.defineProperty([], \"keys\", ({})), objectEmulatingUndefined(), objectEmulatingUndefined(), Object.defineProperty([], \"keys\", ({})), Object.defineProperty([], \"keys\", ({})), objectEmulatingUndefined(), function(){}, Object.defineProperty([], \"keys\", ({})), function(){}, -0x2D413CCC, objectEmulatingUndefined(), function(){}, Object.defineProperty([], \"keys\", ({})), function(){}, -0x2D413CCC, function(){}, function(){}, Object.defineProperty([], \"keys\", ({})), -0x2D413CCC, Object.defineProperty([], \"keys\", ({})), Object.defineProperty([], \"keys\", ({})), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, -0x2D413CCC, Object.defineProperty([], \"keys\", ({})), function(){}, function(){}, function(){}, function(){}, Object.defineProperty([], \"keys\", ({})), function(){}, Object.defineProperty([], \"keys\", ({})), function(){}, function(){}, -0x2D413CCC, function(){}, objectEmulatingUndefined(), Object.defineProperty([], \"keys\", ({})), function(){}, Object.defineProperty([], \"keys\", ({})), objectEmulatingUndefined(), -0x2D413CCC, function(){}, -0x2D413CCC, Object.defineProperty([], \"keys\", ({})), objectEmulatingUndefined(), Object.defineProperty([], \"keys\", ({})), function(){}, Object.defineProperty([], \"keys\", ({})), -0x2D413CCC, objectEmulatingUndefined(), -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, objectEmulatingUndefined(), function(){}, Object.defineProperty([], \"keys\", ({})), Object.defineProperty([], \"keys\", ({})), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, Object.defineProperty([], \"keys\", ({})), function(){}, function(){}, -0x2D413CCC, function(){}]) { /*RXUB*/var r = r0; var s = s1; print(s.search(r));  }");
/*fuzzSeed-254361819*/count=194; tryItOut("mathy2 = (function(x, y) { return Math.log(Math.fround(( + Math.fround(((mathy0(y, (mathy1(x, Math.fround(0x0ffffffff)) | 0)) | 0) != (((-Number.MAX_VALUE >>> 0) == ( ~ Math.imul(x, 0/0))) >>> 0)))))); }); ");
/*fuzzSeed-254361819*/count=195; tryItOut("x;");
/*fuzzSeed-254361819*/count=196; tryItOut("\"use strict\"; v1 = 0;");
/*fuzzSeed-254361819*/count=197; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.acosh(( + ( + Math.imul(( + (Math.expm1(x) != ( + ((Math.atan2(Math.fround(( - Math.fround(x))), ((0x07fffffff | 0) != 1.7976931348623157e308)) | 0) ? ( + x) : ( + y))))), ( + Math.sqrt(Math.fround(Math.clz32((((((1 << y) | 0) <= (y | 0)) | 0) | 0))))))))); }); testMathyFunction(mathy5, /*MARR*/[true, true, new String('q'), -Infinity, new Boolean(true), -Infinity, -Infinity, -Infinity, true, new String('q'), new Boolean(true), new Boolean(true), -Infinity, true, new Boolean(true), true, true, true, new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), -Infinity, new String('q'), true, new Boolean(true), new Boolean(true), true, new Boolean(true), true]); ");
/*fuzzSeed-254361819*/count=198; tryItOut("s2 + '';\n/*infloop*/M:for([\u0009y++]; e|= ''  +  '' ; (25.__defineGetter__(\"x\", String.prototype.search))) {print(x) /x/g ; }\n");
/*fuzzSeed-254361819*/count=199; tryItOut("Object.defineProperty(this, \"v0\", { configurable: true, enumerable: ({ set x eval ()\"use asm\";   var cos = stdlib.Math.cos;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      (Float32ArrayView[((((((-134217728.0)) / ((2049.0))) + ((0xffffffff) ? (-288230376151711740.0) : (-1.0009765625))) >= (d1))) >> 2]) = ((d1));\n    }\n    (Int32ArrayView[(((((+(0.0/0.0))) * ((d0))))) >> 2]) = (((0x407a4198) == (((0x55a79dc4))>>>(((((0xfbbc857c))>>>((0xbd196b3d))) == (0x0))-(0xc9d235c4))))+((((((0xfaa7362b) ? (0x3908cd0e) : (0xfab5631a)) ? (0x64e41db0) : (0x5104a850))*0x3ab3b)>>>(((0x7106379c))+(0xc11bb9c6)-((((0x2b5550e6)) & ((0x28500c77)))))) > (((0xd5b35906)+(0xfcc39713))>>>(-0x1844d*(0xac665f2)))));\n    d0 = (d0);\n    switch ((~(0xad0d0*(0xfcb64d33)))) {\n      default:\n        {\n          d1 = (+(-1.0/0.0));\n        }\n    }\n    d0 = (+cos(((Int32ArrayView[((0x551787af) % (((0x86350f53))>>>((-0x8000000)))) >> 2]))));\n    return +((Float32ArrayView[((!(0xc4f08623))-(-0x8000000)) >> 2]));\n    d0 = (d0);\n    d1 = (d0);\n    return +((+(1.0/0.0)));\n  }\n  return f;, \"-15\": window >= x }),  get: function() {  return t0.length; } });");
/*fuzzSeed-254361819*/count=200; tryItOut("\"use asm\"; p2 = m0.get(true);");
/*fuzzSeed-254361819*/count=201; tryItOut("/*RXUB*/var r = new RegExp(\"[\\\\u00e9]\\\\3|(?=\\\\2{2097151,2097152}|(?:[^]\\\\B))([\\\\x36-\\u5682\\\\w\\\\0\\u00ba]\\\\u00a9?|(?!\\\\S)*?+?){4,}{33554431,33554432}\", \"gyim\"); var s = \"\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u26926aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u2692\\n1a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\\u26920a0a\\u610e\\u610e\\u610e\\u610e\\u610e\\u610ea\\u610e\\u610e\\u610e\\u610e\\u610e\\u610e\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=202; tryItOut("o1 = {};\no2.toString = (function() { for (var j=0;j<48;++j) { f2(j%5==1); } });\n");
/*fuzzSeed-254361819*/count=203; tryItOut("for (var p in s1) { try { this.a2.forEach(); } catch(e0) { } v1 = null; }");
/*fuzzSeed-254361819*/count=204; tryItOut("v2 = r0.sticky;");
/*fuzzSeed-254361819*/count=205; tryItOut("\"use strict\"; for (var v of g2) { try { /*MXX3*/g0.RegExp.prototype.sticky = g1.RegExp.prototype.sticky; } catch(e0) { } try { (void schedulegc(g0)); } catch(e1) { } o0.m0.has(v2); }");
/*fuzzSeed-254361819*/count=206; tryItOut("\"use strict\"; switch(\"\\u8B77\") { case  /x/ : break; default:  }");
/*fuzzSeed-254361819*/count=207; tryItOut("g1.offThreadCompileScript(\";\");");
/*fuzzSeed-254361819*/count=208; tryItOut("mojehx, x = \"\\u308C\", x, pzsdwr, ykiism, z, z;/*tLoop*/for (let x of /*MARR*/[null,  /x/g ,  /x/g ,  /x/g ,  /x/g , null,  /x/g ,  /x/g , null,  /x/g , null,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , null,  /x/g , null, null, null,  /x/g , null,  /x/g , null, null, null, null, null,  /x/g , null, null, null, null,  /x/g , null,  /x/g , null, null, null,  /x/g , null, null, null, null,  /x/g ,  /x/g , null,  /x/g ,  /x/g ,  /x/g , null, null, null, null, null, null, null,  /x/g ,  /x/g , null,  /x/g , null, null, null, null,  /x/g ,  /x/g , null, null, null, null,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , null,  /x/g ,  /x/g , null, null,  /x/g , null, null, null, null,  /x/g , null, null, null, null,  /x/g , null,  /x/g , null, null, null,  /x/g ,  /x/g ,  /x/g , null, null, null,  /x/g ,  /x/g , null, null,  /x/g , null,  /x/g , null,  /x/g ,  /x/g ,  /x/g , null,  /x/g ]) {  }");
/*fuzzSeed-254361819*/count=209; tryItOut("g1.offThreadCompileScript(\"a0 = g0.a1.filter(f0);\");");
/*fuzzSeed-254361819*/count=210; tryItOut("for (var p in p1) { h0.has = f1; }");
/*fuzzSeed-254361819*/count=211; tryItOut("\"use strict\"; if((x % 2 == 1)) t1 + '';Array.prototype.sort.apply(g0.g2.a1, [g0.g1]); else  if (x >> x) print(new RegExp(\"^{2,3}\", \"gym\").__defineSetter__(\"x\", Object.isFrozen)); else Array.prototype.forEach.apply(a1, [(function() { try { g1.g1.v1.valueOf = (function() { m0 = new WeakMap; return h0; }); } catch(e0) { } try { a0.shift(); } catch(e1) { } o2.i2.next(); return t0; })]);");
/*fuzzSeed-254361819*/count=212; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.clz32(Math.fround(Math.atan2(( - x), y))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), 0/0, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 42, -(2**53-2), 0, -0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 0x080000001, Number.MIN_VALUE, 2**53, Number.MAX_VALUE, 0x07fffffff, 1/0, -(2**53+2), -1/0, 1, 0.000000000000001, -Number.MIN_VALUE, -0x0ffffffff, -0x100000000, 2**53-2, Math.PI, 0x100000001, -0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=213; tryItOut("testMathyFunction(mathy0, [-0x080000001, -0, 0x080000000, 1, -0x07fffffff, 0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, 0, 2**53-2, -(2**53), -0x080000000, 0x07fffffff, -0x0ffffffff, -(2**53-2), Number.MIN_VALUE, -0x100000001, 0x100000000, 1/0, 2**53, -(2**53+2), 2**53+2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000001, 42, 0x100000001, -Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=214; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 35184372088833.0;\n    var i3 = 0;\n    {\n      (Float32ArrayView[4096]) = ((0.0078125));\n    }\n    {\n      (Float64ArrayView[4096]) = ((-1.9342813113834067e+25));\n    }\n    return +((((makeFinalizeObserver('nursery'))) % ((d2))));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; return this.zzz.zzz = y }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, Math.PI, 0x080000001, 2**53+2, -0, -0x080000001, 0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, 2**53-2, -1/0, 0, 1, -0x080000000, 42, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0/0, Number.MAX_VALUE, -0x100000000, -0x100000001, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=215; tryItOut("allocationMarker();");
/*fuzzSeed-254361819*/count=216; tryItOut("for (var v of v1) { try { g0.a2 + ''; } catch(e0) { } try { e0.add(b1); } catch(e1) { } function f2(this.s1)  { /*vLoop*/for (let feyioz = 0, NaN = /*FARR*/[false, -4].filter(DataView.prototype.setFloat64); feyioz < 9; ++feyioz) { var z = feyioz; print(uneval(g0.m1)); }  }  }");
/*fuzzSeed-254361819*/count=217; tryItOut("g0.v0 = (a2 instanceof h0);");
/*fuzzSeed-254361819*/count=218; tryItOut("s2.valueOf = (function() { v1 = Object.prototype.isPrototypeOf.call(i1, this.t0); return t2; });");
/*fuzzSeed-254361819*/count=219; tryItOut("for(let e in +x) ;");
/*fuzzSeed-254361819*/count=220; tryItOut("for(var x in (((this.zzz.zzz))((void \u0009window))))a0[2] = i1;");
/*fuzzSeed-254361819*/count=221; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    switch ((~((i1)))) {\n      default:\n        i0 = (i1);\n    }\n    i0 = (i0);\n    i0 = ((i1) ? (((((131073.0) <= (-8388609.0))) << ((i1)-((~~(-3.777893186295716e+22))))) <= ((((-1.125) <= (-134217728.0))*-0x3c86)|0)) : (x));\n    {\n      {\n        (Int32ArrayView[4096]) = ((i0)+(!(i1))-(i0));\n      }\n    }\n    i0 = (/*FFI*/ff(((Infinity)), ((NaN)))|0);\n    i1 = (i1);\n    i0 = (i1);\n    i0 = (i0);\n    i1 = (((((~((i1))) <= (((0xf87f9509)*-0x95c5f) << ((0x6f8c77cd)-(-0x8000000))))*-0xae967) << ((i0))) < (~((i0))));\nvar mzfxzx = new ArrayBuffer(8); var mzfxzx_0 = new Float64Array(mzfxzx); mzfxzx_0[0] = -8; Array.prototype.splice.call(a2, NaN,  \"\" , i2, g1, s0, t0, f2);    return +(((i1) ? (((1.5)) % ((+/*FFI*/ff()))) : (9.44473296573929e+21)));\n  }\n  return f; })(this, {ff: (new Function(\"Array.prototype.reverse.call(a0, m0, g0.v0);\"))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-254361819*/count=222; tryItOut("\"use strict\"; m0 = new Map(a1);");
/*fuzzSeed-254361819*/count=223; tryItOut("\"use strict\"; \"use asm\"; g1.o1 = g1.__proto__;");
/*fuzzSeed-254361819*/count=224; tryItOut("Object.prototype.unwatch.call(m0, \"asinh\");");
/*fuzzSeed-254361819*/count=225; tryItOut("\"use strict\"; Array.prototype.forEach.apply(this.a1, [(function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -16384.0;\n    d2 = (d2);\n    return ((-0xfffff*((((((0xffffffff)+(0xfd5e0cde)+(0xb4c571e5))>>>((0xfd7fc595)+(0xffffffff))) / (0xbb5be30e))>>>(((((0xfd69b472)-(0xff824ee4)+(0xff621279))>>>((Int16ArrayView[((0xff44d797)) >> 1]))))+((((0x5decfed8) % (0x4e5516e5)) >> (((0xfada590a) ? (0x1448a9d4) : (0x7de8970a))))))))))|0;\n    i1 = (0x59e6a69c);\n    switch ((imul((1), (0xff335e4e))|0)) {\n      default:\n        i1 = (0xf4bb4f4b);\n    }\n    i1 = (0xfd72ab91);\n;    {\n      i1 = (0xb096446d);\n    }\n    d0 = (+atan2(((d2)), (((d0) + (Infinity)))));\n    return (((0x8fa1a5a6)-(1)-(i1)))|0;\n  }\n  return f; })]);");
/*fuzzSeed-254361819*/count=226; tryItOut("print(o2);");
/*fuzzSeed-254361819*/count=227; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.log(Math.log10(( + Math.min(x, -Number.MIN_SAFE_INTEGER)))); }); ");
/*fuzzSeed-254361819*/count=228; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((Math.fround(Math.asinh(Math.atan2(( + ( ~ ( + (( - (y | 0)) | 0)))), (Math.hypot((( + ((0x07fffffff == ( + y)) >>> 0)) >>> 0), (x | 0)) | 0)))) % Math.fround((( ~ (Math.pow((x >> ( - (mathy0(((( - (0 | 0)) >>> 0) | 0), (y | 0)) | 0))), Math.imul(-0x100000000, ( + x))) | 0)) | 0)))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x0ffffffff, -1/0, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, -0x100000001, -(2**53), -0x0ffffffff, Number.MAX_VALUE, 2**53+2, -0x080000000, 0x07fffffff, 42, 1/0, Math.PI, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0, 0x100000001, 2**53, -(2**53+2), 1, 0/0, 0x080000001]); ");
/*fuzzSeed-254361819*/count=229; tryItOut("\"use strict\"; var bhlhzt = new ArrayBuffer(3); var bhlhzt_0 = new Uint16Array(bhlhzt); var bhlhzt_1 = new Int16Array(bhlhzt); var bhlhzt_2 = new Int32Array(bhlhzt); var bhlhzt_3 = new Float32Array(bhlhzt); bhlhzt_3[0] = 3; var bhlhzt_4 = new Int16Array(bhlhzt); bhlhzt_4[0] = -23; var bhlhzt_5 = new Uint8Array(bhlhzt); bhlhzt_5[0] = -12; var bhlhzt_6 = new Uint8Array(bhlhzt); var bhlhzt_7 = new Float64Array(bhlhzt); var bhlhzt_8 = new Float64Array(bhlhzt); bhlhzt_8[0] = 10; var bhlhzt_9 = new Int8Array(bhlhzt); var bhlhzt_10 = new Uint32Array(bhlhzt); print(bhlhzt_10[0]); var bhlhzt_11 = new Uint16Array(bhlhzt); /*infloop*/while(new RegExp(\"^\", \"gyi\").__defineGetter__(\"c\", q => q))print(((bhlhzt_6 = [,])));s2 = a1.join(s1);var zoptwr = new SharedArrayBuffer(16); var zoptwr_0 = new Int8Array(zoptwr); zoptwr_0[0] = -22; var zoptwr_1 = new Uint8Array(zoptwr); zoptwr_1[0] = -2124130769; var zoptwr_2 = new Int8Array(zoptwr); zoptwr_2[0] = -12; var zoptwr_3 = new Uint16Array(zoptwr); zoptwr_3[0] = -287441313.5; v2 = t2[\"cbrt\"];a2.sort((function() { this.v2 = Object.prototype.isPrototypeOf.call(a1, g0.e1); return o0; }), g0.e1, g0, o2, e1);print(bhlhzt_1);Array.prototype.forEach.apply(a1, [(function() { try { a0.push(window, m0); } catch(e0) { } Array.prototype.pop.call(a0); throw g1; }), o0]);([,,]);o0 = this.a0.__proto__;e2 = new Set;a0[v2] =  \"\" ;function bhlhzt_1[0](bhlhzt_7[0])\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+(0.0/0.0));\n    (Float32ArrayView[4096]) = ((73786976294838210000.0));\n    return (((!(i1))+(((p={}, (p.z = timeout(1800))())) != (~(((-0x34ab1*(i1)) >> ((0xf875cb81)*-0xfffff)) % (((!(0x730e5d88))+(i1)) >> ((0xf92106b3)-(i1))))))))|0;\n  }\n  return f;g2.offThreadCompileScript(\"\\\"use strict\\\"; mathy2 = (function(x, y) { return Math.imul((( + (Math.max((( + Math.cosh(( + ( - 1/0)))) >>> 0), Math.fround(mathy1(y, y))) | 0)) >>> 0), (( + Math.max(((Math.round((x >>> 0)) >>> 0) % mathy0(( + mathy0(( + x), ( + 0.000000000000001))), ( ~ Math.sinh(x)))), (Math.abs(Math.fround(( + mathy0(( + Number.MIN_VALUE), ( + ( + mathy1(Math.fround((Math.fround(x) ^ y)), y))))))) | 0))) >>> 0)); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0, -0x080000001, 1, 2**53+2, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, -1/0, 1/0, 0x07fffffff, -0, -Number.MAX_VALUE, -0x100000000, 0/0, 0.000000000000001, 42, 2**53-2, 0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -(2**53-2)]); \");");
/*fuzzSeed-254361819*/count=230; tryItOut("\"use strict\"; g2.a2.length = 1;");
/*fuzzSeed-254361819*/count=231; tryItOut("testMathyFunction(mathy1, [2**53-2, -1/0, 1/0, 42, -0x080000000, -0, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 0.000000000000001, 0/0, -0x100000000, -0x100000001, Math.PI, -Number.MAX_VALUE, -(2**53-2), Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, -(2**53+2), -Number.MIN_VALUE, 0, 0x100000001, 0x0ffffffff, -0x0ffffffff, 1, 2**53+2, 0x07fffffff, -0x080000001, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=232; tryItOut("\"use strict\"; v0 = g2.eval(\"function f1(g0.o1) window\");");
/*fuzzSeed-254361819*/count=233; tryItOut("mathy3 = (function(x, y) { return Math.round((Math.fround(Math.acos(( - Math.sin(Math.fround((y ? 0x080000000 : (( + Math.imul(Math.min((y | 0), y), y)) | 0))))))) | 0)); }); testMathyFunction(mathy3, [2**53-2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000000, -0x07fffffff, -1/0, 1/0, 1, 0, -0x100000001, -(2**53), 2**53, -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, 2**53+2, 1.7976931348623157e308, 0x0ffffffff, 42, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, -0x080000000, -(2**53+2), 0/0, 0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-254361819*/count=234; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1152921504606847000.0;\n    return (((/*FFI*/ff()|0)-(0xbc4a1f51)))|0;\n  }\n  return f; })(this, {ff: Math.pow((function ([y]) { })().throw(\"\\uA94B\"), -28)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53-2, 42, 0x100000001, 0x100000000, -0x080000001, Number.MAX_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 1, 0x080000001, 0x080000000, 2**53, -0x100000001, Number.MIN_VALUE, -1/0, 1/0, 0/0, Number.MAX_SAFE_INTEGER, 0, Math.PI, -0, -(2**53+2), -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, -Number.MIN_VALUE, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53)]); ");
/*fuzzSeed-254361819*/count=235; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.tanh(Math.fround(Math.hypot((( + ( - y)) | 0), Math.pow(-Number.MIN_SAFE_INTEGER, mathy2(y, ((((( ~ y) | 0) ? (x | 0) : (y | 0)) | 0) ? x : mathy3(( + x), ( + x)))))))); }); testMathyFunction(mathy4, /*MARR*/[function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-254361819*/count=236; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( - (Math.expm1(Math.fround(Math.max(Math.fround(x), Math.fround((Math.clz32((mathy2(y, x) | 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-254361819*/count=237; tryItOut("let c = ({b: x});Object.defineProperty(this, \"t2\", { configurable: -26, enumerable: -21,  get: function() {  return new Uint8Array(({valueOf: function() { print(x);return 0; }})); } });");
/*fuzzSeed-254361819*/count=238; tryItOut("eklznz( \"\" );/*hhh*/function eklznz(){[,] -  /x/g ;}");
/*fuzzSeed-254361819*/count=239; tryItOut("testMathyFunction(mathy3, [0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, -0x0ffffffff, 1/0, 0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, -0x080000001, -1/0, -0x07fffffff, 42, 2**53-2, 0x080000000, -0, 0x0ffffffff, 0/0, -0x080000000, 2**53, 1, 1.7976931348623157e308, 0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, 2**53+2, 0x100000001]); ");
/*fuzzSeed-254361819*/count=240; tryItOut("\"use strict\"; /*infloop*/L:for(var y; (new String.prototype.concat()); Math.atan2(-2247854481, 3)) /*infloop*/for(let ([]) in  '' ) Array.prototype.forEach.call(a1, (function(j) { if (j) { try { e1.delete(e0); } catch(e0) { } try { v0 = (p0 instanceof b0); } catch(e1) { } try { m0.has(s0); } catch(e2) { } m2 = new Map(f2); } else { try { /*RXUB*/var r = r2; var s = s2; print(s.split(r));  } catch(e0) { } try { v1 = true; } catch(e1) { } try { s1.__proto__ = v2; } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(a0, g0.b1); } }), this.g1.e0);");
/*fuzzSeed-254361819*/count=241; tryItOut("/*tLoop*/for (let z of /*MARR*/[new Boolean(false), eval]) { throw (p={}, (p.z = new (w--)((4277),  \"\" ))()); }");
/*fuzzSeed-254361819*/count=242; tryItOut("for(let a in ((WeakMap)(/.(?!\\S){3,}\u8f18$|\\D{2,5}^(?!.[^]|[\\\u0090\\cJ]+){1,}*/yim >>>= b))){for (var v of g0) { try { a2.shift(); } catch(e0) { } try { m0 = new Map(f1); } catch(e1) { } s1 += 'x'; }print(eval(\"\\\"use strict\\\"; testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, Math.PI, -1/0, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0, Number.MIN_VALUE, 0x100000000, -Number.MIN_VALUE, 0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -0x07fffffff, 2**53+2, -0x100000001, 0x080000001, 1, 1/0, -0x100000000, -0x0ffffffff, 2**53-2, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, -0, -0x080000001, 42, -Number.MAX_VALUE, Number.MAX_VALUE, 0x07fffffff]); \") - String.prototype.italics); }");
/*fuzzSeed-254361819*/count=243; tryItOut("testMathyFunction(mathy0, [1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -0x07fffffff, 0.000000000000001, 0x080000000, -(2**53-2), -Number.MAX_VALUE, 42, -0, -(2**53), Number.MIN_VALUE, 0x07fffffff, -(2**53+2), 0, -0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000001, Number.MAX_SAFE_INTEGER, -1/0, 1/0, 1, -0x100000000, 0x100000000, 2**53, -Number.MIN_VALUE, 0x080000001, -0x080000001, 0x100000001, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=244; tryItOut("s0 = o1.s2.charAt(x);");
/*fuzzSeed-254361819*/count=245; tryItOut("testMathyFunction(mathy5, [1, Math.PI, 42, 0x080000000, 2**53-2, -0x100000001, -Number.MIN_VALUE, 0, 2**53, 0x0ffffffff, -(2**53), -0x100000000, Number.MAX_VALUE, -0, 0/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, -(2**53+2), Number.MIN_VALUE, 2**53+2, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -0x07fffffff, -0x080000001]); ");
/*fuzzSeed-254361819*/count=246; tryItOut("yield ((makeFinalizeObserver('nursery')));w = e;");
/*fuzzSeed-254361819*/count=247; tryItOut("let(x = x, e, x) { let(a) ((function(){return 28;})());}");
/*fuzzSeed-254361819*/count=248; tryItOut("\"use strict\"; (Map.prototype.set) = x;");
/*fuzzSeed-254361819*/count=249; tryItOut("/*oLoop*/for (xbrxoa = 0; xbrxoa < 2; ++xbrxoa) { s1 += s0; } i2 = f2;");
/*fuzzSeed-254361819*/count=250; tryItOut("M: for (var e of x) print(x);");
/*fuzzSeed-254361819*/count=251; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=252; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return ((Math.sinh(Math.atan2(Math.fround(-(2**53+2)), ( + 2**53))) | 0) ? ( ~ (((((Math.fround((x ** x)) >> ((Math.fround(y) % Math.fround((mathy0((42 | 0), (x | 0)) | 0))) | 0)) | 0) ? (Math.max(x, -0x080000001) | 0) : ((((( + ( + y)) >>> 0) >> ((Math.imul((((x | 0) || (1.7976931348623157e308 | 0)) | 0), (0 | 0)) | 0) >>> 0)) >>> 0) | 0)) | 0) | 0)) : ( + (Math.min((( ~ mathy0(Math.max(Math.pow(y, 2**53), y), x)) | 0), (Math.tanh((Math.imul((x | 0), Math.fround(mathy0(-(2**53+2), x))) | 0)) | 0)) | 0))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), 1, '0', (new String('')), '/0/', (new Number(-0)), (new Number(0)), [], ({valueOf:function(){return '0';}}), (new Boolean(false)), '\\0', '', [0], ({toString:function(){return '0';}}), true, (function(){return 0;}), ({valueOf:function(){return 0;}}), -0, null, NaN, false, 0.1, undefined, 0, (new Boolean(true)), /0/]); ");
/*fuzzSeed-254361819*/count=253; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.clz32(mathy2(((Math.tanh((mathy1((x | 0), ((Math.hypot(Math.fround(x), (-0 | 0)) | 0) >>> 0)) >>> 0)) >>> 0) | 0), ((Math.tan(( + (( + -1/0) <= mathy1(( + x), 1/0)))) | 0) >>> 0)))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 1/0, 0/0, 2**53, -(2**53+2), 0, -1/0, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, -0x100000001, 2**53+2, 1.7976931348623157e308, -(2**53), Math.PI, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, -0, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), 2**53-2, 0x100000001, 42, 0x100000000, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=254; tryItOut("if(true) print(x) else const v0 = new Number(o0.m2);");
/*fuzzSeed-254361819*/count=255; tryItOut("mathy0 = (function(x, y) { return (( + (( + Math.log2(( ~ (y | 0)))) ? ( + Math.min(Math.max(-0x080000000, (0.000000000000001 != Math.pow((Math.pow(( + x), (x >>> 0)) >>> 0), x))), ((( + Math.sign((Number.MIN_SAFE_INTEGER >>> 0))) , x) >>> 0))) : ( + (y , ( - (Math.fround((Math.fround(Math.pow(42, y)) , y)) * y)))))) << ( + Math.log(( + Math.min(Number.MAX_SAFE_INTEGER, -(2**53)))))); }); testMathyFunction(mathy0, [0x080000000, -0x0ffffffff, 1, 42, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -0x100000001, -0x100000000, 2**53-2, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 2**53, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), 0/0, Math.PI, -Number.MIN_VALUE, -0x080000000, 0x07fffffff, 0x100000000, 0x080000001, -(2**53-2), Number.MIN_VALUE, -0, 0]); ");
/*fuzzSeed-254361819*/count=256; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53+2, Number.MAX_VALUE, 0x100000000, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, -1/0, 0, 0/0, 1/0, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -0x100000001, -0, 0x07fffffff, -(2**53+2), -Number.MIN_VALUE, -0x080000000, 0x0ffffffff, -(2**53), -0x080000001, -0x0ffffffff, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, 1, 2**53-2]); ");
/*fuzzSeed-254361819*/count=257; tryItOut("return;");
/*fuzzSeed-254361819*/count=258; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[(void 0), new String(''), new String(''), ([] = x), (void 0), ([] = x), (void 0), ([] = x), new String(''), new String(''), new String(''), ([] = x), (void 0), new String(''), (void 0), new String(''), ([] = x), (void 0), ([] = x), new String(''), new String(''), new String(''), (void 0), (void 0), new String(''), ([] = x), ([] = x), (void 0), ([] = x), ([] = x), (void 0), new String(''), new String(''), ([] = x), (void 0), ([] = x), new String(''), ([] = x), new String(''), ([] = x), ([] = x), (void 0), new String(''), ([] = x), new String(''), (void 0), new String(''), ([] = x), new String(''), (void 0), (void 0), ([] = x), (void 0), new String(''), ([] = x), ([] = x), new String(''), ([] = x), (void 0), (void 0), new String(''), ([] = x), new String(''), (void 0), ([] = x), new String(''), new String(''), (void 0), (void 0), (void 0), (void 0), (void 0), ([] = x), new String(''), (void 0), ([] = x), ([] = x), ([] = x), ([] = x), new String(''), ([] = x), ([] = x), ([] = x), (void 0), new String(''), new String(''), (void 0), new String(''), (void 0), new String(''), new String(''), ([] = x), ([] = x), (void 0), new String(''), (void 0), (void 0), new String(''), (void 0), ([] = x), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (void 0), ([] = x), ([] = x), new String(''), ([] = x), (void 0), new String(''), new String(''), new String(''), ([] = x), ([] = x), ([] = x), new String(''), new String(''), new String(''), new String(''), new String(''), (void 0), ([] = x), new String(''), ([] = x), ([] = x), (void 0), ([] = x), new String(''), new String(''), (void 0), ([] = x), new String(''), (void 0), new String(''), (void 0), new String(''), ([] = x), new String(''), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0)]) { a2.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17) { a0 = a15 % a15; var r0 = a14 & z; var r1 = 0 | a3; var r2 = a13 + r1; var r3 = a13 % a15; var r4 = a16 - 2; var r5 = a2 % a11; var r6 = a3 % a7; var r7 = r3 - r3; var r8 = 2 | a16; var r9 = r5 / a4; r2 = 1 * a12; var r10 = a13 - 4; var r11 = 6 / a15; var r12 = a9 % 1; var r13 = 9 | a1; var r14 = 1 ^ a6; print(r1); var r15 = a5 | a16; var r16 = 4 % a6; var r17 = a13 - 1; a0 = r5 / r4; var r18 = 6 - 0; r16 = r6 & 4; a12 = r7 | 4; var r19 = r4 ^ a3; return a6; })); }");
/*fuzzSeed-254361819*/count=259; tryItOut("\"use asm\"; var r0 = x ^ 9; var r1 = 0 - x; var r2 = r1 % r1; var r3 = r1 / x; r3 = r1 - r3; var r4 = r2 ^ r1; var r5 = r4 % x; var r6 = r2 - r3; var r7 = r3 & r2; var r8 = 8 - r2; var r9 = r5 / r8; var r10 = r1 % r3; r5 = 1 + r0; var r11 = 4 % r2; r11 = 1 ^ r10; var r12 = 7 - r5; var r13 = r6 + 8; var r14 = 2 / 0; var r15 = 7 - r2; var r16 = r3 ^ r7; r3 = r4 / r9; var r17 = r3 / 7; var r18 = r15 | r15; var r19 = r9 % 8; var r20 = 3 & 8; var r21 = 3 & 2; var r22 = 6 & 0; var r23 = 7 % r17; var r24 = r15 % r15; var r25 = r21 - 7; var r26 = 6 | 8; var r27 = r0 & 5; var r28 = r17 + r0; var r29 = r13 - 5; var r30 = r20 - r0; var r31 = r12 / r0; var r32 = r8 + r24; r15 = 8 & r26; var r33 = 4 & r1; var r34 = r17 - r17; var r35 = r5 / r5; var r36 = 8 - r10; var r37 = r9 / r24; var r38 = 8 & r28; r24 = 9 | 9; var r39 = 7 * r22; print(r2); print(r20); var r40 = r14 + r31; var r41 = 0 - r21; var r42 = r34 + r4; var r43 = r36 + r37; var r44 = r15 - 2; r0 = r1 / r14; r19 = 8 & 8; var r45 = r2 + r9; var r46 = 9 * r26; r24 = 1 / r18; var r47 = 3 - 3; var r48 = 0 + r34; var r49 = 9 / r14; var r50 = x - r2; var r51 = r40 / 5; var r52 = r15 / r15; var r53 = r15 * r23; var r54 = r6 % 9; var r55 = r6 / 8; r44 = r15 + r23; var r56 = r21 % r12; var r57 = 3 - 0; r12 = 5 ^ 5; r0 = r6 * 0; var r58 = r21 ^ r18; var r59 = r51 & r47; r47 = 5 - r19; var r60 = r23 % 7; var r61 = r2 % 9; var r62 = 7 + r1; var r63 = r27 | 9; var r64 = r50 * r35; var r65 = 9 * r29; var r66 = r36 + r6; var r67 = 1 + 6; r38 = 3 | r15; r22 = r12 & 8; var r68 = 6 & 7; var r69 = r44 * 0; print(r52); r7 = r23 ^ r11; var r70 = r50 % 4; var r71 = r0 & r48; r20 = 3 + r37; var r72 = r3 / r66; var r73 = 7 + 1; var r74 = r33 / 3; var r75 = 0 + r47; var r76 = r63 + r27; var r77 = 0 & r64; var r78 = 6 % 8; var r79 = r46 / r31; r35 = 2 - r7; var r80 = r7 & r29; var r81 = 1 & r32; r66 = 8 * r37; var r82 = r53 * r41; var r83 = 3 / r77; r3 = r65 & 4; var r84 = 9 % 9; var r85 = r73 + r13; var r86 = r68 & 4; var r87 = 1 - 6; var r88 = r12 / r79; var r89 = r42 - r46; var r90 = r38 & r1; r29 = r76 + r30; var r91 = r39 | r45; r23 = r62 * r4; var r92 = 2 / 3; var r93 = r76 ^ 9; r59 = r79 + 2; r66 = r10 & r56; var r94 = r71 ^ r44; var r95 = r19 * r90; var r96 = 1 - r62; var r97 = r73 | 5; ");
/*fuzzSeed-254361819*/count=260; tryItOut("");
/*fuzzSeed-254361819*/count=261; tryItOut("\"use strict\"; /*RXUB*/var r = /\\B/gi; var s = \"  \"; print(s.replace(r, intern(9))); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=262; tryItOut("/*RXUB*/var r = /[^](\\B){2,2}?/ym; var s = \"\\n\\u1e55  \\u31d2\\u00b6 \\u4ff3\\u00dc\\u1467\\n\\u1e55  \\u31d2\\u00b6 \\u4ff3\\u00dc\\u1467\"; print(s.split(r)); ");
/*fuzzSeed-254361819*/count=263; tryItOut("Object.prototype.unwatch.call(m1, x.valueOf(\"number\"));");
/*fuzzSeed-254361819*/count=264; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -2305843009213694000.0;\n    var d3 = -8589934593.0;\n    var i4 = 0;\n    (Float64ArrayView[((+(1.0/0.0))) >> 3]) = (((-((Float64ArrayView[(({x: \"\\u8D16\"})) >> 3]))) + (NaN)));\n    return +((d3));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, 0x100000001, Number.MIN_VALUE, 1, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), -1/0, Math.PI, 0, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, -0, -0x080000000, 0x0ffffffff, 42, 0/0, -(2**53-2)]); ");
/*fuzzSeed-254361819*/count=265; tryItOut("h2.has = (function() { for (var j=0;j<0;++j) { f0(j%5==0); } });");
/*fuzzSeed-254361819*/count=266; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var floor = stdlib.Math.floor;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+((8388609.0))));\n    d1 = (d1);\n    d1 = (((+atan2(((4503599627370497.0)), ((((d1)) - ((d1)))))) + (-1025.0)) + (+((d1))));\n    d1 = (+floor(((Infinity))));\n    {\n      d1 = (((-1.0625)) / ((2097151.0)));\n    }\n    d1 = (-1.0078125);\n    i0 = (i0);\n    i0 = ((((i0))>>>((~~(281474976710657.0)))) < (0xcae0e80a));\n    return +((+/*FFI*/ff(((d1)))));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000000, 2**53+2, -0, Math.PI, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, 0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, Number.MIN_VALUE, 0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0, -(2**53), 1, 2**53-2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, -0x080000001, 2**53, 0.000000000000001, Number.MAX_VALUE, -0x080000000, 42, 1.7976931348623157e308, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=267; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! (((( + Math.hypot(( + Math.log10(( + Math.asinh(-0x0ffffffff)))), ( + x))) >>> 0) <= (Math.fround((Math.fround(Math.fround(Math.pow(( + Math.log10((((y >>> 0) <= (x >>> 0)) >>> 0))), Math.fround((Math.cbrt(Math.max(y, y)) * -(2**53-2)))))) == Math.fround(Math.min((( + ( - x)) >>> 0), (((y <= (y >>> 0)) | 0) ? -Number.MAX_VALUE : y))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [[], /0/, NaN, 1, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), -0, null, (new Number(0)), ({valueOf:function(){return 0;}}), '', '/0/', (new Boolean(true)), 0, (function(){return 0;}), objectEmulatingUndefined(), [0], true, (new String('')), false, (new Number(-0)), undefined, (new Boolean(false)), 0.1, '0', '\\0']); ");
/*fuzzSeed-254361819*/count=268; tryItOut("mathy2 = (function(x, y) { return (((((( - ( + y)) >>> 0) ? ( + mathy1(( + Math.acosh(Number.MIN_VALUE)), ( + Math.fround(Math.ceil(Math.fround(Math.exp(x))))))) : Math.min(y, y)) | 0) ? (( + Math.tan((Math.sinh((Math.atan2((x | 0), (-Number.MIN_VALUE | 0)) | 0)) | 0))) | 0) : (((Math.sign(( + (Math.fround(mathy1(y, (Math.tan(( + y)) | 0))) % (Math.atan2(((Math.acos((y >>> 0)) | 0) | 0), (( + Math.tan(( + -Number.MAX_SAFE_INTEGER))) | 0)) | 0)))) ? (((y > (Math.hypot((x >>> 0), (Math.fround(Math.imul(y, 0x100000001)) | 0)) | 0)) | 0) >>> 0) : (Math.fround((Math.fround(x) >> Math.fround(y))) > ( ~ x))) >>> 0) | 0)) | 0); }); ");
/*fuzzSeed-254361819*/count=269; tryItOut("{ void 0; minorgc(false); } print((/(?:[^P-\\\ue3c2y\\r-\\cZ\\S])(?![^])|(?!^|\\b*?{4,4})[^\\x5B-\u00a8p-\\udFE6~\\S]/i.eval(\" \\\"\\\" \")));");
/*fuzzSeed-254361819*/count=270; tryItOut("\"use strict\"; v1 = g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-254361819*/count=271; tryItOut("i2 + p2;var w = (\u3056 = z);/*infloop*/do Array.prototype.push.apply(a1, [s0, /*FARR*/[(arguments--), (allocationMarker()), ({/*TOODEEP*/}), , Math.log10(Math.fround((Math.fround(w) > Math.fround(w)))), w]]); while(/*UUV1*/(this.w.defineProperties = /*wrap3*/(function(){ var ynirjc = ({x: (4277)}); (/*wrap2*/(function(){ \"use asm\"; var kdhinw =  /x/ ; var favsly = (function shapeyConstructor(xnruuv){\"use strict\"; if (\"\\u58C4\") this[\"7\"] = function(){};for (var ytqhoqqox in this) { }if (c) { a2 = new Array; } Object.freeze(this);Object.preventExtensions(this);this[\"0\"] = [,,];return this; }).call; return favsly;})())(); })));");
/*fuzzSeed-254361819*/count=272; tryItOut("Object.prototype.unwatch.call(b2, \"link\");\nv1 = this.g2.runOffThreadScript();\n");
/*fuzzSeed-254361819*/count=273; tryItOut("\"use strict\"; new RegExp(\"\\\\W\", \"gyim\");print(x);");
/*fuzzSeed-254361819*/count=274; tryItOut("/*hhh*/function sihfus(x){;}/*iii*/f2(o0);(2);");
/*fuzzSeed-254361819*/count=275; tryItOut("\"use strict\"; a2.toString = (function() { try { for (var p in t0) { a0.sort((function() { try { Array.prototype.shift.apply(a1, [this.p1, b0]); } catch(e0) { } t1 = new Uint8Array(b0, 16, 13); return t2; }), v1); } } catch(e0) { } v0 = (s2 instanceof f0); throw v1; });e2.valueOf = (function() { a1 = arguments; return a0; });function c(x)window >>= (4277)/*infloop*/ for (var \u3056 of x) {/* no regression tests found *//*infloop*/do if((x % 3 != 0)) e2.delete(h2); else  if (delete x.x) (window); else /*RXUB*/var r = new RegExp(\"(?!(?=\\\\3(\\\\3){4,5})|\\\\n|[^]*?|\\\\1*?|.(?!$)|$\\\\\\u019e|[^]$+|\\\\B+?*{4,7})\", \"i\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n 1\\n1a\\n1a\\n\"; print(uneval(r.exec(s)));  while(eval = Proxy.createFunction(({/*TOODEEP*/})(20), new Function).__defineSetter__(\"eval\", /*wrap1*/(function(){ \"use strict\"; v2 = evalcx(\"\\u3056\", g2);return objectEmulatingUndefined})())); }");
/*fuzzSeed-254361819*/count=276; tryItOut("mathy2 = (function(x, y) { return ( + mathy1(( + (((Math.fround(Math.pow((((y | 0) !== Math.fround(Math.exp(Math.fround(x)))) + y), (-0x0ffffffff === 1/0))) >>> 0) < (( ! Math.log10(-0x080000001)) >>> 0)) >>> 0)), ( + (Math.min(Math.fround(( + ( ~ ( + (y , x))))), (Math.fround(( - ( + y))) / Math.tan((( + (( + ( ~ -0x100000001)) | 0)) | 0)))) | 0)))); }); testMathyFunction(mathy2, [-0x080000000, 1/0, 1, Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, 2**53+2, 0.000000000000001, 2**53-2, -Number.MAX_VALUE, -0, Number.MAX_VALUE, -0x07fffffff, -0x080000001, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, 0x07fffffff, 2**53, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, 0x100000001, -0x0ffffffff, 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, Math.PI]); ");
/*fuzzSeed-254361819*/count=277; tryItOut("{print(false);const x = x, x = ([window]);/*RXUB*/var r = new RegExp(\"(?=(?:\\\\b([^])*[^]^)+(?:\\\\u9eEa)*?)(?=\\\\2)+\", \"gyim\"); var s = \"\"; print(r.test(s)); print(r.lastIndex);  }");
/*fuzzSeed-254361819*/count=278; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 2**53+2, 1, 1/0, -0x100000000, 0x100000001, -0x100000001, 42, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 0x07fffffff, 0, -0, -1/0, -0x080000001, Math.PI, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53+2), -0x07fffffff, 2**53, -0x080000000, 0/0, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=279; tryItOut("/*bLoop*/for (var wvdghl = 0; wvdghl < 15 && (x); ++wvdghl) { if (wvdghl % 6 == 4) { /*RXUB*/var r = /(?!(?:(^)){15,}){1}(?![^]{2})(?:([])|\\2*{4}){0,}*/m; var s = \"\"; print(s.replace(r, ((--this.eval) % /*MARR*/[-0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  '\\0' , -0x0ffffffff, 1e-81,  '\\0' , -0x0ffffffff, [undefined],  '\\0' , 1e-81, 1e-81, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, 1e-81, 1e-81, [undefined],  '\\0' ,  '\\0' , -0x0ffffffff,  '\\0' , [undefined]].filter(arguments.callee.caller, 22))));  } else { /*RXUB*/var r = /\\1/y; var s = \"\"; print(s.replace(r, Array.prototype.splice, \"ym\"));  }  } ");
/*fuzzSeed-254361819*/count=280; tryItOut("\"use strict\"; v2 = g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-254361819*/count=281; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.imul(Math.fround(Math.cos(Math.imul(Math.fround(Math.sign(y)), ((x === Math.hypot(x, x)) - mathy0(( + ((x | 0) ? ( + y) : ( + x))), (Math.atan2((x >>> 0), ( + (Math.asinh((x | 0)) | 0))) >>> 0)))))), ( + mathy2(0x080000000, ((Math.atan2(-0x080000000, ( + Math.log10(x))) >>> 0) ? y : ((y >= x) | 0))))); }); testMathyFunction(mathy3, [2**53, -(2**53), 1/0, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, 1.7976931348623157e308, 0x080000000, 0x100000001, 2**53-2, -(2**53-2), 1, -0x07fffffff, -0x0ffffffff, -0x080000000, -0x100000000, Number.MIN_VALUE, -0, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 0/0, 0, 42, -0x100000001, 2**53+2, Math.PI, 0x080000001]); ");
/*fuzzSeed-254361819*/count=282; tryItOut("\"use strict\"; print(x);function d(x = yield d, NaN, ...x) { return ({prototype: \"\\u8901\" }) } print(\"\\u4ACF\");");
/*fuzzSeed-254361819*/count=283; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((((Uint16ArrayView[((0xf951a098)+(i0)+(!(i0))) >> 1]))>>>((i0)+((0x708f4eda) >= (((/*FFI*/ff(((-562949953421313.0)), ((-257.0)), ((1.0)), ((3.777893186295716e+22)), ((7.737125245533627e+25)))|0))>>>(-(0xfa64fa8a)))))) % (0xa96089d8)))|0;\n    i0 = (((+(0.0/0.0))));\n    {\n      i1 = (i1);\n    }\n    {\n      i1 = (i0);\n    }\n    return ((((+((((function(y) { \"use strict\"; h2.__proto__ = g0; })())))) <= (-9.0))-(/*FFI*/ff()|0)-(i1)))|0;\n  }\n  return f; })(this, {ff: (x).bind()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0.000000000000001, -1/0, -Number.MIN_VALUE, 0/0, 42, -0x100000001, 0, 2**53, 0x100000001, -0x0ffffffff, 0x080000000, Number.MIN_VALUE, -0x080000001, 0x07fffffff, -(2**53-2), 0x100000000, 0x0ffffffff, 1, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 1/0, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -0, -(2**53+2), Math.PI, 2**53+2]); ");
/*fuzzSeed-254361819*/count=284; tryItOut("o1.m0.has(b0);");
/*fuzzSeed-254361819*/count=285; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.pow(Math.imul(Math.sin(( - y)), ( - ((x | 0) && (y | 0)))), Math.fround((x & (( + Math.expm1(( + Math.pow(y, x)))) == ( + x))))) >>> 0) & Math.atanh((Math.atan2(( + ( + (( + y) ? ( + (y == -(2**53-2))) : Math.fround(( + (Math.asinh(y) || ( + y))))))), Math.acos(y)) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[x, (0/0), x, x, (({}) = (4277)), x, (0/0), x, (({}) = (4277)), (0/0), x, x, (0/0), x, x, x, (0/0), x, (0/0), x, (0/0), x, (({}) = (4277)), (0/0), (({}) = (4277)), (({}) = (4277)), (({}) = (4277)), (0/0), (0/0), x, x, x, x, x, x, x, x, x, (0/0), (({}) = (4277)), x, x, x, x, (({}) = (4277)), x, x, x, (({}) = (4277)), x, (({}) = (4277)), x, x, (({}) = (4277)), (({}) = (4277)), x, x, (0/0), (0/0), x]); ");
/*fuzzSeed-254361819*/count=286; tryItOut("/*vLoop*/for (rsxnak = 0, {x: [[{NaN: [[]], NaN: c, x: arguments.callee.arguments}, {e}], y, , , , ], x, w, x: [[, x, , ], {}, ], x: [[z = function ([y]) { }, NaN, ], ], eval: {d: [, , [], , x]}, e} = 26; rsxnak < 104; ++rsxnak) { var c = rsxnak; h2.set = f0; } ");
/*fuzzSeed-254361819*/count=287; tryItOut("var kuvllx = new ArrayBuffer(16); var kuvllx_0 = new Float64Array(kuvllx); kuvllx_0[0] = -0x100000000; var kuvllx_1 = new Float64Array(kuvllx); kuvllx_1[0] = -13; var kuvllx_2 = new Uint32Array(kuvllx); print(kuvllx_2[0]); kuvllx_2[0] = -10; var kuvllx_3 = new Float64Array(kuvllx); kuvllx_3[0] = -20; var kuvllx_4 = new Int8Array(kuvllx); print(kuvllx_4[0]); kuvllx_4[0] = -0; var kuvllx_5 = new Uint32Array(kuvllx); print(kuvllx_5[0]); kuvllx_5[0] = -3994776400; var kuvllx_6 = new Uint8ClampedArray(kuvllx); var kuvllx_7 = new Uint32Array(kuvllx); kuvllx_7[0] = 1; Array.prototype.forEach.apply(a2, [(function(stdlib, foreign, heap){ \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float64ArrayView[(((((0x60517e5a))>>>((!(-0x8000000)))) >= (((-0x8000000)-(0x99e2de3b))>>>(((0x41fc5394)))))+(0x59a8d4a1)) >> 3]) = ((+((d0))));\n    return ((((0xffffffff) ? (0xffffffff) : (0xffffffff))))|0;\n    d0 = ((0xfc9cb1b5) ? (d0) : (d1));\n    return (((0x4d05fc1b)+(0xff5f40b6)))|0;\n  }\n  return f; })]);Array.prototype.unshift.call(a2, p0, this.a1, t2, g1, g0);Array.prototype.push.apply(a2, [this.v2]);h1.iterate = f0;");
/*fuzzSeed-254361819*/count=288; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy0(( - (( + Math.atan2(Math.fround(Math.atan2(Math.fround((-(2**53-2) ? 1 : Number.MAX_SAFE_INTEGER)), Math.fround(0x080000000))), ( + Math.acos((((x != -Number.MIN_SAFE_INTEGER) ** ( + y)) | 0))))) >>> 0)), Math.fround(( - ( + (Math.sin((x >>> 0)) ** ( + 1.7976931348623157e308)))))); }); ");
/*fuzzSeed-254361819*/count=289; tryItOut("/*bLoop*/for (var nrxqis = 0; nrxqis < 11; ++nrxqis) { if (nrxqis % 30 == 2) { /*RXUB*/var r = r0; var s = \"\\u4377\\u4377\\u4377\"; print(s.match(r));  } else { a0.forEach((function(j) { f1(j); })); }  } ");
/*fuzzSeed-254361819*/count=290; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((((0 - ( - ((y , ( + x)) >>> 0))) * Math.hypot((( + y) || ( + y)), (((y | 0) / Math.fround(Math.pow(Math.fround((y == -Number.MAX_SAFE_INTEGER)), Math.fround(Math.round(y))))) , x))) >>> 0), (Math.min((Math.fround(( - Math.fround(y))) | 0), (Math.atan2((Math.max(Math.fround(( + ( + x))), Math.fround(x)) & (( + y) | 0)), (( + (Math.imul((y >>> 0), -0x080000000) >>> 0)) | 0)) | 0)) | 0)); }); ");
/*fuzzSeed-254361819*/count=291; tryItOut("g1.v2 = g1.g1.eval(\"function f1(m1) x\");");
/*fuzzSeed-254361819*/count=292; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new String('')), (new Boolean(false)), ({toString:function(){return '0';}}), '0', -0, undefined, (function(){return 0;}), NaN, '/0/', objectEmulatingUndefined(), (new Boolean(true)), ({valueOf:function(){return 0;}}), [0], '\\0', false, 0, ({valueOf:function(){return '0';}}), /0/, (new Number(0)), [], 0.1, null, true, (new Number(-0)), '', 1]); ");
/*fuzzSeed-254361819*/count=293; tryItOut("\"use strict\"; Array.prototype.shift.apply(a1, []);");
/*fuzzSeed-254361819*/count=294; tryItOut("\"use strict\"; var b = (new Map());v1 = Object.prototype.isPrototypeOf.call(i2, o1);");
/*fuzzSeed-254361819*/count=295; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -140737488355329.0;\n    ( \"\" ) = ((+(-1.0/0.0)));\n    d1 = (d2);\n    i0 = ((eval(\"a1.unshift();\")));\n    i0 = ((((0x87413b10)-(0xff45c6d7))|0) != ((((((0xfa691e66)+(0xfa1fe984))>>>((0x14db3979) % (0x0))) != (0xdc22eb6))-((-0x2a017a2) == (abs((((0xda76866)) << ((0x9c0af877))))|0))) & (0xd0484*(i0))));\n    d2 = (d2);\n    return (((!(/*FFI*/ff(((d1)), ((+abs((((Object.prototype.toLocaleString)())(w = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(){}, defineProperty: /*wrap2*/(function(){ \"use strict\"; var lhmomc =  /x/ ; var czppsf = ({/*TOODEEP*/}); return czppsf;})(), getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return []; }, }; })( \"\" ), (/*UUV2*/(x.clz32 = x.delete)))))))), ((d2)), ((~((!(0xffffffff))-((((0xa0afbf09)) | ((0x38d4ee7d))))))))|0))+(((((0x75c21fd) ? (0xd5fdab05) : (i0)))>>>((!(new RegExp(\"(.)\", \"yim\"))))) >= (((-0x8000000)-(0xfc54b0ba))>>>((i0)+(/*FFI*/ff(((-((-1.9342813113834067e+25)))))|0))))))|0;\n    d2 = (536870911.0);\n    return (((/*FFI*/ff((((d1) + (-18446744073709552000.0))))|0)-(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: /*UUV1*/(z.getInt32 =  /x/ ).all}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-254361819*/count=296; tryItOut("/*RXUB*/var r = new RegExp(\"[\\\\cZ-\\\\\\uac43\\\\d\\\\d]\", \"im\"); var s = \"_\"; print(s.replace(r, 'x')); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=297; tryItOut("\"use strict\"; v2 = g1.eval(\"function f2(p1) \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d1 = (((d1)) / ((+(0x0))));\\n    (Float64ArrayView[0]) = ((+((d0))));\\n    d1 = (d0);\\n    d0 = (d0);\\n    switch ((((Uint8ArrayView[(-(0xffde556e)) >> 0]))|0)) {\\n      case 1:\\n        {\\n          d0 = (d1);\\n        }\\n        break;\\n      case 0:\\n        d1 = (d1);\\n        break;\\n      case -1:\\n        (Int32ArrayView[((0xb76f89b0)) >> 2]) = ((0x7908f7c5)-(0x5230b930)-((0xffffffff) ? (((eval(\\\"\\\\\\\"use strict\\\\\\\"; m0.has(h1);\\\", Math.max(-22, ({a2:z2}))))>>>((0x35f298b0))) == (0x66e65c1f)) : ((+(0xc6a27213)) < (d0))));\\n        break;\\n      case 1:\\n        d0 = (d1);\\n        break;\\n      default:\\n        d0 = (d1);\\n    }\\n    {\\n      d1 = (d1);\\n    }\\n    d0 = (d0);\\n    {\\n      {\\n        d0 = (+(1.0/0.0));\\n      }\\n    }\\n    d0 = (Infinity);\\n    {\\n      (Uint8ArrayView[((0x3fea64f1)) >> 0]) = ((Uint32ArrayView[4096]));\\n    }\\n    (Float64ArrayView[0]) = ((Float32ArrayView[((-0x8000000)) >> 2]));\\n    (Int16ArrayView[((0x59a59637)-((0xff740ee5) ? (0xffffffff) : ((-0x8000000) >= (-0x8000000)))) >> 1]) = ((new (-1808850899.5)()));\\n    return +((d1));\\n  }\\n  return f;\");");
/*fuzzSeed-254361819*/count=298; tryItOut("\"use strict\"; selectforgc(g1.o0.o2);");
/*fuzzSeed-254361819*/count=299; tryItOut("print( /* Comment */Math.pow(Math.fround(0/0), ( + x)));");
/*fuzzSeed-254361819*/count=300; tryItOut("testMathyFunction(mathy2, [0x100000000, -(2**53+2), -0x080000000, -0x0ffffffff, -Number.MAX_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, 0, 1, 2**53-2, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), Number.MIN_VALUE, -0x100000000, -Number.MIN_VALUE, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, -0, 0.000000000000001, -(2**53-2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, -1/0, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0x080000000, 42, -0x080000001, 0/0]); ");
/*fuzzSeed-254361819*/count=301; tryItOut("\"use asm\"; v0 = Array.prototype.every.apply(o0.a0, [(function() { try { ; } catch(e0) { } v2 = a0.reduce, reduceRight((function(stdlib, foreign, heap){ \"use asm\";   var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      return ((d = e|=/(?:\\b+)\\1{0}|(?!\\2)*?|(?:^)(\\B\\B{0,3}\\S|.|\\w+*+?)/im))|0;\n    }\n    i0 = (0xffd59aed);\n    return (((i0)+(i0)-(((Int32ArrayView[((0xf97606a7)-(i0)-(0x695bb009)) >> 2])) == (0x6d567ff8))))|0;\n  }\n  return f; }), v0); return v1; }), s2]);");
/*fuzzSeed-254361819*/count=302; tryItOut("mathy2 = (function(x, y) { return ( + ( + (mathy0((Math.trunc(( + Math.sign(Math.fround((x || Math.fround(Math.fround(Math.abs((y >>> 0))))))))) | 0), ((( + (mathy1(mathy1(mathy1(x, x), x), Math.fround(( ! Math.fround((-(2**53+2) === x))))) | 0)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy2, /*MARR*/[new Boolean(true)]); ");
/*fuzzSeed-254361819*/count=303; tryItOut("o1.a0.unshift(/*FARR*/[null, , /\\3|\\d|\\u00B7|[]+?+?|\uf100+((?=(?:$){1,}))/m, ].sort(Math.ceil, undefined), t0, i2, p2, h1);");
/*fuzzSeed-254361819*/count=304; tryItOut("o1.a1[14] = (arguments.callee.caller.caller.caller(timeout(1800), String.prototype.trimLeft()));");
/*fuzzSeed-254361819*/count=305; tryItOut("\"use strict\"; x = e1;");
/*fuzzSeed-254361819*/count=306; tryItOut("t2[()] = v1;");
/*fuzzSeed-254361819*/count=307; tryItOut("if((x % 4 == 1)) {Array.prototype.shift.call(a0); } else  if (new function shapeyConstructor(wbtlhr){\"use strict\"; this[new String(\"7\")] = 0.000000000000001;this[new String(\"7\")] = new Boolean(false);return this; }(x, false)) for (var p in h0) { try { for (var v of i0) { a0[this.v1] = undefined; } } catch(e0) { } try { a0.shift(h2); } catch(e1) { } try { i2.next(); } catch(e2) { } o0.a1.push(this.a2, g0); } else L: { }");
/*fuzzSeed-254361819*/count=308; tryItOut("\"use strict\"; /*MXX2*/g2.Math.atan = b0;\n/*hhh*/function fqtixj(w){((4277));}/*iii*/var iljwht = new ArrayBuffer(1); var iljwht_0 = new Uint16Array(iljwht); iljwht_0[0] = 9; s1 = new String(t0);\n");
/*fuzzSeed-254361819*/count=309; tryItOut("\"use strict\"; /*bLoop*/for (let odubcu = 0, Math.log1p([2]),  /x/g .valueOf(\"number\"); odubcu < 56; ++odubcu) { if (odubcu % 49 == 0) { with(x)print(new RegExp(\"\\\\B\\\\1\", \"gm\")); } else { v0 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 != 5), sourceIsLazy: this, catchTermination: (x % 6 != 1) })); }  } ");
/*fuzzSeed-254361819*/count=310; tryItOut("\"use strict\"; throw c;return (x) = ++x;");
/*fuzzSeed-254361819*/count=311; tryItOut("");
/*fuzzSeed-254361819*/count=312; tryItOut("h0.enumerate = x << -20;");
/*fuzzSeed-254361819*/count=313; tryItOut("\"use strict\"; for (var p in b1) { for (var p in h2) { try { s0 += s2; } catch(e0) { } try { Array.prototype.unshift.apply(a0, [v0]); } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(s0, b2); } catch(e2) { } e2.add(i1); } }");
/*fuzzSeed-254361819*/count=314; tryItOut("/*bLoop*/for (var zkrypd = 0, ztkjiz; zkrypd < 125; ++zkrypd) { if (zkrypd % 3 == 0) { e0.delete(e1); } else { continue M; }  } ");
/*fuzzSeed-254361819*/count=315; tryItOut("\"use strict\"; switch(this) { case 3: break;  }");
/*fuzzSeed-254361819*/count=316; tryItOut("testMathyFunction(mathy2, [2**53-2, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, -0x100000000, 42, -0x0ffffffff, -Number.MAX_VALUE, -1/0, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 1, Math.PI, -0x100000001, 0x07fffffff, 0.000000000000001, 2**53+2, Number.MIN_VALUE, -(2**53-2), 0x080000000, -(2**53), 0x100000001, 0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-254361819*/count=317; tryItOut("Object.defineProperty(this, \"s0\", { configurable: true, enumerable: (/*UUV1*/(w.revocable = (decodeURI).call)),  get: function() {  return ''; } });");
/*fuzzSeed-254361819*/count=318; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( ! (( + mathy0(( + ( + Math.pow(Math.fround(-1/0), Math.fround(Math.pow(( + ( ~ ( + ( + (y != ( + x)))))), x))))), ( + ( ~ (Math.acosh(-0x0ffffffff) | 0))))) >>> 0)) ^ (Math.tanh((( + (Math.hypot((y >>> 0), Math.log2(((2**53 ? 2**53+2 : -Number.MIN_VALUE) | 0))) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [42, 0x080000001, -0x100000001, 0x080000000, 0.000000000000001, 0, -0x07fffffff, Number.MIN_VALUE, 2**53+2, 2**53-2, -(2**53), 0x0ffffffff, 0/0, -(2**53+2), Number.MAX_VALUE, -0, 1, 0x100000000, -0x100000000, Math.PI, -Number.MAX_VALUE, 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=319; tryItOut("let(a) { -11;}throw false;");
/*fuzzSeed-254361819*/count=320; tryItOut("v1 = this.g2.runOffThreadScript();");
/*fuzzSeed-254361819*/count=321; tryItOut("print(let (tmdsbj)  /x/g );");
/*fuzzSeed-254361819*/count=322; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\B\", \"gi\"); var s = \"1aa\\n11\"; print(s.match(r)); ");
/*fuzzSeed-254361819*/count=323; tryItOut("t1.set(a0, 17);");
/*fuzzSeed-254361819*/count=324; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.fround(( ! Math.pow(-1/0, (Math.pow((( + (( + x) <= ( + -0x080000001))) >>> 0), (Math.log2(Math.fround((0 * Math.fround(y)))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [-(2**53), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -0, 2**53, -0x100000000, -1/0, 0x100000000, 1.7976931348623157e308, 0.000000000000001, 1, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, 42, -0x080000000, 0x080000001, -0x080000001, -0x07fffffff, 0x07fffffff, -Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, Math.PI, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-254361819*/count=325; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=326; tryItOut("g2.v0 = (p2 instanceof b0);");
/*fuzzSeed-254361819*/count=327; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=328; tryItOut("\"use strict\"; b = x;o0 = Object.create(a2);");
/*fuzzSeed-254361819*/count=329; tryItOut("\"use strict\"; v2 = evaluate(\"function f1(g1.i2)  { h1.defineProperty = (function() { try { a2 = o2.a0.concat(a0, a2, t2, a0, t1, a0, this.f0); } catch(e0) { } try { g2 + o2.a0; } catch(e1) { } try { v1 = (v2 instanceof a2); } catch(e2) { } Array.prototype.sort.apply(a0, [g1.f0, h1, o0]); return a0; }); } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-254361819*/count=330; tryItOut("mathy3 = (function(x, y) { return Math.tanh(( + ((( ! Number.MAX_SAFE_INTEGER) === x) << ( + ((Math.max(((Math.hypot(((Math.max(0.000000000000001, Math.fround(Math.fround(Math.expm1(Math.fround(y))))) >>> 0) >>> 0), (-Number.MAX_SAFE_INTEGER | 0)) >>> 0) >>> 0), (x >>> 0)) >>> 0) ? Math.max(((-0x0ffffffff || (Math.imul((x * y), y) >>> 0)) >>> 0), x) : Math.log10(Math.fround(mathy2(0x100000000, (mathy1((((y >>> 0) / (y >>> 0)) >>> 0), -1/0) | 0))))))))); }); testMathyFunction(mathy3, [Math.PI, -0x07fffffff, -0x080000000, 0x100000000, 2**53, Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, 42, 2**53-2, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 0x07fffffff, 1, -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, 0, -0, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -1/0, 2**53+2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=331; tryItOut("Array.prototype.shift.call(a0, t2);");
/*fuzzSeed-254361819*/count=332; tryItOut("v0 = g2.eval(\"g0.toString = (function mcc_() { var vxtokq = 0; return function() { ++vxtokq; if (/*ICCD*/vxtokq % 11 == 1) { dumpln('hit!'); v2 = false; } else { dumpln('miss!'); try { new Function = t0[1]; } catch(e0) { } try { v1 = 0; } catch(e1) { } try { this.v0 = o1.t0.length; } catch(e2) { } function f1(p0) (({x: this})) } };})();\");");
/*fuzzSeed-254361819*/count=333; tryItOut("mathy3 = (function(x, y) { return Math.log(Math.min((Math.atan2(((( + (Math.fround(( ~ (-Number.MAX_SAFE_INTEGER >>> 0))) | 0)) % (Math.imul(y, y) | 0)) | 0), ((y <= ( + (mathy1((x | 0), ((x ^ (Math.sinh((y >>> 0)) | 0)) | 0)) | 0))) | 0)) | 0), ( + mathy2(Math.min(( + ( + x)), ( + ( + Math.exp(( + (mathy0((Math.fround(Math.max(Math.fround(y), Math.fround(x))) | 0), (y | 0)) | 0)))))), Math.hypot(Math.fround(Math.ceil((Math.abs(-Number.MAX_SAFE_INTEGER) >>> 0))), (((y >>> 0) | (mathy2(x, -0x080000001) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [-1/0, -(2**53+2), 2**53+2, 1/0, -(2**53-2), 42, 0x100000000, Math.PI, 0x080000001, 0x100000001, 0/0, -0, -(2**53), -0x100000000, Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, 2**53, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 2**53-2, 1.7976931348623157e308, -0x100000001, 1, 0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=334; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.max(( + ( ! ( ~ (Math.fround(Math.min((( + (y | 0)) | 0), ( + (((-(2**53+2) | 0) !== ( + ((y && (-0x080000000 >>> 0)) >>> 0))) | 0)))) - x)))), (( - (mathy2((x >>> 0), Math.fround((( - Math.pow(-0x0ffffffff, y)) >= Math.fround(y)))) | 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-254361819*/count=335; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-254361819*/count=336; tryItOut("testMathyFunction(mathy2, [0x0ffffffff, Math.PI, 0x07fffffff, -(2**53-2), 0x100000001, -0, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, -0x080000001, -1/0, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, 42, 0x080000000, 0x080000001, 0.000000000000001, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 1/0, -(2**53), -0x100000000, 0x100000000, Number.MIN_VALUE, 0, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-254361819*/count=337; tryItOut("mathy4 = (function(x, y) { return ( - ( ! Math.cosh(Math.fround((( + (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy4, /*MARR*/[(0/0), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), Infinity, true, objectEmulatingUndefined(), (0/0),  /x/ ,  /x/ , true, true, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), true, (0/0), (0/0), (0/0), true, objectEmulatingUndefined(), (0/0), Infinity, true, (0/0), true, Infinity,  /x/ , true, true, objectEmulatingUndefined(), (0/0), Infinity, (0/0),  /x/ , (0/0), (0/0), true, objectEmulatingUndefined(), (0/0),  /x/ ,  /x/ , (0/0), true, objectEmulatingUndefined(),  /x/ , true, objectEmulatingUndefined(), (0/0),  /x/ , objectEmulatingUndefined(), (0/0), (0/0),  /x/ , (0/0),  /x/ ]); ");
/*fuzzSeed-254361819*/count=338; tryItOut("f1.valueOf = (function() { v2 = evalcx(\"((void options('strict_mode')))\", g0); return t1; });");
/*fuzzSeed-254361819*/count=339; tryItOut("mathy3 = (function(x, y) { return ((mathy0((Math.atan2((( ~ (mathy0(x, x) >>> 0)) >>> 0), (Math.asin(y) | 0)) >>> 0), (( + Math.min(y, ((x | 0) ? 1 : ( + (y ^ ( + -0)))))) >>> 0)) >>> 0) ? ( + ((y >= (( ! (y >>> 0)) >>> 0)) !== ((mathy2((x >>> 0), ( ~ x)) >>> 0) ? undefined : (Math.pow(Math.fround(y), Math.fround((Math.pow(((Math.cbrt(x) >>> 0) >>> 0), (y | 0)) >>> 0))) >>> 0)))) : ((Math.fround(Math.sinh(Math.imul((x >>> 0), ( + Math.clz32(y))))) | (( + Math.sin(Math.max(y, (( + y) >>> 0)))) | 0)) | 0)); }); testMathyFunction(mathy3, [1, 0x080000001, -(2**53-2), 0x100000001, Number.MAX_VALUE, -0x100000001, 0x080000000, -0x07fffffff, -1/0, 42, -Number.MAX_SAFE_INTEGER, Math.PI, 1/0, 2**53-2, 0, -0, Number.MIN_VALUE, -0x080000001, 0x07fffffff, 0.000000000000001, -0x100000000, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, 0x0ffffffff, -(2**53), 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=340; tryItOut("\"use strict\"; e1.add(e2);");
/*fuzzSeed-254361819*/count=341; tryItOut("Array.prototype.forEach.apply(a0, []);o1.e2.toString = (function mcc_() { var buqokz = 0; return function() { ++buqokz; if (/*ICCD*/buqokz % 10 == 8) { dumpln('hit!'); try { t1[5] = this.h0; } catch(e0) { } try { ; } catch(e1) { } try { print(x);function x(this.x) { return x } this.o0.g0.t1.toSource = null; } catch(e2) { } Object.seal(b1); } else { dumpln('miss!'); m2.set([] = -22[\"toJSON\"] = \"\\u7B10\" <  \"\" , s1); } };})();");
/*fuzzSeed-254361819*/count=342; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround((((( + Math.max(Math.hypot(Math.fround(x), Math.min(-0, (mathy0((x | 0), x) | 0))), x)) > (((( ! (( ! y) >>> 0)) >>> 0) > Math.fround(( + Math.sqrt((-(2**53-2) | 0))))) >>> 0)) << ( ~ (( - (y | 0)) | 0))) ? Math.fround(( + Math.fround(( + ( ! (( ~ (Math.fround(( + Math.fround(x))) | 0)) | 0)))))) : Math.fround((Math.cos((Math.fround(((((((( + Math.fround(x)) | 0) | 0) | x) | 0) >>> 0) + Math.fround(Math.fround((Math.fround((( ! ( + -Number.MIN_VALUE)) >>> 0)) <= x))))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-254361819*/count=343; tryItOut("\"use strict\"; (void schedulegc(o2.o0.g2));");
/*fuzzSeed-254361819*/count=344; tryItOut("\"use strict\"; t0[v1] = Math.sin(-15);");
/*fuzzSeed-254361819*/count=345; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return ( + Math.fround(( + ( + ((((( + (Math.imul(( + (((Math.acos(x) >>> 0) > (y >>> 0)) >>> 0)), ((x + Math.fround(Math.imul(Math.fround(-0x080000001), y))) >>> 0)) >>> 0)) >= ( + y)) | 0) ** (Math.asin((Math.fround(y) | x)) | 0)) | 0))))); }); testMathyFunction(mathy0, [1.7976931348623157e308, 0x080000000, 0x100000001, -(2**53-2), -1/0, 0.000000000000001, 0, Number.MAX_VALUE, 2**53, -0, Math.PI, Number.MIN_VALUE, 2**53-2, 0x100000000, 0x07fffffff, -(2**53+2), 42, 1, 0/0, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 1/0, 0x080000001, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-254361819*/count=346; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x07fffffff, Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -0x080000001, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, 42, -0x100000000, 2**53-2, -(2**53), -0x0ffffffff, -0x100000001, 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -(2**53-2), 0, -Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, 1/0, 1, 0x100000001, 2**53+2, -Number.MAX_VALUE, 0/0, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-254361819*/count=347; tryItOut("\"use strict\"; s0.__proto__ = p0;");
/*fuzzSeed-254361819*/count=348; tryItOut("\"use strict\"; v2 = g1.eval(\"\\\"use strict\\\"; this.v1 = r1.multiline;\");");
/*fuzzSeed-254361819*/count=349; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((( + ( ! Math.fround(((((( ~ ((Math.min(x, ((Math.pow(y, x) >>> 0) && x)) >>> 0) >>> 0)) >>> 0) >>> 0) | ((Math.log2((Math.sin(2**53-2) | 0)) | 0) | 0)) >>> 0)))) | 0) ** ( + ((((0x100000001 >>> 0) || (mathy1(( + (( + y) != ( + (Math.max((-1/0 >>> 0), (((x !== x) | 0) >>> 0)) >>> 0)))), mathy0(Math.fround(Math.cbrt(Math.fround(x))), Math.abs(x))) >>> 0)) >>> 0) && ( + Math.tan(( + ( + mathy0((( ~ (2**53+2 | 0)) >>> 0), 0/0)))))))); }); testMathyFunction(mathy3, [-1/0, 0x0ffffffff, -(2**53), 0x07fffffff, 1.7976931348623157e308, 0x080000001, 0, Number.MIN_VALUE, 42, -(2**53+2), 0x080000000, 0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, -(2**53-2), -0, 1, Math.PI, -0x100000000, 0x100000000, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, 1/0]); ");
/*fuzzSeed-254361819*/count=350; tryItOut("/*RXUB*/var r = /(?=[^])/gym; var s = \"\\u89b9\"; print(uneval(s.match(r))); ");
/*fuzzSeed-254361819*/count=351; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy0(Math.hypot((timeout(1800) | 0), ((( + Math.acos(( + mathy1(Math.max(Math.fround(mathy2((0x100000000 >>> 0), (y >>> 0))), x), y)))) ? ((Math.log2((x >>> 0)) >>> 0) >> mathy3((y && ( - x)), Math.atan2(Math.PI, (y | 0)))) : 2**53+2) | 0)), Math.fround(Math.asinh(Math.fround(Math.ceil(Math.atan2(mathy1(0, y), (0x100000001 * Number.MAX_VALUE))))))); }); testMathyFunction(mathy4, [0, 1/0, -Number.MAX_VALUE, -0, 42, 0x100000000, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), 1, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x080000000, -0x100000000, 0.000000000000001, 2**53, -0x07fffffff, 1.7976931348623157e308, -(2**53), -0x100000001, Number.MIN_VALUE, 2**53+2, -0x080000000, 2**53-2, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=352; tryItOut("/*vLoop*/for (var mqeqln = 0; (false) && mqeqln < 15; ++mqeqln) { var y = mqeqln;  } ");
/*fuzzSeed-254361819*/count=353; tryItOut("/*oLoop*/for (var ozotuj = 0; ozotuj < 126; ++ozotuj) { print(\"\\u5097\"); } ");
/*fuzzSeed-254361819*/count=354; tryItOut("var b = (4277);(\"\\uAAB0\");");
/*fuzzSeed-254361819*/count=355; tryItOut("\"use strict\"; f0(o2.g1);");
/*fuzzSeed-254361819*/count=356; tryItOut("\"use strict\"; v1 = evaluate(\"function f0(b1)  { \\\"use strict\\\"; yield (/*MARR*/[].map) } \", ({ global: g0.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*wrap2*/(function(){ var dvmawt = (--a); var fuefta = (let (c) (4277)).apply; return fuefta;})()(), noScriptRval:  \"\" , sourceIsLazy: Object.defineProperty(this.eval, \"setFullYear\", ({value: (Math.round(NaN))})), catchTermination: true }));");
/*fuzzSeed-254361819*/count=357; tryItOut("e2.has(o2);");
/*fuzzSeed-254361819*/count=358; tryItOut("testMathyFunction(mathy5, [-1/0, -0x100000001, Number.MIN_VALUE, 0x0ffffffff, 0x100000000, -0x100000000, 2**53-2, -0, 0x080000000, -0x0ffffffff, 0x080000001, 2**53, 0, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), 0x07fffffff, 42, Math.PI, Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -0x07fffffff, 1/0, 0/0, -(2**53+2)]); ");
/*fuzzSeed-254361819*/count=359; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( - (Math.fround((Math.fround((Math.imul((Math.fround(x) >>> 0), -Number.MAX_SAFE_INTEGER) & (x > x))) === Math.fround(x))) == (((( + Math.fround(Math.imul(Math.fround(x), (x | 0)))) << ( + x)) === ( + Math.imul(( + (Math.ceil(Number.MIN_VALUE) | 0)), (x >> Math.fround(mathy0((x | 0), 1/0)))))) >>> 0))) << ( + ((( ~ ((( + ( - ( + Math.fround(Math.pow((( + Math.fround(-0x0ffffffff)) >>> 0), x))))) ** (Math.tanh((x >>> 0)) >>> 0)) >>> 0)) >>> 0) ^ Math.fround(Math.pow(Math.log1p(Math.tan(( + x))), Math.fround(( + (( + (y === (x >>> 0))) ? ( + 0x100000000) : ( + 0x0ffffffff))))))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 2**53+2, 1, -0x100000001, -Number.MAX_VALUE, -0x100000000, -0x080000000, -(2**53-2), 0x100000001, -(2**53), 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -0x080000001, 1/0, 2**53-2, 0x080000001, Math.PI, 1.7976931348623157e308, -0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, Number.MAX_VALUE, 0x080000000, -1/0, Number.MIN_VALUE, 0x100000000, 0.000000000000001, 2**53, -0x0ffffffff, 0x07fffffff, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-254361819*/count=360; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + (Math.sinh(( + ((((( + -0x07fffffff) && x) <= y) < x) % x))) == (Math.hypot(( ~ ( + Math.clz32(Math.tan(y)))), (( ! ( + ( - ( + y)))) >>> 0)) | (((0.000000000000001 | 0) / (Math.cosh(Math.clz32(Math.trunc(x))) | 0)) | 0)))) / Math.pow((( - (2**53-2 >>> 0)) >>> 0), Math.exp(((((mathy3(( + x), (x >>> 0)) >>> 0) | 0) ? x : x) | 0)))); }); testMathyFunction(mathy5, [1/0, -0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, -0x07fffffff, 0x07fffffff, -0, 0x080000001, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 1, -Number.MIN_VALUE, 0x080000000, 42, -0x0ffffffff, 0x100000000, -(2**53+2), -(2**53), 2**53+2, 0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, 0/0, -0x080000001, -(2**53-2), -0x080000000, 0x100000001]); ");
/*fuzzSeed-254361819*/count=361; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -0.5;\n    return +((+abs((((+atan2(((+(-1.0/0.0))), ((d1)))) + (-1.00390625))))));\n  }\n  return f; })(this, {ff: Array.prototype.slice}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Math.PI, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53), -0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 2**53, 0/0, 1.7976931348623157e308, -(2**53+2), -0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 2**53+2, -1/0, 0x07fffffff, 1, -0, 0x0ffffffff, -0x100000001, 42, 0x100000000, 2**53-2, -0x080000000, 0x080000001, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=362; tryItOut("mathy1 = (function(x, y) { return (( ! ( ! ( ! (Math.pow(((( ~ (x >>> 0)) >>> 0) >>> 0), Math.fround(Math.atan2(Math.fround(y), Math.fround(x)))) >>> 0)))) | 0); }); ");
/*fuzzSeed-254361819*/count=363; tryItOut("a1.pop();");
/*fuzzSeed-254361819*/count=364; tryItOut("v2 = evalcx(\"Object.seal(this.t1);\", g0);");
/*fuzzSeed-254361819*/count=365; tryItOut(" for  each(d in new RegExp(\"(\\\\D{4,}|\\\\b+[^]|\\\\d{1}*?)\", \"y\")) print(d);");
/*fuzzSeed-254361819*/count=366; tryItOut("v0 = g0.o1.o1.r2.global;");
/*fuzzSeed-254361819*/count=367; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul(( + ((Math.atan2((x | 0), (Math.sign(Math.fround(Math.asinh(Math.atan(x)))) | 0)) | 0) >>> ((x || Math.fround(( + ( + (( + (x >> y)) >> Math.fround((x != Math.fround(Math.fround(Math.max(Math.fround(0x100000001), Math.fround(y))))))))))) >>> 0))), (( - ((( + (( + y) === ( + ( + Math.max(( + x), ( + x)))))) !== x) >>> 0)) !== ((( + Math.fround(( - 2**53-2))) ? Math.min(Math.min(y, 1), y) : (y | 0)) | 0))); }); testMathyFunction(mathy0, /*MARR*/[new String(''), -0x080000000, true, .2, {}, .2, {}, {}, .2, new String(''), true, true, .2, .2, -0x080000000, new String(''), -0x080000000, -0x080000000, true, new String(''), .2, new String(''), {}, new String(''), {}, -0x080000000, new String(''), -0x080000000, -0x080000000, true, true, true, {}, new String(''), true]); ");
/*fuzzSeed-254361819*/count=368; tryItOut("\"use strict\"; with({}) { let(c) ((function(){throw StopIteration;})()); } ");
/*fuzzSeed-254361819*/count=369; tryItOut("\"use strict\"; /*oLoop*/for (var tsykfa = 0; tsykfa < 108; ++tsykfa) { selectforgc(o2); } ");
/*fuzzSeed-254361819*/count=370; tryItOut("(window) = ((eval) = delete d.x) = a1[2];");
/*fuzzSeed-254361819*/count=371; tryItOut("\"use strict\"; for (var p in t1) { try { t0[({valueOf: function() { i1.next();return 18; }})] = (4277); } catch(e0) { } try { m0.has(h1); } catch(e1) { } try { /*MXX1*/o2 = g0.Date.parse; } catch(e2) { } g0.o2.o1.g0 = a1[16]; }");
/*fuzzSeed-254361819*/count=372; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1.125;\n    d2 = (+(0.0/0.0));\n    {\n      /*FFI*/ff(((((-8796093022207.0)) - ((d2)))), ((+pow(((+(1.0/0.0))), ((d2))))));\n    }\n    i1 = (i0);\n    i1 = (i1);\n    i1 = (0x2864cd97);\n    (Float64ArrayView[(timeout(1800)) >> 3]) = ((d2));\n    return +((((1025.0)) / ((+abs(((7.555786372591432e+22)))))));\n  }\n  return f; })(this, {ff: function(y) { return (({/*toXFun*/valueOf: function() { return this; } })) }}, new ArrayBuffer(4096)); ");
/*fuzzSeed-254361819*/count=373; tryItOut("\"use strict\"; e0.delete(this.p1);");
/*fuzzSeed-254361819*/count=374; tryItOut("for (var v of e2) { try { f1 = h1; } catch(e0) { } this.i2.next(); }\n/*ADP-1*/Object.defineProperty(a2, {} = (4277), ({get: ((this.z) =>  { yield this.__defineGetter__(\"x\", (function(y) { \"use strict\"; yield y; o2.a1.reverse();; yield y; }).bind(-19)).watch(\"3\", decodeURIComponent) } ).bind, set: (p={}, (p.z = yield undefined)()), configurable: (x % 5 == 3)}));\n");
/*fuzzSeed-254361819*/count=375; tryItOut("/*vLoop*/for (var qhzkrs = 0, (uneval((x)())), x; qhzkrs < 4; ++qhzkrs, Function.prototype.call.prototype) { let a = qhzkrs; ; } ");
/*fuzzSeed-254361819*/count=376; tryItOut("o1 + '';");
/*fuzzSeed-254361819*/count=377; tryItOut("\"use strict\"; i0.send(this.v0);v0 = t1.length;");
/*fuzzSeed-254361819*/count=378; tryItOut("\"use strict\"; o2.valueOf = x = x;");
/*fuzzSeed-254361819*/count=379; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1|\\\\3+?\", \"i\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=380; tryItOut("\"use strict\"; pgafeg, x;return;yield  /x/ ;");
/*fuzzSeed-254361819*/count=381; tryItOut("v2 = a1.length;");
/*fuzzSeed-254361819*/count=382; tryItOut("/*oLoop*/for (kgmsyi = 0; kgmsyi < 4; ++kgmsyi) { this.t1 = new Float32Array(this.a1); } ");
/*fuzzSeed-254361819*/count=383; tryItOut("testMathyFunction(mathy3, [2**53+2, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, -0, 0x080000001, -0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -1/0, Math.PI, -0x080000001, 1/0, 2**53-2, 1, Number.MIN_VALUE, 0x07fffffff, 0x100000000, -0x100000000, -(2**53), 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, -0x100000001, 0, Number.MIN_SAFE_INTEGER, 0x080000000, 42, 0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=384; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.fround((( - Math.atan(Math.fround(x))) >>> 0))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, -(2**53), 0, 0/0, 2**53-2, -0x080000001, 2**53, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, -1/0, 0x0ffffffff, -0x100000000, 0x080000001, 1/0, Number.MAX_VALUE, -(2**53-2), 1, Math.PI, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, -0x080000000]); ");
/*fuzzSeed-254361819*/count=385; tryItOut("\"use strict\"; /*infloop*/L:for(var e; -4.__defineSetter__(\"y\", ((w) => false).bind()); (p={}, (p.z = x--)()) in 0()) {e; }");
/*fuzzSeed-254361819*/count=386; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[Infinity, Infinity, function(){},  /x/ ,  /x/ , Infinity, Infinity, Infinity,  /x/ ,  /x/ , Infinity,  /x/ , Infinity, function(){}, function(){}, Infinity, function(){}, function(){},  /x/ , Infinity, function(){},  /x/ ,  /x/ , function(){}, function(){},  /x/ , function(){},  /x/ , Infinity,  /x/ , Infinity, function(){}, Infinity, function(){}, function(){}, function(){},  /x/ , Infinity,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){},  /x/ ,  /x/ , Infinity, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, Infinity, function(){}, Infinity, function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/ , Infinity,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , Infinity, Infinity,  /x/ , Infinity,  /x/ , Infinity, function(){},  /x/ ,  /x/ , function(){}, Infinity, function(){}, Infinity,  /x/ , function(){}]); ");
/*fuzzSeed-254361819*/count=387; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return (Math.min((( + (Math.fround((( + x) >>> 0)) ** (x >>> (((Math.atan2(x, Math.imul(x, (((y >>> 0) * Number.MAX_SAFE_INTEGER) >>> 0))) >>> 0) / Math.pow(-0x100000001, Math.fround(y))) >>> 0)))) | 0), ( + Math.imul(Math.fround(( + Math.hypot(Math.acos((Math.hypot(y, ((mathy1(x, (y >>> 0)) >>> 0) | 0)) === y)), ( + mathy1(((x << 0x100000000) != y), -(2**53+2)))))), Math.min((Math.min(Math.max(( ~ y), Number.MIN_VALUE), ( ! x)) | 0), Math.log2(1))))) | 0); }); ");
/*fuzzSeed-254361819*/count=388; tryItOut("\nthis\n;\nv2 = Object.prototype.isPrototypeOf.call(v2, v2);i1.next();\n");
/*fuzzSeed-254361819*/count=389; tryItOut("/*tLoop*/for (let d of /*MARR*/[ '' , [1,,],  '' ,  '' ,  '' , [1,,],  '' ,  '' ,  '' ,  '' ,  '' ,  '' , [1,,], [1,,],  '' , [1,,], [1,,], [1,,],  '' , [1,,],  '' , [1,,]]) { print(d); }");
/*fuzzSeed-254361819*/count=390; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.fround(Math.fround(Math.pow(Math.fround(Math.fround(((( - Math.cos(( + (( + y) ** ( + y))))) | 0) / Math.fround(( + Math.fround((Math.fround(((y | 0) >= y)) | (Math.imul((0.000000000000001 >>> 0), x) >>> 0)))))))), Math.fround(( + Math.atan2(( + ( + Math.asin(( + y)))), ( + Math.imul(Math.fround(mathy1(Math.fround(y), Math.fround(Math.atan2(y, mathy1(Number.MAX_VALUE, y))))), ( + -0x100000001)))))))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, 0x100000001, 0/0, 42, 1, 2**53, 1/0, 0.000000000000001, -0x080000000, -(2**53+2), Math.PI, 0x0ffffffff, 2**53+2, -Number.MIN_VALUE, -0x100000000, -0x100000001, -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53-2, -(2**53), Number.MIN_VALUE, -0, 0x080000000, 0x100000000]); ");
/*fuzzSeed-254361819*/count=391; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a1, []);");
/*fuzzSeed-254361819*/count=392; tryItOut("\"use strict\"; v1 = t0.byteLength;\n/*bLoop*/for (let arhkzw = 0; arhkzw < 2; ++arhkzw) { if (arhkzw % 5 == 2) { a1.forEach(this.f2, a1); } else { yield; }  } \n");
/*fuzzSeed-254361819*/count=393; tryItOut("\"use strict\"; a2[({valueOf: function() { for (var p in g2) { try { v2 = evaluate(\"m0 = new WeakMap;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 != 3), sourceIsLazy: (x % 42 == 38), catchTermination: x--, elementAttributeName: s0, sourceMapURL: s1 })); } catch(e0) { } a2 + ''; }return 0; }})] = g1.h0;");
/*fuzzSeed-254361819*/count=394; tryItOut("\"use strict\"; this.m0.set(o0.t1, f2);");
/*fuzzSeed-254361819*/count=395; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.sin(( + Math.fround(( - (Math.imul((( ! x) | 0), (x | 0)) | 0)))))); }); testMathyFunction(mathy0, [0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, -(2**53), 42, 1, -0x080000000, 1/0, -(2**53+2), Math.PI, 2**53-2, Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, 0, 2**53, -0x080000001, -0, -1/0, 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-254361819*/count=396; tryItOut("o1 = new Object;");
/*fuzzSeed-254361819*/count=397; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d0 = (1.001953125);\n    return (((i2)-(i2)-((0x69464538) ? (0x970d14f5) : ((+(0.0/0.0)) >= (-((\"\\u43D4\")))))))|0;\n  }\n  return f; })(this, {ff: \"\u03a0\"}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x07fffffff, -(2**53+2), 1, 0x100000001, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0/0, 1/0, Number.MIN_VALUE, 0x100000000, -0x100000001, 2**53-2, -1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, -Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 2**53, 0, 0x080000001, 0.000000000000001, -0, 0x080000000, -0x07fffffff, 0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=398; tryItOut("v0 = (t1 instanceof a0);");
/*fuzzSeed-254361819*/count=399; tryItOut("var v1 = this.g2.eval(\"function f2(p2)  { yield d + eval } \");");
/*fuzzSeed-254361819*/count=400; tryItOut("\"use strict\"; o2.a0.forEach((function() { try { /*MXX3*/g2.RegExp.$* = g0.g0.RegExp.$*; } catch(e0) { } try { s0.valueOf = (function() { for (var j=0;j<48;++j) { this.f2(j%3==1); } }); } catch(e1) { } try { t0 + g1.v1; } catch(e2) { } /*ADP-3*/Object.defineProperty(a0, ({valueOf: function() { this.e1.add(t1);return 9; }}), { configurable: true, enumerable: false, writable: false, value: t0 }); return s0; }), e1, i1, v0, this.p0);");
/*fuzzSeed-254361819*/count=401; tryItOut("t2[17];");
/*fuzzSeed-254361819*/count=402; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-254361819*/count=403; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=404; tryItOut("\"use strict\"; i2.next();");
/*fuzzSeed-254361819*/count=405; tryItOut("this.m2.delete(m2);");
/*fuzzSeed-254361819*/count=406; tryItOut("(this);e1 = new Set;");
/*fuzzSeed-254361819*/count=407; tryItOut("\"use strict\"; /*vLoop*/for (var mwkeiu = 0; mwkeiu < 41 && ((4277)); ++mwkeiu, (\"\\uB032\")(arguments)++) { w = mwkeiu; m2.valueOf = (function() { for (var j=0;j<8;++j) { f2(j%5==1); } }); } ");
/*fuzzSeed-254361819*/count=408; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.log10(( + Math.exp(( + ((( + (Math.fround(x) >>> Math.fround(y))) | 0) === (Math.fround(( ! x)) + Math.fround(Math.imul(Math.fround(( ~ (x >>> 0))), x)))))))); }); testMathyFunction(mathy4, /*MARR*/[-0x080000001, -0x080000001, new Boolean(true), new Boolean(true), -0x080000001, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), -0x080000001]); ");
/*fuzzSeed-254361819*/count=409; tryItOut("\"use strict\"; v1 = true;");
/*fuzzSeed-254361819*/count=410; tryItOut("const x, {({a2:z2}): z} = z = /(?:[^\\u005F-\\t\\ue3e3-\\cT]?)|\\1.{3,}++?/yi, a, wouaak, of = x, y = TypeError(\"\u03a0\", -21) ^= x, ulraiv, NaN = new RegExp(\"((?=.+))|(.*?)+\", \"gym\"), osleas, rlqakv;v1 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-254361819*/count=411; tryItOut("t2 = new Float64Array(v0);");
/*fuzzSeed-254361819*/count=412; tryItOut("x;");
/*fuzzSeed-254361819*/count=413; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.max((Math.fround(Math.abs((Math.acos(Math.fround(Math.atan2(Math.fround(mathy1(x, -0x07fffffff)), y))) | 0))) | 0), (( ~ Math.pow(y, mathy0(Math.exp(Number.MIN_VALUE), Math.asin(x)))) | 0)) | 0); }); testMathyFunction(mathy2, [0/0, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 0.000000000000001, 0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), -0x100000001, -0, 0, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, 1, -0x0ffffffff, 0x100000000, 2**53, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -Number.MAX_VALUE, 2**53+2, 1/0, -0x080000000, 0x080000001, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -1/0, -0x080000001]); ");
/*fuzzSeed-254361819*/count=414; tryItOut("h0 = {};");
/*fuzzSeed-254361819*/count=415; tryItOut("t1.set(a0, v2);");
/*fuzzSeed-254361819*/count=416; tryItOut("\"use strict\"; o1.m0.has((/*FARR*/[].sort));");
/*fuzzSeed-254361819*/count=417; tryItOut("/*RXUB*/var r = /[^]/gyi; var s = \"\\n\"; print(r.test(s)); ");
/*fuzzSeed-254361819*/count=418; tryItOut("\"use strict\"; {f0.toSource = (function() { try { o1.v0 = evaluate(\"x, window, illmqm, d, xsxyvh, gjlsvb, eresgn, b, eval, e;\\nyield;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 14 != 7), noScriptRval: delete a.this, sourceIsLazy: false, catchTermination: true })); } catch(e0) { } /*ODP-2*/Object.defineProperty(b0, \"sin\", { configurable: false, enumerable: false, get: (function() { t0.__proto__ = this.m0; return v0; }), set: f1 }); throw t1; }); }");
/*fuzzSeed-254361819*/count=419; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0.000000000000001, -(2**53), Number.MAX_VALUE, -1/0, 2**53, 0x0ffffffff, -0x07fffffff, -(2**53+2), -0x080000000, 1.7976931348623157e308, 0x080000000, 2**53-2, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, 0/0, 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 0, 1, 0x080000001, -0x080000001, -0, -Number.MAX_VALUE, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=420; tryItOut("M:switch((4277)) { case (yield /*MARR*/[ 'A' , new String(''), 0x0ffffffff,  'A' , new String(''),  'A' , new String('q'), 0x0ffffffff,  'A' , 0x0ffffffff, 0x0ffffffff, new String('q'), new String(''), new String('q'),  'A' , 0x0ffffffff, new String('q'), 0x0ffffffff,  'A' , new String('q'), new String('q'),  'A' , 0x0ffffffff, new String(''), 0x0ffffffff,  'A' , new String(''), 0x0ffffffff, 0x0ffffffff, new String(''), new String('q'), new String(''), 0x0ffffffff, new String(''), new String('q'), new String(''), new String(''), 0x0ffffffff, new String(''), new String('q'), new String('q'),  'A' , new String('q'), new String(''), new String('q'), 0x0ffffffff, 0x0ffffffff, new String('q'), new String(''), 0x0ffffffff, new String('q'), new String(''), new String(''),  'A' , 0x0ffffffff, new String('q'), new String('q'), new String('q'),  'A' , new String('q'),  'A' , 0x0ffffffff,  'A' , new String(''),  'A' , new String(''), new String(''), new String('q'), new String('q'), new String(''), new String(''), new String('q'), 0x0ffffffff, new String('q'),  'A' , new String(''), new String(''), 0x0ffffffff,  'A' , 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, new String(''),  'A' ,  'A' ,  'A' , 0x0ffffffff,  'A' , new String(''), new String('q'),  'A' , 0x0ffffffff, new String('q'), new String(''), new String(''), 0x0ffffffff,  'A' , new String('q'), new String('q'), new String(''), new String(''),  'A' , new String(''), 0x0ffffffff, new String('q'), 0x0ffffffff, new String(''), new String('q'), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, new String('q'), 0x0ffffffff, new String('q'), 0x0ffffffff, new String(''), new String('q'),  'A' , new String('q'),  'A' , 0x0ffffffff, new String(''), new String(''), new String('q'), new String(''),  'A' ,  'A' ,  'A' ,  'A' , new String('q'), new String('q'), new String(''), 0x0ffffffff, new String(''), 0x0ffffffff, 0x0ffffffff, new String(''), 0x0ffffffff, new String(''), new String('q'), new String('q'), new String(''), new String('q'),  'A' ].map(e => this)): for (var v of s0) { try { e2.add(g0.v1); } catch(e0) { } try { this.b0 = new ArrayBuffer(6); } catch(e1) { } b2.valueOf = (function() { v0 = g1.eval(\"print(w = this.__defineGetter__(\\\"\\\\u3056\\\", (1 for (x in []))));\"); return i2; }); }break; default: (-14);break; /*bLoop*/for (bcqlft = 0; bcqlft < 6; ++bcqlft) { if (bcqlft % 2 == 1) { print(\"\\u086F\"); } else { c; }  } break; case \"\\u25C6\".__defineGetter__(\"c\", \"\\u16B4\"): break; print(uneval(g2));case 1:  }");
/*fuzzSeed-254361819*/count=421; tryItOut("\"use strict\"; g1.b1 = m1.get(o2);");
/*fuzzSeed-254361819*/count=422; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=423; tryItOut("mathy2 = (function(x, y) { return ( + Math.atan2(( + (Math.tanh(Math.trunc(((((y | 0) == ( + Number.MIN_VALUE)) | 0) | 0))) >>> mathy1(x, Math.imul(y, (Math.pow((y >>> 0), ((y | -Number.MIN_VALUE) >>> 0)) >>> 0))))), ( + Math.sqrt(( + ( + mathy0(( + x), Math.atanh(Math.atanh(y))))))))); }); ");
/*fuzzSeed-254361819*/count=424; tryItOut("\"use strict\"; \"use asm\"; e1[\"8\"] = t0;function x(x, x = ({x: x, -14: NaN }))new String();");
/*fuzzSeed-254361819*/count=425; tryItOut("testMathyFunction(mathy1, [-0x080000001, -0, 0x07fffffff, -1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -0x0ffffffff, 0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, 1/0, 0x100000001, -(2**53), 0, 2**53, -0x080000000, -(2**53+2), 2**53-2, -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53+2, 42, -Number.MAX_VALUE, -0x100000001, 0x080000001]); ");
/*fuzzSeed-254361819*/count=426; tryItOut("a0 = Array.prototype.map.call(a2, (function() { for (var j=0;j<6;++j) { f2(j%4==1); } }));");
/*fuzzSeed-254361819*/count=427; tryItOut("this.a1.reverse();");
/*fuzzSeed-254361819*/count=428; tryItOut("\"use strict\"; v1 = evaluate(\"function f2(h1) (uneval( \\\"\\\" ))\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 17 == 2), sourceIsLazy: false, catchTermination:  /x/g  }));\nObject.prototype.__defineGetter__\n");
/*fuzzSeed-254361819*/count=429; tryItOut("\"use strict\"; print(t0);function x(c, e = (p={}, (p.z = (uneval(undefined)))()), NaN, c = false, NaN = (+let (e)  \"\" ), [w], x, eval, z, NaN, NaN, x, x, x, \u3056 = false, x, x, \u3056, x, this.x, c, y, b, d = true, c, x, w, x, c, d = x, x, \u3056, NaN, eval, d, d = false, x, window, z, window = -16, this.c, c, x, a = new RegExp(\"(?![^])[^\\\\u005D\\\\t-\\ufef1\\u008a-\\ua7a3\\\\x62-\\u2922]|\\\\cL\\\\b+?+[^]{0,}\\\\3*?|^\", \"gm\"), d, x, x, x, x, b, x, d = Math, x, NaN, b, NaN, x, z =  /x/g , x, a, x, window, x, NaN, \u3056, x, x, y, eval, NaN, x, x, window, x, y, w, x, x, y, d) { return x-- } {}\nt1[v0] = f1;\n");
/*fuzzSeed-254361819*/count=430; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min(Math.pow(Math.asin(Number.MIN_SAFE_INTEGER), ( ~ ((Math.max(( ! x), ( + y)) && Math.acosh((Math.imul((y | 0), (y | 0)) | 0))) + Math.fround((Math.pow(x, (Math.log1p((1/0 | 0)) | 0)) >>> 0))))), (( + (Math.clz32((x >>> 0)) >>> 0)) ? (Math.fround(Math.trunc(x)) & ((((Math.max(-(2**53), ( ~ ( ! x))) >>> 0) >>> 0) <= (x >>> 0)) >>> 0)) : Math.fround(Math.log(Math.fround(Math.asinh(y)))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, -Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 0/0, -0x100000001, 0x0ffffffff, -(2**53-2), Number.MIN_VALUE, -0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, 1, Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, -(2**53), -0x0ffffffff, 1/0, 2**53-2, -0, -0x07fffffff, -1/0, 0, 42, -Number.MAX_VALUE, -(2**53+2), 0x080000000, 0x100000000, 0x100000001]); ");
/*fuzzSeed-254361819*/count=431; tryItOut("testMathyFunction(mathy3, [1, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE, 42, 1/0, -0x0ffffffff, 0.000000000000001, 0x100000000, -(2**53), -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 2**53-2, -0, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, 0, Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, -0x07fffffff, -(2**53+2), 0x07fffffff, -0x080000001, 0x080000001]); ");
/*fuzzSeed-254361819*/count=432; tryItOut("/*RXUB*/var r = r1; var s = \"\\u00c2\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=433; tryItOut("\"use strict\"; /*RXUB*/var r = 29; var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=434; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.fround((Math.fround(( + (((Math.max(( + (Math.asinh((-0x100000000 >>> 0)) >>> 0)), ( + x)) >>> 0) >>> 0) <= ( + (Math.max(y, (( - (Math.cosh((y >>> 0)) >>> 0)) >>> 0)) >>> 0))))) ? Math.fround(Math.fround(Math.sinh(Math.fround((Math.max(y, 0.000000000000001) && y))))) : Math.fround(Math.log2((Math.fround((Math.fround(( + (( + x) ? ( + Number.MAX_SAFE_INTEGER) : (Math.cosh(x) | 0)))) & Math.fround(x))) == Math.min(x, x))))))); }); testMathyFunction(mathy5, [-1/0, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53-2), 1/0, 0x080000001, Number.MIN_VALUE, -0x100000001, Math.PI, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001, 0x080000000, 0, -0x080000000, -(2**53), 0x100000001, 2**53-2, 0x0ffffffff, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 0x100000000, -0, 0/0, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 2**53+2, -0x07fffffff, 42]); ");
/*fuzzSeed-254361819*/count=435; tryItOut("g1.h2 = {};");
/*fuzzSeed-254361819*/count=436; tryItOut("print(x);");
/*fuzzSeed-254361819*/count=437; tryItOut("Math.trunc( /x/ );");
/*fuzzSeed-254361819*/count=438; tryItOut("\"use strict\"; e1.add(e2);");
/*fuzzSeed-254361819*/count=439; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[new String(''), new String(''), undefined, new Number(1.5), new String(''), new String(''), new String(''), new Number(1.5), undefined, new Number(1.5), undefined, new Number(1.5), new String(''), new Number(1.5), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), undefined, undefined, undefined, new Number(1.5), new String(''), undefined, new String(''), new String(''), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), undefined, new String(''), undefined, undefined, new String(''), new Number(1.5), new String(''), undefined, new Number(1.5), new Number(1.5), new String(''), new String(''), new String(''), undefined, undefined, new Number(1.5), undefined, new Number(1.5), new String('')]) { e0.has(v1); }");
/*fuzzSeed-254361819*/count=440; tryItOut("mathy3 = (function(x, y) { return ((Math.log(( + mathy0(( + y), ( + mathy1(( + mathy2(( - y), y)), ( + ( + Math.sinh((Math.fround(( ! (-0x080000001 | 0))) >>> 0))))))))) | 0) * (Math.fround(Math.sinh(Math.fround((( - (mathy1(y, ((-0x0ffffffff - ( + Math.imul(x, Math.PI))) | 0)) | 0)) | 0)))) | 0)); }); testMathyFunction(mathy3, [0/0, -(2**53), 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, 42, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -0x080000000, -Number.MAX_VALUE, 0x080000000, -0x07fffffff, -(2**53+2), 0x07fffffff, 0x100000000, -0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 2**53+2, 0x100000001, 0.000000000000001, 0, -0x100000001, -0, 0x080000001, 2**53, -1/0]); ");
/*fuzzSeed-254361819*/count=441; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a2, [(function mcc_() { var tzxglo = 0; return function() { ++tzxglo; if (/*ICCD*/tzxglo % 6 == 3) { dumpln('hit!'); try { v0 = t1.BYTES_PER_ELEMENT; } catch(e0) { } try { /*RXUB*/var r = this.r0; var s = s1; print(r.test(s));  } catch(e1) { } try { t1.set(t2, 13); } catch(e2) { } i0.next(); } else { dumpln('miss!'); Object.defineProperty(this, \"v1\", { configurable: (x % 13 != 0), enumerable: true,  get: function() {  return g1.t0.byteOffset; } }); } };})(), a2]);");
/*fuzzSeed-254361819*/count=442; tryItOut("\"use strict\"; for (var v of g2.a1) { try { g1.a1.sort((function() { try { s0 += 'x'; } catch(e0) { } try { v2 = evalcx(\"yield;Function\", g0); } catch(e1) { } try { a1.pop(this.o0, o0, i2, (/*UUV2*/(x.fround = x.indexOf) += x), (4277), s2, e1); } catch(e2) { } s0 += 'x'; throw o0.o2.e2; }), t0, h2); } catch(e0) { } s0 = s2.charAt(7); }");
/*fuzzSeed-254361819*/count=443; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-254361819*/count=444; tryItOut("mathy5 = (function(x, y) { return Math.imul((Math.pow(Math.atan(y), (Math.trunc(( + y)) & (( ! (y | 0)) | 0))) >>> 0), (( + (( + (( + ( ~ ( + mathy0(( + x), ( + x))))) % ( + Math.log1p(( + ( - ( + -(2**53-2)))))))) | 0)) | 0)); }); ");
/*fuzzSeed-254361819*/count=445; tryItOut("(-26);");
/*fuzzSeed-254361819*/count=446; tryItOut("\"use strict\"; Object.defineProperty(this, \"f0\", { configurable: Math.sqrt(-23), enumerable: (x % 6 == 5),  get: function() {  return Proxy.createFunction(h1, f2, f1); } });");
/*fuzzSeed-254361819*/count=447; tryItOut("\"use strict\"; let (oberub) { v0 = Object.prototype.isPrototypeOf.call(v2, o0); }");
/*fuzzSeed-254361819*/count=448; tryItOut("mathy2 = (function(x, y) { return ( ! Math.max(Math.atan2(Math.hypot(x, 0/0), (mathy0(0x07fffffff, ( ~ -1/0)) >>> 0x080000000)), Math.ceil(Math.fround((mathy1((0x0ffffffff >>> 0), ((Math.cbrt((x | 0)) | 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [(new Number(0)), objectEmulatingUndefined(), false, (new Boolean(false)), (new String('')), [], NaN, (function(){return 0;}), /0/, -0, '/0/', '0', null, 0, ({valueOf:function(){return 0;}}), (new Boolean(true)), true, [0], ({valueOf:function(){return '0';}}), 1, (new Number(-0)), '', '\\0', 0.1, undefined, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-254361819*/count=449; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround((( + Math.atan2((Math.max((( + Math.sinh(Math.fround((( + ( ! ( + y))) ? x : x)))) >>> 0), (Math.imul((x >>> 0), Math.imul(((( - (x | 0)) | 0) && y), ( + ( - Math.fround(((Math.fround(x) === Math.fround(y)) >>> 0)))))) >>> 0)) >>> 0), Math.atan2(0x080000001, y))) || (( + mathy3((((Math.asinh(y) < ( + (( + ( + mathy0(( + (mathy3(y, Math.fround((Math.fround(x) ? Math.fround(y) : x))) >>> 0)), ((mathy2((x >>> 0), (x >>> 0)) >>> 0) >>> 0)))) >>> ( + -0x080000001)))) | 0) | 0), ((mathy2((x | 0), ((Math.asinh((mathy3(Math.fround(( + Math.atan2(x, y))), -0x100000000) | 0)) | 0) | 0)) | 0) | 0))) >>> 0))); }); testMathyFunction(mathy5, ['\\0', /0/, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 0.1, false, (new Number(-0)), '/0/', 1, true, 0, [], null, '', (new Number(0)), (new Boolean(false)), ({valueOf:function(){return '0';}}), (new String('')), '0', ({toString:function(){return '0';}}), [0], NaN, undefined, (new Boolean(true)), -0, (function(){return 0;})]); ");
/*fuzzSeed-254361819*/count=450; tryItOut("\"use strict\"; (new Boolean(false));");
/*fuzzSeed-254361819*/count=451; tryItOut("\"use strict\"; a2.unshift(e1, let (d = /\\u008B|[^]*?|./ym) new RegExp(\"(?=[^\\\\u0063-\\\\u3D47\\\\u1239-\\\\ub32B\\\\W]){0,0}|((?=($)*))[\\\\x1C-\\\\u5006\\\\xE2\\\\W6-\\\\u003A]\", \"g\"), g2, g0, p2);");
/*fuzzSeed-254361819*/count=452; tryItOut("\"use strict\"; { void 0; void relazifyFunctions('compartment'); } g1.v2 = (b0 instanceof s2);");
/*fuzzSeed-254361819*/count=453; tryItOut("v2 = evaluate(\"this.t1 = t2.subarray(12, 4);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-254361819*/count=454; tryItOut("/*oLoop*/for (let vrquzj = 0; vrquzj < 121; ++vrquzj) { h1.iterate = f0; } ");
/*fuzzSeed-254361819*/count=455; tryItOut("with(-4){/*vLoop*/for (let afuffb = 0; afuffb < 97; ++afuffb) { var a = afuffb; a1.pop(g0.o2, \"\\uF7D2\"); }  }");
/*fuzzSeed-254361819*/count=456; tryItOut("{ void 0; void gc(this); }");
/*fuzzSeed-254361819*/count=457; tryItOut("\"use strict\"; h1.iterate = this.f2;");
/*fuzzSeed-254361819*/count=458; tryItOut("\"use strict\"; h2.valueOf = (function() { try { o2.m2.has(e1); } catch(e0) { } try { i2.send(t1); } catch(e1) { } v1 = (i1 instanceof this.i2); return h0; });");
/*fuzzSeed-254361819*/count=459; tryItOut("var w;print(-16);\ne2.add(t1);\n");
/*fuzzSeed-254361819*/count=460; tryItOut("/*iii*/((\"\\u1305\" - new RegExp(\"(?=(?=(?=.*).))[^\\\\S\\u009a\\\\x01-\\u1bae]{3,}\", \"\").yoyo((ejcaco) = undefined)));/*hhh*/function ejcaco(z, ...window){print((/*wrap3*/(function(){ var qexzvc = [,,z1]; ((let (e=eval) e))(); })\u000c).call(({a2:z2}), ));}");
/*fuzzSeed-254361819*/count=461; tryItOut(" /x/ .yoyo(undefined);");
/*fuzzSeed-254361819*/count=462; tryItOut("\"use strict\"; var gaeejz = new ArrayBuffer(6); var gaeejz_0 = new Int16Array(gaeejz); gaeejz_0[0] = -21; var gaeejz_1 = new Uint16Array(gaeejz); var gaeejz_2 = new Int16Array(gaeejz); i0.send(a2);switch(null) { case 8: this.a0 = arguments; }");
/*fuzzSeed-254361819*/count=463; tryItOut(";");
/*fuzzSeed-254361819*/count=464; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot((Math.trunc(((((Math.round(x) >>> 0) ? ((Math.max(y, Math.PI) !== ( + Math.hypot(( + Math.atan((( ~ (x | 0)) | 0))), ( + (Math.imul(Math.acos(x), (Math.ceil(( + y)) >>> 0)) >>> 0))))) >>> 0) : (y >>> 0)) >>> 0) >>> 0)) >>> 0), (( ~ (( ~ Math.clz32(0x100000000)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-254361819*/count=465; tryItOut("testMathyFunction(mathy5, [Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, 0x080000001, -(2**53), 1, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 2**53-2, -Number.MIN_VALUE, 2**53+2, 0.000000000000001, -0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, 0/0, -(2**53+2), 0x080000000, 0x100000001, -0x100000000, 0, Number.MIN_SAFE_INTEGER, 1/0, Math.PI, 42, 1.7976931348623157e308, -0, -0x100000001, 2**53, -0x080000001]); ");
/*fuzzSeed-254361819*/count=466; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan2(( ! (Math.round((((( ! (x >>> 0)) >>> 0) + (Math.abs(( + Math.fround(( - Math.fround(x))))) | 0)) >>> 0)) >>> 0)), ((x ? Math.fround(Math.min(Math.fround(Math.round(0x100000001)), Math.fround(Math.imul(y, ( + (Math.fround(Math.max(y, y)) ? Math.fround(y) : Math.fround(Math.clz32(y)))))))) : (x ? Math.fround(Math.hypot((-Number.MIN_VALUE | 0), ((Math.acos((x | 0)) | 0) >>> 0))) : y)) > Math.max((Math.atan2((x * y), 0.000000000000001) & (( + ( - ( + y))) | 0)), x))); }); ");
/*fuzzSeed-254361819*/count=467; tryItOut("this.t0.set(t0, this);");
/*fuzzSeed-254361819*/count=468; tryItOut("mathy3 = (function(x, y) { return (((mathy2(( + Math.cbrt(( + ( + ( ~ ( + y)))))), ( + (y | Math.log1p(Math.fround(( + (Math.round(((0x07fffffff + -Number.MAX_SAFE_INTEGER) >>> 0)) | 0))))))) >>> 0) | 0) | ((( ~ (( - (x | 0)) | 0)) / (x >>> (1.7976931348623157e308 ? Math.imul(y, y) : (Math.asin(((( - (y >>> 0)) >>> 0) | 0)) | 0)))) | 0)); }); testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '\\0', objectEmulatingUndefined(), (new Boolean(false)), (new String('')), /0/, [0], (new Number(-0)), (function(){return 0;}), '0', true, 0, null, '/0/', [], undefined, (new Number(0)), -0, 1, false, (new Boolean(true)), '', ({toString:function(){return '0';}}), NaN, 0.1]); ");
/*fuzzSeed-254361819*/count=469; tryItOut("\"use strict\"; s0 += this.s1;");
/*fuzzSeed-254361819*/count=470; tryItOut("m1 + '';");
/*fuzzSeed-254361819*/count=471; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.log(Math.fround(y)) | 0), (Math.imul((y >= Math.fround(Math.min(Number.MAX_VALUE, Math.fround(x)))), Math.cos(( ~ -(2**53+2)))) | 0)) ? (Math.max(( + mathy0((y | 0), (0x0ffffffff != Math.hypot(Math.fround(-(2**53)), (y >>> 0))))), Math.max(x, -Number.MAX_SAFE_INTEGER)) === (Math.fround(( ! (( + x) >>> 0))) | 0)) : ((( + (( + Math.log(x)) - ( + x))) >>> 0) ? Math.max(( + Math.max(y, x)), Math.imul((x - Math.fround(Math.log2(y))), Math.fround(Math.hypot((y | 0), mathy0(x, Number.MAX_SAFE_INTEGER))))) : (Math.fround(mathy1((( + (( + Math.log2(y)) * ( + ( ~ y)))) >>> 0), Math.fround(-0x100000001))) >= (Math.sin(( + Math.imul((mathy2(x, y) >>> 0), (mathy1((0/0 >>> 0), (x >>> 0)) >>> 0)))) >>> 0)))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x100000001, 0x07fffffff, -0x100000001, 1, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, Math.PI, 0, -(2**53+2), 0/0, -Number.MAX_VALUE, -0x080000001, 1/0, 0.000000000000001, -Number.MIN_VALUE, 42, 0x080000001, 2**53+2, -0, -(2**53-2), -0x100000000, 0x080000000, 2**53, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-254361819*/count=472; tryItOut("a0[({valueOf: function() { Array.prototype.splice.apply(a1, [h2, f0, o1.i0]);return 0; }})];");
/*fuzzSeed-254361819*/count=473; tryItOut("\"use strict\"; p0 + '';");
/*fuzzSeed-254361819*/count=474; tryItOut("const mcdydl, eval, x = this, x, BYTES_PER_ELEMENT = y - z, c = (Number.MIN_VALUE);t1[14];");
/*fuzzSeed-254361819*/count=475; tryItOut("(undefined);( /x/ );");
/*fuzzSeed-254361819*/count=476; tryItOut("/*infloop*/for( \"\" ; (void shapeOf(({} =  /* Comment */(({e: x}))))); objectEmulatingUndefined.prototype) t2.set(t1, x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: objectEmulatingUndefined, fix: String.prototype.padStart, has: function() { return false; }, hasOwn: ({a2:z2}), get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(-1), function(y) { yield y; (\"\\u6BE5\");; yield y; }));");
/*fuzzSeed-254361819*/count=477; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?:(?!(?:\\cE))(?=(?![][\uea79\\xbF\\u0095-\\u51a1\\d].|\u008f)))\\B*)/m; var s = x(false) = []; print(s.replace(r, '\\u0341', \"gym\")); ");
/*fuzzSeed-254361819*/count=478; tryItOut("while(((new (Object.isFrozen)())) && 0){g2.t0[13] = v2;print(uneval(a1)); }");
/*fuzzSeed-254361819*/count=479; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ (( + ((((( ~ Math.tan(x)) | 0) === ((x * x) | 0)) | 0) | 0)) | 0)); }); ");
/*fuzzSeed-254361819*/count=480; tryItOut("mathy4 = (function(x, y) { return (((((((Math.acos((Math.trunc(-0x0ffffffff) >>> 0)) >>> 0) >>> 0) ? (Math.atanh(x) >>> 0) : mathy2(( + (((( ~ Math.hypot(x, y)) | 0) > (((Math.min(x, x) | 0) ? ( + Math.atan(( + x))) : (x | 0)) | 0)) >>> 0)), Math.fround(Number.MIN_VALUE))) >>> 0) >>> 0) ? ((( ~ ( + (-(2**53) ? (( ~ Math.fround(((( ~ y) >>> 0) ? y : x))) | 0) : 1))) % (Math.max(Number.MAX_SAFE_INTEGER, Math.max((Math.imul((x >>> 0), Math.fround(x)) >>> 0), -Number.MAX_VALUE)) & ( + ((((Math.min(( + y), ( + x)) >>> 0) , (y >>> 0)) >>> 0) | 0)))) | 0) : (( ! (Math.atan2((Math.pow(y, Math.fround(( ~ (( + ( + x)) | 0)))) >>> 0), ( ! ( + ((y | 0) & (x >>> 0))))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0x080000000, 0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, 42, -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, -1/0, 0x07fffffff, 0x0ffffffff, -(2**53-2), 0/0, Number.MIN_VALUE, 2**53, -0x080000001, 0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, -(2**53), -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, 0x080000001, 0.000000000000001, 0x100000001, Math.PI, 2**53+2, Number.MAX_VALUE, 0x080000000, -0x100000001]); ");
/*fuzzSeed-254361819*/count=481; tryItOut("v2 = (e0 instanceof f2);");
/*fuzzSeed-254361819*/count=482; tryItOut("\"use strict\"; { void 0; void gc('compartment'); } f0(this.i1);");
/*fuzzSeed-254361819*/count=483; tryItOut("\"use strict\"; var xwextz = new SharedArrayBuffer(4); var xwextz_0 = new Uint8ClampedArray(xwextz); xwextz_0[0] = 331686209; var xwextz_1 = new Int16Array(xwextz); var xwextz_2 = new Int16Array(xwextz); xwextz_2[0] = -13; var xwextz_3 = new Int8Array(xwextz); print(xwextz_3[0]); xwextz_3[0] = 27; var xwextz_4 = new Uint8Array(xwextz); print(xwextz_4[0]); xwextz_4[0] = 22; var xwextz_5 = new Int8Array(xwextz); xwextz_5[0] = -2267046467; var xwextz_6 = new Int16Array(xwextz); xwextz_6[0] = -22; var xwextz_7 = new Uint32Array(xwextz); var xwextz_8 = new Uint16Array(xwextz); print(xwextz_8[0]); xwextz_8[0] = 19; var xwextz_9 = new Float32Array(xwextz); print(xwextz_9[0]); var xwextz_10 = new Uint16Array(xwextz); xwextz_10[0] = -10; var xwextz_11 = new Uint16Array(xwextz); /* no regression tests found */Object.defineProperty(this, \"v1\", { configurable: ((void version(180))), enumerable: (xwextz_2[6] % 2 != 1),  get: function() {  return t0.BYTES_PER_ELEMENT; } });a2 = this.r1.exec(s1);m2.get(e1);");
/*fuzzSeed-254361819*/count=484; tryItOut("e0.add(o0);");
/*fuzzSeed-254361819*/count=485; tryItOut("this.o1.v2 = (v1 instanceof this.e2);");
/*fuzzSeed-254361819*/count=486; tryItOut("/*infloop*/for((yield true); x; x) f1 = (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -281474976710655.0;\n    d3 = (d0);\n    return +((Float32ArrayView[2]));\n  }\n  return f; });");
/*fuzzSeed-254361819*/count=487; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[ 'A' , objectEmulatingUndefined(),  /x/g , function(){}, function(){}, function(){},  'A' ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), b = ([Math.max( '' , a)]),  'A' , objectEmulatingUndefined(),  /x/g , function(){}, objectEmulatingUndefined(), function(){}, b = ([Math.max( '' , a)]),  'A' , b = ([Math.max( '' , a)]), b = ([Math.max( '' , a)]), b = ([Math.max( '' , a)]), b = ([Math.max( '' , a)]), b = ([Math.max( '' , a)]), b = ([Math.max( '' , a)]), b = ([Math.max( '' , a)]), b = ([Math.max( '' , a)]), objectEmulatingUndefined(),  /x/g , function(){},  /x/g ]); ");
/*fuzzSeed-254361819*/count=488; tryItOut("v1 = g2.eval(\"function this.f1(t2)  { yield /*\\n*/x } \");");
/*fuzzSeed-254361819*/count=489; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Object.assign-=x; }); ");
/*fuzzSeed-254361819*/count=490; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ! ((((( + Math.atan2(( + Math.max(-0x080000001, x)), ( + Math.fround(Math.acos(( + ( ! ( + 2**53+2)))))))) < Math.round(Math.fround(mathy1(((( + y) >= (x >>> 0)) >>> 0), y)))) | 0) !== ((( - ((((Math.sqrt((x >>> 0)) | 0) % (0x100000001 | 0)) >>> 0) == (y <= 42))) >>> 0) ? ( + ( + Math.log2(( + x)))) : ( + (( + 1.7976931348623157e308) | ( + Math.fround((Math.fround(x) < Math.fround(Math.fround(( ~ (( + ((y | 0) && -1/0)) | 0))))))))))) >>> 0)); }); testMathyFunction(mathy5, [-0x100000001, -(2**53+2), -0, Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 42, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, 0x100000001, -0x07fffffff, 0/0, -(2**53), Number.MAX_VALUE, -0x0ffffffff, 0, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, 0x100000000, -0x080000000, 0x07fffffff, 1, 1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000]); ");
/*fuzzSeed-254361819*/count=491; tryItOut("\"use strict\"; print([[]]);");
/*fuzzSeed-254361819*/count=492; tryItOut("mathy3 = (function(x, y) { return (( - ((Math.sqrt(Math.sqrt(Math.hypot((-(2**53-2) | 0), y))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [-0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000000, 0, -0x0ffffffff, 1/0, 0x07fffffff, 42, -1/0, -0x100000000, -(2**53-2), -0x100000001, -(2**53), -Number.MIN_VALUE, Math.PI, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -0x080000001, Number.MAX_VALUE, 0/0, 0.000000000000001, 2**53+2, 1, 0x100000001, -0, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-254361819*/count=493; tryItOut("let(gsokrm, nrxsvb, d = (function() { yield Math.tan(18); } })(), this) ((function(){e+=e ? false : true;})());let(x = /*FARR*/[.../*FARR*/[], new (new (window)(\"\\u5301\", z))(Math.atan2(-29, new RegExp(\"(?=(?=((?:\\\\D)|$|\\\\B|\\\\cZ|\\\\d))+)\", \"ym\"))\u0009), x].sort(DataView.prototype.setUint32), window, x = (function ([y]) { })() >>>= arguments, {c: {x: [], x: {x: []}}, x: {y}, x: {x: []}} =  /* Comment */\"\\u2B3A\", idwawc, NaN, window = Map(/\u0c5a[]/y)) ((function(){x.__proto__ = w;})());");
/*fuzzSeed-254361819*/count=494; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.cbrt((( ! (Math.tanh(y) | 0)) | 0)); }); testMathyFunction(mathy0, [0x100000001, 42, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 2**53-2, -(2**53), 0/0, -0x100000001, 0, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 0x100000000, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff, 2**53, 2**53+2, -0, 0x0ffffffff, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, -(2**53-2), 0x07fffffff, 1/0, 1]); ");
/*fuzzSeed-254361819*/count=495; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 3.022314549036573e+23;\n    {\n      d2 = (((d1)) % ((d1)));\n    }\n    {\n      d1 = (d2);\n    }\n    return ((((((0xfb3eb65)-((new RegExp(\"(.)^\", \"g\")) <= (((!((-0x8000000) == (0x213b7a83))))>>>((0xe8326817) % (0xffffffff)))))>>>((((((0xb9939121))>>>((0x47d9249)))) ? (0x83270815) : (0x480aa97a))-(0xffffffff))))))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0, 2**53+2, -0x100000001, 0x100000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, 1/0, 0x0ffffffff, -(2**53+2), -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -Number.MIN_VALUE, 2**53-2, 0x080000000, Math.PI, 42, -0, -(2**53-2), Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, -1/0, 2**53, -0x07fffffff, 1]); ");
/*fuzzSeed-254361819*/count=496; tryItOut("/*RXUB*/var r = /(((?=\ub30f*|\\s|$|\\S(\\d)))|(?:[])*{4,})/i; var s = \"\"; print(s.replace(r, (c = c = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: function() { return true; }, get: Proxy, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: undefined, }; })(true), tyspik), \u3056, this.r, r = r, x, c, \u3056 = /*FARR*/[.../*FARR*/[d, window, ...[], ]].map((new Function(\";\")), e), \u3056 = s, \u3056, window, {}, z = window, s,  , s, x, \u3056, e, s, window, w, r = new RegExp(\"[^]\", \"yi\"), c, d, x, x, window, window, r, x = Math, this.b, r =  /x/ , z, x, s, window, b, d, NaN, y, s, c, this.s, r = b, eval = this, s, r, \u3056, y, r, x, x, s) =>  { return x } )); ");
/*fuzzSeed-254361819*/count=497; tryItOut("mathy5 = (function(x, y) { return ( ! ( ! (Math.cbrt((Math.acosh((Math.fround((y | 0)) | 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-254361819*/count=498; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?=(?!\\b|(?=(?:[^])|.)))?)\\D|(?!(?:\\\u45b5\\s^+?|\\cI))*/gim; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=499; tryItOut("M:switch((({/*toXFun*/toString: function() { return this; } }))) { default: break; case 9: break;  }");
/*fuzzSeed-254361819*/count=500; tryItOut("v1 = (a1 instanceof this.f0);");
/*fuzzSeed-254361819*/count=501; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=502; tryItOut("\"use strict\"; ;");
/*fuzzSeed-254361819*/count=503; tryItOut("let z = ((function factorial(frbeif) { ; if (frbeif == 0) { ; return 1; } ; return frbeif * factorial(frbeif - 1);  })(1));s0 = '';");
/*fuzzSeed-254361819*/count=504; tryItOut("mathy2 = (function(x, y) { return Math.asinh((Math.fround(((Math.fround(( ! Math.fround(Math.max(Math.cosh(x), (Math.imul((y | 0), Math.tan(-0x0ffffffff)) | 0))))) | 0) > ( + mathy0(( + Math.fround((x == Math.tan(Math.log1p(((( + -0) >>> 0) | 0)))))), ( + ( + ( + Math.atan2((Math.cbrt(Math.fround(y)) >>> 0), ( + (mathy0((x >>> 0), (y >>> 0)) >>> 0)))))))))) >>> 0)); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 0x080000001, -(2**53+2), -1/0, 0x07fffffff, -0x080000000, 2**53-2, -(2**53), -0x100000001, Math.PI, 0x100000001, Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, 1, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 1/0, -0, Number.MAX_VALUE, 2**53, 0.000000000000001, 0x0ffffffff, -0x100000000, -0x07fffffff, -0x0ffffffff, 42, -0x080000001, 0, -(2**53-2)]); ");
/*fuzzSeed-254361819*/count=505; tryItOut("\"use strict\"; if((x % 3 == 2)) const v2 = null; else {e0.has( /x/ );v1 = g0.runOffThreadScript(); }");
/*fuzzSeed-254361819*/count=506; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 4.835703278458517e+24;\n    i0 = (!(/*FFI*/ff(((+((((d1)) - ((this.__defineGetter__(\"window\", x.setSeconds))))))), ((+(((0xf9a8c7ee)+(0xfd5b3b5b))>>>((0xffffffff))))), ((d1)))|0));\n    d1 = (+log(((-((9.671406556917033e+24))))));\n    d2 = (+((-((+(-1.0/0.0))))));\n    return ((((((i0)) >> ((i0)+((((0xa3d77ecc)+(0x1d7ad43e)) >> ((Int16ArrayView[4096]))) >= ((-(0x8dba3232))|0))+(!((~~(d2)))))))))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MAX_VALUE, 2**53+2, 0/0, -Number.MIN_VALUE, Math.PI, -(2**53), 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 2**53, 0x0ffffffff, 0x100000001, -1/0, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, 2**53-2, -0x100000000, 0x07fffffff, 0.000000000000001, 0x080000001, -0x07fffffff, 1, 0, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, -0x080000001, -0x100000001]); ");
/*fuzzSeed-254361819*/count=507; tryItOut("mathy3 = (function(x, y) { return (mathy2((Math.fround(Math.clz32(Math.fround(((((Math.sqrt(( + x)) >>> 0) + (y >>> 0)) >>> 0) * ( ~ ( + (((x >>> 0) < (0x07fffffff >>> 0)) | 0))))))) | 0), ((Math.ceil((Math.atan(( + -Number.MIN_VALUE)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, -(2**53), 1.7976931348623157e308, 2**53, 1/0, -Number.MAX_VALUE, 0x100000000, 0x080000001, -0x080000000, 0x100000001, 0x080000000, 2**53-2, Number.MIN_VALUE, -0x07fffffff, -0, -Number.MIN_VALUE, -(2**53+2), -0x100000000, 0, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, 2**53+2, 0.000000000000001, -0x100000001, Math.PI, 1, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-254361819*/count=508; tryItOut("/*tLoop*/for (let z of /*MARR*/[-(2**53+2), -(2**53+2)]) {  \"\" ; }");
/*fuzzSeed-254361819*/count=509; tryItOut("print(w);let w =  /x/ ;\n{a2[6];print(x); }\n");
/*fuzzSeed-254361819*/count=510; tryItOut("/*bLoop*/for (var yfonoz = 0; yfonoz < 32; ++yfonoz) { if (yfonoz % 2 == 0) { Object.defineProperty(this, \"v1\", { configurable: true, enumerable: (x % 35 == 30),  get: function() {  return g1.runOffThreadScript(); } });f2[-16] = (yield Math.atan2(27, 1099511627776)); } else { { void 0; void 0; } }  } ");
/*fuzzSeed-254361819*/count=511; tryItOut("this.f0 + o2.b2;");
/*fuzzSeed-254361819*/count=512; tryItOut("\"use strict\"; for(var [a, c] = d in this) /*MXX1*/o2 = g2.g2.Function.prototype.call;");
/*fuzzSeed-254361819*/count=513; tryItOut("new RegExp(\"[^]|(?=(\\\\b{4})){1,1}*\", \"gyim\");");
/*fuzzSeed-254361819*/count=514; tryItOut("\"use strict\"; { void 0; gcPreserveCode(); }\ne0 + o0.o2;\n");
/*fuzzSeed-254361819*/count=515; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = ((73786976294838210000.0) + (((+(0.0/0.0))) % ((-1.0078125))));\n    {\n      {\n        d0 = (d0);\n      }\n    }\n    return +((((d0)) / (((0xe0b12197) ? (+(0x2b96a01)) : (+atan2(((((+(1.0/0.0))) - ((+/*FFI*/ff(((1.0625))))))), ((+((-8388607.0))))))))));\n    d0 = (((d0)) * (((-35184372088832.0) + (+/*FFI*/ff(((yield c = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"\\\\1|.*\", \"gym\")), /(?:\\2)|(?=(?:^)\\W)/gyi, function (b) { yield \"\\uE755\" } ))), ((abs((((0xff3aac3c)) | ((0x7301db6a)-(0xb875eb78))))|0)))))));\n    i1 = (0x38ec7b66);\n    d0 = (-1.25);\n    d0 = (Infinity);\n    {\n      d0 = (d0);\n    }\n    d0 = (-1.0078125);\n    d0 = (d0);\n    i1 = (/*wrap3*/(function(){ \"use strict\"; var sisrso = x; ((1 for (x in [])))(); })((new (eval =  '' )(Math.atan(new ( /x/ )()))), x));\n    i1 = (0x8650fd25);\n    (Float32ArrayView[0]) = ((4095.0));\n    /*FFI*/ff(((+(0.0/0.0))), ((NaN)), (((-(0xdce240c5)) << ((/*FFI*/ff(((~~(4.722366482869645e+21))), ((36893488147419103000.0)), ((-17179869185.0)), ((-7.737125245533627e+25)), ((72057594037927940.0)))|0)-(!(0xffded721))))), ((-((d0)))), ((0x4e233d15)), ((d0)), ((Float32ArrayView[1])), ((-6.189700196426902e+26)));\n    return +((d0));\n  }\n  return f; })(this, {ff: --eval}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53, 0/0, -(2**53-2), -0x07fffffff, -0x100000000, -0, 0x080000000, -0x080000000, 0x080000001, 42, 0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, 2**53+2, Math.PI, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 0x100000001, 1.7976931348623157e308, 1, -1/0, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-254361819*/count=516; tryItOut("v2 = evalcx(\"function f1(g0.g2)  { return (4277) } \", g0.g2);");
/*fuzzSeed-254361819*/count=517; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.imul(Math.imul((y * ( + ( ! ( + (Math.max(( + ((( ! (x | 0)) | 0) ? (x | 0) : ( + x))), Math.sin(x)) >>> 0))))), (( + (y >>> 0)) >>> 0)), Math.acosh(Math.fround(Math.cbrt(Math.fround(x))))); }); ");
/*fuzzSeed-254361819*/count=518; tryItOut("");
/*fuzzSeed-254361819*/count=519; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.min((( + (Math.trunc(( + ((Math.trunc((Number.MAX_SAFE_INTEGER >>> 0)) << ( - x)) | 0))) >>> 0)) ? (Math.fround(((Math.hypot(x, (x >>> 0)) >>> 0) >>> 0)) >>> 0) : Math.min((Math.log1p(y) >>> 0), (Math.imul((Math.fround(2**53) <= Number.MAX_VALUE), x) | 0))), (Math.ceil(( - ( ! ((y , x) | 0)))) | 0)); }); testMathyFunction(mathy5, [true, '', 1, (new Number(-0)), '0', (new String('')), /0/, (new Number(0)), NaN, (function(){return 0;}), (new Boolean(false)), null, objectEmulatingUndefined(), '/0/', 0.1, ({valueOf:function(){return 0;}}), undefined, 0, -0, [0], (new Boolean(true)), [], '\\0', ({valueOf:function(){return '0';}}), false, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-254361819*/count=520; tryItOut("if( '' ) {print(x); }");
/*fuzzSeed-254361819*/count=521; tryItOut("mathy0 = (function(x, y) { return (Math.log10((Math.fround(Math.acos((( + ( ~ Math.ceil(Math.atan2(x, (x | 0))))) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[ '' , x != x =  /x/ , null, x != x =  /x/ ,  '' ,  /x/g ,  /x/g , null, x != x =  /x/ ,  \"use strict\" , null,  '' ,  /x/g , null,  /x/g ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  '' , null,  \"use strict\" , null,  /x/g ,  '' , null, null, x != x =  /x/ ,  '' , x != x =  /x/ ,  /x/g ,  /x/g ,  '' , null,  /x/g ,  '' ,  \"use strict\" ,  /x/g ,  '' ,  \"use strict\" ,  \"use strict\" ]); ");
/*fuzzSeed-254361819*/count=522; tryItOut("\"use strict\"; a0.__iterator__ = f1;");
/*fuzzSeed-254361819*/count=523; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( - Math.fround(( - (Math.pow((mathy2((( + ((Math.cbrt(Math.fround((Math.imul(y, (x >>> 0)) | 0))) >>> 0) ? (x | 0) : (Math.pow((x | 0), (x | 0)) | 0))) >>> 0), Math.hypot(Math.fround(y), y)) >>> 0), ( + ((((-Number.MIN_SAFE_INTEGER | 0) ? Math.sqrt((x >>> 0)) : y) | 0) != Math.fround((Math.pow((y | 0), (y | 0)) | 0))))) | 0)))); }); testMathyFunction(mathy5, [-0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, 0, 0/0, 0x100000001, 0x0ffffffff, 0x07fffffff, 1, Math.PI, -0x080000001, -(2**53+2), 2**53, Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, -1/0, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -0, 0x080000000, 2**53-2, -(2**53-2), -(2**53), -Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-254361819*/count=524; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ! ( + Math.pow(Math.atan2(Math.tan(( + Math.imul(0x100000000, ( + -0x07fffffff)))), 0x100000000), ( + ( + Math.hypot(Math.fround(x), 0x0ffffffff)))))) ** ( + Math.hypot(Math.log((( ! (((((y >>> 0) / 0x100000001) && (y >>> 0)) ? (0/0 | 0) : Math.imul(((y | 0) || ( + x)), x)) >>> 0)) | 0)), ( + Math.atan2(Math.asin((( + (y ^ x)) | 0)), ( + (( + y) ^ ( + y)))))))); }); testMathyFunction(mathy0, [2**53+2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, -0, 1/0, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 42, -1/0, 0x100000001, Number.MIN_VALUE, 2**53, 1.7976931348623157e308, -(2**53), -0x07fffffff, -0x080000000, 0, 0/0, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, 0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), Math.PI]); ");
/*fuzzSeed-254361819*/count=525; tryItOut("/*ADP-1*/Object.defineProperty(this.g0.a1, 2, ({value: (void shapeOf(([(void 0)]) -= w = /\\B{2}($)?|((?:(?:.))*?)/gyi))}));");
/*fuzzSeed-254361819*/count=526; tryItOut("v1 = Infinity;");
/*fuzzSeed-254361819*/count=527; tryItOut("mathy3 = (function(x, y) { return (((Math.fround(((Math.max(( - Math.fround((Math.fround(y) & Math.fround(( ! -Number.MIN_VALUE))))), ((( + Math.hypot(-0x07fffffff, x)) | y) >>> 0)) >>> 0) + (Math.atan2((x | 0), ( ~ ((mathy1((-0x100000001 >>> 0), (y >>> 0)) >>> 0) | 0))) | 0))) > ((Math.min((Math.atan2(x, -(2**53)) >>> 0), (2**53+2 >>> 0)) >>> 0) === Math.hypot((x >>> 0), Math.atan(Math.fround(-0x0ffffffff))))) | 0) ? Math.log(Math.atan2(Math.pow(y, Math.cbrt((( + ( - (y | 0))) / ( + (Math.fround(y) >>> -0x080000001))))), (x / ((Math.atan2((x >>> 0), Number.MIN_SAFE_INTEGER) >>> 0) | Math.tanh(x))))) : (Math.fround(Math.max(Math.fround((Math.imul(Math.fround(mathy1(y, y)), Math.fround(x)) < (y | 0))), Math.fround(Math.fround(Math.imul(Math.fround((Math.imul(x, x) | 0)), Math.fround(Math.atan2(x, ( - -(2**53-2))))))))) << mathy0(( + Math.tanh(( + x))), y))); }); testMathyFunction(mathy3, [2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, 0.000000000000001, 0x080000000, 42, 1.7976931348623157e308, 2**53-2, -0x080000000, 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), -(2**53), -0x100000000, 0x0ffffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, 0, 0x100000001, -0x100000001, 2**53, -0x0ffffffff, -1/0, Math.PI, 0x07fffffff, 1, 0/0]); ");
/*fuzzSeed-254361819*/count=528; tryItOut("v0 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-254361819*/count=529; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=530; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(v2, o2);");
/*fuzzSeed-254361819*/count=531; tryItOut("mathy2 = (function(x, y) { return ( ~ Math.fround((( - ( + Math.hypot(( + 1), (x > (( + x) ? ( + y) : x))))) | 0))); }); ");
/*fuzzSeed-254361819*/count=532; tryItOut("a2.push(i2, o0, p0, a0, f2, o2);");
/*fuzzSeed-254361819*/count=533; tryItOut("Array.prototype.shift.call(a0, v1);");
/*fuzzSeed-254361819*/count=534; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((((i0)+((((0xf8ed4e7f)+(0xc3112e14)-(0xff617545)) & ((0xffffffff)-(0xf9e0bb80)+(0xffffffff))) < (((0x3404010f)-(0x87c434da)) >> (/*UUV2*/(window.repeat = window.all))))) & ((Int16ArrayView[((imul((-0x8000000), (0xf9fbf071))|0) / (imul((0x40adb94a), (0x583e82a2))|0)) >> 1]))) == (((i0)) << ((((-0x545e4*(0xf892de95)) | ((i0))))-((0x33766da6) ? (0xfe269586) : ((((0xf9146ecd))>>>((0x81aab2c9))))))));\n    return +((d1));\n  }\n  return f; })(this, {ff: function  x (eval = x, []) { yield -9 } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53+2), 0x080000001, 0x07fffffff, 0, 1, -Number.MIN_VALUE, 0x0ffffffff, 2**53+2, Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, -0, 1/0, 2**53-2, -Number.MAX_VALUE, -0x100000000, -(2**53-2), 1.7976931348623157e308, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, -0x100000001, Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, -0x07fffffff, -0x080000000, -1/0, 0/0, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-254361819*/count=535; tryItOut("/* no regression tests found */\nfor (var v of o2.o1.s0) { g1 = t2[19]; }\n");
/*fuzzSeed-254361819*/count=536; tryItOut("testMathyFunction(mathy4, [-1/0, -Number.MIN_VALUE, 2**53+2, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, Math.PI, 0.000000000000001, -0x100000000, 2**53, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, 2**53-2, 0x100000000, 0x0ffffffff, 0x080000000, 42, 0/0, Number.MIN_VALUE, 1/0, -(2**53), -0x100000001, -(2**53-2), 0x100000001]); ");
/*fuzzSeed-254361819*/count=537; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[0/0, \"\\u3B7E\", 033, \"\\u07B3\", \"\\u3B7E\", 033, \"\\u3B7E\", \"\\u07B3\", \"\\u3B7E\", \"\\u3B7E\", 0/0]) { t1 = new Uint8Array(g2.b2, 16, ({valueOf: function() { s0 + '';return 13; }})); }");
/*fuzzSeed-254361819*/count=538; tryItOut("testMathyFunction(mathy4, [-0x07fffffff, 0x100000001, 1.7976931348623157e308, 0.000000000000001, -0x080000000, -1/0, 0/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -0x080000001, -Number.MAX_VALUE, 42, -(2**53), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -0x100000000, -0, 1/0, -(2**53+2), 0x0ffffffff, 2**53, 0x100000000, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, -0x100000001, 1, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=539; tryItOut("/*RXUB*/var r = /\\3\\b*?[\\s]/gim; var s = \"a\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=540; tryItOut("v1 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (void options('strict')), noScriptRval: (4277), sourceIsLazy: false, catchTermination: (x % 4 != 0), element: o0, elementAttributeName: this.s0, sourceMapURL: s2 }));");
/*fuzzSeed-254361819*/count=541; tryItOut("a1.push(a1, v0, o1.o1.g0);");
/*fuzzSeed-254361819*/count=542; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( ! ( + Math.cosh(Math.tan((( + (y >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [1/0, -0x080000001, -(2**53+2), 0x100000000, 0x07fffffff, -0x080000000, 0, 0/0, -0x100000000, 0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -1/0, 2**53+2, 0.000000000000001, 1, -0, 42, -Number.MAX_VALUE, -0x100000001, 0x080000000, 0x080000001, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, -(2**53)]); ");
/*fuzzSeed-254361819*/count=543; tryItOut("\"use strict\"; with(\u000cx *= [1]){throw  /x/ ;r2 = /[^]/gyi; }");
/*fuzzSeed-254361819*/count=544; tryItOut("Array.prototype.pop.call(o1.a1, h1);");
/*fuzzSeed-254361819*/count=545; tryItOut("s2.__proto__ = b0;");
/*fuzzSeed-254361819*/count=546; tryItOut("a0.reverse();");
/*fuzzSeed-254361819*/count=547; tryItOut("/*RXUB*/var r = /\\1/m; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=548; tryItOut("let (x) { function shapeyConstructor(offdht){{  \"\" ; } for (var ytqzfdfhu in this) { }if (((function factorial(tpxmor) { ; if (tpxmor == 0) { g1.__iterator__ = (function mcc_() { var cqoajm = 0; return function() { ++cqoajm; this.f2(/*ICCD*/cqoajm % 10 == 1);};})();; return 1; } ; return tpxmor * factorial(tpxmor - 1);  })(2))) for (var ytqkbakvo in this) { }for (var ytqxgxzpb in this) { }Object.freeze(this);{ Object.defineProperty(this, \"s2\", { configurable: [1,,], enumerable: new RegExp(\"((?=\\\\uF202[\\\\d\\u6bf3\\\\f-5\\\\d])|\\\\B?)|\\\\b(?:($){0,})\\\\2{3,}|(^)?(?!(?!\\\\B)[^]){3}\", \"gyi\"),  get: function() {  return Array.prototype.join.call(a0, s0, g0.g1.o2, p0, t0, p1, o1); } }); } return this; }/*tLoopC*/for (let d of /*FARR*/[.../*MARR*/[eval, eval, 0x100000000, 0x100000000], .../*MARR*/[objectEmulatingUndefined(), \"\u03a0\", objectEmulatingUndefined(), ['z'], \"\u03a0\", ['z'], ['z'], \"\u03a0\", ['z'], ['z'], ['z'], objectEmulatingUndefined(), \"\u03a0\", \"\u03a0\", ['z'], ['z'], ['z'], ['z'], \"\u03a0\", ['z'], objectEmulatingUndefined(), ['z'], ['z'], ['z'], \"\u03a0\", ['z'], ['z'], \"\u03a0\", ['z'], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ['z'], \"\u03a0\", ['z'], objectEmulatingUndefined(), \"\u03a0\", objectEmulatingUndefined(), objectEmulatingUndefined()], (Math.pow(-29,  \"\" )), , ((function factorial(mvbvch) { ; if (mvbvch == 0) { ; return 1; } ; return mvbvch * factorial(mvbvch - 1);  })(2))]) { try{let jesqdk = new shapeyConstructor(d); print('EETT'); return;}catch(e){print('TTEE ' + e); } } }");
/*fuzzSeed-254361819*/count=549; tryItOut("v0 = Object.prototype.isPrototypeOf.call(g0, t2);");
/*fuzzSeed-254361819*/count=550; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -36893488147419103000.0;\n    var i4 = 0;\n    return (((0x43865134) / (~~(+(-1.0/0.0)))))|0;\n  }\n  return f; })(this, {ff: function  b (x, w)(void options('strict_mode'))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x100000000, -Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, -(2**53-2), -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, -0x100000001, -(2**53+2), 0x100000001, -0x0ffffffff, 0x080000000, 1, 42, -Number.MIN_SAFE_INTEGER, 1/0, 2**53, Math.PI, -0, Number.MIN_VALUE, 0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, 1.7976931348623157e308, 0/0, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-254361819*/count=551; tryItOut("const x = ((c = (4277))), w;o1.a1 = Array.prototype.concat.apply(a2, [g1.t0, a0, g2, t1, i1]);");
/*fuzzSeed-254361819*/count=552; tryItOut("/*vLoop*/for (var svnuja = 0; svnuja < 112; ++svnuja) { let y = svnuja; g0.h0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 9223372036854776000.0;\n    return ((((new RegExp(\"\\\\3\", \"im\")) <= (+pow(((d0)), ((((-16385.0)) - ((d2)))))))-(0xf8f7f697)))|0;\n  }\n  return f; });m1.get(e0); } ");
/*fuzzSeed-254361819*/count=553; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.atan2(((Math.imul((Math.atan2(( + Math.fround(( ! Math.fround(x)))), y) | 0), (Math.atan2(( ~ y), Math.fround(Math.acosh(Math.fround(( ! Math.fround(mathy0(x, y))))))) | 0)) | 0) | 0), ((Math.clz32(mathy1(( ! 0x0ffffffff), y)) ** ((Math.atan2(( + 1.7976931348623157e308), Math.pow((Number.MIN_SAFE_INTEGER ? 2**53-2 : y), ( + x))) & Math.imul((Math.asin(( - y)) >>> 0), mathy1(( + ( ! y)), y))) | 0)) | 0))); }); testMathyFunction(mathy2, [-0x100000000, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, 1.7976931348623157e308, 2**53, -0x07fffffff, -(2**53-2), 0x100000000, -1/0, 2**53+2, Math.PI, 0x080000001, 0x100000001, -Number.MAX_VALUE, 0/0, 1, 0.000000000000001, -0x080000000, -0x0ffffffff, 0, -(2**53), 1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=554; tryItOut("o0.i1 + '';");
/*fuzzSeed-254361819*/count=555; tryItOut("s1 += 'x';");
/*fuzzSeed-254361819*/count=556; tryItOut("o0.v0 = Object.prototype.isPrototypeOf.call(v1, o0.g2.o0.h2);");
/*fuzzSeed-254361819*/count=557; tryItOut("o2.v1 = evalcx(\"/*oLoop*/for (var dfkpgz = 0, this; dfkpgz < 49; ++dfkpgz) { print(\\\"\\\\uA7CA\\\"); } Object.defineProperty(this, \\\"this.a2\\\", { configurable: true, enumerable: false,  get: function() {  return a1.slice(NaN, NaN); } });\", g2);");
/*fuzzSeed-254361819*/count=558; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.cbrt(Math.cosh(( + Math.pow((Math.imul(( + ((Math.fround(y) ? (x >>> 0) : ( + Math.round((x | 0)))) >>> 0)), ( + (( ! y) != y))) | 0), Math.atan2(Math.hypot((x >>> 0), (-0x100000001 | 0)), y))))) | 0); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 0, -0x100000001, 0/0, -0x0ffffffff, Math.PI, -0, 1.7976931348623157e308, 0x080000000, 2**53+2, 1/0, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 1, -(2**53+2), 2**53-2, -(2**53-2), -0x07fffffff, 0x080000001, Number.MIN_VALUE, 0x100000000, 0x100000001, 42, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-254361819*/count=559; tryItOut("for (var p in o1.t1) { try { v2 = r2.multiline; } catch(e0) { } this.i2.send(t2); }");
/*fuzzSeed-254361819*/count=560; tryItOut("m2.set(this.f1, t1);");
/*fuzzSeed-254361819*/count=561; tryItOut("do return  '' ; while((\"\\uCBE8\" %= window-=\"\\u0202\") && 0);");
/*fuzzSeed-254361819*/count=562; tryItOut("for(\u3056 = x in new (\u3056)(/(?=(?:\ub102+[^]|\\W(\\d)*?)(?:[\u00a5-\\uDA39\\D\\v-\\u6DCE\\b-\\x1C]))/yim)) {s2 += 'x';v1 + '';f0 + ''; }");
/*fuzzSeed-254361819*/count=563; tryItOut("t1 + v2;");
/*fuzzSeed-254361819*/count=564; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return Math.asinh(Math.imul(((y - ( - (-Number.MIN_VALUE && ( + Math.pow(( + 0x080000000), Math.fround(x)))))) | 0), ((-(2**53) ? ( + Math.min(x, y)) : ( + x)) | 0))); }); ");
/*fuzzSeed-254361819*/count=565; tryItOut("mathy5 = (function(x, y) { return Math.atan(Math.sinh((Math.sqrt(Math.atan2((Math.clz32(Math.hypot(y, Math.fround(x))) ? (y | 0) : mathy3(( + (Math.atan(y) | 0)), -Number.MIN_VALUE)), (Math.imul(mathy1(x, (x && x)), ( + (y ? ( + x) : ( + Math.fround(mathy4(y, x)))))) | 0))) >>> 0))); }); ");
/*fuzzSeed-254361819*/count=566; tryItOut("h0.getOwnPropertyDescriptor = o0.f2;");
/*fuzzSeed-254361819*/count=567; tryItOut("/*RXUB*/var r = new RegExp(\"(?![])\", \"\"); var s = \"2\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=568; tryItOut("delete a0[\"set\"];");
/*fuzzSeed-254361819*/count=569; tryItOut("\"use strict\"; testMathyFunction(mathy5, [(new String('')), NaN, (new Number(-0)), (function(){return 0;}), false, (new Boolean(true)), (new Number(0)), objectEmulatingUndefined(), 0, [0], 0.1, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '0', '/0/', [], /0/, '\\0', true, null, '', 1, undefined, -0, (new Boolean(false))]); ");
/*fuzzSeed-254361819*/count=570; tryItOut("mathy2 = (function(x, y) { return ((((( + (y ? ( + Math.imul(( + 0x100000000), ( + ( + mathy1(( + -0x07fffffff), (x >>> 0)))))) : Math.cosh(y))) >>> 0) != ( + Math.trunc((Math.imul(Math.max(y, y), 0x080000000) >>> 0)))) >>> 0) , ( + Math.tanh((Math.imul(Math.log10(Math.fround((Math.fround(x) !== Math.fround(( + (( + y) ? ( + y) : ( + y))))))), ( ~ y)) | 0)))); }); testMathyFunction(mathy2, [0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 2**53+2, 1/0, -(2**53-2), -Number.MIN_VALUE, 0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -0, 0x0ffffffff, 0x100000001, 2**53-2, 0/0, 2**53, -0x080000000, Number.MAX_VALUE, -0x080000001, 1, 0]); ");
/*fuzzSeed-254361819*/count=571; tryItOut("mathy3 = (function(x, y) { return (( + ( - ( + ( ~ Math.fround((Math.pow((x >>> 0), ((x / y) >>> 0)) >>> 0)))))) < Math.atan((Math.trunc((Math.tanh((( ! ( ! 2**53-2)) >>> 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-254361819*/count=572; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=573; tryItOut("let a = (4277)\n;/*RXUB*/var r = /\\b/m; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-254361819*/count=574; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 3.094850098213451e+26;\n    switch ((((-0x8000000)+(0xffffffff)) | (((0x5ebf1ec5))*0xb1ad))) {\n      case -2:\n        (Float32ArrayView[((0xffffffff)-((0xae25873))) >> 2]) = ((d0));\n        break;\n      case -3:\n        (Int32ArrayView[2]) = ((new encodeURIComponent()));\n      default:\n        d2 = (+pow(((((d1)) % ((d2)))), ((Float64ArrayView[((Uint16ArrayView[((0xffffffff)) >> 1])) >> 3]))));\n    }\n    switch (((((-2199023255552.0) <= (-562949953421312.0))-((0x7fffffff))) ^ ((0x2320fca)+(0xffffffff)+(0xa24e9f5a)))) {\n      case -2:\n        d0 = (+(1.0/0.0));\n        break;\n      case 0:\n        d0 = (+(1.0/0.0));\n        break;\n      case -1:\n        (Float32ArrayView[((0x683ba72c)+(0xf857ba1c)) >> 2]) = ((d0));\n        break;\n      case 0:\n        (Int16ArrayView[((Int16ArrayView[((0x7f0344c)-(0xa4667cdc)) >> 1])) >> 1]) = (-(0xeeaf192));\n        break;\n      case -1:\n        /*FFI*/ff(((((0xb2975a54)+(0x18f0fba)) ^ ((0x52ff7f44)))), ((d2)));\n        break;\n    }\n    d1 = (+(1.0/0.0));\n    {\n      return +((+(((-262145.0) + (NaN)))));\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var zooksu = new new RegExp(\"$^{2,}\", \"g\")(); var qsnelp = (let (e=eval) e); return qsnelp;})()}, new ArrayBuffer(4096)); ");
/*fuzzSeed-254361819*/count=575; tryItOut("m1.get(h0);");
/*fuzzSeed-254361819*/count=576; tryItOut("Array.prototype.forEach.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var asin = stdlib.Math.asin;\n  var Infinity = stdlib.Infinity;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -4097.0;\n    {\n      (Float32ArrayView[1]) = ((d1));\n    }\n    d0 = (+atan2(((+(0.0/0.0))), ((d0))));\n    {\n      d2 = ((0xaadb3da) ? (((+((Float32ArrayView[(((0x92b9ccea) <= (0x1a093b5a))) >> 2])))) % ((Float32ArrayView[((0x5247dd0b)+((0x86dc77b3) <= (0xffffffff))) >> 2]))) : (d0));\n    }\n    d1 = (d1);\n    d1 = (+atan2(((+(0x10589a81))), ((+asin(((d2)))))));\n    d1 = (((((+(((0xf830b939)-((-524289.0) >= (-576460752303423500.0))-(0xbab5eafa))>>>(((0xc1fc73a7) > (((0xdc65ba0e))>>>((-0x8000000)))))))) - ((d2)))) * ((Infinity)));\n    {\n      d2 = (Infinity);\n    }\n    d2 = (d1);\n    d2 = (Infinity);\n    return +((Infinity));\n    return +((+(((((0xcd2ff86f)*-0xa4ff0) ^ (((((0xfb77efef))>>>((0xa27a2761))) > (0xab017d8f)))) / (~~(Infinity))) & ((0x4da4344e)))));\n  }\n  return f; })]);");
/*fuzzSeed-254361819*/count=577; tryItOut("\"use strict\"; /*oLoop*/for (gfttoe = 0; gfttoe < 122; ++gfttoe) { Array.prototype.splice.apply(a2, [b0]); } ");
/*fuzzSeed-254361819*/count=578; tryItOut("mathy0 = (function(x, y) { return ( + Math.atanh(( + Math.fround((Math.fround(Math.fround((Math.fround((y >>> (( + (1/0 >>> 0)) >>> 0))) * Math.fround(Math.max(Math.fround(Math.fround(( - x))), ( + ( ~ ( + y)))))))) , Math.fround(Math.max((Math.tan(y) || Number.MIN_VALUE), Math.fround(Math.trunc((-Number.MIN_SAFE_INTEGER | 0)))))))))); }); testMathyFunction(mathy0, [0/0, 2**53-2, 2**53+2, -(2**53), 0x100000000, -0x080000000, 42, -(2**53-2), -0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0x080000000, Number.MIN_VALUE, -(2**53+2), 2**53, 1, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, Math.PI, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0x100000001, 0, 0x080000001, -0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-254361819*/count=579; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-254361819*/count=580; tryItOut("testMathyFunction(mathy1, [0x0ffffffff, 0, -0, -Number.MIN_VALUE, 0.000000000000001, 2**53, -0x100000001, Number.MAX_VALUE, -1/0, 0x100000001, Number.MIN_VALUE, -0x0ffffffff, 0x080000001, -(2**53+2), -(2**53-2), 2**53+2, 1, -Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), -0x080000001, 0/0, Math.PI, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, 42, 0x100000000]); ");
/*fuzzSeed-254361819*/count=581; tryItOut("testMathyFunction(mathy2, [null, '\\0', objectEmulatingUndefined(), 0, ({valueOf:function(){return '0';}}), '/0/', (new Boolean(false)), (function(){return 0;}), -0, false, '0', (new String('')), /0/, 0.1, 1, NaN, '', (new Number(0)), [0], ({toString:function(){return '0';}}), undefined, (new Number(-0)), [], ({valueOf:function(){return 0;}}), true, (new Boolean(true))]); ");
/*fuzzSeed-254361819*/count=582; tryItOut("");
/*fuzzSeed-254361819*/count=583; tryItOut("mathy5 = (function(x, y) { return (( - (( - ( + ( ! Math.fround(Math.fround(Math.min(Math.fround(x), Math.fround(Math.acos(x)))))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-254361819*/count=584; tryItOut("(void options('strict'));");
/*fuzzSeed-254361819*/count=585; tryItOut("mathy4 = (function(x, y) { return ( - (Math.fround(Math.fround(( + Math.atanh(Math.fround(y))))) >>> 0)); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 0x100000001, 2**53-2, -(2**53), -0, -0x080000001, 2**53+2, 0x080000001, 0/0, 0, 1, -0x100000000, Math.PI, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -0x080000000, 1/0, 2**53, 0x07fffffff, Number.MAX_VALUE, 0x080000000, -0x07fffffff, 42, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -(2**53-2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=586; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 3.094850098213451e+26;\n    d3 = (+/*FFI*/ff(((~((i2))))));\n    (Float32ArrayView[(-(0xffffffff)) >> 2]) = ((((+((-((590295810358705700000.0)))))) - ((+abs(((d0)))))));\n    return (((0xffffffff)))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0, 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 1, -0x080000000, 0x07fffffff, -Number.MIN_VALUE, -0x100000001, -0x100000000, 2**53-2, Number.MAX_VALUE, 2**53, -(2**53-2), 0x100000001, 1.7976931348623157e308, -0x080000001, -0x07fffffff, -0x0ffffffff, 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, -1/0, 1/0, -(2**53), -Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, 0x0ffffffff, 0.000000000000001, 42]); ");
/*fuzzSeed-254361819*/count=587; tryItOut("null;function x(...x)(4277)this.f2(this.v0);");
/*fuzzSeed-254361819*/count=588; tryItOut("m2.has(g0);");
/*fuzzSeed-254361819*/count=589; tryItOut("s0 += 'x';");
/*fuzzSeed-254361819*/count=590; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.pow((( ~ Math.fround(( + (( + ( - mathy0(0x080000000, x))) ? ( + (Math.fround((( ~ Math.imul(x, ((x | 0) ^ ( + 1)))) >>> 0)) >>> 0)) : ( + x))))) | 0), (mathy0(Math.fround(Math.imul((Math.asin((( - (x >>> 0)) >>> 0)) >>> 0), Math.atan2(( + -0x100000001), ( + (y ? x : mathy0(x, ( + x))))))), mathy0(Math.max(( + y), y), ( - (x + (( + Math.tan(( + -0x100000000))) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [2**53, -(2**53), -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, -(2**53+2), Math.PI, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 0, 0/0, 0.000000000000001, Number.MAX_VALUE, 0x080000000, 2**53+2, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000000, -(2**53-2), -0x080000000, 1/0, 42, -0x100000000, -0x080000001, -Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, -0x07fffffff, 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=591; tryItOut("g2.o0.v0 = Object.prototype.isPrototypeOf.call(f0, e2);");
/*fuzzSeed-254361819*/count=592; tryItOut("\"use strict\"; h2.has = f0;");
/*fuzzSeed-254361819*/count=593; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(( + Math.fround((( - ( ~ Math.max(( + Math.atan2((Math.fround(mathy2(y, Math.fround(y))) >>> 0), Math.fround(2**53))), (y > (y | 0))))) >>> 0)))); }); testMathyFunction(mathy4, [1, 0x07fffffff, 42, 0, 0x0ffffffff, Number.MAX_VALUE, -0x080000001, 1/0, 0x080000000, 0x100000001, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, 2**53, -0, 2**53-2, -(2**53-2), 2**53+2, -Number.MAX_VALUE, -(2**53), 1.7976931348623157e308, -1/0, 0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=594; tryItOut("/*oLoop*/for (var ombmgx = 0; ombmgx < 12; ++ombmgx, x) { ('fafafa'.replace(/a/g, {})\n); } ");
/*fuzzSeed-254361819*/count=595; tryItOut("for (var p in g0) { print(uneval(g0.b1)); }");
/*fuzzSeed-254361819*/count=596; tryItOut("let khzrkq, jtfsdc;(false);");
/*fuzzSeed-254361819*/count=597; tryItOut("a1.pop();");
/*fuzzSeed-254361819*/count=598; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return ( + Math.hypot(((( + Math.max(x, ( + (mathy0(((Math.exp(y) < (Math.pow(x, (y | 0)) | 0)) >>> 0), (Math.log10(x) ? mathy1((x | 0), (y >>> 0)) : (x / Math.fround((Math.fround(y) ? x : x))))) >>> 0)))) >= (( + mathy1(( + x), x)) | Math.hypot(x, (Math.sinh(x) | 0)))) >>> 0), ( ! ((Math.cos((( - y) >>> 0)) >>> 0) << (( - Math.min(-Number.MIN_SAFE_INTEGER, x)) >>> 0))))); }); ");
/*fuzzSeed-254361819*/count=599; tryItOut("\"use strict\"; /*hhh*/function bmxsaa(NaN, x, -7, b, x = (new window(/(?:(?=\\w).|.(?:\\b)\u00b9|[^]\\b*?)+/gym)), x = this, eval, x, x, x){m1.has(g0);}/*iii*//* no regression tests found */");
/*fuzzSeed-254361819*/count=600; tryItOut("let(b) { ( '' );}throw StopIteration;");
/*fuzzSeed-254361819*/count=601; tryItOut("o2.a1.push();var y =  /* Comment *//*UUV1*/(eval.getOwnPropertyDescriptor = decodeURIComponent);");
/*fuzzSeed-254361819*/count=602; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(s0, \"__count__\", ({get: decodeURIComponent, set: encodeURIComponent, configurable: (uneval(7)), enumerable: true}));");
/*fuzzSeed-254361819*/count=603; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = \"__\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=604; tryItOut("\"use strict\"; ");
/*fuzzSeed-254361819*/count=605; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.log2(Math.fround(mathy0(mathy1((Math.max((( ~ x) | 0), (( + (( + y) - ( + (( + y) ? ( + x) : ( + x))))) | 0)) >>> 0), ((( + y) === (x | 0)) | 0)), Math.pow((Math.pow(x, ( + ((( + y) && (x >>> 0)) >>> 0))) | 0), (((Math.max(( + x), ( + y)) >>> 0) * ((Math.asinh((mathy0(2**53-2, y) | 0)) | 0) | 0)) | 0))))) | 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, 0/0, 2**53+2, 0x07fffffff, -0x080000001, 1, -0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0, -(2**53), -0x0ffffffff, 0, 0x100000000, -1/0, 42, 2**53, -(2**53+2), -0x100000001, 0x080000000, Number.MIN_VALUE, 0x080000001, 0x100000001, -0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=606; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(( + mathy1(( + Math.pow(( + mathy0(( + y), ( + (( ~ (Math.tanh((mathy1((x >>> 0), Math.fround(y)) >>> 0)) >>> 0)) | 0)))), (Math.imul((Math.sqrt((mathy1((y >>> 0), (-1/0 >>> 0)) >>> 0)) | 0), (mathy0(( + y), (Math.hypot((( + (( + y) <= Number.MAX_VALUE)) | 0), (0/0 >>> 0)) >>> 0)) | 0)) | 0))), ( + (((Math.min((Math.atan(y) | 0), (x | 0)) | 0) | 0) > ((Math.fround((Math.fround((Math.fround(y) / Math.fround((( + (-1/0 << y)) >>> 0)))) >>> 0)) >>> 0) | 0))))), (Math.fround(( + Math.fround(Math.max(Math.fround((Math.fround((y || ((-0x07fffffff >>> 0) || y))) + y)), Math.log(x))))) | 0)) | 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, 0x100000001, 0.000000000000001, -Number.MAX_VALUE, -0, -0x080000001, -0x100000000, 1, 2**53, Number.MIN_VALUE, 0x080000001, 2**53-2, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -0x07fffffff, -0x100000001, 0, 0x100000000, 2**53+2, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53-2), 0/0, -1/0, 42, -(2**53+2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-254361819*/count=607; tryItOut("/*infloop*/for(var z; (4277); ((Float32Array).call(x, x))) for (var v of s1) { try { i1 + g0; } catch(e0) { } Array.prototype.unshift.apply(a1, [x, (void options('strict'))]); }");
/*fuzzSeed-254361819*/count=608; tryItOut("switch( \"\" ) { case 3: break;  }");
/*fuzzSeed-254361819*/count=609; tryItOut("\"use strict\"; ");
/*fuzzSeed-254361819*/count=610; tryItOut("L:for(let b in ((decodeURIComponent)( \"\" )))s2 + '';function w()x-19;");
/*fuzzSeed-254361819*/count=611; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return Math.fround(mathy0((Math.log10((((Math.fround((( + Math.fround(Math.min(x, Math.fround(Math.fround((Math.fround(mathy0(y, y)) && (y | 0))))))) / Math.tanh((x | 0)))) >>> 0) + (( + (Math.hypot(Math.fround(y), (x | 0)) | 0)) >>> 0)) >>> 0)) >>> 0), Math.imul(Math.exp(Math.fround(mathy0(Math.fround(y), Math.fround((-0x07fffffff < y))))), ( + (( + y) ** Math.clz32(mathy0(Math.acosh(Math.fround(x)), y))))))); }); testMathyFunction(mathy1, [1, -Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, 2**53-2, -(2**53+2), -0x080000001, 0, Number.MIN_VALUE, 0x080000001, 2**53, -(2**53-2), -0x0ffffffff, -0, -0x080000000, -1/0, 0x100000000, 0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x080000000, 42, Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, 0/0, 0x100000001, Math.PI]); ");
/*fuzzSeed-254361819*/count=612; tryItOut("\"use asm\"; v2 = evaluate(\"v2 = new Number(g2.t2);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 0), noScriptRval: (4277), sourceIsLazy: true, catchTermination: (x % 49 != 0), elementAttributeName: s1 }));");
/*fuzzSeed-254361819*/count=613; tryItOut("/*RXUB*/var r = /\\2|(?:(?![^]|\\B|(?:(?:\u52a7){1,3})?))(?:(?:.)*?)+?/i; var s = \"_\"; print(s.replace(r, ({s: [[1]]}))); ");
/*fuzzSeed-254361819*/count=614; tryItOut("testMathyFunction(mathy2, [-(2**53), 0x080000001, 0x100000000, 0x080000000, -0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), -0, 0x100000001, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, 1, -1/0, 0.000000000000001, -0x100000001, -0x100000000, Number.MIN_VALUE, 42, Number.MAX_VALUE, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 0x0ffffffff, Math.PI, 1.7976931348623157e308, 0, 2**53, -Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=615; tryItOut("\"use strict\"; a0.pop(i0, \u3056 **= x);");
/*fuzzSeed-254361819*/count=616; tryItOut("testMathyFunction(mathy2, [0x080000000, 0/0, 42, 2**53, 0x080000001, -0x100000000, -(2**53), 2**53+2, -0x100000001, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff, Math.PI, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 1, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, -(2**53-2), 1.7976931348623157e308, 0x07fffffff, -0x080000000, 0x0ffffffff, 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-254361819*/count=617; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = \"\\n\\n\\n\\ud34a\\ny\\n\\n\\n\\n 1\\n\\n\\n\\n\\n\\n 1\\n\\n\\n\\n\\n\\n 1\\n\\n\\n\\n\\n\\n 1\\n\\n\\n\\n\\n\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=618; tryItOut("h1.__iterator__ = (function(j) { f0(j); });");
/*fuzzSeed-254361819*/count=619; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (/*FFI*/ff((()), ((70368744177664.0)))|0);\n    }\n    return +((((1025.0)) / ((1.2089258196146292e+24))));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/ , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/ , function(){}, function(){}, function(){}, function(){}, function(){},  /x/ ,  /x/ , function(){}, function(){}, function(){}, function(){},  /x/ , function(){},  /x/ , function(){},  /x/ , function(){},  /x/ ,  /x/ ,  /x/ , function(){},  /x/ ,  /x/ ]); ");
/*fuzzSeed-254361819*/count=620; tryItOut("testMathyFunction(mathy4, [-0x080000001, Number.MIN_VALUE, -(2**53), -1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 1, 2**53+2, -(2**53+2), 0x080000000, -0x0ffffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, 1/0, 0x100000000, 0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, 42, -0x080000000, -Number.MIN_SAFE_INTEGER, -0, -(2**53-2), -0x100000000, Number.MAX_VALUE, Math.PI, 0, 1.7976931348623157e308, 0x100000001, 0x080000001, -Number.MAX_VALUE, 2**53-2, 0x07fffffff]); ");
/*fuzzSeed-254361819*/count=621; tryItOut("for(let y in new Array(-15)) with({}) { try { with({}) with({}) return; } catch(a) { for (var p in s2) { v1 = g1.runOffThreadScript(); } }  } window.name;");
/*fuzzSeed-254361819*/count=622; tryItOut("\"use strict\"; /*vLoop*/for (var flbjbf = 0; flbjbf < 1; ++flbjbf) { const y = flbjbf; i2 = m1.values; } ");
/*fuzzSeed-254361819*/count=623; tryItOut("print(x);");
/*fuzzSeed-254361819*/count=624; tryItOut("var v2 = b0.byteLength;");
/*fuzzSeed-254361819*/count=625; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return ( + (( + (( + (Math.ceil(( + x)) >>> 0)) ** (Math.fround(Math.exp(Math.fround(x))) % Math.cos(y)))) ^ (( ~ ( ~ 0)) | 0))); }); testMathyFunction(mathy1, ['', 0, null, (new Boolean(true)), (new Number(-0)), /0/, 1, false, '0', NaN, (new Number(0)), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (function(){return 0;}), ({valueOf:function(){return '0';}}), -0, ({toString:function(){return '0';}}), undefined, '\\0', [0], (new Boolean(false)), [], (new String('')), true, 0.1, '/0/']); ");
/*fuzzSeed-254361819*/count=626; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(s1, h0);");
/*fuzzSeed-254361819*/count=627; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?!(?=$|${2,5}*?){4,}))\\t|(?=.)\\B/i; var s = \"\\u0009\"; print(s.match(r)); ");
/*fuzzSeed-254361819*/count=628; tryItOut("mathy5 = (function(x, y) { return Math.acosh((( + Math.atan2(Math.fround(( - Math.atan2(2**53+2, x))), ( + (y != x)))) | 0)); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x080000001, -(2**53-2), 2**53-2, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, 2**53, -0x07fffffff, -0, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, 1/0, Number.MIN_VALUE, 0x07fffffff, -(2**53+2), 0, 42, -0x080000000, 0/0, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, Number.MAX_VALUE, -(2**53), -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI]); ");
/*fuzzSeed-254361819*/count=629; tryItOut("this.e1.delete(b0);v0 = o1.f1[\"x\"];");
/*fuzzSeed-254361819*/count=630; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (mathy0(( + (y ? (y ? ( ~ 2**53-2) : ( + (Math.atan((y | 0)) | 0))) : x)), (Math.imul((Math.max(y, x) | 0), (Math.fround(Math.pow(y, Math.fround(-0x080000001))) | 0)) | 0)) <= Math.pow(Math.fround(( - Math.trunc(Math.fround(Math.min(x, x))))), Math.atan2((Math.max((Math.fround((0 | 0)) | 0), ((x << y) | 0)) | 0), Math.PI)))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), 0x080000000, -(2**53+2), 42, -0, -0x100000001, 1, 2**53-2, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, -0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, Number.MIN_VALUE, 0x100000001, 0x0ffffffff, 2**53, -0x0ffffffff, 1.7976931348623157e308, Math.PI, -(2**53), -0x100000000, 0]); ");
/*fuzzSeed-254361819*/count=631; tryItOut("\"use strict\"; /*bLoop*/for (fralvs = 0; fralvs < 43; ++fralvs) { if (fralvs % 4 == 1) { for (var v of o1.i0) { try { g1.offThreadCompileScript(\"\"); } catch(e0) { } Array.prototype.pop.call(a1); } } else { v1 = evalcx(\"function g0.f2(o1)  { \\\"use strict\\\"; a0[8]; } \", g0); }  } ");
/*fuzzSeed-254361819*/count=632; tryItOut("s1 += s1;\no1 + a2;\n");
/*fuzzSeed-254361819*/count=633; tryItOut("\"use strict\"; t1[16];");
/*fuzzSeed-254361819*/count=634; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(mathy0((Math.imul((mathy0((( - 2**53-2) | 0), ((Math.pow((Number.MAX_VALUE >>> 0), (y >>> 0)) >>> 0) | 0)) | 0), (mathy1(( + Math.sqrt(Math.log10(y))), ( + ( + ( ! (Math.hypot(y, ((((x | 0) || ((Math.atanh(-(2**53)) >>> 0) | 0)) | 0) | 0)) | 0))))) >>> 0)) >>> 0), Math.fround((( + ((( ! ( ~ (( ~ ( + ( - y))) | 0))) | 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 0, 2**53-2, -Number.MIN_VALUE, 1/0, 2**53, 0x080000000, 1.7976931348623157e308, 0x080000001, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -0x080000000, 0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), -0, 0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0x100000001, -(2**53), -0x100000000, 0/0, 1, Math.PI, 2**53+2, 42, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=635; tryItOut("/*RXUB*/var r = g2.r1; var s = s2; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=636; tryItOut("o0.v2 = evalcx(\"throw e;let(z) ((function(){(Object.defineProperty(x, \\\"__parent__\\\", ({value: 1.7976931348623157e308, writable: true, enumerable: (x % 87 == 81)})));})());\", g2);");
/*fuzzSeed-254361819*/count=637; tryItOut("t0.toString = f0;");
/*fuzzSeed-254361819*/count=638; tryItOut("v1 = evalcx(\"this.v1 = a2.reduce, reduceRight((function(j) { f2(j); }), e2, h2);\", g1);");
/*fuzzSeed-254361819*/count=639; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.expm1(( + Math.atan2(( + Math.fround(Math.log(( - x)))), ( + ((Math.log2(y) | 0) | (Math.fround((x ? y : y)) | ( + ( ! Math.min(y, y))))))))); }); testMathyFunction(mathy0, [0, ({valueOf:function(){return '0';}}), false, null, '\\0', '/0/', NaN, (new Boolean(true)), (function(){return 0;}), 0.1, undefined, '0', (new String('')), [], 1, -0, /0/, (new Number(-0)), [0], true, (new Boolean(false)), objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new Number(0)), ({valueOf:function(){return 0;}}), '']); ");
/*fuzzSeed-254361819*/count=640; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(((Math.pow(Math.max(((Math.fround((Math.fround((1 + ( + y))) * Number.MIN_VALUE)) >> Math.fround(Math.max((x >= Math.asinh(( + x))), ((Math.imul(( ! x), (( ! x) | 0)) | 0) >>> 0)))) | 0), (Math.exp(((Math.pow((x >>> 0), (Math.hypot(1, x) >>> 0)) >>> 0) >>> 0)) >>> 0)), Math.max(-0x07fffffff, mathy0((-0x080000001 >>> 0), (x >>> 0)))) | 0) * Math.fround((( ~ ((Math.max((( + ( ! 0x100000000)) | 0), y) !== ( + ( - ( + Math.hypot(Math.fround(Math.min(( + Math.fround(Math.atan2(Math.fround(-0x07fffffff), 1/0))), ( + x))), y))))) | 0)) | 0)))); }); ");
/*fuzzSeed-254361819*/count=641; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2/m; var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=642; tryItOut("g0.e0.delete(m0);");
/*fuzzSeed-254361819*/count=643; tryItOut("\"use strict\"; t1.toString = f1;");
/*fuzzSeed-254361819*/count=644; tryItOut("Array.prototype.splice.apply(a0, [3, ({valueOf: function() { /*infloop*/L:for(let a in new ((/*MARR*/[new Boolean(true), new String(''), NaN, (-1/0), (-1/0), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), new String(''), new Boolean(true), (-1/0), (-1/0), objectEmulatingUndefined(), new Boolean(true), (-1/0), new Boolean(true), NaN, new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), NaN, new String(''), new String(''), new String(''), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new String(''), NaN, new String(''), new Boolean(true), NaN, new Boolean(true), NaN, NaN, objectEmulatingUndefined(), (-1/0), NaN, objectEmulatingUndefined(), NaN, NaN, new String(''), (-1/0), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new String(''), new String(''), (-1/0), new Boolean(true), objectEmulatingUndefined(), new String(''), new String(''), (-1/0), new Boolean(true), NaN, objectEmulatingUndefined(), NaN, new Boolean(true), NaN].sort(WeakMap.prototype.get, \"\\u0F5B\")().unwatch(\"getMonth\"))((Math.exp(((( + ( - ( - (0x07fffffff >>> 0)))) * x) >>> 0)))))((Date.prototype.setMilliseconds).call(typeof Math.hypot(14, 0), new ((makeFinalizeObserver('nursery')))(x, \"\\uC4B5\"), (4277)), x)) (void schedulegc(g1));return 8; }})]);");
/*fuzzSeed-254361819*/count=645; tryItOut("\"use strict\"; a1 = Array.prototype.map.apply(a2, [(function() { i2.send(b2); return a2; })]);");
/*fuzzSeed-254361819*/count=646; tryItOut("a1.sort((function() { s0 + ''; return v1; }), g2.o1.s0);function d((function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var cos = stdlib.Math.cos;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 8589934593.0;\n    d2 = (((0xff3f49a2) ? (0xfd87cc00) : (i0)) ? (+((((-0x8000000) ? ((0x133072ac)) : ((0x1a4e1b99)))) | (0xbfe7e*((((0x6de114f9)) ^ ((0x751b9801))) != (imul((0xfbe57eea), (-0x8000000))|0))))) : (+abs(((+/*FFI*/ff((((0xfe45ed0e) ? (8388609.0) : (d2))), ((36028797018963970.0)), ((((d2)) - ((({window: (4277)}))))), ((590295810358705700000.0)), ((((0xfca9fe02)) << ((0xfb3d9cd8))))))))));\n    d1 = (d1);\n    d1 = (+abs(((d2))));\n    {\n      {\n        i0 = (!(0x134b4a0));\n      }\n    }\n    d2 = (((1.0625)) % ((2097153.0)));\n    {\n      d1 = (((-18014398509481984.0)) / (({\"15\": \"\\u5B95\", \"0\": new RegExp(\"(?:\\\\S\\u5730|\\\\B+?[^\\\\u04F0-\\\\0\\\\xc9-\\u0622]{2}){4,}(?!\\\\s)(?:\\\\b|[^]|\\\\b).|$\", \"gyim\") }).yoyo( /x/g )));\n    }\n    switch (((((0xfad8821d) ? (0xf9e14fdd) : (0xc708062a))) << ((0xfc00098a) / (0xbce640c0)))) {\n    }\n    (Float64ArrayView[1]) = ((Infinity));\n    return ((((~((((0xfded1cbf)-(0x221a9bdc))>>>((-0x8000000)+(0xff0b0f8a))) % ((-(i0))>>>(((Float64ArrayView[((0xfbe77959)) >> 3]))-((0xe49413ae) > (0x1be21c71)))))) > ( \"\" ))))|0;\n    d2 = (((+cos(((-18446744073709552000.0))))) / ((+(0x0))));\n    return (((Uint32ArrayView[((/*FFI*/ff(((((((1152921504606847000.0) + (4294967297.0)) != (-7.737125245533627e+25))*-0xcdc9e) ^ ((Math.abs(x) >>> 0)))), ((((Math.abs(-5))) & ((0x0) / (((0x8895abcb))>>>((0x7b11c8bc)))))))|0)) >> 2])))|0;\n  }\n  return f; })(this, {ff: DataView.prototype.getInt8}, new SharedArrayBuffer(4096)), x = x, y = ((function sum_slicing(yewufc) { ; return yewufc.length == 0 ? 0 : yewufc[0] + sum_slicing(yewufc.slice(1)); })(/*MARR*/[function(){}, false, function(){}, false, function(){}, function(){}, function(){}, false, function(){}, false, false, function(){}, function(){}, function(){}, false, function(){}, function(){}, false, false, false, false, false, false, false, false])), [], y, b, x, x, x, NaN, window, e, e, eval, b, y, c, eval, x, x, window, x, x, 1, x, y, x = \"\\uBA41\", a, x, d, a, window, window, w, x, e, eval = /\\1\\d+|(?=[\\u0054\\cW]){0,}|\\s|^{4,}|(?:.\\B*)|(?=(\\3))/gm, x = ({a1:1}), x = undefined, x = undefined, \u3056, x, window = [z1,,], c, x, w, \u3056, z, window, x, x, window, let, x, x, \u3056, x = [,], z, x = x, \"-22\", eval, x = a, y, eval, c, NaN, x = 11, x, x, x, \u3056, x, NaN, x, d, b, eval, \u3056, \"\\uF51F\", a, \u3056, eval, x, eval, x, x = (function ([y]) { })(), x =  /x/g , w, this.z, x = [], x = /(?![^\ud317-\ud8de\\cW\\u6f0a-\\cZg])/i, eval, x, name, z, d, getter = ({a2:z2}), x =  /x/g , w, ...z) { \"use asm\"; return x.yoyo(((arguments[\"\\uCAFC\"])) = (4277)) } a2.shift();");
/*fuzzSeed-254361819*/count=647; tryItOut("mathy2 = (function(x, y) { return mathy1(Math.fround(( + Math.fround((( + (-(2**53+2) >>> 0)) >>> 0)))), ( + ( + (((( ~ ( + Math.acos(-(2**53)))) | 0) >= ( + (( + x) <= ( + y)))) | 0)))); }); testMathyFunction(mathy2, [-0, '0', (function(){return 0;}), true, [], undefined, ({valueOf:function(){return 0;}}), (new Number(-0)), '', ({toString:function(){return '0';}}), (new Boolean(false)), NaN, null, (new String('')), objectEmulatingUndefined(), (new Boolean(true)), 1, 0.1, [0], (new Number(0)), /0/, '\\0', false, '/0/', 0, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-254361819*/count=648; tryItOut("/*RXUB*/var r = /\\2/yim; var s = \"_\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=649; tryItOut("\"use strict\"; v1 = t2.length;print(g1);");
/*fuzzSeed-254361819*/count=650; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.log10(( + ( + ( + Math.min(( ! ( + ( + ( + ( ! ( + x)))))), ( + ( + ( + Math.pow(( + ( - 0x080000001)), -(2**53)))))))))); }); testMathyFunction(mathy5, /*MARR*/[function(){}, (1/0), function(){}, function(){}, function(){}, (1/0), (1/0)]); ");
/*fuzzSeed-254361819*/count=651; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    {\n      d1 = ((objectEmulatingUndefined).call(this, new RegExp(\"(?=(?!(?!\\\\1)))|(?:\\\\b)|\\\\1\\\\3+\", \"gym\")));\n    }\n    d1 = (d1);\n    (Int16ArrayView[((/*FFI*/ff(((+(((0xfdeb4c4c)) >> ((0xd44fef38))))), ((-4097.0)), ((d1)), ((-32769.0)), ((-4.835703278458517e+24)), ((281474976710657.0)))|0)+(i0)-(!(0xfeb926d7))) >> 1]) = ((0xfa4249f1));\n    d1 = (+(((((d1) + (((d1)) % ((+/*FFI*/ff(((imul(((0x2d2cc849) != (0x7594f5ea)), ((0xffffffff) ? (0xb06b21a4) : (0xfe52623e)))|0)), ((((0xa80a1695)-(0xb5eac06c)) << ((i0)))), ((+(((0x2cbdc060))>>>((0xfa9b0369))))), ((-6.189700196426902e+26)))))))))));\n    return +((d1));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [1, -1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, -0x100000001, -0x100000000, 1/0, Number.MAX_VALUE, 0, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 0.000000000000001, -0x080000001, 1.7976931348623157e308, 0x100000000, -(2**53-2), Math.PI, 0x100000001, 0/0, -0x080000000, 0x080000001, 2**53-2, 0x07fffffff, -0x0ffffffff, 2**53+2, Number.MIN_VALUE, 0x0ffffffff, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=652; tryItOut("for (var v of s2) { try { v0 = t0.byteOffset; } catch(e0) { } /*RXUB*/var r = r2; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex);  }");
/*fuzzSeed-254361819*/count=653; tryItOut("/*RXUB*/var r = new RegExp(\"[^\\u6428\\ub749\\\\\\u09a1\\\\s]\", \"gyi\"); var s = \"_\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=654; tryItOut("/*infloop*/ for  each(var e in x) print(x);");
/*fuzzSeed-254361819*/count=655; tryItOut("\"use strict\"; print(x);g2.s0 += 'x';");
/*fuzzSeed-254361819*/count=656; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var exp = stdlib.Math.exp;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = -4096.0;\n    {\n      i4 = (0x1c36e72a);\n    }\n    i4 = (i4);\n    d1 = (+abs((((eval(\" /x/ .yoyo(x)\")) ? (d1) : (d0)))));\n    (Float32ArrayView[0]) = ((d5));\n    (Int8ArrayView[(((i3))+(0xb61bd567)) >> 0]) = ((0xfcf97ee3)-((-5.0) == (((((-(((-1.2089258196146292e+24) + (-147573952589676410000.0))))) / ((+abs(((+(0.0/0.0)))))))) / ((+(0.0/0.0))))));\n    {\n      return (((((i4))>>>((i3)*-0x558ba)) % ((-0xc82d0*(0xfd14fd11))>>>((i3)-(0xf8cebf3f)))))|0;\n    }\n    i4 = (i3);\n    (Int16ArrayView[1]) = ((0x236fc1ef)*-0x9e098);\n    i3 = (i3);\n    i2 = (0xb6ee3b68);\n    (Uint16ArrayView[((0x48ae603) % (0x581ee873)) >> 1]) = ((0xf828ffee)+(i2));\n    d1 = (Infinity);\n    i3 = ((((0xac4fbffb))>>>((0x23eb82e8) % (((Uint8ArrayView[((0x7ce8d92d)) >> 0])) & (((0x3c133426) >= (0x3ba8be6f))+((0x697fe190) == (0x75f2bb64)))))) >= ((((0x0))-(0x528adc1d))>>>((/*FFI*/ff(((+exp(((Float32ArrayView[1]))))), ((((0xfc57edb1)-(0xfb284cbc)) ^ ((0x5b10d94c)*-0x564ed))))|0)*-0xfffff)));\n    i3 = ((0x8e584c43));\n    {\n      i2 = ((((((0xe0fcd*(i4)) | (((((0xcba530cb))>>>((0xfc267015))))-((+(((0xf8b16ce2))>>>((-0x8000000)))))))))>>>((0xfd0627f4))) >= (((0x25eec927) / (0x249b0af6))>>>((i4)+(i2)+((+(-1.0/0.0)) > (-((d1)))))));\n    }\n    {\n      i4 = (i2);\n    }\n    return (((i2)+(0xfa5178f3)+(i3)))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var ojqmur = this; (function(y) { return (z = Proxy.createFunction(({/*TOODEEP*/})(/(?!(\\b)|.)|.*?$*+/gi), c =>  { yield [1] } )) })(); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-254361819*/count=657; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( ! (( + ( - (Math.hypot(Math.fround(x), Math.fround(Math.log10(Math.cosh(((( + (y | 0)) | 0) ^ -Number.MAX_SAFE_INTEGER))))) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-254361819*/count=658; tryItOut("\"use strict\"; const v2 = evaluate(\"x\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (Math.cbrt(-27)), noScriptRval: false, sourceIsLazy: false, catchTermination: ({name: 22.watch(\"\\u5C57\", Math) }) }));");
/*fuzzSeed-254361819*/count=659; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[new String('q'), new String('q'), -Infinity, -Infinity, objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), -Infinity, -Infinity, -Infinity, new String('q'), -Infinity, -Infinity, new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity]); ");
/*fuzzSeed-254361819*/count=660; tryItOut("for(var w in ((Function)(((function factorial(rbshfg) { ; if (rbshfg == 0) { ;; return 1; } ; return rbshfg * factorial(rbshfg - 1);  })(37872))))){Array.prototype.sort.call(a0, (function() { try { o1.__proto__ = m0; } catch(e0) { } try { v0 = r2.exec; } catch(e1) { } try { t1[9] = t1; } catch(e2) { } a2.sort((function() { try { for (var p in g2) { try { v0 = a2.length; } catch(e0) { } try { o1.s1 += s2; } catch(e1) { } o0.e0 + v2; } } catch(e0) { } try { v2.__proto__ = t1; } catch(e1) { } try { v0 = g1.p1; } catch(e2) { } g1.offThreadCompileScript(\"[[]]\"); return g2; }), p0, e0, o0.i0); return g2; }));a1.pop(a2, s0); }");
/*fuzzSeed-254361819*/count=661; tryItOut("\"use strict\"; for (var v of f0) { try { for (var v of a2) { this.o0.v2 = a0.reduce, reduceRight((function() { try { g2.m1 = new Map; } catch(e0) { } ; return v2; }), p1); } } catch(e0) { } try { t1[10] = this.h1; } catch(e1) { } Array.prototype.reverse.call(a0, s0); }");
/*fuzzSeed-254361819*/count=662; tryItOut("\"use strict\"; ");
/*fuzzSeed-254361819*/count=663; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o0, t0);");
/*fuzzSeed-254361819*/count=664; tryItOut("\"use asm\"; i2.__proto__ = b2;function \u3056(x, z =  '' , b, x, x, d = window, x, x, x, d, x, b, e, x)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+(0.0/0.0)));\n  }\n  return f; /x/g ;");
/*fuzzSeed-254361819*/count=665; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 134217729.0;\n    {\n      i0 = (0xfeca1de0);\n    }\n    i1 = ((((i0) ? (i1) : (i1)) ? (0xf8525744) : (i0)) ? ((~~(65537.0))) : ((+sin(((((d2)) / ((d2)))))) == (((147573952589676410000.0)) * ((Float32ArrayView[4096])))));\n    i1 = (!(i1));\n    return +((((Float32ArrayView[2])) - ((+(-1.0/0.0)))));\n  }\n  return f; })(this, {ff: mathy4}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53-2), 1.7976931348623157e308, 0x100000001, 0, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, -Number.MIN_VALUE, 0x0ffffffff, 42, 1, 2**53, -(2**53), -1/0, -0x100000000, 2**53-2, -0x080000001, Math.PI, 0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0, -0x100000001, 0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000]); ");
/*fuzzSeed-254361819*/count=666; tryItOut("\"use strict\"; v1 = (t2 instanceof m2);\n{}\n");
/*fuzzSeed-254361819*/count=667; tryItOut(";");
/*fuzzSeed-254361819*/count=668; tryItOut("a2.push(i2, f0, p2);");
/*fuzzSeed-254361819*/count=669; tryItOut("mathy5 = (function(x, y) { return ( + (( + (Math.asinh(((Math.clz32(Math.fround(( ! Math.imul((-(2**53) - y), (x !== y))))) - (-0x07fffffff === Math.atan(Math.fround(Math.cosh(Math.fround(2**53+2)))))) >>> 0)) >>> 0)) != ( + (Math.tan(Math.fround((mathy0(Math.abs(x), Math.fround(Math.fround(((Math.fround(-0x100000000) << Math.fround(x)) ? mathy3(y, y) : y)))) | 0))) >>> 0)))); }); testMathyFunction(mathy5, [0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, Number.MAX_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 2**53, 0x07fffffff, -0x0ffffffff, Math.PI, 2**53+2, 0x0ffffffff, 1.7976931348623157e308, 1/0, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 0, -0x100000000, -0x080000001, -(2**53+2), 1, -(2**53), -0, -(2**53-2), -1/0, 0x100000001, 0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=670; tryItOut("\"use strict\"; g2.i1.next();");
/*fuzzSeed-254361819*/count=671; tryItOut("mathy4 = (function(x, y) { return ( + Math.min(( + (Math.sin((Math.atan2(x, ( + y)) | 0)) | 0)), ( + (Math.acosh((Math.hypot((( - ((mathy2((-0x100000000 >>> 0), 1) >>> 0) >>> 0)) | 0), x) | 0)) | 0)))); }); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-254361819*/count=672; tryItOut("h1.delete = f2;\nv2 = evalcx(\"return;\", g2);\n");
/*fuzzSeed-254361819*/count=673; tryItOut("");
/*fuzzSeed-254361819*/count=674; tryItOut("\"use strict\"; o0.m1.toSource = f2;");
/*fuzzSeed-254361819*/count=675; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; selectforgc(this); } void 0; }");
/*fuzzSeed-254361819*/count=676; tryItOut("/*tLoop*/for (let c of /*MARR*/[[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], objectEmulatingUndefined(), objectEmulatingUndefined(), [], [], objectEmulatingUndefined(), objectEmulatingUndefined(), [], true, true, [], []]) { v2 = t1.length;({/*TOODEEP*/}) }");
/*fuzzSeed-254361819*/count=677; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.tanh(Math.fround(Math.hypot(((Math.fround(Math.hypot(Math.fround(Math.max(((2**53+2 ? y : 0x100000000) | 0), Math.log1p((Math.fround(( ! x)) >>> 0)))), Math.fround(y))) ? ( + mathy2(x, ( + mathy1(( + x), ( + Math.atan2(0x100000000, y)))))) : (y >>> 0)) | 0), Math.atan2((Math.hypot((((x >>> 0) < Math.PI) >>> 0), 0/0) | 0), mathy1(( ! x), Math.fround(( ~ (y >>> 0)))))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), -(2**53), 0x100000001, -0x100000001, 0/0, -0x0ffffffff, 0x0ffffffff, 1, -(2**53-2), 0x100000000, 0x080000000, Number.MIN_VALUE, 2**53, 0.000000000000001, -Number.MAX_VALUE, 0, 1/0, 42, 0x080000001, Math.PI, -0x080000000, 2**53+2, 0x07fffffff, -0x100000000, -0x080000001, 2**53-2]); ");
/*fuzzSeed-254361819*/count=678; tryItOut("\"use strict\"; /*infloop*/for(let arguments[\"toString\"] = ((x)); /*UUV1*/(x.slice = (function(x, y) { \"use strict\"; return x; })); /*UUV1*/(w.atan2 = (function (b)\"use asm\";   var tan = stdlib.Math.tan;\n  var imul = stdlib.Math.imul;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -262143.0;\n    var i3 = 0;\n    switch ((c)) {\n      case -2:\n        d0 = ((d2) + (+tan(((d1)))));\n        break;\n      case 1:\n        {\n          i3 = (0x4dd9dbe9);\n        }\n        break;\n      case 1:\n        (Uint8ArrayView[(0xf5a7*(i3)) >> 0]) = ((((imul((0xfed74a64), (0xaaddefad))|0) % (~~(d2))) << (-0xb03a6*((0xd6411f9)))) % ((((0x97c46689))-((0x5c3245) ? (-0x8000000) : (0xf8adc4b6))+((imul((0xffffffff), (-0x8000000))|0) >= (((0xddec57c0))|0))) | ((1))));\n        break;\n      default:\n        i3 = (0xbd7a5193);\n    }\n    i3 = ((~~((0x975fb663) ? (-134217728.0) : (+((d0))))));\n    d2 = (-549755813889.0);\n    i3 = ((((0x7c6f911f)-(0xb9362cef)-(0xfdb3a77b))>>>((!(i3))-((d0)))));\n    (Float32ArrayView[((Uint32ArrayView[0])) >> 2]) = ((d0));\n    {\n      (Uint16ArrayView[0]) = ((/^/yim)-(0xffffffff)-(i3));\n    }\n    return +((d1));\n    d0 = (-70368744177663.0);\n    return +((d2));\n  }\n  return f;).bind(null))) {g1.b2 + o1; \"\" ; }");
/*fuzzSeed-254361819*/count=679; tryItOut("m1.set(p1, g2.m1);");
/*fuzzSeed-254361819*/count=680; tryItOut("mathy1 = (function(x, y) { return (((((((-0 == x) >>> 0) ^ y) >>> 0) >>> 0) | ( + (Math.pow(Math.fround(Math.atan2(( + Math.imul(Math.fround(0), Math.fround(x))), Math.log(x))), Math.sinh(Math.fround(Math.pow((-Number.MIN_SAFE_INTEGER >>> 0), (y >>> 0))))) >>> 0))) ^ Math.abs(Math.max((((1/0 | 0) >> ((Math.log(x) ? ( + ( ~ (y | 0))) : Math.fround(Math.ceil(Number.MAX_VALUE))) | 0)) | 0), Math.fround(Math.cbrt(Math.min((y | 0), (((x | 0) != (x | 0)) | 0))))))); }); testMathyFunction(mathy1, /*MARR*/[true, 033, true, true, true, 033, new Number(1.5), 033, 033, 033, new Number(1.5), true, true, 033, 033, new Number(1.5), true, true, 033, true, new Number(1.5), true, new Number(1.5), 033, 033, true, true, new Number(1.5), true, new Number(1.5), true, 033, true, 033, new Number(1.5), true]); ");
/*fuzzSeed-254361819*/count=681; tryItOut("a0.pop();");
/*fuzzSeed-254361819*/count=682; tryItOut("/*vLoop*/for (var xljzhz = 0, x; xljzhz < 77; x, ++xljzhz) { var c = xljzhz;  } ");
/*fuzzSeed-254361819*/count=683; tryItOut("v0 = (a0 instanceof f0);");
/*fuzzSeed-254361819*/count=684; tryItOut("a1.__iterator__ = (function() { v0 = r0.multiline; return v2; });");
/*fuzzSeed-254361819*/count=685; tryItOut("mathy4 = (function(x, y) { return Math.abs(((mathy2(((Math.fround(Math.asin((y | 0))) ? ( ~ (Math.min(-0x100000001, (0x100000000 >>> 0)) >>> 0)) : x) >>> (Math.round(x) <= x)), ((( ~ (y ** Math.hypot(Math.log1p((0x080000000 | 0)), -0x100000000))) | 0) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 1/0, 0, -0x080000000, 42, 0x100000000, 0x080000001, -(2**53-2), Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, -1/0, -0, 1, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -0x07fffffff, 2**53+2, 0x100000001, 0/0, 0.000000000000001]); ");
/*fuzzSeed-254361819*/count=686; tryItOut("a0.reverse(i0);");
/*fuzzSeed-254361819*/count=687; tryItOut("for (var v of m0) { try { e0.has(this.g0.t1); } catch(e0) { } try { v0 = (f0 instanceof i0); } catch(e1) { } v2 = g2.eval(\"Object.prototype.watch.call(o0.v0, (({}) = x++), (function(j) { if (j) { print(uneval(e1)); } else { try { a2[0] = h2; } catch(e0) { } try { e1.delete(b1); } catch(e1) { } try { m1 = new Map; } catch(e2) { } v1 = (g2.g0 instanceof g2); } }));\"); }");
/*fuzzSeed-254361819*/count=688; tryItOut("{};");
/*fuzzSeed-254361819*/count=689; tryItOut("\"use asm\"; t2[v2];");
/*fuzzSeed-254361819*/count=690; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"x\");");
/*fuzzSeed-254361819*/count=691; tryItOut("a2.reverse(this.e1);");
/*fuzzSeed-254361819*/count=692; tryItOut("m2.has(g0);");
/*fuzzSeed-254361819*/count=693; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( - Math.max(( + Math.atan(((( ! (Math.tan(y) >>> 0)) >>> 0) | 0))), (( - ( ~ y)) | 0))); }); ");
/*fuzzSeed-254361819*/count=694; tryItOut("v2 = g2.r0.global;");
/*fuzzSeed-254361819*/count=695; tryItOut("\"use strict\"; with({}) { this.zzz.zzz; } ");
/*fuzzSeed-254361819*/count=696; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.min(Math.fround(( - ( + ( - ( + Math.imul((y | 0), (Math.imul(y, ( ! x)) >>> 0))))))), (mathy4(mathy2(Math.min(y, ((y | 0) >= 0/0)), 2**53+2), (Math.min((Math.sinh(( ! x)) | 0), ( - mathy2(y, (( + ( ~ y)) <= ((x >>> 0) != 0x0ffffffff))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-0x080000001, 42, 1, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -(2**53+2), -1/0, 2**53, 2**53+2, -0x0ffffffff, -0x100000001, 1.7976931348623157e308, Math.PI, 0/0, 0x100000001, -Number.MAX_VALUE, 0x100000000, -0x07fffffff, 2**53-2, -(2**53), 0x07fffffff, 0x0ffffffff, -0, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), 0]); ");
/*fuzzSeed-254361819*/count=697; tryItOut("mathy2 = (function(x, y) { return ( + (((((Math.clz32(y) >>> (mathy0((x >>> 0), (Number.MIN_VALUE | 0)) / y)) == ( + ( ! Math.fround(-0x07fffffff)))) >>> 0) ^ (Math.fround(-0x07fffffff) != Math.max(( + ( ~ (x && 0.000000000000001))), ( + (Math.sign((y >>> 0)) >>> 0))))) | 0)); }); ");
/*fuzzSeed-254361819*/count=698; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-254361819*/count=699; tryItOut("Object.defineProperty(this, \"this.t2\", { configurable: x, enumerable: true,  get: function() {  return new Int16Array(this.t1); } });");
/*fuzzSeed-254361819*/count=700; tryItOut("g0.o0.p0 = o0.a2[3];");
/*fuzzSeed-254361819*/count=701; tryItOut("h2.__iterator__ = (function(j) { if (j) { try { v0 = t1.length; } catch(e0) { } for (var v of a1) { g1 = this; } } else { try { this.m1.has(this.s1); } catch(e0) { } m2.get(g0); } });/*vLoop*/for (let vhmowe = 0; vhmowe < 72; ++vhmowe) { var c = vhmowe; Array.prototype.sort.call(a0, (function() { try { /*ADP-3*/Object.defineProperty(a0, 9, { configurable: (x % 46 != 10), enumerable: true, writable: true, value: o1.g1.g0 }); } catch(e0) { } try { let a0 = a0.filter((function() { try { v2 = true; } catch(e0) { } g0.e1.delete(b2); return g0.e1; })); } catch(e1) { } Array.prototype.shift.call(a1); throw e2; }), i2); } ");
/*fuzzSeed-254361819*/count=702; tryItOut("\"use strict\"; /*vLoop*/for (let znypjy = 0, null; znypjy < 2; ++znypjy) { let a = znypjy; v0 = evaluate(\"a1.splice(NaN, 2);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy:  /x/ , catchTermination: true })); } ");
/*fuzzSeed-254361819*/count=703; tryItOut("mathy3 = (function(x, y) { return (Math.expm1(((Math.asin((( + (( + Math.fround(Math.sign(Math.fround(mathy0(-Number.MIN_VALUE, ( + ((y >= (x | 0)) | 0))))))) & ( + (((x >>> 0) * ((Math.acosh(x) | 0) >>> 0)) >>> 0)))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-(2**53), Math.PI, 0x0ffffffff, 0.000000000000001, -0x100000001, -0x07fffffff, -0x0ffffffff, -(2**53-2), -1/0, 0x100000000, -0, Number.MIN_VALUE, 2**53, 2**53+2, 1/0, 42, 0x080000001, -Number.MAX_VALUE, 0x080000000, 1, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), -0x080000001, 0x100000001, -0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-254361819*/count=704; tryItOut("\"use strict\"; t1 = new Uint8ClampedArray(t0);");
/*fuzzSeed-254361819*/count=705; tryItOut("g0.s1 = a0.join(s0);");
/*fuzzSeed-254361819*/count=706; tryItOut("mathy5 = (function(x, y) { return (( ! Math.fround(Math.min(Math.fround(Math.atan2(( + mathy4(( + (Math.expm1((y ? x : y)) >>> 0)), ( + ( + Math.log1p(( + -0x07fffffff)))))), (( + (( + ( ! ( - ( + y)))) >= (x % x))) | 0))), Math.fround(Math.min(( + Math.max(( + x), Math.imul((y == y), (Math.acosh((y >>> 0)) >>> 0)))), Math.max(( + -(2**53-2)), y)))))) | 0); }); testMathyFunction(mathy5, [2**53, -1/0, 1.7976931348623157e308, 0, Number.MAX_VALUE, -0x100000000, -0x100000001, -Number.MIN_VALUE, -(2**53+2), 0x07fffffff, Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53-2), 1/0, 0.000000000000001, Math.PI, 0x080000001, 1, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 2**53+2, 0x100000000, 0x0ffffffff, -0x080000001, -0, 0x080000000, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-254361819*/count=707; tryItOut("v0.__proto__ = g1.s1;");
/*fuzzSeed-254361819*/count=708; tryItOut("o2.h1.getPropertyDescriptor = (function() { try { this.v0 = (this.a2 instanceof g0); } catch(e0) { } try { this.v2 = undefined; } catch(e1) { } try { o2.e2.add(h2); } catch(e2) { } v2 = r1.unicode; return this.o0; });");
/*fuzzSeed-254361819*/count=709; tryItOut("mathy3 = (function(x, y) { return (Math.fround(((Math.fround((Math.max((mathy1(Math.fround((y >> y)), Number.MAX_VALUE) | 0), (-Number.MAX_VALUE | 0)) | 0)) >> Math.fround(( ! ( + Math.atan2(( ~ -Number.MAX_VALUE), Math.fround(Math.max(Math.fround(x), Math.fround(0.000000000000001)))))))) >>> 0)) + Math.fround((mathy1(((Math.max(x, (y | 0)) | 0) !== y), (Math.pow(-0, Math.hypot((mathy2(-0, x) ^ Math.trunc(x)), (mathy0((y | 0), (mathy0((x | 0), ( + y)) | 0)) | 0))) >>> 0)) - Math.fround((Math.fround(mathy2(( + y), -0x100000000)) , Math.fround(Math.min((x | 0), (( ~ Math.fround(Math.fround(( + Math.fround(-0x100000000))))) | 0)))))))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -1/0, -0, 0.000000000000001, Math.PI, 0x080000001, 2**53+2, -0x100000000, -(2**53+2), -Number.MAX_VALUE, 42, 1/0, 1, 0x07fffffff, -0x07fffffff, 0/0, 0x080000000, 0x0ffffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, -Number.MIN_VALUE, 0x100000001, 2**53-2, 0x100000000]); ");
/*fuzzSeed-254361819*/count=710; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=711; tryItOut("\"use strict\"; with(/*UUV2*/(x.toJSON = x.values)){print(0x100000001);v1 = r2.test; }");
/*fuzzSeed-254361819*/count=712; tryItOut("\"use strict\"; a0.forEach(f2);");
/*fuzzSeed-254361819*/count=713; tryItOut("\"use strict\"; delete h0[\"5\"];");
/*fuzzSeed-254361819*/count=714; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.imul(mathy3(mathy1(((( + Math.min(( + y), ( + mathy2((y !== x), (-0x0ffffffff ? x : x))))) + ((( + mathy1(( + Math.hypot(x, y)), ( + -0))) ** ( + y)) | 0)) | 0), ( + ((((Math.tanh(((((x >>> 0) >>> (( + (( + -0x07fffffff) & x)) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0) * (x | 0)) | 0))), mathy1((x % Math.fround(y)), Math.fround((Math.fround((Math.max((y >>> 0), x) >>> 0)) - Math.fround((Math.sinh(y) >>> 0)))))), ( ! ((( + ( + (( + ( + Math.trunc(( + (y ? (Math.fround((x >>> y)) >>> 0) : (( - (Number.MIN_SAFE_INTEGER >>> 0)) | 0)))))) || (( + ( ~ ( + (( ! x) >>> 0)))) / ( ~ -0x07fffffff))))) ? ((Math.fround((Math.fround(y) <= Math.fround(-Number.MIN_SAFE_INTEGER))) ? x : (((y >>> 0) >> (y >>> 0)) >>> 0)) | 0) : (Math.ceil(1/0) | 0)) | 0))); }); testMathyFunction(mathy5, [-0x100000001, -0x0ffffffff, 0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 1/0, -(2**53-2), -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000000, -Number.MIN_VALUE, 42, -(2**53), Number.MAX_VALUE, 0.000000000000001, -0, 1, 0x080000000, 0/0, 1.7976931348623157e308, Number.MIN_VALUE, 2**53+2, -0x100000000, 0, -(2**53+2), 2**53, 0x100000001]); ");
/*fuzzSeed-254361819*/count=715; tryItOut("mathy1 = (function(x, y) { return (( + mathy0(y, -Number.MAX_SAFE_INTEGER)) >> Math.atan2(Math.max((( + Math.hypot(mathy0(Math.max(x, ( ! -(2**53+2))), ( + ( + ( + y)))), ( ! ( + ( + Math.ceil(( + (y >= -(2**53-2))))))))) >>> 0), (0x080000001 >>> 0)), Math.fround(Math.max(( + ((y << x) && Math.sqrt(( - y)))), ( ~ x))))); }); testMathyFunction(mathy1, [-0x100000001, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, 0.000000000000001, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, -(2**53+2), -(2**53), 1, -0, Math.PI, -Number.MIN_VALUE, 0/0, 42, -(2**53-2), 0x080000000, 2**53-2, 0x080000001, -0x080000000, Number.MIN_VALUE, -0x100000000, 2**53+2, Number.MAX_VALUE, -0x0ffffffff, -0x080000001, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-254361819*/count=716; tryItOut("let (x) { print(uneval(h2)); }");
/*fuzzSeed-254361819*/count=717; tryItOut("\"use strict\"; for (var v of h1) { try { a2.forEach(Array.prototype.splice.bind(s1), s0, h1); } catch(e0) { } i0 + b0; }");
/*fuzzSeed-254361819*/count=718; tryItOut("/*RXUB*/var r = /\\2/gym; var s = \"\\u234c1\\n\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=719; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( + (((Math.atan(mathy1(Math.fround(y), (y >>> 0))) | 0) != ( + Math.imul(Math.PI, Math.imul((x >>> 0), -0x0ffffffff)))) | 0)) % ( + (( + ( + Math.cos(( + (Math.min(( + ((0x0ffffffff == (Math.tan(Math.imul((y >>> 0), (-0x0ffffffff >>> 0))) >>> 0)) >>> 0)), ( + ( + Math.abs(( + Math.sqrt((x || y))))))) | 0))))) >>> ( + ( + (( + (mathy3((y | 0), Number.MAX_SAFE_INTEGER) | 0)) ? ( + (Math.fround(y) ** -0x0ffffffff)) : ( + x))))))) >>> 0); }); testMathyFunction(mathy4, [-0x080000001, -(2**53+2), 0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, 0x080000000, -1/0, Math.PI, -0x080000000, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, 2**53, -(2**53), 0, 2**53-2, 1.7976931348623157e308, -0x100000001, 0.000000000000001, 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, 1, -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-254361819*/count=720; tryItOut("\"use strict\"; p0.__iterator__ = (function() { for (var v of g0) { try { var v2 = new Number(Infinity); } catch(e0) { } try { for (var v of e0) { v2 = g1.eval(\"a1 = new Array;\"); } } catch(e1) { } try { t2.valueOf = (function mcc_() { var dipzxe = 0; return function() { ++dipzxe; f0(true);};})(); } catch(e2) { } e0.has(a0); } return g2; });");
/*fuzzSeed-254361819*/count=721; tryItOut("a1 = a1.concat(a2, a0, this.o1);");
/*fuzzSeed-254361819*/count=722; tryItOut("\"use strict\"; v1 = g1.runOffThreadScript();");
/*fuzzSeed-254361819*/count=723; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g2.o2, this.f2);");
/*fuzzSeed-254361819*/count=724; tryItOut("mathy2 = (function(x, y) { return ( ~ (Math.pow(( + ( ~ mathy1(( + Math.log1p(( + Math.fround((Math.fround(Math.min(x, Math.PI)) <= y))))), y))), ( ! mathy0(++\u3056, ((( + Math.fround(y)) >>> 0) ? x : y)))) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[new Number(1), new Number(1), true, new Number(1), new Number(1), true, true, true, true, true, true, new Number(1), new Number(1), true, true, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), true, new Number(1), new Number(1), new Number(1), new Number(1), true, new Number(1), true, new Number(1), new Number(1), true, new Number(1), new Number(1), true, true, new Number(1), new Number(1), true, true, new Number(1), new Number(1), true, true, new Number(1), true, true, new Number(1), new Number(1), true, new Number(1), true, new Number(1), new Number(1), true, new Number(1), true, new Number(1), true, new Number(1), true, new Number(1), new Number(1), new Number(1), true, true, true, new Number(1), true, true, new Number(1), true, true, true, true, new Number(1), new Number(1), true, new Number(1), new Number(1), true, true, true, true, true, true, new Number(1)]); ");
/*fuzzSeed-254361819*/count=725; tryItOut("s0 += 'x';");
/*fuzzSeed-254361819*/count=726; tryItOut("{return;\nh0.get = f2;\nprint(delete e.x); }");
/*fuzzSeed-254361819*/count=727; tryItOut("o0.i1 = new Iterator(s0);");
/*fuzzSeed-254361819*/count=728; tryItOut("delete h0.getOwnPropertyDescriptor;");
/*fuzzSeed-254361819*/count=729; tryItOut("print(uneval(a1));");
/*fuzzSeed-254361819*/count=730; tryItOut("\"use strict\"; v2 = evalcx(\"\\\"use strict\\\"; mathy0 = (function(x, y) { \\\"use strict\\\"; return (((Math.asinh((((Math.max(Math.fround(x), Math.fround(( + (y | 0)))) | 0) , ( + Math.tanh(( + ((Math.fround(1/0) > (x | 0)) | 0))))) / Math.min(y, (Math.min((y | 0), x) | 0)))) >>> 0) >= ((Math.log1p((( ~ Math.fround(Math.pow(((x <= (x | 0)) | 0), Math.fround(( + Math.imul(( + -Number.MIN_SAFE_INTEGER), ( + x))))))) | 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, -(2**53), 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, -(2**53+2), Number.MAX_VALUE, 2**53, 1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 2**53+2, -0, -0x080000001, 1, -0x0ffffffff, 0x080000000, -0x080000000, 0x07fffffff, 0.000000000000001, 0, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 0/0, 42, -1/0, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, 0x080000001]); \", g0);");
/*fuzzSeed-254361819*/count=731; tryItOut("\"use strict\"; h0.defineProperty = f0;");
/*fuzzSeed-254361819*/count=732; tryItOut("mathy3 = (function(x, y) { return Math.sign(((((x >>> 0) < (x >>> 0)) >>> 0) ** Math.exp(( + ((mathy1(mathy0(y, y), y) >>> 0) ^ Math.max(x, Math.acosh(-(2**53+2)))))))); }); ");
/*fuzzSeed-254361819*/count=733; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.min(Math.fround(Math.abs(Math.fround(Math.hypot((((x != x) | 0) >>> 0), Math.max(y, y))))), Math.acosh(Math.pow(x, 2**53))) | (( - (Math.pow(( ! 2**53), ((y * ( + (( + x) << ( + 2**53+2)))) | 0)) && (Math.fround(Math.pow(x, ( + y))) >>> x))) | 0)) >>> 0); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -(2**53+2), -Number.MIN_VALUE, 0x100000000, -1/0, Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, 0.000000000000001, 1/0, -0x100000001, -0x07fffffff, -0, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, -0x080000001, -(2**53-2), 0x080000000, Math.PI, -(2**53), -0x100000000, 0, -0x0ffffffff, 2**53, 1, -Number.MAX_VALUE, 0x080000001, 0/0]); ");
/*fuzzSeed-254361819*/count=734; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=735; tryItOut("\"use asm\"; v0.__proto__ = m2;function x((( /x/ \n))(x), c = this.__defineGetter__(\"x\", WeakSet)) { \"use strict\"; yield ((yield /*FARR*/[, window, , \"\\uE4FA\", [,,z1], false, ({a2:z2}), this, ...[], true, [], 10, \"\\u3FA7\", ...[]].filter(decodeURIComponent))) } print(x);");
/*fuzzSeed-254361819*/count=736; tryItOut("\"use strict\"; t1 = new Uint32Array(14);");
/*fuzzSeed-254361819*/count=737; tryItOut("testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, 0.000000000000001, -1/0, -0x080000000, 0x07fffffff, 42, 1, Math.PI, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -0, Number.MAX_VALUE, -(2**53-2), 0x100000001, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, 0, 0x0ffffffff, -0x100000000, 2**53+2, -(2**53), -Number.MAX_VALUE, -0x07fffffff, -(2**53+2), 0x080000000, 1.7976931348623157e308, 2**53-2]); ");
/*fuzzSeed-254361819*/count=738; tryItOut("/*RXUB*/var r = /.{1,2}/gyim; var s = \"\\n\\n\"; print(s.match(r)); ");
/*fuzzSeed-254361819*/count=739; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.imul((Math.ceil(( + (( + ( + Math.imul(( + Math.fround(((( ! 2**53) | 0) % Math.fround(x)))), ( + Math.cbrt((x >>> 0)))))) | (x | 0)))) | 0), (Math.log10((Math.fround(Math.atan((x & (Math.log1p((Math.ceil(Math.fround(Math.log(-(2**53)))) | 0)) | 0)))) | 0)) | 0)); }); testMathyFunction(mathy1, [-0, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), 2**53-2, -(2**53+2), 0x0ffffffff, -0x080000001, 1/0, -0x080000000, -0x100000000, -Number.MIN_VALUE, 0/0, -0x100000001, 0x080000001, -0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 0x080000000, 0x07fffffff, 0x100000001, 1, 0x100000000, 0, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2]); ");
/*fuzzSeed-254361819*/count=740; tryItOut("(void schedulegc(g2.g0.o2.g1));");
/*fuzzSeed-254361819*/count=741; tryItOut("mathy0 = (function(x, y) { return Math.pow(Math.trunc(Math.fround(Math.imul((Math.min((y >>> 0), ( + x)) >>> 0), (((x | 0) ** (x | 0)) | 0)))), ( + Math.fround((Math.fround(Math.min(x, y)) << Math.fround((( - (Math.fround((y / Math.fround(( ! -(2**53+2))))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [0x100000000, 1, -0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, 2**53, 2**53-2, 0/0, 0x080000001, -(2**53+2), 1.7976931348623157e308, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0x100000001, 0x0ffffffff, 0, 1/0, -0x0ffffffff, -Number.MAX_VALUE, -0x100000001, -0x100000000, Number.MIN_VALUE, 42, 2**53+2, Math.PI]); ");
/*fuzzSeed-254361819*/count=742; tryItOut("/*RXUB*/var r = new RegExp(\"(([^]|^\\\\s|[\\u0012-\\u5c10\\u0003]{2,})((?=[^]))|\\\\B|$|\\\\B*?(?!^){0,1}^+?+?)|\\\\\\u24e6|\\\\3|\\\\cJ|.(?!\\\\u00Fd)|.|^[^]+?\", \"gim\"); var s = \"\\ufd4b\\uc416\"; print(s.match(r)); ");
/*fuzzSeed-254361819*/count=743; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.fround((Math.fround((((Math.min(x, x) >>> 0) == ( + y)) | (Number.MIN_SAFE_INTEGER / x))) ^ Math.fround(( + ( ! ( + y)))))), Math.fround(Math.tan((Math.acosh(( + Math.fround(Math.hypot(0x080000000, Math.fround((Math.sqrt(x) | 0)))))) == ( + Math.hypot(( + ( ~ x)), ( + x)))))))); }); testMathyFunction(mathy4, [-1/0, -0x080000001, -(2**53+2), -(2**53), 0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, 0x080000001, 42, 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, Number.MIN_VALUE, 0x100000000, -0x100000000, 1, 1.7976931348623157e308, Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, -0, -(2**53-2), -0x080000000]); ");
/*fuzzSeed-254361819*/count=744; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.pow(mathy4(Math.fround(( + Math.fround(( + mathy1((-Number.MAX_SAFE_INTEGER | 0), (Math.tan(y) >>> 0)))))), (Math.min((( ~ ( + x)) >>> 0), (y >>> 0)) >>> 0)), ( ! Math.acosh(( + mathy3(( + x), ( + x))))))); }); testMathyFunction(mathy5, [2**53+2, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -1/0, 2**53-2, 0, Number.MIN_SAFE_INTEGER, 1, -0x080000000, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -0, 1/0, -Number.MAX_VALUE, 0x100000001, 0x100000000, -0x100000001, -0x0ffffffff, -0x100000000, 0x07fffffff, 42, -(2**53-2), -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, 0.000000000000001, 0x0ffffffff, Math.PI, 2**53, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-254361819*/count=745; tryItOut("{ void 0; deterministicgc(false); } print((4277));");
/*fuzzSeed-254361819*/count=746; tryItOut("\"use strict\"; { void 0; minorgc(true); } neuter(g2.b1, \"same-data\");");
/*fuzzSeed-254361819*/count=747; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(Math.tan(Math.fround(((Math.cbrt((( + (( + ( ! y)) ^ ( + y))) | 0)) | 0) - (Math.fround((-0x080000000 >= (x | 0))) >>> 0))))) ? ((((Math.fround((Math.fround(( ~ -Number.MIN_SAFE_INTEGER)) !== Math.fround(y))) | 0) + ((Math.min(Math.log((y | 0)), Math.fround(Math.hypot(y, ( + x)))) >>> 0) >>> 0)) >>> 0) ** ( + Math.atan2((Math.fround(Math.hypot(Math.fround((Math.round(( + ( ! ( + x)))) | 0)), ((x ? Math.fround(Math.imul(Math.fround(y), Math.fround(y))) : Math.atan2(x, x)) === ( + Math.min(( + y), (x > y)))))) | 0), (Math.min(Math.imul(((( + y) < 0x07fffffff) | 0), x), Math.fround(Math.acos(Math.fround(x)))) | 0)))) : Math.tan(((x | 0) + (Math.sin(y) | 0)))); }); ");
/*fuzzSeed-254361819*/count=748; tryItOut("o2.g0.e1.__proto__ = this.g0;");
/*fuzzSeed-254361819*/count=749; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.abs((( + Math.max((Math.hypot((mathy0(( + (( + Math.log2(y)) | ((-0x100000001 ^ y) | 0))), (x | 0)) >>> 0), (Math.log1p((Number.MIN_SAFE_INTEGER >>> 0)) ? Math.exp(x) : y)) | 0), (( - (((Math.atan2(-Number.MIN_SAFE_INTEGER, y) >>> 0) <= (Number.MAX_VALUE >>> 0)) >>> 0)) <= Math.sinh(( + Math.atan2(( + /*iii*/(void schedulegc(g1));/*hhh*/function ecxriw(x, ...d){((4277));}), 0x100000001)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), (0/0), (0/0), new String(''), (0/0), new String(''), new String(''), objectEmulatingUndefined(), function(){}, function(){}, (0/0), (void 0), (void 0)]); ");
/*fuzzSeed-254361819*/count=750; tryItOut("o0.a1.reverse(g2, v0);");
/*fuzzSeed-254361819*/count=751; tryItOut("\"use strict\"; this.g1.a2.__iterator__ = (function() { for (var j=0;j<50;++j) { f1(j%2==0); } });");
/*fuzzSeed-254361819*/count=752; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.asinh((( - ( + ( - (1.7976931348623157e308 >>> 0x07fffffff)))) | 0)) ** Math.fround((Math.trunc((((Math.expm1(( + Math.acos((x >>> 0)))) | 0) | y) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-254361819*/count=753; tryItOut("\"use strict\"; e0.add(g2);");
/*fuzzSeed-254361819*/count=754; tryItOut("p2 = t2[4];");
/*fuzzSeed-254361819*/count=755; tryItOut("y = linkedList(y, 4505);");
/*fuzzSeed-254361819*/count=756; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)+(0x80ba314f)))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), NaN, undefined, -0, 1, [0], objectEmulatingUndefined(), ({toString:function(){return '0';}}), null, '', true, (new Number(-0)), 0, '/0/', (new Number(0)), (new Boolean(false)), false, [], (new Boolean(true)), ({valueOf:function(){return 0;}}), (function(){return 0;}), /0/, (new String('')), '0', 0.1, '\\0']); ");
/*fuzzSeed-254361819*/count=757; tryItOut("/*RXUB*/var r = new RegExp(\"[^\\\\s\\\\ud724-\\ude9b]+?(?=(?=(.))|(?:[^\\\\@\\\\D])|(?!\\\\3|\\\\1+\\\\B(?!\\\\B){3}))|.*\", \"im\"); var s = \"\\n\\n\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-254361819*/count=758; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=759; tryItOut("mathy0 = (function(x, y) { return ((( + Math.fround(( + Math.fround(Math.atanh((Math.min(y, ( + (( + -0x0ffffffff) ? ( + Math.clz32(x)) : ( + y)))) >>> 0)))))) >>> 0) / ( + Math.fround(Math.imul(Math.fround(Math.fround(Math.clz32(Math.fround(( + Math.clz32(( + 1.7976931348623157e308))))))), Math.fround(((Math.fround((( + y) | 0)) > Math.fround((( ! (x | 0)) | 0))) | 0)))))); }); testMathyFunction(mathy0, [-1/0, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), Math.PI, 42, Number.MIN_SAFE_INTEGER, 2**53, 0/0, 0x080000000, -(2**53), 1/0, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -0, 2**53+2, 0x080000001, -(2**53-2), -0x100000001, 0x100000000, 0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, -0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=760; tryItOut("h0.hasOwn = (function(j) { if (j) { try { i1 = t0[13]; } catch(e0) { } o0 = new Object; } else { try { print(uneval(i2)); } catch(e0) { } i1.send(s2); } });");
/*fuzzSeed-254361819*/count=761; tryItOut("testMathyFunction(mathy5, [Number.MIN_VALUE, 1.7976931348623157e308, -0, 2**53, Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, Math.PI, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -(2**53+2), 0x100000001, Number.MAX_VALUE, 0x100000000, -1/0, 42, -0x100000001, -(2**53), -0x100000000, 1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -0x0ffffffff, 0, -0x080000000, 0x080000000, 2**53-2, -0x07fffffff, 0x07fffffff]); ");
/*fuzzSeed-254361819*/count=762; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.ceil((Math.max(( + Math.trunc(( + 0.000000000000001))), ( + ( + ( + Math.min(y, (Math.sign(Math.fround(y)) >>> 0)))))) | 0))); }); testMathyFunction(mathy2, [0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 1, Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 1/0, -0x080000001, -1/0, -(2**53-2), 0x080000000, 0x0ffffffff, 2**53, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), Number.MIN_VALUE, 0/0, 0, -Number.MIN_VALUE, -0x07fffffff, -(2**53), 0x07fffffff, Math.PI, 0x100000001]); ");
/*fuzzSeed-254361819*/count=763; tryItOut("");
/*fuzzSeed-254361819*/count=764; tryItOut("testMathyFunction(mathy3, /*MARR*/[new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String(''), new String(''), new Boolean(true), new Boolean(true), new String(''), new String(''), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String(''), new Boolean(true), new String(''), new Boolean(true), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Boolean(true), new String(''), new String(''), new String(''), new Boolean(true), new String(''), new String(''), new String('')]); ");
/*fuzzSeed-254361819*/count=765; tryItOut("e0 = new Set(b2);");
/*fuzzSeed-254361819*/count=766; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.imul((x >= ( + Math.imul((((x | 0) % Math.fround((Math.atan2((x | 0), (x | 0)) | 0))) >>> 0), Math.max(0.000000000000001, y)))), ( + Math.abs(x)))); }); testMathyFunction(mathy0, [1, 0, 2**53+2, 0x080000000, -0x080000001, Number.MIN_VALUE, -(2**53+2), -1/0, 0.000000000000001, 0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), -0, 0x100000001, 1.7976931348623157e308, 0x100000000, 1/0, -0x07fffffff, 0x0ffffffff, -0x080000000, 0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53-2), 42, -0x100000000, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=767; tryItOut("let (a) { (true); }");
/*fuzzSeed-254361819*/count=768; tryItOut("/*RXUB*/var r = new RegExp(\"((?![^\\\\d\\\\B\\\\W]\\\\2*){2})|\\\\q\", \"gyim\"); var s = \"\\uf93e\"; print(r.test(s)); ");
/*fuzzSeed-254361819*/count=769; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.exp(( ! Math.min((x ? y : -0x100000001), x))); }); testMathyFunction(mathy3, [0x100000001, -0x100000000, 0x080000000, 0x080000001, 1, -Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, 42, 1/0, 0, 2**53+2, 0x100000000, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, 0/0, 0x0ffffffff, Math.PI, -(2**53), -(2**53-2), -0, -(2**53+2), 0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=770; tryItOut("/*MXX3*/g0.TypeError.prototype.message = g2.TypeError.prototype.message;");
/*fuzzSeed-254361819*/count=771; tryItOut("this.o0.s0 += s0;");
/*fuzzSeed-254361819*/count=772; tryItOut("\"use strict\"; { void 0; minorgc(true); } h1.get = f1;\nvar xqeala = new SharedArrayBuffer(1); var xqeala_0 = new Float32Array(xqeala); xqeala_0[0] = 0.84; print(xqeala_0[9]);\n");
/*fuzzSeed-254361819*/count=773; tryItOut("\"use strict\"; f1 = f0;");
/*fuzzSeed-254361819*/count=774; tryItOut("for(e = x in (4277)) /* no regression tests found */");
/*fuzzSeed-254361819*/count=775; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.sqrt(( + Math.hypot(( + Math.sign(Math.imul(Math.fround(Math.atan2(1, x)), x))), (2**53+2 | 0)))) | 0) ? (( + ( + (( + Math.sin(( + Math.atan2((Math.cbrt((y | 0)) | 0), Math.cosh(Math.fround(( + ( + y)))))))) >>> 0))) | 0) : ((Math.atan2(Math.exp(x), Math.hypot(Math.fround(Math.imul(x, (((y ? x : y) >>> 0) * -Number.MAX_VALUE))), (((-(2**53) | 0) ** Math.acosh((( ~ (y >>> 0)) >>> 0))) | 0))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [2**53+2, -0x100000000, -0, 2**53, 0x080000001, 1/0, 0x0ffffffff, Math.PI, 2**53-2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, Number.MAX_VALUE, -(2**53+2), -(2**53-2), 0/0, Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 0x080000000, -0x080000000, 1, -(2**53), 0x07fffffff, 42, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, Number.MIN_VALUE, -0x100000001]); ");
/*fuzzSeed-254361819*/count=776; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.fround(( ! Math.imul((0 ? y : mathy3(((( ~ (x | 0)) | 0) | 0), ( + Math.fround(x)))), y))), ((((((mathy4(Math.fround((( + (( - y) | 0)) | 0)), Math.fround((Math.fround(Math.max(y, Math.fround(y))) >> (x <= 42)))) | 0) || (( ~ (( ~ y) >>> 0)) | 0)) | 0) | 0) === (Math.pow((( - (( + ( + (( + x) !== ( + 2**53)))) >>> 0)) >>> 0), ((( + mathy4(2**53-2, y)) >> ( + ( - y))) >>> 0)) | 0)) | 0))); }); testMathyFunction(mathy5, [2**53, -0x100000000, -0x0ffffffff, 0, 0x080000000, -Number.MAX_VALUE, 2**53+2, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, 0x100000001, 1, 0/0, Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -(2**53-2), -0x07fffffff, 1.7976931348623157e308, Math.PI, -0, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -(2**53+2), -(2**53), -0x080000001, 0x080000001]); ");
/*fuzzSeed-254361819*/count=777; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.round(Math.fround(Math.max(Math.min(( - (( ! y) >> x)), Math.fround(x)), Math.fround((( ~ (( + mathy0(( + Math.fround(((( ! y) >>> 0) ? Math.fround((y ? ( + (Math.clz32((42 | 0)) | 0)) : (x > 2**53+2))) : (( + y) >>> 0)))), (mathy0(( + -Number.MIN_SAFE_INTEGER), y) >>> 0))) | 0)) | 0))))); }); testMathyFunction(mathy1, [0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -1/0, 2**53-2, 0x080000000, 0x100000000, 1.7976931348623157e308, 0x100000001, Number.MIN_VALUE, -0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, -Number.MAX_VALUE, 1/0, 1, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), -0x080000001, -Number.MIN_VALUE, -0x080000000, 2**53+2, 42, 0x080000001, 0, Number.MIN_SAFE_INTEGER, 0/0, 2**53, Math.PI]); ");
/*fuzzSeed-254361819*/count=778; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.hypot((mathy1((y >>> 0), (Math.imul((-(2**53-2) | 0), y) | 0)) >>> 0), (Math.trunc((Math.log2(( ~ (Number.MIN_SAFE_INTEGER | 0))) >>> 0)) >>> 0)) <= ((( + ( - ( + (( + x) + ((Math.min((y >>> 0), (Math.asin(y) >>> 0)) >>> 0) >>> 0))))) + ( + ((Math.acos((-0x07fffffff > (((0x100000000 >>> 0) >> (Math.max(y, y) >>> 0)) >>> 0))) >>> 0) >= Math.hypot(x, x)))) >>> 0)); }); ");
/*fuzzSeed-254361819*/count=779; tryItOut("a1 = arguments.callee.arguments;");
/*fuzzSeed-254361819*/count=780; tryItOut("\"use strict\"; L:do v0 = evalcx(\"\\\"use strict\\\"; mathy5 = (function(x, y) { return Math.min(( ! (( + (( + x) % ( + Math.imul(Math.imul(Number.MAX_SAFE_INTEGER, x), -0x100000000)))) + (( + Math.min(( + ( ! 0)), ( + x))) | 0))), (((mathy4((mathy1(y, (( + -0x100000000) === Math.max(mathy4(x, x), x))) >>> 0), (( ~ ( + (Math.min(( + 2**53), ( + (( + (x >>> 0)) >>> 0))) >>> 0))) >>> 0)) >>> 0) ? (Math.exp((Math.sin(((Math.atan2((x >>> 0), (Math.min(Math.fround(-0x0ffffffff), 0) >>> 0)) >>> 0) || (Math.max(( + Math.round(x)), ( + x)) >>> 0))) >>> 0)) | 0) : ((Math.hypot((Math.min((( + Math.fround(( + x))) | (y && y)), (x >>> 0)) >>> 0), Math.max(( + x), Math.fround(x))) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy5, [0x080000000, -Number.MIN_VALUE, 1, -0, -Number.MAX_VALUE, -0x080000000, -(2**53-2), 0x080000001, -0x080000001, 0.000000000000001, Number.MAX_VALUE, -0x100000001, -0x07fffffff, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, -(2**53), -0x0ffffffff, 0/0, 0x100000001, 2**53-2, 0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 0x100000000, 0x07fffffff]); \", g0); while(((4277)) && 0);");
/*fuzzSeed-254361819*/count=781; tryItOut("\"use strict\"; e1.has(/*UUV1*/(e.toString = (allocationMarker())));");
/*fuzzSeed-254361819*/count=782; tryItOut("x = let (z = x) (4277).unwatch(\"call\"), e = this;v0 = evalcx(\"function this.f0(g0.o0.g0)  { \\\"use strict\\\"; /*oLoop*/for (var btdjns = 0; btdjns < 50; ++btdjns, new RegExp(\\\"(?=(?!^{15,15}|\\\\\\\\1{1}))+?\\\", \\\"i\\\")) { o1.o2.a0[v2]; }  } \", this.g2);");
/*fuzzSeed-254361819*/count=783; tryItOut("mathy3 = (function(x, y) { return ( + mathy2(Math.fround(( - Math.atan2((Math.sqrt(Math.max(x, (y == y))) >>> 0), (Math.cosh(( + ( ! ((Math.exp((y | 0)) | 0) | 0)))) >>> 0)))), ( + Math.fround(Math.imul((mathy2(Math.abs(Math.fround((( ! Math.fround(( ! (y >> 42)))) >>> 0))), Math.acosh(-0x080000001)) >>> 0), Math.fround((( + Math.asin(Math.fround(y))) ** ((Math.atan2((( + Math.sign((x | 0))) | 0), ((Math.imul(( + y), 1) | 0) | 0)) | 0) >>> 0)))))))); }); testMathyFunction(mathy3, [0x07fffffff, 2**53+2, 0x080000000, -0x080000000, -0x0ffffffff, 2**53-2, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, 1/0, Number.MIN_VALUE, -(2**53), 0x100000000, -0x080000001, -Number.MIN_VALUE, 0/0, 0.000000000000001, -0x100000000, 1.7976931348623157e308, Math.PI, -(2**53+2), 0x080000001, 0x100000001, 42, -Number.MIN_SAFE_INTEGER, -0x100000001, 0, 0x0ffffffff, 2**53, -(2**53-2), -1/0]); ");
/*fuzzSeed-254361819*/count=784; tryItOut("const x =  /x/g , lrewhc, x, gaprxx, molxjv;g0.h2.iterate = f2;");
/*fuzzSeed-254361819*/count=785; tryItOut("this.r2 = /((?=(?:(?:([^])|[^]))))/y;");
/*fuzzSeed-254361819*/count=786; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\W?\", \"im\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=787; tryItOut("\"use asm\"; t2[2] = v1;function NaN(eval)x{ void 0; void gc('compartment'); }");
/*fuzzSeed-254361819*/count=788; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( ~ Math.fround(((( + (y / Math.fround(Math.fround(mathy2(1.7976931348623157e308, Number.MAX_VALUE))))) == mathy0((( + y) | Math.fround(x)), (( ! (y != Math.PI)) % (( + Math.pow(( + ( - x)), ( + ((0x07fffffff == ( + Math.fround(( ~ x)))) | 0)))) >>> 0)))) >>> 0)))); }); ");
/*fuzzSeed-254361819*/count=789; tryItOut("o1.valueOf = (function() { try { for (var p in g0.b2) { try { Array.prototype.push.apply(a0, [this.f1]); } catch(e0) { } s1 += 'x'; } } catch(e0) { } try { e0.delete(v0); } catch(e1) { } try { s0.toString = DFGTrue.bind(b0); } catch(e2) { } Array.prototype.shift.call(o2.a1); return o0.g1; });");
/*fuzzSeed-254361819*/count=790; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy0(mathy2((x * (((y >>> 0) === ((mathy1(Math.max(x, Math.fround(y)), x) >>> 0) >>> 0)) >>> 0)), (Math.hypot(Math.fround((Math.fround(x) ? Math.fround(((Math.fround(( ~ ( ! (x | 0)))) | (-(2**53-2) >>> 0)) >>> 0)) : x)), -0) >>> 0)), Math.tan(Math.imul(y, (Math.sin(( ! mathy4((-Number.MAX_VALUE | 0), ( + x)))) >>> 0)))); }); ");
/*fuzzSeed-254361819*/count=791; tryItOut("const r1 = new RegExp(\"\\\\3+?\", \"i\");");
/*fuzzSeed-254361819*/count=792; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3\", \"ym\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-254361819*/count=793; tryItOut("\"use strict\"; a0[5] = (4277);");
/*fuzzSeed-254361819*/count=794; tryItOut("/*ODP-1*/Object.defineProperty(b1, \"call\", ({enumerable: false}));function d(c, ...y)\"use asm\";   var NaN = stdlib.NaN;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (-32769.0);\n    d0 = (7.555786372591432e+22);\n    d0 = ((0xff59351a) ? (4.722366482869645e+21) : (NaN));\n    return +((-8796093022209.0));\n    d0 = (((4.835703278458517e+24)) / (((p={}, (p.z = this)()))));\n    {\n      return +((Float32ArrayView[((i1)) >> 2]));\n    }\n    {\n      {\n        (Float32ArrayView[0]) = ((-((d0))));\n      }\n    }\n    {\n      switch ((((!(1)))|0)) {\n        default:\n          d0 = (d0);\n      }\n    }\n    return +((d0));\n  }\n  return f;a2.unshift(this.a2, g2.b1, t2, h2, a0, t2);");
/*fuzzSeed-254361819*/count=795; tryItOut("/*RXUB*/var r = /[^]{0,}[^]\\1?((?=($)+?\\d*?))|(?!(?!\\3)\\3|[^\\cEp\\u008D])+[\u2ea8\\u1a29\\D]/y; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\na\"; print(s.match(r)); ");
/*fuzzSeed-254361819*/count=796; tryItOut("v1 = a2.reduce, reduceRight((function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (i1);\n    return (((0xeec4d4ae) % (((i2))>>>(((1.5) < (8589934593.0))))))|0;\n    {\n      i1 = (0xf8b5cf37);\n    }\n    i1 = (((-0xfffff*([,] ? window : \"\\u2A50\"))>>>(((~~(+ceil(((-513.0))))))+(!(0x7a1132b2)))));\n    {\n      i1 = (i2);\n    }\n;    (Float64ArrayView[2]) = ((d0));\n    {\n      d0 = (-2.3611832414348226e+21);\n    }\n    d0 = (1.25);\n    {\n      d0 = (-68719476737.0);\n    }\n    i2 = (i2);\n    (Float64ArrayView[4096]) = ((((262143.0)) - (((-67108864.0)))));\n    return ((((d0) <= (d0))*-0xfffff))|0;\n    {\n      i1 = (0x3fb6d399);\n    }\n    d0 = (-1.25);\n    d0 = (3.8685626227668134e+25);\n    (Float64ArrayView[((((0x98790353)-(0xf15244c3)-(0xb9830d1a)) ^ (((0x5f9af183))-(i1))) % (~~(Infinity))) >> 3]) = ((65.0));\n    return (((((4277) < (((4277))({}, Math))) ? (0xb35ecb28) : ((((0x2ac13730))>>>(-0x696d3*(i1)))))))|0;\n  }\n  return f; })(this, {ff: Date.prototype.toString}, new ArrayBuffer(4096)));");
/*fuzzSeed-254361819*/count=797; tryItOut("\"use strict\"; oadjlu, poqomp, wnnaje, {} = function(id) { return id } >>>= a;g0 + '';");
/*fuzzSeed-254361819*/count=798; tryItOut("\"use strict\"; s2 += s0;");
/*fuzzSeed-254361819*/count=799; tryItOut("\"use strict\"; print(this.f2);");
/*fuzzSeed-254361819*/count=800; tryItOut("mathy2 = (function(x, y) { return Math.acosh(Math.min(mathy0((Math.hypot((y | 0), ( - 0/0)) >>> 0), (Math.cosh((y ** x)) >>> 0)), (Math.cos((4277)) >>> 0))); }); testMathyFunction(mathy2, [-0x080000001, 0x100000000, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, 2**53, 0x080000000, -(2**53-2), 2**53-2, -0x0ffffffff, 2**53+2, -Number.MIN_VALUE, 0/0, -1/0, -0x080000000, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -0, 0x080000001, 42, -0x100000001, -(2**53), -Number.MAX_VALUE, -0x07fffffff, 0, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1]); ");
/*fuzzSeed-254361819*/count=801; tryItOut("v0 = a0.reduce, reduceRight((function() { try { /*MXX1*/o0 = this.g1.Array.name; } catch(e0) { } o2 + ''; return i1; }), b1);");
/*fuzzSeed-254361819*/count=802; tryItOut("v0 = o2.a1.length;");
/*fuzzSeed-254361819*/count=803; tryItOut("f2 + b2;");
/*fuzzSeed-254361819*/count=804; tryItOut("this;");
/*fuzzSeed-254361819*/count=805; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=806; tryItOut("\"use strict\"; v1 = a2.length;");
/*fuzzSeed-254361819*/count=807; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0(mathy0(mathy0(Math.tan(Math.fround((Math.cos((y >>> 0)) >>> 0))), Math.fround(( ~ Math.fround(y)))), ( ~ (((( + Math.log1p(x)) | 0) << (((Math.pow((y >>> 0), (x >>> 0)) >>> 0) + x) | 0)) | 0))), Math.fround(( - Math.fround(Math.log2((-(2**53) >>> 0))))))); }); testMathyFunction(mathy1, [NaN, ({valueOf:function(){return 0;}}), (new Number(-0)), [0], 1, undefined, 0.1, 0, ({toString:function(){return '0';}}), (new Number(0)), (new Boolean(true)), -0, (new Boolean(false)), null, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), '\\0', false, (function(){return 0;}), (new String('')), '', '/0/', /0/, true, '0', []]); ");
/*fuzzSeed-254361819*/count=808; tryItOut("mathy4 = (function(x, y) { return (Math.imul((Math.sqrt(( + mathy3(( + ( ~ Math.fround(Math.pow(Math.log10(x), 2**53)))), ( + Math.atanh((Math.hypot(y, x) | 0)))))) >>> 0), (( - ( + ( + Math.imul(( + ( + ( ~ Math.fround(Math.cosh((x | 0)))))), ( + Math.sqrt((( + Math.cbrt(( + Math.fround(( + y))))) >>> 0))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 1, Math.PI, -0x080000001, 0x100000000, 0.000000000000001, -0x080000000, -(2**53+2), -1/0, 0x07fffffff, -(2**53), 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, -0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 2**53-2, 0/0, 1/0, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, 2**53, -Number.MIN_VALUE, 42, 0x0ffffffff, -0x100000000, 0x100000001, 0, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=809; tryItOut("m0.delete(o1);");
/*fuzzSeed-254361819*/count=810; tryItOut("this.e0 = new Set;");
/*fuzzSeed-254361819*/count=811; tryItOut("let(d =  \"\" , zlykim, a, edqsbd, d, x) { t0 = new Int32Array(t2);}");
/*fuzzSeed-254361819*/count=812; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.sin(Math.fround(Math.log10(Math.fround(( + Math.atan2(( + Math.hypot(Math.log((-0x080000001 >>> 0)), (y | 0))), ( + ( + (( + x) , ( + (x >>> Math.cos(y)))))))))))); }); ");
/*fuzzSeed-254361819*/count=813; tryItOut("mathy5 = (function(x, y) { return (((( + mathy3(( + (((( + Math.pow(( + y), ( + x))) >>> 0) & (0x080000000 >>> 0)) >>> 0)), (Math.min(y, ( + ( + ( ! ( + (( ! -(2**53)) >>> 0)))))) | 0))) * (( + y) - Math.fround(((( - y) | 0) ? Math.fround((Math.exp((x >>> 0)) >>> 0)) : Math.fround(Math.min(x, (x ** y))))))) === ( - (( - (y >>> 0)) >>> 0))) ** Math.cbrt((( + mathy4(Math.fround(Math.hypot(y, Math.fround((Math.asin((y >>> 0)) >>> 0)))), Math.imul(x, (y ? y : -Number.MIN_SAFE_INTEGER)))) >>> 0))); }); testMathyFunction(mathy5, [-0, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0.000000000000001, -0x080000001, 2**53+2, Math.PI, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53, -(2**53), 0/0, -1/0, 0x100000001, 42, -0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, -0x07fffffff, -(2**53+2), 0, -(2**53-2), -0x100000000, 0x080000001, 0x080000000, 1]); ");
/*fuzzSeed-254361819*/count=814; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( - ((( ! x) >>> 0) >= Math.pow(x, y))) | (Math.exp((x === Math.ceil(( + ( ~ Math.fround((( + Math.acosh(y)) & Math.fround(x)))))))) >>> 0)); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -(2**53+2), 0, 0.000000000000001, -0x080000000, 0x100000001, -(2**53-2), 2**53-2, 0x0ffffffff, -0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 42, -0x100000000, 1, -(2**53), 2**53, -0x080000001, -0x07fffffff, 0/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -1/0, -0x0ffffffff, 2**53+2, -0x100000001, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=815; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -70368744177665.0;\n    d1 = (+(1.0/0.0));\n    return +(((((((6.044629098073146e+23) + (((NaN)) % ((262143.0))))) % ((1.1805916207174113e+21)))) * ((+atan2(((Float64ArrayView[2])), ((((1.5474250491067253e+26)) / ((262143.0)))))))));\n  }\n  return f; })(this, {ff: this ? /(?=\\u7489)|[\\s\\w\\0-\\\u8143]|(?=\\B)+?|\u000e+?[^]{64}\u0084*?|((?:\\B)[\u71e5-\\v]*)??/gyim : \"\\u2CF7\"}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, 1/0, -0x0ffffffff, 2**53, Number.MIN_VALUE, 0, 42, 0x07fffffff, -0x080000000, -Number.MIN_VALUE, 0x080000001, -(2**53), 1.7976931348623157e308, -(2**53+2), 2**53+2, 0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 1, -0x080000001, -0x07fffffff, 0x080000000, -0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-254361819*/count=816; tryItOut("\"use strict\"; /*RXUB*/var r = /((?=([^])))|\\1*|.*|(.|\\b?)(?=^)|\\n?{262144,}{0}/gyim; var s = \"\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\\uffea\"; print(r.exec(s)); ");
/*fuzzSeed-254361819*/count=817; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy0(( + Math.cos(( + (mathy0(Math.fround(-0), Math.fround(( + (( + Math.atan(y)) + ( + ( + ( + mathy0(( + -0x080000001), ( + 2**53+2))))))))) >>> 0)))), Math.min(( + Math.fround((Math.min(y, y) > (Math.hypot((y >>> 0), ((Math.fround(1) >>> 0) >>> 0)) >>> 0)))), ( + Math.pow((x >>> 0), ( + (( + ( ~ (( ! (y | 0)) | 0))) >> y)))))) >>> 0); }); testMathyFunction(mathy2, [-(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, 0x080000001, Number.MAX_VALUE, 1/0, 2**53, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, 0, -0x080000001, 0.000000000000001, 42, -0x0ffffffff, 0x100000000, 1, Number.MIN_VALUE, 0x100000001, -0x100000000, -0x100000001, -0, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, -0x080000000]); ");
/*fuzzSeed-254361819*/count=818; tryItOut("\"use strict\"; r2 = new RegExp(\"(?!(?!\\\\x0A))\", \"yim\");");
/*fuzzSeed-254361819*/count=819; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.imul((( - ( + Math.round((( - Math.log(( ! Math.fround(Math.fround(Math.min(x, x)))))) >>> 0)))) >>> 0), (Math.cosh(Math.fround(Math.log2(( ! Math.expm1(mathy0(( + Math.acos(x)), y)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x080000000, 0.000000000000001, -(2**53+2), Math.PI, -0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), -0x07fffffff, 0x100000000, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, 0x080000001, 0x07fffffff, 0/0, 1/0, -0x100000001, 2**53+2, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, -(2**53-2), 0x0ffffffff, 42, -1/0, -0, 0x100000001]); ");
/*fuzzSeed-254361819*/count=820; tryItOut("for (var p in i1) { try { /*MXX3*/g0.RegExp.$' = g0.RegExp.$'; } catch(e0) { } g2.o1 = new Object; }this.a2 = Array.prototype.concat.call(a0, t2, g1, f1);");
/*fuzzSeed-254361819*/count=821; tryItOut("a2.forEach((function() { try { h2.valueOf = (function(j) { if (j) { try { a0.pop(arguments[new String(\"-0\")] = x = this |= eval(\"Array.prototype.shift.call(a1, g1, v0);\", window) ? /\\d+|\\1(?:\\cC?){17}|\\M|(?=[^\\w\u6d0e-\\uD279\\xB1-\u7b81])|[\\S\\v-\\\u17aa\\uC00E]*?{1,}/gim.throw(new RegExp(\"$(?:\\\\b)|(?=\\\\3)*\\\\b\", \"im\")) : ({}), t0); } catch(e0) { } f1 = Proxy.createFunction(h0, f1, o2.f0); } else { try { v2 = a1.reduce, reduceRight((function() { try { a1[2] = \"\\u539A\"; } catch(e0) { } e0.add(m0); return this.a2; })); } catch(e0) { } try { v2 = evalcx(\"\", g2); } catch(e1) { } try { h1.toSource = o0.o0.f2; } catch(e2) { } v0 = evaluate(\"function f2(p0)  { yield ({} = [] = p0) } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 3 != 1), noScriptRval: -16, sourceIsLazy: true, catchTermination: true })); } }); } catch(e0) { } m1 = new Map; return f2; }));");
/*fuzzSeed-254361819*/count=822; tryItOut("mathy1 = (function(x, y) { return Math.fround(( + Math.sin((((Math.pow(( + x), ( + (( + x) + Math.imul(( + (( + y) != ( + y))), y)))) | 0) >>> 0) < ((Number.MAX_VALUE / Math.hypot(Math.log2(y), y)) >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[true, null, function(){}, null, new String('q'), function(){}, true, function(){}, true, function(){}, new String('q'), true, new String('q'), true, function(){}, function(){}, true, null, null, null, new String('q'), null, true, true, null, true, null, true, function(){}, true, true, true, function(){}, function(){}, new String('q'), new String('q')]); ");
/*fuzzSeed-254361819*/count=823; tryItOut("\"use strict\"; function shapeyConstructor(dmbivi){\"use strict\"; if ((19.watch(19, (true).apply))) Object.preventExtensions(dmbivi);Object.preventExtensions(dmbivi);if (x) Object.preventExtensions(dmbivi);if (((dmbivi = /(?!\\3\\w+|(?![^])\u00bf(?!\\b\\d*?))/ym))) delete dmbivi[11];return dmbivi; }/*tLoopC*/for (let a of /*MARR*/[({x:3}), -Infinity, -Infinity, ({x:3}), ({x:3}), ({x:3}), -Infinity, -Infinity, ({x:3}), ({x:3}), -Infinity, -Infinity, -Infinity, ({x:3}), -Infinity, ({x:3}), -Infinity, ({x:3}), -Infinity, ({x:3}), ({x:3}), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, ({x:3}), -Infinity, -Infinity, -Infinity, ({x:3}), -Infinity, -Infinity, ({x:3}), -Infinity, -Infinity, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), -Infinity, ({x:3}), -Infinity, -Infinity, -Infinity, ({x:3}), -Infinity, -Infinity, -Infinity, ({x:3}), -Infinity, -Infinity, -Infinity, ({x:3}), -Infinity, ({x:3}), ({x:3}), -Infinity, ({x:3}), ({x:3}), -Infinity, ({x:3}), -Infinity, ({x:3}), -Infinity, ({x:3}), -Infinity, ({x:3}), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, ({x:3}), ({x:3}), ({x:3}), -Infinity, ({x:3}), ({x:3}), ({x:3}), -Infinity, -Infinity, ({x:3}), ({x:3}), -Infinity, ({x:3}), -Infinity, -Infinity, ({x:3}), ({x:3}), ({x:3}), -Infinity, ({x:3}), -Infinity, -Infinity, ({x:3}), -Infinity, ({x:3}), -Infinity, -Infinity, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), -Infinity, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), -Infinity, ({x:3}), -Infinity, -Infinity, -Infinity, -Infinity, ({x:3}), -Infinity, ({x:3}), ({x:3}), -Infinity, ({x:3}), ({x:3}), ({x:3}), -Infinity, ({x:3}), ({x:3}), -Infinity, -Infinity, ({x:3}), -Infinity, ({x:3}), -Infinity, ({x:3}), ({x:3})]) { try{let fexgjr = shapeyConstructor(a); print('EETT'); (void schedulegc(g2));}catch(e){print('TTEE ' + e); } }\nv2 = evalcx(\"/*ADP-1*/Object.defineProperty(a2, 4, ({get: function(y) { \\\"use strict\\\"; return  /x/  }, set: (x).apply, enumerable: (eval(\\\"v2 = r0.sticky;\\\"))}));\", g1);");
/*fuzzSeed-254361819*/count=824; tryItOut("mathy2 = (function(x, y) { return (Math.atan2((Math.log2(((y !== Math.max(Math.log2(y), x)) >>> 0)) >>> 0), (( + Math.sin(((((Math.max(x, ((x | 0) & -Number.MIN_VALUE)) + y) | 0) ^ x) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, -0x100000000, 0/0, Math.PI, -0x080000000, 0, Number.MIN_VALUE, 0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, -Number.MAX_VALUE, 0x07fffffff, 0x080000000, Number.MAX_VALUE, -0x100000001, 0x0ffffffff, 0x080000001, 1, 42, -0, 1.7976931348623157e308, -(2**53), -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 2**53, -(2**53+2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-254361819*/count=825; tryItOut("\"use strict\"; s0 = s0.charAt(16);");
/*fuzzSeed-254361819*/count=826; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.max((Math.hypot(( + ( ! ( + Math.hypot((((Math.imul(y, (( ~ (-1/0 >>> 0)) | 0)) >>> 0) + Number.MAX_SAFE_INTEGER) | 0), 1/0)))), ( - (Math.atan2(Math.imul(-0x080000001, Math.atan2(Math.fround(x), x)), 0.000000000000001) >>> 0))) >>> 0), Math.fround(mathy0(Math.fround(Math.asin(((Math.atanh((x | 0)) >>> 0) || ( - y)))), Math.fround(Math.fround(Math.acosh(((( + Math.cosh(Math.fround(y))) != Math.fround((y !== ( + y)))) >>> 0))))))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, function(){}, 5.0000000000000000000000, function(){}, function(){}, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, function(){}, function(){}, function(){}, 5.0000000000000000000000, function(){}, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, function(){}, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, function(){}, function(){}, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, function(){}, function(){}, function(){}, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, function(){}, 5.0000000000000000000000]); ");
/*fuzzSeed-254361819*/count=827; tryItOut("\"use strict\"; /*hhh*/function ocgazu(){print((Math.atan(e)));}ocgazu();");
/*fuzzSeed-254361819*/count=828; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0/0, 0, Number.MIN_VALUE, 2**53, -0x100000000, -0x07fffffff, -0x100000001, -1/0, -Number.MAX_VALUE, 0x0ffffffff, 1/0, 0x100000000, -(2**53-2), 42, Math.PI, -0x0ffffffff, Number.MAX_VALUE, -0x080000001, -(2**53+2), -0, 0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), 2**53+2, 0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 1, 1.7976931348623157e308, 0x080000001]); ");
/*fuzzSeed-254361819*/count=829; tryItOut("\"use strict\"; x([,,z1]) = x;");
/*fuzzSeed-254361819*/count=830; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.pow((Math.max((( + Math.max(Math.fround((Math.fround((( ! ( + (y | 0))) | 0)) * Math.fround(x))), Number.MIN_SAFE_INTEGER)) === (x ** (Math.atan2((Number.MAX_VALUE >>> 0), (x >>> 0)) >>> 0))), Math.imul((Math.max(y, (Math.imul(x, (x ? x : y)) >>> 0)) | 0), ((Math.fround(( ! ( + 0x080000000))) ? ( - -0x0ffffffff) : Math.sqrt(x)) | 0))) >>> 0), (((Math.min(( - (( ~ y) >>> 0)), Math.fround(Math.imul((-0x080000000 | 0), 1/0))) >>> 0) >> (Math.fround(( + Math.fround(-0x100000001))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1, [0], (new String('')), true, (new Boolean(true)), 0.1, /0/, (new Number(0)), 0, objectEmulatingUndefined(), NaN, '0', (new Boolean(false)), null, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), false, '/0/', (function(){return 0;}), -0, ({valueOf:function(){return '0';}}), undefined, (new Number(-0)), '', '\\0', []]); ");
/*fuzzSeed-254361819*/count=831; tryItOut("o2.a2.splice();");
/*fuzzSeed-254361819*/count=832; tryItOut("\"use strict\"; /*RXUB*/var r = (x) =  /x/g ; var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-254361819*/count=833; tryItOut("Array.prototype.pop.call(a2);");
/*fuzzSeed-254361819*/count=834; tryItOut("\"use strict\"; print(x);\na1 = t0[eval];\n");
/*fuzzSeed-254361819*/count=835; tryItOut("mathy4 = (function(x, y) { return ((((x == x) , Math.imul((((((y | 0) === -Number.MIN_VALUE) >= mathy1(y, Math.log2(-0))) ? ( ! x) : Math.fround(( ! Math.fround(Math.fround((Math.fround(Math.fround(mathy3(Math.fround(x), Math.fround(x)))) ^ Math.fround(1/0))))))) | 0), (Math.fround(( ! 1/0)) | 0))) >>> 0) ? (Math.min(((mathy1((Math.fround(Math.fround((x >> y))) | 0), Math.log10((Math.acosh(y) | 0))) | 0) == (x | y)), (Math.ceil(Math.atan2(y, mathy2(x, x))) >>> 0)) >>> 0) : ( + ( ~ Math.fround(( ~ (Math.min(2**53+2, x) | 0)))))); }); testMathyFunction(mathy4, [-0x080000000, 0x0ffffffff, 0x080000001, 2**53-2, -Number.MAX_VALUE, 1/0, 1.7976931348623157e308, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_VALUE, -0x100000001, Number.MIN_VALUE, 0/0, -(2**53+2), 2**53, Math.PI, -0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, -(2**53), 2**53+2, 0x07fffffff, 0x100000000, 0, -0x07fffffff, -0, 0.000000000000001, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=836; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((NaN) >= (+(((i1)-(i1)+(i1)) | ((0xfc9333bc)))));\n    d0 = (2305843009213694000.0);\n    d0 = (524289.0);\n;    d0 = (+abs(((Float32ArrayView[((-0x8000000)+(0xee5c2fb3)) >> 2]))));\n    return +((1.2089258196146292e+24));\n    d0 = (2147483648.0);\n;    return +((d0));\n  }\n  return f; })(this, {ff: function(y) { return (/*FARR*/[].map) }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000000, 0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 0x0ffffffff, 0.000000000000001, 0x100000000, -0, -Number.MIN_VALUE, 2**53+2, 0x080000000, Math.PI, -(2**53-2), 42, 0, 0/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 1/0, -(2**53), -1/0, 1, 1.7976931348623157e308, 0x100000001, 2**53, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=837; tryItOut("\"use strict\"; v1 = Array.prototype.every.call(g1.a1);");
/*fuzzSeed-254361819*/count=838; tryItOut(" '' ;z = window;");
/*fuzzSeed-254361819*/count=839; tryItOut("mathy4 = (function(x, y) { return (Math.atan2(Math.fround(Math.hypot(Math.fround(( + ( - Math.fround(y)))), (Math.atan2((Math.atan2(y, (x < Math.fround(Math.log1p(x)))) >>> 0), (Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) === (y >>> Math.max(x, y)))) >>> 0)) >>> 0))), ( + (( ! (Math.fround(Math.cos(Math.fround(Math.min(Math.fround((Math.fround(y) || Math.fround(-(2**53+2)))), (0.000000000000001 ^ x))))) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 2**53, -(2**53+2), -0x080000000, 0, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53-2, 42, 0x080000000, -0x100000001, Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, -1/0, 1.7976931348623157e308, 0/0, -0x100000000, -Number.MIN_VALUE, 0x100000000, -0x080000001, 2**53+2, 0x080000001, Math.PI, 1/0, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=840; tryItOut("\"use strict\"; let x = 'fafafa'.replace(/a/g, x = (x) = \"\\u3D96\"), NaN = ((uneval((undefined ^ window))).yoyo(function(y) { return \"\\uEFC7\" }.prototype)), x, x = (void shapeOf(eval|= \"\"  >> this)), rneamb, [[x], [, ]] =  '' .valueOf(\"number\"\u0009), {} = new  /x/g .prototype;print(a2);");
/*fuzzSeed-254361819*/count=841; tryItOut("\"use strict\"; i1 = new Iterator(e1);");
/*fuzzSeed-254361819*/count=842; tryItOut("([ '' ]);");
/*fuzzSeed-254361819*/count=843; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atanh(Math.fround(mathy0(( + ((( ! Math.fround(-Number.MIN_VALUE)) << Math.imul(((x && y) >= 0x080000000), 2**53)) | Math.fround(Math.min((((( + x) >> ( + y)) | 0) | (0x100000001 - 0x100000000)), Math.log2(x))))), Math.fround(( ! Math.fround(( ! Math.fround((Math.pow((((Math.fround((mathy0((0 | 0), (x | 0)) | 0)) & y) >>> 0) >>> 0), (-0x100000001 % -0x0ffffffff)) >>> 0))))))))); }); testMathyFunction(mathy1, [0, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000001, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 1, -0x0ffffffff, 2**53+2, -(2**53+2), 0x100000001, 0x0ffffffff, -(2**53), -Number.MIN_VALUE, 0/0, -0, -1/0, -0x080000001, -(2**53-2), 1/0, 42, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, 0x07fffffff]); ");
/*fuzzSeed-254361819*/count=844; tryItOut("/*RXUB*/var r = /((?!\\b)*?)?{4,4}/gyi; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-254361819*/count=845; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      (Float64ArrayView[(((([] = 24.prototype)))-(i0)-((((0x45ca53b2)) >> ((0xf99b37bd))) > (~((i1))))) >> 3]) = (((( '' )) / ((3.022314549036573e+23))));\n    }\n    i1 = (i1);\n    i1 = (i1);\n    i1 = (((+(1.0/0.0)) != (-1099511627777.0)) ? (i0) : (i0));\n    i1 = (((-0xeadbc*(i1))>>>((abs((((0x7f632c42) % (0x792856e8)) ^ ((i0)+(i1))))|0) / (((i1)) ^ ((i1)+(i0))))));\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: [[1]]}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-254361819*/count=846; tryItOut("mathy3 = (function(x, y) { return (Math.fround((Math.fround(Math.fround(Math.imul(y, Math.fround(((x >>> 0) | Math.imul(x, y)))))) < Math.fround(Math.cos((( ~ (x | 0)) | 0))))) ? (( + (( + (Math.asinh((( + (mathy1(((mathy2(x, (y | 0)) | 0) >>> 0), (0x0ffffffff >>> 0)) >>> 0)) >>> 0)) >>> 0)) << (( + Math.acosh(( + y))) ? Math.log(Math.clz32((2**53 >>> 0))) : (Math.asin((y >>> 0)) >>> 0)))) !== Math.fround(Math.fround(Math.asin(Math.fround(x))))) : Math.max(Math.pow(Math.fround((((((x | 0) < (y | 0)) | 0) / (Math.fround(x) || 0/0)) ? Math.pow(Math.min(x, 2**53+2), y) : (mathy1(x, (x === (x | 0))) >>> 0))), ((Math.pow((x | 0), ((mathy1(( + y), x) >>> 0) | 0)) | 0) >>> 0)), ( + (( + ( - ( ~ 0x100000001))) && ( + (( + x) ? (Math.hypot(Number.MIN_VALUE, Math.fround((x > ( + Math.clz32(x))))) | 0) : ( - x))))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -Number.MAX_VALUE, 2**53, -(2**53-2), 2**53-2, 2**53+2, -0x07fffffff, -0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x100000001, -(2**53), 1.7976931348623157e308, 0x07fffffff, -1/0, 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0, 42, -0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 0x080000000, 1, 0.000000000000001, -0x080000001, 0x0ffffffff, 0]); ");
/*fuzzSeed-254361819*/count=847; tryItOut("\"use strict\"; t1[(4277)] = (([]) = x);");
/*fuzzSeed-254361819*/count=848; tryItOut("for (var p in g0.m0) { for (var v of b0) { try { /*ADP-3*/Object.defineProperty(a1, v0, { configurable: true, enumerable: false, writable: false, value: f2 }); } catch(e0) { } try { g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (void options('strict')), noScriptRval: (x % 27 != 21), sourceIsLazy: true, catchTermination: (x % 58 == 52) })); } catch(e1) { } try { m0.has(f0); } catch(e2) { } v2 = g1.runOffThreadScript(); } }");
/*fuzzSeed-254361819*/count=849; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.888946593147858e+22;\n    (Int32ArrayView[(((0xfd790b40) ? (i1) : ((-0x56a0688) < (-0x8000000)))-(0xffffffff)) >> 2]) = ((0xf9636a8d)-(0xbb5eedcd));\n    return (((0x1095163e)))|0;\n  }\n  return f; })(this, {ff: (new Function(\"m0.toString = (function() { v0 = Object.prototype.isPrototypeOf.call(h0, b1); return g2; });\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, 2**53-2, 2**53, 1/0, 2**53+2, 0x07fffffff, 1, 0x080000001, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, 0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, -0x080000000, 0x100000001, 42, -0, -(2**53+2), 1.7976931348623157e308, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, -0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=850; tryItOut("testMathyFunction(mathy2, [0.000000000000001, -Number.MAX_VALUE, 0x0ffffffff, 0, 0x080000000, -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, 1, -0x100000000, Number.MAX_VALUE, -0x0ffffffff, Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 42, Number.MIN_VALUE, -0, -(2**53+2), -0x080000000, 1.7976931348623157e308, 0x080000001, 0/0, 0x100000001, -Number.MIN_VALUE, 2**53-2, -(2**53), -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=851; tryItOut("\"use strict\";  for (var a of RegExp(\"\\uB030\")) {{ void 0; try { gcparam('sliceTimeBudget', 50); } catch(e) { } } print(uneval(g1.m1));s1 += 'x'; }");
/*fuzzSeed-254361819*/count=852; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return (((i1)-(i0)+(i1)))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(tlhnbj){Object.freeze(this);return this; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[x, (4277), (void 0), x, x, (4277), (void 0), x, (4277), x, (4277), (4277), x, (4277), x, (4277), (void 0), (void 0), (4277), (4277), (4277), x, x, x, x, (4277), x, (void 0), (void 0), (4277), (4277), (4277), (4277), (4277), x, x, (4277), x, (4277), (void 0), x, (4277), (4277), x, x, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (4277), (4277), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (void 0)]); ");
/*fuzzSeed-254361819*/count=853; tryItOut("m1.delete(m0);");
/*fuzzSeed-254361819*/count=854; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g0, t0);");
/*fuzzSeed-254361819*/count=855; tryItOut(";");
/*fuzzSeed-254361819*/count=856; tryItOut("");
/*fuzzSeed-254361819*/count=857; tryItOut("if(function shapeyConstructor(rriarx){\"use strict\"; return rriarx; }) /*tLoop*/for (let a of /*MARR*/[]) { t1.valueOf = (function(j) { if (j) { try { g2.v0 = t0.length; } catch(e0) { } Array.prototype.unshift.apply(a2, [h0]); } else { try { t2 = this.a2[0]; } catch(e0) { } try { this.v0 = evalcx(\"function f0(g2) \\\"use asm\\\";   var ceil = stdlib.Math.ceil;\\n  var Infinity = stdlib.Infinity;\\n  var pow = stdlib.Math.pow;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    d1 = (-4398046511103.0);\\n    d1 = (d1);\\n    {\\n      d1 = (d1);\\n    }\\n    i0 = (i0);\\n    d1 = (+(0.0/0.0));\\n    i0 = (i0);\\n    d1 = (+ceil(((d1))));\\n    {\\n      i0 = (((((((68719476737.0) != (-3.8685626227668134e+25))+(0xfa030d64)) >> ((0xfcbcbcff)+(0xff73e0a4)-(-0x8000000)))) ? ((d1) + (((Infinity)) / ((Float64ArrayView[4096])))) : ((+(((0xfc226084)) << ((0xf819d807)))) + (+pow(((d1)), ((Float64ArrayView[4096])))))) != (d1));\\n    }\\n    switch ((((0xd3900124)+(i0))|0)) {\\n      default:\\n        i0 = (0xb190d8a9);\\n    }\\n    return +((-((-1.5474250491067253e+26))));\\n  }\\n  return f;\", g0); } catch(e1) { } this.m1 + ''; } }); }\n{}a1.unshift(\"\\u8643\");\n");
/*fuzzSeed-254361819*/count=858; tryItOut("\"use strict\"; i0 = e1.iterator;");
/*fuzzSeed-254361819*/count=859; tryItOut("\"use strict\"; { void 0; selectforgc(this); } (\"\\u15BB\");");
/*fuzzSeed-254361819*/count=860; tryItOut("\"use strict\"; print(o0);");
/*fuzzSeed-254361819*/count=861; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"gyi\"); var s = \"\\n\"; print(s.split(r)); ");
/*fuzzSeed-254361819*/count=862; tryItOut("\"use strict\"; for (var v of e2) { try { /*MXX2*/g0.Int32Array.length = this.o2.i1; } catch(e0) { } try { f2(o1); } catch(e1) { } s0 += o1.s0; }");
/*fuzzSeed-254361819*/count=863; tryItOut("/*MXX1*/o1 = g0.Array.prototype.values;");
/*fuzzSeed-254361819*/count=864; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((Math.expm1(( ! (Math.atan2(( + (y >> -1/0)), ( + (((2**53+2 | 0) == (y | 0)) | 0))) | 0))) >>> 0) === (( - ( + (( + (Math.cbrt(y) | 0)) - ( - ( + y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0x07fffffff, Number.MIN_VALUE, 0x100000001, 42, -(2**53), -0x100000000, Math.PI, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 2**53-2, -0x0ffffffff, 0x0ffffffff, -0, 1.7976931348623157e308, 0/0, 0, -0x080000000, 0x100000000, -0x080000001, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, -(2**53+2), 0x080000001, -Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, -0x100000001, 1/0]); ");
/*fuzzSeed-254361819*/count=865; tryItOut("print(23);");
/*fuzzSeed-254361819*/count=866; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.exp(Math.cbrt(mathy1(x, ( + ( + (Math.fround((Math.fround(y) % Math.fround(Math.atan2(Math.fround(x), y)))) > (((y >>> 0) , (y >>> 0)) >>> 0))))))) | 0); }); testMathyFunction(mathy2, [-(2**53), -0x07fffffff, 1, -0x080000000, 0x100000001, Math.PI, 0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, -(2**53+2), 2**53-2, -Number.MIN_SAFE_INTEGER, -1/0, 42, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, 0/0, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53-2), -0x100000000, -0, 0x07fffffff, 0x0ffffffff, -0x100000001, 0x080000001, 0, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-254361819*/count=867; tryItOut("mathy4 = (function(x, y) { return ( ~ (((Math.max(y, Math.fround(y)) | 0) ? ( ~ ( + Math.atan2((Math.ceil(((Math.min((y >>> 0), (x >>> 0)) >>> 0) | 0)) >>> 0), Math.atan2(x, x)))) : (Math.clz32(mathy3(((( + Math.asin(y)) / x) | 0), (( - (1/0 | 0)) | 0))) | 0)) | 0)); }); testMathyFunction(mathy4, /*MARR*/[(void 0), false, x, false, x, (void 0), true, (void 0), (void 0), (void 0), false, true, (void 0), (void 0), x, false, true, true, false, (void 0), (void 0), x, false, x, x, x, x, false, x, true, true, x, false, false, false, (void 0), x, x, true, x, x, true, (void 0), false, x, false, (void 0), x, x, (void 0), true, (void 0), (void 0), x, false]); ");
/*fuzzSeed-254361819*/count=868; tryItOut("var dezblt = new ArrayBuffer(4); var dezblt_0 = new Int16Array(dezblt); print(dezblt_0[0]); g2.toSource = f1;a0.__proto__ = p2;");
/*fuzzSeed-254361819*/count=869; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -68719476736.0;\n    return +((Float32ArrayView[(((0xe66fd657))) >> 2]));\n  }\n  return f; })(this, {ff: [] = Object.defineProperty(x, \"e\", ({configurable: true, enumerable: true}))}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 0x100000000, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, 42, -(2**53-2), -Number.MAX_VALUE, 0x080000001, -0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, 0x100000001, 0, -0x0ffffffff, 1/0, Number.MIN_VALUE, -1/0, 2**53-2, 0x0ffffffff, 0/0, -0, 0x07fffffff, 2**53+2, 1]); ");
/*fuzzSeed-254361819*/count=870; tryItOut("h2.__proto__ = f1;");
/*fuzzSeed-254361819*/count=871; tryItOut("\"use strict\"; L: v0 = g0.runOffThreadScript();");
/*fuzzSeed-254361819*/count=872; tryItOut("a2 + '';");
/*fuzzSeed-254361819*/count=873; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.trunc(((( + (0x080000000 && (Math.min(y, Math.exp(( + ( ~ x)))) >>> 0))) / ( + Math.pow((Math.pow(( + ((y | 0) !== y)), (Math.fround((Math.fround((-0x100000000 << (x | 0))) > Math.fround(x))) | 0)) >>> 0), (((Math.cbrt(( + y)) | 0) ^ (y >>> 0)) >>> 0)))) | 0))); }); testMathyFunction(mathy2, [-1/0, 1.7976931348623157e308, -0x080000000, -0x0ffffffff, 0x0ffffffff, 0x080000000, 0x07fffffff, 0/0, -0x100000001, -0, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1, 42, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 0.000000000000001, -0x080000001, 1/0, -(2**53), 2**53+2, 0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 2**53, Number.MIN_VALUE, 0]); ");
/*fuzzSeed-254361819*/count=874; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 4294967297.0;\n    var i3 = 0;\n    d2 = (d0);\n    /*FFI*/ff();\n    d1 = (+(((i3)-((!((0x462b835c) == (-0x8000000))) ? (/*FFI*/ff(((((-0x8000000))|0)), ((-36893488147419103000.0)), ((-1.5)), ((1.015625)), ((1125899906842625.0)), ((-33554431.0)), ((4294967296.0)), ((9.671406556917033e+24)), ((-0.0625)))|0) : (0x6577722e))+(0xc7dde2f6))>>>((0xf8772dd3))));\n    d1 = (d0);\n    {\n      d1 = (d0);\n    }\n    return +((Float64ArrayView[0]));\n  }\n  return f; })(this, {ff: 'fafafa'.replace(/a/g, mathy1).unwatch(\"length\")}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0, -(2**53+2), -0x100000000, Number.MIN_SAFE_INTEGER, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, Math.PI, 0x080000001, -0x080000000, 0x100000000, 1.7976931348623157e308, -0x080000001, 0x07fffffff, 0x0ffffffff, 2**53-2, 1, 2**53, 0, -Number.MAX_VALUE, 0x080000000, 0.000000000000001, -1/0, 42, -(2**53-2), -0x100000001, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=875; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.imul((( ! ((( - (((Math.cosh(x) >>> 0) ? (((x + ((Math.max(window, (y | 0)) | 0) | 0)) | 0) >>> 0) : ((Math.tanh(-0x100000001) | 0) >>> 0)) | 0)) | 0) >>> 0)) >>> 0), (( + (mathy1(( + x), 1.7976931348623157e308) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [2**53-2, -Number.MIN_VALUE, Math.PI, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 2**53+2, -0x100000000, 0x100000001, -Number.MAX_VALUE, -0x100000001, 42, 1/0, 0x07fffffff, -0, Number.MIN_VALUE, 1, -(2**53), 0, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, Number.MAX_VALUE, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, -0x080000000, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-254361819*/count=876; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=877; tryItOut("mathy4 = (function(x, y) { return Math.fround(mathy3(Math.fround((Math.fround((Math.fround(Math.atan2(( - (Math.acos(x) | 0)), x)) ? Math.fround((Math.pow(((( ! (( + (( + -0x100000001) > ( + Math.fround((y ** Math.fround(x)))))) >>> 0)) >>> 0) | 0), (( ~ Math.fround(-0x080000000)) | 0)) | 0)) : Math.fround(( - x)))) ^ (Math.fround((( + y) ? (Math.round((x / (((y >>> 0) ? (-0x100000001 >>> 0) : y) >>> 0))) === x) : x)) >>> 0))), Math.fround(Math.max(Math.fround((( + 0x100000000) >>> y)), Math.fround(Math.cosh(((-(2**53) === ( ~ 2**53+2)) | 0))))))); }); ");
/*fuzzSeed-254361819*/count=878; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (4096.0);\n    (Uint16ArrayView[((!(/*FFI*/ff(((~~(-2199023255551.0))), ((-262145.0)), ((36028797018963970.0)), ((-262143.0)), ((2049.0)), ((-2.4178516392292583e+24)))|0))+((0xfe54df1f) ? ((0x7a401c0e)) : (i1))-(i1)) >> 1]) = ((!((0xd656f9c5) ? (-0x8000000) : (/*FFI*/ff(((((0xe99c0c5f)+((0xada7ea39))) >> (0x68d7b*(0xf8263441)))))|0)))+(0xac3a7476));\n    {\n      d0 = (+abs(((d0))));\n    }\n    i1 = (0xec3adfc3);\n    return (((0xfc4aa15c)))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-254361819*/count=879; tryItOut("\"use asm\"; i0.next();");
/*fuzzSeed-254361819*/count=880; tryItOut("mathy5 = (function(x, y) { return Math.hypot(Math.pow(Math.fround((Math.tanh((((( + ( + -Number.MAX_VALUE)) >>> 0) ? (((Math.max((x >>> 0), x) - Math.cbrt(Math.fround(y))) >>> 0) >>> 0) : ((( - Math.fround(y)) >>> 0) >>> 0)) >>> 0)) >>> 0)), Math.fround((Math.fround(Math.fround(Math.min(( + Math.pow(( + ( + ( ~ ( + x)))), ( + (( - (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))), Math.fround(Math.min(mathy3(x, Math.fround(y)), 0.000000000000001))))) | Math.fround(x)))), (( + Math.hypot(mathy3(Math.fround(Math.log2(Math.fround(x))), (x << Math.sqrt(y))), (Math.min((y | 0), (Math.fround(( ! ((Math.acos((-Number.MAX_VALUE | 0)) | 0) | 0))) | 0)) | 0))) + Math.sqrt((Math.exp(Math.fround(Math.expm1(x))) ? (mathy2(x, mathy2(y, y)) >>> 0) : x)))); }); testMathyFunction(mathy5, [0x080000001, -0x0ffffffff, -0x07fffffff, 0x0ffffffff, -0, -0x080000000, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -0x080000001, 2**53, -0x100000001, -Number.MIN_VALUE, -1/0, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, Math.PI, 0x100000000, 0x080000000, 2**53+2, 0, 1/0, 0x07fffffff, 0.000000000000001, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-254361819*/count=881; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! ( + Math.max((mathy3(((((Math.log(( + Math.sqrt((x >>> 0)))) >>> 0) & x) < y) | 0), ((Math.hypot(((((Math.hypot(x, (y >>> 0)) >>> 0) * y) >>> 0) >>> 0), Math.fround(( ~ x))) >>> 0) | 0)) >>> 0), (Math.max(Math.fround(Math.atan2(x, ( + mathy3(Math.fround(((( + ( + Math.log2(Math.fround(y)))) , x) | 0)), Math.fround(Math.fround(( - Math.fround((mathy2(Math.fround(y), (-1/0 | 0)) | 0))))))))), ( + ( - (Math.log1p(x) >>> 0)))) | 0)))); }); testMathyFunction(mathy5, [NaN, (new Number(-0)), undefined, -0, (new String('')), '0', [], ({toString:function(){return '0';}}), null, '/0/', '', (function(){return 0;}), '\\0', true, 1, 0.1, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), /0/, (new Boolean(false)), (new Number(0)), [0], 0, (new Boolean(true)), ({valueOf:function(){return 0;}}), false]); ");
/*fuzzSeed-254361819*/count=882; tryItOut("/*hhh*/function niiroi(eval, x = null){g1.f2 = m0.get( \"\" );}/*iii*/false;");
/*fuzzSeed-254361819*/count=883; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return ( ! Math.fround(( + (( ! Math.fround(x)) === ( ! ( + ((Math.atan(Math.ceil(x)) >>> 0) ** x))))))); }); testMathyFunction(mathy1, [Math.PI, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, -(2**53-2), 42, -(2**53), -0x0ffffffff, -0x080000001, -Number.MIN_VALUE, 0x080000000, 2**53+2, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 0x100000001, 1.7976931348623157e308, 2**53-2, -(2**53+2), 0, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 0.000000000000001, -0x080000000, 0/0, 1, 0x080000001, 2**53, 0x0ffffffff, 0x07fffffff, -0]); ");
/*fuzzSeed-254361819*/count=884; tryItOut("const mvlwvc;(-5);");
/*fuzzSeed-254361819*/count=885; tryItOut("{ void 0; abortgc(); } i2 + i0;");
/*fuzzSeed-254361819*/count=886; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround((Math.fround(Math.fround(Math.cosh(Math.fround(Math.acos(( + x)))))) <= ( + (( + Math.ceil(( ! Math.fround(Math.log((( + x) | 0)))))) & ( + (Math.fround((Math.trunc((mathy0(x, Math.exp(x)) | 0)) >>> Math.ceil(x))) < ( + ( + Math.hypot((Math.fround(mathy0(Math.fround(x), ( ! (x >>> 0)))) ? (0x0ffffffff >>> 0) : Math.acos(((y | 0) % (1 | 0)))), ( + (y ? ( + -Number.MIN_VALUE) : Math.fround(Math.asinh(y))))))))))))); }); testMathyFunction(mathy1, [1, 0x100000001, -1/0, -0x100000000, 1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), 0/0, 2**53+2, 2**53, 0x0ffffffff, -0, 1.7976931348623157e308, 0x080000001, -0x080000000, 0, -(2**53+2), 2**53-2, 0.000000000000001, 42, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-254361819*/count=887; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.acos(( + Math.log(((Math.fround((Math.asin((-0 >>> 0)) >>> 0)) , Math.fround((x + 0.000000000000001))) >>> 0)))); }); testMathyFunction(mathy4, /*MARR*/[new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), x, x, x, x, new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), x, x, new Number(1), x, x, new Number(1), x, new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, x, x, x, x, x, x, new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, x, x, x, x, x, new Number(1), new Number(1), x, x, x, x, x, x, new Number(1), new Number(1), new Number(1), x, x, new Number(1), new Number(1), x, x, x, x, x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), x, x, x, new Number(1), new Number(1), x, x, x, x, x, x, x, new Number(1), new Number(1), new Number(1), x, x, x, new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), x, x, x, new Number(1), x, new Number(1), x, new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), x, new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, new Number(1), new Number(1), new Number(1), x, new Number(1), x, new Number(1), new Number(1), new Number(1), new Number(1), x]); ");
/*fuzzSeed-254361819*/count=888; tryItOut("\"use strict\"; for (var v of g1) { m0.delete(o1); }");
/*fuzzSeed-254361819*/count=889; tryItOut("mathy1 = (function(x, y) { return Math.abs(( + Math.atan2(( ! (x | 0)), ((y ? ( + Math.sinh(( + y))) : ( + y)) | 0)))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, Math.PI, -1/0, 2**53-2, -0x0ffffffff, -0x100000000, 1/0, -0x07fffffff, 0x07fffffff, 2**53, 42, 1.7976931348623157e308, 0x100000001, 0x080000000, -(2**53+2), -Number.MIN_VALUE, 0x080000001, 0.000000000000001, -0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, -0x080000001, 0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x100000000, -(2**53-2), 0/0, 1, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=890; tryItOut("x = t2;");
/*fuzzSeed-254361819*/count=891; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.atan2((Math.fround(( + Math.fround(mathy2(Math.fround(( + (mathy2(0.000000000000001, ((x % (x >>> 0)) >>> 0)) | 0))), Math.hypot(((((y >>> 0) - (Math.log(x) >>> 0)) >>> 0) | 0), x))))) | 0), (Math.fround((Math.max((y >>> 0), (( + x) >>> 0)) >>> 0)) % Math.fround(Math.min(Math.fround(Math.max((y ? x : Math.imul(y, (y >>> 0))), Math.cbrt(0x080000001))), Math.fround(Math.cos(x)))))) | 0); }); ");
/*fuzzSeed-254361819*/count=892; tryItOut("v1 = g2.r2.exec;");
/*fuzzSeed-254361819*/count=893; tryItOut("mathy5 = (function(x, y) { return ( + (((Math.tan((Math.sinh((Math.acos(x) | 0)) | 0)) | 0) ? ((( + mathy1(( + ( + (( + Math.fround((Math.fround(x) != Math.fround(x)))) ? x : ( + 0x0ffffffff)))), ( + (y ? -(2**53) : y)))) >>> Math.fround(Math.hypot(Math.fround((42 && ( + x))), Math.fround(( + mathy3(y, (Math.max(( + ( ~ (2**53 | 0))), (x >>> 0)) >>> 0))))))) | 0) : ( + Math.fround(Math.atan2((Math.max(x, x) ? x : ((( - Math.atan2(-0x07fffffff, (x | 0))) >>> (mathy3((y | 0), (x | 0)) | 0)) | 0)), ((( ~ y) | 0) | 0))))) | 0)); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0, Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 0x080000000, 0x07fffffff, 0x100000000, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 2**53, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, -0x07fffffff, 0x100000001, -(2**53+2), 2**53-2, -0x080000001, 0.000000000000001, -(2**53), 0/0, -1/0, 0x080000001, 42, 1, -Number.MIN_VALUE, Math.PI, 2**53+2]); ");
/*fuzzSeed-254361819*/count=894; tryItOut("mathy1 = (function(x, y) { return Math.log2(Math.fround((Math.trunc(x) - Math.fround(Math.pow(((((y | 0) && x) | 0) != (Math.min((mathy0(x, y) >>> 0), x) >>> 0)), Math.trunc(x)))))); }); testMathyFunction(mathy1, [-(2**53), 0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 0/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, -(2**53-2), 2**53+2, 0x100000001, 0x07fffffff, -(2**53+2), 1, 0.000000000000001, 42, 1/0, -Number.MIN_VALUE, Math.PI, -0x100000001, -Number.MAX_VALUE, 2**53, -0x100000000, 0x080000000, 0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, -0x080000000]); ");
/*fuzzSeed-254361819*/count=895; tryItOut("mathy3 = (function(x, y) { return mathy0(Math.atan2(Math.atanh(Math.trunc((Math.cos(Math.PI) >>> 0))), Math.pow((Math.atan2((Math.asinh(y) | 0), y) | 0), (Math.cosh(y) >>> 0))), (Math.fround(( + ( ! ( + Math.imul((Math.fround(mathy0(Math.tanh(y), y)) | 0), (Math.imul((Math.pow(x, x) | 0), Math.fround((Math.fround(x) != Math.fround(y)))) | 0)))))) != (((( + ( + ( + ( ! (( ~ y) >>> 0))))) >>> 0) << (Math.atan2((y >= (((Math.log10(( + 0x100000001)) | 0) || Number.MIN_VALUE) | 0)), ( + Math.exp(y))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0.000000000000001, 1, 0x0ffffffff, 0x080000001, 0x080000000, -1/0, -0x100000001, 0x100000001, -0, -(2**53-2), 1/0, Number.MAX_VALUE, -0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, 0/0, -(2**53+2), 0, -Number.MIN_VALUE, -0x07fffffff, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 0x100000000, 42, Number.MIN_VALUE, 0x07fffffff, 2**53]); ");
/*fuzzSeed-254361819*/count=896; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan2(Math.abs((Math.exp(y) === (( + (( + -Number.MIN_VALUE) != x)) ? ( + y) : (x , ( + ((( ~ x) | 0) + Math.fround(x))))))), Math.max(( ~ (( ! 0x080000001) * ( - x))), ( + (Math.fround(Math.imul(Math.fround(-0x100000001), Math.fround(( + Math.imul(Math.fround(Math.pow(Math.fround(x), Math.fround(( + ( - x))))), (-Number.MAX_SAFE_INTEGER === y)))))) | 0)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x100000000, 42, 1.7976931348623157e308, 0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, 0x080000001, -1/0, -Number.MIN_VALUE, 2**53+2, 0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 0.000000000000001, Math.PI, -(2**53), 1/0, 1, Number.MIN_VALUE, -0, 2**53, 0/0, -(2**53-2), -0x0ffffffff, 0x100000000, 0x080000000, -0x080000000, -(2**53+2)]); ");
/*fuzzSeed-254361819*/count=897; tryItOut("testMathyFunction(mathy2, [0x0ffffffff, 42, 2**53+2, -0, 0x07fffffff, -0x0ffffffff, -0x07fffffff, -0x080000001, 2**53-2, 0x100000000, -0x080000000, 0/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -Number.MIN_VALUE, -(2**53), Math.PI, Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, 0.000000000000001, -0x100000000, 1, -1/0, -0x100000001, 1/0, 0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=898; tryItOut("/*MXX1*/o1 = g2.Date.prototype.setUTCMinutes;function \u3056({NaN: [, [{NaN: [{y: {c: {y, \u3056}, x}, b, x: [{}, {x: {this.x: NaN}}], x: [, {\u3056: eval}, ]}, ], x: ((26)( /x/g ))}, [], [{x}, , , [, , ], , {NaN: [[[, ], , {}]]}], , {w, d, x: [], a}, ], , {}, [[], b]], x: z, x: [, ], b: [, , {z}], x: {x: [], x: NaN((uneval(new Uint32Array(true))) >>> eval(\"/* no regression tests found */\", z)), e: {NaN}}, x, x, x})x ^= xe2.has(i1);");
/*fuzzSeed-254361819*/count=899; tryItOut(" for (var c of window) Array.prototype.push.call(a1, t1, s1);");
/*fuzzSeed-254361819*/count=900; tryItOut("\"use strict\"; a2.splice(NaN, 0);");
/*fuzzSeed-254361819*/count=901; tryItOut("\"use strict\"; s2 + '';");
/*fuzzSeed-254361819*/count=902; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (((Float32ArrayView[2])) ? ((0xffffffff)) : (i1));\n    i1 = (i1);\n    (Int8ArrayView[4096]) = ((0xfd06586b));\n    d0 = (+((((((i1)-(!(-0x8000000)))>>>((0x1bbe303e)-(i1))) < (0x465f70df))-((0x71a9340f))) >> (((0x9fd2672d))-(i1))));\n    (Float64ArrayView[((!(i1))*-0xf3b8a) >> 3]) = ((+atan2(((d0)), ((65537.0)))));\n    i1 = (i1);\n    d0 = (((Float32ArrayView[1])) % ((+(0x3d2d3d1e))));\n    d0 = (d0);\n    (Int16ArrayView[2]) = ((0x1a52f920)-((((0xffffffff)) >> ((i1)+(0x8073a5e6))))-(0xd4f3f680));\n    i1 = (((33554433.0)));\n    i1 = ((((((i1)+((0xfc174caf) ? (0xfacf43bc) : (0x80a5d1b2))) << ((~((0x3f57e60a))))) / (0xc0cae4))>>>(((0.5) <= (1.03125))+(/*FFI*/ff(((d0)))|0))));\n    d0 = (Infinity);\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x0ffffffff, 0x07fffffff, 0x080000001, Number.MAX_VALUE, 2**53-2, 42, -(2**53), Math.PI, -(2**53+2), 0.000000000000001, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, 0x080000000, -1/0, -0, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 0, 2**53+2, 1, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, 1/0, -0x080000000, 0x100000000]); ");
/*fuzzSeed-254361819*/count=903; tryItOut("mathy4 = (function(x, y) { return ( ! (Math.min(Math.max((( + (Math.log(( + y)) >>> 0)) >>> 0), Math.fround(((-Number.MIN_VALUE >>> 0) == (x >>> 0)))), Math.clz32(Math.exp((( + (1 | 0)) | 0)))) | 0)); }); testMathyFunction(mathy4, [Number.MAX_VALUE, 2**53-2, 0x0ffffffff, -Number.MAX_VALUE, -0, -0x07fffffff, -0x080000000, Math.PI, 2**53+2, 1/0, -0x100000000, 1, -0x100000001, 0x07fffffff, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, 0x080000001, 1.7976931348623157e308, -(2**53), 0.000000000000001, -0x080000001, Number.MAX_SAFE_INTEGER, 42, -(2**53+2), 0, 0x100000000, Number.MIN_VALUE, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=904; tryItOut("\"use strict\"; v1 = evaluate(\"this.v1 = evaluate(\\\"h2 = t1[8];\\\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 63 == 40), noScriptRval: true, sourceIsLazy: (x % 2 != 0), catchTermination: (void options('strict_mode')) }));\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 34 != 15), noScriptRval: (x % 4 != 1), sourceIsLazy: (makeFinalizeObserver('tenured')), catchTermination:  /x/  }));");
/*fuzzSeed-254361819*/count=905; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(( + Math.fround((Math.fround(((((Math.fround(0x080000000) >= (y >>> 0)) | 0) ? (x | 0) : (x | 0)) | 0)) == (( + y) >> Math.max(y, -Number.MAX_VALUE)))))) ? (Math.min(( + Math.hypot((0x07fffffff >>> 0), (y >>> 0))), Math.fround(x)) ** Math.fround(( ~ Math.fround(-1/0)))) : Math.imul((Math.atan2(Math.fround(x), Math.fround((((y | 0) ^ (x | 0)) | 0))) + (Math.fround(Math.imul(Math.fround(-0x080000001), Math.fround(x))) | 0)), (( - Math.atan(Math.hypot(Math.sinh(y), (y >>> (Math.cbrt(y) | 0))))) >>> 0))); }); testMathyFunction(mathy0, [-0, 0x080000001, 2**53, 0x100000001, -0x080000000, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -(2**53-2), -0x07fffffff, 1/0, -(2**53), 1, 2**53+2, -0x0ffffffff, -1/0, 0, 0x0ffffffff, -0x080000001, 0/0, Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 0x07fffffff, -Number.MIN_VALUE, 42, Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-254361819*/count=906; tryItOut("v0.__iterator__ = (function() { try { g0.b0 = new SharedArrayBuffer(48); } catch(e0) { } try { for (var p in o2.p2) { try { a1.reverse(i1, o2.m1, p1, e1, a1); } catch(e0) { } try { i2 + b0; } catch(e1) { } try { s0 = Array.prototype.join.call(a1, s0); } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(i0, g2.o2); } } catch(e1) { } this.s0 + v1; return e1; });");
/*fuzzSeed-254361819*/count=907; tryItOut("( '' );");
/*fuzzSeed-254361819*/count=908; tryItOut("\"use strict\"; v2 = evalcx(\"print(b0);\", g2);");
/*fuzzSeed-254361819*/count=909; tryItOut("/*vLoop*/for (var qgwioy = 0; qgwioy < 65; ++qgwioy) { y = qgwioy; let (x =  /x/ , \u3056, d, c, {} = (4277)) { v2 = Array.prototype.reduce, reduceRight.call(a0, (function mcc_() { var ppjbrq = 0; return function() { ++ppjbrq; if (/*ICCD*/ppjbrq % 8 == 7) { dumpln('hit!'); try { g2.offThreadCompileScript(\"window()\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (y % 4 != 3), noScriptRval: false, sourceIsLazy: false, catchTermination: (y % 4 == 1) })); } catch(e0) { } try { b0 = new ArrayBuffer(19); } catch(e1) { } a1.shift(a1); } else { dumpln('miss!'); try { this.t1.set(t2, (-25() ^= /*UUV2*/(y.toString = y.getUint8))); } catch(e0) { } m0.has(s0); } };})()); } } ");
/*fuzzSeed-254361819*/count=910; tryItOut("\"use strict\"; \"use asm\"; Math;");
/*fuzzSeed-254361819*/count=911; tryItOut("testMathyFunction(mathy2, /*MARR*/[arguments, arguments, arguments, arguments, function(){}, arguments]); ");
/*fuzzSeed-254361819*/count=912; tryItOut("var ruruya = new ArrayBuffer(2); var ruruya_0 = new Uint8ClampedArray(ruruya); print(ruruya_0[0]); var ruruya_1 = new Float64Array(ruruya); var ruruya_2 = new Uint16Array(ruruya); print(ruruya_2[0]); var ruruya_3 = new Int32Array(ruruya); ruruya_3[0] = 13; var ruruya_4 = new Int32Array(ruruya); var ruruya_5 = new Int8Array(ruruya); print(ruruya_5[0]); m0.get(g0);v0 = (p1 instanceof s0);o0.a1.unshift(, s1, Math.imul([] ? Math.min(c, 2) : new RegExp(\"^?\", \"im\"), ( /x/g .prototype)), p2, v0, this.m2, i1, new (ruruya_3[0])() || (void options('strict_mode')));M:with({c: (void options('strict'))}){a2 = []; }v2 = Object.prototype.isPrototypeOf.call(g0, v0);");
/*fuzzSeed-254361819*/count=913; tryItOut("(x);");
/*fuzzSeed-254361819*/count=914; tryItOut("mathy3 = (function(x, y) { return Math.atan2((((x & Math.fround(Math.imul(Math.sin(0x100000000), (((y | 0) % ((x ? y : ( + Math.cosh(x))) | 0)) | 0)))) >>> 0) < Math.max(Math.min((y >>> x), (Math.fround((Math.fround(-0x080000000) >>> Math.fround(y))) < (Math.min((y | 0), ((( + 0/0) | 0) | 0)) | 0))), (Math.pow(y, ((Math.pow((0x100000000 | 0), ((y % x) | 0)) | 0) | ( + -0x080000000))) | 0))), ( + Math.fround(Math.pow((( ! (Math.fround(Math.atanh(Math.fround(y))) >>> 0)) >>> 0), y)))); }); testMathyFunction(mathy3, [0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 0/0, 0.000000000000001, Number.MAX_VALUE, 1, 1/0, -0, -(2**53+2), 2**53+2, 0x080000000, -1/0, -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), 2**53-2, Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, 42, 2**53, Math.PI, -0x07fffffff, -Number.MIN_VALUE, 0x080000001, 0, 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-254361819*/count=915; tryItOut("mathy1 = (function(x, y) { return (Math.fround(((( ~ (((0/0 * Math.max(x, ( + x))) | 0) ? ( + mathy0(y, ( + y))) : ((((Math.hypot(x, x) >>> 0) >= (y >>> 0)) >>> 0) ? ( + Math.log(( + y))) : (0x0ffffffff == -0x080000001)))) << ((x < -0x0ffffffff) >>> 0)) >>> 0)) === ( + Math.fround((( ! Math.cosh((0x100000000 >>> 0))) | 0)))); }); testMathyFunction(mathy1, [0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 1/0, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 0, 0.000000000000001, -0x100000001, Math.PI, 2**53, -0x080000000, -0x07fffffff, Number.MAX_VALUE, 42, 0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -0, -Number.MAX_VALUE, 0/0, 0x0ffffffff, -(2**53), -(2**53+2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, 0x080000001, -0x080000001, 0x100000001, 0x100000000]); ");
/*fuzzSeed-254361819*/count=916; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(g2, g0.v1);");
/*fuzzSeed-254361819*/count=917; tryItOut("var fxljol = new SharedArrayBuffer(32); var fxljol_0 = new Uint16Array(fxljol); print(fxljol_0[0]); fxljol_0[0] = -11; /*RXUB*/var r = r2; var s = s0; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=918; tryItOut("\"use strict\"; m1.__proto__ = e0;");
/*fuzzSeed-254361819*/count=919; tryItOut("\"use strict\"; /*bLoop*/for (qhefev = 0, w = (4277); ([w] = (4277)) && qhefev < 22; ++qhefev) { if (qhefev % 9 == 1) { t1.set(this.a1, this.v0); } else { a0.shift([1,,]); }  } ");
/*fuzzSeed-254361819*/count=920; tryItOut("x = e1;");
/*fuzzSeed-254361819*/count=921; tryItOut("for (var p in b0) { try { o0.e2 + b0; } catch(e0) { } a0 = new Array; }");
/*fuzzSeed-254361819*/count=922; tryItOut("x = (let (e) /*UUV2*/(a.setUTCDate = a.pop) % (void version(170))), zjwrin, window, e = (void shapeOf((d = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: /*wrap3*/(function(){ \"use strict\"; \"use asm\"; var wvuhwz =  \"\" ; ( \"\" .values)(); }), getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return false; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: new RegExp(\".+?|(?:(?:\\\\3))+\", \"gm\"), get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: d => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (i0);\n    }\n    return +((8388609.0));\n  }\n  return f;, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })( /x/g ), Set.prototype.delete))));a1[9] = m2;");
/*fuzzSeed-254361819*/count=923; tryItOut("\"use strict\"; let f2 = Proxy.create(g2.h0, o2);");
/*fuzzSeed-254361819*/count=924; tryItOut("if(intern(new RegExp(\"(?=\\u00f0(?![^])*?)[\\\\w]*?|[^]|\\\\xCC|$|$*|(?:.{1}){0,}|(\\\\W^\\\\b*?)|[^]?\", \"im\") && (this | \"\\u16B9\"))) { if ((arguments) =  /x/ ) print(x);} else {m2.get(g0);f2 = a0[3]; }");
/*fuzzSeed-254361819*/count=925; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i0)*-0x5717))|0;\n  }\n  return f; })(this, {ff: ((4277))(x)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [objectEmulatingUndefined(), undefined, false, ({toString:function(){return '0';}}), 0.1, '', (new Boolean(true)), ({valueOf:function(){return 0;}}), NaN, 1, [0], true, (new Number(-0)), (new Boolean(false)), null, -0, [], 0, (function(){return 0;}), (new String('')), '/0/', '0', /0/, (new Number(0)), ({valueOf:function(){return '0';}}), '\\0']); ");
/*fuzzSeed-254361819*/count=926; tryItOut("\"use strict\"; e2.add(b1);\n{}\n");
/*fuzzSeed-254361819*/count=927; tryItOut("Array.prototype.push.apply(a1, [g0, v1, o1.p2]);");
/*fuzzSeed-254361819*/count=928; tryItOut("\"use strict\"; h0.hasOwn = f0;function x(e, x, x, x, x, e, e, \"\\u20B6\", x, x, e, x, x, c, d, x = false, eval = -2, x = \"\\uCDB1\", x, __parent__, c =  '' , d = /(?!\\1*)/y, x, x, x, x, c, x = null, eval, x) { \"use strict\"; return -29 } this;");
/*fuzzSeed-254361819*/count=929; tryItOut("\"use strict\"; h0 = g1.a1[13];");
/*fuzzSeed-254361819*/count=930; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; try { startgc(2726495304); } catch(e) { } } void 0; }");
/*fuzzSeed-254361819*/count=931; tryItOut("mathy5 = (function(x, y) { return mathy4(((Math.fround((Math.fround((mathy4((42 % x), (y >>> 0)) >>> 0)) ? Math.fround(x) : Math.fround(y))) * (((x << (Math.min(Math.tanh(Math.fround(x)), (((0x100000001 >>> 0) ^ (x | 0)) >>> 0)) ? x : Math.fround(( ~ Math.fround(x))))) | 0) >>> 0)) === (Math.atan(mathy2((Math.tanh((x >>> 0)) >>> 0), Math.min(y, (Math.atan2(((( + x) >>> 0) | 0), (-(2**53+2) | 0)) | 0)))) | 0)), ((Math.atanh((( ~ (Math.fround(( ! Math.fround((( + (x | 0)) | 0)))) | 0)) | 0)) >>> 0) >>> 0)); }); ");
/*fuzzSeed-254361819*/count=932; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.fround((( + (y ? (y | 0) : (Math.hypot(Math.max(Math.PI, y), (( - x) >>> 0)) | 0))) & ( ~ Math.fround((Math.asin((y >>> 0)) ? Math.fround(x) : Math.fround(( + Math.max(( + (( - (y | 0)) >>> 0)), ( + x))))))))) ^ Math.fround((mathy3((Math.imul(((-Number.MIN_SAFE_INTEGER != (Math.imul(( + mathy3(y, (Math.exp(x) >>> 0))), (x | 0)) | 0)) | 0), ( + Number.MIN_SAFE_INTEGER)) >>> 0), (( - ( - (((Math.fround(Math.atan(( + 42))) >>> 0) ? x : y) | 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [-(2**53+2), Math.PI, -(2**53-2), 0/0, 0x07fffffff, -0x080000000, 2**53+2, -0x07fffffff, 0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, -0x100000000, -0x100000001, -0, 42, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, 0x100000000, 0.000000000000001, 2**53]); ");
/*fuzzSeed-254361819*/count=933; tryItOut("mathy0 = (function(x, y) { return (Math.max((( ~ ( + ( ! y))) | 0), ((Math.pow(Math.exp(y), (Math.fround(( ! (y , Math.min(x, y)))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy0, [1, -Number.MIN_VALUE, 0x100000000, 0x080000000, -0x080000001, 2**53-2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, -(2**53+2), -0x100000000, Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), 0x100000001, 0, -0x080000000, 1.7976931348623157e308, 0.000000000000001, Math.PI, 0x080000001, 2**53+2, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0/0, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, -0x100000001, -1/0, 0x0ffffffff]); ");
/*fuzzSeed-254361819*/count=934; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\1*?\", \"ym\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-254361819*/count=935; tryItOut("\"use strict\"; yield;\n(timeout(1800));\n");
/*fuzzSeed-254361819*/count=936; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( - Math.asin(Math.cos(Math.imul(x, x))))); }); testMathyFunction(mathy4, [0.000000000000001, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, 0x07fffffff, -(2**53), -0x080000001, -0x100000000, -0x0ffffffff, 0, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, -1/0, 0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, -0, 1.7976931348623157e308, -0x080000000, 2**53-2, 2**53, 0/0, 42, -Number.MIN_VALUE, Math.PI, -0x100000001, 0x100000000, -(2**53-2), 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-254361819*/count=937; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!$)/y; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-254361819*/count=938; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.abs((Math.max(Math.sign(y), -0.095) | 0))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, -0x100000000, 0x07fffffff, 2**53, 0x080000001, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, 0, Number.MIN_VALUE, 0x100000001, -0x080000001, 0.000000000000001, 0x080000000, -(2**53), 0/0, 2**53-2, -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, 1, -1/0, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -Number.MIN_VALUE, 42, 1/0, -(2**53+2), -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=939; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((Math.log2((x ^ 1/0)) === (Math.pow(Math.log1p(Math.fround(Math.hypot((x | 0), Math.fround((-0x100000001 / Math.min(0/0, (x | 0))))))), ( + Math.trunc(Math.pow(( + x), y)))) >>> 0)) >>> 0) < Math.max((( + (( ! Math.imul(((0x080000000 < ( + y)) + (( + (x | 0)) | 0)), (Math.abs(x) | 0))) | 0)) | 0), (x && (x | 0)))); }); testMathyFunction(mathy2, [0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_VALUE, Math.PI, 0/0, -(2**53), 0x100000000, -(2**53-2), -0, 42, -Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, -0x100000000, -0x080000000, 1, 0.000000000000001, 1/0, 2**53+2, 2**53, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, 2**53-2, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff]); ");
/*fuzzSeed-254361819*/count=940; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ((Math.atan2(Math.pow((( + (( + y) ? Math.tan(x) : x)) | 0), ( ~ Math.imul(x, y))), ( ! (( + x) || ( + (y ? Math.trunc(( + ( ~ y))) : x))))) | 0) | (((Math.ceil(( ! x)) | 0) ? (( ! x) | 0) : ((y ^ (mathy0(Math.fround(Math.pow(x, Math.fround(y))), (( ~ (-Number.MAX_VALUE >>> 0)) >>> 0)) >>> 0)) | 0)) | 0))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -0x080000000, -(2**53+2), -0x100000001, 1/0, 1, -0x07fffffff, -0x100000000, 0x0ffffffff, 0, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, -0, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 2**53, -0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, 2**53+2, -1/0, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 2**53-2, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-254361819*/count=941; tryItOut("mathy0 = (function(x, y) { return Math.atan2((( ! ( + ( ~ ( + Math.fround(Math.log2(Math.fround(Number.MAX_VALUE))))))) | 0), Math.hypot(Math.trunc(( + x)), Math.fround(Math.fround(Math.max(Math.fround(Math.fround(Math.hypot(( + Math.fround(Math.max((0x100000001 | 0), Math.fround(x)))), Math.fround(x)))), Math.fround(( + ( + ( + (((Math.log10(Math.fround(-Number.MIN_SAFE_INTEGER)) >>> 0) & Math.fround(x)) >>> 0)))))))))); }); testMathyFunction(mathy0, ['\\0', true, (new Boolean(true)), ({toString:function(){return '0';}}), '', (function(){return 0;}), (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(-0)), '0', false, 0.1, 1, objectEmulatingUndefined(), (new Number(0)), '/0/', undefined, [0], [], NaN, null, /0/, 0, -0, (new String('')), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-254361819*/count=942; tryItOut("v0 = (i2 instanceof g2);");
/*fuzzSeed-254361819*/count=943; tryItOut("mathy4 = (function(x, y) { return Math.fround(( + Math.fround(((Math.exp(((( + (-Number.MIN_SAFE_INTEGER | 0/0)) & y) >>> 0)) >>> 0) == (Math.tan((((y % y) <= x) >>> 0)) >>> 0))))); }); testMathyFunction(mathy4, [(new Boolean(true)), (function(){return 0;}), (new String('')), -0, ({valueOf:function(){return 0;}}), '/0/', [0], undefined, (new Number(-0)), [], '', objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), /0/, '0', 0.1, 0, (new Boolean(false)), ({toString:function(){return '0';}}), false, true, 1, (new Number(0)), '\\0', null, NaN]); ");
/*fuzzSeed-254361819*/count=944; tryItOut("e2 = t0[19];");
/*fuzzSeed-254361819*/count=945; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.cbrt(Math.imul(Math.atan2(Math.hypot(y, y), ( + Math.atan2(( + ( ! ( + -(2**53+2)))), ( + y)))), ( + ( + ( + ( ! Math.fround(Math.cos(y)))))))); }); testMathyFunction(mathy0, [(new Boolean(true)), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), -0, [], ({toString:function(){return '0';}}), (function(){return 0;}), 0, (new Number(0)), '', undefined, false, 1, ({valueOf:function(){return '0';}}), 0.1, true, '0', NaN, null, (new Number(-0)), '\\0', /0/, (new Boolean(false)), [0], (new String('')), '/0/']); ");
/*fuzzSeed-254361819*/count=946; tryItOut("/*tLoop*/for (let b of /*MARR*/[Number.MAX_VALUE, {x:3}, 0x2D413CCC, {x:3}, 0x2D413CCC, 0x2D413CCC, {x:3}, {x:3}, {x:3}, {x:3}, 0x2D413CCC, 2, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, Number.MAX_VALUE, 0x2D413CCC, 0x2D413CCC, Number.MAX_VALUE, 2, Number.MAX_VALUE, {x:3}, Number.MAX_VALUE, {x:3}, 0x2D413CCC, Number.MAX_VALUE, 0x2D413CCC, Number.MAX_VALUE, {x:3}, 2, 2, 2, 2, {x:3}, 2, Number.MAX_VALUE, {x:3}, 2, 0x2D413CCC, Number.MAX_VALUE, 0x2D413CCC, 2, {x:3}, {x:3}, 2, 0x2D413CCC, {x:3}, Number.MAX_VALUE, 0x2D413CCC, 0x2D413CCC, {x:3}, Number.MAX_VALUE, 0x2D413CCC, 0x2D413CCC, {x:3}, 2, {x:3}, {x:3}, 0x2D413CCC, Number.MAX_VALUE]) { e0.add(x); }");
/*fuzzSeed-254361819*/count=947; tryItOut("mathy4 = (function(x, y) { return ( ~ mathy1(Math.hypot(1.7976931348623157e308, (Math.max(((Math.min(mathy0(1.7976931348623157e308, -0x0ffffffff), Math.log(x)) | 0) >>> 0), (y >>> 0)) >>> 0)), ( ! (Math.max(((Math.acos(((( + -0x080000000) ^ ( + y)) | 0)) | 0) >>> 0), (0x100000001 >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [1/0, 0x100000000, 0x0ffffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -(2**53), 42, -0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, -Number.MIN_VALUE, -(2**53+2), 0, Number.MAX_VALUE, -0, 0/0, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, 0.000000000000001, 2**53, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), Math.PI, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-254361819*/count=948; tryItOut("o0.v0 = Object.prototype.isPrototypeOf.call(b2, a0);");
/*fuzzSeed-254361819*/count=949; tryItOut("\"use strict\"; Array.prototype.shift.apply(a2, []);");
/*fuzzSeed-254361819*/count=950; tryItOut("\"use asm\"; /*MXX2*/g0.RegExp.prototype.unicode = m1;");
/*fuzzSeed-254361819*/count=951; tryItOut("\"use strict\"; testMathyFunction(mathy4, [(new String('')), undefined, (new Number(0)), true, (new Boolean(true)), 0, ({toString:function(){return '0';}}), '\\0', [0], '/0/', (function(){return 0;}), (new Boolean(false)), NaN, '0', null, '', ({valueOf:function(){return '0';}}), false, -0, /0/, ({valueOf:function(){return 0;}}), (new Number(-0)), 0.1, [], 1, objectEmulatingUndefined()]); ");
/*fuzzSeed-254361819*/count=952; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.round(Math.fround(((((Math.sin(((Math.atan2(((y + -0x0ffffffff) | 0), (y | 0)) | 0) | 0)) >>> 0) >>> 0) & Math.min((((Math.imul(x, 2**53-2) | 0) >> (Math.fround(Math.asin((y | 0))) | 0)) | 0), ( - y))) >>> 0)))); }); ");
/*fuzzSeed-254361819*/count=953; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.atan2((Math.fround(((Math.pow(0x07fffffff, ( + Math.acosh(Math.sign(y)))) | 0) === (Math.trunc((mathy1((Math.asin(-0x080000001) >>> 0), (y >>> 0)) >>> 0)) | 0))) >>> 0), (Math.fround(Math.sinh((( + ( ~ ( + ( ~ ( - y))))) >>> 0))) ^ Math.fround(Math.log10(Math.fround(((Math.max(x, (Math.imul(Math.fround(mathy2(x, x)), x) >>> 0)) >>> 0) !== Math.hypot((( - (x ^ (y >>> 0))) >>> 0), x))))))); }); testMathyFunction(mathy3, /*MARR*/[4., 4., 4., 4.]); ");
/*fuzzSeed-254361819*/count=954; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-254361819*/count=955; tryItOut("m1.delete(g1.a2);");
/*fuzzSeed-254361819*/count=956; tryItOut("mathy0 = (function(x, y) { return Math.max((Math.max(( - 1), (Math.fround(( ! (x >>> 0))) ^ ( + (( + x) >> x)))) === Math.min(-0x07fffffff, Math.fround(Math.pow(y, Math.clz32(((x ? (-0x07fffffff | 0) : (Math.sign(( + y)) | 0)) | 0)))))), (Math.tanh(Math.log10(x)) | 0)); }); ");
/*fuzzSeed-254361819*/count=957; tryItOut("mathy4 = (function(x, y) { return Math.fround(mathy0(Math.abs(( ! (Math.expm1(Math.fround(Math.pow(Math.fround(y), Math.fround(Math.ceil(y))))) | 0))), Math.max((( + x) >>> 0), Math.pow(Math.min((Math.atan2((x | 0), (-Number.MIN_SAFE_INTEGER | 0)) | 0), ((Math.log1p(x) ? (( + Math.trunc(y)) >>> 0) : Math.imul(y, x)) >>> 0)), Math.fround(Math.max(( + Math.imul(0/0, y)), Math.fround(x))))))); }); ");
/*fuzzSeed-254361819*/count=958; tryItOut("[d, , , {d: {NaN: []}, x: [, , , ], x, -28, window}, [{}, , , {x: [[z, , , , ], [([, [{}]])], , x, [], {eval, x: y, x}], x: {x, x: {w: x, z: [x, , [], ], x}, window: {}, this, x: x}, x: [[, {x: x, x: [, {x, a: {}, x: {d, c: x}}, {x}, arguments[\"__iterator__\"]]}, [], ], w], \u0009NaN, x: x, e: z/*\n*/, x}], [{NaN: [{}, , , , ]}, , ], , , , ] = void new (function (e)this)(), x = (4277), x = x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(){}, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: undefined, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: function() { return undefined }, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(null), Object.defineProperty), x = x, d;M:switch(\"\\u7E97\") { default:  }");
/*fuzzSeed-254361819*/count=959; tryItOut("mathy4 = (function(x, y) { return Math.imul(Math.fround((Math.acos((false &= new RegExp(\"\\\\2|[^]\", \"yi\"))) > mathy2(Math.fround(mathy1(Math.PI, x)), ( ! -(2**53-2))))), (Math.expm1(((Math.pow(Math.fround(y), ( + Math.sin(Math.fround(x)))) | 0) | 0)) | 0)); }); ");
/*fuzzSeed-254361819*/count=960; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.acosh(( + Math.log(((( + ((x >>> 0) * y)) < (Math.imul((Math.round(x) >>> 0), (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)) | 0))))); }); testMathyFunction(mathy5, /*MARR*/[({x:3}),  \"\" , ({x:3}), true, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), true, true, arguments.caller, arguments.caller, arguments.caller, arguments.caller, true, arguments.caller, arguments.caller, new Number(1), true, true, true, true, true, true, true, true, true, true, true, true, ({x:3}),  \"\" , ({x:3}), true, arguments.caller, ({x:3}), arguments.caller,  \"\" ,  \"\" ,  \"\" ,  \"\" , new Number(1), new Number(1)]); ");
/*fuzzSeed-254361819*/count=961; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.acos(Math.fround(Math.fround(Math.min(Math.fround((Math.atan2(Math.max((y || 0x100000000), y), y) | 0)), Math.fround(Math.fround(Math.pow(Math.fround((x & ( - 1))), (( - x) >>> 0)))))))) | 0); }); testMathyFunction(mathy1, [0x0ffffffff, -0x100000001, -0, 1, 0/0, Math.PI, -(2**53-2), -0x0ffffffff, 2**53+2, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -(2**53+2), -1/0, 0x100000000, -0x080000001, 1/0, Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, 2**53-2, -0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-254361819*/count=962; tryItOut("mathy0 = (function(x, y) { return Math.sign(( + Math.atan2((Math.pow(Math.fround(y), x) ** Math.atanh(y)), (Math.asinh(Math.fround(y)) | 0)))); }); testMathyFunction(mathy0, [0x100000000, 1/0, -Number.MIN_VALUE, 0, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 0x100000001, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, 2**53, 0/0, -0x080000001, 42, Number.MIN_SAFE_INTEGER, 1, 0x080000001, -0, -0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 0x0ffffffff, 0x080000000, 0.000000000000001, -0x0ffffffff, -1/0, -0x100000001, -(2**53+2)]); ");
/*fuzzSeed-254361819*/count=963; tryItOut("\"use strict\"; m1.set(h1, /*FARR*/[].map);");
/*fuzzSeed-254361819*/count=964; tryItOut("a2.pop();");
/*fuzzSeed-254361819*/count=965; tryItOut("/*bLoop*/for (paedny = 0; paedny < 55; ++paedny) { if (paedny % 3 == 0) { print(x); } else { i0.next(); }  } function b(x, x, {NaN: {}, x, \u3056: d, b}, x = (/*MARR*/[(void 0), (void 0), (void 0), true, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0)]).eval(\"yield ({-3530575767: (4277),  set __count__() { \\\"use strict\\\"; print(this); }  });\"), x, z, eval, [], z, x, NaN, a, x, x, this.w =  \"\" , NaN, x, w, z, x, delete, x = length, x, x, x, c, e, c, z, e, x, w, b, x, \u3056 = -16, w)\"use asm\";   var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.1805916207174113e+21;\n    var i3 = 0;\n    var d4 = -140737488355329.0;\n    var d5 = -140737488355329.0;\n    var i6 = 0;\n    {\n      {\n        d5 = ((Int16ArrayView[1]));\n      }\n    }\n    return +((9.671406556917033e+24));\n  }\n  return f;/*oLoop*/for (klzxqb = 0; klzxqb < 75; ++klzxqb, ({})) { v0 = (i1 instanceof s2); } ");
/*fuzzSeed-254361819*/count=966; tryItOut("/*tLoop*/for (let b of /*MARR*/[function(){}, function(){}, (void 0), function(){}, function(){}, function(){}, (void 0), (void 0), function(){}, function(){}, function(){}, (void 0), function(){}, (void 0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (void 0), function(){}, function(){}, function(){}, function(){}, function(){}, (void 0), (void 0), (void 0), function(){}, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), function(){}, function(){}, (void 0), function(){}, function(){}, (void 0), function(){}, (void 0)]) { /*tLoop*/for (let y of /*MARR*/[function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}]) { print(b); } }");
/*fuzzSeed-254361819*/count=967; tryItOut("h1.get = f1;");
/*fuzzSeed-254361819*/count=968; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.pow(mathy1((Math.tan(( + ( ! y))) > (Math.ceil((Math.asinh((y >>> 0)) >>> 0)) >>> 0)), Math.fround(mathy1(Math.fround(x), Math.pow(__parent__: ((function a_indexing(ybmqql, zjgdmi) { ; if (ybmqql.length == zjgdmi) { ; return ybmqql; } var qwpotw = ybmqql[zjgdmi]; var sribra = a_indexing(ybmqql, zjgdmi + 1); Math.max(encodeURIComponent, x); })(/*MARR*/[new Number(1.5), objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, new Number(1.5), true, true, true, new Number(1.5), true, true, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), true, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), true, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), true, new Number(1.5), new Number(1.5), true, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), true, new Number(1.5), objectEmulatingUndefined(), true, true, new Number(1.5), true, new Number(1.5), new Number(1.5), new Number(1.5)], 0)), y)))), (( + ( ~ ( + ( - Number.MAX_SAFE_INTEGER)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x0ffffffff, -(2**53+2), 0x0ffffffff, -1/0, 0x080000000, 0x07fffffff, 0, -0x080000001, -Number.MAX_VALUE, -0, -(2**53), 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x080000000, 0x100000001, Math.PI, 2**53-2, 2**53, 0x080000001, 0.000000000000001, 0x100000000, -Number.MIN_VALUE, -0x100000000, 0/0, -0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=969; tryItOut("\"use strict\"; v0 = t0.byteLength;");
/*fuzzSeed-254361819*/count=970; tryItOut("/*iii*/v1 = Object.prototype.isPrototypeOf.call(i1, g1.b1);/*hhh*/function aryxxd(b = x){print(x);}");
/*fuzzSeed-254361819*/count=971; tryItOut("mathy2 = (function(x, y) { return Math.log2(Math.max((mathy1(((( + ( + Math.pow((y >>> 0), y))) >>> 0) | 0), (( ~ x) | 0)) | 0), Math.imul(x, Math.cosh(Math.fround(mathy1(x, Number.MIN_VALUE)))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), 0x080000000, -Number.MAX_VALUE, -0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, 0x100000000, 1.7976931348623157e308, 2**53, -Number.MIN_VALUE, 0.000000000000001, 1, Math.PI, -Number.MIN_SAFE_INTEGER, 0, -0x100000001, 0x0ffffffff, -1/0, -0x0ffffffff, 0x07fffffff, 1/0, -0x07fffffff, 0x080000001, -(2**53+2), Number.MAX_VALUE, 42, -0x080000000, Number.MIN_VALUE, -(2**53-2), -0x080000001, -0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=972; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.sinh((mathy1((( + Math.min(( + x), ( + (((( + ( ~ ( + x))) >>> 0) ? (x >>> 0) : y) >>> 0)))) | 0), (y | 0)) | 0))); }); testMathyFunction(mathy2, [-(2**53), -0x100000001, -0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, -0x080000001, -0x100000000, 0x080000001, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, Math.PI, Number.MIN_VALUE, 0x100000000, 2**53+2, -Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, 1, -1/0, 2**53, 0.000000000000001, 1/0, 0/0, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=973; tryItOut("this.v0 = t2.byteLength;");
/*fuzzSeed-254361819*/count=974; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-254361819*/count=975; tryItOut("/*infloop*/L:for(let [{eval: e, e, eval: c}, x, , , ] = (p={}, (p.z = !(((eval) = (x)())))()); x; (4277)) \u0009for (var v of f1) { try { print(uneval(v1)); } catch(e0) { } v2 = r1.constructor; }");
/*fuzzSeed-254361819*/count=976; tryItOut("/*RXUB*/var r = new RegExp(\"[^](?=(?=(\\\\b{1,})))[^]+\", \"gim\"); var s = \"\\u0081\\n\"; print(s.search(r)); ");
/*fuzzSeed-254361819*/count=977; tryItOut("v0 = t2.length;");
/*fuzzSeed-254361819*/count=978; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0(Math.min(Math.fround(Math.pow((0.000000000000001 | 0), x)), ( + Math.sin(Math.fround(Math.hypot(Math.fround(( + Math.clz32(( + Math.imul(Math.hypot(y, y), x))))), Math.fround(Math.fround((Math.fround(y) << x)))))))), Math.fround(( ! (x ? Math.fround(mathy0(Math.fround(2**53+2), Math.fround(x))) : Math.exp((( ! x) | 0))))))); }); testMathyFunction(mathy1, [-(2**53-2), 0x100000001, -(2**53), 0, -1/0, 2**53, -0x07fffffff, Math.PI, Number.MAX_VALUE, 1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, 42, -0x100000000, -0x080000000, -0x080000001, 2**53-2, 0x07fffffff, 0x080000000, 1.7976931348623157e308, 1, 0x080000001, 0/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -0x100000001, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), -0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=979; tryItOut("testMathyFunction(mathy4, [-0x100000001, Number.MIN_VALUE, -(2**53-2), 2**53-2, 42, -(2**53), 0.000000000000001, 1, 0x080000000, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, -0x080000000, -0x100000000, 0/0, -0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, Math.PI, -0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, Number.MAX_VALUE, 2**53, -(2**53+2), 1/0, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-254361819*/count=980; tryItOut("mathy1 = (function(x, y) { return ( + (( + Math.imul(( + y), (( + Math.max(( + ( - mathy0(mathy0(x, Number.MAX_SAFE_INTEGER), (( - y) | 0)))), Number.MIN_SAFE_INTEGER)) | 0))) === ( + mathy0(((( ! ( ! x)) >>> 0) / ( ! Math.fround(mathy0(Math.acosh(-0x07fffffff), ( + (-(2**53-2) > y)))))), (mathy0(mathy0(( /x/  , y), Math.fround(x)), Math.cos(( + y))) >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[-3/0, 0x10000000,  '\\0' , -3/0,  '\\0' ,  '\\0' , 0x10000000, 0x10000000, -3/0, 0x10000000, -3/0,  '\\0' , -3/0, -3/0,  '\\0' , 0x10000000,  '\\0' , -3/0, -3/0, 0x10000000, -3/0, -3/0,  '\\0' , -3/0, -3/0, -3/0, -3/0, -3/0,  '\\0' ,  '\\0' , -3/0, 0x10000000, -3/0,  '\\0' ,  '\\0' , -3/0, -3/0, -3/0, 0x10000000,  '\\0' , -3/0, 0x10000000, 0x10000000, 0x10000000, 0x10000000,  '\\0' , 0x10000000,  '\\0' ,  '\\0' , -3/0, -3/0, 0x10000000,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , -3/0, -3/0]); ");
/*fuzzSeed-254361819*/count=981; tryItOut("mathy3 = (function(x, y) { return mathy1(Math.fround((( + ((Math.sin(-Number.MAX_SAFE_INTEGER) >>> 0) | 0)) >>> 0)), (Math.asin(Math.min(x, ( + Math.pow(42, Math.fround((x ? Math.fround(Math.clz32(Math.fround(x))) : Math.PI)))))) >>> 0)); }); ");
/*fuzzSeed-254361819*/count=982; tryItOut("for (var v of i0) { var a2 = Array.prototype.slice.call(a2); }");
/*fuzzSeed-254361819*/count=983; tryItOut("print(x);\n(void schedulegc(g1));\n");
/*fuzzSeed-254361819*/count=984; tryItOut("Array.prototype.forEach.call(a1, (function() { h0.get = f1; return m0; }), v1, p2);");
/*fuzzSeed-254361819*/count=985; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy2((((((Math.pow(x, Math.max(Math.fround(0x100000000), y)) == (Math.fround(Math.pow(x, (mathy3(y, ( + x)) | 0))) >>> 0)) | 0) === (( ! -0x080000001) | 0)) | 0) | 0), Math.fround(((((( ~ (Math.fround((Math.fround(y) >>> ( + Math.hypot(x, y)))) >>> 0)) >>> 0) | 0) && Math.log2(x)) | 0))); }); testMathyFunction(mathy4, [[0], /0/, '0', true, 0, (new Boolean(true)), (new Number(0)), null, NaN, '/0/', [], (function(){return 0;}), objectEmulatingUndefined(), -0, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), false, '\\0', 0.1, undefined, '', 1, ({valueOf:function(){return '0';}}), (new Boolean(false)), (new Number(-0)), (new String(''))]); ");
/*fuzzSeed-254361819*/count=986; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, -(2**53+2), -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 0, 2**53, 0x100000001, -0x0ffffffff, 2**53-2, Math.PI, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, -0x07fffffff, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1, 42, Number.MIN_VALUE, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, -0x100000000, 0x0ffffffff, -0, -0x100000001, 0x080000001, Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-254361819*/count=987; tryItOut("\"use strict\"; (void schedulegc(g0));");
/*fuzzSeed-254361819*/count=988; tryItOut("mathy4 = (function(x, y) { return (( ! Math.min(Math.fround(mathy3(x, x)), (((( + x) | 0) > Math.abs(x)) | 0))) , Math.pow(Math.max(Math.log2(-Number.MAX_VALUE), 0x080000001), /*vLoop*/for (var lgaoca = 0; lgaoca < 67; ++lgaoca) { y = lgaoca; print(y); } )); }); testMathyFunction(mathy4, /*MARR*/[undefined, null, (1/0), new Number(1), new Boolean(true), new Number(1), null, undefined, new Boolean(true), (1/0), new Boolean(true), (1/0), new Number(1), null, new Boolean(true), undefined, new Number(1), (1/0), undefined, new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), undefined, undefined, new Number(1), undefined, null, new Boolean(true)]); ");
/*fuzzSeed-254361819*/count=989; tryItOut("selectforgc(o0);");
/*fuzzSeed-254361819*/count=990; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( - (Math.fround(Math.cosh(Math.pow((( ~ (Math.pow(Math.min(y, (y | 0)), y) | 0)) | 0), mathy4(-0x080000000, ( ~ Math.fround(((Math.fround(Math.fround(Math.atan2((x | 0), y))) | (x >>> 0)) >>> 0))))))) | 0)) | 0); }); testMathyFunction(mathy5, [2**53+2, 2**53, 0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, -Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, -0x080000001, -0, -0x100000001, -0x100000000, 2**53-2, Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, -1/0, 0x080000000, 0, 0/0, 0x0ffffffff, 42, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 0.000000000000001, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-254361819*/count=991; tryItOut("i1.__proto__ = p2;");
/*fuzzSeed-254361819*/count=992; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-(2**53+2), -Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, 0, -0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, 2**53-2, -1/0, 0/0, -0x100000001, -0x100000000, 0.000000000000001, Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, 42, 0x080000001, -Number.MIN_VALUE, 0x080000000, Math.PI, 0x100000000, -0x080000001, -(2**53), 1, -Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-254361819*/count=993; tryItOut("dxsavt, c, \u3056 =  /x/ , eval, eukyvb, x = x, \u3056 =  '' , \u3056;/*RXUB*/var r = /(((?!($\\B|[^]?.))(?=\\x4e)|([^]*)*?\\b{4,}|(?:([\\s]){2,2}){2,}))/yi; var s = \"B\\nB\\n\\n\\n\\n\\u4e2d\\u00d8a\\n\\u4e2d\\u00d8a\\n \\n\\n\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-254361819*/count=994; tryItOut("/* no regression tests found */");
/*fuzzSeed-254361819*/count=995; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (( ~ ( + ( + (( + (Math.hypot(( + ( + ( + ( + (( - (Math.fround(Math.sin(y)) | 0)) | 0))))), (x | 0)) | 0)) ** ( + ((x ? ((Math.fround(y) >= Math.fround(( + ( + y)))) | 0) : ( - y)) | 0)))))) | 0); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, Math.PI, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, 2**53-2, -0x07fffffff, 0x080000000, 42, -(2**53-2), 0x080000001, 0x100000001, -0x100000000, -0x080000000, 2**53, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0x100000000, -0x080000001, 0/0, 1/0, -Number.MIN_VALUE, 0, -0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, -0]); ");
/*fuzzSeed-254361819*/count=996; tryItOut("\"use strict\"; \"use asm\"; a2 = arguments;function d(e) { s0 += g1.s2; } this.a0 = [({x: x}) for (Set in x) for (e in ((x ? (4277).__defineSetter__(\"x\", Math.acos) : null) / (4277).setFloat64(-5))) for (x in (4277))];");
/*fuzzSeed-254361819*/count=997; tryItOut("f1 + '';");
/*fuzzSeed-254361819*/count=998; tryItOut("/*iii*/delete h0.keys;/*hhh*/function zjgfdb(eval, d, window, apply, x = delete NaN.x, d = x, x, y, window, z = new RegExp(\"(?:(\\\\b){3,7}|(?:\\u0084?))+?(?!(\\\\u00AC)).\", \"gy\"), \u3056, x, w, x, e, eval, d = d, x, d = this, \u3056, y, b, w, c = false, b, x, x, y = this, window, x, w, a, x, a, b, x = /(?!$)/, x, x, x, -1005397175, eval, y = -21, e, w = \"\\uE5A5\", b = window, x, w, x = \"\\u7FFC\", d, x = x, a, x, z, c, window, x, e, x, \u3056, b =  /x/g , w, x, x = /\\3/m, x, x, y, e, x =  /x/ , x, d, a, x, b, window, window, x, x, x, x, b, eval, x, NaN, x = this, a, e, y, x, b, x, x, b, \u3056, NaN, w, x =  /x/g ){/*oLoop*/for (svfdyh = 0; svfdyh < 67; ++svfdyh) { v0 = g2.runOffThreadScript(); } }");
/*fuzzSeed-254361819*/count=999; tryItOut("print(x);\np2.toString = f0;\n");
/*fuzzSeed-254361819*/count=1000; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (Infinity);\n    return ((((0x157ffe18) ? (0xa3176ac4) : (0xce65af09))-(0xa5a15b5e)))|0;\n    {\nwith(-29)f1 + i2;    }\n    (Float32ArrayView[1]) = ((+(-1.0/0.0)));\n    return (((0xdaf79e73)-(0x379a43dd)-((((/*FFI*/ff(((imul(((-0x8000000) ? (0x3347536b) : (0x3a43a4a4)), (0x5c9e607d))|0)), (((((9007199254740992.0)) - ((1.0078125))) + (d0))), ((imul((0xea2abd89), (0xffffffff))|0)), ((~~(17.0))), ((1048576.0)), ((4398046511104.0)), ((-2.3611832414348226e+21)))|0)) & ((0xfb3fd6db)+((((0x80648fdb)) | ((0xacb6add1))) < (abs((0x263267d9))|0)))))))|0;\n  }\n  return f; })(this, {ff: Object.getOwnPropertySymbols}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53-2), 0, -0x100000000, -1/0, -0, -0x080000000, 0.000000000000001, -0x07fffffff, -Number.MAX_VALUE, 2**53+2, 0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000001, 42, 1, -(2**53), 0x0ffffffff, -0x0ffffffff, -Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, 0x07fffffff, 0x080000000, 0x100000000, 0/0, 0x100000001, 1.7976931348623157e308, -(2**53+2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-254361819*/count=1001; tryItOut("\"use strict\"; v1 = (i2 instanceof b1);");
/*fuzzSeed-254361819*/count=1002; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-254361819*/count=1003; tryItOut("\"use strict\"; Object.prototype.watch.call(g0, 18, f2);");
/*fuzzSeed-254361819*/count=1004; tryItOut("\"use strict\"; ");
/*fuzzSeed-254361819*/count=1005; tryItOut("\"use asm\"; for (var p in s0) { try { this.t1[17] = 20; } catch(e0) { } try { this.v2 = (o1.s2 instanceof a1); } catch(e1) { } a0 = Array.prototype.concat.call(a1, t2, a0, a2, a0, o0.i2, g2, e2, v2); }\nthrow new RegExp(\"((?:${0,1}))(?!^{4,5})(?=(?!\\\\b+?)){3,7}+?\\\\xAf\", \"yi\");\n");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
