

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
/*fuzzSeed-451211*/count=1; tryItOut("v2 = g1.runOffThreadScript();");
/*fuzzSeed-451211*/count=2; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + Math.imul(( + mathy1(Math.log(Math.tanh((-1/0 | 0))), ((x | 0) >> (y | 0)))), ((Math.atan2((0x0ffffffff == Math.atan2(x, 0.000000000000001)), Math.atanh((((-Number.MIN_VALUE >>> 0) ? (Math.asin(0x100000001) >>> 0) : y) >>> 0))) | 0) | 0))) ? ( + ( - ((Math.atanh(((( ! ( + ( ! Math.fround((Math.fround(x) ? x : y))))) | 0) | 0)) | 0) >>> 0))) : ( + Math.fround(Math.trunc(Math.hypot(Math.fround(y), (Number.MIN_VALUE >>> 0)))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 0x080000001, 0x0ffffffff, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, 0.000000000000001, 0/0, 0x07fffffff, -(2**53+2), -0x0ffffffff, 2**53, -(2**53-2), -0x080000000, 42, 0, 1, -0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, 0x080000000, -0, 2**53+2, 0x100000000, -(2**53)]); ");
/*fuzzSeed-451211*/count=3; tryItOut("/*RXUB*/var r = /(?:(?=(?:\\s|\\3)(?=(?=\\d))*?(?:\\0)){0})|(?!.*)/yi; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-451211*/count=4; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(g0, \"findIndex\", { configurable: (x % 29 == 6), enumerable: true, writable: false, value: e0 });");
/*fuzzSeed-451211*/count=5; tryItOut("mathy4 = (function(x, y) { return Math.pow(Math.fround((Math.log(( + ( ! ( + ( + y))))) >>> 0)), (( - (Math.ceil(((((( ! -Number.MIN_VALUE) | 0) >>> 0) ? ((Math.sinh(Math.min(y, ((x ? -0x100000000 : ( + y)) | 0))) >>> 0) >>> 0) : (x >>> 0)) >>> 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-451211*/count=6; tryItOut("\"use strict\"; v0 = g0.runOffThreadScript();");
/*fuzzSeed-451211*/count=7; tryItOut("\"use strict\"; /*bLoop*/for (var plqrfo = 0; plqrfo < 2; ++plqrfo) { if (plqrfo % 5 == 1) { Array.prototype.pop.apply(a0, [o1.h2]); } else { neuter(this.b0, \"same-data\"); }  } ");
/*fuzzSeed-451211*/count=8; tryItOut("/*RXUB*/var r = /\\2/gym; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-451211*/count=9; tryItOut("m2.has(s0);");
/*fuzzSeed-451211*/count=10; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.cos(( + (((( + ( + (Math.ceil(y) | 0))) | 0) - Math.fround((Math.fround(Math.fround(Math.max((x | 0), Math.fround(y)))) > Math.fround((mathy0('', x) / y))))) >>> 0)))); }); testMathyFunction(mathy3, [-1/0, Number.MIN_VALUE, -0, -(2**53+2), 0.000000000000001, -(2**53), 0/0, 0x0ffffffff, -0x080000000, 0x080000001, 0, -0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, -0x080000001, 2**53+2, 1.7976931348623157e308, -0x100000000, 42, -0x07fffffff, 1/0, 0x100000000, 0x080000000, -0x0ffffffff, 0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -(2**53-2), Math.PI, 0x07fffffff]); ");
/*fuzzSeed-451211*/count=11; tryItOut("\"use strict\"; /*infloop*/M:for(c = (({ get prototype() { yield function(id) { return id } } ,  set \"5\" z (b)\"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    (Float32ArrayView[2]) = ((((Float64ArrayView[(((((1))>>>((arguments.callee.arguments ? false : new 'fafafa'.replace(/a/g, DataView.prototype.getInt16)(Date.prototype.setUTCHours, ({}) =  '' )))) != (((0x36e46050) / (0x0))>>>((-0x518c461)-((abs((0x38ebfbc0))|0)))))) >> 3])) % ((+(((-0x8000000))|0)))));\n    return +(((((((0xf8b9c5af) >= (0x8c31ed18))-((-0x8000000) >= (0x5ebdc91c))-(i0)) ^ (((((0x859d65ae)) ^ ((0x7b0bfceb))) < (((0xfb953a00)) << ((0xfb79b9be))))))) ? (+atan2((((i0) ? (-((\n\"\\u9681\" !== delete b.this.x))) : (1.9342813113834067e+25))), ((d1)))) : (+abs(((d1))))));\n  }\n  return f; })); (makeFinalizeObserver('tenured')); false) i1 = e2.values;");
/*fuzzSeed-451211*/count=12; tryItOut("var ehumlo = new SharedArrayBuffer(8); var ehumlo_0 = new Uint8ClampedArray(ehumlo); print(ehumlo_0[0]); m1.delete(h0);g0.s1.__iterator__ = (function() { try { g1.v2 = evalcx(\"o1.m1.delete(o2);\", g2.g0); } catch(e0) { } try { m0.set(g2, p1); } catch(e1) { } try { r0 = /\\1|.+?/gi; } catch(e2) { } Array.prototype.shift.apply(a2, [m1]); throw e1; });v0 = Array.prototype.reduce, reduceRight.apply(a2, [f2, g2, s2, g1.s1]);yield  \"\" ;return;print(ehumlo_0[1]);t2 = o2.t2.subarray(({valueOf: function() { neuterreturn 3; }}), []); '' ;e0.add(s1);a2 = r2.exec(o1.g1.s1);");
/*fuzzSeed-451211*/count=13; tryItOut("v2 = g0.eval(\"(void schedulegc(g0));\");");
/*fuzzSeed-451211*/count=14; tryItOut("\"use strict\"; /*RXUB*/var r = /((?=(?!(?=(?=\\b)\\1|.{2}|\\b)))|(?!(?=(?!(?:(?:^)[^]\u3b19)))){0,1})/gm; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-451211*/count=15; tryItOut("/*RXUB*/var r = /\\3/im; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-451211*/count=16; tryItOut("this.g0.p1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Int16ArrayView[((0x6418ff01)*-0xfffff) >> 1]) = ((0xf8f4c9fa));\n    {\n      {\n        (Float32ArrayView[0]) = (((-6.044629098073146e+23)));\n      }\n    }\n    {\n      d0 = (+((33554433.0)));\n    }\n    {\n      (Float32ArrayView[((!((imul((i1), (0x20c6190e))|0)))+(((((0x7b7216d9))+(!(0xc1668cc3)))>>>(x)))) >> 2]) = ((-7.737125245533627e+25));\n    }\nv2 = evalcx(\"function f0(i0)  { yield (x.__defineGetter__(\\\"e\\\", /*wrap1*/(function(){ (\\u3056);return decodeURIComponent})())) } \", g0);    {\n      i1 = (i1);\n    }\n    d0 = (147573952589676410000.0);\n    d0 = (-17592186044417.0);\n    {\n      d0 = (-34359738369.0);\n    }\n    switch ((~((!((0x56fb1bc9)))*0xfffff))) {\n      case 0:\n        i1 = ((abs(((((((0x246937b1)) >> ((0xe69c44d) / (0x71e58200))))*0xaf54f) | (-(0x668f696b))))|0));\n        break;\n      case 1:\n        i1 = (0xf0934dcb);\n        break;\n    }\n    {\n      i1 = (i1);\n    }\n    return +((((d0)) * ((3.094850098213451e+26))));\n  }\n  return f; });");
/*fuzzSeed-451211*/count=17; tryItOut("\"use strict\"; /*MXX1*/o1 = g0.TypeError;");
/*fuzzSeed-451211*/count=18; tryItOut("\"use strict\"; /*MXX1*/o0 = g2.g1.g0.g2.Date.prototype.setSeconds;");
/*fuzzSeed-451211*/count=19; tryItOut("mathy4 = (function(x, y) { return Math.fround(((( + mathy0(((Math.cbrt(((Math.asinh((Math.hypot(x, (( - x) | 0)) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0), ((y != Math.atan((y | 0))) | 0))) | 0) / Math.fround(( ~ Math.fround((((((0x0ffffffff >>> 0) ^ x) >>> 0) | 0) * (( ! (Math.max(Math.fround(Math.acos(y)), x) >>> 0)) | 0))))))); }); testMathyFunction(mathy4, [-1/0, -(2**53), 1.7976931348623157e308, 0x0ffffffff, 1/0, 1, 42, 2**53+2, 0, 0.000000000000001, 2**53-2, -0x080000000, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, -Number.MIN_VALUE, 0x100000000, 0x100000001, 0x080000001, -(2**53-2), -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, -0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -(2**53+2), 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 0/0, 2**53]); ");
/*fuzzSeed-451211*/count=20; tryItOut("this.a0.push(v2, o2.f2, x >>= (4277), yield ,  '' (q => q, (4277)));");
/*fuzzSeed-451211*/count=21; tryItOut("mathy4 = (function(x, y) { return Math.atan((Math.acos((( + ((Math.trunc((x | 0)) | 0) >>> 0)) >>> (Math.sign(Math.fround((( - (-0 >>> 0)) >>> 0))) | 0))) >>> 0)); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, 0x100000001, 2**53+2, -0x100000001, 1, 2**53-2, -(2**53+2), 0.000000000000001, -0x080000001, 0x080000001, 0x0ffffffff, -1/0, -(2**53), 0x080000000, Math.PI, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000000, 0, -Number.MIN_VALUE, 2**53, 0/0, -(2**53-2), -0x0ffffffff, -0x07fffffff, 1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 42]); ");
/*fuzzSeed-451211*/count=22; tryItOut("\"use asm\"; print(e2);");
/*fuzzSeed-451211*/count=23; tryItOut("a0.toString = (function() { try { m1.set(a2, f2); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(h0, v2); return g1; });");
/*fuzzSeed-451211*/count=24; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.min((Math.imul(Math.log(( + 2**53+2)), ( + ( ~ Math.fround(mathy3((( + Math.max(Number.MIN_VALUE, ( + Math.min(( + y), y)))) ? (Math.round((Math.min(-(2**53-2), y) | 0)) >>> 0) : x), Math.abs(Math.fround(y))))))) >>> 0), (Math.abs(( + (((( + Math.tan(( + Math.clz32(Math.fround(x))))) >>> 0) | ( + x)) | 0))) * (((Math.sqrt(Math.fround(Math.atan2(Math.fround(x), (Math.log(( ! y)) >>> 0)))) | 0) || (( - 1) | 0)) | 0))); }); testMathyFunction(mathy4, [0x0ffffffff, 0, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 1/0, 0x100000001, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, 1, 0x100000000, 2**53-2, -(2**53+2), 0.000000000000001, 0x080000001, 42, -0x100000001, 2**53+2, -0x07fffffff, -(2**53), Math.PI, 0x07fffffff, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, Number.MAX_VALUE, 0x080000000, 2**53, -0x0ffffffff, -0]); ");
/*fuzzSeed-451211*/count=25; tryItOut("Object.prototype.unwatch.call(o2.v2,  /x/ );");
/*fuzzSeed-451211*/count=26; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.max((Math.min(Math.fround(Math.log10((x | 0))), (Math.pow(-1/0, (Math.tan((x | 0)) | 0)) >>> 0)) | 0), ( + ((((Math.atan2((( + (x ? y : ( + x))) >>> 0), (y >>> 0)) >>> 0) >>> 0) === (( - y) | 0)) >>> 0)))) || (Math.hypot(( + Math.atan2(( + Math.hypot(Math.acosh(x), (Math.hypot(((x ? x : -Number.MIN_VALUE) | 0), (Math.sign((x >>> 0)) | 0)) | 0))), (Math.trunc(0/0) >>> 0))), ( + ( ! ( + y)))) | 0)); }); ");
/*fuzzSeed-451211*/count=27; tryItOut("\"use strict\"; /*RXUB*/var r = /([^][^]{4,5}|(\\b)|\\r[^7\\W]|(?=^*|[^])|(?!\u00b2){1,2}[^]|\\2*?(?=\\b){4,2097156}\\3|(?:\\b){3})|(?:(\\S?)|(?:\\)[\\cR\ua7b2-\\x38](?!.[^]{4,7})\\2+?{4,})|\\1|\\3\\2/yim; var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=28; tryItOut("\"use strict\"; o1.v1 = r0.multiline;");
/*fuzzSeed-451211*/count=29; tryItOut("this.i2.send(v2);");
/*fuzzSeed-451211*/count=30; tryItOut("\"use strict\"; a2.reverse(f0);");
/*fuzzSeed-451211*/count=31; tryItOut("mathy0 = (function(x, y) { return Math.min(Math.min((Math.max(((Math.expm1((y | 0)) | 0) >>> 0), (( ~ (y ** ( ! x))) >>> 0)) >>> 0), (( + Math.acos(( + ((-(2**53) ** y) , ( ~ (y | 0)))))) >>> 0)), Math.min(( + (( + (Math.asinh(x) | 0)) & ( + ((y | 0) / x)))), Math.trunc((Math.min(x, (y == 0.000000000000001)) ? (((x | 0) ^ 2**53+2) >>> 0) : y)))); }); ");
/*fuzzSeed-451211*/count=32; tryItOut("mathy1 = (function(x, y) { return ( ~ (( + ((( - (x | 0)) | 0) | 0)) > mathy0((( ~ ( ~ (Math.pow((x | 0), x) | 0))) | 0), (Math.fround(mathy0(Math.log10(x), Math.fround(((( + Math.pow(x, ( + y))) >>> 0) / Math.fround(( ~ x)))))) | 0)))); }); testMathyFunction(mathy1, [-0, 0x080000000, -0x0ffffffff, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000001, 1.7976931348623157e308, 0x100000001, Number.MAX_VALUE, -0x080000000, 0, -(2**53-2), -Number.MIN_VALUE, 1/0, 0.000000000000001, 2**53, Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, 0x080000001, -0x100000000, 0x100000000, -0x080000001, 0x0ffffffff, 2**53+2, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -1/0, 42]); ");
/*fuzzSeed-451211*/count=33; tryItOut("v1 = r1.global;");
/*fuzzSeed-451211*/count=34; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, 0x080000001, -0x080000000, -1/0, -0x100000001, -(2**53), 1, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE, 0/0, -0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, Math.PI, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -(2**53-2), 2**53, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -0x07fffffff, 0x100000000, 42, -0, -(2**53+2), 0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=35; tryItOut("\"use strict\"; i1.next();");
/*fuzzSeed-451211*/count=36; tryItOut("/*RXUB*/var r = r2; var s = s2; print(s.search(r)); ");
/*fuzzSeed-451211*/count=37; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(( ~ Math.tanh(Math.atan2(Math.fround(Math.cosh(( + ( + ( + Math.log2(( + y))))))), x)))); }); testMathyFunction(mathy1, [[0], ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), /0/, -0, true, (new Boolean(true)), (new Boolean(false)), (function(){return 0;}), '\\0', 0, '', (new Number(-0)), '0', undefined, null, false, (new String('')), ({toString:function(){return '0';}}), [], '/0/', 1, NaN, 0.1, (new Number(0)), objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=38; tryItOut("\"use strict\"; /*vLoop*/for (let qlanyf = 0; qlanyf < 1; ++qlanyf) { var a = qlanyf; print(a); } ");
/*fuzzSeed-451211*/count=39; tryItOut("m0.has(h2);");
/*fuzzSeed-451211*/count=40; tryItOut("Array.prototype.forEach.call(a1, o2);e = x = ((eval(\"[z1]\", Math.hypot(0, undefined))).__defineGetter__(\"x\", arguments.callee));");
/*fuzzSeed-451211*/count=41; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.max(( + Math.abs((Math.tan(y) * ( ! Math.ceil(x))))), (( ~ ( + ( ~ ( + (Math.atan2(((Math.PI <= x) >>> 0), (x >>> 0)) >>> 0))))) ** (x << y))) >>> 0); }); testMathyFunction(mathy4, [0.000000000000001, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, 1, 0x080000001, -(2**53), 0x100000001, Math.PI, 2**53-2, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, 2**53+2, 0x100000000, 1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -0x080000000, -0x080000001, -(2**53-2), -0x0ffffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 42, -0x100000000, -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53, -(2**53+2), -1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=42; tryItOut("\"use strict\"; /*infloop*/while({x: [, , [, , [x, ], ], , ]} = new RegExp(\"(?:(?!(?:(\\udd25))))|\\\\b|(?:${1}(\\\\s)|.|.{137438953471,}|\\\\B){2,}\", \"y\")){const b = yield (new WeakSet(b).__defineGetter__(\"d\", window));v0 = (void version(185)); }");
/*fuzzSeed-451211*/count=43; tryItOut("g2.a0.reverse(e0);");
/*fuzzSeed-451211*/count=44; tryItOut("/*oLoop*/for (let qxlblu = 0; qxlblu < 50; ++qxlblu) { m0.has(v2); } ");
/*fuzzSeed-451211*/count=45; tryItOut("\"use strict\"; \"use asm\"; print(uneval(this.g2.h2));");
/*fuzzSeed-451211*/count=46; tryItOut("o1.e1.has(s1);");
/*fuzzSeed-451211*/count=47; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.atanh(( + Math.fround(Math.acosh((Math.imul(y, -0) | 0))))) ** (((Math.min((Math.abs(0x0ffffffff) >>> 0), (y - (( - y) >>> 0))) | 0) || ((Math.fround(Math.fround(Math.cos(Math.hypot(y, y)))) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[true, {}, {}, true, {}, {}]); ");
/*fuzzSeed-451211*/count=48; tryItOut("h0 = e0;");
/*fuzzSeed-451211*/count=49; tryItOut("s2 += s2;function d(NaN, NaN) { \"use strict\"; /*RXUB*/var r = /^/g; var s = \"\\n\"; print(s.split(r));  } var (this.zzz.zzz = x).__proto__, x = \"\\u7670\", \u3056, x, a = c = /(?:(\\d[^]{3}{1}))+?/m, fzhits, lbtjxf, tdshrk;v0 = Object.prototype.isPrototypeOf.call(h2, this.s0);");
/*fuzzSeed-451211*/count=50; tryItOut("\"use asm\"; e2.add(i0);");
/*fuzzSeed-451211*/count=51; tryItOut("\"use strict\"; \"use asm\"; o0.s0 += 'x';");
/*fuzzSeed-451211*/count=52; tryItOut("\"use strict\"; const this.x, tdozfy, z, amfewc, b, NaN, x, eejfvt;Object.prototype.unwatch.call(g0, \"find\");");
/*fuzzSeed-451211*/count=53; tryItOut("mathy2 = (function(x, y) { return Math.fround(((Math.fround((Math.fround(y) ? Math.fround(x) : Math.fround(y))) ? ( + (Math.fround(( - (x >= y))) & ( + (( + x) != ( + x))))) : ( + Math.tanh(( + ( - Math.atan(y)))))) >> (((x !== ((Math.tan((x | 0)) | 0) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy2, [0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 0.000000000000001, -0, 0, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, 0x100000001, 42, 1.7976931348623157e308, -(2**53+2), -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, -Number.MAX_VALUE, Number.MAX_VALUE, 1, 0/0, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -(2**53), 0x100000000, -0x0ffffffff, -0x080000001, 2**53-2, -0x080000000, Math.PI]); ");
/*fuzzSeed-451211*/count=54; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=55; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=56; tryItOut("\"use strict\"; o1.g2.o0.a1.push(v2, i0);");
/*fuzzSeed-451211*/count=57; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( - mathy0(Math.sign(-Number.MIN_VALUE), (Math.hypot((( ! (Math.cosh(Math.imul((x >>> 0), -0x07fffffff)) >>> 0)) >>> 0), ((Math.sign(( + mathy0(Math.fround(Math.atan(x)), mathy1(y, Math.max(Math.fround(x), Math.fround(y)))))) | 0) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy2, [1, -0x100000001, -(2**53), 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, 0x100000001, -1/0, -(2**53-2), 0/0, 42, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0x080000001, -0x07fffffff, 1/0, -0, 0x100000000, -0x080000001, -0x080000000, -0x0ffffffff, Math.PI]); ");
/*fuzzSeed-451211*/count=58; tryItOut("mathy0 = (function(x, y) { return ( + (Math.fround(Math.fround(Math.log2(Math.fround(Math.abs(( + -Number.MAX_VALUE)))))) >> ( + ( + (( + (-0x080000000 >= (Math.log2(( + y)) >> ( + Math.pow(( + x), ( + y)))))) & Math.pow(x, x)))))); }); testMathyFunction(mathy0, [-0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 0x080000001, -1/0, 42, 0/0, 1, 0x080000000, 1/0, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 0.000000000000001, -0x080000000, -0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, -(2**53-2), -0x100000000, Math.PI, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 1.7976931348623157e308, -(2**53), 0x100000000, -0x080000001]); ");
/*fuzzSeed-451211*/count=59; tryItOut("\"use strict\"; Array.prototype.pop.apply(a1, [m1]);");
/*fuzzSeed-451211*/count=60; tryItOut("mathy1 = (function(x, y) { return ( - Math.fround(Math.imul(Math.fround(Math.fround(( ~ (((y | 0) ? (x | 0) : (mathy0(y, Number.MAX_VALUE) | 0)) | 0)))), Math.fround(Math.fround(((Math.min(x, (( - Math.fround((Math.fround((Math.sin(Math.fround(-0x100000000)) | 0)) <= Math.fround(y)))) >>> 0)) | 0) | (( + ((x ? Number.MIN_VALUE : Math.min(( + (( - x) >>> 0)), x)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy1, /*MARR*/[0.000000000000001, (void 0), objectEmulatingUndefined(), ['z'], objectEmulatingUndefined(), 0.000000000000001, 0.000000000000001, ['z'], (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ['z'], objectEmulatingUndefined(), (void 0), (void 0), 0.000000000000001, objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=61; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = (/*FFI*/ff(((yield \"\\u1D1F\").__defineSetter__(\"b\", decodeURI)), ((~~(((-137438953471.0)) / ((+/*FFI*/ff()))))))|0);\n    switch ((~((0x88ba4a38)+((-33554432.0) <= (2097151.0))))) {\n      case 0:\n        d1 = (d1);\n        break;\n    }\n    i0 = (i0);\n    {\n      d1 = (-1125899906842625.0);\n    }\n    {\n      d1 = (-2305843009213694000.0);\n    }\nprint(x);    {\n      return +(((295147905179352830000.0) + (+(-1.0/0.0))));\n    }\n    i0 = (i2);\n    return +((2097151.0));\n    return +((((+abs(((67108865.0))))) * ((Float64ArrayView[((0x7251b137)+(/*FFI*/ff(((~((imul((-0x8000000), (-0x8000000))|0) / (((0xff5445e5)) | ((-0x8000000)))))), ((1048577.0)), ((+(1.0/0.0))), ((+(-0x8000000))), ((268435457.0)))|0)) >> 3]))));\n  }\n  return f; })(this, {ff: Array.prototype.slice}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-451211*/count=62; tryItOut("o1.i2.send(e0);");
/*fuzzSeed-451211*/count=63; tryItOut("this.v1 = (v0 instanceof g1.t1);function y(...x) { /*MXX2*/g0.String.prototype.sub = g0.s0; } /*bLoop*/for (var xwfkzm = 0; xwfkzm < 48; ++xwfkzm) { if (xwfkzm % 20 == 17) { print(this.h0); } else { print((new [](((\"\\u84A8\".__defineSetter__(\"w\", neuter)) *= \u3056 !== c), this.__defineGetter__(\"x\", ({/*TOODEEP*/})))\u000c)); }  } ");
/*fuzzSeed-451211*/count=64; tryItOut("\"use strict\"; v2 = (this.h2 instanceof f1);");
/*fuzzSeed-451211*/count=65; tryItOut("i0.toSource = (function() { for (var j=0;j<5;++j) { f1(j%5==0); } });");
/*fuzzSeed-451211*/count=66; tryItOut("(Object.defineProperty(x, \"caller\", ({get: z, configurable: true})));");
/*fuzzSeed-451211*/count=67; tryItOut("var lmivbk = new ArrayBuffer(4); var lmivbk_0 = new Int32Array(lmivbk); lmivbk_0[0] = -13; var lmivbk_1 = new Int8Array(lmivbk); var lmivbk_2 = new Uint32Array(lmivbk); print(lmivbk_2[0]); lmivbk_2[0] = -26; var lmivbk_3 = new Float32Array(lmivbk); print(lmivbk_3[0]); lmivbk_3[0] = -3; a2.push(this.g0, i2, o0, g2, m2, g0.b2);/*ODP-3*/Object.defineProperty(i1, new String(\"1\"), { configurable:  \"\" , enumerable: \"\\uE5F8\", writable: \"\\u55D4\", value: o2 });print(lmivbk_3[0]);print(lmivbk_0);t0 = new Int32Array(b1, 32, /*UUV2*/(w.sub = w.getOwnPropertySymbols));v0 = (this.v0 instanceof f2);");
/*fuzzSeed-451211*/count=68; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.sign(Math.hypot(Math.min(Math.atan2(-0x080000001, x), (Math.fround((Math.fround(x) <= 2**53-2)) % x)), Math.fround((y != (Math.clz32((x | 0)) | 0))))); }); ");
/*fuzzSeed-451211*/count=69; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.max((Math.imul(Math.max((Math.log2((Math.pow(y, 0x100000001) | 0)) | 0), (Math.log10(( ! x)) | 0)), ( + Math.fround(( - Math.fround((x / (((y | 0) == x) | 0))))))) - mathy0(y, (Math.hypot(0x0ffffffff, x) >>> 0))), (((Math.fround(Math.fround(Math.fround((y ** x)))) >>> 0) * Math.clz32(mathy3(Math.atan2(( + Math.tanh((Math.fround((x >= y)) >>> 0))), x), (y > ( + Math.fround(Math.round(x))))))) >>> 0)); }); ");
/*fuzzSeed-451211*/count=70; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?!\\s)|[^\\xC9]|\\b{511,511}\\1|\\W*?[\\x52|-\u1f7f]|(?:[\u00d6].)*)+|(?=$+?)?/; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-451211*/count=71; tryItOut("\"use strict\"; a0 + b2;");
/*fuzzSeed-451211*/count=72; tryItOut("for (var p in this.f1) { try { g0.v0 = Object.prototype.isPrototypeOf.call(g2, t1); } catch(e0) { } s1.__proto__ = g0.v2; }");
/*fuzzSeed-451211*/count=73; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"((void options('strict_mode')))\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x.eval(\"testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, Math.PI, 0x100000001, -0x100000001, -Number.MIN_VALUE, 2**53+2, 0x100000000, 0, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 1, -0, -0x07fffffff, 0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, 42, -(2**53+2), 0x080000001, -0x100000000, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, Number.MIN_VALUE, -1/0, -0x080000001, 0.000000000000001, 0/0, -Number.MIN_SAFE_INTEGER]); \")), noScriptRval: (4277), sourceIsLazy: (x % 26 != 13), catchTermination: false }));");
/*fuzzSeed-451211*/count=74; tryItOut("\"use strict\"; g2.s2 + o2.a1;");
/*fuzzSeed-451211*/count=75; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53+2), -0x0ffffffff, Number.MIN_VALUE, -1/0, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, -(2**53-2), 0x080000001, -0x080000000, 0x100000000, 0, -0x100000000, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, 1, -0x07fffffff, 0x0ffffffff, -(2**53), 2**53-2, 0.000000000000001, 1.7976931348623157e308, 1/0, Math.PI, -0x080000001, -0, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-451211*/count=76; tryItOut("/*hhh*/function nmclpz(y, x){}/*iii*/(this);");
/*fuzzSeed-451211*/count=77; tryItOut("mathy2 = (function(x, y) { return (( + (( ! Math.hypot(( ! Math.asin(x)), ( + mathy0(x, 1/0)))) | 0)) | 0); }); ");
/*fuzzSeed-451211*/count=78; tryItOut("print(uneval(i0));");
/*fuzzSeed-451211*/count=79; tryItOut("\"use strict\"; v2 = a1.length;");
/*fuzzSeed-451211*/count=80; tryItOut("a2.unshift(a0, g0.i1);");
/*fuzzSeed-451211*/count=81; tryItOut("\"use strict\"; /*infloop*/ for  each(var this.zzz.zzz in allocationMarker()) {g0.offThreadCompileScript(\"for (var p in s2) { try { this.a2 = arguments; } catch(e0) { } a2 = Array.prototype.slice.call(a0, NaN, 16); }\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*RXUE*/((function sum_indexing(hfmwub, ouduzg) { print(x);; return hfmwub.length == ouduzg ? 0 : hfmwub[ouduzg] + sum_indexing(hfmwub, ouduzg + 1); })(/*MARR*/[w, objectEmulatingUndefined(), w, w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), w, w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, w, w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, w, w, w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), w, w, objectEmulatingUndefined(), w, w, w, objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), w, objectEmulatingUndefined(), w, w, objectEmulatingUndefined()], 0)).exec(\"\"), noScriptRval: (/*FARR*/[, \"\\uE191\", new RegExp(\"(\\\\d{3})\", \"ym\"), , , , , window].sort), sourceIsLazy: true, catchTermination: false })); }");
/*fuzzSeed-451211*/count=82; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 4.0;\n    d2 = (d1);\n    i0 = ((-0x8000000) ? ((((-0x8000000))>>>((i0)))) : ((Uint16ArrayView[1])));\n    d2 = (-3.094850098213451e+26);\n    {\n      d2 = (1.9342813113834067e+25);\n    }\n    (Float64ArrayView[1]) = ((d2));\n    d1 = (d2);\n    (Uint16ArrayView[0]) = (((Int16ArrayView[1]))*0x1be0f);\n    return +((d2));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var fnrpqc = x; var aurnne = Object.getOwnPropertyNames; return aurnne;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0/0, -1/0, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, -0x080000001, Number.MAX_VALUE, 0, -0, 2**53+2, 0x080000001, -(2**53), 2**53, -(2**53-2), -0x07fffffff, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 1, 2**53-2, -0x100000000, 42, 0x0ffffffff, -0x0ffffffff, 0x100000000, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=83; tryItOut("/*MXX2*/g1.Promise.name = v1;");
/*fuzzSeed-451211*/count=84; tryItOut("g0.v1 = (e1 instanceof p1);");
/*fuzzSeed-451211*/count=85; tryItOut("a2[16] = ((yield Proxy(Math.max(-15, x))));");
/*fuzzSeed-451211*/count=86; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy3(( + Math.pow(Math.tanh(Math.imul(( + x), ( + 0x080000000))), (( - (Math.fround(Math.atan2(Math.fround(-0x100000001), Math.fround(x))) | 0)) >>> (x / ( + Math.asinh(( + x))))))), ( ! (Math.min((x | 0), Math.tan(Math.round((( ~ y) | 0)))) >>> 0))); }); ");
/*fuzzSeed-451211*/count=87; tryItOut("\"use strict\"; o2.o2.a2.reverse();");
/*fuzzSeed-451211*/count=88; tryItOut("\"use strict\"; for (var p in v1) { try { t0.set(a2, 4); } catch(e0) { } try { o2.v2 = evalcx(\"x\", g1); } catch(e1) { } try { this.v1 = true; } catch(e2) { } g1.i2.next(); }");
/*fuzzSeed-451211*/count=89; tryItOut("Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-451211*/count=90; tryItOut("/*infloop*/for(x =  \"\" ; \"\\u448B\"; x) print(x);");
/*fuzzSeed-451211*/count=91; tryItOut("");
/*fuzzSeed-451211*/count=92; tryItOut("\"use strict\"; a1.splice(h2, m0, t2, this.i1);");
/*fuzzSeed-451211*/count=93; tryItOut("\"use strict\"; const b = Object.defineProperty(x, 19, ({configurable: false}));g1.toSource = (function() { try { this.e0.has(((void options('strict')))); } catch(e0) { } try { i0.send(a0); } catch(e1) { } o0.o0.i2 + ''; throw h2; });");
/*fuzzSeed-451211*/count=94; tryItOut("g1.m2.get(o2);");
/*fuzzSeed-451211*/count=95; tryItOut("/*oLoop*/for (let neafxu = 0; neafxu < 48; ++neafxu) { a0 = []; } ");
/*fuzzSeed-451211*/count=96; tryItOut("\"use strict\"; with({y: ((x))})var usllhz = new SharedArrayBuffer(6); var usllhz_0 = new Uint8Array(usllhz); usllhz_0[0] = -10; var usllhz_1 = new Int8Array(usllhz); print(usllhz_1[0]); usllhz_1[0] = 7; var usllhz_2 = new Uint8Array(usllhz); print(usllhz_2[0]); usllhz_2[0] = -11; var usllhz_3 = new Int32Array(usllhz); v2 = false;/*bLoop*/for (var qzjxxu = 0; qzjxxu < 1; ++qzjxxu) { if (qzjxxu % 3 == 1) { print( /x/ ); } else { throw -13; }  } v0 = a0.every((function() { f1 + ''; return g1; }));");
/*fuzzSeed-451211*/count=97; tryItOut("testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000000, objectEmulatingUndefined(), new String(''), new String(''), new String(''), -0x080000000, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000000, objectEmulatingUndefined(), -0x080000000, objectEmulatingUndefined(), -0x080000000, -0x080000000, objectEmulatingUndefined(), true, true, new String(''), new String(''), -0x080000000, true, new String(''), objectEmulatingUndefined(), -0x080000000, objectEmulatingUndefined(), true, new String(''), -0x080000000, true, new String(''), true, true, true, true, objectEmulatingUndefined(), true, objectEmulatingUndefined(), -0x080000000, true, -0x080000000, true, objectEmulatingUndefined(), true, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, true, objectEmulatingUndefined(), new String(''), true, -0x080000000, true, new String('')]); ");
/*fuzzSeed-451211*/count=98; tryItOut("/*bLoop*/for (let wzalgt = 0; wzalgt < 23; ++wzalgt) { if (wzalgt % 4 == 1) { delete h1.getOwnPropertyDescriptor; } else { return  /x/ ;continue L; }  } ");
/*fuzzSeed-451211*/count=99; tryItOut("mathy0 = (function(x, y) { return (Math.trunc((Math.abs((y + (( + Math.pow(( + x), Math.fround(( ! x)))) > ( + (Math.min(Math.fround(2**53), x) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0.1, (new Number(0)), (new Boolean(false)), [0], false, [], (function(){return 0;}), true, objectEmulatingUndefined(), '', ({valueOf:function(){return '0';}}), '\\0', ({valueOf:function(){return 0;}}), NaN, ({toString:function(){return '0';}}), undefined, (new Boolean(true)), 1, /0/, (new Number(-0)), '/0/', 0, -0, (new String('')), '0', null]); ");
/*fuzzSeed-451211*/count=100; tryItOut("f1 + m1;");
/*fuzzSeed-451211*/count=101; tryItOut("testMathyFunction(mathy4, [-0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 0/0, 0x0ffffffff, 2**53, -(2**53-2), -0, -Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, 1/0, -(2**53), 2**53+2, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 1, 42, -0x07fffffff, 2**53-2, 0x07fffffff, 1.7976931348623157e308, 0x080000000, 0, -0x100000001, -0x100000000, 0.000000000000001, -Number.MAX_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=102; tryItOut("bpdcqw(window);/*hhh*/function bpdcqw(\u3056, z, x, x, [], x, eval =  \"\" , x = x, x = this ?  \"\"  :  /x/ , /*UUV1*/(d.toUpperCase = encodeURI).__proto__, x = 6, x = (4277), x = 8, x, x, NaN = \"\\uBBDA\", NaN = function ([y]) { }, \u3056, x, x, NaN, d, x, eval, z, e, delete, x, d, b = false, x, x, x, \u3056, d =  /x/ , x, x, y, a, y, c, x = \u3056, \u3056, x, a, x, d, x, NaN, b = new RegExp(\"(?![^]){0}(?!(?!.))|(?:[\\u00e3\\\\u00aE-\\u67cb\\\\\\u45a5-\\\\\\u5601]|\\\\b)*?|(^*)?\", \"y\"), x, e, b, eval, d = true, NaN, x =  /x/ , d, a, x, x, NaN, e = -19, x = window, NaN, x, w, x = true, w, b = undefined, x = \"\\uAA68\", x, -19, d = e,  /x/ ){p0.__iterator__ = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) { x = a0 % x; a15 = 0 * 4; var r0 = 0 / a11; var r1 = a3 & a3; var r2 = a0 + 1; var r3 = a15 * a13; a0 = r0 % 5; var r4 = a9 ^ r0; var r5 = 3 - r2; a1 = 9 | a9; var r6 = x / a11; var r7 = r0 - a8; var r8 = 1 & a15; return a10; });}");
/*fuzzSeed-451211*/count=103; tryItOut("function(id) { return id };");
/*fuzzSeed-451211*/count=104; tryItOut("testMathyFunction(mathy3, [-0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, -1/0, Math.PI, -0x080000000, 0x100000000, -0, 2**53-2, -(2**53+2), -0x100000000, 0, Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, 0x100000001, -0x080000001, 0/0, 0x080000001, 2**53, 42, -Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, -(2**53), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=105; tryItOut("a0.shift();");
/*fuzzSeed-451211*/count=106; tryItOut("mathy4 = (function(x, y) { return ( ~ (Math.tanh(( + Math.sin(( + (( + ((x | -0x080000000) | 0)) * ( + ( + Math.pow(( + Math.fround(Math.sqrt(Math.fround(0x0ffffffff)))), ( + 0.000000000000001))))))))) | 0)); }); ");
/*fuzzSeed-451211*/count=107; tryItOut("y = 'fafafa'.replace(/a/g, eval);/*bLoop*/for (tjzdip = 0; tjzdip < 149; ++tjzdip, new RegExp(\"[^\\\\xE4\\\\S\\u92a2-\\uff14]\", \"gy\")) { if (tjzdip % 5 == 0) { print(x); } else { b; }  } ");
/*fuzzSeed-451211*/count=108; tryItOut("this.zzz.zzz;Object.preventExtensions(this.g1);");
/*fuzzSeed-451211*/count=109; tryItOut("mathy5 = (function(x, y) { return ((Math.fround(Math.fround(Math.min(((mathy4(Math.fround(( + (Math.fround(y) ? Math.fround(y) : Math.fround(Math.ceil(x))))), -0x080000001) ? ( + Math.fround(( ~ (x | 0)))) : y) | 0), (Math.atanh((-Number.MAX_SAFE_INTEGER && x)) >>> 0)))) | 0) != Math.tan(( + (Math.tanh((-(2**53) >= ( + y))) + ( + ( ! (Math.fround(Math.tanh(Math.fround(x))) % ((y , (Number.MAX_SAFE_INTEGER | 0)) | 0)))))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -0, -0x0ffffffff, 0x0ffffffff, -(2**53), 1.7976931348623157e308, 42, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, -0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, 0, 1, -Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 0/0, 0x100000001, Math.PI, 0x080000001, 2**53+2, -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, -0x080000001, -(2**53+2)]); ");
/*fuzzSeed-451211*/count=110; tryItOut("\"use strict\"; print(new Math.asin(window)(\n '' ));");
/*fuzzSeed-451211*/count=111; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.max((( + ( ! mathy2(Math.fround((Math.fround(x) > Math.fround(y))), (( + Math.pow(x, (x >>> 0))) | 0)))) >>> 0), (mathy1(( + Math.log10(y)), ( + Math.exp((Math.fround((Math.fround(Math.expm1(0.000000000000001)) & Math.fround(y))) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -0, Number.MAX_VALUE, 2**53-2, -0x080000001, 0x100000000, -Number.MAX_VALUE, 1, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, -0x080000000, -(2**53+2), 42, 0.000000000000001, 0x07fffffff, -0x100000001, -0x100000000, 1/0, -0x0ffffffff, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000001, -1/0, 2**53+2, 0, -(2**53), 0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=112; tryItOut("g2.v2 = (t1 instanceof f0);");
/*fuzzSeed-451211*/count=113; tryItOut("\"use strict\"; this.v2 = t2.length;");
/*fuzzSeed-451211*/count=114; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = newGlobal({  }); f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; \na1[\"\\uB4C2\"];\n");
/*fuzzSeed-451211*/count=115; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1((Math.atan(((mathy0((x >>> 0), ( + mathy0(Math.min(mathy1((y | 0), x), Math.fround(( + Math.imul(( + y), ( + ( ~ y)))))), ( ~ x)))) >>> 0) | 0)) >>> 0), ((mathy0(( ~ y), (Math.log(y) / ( + (-0x100000001 | 0)))) | 0) | 0)); }); ");
/*fuzzSeed-451211*/count=116; tryItOut("print((4277));");
/*fuzzSeed-451211*/count=117; tryItOut("/*tLoop*/for (let b of /*MARR*/[new Number(1), new Number(1), false, false, new Number(1), new Number(1), false, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), false, false, false, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), false, false, new Number(1), new Number(1), false, false, new Number(1)]) { i2.send(a2); }");
/*fuzzSeed-451211*/count=118; tryItOut("\"use strict\"; h2.has = (function() { try { g1.v0 = g2.eval(\"e1.add(h2);\"); } catch(e0) { } try { a2.__proto__ = e2; } catch(e1) { } v1 = r2.flags; return g0; });");
/*fuzzSeed-451211*/count=119; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( - ( + (Math.max((Math.tanh(Math.fround(y)) ^ x), ( + (Math.imul(y, y) | 0))) ? Math.imul(Math.fround(( ~ ( + (Math.expm1((y | 0)) | 0)))), ( + ( + (y >>> 0)))) : (Math.imul(x, (mathy1(x, y) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [1, 0x080000001, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53), -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x100000001, 0, 1/0, 0/0, -1/0, -0, 2**53+2, 42, 0x100000000, 2**53-2, 0.000000000000001, -(2**53-2), 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, -Number.MIN_VALUE, 0x0ffffffff, -0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000]); ");
/*fuzzSeed-451211*/count=120; tryItOut("\"use strict\"; {/*ODP-3*/Object.defineProperty(b0, \"seal\", { configurable: false, enumerable: (x % 3 != 0), writable: Boolean((makeFinalizeObserver('nursery'))), value: p2 });print(x); }");
/*fuzzSeed-451211*/count=121; tryItOut("/*oLoop*/for (ubytvu = 0; ubytvu < 0; ++ubytvu) { a1.splice(13, 13, m2); } m2 + b1;");
/*fuzzSeed-451211*/count=122; tryItOut("mathy1 = (function(x, y) { return (Math.atan((((( + ( - ( + ( + ( + ( + ( + Math.cos(x)))))))) <= (y ? y : y)) ? Math.fround((Math.fround(mathy0(y, x)) + Math.fround(Math.sign(x)))) : Math.fround(Math.atan2(Math.imul((((Math.fround(((y | 0) ? x : (y | 0))) >= ( + Math.min(( + x), x))) >>> 0) | 0), (( ~ (Math.max(Math.PI, x) >>> 0)) >>> 0)), y))) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 1, 1/0, Number.MAX_VALUE, -0x100000001, -0x080000000, 0x07fffffff, 0/0, -(2**53+2), -0x080000001, 1.7976931348623157e308, -(2**53), 0.000000000000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), -0x07fffffff, -0x100000000, 2**53, -0x0ffffffff, 0x080000000, 2**53+2, -Number.MIN_VALUE, 2**53-2, 0, 0x100000000, Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-451211*/count=123; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return (((( + ( + (( + ((x | 0) | (Math.imul((y >>> 0), Math.tanh(Number.MIN_SAFE_INTEGER)) >>> 0))) >>> (Math.acosh((x | 0)) | 0)))) | 0) , (mathy0(((( + (y | 0)) | 0) === mathy0(y, 0x100000001)), ( + mathy0(( + Math.pow(((Math.ceil(Math.fround(-0x100000001)) >>> 0) | 0), (Math.fround(Math.max(x, y)) || ( + y)))), (Math.log1p((( ~ x) | 0)) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-451211*/count=124; tryItOut("with({c: (decodeURI.prototype)}){;v1 = Array.prototype.reduce, reduceRight.call(a0, (function mcc_() { var jtabdd = 0; return function() { ++jtabdd; f0(/*ICCD*/jtabdd % 10 == 3);};})(), o1,  \"\" , this.h2, t1); }");
/*fuzzSeed-451211*/count=125; tryItOut("v0 = evaluate(\"(++x)\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: decodeURI, delete: Element, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function(q) { return q; }, enumerate: offThreadCompileScript, keys: undefined, }; })([1,,]), [[]] = Proxy.createFunction(({/*TOODEEP*/})(-16), function shapeyConstructor(rdytff){delete this[\"toString\"];if (rdytff) delete this[\"toString\"];return this; }, function  a (a)\"\\uFE3A\")), noScriptRval: true, sourceIsLazy: (x % 20 != 8), catchTermination: (x % 4 == 2) }));");
/*fuzzSeed-451211*/count=126; tryItOut("window;");
/*fuzzSeed-451211*/count=127; tryItOut("print(x);");
/*fuzzSeed-451211*/count=128; tryItOut("/*hhh*/function ybozsd(x){a2[({valueOf: function() { (Math.hypot(false, \"\\uF8B6\"));return 9; }})] = i0;}ybozsd();");
/*fuzzSeed-451211*/count=129; tryItOut("\"use strict\"; let(x = x) { x.lineNumber;}");
/*fuzzSeed-451211*/count=130; tryItOut("let(w) { w.name;}throw StopIteration;");
/*fuzzSeed-451211*/count=131; tryItOut("\"use strict\"; m2.set(e1, t0);");
/*fuzzSeed-451211*/count=132; tryItOut("testMathyFunction(mathy5, [0.000000000000001, Number.MIN_VALUE, -(2**53), 2**53+2, -0, Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -(2**53-2), 0/0, 2**53, 0, 0x080000000, -0x100000001, 1, 1/0, -0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -0x080000001, -1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), 0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-451211*/count=133; tryItOut("\"use strict\"; o1 = f1.__proto__;");
/*fuzzSeed-451211*/count=134; tryItOut("mathy3 = (function(x, y) { return Math.pow((((( ! (Math.imul(Math.fround(mathy2(Math.fround(0x080000001), (Math.atan2(y, y) === (x | 0)))), ((((( + Math.max(-0, y)) >>> 0) ? (-Number.MAX_SAFE_INTEGER >>> 0) : (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) | 0)) >>> 0)) >>> 0) ** (Math.fround(mathy2(y, ( + mathy1(( + x), ( + (( + ( + ( + y))) * Number.MAX_VALUE)))))) >>> 0)) >>> 0), (( ~ (( ~ ((Math.ceil(y) | 0) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy3, [-1/0, 42, 0x07fffffff, -0x100000001, 0x080000001, 0x0ffffffff, 0/0, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, 0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, 2**53, -(2**53+2), -(2**53), -0x080000001, 2**53-2, Number.MAX_VALUE, 1/0, 0x080000000, -0x100000000]); ");
/*fuzzSeed-451211*/count=135; tryItOut("/*RXUB*/var r = /(?=\\s)+|(?:(?!\\B{1})*)|$|\\B(?:\\B)?|^\\1\\u9C87([^\u153f-\u9133\\xC7-\\xF1\\v]|\\cY)|\\B|\\W*?/y; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-451211*/count=136; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, -0x080000001, -0x100000001, 2**53, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0x080000000, -(2**53+2), -(2**53), -Number.MIN_VALUE, -1/0, 1, -0, -0x080000000, Number.MAX_VALUE, 42, -(2**53-2), Math.PI, 2**53-2, -0x100000000, 0.000000000000001]); ");
/*fuzzSeed-451211*/count=137; tryItOut("new \u3056((/*RXUE*//(?:(?!\\W\\2)+)/gm.exec(\"\")));");
/*fuzzSeed-451211*/count=138; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log10(( + mathy2(( + Math.atan(Math.fround(Math.max(Math.min(((x <= Math.fround(( + (( + y) | ( + 0x100000000))))) | 0), Math.min(x, x)), x)))), ( - ((((Math.fround(x) !== (( ! (x ? (1.7976931348623157e308 >>> 0) : (0x080000000 >>> 0))) | 0)) | 0) < x) | 0))))); }); testMathyFunction(mathy3, /*MARR*/[ \"\" ,  \"\" ,  /x/g ,  \"\" , arguments.caller, new String('q'), arguments.caller,  \"\" ,  \"\" ,  /x/g ,  /x/g , arguments.caller, new String('q'), arguments.caller,  /x/g , new String('q'),  \"\" ,  /x/g , arguments.caller,  \"\" , arguments.caller, new String('q'),  \"\" ,  /x/g ,  \"\" ,  /x/g , arguments.caller,  /x/g ,  \"\" ,  /x/g ,  \"\" ,  \"\" ]); ");
/*fuzzSeed-451211*/count=139; tryItOut("mathy3 = (function(x, y) { return (( - Math.fround(Math.hypot(Math.fround(Math.cosh((Math.fround(Math.imul(Math.fround((( + (Math.atanh(( + -(2**53))) >>> 0)) >>> 0)), ( - Math.fround(y)))) >>> 0))), ((Math.ceil((-Number.MIN_SAFE_INTEGER | 0)) * y) >>> 0)))) | 0); }); testMathyFunction(mathy3, [0/0, -0x080000001, Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0.000000000000001, -(2**53), -1/0, Number.MAX_VALUE, -(2**53-2), 42, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, -(2**53+2), -0x07fffffff, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 1/0, Number.MIN_SAFE_INTEGER, 1, -0x100000001, 0x100000000, 2**53, -0x100000000, 0x080000000, -0, 2**53+2]); ");
/*fuzzSeed-451211*/count=140; tryItOut("\"use strict\"; yield ( '' .exec(Math) / (void version(170)));");
/*fuzzSeed-451211*/count=141; tryItOut("new (4277)().__defineSetter__(\"x\", (Math.atan2(-25, -21)));");
/*fuzzSeed-451211*/count=142; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=143; tryItOut("\"use strict\"; /*FARR*/[( /x/g  | -20)].filter;");
/*fuzzSeed-451211*/count=144; tryItOut("\"use strict\"; t2 = t1.subarray(19, 11);");
/*fuzzSeed-451211*/count=145; tryItOut("testMathyFunction(mathy4, [0x100000001, 42, 0x080000001, 2**53-2, -1/0, -(2**53+2), -Number.MAX_VALUE, 0x07fffffff, 2**53+2, -0x0ffffffff, 0x080000000, -(2**53), Math.PI, 0/0, 0.000000000000001, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, -0x080000000, Number.MIN_VALUE, -0x100000001, 1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-451211*/count=146; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=147; tryItOut("mathy0 = (function(x, y) { return (Math.clz32(Math.fround(( ~ Math.fround(((( ! (/*MARR*/[y, y, y, (void 0), (void 0), (void 0), y, y, (void 0), y, y, y, (void 0), y, y, y, y, y, y, y, y, y, y, y, y, (void 0), y, y, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), y, y, y, y, (void 0), y, y, (void 0), y, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), y, (void 0), (void 0), y, (void 0), (void 0), y, (void 0), y, (void 0), (void 0), (void 0), y, (void 0), y, (void 0), (void 0), (void 0), (void 0), (void 0), y, y, y, y, y, y, y, (void 0), y, y, y, (void 0), y, y, (void 0), y, y, (void 0), y, (void 0), y, y, (void 0), y, (void 0), y, (void 0), (void 0), y, (void 0), (void 0), (void 0), y, y, y, y, y, (void 0), y, (void 0), y, (void 0)].map(Object.isSealed, window))) - (x >>> 0)) >>> 0))))) >>> 0); }); ");
/*fuzzSeed-451211*/count=148; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-451211*/count=149; tryItOut("t2 = new Float64Array(4);");
/*fuzzSeed-451211*/count=150; tryItOut("this.b0 = t2.buffer;");
/*fuzzSeed-451211*/count=151; tryItOut("\"use strict\"; /*MXX3*/g1.Object.prototype.propertyIsEnumerable = g0.Object.prototype.propertyIsEnumerable;");
/*fuzzSeed-451211*/count=152; tryItOut("\"use strict\"; L: for  each(let w in (4277)) v0.toString = DataView.prototype.setFloat32;");
/*fuzzSeed-451211*/count=153; tryItOut("while(((4277)) && 0){o2.g0.offThreadCompileScript(\"s1 += 'x';\");new RegExp(\"\\\\1\", \"yi\"); }");
/*fuzzSeed-451211*/count=154; tryItOut("\"use strict\"; m0 = new Map;");
/*fuzzSeed-451211*/count=155; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 2.4178516392292583e+24;\n    var d3 = 16385.0;\n    var d4 = 9.44473296573929e+21;\n    var d5 = 2305843009213694000.0;\n    var i6 = 0;\n    var d7 = 2049.0;\n    (Int32ArrayView[1]) = ((Int8ArrayView[0]));\n    d3 = (d2);\n    d7 = (d4);\n    d5 = (d2);\n    {\n      return +((Float64ArrayView[0]));\n    }\n    i6 = (i6);\n    d4 = (d7);\n    {\n      i0 = ((0x9d418eed));\n    }\n    i1 = (i6);\n    return +((1.25));\n  }\n  return f; })(this, {ff:  /x/g }, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-451211*/count=156; tryItOut("testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, -0, 0x080000000, -(2**53+2), 2**53-2, -0x100000001, -Number.MAX_VALUE, 2**53, -0x080000000, 42, -0x100000000, 0, 0.000000000000001, 0x07fffffff, -1/0, 1/0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, 1, -Number.MIN_VALUE, Math.PI, 0x100000001, -(2**53-2), Number.MIN_VALUE, 2**53+2, 0/0, -0x0ffffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, -0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-451211*/count=157; tryItOut("a1.valueOf = (function() { try { a2.unshift(this.o0, a1, this.f0, g1, a2, g2.s0, t0, m2); } catch(e0) { } for (var p in i2) { try { Array.prototype.forEach.call(a1, (function(j) { f1(j); }), e1); } catch(e0) { } try { this.o2.v2 = (f2 instanceof f0); } catch(e1) { } x = m2; } return i0; });");
/*fuzzSeed-451211*/count=158; tryItOut("o2.g1.s2 += s1;");
/*fuzzSeed-451211*/count=159; tryItOut("\"use strict\"; b0.toString = (function(j) { if (j) { v2 = Object.prototype.isPrototypeOf.call(p2, b1); } else { try { o0.a0 = new Array; } catch(e0) { } b2 + o0; } });");
/*fuzzSeed-451211*/count=160; tryItOut("let v2 = false;");
/*fuzzSeed-451211*/count=161; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(( ! Math.fround(Math.hypot((( - Math.hypot(x, Math.fround(Math.imul(x, x)))) || y), Math.fround(((y << ( ~ ((Math.fround(x) % Math.fround(y)) | 0))) >>> 0)))))); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), this, this, this, this, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), this, this, this, this, objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(), this, this, objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(), this, this, objectEmulatingUndefined(), this, this, objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=162; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=163; tryItOut("testMathyFunction(mathy3, [0, 1, -Number.MIN_VALUE, 0x07fffffff, 0/0, -(2**53-2), 0.000000000000001, -0x100000001, 0x100000001, 0x100000000, -0, 1.7976931348623157e308, -0x080000001, 2**53, -1/0, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53+2), 2**53-2, 0x080000001, 0x0ffffffff, -0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 42, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), Math.PI]); ");
/*fuzzSeed-451211*/count=164; tryItOut("\"use strict\"; let z = window;m2.has((\u3056 = (z = [z1])));");
/*fuzzSeed-451211*/count=165; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=166; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-451211*/count=167; tryItOut("\"use strict\"; h2 + i2;");
/*fuzzSeed-451211*/count=168; tryItOut("const p1 = Proxy.create(h2, g2);");
/*fuzzSeed-451211*/count=169; tryItOut("\"use strict\"; e1.valueOf = (function() { try { g0.a0.__iterator__ = f0; } catch(e0) { } try { v2 = t0.byteLength; } catch(e1) { } try { g1.a0.sort((function mcc_() { var hplhos = 0; return function() { ++hplhos; if (/*ICCD*/hplhos % 6 == 4) { dumpln('hit!'); a0.valueOf = (function() { try { v0 = r0.source; } catch(e0) { } v0 = (v0 instanceof this.g1); return g2; }); } else { dumpln('miss!'); try { delete s2[\"wrappedJSObject\"]; } catch(e0) { } try { i0.send(m0); } catch(e1) { } v1.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { var r0 = x / a2; var r1 = r0 | 9; var r2 = x - a18; a3 = a12 * r0; var r3 = 8 * 3; var r4 = 3 / 3; return a19; }); } };})()); } catch(e2) { } a1.push(i2, a1, x, g2, ({x: (4277)})); return b1; });");
/*fuzzSeed-451211*/count=170; tryItOut("\"use strict\"; i0.__proto__ = a0;");
/*fuzzSeed-451211*/count=171; tryItOut("v1 = 4;");
/*fuzzSeed-451211*/count=172; tryItOut("v1 = g2.runOffThreadScript();");
/*fuzzSeed-451211*/count=173; tryItOut("/*tLoop*/for (let e of /*MARR*/[x, x, objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, [[1]] ? /\\S*?(\\2{1})/m :  '' , x, Number.MIN_SAFE_INTEGER, x, x, [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), x, objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, x, objectEmulatingUndefined(), objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), x, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, x, [[1]] ? /\\S*?(\\2{1})/m :  '' , x, [[1]] ? /\\S*?(\\2{1})/m :  '' , Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, [[1]] ? /\\S*?(\\2{1})/m :  '' , Number.MIN_SAFE_INTEGER, objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, x, Number.MIN_SAFE_INTEGER, x, objectEmulatingUndefined(), objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, [[1]] ? /\\S*?(\\2{1})/m :  '' , [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, objectEmulatingUndefined(), x, Number.MIN_SAFE_INTEGER, [[1]] ? /\\S*?(\\2{1})/m :  '' , Number.MIN_SAFE_INTEGER, x, [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), x, [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, x, objectEmulatingUndefined(), objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , [[1]] ? /\\S*?(\\2{1})/m :  '' , Number.MIN_SAFE_INTEGER, objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , x, Number.MIN_SAFE_INTEGER, x, objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , Number.MIN_SAFE_INTEGER, x, objectEmulatingUndefined(), x, [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, [[1]] ? /\\S*?(\\2{1})/m :  '' , x, objectEmulatingUndefined(), [[1]] ? /\\S*?(\\2{1})/m :  '' , [[1]] ? /\\S*?(\\2{1})/m :  '' , objectEmulatingUndefined(), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) {  for (let z of x) {let o1.v2 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: undefined, noScriptRval: null, sourceIsLazy: (e % 39 != 5), catchTermination: /\\B|[^\ud588-\\u000F\\u0015-[\\\u00b8-U]/gm }));print(x); } }");
/*fuzzSeed-451211*/count=174; tryItOut("testMathyFunction(mathy1, [-0, 1/0, 0x100000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, 0/0, 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), 0, -0x0ffffffff, 0x100000000, 0x080000000, 42, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 0x07fffffff, -Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, 1, 0.000000000000001, -(2**53+2), -0x100000001, -0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53]); ");
/*fuzzSeed-451211*/count=175; tryItOut("mathy3 = (function(x, y) { return Math.min((( + (( + Math.pow(( + mathy1((((y >>> 0) < (Math.cosh(x) >>> 0)) >>> 0), ( ~ x))), (mathy1(((( + 2**53) + ( ! y)) >>> 0), Math.min(y, ( + y))) >>> 0))) === ( + Math.fround(Math.max(Math.fround(( + Math.atan(( + y)))), Math.fround(y)))))) >>> 0), (((( + Math.fround((-(2**53+2) ? Math.hypot((( ! (x >>> 0)) >>> 0), Math.cbrt(x)) : Math.fround(Math.asin(y))))) | 0) + Math.sin(Math.acos(Math.fround(Math.sinh((( + Math.fround(( + 42))) | 0)))))) >>> 0)); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -1/0, 0x100000000, 0, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 0.000000000000001, -0x080000000, 0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, -Number.MAX_VALUE, -0, -(2**53+2), 0x0ffffffff, -0x100000000, -0x080000001, 42, -0x100000001, 1, 2**53+2, 1.7976931348623157e308, 0x07fffffff, 0x080000000, 1/0, -0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=176; tryItOut("mathy1 = (function(x, y) { return Math.acos((Math.pow(((Math.pow((( + (Math.expm1(Math.hypot(x, x)) >>> 0)) >>> 0), Math.fround(mathy0(( ~ y), Math.sign(Math.fround(Math.cosh(Math.fround(x))))))) | 0) >>> 0), ((Math.fround((( + Math.tanh(2**53)) <= ( + ((( + Math.max((y % y), y)) <= x) | 0)))) << Math.asinh(mathy0(y, x))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[{x:3}, [1], {x:3}, [1], {x:3}]); ");
/*fuzzSeed-451211*/count=177; tryItOut("\"use strict\"; try { s1 = new String(m2); } catch(NaN if /(?:.\\b*?)|(?:.(?=\\w*?)+?)(?:\\W){4,5}(?:((?![^])){512,})+/ += \"\\u9C0E\") { print(uneval(b1)); } catch(c) { {} } finally { 8; } ");
/*fuzzSeed-451211*/count=178; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=179; tryItOut("e1.add(m0);");
/*fuzzSeed-451211*/count=180; tryItOut("{ void 0; validategc(false); }");
/*fuzzSeed-451211*/count=181; tryItOut("(27);var \u000cz = this;");
/*fuzzSeed-451211*/count=182; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.log1p((Math.tan((Math.fround(( - Math.fround(y))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-451211*/count=183; tryItOut("h1.getPropertyDescriptor = g2.f0;");
/*fuzzSeed-451211*/count=184; tryItOut("v2.__proto__ = m0;");
/*fuzzSeed-451211*/count=185; tryItOut("mathy2 = (function(x, y) { return mathy0(Math.max((Math.max((( + (Math.fround((y / Math.fround(x))) & Math.fround(y))) / Math.fround(0/0)), Math.log1p(mathy0((Math.atan(y) | 0), x))) >>> 0), ( ! mathy0(y, Math.fround(( ~ Math.fround(Math.asin(-0x080000001))))))), ( + Math.trunc(Math.fround(mathy1(y, Math.fround(Math.asinh(Math.fround(y)))))))); }); testMathyFunction(mathy2, [-0, 2**53, -Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, 0, Number.MAX_VALUE, -0x080000000, -0x100000001, 42, -1/0, 1, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 0x100000001, 2**53-2, -0x07fffffff, 0.000000000000001, 0x080000001, -(2**53-2), 0x100000000, 2**53+2, -(2**53+2), 0/0, 0x07fffffff, -(2**53), 1/0]); ");
/*fuzzSeed-451211*/count=186; tryItOut("o2.o0.h2.get = f2;");
/*fuzzSeed-451211*/count=187; tryItOut("/*bLoop*/for (let twxubq = 0; twxubq < 68; ++twxubq) { if (twxubq % 10 == 7) { var v1 = o1.g0.eval(\"/*RXUB*/var r = /(?![^]|(?=(\\\\s)+?)|[^]?)(?:(.)*|(?=\\\\B|\\\\u005A|\\\\].{2,})*)|(?:(?!\\u0007(?=.*){1,32769}){3,7})/im; var s = \\\"\\\\n\\\\n\\\"; print(uneval(r.exec(s))); print(r.lastIndex); \"); } else { ((objectEmulatingUndefined).call( '' , )); }  } ");
/*fuzzSeed-451211*/count=188; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((((((y << Math.fround(42)) | 0) * Math.log2(Math.clz32((y >= Math.imul(( + ((x | 0) <= 2**53+2)), 42))))) | 0) << (Math.fround(Math.pow(Math.pow(x, (mathy2(Math.fround(y), ( + Math.log10(y))) >>> 0)), Math.fround((Math.acosh((mathy0(0x07fffffff, ((y | 0) === (x | 0))) | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy3, [-0x100000001, 0x0ffffffff, 1, 0x100000000, -0, -0x080000001, -0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, -0x080000000, -Number.MAX_VALUE, 2**53-2, 1/0, -1/0, 2**53+2, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 0x080000000, 0x080000001, Number.MAX_VALUE, -(2**53+2), -(2**53), 42, 1.7976931348623157e308, 0x07fffffff, -0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-451211*/count=189; tryItOut("\"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.sqrt(Math.imul(Math.fround(mathy0(Math.sign((y >>> 0)), Math.round(y))), Math.fround(( ~ mathy0(( + x), Math.fround(y)))))) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -0, Number.MAX_VALUE, 0x07fffffff, 0x080000001, -(2**53+2), 1, -0x0ffffffff, 0.000000000000001, 0, Math.PI, -(2**53-2), 42, 1/0, 0x100000000, 2**53+2, -0x100000000, -0x080000000, 1.7976931348623157e308, 0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -0x100000001, 0/0]); ");
/*fuzzSeed-451211*/count=190; tryItOut("for (var v of h0) { try { o2.m2.has(h2); } catch(e0) { } e2 = g0.objectEmulatingUndefined(); }");
/*fuzzSeed-451211*/count=191; tryItOut("testMathyFunction(mathy0, [0x0ffffffff, -(2**53+2), Math.PI, -0x100000000, 0x080000001, -1/0, 1/0, -0x100000001, Number.MAX_VALUE, 0, 42, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_VALUE, 0x080000000, -(2**53-2), 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -(2**53), 2**53, -0, 1.7976931348623157e308, 1, -0x07fffffff, -0x080000001, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001]); ");
/*fuzzSeed-451211*/count=192; tryItOut("");
/*fuzzSeed-451211*/count=193; tryItOut("\"use strict\"; /*hhh*/function jsezuh(){throw  /x/g ;}/*iii*/(\"\\u2DED\");");
/*fuzzSeed-451211*/count=194; tryItOut("mathy3 = (function(x, y) { return Math.acosh(( - ((Math.min(( ! Math.fround(Math.sin(y))), ( + Math.asin(y))) >>> 0) % Math.cos((x | 0))))); }); testMathyFunction(mathy3, [0, -Number.MIN_VALUE, 0x080000000, -(2**53+2), 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 42, 1, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, -1/0, 2**53, 2**53-2, -0, Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, 0x07fffffff, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 0.000000000000001, -0x07fffffff, Math.PI, -0x080000001, 2**53+2]); ");
/*fuzzSeed-451211*/count=195; tryItOut("\"use asm\"; /*RXUB*/var r = this.r2; var s = \"0\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=196; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( - ( + ( + Math.asinh((( + Math.max(( + x), ( + null))) | 0))))); }); testMathyFunction(mathy0, [0/0, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -0x100000000, 0x100000001, -0x07fffffff, -(2**53+2), -0, -0x100000001, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0x080000000, -0x080000000, 2**53+2, -1/0, -0x080000001, -0x0ffffffff, 42, 1, 1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-451211*/count=197; tryItOut("Array.prototype.reverse.apply(a0, [x]);");
/*fuzzSeed-451211*/count=198; tryItOut("var xzzegt = new ArrayBuffer(0); var xzzegt_0 = new Float64Array(xzzegt); xzzegt_0[0] = -7; var xzzegt_1 = new Int16Array(xzzegt); xzzegt_1[0] = -25; var xzzegt_2 = new Uint8Array(xzzegt); var xzzegt_3 = new Uint16Array(xzzegt); var xzzegt_4 = new Int32Array(xzzegt); xzzegt_4[0] = 18; var xzzegt_5 = new Uint8Array(xzzegt); xzzegt_5[0] = 0; yield false;s0 += 'x';(\"\\uF159\");v0 = Object.prototype.isPrototypeOf.call(s0, g2.p1);");
/*fuzzSeed-451211*/count=199; tryItOut("/*ADP-3*/Object.defineProperty(a1, 9, { configurable: false, enumerable: (x % 27 != 15), writable: (x % 5 == 4), value: g0 });");
/*fuzzSeed-451211*/count=200; tryItOut("testMathyFunction(mathy5, /*MARR*/[Number.MIN_SAFE_INTEGER, ['z'], Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, [1], [1], Number.MIN_SAFE_INTEGER, [1], ['z'], -0x080000001, ['z'], [1], [1], Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000001, ['z'], new Boolean(false), ['z'], [1], [1], [1], -0x080000001, new Boolean(false), ['z'], ['z'], [1], -0x080000001, new Boolean(false), ['z'], new Boolean(false), -0x080000001, ['z'], -0x080000001, [1], Number.MIN_SAFE_INTEGER, ['z'], new Boolean(false), -0x080000001, -0x080000001, new Boolean(false), [1], -0x080000001, -0x080000001, [1], Number.MIN_SAFE_INTEGER, ['z'], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Boolean(false), [1], -0x080000001, Number.MIN_SAFE_INTEGER, [1]]); ");
/*fuzzSeed-451211*/count=201; tryItOut("this.v1 = a1.some((function() { try { for (var p in s1) { try { ; } catch(e0) { } try { o1.valueOf = Date.prototype.toTimeString.bind(this.g0.i1); } catch(e1) { } v0 = -0; } } catch(e0) { } try { Array.prototype.shift.apply(this.a0, []); } catch(e1) { } try { f2(s0); } catch(e2) { } Array.prototype.forEach.apply(a1, [(function() { try { g2.s1 += 'x'; } catch(e0) { } try { Object.defineProperty(this, \"m2\", { configurable: \"\\u3D84\", enumerable: (x % 2 == 0),  get: function() {  return new WeakMap; } }); } catch(e1) { } try { Array.prototype.sort.apply(a1, [(function() { for (var j=0;j<74;++j) { f1(j%2==0); } })]); } catch(e2) { } g2.m2.has(s0); return v1; })]); return f2; }));");
/*fuzzSeed-451211*/count=202; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + (((( + ((((( - x) >>> 0) >>> 0) >= (( ~ Math.fround(Math.fround(Math.clz32(Math.fround(x))))) >>> 0)) >>> 0)) , (Math.fround(x) >>> 0)) | 0) && ((Math.min(x, Math.expm1(Math.max(x, Math.fround(x)))) >>> 0) ? ((Math.fround(((( ! (Math.max(Math.exp(( + x)), y) | 0)) | 0) | 0)) | 0) >>> 0) : Math.fround(( ! Math.fround((( + (x | 0)) | 0))))))); }); testMathyFunction(mathy2, [0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), 1, 0x100000000, -0x100000000, -0x0ffffffff, 0/0, Math.PI, 0x100000001, -Number.MIN_VALUE, 2**53-2, -(2**53-2), 1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -1/0, -0x080000000, 0, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, -0x080000001, 2**53+2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 42, 0x080000001]); ");
/*fuzzSeed-451211*/count=203; tryItOut("testMathyFunction(mathy1, [2**53, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000001, 1, Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, 42, -Number.MAX_VALUE, 1/0, 2**53+2, -0x0ffffffff, 0, -0x100000001, -(2**53+2), 0x100000000, -(2**53), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, 0/0, Math.PI]); ");
/*fuzzSeed-451211*/count=204; tryItOut("\"use strict\"; /*MXX3*/g1.DataView.prototype.getInt8 = o0.g0.DataView.prototype.getInt8;");
/*fuzzSeed-451211*/count=205; tryItOut("throw (z);");
/*fuzzSeed-451211*/count=206; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.min(((Math.atan2(y, Math.fround(((x ? (x | 0) : (y >>> 0)) | 0))) | 0) ** (Math.imul(y, (y >> (42 , Math.min(-(2**53+2), ((y > x) | 0))))) | 0)), Math.cbrt(Math.pow(( ~ (y >>> 0)), ( + Math.fround(mathy0(Math.fround(-0x080000001), y)))))); }); testMathyFunction(mathy1, /*MARR*/[[], -Infinity, (void 0), (void 0), new String(''), -Infinity, (void 0), (void 0), (-1/0), (-1/0), new String(''), -Infinity, -Infinity, new String(''), (void 0), (-1/0), (void 0), [], [], (void 0), (void 0), (void 0), [], [], new String(''), (-1/0), new String(''), (void 0), [], new String(''), new String(''), (-1/0), new String(''), (void 0), new String(''), (void 0), (-1/0), (-1/0), (void 0), new String(''), (void 0), -Infinity, (-1/0), new String(''), [], (-1/0), -Infinity, (-1/0), new String(''), (-1/0), -Infinity, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (void 0), new String(''), (-1/0), [], -Infinity, -Infinity, (-1/0), (void 0), (void 0), (-1/0), new String(''), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), -Infinity, [], -Infinity, (-1/0), [], [], -Infinity, [], [], -Infinity, [], [], new String(''), [], [], (void 0), new String(''), (-1/0), (-1/0), (-1/0), (void 0), (void 0), new String(''), [], [], [], [], [], [], [], [], [], [], new String(''), (-1/0), (void 0), (void 0), (void 0), [], (void 0), [], [], [], (-1/0), (-1/0), (void 0), (-1/0), (-1/0), [], (void 0), [], -Infinity, new String(''), new String(''), (void 0), [], (void 0), (void 0), -Infinity, (void 0), (void 0), []]); ");
/*fuzzSeed-451211*/count=207; tryItOut("o2.o2.e2.add(p1);");
/*fuzzSeed-451211*/count=208; tryItOut("Array.prototype.forEach.call(a0, Math.imul.bind(f2), a = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: mathy3, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: [z1], enumerate: function() { throw 3; }, keys: function() { return []; }, }; })([[1]]), ((new Function(\"v1 + '';\"))).call));");
/*fuzzSeed-451211*/count=209; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.asin((Math.sign((\u3056 = ({a1:1}))) | 0))); }); testMathyFunction(mathy2, [2**53, 0.000000000000001, -0, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, Math.PI, 2**53-2, 0x100000000, 0x080000000, 0, 1.7976931348623157e308, -(2**53+2), -0x080000000, 0x080000001, 42, 0x100000001, -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, -0x07fffffff, -0x100000000, 0x0ffffffff, 0/0, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, -Number.MAX_VALUE]); ");
/*fuzzSeed-451211*/count=210; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.hypot((mathy0(( + mathy0(( + ( + Math.imul(( + y), ( + (Math.imul((-0x080000001 | 0), y) | 0))))), y)), Math.atan2(( + Math.atan2((x | y), ( ! (x | 0)))), (Math.hypot(x, y) | 0))) >>> 0), ((Math.min((( ! Math.ceil(Math.fround(mathy0(y, (y - x))))) >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0) > Math.max(mathy0(Math.sinh((((0x080000001 | 0) | -(2**53+2)) ? (-Number.MAX_SAFE_INTEGER != y) : Math.fround((y && Math.fround(Number.MIN_VALUE))))), ( + (( + Math.min(( + y), ( + Math.trunc(Math.fround(0.000000000000001))))) << (y , x)))), (Math.tan(((Math.hypot(x, x) ? (Math.fround(Math.sin(Math.fround(y))) >>> 0) : (((y ? Math.fround(y) : ((y >= Math.fround(y)) | 0)) | 0) | 0)) | 0)) | 0))); }); testMathyFunction(mathy1, [42, -(2**53), -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, -(2**53-2), 0x100000001, -0x0ffffffff, 1, Number.MAX_VALUE, 0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, Math.PI, Number.MIN_VALUE, 0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, -0x100000000, 0x080000000, 0x07fffffff, -0, 2**53-2, -0x080000001, -1/0, 1.7976931348623157e308, 0/0, 0x0ffffffff, 1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-451211*/count=211; tryItOut("mathy4 = (function(x, y) { return (((((Math.fround((Math.fround(Math.tan(( + Math.atan(x)))) == (( ~ (( ~ x) | 0)) | 0))) | 0) <= ((mathy2(((mathy0((-0x080000001 | 0), y) | 0) | 0), x) | 0) | 0)) | 0) ? ((( - ( - 0x080000000)) ? Math.min(Math.atan2(((x | 0) + x), ( + ((((( ~ -0x07fffffff) | 0) >>> 0) & (x >>> 0)) >>> 0))), ( + ( ! ( + ( + mathy1(x, (1 | 0))))))) : x) | 0) : Math.fround(( ! ((( - Math.sqrt(y)) >>> 0) >>> 0)))) ? (mathy3((Math.pow(Math.fround((Math.fround(0x07fffffff) >>> ( ! y))), ((x ? ((Math.abs((y >>> 0)) >>> 0) ? 1.7976931348623157e308 : y) : ( ~ -(2**53+2))) ? ( ! ( + (y * 2**53+2))) : Math.fround(0x080000001))) >>> 0), (( - Math.imul(( + x), ( + Math.fround(Math.clz32(Math.hypot(x, Math.fround(x))))))) | 0)) >>> 0) : ( + mathy0(( + (( ! (( ! y) | 0)) | 0)), ( + Math.fround(Math.imul(( ! 0x100000000), Math.fround((Math.atan2((0x07fffffff | 0), (Math.atanh(x) | 0)) | 0)))))))); }); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-451211*/count=212; tryItOut("mathy0 = (function(x, y) { return Math.log1p((((((Math.sin(( ! ( + ( - x)))) | 0) >= ((Math.trunc(( + y)) | 0) | 0)) | 0) | Math.atan2(( + ( + ( + ( + x)))), ( + Math.fround(Math.min(((-0x100000001 ? x : 0x100000001) >>> 0), Math.atanh(-0)))))) >>> 0)); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 0x100000000, 2**53, 0x080000000, 0, 2**53-2, -0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), -Number.MIN_VALUE, -0x080000001, Number.MIN_VALUE, 0.000000000000001, -0, -0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), -0x0ffffffff, 0x07fffffff, 1, -0x07fffffff, -1/0, Math.PI, 0x080000001, 2**53+2, 42]); ");
/*fuzzSeed-451211*/count=213; tryItOut("mathy3 = (function(x, y) { return ( + Math.pow((((Math.sinh(( + mathy0(( + x), ( + Number.MIN_VALUE)))) < (0x0ffffffff < x)) | 0) * (( ~ (y + (( + x) | 0))) | 0)), ( + ((((((((Math.log((42 , y)) | 0) | 0) * ( + Math.atan2(((y % y) | 0), y))) | 0) | 0) === ((x !== ( ! (y | 0))) | 0)) | 0) === ((y || (y > x)) & -0x07fffffff))))); }); ");
/*fuzzSeed-451211*/count=214; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=215; tryItOut("\"use strict\"; m0 = new WeakMap;");
/*fuzzSeed-451211*/count=216; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.fround(( + Math.log(mathy1(((y >>> y) >>> 0), Math.fround(( ~ Math.fround((Math.log2(Math.cos(y)) | 0))))))))); }); testMathyFunction(mathy3, [0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, -0x07fffffff, -(2**53+2), 2**53, -1/0, 1.7976931348623157e308, 0/0, 0x080000000, -(2**53-2), Math.PI, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 1/0, 0, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 0x0ffffffff, -0, 0x100000000, -0x080000001, -0x100000001, 42, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-451211*/count=217; tryItOut("a2.forEach((function() { try { /*MXX3*/g2.Error.prototype.name = g1.Error.prototype.name; } catch(e0) { } v0 = g0.runOffThreadScript(); return p1; }), m0, g0.o0.p2, g2);");
/*fuzzSeed-451211*/count=218; tryItOut("for (var v of this.g1) { try { v2 = evalcx(\" \\\"\\\" \", g1); } catch(e0) { } try { t1 = new Int32Array(o2.b0, 52, 5); } catch(e1) { } try { /*MXX2*/g0.Object.seal = a1; } catch(e2) { } t0 = t2.subarray(13); }");
/*fuzzSeed-451211*/count=219; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = ((-((144115188075855870.0))) != (d1));\n    i2 = ((0x9d632ba0) ? ((0xd555beb9)) : ((0x2742db71)));\n    i2 = ((0x7e440e66) ? (timeout(1800)) : ((((!(0xfe0a6a91))+(!(0xfcfc977f))+(0xfc5a15ec))>>>(0x6d6df*(-0x8000000))) < (((((0xf533506e))>>>((-0x8000000))) / (0x33dd14da))>>>((i0)-(i0)-((-128.0) < (2.0))))));\n    i2 = (0xf9d73545);\n    return +((d1));\n  }\n  return f; })(this, {ff: ((d, w, ...x) => \u3056).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, 1, 0x07fffffff, -0x080000001, 42, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, 2**53, 1.7976931348623157e308, 0x100000000, 0x0ffffffff, -0x07fffffff, -(2**53-2), 0/0, 0.000000000000001, -0x0ffffffff, Number.MAX_VALUE, 2**53+2, -0, -(2**53), -(2**53+2), -0x100000001, -0x080000000, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, 0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-451211*/count=220; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return ( ~ Math.clz32(( ~ Math.fround(mathy3(Math.fround(( - (y >>> 0))), Math.fround(x)))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, 0x080000000, -0x0ffffffff, -(2**53-2), -0x080000000, 0, -0x100000001, 0x100000000, 0/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, -0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0x100000001, Number.MAX_VALUE, 0x0ffffffff, 2**53-2, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53), 2**53, -0, 1, 2**53+2, Number.MIN_VALUE, 0x080000001, 42]); ");
/*fuzzSeed-451211*/count=221; tryItOut("mathy1 = (function(x, y) { return Math.max(Math.imul((-0x080000001 <= Math.expm1(Math.min((0x080000000 >>> 0), ((( ~ ((((y | 0) ^ (y | 0)) >>> 0) >>> 0)) >>> 0) >>> 0)))), (Math.pow(Math.fround((mathy0(mathy0(y, Math.max(x, x)), (( ~ Number.MIN_SAFE_INTEGER) | 0)) | 0)), (Math.cos(Math.acosh(( + x))) | 0)) >>> 0)), (Math.round((y || Math.log2(mathy0(x, y)))) + (((((y >>> 0) % y) >>> 0) ^ (0x080000001 >>> 0)) >>> 0))); }); testMathyFunction(mathy1, ['/0/', '0', (new String('')), false, 0, undefined, [0], 1, /0/, (new Number(0)), -0, ({toString:function(){return '0';}}), (function(){return 0;}), 0.1, (new Boolean(false)), ({valueOf:function(){return 0;}}), (new Boolean(true)), true, '\\0', objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), null, (new Number(-0)), '', NaN, []]); ");
/*fuzzSeed-451211*/count=222; tryItOut("\"use strict\"; v1 = (e2 instanceof s1);");
/*fuzzSeed-451211*/count=223; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow(Math.imul(Math.fround((Math.fround(Math.acos(mathy0(( + (( ~ Math.fround(y)) % (( ~ (x >>> 0)) >>> 0))), 0x100000000))) << Math.fround((Math.fround(Math.min(Math.fround(y), Math.fround(x))) >> Math.sinh(( + Math.log2(y))))))), Math.atanh(( + x))), ((Math.fround(( + (((y | 0) & (Math.fround(Math.acos(Math.fround(y))) | 0)) | 0))) < Math.fround((Math.fround(Math.round(Math.sign(( + Math.trunc(Math.fround(x)))))) + Math.fround((y ? ( + Math.fround((Math.fround(Math.log2(Math.PI)) >> Math.fround(y)))) : ( + (( + Math.fround(-(2**53+2))) | 0))))))) >>> 0)); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -0x07fffffff, 0, 1/0, 2**53, 0x100000000, -(2**53+2), 42, -Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, 1.7976931348623157e308, -(2**53-2), -(2**53), Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, -1/0, 0x100000001, 2**53+2, -0x080000001, 2**53-2, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, 1, 0x080000001]); ");
/*fuzzSeed-451211*/count=224; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy2(Math.fround(Math.trunc(( + ( ~ ( + y))))), Math.fround(( ! ( + ( + (x >>> 0)))))); }); testMathyFunction(mathy5, [1, 0, 0x0ffffffff, Math.PI, 0x080000000, -0x100000000, 0x080000001, 0x100000001, 0x07fffffff, -Number.MIN_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53), -1/0, Number.MIN_SAFE_INTEGER, 0/0, 2**53, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53-2), -0x100000001, 0x100000000, -0, -0x080000000, 2**53+2, -0x07fffffff, -0x080000001, -(2**53+2)]); ");
/*fuzzSeed-451211*/count=225; tryItOut("t1[({valueOf: function() { o0.__proto__ = o1;return 0; }})] = v0;");
/*fuzzSeed-451211*/count=226; tryItOut("\"use strict\"; ;");
/*fuzzSeed-451211*/count=227; tryItOut("this.v0 = r2.global;");
/*fuzzSeed-451211*/count=228; tryItOut("/*vLoop*/for (var jlopya = 0; jlopya < 41; ++jlopya) { a = jlopya; /*tLoop*/for (let d of /*MARR*/[x, false, [], [], [], [], [], [], [], [], [], x, x, [], x, false, [], [], x, [], x, [], false, [], [], [], false, x, [], x, [], false, x, false]) { v2 = evalcx(\"m2.delete(a2);\", g1); } } ");
/*fuzzSeed-451211*/count=229; tryItOut("\"use strict\"; /*bLoop*/for (var ntivrm = 0; ntivrm < 140; ++ntivrm) { if (ntivrm % 70 == 59) { (new RegExp(\"(?:\\n)*\", \"gm\")); } else { a0.forEach((function() { for (var j=0;j<77;++j) { f2(j%2==0); } }), s2, h0, m1); }  } ");
/*fuzzSeed-451211*/count=230; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-451211*/count=231; tryItOut("testMathyFunction(mathy1, [0x100000001, 0x07fffffff, 0.000000000000001, 2**53-2, -(2**53-2), 2**53, 0x0ffffffff, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1, 42, Number.MAX_VALUE, 0x100000000, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, -1/0, 0, -Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, Math.PI, -0x080000001, 2**53+2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, 0/0, 1/0, Number.MIN_VALUE, -0x080000000, -(2**53)]); ");
/*fuzzSeed-451211*/count=232; tryItOut("let (b) { h1 = ({getOwnPropertyDescriptor: function(name) { e2.delete(t1);; var desc = Object.getOwnPropertyDescriptor(h2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g2.offThreadCompileScript(\"\\\"use strict\\\"; print(x);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 15 != 1), noScriptRval: false, sourceIsLazy: b, catchTermination: b }));; var desc = Object.getPropertyDescriptor(h2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { i0 + v2;; Object.defineProperty(h2, name, desc); }, getOwnPropertyNames: function() { for (var v of h1) { a0.__proto__ = o2.a1; }; return Object.getOwnPropertyNames(h2); }, delete: function(name) { Object.prototype.watch.call(v2, \"wrappedJSObject\", f0);; return delete h2[name]; }, fix: function() { x = e0;; if (Object.isFrozen(h2)) { return Object.getOwnProperties(h2); } }, has: function(name) { this.a2.forEach((function() { s0 = new String; return m1; }));; return name in h2; }, hasOwn: function(name) { t0[({valueOf: function() { Array.prototype.reverse.call(a2, function(y) { yield y; v2 = evaluate(\"/*MXX1*/Object.defineProperty(this.o0, \\\"this.o0\\\", { configurable: d, enumerable: (x % 85 != 47),  get: function() {  return g1.String.prototype.replace; } });\", ({ global: o2.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: arguments, sourceIsLazy: false, catchTermination: (x % 6 != 0) }));; yield y; }(), m2);return 12; }})] = (this.__defineGetter__(\"\\u3056\", Array.prototype.lastIndexOf));; return Object.prototype.hasOwnProperty.call(h2, name); }, get: function(receiver, name) { /*RXUB*/var r = r0; var s = \"\\u42ec\"; print(uneval(s.match(r))); ; return h2[name]; }, set: function(receiver, name, val) { i2.send(s0);; h2[name] = val; return true; }, iterate: function() { e2.delete(v1);; return (function() { for (var name in h2) { yield name; } })(); }, enumerate: function() { this.e0.add(b0);; var result = []; for (var name in h2) { result.push(name); }; return result; }, keys: function() { s0 + o2;; return Object.keys(h2); } }); }");
/*fuzzSeed-451211*/count=233; tryItOut("mathy0 = (function(x, y) { return ((Math.sin(( + (Math.max(((x ** 0x07fffffff) | 0), (( + ((( + ( ! Math.fround(y))) - ( + -Number.MAX_SAFE_INTEGER)) >>> 0)) >>> 0)) | 0))) >>> 0) ** ( + (( + ( - (Math.atan2(Math.fround(2**53), x) ^ Math.clz32(y)))) < ( + Math.clz32((((((y / ( + y)) | 0) >>> (y | 0)) | 0) == (Math.abs(x) | 0))))))); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(false), new Boolean(false), (1/0), x, new Boolean(false), objectEmulatingUndefined(), new Boolean(false), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, new Boolean(false), null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), (1/0), null, new Boolean(false), null, new Boolean(false), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), null, null, null, objectEmulatingUndefined(), x, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (1/0), x, (1/0), null, x, (1/0), null, x, null, null, new Boolean(false), new Boolean(false), new Boolean(false), x, (1/0), null, null, null, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, null, (1/0), (1/0)]); ");
/*fuzzSeed-451211*/count=234; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.min((( + (( + (Math.pow((Math.fround(Math.cbrt(Math.fround(2**53-2))) >>> 0), (x >>> 0)) | 0)) > ( + ( + ((Math.cosh(x) >>> 0) ? (Math.sinh((Math.pow((((y | 0) ? (x | 0) : (y | 0)) | 0), -0x080000000) >>> 0)) >>> 0) : (( ~ ( + (((x | 0) ? (Math.fround((y | 0)) >>> 0) : (-Number.MIN_SAFE_INTEGER | 0)) | 0))) >>> 0)))))) >>> 0), ( + Math.pow(Math.atan2(0x0ffffffff, 0.000000000000001), ((mathy1(( + (( + x) ? ((x ? y : x) ? x : (Math.trunc(x) | 0)) : ( + y))), (( ! x) | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy2, [NaN, '', (new String('')), -0, '\\0', /0/, (new Number(-0)), undefined, (new Number(0)), ({toString:function(){return '0';}}), 0.1, ({valueOf:function(){return '0';}}), 1, [], 0, '/0/', '0', ({valueOf:function(){return 0;}}), [0], true, false, (new Boolean(false)), null, (new Boolean(true)), (function(){return 0;}), objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=235; tryItOut("\"use strict\"; testMathyFunction(mathy4, [null, [], undefined, (new Number(0)), ({valueOf:function(){return 0;}}), true, (new Number(-0)), objectEmulatingUndefined(), '0', 1, '', -0, 0.1, [0], (new String('')), /0/, (new Boolean(true)), (new Boolean(false)), '\\0', ({valueOf:function(){return '0';}}), 0, (function(){return 0;}), NaN, '/0/', false, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-451211*/count=236; tryItOut("mathy4 = (function(x, y) { return Math.hypot(((((((( ! Math.fround((Math.atan2((Math.ceil(y) | 0), (((Math.fround(mathy1(Math.fround(x), Math.fround(y))) >>> 0) > (y >>> 0)) >>> 0)) | 0))) >>> 0) || (-(2**53+2) >>> 0)) >>> 0) | 0) || (( ~ (( ! x) | 0)) | 0)) | 0), Math.asinh(Math.min((( ! (x - x)) | 0), Math.hypot(((mathy3(x, y) >>> 0) ? (y >>> 0) : (1/0 >>> 0)), ( + Math.acos(( + -Number.MAX_SAFE_INTEGER))))))); }); testMathyFunction(mathy4, [-1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), -0x100000000, -Number.MIN_VALUE, -0x080000001, 0x100000001, 2**53-2, 2**53, 0/0, 0x07fffffff, 0.000000000000001, -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, 0x100000000, 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000000, 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1/0, 42, -0, Math.PI, 0, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-451211*/count=237; tryItOut("\"use strict\"; a2[14];");
/*fuzzSeed-451211*/count=238; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ~ (mathy2(( + y), (0/0 | 0)) >= -0x080000000)) , Math.fround(Math.pow(Math.fround(Math.log2(Math.hypot(( ! (Math.atan2((y >>> 0), (x >>> 0)) >>> 0)), x))), Math.cos(x)))); }); ");
/*fuzzSeed-451211*/count=239; tryItOut("\"use strict\"; a1.pop();");
/*fuzzSeed-451211*/count=240; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.fround((Math.hypot((Math.PI >>> 0), Math.fround(x)) !== Math.fround(Math.max(Math.fround(((mathy0(x, x) | 0) | x)), Math.fround(( + (y >>> 0))))))) ** Math.fround(Math.max((Math.imul((((Math.fround(((((y >>> 0) === (-(2**53+2) >>> 0)) >>> 0) ** Math.fround(Math.round(y)))) > -1/0) >>> 0) >>> 0), (y | 0)) | 0), (Math.round((Math.fround(Math.acos((y | 0))) | 0)) | 0)))) > (Math.fround(( + (y | 0))) , Math.imul(( ~ -Number.MAX_SAFE_INTEGER), x))); }); testMathyFunction(mathy1, [-0x080000000, -Number.MAX_VALUE, Math.PI, -0x100000001, 1, 0x080000001, 0x080000000, 0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, 42, -0x07fffffff, 0x0ffffffff, 2**53, 0x100000000, -(2**53), -1/0, 1/0, 0, Number.MAX_VALUE, 0/0, -0x080000001, 2**53+2, -(2**53-2), -0, -(2**53+2), 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=241; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.min(Math.fround(( + Math.acos(((Math.exp((Math.sign(Number.MAX_VALUE) << x)) && Math.atan2(((Math.max(Math.expm1(x), (( + (y | 0)) | 0)) * Math.fround(Math.acosh(Math.fround(y)))) >>> 0), ((y >> ( ! x)) >>> 0))) | 0)))), ((Math.atan2(Math.fround(( ~ ( + ( + Math.fround((x ? (Math.trunc((Math.fround(( + x)) >>> 0)) >>> 0) : x)))))), (Math.max(Math.imul(x, (y < -0x080000000)), Math.acos(y)) >>> 0)) >>> 0) >>> 0))); }); ");
/*fuzzSeed-451211*/count=242; tryItOut("a2 = this.a2.map(g2.f1, h2);");
/*fuzzSeed-451211*/count=243; tryItOut("mathy3 = (function(x, y) { return (Math.fround(Math.min(Math.fround(( + ( ~ Math.hypot(x, (Math.sinh(-0x0ffffffff) | 0))))), Math.fround(Math.sqrt((x >>> 0))))) && ( + (( + Math.max(-Number.MIN_VALUE, y)) != Math.fround(Math.atan(((mathy2((Math.pow((-Number.MIN_VALUE >>> 0), y) >>> 0), (((y ? x : x) >>> 0) & ( + x))) >>> 0) >>> 0)))))); }); testMathyFunction(mathy3, [2**53-2, -0x100000001, 0.000000000000001, 0x100000001, 2**53, 0x100000000, -(2**53), 2**53+2, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, -(2**53-2), -0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -0x100000000, 0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, 42, Math.PI, -0x07fffffff, 1/0, 0x080000001, -1/0, 1]); ");
/*fuzzSeed-451211*/count=244; tryItOut("v0.__iterator__ = (function() { try { b1.valueOf = (function mcc_() { var iwhuqv = 0; return function() { ++iwhuqv; if (/*ICCD*/iwhuqv % 11 == 3) { dumpln('hit!'); try { e0 + ''; } catch(e0) { } try { for (var p in s2) { try { a0 = arguments; } catch(e0) { } try { const h0 = {}; } catch(e1) { } Array.prototype.splice.apply(a1, [NaN, 6, h1]); } } catch(e1) { } g1.o1 = a1[3]; } else { dumpln('miss!'); this.o1.t1 = new Float64Array(b2, 28, 17); } };})(); } catch(e0) { } o1.__proto__ = h2; return s2; });");
/*fuzzSeed-451211*/count=245; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(a2, \"valueOf\", ({value: (4277), enumerable: true}));");
/*fuzzSeed-451211*/count=246; tryItOut("\"use strict\"; if((x % 87 == 83)) { if (\"\\uE618\") {v0 = Object.prototype.isPrototypeOf.call(h1, s1); }} else {print((4277)); }");
/*fuzzSeed-451211*/count=247; tryItOut("");
/*fuzzSeed-451211*/count=248; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul(Math.fround(((Math.fround(Math.pow(Math.fround(y), Math.fround(( ~ (Math.atan2(( + 0x080000001), y) >>> 0))))) | 0) - Math.exp((Math.pow(( + ( + ((y , y) ? -Number.MAX_SAFE_INTEGER : (Math.pow(x, -0x080000001) >>> 0)))), (( ~ y) >>> 0)) >>> 0)))), Math.imul((Math.fround(Math.ceil(( ! -0x080000001))) >> y), ( - x))); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), objectEmulatingUndefined(), ({}), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), objectEmulatingUndefined(), ({}), ({}), ({}), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), ({}), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=249; tryItOut("\"use strict\"; let (wuryla)/*\n*/ { print(x); }");
/*fuzzSeed-451211*/count=250; tryItOut("v2 = (v1 instanceof g1);");
/*fuzzSeed-451211*/count=251; tryItOut("\"use strict\"; NaN = a;");
/*fuzzSeed-451211*/count=252; tryItOut("mathy2 = (function(x, y) { return mathy1((( + Math.sin(( + Math.fround(Math.max(x, Math.trunc((( + Math.sign(0.000000000000001)) || 0x0ffffffff))))))) >>> 0), (Math.asinh(Math.fround(mathy1(Math.fround(Math.pow((x | 0), (y | 0))), (Math.pow((mathy0(x, (x >>> 0)) >>> 0), 1) >>> 0)))) >>> 0)); }); testMathyFunction(mathy2, [0x080000000, -(2**53+2), 1, -Number.MAX_VALUE, 2**53, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, 42, 0x100000000, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, -0x080000000, 2**53+2, 1.7976931348623157e308, -(2**53), 1/0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 0, 2**53-2, 0.000000000000001, 0/0, -0x100000001, 0x080000001, Math.PI]); ");
/*fuzzSeed-451211*/count=253; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + Math.cbrt(( + Math.imul(( + x), ((Math.fround((Math.fround(-(2**53-2)) ? (-0x0ffffffff >>> 0) : Math.atan(( + ((Math.fround(x) >>> 0) !== ( + x)))))) - (Math.hypot(x, ( + Math.min(mathy0(Math.fround(x), y), y))) | 0)) | 0))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, -(2**53), -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, 0x080000001, -0x0ffffffff, 42, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 0x07fffffff, -0x080000000, 2**53, -(2**53+2), -0x100000001, 1, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0, -0, -0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0, -1/0]); ");
/*fuzzSeed-451211*/count=254; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=255; tryItOut("for (var p in f1) { try { v0 = (a0 instanceof t2); } catch(e0) { } try { f1 = Proxy.createFunction(h0, f1, f2); } catch(e1) { } try { print(uneval(i1)); } catch(e2) { } t0 = new Int32Array(16); }");
/*fuzzSeed-451211*/count=256; tryItOut("/*MXX3*/g2.Date.parse = g0.Date.parse;");
/*fuzzSeed-451211*/count=257; tryItOut("/*bLoop*/for (var fznwgt = 0; fznwgt < 4; ++fznwgt) { if (fznwgt % 6 == 2) { /*infloop*/ for  each(let y in allocationMarker()) ( ''  >> c); } else { ; }  } ");
/*fuzzSeed-451211*/count=258; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.sign(Math.fround(Math.max(Math.fround((( + x) && (( - ((((x | 0) ? (( + (y >>> 0)) | 0) : (( + ( + ( + x))) | 0)) | 0) | 0)) >>> 0))), Math.fround((Math.abs((-0 >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [({valueOf:function(){return '0';}}), 0, undefined, (new Number(0)), objectEmulatingUndefined(), '', true, '\\0', 0.1, /0/, NaN, 1, -0, (new Boolean(false)), (function(){return 0;}), false, null, ({valueOf:function(){return 0;}}), (new Number(-0)), '0', (new String('')), [0], [], ({toString:function(){return '0';}}), '/0/', (new Boolean(true))]); ");
/*fuzzSeed-451211*/count=259; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - (((Math.sign((Math.max((Math.fround(( + y)) >>> 0), (y >>> 0)) >>> 0)) | 0) === (((Math.max((Math.atanh(((Math.log10(Math.max(Math.fround(0x100000001), Math.fround(x))) | 0) | 0)) | 0), (y | 0)) | 0) - ((( + x) ? (x >>> 0) : ( + (Math.expm1(Math.fround(0x100000001)) >>> 0))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy4, [-(2**53), 0x0ffffffff, -0x080000001, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 42, -0x07fffffff, 2**53+2, -(2**53-2), -0, 1, 0/0, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, 0.000000000000001, -Number.MIN_VALUE, -1/0, 0x100000001, 1.7976931348623157e308, -(2**53+2), 0]); ");
/*fuzzSeed-451211*/count=260; tryItOut("testMathyFunction(mathy3, [0/0, -(2**53), Math.PI, Number.MIN_VALUE, 2**53-2, -0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, -0, 1, 1.7976931348623157e308, 0.000000000000001, 0x100000000, Number.MAX_VALUE, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 1/0, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -0x100000001, 2**53, -0x080000000, 0x080000001, 0x100000001, 0x080000000, 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE]); ");
/*fuzzSeed-451211*/count=261; tryItOut("v1 = a0.reduce, reduceRight((function() { g0.__proto__ = e1; return o0; }), p1, t1, t1);");
/*fuzzSeed-451211*/count=262; tryItOut("a2.length = 10;");
/*fuzzSeed-451211*/count=263; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((-0x8000000)))|0;\n  }\n  return f; })(this, {ff: function(q) { \"use strict\"; return q; }}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [1, 0x0ffffffff, Number.MAX_VALUE, 0x100000000, 0.000000000000001, -0x080000000, 1.7976931348623157e308, 42, 0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x100000001, 0/0, 0, -0x100000000, -0x07fffffff, -(2**53+2), 2**53-2, -0, 2**53+2, -0x100000001, -(2**53), -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, 1/0, Math.PI]); ");
/*fuzzSeed-451211*/count=264; tryItOut("a, iqzhmv, ezpwku, gilwvg, xqiggf, kvjsvp;print(uneval(i0));");
/*fuzzSeed-451211*/count=265; tryItOut("\"use strict\"; \"use asm\"; v2 = null;");
/*fuzzSeed-451211*/count=266; tryItOut("mathy0 = (function(x, y) { return v2 = evaluate(\"i2 = new Iterator(m1);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: /(?:(?:[^]|[^])*?)*|(?=\\d|[^\\P-\\u0070]|[\\xB2-\u00e7\\cB\\\u43db]*?|(?=\\s[^]$))(?![\\S\\cL]+$){0,2147483649}/yi, catchTermination: true, elementAttributeName: this.g1.s1 }));; }); testMathyFunction(mathy0, /*MARR*/[[], x, [], x, [], new Number(1.5), new Number(1.5), x, new Number(1.5), [], new Number(1.5), x, x, new Number(1.5), new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [], [], x, [], new Number(1.5), new Number(1.5), [], x, [], new Number(1.5), x, new Number(1.5), new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x, [], new Number(1.5), new Number(1.5), [], new Number(1.5), x, [], new Number(1.5), new Number(1.5), [], x, new Number(1.5), new Number(1.5), [], new Number(1.5), new Number(1.5), [], new Number(1.5), [], new Number(1.5), new Number(1.5), new Number(1.5), [], [], new Number(1.5), x, x, [], x, new Number(1.5), new Number(1.5), x, new Number(1.5), [], [], [], [], [], new Number(1.5), [], [], new Number(1.5), new Number(1.5), new Number(1.5), x, new Number(1.5), [], new Number(1.5), new Number(1.5), new Number(1.5), [], new Number(1.5), x, x, new Number(1.5), x, [], [], new Number(1.5), new Number(1.5), new Number(1.5), x, x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x]); ");
/*fuzzSeed-451211*/count=267; tryItOut("\"use strict\"; this.v0 + '';");
/*fuzzSeed-451211*/count=268; tryItOut("o0 = Object.create(b0);");
/*fuzzSeed-451211*/count=269; tryItOut("\"use strict\"; b1 = new ArrayBuffer(4);");
/*fuzzSeed-451211*/count=270; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! mathy1((mathy0((( + (( + (Math.imul((((x >>> 0) & ( + x: this)) >>> 0), (y * (y || x))) | 0)) + (Math.fround(Math.atan(Math.fround(( ! Math.fround(y))))) | 0))) >>> 0), (x > ((Math.round(((x >>> 0) ? ( + -0x0ffffffff) : ( + y))) | 0) >>> 0))) >>> 0), mathy0((Math.atan2(y, ((Math.atanh((y >>> 0)) >>> 0) > ( ! y))) >>> 0), (mathy1(Math.log10(y), 0x100000000) | 0)))); }); testMathyFunction(mathy4, [0x100000000, 2**53-2, 0x100000001, -(2**53-2), 1, 0x080000000, Number.MIN_VALUE, -0x100000000, Math.PI, 2**53, 42, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000001, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 0x0ffffffff, 0/0, -0, 0.000000000000001, 0x080000001, 1.7976931348623157e308, 0x07fffffff, -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -1/0, 0, -Number.MAX_VALUE, -(2**53+2), 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=271; tryItOut("/*infloop*/for(var y = intern(Object.defineProperty(x, \"toString\", ({}))); \u3056; (4277) /= x = null) {for (var v of b2) { try { a0 = []; } catch(e0) { } Array.prototype.forEach.apply(a1, [(function() { try { t0.set(t0, 9); } catch(e0) { } try { m0.set(o2.e1, h1); } catch(e1) { } /*ODP-1*/Object.defineProperty(g1.i2, \"setFullYear\", ({writable: \u3056, configurable:  /x/g })); return o1; }), o2.e0, g0]); } }");
/*fuzzSeed-451211*/count=272; tryItOut("v0 = Object.prototype.isPrototypeOf.call(s0, a0);");
/*fuzzSeed-451211*/count=273; tryItOut("/*oLoop*/for (qpokzg = 0; qpokzg < 48; ++qpokzg) { e; } ");
/*fuzzSeed-451211*/count=274; tryItOut("a1.length = 3;");
/*fuzzSeed-451211*/count=275; tryItOut("\"use strict\"; {a1.shift(this.p2, e1, t2, s0, t2, g2, g0, o1, o1, o0.g0.s1); }");
/*fuzzSeed-451211*/count=276; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=277; tryItOut("let (b, x = x, ldhdyk, x = x, x = window, x, e, lhgzgn) { this.e2.valueOf = (function() { try { g1.i2 = new Iterator(a2); } catch(e0) { } try { t0.set(t1, 14); } catch(e1) { } s2 += 'x'; return g2; }); }");
/*fuzzSeed-451211*/count=278; tryItOut("mathy5 = (function(x, y) { return (Math.min((( ! Math.asin(Math.fround(Math.ceil(Math.fround((Math.fround(Math.expm1(y)) , Math.fround(( - y)))))))) | 0), (Math.fround(Math.hypot(Math.fround(( ! mathy4((-0x07fffffff >>> 0), ( + y)))), Math.atan2(Math.fround(Math.ceil(Math.fround(y))), (mathy0(((Math.atan((Math.fround((x == ( + x))) >>> 0)) | 0) >>> 0), Math.asin(x)) ? Math.imul((Math.fround(Math.hypot(Math.fround(x), Math.fround(x))) | 0), (x | 0)) : x)))) | 0)) | 0); }); ");
/*fuzzSeed-451211*/count=279; tryItOut("print(x);{for (var p in m1) { try { ; } catch(e0) { } try { g1.i0 + s1; } catch(e1) { } try { i1.send(i0); } catch(e2) { } v1 = Array.prototype.reduce, reduceRight.call(a2, (function(j) { if (j) { try { v2 = Object.prototype.isPrototypeOf.call(this.p0, t2); } catch(e0) { } try { m0.set(g0.v0, m0); } catch(e1) { } /*ADP-1*/Object.defineProperty(g0.a1, 15, ({value:  \"\" })); } else { try { v1 = Object.prototype.isPrototypeOf.call(e2, this.o2); } catch(e0) { } try { t2[\"\\uE362\"] = o1.s0; } catch(e1) { } s2.valueOf = (function() { Object.defineProperty(this, \"t2\", { configurable: false, enumerable: \"\\u8BEC\",  get: function() {  return t2.subarray(new RegExp(\"\\\\2\", \"i\")); } }); return i1; }); } }), e2); } }m1.has(v0)");
/*fuzzSeed-451211*/count=280; tryItOut("\"use strict\"; s2 + '';");
/*fuzzSeed-451211*/count=281; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a0, v2, { configurable: x, enumerable: true, writable: Object.defineProperty(x, \"x\", ({})) << x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: (({/*TOODEEP*/})).bind( /x/g , window), fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: undefined, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: undefined, keys: function() { throw 3; }, }; })(\"\\u4A44\"), ({e: \"\\u3162\"})), value: b1 });");
/*fuzzSeed-451211*/count=282; tryItOut("smndln( /x/ .watch(\"constructor\", Uint8ClampedArray));/*hhh*/function smndln(x = new RegExp(\"(?![^\\\\u21D6-\\u0014\\\\D]{1}|\\\\xF9^\\\\S+?{2})\", \"m\"), b, x ? Math.atan2(this <  /x/ , 12) : ( \"\" )().__defineSetter__(\"z\", new Function), e, x = new (-15)( /x/ ), y, x = (4277), window, {window}, eval, x, \u3056, {}, a, x, eval, ...\u3056){/*ODP-1*/Object.defineProperty(this.e2, \"call\", ({}));}");
/*fuzzSeed-451211*/count=283; tryItOut("mathy4 = (function(x, y) { return ( - ( + (( + ( + (( + (Math.trunc(x) >= x)) / ( + (( ! (( + mathy0((( - x) | 0), y)) >>> 0)) >>> 0))))) - Math.fround(Math.atanh(Math.fround((x != (x | 0)))))))); }); testMathyFunction(mathy4, [0.1, (new Boolean(true)), NaN, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), 0, undefined, -0, (new Number(-0)), /0/, 1, (function(){return 0;}), [], (new Number(0)), '0', [0], '', true, ({valueOf:function(){return '0';}}), (new String('')), '/0/', objectEmulatingUndefined(), null, (new Boolean(false)), false, '\\0']); ");
/*fuzzSeed-451211*/count=284; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.sinh(Math.pow((y <= Math.hypot(((x >>> 0) & ((Math.min(((x <= (y | 0)) | 0), Number.MAX_SAFE_INTEGER) >>> 0) >>> 0)), ( + (( - y) >>> 0)))), (( + (((( + x) - Math.fround(Math.sqrt((Math.atan2((y | 0), (y | 0)) >>> 0)))) >>> 0) | 0)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[false, false, new Boolean(true), new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), false, false, new ((Boolean.prototype.valueOf).call)(), false, new Boolean(true), false, new Boolean(true), new Boolean(true), new Boolean(true), false, false, new ((Boolean.prototype.valueOf).call)(), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), false, new ((Boolean.prototype.valueOf).call)(), false, new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), false, new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), false, false, false, new Boolean(true), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), false, false, false, new Boolean(true), new ((Boolean.prototype.valueOf).call)(), new Boolean(true), new Boolean(true), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), false, new ((Boolean.prototype.valueOf).call)(), false, new Boolean(true), new Boolean(true), false, new ((Boolean.prototype.valueOf).call)(), new Boolean(true), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), false, new ((Boolean.prototype.valueOf).call)(), new Boolean(true), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), new Boolean(true), false, new Boolean(true), new Boolean(true), new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), new ((Boolean.prototype.valueOf).call)(), false, new Boolean(true), new Boolean(true), false, false]); ");
/*fuzzSeed-451211*/count=285; tryItOut("this.a1.sort();");
/*fuzzSeed-451211*/count=286; tryItOut("\"use strict\"; v2 = a1[\"11\"];");
/*fuzzSeed-451211*/count=287; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.log10(( + ( + Math.atanh(Math.fround(( - (((y >>> 0) * (Math.fround(Math.atanh(Math.fround(x))) >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy4, /*MARR*/[-Infinity, new Boolean(true), -Infinity, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), [1], -Infinity, -Infinity, -Infinity]); ");
/*fuzzSeed-451211*/count=288; tryItOut("\"use strict\"; print(y);let y = --arguments;");
/*fuzzSeed-451211*/count=289; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-451211*/count=290; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[(1/0), (1/0), (1/0), [], (1/0), (1/0), (1/0), (1/0), (1/0), [], (1/0), (1/0), [], [], new Number(1), new Number(1), (1/0), new Number(1), new Number(1), new Number(1), [], [], [], [], [], (1/0), (1/0), (1/0), [], [], new Number(1), new Number(1), (1/0), (1/0), [], (1/0), new Number(1), new Number(1), new Number(1), new Number(1), []]) { /*bLoop*/for (xmvofx = 0; xmvofx < 22; ++xmvofx) { if (xmvofx % 90 == 51) { b0 + ''; } else { /*MXX2*/g2.String.prototype.toUpperCase = t0; }  }  }");
/*fuzzSeed-451211*/count=291; tryItOut("t2.valueOf = (function mcc_() { var hozrbb = 0; return function() { ++hozrbb; if (/*ICCD*/hozrbb % 11 == 9) { dumpln('hit!'); try { s2 += s1; } catch(e0) { } try { v0 = (this.i2 instanceof s0); } catch(e1) { } try { v1 = g2.a0.length; } catch(e2) { } t1[({valueOf: function() { a0 = [];return 15; }})] = f1; } else { dumpln('miss!'); a0 = Array.prototype.filter.apply(a0, [(function mcc_() { var miqjcz = 0; return function() { ++miqjcz; if (/*ICCD*/miqjcz % 6 == 5) { dumpln('hit!'); try { function g2.f0(g1.h2) ((a = 6) in ((/(\\3)(\\s\\w\\uF26D{3}[\\uc1e1\\w\\r-\\n\\t-\u00d9]\\2+)/yi)())) } catch(e0) { } try { g2.a0.push(g2); } catch(e1) { } try { o0.__proto__ = t1; } catch(e2) { } o1 = {}; } else { dumpln('miss!'); g0.offThreadCompileScript(\"a0 = arguments.callee.arguments;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 != 3), noScriptRval: Object.prototype.__lookupSetter__(x), sourceIsLazy: true, catchTermination: false, element: o1, elementAttributeName: g0.s0, sourceMapURL: s1 })); } };})()]); } };})();");
/*fuzzSeed-451211*/count=292; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( + ( + ((Math.hypot((-(2**53+2) >>> 0), (( + (( + (((x | 0) ? y : (( ~ Math.fround(y)) | 0)) >>> 0)) ^ ( + x))) >>> 0)) | 0) | 0))) != ( - ( + ( + ( + (mathy0((x | 0), (Math.tan(((Math.fround((0x100000001 < y)) + Math.fround((Math.fround(x) % x))) >>> 0)) | 0)) | 0)))))); }); ");
/*fuzzSeed-451211*/count=293; tryItOut("v1 = (e0 instanceof h2);");
/*fuzzSeed-451211*/count=294; tryItOut("for(let y in (void version(180))) selectforgc(o2);");
/*fuzzSeed-451211*/count=295; tryItOut("\"use strict\"; for (var p in o2.a1) { a1.pop(v1); }");
/*fuzzSeed-451211*/count=296; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((( + (Math.fround(Math.atan2(y, Math.fround(Math.log10(-0x100000001)))) >>> 0)) >>> 0) ? Math.atanh(( + Math.pow(Math.fround((x ^ (x ? y : -Number.MIN_SAFE_INTEGER))), Math.fround(Math.cos(Math.fround(Math.pow(Math.imul(y, x), ( + x)))))))) : ((Math.expm1(Math.trunc(( + ( - ( + x))))) >>> 0) ? Math.imul((((Math.log10(Math.atan2(y, x)) | 0) != (x | 0)) | 0), (((( + ( + x)) | 0) - Math.atan2(y, ( + ( + x)))) | 0)) : Math.imul(Math.pow(( + (Math.log(( ~ x)) < ( + Math.min(y, y)))), (( + Math.trunc(Math.fround(( - x)))) && Math.asinh(( + (y && y))))), Math.fround(Math.imul(Math.fround(((y % (y >>> 0)) >>> 0)), Math.fround(-0x100000001)))))); }); ");
/*fuzzSeed-451211*/count=297; tryItOut("\"use strict\"; a2.sort((function() { for (var p in this.a2) { try { /*RXUB*/var r = r0; var s = s1; print(s.search(r));  } catch(e0) { } v2 = -Infinity; } return a1; }));");
/*fuzzSeed-451211*/count=298; tryItOut("mathy0 = (function(x, y) { return Math.pow((Math.tanh(((Math.atan2((Math.atan2((Math.trunc((x >>> 0)) >>> 0), (y ? y : (( ! (x | 0)) | 0))) | 0), ((Math.fround(y) >= Math.fround(new RegExp(\"((?=$(?:\\\\W[^]))*)(?=\\\\D)\\\\D\", \"\"))) | 0)) | 0) >>> 0)) >>> 0), ( + ((((Math.atan((y | 0)) ^ y) >>> 0) | 0) ? ((Math.atan((((( + y) < ( + -Number.MAX_SAFE_INTEGER)) | 0) >>> 0)) >>> 0) | 0) : (Math.max((Math.log2(Math.fround(y)) >= (y , x)), (2**53-2 , Number.MAX_SAFE_INTEGER)) | 0)))); }); ");
/*fuzzSeed-451211*/count=299; tryItOut("\"use strict\"; for(let x = window in x) /*ADP-3*/Object.defineProperty(a0, v0, { configurable: true, enumerable: true, writable: (x % 43 != 6), value: h1 });");
/*fuzzSeed-451211*/count=300; tryItOut("/*RXUB*/var r = Math.ceil(-23); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=301; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((((Math.round(((Math.sign(-0x07fffffff) | ((Math.imul((( - y) | 0), (y | 0)) | 0) >>> 0)) | 0)) | 0) | 0) ? Math.imul(( + mathy0((( ! ((Math.PI >>> 0) >= (Number.MAX_SAFE_INTEGER >>> 0))) | 0), (( + mathy0(( + ( ! x)), (Math.imul((x | 0), (0x080000000 | 0)) | 0))) >>> 0))), Math.fround(Math.imul(Math.fround(0x100000000), Math.fround(( + Math.atan2(( + ( ~ y)), ( + -(2**53-2)))))))) : (( - (Math.exp(( + ( + ((( + (-0x080000001 < Math.atanh(y))) ** (((y >>> 0) + y) >>> 0)) >>> 0)))) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-451211*/count=302; tryItOut("for(let b of /*MARR*/[new Number(1), new Number(1), new String(''), new String(''), x, x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String(''), new Boolean(true), new Boolean(true), new String(''), x, new String(''), new Number(1), x]) yield  /x/g ;let(d) { (arguments);}");
/*fuzzSeed-451211*/count=303; tryItOut("v0.__proto__ = b1;");
/*fuzzSeed-451211*/count=304; tryItOut("o1.v1 = (this.g0 instanceof p2);");
/*fuzzSeed-451211*/count=305; tryItOut("\"use strict\"; (void options('strict'));");
/*fuzzSeed-451211*/count=306; tryItOut("throw StopIteration;return Math.hypot(10, window);");
/*fuzzSeed-451211*/count=307; tryItOut("testMathyFunction(mathy2, [2**53, 0/0, 0x100000001, -(2**53), -0x0ffffffff, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), 0x080000001, -0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), 0x100000000, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, Math.PI, 1, 0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -0, 42, -0x080000001, -1/0, -0x100000001, -0x100000000, 2**53+2, 1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=308; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.asin((((mathy1((Math.imul((Math.fround(((y | 0) << Math.log1p(0x0ffffffff))) | 0), (x | 0)) | 0), ( - Math.sin(x))) ? (Math.sin(Math.fround(-Number.MIN_SAFE_INTEGER)) >>> 0) : y) <= (( + (((( ! ( ~ (-0x080000000 | 0))) >>> 0) + (Math.imul(y, y) >>> 0)) ? (Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround((x , ( + (((x >>> 0) | (-0 >>> 0)) >>> 0)))))) | 0) : ( + mathy0((y | 0), ((Math.atan2((x >>> 0), -(2**53+2)) >>> 0) | 0))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [(function(){return 0;}), ({valueOf:function(){return '0';}}), '0', 0.1, undefined, objectEmulatingUndefined(), '\\0', false, (new Number(-0)), ({toString:function(){return '0';}}), '/0/', /0/, NaN, (new Boolean(true)), -0, (new Number(0)), (new String('')), '', ({valueOf:function(){return 0;}}), null, 1, 0, [0], [], (new Boolean(false)), true]); ");
/*fuzzSeed-451211*/count=309; tryItOut("g2 + g1;");
/*fuzzSeed-451211*/count=310; tryItOut("\"use strict\"; m1.set([z1,,], \u3056-=x);");
/*fuzzSeed-451211*/count=311; tryItOut("((makeFinalizeObserver('tenured'))) >>>= x.__defineSetter__(\"b\", String.prototype.replace);");
/*fuzzSeed-451211*/count=312; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.imul(( + ( ! Math.max(Math.fround(( + Math.fround(Math.fround(Math.asinh(( + ((0 != y) >>> 0))))))), Math.pow(0x100000001, ((((((-Number.MIN_VALUE >>> 0) != (( + ((-0 >>> 0) >>> ( + y))) >>> 0)) >>> 0) >>> 0) , (( + ( + x)) | 0)) | 0))))), ( - (Math.imul(x, Math.hypot((Math.clz32(x) | 0), y)) >>> Math.fround(( - (((x | 0) >= -(2**53-2)) | 0))))))); }); testMathyFunction(mathy1, [-(2**53+2), 0x100000001, 1/0, -0x080000001, -1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0, -(2**53-2), 0x100000000, -0x100000000, 0/0, 1.7976931348623157e308, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, 2**53, 0x080000001, -0x07fffffff, 42, -0, -Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0x07fffffff, 2**53+2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, Math.PI]); ");
/*fuzzSeed-451211*/count=313; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-1/0, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 1/0, -(2**53-2), 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, 2**53+2, Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0, 1.7976931348623157e308, 0x100000001, Number.MAX_VALUE, Math.PI, 0x100000000, 2**53, -(2**53), -0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 0x080000001, -Number.MAX_VALUE, 1, -0x080000001, -(2**53+2), -0]); ");
/*fuzzSeed-451211*/count=314; tryItOut("{ void 0; try { gcparam('sliceTimeBudget', 74); } catch(e) { } } (/(?:\\B+?)**/m);");
/*fuzzSeed-451211*/count=315; tryItOut("\"use strict\"; g1.m1.delete(s1);");
/*fuzzSeed-451211*/count=316; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.clz32(( + (((Math.sin(( ~ (( + Math.cosh(y)) | 0))) | 0) >> (Math.max(Math.max((( + Math.fround(Math.tanh(Math.atan2((y >>> 0), (-Number.MIN_VALUE >>> 0))))) >>> 0), ( + (x % ( - x)))), x) | 0)) | 0))); }); testMathyFunction(mathy0, [0, (new String('')), undefined, false, null, 0.1, [], '0', ({toString:function(){return '0';}}), '/0/', (new Boolean(true)), -0, '\\0', true, [0], objectEmulatingUndefined(), 1, (new Boolean(false)), (new Number(0)), (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Number(-0)), /0/, NaN, '', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-451211*/count=317; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! (mathy4((Math.fround(mathy4(Math.fround(Math.max(Math.cosh((((0x100000000 >>> 0) ** (x >>> 0)) >>> 0)), y)), mathy1(Math.fround(Math.hypot(( + y), ( + Math.cbrt(0x080000000)))), ( + Math.fround((Math.fround(x) === Math.fround(x))))))) | 0), (Math.acosh(((( + ( + ( + ( + y)))) ? ((y | 0) ? (( + Math.hypot((( ! ( + y)) | 0), (y | 0))) | 0) : (y | 0)) : y) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy5, [-0x07fffffff, 1.7976931348623157e308, 0x080000001, 0x0ffffffff, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, -0x100000000, -(2**53+2), 1, Number.MAX_VALUE, 0/0, 0x100000001, -(2**53), 1/0, Math.PI, 42, 2**53, -0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, -1/0, 0, 2**53-2, -(2**53-2), 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=318; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    (Float64ArrayView[((((i2)*-0x7768) ^ (-(0xfdeda81b))) / (((!(0xfd3d66a9))-((0x44a7e637) >= (0x610d0b22))) >> ((0xe5e89d3e) / (0xa9e9e10a)))) >> 3]) = ((d1));\n    return (((/*FFI*/ff(((~~(d0))), ((0x61481ab9)), ((~~(d1))), ((+(((0xf84fde60))|0))), ((d1)), ((-257.0)), ((d0)), ((((0xf9e68ce2)) >> ((0xdb3e77f7)))), ((2.4178516392292583e+24)), ((-1099511627775.0)), ((-295147905179352830000.0)), ((1.9342813113834067e+25)), ((-2097151.0)), ((295147905179352830000.0)), ((9.671406556917033e+24)), ((-2147483647.0)), ((70368744177665.0)), ((1125899906842623.0)), ((-33.0)), ((34359738369.0)), ((-147573952589676410000.0)), ((-0.03125)), ((17.0)), ((1.0078125)), ((-1.888946593147858e+22)))|0)+(0xc3d3e93b)))|0;\n    return (((0xffffffff)))|0;\n  }\n  return f; })(this, {ff: String.prototype.substr}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[-Infinity, -Infinity, NaN, 0x080000001, NaN, 0x080000001, NaN, NaN, -Infinity, -Infinity, null, -Infinity, 0x080000001, 0x080000001, 0x080000001, null, null,  '' ,  '' ,  '' , null, 0x080000001, null,  '' , NaN, NaN, 0x080000001, NaN,  '' , NaN, -Infinity, 0x080000001, null, 0x080000001, NaN, NaN,  '' , 0x080000001,  '' , NaN, -Infinity, -Infinity, null, null,  '' , null, 0x080000001, -Infinity, 0x080000001, NaN, null,  '' , NaN,  '' ,  '' ,  '' , NaN, null, NaN, -Infinity, -Infinity,  '' , 0x080000001, null, -Infinity, -Infinity]); ");
/*fuzzSeed-451211*/count=319; tryItOut("g2.v0 = g2.eval(\"t0 = new Int8Array(t0);\");a1.pop();\u000c");
/*fuzzSeed-451211*/count=320; tryItOut("s2 += s1;");
/*fuzzSeed-451211*/count=321; tryItOut("\"use strict\"; m2.get((4277));/*MXX2*/g2.ReferenceError = o1;");
/*fuzzSeed-451211*/count=322; tryItOut("g1.m2.set(this.v2, h0);");
/*fuzzSeed-451211*/count=323; tryItOut("this.m2 = new Map(b0);");
/*fuzzSeed-451211*/count=324; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s0; print(s.split(r)); ");
/*fuzzSeed-451211*/count=325; tryItOut("o2.v2 = Object.prototype.isPrototypeOf.call(g1.o1.e2, v2);");
/*fuzzSeed-451211*/count=326; tryItOut("s0 += 'x';");
/*fuzzSeed-451211*/count=327; tryItOut("testMathyFunction(mathy3, [Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, Math.PI, -0x080000001, 0x100000000, -(2**53), -Number.MAX_VALUE, 0/0, -0x100000001, -0x080000000, 2**53, 0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), 1.7976931348623157e308, 0x080000000, 1, 0, -0, -0x07fffffff, 0x080000001, 2**53-2, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=328; tryItOut("var v2 = t1.length;");
/*fuzzSeed-451211*/count=329; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0x100000001, 1, 2**53, -1/0, 0.000000000000001, 42, 2**53-2, 2**53+2, 1.7976931348623157e308, 0/0, -0, -Number.MAX_VALUE, -0x100000000, 0x100000000, 0x080000001, Number.MAX_VALUE, -(2**53-2), -0x080000000, -(2**53+2), 0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, 1/0, -0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=330; tryItOut("mathy4 = (function(x, y) { return (( + ( + mathy2((((y | 0) >= ((( ~ (x | 0)) >>> 0) | 0)) >>> 0), x))) | 0); }); testMathyFunction(mathy4, /*MARR*/[arguments, (z = d), (z = d), arguments, arguments, (void 0), (void 0), arguments, (z = d), arguments, arguments, (void 0), (z = d), (void 0), arguments, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (z = d), (z = d), arguments, (z = d), (z = d), (void 0), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d), (z = d)]); ");
/*fuzzSeed-451211*/count=331; tryItOut("\"use strict\"; Array.prototype.shift.call(a1);");
/*fuzzSeed-451211*/count=332; tryItOut("for (var p in g2) { Array.prototype.splice.call(a0, NaN, o1.v2); }");
/*fuzzSeed-451211*/count=333; tryItOut("h1.valueOf = f2;");
/*fuzzSeed-451211*/count=334; tryItOut("{h2.toSource = (function(j) { if (j) { try { m2.has(e0); } catch(e0) { } try { a1.unshift(b1); } catch(e1) { } for (var v of e0) { try { for (var v of b1) { try { t2 + o0.o1; } catch(e0) { } v2 = (s0 instanceof this.a1); } } catch(e0) { } try { /*RXUB*/var r = r1; var s = s1; print(uneval(r.exec(s)));  } catch(e1) { } try { a2.splice(-10, 3,  \"\" ); } catch(e2) { } /*ODP-3*/Object.defineProperty(this.i0, \"call\", { configurable: false, enumerable: (x % 3 == 2), writable: true, value: e0 }); } } else { o2 = {}; } });o1 = Object.create(o2.v1); }");
/*fuzzSeed-451211*/count=335; tryItOut("\"use strict\"; with({}) { let( /x/g [\"constructor\"] = let (z = d.watch(\"caller\", new Function)) (p={}, (p.z =  \"\" )()), vkmmrx, [] = /*FARR*/[].sort ? ((p={}, (p.z = /(?:\\1)/gim)())) : (x = z), x = x) { x = c;} } throw StopIteration;");
/*fuzzSeed-451211*/count=336; tryItOut("v0 = Object.prototype.isPrototypeOf.call(i0, a0);");
/*fuzzSeed-451211*/count=337; tryItOut("\"use strict\"; this.a1.forEach(ReferenceError.bind(f1), x.getOwnPropertyNames(c = timeout(1800), (4277)));");
/*fuzzSeed-451211*/count=338; tryItOut("\"use strict\"; s2 + '';");
/*fuzzSeed-451211*/count=339; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=340; tryItOut("mathy1 = (function(x, y) { return (((Math.pow(( + Number.MIN_VALUE), x) | 0) < (((((( + x) >>> 0) ? x : ((x || 2**53) >>> 0)) >>> 0) - ( - ( + x))) | 0)) || Math.sinh((( + (-(2**53+2) & ( + y))) && x))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, 42, -0x100000001, 0x080000000, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, 0x080000001, -0, 0x07fffffff, -(2**53+2), -0x100000000, -0x0ffffffff, -(2**53), -0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1, Math.PI, -0x080000000, 1/0, Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-451211*/count=341; tryItOut("var mjyqbk, x, rjlfac, c, yxvmxp;/*hhh*/function xhgodr(){delete e0[11];}\u000c/*iii*/r0 = /(?=\\cV)|.|[^]*|.{0}/gm;");
/*fuzzSeed-451211*/count=342; tryItOut("/*oLoop*/for (lfvqoy = 0; lfvqoy < 97; ++lfvqoy) { o0.valueOf = (function mcc_() { var qjupzg = 0; return function() { ++qjupzg; if (/*ICCD*/qjupzg % 10 == 9) { dumpln('hit!'); try { g1.v2 = o1.a2.every(eval); } catch(e0) { } s1 = t2['fafafa'.replace(/a/g, RegExp.prototype.toString)]; } else { dumpln('miss!'); m0.get(v1); } };})(); } ");
/*fuzzSeed-451211*/count=343; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = ((0xffffffff) != ((((Int16ArrayView[((((0xb451e7b6)+(/*FFI*/ff(((536870913.0)), ((16777217.0)), ((-8388609.0)), ((4294967295.0)), ((-4294967297.0)), ((8388607.0)))|0)))) >> 1])) / (0xcf26ef6e))>>>((Float32ArrayView[1]))));\n    i2 = (i2);\n    d0 = (+(-1.0/0.0));\n    return +((d1));\n  }\n  return f; })(this, {ff: \n/(?=\\s){1,}/im}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MIN_VALUE, -(2**53), Number.MIN_VALUE, -0, 0x100000001, 0x080000001, 0, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, -1/0, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -0x080000000, 0/0, -0x100000000, 0x0ffffffff, -0x0ffffffff, Math.PI, 0x080000000, 1, -0x080000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000001, 1/0, 42, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-451211*/count=344; tryItOut("e1 + h0;");
/*fuzzSeed-451211*/count=345; tryItOut("\"use asm\"; /*vLoop*/for (fnelvt = 0; fnelvt < 1; ++fnelvt) { const d = fnelvt; e0 = new Set(s1); } ");
/*fuzzSeed-451211*/count=346; tryItOut("/*bLoop*/for (var usiqeu = 0; usiqeu < 22; ++usiqeu) { if (usiqeu % 3 == 0) { /* no regression tests found */ } else { let (e) { print((w) = (void version(185))); } }  } ");
/*fuzzSeed-451211*/count=347; tryItOut("\"use strict\"; a1 = a1.concat(t2, a0, g1.t2);");
/*fuzzSeed-451211*/count=348; tryItOut("\"use strict\"; v0 = (p0 instanceof o0.a0);");
/*fuzzSeed-451211*/count=349; tryItOut("\"use strict\"; print(uneval(a0));");
/*fuzzSeed-451211*/count=350; tryItOut("i2.next();");
/*fuzzSeed-451211*/count=351; tryItOut("v1 = (v0 instanceof this.p2);");
/*fuzzSeed-451211*/count=352; tryItOut("let (x = (4277), x, NaN = (Uint16Array(/*FARR*/[...[], 42177246,  '' ,  '' ], (function(){}))), this.zzz.zzz =  '' , x = new Root(-907808524.5), z) { o0.v2 = Infinity;\nv0 = this.a2.length;\n }");
/*fuzzSeed-451211*/count=353; tryItOut("Object.defineProperty(this, \"t2\", { configurable: true, enumerable: false,  get: function() {  return t2.subarray(arguments = x = Proxy.createFunction(({/*TOODEEP*/})(\"\\u1F58\"), function shapeyConstructor(kzvoom){\"use strict\"; { yield; } Object.defineProperty(this, \"arguments\", ({writable: kzvoom, configurable: new RegExp(\"(?!\\\\3(\\\\b|\\\\x4A{4})(?:[\\\\w\\\\x4C-\\u00c9\\\\W\\\\u0050-\\\\uC141]|\\\\u54FB[\\u61c3\\u0003-\\\\u3b21\\\\d\\u22d4-\\\\uD6F9]){4,})\", \"gym\")}));if (kzvoom) delete this[-11];if (kzvoom) delete this[-11];{ delete h2.get; } if (-18) this[-11] = eval;return this; })); } });for (var p in s1) { /*RXUB*/var r = o1.r2; var s = \"\\n\\n\\n\\n\\n\\n\"; print(r.exec(s));  }");
/*fuzzSeed-451211*/count=354; tryItOut("/*RXUB*/var r = /(?:(?!\\3|(?:\\d\\u618a{1}(?:\\b))|.\\1|(?:[^])[^]|\\B?))/i; var s = \"a\\u618aa\\u618a \\n\\u00e1\\nc\"; print(r.exec(s)); ");
/*fuzzSeed-451211*/count=355; tryItOut("(((p={}, (p.z = (void options('strict_mode')).throw(( /x/g  %= window) <= x))())));");
/*fuzzSeed-451211*/count=356; tryItOut("Object.prototype.watch.call(i0, \"toSource\", (function mcc_() { var lzvyaj = 0; return function() { ++lzvyaj; if (/*ICCD*/lzvyaj % 10 == 8) { dumpln('hit!'); try { /*ODP-3*/Object.defineProperty(o2.i1, \"__proto__\", { configurable: (x % 6 != 1), enumerable: x ? 28 : (4277), writable: false, value: v2 }); } catch(e0) { } m2.has(v1); } else { dumpln('miss!'); try { Object.defineProperty(this, \"v2\", { configurable: true, enumerable: true,  get: function() { v2 = (f2 instanceof g0); return this.a1.some((function() { try { this.b0 + o1; } catch(e0) { } try { h1.set = f1; } catch(e1) { } m2.get(i1); return a2; })); } }); } catch(e0) { } try { t1 = new Uint32Array(this.b1); } catch(e1) { } s1 += 'x'; } };})());");
/*fuzzSeed-451211*/count=357; tryItOut("\"use strict\"; if((x % 3 == 1)) {var bcmvha = new ArrayBuffer(8); var bcmvha_0 = new Int16Array(bcmvha); var bcmvha_1 = new Uint16Array(bcmvha); bcmvha_1[0] = -24; var bcmvha_2 = new Int16Array(bcmvha); print(bcmvha_2[0]); bcmvha_2[0] = -28; var bcmvha_3 = new Int8Array(bcmvha); print(bcmvha_3[0]); bcmvha_3[0] = 4; var bcmvha_4 = new Int8Array(bcmvha); print(bcmvha_4[0]); bcmvha_4[0] = 19; e2.add(i1);(this);print(uneval(b0));print(bcmvha_1);a2 = Array.prototype.slice.apply(this.a0, [3, NaN]); } else  if (/(?!(\u0876{4,}))\\b/yim) {print(-19); }");
/*fuzzSeed-451211*/count=358; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((Math.fround(( ! (Math.log(y) >> Math.fround((( ~ y) >>> 0))))) < Math.fround((Math.max((Math.imul(( - ((Math.atan2(42, (Math.cos((Math.PI >>> 0)) >>> 0)) ** (((y || (-Number.MAX_VALUE >>> 0)) >>> 0) >>> 0)) >>> 0)), (Math.asinh((Math.cos((Math.imul(Math.acosh(Math.fround(-0)), -Number.MAX_VALUE) >>> 0)) >>> 0)) | 0)) >>> 0), ((x / Math.atan2((y && Math.fround(x)), ( + Math.fround(( - (Math.fround(((y >>> 0) <= y)) | 0)))))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-451211*/count=359; tryItOut("\"use strict\"; g1.v2 = (t0 instanceof i1);");
/*fuzzSeed-451211*/count=360; tryItOut("v0 = g2.runOffThreadScript();");
/*fuzzSeed-451211*/count=361; tryItOut("\"use asm\"; g1.v0.__proto__ = o2;");
/*fuzzSeed-451211*/count=362; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy1(Math.fround(Math.min(Math.fround(( ~ Math.fround(( + ( + ( ~ x)))))), ( + mathy1((Math.atanh((y >>> 0)) >>> 0), Math.asin(x))))), (( + Math.fround(Math.log(Math.fround((Math.exp(((( ~ (x >>> 0)) | 0) >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 0.000000000000001, 1/0, -0x080000001, -0x080000000, 1, -(2**53-2), 0x0ffffffff, -Number.MAX_VALUE, 2**53, -0, 0x100000001, -0x07fffffff, Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, 1.7976931348623157e308, -0x100000000, -0x0ffffffff, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000001, 0x07fffffff, 42, Number.MIN_VALUE, 0, -(2**53)]); ");
/*fuzzSeed-451211*/count=363; tryItOut("for (var v of v2) { try { a2 = Array.prototype.slice.apply(a0, [1, 7, g2, i1]); } catch(e0) { } try { i2 = a2.keys; } catch(e1) { } m0 + s1; }");
/*fuzzSeed-451211*/count=364; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1, -0x07fffffff, 42, -(2**53+2), Number.MIN_VALUE, -(2**53), 1/0, -Number.MAX_VALUE, Math.PI, -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, Number.MIN_SAFE_INTEGER, 0/0, -0, 0, 2**53+2, -0x100000001, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -1/0, -0x0ffffffff, 0x0ffffffff, -0x080000001, 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001]); ");
/*fuzzSeed-451211*/count=365; tryItOut(";");
/*fuzzSeed-451211*/count=366; tryItOut("a0.splice(-1, 5);/*oLoop*/for (bqcrho = 0; bqcrho < 29; ++bqcrho) { print(x); } ");
/*fuzzSeed-451211*/count=367; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.max(((Math.pow((((( - y) >>> 0) >>> ( + (x ? ( ~ (((x | 0) , y) | 0)) : Math.fround(mathy4(((( + 0.000000000000001) >>> 0) >>> 0), (Math.acosh(y) >>> 0)))))) >>> 0), (( ~ Math.log(x)) >>> 0)) >>> 0) | 0), (((( ~ ((( ! y) ? ( + Math.cosh(y)) : y) | 0)) | 0) ? Math.max(( ! Math.fround(y)), (Math.tan((Math.min((-0x0ffffffff | 0), (Math.fround(( + y)) >>> 0)) | 0)) | 0)) : ( ~ (( ~ (Math.fround((Math.fround(( + Math.imul((x >>> 0), (y >>> 0)))) > Math.fround((Math.pow(((mathy3((-(2**53-2) >>> 0), y) >>> 0) >>> 0), (y >>> 0)) >>> 0)))) >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy5, [-0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -0x080000000, 0, -0, -0x080000001, Math.PI, 0x100000001, -0x100000000, -Number.MIN_VALUE, -1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 1, 0x100000000, 2**53+2, -0x100000001, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, -(2**53), 42, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, 1/0, -0x0ffffffff]); ");
/*fuzzSeed-451211*/count=368; tryItOut("\"use strict\"; this.a0[v1];");
/*fuzzSeed-451211*/count=369; tryItOut("\"use strict\"; /*RXUB*/var r = /\\uFacD*/gm; var s = \"\\u8448\\u8448\\u8448\\u8448\"; print(r.exec(s)); ");
/*fuzzSeed-451211*/count=370; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((((mathy1(( + (Math.acos((Math.fround((((Math.imul(y, -1/0) + (y | 0)) | 0) || mathy3(( + -Number.MIN_SAFE_INTEGER), Math.sqrt(x)))) | 0)) | 0)), ( + ( ! Math.atan2(x, (mathy4((42 | 0), (y | 0)) | 0))))) | 0) | 0) == ((Math.log2(Math.fround((Math.atanh((mathy2(( + x), (x != 0)) | 0)) >>> 0))) | 0) | 0)) | 0); }); testMathyFunction(mathy5, [-0x100000000, -0x080000001, Number.MAX_VALUE, 0x080000001, 0x100000001, -0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 42, 2**53-2, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 1/0, -0x080000000, 2**53+2, 0x100000000, 0, 0/0, -0, 1.7976931348623157e308, 2**53, -(2**53), -(2**53+2), Math.PI, -1/0, -0x100000001]); ");
/*fuzzSeed-451211*/count=371; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((abs(((((y = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: (function(x, y) { return y; }), getOwnPropertyNames: function() { return []; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(( \"\"  in b)), (let (myyjrd)  /x/ ))))*0xfffff)|0))|0) < ((((makeFinalizeObserver('nursery')))) & (((0xffffffff))-((+(1.0/0.0)) >= (((d0)) % ((Float32ArrayView[0])))))))))|0;\n  }\n  return f;eval })(this, {ff: (neuter).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53+2), 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, -0, Number.MIN_VALUE, 0/0, 2**53, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, 0, 0x0ffffffff, Math.PI, -0x080000001, 1, -(2**53), Number.MAX_VALUE, -0x080000000, 2**53+2, 0x080000001, -0x07fffffff, 0x07fffffff, -0x0ffffffff, -0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 42, 0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-451211*/count=372; tryItOut("\"use strict\"; a0.forEach(o0);");
/*fuzzSeed-451211*/count=373; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[ /x/ ,  /x/ , new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5),  /x/ , new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/ , new Number(1.5),  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5), new Number(1.5),  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), new Number(1.5),  /x/ , new Number(1.5),  /x/ ,  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5), new Number(1.5),  /x/ ,  /x/ , new Number(1.5), new Number(1.5), new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5),  /x/ ,  /x/ , new Number(1.5),  /x/ , new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ]) { s0 += s0; }");
/*fuzzSeed-451211*/count=374; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=375; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atan((((Math.max(( - Number.MAX_VALUE), Math.cosh(x)) | 0) , ( + (((Math.atan2(Math.fround(x), Math.fround((Math.max(-0x07fffffff, -1/0) ? y : x))) >>> 0) >> ((Math.pow((((2**53 >>> 0) > -(2**53+2)) | 0), ( - mathy0(1/0, mathy0(y, (y >>> 0))))) >>> 0) >>> 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy1, [42, -0x080000000, -0, -Number.MAX_SAFE_INTEGER, 0, -0x100000001, Math.PI, Number.MAX_VALUE, -(2**53-2), 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 0x080000001, 1, -Number.MIN_VALUE, 1/0, -(2**53+2), Number.MIN_VALUE, -(2**53), 2**53+2, 0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, 0x100000001, -0x100000000, 0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 1.7976931348623157e308, -0x07fffffff, 0/0]); ");
/*fuzzSeed-451211*/count=376; tryItOut("\"use asm\"; z = (Math.round(-16777217));{}");
/*fuzzSeed-451211*/count=377; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ Math.trunc(( ~ -0x100000001))); }); testMathyFunction(mathy5, [-(2**53+2), 0x100000000, -0x080000001, 42, -0x07fffffff, -0, 0x080000000, 1/0, 2**53-2, 1, -(2**53), 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, 0.000000000000001, -0x100000001, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, 0, Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-451211*/count=378; tryItOut("t0 = new Float64Array(b2, 80, 11);");
/*fuzzSeed-451211*/count=379; tryItOut("h1.has = f2;");
/*fuzzSeed-451211*/count=380; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a1, x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(new RegExp(\"((?=(?:(?=\\\\cU{0,3})))(?![^]))*\", \"gym\")), ( /x/  +=  /x/ )), { configurable: (x % 6 == 4), enumerable: (x % 4 != 2), get: (function(a0, a1, a2, a3, a4) { var r0 = x + x; var r1 = r0 & x; var r2 = a4 % 0; var r3 = r2 - 0; var r4 = x - x; var r5 = x * r0; var r6 = 9 * a2; print(r0); var r7 = a2 + r3; print(r6); var r8 = 5 % 9; var r9 = r0 ^ r8; r7 = a3 / r3; var r10 = r7 - r1; var r11 = r5 & 6; r5 = a4 | r3; var r12 = 2 + 7; r0 = 0 & r5; var r13 = a3 & r12; var r14 = a0 | 9; var r15 = 0 & 3; var r16 = 8 ^ r3; var r17 = 2 | r7; var r18 = a3 % 5; var r19 = 0 / x; var r20 = r0 / 1; var r21 = r12 ^ r19; var r22 = r13 | r14; var r23 = 6 * 5; var r24 = r19 + 1; r21 = x | 6; r21 = r22 & 5; var r25 = 5 % r1; var r26 = r17 ^ 5; var r27 = r22 | 8; var r28 = r2 * 3; var r29 = r26 & 2; r15 = a4 % 3; var r30 = r1 * r20; var r31 = a4 * 6; r10 = r2 - 6; var r32 = 7 & r20; r14 = r32 - r21; a3 = r5 / 3; var r33 = r25 ^ r28; var r34 = 1 / a4; var r35 = r3 & r34; var r36 = 7 / 5; a2 = 0 + 6; r4 = 5 * r25; var r37 = 3 ^ x; var r38 = 5 ^ r18; var r39 = r28 & 4; var r40 = r22 ^ r37; var r41 = 7 - r36; r7 = r29 & 1; r7 = r10 | 2; var r42 = 1 % 8; var r43 = 1 / a1; var r44 = r16 - r42; var r45 = r19 % 3; var r46 = r10 % 5; print(r13); r4 = r38 | r11; var r47 = r25 * 5; var r48 = 0 + a2; r11 = r1 - r36; var r49 = r9 ^ 3; a0 = r38 * r41; var r50 = r21 - 8; var r51 = 3 | a3; var r52 = r5 % 9; var r53 = r35 | r4; r46 = 0 | r39; var r54 = r23 - r18; var r55 = r2 & r50; var r56 = r48 / r18; var r57 = 1 / r39; var r58 = r25 + r53; r52 = 1 + 2; var r59 = r1 | 0; r24 = 3 * r26; var r60 = r58 ^ r15; var r61 = r26 + r57; r0 = r13 | r19; r5 = r24 / 1; var r62 = 2 ^ 0; r30 = r34 ^ r12; var r63 = 8 / 8; r50 = r48 ^ r14; var r64 = 8 + x; var r65 = r62 ^ 3; var r66 = 1 & r2; var r67 = r37 & r26; r18 = 7 | r27; r23 = 9 & 1; var r68 = 7 ^ 3; print(r30); a1 = r7 / 4; var r69 = r48 * 2; var r70 = 2 & 8; r8 = 1 | r38; var r71 = r22 ^ r55; var r72 = r46 | 5; r45 = r58 | r3; var r73 = r23 & r21; var r74 = 8 / 1; a3 = r30 % r35; var r75 = r42 - r15; var r76 = a2 + r5; var r77 = r25 / 5; var r78 = r13 + r55; var r79 = 2 ^ r1; r12 = r57 & 6; var r80 = 3 + r24; var r81 = r53 % 7; var r82 = x + r71; var r83 = r16 / 1; var r84 = r76 ^ 7; r16 = r39 % 2; var r85 = r82 ^ 5; r43 = 8 % r24; var r86 = r60 * 7; var r87 = a3 + r1; var r88 = r64 * a3; var r89 = r46 % r80; var r90 = r37 % r44; var r91 = 6 * 5; r48 = r0 / r75; var r92 = r31 & 4; var r93 = a4 ^ 2; var r94 = 4 / r43; print(r56); print(r65); r88 = a4 * r45; var r95 = r53 | 3; var r96 = r46 - 3; r59 = r51 % a0; var r97 = r66 - r31; var r98 = 9 & r29; r97 = r80 - r1; r5 = r39 - 5; r59 = 8 ^ r11; var r99 = r7 - r10; var r100 = 0 * r19; var r101 = r66 % 6; r77 = r0 ^ 7; var r102 = 4 % r10; var r103 = r29 & r29; r22 = r44 * r15; r69 = 4 ^ a0; var r104 = r87 - r63; var r105 = r20 % r22; var r106 = 9 % r100; var r107 = r105 ^ 6; r81 = r50 * r75; r18 = r27 * r42; var r108 = 8 * r21; var r109 = r25 ^ 1; print(r58); var r110 = a2 ^ 2; var r111 = r74 / r70; r35 = r51 ^ r98; r100 = r41 | 9; a0 = a4 | r40; var r112 = 4 * r59; r85 = r20 % r62; var r113 = r35 ^ r109; var r114 = r51 % r40; var r115 = r22 - r94; var r116 = r108 / 2; r95 = r109 - r70; var r117 = r21 ^ 8; r113 = 0 - r41; r50 = r70 | r109; var r118 = 0 | r110; var r119 = r21 / r78; r40 = r80 - r32; var r120 = r30 ^ r74; var r121 = r89 * r49; r25 = r10 & r2; return a0; }), set: (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 3.0;\n    {\n      (Int32ArrayView[(-(i0)) >> 2]) = ((i0)*0xda478);\n    }\n    i0 = (0xfe4c3f7e);\n    i0 = (0xffffffff);\n    /*FFI*/ff(((((0xf92c5664)-(i0)) ^ (((+(~((0xf8809441)))) != (+acos((((0xe7e11838) ? (562949953421311.0) : (2147483649.0))))))-(0xec3cd3c3)))), (((((((0xcd7ee08))>>>((0xf45246e5))))+((abs((~((0xfe881f7e))))|0))+(i0))|0)), ((d1)), ((imul((0xffffffff), (0xffffffff))|0)), ((((1.888946593147858e+22)) * ((d2)))));\n    return +((+(1.0/0.0)));\n    return +((7.737125245533627e+25));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)) });");
/*fuzzSeed-451211*/count=381; tryItOut("\"use strict\"; g0 = this;");
/*fuzzSeed-451211*/count=382; tryItOut("/*oLoop*/for (perktu = 0; perktu < 67; (\u000c'fafafa'.replace(/a/g, String.prototype.toString)), ++perktu) { i1 = new Iterator(p2, true); } ");
/*fuzzSeed-451211*/count=383; tryItOut("\"use strict\"; f2(h1);");
/*fuzzSeed-451211*/count=384; tryItOut("v1 = new Number(Infinity);");
/*fuzzSeed-451211*/count=385; tryItOut("const w = ((Object.defineProperty(a, \"(e = 14)\", ({value: 1, writable: /*wrap3*/(function(){ \"use strict\"; var hqfeax =  /x/ ; (((function(x, y) { \"use strict\"; return x; })).bind)(); })})).__defineSetter__(\"x\", Map.prototype.delete))());Array.prototype.shift.apply(a1, [(4277)]);");
/*fuzzSeed-451211*/count=386; tryItOut("mathy1 = (function(x, y) { return ((Math.sinh((Math.cos((( ! (x >>> 0)) >>> 0)) >>> 0)) >>> 0) - ( + Math.acos(Math.fround(mathy0(Math.fround(-0), Math.sinh(2**53-2)))))); }); testMathyFunction(mathy1, [Math.PI, 1, -0x080000001, -1/0, 0.000000000000001, 0x080000000, 0/0, -0, -Number.MAX_VALUE, 42, 2**53, 0x0ffffffff, 1/0, 2**53-2, 0x080000001, -0x0ffffffff, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 2**53+2, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), -(2**53-2), -0x100000001, 1.7976931348623157e308, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000]); ");
/*fuzzSeed-451211*/count=387; tryItOut("v2 = this.o1[\"apply\"];");
/*fuzzSeed-451211*/count=388; tryItOut("testMathyFunction(mathy1, [-0x080000001, -0x0ffffffff, Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -0x100000000, 0x100000001, -0, 1, 0x080000000, -(2**53), 42, -0x100000001, -1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, 2**53, 0/0, -(2**53+2), 0x0ffffffff, 2**53+2, -Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, -0x080000000, 0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=389; tryItOut("\"use strict\"; a0.splice(NaN, x);");
/*fuzzSeed-451211*/count=390; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.min((((Math.atan2((( + Math.imul(( + Math.cbrt((y >>> 0))), ( + x))) >>> 0), Math.fround(( + Math.clz32(( + y))))) >>> 0) ? ((( + Math.hypot(( + x), ( + y))) && ( + Math.atanh(x))) >>> 0) : Math.exp(x)) * ((Math.imul(((( - (Math.log2(Math.fround(Math.min(x, y))) | 0)) | 0) >>> 0), (x >>> 0)) >>> 0) | 0)), ( ! Math.log1p(mathy2((( + (x >>> 0)) >>> 0), ( + ( + ( - (( + y) | 0))))))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -0x080000000, -Number.MAX_VALUE, -0, -1/0, 0, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, -(2**53), -0x07fffffff, 0x080000000, 0.000000000000001, 2**53+2, 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, 2**53-2, -0x100000000, Math.PI, 0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 42, -(2**53-2), 0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-451211*/count=391; tryItOut("mathy1 = (function(x, y) { return ( + Math.log1p(( + Math.asin(( + mathy0(Math.fround(( + Math.fround(( + Math.imul(x, ( + (y ? y : x))))))), Math.sin((Math.imul((y | 0), x) | 0)))))))); }); testMathyFunction(mathy1, [0.000000000000001, -0, -0x100000001, Math.PI, 42, 1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, 2**53+2, -0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, 0x07fffffff, -0x07fffffff, -(2**53-2), 0/0, 0x080000000, 0x100000001, 1, -Number.MAX_VALUE, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-451211*/count=392; tryItOut("\"use strict\"; Array.prototype.reverse.apply(this.o2.a2, []);");
/*fuzzSeed-451211*/count=393; tryItOut("\"use strict\"; let (w) { print((void options('strict_mode'))); }");
/*fuzzSeed-451211*/count=394; tryItOut("testMathyFunction(mathy4, [-(2**53+2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -(2**53), -0x080000001, -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -0x100000000, -0x100000001, 1/0, -0x080000000, Number.MIN_VALUE, -1/0, -(2**53-2), -0x0ffffffff, 2**53+2, 0/0, 0x100000000, -0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, 2**53, 0x100000001, 0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 1, Number.MAX_VALUE]); ");
/*fuzzSeed-451211*/count=395; tryItOut("\"use asm\"; /*hhh*/function oltgfr(z, e, e, {x: []}, x,  , x, x, x, w, y, x, z, NaN, x, x, NaN, x, x, e, x, NaN, c = -12, d, x, x, a, x, eval, b, window, a, b, b, x, \u3056, eval, eval = \"\\uA9D2\", w, x, y, window, x, z, \u3056, c, b, x, w = this){/*RXUB*/var r = /(?=\\2*?)/ym; var s = \"\"; print(s.search(r)); print(r.lastIndex); }/*iii*/{b2.valueOf = Number.prototype.valueOf.bind(g1);v1 = (o2.g0.t0 instanceof this.h0); }");
/*fuzzSeed-451211*/count=396; tryItOut("\"use strict\";  \"\" ;");
/*fuzzSeed-451211*/count=397; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.fround(Math.min(Math.fround((Math.pow(-Number.MAX_SAFE_INTEGER, (((y >>> 0) ? (y >>> 0) : ((Math.imul(y, (Math.asinh(-Number.MAX_VALUE) | 0)) | 0) >>> 0)) >>> 0)) | Math.imul(Math.abs(y), 2**53-2))), Math.fround(Math.fround(mathy0(Math.fround(((Number.MAX_SAFE_INTEGER / ((mathy0(((((0/0 | 0) >>> (y | 0)) >>> 0) >>> 0), ((Math.log((y | 0)) | 0) >>> 0)) >>> 0) | 0)) | 0)), Math.tan((y + (Math.abs((-0x080000000 | 0)) | 0)))))))), ( + Math.max((( + Math.min((((( - (y >>> 0)) >>> 0) ? ( + 0) : Math.atanh((( + mathy0(x, x)) ? Number.MIN_SAFE_INTEGER : ((0.000000000000001 && (x >>> 0)) | 0)))) | 0), (Math.atan2((( - (0x100000001 | 0)) | 0), (((x ? Math.fround(x) : y) !== (mathy0((0x100000000 >>> 0), 0x07fffffff) | 0)) | 0)) | 0))) | 0), (( ~ Math.fround(((((Math.expm1(Math.fround(Math.asin(-(2**53)))) >>> 0) | 0) >>> (( ~ x) | 0)) | 0))) | 0)))); }); ");
/*fuzzSeed-451211*/count=398; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.log1p(Math.fround(( + (( + ( + Math.fround((((y | 0) === (y <= ((Math.fround((Number.MIN_VALUE | 0)) | 0) - x))) | 0)))) || (Math.tan(( + ( ! ( + (mathy2(-0x100000001, y) * 0/0))))) << Math.max(( + Math.abs(( + ( - y)))), (mathy2(Math.fround(y), (((x * Math.fround((Math.max((x >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0))) >>> 0) | 0)) | 0))))))); }); testMathyFunction(mathy4, [0, 2**53+2, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, 2**53-2, -(2**53), -0x100000001, 0x080000000, -0x080000001, Number.MAX_VALUE, 0x080000001, -0, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, 42, -1/0, 0/0, -Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -(2**53-2), 1, 0x07fffffff, 0x0ffffffff, -0x100000000, -0x080000000, Math.PI, 2**53]); ");
/*fuzzSeed-451211*/count=399; tryItOut("const vxowig, z, window, window, jehrhl, c, window, x, x, w;Object.defineProperty(this, \"o2\", { configurable: (x % 6 == 1), enumerable: true,  get: function() {  return {}; } });");
/*fuzzSeed-451211*/count=400; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + (( + ( ! ( + ( + Math.asinh(Math.imul(y, mathy0(Math.PI, (( + -0) << ( + x))))))))) !== (Math.imul((Math.fround(Math.sign(Math.fround(Math.imul(( + mathy0(( + ( ~ ( + ((y | 0) ? (Number.MAX_SAFE_INTEGER | 0) : (Number.MIN_SAFE_INTEGER | 0))))), (y | 0))), y)))) >>> 0), (mathy0(((mathy0(y, (y | 0)) | 0) << ( ~ (x ? (((x >>> 0) ? 2**53+2 : (x >>> 0)) >>> 0) : ((y ? (x | 0) : (y | 0)) | 0)))), ( + Math.atan2(( + ( - ( ! Math.fround((Math.fround(x) !== Math.fround(-(2**53+2))))))), ( + (((mathy0((Math.acosh((-0x080000000 | 0)) | 0), Math.pow(-Number.MAX_VALUE, 1/0)) >>> 0) && (Math.PI >>> 0)) >>> 0))))) | 0)) | 0))); }); ");
/*fuzzSeed-451211*/count=401; tryItOut("mathy3 = (function(x, y) { return ( ! (( ~ ( + ( - Math.fround(Math.sin(Number.MAX_VALUE))))) >>> 0)); }); testMathyFunction(mathy3, [0, '/0/', false, /0/, ({valueOf:function(){return 0;}}), -0, [0], (function(){return 0;}), 0.1, '0', (new Number(-0)), '\\0', ({valueOf:function(){return '0';}}), undefined, (new Boolean(false)), objectEmulatingUndefined(), 1, NaN, null, (new String('')), (new Number(0)), (new Boolean(true)), true, ({toString:function(){return '0';}}), [], '']); ");
/*fuzzSeed-451211*/count=402; tryItOut("p2.__proto__ = s1;");
/*fuzzSeed-451211*/count=403; tryItOut("t0[x] = (\nx = [,,z1]) <<= (uneval((this.eval(\"/* no regression tests found */\").__proto__++)));");
/*fuzzSeed-451211*/count=404; tryItOut("z = x;let(e = new WeakSet(), x, x) { a0.pop();}");
/*fuzzSeed-451211*/count=405; tryItOut("\"use strict\"; m1.get(g1);");
/*fuzzSeed-451211*/count=406; tryItOut("let b = x *= eval, x, wcpfnd, a = \n/*MARR*/[new String(''), x, (void 0), (void 0), new String(''), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), (void 0), new String(''), (void 0), x, new String(''), new String(''), (void 0), new Boolean(true), (void 0), x, new Number(1), x, new String(''), x, x, new String(''), (void 0), (void 0), new String(''), new String(''), new Boolean(true), new Number(1), x, new String(''), new Boolean(true), x, new String(''), new String(''), new Boolean(true), new Boolean(true), (void 0), x, new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), new String(''), new Number(1), new String(''), new String(''), (void 0), new Boolean(true), new Number(1), (void 0), x, (void 0), x, x, new Boolean(true)].filter(new Function, [,]), b, w = (new Uint8ClampedArray((c & x))), x, {x: {b}} = [] = /(?!(?!.*)+?)(?=(?:^){4,})+[^]+?/gy.unwatch(\"1\") = (makeFinalizeObserver('tenured')), x = (this.__defineSetter__(\"NaN\", Object.defineProperties)), c;let (d) { print(x); }");
/*fuzzSeed-451211*/count=407; tryItOut("\"use strict\"; e1 = new Set(o2);");
/*fuzzSeed-451211*/count=408; tryItOut("for (var p in o2.p0) { try { /*MXX3*/g0.String.prototype.toString = g0.String.prototype.toString; } catch(e0) { } try { f2.__iterator__ = f2; } catch(e1) { } try { print(v0); } catch(e2) { } h2.enumerate = (function() { try { g1.m2.get(p1); } catch(e0) { } try { t1.set(t0, 16); } catch(e1) { } Array.prototype.reverse.apply(a2, []); return a2; }); }");
/*fuzzSeed-451211*/count=409; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a0, [(function mcc_() { var lfrjck = 0; return function() { ++lfrjck; f2(/*ICCD*/lfrjck % 10 == 8);};})(), e1, e2, v2]);");
/*fuzzSeed-451211*/count=410; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.imul((mathy1(((-0 | 0) ? Math.max((Math.log2((mathy1((x >>> 0), (x >>> 0)) >>> 0)) | 0), (2**53-2 >>> 0)) : x), Math.abs(mathy1(x, ((( - ((y < y) >>> 0)) >>> 0) && Math.fround(Number.MAX_VALUE))))) >>> 0), (((Math.min((Math.fround((((y & ( + x)) >>> 0) & Math.fround(0))) >>> 0), ( + Math.atan2(Math.max(y, y), Math.atan2(x, x)))) >>> 0) == x) != (Math.fround(y) >>> 0))); }); testMathyFunction(mathy2, [0x100000001, 2**53, -(2**53-2), -0, 1, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), 1/0, 0/0, -0x100000000, 0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -1/0, 0x080000001, 0x100000000, -0x080000001, -(2**53+2), 0x0ffffffff, Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -0x0ffffffff, 42]); ");
/*fuzzSeed-451211*/count=411; tryItOut("v0 = -0;");
/*fuzzSeed-451211*/count=412; tryItOut("\"use asm\"; yhmtuq, x, c = ((function sum_slicing(eprydt) { ; return eprydt.length == 0 ? 0 : eprydt[0] + sum_slicing(eprydt.slice(1)); })(/*MARR*/[true, x, true, x, x, true, true, true, true, true, true, true, x, x, true, x, true, true, x, x, true, x, true, x, true, x, true, x, x, x, true, true, true, true, x, x, true, x, true, true, true, x, true, x, true, x, true, true, true, true, x, true, true])), y = (({NaN: 13}));/* no regression tests found */");
/*fuzzSeed-451211*/count=413; tryItOut("s1 = new String(s1);");
/*fuzzSeed-451211*/count=414; tryItOut("\"use asm\"; { void 0; void gc(this); }");
/*fuzzSeed-451211*/count=415; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ( - Math.max(( ! Math.abs((Math.max((x | 0), (y | 0)) | 0))), ((( + Math.pow(Math.fround((Math.atan2(y, x) | 0)), Math.imul(y, -0x080000001))) / Math.fround((Math.fround((mathy0(x, Math.clz32(mathy0(0x080000001, y))) | 0)) + (Math.imul(((( ! (x >>> 0)) >>> 0) >>> 0), (( - 2**53) >>> 0)) >>> 0)))) >>> 0)))); }); testMathyFunction(mathy5, [-0x0ffffffff, Number.MAX_VALUE, 0/0, 1, 2**53-2, -(2**53), 2**53+2, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, 1/0, 0x07fffffff, -1/0, -0x080000001, -0x080000000, -0x100000001, Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0, 42, 2**53, 0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, -0x07fffffff]); ");
/*fuzzSeed-451211*/count=416; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.imul((Math.fround(((( ~ x) | 0) > Math.fround(( - (2**53+2 >>> 0))))) < Math.atan2(Math.fround(( + Math.fround(Number.MAX_SAFE_INTEGER))), ( - y))), Math.pow(Math.cos(Math.acos((x >>> 0))), (mathy0(Math.fround((Math.log1p((y >>> 0)) >>> 0)), Math.fround((Math.max((((y >> (0x100000001 | 0)) >>> 0) | 0), x) | 0))) ? x : (Math.fround(mathy0(Math.fround(y), Math.fround(x))) ? (y | 0) : (Math.atan2(( + x), x) | 0))))); }); testMathyFunction(mathy1, [-0x100000001, 0x0ffffffff, -1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, -0x100000000, 0/0, -0x080000000, -(2**53+2), -0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, 0x100000001, -(2**53-2), Math.PI, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53, 0, -0x0ffffffff, 2**53+2, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 1/0, 42]); ");
/*fuzzSeed-451211*/count=417; tryItOut("this.v0.valueOf = (function() { try { o2.t0[11] = b2; } catch(e0) { } a1 + ''; return o2.t0; });");
/*fuzzSeed-451211*/count=418; tryItOut("\"use strict\"; {/*ADP-3*/Object.defineProperty(a2, 9, { configurable: (x % 32 != 20), enumerable: false, writable: true, value: s0 });s2 + m1; }");
/*fuzzSeed-451211*/count=419; tryItOut("mathy1 = (function(x, y) { return Math.tan((( + (( + Math.atan((( ! y) >>> 0))) - ( + (Math.acosh(( - Math.acosh(x))) | 0)))) | 0)); }); testMathyFunction(mathy1, [Math.PI, 0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, Number.MAX_VALUE, -0, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -0x0ffffffff, 2**53, 0/0, -Number.MAX_VALUE, -(2**53+2), 42, 1/0, -0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1, 2**53-2, 0x080000000, -(2**53-2), 0x100000000, -1/0, -0x100000001, 0, -(2**53), 0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=420; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=421; tryItOut("let m2 = new Map;");
/*fuzzSeed-451211*/count=422; tryItOut("x = x, NaN = ((x)((({/*toXFun*/toSource: function() { return this; } }) ? eval|=[[]]\u000c : (makeFinalizeObserver('tenured'))))) =  x: /*\n*/new TypeError()x, x = [] = {}, y, hhyiom, \u3056;this.v0 = a1.length;");
/*fuzzSeed-451211*/count=423; tryItOut("a2.toString = (function(j) { o1.f0(j); });");
/*fuzzSeed-451211*/count=424; tryItOut("\"use asm\"; testMathyFunction(mathy0, [-0x07fffffff, 2**53-2, -0x080000000, 0, 0.000000000000001, Math.PI, -(2**53), 0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, 1/0, 0x100000000, 0x0ffffffff, -0x100000001, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, -0x0ffffffff, 0x080000000, 1.7976931348623157e308, -0x080000001, Number.MAX_VALUE, -0, -1/0, 42, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=425; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.hypot(( + Math.fround(mathy0(Math.atanh((Math.log2((y | 0)) | 0)), Math.fround(( - x))))), ( + (Math.imul(( + ( - ( + mathy2(( + (Math.trunc(( + y)) | 0)), (x >>> 0))))), ( + Math.abs(( + ( + ( - ( + (( + y) >>> 0)))))))) | 0)))); }); ");
/*fuzzSeed-451211*/count=426; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(( + Math.fround(Math.expm1(Math.fround(( + Math.min((x >>> 0), Math.fround(Math.atan2(x, ( ~ Math.min(x, 1/0))))))))))) >> Math.fround(((Math.log10(( + ( - ( + x)))) >>> 0) & (( ~ x) >>> 0)))); }); testMathyFunction(mathy5, [-0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -0x080000000, 0x080000000, 2**53, -0x100000000, -(2**53), 1/0, -0x07fffffff, 0x07fffffff, -(2**53-2), -0x0ffffffff, Number.MIN_VALUE, 42, 0, Number.MIN_SAFE_INTEGER, 2**53+2, 1, 1.7976931348623157e308, -1/0, 0.000000000000001, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53+2), 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-451211*/count=427; tryItOut("const e = /F{2,}|(?:(?:(?=[^]))|(?:[^]){4,}\\b?)|\\1/.__defineGetter__(\"window\", /*wrap1*/(function(){ \"use strict\"; ;return /*wrap2*/(function(){ \"use strict\"; var wjxhla =  /x/g ; var cfpvrp = function(q) { return q; }; return cfpvrp;})()})()), a, w, \u3056 =  /x/g , mwtlqd, mkwbuu, tpliiq, pynpai;print(x);");
/*fuzzSeed-451211*/count=428; tryItOut("testMathyFunction(mathy3, [0x07fffffff, 1/0, 2**53+2, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 0/0, -0x07fffffff, -(2**53+2), -(2**53-2), -1/0, 2**53, 0x080000000, -0x080000001, 0x0ffffffff, 1, 1.7976931348623157e308, 0x080000001, -Number.MIN_VALUE, 0x100000000, -0x100000001, -0x080000000, -(2**53), 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -0, -Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, 0x100000001, Number.MAX_VALUE]); ");
/*fuzzSeed-451211*/count=429; tryItOut("\"use strict\"; /*bLoop*/for (var mstrnu = 0; mstrnu < 117; ++mstrnu) { if (mstrnu % 3 == 0) { /* no regression tests found */ } else { b0 + ''; }  } ");
/*fuzzSeed-451211*/count=430; tryItOut("\"use strict\"; /*bLoop*/for (jduyze = 0; jduyze < 95; ++jduyze) { if (jduyze % 47 == 41) { (eval); } else { a1.push(g1, g1); }  } ");
/*fuzzSeed-451211*/count=431; tryItOut("/*MXX1*/o1 = o2.g2.RegExp.$';");
/*fuzzSeed-451211*/count=432; tryItOut("\"use strict\"; a1 = [];");
/*fuzzSeed-451211*/count=433; tryItOut("a2.unshift(f2, g0.g0);");
/*fuzzSeed-451211*/count=434; tryItOut("this.v2 = evalcx(\"9\", g0);");
/*fuzzSeed-451211*/count=435; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return Math.fround(( ~ Math.fround(Math.pow(( + mathy0(( + ( + Math.hypot(( + x), ( + ( + x))))), x)), ( + Math.max(( + Math.pow(((((Math.exp((x >>> 0)) | 0) - (x | 0)) | 0) | 0), Math.sin(Math.fround((((x >>> 0) ? (x >>> 0) : (Math.sqrt((x >>> 0)) >>> 0)) >>> 0))))), ( + ( + (Math.atanh(x) | 0))))))))); }); testMathyFunction(mathy4, [-(2**53+2), 0x0ffffffff, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, 2**53-2, 0, -0x080000000, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, -(2**53-2), 2**53, 0/0, -1/0, -Number.MAX_VALUE, 0x07fffffff, 1/0, 2**53+2, -0x080000001, -Number.MIN_VALUE, -0, -0x100000001, 0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, 1, 0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=436; tryItOut("/*hhh*/function hyvtrs(window, ...w){for (var p in g2) { try { s0 += 'x'; } catch(e0) { } try { t2.__proto__ = s0; } catch(e1) { } g1 = this; }}/*iii*/v0 = Infinity;");
/*fuzzSeed-451211*/count=437; tryItOut("throw StopIteration;");
/*fuzzSeed-451211*/count=438; tryItOut("m0.has(m0);");
/*fuzzSeed-451211*/count=439; tryItOut("print(uneval(h1));");
/*fuzzSeed-451211*/count=440; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((((Math.fround(Math.tanh((Number.MAX_VALUE === ( ! x)))) ^ Math.acosh(x)) >>> 0) + (( ! (y >>> 0)) >>> 0)) >>> 0) > (mathy3(( ~ Math.exp(Math.hypot((((Number.MAX_VALUE | 0) , (( ~ (x >>> 0)) >>> 0)) >>> 0), y))), Math.hypot(((( ! (0x080000000 | 0)) !== x) & Math.atan2(( + ( + x)), Math.fround(Math.max(Math.fround(1/0), Math.fround(0x080000000))))), ( - ( + ( + Math.min(0x080000000, (y | 0))))))) >>> 0)); }); testMathyFunction(mathy4, [-0x080000001, 2**53-2, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -0x080000000, 0x07fffffff, Math.PI, 0x100000000, 0x100000001, 0x080000001, -Number.MIN_VALUE, 0/0, -(2**53), Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 0x080000000, 1, 42, 0x0ffffffff, 0, -0x07fffffff, -(2**53-2), 2**53+2, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, 2**53, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-451211*/count=441; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-451211*/count=442; tryItOut("var x;f2 = (function(j) { if (j) { try { Array.prototype.sort.call(a0, f2, e1); } catch(e0) { } v1 = evalcx(\"m2.set(t1, e0);\", g1); } else { try { o1.g1.v0 = evaluate(\"function f1(f2) /(?!(?!(?![^]))|^|\\\\2)|(?!(\\\\B)*){0,}(?!(?:[^]$))|(\\\\w)|(?:[^])??{3,}/gyi\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: true })); } catch(e0) { } e0.has(o1); } });");
/*fuzzSeed-451211*/count=443; tryItOut("this.h2 = ({getOwnPropertyDescriptor: function(name) { f2 = m0.get(this.g2);; var desc = Object.getOwnPropertyDescriptor(i0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { a2.forEach(Function.bind(v2), p1, t1, h0, ((void shapeOf((this.__defineGetter__(\"x\", null))))));; var desc = Object.getPropertyDescriptor(i0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { x = o0;; Object.defineProperty(i0, name, desc); }, getOwnPropertyNames: function() { s0 += s1;; return Object.getOwnPropertyNames(i0); }, delete: function(name) { Array.prototype.push.call(a1, o0, window, h2, g0);; return delete i0[name]; }, fix: function() { f0 + m1;; if (Object.isFrozen(i0)) { return Object.getOwnProperties(i0); } }, has: function(name) { e2.delete(s2);; return name in i0; }, hasOwn: function(name) { v1 = a0.length;; return Object.prototype.hasOwnProperty.call(i0, name); }, get: function(receiver, name) { v2 = Object.prototype.isPrototypeOf.call(a2, g2.o1.s2);; return i0[name]; }, set: function(receiver, name, val) { a1 + '';; i0[name] = val; return true; }, iterate: function() { throw g2; return (function() { for (var name in i0) { yield name; } })(); }, enumerate: function() { m2.set(a1, t0);; var result = []; for (var name in i0) { result.push(name); }; return result; }, keys: function() { return i2; return Object.keys(i0); } });");
/*fuzzSeed-451211*/count=444; tryItOut("t2.set(a2, 5);");
/*fuzzSeed-451211*/count=445; tryItOut("\"use strict\"; M:switch(new RegExp(\"^\\\\B(?:.|[^])*?|\\\\1\\u0080|[^\\\\S\\\\w\\\\x7d-\\u00b3]*?|(?=\\\\B)|[^]+|^|(.)\", \"gim\")) { default: case 7:  }");
/*fuzzSeed-451211*/count=446; tryItOut("selectforgc(o1);");
/*fuzzSeed-451211*/count=447; tryItOut("mathy0 = (function(x, y) { return Math.pow(( + (((Math.atanh(( + Math.log(((Math.atan2((( + y) | 0), (x | 0)) | 0) >>> 0)))) | 0) <= Math.fround(Math.sin(Math.fround((Math.acos(((Math.atan(((( ~ (y >>> 0)) >>> 0) | 0)) | 0) >>> 0)) >>> 0))))) | 0)), ( + ( ! (( + ( ~ ( + (Math.max((Number.MAX_SAFE_INTEGER >>> 0), (Math.fround(( + ( + x))) >>> 0)) >>> 0)))) / (Math.min((Math.PI >>> 0), ((( ! -1/0) | 0) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-451211*/count=448; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-451211*/count=449; tryItOut("Array.prototype.pop.apply(a2, [a2, y in a]);");
/*fuzzSeed-451211*/count=450; tryItOut("mathy5 = (function(x, y) { return Math.max((( + ( + Math.trunc(( + Math.acosh(-Number.MAX_SAFE_INTEGER))))) | ( + Math.cbrt(( + Math.tanh(Math.ceil(y)))))), ( + (( + mathy1(Math.ceil(y), Math.fround(( + Math.fround((Math.min((x >>> 0), (Math.pow(y, (x | 0)) | 0)) ? (Math.round(y) | 0) : ( ~ y))))))) >>> ( + Math.fround(Math.hypot(( + ((mathy0(( + y), ( + x)) >>> ( + (mathy1(y, (x | 0)) | 0))) >>> 0)), ( + 1/0))))))); }); testMathyFunction(mathy5, [-(2**53+2), -0x100000000, -0x080000000, -(2**53), 42, 2**53, 0x080000000, 0x100000000, 1/0, -0, -0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, -(2**53-2), 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 1, -0x080000001, 0/0, 0x080000001, Number.MAX_VALUE, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-451211*/count=451; tryItOut("m1.has(t2);");
/*fuzzSeed-451211*/count=452; tryItOut("L:do {print(\"\\uC8E7\");function x(NaN, ...window) {  /x/ ; } g2 = t0[19]; } while((x) && 0);");
/*fuzzSeed-451211*/count=453; tryItOut("mathy0 = (function(x, y) { return Math.log1p((Math.sinh((Math.min((Math.atan2(x, y) | 0), ( + Math.log10(Math.fround(( + (y <= x)))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-0, -Number.MAX_VALUE, 0, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000001, 0x080000001, -0x0ffffffff, 0x100000000, 1, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -0x07fffffff, -(2**53), 2**53+2, -0x080000000, -1/0, 0x0ffffffff, -(2**53+2), -(2**53-2), 0x07fffffff, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000001, 42, 2**53]); ");
/*fuzzSeed-451211*/count=454; tryItOut("m0 = new Map(m0);");
/*fuzzSeed-451211*/count=455; tryItOut("v0 = evalcx(\"throw StopIteration;var etwsuy = new SharedArrayBuffer(6); var etwsuy_0 = new Int16Array(etwsuy); print(etwsuy_0[0]); etwsuy_0[0] = 24; continue M;\", g2);");
/*fuzzSeed-451211*/count=456; tryItOut("\"use strict\"; ");
/*fuzzSeed-451211*/count=457; tryItOut("Array.prototype.sort.call(g0.a0);");
/*fuzzSeed-451211*/count=458; tryItOut("\"use strict\"; var c = this;m2 = new Map(b2);");
/*fuzzSeed-451211*/count=459; tryItOut("\"use strict\"; m1 = new Map;");
/*fuzzSeed-451211*/count=460; tryItOut("/*iii*/v1 = new Number(-Infinity);/*hhh*/function itatgz(x = x|=({}), x//h\n){this.v0 = g0.eval(\"p0.toString = (function(j) { f2(j); });\");}");
/*fuzzSeed-451211*/count=461; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Int16ArrayView[(((((0xecf68153)+(0xfa1e7666))>>>(((d1) > (+(0.0/0.0))))))) >> 1]) = (-(new (this)(Math.atan2(this,  /x/g ))));\n;    return ((((imul(((((4277)) | (((0x31b93c7b)))) >= ((((0x283028fc) >= (0x1b52d19e))-((0x3729c02d) < (0xf3ebce24)))|0)), (/*RXUE*//[^]/yim.exec(\"\\n\")))|0) == (((i0)) ^ ((i0)-((0xf782424)))))))|0;\n  }\n  return f; })(this, {ff: new RegExp(\"(?:(?=(?:(?!\\\\1))?))\", \"gm\").prototype}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[delete NaN.x, (-1/0), new String('q'), new String('q'), (-1/0), new String('q'), delete NaN.x, (-1/0), delete NaN.x, new String('q'), new String('q'), new String('q'), delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, delete NaN.x, (-1/0), new String('q'), (-1/0), (-1/0), delete NaN.x, (-1/0), delete NaN.x, delete NaN.x, (-1/0), new String('q')]); ");
/*fuzzSeed-451211*/count=462; tryItOut("v1 = t1.byteOffset;");
/*fuzzSeed-451211*/count=463; tryItOut("\"use strict\"; Array.prototype.pop.apply(o0.a2, [b2, m0, t0]);");
/*fuzzSeed-451211*/count=464; tryItOut("\"use strict\"; o1.s2 = x;");
/*fuzzSeed-451211*/count=465; tryItOut("\"use strict\"; o2.v1 = (o0 instanceof v2);");
/*fuzzSeed-451211*/count=466; tryItOut("\"use strict\"; ");
/*fuzzSeed-451211*/count=467; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?=\\\\cW{3}|\\\\b)?)+?\", \"gym\"); var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=468; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((((Math.imul(((Math.clz32((x & (Math.pow((x | 0), (y | 0)) | 0))) >>> 0) >= (Math.max((Math.sign(-(2**53-2)) >>> 0), (0/0 >>> 0)) >>> 0)), Math.hypot(Math.log2(y), y)) >>> 0) | 0) < Math.fround(Math.fround(Math.min(Math.fround(Math.tanh(( - y))), Math.fround((( ! (y >>> 0)) >>> 0)))))) >>> 0); }); ");
/*fuzzSeed-451211*/count=469; tryItOut("print(x);");
/*fuzzSeed-451211*/count=470; tryItOut("/*MXX1*/o1 = g2.TypeError;");
/*fuzzSeed-451211*/count=471; tryItOut("\"use strict\"; neuter(this.g0.b1, \"change-data\");");
/*fuzzSeed-451211*/count=472; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[Number.MAX_VALUE, Number.MAX_VALUE, null, new String(''), null, new String(''), length, new String(''), null, let (z = NaN) x, let (z = NaN) x, length, Number.MAX_VALUE, Number.MAX_VALUE, let (z = NaN) x, Number.MAX_VALUE, Number.MAX_VALUE, new String(''), Number.MAX_VALUE, Number.MAX_VALUE, let (z = NaN) x, length, Number.MAX_VALUE, let (z = NaN) x, length, new String(''), let (z = NaN) x, let (z = NaN) x, null, let (z = NaN) x, new String(''), new String(''), new String(''), new String(''), Number.MAX_VALUE, let (z = NaN) x, new String(''), let (z = NaN) x, Number.MAX_VALUE, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), length, Number.MAX_VALUE, null, length, Number.MAX_VALUE, Number.MAX_VALUE, length, null, null, let (z = NaN) x, Number.MAX_VALUE, null, let (z = NaN) x, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), null, new String(''), length, length, let (z = NaN) x, new String(''), new String(''), let (z = NaN) x, null, new String(''), let (z = NaN) x, let (z = NaN) x, new String(''), Number.MAX_VALUE, null]) { print((x) =  \"\" ); }");
/*fuzzSeed-451211*/count=473; tryItOut("g0.g2.v0 = Array.prototype.reduce, reduceRight.call(a0, (function() { a1 = arguments.callee.arguments; return e2; }), this.g0.g1, f1);");
/*fuzzSeed-451211*/count=474; tryItOut("\"use strict\"; o0.v1 = (this.f1 instanceof o0);");
/*fuzzSeed-451211*/count=475; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( + Math.min(((( + ( - -Number.MAX_VALUE)) < (-Number.MIN_SAFE_INTEGER >>> 0)) , ( + y)), (Math.tan(Math.max((( - y) >>> 0), ( ! x))) | 0))) * Math.fround(( - (((( - x) | 0) ? ( + y) : (Math.sign(y) | 0)) | 0)))) + ( + Math.ceil(( + Math.abs((Math.atan2(( + Math.imul(x, ( ~ ( + -0x100000000)))), ((Math.imul((x | 0), (y | 0)) | 0) > x)) >>> 0)))))); }); testMathyFunction(mathy3, [-1/0, -Number.MAX_VALUE, 0x100000001, 1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -0x100000000, -(2**53), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, -0x080000000, -0, 0x080000000, -0x080000001, 2**53, 2**53+2, -0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, 1, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, -(2**53+2), 0x100000000, 0/0, -0x07fffffff, 0, 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=476; tryItOut("mathy0 = (function(x, y) { return (Math.sign(((Math.fround(Math.sign(Math.fround(Math.PI))) >> x) | 0)) , Math.log((Math.log1p(y) >>> 0))); }); testMathyFunction(mathy0, [0x100000000, 0, 0/0, 1, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 2**53+2, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, 42, 0x080000000, -0x07fffffff, -0x080000001, -0, Number.MIN_SAFE_INTEGER, -1/0, 2**53-2, -Number.MIN_VALUE, -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, Number.MAX_VALUE, Math.PI, -0x080000000, 1.7976931348623157e308, -0x100000001, Number.MIN_VALUE, 2**53, 0x100000001, -(2**53)]); ");
/*fuzzSeed-451211*/count=477; tryItOut("\"use strict\"; e0.valueOf = f0;");
/*fuzzSeed-451211*/count=478; tryItOut("\"use strict\"; for (var p in p0) { /*MXX3*/g2.Math.log1p = g2.Math.log1p; }");
/*fuzzSeed-451211*/count=479; tryItOut("v1 = evalcx(\"v0 = (i2 instanceof o2.t1);/*infloop*/for(let d = /((?:(?=^){34359738369}|[^\\\\M]|..{2,})|(?!.)*[^]\\\\B[^]?*)/g >> ((p={}, (p.z = (x = b))())); y.unwatch(16).__defineSetter__(\\\"x\\\", neuter); /*FARR*/[].map(Object.getPrototypeOf)) for (var v of b1) { try { h1.delete = g0.f2; } catch(e0) { } try { v0 = x; } catch(e1) { } a0.unshift(m1); }\", g2);");
/*fuzzSeed-451211*/count=480; tryItOut("if((x % 3 == 0)) {v2 = Object.prototype.isPrototypeOf.call(o0.o0.g0, b0);this.s0 += 'x'; } else {s1 + o0.e2; }");
/*fuzzSeed-451211*/count=481; tryItOut("mathy3 = (function(x, y) { return Math.max(Math.imul((((Math.sign(y) >>> 0) > ((y ? ((-(2**53) | ( + 1)) | 0) : mathy1(x, (y >>> y))) >>> 0)) >>> 0), (Number.MIN_SAFE_INTEGER || x)), (Math.atan2((y | 0), ( ~ Math.sinh(((x | 0) ? Math.fround(Math.log10(Math.fround(0x07fffffff))) : Math.tan(x))))) < Math.hypot(Math.fround(y), (( + ( + ( + 0x07fffffff))) >>> 0)))); }); ");
/*fuzzSeed-451211*/count=482; tryItOut("Array.prototype.push.apply(a1, [v2, v2]);");
/*fuzzSeed-451211*/count=483; tryItOut("\"use strict\"; delete h0.get;");
/*fuzzSeed-451211*/count=484; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1, '\\0', '/0/', null, -0, undefined, (new Boolean(true)), objectEmulatingUndefined(), ({toString:function(){return '0';}}), [0], 0.1, ({valueOf:function(){return '0';}}), (new Number(-0)), [], '', false, (function(){return 0;}), (new Number(0)), 0, '0', (new Boolean(false)), true, /0/, ({valueOf:function(){return 0;}}), NaN, (new String(''))]); ");
/*fuzzSeed-451211*/count=485; tryItOut("/*iii*/print(fdezmh);/*hhh*/function fdezmh(z, x, setter, \"\\u01C3\", x, x = \"\\u7D0E\", NaN, b = null, eval = window, z, e, window, y = null, d, c, NaN, d, eval, x, eval, d, NaN, x, \u3056, z, e, x, x, x, \u3056, c, x, x, setter, b, x = -15, NaN, d = x, \u3056, a, x, eval, z, e, e, x, y, x, \u3056, \u3056, c, d, z, x, x, NaN, x, a, d, this.b, x, x = this, NaN, window, e = ;, b, y = -14, NaN, x, window = NaN, x, c = this, c =  /x/ , e, e = a, x, z, z, x = true, w =  /x/g , b, x =  '' , \u3056, x, b = window, x, x, e, window, ...x){t1.set(t0, 18);}");
/*fuzzSeed-451211*/count=486; tryItOut("/*MXX1*/o0 = g2.Uint8Array.length;");
/*fuzzSeed-451211*/count=487; tryItOut("for([y, a] = (this.__defineSetter__(\"x\", Date.UTC)) in (4277)) i1 + b0;");
/*fuzzSeed-451211*/count=488; tryItOut("Array.prototype.push.apply(a0, [p1, /*RXUE*//^/gyim.exec(\"\\n\\n\\u30ef\") >>> ((x) = (void options('strict'))) ? x : x]);");
/*fuzzSeed-451211*/count=489; tryItOut("\"use asm\"; a0.push(g0);");
/*fuzzSeed-451211*/count=490; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.sin(((Math.sin(Math.atan2(-0x100000000, (mathy0(x, ((x ^ y) | 0)) | 0))) | 0) , (y & Math.sign(( + y))))) ? Math.fround((((( + Math.round(Math.sign(Number.MIN_VALUE))) && ( - y)) >>> 0) >= (( + mathy1((Math.log1p(0x0ffffffff) >>> 0), (x >>> 0))) >>> 0))) : (( - Math.fround(Math.hypot((((x >>> 0) ^ (-(2**53) >>> 0)) >>> 0), (( - Math.fround(-(2**53-2))) | 0)))) <= (mathy1(( ! 0x080000001), Math.atan2(0x0ffffffff, (y / x))) ** y))); }); testMathyFunction(mathy4, [0.1, -0, NaN, 1, (new Boolean(true)), (function(){return 0;}), (new String('')), [], ({valueOf:function(){return 0;}}), [0], '\\0', /0/, '/0/', undefined, 0, null, false, true, (new Number(-0)), ({valueOf:function(){return '0';}}), '0', (new Number(0)), ({toString:function(){return '0';}}), '', objectEmulatingUndefined(), (new Boolean(false))]); ");
/*fuzzSeed-451211*/count=491; tryItOut("m0.has((void version(180)));");
/*fuzzSeed-451211*/count=492; tryItOut("if(true) print(x);");
/*fuzzSeed-451211*/count=493; tryItOut("g1.t0[v0] = /*UUV2*/(b.keys = b.__lookupSetter__);");
/*fuzzSeed-451211*/count=494; tryItOut("\"use strict\"; Object.defineProperty(this, \"v2\", { configurable: false, enumerable: (x % 30 != 19),  get: function() {  return g2.g0.eval(\"mathy1 = (function(x, y) { \\\"use strict\\\"; return (Math.hypot(Math.atan2(( - Math.imul((Math.fround(Math.log1p(x)) >>> 0), y)), (Math.sqrt(((mathy0((-0x0ffffffff | 0), ((Math.imul(y, (Math.atan2(((y - x) | 0), Math.fround((Math.fround(x) >> Math.fround(0x080000000)))) >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0)), mathy0(Math.fround(Math.expm1((((mathy0(y, -(2**53)) >>> 0) || ((( ! (0x080000000 | 0)) | 0) >>> 0)) >>> 0))), Math.fround((((( ! (x | 0)) | 0) | 0) === ( + mathy0(( + ( - x)), ( + -0x080000001))))))) >>> 0); }); testMathyFunction(mathy1, [0x080000001, 1/0, -(2**53+2), 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, -0x100000000, -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, -0x100000001, Math.PI, -Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, 0x100000001, 0x07fffffff, 42, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, -1/0, 1.7976931348623157e308, 0, -Number.MAX_VALUE, -0, Number.MAX_VALUE, -0x080000001, 0.000000000000001, 0/0]); \"); } });");
/*fuzzSeed-451211*/count=495; tryItOut("\"use strict\"; {let (e) { print(window); } }");
/*fuzzSeed-451211*/count=496; tryItOut("v1 = (i2 instanceof p1);");
/*fuzzSeed-451211*/count=497; tryItOut("s1 += 'x';");
/*fuzzSeed-451211*/count=498; tryItOut("\"use strict\"; v2 = (g2 instanceof h1);");
/*fuzzSeed-451211*/count=499; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-451211*/count=500; tryItOut("i2.send(e2);");
/*fuzzSeed-451211*/count=501; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var tan = stdlib.Math.tan;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.0009765625;\n    var d3 = -590295810358705700000.0;\n    var d4 = 9223372036854776000.0;\n    var i5 = 0;\n    d3 = (d2);\n    i5 = ((~~(d4)));\n    (Float32ArrayView[0]) = ((NaN));\n    return ((((((i1))>>>(((~((/*FFI*/ff(((524289.0)), ((-36028797018963970.0)))|0)+(0x2d7130f4))) >= (imul((/*FFI*/ff(((-1048577.0)))|0), ((0x55959b20)))|0)))) > (((0x78796190))>>>(0xfffff*(0xfc5e7e8a))))-((~~(d0)))))|0;\n    d2 = (((+abs(((+tan(((Infinity)))))))) * ((((d4)) * ((((68719476737.0)) - ((Float32ArrayView[1])))))));\n    return (((0x25117bda) % ((x) = null)))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 42, -0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 1, 0x100000000, 0x07fffffff, Math.PI, Number.MIN_VALUE, -(2**53-2), 2**53+2, 0.000000000000001, 0x100000001, 2**53, -(2**53), -0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 0, 2**53-2, -0x100000001, -0x0ffffffff, 1.7976931348623157e308, 1/0, -Number.MIN_VALUE, 0x0ffffffff, 0x080000000, -1/0, 0x080000001, -(2**53+2)]); ");
/*fuzzSeed-451211*/count=502; tryItOut("mathy5 = (function(x, y) { return Math.sqrt((Math.trunc(( + (Math.log(((0x07fffffff === 0x080000001) | 0)) | 0))) >>> 0)); }); testMathyFunction(mathy5, [-(2**53+2), -0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, 42, 2**53-2, 1, 0x100000000, 0x080000000, -0x100000000, 1/0, 2**53+2, -(2**53), -0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 0.000000000000001, -0x0ffffffff, 0/0, -1/0, -Number.MIN_VALUE, 0x100000001, 0x0ffffffff, 0, 0x080000001]); ");
/*fuzzSeed-451211*/count=503; tryItOut("testMathyFunction(mathy1, [Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, -0x100000001, 0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -(2**53+2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, 1.7976931348623157e308, 0x080000001, 42, 0x100000001, -(2**53-2), 1, 2**53, 0.000000000000001, -(2**53), -1/0, 0x100000000, 1/0, 0, Number.MIN_VALUE, -0x100000000, 2**53-2, -Number.MAX_VALUE, Math.PI, 2**53+2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=504; tryItOut("t0.set(t2, 8);");
/*fuzzSeed-451211*/count=505; tryItOut("\"use strict\"; p0.toString = (function() { h1.enumerate = (function() { print(uneval(g2.h2)); return i0; }); return t0; });");
/*fuzzSeed-451211*/count=506; tryItOut("testMathyFunction(mathy3, [0x0ffffffff, -(2**53+2), 1/0, -0x07fffffff, 0.000000000000001, 0x100000001, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 42, -0x100000001, 1, 0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000001, 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x080000001, -(2**53), -0x0ffffffff, -0x080000000, -0, Math.PI, 2**53, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -(2**53-2), 2**53-2]); ");
/*fuzzSeed-451211*/count=507; tryItOut("mathy0 = (function(x, y) { return ( + Math.tanh(( + (( ~ ((Math.fround(x) == Math.fround(x)) >>> 0)) * ((( ~ ( + Math.max(-Number.MAX_SAFE_INTEGER, ( + ( ! Math.fround(42)))))) | 0) >>> 0))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 0, 0x080000001, -0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, 2**53, 0/0, -0x100000001, -1/0, -0x080000000, 42, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), 0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, Math.PI, 0.000000000000001, Number.MIN_VALUE, 2**53-2, 2**53+2, -Number.MIN_VALUE, -(2**53+2), 0x080000000, 0x100000000, -0x100000000, 1, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-451211*/count=508; tryItOut("t2.__proto__ = o1;");
/*fuzzSeed-451211*/count=509; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.exp(Math.fround((( ~ (( + (( + Math.fround(Math.asinh(Math.fround(Math.sqrt(( + mathy1(y, -0x100000001))))))) <= ( + (((x | 0) - ((Math.imul(y, (Math.pow(y, y) >>> 0)) >>> 0) | 0)) | 0)))) | 0)) | 0))); }); testMathyFunction(mathy5, [0x080000000, 0x080000001, 1, 0x0ffffffff, Number.MIN_VALUE, -0x100000000, -0x080000000, 0x07fffffff, Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, -(2**53), 2**53+2, 2**53, 0.000000000000001, -Number.MIN_VALUE, -(2**53-2), -0x080000001, 42, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, 0, -(2**53+2), 2**53-2, 0x100000000, 0/0]); ");
/*fuzzSeed-451211*/count=510; tryItOut("o0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    {\n      i0 = (i0);\n    }\n    {\n      i0 = ((0x95ba5d34) ? ((((Uint8ArrayView[1])) >> ((((0x7b82ec4a))>>>((0xf88090a8))) % (0x12fcc624)))) : ((4.722366482869645e+21) <= (1.0)));\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: ({/*TOODEEP*/})}, new ArrayBuffer(4096));v2 = new Number(4);");
/*fuzzSeed-451211*/count=511; tryItOut("(void options('strict_mode'));");
/*fuzzSeed-451211*/count=512; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.tan(((((( + Math.log10(( + x))) >>> 0) % ((((((( + Math.tanh(x)) >>> 0) && Math.imul(Math.PI, Math.fround(Math.cosh(((y !== -(2**53+2)) >>> 0))))) >>> 0) <= ((( + (Math.exp((( + x) ? y : -Number.MAX_VALUE)) | 0)) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy0, [0x100000000, 1, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, 0x0ffffffff, -0x07fffffff, 0, -1/0, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, 0x080000000, 0.000000000000001, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53, -0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, Math.PI, -0x080000001, 2**53-2, -(2**53), 42, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, -0x100000001]); ");
/*fuzzSeed-451211*/count=513; tryItOut("v1 = Object.prototype.isPrototypeOf.call(v2, o0.t0);");
/*fuzzSeed-451211*/count=514; tryItOut("\"use strict\"; sbkynl();/*hhh*/function sbkynl(){v0 = (m2 instanceof this.s2);\nv1 = this.g1.runOffThreadScript();\n}");
/*fuzzSeed-451211*/count=515; tryItOut("\"use strict\"; s1 = a0.join(s1, h0);");
/*fuzzSeed-451211*/count=516; tryItOut("\"use strict\"; ");
/*fuzzSeed-451211*/count=517; tryItOut("mathy0 = (function(x, y) { return ((Math.fround(Math.cos((Math.fround(Math.min(Math.fround(Math.max(( + -Number.MAX_VALUE), Math.clz32(x))), Math.max(Math.fround(Math.acos(Math.fround(Math.atan((y >>> 0))))), Math.imul((Math.atan2((x | 0), (x >>> 0)) >>> 0), x)))) | 0))) > ((((Math.fround(( ~ Math.fround((Math.atan(0x100000000) >>> 0)))) >>> 0) << (( + ( + ( + Math.fround(Math.max(x, Math.asin(y)))))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53), -0x100000001, Math.PI, 2**53, 0.000000000000001, 2**53-2, 0x100000000, 1/0, -(2**53+2), -0x0ffffffff, -0x07fffffff, -1/0, -Number.MAX_VALUE, 0/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, -0, 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, 1, -Number.MIN_VALUE, 0, 0x07fffffff, 42, 0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-451211*/count=518; tryItOut("/*tLoop*/for (let x of /*MARR*/[x,  '\\0' , objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(true), x, objectEmulatingUndefined(), new Number(1.5), x, new Boolean(true), new Number(1.5),  '\\0' , new Number(1.5),  '\\0' , new Number(1.5),  '\\0' , x, x, x, x, x, new Number(1.5), new Boolean(true), objectEmulatingUndefined(),  '\\0' , x, new Number(1.5),  '\\0' , x, objectEmulatingUndefined(), x, new Number(1.5), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Boolean(true),  '\\0' , objectEmulatingUndefined(), new Boolean(true), new Number(1.5), objectEmulatingUndefined(), x, new Number(1.5), x, new Number(1.5), x, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5)]) { print({} = (( /x/g ).call( /x/ , ))); }");
/*fuzzSeed-451211*/count=519; tryItOut("");
/*fuzzSeed-451211*/count=520; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return Math.hypot((Math.ceil(((( + (Math.max((-Number.MAX_SAFE_INTEGER | 0), (( ~ ( - y)) | 0)) | 0)) == ( + (( + (mathy1(x, Math.fround(( + Math.fround(x)))) >>> 0)) + (Number.MAX_SAFE_INTEGER >>> 0)))) | 0)) | 0), ( + ((Math.fround(Math.atan2(Math.fround((((Math.atanh(Math.fround(( + y))) >>> 0) / (mathy2(( + ( + Math.hypot(( + x), (y | 0)))), y) | 0)) >>> 0)), (Math.log1p(y) | 0))) >>> 0) === (( + ( - ( + Math.pow(Math.imul(Math.trunc(y), Math.imul((y >>> 0), ( + (y ? y : y)))), x)))) >>> 0)))); }); testMathyFunction(mathy4, [-1/0, 2**53-2, 0x100000001, 0x080000001, -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 0.000000000000001, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, -0x07fffffff, Math.PI, 2**53+2, 2**53, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -0x080000000, 0x080000000, 0x07fffffff, 1, 0x100000000, 42, 0/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=521; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=522; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ! (Math.log2((Math.clz32((Math.clz32((Math.tan(y) | 0)) | 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-451211*/count=523; tryItOut("mathy3 = (function(x, y) { return ( - (Math.pow((( - Number.MIN_VALUE) >>> 0), (Math.sin(Math.tanh(( ~ x))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-451211*/count=524; tryItOut("\"use strict\"; L:with(x){yield;v1 = evaluate(\"print(x);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: \"\\u2674\", noScriptRval: true, sourceIsLazy: true, catchTermination: true })); }");
/*fuzzSeed-451211*/count=525; tryItOut("testMathyFunction(mathy5, [-0x100000000, 0x100000001, -0x07fffffff, Math.PI, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53, -0x100000001, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), 1/0, -(2**53-2), 42, Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, 0, -1/0, -0, 1, Number.MIN_VALUE, 2**53+2, 0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, 0x100000000, -0x080000000]); ");
/*fuzzSeed-451211*/count=526; tryItOut("\"use strict\"; s1 = '';function c(...NaN)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i2 = (1);\n    (Float32ArrayView[((x = ({a2:z2}))) >> 2]) = ((d0));\n    return ((((((i1))>>>((i1)-((((0xfdc2b5cc))>>>((0xe420a2f3))))-((({1: this.__defineSetter__(\"x\", objectEmulatingUndefined) }))))) < (0xffffffff))*-0x46b95))|0;\n  }\n  return f;(void schedulegc(g2));");
/*fuzzSeed-451211*/count=527; tryItOut("\"use strict\"; /*RXUB*/var r = /[^\\D\\D\\w\\D]+|(?:\\u8Fb2(?:(?:\u001c))*)|(?:j)[^]{1,1}/m; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=528; tryItOut("yield window\n;");
/*fuzzSeed-451211*/count=529; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround((Math.exp((mathy0(Math.pow(Math.fround(Math.max(Math.fround(mathy0(x, (x % -Number.MAX_SAFE_INTEGER))), Math.fround(Number.MIN_VALUE))), (y | x)), (( + ( + ( - (x | 0)))) >>> 0)) | 0)) | 0)) ? Math.fround(( - ( + Math.hypot(( + 2**53-2), ( + ( - mathy0(( + Math.cos(Math.min(( + x), x))), y))))))) : Math.fround(Math.sinh((Math.atanh(Math.pow(y, y)) >>> 0))))); }); testMathyFunction(mathy1, [0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 42, 0x080000001, -0x080000000, 2**53+2, -(2**53), 2**53-2, -1/0, -(2**53+2), -0x080000001, -0x0ffffffff, 0x07fffffff, 0x0ffffffff, 1/0, Number.MIN_VALUE, -0, 0x100000001, 2**53, Number.MAX_VALUE, -0x100000001, -(2**53-2), 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 1, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-451211*/count=530; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(Math.cos(Math.fround(((0x080000001 | 0) >>> x)))) !== Math.asinh((( - (y | 0)) | 0))); }); testMathyFunction(mathy0, [1/0, 0x100000000, -0x080000001, 0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 0, 0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, 1, -0x07fffffff, Number.MIN_VALUE, 0x07fffffff, 0/0, 0x080000001, -(2**53-2), 1.7976931348623157e308, -0x080000000, -(2**53), 2**53, -0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), 2**53+2, Math.PI, 2**53-2, -0]); ");
/*fuzzSeed-451211*/count=531; tryItOut("\"use strict\"; this.a1 = [];");
/*fuzzSeed-451211*/count=532; tryItOut("mathy4 = (function(x, y) { return (Math.fround(( + ( + (mathy2(Math.atanh(x), ((((( ! (y | 0)) | 0) | 0) <= ((( + (x >>> 0)) | 0) | 0)) | 0)) | 0)))) << mathy2(Math.fround(Math.imul(Math.fround((( ! (((( ~ (Math.asin((-(2**53-2) | 0)) | 0)) | 0) ? x : x) >>> 0)) >>> 0)), Math.fround(( + ( - ( + ((y & (y >>> 0)) >>> 0))))))), ( - x))); }); testMathyFunction(mathy4, [1/0, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 0, 2**53, 0x100000001, 2**53+2, -0x100000000, -0, 2**53-2, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, 1, -1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, -0x07fffffff, 42, -Number.MAX_VALUE, 0x0ffffffff, -(2**53), -0x080000000, 1.7976931348623157e308, -(2**53-2), 0x080000001, Number.MAX_VALUE, 0/0, 0x07fffffff]); ");
/*fuzzSeed-451211*/count=533; tryItOut("\"use strict\"; a1.unshift(/*FARR*/[({a2:z2}).watch(\"caller\", false.fromCharCode), undefined].map);");
/*fuzzSeed-451211*/count=534; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + ( ~ Math.sin(-(2**53-2)))) % (mathy3(Math.sign(Math.fround((0x080000001 || mathy2((x | 0), (y | 0))))), ( + x)) >>> 0))); }); testMathyFunction(mathy4, ['', ({valueOf:function(){return '0';}}), '0', /0/, [], (new String('')), undefined, (new Number(-0)), 1, 0.1, ({toString:function(){return '0';}}), (function(){return 0;}), (new Number(0)), objectEmulatingUndefined(), true, (new Boolean(false)), NaN, null, '\\0', (new Boolean(true)), false, '/0/', [0], 0, -0, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-451211*/count=535; tryItOut("mathy4 = (function(x, y) { return (( - Math.fround(( - Math.fround((Math.imul(( + x), Math.cbrt(x)) !== (Math.fround(( ! Math.fround((y > Math.fround(-(2**53+2)))))) >>> 0)))))) | 0); }); testMathyFunction(mathy4, [-0, -1/0, -(2**53+2), 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 42, 2**53+2, 0x100000000, 2**53, 0x080000001, -0x100000000, 1/0, Number.MAX_VALUE, -(2**53), -0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, 1, 0x100000001, 0/0, 0x07fffffff, 0, -(2**53-2), Math.PI, -0x100000001, 2**53-2, -0x07fffffff, -0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-451211*/count=536; tryItOut("mathy1 = (function(x, y) { return ((((Math.min(x, Math.pow(Math.fround(y), Number.MIN_VALUE)) ? (( ~ Math.atan2(-Number.MAX_SAFE_INTEGER, x)) | 0) : (x << ((y % y) >>> 0))) | 0) && (( ! (Math.fround(( ! y)) | 0)) | 0)) < (((( + mathy0(( + Math.atan(( ~ 0x080000000))), (x >>> 0))) >>> 0) !== ((( ! (x | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0x080000001, -Number.MIN_VALUE, -0x0ffffffff, 0x100000001, Math.PI, -0x100000000, 2**53, -(2**53+2), -(2**53), Number.MIN_VALUE, -0x100000001, 0.000000000000001, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, 0/0, -1/0, -Number.MAX_VALUE, 42, 1, 0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, -(2**53-2), -0x080000000, -0x080000001, Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, 1.7976931348623157e308]); ");
/*fuzzSeed-451211*/count=537; tryItOut("with(/*UUV2*/(x.slice = x.floor))a2 = arguments;function window()xv2 = evalcx(\"13\", this.g0);");
/*fuzzSeed-451211*/count=538; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log1p((Math.atan2(( + ( + Math.fround(( - Math.fround(Math.sign(x)))))), ( + (Math.max(Math.imul(y, 0x080000001), x) >>> (( + (( + x) >>> 0)) !== Math.pow(x, (Math.tanh(x) >>> 0)))))) | 0)); }); testMathyFunction(mathy1, [0x100000000, -0x07fffffff, Math.PI, 0x080000001, 2**53-2, 0, -1/0, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -0x080000000, 1, -(2**53+2), 0.000000000000001, 42, -0, -(2**53), 0x100000001, -0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 1/0, -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, 0x080000000]); ");
/*fuzzSeed-451211*/count=539; tryItOut("v0 + '';");
/*fuzzSeed-451211*/count=540; tryItOut("\"use strict\"; M:if(true) v1 = g0.eval(\"t1.set(t2, 16);\"); else i2.send(g0.o1);");
/*fuzzSeed-451211*/count=541; tryItOut("let \u3056 =  '' , get = Math.hypot(22, (makeFinalizeObserver('tenured'))), \u3056 = (/*UUV2*/(eval.asin = eval.toString)), y = x, window = function(y) { \"use asm\"; return let (y = this.x, y =  /x/g , \u3056, c, e, oyddzi) ((makeFinalizeObserver('nursery'))) }(), dtmxrp, NaN =  ''  < ((function sum_slicing(rrpgqc) { ; return rrpgqc.length == 0 ? 0 : rrpgqc[0] + sum_slicing(rrpgqc.slice(1)); })(/*MARR*/[objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), false])), NaN = ((let (e=eval) e))(), NaN = delete b.\u3056;/*tLoop*/for (let z of /*MARR*/[new Boolean(false), new String('q'), (x >>> eval.unwatch(new String(\"19\"))), new Boolean(false), new String('q'), new String('q'), new String('q')]) { /*RXUB*/var r = new RegExp(\"(?!(?!\\\\b))^(\\\\D)\", \"i\"); var s = \"\\n\\u00fd  \\n\\n\"; print(uneval(s.match(r)));  }");
/*fuzzSeed-451211*/count=542; tryItOut("\"use asm\"; a1.forEach(f2, g0.i2);");
/*fuzzSeed-451211*/count=543; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.fround(Math.imul(Math.fround(Math.fround(Math.hypot(( + Math.max(0x080000000, x)), ( + ( + Math.fround(( - (( ! x) | 0)))))))), Math.sign(x)))); }); testMathyFunction(mathy0, /*MARR*/[false, false, false,  /x/g ,  /x/g ,  /x/g ,  /x/g , false, false, false,  /x/g , false,  /x/g , false,  /x/g , false,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , false, false]); ");
/*fuzzSeed-451211*/count=544; tryItOut("v2 = new Number(0);");
/*fuzzSeed-451211*/count=545; tryItOut("Array.prototype.splice.call(a1, NaN, 12);");
/*fuzzSeed-451211*/count=546; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + mathy1(( + ( + ( ~ ( + ( - x))))), ( + ( ~ (( + Math.pow((-Number.MAX_SAFE_INTEGER >>> 0), (y | 0))) && (x >>> Math.fround(x))))))); }); testMathyFunction(mathy2, [-0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -0, -Number.MAX_VALUE, -0x0ffffffff, 1, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, Math.PI, 0x100000001, 0/0, -0x080000001, 0x100000000, -1/0, 1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, 0.000000000000001, -(2**53), 1.7976931348623157e308, -0x07fffffff, 2**53+2, -(2**53-2), 2**53, 0, 0x0ffffffff]); ");
/*fuzzSeed-451211*/count=547; tryItOut("/*infloop*/L:for(let x in window) {print(t2); }");
/*fuzzSeed-451211*/count=548; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(( ! ( + ( - x)))), Math.fround(Math.fround(Math.sinh(mathy3(Math.atan2((( ~ (y >>> 0)) >>> 0), (((-0 >>> 0) !== (( + (-Number.MAX_SAFE_INTEGER >>> ( + Math.asin(x)))) >>> 0)) >>> 0)), Math.tanh(2**53))))))); }); ");
/*fuzzSeed-451211*/count=549; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=550; tryItOut("mathy3 = (function(x, y) { return Math.fround(( - Math.fround(( + Math.sqrt(Math.max((( ! (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0), y)))))); }); testMathyFunction(mathy3, [42, 0x100000001, Math.PI, 0x0ffffffff, -Number.MAX_VALUE, 0x080000000, -0x07fffffff, 2**53+2, -1/0, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, -0, 1.7976931348623157e308, -(2**53), 2**53-2, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -(2**53+2), 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, -0x100000000, 2**53, Number.MIN_VALUE, 1, 0, 0x080000001]); ");
/*fuzzSeed-451211*/count=551; tryItOut("\"use strict\"; v0 = evaluate(\"new (function(q) { return q; })(true)\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 == 4), noScriptRval: (uneval((makeFinalizeObserver('tenured')))), sourceIsLazy: !(w(eval = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(/(?:\\b|.*|\\w+?)|(?=^)|.\\1*?/gym), (window = function ([y]) { }))) = (((4277) ? (Math.hypot(12, x)) : \"\\uFD6C\".watch(\"acosh\", String.prototype.endsWith))).call((4277), )), catchTermination: (x % 4 != 1), element: o0, elementAttributeName: s1 }));");
/*fuzzSeed-451211*/count=552; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.cos(Math.pow(((y ? ( + (( + x) | (x , (((y >>> 0) >> (x >>> 0)) >>> 0)))) : (( ~ Math.fround(y)) ? ( + (y & ( + Math.acos((Math.hypot((0x100000000 | 0), -0x0ffffffff) | 0))))) : (((( ! y) ? y : y) ^ y) | 0))) >>> 0), Math.fround(( + (x + (( + Math.exp((y >>> 0))) >>> 0)))))); }); testMathyFunction(mathy2, [42, 0x080000000, -Number.MAX_VALUE, -0, 1/0, 0/0, 0x100000000, -0x100000000, 0x0ffffffff, -0x100000001, 0x100000001, -(2**53+2), -(2**53), Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, 1, -0x080000001, 0x080000001, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, -(2**53-2), Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0]); ");
/*fuzzSeed-451211*/count=553; tryItOut("/*MXX1*/g2.o2 = g1.g2.ArrayBuffer.length;");
/*fuzzSeed-451211*/count=554; tryItOut("this.a2.splice(NaN, 13);");
/*fuzzSeed-451211*/count=555; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.log1p((( ~ ((Math.sqrt(( + y)) >>> ((( + Math.abs(x)) | 0) | 0)) >>> 0)) | 0)); }); testMathyFunction(mathy1, [Math.PI, -(2**53+2), 0x080000000, Number.MAX_VALUE, 0.000000000000001, -0x100000000, 1, 0x100000000, Number.MAX_SAFE_INTEGER, 1/0, 42, -0x07fffffff, 0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000001, -0x080000000, -(2**53-2), 1.7976931348623157e308, 0x07fffffff, -0x0ffffffff, -(2**53), 0x080000001, 0x100000001, 2**53+2, Number.MIN_VALUE, -0, 0x0ffffffff, -1/0, 0/0, -0x100000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-451211*/count=556; tryItOut("g1.offThreadCompileScript(\"/* no regression tests found */\");/*MXX3*/g1.Map.prototype = g0.Map.prototype;");
/*fuzzSeed-451211*/count=557; tryItOut("\"use strict\"; let b1 = t0.buffer;");
/*fuzzSeed-451211*/count=558; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=559; tryItOut("/*oLoop*/for (let jzsvkz = 0; jzsvkz < 57; ++jzsvkz) { o0.v0 = g0.runOffThreadScript(); } ");
/*fuzzSeed-451211*/count=560; tryItOut("this.s0 += s2;");
/*fuzzSeed-451211*/count=561; tryItOut("v0 = this.g0.g2.t1.length;");
/*fuzzSeed-451211*/count=562; tryItOut("g0.t1[7] = g1;");
/*fuzzSeed-451211*/count=563; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(( + Math.cos(mathy0(Math.hypot(( + Math.fround(( ! Math.fround(y)))), ( + (( + x) ? x : ( + ((y , x) < Math.imul((x | 0), y)))))), ((x | y) ? Math.max((y | 0), ((Math.log((x | 0)) | 0) >>> 0)) : (( ! (-Number.MAX_VALUE >>> 0)) >>> 0))))), mathy0(Math.sqrt(x), ( ~ (Math.tan((Math.round(y) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), -1/0, 2**53, Number.MAX_VALUE, 0x100000000, -0x080000000, 0x100000001, 0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 42, 2**53+2, 0.000000000000001, -(2**53-2), -0, Math.PI, 0x0ffffffff, 1/0, -(2**53), -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, 1, 0/0, -0x100000001, -0x080000001, -0x07fffffff, -Number.MIN_VALUE, 0x07fffffff]); ");
/*fuzzSeed-451211*/count=564; tryItOut("\"use strict\"; s2 = new String(a1);");
/*fuzzSeed-451211*/count=565; tryItOut("print((makeFinalizeObserver('nursery')));function z()(4277)print([ '' ]);");
/*fuzzSeed-451211*/count=566; tryItOut("Object.defineProperty(this, \"b1\", { configurable: [,] ? [,,z1] : [z1], enumerable: (x % 51 != 16),  get: function() {  return new SharedArrayBuffer(16); } });");
/*fuzzSeed-451211*/count=567; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.cbrt(Math.fround(( - mathy2(y, y)))), Math.exp((Math.log10(Math.max(Math.fround(((y / y) || -0x080000001)), Math.fround(Math.atan2(Math.hypot(mathy1(x, y), y), x)))) | 0)))); }); testMathyFunction(mathy3, [0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, 2**53+2, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), 0x100000000, -0x0ffffffff, 0x0ffffffff, 0x07fffffff, -0x080000001, -0, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000000, 1/0, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, 1, 0x080000001, 0, 2**53, -1/0, Number.MIN_VALUE, -(2**53-2), 42]); ");
/*fuzzSeed-451211*/count=568; tryItOut("testMathyFunction(mathy0, /*MARR*/[ 'A' , new Number(1.5),  'A' ,  'A' , x, new Number(1.5), length *= z, x, new Number(1.5), length *= z,  'A' , x, length *= z, new Number(1.5), new Number(1.5), new Number(1.5),  'A' , length *= z, x, x, new Number(1.5), new Number(1.5), length *= z,  'A' ,  'A' , new Number(1.5), x,  'A' , length *= z,  'A' , new Number(1.5), length *= z, length *= z, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), length *= z,  'A' ,  'A' , x, x,  'A' , new Number(1.5),  'A' , new Number(1.5), x,  'A' , new Number(1.5), new Number(1.5),  'A' , length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, length *= z, x, length *= z, x, x, new Number(1.5), new Number(1.5), length *= z, new Number(1.5),  'A' , new Number(1.5), x, x, new Number(1.5),  'A' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), length *= z,  'A' ,  'A' ,  'A' , x, length *= z, length *= z, new Number(1.5), length *= z,  'A' ,  'A' , new Number(1.5), new Number(1.5), new Number(1.5),  'A' , x,  'A' ,  'A' ,  'A' , x, length *= z, new Number(1.5)]); ");
/*fuzzSeed-451211*/count=569; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.log2(( + ((( ~ ( - y)) >>> 0) <= (( ! Math.max(0x0ffffffff, Number.MIN_SAFE_INTEGER)) ? (Math.acosh(( + ( ! ( + ( ! y))))) - (Math.min(y, y) ? y : y)) : ( + Math.fround((Math.fround((Math.asinh((Number.MIN_VALUE >>> 0)) >>> 0)) != Math.fround(Math.atan2(y, x))))))))) | 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 1, 0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 1/0, Number.MAX_VALUE, -0x080000000, 0x100000000, -0x080000001, 2**53+2, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 0x07fffffff, 0x100000001, -0x0ffffffff, 2**53-2, -0x100000001, 0/0, -1/0, -(2**53+2), -0x07fffffff, -0x100000000, 0, Math.PI, 42, -Number.MIN_VALUE, -(2**53), 0x0ffffffff]); ");
/*fuzzSeed-451211*/count=570; tryItOut("\"use strict\"; m1.has(h0);");
/*fuzzSeed-451211*/count=571; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = ((abs((~~(d0)))|0));\n    }\n    {\n      {\n        d1 = (17179869185.0);\n      }\n    }\n    d1 = (d0);\n    d0 = (d1);\n    {\n      d0 = (+pow(((d1)), ((d0))));\n    }\n    d1 = (+(imul(((0x0)), (-0x8000000))|0));\n    d0 = (d1);\n    (Int32ArrayView[(((d1) > (d0))+((0x7496efda) != (((0xf84ceeba))>>>((0xd6eefc13))))-(/*FFI*/ff()|0)) >> 2]) = (((abs(((Float64ArrayView[0])))|0) == (0x2679941e))+(0x9026e09c)+(-0x8000000));\n    d1 = (d0);\n    return +((d0));\n  }\n  return f; })(this, {ff: Promise.prototype.then}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MAX_VALUE, 2**53+2, 1/0, -Number.MAX_VALUE, -0x07fffffff, 42, Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, 0/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 1.7976931348623157e308, -0x100000001, 1, 0x080000000, 0x100000001, 0x0ffffffff, 2**53, -(2**53), 0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, 0, 0x080000001, -0, 2**53-2, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0.000000000000001, 0x07fffffff]); ");
/*fuzzSeed-451211*/count=572; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=573; tryItOut("{var biavdg = new ArrayBuffer(24); var biavdg_0 = new Float32Array(biavdg); biavdg_0[0] = -10; var biavdg_1 = new Uint16Array(biavdg); print(biavdg_1[0]); biavdg_1[0] = 11; var biavdg_2 = new Uint8Array(biavdg); biavdg_2[0] = -23; t1 + '';yield /(?=\\b)/yim;return undefined;m1.has(m0); }");
/*fuzzSeed-451211*/count=574; tryItOut("Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-451211*/count=575; tryItOut("\"use strict\"; this.v1 = Array.prototype.every.call(a2);");
/*fuzzSeed-451211*/count=576; tryItOut("for (var p in h1) { for (var p in p2) { try { a1.forEach((function() { for (var j=0;j<57;++j) { f1(j%5==1); } })); } catch(e0) { } g0.toSource = (function() { try { a0.toSource = (function() { v0 + ''; return i1; }); } catch(e0) { } try { a1.pop(); } catch(e1) { } /*MXX1*/o2 = g0.RegExp.lastMatch; return p1; }); } }");
/*fuzzSeed-451211*/count=577; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[new String(''), NaN, NaN, NaN, new String(''), new String(''), NaN, new String(''), new String(''), NaN, new String(''), new String(''), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, new String(''), new String(''), NaN, NaN, new String(''), NaN, NaN, NaN, new String(''), new String(''), NaN, new String(''), NaN, new String(''), new String(''), NaN, new String(''), NaN, new String(''), NaN, NaN, new String(''), new String(''), new String(''), new String(''), NaN, NaN, NaN, NaN, new String(''), NaN, new String(''), NaN, new String(''), NaN, NaN, NaN, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, new String(''), new String(''), NaN, NaN, NaN, new String(''), new String(''), new String(''), new String(''), new String(''), NaN, NaN, NaN, new String(''), NaN, new String(''), NaN, NaN, NaN, new String(''), new String(''), NaN, NaN, new String(''), NaN, new String(''), NaN, NaN, new String(''), new String(''), new String(''), new String(''), new String(''), NaN, NaN, NaN, NaN, new String(''), NaN, NaN, new String(''), NaN, new String(''), NaN, NaN, new String(''), new String(''), NaN, NaN, NaN, new String(''), NaN, new String(''), new String(''), NaN]); ");
/*fuzzSeed-451211*/count=578; tryItOut("print(m1);");
/*fuzzSeed-451211*/count=579; tryItOut("mathy0 = (function(x, y) { return ((( + (Math.acosh((x - ((-Number.MIN_SAFE_INTEGER <= y) >>> 0))) != Math.sinh(x))) && ( + ( - (y ? (Math.atan2(Math.max(( + Math.fround(Math.log1p(y))), ( + x)), ( + x)) | 0) : Math.log10(( ! x)))))) >>> 0); }); testMathyFunction(mathy0, [0, null, (new Boolean(false)), 0.1, '\\0', '', ({toString:function(){return '0';}}), (new Number(-0)), -0, /0/, (new Boolean(true)), [0], undefined, [], (new String('')), 1, ({valueOf:function(){return '0';}}), (function(){return 0;}), false, NaN, '/0/', ({valueOf:function(){return 0;}}), (new Number(0)), '0', objectEmulatingUndefined(), true]); ");
/*fuzzSeed-451211*/count=580; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + (( + ( ~ ((((( ! (Math.acos(x) + y)) >>> 0) | 0) && ((mathy4(0x07fffffff, (Math.pow(x, y) >>> 0)) >>> 0) | 0)) | 0))) >= ( + (((((mathy3((x | 0), ((Math.asin((x | 0)) | 0) | 0)) | 0) | 0) >> (Math.fround(( ! mathy1(x, y))) | 0)) | 0) << (Math.pow(x, y) | 0))))); }); testMathyFunction(mathy5, /*MARR*/[ /x/g , new Number(1), new Number(1),  /x/g , new Number(1), new RegExp(\"(?=\\\\r|\\\\B)(\\ud81a)*?+?\", \"\"),  /x/g ,  /x/g , new RegExp(\"(?=\\\\r|\\\\B)(\\ud81a)*?+?\", \"\"),  /x/g ,  /x/g , new RegExp(\"(?=\\\\r|\\\\B)(\\ud81a)*?+?\", \"\"),  /x/g , new RegExp(\"(?=\\\\r|\\\\B)(\\ud81a)*?+?\", \"\"),  /x/g ,  /x/g ]); ");
/*fuzzSeed-451211*/count=581; tryItOut("let this.v0 = g1.a0.length;");
/*fuzzSeed-451211*/count=582; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.sin((Math.asinh((Math.tanh(Math.cbrt(-Number.MIN_SAFE_INTEGER)) >>> 0)) | 0)); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, 42, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, 0x100000000, 0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, 2**53-2, -(2**53-2), Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), -0x080000000, 2**53+2, -0, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, 2**53, 0, 0/0, -1/0, Math.PI, 1/0, 0x080000000, Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-451211*/count=583; tryItOut("var adymle, a = (), w, x, x = ((Math.sinh(-65091448)) ? (makeFinalizeObserver('nursery')) :  /x/g ), x, x =  /x/ , mfjsgu, z, oevaiv; ''  instanceof 3;");
/*fuzzSeed-451211*/count=584; tryItOut("\"use strict\"; b2 + '';");
/*fuzzSeed-451211*/count=585; tryItOut("\"use strict\"; g2.g2.o2.o2 + g2.o1.e1;");
/*fuzzSeed-451211*/count=586; tryItOut("print(m2);\no1.a2 = m2.get(m1);\n");
/*fuzzSeed-451211*/count=587; tryItOut("\"use strict\"; v2 = a1.length;");
/*fuzzSeed-451211*/count=588; tryItOut("i2 + o0;");
/*fuzzSeed-451211*/count=589; tryItOut("a2.reverse(o2.g2.e0);");
/*fuzzSeed-451211*/count=590; tryItOut("Array.prototype.splice.apply(a0, [-1, ({valueOf: function() { /*tLoop*/for (let d of /*MARR*/[objectEmulatingUndefined(), new Number(1), new Number(1), (void 0), new Number(1), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), (void 0), new Number(1), new Number(1), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), new Number(1), (void 0), objectEmulatingUndefined(), (void 0), new Number(1), new Number(1), (void 0), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), (void 0), new Number(1), new Number(1), new Number(1), (void 0), (void 0), (void 0), objectEmulatingUndefined(), new Number(1), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), new Number(1), objectEmulatingUndefined(), new Number(1), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), (void 0)]) { s2 = o0.a2.join(s2, b2); }return 14; }}), this.a0, this.e0]);");
/*fuzzSeed-451211*/count=591; tryItOut("mathy4 = (function(x, y) { return Math.pow(((Math.asin(Math.fround(Math.imul(Math.fround(((1 | 0) >> x)), Math.fround(-(2**53))))) >>> 0) ? ((x ? x : Math.ceil(x)) ? mathy2(Math.asin(( + 0x080000001)), -Number.MAX_VALUE) : (Math.atan2(0x080000000, ( + (Number.MIN_VALUE < mathy3(y, 0x080000000)))) % x)) : (Math.min((mathy0((x && Math.fround(Math.fround(( ! 2**53)))), Math.log2((y >>> 0))) | 0), ((Math.asinh((x | 0)) | 0) | 0)) | 0)), Math.fround(Math.acosh(( + Math.tanh(( + Math.min((y | 0), (y | 0)))))))); }); ");
/*fuzzSeed-451211*/count=592; tryItOut("\"use strict\"; a0.length = 5;");
/*fuzzSeed-451211*/count=593; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=594; tryItOut("\"use strict\"; testMathyFunction(mathy1, [(new Number(0)), undefined, '0', objectEmulatingUndefined(), (new String('')), 0, '\\0', (new Number(-0)), /0/, false, ({valueOf:function(){return '0';}}), (function(){return 0;}), (new Boolean(false)), (new Boolean(true)), ({toString:function(){return '0';}}), 0.1, 1, true, -0, [0], '', NaN, '/0/', ({valueOf:function(){return 0;}}), null, []]); ");
/*fuzzSeed-451211*/count=595; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.hypot((( + (-0x080000001 << y)) ** Math.log(y)), (( + Math.min(Math.fround(0x0ffffffff), ( + Math.fround(Math.pow(42, Math.fround((( ~ ((-0 ? (y | 0) : y) >>> 0)) >>> 0))))))) != Math.fround(Math.asinh(((Math.hypot(( + y), y) ^ (Math.min((y >>> 0), (-0x100000000 >>> 0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, 2**53+2, 0, 2**53-2, -0, -0x100000001, -0x080000001, 2**53, -0x07fffffff, 0x080000000, 0/0, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x080000000, 0x07fffffff, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, -Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, Math.PI, 0x0ffffffff, 0x100000001, Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-451211*/count=596; tryItOut("\"use strict\"; L:for(y = (uneval(this)) in x) a0 = arguments;");
/*fuzzSeed-451211*/count=597; tryItOut("g1.a0.sort((function() { try { for (var v of g0.b0) { try { for (var p in s2) { try { Array.prototype.shift.call(a2); } catch(e0) { } try { t2 = t0.subarray(12); } catch(e1) { } try { s0 + ''; } catch(e2) { } o2.__proto__ = i1; } } catch(e0) { } try { v1 = evalcx(\"/* no regression tests found */\", g1); } catch(e1) { } try { i0 + ''; } catch(e2) { } v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: eval | x, noScriptRval: (x % 2 == 1), sourceIsLazy: false, catchTermination: x, sourceMapURL: s1 })); } } catch(e0) { } Array.prototype.sort.apply(a2, [(function() { Array.prototype.reverse.call(a0); return g1.e0; })]); return o1; }));");
/*fuzzSeed-451211*/count=598; tryItOut("/*RXUB*/var r = g1.r2; var s = this.s1; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=599; tryItOut("\"use strict\"; ");
/*fuzzSeed-451211*/count=600; tryItOut("mathy3 = (function(x, y) { return Math.fround((Math.fround((Math.imul((Math.fround((Math.acosh((Math.expm1(((x ** ( + 1.7976931348623157e308)) >>> 0)) >>> 0)) | ( + (Math.fround(mathy1(0, Math.fround(-0x100000001))) && y)))) >>> 0), (mathy2(( + (( + y) >>> ( + Math.pow(Math.fround(y), Math.fround(Math.max(1, Math.fround(Math.clz32(x)))))))), Math.hypot(( + y), x)) >>> 0)) | 0)) == Math.fround(Math.exp(Math.sin(x))))); }); testMathyFunction(mathy3, /*MARR*/[ \"\" ,  \"\" , function(){}, function(){}, function(){}, function(){},  \"\" , function(){}, function(){},  \"\" , function(){}, function(){},  \"\" ,  \"\" , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  \"\" , function(){},  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , function(){}, function(){},  \"\" , function(){}, function(){}, function(){},  \"\" , function(){}, function(){},  \"\" , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-451211*/count=601; tryItOut("\"use strict\"; with({e:  /x/ }){o2 = i0.__proto__; }");
/*fuzzSeed-451211*/count=602; tryItOut("\"use strict\"; /*infloop*/while(((++Math.imul) ? x : timeout(1800)))h2.fix = f1;");
/*fuzzSeed-451211*/count=603; tryItOut("\"use strict\"; let ipttno; '' ;");
/*fuzzSeed-451211*/count=604; tryItOut("testMathyFunction(mathy1, [-0x07fffffff, 0x080000000, -0, 0x100000001, 1/0, Math.PI, -0x0ffffffff, -0x100000001, 1, 2**53, 0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, 42, 0x100000000, -0x080000001, 0, Number.MAX_VALUE, -(2**53+2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, -(2**53-2), -Number.MIN_VALUE, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x080000000, 0x07fffffff, 0x080000001, -(2**53), 1.7976931348623157e308]); ");
/*fuzzSeed-451211*/count=605; tryItOut("a2.forEach((function(j) { if (j) { try { o1.m0.has(h1); } catch(e0) { } v1 = g1.eval(\"/* no regression tests found */\"); } else { try { v2 = Object.prototype.isPrototypeOf.call(p0, b0); } catch(e0) { } try { function f2(g1.m1)  { \"use strict\"; yield JSON.stringify.prototype }  } catch(e1) { } try { v0 = (m1 instanceof b0); } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(v0, this.e0); } }), s0, g1.m2, this.h1);");
/*fuzzSeed-451211*/count=606; tryItOut("\"use asm\"; v0 = (e2 instanceof o2.h2);");
/*fuzzSeed-451211*/count=607; tryItOut("/*RXUB*/var r = /.+/gy; var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-451211*/count=608; tryItOut("\"use strict\"; o0.e1 + h0;");
/*fuzzSeed-451211*/count=609; tryItOut("testMathyFunction(mathy0, [({valueOf:function(){return '0';}}), (function(){return 0;}), false, 0, (new Boolean(true)), 1, (new Number(0)), (new Number(-0)), true, '0', ({toString:function(){return '0';}}), '', (new Boolean(false)), undefined, NaN, '/0/', [], null, 0.1, '\\0', /0/, -0, objectEmulatingUndefined(), [0], (new String('')), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-451211*/count=610; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.hypot(mathy2(-0x080000000, mathy0(((Math.min((Math.hypot(( + x), (x >>> 0)) >>> 0), x) | 0) > x), (-0 | 0))), Math.log1p(( + ( ~ Math.atan2((x >>> 0), y))))) | 0), Math.fround(mathy0(Math.fround(Math.pow((Math.max(mathy3(2**53+2, ((Math.fround(Math.fround(Math.atan2(Math.fround(y), ( + y)))) & Math.fround(y)) | 0)), (( ~ ((mathy3(x, x) | 0) >>> 0)) >>> 0)) | 0), x)), Math.fround(Math.sin(Math.cbrt((y | 0))))))) | 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, 2**53-2, 0x080000000, -0, 42, 0x100000000, -(2**53), -(2**53-2), 0x0ffffffff, -(2**53+2), 1.7976931348623157e308, 2**53, -0x07fffffff, -Number.MIN_VALUE, -0x100000001, -1/0, -Number.MAX_VALUE, 1/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, 0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53+2, -0x0ffffffff, Math.PI]); ");
/*fuzzSeed-451211*/count=611; tryItOut("mathy3 = (function(x, y) { return (( - ( + Math.fround(Math.tanh(( + Math.atan2(Math.fround((((mathy1(( ~ y), x) >>> 0) | (Math.tanh(0.000000000000001) >>> 0)) | 0)), ( + Math.hypot(y, Math.sqrt(y))))))))) | 0); }); testMathyFunction(mathy3, [2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -0x07fffffff, -(2**53-2), -1/0, -Number.MAX_VALUE, 0x100000000, -(2**53), 0.000000000000001, -0x0ffffffff, -0x080000001, -(2**53+2), Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, 42, -0x080000000, Math.PI, 2**53+2, 0/0, -0, 1/0, 0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 1, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=612; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x080000000, 0x080000001, 0x080000000, 1/0, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 0.000000000000001, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, 0/0, -0x07fffffff, 2**53+2, 0, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 42, -0x0ffffffff, Number.MIN_VALUE, -1/0, -(2**53), -(2**53+2), Number.MIN_SAFE_INTEGER, -0, 1, -(2**53-2)]); ");
/*fuzzSeed-451211*/count=613; tryItOut("testMathyFunction(mathy3, /*MARR*/[{}, new String('q'), new String('q'), new String('q'), new String(''), new String(''), new String(''), function(){}, new String('q'), {}, [1], [1]]); ");
/*fuzzSeed-451211*/count=614; tryItOut("/*vLoop*/for (var ytuwvq = 0; ( '' ) && ytuwvq < 5; ++ytuwvq) { const e = ytuwvq; e0.has(i0); } ");
/*fuzzSeed-451211*/count=615; tryItOut("mathy0 = (function(x, y) { return Math.hypot(( + ( + (( ~ ( + Math.min(( + Math.max(( + x), ( + (y ? (x | 0) : x)))), ( + ( + ( - y)))))) | 0))), ( + (Math.atanh((Math.pow(Math.fround(((x !== x) ? Math.fround(y) : Math.fround((Math.atan2((Math.fround((( + x) << Number.MAX_VALUE)) >>> 0), (0x080000001 >>> 0)) >>> 0)))), (Number.MAX_SAFE_INTEGER >>> (0x07fffffff / Math.fround(Math.log1p(Math.fround(x)))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-0, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, -1/0, -0x07fffffff, -(2**53+2), 0.000000000000001, 2**53+2, 0x0ffffffff, 2**53-2, -(2**53-2), 1/0, -0x080000001, Number.MIN_VALUE, 2**53, 0/0, 0, 0x080000001, 0x100000000, 1, 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 42, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, -0x100000001, Math.PI]); ");
/*fuzzSeed-451211*/count=616; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=617; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-451211*/count=618; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ mathy0(((Math.max(Math.hypot(y, (y ^ y)), ( + mathy0(Math.sinh(y), x))) >>> 0) && ((Math.tanh(Math.fround(Math.fround(Math.atan2(y, Math.round(Math.fround(x)))))) >>> 0) | 0)), (mathy0((Math.sinh((y | 0)) >>> 0), (( + (( + y) !== ( + (Math.acosh(-0x100000001) | 0)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [-0x100000001, Number.MAX_VALUE, -0x080000001, 0x080000001, 2**53-2, -(2**53-2), -Number.MIN_VALUE, 0x100000000, 0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, -0, 42, Number.MIN_VALUE, Math.PI, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x07fffffff, 0, -0x080000000, -Number.MAX_VALUE, 2**53, 0/0, -0x0ffffffff, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-451211*/count=619; tryItOut("v0 = t1.length;");
/*fuzzSeed-451211*/count=620; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(m2, \"2\", { configurable: false, enumerable: (x % 5 == 1), writable: false, value: o1.h0 });");
/*fuzzSeed-451211*/count=621; tryItOut("mathy0 = (function(x, y) { return Math.pow(( + ( + (( + Math.atan2(-Number.MAX_VALUE, ( + Math.pow((Math.acosh(y) | 0), ( + -(2**53+2)))))) ^ ( + ( - ( ~ -Number.MIN_SAFE_INTEGER)))))), ( + Math.atan2((Math.acos((((x >>> 0) ^ (((( ! Math.fround((Math.fround(y) ? Math.fround(-Number.MAX_SAFE_INTEGER) : y))) | 0) + Math.pow(2**53-2, -1/0)) >>> 0)) >>> 0)) | 0), (( ! ( ~ 0)) | 0)))); }); testMathyFunction(mathy0, [-0x07fffffff, -0, 1.7976931348623157e308, 0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, -0x080000000, Number.MAX_VALUE, 0x080000000, 0x100000000, 0, 0.000000000000001, -0x100000000, 1, -(2**53+2), -0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, 1/0, -1/0, 2**53, -Number.MAX_VALUE, 42, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, 0/0, -Number.MIN_VALUE, 2**53-2, Math.PI]); ");
/*fuzzSeed-451211*/count=622; tryItOut("{ void 0; void relazifyFunctions(this); }");
/*fuzzSeed-451211*/count=623; tryItOut("this.i2.send(a1);");
/*fuzzSeed-451211*/count=624; tryItOut("\"use strict\"; v0 = null;");
/*fuzzSeed-451211*/count=625; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-451211*/count=626; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - Math.fround(((Math.atan(x) | (Math.sign(y) | 0)) >>> 0))); }); testMathyFunction(mathy3, [-0x100000000, -(2**53-2), 1/0, -(2**53), -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 0/0, 2**53-2, 0x080000000, Math.PI, 0x100000000, Number.MIN_SAFE_INTEGER, -0, 0, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, Number.MAX_VALUE, 1, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, -0x100000001, -0x0ffffffff, 2**53, 42, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-451211*/count=627; tryItOut("o2.o1.e0.add(o2.g1);");
/*fuzzSeed-451211*/count=628; tryItOut("\"use strict\"; m1.get(v1);");
/*fuzzSeed-451211*/count=629; tryItOut("print((4277));");
/*fuzzSeed-451211*/count=630; tryItOut("\"use strict\"; (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function shapeyConstructor(lezogk){\"use strict\"; return this; }, delete: function(name) { return delete x[name]; }, fix: function(q) { return q; }, has: function (window, b)c, hasOwn: eval, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; }).prototype || eval.prototype;");
/*fuzzSeed-451211*/count=631; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! (Math.atan2((mathy4((((y | 0) ? (y | 0) : (x | 0)) | 0), y) >>> 0), Math.hypot(( + Math.imul(( + x), ( - x))), ( ~ Math.max((y >>> 0), Math.fround(( + Math.max(-0x0ffffffff, y))))))) >>> 0)); }); ");
/*fuzzSeed-451211*/count=632; tryItOut("Array.prototype.sort.call(a1, f0, o2);");
/*fuzzSeed-451211*/count=633; tryItOut("/*infloop*/while((arguments.callee.arguments = x)){v2 + m1; }");
/*fuzzSeed-451211*/count=634; tryItOut("");
/*fuzzSeed-451211*/count=635; tryItOut("/*MXX2*/g0.Date.prototype.toLocaleDateString = g1.f0;");
/*fuzzSeed-451211*/count=636; tryItOut("this.v2 = (b0 instanceof t0);");
/*fuzzSeed-451211*/count=637; tryItOut("\"use strict\"; Object.defineProperty(this, \"o2.v2\", { configurable: false, enumerable: x,  get: function() {  return t2.byteLength; } });\nvar bsslzw = new SharedArrayBuffer(12); var bsslzw_0 = new Int16Array(bsslzw); print(bsslzw_0[0]); bsslzw_0[0] = -16; a1 = Array.prototype.slice.call(a0, NaN, -2, g2);for (var v of o1.g1.e0) { p1 = o1.m2.get(a0); }throw -0;\nMath.pow(2805624654, (-24 || window));\n\u000c\n");
/*fuzzSeed-451211*/count=638; tryItOut("\"use strict\"; v0 = evalcx(\"Object.defineProperty(this, \\\"f0\\\", { configurable: (x % 12 == 1), enumerable: (x % 2 == 1),  get: function() {  return (function() { for (var j=0;j<8;++j) { f1(j%2==0); } }); } });\", o1.g2);");
/*fuzzSeed-451211*/count=639; tryItOut("/*infloop*/L: for (var Date.prototype.getUTCMonth of yield Boolean()) switch((new ({ set window(x = this) { \"use strict\"; /*MXX1*/const o2 = o1.g1.Proxy.length; } ,  set x()(x%=/(?:\\D)([^])|(.){1}{2,6}/gm) })())) { case 6: break; default: v1 = r2.test;break; o0.m0.set(s0, this.p1); }");
/*fuzzSeed-451211*/count=640; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (Math.log(Math.atanh((mathy1((Math.exp((Math.asin((x - y)) >>> 0)) | 0), ( + (Math.acos((((2**53 | (y >>> 0)) >>> 0) >>> 0)) >>> 0))) | 0))) !== ( + ((((Math.imul(Math.min(( + ((0x100000001 | 0) ? ( + 0.000000000000001) : Math.fround(Math.round(Math.fround(x))))), ( ~ x)), y) | 0) >>> 0) - (( - (Math.pow(( + y), x) >= (y ? Math.fround((Math.fround(Math.min(Number.MAX_SAFE_INTEGER, Math.fround(x))) - Math.fround(y))) : 0x080000001))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0/0, 0x0ffffffff, -0x0ffffffff, 1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000001, 2**53, 42, -(2**53+2), 0, -0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 2**53+2, 0x100000000, 0x07fffffff, -1/0, 1, 0.000000000000001, -(2**53-2), -0x07fffffff, 0x080000000, -0x100000001, -(2**53), -0, -Number.MAX_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-451211*/count=641; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1/0, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000001, 42, 0x080000001, -0x100000001, -0x080000000, -0x07fffffff, 0x080000000, -(2**53-2), 0, -0x0ffffffff, Math.PI, 2**53-2, 0.000000000000001, 0/0, -Number.MIN_VALUE, -1/0, -(2**53+2), 2**53, -Number.MIN_SAFE_INTEGER, 1, -(2**53), 0x100000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 0x0ffffffff, 0x100000000, -0]); ");
/*fuzzSeed-451211*/count=642; tryItOut("let (zdcqlp, y = Math.pow(29, --(y)), [{x}] = this, grtodr) { /*tLoop*/for (let c of /*MARR*/[x, x, undefined, 1e+81, x, x, x, 1e+81, x, 1e+81, 1e+81, undefined, x, x, 1e+81, x, 1e+81, undefined, undefined, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, undefined, undefined, 1e+81, undefined, undefined, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, undefined, 1e+81, undefined, 1e+81, 1e+81, 1e+81, undefined]) { g0.v1 = g0.eval(\"/*ODP-1*/Object.defineProperty(g1.s0, -5, ({configurable: (x % 6 == 1), enumerable: true}));\");\n/*hhh*/function ufuqxh(y = /*FARR*/[...[], window, false].sort){s0 += s0;}ufuqxh();\n } }");
/*fuzzSeed-451211*/count=643; tryItOut("mathy0 = (function(x, y) { return ((Math.log1p(Math.cos((y || y))) | 0) != Math.cosh(( + (( - (Math.log1p((((Math.max(-Number.MIN_VALUE, y) >>> 0) + (((y != x) >>> 0) >>> 0)) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy0, [0x100000000, -0x07fffffff, 0x0ffffffff, -(2**53-2), Math.PI, -0x080000001, -Number.MAX_VALUE, -0x080000000, 2**53+2, 1, 2**53-2, 0.000000000000001, -0, 2**53, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, 1/0, 0x080000000, -0x0ffffffff, -0x100000001, Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, -(2**53+2), 0]); ");
/*fuzzSeed-451211*/count=644; tryItOut("this.f2(e2);");
/*fuzzSeed-451211*/count=645; tryItOut("testMathyFunction(mathy3, /*MARR*/[eval, Infinity, (0x50505050 >> 1), eval, (0x50505050 >> 1), (-1/0), eval, (-1/0), Infinity, eval, Infinity, (-1/0), eval, (-1/0), (-1/0), (-1/0), Infinity, (-1/0), eval, (-1/0), (-1/0), (0x50505050 >> 1), (0x50505050 >> 1), (-1/0), eval, Infinity, Infinity, (-1/0), Infinity, eval, Infinity, (0x50505050 >> 1), Infinity, Infinity, (-1/0), (0x50505050 >> 1), (0x50505050 >> 1), Infinity, (0x50505050 >> 1), (-1/0), eval, (0x50505050 >> 1), (-1/0), (0x50505050 >> 1), eval, (0x50505050 >> 1), (-1/0), (-1/0), Infinity, eval, (0x50505050 >> 1), Infinity, Infinity, eval, Infinity, Infinity, (-1/0), eval, (-1/0), (0x50505050 >> 1), eval, eval, (-1/0), Infinity, Infinity, (0x50505050 >> 1), (0x50505050 >> 1), (-1/0), Infinity, (-1/0), eval, (0x50505050 >> 1), Infinity, (-1/0), (-1/0), Infinity, (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), Infinity, eval, (0x50505050 >> 1), Infinity, Infinity, (-1/0), Infinity, eval, (0x50505050 >> 1), Infinity, eval, eval, (-1/0), (-1/0), eval, eval, (-1/0), Infinity, (-1/0), (0x50505050 >> 1), (0x50505050 >> 1), (-1/0), eval, eval, Infinity, (-1/0), Infinity, (0x50505050 >> 1), Infinity, eval]); ");
/*fuzzSeed-451211*/count=646; tryItOut("a1 + '';");
/*fuzzSeed-451211*/count=647; tryItOut("testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 42, -1/0, -(2**53+2), 0, -(2**53-2), 0x0ffffffff, 2**53, 0x07fffffff, 2**53-2, -0x07fffffff, -0x080000001, 0x080000001, -Number.MAX_VALUE, -0x100000000, -0x080000000, -0, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, 1/0, 0x080000000, 0.000000000000001, 1, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53), -Number.MIN_VALUE, Math.PI, -0x100000001, -0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=648; tryItOut("/*RXUB*/var r = this.r2; var s = \"\\n\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-451211*/count=649; tryItOut("mathy2 = (function(x, y) { return ( + ( - (Math.atan2((( + (y < Math.fround(x))) ? y : ((x ? ( + Math.log2(y)) : y) === Math.fround(x))), y) | 0))); }); testMathyFunction(mathy2, /*MARR*/[undefined, 0x080000000, undefined, undefined, false, false, false, undefined, 0x080000000, false, false, false, 0x080000000, undefined, undefined, 0x080000000, undefined, 0x080000000, 0x080000000, 0x080000000]); ");
/*fuzzSeed-451211*/count=650; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = \"\\ud491\\ud491\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=651; tryItOut("a1.pop();");
/*fuzzSeed-451211*/count=652; tryItOut("/*ADP-2*/Object.defineProperty(a1, 16, { configurable: (x % 2 == 1), enumerable: false, get: (function mcc_() { var tlvvur = 0; return function() { ++tlvvur; if (/*ICCD*/tlvvur % 6 == 3) { dumpln('hit!'); try { a1.shift(g0.g1, x, p0, (eval = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: (new Function(\"for (var v of m0) { try { (void schedulegc(g2)); } catch(e0) { } m0.toString = (function mcc_() { var qohucl = 0; return function() { ++qohucl; if (/*ICCD*/qohucl % 2 == 0) { dumpln('hit!'); /*MXX3*/g1.RegExp.input = g1.RegExp.input; } else { dumpln('miss!'); try { print(uneval(a0)); } catch(e0) { } v1 = a2.length; } };})(); }\")), defineProperty: (4277), getOwnPropertyNames: Element, delete: (Uint32Array).apply, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: (arguments.callee.caller.caller.caller).bind, iterate: undefined, enumerate: undefined, keys: function() { throw 3; }, }; })(x), Math.min(new RegExp(\"([^](?:k)|(?:[^])|\\\\W|(?=.)(?:.)*)?\", \"g\"), ([]) = (4277)))), g2.g0.o2.t2, function (e)e = e = \"\\uCB25\"(Date.prototype.setUTCMonth(window, \"\\uD0B1\"),  \"\" ), v0, p1, o1, h0); } catch(e0) { } let i0 = new Iterator(f0); } else { dumpln('miss!'); try { t0[19] = /*RXUE*//\\3\\D/gyim.exec(\"\"); } catch(e0) { } a0.splice(NaN, ({valueOf: function() { { void 0; gcslice(648357825); }return 15; }}), i1); } };})(), set: (function() { try { neuter(b0, \"same-data\"); } catch(e0) { } try { v0 = evalcx(\"v2 = evalcx(\\\"for (var v of h0) { try { /*RXUB*/var r = r2; var s = \\\\\\\"\\\\\\\\n\\\\\\\"; print(s.search(r)); print(r.lastIndex);  } catch(e0) { } try { a1 + g2.g0; } catch(e1) { } /*RXUB*/var r = r2; var s = \\\\\\\"\\\\\\\\n\\\\\\\\n\\\\\\\"; print(uneval(s.match(r))); print(r.lastIndex);  }\\\", g2.o0.g0);\", g1); } catch(e1) { } e2.has(s1); return g2.t1; }) });");
/*fuzzSeed-451211*/count=653; tryItOut("\"use strict\"; v2 = a1.length;\ncontinue ;\narguments.callee\n\n");
/*fuzzSeed-451211*/count=654; tryItOut("v2 = Object.prototype.isPrototypeOf.call(s0, s1);");
/*fuzzSeed-451211*/count=655; tryItOut("/*tLoop*/for (let y of /*MARR*/[ /x/g , (1/0), (1/0),  /x/g , (1/0),  /x/g ,  /x/g ,  /x/g ,  /x/g , (1/0), (1/0),  /x/g ,  /x/g , (1/0), (1/0), (1/0), (1/0),  /x/g , (1/0), (1/0), (1/0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (1/0), (1/0), (1/0), (1/0),  /x/g , (1/0),  /x/g ,  /x/g , (1/0),  /x/g ,  /x/g , (1/0),  /x/g ]) { m1 + p2;function b(a =  '' ) { yield true } print(y); }");
/*fuzzSeed-451211*/count=656; tryItOut("Array.prototype.forEach.call(g2.a0);function x()\"use asm\";   var NaN = stdlib.NaN;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      {\n        return +((-1.0));\n      }\n    }\n    return +((NaN));\n    return +((d0));\n  }\n  return f;this.f0(o1.m1);");
/*fuzzSeed-451211*/count=657; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[(-1/0), new Boolean(false), new Boolean(false), (-1/0), new Boolean(false), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(false), (-1/0), (-1/0), (-1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(false), (-1/0), new Boolean(false), (-1/0), (-1/0), new Boolean(false), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (-1/0), (-1/0), (-1/0), (-1/0)]); ");
/*fuzzSeed-451211*/count=658; tryItOut("/*RXUB*/var r = /(?=(?=^*)?)/im; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=659; tryItOut("{ void 0; void schedulegc(this); }");
/*fuzzSeed-451211*/count=660; tryItOut("\"use strict\"; a0 = new Array;");
/*fuzzSeed-451211*/count=661; tryItOut("\"use strict\"; a2[10] = a1;");
/*fuzzSeed-451211*/count=662; tryItOut("const this.b2 = new SharedArrayBuffer(12);");
/*fuzzSeed-451211*/count=663; tryItOut("{s1 = this.s0.charAt(true); }");
/*fuzzSeed-451211*/count=664; tryItOut("Array.prototype.push.call(g0.a0, v0, g1.g2.g1.s2, g0.s1);");
/*fuzzSeed-451211*/count=665; tryItOut("{print(uneval(f0));Math.tan }");
/*fuzzSeed-451211*/count=666; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.sinh(( ~ Math.trunc((( + (( + Math.pow((y >>> 0), (y >>> 0))) % ( + y))) >> (( ~ x) >>> 0)))))); }); ");
/*fuzzSeed-451211*/count=667; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 18446744073709552000.0;\n    var i4 = 0;\n    var d5 = 9007199254740992.0;\n    var d6 = 2199023255553.0;\n    var i7 = 0;\n    var i8 = 0;\n    d3 = (d0);\n    return (((i1)))|0;\n    /*FFI*/ff(((abs((0x27b44549))|0)), ((17.0)), ((-2097151.0)), ((-18446744073709552000.0)), ((d0)), ((((0x969ab898)) & ((0xfaf1fe1b)))));\n    (Float32ArrayView[(((((0xc1415675))-(i1))>>>(((0xffffffff) == (0xcd82ee3)))) % ((((-4611686018427388000.0) < (-1.125)))>>>(((0x39a2f702) < (0xffffffff))))) >> 2]) = ((Infinity));\n    return (((i1)-((Math.hypot(23, \u3056 = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: (Uint16Array).bind, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: Uint32Array, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: mathy1, keys: function() { throw 3; }, }; })(0), SimpleObject))))+(!(intern(new ((arguments.callee.caller.caller).bind)())))))|0;\n  }\n  return f; })(this, {ff: function(y) { return y }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0, 0/0, -Number.MAX_VALUE, -1/0, -(2**53-2), -(2**53+2), 0x080000000, -0x0ffffffff, Math.PI, Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, 2**53, 42, -Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -0x100000001, -0x07fffffff, 0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-451211*/count=668; tryItOut("mathy2 = (function(x, y) { return ( ! Math.fround((( + Math.imul(Math.fround(Math.hypot(x, (x << 2**53))), Math.fround(mathy1((mathy1((Math.clz32(Math.log(x)) >>> 0), 42) >>> 0), y)))) >> Math.hypot(Math.fround(Math.atan(Math.fround((Math.fround(x) >>> 0)))), ( + Math.min(( + Math.fround((y % (x | 0)))), ( + y))))))); }); ");
/*fuzzSeed-451211*/count=669; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ! Math.hypot(( + Math.atanh(( + Math.min((y | 0), ((Math.cosh(x) >>> 0) | 0))))), ( + ( + Math.hypot(( + (Math.log10((( + Math.abs(Math.fround(x))) | 0)) | 0)), 1))))) >>> 0); }); testMathyFunction(mathy5, [({valueOf:function(){return '0';}}), (new String('')), (new Boolean(false)), null, /0/, NaN, false, undefined, objectEmulatingUndefined(), (new Number(-0)), 0, '0', [0], ({toString:function(){return '0';}}), '\\0', 0.1, 1, true, (new Number(0)), '', [], (new Boolean(true)), (function(){return 0;}), ({valueOf:function(){return 0;}}), -0, '/0/']); ");
/*fuzzSeed-451211*/count=670; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -562949953421313.0;\n    var i3 = 0;\n    {\n      {\n        i3 = (-0x590ceb4);\n      }\n    }\n    d2 = (511.0);\n    d2 = (6.189700196426902e+26);\n    {\n      switch (((((-0x8000000))*-0x64203) << ((0xfacebaff)+(0x26a2075f)+(0x418a7b40)))) {\n        case -2:\n          d2 = ((281474976710657.0) + (-2.0));\n          break;\n        case -1:\n          i3 = (0xa3444532);\n          break;\n      }\n    }\n    return ((-(i1)))|0;\n    d2 = (d2);\n    {\n      switch (((-0xc0293*(i3)) & ((i1)))) {\n        case 1:\n          i3 = ((~((!((i3) ? ((((-0x8000000))>>>((0xffffffff))) < (((0xfa5cac03))>>>((0xfc6db3f1)))) : ((((0xffffffff)) << ((0xffffffff))))))-(0x6c0906dd))));\n          break;\n        case 1:\n          i3 = ((((((i1))>>>(((0x7ecac1a4))+(-0x8000000)))) ? (+/*FFI*/ff(((((i3)+(!(0xf97349ea))) >> (((void options('strict')))))), ((Infinity)), ((((0xb915a87e)) ^ ((0xfcdcff1a)))), ((2049.0)), ((8388608.0)), ((-562949953421313.0)))) : (-18014398509481984.0)) > ((((0xfde8ca7f) ? (16777217.0) : ((0x8732dac7) ? (1099511627776.0) : (513.0)))) % ((Float64ArrayView[2]))));\n        case 1:\n          i1 = (/*FFI*/ff((((4.0) + (d2))))|0);\n          break;\n        case -3:\n          i0 = ((Math.expm1(23)));\n          break;\n      }\n    }\n    {\n      (Float32ArrayView[(((!((0xe8dac0d3) >= (0xcbae2641))) ? (0xfbe8042f) : (i3))-(0xa8eb32be)) >> 2]) = (((i1) ? (-1.03125) : ((137438953471.0) + (((+(1.0/0.0)) + (((-524287.0)) * ((-147573952589676410000.0)))) + (+(((0xffc268ad))>>>((0x5c51ed36))))))));\n    }\n    i0 = (((+(1.0/0.0))));\n    d2 = (8388609.0);\n    return (((((abs((0x6940e07d))|0) / (0x5b8bc86a))>>>((Math.pow(-25, 17)).yoyo(d = ((makeFinalizeObserver('nursery'))).unwatch(\"c\")))) % (0xffffffff)))|0;\n  }\n  return f; })(this, {ff: allocationMarker()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Math.PI, 0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, 2**53-2, 2**53, Number.MAX_VALUE, 0x080000001, 0x0ffffffff, 42, Number.MIN_VALUE, 2**53+2, -0x07fffffff, -0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, -1/0, -(2**53-2), 1, 0.000000000000001, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-451211*/count=671; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.min((mathy0((y * (1.7976931348623157e308 >>> 0)), x) > Math.hypot(Math.cosh(( + mathy0(( + x), ( + x)))), (y >>> 0))), (Math.hypot((Math.acosh(0/0) | 0), ( + ( ~ ( + x)))) | 0)) | ( ! Math.asin(((Math.imul(y, ((0/0 ? x : ( + (Math.sinh((Math.PI >>> 0)) >>> 0))) >>> 0)) | 0) >>> 0)))); }); ");
/*fuzzSeed-451211*/count=672; tryItOut("testMathyFunction(mathy0, [true, false, 0, '', ({toString:function(){return '0';}}), 1, (new String('')), -0, /0/, [], '\\0', '/0/', undefined, NaN, ({valueOf:function(){return 0;}}), '0', (new Boolean(true)), null, 0.1, objectEmulatingUndefined(), (function(){return 0;}), (new Number(0)), [0], (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(-0))]); ");
/*fuzzSeed-451211*/count=673; tryItOut("\"use strict\"; a0.forEach();");
/*fuzzSeed-451211*/count=674; tryItOut("s2 += s1;");
/*fuzzSeed-451211*/count=675; tryItOut("\"use strict\"; s1 = new String;");
/*fuzzSeed-451211*/count=676; tryItOut("\"use strict\"; v2 = a1.length;");
/*fuzzSeed-451211*/count=677; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.sinh(Math.min(( + mathy0((( + Math.min(x, Math.atan2(x, -(2**53)))) / (Math.pow(x, -Number.MIN_SAFE_INTEGER) | 0)), (Math.imul(( + (mathy0((Math.sin((0x080000000 | 0)) | 0), (0x080000000 | 0)) | 0)), ( + ( + Math.cos(x)))) >>> 0))), (Math.fround(( ~ ((Math.sin((x >>> 0)) >>> 0) % Math.ceil(Math.fround(-0x100000001))))) || Math.min(y, Math.fround(-(2**53)))))); }); testMathyFunction(mathy2, [Math.PI, -0x0ffffffff, 2**53-2, -0x080000001, -(2**53+2), Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, 42, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, 2**53+2, 0x0ffffffff, -0, 1, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, -0x100000001, 0x100000001, 1/0, 2**53, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, 0/0, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-451211*/count=678; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.expm1((( ~ Math.imul(( + ( + x)), ( + Math.hypot(0x080000001, x)))) >>> 0))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, Math.PI, 42, -(2**53-2), -0, -0x080000001, -0x07fffffff, 1/0, 2**53-2, -(2**53), -0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, 2**53+2, 0, 0x100000001, -0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, -0x100000000, 1, 0x0ffffffff, 0x100000000, -1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=679; tryItOut("o2.s0.toString = (function() { try { v2 = f2[new String(\"13\")]; } catch(e0) { } try { m0.delete(o1.v0); } catch(e1) { } try { s0 + ''; } catch(e2) { } e0 = new Set; return t2; });");
/*fuzzSeed-451211*/count=680; tryItOut("/*oLoop*/for (let hwarnc = 0; hwarnc < 31; ++hwarnc) { /*oLoop*/for (let xlsrrd = 0; xlsrrd < 11; ++xlsrrd) { \"\\uF833\"; }  } ");
/*fuzzSeed-451211*/count=681; tryItOut("/*ADP-2*/Object.defineProperty(this.a1, 8, { configurable: (runOffThreadScript), enumerable: false, get: (function() { try { m1.set(m1, h2); } catch(e0) { } try { g1.g2.o0.e0.toSource = (function mcc_() { var vhplpv = 0; return function() { ++vhplpv; if (false) { dumpln('hit!'); try { e0.delete(s0); } catch(e0) { } try { this.v1 = true; } catch(e1) { } try { t0[v2] = m1; } catch(e2) { } Array.prototype.shift.call(a0); } else { dumpln('miss!'); try { a2.pop(); } catch(e0) { } s2 = s2.charAt(6); } };})(); } catch(e1) { } /*MXX1*/o0 = g1.String.prototype.lastIndexOf; return t2; }), set: (function() { try { /*MXX3*/g2.Map.prototype.constructor = g2.Map.prototype.constructor; } catch(e0) { } try { /*RXUB*/var r = r2; var s = \"\\n\"; print(uneval(r.exec(s)));  } catch(e1) { } v2 = r0.multiline; return o0; }) });");
/*fuzzSeed-451211*/count=682; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(Math.imul((Math.imul((( + Math.exp(( + (Math.sign((x | 0)) | 0)))) >>> 0), Math.atan2(Math.sqrt(x), x)) >>> 0), ( - Math.fround(Math.ceil(Math.fround(-0x100000000)))))), Math.fround((Math.atan(( + Math.fround(( ~ (((Math.atanh(x) ? ( + x) : 1) , y) | 0))))) >>> 0)))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 0, 0x100000000, 2**53+2, 0x0ffffffff, -1/0, 0/0, Number.MIN_SAFE_INTEGER, -0, 0x080000001, 42, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -0x100000001, 0x100000001, -0x080000000, -0x100000000, Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, Number.MIN_VALUE, 1, 1/0, 0x07fffffff, -(2**53+2), 2**53-2, -0x080000001, -(2**53)]); ");
/*fuzzSeed-451211*/count=683; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(( ~ Math.fround(Math.log2((( ! ((( ~ (y | 0)) !== ( + 1)) | 0)) | 0))))); }); ");
/*fuzzSeed-451211*/count=684; tryItOut("\"use asm\"; Object.defineProperty(this, \"v0\", { configurable: false, enumerable: false,  get: function() {  return this.t0.length; } });");
/*fuzzSeed-451211*/count=685; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=686; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=687; tryItOut("Array.prototype.unshift.call(g0.a0, s0);");
/*fuzzSeed-451211*/count=688; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=689; tryItOut("mathy0 = (function(x, y) { return (( ~ (Math.log1p((Math.fround(x) & Math.cosh(y))) | 0)) ? ( + Math.fround(( + ( + Math.hypot(( + Math.exp(Math.fround(y))), ( + ((( + Math.trunc(2**53-2)) || (( ! (x | 0)) >>> 0)) >>> 0))))))) : (Math.atan2(Math.sin(1.7976931348623157e308), ((Math.fround((( - ((Math.abs((x | 0)) | 0) >>> 0)) | 0)) / (Math.fround(( - ((Math.fround(y) <= x) <= y))) >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy0, [-0x080000000, 0x080000000, 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, -0x0ffffffff, 1/0, -Number.MAX_VALUE, -1/0, 1, -(2**53), 0, 2**53+2, 1.7976931348623157e308, 0x080000001, 0x100000000, -0x100000000, 0x100000001, Math.PI, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 2**53, 0.000000000000001, 0/0]); ");
/*fuzzSeed-451211*/count=690; tryItOut("/*infloop*/for(e in ((arguments.callee)(x))){g0.g2.v0 = (a2 instanceof m2); }");
/*fuzzSeed-451211*/count=691; tryItOut("a0.reverse(f2);");
/*fuzzSeed-451211*/count=692; tryItOut("s2.toSource = x;");
/*fuzzSeed-451211*/count=693; tryItOut("for (var v of p1) { Object.preventExtensions(b0); }");
/*fuzzSeed-451211*/count=694; tryItOut("\"use strict\"; ");
/*fuzzSeed-451211*/count=695; tryItOut("/*RXUB*/var r = /^/g; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-451211*/count=696; tryItOut("\"use strict\"; for (var v of t2) { a2.splice(v1); }");
/*fuzzSeed-451211*/count=697; tryItOut("/*tLoop*/for (let c of /*MARR*/[(1/0),  '' , new Boolean(false), (1/0), new Boolean(false), (void 0), x <= \u3056 in x == x, (void 0), (void 0), (1/0), (void 0),  '' ,  '' , new Boolean(false), (void 0), new Boolean(false), x <= \u3056 in x == x, x <= \u3056 in x == x, new Boolean(false), x <= \u3056 in x == x, new Boolean(false), (void 0), new Boolean(false), x <= \u3056 in x == x,  '' ,  '' , x <= \u3056 in x == x, new Boolean(false), x <= \u3056 in x == x, (void 0), new Boolean(false), (1/0),  '' ,  '' , (void 0), x <= \u3056 in x == x, (1/0), (1/0), (1/0), (void 0),  '' ,  '' , (void 0), (void 0), (void 0), (void 0), (1/0), new Boolean(false), (void 0), x <= \u3056 in x == x,  '' , (1/0), x <= \u3056 in x == x, (void 0), (void 0), (void 0),  '' , x <= \u3056 in x == x, new Boolean(false), x <= \u3056 in x == x, new Boolean(false),  '' , (1/0),  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , new Boolean(false), (1/0),  '' , (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), x <= \u3056 in x == x, (1/0),  '' , x <= \u3056 in x == x, x <= \u3056 in x == x, x <= \u3056 in x == x, x <= \u3056 in x == x,  '' , x <= \u3056 in x == x,  '' , (1/0), x <= \u3056 in x == x, (1/0)]) { print(c); }");
/*fuzzSeed-451211*/count=698; tryItOut("o2.g0.offThreadCompileScript(\"print(uneval(p0));\");");
/*fuzzSeed-451211*/count=699; tryItOut("(({\"-21\": ( /* Comment */\"\\u8014\"), \"-14\": (z++) }));");
/*fuzzSeed-451211*/count=700; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -32769.0;\n    d2 = (((+(0.0/0.0))) - ((d1)));\n    {\n      d1 = (((+(1.0/0.0))) - ((d1)));\n    }\n    (Float32ArrayView[((0xfe386e1e)) >> 2]) = (((0x9d3515cd) ? (+(1.0/0.0)) : (d0)));\n    d0 = (+abs((('fafafa'.replace(//*\n*/a/g, function(y) { e2.add(length); })))));\n    {\n      (Int32ArrayView[((/*FFI*/ff(((((((0xd278562c))|0) % (abs((0x61aa4015))|0)) ^ (((9.671406556917033e+24) != (3.022314549036573e+23))+(0x20eda2d8)+((0x92bc6198) == (0x23a7ef05))))), ((d2)), ((~~(+/*FFI*/ff(((((-0x8000000))|0)), ((4097.0)), ((-18446744073709552000.0)), ((-3.094850098213451e+26)), ((-295147905179352830000.0)), ((9223372036854776000.0)), ((-2097151.0)), ((-17179869184.0)), ((-35184372088833.0)), ((1.2089258196146292e+24)), ((16385.0)), ((3.0)), ((-147573952589676410000.0)))))))|0)) >> 2]) = (-(((0xcfe2fbde)) ? (0xfdcb0acf) : ((((~~(-4194305.0)) % (((0xf8766990)) << ((0xffffffff)))) >> ((0x36deb29d)-(/*FFI*/ff()|0)-(0x55e6e620))))));\n    }\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: function (e)( /* Comment */21)}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-451211*/count=701; tryItOut("");
/*fuzzSeed-451211*/count=702; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-451211*/count=703; tryItOut("\"use asm\"; /*infloop*/for(var x; b = Proxy.createFunction(x(this), y); new Uint8ClampedArray(false, ({a1:1}))) {/*RXUB*/var r = r2; var s = \"\"; print(s.search(r)); print(r.lastIndex); o0.p1.valueOf = (function mcc_() { var mxbqpk = 0; return function() { ++mxbqpk; if (/*ICCD*/mxbqpk % 8 == 0) { dumpln('hit!'); try { v1 = g1.eval(\"function f1(v0)  { return this } \"); } catch(e0) { } try { v2 = evalcx(\"/* no regression tests found */\", g1); } catch(e1) { } try { e1.add(g2.b0); } catch(e2) { } for (var v of p0) { try { for (var p in o2) { e0 + i1; } } catch(e0) { } a0.reverse(/(?!\\s+?|.+|(?!(?=(?:\\cR)+)){4,})/gim, f1); } } else { dumpln('miss!'); try { a1 = arguments; } catch(e0) { } print(v1); } };})(); }");
/*fuzzSeed-451211*/count=704; tryItOut("\"use strict\"; for (var v of g2) { e2.add(o1.b2); }");
/*fuzzSeed-451211*/count=705; tryItOut("\"use strict\"; this.e0.delete(((Array.prototype.includes).call)());/*RXUB*/var r = new RegExp(\"(?!\\\\1)|$?|[\\u009c\\\\cX-\\u00d5\\\\n-\\\\x65\\\\w]\\\\2+??\", \"y\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-451211*/count=706; tryItOut("\"use strict\"; h0 = this.m2.get(b1);((new WebAssemblyMemoryMode((Math.atan2(null, true)))));");
/*fuzzSeed-451211*/count=707; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -140737488355327.0;\n    /*FFI*/ff(((-590295810358705700000.0)));\n    i1 = (/*FFI*/ff()|0);\n    i1 = ((0x4c355a07));\n    d2 = (+(0x3f0712ea));\n    return ((((0x59396452))))|0;\n  }\n  return f; })(this, {ff: (function (eval) { yield (((function(x, y) { return y; }))(-0x080000001)) } ).bind()}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-451211*/count=708; tryItOut("\"use strict\"; o0 = new Object;");
/*fuzzSeed-451211*/count=709; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=710; tryItOut("neuter(b0, \"change-data\");");
/*fuzzSeed-451211*/count=711; tryItOut("mathy2 = (function(x, y) { return (( + Math.fround(( - ((Math.max(((x ? y : (x >>> 0)) , (( - x) >>> 0)), (Math.fround(( ! Math.fround(x))) % ( + ( ! ( + y))))) << y) ? ( - mathy0(x, 0x080000000)) : ( + (x < -(2**53-2))))))) ? ( + (mathy1(x, -0x100000001) ? ( + Math.sqrt(Math.sinh(-0x080000001))) : Math.fround((Math.hypot((( ! (-(2**53+2) | 0)) | 0), (0x0ffffffff | 0)) | 0)))) : (Math.round(( ! ( - Math.hypot((( ! (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0), x)))) | 0)); }); testMathyFunction(mathy2, [-0x0ffffffff, Math.PI, 0/0, 0x07fffffff, 2**53-2, -0x07fffffff, 0x080000000, 1, -(2**53-2), 2**53, -0x100000000, -0, -(2**53), -Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, 0, 1/0, 0x100000001, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, 0.000000000000001, 0x080000001, -0x080000000, 2**53+2, -(2**53+2), 0x0ffffffff]); ");
/*fuzzSeed-451211*/count=712; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((((((( + ( - Math.ceil(-Number.MIN_VALUE))) <= (2**53-2 | 0)) | 0) % Math.fround(0x080000000)) >>> 0) % mathy1((((-Number.MAX_VALUE + (x ? -0x080000001 : -Number.MIN_SAFE_INTEGER)) << y) | 0), Math.fround(Math.hypot(mathy1(1/0, y), x)))) >>> 0) || Math.tan(Math.log2(-(2**53+2)))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), (new Boolean(false)), NaN, 1, [], [0], '\\0', (new Number(-0)), true, '', -0, undefined, (function(){return 0;}), '0', /0/, (new String('')), false, 0.1, (new Number(0)), null, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), 0, ({valueOf:function(){return 0;}}), '/0/', (new Boolean(true))]); ");
/*fuzzSeed-451211*/count=713; tryItOut("\"use strict\"; ;");
/*fuzzSeed-451211*/count=714; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.trunc(((( ! x) ? (( + (y >>> 0)) | 0) : Math.min(mathy0(Math.fround(y), ( + ( + ( ~ x)))), Math.fround(Math.acosh(Math.fround(y))))) | 0)); }); testMathyFunction(mathy2, /*MARR*/[NaN, NaN, [1]]); ");
/*fuzzSeed-451211*/count=715; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((mathy0(Math.fround(Math.log1p(Math.fround(Math.atan2((Math.fround(Math.max(Number.MIN_VALUE, Math.fround(-Number.MIN_SAFE_INTEGER))) | 0), Math.fround(x))))), Math.fround(Math.max((Math.fround((Math.fround(y) != Math.fround((mathy0((((y * y) >>> 0) | 0), (y | 0)) | 0)))) | y), Math.min(y, ( + mathy0(( + y), ( + y))))))) | 0) % ((Math.sin(((Math.ceil(((x >>> 0) - (mathy0(x, x) < -1/0))) ? 2**53-2 : y) | 0)) | 0) >>> 0)); }); ");
/*fuzzSeed-451211*/count=716; tryItOut("o1.e1.__proto__ = h0;");
/*fuzzSeed-451211*/count=717; tryItOut("y = 5;print(23)\n/* no regression tests found */");
/*fuzzSeed-451211*/count=718; tryItOut("\"use strict\"; t0.set(a2, true);");
/*fuzzSeed-451211*/count=719; tryItOut("\"use strict\"; g1.v2 = (m2 instanceof p2);");
/*fuzzSeed-451211*/count=720; tryItOut("\"use strict\"; Array.prototype.splice.call(a2, NaN, v2, this.o2);");
/*fuzzSeed-451211*/count=721; tryItOut("\"use strict\"; let (b) { v0 = evalcx(\"function f2(i1) \\\"use asm\\\";   var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    i0 = (((Int16ArrayView[((0xffffffff)+(0xbb43d10f)) >> 1])) ? ((((1)-(0x7d2b3edb)) | ((i0)-(i0)))) : ((d1) >= (8193.0)));\\n    return +((d1));\\n  }\\n  return f;\", g2); }");
/*fuzzSeed-451211*/count=722; tryItOut("m1.set(this.i2, m0);/*oLoop*/for (var liexox = 0; liexox < 40; ++liexox) { print(x); } ");
/*fuzzSeed-451211*/count=723; tryItOut("mathy2 = (function(x, y) { return (Math.hypot((( - Math.fround((( ! (mathy1(Math.fround(y), (Math.hypot(Math.fround(x), ( + x)) >>> 0)) >>> 0)) >>> 0))) | 0), (Math.hypot(((Math.expm1((Math.fround(Math.tan(Math.fround((Math.max(( + x), (x >>> 0)) >>> 0)))) | 0)) | 0) | 0), (Math.fround((mathy0(y, (x | 0)) <= Math.fround(x))) | 0)) >>> 0)) == Math.hypot(( - Math.max(-(2**53), ( + (Math.expm1(((((-(2**53-2) >>> 0) ^ (y >>> 0)) >>> 0) | 0)) | 0)))), (( + (mathy0(y, (( + mathy0(( + Math.PI), ( + y))) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy2, [1.7976931348623157e308, -0x100000000, 1/0, Number.MAX_SAFE_INTEGER, -0, Math.PI, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, 2**53, 2**53+2, -(2**53-2), -0x100000001, -(2**53+2), Number.MAX_VALUE, 2**53-2, 0x080000001, -Number.MAX_VALUE, 0.000000000000001, 0x100000000, 0x080000000, -0x07fffffff, -0x080000000, -(2**53), 0/0, 42, 0x07fffffff, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-451211*/count=724; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ ( ! Math.imul((x | 0), x))); }); testMathyFunction(mathy2, [-0x080000001, 2**53, -0x100000000, 0x0ffffffff, -0x080000000, -(2**53), 0x100000001, 0x080000001, 1/0, -0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -(2**53-2), 1, 2**53+2, 0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, 0.000000000000001, -(2**53+2), 42, Number.MAX_VALUE, 0x07fffffff, 2**53-2, 0/0, 0x080000000]); ");
/*fuzzSeed-451211*/count=725; tryItOut("e1.has(m2);");
/*fuzzSeed-451211*/count=726; tryItOut("mathy4 = (function(x, y) { return ( ! mathy2(Math.fround(( - ( + (Math.cbrt(y) & -(2**53-2))))), (Math.asinh((Math.asin(Math.fround(Math.pow(Math.cbrt(((x ^ x) | 0)), ( + y)))) | 0)) | 0))); }); testMathyFunction(mathy4, [0/0, Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, -1/0, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), 0x100000001, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53, -0x080000001, 42, -0x100000001, 0x100000000, -(2**53+2), 1.7976931348623157e308, -0x07fffffff, 0x080000000, 1, 2**53+2, -(2**53-2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, Number.MIN_VALUE, 1/0, 2**53-2]); ");
/*fuzzSeed-451211*/count=727; tryItOut("mathy5 = (function(x, y) { return (Math.acosh(mathy0(Math.atan2(((Math.pow(( + (Math.ceil((( ! x) | 0)) | 0)), ( + mathy1(( + y), ( + x)))) >>> 0) | 0), -(2**53+2)), (( + Math.sign(2**53+2)) > y))) | 0); }); testMathyFunction(mathy5, [-(2**53+2), 0x080000000, Math.PI, 0.000000000000001, -(2**53), 0/0, 2**53+2, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -0x100000000, Number.MIN_VALUE, -(2**53-2), -1/0, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 0x100000001, 1, 42, 0x100000000, 2**53-2, 2**53, -0x100000001, 0, -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, 1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=728; tryItOut("Array.prototype.splice.apply(a2, [o2]);");
/*fuzzSeed-451211*/count=729; tryItOut("/*bLoop*/for (var fpqvbm = 0, z = x, 1; fpqvbm < 36; ++fpqvbm) { if (fpqvbm % 29 == 12) { Array.prototype.pop.apply(a1, []); } else { ('fafafa'.replace(/a/g, ({/*TOODEEP*/}))); }  } ");
/*fuzzSeed-451211*/count=730; tryItOut("print(x);");
/*fuzzSeed-451211*/count=731; tryItOut(" /x/ ;function w(x = [1](), x, eval, x, x = this, d, x, y = null, x =  \"\" , x, x, x, \u3056, d, eval = this, x, \"0\") { \"use strict\"; return false } b1 + '';function w(c, x, new SimpleObject(x, timeout(1800)).valueOf(\"number\"), x, x, w, Date.prototype.setUTCHours = ([]) = 10 in d, x, b, eval, b, x, x = /[\\w\\uA536\u00b4-\uda31].[\\w]+?|\\u0035*|(?!\\B){4,}\\2|\\W{1,}{268435456}|\\1|\\S|\u5c15[^]{3}|([\\W\\s\\u0075]+)|\\s/gym, a, z, x, x, x, y, \u3056, eval, toFixed, w, x, x = new RegExp(\"(?=\\\\3.+?|[^](?=.|\\u7412\\\\n)\\\\1(?=(?:$)){2}|\\\\d^(?:})(?=[^\\\\d\\\\d])?)\", \"gyi\"), a = \"\\uB39A\", c, NaN, y, eval = {}, x = length, x, x = true, e, a, c, NaN = arguments, b, eval, d, x, x, x = -18, x, e, a, eval, x, e, d, a, x, c, eval =  /x/ , window) { \"use strict\"; { void 0; minorgc(true); } } this.a1.unshift(e0, g2.t2, o2.t1, b0, o2.b0, v1, t2, o2.o1, ((void shapeOf(x))), p0);");
/*fuzzSeed-451211*/count=732; tryItOut("\"use strict\"; print(uneval(this.i0));");
/*fuzzSeed-451211*/count=733; tryItOut("v0 = (h1 instanceof b1);function x(z = (b--).yoyo(x)) { print(b = e = 22); } /*MXX2*/o2.g2.g1.Uint8Array.prototype.BYTES_PER_ELEMENT = o2.m1;");
/*fuzzSeed-451211*/count=734; tryItOut("v1 = g0.t1.byteLength;b0.__proto__ = g0;");
/*fuzzSeed-451211*/count=735; tryItOut("v0 = Array.prototype.reduce, reduceRight.apply(a2, [(function(j) { if (j) { print(uneval(this.i0)); } else { try { o0.v1 = o1.t2.byteLength; } catch(e0) { } try { h0.hasOwn = f2; } catch(e1) { } t0[17]; } }), i2, g0, t2, g2, b0])\n/*infloop*/M:while(x)/*vLoop*/for (var lfsgbp = 0; lfsgbp < 58; ++lfsgbp) { let a = lfsgbp; /*infloop*/for(let d in Math) s1 += s0; } ");
/*fuzzSeed-451211*/count=736; tryItOut("/*ODP-1*/Object.defineProperty(e0, \"getUTCHours\", ({enumerable: (x % 17 == 9)}));");
/*fuzzSeed-451211*/count=737; tryItOut("v0 = a0.length;");
/*fuzzSeed-451211*/count=738; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.min(Math.pow(x, Math.fround(( ~ Math.fround(( + Math.log(( + ((Math.max(x, (x | 0)) | 0) ? ( + -0x07fffffff) : y)))))))), (Math.pow(Math.tan((( - ( ~ x)) >>> 0)), ((Math.atan2(x, Math.fround(y)) >>> 0) >>> 0)) >>> 0)) >>> (Math.asin(( + (( + -Number.MIN_SAFE_INTEGER) >> ( + (((x >>> 0) != mathy0(( - -0x080000001), ( + (( + x) === y)))) >>> 0))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-451211*/count=739; tryItOut("\"use strict\"; x.name;let(b = (4277)) ((function(){return;})());");
/*fuzzSeed-451211*/count=740; tryItOut("v0 = o1.b0.byteLength;");
/*fuzzSeed-451211*/count=741; tryItOut("print(undefined);");
/*fuzzSeed-451211*/count=742; tryItOut("\"use strict\"; let this.g0.g2.v1 = Array.prototype.every.call(g0.a2, ((4277) && new function(y) { return  }((x = /(?!(?=^{0,})){0}/gyi))));");
/*fuzzSeed-451211*/count=743; tryItOut("e0 = new Set(e1);");
/*fuzzSeed-451211*/count=744; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return ( + (( + ((Math.sin((Math.atan2(((( + y) >> x) | 0), (Math.hypot(x, (Math.fround(Math.imul((y >>> 0), (2**53 | 0))) >>> 0)) >>> 0)) | 0)) | 0) / (Math.max(-(2**53-2), (( ! ( + ( + ( + x)))) | 0)) | 0))) < ( + Math.max(( + (( + Math.imul((y | 0), x)) >>> 0)), ((((Math.atanh((((((Math.exp((( + y) >>> 0)) >>> 0) >>> 0) + Math.fround(Math.imul(y, Math.fround(Math.atan2(y, y))))) >>> 0) >>> 0)) >>> 0) >>> 0) >= ((Math.atan2(Math.tanh(42), ( + Math.imul(x, Math.fround(x)))) | 0) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-451211*/count=745; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(mathy0(mathy0(((y - (x ? x : ( + (y !== -0x100000000)))) != Math.fround(Math.max((( ! (x | 0)) >>> 0), y))), y), (((( ~ Math.fround((Math.fround(( + ( - ( + -(2**53))))) ? Math.fround(y) : Math.fround(y)))) >>> 0) >> ( + Math.log10(Math.fround((Math.abs(Math.atan2(x, 2**53)) >>> 0))))) | 0)), Math.asinh(Math.atanh(y))); }); testMathyFunction(mathy1, /*MARR*/[function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=746; tryItOut("\"use strict\"; print(this);function d(x = null, x, x, z, w, x, x, NaN, x, w =  \"\" , d, setter, NaN = false, window = length, x, x, z, \u3056, w =  '' , \u3056 = d, e, x, x, NaN = \"\\uD2C6\", x, x, eval, d, c, b, x = \"\\u3555\", x, x = 18, a, x, x, window, b = this, d, b, x, x, x, x, x = [,], w, x =  '' , eval, x, NaN = ({a2:z2}), NaN, window, NaN, a, window, w, x = \"\\uE183\", this.NaN = ({}), x, y, d, a, x, a, z, z, x, getter, x, y, x, y, c, z, y, eval, eval, d, x, w, y, \u3056 = [[]], x, x, NaN, x, y, b, d, window, x = -22, x, d, NaN =  /x/g , z, a = this) { yield  \"\" ; } 11;");
/*fuzzSeed-451211*/count=747; tryItOut("mathy4 = (function(x, y) { return Math.round(( - (((mathy2(mathy0(y, 42), Math.atan(x)) + mathy3(( ~ Math.max((0 == y), x)), 0x100000001)) | 0) >>> 0))); }); testMathyFunction(mathy4, [-0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 42, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, -1/0, 0x07fffffff, Math.PI, 0.000000000000001, 2**53-2, -0x07fffffff, -0x100000001, 0x0ffffffff, -0x080000000, 1/0, 1, Number.MAX_VALUE, 0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, Number.MIN_VALUE, -0x100000000, -0, 0x080000001, 2**53, -(2**53), 0x080000000, 1.7976931348623157e308, 0/0, -0x0ffffffff]); ");
/*fuzzSeed-451211*/count=748; tryItOut("\"use asm\"; Array.prototype.push.call(o0.a0, t1, a1);");
/*fuzzSeed-451211*/count=749; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(( + (( ~ (Math.fround(Math.hypot(Math.acos(x), Math.fround((( + x) % ( + y))))) | 0)) >>> 0))); }); testMathyFunction(mathy4, [0x07fffffff, 0.000000000000001, 2**53+2, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0, 1.7976931348623157e308, 0x080000000, -0x080000001, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, 42, 0x100000001, -0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, -0x100000001, -(2**53), 2**53-2, Number.MAX_VALUE, -(2**53+2), 0, 1/0, -0x07fffffff, 0x080000001, -Number.MAX_VALUE, 0/0, -0x080000000, 2**53, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=750; tryItOut("let(b, x = (4277), x = (void shapeOf( /x/g )) !== /*FARR*/[].filter(z.fround, (\u3056 = Proxy.createFunction(({/*TOODEEP*/})(this), Date.prototype.getDate))), w = Math.sign(yield  \"\" ), ytxzxq, qablax, \u3056, {} =  /x/g .__defineGetter__(\"x\", objectEmulatingUndefined), d = (w = -8), z = this) ((function(){let(x, c = x, fglhzm, x = x%= /x/g , {x: x, y}\u000c = x, x, xxgazx, lcqfkq, paatbj) ((function(){with({}) x.name;})());})());");
/*fuzzSeed-451211*/count=751; tryItOut("const c = allocationMarker();v1 = Object.prototype.isPrototypeOf.call(m0, m2);");
/*fuzzSeed-451211*/count=752; tryItOut("testMathyFunction(mathy3, [(function(){return 0;}), objectEmulatingUndefined(), NaN, (new Boolean(true)), (new String('')), '0', (new Number(0)), ({valueOf:function(){return 0;}}), (new Boolean(false)), -0, undefined, 0.1, [], 1, '', false, true, [0], '\\0', null, 0, ({valueOf:function(){return '0';}}), (new Number(-0)), /0/, ({toString:function(){return '0';}}), '/0/']); ");
/*fuzzSeed-451211*/count=753; tryItOut("this.i0.next();");
/*fuzzSeed-451211*/count=754; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.cos(Math.fround(( - ( ! (( + y) | 0))))); }); testMathyFunction(mathy4, [[0], ({valueOf:function(){return '0';}}), (new Boolean(true)), true, objectEmulatingUndefined(), 0.1, (new Number(-0)), '0', (new String('')), ({valueOf:function(){return 0;}}), NaN, undefined, (new Number(0)), -0, /0/, '', null, ({toString:function(){return '0';}}), false, 0, [], (function(){return 0;}), '/0/', 1, '\\0', (new Boolean(false))]); ");
/*fuzzSeed-451211*/count=755; tryItOut("s0 + o0;function x(y, a)x/*bLoop*/for (var hvwdhq = 0; hvwdhq < 162; ++hvwdhq) { if (hvwdhq % 2 == 1) { (true); } else { ( \"\" ); }  } ");
/*fuzzSeed-451211*/count=756; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=757; tryItOut("v2 = Object.prototype.isPrototypeOf.call(f0, b2);\nprint(\"\\u0352\");\n");
/*fuzzSeed-451211*/count=758; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i1 = (i1);\n    (Float32ArrayView[((i1)) >> 2]) = ((+(1.0/0.0)));\n    return (((((((~~(-1073741825.0))) <= (-536870913.0))+(i1))|0) / (((i0)+((((+(-1.0/0.0)))) < (0x0))) << (((0xb64f1b18) >= (0x4634835f))-((0x507c6b59))))))|0;\n  }\n  return f; })(this, {ff: (intern(false)).bind(/(\\S)|(?:(\\1)+?).(?!\\W)$|(?![^\\u002a-\u292b\\D][^\\d\\D\\B\\0]^|[^])*?/im)}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -(2**53), 0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -(2**53+2), 0x100000001, 0x100000000, 42, 0x080000000, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 1, -1/0, -0x100000000, 0x07fffffff, -0x080000000, 2**53, 0, 0x080000001, Number.MIN_VALUE, -0x080000001, 0/0, -0, -0x07fffffff, -0x100000001, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-451211*/count=759; tryItOut("for (var v of t0) { t1[7]; }");
/*fuzzSeed-451211*/count=760; tryItOut("{ void 0; void relazifyFunctions(); }");
/*fuzzSeed-451211*/count=761; tryItOut("\"use strict\"; if(false) {m1 = new Map(b1); } else for (var p in f0) { try { /*MXX1*/o0.o0 = g0.Date.prototype.toJSON; } catch(e0) { } try { g2.h2.delete = f2; } catch(e1) { } this.v2 = (o0 instanceof f1); }");
/*fuzzSeed-451211*/count=762; tryItOut("mathy0 = (function(x, y) { return Math.max((( + ( - Math.hypot(( ~ Math.fround(y)), Math.sinh(( + (y | 0)))))) >>> 0), Math.atan(( + (Math.fround(Math.acosh(-0x100000001)) + ( - 0x100000001))))); }); ");
/*fuzzSeed-451211*/count=763; tryItOut("g2.offThreadCompileScript(\"mathy3 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var ff = foreign.ff;\\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    return ((((0xffcfdaf1) ? (0xffffffff) : ((((0x38d62b23))>>>((0xfed2e467))) >= (0x0)))+(0xffffffff)))|0;\\n    (Uint8ArrayView[0]) = (-(0xf5fed5c9));\\n    return (((0xf8bd6d74)+(0xfba6159d)))|0;\\n  }\\n  return f; })(this, {ff: Math.max(16, -29).isPrototypeOf}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MIN_VALUE, Math.PI, -0x080000000, -0x100000000, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, 0/0, 0x100000000, -0x100000001, 1, 42, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0, 2**53, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, -(2**53+2), -(2**53-2), -0x080000001, 2**53+2, -1/0, -0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, 0x100000001, -(2**53), 0.000000000000001, 1/0, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001]); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 2 != 0), noScriptRval: (x % 16 != 14), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-451211*/count=764; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 3.0;\n    var i3 = 0;\n    d2 = (d2);\n    i3 = (i3);\n    {\n      i1 = ((((0xfdff01ad)+((((0x428178b9))>>>((0xe98a4eda))) != (((0xffffffff))>>>((-0x454cf53))))+(!((+atan2(((-63.0)), ((-6.044629098073146e+23)))) < (d2)))) << (((Uint8ArrayView[((i3)) >> 0])) / (((0x4fa90c1c)-(i0)) | ((-0x8000000))))) != (~(((((i1)+(i1))>>>(-0x68d0f*(0xa6386644))))+((i0) ? ((abs((-0x8000000))|0)) : (0x73607b1a)))));\n    }\n    i1 = (i1);\n    return +((-3.8685626227668134e+25));\n  }\n  return f; })(this, {ff: (decodeURIComponent).call}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0/0, -0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), -0x080000000, 0, 2**53-2, 0x100000001, 2**53, -0x07fffffff, 2**53+2, Number.MAX_VALUE, 0x100000000, -(2**53), 0x080000000, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 1, Number.MIN_VALUE, 0x080000001, -0x080000001, 42, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, Math.PI]); ");
/*fuzzSeed-451211*/count=765; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[false, objectEmulatingUndefined(),  /x/g , false,  /x/g , false,  /x/g , false, false, objectEmulatingUndefined(),  /x/g ,  /x/g , x, objectEmulatingUndefined(), objectEmulatingUndefined(), x,  /x/g , x, x, x, x, x,  /x/g , false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, x, x, objectEmulatingUndefined(), x,  /x/g , objectEmulatingUndefined(),  /x/g , false, objectEmulatingUndefined(), objectEmulatingUndefined(), x,  /x/g ,  /x/g , x, false,  /x/g ,  /x/g , objectEmulatingUndefined(), false, x, objectEmulatingUndefined(),  /x/g , false,  /x/g , false,  /x/g ,  /x/g ,  /x/g , x, x, x, x, x, x, x,  /x/g , x,  /x/g ,  /x/g ,  /x/g , x,  /x/g , x, x,  /x/g , x, x,  /x/g , x,  /x/g ,  /x/g , objectEmulatingUndefined(), false,  /x/g ,  /x/g , objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/g , false,  /x/g , x,  /x/g , x]); ");
/*fuzzSeed-451211*/count=766; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=767; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.cosh((Math.max(((Math.exp(y) == (Math.max(-0x0ffffffff, Math.hypot(y, 1/0)) >>> 0)) | 0), ( + ( ~ ((x | 0) ? (y | 0) : (y | 0))))) | 0)) | 0) | 0) ? (( + Math.pow(Math.imul(Math.ceil(y), -0x080000000), ( + ( + (( + x) , ( + (( - ((x === (( - 0x080000001) | 0)) | 0)) | 0))))))) | 0) : ((Math.cbrt(( - Math.fround((Math.asinh((y >>> 0)) >>> 0)))) >>> 0) | 0)); }); testMathyFunction(mathy3, /*MARR*/[1, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1/0), (-1/0), (void 0), (-1/0), (void 0), 1, 1, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), 1, (-1/0), (void 0), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, (-1/0), (-1/0), (-1/0), 1, (void 0), 1, (-1/0), (void 0), (-1/0), (-1/0)]); ");
/*fuzzSeed-451211*/count=768; tryItOut("\"use strict\"; \u000cx = (yield \u3056);for (var v of t1) { try { this.a1 = arguments.callee.arguments; } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } g2.__proto__ = a1; }\nthrow \"\\u824E\" ?  /x/g  :  /x/ ;\n");
/*fuzzSeed-451211*/count=769; tryItOut("print(uneval(p0));");
/*fuzzSeed-451211*/count=770; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( + (Math.fround((((Math.acos((1.7976931348623157e308 | 0)) | 0) & -0x07fffffff) || (mathy0(0x100000001, mathy0(x, (y && y))) | 0))) <= ( - x))) | 0); }); testMathyFunction(mathy1, /*MARR*/[(4277).unwatch(\"getDay\"), (4277).unwatch(\"getDay\"), objectEmulatingUndefined(), (4277).unwatch(\"getDay\"), objectEmulatingUndefined(), x, x,  '' , (4277).unwatch(\"getDay\"), (4277).unwatch(\"getDay\"),  'A' , (4277).unwatch(\"getDay\"), (4277).unwatch(\"getDay\"),  '' , (4277).unwatch(\"getDay\"),  '' , x, x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(),  '' , x, objectEmulatingUndefined(),  '' ,  'A' , objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=771; tryItOut("\"use strict\"; /*infloop*/while((yield window)(/*FARR*/[].map, (c = window)))v1 = g2.runOffThreadScript();");
/*fuzzSeed-451211*/count=772; tryItOut("/*ADP-1*/Object.defineProperty(a0, 8, ({value: (p={}, (p.z = [z1,,])()), writable: false, enumerable: x}));");
/*fuzzSeed-451211*/count=773; tryItOut("\"use strict\"; b0.toSource = (function(j) { if (j) { try { /*MXX1*/o2 = g0.Number.isSafeInteger; } catch(e0) { } a2.sort((function(j) { if (j) { try { v1 = (p1 instanceof a1); } catch(e0) { } Object.prototype.unwatch.call(o0, (\"\u03a0\" && x)); } else { /*MXX1*/o1 = g2.Map.prototype.clear; } })); } else { try { print(uneval(s1)); } catch(e0) { } for (var p in p1) { try { Array.prototype.splice.apply(this.a2, [NaN, 6]); } catch(e0) { } p0 + ''; } } });");
/*fuzzSeed-451211*/count=774; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.ceil((Math.ceil((( ! ( + ( - ( + ( ~ ( ! (y | 0))))))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-451211*/count=775; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((0xf9555c41)-(0xd7b5e9)))|0;\n  }\n  return f; })(this, {ff: DataView.prototype.setUint8}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-451211*/count=776; tryItOut("o1.a0.forEach((function(stdlib, foreign, heap){ \"use asm\";   var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 4.722366482869645e+21;\n    d0 = (34359738369.0);\n    d0 = (-72057594037927940.0);\n    (Int32ArrayView[((0x303d2017)) >> 2]) = (((0xb20fee9b) == (((Uint16ArrayView[(((0x7fffffff) >= (0x2f2b9513))+(0xffffffff)) >> 1]))>>>((Int16ArrayView[1]))))+(i2)+(i1));\n    i2 = (0xff731506);\n    i2 = (1);\n    return +(((0xffffffff) ? ((-0x8000000) ? (d3) : (257.0)) : (-(((~((i2)-(i1))))))));\n    i2 = (i2);\n    return +((d0));\n  }\n  return f; }));");
/*fuzzSeed-451211*/count=777; tryItOut("for(let a of (/*MARR*/[[], (void 0), [], [], (void 0), (void 0), (void 0), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], (void 0), (void 0), (void 0), (void 0), [], (void 0), [], (void 0), [], (void 0), (void 0), (void 0), (void 0), [], [], (void 0), [], [], (void 0), (void 0), (void 0), [], (void 0), [], [], (void 0), (void 0), [], [], (void 0), (void 0), [], (void 0), (void 0), [], (void 0), [], (void 0), [], (void 0), (void 0), [], [], (void 0), [], (void 0), [], (void 0)].filter(( \"\" ).bind(),  \"\" ) for each (eval in []) if (c))) return  /x/  in e;");
/*fuzzSeed-451211*/count=778; tryItOut("w = window;");
/*fuzzSeed-451211*/count=779; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.fround(( ! Math.fround((( + Math.fround(Math.hypot((Math.clz32((((( + 1) & 1.7976931348623157e308) | 0) | 0)) | 0), y))) ? Math.fround(y) : Math.fround(y))))))); }); testMathyFunction(mathy4, [0x080000001, 1, -0x100000001, 0x0ffffffff, Number.MAX_VALUE, -0x100000000, 2**53-2, 0x100000000, 1/0, 0.000000000000001, 2**53+2, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0, 0/0, Number.MIN_VALUE, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, 2**53, 0x07fffffff, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 42, -0x0ffffffff, -0x080000000, -1/0, Math.PI, -(2**53), -(2**53+2)]); ");
/*fuzzSeed-451211*/count=780; tryItOut("\"use asm\"; a0.reverse(intern(Object.defineProperty(x, \"arguments\", ({writable: -22, enumerable: true}))), f2);");
/*fuzzSeed-451211*/count=781; tryItOut("t1.set(a2, 5);");
/*fuzzSeed-451211*/count=782; tryItOut("\"use strict\"; /*RXUB*/var r = /(?![^]\\b{4,}){2}(\\B)\\B+?|(?:\u8b7b)^{2,33}*?|(?:(?!$))|((\udbc0))+\\3(?:(?=\\B)+)/m; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=783; tryItOut("v0 = evaluate(\"print(g1.a1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 22 != 0), noScriptRval: (x % 4 == 2), sourceIsLazy: false, catchTermination: (Math.min(-1, let (z = (4277)) Math.pow(window, -24)\n)) }));");
/*fuzzSeed-451211*/count=784; tryItOut("\"use strict\"; this.g1.offThreadCompileScript(\"g0.offThreadCompileScript(\\\"/* no regression tests found */\\\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 25 != 7), sourceIsLazy: true, catchTermination: (x % 3 != 1), elementAttributeName: s1, sourceMapURL: s2 }));\");");
/*fuzzSeed-451211*/count=785; tryItOut("a2 = /*FARR*/[null, undefined, (null), ];");
/*fuzzSeed-451211*/count=786; tryItOut("mathy0 = (function(x, y) { return ( ~ ( ~ ((Math.sqrt((-0x100000001 >>> 0)) >>> 0) >>> Math.trunc(( + (( + y) & ( + 0x07fffffff))))))); }); testMathyFunction(mathy0, [0.000000000000001, 2**53, 0x100000001, 0/0, -Number.MIN_VALUE, -0x0ffffffff, 2**53-2, 0x0ffffffff, -1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000001, 0x100000000, 0x07fffffff, -0x080000001, -(2**53-2), -0x100000001, Math.PI, Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), -0x100000000, 42, 1, Number.MIN_SAFE_INTEGER, -0, Number.MIN_VALUE, -0x080000000, -0x07fffffff, 0, 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=787; tryItOut("/*RXUB*/var r = r2; var s = \"\\n\\u5164\\n\\u5164\\n\\u5164\"; print(r.exec(s)); ");
/*fuzzSeed-451211*/count=788; tryItOut("x = g2;");
/*fuzzSeed-451211*/count=789; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=790; tryItOut("L:with((new new decodeURIComponent()())){{v0 = (s2 instanceof o1.e0);print(x); }g1.a1[19] = x; }");
/*fuzzSeed-451211*/count=791; tryItOut("let (z) { Array.prototype.sort.call(a1, Date.prototype.getUTCHours.bind(g2), o2.f0, /(?=\\S\\3)+/gyi, p0, h1, b1, v1, this); }");
/*fuzzSeed-451211*/count=792; tryItOut("this.g0.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 4 == 1), catchTermination: new (intern(((function fibonacci(rcfbes) { ; if (rcfbes <= 1) { ; return 1; } ; return fibonacci(rcfbes - 1) + fibonacci(rcfbes - 2);  })(1))))(false, Math.log2(z)) }));");
/*fuzzSeed-451211*/count=793; tryItOut("(allocationMarker());");
/*fuzzSeed-451211*/count=794; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=795; tryItOut("t0 = new Uint8ClampedArray(b2, 44, 2);");
/*fuzzSeed-451211*/count=796; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((( + ( - Math.hypot(((-Number.MIN_SAFE_INTEGER < x) ** mathy0(x, x)), y))) | 0) < (Math.imul(Math.trunc(((Math.imul(((mathy0((((x === x) >>> 0) | 0), (Math.log2(Math.fround(x)) | 0)) | 0) | 0), (Math.sqrt(-0x100000000) | 0)) | 0) ? y : Math.pow(( + Math.log1p(( + y))), ( + (x >>> 0))))), Math.acosh(y)) | 0)) | 0); }); ");
/*fuzzSeed-451211*/count=797; tryItOut("\"use strict\"; a2.push(v0);");
/*fuzzSeed-451211*/count=798; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(e0, v2);");
/*fuzzSeed-451211*/count=799; tryItOut("\"use strict\"; g2 + h0;");
/*fuzzSeed-451211*/count=800; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((((Math.pow((( + Math.trunc(( + (mathy2((x >>> 0), (-0x080000001 >>> 0)) >>> 0)))) >>> 0), Math.fround(Math.min(Math.fround(Math.sin(y)), Math.fround(y)))) ** ( + Math.atan2(x, x))) >>> 0) * (Math.max(( ! (1 * ( - x))), ( + ( ~ (( + Math.hypot(( + -0x07fffffff), Math.hypot(Math.fround(( ! (y ^ x))), mathy3(-0x07fffffff, y)))) | 0)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-451211*/count=801; tryItOut("mathy2 = (function(x, y) { return ( + (( ! (Math.min((mathy1(((( + Math.max(( + x), Math.fround(x))) - (( ~ -Number.MIN_VALUE) >>> 0)) >>> 0), Math.pow((0/0 >>> 0), (( ! Math.fround(-Number.MIN_VALUE)) >>> 0))) >>> 0), (( + Math.sin(( + (Math.log(Math.fround(mathy0(-0x100000000, y))) | 0)))) >>> 0)) >>> 0)) == Math.fround((( + Math.fround(mathy1(Math.fround(Math.fround(mathy1(x, Math.fround(y)))), x))) && Math.fround(( ~ Math.fround(Math.cos(Math.imul(( + Math.sign(( + x))), Math.fround(Math.expm1(Math.fround(y)))))))))))); }); testMathyFunction(mathy2, /*MARR*/[new String('q')]); ");
/*fuzzSeed-451211*/count=802; tryItOut("this.a1.reverse();");
/*fuzzSeed-451211*/count=803; tryItOut("\"use asm\"; ({ set then x () { return (({ get e(...z) { \"use strict\"; return  \"\"  }  })) }  });\nintern(());\n");
/*fuzzSeed-451211*/count=804; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -549755813887.0;\n    (Float64ArrayView[1]) = ((1048577.0));\n    d3 = (-8192.0);\n    {\n      d3 = (513.0);\n    }\n    {\n      return (((-7.0)))|0;\n    }\n    d3 = (-4.722366482869645e+21);\n    {\n      i2 = (i0);\n    }\n    (Float64ArrayView[1]) = ((NaN));\n    return (((Int8ArrayView[4096])))|0;\n  }\n  return f; })(this, {ff: (this.__defineSetter__(\"x\", Promise)\n)}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53-2), 1/0, 0x080000001, -0x080000000, -(2**53+2), -0x07fffffff, 0x100000001, 0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 2**53, -0x0ffffffff, Number.MAX_VALUE, -0x080000001, -0x100000001, 0.000000000000001, 2**53+2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, Number.MIN_SAFE_INTEGER, 42, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, -0, 0, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, 1, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-451211*/count=805; tryItOut("for (var p in i2) { try { v0 = g0.eval(\"(4277)\"); } catch(e0) { } try { v0.valueOf = (function mcc_() { var tfdhvg = 0; return function() { ++tfdhvg; if (/*ICCD*/tfdhvg % 11 == 3) { dumpln('hit!'); try { e2.add(s0); } catch(e0) { } try { h2 + a0; } catch(e1) { } try { t2.set(t1, 10); } catch(e2) { } Object.prototype.unwatch.call(o2, \"toString\"); } else { dumpln('miss!'); try { this.i2.next(); } catch(e0) { } try { o2 = a0[4]; } catch(e1) { } try { s0 += 'x'; } catch(e2) { } v2 = evaluate(\"((function factorial(giifix) { ; if (giifix == 0) { ; return 1; } this.g0.t0[g0.v1] = (uneval([,,]));; return giifix * factorial(giifix - 1); throw  /x/g  >>> window; })(20625))\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: timeout(1800), noScriptRval: false, sourceIsLazy:  \"\" , catchTermination: (x % 35 != 12), elementAttributeName: s2 })); } };})(); } catch(e1) { } /*MXX3*/g0.Uint32Array = g0.Uint32Array; }");
/*fuzzSeed-451211*/count=806; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0x0ffffffff, -0x080000000, 1/0, -Number.MAX_VALUE, 0, 1.7976931348623157e308, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, Math.PI, 0x100000000, -(2**53), 1, -(2**53+2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, 0x080000001, -0, 42, -0x100000001, -Number.MIN_VALUE, -0x100000000, -(2**53-2), 0x07fffffff, 0.000000000000001, Number.MAX_VALUE, -1/0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, -0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=807; tryItOut("mathy2 = (function(x, y) { return ( + ( ~ ( + (Math.max((x ? (Math.pow(( + mathy1(x, y)), ( + x)) == x) : mathy0(( + x), x)), (Math.min(Math.atan2(y, y), Math.fround(Math.log10(y))) ? (( + x) >>> 0) : x)) , ( + ( + mathy0(( + x), (Number.MAX_VALUE | 0)))))))); }); testMathyFunction(mathy2, [-0x080000000, -0x07fffffff, 2**53-2, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, Number.MAX_VALUE, Math.PI, -0, -0x0ffffffff, Number.MIN_VALUE, -(2**53+2), 0x07fffffff, 1, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0.000000000000001, 2**53+2, -0x080000001, 0x100000000, 0x080000001, -(2**53-2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 2**53, 0, 42, Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-451211*/count=808; tryItOut("/*MXX2*/g1.Symbol.isConcatSpreadable = a2;");
/*fuzzSeed-451211*/count=809; tryItOut("/*infloop*/M:for(w = (new (x)()); (void shapeOf(delete)); /*MARR*/[x,  '' ,  '' , \"\\u5833\", \"\\u5833\", eval, eval,  '' , eval,  '' ,  '' , x, x, eval,  '' , \"\\u5833\", eval,  '' , eval, eval, \"\\u5833\", \"\\u5833\", \"\\u5833\", \"\\u5833\", \"\\u5833\", eval,  '' ].some((1 for (x in [])))) {;function w() { \"use strict\"; yield w.yoyo(\"\\uB944\").__lookupGetter__( '' ) } yield; }");
/*fuzzSeed-451211*/count=810; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.imul(Math.fround(( ! (( + Math.imul(mathy0(y, x), (( - ( + x)) >>> 0))) >>> 0))), Math.fround(( + mathy0(Math.atan2((((((( ! x) > Math.fround((x > Math.fround(x)))) ^ -0x0ffffffff) | 0) ? (y | 0) : ((mathy1(( - y), x) >>> 0) | 0)) | 0), 0x07fffffff), ( + Math.hypot(((x > y) >= x), (mathy0((Math.fround(mathy0(x, (x >>> 0))) | 0), (Math.hypot(y, x) | 0)) | 0)))))))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(true), new Number(1), new Number(1), new Boolean(true), new Boolean(true), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(true), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(true)]); ");
/*fuzzSeed-451211*/count=811; tryItOut("for (var p in h0) { s0 + ''; }");
/*fuzzSeed-451211*/count=812; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! ( - (Math.cosh((( + (Math.max(( - 1), ( + x)) === ((Math.sin((x | 0)) | 0) | 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[new Boolean(false), function(){}, new Boolean(false), new Boolean(false), new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, undefined, undefined, undefined, new Boolean(false), undefined, function(){}, new Boolean(false), function(){}, undefined, undefined, new Boolean(false), undefined, function(){}, function(){}, new Boolean(false), undefined, new Boolean(false), function(){}, function(){}, undefined, new Boolean(false), function(){}, undefined, undefined, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-451211*/count=813; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((((0xfc515206)*-0xfffff) & (((((0x75fa373c)) << ((i0)+(0x8991cf10)))))));\n    {\n      {\n        i0 = (i0);\n      }\n    }\n    return +(((((Uint16ArrayView[0]))) / ((yield -12))));\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return Math.imul(0/0, ( + Math.atan2(Math.fround(Math.hypot(Math.fround(y), Math.fround(y))), y))); })}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -(2**53), 2**53-2, 0, 0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53+2, 42, -0x080000000, -(2**53-2), 2**53, 0/0, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff, 0x100000000, 1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0, -0x100000000, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1, -1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, 0x07fffffff, 0x080000000]); ");
/*fuzzSeed-451211*/count=814; tryItOut("for (var p in f0) { try { /*MXX2*/g2.ArrayBuffer.prototype.constructor = t1; } catch(e0) { } o0.m2.has(m2); }");
/*fuzzSeed-451211*/count=815; tryItOut("\"use strict\"; s2 = new String;");
/*fuzzSeed-451211*/count=816; tryItOut("const m2 = m2.get(this.e1);");
/*fuzzSeed-451211*/count=817; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.pow(Math.atan2((((( - x) | 0) > (Math.fround(( - Math.fround((( ! x) >>> 0)))) | 0)) >>> 0), ( + ( ! Math.max((x >>> 0), 0x080000000)))), ( ~ Math.hypot((y > ( ! 0/0)), 0x100000001))); }); ");
/*fuzzSeed-451211*/count=818; tryItOut("\"use strict\"; h0 = {};function y(x, c = \u3056, x = undefined, x, x =  /x/ , b) { b2 + ''; } print(x);\n/*hhh*/function irkcnc({x: b}, ...get){(makeFinalizeObserver('tenured'));}irkcnc(\"\\u7485\");\n");
/*fuzzSeed-451211*/count=819; tryItOut("o1.s1 += 'x';");
/*fuzzSeed-451211*/count=820; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions('compartment'); } void 0; }");
/*fuzzSeed-451211*/count=821; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.hypot(((Math.fround(((( ! ( + ((y < x) | 0))) >>> 0) & ( + mathy0((((( - -0x0ffffffff) >>> 0) != y) >>> 0), y)))) <= Math.fround((mathy1(Math.acos(( ! x)), (Math.pow(Math.cbrt(Math.cbrt(x)), ( + (( ! (x | 0)) | 0))) >>> 0)) >>> 0))) >>> 0), Math.fround(( ~ (Math.asin(Math.max(-0x100000000, ((Math.pow((-0x07fffffff < y), x) >>> 0) ** ((mathy0((( + Math.hypot(( + y), ( + y))) | 0), ((mathy0(0x07fffffff, 2**53-2) | 0) | 0)) | 0) >>> 0)))) | 0)))) >>> 0); }); testMathyFunction(mathy2, [2**53+2, -Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 42, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, 0x080000001, -0x0ffffffff, -0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, 0x080000000, 1, 0x100000001, -(2**53+2), -0x07fffffff, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, -(2**53), Number.MIN_VALUE, -(2**53-2), 2**53-2, 0x100000000, 0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=822; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\b)\", \"gym\"); var s = \"\\u1f9c?aa\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=823; tryItOut("\"use strict\"; s1 += s0;");
/*fuzzSeed-451211*/count=824; tryItOut("a1.shift();");
/*fuzzSeed-451211*/count=825; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -16383.0;\n    i1 = ((Int16ArrayView[((i2)-((0x5b359da0))) >> 1]));\n    d3 = (+ceil(((Float32ArrayView[0]))));\n    return +((d3));\n  }\n  return f; })(this, {ff: (let (y, z, NaN, x) undefined).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[(-1/0), {}, {}]); ");
/*fuzzSeed-451211*/count=826; tryItOut("\"use strict\"; Object.defineProperty(this, \"this.v2\", { configurable: true, enumerable: (x % 35 != 22),  get: function() {  return o1.g2.runOffThreadScript(); } });function c()\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((+(1.0/0.0)));\n  }\n  return f;print(x);function a(x =  /x/g  ,  \"\" , w, ...x) { \"use strict\"; Array.prototype.splice.call(g1.a0, NaN, ((uneval(x))), g2, m1); } /*MXX3*/o1.g2.Date.prototype.getYear = g1.Date.prototype.getYear;");
/*fuzzSeed-451211*/count=827; tryItOut("\"use strict\"; yield;");
/*fuzzSeed-451211*/count=828; tryItOut("\"use asm\"; g0.v1 = g1.eval(\"s1 += s1;\");");
/*fuzzSeed-451211*/count=829; tryItOut("testMathyFunction(mathy1, [2**53+2, 0x100000000, 1/0, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, 0, 0.000000000000001, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, Math.PI, 42, -0x100000000, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, 0/0, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, 2**53-2, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000001, 0x100000001, 2**53, 0x080000001, 1]); ");
/*fuzzSeed-451211*/count=830; tryItOut("m0.has(e2);");
/*fuzzSeed-451211*/count=831; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=832; tryItOut("Object.prototype.unwatch.call(this.o1.i0, \"__parent__\");");
/*fuzzSeed-451211*/count=833; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( - ( + Math.max(( + x), ( + x))))); }); testMathyFunction(mathy4, /*MARR*/[{}, objectEmulatingUndefined(), (4277), objectEmulatingUndefined(), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , (4277), {},  \"use strict\" , objectEmulatingUndefined(), {}, (4277), {}, (4277), {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), (4277), (4277), (4277), (4277), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , (4277), {},  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , {}, (4277), objectEmulatingUndefined(), (4277), objectEmulatingUndefined(), {}, (4277), objectEmulatingUndefined(), objectEmulatingUndefined(), (4277), (4277), objectEmulatingUndefined(), (4277), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, (4277), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , (4277), (4277), {}, objectEmulatingUndefined(),  \"use strict\" , (4277),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined()]); ");
/*fuzzSeed-451211*/count=834; tryItOut("/*bLoop*/for (var jbcruf = 0; jbcruf < 4; ++jbcruf) { if (jbcruf % 3 == 2) { for (var v of e2) { try { a2.length = 19; } catch(e0) { } try { this.e1.add(p2); } catch(e1) { } v1 = Object.prototype.isPrototypeOf.call(m0, this.g1); } } else { v2 = false; }  } \nfor (var v of this.b1) { try { v2 = evaluate(\"o0 = {};\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: \u3056 = Proxy.createFunction(({/*TOODEEP*/})(/[^]/ym), mathy1, Map), noScriptRval: false, sourceIsLazy: true, catchTermination: ([()]) })); } catch(e0) { } v1 = i2[\"callee\"]; }\n");
/*fuzzSeed-451211*/count=835; tryItOut(";");
/*fuzzSeed-451211*/count=836; tryItOut("for (var v of a1) { try { Array.prototype.sort.apply(a1, [(function() { try { Object.prototype.unwatch.call(v2, \"toLocaleUpperCase\"); } catch(e0) { } try { i2.next(); } catch(e1) { } g2.v2 = t0.BYTES_PER_ELEMENT; return h2; }), (4277)]); } catch(e0) { } try { i2.__iterator__ = (function() { try { s0 += 'x'; } catch(e0) { } try { h0 = ({getOwnPropertyDescriptor: function(name) { m2.delete(this.g0.o0.e2);; var desc = Object.getOwnPropertyDescriptor(f1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { a1 = r2.exec(s0);; var desc = Object.getPropertyDescriptor(f1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { s0 = s2.charAt(v0);; Object.defineProperty(f1, name, desc); }, getOwnPropertyNames: function() { /*MXX1*/Object.defineProperty(this, \"o2\", { configurable: false, enumerable: ,  get: function() { s2 = new String; return g2.Math.atanh; } });; return Object.getOwnPropertyNames(f1); }, delete: function(name) { /*MXX3*/this.g2.ReferenceError.prototype = g1.ReferenceError.prototype;; return delete f1[name]; }, fix: function() { print(p2);; if (Object.isFrozen(f1)) { return Object.getOwnProperties(f1); } }, has: function(name) { o0.a0 = [];; return name in f1; }, hasOwn: function(name) { /*RXUB*/var r = r1; var s = \"\\uffe1\"; print(r.test(s)); print(r.lastIndex); ; return Object.prototype.hasOwnProperty.call(f1, name); }, get: function(receiver, name) { this.i0.next();; return f1[name]; }, set: function(receiver, name, val) { for (var v of g2.g0) { try { g2.h1.toString = f2; } catch(e0) { } try { v1 = a1.length; } catch(e1) { } h2.valueOf = (function() { for (var j=0;j<4;++j) { f1(j%3==1); } }); }; f1[name] = val; return true; }, iterate: function() { p2 = Proxy.create(h0, o2.t1);; return (function() { for (var name in f1) { yield name; } })(); }, enumerate: function() { a0 + h0;; var result = []; for (var name in f1) { result.push(name); }; return result; }, keys: function() { /*ODP-1*/Object.defineProperty(h1, \"caller\", ({value:  /x/ , writable: null, configurable: (x % 4 != 3), enumerable: (x % 2 == 0)}));; return Object.keys(f1); } }); } catch(e1) { } v2 = g0.eval(\"g0 = this;\"); return g0; }); } catch(e1) { } try { g0.s0 += this.s1; } catch(e2) { } a1.shift(); }function w(...z) { return x } x;\nt1.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = a9 / a5; var r1 = a0 % 0; var r2 = a9 ^ a5; a1 = 0 ^ a6; var r3 = 1 & a1; var r4 = a8 + 6; a6 = 0 + 5; var r5 = 1 + r0; r5 = a4 - 9; var r6 = x ^ 2; r3 = 1 % 4; var r7 = 6 + 9; var r8 = 2 - r1; var r9 = a2 * a5; var r10 = r4 ^ a11; var r11 = 7 / r5; var r12 = r10 & 6; var r13 = a0 * a8; a8 = a2 | r1; var r14 = r2 % r10; print(x); var r15 = a11 - r8; var r16 = 7 & 6; var r17 = 5 + r16; var r18 = r16 & a0; print(r15); var r19 = a4 & r8; var r20 = r8 ^ 0; var r21 = r0 * a6; r18 = r13 ^ 5; var r22 = a8 | r9; var r23 = 5 % a0; a4 = 1 | r21; r8 = a10 - a8; a3 = r2 & 5; print(r0); print(x); var r24 = 9 + r23; var r25 = r11 / 7; var r26 = r16 & a4; var r27 = 4 / a9; var r28 = r20 * 3; var r29 = r2 + r12; var r30 = r18 | 5; var r31 = r13 % r6; var r32 = a8 & a5; var r33 = a4 / r0; var r34 = r24 - a8; var r35 = r7 % 9; r10 = 2 | r12; print(r20); var r36 = r24 & a4; r29 = r31 ^ 0; var r37 = r29 - a2; var r38 = r0 * 7; var r39 = r28 / 6; var r40 = r1 * x; var r41 = a1 - 9; var r42 = 3 + r29; var r43 = x ^ a10; var r44 = r39 & r37; var r45 = 8 * a8; var r46 = a4 ^ 9; var r47 = 5 + a11; var r48 = r40 & a10; a4 = r7 & r44; var r49 = r36 - a7; var r50 = a10 * 6; r32 = 2 / 0; var r51 = 3 * r8; var r52 = r10 % 3; var r53 = r34 + r10; print(r32); var r54 = r19 / a0; var r55 = r27 * r47; var r56 = r8 ^ a3; var r57 = r52 / r34; r48 = r57 % a0; var r58 = 3 / r34; var r59 = r19 * r30; var r60 = r2 - r22; var r61 = r25 % r31; var r62 = 7 + 0; var r63 = r48 % 3; var r64 = a6 - r53; r54 = r56 ^ r20; var r65 = a11 % r35; r24 = 7 & r31; var r66 = r9 / r17; var r67 = r13 / 6; var r68 = r58 + 9; var r69 = r14 % 9; var r70 = 2 & a6; var r71 = r21 % a0; r14 = r69 / 1; r63 = 6 ^ 3; var r72 = 5 % r43; r3 = r36 ^ r1; var r73 = r48 * r7; var r74 = r67 % 9; a1 = 7 | 6; r68 = 0 + r31; print(r42); var r75 = r61 ^ r62; var r76 = 4 + 9; r62 = a7 - r17; var r77 = 2 & r75; var r78 = 5 + 6; var r79 = r63 / a11; var r80 = r58 + r36; var r81 = r68 + r57; var r82 = r67 / 3; var r83 = 5 % r19; r26 = r73 + r31; var r84 = r17 ^ a7; var r85 = r67 | 0; var r86 = r23 + r20; var r87 = r9 * 4; r0 = r25 | 8; var r88 = 3 ^ r2; r39 = r80 | 4; var r89 = 5 ^ r54; var r90 = r59 - r35; var r91 = r65 - a2; var r92 = r15 / r90; var r93 = r41 / 6; var r94 = r82 & r79; print(r17); var r95 = 7 * r29; var r96 = r31 & r32; r76 = 7 * r32; return a8; });\n");
/*fuzzSeed-451211*/count=837; tryItOut("\"use strict\"; \"use asm\"; for(var z = /*RXUE*/new RegExp(\"(.)*|(?=([^]\\\\s))+|^|(\\\\w|[^]{4,}){0,}{4,6}\", \"gim\").exec(\"\\u092b\\n\\n\\u46cc\\u00a8%%%%\\u092b\\n\\n\\u46cc\\u00a8\\u092b\\n\\n\\u46cc\\u00a8\") in x) {/*RXUB*/var r = r2; var s = s0; print(r.test(s)); print(r.lastIndex);  }");
/*fuzzSeed-451211*/count=838; tryItOut("h0 = m2.get(this.f1);");
/*fuzzSeed-451211*/count=839; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sinh(Math.log(( + Math.atan2(1.7976931348623157e308, y)))); }); ");
/*fuzzSeed-451211*/count=840; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(( ! ((( + x) >>> 0) >>> Math.trunc(Math.sinh((-Number.MAX_VALUE >>> 0)))))); }); testMathyFunction(mathy5, [-(2**53), 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, 0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, 0, -0x080000001, 1.7976931348623157e308, -1/0, 1, 0/0, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0x100000000, -0x07fffffff, -0x080000000, 42, 0x0ffffffff, -(2**53-2), 2**53, -Number.MAX_VALUE, -0x0ffffffff, 0x080000001, 0x100000000, -0]); ");
/*fuzzSeed-451211*/count=841; tryItOut("testMathyFunction(mathy4, [0x07fffffff, 2**53, 42, 0.000000000000001, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, 2**53-2, -0x100000001, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, Math.PI, -(2**53), -0x080000001, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, 0x100000001, -0, 0, 1, -(2**53+2), 0x080000001, -1/0, -0x07fffffff, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-451211*/count=842; tryItOut("mathy0 = (function(x, y) { return ( - ( ! (( + Math.asinh(( + y))) ? (Math.hypot(x, Math.fround(( ~ Math.fround(y)))) >>> 0) : ( + x)))); }); testMathyFunction(mathy0, [-0x0ffffffff, 1, -0, 0x100000001, -0x100000001, -(2**53), 0x080000001, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, -(2**53-2), 0x07fffffff, -1/0, 0/0, -0x100000000, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000000, 2**53-2, -Number.MIN_VALUE, -(2**53+2), 42, Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 0, 0x100000000]); ");
/*fuzzSeed-451211*/count=843; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( - ((Math.min(( + (Math.fround(Math.atan2(Math.fround(y), (( + (( - (y >>> 0)) | 0)) << x))) >>> 0)), (( + ( + Math.pow(x, ( + mathy0(( + x), x))))) * ( ~ 0x080000001))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 0, 0x100000001, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0.000000000000001, 0x080000000, 1/0, -(2**53+2), -0x100000000, 1, -0x080000000, -Number.MAX_VALUE, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 0/0, -0, -0x0ffffffff, 0x100000000, 2**53+2, -0x100000001, 0x0ffffffff, -0x07fffffff, 42, 0x080000001]); ");
/*fuzzSeed-451211*/count=844; tryItOut("g2.valueOf = this.f0;");
/*fuzzSeed-451211*/count=845; tryItOut("v0 = g0.t2.byteLength;");
/*fuzzSeed-451211*/count=846; tryItOut("v1 = o1.a2[({valueOf: function() { this.e2.add(m2);return 19; }})];");
/*fuzzSeed-451211*/count=847; tryItOut("\"use strict\"; vlmwws();/*hhh*/function vlmwws(...d){v2 = new Number(v0);}");
/*fuzzSeed-451211*/count=848; tryItOut("mathy0 = (function(x, y) { return ( + Math.asin((Math.cosh(( ~ ( + Math.pow(( + (x >> -1/0)), ( + Number.MAX_SAFE_INTEGER))))) | 0))); }); testMathyFunction(mathy0, /*MARR*/[true, true, true, true, (1/0), true, null, true, null, ({}), new Boolean(false), true, true, new Boolean(false), new Boolean(false), new Boolean(false), null, new Boolean(false), null, null, new Boolean(false), (1/0), true, null, ({}), true, (1/0), new Boolean(false), ({}), (1/0), (1/0), (1/0), null, ({}), (1/0), true, new Boolean(false), null, (1/0), null, new Boolean(false), true, null, null, true, (1/0), new Boolean(false)]); ");
/*fuzzSeed-451211*/count=849; tryItOut("\"use asm\"; for(b in new String.prototype.valueOf((void shapeOf([])), (void options('strict')))) {/*RXUB*/var r = new RegExp(\"\\\\2\", \"m\"); var s = \"\\n\"; print(r.test(s));  }");
/*fuzzSeed-451211*/count=850; tryItOut("mathy3 = (function(x, y) { return (mathy2((((Math.pow(( + (x !== (x | 0))), x) >>> 0) >>> Math.expm1(Math.atanh(mathy1(y, ( + Math.sqrt(( + y))))))) | 0), (Math.max(Math.min((((-Number.MAX_SAFE_INTEGER >>> 0) <= mathy1(-0x07fffffff, x)) * (Math.trunc(y) >>> 0)), -0), (Math.log10((0x080000000 >>> 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, [objectEmulatingUndefined(), null, (new Number(0)), '\\0', ({valueOf:function(){return 0;}}), (function(){return 0;}), -0, false, (new Number(-0)), 0, /0/, '', true, 1, (new Boolean(true)), '/0/', ({valueOf:function(){return '0';}}), undefined, 0.1, [], (new String('')), (new Boolean(false)), '0', NaN, [0], ({toString:function(){return '0';}})]); ");
/*fuzzSeed-451211*/count=851; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( + ( - (((Math.ceil(2**53+2) >= x) | Math.cosh(Math.fround(((Math.pow((( - x) | 0), (-Number.MAX_VALUE | 0)) | 0) % -Number.MIN_VALUE)))) >>> 0)))); }); ");
/*fuzzSeed-451211*/count=852; tryItOut("/*RXUB*/var r = /(?=\\9|$+)/y; var s = \"\\n\\n\\n\\n\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=853; tryItOut("\"use strict\"; a0 = a2.slice();");
/*fuzzSeed-451211*/count=854; tryItOut("testMathyFunction(mathy4, [-0, 0x100000001, -(2**53-2), Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000001, 1, -Number.MAX_VALUE, -(2**53), -1/0, Number.MIN_VALUE, Math.PI, 0, -0x0ffffffff, 2**53+2, 0x080000000, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, -(2**53+2), -0x100000001, -0x100000000, -0x080000000, 2**53-2, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, 0/0, 2**53]); ");
/*fuzzSeed-451211*/count=855; tryItOut("\"use strict\"; e0.add(a1);");
/*fuzzSeed-451211*/count=856; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround((Math.fround(Math.imul(((( + mathy1(( + y), ( + 2**53+2))) | 0) >> (( + Math.hypot(( + Math.imul((( ~ (y >>> 0)) >>> 0), -0)), ( + ( + mathy2(( + (Math.hypot((( + (( + Number.MAX_SAFE_INTEGER) + y)) >>> 0), (y >>> 0)) | 0)), ( + x)))))) | 0)), ((x >>> 0) & Math.imul(mathy1(y, x), x)))) & Math.fround(Math.log10((Math.fround(( ~ Math.fround((uneval(/(?!(?:\\S)|(.))|[\\u0001-\\cC\\D\\x8E-\\u9Aa7\\u31Cb]+|\u6fcf|s{3,}/g))))) - -(2**53-2)))))); }); testMathyFunction(mathy4, [-0x100000000, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, 0, -(2**53+2), -0x07fffffff, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, 1/0, 0/0, 2**53+2, 0x0ffffffff, -0x100000001, -(2**53-2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 0x080000000, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 42, 0x100000000, 1.7976931348623157e308, -1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, Number.MAX_VALUE, 0x080000001, 1]); ");
/*fuzzSeed-451211*/count=857; tryItOut("i2 = new Iterator(t2, true);a = ((y)( /x/ ,  '' )).__defineGetter__(\"c\", DFGTrue);const y = x;/*tLoop*/for (let e of /*MARR*/[ /x/ , null,  /x/ , null, null, null,  /x/ , null,  /x/ , null,  /x/ ,  /x/ , null,  /x/ , null, null, null, null,  /x/ ,  /x/ , null, null,  /x/ , null,  /x/ , null,  /x/ , null, null, null,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , null, null,  /x/ , null, null, null, null,  /x/ ,  /x/ , null, null,  /x/ , null, null, null, null, null, null,  /x/ ,  /x/ ]) { print(this.__defineSetter__(\"x\", TypeError)); }");
/*fuzzSeed-451211*/count=858; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x080000001, -(2**53), -1/0, -(2**53-2), 2**53+2, -0x100000001, -0x0ffffffff, 0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, -Number.MAX_VALUE, 0, 0x07fffffff, Math.PI, 0x0ffffffff, Number.MAX_VALUE, -(2**53+2), 0x100000000, 1.7976931348623157e308, 1/0, 0/0, 42, -0x080000000, 1, Number.MIN_VALUE, 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 2**53-2]); ");
/*fuzzSeed-451211*/count=859; tryItOut("a0.__proto__ = this.b2;");
/*fuzzSeed-451211*/count=860; tryItOut("print(x);");
/*fuzzSeed-451211*/count=861; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=862; tryItOut("var umoccz = new SharedArrayBuffer(2); var umoccz_0 = new Uint8ClampedArray(umoccz); umoccz_0[0] = x; h2.__proto__ = e2;");
/*fuzzSeed-451211*/count=863; tryItOut("mathy3 = (function(x, y) { return Math.hypot((Math.hypot(mathy1(x, ( + Math.max((y >>> 0), y))), (42 ? (( - (y >>> 0)) >>> 0) : y)) < Math.hypot(y, ( + (Math.sin(y) ^ (( - Math.fround(-0x07fffffff)) >>> 0))))), (( ! (-23.__defineSetter__(\"y\", WeakMap.prototype.get)\u0009 | 0)) | 0)); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0x100000001, -(2**53-2), -1/0, -(2**53+2), 42, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 1, 0.000000000000001, -0x07fffffff, -0x0ffffffff, 0, 0/0, 1.7976931348623157e308, 0x080000000, 0x100000000, -0x080000001, 0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -0, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -(2**53), 2**53+2, Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=864; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=865; tryItOut("m0.delete(s1);");
/*fuzzSeed-451211*/count=866; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\nObject.seal(i0);v2 = this.t0.length;    return (((i0)))|0;\n  }\n  return f; })(this, {ff: function(y) { return x }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, Number.MIN_VALUE, -0x080000001, 0x080000000, -0x0ffffffff, 2**53-2, -0, 1, 0x100000000, -(2**53-2), Math.PI, -0x080000000, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, 0x080000001, -1/0, 1.7976931348623157e308, 42, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, 0x07fffffff, 2**53, 0, -(2**53), 0.000000000000001, Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=867; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?=\\\\W+)?(?=(?=$*)?)){3,}|^|\\\\2{4,}|(?:\\\\D+){3}|(.*?)^((?:$)){4,6}\", \"gi\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-451211*/count=868; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ ( + Math.atan((( + Math.fround(( ! x))) | 0)))); }); testMathyFunction(mathy0, ['0', (new Boolean(false)), '', undefined, (new Number(0)), '\\0', (function(){return 0;}), false, [], '/0/', 0.1, [0], ({valueOf:function(){return '0';}}), true, null, (new Number(-0)), objectEmulatingUndefined(), NaN, 1, -0, (new String('')), (new Boolean(true)), ({valueOf:function(){return 0;}}), 0, /0/, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-451211*/count=869; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + (( + Math.hypot((( - Math.fround(Math.cbrt((( - -0x080000000) >>> 0)))) | 0), ( + Math.log(((y ? (((x && y) >>> 0) | 0) : ((x < (((-0x080000001 >>> 0) != (1/0 >>> 0)) >>> 0)) | 0)) | 0))))) / ( + (Math.hypot((((((Math.pow(( + Math.sqrt(x)), (Math.atan2((x | 0), (-0x0ffffffff | 0)) | 0)) >>> 0) >>> 0) ? Math.fround((x != mathy2(-0x07fffffff, ( ~ y)))) : (Math.min((-0x100000000 >>> 0), x) >>> 0)) >>> 0) | 0), (Math.cos(0x07fffffff) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [2**53, 0x100000000, -0x100000001, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, Number.MAX_VALUE, -(2**53), -1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, 0x07fffffff, Math.PI, 0, -0x080000001, Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, -Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), 2**53+2, 42, 0/0, Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, 1/0, -0x07fffffff]); ");
/*fuzzSeed-451211*/count=870; tryItOut("\"use strict\"; return;\nv0 = g2.eval(\"function f0(h2)  { \\\"use strict\\\"; yield NaN++ } \");\n");
/*fuzzSeed-451211*/count=871; tryItOut("\"use strict\"; e2.toString = (function(j) { if (j) { try { v0 = r0.multiline; } catch(e0) { } try { Object.defineProperty(this, \"b1\", { configurable: false, enumerable: false,  get: function() {  return new SharedArrayBuffer(8); } }); } catch(e1) { } ; } else { try { a2 = this.r2.exec(s2); } catch(e0) { } try { g1.v2 = new Number(g1.i0); } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(g2, t0); } });");
/*fuzzSeed-451211*/count=872; tryItOut("/*oLoop*/for (let egqqpv = 0; egqqpv < 5; ++egqqpv) { print(allocationMarker()); } /* no regression tests found */");
/*fuzzSeed-451211*/count=873; tryItOut("/*oLoop*/for (let obribw = 0; obribw < 43; ++obribw) { v1 = g1.runOffThreadScript(); } ");
/*fuzzSeed-451211*/count=874; tryItOut("/*hhh*/function egvzox(){/*ADP-1*/Object.defineProperty(a0, 11, ({}));}/*iii*/m2.get(h2);");
/*fuzzSeed-451211*/count=875; tryItOut("for (var v of m2) { try { /*oLoop*/for (etdnzh = 0; etdnzh < 43; ++etdnzh) { for(let x = \u000c({a1:1}) in this) this.a0 = [];/*RXUB*/var r = r1; var s = a; print(s.search(r));  }  } catch(e0) { } try { v2 = evalcx(\"(\\\"\\\\u1853\\\".__proto__ = (EvalError(new RegExp(\\\"[\\\\\\\\x37-\\\\\\\\B\\\\\\\\d\\\\\\\\D\\\\\\\\u007A-\\\\\\\\n](\\\\ue133)\\\\\\\\D\\\", \\\"yi\\\").watch(\\\"defineProperties\\\", offThreadCompileScript),  /x/g )))\", g1); } catch(e1) { } v1 = g2.a2.length; }");
/*fuzzSeed-451211*/count=876; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-451211*/count=877; tryItOut("print(x);");
/*fuzzSeed-451211*/count=878; tryItOut("\"use strict\"; v2 = evaluate(\"b2 + f1;\", ({ global: o2.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 22 == 12), noScriptRval: true, sourceIsLazy: false, catchTermination: true, elementAttributeName: s0, sourceMapURL: s0 }))");
/*fuzzSeed-451211*/count=879; tryItOut("v1 = evalcx(\"function f0(o2.g2)  { yield o2.g2 } \", g2);print(let (x = this, wqvdcu, x, x, fnwrzo, eqrjdi) (eval = 13));");
/*fuzzSeed-451211*/count=880; tryItOut("/* no regression tests found */");
/*fuzzSeed-451211*/count=881; tryItOut("/*tLoop*/for (let b of /*MARR*/[ \"use strict\" ,  /x/g ,  \"use strict\" ,  \"use strict\" , 0x0ffffffff,  /x/g ,  /x/g ,  /x/g ]) { v2 = evalcx(\"b\", g0); }");
/*fuzzSeed-451211*/count=882; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-Number.MAX_VALUE, 2**53-2, -0x100000000, -0x080000000, 0x100000000, 0x080000000, -(2**53), 42, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, 0.000000000000001, 0x100000001, 0x07fffffff, -0x100000001, -(2**53-2), 0/0, Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER, -0, 0, 2**53, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 1]); ");
/*fuzzSeed-451211*/count=883; tryItOut("f0 = Proxy.createFunction(h0, f1, f1);");
/*fuzzSeed-451211*/count=884; tryItOut("/*oLoop*/for (var bmbgjx = 0, x, \u3056 = \"\\uF9B8\"; bmbgjx < 44; ++bmbgjx) { neuter(b2, \"same-data\"); } ");
/*fuzzSeed-451211*/count=885; tryItOut("/*RXUB*/var r = new RegExp(\"[^][^\\\\W\\\\0\\uc22f]\\\\1|\\\\W|[^]|[^\\\\cM]{4,6}|^|.+.[^]{0}((?!\\\\w.*))(?=\\\\d+)+?\", \"g\"); var s = \"\\n\\n\\n\"; print(s.replace(r, 'x')); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=886; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround(( + ((Math.atan2((mathy0((Math.hypot(x, ( + x)) | 0), (( + (y && mathy0(y, x))) | 0)) | 0), ( + ( ! y))) >>> 0) | 0))) - Math.fround((Math.cos((Math.imul((Math.atan2(((x | 0) | y), ( + Math.hypot((x >>> 0), Number.MAX_SAFE_INTEGER))) >>> 0), ((Math.pow((Math.atan2((Math.sinh((-0x100000000 >>> 0)) >>> 0), x) | 0), (mathy0(((-Number.MAX_SAFE_INTEGER * y) & Math.fround(y)), Math.exp(y)) | 0)) | 0) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [(new Number(0)), [], (new String('')), (new Number(-0)), [0], 0, ({toString:function(){return '0';}}), (function(){return 0;}), '', NaN, ({valueOf:function(){return '0';}}), '/0/', 0.1, true, 1, objectEmulatingUndefined(), -0, (new Boolean(false)), false, undefined, /0/, '\\0', null, '0', (new Boolean(true)), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-451211*/count=887; tryItOut("var v2 = evalcx(\"\\\"use strict\\\"; a2.length = ({valueOf: function() { /*MXX3*/g2.Error.name = g1.Error.name;return 17; }});\", g0);");
/*fuzzSeed-451211*/count=888; tryItOut("mathy3 = (function(x, y) { return mathy1((mathy0(Math.ceil(mathy0(Math.sin(y), Math.max(Math.fround(Math.atan2(( + y), ( + y))), (( ~ (x | 0)) | 0)))), ( + (Math.log10(x) && ( + (x == ( + (((( - (x | 0)) | 0) >> y) | 0))))))) | 0), Math.max((Math.abs(y) >>> 0), (Math.hypot((Math.imul(mathy0(y, Math.PI), ( + ( + (0.000000000000001 + x)))) >>> 0), ( + Math.sqrt(( + ( ~ Math.asin(y)))))) >>> 0))); }); testMathyFunction(mathy3, [0x080000000, 2**53-2, Number.MIN_VALUE, -0x100000001, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -(2**53+2), -0x080000001, -1/0, 1.7976931348623157e308, 1/0, 0x100000001, 1, 42, -0x07fffffff, -0, -0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 0, 2**53+2, 0/0, -(2**53)]); ");
/*fuzzSeed-451211*/count=889; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ~ (( + Math.fround(( + ( - ( + ((Math.fround(x) >> Math.fround(x)) >>> x)))))) | 0))); }); testMathyFunction(mathy4, [-(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0, -(2**53-2), 0x07fffffff, 0/0, 42, -0x100000000, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -(2**53+2), 1, 0x080000001, -0x100000001, 1/0, 0.000000000000001, 2**53, 2**53+2, -0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, 0x100000001, -0x07fffffff, 0]); ");
/*fuzzSeed-451211*/count=890; tryItOut("\"use strict\"; for(var [b, b] = () in x) {selectforgc(o1);e0.add(h0); }");
/*fuzzSeed-451211*/count=891; tryItOut("a0.unshift(x);");
/*fuzzSeed-451211*/count=892; tryItOut("e2.has(v2);");
/*fuzzSeed-451211*/count=893; tryItOut("\"use strict\"; m1 = new WeakMap;");
/*fuzzSeed-451211*/count=894; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + Math.max(( + ( + Math.fround(Math.exp(42)))), ( + Math.sqrt(((x ? Math.cosh(Math.cosh(x)) : ( + Math.pow(x, ( + x)))) >>> 0))))) <= ( + (Math.tanh((y ? y : (Math.imul((((x >> (y | 0)) | 0) >>> 0), x) >>> 0))) >>> 0))); }); ");
/*fuzzSeed-451211*/count=895; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -5.0;\n    var i3 = 0;\n    var d4 = 511.0;\n    var d5 = 0.125;\n    (Float64ArrayView[((Int8ArrayView[(((0x4a2a49c8) < (-0x533ee93))-(0xac176864)-(i3)) >> 0])) >> 3]) = ((Float64ArrayView[((i3)-(0xfd7fee55)+(0xfdecf955)) >> 3]));\n    d2 = (((+abs(((d4))))) * ((-36028797018963970.0)));\n    d2 = (576460752303423500.0);\n    return (((((-0x3d644a1)+(i0)) >> ((0xfff08372)+((((0xbcbdee3f))>>>((-0x56d6fdc))) < (((-0x8000000))>>>((0xfbb8e66a))))-(-0x8000000))) / (((0x43bfd160)) >> ((i1)+((0x760a8f13) != (0x830fbd5d))-(i1)))))|0;\n    i1 = (!(-0x8000000));\n    {\n      i0 = (0xfc9f353b);\n    }\n    (Int32ArrayView[((x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function(name) { return delete x[name]; }, fix: function() { return []; }, has: undefined, hasOwn: function() { throw 3; }, get: function(y) { yield y; Array.prototype.unshift.apply(a1, [this, g2.t2]);; yield y; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: neuter, enumerate: undefined, keys: function() { return []; }, }; })(\"\\uFD1D\"), /*wrap3*/(function(){ var bckazp = \u3056 = z; (Map.prototype.has)(); }), Date.prototype.setTime))+(0x70d27aea)) >> 2]) = (((-6.189700196426902e+26) == (d4))-((abs((imul(((((0x8beb4a67))>>>((0xffffffff))) > (((0xfe27909b))>>>((0xffffffff)))), ((~((Int32ArrayView[((0xffffffff)) >> 2])))))|0))|0) >= ((((+pow(((+atan2(((-2.0)), ((-4194305.0))))), ((x)))) > (+(imul((0xfe171075), (0xdf5cdf53))|0)))) | ((0x811468ec)))));\n    return (((-0x8000000)-(i3)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); ");
/*fuzzSeed-451211*/count=896; tryItOut("/*tLoop*/for (let y of /*MARR*/[['z'], ['z'],  /x/ , ['z'],  '' ,  '' ,  /x/ ,  /x/ ,  /x/ , new Boolean(true), ['z'], new Boolean(true), ['z'], ['z'], ['z'],  /x/ ,  /x/ , new Boolean(true),  '' , new Boolean(true),  /x/ ,  '' , ['z'],  '' ,  /x/ , new Boolean(true), new Boolean(true), ['z'], new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), ['z'],  '' , ['z'], ['z'], new Boolean(true), new Boolean(true), new Boolean(true),  '' ,  /x/ ,  '' ,  /x/ , new Boolean(true), new Boolean(true),  '' , ['z'], ['z'],  /x/ ]) { for (var v of g1) { try { a1 = Array.prototype.slice.apply(a0, [NaN, NaN, h1]); } catch(e0) { } try { ; } catch(e1) { } try { /*MXX2*/g2.Array.prototype.includes = a2; } catch(e2) { } a0 = a2.filter((function(j) { if (j) { for (var v of m2) { try { for (var p in o0.f2) { s0 += s1; } } catch(e0) { } a0[2]; } } else { try { print(uneval(this.e0)); } catch(e0) { } i1 = Proxy.create(h1, g0.o0.i2); } }), (x) = new RegExp(\"((?!${1,4}){3,4}|$|[^]|\\\\B\\\\b+(?:^))\", \"yi\"), f2, i0, h0); } }p0 + i1;");
/*fuzzSeed-451211*/count=897; tryItOut("\"\u03a0\";g1.toString = f1;");
/*fuzzSeed-451211*/count=898; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ~ ((((-1/0 & ( + Math.log2(2**53-2))) >>> 0) ? (((Math.log2(( + Math.atan2(( + Number.MIN_VALUE), ( + x)))) >>> 0) < Math.fround(-0x07fffffff)) >>> 0) : (Math.min((Math.pow(y, Math.sqrt(((0x0ffffffff >= 1) && y))) | 0), (( + ((Math.asin(y) >>> 0) ? ( + 0) : (y >>> 0))) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [0x080000000, -Number.MIN_VALUE, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, 0, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53, Math.PI, 0/0, 0x0ffffffff, 0x100000000, -0x0ffffffff, -0x080000000, -1/0, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x100000001, -(2**53-2), -0x07fffffff, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 42, 1, 2**53-2, 1/0]); ");
/*fuzzSeed-451211*/count=899; tryItOut("/*infloop*/for(let [] = (y = -5); x;  /x/ ) {\"\\u475C\"; }");
/*fuzzSeed-451211*/count=900; tryItOut("\"use strict\"; print(o2);function y(x) { \"use strict\"; yield x } var \u3056, e = new String(''), drkfqf, tosvkc;v2 = g2.eval(\"x = a2[v0];\");");
/*fuzzSeed-451211*/count=901; tryItOut("const w = a >= x;v0 = (o1 instanceof b1);");
/*fuzzSeed-451211*/count=902; tryItOut("s2 += 'x';");
/*fuzzSeed-451211*/count=903; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.max((( ~ (Math.cbrt(Math.log1p(( + (( + Math.pow(x, x)) !== ( + y))))) < (Math.fround(x) ^ (-Number.MIN_VALUE >>> 0)))) | 0), (Math.fround(Math.imul((x > Math.fround(mathy0((( + Math.min(( + x), ( + y))) >>> 0), Math.fround(Math.sinh(x))))), ((((( ! ( + x)) >>> 0) * (Math.fround(Math.hypot(Math.fround(Math.PI), Math.fround(2**53-2))) >>> 0)) >>> 0) >> ( ~ (( - x) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), (new Boolean(false)), (new String('')), '/0/', 1, NaN, [0], /0/, (new Number(0)), false, ({valueOf:function(){return '0';}}), '0', '\\0', ({toString:function(){return '0';}}), null, (function(){return 0;}), true, undefined, objectEmulatingUndefined(), -0, 0, '', (new Boolean(true)), (new Number(-0)), 0.1, []]); ");
/*fuzzSeed-451211*/count=904; tryItOut("v1 = a1.length;");
/*fuzzSeed-451211*/count=905; tryItOut("t2[12] = x++;");
/*fuzzSeed-451211*/count=906; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.fround(Math.fround(( + Math.fround(Math.fround(Math.max(Math.fround((Math.tan((((Number.MIN_VALUE ? x : Number.MAX_VALUE) !== y) >>> 0)) >>> 0)), Math.fround(-1/0))))))), ( + Math.sinh(( + (mathy0(( ~ x), ( + x)) | (y | 0)))))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0x07fffffff, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0x080000001, 1/0, Number.MIN_VALUE, 2**53, 0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 1, -(2**53), 0, -(2**53-2), 0x0ffffffff, 0x100000000, -0x07fffffff, -0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, -0, Math.PI, 2**53+2, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0.000000000000001, Number.MAX_VALUE, -0x100000001, -0x080000000]); ");
/*fuzzSeed-451211*/count=907; tryItOut("/*RXUB*/var r = /[^]{1}|[^][^]+?|\\b{1,}|[\\B-\\x8F\u5c37-\\u83DE\\S\\d].|[^]\\B*?|(?:[^]?)*+\\b+?\u1e0c*?|[^][]{1}\\d\\b{1,1}^{1,}(?=[^]$+?|[^U-\\x12\\u2E9a\0-\u000f])\\w{3,3}((?=\\B){4})|(?=(?!(?!\\b)(?=(?=\\B*)+))){3,}/yi; var s = \" \\u00e4\\u0904s \"; print(r.test(s)); ");
/*fuzzSeed-451211*/count=908; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2\", \"yim\"); var s = \"\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-451211*/count=909; tryItOut("/* no regression tests found *//*oLoop*/for (var pthldf = 0; pthldf < 3 && ((eval(\"print(x);\"))); ++pthldf) { /*bLoop*/for (var yymgni = 0; yymgni < 27; ++yymgni) { if (yymgni % 4 == 3) { a0 = arguments.callee.caller.caller.caller.caller.caller.arguments; } else { e0.delete(a1); }  }  } ");
/*fuzzSeed-451211*/count=910; tryItOut("mathy5 = (function(x, y) { return Math.sinh(( ! Math.hypot(( ! Math.fround(x)), (( + Math.fround(Math.PI)) !== ( + Math.imul(( + Math.fround(Math.atan(Math.fround(y)))), ( + x))))))); }); testMathyFunction(mathy5, [1, 0x100000000, -0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 2**53+2, 0, Number.MAX_SAFE_INTEGER, 1/0, -0x0ffffffff, -(2**53), 0.000000000000001, -0x080000000, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, 0x080000000, 0x0ffffffff, -(2**53+2), 2**53, 0/0, 0x100000001, 42, -Number.MAX_SAFE_INTEGER, -0, -(2**53-2), 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, Math.PI, -1/0, -Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-451211*/count=911; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53+2, 0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 42, 0x080000000, 0x07fffffff, 0.000000000000001, 2**53-2, -Number.MAX_VALUE, -0x100000001, 2**53, -0x080000000, 1, 0x0ffffffff, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0, 1.7976931348623157e308, -(2**53-2), -(2**53), 0x100000000, Number.MIN_VALUE, -0, -0x080000001, 0x080000001, -Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-451211*/count=912; tryItOut(";");
/*fuzzSeed-451211*/count=913; tryItOut("\"use strict\"; /*vLoop*/for (npfsfm = 0; npfsfm < 3; ++npfsfm) { e = npfsfm; v1 = r2.test; } function eval(y) { return ((w = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { return []; }, }; })(\"\\uC2DE\"), x)).watch(\"4\", new Number(1))) } e0.has(o2);");
/*fuzzSeed-451211*/count=914; tryItOut("Object.defineProperty(this, \"m0\", { configurable: (x % 10 == 9), enumerable: (x % 86 == 30),  get: function() {  return new Map(a2); } });");
/*fuzzSeed-451211*/count=915; tryItOut("\"use strict\"; testMathyFunction(mathy4, ['/0/', /0/, (function(){return 0;}), (new Number(-0)), 1, '0', ({toString:function(){return '0';}}), objectEmulatingUndefined(), (new String('')), (new Boolean(true)), 0.1, ({valueOf:function(){return 0;}}), false, (new Boolean(false)), (new Number(0)), 0, -0, '', [], null, undefined, [0], true, ({valueOf:function(){return '0';}}), '\\0', NaN]); ");
/*fuzzSeed-451211*/count=916; tryItOut("b1 = t0.buffer;function x(x, ...w) { \"use strict\"; \"use asm\"; return (function(y) { yield y; s1 + o2;; yield y; }).call(x, ) } /*RXUB*/var r = r2; var s = false; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=917; tryItOut("\"use strict\"; print(g2.h2);");
/*fuzzSeed-451211*/count=918; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(( ~ Math.fround(Math.pow((( + ( ~ ( + mathy0(( + (((x >>> 0) != (( + Math.min(( + 0x0ffffffff), y)) >>> 0)) >>> 0)), (((x >>> 0) > (Math.fround((( + y) * ( + x))) | 0)) >>> 0))))) | 0), (Math.round(( + ( + x))) | 0))))); }); ");
/*fuzzSeed-451211*/count=919; tryItOut("Object.prototype.unwatch.call(v0, \"wrappedJSObject\");");
/*fuzzSeed-451211*/count=920; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.max(Math.sqrt(Math.fround(Math.expm1(( + ( + Math.fround(-0x100000001)))))), Math.cos((Math.hypot((x | 0), (( ~ ( ~ (Math.cbrt(Math.tanh(x)) >>> 0))) | 0)) | 0))); }); ");
/*fuzzSeed-451211*/count=921; tryItOut("\"use strict\"; t2 = new Uint16Array(o1.a0);");
/*fuzzSeed-451211*/count=922; tryItOut("/*RXUB*/var r = x; var s = \"\"; print(s.replace(r, (\"\\u66AD\".valueOf(\"number\").throw(15) >>>= r.unwatch((/*RXUE*/new RegExp(\"(?:([^]))\\\\d*\", \"yi\").exec(\"\")) instanceof (Math.hypot(-0,  /x/ )))))); print(r.lastIndex); ");
/*fuzzSeed-451211*/count=923; tryItOut("/*RXUB*/var r = /(?=((?:\\D)))|\\2{1,5}|(?![^]|(?!(?!\\\u5c89{2}))|(?=[^])+?)/gim; var s = \"\\na\\na\\na\\na\\na\\na\\na\\naNa\\na\\na\\na\\na\"; print(uneval(s.match(r))); ");
/*fuzzSeed-451211*/count=924; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + ( + (({x: (function ([y]) { })()}) != mathy3(2**53-2, ( ! Math.asinh((2**53+2 >>> 0))))))); }); testMathyFunction(mathy4, /*MARR*/[5.0000000000000000000000, this.__defineGetter__(\"d\", mathy3), function(){}, function(){}, new Boolean(true),  /x/ , this.__defineGetter__(\"d\", mathy3), function(){}, this.__defineGetter__(\"d\", mathy3), this.__defineGetter__(\"d\", mathy3), 5.0000000000000000000000, 5.0000000000000000000000, this.__defineGetter__(\"d\", mathy3),  /x/ , function(){}, 5.0000000000000000000000, function(){}, function(){}, function(){}, new Boolean(true), this.__defineGetter__(\"d\", mathy3),  /x/ , this.__defineGetter__(\"d\", mathy3), 5.0000000000000000000000,  /x/ , function(){}, 5.0000000000000000000000, new Boolean(true), function(){}, this.__defineGetter__(\"d\", mathy3),  /x/ , 5.0000000000000000000000, new Boolean(true), new Boolean(true),  /x/ , this.__defineGetter__(\"d\", mathy3), this.__defineGetter__(\"d\", mathy3), function(){}, 5.0000000000000000000000, function(){}, 5.0000000000000000000000, new Boolean(true)]); ");
/*fuzzSeed-451211*/count=925; tryItOut("\"use strict\"; Object.defineProperty(this, \"g0.v0\", { configurable: ((uneval( /x/g ))), enumerable: true,  get: function() {  return g0.t0.length; } });/*infloop*/while((x) = \"\\u3D52\"){e1.has(a2);o1 = new Object; }");
/*fuzzSeed-451211*/count=926; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-451211*/count=927; tryItOut("\"use strict\"; this.s0.valueOf = (function() { try { i0.next(); } catch(e0) { } e2.__proto__ = e1; return b2; });");
/*fuzzSeed-451211*/count=928; tryItOut("\"use strict\"; with(let (w) w)o0.f2 + '';function x(c, []) { return x } (false);\nv1 = evaluate(\"print((void version(185)));\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (((decodeURIComponent).call).apply.prototype), noScriptRval: true, sourceIsLazy: true, catchTermination: true, sourceMapURL: s0 }));\n");
/*fuzzSeed-451211*/count=929; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(v2, \"__iterator__\", { configurable: /(?:(?!\\b|.)*)/gi, enumerable: (x % 29 != 26), get: (function() { m1.get(p2); return o2.m0; }), set: (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 36893488147419103000.0;\n    d1 = (d2);\n    return +((((decodeURIComponent)((4277)))));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var nspdqt = x; var pwbfrf = (RegExp.prototype.toString).bind([z1,,]\n, (4277)); return pwbfrf;})()}, new ArrayBuffer(4096)) });");
/*fuzzSeed-451211*/count=930; tryItOut("mathy3 = (function(x, y) { return ((Math.max(( - x), ((Math.imul((x >>> 0), (( + (( + Math.exp(x)) / ( + ( + y)))) >>> 0)) >>> 0) | 0)) | 0) & Math.min(Math.fround((Math.fround((-1/0 / x)) ? Math.fround(( ! Math.hypot(Math.fround(y), (x | 0)))) : Math.fround((Math.asin((y | 0)) | 0)))), (( ! (-0x0ffffffff | 0)) | 0))); }); testMathyFunction(mathy3, [/0/, 0.1, null, (new Number(-0)), [], (new Boolean(true)), '/0/', undefined, ({toString:function(){return '0';}}), (new Boolean(false)), ({valueOf:function(){return '0';}}), NaN, (new Number(0)), 0, [0], (function(){return 0;}), '', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), -0, (new String('')), 1, false, '0', true, '\\0']); ");
/*fuzzSeed-451211*/count=931; tryItOut("g0.m2.delete(g2);");
/*fuzzSeed-451211*/count=932; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - (( ! ( ~ ( + Math.hypot(Math.imul(Math.fround(y), Number.MIN_VALUE), y)))) !== ((( ~ Math.hypot(x, y)) >>> 0) | (Math.fround(((((2**53+2 !== -0) | 0) & ( + ( ~ (x >>> 0)))) | 0)) == (Math.expm1(Math.fround(Math.sqrt(Math.fround(y)))) >>> 0))))); }); ");
/*fuzzSeed-451211*/count=933; tryItOut("/*RXUB*/var r = x; var s = \"\\uae02\"; print(r.exec(s)); ");
/*fuzzSeed-451211*/count=934; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.atan((((( + (y >>> 0)) | 0) | (Math.atan2(y, ( + Math.pow(( + Math.fround(Math.max(y, Math.fround(-Number.MIN_VALUE)))), ( + (x == x))))) | 0)) | 0)); }); ");
/*fuzzSeed-451211*/count=935; tryItOut("t2[v0];");
/*fuzzSeed-451211*/count=936; tryItOut("/*RXUB*/var r = r0; var s = s0; print(uneval(s.match(r))); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
