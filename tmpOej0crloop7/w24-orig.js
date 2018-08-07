

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
/*fuzzSeed-168297596*/count=1; tryItOut("/*oLoop*/for (let rdmpoq = 0; rdmpoq < 22; ++rdmpoq) { (new RegExp(\"\\\\u0020\", \"g\")); } \nfor (var v of i1) { try { Array.prototype.sort.call(a2, (function() { for (var j=0;j<5;++j) { f2(j%4==0); } }), t1); } catch(e0) { } try { t0 = new Float32Array(b0, 19, 19); } catch(e1) { } e2 = t1[17]; }\n");
/*fuzzSeed-168297596*/count=2; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0x1262fef2);\n    d0 = (+((d0)));\n    return +((+((((0xffffffff) ? ((((0xffffffff)*-0xd3924)|0)) : (i1))-(0xc42953c8))>>>((((((((0xffffffff))>>>((0xfef1fce8))) > ((x = \"\\u067D\")))) ^ ((0xffffffff))) > (~((!(0x189eaa91))-((((0x2ad43df0))>>>((0xfef46049))) != (0xfb095447)))))))));\n  }\n  return f; })(this, {ff: String.prototype.slice}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x080000000, 2**53-2, -Number.MIN_VALUE, 2**53, -(2**53-2), 1, Number.MAX_VALUE, Math.PI, 1/0, 0/0, -Number.MAX_VALUE, -0x0ffffffff, 0x100000000, -0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 42, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0, 2**53+2, 0x080000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, 0x080000001, -0x080000001, -(2**53+2), 0, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=3; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-168297596*/count=4; tryItOut("/*oLoop*/for (var jflyvx = 0; jflyvx < 4; ++jflyvx) { print(x); } ");
/*fuzzSeed-168297596*/count=5; tryItOut("print((void options('strict_mode')));v1 = g0.eval(\"(x = this.yoyo(x))\");");
/*fuzzSeed-168297596*/count=6; tryItOut("mathy3 = (function(x, y) { return mathy0(((((( + Math.acosh(( - x))) | 0) ^ Math.pow(Math.min(y, (((x >>> 0) ? (0x100000001 >>> 0) : (Number.MAX_VALUE >>> 0)) >>> 0)), Math.cosh(Number.MIN_VALUE))) % ( + Math.cbrt(Math.imul(Math.imul(y, x), x)))) | 0), ( ! ( + ( - ( + y))))); }); ");
/*fuzzSeed-168297596*/count=7; tryItOut("mathy2 = (function(x, y) { return (mathy1((Math.tanh(((((( + x) >>> 0) | 0) ** ((mathy0((((x >> 1) || y) | 0), (Math.fround(( ! ( + y))) | 0)) >>> 0) | 0)) | 0)) | 0), ((mathy0(Math.fround(( + (( + Math.log2(Math.fround(Math.hypot(y, Math.pow(( + 1), ( + x)))))) >= ((Math.log1p(( ~ y)) >>> 0) >>> 0)))), (Math.ceil(((-0x100000000 | 0) > y)) , Math.atan2(Math.tanh(x), x))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -0x080000001, -0x07fffffff, 2**53, -0x100000001, -0x080000000, 2**53-2, 0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, 0x100000001, 1/0, 42, -0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, 1, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, Math.PI, 0x07fffffff, 0, -1/0, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=8; tryItOut("/*tLoop*/for (let z of /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false)]) { /* no regression tests found */ }");
/*fuzzSeed-168297596*/count=9; tryItOut("testMathyFunction(mathy4, [0.1, (new Boolean(false)), true, false, (new Boolean(true)), (new Number(-0)), null, 1, '/0/', '0', (new Number(0)), (new String('')), '', [0], ({toString:function(){return '0';}}), undefined, /0/, objectEmulatingUndefined(), '\\0', ({valueOf:function(){return 0;}}), (function(){return 0;}), -0, 0, ({valueOf:function(){return '0';}}), NaN, []]); ");
/*fuzzSeed-168297596*/count=10; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.abs(((Math.sinh(( - Math.fround((((y | 0) ** (y | 0)) | 0)))) | 0) | 0)); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -1/0, -(2**53), -0x100000001, 2**53, 1, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, -(2**53-2), 0/0, 42, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, -0x07fffffff, -0x080000001, 2**53+2, 2**53-2, Math.PI, -0x080000000, 1/0, 0x100000001, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, -(2**53+2), 0.000000000000001, 0, -0]); ");
/*fuzzSeed-168297596*/count=11; tryItOut("");
/*fuzzSeed-168297596*/count=12; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((((Math.exp(x) >>> 0) < ((y << Math.imul(( + x), Math.fround(( - x)))) | 0)) | 0) && (Math.imul(( + (x ? mathy2(((Math.fround(x) ? (y >>> 0) : (y >>> 0)) >>> 0), ( ! y)) : x)), (Math.cosh((((Math.atan2(Math.fround(Math.round(x)), (0x100000001 >>> 0)) >>> 0) | 0) * x)) | 0)) | 0)) | 0); }); testMathyFunction(mathy3, [1.7976931348623157e308, 0x080000001, -0x0ffffffff, 0x080000000, -0x07fffffff, 0x07fffffff, -(2**53+2), 2**53+2, 2**53, 2**53-2, -0x080000000, 0x0ffffffff, -(2**53), -1/0, 0.000000000000001, -Number.MIN_VALUE, -0, Number.MIN_VALUE, 0x100000001, -(2**53-2), 0, Number.MIN_SAFE_INTEGER, 42, -0x080000001, Math.PI, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0/0, -Number.MAX_VALUE, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-168297596*/count=13; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=14; tryItOut("\"use strict\"; let w =  '' ;(Object.prototype.unwatch.call(t1, \"\\u3035\"));function a({x: {x: [{this: x, d: {w: {x, NaN}, x}, x}, , {x, x, ((x)): d, w, x: {e: {y, d}}, x}, a, ]}, z, x, x: z, d: [, , , {w: {NaN: [[, [[]], x, []], [, z], [, , {NaN: a, e: w}, ]], x: (\"\\u7A06\" in window), x: {x, x: {c: {window: [], z, x: []}}, b: b}, x: [, [[]], x((arguments = []))], eval: []}, b, NaN, e, b: b}, , [[, , [{z: {x, window: {a, a}}, /*\n*/d: []}, ]], , x, {w, x: eval}, ], {z, window, window}, \u3056]}) { yield ( /x/  >= Math.max(x, ((void options('strict'))))) } g1.m2.set(v0, b0);");
/*fuzzSeed-168297596*/count=15; tryItOut("\"use strict\"; for (var p in o0.o0.m1) { try { Array.prototype.unshift.apply(a2, []); } catch(e0) { } try { /*MXX2*/g1.DFGTrue.name = b0; } catch(e1) { } try { h2.hasOwn = (function() { try { this.a2[({valueOf: function() { ;return 17; }})] =  /x/g ; } catch(e0) { } try { v0 = b0.byteLength; } catch(e1) { } s0 += 'x'; return v0; }); } catch(e2) { } a0.reverse(p2, t2, g0.e2, /*FARR*/[  = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: undefined, set: function() { return false; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { throw 3; }, }; })(this), Symbol)[\"d\"]++, ([] | false), x].some(function shapeyConstructor(hxsnns){\"use strict\"; this[\"13\"] = (-1/0);this[\"toString\"] = ['z'];if (hxsnns) this[\"__proto__\"] = hxsnns;for (var ytqulalfr in this) { }return this; }, this.__defineGetter__(\"x\", (ArrayBuffer = {})))); }");
/*fuzzSeed-168297596*/count=16; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\S\", \"i\"); var s = \"_\"; print(s.split(r)); ");
/*fuzzSeed-168297596*/count=17; tryItOut("\"use strict\"; { void 0; void relazifyFunctions(); }");
/*fuzzSeed-168297596*/count=18; tryItOut("s0 = s0.charAt(\"\\u3ABF\");");
/*fuzzSeed-168297596*/count=19; tryItOut("\"use asm\"; s2 += g2.s0;function \u3056(w) { \"use asm\"; /* no regression tests found */ } (new ((4277))((void shapeOf(new RegExp(\"(\\\\s)\", \"gyim\"))), true));");
/*fuzzSeed-168297596*/count=20; tryItOut("this.v2 = new Number(o1.g0.b0);");
/*fuzzSeed-168297596*/count=21; tryItOut("mathy4 = (function(x, y) { return ( + ( ~ Math.expm1((( ~ ( + ( - y))) >>> 0)))); }); testMathyFunction(mathy4, [-(2**53+2), 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, 1/0, 2**53, 42, -0, Number.MAX_VALUE, 0x080000000, -(2**53-2), -1/0, 0x0ffffffff, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1, -0x080000001, 0.000000000000001, 2**53-2, -0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 0x100000001, -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 0, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=22; tryItOut("\"use strict\"; if(true) { if ( /* Comment */new (new ((Date.prototype.toLocaleTimeString).bind)())()) {print(new (Math.sin)());print(x); }} else print(x);");
/*fuzzSeed-168297596*/count=23; tryItOut("\"use strict\"; {this.m2 = new Map;print(x); }");
/*fuzzSeed-168297596*/count=24; tryItOut("v2 = a2.length;");
/*fuzzSeed-168297596*/count=25; tryItOut("\"use strict\"; for (var p in g1) { e2.delete(o2); }");
/*fuzzSeed-168297596*/count=26; tryItOut("");
/*fuzzSeed-168297596*/count=27; tryItOut("\"use strict\"; selectforgc(o1);function z(a, x, eval, e, window, x = timeout(1800), d, e, x) /x/g t2 = new Int8Array(b1);");
/*fuzzSeed-168297596*/count=28; tryItOut("e0.add(h2);");
/*fuzzSeed-168297596*/count=29; tryItOut("s2.toString = (encodeURIComponent).bind((Math.min(9, (let (x) /*FARR*/[((void options('strict_mode'))), window,  /x/ , d **= x, window, (new \"\\u754D\"(NaN, -11)), ].sort))), (makeFinalizeObserver('nursery')));");
/*fuzzSeed-168297596*/count=30; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.expm1(( + ( ~ ( + y)))) !== mathy1((Math.fround(mathy1(Math.fround(-0x100000000), ( + ( ~ Math.pow(Math.fround(( ! Math.fround(2**53+2))), Number.MAX_VALUE))))) >>> 0), Math.imul(Math.tanh((y | 0)), (Math.fround(Math.fround(Math.log(x))) ? (Math.pow(Math.fround(( ~ y)), y) | 0) : y)))); }); ");
/*fuzzSeed-168297596*/count=31; tryItOut("for([w, z] = x in x) {print(z); }\nm2.has( /x/ );\n");
/*fuzzSeed-168297596*/count=32; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.hypot(Math.imul(mathy0(( + mathy0((Math.hypot((42 >>> 0), (mathy0(x, y) >>> 0)) >>> 0), (((x >>> 0) - (x >>> 0)) | 0))), Math.atan2(( + (-Number.MAX_VALUE >>> y)), -(2**53))), Math.fround((Math.fround(-Number.MAX_SAFE_INTEGER) & Math.fround(Math.cosh((( + mathy0(-0x07fffffff, Math.fround(2**53-2))) ? (( ~ x) >>> 0) : Math.fround(Math.log1p((Math.exp((y >>> 0)) >>> 0))))))))), ( ~ Math.asin(-0x0ffffffff))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -0x0ffffffff, 0/0, -0x07fffffff, 0x080000000, 0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), 1, 2**53-2, -0x100000000, -0x100000001, 0, 1.7976931348623157e308, 2**53, -Number.MIN_SAFE_INTEGER, 42, -0x080000000, -0, -Number.MIN_VALUE, -0x080000001, 0x100000000, Math.PI, 1/0, Number.MIN_VALUE, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-168297596*/count=33; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MAX_VALUE, 2**53-2, 0/0, 0x100000000, Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, 0, 0x0ffffffff, 2**53, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000000, 42, -0x080000001, 1/0, -0x0ffffffff, -0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -0, Math.PI, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2]); ");
/*fuzzSeed-168297596*/count=34; tryItOut("g2.b2.toSource = (function() { for (var j=0;j<15;++j) { o1.f0(j%4==1); } });");
/*fuzzSeed-168297596*/count=35; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.imul((( ! Math.fround(Math.log2(Math.fround(( + ( ! ( + x))))))) >>> 0), (( + ( ! ( + (Math.hypot((( - Math.fround(( - Math.fround(Math.cosh(y))))) >>> 0), ((Math.sin(((y < Math.imul(x, Math.fround(x))) >>> 0)) >>> 0) >>> 0)) | 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 0, -(2**53), 0.000000000000001, 2**53, -(2**53-2), -0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, 1, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, 0x07fffffff, 0x0ffffffff, 2**53+2, -Number.MAX_VALUE, 2**53-2, -0x080000000, 0/0, 1.7976931348623157e308, -0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000001, 0x100000000, 0x080000001, 0x100000001, 42, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=36; tryItOut("/*vLoop*/for (let tetezk = 0; tetezk < 0; ++tetezk) { x = tetezk; -29; } ");
/*fuzzSeed-168297596*/count=37; tryItOut("mathy5 = (function(x, y) { return ((( - Math.fround(( ! Math.log2(( + ((-1/0 % (-0 >>> 0)) >>> 0)))))) && Math.abs(Math.fround(( - y)))) && (Math.fround(mathy1((Math.imul(x, y) >>> 0), ( + ( ~ (0x100000000 | 0))))) / ( + mathy2(( + (Math.hypot(Math.imul(( + Math.min(x, ( + 0.000000000000001))), y), (( + (y >>> 0)) >>> 0)) <= mathy0(Math.fround(( + ( + ( + -0x080000000)))), ( + Math.atan2(( + x), ( + x)))))), ( + 2**53+2))))); }); testMathyFunction(mathy5, [-0x0ffffffff, 0x100000001, 2**53-2, 0x0ffffffff, 2**53, 0x080000001, 0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, 42, 0, 0x100000000, -1/0, -0x080000000, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 0x07fffffff, -(2**53), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -Number.MAX_VALUE, 1, -(2**53-2), -0x100000001, -0, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=38; tryItOut("\"use strict\"; e0.__iterator__ = (function() { for (var j=0;j<16;++j) { f1(j%3==0); } });");
/*fuzzSeed-168297596*/count=39; tryItOut("v1 = g0.eval(\"g2.h2.getOwnPropertyNames = (function(j) { if (j) { try { print(f2); } catch(e0) { } try { Array.prototype.shift.apply(a1, []); } catch(e1) { } try { e2.add(h0); } catch(e2) { } for (var v of e2) { try { yield 27; } catch(e0) { } try { s0.valueOf = (function() { for (var j=0;j<153;++j) { f2(j%3==1); } }); } catch(e1) { } try { v0 = (o2.p0 instanceof o0); } catch(e2) { } Array.prototype.push.call(a0, g1, o2.i0); } } else { try { for (var p in g2.f2) { selectforgc(o1); } } catch(e0) { } a1.sort((function() { try { g0.m0.set(p2, b0); } catch(e0) { } try { /*MXX1*/o2 = g0.Float64Array.prototype.constructor; } catch(e1) { } for (var v of e0) { try { h0.fix = f0; } catch(e0) { } try { v0 = evaluate(\\\"mathy3 = (function(x, y) { \\\\\\\"use strict\\\\\\\"; return (Math.trunc((((( + ( + Math.tan(( + Math.imul(Math.fround((x | x)), x))))) <= Math.fround(( - Math.fround(( ~ Math.PI))))) , (Math.imul(y, ((( ~ y) != (x > (Math.PI | 0))) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [42, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, 0/0, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, 0x080000000, -0x100000001, -(2**53), Number.MIN_VALUE, -0x100000000, -(2**53-2), Math.PI, -Number.MIN_VALUE, -1/0, 2**53-2, -0x080000001, 0x100000001, 1/0, 0x0ffffffff, 0x080000001, -0]); \\\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 8 == 6), sourceIsLazy: false, catchTermination: -12 })); } catch(e1) { } try { i0 + ''; } catch(e2) { } s0 += 'x'; } return s0; }), m1); } });\");");
/*fuzzSeed-168297596*/count=40; tryItOut("");
/*fuzzSeed-168297596*/count=41; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=42; tryItOut("m2 + b2;");
/*fuzzSeed-168297596*/count=43; tryItOut("");
/*fuzzSeed-168297596*/count=44; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=45; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=46; tryItOut("/*RXUB*/var r = /(\\2*?|[^\\cH\\cO-V]*?)(((\\1)))/y; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-168297596*/count=47; tryItOut("mathy3 = (function(x, y) { return (Math.min((( - (Math.atan2(mathy1(Math.max(((-0 >>> 0) / ( + x)), ((x - (1 >>> 0)) >>> 0)), (0x080000000 == x)), Math.fround(Math.imul((y >>> 0), (y >>> 0)))) >>> 0)) >>> 0), ( + ((Math.fround(Math.sign(Math.fround(y))) | 0) ? ( ! y) : Math.fround(( + mathy1(( + y), Math.fround(Math.min((-1/0 | 0), 2**53+2)))))))) !== ( ! ( ~ Math.fround((Math.fround((mathy1((-0x0ffffffff >>> 0), (y | 0)) >>> 0)) & Math.fround(-1/0)))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x0ffffffff, 0x080000000, -0x0ffffffff, Math.PI, 0/0, -0, 42, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 2**53-2, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, 1, 0x100000001, -0x080000000, -0x100000001, 0.000000000000001, 0, 2**53, -(2**53+2), -1/0, 0x080000001, 0x100000000, -0x080000001]); ");
/*fuzzSeed-168297596*/count=48; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul(Math.fround(( - Math.fround(Math.tan(Number.MAX_SAFE_INTEGER)))), Math.fround((((Math.pow((( + (( + Math.max(x, x)) - ( + y))) , ((y >>> 0) ? -Number.MAX_VALUE : (( - (y >>> 0)) >>> 0))), Math.clz32((Math.fround(Math.fround(0x100000000)) | 0))) >>> 0) * (Math.fround((Math.fround(Math.log1p((Math.imul(y, Math.fround(mathy0(x, 42))) >>> 0))) ? y : -Number.MAX_SAFE_INTEGER)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-168297596*/count=49; tryItOut("\"use strict\"; v2 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-168297596*/count=50; tryItOut("mathy3 = (function(x, y) { return ((Math.fround(Math.expm1(Math.fround(( + ( ! ( + Math.fround(( - Math.fround(( ~ ( + x))))))))))) != (mathy2((Math.asin(Math.fround((((((0x0ffffffff >>> 0) && Math.fround(Math.fround((Math.fround(Math.fround((Math.fround(Number.MIN_VALUE) ? Math.fround(x) : Math.fround(y)))) == Math.fround(y))))) >>> 0) | 0) ^ (( ! x) | 0)))) >>> 0), ((-1/0 & Math.atan2((( ~ x) >>> 0), (Math.fround((Math.fround(x) | Math.fround(y))) | 0))) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=51; tryItOut("{ void 0; void gc('compartment', 'shrinking'); }");
/*fuzzSeed-168297596*/count=52; tryItOut("{print(Math.pow(/(?!\\x5d*?)*/im, [,,])); }");
/*fuzzSeed-168297596*/count=53; tryItOut("\"use strict\"; v1.toString = Object.setPrototypeOf;");
/*fuzzSeed-168297596*/count=54; tryItOut("/*bLoop*/for (iginwd = 0; iginwd < 32; ++iginwd, -12) { if (iginwd % 5 == 0) { m2 + v0; } else { v0 = a2.length; }  } function x() { return   = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { throw 3; }, has: function() { throw 3; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { throw 3; }, iterate: false, enumerate: function() { return []; }, keys: function() { return []; }, }; })(true), yield  \"\" ) } a0.sort(f2, s2, o1);");
/*fuzzSeed-168297596*/count=55; tryItOut("o2.o2.h0 = ({getOwnPropertyDescriptor: function(name) { /*ADP-1*/Object.defineProperty(a2, ({valueOf: function() { /*RXUB*/var r = new RegExp(\"(?!\\\\B)?(?:(?=\\\\b{4,}.|\\\\u0045\\\\0+(?:[^\\\\s]){3}|(?!.{131072}){1,}|\\\\b))\", \"gm\"); var s = -15; print(r.test(s)); print(r.lastIndex); return 10; }}), ({}));; var desc = Object.getOwnPropertyDescriptor(p2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v0 = (i2 instanceof o2);; var desc = Object.getPropertyDescriptor(p2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { for (var v of s1) { try { for (var v of h0) { try { for (var p in t1) { try { for (var p in g2) { try { Object.prototype.unwatch.call(this.i0, \"includes\"); } catch(e0) { } try { v2 = (o0.b0 instanceof i2); } catch(e1) { } s0 += s2; } } catch(e0) { } for (var p in m2) { try { m2.set(a0, o2.b2); } catch(e0) { } try { v2[6] = t1; } catch(e1) { } v0 = g0.runOffThreadScript(); } } } catch(e0) { } m1 = a1[15]; } } catch(e0) { } for (var v of v0) { for (var p in o1) { try { h2.enumerate = (function() { for (var j=0;j<1;++j) { f1(j%4==1); } }); } catch(e0) { } try { /*ADP-3*/Object.defineProperty(a0, 16, { configurable: (x % 73 != 34), enumerable: 4 + /\\b[]/im, writable: false, value: this.p2 }); } catch(e1) { } this.m2 = new Map; } } }; Object.defineProperty(p2, name, desc); }, getOwnPropertyNames: function() { ;; return Object.getOwnPropertyNames(p2); }, delete: function(name) { s2 += 'x';; return delete p2[name]; }, fix: function() { return o0.p1; if (Object.isFrozen(p2)) { return Object.getOwnProperties(p2); } }, has: function(name) { v2 = (m1 instanceof g0.o1.o1);; return name in p2; }, hasOwn: function(name) { return a0; return Object.prototype.hasOwnProperty.call(p2, name); }, get: function(receiver, name) { m1 + o0;; return p2[name]; }, set: function(receiver, name, val) { this.m1.toString = (function mcc_() { var qcrypp = 0; return function() { ++qcrypp; g2.f1(/*ICCD*/qcrypp % 11 == 0);};})();; p2[name] = val; return true; }, iterate: function() { h1.toString = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((((144115188075855870.0)) % ((+((1.9342813113834067e+25))))));\n  }\n  return f; })(this, {ff: x.toString}, new SharedArrayBuffer(4096));; return (function() { for (var name in p2) { yield name; } })(); }, enumerate: function() { /*ODP-3*/Object.defineProperty(i0, -11, { configurable: (x % 49 == 17), enumerable: (x % 5 == 0), writable: x, value: p0 });; var result = []; for (var name in p2) { result.push(name); }; return result; }, keys: function() { this.o1.a2 = new Array;; return Object.keys(p2); } });");
/*fuzzSeed-168297596*/count=56; tryItOut("a1[8] = ({x: {x: [x], x, w, w: []}}) = arguments instanceof (4277);");
/*fuzzSeed-168297596*/count=57; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[eval, eval, eval, eval, eval]); ");
/*fuzzSeed-168297596*/count=58; tryItOut("this.v1 = false;");
/*fuzzSeed-168297596*/count=59; tryItOut("testMathyFunction(mathy3, /*MARR*/[new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), encodeURI, encodeURI, new String('q'), objectEmulatingUndefined(), encodeURI, encodeURI, new String('q'), objectEmulatingUndefined(), encodeURI, objectEmulatingUndefined(), encodeURI, new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), encodeURI, new String('q'), objectEmulatingUndefined(), encodeURI, objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), encodeURI, encodeURI, encodeURI, encodeURI, new String('q'), new String('q'), encodeURI, new String('q'), encodeURI, encodeURI, encodeURI, new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), encodeURI, new String('q'), encodeURI, objectEmulatingUndefined(), encodeURI, encodeURI, encodeURI, encodeURI, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), new String('q')]); ");
/*fuzzSeed-168297596*/count=60; tryItOut("\"use strict\"; ( \"\" );");
/*fuzzSeed-168297596*/count=61; tryItOut("\"use strict\"; Array.prototype.shift.call(a2, a1, m2, o2.b1);");
/*fuzzSeed-168297596*/count=62; tryItOut("\"use strict\"; /*RXUB*/var r = /((?!(\\b|.|\\b)*(?!\u001b){0})|(?=(?!.)((?:^)|\\D|\\B?+)))/yim; var s = (4277); print(s.match(r)); ");
/*fuzzSeed-168297596*/count=63; tryItOut("\"use strict\"; p0 + a0;");
/*fuzzSeed-168297596*/count=64; tryItOut("/*tLoop*/for (let w of /*MARR*/[function(){}, [(void 0)], [(void 0)], [(void 0)], objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), [(void 0)], [(void 0)], (void 0), [(void 0)], (void 0), objectEmulatingUndefined(), [(void 0)], (void 0), [(void 0)], [(void 0)], objectEmulatingUndefined(), [(void 0)], function(){}, [(void 0)], [(void 0)], (void 0), objectEmulatingUndefined(), [(void 0)], [(void 0)], [(void 0)], (void 0), objectEmulatingUndefined(), function(){}, function(){}, (void 0), (void 0), objectEmulatingUndefined(), function(){}]) { print(w); }this.v1 = this.g0.runOffThreadScript();");
/*fuzzSeed-168297596*/count=65; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=66; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.abs(( ! Math.fround(Math.hypot((( + (x ** Math.atan2(y, 2**53-2))) < x), (( - -0) >>> 0))))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, (-1/0), (-1/0), x, (-1/0), function(){}, (-1/0), function(){}, (-1/0), (-1/0), (-1/0), function(){}, (-1/0)]); ");
/*fuzzSeed-168297596*/count=67; tryItOut("i0 = new Iterator(p1, true);");
/*fuzzSeed-168297596*/count=68; tryItOut("f1(t1);return x;");
/*fuzzSeed-168297596*/count=69; tryItOut("\"use strict\"; print(({ set BYTES_PER_ELEMENT z (window, x, x, x, z, x, x = window, c, window, x = false, x =  \"\" , eval, x, x, d, b = new RegExp(\"(?=(?:(?:\\\\d?)(?!\\\\b))^(?=[^\\\\\\u000f-\\\\u0060\\\\S]?){3}*?)\", \"\"), b, w, eval, b, x = true, e, z, z, c, x, x, d, x, x, c, x, x, w, e, a =  /x/ , z, x, eval, x, d, \u3056, x, x, e, x, y =  '' , y = \"\\u4775\", x, c, \u3056, w, x, x, 0, x, x = new RegExp(\"[^\\\\b-\\\\cO\\u3f26\\\\u0074].|\\\\2{4}|(?![^]){2,}\", \"m\"), eval, let = true, x, e, x, x, b, d, z, z, z, x, c) { yield x } , \"9\":  \"\"  }).__defineSetter__(\"w\", (\"\\u549E\").call))\n");
/*fuzzSeed-168297596*/count=70; tryItOut("h2 + '';");
/*fuzzSeed-168297596*/count=71; tryItOut("mathy1 = (function(x, y) { return (Math.fround(( + (( + Math.atan2(( ! mathy0(( + ( + ( - (Math.asinh(y) | 0)))), Math.fround(x))), x)) == ( + Math.fround(x))))) | 0); }); ");
/*fuzzSeed-168297596*/count=72; tryItOut("for (var v of p1) { a1.__proto__ = t1; }");
/*fuzzSeed-168297596*/count=73; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( + (Math.imul((Math.hypot((Math.atanh(( - Math.max((Math.fround(y) >> x), (x || x)))) | 0), ( + Math.fround(Math.cbrt(Math.fround(( + Math.log10(( + ((x , y) >>> 0))))))))) | 0), ((Math.imul((Math.min(((x | Math.fround(Math.abs(y))) >>> 0), -Number.MIN_SAFE_INTEGER) >>> 0), (Math.fround(Math.min(Math.fround(y), (Math.fround(Math.imul((Math.max(-Number.MIN_VALUE, y) | 0), 1.7976931348623157e308)) >>> 0))) >>> 0)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy0, [0x100000001, Math.PI, 0x07fffffff, 0.000000000000001, 2**53+2, Number.MAX_VALUE, 2**53, -(2**53+2), -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, -0x100000001, -0x080000000, 1/0, 0, -0x07fffffff, -(2**53-2), 0x100000000, 42, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, 0/0, 0x0ffffffff, -1/0, -0x0ffffffff, 0x080000001, 1]); ");
/*fuzzSeed-168297596*/count=74; tryItOut("if(true) { if (new RegExp(\"(.)\", \"\")) {Array.prototype.sort.apply(a0, [(function mcc_() { var fvkbqo = 0; return function() { ++fvkbqo; if (/*ICCD*/fvkbqo % 2 == 1) { dumpln('hit!'); try { v1 = evalcx(\"function f1(g0.v2)  { (void schedulegc(g2)); } \", g1.g2); } catch(e0) { } try { f1 = Proxy.createFunction(h2, f0, f2); } catch(e1) { } v2 = (v0 instanceof a2); } else { dumpln('miss!'); print(uneval(g0.o1.a0)); } };})(), i0, f0]);a2 = []; } else window =  \"\" , window, this.c, \u3056, x, shqgyo, x;print(x);}");
/*fuzzSeed-168297596*/count=75; tryItOut("mathy5 = (function(x, y) { return ( + ( ~ Math.fround((( + (((mathy3((Math.cos(0x100000000) >>> 0), (y >>> 0)) >>> 0) ** Math.atan2(Math.fround(x), Math.atan2((0 >>> 0), x))) << ( - Math.fround(Math.fround((( + (( + x) <= ((y >>> y) | 0))) ? Math.fround(( ~ x)) : Math.fround(x))))))) === ( + Math.fround(( ! Math.fround(Math.exp(( + mathy2(((x | ((((0x07fffffff >>> 0) - (x >>> 0)) >>> 0) >>> 0)) | 0), ( + Math.cbrt(x))))))))))))); }); ");
/*fuzzSeed-168297596*/count=76; tryItOut("\"use strict\"; ;");
/*fuzzSeed-168297596*/count=77; tryItOut("\"use strict\"; p2.valueOf = (function() { for (var j=0;j<21;++j) { f2(j%4==1); } });");
/*fuzzSeed-168297596*/count=78; tryItOut("\"use strict\"; i2.next();");
/*fuzzSeed-168297596*/count=79; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.fround((Math.max(Math.cbrt(y), ( ~ x)) * ( ! Math.min((Math.pow((x >>> 0), ((Math.fround(x) != Math.fround(x)) >>> 0)) >>> 0), (Math.fround(( ! Math.fround(\"\\u65DF\"))) >>> 0)))))); }); testMathyFunction(mathy2, [0x100000001, -1/0, -0x100000000, -(2**53+2), -0x0ffffffff, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 0.000000000000001, 2**53+2, 0/0, -0x07fffffff, 1, 0, -0, 1.7976931348623157e308, Math.PI, 1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, Number.MIN_VALUE, 2**53, 0x07fffffff, -0x080000001, -Number.MIN_VALUE, -0x100000001, 0x100000000, -0x080000000, 2**53-2, -Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=80; tryItOut("\"use strict\"; p0 + i0;");
/*fuzzSeed-168297596*/count=81; tryItOut("h1.hasOwn = (function mcc_() { var nqvada = 0; return function() { ++nqvada; if (/*ICCD*/nqvada % 2 == 0) { dumpln('hit!'); try { b2 = new SharedArrayBuffer(48); } catch(e0) { } i1 = new Iterator(o1.o2); } else { dumpln('miss!'); try { t2 = t0.subarray((/*RXUE*//(?:[\u97fb\\[-\ucbe9\\D\\xB9-\u00e7])/im.exec(1))); } catch(e0) { } try { g2.o0.e2.has(v2); } catch(e1) { } for (var p in this.s1) { e1.add(x); } } };})();");
/*fuzzSeed-168297596*/count=82; tryItOut("testMathyFunction(mathy2, /*MARR*/[null, null, null, (0x50505050 >> 1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (0x50505050 >> 1), null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, 3/0, null, 3/0, null, 3/0, (0x50505050 >> 1), (0x50505050 >> 1), (void 0), (0x50505050 >> 1), (void 0), null, 3/0, objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), null, (void 0), null, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, 3/0, objectEmulatingUndefined(), objectEmulatingUndefined(), 3/0, null, null, (void 0), null]); ");
/*fuzzSeed-168297596*/count=83; tryItOut("f2 = m2.get(g0.a0);\n/*bLoop*/for (let xoklzg = 0, this << x; xoklzg < 80; ++xoklzg) { if (xoklzg % 16 == 15) { v1 = Object.prototype.isPrototypeOf.call(h2, h2); } else { \u000cfor([e, e] = 10 += new RegExp(\"(?:[^\\\\u99F5O-\\u0108]|\\\\D)+|(?=\\u0209)|\\\\D(?=(?!.)\\\\3)|(?:(?![^]))+\", \"yim\") in  \"\" ) for (var v of t2) { m0.set(this.m1, e2); } }  } \n");
/*fuzzSeed-168297596*/count=84; tryItOut("{print((makeFinalizeObserver('nursery')));a0[1] = (void options('strict')); }");
/*fuzzSeed-168297596*/count=85; tryItOut("do {e0.add(this.o1); } while((/*UUV1*/(z.isFinite = (let (e=eval) e))) && 0);");
/*fuzzSeed-168297596*/count=86; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-168297596*/count=87; tryItOut("g2.a0.splice(NaN, 5, v1);");
/*fuzzSeed-168297596*/count=88; tryItOut("s2 += g2.s2;");
/*fuzzSeed-168297596*/count=89; tryItOut("\"use strict\"; this.e0.has(m0);");
/*fuzzSeed-168297596*/count=90; tryItOut("\"use strict\"; L:if((4277)) { if ((4277)) {v2 = Object.prototype.isPrototypeOf.call(o2, e1); }} else {s1 += 'x'; }");
/*fuzzSeed-168297596*/count=91; tryItOut("mathy5 = (function(x, y) { return (((Math.cbrt(Math.fround(Math.imul(Math.fround((( ! (Math.acosh(y) | 0)) >>> 0)), Math.fround(((x >= (x ? (x | 0) : x)) === Math.acosh(y)))))) | 0) ** (((Math.ceil(((mathy4(( + x), ( + (x , Math.fround(x)))) | 0) >>> 0)) >>> 0) ** y) ** Math.fround(Math.atan2(Math.fround(( + ( ~ Math.fround(Math.fround(Math.log10(Math.fround(1/0))))))), Math.fround(( + Math.fround((-(2**53-2) ^ x)))))))) >>> 0); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 0, 0x080000001, -(2**53), -(2**53-2), Math.PI, -0, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -1/0, 0/0, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, -0x080000000, 0x080000000, 0x100000001, 0x100000000, 0.000000000000001, Number.MIN_VALUE, 1/0, 1, -(2**53+2), 42, -0x07fffffff, 2**53-2, 0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=92; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.pow((( + ((x | 0) >>> ( + Math.atan2(y, y)))) | 0), (Math.tanh((( ~ (Math.fround(Math.atan2(Math.fround(((y >> (2**53+2 | 0)) | 0)), Math.fround((x / (y >>> 0))))) | 0)) >>> 0)) | 0)) | 0) != (Math.log1p((mathy2(((( - ( - (0x100000001 != x))) | 0) | 0), Math.sin((( + (( + (Number.MAX_VALUE >>> 0)) | 0)) | 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-(2**53), 0x080000000, 0, 0/0, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -(2**53+2), 0.000000000000001, 42, -0x080000001, 2**53-2, 1.7976931348623157e308, 1/0, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 2**53+2, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, -0x080000000, -0x100000000, -(2**53-2), -0, Number.MIN_VALUE, -1/0, 0x100000000, -Number.MAX_VALUE, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=93; tryItOut("\"use strict\"; /*RXUB*/var r = /\\3/ym; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=94; tryItOut("\"use strict\"; x;");
/*fuzzSeed-168297596*/count=95; tryItOut("\"use strict\"; for (var p in v1) { try { /*MXX3*/g1.String.prototype.padEnd = g2.String.prototype.padEnd; } catch(e0) { } m1.delete(v0); }");
/*fuzzSeed-168297596*/count=96; tryItOut("v0 = g0.runOffThreadScript();");
/*fuzzSeed-168297596*/count=97; tryItOut("o2 = new Object;function eval(z, c =  '' ) { yield true } g0.i2 = e1.values;");
/*fuzzSeed-168297596*/count=98; tryItOut("let (y) { ( /x/ ); }");
/*fuzzSeed-168297596*/count=99; tryItOut("for (var p in a0) { try { p2 + o0; } catch(e0) { } try { delete h0.has; } catch(e1) { } try { print(g1); } catch(e2) { } v2 = o2[\"toLocaleString\"]; }var a = z >>= delete;");
/*fuzzSeed-168297596*/count=100; tryItOut("x;s1 += s2;");
/*fuzzSeed-168297596*/count=101; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround((((x !== y) / Math.log(((( ! ((Math.log10(x) | 0) >>> 0)) >>> 0) >>> 0))) - ( + Math.atanh(Math.pow(mathy0((((y | 0) ? (y | 0) : (( ! (((x | 0) ** ( + Number.MAX_SAFE_INTEGER)) | 0)) | 0)) | 0), y), Math.min(y, y)))))); }); ");
/*fuzzSeed-168297596*/count=102; tryItOut("{ void 0; void gc(this); } print(e);function x() { h1 = {};\u0009 } print(new -6(window));");
/*fuzzSeed-168297596*/count=103; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=104; tryItOut("\"use asm\"; ");
/*fuzzSeed-168297596*/count=105; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((((i0)+(!(-0x8000000)))>>>(((-1048577.0) >= (-1.001953125)))));\n    {\n      (Float32ArrayView[1]) = (((0.eval(\"/* no regression tests found */\"))));\n    }\n    i0 = (i0);\n    i0 = (i0);\n    d1 = (+(1.0/0.0));\n    switch ((-0x8000000)) {\n    }\n    (Float64ArrayView[1]) = ((-7.737125245533627e+25));\n    d1 = (d1);\n    return (((((0x52756f59)) ? (i0) : (!(0x43aef283)))))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x07fffffff, 0.000000000000001, -(2**53), 2**53+2, 1/0, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, -0x100000000, -(2**53-2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 2**53-2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, -Number.MAX_VALUE, 2**53, 0, -0, 1, -0x0ffffffff, 0x0ffffffff, -(2**53+2), -0x080000000, -1/0, 0x080000001, 42, 0x100000000]); ");
/*fuzzSeed-168297596*/count=106; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + (mathy4(Math.fround(( ! Math.fround(( + Math.pow(x, ( + Math.fround((y ? ( + y) : Math.fround(((Math.sqrt((y | 0)) | 0) !== x)))))))))), ( + Math.max(2**53-2, Math.imul(y, y)))) - ( + (Math.exp((Math.imul(( + (mathy4((((x | 0) , x) | 0), ((Math.sinh((mathy3(Math.fround(x), Math.fround(y)) >>> 0)) >>> 0) | 0)) | 0)), ( + mathy4(y, (x | 0)))) >>> 0)) | 0)))); }); ");
/*fuzzSeed-168297596*/count=107; tryItOut("testMathyFunction(mathy2, [-0x0ffffffff, 0, -0, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 1/0, -Number.MAX_VALUE, -1/0, 0x100000000, 0x07fffffff, -0x080000000, -0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 0x080000001, 2**53-2, -Number.MIN_VALUE, -(2**53), Math.PI, 0x100000001, -0x100000001, 0x0ffffffff, 2**53+2, Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1, 0/0, 0.000000000000001, 1.7976931348623157e308, 42]); ");
/*fuzzSeed-168297596*/count=108; tryItOut("\"use strict\"; print(uneval(g0.g1));");
/*fuzzSeed-168297596*/count=109; tryItOut("v2 = Object.prototype.isPrototypeOf.call(p2, e2);");
/*fuzzSeed-168297596*/count=110; tryItOut("\"use strict\"; i2 = new Iterator(m1, true);");
/*fuzzSeed-168297596*/count=111; tryItOut("\"use strict\"; m2.set(e2, p2);");
/*fuzzSeed-168297596*/count=112; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-168297596*/count=113; tryItOut(";/\\3|(?!\\D){1,5}+?/;");
/*fuzzSeed-168297596*/count=114; tryItOut("let \u3056, z, window, window = window >= window, z = Math.min(10, -2653591565);/*RXUB*/var r = /(?=(?=\\1){2})/; var s = \"\"; print(s.split(r)); \n/*oLoop*/for (let ewlgcx = 0, rbkmwa; ( /x/g ) && ewlgcx < 3; ++ewlgcx) { v2 = g0.runOffThreadScript(); } \n");
/*fuzzSeed-168297596*/count=115; tryItOut("krcmmn();/*hhh*/function krcmmn(){with({y: this}){v0 = (i2 instanceof p1);{} }}");
/*fuzzSeed-168297596*/count=116; tryItOut("/*RXUB*/var r = /\\b*?(?=[\u6b3e\\D][^\\0>\\u00Ff\\s]?)|[^]*?{4}/i; var s = \"\\u0008\\u0008\\u0008\\u0008\\uf416\\u0008\\uf416\\u0008\\uf416\\u0008\\uf416\"; print(r.exec(s)); ");
/*fuzzSeed-168297596*/count=117; tryItOut("");
/*fuzzSeed-168297596*/count=118; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=119; tryItOut("mathy3 = (function(x, y) { return Math.log(Math.imul(( + (y >>> 0)), ( - y))); }); ");
/*fuzzSeed-168297596*/count=120; tryItOut("\"use strict\"; t0.valueOf = (function() { try { g1.t1.toSource = (function() { p0.__proto__ = g2.g0.m0; return f2; }); } catch(e0) { } try { i0.send(o0.e2); } catch(e1) { } o2 = Object.create(i2); return o0.m2; });");
/*fuzzSeed-168297596*/count=121; tryItOut("\"use asm\"; v0 = r1.source;");
/*fuzzSeed-168297596*/count=122; tryItOut("/*bLoop*/for (var dmuvkf = 0, stkptc; dmuvkf < 16; ++dmuvkf) { if (dmuvkf % 6 == 4) { 19; } else { v0 = r1.sticky; }  } ");
/*fuzzSeed-168297596*/count=123; tryItOut("a0 = arguments;");
/*fuzzSeed-168297596*/count=124; tryItOut("a0.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = 4 * a10; var r1 = a9 ^ a4; var r2 = a9 & a9; var r3 = a2 ^ a11; var r4 = 3 | 1; a5 = a3 * a9; var r5 = 6 / r2; a10 = a5 % 0; var r6 = r0 | 3; var r7 = a5 ^ 9; var r8 = r6 & 0; var r9 = a7 % 1; print(r1); r8 = r5 | a0; var r10 = r3 ^ a9; r3 = a5 - a1; var r11 = 6 - a9; var r12 = 3 * a8; var r13 = r5 * x; var r14 = 2 & a5; print(r4); print(a11); var r15 = r4 + 3; var r16 = 9 ^ a10; var r17 = a5 - r16; var r18 = r1 * 1; print(r4); var r19 = r5 - r7; var r20 = r18 * r12; var r21 = r13 & r8; var r22 = 5 + a1; var r23 = 4 * a10; a10 = a3 - 1; var r24 = 3 + a0; r16 = a11 & 5; var r25 = r18 + a9; var r26 = r22 ^ a1; r3 = 4 & a11; var r27 = 0 - r20; var r28 = a0 % r5; r5 = r6 * r3; var r29 = r10 & 4; var r30 = a7 - 5; var r31 = a9 + a10; var r32 = a12 + a11; r4 = r22 ^ a10; var r33 = r7 - x; var r34 = r32 | r31; r22 = r2 + r29; r4 = r20 & r4; print(r0); r12 = r9 / r2; var r35 = r34 / r16; var r36 = 7 % 9; var r37 = 8 + 0; a2 = r25 & 7; r36 = r20 ^ a7; var r38 = 1 | 1; r29 = r9 - 4; r25 = r4 % 1; r6 = r7 | 8; var r39 = r19 - 8; var r40 = r37 + a8; r2 = r11 & r31; var r41 = 6 | r12; var r42 = r18 / r1; var r43 = r10 % 7; var r44 = 4 - r15; var r45 = 6 & r20; return a0; });");
/*fuzzSeed-168297596*/count=125; tryItOut("{a1.pop();e1.add(b0); }for (var p in s1) { try { g1 + g0; } catch(e0) { } try { e1.add(s0); } catch(e1) { } try { /*ADP-2*/Object.defineProperty(a0, 3, { configurable: false, enumerable: true, get: f2, set: encodeURIComponent }); } catch(e2) { } (void schedulegc(g2)); }");
/*fuzzSeed-168297596*/count=126; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( - ( + ((( + ((Math.log2((Math.pow(y, ((x / y) | 0)) | 0)) >>> 0) ? x : ( + ((((Math.round(Math.PI) >>> 0) ? (0x080000001 >>> 0) : (x >>> 0)) >>> 0) ? -0x100000001 : ( ~ 0/0))))) - ( + (Math.fround(((y >= Math.fround(mathy4(x, 0))) !== Math.fround(Math.fround(mathy3(Math.fround(x), Math.fround(x)))))) | Math.sinh((Math.atan2(y, (x | 0)) | 0))))) >>> 0)))); }); ");
/*fuzzSeed-168297596*/count=127; tryItOut("a0.shift();");
/*fuzzSeed-168297596*/count=128; tryItOut("/*oLoop*/for (wowjlm = 0; wowjlm < 0; ++wowjlm) { v1 = (o1.a2 instanceof t2); } ");
/*fuzzSeed-168297596*/count=129; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + Math.atan2(Math.atan2(Math.fround(Math.imul(Math.fround(x), Math.fround(y))), (( + Math.pow(x, 42)) | 0)), Math.fround(Math.fround(( ! y))))) != Math.fround((Math.round(((Math.cosh((( + ( ! y)) >>> 0)) >>> 0) < (y < Number.MAX_VALUE))) << Math.fround(Math.sqrt(Math.fround(-0))))))); }); testMathyFunction(mathy4, [2**53+2, -0x100000001, 0x080000001, -0x080000000, Math.PI, 0, -(2**53), -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53, -0, -0x100000000, 0x080000000, -1/0, 0x07fffffff, -Number.MIN_VALUE, -0x07fffffff, -0x080000001, 1.7976931348623157e308, 1, 0/0, 0x100000001, 0x0ffffffff, -(2**53-2), -0x0ffffffff, 2**53-2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, 42, 1/0]); ");
/*fuzzSeed-168297596*/count=130; tryItOut("/*bLoop*/for (var uogsbt = 0; uogsbt < 89; ++uogsbt) { if (uogsbt % 22 == 5) { print(uneval(v2)); } else { g2.offThreadCompileScript(\"v2 = evalcx(\\\"/* no regression tests found */\\\", g1);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 94 == 9), catchTermination: true, element: o1, elementAttributeName: s0, sourceMapURL: g0.o1.g1.s0 })); }  } ");
/*fuzzSeed-168297596*/count=131; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.fround(Math.min(Math.fround((mathy1(( + (( ~ Math.fround(Math.pow(x, x))) + Math.fround(0/0))), (Math.fround(Math.log10(Math.fround(Math.PI))) ? y : ( ~ y))) | 0)), Math.fround(Math.fround((Math.fround(Math.fround((0x100000000 ? Math.sinh(( + x)) : x))) % ( + Math.sinh(( + x)))))))) | 0) , (Math.tan((Math.cos(( + Math.pow(( + Math.acos((Math.fround(Math.atan2(Math.fround(y), y)) / 1))), (Math.fround(Math.imul(x, ( + (y / (( + (0 | 0)) | 0))))) | 0)))) | 0)) | 0)); }); testMathyFunction(mathy2, [-0x080000000, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, 42, 0, 0x080000000, 1/0, 0x0ffffffff, -0x0ffffffff, -1/0, 0x080000001, -(2**53-2), 0.000000000000001, Math.PI, -0x100000001, -0x100000000, Number.MAX_VALUE, 2**53+2, 2**53-2, 0x100000001, Number.MIN_VALUE, 0/0, -(2**53), 0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -0x080000001, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=132; tryItOut("m1.has(p2);");
/*fuzzSeed-168297596*/count=133; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-168297596*/count=134; tryItOut("/*bLoop*/for (var pcrhqa = 0; pcrhqa < 57 && (( \"\" .throw(/(?!\\\uc26f)|(?:(?:(?:[^\\u00B2f-\u00bd\\\ub5d8]|\\b)?))|(\\2)[\\x10\\s]{2}[^\u036d-\u6ef6\\w]/))); ++pcrhqa) { if (pcrhqa % 8 == 6) { v0 = Array.prototype.every.apply(a0, [(function() { e0.add(h0); return v2; })]); } else { print(x); }  } ");
/*fuzzSeed-168297596*/count=135; tryItOut("let (w) { z = eval;let(qgdvmw, pwopoe) ((function(){with({}) { throw b; } })()); }");
/*fuzzSeed-168297596*/count=136; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -2305843009213694000.0;\n    var d3 = 35184372088833.0;\n    return (((0xe5c6045b)+(0x7dd682fd)))|0;\n    switch ((((0xdc0d84ec)) ^ ((0x0) / (0xffffffff)))) {\n      case 1:\n        d3 = (d1);\n        break;\n      case -1:\n        {\n          d3 = (((d0)) / ((d1)));\n        }\n        break;\n      default:\n        d1 = (d0);\n    }\n    {\n      d3 = (d0);\n    }\n    d3 = (((d3)) % ((+(1.0/0.0))));\n    d1 = (d2);\n    d2 = (d0);\n    return (((/*UUV1*/(d.setDate = q => q))*0x8c1cf))|0;\n    {\n      d3 = (((+(((Int8ArrayView[0]))>>>((x.yoyo(window |= false)) % (0x2c4dad43))))) % (((0xf862755c) ? (d3) : (1073741823.0))));\n    }\n    d3 = (d0);\n    return (((0x1f33a124) % (0xaabdafce)))|0;\n  }\n  return f; })(this, {ff: Math.acosh}, new ArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=137; tryItOut("\"use strict\"; ");
/*fuzzSeed-168297596*/count=138; tryItOut(" /x/ ;o1.a2 = Array.prototype.map.call(a0, (function(j) { if (j) { o1.v0 = Array.prototype.reduce, reduceRight.apply(a2, [(function() { v0 = t2.byteOffset; return o2; }), g2]); } else { try { m1 = new WeakMap; } catch(e0) { } o1 = {}; } }), p1);");
/*fuzzSeed-168297596*/count=139; tryItOut("pclpcs();/*hhh*/function pclpcs(...NaN){for (var p in e0) { try { o1.o0 = m2.get(h0); } catch(e0) { } try { a2[v1] = v1; } catch(e1) { } try { neuter(b0, \"same-data\"); } catch(e2) { } o0.e2 = g0.objectEmulatingUndefined(); }}");
/*fuzzSeed-168297596*/count=140; tryItOut("\"use strict\"; let pmirqs;print(y = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: undefined, fix: Date.prototype.setSeconds, has: undefined, hasOwn: function() { return false; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })( \"\" ), (DataView.prototype.setInt32).bind(/(?!(?:(?:\\B|$+|(\\D)))*?)/gi, \"\\uE934\")));");
/*fuzzSeed-168297596*/count=141; tryItOut("\"use strict\"; /*bLoop*/for (let cixasd = 0, {NaN: {__parent__: [[]], a: {x: {}}}, b: {x, x: {w}, \u3056: {}}} = \"\\uCA64\"; cixasd < 10; ++cixasd) { if (cixasd % 15 == 4) { e2.add(this.o2.p1); } else { var wmsxrw = new ArrayBuffer(6); var wmsxrw_0 = new Float32Array(wmsxrw); var wmsxrw_1 = new Uint32Array(wmsxrw); print(wmsxrw_1[0]); var wmsxrw_2 = new Int32Array(wmsxrw); wmsxrw_2[0] = 6; ;o1 = {};m1.get(h0); }  } ");
/*fuzzSeed-168297596*/count=142; tryItOut("t0.set(this.t0, 13);");
/*fuzzSeed-168297596*/count=143; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.exp(( + ((Math.atan2(( + mathy1(Math.fround(( ~ (Math.cosh(Math.fround(0x07fffffff)) >>> 0))), ( ! Math.fround((( + y) >>> 0))))), 0x100000000) >>> 0) >= ( + Math.pow((Math.sqrt((x / Math.sinh(x))) ? x : ( ! (( ~ (y | 0)) | 0))), (Math.log1p((Math.fround(Math.imul(y, Math.fround(x))) | 0)) | 0)))))); }); testMathyFunction(mathy3, /*MARR*/[new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, x, x, x, new String('q'), new String('q'), x, new String('q'), new String('q'), new String('q'), new String('q'), x, new String('q'), x, x]); ");
/*fuzzSeed-168297596*/count=144; tryItOut("\"use strict\"; /*infloop*/for(var e = [z1]; undefined; new RegExp(\"\\\\v\", \"yim\")) g2 = x;");
/*fuzzSeed-168297596*/count=145; tryItOut("const lbjkfc, x = (x += d), x = Math.hypot(10, -10), \u3056 = \nEvalError(window), opafuz, {} = (yield /(?:(?![^]?)*?\\b)|([^\\xDf\\#\\d])(?:.){3}{1,}\\b+?/ym), yeeyyj;g0.v1 = Object.prototype.isPrototypeOf.call(b2, g1);");
/*fuzzSeed-168297596*/count=146; tryItOut("\"use strict\"; { void 0; gcPreserveCode(); } do {/*tLoop*/for (let x of /*MARR*/[ \"\" ]) { /*MXX1*/o0 = g1.String.prototype.toString; } } while((undefined) && 0);");
/*fuzzSeed-168297596*/count=147; tryItOut("g0.h0.toString = f2;");
/*fuzzSeed-168297596*/count=148; tryItOut("Array.prototype.reverse.apply(a2, [b0, v0, s2, t1, s2, this.o1.t2, (4277), f2]);");
/*fuzzSeed-168297596*/count=149; tryItOut(";");
/*fuzzSeed-168297596*/count=150; tryItOut("\"use strict\"; /*MXX1*/o1 = g1.Promise;");
/*fuzzSeed-168297596*/count=151; tryItOut("mathy2 = (function(x, y) { return ( - ((Math.imul(( + ( + x)), -(2**53)) <= (Math.fround(((Math.ceil(y) | 0) ? ((-Number.MAX_VALUE / 42) | 0) : (Math.hypot(Math.fround(Math.cbrt(Math.fround(((( + Math.tanh(y)) << ( + x)) >>> 0)))), ( + ( ! 0.000000000000001))) | 0))) >>> 0)) | 0)); }); testMathyFunction(mathy2, [(function(){return 0;}), (new Number(0)), ({valueOf:function(){return '0';}}), '/0/', 1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 0.1, /0/, NaN, false, [], (new Boolean(true)), undefined, '\\0', 0, null, '0', '', (new Boolean(false)), -0, objectEmulatingUndefined(), true, (new String('')), (new Number(-0)), [0]]); ");
/*fuzzSeed-168297596*/count=152; tryItOut("\"use strict\"; \"use asm\"; h2.get = f1;\na0.unshift(this.e2, p2,  /* Comment */new RegExp(\"\\u15dc\", \"ym\"), p2);\nfunction d() /x/  ** nulla0.forEach();");
/*fuzzSeed-168297596*/count=153; tryItOut("/*RXUB*/var r = this.__defineGetter__(\"x\", function(y) { yield y; Object.defineProperty(this, \"this.o1.v2\", { configurable: false, enumerable: undefined,  get: function() {  return 0; } });; yield y; }); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=154; tryItOut("for (var p in this.h2) { try { s2 += s0; } catch(e0) { } g1.g2.t2[/*MARR*/[arguments, -(2**53+2), -(2**53+2), arguments, -(2**53+2), [(void 0)], arguments, [(void 0)], -(2**53+2), arguments, arguments, [(void 0)], [(void 0)], [(void 0)], arguments, arguments, arguments, [(void 0)], arguments, arguments, [(void 0)], arguments, arguments, [(void 0)], -(2**53+2), -(2**53+2), -(2**53+2), arguments, [(void 0)], [(void 0)], [(void 0)], [(void 0)], -(2**53+2), [(void 0)], -(2**53+2), -(2**53+2), arguments, [(void 0)], arguments].filter(Date.prototype.setHours)]; }function x() { return (4277) } print(x);");
/*fuzzSeed-168297596*/count=155; tryItOut("mathy2 = (function(x, y) { return ((((( + (mathy1(mathy1(Math.abs(y), (((Math.fround((Math.atan2(x, (x >>> 0)) >>> 0)) ? x : Math.fround(( - x))) && Math.fround(y)) >>> 0)), (( + Math.hypot(y, Math.fround(x))) | 0)) | 0)) && Math.fround(((y && ( - (Math.cbrt((mathy0((0x100000000 | 0), y) | 0)) >>> 0))) >>> ((( ~ -0x07fffffff) | 0) >= x)))) | 0) - (Math.min(((((Math.pow((y >>> 0), (Math.atan(((Math.min((y | 0), (y | 0)) | 0) * y)) >>> 0)) >>> 0) | 0) | (( - Math.fround((-0x080000001 << 0/0))) >>> 0)) | 0), (Math.asin((-1/0 | 0)) * ((( + x) + (mathy0(y, Math.fround(((y | 0) === Math.fround(y)))) | 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy2, [0x0ffffffff, 1/0, -Number.MIN_VALUE, -1/0, -0x100000001, -0x080000000, 2**53-2, 0x080000000, -(2**53), -0x0ffffffff, -0x100000000, -0x07fffffff, 0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, 1, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 2**53, 42, -0x080000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Math.PI, 0/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, -(2**53+2), 0x100000000]); ");
/*fuzzSeed-168297596*/count=156; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    /*FFI*/ff(((((i1)-(i1)) >> ((i0)-(i0)+((imul((0xd6506bbf), (0xffffffff))|0) > (((0x50b60666)) >> ((0xfe1b11eb))))))), ((~~(+((-(/*FFI*/ff(((18014398509481984.0)), ((8589934593.0)), ((-1024.0)), ((18446744073709552000.0)), ((-36893488147419103000.0)), ((-295147905179352830000.0)), ((-511.0)), ((-147573952589676410000.0)), ((17592186044417.0)), ((281474976710655.0)), ((-2251799813685248.0)), ((-16777216.0)), ((144115188075855870.0)), ((-3.8685626227668134e+25)))|0))>>>((0xa9cd50f0) / (0xffffffff)))))), ((+(abs((((0xe52bd4a8)+(0xfb46f9e7)) >> ((0x5ac0bb53) % (0x6deaa6c8))))|0))), ((-7.555786372591432e+22)), ((((0x4959ad9a)+(0xffe31194)-(0xf89e77b1)) >> ((0xafff5aed)-(0x6d60db3e)))), ((-0x54c238d)), ((2.0)), ((131071.0)));\n    return (((i0)-(i1)+((0x66592eee))))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var xlprhk = new RegExp(\"(?!\\\\v)*?\", \"ym\"); ((let (e=eval) e))(); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_VALUE, 0.000000000000001, -1/0, -0x100000001, 2**53-2, Number.MAX_VALUE, -0x080000001, -0, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 2**53, 0/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 1/0, 0x080000000, 0x100000001, -0x07fffffff, -(2**53-2), 0x0ffffffff, -0x080000000, 0, -0x100000000, 42, -Number.MIN_SAFE_INTEGER, 1, 1.7976931348623157e308, Math.PI, -(2**53+2), 0x100000000]); ");
/*fuzzSeed-168297596*/count=157; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-168297596*/count=158; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -3.022314549036573e+23;\n    var i3 = 0;\n    i1 = (((delete z.x)) >= (0x0));\n    (Float64ArrayView[2]) = (((+((268435457.0))) + (+pow(((134217727.0)), ((+(1.0/0.0)))))));\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0, 0x100000001, -0x100000000, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, -0x080000001, 0.000000000000001, -(2**53), 0x100000000, 0/0, 0x080000000, -Number.MIN_VALUE, -0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), -0x0ffffffff, 0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, -0x080000000, -1/0, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, 2**53]); ");
/*fuzzSeed-168297596*/count=159; tryItOut("M:with(x){a1.__proto__ = t0; }");
/*fuzzSeed-168297596*/count=160; tryItOut("\"use strict\"; t2[12];");
/*fuzzSeed-168297596*/count=161; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(a1, f1);");
/*fuzzSeed-168297596*/count=162; tryItOut("\"use strict\"; this.zzz.zzz;this.zzz.zzz;");
/*fuzzSeed-168297596*/count=163; tryItOut("Array.prototype.push.call(this.a1, m1, a1, new (Object.getOwnPropertyDescriptor)(), m1, v2, i2);");
/*fuzzSeed-168297596*/count=164; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((Math.atan2(( + Math.tanh(y)), ( - ( + ((( ! x) >>> 0) * (Math.fround(mathy1((y >>> 0), (-0x100000000 >>> 0))) >>> 0))))) | 0) !== ( - (y == Math.fround(Math.hypot(Math.fround((( + x) !== ( + ( + mathy1(y, (Number.MIN_VALUE || x)))))), (Math.min(Math.fround(Math.imul(y, y)), (Math.hypot(Number.MAX_SAFE_INTEGER, -0x080000000) >>> 0)) >>> 0)))))) | 0); }); testMathyFunction(mathy2, [0x100000001, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, -0x080000000, 0, 2**53+2, 1/0, 0x080000001, 0/0, 0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, 1, -0x080000001, -(2**53), -(2**53-2), -1/0, 42, Math.PI, -Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=165; tryItOut("/*hhh*/function lqchfn(this.w, this.zzz.zzz = x, x, window = x, e, x, x, x, e, \u3056, x, z, z, b, c, window, NaN, a, w, w, d, x = /Q{1,2}(?:\\1+?)*?/gyim, x = false, x, eval, \u3056, d, w = window, x, c, c, x, x =  '' , x =  '' , x, b, y, __count__, NaN, y, set = \"\\u15D2\", c, b, 1 =  '' , x, w, y, a, w, x = ({a1:1}), y, c, eval, a, z, x, NaN, e, eval, NaN, \u3056, w = ({a1:1}), window, d, x, d, window = this, x = new RegExp(\"[^]+?\\\\u8405|\\\\u1550$*(\\\\B*)\", \"gym\"), x, x = null, x, eval, \u3056, e, d =  /x/g , eval, d, b, b, z, eval, x, z, b, e =  \"\" , eval, -12, this.x, x, x = false, x){print(t1);}lqchfn(x, NaN = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: encodeURI, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: window, delete: function() { throw 3; }, fix: function() { return []; }, has: Error.prototype.toString, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( /x/g ), x));");
/*fuzzSeed-168297596*/count=166; tryItOut("testMathyFunction(mathy1, [0x080000000, 0, -0x100000000, 2**53-2, -0x080000001, -Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, Math.PI, 0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, 1, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -(2**53-2), 42, 1/0, -0x080000000, 0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, -1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53), 0x080000001, 0.000000000000001, -0, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=167; tryItOut("testMathyFunction(mathy3, /*MARR*/[new String(''), x, new String(''), new String(''), x, new String(''), x, new String(''), x, new String(''), new String(''), x, new String(''), x, new String(''), new String(''), new String(''), new String(''), new String(''), x, x, new String(''), x, new String(''), x, x, new String(''), x, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String(''), new String(''), x, new String(''), x, x, new String(''), new String(''), x, x, new String(''), x, x, x, x, x, new String(''), new String(''), x, new String(''), x, x, new String('')]); ");
/*fuzzSeed-168297596*/count=168; tryItOut("a1[14] = g1.o2.g2;");
/*fuzzSeed-168297596*/count=169; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.cos(mathy1(( + (( + x) * ( + (x < x)))), ( + (( + ( + (( + x) && (Math.exp((mathy3(y, ( + x)) | 0)) | 0)))) ? (mathy3((y >>> 0), (y >>> 0)) >>> 0) : ( ~ (Math.ceil((( + Math.round((y | 0))) | 0)) | 0)))))) ? ( ~ Math.fround(mathy1((Math.max(Math.hypot(( + (0x100000000 ? Math.fround((y >> y)) : Math.fround(y))), ( + Math.log10(y))), ( + Math.ceil(0x100000001))) >>> 0), (x | 0)))) : mathy0(( + (( - ( + Math.hypot(( + y), ( + x)))) & ( + ( ! (( ! (x >>> 0)) >>> 0))))), ( - ( + ( + Math.cos(( + y))))))); }); testMathyFunction(mathy4, [0x07fffffff, -0x0ffffffff, 2**53, -0x100000001, 1.7976931348623157e308, 0x080000001, -(2**53), 42, 0, 0x100000000, -Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -0x100000000, 0/0, Number.MAX_VALUE, 0x100000001, -0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, 2**53-2, -0, -0x07fffffff, Math.PI, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1]); ");
/*fuzzSeed-168297596*/count=170; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul(( + Math.log10(Math.fround(Math.sin((-(2**53+2) | 0))))), (( + Math.imul(Math.fround(Math.tanh((Math.exp(Math.fround((y == -1/0))) >>> 0))), ( + ( + Math.max(((x != (x >>> 0)) >>> 0), ( + Math.imul(y, (y >>> 0)))))))) <= Math.fround(( + Math.fround(( + ( + x))))))); }); testMathyFunction(mathy0, [1, 0x07fffffff, -0x080000001, 0x100000000, 0, -Number.MAX_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, 42, 0.000000000000001, 2**53, -0x100000000, Number.MAX_VALUE, -0, -(2**53+2), 1/0, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 2**53+2, -(2**53-2), 0x080000000, -Number.MIN_VALUE, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0x0ffffffff, -(2**53), 0x100000001, 0x080000001]); ");
/*fuzzSeed-168297596*/count=171; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, 2**53+2, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -0x100000000, 0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), -1/0, -0x100000001, Number.MAX_VALUE, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, -0, -0x080000001, 1, 0x080000000, 42, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 0, 2**53, -Number.MIN_VALUE, 0x100000000, 0/0, 0x100000001, -(2**53-2), Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=172; tryItOut("h1 = t2[({valueOf: function() { e1 + '';return 8; }})];");
/*fuzzSeed-168297596*/count=173; tryItOut("mathy2 = (function(x, y) { return Math.acosh(( - (Math.round(( + x)) / ( ! x)))); }); testMathyFunction(mathy2, [-(2**53-2), 2**53-2, 1/0, -0, -0x080000000, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -1/0, 0x100000000, 2**53, -0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, -0x100000001, Math.PI, 0.000000000000001, 0, 2**53+2, 42, -0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=174; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.asin(Math.max(((Math.atan2(( + ( ! ( + Math.max(( + -0x100000000), x)))), (Math.acosh((x >>> 0)) >>> 0)) * Math.hypot((Math.asinh((( + Math.imul(( + x), -(2**53))) | 0)) | 0), y)) >>> 0), Math.fround((y !== Math.fround(Math.log2(((-Number.MIN_SAFE_INTEGER === Math.min(y, x)) | 0))))))); }); testMathyFunction(mathy0, [-(2**53), -0x080000000, 0x080000001, 0.000000000000001, 0, -(2**53+2), 1/0, 2**53, -0, 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, -0x100000000, -1/0, 0x080000000, 0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, 42, 0x100000001, 0/0, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=175; tryItOut("timeout(1800);");
/*fuzzSeed-168297596*/count=176; tryItOut("h0.valueOf = this.f1;");
/*fuzzSeed-168297596*/count=177; tryItOut("mathy1 = (function(x, y) { return ((Math.min(( + ( ~ ( + (( ~ Math.fround(x)) >>> 0)))), Math.log1p(y)) >>> 0) >>> Math.max(( ! ((Math.imul((y >>> 0), -(2**53-2)) ? Math.fround(Math.fround((Math.fround(x) == -(2**53)))) : Math.sinh(( + (Math.fround(-Number.MIN_SAFE_INTEGER) * Math.ceil(y))))) >>> 0)), ((Math.fround((Math.min(y, ( + (x >= Number.MAX_VALUE))) >>> 0)) % ( + (x | ( + x)))) % (Math.fround(( ~ Math.fround(Math.asin(((Math.max((x | 0), ( + y)) | 0) >>> 0))))) >>> 0)))); }); testMathyFunction(mathy1, [1/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, -0, -(2**53+2), -1/0, -Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, -0x100000000, -0x080000001, 1.7976931348623157e308, -(2**53-2), 2**53, 0x07fffffff, 0x080000001, 2**53+2, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, -0x100000001, 0x100000000, 0x100000001, 0x080000000, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, 42, Math.PI, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=178; tryItOut("");
/*fuzzSeed-168297596*/count=179; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-168297596*/count=180; tryItOut("e0 + f2;");
/*fuzzSeed-168297596*/count=181; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + ( ~ ( + (( ~ ((mathy1(((((Math.trunc((( ~ y) | 0)) >>> 0) & (y >>> 0)) >>> 0) >>> 0), (Math.min(( ~ x), y) >>> 0)) >>> 0) | 0)) | 0)))); }); ");
/*fuzzSeed-168297596*/count=182; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.atan2((( ! ( + Math.sign(Math.fround(Math.exp(x))))) | 0), (Math.pow(Math.abs(( + ( + Math.cosh(( + y))))), ( + Math.pow(Math.fround(Math.imul(Math.log10(x), -(2**53))), (x | 0)))) | 0)) | 0); }); testMathyFunction(mathy0, [0x080000001, 0/0, 2**53+2, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -1/0, -(2**53-2), -0x080000000, 0.000000000000001, 0x0ffffffff, 1, 0x100000001, -0x100000000, -0x080000001, 42, -0, Number.MIN_SAFE_INTEGER, 1/0, Math.PI]); ");
/*fuzzSeed-168297596*/count=183; tryItOut("/*oLoop*/for (njtonk = 0; njtonk < 9; \u0009/*MARR*/[({x:3}), ({x:3}),  'A' , ({x:3}),  'A' ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , ({x:3}),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , ({x:3}), ({x:3}),  \"use strict\" ,  'A' , ({x:3}), ({x:3}),  \"use strict\" ,  'A' ,  \"use strict\" ,  \"use strict\" , ({x:3}),  \"use strict\" , ({x:3}), ({x:3}),  'A' ,  'A' , ({x:3}),  \"use strict\" ,  'A' ,  'A' , ({x:3}), ({x:3}),  'A' ,  \"use strict\" ,  \"use strict\" ,  'A' ,  \"use strict\" ,  'A' , ({x:3}), ({x:3}), ({x:3}),  \"use strict\" ,  'A' , ({x:3}),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  \"use strict\" ,  \"use strict\" , ({x:3}),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  'A' ,  \"use strict\" , ({x:3}), ({x:3}), ({x:3}),  'A' ,  'A' ,  'A' ,  'A' , ({x:3})].some(Function, [\"\\u1678\"]), ++njtonk) { e0.has(m1); } \ne0.toSource = f1;\n");
/*fuzzSeed-168297596*/count=184; tryItOut("\"use strict\"; Object.seal(p2);");
/*fuzzSeed-168297596*/count=185; tryItOut("f1 + p0;");
/*fuzzSeed-168297596*/count=186; tryItOut("mathy4 = (function(x, y) { return Math.min((( + ( + Math.atanh(( + x)))) == ( + ((( ~ (a | 0)) | 0) << (( + -Number.MIN_VALUE) < Math.atanh(Math.fround(Math.expm1(y))))))), (Math.log((Math.max(x, x) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 0x07fffffff, 0x100000001, Number.MAX_VALUE, 0x080000000, -0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, -0, 2**53+2, 0.000000000000001, 1, 2**53-2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, -0x0ffffffff, -Number.MAX_VALUE, 42, 1.7976931348623157e308, -(2**53-2), 0/0, -(2**53), -Number.MIN_VALUE, 0, -0x100000001, 0x080000001, 0x100000000, 1/0, 2**53]); ");
/*fuzzSeed-168297596*/count=187; tryItOut("\"use strict\"; p2 + b1;");
/*fuzzSeed-168297596*/count=188; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -524289.0;\n    var d3 = -0.0625;\n    var d4 = 1.9342813113834067e+25;\n    return +((9007199254740992.0));\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[(-1/0), x, (-1/0), (-1/0), (-1/0), x, x, (-1/0), 0x100000001, 0x100000001, x, x, (-1/0), (-1/0), (-1/0), (-1/0), x, (-1/0), (-1/0), (-1/0), 0x100000001, x, (-1/0), 0x100000001, x, x, 0x100000001, 0x100000001, x, x, (-1/0), x]); ");
/*fuzzSeed-168297596*/count=189; tryItOut("\"use strict\"; var nnnrvi = new ArrayBuffer(12); var nnnrvi_0 = new Float32Array(nnnrvi); nnnrvi_0[0] = -12; var nnnrvi_1 = new Int16Array(nnnrvi); print(nnnrvi_1[0]); nnnrvi_1[0] = 29; L:with(\"\\u7FF3\")print(nnnrvi_0);o1.g2.offThreadCompileScript(\"void (this.__defineSetter__(\\\"z\\\", function(y) { return (void shapeOf( '' )) }))\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: (nnnrvi_0[0] % 38 == 0) }));a0.reverse();");
/*fuzzSeed-168297596*/count=190; tryItOut("i0.send(s1);");
/*fuzzSeed-168297596*/count=191; tryItOut("\"use strict\"; ");
/*fuzzSeed-168297596*/count=192; tryItOut("h2 + m2;");
/*fuzzSeed-168297596*/count=193; tryItOut("mathy3 = (function(x, y) { return ((Math.imul(Math.expm1(((((x % x) ** (Math.max(( + x), ((y ? Math.PI : y) >>> 0)) >>> 0)) | 0) === Math.fround(Math.acos(x)))), (((( + Math.atan2(Math.min(( + y), ( + -1/0)), -Number.MAX_SAFE_INTEGER)) ? y : y) >> (Math.tanh((x >>> 0)) >>> 0)) >>> 0)) ** (mathy1((( + Math.max(-Number.MIN_VALUE, Number.MAX_VALUE)) | 0), ( ~ y)) >>> 0)) | 0); }); testMathyFunction(mathy3, [0x100000001, 0x080000000, -(2**53), -(2**53+2), Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, 0x100000000, -0x080000001, 0/0, 2**53+2, -0x100000000, -0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MIN_VALUE, 1, 2**53-2, -0x0ffffffff, 0.000000000000001, Number.MAX_VALUE, -1/0, 1/0, 1.7976931348623157e308, -(2**53-2), -0x080000000, Number.MAX_SAFE_INTEGER, 2**53, 42, 0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=194; tryItOut("testMathyFunction(mathy2, [-0x0ffffffff, -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, 0x080000001, -(2**53-2), Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -0x080000000, 0x100000001, 0, 0.000000000000001, 0x100000000, -1/0, -(2**53), Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, 1, 0/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, 42, 1/0, 2**53, -0x080000001, 2**53-2, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, -0x100000001]); ");
/*fuzzSeed-168297596*/count=195; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(( ~ (Math.fround((mathy1(mathy0(( - (Math.round(y) >>> 0)), y), (( ! Math.max(Math.min(0x100000000, y), 1.7976931348623157e308)) | 0)) | 0)) | ((((Math.round(y) | 0) == mathy0(Math.fround(Math.log2(x)), 2**53+2)) | 0) | 0)))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0x080000000, 42, 0x0ffffffff, 0x07fffffff, 0/0, Number.MAX_VALUE, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, -(2**53-2), -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, -0, 1, -0x080000001, -0x07fffffff, -0x100000001, -(2**53), 0.000000000000001, -1/0, 1/0, -(2**53+2), 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=196; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(t2, \"hasOwnProperty\", ({enumerable: false}));");
/*fuzzSeed-168297596*/count=197; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\S.|\\\\D\", \"y\"); var s = \"0\"; print(r.test(s)); ");
/*fuzzSeed-168297596*/count=198; tryItOut("this.v1 = evaluate(\"v2 = Array.prototype.every.apply(a2, [s0]);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 3), noScriptRval: true, sourceIsLazy: true, catchTermination: (Math.fround(6)), element: o0, elementAttributeName: s2, sourceMapURL: s1 }));");
/*fuzzSeed-168297596*/count=199; tryItOut("mathy4 = (function(x, y) { return (Math.fround(( ! Math.fround(Math.log10(Math.imul((y >>> 0), (y >>> 0)))))) << ( - (((Math.atan(( + x)) || 0/0) ? (((y >>> 0) ** (( + (0/0 | 0)) | 0)) | 0) : (Math.atanh(( + Math.sinh(Math.fround(mathy2(Math.fround(x), Math.fround(Math.cosh((y | 0)))))))) | 0)) | 0))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, -Number.MIN_VALUE, 0.000000000000001, 0x100000000, 2**53+2, 0x0ffffffff, -0x0ffffffff, -(2**53+2), 42, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, -1/0, 0, 1.7976931348623157e308, -0x07fffffff, 0x080000001, 2**53, -0x100000001, 0x100000001, -Number.MAX_VALUE, Math.PI, 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 0x07fffffff, 1, 2**53-2, -(2**53-2), -0]); ");
/*fuzzSeed-168297596*/count=200; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(( - Math.fround((( - (Math.hypot(( + mathy2(y, ( + (Math.pow((x | 0), (( + Math.atan2(Math.PI, ( + -Number.MAX_SAFE_INTEGER))) | 0)) | 0)))), ( + (x << y))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [(new Number(-0)), '/0/', /0/, false, true, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), undefined, objectEmulatingUndefined(), (new Boolean(false)), 1, '\\0', '0', (new Boolean(true)), (new Number(0)), (new String('')), ({valueOf:function(){return 0;}}), NaN, 0.1, [0], '', -0, [], null, (function(){return 0;}), 0]); ");
/*fuzzSeed-168297596*/count=201; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ((((Math.pow(( + mathy0(( + y), x)), Math.fround(( + x))) | 0) / (( ! (( ~ (( + (y ** ( + y))) >>> 0)) >>> 0)) === ( + (Math.asin(( + ( ! y))) >>> 0)))) | 0) >>> mathy1((Math.fround(Math.imul(Math.fround((((y >>> 0) / (y >>> 0)) >>> 0)), (y >>> 0))) <= Math.max(mathy4(y, y), (Math.hypot((Math.fround(Math.exp(Math.fround(( + (x | 0))))) >>> 0), Math.fround(( ~ Math.PI))) >>> 0))), (((Math.acosh(42) | 0) << (( + ((x >>> 0) - Math.fround(( - Math.fround(x))))) | 0)) ? ( ! ((x && y) >>> 0)) : (Math.sin(((( + y) < y) | 0)) | 0))))); }); testMathyFunction(mathy5, /*MARR*/[x, true, x, x, true, x, true, true, true, x, x, true, true, x, true, true, true, true, x, true, true, true, x, true, true, true, x, true, true, true, true, true, x, true, true, true, true, x, true, true, true, true, x, x, true, true, x, x, x, x, true, true, x, true, true, true, true, true, x, true, true, true, true, true, x, true, true, true, x, x, x, true, x, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, x, x, true, x, x, true, true, true, true, true, x, true, true, x, x, x, x, true, x, x, x, x, x, true, true, true, true, true, true, true, true, true, true, x, true, true, true, true, x, x, x, x, true, true, true, true, x, true, true, x, true, true, true, true, true, x, true, x, true, x, true, true, true, true, x, true, true, x]); ");
/*fuzzSeed-168297596*/count=202; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.trunc(( + ( ! ( + ( + Math.pow(2**53-2, 1/0)))))) ? ((( + (( ! x) | 0)) | 0) >>> 0) : (Math.cosh(Math.min(x, ( + (( + y) ? ( + (Math.fround(Math.min(Math.max(x, 2**53), ( + x))) != ((Math.min(y, x) | 0) + x))) : x)))) >>> 0)) | 0); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -Number.MIN_VALUE, 2**53, -(2**53+2), 0x0ffffffff, 0x100000000, -Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 0, Number.MAX_VALUE, 2**53+2, -0x100000000, -0x080000001, Math.PI, 0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 2**53-2, 1.7976931348623157e308, 0.000000000000001, 1/0, -0x080000000, -0x0ffffffff, 0x080000000, 1, -Number.MAX_SAFE_INTEGER, -(2**53), 0/0, -0, 0x100000001, 42]); ");
/*fuzzSeed-168297596*/count=203; tryItOut("testMathyFunction(mathy1, [0x080000001, Math.PI, 0x07fffffff, 0x100000000, -0x080000001, -0, 2**53+2, 1.7976931348623157e308, 0x0ffffffff, 1, -0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, 2**53-2, -1/0, -(2**53+2), -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), -(2**53), -Number.MIN_VALUE, -0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, -0x07fffffff, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-168297596*/count=204; tryItOut("(Math.atan2(/[\u00cd-\u36f2\\u002f-\ub2fd\\f\\D]/gi, /(?![^])/i) <<= (4277));");
/*fuzzSeed-168297596*/count=205; tryItOut("with({}) let(d) ((function(){function(y) { print(x); }})());");
/*fuzzSeed-168297596*/count=206; tryItOut("v1 = (b1 instanceof s0);");
/*fuzzSeed-168297596*/count=207; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=208; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return mathy0((( + Math.sinh(( + (Math.hypot(x, -0x080000000) > x)))) % ((Math.imul((Math.min(Math.expm1(x), (Math.imul((x | 0), (x | 0)) | 0)) >>> 0), x) >>> 0) - Math.cbrt(y))), ( + ( - (Math.sin(Math.fround(( + ( - Math.imul(Math.fround(y), y))))) >>> 0)))); }); testMathyFunction(mathy1, [-(2**53+2), -0x080000000, 2**53+2, -0x100000001, 42, Number.MIN_VALUE, 0x080000001, -(2**53), 0.000000000000001, -(2**53-2), -0x07fffffff, -Number.MIN_VALUE, 2**53-2, 0x100000000, 0x100000001, 1/0, -0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, Math.PI, 1, 0x080000000, -1/0, 2**53, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0, 0]); ");
/*fuzzSeed-168297596*/count=209; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x07fffffff, 2**53-2, 0x080000000, -Number.MAX_VALUE, -0x07fffffff, 0x080000001, 0/0, 1.7976931348623157e308, -1/0, -0x0ffffffff, -0x100000001, Number.MAX_VALUE, 2**53+2, 1/0, 0x100000000, 2**53, 1, 0x0ffffffff, -(2**53+2), 0.000000000000001, 42, -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, 0, 0x100000001, -0, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=210; tryItOut("\"use strict\"; /*MXX1*/o2 = g1.Uint16Array.prototype.BYTES_PER_ELEMENT;");
/*fuzzSeed-168297596*/count=211; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.atan((Math.fround(Math.pow(Math.atan2(((Math.pow(( + ( + 0x080000001)), (Math.sinh(x) % ( ~ x))) < x) >>> 0), (Math.pow(Math.fround(Math.imul(Math.fround(0x100000001), ( - (x >>> 0)))), x) >>> 0)), Math.fround(( - Math.fround(Math.acosh(( + Math.max(0x100000000, y)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x080000000, 0x07fffffff, 0x100000000, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, -0x080000001, 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -Number.MIN_SAFE_INTEGER, 1, -0x07fffffff, -0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), Math.PI, 0x080000001, 1/0, -(2**53), 2**53+2, 0x080000000, -(2**53+2), 2**53, 0x0ffffffff, 2**53-2, -0, Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-168297596*/count=212; tryItOut("/*MXX2*/g2.SimpleObject.length = g2;");
/*fuzzSeed-168297596*/count=213; tryItOut("for (var p in i1) { try { /*MXX3*/g1.RegExp.$8 = g0.RegExp.$8; } catch(e0) { } try { neuter(b2, \"same-data\"); } catch(e1) { } try { for (var p in v0) { try { Array.prototype.reverse.call(a0, t2); } catch(e0) { } try { e2.add(((function too_much_recursion(qqsogj) { ; if (qqsogj > 0) { ; too_much_recursion(qqsogj - 1); print((makeFinalizeObserver('tenured'))); } else {  }  })(24627))); } catch(e1) { } h1 = {}; } } catch(e2) { } m1 = new Map; }");
/*fuzzSeed-168297596*/count=214; tryItOut("\"use strict\"; g0.i0.next();");
/*fuzzSeed-168297596*/count=215; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.asin(Math.trunc((Math.trunc(Math.atan(x)) | 0))); }); testMathyFunction(mathy0, [0x07fffffff, 2**53-2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 2**53+2, -(2**53+2), 1.7976931348623157e308, 0x0ffffffff, 0x100000001, -1/0, -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, 0, Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 42, 2**53, 1/0, 0/0, Number.MAX_VALUE, -(2**53-2), 0x080000000, 1, 0x080000001, -(2**53), -0, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001]); ");
/*fuzzSeed-168297596*/count=216; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.sqrt(Math.fround(Math.log2(( + (( + (( + Math.pow(((( + y) ? ( + 0x0ffffffff) : ( + y)) >>> 0), (Math.max(-Number.MIN_SAFE_INTEGER, x) | 0))) >>> 0)) >> ( - ((x , (Math.atan2((x | 0), x) | 0)) ? x : x)))))))); }); testMathyFunction(mathy1, [1.7976931348623157e308, Number.MAX_VALUE, 2**53, Number.MIN_VALUE, -(2**53-2), 2**53-2, 0x100000000, 1, -0, -0x080000000, Math.PI, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, 2**53+2, 42, 1/0, 0x0ffffffff, -0x100000000, -(2**53), 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 0/0, -(2**53+2), -0x080000001, 0x080000001, 0x080000000, -1/0]); ");
/*fuzzSeed-168297596*/count=217; tryItOut("/*RXUB*/var r = /\\3/m; var s = \"\\u00f7\\n\\n\\u00f7\\n\\n\\u00f7\\n\\n\\u00f7\\n\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-168297596*/count=218; tryItOut("e0 + this.b2;");
/*fuzzSeed-168297596*/count=219; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\3+|(?:$)\\\\W)\", \"y\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-168297596*/count=220; tryItOut("v0 = (m0 instanceof i1);");
/*fuzzSeed-168297596*/count=221; tryItOut("mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(mathy0(( ! mathy1(Math.max(Math.imul(Math.round((x >>> 0)), y), Math.atan(2**53-2)), -(2**53-2))), Math.log1p((Math.sin(Math.fround(y)) >>> 0)))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -1/0, 2**53-2, 0, 2**53+2, -(2**53-2), -Number.MIN_VALUE, 0.000000000000001, 0x100000001, Number.MAX_SAFE_INTEGER, 1, 1/0, 0x07fffffff, -0, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -(2**53+2), -0x07fffffff, -0x080000001, -0x100000001, 0x080000000, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), 0/0, Math.PI]); ");
/*fuzzSeed-168297596*/count=222; tryItOut("e2 + o0.f1;");
/*fuzzSeed-168297596*/count=223; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-(2**53+2), -(2**53-2), 2**53-2, -(2**53), 0.000000000000001, 0x0ffffffff, 2**53, Number.MAX_VALUE, 2**53+2, -0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, 42, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000001, -0x07fffffff, -0x100000000, -0, -Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, 1.7976931348623157e308, -Number.MAX_VALUE, 0/0, Math.PI, -0x0ffffffff, Number.MIN_VALUE, 1, -0x080000000]); ");
/*fuzzSeed-168297596*/count=224; tryItOut("for(let e in (((4277))((\nx)))){throw e('fafafa'.replace(/a/g, ArrayBuffer.prototype.slice), (d));a2.unshift(this.e0); }");
/*fuzzSeed-168297596*/count=225; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.max((Math.cosh(Math.fround(( - (mathy3(Math.log2(Math.fround(Math.trunc(( + Math.fround(Math.trunc((x | 0))))))), ( ~ x)) | 0)))) >>> 0), (Math.acosh(((( ~ (x | 0)) || y) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1/0, -0, -Number.MIN_VALUE, -0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, 1, 2**53, -(2**53-2), 0/0, 2**53+2, -0x080000000, 0x080000001, Number.MAX_VALUE, Math.PI, -1/0, 0x07fffffff, 0, -(2**53), 0x080000000, 42, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -(2**53+2), Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=226; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(Math.abs(Math.imul(((Math.acosh((Math.cos(Number.MAX_VALUE) >>> 0)) >>> 0) >>> 0), (Math.log1p((( ! 1) >>> 0)) >>> 0))), (Math.min(mathy0(((( ~ Math.round(Math.fround((x ? y : Math.imul(0, y))))) | 0) | 0), ( + mathy1(0/0, x))), ( + Math.imul(( + Math.fround((Math.fround(y) * y))), x))) | 0)) | 0); }); testMathyFunction(mathy2, [-0x100000000, -1/0, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, -0x080000000, 0x080000000, 1.7976931348623157e308, -(2**53-2), -(2**53), 2**53+2, -0x07fffffff, 0/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -0, 1/0, -0x0ffffffff, 0x0ffffffff, 2**53, Math.PI, 0, 1, -Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, -0x100000001, Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-168297596*/count=227; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-168297596*/count=228; tryItOut("\"use strict\"; Array.prototype.shift.apply(a0, [o0, g2, o1.f2]);");
/*fuzzSeed-168297596*/count=229; tryItOut("\"use strict\"; g1.v1 = o2.g0.runOffThreadScript();");
/*fuzzSeed-168297596*/count=230; tryItOut("mathy0 = (function(x, y) { return (((((Math.fround(Math.max(( + (Math.max(((Math.clz32((x | 0)) >>> 0) >>> 0), (x >>> 0)) >>> 0)), Math.fround(((Math.pow(( + Math.abs(x)), ( + (Math.cosh((Math.atan2(x, (y | 0)) >>> 0)) >>> 0))) >>> 0) ? Math.min((x >>> 0), Math.imul(-Number.MAX_SAFE_INTEGER, (x | 0))) : (x === x))))) | 0) === (Math.fround(Math.sign(Math.fround(( ! y)))) % (( ~ (x >>> 0)) >>> 0))) | 0) > (Math.sign(Math.cbrt(( + x))) | 0)) | 0); }); testMathyFunction(mathy0, [42, Number.MAX_VALUE, 0x100000000, -0, 1, Math.PI, -Number.MIN_VALUE, -0x080000000, 0, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, -0x080000001, -0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 2**53+2, 1/0, 0.000000000000001, -1/0, 0x100000001, -(2**53+2), 0x080000000, 0x0ffffffff, 1.7976931348623157e308, 0/0, 0x080000001, Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=231; tryItOut("b2 = new SharedArrayBuffer(16);");
/*fuzzSeed-168297596*/count=232; tryItOut("\"use strict\"; testMathyFunction(mathy1, [42, -0x080000000, -0, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, 1, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, 1/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -0x100000001, 0x100000000, 0, 0x0ffffffff, -(2**53-2), 0/0, 0x080000000, -(2**53+2), 0x07fffffff, 2**53+2, -(2**53), -0x100000000, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=233; tryItOut("mathy4 = (function(x, y) { return ( + Math.atan(((( ! Math.asinh(mathy0(x, y))) , (((0x07fffffff >>> 0) || ( ! x)) & (((x | 0) ? (( + (( + x) * y)) | 0) : ((y >= Math.max(x, 2**53)) | 0)) | 0))) | 0))); }); ");
/*fuzzSeed-168297596*/count=234; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.abs((( ! (Math.fround(((Math.sign(y) | 0) != (y >>> 0))) > (mathy0(-Number.MIN_VALUE, Math.atan2(x, y)) >>> 0))) | 0)) >> Math.fround(( + Math.fround((Math.fround((Math.PI === Math.fround(y))) + x)))))); }); testMathyFunction(mathy2, /*MARR*/[[(void 0)], -Number.MAX_SAFE_INTEGER, ((4277).unwatch(new String(\"-15\"))), true, true,  '' , -Number.MAX_SAFE_INTEGER, [(void 0)], -Number.MAX_SAFE_INTEGER, ((4277).unwatch(new String(\"-15\")))]); ");
/*fuzzSeed-168297596*/count=235; tryItOut("\"use strict\"; let x = /*UUV1*/(x.sign = true);{ void 0; void relazifyFunctions(this); } /*RXUB*/var r = r1; var s = \"11a11  1\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=236; tryItOut("i2.next();");
/*fuzzSeed-168297596*/count=237; tryItOut("\"use strict\"; print(uneval(h1));");
/*fuzzSeed-168297596*/count=238; tryItOut("for (var p in i1) { try { e0 + ''; } catch(e0) { } try { v2 = a2.length; } catch(e1) { } try { m1.get(e1); } catch(e2) { } print(a1); }");
/*fuzzSeed-168297596*/count=239; tryItOut("\"use strict\"; for(let w = window in 20) {/*vLoop*/for (var rhextg = 0, x; rhextg < 41; ++rhextg) { w = rhextg; g2.s1 += 'x'; }  }");
/*fuzzSeed-168297596*/count=240; tryItOut("/*tLoop*/for (let d of /*MARR*/[ /x/g , (0x50505050 >> 1), y, y, ({a2:z2}), y,  /x/g , ({a2:z2}), y, (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), y, y, ({a2:z2}), (0x50505050 >> 1), y, ({a2:z2}), (0x50505050 >> 1),  /x/g , (0x50505050 >> 1), ({a2:z2}), ({a2:z2})]) { e2.add(h1); }");
/*fuzzSeed-168297596*/count=241; tryItOut("\"use strict\"; /*infloop*/for( /x/  in ((String.prototype.substr)(this)))/*tLoop*/for (let d of /*MARR*/[null, NaN, {}, {}, {}, null, {}, NaN, NaN, NaN, NaN, {}, null, NaN, {}, {}, {}, {}, null, NaN, {}, NaN, {}, null, null, null, {}, NaN, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, NaN, null, NaN, {}, null, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, NaN, {}, {}, null, {}, NaN, {}]) { print( /x/g ); }");
/*fuzzSeed-168297596*/count=242; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s2; print(r.exec(s)); ");
/*fuzzSeed-168297596*/count=243; tryItOut("\"use strict\"; (/*RXUE*/new RegExp(\"\\\\1|.\\\\3+{0,4}?\", \"yi\").exec(\"\").prototype);");
/*fuzzSeed-168297596*/count=244; tryItOut("mathy2 = (function(x, y) { return ((mathy0((y ? ( + 2**53) : (x / x)), y) ? (Math.clz32((y >>> 0)) >>> 0) : (mathy0(( + 1.7976931348623157e308), ( ~ (Math.tanh(( + (( + Math.asinh(( + x))) < ( + x)))) | 0))) | 0)) % Math.max(Math.fround((Math.imul(x, Math.asin(y)) ? Math.cosh(x) : Math.atan(Math.atan2((x >>> 0), ( + ( - x)))))), ((-(2**53-2) >>> 0) ? (x <= (((0x100000000 | 0) * (x | 0)) % x)) : Math.sign(( + (( + Math.log2(( + x))) - ( + Math.cos(x)))))))); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 0.000000000000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 0, Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -0x100000000, 1/0, Number.MIN_VALUE, 0x100000000, -0x100000001, -1/0, 0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -0x080000001, 42, -0x07fffffff, 1, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, 0/0, -0x080000000, Math.PI, 2**53, 0x100000001]); ");
/*fuzzSeed-168297596*/count=245; tryItOut("mathy1 = (function(x, y) { return ((((Math.cbrt(((Math.hypot((x >>> 0), (((( + (Math.acosh(((x ? x : y) | 0)) | 0)) ? Math.fround(mathy0(-(2**53), 0x0ffffffff)) : ( + y)) >>> 0) >>> 0)) >>> 0) | 0)) | 0) | 0) ? (( - (( - (y >>> 0)) >>> 0)) | 0) : mathy0((Math.round(Math.fround(( ! Math.fround(y)))) & ( ! ((( + x) ^ ( ~ 1.7976931348623157e308)) >>> 0))), (Math.pow(x, 1/0) + (x && (Math.min(mathy0(x, y), (( ! y) | 0)) | 0))))) | 0); }); testMathyFunction(mathy1, [-0, undefined, null, '', '0', (new String('')), false, /0/, 0.1, (new Number(-0)), [0], NaN, ({valueOf:function(){return 0;}}), (new Number(0)), [], '\\0', objectEmulatingUndefined(), 0, true, 1, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), '/0/', (new Boolean(true)), (function(){return 0;}), (new Boolean(false))]); ");
/*fuzzSeed-168297596*/count=246; tryItOut("mathy2 = (function(x, y) { return (Math.imul((( ~ (Math.imul((((x % ( ! ( + 2**53+2))) | 0) >>> 0), (x >>> 0)) | 0)) | 0), Math.fround(Math.tanh(Math.imul(x, y)))) == (( - Math.asin(Math.acosh(x))) >>> 0)); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, -0x100000000, Math.PI, 0x100000000, -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, -(2**53-2), -(2**53+2), 0/0, -1/0, -(2**53), 0x080000000, -0, 0x0ffffffff, 0.000000000000001, 1/0, 2**53, 42, -Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, 1, 2**53+2, 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=247; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 0x080000001, Number.MIN_VALUE, 1, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, 0, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, -0x080000001, 0x080000000, -(2**53+2), 0x0ffffffff, Number.MAX_VALUE, -(2**53), 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, -1/0, -0x100000001, 1.7976931348623157e308, -0, 2**53, -Number.MIN_VALUE, 0x100000000, 42, 2**53-2, 0.000000000000001, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=248; tryItOut("switch(((String.prototype.fontcolor).call(\"\\uF3B0\", a,  '' ))) { case 9: t0 = t2.subarray(1, v2);a2.splice(-6, 6, b2, p0); }");
/*fuzzSeed-168297596*/count=249; tryItOut("\"use strict\"; a0 = arguments.callee.arguments;");
/*fuzzSeed-168297596*/count=250; tryItOut("\"use strict\"; o1.i1 = Proxy.create(this.h0, o0.i2);function x(x)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    return ((((-1.03125))-(i1)-((8193.0) == (-536870913.0))))|0;\n  }\n  return f;return  /x/g ;");
/*fuzzSeed-168297596*/count=251; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.fround(( ~ ((Number.MIN_VALUE << Math.fround(((x | 0) / (x | 0)))) || Math.fround(Math.log1p(Math.fround(( ! y)))))))); }); testMathyFunction(mathy1, /*MARR*/[undefined, undefined, new Boolean([z1,,], x), undefined, null, new Boolean([z1,,], x), null, new Boolean([z1,,], x), undefined, null, null, null, new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, new Boolean([z1,,], x), new Boolean([z1,,], x), undefined, undefined, new Boolean([z1,,], x), new Boolean([z1,,], x), undefined, undefined, undefined, null, new Boolean([z1,,], x), null, undefined, undefined, undefined, undefined, null, new Boolean([z1,,], x), undefined, new Boolean([z1,,], x), undefined, new Boolean([z1,,], x), null, new Boolean([z1,,], x), null, new Boolean([z1,,], x), new Boolean([z1,,], x), undefined, null, new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), undefined, new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), new Boolean([z1,,], x), undefined, undefined, new Boolean([z1,,], x), null, new Boolean([z1,,], x), null, undefined, undefined, new Boolean([z1,,], x), new Boolean([z1,,], x), null, undefined, new Boolean([z1,,], x), undefined, undefined, undefined, undefined, null, null, null, new Boolean([z1,,], x)]); ");
/*fuzzSeed-168297596*/count=252; tryItOut("mathy5 = (function(x, y) { return ( + ( - ( + Math.asinh((((Math.fround((Math.fround(x) & Math.fround((( ~ 0x080000001) >>> 0)))) ? x : -Number.MIN_SAFE_INTEGER) <= mathy2(-Number.MAX_VALUE, ( + -0x100000000))) >>> 0))))); }); testMathyFunction(mathy5, [2**53-2, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, 42, 1.7976931348623157e308, 1, 0, -Number.MAX_VALUE, Math.PI, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 2**53+2, 0.000000000000001, -0x080000001, -0x080000000, 0x100000001, -0x100000000, 0x080000000, -0x100000001, -0, 2**53, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, -(2**53-2), -(2**53), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=253; tryItOut("\"use strict\"; v0 = (b2 instanceof this.o1.h0);");
/*fuzzSeed-168297596*/count=254; tryItOut("mathy3 = (function(x, y) { return ( + ( ~ ( + Math.atan((Math.atan2(Math.atan2((y | 0), (Math.min(y, (y >>> 0)) | 0)), x) === x))))); }); testMathyFunction(mathy3, [0x07fffffff, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0x0ffffffff, 0x080000001, 0x100000000, 2**53, Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, -0x100000000, 0x100000001, Math.PI, 2**53+2, 0/0, -0x07fffffff, -0, -Number.MAX_VALUE, 0, -1/0, -(2**53-2), 0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x080000000]); ");
/*fuzzSeed-168297596*/count=255; tryItOut("\"use strict\"; f2.__proto__ = o1;");
/*fuzzSeed-168297596*/count=256; tryItOut("\"use strict\"; b0.toString = f0;");
/*fuzzSeed-168297596*/count=257; tryItOut("\"use strict\"; x;");
/*fuzzSeed-168297596*/count=258; tryItOut("testMathyFunction(mathy3, [-0x07fffffff, -0x100000000, 0x080000001, 0x100000001, Number.MAX_VALUE, 0x0ffffffff, 0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 0x100000000, -(2**53), 42, -Number.MAX_SAFE_INTEGER, 0, 0x080000000, 1, 1.7976931348623157e308, -0x080000001, -1/0, 2**53+2, 0.000000000000001, -0, -0x100000001, -(2**53-2), 2**53, -Number.MIN_VALUE, Math.PI, Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=259; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.atanh((mathy1(((( ! ((( + ( ~ x)) ** Math.atan2((x === y), ((0x100000000 != y) | 0))) | 0)) | 0) | 0), (Math.pow(Math.fround(Math.trunc(x)), y) | 0)) | 0)); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), '\\0', [0], undefined, 1, /0/, 0.1, ({valueOf:function(){return '0';}}), (new Number(0)), true, (new Boolean(true)), false, -0, [], '/0/', (function(){return 0;}), '', (new String('')), 0, (new Number(-0)), null, (new Boolean(false)), ({toString:function(){return '0';}}), NaN, '0', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-168297596*/count=260; tryItOut("\"use strict\"; print(let (b = /(?:.)/ym) window);");
/*fuzzSeed-168297596*/count=261; tryItOut("x.fileName;");
/*fuzzSeed-168297596*/count=262; tryItOut("a2 = a2.slice(NaN, NaN, t1, ({x: x}), p1, f1);");
/*fuzzSeed-168297596*/count=263; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot(Math.sinh(( + ( ! (y | 0)))), mathy1(Math.fround((( + (( ~ (mathy0(x, ( + mathy2(1, -Number.MAX_VALUE))) >>> 0)) >>> 0)) !== Math.fround(Math.trunc(x)))), Math.asin((Math.fround(Math.min(Math.fround(( ~ -Number.MAX_VALUE)), ( + x))) >>> 0)))); }); testMathyFunction(mathy3, [1.7976931348623157e308, -0x080000001, 42, 0x080000000, -0x100000001, 2**53+2, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -0, 0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, 1, 0.000000000000001, Math.PI, -Number.MIN_VALUE, -(2**53), 1/0, -(2**53+2), -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, 0/0, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, -0x080000000, 0]); ");
/*fuzzSeed-168297596*/count=264; tryItOut("this.h1.getPropertyDescriptor = f0;");
/*fuzzSeed-168297596*/count=265; tryItOut("\"use strict\"; x");
/*fuzzSeed-168297596*/count=266; tryItOut("\"use strict\"; Array.prototype.sort.call(g1.a2, (function(j) { if (j) { try { this.a2 = new Array; } catch(e0) { } h0.get = f2; } else { e1 = new Set(a1); } }), i1);");
/*fuzzSeed-168297596*/count=267; tryItOut("a2.pop();function d(y, z)Math.atan2(-7, window)t2 = g0.t0[6];");
/*fuzzSeed-168297596*/count=268; tryItOut("s0 += o1.s1;");
/*fuzzSeed-168297596*/count=269; tryItOut("\"use strict\"; let (d = ({ get constructor x (x, eval)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((i0)*0xfffff))|0;\n  }\n  return f;,  set x z () { yield  /x/g  }  }), sppddo, window, x, z =  /x/g  ? x : false, eval = (x + (eval(\"w\", \"\u03a0\"))), c) { Array.prototype.unshift.call(a1, t0, (z) = (4277)); }");
/*fuzzSeed-168297596*/count=270; tryItOut("o0.m1.get(e1);");
/*fuzzSeed-168297596*/count=271; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return mathy0(((Math.min((Math.fround((x | 0)) | 0), (((Math.ceil(mathy1(y, y)) | 0) , (x | 0)) | 0)) | 0) >>> 0), ((mathy2((( + Math.tanh(( + (0x100000000 | 0)))) | 0), (((Math.sign(( + (0x100000001 >>> 0))) | 0) ? ((Math.expm1(x) || (y ? x : x)) | 0) : ((Math.atan2((((((Math.fround(x) | 0) | 0) * (Math.max((x >>> 0), mathy2(( + Number.MIN_VALUE), ( + y))) >>> 0)) | 0) >>> 0), (( + ( + Number.MAX_VALUE)) >>> 0)) >>> 0) | 0)) | 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy4, [[], '', true, 1, false, -0, (new String('')), '\\0', '0', null, (new Boolean(false)), NaN, '/0/', 0, (function(){return 0;}), (new Number(0)), undefined, /0/, ({toString:function(){return '0';}}), 0.1, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (new Boolean(true)), ({valueOf:function(){return '0';}}), (new Number(-0)), [0]]); ");
/*fuzzSeed-168297596*/count=272; tryItOut("v1 = false;");
/*fuzzSeed-168297596*/count=273; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (( ~ Math.imul(Math.max(Math.fround((Math.fround(1/0) !== Math.atan2(( + Math.min(( + x), ( + x))), ( - ( + ((y ? (-(2**53+2) | 0) : (y | 0)) | 0)))))), (( - Math.sign(2**53+2)) | 0)), (Math.exp(2**53+2) << ( + y)))) | 0); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-168297596*/count=274; tryItOut("o0.e0.add(h1);");
/*fuzzSeed-168297596*/count=275; tryItOut("{m0 = new Map;s1 += 'x'; }");
/*fuzzSeed-168297596*/count=276; tryItOut("var vgclsu, eval, bvgjim, epcybk, x, lpxjpl, \u3056, x, \u3056;this.v0 = (f1 instanceof m2);");
/*fuzzSeed-168297596*/count=277; tryItOut("{/*RXUB*/var r = new RegExp(\".\", \"yi\"); var s = \"\\n\"; print(s.match(r)); print(r.lastIndex);  }");
/*fuzzSeed-168297596*/count=278; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=279; tryItOut("h2.set = (function() { for (var j=0;j<11;++j) { f1(j%4==0); } });c = let (window = \"\\uC0AE\", \u3056, dtiyxh, eval, x)  /x/g ;");
/*fuzzSeed-168297596*/count=280; tryItOut("{ void 0; verifyprebarriers(); } (x);");
/*fuzzSeed-168297596*/count=281; tryItOut("mathy5 = (function(x, y) { return Math.atan((( + Math.atanh(Math.round(( - (y >>> 0))))) ? ((( + ( ~ ( + x))) >>> mathy1(x, x)) ** y) : Math.imul(mathy0(y, 1), Math.pow((((x >>> 0) >>> (0x100000001 >>> 0)) >>> 0), x)))); }); ");
/*fuzzSeed-168297596*/count=282; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.acos(Math.fround((mathy1(Math.fround(Math.atan2((mathy1((y >>> 0), y) >>> 0), x)), ( + (( + -1/0) !== Math.fround((Math.trunc(y) >>> 0))))) * mathy3(y, (y / y))))); }); testMathyFunction(mathy5, [-0x07fffffff, Math.PI, 2**53, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0, Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, -0, Number.MIN_VALUE, -1/0, -0x0ffffffff, 1.7976931348623157e308, 0x080000000, Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, -0x100000001, 0x080000001, -(2**53+2), 2**53-2, 0x0ffffffff, -(2**53), -0x100000000, -(2**53-2), 42, 1/0]); ");
/*fuzzSeed-168297596*/count=283; tryItOut("mathy5 = (function(x, y) { return (Math.imul(((Math.min((( + Math.imul(( + Math.atan2((Math.atan2(Math.fround(0), Math.fround(x)) | 0), y)), ( + y))) >>> 0), mathy0(y, x)) >>> 0) | 0), (((y ? Math.round(( + Math.log10(y))) : x) | 0) * (Math.fround(Math.sign(x)) || y))) <= ( + Math.pow(( + (Math.min(Math.max(y, x), y) , (Math.min(Math.fround(Math.min(y, y)), Math.fround(y)) == Math.acosh(x)))), ( + Math.pow((mathy4(((Math.min((y | 0), ( + Math.trunc(((Math.sqrt((-1/0 | 0)) | 0) | 0)))) | 0) | 0), (Math.PI | 0)) | 0), ( + Math.max(-0x080000000, -Number.MAX_VALUE))))))); }); testMathyFunction(mathy5, [null, -0, false, true, 1, '/0/', objectEmulatingUndefined(), NaN, ({valueOf:function(){return 0;}}), (new Number(-0)), '', 0, (new String('')), 0.1, [], [0], '\\0', (new Boolean(true)), ({valueOf:function(){return '0';}}), (new Boolean(false)), undefined, (function(){return 0;}), (new Number(0)), /0/, '0', ({toString:function(){return '0';}})]); ");
/*fuzzSeed-168297596*/count=284; tryItOut("v1 = g0.eval(\"neuter(b2, \\\"same-data\\\");\");");
/*fuzzSeed-168297596*/count=285; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return mathy0(Math.min(( + mathy0(0x080000001, x)), Math.expm1(( + ( + Math.fround(0x080000001))))), (( + ( ~ Math.hypot((x >>> 0), (( ~ ( ~ (-0x100000000 | 0))) >>> 0)))) | 0)); }); testMathyFunction(mathy1, [-0x0ffffffff, 2**53-2, 2**53, Number.MAX_VALUE, 0x100000001, 0.000000000000001, 0x0ffffffff, -(2**53), -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 42, 0/0, 0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, -0x100000000, -0x080000001, Math.PI, 0x07fffffff, -(2**53+2), -(2**53-2), 2**53+2, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, -1/0, -0x100000001, -0, 1, Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=286; tryItOut("\"use strict\"; for(let a in ((arguments.delete)(e instanceof d))){/* no regression tests found */ }");
/*fuzzSeed-168297596*/count=287; tryItOut("e0.add(t0);");
/*fuzzSeed-168297596*/count=288; tryItOut("/*oLoop*/for (qreoat = 0; qreoat < 28; ++qreoat) { this.o0.e2.has(s1); } ");
/*fuzzSeed-168297596*/count=289; tryItOut("print(uneval(a0));");
/*fuzzSeed-168297596*/count=290; tryItOut("\"use strict\"; for(x in ) {/* no regression tests found */11; }");
/*fuzzSeed-168297596*/count=291; tryItOut("\"use strict\"; \"use asm\"; t1.set(a1, 5);");
/*fuzzSeed-168297596*/count=292; tryItOut("v1 = Object.prototype.isPrototypeOf.call(b0, v2);\nprint(false);\n\nObject.seal(f1);\n");
/*fuzzSeed-168297596*/count=293; tryItOut("mathy0 = (function(x, y) { return ( + Math.imul(Math.imul(Math.max(x, ( + ( ~ (Math.log1p((Math.acos((x >>> 0)) >>> 0)) | 0)))), Math.hypot(( - y), ( ! x))), ( ! Math.fround(Math.clz32(Math.max(x, x)))))); }); ");
/*fuzzSeed-168297596*/count=294; tryItOut("this.v2 = t0.length;");
/*fuzzSeed-168297596*/count=295; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=296; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.hypot((( + ( - ((Math.fround(( + -0x100000001)) % Math.atan2(Math.sinh((2**53-2 >>> 0)), x)) >>> 0))) | 0), (( - ( - ((( - Number.MIN_VALUE) >>> 0) || (( ~ ((x ^ -0x100000000) | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy0, [1, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, -(2**53+2), 0x080000001, Math.PI, -0x100000001, 2**53+2, 42, -0x0ffffffff, 0/0, Number.MIN_VALUE, 0x080000000, -(2**53), 1.7976931348623157e308, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, 2**53-2, -0x080000001, -0x080000000, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 1/0]); ");
/*fuzzSeed-168297596*/count=297; tryItOut("m0.has(p1);\nb0 = t0.buffer;\n");
/*fuzzSeed-168297596*/count=298; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[function(){}, function(){}, function(){}, x, function(){},  /x/g ,  /x/g , function(){}]) { a0.pop(t0); }");
/*fuzzSeed-168297596*/count=299; tryItOut("let (x) { (-22); }");
/*fuzzSeed-168297596*/count=300; tryItOut("\"use strict\"; /*RXUB*/var r = o2.r0; var s = \"\\u00ee\"; print(r.test(s)); ");
/*fuzzSeed-168297596*/count=301; tryItOut("var bzfrpw = new SharedArrayBuffer(4); var bzfrpw_0 = new Uint16Array(bzfrpw); print(bzfrpw_0[0]); bzfrpw_0[0] = -21; /*tLoop*/for (let b of /*MARR*/[]) { print((void options('strict'))); }");
/*fuzzSeed-168297596*/count=302; tryItOut("\"use strict\"; v1 = (f0 instanceof o0);");
/*fuzzSeed-168297596*/count=303; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - (Math.acos(Math.max(x, y)) ? Math.fround(( - ( + Math.clz32(( + x))))) : Math.fround(( ! (Math.ceil(Math.fround(Math.hypot((((((x > x) >>> 0) >> ((Math.log10((x >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0), ( + y)))) >>> 0))))); }); testMathyFunction(mathy1, [2**53-2, Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, -Number.MIN_VALUE, 0x100000001, 0x080000000, Math.PI, -1/0, 0/0, 1, -(2**53-2), -0x100000000, -(2**53+2), -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, -0, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 2**53, 0, -0x100000001]); ");
/*fuzzSeed-168297596*/count=304; tryItOut("m2.delete(s1);");
/*fuzzSeed-168297596*/count=305; tryItOut("g1.v2 = (e0 instanceof b1);");
/*fuzzSeed-168297596*/count=306; tryItOut("\"use strict\"; for (var p in p2) { try { /*ODP-1*/Object.defineProperty(t2, \"1\", ({set: this, configurable: (x % 2 != 0), enumerable: true})); } catch(e0) { } e0.add(true); }this.zzz.zzz;");
/*fuzzSeed-168297596*/count=307; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((( ~ Math.cosh((Math.ceil(y) >>> 0))) || Math.fround((1/0 >>> Math.acosh((Math.atan(y) ? y : ( - Math.fround(Math.min(Math.fround(x), Math.fround(0/0))))))))) + (( ! ( + Math.pow(( + ( + (( + (mathy0((y >>> 0), (( ! y) >>> 0)) >>> 0)) >> ( + Math.fround(Math.pow(Math.fround(x), Math.fround(x))))))), ((Math.min((( + ( ! Math.fround(-0x080000001))) | 0), (x | 0)) | 0) >>> 0)))) >>> 0)); }); ");
/*fuzzSeed-168297596*/count=308; tryItOut("mathy3 = (function(x, y) { return mathy0(( ~ ( ! ( + ( + Math.atanh(Math.sign(Math.pow(y, x))))))), (mathy1((Math.round(Math.fround((( + y) ? y : Math.log1p(x)))) < (Math.acosh(( + ( - Math.atan2(x, ( + x))))) >>> 0)), (Math.imul((y | 0), ((Math.atan2(Math.fround(y), Math.fround(Math.cosh((y >>> 0)))) | 0) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy3, [-0, Math.PI, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, -0x07fffffff, -0x100000000, 2**53-2, 0/0, -(2**53+2), 2**53, 1.7976931348623157e308, 0x080000000, -0x100000001, -0x080000001, 42, 0, 0x0ffffffff, Number.MIN_VALUE, 0x100000001, -(2**53-2), -(2**53), 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -0x080000000, 2**53+2, 0x07fffffff, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=309; tryItOut("testMathyFunction(mathy4, [1, 0x080000001, -0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, 1/0, 0.000000000000001, -0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, 42, Math.PI, -(2**53), -0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, 0/0, -(2**53-2), 2**53+2, -0x080000000, 2**53-2, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-168297596*/count=310; tryItOut("Array.prototype.reverse.apply(g0.a2, [m0, v2,  /x/  &= new 3941066636(/*wrap1*/(function(){ \"use strict\"; f2 = t0[15];return Error.prototype.toString})()(y = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: (\u3056 = window, eval = \"\\u9C95\", x, eval, x, e, y, x, w, NaN, x, w, d = -9223372036854776000, x, x, x, c, y, x, y, x, d, c, x, x, x, a, c, e, x, y, c, b = eval, e, z, x = window, eval = this, b, window, x, \u3056, e, eval, c, x, x, x, eval, \u3056, \u3056, a, d = window, x, e, x, let, x, a, x, c, y, w, x, w, eval = \"\\u29F4\", z, x = true, y, x, e, x, d, z = ({a2:z2}), eval, window =  /x/g , eval = new RegExp(\"(?!(?=.{1,})|(((?!\\\\w))))*?\", \"gi\"), e, w, e, x, x, e, e, b, eval, b = 1.7976931348623157e308, e, \u3056 = window, c, x, y, x = \"\\uDF3F\", d, z, ...e) =>  { yield e } , getOwnPropertyNames: function() { throw 3; }, delete: function() { return false; }, fix: q => q, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: length, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })(Math.pow(new RegExp(\"[^]*|\\\\s\\\\W|\\\\d{2}(([\\u5b3d])(?:[\\\\D]|\\\\b*)){0,}\", \"gi\"),  /x/g )), Math.asin(-0.825)), x))]);");
/*fuzzSeed-168297596*/count=311; tryItOut("/*bLoop*/for (upakjn = 0; upakjn < 3; ++upakjn) { if (upakjn % 73 == 67) { \"\\u3928\"; } else { for (var v of e2) { try { a2.shift(this.e2, h0, t0, t0, t2); } catch(e0) { } m0 + e1; } }  } ");
/*fuzzSeed-168297596*/count=312; tryItOut("/*infloop*/for(let NaN in new RegExp(\"((?!(?=(^)..|[\\\\\\u0005-\\u00da\\\\w\\u50cc\\\\w]+)|\\\\w))\", \"gym\")) Object.preventExtensions(b0);");
/*fuzzSeed-168297596*/count=313; tryItOut("a0.pop();");
/*fuzzSeed-168297596*/count=314; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.log2((Math.fround(( - Math.fround(x))) >>> 0)) !== (Math.max((Math.min(x, (Math.atan(( ~ Number.MAX_VALUE)) >>> 0)) | 0), ( - y)) ? Math.atan2(x, ((Math.fround(Math.imul(y, ( + (Math.hypot((x >>> 0), x) >>> 0)))) && Number.MIN_VALUE) , Math.fround(Math.imul(y, y)))) : ((( + mathy3(0x100000001, y)) < ( + Math.atan2(( + (x < ( + -(2**53-2)))), (Math.hypot((x >>> 0), ( + ( - y))) >>> 0)))) >>> 0))); }); testMathyFunction(mathy5, [0x080000000, 0x100000000, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, -0x080000000, -(2**53-2), -0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, -1/0, 0x07fffffff, -0x100000001, 1.7976931348623157e308, -0x0ffffffff, -0, -0x100000000, -(2**53), 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, -0x080000001, 42, Number.MAX_VALUE, Math.PI, 2**53-2, 0x100000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=315; tryItOut("\"use strict\"; o1 = Object.create(b2);");
/*fuzzSeed-168297596*/count=316; tryItOut("\"use strict\"; b0 = t1.buffer;");
/*fuzzSeed-168297596*/count=317; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.hypot(( + Math.atan2((( - (mathy1((y & Math.fround(y)), 1/0) | 0)) >>> 0), (Math.atan2(Math.fround(Math.fround(Math.ceil(Math.fround((y + y))))), Math.fround(y)) >>> 0))), (( + (Math.fround(( + ( - ( + ( + mathy0(x, ( ~ y))))))) ? Math.fround(Math.fround(( ! Math.fround(Math.fround(( + (Math.atan2((Number.MAX_VALUE >>> 0), 2**53-2) >> y))))))) : Math.fround((Math.hypot(((y - x) >>> 0), ( - y)) + (((x >>> 0) >= x) | 0))))) | 0))); }); testMathyFunction(mathy4, [0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, 0/0, Number.MIN_VALUE, -0, 0, 0x0ffffffff, -0x080000001, -0x07fffffff, -0x080000000, 2**53-2, Math.PI, 1, 42, Number.MAX_VALUE, 0x100000001, 2**53, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -1/0, -(2**53), 1.7976931348623157e308, 0x07fffffff, 0.000000000000001, -0x100000000, -(2**53+2), 2**53+2, -0x0ffffffff, 1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=318; tryItOut("\"use strict\"; g0 = this;function delete(b = x, eval = yield this) { yield -10 } g0.a2 + t2;");
/*fuzzSeed-168297596*/count=319; tryItOut("v2 = undefined;( '' )\u000c;");
/*fuzzSeed-168297596*/count=320; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0((Math.hypot(Math.log10(y), ( + Math.hypot(( - ( + Math.min(Math.asinh(x), Math.min(Math.pow(x, y), y)))), ( + Math.expm1(y))))) >>> 0), Math.fround(( + ((( + ( ! ( + Math.tanh(( ~ (Math.hypot(Math.imul(Number.MAX_VALUE, y), y) | 0)))))) >>> 0) ^ ( + mathy0(y, (( ~ (-(2**53+2) | 0)) | 0))))))) >>> 0); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), 1/0, 0x080000000, -0x07fffffff, 0x100000001, 0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), 0x080000001, 2**53+2, -0x0ffffffff, -0, Math.PI, -0x080000001, 2**53, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0/0, -Number.MAX_VALUE, 1, -1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, Number.MIN_VALUE, 2**53-2, -0x100000000]); ");
/*fuzzSeed-168297596*/count=321; tryItOut("\"use asm\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Uint16ArrayView[0]) = ((0xffffffff)+(((imul((0xfff15779), (0x3961d6ce))|0)) ? ((((0xd1edac9f)-(0xffc2b321)+(0x38cbc37d)) | ((0xff010c11)*-0xf5200)) >= ((((0x7fffffff) != (0x17abb028))-(i0)) << ((i0)-(i0)))) : (i0)));\n    i0 = (-0x8000000);\n    (Float64ArrayView[0]) = ((d1));\n    return +((d1));\n    d1 = (d1);\n    {\n      switch ((~~(+abs(((4194305.0)))))) {\n      }\n    }\n    {\n      i0 = ((0xdcd0ce80) ? (0xf8c95860) : (i0));\n    }\n    {\n      i0 = (i0);\n    }\n    d1 = (67108865.0);\n    return +((+(~((0xffffffff)))));\n  }\n  return f; })(this, {ff: function(y) { return x }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=322; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.trunc((Math.fround(Math.atan2(mathy0(( - ( + (( + ( + Math.pow(( + Math.sinh(x)), ( + y)))) * ( + x)))), ( + ( - ( + y)))), (Math.cos((Math.imul(( + ((( ! y) >>> 0) | ( + x))), (y | 0)) | 0)) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), new Number(1), new Number(1), Uint8Array(), new Number(1), new Number(1), Uint8Array(), new Number(1), new Number(1), Uint8Array(), new Number(1), Uint8Array(), new Number(1), new Number(1), Uint8Array(), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), new Number(1), Uint8Array(), new Number(1), new Number(1), new Number(1), new Number(1), Uint8Array(), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), Uint8Array(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), new Number(1), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), Uint8Array(), new Number(1), new Number(1), new Number(1)]); ");
/*fuzzSeed-168297596*/count=323; tryItOut("/*bLoop*/for (ivmbva = 0, , (makeFinalizeObserver('tenured')), (p={}, (p.z = (-24.valueOf(\"number\")))()); ivmbva < 34; ++ivmbva) { if (ivmbva % 4 == 1) { /*oLoop*/for (let ucszdg = 0; ucszdg < 31; ++ucszdg, 100522905) { print(x); }  } else { print((let (x)  /x/g )); }  } ");
/*fuzzSeed-168297596*/count=324; tryItOut("testMathyFunction(mathy0, [0x080000000, Number.MIN_VALUE, 1, -Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, 0x100000001, -0x100000001, -(2**53-2), 0x100000000, -1/0, -0x0ffffffff, 1/0, 2**53, -0x07fffffff, -0x080000001, -0, 0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, 0/0, -0x100000000, 2**53-2]); ");
/*fuzzSeed-168297596*/count=325; tryItOut("var mxcioi = new SharedArrayBuffer(8); var mxcioi_0 = new Uint8Array(mxcioi); mxcioi_0[0] = 10; a2.splice(NaN, 7, f1);(/(?=[]){1}/gyi);m0 + o0;{};return;( '' );v1 = evaluate(\"/*RXUB*/var r = r0; var s = s0; print(s.split(r)); \", ({ global: g0.g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy:  '' , catchTermination: (mxcioi_0 % 4 != 2), element: this.o2, sourceMapURL: this.s0 }));");
/*fuzzSeed-168297596*/count=326; tryItOut("mathy5 = (function(x, y) { return ( + mathy4(Math.min(mathy4(y, ( + ( + (y ? y : -Number.MAX_VALUE)))), ( + 0/0)), Math.sqrt(( + (((( - Math.fround(y)) | 0) != (Math.clz32(Math.fround((((( + (( + 0x07fffffff) != ( + Number.MIN_VALUE))) > (-1/0 >>> 0)) | 0) << y))) | 0)) | 0))))); }); testMathyFunction(mathy5, [-(2**53-2), -(2**53), 0x0ffffffff, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -0x100000000, 0x100000000, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 2**53-2, -0x0ffffffff, 0x080000001, -0x080000000, -Number.MIN_VALUE, 2**53, 1, -Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, Number.MIN_VALUE, 0, 42, -Number.MAX_SAFE_INTEGER, Math.PI, 0/0, -(2**53+2), -0x07fffffff, -0, 0.000000000000001, 0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=327; tryItOut("\"use strict\"; /*MXX1*/Object.defineProperty(this, \"o1\", { configurable: x, enumerable: Math.max(-5, -29),  get: function() { a0.splice(-9, ({valueOf: function() { o0 = {};return 19; }}), m0, this.m1, x, i1, v0); return g1.ReferenceError.name; } });");
/*fuzzSeed-168297596*/count=328; tryItOut("p1 + '';");
/*fuzzSeed-168297596*/count=329; tryItOut(";");
/*fuzzSeed-168297596*/count=330; tryItOut("d = e;");
/*fuzzSeed-168297596*/count=331; tryItOut("\"use strict\"; /*bLoop*/for (naqlda = 0; naqlda < 30; ++naqlda) { if (naqlda % 11 == 2) { o0.m1.delete(a1); } else { Object.defineProperty(this, \"a1\", { configurable:  /x/g , enumerable: false,  get: function() {  return o2.o1.a0.filter((1 for (x in [])), v1); } }); }  } ");
/*fuzzSeed-168297596*/count=332; tryItOut("for(a in ((encodeURI)(window))){sprmyn(q => q.prototype,  /x/ );/*hhh*/function sprmyn(window, x, x, b, a = x, z = \"\\uACD5\", c, a, x, x, x, a, \u3056, a, c, a, w, y, a, this.y, x, x = z, NaN, y, y, window, a =  \"\" , window, w = 17, eval, \u3056 =  /x/ , a = new RegExp(\".|(([^]){1})^{2,5}\\\\3\", \"gym\"), x, a, toSource, x, c, window =  \"\" , e =  /x/ , c, c, x, x, a, window, x, x, c, a, \u3056, a, \u3056, x, a, b, a, eval = window, window, c, w, a, eval, x, x, a, d, window, y, d, x, c, x, x, a = /(?!\\b{4})|[^\\B\\t-\u0006]++?/gym, d, a, a, w){const b1 = t1.buffer;} }");
/*fuzzSeed-168297596*/count=333; tryItOut("t1[9] = (Math.hypot(x, x || (Math.pow(x, ({arguments: x, -26: null })))));");
/*fuzzSeed-168297596*/count=334; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, -1/0, -Number.MIN_VALUE, 1, Number.MIN_VALUE, -0, 0x0ffffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, 1/0, -Number.MAX_VALUE, 0x100000000, 0x100000001, 0, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 2**53-2, -(2**53-2), -0x100000001, Math.PI, 2**53, -0x080000001, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-168297596*/count=335; tryItOut("testMathyFunction(mathy1, /*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){},  /x/ , new Boolean(false), (0/0), function(){}, new Boolean(false), new Boolean(false),  /x/ , (0/0), new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, {}, function(){}, function(){}, function(){}, (0/0), {}, function(){}, function(){}, new Boolean(false), function(){}, function(){}]); ");
/*fuzzSeed-168297596*/count=336; tryItOut("/*infloop*/for(setter in ({ get x x (a, window, a, window, x, x, x, w, x, a, c = this, a, x, x = false, x, window, c, c = x, b = ({a1:1}), z, c =  '' , z, y =  /x/ , x, window = null, window, x, y, NaN = 9, x, x = \"\\u7DA8\", x, eval, NaN, w, z, x)\"use asm\";   var abs = stdlib.Math.abs;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (i0);\n    }\n    {\n      i0 = (i1);\n    }\n    switch ((abs(((-0x5f535*(0xffffffff)) ^ ((0xffef8104)+(0xb487ee0a))))|0)) {\n    }\n    {\n      i0 = (!(i0));\n    }\n    (Float32ArrayView[(0xa4b02*((67108865.0) >= (17.0))) >> 2]) = ((-65.0));\n    i1 = (i1);\n    {\n      i0 = (i0);\n    }\n    return (((i1)+(i0)))|0;\n  }\n  return f;, name: yield }) ? /*UUV2*/(\u3056.raw = \u3056.stringify) : new /(?!\\b*)+?|(?=[^\\s\\u0013-\\xB3\\w\\cA-\\\ufc18]([^])(?:\\3))/yim(NaN, undefined)) {/*MXX1*/o2 = g2.RegExp.prototype.constructor;/*RXUB*/var r = r0; var s = s2; print(s.match(r)); print(r.lastIndex);  }");
/*fuzzSeed-168297596*/count=337; tryItOut("\"use strict\"; a2[11] = i2;function x()\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    return +((8589934593.0));\n  }\n  return f;v1 = false;");
/*fuzzSeed-168297596*/count=338; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        i1 = (i1);\n      }\n    }\n    {\n      i1 = (((((Float64ArrayView[0]))) >> ((i1)-(0x2619d1a3))));\n    }\n    i1 = (i1);\n    d0 = (+pow(((d0)), ((-67108865.0))));\n    return +((NaN));\n  }\n  return f; })(this, {ff: (new Function(\"h1.set = o2.f2;\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0, /0/, '\\0', objectEmulatingUndefined(), (new Boolean(true)), false, [0], 1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), null, '0', ({valueOf:function(){return 0;}}), 0.1, true, (new String('')), (new Boolean(false)), undefined, (function(){return 0;}), (new Number(0)), NaN, '', -0, (new Number(-0)), '/0/', []]); ");
/*fuzzSeed-168297596*/count=339; tryItOut("\"use strict\"; \"use asm\"; v2 = (h1 instanceof m2);");
/*fuzzSeed-168297596*/count=340; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( + Math.abs((Math.fround(Math.max(Math.fround(( + Math.atan2(( + Math.fround(mathy0(Math.fround(-(2**53-2)), Math.fround(((( ~ (x >>> 0)) >>> 0) >>> x))))), ( + (-0x100000001 | y))))), Math.fround(Math.fround(( - Math.fround(x)))))) >>> 0)))) / Math.fround(Math.hypot(Math.imul(mathy0(Math.fround(((x | (( + (( + y) | ( + y))) | 0)) | 0)), Math.fround((( + (-(2**53-2) | y)) !== y))), ( ~ x)), Math.fround(Math.hypot((y >>> 0), (( + y) >>> 0))))))); }); ");
/*fuzzSeed-168297596*/count=341; tryItOut("/*RXUE*//((?=(?=(?!(?!$)))))/gi.exec(\"\\n\")");
/*fuzzSeed-168297596*/count=342; tryItOut("/*vLoop*/for (iouhgw = 0; iouhgw < 0; ++iouhgw) { let y = iouhgw; /*MXX1*/o2 = g0.Array.prototype.length;function b(d, eval, [], b, e, x = undefined, y, d, \u3056, c, x, y, y, e, w = /[\\t-\u0004\\D]/gm, x, y, a, a, b, d, z, z, d, y, z, x, z, y, b, y = /^|$|(?:\\2?)*?/g, \u3056, z, x, x, y =  '' , x, y, x = false, y, y, e, y, x, x, a, d = \u3056, y, y, x, c = length)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      return +((((+(0.0/0.0)) >= (((+(-1.0/0.0))) - ((-4194305.0)))) ? (4611686018427388000.0) : (+(0.0/0.0))));\n    }\n    i1 = (i1);\n    return +((((Float32ArrayView[((!(0xfac784fa))) >> 2])) - ((d0))));\n  }\n  return f;( /x/g ); } ");
/*fuzzSeed-168297596*/count=343; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min(Math.atan(( + (Math.log10((((Math.fround(Math.min(( ~ x), 0)) ^ Math.fround(0x080000001)) >>> 0) >>> 0)) | 0))), ( ! ( + Math.log2(Math.atanh(( - y)))))); }); ");
/*fuzzSeed-168297596*/count=344; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.fround(Math.max(Math.fround((Math.hypot(((Math.log1p((Math.log2((x >>> 0)) >>> 0)) >>> 0) >>> 0), (((((x > Math.fround(Math.min(y, y))) ? y : (y | 0)) >>> 0) ^ x) >>> 0)) >>> 0)), Math.fround(( ! ((( + Math.min(( ~ Math.abs(( + y))), x)) >>> 0) >>> ( + ( - (y >>> 0)))))))) || ( + ( + ( + Math.fround(mathy0(Math.atan2(Number.MAX_SAFE_INTEGER, y), (Math.pow(Math.fround(Number.MIN_SAFE_INTEGER), ((( + y) ** ( + (Math.max((Math.min(x, -0x0ffffffff) >>> 0), (-Number.MAX_VALUE >>> 0)) >>> 0))) | 0)) | 0))))))); }); testMathyFunction(mathy1, [objectEmulatingUndefined(), (new Number(0)), ({valueOf:function(){return 0;}}), '', (new Number(-0)), 1, '/0/', '0', true, 0.1, NaN, (new Boolean(true)), '\\0', null, (function(){return 0;}), -0, 0, ({valueOf:function(){return '0';}}), [], ({toString:function(){return '0';}}), (new String('')), (new Boolean(false)), undefined, /0/, [0], false]); ");
/*fuzzSeed-168297596*/count=345; tryItOut("/*RXUB*/var r = /\\3(?=\\w{2,})|($)?|(\\3*?)+?*/i; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-168297596*/count=346; tryItOut("mathy5 = (function(x, y) { return Math.pow(( + (Math.ceil((Math.pow((0x0ffffffff | 0), (( + (mathy1(( - Math.clz32(x)), x) | 0)) | 0)) | 0)) >>> 0)), ( - ((( + Math.cbrt(Math.fround(Math.atan2((Math.min(( + (( + x) , ( + 42))), y) | 0), (( + (Math.fround(Math.pow(Math.fround(x), Math.fround(y))) >>> 0)) | 0))))) ? ( + Math.hypot((x | 0), Math.fround(( - Math.fround(( + (y / ( + Math.sinh(y))))))))) : ( + (((x >>> 0) % (y >>> 0)) >>> 0))) >>> 0))); }); testMathyFunction(mathy5, /*MARR*/[ /x/g ,  /x/g ]); ");
/*fuzzSeed-168297596*/count=347; tryItOut("\"use strict\"; a0.shift();");
/*fuzzSeed-168297596*/count=348; tryItOut("a2.splice(NaN, 3);");
/*fuzzSeed-168297596*/count=349; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (((Math.hypot(( - ( + Math.fround(Math.imul(-Number.MIN_VALUE, Math.acosh(y))))), (mathy4(((Math.max(Math.fround(( ~ Math.fround(x))), Math.fround(y)) | 0) ? x : x), Math.fround((x ? Math.imul(y, ( + Number.MIN_VALUE)) : Math.atan2(y, Math.fround(( ~ y)))))) | 0)) | 0) >= Math.fround(Math.max(Math.fround(( ~ (( + ( + (( + (Math.log2(Number.MAX_SAFE_INTEGER) | 0)) ? ( + y) : (Math.max(x, x) | 0)))) >>> 0))), Math.fround(((Math.atanh(Math.fround(Math.tanh(Math.fround(-0x080000001)))) / ( + Math.tanh(x))) | 0))))) | 0); }); testMathyFunction(mathy5, /*MARR*/[-0x080000000, -0x080000000, -0x080000000, -0x080000000]); ");
/*fuzzSeed-168297596*/count=350; tryItOut("mathy4 = (function(x, y) { return ( + Math.acosh(( + Math.fround((((Math.asinh(Math.clz32(x)) > ( + x)) || ((( + y) || ( + y)) - (-(2**53) >= Math.fround((( + y) >>> Math.fround(y)))))) | Math.fround(( ~ ( + Math.fround((( + ( + ((Math.ceil((-1/0 | 0)) | 0) , x))) ^ ( + (Math.sinh(x) >>> 0)))))))))))); }); testMathyFunction(mathy4, ['', (function(){return 0;}), (new String('')), 0, false, [0], objectEmulatingUndefined(), 0.1, true, '0', (new Number(0)), (new Number(-0)), 1, '\\0', ({toString:function(){return '0';}}), /0/, ({valueOf:function(){return '0';}}), (new Boolean(true)), (new Boolean(false)), '/0/', -0, ({valueOf:function(){return 0;}}), [], NaN, undefined, null]); ");
/*fuzzSeed-168297596*/count=351; tryItOut("\"use strict\"; print(x);\nprint(x);\n/*tLoop*/for (let e of /*MARR*/[3, ({x:3}), ({x:3}), ({x:3}), 3, 3, new Number(1.5), 3, 3, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), ({x:3}), ({x:3}), 3, new Number(1.5)]) { ; }const b = \"\\u9DE5\";");
/*fuzzSeed-168297596*/count=352; tryItOut("\"use strict\"; b, ueqbtt, set, galzqp, slxfoi;m0 = new Map;");
/*fuzzSeed-168297596*/count=353; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(Math.ceil(Math.fround(( + (( + ((y + ( - (((42 | 0) % x) >>> 0))) % y)) && 2**53+2))))) == Math.log2(Math.acos(y))); }); testMathyFunction(mathy0, /*MARR*/[1.2e3, return eval(\"/* no regression tests found */\"), 1.2e3, return eval(\"/* no regression tests found */\"), {}, [(void 0)]]); ");
/*fuzzSeed-168297596*/count=354; tryItOut("\"use strict\"; L: return;");
/*fuzzSeed-168297596*/count=355; tryItOut("m0[8] = a0;");
/*fuzzSeed-168297596*/count=356; tryItOut("/*vLoop*/for (let woqjws = 0; (/([^]){536870913,536870916}/) && woqjws < 10; ++woqjws) { c = woqjws; 13; } ");
/*fuzzSeed-168297596*/count=357; tryItOut("\"use strict\"; [1];\n(new RegExp(\"(?:(?=(?=$[^\\ud757\\\\xA7-\\ub7e7\\\\t-\\\\u205A\\\\x96]{3,4}*?)))\", \"gim\"));\nfunction e(x, b, x, z, x, {}, x, b, x, \u3056, this.NaN, e, window, a, a, c, x, NaN, \u3056, e) { \"use strict\"; yield (a) = /\u0013/g += [1,,] } print((true ? \u3056-- : x));");
/*fuzzSeed-168297596*/count=358; tryItOut("\"use strict\"; x.message;");
/*fuzzSeed-168297596*/count=359; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(Math.pow(Math.fround((( ~ x) - Math.abs(x))), Math.fround(( + Math.pow(( + Math.imul(( ~ Math.fround(0x100000001)), ( + ( + 1)))), ( + (( + Math.min(y, (Math.trunc(y) >>> 0))) == ( + ( + Math.fround((Math.fround((x ? Math.fround(x) : Math.fround(y))) - y))))))))))); }); testMathyFunction(mathy1, [0.000000000000001, 0x100000000, -0, -0x100000000, 0x080000000, 0x080000001, 0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, -Number.MIN_VALUE, 2**53, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -1/0, Math.PI, 1, -(2**53-2), 42, Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff, 0/0, -0x080000001, -(2**53+2), -(2**53), 1/0, Number.MAX_VALUE, -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=360; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=361; tryItOut("testMathyFunction(mathy1, [Math.PI, -1/0, Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, -Number.MIN_VALUE, 0/0, 0x100000001, -0x100000001, 0.000000000000001, -0, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, -0x080000000, 2**53, -0x080000001, 0x0ffffffff, 2**53-2, -Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, 0, 1/0, 2**53+2, -(2**53+2)]); ");
/*fuzzSeed-168297596*/count=362; tryItOut("o2 = x;");
/*fuzzSeed-168297596*/count=363; tryItOut("print(uneval(p2));");
/*fuzzSeed-168297596*/count=364; tryItOut("{print(x);( \"\" ); }function NaN()\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -72057594037927940.0;\n    return +((d1));\n  }\n  return f;e0 = a1[11];");
/*fuzzSeed-168297596*/count=365; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    switch (((((0xf644f8fe))+((0xff53811f) ? (0x3893916b) : (0xfd7cf014))) | ((/*FFI*/ff()|0)+((0x411e4092))))) {\n      case 0:\n        {\n          return (((i1)))|0;\n        }\n        break;\n      case 1:\n        {\n          i1 = (i0);\n        }\n        break;\n      case -1:\n        (Uint16ArrayView[((i0)+((-9.44473296573929e+21) >= (-0.0078125))-((i0) ? (-0x5b6c94b) : (0xf17eddee))) >> 1]) = (((i1) ? ((Math.imul(29, 21)) != (0xd9af5148)) : ((i1) ? (i0) : ((p={}, (p.z =  \"\" (\"\\u8545\"))()))))-(i1));\n        break;\n      case 0:\n        {\n          i1 = ((8191.0) <= (+atan(((NaN)))));\n        }\n      default:\n        return ((/*RXUE*//$/gim.exec(\"\")))|0;\n    }\n    (Float32ArrayView[4096]) = ((17592186044417.0));\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: Map.prototype.clear}, new ArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=366; tryItOut("testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 0/0, 0x080000001, 1/0, 2**53-2, -0, Number.MIN_VALUE, -(2**53-2), -0x080000001, -0x100000001, Math.PI, -0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -(2**53), 1, 2**53, -1/0, 42, -0x07fffffff, -(2**53+2), 1.7976931348623157e308, 0x080000000, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=367; tryItOut("mathy1 = (function(x, y) { return ( ~ (((Math.max((x + mathy0(Math.imul(Math.fround(x), Math.min(-0, -Number.MIN_SAFE_INTEGER)), y)), (Math.acosh((x >>> 0)) >>> 0)) >>> 0) | Math.fround(mathy0((( ! (x >>> 0)) >>> 0), (y ? Math.atanh(x) : ( - ( + x)))))) >>> 0)); }); ");
/*fuzzSeed-168297596*/count=368; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[new Number(1), new String(''), new String(''), new String(''), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new String(''), new String(''), new Boolean(false), new String(''), new String(''), new String(''), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new String(''), new Boolean(false), new String(''), new String(''), new Boolean(false), new Number(1), new Boolean(false), new String(''), new Number(1), new String(''), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new String(''), new String(''), new String(''), new Boolean(false), new String(''), new Number(1), new Number(1), new Number(1), new String(''), new Boolean(false), new Boolean(false), new Boolean(false), new String(''), new String(''), new Boolean(false), new Number(1), new Number(1), new String(''), new Boolean(false), new String(''), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Number(1), new Number(1), new Boolean(false), new String(''), new String(''), new Boolean(false), new Number(1)]) { o1.v2 = (g0 instanceof b0); }");
/*fuzzSeed-168297596*/count=369; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy2, ['/0/', null, 0.1, ({valueOf:function(){return '0';}}), '0', (new Boolean(true)), [0], (new Boolean(false)), objectEmulatingUndefined(), undefined, true, -0, [], /0/, (new Number(-0)), (new Number(0)), (new String('')), ({valueOf:function(){return 0;}}), '\\0', false, 0, ({toString:function(){return '0';}}), (function(){return 0;}), NaN, 1, '']); ");
/*fuzzSeed-168297596*/count=370; tryItOut("f0 = Proxy.createFunction(h0, f0, f2);");
/*fuzzSeed-168297596*/count=371; tryItOut("this.s1 = '';");
/*fuzzSeed-168297596*/count=372; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=373; tryItOut("\"use strict\"; a1.toString = f2;");
/*fuzzSeed-168297596*/count=374; tryItOut("\"use strict\"; Array.prototype.splice.apply(a1, [9, 0]);");
/*fuzzSeed-168297596*/count=375; tryItOut("\"use asm\"; ((p={}, (p.z = window)()));");
/*fuzzSeed-168297596*/count=376; tryItOut("print(i2);");
/*fuzzSeed-168297596*/count=377; tryItOut("/*oLoop*/for (bhjpxy = 0; bhjpxy < 144; ++bhjpxy) { m1 = new Map; } ");
/*fuzzSeed-168297596*/count=378; tryItOut("\"use strict\"; m0.set(g1.t2, t0);");
/*fuzzSeed-168297596*/count=379; tryItOut("b0.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17) { var r0 = a10 | a7; var r1 = x + 8; x = r0 ^ 3; var r2 = 5 / 7; a8 = r0 % a2; a11 = 4 ^ 5; var r3 = x + 7; var r4 = 6 % a10; var r5 = r2 | a15; return a12; });");
/*fuzzSeed-168297596*/count=380; tryItOut(";");
/*fuzzSeed-168297596*/count=381; tryItOut("\"use strict\"; Array.prototype.reverse.call(g2.a2);");
/*fuzzSeed-168297596*/count=382; tryItOut("x;");
/*fuzzSeed-168297596*/count=383; tryItOut("\"use strict\"; \"use asm\"; var itkauk = new ArrayBuffer(2); var itkauk_0 = new Float32Array(itkauk); print(itkauk_0[0]); var itkauk_1 = new Uint32Array(itkauk); print(itkauk_1[0]); var itkauk_2 = new Int32Array(itkauk); print(itkauk_2[0]); itkauk_2[0] = -0; var itkauk_3 = new Float64Array(itkauk); itkauk_3[0] = -18; window === e;Object.seal(o2);");
/*fuzzSeed-168297596*/count=384; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-168297596*/count=385; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + Math.imul(Math.fround(Math.max((Math.fround(Math.tan(Math.fround(Math.fround(( + Math.fround(x)))))) | 0), Math.fround(( + Math.acos(( + ((x <= (( + Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0))))))), ( ~ Math.fround(Math.acosh((Math.min(( + y), ( + (x >>> Math.fround(y)))) | 0)))))) >>> (((Math.fround(Math.min(Math.fround(Math.atanh(Math.hypot((x ? (-Number.MIN_SAFE_INTEGER | 0) : 0x080000001), x))), (Math.trunc(Math.fround(Math.cbrt(x))) >>> 0))) >>> 0) >> ( + (((Math.atan(0x080000001) | 0) >> ( - Math.fround((( + ( + Number.MAX_VALUE)) >= Math.fround((x > Number.MAX_VALUE)))))) | 0))) >>> 0)); }); testMathyFunction(mathy0, [-0x0ffffffff, Number.MIN_VALUE, 0x080000001, 1/0, -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, 42, 0, 2**53+2, -0, -0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, 0x100000000, 2**53, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1, 2**53-2, Number.MAX_VALUE, -0x100000000, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-168297596*/count=386; tryItOut("o0 = new Object;");
/*fuzzSeed-168297596*/count=387; tryItOut("mathy1 = (function(x, y) { return ( + ((( + 2**53) | ( + Math.fround(( ~ Math.fround(x))))) !== ( - Math.fround(Math.ceil((y | 0)))))); }); testMathyFunction(mathy1, [({toString:function(){return '0';}}), NaN, 1, 0, (new Number(-0)), objectEmulatingUndefined(), true, null, (function(){return 0;}), ({valueOf:function(){return 0;}}), [], undefined, 0.1, /0/, ({valueOf:function(){return '0';}}), (new Number(0)), false, [0], '/0/', (new Boolean(true)), (new Boolean(false)), (new String('')), -0, '', '0', '\\0']); ");
/*fuzzSeed-168297596*/count=388; tryItOut("\"use strict\"; i1.send(i0);");
/*fuzzSeed-168297596*/count=389; tryItOut("Array.prototype.forEach.apply(a1, [(function() { try { i2 + v0; } catch(e0) { } try { v0 = (a2 instanceof o2); } catch(e1) { } t1 = new Int16Array(t2); return b0; })]);");
/*fuzzSeed-168297596*/count=390; tryItOut("mathy1 = (function(x, y) { return Math.fround(( + Math.max(Math.atan2((mathy0(Math.fround(mathy0((y | 0), Math.fround(-(2**53)))), Math.trunc((1 | 0))) | 0), Math.fround(((y >>> 0) * (x >>> 0)))), (Math.min(mathy0(-(2**53), mathy0(y, (( + ((mathy0(y, (-0x0ffffffff >>> 0)) >>> 0) >>> 0)) >>> 0))), Math.min(mathy0(x, (mathy0(y, (0.000000000000001 ? x : y)) | 0)), (mathy0(((Math.cosh(((y >> x) >>> 0)) >>> 0) >>> 0), (-0x100000000 >>> 0)) >>> 0))) >>> 0)))); }); testMathyFunction(mathy1, [0/0, -0x07fffffff, -0x080000001, 42, 2**53-2, 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 1/0, 0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), -0, 0x0ffffffff, 0x07fffffff, -(2**53), 2**53+2, 0x100000001, 2**53, 0x100000000, 0x080000001, -1/0, -0x0ffffffff, 1.7976931348623157e308, Math.PI, -Number.MIN_VALUE, Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=391; tryItOut("testMathyFunction(mathy3, [1.7976931348623157e308, -0x080000000, -(2**53+2), 0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, 42, Math.PI, 0.000000000000001, 2**53, Number.MAX_VALUE, 1/0, 0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 1, 0x0ffffffff, -1/0, 0x100000001, 0x080000000, -0, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, 0/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-168297596*/count=392; tryItOut("/*bLoop*/for (var axcghs = 0; axcghs < 13; ++axcghs) { if (axcghs % 5 == 4) { print(uneval(m1)); } else { s1 += 'x'; }  } ");
/*fuzzSeed-168297596*/count=393; tryItOut("\"use strict\"; /*infloop*/ for  each(z in ((void options('strict')))) {v0 = this.t0.length; }");
/*fuzzSeed-168297596*/count=394; tryItOut("mathy3 = (function(x, y) { return ( + (Math.expm1((Math.hypot(( + Math.acos(( + (( ~ (x | 0)) | 0)))), (x & (Math.imul((x >>> 0), (x >>> 0)) >>> 0))) | 0)) | 0)); }); testMathyFunction(mathy3, [NaN, undefined, '/0/', [0], objectEmulatingUndefined(), 1, (new String('')), (new Boolean(false)), '', '\\0', /0/, (function(){return 0;}), 0.1, -0, ({valueOf:function(){return 0;}}), true, (new Number(0)), (new Boolean(true)), ({valueOf:function(){return '0';}}), false, ({toString:function(){return '0';}}), null, (new Number(-0)), 0, '0', []]); ");
/*fuzzSeed-168297596*/count=395; tryItOut("\"use strict\"; \"use asm\"; a0 = a0.filter((function() { try { i1.next(); } catch(e0) { } try { /*MXX2*/g1.RegExp.lastParen = a1; } catch(e1) { } a1.shift(i1); return t1; }));");
/*fuzzSeed-168297596*/count=396; tryItOut("\"use strict\"; /*oLoop*/for (let xubnit = 0; xubnit < 136; ++xubnit) { a2.unshift(this.o1); } ");
/*fuzzSeed-168297596*/count=397; tryItOut("\"use strict\"; for (var v of f0) { try { s2.toString = (function(j) { if (j) { try { g0.a2.unshift(m2, this.g0, m2); } catch(e0) { } try { i2 = t2[v2]; } catch(e1) { } const v0 = false; } else { try { g0.f2 = Proxy.create(h0, g1.a0); } catch(e0) { } try { e0.add(v0); } catch(e1) { } try { o2 = e2.__proto__; } catch(e2) { } t2 = a1[3]; } }); } catch(e0) { } try { t1[o2.v0]; } catch(e1) { } t2.toString = f1; }");
/*fuzzSeed-168297596*/count=398; tryItOut("\"use strict\"; b2 = t2.buffer;");
/*fuzzSeed-168297596*/count=399; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.fround((mathy0(Math.fround(mathy2(Math.fround(((Math.log2(( + Math.pow(( + y), y))) >>> 0) ? ( + ( ~ ( ! x))) : Math.acos(Math.fround(( ! Math.fround(0/0)))))), ((y < mathy4(( + x), ( + (( + y) & (mathy0((-0x080000000 >>> 0), (y >>> 0)) >>> 0))))) >>> 0))), (Math.fround(((y | y) | 0)) / Math.fround(( + (( + x) ? Math.fround((Math.atan((y | 0)) | 0)) : ( + x)))))) | 0))); }); testMathyFunction(mathy5, [1.7976931348623157e308, Math.PI, -0x100000000, -0x07fffffff, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, -Number.MAX_VALUE, 2**53+2, 0x100000000, -0x0ffffffff, 0x100000001, 0x080000000, 0/0, -1/0, 42, Number.MIN_VALUE, -0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1, 0, 0x080000001, -Number.MIN_VALUE, -0, -0x100000001, 0x0ffffffff, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=400; tryItOut("var x, inbnxk, utjmqb, x, x;c;");
/*fuzzSeed-168297596*/count=401; tryItOut("\"use strict\"; var r0 = x - x; x = r0 & r0; var r1 = r0 + x; var r2 = 5 % 1; var r3 = x * 0; var r4 = 6 - 5; var r5 = 9 - r2; var r6 = 5 - 6; var r7 = r1 / 8; ");
/*fuzzSeed-168297596*/count=402; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( - (( + (Math.round(((( ~ (((x === ((((y >>> 0) ? (x >>> 0) : (y >>> 0)) >>> 0) >>> 0)) >>> 0) ? y : Math.min(x, x))) >>> 0) >>> 0)) | 0)) | 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=403; tryItOut("/*RXUB*/var r = /\\D*|\\2+?/gym; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-168297596*/count=404; tryItOut("x;");
/*fuzzSeed-168297596*/count=405; tryItOut("var ukzrbn = new ArrayBuffer(8); var ukzrbn_0 = new Int16Array(ukzrbn); var ukzrbn_1 = new Int32Array(ukzrbn); print(ukzrbn_1[0]); ukzrbn_1[0] = -19; print(ukzrbn_1[1]);print(ukzrbn_1[0]);");
/*fuzzSeed-168297596*/count=406; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-168297596*/count=407; tryItOut("testMathyFunction(mathy3, [0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, 0x100000000, -0x080000000, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, -(2**53), 2**53+2, 42, 0x07fffffff, -(2**53-2), 0x080000000, -0x080000001, -0, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 2**53, 0x100000001, Number.MAX_VALUE, 0, 1.7976931348623157e308, 1, 0/0, Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-168297596*/count=408; tryItOut("\"use asm\"; ydeacn([[]], \"\\u322F\");/*hhh*/function ydeacn(a){(true);}");
/*fuzzSeed-168297596*/count=409; tryItOut("\"use strict\"; e0 = new Set(o1.e2);");
/*fuzzSeed-168297596*/count=410; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ! Math.clz32(Math.acosh(( + mathy0(Math.pow(y, (Number.MAX_VALUE >>> 0)), Math.trunc(-1/0)))))) >>> 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 42, 2**53+2, -(2**53), 0, 0x100000001, 2**53, 0x080000001, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, 0x07fffffff, 0x100000000, 1/0, -0x0ffffffff, 1, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, Math.PI, -0x080000000, Number.MIN_VALUE, 0/0, 0x080000000]); ");
/*fuzzSeed-168297596*/count=411; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return Math.expm1(Math.fround(Math.atan2(Math.fround(( ~ Math.min(x, x))), (Math.sinh(Math.fround(Math.atan2((( + (y | 0)) | 0), Math.fround(-(2**53+2))))) | 0)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 1/0, -Number.MAX_VALUE, 2**53-2, 2**53+2, 0x07fffffff, 0, -(2**53), -0x07fffffff, -0x080000000, -Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1, Math.PI, 0x100000001, Number.MIN_VALUE, 0x080000000, -(2**53-2), -(2**53+2), -0x100000000, 42, -1/0, Number.MAX_VALUE, 0/0, 0x100000000, -0, -0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=412; tryItOut("\"use strict\"; v0 = (this.t2 instanceof b2);Object.preventExtensions(p0);");
/*fuzzSeed-168297596*/count=413; tryItOut("mathy2 = (function(x, y) { return ((Math.log10(Math.pow(x, Math.log(x))) >>> 0) >>> ((((( + (( + x) ? Number.MIN_SAFE_INTEGER : 0x100000000)) || ( + Math.tan(x))) ? (Math.tanh(Math.fround(Math.atan(y))) | 0) : ((Math.cos((y >>> 0)) >>> 0) | 0)) ? ( - (Math.hypot(y, x) | 0)) : (( + Math.max(0, (x >>> 0))) / ( + mathy0(x, 1.7976931348623157e308)))) > Math.round(mathy0(Math.acosh(-(2**53-2)), x)))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, 2**53+2, 1.7976931348623157e308, 0, 1/0, -Number.MAX_VALUE, -(2**53-2), -0x100000000, 1, -(2**53), 0.000000000000001, Math.PI, -1/0, -0x100000001, -(2**53+2), 0x07fffffff, 42, -0x0ffffffff, 0x100000000, -0, 2**53-2, Number.MIN_VALUE, 0x100000001, -0x080000000, -0x080000001, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=414; tryItOut("\"use asm\"; t2.__proto__ = a2;");
/*fuzzSeed-168297596*/count=415; tryItOut("/*infloop*/M:for(let a; ((function sum_slicing(wtbljv) { v0 = Infinity;; return wtbljv.length == 0 ? 0 : wtbljv[0] + sum_slicing(wtbljv.slice(1)); })(/*MARR*/[ \"use strict\" ,  \"use strict\" ,  \"use strict\" , [1],  \"use strict\" , [1],  \"use strict\" ,  \"use strict\" ,  \"use strict\" , [1],  \"use strict\" , [1], [1], [1],  \"use strict\" ,  \"use strict\" , [1], [1]])); (({length: (arguments[\"-2\"]) = (void options('strict_mode')), call: [,,] }))) {{ if (!isAsmJSCompilationAvailable()) { void 0; verifyprebarriers(); } void 0; } /*MXX1*/this.o1 = g1.String.prototype.toString;;L:if( '' ) {/*MXX1*/o0 = g0.Error.prototype.name;print(b); } }");
/*fuzzSeed-168297596*/count=416; tryItOut("\"use strict\"; var dxfhlz = new SharedArrayBuffer(24); var dxfhlz_0 = new Int16Array(dxfhlz); dxfhlz_0[0] = 10; var dxfhlz_1 = new Uint32Array(dxfhlz); var dxfhlz_2 = new Float32Array(dxfhlz); var dxfhlz_3 = new Int16Array(dxfhlz); dxfhlz_3[0] = -4; var dxfhlz_4 = new Uint16Array(dxfhlz); print(dxfhlz_4[0]); dxfhlz_4[0] = 23; var dxfhlz_5 = new Float32Array(dxfhlz); dxfhlz_5[0] = 0; var dxfhlz_6 = new Uint8Array(dxfhlz); dxfhlz_6[0] = -15; var dxfhlz_7 = new Int32Array(dxfhlz); dxfhlz_7[0] = -23; e1.add(p2);print(dxfhlz_7[0]);s1 = s0.charAt(8);");
/*fuzzSeed-168297596*/count=417; tryItOut("testMathyFunction(mathy5, [-0x100000001, 2**53, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, 0x100000001, 1.7976931348623157e308, -0, Number.MAX_VALUE, -0x080000000, Math.PI, 0.000000000000001, -0x080000001, 2**53+2, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -1/0, 0x080000000, -(2**53-2), 1, 0, 2**53-2, 1/0, -(2**53), -(2**53+2), 0x07fffffff, 0x0ffffffff, 42]); ");
/*fuzzSeed-168297596*/count=418; tryItOut("\"use strict\"; const hftdqc, x;e = linkedList(e, 2610);");
/*fuzzSeed-168297596*/count=419; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[-0x100000000]) { this.f2(h1); }");
/*fuzzSeed-168297596*/count=420; tryItOut("mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return ((((Math.fround(Math.clz32((((Math.hypot(-(2**53+2), y) >>> 0) || (Math.hypot(y, x) | 0)) | 0))) > ( + Math.hypot(( + (Math.fround(0x080000000) <= ( + -Number.MAX_SAFE_INTEGER))), ( + x)))) | 0) ? (Math.fround((Math.acosh((1/0 ? 0.000000000000001 : x)) < Math.fround(Math.tan(Math.imul(Math.max(( ~ y), x), (((Math.cosh(Math.fround(y)) | 0) !== (y | 0)) | 0)))))) >>> 0) : Math.max(Math.fround(( + (( - Math.hypot(1.7976931348623157e308, x)) >>> 0))), (( + Math.fround(Math.round(Math.fround((( + (( + y) >>> ( + y))) ? ( + y) : y))))) * (x | 0)))) | 0); }); testMathyFunction(mathy0, [-(2**53+2), 2**53, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0, -0x080000001, -Number.MAX_VALUE, 0.000000000000001, Number.MAX_VALUE, 0x100000000, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 0x080000001, 1.7976931348623157e308, 0/0, 1/0, Math.PI, -(2**53), -0x0ffffffff, 2**53+2, 2**53-2, -0x080000000, -Number.MIN_VALUE, 1, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=421; tryItOut("testMathyFunction(mathy5, /*MARR*/[x, new Number(1.5), x, new String('q'), x, new Number(1.5), x, x, x, new Number(1.5), x, new Number(1.5), x, x, x, new Number(1.5), new Number(1.5), x, x, new Number(1.5), new String('q'), new Number(1.5), x, new String('q'), new Number(1.5), new Number(1.5), new String('q'), new Number(1.5), x, x, new Number(1.5), x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1.5), new Number(1.5), new Number(1.5), new String('q'), new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, new Number(1.5), new Number(1.5), new Number(1.5), x, x, new Number(1.5), new String('q'), new Number(1.5), x, new String('q'), x, new Number(1.5), new String('q'), x, new Number(1.5), x, x, new Number(1.5), new String('q'), new String('q'), new String('q'), new Number(1.5), x, new Number(1.5), new String('q'), new String('q'), x, x, new String('q'), x, new Number(1.5), new Number(1.5), new Number(1.5), x, new Number(1.5), x, new Number(1.5), new String('q'), x, new Number(1.5), new Number(1.5), new String('q'), new String('q'), new String('q'), new Number(1.5), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1.5), new Number(1.5), x, new Number(1.5), new String('q'), x, new Number(1.5), new Number(1.5), new String('q'), x, new String('q'), x, new String('q'), new String('q'), new String('q')]); ");
/*fuzzSeed-168297596*/count=422; tryItOut("testMathyFunction(mathy2, [0x100000001, -(2**53+2), -0x100000000, 0, 0x080000001, 0x080000000, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), -0x0ffffffff, -0, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, 0.000000000000001, 2**53+2, 1, -0x07fffffff, 0x100000000, Math.PI, 2**53-2, 0x07fffffff, -0x080000000, -(2**53), 2**53, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=423; tryItOut("");
/*fuzzSeed-168297596*/count=424; tryItOut("\"use strict\"; a1 = /*MARR*/[new String('q'), new RegExp(\"($)\", \"yim\"), new String('q'), new String('q'), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), objectEmulatingUndefined(), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), new String('q'), new RegExp(\"($)\", \"yim\"), new String('q'), new String('q'), new RegExp(\"($)\", \"yim\"), new String('q'), objectEmulatingUndefined(), new RegExp(\"($)\", \"yim\"), new String('q'), new String('q'), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new String('q'), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), new String('q'), new RegExp(\"($)\", \"yim\"), new String('q'), new RegExp(\"($)\", \"yim\"), new String('q'), objectEmulatingUndefined(), new String('q'), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), new String('q'), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), new String('q'), new String('q'), new RegExp(\"($)\", \"yim\"), new RegExp(\"($)\", \"yim\"), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new RegExp(\"($)\", \"yim\")];");
/*fuzzSeed-168297596*/count=425; tryItOut("\"use strict\"; Array.prototype.push.call(a0, 29.__defineGetter__(\"x\", 281474976710656), o0.v1, o2.h0);\nthis.v1 = g1.eval(\"/* no regression tests found */\");\n");
/*fuzzSeed-168297596*/count=426; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - Math.fround(mathy0(Math.fround(Math.fround(mathy2(Math.fround(Math.log2(Math.fround(((y || (x >>> 0)) >> (y !== mathy0(Number.MIN_SAFE_INTEGER, (Number.MAX_SAFE_INTEGER >>> 0))))))), y))), Math.fround(Math.tanh(((((Math.max(Math.fround(Number.MIN_SAFE_INTEGER), (x >>> 0)) >>> 0) >>> 0) ? (Math.fround(mathy1(Math.fround(( + ( ~ x))), (Math.fround(x) >>> Math.fround(Number.MAX_VALUE)))) >>> 0) : (mathy3(Math.acosh(( + y)), y) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy4, [objectEmulatingUndefined(), -0, (function(){return 0;}), (new Number(0)), false, '\\0', /0/, (new Boolean(false)), true, 0.1, ({valueOf:function(){return 0;}}), '', ({valueOf:function(){return '0';}}), [0], 1, (new Boolean(true)), NaN, (new Number(-0)), undefined, (new String('')), 0, '0', null, ({toString:function(){return '0';}}), '/0/', []]); ");
/*fuzzSeed-168297596*/count=427; tryItOut("");
/*fuzzSeed-168297596*/count=428; tryItOut("v1 = (e1 instanceof t1);");
/*fuzzSeed-168297596*/count=429; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.max((Math.atan2((( - 0x080000001) | 0), (((Math.pow(( ~ y), x) >>> 0) & (2**53-2 !== Math.fround(y))) | 0)) | 0), Math.fround((Math.fround((((Math.pow(y, (( ! ((Math.fround(2**53-2) <= Math.fround(y)) >>> 0)) >>> 0)) >>> 0) ? x : (Math.fround((((Math.trunc(x) | 0) | 0) % x)) >>> 0)) >>> 0)) ** Math.fround(Math.pow(Math.fround((Math.fround(( - Math.sinh(y))) != Math.fround(( ~ Math.fround(-0x0ffffffff))))), (( + y) - (Math.fround(( ! y)) | 0))))))); }); ");
/*fuzzSeed-168297596*/count=430; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=431; tryItOut("Object.defineProperty(this, \"a2\", { configurable: false, enumerable:  /x/g ,  get: function() {  return []; } });");
/*fuzzSeed-168297596*/count=432; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\B\", \"gyim\"); var s = \" 1\"; print(s.replace(r, s)); ");
/*fuzzSeed-168297596*/count=433; tryItOut("a2[14] = o0;");
/*fuzzSeed-168297596*/count=434; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! (Math.ceil((( + y) | 0)) | 0)); }); testMathyFunction(mathy5, [-0x0ffffffff, Number.MAX_VALUE, 42, 0x080000001, -0x100000001, -0x07fffffff, 0, -(2**53), -Number.MAX_VALUE, 1, -0x080000001, -0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, 2**53-2, Math.PI, 0x080000000, -Number.MIN_VALUE, -0x100000000, 0/0, 0x100000000, -(2**53+2), 0x100000001, 1.7976931348623157e308, 0.000000000000001, Number.MIN_VALUE, -0x080000000, 1/0, 2**53+2, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=435; tryItOut("\"use asm\"; print(x); x = 2 ^ x; var r0 = x ^ x; r0 = r0 - x; var r1 = 8 ^ r0; x = 6 + r0; print(r1); var r2 = r1 ^ r0; print(r1); var r3 = x ^ r2; var r4 = r3 ^ 8; var r5 = r3 & r3; ");
/*fuzzSeed-168297596*/count=436; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x100000001, 0x07fffffff, -0x080000001, 2**53-2, 0x0ffffffff, -(2**53-2), -1/0, -0x0ffffffff, Math.PI, 1, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, 0x080000001, -(2**53), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 1/0, -0x100000000, -(2**53+2), 0x080000000, 0x100000000, 0, 42, 2**53, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=437; tryItOut("i2.next();");
/*fuzzSeed-168297596*/count=438; tryItOut("mathy5 = (function(x, y) { return Math.imul((Math.sign(Math.fround(( - Math.fround(Math.fround(mathy4((((x >>> 0) != (( + (x & ( + ( ~ x)))) >>> 0)) >>> 0), x)))))) | 0), ( - ( + y))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, -0x100000001, 0, 0x100000001, 0.000000000000001, -0x0ffffffff, -0x080000001, 1/0, 0x080000000, 42, -0, 0x07fffffff, 2**53+2, Number.MAX_VALUE, 0x100000000, 0x080000001, 2**53, 1.7976931348623157e308, -0x100000000, -(2**53-2), 1, Math.PI, -0x080000000, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=439; tryItOut("const x = window, x = [,], upzjdq;/*RXUB*/var r = r1; var s = s1; print(r.test(s)); ");
/*fuzzSeed-168297596*/count=440; tryItOut("this.s1 = '';");
/*fuzzSeed-168297596*/count=441; tryItOut("Array.prototype.forEach.apply(a0, []);g0.a0 = new Array(-0);");
/*fuzzSeed-168297596*/count=442; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+pow(((147573952589676410000.0)), ((Float32ArrayView[((i0)+(-0x8000000)) >> 2]))));\ne2.add(p2);    i0 = (0xbccaae5);\n    (Float32ArrayView[((0xffffffff)+(0x8c660c32)+(((0x5011c2f5)) ? (0x347cabff) : (i0))) >> 2]) = ((73786976294838210000.0));\n    i0 = (i0);\n    return +((Infinity));\n  }\n  return f; })(this, {ff: Math.fround(Math.max(Math.fround(0x0ffffffff), -0)).imul}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[ 'A' , function(){}, x,  'A' , function(){},  /x/g ,  'A' ,  /x/g ,  /x/g , x, x, x, x, function(){},  'A' , function(){}, objectEmulatingUndefined(), function(){},  'A' , objectEmulatingUndefined(),  'A' , x,  /x/g , function(){},  'A' ,  'A' , function(){}, objectEmulatingUndefined(), x, objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), function(){},  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  'A' , x, x, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), x,  'A' ,  /x/g , function(){},  'A' ,  'A' , function(){}, function(){},  /x/g , x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  /x/g , objectEmulatingUndefined(),  'A' , x, objectEmulatingUndefined(),  /x/g , x, objectEmulatingUndefined(), function(){}, function(){},  'A' , function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined()]); ");
/*fuzzSeed-168297596*/count=443; tryItOut("mathy5 = (function(x, y) { return (( ~ ((Math.hypot((Math.acos(((( - Math.fround(( - x))) >>> 0) >>> 0)) >>> 0), ( + (Math.imul(0x100000000, (y >>> 0)) >>> 0))) && (( + (Math.imul(( + ((Math.fround(x) << Math.fround(-(2**53-2))) >>> Math.exp(y))), ( + Math.imul((Math.log2(-(2**53+2)) ? Math.fround(x) : y), x))) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -0, 0x07fffffff, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, -(2**53-2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, 0, 0x0ffffffff, -(2**53+2), 1, 2**53+2, -(2**53), Math.PI, 42, 1/0, Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0/0]); ");
/*fuzzSeed-168297596*/count=444; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0.000000000000001, -0x0ffffffff, 1, -1/0, 1/0, 1.7976931348623157e308, -0x07fffffff, -0, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000001, 0x100000001, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, 42, 0x100000000, -(2**53-2), Math.PI, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -0x100000000, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 0/0, 2**53+2, 0x07fffffff]); ");
/*fuzzSeed-168297596*/count=445; tryItOut("a2.pop();");
/*fuzzSeed-168297596*/count=446; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=447; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return mathy1(( + mathy0((( ~ ((x | 0) + (Math.min(y, x) | 0))) >>> 0), Math.asinh(mathy0(Math.sin((x | 0)), Math.pow(Math.fround(Math.acosh(x)), Math.fround(mathy0(Math.fround(( - Math.fround(0/0))), x))))))), Math.pow(Math.min(x, ( ~ Math.fround(Math.atan2(x, x)))), ( - Math.hypot((mathy2((Math.fround(Math.pow(y, Math.fround(x))) | 0), (x | 0)) | 0), 0x100000000)))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), true, ({valueOf:function(){return '0';}}), [0], 0.1, (new Number(0)), (new Number(-0)), (new Boolean(false)), '', 0, [], '0', (new String('')), -0, /0/, ({valueOf:function(){return 0;}}), 1, '\\0', (function(){return 0;}), (new Boolean(true)), objectEmulatingUndefined(), false, undefined, NaN, '/0/', null]); ");
/*fuzzSeed-168297596*/count=448; tryItOut("\"use strict\"; for(w in ((((makeFinalizeObserver('tenured'))))(x))) /x/g ;\u0009");
/*fuzzSeed-168297596*/count=449; tryItOut("((4277) instanceof ({}));");
/*fuzzSeed-168297596*/count=450; tryItOut("f2.toSource = f1;");
/*fuzzSeed-168297596*/count=451; tryItOut("return;\nv0 = (o1 instanceof e1);\n");
/*fuzzSeed-168297596*/count=452; tryItOut("v2 = evalcx(\"o1.b2 = g2.objectEmulatingUndefined();\", this.g0);\na2[({valueOf: function() { print(this);return 6; }})];\n");
/*fuzzSeed-168297596*/count=453; tryItOut("w = ([[]].__defineGetter__(\"x\", window)), y = \"\\uABFA\";/*RXUB*/var r = r1; var s = \"\"; print(s.replace(r, [z1], \"gy\")); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=454; tryItOut("switch((y ** x)) { case 4: break;  }");
/*fuzzSeed-168297596*/count=455; tryItOut("mathy2 = (function(x, y) { return (Math.log((Math.tan(( + ( - (x ? (( + ( ~ ( + ( + ( + -(2**53)))))) | 0) : ( - y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 1/0, Number.MIN_VALUE, -0x100000001, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, Math.PI, -0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 1, -0x100000000, 0x080000000, 0x080000001, 2**53, 2**53+2, -0x0ffffffff, -0x07fffffff, -(2**53), 42, -(2**53+2), 0x0ffffffff, 0.000000000000001, 0x07fffffff, 0x100000001, 0x100000000, 2**53-2]); ");
/*fuzzSeed-168297596*/count=456; tryItOut("v1 = Object.prototype.isPrototypeOf.call(h1, p0);");
/*fuzzSeed-168297596*/count=457; tryItOut("o0 = t0.__proto__\nv2 = t0.byteLength;");
/*fuzzSeed-168297596*/count=458; tryItOut("\"use strict\"; Object.defineProperty(g0, \"v0\", { configurable:  /x/ , enumerable: true,  get: function() {  return this.t1.length; } });");
/*fuzzSeed-168297596*/count=459; tryItOut("mathy1 = (function(x, y) { return ((( ~ (Math.log(Math.fround(Math.atan2(-0x080000001, Number.MAX_SAFE_INTEGER))) | 0)) ? ( + Math.hypot(Math.abs(Math.fround(( ~ Math.fround(x)))), Math.pow(Math.trunc(x), -(2**53-2)))) : Math.max(( ! mathy0(Math.fround(-0), x)), Math.fround((((Math.imul(-0x100000001, ((y >>> 0) - y)) | 0) + y) | 0)))) || ( + Math.acos((Math.min((Math.fround(((y | 0) ? Math.fround(( + (( + y) ? ( + x) : ( + (Math.atan2(x, -0x080000000) | 0))))) : (y | 0))) >>> 0), Math.imul(Math.fround(2**53+2), y)) | 0)))); }); ");
/*fuzzSeed-168297596*/count=460; tryItOut("/*RXUB*/var r = [( /* Comment */\"\\u0DDA\")]; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=461; tryItOut("/*RXUB*/var r = /(?=(?!.|\\f+?)+){0}/yim; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-168297596*/count=462; tryItOut("t0 = new Float32Array(this.t0);");
/*fuzzSeed-168297596*/count=463; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy0, [1/0, -Number.MIN_VALUE, -0, -0x080000001, 0x100000001, 0/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, Number.MIN_VALUE, -(2**53+2), 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, 0, 0.000000000000001, -1/0, Math.PI, 0x080000001, 42, -(2**53-2), 2**53+2, 2**53-2, 1.7976931348623157e308, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 0x0ffffffff, -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=464; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.sin(( + ( ! (Math.min((((((y >>> 0) >>> ( ~ x)) | 0) == (y | 0)) | 0), (Math.asinh(((y !== x) >>> 0)) >>> 0)) ? (( + (Math.sqrt((x | 0)) | 0)) >>> 0) : x)))); }); testMathyFunction(mathy3, /*MARR*/[[(void 0)], [(void 0)], [(void 0)], [(void 0)], eval, [(void 0)], [(void 0)], [(void 0)], eval, [(void 0)], [(void 0)], [(void 0)], eval, eval, [(void 0)], eval, [(void 0)], eval, eval, [(void 0)], [(void 0)], eval, [(void 0)], [(void 0)], [(void 0)]]); ");
/*fuzzSeed-168297596*/count=465; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( ~ (mathy1((mathy0((y >>> 0), (Math.fround(Math.pow(x, Math.fround(Math.max(y, ( + x))))) >>> 0)) >>> 0), (Math.acos(-0x07fffffff) >>> 0)) | 0))); }); testMathyFunction(mathy2, [-0x100000000, -0x0ffffffff, Math.PI, -0x080000001, Number.MAX_VALUE, -(2**53), -(2**53-2), 0x080000001, -Number.MAX_VALUE, -0x07fffffff, 0/0, -0, -Number.MIN_VALUE, -0x100000001, Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -(2**53+2), 0x100000000, 0, 0.000000000000001, -0x080000000, 2**53-2, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, -1/0, 0x07fffffff, 42, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=466; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=467; tryItOut("b1 = t2.buffer;");
/*fuzzSeed-168297596*/count=468; tryItOut("/*RXUB*/var r = /\\3{2,5}/gy; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-168297596*/count=469; tryItOut("({wrappedJSObject:  '' ,  get -27 eval (x = (4277), ...x) { return (e **= y) }  });");
/*fuzzSeed-168297596*/count=470; tryItOut("testMathyFunction(mathy0, [0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, -(2**53), 0.000000000000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -1/0, 0x0ffffffff, 0, 1/0, -0x100000000, -0x100000001, 42, 0x100000000, 1, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0x07fffffff, 2**53, -Number.MAX_VALUE, Number.MAX_VALUE, Math.PI, 0x080000001, 2**53-2, -0x080000001, -(2**53-2), -0]); ");
/*fuzzSeed-168297596*/count=471; tryItOut("\"use strict\"; for (var p in m0) { try { v1 = t2.byteOffset; } catch(e0) { } try { Array.prototype.forEach.apply(a1, []); } catch(e1) { } try { for (var v of f1) { try { const h0 = {}; } catch(e0) { } try { t0.set(t2, 0); } catch(e1) { } t0.__proto__ = p2; } } catch(e2) { } e1 = new Set(a0); }");
/*fuzzSeed-168297596*/count=472; tryItOut("/*RXUB*/var r = r0; var s = s2; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=473; tryItOut("\"use asm\"; this.a2.splice(0, this.v2, a2, p0);");
/*fuzzSeed-168297596*/count=474; tryItOut("var ksmraw = new ArrayBuffer(1); var ksmraw_0 = new Float32Array(ksmraw); print(ksmraw_0[0]); ksmraw_0[0] = -12; var ksmraw_1 = new Int8Array(ksmraw); ksmraw_1[0] = 27; var ksmraw_2 = new Int8Array(ksmraw); var ksmraw_3 = new Float64Array(ksmraw); ksmraw_3[0] = -0; var ksmraw_4 = new Uint8ClampedArray(ksmraw); print(ksmraw_4[0]); ksmraw_4[0] = -8; var ksmraw_5 = new Int16Array(ksmraw); ksmraw_5[0] = 5; var ksmraw_6 = new Int32Array(ksmraw); ksmraw_6[0] = 0; var ksmraw_7 = new Uint16Array(ksmraw); ksmraw_7[0] = -15; var ksmraw_8 = new Uint8ClampedArray(ksmraw); print(ksmraw_8[0]); ksmraw_8[0] = 28; var ksmraw_9 = new Float32Array(ksmraw); ksmraw_9[0] = -21; ;v1 = a0.length;");
/*fuzzSeed-168297596*/count=475; tryItOut("for (var v of p1) { try { for (var v of e2) { try { t2.set(a2, v0); } catch(e0) { } g2.toString = (function(j) { f1(j); }); } } catch(e0) { } e2 + ''; }");
/*fuzzSeed-168297596*/count=476; tryItOut("\"use asm\"; delete s2[\"__count__\"];");
/*fuzzSeed-168297596*/count=477; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.pow(Math.atan2(Math.fround(Math.hypot((Math.round(Math.atanh(( ! -(2**53)))) >>> 0), Math.fround(Number.MAX_SAFE_INTEGER))), ((((Math.atan2(x, (x | 0)) - 0x080000001) | 0) < (mathy0(y, x) | 0)) | 0)), (((( - (( + (Math.fround((y + ( + x))) <= mathy0((y | 0), y))) >>> 0)) - (Math.pow(Number.MIN_SAFE_INTEGER, 0x080000001) | 0)) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=478; tryItOut("this.a2.sort(a => \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.1805916207174113e+21;\n    var i3 = 0;\n    return ((0x1ca75*(0x4189c306)))|0;\n  }\n  return f;);");
/*fuzzSeed-168297596*/count=479; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.min(( + (Math.imul(Math.atan2(( + (y & y)), x), (x | 0)) < Math.fround(( + Math.fround(-Number.MIN_SAFE_INTEGER))))), ( + Math.asin(( + ((( + ( ! x)) === (( + (( ~ (( ! x) | 0)) | ((Math.atan2((((( ! y) | 0) ? (y | 0) : 2**53+2) | 0), (Math.max(-0x100000000, ( ~ (1.7976931348623157e308 >>> 0))) | 0)) | 0) >>> 0))) | 0)) | 0))))); }); ");
/*fuzzSeed-168297596*/count=480; tryItOut("testMathyFunction(mathy1, [({valueOf:function(){return '0';}}), -0, (new Boolean(true)), false, 0, [0], (new Number(0)), undefined, null, true, '\\0', 1, '0', '/0/', objectEmulatingUndefined(), /0/, (function(){return 0;}), '', (new Boolean(false)), (new Number(-0)), ({toString:function(){return '0';}}), NaN, 0.1, [], (new String('')), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-168297596*/count=481; tryItOut("a1.splice(NaN, v2, new Array(7));");
/*fuzzSeed-168297596*/count=482; tryItOut("\"use strict\"; /*bLoop*/for (jlyhqh = 0; jlyhqh < 60; ++jlyhqh, [].watch(9, Date.prototype.toLocaleTimeString)) { if (jlyhqh % 5 == 3) { /*RXUB*/var r = new RegExp(\"(\\\\2[\\\\D]?)\\\\W\", \"ym\"); var s = \"a\"; print(s.search(r));  } else { (4277); }  } ");
/*fuzzSeed-168297596*/count=483; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + ( ! ( ~ ( + (((( + y) | 0) >>> (( + ( + (( + Math.max(y, ( + Math.fround(( - 0/0))))) >>> 0))) | 0)) | 0))))); }); ");
/*fuzzSeed-168297596*/count=484; tryItOut("");
/*fuzzSeed-168297596*/count=485; tryItOut("(x);");
/*fuzzSeed-168297596*/count=486; tryItOut("\"use strict\"; Array.prototype.splice.call(a1, -12, 19, i2, t2);");
/*fuzzSeed-168297596*/count=487; tryItOut("mathy3 = (function(x, y) { return Math.imul((Math.min(Math.fround(Math.acos((Math.cosh(y) >>> 0))), ((Math.pow((Math.pow(y, y) | 0), ((x > x) | 0)) | 0) | 0)) | 0), (Math.atan2((Math.min((( ~ Math.fround(x)) | 0), ((-0x100000001 | 0) << 0.000000000000001)) | 0), ( + (y <= (mathy0(Math.fround((Math.fround(Math.max(( + Math.acosh(( + -(2**53)))), 1/0)) && Math.fround((( + Math.fround(y)) ? y : x)))), mathy2(y, x)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy3, ['\\0', NaN, '', 1, undefined, null, (new String('')), objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), (new Number(-0)), 0.1, ({toString:function(){return '0';}}), (function(){return 0;}), [0], true, (new Number(0)), [], (new Boolean(true)), (new Boolean(false)), /0/, '0', false, '/0/', -0, 0, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-168297596*/count=488; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot((( - ( ! (y >>> 0))) <= ( + (y | 0))), ( + Math.atan2(( + (Math.pow(Math.hypot((Math.expm1((-0x07fffffff | 0)) >>> 0), ((y ? (( ! (x >>> 0)) >>> 0) : ( - x)) >>> 0)), ( + ( ! ( + Math.atan2(x, x))))) | 0)), ( + ((( ~ (x | 0)) === (-0x100000000 | y)) || Math.min(Math.round(y), -0x0ffffffff)))))); }); ");
/*fuzzSeed-168297596*/count=489; tryItOut("f0 = (function mcc_() { var yzabpo = 0; return function() { ++yzabpo; if (/*ICCD*/yzabpo % 8 == 0) { dumpln('hit!'); try { b0 + ''; } catch(e0) { } try { s0 += o2.s2; } catch(e1) { } try { v2 = evalcx(\"(new x = undefined(true ?  /x/  :  /x/ ));\", g1); } catch(e2) { } m0.has(t2); } else { dumpln('miss!'); try { i2.send(f1); } catch(e0) { } try { /*ADP-2*/Object.defineProperty(a1, ({valueOf: function() { (void schedulegc(g2));return 9; }}), { configurable: undefined, enumerable: true, get: (function() { try { m1.set(a0, a0); } catch(e0) { } try { (void schedulegc(g0)); } catch(e1) { } /*MXX2*/g0.Set.length = g1.v1; return v1; }), set: f0 }); } catch(e1) { } Object.prototype.watch.call(i2, \"x\", (function() { v2 = g1.eval(\"Object.defineProperty(this, \\\"this.t1\\\", { configurable: true, enumerable: true,  get: function() {  return new Uint8ClampedArray(g1.t2); } });\"); return f0; })); } };})();function x(eval, a, e = x, window = ({e: \"\\uE572\"}), this.x = (/*UUV2*/(x.getDay = x\n.stringify)), w, x, eval = x, NaN, z, x = /*UUV1*/(\u3056.toString = null), a, NaN\u000c)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (i1);\n    }\n    {\n      {\n        {\n          i2 = ((68719476737.0) < (-147573952589676410000.0));\n        }\n      }\n    }\n    i0 = (1);\n    i0 = (i0);\n    return +((+(0xe786281b)));\n  }\n  return f;g2.v0 = Object.prototype.isPrototypeOf.call(v0, h2);");
/*fuzzSeed-168297596*/count=490; tryItOut("\"use strict\"; let (z) { p1 + ''; }");
/*fuzzSeed-168297596*/count=491; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( - (( + ( - Math.expm1((Math.min((y >>> 0), Math.fround(Math.atan2(x, y))) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 2**53+2, 1/0, Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, Math.PI, 0, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), -0x07fffffff, -0, -Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, 42, 0x07fffffff, -(2**53-2), -0x100000000, -0x080000000, 2**53, 2**53-2, 0/0, 0x100000001, 0x080000001, -0x0ffffffff, Number.MAX_VALUE, 1, -0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=492; tryItOut("mathy0 = (function(x, y) { return ((( ! (((Math.clz32(( + (y > ( + y)))) | 0) !== y) >>> 0)) ? ( + Math.log(((Math.tanh((x >>> 0)) | 0) >>> 0))) : Math.atan2(( + Math.fround((Math.fround(y) ? (( ~ 0x080000000) | 0) : Math.fround((( ! (x | 0)) | 0))))), (Math.fround((Math.fround(( - y)) ? x : Math.fround((-0 >= Math.fround(Math.abs(Math.fround(y))))))) >>> 0))) && Math.atan2((Math.fround(x) ? ( + Math.min(Math.fround((( + Math.atanh(( + y))) && x)), x)) : (((-0x100000001 >>> 0) != x) >>> 0)), Math.hypot(Math.fround(Math.hypot(( ~ (x - (Math.min((x >>> 0), (y >>> 0)) >>> 0))), x)), Math.imul(y, y)))); }); testMathyFunction(mathy0, [0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, 1/0, 2**53+2, 2**53-2, -0x100000000, 0x100000000, -0x07fffffff, -0x080000001, -1/0, -(2**53-2), 0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, Math.PI, 0/0, -(2**53), -Number.MIN_VALUE, 1, 0x07fffffff, 0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, Number.MAX_VALUE, 0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, -0, -0x080000000, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-168297596*/count=493; tryItOut("print(\n( \"\" )(((yield \"\\u895E\"))));");
/*fuzzSeed-168297596*/count=494; tryItOut("Array.prototype.pop.call(g1.a0, a1, i2, s1);");
/*fuzzSeed-168297596*/count=495; tryItOut("t0 = new Uint32Array(t0);\na0.pop(f0);\n");
/*fuzzSeed-168297596*/count=496; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 4503599627370497.0;\n    (Float32ArrayView[(((0xffffffff) ? (0xfa736a18) : (i2))-((d0) != (+((((0xe6720be1) ? (1048577.0) : (-33.0))))))-(0xff20b428)) >> 2]) = (((d1)));\n    d1 = (d0);\n    d1 = (NaN);\n    d3 = (+(-1.0/0.0));\n    {\n      d1 = (NaN);\n    }\n    return (((0x807d22f9)*0xc65c2))|0;\n    i2 = (0xf91a0a46);\n    switch ((((0xf9fe03f4)) >> ((0xfa66a6c1)+(0x654b1d4b)-(0x42b34137)))) {\n      case -2:\n        return (((((i2)) >> ((0xfb1f0c07)-(0x5a9f202f))) % (imul((i2), ((0x0)))|0)))|0;\n      case -1:\n        d0 = ((((Int32ArrayView[0]))) - ((d0)));\n        break;\n      case 1:\n        {\n          d1 = (d1);\n        }\n        break;\n      case -1:\n        {\n          d3 = (36028797018963970.0);\n        }\n        break;\n      case 0:\n        d0 = (-7.0);\n        break;\n      case 1:\n        i2 = (0xf3126c87);\n      default:\n        d3 = (NaN);\n    }\n    d0 = (((Object.defineProperty(x, \"entries\", ({configurable: \"\\uE5EC\", enumerable: ({a2:z2})})) >>> x)) + (((d0)) - ((d1))));\n    d3 = (+/*FFI*/ff(((d3)), ((0x38713d29)), ((((/*FFI*/ff((((((x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: decodeURI, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: function() { return []; }, keys: undefined, }; })(function(id) { return id }), (timeout(1800))).trim(false, (4277))))) ^ (((0x7fffffff) <= (0x5f1025f6))+(0xe1498075)))), ((imul((i2), (0xfa31a4cb))|0)))|0)*-0xfffff)|0)), ((d1)), ((d3)), ((imul((0x57e844bf), (0xfae4aa1f))|0)), ((-17592186044415.0)), ((0x6d86922)), (((-1125899906842625.0) + (-36028797018963970.0))), ((-1.5111572745182865e+23)), ((-2.0)), ((-1.0625)), ((-9223372036854776000.0)), ((-17592186044417.0)), ((-562949953421313.0))));\n    (Uint8ArrayView[4096]) = ((0x839b7052));\n    i2 = (!(0x73836c54));\n    return (((0xf84ce2b9)+(0xb90ab42c)+((((0xa872ffd0) ? ((+/*FFI*/ff()) <= (d1)) : (0xa717dcb2))+(!(!(i2)))))))|0;\n    i2 = (0x1b260bb1);\n    d0 = (2251799813685249.0);\n    d0 = (-1.001953125);\n    i2 = (i2);\n    switch ((imul((/*FFI*/ff()|0), ((0x6dd7f56d) ? (0xa33d5575) : (0xbd154f58)))|0)) {\n    }\n    d0 = ((0x3735d305) ? (d0) : (+(0x3cdbe9c9)));\n    d1 = (((void 0)));\n    i2 = (0xfd9cc3b3);\n    d3 = (d3);\n    i2 = (0x592121dd);\n    return (((abs((~((0x3e1017e0)-(-0x8000000))))|0) / (imul((!(0x7621fe23)), ((allocationMarker()) <= (d1)))|0)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return y; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, 2**53-2, Number.MAX_VALUE, 0x0ffffffff, -0x080000000, 1.7976931348623157e308, 0.000000000000001, 0x080000001, 1, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 1/0, -1/0, 0x080000000, -(2**53), 0/0, Number.MIN_VALUE, 0x100000001, Math.PI, 0, 2**53+2, 2**53, 42, -0x07fffffff, -0x100000000, 0x07fffffff, -(2**53+2), 0x100000000]); ");
/*fuzzSeed-168297596*/count=497; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=498; tryItOut("o2.f0(i0);");
/*fuzzSeed-168297596*/count=499; tryItOut("\"use strict\"; /*oLoop*/for (var yazame = 0; yazame < 24; ++yazame) { v1 = r2.unicode; } ");
/*fuzzSeed-168297596*/count=500; tryItOut("var x;for (var v of o0) { try { var a0 = a1.slice(NaN, NaN); } catch(e0) { } try { v2 = (f0 instanceof b1); } catch(e1) { } i0 + t1; }");
/*fuzzSeed-168297596*/count=501; tryItOut("\"use strict\"; (window);/*MXX2*/g0.g0.DataView.prototype = p2;\n(\"\\u2361\");\n");
/*fuzzSeed-168297596*/count=502; tryItOut("m0.set(t1, i2);");
/*fuzzSeed-168297596*/count=503; tryItOut("\"use strict\"; this.v0 = evalcx(\"function f2(o2)  { v1 = (this.e2 instanceof o1.v1); } \", g2.g0);");
/*fuzzSeed-168297596*/count=504; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.clz32(Math.fround(((((( + Math.max(y, Math.PI)) & ((( ~ y) || (( ~ (Math.imul(x, (x >>> 0)) >>> 0)) >>> 0)) | 0)) | 0) | 0) , Math.fround(Math.asinh(Math.atanh(0x080000000)))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 2**53, 1/0, -0x080000000, 1.7976931348623157e308, -(2**53), -0, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x080000000, 1, -Number.MAX_VALUE, Number.MIN_VALUE, -0x100000001, -0x100000000, 0, 0/0, -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0x100000000, -(2**53-2), Number.MAX_VALUE, 2**53-2, 0x07fffffff, 0x0ffffffff, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 0.000000000000001, -1/0]); ");
/*fuzzSeed-168297596*/count=505; tryItOut("/*tLoop*/for (let c of /*MARR*/[/*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), new Boolean(false), NaN, NaN, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, NaN, NaN, new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, NaN, new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), new Boolean(false), NaN, NaN, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), new Boolean(false), new Boolean(false), NaN, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, NaN, new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), NaN, NaN, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, NaN, NaN, NaN, NaN, new Boolean(false), new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, new Boolean(false), NaN, NaN, NaN, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, NaN, new Boolean(false), /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, NaN, NaN, /*FARR*/[(z) = \u3056, (p={}, (p.z = window)())].map, NaN, NaN]) { /* no regression tests found */ }");
/*fuzzSeed-168297596*/count=506; tryItOut("selectforgc(o2);");
/*fuzzSeed-168297596*/count=507; tryItOut("\"use strict\"; t0 = this.t2[(4277)];");
/*fuzzSeed-168297596*/count=508; tryItOut("b2 = t0.buffer;");
/*fuzzSeed-168297596*/count=509; tryItOut("mathy2 = (function(x, y) { return ( + Math.acosh(( + ( + ((mathy1((Math.sqrt(x) | 0), (Math.log2((y >>> 0)) & (( - y) < (((Math.cbrt(y) | 0) ? y : (y | 0)) | 0)))) >>> 0) * (( ~ (x >>> 0)) | 0)))))); }); testMathyFunction(mathy2, /*MARR*/[function(){}, x, x, x, x, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-168297596*/count=510; tryItOut("mathy5 = (function(x, y) { return ( + Math.imul((Math.ceil(x) ? (( - (y | 0)) | 0) : ( - x)), ( - ( + Math.fround(Math.fround(Math.fround((x % ((Math.fround((Math.pow((x >>> 0), (x >>> 0)) >>> 0)) * 1/0) >>> 0))))))))); }); testMathyFunction(mathy5, [0, 1.7976931348623157e308, 42, -0x0ffffffff, -0, 0x07fffffff, -Number.MAX_VALUE, 0x080000001, 1, Math.PI, 0x100000001, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, -(2**53-2), 2**53, -1/0, 2**53-2, Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, -(2**53+2), Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -0x080000001, 1/0, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=511; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: w = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { throw 3; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(true), (function(x, y) { return (Math.atan2(Math.expm1(y), y) >>> 0); }), eval), enumerable: false,  get: function() { Array.prototype.pop.apply(a2, []); return evaluate(\"x\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: ((new (({a2:z2}))( '' )))((4277)) })); } });");
/*fuzzSeed-168297596*/count=512; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=513; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.abs((Math.cosh((((( + ((x >>> 0) >>> (( ! (y ? x : 0.000000000000001)) >>> 0))) >>> 0) ? ((Math.fround((Math.fround(x) , Math.fround(x))) ** -(2**53)) | 0) : (( ! 0x080000000) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, -0x080000001, 2**53, -0x07fffffff, 42, 0x080000000, 1/0, 2**53+2, -0x0ffffffff, -(2**53), Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, -0, 2**53-2, 0/0, 0x07fffffff, 0x100000001, 0x100000000, -0x100000001, -0x100000000, 0x0ffffffff, -(2**53-2), -0x080000000, 0, 1, Number.MAX_VALUE, -1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=514; tryItOut("this.zzz.zzz;");
/*fuzzSeed-168297596*/count=515; tryItOut("for (var v of m1) { try { a0.length = v0; } catch(e0) { } try { Object.prototype.watch.call(o2.v1, 7, (function() { Array.prototype.pop.call(a2); return g1.v1; })); } catch(e1) { } try { a1 = g0.a1.concat(a1, o1.t1); } catch(e2) { } h1.keys = f1; }");
/*fuzzSeed-168297596*/count=516; tryItOut("\"use strict\"; v2 = Array.prototype.reduce, reduceRight.call(a2, (function(j) { if (j) { try { print(e1); } catch(e0) { } try { o0 = {}; } catch(e1) { } (void schedulegc(g1)); } else { try { this.v0 = this.g1.runOffThreadScript(); } catch(e0) { } try { for (var v of this.f1) { a2[14] = p1; } } catch(e1) { } try { e0.add(v0); } catch(e2) { } s1.valueOf = (function() { try { v1 = a1.length; } catch(e0) { } try { Array.prototype.splice.call(a2, NaN,  /x/g ); } catch(e1) { } Array.prototype.sort.apply(a1, [/(?=(?![\\w\u00e9-\\x93\\u0099-\u6c4c\u9f1b]|(?!^){4,}){4})\\x11/gi( /x/ )]); throw b1; }); } }));");
/*fuzzSeed-168297596*/count=517; tryItOut("\"use strict\"; f1 = Proxy.createFunction(this.h1, f2, f1);");
/*fuzzSeed-168297596*/count=518; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -1073741825.0;\n    var i4 = 0;\n    var d5 = -1.2089258196146292e+24;\n    switch ((abs(((0xdbe48*(0x699023ef)) >> ((0xffffffff)+(-0x8000000))))|0)) {\n      case 1:\n        i0 = ((i2) ? (!(0xffffffff)) : (i2));\n        break;\n      case 1:\n        (Float64ArrayView[2]) = ((d5));\n    }\n    return (((i0)+('fafafa'.replace(/a/g, q => q))-((+(0xb14b0b15)) != (+(1.0/0.0)))))|0;\n    return (((0x15035add)-(0xfd68b4d1)))|0;\n  }\n  return f; })(this, {ff: ((function a_indexing(zhhtwj, zstebq) { /*hhh*/function ssvnkn(z){p1 + i1;}ssvnkn(/\\B|(?:\\b|\\b|.?)(?=(?!\\u4aC0))?|.|.|\\B/gym,  \"\" );; if (zhhtwj.length == zstebq) { ; return Math.acosh(18); } var vdbfkt = zhhtwj[zstebq]; var shvjzr = a_indexing(zhhtwj, zstebq + 1); return (4277); })(/*MARR*/[new String(''), new String(''), Number.MIN_VALUE, new String(''), Number.MIN_VALUE, new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), new String(''), Number.MIN_VALUE, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), Number.MIN_VALUE, new String(''), Number.MIN_VALUE, new String(''), new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, new String(''), new String(''), new String(''), new String(''), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE], 0))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000000, -0, 2**53-2, -1/0, 0x100000001, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, Math.PI, -0x080000001, -Number.MIN_VALUE, 0, Number.MIN_VALUE, 0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, 2**53+2, 0x080000000, 2**53, 0/0, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), -(2**53+2), -0x07fffffff, 0x100000000, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-168297596*/count=519; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (d0);\n    {\n      i2 = (0xffffffff);\n    }\n    return ((((((0xf8b5429b)+(((d0))))>>>((((0x547618d8) == (((0x2ee8b2b0))>>>((0x524204fe)))) ? ((0xbdd5424c) ? (0xfafd9c83) : (0xfc7ea74d)) : ((((0x4dd12838)) & ((0xfe214cd4))))))) < ((((imul((0xffffffff), (-0x8000000))|0))+( /x/g )+(i2))>>>(-(0x4db77847))))))|0;\n    return (((/*FFI*/ff(((d0)))|0)))|0;\n  }\n  return f; })(this, {ff: (function(y) { return x }).call}, new ArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=520; tryItOut("L:for(let [b, e] = new RegExp(\"(.|$+)\", \"gy\") in [] = [] %= Math.trunc(8)) print(x);");
/*fuzzSeed-168297596*/count=521; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-168297596*/count=522; tryItOut("\"use strict\"; { void 0; void schedulegc(this); } s2 += 'x';");
/*fuzzSeed-168297596*/count=523; tryItOut("this.a0.shift();");
/*fuzzSeed-168297596*/count=524; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (0x4f28be2a);\n    i2 = (/*FFI*/ff(((3.0)), ((+((((((-0x8000000)-(-0x8000000)) | ((0xffffffff)-(0x5ed3c502))))*-0xfffff)>>>((i1))))), (((((d0))) >> ((i2)+((d0) == (d0))+(0xffffffff)))), ((((0x44e19bf0)-(i1)) & ((!((((0x389c65b9)) ^ ((0x8a4cace8)))))+(0x55741062)))), ((d0)), (x), ((((0x9e837d43)-(0x928feba)) & ((-0x38db2c7)-(0x7e1aba3d)))))|0);\n    d0 = (-35184372088833.0);\n    i1 = (i1);\n    d0 = (1.00390625);\n    (Float32ArrayView[4096]) = ((+pow(((134217729.0)), ((d0)))));\n    return (((i1)))|0;\n    i2 = (0xff9c0ab3);\n    (Int8ArrayView[2]) = ((i1));\n    d0 = (+(~~(-(((((Int32ArrayView[0]))) - ((((((((35184372088833.0)) / ((-288230376151711740.0)))) - ((1.0)))) / ((Float64ArrayView[4096])))))))));\n    d0 = ((i2) ? ((-590295810358705700000.0) + ((void version(180)))) : ((((((0xffffffff) ? (-3.094850098213451e+26) : (-3.094850098213451e+26))) * ((+(-1.0/0.0))))) - ((NaN))));\n    i2 = (0x21c1708a);\n    return ((((0xe621de69) > (0xffffffff))+(0xd033540c)+((Float64ArrayView[(((i2))-((((0xdb825e5a)-(0xce8a0ee5)) | ((0xffffffff)*0x2111b)) < (((0xa952fce6)+(-0x8000000)) >> ((0x74e323de)-(0xd74d1dd3)+(0x9251a1b4))))) >> 3]))))|0;\n    {\n      d0 = (+abs(((1025.0))));\n    }\n    {\n      (Float64ArrayView[((i2)-(i2)) >> 3]) = ((d0));\n    }\n    i1 = (/*FFI*/ff((((Float64ArrayView[((i1)-(((0x2ce71da0)) > (~(-((0xfbfeeb55) ? (0x6aef336a) : (0xffffffff)))))) >> 3]))), ((262143.0)), ((~(((0x61550b36))+((~((0x155fc280) / (0x41066b34))) != (abs((0x962e2aa))|0))))))|0);\n    return (((i1)+(i2)))|0;\n  }\n  return f; })(this, {ff: new Function}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [(new Boolean(false)), false, -0, (function(){return 0;}), '', (new Number(-0)), true, '0', '\\0', 0, ({valueOf:function(){return 0;}}), /0/, 1, (new Number(0)), objectEmulatingUndefined(), NaN, null, ({toString:function(){return '0';}}), undefined, [], 0.1, '/0/', (new Boolean(true)), ({valueOf:function(){return '0';}}), (new String('')), [0]]); ");
/*fuzzSeed-168297596*/count=525; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - (( + Math.hypot(Math.fround(Math.max((( + 0) >>> (x >>> 0)), ((x | 0) < (( - Math.imul(x, x)) | 0)))), (y ? -(2**53) : ( + (( + x) ? ( + Math.pow(x, x)) : ( + -1/0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [42, 0x100000000, -(2**53-2), -Number.MAX_VALUE, 0.000000000000001, -0x100000000, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, -0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 1, -(2**53+2), 2**53-2, 2**53+2, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, -Number.MAX_SAFE_INTEGER, -1/0, -0, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, 0, 0/0, -(2**53), 1/0]); ");
/*fuzzSeed-168297596*/count=526; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=527; tryItOut("v0 = evaluate(\"e0.has(g0);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 18 == 2), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-168297596*/count=528; tryItOut("i1 + '';");
/*fuzzSeed-168297596*/count=529; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((( + ( ~ Math.imul(y, Math.min(Math.fround(x), ( + (( + x) ? ( + -0x0ffffffff) : x)))))) ? Math.fround(Math.clz32((Math.fround(( - Math.log10(x))) | 0))) : (( ! (y >>> 0)) >>> 0)) - Math.asin((( ~ (( + Math.atan2(( ~ ( + Math.tanh(0x0ffffffff))), ( + Math.pow((Math.imul(( + x), ( + 1/0)) | 0), ( + -0))))) >>> 0)) | 0))); }); testMathyFunction(mathy0, [-(2**53+2), Math.PI, -0, 0, Number.MAX_SAFE_INTEGER, 2**53+2, 1, -Number.MIN_VALUE, -0x080000001, 1/0, Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -0x07fffffff, -(2**53), -(2**53-2), 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000001, 42, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, -0x0ffffffff, 0x0ffffffff, 2**53, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000001, 0.000000000000001, 0/0, 0x080000000, 0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=530; tryItOut("testMathyFunction(mathy0, [1, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, 2**53, -0x07fffffff, -0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -0x080000001, 0x100000000, -0x080000000, -(2**53-2), 2**53+2, 0x100000001, -1/0, 0x07fffffff, -0x100000001, 1/0, Number.MAX_VALUE, 42, 0, 0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-168297596*/count=531; tryItOut("\"use asm\"; print(x);");
/*fuzzSeed-168297596*/count=532; tryItOut("\"use strict\"; print(x);g1.f0 = f2;");
/*fuzzSeed-168297596*/count=533; tryItOut("/*vLoop*/for (var lpgrka = 0, NaN = (p={}, (p.z =  \"\" )()); lpgrka < 37; ++lpgrka) { x = lpgrka; print(x); } ");
/*fuzzSeed-168297596*/count=534; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 2.3611832414348226e+21;\n    i0 = (i0);\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MIN_VALUE, -1/0, 2**53, 0x0ffffffff, -0x100000000, 0, -0x100000001, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -Number.MAX_VALUE, 0x100000001, -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, 1, 0/0, Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, -(2**53), 0x080000000, -(2**53+2), 0.000000000000001, Math.PI, 0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-168297596*/count=535; tryItOut("if(/*wrap3*/(function(){ var bxjqdd = Math.pow(x = Proxy.create(({/*TOODEEP*/})(-28), x), 27); ((z, bxjqdd, bxjqdd, NaN, x, yield, w, y, x, bxjqdd, bxjqdd, bxjqdd, get, name, a, bxjqdd, \u3056 = false, x = null, x, eval, b, bxjqdd, bxjqdd, a, c, x, d, eval, x, NaN, eval, x, z, ...e) =>  { yield bxjqdd } )(); }).prototype) a0.unshift(v2); else  if (function(id) { return id }) d = linkedList(d, 1287);");
/*fuzzSeed-168297596*/count=536; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a1, 19, ({set: Date.prototype.getDate, configurable: (x % 4 != 1)}));");
/*fuzzSeed-168297596*/count=537; tryItOut("mathy2 = (function(x, y) { return Math.atan2(( ~ (mathy1(((Math.imul(y, x) | 0) >>> 0), (( + (( + y) >= ( + y))) | 0)) >>> 0)), ((Math.clz32(Math.fround(Math.fround(mathy0((Math.cos((-1/0 | 0)) | 0), Math.fround(((x | 0) == ((Math.max((1.7976931348623157e308 | 0), (( ~ x) | 0)) | 0) >>> 0))))))) | 0) >= Math.fround(Math.acosh((y === x))))); }); testMathyFunction(mathy2, [false, '0', [0], '\\0', true, (new Number(-0)), 0, (function(){return 0;}), (new Boolean(false)), objectEmulatingUndefined(), (new String('')), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), -0, '/0/', (new Boolean(true)), undefined, /0/, '', 1, null, 0.1, (new Number(0)), [], NaN, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-168297596*/count=538; tryItOut("this.v0 = this.t0.byteLength;");
/*fuzzSeed-168297596*/count=539; tryItOut("\"use strict\"; { void 0; void gc('compartment'); } ((( /x/g )()));");
/*fuzzSeed-168297596*/count=540; tryItOut("testMathyFunction(mathy0, /*MARR*/[2**53, arguments.caller, arguments.caller, arguments.caller, arguments.caller, 2**53, {x:3}, new String('q'), 2**53, arguments.caller, 2**53, new String('q'), 2**53, arguments.caller, new String('q'), arguments.caller, arguments.caller, new String('q'), {x:3}, new String('q'), arguments.caller, arguments.caller, new String('q'), {x:3}]); ");
/*fuzzSeed-168297596*/count=541; tryItOut("\"use strict\"; (window ^ z);");
/*fuzzSeed-168297596*/count=542; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy1((( ~ Math.sin((( + y) >>> 0))) < Math.fround(mathy0(mathy0(( ! y), -0x080000001), Math.asin((( ! (y | 0)) | 0))))), Math.log10(( ! ( + ( ~ x))))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 2**53+2, -0, Math.PI, -0x080000001, -0x100000001, 0x100000000, 0x080000000, -0x080000000, Number.MAX_VALUE, 0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, 0x080000001, 0, 1.7976931348623157e308, 2**53, 0x07fffffff, -0x0ffffffff, -(2**53), 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 1, -(2**53-2), 0/0, Number.MIN_VALUE, -Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-168297596*/count=543; tryItOut("v0 = evalcx(\"t0[11] =  /x/ ;\", g0)");
/*fuzzSeed-168297596*/count=544; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 1.2089258196146292e+24;\n    var i3 = 0;\n    return +((((d2)) / ((((-0.125)) / ((Float64ArrayView[2]))))));\n  }\n  return f; })(this, {ff: Math.clz32(Math.max(4, -Number.MAX_SAFE_INTEGER))}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Math.PI, -Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 1, 0/0, 0x0ffffffff, -(2**53+2), 0x080000000, Number.MAX_VALUE, -(2**53-2), 42, 2**53, -0x0ffffffff, 0x07fffffff, 0.000000000000001, -0x100000001, -0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -0, 0, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, -1/0, -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, 2**53+2, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-168297596*/count=545; tryItOut("e2.add(g2.m0);");
/*fuzzSeed-168297596*/count=546; tryItOut("s2.__proto__ = f1;");
/*fuzzSeed-168297596*/count=547; tryItOut("testMathyFunction(mathy4, /*MARR*/[new String(''), {x:3}, new String(''), new String(''), {x:3}, new String(''), new String(''), new String(''), new String(''), {x:3}, {x:3}, {x:3}, new String(''), new String(''), {x:3}, new String(''), {x:3}, new String(''), {x:3}, {x:3}, new String(''), new String(''), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, new String(''), {x:3}, {x:3}, {x:3}, new String(''), new String(''), new String(''), {x:3}, {x:3}, {x:3}, {x:3}]); ");
/*fuzzSeed-168297596*/count=548; tryItOut("NaN.name;");
/*fuzzSeed-168297596*/count=549; tryItOut("\"use strict\"; do w if (x) while((Math.atan2(-7, -15)) && 0);");
/*fuzzSeed-168297596*/count=550; tryItOut("\"use strict\"; v1 = (p0 instanceof g0.p2);");
/*fuzzSeed-168297596*/count=551; tryItOut("a1 + g2;");
/*fuzzSeed-168297596*/count=552; tryItOut("testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -0x100000000, -0x07fffffff, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), -1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, -0x080000001, 0x0ffffffff, 0.000000000000001, 2**53+2, -0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, -0x100000001, 0/0, Number.MAX_VALUE, -(2**53+2), 1/0, Number.MIN_VALUE, -(2**53), 2**53-2, Math.PI, 0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=553; tryItOut("\"use strict\"; for(let y in /*MARR*/[new Number(1.5), new Boolean(true), new Number(1.5), -Number.MAX_SAFE_INTEGER, undefined, (1/0), -Number.MAX_SAFE_INTEGER, new Boolean(true), undefined, -Number.MAX_SAFE_INTEGER, (1/0), new Number(1.5), (1/0), undefined, new Boolean(true), new Boolean(true), -Number.MAX_SAFE_INTEGER, new Number(1.5), new Number(1.5), new Boolean(true), undefined, new Number(1.5), (1/0), new Boolean(true), new Number(1.5), new Number(1.5), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Boolean(true), new Boolean(true), (1/0), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(true), new Number(1.5), new Boolean(true), new Number(1.5), new Number(1.5), new Number(1.5), undefined, new Boolean(true), undefined, -Number.MAX_SAFE_INTEGER, undefined, (1/0), new Number(1.5), (1/0), (1/0), new Number(1.5), (1/0), new Number(1.5), new Boolean(true), undefined, new Boolean(true), new Number(1.5), -Number.MAX_SAFE_INTEGER, (1/0), (1/0), undefined, -Number.MAX_SAFE_INTEGER, new Boolean(true), new Boolean(true), (1/0), new Boolean(true), new Number(1.5), new Boolean(true), new Number(1.5), (1/0), -Number.MAX_SAFE_INTEGER, (1/0), (1/0), (1/0), (1/0), (1/0), -Number.MAX_SAFE_INTEGER, new Number(1.5), new Number(1.5), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1.5), new Boolean(true), undefined, -Number.MAX_SAFE_INTEGER, undefined, undefined, new Number(1.5), -Number.MAX_SAFE_INTEGER, undefined, undefined, new Number(1.5), -Number.MAX_SAFE_INTEGER, new Boolean(true), -Number.MAX_SAFE_INTEGER, undefined, -Number.MAX_SAFE_INTEGER, (1/0), new Number(1.5), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Number(1.5), new Number(1.5), (1/0), (1/0), new Number(1.5), (1/0), (1/0), new Boolean(true), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), undefined, undefined, new Boolean(true), new Boolean(true), undefined, -Number.MAX_SAFE_INTEGER, undefined, new Boolean(true), new Number(1.5), -Number.MAX_SAFE_INTEGER, new Boolean(true), new Number(1.5), new Number(1.5), -Number.MAX_SAFE_INTEGER, undefined, new Boolean(true), (1/0), new Boolean(true), new Boolean(true), new Boolean(true), (1/0), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Boolean(true), new Boolean(true), new Number(1.5), -Number.MAX_SAFE_INTEGER, (1/0), -Number.MAX_SAFE_INTEGER, undefined, new Boolean(true), new Number(1.5), undefined, new Number(1.5), undefined, undefined, undefined, undefined, -Number.MAX_SAFE_INTEGER, undefined, (1/0), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(true), new Number(1.5), new Boolean(true), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Boolean(true), -Number.MAX_SAFE_INTEGER, new Boolean(true), undefined, new Boolean(true), new Boolean(true), new Boolean(true), (1/0), undefined, (1/0), new Boolean(true), undefined, new Number(1.5), undefined, -Number.MAX_SAFE_INTEGER, new Number(1.5), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, undefined, new Boolean(true), new Boolean(true)]) with({}) { return; } ");
/*fuzzSeed-168297596*/count=554; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=555; tryItOut("\"use strict\"; /*bLoop*/for (let xnwyav = 0; xnwyav < 9; ++xnwyav) { if (xnwyav % 2 == 0) { /*vLoop*/for (let wmeclm = 0; wmeclm < 45; ++wmeclm) { let b = wmeclm; print(b); }  } else { print( /x/g \n); }  } ");
/*fuzzSeed-168297596*/count=556; tryItOut("{uafupv();/*hhh*/function uafupv(...x){print(x);} }");
/*fuzzSeed-168297596*/count=557; tryItOut("mathy2 = (function(x, y) { return (Math.fround(( - (( + y) >>> 0))) ** Math.hypot((((Math.hypot(Math.fround(Math.trunc((y >>> 0))), (y >>> 0)) >>> 0) + Math.max(( + x), x)) * ( - Math.fround((Math.fround(( ~ y)) == ( - x))))), Math.fround((Math.expm1(x) | 0)))); }); testMathyFunction(mathy2, /*MARR*/[objectEmulatingUndefined(), false, (void 0), false, objectEmulatingUndefined(), (4277), ({}), objectEmulatingUndefined(), (void 0), (void 0), false, (void 0), (4277), (void 0), objectEmulatingUndefined(), (4277), (4277), objectEmulatingUndefined(), (4277), (4277), objectEmulatingUndefined(), false, false, false, ({}), objectEmulatingUndefined(), false, (4277), (4277), ({}), (void 0), (4277), ({}), ({}), false, false, ({}), objectEmulatingUndefined(), (4277), (void 0), false, (void 0), false, false, false, (void 0), ({}), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (4277), false, (4277), (void 0), false, ({}), (4277), (void 0), false, ({}), false, (void 0), (void 0), false, (4277), objectEmulatingUndefined(), (4277), (4277), (void 0), false, (void 0), false, false, (void 0), objectEmulatingUndefined(), ({}), (void 0), (4277), (void 0), ({}), objectEmulatingUndefined(), false, false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), (4277), false, ({}), (4277), false, false]); ");
/*fuzzSeed-168297596*/count=558; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i0);\n    }\n    i0 = ((((i0)+(!(((((0x14d7af83))) >> ((0xffffffff) / (0xb7438624)))))) & ((i0))) == ((4277)));\n    return (((/*FFI*/ff(((((Uint8ArrayView[(((+/*FFI*/ff()) == (+acos(((137438953473.0)))))) >> 0])) >> ((((0x2d77f9) ? (0xfbf184a3) : (0xa12f7850)) ? ((0xc068726a) == (0x90f9bdab)) : (0xc108b1a7))-(x && (new (Promise.reject)((let (x, opyuip, this.d) /(?!\\3+?)+?/gyim), [1,,])))))))|0)+((((-34359738367.0)) % ((73786976294838210000.0))) <= (([]) + (+(0x26b217ec))))+(i0)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53, 1/0, 2**53+2, 42, 1.7976931348623157e308, 0x07fffffff, -0x07fffffff, 0x100000001, 0x080000001, 0, -0x080000001, Number.MAX_VALUE, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 2**53-2, -0, -(2**53), -(2**53+2), -0x080000000, -Number.MAX_VALUE, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 1, -0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=559; tryItOut("\"use strict\"; t0.toString = (function() { try { this.v0 = Array.prototype.some.apply(a1, [o2.t0, p0]); } catch(e0) { } try { h0.hasOwn = (function() { for (var j=0;j<161;++j) { f2(j%3==0); } }); } catch(e1) { } o2.v2 = Object.prototype.isPrototypeOf.call(b2, f0); return t1; });");
/*fuzzSeed-168297596*/count=560; tryItOut("Object.defineProperty(o0, \"v2\", { configurable: true, enumerable: ({length: eval(\"/* no regression tests found */\", /$/yi),  get -16(e, x, w = x, eval, z, arguments.callee.caller.arguments, this.x, c = \"\u03a0\", c, e =  /x/ , window, x, y, window, NaN, x, d, e, x, x = /\\b/gi, x = this, x, x, c, \u3056, x =  /x/g , x, NaN, c =  /x/ , NaN, x, z = true, x, x, x, x, x = length, set, x, x, c, x, x, x,  , \u3056 = [,,z1], wrappedJSObject, window, b, x = x, x, \u3056, window, eval =  '' )( /x/  **=  /x/g ) }),  get: function() {  return false; } });");
/*fuzzSeed-168297596*/count=561; tryItOut("o1.o1.o2 = g0.objectEmulatingUndefined();\nprint(x);\n");
/*fuzzSeed-168297596*/count=562; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=[^]|(?:^)|(?=\\uBB10){3})+(?![^])((?!\\b^{1,1}))+?|(?=[^]){4,8}/im; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=563; tryItOut("\"use strict\"; /*MXX1*/o1 = g1.Proxy.name;print(new RegExp(\"\\u00a4\\\\2\", \"m\"));");
/*fuzzSeed-168297596*/count=564; tryItOut("/*ODP-3*/Object.defineProperty(e0, \"push\", { configurable: new RegExp(\"\\\\3\", \"gyi\"), enumerable: true, writable: false, value: v1 });");
/*fuzzSeed-168297596*/count=565; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround((mathy0(( + Math.fround(Math.pow(( + mathy0(y, y)), ( + mathy0((Math.tan((y >>> 0)) >>> 0), (y | 0)))))), ( + Math.imul(Math.sqrt(x), (Math.exp((-Number.MAX_VALUE | 0)) | 0)))) & (Math.cos(Math.atan2((Math.imul(Math.max(y, Math.fround((mathy1(y, Number.MAX_SAFE_INTEGER) * x))), (Math.max(-0x080000001, (Math.tanh((x >>> 0)) ** x)) >>> 0)) | 0), y)) >>> 0))); }); testMathyFunction(mathy2, [-1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, -0, 0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -(2**53+2), 0x080000001, -(2**53-2), 2**53-2, 42, 1.7976931348623157e308, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, -0x100000001, 1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, -0x0ffffffff, -(2**53), 0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, 0, -0x080000000]); ");
/*fuzzSeed-168297596*/count=566; tryItOut("");
/*fuzzSeed-168297596*/count=567; tryItOut("\"use asm\"; s1 += 'x';");
/*fuzzSeed-168297596*/count=568; tryItOut("{ void 0; void relazifyFunctions('compartment'); } a2.shift(f2);");
/*fuzzSeed-168297596*/count=569; tryItOut("testMathyFunction(mathy0, [-0x100000000, -0, Number.MIN_VALUE, 1/0, 2**53-2, 0, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -(2**53-2), Math.PI, -0x080000000, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000001, 0x100000000, 0x080000001, 0/0, Number.MAX_VALUE, 0.000000000000001, 2**53, -0x0ffffffff, -(2**53+2), -1/0, 1.7976931348623157e308, 42, -0x100000001]); ");
/*fuzzSeed-168297596*/count=570; tryItOut("\"use strict\"; print(x)\n");
/*fuzzSeed-168297596*/count=571; tryItOut("\"use strict\"; print(\"\\u517E\");a2 + '';");
/*fuzzSeed-168297596*/count=572; tryItOut("\"use asm\"; testMathyFunction(mathy2, [-1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0, -(2**53+2), -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, 0x100000001, 1, -0, -0x080000001, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -(2**53-2), Math.PI, 0x07fffffff, -Number.MIN_VALUE, 2**53+2, -0x080000000, 0x100000000, Number.MIN_VALUE, 0x080000000, 42, 0x0ffffffff, -0x100000001, 2**53, 1.7976931348623157e308, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=573; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + ( ~ ( + Math.clz32((((x ** Math.fround(Math.log(y))) | 0) >>> 0))))); }); testMathyFunction(mathy1, [-0x080000001, Number.MAX_VALUE, 0x100000000, -Number.MAX_VALUE, -0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, -0, 0x07fffffff, 2**53, -Number.MIN_VALUE, -0x080000000, -1/0, 0, 0/0, 0x080000001, 1/0, 0.000000000000001, 0x100000001, 1, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), 42, 0x080000000, -0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=574; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 129.0;\n    var i4 = 0;\n    {\n      d1 = (Infinity);\n    }\n    i4 = (new RegExp(\"(\\\\s)|(?:(?!\\\\2)?)|\\\\cB(\\\\3)*?\", \"yim\"));\n    {\n      d3 = (d3);\n    }\n    (Uint16ArrayView[((i2)) >> 1]) = ((i2)+(0xfb1051ba));\n    i4 = ((+(0.0/0.0)) <= (+abs(((d3)))));\n    return +((d3));\n  }\n  return f; })(this, {ff: this}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Math.PI, 0x100000001, 1, -0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53+2, -0x07fffffff, 0x07fffffff, 0x080000000, 0x080000001, 0, -(2**53+2), 0x0ffffffff, -(2**53-2), 1/0, 1.7976931348623157e308, 0/0, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 42, -Number.MIN_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 2**53-2, -1/0, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-168297596*/count=575; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(t1, \"call\", { configurable: (x) = (({ set caller(eval, ...y)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-1.0625));\n  }\n  return f; }) ^ (makeFinalizeObserver('nursery'))), enumerable: true, writable: true, value: b1 });");
/*fuzzSeed-168297596*/count=576; tryItOut("a2.push(h2, h1, a2);");
/*fuzzSeed-168297596*/count=577; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xffffffff);\n    i0 = (0xf9eb3928);\n    {\n      {\n        (Uint32ArrayView[2]) = ((!(0xffffffff)));\n      }\n    }\n    i0 = (/*FFI*/ff()|0);\n    return ((((9223372036854776000.0) != (-36893488147419103000.0))+(0xfedad0a3)))|0;\n    return (((0x3ad3c0f2)))|0;\n  }\n  return f; })(this, {ff: Date.now}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 42, -0x07fffffff, 0.000000000000001, 1, Number.MIN_VALUE, 2**53-2, -0x080000001, 1.7976931348623157e308, Math.PI, 2**53+2, 0, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, -0x100000000, 0x100000001, -0x0ffffffff, Number.MAX_VALUE, 2**53, -0, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, -0x100000001, -1/0, -(2**53+2), -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=578; tryItOut("var b0 = t2.buffer;");
/*fuzzSeed-168297596*/count=579; tryItOut("testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0, 2**53, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, -0x080000000, -0x07fffffff, 0x0ffffffff, 1, 0x100000000, -1/0, -0x100000001, 0x07fffffff, 42, -0x100000000, 2**53+2, Math.PI, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x080000000, 2**53-2, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 1/0, -0, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-168297596*/count=580; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(Math.fround(( ! (Math.max(((( - y) ? x : ( + Math.imul((( ~ (x * x)) >>> 0), ( + x)))) >>> 0), (Math.fround(mathy0(Math.fround(Math.fround((Math.fround(y) % Math.fround(y)))), Math.fround(y))) >>> 0)) >>> 0))), ( + ( ~ ( - (( + Math.min(( + x), Math.fround(Math.acosh(Math.fround(x))))) == x))))); }); ");
/*fuzzSeed-168297596*/count=581; tryItOut("");
/*fuzzSeed-168297596*/count=582; tryItOut("\"use strict\"; m1.delete(s1);");
/*fuzzSeed-168297596*/count=583; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var pow = stdlib.Math.pow;\n  var sin = stdlib.Math.sin;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+abs(((d1))));\n    d0 = (+abs(((4611686018427388000.0))));\n    {\n      {\n        switch ((abs((((-0x8000000)-(0x401c244c)) | ((0xffffffff)-(0xc7e9971e)+(0xfd4033ff))))|0)) {\n          case 0:\n            (Float64ArrayView[1]) = ((d0));\n            break;\n        }\n      }\n    }\n    d1 = (d0);\n    d0 = (Infinity);\n    d0 = (+(1.0/0.0));\n    return +((((+pow(((d1)), ((+abs(((0x5a6a1*(0x248a2b88))))))))) - ((+sin(((Infinity)))))));\n  }\n  return f; })(this, {ff: Date.prototype.setUTCMinutes}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53-2), -0, -0x100000000, -0x080000001, -0x100000001, 0x100000001, -(2**53+2), 2**53+2, -(2**53), Math.PI, -1/0, 0x100000000, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, 0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 1, 0x080000000]); ");
/*fuzzSeed-168297596*/count=584; tryItOut("\"use strict\"; v0 = r0.global;");
/*fuzzSeed-168297596*/count=585; tryItOut("\"use strict\"; g1.a0 = arguments.callee.arguments;");
/*fuzzSeed-168297596*/count=586; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, -0x080000001, 2**53-2, 0x0ffffffff, 0x100000000, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0x080000000, -0x07fffffff, -(2**53+2), 0x07fffffff, 42, -0x0ffffffff, -(2**53), 2**53, 0x080000001, -0x100000000, 0.000000000000001, -0, 0/0, 1, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, 0, 1/0, -0x080000000]); ");
/*fuzzSeed-168297596*/count=587; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=588; tryItOut("\"use strict\"; /*bLoop*/for (bcopmv = 0; bcopmv < 3; ++bcopmv) { if (bcopmv % 6 == 2) { /*tLoop*/for (let x of /*MARR*/[x, (0/0), arguments.caller, (0/0), x, (0/0), x, 3/0, x, ((26)), 3/0, x, ((26)), x, arguments.caller, ((26)), (0/0), x, x, (0/0), arguments.caller, (0/0), (0/0), (0/0), ((26)), ((26)), 3/0, (0/0), (0/0), arguments.caller, (0/0), arguments.caller, x, x, 3/0, 3/0, (0/0), x, ((26)), ((26)), ((26)), (0/0), (0/0), arguments.caller, (0/0), arguments.caller, arguments.caller, 3/0, arguments.caller, 3/0, ((26)), arguments.caller, ((26)), x, 3/0, 3/0, 3/0, ((26)), x, arguments.caller, arguments.caller, (0/0), (0/0), 3/0, (0/0), arguments.caller, x, x, x, x, ((26))]) { print(/*MARR*/[1e4, true, Infinity, new String(''), 1e4, new String(''), Infinity, Infinity, Infinity, Infinity, Infinity, 1e4, new String(''), (-1/0), (-1/0), 1e4, (-1/0), Infinity, true, Infinity, new String(''), 1e4, true, (-1/0), 1e4, true, (-1/0), (-1/0), new String(''), true, (-1/0), 1e4, (-1/0), Infinity, (-1/0), new String(''), new String(''), new String(''), true, (-1/0), 1e4, new String(''), 1e4, 1e4, true, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, Infinity].some(function(y) { \"use strict\"; return this })); } } else { v2 = NaN; }  } ");
/*fuzzSeed-168297596*/count=589; tryItOut("this.i0 = m2.iterator;");
/*fuzzSeed-168297596*/count=590; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -3.022314549036573e+23;\n    var i4 = 0;\no1 = a1[({valueOf: function() { v1 = a2.length;return 7; }})];    (Uint8ArrayView[0]) = ((i0));\n    return ((((0xa495215f) > (0x260ab49c))+(i4)))|0;\n  }\n  return f; })(this, {ff: Number.prototype.toString}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x07fffffff, 1/0, -0x080000000, -(2**53+2), -(2**53), 42, -Number.MAX_VALUE, 0x080000000, -0x100000001, -0, -Number.MIN_VALUE, 0x100000000, 2**53+2, 2**53, 0x0ffffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 1, 0, -0x100000000, Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, 0x080000001, 0x07fffffff, -0x080000001, Math.PI, 0/0, 0x100000001]); ");
/*fuzzSeed-168297596*/count=591; tryItOut("e1.add(v2);");
/*fuzzSeed-168297596*/count=592; tryItOut("for (var p in t1) { try { t0 + s1; } catch(e0) { } try { /*ODP-3*/Object.defineProperty(e2, \"keys\", { configurable: true, enumerable: x, writable: false, value: x }); } catch(e1) { } v1 = (t2 instanceof f0); }");
/*fuzzSeed-168297596*/count=593; tryItOut("\"use strict\"; /*oLoop*/for (var hhgaqt = 0; hhgaqt < 43; ++hhgaqt) { /*RXUB*/var r = new RegExp(\"(?:\\\\s*?\\\\b|[^\\\\W\\u0008-\\u00d3\\\\S]|$|(?:(^))*?)(?:(?=\\\\b)|.$${4,4}|\\\\b{3})*(?:\\\\3{1,}).|^+?|(\\\\B)|.[^]|\\\\b\\\\b|$\\\\D+\", \"gy\"); var s = \"_\"; print(s.search(r));  } ");
/*fuzzSeed-168297596*/count=594; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -8589934591.0;\n    i0 = ((+(-1.0/0.0)) == (+((Infinity))));\n    return ((-0xfffff*(0xf8d80216)))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; do {m0.has(e1);for (var p in h1) { try { a2.valueOf = (function() { try { Object.freeze(v2); } catch(e0) { } v2 = false; return i1; }); } catch(e0) { } try { s1 += this.s2; } catch(e1) { } try { /*RXUB*/var r = r2; var s = \"\\n\"; print(uneval(r.exec(s)));  } catch(e2) { } g2.offThreadCompileScript(\"a0.forEach(f2, g2.g1, g1, b1);\"); } } while((NaN in \u3056) && 0);; yield y; }}, new ArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=595; tryItOut("mathy5 = (function(x, y) { return (mathy3((( + (Math.fround(( + (Math.fround(Math.tanh(Number.MAX_VALUE)) && ((( + ( + ( + x))) ** (Math.log10(Math.clz32(Math.fround(y))) >>> 0)) | 0)))) | ( + Math.fround((Math.fround(x) ? Math.fround(y) : Math.fround(y)))))) >>> 0), ((( ~ (((y | 0) ? (y ** y) : (((y | 0) ? ( + Math.log2(Math.fround(mathy2(y, y)))) : (mathy3(Math.fround(-0x100000001), x) | 0)) | 0)) | 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0.000000000000001, 42, 2**53-2, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, 2**53, 0x100000001, -0x100000000, 1/0, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53), -0, 0/0, -(2**53+2), 0x080000001, -1/0, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 2**53+2, Number.MIN_VALUE, 0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), Math.PI]); ");
/*fuzzSeed-168297596*/count=596; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(mathy0(Math.fround((( - (( ~ Math.fround(( - Math.fround(( + (Math.fround(y) + y)))))) >>> 0)) >>> 0)), ( ! Math.pow(-0x0ffffffff, x)))) >>> ((Math.min((Math.max(Math.fround(y), (y >>> 0)) >>> 0), (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) | Math.sin(((Math.fround((Math.fround(y) == Math.fround(Math.imul(x, (y | 0))))) * (( + Math.max(Math.fround(mathy0(2**53-2, -0x080000001)), (mathy0(0x100000001, x) | 0))) >>> 0)) >>> 0)))) >>> 0); }); testMathyFunction(mathy1, [NaN, (new String('')), [0], (new Number(-0)), null, '/0/', false, ({valueOf:function(){return 0;}}), [], (new Number(0)), 0, (new Boolean(false)), -0, '', 1, objectEmulatingUndefined(), '0', ({valueOf:function(){return '0';}}), (new Boolean(true)), 0.1, '\\0', ({toString:function(){return '0';}}), undefined, (function(){return 0;}), /0/, true]); ");
/*fuzzSeed-168297596*/count=597; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((( + Math.cosh((Math.log10((Math.sin(Math.hypot(x, 0.000000000000001)) | 0)) | 0))) + ( + (Math.cbrt(((y ? ( + (0x0ffffffff >>> 0)) : Math.fround(( ! Math.fround(x)))) >>> 0)) >>> 0))) >>> 0); }); ");
/*fuzzSeed-168297596*/count=598; tryItOut("\"use strict\"; v1.__proto__ = a1;");
/*fuzzSeed-168297596*/count=599; tryItOut("mathy5 = (function(x, y) { return ( + Math.hypot((( ! Math.fround(Math.log1p(Math.fround((Math.fround(( ~ Math.min(y, y))) / Math.hypot(y, ((x >>> 0) - y))))))) | 0), ((Math.sinh((( + Math.min(( + Math.sqrt(x)), ( + (x === ( - (Number.MAX_VALUE | 0)))))) | 0)) | 0) | 0))); }); testMathyFunction(mathy5, [-0x100000001, -Number.MAX_VALUE, 0, Number.MIN_VALUE, -0x07fffffff, 42, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, 0x0ffffffff, 0x080000000, 0x07fffffff, 1, 1/0, -0x080000000, -(2**53+2), 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, 0x100000001, -0, -1/0, Math.PI, 2**53+2, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, 1.7976931348623157e308, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=600; tryItOut("b1.__proto__ = f1;");
/*fuzzSeed-168297596*/count=601; tryItOut("Array.prototype.pop.call(a0);");
/*fuzzSeed-168297596*/count=602; tryItOut("mathy4 = (function(x, y) { return (Math.pow((( + (Math.cos(mathy3(( + Math.trunc(x)), Math.fround((42 ^ (-Number.MIN_SAFE_INTEGER | 0))))) >>> 0)) | 0), (( ! (Math.imul(Math.fround(Math.round(x)), ( + Math.tanh((y >>> 0)))) | 0)) | ( + Math.min(( + (((((x <= x) ^ Math.expm1(( + x))) | 0) <= (mathy1(((( ~ (y >>> 0)) | 0) >>> 0), -Number.MAX_VALUE) | 0)) | 0)), Math.pow(x, Math.fround((Math.atan(((x >>> 0) <= y)) * x))))))) | 0); }); testMathyFunction(mathy4, [-0x100000000, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, 1/0, 2**53+2, 1, -0x080000001, 2**53-2, Number.MIN_VALUE, 0.000000000000001, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, -Number.MIN_VALUE, 2**53, -0, 0x100000000, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -0x100000001, -0x080000000, 0/0, -Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, Math.PI, -1/0]); ");
/*fuzzSeed-168297596*/count=603; tryItOut("\"use strict\"; \u000cz;\ni1.send(e2);\n");
/*fuzzSeed-168297596*/count=604; tryItOut("/*vLoop*/for (let tiwdkl = 0, qmixeu; tiwdkl < 25; ++tiwdkl) { b = tiwdkl; print(Math.hypot(-11,  \"\" )); } t1 = new Float32Array(b2);");
/*fuzzSeed-168297596*/count=605; tryItOut(" for  each(let b in false) {print(x);\"\\u08FE\"; }");
/*fuzzSeed-168297596*/count=606; tryItOut("mathy3 = (function(x, y) { return Math.log10(Math.abs(( + (( + ( + Math.sqrt(( + x)))) <= ( + Math.cosh(Math.hypot(y, Math.pow(y, ((0/0 < (y | 0)) | 0))))))))); }); testMathyFunction(mathy3, [-(2**53+2), Number.MIN_VALUE, 2**53, 0x080000000, -Number.MAX_VALUE, 0x100000001, Math.PI, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, -(2**53), 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 0x080000001, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, 1/0, -0x07fffffff, -1/0, 1, 0, 0.000000000000001, -0, 42, -0x080000000]); ");
/*fuzzSeed-168297596*/count=607; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[new Boolean(false), {}, new Boolean(false), ['z'], ['z'], {}, new Boolean(false), {}, {}, ['z'], new Boolean(false), {}, {}, new Boolean(false), ['z'], ['z'], {}, new Boolean(false), ['z'], ['z'], ['z'], new Boolean(false), ['z'], ['z'], {}, {}, new Boolean(false), ['z'], ['z'], {}, new Boolean(false), {}, new Boolean(false), ['z'], new Boolean(false), ['z']]); ");
/*fuzzSeed-168297596*/count=608; tryItOut("const this.t2 = new Int32Array(({valueOf: function() { /* no regression tests found */return 12; }}));");
/*fuzzSeed-168297596*/count=609; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.ceil((Math.sin(( ~ ((x >>> 0) < Math.hypot(y, x)))) | 0)) === Math.hypot(Math.fround((Math.expm1(Number.MAX_VALUE) == Math.PI)), Math.fround(Math.atan2((Math.imul(x, 0) | 0), x)))); }); testMathyFunction(mathy0, /*MARR*/[x, (uneval((4277))), x, x, (uneval((4277))), x, x, (uneval((4277))), (uneval((4277))), x, (uneval((4277))), (uneval((4277))), x, x, (uneval((4277))), x, (uneval((4277))), x, (uneval((4277))), (uneval((4277))), x, (uneval((4277))), (uneval((4277))), (uneval((4277))), (uneval((4277))), x, x, (uneval((4277))), x, x, (uneval((4277))), (uneval((4277))), x, (uneval((4277))), (uneval((4277))), (uneval((4277))), x, (uneval((4277))), x, (uneval((4277))), (uneval((4277))), (uneval((4277))), (uneval((4277))), x, (uneval((4277))), x, (uneval((4277))), x, x]); ");
/*fuzzSeed-168297596*/count=610; tryItOut("f0(g1.b0);");
/*fuzzSeed-168297596*/count=611; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( - ( + Math.fround(mathy0(Math.fround(Math.fround(( ! Math.fround((Math.cosh((-0x080000000 >>> 0)) >>> 0))))), (Math.clz32(( + Math.atan2(( + y), ( - y)))) >>> 0))))) >>> 0); }); testMathyFunction(mathy1, [0x07fffffff, 0, 2**53-2, 42, -0x080000001, 0x080000001, Math.PI, -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000000, 1, -0x080000000, 2**53, 0x0ffffffff, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0/0, -Number.MAX_VALUE, -(2**53-2), 1/0, -0, 0x100000001, -Number.MIN_VALUE, -(2**53), Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=612; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=613; tryItOut("i0 = t2[16];");
/*fuzzSeed-168297596*/count=614; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_VALUE, 0x080000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, -0x100000000, 0x100000000, 0x080000000, 0.000000000000001, -0, Math.PI, Number.MAX_VALUE, -0x100000001, -0x07fffffff, 0, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 1/0, -0x0ffffffff, -1/0, -0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, 1, 0x100000001, 2**53, 2**53+2]); ");
/*fuzzSeed-168297596*/count=615; tryItOut("print(/\\cR/m);for (var p in o2) { try { e2.has(e2); } catch(e0) { } try { a0 = new Array; } catch(e1) { } (void schedulegc(this.o0.g1)); }");
/*fuzzSeed-168297596*/count=616; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - Math.hypot(( + ( + y)), ( + y))); }); testMathyFunction(mathy4, [0x080000001, 1, 0x080000000, 0x07fffffff, 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, 1/0, -0x07fffffff, -(2**53-2), -0x080000001, 0, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, 2**53-2, 0/0, -0x100000000, -0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, 0.000000000000001, 42, -0x100000001, 2**53, Math.PI, -(2**53+2), -(2**53), -1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=617; tryItOut("/*infloop*/L: for  each(var this.zzz.zzz in (4277)) {/* no regression tests found */ }");
/*fuzzSeed-168297596*/count=618; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(( + (((Math.fround(( ! ( + (Math.atan2((Math.min((0x080000001 >>> 0), (x >>> 0)) >>> 0), ((-0x080000000 >>> 0) || ((Math.hypot((x | 0), (x | 0)) | 0) >>> 0))) | y)))) >>> 0) << (( ! (y >>> 0)) >>> 0)) >>> 0)), (Math.fround(mathy0(Math.fround((Math.fround(Math.atan2(Math.fround(y), Math.fround(Math.fround(Math.sqrt(( + y)))))) + Math.fround(mathy1(Math.fround(x), Math.fround(Math.fround(( + Math.fround((Math.fround(Math.atan(Math.fround(y))) ? ( + x) : Math.expm1(x)))))))))), ( + (Math.sin(Math.atanh(Math.cbrt((42 | 0)))) === ( + Math.fround(( + Math.fround(-Number.MIN_VALUE)))))))) | 0)); }); ");
/*fuzzSeed-168297596*/count=619; tryItOut("testMathyFunction(mathy3, /*MARR*/[[[1]], 1e81, [[1]], (let (c, b, ptjneg) x\u000d), 1e81, (let (c, b, ptjneg) x\u000d), (let (c, b, ptjneg) x\u000d), [1], [1], [[1]], 1e81, (let (c, b, ptjneg) x\u000d), [1], [1], 1e81, [[1]], (let (c, b, ptjneg) x\u000d), [1], [1], [1], [1], [1], [[1]], (let (c, b, ptjneg) x\u000d), (let (c, b, ptjneg) x\u000d)]); ");
/*fuzzSeed-168297596*/count=620; tryItOut("a0.shift();");
/*fuzzSeed-168297596*/count=621; tryItOut("\"use strict\"; print( '' );");
/*fuzzSeed-168297596*/count=622; tryItOut("a2 = [];");
/*fuzzSeed-168297596*/count=623; tryItOut("mathy2 = (function(x, y) { return (mathy0(Math.sin(Math.cos(0/0)), ((Math.imul((Math.fround(( ~ y)) | 0), ((x >>> (Math.fround(x) >>> 0)) | 0)) !== Math.expm1((( - (2**53-2 | 0)) | 0))) | 0)) >>> 0); }); testMathyFunction(mathy2, [0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, Number.MIN_VALUE, 0.000000000000001, -0x100000000, -(2**53-2), -0x07fffffff, 2**53-2, -(2**53), 1, 0/0, 2**53, -0, -Number.MAX_VALUE, 0x100000001, 0x0ffffffff, -0x080000000, Number.MAX_VALUE, Math.PI, 2**53+2, -(2**53+2), -0x100000001, 0x080000001, -0x080000001, 1/0, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, -1/0, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=624; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i0, m1);");
/*fuzzSeed-168297596*/count=625; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=626; tryItOut("m0.valueOf = (function() { for (var j=0;j<60;++j) { f0(j%4==1); } });");
/*fuzzSeed-168297596*/count=627; tryItOut("\"use strict\"; delete this.p2[(4277)];");
/*fuzzSeed-168297596*/count=628; tryItOut("testMathyFunction(mathy1, [-0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, 1, 0x100000000, 0x100000001, -0, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0, Number.MAX_VALUE, 42, Math.PI, 1.7976931348623157e308, 0x07fffffff, 0.000000000000001, -0x100000000, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, 0x080000001, -(2**53+2), -0x080000001, Number.MIN_VALUE, 2**53-2, -0x100000001, -0x0ffffffff, -(2**53-2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=629; tryItOut("/*infloop*/for(let z = x; (4277); -11) print(z);");
/*fuzzSeed-168297596*/count=630; tryItOut("mathy2 = (function(x, y) { return (( + mathy1(( + ( + Math.max(Math.fround(( + ( + (( ~ x) >>> 0)))), ( ! y)))), ( + ((mathy1((y | 0), x) | 0) || 1)))) === Math.trunc((( + (((( + Math.clz32(x)) || ( + (Math.asin(((Math.pow((y | 0), (Math.PI | 0)) | 0) >>> 0)) >>> 0))) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -(2**53-2), -(2**53), Math.PI, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, 2**53-2, Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, -0x080000001, -(2**53+2), -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, -0, 0/0, 2**53, 0x080000001, -0x100000001, -0x100000000, 0x0ffffffff, 1.7976931348623157e308, 0, 0x07fffffff, 2**53+2, 0x100000001, 42, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=631; tryItOut("\"use strict\"; const NaN, NaN, x, { sameZoneAs: /*RXUE*/new RegExp(\"[^]{4,5}(?=(?:.{1}|(?=[^])){4,})|(?=\\\\b)^^+?+\", \"gyi\").exec(\"\\n\\u2391\\ub530\\n \\n\\u9f0d\\n\\u4980\\n\\n\\n\\n \\n\\u9f0d\\n\\u4980\\n\\n\\n\\n \\n\\u9f0d\\n\\u4980\\n\\n\\n\\n\"), cloneSingletons: (x % 33 == 25), disableLazyParsing: (x % 23 == 22) } = (function(y) { return y }).call(x / x, ) >>>= x, window = Math.max(-22, -12), [] = (String.prototype.link)(), e = (/*FARR*/[].filter(\"\\u3520\")) && \u37d5.prototype, c = (this.__defineGetter__(\"x\", 28.setPrototypeOf).__defineGetter__(\"c\", (function(x, y) { \"use strict\"; return (Math.max((y >>> 0), (y >>> 0)) >>> 0); })));L:if(true) {; }");
/*fuzzSeed-168297596*/count=632; tryItOut("\"use strict\"; var ocyjeh = new SharedArrayBuffer(2); var ocyjeh_0 = new Int32Array(ocyjeh); var ocyjeh_1 = new Int8Array(ocyjeh); print(ocyjeh_1[0]); var ocyjeh_2 = new Uint8Array(ocyjeh); var ocyjeh_3 = new Uint16Array(ocyjeh); print(ocyjeh_3[0]); ocyjeh_3[0] = -27; var ocyjeh_4 = new Int32Array(ocyjeh); print(ocyjeh_4[0]); var ocyjeh_5 = new Int32Array(ocyjeh); ocyjeh_5[0] = -4; var ocyjeh_6 = new Uint32Array(ocyjeh); print(ocyjeh_6[0]); ocyjeh_6[0] = -15; var ocyjeh_7 = new Uint16Array(ocyjeh); s2 += 'x';o0.h2.fix = f1;(Math.log10).bind(w, d)this;print(true);(new RegExp(\"(\\\\d[\\\\s]+){2}\\\\d|[\\\\\\u00d9-\\u6f54\\\\w\\u00fa]?\", \"m\"));this.v1 = Object.prototype.isPrototypeOf.call(s0, g2.e0);print({});print(false);e2.add(p1);e2 + p2;\"\\uDBA1\";");
/*fuzzSeed-168297596*/count=633; tryItOut("testMathyFunction(mathy1, /*MARR*/[function(){}, -0x5a827999, -0x5a827999,  /x/ , objectEmulatingUndefined(), function(){},  /x/ ,  /x/ , function(){}, function(){}, function(){},  /x/ ,  /x/ ,  /x/ , function(){}, objectEmulatingUndefined(), function(){}, -0x5a827999, function(){}, function(){},  /x/ , objectEmulatingUndefined(), function(){}, function(){}, -0x5a827999, function(){}, function(){},  /x/ , objectEmulatingUndefined(), function(){}, function(){},  /x/ , function(){}, function(){},  /x/ ]); ");
/*fuzzSeed-168297596*/count=634; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?!(?:\\\\1)))+?\", \"gyi\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-168297596*/count=635; tryItOut("\"use strict\"; t0[5] = /*MARR*/[(-1/0), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), x |= (4277), null, (0/0), null, new Number(1), (0/0), (-1/0), new Number(1), null, null, (-1/0), x |= (4277), new Number(1), null, new Number(1), (0/0)].map(encodeURIComponent, Math.min(-20, -6));");
/*fuzzSeed-168297596*/count=636; tryItOut("testMathyFunction(mathy0, [0x07fffffff, -1/0, 2**53, 0x080000001, -0x07fffffff, -0x080000001, -(2**53), -(2**53+2), 0/0, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, -0x100000001, -0, -Number.MAX_VALUE, 42, 0, 0.000000000000001, 1/0, 1.7976931348623157e308, 0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), 0x080000000, -0x0ffffffff, -0x100000000, 0x100000000]); ");
/*fuzzSeed-168297596*/count=637; tryItOut("\"use strict\"; /*infloop*/for/*\n*/(b; (Object.defineProperty(\u3056, 7, ({writable: true, configurable: (x % 57 != 39)}))); let (y) (4277)) g1.v1 = t2.BYTES_PER_ELEMENT\n");
/*fuzzSeed-168297596*/count=638; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.cbrt(( + Math.max(( - ( + Math.clz32(x))), Math.atan(((((Math.max((( ! y) >>> 0), ((Math.min(y, (y | 0)) | 0) | 0)) | 0) >>> y) ? (Math.max((Math.min(x, (0x100000001 >>> 0)) >>> 0), Math.fround(Math.cosh(y))) | 0) : ((Math.fround((( - (y >>> 0)) >>> 0)) > Math.fround(x)) | 0)) | 0))))) | 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x07fffffff, 1/0, -1/0, -0x100000001, -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, Number.MIN_VALUE, 1, 2**53, -0x080000000, -0, -Number.MIN_VALUE, -(2**53), -0x100000000, -(2**53+2), Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, 0x100000001, 2**53+2, -0x080000001, 0x100000000, 0x080000001, 0, 0x080000000]); ");
/*fuzzSeed-168297596*/count=639; tryItOut("print(x);function x({})\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (i1);\n    }\n    return +((d0));\n  }\n  return f;print(x);");
/*fuzzSeed-168297596*/count=640; tryItOut("M:do let (d) { m0.has(v0); } while(([,,] === (-4 ? 29 : this) || x) && 0);");
/*fuzzSeed-168297596*/count=641; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = o1.s0; print(r.test(s)); \n/* no regression tests found */\n");
/*fuzzSeed-168297596*/count=642; tryItOut("g1.b0.toString = (function() { for (var j=0;j<29;++j) { f2(j%3==0); } });");
/*fuzzSeed-168297596*/count=643; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return -5200806; }); testMathyFunction(mathy5, [1.7976931348623157e308, -(2**53+2), -(2**53-2), 0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, Number.MIN_VALUE, -(2**53), -0x07fffffff, 0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, 2**53, -0, 2**53-2, -1/0, -0x100000000, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 1, 42, Math.PI]); ");
/*fuzzSeed-168297596*/count=644; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 576460752303423500.0;\n    d2 = (-295147905179352830000.0);\n    i1 = (0xfcd03711);\n    {\n      i1 = (0xfa256b24);\n    }\n    d2 = (NaN);\n    i1 = ((6.044629098073146e+23) >= (+(0.0/0.0)));\n    i1 = ((imul((i1), ((0x18da987e)))|0) >= (~~(-1.9342813113834067e+25)));\n    d2 = (+floor((((/*FFI*/ff((((-0xfffff*(!(-0x8000000))) << (((147573952589676410000.0) < (-1.0078125))-((-0x8000000) ? (0xffffffff) : (-0x8000000))-(0x4cb3f8a7)))), ((d2)), ((+/*FFI*/ff(((~~(-67108865.0))), ((NaN)), ((-257.0)), ((-513.0)), ((2.4178516392292583e+24)), ((-72057594037927940.0)), ((-18446744073709552000.0)), ((-576460752303423500.0)), ((1.125)), ((-72057594037927940.0)), ((513.0)), ((-0.25)), ((4097.0)), ((-2147483647.0)), ((1.125))))))|0) ? (((Float32ArrayView[((!((0x70da8b3a) >= (0xaf7f2321)))) >> 2])) / ((0x9717c9ea))) : (d2)))));\n    d2 = (((d2)) * ((+(~~(((+(imul(((0xe06e3a08) <= (0x3ccc594c)), (i1))|0))) % ((4294967297.0)))))));\n    (Uint8ArrayView[1]) = (-0xf9206*((~((((0xfcd88361)+(0xffffffff)) | (((0xfc118fc5) ? (0xfd0acb70) : (0xffffffff))-(i0))) % (~((0xfc42441d)))))));\n    {\n      {\n        i0 = (i0);\n      }\n    }\n    {\n      {\n        switch (((((562949953421313.0) == (-8.0))) >> ((!((0x7fffffff) > (0x53aa813f)))))) {\n          case -1:\n            (Float64ArrayView[((!(i0))+((+(imul((0xfada9c55), (0x6100f1da))|0)) != (1.125))-((0x20402c27))) >> 3]) = ((Float64ArrayView[((-0x8000000)-((((0xe3883090) % (0xffffffff)) << ((i1)+(!(0xf826b443)))) <= (this >>  '' ))-((((0x752632b0)-(0x30de42f7)+(0x962165e8))>>>(-((35184372088833.0) < (-17592186044416.0)))) < (((i0)-(0x76069596))>>>((0xffffffff)-(0xfec128f3)+(0xd4bde151))))) >> 3]));\n            break;\n          case 1:\n            i1 = (!((~~(-288230376151711740.0))));\n          case -1:\n            i1 = (i1);\n            break;\n          case 0:\n            i1 = (0xde0b42da);\n            break;\n          default:\n            return +((-4097.0));\n        }\n      }\n    }\n    return +((Float64ArrayView[((i1)-(0x9f96ac66)) >> 3]));\n    return +(((Float32ArrayView[2])));\n  }\n  return f; })(this, {ff: eval(\"print(x);\")}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[]); ");
/*fuzzSeed-168297596*/count=645; tryItOut("/*hhh*/function cdmwkl(){L:if(true) for (var p in v1) { try { o2 = new Object; } catch(e0) { } try { g1.a2[(function ([y]) { })()] = v2; } catch(e1) { } try { e1.delete(e1); } catch(e2) { } for (var v of g0.a1) { try { this.p2 + ''; } catch(e0) { } try { Array.prototype.unshift.call(a2, b0); } catch(e1) { } try { v1 = r2.exec; } catch(e2) { } h2 + ''; } } else {e2 + '';a2.unshift(t0, m2, v0); }}/*iii*/a2.forEach((function() { try { g2.__proto__ = this.h0; } catch(e0) { } o2.v1 = Object.prototype.isPrototypeOf.call(this.g0, t2); throw o1; }));");
/*fuzzSeed-168297596*/count=646; tryItOut("let (x = (p={}, (p.z = /\\B{1,}(((?!\u00e2)))+?|[^]{3}/m)()), d, x = -27 ?  /x/  : -2812607673.watch(\"__count__\", Error), z = \"\\u7730\", x =  \"\" , x, e) { this.t0[o0.v1] = o2.g0; }");
/*fuzzSeed-168297596*/count=647; tryItOut("mathy2 = (function(x, y) { return ((Math.pow(y, (y << -(2**53+2))) !== Math.atan(-0x100000000)) === ( - ( + (((x ? x : x) > Math.round(y)) && ( + (Math.atan2(Math.hypot(0x100000001, x), x) | 0)))))); }); ");
/*fuzzSeed-168297596*/count=648; tryItOut("a2.push(g1.g1.g2.g1.g1, h1, a2);/*ADP-1*/Object.defineProperty(a1, 4, ({get: offThreadCompileScript, configurable: \"\\uFD76\", enumerable: true}));");
/*fuzzSeed-168297596*/count=649; tryItOut("testMathyFunction(mathy1, [0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, -0, 0x080000000, -0x07fffffff, -0x100000000, -(2**53-2), -Number.MIN_VALUE, -0x080000001, 0.000000000000001, -(2**53), 0/0, 2**53+2, -0x100000001, 42, 1, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, -Number.MAX_VALUE, 1/0, -0x0ffffffff, 1.7976931348623157e308, 2**53, Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, -0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=650; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=651; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.tan((Math.cbrt((Math.acosh((( - y) >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x0ffffffff, 2**53, 0/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, -(2**53), 2**53+2, 1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, -(2**53-2), -0x07fffffff, -0, -0x100000000, -0x080000001, -Number.MIN_VALUE, -0x100000001, 42, 1, 0, -Number.MAX_VALUE, 0x080000001, 0x080000000, 1.7976931348623157e308, -0x080000000, 0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=652; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Math.PI, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53, 2**53-2, 1/0, 0x080000000, 0.000000000000001, Number.MAX_VALUE, -0x100000001, -0x080000000, 1.7976931348623157e308, 0x0ffffffff, -1/0, 0x100000000, 0x100000001, -(2**53), -Number.MIN_VALUE, -0x100000000, 0/0, -0, 0x080000001, -(2**53+2), 1]); ");
/*fuzzSeed-168297596*/count=653; tryItOut("print(this.a1);");
/*fuzzSeed-168297596*/count=654; tryItOut("(4277);");
/*fuzzSeed-168297596*/count=655; tryItOut("a0 = Array.prototype.slice.call(g0.a1, 4, 1);");
/*fuzzSeed-168297596*/count=656; tryItOut("for(let z in []);\u0009\nvar kksegi = new ArrayBuffer(4); var kksegi_0 = new Int16Array(kksegi); kksegi_0[0] = 0; o2 + '';print(x);\n");
/*fuzzSeed-168297596*/count=657; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.hypot(Math.fround((mathy4((mathy1(Math.pow(x, (((1/0 >>> 0) || (((x | 0) % y) | 0)) | 0)), ( ~ Math.fround(Number.MIN_VALUE))) | 0), (( ! (Math.imul((0.000000000000001 * y), ( ~ x)) >>> 0)) >>> 0)) | 0)), Math.fround((Math.fround(Math.acosh(((Math.log2(y) + ( + Math.fround(( + Math.fround(-(2**53+2)))))) | 0))) > (( - ((y ? y : x) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [0.000000000000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, 0x100000000, 0/0, 0, -(2**53), 42, -0x100000000, 1, 2**53-2, 0x080000001, -0x080000001, 2**53, 0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, Math.PI, 2**53+2, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x100000001, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=658; tryItOut("const {} = /(\\W){0}|(?=[^])*?|.|.{2,}{4,}^|.*?[^\\D\u367e\\W\\w]*?/gyim >= this, nqovsg, wrrkdt, mdrxfr, jmropl, x, nodtgg;this.v0 = Object.prototype.isPrototypeOf.call(m0, o0);\nv2 = Object.prototype.isPrototypeOf.call(g2, p0);\n");
/*fuzzSeed-168297596*/count=659; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=660; tryItOut("\"use strict\"; bmxqho();/*hhh*/function bmxqho(x){({ : (\n((void options('strict_mode'))))}) = a0[v1];}");
/*fuzzSeed-168297596*/count=661; tryItOut("\"use strict\"; with({x: ({x: (\u3056 = x) })})(new (/*UUV2*/(eval.valueOf = eval.__lookupGetter__))());");
/*fuzzSeed-168297596*/count=662; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2*?\", \"ym\"); var s = ((yield delete x.d)); print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=663; tryItOut("Array.prototype.push.apply(g0.a2, [t1, o2.m2, (Math.expm1(x))]);");
/*fuzzSeed-168297596*/count=664; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-168297596*/count=665; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy2(Math.atanh(Math.fround(( ! ( + Math.expm1(Math.fround((Math.pow(( + Math.fround(mathy2(x, y))), (Math.pow(x, 42) >>> 0)) >>> 0))))))), (Math.expm1(( + mathy1(( + (( ! Math.sin(x)) | 0)), ( + Math.max(x, (( + Math.fround(Math.max((( ~ (-Number.MIN_VALUE | 0)) | 0), (x ^ y)))) | 0)))))) | 0)); }); ");
/*fuzzSeed-168297596*/count=666; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?:\\\\2){34359738369,34359738372})(?:\\\\1|.+)+|(?:(?!(?!\\\\w)))\", \"ym\"); var s = x; print(s.split(r)); ");
/*fuzzSeed-168297596*/count=667; tryItOut("with({y: x})((new Function(\" \\\"\\\" ;\"))).apply\nv1.toSource = (function mcc_() { var pqwudz = 0; return function() { ++pqwudz; if (/*ICCD*/pqwudz % 10 == 1) { dumpln('hit!'); try { /*MXX2*/g2.Uint32Array.prototype.constructor = e0; } catch(e0) { } try { t0 = new Uint32Array(b1); } catch(e1) { } t1[v1]; } else { dumpln('miss!'); for (var v of o0) { v2 = g0.eval(\"/*ODP-3*/Object.defineProperty(h2, \\\"split\\\", { configurable: (y % 2 == 1), enumerable: true, writable: false, value: s0 });\"); } } };})();\n");
/*fuzzSeed-168297596*/count=668; tryItOut("\"use strict\"; o1.r1 = new RegExp(\"$\\\\S\", \"yi\");");
/*fuzzSeed-168297596*/count=669; tryItOut("testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 2**53-2, -1/0, 0x0ffffffff, 1/0, -(2**53), 2**53+2, -(2**53+2), Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, Number.MAX_VALUE, 0/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -0, -0x080000000, 0x080000000, -(2**53-2), -0x100000001, 0x100000000, 2**53, 0, 1.7976931348623157e308, 0x07fffffff, 42]); ");
/*fuzzSeed-168297596*/count=670; tryItOut("m1 = new WeakMap;let d = /*UUV1*/(x.endsWith = Object.getOwnPropertyNames);");
/*fuzzSeed-168297596*/count=671; tryItOut("mathy5 = (function(x, y) { return Math.expm1(Math.fround(( + Math.fround((y != ( ~ -0x080000001)))))); }); testMathyFunction(mathy5, [2**53-2, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, -0, 2**53, -0x080000001, Number.MAX_VALUE, -(2**53), -1/0, -Number.MIN_VALUE, 0.000000000000001, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, -0x100000001, 2**53+2, -Number.MAX_VALUE, 0/0, 0x0ffffffff, 0x100000000, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, 0x100000001, 42, 0, -0x100000000, -0x07fffffff, -(2**53+2), 1]); ");
/*fuzzSeed-168297596*/count=672; tryItOut("v1 = Object.prototype.isPrototypeOf.call(t2, f1);");
/*fuzzSeed-168297596*/count=673; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (0xffffffff);\n    }\n    return ((((+(((0x9d46a48b)+(0xad673e39))>>>((0x7753049a)))) > (Infinity))*0xfffff))|0;\n  }\n  return f; })(this, {ff: (4277)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MAX_VALUE, -1/0, 1, 0x080000000, Math.PI, -(2**53), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, 2**53+2, 2**53, 0/0, -(2**53+2), -0, -Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 0x100000000, -0x080000001, -0x100000000, -0x0ffffffff, -0x080000000, Number.MIN_VALUE, -0x100000001, 0x07fffffff, 0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=674; tryItOut("/*tLoop*/for (let b of /*MARR*/[undefined, new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), new Boolean(false), new Boolean(false), undefined, undefined, new Boolean(false), undefined, undefined, undefined, new Boolean(false), undefined, undefined, new Boolean(false), undefined, undefined, new Boolean(false), undefined, undefined, undefined, undefined, new Boolean(false), undefined, undefined, undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), undefined, undefined, undefined, new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), undefined, undefined, undefined, undefined, new Boolean(false), undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), new Boolean(false), undefined, undefined, undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), undefined, undefined, new Boolean(false), undefined, undefined, new Boolean(false), undefined, undefined, undefined]) { print(b); }");
/*fuzzSeed-168297596*/count=675; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = \"\\u6cea\"; print(uneval(s.match(r))); ");
/*fuzzSeed-168297596*/count=676; tryItOut("m1.has(e2);");
/*fuzzSeed-168297596*/count=677; tryItOut("neuter(b0, \"change-data\");");
/*fuzzSeed-168297596*/count=678; tryItOut("/*RXUB*/var r = new RegExp(\"[^]\", \"y\"); var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-168297596*/count=679; tryItOut("\"use strict\"; return true;(\"\\uE93A\");");
/*fuzzSeed-168297596*/count=680; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.imul(( + (Math.max(( + 1), Math.fround((Math.fround(Math.hypot(x, x)) ^ x))) >>> 0)), Math.ceil(Math.fround(Math.exp((Math.min(1/0, x) >>> 0)))))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 2**53-2, 2**53+2, -(2**53), 2**53, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -0x07fffffff, 0x080000001, Math.PI, 0x100000001, 0/0, -Number.MIN_VALUE, 1.7976931348623157e308, -0, 42, -0x080000000, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 1, 0x0ffffffff, -0x100000000, 0x07fffffff, -0x100000001, 0]); ");
/*fuzzSeed-168297596*/count=681; tryItOut("mathy0 = (function(x, y) { return Math.ceil(( + ( + (Math.fround(Math.sin((x % Math.fround(( + Math.fround(-0x0ffffffff)))))) >>> 0)))); }); testMathyFunction(mathy0, [0x080000001, 0x080000000, -(2**53+2), 1.7976931348623157e308, 1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, -0x07fffffff, 2**53+2, Math.PI, -0, 0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 42, 0/0, 1, 2**53-2, -1/0, -(2**53-2), 0x100000001, -(2**53), 0x07fffffff, -0x080000001, 0x0ffffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-168297596*/count=682; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\\u00e2\"; print(s.replace(r, -13)); ");
/*fuzzSeed-168297596*/count=683; tryItOut("\"use strict\"; /*RXUB*/var r = /(((?!\\1{0,3})?){0})/gyi; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=684; tryItOut("\"use strict\"; a1.unshift(s0, o1);");
/*fuzzSeed-168297596*/count=685; tryItOut("\"use strict\"; var ywlslc = new ArrayBuffer(3); var ywlslc_0 = new Uint16Array(ywlslc); print(ywlslc_0[0]); ywlslc_0[0] = -26; var ywlslc_1 = new Int16Array(ywlslc); var ywlslc_2 = new Uint8Array(ywlslc); ywlslc_2[0] = -1; var ywlslc_3 = new Float32Array(ywlslc); print(ywlslc_3[0]); ywlslc_3[0] = -1; var ywlslc_4 = new Float64Array(ywlslc); ywlslc_4[0] = -0; var ywlslc_5 = new Float32Array(ywlslc); print(ywlslc_5[0]); var ywlslc_6 = new Int8Array(ywlslc); ywlslc_6[0] = -26; var ywlslc_7 = new Float32Array(ywlslc); print(ywlslc_7[0]); ywlslc_7[0] = 5; var ywlslc_8 = new Int32Array(ywlslc); print(ywlslc_8[0]); var ywlslc_9 = new Int8Array(ywlslc); ywlslc_9[0] = -26; var ywlslc_10 = new Int16Array(ywlslc); print(ywlslc_10[0]); var ywlslc_11 = new Uint8Array(ywlslc); var ywlslc_12 = new Uint16Array(ywlslc); print(ywlslc_12[0]); ywlslc_12[0] = 1; a1[10];");
/*fuzzSeed-168297596*/count=686; tryItOut("g2.v1 = a1[\"1\"];");
/*fuzzSeed-168297596*/count=687; tryItOut("print(x);function x(...x)x = \"\u03a0\"v0 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-168297596*/count=688; tryItOut("\"use strict\"; s1 + '';");
/*fuzzSeed-168297596*/count=689; tryItOut("o1.b2 + h2;");
/*fuzzSeed-168297596*/count=690; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:$)\", \"gym\"); var s = \"\\n\\n\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=691; tryItOut("mathy1 = (function(x, y) { return Math.fround(( + (( + Math.max(( + Math.exp(( + Math.fround(Math.pow(Math.fround(y), Math.fround(Math.fround(Math.ceil(Math.fround(x))))))))), ( + Math.fround((Math.fround(((Math.asin(Math.fround(x)) | 0) + (Math.cbrt(x) | 0))) < Math.fround((Math.max(x, -0) >> ( + Math.min(-(2**53), 0x080000001))))))))) | 0))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 42, -0x100000001, 0/0, 1, Number.MIN_VALUE, 0x080000000, 0, -0x0ffffffff, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, 1.7976931348623157e308, -0x100000000, 0x080000001, 0x0ffffffff, -0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, -(2**53-2), -Number.MIN_VALUE, Math.PI, 2**53-2, -(2**53), 0.000000000000001, 1/0, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -1/0]); ");
/*fuzzSeed-168297596*/count=692; tryItOut("\"use strict\"; v0 = a1.length;");
/*fuzzSeed-168297596*/count=693; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.log10(( + (Math.fround(((Math.imul(( - Math.fround(y)), -0x07fffffff) | 0) | 0)) >> (Math.min((Math.fround(Math.ceil(Math.fround(x))) >>> 0), (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, /*MARR*/[NaN, new Number(1.5), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), NaN, objectEmulatingUndefined(), NaN, NaN, new String(''), new String(''), NaN, new Number(1.5), new String(''), new String(''), new Number(1.5), new String(''), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new String(''), NaN, NaN, NaN, objectEmulatingUndefined(), new String(''), NaN, objectEmulatingUndefined(), new String(''), NaN, new Number(1.5), new Number(1.5), new String(''), NaN, new String(''), new String('')]); ");
/*fuzzSeed-168297596*/count=694; tryItOut(";");
/*fuzzSeed-168297596*/count=695; tryItOut("mathy0 = (function(x, y) { return (Math.fround((Math.max(( + y), ((-0x100000000 >>> 0) | Math.min(Math.imul(Math.fround((Math.fround(-1/0) - Math.fround(y))), x), ( ! x)))) >= ((makeFinalizeObserver('nursery')) >>> 0))) ? (Math.imul((Math.min(( - (Math.atanh(((((y | 0) | (42 | 0)) | 0) | 0)) >>> 0)), (Math.fround(( ! (Math.abs((x >>> 0)) >>> 0))) >> Math.PI)) | 0), (Math.max(( ! (x - Number.MAX_SAFE_INTEGER)), Math.fround(Math.hypot(( + (( + x) && x)), ( ! (Math.sin((42 >>> 0)) >>> 0))))) | 0)) >>> 0) : ((( + Math.fround(Math.atanh(Math.fround((x | -Number.MAX_SAFE_INTEGER))))) | 0) - (((2**53-2 % x) >= -0x080000000) > ( + x)))); }); testMathyFunction(mathy0, [1/0, 1, 2**53, 0x0ffffffff, -0x100000000, 0, -(2**53), -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 0/0, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, Math.PI, -1/0, 2**53-2, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, 42, -0x07fffffff, -0x080000001, 0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=696; tryItOut("\"use strict\"; t2[16];");
/*fuzzSeed-168297596*/count=697; tryItOut("mathy5 = (function(x, y) { return ( + Math.tan((Math.sinh(Math.fround(( + Math.log10((( ~ x) >>> 0))))) | 0))); }); testMathyFunction(mathy5, [-(2**53-2), 0x100000000, 0x100000001, -0, 0/0, 0x07fffffff, -0x0ffffffff, -0x100000001, 0x080000000, 2**53, -(2**53), Math.PI, 0x080000001, 2**53+2, Number.MAX_VALUE, 2**53-2, -0x080000000, 1, 0.000000000000001, -1/0, 0x0ffffffff, 1/0, -Number.MIN_VALUE, -0x080000001, 42, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-168297596*/count=698; tryItOut("mathy5 = (function(x, y) { return mathy4(Math.fround(Math.min(Math.fround(( ~ ((y > x) | 0))), Math.fround(( + Math.fround(x))))), Math.tan(( ! ((( + (( + -0) ? ( + Math.atan(((((x | 0) <= (y | 0)) | 0) >>> 0))) : ( + Math.atan2(-0x080000000, ((Math.fround(x) ^ (x >>> 0)) | 0))))) >= (( + x) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [2**53+2, 1.7976931348623157e308, -(2**53+2), -0x080000001, -1/0, 42, Math.PI, Number.MAX_VALUE, 0x07fffffff, 2**53-2, -0x07fffffff, -(2**53), -0x0ffffffff, Number.MIN_VALUE, 1, -Number.MIN_VALUE, -0x100000001, 0, 0x0ffffffff, 0x100000000, 2**53, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, 0x080000000, 0x080000001, 1/0, -0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=699; tryItOut("\"use strict\"; /*iii*/this.p2 + '';function NaN(y)\"-7\"m2 = new Map;m1.has(g2);/*hhh*/function awgpnk(){print(x);}");
/*fuzzSeed-168297596*/count=700; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min(Math.fround((( ~ Math.fround(Math.abs(( + (2**53-2 != ( + x)))))) / ( + ((( ! x) | 0) ? ( ! y) : x)))), (( + Math.hypot(( + Math.log(Math.atan(Math.min(y, x)))), Math.fround(Math.hypot(( + (( + ( + Math.imul((1 | 0), ( + y)))) , (y >>> 0))), (( - (Math.log10(y) >>> 0)) | 0))))) >>> 0)); }); testMathyFunction(mathy0, [(new Number(0)), null, /0/, '\\0', -0, ({valueOf:function(){return '0';}}), [0], 0.1, ({valueOf:function(){return 0;}}), true, '', [], objectEmulatingUndefined(), '0', ({toString:function(){return '0';}}), (new String('')), undefined, 1, 0, (new Number(-0)), (new Boolean(false)), (new Boolean(true)), '/0/', (function(){return 0;}), NaN, false]); ");
/*fuzzSeed-168297596*/count=701; tryItOut("m1.has(h0);");
/*fuzzSeed-168297596*/count=702; tryItOut("\"use strict\"; i1.next();");
/*fuzzSeed-168297596*/count=703; tryItOut("e2 + '';");
/*fuzzSeed-168297596*/count=704; tryItOut("\"use strict\"; o2.g1.offThreadCompileScript(\"m2 + '';\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 5 == 1), noScriptRval: (4277), sourceIsLazy: (x % 2 == 1), catchTermination: false }));");
/*fuzzSeed-168297596*/count=705; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.ceil(Math.pow(Math.expm1((Math.fround((Math.max(x, Number.MAX_SAFE_INTEGER) ? (Math.fround((42 << Math.fround(y))) == y) : ( + mathy0(( + x), Math.fround(x))))) >>> 0)), ( + x)))); }); testMathyFunction(mathy1, [Math.PI, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -1/0, 0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, 0x100000001, -0x080000001, -0x07fffffff, 2**53, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, -(2**53-2), 2**53-2, Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, 0x080000001, -0, 0x080000000, -0x100000001, -(2**53), 2**53+2, Number.MIN_VALUE, 0/0, -0x100000000, 0x07fffffff]); ");
/*fuzzSeed-168297596*/count=706; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (((Math.hypot(( + Math.min(( + (mathy3(Math.pow(2**53+2, 0x07fffffff), (Math.pow(1.7976931348623157e308, Math.hypot(-0x100000000, (Math.atanh((y | 0)) | 0))) >>> 0)) >>> 0)), ( + Math.fround(( + Math.fround((Math.log((x >>> 0)) >>> 0))))))), (((x >>> 0) ? Math.fround(mathy4(Math.atan2(x, x), (Math.max(x, y) >>> 0))) : Math.asin((Math.sign(Math.fround(y)) | 0))) | 0)) | 0) >>> 0) | ((mathy3(( + ( ! ((Math.sqrt((-0 >>> 0)) >>> 0) | 0))), (-0 >= ((y | 0) ? y : ( - (Number.MAX_SAFE_INTEGER >>> 0))))) < Math.fround(((0x07fffffff <= ( + ((y >>> 0) != ( + (((x | 0) || (x | 0)) | 0))))) >> ( + x)))) | 0)); }); ");
/*fuzzSeed-168297596*/count=707; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.log((( + ( + ( + (y & Math.pow(( + (( + Math.tan(( + x))) >> ( + mathy0(x, y)))), ((( + (x ^ Math.imul(Math.fround(0x100000001), y))) ? ( + x) : ( + y)) >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[ '' , x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), objectEmulatingUndefined(),  '' , new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , objectEmulatingUndefined(), -Number.MAX_VALUE, -Number.MAX_VALUE, x,  '' , -Number.MAX_VALUE, objectEmulatingUndefined(),  '' , new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , -Number.MAX_VALUE,  '' , x, objectEmulatingUndefined(),  '' , objectEmulatingUndefined(), x, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), -Number.MAX_VALUE, -Number.MAX_VALUE, objectEmulatingUndefined(),  '' ,  '' , -Number.MAX_VALUE,  '' ,  '' , -Number.MAX_VALUE, x, objectEmulatingUndefined(), -Number.MAX_VALUE, new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true),  '' , -Number.MAX_VALUE, objectEmulatingUndefined(), new Boolean(true), -Number.MAX_VALUE, new Boolean(true), new Boolean(true),  '' , -Number.MAX_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, -Number.MAX_VALUE, -Number.MAX_VALUE, new Boolean(true), -Number.MAX_VALUE, objectEmulatingUndefined(),  '' , -Number.MAX_VALUE, new Boolean(true),  '' , -Number.MAX_VALUE, -Number.MAX_VALUE, objectEmulatingUndefined(), new Boolean(true), new Boolean(true), -Number.MAX_VALUE,  '' , -Number.MAX_VALUE,  '' , -Number.MAX_VALUE,  '' , x, new Boolean(true), objectEmulatingUndefined(), x, new Boolean(true), -Number.MAX_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), -Number.MAX_VALUE, x, -Number.MAX_VALUE,  '' , objectEmulatingUndefined()]); ");
/*fuzzSeed-168297596*/count=708; tryItOut("\"use strict\"; /*hhh*/function dljnqy(NaN = (b = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function shapeyConstructor(jtgfsu){if (jtgfsu) Object.freeze(jtgfsu);Object.preventExtensions(jtgfsu);return jtgfsu; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: (/(?!.{1,3})/i).apply, delete: function() { return true; }, fix: function() { throw 3; }, has: function(name) { return name in x; }, hasOwn: String.prototype.link, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return Object.keys(x); }, }; })(true), new Object(x = Proxy.create(({/*TOODEEP*/})([z1]), -13))))){Array.prototype.reverse.call(a1, h1);}dljnqy((\"\\u1DB0\" >>>= (void options('strict'))));");
/*fuzzSeed-168297596*/count=709; tryItOut("\"use strict\"; t2.set(a1,  '' );\no2 = {};\n");
/*fuzzSeed-168297596*/count=710; tryItOut("/*RXUB*/var r = /((\\1))|(?=[^]+\\w)|\\xc9+|(?!${262145}|[\u7f22]{0})\\B|\\b{32768,}/gyi; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-168297596*/count=711; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 42, 0x100000001, 0x080000001, -0x100000000, 2**53+2, -0x100000001, -0x0ffffffff, -0x080000000, -0x080000001, 1.7976931348623157e308, -(2**53), -Number.MAX_VALUE, 2**53, -0, 0, 0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 1, Math.PI, Number.MAX_VALUE, 0/0, 0x07fffffff, Number.MIN_VALUE, 1/0, -1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=712; tryItOut("for (var p in e1) { try { e2.delete(p1); } catch(e0) { } selectforgc(o1); }");
/*fuzzSeed-168297596*/count=713; tryItOut("\"use strict\"; a0.pop(p1, g2);function x(...eval) { return y([z1])+=delete eval.window } /*RXUB*/var r = /((\\d|\ub5fb*?){2}){2}/gm; var s = {} = x; print(uneval(s.match(r))); ");
/*fuzzSeed-168297596*/count=714; tryItOut("mathy1 = (function(x, y) { return (( ~ (mathy0(( + Math.imul(( + (((mathy0((-0x07fffffff | 0), (Math.hypot((y | 0), y) | 0)) | 0) | 0) ? (Math.min(x, ( + Math.fround(( - Math.fround((( - x) >>> 0)))))) | 0) : x)), ( + (x ** ( + (((-Number.MAX_SAFE_INTEGER >>> 0) >= ( + y)) >>> 0)))))), ( ! 0x100000000)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x080000001, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 1/0, 0x080000000, -(2**53-2), 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, 42, -0x100000000, 0x100000000, Math.PI, Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 1, -0, -0x07fffffff, -1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, 0x100000001, 2**53-2]); ");
/*fuzzSeed-168297596*/count=715; tryItOut("\"use strict\"; t1.set(t0, 12);");
/*fuzzSeed-168297596*/count=716; tryItOut("const jfvndk;print(x);");
/*fuzzSeed-168297596*/count=717; tryItOut("\"use strict\"; for([z, y] = (x) = 3 in Error.prototype) ( \"\" );");
/*fuzzSeed-168297596*/count=718; tryItOut("var NaN;h1 = {};");
/*fuzzSeed-168297596*/count=719; tryItOut("var c;throw \"\\u2D33\";function x(y)\"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i3 = ((((1))|0) > (((i0)+((-1.25)))|0));\n    i3 = ((((-0x8000000)) ^ ((imul((i1), (!(i1)))|0) % (((-4.835703278458517e+24))))) != (abs((((i3)+(i2)) ^ ((i0))))|0));\n    {\n      switch ((((((65.0)))-(i1)) >> ((1)))) {\n      }\n    }\n    {\n      i3 = ((i3) ? (i3) : ((1.5474250491067253e+26) == (-((-1.888946593147858e+22)))));\n    }\n    i3 = (i2);\n    i1 = ((((((0xda6fdc83)+(0xea868c1e)-(0x2b9facd6)) ^ (((abs((0x7d614e86))|0)))) / (((i1)) ^ (-(i1))))>>>(((i1) ? (i1) : (1)))) >= (((i0)+((((+abs(((549755813889.0))))) % ((-3.0))) != (1.25)))>>>((i2)-(i1))));\n    {\n      i2 = ((0xbdba6ed1));\n    }\n    return +((Float32ArrayView[1]));\n  }\n  return f;Array.prototype.reverse.apply(a0, []);");
/*fuzzSeed-168297596*/count=720; tryItOut("\"use strict\"; const e = -Number.MIN_VALUE;/*MXX1*/o0 = this.g1.Boolean.prototype\n");
/*fuzzSeed-168297596*/count=721; tryItOut("\"use strict\"; let v1 = g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-168297596*/count=722; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = ({x: {y, x}, c, window, x: [, ], c: \u3056, \u000cd: [{ , eval: b}]} = (void shapeOf(window ? [,,z1] : x))); var s = \"\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=723; tryItOut("mathy3 = (function(x, y) { return ( + ( ~ ( + (Math.log1p((Math.atan2(Math.fround(( - Math.fround(Number.MAX_SAFE_INTEGER))), mathy0(y, Math.min(( + ((-(2**53-2) > Math.fround(x)) | 0)), y))) | 0)) | 0)))); }); testMathyFunction(mathy3, [0x080000000, 0.000000000000001, 0x07fffffff, 0x100000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, Number.MIN_VALUE, 0/0, -1/0, -0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, 1, -0x080000000, 1.7976931348623157e308, 42, 2**53+2, -0, 0x080000001, 2**53-2, -Number.MIN_VALUE, -(2**53+2), 2**53, -0x07fffffff, 0, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=724; tryItOut("g2.b2.toString = (function() { h0.fix = f2; return t2; });");
/*fuzzSeed-168297596*/count=725; tryItOut("i2.send(o0);");
/*fuzzSeed-168297596*/count=726; tryItOut("\"use strict\"; /*infloop*/M:for(this.zzz.zzz in  /x/g ) ;");
/*fuzzSeed-168297596*/count=727; tryItOut("Object.defineProperty(this, \"v1\", { configurable:  \"\" , enumerable: (x % 11 != 5),  get: function() {  return evalcx(\"/./m\", g1); } });");
/*fuzzSeed-168297596*/count=728; tryItOut("x.message;");
/*fuzzSeed-168297596*/count=729; tryItOut("a2.shift();");
/*fuzzSeed-168297596*/count=730; tryItOut("var mqskbk = new SharedArrayBuffer(16); var mqskbk_0 = new Float64Array(mqskbk); mqskbk_0[0] = 850971047; var mqskbk_1 = new Uint8ClampedArray(mqskbk); mqskbk_1[0] = -25; var mqskbk_2 = new Float32Array(mqskbk); print(mqskbk_2[0]); var mqskbk_3 = new Uint16Array(mqskbk); print(mqskbk_3[0]); var mqskbk_4 = new Int8Array(mqskbk); var mqskbk_5 = new Int8Array(mqskbk); print(mqskbk_5[0]); mqskbk_5[0] = -1311728740.5; v2 = g1.eval(\"window\");o1.f2 = (function(j) { f0(j); });m1.get(a0);(undefined);print(mqskbk_0[7]);");
/*fuzzSeed-168297596*/count=731; tryItOut("for (var p in b2) { try { v2 + o0; } catch(e0) { } try { Array.prototype.sort.call(a0, this.f1); } catch(e1) { } try { g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (d)--, noScriptRval: false, sourceIsLazy: x, catchTermination: true })); } catch(e2) { } m1.toString = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (((imul((0x5baf891d), (i1))|0)) ? (1.0) : (d0));\n    {\n      (Uint8ArrayView[(((((0xfa1ca238)) >> ((0x6d32922)+(-0x8000000))))) >> 0]) = ((i1)-(undefined));\n    }\n    {\n      (Uint32ArrayView[((0xf842b178)) >> 2]) = ((0xfdbcfaeb)-((4194305.0) == (-((+(1.0/0.0))))));\n    }\n    {\n      i1 = (i1);\n    }\n    (Float64ArrayView[1]) = ((-1073741825.0));\n    (Float32ArrayView[((0x37e7a99) / ((((((0xe95aa697))|0))) >> ((Uint32ArrayView[0])))) >> 2]) = ((d0));\n    i1 = (0x2549c506);\n    d0 = (+(1.0/0.0));\n    {\n      (Int32ArrayView[((i1)) >> 2]) = (((0xd33cdc22)));\n    }\n    return ((0x44dac*((((((0x6ada2429))|0) != (~((0xfec37923)+(i1))))-(i1)-(0x184a9709)))))|0;\n  }\n  return f; }); }");
/*fuzzSeed-168297596*/count=732; tryItOut("/*RXUB*/var r = /(($))+?/m; var s = \"7\\u5a20\\n\\uec447\\u5a20\\n\\uec44\"; print(r.test(s)); ");
/*fuzzSeed-168297596*/count=733; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((((( ! ( - ((0x080000001 | (x | 0)) | 0))) >>> 0) >>> 0) == (Math.cbrt(Math.max((((Math.imul(( + (mathy2(((( ! y) | 0) >>> 0), (x >>> 0)) >>> 0)), Math.min(( + (Math.fround(x) & ( + x))), -0x080000000)) | 0) / Math.atan2(y, ( + Math.fround((x ** x))))) | 0), (( + mathy1(( + ( ! 0x080000000)), Math.pow((y ? x : (x >>> 0)), y))) >>> x))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=734; tryItOut("let eval, x, y;yield;");
/*fuzzSeed-168297596*/count=735; tryItOut("switch(/*MARR*/[undefined, objectEmulatingUndefined(), undefined, NaN, NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, undefined, undefined, undefined, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), undefined, NaN, objectEmulatingUndefined(), undefined, NaN, objectEmulatingUndefined(), NaN, undefined, objectEmulatingUndefined(), undefined, objectEmulatingUndefined()].sort((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete:  \"\" , fix: function() { return []; }, has: function() { return false; }, hasOwn: (null).bind(), get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; }))(timeout(1800))) { default: case 1: v2 = Array.prototype.every.call(a1, (function(j) { if (j) { try { /*ADP-2*/Object.defineProperty(a2, ({valueOf: function() { print(x);return 0; }}), { configurable: false, enumerable: (x % 10 == 9), get: (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -295147905179352830000.0;\n    return ((-0x7b4a7*(0xd29e6986)))|0;\n  }\n  return f; })(this, {ff: Object.prototype.valueOf}, new SharedArrayBuffer(4096)), set: f2 }); } catch(e0) { } try { i1.__proto__ = t2; } catch(e1) { } try { e2.has(g0.b1); } catch(e2) { } Array.prototype.splice.call(a2, NaN, 13); } else { o0.__iterator__ = (function mcc_() { var lbwlky = 0; return function() { ++lbwlky; if (/*ICCD*/lbwlky % 7 == 3) { dumpln('hit!'); try { t2.set(t1, 0); } catch(e0) { } print(s0); } else { dumpln('miss!'); try { g0.o1.v2 = a1.length; } catch(e0) { } try { f2.valueOf = (function() { try { s0 += 'x'; } catch(e0) { } m1.get(f0); return g1.g1; }); } catch(e1) { } Array.prototype.push.call(a2, t2, g2.a0, p2, h1, e1); } };})(); } })); }");
/*fuzzSeed-168297596*/count=736; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (mathy0(( - (((x | 0) ? x : (Math.asin(x) | 0)) | 0)), (( ~ (Math.fround(Math.pow(( ! y), Math.fround((mathy0((x >>> 0), (Math.asinh(y) >>> 0)) >>> 0)))) | 0)) | 0)) & (Math.pow(Math.fround((( + y) & Math.fround(Math.max(((x | 0) ? 1 : Math.asin(y)), x)))), Math.fround(Math.log2(( + Math.fround(((( ~ 0x080000000) ? -Number.MIN_VALUE : x) && Math.fround(mathy0(x, (Math.cosh(Math.fround(0/0)) >>> 0))))))))) | 0)); }); testMathyFunction(mathy1, [-0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, Math.PI, 2**53-2, 1/0, 1, -0x100000000, 0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, 0.000000000000001, 0, -Number.MAX_VALUE, -(2**53), 1.7976931348623157e308, 42, -0, -1/0, 0x100000000, 0x080000000, -0x0ffffffff, -0x100000001, -0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -0x080000000, 0x07fffffff, Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-168297596*/count=737; tryItOut("let v2 = new Number(Infinity);");
/*fuzzSeed-168297596*/count=738; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( + Math.max(Math.fround(Math.expm1((mathy0(Math.min(x, y), y) | 0))), Math.imul(( + ( - (y | 0))), Math.fround(( + (x - Math.atan2(Number.MAX_VALUE, y)))))))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 42, 1/0, -1/0, 0x07fffffff, 0x0ffffffff, -(2**53+2), 0x100000000, -(2**53-2), 0/0, 0, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -0x0ffffffff, 0x080000000, 0.000000000000001, 2**53-2, Number.MAX_VALUE, Math.PI, -0x100000001, 0x100000001, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_VALUE, 2**53, -0, 0x080000001, 1]); ");
/*fuzzSeed-168297596*/count=739; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.atan2((( + Math.log1p(( + x))) - mathy1(( + ( ! (Math.fround(Math.atan2(Math.fround(y), Math.fround(Math.max(0x07fffffff, x)))) >>> 0))), (( + Math.atan2(Math.fround((0 , y)), ( ! (Math.atan2(Math.expm1(x), y) | 0)))) | 0))), (Math.trunc(( + Math.trunc(((x !== Math.fround(2**53-2)) | 0)))) | 0)); }); testMathyFunction(mathy5, [-(2**53), Math.PI, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 2**53, 0x07fffffff, 0/0, -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, -1/0, 0x0ffffffff, 0x100000000, 1, Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -0, -0x100000000, 2**53-2, 2**53+2]); ");
/*fuzzSeed-168297596*/count=740; tryItOut("a0 = arguments;");
/*fuzzSeed-168297596*/count=741; tryItOut("for (var p in e0) { try { i0 = new Iterator(g2); } catch(e0) { } try { v0.__proto__ = f0; } catch(e1) { } p2.toSource = f2; }");
/*fuzzSeed-168297596*/count=742; tryItOut("/*infloop*/for(x = false; Math.hypot((Math.hypot(( + (Math.hypot(Math.atan2((( + x) , (x >>> 0)), x), (( + ( ~ x)) | 0)) | 0)), ( + x)) & (Math.atan((((x | 0) ** Math.fround(Math.ceil(x))) | 0)) | 0)), Math.fround(Math.atanh(((( + (((x >>> 0) == (x >>> 0)) >>> 0)) ? x : (x & x)) >>> 0)))); x) /* no regression tests found */");
/*fuzzSeed-168297596*/count=743; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.sinh((Math.max((( + (( + (((x >>> 0) % (Math.fround(( + Math.fround(x))) >>> 0)) >>> 0)) >= ( + (y >> ((((y >>> 0) >> (-0x080000000 >>> 0)) >>> 0) | 0))))) | 0), (Math.fround(Math.pow(Math.fround(Math.PI), Math.fround(Math.max(x, x)))) | 0)) | 0)) >> Math.hypot((mathy1(Math.fround((((0x080000001 >>> 0) ? ((((y >>> 0) === (x >>> 0)) >>> 0) | 0) : (Math.pow(( + ( + (Math.fround(x) <= ( + y)))), (2**53+2 >>> 0)) >>> 0)) >>> 0)), Math.fround((( + Math.acos(y)) > ( + mathy1(Math.fround(( ! x)), Math.PI))))) >>> 0), Math.fround(( ~ (( + ((x >>> 0) + ((( + y) >>> 0) >>> 0))) >>> 0))))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, Math.PI, 0, 0x080000000, -0, -0x0ffffffff, 42, -Number.MIN_VALUE, -(2**53-2), -0x100000001, 2**53-2, -1/0, 1, 0x100000000, Number.MIN_VALUE, 0x080000001, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, -0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -(2**53), -0x080000001, -0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-168297596*/count=744; tryItOut("\"use asm\"; x;");
/*fuzzSeed-168297596*/count=745; tryItOut("\"use strict\"; for (var v of v2) { try { f2(g0.p2); } catch(e0) { } try { neuter(b1, \"same-data\"); } catch(e1) { } v2 = t2.BYTES_PER_ELEMENT; }");
/*fuzzSeed-168297596*/count=746; tryItOut("testMathyFunction(mathy1, [-Number.MAX_VALUE, 2**53, 0x080000001, 1, 1.7976931348623157e308, 0x0ffffffff, -0x100000001, -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -(2**53-2), 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 0/0, 0.000000000000001, -0x0ffffffff, 42, 0x100000001, -(2**53), 0, 2**53+2, 1/0, -0x080000001, Math.PI, Number.MIN_VALUE, -0, 0x100000000, 0x07fffffff]); ");
/*fuzzSeed-168297596*/count=747; tryItOut("\"use strict\"; this.t2 = new Uint16Array(b0, 14, ({valueOf: function() { /* no regression tests found */return 10; }}));/*tLoop*/for (let d of /*MARR*/[x, ({x:3}), -8,  \"\" , ({x:3}), x,  \"\" , (1/0), -8,  \"\" , ({x:3}),  \"\" , x, ({x:3}), (1/0), ({x:3}), -8, -8, ({x:3}), (1/0), -8, ({x:3}), (1/0), x, ({x:3}), ({x:3}), -8, x,  \"\" ,  \"\" , -8, (1/0), x, x,  \"\" ,  \"\" , -8,  \"\" ,  \"\" , ({x:3}), -8,  \"\" , (1/0),  \"\" ]) { print(length); }");
/*fuzzSeed-168297596*/count=748; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((( - (Math.cosh((1/0 >>> 0)) >>> 0)) | 0) * (Math.clz32(( + (( + (( + (Math.hypot((y | 0), 1.7976931348623157e308) | 0)) << ( + x))) === Math.min(Number.MIN_VALUE, x)))) | 0)) | 0); }); testMathyFunction(mathy1, [-(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -0x080000001, 1, 0, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, -0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -(2**53+2), 0x100000001, 42, -1/0, 2**53+2, Math.PI, -0x080000000, 2**53, 0.000000000000001, 1.7976931348623157e308, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, 0x100000000, 1/0, -(2**53), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=749; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x100000000, -0, Math.PI, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 0.000000000000001, 0x080000000, -(2**53-2), -0x080000000, -0x080000001, 0x080000001, -(2**53), 42, -Number.MIN_VALUE, Number.MAX_VALUE, 1, -0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, -Number.MAX_VALUE, 2**53, 2**53-2, -0x0ffffffff, 0, -(2**53+2), 1.7976931348623157e308, -0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 0/0]); ");
/*fuzzSeed-168297596*/count=750; tryItOut("\"use strict\"; /*bLoop*/for (anthxp = 0; anthxp < 87; new this(null, x), ++anthxp) { if (anthxp % 25 == 11) { /*bLoop*/for (let mkhvtn = 0; mkhvtn < 0; ++mkhvtn) { if (mkhvtn % 3 == 1) { print(x); } else { yield -27; }  }  } else { with(Math.pow((4277), 19))print(x); }  } ");
/*fuzzSeed-168297596*/count=751; tryItOut("mathy2 = (function(x, y) { return Math.expm1(Math.fround(((Math.imul((( + Math.atan2(y, ( + ( + ( - y))))) >>> 0), y) >>> 0) + Math.fround((Math.fround(Math.tanh((Math.max((y | 0), (-0x100000000 | 0)) | 0))) ? Math.fround((((y | 0) < ( - mathy1(-0x07fffffff, y))) | 0)) : ( + (( ! y) * x))))))); }); testMathyFunction(mathy2, [0x100000000, 0/0, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), 2**53+2, Math.PI, 0x080000001, -(2**53), -0x07fffffff, 2**53, 0x080000000, 2**53-2, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, -0x100000000, -0, 0x0ffffffff, -0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, 0, 1/0, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=752; tryItOut("(void schedulegc(o1.g1));");
/*fuzzSeed-168297596*/count=753; tryItOut("testMathyFunction(mathy4, /*MARR*/[\"\\u718C\", delete x.y >>= x.watch(\"sin\", runOffThreadScript), -0x080000001, -0x080000001, -0x080000001, -0x080000001, delete x.y >>= x.watch(\"sin\", runOffThreadScript), \"\\u718C\", \"\\u718C\", \"\\u718C\", -0x080000001, delete x.y >>= x.watch(\"sin\", runOffThreadScript), \"\\u718C\", -0x080000001, delete x.y >>= x.watch(\"sin\", runOffThreadScript), delete x.y >>= x.watch(\"sin\", runOffThreadScript), delete x.y >>= x.watch(\"sin\", runOffThreadScript), delete x.y >>= x.watch(\"sin\", runOffThreadScript), -0x080000001, delete x.y >>= x.watch(\"sin\", runOffThreadScript), \"\\u718C\", -0x080000001, \"\\u718C\", delete x.y >>= x.watch(\"sin\", runOffThreadScript), -0x080000001, -0x080000001, delete x.y >>= x.watch(\"sin\", runOffThreadScript), -0x080000001, delete x.y >>= x.watch(\"sin\", runOffThreadScript), -0x080000001]); ");
/*fuzzSeed-168297596*/count=754; tryItOut("testMathyFunction(mathy1, /*MARR*/[new Number(1),  /x/ , new Number(1), new Number(1),  /x/ , new Boolean(false),  /x/ , new Boolean(false),  /x/ , new Number(1), new Number(1), new Number(1.5), new Number(1),  /x/ , new Number(1), new Number(1.5),  /x/ ]); ");
/*fuzzSeed-168297596*/count=755; tryItOut("testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, Math.PI, -0x080000001, -0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, 42, -Number.MIN_VALUE, -(2**53-2), 0x100000000, 0x0ffffffff, 0x080000000, -(2**53), 0, 2**53-2, Number.MAX_SAFE_INTEGER, -0, 1, -0x080000000, 0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000001, -1/0, 2**53, 1/0, 0x100000001, -0x07fffffff, 0.000000000000001, Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-168297596*/count=756; tryItOut("v0 = g0.eval(\"{ void 0; bailAfter(5); }\");");
/*fuzzSeed-168297596*/count=757; tryItOut("testMathyFunction(mathy0, [0/0, 0, -0, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 1, Math.PI, -(2**53), 2**53-2, -(2**53+2), Number.MAX_VALUE, -1/0, 0x080000000, 0x100000001, 2**53, -0x07fffffff, -(2**53-2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, -0x100000001, 0x0ffffffff, -Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0x080000001]); ");
/*fuzzSeed-168297596*/count=758; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot((Math.imul(1/0, Math.log2(y)) && Math.fround(Math.ceil((((( + Math.pow(( + mathy0(-Number.MIN_VALUE, x)), Math.fround(y))) | 0) >= ( + ( + ( + 1/0)))) | 0)))), mathy1((Math.min((Math.fround((Math.fround(( + ( ~ ( + x)))) , Math.fround(y))) | 0), ((( - ((2**53 >= x) >>> 0)) >>> 0) | 0)) | 0), .../*FARR*/[[ /x/g ], let (b) this])); }); ");
/*fuzzSeed-168297596*/count=759; tryItOut("this.a0.splice(4, ({valueOf: function() { v2 = 4.2;return 15; }}), h1, p1, i0, e0, p0);");
/*fuzzSeed-168297596*/count=760; tryItOut("mathy2 = (function(x, y) { return (Math.fround((Math.fround(mathy1(Math.min(x, y), (( ! ((false % -Number.MIN_VALUE) >>> 0)) >>> 0))) != (Math.fround((y !== y)) , ((Math.hypot(x, x) , ((mathy1(( + ( + (y | 0))), ( + y)) >>> 0) >>> 0)) >>> 0)))) ? (Math.tanh((Number.MAX_SAFE_INTEGER , x)) | 0) : (Math.cosh(((mathy1((Math.fround((Math.fround((((y >>> 0) ? (Math.atan2(Math.clz32(var r0 = x % y; var r1 = y / 6; var r2 = 6 * r0; var r3 = r2 | r1; var r4 = r0 ^ x; var r5 = r3 - 9; var r6 = x % 9; x = r6 | 3; var r7 = 4 * 1; var r8 = r4 * 2; var r9 = x + r8; var r10 = 0 * 1; ), -0x080000000) >>> 0) : (x >>> 0)) >>> 0)) ? ( + -Number.MIN_VALUE) : Math.fround(( - ( + Math.hypot(( + Number.MIN_SAFE_INTEGER), Math.fround(x))))))) >>> 0), (0x100000001 >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy2, [2**53, Number.MIN_VALUE, 0.000000000000001, 2**53-2, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 0x080000001, 0x080000000, -(2**53-2), 0x0ffffffff, -0x100000000, -0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, 0x100000001, 0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, 2**53+2, 42, -0x080000000, 1/0, 0/0, 0, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-168297596*/count=761; tryItOut("s2.__proto__ = g0;");
/*fuzzSeed-168297596*/count=762; tryItOut("m2.has(i2)\n");
/*fuzzSeed-168297596*/count=763; tryItOut("e0 = new Set(e2);");
/*fuzzSeed-168297596*/count=764; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-168297596*/count=765; tryItOut("/*ODP-2*/Object.defineProperty(o1.g1.a1, \"stringify\", { configurable: false, enumerable: (x % 5 != 2), get: (function() { try { (4277) = a0[v2]; } catch(e0) { } h1.enumerate = (function() { for (var j=0;j<17;++j) { f2(j%3==1); } }); throw f2; }), set: (function(j) { if (j) { try { Array.prototype.sort.call(a2, (function() { try { v1 = a2.length; } catch(e0) { } try { s0 = s2.charAt((4277)); } catch(e1) { } try { v2 = a1.length; } catch(e2) { } g0.o1.v1 = Object.prototype.isPrototypeOf.call(g0.m2, b2); return g0; })); } catch(e0) { } try { /*RXUB*/var r = r2; var s = \"0\"; print(s.match(r)); print(r.lastIndex);  } catch(e1) { } a1[Math.min(0, -5)]; } else { try { v2 = g0.runOffThreadScript(); } catch(e0) { } f1.toString = (function() { for (var j=0;j<6;++j) { f0(j%2==1); } }); } }) });");
/*fuzzSeed-168297596*/count=766; tryItOut("\"use strict\"; v1 = 0;/*MXX1*/o0 = g0.RegExp.prototype.exec;function x(x, \u3056, ...z) { \"use strict\"; yield  /x/  } /*MXX1*/o2 = g0.OSRExit.length;");
/*fuzzSeed-168297596*/count=767; tryItOut("a0.shift(g2.t2);");
/*fuzzSeed-168297596*/count=768; tryItOut("mathy5 = (function(x, y) { return ((( ~ (Math.sign((Math.pow(Math.fround(Math.sign((( ! y) | 0))), (( + ( ~ ( + x))) | 0)) | 0)) >>> 0)) >>> 0) + Math.sin(Math.fround(mathy0(Math.fround(Math.min(x, Math.imul(Math.fround(( + Math.tan(y))), y))), ( + y))))); }); testMathyFunction(mathy5, [Math.PI, -0x07fffffff, -0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 0x080000000, 0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0x100000000, 42, 1.7976931348623157e308, -0x0ffffffff, -0, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, -0x100000001, 2**53, -0x080000001, -(2**53), -(2**53+2), 0, -0x100000000, 0/0, Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-168297596*/count=769; tryItOut("{ void 0; setIonCheckGraphCoherency(false); } v1 = o0.t2.length;");
/*fuzzSeed-168297596*/count=770; tryItOut("\"use strict\"; f2 = Proxy.createFunction(h0, f0, f1);");
/*fuzzSeed-168297596*/count=771; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.sqrt(( + ( + ( - ( + (( + Math.imul(( + ( + (( + y) ? ((mathy2(x, Math.fround((Math.cosh((Number.MAX_VALUE | 0)) | 0))) | 0) | 0) : Math.fround(x)))), Math.round(Math.round(x)))) || Math.pow(Math.fround(Math.hypot((Number.MAX_SAFE_INTEGER >>> 0), mathy3(y, -0x100000000))), Math.fround(x)))))))) | 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 0, 42, -(2**53), 1, -Number.MIN_VALUE, -0x0ffffffff, -0x080000001, 2**53, Number.MAX_VALUE, 2**53+2, 0x080000000, -0x080000000, 0x100000001, Math.PI, 2**53-2, -0x100000001, -(2**53-2), -0x07fffffff, -1/0, 0x0ffffffff, Number.MIN_VALUE, 1/0, -0, -0x100000000, 0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-168297596*/count=772; tryItOut("mathy5 = (function(x, y) { return ( ! mathy3((Math.fround(Math.min(Math.fround(((x / (Math.min(x, ( + ( ! (x | 0)))) ? y : Math.atan2((y | 0), y))) >>> 0)), Math.fround(( + ((Math.fround(( + ( ~ y))) | 0) > ( + Math.cbrt((mathy2(-0x0ffffffff, x) || ( ~ -Number.MAX_SAFE_INTEGER))))))))) | 0), (( + Math.log10((Math.hypot(Math.fround((Math.fround(Math.min(2**53, (x >>> 0))) << Math.fround(x))), (Math.min(x, (x | 0)) >>> 0)) | 0))) | 0))); }); testMathyFunction(mathy5, [0, -0x100000001, 2**53-2, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, 2**53, -0x100000000, -Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, 0x080000000, 0x07fffffff, -0x080000000, -(2**53-2), 2**53+2, -(2**53+2), -0, 0/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 0x080000001, Math.PI, 0x0ffffffff, 42, -0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=773; tryItOut("t1[({valueOf: function() { (void version(185));return 9; }})] = new (Object.prototype.__defineGetter__)(w).__proto__--;");
/*fuzzSeed-168297596*/count=774; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=775; tryItOut("");
/*fuzzSeed-168297596*/count=776; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.round(Math.max(( + ((( ! y) >= (( + ((y !== x) >>> 0)) | 0)) | 0)), Math.min(( + (Math.pow((x >>> 0), (Math.sign((Math.hypot(Math.fround(y), (x | 0)) >>> 0)) >>> 0)) >>> 0)), ( + ( ! y))))); }); testMathyFunction(mathy0, [0x07fffffff, -0x0ffffffff, 2**53-2, -0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53), 0/0, -(2**53+2), 0x080000000, -0x100000000, 2**53, 0, 0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, 1/0, -0x080000000, 1.7976931348623157e308, -(2**53-2), 1, 0.000000000000001, -0x07fffffff, Math.PI, -1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=777; tryItOut("m1 = new Map;");
/*fuzzSeed-168297596*/count=778; tryItOut("v2 = evaluate(\"function f2(this.m0) x\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: e, noScriptRval: true, sourceIsLazy: false, catchTermination: (void shapeOf(x)) }));");
/*fuzzSeed-168297596*/count=779; tryItOut("\"use strict\"; m2.has(g0);");
/*fuzzSeed-168297596*/count=780; tryItOut("t2[v1] = this.__defineSetter__(\"w\", arguments.callee);");
/*fuzzSeed-168297596*/count=781; tryItOut("for (var p in p0) { h0 = ({getOwnPropertyDescriptor: function(name) { return m0; var desc = Object.getOwnPropertyDescriptor(g1.i0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g2.offThreadCompileScript(\"m2.set(p1, g1);\");; var desc = Object.getPropertyDescriptor(g1.i0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { print(uneval(h1));; Object.defineProperty(g1.i0, name, desc); }, getOwnPropertyNames: function() { v0 = this.g1.runOffThreadScript();; return Object.getOwnPropertyNames(g1.i0); }, delete: function(name) { t0.set(a0, 17);; return delete g1.i0[name]; }, fix: function() { b1 = Proxy.create(h2, this.o0.o1);; if (Object.isFrozen(g1.i0)) { return Object.getOwnProperties(g1.i0); } }, has: function(name) { f1(g0.h0);; return name in g1.i0; }, hasOwn: function(name) { throw o1; return Object.prototype.hasOwnProperty.call(g1.i0, name); }, get: function(receiver, name) { t1 + s0;; return g1.i0[name]; }, set: function(receiver, name, val) { a0.push(o0, i2);; g1.i0[name] = val; return true; }, iterate: function() { throw g2.v1; return (function() { for (var name in g1.i0) { yield name; } })(); }, enumerate: function() { s1 = Array.prototype.join.call(a2, s0, g0, v1, o1.o2);; var result = []; for (var name in g1.i0) { result.push(name); }; return result; }, keys: function() { return a1; return Object.keys(g1.i0); } }); }\nv1 = Object.prototype.isPrototypeOf.call(h1, i1);\n");
/*fuzzSeed-168297596*/count=782; tryItOut("mathy4 = (function(x, y) { return ((Math.fround((Math.max(Math.fround(( ! (y & (( - ( + y)) >>> 0)))), Math.fround(Math.atanh(Math.fround(y)))) + (((( ~ (Math.cosh((Math.exp((mathy0(1, y) | 0)) >>> 0)) >>> 0)) >>> 0) !== ( ! (Math.clz32(Math.fround(mathy3((((-0x07fffffff | 0) >>> (x | 0)) | 0), y))) >>> 0))) >>> 0))) >>> 0) + (Math.acos(( ~ -0)) ? ( + (Math.cos(((( + x) >> (Number.MIN_VALUE ? x : x)) | 0)) | Math.fround((( + Math.imul(Number.MAX_VALUE, y)) - mathy1(-0x07fffffff, ( + y)))))) : Math.fround(( + Math.atanh(( + Math.sinh(( ! x)))))))); }); ");
/*fuzzSeed-168297596*/count=783; tryItOut("Object.defineProperty(this, \"s0\", { configurable: (28).call(false, false), enumerable: (x % 56 == 53),  get: function() {  return new String(o0); } });");
/*fuzzSeed-168297596*/count=784; tryItOut("/*oLoop*/for (uyqbvp = 0; uyqbvp < 26; ++uyqbvp) { print(x); } ");
/*fuzzSeed-168297596*/count=785; tryItOut("f2.valueOf = (function() { b2.__iterator__ = f1; return s2; });function eval(window, x)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    {\n      (Float32ArrayView[4096]) = ((-137438953473.0));\n    }\n    return (((i1)))|0;\n  }\n  return f;p0 = Proxy.create(h2, g2);");
/*fuzzSeed-168297596*/count=786; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.pow(Math.asin(( + Math.round(( + (Math.hypot((Math.abs(x) >>> 0), (y >>> 0)) >>> 0))))), ((( + ( ~ y)) ? x : mathy0(x, ( + y))) + ( + (((y ** x) / (y , Math.exp(Math.max((y >>> 0), y)))) == x)))); }); testMathyFunction(mathy3, [2**53, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -0x100000000, 0/0, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -1/0, 0, -0, 0.000000000000001, 2**53+2, 1, 2**53-2, -0x100000001, -0x080000000, 0x080000000, -0x080000001, Math.PI, Number.MAX_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, -(2**53+2), -(2**53-2), 42]); ");
/*fuzzSeed-168297596*/count=787; tryItOut("mathy0 = (function(x, y) { return Math.min(Math.log10(Math.cbrt((Math.max((2**53+2 >>> 0), (( + y) , ( + Number.MIN_VALUE))) >>> 0))), ( + Math.round(( + ((Math.imul(Math.fround((x ? y : (Math.log(Math.fround(Math.atan2(y, y))) >>> 0))), Math.fround(Math.acosh((y | 0)))) >>> 0) || ( + ( ~ (( + Math.hypot(( + ( + ( ! y))), ( + ( ! ( + x))))) >>> 0)))))))); }); testMathyFunction(mathy0, [42, 1, -0x0ffffffff, 1/0, 0, Number.MIN_VALUE, -1/0, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 0x100000001, 0x100000000, -0, -(2**53+2), -(2**53), 1.7976931348623157e308, -0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, Math.PI, -0x080000000, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -0x100000001, 0x080000001, 0/0, -0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff]); ");
/*fuzzSeed-168297596*/count=788; tryItOut("\"use strict\"; this.t2[5];o0 = {};");
/*fuzzSeed-168297596*/count=789; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=790; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=791; tryItOut("\"use strict\"; var a = (Math.hypot(25, (({\u3056: (4277)}))));p0 + '';");
/*fuzzSeed-168297596*/count=792; tryItOut("for(let c in window) for(let b in []);for(let e of ((void shapeOf( \"\" )))) return;");
/*fuzzSeed-168297596*/count=793; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\nprint(x);    }\n    return +((d1));\n  }\n  return f; })(this, {ff: Math.trunc}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x080000000, 0x080000000, Number.MIN_VALUE, 1/0, -0x080000001, 2**53, 2**53+2, Math.PI, 0x100000000, 0.000000000000001, 0x100000001, -Number.MAX_VALUE, 0/0, 1, -(2**53+2), -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, 1.7976931348623157e308, 0, -0x100000001, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, 2**53-2, 42, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -(2**53)]); ");
/*fuzzSeed-168297596*/count=794; tryItOut("print(x);\nObject.defineProperty(g0, \"m1\", { configurable: true, enumerable: false,  get: function() {  return new Map; } });\n");
/*fuzzSeed-168297596*/count=795; tryItOut("\"use strict\"; Array.prototype.push.call(a2, s2, g2);function d() { return x } (Math\u000d);");
/*fuzzSeed-168297596*/count=796; tryItOut("testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 1, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, -(2**53), Math.PI, -(2**53-2), 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, 0x0ffffffff, -0x080000001, -0x100000000, 1.7976931348623157e308, 0/0, -1/0, -(2**53+2), -0, Number.MIN_VALUE, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 42, 1/0, -0x100000001, 0, -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=797; tryItOut("v1 = g0.eval(\"Object.defineProperty(this, \\\"v2\\\", { configurable: Object.defineProperty(x, \\\"bold\\\", ({value: -9})), enumerable: ({} = x ?  /x/  : 4),  get: function() {  return g1.eval(\\\"function f1(v0)  { \\\\\\\"use asm\\\\\\\"; yield w((4277)) = yield ((c)) = v0 } \\\"); } });\");");
/*fuzzSeed-168297596*/count=798; tryItOut("testMathyFunction(mathy3, [1/0, 2**53+2, -(2**53-2), 0x080000000, 0, -0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -0x080000001, 0x080000001, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, 0x100000001, -0x100000000, 2**53, -(2**53), 0.000000000000001, -1/0, Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, -0x07fffffff, 2**53-2, 0x100000000, 42, 0/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=799; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use asm\"; return ((Math.atan2(( + Math.trunc(mathy0((mathy0(( - -0x100000001), ( ! (y >>> 0))) | 0), (y | 0)))), Math.fround(Math.hypot(Math.fround(0x080000000), Math.fround(mathy1(x, (-Number.MIN_SAFE_INTEGER || -0x07fffffff)))))) | 0) - Math.atan2(Math.max(y, Math.tanh(x)), Math.atan2(Math.fround(mathy1(Math.asinh((1 | 0)), ( + Math.fround(((Math.min(x, 1/0) >>> 0) >>> 0))))), mathy1((Math.pow(x, x) >>> 0), y)))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -(2**53+2), -0, 2**53, -0x100000001, 42, Number.MIN_VALUE, 0x080000000, 0.000000000000001, 2**53+2, 0/0, 0, 0x07fffffff, -0x080000001, 0x100000001, Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, -0x100000000, 1, -Number.MAX_VALUE, -1/0, 0x080000001, -0x07fffffff, 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=800; tryItOut("\"use strict\"; var hydtuj = new SharedArrayBuffer(8); var hydtuj_0 = new Uint8ClampedArray(hydtuj); this.a0.shift(i2, i0, /(?:.{0})/, t2, m2, this.s1, t0, p1, b0, g1);");
/*fuzzSeed-168297596*/count=801; tryItOut("mathy0 = (function(x, y) { return ( + Math.sin(( + (( + (( + y) && ( + Math.cosh((y | 0))))) !== Math.log1p(Math.exp(x)))))); }); testMathyFunction(mathy0, /*MARR*/[(-1/0), (-1/0), (-1/0), function(){}, new String(''), new String(''), (-1/0), (-1/0), -0x100000001, function(){}, new String(''), -0x100000001, (-1/0), function(){}]); ");
/*fuzzSeed-168297596*/count=802; tryItOut("a2 = arguments;");
/*fuzzSeed-168297596*/count=803; tryItOut("testMathyFunction(mathy0, [0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, -(2**53-2), -(2**53+2), 0x080000001, 0/0, 42, -0, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 1, 0x100000000, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, -(2**53), 2**53+2, Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, -0x07fffffff, -0x100000000, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, -0x080000000, -1/0]); ");
/*fuzzSeed-168297596*/count=804; tryItOut("m0.set(a0, g0.e2);");
/*fuzzSeed-168297596*/count=805; tryItOut("/*vLoop*/for (hmfhgk = 0; hmfhgk < 65; ++hmfhgk) { const x = hmfhgk; selectforgc(o0); } ");
/*fuzzSeed-168297596*/count=806; tryItOut("f2 + '';");
/*fuzzSeed-168297596*/count=807; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((d1) == (+/*FFI*/ff(((4.0)), (((Int32ArrayView[((0x8fb92f07)*-0xb63cf) >> 2]))), ((-67108865.0)), ((d1)), (((-(0xfcc40886)) >> (((0xa198ef5) < (0x2d78e22e))))))));\n    return (((i0)-((4398046511105.0) > (70368744177665.0))))|0;\n  }\n  return f; })(this, {ff: Date.prototype.toDateString}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [(new Boolean(false)), '', [0], -0, 0, NaN, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (function(){return 0;}), (new String('')), false, (new Boolean(true)), true, [], '0', 0.1, /0/, 1, undefined, (new Number(-0)), ({valueOf:function(){return 0;}}), (new Number(0)), null, objectEmulatingUndefined(), '/0/', '\\0']); ");
/*fuzzSeed-168297596*/count=808; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + ((mathy0((Math.pow((((y | 0) / Math.asin(Math.expm1(( + y)))) | 0), ((x | 0) / (x / (mathy3((x | 0), (y | 0)) | 0)))) >>> 0), (mathy3((Math.fround(( ! Math.fround(Math.sign(Math.log1p(x))))) | 0), (Math.fround(((Math.max((-Number.MIN_VALUE >>> 0), (((x | 0) << y) >>> 0)) >>> 0) << y)) | 0)) | 0)) >>> 0) | 0)) | 0); }); ");
/*fuzzSeed-168297596*/count=809; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((( - (Math.tan((Math.min((Math.hypot(Math.fround(x), Math.fround(y)) >>> 0), (( ~ Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0)) | 0)) | 0) | (Math.abs(mathy0(( + Math.imul((x | 0), ( + y))), ( + Math.atan2((x >>> 0), 1)))) ? (((( ~ (y % x)) | 0) << ((mathy0((y >>> 0), (( ! ((x >>> 0) - x)) >>> 0)) >>> 0) | 0)) | 0) : (Math.asinh(Math.fround(Math.tan(Math.fround((((0.000000000000001 | 0) < (( + x) ? ( + x) : ( + Math.cosh(( + x))))) | 0))))) | 0))); }); testMathyFunction(mathy2, [-0x100000000, 0x080000000, 0x0ffffffff, 0/0, 0x100000001, -(2**53+2), 42, 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, -0, 0.000000000000001, -(2**53-2), Math.PI, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, -0x080000001, 2**53+2, 1.7976931348623157e308, -0x07fffffff, 2**53-2, 0x080000001, -Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 1/0, -(2**53)]); ");
/*fuzzSeed-168297596*/count=810; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ! ((Math.atan2((Math.trunc(( + (y ? y : y))) >>> 0), ((Math.atan2((x >>> 0), ( + Math.acos(y))) >>> 0) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy1, [0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), -0x080000001, 0.000000000000001, -0x100000001, 2**53+2, -0x0ffffffff, 0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -0x100000000, 0, 2**53, -(2**53-2), 0/0, -1/0, -0x080000000, 0x080000000, 42, -0, 0x100000000, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=811; tryItOut("\"use strict\"; this.e2.has(p1);");
/*fuzzSeed-168297596*/count=812; tryItOut("const dxdazu, z = false, x, aobpnk, d, pyeorc, zdgazz, ljrfoi;print(x);");
/*fuzzSeed-168297596*/count=813; tryItOut("Array.prototype.push.apply(a1, [i0, g2.s1, h1, f2, s0, v2, i2, s2]);");
/*fuzzSeed-168297596*/count=814; tryItOut("testMathyFunction(mathy2, /*MARR*/[x, x, x, x, x, new Number(1), x, 0/0, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), 0/0, x, 0/0, x, x, x, new Number(1), new Number(1), 0/0, x, 0/0, new Number(1), 0/0, new Number(1), 0/0, 0/0, 0/0, 0/0, 0/0, 0/0, 0/0, 0/0, new Number(1), 0/0, x, new Number(1), new Number(1), new Number(1), x, x, new Number(1), new Number(1)]); ");
/*fuzzSeed-168297596*/count=815; tryItOut("g2 = t0[v0];print(/..|.+(?=.)*|\\3+?/im);");
/*fuzzSeed-168297596*/count=816; tryItOut("a2.toString = f2;");
/*fuzzSeed-168297596*/count=817; tryItOut("\"use strict\"; /*MXX2*/o1.g2.Math.expm1 = a2;");
/*fuzzSeed-168297596*/count=818; tryItOut("v2 = Object.prototype.isPrototypeOf.call(m0, h1);");
/*fuzzSeed-168297596*/count=819; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    d0 = (((d1)) * ((2251799813685249.0)));\n    {\n      i2 = (!(i3));\n    }\n    d1 = (+((-1.888946593147858e+22)));\nprint((x = /*UUV2*/(x.isSealed = x.catch).yoyo(new (\"\\uB025\")(/\\1/ym,  \"\" ))));    i3 = (i2);\n    i3 = (/*FFI*/ff(((65537.0)), ((((((d1)) * ((+(0.0/0.0))))) * ((+(1.0/0.0))))))|0);\n    {\n      {\n        d1 = (-32769.0);\n      }\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: 'fafafa'.replace(/a/g, (Math.atanh).bind)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_VALUE, 1/0, 0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, 0.000000000000001, -0x07fffffff, 0x080000000, -0x100000001, -Number.MIN_VALUE, 0x07fffffff, -0x080000001, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53), -1/0, 2**53+2, -(2**53+2), 0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 0x0ffffffff, 2**53, Math.PI, -0, 0/0, Number.MIN_SAFE_INTEGER, 1, -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=820; tryItOut("\"use strict\"; ;");
/*fuzzSeed-168297596*/count=821; tryItOut("\"use strict\"; h0 = ({getOwnPropertyDescriptor: function(name) { v0 = t1.length;; var desc = Object.getOwnPropertyDescriptor(a1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return m2; var desc = Object.getPropertyDescriptor(a1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { g2.e1.add(a2);; Object.defineProperty(a1, name, desc); }, getOwnPropertyNames: function() { throw m0; return Object.getOwnPropertyNames(a1); }, delete: function(name) { g2.v2.__proto__ = this.m0;; return delete a1[name]; }, fix: function() { o2.h1.__iterator__ = (function() { try { o0.h2.toString = (function(j) { if (j) { try { m1.set(s0, h2); } catch(e0) { } try { v1 = true; } catch(e1) { } try { a0.pop(t1, s1); } catch(e2) { } e0 + ''; } else { try { v1 = r1.test; } catch(e0) { } try { g0.e2.has(a2); } catch(e1) { } try { this.m1.set(b2, s2); } catch(e2) { } b1 = t1.buffer; } }); } catch(e0) { } /*ODP-2*/Object.defineProperty(i2, \"valueOf\", { configurable: x, enumerable:  /x/ , get: (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x6b389342)))|0;\n  }\n  return f; }), set: (function(j) { g2.f2(j); }) }); return this.g2; });; if (Object.isFrozen(a1)) { return Object.getOwnProperties(a1); } }, has: function(name) { e2.has(b0);; return name in a1; }, hasOwn: function(name) { g2.h1.get = (function() { try { o1.valueOf = (function() { try { e2.has(e2); } catch(e0) { } try { /*RXUB*/var r = r0; var s = s0; print(s.search(r));  } catch(e1) { } try { s1 = s2.charAt(5); } catch(e2) { } for (var p in this.f0) { try { selectforgc(o2); } catch(e0) { } try { ; } catch(e1) { } Array.prototype.unshift.call(a0, o1); } return i1; }); } catch(e0) { } try { for (var p in p2) { try { o1.g2.v0 + ''; } catch(e0) { } try { for (var p in v0) { try { h2 + v0; } catch(e0) { } try { s1 += 'x'; } catch(e1) { } e0 + ''; } } catch(e1) { } try { o1.v0 = (h1 instanceof this.o0); } catch(e2) { } this.h2.get = f2; } } catch(e1) { } try { v2 = evalcx(\"mathy1 = (function(x, y) { return ( + mathy0(Math.fround((Math.fround(Math.fround((Math.fround((y ? ( + (Math.imul(-0x080000000, (-0x100000000 >>> 0)) * Math.fround((((0x07fffffff | 0) !== (( + Math.min(( + x), ( + y))) | 0)) | 0)))) : ( + Math.cosh((y >>> 0))))) ? Math.fround((y ^ Math.atan2((Math.log2(y) >>> 0), -Number.MIN_VALUE))) : Math.fround(y)))) & Math.fround(Math.atan2(( ~ ( ~ (( ~ y) | 0))), x)))), ( + (Math.imul((( + (( + Math.cbrt(y)) >>> 0)) | 0), Math.fround(Math.sign(Math.hypot((x >>> 0), ( + var r0 = y % x; x = r0 / x; var r1 = r0 - x; var r2 = 3 & r0; var r3 = r1 * r2; var r4 = r2 % r1; var r5 = r4 % r3; r2 = 8 * 7; r3 = r4 ^ y; r0 = r3 + 2; r0 = 4 % r5; r2 = r0 - r0; var r6 = y | r5; var r7 = 5 | 9; var r8 = y - 0; var r9 = 7 ^ r8; x = r0 | 5; var r10 = 0 ^ 3; var r11 = r3 / r10; var r12 = 0 - r9; var r13 = r1 / r4; var r14 = r0 & 0; var r15 = 8 * r10; var r16 = 1 + r8; r14 = r15 | r1; var r17 = r11 / 7; var r18 = r11 * r0; print(r18); var r19 = 8 - 2; var r20 = r1 / r3; var r21 = y & r3; r11 = r19 & y; var r22 = r2 % r19; var r23 = 4 / r17; var r24 = r19 * 5; var r25 = r14 + r1; print(y); r24 = r19 | r9; print(r25); var r26 = 6 ^ r4; var r27 = r15 ^ 7; var r28 = r20 / 4; var r29 = 0 / r28; var r30 = r25 / 0; var r31 = r24 / 1; var r32 = r13 * r22; var r33 = r22 / r0; var r34 = 4 / r5; var r35 = r19 * r28; var r36 = r24 * r9; r1 = r31 ^ r5; var r37 = 1 - r3; var r38 = r33 % r4; var r39 = r12 % r8; var r40 = 0 ^ r34; var r41 = r40 + 0; var r42 = 0 & r23; var r43 = 1 + 7; print(r0); var r44 = r38 - r19; r43 = 2 - r31; var r45 = r0 / r27; var r46 = r26 * r19; var r47 = r10 ^ 3; var r48 = 5 / r16; var r49 = r35 - 2; var r50 = 0 % 6; var r51 = r14 - r27; r44 = 4 * 6; r18 = r26 * 3; var r52 = 5 + 4; var r53 = 7 - 8; var r54 = r37 + 0; var r55 = 1 | 7; var r56 = 8 * r37; var r57 = 0 / 7; print(r13); var r58 = r10 % r50; var r59 = 9 / r35; var r60 = 8 - r7; var r61 = r50 ^ r30; var r62 = 6 % r7; var r63 = r25 & 3; var r64 = r27 + x; print(y); var r65 = r62 + r7; var r66 = r14 | r44; r0 = r33 ^ r47; var r67 = 2 + r57; var r68 = 4 - r43; var r69 = 7 & 2; var r70 = r19 & 5; var r71 = r24 * r67; var r72 = 9 - 4; r45 = 0 % r56; ))))) | 0)))); }); testMathyFunction(mathy1, [1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 2**53+2, 0x080000000, -(2**53), 2**53-2, 0/0, Math.PI, 1/0, -Number.MIN_VALUE, 0x100000000, -(2**53-2), -0x080000001, 1, -0x100000001, 0x080000001, 0.000000000000001, -0x080000000, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -(2**53+2), -1/0, 42, 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, Number.MIN_VALUE, -0x100000000]); \", g2); } catch(e2) { } f1(o1); return t0; });; return Object.prototype.hasOwnProperty.call(a1, name); }, get: function(receiver, name) { throw a0; return a1[name]; }, set: function(receiver, name, val) { a0 = a2.filter((function() { try { v0 = g0.runOffThreadScript(); } catch(e0) { } v2 = NaN; return p2; }));; a1[name] = val; return true; }, iterate: function() { /*MXX1*/o2 = g1.RangeError.name;; return (function() { for (var name in a1) { yield name; } })(); }, enumerate: function() { g2.offThreadCompileScript(\"function f1(p0)  { /*hhh*/function ithhxj(p0, e = eval(\\\"/* no regression tests found */\\\")){a2.push(g0.o1);}ithhxj(/*UUV1*/(x.setSeconds = objectEmulatingUndefined), window); } \");; var result = []; for (var name in a1) { result.push(name); }; return result; }, keys: function() { v0 = g1.runOffThreadScript();; return Object.keys(a1); } });");
/*fuzzSeed-168297596*/count=822; tryItOut("/*vLoop*/for (nnpsab = 0; nnpsab < 94; ++nnpsab) { let y = nnpsab; print(this.s0); } ");
/*fuzzSeed-168297596*/count=823; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((Math.atanh(( - y)) & ( + Math.cosh(( + y)))) != (( + (Math.fround(Math.exp(Math.fround(Math.min(Math.fround(x), Math.fround(y))))) && ( + (( - (Math.tanh(( ~ (y | 0))) >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy0, [0x100000000, -Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, -(2**53-2), 1/0, 0.000000000000001, 0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, 2**53-2, -(2**53+2), 1.7976931348623157e308, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -0x0ffffffff, -0, Number.MIN_VALUE, 0x080000000, 42, 2**53, -0x07fffffff, 0, -0x100000001, -0x080000001, 2**53+2, -0x100000000, 0/0]); ");
/*fuzzSeed-168297596*/count=824; tryItOut("mathy5 = (function(x, y) { return Math.hypot(((((Math.atan2((( + (( + y) | ( + ((y + 0x080000000) * Math.min(( + mathy2(x, y)), ( + 0x080000001)))))) >>> 0), Math.fround((Math.fround((Math.cbrt((-0x0ffffffff >>> 0)) >>> 0)) > Math.fround(( ~ Math.imul(Math.fround(( ! y)), ( + x))))))) >>> 0) ? (((Math.sqrt(((y === y) > Math.imul(y, Math.clz32(x)))) | 0) && (((y | 0) >> (x >>> 0)) | 0)) | 0) : (Math.clz32((Math.atan2(x, Math.fround((42 % Math.fround(((((y | 0) + Math.fround(x)) | 0) ? y : x))))) >>> 0)) >>> 0)) >>> 0) >>> 0), ((mathy4(Math.imul((x ? ((( - y) | 0) | 0) : x), y), y) !== (Math.sign((0x100000000 >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53), -(2**53+2), 0x100000000, 42, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x080000001, -0x080000001, -0x100000001, -0x07fffffff, 0/0, 0x07fffffff, -1/0, -Number.MAX_VALUE, -0, -(2**53-2), 0, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0x100000001, -Number.MIN_VALUE, 0x0ffffffff, 1/0, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, 0.000000000000001, 1, -0x100000000, 2**53+2]); ");
/*fuzzSeed-168297596*/count=825; tryItOut("mathy5 = (function(x, y) { return Math.imul((Math.pow(Math.fround(mathy3(Math.fround((( + Math.min(( + x), ( + x))) ? y : Math.imul(x, x))), Math.fround((Math.imul((y >>> 0), (x >>> 0)) | 0)))), ( - (x ? (Math.pow(( + Math.hypot((2**53+2 >>> 0), (y >>> 0))), Math.fround(x)) >>> 0) : (mathy3(x, -1/0) >>> 0)))) - ( + Math.asin(( + (x | 0))))), ((((((y | 0) ? (Math.fround((Math.fround(Math.ceil(x)) ? Math.fround(( + Math.clz32(( + 0x100000001)))) : Math.fround((( - ( + x)) | 0)))) | 0) : (( ! -Number.MIN_SAFE_INTEGER) | 0)) | 0) >>> 0) >= ((Math.min((2**53 >>> 0), (mathy0((mathy3(((x - (( + y) | 0)) | 0), mathy2(Number.MIN_VALUE, y)) | 0), ( + (y != ( + Math.acos(((0.000000000000001 ** x) >>> 0)))))) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-0x07fffffff, 0.000000000000001, -(2**53+2), 1/0, -1/0, -0x080000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 42, -0x100000000, 0x07fffffff, 1.7976931348623157e308, 2**53, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0, -0x100000001, 2**53-2, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 1, 0x100000001, 0x100000000, 0, -(2**53-2), 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, 0/0, Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=826; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -8796093022209.0;\n    d2 = (d0);\n    return ((-(/*FFI*/ff()|0)))|0;\n  }\nprint(x);\n;s1 = new String(t2);\n\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0, 1, [0], null, (new String('')), NaN, '', '/0/', (new Boolean(true)), (new Number(-0)), 0.1, true, objectEmulatingUndefined(), false, '0', '\\0', ({valueOf:function(){return '0';}}), /0/, (new Boolean(false)), 0, ({toString:function(){return '0';}}), undefined, ({valueOf:function(){return 0;}}), (new Number(0)), [], (function(){return 0;})]); ");
/*fuzzSeed-168297596*/count=827; tryItOut("\"use strict\"; a1.shift();");
/*fuzzSeed-168297596*/count=828; tryItOut("/*RXUB*/var r = /\\3/im; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-168297596*/count=829; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=830; tryItOut("d, soipbw, a = (d%=length), d = 'fafafa'.replace(/a/g, Set.prototype.add), {} = null *= window, b,  ''  = ((void options('strict')));if(true) v2 = new Number(p2); else {g0.v1 = t0.byteLength;(void schedulegc(g2)); }let b = let (e) this.__defineGetter__(\"e\", (let (e=eval) e));");
/*fuzzSeed-168297596*/count=831; tryItOut("\"use strict\"; for(var d in ((Map.prototype.values)((x.yoyo(15)\n)))){M:switch(let (z) \"\\u1004\")\u000c { default: i0.send(s0);break; break; case 9: break;  }this.v0 = new Number(4.2); }");
/*fuzzSeed-168297596*/count=832; tryItOut("Math.hypot(new  /x/ (), x);");
/*fuzzSeed-168297596*/count=833; tryItOut("mathy2 = (function(x, y) { return Math.fround(( + ( + ( - ( + Math.exp(Math.log1p(y))))))); }); testMathyFunction(mathy2, [0x0ffffffff, -0, -0x080000001, -Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0/0, Number.MIN_VALUE, 1, -Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, 0x080000001, -0x080000000, -0x100000001, 1/0, 0x100000001, 0x100000000, 0.000000000000001, -1/0, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 2**53-2, 2**53, Number.MAX_VALUE, -0x07fffffff, 0x080000000]); ");
/*fuzzSeed-168297596*/count=834; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions('compartment'); } void 0; } /*tLoop*/for (let x of /*MARR*/[ /x/ , objectEmulatingUndefined(), false,  /x/ ,  /x/ , new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), false,  /x/ , false, false,  /x/ ,  /x/ , objectEmulatingUndefined()]) { Array.prototype.splice.call(a2, NaN, z++, h1, v2, g1.i1, f1); }");
/*fuzzSeed-168297596*/count=835; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return ( + (( + ( + ( - ((( - (mathy0(((x >>> 0) ** ((Math.sinh((42 | 0)) | 0) >>> 0)), Math.PI) | 0)) | 0) | 0)))) - Math.atanh(Math.min(( + x), (x * x))))); }); ");
/*fuzzSeed-168297596*/count=836; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.cos(Math.fround((( ~ ((Math.pow(Math.fround(((((((y | 0) && y) | 0) | 0) - (x | 0)) | 0)), Math.fround(( + mathy0(( + Math.min(y, y)), ( + Number.MIN_VALUE))))) << ( - Math.hypot(( - y), x))) | 0)) | 0)))); }); testMathyFunction(mathy1, [-(2**53-2), 2**53, 0x080000001, 0.000000000000001, 0x07fffffff, Number.MIN_VALUE, 2**53-2, 0/0, -(2**53+2), Math.PI, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, 0x080000000, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 1, -0, -1/0, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, 0x100000001, -0x100000000, 0x100000000, -0x080000001, 42, -0x07fffffff, 2**53+2]); ");
/*fuzzSeed-168297596*/count=837; tryItOut("print(( /x/g .unwatch(\"has\")))\n");
/*fuzzSeed-168297596*/count=838; tryItOut("\"use asm\"; var y = c => delete  /x/g .y.NaN;t1[7] = undefined;\nv0 = g0.runOffThreadScript();\n");
/*fuzzSeed-168297596*/count=839; tryItOut("Array.prototype.shift.call(g0.a1, o1.s0, o1.e0);");
/*fuzzSeed-168297596*/count=840; tryItOut("g0.a1.splice(NaN, g2.o1.o1.g2.g1.g1.o2.o0.v0);");
/*fuzzSeed-168297596*/count=841; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\x0A\", \"gi\"); var s = \"\\u00f6\"; print(r.exec(s)); ");
/*fuzzSeed-168297596*/count=842; tryItOut("\"use strict\"; this.o0 = b2.__proto__;");
/*fuzzSeed-168297596*/count=843; tryItOut("\"use strict\"; L:with({w: x}){let b = function ([y]) { } >>>=  /x/g .substr(Math.imul( '' , 7), [,]);for (var p in o0) { try { v2 = Array.prototype.reduce, reduceRight.call(a0, (function() { try { s2 = o1.a0.join(s2, g0.e2); } catch(e0) { } v1 + s1; return i0; })); } catch(e0) { } try { e0.add(this.h1); } catch(e1) { } try { /*ODP-1*/Object.defineProperty(s0, \"-6\", ({set: new RegExp(\"(?=(?!\\ufbb7*)+)\", \"m\"), configurable: false, enumerable: this})); } catch(e2) { } f0.valueOf = (function(j) { if (j) { o0.e2.add(this.g2); } else { v0 = g1.eval(\"a1 = Array.prototype.map.apply(a0, [(function(j) { if (j) { e1.valueOf = -3417279168; } else { try { h2.hasOwn = (function() { for (var j=0;j<54;++j) { f2(j%3==0); } }); } catch(e0) { } /*MXX2*/g0.Array.prototype.filter = f2; } }), this.a1, p2]);\"); } }); }a2 = a2.filter((function mcc_() { var azzzrj = 0; return function() { ++azzzrj; o1.f2(/*ICCD*/azzzrj % 11 == 9);};})()); }");
/*fuzzSeed-168297596*/count=844; tryItOut("mathy2 = (function(x, y) { return Math.fround((Math.pow((( + ( + ( + Math.acosh(y)))) >>> 0), (( ~ (Math.pow(((-0 | Math.hypot((( ! x) >>> 0), (((y >>> 0) * -Number.MIN_VALUE) | 0))) | 0), (( + Math.imul(( + ( + Math.ceil(( + x)))), ( ~ x))) | 0)) | 0)) >>> 0)) && ( ~ (( ! ( + Math.max(x, y))) >>> 0)))); }); testMathyFunction(mathy2, [-1/0, 0, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, -0x100000000, -0x100000001, 0/0, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, 0x100000001, -0x080000001, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 42, Math.PI, 2**53, -0x0ffffffff, -0, 0x080000000, 0x0ffffffff, 0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, 1, 0x080000001, -(2**53-2), -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=845; tryItOut("for(c in x) Array.prototype.pop.call(a2);");
/*fuzzSeed-168297596*/count=846; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.trunc(mathy0(( ! ( + (( + y) ? ( + Math.sin(y)) : x))), (( + ((y === ( + Math.imul(( + 42), ( + (( + mathy0(( + x), ( + x))) | -Number.MAX_VALUE))))) | 0)) | 0))); }); testMathyFunction(mathy5, [-0x07fffffff, -(2**53+2), -0x080000000, -(2**53-2), Number.MAX_VALUE, -0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, 1/0, 0x07fffffff, -Number.MIN_VALUE, 0x100000000, 0x080000001, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, -0, 0, 2**53, 0x100000001, 42, -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, Math.PI, 0x080000000, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-168297596*/count=847; tryItOut("\"use strict\"; /*RXUB*/var r = /\\b|(?:\\b+\\u90ec\\xaC{4,5}|$?)(?:(?!.\\b)[^]{0,}[^].|\\D?(?:(?=\\S))|(?:\\1)+)+?/y; var s = \"a\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-168297596*/count=848; tryItOut("x;");
/*fuzzSeed-168297596*/count=849; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((Math.log2(( + Math.fround(Math.atan2(y, Math.fround(x))))) , (( ~ (Math.log2((( + ( ~ ( + (((x | 0) ? (y | 0) : (Math.hypot(x, y) | 0)) | 0)))) | 0)) | 0)) | 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=850; tryItOut("Array.prototype.unshift.apply(a0, [g0.m0, m1, o2.h0]);\nf1.__proto__ = g2.o2.a0;\n");
/*fuzzSeed-168297596*/count=851; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.asin(Math.fround((( + Math.fround((Math.fround(( - y)) ? Math.fround(( + Math.log2(( + y)))) : Math.fround((Math.atan2((( ! Math.fround(( - ( + x)))) >>> 0), (y , x)) | 0))))) ? (((mathy0(( + Math.max(-0x080000001, y)), Math.min(x, Math.clz32(y))) === (Math.pow(( + Math.fround(( - x))), mathy0(x, y)) | 0)) | 0) | 0) : ( + (( + (1.7976931348623157e308 >= (1 == Math.acosh(-(2**53))))) * -0)))))); }); testMathyFunction(mathy1, [1, '/0/', (new Boolean(false)), -0, (new Number(0)), ({valueOf:function(){return '0';}}), false, ({toString:function(){return '0';}}), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 0, '0', null, 0.1, true, '', (new Boolean(true)), /0/, [], (new Number(-0)), '\\0', NaN, (new String('')), [0], (function(){return 0;}), undefined]); ");
/*fuzzSeed-168297596*/count=852; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        i0 = ((((i0))>>>(((0x39f26e02) ? (0xfe2dcd15) : ((-1.9342813113834067e+25) >= (32768.0)))+(i0)+(i0))));\n      }\n    }\n    /*FFI*/ff(((((i0)-(i0)-(/*FFI*/ff(((((0xff197c8)) & ((0x4e1140e4)))), ((d1)), ((-2097153.0)), ((0.25)))|0)) | ((0x209555e2)+((((0xf0fd26d4)-(0xc185a540))>>>((0xfdb47df4)*-0x6f928)))))), ((+tan(((((0x5568437) ? (d1) : (1073741825.0))))))), ((~((0x7b72e54c)-(0xe2a225e1)))), ((((67108864.0)) % ((-288230376151711740.0)))), ((~~(+(0.0/0.0)))), ((abs((abs((0x7fffffff))|0))|0)), ((-295147905179352830000.0)), ((9007199254740992.0)), ((1.0)), ((2.0)), ((0.0625)), ((70368744177665.0)), ((2305843009213694000.0)), ((-281474976710657.0)));\n    return +((NaN));\n  }\n  return f; })(this, {ff: null.toString}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-1/0, 2**53, Number.MIN_VALUE, -0x07fffffff, -0x100000000, Math.PI, 0.000000000000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -0x080000001, -0x0ffffffff, 0x080000000, 2**53-2, -0, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), 0/0, 0x100000001, 0x07fffffff, 1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -0x100000001, -0x080000000, 0, 1]); ");
/*fuzzSeed-168297596*/count=853; tryItOut("o1.t0.set(a2, 5);");
/*fuzzSeed-168297596*/count=854; tryItOut("f1 = this.a2[({valueOf: function() { var v1 = g2.runOffThreadScript();return 15; }})];");
/*fuzzSeed-168297596*/count=855; tryItOut("print(true);a0.shift(t0);");
/*fuzzSeed-168297596*/count=856; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=857; tryItOut("g2.v2 = g0.a0.length;");
/*fuzzSeed-168297596*/count=858; tryItOut("print(x);i1.next();");
/*fuzzSeed-168297596*/count=859; tryItOut("e1 + '';");
/*fuzzSeed-168297596*/count=860; tryItOut("e1.has(b0);");
/*fuzzSeed-168297596*/count=861; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=862; tryItOut("\"use strict\"; s1 += this.s1;");
/*fuzzSeed-168297596*/count=863; tryItOut("\"use strict\"; const t2 = t1.subarray(17);");
/*fuzzSeed-168297596*/count=864; tryItOut("\"use strict\"; ((d) = null);v2 = r1.exec;");
/*fuzzSeed-168297596*/count=865; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.pow(Math.pow(( + (Math.log2((x | 0)) | 0)), (Math.tanh(( ~ y)) | 0)), (Math.fround(Math.pow(Math.imul(Math.fround(y), Math.fround(y)), Math.fround(y))) % Math.fround(Math.log10((Math.imul((x | 0), (y >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [-0x080000001, -(2**53), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, 0x080000000, -1/0, -0, 0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 0x080000001, -0x080000000, -0x07fffffff, Math.PI, 2**53, -0x100000000, Number.MAX_VALUE, -(2**53-2), 1, Number.MIN_VALUE, 0x100000000, 42, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), 0, 0x100000001, 0x07fffffff, 0/0, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=866; tryItOut("\"use strict\"; g2.i1 = new Iterator(o1.i2, true);function x(x)\"use asm\";   var pow = stdlib.Math.pow;\n  var sqrt = stdlib.Math.sqrt;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -274877906945.0;\n    return (((i2)))|0;\n    {\n      i2 = (0xffffffff);\n    }\n    d4 = (-1099511627777.0);\n    i2 = (!(i0));\n    d4 = (+pow(((140737488355329.0)), ((0.125))));\n    switch ((((this.__defineGetter__(\"[]\", Set.prototype.forEach))) << ((0xf93f554d)-(0xffcb6f5d)-(0x1283850c)))) {\n      case 0:\n        i0 = (((((((0x62c983ba))>>>((0xb249f45d))) >= (((0xfaedc9a6))>>>((-0x8000000))))-(i1)+(-0x8000000))>>>(((w = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })((void shapeOf(x))), eval)) < (-70368744177665.0))+(i3))) <= (0xca026879));\n        break;\n      case 0:\n        d4 = (+sqrt(((-2199023255551.0))));\n        break;\n      case -3:\n        (Float64ArrayView[0]) = ((+(0x996c291c)));\n        break;\n      case -3:\n        d4 = ((1.0) + (+(-1.0/0.0)));\n        break;\n      case 0:\n        i2 = (i0);\n        break;\n      case -1:\n        i2 = ((2.4178516392292583e+24) > (+((-0x5d927*(!((((0x86875889)) >> ((0xa243ad48)))))) << ((((0x4587001)) ? (i0) : ((0x76600365) < (0xe4349496)))-(i0)))));\n        break;\n      default:\n        switch ((-0x8000000)) {\n        }\n    }\n    i3 = ((~((i3)-(i1))));\n    return ((((~((i1)*0x31a6a)))-(((-(((((0x7fffffff) != (0x1331188a))-((1152921504606847000.0) >= (1.5))) << ((0x6ce24191) / (0x9601d0ca))) == (~~((d <= c)((yield (4277)), (this.__defineGetter__(\"x\", Boolean.prototype.valueOf)))))))|0))))|0;\n  }\n  return f;t2 + v1;");
/*fuzzSeed-168297596*/count=867; tryItOut("v2 = null;");
/*fuzzSeed-168297596*/count=868; tryItOut("a2.push(a2);");
/*fuzzSeed-168297596*/count=869; tryItOut("\"use strict\"; case true || delete [,]: Array.prototype.splice.call(a1, NaN, 2, g2.p0, m2);case 0: \nthis;function NaN() { \"use strict\"; yield  ''  } selectforgc(o1);\n");
/*fuzzSeed-168297596*/count=870; tryItOut("/*infloop*/for(var z = \"\\u32BA\"; 'fafafa'.replace(/a/g, (new Function(\"b2 = t1.buffer;\")))\u000c; window-=(x = Proxy.createFunction(({/*TOODEEP*/})(\"\\uB17B\"), (Math).bind(false)))) {o0.f2 = a2[window];L:if(false) m1 + ''; else {g2.g1.a2.forEach((function() { e0 = new Set(o0); return i1; })); } }");
/*fuzzSeed-168297596*/count=871; tryItOut("/*RXUB*/var r = /(?:\\u03ae{1})/yim; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-168297596*/count=872; tryItOut("mathy5 = (function(x, y) { return mathy3((( + ((Math.min(x, ((((x | 0) , ((( ! (x | 0)) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0) ? (( + 2**53-2) | 0) : Math.atan2((Number.MAX_SAFE_INTEGER | 0), (-(2**53-2) | 0)))) || (Math.min((( + (y !== (( - (y >>> 0)) >>> 0))) ? ( ! -(2**53+2)) : ( + x)), ((((y | 0) * (0.000000000000001 | 0)) >>> 0) | 0)) | 0)), Math.tan((Math.sqrt((Math.fround(( + Math.fround(Math.acosh(y)))) | 0)) | 0))); }); testMathyFunction(mathy5, [-0x07fffffff, Number.MIN_VALUE, 1, 2**53, -(2**53+2), Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, 0x100000000, -0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, 0, -(2**53), -(2**53-2), 0.000000000000001, 2**53+2, -0x100000001, 0x080000001, -0x080000000, 0x100000001, -1/0, 42, 2**53-2, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 1/0, Math.PI, -0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=873; tryItOut("\"use strict\"; window = (x) = -0.069, w = \"\\uCFF1\", c, rfkghr, x, \u3056, etpdmy;v1 = (m0 instanceof v2);");
/*fuzzSeed-168297596*/count=874; tryItOut("Object.defineProperty(g0, \"a0\", { configurable: true, enumerable: (x % 2 == 0),  get: function() {  return /*FARR*/[--x.__proto__, z = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: Date.prototype.setMonth, delete: function(name) { return delete x[name]; }, fix: undefined, has: function() { throw 3; }, hasOwn: (Object.defineProperty(x, \"max\", ({set: WeakMap.prototype.has}))).call, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: RangeError, enumerate: objectEmulatingUndefined, keys: function() { throw 3; }, }; })(x), ((void options('strict_mode')))), (Math.tan(x)) %= (yield e = arguments), , new Function, (4277), ...((d)(-0)).eval(\"/*ADP-2*/Object.defineProperty(a1, 16, { configurable: false, enumerable: false, get: (function() { try { for (var v of g1.a0) { try { h0.iterate = g0.f0; } catch(e0) { } try { v2 = g2.r2.ignoreCase; } catch(e1) { } try { v1 = g0.runOffThreadScript(); } catch(e2) { } /*MXX1*/o0 = g2.Math.log10; } } catch(e0) { } try { /*MXX1*/o1 = g0.SyntaxError.prototype.constructor; } catch(e1) { } o1.i1.next(); throw o2; }), set: (function() { try { m2.delete(e0); } catch(e0) { } try { neuter(b1, \\\"same-data\\\"); } catch(e1) { } try { m0.delete(undefined); } catch(e2) { } m0 = new Map; return s0; }) });\") for (b of x) for (e of (4277)) for each (NaN in decodeURIComponent), ...(window >= x if (e))]; } });");
/*fuzzSeed-168297596*/count=875; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-168297596*/count=876; tryItOut("mathy2 = (function(x, y) { return ( + (Math.fround(Math.clz32(( + ( + ( + (((((Math.log10((y | 0)) | 0) || x) >>> 0) != (Math.PI >>> 0)) >>> 0)))))) | 0)); }); testMathyFunction(mathy2, [-1/0, 1/0, -0x080000001, -(2**53), 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, Number.MIN_VALUE, -0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, 0, 0x07fffffff, 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, 2**53+2, Math.PI, 42, -Number.MIN_VALUE, 0x080000001, 2**53, -0x080000000, 0x100000000, 1]); ");
/*fuzzSeed-168297596*/count=877; tryItOut("this.zzz.zzz;for(let e of /*FARR*/[]) let(x = x, x) ((function(){with({}) (eval(\"selectforgc(o0);\",  '' ));})());");
/*fuzzSeed-168297596*/count=878; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return (mathy1(( + ( ! ( + Math.asinh(0x100000000)))), (mathy0((Math.acos((x | 0)) >>> 0), (Math.asinh(x) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 0, 1/0, -0, 0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000001, -Number.MAX_VALUE, 0x100000000, -(2**53-2), 0/0, 0.000000000000001, -1/0, 2**53-2, -(2**53+2), 0x080000000, 0x07fffffff, 1, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, -0x080000000, 2**53+2, -0x100000001, Math.PI]); ");
/*fuzzSeed-168297596*/count=879; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(.*?\\\\u0074*?)\", \"ym\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=880; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-168297596*/count=881; tryItOut("v0 = (a1 instanceof f2);");
/*fuzzSeed-168297596*/count=882; tryItOut("");
/*fuzzSeed-168297596*/count=883; tryItOut("a2.valueOf = (function() { try { m0.set(m2, o0.g2); } catch(e0) { } try { for (var p in i0) { try { e1.add(g1); } catch(e0) { } try { v2 = (g2.v0 instanceof m2); } catch(e1) { } try { g1.offThreadCompileScript(\"/*MARR*/[null,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" , function(){}, null,  \\\"use strict\\\" , null, null,  \\\"use strict\\\" ,  \\\"use strict\\\" , null, null, null, null, null, null, null, null, null, null, null, null, null, null, function(){},  \\\"use strict\\\" , null, function(){},  \\\"use strict\\\" , null, null,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" , function(){}, function(){},  \\\"use strict\\\" , function(){}, null, function(){},  \\\"use strict\\\" ,  \\\"use strict\\\" , null, function(){}, null,  \\\"use strict\\\" , function(){}, function(){},  \\\"use strict\\\" , function(){}, null, null, function(){}, null, function(){}, null,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" , null, function(){}, null,  \\\"use strict\\\" , function(){},  \\\"use strict\\\" , function(){}, function(){},  \\\"use strict\\\" , function(){},  \\\"use strict\\\" , null,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" , null, null, function(){}, null, null,  \\\"use strict\\\" , function(){}, function(){}, null, null, function(){}, function(){}, function(){}].sort(objectEmulatingUndefined)\"); } catch(e2) { } for (var p in a2) { try { t1 = new Int8Array(b0); } catch(e0) { } try { Array.prototype.splice.call(a1, NaN, 17); } catch(e1) { } Array.prototype.push.call(g0.a0, ((x in ((function factorial_tail(rifxfs, ozuoxf) { ; if (rifxfs == 0) { ; return ozuoxf; } \"\\u27B5\";; return factorial_tail(rifxfs - 1, ozuoxf * rifxfs);  })(3, 1))).watch(\"asinh\", decodeURI)), t0, s2); } } } catch(e1) { } try { selectforgc(o2); } catch(e2) { } t2.set(a0, 15); return v0; });");
/*fuzzSeed-168297596*/count=884; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul(( ! Math.fround((Math.fround((x >>> (((Math.fround(y) >>> (Math.log(Math.fround(0x080000001)) | 0)) | 0) >>> 0))) - (( ~ ( + Math.min(x, x))) >>> 0)))), (( ~ ((Math.asinh(( - y)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy2, [-0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 1/0, Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 0x080000000, 42, Math.PI, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, -1/0, 0x100000000, -0x080000001, 0x100000001, 1, -0x100000000, -(2**53+2), 0.000000000000001, 2**53+2, 0, -(2**53), 0x080000001, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=885; tryItOut("\"use strict\"; let (x) { o0.e1.add(p0); }");
/*fuzzSeed-168297596*/count=886; tryItOut("mathy2 = (function(x, y) { return Math.imul(Math.sign(\"\\uE5B5\"), Math.log10(Math.fround(Math.imul(( + (( + ( ~ ( + Number.MIN_VALUE))) << y)), ( + Math.pow(( ~ (x | 0)), Math.fround(y))))))); }); testMathyFunction(mathy2, [2**53-2, 2**53, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0/0, -Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, -(2**53-2), -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, 0x080000001, -0x100000001, Number.MIN_VALUE, 0, 0.000000000000001, -0x0ffffffff, -(2**53), 2**53+2, 0x100000000, -0x080000001, -(2**53+2), 42, -0, 1, 0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-168297596*/count=887; tryItOut("\"use asm\"; /*RXUB*/var r = /(?:(?=(?:[^])))|(\\f)\\w*?|\\0{0,2}*?/g; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=888; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=889; tryItOut("mathy4 = (function(x, y) { return (( ! Math.fround((Math.fround(Math.log1p((Math.atan(y) | 0))) ? ( + mathy0((x | 0), ( ~ (Math.hypot(x, Number.MAX_SAFE_INTEGER) << x)))) : Math.fround((mathy1(( ~ Number.MIN_VALUE), ( ~ Math.fround(Math.asinh(x)))) >>> 0))))) | 0); }); testMathyFunction(mathy4, [0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0/0, 2**53, 2**53-2, Number.MIN_VALUE, 0x07fffffff, 1, -(2**53), 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, -0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x07fffffff, -Number.MIN_VALUE, 0, 0x080000000, -0, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, 42, 1/0, -(2**53-2), -0x0ffffffff, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-168297596*/count=890; tryItOut("f2(t2);");
/*fuzzSeed-168297596*/count=891; tryItOut("L:switch((4277)) { default: /* no regression tests found */break; case 0: break;  }");
/*fuzzSeed-168297596*/count=892; tryItOut("print(let (a =  '' .valueOf(\"number\")) \"\\u647D\")\n/*MXX3*/g0.Promise.prototype.then = o0.g2.Promise.prototype.then;");
/*fuzzSeed-168297596*/count=893; tryItOut("\"use strict\"; (({NaN: 22}));\n/*RXUB*/var r = r2; var s = \" \"; print(s.split(r)); print(r.lastIndex); \n");
/*fuzzSeed-168297596*/count=894; tryItOut("h0 = x\n");
/*fuzzSeed-168297596*/count=895; tryItOut("/*infloop*/for(let z(-0) in \"\\u8426\") {this.o2.a1[x];print(x); }");
/*fuzzSeed-168297596*/count=896; tryItOut("m2 + g1;");
/*fuzzSeed-168297596*/count=897; tryItOut("for(y = x in (uneval(x))) {/\\3?|(\\3)|(?=\\uA91C)?\\b+?/function window(c, ...e)\"use asm\";   var imul = stdlib.Math.imul;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -2.4178516392292583e+24;\n    d3 = (d1);\n    d1 = (-9007199254740992.0);\n    i0 = (((+(~(-(0xfde02560)))) >= (1.0)) ? (-0x8000000) : ((((!(-0x8000000))-(0xfe43c784)-(i2)) >> ((0x6cdf9ed7)*0x196e9)) == (imul(((((0xca8f3291))>>>((0xfc435da8))) == (((-0x8000000))>>>((-0x8000000)))), ((((0xfe10f623))>>>((0xfe3ed693))) <= (0x28b56660)))|0)));\n    return (((0xbdf0d098)+(i0)))|0;\n  }\n  return f;print(true); }");
/*fuzzSeed-168297596*/count=898; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, 1, 42, 0, 1.7976931348623157e308, 0.000000000000001, 2**53-2, -(2**53-2), 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 1/0, -0, -0x100000001, 0/0, 0x080000001, Math.PI, -0x080000001, -1/0, 0x0ffffffff, -0x100000000, 2**53, -Number.MIN_VALUE, 0x100000000, 2**53+2, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_VALUE, 0x100000001, -0x080000000]); ");
/*fuzzSeed-168297596*/count=899; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.tanh(Math.fround((Math.expm1(Math.fround(( - (Math.fround(Math.fround(Math.min(Math.asin(y), 0.000000000000001))) | 0)))) || Math.clz32((( + ( + Math.pow(( + (((y >>> 0) != x) >>> 0)), Math.fround((((y | 0) || ( + y)) | 0))))) | 0))))); }); testMathyFunction(mathy1, [-0, -0x100000000, 0.000000000000001, 2**53-2, 0x080000000, 0/0, 0x100000001, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, -(2**53-2), 2**53+2, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 0, Number.MAX_SAFE_INTEGER, 42, 1/0, Math.PI, -(2**53+2), 0x080000001, -0x0ffffffff, -0x080000000, 2**53]); ");
/*fuzzSeed-168297596*/count=900; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (d1);\n    i2 = ((0x3573cbf8));\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: Array.prototype.reduce}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[2**53-2, {}, true, {}, new Boolean(true), 2**53-2, true, new Boolean(true), true, new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), {}, true, true, {}, true, {}, 2**53-2, true, 2**53-2, true, new Boolean(true), true, {}, true, 2**53-2, {}, 2**53-2]); ");
/*fuzzSeed-168297596*/count=901; tryItOut("\"use strict\"; a0 + '';");
/*fuzzSeed-168297596*/count=902; tryItOut("yield \"\u03a0\";true;function eval(NaN)\"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      (Uint8ArrayView[((0xfbcccbc5)-((((i1)-((0x0)))|0) <= ((-0x16160*(i1))|0))) >> 0]) = ((0xf9b07a5d));\n    }\n    {\n      d0 = ((0xfe4a219f) ? (+pow(((+(1.0/0.0))), ((0.001953125)))) : (let (x, window, npfjde, chxtjx, a) undefined));\n    }\n    (Float32ArrayView[2]) = ((0.0078125));\n    return (((!(0xe4bce582))+((+abs(((Float64ArrayView[(((0x24fbc6fd) > (0x455c7ae0))-((0x970be4cb))) >> 3])))) < (d0))+((((imul(((((0xffffffff)) & ((0x60e1ad20)))), ((((0xfad9c94a))>>>((0xfb326367)))))|0)) + (d0)) != (d0))))|0;\n  }\n  return f;var r0 = x % x; var r1 = r0 % r0; var r2 = x ^ x; var r3 = r1 | 5; var r4 = 3 % 3; r4 = r0 / 2; var r5 = r3 % r1; var r6 = r2 - r0; print(r0); var r7 = 0 & r1; var r8 = r3 - 6; var r9 = r8 | r1; r9 = r1 % r6; var r10 = 6 % r8; var r11 = r8 + 8; var r12 = 5 - r7; var r13 = r6 * r7; var r14 = x | r5; x = 7 & r0; var r15 = r5 / r7; ");
/*fuzzSeed-168297596*/count=903; tryItOut("with({z: (4277)}){/*ODP-2*/Object.defineProperty(p0, \"delete\", { configurable: false, enumerable: true, get: (function(j) { if (j) { try { g2.a1 = this.r2.exec(s1); } catch(e0) { } try { v2 = b2.byteLength; } catch(e1) { } o1.v1 = Object.prototype.isPrototypeOf.call(h0, s1); } else { for (var v of this.e1) { try { a0.sort((function() { for (var j=0;j<48;++j) { g2.f0(j%2==1); } })); } catch(e0) { } try { g0.offThreadCompileScript(\"this.g0.v0 = o0.g2.runOffThreadScript();\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (z % 2 == 0), noScriptRval: false, sourceIsLazy: x & e++, catchTermination: (x % 13 == 6), element: o1, sourceMapURL: s2 })); } catch(e1) { } v0 = o0.a0.reduce, reduceRight((function() { for (var j=0;j<0;++j) { f2(j%3==1); } })); } } }), set: (function() { try { (void schedulegc(g2)); } catch(e0) { } try { g2.i2 = new Iterator(t0); } catch(e1) { } v1 = r1.ignoreCase; return a2; }) }); }");
/*fuzzSeed-168297596*/count=904; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 2**53+2, 0, -Number.MAX_VALUE, -0x07fffffff, -(2**53-2), 2**53, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -0x080000000, 2**53-2, -0x0ffffffff, 0x100000000, -0x100000001, 1, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, 42, 0x080000001, 0x100000001, 0x0ffffffff, 1/0, -(2**53), -0, -0x080000001]); ");
/*fuzzSeed-168297596*/count=905; tryItOut("v2 = Object.prototype.isPrototypeOf.call(t0, s0);");
/*fuzzSeed-168297596*/count=906; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0x4252c153);\n    i0 = (0x691017ec);\n    d1 = (d1);\n    d1 = (-33554433.0);\n    return (((0xfa343ee3)-(i0)))|0;\n    i0 = (0x2d5b08ea);\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000000, 1/0, 0.000000000000001, 0x100000001, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -0, 1, Math.PI, 0/0, 0x07fffffff, -(2**53-2), 0x080000001, 2**53-2, 2**53, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, -Number.MAX_VALUE, -0x100000000, 0, 0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -(2**53), -0x100000001]); ");
/*fuzzSeed-168297596*/count=907; tryItOut("a0 = arguments.callee.arguments;");
/*fuzzSeed-168297596*/count=908; tryItOut("h1.fix = f0;");
/*fuzzSeed-168297596*/count=909; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.ceil(Math.tanh(( + (Math.fround((Math.fround(Math.tanh(x)) | 0)) != (-0x100000000 | 0))))); }); testMathyFunction(mathy1, [({valueOf:function(){return '0';}}), '', null, -0, (new Number(0)), '/0/', true, '0', 0, undefined, [], objectEmulatingUndefined(), /0/, ({valueOf:function(){return 0;}}), (function(){return 0;}), 1, false, '\\0', (new Number(-0)), [0], ({toString:function(){return '0';}}), NaN, (new Boolean(true)), (new String('')), 0.1, (new Boolean(false))]); ");
/*fuzzSeed-168297596*/count=910; tryItOut("\"use strict\"; x;Array.prototype.reverse.call(a0);");
/*fuzzSeed-168297596*/count=911; tryItOut("\"use strict\"; v2 = g1.eval(\"function f0(s2)  { \\\"use strict\\\"; e1.add(o2); } \");");
/*fuzzSeed-168297596*/count=912; tryItOut("/*RXUB*/var r = r1; var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-168297596*/count=913; tryItOut("mathy0 = (function(x, y) { return (( + Math.tan(y)) != (( + Math.ceil(Math.log(( + Math.imul(( + y), ( + Math.clz32(( + x)))))))) & (( + (Math.sign(Math.fround(-Number.MIN_VALUE)) >>> 0)) != x))); }); testMathyFunction(mathy0, [1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, 1, 1/0, -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 0, -1/0, Math.PI, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, -0x080000000, 0x080000000, 2**53, 0x07fffffff, Number.MAX_VALUE, -0x080000001, -0x100000001, -(2**53), 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -0x100000000, 0x080000001, 2**53-2, -Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=914; tryItOut("let (window = (4277),   = ([]), a, NaN, c, x, mpjxur) { i1 = a1.keys; }");
/*fuzzSeed-168297596*/count=915; tryItOut("mathy4 = (function(x, y) { return Math.fround(((( ~ ( + ( ~ (x | 0)))) | 0) && Math.fround(Math.fround((Math.fround((((Math.fround(mathy3(x, x)) >>> 0) ? (Math.fround(mathy2(Math.fround(Math.fround(Math.cbrt(Math.fround((( + (y >>> 0)) >>> 0))))), Math.fround((( ~ (y | 0)) | 0)))) >>> 0) : -0x0ffffffff) >>> 0)) !== Math.fround((((( ! 1/0) >>> 0) || ( + ( + ((Math.fround(mathy1(( - (y | 0)), ( + Math.fround(Math.imul(x, x))))) | x) | 0)))) >>> 0))))))); }); ");
/*fuzzSeed-168297596*/count=916; tryItOut("print(uneval(b0));");
/*fuzzSeed-168297596*/count=917; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a1, ({valueOf: function() { {}false;return 5; }}), { configurable: ({x: [], eval: x} = -Infinity.valueOf(\"number\")), enumerable: (z >> y + (/*UUV2*/( .expm1 =  .isFinite))), get: f0, set: (function(j) { if (j) { t1 = new Uint16Array(b1, 16, 2); } else { for (var v of g0.f2) { Object.defineProperty(this, \"a2\", { configurable: \"\\uAA69\", enumerable: false,  get: function() {  return arguments; } }); } } }) });");
/*fuzzSeed-168297596*/count=918; tryItOut("var x, wldigv, \u3056 =  \"\" , z, \u3056 = x;Array.prototype.shift.apply(a0, [t0, i2]);");
/*fuzzSeed-168297596*/count=919; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    return +((Float64ArrayView[(x) >> 3]));\n    i1 = ((((i0)) ^ ((/*FFI*/ff(((((-274877906945.0)) % ((((134217729.0)) * ((1.5111572745182865e+23)))))), ((((3.8685626227668134e+25)) * (((4398046511105.0) + (-1.9342813113834067e+25))))), ((-1125899906842624.0)), ((~((0xa1da4089)+(0xf866ff47)))), ((~((0xfd7b25c6)))))|0)-(i0))));\n    {\n      i0 = (i1);\n    }\n    (Float64ArrayView[1]) = ((+((((((0xe840ae7e) ? (0xfddbbc96) : (0xe1f75351))+(i0))>>>((i1)+(i0))) / (x))>>>(((~(0x441fb*(i0))) > (abs((abs((imul((0xfcdb92dc), (-0x8000000))|0))|0))|0))-(i1)+((0x79de0f0d))))));\n    i1 = (i1);\n    return +((+atan2(((Float32ArrayView[2])), ((Infinity)))));\n  }\n  return f; })(this, {ff: String}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[0x10000000,  /x/g , new Boolean(true), null, objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/g , 0x10000000,  /x/g , objectEmulatingUndefined(), 0x10000000, new Boolean(true), 0x10000000, null, null, new Boolean(true),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), 0x10000000,  /x/g , 0x10000000,  /x/g , new Boolean(true), objectEmulatingUndefined(), null, new Boolean(true), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), 0x10000000, objectEmulatingUndefined(), 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, objectEmulatingUndefined(), null, new Boolean(true), new Boolean(true), 0x10000000, 0x10000000, new Boolean(true), objectEmulatingUndefined(), new Boolean(true),  /x/g , new Boolean(true),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), null, 0x10000000, 0x10000000,  /x/g , objectEmulatingUndefined(), null, new Boolean(true), 0x10000000, objectEmulatingUndefined(), objectEmulatingUndefined(), null, 0x10000000, objectEmulatingUndefined(), objectEmulatingUndefined(), null,  /x/g , 0x10000000, objectEmulatingUndefined(), 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, new Boolean(true), null, objectEmulatingUndefined(), null,  /x/g , new Boolean(true), 0x10000000, new Boolean(true), new Boolean(true),  /x/g ,  /x/g , objectEmulatingUndefined(),  /x/g , 0x10000000, 0x10000000, objectEmulatingUndefined(), null, 0x10000000, objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), 0x10000000,  /x/g , objectEmulatingUndefined(), 0x10000000, new Boolean(true), 0x10000000,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , null, null, null, 0x10000000, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), null, null, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g , null, objectEmulatingUndefined()]); ");
/*fuzzSeed-168297596*/count=920; tryItOut("mathy1 = (function(x, y) { return ( ! Math.fround(((Math.fround(( + Math.fround(y))) * Math.tanh(x)) ^ ( + (( + (Math.acos(((Math.cosh(x) - 2**53) | 0)) | 0)) == ( + y)))))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 1, 1/0, -(2**53-2), -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, 2**53+2, -0, 2**53, -0x080000001, 0x080000000, 0x0ffffffff, -(2**53), -0x080000000, 42, -0x100000000, -(2**53+2), 1.7976931348623157e308, Number.MAX_VALUE, 0x080000001, 0x100000001, 0.000000000000001, -0x07fffffff, 0/0, -0x0ffffffff, 0, 2**53-2, Math.PI]); ");
/*fuzzSeed-168297596*/count=921; tryItOut("\"use strict\"; v0 = new Number(-0);function this() { print(x); } e0.__iterator__ = (function(j) { if (j) { try { for (var v of g0.h1) { p0 = t2[12]; } } catch(e0) { } (void schedulegc(g2)); } else { try { a2.shift(this.a2, m0); } catch(e0) { } try { m0.has(o1.f1); } catch(e1) { } this.o1.e2 + ''; } });");
/*fuzzSeed-168297596*/count=922; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -36893488147419103000.0;\n    var d3 = -9.0;\n    var i4 = 0;\n    var i5 = 0;\n    var i6 = 0;\n    var d7 = -274877906945.0;\n    {\n      {\n        (Float32ArrayView[0]) = ((-268435457.0));\n      }\n    }\n    return (((((Int16ArrayView[((((0xa84b8485))>>>((0xf50a3a4b))) / (((-0x4bff8ba))>>>((0xdc3dfc5)))) >> 1])) >> (((((0xfef4fcbd)) & ((0xfcd7f024))) <= (imul((0xfe4277c0), (0x3e76c655))|0))+((+(1.0/0.0)) <= (d2))+(i0))) / (~((0xdfdb87d8)-(0xffffffff)))))|0;\n  }\n  return f; })(this, {ff: Uint8ClampedArray}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [/0/, null, [], (new Boolean(true)), (new Number(0)), '/0/', 0, ({valueOf:function(){return 0;}}), '', ({valueOf:function(){return '0';}}), (function(){return 0;}), NaN, '0', (new Number(-0)), -0, undefined, false, 0.1, objectEmulatingUndefined(), (new String('')), ({toString:function(){return '0';}}), 1, true, [0], (new Boolean(false)), '\\0']); ");
/*fuzzSeed-168297596*/count=923; tryItOut("b1.toString = f0;");
/*fuzzSeed-168297596*/count=924; tryItOut("\"use strict\"; testMathyFunction(mathy1, [[0], ({valueOf:function(){return '0';}}), 0.1, NaN, (new Boolean(false)), (new String('')), (new Number(0)), (new Boolean(true)), [], ({valueOf:function(){return 0;}}), '', ({toString:function(){return '0';}}), null, undefined, -0, '\\0', false, 0, 1, '0', '/0/', /0/, (function(){return 0;}), objectEmulatingUndefined(), (new Number(-0)), true]); ");
/*fuzzSeed-168297596*/count=925; tryItOut("\"use strict\"; e0.has(m2);");
/*fuzzSeed-168297596*/count=926; tryItOut("\"use strict\"; M:if((x % 9 != 1)) s1 = new String; else  if (++String.prototype) {v2 = a0.length;\nv2 = g1.eval(\"function f1(h1)  { \\\"use strict\\\"; return (makeFinalizeObserver('tenured')) } \");\n }");
/*fuzzSeed-168297596*/count=927; tryItOut("mathy0 = (function(x, y) { return Array.prototype.shift.call(g1.a0);; }); ");
/*fuzzSeed-168297596*/count=928; tryItOut("\"use strict\"; e1.has(o0);");
/*fuzzSeed-168297596*/count=929; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=930; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ~ mathy0(Math.imul((((Math.fround(Math.max(Math.imul(x, y), Math.fround(((2**53+2 != x) && x)))) >>> 0) ? (Math.fround(Math.imul(((( + (y | 0)) | 0) >>> 0), (y >>> 0))) >>> 0) : (((((Math.acosh(x) | 0) >>> 0) * (Math.log10(x) >>> 0)) >>> 0) >>> 0)) >>> 0), ( + x)), ( - (( + ( ~ x)) | 0)))); }); testMathyFunction(mathy1, [objectEmulatingUndefined(), (new Number(-0)), ({valueOf:function(){return '0';}}), 0, (new Number(0)), true, 1, ({toString:function(){return '0';}}), (new Boolean(false)), /0/, NaN, [], '/0/', (function(){return 0;}), (new String('')), null, '0', 0.1, -0, '\\0', undefined, false, ({valueOf:function(){return 0;}}), (new Boolean(true)), '', [0]]); ");
/*fuzzSeed-168297596*/count=931; tryItOut("t2 = o2.t2.subarray(v0);");
/*fuzzSeed-168297596*/count=932; tryItOut("v2 = Object.prototype.isPrototypeOf.call(b0, b0);");
/*fuzzSeed-168297596*/count=933; tryItOut("v2 = (i0 instanceof i0);");
/*fuzzSeed-168297596*/count=934; tryItOut("\"use strict\"; { void 0; try { startgc(56972); } catch(e) { } } this.v1 = Array.prototype.reduce, reduceRight.call(a0, (function() { a0.forEach((function() { try { e2 = m0; } catch(e0) { } try { a0[19] = f0; } catch(e1) { } try { this.t2.toSource = Function; } catch(e2) { } Array.prototype.unshift.apply(o1.a1, [s0]); return m0; })); return s0; }), g0, t2);\nvar zpuqqq = new SharedArrayBuffer(12); var zpuqqq_0 = new Uint16Array(zpuqqq); for (var p in v0) { try { v0 = -0; } catch(e0) { } try { print(uneval(g2)); } catch(e1) { } try { this.v2 = m1.get(v0); } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(i0, b0); }/*tLoop*/for (let b of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], [1], new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1]]) { b0.valueOf = f0; }v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (y += eval), noScriptRval: false, sourceIsLazy: (/*FARR*/[2, w, ,  /x/g , eval].some(JSON.stringify)), catchTermination: Object.defineProperty\u0009(e, 19, ({configurable: false})) }));\n");
/*fuzzSeed-168297596*/count=935; tryItOut("b1.__proto__ = h1;");
/*fuzzSeed-168297596*/count=936; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=937; tryItOut("h2.defineProperty = o1.f1;");
/*fuzzSeed-168297596*/count=938; tryItOut("\"use strict\"; print(\"-6\");");
/*fuzzSeed-168297596*/count=939; tryItOut("m0.has(m0);");
/*fuzzSeed-168297596*/count=940; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-1/0, 0/0, -0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, -(2**53+2), 2**53-2, 0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -(2**53-2), -0, Number.MAX_VALUE, -0x100000000, 1, 42, 0x100000000, 0x0ffffffff, -0x080000000, -(2**53), -Number.MAX_VALUE, 0x100000001, 0x080000001]); ");
/*fuzzSeed-168297596*/count=941; tryItOut("g0.s1 = new String;({\"-27\": this.__defineSetter__(\"e\", function(y) { \"use strict\"; f1 = f1; }), -4: 25 });");
/*fuzzSeed-168297596*/count=942; tryItOut("\"use strict\"; testMathyFunction(mathy4, ['', (new String('')), (new Boolean(false)), (function(){return 0;}), /0/, true, [0], '0', (new Number(-0)), undefined, ({valueOf:function(){return 0;}}), 0, [], ({toString:function(){return '0';}}), (new Number(0)), '\\0', (new Boolean(true)), 1, false, '/0/', null, 0.1, objectEmulatingUndefined(), NaN, ({valueOf:function(){return '0';}}), -0]); ");
/*fuzzSeed-168297596*/count=943; tryItOut("\"use strict\"; o0 = {};");
/*fuzzSeed-168297596*/count=944; tryItOut("for(let e in new Array(-4)) let(x) ((function(){return;})());x.constructor;");
/*fuzzSeed-168297596*/count=945; tryItOut("\"use strict\"; /*RXUB*/var r = /\\3/gim; var s = x < x; print(s.replace(r, ArrayBuffer.isView, \"g\")); ");
/*fuzzSeed-168297596*/count=946; tryItOut("\"use strict\"; t0[19] =  '' ();");
/*fuzzSeed-168297596*/count=947; tryItOut("testMathyFunction(mathy3, [0x080000000, 1.7976931348623157e308, 42, 1, -Number.MAX_VALUE, 0x0ffffffff, Math.PI, 2**53+2, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0/0, 2**53-2, 0.000000000000001, -0x080000001, -0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -(2**53-2), -Number.MIN_VALUE, 0x100000000, 0, -0, 0x100000001, -0x100000000, -(2**53+2), -0x080000000]); ");
/*fuzzSeed-168297596*/count=948; tryItOut("print(let (despkh, x =  '' , aujewx, x, xaejcr)  /x/  - /\\3|(?=(?!^))|((?!(?=\u6bdc*?)*?))/im);");
/*fuzzSeed-168297596*/count=949; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! Math.fround(Math.fround(( ~ Math.fround((( ~ ((Math.exp(((Math.fround((( + x) ? (0 >>> 0) : (y >>> 0))) >>> 0x100000000) >>> 0)) >>> 0) | 0)) | 0)))))); }); testMathyFunction(mathy4, [-0x100000000, 0x0ffffffff, -(2**53), -0, 1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1, 0/0, -0x100000001, 2**53+2, Number.MAX_VALUE, -0x080000000, -1/0, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, -Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, 0, -0x080000001, 2**53, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, 0x080000001]); ");
/*fuzzSeed-168297596*/count=950; tryItOut("testMathyFunction(mathy1, [-Number.MAX_VALUE, -0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, 42, 2**53+2, -0x080000000, -0x080000001, -0x100000001, -(2**53-2), 0/0, 0x0ffffffff, 0x100000001, -(2**53), 0.000000000000001, 2**53-2, Math.PI, 0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -0x100000000, 1, 0x080000000, Number.MIN_VALUE, -0, Number.MAX_VALUE, 1/0, 2**53, -0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=951; tryItOut("L: for (var c of (this.__defineSetter__(\"window\", (\"\\u7E9D\").bind())) !== (function(y) { yield y; print([,,]);; yield y; }).call(true, [1,,],  /x/g )) {/*MXX3*/g0.URIError.prototype.constructor = g2.URIError.prototype.constructor;m2.has(h0); }");
/*fuzzSeed-168297596*/count=952; tryItOut(";\n(/*UUV1*/(x.__lookupSetter__ = Number.parseInt));\n");
/*fuzzSeed-168297596*/count=953; tryItOut("/*hhh*/function zjfkqx(){print(x);}zjfkqx((yield this.x));");
/*fuzzSeed-168297596*/count=954; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.pow((Math.sinh(( + (((Math.pow(Math.min(x, y), Math.fround((Math.fround(y) ? (-0x07fffffff >>> 0) : (( + Math.hypot(x, x)) | 0)))) >>> 0) == (Math.atanh(mathy1((Math.fround(Math.atan2((( + x) | 0), Math.fround(x))) >>> 0), (Math.cbrt(y) >>> 0))) >>> 0)) >>> 0))) | 0), (Math.fround((((((x >>> 0) && (x | 0)) >>> 0) ? Math.fround(Math.hypot(x, y)) : Math.exp(Math.ceil(Math.fround(y)))) > ( + (mathy0((Math.fround(( ~ Math.fround(Math.exp((((Math.PI >>> 0) + (-0x100000000 >>> 0)) >>> 0))))) >>> 0), (Math.pow((x >>> 0), ((Math.asinh(x) | 0) >>> 0)) >>> 0)) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-168297596*/count=955; tryItOut("\"use strict\"; for (var v of o2) { this.o0.h2.keys = f2; }");
/*fuzzSeed-168297596*/count=956; tryItOut("var v1 = t0.byteOffset;");
/*fuzzSeed-168297596*/count=957; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 4294967297.0;\n    i1 = (0x861ea73d);\n    d2 = (((Float64ArrayView[1])) * ((134217729.0)));\n    return +((d2));\n  }\n  return f; })(this, {ff: z => x -= z}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[/*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' ,  '\\0' ,  '\\0' , {},  '\\0' ,  '\\0' ,  '\\0' , {}, {}, {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ), {},  '\\0' , {}, {},  '\\0' , {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' , {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ), {},  '\\0' ,  '\\0' , {}, {},  '\\0' ,  '\\0' ,  '\\0' , {}, {},  '\\0' , {}, {},  '\\0' ,  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' ,  '\\0' , {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ), /*UUV1*/(x.slice = (a, x) =>  /x/g ), {},  '\\0' ,  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ), /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ), /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, {}, {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ), /*UUV1*/(x.slice = (a, x) =>  /x/g ), /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' , {}, {},  '\\0' ,  '\\0' , {}, {},  '\\0' ,  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ),  '\\0' , {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, /*UUV1*/(x.slice = (a, x) =>  /x/g ), /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, {},  '\\0' , /*UUV1*/(x.slice = (a, x) =>  /x/g ), {}, {}, {},  '\\0' ,  '\\0' , {}]); ");
/*fuzzSeed-168297596*/count=958; tryItOut("\"use strict\"; /*tLoop*/for (let y of (makeFinalizeObserver('nursery'))) { g2.i0 + ''; }");
/*fuzzSeed-168297596*/count=959; tryItOut("\"use strict\"; v2 = t2.byteOffset;");
/*fuzzSeed-168297596*/count=960; tryItOut("\"use strict\"; v0 = t1.length;");
/*fuzzSeed-168297596*/count=961; tryItOut("for (var v of g0.f0) { try { b1 + s0; } catch(e0) { } try { v2 = a0.reduce, reduceRight((function(j) { if (j) { try { v0 = evaluate(\"Function()\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: , noScriptRval: (x % 5 == 2), sourceIsLazy: false, catchTermination: (x % 2 != 1) })); } catch(e0) { } try { var v1 = evalcx(\"o0.g0.o2.t0 = new Float64Array(({valueOf: function() { for (var v of o1) { try { /*RXUB*/var r = r1; var s = s1; print(uneval(r.exec(s)));  } catch(e0) { } try { m2 = new Map(f0); } catch(e1) { } try { a1.toSource = (function() { e1.add(h2); return a1; }); } catch(e2) { } this.i0.next(); }return 19; }}));\", g1); } catch(e1) { } try { i2 = e2.iterator; } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(g2, this.o1.g1); } else { try { /*RXUB*/var r = r0; var s = \"\"; print(r.exec(s));  } catch(e0) { } this.v2 = o0.g0.runOffThreadScript(); } }), i0); } catch(e1) { } try { ; } catch(e2) { } o1.m0.set(f0, h0); }");
/*fuzzSeed-168297596*/count=962; tryItOut("\"use strict\"; testMathyFunction(mathy0, [1, 0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 2**53+2, -(2**53), -Number.MAX_VALUE, -0x100000000, 42, Number.MIN_VALUE, Math.PI, 2**53, 0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -0x080000000, -Number.MIN_VALUE, -0x080000001, 1/0, -0x100000001, 0x100000000, -0, 0x080000001, 0/0, 0.000000000000001, -0x07fffffff, -(2**53-2), 2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-168297596*/count=963; tryItOut("\"use strict\"; v1 = a1.every(f2, e1, new (x = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), function(q) { \"use strict\"; return q; })));");
/*fuzzSeed-168297596*/count=964; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=965; tryItOut("wjjdhl(new encodeURIComponent(~(4277)));/*hhh*/function wjjdhl(){window\nArray.prototype.splice.apply(a1, [1, this.v2, h2]);}");
/*fuzzSeed-168297596*/count=966; tryItOut("/*MXX3*/g0.String.prototype.localeCompare = g0.String.prototype.localeCompare;");
/*fuzzSeed-168297596*/count=967; tryItOut("mathy0 = (function(x, y) { return Math.acos(( + ((( + ((( ! (y | 0)) | 0) >>> 0)) >>> 0) || (( + Math.cos(Math.atan2(x, Math.fround(( - Math.fround(Math.fround(Math.max(-Number.MAX_VALUE, x)))))))) >>> 0)))); }); ");
/*fuzzSeed-168297596*/count=968; tryItOut("selectforgc(o1);");
/*fuzzSeed-168297596*/count=969; tryItOut("let(rqfkyx, x = this.__defineSetter__(\"x\", (function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { throw 3; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })), e, x, x = 'fafafa'.replace(/a/g, (function(x, y) { return y; })), z = delete x.NaN, x, wteasr) ((function(){yield (\"\\u5DDB\".yoyo(a = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: undefined, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: function() { throw 3; }, }; })(this), function(q) { return q; })));})());x.name;");
/*fuzzSeed-168297596*/count=970; tryItOut("/*vLoop*/for (pkizpi = 0, x; pkizpi < 1; ++pkizpi) { const x = pkizpi; (-14); } ");
/*fuzzSeed-168297596*/count=971; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((mathy2(( ! (( + Math.atan2(y, ( ~ x))) < ( + Math.hypot(42, ( + y))))), Math.pow(( + mathy1(Math.exp(-0x080000000), y)), Math.pow(Math.hypot(x, 0x080000000), ((( ! ((( + y) ? (-Number.MIN_SAFE_INTEGER | 0) : (-Number.MAX_SAFE_INTEGER | 0)) | 0)) - ( + Math.min(x, ( + y)))) | 0)))) >>> (( - Math.acos(( + ( ! Math.fround(42))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_VALUE, -Number.MAX_VALUE, 0, -0x100000000, 0x080000000, 0x080000001, -(2**53), 0x100000001, -(2**53+2), 1.7976931348623157e308, -0x080000000, 0x100000000, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, Math.PI, 42, -1/0, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -0x0ffffffff, 2**53-2, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, -0, -0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=972; tryItOut("return this;function x(x, x, ...x) { \"use strict\"; return  \"\"  } e1.valueOf = (function() { try { v2 = undefined; } catch(e0) { } try { for (var p in a2) { g1.o2.v2 = (v2 instanceof e1); } } catch(e1) { } try { a2 = r0.exec(s2); } catch(e2) { } for (var v of p1) { try { /*RXUB*/var r = r1; var s = s2; print(s.search(r));  } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(h2, this.o0); } return p0; });");
/*fuzzSeed-168297596*/count=973; tryItOut("o2 = i2.__proto__;");
/*fuzzSeed-168297596*/count=974; tryItOut("");
/*fuzzSeed-168297596*/count=975; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((-549755813888.0));\n  }\n  return f; })(this, {ff: Promise.resolve}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 2**53, 0, -(2**53-2), 1, -0x0ffffffff, -0x080000000, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, -(2**53), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 0x080000000, -1/0, Number.MIN_VALUE, -0x080000001, 42, 0x100000000, -Number.MIN_VALUE, 0/0, 0x07fffffff, 0x0ffffffff, 0x080000001, 0x100000001, 2**53-2, 1.7976931348623157e308, -0, -Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2]); ");
/*fuzzSeed-168297596*/count=976; tryItOut("testMathyFunction(mathy5, [-0, -0x080000001, 2**53, -(2**53), -0x100000000, 0x07fffffff, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -0x07fffffff, -Number.MIN_VALUE, 1/0, 2**53+2, 0, 0x080000000, -Number.MAX_VALUE, -0x100000001, 42, Number.MAX_VALUE, Number.MIN_VALUE, 1, -0x0ffffffff, 0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-168297596*/count=977; tryItOut("o2.a1.push(t2, g1);");
/*fuzzSeed-168297596*/count=978; tryItOut("mathy4 = (function(x, y) { return mathy3(Math.hypot(((Math.fround(Math.min(( + x), ( + ( ! y)))) ^ Math.fround((Math.fround(-(2**53)) % Math.fround(( ! ((x < x) | 0)))))) | 0), (Math.fround(mathy2(Math.min(2**53, Math.tan(Math.acos((x * y)))), Math.fround(y))) | 0)), Math.imul(((Math.max(( + ((Math.fround((( + (Math.min(Number.MAX_SAFE_INTEGER, (mathy3(x, x) | 0)) | 0)) % ( + x))) ** ((mathy1(((y || (Math.exp(Math.fround(y)) | 0)) | 0), ( + Math.sqrt(y))) | 0) | 0)) | 0)), ( + Math.fround(Math.pow((y >>> 0), (Math.tanh(x) >>> 0))))) | 0) >>> 0), Math.fround(mathy0((( ! ( + x)) ? Math.fround(x) : ((y & Math.fround(((x >>> 0) ? Math.fround(y) : 0))) | 1.7976931348623157e308)), ( + Math.sign(Math.fround(( + x)))))))); }); testMathyFunction(mathy4, [-0x0ffffffff, -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 0x080000000, 1/0, -(2**53), -0x100000000, -0x100000001, 0x07fffffff, 0.000000000000001, 2**53, 1.7976931348623157e308, 0, -(2**53-2), 0/0, 2**53+2, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, 42, 1, Math.PI, 0x080000001, -(2**53+2), Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=979; tryItOut("testMathyFunction(mathy3, [0/0, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, -0x080000001, 1/0, 0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -0, Math.PI, 42, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), -(2**53+2), -1/0, 0.000000000000001, -0x0ffffffff, 2**53, 2**53-2, Number.MAX_VALUE, -0x080000000, 0x080000001, 0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=980; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=981; tryItOut("/*bLoop*/for (let baiqnt = 0; baiqnt < 15; ++baiqnt) { if (baiqnt % 5 == 2) { o0.f1 = (function() { for (var j=0;j<168;++j) { f0(j%4==1); } }); } else { M:with(d){print(w); } }  } ");
/*fuzzSeed-168297596*/count=982; tryItOut("Array.prototype.push.call(a2, o2);");
/*fuzzSeed-168297596*/count=983; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.max((( + (Math.asinh(Math.fround((Math.sign((Math.fround(( - Math.fround(( + Math.fround(Math.PI))))) | 0)) | 0))) || ( - x))) >>> 0), (( + mathy0(( + (Math.atan2(x, (Math.sin((((2**53 != y) | 0) >>> 0)) | 0)) | 0)), ( + Math.hypot(Math.fround(Math.log1p(Math.fround(((((y === x) >>> 0) ? (x >>> 0) : (1 >>> 0)) >>> 0)))), Math.min(( ! y), (( ~ Number.MIN_SAFE_INTEGER) >>> 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [(new Boolean(true)), -0, '/0/', (function(){return 0;}), (new Boolean(false)), [], (new Number(-0)), ({valueOf:function(){return '0';}}), undefined, false, '\\0', true, 0.1, 0, ({toString:function(){return '0';}}), '', /0/, (new String('')), '0', (new Number(0)), 1, null, NaN, [0], ({valueOf:function(){return 0;}}), objectEmulatingUndefined()]); ");
/*fuzzSeed-168297596*/count=984; tryItOut("let v1 = t2.length;");
/*fuzzSeed-168297596*/count=985; tryItOut("\"use strict\"; selectforgc(o2);function x(e, x = ([ /x/g ]), z, x, eval =  '' , NaN, x, w)\"use asm\";   var NaN = stdlib.NaN;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float32ArrayView[(((void shapeOf((NaN) = false)))) >> 2]) = ((+(((0x19ab27e7))>>>(-(0xacbb3c06)))));\n    return +((NaN));\n  }\n  return f;return (Proxy(\"\\u7E00\"));");
/*fuzzSeed-168297596*/count=986; tryItOut("\"use strict\"; e1 + '';");
/*fuzzSeed-168297596*/count=987; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[ '' ,  '' ]) { (new RegExp(\"((?:\\\\x14))+\\\\2{0}\", \"gim\")); }");
/*fuzzSeed-168297596*/count=988; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.round((Math.atanh(Math.fround((0x100000001 * (0x100000001 | 0)))) << ((((Math.fround(( ! Math.fround(y))) >>> 0) <= (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) == ( + (( + Math.sqrt(( + -Number.MAX_SAFE_INTEGER))) > Math.sign(x)))))); }); testMathyFunction(mathy2, [2**53, 1.7976931348623157e308, 0/0, -0x100000000, 0x100000000, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, -1/0, 0x080000001, 1, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 0x07fffffff, -0x080000001, -(2**53), -(2**53+2), Number.MAX_VALUE, 2**53+2, 1/0, -(2**53-2), 0x0ffffffff, 0x080000000, -Number.MAX_VALUE, -0x07fffffff, -0x100000001, -0, 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-168297596*/count=989; tryItOut("Array.prototype.push.call(a2, e2, s2);");
/*fuzzSeed-168297596*/count=990; tryItOut("v0 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-168297596*/count=991; tryItOut("Array.prototype.forEach.call(a1, (function() { m0 = new Map; return b1; }));");
/*fuzzSeed-168297596*/count=992; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=993; tryItOut("v2 = Infinity;");
/*fuzzSeed-168297596*/count=994; tryItOut("e = x;s0 += 'x';");
/*fuzzSeed-168297596*/count=995; tryItOut("testMathyFunction(mathy5, /*MARR*/[ /x/ , null,  /x/ , null, eval, eval, eval, eval, null,  /x/ , eval,  /x/ , 0x50505050, 0x50505050,  /x/ , 0x50505050, (4277), null, (4277), (4277), eval, 0x50505050, eval,  /x/ , eval, eval]); ");
/*fuzzSeed-168297596*/count=996; tryItOut("for(c in ((Uint16Array)(x |= /\\u00F9|(?=^|\\S+)|\\\u00de{67108863,67108866}*?/i.yoyo(this) | -29)))delete h2.set;");
/*fuzzSeed-168297596*/count=997; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.sinh(mathy1(Math.atan2((( - x) >>> 0), ( ! ( + Math.hypot(Number.MAX_SAFE_INTEGER, 0.000000000000001)))), Math.fround(Math.imul(Math.fround(Math.fround(( - (( + y) ? 42 : Math.fround(( - Math.fround(x))))))), Math.fround(Math.fround((Math.fround(Math.fround(Math.trunc(Math.fround(mathy4(x, x))))) === Math.fround(Math.min(x, Math.min(Math.asin(0.000000000000001), x)))))))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -(2**53), 0, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 42, 0x100000000, 0.000000000000001, -0x080000000, -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 2**53, -0, -(2**53-2), 0/0, 2**53-2, 1.7976931348623157e308, -0x100000000, 1, -0x080000001, 0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI]); ");
/*fuzzSeed-168297596*/count=998; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + ( + ( + (( - Math.fround(Math.acos(Math.fround(2**53)))) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, -1/0, -0x080000000, Number.MAX_VALUE, 42, 0x0ffffffff, 2**53-2, 0.000000000000001, Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, Math.PI, 0/0, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), -0x07fffffff, -(2**53-2), 0x080000001, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -0, 0x100000000, 1.7976931348623157e308, 1/0, 1, 2**53+2, -0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-168297596*/count=999; tryItOut("mathy0 = (function(x, y) { return (Math.log(( + (Math.hypot(y, Math.pow((y <= x), (y >>> 0))) / ( + ( + ( + x)))))) & Math.sin(( + Math.max((y >>> 0), Math.sinh(x))))); }); ");
/*fuzzSeed-168297596*/count=1000; tryItOut("f0 = Proxy.createFunction(h1, f1, f0);");
/*fuzzSeed-168297596*/count=1001; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.pow((Math.sinh(Math.log1p(( + (Math.fround(mathy1(Math.fround(y), Math.fround(( + (( + 0x07fffffff) ? ( + (Math.min(x, (y >>> 0)) >>> 0)) : ( + ( ! Math.fround(y)))))))) >> ( + Math.min(Math.fround(1/0), ( + y))))))) >>> 0), (Math.acos((( + Math.acos(Math.min(42, mathy0(0x100000000, Math.sinh(-0))))) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[ /x/ ,  /x/ ,  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/ ,  /x/ ,  /x/ , (-1/0),  /x/ , (-1/0),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true), new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (-1/0), new Boolean(true),  /x/ ,  /x/ , new Boolean(true), (-1/0), (-1/0),  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), new Boolean(true),  /x/ , (-1/0), (-1/0),  /x/ , (-1/0), new Boolean(true), new Boolean(true),  /x/ ,  /x/ , (-1/0),  /x/ , new Boolean(true), (-1/0), new Boolean(true),  /x/ , (-1/0), new Boolean(true), (-1/0), (-1/0), (-1/0),  /x/ , (-1/0),  /x/ , (-1/0), new Boolean(true),  /x/ , new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (-1/0),  /x/ , (-1/0),  /x/ , new Boolean(true),  /x/ , (-1/0), new Boolean(true),  /x/ ,  /x/ , (-1/0),  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (-1/0), (-1/0),  /x/ , (-1/0), (-1/0),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true), (-1/0), (-1/0),  /x/ , new Boolean(true),  /x/ , (-1/0),  /x/ , new Boolean(true), new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (-1/0),  /x/ ,  /x/ ,  /x/ , (-1/0), new Boolean(true),  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (-1/0),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true),  /x/ ]); ");
/*fuzzSeed-168297596*/count=1002; tryItOut("a0.shift(o0, t2); for  each(e in (4277)) {v1 = (m1 instanceof p0);p0.toString = Math.cbrt; }");
/*fuzzSeed-168297596*/count=1003; tryItOut("testMathyFunction(mathy0, [-0x0ffffffff, -0x080000000, Number.MAX_VALUE, Math.PI, 0x080000001, -0, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, -0x100000000, 0x100000000, 42, 1/0, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, -0x080000001, 2**53, 0x100000001, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x100000001, -(2**53-2), Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-168297596*/count=1004; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.imul(( + Math.sqrt(( + Math.log(x)))), Math.atan2((Math.hypot(((Math.fround((0 | 0)) | 0) >>> 0), (x >>> 0)) >>> 0), Math.fround(Math.atan2(Math.fround(Math.hypot((Math.atan2((y | 0), Math.fround(( + Math.fround((Math.fround(x) || Math.fround(y)))))) | 0), x)), Math.fround((Math.fround(Math.fround(Math.atan2(Math.fround(y), Math.fround((Math.clz32(x) | 0))))) * Math.fround(( - (1 | 0))))))))); }); testMathyFunction(mathy3, [2**53, 0x0ffffffff, Math.PI, -0x07fffffff, 2**53+2, 0, 0.000000000000001, -(2**53+2), Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, -(2**53), -Number.MAX_VALUE, 2**53-2, 1, -(2**53-2), -0x0ffffffff, 1/0, 42, Number.MAX_SAFE_INTEGER, 0/0, -0, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -Number.MIN_VALUE, 0x080000000, Number.MIN_VALUE, 0x100000000, -0x100000001, 0x080000001]); ");
/*fuzzSeed-168297596*/count=1005; tryItOut("\"use strict\"; const dtfmxk;print(x);");
/*fuzzSeed-168297596*/count=1006; tryItOut("/* no regression tests found */for(let z in []);");
/*fuzzSeed-168297596*/count=1007; tryItOut("e0.toSource = (function() { for (var j=0;j<14;++j) { f2(j%2==0); } });");
/*fuzzSeed-168297596*/count=1008; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.hypot(Math.clz32(( + ( + Math.hypot(((Math.pow((( + (0.000000000000001 ** ( + y))) >>> 0), ((Math.max(x, (Math.cbrt(-0x07fffffff) | 0)) | 0) >>> 0)) >>> 0) >>> 0), (0x100000000 >>> 0))))), ( + Math.fround(Math.atan2((Math.max(Math.fround(Math.hypot((y >>> 0), Math.fround(Math.asin(y)))), x) >>> 0), (( - Math.fround(( + x))) >>> 0)))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, 0x07fffffff, -(2**53-2), 0x080000001, -0x07fffffff, 0/0, 2**53+2, 42, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, -0x100000000, 2**53-2, -0x0ffffffff, -0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0, 2**53, 0x100000000, -(2**53), -1/0, -0x080000001, Number.MAX_VALUE, 0, 0x080000000, -(2**53+2), 0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1009; tryItOut("/*ADP-1*/Object.defineProperty(this.a0, (4277), ({enumerable: false}));");
/*fuzzSeed-168297596*/count=1010; tryItOut("\"use strict\"; let x = x, x, NaN = this.__defineSetter__(\"x\", (new Function(\"/*MXX3*/g1.String.prototype.small = g0.String.prototype.small;\"))).watch(\"x\", Object.prototype.valueOf), shyiep, a, x, x, x, yjfyvy;/*oLoop*/for (let phqlrz = 0, x; phqlrz < 12; ++phqlrz) { this.f1(e0); } ");
/*fuzzSeed-168297596*/count=1011; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -0.5;\n    var d3 = 134217729.0;\n    var d4 = 16385.0;\n    d4 = (-17.0);\n    {\n      d1 = (d2);\n    }\n    return ((((0x498f9eda))))|0;\n  }\n  return f; })(this, {ff: RegExp}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x100000000, -(2**53), 0, -0x07fffffff, 1, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, 0x100000001, 2**53, 2**53-2, 0/0, -0x080000000, -(2**53-2), Math.PI, -Number.MIN_VALUE, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 0.000000000000001, -0x100000001, 2**53+2, 0x080000001, 0x080000000, 0x100000000, Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1012; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(((Math.min((( + (Math.fround(( ~ y)) === (( ~ (y > ((y >= (y >>> 0)) >>> 0))) >>> 0))) >>> 0), ((Math.sinh((Math.clz32(x) >>> 0)) >>> 0) >>> 0)) >>> 0) ? (Math.fround((x || Math.fround((Math.hypot((x | 0), (Math.fround(Math.min(Math.fround(x), Math.fround(x))) | 0)) | 0)))) % Math.fround(Math.log(Math.cos(((( + ( + (Math.asinh(x) >>> 0))) || ( + Math.fround((( + x) !== (y | 0))))) | 0))))) : ( - Math.cos(((( ! x) <= Math.atan2(( - y), 2**53)) | 0))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -(2**53-2), -0, 0x080000001, -(2**53+2), 0x07fffffff, 0x0ffffffff, -0x100000001, -0x080000000, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, Math.PI, 0x100000001, -Number.MIN_VALUE, -0x07fffffff, -1/0, 0x080000000, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), 0.000000000000001, 1, -0x100000000, 2**53, 0]); ");
/*fuzzSeed-168297596*/count=1013; tryItOut("yield;const w = undefined;function window([x, {x: [\u000d, , {}], z, eval, NaN, x}, ], z = /*FARR*/[...eval(\"o0.v1 = -0;\") for each (window in [timeout(1800)]), (\nintern(x)), .../*MARR*/[{}, {}, (-1/0), {}, (-1/0), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, (-1/0), (-1/0), {}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), {}, {}, {}, (-1/0), (-1/0), {}, {}, {}, {}, {}, (-1/0), {}, (-1/0), (-1/0), {}, {}, {}, (-1/0), {}, {}, {}, (-1/0), {}, {}, {}, (-1/0), (-1/0), (-1/0), {}, (-1/0), {}, {}, {}, (-1/0), {}, (-1/0), (-1/0), {}, {}, {}, (-1/0), {}, (-1/0), {}, (-1/0), {}, (-1/0), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, (-1/0), {}, (-1/0), (-1/0), {}, {}, {}, {}, {}, {}, {}], , ...(function() { yield (((( + (Math.min(Math.fround((Math.asinh((((x < ((x ? x : Math.cbrt(1)) >>> 0)) >>> 0) | 0)) | 0)), x) ? ( + Math.sin(Math.trunc((x >>> 0)))) : ( + ((Math.abs((( ~ -0x07fffffff) || Math.fround(x))) >>> 0) ^ ( + ( - ( ! (Math.fround(((Math.hypot((x >>> 0), (x >>> 0)) >>> 0) && ((x >> x) | 0))) | 0)))))))) >>> 0) <= (Math.atan(Math.fround(Math.expm1((( ! (x >>> 0)) | 0)))) | 0)) >>> 0); } })()].sort(Math.min(x, x),  '' )) { return /\\3/y } /*ODP-3*/Object.defineProperty(v2, \"constructor\", { configurable: false, enumerable: false, writable: true, value: b1 });");
/*fuzzSeed-168297596*/count=1014; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( ! (( + (((( ~ 2**53+2) !== Number.MIN_SAFE_INTEGER) && ( ~ (mathy3((x | 0), Math.fround((y != (x | x)))) | 0))) > (Math.trunc(-0x080000000) >>> 0))) >>> 0))); }); testMathyFunction(mathy4, [0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, 1/0, 0/0, -0x07fffffff, -(2**53-2), -Number.MIN_VALUE, 2**53+2, 0x080000000, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, -(2**53+2), -0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 1, 0x100000001, -(2**53), 2**53, 0x100000000, -0x080000001, 2**53-2, 42, -0x100000001, -0, -0x0ffffffff, 0, -0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1015; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (/*FFI*/ff(((imul((i1), ((0xdf777187) ? (0x79d570bb) : (((-0x8000000)) ? (!(0xf3b53237)) : (/*FFI*/ff(((-35184372088833.0)), ((2147483649.0)))|0))))|0)), ((-9.0)), ((0x37fa7d39)), ((d0)))|0);\n    (Float64ArrayView[4096]) = ((d0));\n    {\n      d0 = (+(-1.0/0.0));\n    }\n    {\n      return ((((Float64ArrayView[2]))*-0xaf8df))|0;\n    }\n    i1 = (!((0xffffffff)));\n    {\n      i1 = (!(0xfa5a6c6e));\n    }\n    i1 = (window);\n    return (((!(0x14d40735))-(0x878459d6)-(i1)))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var tioduu = eval(\"/* no regression tests found */\"); ((function(x, y) { return 0; }))(); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=1016; tryItOut("if(true) o1.v1 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: Math.min(new RegExp(\"(?=(?:\\u0014)|\\\\S{4})(((?=\\\\f|\\\\B|\\\\W|\\\\b)))+?\", \"gim\"), x), sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-168297596*/count=1017; tryItOut("e0 + b2;");
/*fuzzSeed-168297596*/count=1018; tryItOut("this.zzz.zzz;");
/*fuzzSeed-168297596*/count=1019; tryItOut("let (uhsqul, jgenxc) { var tohkvg = new ArrayBuffer(0); var tohkvg_0 = new Uint8Array(tohkvg); tohkvg_0[0] = -20; a1[2]; }selectforgc(o1);");
/*fuzzSeed-168297596*/count=1020; tryItOut("/* no regression tests found */\nprint((x));\n");
/*fuzzSeed-168297596*/count=1021; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy1((((mathy1(Math.fround(Math.fround(Math.atanh(Math.fround(( + -Number.MAX_VALUE))))), Math.fround(mathy1(Math.fround(x), Math.fround(Math.fround(( - Math.fround(y))))))) >>> 0) ? ((( + ((x , Math.fround((Math.fround(Math.imul((-(2**53+2) >>> 0), (y >>> 0))) === Math.fround(( + y))))) | 0)) | 0) ? x : (Math.acos((x >>> 0)) | 0)) : ((((Math.log2((y | 0)) | 0) << ( + (Number.MAX_SAFE_INTEGER & x))) | 0) | ( ! Math.fround((Math.fround(x) ? Math.fround(( + (x | 0))) : Math.fround(x)))))) >>> 0), (( ! ( - ( + 0/0))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 1, Number.MAX_VALUE, 0/0, -0x07fffffff, -(2**53), Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 0.000000000000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000001, 2**53, -1/0, -0x080000001, -Number.MIN_VALUE, 2**53-2, -0, 0, -(2**53+2), -(2**53-2), 0x100000001, 42, Math.PI, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, 0x080000001]); ");
/*fuzzSeed-168297596*/count=1022; tryItOut("mathy5 = (function(x, y) { return (Math.min(((mathy0(mathy4(Math.fround(Math.pow(Math.fround((( + y) && (-0 | 0))), Math.fround(mathy0(y, x)))), ( + ( + mathy3(Math.fround(y), (1 | 0))))), ((x ? x : (Math.fround((0x07fffffff ^ -Number.MIN_VALUE)) | y)) | 0)) << (( + ( + y)) | 0)) >>> 0), Math.log(Math.fround(( + (x % (0x080000000 ? Math.min(x, ( ~ y)) : x)))))) >>> 0); }); testMathyFunction(mathy5, [2**53-2, Math.PI, -0x080000000, 0x0ffffffff, 0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, 0x07fffffff, 0x080000000, 2**53, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, 42, 1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, 0, 0/0, 0x080000001, 2**53+2, -0x07fffffff, 1, -Number.MAX_VALUE, -1/0, 0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0, -(2**53), Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=1023; tryItOut("print((4277));");
/*fuzzSeed-168297596*/count=1024; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.pow((((Math.sin((( ! x) | 0)) | 0) ? ( + ((Math.imul(y, y) >>> 0) | ((( + (( + mathy4(y, x)) >> ( + x))) >>> 0) === x))) : (mathy1(y, Math.fround(Math.hypot(Math.fround(x), Math.fround(Math.atan2(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround(0x07fffffff)))))) | 0)) | 0), (mathy2(( + Math.fround((Math.fround(Math.fround(((Math.pow((-Number.MIN_SAFE_INTEGER >>> 0), (x >>> 0)) >>> 0) ? -(2**53+2) : y))) >> 1))), Math.acos(y)) | 0))); }); testMathyFunction(mathy5, [-0x100000000, 1.7976931348623157e308, -0x080000001, 2**53-2, -0x080000000, -0x0ffffffff, -(2**53+2), 0x080000000, -(2**53-2), -(2**53), Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 2**53+2, 42, Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, 0x080000001, -Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, 0x100000001, -0x07fffffff, 0x100000000, 0/0]); ");
/*fuzzSeed-168297596*/count=1025; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((((((( - ((Math.fround((Math.fround(y) - y)) | 0) === y)) | 0) | 0) ? (Math.max((( ~ y) | 0), (( - x) | 0)) | 0) : ((Math.fround(Math.round(((Math.cos((x >>> 0)) >>> 0) / y))) >> Math.fround(Math.fround(( ~ Math.fround(y))))) | 0)) | 0) >>> ((Math.hypot(( + x), ((((-(2**53-2) >= y) | 0) == ((( + ( + x)) | 0) >>> 0)) | 0)) | 0) >>> 0)) | Math.fround(( + Math.fround(Math.fround(Math.sqrt(Math.fround(-Number.MIN_SAFE_INTEGER))))))); }); ");
/*fuzzSeed-168297596*/count=1026; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x07fffffff, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, 2**53+2, -(2**53), -0x080000001, -0x080000000, 0.000000000000001, 2**53, 1.7976931348623157e308, 1/0, -0x100000001, 0/0, -(2**53-2), 0, 0x100000001, 0x0ffffffff, -1/0, Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 42, 0x100000000, 1, Math.PI, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000]); ");
/*fuzzSeed-168297596*/count=1027; tryItOut("v2 = (f1 instanceof p0);");
/*fuzzSeed-168297596*/count=1028; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1029; tryItOut("this.e1[\"getUTCSeconds\"] = h0;");
/*fuzzSeed-168297596*/count=1030; tryItOut("for (var v of t0) { try { /*MXX2*/g1.String.prototype.normalize = e2; } catch(e0) { } /*MXX1*/this.o2 = this.g2.DataView.prototype.byteOffset; }");
/*fuzzSeed-168297596*/count=1031; tryItOut("t1 = g1.o1.t1.subarray(3, \"\\u97F9\");");
/*fuzzSeed-168297596*/count=1032; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.min(( + (((( + (x >>> 0)) | 0) == Math.fround(Math.cbrt(Math.fround(x)))) % ((Math.sin(((Math.fround((x , ( + ( ~ ( + 0x100000000))))) + ( + Math.fround(x))) >>> 0)) >>> 0) ? Math.fround(Math.clz32(-0)) : Math.hypot(( + Math.fround(( + y))), y)))), ( + (Math.hypot(((((((x ^ x) % (Math.exp(y) | 0)) | 0) ? (( + (( + y) / ( + x))) >>> 0) : (x >>> 0)) >>> 0) | 0), Math.hypot(( - -(2**53-2)), x)) | 0)))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 42, -0x080000001, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 0x080000000, 2**53, 0x07fffffff, -(2**53), 2**53+2, -0, 1, -0x100000001, -(2**53+2), -0x07fffffff, 0x100000000, Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, 0, -1/0, -0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 0x100000001, -Number.MAX_VALUE, 2**53-2, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=1033; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (mathy0((Math.fround((Math.fround(Math.atan2(Math.fround(Math.acosh(( + ( + (( + Math.fround(((y | 0) >> y))) , Math.fround(y)))))), Math.fround(Math.fround(( ! (Math.fround(Math.pow(mathy0(0x100000000, ( - y)), Math.fround((Math.log2(y) !== ( ! x))))) | 0)))))) > Math.fround(((( + ( ! (2**53-2 >>> 0))) ** (((x ? ( + Math.ceil(( + x))) : (Math.fround(Math.min((y | 0), y)) >>> 0)) >>> 0) >>> 0)) >>> 0)))) >>> 0), (Math.acosh((( ! ( + ( ! (Math.min(x, Math.PI) - y)))) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=1034; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    d0 = (-513.0);\n    switch (((((0xdfc06cb2))+((0xa6761f39) > (0x0))) >> ((0xffffffff)-(0xffffffff)))) {\n      case 0:\n        (Float32ArrayView[((0xb3e2453c)) >> 2]) = ((1125899906842625.0));\n        break;\n    }\n    {\n      i1 = (x);\n    }\n    return (((((0xb1ec957a)-(i1)) >> ((i1))) / (((i1)+(0x6b027f20)+(i1)) ^ ((0xb16a7792)+((d0) != (1.0009765625))))))|0;\n    {\n      i1 = (0xdd95db4);\n    }\n    i1 = (i1);\n    d0 = (Math.cbrt(11));\n    i1 = (!(!(i1)));\n    return ((0xfffff*(0xf8258821)))|0;\n    (Float32ArrayView[2]) = ((d0));\n    i1 = (0xa6cb51a3);\n    return ((((((i1)+(-0x8000000)+((((0xda4d7f61)) ^ ((-0x8000000))) <= (~((0xbfe318ff)+(0xfd2ac358)))))>>>((i1)*0x3b21e)))+(0xffa40fee)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, ['\\0', /0/, [0], (new String('')), (new Boolean(true)), NaN, '', (new Number(0)), 0, undefined, '/0/', objectEmulatingUndefined(), '0', null, (new Boolean(false)), [], 0.1, false, -0, true, ({valueOf:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return 0;}}), 1, ({toString:function(){return '0';}}), (new Number(-0))]); ");
/*fuzzSeed-168297596*/count=1035; tryItOut("mathy1 = (function(x, y) { return (Math.cos(Math.fround(Math.cbrt(( + mathy0(Math.pow(y, Math.atan2((Math.atan(x) >>> 0), x)), (Math.fround((Math.fround(x) * Math.fround(( ! (mathy0(y, x) | 0))))) >>> 0)))))) | 0); }); testMathyFunction(mathy1, [1, -1/0, -Number.MIN_VALUE, 42, -0x100000000, Math.PI, 0/0, 0x0ffffffff, -0x07fffffff, -0, 0x100000000, -(2**53-2), 2**53, 0x080000001, 2**53+2, -Number.MAX_VALUE, 1/0, -0x100000001, -(2**53), 0.000000000000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, 2**53-2, Number.MIN_VALUE, 0x100000001, -0x080000001, 1.7976931348623157e308, 0, 0x080000000, -(2**53+2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1036; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=1037; tryItOut("\"use strict\"; let a = (4277);t2.set(t0, ({valueOf: function() { g1.o1.a0[({valueOf: function() { t2 = new Uint32Array(x\n);return 14; }})] = a0;return 9; }}));");
/*fuzzSeed-168297596*/count=1038; tryItOut("/*RXUB*/var r = /\\xd1/g; var s = \"\\u00b1\"; print(s.search(r)); ");
/*fuzzSeed-168297596*/count=1039; tryItOut("e = Promise.prototype;var piqwnh = new SharedArrayBuffer(4); var piqwnh_0 = new Float64Array(piqwnh); print(piqwnh_0[0]); piqwnh_0[0] = 0; var piqwnh_1 = new Uint8Array(piqwnh); print(piqwnh_1[0]); var piqwnh_2 = new Uint8ClampedArray(piqwnh); piqwnh_2[0] = -28; var piqwnh_3 = new Uint16Array(piqwnh); piqwnh_3[0] = -3; var piqwnh_4 = new Float64Array(piqwnh); print(piqwnh_4[0]); for (var v of m2) { try { o0.o2.o1.o1.valueOf = (function mcc_() { var hlpiwk = 0; return function() { ++hlpiwk; if (/*ICCD*/hlpiwk % 10 != 7) { dumpln('hit!'); try { /*MXX2*/g2.String.prototype.startsWith = p0; } catch(e0) { } try { h1[\"call\"] = g2.a2; } catch(e1) { } t1.set(t0, 16); } else { dumpln('miss!'); try { for (var v of p2) { try { v2.__proto__ = v1; } catch(e0) { } try { s2 += 'x'; } catch(e1) { } s0 += s1; } } catch(e0) { } o2.__proto__ = e2; } };})(); } catch(e0) { } try { /*MXX2*/g2.Object.length = i0; } catch(e1) { } try { o0.a1.__proto__ = h1; } catch(e2) { } v1 = (o1 instanceof g1.a0); }print((4277));print(piqwnh_4[0]);");
/*fuzzSeed-168297596*/count=1040; tryItOut("\"use strict\"; /*oLoop*/for (let bymeri = 0, \"\\u1A8C\"; bymeri < 160; ++bymeri) { /*vLoop*/for (var ojijgh = 0; ojijgh < 43; ++ojijgh) { var c = ojijgh; Array.prototype.unshift.apply(a2, [o2, e2, v0, this.i1]); }  } ");
/*fuzzSeed-168297596*/count=1041; tryItOut("with({}) for(let w in  '' ) i0.toSource = function(y) { \"use strict\"; a0.shift(f0); };arguments = e;");
/*fuzzSeed-168297596*/count=1042; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((mathy2(Math.fround((Math.fround(Math.fround(( ~ Math.fround(y)))) * Math.fround(x))), Math.fround((x > (Math.atanh((x >>> 0)) >>> 0)))) | ( + Math.asinh(( + ( ~ Math.fround(y)))))) || Math.hypot(Math.fround((( ~ Math.hypot(0x080000000, x)) >>> 0)), Math.fround(( ! ((Math.fround(-Number.MIN_SAFE_INTEGER) < Math.fround(y)) | 0))))); }); testMathyFunction(mathy4, [-0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), 1, 2**53-2, 0x080000000, 2**53, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, 1/0, 2**53+2, -0x0ffffffff, 0/0, -(2**53), -Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, 0x07fffffff, -1/0, 1.7976931348623157e308, 0x100000000, -0, Math.PI, 0, 0x100000001]); ");
/*fuzzSeed-168297596*/count=1043; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.sqrt(( + (( + (( ! (( - Math.hypot((-0x100000001 & (y | 0)), (x >>> 0))) | 0)) >>> 0)) !== ( + (( - ((y ? (Math.hypot((x >>> 0), (y >>> 0)) | 0) : (x ? (0 ? x : Math.fround(x)) : Math.imul(-0x100000001, (x >>> 0)))) | 0)) >>> 0))))); }); testMathyFunction(mathy5, ['\\0', (function(){return 0;}), NaN, null, (new Number(0)), [], true, undefined, objectEmulatingUndefined(), '', (new String('')), (new Boolean(true)), ({valueOf:function(){return 0;}}), 0.1, 1, (new Number(-0)), /0/, 0, ({toString:function(){return '0';}}), '/0/', (new Boolean(false)), false, '0', -0, ({valueOf:function(){return '0';}}), [0]]); ");
/*fuzzSeed-168297596*/count=1044; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return ( - ((Math.atan2(Math.log1p((Math.pow(Math.fround(0x080000000), ((Math.imul(x, x) | 0) | 0)) | 0)), (mathy1(Math.atan2(y, x), ( + (x >> y))) >>> 0)) % y) , Math.tan(y))); }); ");
/*fuzzSeed-168297596*/count=1045; tryItOut("z = Math.hypot(9,  ''  %= window);print(z);");
/*fuzzSeed-168297596*/count=1046; tryItOut("\"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return Math.hypot((( - (Math.fround(mathy0(( + Math.log1p(( ! x))), (Math.pow((Math.pow(y, 0x07fffffff) >>> 0), (y >>> 0)) >>> 0))) | 0)) | 0), Math.min((( - (( + ((x | 0) ? ( + y) : x)) | 0)) | 0), Math.sin(Math.hypot(Math.imul(-0x100000000, y), ( + mathy1(( + x), ( + ( + (Math.fround(-0x100000000) - ( + y)))))))))); }); testMathyFunction(mathy2, [-0x080000001, -0, 0x100000001, 1/0, 0.000000000000001, 0x100000000, -1/0, -(2**53), -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 1, -0x100000001, 0x0ffffffff, 42, 2**53-2, 0, -Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -(2**53-2), 2**53, -(2**53+2), -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 0x080000000]); ");
/*fuzzSeed-168297596*/count=1047; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.pow(Math.fround((Math.fround(0x080000000) ? Math.fround(x) : ((y >>> 0) ? Math.fround(y) : (Math.fround(Math.sin(Math.fround(x))) >>> 0)))), ( + Math.atan2(y, (Math.atanh(Math.fround(Math.imul(Math.fround(x), Math.fround(x)))) >>> 0)))) ? Math.fround(( + (Math.min(-0x07fffffff, (Number.MAX_VALUE | 0)) % Math.log10((Math.atan2((Math.atan2(y, Number.MAX_VALUE) >>> 0), (y >>> 0)) | 0))))) : Math.fround(((Math.max((Math.fround(Math.imul((( + y) | 0), (x | 0))) ** -Number.MAX_VALUE), ((-Number.MAX_SAFE_INTEGER === Math.exp(Math.pow(x, y))) | 0)) | 0) / (((( - Math.fround(Math.cosh(( ~ y)))) | 0) + (Math.min(y, (((x >>> 0) | Math.fround(x)) >>> 0)) | 0)) | 0))))); }); ");
/*fuzzSeed-168297596*/count=1048; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -8388609.0;\n    var i3 = 0;\n    return +((-((+((3.022314549036573e+23))))));\n  }\n  return f; })(this, {ff: Set.prototype.entries}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0, false, ({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return 0;}}), '', undefined, '0', (new Boolean(false)), objectEmulatingUndefined(), null, (function(){return 0;}), true, /0/, 0, '/0/', [], [0], '\\0', 1, (new Boolean(true)), ({valueOf:function(){return '0';}}), (new String('')), (new Number(0)), NaN, 0.1]); ");
/*fuzzSeed-168297596*/count=1049; tryItOut("mathy2 = (function(x, y) { return (mathy1(Math.imul(mathy1(y, y), ((x >= y) | 0)), ( ~ ( ! ( + ( + y))))) == Math.atan2((Math.fround(Math.max(y, (( - -0x0ffffffff) | 0))) >>> 0), mathy1(Number.MIN_SAFE_INTEGER, (Math.sqrt(y) >>> 0)))); }); testMathyFunction(mathy2, [-0x080000001, 1, 0, -0x100000000, 1.7976931348623157e308, -(2**53), Number.MIN_VALUE, 0x100000000, 1/0, -0x07fffffff, -0x100000001, Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, 0x100000001, 0x07fffffff, -(2**53+2), 0x0ffffffff, -0x0ffffffff, 2**53+2, 0/0, -0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, 0x080000000, 0.000000000000001, 2**53, 0x080000001]); ");
/*fuzzSeed-168297596*/count=1050; tryItOut("mathy4 = (function(x, y) { return ( + (( + (((( ! (( + ( ~ x)) | 0)) | 0) ? x : y) !== (Math.log10((y | 0)) ? x : ( ~ ( + (Math.imul(-Number.MAX_VALUE, 2**53) === ( + x))))))) >> ( + ( + (Number.MIN_SAFE_INTEGER ** mathy2(((( - (Math.ceil(Math.atan2(x, x)) >>> 0)) >>> 0) >>> 0), (Math.atanh(( + ( ! ( + x)))) >>> 0))))))); }); testMathyFunction(mathy4, [0x100000001, -0x07fffffff, -0x0ffffffff, -Number.MAX_VALUE, 2**53+2, 0x080000001, 0, -0x080000000, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, -(2**53-2), 2**53, 1.7976931348623157e308, -0, 0x100000000, 2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 0x080000000, -(2**53+2), Number.MAX_VALUE, -Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, 1, -0x100000001, -0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000001]); ");
/*fuzzSeed-168297596*/count=1051; tryItOut("\"use strict\"; v1 = (f2 instanceof o0.g0);");
/*fuzzSeed-168297596*/count=1052; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var tan = stdlib.Math.tan;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 4.835703278458517e+24;\n    var i3 = 0;\n    d2 = (-140737488355329.0);\n    d2 = (-562949953421313.0);\n    i1 = (i3);\n    i3 = ((((~~(-8192.0)) % (((!((-2305843009213694000.0) <= (32769.0)))*-0x48d5a) | (-(/*FFI*/ff((((4277) ? (w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: /*wrap2*/(function(){ \"use strict\"; \"use asm\"; var kxmikh = \"\\uCB08\"; var prabwe = 27; return prabwe;})(), getOwnPropertyNames: RegExp.prototype.test, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: encodeURIComponent, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; })(-17), Function, (Function).bind((x) = 24,  \"\" ))) > (/*UUV2*/(x.atan2 = x.getUTCMilliseconds) - (Math.pow(arguments,  /x/ ))) : eval(\"/* no regression tests found */\", (void version(185))))), ((-4503599627370497.0)), ((1099511627777.0)), ((-2147483649.0)), ((-1048575.0)), ((2305843009213694000.0)), ((2.0)), ((-4503599627370497.0)), ((274877906943.0)), ((-68719476737.0)), ((-3.094850098213451e+26)), ((8193.0)), ((-1.0078125)), ((-35184372088832.0)), ((-34359738369.0)), ((18014398509481984.0)), ((-1.5)))|0))))>>>(-(i0))));\n    {\n      {\n        i3 = (i1);\n      }\n    }\n    {\n      switch (((Math.min(-7, 033)) | ((0x736d8bee)-(-0x8000000)-(0xfea74841)))) {\n        default:\n          {\n            i1 = ((0x775eb742) != (x));\n          }\n      }\n    }\n    (Float32ArrayView[4096]) = ((-17179869184.0));\n    i0 = (/*FFI*/ff(((((NaN)) / (new eval(\"c\")(false)))), ((~~(17592186044415.0))), ((((((((0xa839e5fe)) >> ((0xe63325b3)))) ? (!((0xc00e61d4) < (0xb27e93ec))) : (!((0x6b13b1ba) == (0x1eb985f9))))) << (((((0xe48b8ebb) >= (0x81386ad2))) ^ (((0x38e6b799) == (0x2a2329d7)))) % (~((i1)))))), ((i0)))|0);\n    i0 = (((-(0xfb083788)) << ((!(((0xec228749) % (((0x653388c0))>>>((0x393a205c))))))+((i0) ? (i0) : (i0)))) != (((i3)*-0xb9b4d) << ((/*FFI*/ff(((~(((-1152921504606847000.0) != (-2199023255553.0))-(i3)+((0x164c098c) >= (0x22abbba2))))), ((((0x815acb8e)) >> ((i0)))), ((-((-262145.0)))), ((((0xfce2251c)) & ((0xfead1710)))), ((67108864.0)), ((-576460752303423500.0)), ((1.5474250491067253e+26)), ((17592186044417.0)), ((-562949953421311.0)), ((590295810358705700000.0)), ((-6.189700196426902e+26)))|0)+((17.0) != (+tan(((((new Function(\"true;\")))(\"\\uA7E6\",  /x/g ).eval(\"true\")))))))));\n    i0 = ((((Int16ArrayView[((((x)) ? (i1) : (i3))*-0x7f566) >> 1]))|0));\n    return +((+((-32768.0))));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x0ffffffff, 0x07fffffff, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 0, 1.7976931348623157e308, 42, -Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, -Number.MAX_VALUE, 2**53+2, 1, -0x080000001, 0x080000001, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), 0x100000000, 2**53, 0x080000000, Math.PI, 0x0ffffffff, -0x080000000, -(2**53), -0x100000001, -0x100000000]); ");
/*fuzzSeed-168297596*/count=1053; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.tan((mathy0(( + Math.hypot(( + Math.tanh((((y | (x >>> 0)) >>> 0) ** Math.min(x, mathy0(y, (x | 0)))))), ( + ( + Math.asin(( + ( + Math.fround((Math.max(( + 1.7976931348623157e308), ( + y)) >>> 0))))))))), ( - ( + (x ^ x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), true, -0, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '0', 1, (new Number(-0)), null, false, [], NaN, '', [0], (function(){return 0;}), undefined, '/0/', (new Boolean(true)), (new Number(0)), objectEmulatingUndefined(), /0/, 0.1, (new Boolean(false)), (new String('')), 0, '\\0']); ");
/*fuzzSeed-168297596*/count=1054; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=1055; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-168297596*/count=1056; tryItOut("Array.prototype.forEach.call(a2, (function() { try { /*MXX2*/o1.o0.g1.OSRExit.length = b0; } catch(e0) { } try { a1.sort((function() { try { i1.next(); } catch(e0) { } Array.prototype.sort.call(a2, (function(j) { if (j) { v1 = t0.byteOffset; } else { try { v0 = (m0 instanceof o2.v1); } catch(e0) { } a1[18] = (new (new Function(\"a1 = Array.prototype.slice.apply(a0, [o2.h0, b2]);\"))(false)); } })); return b0; }), delete x.w.eval(\"/* no regression tests found */\"), this.b0); } catch(e1) { } for (var p in m2) { try { print(f0); } catch(e0) { } v0 = g0.eval(\"/* no regression tests found */\"); } return e1; }));");
/*fuzzSeed-168297596*/count=1057; tryItOut("\"use strict\"; Array.prototype.shift.apply(a2, [this.f1, t1, i2]);");
/*fuzzSeed-168297596*/count=1058; tryItOut("/*RXUB*/var r = /(?!(?!(?!(?:\\W))+?(?:(?=.)|.|\\d)|(?:(?=\\b|\\B){4,4194308}))*|\\3{0,1}|\\2\\3{1})/i; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-168297596*/count=1059; tryItOut("e0.has(o1.g1);\n/*ADP-1*/Object.defineProperty(a1, 10, ({configurable: false, enumerable: true}));\n");
/*fuzzSeed-168297596*/count=1060; tryItOut("Array.prototype.unshift.call(a0, o2, v0, this.o0);");
/*fuzzSeed-168297596*/count=1061; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-168297596*/count=1062; tryItOut("var byslcm = new ArrayBuffer(4); var byslcm_0 = new Float32Array(byslcm); byslcm_0[0] = 2; var byslcm_1 = new Float32Array(byslcm); byslcm_1[0] = 20; var byslcm_2 = new Int32Array(byslcm); print(byslcm_2[0]); byslcm_2[0] = -28; var byslcm_3 = new Uint8ClampedArray(byslcm); s0 = s1.charAt(({valueOf: function() { print(Math);return 14; }}));Object.defineProperty(this, \"v1\", { configurable: false, enumerable: 4,  get: function() {  return undefined; } });return  /x/ ;b0 = g1.objectEmulatingUndefined();s0 += s1;throw  /x/ ;print(byslcm_2);v1 = true;s0 += s2;print(byslcm_3);");
/*fuzzSeed-168297596*/count=1063; tryItOut("o0.h2 + e0;");
/*fuzzSeed-168297596*/count=1064; tryItOut("\"use strict\"; if((x % 65 == 9)) {with(x)v1 = g2.runOffThreadScript();/*MXX3*/g1.RegExp.length = g1.RegExp.length;/*ADP-3*/Object.defineProperty(a1, (Object.defineProperty(y, \"log2\", ({get: (1 for (x in [])), set: window.revocable(), configurable: (x % 4 != 1)}))), { configurable: true, enumerable: true, writable: true, value: 7 }); }");
/*fuzzSeed-168297596*/count=1065; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1066; tryItOut("o0.a1.shift(h1, f1);");
/*fuzzSeed-168297596*/count=1067; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (((Math.log((y ? (x - Math.fround(x)) : ( + (( + Math.fround(Math.atan2(( + y), Math.fround(x)))) ? ( + Math.hypot(y, y)) : ( + -(2**53+2)))))) | 0) === ((Math.trunc((x | 0)) < ( + Math.max(y, -Number.MAX_VALUE))) >>> 0)) | 0); }); testMathyFunction(mathy0, [-1/0, -(2**53-2), 1, 0, 0x100000000, 0x07fffffff, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 1/0, 0/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 0x0ffffffff, 1.7976931348623157e308, 2**53-2, 0x080000000, 0.000000000000001, -0x080000000, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, -(2**53), -(2**53+2), -0x100000001, 0x080000001, -0, 0x100000001]); ");
/*fuzzSeed-168297596*/count=1068; tryItOut("mathy4 = (function(x, y) { return (Math.fround((( + ( ! ( + (( + ((Math.tan(Math.cbrt((Math.asinh(( + x)) >>> 0))) >>> 0) | 0)) | 0)))) || (Math.min((( + (( + (Math.abs(mathy3(y, x)) | 0)) ? -(2**53-2) : x)) >>> 0), (Math.fround(( ! Math.fround(Math.pow(mathy1((Math.round(y) | 0), (y | 0)), Math.fround(2**53-2))))) >>> 0)) >>> 0))) ? ( ~ ((Math.fround(( ~ ( + ( ~ x)))) < Math.hypot(y, x)) >>> 0)) : (Math.acosh(2**53) * ( + Math.round((( + (( ~ x) | 0)) >>> 0))))); }); testMathyFunction(mathy4, /*MARR*/[-Infinity, -Infinity, null, -Infinity, null, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, null, {}, {}, {}, {}, null, -Infinity, null, -Infinity]); ");
/*fuzzSeed-168297596*/count=1069; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((( + ( ~ Math.hypot(x, (Math.sign(y) | 0)))) | 0) == (((Math.ceil((Math.fround(Number.MAX_VALUE) > ((Math.imul(y, (( + x) > ( + y))) | 0) - Number.MIN_VALUE))) | 0) > ( + x)) | 0)) | 0); }); testMathyFunction(mathy1, [0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53, 0/0, Math.PI, Number.MAX_VALUE, -0x100000000, -0x100000001, -0x0ffffffff, 0x080000000, -(2**53+2), 0x0ffffffff, -0x07fffffff, -0, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), 1.7976931348623157e308, 0x080000001, 0x100000001, 1, -Number.MAX_VALUE, -0x080000000, -1/0, 42, 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, 0, 2**53+2]); ");
/*fuzzSeed-168297596*/count=1070; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return Math.log1p((Math.pow((((Math.pow(( + (( + -(2**53-2)) ? ( + x) : -0)), (-Number.MAX_VALUE | 0)) >>> 0) ? (((y | 0) && ( + y)) >>> 0) : ( + (Math.fround(x) - x))) >>> 0), (( ~ ( ! y)) >>> 0)) <= Math.fround((Math.hypot(( + ( ! Math.fround(Math.pow(Math.fround(( + Math.atan2(( + 0x100000001), (y >>> 0)))), Math.fround(Math.fround(Math.pow(( + 2**53+2), (-0x07fffffff | 0)))))))), ( + Math.atanh(( + (Math.pow((Math.sign((1/0 >>> 0)) >>> 0), ((y >= Number.MAX_VALUE) >>> 0)) >>> 0))))) >>> 0)))); }); testMathyFunction(mathy0, [-0x100000000, Number.MAX_SAFE_INTEGER, -0, 0/0, -(2**53-2), 1, Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, -(2**53+2), -0x0ffffffff, Math.PI, 2**53+2, 0x100000000, 1/0, -(2**53), -0x080000000, 0x07fffffff, -1/0, 0x0ffffffff, 2**53, 2**53-2, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=1071; tryItOut("/*RXUB*/var r = function (z) { yield \"\\u22BB\" } ; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-168297596*/count=1072; tryItOut("mathy0 = (function(x, y) { return Math.atan2((( - (Math.max(((2**53-2 > (y >>> 0)) >>> 0), Math.atan2(Math.max(x, (x | Math.pow(y, y))), Math.fround(y))) >>> 0)) >>> 0), ( + ( - Math.min((( + ( ~ y)) >>> 0), Math.round((( ! (Math.atan(( + ((0x080000000 >>> 0) ? ( + x) : y))) | 0)) | 0)))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 2**53, 1/0, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 1, -Number.MAX_VALUE, 42, -0x080000001, Math.PI, 0.000000000000001, -1/0, 2**53+2, 0x080000000, -0x07fffffff, Number.MAX_VALUE, -0x100000000, 2**53-2, 0x100000000, -0x0ffffffff, 0x080000001, 0x0ffffffff, 0/0, -0, -(2**53-2), 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=1073; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1074; tryItOut("\"use strict\"; b = Math.imul( \"\" , -2), x;Array.prototype.forEach.apply(this.a0, [(function() { a1.unshift(); return o2; }), o1]);");
/*fuzzSeed-168297596*/count=1075; tryItOut("");
/*fuzzSeed-168297596*/count=1076; tryItOut("s0 += 'x';");
/*fuzzSeed-168297596*/count=1077; tryItOut("/*bLoop*/for (var pjlsoy = 0, odeuxe; pjlsoy < 1; ++pjlsoy) { if (pjlsoy % 5 == 4) { print(x); } else { v2 = new Number(o1.p0); }  } ");
/*fuzzSeed-168297596*/count=1078; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-168297596*/count=1079; tryItOut("mathy5 = (function(x, y) { return Math.imul(Math.pow((Math.asinh(( - ((mathy1(( + (( + y) != ( + x))), y) >>> 0) | 0))) >>> 0), (( ! (x === 0/0)) >>> 0)), ( + ( + let (window, ithvmw, czzwqi, ktgrxa, x, shnlxg, eccxzf, a) ({a2:z2}).eval(\"/* no regression tests found */\")))); }); testMathyFunction(mathy5, ['0', [0], (new Boolean(true)), false, '', ({valueOf:function(){return 0;}}), undefined, 0, (new Number(-0)), [], (function(){return 0;}), -0, NaN, 1, (new String('')), '\\0', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), null, objectEmulatingUndefined(), (new Boolean(false)), 0.1, (new Number(0)), '/0/', /0/, true]); ");
/*fuzzSeed-168297596*/count=1080; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.expm1(Math.fround(mathy2(Math.fround(Math.pow(Math.fround(((( + ( ! ( + Math.fround(( + Math.fround(-0)))))) * (-1/0 >>> 0)) >>> 0)), Math.fround(x))), Math.fround(Math.hypot(Math.hypot(Math.fround(x), -0x07fffffff), y)))))); }); ");
/*fuzzSeed-168297596*/count=1081; tryItOut("print(x);print(true);");
/*fuzzSeed-168297596*/count=1082; tryItOut("e2.add(e1);");
/*fuzzSeed-168297596*/count=1083; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul(( - (Math.min((2**53+2 ? Math.pow(x, Math.fround(mathy0(Math.fround(x), Math.fround(Number.MAX_SAFE_INTEGER)))) : Number.MIN_VALUE), (((((Math.imul(1.7976931348623157e308, (y | 0)) | 0) >>> 0) >> x) >>> 0) < (y >>> 0))) >>> 0)), ((Math.fround((Math.fround(-(2**53+2)) < 1)) , Math.fround(Math.max((0x100000000 ? ( ! x) : 0.000000000000001), (y ? y : y)))) == Math.fround((Math.max((mathy1(y, y) >>> 0), (Math.min(x, Math.fround(mathy0(Math.fround(Math.fround((x <= x))), Math.fround(x)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 2**53, 0/0, 1.7976931348623157e308, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 42, -0x0ffffffff, 0.000000000000001, -0, Number.MIN_VALUE, -0x080000000, 1, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, 1/0, -(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 0x07fffffff, -(2**53), 0x080000001, -(2**53+2), 0x100000001, -0x100000000, -1/0, 0]); ");
/*fuzzSeed-168297596*/count=1084; tryItOut("\"use strict\"; b2.toSource = (function() { try { t2 = new Uint8Array(v0); } catch(e0) { } try { v2 = t0.length; } catch(e1) { } try { ; } catch(e2) { } Array.prototype.shift.apply(a2, []); return b2; });");
/*fuzzSeed-168297596*/count=1085; tryItOut("a1.splice(0, v0, o2.o2, (void options('strict')).eval(\"return [({})];\\nvar v1 = g2.eval(\\\"/* no regression tests found */\\\");\\n\"), o1);");
/*fuzzSeed-168297596*/count=1086; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + ((((x > Math.fround(Math.cbrt(Math.fround(x)))) ? Math.imul(Math.fround((y ^ Math.fround(x))), Math.pow(0/0, ((x | 0) || y))) : x) && Math.fround(( - Math.fround(y)))) >>> 0)); }); testMathyFunction(mathy1, [0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, -(2**53), 0x07fffffff, 1/0, Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -0, -1/0, 0x100000001, 0x080000001, 1, 0, -(2**53+2), 2**53, -0x080000000, -0x080000001, 0/0, Number.MAX_VALUE, 42, 2**53+2, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1087; tryItOut("if(true) {print(window);print( /x/ ); }v1 = new Number(b1);");
/*fuzzSeed-168297596*/count=1088; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1089; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-168297596*/count=1090; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return ((( + ((( ~ Math.max((0x100000001 | 0), (0x080000001 | 0))) | 0) ? (((( + (( + y) == ( + y))) !== ((Math.asinh(Math.min(-(2**53+2), y)) ^ ( + ( ! ( + y)))) >>> 0)) | 0) | 0) : ((( ! Math.fround(Math.fround((Math.fround(x) % Math.fround(-0x0ffffffff))))) | 0) | 0))) === (Math.cos((Math.trunc((( + x) | 0)) | 0)) | 0)) >> ((((Math.atan2(( + ( + 2**53-2)), ( + x)) - Math.asin(Math.tanh(Math.pow(0.000000000000001, (Math.tanh(x) >>> 0))))) >>> 0) ** ((1/0 / -0x100000000) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, Math.PI, 1, 1/0, -0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, 0/0, 2**53, Number.MIN_VALUE, 0x07fffffff, -0x080000001, -(2**53), -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, 2**53+2, 2**53-2, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, -0x0ffffffff, 0x080000000, 0.000000000000001, 1.7976931348623157e308, 0x080000001, -0, 0x100000000, -(2**53+2), 0]); ");
/*fuzzSeed-168297596*/count=1091; tryItOut("mathy0 = (function(x, y) { return ( ! ( + (( + Math.tanh(( + Math.min(y, (Math.min((Math.hypot((Math.max(( + 0x100000000), ( + x)) | 0), y) | 0), ( + (Math.log1p(x) | 0))) | 0))))) > Math.abs((Math.pow((x | 0), (x | 0)) | 0))))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, 2**53+2, -(2**53-2), 1.7976931348623157e308, -0x100000001, -0, 0x100000001, 42, Math.PI, -(2**53), 1, -0x100000000, 0/0, -1/0, -0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 0, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000]); ");
/*fuzzSeed-168297596*/count=1092; tryItOut("mathy3 = (function(x, y) { return (((mathy2(( + ((Math.acos(( + y)) | 0) != Math.fround(Math.pow(Math.fround((Math.max(y, y) ? y : x)), Math.fround(1.7976931348623157e308))))), (x ** x)) > ((Math.max(((Math.imul((y | 0), (x | 0)) | 0) | 0), ( + (Math.acosh((x | 0)) | 0))) | 0) >>> 0)) | 0) >= ( + mathy0(( + ( + (( ! x) ^ x))), Math.fround(x)))); }); ");
/*fuzzSeed-168297596*/count=1093; tryItOut("\"use strict\"; v2 = r1.test;");
/*fuzzSeed-168297596*/count=1094; tryItOut("print(Math.imul(23, -23));");
/*fuzzSeed-168297596*/count=1095; tryItOut("\"use strict\"; v0 = a2.length;");
/*fuzzSeed-168297596*/count=1096; tryItOut(";");
/*fuzzSeed-168297596*/count=1097; tryItOut("with({} = function ([y]) { }){/*tLoop*/for (let d of /*MARR*/[new Number(1), new Number(1)]) { i1.valueOf = f2; }L:switch(\u0009x) { default: break; /*tLoop*/for (let x of /*MARR*/[new Boolean(false), new Number(1), new Boolean(false), false, new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1)]) { a2.forEach((function mcc_() { var nlydcv = 0; return function() { ++nlydcv; if (nlydcv > 4) { dumpln('hit!'); Object.defineProperty(g2, \"o0.g0.s0\", { configurable: false, enumerable: true,  get: function() {  return new String; } }); } else { dumpln('miss!'); try { /*MXX1*/o2 = g2.Date.prototype.toGMTString; } catch(e0) { } try { b0 = new ArrayBuffer(11); } catch(e1) { } /*MXX3*/g1.WeakSet.prototype.add = g1.WeakSet.prototype.add; } };})(), i0); }case  \"\" : break;  } }");
/*fuzzSeed-168297596*/count=1098; tryItOut("a0 = arguments;");
/*fuzzSeed-168297596*/count=1099; tryItOut("mathy0 = (function(x, y) { return ( - ( ! ((( + (x >>> 0)) >>> 0) % ((((x >>> 0) === (((( + x) === ( + Math.log2(1/0))) >>> Math.trunc(((-(2**53-2) | x) | 0))) >>> 0)) >>> 0) | 0)))); }); testMathyFunction(mathy0, [0x080000001, 1.7976931348623157e308, 0/0, 0x080000000, 0.000000000000001, 0x100000000, 0x07fffffff, 0, 42, -1/0, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, -0x100000001, -(2**53+2), -0x080000001, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000001, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, -(2**53), -Number.MIN_VALUE, 1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, -0x080000000, 2**53]); ");
/*fuzzSeed-168297596*/count=1100; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -8796093022208.0;\n    i0 = (0xf91d48ef);\n    d2 = (((-0x514f109) % (imul((0xa5ea636e), ((-2097151.0) == (-1025.0)))|0)));\n    return ((((((0x81ce61b5)) << ((0xc1d66407) / ((-(0xf94e549d))>>>((0x460077b4) % (-0x8000000))))))-(-0x8000000)+(!(!((((0xfe1952f8))>>>(0x4b2ed*((0xf8e57f18) ? (0x9d22f7) : (-0x8000000)))))))))|0;\n    return (((0x62494a06) % (((i0)+(/*FFI*/ff(((+(0.0/0.0))), ((~((0x578950a6)-(-0x8000000)))), ((((-0x8000000)) & ((0xffffffff)))), ((-2.3611832414348226e+21)), ((-8192.0)), ((33.0)), ((147573952589676410000.0)), ((-9223372036854776000.0)), ((2251799813685247.0)))|0)+((((0x1b68c227)) >> (((0x7fffffff))+(0x8c2d4c8b)))))>>>((i0)-((((0x4f347637)-(0xcf29aa1d))>>>((0xbbe8907c))))+((0xdd9c2b76))))))|0;\n    {\n      d2 = (d1);\n    }\n    {\n      (Uint32ArrayView[4096]) = ((((!((+(-1.0/0.0)) > (((-1.001953125)) / ((-2.4178516392292583e+24)))))+(0xfe65f07d))>>>(((((0x7e113e64))|0) != (((0x92a82317)) & ((0x4e8ca199))))+(i0)+(0xe4c6c5de))) % ((((0xffb7d5d4) ? (i0) : (!(i0)))+(0x8ad767ec))>>>((i0)+(0x4fd74510))));\n    }\n    return ((apply =  '' .watch(\"__count__\", x)))|0;\n  }\n  return f; })(this, {ff: z -= window}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [true, (new Number(0)), (new Number(-0)), (new Boolean(true)), 0, 0.1, /0/, '0', [0], (function(){return 0;}), ({valueOf:function(){return 0;}}), (new String('')), false, '/0/', '\\0', -0, NaN, ({toString:function(){return '0';}}), undefined, null, (new Boolean(false)), '', [], ({valueOf:function(){return '0';}}), 1, objectEmulatingUndefined()]); ");
/*fuzzSeed-168297596*/count=1101; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ~ Math.sqrt(Math.exp(Math.tanh(( + y))))); }); testMathyFunction(mathy3, /*MARR*/[(-1/0), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), (-1/0), (-1/0), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), (-1/0)]); ");
/*fuzzSeed-168297596*/count=1102; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s1; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=1103; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(Math.fround(Math.hypot(Math.fround((x - ( + (x | 0)))), ((( - Math.fround(x)) ** mathy1(y, 1.7976931348623157e308)) / (( + (( + Math.max(-0x080000000, mathy1((y | 0), (-Number.MIN_VALUE >>> 0)))) | 0)) >>> 0)))), Math.fround(Math.log((Math.hypot(Math.fround(( ! (( + (y >>> 0)) >>> 0))), Math.fround(x)) | 0)))); }); testMathyFunction(mathy2, [0.000000000000001, -(2**53-2), -1/0, Math.PI, -0x100000000, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, 0x0ffffffff, 0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), 1/0, 2**53-2, 0x100000000, -0x080000000, 0x080000001, 2**53, 42, -0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, -Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=1104; tryItOut("mathy5 = (function(x, y) { return (Math.atan2((mathy2(( ! (x << (( ! Math.fround(( ~ Math.fround(x)))) >>> 0))), (Math.atan((( + ( - Math.fround(Math.atan2((x >>> 0), x)))) >>> 0)) >>> 0)) | 0), (mathy2(( + ( + ( + Math.fround((Math.fround(y) - Math.fround(mathy0(( + (Math.asin(0) - ( + y))), ( + mathy4(( + x), ( + x)))))))))), Math.max((-0x100000001 | 0), ( + Math.pow(((-0x0ffffffff && ( + Math.pow(( + (( ! Math.fround(-0x0ffffffff)) >>> 0)), ( + x)))) >>> 0), (x ** (Math.imul((Math.sign((y >>> 0)) >>> 0), x) >>> 0)))))) >>> 0)) | 0); }); ");
/*fuzzSeed-168297596*/count=1105; tryItOut("mathy3 = (function(x, y) { return (Math.max((((Math.hypot(y, ( + (x >= (mathy1(y, y) | 0)))) >>> 0) << Math.fround(mathy0((Math.fround(((Math.fround((Math.fround(Math.fround(Math.pow(x, (x >>> 0)))) ? Math.fround((Math.pow(y, Math.fround(-0)) | 0)) : Math.fround(x))) | 0) !== ((( ! (Math.expm1(-Number.MIN_VALUE) | 0)) | 0) >>> 0))) >>> 0), Math.fround(Math.tanh(((Math.fround(mathy2(Math.fround((x === y)), Math.fround(y))) | 0) ? x : ( ! x))))))) >>> 0), (( ~ ( + (( + x) || (mathy2((2**53+2 << y), Math.fround(((x >>> 0) << x))) >>> 0)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=1106; tryItOut("\"use strict\"; print(this.p0);");
/*fuzzSeed-168297596*/count=1107; tryItOut("testMathyFunction(mathy2, [1, Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0x080000000, -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, 42, 0, 1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 2**53+2, -0x100000000, -0x080000000, Math.PI, 2**53, Number.MIN_VALUE, -0x080000001, -(2**53), -0, 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, -Number.MIN_VALUE, 0/0, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=1108; tryItOut("mathy1 = (function(x, y) { return (Math.abs((mathy0(((((y , ( ! x)) | 0) && ( - Math.PI)) >>> 0), (Math.atan2((mathy0((Math.max(x, (((Math.fround(y) , Math.fround(-1/0)) | 0) >>> 0)) >>> 0), Math.fround(( + Math.acosh((((-0 / (2**53+2 >>> 0)) >>> 0) | 0))))) | 0), (y | 0)) | 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=1109; tryItOut("/*infloop*/for(var (eval).call(x, ).x in (void shapeOf([d]))) {print((4277)); }function y(x = NaN >>>= /(?=(?:\u46a2))/gim\n, x) { \"use strict\"; f0(p0); } t0[6];");
/*fuzzSeed-168297596*/count=1110; tryItOut("Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-168297596*/count=1111; tryItOut("{ sameZoneAs: (4277) }");
/*fuzzSeed-168297596*/count=1112; tryItOut("/*tLoop*/for (let b of /*MARR*/[ '' ,  '' ,  '' , x,  'A' , objectEmulatingUndefined(), new Number(1),  '' , x, new Number(1),  '' , x,  'A' , x, objectEmulatingUndefined(),  '' ,  '' ,  '' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), x, x, x, x, x, x, x, x, x, x,  '' ,  'A' , new Number(1),  '' , objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(),  'A' , new Number(1),  'A' ,  'A' , x,  '' ,  '' , new Number(1),  'A' , new Number(1),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , new Number(1),  '' ,  '' , x, x,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), x,  '' , objectEmulatingUndefined(), x,  'A' ,  'A' ,  '' , x, objectEmulatingUndefined(),  'A' , x, objectEmulatingUndefined(), new Number(1),  'A' ,  'A' , new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined()]) { Object.prototype.unwatch.call(h2, \"a\"); }");
/*fuzzSeed-168297596*/count=1113; tryItOut("e1.add(m1);");
/*fuzzSeed-168297596*/count=1114; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-168297596*/count=1115; tryItOut("x;");
/*fuzzSeed-168297596*/count=1116; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh(Math.atan((( + Math.atan2(Number.MIN_SAFE_INTEGER, (( ~ (x | 0)) | 0))) - (((y | 0) % ((( - ((( ! (x >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0)))); }); ");
/*fuzzSeed-168297596*/count=1117; tryItOut("\"use strict\"; /*RXUB*/var r = /[\\w\\xe5]/gyim; var s = \"0\"; print(s.replace(r,  \"\" )); ");
/*fuzzSeed-168297596*/count=1118; tryItOut("\"use strict\"; h1.getPropertyDescriptor = f2;");
/*fuzzSeed-168297596*/count=1119; tryItOut("for(z = ({w: \"\\uB854\".unwatch(\"a\") }) in new RegExp(\"(?![^]{4})|\\\\x01+\", \"gy\") ? -2 : Math//h\n.valueOf(\"number\")) p0 = Proxy.create(h0, s2);");
/*fuzzSeed-168297596*/count=1120; tryItOut("a0.reverse();");
/*fuzzSeed-168297596*/count=1121; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.fround((Math.fround(Math.fround(( ! Math.fround((( + 0.000000000000001) != ( ! (( + Math.fround(y)) >>> 0))))))) ? Math.fround(((((-0x080000000 === (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) ? Math.hypot((x ? ( + x) : Math.expm1(y)), y) : Math.fround(Math.imul(( + (( + y) < x)), Math.cbrt(( + ( ~ ( + y))))))) >>> 0)) : ( ! mathy2(42, (Math.fround((y ? y : ( + ( ! 0x100000000)))) | 0))))) <= Math.max(( ! Math.acos((Math.min((-(2**53) >>> 0), -Number.MIN_SAFE_INTEGER) | 0))), ( + ( + ( + -Number.MAX_SAFE_INTEGER))))); }); testMathyFunction(mathy4, ['', (new String('')), objectEmulatingUndefined(), (new Number(-0)), true, (new Number(0)), (function(){return 0;}), 0, -0, null, [0], '\\0', ({valueOf:function(){return 0;}}), [], false, /0/, undefined, ({valueOf:function(){return '0';}}), 1, NaN, (new Boolean(true)), 0.1, ({toString:function(){return '0';}}), '/0/', '0', (new Boolean(false))]); ");
/*fuzzSeed-168297596*/count=1122; tryItOut("m1.has(p1);");
/*fuzzSeed-168297596*/count=1123; tryItOut("testMathyFunction(mathy4, /*MARR*/[ /x/ , 0x99, 0x99, true, true, 0x99, true, true, 0x99, true, true,  /x/ , 0x99,  /x/ ,  /x/ , true, true, 0x99, 0x99, 0x99,  /x/ , true, true, 0x99, 0x99, 0x99, true, 0x99, true, true, 0x99,  /x/ , 0x99, true,  /x/ , true,  /x/ ,  /x/ , 0x99, true,  /x/ , 0x99, 0x99,  /x/ , 0x99,  /x/ , 0x99,  /x/ , true,  /x/ , true,  /x/ ,  /x/ ,  /x/ , true,  /x/ , 0x99,  /x/ , true,  /x/ , true]); ");
/*fuzzSeed-168297596*/count=1124; tryItOut("/*infloop*/M: for ((this)(d) of \"\\u1B3A\") {-16;(new RegExp(\"\\\\1+?|(?![^])|[^\\\\f\\\\w{x]\\u00ac|\\\\\\u00ef\\\\B{0,0}|(\\u00de)*\", \"ym\")); }");
/*fuzzSeed-168297596*/count=1125; tryItOut("s2 += 'x';\n/*MARR*/[new String(''), new String(''), new String(''), new Number(1), new String(''), objectEmulatingUndefined(), function(){}, new String(''),  'A' , new Number(1), objectEmulatingUndefined(),  'A' , new Number(1)].filter;\n");
/*fuzzSeed-168297596*/count=1126; tryItOut("this.o2 = {};");
/*fuzzSeed-168297596*/count=1127; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(Math.cos((Math.exp((Math.sqrt((Math.fround((Math.fround(( + (( + x) ^ ( + x)))) == Math.fround((y ^ x)))) | 0)) | 0)) >>> 0))), Math.fround(( ! Math.acos(( ~ ( + x))))))); }); testMathyFunction(mathy0, /*MARR*/[function(){},  /x/ ]); ");
/*fuzzSeed-168297596*/count=1128; tryItOut("mathy4 = (function(x, y) { return (Math.trunc(((( + mathy1(( + Math.fround(Math.pow(((x >>> 0) ? ( - y) : (0.000000000000001 >>> 0)), y))), x)) >= Math.pow(mathy1((Math.fround(Math.acos(Math.fround(-(2**53+2)))) | 0), Math.fround(Math.sqrt(Math.fround(0x100000001)))), x)) | 0)) | (Math.fround(( + ( + (( + Math.clz32((Math.fround(( ! x)) >>> 0))) ** (Math.hypot(Math.fround(x), x) | 0))))) >>> 0)); }); ");
/*fuzzSeed-168297596*/count=1129; tryItOut("\"use strict\"; o0.b0.__iterator__ = (function(a0, a1, a2, a3, a4, a5, a6, a7) { a2 = 1 + a7; a2 = a2 / a5; a1 = 6 - 1; print(a6); var r0 = a6 - 1; var r1 = a2 | a4; var r2 = 9 + 5; var r3 = 6 % 0; a5 = a2 ^ a6; var r4 = a6 % a1; r3 = 2 / a4; var r5 = a5 & a5; a5 = 2 / a4; var r6 = a7 | r4; var r7 = 6 * a6; var r8 = 7 & a2; var r9 = 8 % 0; var r10 = 0 + a3; a0 = 8 % a0; var r11 = 0 % 3; r8 = a2 ^ r0; var r12 = a6 % 2; a1 = r7 ^ a4; r5 = 8 + a2; var r13 = r10 | a5; var r14 = a2 + a4; var r15 = r0 / a4; var r16 = a7 % a7; var r17 = r3 - r5; r2 = r1 + a2; var r18 = r15 ^ a7; var r19 = r9 % r2; var r20 = a4 / 8; var r21 = r10 - r5; var r22 = r2 & r19; print(a1); var r23 = 2 * 7; var r24 = r23 / x; var r25 = r16 ^ r17; var r26 = 9 ^ 1; var r27 = r25 * r12; a6 = r12 / r24; var r28 = r5 % r22; r18 = 0 % 1; var r29 = r15 * r22; var r30 = a6 & a6; var r31 = 9 - r17; var r32 = r24 % 3; var r33 = 3 ^ 1; var r34 = 9 % 1; var r35 = r6 | 5; r13 = a7 / r30; var r36 = r28 ^ 3; var r37 = 7 ^ r13; var r38 = r21 ^ 0; var r39 = a6 | r36; var r40 = 8 + r29; var r41 = 2 - 3; var r42 = r35 + r20; var r43 = 5 | r17; var r44 = r26 & r20; var r45 = r7 + r1; var r46 = r11 + x; var r47 = 3 + r43; return a5; });");
/*fuzzSeed-168297596*/count=1130; tryItOut("/*RXUB*/var r = new RegExp(\"(\\u0012|W*?|\\\\W\\\\b{1}|(?![^]+?(?![^]))(?:..)*?+*)*?\", \"gi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-168297596*/count=1131; tryItOut("mathy1 = (function(x, y) { return (Math.trunc((((((mathy0(Math.tan(y), ((x ? Math.acosh((( ! y) >>> 0)) : ( + x)) | 0)) >>> 0) >>> 0) / ((Math.hypot((Math.cosh(x) >>> 0), x) >> (Math.asin(((x * Math.pow(y, Number.MAX_VALUE)) | 0)) | 0)) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[{}, -Number.MAX_SAFE_INTEGER, {}, new Boolean(false), new Boolean(false), new Boolean(false), -Number.MAX_SAFE_INTEGER,  '' , -Number.MAX_SAFE_INTEGER, new Boolean(false), new Boolean(false), new Boolean(false), -Number.MAX_SAFE_INTEGER,  '' , new Boolean(false),  '' , {},  '' , {}, -Number.MAX_SAFE_INTEGER, {}]); ");
/*fuzzSeed-168297596*/count=1132; tryItOut("\"use strict\"; g0.a0.push(p1);");
/*fuzzSeed-168297596*/count=1133; tryItOut("testMathyFunction(mathy5, /*MARR*/[(x), false, (x), (0/0), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (x), (0/0), (x), false, (x), false, (x), (0/0), (x), (x), (0/0), (0/0), false, false, false, (0/0), false, (x), (x), false, (x), (x), (x), (x), (x), (x), (0/0), (0/0), (0/0), false, false, (0/0), (x), false, false, (x), (0/0), (0/0), false, (x), (0/0), false, false, (0/0), (x), false, false]); ");
/*fuzzSeed-168297596*/count=1134; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul(Math.fround(Math.imul(Math.fround(Math.fround(Math.min(Math.trunc(0), Math.fround(y)))), (( + Math.fround(( ~ ( - x)))) >>> 0))), Math.hypot((Math.cosh((( + y) , Math.fround(Math.atan2(Math.fround((Math.pow((y | 0), (x | 0)) | 0)), Math.fround(x))))) | 0), Math.expm1(( ! x)))) && (mathy2(((mathy0((Math.abs(y) | 0), x) | 0) | 0), ((Math.fround(mathy1(y, ((mathy2(y, (x | 0)) | 0) >>> 0))) | Math.fround((( + y) | Math.fround(y)))) | 0)) | 0)); }); testMathyFunction(mathy3, [0, undefined, (new String('')), (function(){return 0;}), /0/, '/0/', '\\0', NaN, ({valueOf:function(){return '0';}}), (new Number(-0)), 0.1, true, false, objectEmulatingUndefined(), '0', ({valueOf:function(){return 0;}}), [], (new Boolean(true)), (new Number(0)), -0, 1, ({toString:function(){return '0';}}), (new Boolean(false)), '', null, [0]]); ");
/*fuzzSeed-168297596*/count=1135; tryItOut("\"use strict\"; m1.set(v2, this.o2);");
/*fuzzSeed-168297596*/count=1136; tryItOut("/*RXUB*/var r = /.?(.\\d\\b)|\uef55|^{3,3}|\\B+?|\\2+?|^*/gy; var s = x = -0; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=1137; tryItOut("\"use strict\"; return  \"\" ;");
/*fuzzSeed-168297596*/count=1138; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+abs(((Infinity)))));\n  }\n  return f; })(this, {ff: (this)((Math.log1p( '' )))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000000, 0x080000001, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -0x07fffffff, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, Number.MAX_VALUE, 0x100000001, 0x080000000, -0x0ffffffff, -0x100000001, Math.PI, -Number.MAX_VALUE, -0, 1, 1.7976931348623157e308, 42, 0.000000000000001, -0x100000000, -0x080000001, -(2**53), 2**53+2, 0/0, 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1139; tryItOut("for(let w of /*FARR*/[let (z) \"\\uFE23\"]) let(z) { /*tLoop*/for (let z of /*MARR*/[({x:3}), 1e+81, function(){}, function(){}, function(){}, ({x:3}), 1e+81, undefined, function(){}, ({x:3}), undefined, undefined, undefined, ({x:3}), ({x:3}), ({x:3}), undefined, 1e+81, undefined, ({x:3}), ({x:3}), 1e+81, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, undefined, function(){}, undefined, ({x:3}), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, 1e+81, 1e+81, ({x:3}), function(){}, ({x:3}), function(){}, undefined, function(){}, undefined, 1e+81, undefined, undefined, ({x:3}), ({x:3}), ({x:3}), 1e+81, ({x:3}), ({x:3}), 1e+81, ({x:3}), ({x:3}), undefined, 1e+81, ({x:3}), undefined, undefined, function(){}, undefined, function(){}, 1e+81, undefined, 1e+81, function(){}, 1e+81, undefined, function(){}, 1e+81, 1e+81, undefined, 1e+81, undefined, 1e+81, 1e+81, undefined, 1e+81, 1e+81, undefined, undefined, undefined]) { i1 + ''; }}");
/*fuzzSeed-168297596*/count=1140; tryItOut("e2.has(o2);");
/*fuzzSeed-168297596*/count=1141; tryItOut("\"use strict\"; o0.v0 = (s0 instanceof s1);");
/*fuzzSeed-168297596*/count=1142; tryItOut("g0.offThreadCompileScript(\"function g0.f1(g0.s0) ((new window())())\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: ({__parent__: window.valueOf(\"number\") }), sourceIsLazy: false, catchTermination: (Math.acos(24)) }));");
/*fuzzSeed-168297596*/count=1143; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 18014398509481984.0;\n    d1 = (d1);\n    (Float64ArrayView[((~((0xa144d5a5))) / (abs((((0xf8b5564e)+(0x9ef59443)) << ((0x289e58f5))))|0)) >> 3]) = ((((-((((d2)) - ((d2)))))) - ((Infinity))));\n    d0 = (d1);\n    (Uint8ArrayView[4096]) = ((-0x8000000)-(/*FFI*/ff()|0));\n    {\n      d1 = (+(~((0xd9399884)+((~~(+ceil(((((d2)) % ((+abs(((-8796093022209.0)))))))))) != (((((0x9baaaa19)) >> ((-0x8000000))) % (~((0xf1e61985)))) << ((0xfb7a47ba)))))));\n    }\n    d2 = (d1);\n    d1 = (((d0)) % ((+(-1.0/0.0))));\n    return +((d2));\n  }\n  return f; })(this, {ff: DataView.prototype.setUint8}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[(0/0), (void 0), (1/0), (void 0), 2**53-2, (1/0), (0/0), (void 0), {}, (1/0), (void 0), (1/0), (1/0), (void 0), (0/0), (0/0), (void 0), 2**53-2, {}, {}, (1/0), (1/0), (void 0), (0/0), (1/0), 2**53-2, {}, (void 0), (1/0), (void 0), (0/0), 2**53-2, 2**53-2, (1/0), {}, 2**53-2, {}, (void 0), {}, (0/0), 2**53-2, 2**53-2, (0/0), {}, {}, (1/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), 2**53-2, 2**53-2, (void 0), {}, {}, (void 0), (void 0), 2**53-2, (0/0), {}, (1/0), 2**53-2, 2**53-2, (0/0), {}, (void 0), (0/0), (void 0), (0/0), (void 0), (0/0), 2**53-2, (1/0), 2**53-2, {}, (void 0), (0/0), {}, (0/0), {}, (1/0), 2**53-2, {}, (1/0), {}, {}, {}, (1/0), 2**53-2, (0/0), 2**53-2, (1/0), {}, (void 0), 2**53-2, (1/0), (void 0)]); ");
/*fuzzSeed-168297596*/count=1144; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.pow(( + (Math.min(((mathy2((mathy1(y, y) >>> (y !== (( ! y) >= -0x080000000))), ((((Number.MIN_VALUE | 0) === (y | 0)) | 0) | 0)) >>> 0) >>> 0), ( + ( + ( ! (Math.min((y | 0), (( + y) ? (Math.fround(x) | (0 | 0)) : -Number.MIN_SAFE_INTEGER)) | 0))))) >>> 0)), Math.fround(Math.atanh((( + (mathy2((x >>> 0), (x >>> 0)) >>> 0)) > mathy0(((mathy2(x, x) >>> 0) != x), ( + x))))))); }); ");
/*fuzzSeed-168297596*/count=1145; tryItOut("\"use strict\"; /*oLoop*/for (var adloet = 0, b = (b.throw( '' )); adloet < 58; ++adloet) { Object.defineProperty(this, \"o1.v2\", { configurable: \"\\u6EAD\", enumerable: true,  get: function() {  return evalcx(\"((window)( \\\"\\\" , \\\"\\\\u1F44\\\"));\", g2); } }); } ");
/*fuzzSeed-168297596*/count=1146; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.min(( + (( + Math.atanh(y)) | Math.fround(mathy0(Math.fround((Math.atanh(((Math.sign(y) | 0) >>> 0)) >>> 0)), Math.fround(Math.fround(Math.pow(Math.fround(y), Math.fround(-0x100000001)))))))), ( + (Math.fround(Math.log10((Math.fround(Math.log(-Number.MIN_SAFE_INTEGER)) | 0))) | (( ~ Math.sin(x)) ? ( + Math.hypot(( + -Number.MAX_SAFE_INTEGER), (( + x) | 0))) : Math.fround(Math.pow(Math.fround(Math.min(( + x), ((42 != x) >>> 0))), Math.fround(Math.atan2(Math.fround(( - ( + -Number.MAX_VALUE))), ( + (x - ( + y))))))))))) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, 0x100000000, -1/0, Math.PI, -(2**53-2), -Number.MAX_VALUE, 0.000000000000001, Number.MAX_VALUE, -(2**53+2), -0x100000000, 0x080000000, 1, 1.7976931348623157e308, -0x07fffffff, -0x100000001, Number.MIN_VALUE, 0x080000001, -0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 0/0, -0x080000001, 0, 1/0, -0, -(2**53), 2**53+2, 0x100000001]); ");
/*fuzzSeed-168297596*/count=1147; tryItOut("\"use strict\"; Object.prototype.unwatch.call(h2, \"isArray\");");
/*fuzzSeed-168297596*/count=1148; tryItOut("var [, , , eval, x, , , , [, , ]] = x >= e, set = x;this.m0.has(f0);");
/*fuzzSeed-168297596*/count=1149; tryItOut("\"use strict\"; Array.prototype.shift.call(a0, /*UUV2*/(d.toString = d.fromCodePoint), m1);");
/*fuzzSeed-168297596*/count=1150; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ( + Math.hypot(mathy0((Math.round(((Number.MAX_VALUE * Math.min((x != y), 1/0)) | 0)) | 0), Math.atan((( + Math.hypot(Number.MIN_VALUE, (x >>> 0))) * x))), ( + Math.hypot(Math.log1p(x), Math.fround(Math.acosh(Math.fround(x))))))); }); ");
/*fuzzSeed-168297596*/count=1151; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.trunc(( + Math.atan2(((Math.imul(y, (( + (( + 0) , Math.fround(Math.atan2(((y | 0) | 1.7976931348623157e308), x)))) >>> 0)) >>> 0) | 0), ( + Math.fround(Math.max(((y ? Math.max(y, (Math.exp((x >>> 0)) >>> 0)) : (Math.pow(Math.max(x, y), (x >>> 0)) >>> 0)) | 0), y)))))); }); testMathyFunction(mathy2, [0x080000000, 0.000000000000001, Number.MIN_VALUE, -0, 42, 0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 2**53-2, -0x080000001, -0x0ffffffff, -(2**53), 1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, -Number.MAX_VALUE, -0x100000001, 0/0, Math.PI, -(2**53-2), 0x080000001, Number.MAX_VALUE, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 0, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=1152; tryItOut("/*RXUB*/var r = new RegExp(\".\", \"gyi\"); var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-168297596*/count=1153; tryItOut("\"use strict\"; \"use asm\"; v0 = evalcx(\"a1.reverse(s1);\\nm1.delete(p2);\\n\", this.g1);");
/*fuzzSeed-168297596*/count=1154; tryItOut("");
/*fuzzSeed-168297596*/count=1155; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.clz32(((Math.atan2(mathy0(Math.pow(y, (Math.imul((x >>> 0), y) >>> 0)), -Number.MIN_SAFE_INTEGER), Math.trunc(0x0ffffffff)) | 0) >>> 0)); }); testMathyFunction(mathy1, [0x080000001, 1/0, 0x0ffffffff, 0x080000000, Math.PI, 0/0, 2**53+2, -0, -0x100000001, 1, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, -(2**53+2), 0x07fffffff, 42, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 2**53, -(2**53), -Number.MAX_VALUE, -0x100000000, 2**53-2, -(2**53-2), 0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000000, -1/0]); ");
/*fuzzSeed-168297596*/count=1156; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1157; tryItOut("h2 = {};");
/*fuzzSeed-168297596*/count=1158; tryItOut("h0 = ({getOwnPropertyDescriptor: function(name) { v1 = Object.prototype.isPrototypeOf.call(g2, this.g2);; var desc = Object.getOwnPropertyDescriptor(a0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { s0 = '';; var desc = Object.getPropertyDescriptor(a0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { h2.getOwnPropertyNames = f0;; Object.defineProperty(a0, name, desc); }, getOwnPropertyNames: function() { v0 = a2.length;; return Object.getOwnPropertyNames(a0); }, delete: function(name) { return a2; return delete a0[name]; }, fix: function() { v1 = g0.eval(\"Array.prototype.push\");; if (Object.isFrozen(a0)) { return Object.getOwnProperties(a0); } }, has: function(name) { return this.a0; return name in a0; }, hasOwn: function(name) { s0 = a2[6];; return Object.prototype.hasOwnProperty.call(a0, name); }, get: function(receiver, name) { m2.get((z < x));; return a0[name]; }, set: function(receiver, name, val) { e1.has(v2);; a0[name] = val; return true; }, iterate: function() { print(uneval(p0));; return (function() { for (var name in a0) { yield name; } })(); }, enumerate: function() { return o2.b1; var result = []; for (var name in a0) { result.push(name); }; return result; }, keys: function() { a0.shift(i2);; return Object.keys(a0); } });\nt2 = new Float64Array(t1);\n");
/*fuzzSeed-168297596*/count=1159; tryItOut("/*RXUB*/var r = /((\\3)*?)+?/ym; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-168297596*/count=1160; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -73786976294838210000.0;\n    var d3 = 147573952589676410000.0;\n    var i4 = 0;\n    (Float32ArrayView[((0xf259119b)) >> 2]) = ((Float64ArrayView[0]));\n    i4 = ((~(((~~(8796093022208.0)) > (0x7fffffff))-(( /x/g \n) == (0x14e471ce)))));\n    d3 = (d3);\n    d0 = ((-6.044629098073146e+23) + (d0));\n    return +((-((d3))));\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=1161; tryItOut("\"use asm\"; (4277);const y = /*RXUE*/new RegExp(\"(?:\\\\W)((?!\\\\B[^])+)|\\\\2?{4,5}\", \"y\").exec(\"\\ue99e\\ue99e\\ue99e\\ue99ea\\u9c2e\\n\");e0.has(v1);");
/*fuzzSeed-168297596*/count=1162; tryItOut("testMathyFunction(mathy2, [1.7976931348623157e308, 0, 2**53-2, 0/0, -Number.MAX_VALUE, 0x07fffffff, 2**53+2, Number.MIN_VALUE, -0x080000000, 0.000000000000001, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, 1, -0x0ffffffff, 0x100000000, -(2**53+2), -0, -0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 0x100000001, 0x080000001, 42, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 0x080000000, -Number.MIN_VALUE, -0x100000000, -(2**53)]); ");
/*fuzzSeed-168297596*/count=1163; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.888946593147858e+22;\n    i1 = (/*FFI*/ff()|0);\n    {\n      (Float32ArrayView[((Int8ArrayView[1])) >> 2]) = ((Float64ArrayView[1]));\n    }\n    {\n      return (((0x180958c4)))|0;\n    }\n    d2 = (513.0);\n    i1 = (0xffffffff);\n    (Float32ArrayView[0]) = ((+(1.0/0.0)));\n    i1 = (i1);\n    d0 = (+(-1.0/0.0));\n    d0 = (((+/*FFI*/ff(((d2)), ((((-1.5474250491067253e+26)) % ((d0)))), ((d2)), ((~((i1)))), ((imul((!(-0x8000000)), (-0x8000000))|0))))) * ((d2)));\n    (Float64ArrayView[((((((-9223372036854776000.0)))|0))) >> 3]) = ((+((((0x448856fa) < (((i1)) >> ((0x58dad3a4)+(-0x6bb290b)-(-0x56802d2))))+(0xf951e5e1)) ^ ((((0xffba9395)) ^ ((-0x8000000))) % (this)))));\n    d0 = (NaN);\n    return (((0xff762748)*0xe1aff))|0;\n  }\n  return f; })(this, {ff: arguments.callee.caller}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=1164; tryItOut("\"use strict\"; /*vLoop*/for (var sbnvse = 0; sbnvse < 57; ++sbnvse) { let c = sbnvse; e2.has(new RegExp(\"(.)+\\\\b+\", \"yim\")); } \n\n");
/*fuzzSeed-168297596*/count=1165; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  var atan = stdlib.Math.atan;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((+pow(((+atan2(((9.44473296573929e+21)), ((+atan(((Float64ArrayView[((-0x8000000)-(-0x8000000)) >> 3])))))))), ((+(1.0/0.0))))));\n  }\n  return f; })(this, {ff: function(y) { a2.reverse(); }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [2**53-2, Number.MAX_VALUE, 0x100000001, 0x080000001, -0x100000000, -0, 1/0, Number.MIN_SAFE_INTEGER, 42, -0x080000001, 0.000000000000001, -0x07fffffff, 1, -0x080000000, 0x080000000, -(2**53), Math.PI, 2**53, -(2**53-2), -1/0, 0x100000000, 0x07fffffff, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 0/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=1166; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(( + (Math.fround(Math.max((Math.fround(( ! Math.fround(0.000000000000001))) >>> 0), Math.pow(( + Math.fround((( + (y ? Math.expm1(x) : 2**53+2)) > Math.fround(x)))), x))) | 0))); }); testMathyFunction(mathy0, [-0x080000000, Number.MIN_VALUE, 2**53+2, -(2**53-2), 0x080000001, 2**53, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, 42, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, -Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, -0x100000000, 1, -(2**53+2), -1/0, 0, Number.MAX_VALUE, -(2**53), -0x080000001, 0x100000000, 0/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-168297596*/count=1167; tryItOut("with({}) for(let x in []);for(let x of new Array(-10)) throw StopIteration;");
/*fuzzSeed-168297596*/count=1168; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((((Math.fround((( + Math.fround(mathy2(Math.fround(( + (( + x) == Math.fround(( + (x && -(2**53))))))), Math.fround(mathy2(Math.fround(y), Math.clz32(y)))))) >>> 0)) > Math.fround(Math.hypot((( + Math.sinh(11)) !== x), (( ! (mathy0(x, (( + (x ? ( + x) : ( + x))) >>> 0)) >>> 0)) >>> 0)))) >>> 0) & ((((((Math.sin(0.000000000000001) >>> 0) >>> 0) ** (Math.abs(Math.fround(Math.log1p((Math.tanh(y) | 0)))) >>> 0)) >>> 0) ? Math.ceil(((-Number.MIN_VALUE < Math.atanh((2**53 | 0))) | 0)) : Math.imul((( - (0.000000000000001 | 0)) | 0), (y << -0x080000000))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[(-1/0), [undefined], (-1/0), ({x:3}), [undefined], ({x:3}), ({x:3}), [undefined], (-1/0), ({x:3}), NaN, ({x:3}), [undefined], (-1/0), ({x:3}), [undefined], [undefined], ({x:3}), (-1/0), (-1/0), ({x:3}), (-1/0), (-1/0), ({x:3}), NaN, NaN, (-1/0), ({x:3}), (-1/0), [undefined], NaN, [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], ({x:3}), (-1/0), (-1/0), NaN, (-1/0), NaN, [undefined], ({x:3}), ({x:3}), ({x:3}), (-1/0), ({x:3}), NaN, NaN, [undefined], ({x:3}), NaN, (-1/0), ({x:3}), (-1/0), NaN, [undefined], ({x:3}), ({x:3}), [undefined], NaN, NaN, [undefined], NaN, ({x:3}), (-1/0), NaN, (-1/0), ({x:3}), [undefined], NaN, ({x:3}), (-1/0), NaN, ({x:3}), [undefined], ({x:3}), (-1/0), ({x:3})]); ");
/*fuzzSeed-168297596*/count=1169; tryItOut("mathy1 = (function(x, y) { return Math.max(((((((-0 | 0) != (y | 0)) | 0) | 0) ? (( + Math.asinh((Math.acos((y >>> 0)) | 0))) | 0) : ((( ~ Math.fround((( + x) ^ ( + (Math.log1p((y | 0)) | 0))))) | 0) | 0)) | 0), Math.min(( + mathy0((((Math.pow((((y , x) | 0) * x), y) | 0) ? (x | 0) : (( - x) | 0)) | 0), (Math.sin(y) >>> 0))), (((x || y) == x) && ((y | 0) - ((x >= (y | 0)) >>> 0))))); }); ");
/*fuzzSeed-168297596*/count=1170; tryItOut("o0.m2 = new Map(o0);");
/*fuzzSeed-168297596*/count=1171; tryItOut("mathy1 = (function(x, y) { return (Math.pow(Math.max((mathy0(Math.log1p((( + x) !== -Number.MAX_SAFE_INTEGER)), x) >>> 0), (((Math.sin(( ~ ((((y >>> 0) >> ( + (x | 42))) >>> 0) | 0))) | 0) ** ( + Math.atan2(Math.fround(y), Math.fround(x)))) >>> 0)), ((( - Math.asinh(( + ( ! ( + -0x080000000))))) >>> 0) >>> 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[NaN, new String('q'), NaN, null, new String('q'), null, null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), NaN, new String('q'), NaN, new String('q'), null, NaN, objectEmulatingUndefined(), new String('q'), NaN, NaN, null, objectEmulatingUndefined(), null, NaN, objectEmulatingUndefined(), NaN, null, new String('q'), NaN, null, new String('q'), new String('q'), objectEmulatingUndefined(), null, objectEmulatingUndefined(), new String('q'), null, NaN, NaN, NaN, objectEmulatingUndefined(), null, new String('q'), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, null, NaN, objectEmulatingUndefined(), null, NaN, NaN, null, null, NaN, NaN, NaN, null, new String('q'), null, NaN, null, new String('q'), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, null, objectEmulatingUndefined()]); ");
/*fuzzSeed-168297596*/count=1172; tryItOut("\"use strict\"; v1 = g1.eval(\"v2 = new Number(-Infinity);\\n;\\n\");");
/*fuzzSeed-168297596*/count=1173; tryItOut("L:if((x % 5 == 4)) { if (window) g0.v0 = evaluate(\"function f1(a2) Math.pow(9, [[[1]]])\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 52 == 2), noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 2 != 1) })); else i1.toString = f1;}");
/*fuzzSeed-168297596*/count=1174; tryItOut("mathy1 = (function(x, y) { return (Math.fround(( ! (( ! (Math.fround((Math.fround(( + Math.clz32(( + x)))) >= (y + x))) == y)) | 0))) - Math.fround(((( ! (( - x) | 0)) && (Math.round(( + Math.atan2(y, Math.fround(( ! Math.fround(Math.fround(mathy0(Math.fround(( + x)), Math.fround(mathy0(-0x07fffffff, (-Number.MAX_VALUE | 0))))))))))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-168297596*/count=1175; tryItOut("\"use strict\"; /*bLoop*/for (biagme = 0; biagme < 129; ++biagme) { if (biagme % 19 == 17) { ; } else { yield false; }  } ");
/*fuzzSeed-168297596*/count=1176; tryItOut("h1 = m2.get(m0);");
/*fuzzSeed-168297596*/count=1177; tryItOut("\"use asm\"; h2.has = (function mcc_() { var bydggw = 0; return function() { ++bydggw; f0(/*ICCD*/bydggw % 9 == 0);};})();");
/*fuzzSeed-168297596*/count=1178; tryItOut("mathy0 = (function(x, y) { return (( + (Math.expm1((Math.hypot(Math.fround(( ~ Math.fround(y))), Math.fround((Math.fround(Math.hypot(y, x)) << Math.fround(1)))) || ( ! (Math.hypot(Math.clz32((x | 0)), Math.hypot(x, y)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -(2**53-2), 1/0, 0.000000000000001, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, 2**53, -0x07fffffff, 0x080000001, 0x080000000, -(2**53+2), 2**53+2, -(2**53), -0x0ffffffff, -0, 0x07fffffff, Math.PI, -Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0x100000001, 42, -0x080000001, -0x100000000, Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-168297596*/count=1179; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.min((Math.hypot(( ~ x), ((Math.hypot(( + Math.min(42, x)), ( + (mathy0((Math.pow(y, y) | 0), ( + 0/0)) >>> 0))) | 0) + x)) | 0), (Math.tan((Math.sin(y) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, [0x080000001, 2**53-2, -(2**53+2), -Number.MAX_VALUE, -0x080000001, -0, -0x100000001, Number.MIN_VALUE, -0x080000000, Math.PI, 0x080000000, 0.000000000000001, 0x100000001, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -0x07fffffff, -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, -(2**53), 1, 42, Number.MAX_VALUE, -(2**53-2), 2**53, -1/0, 1/0, 0, 2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=1180; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=1181; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( + ( ! (mathy1((Math.fround(Math.round((x | 0))) >>> 0), (-0x080000000 >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, 0/0, 2**53, 0x080000001, Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 2**53-2, Math.PI, 1, 0x100000001, Number.MAX_VALUE, -0, 42, -0x080000000, 0, -(2**53), -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-168297596*/count=1182; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1183; tryItOut("/*RXUB*/var r = r0; var s = s2; print(s.search(r)); ");
/*fuzzSeed-168297596*/count=1184; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( ~ (Math.fround(Math.imul(Math.fround(( + (( ! (( ~ (y >>> 0)) >>> 0)) || ( + ((x | x) & (Math.fround(( ! (y >>> 0))) ^ Math.fround(Math.ceil(Math.fround(( ~ y)))))))))), Math.fround(( + ( - (Math.log(( - Math.log1p((x | 0)))) | 0)))))) | 0)) | 0); }); testMathyFunction(mathy0, [Math.PI, -0x080000000, 0x0ffffffff, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 1/0, 0x100000000, 2**53-2, -1/0, 0x080000000, 0, -0, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, 2**53, -0x080000001, 42, Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 2**53+2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 1, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001]); ");
/*fuzzSeed-168297596*/count=1185; tryItOut("\"use strict\"; delete h0.keys;");
/*fuzzSeed-168297596*/count=1186; tryItOut("mathy2 = (function(x, y) { return (( ~ (Math.pow(Math.fround((Math.tan((( + Math.fround(( ! (Math.fround(Math.trunc(y)) >>> 0)))) | 0)) | 0)), Math.hypot(Math.log2(x), (Math.hypot((0/0 >>> 0), (( ! y) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0x080000001, 42, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0, Math.PI, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 0x100000000, -0x07fffffff, -Number.MIN_VALUE, 2**53-2, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, -0x080000001, 0x07fffffff, -0, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, 1/0, 0x0ffffffff, 0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0/0, 1, -0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=1187; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.atan2(( + ( + (Math.min(( + x), ((( + -Number.MAX_SAFE_INTEGER) ? (Math.atan2((( + ( + Math.fround(-(2**53-2)))) | 0), (Math.cosh(Math.atan2(y, x)) | 0)) | 0) : (((x / x) - y) | 0)) | 0)) | 0))), (Math.fround(( ~ Math.fround(x))) < Math.min(0x0ffffffff, ( ! y)))); }); testMathyFunction(mathy3, /*MARR*/[-3/0, -Infinity, -Infinity, -3/0, -Infinity, -3/0, x, -Infinity, -3/0, -3/0, -Infinity, -3/0, x, x, -Infinity, -Infinity, -Infinity, -Infinity, x, x, -3/0, -Infinity, -Infinity, x, x, x, -Infinity, x, -Infinity, -3/0, -3/0, -Infinity, -3/0, -Infinity, x, -Infinity, -3/0, -3/0, -3/0, -3/0, -3/0, -3/0, x, x, -3/0, -Infinity, -3/0, x, -3/0, -Infinity, -3/0, x, -Infinity, -Infinity, -3/0, x, -3/0, -Infinity, -3/0, -Infinity, -Infinity, x, x, -3/0, x, -3/0, x, -Infinity, -3/0, -3/0, x, -Infinity, -3/0, -3/0, x, -Infinity, x, x, x, x, x, -Infinity, -3/0, x, -Infinity, -Infinity, -3/0, -3/0, -3/0, x, -Infinity, -Infinity, -Infinity, x, -Infinity, -Infinity, x, -Infinity, -3/0, -Infinity, -Infinity, x, x, x, -3/0]); ");
/*fuzzSeed-168297596*/count=1188; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! mathy2(Math.fround(( - ( + mathy1(y, -(2**53+2))))), (( - ((Math.min((Math.min(Math.PI, y) | 0), ((Math.hypot((y >>> 0), y) >>> 0) | 0)) | 0) < ( + Math.fround(Math.acos(Math.fround(-0x080000000)))))) >>> 0))) >>> 0); }); testMathyFunction(mathy5, [Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, 0x07fffffff, 1/0, -Number.MAX_VALUE, -0x100000000, 2**53, 42, -0x07fffffff, -Number.MIN_VALUE, 0x100000000, Math.PI, 0x0ffffffff, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -0, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, 0, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, 2**53-2, -0x080000001, 2**53+2, -(2**53-2), -(2**53+2)]); ");
/*fuzzSeed-168297596*/count=1189; tryItOut("o2.i0.next();");
/*fuzzSeed-168297596*/count=1190; tryItOut("\"use strict\"; /*vLoop*/for (let cyagub = 0, true.throw(true)/*\n*/; cyagub < 1; ++cyagub) { const e = cyagub; v2 = Object.prototype.isPrototypeOf.call(m1, o0.e0);function c()\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((x))|0;\n  }\n  return f;yield window; } ");
/*fuzzSeed-168297596*/count=1191; tryItOut("\"use strict\"; /*RXUB*/var r = /\\3/gy; var s = \"\\u00c9\\u00c9\"; print(uneval(r.exec(s))); \n{print(x);f2.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { a6 = a3 / 3; a2 = a6 / x; var r0 = 7 / 7; a2 = 6 + a3; var r1 = 6 * a7; a7 = 8 + 5; a7 = a8 + r1; var r2 = 6 & a2; var r3 = 0 / 2; var r4 = 5 + 6; var r5 = r0 % 7; var r6 = 9 * 5; var r7 = a8 & x; var r8 = a4 - 2; var r9 = 4 / a8; var r10 = 6 - a6; var r11 = r2 % a6; r5 = r8 | x; var r12 = r0 / a4; var r13 = a3 / 4; var r14 = r8 & r9; var r15 = r13 / a1; a7 = a6 / a0; var r16 = 4 - r11; var r17 = r11 % r16; var r18 = 0 - 2; var r19 = 4 ^ r17; var r20 = 8 ^ r16; var r21 = a2 % a2; var r22 = 9 * a6; var r23 = r2 * 1; r6 = r23 / r9; var r24 = r22 & 9; r3 = 8 % 3; var r25 = a0 / a2; print(r10); var r26 = r25 ^ r13; var r27 = r14 % r10; r3 = r4 + 1; r20 = r16 * r4; var r28 = r12 | a8; r5 = 2 / 3; var r29 = 1 | 8; var r30 = 3 - a0; var r31 = 3 | r19; r3 = r28 / 9; var r32 = a2 - 3; var r33 = 2 ^ r1; var r34 = r16 / r13; var r35 = 2 * a2; var r36 = r9 & r10; r16 = a4 + r29; var r37 = r21 / r3; var r38 = r24 / 3; var r39 = 2 ^ 6; var r40 = a5 - 5; var r41 = 5 / r33; var r42 = r33 / 9; var r43 = 2 % r18; var r44 = 1 + r24; var r45 = 2 & 1; return a1; }); }\u0009\n");
/*fuzzSeed-168297596*/count=1192; tryItOut("\"use strict\"; h1.__proto__ = h1;");
/*fuzzSeed-168297596*/count=1193; tryItOut("\"use strict\"; m1.has(p2);");
/*fuzzSeed-168297596*/count=1194; tryItOut("s0 += 'x';");
/*fuzzSeed-168297596*/count=1195; tryItOut("\"use strict\"; g2.g2.offThreadCompileScript(\"s0 += s1;\", ({ global: o0.g0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: null, noScriptRval: true, sourceIsLazy: false, catchTermination: this.__defineGetter__(\"z\", function shapeyConstructor(vgxjwe){\"use strict\"; \"use asm\"; for (var ytqfcauff in this) { }return this; }).__defineSetter__(\"a\", /*wrap2*/(function(){ \"use asm\"; var jykrrf = x; var yqxhds = Int32Array; return yqxhds;})()), element: o0, elementAttributeName: this.s2 }));");
/*fuzzSeed-168297596*/count=1196; tryItOut("a2.forEach((function() { try { m1 = x; } catch(e0) { } try { i0.__proto__ = p2; } catch(e1) { } try { s0.__proto__ = s0; } catch(e2) { } f2.toSource = f1; return p2; }));print(x);");
/*fuzzSeed-168297596*/count=1197; tryItOut("\"use strict\"; print(-8);o2 = h2.__proto__;");
/*fuzzSeed-168297596*/count=1198; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-1/0, Math.PI, 1.7976931348623157e308, 2**53-2, -0x07fffffff, -0, 0x080000000, 0, 0.000000000000001, 42, 0x07fffffff, -0x080000000, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, 2**53, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), 2**53+2, -0x100000000, 0x100000001, -0x100000001, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), 0/0]); ");
/*fuzzSeed-168297596*/count=1199; tryItOut("/*tLoop*/for (let x of /*MARR*/[objectEmulatingUndefined(), [], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5),  /x/ , [],  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5), [], {x:3},  /x/ ,  /x/ , {x:3}, objectEmulatingUndefined(), {x:3},  /x/ , [],  /x/ , objectEmulatingUndefined(),  /x/ , {x:3}, objectEmulatingUndefined(), new Number(1.5), {x:3}, objectEmulatingUndefined(), new Number(1.5), {x:3}, objectEmulatingUndefined(), [], objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), [],  /x/ , objectEmulatingUndefined(), {x:3},  /x/ , objectEmulatingUndefined(), [],  /x/ , objectEmulatingUndefined(),  /x/ , {x:3}, {x:3}, {x:3},  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), {x:3}, objectEmulatingUndefined(),  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), {x:3}, [],  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), [], new Number(1.5),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), {x:3},  /x/ , {x:3}]) { {/*infloop*/for(Map.prototype.delete in ((eval)(((eval =  /x/g )))))a0.splice(3, 19, e2, p0, g0); } }");
/*fuzzSeed-168297596*/count=1200; tryItOut("mathy3 = (function(x, y) { return (( + (Math.fround(Math.min(Math.fround((( ~ (x >>> 0)) | 0)), Math.fround((Math.fround(Math.min(y, Math.fround((y < (y >>> 0))))) << Math.pow((Math.min(x, x) >>> 0), ( + y)))))) >>> ( ! ( + ( - (Math.min(x, 0) >>> 0)))))) & Math.asin(( + y))); }); testMathyFunction(mathy3, [-0x0ffffffff, 0x080000001, Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000001, -1/0, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, -0x100000000, 0, Math.PI, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, 2**53, Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, -(2**53+2), 0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, 42, 0x07fffffff, -0x07fffffff, -0x080000000, -(2**53-2), 0/0, 0x100000000, 1/0, -0, -(2**53)]); ");
/*fuzzSeed-168297596*/count=1201; tryItOut("testMathyFunction(mathy2, [0x100000000, -0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 1.7976931348623157e308, -0x07fffffff, -(2**53), 42, 0x100000001, -0x100000000, 0x080000000, -0x0ffffffff, Math.PI, 2**53, -(2**53+2), 2**53-2, 2**53+2, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, -0x100000001, 0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -0x080000000, -1/0, 0x080000001, 0x07fffffff, Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1202; tryItOut("\"use strict\"; v1 = Array.prototype.some.apply(a2, [g2.f0, h0, s1]);");
/*fuzzSeed-168297596*/count=1203; tryItOut("/*infloop*/do m0.set(g0.h1, g0.g2.s1); while( \"\" );");
/*fuzzSeed-168297596*/count=1204; tryItOut("");
/*fuzzSeed-168297596*/count=1205; tryItOut("\"use strict\"; Object.defineProperty(this, \"b2\", { configurable: true, enumerable: new ((x = (/*RXUE*//(?!.[\\u0008-\n]|[^]+[^]*?\u00e1)|(?!$+)?(?=(?:[^]))/.exec(\"\").__defineSetter__(\"x\", objectEmulatingUndefined))))((eval(\"(String.prototype.toString).call(\\\"\\\\u2CC3\\\",  \\\"\\\" )\")), x),  get: function() {  return new ArrayBuffer(9); } });");
/*fuzzSeed-168297596*/count=1206; tryItOut("\"use strict\"; testMathyFunction(mathy4, ['/0/', false, (new Number(-0)), ({toString:function(){return '0';}}), '\\0', -0, null, objectEmulatingUndefined(), 0, (new Boolean(false)), ({valueOf:function(){return '0';}}), true, 0.1, 1, /0/, '', '0', [0], (new Number(0)), (function(){return 0;}), (new String('')), (new Boolean(true)), undefined, [], NaN, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-168297596*/count=1207; tryItOut("a0.shift();");
/*fuzzSeed-168297596*/count=1208; tryItOut("(c = let (\u000cy = ()) ((void options('strict_mode'))));");
/*fuzzSeed-168297596*/count=1209; tryItOut("\"use strict\"; v0 = t0.length;");
/*fuzzSeed-168297596*/count=1210; tryItOut("\"use asm\"; Object.defineProperty(o1, \"m2\", { configurable: false, enumerable: false,  get: function() {  return new Map; } })");
/*fuzzSeed-168297596*/count=1211; tryItOut("testMathyFunction(mathy3, [0x080000000, 2**53+2, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, 1.7976931348623157e308, 0, -0x080000000, -0x100000001, -0x080000001, -(2**53-2), 0x100000000, 0x100000001, Number.MAX_VALUE, -1/0, -(2**53), 1, -0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, 42, -Number.MAX_VALUE, -0]); ");
/*fuzzSeed-168297596*/count=1212; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (((Math.log10((( + (( + y) % y)) + x)) === Math.fround((( + (x ^ (Math.min(Number.MIN_VALUE, (x | 0)) | 0))) ? (Math.min((((((Math.pow((Math.pow(x, Math.fround(y)) | 0), (((( + y) | y) | 0) | 0)) | 0) >>> 0) >> (y >>> 0)) >>> 0) >>> 0), (x | 0)) | 0) : ( ~ x)))) || ((Math.trunc(Math.sin(( + Math.log10(((( + (Math.atan(2**53+2) >>> 0)) >>> 0) | 0))))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, [0x100000001, 0.000000000000001, Number.MIN_VALUE, -1/0, 1.7976931348623157e308, -0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, Math.PI, 0x0ffffffff, 42, 1, 0x080000001, -(2**53+2), -0x080000000, -0, -0x07fffffff, 1/0, 0x07fffffff, 0/0, -(2**53-2), -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, 2**53+2, 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-168297596*/count=1213; tryItOut("var x;(\"\\u97D6\");a1.push(o1, b1);");
/*fuzzSeed-168297596*/count=1214; tryItOut("Array.prototype.forEach.call(a2, (function mcc_() { var mjtdqc = 0; return function() { ++mjtdqc; if (/*ICCD*/mjtdqc % 10 == 0) { dumpln('hit!'); try { Array.prototype.shift.call(a0, e0, p1, g2, m1, allocationMarker()); } catch(e0) { } try { this.v0 = undefined; } catch(e1) { } v2 = Array.prototype.reduce, reduceRight.apply(a1, [(function() { try { a0[18] = x; } catch(e0) { } try { v2 + m0; } catch(e1) { } try { for (var p in s0) { try { f0 = Proxy.createFunction(h1, f2, f0); } catch(e0) { } try { this.i1.next(); } catch(e1) { } try { for (var v of m1) { try { g1 + ''; } catch(e0) { } try { x = f2; } catch(e1) { } try { selectforgc(o2.o2); } catch(e2) { } v0 = r1.compile; } } catch(e2) { } /*MXX1*/o0 = g2.String.prototype.trimRight; } } catch(e2) { } /*MXX2*/g1.WebAssemblyMemoryMode.name = m2; return m1; }), i0, g0]); } else { dumpln('miss!'); try { v1 = r1.test; } catch(e0) { } g2.t1 = new Int16Array(b2, 2, ({valueOf: function() { for(let eval = (yield = x) in (4277)) this.v1 = this.g0.eval(\"testMathyFunction(mathy4, [2**53+2, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -Number.MIN_VALUE, 42, 0x100000000, -0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), Math.PI, 0, 0x080000001, 0x07fffffff, 0x080000000, 0/0, Number.MIN_VALUE, -(2**53), 0x100000001, -0x07fffffff, -1/0, 1, -0x080000000, -0x0ffffffff, 0.000000000000001, 2**53-2, -0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -0]); \");return 0; }})); } };})());");
/*fuzzSeed-168297596*/count=1215; tryItOut("mathy1 = (function(x, y) { return (((Math.trunc(((Math.fround(Math.fround(Math.imul(Math.fround((Math.atan2((-0x0ffffffff | 0), mathy0(x, Math.fround(y))) >>> 0)), Math.fround(0x0ffffffff)))) >>> ( ! y)) >>> 0)) >>> 0) >>> 0) & (Math.hypot(( + ( + (Math.fround(x) * ( - y)))), Math.fround(Math.fround(Math.sin((x | 0))))) >>> 0)); }); testMathyFunction(mathy1, [false, ({valueOf:function(){return '0';}}), true, (new Number(-0)), (new String('')), (new Number(0)), /0/, [0], undefined, [], NaN, ({toString:function(){return '0';}}), -0, 1, objectEmulatingUndefined(), '/0/', 0.1, (new Boolean(true)), '', null, ({valueOf:function(){return 0;}}), 0, '0', '\\0', (new Boolean(false)), (function(){return 0;})]); ");
/*fuzzSeed-168297596*/count=1216; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - (Math.hypot(Math.log(x), (x >>> 0)) >> (Math.fround(Math.clz32(x)) >>> 0))); }); testMathyFunction(mathy1, [2**53, 2**53+2, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, -Number.MAX_VALUE, -0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -0x07fffffff, 42, 1, 0x100000001, 2**53-2, Number.MIN_VALUE, -0, 0x100000000, 0.000000000000001, 0, -(2**53+2), 0x080000001, -1/0, -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=1217; tryItOut("\"use strict\"; g0.v1.toString = (function(j) { f1(j); });");
/*fuzzSeed-168297596*/count=1218; tryItOut("mathy4 = (function(x, y) { return ((Math.expm1((Math.fround(( + Math.fround(y))) <= y)) ^ Math.atan2(((( + ( - (y >>> 0))) ? x : mathy3(( - y), x)) >>> 0), (x ? ( + Math.atan2(try { z = d; } finally { try { undefined; } catch(w) {  } finally { return; }  } , ( + 0x080000000))) : -0))) ? Math.hypot(( ! y), ( + (Math.clz32(0x080000001) | 0))) : ( + ( + mathy3(( + Math.fround(Math.pow(x, Math.fround(Math.atan2(y, Math.atan2(mathy2((x >>> 0), (y >>> 0)), y)))))), ( + ( + mathy0((x == Math.sqrt((Math.cos((-0x07fffffff >>> 0)) >>> 0))), ( ! y)))))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), 1.7976931348623157e308, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 0x100000001, -0x100000001, Math.PI, Number.MIN_VALUE, -0x080000000, 42, 0/0, 1/0, 0x080000001, -0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 1, -0, 2**53+2, 2**53, -Number.MIN_VALUE, -(2**53-2), 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1219; tryItOut("v2 = g2.eval(\"/* no regression tests found */\");");
/*fuzzSeed-168297596*/count=1220; tryItOut("throw e;");
/*fuzzSeed-168297596*/count=1221; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\B)\", \"gy\"); var s = \"\"; print(s.replace(r, (z = (timeout(1800))))); ");
/*fuzzSeed-168297596*/count=1222; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.trunc(( ! ( + ((Math.sign((Math.min(( ! y), y) >>> 0)) >>> 0) === mathy0((0x080000000 >>> 0), (mathy0(Math.fround(Math.fround((Math.fround(x) >> Math.fround(x)))), (Math.round((( ~ y) | 0)) | 0)) >>> 0)))))); }); testMathyFunction(mathy1, /*MARR*/[new Boolean(true), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true), (-1/0), (1/0), (1/0), (1/0), (-1/0), (1/0), new Boolean(true), (1/0), (1/0), new Boolean(true), (1/0), new Boolean(true), (1/0), (-1/0), (-1/0), (1/0), (-1/0), new Boolean(true), (-1/0), new Boolean(true), (1/0), (1/0), (-1/0), (-1/0), (1/0), (-1/0), new Boolean(true), (1/0), new Boolean(true), new Boolean(true), (-1/0), (-1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new Boolean(true), (1/0), (-1/0), (1/0), new Boolean(true), (-1/0), (-1/0), (-1/0), new Boolean(true), (-1/0)]); ");
/*fuzzSeed-168297596*/count=1223; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000000, 0/0, 0x080000000, 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, 0.000000000000001, -(2**53-2), 2**53-2, 2**53, -(2**53), -1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, -0x100000000, -(2**53+2), 0, -0x080000001, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 0x080000001, 2**53+2, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, 1/0]); ");
/*fuzzSeed-168297596*/count=1224; tryItOut("o2 = {};");
/*fuzzSeed-168297596*/count=1225; tryItOut("g1.a1.reverse(e1);");
/*fuzzSeed-168297596*/count=1226; tryItOut("mathy4 = (function(x, y) { return mathy3(( + mathy2(( + Math.fround(Math.hypot(Math.imul((Math.imul(y, x) | 0), (( + ( + 0x0ffffffff)) | 0)), ((x | 0) | x)))), ( + (( + Math.min(( + (x | (Math.fround((-0x080000001 / Number.MAX_VALUE)) ? x : y))), ( + (x ? (x >>> 0) : ( + Math.sin((x | 0))))))) & ( + ( + (( + Math.fround(Math.ceil(Math.fround(( - y))))) ** ( + (Math.atan((y >>> 0)) >>> 0))))))))), ( + (( + ((Math.fround(Math.asinh(( + Math.exp(x)))) && (( + mathy2(Math.fround(y), ( + (((Math.abs((x | 0)) | 0) , Number.MAX_VALUE) | 0)))) >>> 0)) | 0)) & ( + Math.fround(( ~ Math.fround(( + Math.asin(Math.imul(x, Math.fround(( ~ ( + (( + x) != ( + y))))))))))))))); }); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), (new Number(-0)), null, [0], -0, (new Number(0)), true, '/0/', '', (new Boolean(true)), ({toString:function(){return '0';}}), 1, false, [], undefined, (function(){return 0;}), 0, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), (new Boolean(false)), NaN, 0.1, (new String('')), /0/, '0', '\\0']); ");
/*fuzzSeed-168297596*/count=1227; tryItOut("( \"\" );");
/*fuzzSeed-168297596*/count=1228; tryItOut("\"use strict\"; (((uneval( /x/ ))));function x(x, z) { for (var p in a2) { try { g1.v1 = g2.runOffThreadScript(); } catch(e0) { } try { g0.i1 = new Iterator(g1.o0); } catch(e1) { } p0.toString = (function() { for (var j=0;j<161;++j) { f2(j%4==1); } }); } } Object.defineProperty(this, \"this.o2.f1\", { configurable:  '' .prototype, enumerable: true,  get: function() {  return Proxy.create(this.h1, m1); } });");
/*fuzzSeed-168297596*/count=1229; tryItOut("for (var p in this.i1) { a2 = Array.prototype.concat.apply(a0, [t0, o2.o0, g0.f2, v1, f2, g0, v2]); }");
/*fuzzSeed-168297596*/count=1230; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + ( - ( + mathy0(((x | (Math.fround(Math.min(x, Math.fround(Math.sinh(( ! x))))) | 0)) | 0), Math.fround(mathy1((( + (Math.min(-Number.MAX_SAFE_INTEGER, y) | 0)) % ( + Math.fround(( - ( + mathy0(( + (mathy1((-1/0 | 0), (0/0 | 0)) | 0)), ( + Math.hypot(y, y)))))))), ( + y))))))); }); testMathyFunction(mathy2, [-0x0ffffffff, 0.000000000000001, 1/0, 2**53-2, 0x100000000, 0x100000001, -Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 0, Number.MAX_VALUE, -(2**53+2), -(2**53), -(2**53-2), 0x080000000, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, 1, 2**53, -0x100000001, -0x080000000, 0x07fffffff, -1/0, -0x100000000, Math.PI, Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-168297596*/count=1231; tryItOut("print(new RegExp(\"(?!\\\\w{63})+\", \"gim\"));");
/*fuzzSeed-168297596*/count=1232; tryItOut("mathy2 = (function(x, y) { return ( + Math.fround(Math.cos(Math.fround(Math.atan2(Math.fround(( ~ Math.fround(Math.pow(Math.fround(y), (Math.atan(((( ! (x | 0)) | 0) | 0)) | 0))))), ( + Math.expm1((Number.MIN_VALUE | 0)))))))); }); testMathyFunction(mathy2, ['/0/', objectEmulatingUndefined(), (new Boolean(false)), -0, 0.1, ({toString:function(){return '0';}}), NaN, /0/, undefined, [], (new Number(-0)), null, false, ({valueOf:function(){return '0';}}), [0], ({valueOf:function(){return 0;}}), '0', 0, (new Boolean(true)), (new String('')), (new Number(0)), 1, true, '', '\\0', (function(){return 0;})]); ");
/*fuzzSeed-168297596*/count=1233; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((Uint8ArrayView[2])))|0;\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [false, 0.1, /0/, (new Boolean(false)), (new Boolean(true)), (new Number(0)), NaN, '\\0', ({valueOf:function(){return 0;}}), [0], '/0/', (new Number(-0)), null, 1, true, 0, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '', (function(){return 0;}), [], ({toString:function(){return '0';}}), undefined, '0', (new String('')), -0]); ");
/*fuzzSeed-168297596*/count=1234; tryItOut("/*RXUB*/var r = /^|(\\3(?!(.+)[^])|(?!\\\uf0b9)){1}/g; var s = \"\\u493a\\u493a\\u493a\\uf0b9\\u493a\\u493a\\u493a\\uf0b9\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=1235; tryItOut("this.i0.next();");
/*fuzzSeed-168297596*/count=1236; tryItOut("v1 = (i1 instanceof this.a1);");
/*fuzzSeed-168297596*/count=1237; tryItOut("mathy3 = (function(x, y) { return ( + (( + ((((Math.acosh(y) || (Math.imul(y, (x | 0)) | 0)) >>> 0) / (( + x) < (mathy1((( ~ Math.imul(x, y)) >>> 0), ( + 1.7976931348623157e308)) >>> 0))) ^ ( + Math.hypot(( + Math.imul(2**53+2, ( - x))), (1.7976931348623157e308 >>> 0))))) ^ ((Math.max(((((Math.acosh(( + ( - Math.log1p(x)))) | 0) | 0) , x) & ( + (( ! 0.000000000000001) * ( + y)))), Math.atan(((Math.hypot((mathy1((( + Math.abs(( + y))) | 0), Math.fround((1/0 ^ y))) | 0), (x | 0)) | 0) | 0))) | 0) | 0))); }); ");
/*fuzzSeed-168297596*/count=1238; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-168297596*/count=1239; tryItOut("\"use asm\"; { void 0; fullcompartmentchecks(false); }function x(d =  ''  += (eval(\"mathy2 = (function(x, y) { return (Math.atan2(( + ( + Math.hypot(( + mathy0(Math.clz32(y), Math.imul(y, -Number.MIN_VALUE))), ( + Math.tanh(Math.fround(( ! x))))))), ( + Math.imul(( + (( + Math.imul(( + y), ( + y))) <= (2**53+2 >>> 0))), 1/0))) !== Math.atan2(Math.imul(Math.imul(x, (Math.asin(((Math.atanh(x) >>> 0) | 0)) | 0)), Math.asinh((x | 0))), Math.ceil(y))); }); testMathyFunction(mathy2, [0x0ffffffff, -0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, 42, -1/0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000001, 0x100000000, 2**53-2, 1/0, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), Math.PI, 0x07fffffff, 2**53, -0, -0x080000000, -(2**53), 0/0, 2**53+2, 0, -0x080000001]); \")), x) { \"use strict\"; return [(/*RXUE*//[^]/im.exec(\"\\n\"))] } ;");
/*fuzzSeed-168297596*/count=1240; tryItOut("");
/*fuzzSeed-168297596*/count=1241; tryItOut("mathy3 = (function(x, y) { return Math.abs((Math.atan2(( + (( - (y >>> 0)) >>> 0)), ( + ( + Math.max(Math.min(Math.min((Math.tan(x) | 0), (mathy0((Math.max(x, x) | 0), -0x080000001) | 0)), (x | 0)), ( + Math.tan(( + (x | 0)))))))) >>> 0)); }); testMathyFunction(mathy3, [-0x100000000, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 42, -0x080000000, 1.7976931348623157e308, 0, 0x100000000, 0x080000001, 0x07fffffff, -(2**53+2), 0/0, 1/0, -0x07fffffff, Number.MAX_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, -(2**53), 0.000000000000001, 1, -Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -0x0ffffffff, 2**53, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-168297596*/count=1242; tryItOut("try { print(x); } catch(w if (function(){x = eval;})()) { c = x; } /*vLoop*/for (xqmitz = 0; (/((?:[^]|[^\\s\\s\\\u00be-\u00f2]{3,}\\B.*?))/) && xqmitz < 30; ++xqmitz) { let d = xqmitz; yield  /x/ ; } ");
/*fuzzSeed-168297596*/count=1243; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.log1p(( + ( + ((((y | 0) << (( ! ((y | 0) <= (0 | 0))) | 0)) >>> 0) ? ((( ~ Math.max(x, Math.fround(x))) ? (Math.fround(Math.pow(Math.sinh(Math.PI), x)) + ( + (( + Math.asinh(y)) ? x : (2**53 >>> 0)))) : (y | 0)) | 0) : ( + Math.max(Math.fround(-0x07fffffff), ( + y))))))); }); testMathyFunction(mathy0, [undefined, '0', (function(){return 0;}), [], '/0/', (new Boolean(true)), (new Number(-0)), ({valueOf:function(){return 0;}}), (new String('')), ({valueOf:function(){return '0';}}), NaN, '', (new Boolean(false)), 1, null, -0, [0], /0/, objectEmulatingUndefined(), '\\0', (new Number(0)), false, ({toString:function(){return '0';}}), 0.1, 0, true]); ");
/*fuzzSeed-168297596*/count=1244; tryItOut("mathy1 = (function(x, y) { return ( + (Math.fround(mathy0(Math.fround((Math.fround(Math.cos(( + mathy0(y, x)))) | Math.fround(( ~ x)))), Math.expm1(Math.max((Math.atan2((x | 0), ((( + Math.atan2(x, y)) ? y : y) | 0)) | 0), ( + (Math.imul(y, (x >>> 0)) >>> 0)))))) === Math.fround(Math.abs((( + ( - mathy0((((( + Math.cosh(( + x))) | 0) !== (Math.fround(Math.asinh(((((y >>> 0) * (-0x0ffffffff >>> 0)) >>> 0) >>> 0))) | 0)) | 0), Math.log10((x | 0))))) | 0))))); }); ");
/*fuzzSeed-168297596*/count=1245; tryItOut("\"use strict\";  /x/g ;/*\n*/");
/*fuzzSeed-168297596*/count=1246; tryItOut("\"use strict\"; var w, llhbse, x, x, x, qusjhd, ewzsuk, mrxkfx;(\"\\uA871\");");
/*fuzzSeed-168297596*/count=1247; tryItOut("/*hhh*/function qbbudx([, , {x: eval, \u3056: {x: {this, x: [, {}], w: y, x: []}, x: x, z}, x: window, y}, {x: [x\u000c, {}, ], x: [x, ], eval, {x: eval, x: {x: [[{}, []], ], window: [], \u3056: (w)}, x: [window], x: e}: \u3056, c: [, ]}, , x(x), ({get: [b, {x: []}], e, e})], window){w = [], this.window, x, svuvhy, y, x, mytrrt, this.NaN, x;a2.sort(o0.f2);}qbbudx(Array.prototype.join.prototype, x);function x(x, a)\"use asm\";   var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i1 = (i2);\n    }\n    (Int8ArrayView[(((((i2)+((0x6f52037e) >= (0x83477cbd))) << ((i1))))+(i0)) >> 0]) = ((i2));\n    i2 = ((~~(-1.03125)) <= (((!((((0x510f226a))>>>((0x5ad28a85))) == (((0xc897584a))>>>((0x3bc45fe4)))))-((0x28a7582b) >= (((0x1988c4b6))>>>((0x6a230c80))))+((((8589934593.0)) / ((-16777217.0))) > (8193.0))) >> ((Float64ArrayView[((Uint16ArrayView[2])) >> 3]))));\n    return +((Float32ArrayView[((i2)+(i0)) >> 2]));\n  }\n  return f;/* no regression tests found */");
/*fuzzSeed-168297596*/count=1248; tryItOut("L: print(let (fbdpfx)  \"\" );");
/*fuzzSeed-168297596*/count=1249; tryItOut("mathy2 = (function(x, y) { return (Math.cosh((( + (mathy1( /x/g , (Math.hypot(Math.fround(Math.exp(Math.fround((Math.abs((y >>> 0)) >>> 0)))), (( + x) | 0)) >>> 0)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [42, -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, 1, -Number.MIN_VALUE, 0/0, -0x07fffffff, 1/0, 0.000000000000001, Number.MIN_VALUE, -0, -0x100000001, 2**53+2, -0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 0x07fffffff, -(2**53+2), 0, -(2**53), 0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53-2), -0x080000001, -1/0, -0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-168297596*/count=1250; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.tan(((( + Math.log(( + Math.trunc(y)))) | 0) < ( + ( + Math.abs(( + Math.hypot(( + -0), ( + Math.fround(( ! x))))))))))); }); testMathyFunction(mathy4, [2**53, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 0x080000000, -0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, -(2**53), -(2**53+2), -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, 0x080000001, 0.000000000000001, 42, -0, -0x0ffffffff, 0x100000001, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, 0, 1, -0x100000001, -Number.MAX_VALUE, 0x07fffffff, 1/0, 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-168297596*/count=1251; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -2305843009213694000.0;\n    var d3 = 9.0;\n    /*FFI*/ff(((abs(((((((0x467498a3)) | ((0xe9489a0b))))+(0xfd78e4e4)) >> ((i0))))|0)), ((((d3)) / ((-36028797018963970.0)))));\n    /*FFI*/ff(((0x4f4ea7d9)), ((-268435455.0)), ((((i1))|0)), ((+(0.0/0.0))), ((-2305843009213694000.0)), ((~~(NaN))), ((-0x3e18fa2)), ((9.0)), ((-3.094850098213451e+26)), ((-1.0009765625)), ((-2305843009213694000.0)), ((-1.015625)), ((-4294967297.0)), ((32769.0)), ((-4503599627370496.0)), ((-0.0009765625)), ((-1.015625)), ((16385.0)), ((-67108865.0)), ((-2147483649.0)), ((1.0078125)), ((2.4178516392292583e+24)), ((288230376151711740.0)), ((255.0)), ((2199023255553.0)), ((-1.00390625)));\n    i0 = ((0x1482b158));\n    i0 = (!(i0));\n    {\n      (Uint16ArrayView[0]) = ((i1)*-0xd7f1a);\n    }\n    {\n      (Float32ArrayView[1]) = ((Float64ArrayView[2]));\n    }\n    d2 = (((Float64ArrayView[4096])) / ((+(0.0/0.0))));\n    (Uint32ArrayView[2]) = ((((-(((4277))))|0))+((0x1bc21d72)));\n    i0 = (-0);\n    d2 = (+(0.0/0.0));\n    {\n      {\n        switch ((((i0))|0)) {\n          case -3:\n            {\n              d2 = (7.737125245533627e+25);\n            }\n            break;\n        }\n      }\n    }\n    d2 = (274877906945.0);\n    (Float32ArrayView[4096]) = ((-67108865.0));\n    d2 = (-8388609.0);\n    d3 = (131073.0);\n    (Float32ArrayView[(((0x6abd4326) == (0xd9e4367e))-(i0)-((0x3f17940b))) >> 2]) = (((+abs((((x) + (d2))))) + (1.2089258196146292e+24)));\n    {\n      i0 = (i1);\n    }\n    d3 = (+pow((((/*UUV1*/(b.fromCodePoint = (new Function(\"g2.offThreadCompileScript(\\\"this.g1.offThreadCompileScript(\\\\\\\"Array.prototype.splice.call(a0, 5, v0);\\\\\\\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 == 1), noScriptRval: (x % 2 == 0), sourceIsLazy: (x % 3 == 2), catchTermination: false }));\\\");\"))) && (4277)) - ((3.022314549036573e+23)))), ((67108863.0))));\n    {\n      switch ((~(((0x7fffffff) > (0x663878ed))-((0xd01e495a) ? (0x663532bb) : (0xf82b0a9b))))) {\n        case -3:\n          i0 = (0xe88785a9);\n        case -3:\n          i1 = (0x33ca06cd);\n          break;\n        case -2:\n          (Int32ArrayView[((((0x3c709cde)*0x83f41)>>>((0xfe2c59f2)*0xfffff)) / (((0x43229554)+(i0))>>>(((((0x37a777cd))|0))))) >> 2]) = ((x(false >> -10))-(i1)-(i1));\n        default:\n          (Float32ArrayView[2]) = ((d3));\n      }\n    }\n    return +((Float64ArrayView[0]));\n  }\n  return f; })(this, {ff: Number.isSafeInteger}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x0ffffffff, -0x080000000, 0x080000000, 0, 2**53, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 0/0, 42, -Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, 2**53+2, 0x100000000, -Number.MIN_VALUE, 0x100000001, 2**53-2, 0.000000000000001, 0x07fffffff, -(2**53), Math.PI, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, 1, 0x0ffffffff, 1/0, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1252; tryItOut("with({}) for(let y in []);");
/*fuzzSeed-168297596*/count=1253; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ ( - ((( + Math.hypot(( + Math.clz32(Math.fround(Math.min(Math.fround(y), Math.fround(Math.pow(x, y)))))), (( ! ( + ( + Math.imul(Math.fround((y && Math.fround(x))), ( + x))))) | 0))) >>> 0) + Math.fround((Math.hypot(y, (Math.round((0/0 | 0)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [-(2**53-2), -0x100000000, -(2**53), -0x07fffffff, 1/0, -0, Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 0x080000000, Number.MAX_VALUE, 0/0, 2**53+2, 0, 0x100000000, Number.MIN_VALUE, -0x100000001, 2**53-2, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -1/0, 0x080000001, -Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0x07fffffff, 1]); ");
/*fuzzSeed-168297596*/count=1254; tryItOut("");
/*fuzzSeed-168297596*/count=1255; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + (( + Math.expm1((( + (( + (Math.hypot((0x100000001 >>> 0), ( + Number.MAX_VALUE)) >>> 0)) % ( + ( + Math.min(Number.MIN_VALUE, y))))) | 0))) ** ( + (Math.asinh(((((( - ((( ~ ((1.7976931348623157e308 >= (x >= -Number.MAX_VALUE)) | 0)) | 0) | 0)) | 0) | 0) & -0x080000000) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [[0], objectEmulatingUndefined(), null, /0/, false, ({toString:function(){return '0';}}), (new Number(-0)), 0, true, '\\0', (function(){return 0;}), '', ({valueOf:function(){return '0';}}), (new Boolean(false)), -0, (new Number(0)), 0.1, (new Boolean(true)), ({valueOf:function(){return 0;}}), '0', '/0/', 1, [], undefined, NaN, (new String(''))]); ");
/*fuzzSeed-168297596*/count=1256; tryItOut("print(uneval(this.o2.b1));{ void 0; deterministicgc(false); }");
/*fuzzSeed-168297596*/count=1257; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((( ! ( + Math.hypot(( + ( + Math.sinh(( + (x << mathy1(x, x)))))), ( + ( + Math.pow(( + x), ( + 2**53))))))) | 0) > (( + (( + (( + Math.fround(Math.sin(( + ( ! ( + 0x07fffffff)))))) << ( + ((((((x >>> 0) ^ (x >>> 0)) >>> 0) >>> 0) + (y >>> 0)) >>> 0)))) != ( + ( + (( - ( + Math.log1p(Math.fround((x ? Math.imul(x, y) : (y | 0)))))) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, 2**53-2, 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, -0x0ffffffff, -1/0, -Number.MAX_VALUE, 0x07fffffff, 1/0, Math.PI, 0, -0x07fffffff, 0x080000001, 2**53, -0x100000000, -(2**53), 0x080000000, 42, -0, 0x0ffffffff, -0x100000001, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1258; tryItOut("g1.v2 = new Number(Infinity);");
/*fuzzSeed-168297596*/count=1259; tryItOut("\"use strict\"; e0.has(v1);");
/*fuzzSeed-168297596*/count=1260; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1, -0x100000001, -0x080000000, -1/0, -(2**53+2), Math.PI, Number.MAX_VALUE, 0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 42, Number.MIN_VALUE, 0/0, 0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, 1/0, -0, -0x080000001, 1.7976931348623157e308, 0, 0.000000000000001, -0x0ffffffff, 0x080000001]); ");
/*fuzzSeed-168297596*/count=1261; tryItOut("var a0 = arguments;var d = (Math.min(-24, -8));");
/*fuzzSeed-168297596*/count=1262; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=[^]|[^\\u0092-\\u12f5\\\\D]*$|\\\\cC\\\\2|\\\\b|(?!.^)+?|${2,})+(?!(?![\\\\f\\\\cM\\\\d]))\", \"gyim\"); var s = new 20(\"\\u4291\", this); print(uneval(s.match(r))); ");
/*fuzzSeed-168297596*/count=1263; tryItOut("v1 = evalcx(\"/* no regression tests found */\", this.g0);");
/*fuzzSeed-168297596*/count=1264; tryItOut("print(x);i2.next();");
/*fuzzSeed-168297596*/count=1265; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((( + ( + ( + (uneval(y))))) | 0) < Math.fround(Math.min(((( ! ((Math.min((Math.fround((-0 & y)) | 0), (Math.hypot(y, (y >>> 0)) >>> 0)) | 0) >>> 0)) & ((((Math.asinh((y | 0)) | 0) >> (Math.pow(Math.clz32((x | 0)), Math.log((x | 0))) | 0)) | 0) >>> 0)) >>> 0), (((((x != x) >>> 0) >>> 0) , Math.min(( + ( - x)), Math.sinh(Math.max(Math.log1p(y), y)))) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[ /x/ , ((makeFinalizeObserver('nursery'))), ((makeFinalizeObserver('nursery'))), (delete a.d), (delete a.d), ((makeFinalizeObserver('nursery'))), function(){}, function(){}, {x:3}, (delete a.d), (delete a.d), (delete a.d), {x:3}, function(){}, function(){}, {x:3},  /x/ ,  /x/ ,  /x/ , ((makeFinalizeObserver('nursery'))), {x:3}, ((makeFinalizeObserver('nursery'))), (delete a.d),  /x/ , {x:3}, (delete a.d), (delete a.d),  /x/ , ((makeFinalizeObserver('nursery')))]); ");
/*fuzzSeed-168297596*/count=1266; tryItOut("print(uneval(a1));");
/*fuzzSeed-168297596*/count=1267; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=1268; tryItOut("mathy3 = (function(x, y) { return (Math.fround(mathy0((((((( ~ ((Math.imul((y | 0), (Math.min(x, -0x100000000) | 0)) | 0) | 0)) | 0) | 0) ? ((( ~ (0x100000001 >>> 0)) >>> 0) | 0) : (Math.pow((Math.fround(Math.ceil(Number.MAX_VALUE)) | 0), (arguments.callee.caller | 0)) | 0)) | 0) >>> 0), (Math.acos(mathy2(Math.pow((-0x080000000 >> x), (y >>> 0)), mathy1(((((y >>> 0) > (y >>> 0)) >>> 0) | 0), (x | 0)))) >>> 0))) >= ( ! ( ~ (0x07fffffff !== ( + (x || ((x ^ x) >>> 0))))))); }); testMathyFunction(mathy3, [-(2**53-2), 2**53-2, 2**53, 1, 1.7976931348623157e308, 2**53+2, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -0x100000000, 0, 0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, 0/0, 42, -0x080000001, 0x080000001, 1/0, -Number.MAX_VALUE, -0x100000001, 0x0ffffffff, 0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -0, -0x0ffffffff, -1/0, Math.PI, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1269; tryItOut("/*iii*/a2.toString = f2;/*hhh*/function dyxpkz(){-12;}");
/*fuzzSeed-168297596*/count=1270; tryItOut("i1 = new Iterator(m1, true);");
/*fuzzSeed-168297596*/count=1271; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.asin(Math.fround(( + Math.asinh(( + (Math.expm1(((mathy0(Math.fround(Math.fround((Math.hypot((1.7976931348623157e308 >>> 0), Math.fround(Math.imul(x, (0/0 >>> 0)))) >>> 0))), (Number.MIN_VALUE | 0)) | 0) | 0)) | 0)))))) >>> 0); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -0, 0x0ffffffff, -0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 0, -0x080000001, 42, -(2**53-2), -0x07fffffff, 2**53-2, -1/0, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, 1, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, 2**53, Math.PI, -(2**53+2), 0.000000000000001, 1/0, Number.MIN_VALUE, 2**53+2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-168297596*/count=1272; tryItOut("/*bLoop*/for (fxlgtq = 0; fxlgtq < 2; ++fxlgtq) { if (fxlgtq % 29 == 24) { for(let window = y | -9 in (yield  '' )) {for (var v of f1) { try { v1 = evalcx(\"function f0(t1)  { return window } \", this.g2); } catch(e0) { } neuter(b1, \"change-data\"); }a0 = r2.exec(this.s0); } } else { i1 = new Iterator(s2); }  } ");
/*fuzzSeed-168297596*/count=1273; tryItOut("\"use strict\"; if(false) { if ((4277)\u000c) {print(x);s0.valueOf = (function() { for (var j=0;j<100;++j) { f2(j%4==1); } }); } else /*RXUB*/var r = /(?:(?![\\D\\s\\u5442\u00cc]|\\r(?!.)*|(?!(?:\\D))\\3))*?/gym; var s = true ? new RegExp(\"(?:[\\u8b99-\\\\t\\\\u00C4-\\\\uD0ff\\\\S]|\\\\d{3,}){1}(?=\\\\W|[^])|(?![^]){2}\", \"gm\") : this; print(uneval(s.match(r))); }");
/*fuzzSeed-168297596*/count=1274; tryItOut("\"use strict\"; let (a) { Array.prototype.push.call(a0, g2.i2, a); }\n/*oLoop*/for (let jxqhim = 0; jxqhim < 15; ++jxqhim) { print(x); } \n");
/*fuzzSeed-168297596*/count=1275; tryItOut("L:do {(( /x/ )( /x/ ));Array.prototype.reverse.apply(a0, [b2, g2.m0]); } while(((a = a)) && 0);");
/*fuzzSeed-168297596*/count=1276; tryItOut("b = linkedList(b, 1806);");
/*fuzzSeed-168297596*/count=1277; tryItOut("let(setyah, d, elfvqy, x = Math.imul((delete e.x ^= [,,]), -17), c = mathy2.prototype, x = (-27) =  /x/ , RangeError = 'fafafa'.replace(\u000c/a/g, (1 for (x in []))) **= new \"\\uA54F\"( \"\" ), x = allocationMarker(), x = (4277), /\\1*/ = []) ((function(){g1.p0 = t0[v2];})());");
/*fuzzSeed-168297596*/count=1278; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    {\n      d1 = (+(1.0/0.0));\n    }\n    i0 = (i0);\n    (Float64ArrayView[((imul((0x86879df1), ((-65.0) <= (-1.2089258196146292e+24)))|0) / (~~((0x59937c4a) ? (32.0) : (288230376151711740.0)))) >> 3]) = ((d1));\n    {\n      {\n        i0 = (i0);\n      }\n    }\n    d1 = (+abs(((d1))));\n    (Int8ArrayView[0]) = ((0xfe1c23cc)*0xd9c34);\n    (Uint32ArrayView[((Uint32ArrayView[1])) >> 2]) = ((0x3919e5ae)+(((((0x76031cbe) >= (0xffffffff))+(i0))>>>((i0)-((0x71785bb3))+(0xffffffff)))));\n    i0 = ((((i0)+(0xf8148e9c)) | (0xfffff*(0x81e5fc74))));\n    (Int16ArrayView[(((0xf8dd2682) ? ((((0xfe06dd9f)) >> ((0xffffffff)))) : ((0xa74a0093) == (0xf0052850)))-(0xfcdf91eb)) >> 1]) = ((i0)+(i0));\n    return +((-1.015625));\n  }\n  return f; })(this, {ff: String.prototype.toString}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000000, -0x100000000, 2**53+2, -(2**53), 1/0, 0x080000001, 0/0, 0x0ffffffff, 1, 0.000000000000001, -(2**53+2), -0x0ffffffff, 0x07fffffff, 0x080000000, 42, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, 0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 1.7976931348623157e308, -(2**53-2), Math.PI, -Number.MIN_VALUE, Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, -0, -0x07fffffff, -0x080000000, 0x100000001]); ");
/*fuzzSeed-168297596*/count=1279; tryItOut("\"use strict\"; print(x);\n;\n");
/*fuzzSeed-168297596*/count=1280; tryItOut("for (var v of b0) { try { /*ADP-2*/Object.defineProperty(a0, (((new arguments.callee.caller.caller.caller.caller.caller.caller.caller()))([])), { configurable: false, enumerable: (x % 50 != 26), get: (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = a8 | 5; var r1 = 4 - a2; var r2 = a8 ^ a7; var r3 = 0 ^ 7; var r4 = 4 - 4; var r5 = a11 ^ 0; var r6 = 8 * r0; var r7 = a10 & a11; var r8 = 8 ^ 4; var r9 = a10 * a6; var r10 = a6 | 0; var r11 = 6 * 3; var r12 = a0 / 7; var r13 = r12 | 5; a11 = a6 + a3; var r14 = r9 & 3; var r15 = a6 / 3; var r16 = r9 / 7; a5 = 3 + a10; var r17 = a8 | a2; print(a0); var r18 = 6 & r0; var r19 = 9 + r6; var r20 = r9 / r2; var r21 = a1 - 5; var r22 = r12 % r1; var r23 = r20 ^ r13; var r24 = 7 % 2; a1 = r8 ^ 9; var r25 = a1 / a3; r15 = x + 3; var r26 = a6 ^ r5; var r27 = r0 / 6; r8 = r1 / 5; var r28 = 0 % r18; var r29 = a11 % 8; var r30 = a3 % 9; var r31 = 7 & a5; var r32 = r3 + r30; var r33 = r26 / 3; var r34 = r25 % r17; r20 = 8 % r3; print(r27); var r35 = 6 ^ r22; print(r33); var r36 = a7 - a6; var r37 = r31 & r14; var r38 = r27 / r34; var r39 = r18 ^ 4; var r40 = 3 * r7; print(r2); var r41 = r3 ^ r32; var r42 = r10 - r1; var r43 = 2 | 9; var r44 = r28 * a10; r14 = r7 + a6; print(r4); r35 = r23 * r0; r4 = r1 - 1; var r45 = r42 / r13; var r46 = r41 / 5; var r47 = a0 / a1; var r48 = 4 / r9; print(r35); var r49 = 7 ^ r29; var r50 = 4 / 6; r47 = r41 | r14; r15 = r50 / 2; var r51 = 0 & a0; var r52 = r46 - r31; return a0; }), set: (function() { for (var j=0;j<60;++j) { f2(j%3==0); } }) }); } catch(e0) { } try { Object.freeze(g2); } catch(e1) { } b0 = this.t0.buffer; }");
/*fuzzSeed-168297596*/count=1281; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ((Math.sqrt(Math.max(0/0, ( + Math.expm1(x)))) >>> 0) >>> (Math.imul((Math.min(-0x080000001, y) >>> 0), Math.log10(x)) >> Math.fround(Math.atan2(Math.fround(Math.log(x)), Math.fround(Math.max(Math.atan2(y, ( + x)), -1/0)))))); }); testMathyFunction(mathy5, [0.000000000000001, -(2**53+2), 1, 0x0ffffffff, 1/0, 0x080000001, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, 0x100000001, -0x100000001, -0x080000001, 2**53, -1/0, Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53), 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 0/0, 2**53+2, -0, 42, 0x080000000, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1282; tryItOut("\"use strict\"; /*infloop*/for(var z = x; Object.defineProperty(e, \"exec\", ({configurable: true})) <<= \u3056; (void shapeOf(window.valueOf(\"number\")))) print(window);");
/*fuzzSeed-168297596*/count=1283; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1284; tryItOut("\"use strict\"; /*MXX3*/g0.Math.atan = g2.Math.atan;");
/*fuzzSeed-168297596*/count=1285; tryItOut("\"use strict\"; for (var v of p1) { try { t1[0] = v1; } catch(e0) { } try { v2 = (o0 instanceof a2); } catch(e1) { } print(uneval(this.g0.h1)); }");
/*fuzzSeed-168297596*/count=1286; tryItOut("\"use strict\"; v1 = t2.length;");
/*fuzzSeed-168297596*/count=1287; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.acos(( + Math.fround(Math.tanh(Math.fround(( ~ (( + Math.min(-0x0ffffffff, Math.fround(Math.abs(Math.hypot(( - (x >>> 0)), y))))) | 0)))))))); }); testMathyFunction(mathy4, [Math.PI, -0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, 0x080000001, 0, 0x100000000, -1/0, 1, 0.000000000000001, -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0/0, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, 0x07fffffff, 2**53-2, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, 1/0, -0x080000001, 0x100000001, 2**53, -(2**53), -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1288; tryItOut("with({}) { {} } return;");
/*fuzzSeed-168297596*/count=1289; tryItOut("var xhlmzw = new SharedArrayBuffer(2); var xhlmzw_0 = new Uint16Array(xhlmzw); print(xhlmzw_0[0]); xhlmzw_0[0] = -28; print(-2);");
/*fuzzSeed-168297596*/count=1290; tryItOut("mathy4 = (function(x, y) { return ((Math.clz32((( + (( + Math.sqrt((y | 0))) ? mathy2(( + ( + x)), (( + Math.fround((Math.fround(-(2**53-2)) != Math.fround(x)))) != (y >>> 0))) : Math.fround(Math.asinh(((y != x) | 0))))) | 0)) | 0) >> ( + ( + ((( ~ (x - Math.fround((((-(2**53-2) >>> 0) ? (Math.tanh(x) >>> 0) : (y >>> 0)) >>> 0)))) | 0) | 0)))); }); ");
/*fuzzSeed-168297596*/count=1291; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround((( - ( + (mathy0((y >>> 0), y) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [1.7976931348623157e308, -1/0, -0x07fffffff, 2**53, 0, Number.MAX_SAFE_INTEGER, -0, Math.PI, 2**53+2, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, -(2**53), -0x080000001, 0x100000000, -(2**53-2), 0.000000000000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 1, 1/0, -0x100000001, 0/0, Number.MAX_VALUE, -0x0ffffffff, 2**53-2, 42, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-168297596*/count=1292; tryItOut("\"use strict\"; M:with(Math.max(27, (4277)))e1 = new Set;");
/*fuzzSeed-168297596*/count=1293; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ! Math.fround((mathy0(( + (((( + (y | 0)) | 0) >> y) ? (( ~ (Math.PI | 0)) >>> 0) : Math.round(y))), Math.fround(( - Math.fround(Math.fround((Number.MAX_SAFE_INTEGER != y)))))) >> Math.fround(Math.atan2(x, Math.imul(( + Math.pow(Number.MIN_VALUE, ((x << (y | 0)) | 0))), -0x100000001))))))); }); testMathyFunction(mathy4, /*MARR*/[(1/0), null, ['z'], null, ['z'], (1/0), (1/0), (1/0), ['z'], null, (1/0), (1/0), (1/0), ['z'], ['z'], ['z'], null, false, ['z'], false, null, false, ['z'], null, false, (1/0), (1/0), (1/0), null]); ");
/*fuzzSeed-168297596*/count=1294; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1295; tryItOut("o2.v0 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-168297596*/count=1296; tryItOut("v0 = (a0 instanceof s0);");
/*fuzzSeed-168297596*/count=1297; tryItOut("yield x;");
/*fuzzSeed-168297596*/count=1298; tryItOut("mathy1 = (function(x, y) { return ( - (((-Number.MAX_VALUE | 0) >> ( ! ( ~ Math.tanh(Math.fround(Math.sign(( + x))))))) && (Math.imul((((-(2**53+2) >>> 0) !== ( + (((Math.abs(x) >>> 0) || (x >>> 0)) >>> 0))) >>> 0), (mathy0((Math.round(Math.fround(( ! x))) >>> 0), Math.hypot(x, x)) >>> 0)) | 0))); }); testMathyFunction(mathy1, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-168297596*/count=1299; tryItOut("/*oLoop*/for (let uibyif = 0; uibyif < 82; ++uibyif, (uneval(/*UUV2*/(NaN.includes = NaN.padStart)))) { L:if(true) {v1 = a2.length;(\"\\u00BD\"); } else o0.o1.g2.h0.iterate = Object.prototype.propertyIsEnumerable.bind(p2); } ");
/*fuzzSeed-168297596*/count=1300; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.cos((( + (( - x) !== x)) >= Math.max((( + Math.atan2(Math.atan(y), ( + x))) >>> 0), (Math.hypot((Math.imul(x, x) >>> 0), (y >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-168297596*/count=1301; tryItOut("\"use strict\"; v0 = (g2 instanceof v0);");
/*fuzzSeed-168297596*/count=1302; tryItOut("this.t2[x] = this.g0.v1;");
/*fuzzSeed-168297596*/count=1303; tryItOut("with({a:  \"\" }){}");
/*fuzzSeed-168297596*/count=1304; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.atan2(Math.fround(( ! Math.fround((Math.fround(( + ( ~ y))) + Math.fround(( + Math.cbrt(( + Math.fround(((x | 0) ? Math.fround(x) : (-0x080000001 | 0))))))))))), Math.fround(((Math.cosh(((Math.pow((y >>> 0), (x >>> 0)) >>> 0) | 0)) | 0) >>> ( ~ Math.atan2((( + 0x080000001) >>> y), Math.fround(x))))))) ? Math.fround(Math.ceil(Math.fround(((x >>> 0) > ( + x))))) : Math.fround(( + ( - Math.log(( + (Math.asin(Math.fround((( + (x >>> 0)) >>> 0))) >>> 0)))))))); }); ");
/*fuzzSeed-168297596*/count=1305; tryItOut("v0 = Object.prototype.isPrototypeOf.call(t1, o0.s1);");
/*fuzzSeed-168297596*/count=1306; tryItOut("this.p2.__proto__ = e0;print(\"\\u3AA3\");");
/*fuzzSeed-168297596*/count=1307; tryItOut("m1.has(g1.a0);\n;\n");
/*fuzzSeed-168297596*/count=1308; tryItOut("e1.has(o1);");
/*fuzzSeed-168297596*/count=1309; tryItOut("mathy3 = (function(x, y) { return Math.max(Math.atan2((Math.abs((y % Math.cosh(x))) | 0), ( + mathy2((( ~ y) | 0), y))), Math.fround(( + (( + ((( + mathy0(((( + x) || ( + y)) >>> 0), x)) ? ( + (( + x) ** ( + y))) : ( ~ (x | 0))) * ( ~ ( ~ ((Math.fround((Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) ^ (( + ( + (x | 0))) >>> 0)))))) << ( + ((Math.ceil((( - (0x100000001 | 0)) >>> 0)) >>> 0) % ( + Math.hypot(( + ( + Math.hypot(( + Number.MAX_VALUE), ( + y)))), ( + x))))))))); }); ");
/*fuzzSeed-168297596*/count=1310; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.log10(( + (( + Math.log2(Math.abs(x))) , ( + ( ~ ((Math.log2(( ~ (x | y))) >>> 0) >>> 0)))))); }); testMathyFunction(mathy0, [true, 0, null, NaN, ({valueOf:function(){return '0';}}), (new Boolean(false)), [], undefined, ({valueOf:function(){return 0;}}), (new Number(0)), ({toString:function(){return '0';}}), false, (function(){return 0;}), '/0/', 1, -0, /0/, '', 0.1, '0', '\\0', objectEmulatingUndefined(), (new String('')), [0], (new Boolean(true)), (new Number(-0))]); ");
/*fuzzSeed-168297596*/count=1311; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: (eval).bind(([] = x), \"\\uEFD5\" + ++x)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=1312; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1313; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(mathy0(( + Math.cosh(( + ( ! ( + Math.asinh(Math.fround(mathy0((Math.expm1((y >>> 0)) >>> 0), (Math.log2(Math.fround(0x080000000)) | 0))))))))), ( + Math.fround(mathy0(Math.fround(mathy0(-Number.MAX_VALUE, Math.fround(x))), ( + Math.fround((Math.fround(( ! (-0x080000000 | 0))) , ((( + (Math.imul(y, ( ! x)) >>> 0)) ? ( + x) : y) >>> 0))))))))); }); testMathyFunction(mathy1, [true, '/0/', (new Boolean(false)), -0, '0', ({toString:function(){return '0';}}), '', null, 0.1, undefined, [], ({valueOf:function(){return 0;}}), false, 0, NaN, ({valueOf:function(){return '0';}}), (new Number(0)), (new Number(-0)), (new Boolean(true)), /0/, (function(){return 0;}), objectEmulatingUndefined(), '\\0', (new String('')), 1, [0]]); ");
/*fuzzSeed-168297596*/count=1314; tryItOut("i1.send(o0);");
/*fuzzSeed-168297596*/count=1315; tryItOut("\"use strict\"; o2.s1 = new String(m1);");
/*fuzzSeed-168297596*/count=1316; tryItOut("/*MXX1*/o2 = g2.DataView.prototype.buffer;");
/*fuzzSeed-168297596*/count=1317; tryItOut("t2[19] = v1;\n/*tLoop*/for (let x of /*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , [undefined], [undefined],  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , [undefined], [undefined],  /x/ , [undefined],  /x/ , [undefined], [undefined], [undefined], [undefined],  /x/ , [undefined], [undefined],  /x/ , [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined],  /x/ , [undefined], [undefined],  /x/ , [undefined], [undefined],  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , [undefined],  /x/ ,  /x/ , [undefined], [undefined],  /x/ ,  /x/ , [undefined],  /x/ , [undefined], [undefined],  /x/ , [undefined],  /x/ , [undefined],  /x/ , [undefined], [undefined], [undefined], [undefined],  /x/ , [undefined],  /x/ ,  /x/ , [undefined],  /x/ , [undefined],  /x/ ,  /x/ ,  /x/ ,  /x/ , [undefined]]) { o1 = Object.create(h0); }\n");
/*fuzzSeed-168297596*/count=1318; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ mathy0(Math.atan(( + Math.max(( + x), ( + (Math.min(Math.min(( + ((( + x) >> ( + y)) | 0)), ( + y)), (-0x100000001 >>> 0)) | 0))))), ((Math.max((y | 0), ((((( + Math.imul(y, y)) ? (( ! (y >>> 0)) >>> 0) : (x | 1)) | 0) ? (y / Math.log1p(-1/0)) : x) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy1, [1/0, -0x080000001, -Number.MAX_VALUE, Math.PI, 0/0, 0x100000001, -0x100000001, -0x07fffffff, 42, -0x100000000, 0x080000001, 2**53+2, -(2**53-2), 0, -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, 0.000000000000001, -(2**53), 0x07fffffff, 2**53, 2**53-2, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 1, -(2**53+2), -1/0, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=1319; tryItOut("\"use strict\"; x;");
/*fuzzSeed-168297596*/count=1320; tryItOut("testMathyFunction(mathy0, [0x080000001, 42, -Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -0x07fffffff, 0x100000000, -0x080000001, 0/0, -(2**53-2), -0, 2**53-2, -0x080000000, -0x100000000, 1.7976931348623157e308, -0x0ffffffff, 0, Number.MIN_VALUE, 0.000000000000001, 1, -0x100000001, 0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 2**53, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1321; tryItOut("\"use strict\"; /*oLoop*/for (var hmeqkg = 0; hmeqkg < 107; ++hmeqkg) { {print(true); } } ");
/*fuzzSeed-168297596*/count=1322; tryItOut("mathy3 = (function(x, y) { return (( + (Math.fround((((Math.fround(Math.hypot(Math.fround(( + Math.atan2(( + (x % Math.fround(x))), ( + 1)))), mathy1(((-Number.MAX_SAFE_INTEGER << (y >>> 0)) | 0), 0x100000000))) | 0) <= (Math.fround(Math.sin((y | 0))) >>> 0)) >>> 0)) ? Math.fround((mathy0(Math.fround(Math.log2(Math.fround(x))), (-Number.MAX_SAFE_INTEGER >>> 0)) ^ Math.fround((Math.fround(y) , Math.fround(Math.hypot(( + (y >>> 0)), y)))))) : Math.fround(( - ( + Math.acos(y)))))) && Math.log1p(Math.fround((Math.fround((( + (((((mathy0((y | 0), (x | 0)) | 0) | 0) - ( + -(2**53))) | 0) % x)) != (Math.fround(x) ? ( + ( + Math.abs((y >>> 0)))) : Math.fround((2**53-2 >>> y))))) << Math.fround(-Number.MIN_SAFE_INTEGER))))); }); testMathyFunction(mathy3, [2**53-2, -Number.MIN_SAFE_INTEGER, 2**53, -0, -0x0ffffffff, -(2**53), -0x100000000, Number.MIN_VALUE, 0x07fffffff, 0.000000000000001, -(2**53-2), -1/0, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000001, 42, -Number.MIN_VALUE, 0/0, -0x080000001, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 2**53+2, -0x080000000, -0x100000001, 0x080000000, -Number.MAX_VALUE, 1/0, 0x100000001]); ");
/*fuzzSeed-168297596*/count=1323; tryItOut("\"use asm\"; v1 = r1.multiline;");
/*fuzzSeed-168297596*/count=1324; tryItOut("\"use strict\"; for (var p in g1.a1) { try { s2 += s0; } catch(e0) { } try { s2 += s1; } catch(e1) { } print(uneval(o1)); }");
/*fuzzSeed-168297596*/count=1325; tryItOut("h2.__proto__ = g1.o1.g0.i1;");
/*fuzzSeed-168297596*/count=1326; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0.1, 1, '0', ({valueOf:function(){return '0';}}), (function(){return 0;}), (new Number(0)), '', [], objectEmulatingUndefined(), (new Boolean(true)), /0/, (new Number(-0)), [0], NaN, ({valueOf:function(){return 0;}}), '/0/', (new String('')), true, '\\0', -0, null, 0, (new Boolean(false)), ({toString:function(){return '0';}}), false, undefined]); ");
/*fuzzSeed-168297596*/count=1327; tryItOut("\"use strict\"; testMathyFunction(mathy4, [undefined, 0.1, -0, (new String('')), objectEmulatingUndefined(), 1, '', ({toString:function(){return '0';}}), /0/, '\\0', (new Boolean(true)), (function(){return 0;}), (new Number(-0)), (new Boolean(false)), '0', true, ({valueOf:function(){return 0;}}), '/0/', ({valueOf:function(){return '0';}}), null, (new Number(0)), [0], 0, false, NaN, []]); ");
/*fuzzSeed-168297596*/count=1328; tryItOut("\"use strict\"; this.h2.fix = String.prototype.charCodeAt;var d = (void options('strict_mode'));");
/*fuzzSeed-168297596*/count=1329; tryItOut("t2[x];");
/*fuzzSeed-168297596*/count=1330; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.hypot(( + (( + (( - mathy3(x, Math.abs(0x080000000))) ^ ((( + y) ^ ( + 0/0)) >>> 0))) >>> ( + x))), Math.min(((((((((x ? y : y) == ( + y)) | 0) || (((y >>> 0) ** x) | 0)) | 0) ? (-Number.MAX_VALUE | 0) : (Math.atan2(( + y), ( + 2**53)) | 0)) | 0) | 0), ( + Number.MAX_VALUE))) | Math.fround((Math.atan2((( + (( + ( + Math.log2(Math.acos(2**53-2)))) || Math.fround(( ~ x)))) >>> 0), (((y + 2**53+2) + ( + (1.7976931348623157e308 ? ( + x) : Math.fround(Math.expm1(( + ( - mathy2((-(2**53-2) >>> 0), (y >>> 0))))))))) | 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, 2**53, 0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -0x100000000, 1/0, -0x07fffffff, -0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, 2**53-2, 0x07fffffff, 0/0, 0, Math.PI, 1.7976931348623157e308, 0x100000001, -1/0, 2**53+2, -(2**53), -(2**53+2), 0x100000000, -0, -Number.MIN_VALUE, 0x080000000, -0x100000001, 42, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1331; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.hypot(mathy0(Math.cosh(( - (y % (( - x) | 0)))), Math.fround(( ~ (Math.atan2(Math.fround(( ! ( + Math.atanh(( + x))))), (Math.hypot((( ~ ( + y)) > x), ( + Math.max(x, -Number.MIN_SAFE_INTEGER))) | 0)) >>> 0)))), (( + Math.clz32(Math.atan2(Math.abs(((0x0ffffffff , y) | 0)), (Math.atan(((x ? x : y) >>> 0)) >>> 0)))) % ( + Math.pow(( ! Math.pow(x, (y | 0))), (( + mathy0(( + (y === (Math.max(y, (-0x080000001 | 0)) | 0))), ( + x))) >>> 0))))); }); testMathyFunction(mathy1, [2**53+2, 0x080000001, 1, 2**53-2, 1.7976931348623157e308, -0, -0x07fffffff, Number.MAX_VALUE, 0, -0x100000000, Number.MIN_SAFE_INTEGER, 0/0, -1/0, -Number.MAX_VALUE, -0x100000001, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 0x100000000, -Number.MIN_VALUE, Math.PI, 0x080000000, 42, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, 0x0ffffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-168297596*/count=1332; tryItOut("testMathyFunction(mathy0, [-0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -0, 1/0, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, 0, 0x0ffffffff, -0x0ffffffff, Math.PI, 0x080000001, -0x07fffffff, 2**53+2, 1, 0x080000000, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000000, 2**53, 42, -(2**53-2), -Number.MAX_VALUE, -1/0, 0/0]); ");
/*fuzzSeed-168297596*/count=1333; tryItOut("s1 += s0;");
/*fuzzSeed-168297596*/count=1334; tryItOut("v0 = t0.byteOffset;");
/*fuzzSeed-168297596*/count=1335; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.hypot(mathy2(Math.fround(Math.log10(((Math.pow((-Number.MIN_SAFE_INTEGER >>> 0), (y >>> 0)) >>> 0) >>> 0))), Math.fround(Math.pow(Math.abs(((Math.atan2(x, -Number.MIN_VALUE) ? x : mathy1((0x07fffffff | 0), (y | 0))) >>> 0)), x))), mathy4(Math.cbrt(y), (( ~ ( + ( + (Math.sign(y) >>> 0)))) >>> 0))); }); testMathyFunction(mathy5, [-(2**53-2), -0x07fffffff, 1/0, -0x100000000, 1.7976931348623157e308, 1, Number.MAX_SAFE_INTEGER, -(2**53), 2**53, -0x080000000, -Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, -0x100000001, Number.MIN_VALUE, 42, 0.000000000000001, -Number.MIN_VALUE, 0/0, 0x080000000, 0x100000000, Math.PI, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 0x080000001, 0, -0, 0x100000001, 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1336; tryItOut("o1.v1 = a0.reduce, reduceRight(s2, s0);");
/*fuzzSeed-168297596*/count=1337; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.min(Math.fround(Math.log((Math.max(((( + ( + Math.fround((Math.pow(-Number.MAX_VALUE, (2**53 | 0)) | 0)))) ** (x + ( + ( + ( + -Number.MIN_SAFE_INTEGER))))) | 0), ((((( - Math.fround(((( + Math.max(x, x)) === x) | 0))) >>> 0) >>> 0) ? Math.pow((Math.log(-Number.MIN_VALUE) >>> 0), y) : (Math.atan2(Math.fround(x), Math.fround(Math.expm1(Math.expm1(x)))) | 0)) | 0)) | 0))), Math.fround(Math.pow(( + (y < ( + x))), ( + ((Math.atan2(y, Math.fround(Math.log(Math.fround(y)))) >>> 0) - Math.log(x))))))); }); testMathyFunction(mathy4, [-0x0ffffffff, 2**53+2, -0x080000001, 1.7976931348623157e308, 0x07fffffff, 0.000000000000001, -0x07fffffff, -(2**53+2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, 1, 0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0/0, 0x100000000, Number.MIN_VALUE, -(2**53-2), 1/0, -Number.MAX_VALUE, -0x100000001, 0x100000001, -0x100000000, 0, -0, Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-168297596*/count=1338; tryItOut("/*RXUB*/var r = new RegExp(\".\", \"gyi\"); var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=1339; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (((( ~ y) | 0) | (y | 0)) << Math.sin((mathy1(x, (-0x080000000 >>> mathy1(((x >> y) >>> 0), x))) >>> 0)))) != ( + (Math.abs(((( + x) !== Math.fround(mathy0((Math.hypot((y >>> 0), (x >>> 0)) >>> 0), x))) >>> 0)) | 0))); }); ");
/*fuzzSeed-168297596*/count=1340; tryItOut("\"\\uAFB5\";(null);");
/*fuzzSeed-168297596*/count=1341; tryItOut("Array.prototype.splice.apply(a1, []);");
/*fuzzSeed-168297596*/count=1342; tryItOut("\"use strict\"; for (var v of p2) { s0.toString = f0; }");
/*fuzzSeed-168297596*/count=1343; tryItOut("\"use strict\"; function shapeyConstructor(ngblxv){\"use strict\"; this[\"arguments\"] = Math.round(ngblxv);Object.preventExtensions(this);if (timeout(1800)) this[\"toString\"] = [1];return this; }/*tLoopC*/for (let e of /*MARR*/[0x07fffffff, 0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\u62B5\", (0/0), objectEmulatingUndefined(), \"\\u62B5\", \"\\u62B5\"]) { try{let agrelq = new shapeyConstructor(e); print('EETT'); Array.prototype.sort.apply(a0, [this.g2.s1, o1, /*UUV1*/(agrelq.exp = encodeURIComponent), p1]);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-168297596*/count=1344; tryItOut("h2.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-168297596*/count=1345; tryItOut("\"use strict\"; let d = \"\\u94F6\"(window), a, x;print(uneval(b0));");
/*fuzzSeed-168297596*/count=1346; tryItOut("/*vLoop*/for (fnrtel = 0, (4277); fnrtel < 11; ++fnrtel) { let b = fnrtel; print(window); } ");
/*fuzzSeed-168297596*/count=1347; tryItOut("/*bLoop*/for (ubojii = 0, of, -10; ubojii < 53; ++ubojii) { if (ubojii % 16 == 2) { /*MXX3*/g1.g1.String.prototype.trim = g2.String.prototype.trim; } else { print(x); }  } \nswitch(x) { default: break; m0 = new Map(s0);break; case 8: break; case 8: print(x); }\n");
/*fuzzSeed-168297596*/count=1348; tryItOut("mathy3 = (function(x, y) { return Math.hypot((Math.pow((Math.fround(( ! Math.pow((Math.max(( + (0.000000000000001 || y)), (Math.fround((Math.fround(y) - Math.fround((Math.pow(y, x) >>> 0)))) >>> 0)) >>> 0), x))) >>> 0), (( - ((Math.fround(y) % Math.fround(Math.round(y))) | 0)) | 0)) | 0), Math.hypot(mathy2(Math.imul(( + Math.sin(( + ( + mathy0((y >>> 0), (y >>> 0)))))), mathy2(x, 0)), (((Math.acosh(x) >>> 0) * ((x == y) >>> 0)) >>> 0)), ( ! x))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -(2**53), Number.MAX_VALUE, 0x07fffffff, 42, 0.000000000000001, 0x100000001, -(2**53+2), 0x080000000, -0x0ffffffff, 0/0, 1, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, Number.MAX_SAFE_INTEGER, -0, 2**53+2, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_VALUE, Math.PI, 0x100000000, -0x100000001, 1.7976931348623157e308, 2**53-2, 0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, -0x100000000, -0x07fffffff, -0x080000000, -1/0]); ");
/*fuzzSeed-168297596*/count=1349; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.sign(( + ((((Math.expm1(Math.fround(Math.cos(Math.fround(x)))) >>> 0) >>> 0) * (Math.fround(Math.log1p(Math.fround(( + ( - x))))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-168297596*/count=1350; tryItOut("(/*MARR*/[[1], -15, [,,], function(){}, [,,], -15, new String('q'), [,,], function(){}, new String('q'), function(){}, new String('q'), -15, new String('q'), [1], function(){}, new String('q'), [,,], new String('q'), new String('q'), new String('q'), [1], -15, [1], [1], -15, [,,], new String('q'), [,,], function(){}, [1], -15, new String('q'), new String('q'), new String('q'), [1], function(){}, [,,], [,,], [,,], [,,], function(){}, new String('q'), -15, -15, [1], -15, -15, -15, [,,], [1], function(){}, [,,], new String('q'), new String('q'), -15, [1], function(){}, [,,], [1], new String('q'), [1], [1], new String('q'), [,,], -15, [1], function(){}, [1], new String('q'), -15, [1], new String('q'), [,,], new String('q'), new String('q'), [1], [1], [1], -15, function(){}, new String('q'), new String('q'), [,,], new String('q'), function(){}, [1], -15, [1], -15, [,,], new String('q'), [1], [1], new String('q'), function(){}, function(){}, new String('q'), new String('q'), -15, [1], [1], function(){}, [1], [,,], new String('q'), -15, function(){}, [,,], new String('q'), [1], -15, -15, -15, [,,], [1], new String('q'), new String('q'), -15, [1], [1], function(){}, -15, new String('q'), [,,], [,,], new String('q'), [,,], -15, [,,], [1], -15, new String('q'), [1], function(){}, -15, new String('q'), new String('q'), function(){}, function(){}, function(){}, [,,], [1], [,,], [,,], new String('q'), function(){}, -15, function(){}, [1], function(){}, function(){}, new String('q'), function(){}, function(){}, function(){}, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], -15, new String('q'), new String('q'), function(){}]);");
/*fuzzSeed-168297596*/count=1351; tryItOut("{}-5;");
/*fuzzSeed-168297596*/count=1352; tryItOut("\"use asm\"; f2(g0.i0);");
/*fuzzSeed-168297596*/count=1353; tryItOut("\"use asm\"; /*RXUB*/var r = /\\3\\D(?!(?!\\s{2}){4})+|(?!(?=\\D))/gi; var s = \"\\u0096\\u0096\\u0096\\u00960\"; print(uneval(s.match(r))); ");
/*fuzzSeed-168297596*/count=1354; tryItOut("\"use strict\"; g0.f0 = (function() { try { a1.forEach((function(j) { f1(j); }), v1, s0); } catch(e0) { } h2.__iterator__ = (function mcc_() { var faxrwy = 0; return function() { ++faxrwy; if (/*ICCD*/faxrwy % 3 == 2) { dumpln('hit!'); try { a2.forEach((function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -1.0009765625;\n    {\n      i0 = ((((/*FFI*/ff((((Int16ArrayView[(0x1075*(i2)) >> 1]))), ((-0x8000000)), ((abs((0x68b54fe5))|0)))|0)-(i3))>>>((i3)+(i3))) >= (((0xffffffff)+(i2))>>>((((-8193.0) <= (((2147483647.0)) / ((-6.189700196426902e+26))))+(i0)+(-0x8000000)))));\n    }\n    switch ((((0xdfa5689e)+((-1.125) <= (-524289.0))) | ((0x46531204)-(0x42abd783)-(0xffffffff)))) {\n      case -3:\n        {\n          d4 = ((d1));\n        }\n        break;\n    }\n    i0 = (i0);\n    return +((-3.0));\n    switch ((0x41ca3973)) {\n      case -1:\n        i0 = (0x41356b14);\n    }\n    {\n      {\n        {\n          i2 = (!((d4) <= ((d4))));\n        }\n      }\n    }\n    i2 = ((d4) == (+/*FFI*/ff()));\n    i0 = (/*FFI*/ff(((abs(((((((0xbd92eb9a) ? (-0x8000000) : (0x79db6e5f))+(0xfaa6ea92)-((((0x986839e1))>>>((0xf8d17fee))) >= (((0x52701115))>>>((0xffffffff))))))+(i0)) ^ ((i0)-(0x9e8dac93))))|0)))|0);\n    return +((d4));\n  }\n  return f; })(this, {ff: function(y) { for (var p in g2.b0) { g1.a0.shift(); } }}, new ArrayBuffer(4096))); } catch(e0) { } try { m1.set(t2, f0); } catch(e1) { } try { v2 = r2.compile; } catch(e2) { } /*MXX2*/g0.String.prototype.toLocaleUpperCase = e2; } else { dumpln('miss!'); v1.toString = (function(j) { if (j) { try { v1 = evaluate(\"o1 = a0[12];\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*FARR*/[/(?=\\3+)|\\3{3,3}(?=.*?|\\1|[^]{2,}|[^\u7dba\u00f7\\x32-[\\W]+?|[^]|\\s[^]*?)/gi, ...[], , true, this].sort(/*wrap3*/(function(){ var wyzxjm = this; (WeakMap)(); })), noScriptRval: true, sourceIsLazy: (x % 4 != 2), catchTermination: (x % 83 != 19) })); } catch(e0) { } o1.i1 = new Iterator(o1); } else { try { ; } catch(e0) { } v0 = a1.length; } }); } };})(); return a1; });");
/*fuzzSeed-168297596*/count=1355; tryItOut("mathy1 = (function(x, y) { return Math.acosh(( ~ Math.hypot((x , (( ! (( ! Math.tan(y)) >>> 0)) >>> 0)), (( ! (Math.imul(x, x) | 0)) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[null, x, x, null, x, null, null, x, x, x, null, x, null, null, null, null, null, null, null, x, null, null, x, x, null, x, x, x, x, null, null, null, null, x, null, null, null, null, null, null, null, null, null, null, x, null, null, null, x, x, null, null, null, null, x, null, x, null, x, null, x, null, null, null, null, null, null, x, x, null, null, null, x, null, x, null, null, null, x, null, null, null, x, x, null, null, null, null, x, null, null, null, null, x, null, null, null, null, null, null, x, null]); ");
/*fuzzSeed-168297596*/count=1356; tryItOut("/*infloop*/for(z = (4277); new (NaN)(18); window) {x = f1; }");
/*fuzzSeed-168297596*/count=1357; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, Number.MAX_VALUE, 0x080000001, 2**53-2, -(2**53+2), -(2**53-2), 0x080000000, Number.MIN_VALUE, 1/0, -0x080000001, -0, 2**53, -0x080000000, 0x07fffffff, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, 0x0ffffffff, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, 1, -0x07fffffff, 0, 0x100000000]); ");
/*fuzzSeed-168297596*/count=1358; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=1359; tryItOut("v2 = (e1 instanceof g1);");
/*fuzzSeed-168297596*/count=1360; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.trunc(Math.tanh(mathy0((Math.acosh(x) | 0), (( ~ ((mathy0((Math.fround(( - Math.fround((Math.fround((y | 0)) | 0)))) | 0), (( - (y | 0)) | 0)) | 0) | 0)) | 0)))); }); ");
/*fuzzSeed-168297596*/count=1361; tryItOut("mathy2 = (function(x, y) { return ( + ( ! Math.log10(( + (( ~ (Math.fround(( - Math.fround(x))) | 0)) | 0))))); }); testMathyFunction(mathy2, /*MARR*/[0x10000000, arguments.callee, arguments.callee]); ");
/*fuzzSeed-168297596*/count=1362; tryItOut("/*infloop*/for(\"\\u860A\"; ({x:  /x/ });  \"\" ) {(this);p0.toSource = (function(j) { if (j) { try { m2.has(this.o2); } catch(e0) { } try { v2 = g0.eval(\"a0 + p2;\"); } catch(e1) { } for (var v of b1) { try { for (var p in f2) { try { ; } catch(e0) { } v2 = g2.runOffThreadScript(); } } catch(e0) { } try { v2 = r2.sticky; } catch(e1) { } try { o0 = Object.create(e0); } catch(e2) { } /*ADP-1*/Object.defineProperty(this.a2, v1, ({get: q => q, set: (neuter).bind})); } } else { try { a0 + i2; } catch(e0) { } try { Array.prototype.push.call(a0, g0, this.v1, m0); } catch(e1) { } try { t1 = new Uint8Array(b0, 20,  /x/g ); } catch(e2) { } h1[\"reduceRight\"] = o2; } }); }");
/*fuzzSeed-168297596*/count=1363; tryItOut("(this);");
/*fuzzSeed-168297596*/count=1364; tryItOut("e1.has(this.__defineSetter__(\"c\", Int16Array));");
/*fuzzSeed-168297596*/count=1365; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( - ( + ((( + (( - (Math.min((x >>> 0), (y >>> 0)) >>> 0)) >>> 0)) >>> 0) || (Math.sign((y | 0)) | 0)))) | 0); }); testMathyFunction(mathy4, [(new String('')), true, '\\0', null, (new Boolean(true)), (new Number(0)), 1, '/0/', '0', 0.1, 0, ({valueOf:function(){return 0;}}), NaN, -0, objectEmulatingUndefined(), ({toString:function(){return '0';}}), false, undefined, (new Boolean(false)), [], '', (new Number(-0)), /0/, [0], (function(){return 0;}), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-168297596*/count=1366; tryItOut("\"use strict\"; /*infloop*/L:while(x)print(x);");
/*fuzzSeed-168297596*/count=1367; tryItOut("\"use strict\"; { void 0; void relazifyFunctions(); }");
/*fuzzSeed-168297596*/count=1368; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ! ( + ( ! (mathy0(( + ((Math.fround(Math.imul(x, x)) >> Math.fround(x)) >>> 0)), Math.fround(Math.imul(Math.fround(( ! (x | 0))), Math.fround((mathy0(((y , ( + x)) | 0), (mathy0(x, x) | 0)) | 0))))) >>> 0)))); }); testMathyFunction(mathy1, [0x0ffffffff, 0, Number.MIN_VALUE, -0x080000000, -0x080000001, -0x07fffffff, 0x100000000, 1/0, -(2**53-2), -0x100000000, 1.7976931348623157e308, -(2**53+2), -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -0, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, 1, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53+2, 2**53, Math.PI, 42, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, -0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-168297596*/count=1369; tryItOut("{Object.prototype.unwatch.call(a1, \"call\"); }");
/*fuzzSeed-168297596*/count=1370; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.max((Math.hypot(( + ( - ( + x))), -0x080000001) >= Math.fround((Math.ceil((x | 0)) >>> 0))), (((( + (( + ( ! (Math.pow(y, y) >>> 0))) % y)) >>> 0) > (((Math.fround((Math.hypot(x, y) ? y : y)) , Math.min(( + mathy0(y, ( + (y > (Math.pow((y | 0), (x | 0)) >>> 0))))), (0x080000000 >>> 0))) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -0x100000001, 0x07fffffff, Number.MIN_VALUE, 2**53+2, 0x0ffffffff, 2**53-2, 0x100000001, 0x100000000, -0x080000001, 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, 1, -0x07fffffff, 0.000000000000001, Math.PI, 0, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 0x080000001, 1/0, -(2**53), 2**53]); ");
/*fuzzSeed-168297596*/count=1371; tryItOut("i0.send(i2);");
/*fuzzSeed-168297596*/count=1372; tryItOut("g1.__iterator__ = (function() { try { v1 = g1.g2.t0.length; } catch(e0) { } try { /*MXX2*/g2.Int16Array = g0; } catch(e1) { } try { i0 = a2[x.valueOf(\"number\")]; } catch(e2) { } a0 = (function() { yield /*FARR*/[].some(let (c)  ''  ? x : \"\\u773C\"\n); } })(); return f2; });");
/*fuzzSeed-168297596*/count=1373; tryItOut("\"use asm\"; g2.m0.delete(p2);");
/*fuzzSeed-168297596*/count=1374; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1|(?![]?(?!@){2})|(?=[^]+?)|(?:\\\\2{3,})**\", \"m\"); var s = \"\\n\\n\\n________________________________\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n________________________________\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n________________________________\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\\n\\n\\n/\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=1375; tryItOut("\"use asm\"; /*oLoop*/for (let andyot = 0; andyot < 0; ++andyot) { print(x); } ");
/*fuzzSeed-168297596*/count=1376; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy2(((Math.atanh(( + -Number.MIN_VALUE)) >>> 0) ^ (mathy1((( + Math.atan2(y, ( + y))) >>> 0), ( - (Math.sqrt((Math.max((2**53+2 >>> 0), Math.fround(x)) == y)) >>> 0))) >>> 0)), mathy1(Math.pow((Math.pow(mathy0(Math.fround(x), Math.round((x >>> 0))), x) >>> 0), Math.fround(mathy2(y, (y ? ((-0x100000000 | 0) >= Math.abs(( + x))) : (x | y))))), ((mathy2(((x % y) >>> 0), ((y || Number.MIN_VALUE) >>> 0)) >>> 0) ** (( ~ (Math.fround(Math.max(Math.fround(Math.fround(((y >>> 0) + (x | 0)))), ( ~ x))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[x, x, ({}), arguments.callee, arguments.callee, x, ({}), x, ({}), ({}), arguments.callee, x, ({}), arguments.callee, ({}), ({}), x, x, x, arguments.callee, x, x, arguments.callee, arguments.callee, ({}), x, x, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, ({}), x, ({}), x, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, x, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, ({}), x, ({}), ({}), ({}), x, arguments.callee, ({}), ({}), x, x, x, arguments.callee]); ");
/*fuzzSeed-168297596*/count=1377; tryItOut("/*bLoop*/for (var gdgzmz = 0; gdgzmz < 90; ++gdgzmz) { if (gdgzmz % 4 == 0) { for (var v of i0) { try { /*ODP-3*/Object.defineProperty(g0.s1, new String(\"10\"), { configurable: 12, enumerable: false, writable: false, value: p1 }); } catch(e0) { } try { Object.defineProperty(o0, \"o1.o0\", { configurable: (x % 65 != 35), enumerable: true,  get: function() {  return {}; } }); } catch(e1) { } a0.unshift(this.g1, o1.v2); } } else { a0.push(g2, x, v1); }  } ");
/*fuzzSeed-168297596*/count=1378; tryItOut("s2 += s1;");
/*fuzzSeed-168297596*/count=1379; tryItOut("let b = x, xfxzea, c, sigbdw, kvpfwg, window, tlqxyh, qndbov, usanpi;/*RXUB*/var r = /[\\cK-\\cQ\u90ee]|[^]+?.{1,}/gyi; var s = \"\\n\\n\\uffeb\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=1380; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.sqrt(({x: ( \"\"  ** \"\\uAD90\")}).__defineGetter__(\"x\",  /x/ )) | 0); }); testMathyFunction(mathy1, [0x080000000, -Number.MIN_VALUE, 0x080000001, 0.000000000000001, Number.MIN_VALUE, 0x07fffffff, -0x080000001, -(2**53-2), 1, 42, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, 1/0, Number.MAX_VALUE, -0x080000000, 2**53, -Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, 0/0, -0x100000000, -0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), 2**53+2, 0, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1381; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return mathy1(( + ((((( ~ (( + (( + Math.fround((Math.fround(x) >>> Math.fround(( ~ x))))) ? ( + y) : -Number.MIN_VALUE)) >>> 0)) >>> 0) | 0) == Math.fround(( + ( ~ y)))) | 0)), Math.imul(Math.fround(( - ( + Math.imul(( + y), ( + y))))), Math.abs(Math.PI))); }); testMathyFunction(mathy3, [0x07fffffff, -0x0ffffffff, -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 0.000000000000001, -0x080000000, -0x080000001, 0x080000001, -1/0, 0x0ffffffff, -0x07fffffff, -(2**53), 0x100000001, Number.MAX_VALUE, -0, 0/0, 1, -0x100000000, 0x100000000, -(2**53+2), -Number.MAX_VALUE, 42, 2**53+2, -Number.MIN_VALUE, 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 0, 0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=1382; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1383; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1384; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(( + mathy1(Math.asinh(x), (y + ( + y))))) % (Math.acos(Math.fround(Math.fround(Math.fround((y >>> 0))))) >= (( ~ Math.expm1(x)) || Math.atan2(y, (Math.imul((Math.fround(Math.hypot(Math.fround((-Number.MAX_SAFE_INTEGER ? y : x)), Math.fround(y))) | 0), (((y / x) == x) | 0)) | 0))))); }); testMathyFunction(mathy5, [-0x100000000, 0x080000000, 2**53+2, -0x080000001, 2**53-2, -Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 2**53, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, Math.PI, -0, -(2**53+2), Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 1/0, 0x0ffffffff, -(2**53), 42, 0x080000001, 0x100000001, -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1385; tryItOut("\"use strict\"; { void 0; minorgc(false); }  for (var x of x.__defineGetter__(\"\\u3056\", function(y) { return null })) {print(x);v1 = null; }");
/*fuzzSeed-168297596*/count=1386; tryItOut("\"use strict\"; ((new ( /x/g )(\"\\u8B12\", \"\\uD8E8\")));");
/*fuzzSeed-168297596*/count=1387; tryItOut("mathy3 = (function(x, y) { return ((Math.hypot(Math.fround((Math.max(mathy0((x >>> 0), (y >>> 0)), ((Math.exp((Math.fround(mathy1(Math.fround(( + Math.atan2(Math.fround(-Number.MAX_SAFE_INTEGER), (y | 0)))), Math.fround(x))) >>> 0)) >>> 0) / Math.acosh((((x | 0) | (Math.atan2(x, x) | 0)) | 0)))) >>> 0)), (( + ((( - (Math.atan2(((y , Math.pow((y | 0), (x | 0))) >>> 0), (y >>> 0)) >>> 0)) | 0) < (true | 0))) | 0)) | 0) + mathy0(( + ( ~ Math.fround(Math.min(Math.fround(-Number.MIN_VALUE), Math.fround(Math.atan2((0x100000000 >>> 0), -Number.MIN_VALUE)))))), ( + ((((Math.atan(((( + 0.000000000000001) | 0) >>> 0)) >>> 0) | 0) != ((x % (( - (( - x) | 0)) | 0)) | 0)) | 0)))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -0, -(2**53-2), Number.MIN_SAFE_INTEGER, 42, Math.PI, 0/0, 1.7976931348623157e308, 0x080000001, 1, -1/0, -0x080000001, -0x080000000, -0x07fffffff, 0x100000000, -0x0ffffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), -Number.MIN_VALUE, -(2**53+2), 0, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, 0x07fffffff, 2**53+2, 2**53, 2**53-2, 0x100000001]); ");
/*fuzzSeed-168297596*/count=1388; tryItOut("\"use strict\"; s0 += s0;");
/*fuzzSeed-168297596*/count=1389; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.sign(Math.max(( + ( + (Math.log(Math.fround(Math.pow(x, ( + x)))) ** Math.fround(Math.fround((Math.hypot((Math.fround((0/0 & Math.PI)) ? (y | 0) : x), (x >= Math.fround(( + Math.fround(Number.MAX_VALUE))))) ? Math.fround(-0x07fffffff) : y)))))), (Math.fround(Math.imul(( + (( + y) * ( + ((Math.fround(y) ** Math.fround(-0x080000000)) | 0)))), Math.fround(( ! Math.fround(((((( ~ (x | 0)) | 0) | 0) + (Math.hypot(-0, x) | 0)) | 0)))))) >= Math.fround(((x === Math.fround(Math.sinh(x))) > (Math.atanh(x) >>> 0)))))); }); testMathyFunction(mathy3, [0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 42, 1/0, 0.000000000000001, -0x100000000, -0x080000000, 0x100000000, -(2**53), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 2**53, 0x080000001, 2**53+2, 0, -Number.MAX_VALUE, -1/0, -0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -0x100000001, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, -(2**53+2), 0x0ffffffff, 1.7976931348623157e308, 0/0, 0x080000000, -0]); ");
/*fuzzSeed-168297596*/count=1390; tryItOut("m1.get(m2);a2.pop();");
/*fuzzSeed-168297596*/count=1391; tryItOut("mathy1 = (function(x, y) { return Math.pow((Math.max((Math.fround(mathy0(mathy0((Math.hypot(Math.asinh(x), ( + ( + ((x | 0) === (-0x080000000 | 0))))) | 0), x), ( - (y | 0)))) | 0), ( + ((Math.fround(-0x080000001) >>> Math.fround(x)) ? 0/0 : ((x >= ( + ( ~ (( + ((0x080000000 | 0) || x)) >>> 0)))) >>> 0)))) | 0), (Math.acosh((( + (( + mathy0((Math.max(y, (x ^ ( + Math.fround(-0x100000000)))) | 0), Math.fround(Math.pow(-Number.MIN_VALUE, x)))) ^ ( + Math.fround((Math.fround(( ! x)) << Math.fround((x >>> x))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [2**53, -0, 0x0ffffffff, -(2**53), -0x100000001, 0x100000001, 42, 1.7976931348623157e308, -0x080000001, -0x080000000, 1/0, -0x07fffffff, -(2**53+2), 0x07fffffff, 0.000000000000001, Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, -(2**53-2), 0x080000000, 2**53+2, -0x0ffffffff, 2**53-2, 0x080000001, 0x100000000]); ");
/*fuzzSeed-168297596*/count=1392; tryItOut("\"use strict\"; v2 = a2.length;");
/*fuzzSeed-168297596*/count=1393; tryItOut("{a0 = arguments.callee.caller.caller.arguments; }");
/*fuzzSeed-168297596*/count=1394; tryItOut("delete h1.getOwnPropertyDescriptor;");
/*fuzzSeed-168297596*/count=1395; tryItOut("{ void 0; verifyprebarriers(); }");
/*fuzzSeed-168297596*/count=1396; tryItOut("m2 + '';");
/*fuzzSeed-168297596*/count=1397; tryItOut("mathy4 = (function(x, y) { return ( + ((Math.fround(( ! y)) < Math.fround(( ! (Math.min((( ! (x | 0)) | 0), ( + y)) | 0)))) | 0)); }); testMathyFunction(mathy4, [0x080000000, 0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, -0x080000001, -0x07fffffff, 0, -(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, -0, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, 0.000000000000001, 2**53+2, 1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, 42, Math.PI, 0x080000001, -0x100000001, -(2**53+2), 0x100000001, -0x080000000, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1398; tryItOut("\"use strict\"; a0 = new Array;");
/*fuzzSeed-168297596*/count=1399; tryItOut("mathy0 = (function(x, y) { return  /x/g ; }); ");
/*fuzzSeed-168297596*/count=1400; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ ( ~ (((((x | 0) ? y : ((Math.min(0x0ffffffff, y) >>> 0) | 0)) + ( + y)) * Math.atan2(y, Math.expm1(Math.fround(Math.acosh((( + ( ! Math.fround(x))) | 0)))))) >>> 0))); }); testMathyFunction(mathy4, [1/0, -0x07fffffff, 2**53, Number.MAX_VALUE, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, 0x100000000, -(2**53-2), 0.000000000000001, 1.7976931348623157e308, 0x0ffffffff, 0x080000000, Number.MIN_VALUE, 42, Math.PI, -0x080000001, -0x100000001, -Number.MIN_VALUE, 2**53+2, -1/0, -0, 2**53-2, -(2**53+2), -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, 1, 0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1401; tryItOut("/*infloop*/L:for(let [{x, e: {x: x, a}, x, x: {x: {\u3056: NaN, x: [, {x}], \u3056: x, x}, eval: b}, c: b}, , [{e: arguments[\"callee\"], x: b, d: (delete c.y)((x.__defineGetter__(\"d\", x))), z, b: [, x, , ], y: set, NaN: [, y, x\u000c], b: w, window: ((NaN))}, [], , , {y: {}, w: \u000c{d: [], w: \u3056, x: x, x, a: {}}}, {\u3056: z, \u3056: [window, {x: [], x, e}, {x, x: {w: y, d: {z, c: {\u3056: [], eval: [, , ], eval: a}}, y: []}, x}, , ], x: [[{y: {x, y: [], \u3056}, d: x, c, x, b, this: x}], [, , NaN, {a: [, [], x, this[\"__count__\"], ], x, x, x: {b, window: [[x, , {}]]}, c}, , [, ], ], , , , , {e: {}, x: {w: {window: {z: a}, c: {w: [], d, x}, this.e, d: c, x: x}, x: {}}, x: [, ], x, eval: x}, ], this.zzz.zzz: eval, d: (d), x, x, x: [w, , {\u3056: e, c: x, NaN, getter: x, e, d\u0009: {a: [], NaN, window}}, {z: [], \u3056: [[{d: [, , ], \u000cNaN: [[], , []], b: [, ]}, [], {a: [[]], c: {w\u000c, x: [[]]}}, x], , [[], , , , ], of], [, , ], b: [\u000c[{a: x, x: {\u3056: {x: {}, c: d}, x}, z}, , , ]]}, d, [, [], [{x, x: x}, ], ], ], x: c}, {x, w: {x: {y: [, [, [x, [, {x: [], eval: e}]], , ]], window: {x: [, , {this.delete, x}]}, window: x}, \u3056, this, \u3056: x}, x, x: {}, window}, , , [{e: {d: {e, window: {x, a: [, , ], window: x, x: eval, x: [{c, eval, w: {b: [], c: w}}]}, x: [, x, , , ]}}, window: arguments.callee.caller.caller.arguments, c: {d, window: (arguments), z: [, a, b, , x, {{}: x, setter: w, eval, x: [c, [{}, ]]}], NaN: e, x, d: {eval, window, x: z, x: {x}}, z: x}, x, x: (x), eval: {w: {\u3056, NaN: [[[], ]], b, x}, x: length, x: [{}, x], \u3056: w}, d, x}, {x, window: [x], window, \u3056: [{x}, ], a: {c, setter: [, {x: e, x, eval: x, window: []}, [, , , , ], , , {x, d, x: a, x}], a, \u3056: {c: y, w: [, x], eval, b:  , x}, z: {x: window, x, [[]], y: {x: [{x, e}, , {}], c, z: [], this.\u3056, eval}}, y: {c: [eval, {c: [, {eval: c}]}, [{}, [, , ]], ], w, x: {c, x, e: [, , , arguments[\"apply\"]]}, w}, w: {\u3056: {d, this.__defineSetter__(\"d\", window): [, x, ], x, a: [], x}, a: arguments, \"\u03a0\", x: b, x: [, , ]}}, x}]], , [], , , , [{x, x, x, x, window, \u3056: x, e: [{x}, x, x, , x[new String(\"8\")], [, , x, x, , ], [], ]/*\n*/, b: x}, , , , [{c: [, ], x: [, \u3056, ], x: \u3056, eval, x: {x: [[z, , ], \u0009x, , y], eval: {y, d: x, b, \u3056}, eval: [x, , {x: NaN, c: {b: d, x, window\u000c: x, b}, x, eval: {a: {}}, b: []}, \u3056, , ], x: [, {\u3056, x: {x: [[a], x, {x: [], x: \u3056}], x: z, x}, NaN, eval}], x: x, \u3056, x: (4277) ^= yield eval(\"\\\"use strict\\\"; ([,,z1]);\", -0).__proto__}}, , [{x: {NaN: z, x: [], b: []}, x: {NaN, w: []}, w: window}, , x((4277)%=(4277))], , { }, ], , , [, , , , [, , \u3056], , {a, NaN, eval: {z: x, b: [, {x: a, [], x}, x, ({}), {w: a, z: {c: {}}, e: x, x: [{x: x, x, b}, x], x}], c: y}}, [eval, ], arguments]]] = new (new ((function (w, x, x, c, d, x, x, NaN, a, e =  \"\" , this.window, a, eval, z, window, y, x = arguments, x, eval, eval, x) { return x } ( \"\"  <<=  /x/g ,  '' )))())(); ((yield (e)).eval(\"(4277)\")); \u0009x(\"\\uC91D\")) print(-9 >= \"\\u8276\");");
/*fuzzSeed-168297596*/count=1402; tryItOut("/*vLoop*/for (ufazcl = 0; ufazcl < 14; ++ufazcl) { x = ufazcl; print(x); } ");
/*fuzzSeed-168297596*/count=1403; tryItOut("\"use strict\"; do {g2.v0 = true; } while(((window >>> b)) && 0);");
/*fuzzSeed-168297596*/count=1404; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-168297596*/count=1405; tryItOut("/*RXUB*/var r = /\\2/; var s = \"\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-168297596*/count=1406; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[function(){}, new Boolean(true), [(void 0)], [(void 0)], [], function(){}, new Boolean(true), [(void 0)], function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, [(void 0)], function(){}, new Boolean(true), function(){}, function(){}, new Boolean(true), function(){}, [], [(void 0)], [(void 0)], function(){}, new Boolean(true), [(void 0)], [], function(){}, [(void 0)], function(){}, new Boolean(true), new Boolean(true), [(void 0)], [], [], function(){}, new Boolean(true), function(){}, function(){}, [(void 0)], function(){}, new Boolean(true), [(void 0)], function(){}, [], new Boolean(true)]); ");
/*fuzzSeed-168297596*/count=1407; tryItOut("/* no regression tests found */function e(x, a) { return (void shapeOf(new (({/*toXFun*/toSource: function() { return /(?:(\\2))|\\1*?/i; } }))(([x]), {}))).toLocaleTimeString.prototype } e2.has(s0);");
/*fuzzSeed-168297596*/count=1408; tryItOut("\"use strict\"; testMathyFunction(mathy0, [(new Boolean(false)), true, (new Boolean(true)), 0, ({toString:function(){return '0';}}), undefined, ({valueOf:function(){return 0;}}), (function(){return 0;}), '0', [0], ({valueOf:function(){return '0';}}), '', '\\0', (new String('')), NaN, 0.1, (new Number(0)), objectEmulatingUndefined(), (new Number(-0)), false, -0, /0/, 1, '/0/', null, []]); ");
/*fuzzSeed-168297596*/count=1409; tryItOut("t1 = new Uint32Array(o2.o1.b1);");
/*fuzzSeed-168297596*/count=1410; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(t1, \"keys\", { configurable: false, enumerable: false, writable: (x % 2 == 0), value: (void version(170)) });");
/*fuzzSeed-168297596*/count=1411; tryItOut("\"use strict\"; /*MXX3*/g2.WeakSet = g0.WeakSet;");
/*fuzzSeed-168297596*/count=1412; tryItOut("mathy1 = (function(x, y) { return Math.imul((Math.cosh(((Math.fround((y >= y)) <= ( - Math.expm1(y))) | 0)) | 0), (Math.pow((((( + y) ? y : mathy0(x, ( + x))) >>> 0) << Math.log2(Math.imul((y + -0), y))), ( ~ ( ~ Math.pow(((x + (mathy0(y, y) | 0)) | 0), Math.max(Math.fround(mathy0((x >>> 0), Math.fround(0.000000000000001))), ( + Math.log1p(( + x)))))))) | 0)); }); testMathyFunction(mathy1, [1/0, 0x100000000, 1, 0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x07fffffff, -0, 2**53-2, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, 0/0, 0.000000000000001, Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, -0x080000001, -0x100000000, 0, 2**53, -(2**53), -0x07fffffff, -(2**53-2), -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=1413; tryItOut("for(var w in false) print( /x/ );");
/*fuzzSeed-168297596*/count=1414; tryItOut("\"use strict\"; \"\\u45DC\" >> y;function x(y)[] = {}m2.get(f0);");
/*fuzzSeed-168297596*/count=1415; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return ((((( + ( - Math.asin(0x080000001))) | Math.fround(Math.cos(Math.fround(( ! x))))) | 0) === (( + (( + mathy3(( - Number.MAX_SAFE_INTEGER), 0x100000000)) ? ( + (Math.acosh((Math.atan2(x, (Math.atan2((-0x100000001 >>> 0), (Math.hypot(y, Math.fround(y)) >>> 0)) >>> 0)) | 0)) | 0)) : (Math.imul(y, ( + mathy4(( + y), ( + (Math.asin((1.7976931348623157e308 | 0)) | 0))))) | 0))) | 0)) | 0); }); testMathyFunction(mathy5, [-0x07fffffff, 0x07fffffff, -(2**53+2), 0x080000000, 0x100000000, Math.PI, 0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, 0/0, -Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, -(2**53), -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, 0, -0x100000000, -Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, -0x100000001, 0.000000000000001, 2**53, -0, 42, Number.MIN_VALUE, -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -1/0]); ");
/*fuzzSeed-168297596*/count=1416; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ ( + (((mathy0((( - x) | 0), ( ~ -0x07fffffff)) & -(2**53+2)) | 0) * (( ! ( + (Math.max(((y !== Math.asinh(( + -(2**53)))) >>> 0), ((Math.asinh(x) | 0) >>> 0)) >>> 0))) >>> 0)))); }); testMathyFunction(mathy2, [-(2**53-2), 0x07fffffff, 42, -(2**53+2), -0x100000001, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, 0.000000000000001, 2**53+2, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 1, -(2**53), Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 0x080000001, 1/0, 0, 0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, -0, -1/0, -0x100000000, Math.PI, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-168297596*/count=1417; tryItOut("/*bLoop*/for (xgkxik = 0; xgkxik < 9; ++xgkxik) { if (xgkxik % 46 == 40) { /* no regression tests found */ } else { v2 = a2.some(); }  } ");
/*fuzzSeed-168297596*/count=1418; tryItOut("\"use strict\"; g0 = this;");
/*fuzzSeed-168297596*/count=1419; tryItOut("g2.o2.g1.e0.add(o1.g0.b2);");
/*fuzzSeed-168297596*/count=1420; tryItOut("\"use strict\"; /*RXUB*/var r = o1.r0; var s = s0; print(r.test(s)); ");
/*fuzzSeed-168297596*/count=1421; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot((Math.imul(( + Math.fround(( - (mathy0((Math.ceil(-Number.MAX_SAFE_INTEGER) ? ( + ( + ( - y))) : mathy0(( + 42), Number.MAX_VALUE)), (0x080000000 >>> 0)) >>> 0)))), Math.fround(Math.log(( + Math.cos((x | 0)))))) >>> 0), (mathy0((Math.atanh((( + Math.imul(x, 1)) | 0)) >>> 0), ((-0x080000001 ? (( - y) >>> 0) : ( + Math.pow(Math.atan((mathy1((x >>> 0), x) >>> 0)), ( + y)))) >>> 0)) > ((Math.asin(( + (( + Math.fround((y !== Math.cosh(x)))) !== y))) >>> 0) >>> 0))); }); testMathyFunction(mathy2, [0, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, -0x100000001, Math.PI, -0x0ffffffff, 0x07fffffff, -(2**53-2), 0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1, -0x080000000, 2**53-2, 0x100000001, 2**53, -0x07fffffff, 2**53+2, -0x080000001, -Number.MAX_VALUE, 0x100000000, -(2**53+2), 1/0, 0/0, 1.7976931348623157e308, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-168297596*/count=1422; tryItOut("\"use strict\"; h1 + t0;");
/*fuzzSeed-168297596*/count=1423; tryItOut("\"use strict\"; \"use asm\"; var uaxahu = new ArrayBuffer(4); var uaxahu_0 = new Int8Array(uaxahu); print(uaxahu);");
/*fuzzSeed-168297596*/count=1424; tryItOut("v1 = (x % 2 != 0);");
/*fuzzSeed-168297596*/count=1425; tryItOut("h0.defineProperty = (function() { try { t1 + a2; } catch(e0) { } try { this.g0.g1.offThreadCompileScript(\"f1 = Proxy.createFunction(h2, f0, f2);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 18 != 3), noScriptRval: true, sourceIsLazy: true, catchTermination: false })); } catch(e1) { } try { v1 = a1.length; } catch(e2) { } v0 = (o0.i1 instanceof p0); return b1; });");
/*fuzzSeed-168297596*/count=1426; tryItOut("m1 + i0;");
/*fuzzSeed-168297596*/count=1427; tryItOut("g2.a2.splice(NaN, 16);Array.prototype.forEach.call(a2, (function() { try { a2 = a2.slice(NaN, NaN, m2, p0, p1); } catch(e0) { } for (var p in g1.g1) { print(\"\\u2A88\"); } return a0; }), s1);function e(x, w) { \"use strict\"; return this.__defineGetter__(\"b\", Object.setPrototypeOf) } o1.g2.t1 = new Uint8Array(b0);");
/*fuzzSeed-168297596*/count=1428; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot((Math.fround(Math.fround((Math.fround(( ! (( + Math.clz32(y)) ? Math.fround((Math.fround(y) ** Math.fround(y))) : Math.fround(Math.log2(x))))) ? y : Math.fround((Math.hypot(x, (( - x) >>> 0)) == (Math.max((x | 0), (x | 0)) | 0)))))) > (Math.fround(( ! Math.fround(Math.cos(y)))) | 0)), ( ~ Math.tan((mathy0(Math.fround(Math.ceil(y)), x) | 0)))); }); testMathyFunction(mathy2, [0.1, '0', '/0/', true, false, (new String('')), (function(){return 0;}), 0, (new Number(-0)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), -0, '', 1, [0], null, (new Boolean(false)), ({valueOf:function(){return 0;}}), [], ({toString:function(){return '0';}}), undefined, (new Number(0)), (new Boolean(true)), NaN, '\\0', /0/]); ");
/*fuzzSeed-168297596*/count=1429; tryItOut("mathy3 = (function(x, y) { return Math.fround((Math.fround(mathy0(Math.fround((Math.fround(( ! y)) ? (( + Math.exp((y | 0))) ? y : Math.hypot((-(2**53-2) >>> 0), x)) : ( + Math.imul(( + Math.cosh(Math.asin(( - x)))), Math.log10((y | 0)))))), Math.log10((( ~ ( + (y && ( + (( + y) & (-0x080000001 === 0x080000000)))))) | 0)))) && Math.fround(( ~ (( + ( + ( ~ ( + ( + Math.atan2(( + 0x07fffffff), ( + x))))))) === Math.cosh(y)))))); }); ");
/*fuzzSeed-168297596*/count=1430; tryItOut("print(y = x);");
/*fuzzSeed-168297596*/count=1431; tryItOut("/*bLoop*/for (let gyftfd = 0; gyftfd < 58; ++gyftfd) { if (gyftfd % 92 == 38) { h1.getOwnPropertyDescriptor = (function() { try { s0 = a1.join(s1, o0.o1); } catch(e0) { } try { Object.seal(o2); } catch(e1) { } try { v0 = t1.length; } catch(e2) { } v0 = t0.length; return t0; }); } else { /*ODP-2*/Object.defineProperty(e2, \"callee\", { configurable: false, enumerable: (x % 5 != 4), get: (function() { a0[16]; return o0; }), set: (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = a4 % a2; var r1 = a2 | a5; var r2 = 1 / 4; var r3 = 4 * 1; var r4 = 5 % a12; var r5 = a8 ^ a11; var r6 = 4 | 1; var r7 = x / 8; var r8 = r7 ^ a11; var r9 = r0 % 3; var r10 = a4 - r0; var r11 = a12 - a3; var r12 = r7 | 7; var r13 = 9 - a11; var r14 = r12 + r12; var r15 = r7 * a8; return a4; }) }); }  } ");
/*fuzzSeed-168297596*/count=1432; tryItOut("print(x);\nprint(x);\n");
/*fuzzSeed-168297596*/count=1433; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -524289.0;\n    var i3 = 0;\n    var d4 = -7.737125245533627e+25;\n    {\n      i3 = (0xfac7c5aa);\n    }\n    d4 = (+((-33554433.0)));\n    (Int8ArrayView[2]) = ((Int16ArrayView[1]));\n    i3 = ((0xde62738d) != (((Uint32ArrayView[((x |= \u3056)+(0xf341f98f)) >> 2]))>>>((i0))));\n    return ((0xfffff*((((0x4cfbf62c)) << (-((0xfa7a75f8)))) == (imul((i0), (i1))|0))))|0;\n  }\n  return f; })(this, {ff: x != 20}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, -(2**53+2), 0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, 2**53-2, -0x080000001, -(2**53-2), 42, 2**53, 0.000000000000001, 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, -0, Math.PI, 0x0ffffffff, 0x080000001, Number.MIN_VALUE, -0x100000001, 1, Number.MAX_SAFE_INTEGER, 0/0, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), 0x07fffffff, 0x080000000]); ");
/*fuzzSeed-168297596*/count=1434; tryItOut("mathy4 = (function(x, y) { return (Math.imul(((Math.hypot(((((x | 0) !== ((( + x) ** Math.fround(( ~ Math.fround(x)))) | 0)) >>> 0) >>> 0), (((0x080000000 >>> (( + -0) ** Math.atan2((Math.log1p(Math.fround(x)) | 0), (x | 0)))) | 0) >>> 0)) >>> 0) >>> 0), Math.trunc(Math.fround(Math.atan(Math.fround(( - Math.fround(y))))))) >>> 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, -0x0ffffffff, -0x07fffffff, -0x080000000, -0, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, 0, 0x080000001, 1/0, -(2**53), Number.MIN_VALUE, 0.000000000000001, -(2**53+2), -0x100000000, -(2**53-2), 2**53, -Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, 2**53+2, 2**53-2, 42, -0x080000001, 0x100000001, Math.PI, 0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1435; tryItOut("\"use strict\"; /*vLoop*/for (let gihgty = 0; gihgty < 7; ++gihgty) { const w = gihgty; ( \"\" ); } ");
/*fuzzSeed-168297596*/count=1436; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.pow((Math.log2((Math.atan(-Number.MAX_SAFE_INTEGER) >>> 0)) ? (Math.hypot((( + Math.expm1(( + ( ~ (( - (y >>> 0)) >>> 0))))) >>> 0), (y >>> 0)) >>> 0) : Math.fround(Math.cosh(Math.fround(Math.fround(Math.atan2(x, Math.sinh(x))))))), Math.fround(Math.acos(( ~ Math.abs((-Number.MAX_VALUE !== y)))))) >>> 0); }); testMathyFunction(mathy2, ['\\0', [0], ({valueOf:function(){return '0';}}), 0.1, null, (new Number(-0)), (function(){return 0;}), (new Boolean(true)), objectEmulatingUndefined(), /0/, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), '/0/', [], false, (new Number(0)), 1, undefined, NaN, 0, '', -0, true, (new String('')), '0', (new Boolean(false))]); ");
/*fuzzSeed-168297596*/count=1437; tryItOut("this;");
/*fuzzSeed-168297596*/count=1438; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return mathy0((Math.exp(( + Math.sin(( + (( + (x | 0)) | 0))))) >>> 0), Math.fround(Math.expm1(( - ( + ((Math.atan2(y, Math.acosh(x)) ** Math.fround((( + y) != (Math.sin((-0x080000001 | 0)) | 0)))) >>> 0)))))); }); testMathyFunction(mathy5, /*MARR*/[(void 0), (void 0), new Number(1.5), null, null, 9, (void 0), new Number(1.5), null, 9, new Number(1.5), 9, 9, null, 9, (void 0), (void 0), null, (void 0), 9, new Number(1.5), 9, (void 0), null, new Number(1.5), new Number(1.5), (void 0), new Number(1.5), (void 0), null, new Number(1.5), (void 0), 9, 9, 9, (void 0), 9, (void 0), 9, 9, 9, new Number(1.5), (void 0), (void 0), 9, 9, (void 0), new Number(1.5), null, new Number(1.5), null, null, new Number(1.5), (void 0), null, 9, null, null, 9, new Number(1.5), (void 0), null, null, 9, new Number(1.5), 9, null, (void 0), null, 9, null, 9, null, 9, new Number(1.5), new Number(1.5), null, null, 9, null, (void 0), null, null, null, new Number(1.5), null, new Number(1.5), 9, 9, null, 9, null, (void 0), null, null, new Number(1.5), 9, new Number(1.5), 9, (void 0), new Number(1.5), 9, (void 0), null, null, new Number(1.5), null, (void 0), 9, (void 0), (void 0), 9]); ");
/*fuzzSeed-168297596*/count=1439; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1440; tryItOut("f1 + v2;");
/*fuzzSeed-168297596*/count=1441; tryItOut("Array.prototype.reverse.call(o0.a2);");
/*fuzzSeed-168297596*/count=1442; tryItOut("r0 = /(?=[^])+?/gi;");
/*fuzzSeed-168297596*/count=1443; tryItOut("\"use strict\"; o2.a1.unshift(m0, 28.__defineSetter__(\"x\", eval = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: (new Function(\"a0.unshift(t1);\")), getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: JSON.parse, delete: function() { return false; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: neuter, enumerate: this, keys: function() { return []; }, }; })(x), x)), f2, t0);");
/*fuzzSeed-168297596*/count=1444; tryItOut("g2.h2 = {};");
/*fuzzSeed-168297596*/count=1445; tryItOut("testMathyFunction(mathy3, [0, 42, 0x080000000, 0x0ffffffff, 0x100000001, -0x100000001, -(2**53), -0x080000000, -(2**53-2), 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -0, Math.PI, -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, 1/0, 1, -0x100000000, Number.MIN_VALUE, 2**53, 0x100000000, Number.MAX_VALUE, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1446; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.max((Math.min(Math.min(Math.log1p(y), ( + Math.hypot(Math.min(y, ( + y)), ((Math.pow(( + x), (y | 0)) | 0) ? y : y)))), Math.fround(( ~ (Math.ceil(( + Math.imul(x, y))) >>> 0)))) | 0), (( + Math.exp(Math.fround(Math.sqrt(( + (Math.atan2(( ~ (x | 0)), x) >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy3, [2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, 42, Math.PI, 0x100000000, 0x100000001, -0x100000001, 2**53, -(2**53+2), -1/0, 0x080000001, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, 2**53-2, 0x080000000, 0/0, 1.7976931348623157e308, 0.000000000000001, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, -0, -0x080000001]); ");
/*fuzzSeed-168297596*/count=1447; tryItOut("testMathyFunction(mathy5, [-0, Number.MIN_VALUE, 0x100000001, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 1.7976931348623157e308, -0x080000000, Number.MAX_VALUE, -(2**53), -0x100000000, -Number.MAX_VALUE, 0x0ffffffff, 2**53-2, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, 42, 2**53+2, 0x100000000, 2**53, -Number.MIN_VALUE, 0x080000000, 0x07fffffff, -0x0ffffffff, 1/0, -0x100000001, -(2**53-2), -0x080000001]); ");
/*fuzzSeed-168297596*/count=1448; tryItOut("mathy5 = (function(x, y) { return Math.min((Math.trunc(Math.pow(Math.fround(x), x)) >>> 0), ((Math.fround(Math.min(((Math.max((((y | 0) == x) | 0), x) | 0) % x), ( ~ ( + y)))) % (( ! Math.fround(((y ? ((( - -(2**53+2)) >>> 0) >>> 0) : (y | 0)) | 0))) | 0)) >>> 0)); }); testMathyFunction(mathy5, [(new Boolean(false)), 0.1, false, undefined, '0', /0/, null, '\\0', (new Number(0)), (new String('')), (new Boolean(true)), 1, '', ({valueOf:function(){return 0;}}), NaN, objectEmulatingUndefined(), true, (new Number(-0)), '/0/', -0, [0], 0, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (function(){return 0;}), []]); ");
/*fuzzSeed-168297596*/count=1449; tryItOut("Array.prototype.forEach.apply(a0, [g0.f0]);");
/*fuzzSeed-168297596*/count=1450; tryItOut("/*RXUB*/var r = /(?=\\1(?=\\v|\\B|\\b?)[^]|[^]{3,6}+)/gi; var s = \"\\n\\n\"; print(s.replace(r, encodeURI)); ");
/*fuzzSeed-168297596*/count=1451; tryItOut("mathy4 = (function(x, y) { return ( + Math.pow(( + (( - (mathy0((Math.pow(x, x) | 0), Math.fround(( ! mathy3(x, y)))) >>> 0)) >>> 0)), Math.pow((((( + (( + Math.max(x, y)) ** x)) >> x) >>> x) | 0), Math.fround((Math.fround(Math.clz32(Math.fround(( - x)))) - Math.fround(Math.log(-Number.MAX_SAFE_INTEGER))))))); }); testMathyFunction(mathy4, [2**53, -(2**53), 2**53-2, 0x080000001, 1/0, -0x07fffffff, 0x080000000, -0x080000000, 0x100000000, 0/0, -0x0ffffffff, -(2**53+2), 1, -0x100000000, -0x080000001, -1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, Math.PI, 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 2**53+2, -0, Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1452; tryItOut("\"use strict\"; /*infloop*/for(var arguments.callee.arguments in ((String.prototype.italics)((uneval((makeFinalizeObserver('tenured'))))))){print((function ([y]) { })());print([[1]]); }");
/*fuzzSeed-168297596*/count=1453; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(( ~ ((((Math.exp((( - Math.fround(( ! (x == y)))) | 0)) | 0) | 0) <= (Math.hypot((( + y) | 0), y) | 0)) | 0))); }); testMathyFunction(mathy0, [0x080000000, 2**53-2, 2**53, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0, -0x100000001, Math.PI, 0x100000000, 0x0ffffffff, Number.MAX_VALUE, -1/0, -0x080000001, -(2**53), -Number.MIN_VALUE, 1, 1/0, -0, 2**53+2, -0x07fffffff, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 0x080000001, 42, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), 0/0, -0x100000000]); ");
/*fuzzSeed-168297596*/count=1454; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-168297596*/count=1455; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.hypot(mathy0((Math.max(((y ? (Math.imul(0/0, Math.exp(x)) >>> ( ~ 0x100000001)) : Math.fround(Math.imul(Math.fround(( + (-0x080000000 , x))), Math.fround(-0x100000000)))) >>> 0), ( + ( + (42 >>> 0)))) >>> 0), (( + Math.hypot(( + ( - Math.fround(42))), Math.min(0x080000000, x))) > y)), Math.min(Math.hypot(Math.hypot((Math.cosh((y | 0)) | 0), x), ((Math.imul((x & x), mathy0((1 ^ ((y !== (x | 0)) | 0)), eval)) | 0) >>> 0)), (( ~ Math.atan2((Math.sign((Number.MIN_VALUE >>> 0)) | 0), Math.ceil(x))) | 0))); }); testMathyFunction(mathy1, [0x100000000, 1/0, Math.PI, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -1/0, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, 0x080000001, 0x080000000, -0x07fffffff, -0x100000000, 0x07fffffff, -0x080000001, Number.MAX_VALUE, -(2**53-2), 42, 0x100000001, 1.7976931348623157e308, -(2**53), -(2**53+2), 0, 2**53+2, 1, -0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-168297596*/count=1456; tryItOut("\"use strict\"; m1 + '';");
/*fuzzSeed-168297596*/count=1457; tryItOut("(void (function ([y]) { })());");
/*fuzzSeed-168297596*/count=1458; tryItOut("arguments;");
/*fuzzSeed-168297596*/count=1459; tryItOut("/*RXUB*/var r = /^|((?:\\d)+|^){2,274877906946}/m; var s = \"\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-168297596*/count=1460; tryItOut("\"use strict\"; for (var p in g0.g1.a0) { try { e1.delete(t0); } catch(e0) { } this.h0 = {}; }");
/*fuzzSeed-168297596*/count=1461; tryItOut("e0 + '';");
/*fuzzSeed-168297596*/count=1462; tryItOut("testMathyFunction(mathy2, [0x080000000, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, 0/0, -0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, 1.7976931348623157e308, 42, 1/0, -1/0, Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, Number.MAX_VALUE, -(2**53+2), Math.PI, Number.MIN_VALUE, 0x0ffffffff, 2**53+2, -0x07fffffff, -0x080000000, -0x0ffffffff, 2**53, 2**53-2, -(2**53), -(2**53-2), 0.000000000000001, 0]); ");
/*fuzzSeed-168297596*/count=1463; tryItOut("mathy1 = (function(x, y) { return ( ~ (( + Math.round(( + Math.fround(mathy0((y % (x ** -0x100000000)), ( ~ Math.log(x))))))) ? ( + Math.fround(( + (Math.atan2(((((x | 0) != (( ! x) | 0)) | 0) >>> 0), (Math.max(( + Math.sqrt(( + ( + mathy0(( + -0x07fffffff), x))))), (Math.pow(-0x07fffffff, (-Number.MIN_SAFE_INTEGER | 0)) | 0)) >>> 0)) >>> 0)))) : Math.imul(( + (((Math.tan((-Number.MAX_VALUE === ( + -0x07fffffff))) >>> 0) / x) ? (( ! 2**53) >>> 0) : Math.clz32(((x ** Math.log(y)) | 0)))), ( + x)))); }); ");
/*fuzzSeed-168297596*/count=1464; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1465; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.cos((Math.log2(Math.cbrt((y ? ( + Math.pow(2**53-2, x)) : ( + x)))) >>> 0)) && (Math.log(( + ( - y))) ? ( - (Math.hypot((-Number.MIN_VALUE >>> 0), (y | 0)) >>> 0)) : Math.pow(( + Math.imul(Math.fround(0x080000000), ( + (Math.asinh(((-(2**53) >= 0/0) | 0)) | 0)))), y))) && Math.fround(mathy1((Math.hypot((y >>> 0), (Math.log(x) >>> 0)) >>> 0), ( + ( - Math.max(2**53-2, (2**53-2 <= y))))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, 0x100000001, 0/0, -(2**53-2), 0x0ffffffff, 1/0, Math.PI, Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, -1/0, -(2**53), -0, 1, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, -(2**53+2), -0x07fffffff, 0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, 42, -0x080000001, 0, 0x100000000, 2**53, -Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-168297596*/count=1466; tryItOut("this.x = window;((4277));");
/*fuzzSeed-168297596*/count=1467; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.round((((( ! (Math.imul((((y | 0) ? ( ~ y) : (x | 0)) | 0), Math.fround(x)) | 0)) | 0) ? mathy1(((x / x) !== ( + Math.log10(( + 0.000000000000001)))), Math.fround(-(2**53-2))) : Math.fround(Math.exp(Math.fround(Math.max(Math.clz32(( + (0x100000001 != ( + 42)))), -1/0))))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), x, true, new String('q'), x, arguments, x, Infinity, x, Infinity, new String('q'), new String('q'), true, Infinity, new String('q'), true, arguments, Infinity, Infinity, x, x, true, Infinity, arguments, true, Infinity, x, Infinity, x, true, arguments, x, arguments, x, true, true, new String('q'), x, new String('q'), arguments, Infinity, arguments, arguments, new String('q'), Infinity, true, Infinity, arguments, x, Infinity, true, x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q')]); ");
/*fuzzSeed-168297596*/count=1468; tryItOut("\"use strict\"; /*infloop*/M: for (let b of (String.prototype.blink(((4277).unwatch(\"entries\")), eval = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })([,,z1]), (4277))))) i1.next();");
/*fuzzSeed-168297596*/count=1469; tryItOut("v1 = g0.runOffThreadScript();");
/*fuzzSeed-168297596*/count=1470; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ( + ( + ((( ~ ( + y)) ? (( - Math.fround((( + -Number.MAX_SAFE_INTEGER) == x))) >>> 0) : mathy2(( ! y), ( + Math.expm1(Math.fround(( + x)))))) >>> 0))); }); testMathyFunction(mathy4, [0/0, -(2**53+2), -0x100000000, 42, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, 0, 2**53+2, 1, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, 2**53-2, -0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, 1/0, -Number.MIN_VALUE, 0x100000001, 2**53, -(2**53-2), -0x0ffffffff, 0.000000000000001, 0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, -0]); ");
/*fuzzSeed-168297596*/count=1471; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.sign(Math.fround(Math.asinh(Math.fround((x ^ ( - Math.asinh(x))))))); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  'A' , new Boolean(true), new Boolean(true),  /x/ , new Boolean(true),  'A' ,  /x/ ,  /x/ , new Boolean(true), new String(''), objectEmulatingUndefined(), new String(''), new Boolean(true), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), new String(''),  /x/ , new String(''), new Boolean(true),  /x/ ,  'A' ,  'A' , new String(''),  'A' ,  /x/ ,  'A' , new Boolean(true), objectEmulatingUndefined(),  /x/ , new String(''), objectEmulatingUndefined(),  'A' , new Boolean(true),  'A' ,  'A' ,  'A' , new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Boolean(true),  /x/ ,  /x/ , new String(''), new Boolean(true),  'A' , new String(''), objectEmulatingUndefined(),  'A' ,  /x/ , new String(''), new Boolean(true),  'A' , new Boolean(true), objectEmulatingUndefined(),  'A' ,  'A' ,  'A' , new String(''),  /x/ , objectEmulatingUndefined(), new Boolean(true), new String(''), new Boolean(true), new Boolean(true), new Boolean(true), new String(''), new String(''),  'A' ,  /x/ , new Boolean(true), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  'A' ,  'A' , new Boolean(true),  /x/ , objectEmulatingUndefined(), new String(''), new Boolean(true), new Boolean(true),  /x/ ,  /x/ , new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''),  'A' ,  'A' ,  'A' , new String(''),  'A' ,  /x/ ]); ");
/*fuzzSeed-168297596*/count=1472; tryItOut("\"use strict\"; \"use asm\"; /*oLoop*/for (let ndcpxa = 0; ndcpxa < 152; ++ndcpxa) { o2 = {}; } ");
/*fuzzSeed-168297596*/count=1473; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, 0x080000001, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, 0x100000001, -0x100000000, 42, -1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000001, 0.000000000000001, Math.PI, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, 0x07fffffff, 0, -(2**53), -0, 2**53+2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 0/0, 1, 1.7976931348623157e308]); ");
/*fuzzSeed-168297596*/count=1474; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.acos(Math.fround(( + Math.max(( + (( + (Math.min((y >>> 0), Math.fround(y)) >>> 0)) * Math.fround(Math.pow(Math.fround(y), Math.fround(y))))), ( + (( - x) >>> 0))))))); }); testMathyFunction(mathy1, [-(2**53+2), -0x080000000, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, -0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, 0, -0x100000001, 0.000000000000001, -0x07fffffff, -0, 1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE, -1/0, 0/0, 42, -Number.MAX_VALUE, Math.PI, 1, 2**53-2, 1.7976931348623157e308, 0x0ffffffff]); ");
/*fuzzSeed-168297596*/count=1475; tryItOut("p0.toSource = (function mcc_() { var myxdmt = 0; return function() { ++myxdmt; if (/*ICCD*/myxdmt % 10 == 1) { dumpln('hit!'); try { g1.t1.set(a1, ({valueOf: function() { /*MXX3*/g0.Number.prototype.toString = g2.Number.prototype.toString;return 4; }})); } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"\"; print(s.replace(r, Function)); print(r.lastIndex);  } catch(e1) { } try { m0 = new WeakMap; } catch(e2) { } /*RXUB*/var r = o2.r0; var s = s2; print(s.search(r));  } else { dumpln('miss!'); this.g0.valueOf = (function() { a0.push(o2); return v0; }); } };})();");
/*fuzzSeed-168297596*/count=1476; tryItOut("with({}) for(let a in []);throw b;");
/*fuzzSeed-168297596*/count=1477; tryItOut("\"use asm\"; m0 = new WeakMap;\n/*infloop*/do Array.prototype.push.apply(a2, [g1.g2, g2.g2.s2, b2,  /x/ , e0, b2]); while(x);\n");
/*fuzzSeed-168297596*/count=1478; tryItOut("testMathyFunction(mathy4, [1, '\\0', '', ({toString:function(){return '0';}}), '0', true, (function(){return 0;}), NaN, '/0/', objectEmulatingUndefined(), [0], -0, (new String('')), (new Number(-0)), 0, (new Boolean(false)), (new Number(0)), ({valueOf:function(){return 0;}}), undefined, [], 0.1, false, (new Boolean(true)), ({valueOf:function(){return '0';}}), /0/, null]); ");
/*fuzzSeed-168297596*/count=1479; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.log2(Math.cbrt((0x07fffffff | 0)))) * (( ! Math.sqrt(( + Math.fround(-0x080000000)))) | 0)) | 0) ** (Math.log1p(Math.atan2(( - y), Math.asin(y))) ? (( + ((Math.log1p(Math.fround(Math.fround(Math.min(2**53, mathy3(x, y))))) | 0) / (mathy2(-Number.MIN_VALUE, ( ~ (x >>> 0))) | 0))) ** Math.cos(Math.fround(Math.atan2(y, ( + (( + y) < ( + x))))))) : ((Math.sinh(((Math.fround(((x | 0) || (Math.fround(x) * x))) + Math.fround(y)) >>> 0)) < 1) | 0))); }); testMathyFunction(mathy4, [-0x07fffffff, 0, 2**53+2, 0.000000000000001, -0x080000001, -0, -(2**53-2), -0x100000001, -(2**53), 0x100000001, 2**53-2, -0x0ffffffff, 0x080000001, 0/0, Number.MAX_VALUE, 1, 42, Number.MAX_SAFE_INTEGER, -1/0, 1/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, -0x080000000, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -0x100000000, 0x080000000]); ");
/*fuzzSeed-168297596*/count=1480; tryItOut("s0 += s2;");
/*fuzzSeed-168297596*/count=1481; tryItOut("var b = ({ set $&(...x) { yield x = Proxy.createFunction(({/*TOODEEP*/})(8), Array.prototype.keys) } , NEGATIVE_INFINITY: ((function fibonacci(ztimuu) { ; if (ztimuu <= 1) { s1 += s2;; return 1; } ; return fibonacci(ztimuu - 1) + fibonacci(ztimuu - 2);  })(1)) }), xgzhje;{\"\\u9DEE\";print(x); }");
/*fuzzSeed-168297596*/count=1482; tryItOut("\"use strict\"; Array.prototype.reverse.call(o0.a1, o2);function x(\u3056, y) {  /x/ ; } (this);");
/*fuzzSeed-168297596*/count=1483; tryItOut("/*oLoop*/for (bjidfa = 0; bjidfa < 50 && (0x0ffffffff); undefined, ++bjidfa) { o1 = new Object; } ");
/*fuzzSeed-168297596*/count=1484; tryItOut("Array.prototype.forEach.apply(a2, [(function() { try { a0[Math.hypot(this.eval(\"\\\"use strict\\\"; \\\"use asm\\\"; m0 = new Map;\"), x)] = (/(?:$).\u121f|${0,3}{1}\\1{4,33554435}\u893b[^](?:$*|(\\D)(?:[^\\S]{0}))\\B{0,1}/gm)++; } catch(e0) { } e2 + ''; return v0; }), b0, (eval = \n(eval(\"v1 = Object.prototype.isPrototypeOf.call(t2, g0.t2);\", window)))]);");
/*fuzzSeed-168297596*/count=1485; tryItOut("a1.unshift(e2, s2, g0, o2.p1, o2, e1);");
/*fuzzSeed-168297596*/count=1486; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ Math.asin(( + (Math.fround(Math.log10(-Number.MIN_SAFE_INTEGER)) >> Math.atan2(( + Math.asin(( + x))), Math.pow(( + (1 % Math.hypot((x | 0), x))), mathy1(( + Math.fround((Math.fround(x) << (y >>> 0)))), (y | 0)))))))); }); testMathyFunction(mathy3, [0x080000000, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, Math.PI, 42, 1/0, -(2**53), -0x080000001, -(2**53-2), 0, -0, -Number.MIN_VALUE, 0x100000000, 0x100000001, 2**53-2, -0x100000000, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 1.7976931348623157e308, 0.000000000000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, 0x080000001, -0x100000001, -(2**53+2), 2**53+2, 0/0]); ");
/*fuzzSeed-168297596*/count=1487; tryItOut("\"use strict\"; a1 = [];");
/*fuzzSeed-168297596*/count=1488; tryItOut("m1.set(this.f0, b0);");
/*fuzzSeed-168297596*/count=1489; tryItOut("f0.__iterator__ = String.prototype.padStart.bind(this.h2);");
/*fuzzSeed-168297596*/count=1490; tryItOut("switch(-19) { case 3: e1.has(o0.t1);break;  }");
/*fuzzSeed-168297596*/count=1491; tryItOut("/*infloop*/for(var {x: [x]} = this.__defineGetter__(\"NaN\", function  ({}).__proto__ (x, c) { yield (makeFinalizeObserver('tenured')) } ); (4277); new RegExp(\"(\\\\cC){1}{2}(?=(?:\\\\2)\\\\1)\", \"gyi\")) {s1.toString = this.f2; }");
/*fuzzSeed-168297596*/count=1492; tryItOut("print(x);");
/*fuzzSeed-168297596*/count=1493; tryItOut("mathy4 = (function(x, y) { return ( + ( ~ ( + (Math.min((( + (((( + (( + (( + x) ? ( + x) : ( + -Number.MIN_SAFE_INTEGER))) >>> 0)) >>> 0) | 0) ? -0x100000001 : mathy1(y, (-Number.MIN_SAFE_INTEGER | 0)))) | 0), y) + mathy3(Math.asin(x), mathy3((x >>> 0), (Math.imul((x | 0), -Number.MIN_VALUE) | 0))))))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -Number.MAX_VALUE, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, 1, 1/0, Math.PI, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0, Number.MIN_VALUE, -0x080000001, 2**53+2, -(2**53), 42, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, 0/0, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, 0x100000000, -0x080000000, -0x0ffffffff, 0x07fffffff, 0, 1.7976931348623157e308, -Number.MIN_VALUE, 0.000000000000001, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1494; tryItOut("\"use strict\"; \"use asm\"; a2.pop(i1);");
/*fuzzSeed-168297596*/count=1495; tryItOut("mathy1 = (function(x, y) { return (( ! ((Math.hypot((((Math.fround(y) || ( ! (y | 0))) | 0) | 0), Math.max((( ~ (x | 0)) | 0), x)) | (( ~ ((((Math.fround(Math.tanh(Math.fround(0))) | 0) <= ((( + Math.acosh(x)) / ( + y)) | 0)) | 0) >>> 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 2**53, Number.MIN_VALUE, 1/0, 2**53-2, -(2**53+2), 0/0, Number.MIN_SAFE_INTEGER, -0, -(2**53), 1.7976931348623157e308, 0, -0x080000001, 0x07fffffff, -0x100000001, 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, 0x100000001, -0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1, 0x080000000, -0x100000000, 0x080000001, 42, -0x080000000, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1496; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return Math.pow((( ~ (Math.asin((mathy2((Math.fround(Math.exp(y)) | 0), (x | 0)) | 0)) | 0)) & Math.fround(( - Math.fround(Math.fround(Math.acos(Math.fround(( - Math.fround((x + -0)))))))))), (((y % y) <= Math.atan2(Math.imul((x >>> 0), y), (y < ( + Math.abs((y ? x : y)))))) | 0)); }); ");
/*fuzzSeed-168297596*/count=1497; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + ((Math.hypot((( + Math.min(mathy0((Math.imul((Math.round((Math.acos((y >>> 0)) >>> 0)) >>> 0), (y >>> 0)) >>> 0), x), Math.atan2(y, (((y | 0) | -0x080000001) % y)))) | 0), ( + (( + Math.imul(( + Math.atan2(x, (y | 0))), (Math.fround(1) && ( + Math.expm1(( + y)))))) ? ( + (( ~ Math.fround(x)) >>> 0)) : ( + -0x0ffffffff)))) | 0) >>> 0)); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53), -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 2**53+2, -0x100000001, -0x080000001, -0x100000000, 0x0ffffffff, -(2**53-2), -1/0, 1.7976931348623157e308, 2**53-2, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, 0x100000000, -0, 0, 0.000000000000001, 1/0, 0x07fffffff, -0x080000000, Number.MIN_VALUE, 42, 0/0, 1]); ");
/*fuzzSeed-168297596*/count=1498; tryItOut("\"use strict\"; v1[\"callee\"] = e0;");
/*fuzzSeed-168297596*/count=1499; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ ((Math.max(x, mathy0(Math.sin(x), (Math.tan((x >>> 0)) >>> 0))) < Math.sqrt(Math.fround(( ! (x < Math.log2((y >>> 0))))))) | 0)); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -1/0, 0/0, 0x0ffffffff, 0x080000000, 0.000000000000001, 2**53+2, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, 1, -Number.MIN_VALUE, -0x080000001, -0x07fffffff, -0, -0x100000001, -0x100000000, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53, -(2**53), 0x07fffffff, 1/0, 42, -0x080000000, 0, 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001]); ");
/*fuzzSeed-168297596*/count=1500; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(t1, this.h2);");
/*fuzzSeed-168297596*/count=1501; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.imul(Math.fround(mathy0((Math.expm1((((y ** ( ~ 0x080000001)) | (Math.asin((-0x080000000 >>> 0)) >>> 0)) >>> 0)) >>> 0), (( ! Math.fround(x)) >>> 0))), Math.fround(Math.imul((( + Math.round((x !== x))) | 0), (mathy0((y >>> 0), ((x < Math.imul(x, ( + ((Math.fround(Math.hypot(x, Math.fround(x))) >>> 0) & ( + y))))) | 0)) | 0))))); }); testMathyFunction(mathy2, [0x100000000, 0, 1, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 2**53+2, -0x07fffffff, -1/0, 0x080000001, -0x100000000, -0x080000000, -Number.MIN_VALUE, -0, -(2**53+2), 0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, 42, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, 1.7976931348623157e308, 0/0, -0x080000001, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-168297596*/count=1502; tryItOut("mathy3 = (function(x, y) { return ( ~ (Math.log(Math.fround((Math.fround(( + ( ! Math.fround(x)))) & Math.fround((( + Math.pow(( + ((y >>> 0) >> (x | 0))), Math.fround(Math.sin(-1/0)))) ? y : Math.hypot((Math.max(( + 0x100000001), (x | 0)) | 0), ( ! (( + Math.log(( + y))) >>> 0)))))))) | 0)); }); testMathyFunction(mathy3, [-0x080000001, 2**53+2, -(2**53+2), -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, 0x07fffffff, 42, 2**53, -0x100000001, -1/0, 0x080000001, -0x07fffffff, Math.PI, -0x080000000, -0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 0, 0x100000001, 0x0ffffffff, -0, 0x100000000, 0.000000000000001, 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=1503; tryItOut("print(f2);");
/*fuzzSeed-168297596*/count=1504; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ ( + (Math.expm1((Math.fround(Math.exp(Math.fround(2**53))) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-(2**53+2), -0, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, 1.7976931348623157e308, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, Math.PI, 0.000000000000001, -0x100000000, 2**53+2, 0x0ffffffff, 2**53-2, -0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, -(2**53), 0/0, 0x07fffffff, -0x07fffffff, 1, 0, -0x080000001, -1/0, 1/0]); ");
/*fuzzSeed-168297596*/count=1505; tryItOut("Array.prototype.reverse.call(this.a1);");
/*fuzzSeed-168297596*/count=1506; tryItOut("return;print(x);");
/*fuzzSeed-168297596*/count=1507; tryItOut("/*oLoop*/for (cewrpe = 0; cewrpe < 8; ++cewrpe) { /* no regression tests found */ } ");
/*fuzzSeed-168297596*/count=1508; tryItOut("g1.g2.m2 = t0[x];function get(x) { \"use strict\"; print([] = w); } print(\"\\u304A\" ^= [1,,]);");
/*fuzzSeed-168297596*/count=1509; tryItOut("mathy3 = (function(x, y) { return (( ! (Math.pow(Math.max(Math.trunc((Math.pow(0x080000000, (Math.min(y, ( + Math.min(( + x), ( + x)))) | 0)) >>> 0)), ( + mathy1(( + (( + (Math.atan2(y, (x | 0)) >>> 0)) || 1.7976931348623157e308)), ((mathy2(Math.fround(-0x100000000), x) | 0) >>> 0)))), ((( + (Math.min(((( - (y | 0)) | 0) | 0), x) | 0)) <= (( ! (x | 0)) | 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, [0.000000000000001, -0x100000000, -Number.MIN_VALUE, 1, 0/0, Number.MIN_SAFE_INTEGER, 42, 0, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, -(2**53-2), -1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 1/0, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, -0x0ffffffff, -(2**53), -Number.MAX_VALUE, 0x100000001, -0, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, -(2**53+2), Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 2**53, -0x080000000, 0x080000000]); ");
/*fuzzSeed-168297596*/count=1510; tryItOut("\"use strict\"; if(window) { if ( '' .throw(c)) ; else print(x);}");
/*fuzzSeed-168297596*/count=1511; tryItOut("for (var p in g0) { Object.defineProperty(this, \"v1\", { configurable: false, enumerable: (x % 31 != 22),  get: function() {  return t0.byteOffset; } }); }");
/*fuzzSeed-168297596*/count=1512; tryItOut("{ void 0; gcslice(1031); }\n/* no regression tests found */\n");
/*fuzzSeed-168297596*/count=1513; tryItOut("\"use strict\"; f1(h2);");
/*fuzzSeed-168297596*/count=1514; tryItOut("v2 = r1.constructor\nh0 + g1;\nlet (c) { t1 = t0.subarray(({valueOf: function() { g0 = this;return 18; }})); }\n");
/*fuzzSeed-168297596*/count=1515; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.asin((( + Math.min(( + Math.fround((Math.fround(Math.max(((((((Math.log10(x) >>> 0) ? 1.7976931348623157e308 : ( ! -0)) >>> 0) | 0) ? (Math.fround(mathy2((x >>> 0), (x >>> 0))) | 0) : (y | 0)) | 0), (Math.atan(x) >>> y))) || Math.fround(mathy2(((Math.asinh(( + y)) >>> 0) | 0), Math.exp(x)))))), (Math.trunc((x , (Math.fround((Math.fround(y) >>> -(2**53+2))) / x))) >>> 0))) >>> 0)); }); testMathyFunction(mathy3, [-0x0ffffffff, -1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, 1, -(2**53+2), 0/0, 0x080000001, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, 0, 0x080000000, -0, 42, -0x07fffffff, 0x100000000, -(2**53), 1.7976931348623157e308, 2**53+2, 0x100000001, 0x0ffffffff, -0x080000000, -0x100000001, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-168297596*/count=1516; tryItOut("throw window;");
/*fuzzSeed-168297596*/count=1517; tryItOut("");
/*fuzzSeed-168297596*/count=1518; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1519; tryItOut("v0 = this.a0.every(a2);");
/*fuzzSeed-168297596*/count=1520; tryItOut("var c = {} = /(?=(?![^])|(\\S|^+){1,})*?/gm;Array.prototype.push.call(this.o2.a1, h1, g1.o2.i2);");
/*fuzzSeed-168297596*/count=1521; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 67108864.0;\n    d2 = (d2);\n    i0 = (i0);\n    {\n      {\n        i0 = (i0);\n      }\n    }\n    return +(((-0.0009765625) + (d2)));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [false, '/0/', (function(){return 0;}), 1, objectEmulatingUndefined(), [0], '', (new String('')), '0', null, NaN, '\\0', undefined, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), true, (new Number(-0)), 0, (new Boolean(true)), -0, ({valueOf:function(){return '0';}}), (new Number(0)), [], (new Boolean(false)), 0.1, /0/]); ");
/*fuzzSeed-168297596*/count=1522; tryItOut("s0 += s0;y = (x) = new RegExp(\"((?![^\\\\D\\ud580][^]|(\\\\S)+?))+\", \"im\");");
/*fuzzSeed-168297596*/count=1523; tryItOut("\"use strict\"; this.__defineGetter__(\"a\", objectEmulatingUndefined)();");
/*fuzzSeed-168297596*/count=1524; tryItOut("this.a2.pop(this.f0, x, g1.p1);");
/*fuzzSeed-168297596*/count=1525; tryItOut("\"use strict\"; m1 + o1.v2;");
/*fuzzSeed-168297596*/count=1526; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.min(( + ( + ( - ( + Math.abs(x))))), ( + mathy0(( + Math.atanh((mathy0((Math.asinh(-0) | 0), (Math.max(x, ( + x)) >>> 0)) >>> 0))), ( + (( ! (Math.fround((Math.fround((x >> (x <= (x >>> 0)))) % Math.fround(Math.atanh(y)))) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-168297596*/count=1527; tryItOut("\"use strict\"; L:do print(x); while((new EvalError()) && 0);");
/*fuzzSeed-168297596*/count=1528; tryItOut("aflzfx(let (b =  '' )  \"\" , (/*UUV2*/(x.setMonth = x.values)));/*hhh*/function aflzfx(c){print(x);\na1.__proto__ = h1;\n}");
/*fuzzSeed-168297596*/count=1529; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ! (Math.hypot(Math.atanh(((Math.cosh(x) >>> 0) === y)), mathy1((Math.pow(( + y), ( + Math.expm1(( + x)))) | 0), ( - y))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0x080000001, 0, Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 0.000000000000001, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, 1/0, 0x100000000, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, -0, Number.MIN_VALUE, -0x07fffffff, 2**53, -1/0, -(2**53+2), 0/0, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 42, 0x0ffffffff, -(2**53-2), Number.MAX_VALUE, Math.PI, 0x07fffffff, -0x100000000, -0x100000001]); ");
/*fuzzSeed-168297596*/count=1530; tryItOut("\"use strict\"; o1 = {};");
/*fuzzSeed-168297596*/count=1531; tryItOut("a0.reverse();");
/*fuzzSeed-168297596*/count=1532; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log(((( - ( + Math.expm1(Number.MIN_SAFE_INTEGER))) | 0) || Math.atanh((Math.fround(mathy0(Math.fround(y), Math.fround(Number.MIN_SAFE_INTEGER))) ** Number.MIN_SAFE_INTEGER)))); }); testMathyFunction(mathy2, [0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, -Number.MAX_VALUE, -0x080000000, -0x100000001, 2**53-2, 1.7976931348623157e308, -0x080000001, Math.PI, 0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 2**53, 2**53+2, -(2**53+2), 0x080000001, 42, Number.MAX_SAFE_INTEGER, 1, 0/0, -Number.MIN_VALUE, 0.000000000000001, -0, -1/0, Number.MAX_VALUE, 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1533; tryItOut("\"use asm\";  for  each(let a in  \"\" ) (x);");
/*fuzzSeed-168297596*/count=1534; tryItOut("t0 = new Int8Array((x));");
/*fuzzSeed-168297596*/count=1535; tryItOut("\"use strict\"; \"use asm\"; /*infloop*/for(Number.prototype.toExponential in undefined) e1.add(this.f0);");
/*fuzzSeed-168297596*/count=1536; tryItOut("/*ODP-3*/Object.defineProperty(s0, \"toExponential\", { configurable: (x % 45 == 33), enumerable: true, writable: (x % 97 == 73), value: h2 });");
/*fuzzSeed-168297596*/count=1537; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.pow(( ! (Math.fround(mathy2(((Math.fround(y) + -Number.MIN_VALUE) >>> 0), Math.fround(x))) << Math.min(((Math.trunc(Math.fround(y)) >>> 0) >>> 0), (Math.max(((( - (y | 0)) | 0) >>> 0), y) >>> 0)))), Math.sin((Math.atan2(Math.fround(( + (( + ( - x)) != ( + Number.MAX_VALUE)))), mathy1(y, y)) | 0))); }); testMathyFunction(mathy4, [0/0, 2**53+2, 0.000000000000001, 0x100000000, Math.PI, -1/0, -0x0ffffffff, 0x080000000, -(2**53), 1, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, 42, 0x07fffffff, 2**53, -0x080000001, 0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0, 0x100000001, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff]); ");
/*fuzzSeed-168297596*/count=1538; tryItOut("\"use strict\"; m2.delete(o2);");
/*fuzzSeed-168297596*/count=1539; tryItOut("/*MXX2*/g1.DataView.name = p1;");
/*fuzzSeed-168297596*/count=1540; tryItOut("mathy3 = (function(x, y) { return (( + Math.tanh((( ! (y | 0)) | 0))) + (Math.fround((Math.imul(Math.fround(Math.tan(Math.fround(( + (( + y) ? ( + y) : ( + Math.log1p(mathy1(x, y)))))))), Math.max(Math.max(y, x), ( + mathy2(-Number.MAX_VALUE, y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [(new Boolean(true)), false, -0, (new String('')), [], (new Boolean(false)), '0', [0], '/0/', undefined, ({valueOf:function(){return 0;}}), NaN, 1, (function(){return 0;}), ({valueOf:function(){return '0';}}), /0/, objectEmulatingUndefined(), (new Number(-0)), '\\0', null, ({toString:function(){return '0';}}), 0.1, (new Number(0)), 0, true, '']); ");
/*fuzzSeed-168297596*/count=1541; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-168297596*/count=1542; tryItOut("\"use strict\"; a1.forEach((function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -262145.0;\n    var d3 = 5.0;\n    var i4 = 0;\n    (Int16ArrayView[0]) = ((-0x8000000)*-0x68f7a);\n    d2 = (d2);\n    switch ((imul((i4), (0x887d9f07))|0)) {\n    }\n    {\n      d0 = (d2);\n    }\nvar lqndmm = new SharedArrayBuffer(0); var lqndmm_0 = new Uint8Array(lqndmm); lqndmm_0[0] = -3; print([]);    return (((((((i4)+(i1)) | ((i1))) != (0x5d29084d))-(0xfa2a7d06))))|0;\n    {\n      i1 = (0x70104fe0);\n    }\n    i4 = (i4);\n    return (((0x73f934d2)*0xbe2b7))|0;\n  }\n  return f; }), s1, g0.t1);");
/*fuzzSeed-168297596*/count=1543; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + (( + (mathy2((Math.acos(((((y >>> 0) ? (y >>> 0) : (( - -Number.MAX_VALUE) >>> 0)) >>> 0) | 0)) | 0), ((Math.max(x, (y ? y : 0x080000001)) !== (Math.fround(x) / Math.fround(1.7976931348623157e308))) & (2**53-2 >> ( + x)))) >>> 0)) ? ( + ( ! ((Math.fround((Math.sinh(( - x)) | 0)) | 0) | 0))) : ( + (( + (( + (( + (( - (Math.atan2((Math.fround((0/0 >>> 0)) | 0), (( ~ (x >>> 0)) >>> 0)) | 0)) | 0)) + ( + Math.min((Math.log10((Math.clz32(1/0) | 0)) >>> 0), x)))) | 0)) | 0)))); }); testMathyFunction(mathy3, /*MARR*/[-0x0ffffffff, new Number(1.5), -0x0ffffffff, function(){}, new Number(1.5), -0x0ffffffff, function(){}, new Number(1.5), new Number(1.5), -0x0ffffffff, -0x0ffffffff, function(){}, -0x0ffffffff, function(){}, new Number(1.5), -0x0ffffffff, function(){}, new Number(1.5), function(){}, -0x0ffffffff, new Number(1.5), new Number(1.5), function(){}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, function(){}, function(){}, function(){}, -0x0ffffffff, -0x0ffffffff, new Number(1.5), new Number(1.5), function(){}, -0x0ffffffff, function(){}, -0x0ffffffff, function(){}, -0x0ffffffff, function(){}, function(){}, function(){}, function(){}, new Number(1.5), function(){}, function(){}, function(){}, function(){}, function(){}, -0x0ffffffff, new Number(1.5), function(){}, -0x0ffffffff, function(){}, new Number(1.5), new Number(1.5), function(){}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, new Number(1.5), -0x0ffffffff, -0x0ffffffff, function(){}, new Number(1.5), new Number(1.5), function(){}, function(){}, -0x0ffffffff, -0x0ffffffff, function(){}, new Number(1.5), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, new Number(1.5), new Number(1.5), new Number(1.5), -0x0ffffffff, function(){}, new Number(1.5), function(){}, -0x0ffffffff, -0x0ffffffff, new Number(1.5), function(){}, -0x0ffffffff, function(){}, -0x0ffffffff, function(){}, -0x0ffffffff, function(){}, new Number(1.5), function(){}, new Number(1.5), -0x0ffffffff, -0x0ffffffff, new Number(1.5), function(){}, new Number(1.5), -0x0ffffffff, -0x0ffffffff, new Number(1.5), function(){}, function(){}, -0x0ffffffff, function(){}, new Number(1.5), -0x0ffffffff, function(){}, function(){}, -0x0ffffffff, function(){}, function(){}, function(){}, function(){}, new Number(1.5), function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1.5), new Number(1.5), -0x0ffffffff, new Number(1.5), function(){}, function(){}]); ");
/*fuzzSeed-168297596*/count=1544; tryItOut("mathy1 = (function(x, y) { return ( + (Math.acosh(Math.fround(Math.abs(((mathy0(( + ( - ( + (x , -0x07fffffff)))), x) | 0) >>> 0)))) >>> Math.pow(Math.fround(Math.max(Math.fround((( + (( - Math.fround(( + Math.log1p((mathy0((-Number.MIN_SAFE_INTEGER | 0), (y | 0)) | 0))))) >>> 0)) >>> 0)), Math.fround(Math.cos(Math.sinh(Math.fround(x)))))), (( ! (( + Math.min(x, -Number.MIN_VALUE)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [0x07fffffff, 0.000000000000001, 1/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, 1, 2**53+2, -0x100000001, 0/0, 0x100000001, 0, -0x0ffffffff, -0x07fffffff, -(2**53), -0x100000000, -0x080000001, -(2**53+2), -1/0, 2**53, 42, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, 0x080000000, 0x0ffffffff, -0, -(2**53-2)]); ");
/*fuzzSeed-168297596*/count=1545; tryItOut("v2 = t0.length;function x(w, x, b, x, x, x, c, z, w, z = /([].|\\3)/yi, x, d,  , d, x, x, w, callee, window, y, x, x, x, x = this, x, x, c, ...window)\"use asm\";   var abs = stdlib.Math.abs;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1.5;\n    d0 = ((+abs(((d0)))) + (-3.0));\n    {\n      i1 = (0x92bea7b1);\n    }\n    d2 = (+(0.0/0.0));\n    i1 = (0xfa541537);\n    d2 = (d2);\n    i1 = ((~~(2048.0)));\n    return +((d2));\n  }\n  return f;((this\n));");
/*fuzzSeed-168297596*/count=1546; tryItOut("\"use asm\"; /*MXX2*/g1.Uint16Array.length = e2;");
/*fuzzSeed-168297596*/count=1547; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + mathy2(( + (mathy1(( + Math.min((( + (( + ( - ((Math.fround(-0x100000000) ? -0 : 0x0ffffffff) >>> 0))) === Math.sin(( + Math.tan(( + y)))))) | 0), Math.acos((( ~ ((0x080000001 ? x : y) | 0)) | 0)))), ( + ( ! Math.fround(( ~ Math.fround((Math.sinh((y >>> 0)) >>> 0))))))) | 0)), ( + (( + (Math.atan(Math.hypot(-Number.MAX_VALUE, x)) | 0)) >>> ( + ((( + ( + x)) >>> 0) || (Math.PI >>> 0))))))); }); testMathyFunction(mathy5, [-(2**53+2), 0.000000000000001, 0, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -1/0, 0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000001, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -(2**53), -Number.MAX_VALUE, 2**53-2, -0x07fffffff, -(2**53-2), 0x080000000, Number.MIN_VALUE, -0x080000000, -0x0ffffffff, 1/0, 0x07fffffff, 42, 0x0ffffffff, -0x080000001, 1, Math.PI, 0x080000001]); ");
/*fuzzSeed-168297596*/count=1548; tryItOut("s2 += g2.s0;");
/*fuzzSeed-168297596*/count=1549; tryItOut("\"use strict\"; o0.f1(s0);");
/*fuzzSeed-168297596*/count=1550; tryItOut("switch((4277)) { default: break; case x: break; /*MXX2*/g2.WeakSet.prototype.constructor = this.b0;break;  }");
/*fuzzSeed-168297596*/count=1551; tryItOut("\"use strict\"; L: {e2.has(i1); }");
/*fuzzSeed-168297596*/count=1552; tryItOut("");
/*fuzzSeed-168297596*/count=1553; tryItOut("\"use strict\"; v2 = (t2 instanceof o0);");
/*fuzzSeed-168297596*/count=1554; tryItOut("for (var v of v2) { /*RXUB*/var r = new RegExp(\"(\\\\B{0})(?:(?=(?!\\\\u0046{4,5})|\\\\W*[^]${1}|([^])[^\\\\\\u00d2-\\\\\\u3857\\\\\\u00c2-\\\\x18]))?\", \"\"); var s = \"\\n\\n\\n\\ufff8\\n\\ufff8\"; print(s.search(r)); print(r.lastIndex);  }");
/*fuzzSeed-168297596*/count=1555; tryItOut("Array.prototype.splice.apply(a0, [NaN, 0, a2, t0]);");
/*fuzzSeed-168297596*/count=1556; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a2, [(function(j) { this.o2.f2(j); }), i1, o2.g2.f2]);");
/*fuzzSeed-168297596*/count=1557; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-168297596*/count=1558; tryItOut("x = linkedList(x, 6460);");
/*fuzzSeed-168297596*/count=1559; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.max(( + ( ! ( + ( + ((x >>> 0) >>> ( + ( + Math.log1p(x)))))))), (( - Math.fround(mathy1((((x << ( + y)) | 0) <= (( - (y | 0)) | 0)), (y - (Math.max(Math.fround(Math.hypot((-0x100000000 | 0), (x | 0))), ( + (y | 0))) >>> 0))))) | 0)) >>> 0); }); ");
/*fuzzSeed-168297596*/count=1560; tryItOut("{const v2 = t1.length; }");
/*fuzzSeed-168297596*/count=1561; tryItOut("mathy3 = (function(x, y) { return Math.min((void options('strict')), (Math.fround(( + ( - Math.pow((y >>> 0), -Number.MAX_VALUE)))) ? Math.log2(x) : (Math.tan((Math.atan2(Math.sign(( + y)), (Number.MAX_SAFE_INTEGER | 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-168297596*/count=1562; tryItOut("a2 = a1.concat(a2, t2, t2);");
/*fuzzSeed-168297596*/count=1563; tryItOut("new x.unwatch(\"toString\")();");
/*fuzzSeed-168297596*/count=1564; tryItOut("\"use strict\"; \"\\u6A7F\";");
/*fuzzSeed-168297596*/count=1565; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i3 = ((Int32ArrayView[(((((/*FFI*/ff()|0)-(i3))>>>((i0)-(i0))))-((((((0xf99cf18b))>>>((0xcbfedf90))) % (0xd9293d39))>>>(((0x0))+((~((0xbbf9f1bb)+(0xffffffff)-(0xfde39822)))))))) >> 2]));\n    i3 = (/*FFI*/ff(((~((!(i3))+(!(i1))))))|0);\n    i3 = (i0);\n    i2 = (i3);\n    return +((3.094850098213451e+26));\n  }\n  return f; })(this, {ff: function(y) { yield y; o1.e1.add(h1);; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [(new Number(0)), (new Number(-0)), (new String('')), (new Boolean(true)), -0, [], (function(){return 0;}), (new Boolean(false)), ({toString:function(){return '0';}}), '/0/', ({valueOf:function(){return '0';}}), '0', 0.1, ({valueOf:function(){return 0;}}), '', 1, NaN, 0, false, objectEmulatingUndefined(), [0], null, undefined, true, /0/, '\\0']); ");
/*fuzzSeed-168297596*/count=1566; tryItOut("{ void 0; try { startgc(2, 'shrinking'); } catch(e) { } }");
/*fuzzSeed-168297596*/count=1567; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=1568; tryItOut("\"use strict\"; /*bLoop*/for (var tvipqy = 0; tvipqy < 36; ++tvipqy) { if (tvipqy % 40 == 0) { var usfkta;print(-9); } else { /*RXUB*/var r = r0; var s = s0; print(s.split(r));  }  } ");
/*fuzzSeed-168297596*/count=1569; tryItOut("print(x);\n( '' );\n");
/*fuzzSeed-168297596*/count=1570; tryItOut("Array.prototype.forEach.apply(a0, [(function() { for (var j=0;j<2;++j) { o0.f0(j%4==1); } })]);");
/*fuzzSeed-168297596*/count=1571; tryItOut("Array.prototype.shift.apply(a2, []);");
/*fuzzSeed-168297596*/count=1572; tryItOut("e0.add(s2);function w(eval, NaN, d, eval = (x) = \"\\u1994\", \u3056, d, x, x, a, x, NaN, x =  /x/g , y = window, NaN, window, x = -4, e, x, a, x, \u3056 = /(?!^)/gim, \u3056, a, a, x, x, z, c, this.x, x, x, a, x, e, d = this.window, x, setter, x, 0, x, e, x, x, x, e, d = eval, window, eval, c, eval, x, z, \u3056, x, w, x, z, \u3056 = NaN, NaN, b, x, z, w, d, d = -15, x, window = [[]], c, z, x, c =  /x/ , x, NaN = \"\\uC334\", x, x, get, this.x, e =  /x/ , d, z, \u3056, b = true, z, y, x, eval = Math, c, y, x = null, NaN = function ([y]) { }, x, NaN, w = \"\\u3B5A\", w) { \"use strict\"; print(x); } /*iii*/t0[4] = -27;/*hhh*/function idbtmd(y =  /x/ , \u3056 =  '' ){print(x);}");
/*fuzzSeed-168297596*/count=1573; tryItOut("");
/*fuzzSeed-168297596*/count=1574; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1575; tryItOut("{ void 0; void schedulegc(462); }");
/*fuzzSeed-168297596*/count=1576; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[]) { Array.prototype.splice.apply(a1, [NaN, v1]); }");
/*fuzzSeed-168297596*/count=1577; tryItOut("print(x);function y({}) { return null } print(x);");
/*fuzzSeed-168297596*/count=1578; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1579; tryItOut("let (e) { for (var v of t0) { try { print(uneval(o2.m0)); } catch(e0) { } try { neuter(b0, \"same-data\"); } catch(e1) { } try { m1 = new WeakMap; } catch(e2) { } this.f2 = o1; } }");
/*fuzzSeed-168297596*/count=1580; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1581; tryItOut("{/*tLoop*/for (let a of /*MARR*/[new String(''), new String(''), Infinity, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), Infinity, Infinity, Infinity, new String(''), Infinity, new String(''), Infinity, Infinity, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), Infinity, Infinity]) { {} } }");
/*fuzzSeed-168297596*/count=1582; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2|.[\\\\d\\\\f-\\\\2]|.\\\\B?[^](?=.(?:\\\\d)){3,}\\\\d+|(?!\\\\1)|\\\\1\\\\xE8|\\\\s+|\\\\B?|(?=(?:((?=\\\\3)|(?=\\\\w+)|\\\\b))+)\", \"gym\"); var s = \"\\n\"; print(r.test(s)); ");
/*fuzzSeed-168297596*/count=1583; tryItOut("/* no regression tests found */");
/*fuzzSeed-168297596*/count=1584; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.pow(( + ( + ((mathy1(Math.hypot((Math.tanh(y) | 0), y), ((Math.expm1(((( ! ( ~ 0x100000001)) >>> 0) | 0)) | 0) | 0)) | 0) | 0))), (Math.fround(( - (Math.atan2((Math.fround(Math.hypot(y, x)) | 0), Math.fround(( + (( + (0x080000000 * y)) << ( + (( - y) >>> 0)))))) | 0))) % ((((Math.hypot((-(2**53+2) | 0), (x | 0)) | 0) - (y < (Math.abs(y) | 0))) < 0x100000001) ? mathy0((Math.pow(( + ( + Math.max(( + -Number.MAX_VALUE), y))), (x >>> 0)) >>> 0), y) : Math.fround((Math.fround(-0x100000000) < Math.fround(mathy2((Math.fround((Math.fround(y) ** x)) | 0), y))))))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0.000000000000001, -(2**53), -1/0, 0x100000001, -(2**53+2), 0x0ffffffff, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 2**53, 0x080000000, 1, 1/0, 2**53+2, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 42, 0x100000000, Number.MIN_VALUE, 2**53-2, -(2**53-2), -0x080000001, 0, -Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-168297596*/count=1585; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy1(Math.atan2(Math.hypot(Math.fround(Math.sign((( + 0x080000000) | 0))), Math.log1p(x)), ( ! y)), ( + Math.asin(( + (((Math.sin(( + (x - 0x07fffffff))) | 0) ? (( + (Number.MAX_SAFE_INTEGER >>> 0)) | 0) : (Math.fround(( + Math.fround(Math.fround(( ! ( ~ x)))))) | 0)) | 0))))); }); testMathyFunction(mathy5, [0x07fffffff, -(2**53), -(2**53-2), -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 1/0, 0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, Number.MIN_VALUE, 2**53-2, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, 1, 0/0, 2**53+2, -0x100000000, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -0, -Number.MIN_VALUE, 42, 2**53, 1.7976931348623157e308, -(2**53+2), -1/0, -0x080000001, Math.PI, -0x080000000]); ");
/*fuzzSeed-168297596*/count=1586; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0((Math.max((( + Math.expm1(( + y))) >>> 0), Math.fround(Math.fround(((mathy0(( ~ y), ((Math.fround((( + x) ** ( + y))) >> x) >>> 0)) >>> 0) != y)))) | 0), Math.imul(Math.pow((((0x0ffffffff | 0) ? (x | 0) : Math.fround(x)) | 0), (x ? y : x)), Math.sin(2**53))) | 0); }); testMathyFunction(mathy1, [0x080000000, 0x0ffffffff, Math.PI, Number.MAX_VALUE, -0x080000001, 2**53, -Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, 1/0, 2**53-2, Number.MIN_SAFE_INTEGER, 42, -(2**53), 0/0, 0x07fffffff, -0x100000000, 0x080000001, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -0, -(2**53+2), -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 0, -0x07fffffff, Number.MIN_VALUE, -1/0, 0x100000000]); ");
/*fuzzSeed-168297596*/count=1587; tryItOut("\"use strict\"; i0 = new Iterator(f0);");
/*fuzzSeed-168297596*/count=1588; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-168297596*/count=1589; tryItOut("\"use strict\"; var eval = (e = /*MARR*/[function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}].map), [] = x, a, x = ((\"\\u1E9C\")), sttstk, mrvcuy, arwtui, window =  /x/ , x;a0.unshift();");
/*fuzzSeed-168297596*/count=1590; tryItOut("\"use strict\"; let({x: {}} = ((function a_indexing(cxiuwc, flbhhd) { ; if (cxiuwc.length == flbhhd) { let g1.v2 = Array.prototype.reduce, reduceRight.call(a0, (function(j) { if (j) { try { g0.a0.unshift(o0.g1, t0, g1.s0, e0, m1, p2); } catch(e0) { } m1.set(o2, o0); } else { try { a0.unshift(this, m0, f2); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(o2.g0, i2); } catch(e1) { } t0[v1] = f2; } }), i1);; return (a1.forEach((function(j) { o0.f0(j); }))); } var ahjrjo = cxiuwc[flbhhd]; var pgwmhx = a_indexing(cxiuwc, flbhhd + 1); m2 = new Map(this.t0);(void schedulegc(g2)); })(/*MARR*/[x, 0x3FFFFFFF, 0x3FFFFFFF, new Number(1.5), new Number(1.5), x, x, arguments.caller, 0x3FFFFFFF, x, arguments.caller, 0x3FFFFFFF, new Number(1.5), (0/0), (0/0), 0x3FFFFFFF, 0x3FFFFFFF, x], 0)), kqscri, window = new (/((?!\\1){4})/m)()) ((function(){x.name;})());for (var v of f2) { try { let a0 = arguments.callee.caller.arguments; } catch(e0) { } v2 = -Infinity; }");
/*fuzzSeed-168297596*/count=1591; tryItOut("\"use strict\"; v1 = Array.prototype.every.apply(o1.a0, [(function() { try { s1 = new String; } catch(e0) { } try { for (var v of g2.v1) { try { f1 = Proxy.createFunction(h2, g2.f2, f2); } catch(e0) { } try { o2.e0 + m2; } catch(e1) { } a1 = r2.exec(this.s2); } } catch(e1) { } print(v2); return g2; }), p1]);");
/*fuzzSeed-168297596*/count=1592; tryItOut("/*oLoop*/for (zerkii = 0, ((function a_indexing(zcsuov, bfjqje) { ; if (zcsuov.length == bfjqje) { a2.splice(-11, 0);; return new RegExp(\"\\\\1\", \"gyim\"); } var qrbuus = zcsuov[bfjqje]; var xgglhf = a_indexing(zcsuov, bfjqje + 1); a2.shift(h0); })(/*MARR*/[x, objectEmulatingUndefined(), x, new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), x, new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), x, new String('q'), x, objectEmulatingUndefined()], 0)); zerkii < 16; ++zerkii) { f0 + o2; } ");
/*fuzzSeed-168297596*/count=1593; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-168297596*/count=1594; tryItOut("(function(id) { return id });let (b) { /*RXUB*/var r = /(?=(?:\\2))/g; var s = \"aZ\"; print(s.replace(r, z = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return []; }, delete: (1 for (x in [])), fix: function() { return []; }, has: undefined, hasOwn: function() { return true; }, get: (1 for (x in [])), set: function() { return true; }, iterate: ((function shapeyConstructor(mazxvj){\"use strict\"; if ([[]]) delete this[\"__parent__\"];if (mazxvj) Object.freeze(this);for (var ytqvipate in this) { }for (var ytqxnrztc in this) { }Object.defineProperty(this, \"call\", ({get: /*wrap1*/(function(){ \"use strict\"; selectforgc(o2);return mathy2})(), set: mathy5, configurable: true, enumerable: mazxvj}));for (var ytqsmccsa in this) { }return this; }).bind).apply, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(\"\\uEE98\"), function(y) { \"use strict\"; t1[v0] = s0; }))); print(r.lastIndex);  }");
/*fuzzSeed-168297596*/count=1595; tryItOut("e = x;");
/*fuzzSeed-168297596*/count=1596; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min(((Math.fround((Number.MIN_SAFE_INTEGER ** (Math.imul((( + Math.tan(((((y | 0) / (-0x07fffffff | 0)) | 0) | 0))) >>> 0), Math.fround(((((( + (y >>> 0)) >>> 0) >>> 0) , (Math.atan2((y | 0), (x | 0)) | 0)) >>> 0))) >>> 0))) - (( + x) >>> 0)) >>> 0), ( + Math.sin(( + Math.hypot(Math.log1p(y), Math.fround(Math.log2(Math.fround(y)))))))); }); testMathyFunction(mathy1, [0x080000001, 42, -0x0ffffffff, 1/0, -Number.MIN_VALUE, 0, -(2**53+2), 1.7976931348623157e308, -1/0, 0.000000000000001, 1, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -0x080000001, 0/0, 0x0ffffffff, Number.MIN_VALUE, 2**53, -0, 0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, -Number.MAX_VALUE, 2**53-2, Math.PI, -(2**53), Number.MAX_VALUE, -0x100000000, 0x100000000]); ");
/*fuzzSeed-168297596*/count=1597; tryItOut("\"use strict\"; m1.delete(this.v0);");
/*fuzzSeed-168297596*/count=1598; tryItOut("mathy0 = (function(x, y) { return (Math.log2((((( + y) ? ( + Math.max(Math.ceil((Math.pow((y >>> 0), (( ~ y) >>> 0)) >>> 0)), Math.hypot(y, x))) : ( + Math.fround(Math.min((Math.min(((( ! Number.MIN_VALUE) , ( + x)) >>> 0), (( + Math.hypot(( + y), ( + 0x080000001))) | 0)) >>> 0), x)))) >>> 0) << Math.fround(( + (( + (( + x) >>> 0)) - ( + (( + y) ** ( + Math.hypot(Math.sinh(y), (((y | 0) << Math.PI) >>> 0)))))))))) >>> 0); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, -0x080000001, 0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000, 2**53, Math.PI, 1/0, 0/0, 1, -(2**53), -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -0x100000001, 0x100000000, 0x080000001, -Number.MIN_VALUE, 2**53+2, -1/0, 0.000000000000001, -0, 0, -0x100000000, 0x100000001]); ");
/*fuzzSeed-168297596*/count=1599; tryItOut("mathy2 = (function(x, y) { return Math.tanh(Math.hypot((( ! (( - ((( - (x >>> 0)) >>> 0) >>> 0)) >>> 0)) | 0), (x ? ( + y) : ( + ( ~ -0x080000000))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -0x100000000, -0x100000001, -(2**53+2), -0x080000000, 2**53, Math.PI, 1.7976931348623157e308, -0, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, 0, -1/0, 0/0, -(2**53-2), 0x080000001, 1, 1/0, 0x0ffffffff, -0x0ffffffff, 42, 0x07fffffff, Number.MIN_VALUE, 0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-168297596*/count=1600; tryItOut("mathy5 = (function(x, y) { return (Math.imul(((( + Math.imul(( + ( + -(2**53+2))), ( + (mathy4((y | 0), (x | 0)) | 0)))) && (( - (((y << Number.MAX_SAFE_INTEGER) >>> 0) | 0)) | 0)) >>> 0), ( + ( + Math.log10((Math.acosh(y) >>> 0))))) >>> 0); }); testMathyFunction(mathy5, [2**53-2, Number.MIN_VALUE, -0, -0x080000001, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -0x07fffffff, -(2**53-2), 0x100000000, 0x100000001, 42, -0x0ffffffff, 2**53, -(2**53+2), 0/0, 0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 0, -0x100000001, 1/0, 1, 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -1/0, 2**53+2]); ");
/*fuzzSeed-168297596*/count=1601; tryItOut("v2 = a0.reduce, reduceRight((function() { t1 = new Int16Array(b0, 16, 11); return v2; }), p2);");
/*fuzzSeed-168297596*/count=1602; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?:(?:\\\\b|((?=[\\u001b-\\\\xAF\\u000c\\\\ufc69-\\\\uffBA\\\\S]|[^])[^\\\\B-\\\\u3809\\\\w\\\\d])){67108864}))\", \"gy\"); var s = \"\\n0\\n01\\u09f3\\u3ee71\\u0014\\u0093\\n0\\n0\\n0\\n0\\n0\\n0\"; print(s.match(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
