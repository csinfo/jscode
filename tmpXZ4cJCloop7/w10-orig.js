

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
/*fuzzSeed-85495475*/count=1; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -8193.0;\n    i0 = (i0);\n    d2 = (((((+((0x24d45*(i0)) | ((((0x49aa265f))>>>((0xfb4c7feb))) % (0xb831c4e9))))) % ((Float32ArrayView[4096])))) % ((+abs(((+/*FFI*/ff((((((((0xf9b323fa))>>>((-0x8000000))) > (0xc2099b53))*-0x619d) | (((~~(+/*FFI*/ff(((17179869184.0)), ((-288230376151711740.0)), ((-1.0009765625)), ((-1.03125)), ((-36893488147419103000.0))))))+(0x6074d11b)))), ((+(((/*FFI*/ff((((0xe4584433) ? (17592186044417.0) : (1.0))), ((+(1.0/0.0))), ((imul((0x349e5d98), (0xff1fa455))|0)), ((0.03125)), ((295147905179352830000.0)))|0))))), ((((-0x6c134a7)+(0x9de918bd)) & ( '' .unwatch(-15) %= (4277)\n))), ((d1)), ((0x7fffffff)))))))));\n    return +((d1));\n  }\n  return f; })(this, {ff: DataView.prototype.setUint32}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=2; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^].{0,0}\", \"y\"); var s = \"\\n\\n\"; print(uneval(s.match(r))); ( \"\" );function this.x(x, ...x) { \"use strict\"; yield  /x/g .yoyo( /x/ ) } print(\"\\uBE69\");");
/*fuzzSeed-85495475*/count=3; tryItOut("for(let [e, w] = Math.pow(/\\b(?=\\u00f3|\\B*?)*/y, ((void shapeOf(/(?!((?=$(\\cA)*?)|\\u871e{4,}))/)))) in ( \"\"  ? undefined : Math) > [] = a) (w & eval);");
/*fuzzSeed-85495475*/count=4; tryItOut("a2.reverse(h2);");
/*fuzzSeed-85495475*/count=5; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i1);\n    }\n    return +((-4.722366482869645e+21));\n    return +((+(~~(-6.189700196426902e+26))));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53-2), 0x100000000, -0x080000000, 0x100000001, -(2**53+2), -0x100000000, 0x0ffffffff, 0x080000001, -0x100000001, -Number.MAX_VALUE, -(2**53), -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, 42, 0x07fffffff, 2**53-2, -0x080000001, 2**53+2, Math.PI, 1.7976931348623157e308, 2**53, Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-85495475*/count=6; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return y+=new (decodeURI)(); }); testMathyFunction(mathy5, [1, -Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, 0/0, -(2**53+2), 1/0, 2**53, -0x100000001, -(2**53), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 0x080000001, -(2**53-2), 0.000000000000001, 2**53+2, 42, 0x07fffffff, 0x080000000, -0x100000000, 0x100000001, -0x080000000, -0x07fffffff, -0x080000001, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=7; tryItOut("g2.g0 + this.a2;");
/*fuzzSeed-85495475*/count=8; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 18446744073709552000.0;\n    var d3 = -1.5474250491067253e+26;\n    d0 = ((d0) + (d3));\n    return ((-0xfffff*(0xfae69e86)))|0;\n  }\n  return f; })(this, {ff: /*FARR*/[\"\\u9005\", ({})].filter( /x/ )}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[ /x/g , x, x,  /x/g , x, x, true, x,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , true, true, true,  /x/g , true,  /x/g , x,  /x/g ,  /x/g , x, true, x, true, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/g ,  /x/g ,  /x/g , x, true, true, true,  /x/g ,  /x/g , x, true, x,  /x/g ,  /x/g , true, x, x, x, true, true, x, x,  /x/g , true,  /x/g ,  /x/g , x, x, x, x, x, x, x, x, x, x, x, x, true, true, x, x, true, true, x, true,  /x/g ,  /x/g , true, true,  /x/g , true, x,  /x/g , x,  /x/g , true, x, x, x, true,  /x/g , true, x,  /x/g , true,  /x/g ,  /x/g ,  /x/g , true, true,  /x/g , true, true, true, x, x, x, true,  /x/g ,  /x/g ,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x, x, x,  /x/g , x, x, x, true, x, true,  /x/g ,  /x/g , true, true, x, true, x, x, true, true, x, true, x, x, x,  /x/g , true, true, true, true, x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x, x, x, x, true,  /x/g ,  /x/g , x,  /x/g ]); ");
/*fuzzSeed-85495475*/count=9; tryItOut("\"use strict\"; print(uneval(m1));");
/*fuzzSeed-85495475*/count=10; tryItOut("while(((b = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: \"\\u410C\", has: function() { return false; }, hasOwn: mathy3, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(window), Proxy( '' )))) && 0){v1 = g0.eval(\"+((makeFinalizeObserver('tenured')))\"); }");
/*fuzzSeed-85495475*/count=11; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = evalcx(''); f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-85495475*/count=12; tryItOut("(new RegExp(\"\\\\3\", \"gyim\"));");
/*fuzzSeed-85495475*/count=13; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3\", \"gy\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-85495475*/count=14; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-85495475*/count=15; tryItOut("x = linkedList(x, 756);");
/*fuzzSeed-85495475*/count=16; tryItOut("a1 = arguments.callee.arguments;ssdmaa((let (e) false), 23);/*hhh*/function ssdmaa(b, d, e, e, x, x, x, x, x, x, \"-8\", x, d, \"0x99\" =  /x/ , x, x, c, eval, y, b = \"\\u6EDF\"){([[1]]);}");
/*fuzzSeed-85495475*/count=17; tryItOut("print(({}));");
/*fuzzSeed-85495475*/count=18; tryItOut("\"use strict\"; const a = (/((?:(?=[\\w+-\uf1e0\\uFB9B\\D]).*?\\3)){1,}/yi >=  /x/g ).unwatch(\"0\");m0.has(f0);print(/*FARR*/[].map((1 for (x in [])), this));function x(x, x) { \"use asm\"; yield ((function factorial_tail(cocwth, ukgoup) { v2 = t0.byteLength;; if (cocwth == 0) { ; return ukgoup; } yield  /x/g ;; return factorial_tail(cocwth - 1, ukgoup * cocwth);  })(50976, 1)) } for (var p in g0.s0) { try { Object.defineProperty(this, \"m2\", { configurable: true, enumerable: true,  get: function() {  return new Map; } }); } catch(e0) { } v2 = t2[8]; }");
/*fuzzSeed-85495475*/count=19; tryItOut("\"use strict\"; a0[({valueOf: function() { v1 = Object.prototype.isPrototypeOf.call(o0.g2.g2.s1, e0);return 0; }})] = x;");
/*fuzzSeed-85495475*/count=20; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=21; tryItOut("testMathyFunction(mathy3, /*MARR*/[(void 0), true, new Boolean(false), new Boolean(false), x, x, new Boolean(false), x, true, new Boolean(false), x, (void 0), (void 0), x, true, true, new Boolean(false), new Boolean(false), x, true, (void 0), new Boolean(false), true, true, new Boolean(false), (void 0), (void 0), (void 0), true, x, (void 0), true, x, true, (void 0), new Boolean(false), (void 0), true, (void 0), new Boolean(false), true, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), x, true, (void 0), true, (void 0), true, true, (void 0), (void 0), true, new Boolean(false), true, new Boolean(false), x, x, new Boolean(false), (void 0), (void 0), x, x, x, (void 0), new Boolean(false), (void 0), (void 0), x, x, new Boolean(false), true, (void 0), x, x, true, x, new Boolean(false), (void 0), x, x, (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), true, (void 0), (void 0), true, new Boolean(false), (void 0), true, new Boolean(false), new Boolean(false), (void 0), x, true, new Boolean(false), true, true, x, x, true, x, (void 0), new Boolean(false), new Boolean(false), (void 0), true, true, (void 0), x, x, true, (void 0)]); ");
/*fuzzSeed-85495475*/count=22; tryItOut("([]);");
/*fuzzSeed-85495475*/count=23; tryItOut("for (var p in o0) { try { Array.prototype.forEach.apply(a2, [(function() { try { this.v1 + h2; } catch(e0) { } try { m1.get(p0); } catch(e1) { } g1.i0.send(g0); throw this.s0; }), f0]); } catch(e0) { } try { Array.prototype.shift.call(a2); } catch(e1) { } try { m0.has(\"\\u7471\"); } catch(e2) { } v2 = (g0 instanceof e0); }");
/*fuzzSeed-85495475*/count=24; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.pow(( + (( + x) || ( ! (((x | 0) << (y | 0)) | 0)))), Math.fround(( ! (x - Number.MAX_VALUE))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 2**53, 1, 0.000000000000001, 0x080000001, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0/0, 0x080000000, -0, -0x100000000, 0, Number.MAX_VALUE, 42, Math.PI, 2**53+2, -1/0, 0x0ffffffff, -0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, 0x07fffffff, -0x080000001, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 1/0, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=25; tryItOut("\"use strict\"; for(var [a, x] = 'fafafa'.replace(/a/g, Function) in (--x)) {i0.send(e2); }");
/*fuzzSeed-85495475*/count=26; tryItOut("\"use strict\"; a2.__proto__ = h2;");
/*fuzzSeed-85495475*/count=27; tryItOut("");
/*fuzzSeed-85495475*/count=28; tryItOut("t2 + v1;");
/*fuzzSeed-85495475*/count=29; tryItOut("\"use strict\"; Array.prototype.unshift.call(a1, (arguments.callee.arguments), t2, h0);");
/*fuzzSeed-85495475*/count=30; tryItOut("\"use strict\"; /*vLoop*/for (vochub = 0; vochub < 1; ++vochub, \"\\uFABD\".throw(\"\\uF55B\"), x) { var b = vochub; o0.a2 = r2.exec(s1);var tlykls = new SharedArrayBuffer(24); var tlykls_0 = new Uint8Array(tlykls); print(tlykls_0[0]); g2.s2 = s1.charAt(v1); } ");
/*fuzzSeed-85495475*/count=31; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.fround(Math.fround((Math.fround(Math.imul(mathy1(Math.fround(Math.log10((y >>> 0))), (Math.min((( + y) | 0), (y | 0)) | 0)), (Math.fround(((x ? ( + x) : Math.asinh(y)) >>> Math.fround(x))) | 0))) + Math.fround((( - ((Math.fround(Math.tan(Math.hypot(x, (x >>> 0)))) + x) >>> 0)) >>> 0))))) >>> ((x - Math.fround((mathy2((( + y) >>> 0), (x >>> 0)) * Math.fround(Math.hypot(1/0, testMathyFunction(mathy4, [2**53, -(2**53-2), 0x080000001, Number.MAX_VALUE, 1/0, -0x080000001, 0, 1.7976931348623157e308, -0x07fffffff, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 0x0ffffffff, -Number.MAX_VALUE, Math.PI, 42, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x100000001, 2**53-2, 0x07fffffff, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, 0x100000000, -0, -1/0, 0x100000001, 0/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER]); ))))) + Math.fround(Math.tanh(( + (Math.atan2((y | 0), (Math.pow(x, x) | 0)) | 0)))))); }); testMathyFunction(mathy4, [false, ({valueOf:function(){return '0';}}), -0, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), (new Boolean(false)), '0', '', [], (new Number(0)), '/0/', ({toString:function(){return '0';}}), [0], 1, NaN, 0.1, undefined, true, /0/, (new String('')), (new Number(-0)), (function(){return 0;}), (new Boolean(true)), null, 0, '\\0']); ");
/*fuzzSeed-85495475*/count=32; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=33; tryItOut("\"use strict\";  for  each(let c in (/*UUV2*/(eval.entries = eval.getMilliseconds))) {let b = (uneval(let (x = 25, NaN, oldgyq, leuryc, gqchoh, qdipbx, x, \u3056, c, x) NaN < a)), c, \u3056 = new Uint16Array(this, ((function sum_indexing(nzlqwo, qjvtki) { ; return nzlqwo.length == qjvtki ? 0 : nzlqwo[qjvtki] + sum_indexing(nzlqwo, qjvtki + 1); })(/*MARR*/[x, /\\D/yim, ({x:3}), x, /\\D/yim, /\\D/yim, ({x:3}), /\\D/yim, ({x:3}), ({x:3}), [1], [1], x, x, ({x:3}), /\\D/yim], 0))), {} = c ? new RegExp(\"[^]\", \"\") : c, ttzpor, c = \"\\u81F0\";this.zzz.zzz; }");
/*fuzzSeed-85495475*/count=34; tryItOut("/*infloop*/while((Math.imul(1e-81, 28)))for (var p in f0) { try { for (var p in g2.p0) { this.v1 = evalcx(\"\\\"use strict\\\"; testMathyFunction(mathy0, [2**53+2, 0x080000001, 2**53-2, Math.PI, 42, 1.7976931348623157e308, 0/0, -(2**53-2), 1, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 2**53, -0x07fffffff, 0x080000000, Number.MAX_VALUE, -0x100000000, -0x080000001, -1/0, -(2**53+2), 0.000000000000001, 0, -(2**53), 0x100000000, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -0, Number.MIN_VALUE, -0x080000000]); \", o1.g0); } } catch(e0) { } try { /*RXUB*/var r = r0; var s = s2; print(r.test(s));  } catch(e1) { } Array.prototype.shift.call(a1); }");
/*fuzzSeed-85495475*/count=35; tryItOut("\u000dthis;");
/*fuzzSeed-85495475*/count=36; tryItOut("this.e1.add(g1);");
/*fuzzSeed-85495475*/count=37; tryItOut("\"use strict\"; this.v2 = a2.length;");
/*fuzzSeed-85495475*/count=38; tryItOut("for (var v of h2) { o0.s0 = t1[14]; }");
/*fuzzSeed-85495475*/count=39; tryItOut("\"use strict\"; h2.getOwnPropertyDescriptor = f2;");
/*fuzzSeed-85495475*/count=40; tryItOut("testMathyFunction(mathy5, ['\\0', true, (function(){return 0;}), -0, NaN, '/0/', objectEmulatingUndefined(), [], false, [0], /0/, 1, undefined, (new Boolean(false)), ({valueOf:function(){return 0;}}), '', null, 0.1, '0', (new Boolean(true)), 0, ({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}}), (new Number(-0)), (new String(''))]); ");
/*fuzzSeed-85495475*/count=41; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.round(( + Math.cos(( + ( - Number.MAX_VALUE))))) | 0), Math.fround((( ! Math.fround((y ** (Math.max(Number.MIN_VALUE, Math.sin(Math.pow(y, 0))) >>> 0)))) | 0))) | 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 1/0, -0x0ffffffff, 1, 0x100000000, 2**53-2, -0x080000000, Number.MAX_VALUE, -0x100000001, Math.PI, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 0/0, -0x100000000, 0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -(2**53+2), 0x07fffffff, -0, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53, 42, -(2**53), 0, 2**53+2, 0x0ffffffff, 0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=42; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\b\", \"gy\"); var s = \"a\"; print(r.exec(s)); ");
/*fuzzSeed-85495475*/count=43; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return (((i1)*0xfffff))|0;\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; return NaN instanceof x }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, 1/0, 2**53, -0x0ffffffff, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 0, -1/0, 0x0ffffffff, -0x080000001, 0/0, 0x07fffffff, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 1, -0, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), 2**53-2, Number.MIN_VALUE, 42, 2**53+2]); ");
/*fuzzSeed-85495475*/count=44; tryItOut("s1 += s1;");
/*fuzzSeed-85495475*/count=45; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (33.0);\n    return +((((-1.9342813113834067e+25)) / ((36028797018963970.0))));\n  }\n  return f; })(this, {ff: Math.log10}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [2**53+2, 0/0, -1/0, 0x080000000, -0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 1/0, 42, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 1, -0, -0x080000000, -(2**53-2), -0x0ffffffff, 0, -(2**53), -(2**53+2), -0x080000001, 2**53, -0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=46; tryItOut("/*bLoop*/for (var kyulgc = 0; kyulgc < 10; ++kyulgc, x) { if (kyulgc % 18 == 14) { throw StopIteration;with({}) yield (intern(x)); } else { let (x, b, e = ({/*toXFun*/toSource: eval, \"-13\": ++b }), ddluqe, x = ([]) & x, x = (\"\\uDF6C\".unwatch(\"this\"))) { for(let e in (((\u3056--))(((p={}, (p.z = 27)())))))g1.v0 = g1.eval(\"p1 + p1;\"); } }  } ");
/*fuzzSeed-85495475*/count=47; tryItOut("testMathyFunction(mathy0, [-0x080000000, 1, Math.PI, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 0/0, -1/0, 0x080000001, -0, Number.MAX_SAFE_INTEGER, 42, -0x080000001, 0x080000000, -(2**53-2), -(2**53), -0x0ffffffff, -Number.MAX_VALUE, -0x100000000, 2**53-2, 2**53, -(2**53+2), 2**53+2, -0x100000001]); ");
/*fuzzSeed-85495475*/count=48; tryItOut("\"use strict\"; this.t2 = t2.subarray(6);");
/*fuzzSeed-85495475*/count=49; tryItOut("print(let (b) -21);");
/*fuzzSeed-85495475*/count=50; tryItOut("b2 = new SharedArrayBuffer(24);\n(/*RXUE*//\\B+?|(?:(?!\\d|\\d+?.|\\B))*/y.exec( /x/g ) , ((makeFinalizeObserver('nursery'))));\n");
/*fuzzSeed-85495475*/count=51; tryItOut("/*RXUB*/var r = new RegExp(\".\", \"gym\"); var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=52; tryItOut("print(x);");
/*fuzzSeed-85495475*/count=53; tryItOut("mathy0 = (function(x, y) { return Math.log1p(( ~ ( + ( + ( ! ( + (Math.sqrt((Math.min((y | 0), -0x0ffffffff) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy0, [0x080000000, -0x100000001, -(2**53+2), 2**53+2, Number.MAX_VALUE, 0x100000000, -0x080000000, 0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, 0x0ffffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, 0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -0x100000000, -Number.MIN_VALUE, -0x07fffffff, 1, -1/0, Number.MIN_VALUE, 2**53, Math.PI, -(2**53-2), 42, -Number.MAX_VALUE, -0, 0x100000001]); ");
/*fuzzSeed-85495475*/count=54; tryItOut("mathy2 = (function(x, y) { return Math.exp(Math.fround((Math.imul((x == ( + Math.fround(Math.imul(Math.fround(( ! (x >>> 0))), Math.fround(Math.fround(Math.cbrt(y))))))), ( - Math.max(Math.log10(x), y))) ? (( + ( - ( + 1))) == (Math.cbrt((Math.imul(( + Math.sin(-0x100000001)), (y >>> 0)) >>> 0)) >>> 0)) : Math.fround(Math.fround(Math.trunc(Math.fround(y))))))); }); testMathyFunction(mathy2, [0x080000000, -Number.MIN_VALUE, 0x100000000, 0x080000001, 0, -1/0, -(2**53), 0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, -0x0ffffffff, 0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, 2**53, 2**53-2, 2**53+2, 1.7976931348623157e308, -(2**53-2), 0x100000001, -0x080000000, -0x080000001, 0/0, 42, 1, -0x100000000, -0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=55; tryItOut("\"use strict\"; var -14 = (allocationMarker()), \u3056 = /*FARR*/[\"\\u4D3C\", \"\\u06FC\", , new RegExp(\"(?!\\\\B|\\\\W+?\\\\s|$)*?\", \"ym\"), -4, this, ...[], x,  '' , ...[], ...[], \"\\u5BD4\", ...[], ...[], true, undefined, ...[],  /x/ , this, ...[], null].map(runOffThreadScript, (x) =  /x/g ), a = window, x =  \"\" , ypblaw;for (var p in m1) { try { for (var p in h1) { try { v2 = r2.ignoreCase; } catch(e0) { } try { v1 = new Number(NaN); } catch(e1) { } try { i1 = new Iterator(p2, true); } catch(e2) { } x = e2; } } catch(e0) { } try { h0.getOwnPropertyDescriptor = (function(j) { if (j) { v0 = Object.prototype.isPrototypeOf.call(t1, m2); } else { try { const s2 = new String(t1); } catch(e0) { } print(uneval(o0.f2)); } }); } catch(e1) { } try { s1 += s0; } catch(e2) { } v2 = evalcx(\"s2 = t1[18];\", g2); }");
/*fuzzSeed-85495475*/count=56; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.log(Math.pow(Math.fround(mathy2(Math.fround(( + Math.atan2(((((y >>> 0) >>> (-0x100000000 >>> 0)) >>> 0) | 0), ( + x)))), Math.fround(y))), mathy0((( + Math.fround((((-Number.MIN_VALUE | 0) / ( + ( ! ( + -0x0ffffffff)))) | 0))) | 0), (((mathy3(( + y), ( + y)) >>> 0) | ((( ! Math.fround(x)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy4, [0x080000001, -0x100000001, -0x080000000, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 0, 0x080000000, 2**53+2, -(2**53+2), 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, 1, 1/0, -1/0, 1.7976931348623157e308, 42, Number.MAX_VALUE, -(2**53-2), 0x100000000, -(2**53), -Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=57; tryItOut("with((4277)){lsmfol, of;v0 = g1.runOffThreadScript(); }");
/*fuzzSeed-85495475*/count=58; tryItOut("/*RXUB*/var r = /(?:.)((?!\\3)^\\r)/gim; var s = ({e: ( \"\"  === d)}); print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=59; tryItOut("\"use strict\"; for(var z in null) {(\"\\u9C30\");\u0009( /x/ ); }");
/*fuzzSeed-85495475*/count=60; tryItOut("selectforgc(o1);");
/*fuzzSeed-85495475*/count=61; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      switch ((((0x17e27111) / (0x1b15b29e)) ^ (((0x4be35bf8) <= (0xd77f076c))-((0xf29ba0b))))) {\n        case -3:\n          {\n            i1 = (i1);\n          }\n          break;\n      }\n    }\n    (Float64ArrayView[2]) = ((+sqrt(((Float64ArrayView[2])))));\n    {\n      i0 = (i0);\n    }\n    i1 = (/*FFI*/ff()|0);\n    i1 = ((i1) ? (i0) : (i0));\n    return (((i1)*-0xdf252))|0;\n  }\n  return f; })(this, {ff: (/*FARR*/[true, null, , w, /\\cB/gim, \"\\u45E2\",  /x/ , /[^]/m, null].map((let (e=eval) e)\u0009))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0/0, -0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, 0x100000000, 0x07fffffff, 1/0, 1.7976931348623157e308, -0x07fffffff, 0x080000000, -Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, -0x100000000, 42, 0, 0.000000000000001, 2**53-2, 0x100000001, -0, -(2**53), 2**53, -(2**53+2), 0x080000001, -0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=62; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - (((Math.log2(((y | 0) <= ((Math.log1p(y) >>> 0) >> (Number.MIN_VALUE !== 0/0)))) >>> 0) >= (( + mathy0(Math.atan2(y, Math.hypot(x, ( + x))), (( + y) && (Math.fround(((x >>> 0) != -1/0)) | 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, ['/0/', (new Number(-0)), null, '\\0', -0, [0], '', objectEmulatingUndefined(), (new String('')), ({valueOf:function(){return '0';}}), (new Boolean(true)), false, (new Number(0)), ({valueOf:function(){return 0;}}), /0/, NaN, ({toString:function(){return '0';}}), (new Boolean(false)), true, '0', undefined, 0, 1, [], (function(){return 0;}), 0.1]); ");
/*fuzzSeed-85495475*/count=63; tryItOut("v1 = g1.eval(\"function f1(this.p2)  { \\\"use strict\\\"; //h\\nwith(((yield x)))(((e = function  eval (w = /.{1,4}/ && true)\\u3056 = \\\"\\\\u60F4\\\".prototype))); } \");");
/*fuzzSeed-85495475*/count=64; tryItOut("mathy3 = (function(x, y) { return ( + Math.log((( ~ Math.fround(( - ((y | 0) % ( + -0x100000000))))) >>> 0))); }); testMathyFunction(mathy3, ['', (new Boolean(false)), [], (new Number(-0)), (new Number(0)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '\\0', (function(){return 0;}), '/0/', /0/, null, 1, false, true, '0', NaN, objectEmulatingUndefined(), -0, ({valueOf:function(){return 0;}}), 0, undefined, 0.1, (new String('')), (new Boolean(true)), [0]]); ");
/*fuzzSeed-85495475*/count=65; tryItOut("\"use strict\"; a1.sort((function mcc_() { var fuudyb = 0; return function() { ++fuudyb; f1(true);};})(), m1, g2, e2);");
/*fuzzSeed-85495475*/count=66; tryItOut("\"use strict\"; x = b0;");
/*fuzzSeed-85495475*/count=67; tryItOut("var r0 = x + x; r0 = r0 % 8; var r1 = x * r0; var r2 = r0 & r1; var r3 = r1 * 6; var r4 = 8 * r0; print(r1); r2 = 5 & r2; var r5 = r2 | r1; var r6 = r2 + r2; r2 = 8 ^ 6; var r7 = r5 - r2; var r8 = r0 & x; var r9 = 0 / x; var r10 = r9 & r1; var r11 = r10 & 8; var r12 = r1 - r9; r8 = r9 % r7; r12 = r5 & r10; print(r0); print(r1); var r13 = r3 + 3; var r14 = r6 / 2; var r15 = 4 + r0; var r16 = r5 / r6; var r17 = 2 * r10; var r18 = r8 / r9; var r19 = r18 + 7; r2 = r14 - r14; var r20 = x % 6; var r21 = r1 + r5; r20 = 9 - r12; var r22 = 1 * 6; print(r19); var r23 = r7 - x; r5 = r4 * 4; var r24 = r19 | 1; var r25 = r18 / 3; var r26 = 2 % 5; var r27 = r2 - r8; print(r16); var r28 = r3 % 0; var r29 = r16 ^ r23; var r30 = r3 | r20; var r31 = r21 * r26; var r32 = 8 ^ r3; var r33 = 2 / 2; var r34 = r13 % r7; var r35 = x / 4; var r36 = 8 / r24; var r37 = r7 % r22; r22 = 5 & x; r13 = r10 - 1; var r38 = r34 * r21; r20 = r4 * r27; var r39 = r1 * r13; r23 = r5 | r35; r17 = r6 + r2; var r40 = 9 * 7; print(r3); var r41 = 7 * r5; r11 = 9 | 7; var r42 = r0 + 0; var r43 = r25 - r17; var r44 = r18 % 2; var r45 = r30 ^ 2; var r46 = r20 - r33; var r47 = r22 | r43; var r48 = r16 * 2; var r49 = 9 % 0; r7 = r40 * r25; var r50 = r31 - 0; var r51 = 2 / r50; ");
/*fuzzSeed-85495475*/count=68; tryItOut("\"use asm\"; let (c) { selectforgc(o0); }");
/*fuzzSeed-85495475*/count=69; tryItOut("\"use strict\"; new RegExp(\"(X(?=\\u00de){2})\", \"gyi\");print(x);");
/*fuzzSeed-85495475*/count=70; tryItOut(";");
/*fuzzSeed-85495475*/count=71; tryItOut("mathy1 = (function(x, y) { return (( + ((Math.fround((Math.fround(y) && Math.fround(((y >>> 0) === x)))) % ( + Math.log10((( ~ (Math.hypot(((mathy0(y, (y >>> 0)) >>> 0) >>> 0), (x >>> 0)) >>> 0)) | 0)))) >>> 0)) < Math.asinh(Math.fround(Math.cbrt(Math.fround(mathy0((mathy0(-0x100000000, y) | 0), (( + y) | 0))))))); }); testMathyFunction(mathy1, [0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, Math.PI, 1/0, -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -1/0, 1, 1.7976931348623157e308, -0, 2**53, -Number.MAX_VALUE, 2**53-2, -0x080000001, 0x07fffffff, 0x0ffffffff, 0/0, 0x100000001, 42, 0.000000000000001, -(2**53), -0x100000000, 0x100000000, -(2**53-2), -0x100000001, 0x080000000]); ");
/*fuzzSeed-85495475*/count=72; tryItOut("var w = [(4277)];v1 = Object.prototype.isPrototypeOf.call(a0, b1);");
/*fuzzSeed-85495475*/count=73; tryItOut("h1.enumerate = f2;");
/*fuzzSeed-85495475*/count=74; tryItOut("var xrngnq = new SharedArrayBuffer(12); var xrngnq_0 = new Float32Array(xrngnq); /*ADP-1*/Object.defineProperty(a1, 0, ({configurable:  /x/ , enumerable: false}));");
/*fuzzSeed-85495475*/count=75; tryItOut("\"use strict\"; this.h2.get = f2;function w(valueOf) { Array.prototype.reverse.apply(a2, []); } g1.a0.sort((function() { try { o2 = this.i1; } catch(e0) { } try { e1 = t1[13]; } catch(e1) { } var v0 = 0; return b1; }), p1, x, i2);");
/*fuzzSeed-85495475*/count=76; tryItOut("mathy3 = (function(x, y) { return ((((( ~ ( ! y)) | 0) * ((Math.fround(( ! Math.fround((y == y)))) - (Math.max(Math.fround(( - ( + y))), Math.atan(( + 2**53+2))) | 0)) | 0)) <= (/*RXUE*//($\\W|^*?(?:\\cV)+?|(\\B)\\3\\W|(\\S)|\ue3e7|\\2?)/gyi.exec(\"\\u0016\\u0016\") | 0)) | 0); }); testMathyFunction(mathy3, [2**53+2, 0.000000000000001, -0x100000001, 0x080000001, -0x100000000, -0x0ffffffff, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -1/0, 2**53-2, Number.MIN_VALUE, -(2**53-2), Number.MAX_VALUE, 1, 2**53, 1.7976931348623157e308, -0x080000000, -(2**53), -0x080000001, 0x100000001, -0x07fffffff, -(2**53+2), 0, 42, 0/0, Math.PI, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=77; tryItOut("v1 = g1.eval(\"e0.delete(o1.t2);\");");
/*fuzzSeed-85495475*/count=78; tryItOut("\"use strict\"; { void 0; setGCCallback({ action: \"majorGC\", depth: 10, phases: \"both\" }); }");
/*fuzzSeed-85495475*/count=79; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.expm1((mathy0(mathy0(y, Number.MAX_VALUE), mathy1(Math.pow(Math.fround(( + -0x0ffffffff)), ((Math.hypot(( + x), Math.log1p(x)) | 0) | 0)), x)) >>> 0))); }); ");
/*fuzzSeed-85495475*/count=80; tryItOut("\"use strict\"; \"use asm\"; /*ADP-2*/Object.defineProperty(a1, 14, { configurable: false, enumerable: false, get: (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var Infinity = stdlib.Infinity;\n  var tan = stdlib.Math.tan;\n  var exp = stdlib.Math.exp;\n  var imul = stdlib.Math.imul;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 8388609.0;\n    (Float64ArrayView[2]) = (((-((+log(((((+abs((((0x76520efe) ? (0.001953125) : (18446744073709552000.0)))))) - ((Float64ArrayView[0])))))))) + (d1)));\n    d2 = (-1.2089258196146292e+24);\n    {\n      i0 = (0xf973411e);\n    }\n    {\n      {\n        i0 = ((d2) < (((d1)) % ((+atan2((((0xf8806f30) ? (-17179869185.0) : (NaN))), ((d2)))))));\n      }\n    }\n    d1 = (Infinity);\n    {\n      i0 = ((~~(+((Float32ArrayView[1])))) >= (((0xffffffff)*0xfffff) & ((i0))));\n    }\n    i0 = ((((0xb301d0a1)+(-0x8000000)) << ((i0)-(i0))) >= ((((((0xffffffff) % (0x84cf71eb))>>>(((0xfa4aa6c0) ? (0x414042f1) : (0x1a2e4a96))-((0xf7f0b904) == (0x0)))))-((+tan(((+exp(((d2))))))) < ((0x648c674e) ? (131073.0) : (-4611686018427388000.0)))) & ((0xc9e69da0)+(0xf34c0d5)-(0xffffffff))));\n    return (((imul((0xffffffff), (((this.__defineGetter__(\"x\", DataView.prototype.setInt16))) ? (0x528752d4) : (null.unwatch(\"toUpperCase\"))))|0) % (imul(((0x1cdafda3)), (0xf88dcfbc))|0)))|0;\n  }\n  return f; }), set: (function(j) { f2(j); }) });");
/*fuzzSeed-85495475*/count=81; tryItOut("\"use strict\"; for([a, w] = \n(\n14) in new DataView.prototype.getInt8((x++))) Array.prototype.forEach.call(a1, (function() { try { Array.prototype.splice.call(a2, -17, 3); } catch(e0) { } try { h1.getOwnPropertyDescriptor = f2; } catch(e1) { } try { o0 = {}; } catch(e2) { } this.m2 = this.o2.s0; return t0; }));");
/*fuzzSeed-85495475*/count=82; tryItOut("print(intern([[1]]));v0 = g2.runOffThreadScript();");
/*fuzzSeed-85495475*/count=83; tryItOut("\"use asm\"; Object.defineProperty(o2, \"v0\", { configurable: false, enumerable: (x % 68 != 5),  get: function() {  return a2.length; } });");
/*fuzzSeed-85495475*/count=84; tryItOut("v1 = Object.prototype.isPrototypeOf.call(s2, t0);");
/*fuzzSeed-85495475*/count=85; tryItOut("return;({window: Math.clz32(-8)});");
/*fuzzSeed-85495475*/count=86; tryItOut("\"use strict\"; v1 = (s0 instanceof b1);");
/*fuzzSeed-85495475*/count=87; tryItOut("selectforgc(this.o0);h1 + o1;");
/*fuzzSeed-85495475*/count=88; tryItOut("/*vLoop*/for (let ddzkqb = 0; ddzkqb < 8 && (b = x); ++ddzkqb) { b = ddzkqb; /*RXUB*/var r = /(\\s(?!\\2)|\\3|\\b|(?!(?=\\B{0,0}\\2)))/gim; var s = \"__\\u0016\\u0016\\u873e\\u873e\\u873e\\u873e\\u873e\\u873e\"; print(uneval(s.match(r)));  } ");
/*fuzzSeed-85495475*/count=89; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(( - mathy0(Math.fround(( + Math.fround(( + ( - ( + x)))))), mathy0(Number.MAX_VALUE, mathy1(2**53-2, (((( ! (y >>> 0)) >>> 0) >= y) | 0))))), ((Math.imul(((Math.imul((y >>> 0), (( + (( + ( + Math.tanh(Math.pow((Math.pow((x >>> 0), x) >>> 0), y)))) | ( + Math.imul(mathy0(x, x), Math.fround(Math.fround(( ~ Math.fround(y)))))))) >>> 0)) >>> 0) | 0), (( - ( ! Math.atan2(Math.fround(2**53), ( + Math.imul(Math.fround((Number.MIN_SAFE_INTEGER != x)), x))))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy4, [(new String('')), 0, (new Number(0)), (new Boolean(true)), null, [], ({valueOf:function(){return 0;}}), '0', objectEmulatingUndefined(), -0, '\\0', undefined, 1, /0/, (new Number(-0)), 0.1, '', ({toString:function(){return '0';}}), false, true, NaN, (function(){return 0;}), (new Boolean(false)), '/0/', ({valueOf:function(){return '0';}}), [0]]); ");
/*fuzzSeed-85495475*/count=90; tryItOut("mathy2 = (function(x, y) { return Math.max(Math.abs(Math.log10(y)), ( + Math.exp((( + (2**53+2 >>> 0)) | 0)))); }); ");
/*fuzzSeed-85495475*/count=91; tryItOut("a0.sort((function() { try { m2.set(b1, o0.v2); } catch(e0) { } try { o0.f1(e2); } catch(e1) { } try { v0 = a0.length; } catch(e2) { } t1.set(this.o0.a0, 15); return g1; }));");
/*fuzzSeed-85495475*/count=92; tryItOut("\"use strict\"; /*RXUB*/var r = (undefined)(); var s = \"\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-85495475*/count=93; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=94; tryItOut("\"use strict\"; testMathyFunction(mathy5, [2**53-2, 0x0ffffffff, 0x100000000, 1.7976931348623157e308, 0.000000000000001, -0x100000000, Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, -0x0ffffffff, 0x100000001, 0x07fffffff, -0x080000001, -(2**53), -0x080000000, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 42, 0/0, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 0, -0x100000001, -Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1]); ");
/*fuzzSeed-85495475*/count=95; tryItOut("mathy0 = (function(x, y) { return (( + Math.max(( ~ ( + (x | 0))), Math.round(Math.fround(Math.sign(Math.fround(Math.hypot(Math.fround(Math.log2(-(2**53+2))), Math.fround(y)))))))) ? ( + Math.fround(x)) : (Math.min((Math.asinh(Math.fround(Math.atanh((x ? x : x)))) | 0), ((y && y) >>> 0)) <= ( + Math.cosh(y)))); }); testMathyFunction(mathy0, [false, (new Boolean(false)), 0.1, -0, (new Number(0)), [0], (new Number(-0)), undefined, ({toString:function(){return '0';}}), null, [], 1, '/0/', '', ({valueOf:function(){return '0';}}), (new String('')), '\\0', (function(){return 0;}), /0/, 0, objectEmulatingUndefined(), '0', ({valueOf:function(){return 0;}}), (new Boolean(true)), NaN, true]); ");
/*fuzzSeed-85495475*/count=96; tryItOut("const y = window && x;let x = x;Array.prototype.shift.call(a2);");
/*fuzzSeed-85495475*/count=97; tryItOut("mathy1 = (function(x, y) { return mathy0(( + (Math.atanh(Math.cos(Math.fround(( + ( ! (x >>> 0)))))) >>> 0)), (Math.fround(Math.sqrt(Math.log10(( + y)))) | 0)); }); ");
/*fuzzSeed-85495475*/count=98; tryItOut("for(a = Date(delete z.y ** \"\\u6AAA\".toJSON()) in ((c = /*UUV1*/(z.cbrt = Date.prototype.toLocaleString)))) {for (var p in this.v0) { a0.shift(e1); }t2[2] =  '' ; }");
/*fuzzSeed-85495475*/count=99; tryItOut("\"use strict\"; /*bLoop*/for (var jmuosl = 0, {} =  \"\" ; jmuosl < 55; ++jmuosl) { if (jmuosl % 4 == 3) { m1 = g0.objectEmulatingUndefined(); } else { p2.__iterator__ = Promise.reject.bind(g2.o1.o2); }  } ");
/*fuzzSeed-85495475*/count=100; tryItOut("o0.v2 = false;");
/*fuzzSeed-85495475*/count=101; tryItOut("mathy4 = (function(x, y) { return ( - (Math.log2(Math.hypot((( + y) ** x), ( + (Math.atan2((( + ( + y)) >>> 0), (((y ^ y) >>> 0) >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -0x080000000, Math.PI, 1, 2**53, Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), 2**53+2, 42, -0x100000001, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000001, -0, Number.MAX_SAFE_INTEGER, -1/0, 0, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, 0x07fffffff, 0/0, 0x100000001, 0.000000000000001, -0x100000000, -(2**53), -0x0ffffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=102; tryItOut("\"use strict\"; r0 = /\\b|(?!;)/y;");
/*fuzzSeed-85495475*/count=103; tryItOut("mathy4 = (function(x, y) { return Math.cos(Math.imul(Math.atan2((mathy0(y, x) % (Math.atan2((y >>> 0), 0x080000000) , ((mathy3(Math.fround(y), (y | 0)) | 0) >= ( + (x | 0))))), (y ? x : Math.fround(Math.pow((y && y), x)))), ( + (( - Math.fround(( ~ (((( + ((x >>> 0) || ( + x))) | 0) ? (x | 0) : y) | 0)))) >>> 0)))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, -(2**53+2), -0x07fffffff, 0, 0/0, -(2**53-2), 0x080000001, 0.000000000000001, 0x0ffffffff, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, 1/0, 0x100000000, 42, -0, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, -0x100000000, -0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-85495475*/count=104; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.ceil(Math.fround(Math.atan2((( + (y | 0)) | 0), ( + Math.asinh(Math.log2(Math.fround((( ~ (y >>> 0)) >>> 0)))))))) % (Math.sign((((( ~ Math.fround(y)) == (y >>> 0)) / 0x07fffffff) > Math.fround(Math.atan2(( + Math.hypot(y, y)), y)))) >>> 0)); }); testMathyFunction(mathy0, [-(2**53), -0x080000001, -0, -(2**53+2), Number.MAX_VALUE, 2**53-2, -(2**53-2), 42, 2**53+2, Math.PI, 1.7976931348623157e308, -Number.MAX_VALUE, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 0/0, Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, 0.000000000000001, 0x100000000, -1/0, -Number.MIN_VALUE, 0x080000000, -0x100000001, 0x100000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=105; tryItOut("Array.prototype.shift.apply(a1, [m2]);function d() { return -28 } d = linkedList(d, 2809);");
/*fuzzSeed-85495475*/count=106; tryItOut(";");
/*fuzzSeed-85495475*/count=107; tryItOut("\"use strict\"; print((/*RXUE*/new RegExp(\"${524288,524289}|(?:\\\\2\\\\2{1,})\", \"i\").exec(\"\")));");
/*fuzzSeed-85495475*/count=108; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.acos(Math.fround(( ! ((( + ( - ( + x))) << ( + Math.imul(( + ( ~ ( + (y === (x | 0))))), (( ! ( ~ Math.atan2(x, y))) | 0)))) | 0)))); }); testMathyFunction(mathy2, [1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, 0, -(2**53-2), 0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, -1/0, 42, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -0, -0x080000000, -Number.MIN_VALUE, 2**53-2, 0x080000000, 0.000000000000001, 1, 0x100000000, Math.PI, 2**53+2, 2**53, -(2**53+2), 0x0ffffffff, -0x080000001, -Number.MAX_VALUE, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-85495475*/count=109; tryItOut("\"use strict\"; this.s2 = new String(this.h0);t0 + t2;");
/*fuzzSeed-85495475*/count=110; tryItOut("v2 = Object.prototype.isPrototypeOf.call(p2, t0);");
/*fuzzSeed-85495475*/count=111; tryItOut("\"use strict\"; v2 = a2.reduce, reduceRight((function() { try { this.h1 = {}; } catch(e0) { } try { Array.prototype.unshift.apply(a2, [t2, e2, i2, b1]); } catch(e1) { } h2.valueOf = (function() { try { a1.toSource = (function(j) { if (j) { /*RXUB*/var r = r2; var s = \"\\n\\n\\n \\n\\n\\u08f9\\u08f9\\u08f9\\u08f9\"; print(uneval(r.exec(s)));  } else { m0.delete(v1); } }); } catch(e0) { } try { Object.preventExtensions(h2); } catch(e1) { } try { o0 = {}; } catch(e2) { } Object.defineProperty(this, \"this.v0\", { configurable: true, enumerable: (x % 8 != 7),  get: function() { h2.hasOwn = f2; return Array.prototype.some.call(a0, (function mcc_() { var uoqlfx = 0; return function() { ++uoqlfx; if (false) { dumpln('hit!'); try { for (var v of this.s0) { try { Object.defineProperty(this, \"v0\", { configurable: 26, enumerable:  /x/g ,  get: function() {  return evaluate(\"\\u3056\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: [1], sourceIsLazy: [,,z1], catchTermination: false })); } }); } catch(e0) { } Array.prototype.reverse.call(a0); } } catch(e0) { } a1[v0] = e1; } else { dumpln('miss!'); try { a1.splice(NaN, 13); } catch(e0) { } try { b2 + o0.t0; } catch(e1) { } try { a1 = (x for (window of 8) for (x of []) if (x)); } catch(e2) { } v2 = evaluate(\"switch(28) { case 2: break; case 1: for (var v of t1) { try { /*RXUB*/var r = r0; var s = s2; print(s.split(r));  } catch(e0) { } try { o1.g2.offThreadCompileScript(\\\"/* no regression tests found */\\\", ({ global: this.o2.g2, fileName: null, lineNumber: 42, isRunOnce: new RegExp(\\\"(?=Q{2,6})\\\", \\\"\\\"), noScriptRval: (x % 73 == 32), sourceIsLazy: (x % 8 == 5), catchTermination: false })); } catch(e1) { } try { h0.iterate = f2; } catch(e2) { } h1.__iterator__ = f0; }break; break; default: g1.a1.push(this.g2);break;  }\", ({ global: g1.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 8 != 6), noScriptRval: (x % 5 != 4), sourceIsLazy: [], catchTermination: true })); } };})()); } }); return this.p1; }); return i1; }), a0, p0);");
/*fuzzSeed-85495475*/count=112; tryItOut("v2 = new Number(Infinity);\n(27);\n");
/*fuzzSeed-85495475*/count=113; tryItOut("let (x) { h2 + f2; }");
/*fuzzSeed-85495475*/count=114; tryItOut("tcodwl(({NEGATIVE_INFINITY: \"\\u2809\", \"-12\":  /x/g  }), x);/*hhh*/function tcodwl(b, y, ...NaN){print(x);}");
/*fuzzSeed-85495475*/count=115; tryItOut("/*infloop*/do {o1.v1 = Object.prototype.isPrototypeOf.call(m1, m2); } while(((function a_indexing(ryshwq, nwtsqc) { v2 = evalcx(\"try { (x); } catch(z if (delete window.a)) { with({}) false; } \", g0);; if (ryshwq.length == nwtsqc) { var v1 = a2.length;; return  \"\" ; } var lpawab = ryshwq[nwtsqc]; var zmnzmv = a_indexing(ryshwq, nwtsqc + 1); return ((/\\B|\\S?(?=(?!\\2))$((?!(?!\\cI*?)(?:\\b?|^)))/i * [z1,,]).watch(\"__iterator__\", encodeURI)); })(/*MARR*/[NaN, function(){}, NaN, (x(((void shapeOf(null)))) = 25), NaN, (x(((void shapeOf(null)))) = 25), (x(((void shapeOf(null)))) = 25), NaN, NaN, undefined, NaN, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, NaN, undefined, undefined, undefined, function(){}, function(){}, undefined, function(){}, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined], 0)));");
/*fuzzSeed-85495475*/count=116; tryItOut("\"use strict\"; neuter(b1, \"same-data\");");
/*fuzzSeed-85495475*/count=117; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((((( ~ ((((Math.fround(x) >>> x) | 0) > (Math.fround((Math.fround(y) ? ((Math.fround(x) ? ( + Number.MIN_VALUE) : (x | 0)) | 0) : Math.fround((Math.tanh((x | 0)) | 0)))) | 0)) | 0)) >>> 0) | 0) === Math.fround(( - Math.fround((((( + 0x0ffffffff) ^ (Math.imul(y, x) | 0)) ^ (Math.fround((((x + Math.expm1(-(2**53))) | 0) > (Math.exp(2**53) | 0))) | 0)) | 0))))) >>> 0); }); testMathyFunction(mathy2, [-(2**53+2), -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 0x080000001, -Number.MAX_VALUE, -0x080000000, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53), -0x07fffffff, -Number.MIN_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, 42, Number.MAX_VALUE, 2**53-2, -0x100000000, 0x100000001, 0, -0x080000001, 0/0, 2**53+2, Math.PI, 0x100000000, 1]); ");
/*fuzzSeed-85495475*/count=118; tryItOut("v2 = false;");
/*fuzzSeed-85495475*/count=119; tryItOut("var cdlarr = new ArrayBuffer(4); var cdlarr_0 = new Float64Array(cdlarr); print(cdlarr_0[0]); cdlarr_0[0] = 16; var cdlarr_1 = new Uint8ClampedArray(cdlarr); var cdlarr_2 = new Int32Array(cdlarr); print(cdlarr_2[0]); var cdlarr_3 = new Int8Array(cdlarr); cdlarr_3[0] = -14; var cdlarr_4 = new Uint8Array(cdlarr); print(cdlarr_4[0]); cdlarr_4[0] = 19; var cdlarr_5 = new Float64Array(cdlarr); print(cdlarr_5[0]); var cdlarr_6 = new Uint8Array(cdlarr); cdlarr_6[0] = -6; ( /x/g );cdlarr;a2 = []; '' ;v1 = evalcx(\"(void schedulegc(g0));\", g0);m0.delete(i2);o1 = e0.__proto__;let this.b0 = new ArrayBuffer(2);m0.has(p1);return \u000dMath;g0.g1.o1 = new Object;g2.i0.send(o1.e1);");
/*fuzzSeed-85495475*/count=120; tryItOut("var x;print( \"\" );");
/*fuzzSeed-85495475*/count=121; tryItOut("const x = (yield ((function sum_slicing(lgspif) { ; return lgspif.length == 0 ? 0 : lgspif[0] + sum_slicing(lgspif.slice(1)); })(/*MARR*/[]))), wfjynm, (((x << (x | 0)) | 0))( /x/ ) = (undefined.eval(\"/* no regression tests found */\").eval(\"(new (true)(null, w))\")), crinqa, a = new undefined(), window = (x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: /*wrap2*/(function(){ \"use strict\"; var bypbfp = set; var gluems = x.clear; return gluems;})(), delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: window, iterate: function() { throw 3; }, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })(x), function(q) { \"use strict\"; return q; }, q => q)), x, wdziay;v1 = this.g2.eval(\"for (var v of g0.i1) { try { a2 = arguments; } catch(e0) { } try { i2 + a1; } catch(e1) { } try { function f1(t1)  { yield a + c }  } catch(e2) { } /*MXX1*/o2 = g2.DataView.prototype.getFloat32; }\");");
/*fuzzSeed-85495475*/count=122; tryItOut("\"use strict\"; o1 = new Object;");
/*fuzzSeed-85495475*/count=123; tryItOut("var cwtgog = new ArrayBuffer(6); var cwtgog_0 = new Uint16Array(cwtgog); print(cwtgog_0[0]); cwtgog_0[0] = -16; var cwtgog_1 = new Int16Array(cwtgog); cwtgog_1[0] = 21; var cwtgog_2 = new Uint32Array(cwtgog); print(cwtgog_2[0]); cwtgog_2[0] = 28; function(y) { \"use strict\"; return  /x/g  }print(cwtgog);");
/*fuzzSeed-85495475*/count=124; tryItOut("e1.delete(o1.g2.g2.o0.e2);");
/*fuzzSeed-85495475*/count=125; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-85495475*/count=126; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.sign((Math.fround(( + Math.fround(( ~ y)))) !== mathy0(Math.sin((x ? y : (y >>> 0))), (Math.acos((((( + x) | 0) - x) | 0)) | 0))))); }); ");
/*fuzzSeed-85495475*/count=127; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.abs((((Math.min(Math.fround((( ~ x) >>> 0)), (((y ? Math.atanh(x) : ( + x)) >>> 0) <= ( ~ ( + x)))) | 0) ** ( + ( + ( ! (-Number.MAX_SAFE_INTEGER , Math.fround(Math.tan(Math.fround(-1/0)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [2**53+2, 0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, Math.PI, 1, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, Number.MIN_VALUE, 2**53-2, -0x100000001, -0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -(2**53-2), 0x100000000, -0x080000000, -Number.MAX_VALUE, 42, -0x100000000, 0, 0x07fffffff, 0.000000000000001, -0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, -1/0, -0, 2**53]); ");
/*fuzzSeed-85495475*/count=128; tryItOut("L:if(false) {var nxdjcc, wiqmqs;print(p1); }");
/*fuzzSeed-85495475*/count=129; tryItOut("for(var b in ({d:  '' })) a0 = Array.prototype.concat.call(o0.a1);");
/*fuzzSeed-85495475*/count=130; tryItOut("\"use strict\"; this.v1 = (g1 instanceof a0);");
/*fuzzSeed-85495475*/count=131; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log(( + Math.fround((( + (Math.log10((( - (y >>> 0)) >>> 0)) | 0)) ? ( + (Math.atanh((Math.hypot((x || Math.min(x, mathy1(x, ( + y)))), (x ^ (Math.atanh(x) >>> 0))) | 0)) | 0)) : ( + Math.atanh((((x >>> 0) * y) | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[0x07fffffff, new Boolean(false), new Boolean(false), -0xB504F332, 0x07fffffff, new Boolean(false), new Boolean(false), new Boolean(false), ({x:3}), new Boolean(false), new Boolean(false), null, new Boolean(false), new Boolean(false), -0xB504F332, ({x:3})]); ");
/*fuzzSeed-85495475*/count=132; tryItOut("t1 = t0.subarray(18);");
/*fuzzSeed-85495475*/count=133; tryItOut("for (var p in this.t1) { try { g2.offThreadCompileScript(\"/*UUV2*/(NaN.is = NaN.fontcolor)\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 2 == 1) })); } catch(e0) { } Array.prototype.unshift.call(a2, m2); }");
/*fuzzSeed-85495475*/count=134; tryItOut("\"use strict\"; with({y: \"\\uFE2C\"})/*tLoop*/for (let a of /*MARR*/[{x:3}, {x:3}, ({}), ({}), ({}), ({}), {x:3}, {x:3}, ({}), {x:3}, ({}), ({}), {x:3}, {x:3}, {x:3}, {x:3}, ({}), ({}), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, ({}), {x:3}, {x:3}, {x:3}, {x:3}, ({}), ({}), ({}), {x:3}, {x:3}, {x:3}, ({}), {x:3}, ({}), ({}), ({}), {x:3}, {x:3}, ({}), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, ({}), ({}), {x:3}, ({}), {x:3}, ({}), ({}), ({}), {x:3}, {x:3}, {x:3}, ({}), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}]) {  /x/g ; }");
/*fuzzSeed-85495475*/count=135; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(((( ! ( - (Math.min(((Math.atan2(((Math.fround(-(2**53+2)) | 0) >>> 0), (Math.hypot(-Number.MIN_SAFE_INTEGER, -0x07fffffff) >>> 0)) | 0) >>> 0), ( - (x | 0))) >>> 0))) | 0) == Math.fround(Math.hypot(( + ( + Math.imul(y, (x >>> 0)))), Math.log2((-(2**53-2) >>> 0)))))); }); testMathyFunction(mathy4, [-0x100000000, 0x080000001, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), Number.MAX_VALUE, -0, -(2**53+2), 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0, -1/0, 42, Number.MIN_VALUE, 1, -0x080000000, 0x080000000, 2**53-2, -Number.MIN_VALUE, 0.000000000000001, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, Math.PI, 0x100000001, 0x0ffffffff, 1.7976931348623157e308, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-85495475*/count=136; tryItOut("\"use strict\"; v2 = (this.h0 instanceof b2);");
/*fuzzSeed-85495475*/count=137; tryItOut("var v0 = t1.length;\na2 = [];\n");
/*fuzzSeed-85495475*/count=138; tryItOut("mathy0 = (function(x, y) { return (((Math.acos(0x100000000) !== (( ~ x) ? ( ~ x) : (y * 1))) <= ( ~ Math.sign(Math.cosh(Math.hypot(( + -(2**53)), y))))) == (Math.pow((( ! (y ? ( + x) : Math.fround(( + ((y | 0) <= x))))) >>> 0), ( + ((Math.hypot(( + Math.atan2(x, (Math.atanh((y | 0)) >>> 0))), ((( - Math.max(0x07fffffff, y)) >>> 0) !== Math.hypot(y, y))) || ( ! ( + Math.sin(x)))) >>> 0))) | 0)); }); ");
/*fuzzSeed-85495475*/count=139; tryItOut("\"use strict\"; a2.splice(NaN, 4, a2);");
/*fuzzSeed-85495475*/count=140; tryItOut("\"use strict\"; /*RXUB*/var r = /((>{2,5}\\B{0,}|\uf22d+\\D{0,2}\\d))|[^\\v-\\uFB38\u494e-\u7711\\\u9965-\\uB11e\\x9E-\u7514]|./; var s = \">>11a11a11a11a11a 1\\u000d1a\"; print(s.split(r)); ");
/*fuzzSeed-85495475*/count=141; tryItOut("testMathyFunction(mathy3, ['0', 0.1, 1, null, ({valueOf:function(){return 0;}}), (new Boolean(true)), objectEmulatingUndefined(), false, [0], '/0/', -0, undefined, (function(){return 0;}), (new Number(0)), (new String('')), 0, true, [], (new Boolean(false)), (new Number(-0)), /0/, ({toString:function(){return '0';}}), '\\0', NaN, ({valueOf:function(){return '0';}}), '']); ");
/*fuzzSeed-85495475*/count=142; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[[, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce), [, {z: []}, ] = /*UUV2*/(x.toString = x.reduce)]); ");
/*fuzzSeed-85495475*/count=143; tryItOut("L: /*hhh*/function slvcef(...x){v1 = Object.prototype.isPrototypeOf.call(h0, p0);}slvcef(Math.cbrt(x));");
/*fuzzSeed-85495475*/count=144; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.sinh((Math.imul(Math.fround((Math.fround(Math.atan2(mathy0((Math.min((x >>> 0), (y >>> 0)) >>> 0), x), -0x080000000)) ^ Math.fround(Math.abs(((( + Math.atan2(0.000000000000001, Math.fround(y))) , (1 >>> 0)) >>> 0))))), ( ~ (((x >>> 0) == (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))) | 0)) === Math.fround((Math.fround((Math.fround((( + (( + (((y >>> 0) ^ Math.sinh(y)) >>> 0)) + ( + x))) << Math.fround(x))) !== ( - -0x080000001))) <= ( + (Math.min(-(2**53-2), (x | 0)) | 0))))); }); ");
/*fuzzSeed-85495475*/count=145; tryItOut("mathy1 = (function(x, y) { return Math.imul(Math.fround(Math.exp(Math.fround(Math.min(Math.fround(mathy0(( + Math.asin(( + y))), x)), Math.fround(x))))), Math.exp(Math.fround(Math.expm1(Math.fround(mathy0((( + (y % x)) ^ x), ( ! (x >>> 0)))))))); }); testMathyFunction(mathy1, [-0, 2**53, -0x080000001, 0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, -(2**53+2), 0, 0x07fffffff, -(2**53-2), -0x100000000, 0x080000001, 42, 0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, 1/0, Number.MIN_VALUE, -(2**53), -0x100000001, -0x07fffffff, 0/0, Math.PI, 1, 0x100000001]); ");
/*fuzzSeed-85495475*/count=146; tryItOut("this.a1.forEach(this.f2, this.b1);");
/*fuzzSeed-85495475*/count=147; tryItOut("\"use strict\"; this.a1.unshift(f0, f0, o0.g2.s0, f0);");
/*fuzzSeed-85495475*/count=148; tryItOut("t0.set(a0, 11);");
/*fuzzSeed-85495475*/count=149; tryItOut("\"use asm\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((-513.0));\n  }\n  return f; })(this, {ff: e =>  { return ([] = []) } }, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0.000000000000001, 0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 0x100000001, 2**53, -0x07fffffff, 0/0, 0x080000001, 0, Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 1, -0x080000000, Math.PI, 42, 0x0ffffffff, -(2**53+2), -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -0x0ffffffff, -0, -(2**53-2), -(2**53), 2**53-2, 1/0, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=150; tryItOut("v2 = Array.prototype.every.call(a1, (function() { try { selectforgc(o1); } catch(e0) { } try { v1 = this.a1.every((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = a1 % a0; var r1 = 9 % a3; var r2 = 2 | a7; r2 = 5 + a1; var r3 = a6 + x; a2 = 4 * a10; var r4 = a0 ^ 8; var r5 = a8 - a1; var r6 = r1 + a7; var r7 = r0 * a5; var r8 = 8 ^ a4; var r9 = r2 | a9; print(r0); a4 = 2 ^ 2; a1 = a12 * r9; var r10 = r8 | a5; var r11 = a9 % a10; var r12 = 7 + r10; var r13 = 4 ^ a1; var r14 = 1 ^ a4; a9 = 9 / a4; var r15 = a6 / r7; r3 = r15 & r1; r7 = a7 - r9; var r16 = 6 / r14; var r17 = 6 % 5; var r18 = a2 & 5; var r19 = r9 & 7; r9 = r9 | r3; r17 = a10 - r2; var r20 = a12 - 3; print(r15); return x; }), b2); } catch(e1) { } o0.v1 = (this.g0.g2 instanceof this.g2); return this.b0; }));");
/*fuzzSeed-85495475*/count=151; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.atan2((Math.pow(Math.imul(Math.max(y, Math.log1p(Math.PI)), ((0x080000001 % y) ? Math.fround(Math.sin(y)) : ( + Math.max((0x100000000 | 0), (x | 0))))), (( + ( + (Math.sqrt(( + ( - y))) | 0))) | 0)) >>> 0), (Math.acos(Math.atan2(( + (Math.fround((Math.hypot((-Number.MIN_SAFE_INTEGER | 0), (-(2**53) | 0)) | 0)) - Math.fround(Math.imul(y, 0x100000000)))), x)) >>> 0)); }); testMathyFunction(mathy5, [0/0, -0x100000001, 0x07fffffff, 0, -0, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -0x100000000, 42, 0x080000001, -(2**53), -Number.MIN_VALUE, 2**53-2, 2**53+2, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, 1.7976931348623157e308, 1/0, 1, -0x080000001, -0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-85495475*/count=152; tryItOut("h0.fix = (function mcc_() { var zheett = 0; return function() { ++zheett; if (/*ICCD*/zheett % 6 == 5) { dumpln('hit!'); try { h2 = x; } catch(e0) { } try { a1 = Proxy.create(h1, this.i0); } catch(e1) { } h1 + ''; } else { dumpln('miss!'); try { a2 = arguments.callee.caller.caller.arguments;\nundefined;\n } catch(e0) { } try { x = g2; } catch(e1) { } v2[\"tanh\"] = this.o2; } };})();");
/*fuzzSeed-85495475*/count=153; tryItOut("\"use strict\"; h1.set = this.f2;\n/*RXUB*/var r = /(?=(?!([^]))|(?=$[\\s\u712d]|\ubbd7[^]\\B{0,4}|(?!\\w)+?|(?!\ua4b6|.{0,3})|$|${3}[^\\u00cC-\ue953]|([\\D\\u00cF-\\xD3])(?!\\3){0}))/; var s = \"\"; print(r.test(s)); \n");
/*fuzzSeed-85495475*/count=154; tryItOut("\"use strict\"; for (var p in s0) { try { g1.t1 + s0; } catch(e0) { } try { (({e: /(?!.|(^)\\d{1,}|(.|.*?|.)){4,}/y})); } catch(e1) { } ; }");
/*fuzzSeed-85495475*/count=155; tryItOut("\"use strict\"; let (yszmsy, z, c = (p={}, (p.z = x)()), ltysth, x = allocationMarker(), enpfwn, /((.|(\\W))){2}/m) { h2.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42) { var r0 = 9 % a25; var r1 = a1 | a12; var r2 = 4 * a17; var r3 = a39 ^ a41; var r4 = a33 - r0; var r5 = a5 - a39; var r6 = 7 ^ a8; var r7 = 2 * a7; r0 = r4 | a19; a15 = a27 / x; var r8 = a10 * 3; r2 = 6 | a18; var r9 = r7 % 2; var r10 = a18 & a3; r3 = 6 % a36; var r11 = a35 / a40; var r12 = a31 / x; a18 = a4 | 9; var r13 = a11 % a31; print(r11); print(a41); var r14 = a8 / 2; var r15 = a8 ^ a22; var r16 = r3 ^ a41; var r17 = 7 % a20; var r18 = 1 - a3; print(a28); var r19 = a0 ^ 4; var r20 = a3 * a23; var r21 = r6 ^ 7; var r22 = 9 ^ 2; var r23 = r14 / a0; var r24 = a42 * 5; var r25 = a41 | r1; var r26 = r13 % a10; a37 = a8 * a24; print(a28); r9 = a5 % a38; print(a12); var r27 = a0 / a32; var r28 = a18 - r15; print(a32); var r29 = 4 * r28; var r30 = a0 * a5; a29 = r17 | a38; a41 = 0 - 3; var r31 = r2 * 6; var r32 = a32 % a28; var r33 = a31 % a32; r13 = a30 ^ a14; a32 = 1 + r26; var r34 = a1 + a38; var r35 = r18 / r30; a7 = 4 % 6; print(a40); var r36 = 0 % a11; print(r19); var r37 = 3 | a18; a41 = a33 & a20; var r38 = a8 | r6; print(a10); var r39 = r14 % 4; a12 = a6 % r39; var r40 = a1 / a11; a23 = r23 / r6; var r41 = 7 | r29; var r42 = a3 % a20; var r43 = a10 - a25; var r44 = r14 ^ a20; var r45 = a37 ^ 5; r8 = r11 - 9; var r46 = a37 / a18; var r47 = 4 ^ r20; r23 = 8 | r24; var r48 = a13 | r41; var r49 = a24 - a38; var r50 = r32 | a13; var r51 = r29 % a25; var r52 = r27 + 3; var r53 = a38 + 9; var r54 = r22 - 2; var r55 = r48 ^ r51; print(r50); var r56 = a14 / 1; a24 = r46 - 8; var r57 = r34 / r35; var r58 = a42 * 5; print(r28); r35 = r22 * r17; a3 = a15 | r24; var r59 = r44 * a17; var r60 = 2 | r35; a13 = a38 & a38; r35 = 1 ^ r4; r60 = 0 ^ a2; return a34; }); }");
/*fuzzSeed-85495475*/count=156; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -4.835703278458517e+24;\n    switch ((0x678a5e4c)) {\n      case -1:\n        d2 = (33.0);\n      case -2:\n        i1 = (/*FFI*/ff(((9007199254740992.0)), ((0x556874d7)))|0);\n        break;\n      case 0:\n        {\n          i1 = ((((i1) ? (!((0xdda3a74a))) : (((-0xca4e4*(i0))) >= (((i1))>>>((0x1560bfb3)+(0x7a7d3da4)))))-(i1)+(-0x8000000)));\n        }\n        break;\n      case 1:\n        i0 = (0x51f86e43);\n        break;\n      case 0:\n        return +((Float64ArrayView[((i0)+(i1)) >> 3]));\n        break;\n      case -3:\n        {\n          {\n            return +((-137438953473.0));\n          }\n        }\n        break;\n      case -3:\n        d2 = ((((((0x90344390))+(i1)+((abs((0x2dc6644f))|0))) | ((i1)+(i0)-((0.0009765625) >= (-7.555786372591432e+22)))) < ((((/*FFI*/ff(((((0xbd6f8ea5)) >> ((0xef1de0bc)))))|0)) ^ ((0x76b64958)-((0xdf089b22) ? (0xe6f11aa6) : (0xa275dc69))-((-6.044629098073146e+23) == (1.2089258196146292e+24)))))) ? (1.015625) : (+floor(((Float64ArrayView[0])))));\n        break;\n    }\n    d2 = (-((67108864.0)));\n    i1 = (/*FFI*/ff()|0);\n    {\n      d2 = (131073.0);\n    }\n    return +((/(?:\\1){3}/yim ^ eval));\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return Math.log2(( ~ x)); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0.1, [0], '\\0', 0, objectEmulatingUndefined(), '/0/', ({toString:function(){return '0';}}), (new Number(0)), undefined, /0/, false, 1, ({valueOf:function(){return '0';}}), (new Number(-0)), [], (function(){return 0;}), NaN, (new Boolean(false)), -0, (new String('')), (new Boolean(true)), '0', ({valueOf:function(){return 0;}}), true, '', null]); ");
/*fuzzSeed-85495475*/count=157; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! (mathy2((y | Math.fround(Math.log(y))), Math.fround((mathy0((y >>> 0), (Math.fround((Math.fround(Math.min((( + Math.min(y, x)) >>> 0), x)) >= Math.fround(x))) >>> 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -0x080000000, 0x100000001, -0x07fffffff, -(2**53), 1, 0, 0x0ffffffff, 2**53-2, -Number.MIN_VALUE, -(2**53-2), 42, Number.MAX_VALUE, -0x080000001, -0x100000001, -0x0ffffffff, 0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Math.PI, 0/0, -0, -1/0, -0x100000000, 2**53, 1/0, 0.000000000000001, -Number.MAX_VALUE, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000]); ");
/*fuzzSeed-85495475*/count=158; tryItOut("mathy0 = (function(x, y) { return ( - ( + (((( ~ ( - Math.fround(x))) - ((Math.imul((y >>> 0), (( ! (Math.imul((x >>> 0), (x >>> 0)) >>> 0)) >>> 0)) | 0) >> -0x080000000)) >>> 0) << Math.max(Math.fround(Math.imul(Math.fround(( + Math.fround(y))), x)), (Math.sqrt(y) !== ( ~ Math.pow(y, y))))))); }); testMathyFunction(mathy0, [-0x07fffffff, 0x100000000, 42, 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), Math.PI, 0x080000001, 0x100000001, -(2**53+2), 0x080000000, -0x080000001, -0, -Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, -1/0, 1, 1/0, -Number.MAX_VALUE, -(2**53), 0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, -0x100000000, 0, -0x080000000]); ");
/*fuzzSeed-85495475*/count=159; tryItOut("");
/*fuzzSeed-85495475*/count=160; tryItOut("v0 = r1.constructor;");
/*fuzzSeed-85495475*/count=161; tryItOut("mathy2 = (function(x, y) { return Math.exp(Math.sign((Math.acosh((((Math.min(Number.MIN_VALUE, ( + y)) >>> 0) === mathy1(x, y)) , (Math.hypot(x, Math.cos(x)) >>> 0))) >>> 0))); }); testMathyFunction(mathy2, [2**53+2, 1.7976931348623157e308, -0x07fffffff, 2**53-2, 1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0x100000001, 42, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 0.000000000000001, Number.MAX_VALUE, -(2**53+2), 0, 0/0, 0x080000000, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, 1, 2**53, -0x080000000, -(2**53), 0x080000001, -Number.MIN_VALUE, Math.PI, -1/0, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=162; tryItOut("v2 = Object.prototype.isPrototypeOf.call(e1, p0);");
/*fuzzSeed-85495475*/count=163; tryItOut("print(x);");
/*fuzzSeed-85495475*/count=164; tryItOut("/*MXX2*/g0.ReferenceError.prototype.toString = h1;");
/*fuzzSeed-85495475*/count=165; tryItOut("/*MXX3*/g2.Object.create = g2.Object.create;");
/*fuzzSeed-85495475*/count=166; tryItOut("s1 = new String(s0);");
/*fuzzSeed-85495475*/count=167; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 3.022314549036573e+23;\n    {\n      {\n        return ((((((x))>>>((i1))))-(0xffffffff)-(0x547009d9)))|0;\n      }\n    }\n    d0 = (+pow(((144115188075855870.0)), ((d0))));\n    return (((0x83afd766)-(0xfdd808d8)+(/*FFI*/ff()|0)))|0;\n  }\n  return f; })(this, {ff: function  x (b, ...window)\"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = ((Infinity) + (d1));\n    switch ((((b = x)-(0xf1c58ccb)) << ((0xf2d9ee5d)))) {\n      case 1:\n        d1 = (((d1)) * ((Float64ArrayView[0])));\n        break;\n      case 1:\n        d1 = (d1);\n        break;\n    }\n    {\n      (Float32ArrayView[((((((0xe434c3e4)) | ((0xffffffff)))) ? (-0x8000000) : (1))) >> 2]) = ((+(-1.0/0.0)));\n    }\n    d0 = (d0);\n    d1 = (d0);\n    d0 = (d0);\n    return (((0xfa5562d7)-((0x73d58d4d))))|0;\n    {\n      {\n        d1 = ((this)(new RegExp(\".|\\\\xa1|[^]{1,3}|^*{1,4}\", \"gyim\")));\n      }\n    }\n    d1 = (NaN);\n    d0 = (d1);\n    {\n      d1 = (1.0);\n    }\n    {\n      (Int32ArrayView[(0xf51cc*(0xffffffff)) >> 2]) = ((0xfa8e8a8f));\n    }\n    return ((-((0x798194cb))))|0;\n  }\n  return f;}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x100000000, Math.PI, Number.MIN_VALUE, 42, 0x100000001, -Number.MAX_VALUE, -1/0, 0x080000000, -0, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, 1, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 0/0, -0x100000000, 1.7976931348623157e308, 2**53+2, 0, 0x0ffffffff, -(2**53), 2**53-2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 2**53, 1/0]); ");
/*fuzzSeed-85495475*/count=168; tryItOut("mathy0 = (function(x, y) { return ( + ( ! ( + ((( ! (Math.ceil((x ? ((y | 0) ? 2**53+2 : x) : x)) >>> 0)) | 0) - ( + ( ~ ( + Math.hypot((Math.log1p(1/0) >>> 0), Math.fround(( ~ Math.fround(x))))))))))); }); testMathyFunction(mathy0, /*MARR*/[ 'A' , 1.7976931348623157e308, 1.7976931348623157e308,  \"\" ,  'A' , (4277) >> (4277), 1.7976931348623157e308,  'A' , (4277) >> (4277),  \"\" , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, (4277) >> (4277),  \"\" ,  \"\" ]); ");
/*fuzzSeed-85495475*/count=169; tryItOut("a0 = a1.map((function() { try { v1 = Object.prototype.isPrototypeOf.call(m1, g1.t2); } catch(e0) { } a1.reverse(); return this.h2; }));");
/*fuzzSeed-85495475*/count=170; tryItOut("/*hhh*/function pkjuom(\u3056){Array.prototype.push.apply(a2, [this.e2, this.s2, g2]);}pkjuom();");
/*fuzzSeed-85495475*/count=171; tryItOut("\"use strict\"; this.v0 = (g0 instanceof i0);");
/*fuzzSeed-85495475*/count=172; tryItOut("{ void 0; deterministicgc(false); } return x;");
/*fuzzSeed-85495475*/count=173; tryItOut("\"use asm\"; M:if((x % 5 != 1)) { if (x) return;} else {print(x);o0 = Object.create(/(?=$|[^]|\\x09{1,512}(?:(?!^)))[^]?/yim); }");
/*fuzzSeed-85495475*/count=174; tryItOut("g0 + '';");
/*fuzzSeed-85495475*/count=175; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.hypot((Math.fround(Math.atan2(( + Math.fround(mathy0((y | 0), (( - Math.fround(( - Math.fround(y)))) | 0)))), Math.fround(Math.log1p(( + (( + Math.atan2((-0x080000000 >>> 0), Math.atan2((-1/0 >>> 0), (y >>> 0)))) * ( + Math.cbrt(( + ( + Math.acosh(( + x)))))))))))) >>> 0), ((Math.log10(Math.asin(x)) ? Math.fround((Math.fround(2**53) >= Math.fround((y % ( ! ( + x)))))) : ((( - ((Math.atan2((x | 0), (-1/0 | 0)) | 0) >>> 0)) ** x) ** ( ! mathy1(x, x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0x080000001, -0, 1/0, 0x100000000, -0x100000001, 1.7976931348623157e308, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, 0x100000001, 0x0ffffffff, 0/0, 0, 42, 2**53, Number.MAX_VALUE, -0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 0.000000000000001, Math.PI, -Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 2**53+2, -1/0, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=176; tryItOut("Object.defineProperty(this, \"h1\", { configurable: (x % 2 != 1), enumerable: (x % 5 == 0),  get: function() {  return ({getOwnPropertyDescriptor: function(name) { m1.set(this.h2, a2);; var desc = Object.getOwnPropertyDescriptor(g0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g1.b2 = Proxy.create(h0, b0);; var desc = Object.getPropertyDescriptor(g0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { selectforgc(o0);; Object.defineProperty(g0, name, desc); }, getOwnPropertyNames: function() { p2 = t0[5];; return Object.getOwnPropertyNames(g0); }, delete: function(name) { for (var p in e1) { try { this.v0 = Object.prototype.isPrototypeOf.call(g1.e1, i1); } catch(e0) { } try { Array.prototype.pop.call(a1, /(?!(?!(?=\\2)|(\\b){0,}))/i !=  /x/ , p0, this.h2, i1); } catch(e1) { } try { s0 += 'x'; } catch(e2) { } Array.prototype.sort.call(a0, (function mcc_() { var jalhtg = 0; return function() { ++jalhtg; if (/*ICCD*/jalhtg % 11 == 0) { dumpln('hit!'); try { h1.fix = f2; } catch(e0) { } /*MXX2*/g2.Int16Array.prototype.BYTES_PER_ELEMENT = i2; } else { dumpln('miss!'); print(v1); } };})(), (4277), e2, s2, ([this] ? window -= true : new  \"\" ()), (uneval(delete+={})), b1, this.a2, a1); }; return delete g0[name]; }, fix: function() { s2 = new String(h2);; if (Object.isFrozen(g0)) { return Object.getOwnProperties(g0); } }, has: function(name) { v1 = t0.length;; return name in g0; }, hasOwn: function(name) { e0.add(this.h2);; return Object.prototype.hasOwnProperty.call(g0, name); }, get: function(receiver, name) { print(uneval(f2));; return g0[name]; }, set: function(receiver, name, val) { this.o2.g0.v0 = t0.length;; g0[name] = val; return true; }, iterate: function() { Object.defineProperty(this, \"this.t1\", { configurable: (x % 2 == 1), enumerable: true,  get: function() { m0.delete(g2.b2); return new Uint32Array(o0.v0); } });; return (function() { for (var name in g0) { yield name; } })(); }, enumerate: function() { throw m1; var result = []; for (var name in g0) { result.push(name); }; return result; }, keys: function() { t0 = new Int32Array(t2);; return Object.keys(g0); } }); } });");
/*fuzzSeed-85495475*/count=177; tryItOut("{ void 0; gcslice(5062); }");
/*fuzzSeed-85495475*/count=178; tryItOut("testMathyFunction(mathy4, [2**53-2, -(2**53+2), -0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 42, -0x07fffffff, 2**53, -(2**53-2), -1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, -0, -Number.MIN_VALUE, -0x080000000, 0x100000001, 0x080000001, 0x080000000, 1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, 1, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), 0, 0/0, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=179; tryItOut("testMathyFunction(mathy0, /*MARR*/[new Boolean(false), (-1/0), undefined, (-1/0), -Infinity, new Boolean(false), undefined, new Boolean(false), -Infinity, (-1/0), undefined, -Infinity, (-1/0), new Boolean(false), -Infinity, -Infinity, (-1/0), new Boolean(false), new Boolean(false), -Infinity, -Infinity, new Boolean(false), (-1/0), new Boolean(false), new Boolean(false), undefined, (-1/0), -Infinity, (-1/0), new Boolean(false), undefined, (-1/0), undefined, (-1/0), undefined, undefined, (-1/0), new Boolean(false), -Infinity, undefined, -Infinity, (-1/0), (-1/0), new Boolean(false), new Boolean(false), undefined, -Infinity, undefined, undefined, undefined, (-1/0), new Boolean(false), undefined, new Boolean(false), undefined, (-1/0), -Infinity, undefined, (-1/0), -Infinity, new Boolean(false), (-1/0), -Infinity, (-1/0), undefined, new Boolean(false), (-1/0), new Boolean(false), new Boolean(false), (-1/0), (-1/0), undefined, undefined, -Infinity, undefined, (-1/0), new Boolean(false), (-1/0), -Infinity, undefined, -Infinity, new Boolean(false), new Boolean(false), new Boolean(false), -Infinity, undefined, undefined, new Boolean(false), (-1/0), (-1/0)]); ");
/*fuzzSeed-85495475*/count=180; tryItOut("v0 = g2.g2.runOffThreadScript();");
/*fuzzSeed-85495475*/count=181; tryItOut("o2 = new Object;");
/*fuzzSeed-85495475*/count=182; tryItOut("this.r0 = /((?!(?![^]\\w{1,})))(?:(?:(?=\\b)))(?:.|.|\\b\\b|$|(?=$))/m;");
/*fuzzSeed-85495475*/count=183; tryItOut("print(x);");
/*fuzzSeed-85495475*/count=184; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"\\\\2[^]{0}\", \"y\"); var s = \"\\u652A\"; print(r.exec(s)); ");
/*fuzzSeed-85495475*/count=185; tryItOut("\"use strict\"; /*hhh*/function smzyci(){print(x);\u0009}\u000csmzyci(--eval, (/*FARR*/[, typeof (4277), (WebAssemblyMemoryMode( '' )), (this) = new RegExp(\"$(?=\\\\1{2,})*{2,3}\", \"yim\"), c, (({NaN: (4277)})), /*FARR*/[\"\\u16EB\"].map, Math.log1p(/[^]/yim)].some(null, new Set((Math.atan2( /x/ , -24))))));");
/*fuzzSeed-85495475*/count=186; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (Math.imul(( + (x ** (( ~ ( ~ Math.imul(x, x))) | 0))), ( + (Math.fround((( ! x) | 0)) == y))) | 0)); }); testMathyFunction(mathy0, [0, 0/0, 42, Number.MIN_VALUE, -(2**53-2), 0x080000000, 0x100000000, -(2**53), -(2**53+2), -0x0ffffffff, 1, 0x07fffffff, 0x100000001, 2**53+2, 1/0, Math.PI, -0x100000001, 0.000000000000001, 0x0ffffffff, -0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, 2**53, -0, 1.7976931348623157e308, 2**53-2, -1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=187; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(mathy2(Math.tanh(Math.cbrt(x)), (Math.atan2(Math.fround(Math.hypot(((0x0ffffffff >>> ( + (-0x100000000 || ( + -0x080000000)))) ? (((-(2**53) | 0) ? (y | 0) : 2**53) | 0) : ( + Math.min(y, Math.trunc(Number.MAX_SAFE_INTEGER)))), (((y >>> 0) & Math.sin((x >>> 0))) >>> 0))), Math.hypot(Math.log10(( + 0/0)), (y , y))) | 0)), Math.fround((Math.fround(( + Math.pow(y, Math.asin((y >>> 0))))) ^ Math.fround((( + ( - ( + ( + ( - (y >>> 0)))))) | (Math.log10(((( ~ (y >>> 0)) >>> 0) | 0)) | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[(0/0),  \"use strict\" , (0/0),  \"use strict\" , (0/0), 0x0ffffffff, eval, (0/0), eval, (0/0), eval, 0x0ffffffff, 0x0ffffffff, eval, 0x0ffffffff,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (0/0), eval, (0/0), 0x0ffffffff, (0/0), (0/0), (0/0), 0x0ffffffff,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , eval, (0/0), (0/0), (0/0),  \"use strict\" , eval, 0x0ffffffff,  \"use strict\" , (0/0),  \"use strict\" , (0/0), (0/0), eval, (0/0), eval, eval,  \"use strict\" , (0/0), eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, (0/0),  \"use strict\" , (0/0),  \"use strict\" , 0x0ffffffff, 0x0ffffffff, (0/0), (0/0), 0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=188; tryItOut("\"use strict\"; g2.v2 = r0.exec;");
/*fuzzSeed-85495475*/count=189; tryItOut("a0.shift(s2, g1);");
/*fuzzSeed-85495475*/count=190; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, 42, -0x100000001, 0x0ffffffff, -(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53), 0x080000001, -0x080000000, -0x100000000, 2**53, Number.MAX_VALUE, 1/0, -0x080000001, -Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, -0x0ffffffff, 0/0, 0x07fffffff, Number.MIN_VALUE, 0x100000000, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, 2**53-2, 1.7976931348623157e308, 1, -1/0]); ");
/*fuzzSeed-85495475*/count=191; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      (Float64ArrayView[2]) = ((d0));\n    }\n    (Int32ArrayView[(((((i1)) & (((1.2089258196146292e+24) >= (1.2089258196146292e+24))-(i1)-(0xffffffff))))) >> 2]) = ((/*FFI*/ff(((Uint32ArrayView[((0x8b3d095e)) >> 2])), ((+(((/*RXUE*/new RegExp(\"(\\\\2){3,}\", \"ym\").exec(\"\\n_____\")))))), ((d0)), ((2097153.0)), ((+((Uint32ArrayView[((0x92e13420)) >> 2])))), ((268435457.0)), ((((0xca8cd76a)) | ((0xd4c31a01)))), ((-562949953421313.0)), ((144115188075855870.0)), ((-134217729.0)), ((3.094850098213451e+26)), ((17179869185.0)), ((-73786976294838210000.0)))|0)+((0x9c26109e) != ((((((0xd0b67255))>>>((0xedd263f1))) <= (((0x87f65129))>>>((0xa9bce4a2))))+(i1))>>>((i1)-((imul((0xcb6f666c), (0x630b6271))|0) > (imul((0x5d3df651), (0x14c30d77))|0)))))-(i1));\n    (Float32ArrayView[2]) = ((Float32ArrayView[(((d0) > (35184372088832.0))+(i1)) >> 2]));\n    {\n      d0 = (Infinity);\n    }\n    d0 = (7.737125245533627e+25);\n    return +((((-3.8685626227668134e+25)) - ((((((0xa87db374)-(0xfa988bdd))>>>((/*RXUE*//\u51aa+?|\\b*\\cS?/gym.exec(\"\\u0013\")))) > (((4277))>>>((Uint8ArrayView[4096])))) ? (+(0.0/0.0)) : (NaN)))));\n  }\n  return f; })(this, {ff: Number.prototype.valueOf}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[(-0), new Number(1), [1], false, null, (-0), null, (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), [1], new Number(1), [1], (-0), null, (-0), false, [1], [1], [1], (-0), new Number(1)]); ");
/*fuzzSeed-85495475*/count=192; tryItOut("let (w) { \u000ds1 += s1;print(x); }");
/*fuzzSeed-85495475*/count=193; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.max(mathy3(Math.fround(( - ( + mathy0(( - y), (y >>> 0))))), Math.tanh(y)), (( + Math.fround(mathy3(mathy2(( - x), mathy1((mathy1(y, y) >>> 0), y)), (Math.fround((Math.max((Math.fround(Math.pow(( + mathy2(x, y)), 0x07fffffff)) >>> 0), (x >>> 0)) >>> 0)) !== Math.fround(Number.MAX_SAFE_INTEGER))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-85495475*/count=194; tryItOut("throw [,,z1];print(x);");
/*fuzzSeed-85495475*/count=195; tryItOut("\"use strict\"; /*vLoop*/for (fopqwd = 0; (x === w) && fopqwd < 66; ++fopqwd) { const b = fopqwd; break ; } ");
/*fuzzSeed-85495475*/count=196; tryItOut("if(true) { if (({}) = yield (4277)) o1.m0.has(m2);} else t0[16] = this.t2;");
/*fuzzSeed-85495475*/count=197; tryItOut("\"use strict\"; e0 = new Set(p2);");
/*fuzzSeed-85495475*/count=198; tryItOut("let(a) { let(xxwxud, x, NaN, eval) ((function(){let(b, \u3056, a, b = /((\\v$)|\\1*\\u009A$*)+?/gyim, x, x, qjfxsl, eval, a, uncfnp) ((function(){for(let y in /*PTHR*/(function() { \"use strict\"; for (var i of timeout(1800)) { yield i; } })()) for(let a in /*FARR*/[true.prototype, (makeFinalizeObserver('nursery'))]) yield (void options('strict'));})());})());}for(let e of /*MARR*/[new Boolean(false), -Infinity, new String(''), new String(''), -Infinity, -Infinity, new Boolean(false), new String(''), new String(''), new Boolean(false), -Infinity, -Infinity, new String(''), new String(''), new String(''), -Infinity, new Boolean(false), new String(''), -Infinity, new String(''), -Infinity, new String(''), -Infinity, -Infinity, -Infinity, new String(''), -Infinity, new String(''), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Boolean(false), new Boolean(false), new String(''), new String(''), -Infinity, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Boolean(false), new String(''), new Boolean(false), new Boolean(false), new String(''), -Infinity, -Infinity, new String(''), new String(''), new Boolean(false), new Boolean(false), -Infinity, new String(''), new Boolean(false), -Infinity, new String(''), new Boolean(false), new String(''), new Boolean(false), new Boolean(false), new String(''), new String(''), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new String(''), new Boolean(false), -Infinity, new Boolean(false), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new String(''), new Boolean(false), new Boolean(false), new String(''), -Infinity, new String(''), -Infinity, -Infinity, -Infinity, new Boolean(false), new String(''), new String(''), -Infinity, new Boolean(false), new Boolean(false), new String('')]) this.zzz.zzz;");
/*fuzzSeed-85495475*/count=199; tryItOut("v0 = evalcx(\"function f2(p0)  { \\\"use strict\\\"; \\u0009yield \\\"\\\\u1B9F\\\" } \", g2);");
/*fuzzSeed-85495475*/count=200; tryItOut("v1 = g2.eval(\"a2.reverse((makeFinalizeObserver('tenured')));\");");
/*fuzzSeed-85495475*/count=201; tryItOut("\"use strict\"; Array.prototype.pop.apply(a0, [this.g2, e1, o0, g0.b2]);");
/*fuzzSeed-85495475*/count=202; tryItOut("for (var p in h0) { try { a2.unshift(); } catch(e0) { } try { m2.has(v2); } catch(e1) { } h1.getOwnPropertyNames = f2; }");
/*fuzzSeed-85495475*/count=203; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (((((0x31bb032e)))>>>((0xffffffff))) != (0xffffffff));\n    }\n    i0 = (0xb88ea7e4);\n    return (((i0)-(i0)))|0;\n    {\n      {\n        return (((i0)+(0xdf16945f)))|0;\n      }\n    }\n    {\n      {\n        d1 = (d1);\n      }\n    }\n    switch ((((0xec61ebbe)-(0xf9d5dc29)+(0x50e83312)) ^ ((Int32ArrayView[2])))) {\n      case -3:\n        return (((0xbd11bd17)+((0xfc417e1e))))|0;\n        break;\n      case 1:\n        i0 = (!(0xcd68f4cd));\n        break;\n      case -1:\n        {\n          {\n            i0 = (i0);\n          }\n        }\n      case 1:\n        d1 = (((((-0x8000000))>>>((i0))) / (((0xfe7228fc)-(i0))>>>(((imul((0xd63c75cb), ((0xf9a1f7b3) ? (0xfed6c8c1) : (0x420242e6)))|0))+(((9.0) < (1.9342813113834067e+25)) ? (0x9e0ad12e) : (i0))-(0xc756b60f)))));\n        break;\n      case -3:\n        d1 = (36028797018963970.0);\n        break;\n    }\n    i0 = (i0);\n    (Float64ArrayView[4096]) = ((4(null,  '' \u000c)) % (/\\D{1,}[^]+?|^(?!\\3)*+?/gim | true));\n    {\n      d1 = (+/*FFI*/ff(((((i0)) << ((i0)*0x516b1))), ((imul(((((0xfc0adb77)+(0x1e1262c5)+(0x9e3b906d))>>>((i0)+((0xa3a6d2d5)))) == (0xdb7c79f7)), (i0))|0)), ((~(((((0xfe7836cc))>>>((0x18c6167f))) <= (0xc65935bc))-(/*FFI*/ff()|0)-((((((0xae34e15e)) << ((0x8cf3cad) % (0x36290f20))))))))), (((((~((0x2e528b3e))) > (abs((~~(4294967295.0)))|0))) >> (0x796f6*(-0x8000000)))), ((+((72057594037927940.0)))), (((((0xaa1b29d3))) ^ (((0xcb3f5c9e) > (0xffffffff))*0x23d04))), ((d1)), (((-9.671406556917033e+24) + (1.5474250491067253e+26))), (((0xd8f18cfd) ? (-8796093022209.0) : (2251799813685249.0))), ((-0.00390625)), ((590295810358705700000.0)), ((1.0)), ((4503599627370495.0))));\n    }\n    return (((i0)+(0xfd2eaba4)+(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x100000000, -(2**53+2), -0x100000001, 1.7976931348623157e308, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, -0x080000000, Math.PI, 0/0, 2**53-2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -Number.MAX_VALUE, -0x07fffffff, 0x100000001, 0.000000000000001, -1/0, 0x0ffffffff, 2**53+2, -0x080000001, 0x100000000, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, 1, -(2**53-2), -0, 42, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=204; tryItOut("");
/*fuzzSeed-85495475*/count=205; tryItOut("i1.toSource = (function() { this.e1.delete(t2); throw i2; });");
/*fuzzSeed-85495475*/count=206; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return (Math.sinh((Math.atan2((Math.max(y, (y | 0)) | 0), (((Math.acosh(Math.sinh(Math.fround(-0x100000001))) | 0) << (Math.atanh(0x0ffffffff) | 0)) >>> 0)) | 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('')]); ");
/*fuzzSeed-85495475*/count=207; tryItOut("\"use strict\"; a0.__iterator__ = (function(j) { if (j) { s0 += 'x'; } else { try { s1.__proto__ = i0; } catch(e0) { } v0 = t2.length; } });");
/*fuzzSeed-85495475*/count=208; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ( + (( - (Math.fround(Math.abs(Math.fround(( + ( ! (Math.asinh((y >>> 0)) >>> 0)))))) | 0)) | 0)); }); testMathyFunction(mathy0, [-0, objectEmulatingUndefined(), (new Number(0)), (new Boolean(true)), '', null, (new Boolean(false)), (new Number(-0)), (new String('')), 1, /0/, '/0/', '0', (function(){return 0;}), '\\0', ({toString:function(){return '0';}}), undefined, 0, false, [0], NaN, ({valueOf:function(){return '0';}}), true, ({valueOf:function(){return 0;}}), 0.1, []]); ");
/*fuzzSeed-85495475*/count=209; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[true, true, true, true, true, true, new String(''), new String(''), true, new String(''), true]) { e0.valueOf = (function(j) { if (j) { v1 = t1.length; } else { a2[v1] = a2; } }); }");
/*fuzzSeed-85495475*/count=210; tryItOut("v1 = (e0 instanceof i0);function x()\"use asm\";   var abs = stdlib.Math.abs;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      d1 = (d1);\n    }\n    return (((abs((~~(536870913.0)))|0) % (((Int32ArrayView[4096])) >> ((i2)+(((0xe1832e70) <= (0x5e0dc775)) ? ((((0xffffffff))>>>((-0x8000000)))) : (i0))))))|0;\n  }\n  return f;v2 = r1.toString;");
/*fuzzSeed-85495475*/count=211; tryItOut("mathy2 = (function(x, y) { return Math.atan2(Math.fround(Math.log1p(Math.fround(Math.fround(( ! Math.fround(((1 ? Math.fround(-1/0) : (Math.fround(( - x)) | 0)) | 0))))))), mathy1((( - (( + Math.fround(( - Math.fround((((0x100000001 | 0) || (y | 0)) | 0))))) >>> 0)) >>> 0), Math.fround(Math.imul(Math.fround(x), Math.fround((y || ( + (( + x) ? ( + y) : ( + x))))))))); }); ");
/*fuzzSeed-85495475*/count=212; tryItOut("\"use strict\"; /*RXUB*/var r = (objectEmulatingUndefined()); var s = \"\\uB040\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=213; tryItOut("e0 + '';");
/*fuzzSeed-85495475*/count=214; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((mathy1((Math.fround((Math.fround(Math.cosh(Math.atan((Math.min(y, (x >>> 0)) >>> 0)))) ? Math.fround((((-0x07fffffff >>> 0) != (-0x080000001 >>> 0)) >>> 0)) : Math.fround(mathy0(( + -0x080000001), ( + (-0x100000001 >= x)))))) | 0), Math.sqrt(Math.imul(( + x), y))) ? Math.fround(( + ((Math.atan2((( - ( ~ y)) | 0), (mathy1((( + Math.max(( + x), (y !== x))) & y), y) | 0)) | 0) | 0))) : Math.fround((((( + ( ! (y + x))) >>> 0) <= (Math.imul((-Number.MAX_VALUE ? ( + Math.tan(( + x))) : x), Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, -0x080000001, -(2**53), -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000000, 42, -0x080000000, 2**53+2, Math.PI, Number.MAX_VALUE, 0x080000001, 0x080000000, -0x0ffffffff, 1, 0x100000001, Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 0/0, 2**53-2, 0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, -0x100000000, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-85495475*/count=215; tryItOut("/*infloop*/do {throw this; } while(\nthis);");
/*fuzzSeed-85495475*/count=216; tryItOut("t1 = new Float64Array(t1);");
/*fuzzSeed-85495475*/count=217; tryItOut("mpwdjk, d,   = \"\\u9E66\", d, b, toUTCString, b;g0 = x;");
/*fuzzSeed-85495475*/count=218; tryItOut("Array.prototype.splice.call(a1, -11, 4);");
/*fuzzSeed-85495475*/count=219; tryItOut("testMathyFunction(mathy5, [-1/0, 0x0ffffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53, Number.MIN_SAFE_INTEGER, -0, 0, 42, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, -0x100000001, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0/0, -0x0ffffffff, 2**53-2, -(2**53-2), Math.PI, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, 0x07fffffff, 0x080000001, -0x080000001, -Number.MIN_VALUE, 0x080000000, -0x07fffffff, -(2**53+2), 1/0]); ");
/*fuzzSeed-85495475*/count=220; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.atan2(Math.tanh(((-(2**53-2) | 0) , (( + (( + Math.fround(Math.sqrt(Math.fround(y)))) - ( + Math.expm1(y)))) | 0))), ((Math.cosh(((Math.fround(x) ? (Math.fround(Math.sqrt(Math.fround((x * Math.min(x, y))))) >>> 0) : ( + y)) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, 1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 0x07fffffff, 0x080000000, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, -0x100000001, -0x0ffffffff, 1.7976931348623157e308, 0x100000001, 42, -(2**53), -1/0, 0x080000001, Number.MAX_VALUE, -0x100000000, -0x07fffffff, -0, -0x080000001, 0/0]); ");
/*fuzzSeed-85495475*/count=221; tryItOut("testMathyFunction(mathy3, [Number.MAX_VALUE, 2**53+2, -0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, 42, -Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, 0x100000000, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, Math.PI, 0, -(2**53), 0x07fffffff, 0x0ffffffff, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, -0x100000001, 2**53, 0.000000000000001, -Number.MIN_VALUE, 0x080000001, -0x080000000, 1, -(2**53+2)]); ");
/*fuzzSeed-85495475*/count=222; tryItOut("testMathyFunction(mathy4, [Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 1/0, -(2**53+2), -0x100000000, 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0x100000000, -(2**53-2), -0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, Math.PI, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, 2**53+2, 42, 0, -0, -(2**53), -1/0, 1, 2**53-2]); ");
/*fuzzSeed-85495475*/count=223; tryItOut("s2 += s0;");
/*fuzzSeed-85495475*/count=224; tryItOut(";a0.push(a0, h1, this.o2.a1, a1, this.b0, i2, b0, m2);");
/*fuzzSeed-85495475*/count=225; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - Math.fround(Math.hypot((Math.cosh(( ~ y)) <= ((Math.atan2(x, x) !== ( + ( ! Math.fround(Math.hypot(Math.fround(( + (( + x) ? x : 0x07fffffff))), Math.fround(Number.MIN_VALUE)))))) | 0)), Math.fround(Math.max(Math.fround(x), x))))); }); ");
/*fuzzSeed-85495475*/count=226; tryItOut("testMathyFunction(mathy1, /*MARR*/[new Number(1), new Number(1), function(){}, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), function(){}, function(){}, function(){}, new Number(1), new Number(1), new Number(1), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1), new Number(1), function(){}, function(){}, function(){}, function(){}, new Number(1), new Number(1), function(){}, new Number(1), new Number(1), function(){}, new Number(1), function(){}, new Number(1), function(){}, function(){}, new Number(1), function(){}, new Number(1), function(){}, function(){}, new Number(1), new Number(1), function(){}, function(){}, function(){}, new Number(1), new Number(1), new Number(1)]); ");
/*fuzzSeed-85495475*/count=227; tryItOut("(eval(\"delete e.z\"));");
/*fuzzSeed-85495475*/count=228; tryItOut("mathy5 = (function(x, y) { return mathy3(((( + ( - (mathy0(Math.imul(x, y), (Number.MAX_SAFE_INTEGER | 0)) < (( ! (y | 0)) >>> 0)))) ** Math.fround(( - y))) >>> 0), Math.fround((( + (((y ? y : Math.fround(Math.pow(0x07fffffff, y))) ? ( + Math.acosh(y)) : (x >>> 0)) >>> 0)) >>> (Math.fround(( - ( + (((Number.MIN_VALUE >>> 0) << (((y >= x) ? -0x0ffffffff : Math.fround(( + Math.fround(x)))) >>> 0)) >>> 0)))) ? ((Math.pow((((( + 1/0) ? (-(2**53-2) | 0) : (Math.imul(x, Math.fround(y)) | 0)) | 0) >>> 0), x) >>> 0) >>> 0) : (( ~ -Number.MAX_SAFE_INTEGER) + (( + 0x07fffffff) ** (( + ( ~ x)) != ( + 1.7976931348623157e308)))))))); }); testMathyFunction(mathy5, [[], 1, (new Number(-0)), null, ({valueOf:function(){return 0;}}), 0.1, [0], (new String('')), true, '', NaN, ({toString:function(){return '0';}}), objectEmulatingUndefined(), /0/, (new Boolean(true)), (new Boolean(false)), ({valueOf:function(){return '0';}}), false, '0', '\\0', -0, '/0/', (new Number(0)), undefined, 0, (function(){return 0;})]); ");
/*fuzzSeed-85495475*/count=229; tryItOut("v0 = evaluate(\"h0.getOwnPropertyDescriptor = (function() { for (var j=0;j<12;++j) { g2.f1(j%5==0); } });\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 46 == 37), catchTermination: (\"\\uB787\" &= this.__defineSetter__(\"eval\", (function (w) { \"use strict\"; return w } ).apply)) }));");
/*fuzzSeed-85495475*/count=230; tryItOut("\"use strict\"; m1.has(o0);");
/*fuzzSeed-85495475*/count=231; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (4.835703278458517e+24);\n    return +(((((((0xffffffff))>>>((0x8492a6d3)+((((0xffffffff))>>>((0xd2753823)))))) / ((((~((-0x8000000))) >= (((0x9362b871)) ^ ((0x649888e))))+(i0))>>>(((abs((imul((0xf26ccff4), (0x36f39024))|0))|0))))) | ((0xb8f1fe7c) % (((0x489edde7))>>>((i0)-((0xab8bc8be))-(i0)))))));\n  }\n  return f; })(this, {ff: Object.assign}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_VALUE, 0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -(2**53), 0.000000000000001, 0x100000000, 2**53+2, -0x100000001, 0/0, 0x080000001, -(2**53+2), -Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0, 2**53, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0x07fffffff, Math.PI, 1.7976931348623157e308, -0, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, 2**53-2, -0x080000000, 1/0, 1]); ");
/*fuzzSeed-85495475*/count=232; tryItOut("Array.prototype.shift.call(a1);");
/*fuzzSeed-85495475*/count=233; tryItOut("print(a2);if(false) {print(x); } else  if (undefined >>> \"\\u0473\") a1 = Array.prototype.map.apply(a1, [g0.f1]);");
/*fuzzSeed-85495475*/count=234; tryItOut("s0 += s0;");
/*fuzzSeed-85495475*/count=235; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=236; tryItOut("let wqdvlm, gxqxrt, e, wtmtpa, [, , [ , , , {x: [{eval: x, x: {x: x}}, {x: [], x}, {\u3056: [{}]}], z: {window: [], this.window: [], x:  }, []: [NaN]}, x], , x, ] = new function (c) { \"use strict\"; \u000cprint(uneval(this.o2.t2)); } (new  /x/g () **= , ((void options('strict')))), x, qjjcpd, d((/*RXUE*/ '' .exec(\"\"))) = 'fafafa'.replace(/a/g,  '' ), z = (a = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: this, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: new Function, keys: function() { return Object.keys(x); }, }; })(\"\\u9862\"), Math.acos(/[^]+?/yi)));m2.has(g1);\nvar gwecrj = new SharedArrayBuffer(8); var gwecrj_0 = new Uint16Array(gwecrj); /*ODP-1*/Object.defineProperty(e1, \"NaN\", ({configurable: false, enumerable: (x % 103 == 100)}));\n");
/*fuzzSeed-85495475*/count=237; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return ((( + Math.pow(( + Math.fround(( - Math.fround(( + (x && ( + 1))))))), ( + ( ~ ( ~ 0x07fffffff))))) - ((((( ~ Math.fround(Math.pow(Math.fround(0x100000001), Math.fround((mathy1(x, (Math.fround(Math.expm1(Math.fround(-Number.MIN_SAFE_INTEGER))) | 0)) | 0))))) | 0) !== Math.log((mathy1(y, (y | 0)) | 0))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [-(2**53+2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000000, 0, Math.PI, 2**53+2, Number.MIN_VALUE, 2**53-2, 0x0ffffffff, -0x100000001, 1, -0x080000001, 0x07fffffff, -0x0ffffffff, 2**53, -1/0, 0.000000000000001, 42, -(2**53-2), 0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0/0, -(2**53), 0x080000000, -0x100000000, -Number.MAX_VALUE, -0, 0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=238; tryItOut("i1 + f2;");
/*fuzzSeed-85495475*/count=239; tryItOut("print(x);function x(d) { yield (-20.unwatch( /x/ )) } Array.prototype.push.call(o0.a1, i0, p1, g2.p1, s1, f1);");
/*fuzzSeed-85495475*/count=240; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.tan(( + Math.min((Math.pow(Math.fround(Math.sinh(mathy2(x, ( + -0x0ffffffff)))), ((x ? (Math.fround(( ! ( + Math.fround(Math.log(Math.fround(y)))))) === (((-0x080000001 >>> 0) & (( ! 2**53) >>> 0)) >>> 0)) : y) >>> 0)) >>> 0), (mathy1(( + mathy1(y, ( + Math.expm1(( + Math.fround(Math.pow(y, -(2**53-2)))))))), Math.exp((-(2**53+2) >>> 0))) >>> 0)))); }); ");
/*fuzzSeed-85495475*/count=241; tryItOut("\"use strict\"; var r0 = 6 / x; var r1 = 0 ^ x; r0 = x & r0; var r2 = r1 - r0; var r3 = r2 * r2; r2 = 6 % r0; r1 = r0 | r1; var r4 = x / r1; r2 = x & 3; r3 = r2 % 3; x = r2 * 0; var r5 = r1 | r4; r1 = 2 ^ r1; var r6 = r4 - r1; var r7 = 5 & 7; r7 = r6 / 8; var r8 = r1 | r1; r1 = x + 9; var r9 = 0 + 5; r0 = r4 & r8; var r10 = r5 | r1; var r11 = r0 - 0; var r12 = 2 * r3; var r13 = 6 & 8; var r14 = 8 ^ r5; var r15 = 2 * r11; var r16 = 4 - x; var r17 = 3 * r3; r15 = 4 - r2; var r18 = r12 % 1; var r19 = 4 % x; var r20 = r14 - r16; var r21 = r0 % r15; var r22 = r18 + 1; var r23 = 6 * r7; var r24 = r9 & r6; var r25 = 5 ^ r2; var r26 = 0 + r0; r14 = r24 - r2; var r27 = r3 % 3; r15 = r3 % r14; var r28 = 0 % r0; print(r28); r24 = r23 | 9; r4 = r26 | x; var r29 = 7 + 4; var r30 = r28 % r3; var r31 = r12 * r12; var r32 = 8 - 5; var r33 = r21 ^ 8; var r34 = r2 & 7; var r35 = r7 | r15; var r36 = 5 | 3; var r37 = r16 / 2; var r38 = r28 * 9; var r39 = 1 & r19; var r40 = 6 ^ r32; var r41 = r40 % 0; var r42 = r33 & r29; var r43 = r23 % r36; r10 = r34 - r16; r25 = r1 & 1; var r44 = 8 / r0; var r45 = 1 | r5; var r46 = r42 + 8; r11 = 2 & 1; var r47 = r24 * 0; var r48 = 2 ^ 4; r13 = r6 / r14; var r49 = 6 / r21; var r50 = 6 / r23; print(r35); var r51 = r0 + 5; var r52 = r51 & 2; var r53 = r27 & r7; var r54 = r5 / r26; r7 = r48 / 9; var r55 = r39 | r20; var r56 = r22 & r26; var r57 = r50 ^ r0; var r58 = r40 ^ 0; r49 = r43 | 0; var r59 = r13 % 9; var r60 = 5 ^ r35; var r61 = r22 * 9; var r62 = r22 / 2; var r63 = r36 & r5; var r64 = r4 + r32; var r65 = r47 % r42; r53 = r37 ^ 7; var r66 = r53 * r20; var r67 = r0 % r27; r39 = 8 * 1; var r68 = r62 - r9; var r69 = 6 + r4; var r70 = r67 & r66; r63 = r45 - r69; var r71 = 7 | r45; var r72 = r49 & 3; var r73 = 9 ^ r35; var r74 = r41 - r60; var r75 = 6 | 7; print(r28); r19 = r49 % r47; var r76 = 0 | r37; r58 = 2 & r7; var r77 = r40 - r47; var r78 = r32 * r49; var r79 = r64 ^ r39; var r80 = 5 ^ r74; var r81 = 7 * 1; r14 = 6 ^ 3; var r82 = r20 / r79; var r83 = 0 + r25; var r84 = r46 / r58; var r85 = r33 ^ r51; var r86 = r70 ^ 9; r65 = 8 - r39; var r87 = 3 % r19; var r88 = 5 ^ r51; var r89 = r22 - r18; print(r63); var r90 = r56 / r42; print(r29); var r91 = r55 % r63; var r92 = 8 ^ 9; var r93 = r31 - r27; var r94 = 5 * r50; var r95 = r23 - r4; var r96 = 1 | 3; r11 = r64 | 2; var r97 = r74 + r32; var r98 = r31 % r8; ");
/*fuzzSeed-85495475*/count=242; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void schedulegc(this); } void 0; }");
/*fuzzSeed-85495475*/count=243; tryItOut("\"use strict\"; let z = ({__parent__: x, constructor: (6 = (4277)) });(z);s2 += s0;");
/*fuzzSeed-85495475*/count=244; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(( ! Math.fround(Math.hypot(( + mathy1(( + mathy1((Math.trunc(( + Math.fround((Math.fround(y) >= ( + y))))) | 0), x)), ( + mathy1(y, (0/0 | 0))))), (Math.fround((Math.min((( + ( ~ (x >>> x))) >>> 0), ((y !== y) >>> 0)) >>> 0)) ? Math.pow(1.7976931348623157e308, x) : Math.atan2(Math.fround(Math.log1p(( + Math.asinh(x)))), y)))))); }); ");
/*fuzzSeed-85495475*/count=245; tryItOut("mathy4 = (function(x, y) { return ( - ((Math.cos(Math.fround(Math.round(Math.fround(Math.min(Math.fround((Math.min(y, mathy1(Math.fround(y), (y >>> 0))) >>> 0)), /*RXUE*/new RegExp(\"(?:.[^\\\\cX-\\\\\\u007f\\\\S]+?)|($$){2}\", \"g\").exec(\"\")))))) | 0) ? Math.atan2(Math.expm1((((y >>> 0) % x) >>> Math.sinh(x))), (y != ( + Math.sinh(-1/0)))) : (Math.max(Math.fround(x), Math.min(x, ( - (y | 0)))) | 0))); }); testMathyFunction(mathy4, [1, 0x080000001, 2**53+2, -Number.MIN_VALUE, 0x100000000, -0x080000001, -0x07fffffff, 0x07fffffff, Math.PI, -0, 0, -0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -(2**53), 0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=246; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return mathy0((Math.cos((Math.fround(Math.tanh(Math.fround(( + ( + (((Math.cbrt(y) >>> (y | 0)) | 0) << (( + Math.max(y, y)) | 0))))))) | 0)) | 0), (mathy0((( + Math.max(( + x), ( + Math.log10(Math.fround((( + Math.fround((Math.fround(Number.MAX_VALUE) > Math.fround(y)))) - Math.fround(y))))))) >>> 0), ((( ~ (Math.fround(Math.tanh(2**53+2)) | 0)) | 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=247; tryItOut("\"use strict\"; f1.toSource = (function() { for (var j=0;j<105;++j) { f0(j%2==0); } });");
/*fuzzSeed-85495475*/count=248; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy0(((mathy0(Math.fround(( ! ( + Math.atan(( + x))))), Math.sinh((( + ( + Math.pow(y, Math.hypot(x, Number.MIN_SAFE_INTEGER)))) >>> 0))) | 0) >>> 0), (Math.fround((Math.fround(Math.fround(Math.atanh((mathy2(Math.fround(( - Math.min(Math.fround(( ! Math.fround(-1/0))), 0x07fffffff))), ((y == x) >> y)) | 0)))) ? ( + ( - ((Math.fround(( ! Math.fround(y))) ^ ((x << ( - x)) >>> 0)) >>> 0))) : Math.fround((( ~ ((Math.min(( + x), ( + Math.max(Math.fround(x), Math.fround(2**53+2)))) | 0) >>> 0)) >>> 0)))) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=249; tryItOut("\"use asm\"; delete h1.has;");
/*fuzzSeed-85495475*/count=250; tryItOut("for (var p in m0) { a2.splice(-6, 16, m0, g2.b1, b2, g1.o1, g2.g1.e1, g0, b1, b0); }");
/*fuzzSeed-85495475*/count=251; tryItOut("mathy3 = (function(x, y) { return ( + Math.min(( + ( ! ( + Math.min(Math.fround(-0x0ffffffff), Math.fround(Math.acosh((( - y) >>> 0))))))), ( + Math.hypot(Math.fround(Math.log(Math.fround(( + ((x | 0) | ( + x)))))), Math.hypot(Math.fround(Math.hypot(Math.fround(( ~ y)), Math.fround(Math.fround(Math.clz32(( + Math.log1p(x))))))), (( + Math.atan2(-0x080000000, ( ~ x))) >>> 0)))))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1, 0/0, 0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, 0x07fffffff, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, 0x080000001, 2**53-2, 0x100000000, 0x0ffffffff, Number.MAX_VALUE, -(2**53), -0x080000000, -0x07fffffff, -0x100000001, -(2**53-2), 42, -1/0, 0x100000001, -0x0ffffffff, -0, -0x080000001, -(2**53+2), 2**53+2]); ");
/*fuzzSeed-85495475*/count=252; tryItOut("let y, y, e = Math.tanh(-17);a0.length = 8;");
/*fuzzSeed-85495475*/count=253; tryItOut("Array.prototype.unshift.apply(a1, [e1, i1, g0.o1.a1]);");
/*fuzzSeed-85495475*/count=254; tryItOut("\"use strict\"; /*oLoop*/for (let kqlryr = 0; kqlryr < 26; new eval(Math.hypot(-3, -11),  \"\" ), ++kqlryr) { g2.h1.keys = f1; } ");
/*fuzzSeed-85495475*/count=255; tryItOut("this.a2.shift();");
/*fuzzSeed-85495475*/count=256; tryItOut("\"use strict\";  for (y of ((x.unwatch\u000c(\"wrappedJSObject\") <<= (x) = 10) == (({a2:z2}))())) {s2 += o2.s2;this.t1 = new Int16Array(t2); }");
/*fuzzSeed-85495475*/count=257; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy3(((mathy1(( ~ ( + (mathy3(( + y), y) === ( ! (Math.pow((y >>> 0), (-Number.MAX_SAFE_INTEGER | 0)) >>> 0))))), Math.hypot(x, Number.MIN_SAFE_INTEGER)) || mathy3((( ~ ( + Math.fround(Math.cosh(Math.fround((x ? Math.fround(x) : Math.fround(x))))))) | 0), (Math.log1p((Math.log1p(Math.max(mathy1(x, x), y)) >>> 0)) >>> 0))) >>> 0), ((( - (Math.fround(mathy0(x, x)) & y)) , (((mathy1(y, -0x080000000) | 0) != (Math.fround((Math.fround(( + 0x0ffffffff)) + x)) | 0)) | 0)) != (Math.max((Math.tan(((Math.min((y | 0), ( + mathy3(y, ( + ( + x))))) >>> 0) | 0)) | 0), Math.hypot((Math.tanh(mathy0(-(2**53+2), -(2**53+2))) | 0), ( + Math.abs(( + Number.MAX_VALUE))))) >>> 0))); }); testMathyFunction(mathy4, [1.7976931348623157e308, 0x0ffffffff, -0x07fffffff, 0x100000000, -Number.MIN_VALUE, 0x080000001, 0, -0x080000001, -1/0, Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, 42, Number.MIN_VALUE, 1/0, -0x080000000, 1, -Number.MAX_VALUE, 0/0, -0x0ffffffff, -0, -(2**53+2), 2**53+2, 0x07fffffff, -0x100000001, Math.PI, 2**53-2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=258; tryItOut("a0.sort((function mcc_() { var tebsja = 0; return function() { ++tebsja; if (true) { dumpln('hit!'); try { /*MXX3*/g1.Promise.resolve = g2.Promise.resolve; } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"000___000000\"; print(uneval(r.exec(s)));  } catch(e1) { } try { a2.forEach((function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    i2 = (i0);\n    i2 = ((i2) ? (i4) : (i0));\n    i3 = (((((2048.0)))>>>((i1)*-0xf533e)) == ((((i4) ? ((0x0)) : (1))+(i1))>>>((!((((0x0) / (0x124dca4b)) << ((1)*-0x8a4c0)))))));\n    i2 = (1);\n    i3 = (i0);\n    i3 = (i4);\n    i0 = (i0);\n    return +(((i3) ? (+pow(((-2.3611832414348226e+21)), ((+(1.0/0.0))))) : (33554433.0)));\n  }\n  return f; })); } catch(e2) { } Object.defineProperty(this, \"v2\", { configurable: (x % 6 != 1), enumerable: (x % 3 == 2),  get: function() { o1.g1.m0.get(o1.i2); return r2.compile; } }); } else { dumpln('miss!'); try { Array.prototype.forEach.call(o0.a0, x); } catch(e0) { } try { v0 = r1.unicode; } catch(e1) { } g1.o2.a1.forEach((function() { try { Array.prototype.sort.apply(a2, [(function() { ; return v2; }), g1.h2]); } catch(e0) { } m1.has(i0); throw s0; })); } };})(), g1, this.e2);");
/*fuzzSeed-85495475*/count=259; tryItOut("\"use strict\"; m2 = new WeakMap;");
/*fuzzSeed-85495475*/count=260; tryItOut("mathy2 = (function(x, y) { return (mathy1((Math.max(Math.sinh(Math.expm1(( ! Math.atan2(y, -0x080000000)))), Math.max(( + (Math.pow((0 | 0), (y | 0)) | 0)), (Math.max((x >>> 0), Math.fround(( - -Number.MAX_SAFE_INTEGER))) >>> 0))) >>> 0), ( + (( - ( + -0x100000000)) ** ( + mathy1(( + (Math.abs(x) >>> 0)), ( + y)))))) | 0); }); testMathyFunction(mathy2, [-1/0, 0x080000000, 1/0, -Number.MIN_VALUE, 0, Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0x080000001, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, 1, 1.7976931348623157e308, 0x100000001, Math.PI, -0x0ffffffff, -0x080000000, -0, -0x100000000, -0x100000001, 0x080000001, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-85495475*/count=261; tryItOut("\"use strict\"; v1.__proto__ = a0;");
/*fuzzSeed-85495475*/count=262; tryItOut("g1.offThreadCompileScript(\"window\");");
/*fuzzSeed-85495475*/count=263; tryItOut("M:if(false) print(\nnull); else  if (x === null) t0.set(t0, 8);");
/*fuzzSeed-85495475*/count=264; tryItOut("\"use strict\"; L:with((4277))print((Object.defineProperty(this.w, \"constructor\", ({get: -0, set:  /x/g , configurable: true}))));");
/*fuzzSeed-85495475*/count=265; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-85495475*/count=266; tryItOut("a1 = arguments.callee.caller.caller.arguments;");
/*fuzzSeed-85495475*/count=267; tryItOut("\"use strict\"; v1 = t1.length;");
/*fuzzSeed-85495475*/count=268; tryItOut("\"use strict\"; ;");
/*fuzzSeed-85495475*/count=269; tryItOut("x = (/*FARR*/[, /(?=(?=(.[}]*)+?)){2}/im, ...[],  /x/ , ].filter);");
/*fuzzSeed-85495475*/count=270; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((Math.expm1((Math.tan(((x ? (Math.atan2((( ~ Math.sin(y)) | 0), x) >>> 0) : ( + x)) >>> 0)) | 0)) | 0) && ( ! ( + ( - ((( + Math.fround(0/0)) != ((Math.fround(mathy3(Math.fround(-(2**53-2)), Math.fround((( ~ -0x100000001) | 0)))) | 0) < (y <= Number.MAX_VALUE))) | 0))))); }); testMathyFunction(mathy5, [Math.PI, -(2**53+2), 0x100000000, -0, 1, 0x100000001, 1/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 0x07fffffff, 0/0, -1/0, 1.7976931348623157e308, Number.MIN_VALUE, 2**53, -0x0ffffffff, -(2**53-2), -0x100000000, 0.000000000000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 42, -0x07fffffff, -0x080000000, -0x080000001, 2**53-2, -(2**53), -0x100000001, 0, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=271; tryItOut("\"use asm\"; testMathyFunction(mathy0, [-(2**53+2), -0x080000001, -0, -1/0, Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), -0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 0x100000001, 1/0, -0x07fffffff, Number.MAX_VALUE, 0x100000000, 42, 0x07fffffff, -(2**53), 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, 1, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, Math.PI, 0, 2**53+2]); ");
/*fuzzSeed-85495475*/count=272; tryItOut("/*RXUB*/var r = new RegExp(\"X\\\\B[^\\\\d\\\\xe0-\\u541b\\\\D\\\\u000c]|\\\\t*(\\\\B\\\\d)|(?=\\uf28b|^)|$|\\\\w{0,0}+?+?\", \"gim\"); var s = \"X\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-85495475*/count=273; tryItOut("mathy2 = (function(x, y) { return (mathy0(((mathy0(Math.max(Math.log(x), x), ((x > Math.acos(0x100000001)) | 0)) | 0) >>> 0), Math.fround((Math.fround(( - ( + ( + -0x07fffffff)))) !== Math.fround(Math.atan2(Math.fround((Math.fround((( ~ ((y != -Number.MAX_SAFE_INTEGER) | 0)) | 0)) + Math.fround((x || ( ~ (x >>> 0)))))), ((y != -Number.MIN_SAFE_INTEGER) == y)))))) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 1, Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, 2**53+2, -0x100000001, -Number.MIN_VALUE, 1/0, -0x07fffffff, -(2**53+2), -0x0ffffffff, 42, -0x080000001, 2**53, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0, Number.MIN_VALUE, 0/0, 0x100000000, Math.PI, 0.000000000000001, 0x0ffffffff, -(2**53), 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=274; tryItOut("\"use strict\"; ;");
/*fuzzSeed-85495475*/count=275; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"begin\" }); }");
/*fuzzSeed-85495475*/count=276; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = (i0);\n    i0 = (/*FFI*/ff()|0);\n    d1 = (-((7.555786372591432e+22)));\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(){}, defineProperty: this, getOwnPropertyNames: undefined, delete: undefined, fix: function() { return []; }, has: function() { return false; }, hasOwn: ( /x/ ).apply, get: function() { return undefined }, set: /(?=(?!^{4,}))/, iterate: undefined, enumerate: undefined, keys: undefined, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Math.PI, -(2**53-2), 1.7976931348623157e308, -0x080000001, -0x07fffffff, -0x080000000, 0x0ffffffff, Number.MAX_VALUE, -0, -0x0ffffffff, 2**53, 2**53+2, 2**53-2, -Number.MAX_VALUE, -(2**53+2), 1, 0/0, -0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, 0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 0, 0x080000000, 0x100000000, 0x080000001, -Number.MIN_VALUE, 0.000000000000001, -0x100000001]); ");
/*fuzzSeed-85495475*/count=277; tryItOut("\"use strict\"; s2 += s0;");
/*fuzzSeed-85495475*/count=278; tryItOut("m0.set(m2, v2);");
/*fuzzSeed-85495475*/count=279; tryItOut("\"use strict\"; t1 = new Uint8ClampedArray(b0, 2, ({valueOf: function() { m1.get(g0.m2);return 6; }}));");
/*fuzzSeed-85495475*/count=280; tryItOut("this.e2.__iterator__ = (function() { v0 = Object.prototype.isPrototypeOf.call(i0, p1); return e2; });");
/*fuzzSeed-85495475*/count=281; tryItOut("\"use strict\"; for(let w of [x = 'fafafa'.replace(/a/g, Math.atan) for (x of ((new RegExp(\"([^])\", \"\")).call(Math, -26,  /x/g )))]) try { let(d) ((function(){for(let a in (function() { \"use strict\"; yield \"\\uF964\"; } })()) for(let e in (void options('strict'))) ;})()); } finally { w.message; } return (let (b =  /x/ )  \"\" )(x);");
/*fuzzSeed-85495475*/count=282; tryItOut("this.p0.toSource = (function() { for (var j=0;j<2;++j) { o0.f0(j%2==0); } });");
/*fuzzSeed-85495475*/count=283; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.max(Math.cosh(((( ! ((( + (( + mathy1(((Math.log2(( + x)) >>> 0) >>> 0), ( - x))) ? ( + Math.hypot(y, Math.fround(Math.sqrt(Math.fround(x))))) : ( + (y - -Number.MAX_VALUE)))) <= (mathy2(y, y) | 0)) >>> 0)) >>> 0) >>> 0)), (Math.cbrt(( + (( + (((y * (-0x07fffffff | 0)) | 0) , (x >>> 0))) !== Math.fround(Math.ceil(( + ( ~ y))))))) != (( + (((y | 0) === x) <= 0)) >>> 0))); }); testMathyFunction(mathy3, [-(2**53+2), 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53-2), 0/0, 1, 0x080000001, 2**53-2, -(2**53), -0x080000000, -0x100000001, -0x080000001, -0, 2**53, 1/0, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 0, Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -Number.MAX_VALUE, 0.000000000000001, 0x080000000, -0x0ffffffff, 42, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-85495475*/count=284; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\\n\\n\\n\"; print(s.search(r)); function x(b, z, x, \u3056 = , eval, d, e, x)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((-0x8000000)))|0;\n  }\n  return f;(uneval(this));");
/*fuzzSeed-85495475*/count=285; tryItOut("{this.g1.t0[3] = (/(?![^]|[])(.{3}){3}|(?:\\b\\t)?(?=(?!((?=\\D))\uefe7|.{3,5}))|\\b|((\\b+?))/y , x);if((x % 52 != 37)) { if ((4277)) print(x);} else {v1 = Object.prototype.isPrototypeOf.call(p1, g2.t0); } }");
/*fuzzSeed-85495475*/count=286; tryItOut("mathy4 = (function(x, y) { return ((Math.atanh(Math.acos(Math.fround(Math.pow(x, y)))) ? ( + (((Math.imul((((x | 0) != ((Math.atan2((x | 0), (2**53-2 | 0)) | 0) | 0)) | 0), (x * mathy1((x | 0), 2**53))) >>> 0) || (( + Math.pow(( + x), ( + Math.atan((x | 0))))) | 0)) >>> 0)) : (Math.hypot(y, mathy1(x, ( + ( + mathy1(( + x), ( + y)))))) >>> Math.sqrt(((( + (x << y)) ? (y | 0) : Number.MAX_SAFE_INTEGER) | 0)))) > Math.round(Math.tan(((mathy1(( + y), x) >>> ((Math.hypot(x, (-(2**53) ^ x)) * x) | 0)) | 0)))); }); ");
/*fuzzSeed-85495475*/count=287; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    {\n      i0 = (0xfb87e455);\n    }\n    return (((i0)-(0x8618f507)+(!(i0))))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var jsggtl = this.__defineGetter__(\"x\", false); (offThreadCompileScript)(); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [[], -0, false, (new Number(0)), /0/, ({valueOf:function(){return '0';}}), 0.1, undefined, null, (new String('')), ({toString:function(){return '0';}}), '/0/', (new Boolean(false)), 1, (new Boolean(true)), '\\0', '0', NaN, ({valueOf:function(){return 0;}}), 0, (function(){return 0;}), '', true, (new Number(-0)), [0], objectEmulatingUndefined()]); ");
/*fuzzSeed-85495475*/count=288; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    d1 = (((Uint32ArrayView[2])) + (d0));\n    return (((((-0x8000000))>>>((!(0xfedbb915))-(0x9ddc31fb)+((-((((-140737488355329.0)) - ((536870912.0))))) < (d0)))) / ((-0xb8492*(-0x8000000))>>>((!(0x8cca962f))+((0x621648c6))))))|0;\n    d1 = (((0xc8ec05ab)) ? (d0) : (d0));\n;    d1 = (d0);\n    {\n      return (((0x1aff8136)))|0;\n    }\n    {\n      {\n        (Float64ArrayView[((~~(+(((0x45eea6a2)) << ((0x936afee4))))) % (((0x65f32e11)+(0x3836743e)+(0x46d74aa1)) ^ ((0xfea5f9a4)*0xda1d6))) >> 3]) = ((d0));\n      }\n    }\n    return (((!((((0x14222800)-((0x2193465d))) & ((-0x8000000)-(0xffffffff))) == ((((null ? window : new RegExp(\"(\\\\3)\", \"g\").unwatch(\"__iterator__\")))) ^ ((0xffffffff)))))))|0;\n  }\n  return f; })(this, {ff: Int8Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [1.7976931348623157e308, -0x100000001, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -(2**53), 0, -(2**53+2), 0.000000000000001, -0x07fffffff, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, -0x0ffffffff, -0x080000001, 0x100000001, -1/0, 1/0, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, -(2**53-2), 2**53, 0x0ffffffff, 1, Number.MIN_VALUE, 42, -0]); ");
/*fuzzSeed-85495475*/count=289; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=290; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[null]) { print((b = (void version(170)))); }");
/*fuzzSeed-85495475*/count=291; tryItOut("/* no regression tests found *//*RXUB*/var r = new RegExp(\"((?!((\\\\s{0,})|\\\\s)\\\\W[^]{3})){2,}\", \"m\"); var s = \"aaaaaaaaaaaaaa\"; print(s.match(r)); ");
/*fuzzSeed-85495475*/count=292; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.hypot((mathy4(-0x100000000, ( + Math.expm1(( ! y)))) >>> 0), ( + (( + Math.fround(mathy4(y, (( - Math.fround(y)) >>> 0)))) == ( + y))))); }); testMathyFunction(mathy5, [-0x0ffffffff, -0x100000001, -0x07fffffff, 0x080000001, -1/0, Number.MIN_VALUE, -0x100000000, -0, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 2**53-2, -(2**53+2), 0x080000000, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, -0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, 42, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0x0ffffffff, Math.PI, 0x100000001, 0x100000000, 1/0]); ");
/*fuzzSeed-85495475*/count=293; tryItOut("\"use strict\"; var r0 = 2 / x; var r1 = x * r0; var r2 = r1 / r1; var r3 = r1 | r1; var r4 = r1 & r2; r1 = r2 | r1; r4 = r0 / x; r3 = 0 / 0; var r5 = 6 / 1; var r6 = r4 % r3; var r7 = r3 / r3; var r8 = r5 + 2; var r9 = r8 + 9; var r10 = 9 & r7; r10 = r7 - 9; var r11 = r1 * r2; var r12 = 1 / r7; var r13 = r9 / x; r8 = x ^ r2; var r14 = 7 | r0; var r15 = r13 % r8; var r16 = x * 5; var r17 = r5 | r9; var r18 = r9 % r7; var r19 = r9 / r3; var r20 = r5 % 6; var r21 = r15 % 7; var r22 = 7 | 8; var r23 = 4 - r21; var r24 = r5 & r9; var r25 = r10 / r11; var r26 = 6 ^ r0; r18 = r18 + r15; r8 = r7 | r2; print(r20); ");
/*fuzzSeed-85495475*/count=294; tryItOut("delete o2.h1.keys;g2.g2.s1 = s0.charAt(v0);");
/*fuzzSeed-85495475*/count=295; tryItOut("\"use strict\"; {}function x(this, e, eval = y, a, x, c = x, w, y = false, \u3056, e, d = true, e, c, x = \"\\u43D5\", a, w, w, z, c, x, x, x, \u3056, a, w, x, x, x, x, eval, x, d, NaN, window, this.eval, \u3056, \u3056, \u3056, z, e, x = \"\\u256A\", a, d = x, x, x, z, x, e, NaN,  '' , x, e, d, y, d, d, x, x, x, x = e, b, window, \u3056, of, d, x, x, z, a, b, c, a, x, e = \"\\uE905\", x, window, \u3056, x, b = ({}), y, w, x, x, window) { \"use strict\"; a1.__proto__ = t2; } print(new RegExp(\"(?:(((^|\\\\u004B)))|[\\u00a7-\\u3e18\\\\a-\\u486a\\u0098]+{2})\", \"gm\"));");
/*fuzzSeed-85495475*/count=296; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return (( + (( + Math.fround(Math.expm1((( + Math.fround((((y >>> 0) ? (x >>> 0) : (0 | 0)) >>> 0))) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-85495475*/count=297; tryItOut("mathy1 = (function(x, y) { return (Math.max((Math.sinh(Math.min(( + y), ( + ( - ((Math.min((x >>> 0), y) >>> 0) >>> 0))))) | 0), Math.tanh(Math.fround(Math.log(( ! mathy0(Math.fround(( ~ 0x080000001)), (Math.imul(x, x) | 0))))))) | 0); }); testMathyFunction(mathy1, [-0, Math.PI, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, Number.MAX_VALUE, -0x0ffffffff, 0, 0x100000000, -(2**53), 0x080000000, -Number.MIN_VALUE, 0x100000001, 2**53+2, 0x0ffffffff, 2**53, 0/0, -0x100000001, -0x07fffffff, 2**53-2, 1, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, -0x080000001, -Number.MAX_VALUE, -1/0, -(2**53-2), 42, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=298; tryItOut("/*bLoop*/for (xulcgr = 0; (eval(\"/(?![^\\\\udedB-\\u000e\\\\cS-\\\\u0096])(?!([^\\\\d\\\\b-\\\\cY\\\\S]))*/im\")) && xulcgr < 18; ++xulcgr, new RegExp(\"(?!(^(?![^])|[^]|\\\\S*?))(?=[^\\\\t-\\\\cR\\ua2e6])*?(?=^[^]{2,4})\\\\b$|9|[^r-\\\\u3668]\\\\W{2}(?:$){4}\", \"yi\")) { if (xulcgr % 4 == 2) { var xvfsnp = new ArrayBuffer(8); var xvfsnp_0 = new Int16Array(xvfsnp); print(xvfsnp_0[0]); {} } else { Object.defineProperty(this, \"i1\", { configurable: false, enumerable: (x % 7 == 1),  get: function() {  return Proxy.create(o2.h2, o1.i2); } }); }  } ");
/*fuzzSeed-85495475*/count=299; tryItOut("mathy3 = (function(x, y) { return (( ~ (( + ( ~ mathy2((mathy1((( + Math.fround(x)) >>> 0), x) ? 0.000000000000001 : (( - (y >>> 0)) >>> 0)), ( + Math.cos((Math.cos(y) !== y)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-85495475*/count=300; tryItOut("\"use strict\"; /*vLoop*/for (var zszckb = 0; zszckb < 26; ++zszckb) { d = zszckb; v2 = g2.o0.o1.a0.length; } ");
/*fuzzSeed-85495475*/count=301; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy0(Math.imul(Math.fround(Math.max(((y < (x >>> 0)) >>> 0), (Math.hypot(( + (( + (Math.fround(x) * Math.fround(y))) / y)), (x >>> 0)) >>> 0))), Math.fround(( - (mathy2((y + -0), y) | 0)))), Math.cbrt((( + ((( + y) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, 1/0, -0x0ffffffff, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), Number.MIN_VALUE, 0x100000000, -0, 0/0, -0x07fffffff, Number.MAX_VALUE, -0x080000000, 1, Math.PI, -0x100000001, 0, 1.7976931348623157e308, 0x07fffffff, -0x100000000, -(2**53-2), -(2**53+2), 42, 2**53, 0x080000000, -Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=302; tryItOut("mathy2 = (function(x, y) { return ( + Math.min(( + (mathy0(((Math.fround(( + (( + (-0x07fffffff ^ 0x100000000)) ? x : ( + (((x >>> 0) >= (( ! (x , y)) >>> 0)) >>> 0))))) ^ (Math.tanh((Math.fround(Math.log10(Math.fround(x))) >>> 0)) >>> 0)) | 0), (((x ? Math.log10(x) : 2**53-2) | 0) | 0)) | 0)), ( + ( ~ (Math.acos(Math.fround(mathy1((Math.tan((-Number.MAX_VALUE | 0)) | 0), y))) >>> 0))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, -0x0ffffffff, 0x100000000, Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -0x100000001, 0x080000000, -0x07fffffff, 42, -Number.MIN_VALUE, -1/0, -(2**53+2), 1.7976931348623157e308, Math.PI, 0x07fffffff, 1, 0x080000001, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, 0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 1/0, -0, -0x100000000, 2**53-2]); ");
/*fuzzSeed-85495475*/count=303; tryItOut("g1.v0 = evalcx(\"function f1(o2.g1.g1)  { o2.g1.g1 = d;for(let a in []); } \", g0);");
/*fuzzSeed-85495475*/count=304; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.fround(((((y | 0) != ((x * (mathy0(y, (mathy0(( - y), x) | 0)) | 0)) | 0)) | 0) >>> (( + ( + (x ? 0/0 : (42 | 0)))) | 0))) % Math.fround(( ! Math.fround((Math.pow(( + mathy1(( + Math.cos(42)), y)), (Math.ceil(2**53-2) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [0/0, 0x100000001, 0x0ffffffff, -Number.MIN_VALUE, -1/0, 0x080000001, Math.PI, -(2**53-2), -0x0ffffffff, -(2**53+2), 1/0, 0, Number.MIN_VALUE, 2**53, -0x080000000, 42, -0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -0x07fffffff, -(2**53), 2**53-2, -0x100000001, -0, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=305; tryItOut("for (var p in o1) { try { this.v0 = Object.prototype.isPrototypeOf.call(a0, b1); } catch(e0) { } try { e0.__proto__ = v0; } catch(e1) { } t2[7] = this.f2; }\n");
/*fuzzSeed-85495475*/count=306; tryItOut("(new  \"\"  + \"\\u8764\".valueOf(x));");
/*fuzzSeed-85495475*/count=307; tryItOut("\"use strict\"; \"use asm\"; a2.pop();");
/*fuzzSeed-85495475*/count=308; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.atan2(((Math.clz32((( + mathy2((Math.min(((x * -0x100000001) | 0), mathy1(((Math.sign(y) | 0) | 0), Math.hypot(mathy0(x, 0x100000001), y))) >>> 0), Math.fround((( - Math.fround(Number.MAX_SAFE_INTEGER)) == y)))) >>> 0)) | 0) >>> 0), (Math.fround((Math.fround(Math.fround(Math.pow(Math.fround(Math.fround(Math.hypot(( + Math.acosh(-0x100000001)), Math.expm1(((( + y) != ( + Math.imul((Number.MIN_SAFE_INTEGER >>> 0), (1/0 >>> 0)))) | 0))))), Math.pow(Math.atan2(x, x), y)))) ? (Math.imul(Math.atan2(x, Math.imul(( + (x ^ x)), ( + x))), ( + ((((y >>> 0) !== (y | 0)) >>> 0) - ( + (( + 0.000000000000001) != (Math.min(x, (x | 0)) | 0)))))) | 0) : Math.atan2(Math.atan(((x | 0) === (x | 0))), Math.fround(( ~ x))))) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=309; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-85495475*/count=310; tryItOut("\"use strict\"; for (var p in g0.h0) { a0 = arguments; }");
/*fuzzSeed-85495475*/count=311; tryItOut("/*RXUB*/var r = /\u5044(?=\\3{2,}){3,3}\\b*?|(\\S|\\1+?|(?![\\n\\b\\D\\D])*)|(?=[^\\d\\u0029\\u007E-\ud314]|(?:\\3*^))|(${4,})/y; var s = \"\\u5024\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=312; tryItOut("if(timeout(1800).unwatch(\"callee\")) { if (new RegExp(\"\\\\cN|.[\\u2ea0-\\\\u9450]|[\\\\W]+?(?:.{4,}|(?=\\\\D){0})\", \"gyim\")) {Object.prototype.watch.call(e1, \"then\", f1); }} else /*tLoop*/for (let w of /*MARR*/[null, arguments.callee]) { yield true; }");
/*fuzzSeed-85495475*/count=313; tryItOut("mathy0 = (function(x, y) { return Math.imul(Math.fround(Math.max(Math.log1p(( ! Math.min((Math.pow(x, y) | 0), Math.fround((( - (Number.MAX_VALUE >>> 0)) >>> 0))))), Math.atan((Math.fround(Math.max(x, Math.fround(x))) >= Math.abs(Math.fround(Math.acosh(Math.fround(x)))))))), Math.log(Math.fround(Math.max(Math.fround(( + Math.tan(( + ( + Math.hypot(( + y), (y | 0))))))), Math.cos(-Number.MAX_SAFE_INTEGER))))); }); testMathyFunction(mathy0, /*MARR*/[ '' ,  '' , Infinity, NaN, x, NaN,  '' , Infinity, [1],  '' , NaN, x, Infinity,  '' , [1], NaN, x, x, NaN, Infinity,  '' ,  '' , [1], NaN, Infinity, Infinity, Infinity, NaN, NaN, NaN,  '' ]); ");
/*fuzzSeed-85495475*/count=314; tryItOut("\"use strict\"; print(v0);");
/*fuzzSeed-85495475*/count=315; tryItOut("s2 += o1.o1.s2;");
/*fuzzSeed-85495475*/count=316; tryItOut("{ void 0; void gc(this); }");
/*fuzzSeed-85495475*/count=317; tryItOut(";");
/*fuzzSeed-85495475*/count=318; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float32ArrayView[4096]) = ((4097.0));\n    i1 = (((((((0x73084f36) % (0xd93f9838)) << ((/*FFI*/ff(((Infinity)))|0)-(i0)-(i1))))) >> ((/*FFI*/ff()|0)+(!(/*FFI*/ff(((imul((i0), (i0))|0)), ((9.44473296573929e+21)), ((((0x6fd047bb)) & ((0xde8c99e7)))), ((((0xa0a6f4d))|0)), ((-4.835703278458517e+24)), ((-2.0)))|0)))));\n    {\n      {\n        i0 = ((3.8685626227668134e+25));\n      }\n    }\n    {\n      i0 = (i0);\n    }\n    i0 = (i0);\n    (Uint32ArrayView[1]) = ((Int16ArrayView[0]));\n    (Int16ArrayView[4096]) = (((0x6f1cc9eb)));\n    i0 = ((0x3e3a69be));\n    i0 = ((i0) ? (i0) : ((0x30fcff20) >= (0xe5492841)));\n    return (((i0)*0xb3a9e))|0;\n    i0 = (i1);\n    i0 = (i1);\n    {\n      {\n        (Float64ArrayView[4096]) = ((+(-1.0/0.0)));\n      }\n    }\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: (decodeURI).call}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[-Infinity]); ");
/*fuzzSeed-85495475*/count=319; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=320; tryItOut("Object.defineProperty(this, \"g2\", { configurable: true, enumerable: false,  get: function() {  return this; } });");
/*fuzzSeed-85495475*/count=321; tryItOut("selectforgc(o2);Math.exp");
/*fuzzSeed-85495475*/count=322; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2(( + ( + Math.max(( + Math.fround(mathy2((((Math.trunc(x) >>> 0) < 0.000000000000001) >>> 0), Math.fround((Math.hypot((Math.pow(x, Math.fround(y)) >>> 0), (Number.MAX_VALUE >>> 0)) >>> 0))))), ( + Math.trunc(y))))), ( + Math.fround(((x * ( - Math.cosh((Math.fround(Math.max(Math.fround(( + Math.min(( + x), x))), Math.fround(x))) | 0)))) && ( + ( - ( + Math.sinh((((y >>> 0) >= (x >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy4, /*MARR*/[[], [], arguments.callee, [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], arguments.callee, arguments.callee, arguments.callee, [], []]); ");
/*fuzzSeed-85495475*/count=323; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ (((((Number.MIN_VALUE || ((((Math.min(Math.fround(y), (x >>> 0)) >>> 0) | 0) < (y | 0)) | 0)) | 0) !== (Math.hypot((Number.MAX_VALUE >> y), Math.fround((x | y))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy0, [0x0ffffffff, 0x100000001, 0x07fffffff, 2**53+2, -Number.MAX_VALUE, 1, -(2**53-2), Math.PI, 1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, -0x0ffffffff, 0x080000000, 0x100000000, 0x080000001, -1/0, 2**53-2, -0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, 0/0, Number.MAX_VALUE, -0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), 2**53, Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-85495475*/count=324; tryItOut("Object.defineProperty(this, \"o1\", { configurable: (x % 33 == 32), enumerable: (x % 14 != 8),  get: function() {  return new Object; } });");
/*fuzzSeed-85495475*/count=325; tryItOut("Object.preventExtensions(this.i0);");
/*fuzzSeed-85495475*/count=326; tryItOut("this.s0 = new String;");
/*fuzzSeed-85495475*/count=327; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.tan(Math.log10((( + ((( ! (Number.MIN_VALUE | 0)) !== x) >>> 0)) | 0))); }); testMathyFunction(mathy3, [-(2**53), -0x100000000, Math.PI, -0x07fffffff, -0, 2**53+2, Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 1.7976931348623157e308, -1/0, -0x100000001, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE, 2**53, 1, 0, 42, 0x080000000, 0x080000001, -0x080000001, -Number.MAX_VALUE, 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=328; tryItOut("mathy5 = (function(x, y) { return Math.min((Math.asinh((Math.tan((Math.fround(mathy0(Math.fround(x), Math.fround(((-Number.MIN_SAFE_INTEGER >>> 0) === (x >>> 0))))) | 0)) | 0)) >>> 0), ( - (mathy3(( + Math.fround(mathy1(Math.fround(0.000000000000001), Math.fround(y)))), ( + Math.sign(( + y)))) >>> 0))); }); ");
/*fuzzSeed-85495475*/count=329; tryItOut("/*infloop*/for(let e; \"\\uBA9C\"; /*RXUE*//(?:(?!\\w{3}){1})+?|(?:(?=.+?){1,4}){4,}/.exec(\"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\")) {print(eval(\"a\")); }");
/*fuzzSeed-85495475*/count=330; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.tanh((Math.cosh(Math.sqrt(x)) >>> 0)); }); testMathyFunction(mathy0, [2**53-2, 0x0ffffffff, Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 1/0, -(2**53), -0, Number.MAX_VALUE, -1/0, -0x0ffffffff, 0, Math.PI, -0x080000000, 0/0, 0x080000000, 0x07fffffff, -(2**53-2), -(2**53+2), -0x07fffffff, 42, 0.000000000000001, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1, -Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-85495475*/count=331; tryItOut("L:switch(x) { default: o2 + g1.h2;case this.__defineGetter__(\"x\", Array.prototype.some)\u000c.getOwnPropertySymbols(): break; case ((function sum_slicing(stvqwf) { ; return stvqwf.length == 0 ? 0 : stvqwf[0] + sum_slicing(stvqwf.slice(1)); })(/*MARR*/[new Number(1),  \"\" ,  \"\" ,  \"\" ,  \"\" , new Number(1),  \"\" , new Number(1),  \"\" , new Number(1),  \"\" , new Number(1), -0x2D413CCC, -0x2D413CCC, new Number(1), new Number(1),  \"\" , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC,  \"\" ,  \"\" ])): print(x);/*vLoop*/for (var urrewk = 0; urrewk < 55; ++urrewk) { var d = urrewk; print([1,,]); } break; case /\\d/ym: break; case let (b = 29) new RegExp(\"[^]\", \"i\"): break; case 1: break; for(var [z, a] = let (z =  /x/g ) this in /\\S*?\\2*+/) {print(x); }Array.prototype.shift.apply(this.a0, [a1]);break; case x.__defineGetter__(\"x\", \u000d(function(x, y) { \"use strict\"; \"use asm\"; return -Number.MAX_SAFE_INTEGER; })): e0.delete(g1);print(x);break; v0 = t2.length;break;  }");
/*fuzzSeed-85495475*/count=332; tryItOut("\"use strict\"; a1.pop(f1);");
/*fuzzSeed-85495475*/count=333; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (mathy0((mathy0(Math.max(Number.MAX_SAFE_INTEGER, ((Number.MAX_SAFE_INTEGER - (Math.fround(Math.imul(Number.MAX_VALUE, x)) >>> 0)) >>> 0)), ( + Math.cosh((Math.fround(( - ( + x))) >= y)))) >>> 0), Math.fround(Math.acos(mathy0(mathy0(Math.fround(y), ( + Math.hypot(( + (-(2**53) != y)), 1.7976931348623157e308))), ( + Math.min(( + (((-0x0ffffffff >>> 0) + ((Math.atan(0x080000000) >>> 0) | 0)) | 0)), ( + (Math.tanh((( ~ (-Number.MAX_SAFE_INTEGER % x)) >>> 0)) >>> 0)))))))) >>> 0); }); testMathyFunction(mathy1, [-1/0, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, -(2**53), Number.MAX_VALUE, -(2**53+2), -0, 0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, -(2**53-2), 0x0ffffffff, -0x100000000, 0x07fffffff, Number.MIN_VALUE, 2**53+2, 2**53-2, 1, Math.PI, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x080000001, -0x080000000, 42, 1/0, 1.7976931348623157e308, 0/0, -0x100000001]); ");
/*fuzzSeed-85495475*/count=334; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ /*FARR*/[.../*MARR*/[['z'], Math, null, ['z']], .../*MARR*/[ 'A' , function(){}, function(){}, (-1/0),  'A' , function(){}, function(){}, x,  'A' , function(){}, x, (-1/0), 0.000000000000001], , , x].sort(function(y) { yield y; print(c = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: Function, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function shapeyConstructor(zduhoa){return this; }, }; })(window),  '' ));; yield y; })); }); testMathyFunction(mathy2, [0.1, [0], ({valueOf:function(){return 0;}}), (new Number(0)), NaN, objectEmulatingUndefined(), 1, ({toString:function(){return '0';}}), '', '\\0', false, -0, null, (new Boolean(false)), /0/, (new String('')), (new Number(-0)), '0', ({valueOf:function(){return '0';}}), (new Boolean(true)), undefined, [], (function(){return 0;}), 0, '/0/', true]); ");
/*fuzzSeed-85495475*/count=335; tryItOut("mathy0 = (function(x, y) { return Math.round(Math.fround((((Math.fround(Math.trunc(Math.fround(( - y)))) >>> 0) != (Math.min(y, ( + Math.tanh(( + y)))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-85495475*/count=336; tryItOut("/*infloop*/for((makeFinalizeObserver('tenured'));  /x/g ; [2]) var y = (({y: undefined}) **= x = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"(?:\\\\cP|\\\\2+)\", \"gim\")), Float32Array,  \"\" ));((void shapeOf(x)));");
/*fuzzSeed-85495475*/count=337; tryItOut("/*bLoop*/for (qglpxn = 0; qglpxn < 18; ++qglpxn) { if (qglpxn % 18 == 15) { m2.has(g1.e1); } else { L:switch(new (/*wrap1*/(function(){ \"use strict\"; /*MXX3*/g0.String.name = g1.String.name;return function(y) { return new RegExp(\"(?![^][^-\\u377e\\\\D\\\\r\\\\u0092-\\\\u00b3]+)\\\\d**?|\\\\3|\\\\3?\", \"i\") }})()).call(this, window)((undefined.valueOf(\"number\")))) { default: break; case 4: (void schedulegc(g2));case 8: e2.add(e);case 9: break; case 7: break; case (/*MARR*/[(0x50505050 >> 1), (0x50505050 >> 1), null, (1/0), null, null, (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), null, (0x50505050 >> 1), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null].map(({/*TOODEEP*/}), null)): print(x);break;  } }  } ");
/*fuzzSeed-85495475*/count=338; tryItOut("v2 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-85495475*/count=339; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (Math.fround((Math.fround(Math.exp((( + Math.tan(( + Math.fround(Math.min(-(2**53), (( + -0x07fffffff) || y)))))) == x))) || Math.fround(Math.exp((( - (( + (1.7976931348623157e308 | 0)) | 0)) < ( ~ y)))))) & (Math.asinh(Math.log(x)) | 0))); }); testMathyFunction(mathy1, [-0x0ffffffff, -Number.MAX_VALUE, 0x080000001, 0, 0x0ffffffff, -(2**53), 1.7976931348623157e308, 42, -0x100000000, -1/0, Number.MIN_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, 2**53, -(2**53-2), -0x080000000, -(2**53+2), 0/0, 0x07fffffff, 0x100000000, 0.000000000000001, -0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, Math.PI, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -0, 2**53+2]); ");
/*fuzzSeed-85495475*/count=340; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"function g0.f1(o0)  { \\\"use strict\\\"; return (function (y) { yield (4277) } )() } \");function y()\"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 33554433.0;\n    var i3 = 0;\n    d2 = (32769.0);\n    {\n      d1 = (-((NaN)));\n    }\n    i0 = ((0xfa741dfb) ? (1) : (i0));\n    d2 = (d2);\n    i3 = (((((0x415245b6) ? (0x82bdd7a0) : (i0))+((((i3)+(0xfa253f3b))>>>(((0x274475c1) != (0xb5c6352b))+(0xffffffff))) <= (((-0x8000000))>>>((!(-0x8000000)))))) >> (((((((0xffffffff))>>>((0xfb38eb07))) % (((0xeee62545))>>>((-0x8000000)))) << (-0xd1c5a*((0xb76cd6ab) ? (0x6e9d3e21) : (0xf9cb97d2)))))-(i3))));\n    {\n      {\n        (Float32ArrayView[1]) = (((new (this)())));\n      }\n    }\n    {\n      (Float32ArrayView[(((0x9ec552b7) > (0x8df55759))-(0xffffffff)) >> 2]) = ((+(1.0/0.0)));\n    }\n    i3 = (i0);\n    return +((+((-4.835703278458517e+24))));\n    i0 = ((0xee409d28));\n    return +((+abs(((d2)))));\n  }\n  return f;print(x);function of(x) { return (4277).eval(\"/* no regression tests found */\") } \u3056 = a;try { throw new RegExp(\"(?!\\\\u00fC)|(\\\\w{68719476735,})[^\\\\D\\u00f8-\\u2cae]|[^]|\\\\cC{4}(?:(?:\\\\d))|\\\\b|[^p-\\ud0fc\\u000d\\\\W]\", \"gyi\"); } catch(e if window) { {}\u0009 } catch(\u3056) { (\u3056); } finally { yield; } ");
/*fuzzSeed-85495475*/count=341; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"('fafafa'.replace(/a/g, Array.prototype.findIndex))\");");
/*fuzzSeed-85495475*/count=342; tryItOut("var zjqlwt = new SharedArrayBuffer(4); var zjqlwt_0 = new Int8Array(zjqlwt); zjqlwt_0[0] = 17; var zjqlwt_1 = new Int16Array(zjqlwt); print(zjqlwt_1[0]); zjqlwt_1[0] = 6; var zjqlwt_2 = new Uint8Array(zjqlwt); var zjqlwt_3 = new Int16Array(zjqlwt); print(zjqlwt_3[0]); zjqlwt_3[0] = -26; var zjqlwt_4 = new Int32Array(zjqlwt); var zjqlwt_5 = new Uint32Array(zjqlwt); print(zjqlwt_5[0]); var zjqlwt_6 = new Uint8ClampedArray(zjqlwt); zjqlwt_6[0] = -26; var zjqlwt_7 = new Int16Array(zjqlwt); print(zjqlwt_7[0]); zjqlwt_7[0] = -19; this.m2.set(f2, b1);(8388609);({a2:z2});delete this.i1[\"__count__\"];v0 = Object.prototype.isPrototypeOf.call(o1.o2.g0, v2);yield  \"\" ;false;for (var v of s0) { m2.has(o1.o0.h1); }( \"\" );");
/*fuzzSeed-85495475*/count=343; tryItOut("a1.shift();");
/*fuzzSeed-85495475*/count=344; tryItOut("\"use strict\"; d = x, b = /*UUV2*/(x.clz32 = x.fontcolor), x;e0 = x;");
/*fuzzSeed-85495475*/count=345; tryItOut("\"use strict\"; (arguments -  /x/ );");
/*fuzzSeed-85495475*/count=346; tryItOut("\"use strict\"; { void 0; minorgc(false); } h0.getPropertyDescriptor = (function() { for (var v of this.o1) { try { v0 = g1.eval(\"/* no regression tests found */\"); } catch(e0) { } try { a0.toString = (function() { try { v0 = evaluate(\"function f1(g1.e1) w\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: /\\B|\\2{0,}[^]+?(?=\\w?.)/ym, sourceIsLazy: d, catchTermination: false })); } catch(e0) { } /*ADP-1*/Object.defineProperty(a0, ({valueOf: function() { v1 = a0.length;return 7; }}), ({get: /*wrap3*/(function(){ \"use strict\"; var ktsoqa = \"\\uE421\"; (function shapeyConstructor(aoqsxy){for (var ytqnmuydx in this) { }{ return  \"\" ; } this[\"c\"] = arguments;this[null] = encodeURIComponent;delete this[null];this[\"__proto__\"] = function(y) { yield y; x;; yield y; };if (aoqsxy) delete this[null];Object.preventExtensions(this);delete this[-16];delete this[\"arguments\"];return this; })(); }), set: function(y) { \"use asm\"; for (var v of m1) { v0 = (p2 instanceof g2.b1); } }})); return g2; }); } catch(e1) { } try { v0 = new Number(4); } catch(e2) { } this.a2 = []; } return f1; });");
/*fuzzSeed-85495475*/count=347; tryItOut("\"use strict\"; a2 = new Array;");
/*fuzzSeed-85495475*/count=348; tryItOut("mathy5 = (function(x, y) { return Math.fround(( ! ( + Math.pow(mathy1(Math.max(y, (((-0x080000001 & x) | 0) || Math.sinh(x))), ( + (( + ( + mathy4(( + Math.min((( ! (-0x07fffffff | 0)) | 0), y)), ( + x)))) | ( + Math.atan2(Number.MIN_VALUE, x))))), Math.fround(Math.log(Math.fround(Math.cbrt((-0x100000000 | 0))))))))); }); testMathyFunction(mathy5, [2**53+2, 2**53, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 0.000000000000001, -0x100000001, -(2**53), -0, -0x0ffffffff, 2**53-2, 0x07fffffff, -0x07fffffff, -0x080000001, 0, 1, Number.MIN_VALUE, 0/0, -(2**53-2), 0x080000000, Math.PI, 0x080000001, -0x080000000, -(2**53+2), -1/0, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-85495475*/count=349; tryItOut("o2.__proto__ = g0;");
/*fuzzSeed-85495475*/count=350; tryItOut("\"use strict\"; with({y: Math.asin(/\\1*|(?=\\2)/gym)})/* no regression tests found */");
/*fuzzSeed-85495475*/count=351; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = this.s1; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=352; tryItOut("mathy5 = (function(x, y) { return (((( ~ Math.fround(mathy4(( + (x * Math.fround((Math.atan2((x | 0), ( + y)) | 0)))), Math.fround((mathy2(y, x) | 0))))) | 0) ? (Math.atan2(((((2**53 >>> 0) <= ((( - Math.atan2(y, x)) ? x : Math.log2(Math.sin(Math.fround(x)))) >>> 0)) >>> 0) >>> 0), Math.imul(y, ( ! ( + (x | y))))) >>> 0) : (( - Math.max((Math.hypot((y >>> 0), y) >>> 0), Math.min(y, Math.fround(0.000000000000001)))) ** Math.max(Math.sinh(((0.000000000000001 | 0) ? (x | 0) : (x | 0))), y))) <= Math.min(( ! (( + Math.min((x ** Math.fround((x >>> (0x080000000 | 0)))), 0x0ffffffff)) >>> 0)), Math.fround(Math.max((Math.log1p(x) >>> 0), (Math.cosh((y >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 2**53-2, 0x080000001, 0/0, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), 0x080000000, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, 1, -0x100000001, 42, -1/0, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000001, Math.PI, 0, -0x100000000, 0.000000000000001, -0, -(2**53+2), 0x0ffffffff, 1/0, -0x0ffffffff, Number.MIN_VALUE, 2**53+2, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=353; tryItOut("mathy5 = (function(x, y) { return (( + (Math.hypot(y, ((Math.min(x, 42) ? (Math.cbrt((Math.fround(y) <= (mathy2(x, -Number.MIN_VALUE) >>> 0))) >>> 0) : (( ! x) >>> 0)) | 0)) || Math.abs(( + y)))) , ( ~ ( + Math.fround(( + Math.fround(Math.hypot(Math.fround(( ~ x)), x))))))); }); testMathyFunction(mathy5, [-0x080000000, 1/0, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -(2**53), -0x100000000, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, -0x080000001, 1.7976931348623157e308, 42, 0x0ffffffff, -1/0, 0.000000000000001, -0, Number.MAX_VALUE, -0x100000001, 2**53-2, -Number.MAX_VALUE, 0x080000000, 0, 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), -(2**53-2), 2**53+2, 0x100000000]); ");
/*fuzzSeed-85495475*/count=354; tryItOut("\"use strict\"; o1.v1.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Uint32ArrayView[0]) = ((0xa09ae86)+(i2)+((~~(-3.022314549036573e+23))));\n    i0 = (i2);\n    {\n      i2 = (0x5ef96795);\n    }\n    i0 = ((~((0xe531c048)-(i2))) <= (((i2)) & ((i0)+(0x2108cd74))));\n    (Float32ArrayView[(((-0x8000000) ? (-0x8000000) : ((-0x8000000) == (-0x1230b6c)))-(0xfadfaf25)+(i0)) >> 2]) = ((1.888946593147858e+22));\n    d1 = (+(((i0))>>>((0xff206304))));\n    switch ((imul((eval(\"mathy3 = (function(x, y) { return Math.imul(( + Math.acos(( + Math.fround(mathy2(x, Math.fround((mathy1(((( ! (y | 0)) | 0) | 0), (mathy1(( + Math.clz32(( + y))), ( + mathy2(x, Math.fround(y)))) | 0)) | 0))))))), Math.fround(Math.fround(mathy2((Math.pow(((( + (( + (Math.fround((-0x080000001 | 0)) | 0)) | 0)) , ( + Math.fround(y))) >>> 0), (y | 0)) >>> 0), Math.fround(( + Math.max(Math.asinh(Math.min(-0x0ffffffff, x)), x))))))); }); testMathyFunction(mathy3, [-0x07fffffff, 1.7976931348623157e308, -0x080000000, -0x100000000, Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 42, -Number.MAX_VALUE, 0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -(2**53+2), 0/0, 0.000000000000001, 0x080000000, 1, -0x100000001, -0x080000001, 1/0, -0, 0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -Number.MIN_VALUE, 2**53-2, -(2**53), 2**53+2, Math.PI]); \", timeout(1800))), (i0))|0)) {\n    }\n    d1 = (+(1.0/0.0));\n    return +((d1));\n  }\n  return f; });");
/*fuzzSeed-85495475*/count=355; tryItOut("\"use strict\"; v1 + '';");
/*fuzzSeed-85495475*/count=356; tryItOut("a0.push(h2);");
/*fuzzSeed-85495475*/count=357; tryItOut("mathy0 = (function(x, y) { return Math.fround((((x / y) ? ( + (( + Math.trunc(Math.fround(Math.atan2(x, Math.log2(( + ( ! y))))))) !== ( - (Math.cbrt(y) | 0)))) : Math.log1p(Math.fround(( - (Math.fround((( + x) ? ( + (Math.fround(Math.max(x, 0x100000000)) == x)) : ( + x))) >>> 0))))) ? ( + ( ~ Math.max(Math.ceil(Math.fround(x)), ( ! -0x100000000)))) : Math.fround(Math.max(Math.fround((Math.fround(Math.pow(x, ( - y))) ? Math.fround((Math.min((0.000000000000001 >>> 0), (Math.fround(Math.acos(Math.pow(Math.sin(x), y))) >>> 0)) >>> 0)) : Math.fround((((1.7976931348623157e308 >>> 0) / (Math.max(2**53, x) >>> 0)) >>> 0)))), ((( + (y ? x : 42)) <= y) / ( ! ( ~ y))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 2**53, 1, 1/0, Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000001, -0x100000000, -0x07fffffff, 2**53-2, -0x080000000, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, Math.PI, -0x0ffffffff, -(2**53+2), 2**53+2, 42, Number.MAX_SAFE_INTEGER, 0, -0, 0x100000000, 0/0, -(2**53-2), 0x080000000, 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-85495475*/count=358; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.atan(Math.fround(Math.atan2(mathy4(( + Math.fround(( + Math.fround(Math.fround(Math.pow(Math.fround(y), Math.fround(x))))))), Math.fround(mathy3(Math.fround(y), ( + y)))), Math.pow(( + Math.atan2(Math.fround((( + 0x080000001) == ( + Math.min(y, 0x0ffffffff)))), (y >>> 0))), x)))); }); testMathyFunction(mathy5, [1, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -0x080000000, 0x0ffffffff, -Number.MAX_VALUE, 0.000000000000001, 0x080000000, -(2**53-2), -0x0ffffffff, -(2**53), 1.7976931348623157e308, 0x100000000, 0x100000001, Math.PI, 2**53-2, 1/0, Number.MAX_VALUE, 0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, -0, -0x080000001, -0x07fffffff, 2**53+2, 0/0, 2**53]); ");
/*fuzzSeed-85495475*/count=359; tryItOut("testMathyFunction(mathy5, /*MARR*/[5, x, objectEmulatingUndefined(), x, 5, x, 5, 1e+81, x, objectEmulatingUndefined(), 1e+81, 1e+81, objectEmulatingUndefined(), 1e+81, 1e+81, objectEmulatingUndefined(), 5, 1e+81, 5, 5, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, true, objectEmulatingUndefined(), x, 5]); ");
/*fuzzSeed-85495475*/count=360; tryItOut("mathy2 = (function(x, y) { return Math.hypot(Math.max(( ! ( + Math.round(x))), Math.hypot((Math.acosh(Math.imul(Math.fround(Math.expm1((x | 0))), x)) >>> 0), (Math.abs((mathy0(( + x), ( + y)) >>> 0)) | 0))), ( + (( + ( - (x | 0))) !== ( + (Math.hypot(( + (((mathy1(( + 0x080000000), -(2**53+2)) | 0) >> (x | 0)) % Math.pow(mathy0((y >>> 0), x), x))), ( + y)) | 0))))); }); testMathyFunction(mathy2, [-0x080000000, 1, -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 42, Math.PI, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, 2**53-2, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, -(2**53), 0, 0x0ffffffff, 0x080000001, -0, 0/0, -0x0ffffffff, -0x100000001, 1/0, -0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, -1/0, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=361; tryItOut("i0.next();");
/*fuzzSeed-85495475*/count=362; tryItOut("mathy0 = (function(x, y) { return Math.sqrt(( + Math.sin(( ! (y == ( + (Math.atan(2**53-2) !== ( + -0x100000001)))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0x080000001, -0x100000001, 1, 2**53-2, 0x080000000, -(2**53+2), 0x100000001, 1/0, 0x100000000, 0/0, 0x07fffffff, -(2**53), -1/0, 42, Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 2**53, -0x080000001, Number.MIN_VALUE, 2**53+2, -0x080000000, 0x0ffffffff, 0, -0x100000000, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=363; tryItOut("var w, a, w, \u3056, d, x, e, d;g1 = this.g2.objectEmulatingUndefined();");
/*fuzzSeed-85495475*/count=364; tryItOut("m1.__proto__ = g1;");
/*fuzzSeed-85495475*/count=365; tryItOut("\"use strict\"; for(z = (/*MARR*/[function(){}, -Infinity, -Infinity, 4, -Infinity, 4, 4, -0x07fffffff, function(){}, 4, 4, -0x07fffffff, -Infinity, -0x07fffffff, 4, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, 4, function(){}, function(){}, 4, 4, -0x07fffffff, -0x07fffffff, 4,  \"\" , -Infinity, -Infinity, -Infinity,  \"\" ,  \"\" , 4, function(){}, function(){}, -Infinity, -0x07fffffff,  \"\" ,  \"\" , -Infinity, 4, function(){}, -Infinity, -Infinity, 4, function(){}, 4, 4, -Infinity,  \"\" ,  \"\" , 4,  \"\" , -Infinity, -0x07fffffff, -0x07fffffff, -0x07fffffff, 4, -0x07fffffff].sort(Object.prototype.toLocaleString, -8)) in c|=\"\\uACEE\") {t2 = g0.objectEmulatingUndefined();{ void 0; disableSPSProfiling(); } }");
/*fuzzSeed-85495475*/count=366; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.sin(( + (mathy2((((-Number.MAX_SAFE_INTEGER >>> 0) , (((y ? Math.fround(y) : (( ~ 0x0ffffffff) | 0)) | 0) >>> 0)) >>> 0), (( ~ Math.fround((1/0 >= y))) ** Math.fround((-(2**53) & Math.fround(Number.MIN_SAFE_INTEGER))))) / (Math.atan2(x, (y | Math.log(y))) | 0))))); }); ");
/*fuzzSeed-85495475*/count=367; tryItOut("\"use strict\"; false;");
/*fuzzSeed-85495475*/count=368; tryItOut("this.i2.next();");
/*fuzzSeed-85495475*/count=369; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=370; tryItOut("{v0 = Infinity; }");
/*fuzzSeed-85495475*/count=371; tryItOut("\"use strict\"; /*MXX1*/o0 = g0.String.fromCodePoint;");
/*fuzzSeed-85495475*/count=372; tryItOut("\"use strict\"; a2 = a0.filter((function() { t2.set(a2, 15); return g0; }), a1, g0.o2, m1);");
/*fuzzSeed-85495475*/count=373; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-85495475*/count=374; tryItOut("\"use strict\"; \"use asm\"; /*iii*/const d = new RegExp(\"\\\\D+\\\\2\", \"\");/*RXUB*/var r = /(?!(?=(?=\\D)?)(?!\\1?\\b|(?:(\ucb5a)))|\\d|(?=\\D[\\u0071-\\ua599\\d\\\u646e].)[^]{2}{3})/g; var s = \"0\"; print(s.replace(r, '', \"\")); print(r.lastIndex); /*hhh*/function fmgemk(c = a\n == z ** z, [, x, ]){;}");
/*fuzzSeed-85495475*/count=375; tryItOut("/*MXX1*/Object.defineProperty(this, \"o0\", { configurable: false, enumerable: false,  get: function() {  return g2.String.prototype.toUpperCase; } });");
/*fuzzSeed-85495475*/count=376; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.abs(Math.hypot((( - (Math.pow(y, Math.fround(( ! Math.fround(-0)))) >>> 0)) >>> 0), ( ~ Math.fround(Math.fround(Math.round((x >>> 0))))))); }); testMathyFunction(mathy3, /*MARR*/[new Number(1), new Number(1), ({}), ({}), ({}), ({}), ({}), ({}), ({}), new Number(1), new Number(1), new Number(1), ({}), ({}), new Number(1), ({}), ({}), ({}), new Number(1), ({}), ({}), ({}), new Number(1)]); ");
/*fuzzSeed-85495475*/count=377; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    i1 = ((((i0)-(0x9396e933)) << ((i1)-(i1))) > (((Uint32ArrayView[1])) | (((((0x3796edef) ? (0x3c41dede) : (0xfbd1f8f0))-(!(0xf9ff6fae)))>>>((i1)*0x3d1f8)) / ((((0xb4af87c4) > (0x0)))>>>(((0x5abbe594) ? (0xff5efafd) : (0x9693d820)))))));\n    i1 = (i1);\n    return +((17592186044416.0));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x07fffffff, 2**53-2, -0x0ffffffff, 0x080000000, -(2**53-2), 42, -Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, 0x100000001, -0x100000000, 0x0ffffffff, 0x080000001, 1.7976931348623157e308, -1/0, 1/0, 0, Math.PI, -Number.MIN_VALUE, 0x07fffffff, 0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 2**53, -0x100000001, -(2**53), 0/0, 2**53+2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=378; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - (( + Math.trunc(( + ( ! -0x100000000)))) ? (Math.tanh((Math.hypot((( + Math.atan2(( + Math.fround((Math.fround(( ! y)) % Math.fround(y)))), ( + ( - 2**53+2)))) >>> 0), (x >>> 0)) >>> 0)) >>> 0) : ( ! (((( + 1/0) != (( + x) >>> 0)) >>> 0) | 0)))); }); testMathyFunction(mathy4, /*MARR*/[new Number(1.5),  /x/ ,  /x/ , [], x]); ");
/*fuzzSeed-85495475*/count=379; tryItOut("Array.prototype.push.call(a1, b0, o2, e1);");
/*fuzzSeed-85495475*/count=380; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(t2, b0);");
/*fuzzSeed-85495475*/count=381; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    switch ((~~(d1))) {\n      default:\n        d0 = (+(-1.0/0.0));\n    }\n    d1 = (((d1)) % ((((d0)))));\n    {\n      d0 = (d1);\n    }\n    d0 = (d0);\nm2.set(a2, m0);    (Int8ArrayView[((0x10445413)) >> 0]) = (((0x51debbad) > (0x28273deb))+(/*FFI*/ff(((d0)), ((((0x88084d35)+(0xffffffff)+(0xffffffff)) >> (((0xb97ff6bd))+(-0x8000000)+(0x8564307c)))), ((((d1)) / ((-((Float64ArrayView[((0x655b1e6e)) >> 3])))))), ((imul(((((0xc85e2d73))>>>((0xfae57847)))), (0xe0ff6102))|0)), ((imul(((0x7d88af5) <= (0x37d1cd1e)), ((1.5474250491067253e+26) != (35184372088833.0)))|0)), ((((0xafef059f)) ^ ((0xbb1d6d5)))), (((-3.022314549036573e+23) + (2147483649.0))), ((-6.189700196426902e+26)), ((1073741825.0)), ((4.835703278458517e+24)), ((-1.1805916207174113e+21)), ((9.671406556917033e+24)), ((-33.0)), ((524289.0)), ((-1073741825.0)), ((16384.0)), ((-281474976710655.0)), ((-16777217.0)), ((18446744073709552000.0)))|0)-(0xffffffff));\n    {\n      {\n        d0 = (d0);\n      }\n    }\n    d1 = (d1);\n    switch ((((0xf8b4a29b)+(0xf9b066bc)) >> (((-0x8000000))+(!(0x338f0a35))))) {\n      case -2:\n        {\n          d1 = (d0);\n        }\n    }\n    d1 = (+/*FFI*/ff(((~((((0xff5fae42)-(0xf2db9019))>>>(((abs((0x5fe46435))|0) < (((0xf81bfa28)) ^ ((0x7ade0fc))))-((0x764bbf51) != (((0xf836eb0c)) << ((0x3df09da1)))))) / ((((((Int16ArrayView[0]))>>>((0x198da7) % (0x698860cb)))))>>>((0xb19ecf26)))))), ((d1)), ((d1)), ((( /x/ .watch(new String(\"-11\"), Number.prototype.toPrecision)) % ((((d0)) % ((d1)))))), ((-0x8000000)), ((+(((-0x8000000)+(0x8cb9199a))>>>((/*FFI*/ff()|0))))), ((x) = yield x |= Math.imul(( + Math.atan2(Math.imul(x, Math.imul(( + x), Math.fround(Math.atan2(Math.fround(x), Math.fround(0/0))))), (Math.fround(( ! Math.fround(x))) | 0))), (Math.asin(( + ( ~ x))) >>> 0))), ((d1)), ((((0x1473fe1a)) << ((0xffffffff)))), ((64.0)), ((1.5)), ((1125899906842625.0)), ((-9.0)), ((-67108864.0)), ((65.0)), ((1.888946593147858e+22)), ((2147483649.0)), ((72057594037927940.0)), ((129.0)), ((-8589934593.0))));\n    d1 = (d1);\n    (Float32ArrayView[1]) = ((129.0));\n    (Int32ArrayView[2]) = (-0xf5b9*((((/*FFI*/ff(((({ get c(w, ...y) { yield (4277) }  }))), ((+(((-0x8000000)) >> ((0xf84b5283))))))|0)-(0x2be449a7)) | ((0xaa8efb66)-(0xf9c7cecb)))));\n    return +((d1));\n  }\n  return f; })(this, {ff: Date.prototype.setUTCMinutes}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x07fffffff, 2**53+2, 42, -0x100000001, 0x080000001, -(2**53-2), 0x100000001, -0x07fffffff, 0/0, 2**53, -(2**53+2), 2**53-2, -Number.MIN_SAFE_INTEGER, 0, 1, Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -1/0, 0x100000000, 0.000000000000001, -0, 0x080000000, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-85495475*/count=382; tryItOut("mathy3 = (function(x, y) { return ( - ( ! (( + Math.imul(Math.fround(((Math.fround(Math.exp(y)) | 0) !== y)), (-(2**53+2) >>> 0))) / (((x | 0) >= ( + (((( + x) | 0) * x) | 0))) | 0)))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x07fffffff, 0x100000000, 2**53, -1/0, -0, -(2**53), Number.MAX_SAFE_INTEGER, 42, 1/0, -0x100000000, 0x07fffffff, -Number.MAX_VALUE, 0, 0x100000001, -(2**53+2), 0.000000000000001, 0x080000000, 0/0, -0x100000001, 2**53-2, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, 1, -Number.MIN_VALUE, Math.PI, 0x080000001]); ");
/*fuzzSeed-85495475*/count=383; tryItOut("for (var p in i1) { try { f0(g1.i2); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(m1, o1); } catch(e1) { } try { for (var v of p1) { try { v0 = t0.length; } catch(e0) { } selectforgc(o0); } } catch(e2) { } Object.prototype.unwatch.call(o2.b1, \"callee\"); }s1 + v1;");
/*fuzzSeed-85495475*/count=384; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=385; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var exp = stdlib.Math.exp;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Float32ArrayView[0]) = ((((4097.0)) - ((-2305843009213694000.0))));\n    d1 = (+pow(((Float32ArrayView[((0x9be54c7e)+(i2)) >> 2])), ((+/*FFI*/ff(((((0x3a6579bc) / (abs((abs((~((0xfc89ae96))))|0))|0)) >> ((0x6dc2d768)-((-3.8685626227668134e+25) <= (((281474976710657.0)) / ((-2147483649.0))))))), ((d1)), ((d1)), ((+((d1)))), (((0xfc273f17) ? (-1.25) : (2.3611832414348226e+21))), ((+exp(((d1))))))))));\n    {\n      (Float64ArrayView[1]) = ((-524289.0));\n    }\n    i0 = ((imul((i2), ((imul((0xfda8c35f), (i0))|0)))|0) > (((i2)) | (((((0xff956691)) & ((0xc8edb18e))) != (((0xa344a1bf)) | ((0xff2ab1d4))))+((~((-0x8000000)+(0xfcc34bf9)+(0xc3eb01ae))) <= (~(((0x1a683284)))))-((((((-281474976710657.0)) * ((68719476737.0)))) - ((Float64ArrayView[4096])))))));\n    (Float32ArrayView[(((((i2)-((0xbc651116))) | (((0x4037abab) <= (0x51d325a3)))) != (imul(((-295147905179352830000.0) < (2.4178516392292583e+24)), (i0))|0))) >> 2]) = ((-2199023255553.0));\n    return ((-((i2) ? (((((0x21d64959) ? (0x429c8eba) : (0xb207c15a))*0x94cf5)>>>((0x0) % (((0x433555a1))>>>((-0x8000000)))))) : ((((+abs((((let (a = Math.asin(this)) ([/(?=\\2|.[^]{0})/gyi]))))))) * (((4277)))) != (17179869185.0)))))|0;\n  }\n  return f; })(this, {ff: (new Function(\";\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x080000001, Number.MIN_VALUE, 0x080000000, 0.000000000000001, 1/0, 1, -0x07fffffff, Math.PI, -Number.MIN_VALUE, 42, -0x100000001, -Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, -0x0ffffffff, 0x0ffffffff, -(2**53), 1.7976931348623157e308, 0/0, 0, Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, 0x07fffffff, 0x100000001, 2**53, -0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=386; tryItOut("\"use strict\"; e1.valueOf = this.f2;for (var v of a0) { try { g2.a0[({valueOf: function() { const v1 = r2.ignoreCase;return 7; }})]; } catch(e0) { } try { p2 + ''; } catch(e1) { } try { (void schedulegc(g2)); } catch(e2) { } a0[4]; }function x([], {}, w, NaN, x, w = \"\\u94A4\", x, \u3056, x, NaN, x, NaN, x, x = this, e, x, y, x =  /x/g , x, y, b, a, x, NaN = \"\\u8F30\", w, c, x =  \"\" , x, \u3056, b, NaN, a = \"\\uAEE9\", z = null, x, z, __count__ = eval, x, x = \"\\u3BAF\", w, x, x = null, eval = window, c, a, c, z =  /x/g , a, y, e, x, x, b, x, y, NaN, y, NaN, x, x, b, x, NaN, w, x, z, b = this, x, z, z, d = 0, z) { \"use strict\"; \"use asm\"; yield let (lognfd)  /x/g  } a1 + t0;");
/*fuzzSeed-85495475*/count=387; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-85495475*/count=388; tryItOut("/*MXX1*/o2.o1 = g2.Array.prototype.copyWithin;");
/*fuzzSeed-85495475*/count=389; tryItOut("Array.prototype.reverse.call(a2, e0);");
/*fuzzSeed-85495475*/count=390; tryItOut("");
/*fuzzSeed-85495475*/count=391; tryItOut("Array.prototype.splice.apply(a2, [f2, b1]);");
/*fuzzSeed-85495475*/count=392; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x100000001, 1/0, -(2**53), Math.PI, -0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, 0x100000001, 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -(2**53+2), 1, -1/0, 2**53-2, -Number.MIN_VALUE, 2**53, 0, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, -(2**53-2), Number.MAX_VALUE, -0x100000000, 2**53+2, -0x080000001, 42, 0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=393; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.pow(( + (Math.hypot(Math.log(y), (Math.tanh((y | 0)) | 0)) * Math.fround(Math.atan2(Math.fround((Math.max(x, 0x080000000) % Math.hypot(Math.fround(((( + y) === ( + 0.000000000000001)) | 0)), ( ~ x)))), (( ! y) | 0))))), ( ! Math.max(y, Math.fround(( ~ (( ~ y) | 0)))))); }); testMathyFunction(mathy0, [[0], (new Number(0)), 0.1, -0, (function(){return 0;}), objectEmulatingUndefined(), 1, '/0/', ({valueOf:function(){return 0;}}), undefined, (new Number(-0)), ({toString:function(){return '0';}}), '0', 0, false, true, ({valueOf:function(){return '0';}}), '\\0', /0/, (new String('')), NaN, (new Boolean(true)), null, '', (new Boolean(false)), []]); ");
/*fuzzSeed-85495475*/count=394; tryItOut("v2.__iterator__ = (function() { for (var j=0;j<24;++j) { f0(j%4==1); } });");
/*fuzzSeed-85495475*/count=395; tryItOut("m0 + '';");
/*fuzzSeed-85495475*/count=396; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atan((( ! (Math.fround(Math.imul(y, Math.fround(Math.max(Math.fround(Math.fround(Math.pow((0x100000001 >>> 0), ( + Math.atanh(( + x)))))), Math.fround(Number.MIN_VALUE))))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [1, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -0, -0x080000000, -0x080000001, 1.7976931348623157e308, -0x100000000, 2**53+2, -Number.MIN_VALUE, 0/0, 0x080000001, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 2**53, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, Math.PI, -(2**53-2), Number.MAX_VALUE, -1/0, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=397; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=398; tryItOut("\"use strict\"; m2.delete(a2);");
/*fuzzSeed-85495475*/count=399; tryItOut("v1 = Object.prototype.isPrototypeOf.call(h1, m0);");
/*fuzzSeed-85495475*/count=400; tryItOut("/* no regression tests found */\nlet x, x = x, e = new RegExp(\"(?=\\\\s)\", \"im\"), NaN = NaN = undefined, ivgzih, b, \u3056, juoimh;e2.__proto__ = s2;\n");
/*fuzzSeed-85495475*/count=401; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(((Math.clz32((((mathy1((Math.pow(Math.PI, mathy1(y, 0x080000001)) | 0), ( + ((x >>> (( - (y >>> 0)) >>> 0)) | ( + x)))) | 0) >= Math.max((Math.hypot(( + mathy1(y, ( + Number.MAX_SAFE_INTEGER))), (x | 0)) | 0), (( + ( ! ( + y))) >>> 0))) | 0)) | 0) * Math.fround(((( + Math.min((Math.round(( ! ((Math.exp(0/0) >>> 0) | 0))) >>> 0), ((((Math.atan2(x, (x | 0)) | 0) % -0x100000000) | 0) >>> 0))) < ((mathy0(x, (Math.atan(y) >>> 0)) * Math.pow(Math.atan2(( + 0x080000001), -Number.MIN_VALUE), Math.hypot(2**53-2, y))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-0x07fffffff, 0/0, -0x080000000, Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, 0x080000000, -0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, 0, 1.7976931348623157e308, 1, 2**53+2, 2**53-2, -0x0ffffffff, -0x080000001, 0.000000000000001, -(2**53+2), -(2**53), -1/0, -0x100000001, 42, 2**53]); ");
/*fuzzSeed-85495475*/count=402; tryItOut("\"use strict\"; for (var p in t2) { try { a0 = Array.prototype.filter.call(a2, (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (((70368744177663.0)) % (((d1) + (+(0xd92b1bab)))));\n    i2 = (0xf6d07262);\n    return +((+abs(((d1)))));\n    i0 = (i0);\n    return +((((+atan2(((1.0)), ((Float32ArrayView[2]))))) % ((((-65.0)) - ((-((3.022314549036573e+23))))))));\n    d1 = (-1048577.0);\n    i0 = ((0xfc69b093) ? (i0) : ((((0x5efde588) % (((0x483644e8))>>>((0x82d26e48))))>>>(e--)) >= (0x0)));\n    i0 = (i0);\n    i0 = (0xa3cd399b);\n    (Uint16ArrayView[((i0)+((~~(-2305843009213694000.0)))) >> 1]) = ((Uint8ArrayView[((i2)) >> 0]));\n    return +((+(-1.0/0.0)));\n  }\n  return f; }), f0); } catch(e0) { } delete h0.delete; }");
/*fuzzSeed-85495475*/count=403; tryItOut("\"use strict\"; /*oLoop*/for (let knmfxz = 0; knmfxz < 75; ++knmfxz,  /x/ ) { [1]; } ");
/*fuzzSeed-85495475*/count=404; tryItOut("/* no regression tests found */var y = x;");
/*fuzzSeed-85495475*/count=405; tryItOut("v0 = Array.prototype.reduce, reduceRight.call(a2, (function() { for (var j=0;j<72;++j) { o0.f1(j%5==1); } }), t0);");
/*fuzzSeed-85495475*/count=406; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ! (mathy1(Math.pow(Math.max(y, (y - Math.pow(x, y))), y), ( + Math.tanh(( + ((x != ( + (( + x) | ( + 0.000000000000001)))) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -(2**53-2), 0.000000000000001, -0, -Number.MIN_VALUE, 0, -(2**53), -0x100000001, 1, 1/0, -0x080000000, 0x07fffffff, 2**53, 0x0ffffffff, 2**53-2, -1/0, 0x100000000, -0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, Number.MIN_VALUE, 0/0, 42, -0x100000000]); ");
/*fuzzSeed-85495475*/count=407; tryItOut("g0.g1.offThreadCompileScript(\"delete y.b.eval(\\\"x\\\")\");");
/*fuzzSeed-85495475*/count=408; tryItOut("\"use strict\"; a0 = arguments.callee.arguments;");
/*fuzzSeed-85495475*/count=409; tryItOut("/*RXUB*/var r = /\\2/gy; var s = Object.defineProperties(); print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=410; tryItOut("\"use strict\"; \"use asm\"; ;");
/*fuzzSeed-85495475*/count=411; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( + (((Math.fround(Math.atan2(Math.fround(Math.cbrt(y)), ( + Math.tanh((x >>> 0))))) + Math.PI) | 0) === Math.pow(( ~ 0x100000001), Math.fround(Math.min(Math.fround(Math.sinh(y)), Math.fround(x))))))); }); testMathyFunction(mathy5, [(new Boolean(true)), objectEmulatingUndefined(), undefined, 0.1, [], NaN, -0, [0], (function(){return 0;}), '0', 0, (new Number(-0)), '\\0', null, ({valueOf:function(){return 0;}}), '', false, ({valueOf:function(){return '0';}}), (new String('')), (new Boolean(false)), true, 1, (new Number(0)), '/0/', ({toString:function(){return '0';}}), /0/]); ");
/*fuzzSeed-85495475*/count=412; tryItOut("var gptwpz = new SharedArrayBuffer(4); var gptwpz_0 = new Uint8ClampedArray(gptwpz); var gptwpz_1 = new Float64Array(gptwpz); gptwpz_1[0] = -25; a0[window |= \"\\u4EEF\".watch(\"constructor\", JSON.parse).getPrototypeOf([1])] = o2;");
/*fuzzSeed-85495475*/count=413; tryItOut("/*vLoop*/for (var lchder = 0; ((function ([y]) { })()) && lchder < 12; ++lchder) { var d = lchder; print(d); } v1 = (o0.s0 instanceof o0);");
/*fuzzSeed-85495475*/count=414; tryItOut(" for  each(let w in 36779836) {\u000ca1.length = 1; }");
/*fuzzSeed-85495475*/count=415; tryItOut("fdwkfh(let (c = -8) /$*(\\2)/gyi);/*hhh*/function fdwkfh(){if(\"\\uBB80\") {delete t0[\"freeze\"]; }}");
/*fuzzSeed-85495475*/count=416; tryItOut("\"use strict\"; g2.o2.v1 = t0.byteOffset;");
/*fuzzSeed-85495475*/count=417; tryItOut("");
/*fuzzSeed-85495475*/count=418; tryItOut("mathy1 = (function(x, y) { return ( ! ( ~ ((( + x) || ( + y)) ^ ( + Math.max(( + (Math.max(1/0, -(2**53+2)) >>> 0)), Math.pow(( + mathy0(( + x), (x | 0))), 0x07fffffff)))))); }); testMathyFunction(mathy1, [0x0ffffffff, 1, 42, -0x080000001, 0x080000000, 0x100000000, -0, 1.7976931348623157e308, 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0x07fffffff, -0x100000000, 0x100000001, -0x080000000, -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0x080000001, -0x100000001, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, 0/0, -(2**53), 0x07fffffff, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=419; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (((((x | 0) % (x | 0)) | 0) | 0) < ((( + (Math.fround(((-(2**53+2) | 0) != Math.fround(x))) | 0)) | 0) | 0))) , (((Math.atanh(( + ( - ( + (mathy0((x | 0), ( + ( + Math.imul(( + x), ( + y))))) | 0))))) | 0) ? ( + (( + Math.hypot(x, x)) + Math.sign(y))) : ((Math.hypot((Math.asinh(((x | 0) ? x : -Number.MAX_VALUE)) | 0), ((x > ( + ((y >>> 0) , ( + ( + ( + y)))))) | 0)) | 0) | 0)) | 0)); }); testMathyFunction(mathy2, [0.000000000000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, 1/0, 1.7976931348623157e308, 2**53, Math.PI, -(2**53-2), 0x07fffffff, 0x100000001, 42, 1, Number.MIN_VALUE, -0x080000000, 2**53-2, 0/0, 0, 0x0ffffffff, -0x07fffffff, -0x100000000, Number.MAX_VALUE, 0x080000001, -0x080000001, -(2**53+2), 2**53+2, -0, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=420; tryItOut("([,,]);");
/*fuzzSeed-85495475*/count=421; tryItOut("\"use strict\"; \"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return ( + (( + Math.min((Math.max(Math.fround(y), ((y ? Math.atanh(Math.log(x)) : x) >>> 0)) >>> 0), ( + ( ~ -0)))) - ( + Math.acosh(Math.fround(( + Math.log2(( + Math.pow(x, (Math.imul(y, 0) >>> 0)))))))))); }); testMathyFunction(mathy4, [-0x100000000, -Number.MIN_VALUE, -(2**53+2), -0x080000000, Number.MIN_VALUE, 1, Math.PI, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 0x080000000, 42, 0x100000000, -(2**53), 0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), 0x0ffffffff, 1/0, -1/0, 0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, 2**53, -0x07fffffff, 2**53-2, -0x0ffffffff, 2**53+2, -0]); ");
/*fuzzSeed-85495475*/count=422; tryItOut("/*bLoop*/for (cuhmep = 0; cuhmep < 21; ++cuhmep) { if (cuhmep % 9 == 2) { a2.__proto__ = o2;\nArray.prototype.sort.apply(a1, [(function() { a0.__proto__ = e2; return this.g2; }), a2]);\n; } else { b0 + ''; }  } ");
/*fuzzSeed-85495475*/count=423; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?![^])+?\\d|[^\\cI-\\u18dD]{4,}|[\u00a2-\uf40d\\cK\\S]{3,}|.{1}+)/gim; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-85495475*/count=424; tryItOut("for (var p in m0) { e0 = new Set(o1.p1); }");
/*fuzzSeed-85495475*/count=425; tryItOut("\"use strict\"; m1.has(h0);");
/*fuzzSeed-85495475*/count=426; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, 1, 0x080000001, 2**53-2, Math.PI, -Number.MAX_VALUE, -0x080000001, -(2**53), 2**53, 0x100000000, -0, 1/0, -0x0ffffffff, -0x07fffffff, 0.000000000000001, 0x0ffffffff, 42, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 0/0, -1/0, 0, -0x080000000, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-85495475*/count=427; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy1((Math.imul((Math.fround(Math.imul((( ~ (( + Math.imul(y, ( + y))) | 0)) | 0), (Math.expm1((( ! y) | 0)) >>> 0))) == ( + (( + Math.imul(-0x100000000, Math.fround(1.7976931348623157e308))) / ( + y)))), Math.min(1/0, (( ~ 0x080000000) | 0))) | 0), (mathy0((Math.min((( ! (y | 0)) | 0), (Math.acosh((( ! y) | 0)) | 0)) | 0), Math.fround(Math.acosh((Math.max(y, ( + Math.hypot(0x0ffffffff, (x < Math.fround(Math.acos(Math.fround(x))))))) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy2, [0x07fffffff, 0x0ffffffff, -0x100000001, -0x080000000, 0x100000000, -0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 1, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -(2**53-2), 0x100000001, Number.MIN_VALUE, -1/0, 1/0, -0, -0x07fffffff, -0x0ffffffff, 42, 0, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), -0x100000000, -(2**53), 0.000000000000001, 2**53-2, -Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=428; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 6.189700196426902e+26;\n    var i4 = 0;\n    return +((Float64ArrayView[4096]));\n  }\n  return f; })(this, {ff: (Array.prototype.findIndex).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000000, 0x080000000, -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, 1.7976931348623157e308, 0x100000001, 0/0, 42, -0, Number.MIN_VALUE, 2**53+2, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 0.000000000000001, -0x0ffffffff, -1/0, 0x100000000, Math.PI, 0, -Number.MAX_VALUE, Number.MAX_VALUE, 1/0, -0x080000001, 0x0ffffffff, 2**53-2, -(2**53-2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-85495475*/count=429; tryItOut("mathy0 = (function(x, y) { return ( ! Math.atan2(Math.fround(( + Math.atan(((Math.fround(( + ( ~ x))) < (( + (Math.acos(y) >>> 0)) | 0)) | 0)))), Math.fround(( + Math.fround(Math.hypot(( + (( + y) ? ( + x) : ( + Math.min(y, x)))), Math.sign(y))))))); }); testMathyFunction(mathy0, [-0, 0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, 42, -0x080000001, 0x100000001, -0x080000000, Math.PI, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -Number.MAX_VALUE, 1, -0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, -0x07fffffff, 0x0ffffffff, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -(2**53-2), -0x100000000, -(2**53), 0]); ");
/*fuzzSeed-85495475*/count=430; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.cos(Math.fround(Math.fround((( + ( + 0x100000001)) >> (Math.imul((Math.hypot(-0x100000000, Math.max(x, y)) | 0), ( + ( ! ((Math.atanh(0x100000000) | Math.fround(( ~ 2**53-2))) | 0)))) | 0)))))); }); ");
/*fuzzSeed-85495475*/count=431; tryItOut("g1 = t0[12];\na1.sort((function(j) { if (j) { try { (void schedulegc(g1)); } catch(e0) { } m2.delete(g2); } else { f0.toSource = (function(j) { if (j) { p2 + ''; } else { try { h0.toSource = (function() { try { i1 = m0.entries; } catch(e0) { } try { t0.__proto__ = f0; } catch(e1) { } f1 = Proxy.createFunction(h2, f1, g1.f2); return p0; }); } catch(e0) { } try { o1.p1 + o1; } catch(e1) { } try { this.o0.v2 + o1.f2; } catch(e2) { } /*MXX2*/g0.TypeError.prototype.message = e0; } }); } }));\n");
/*fuzzSeed-85495475*/count=432; tryItOut("mathy5 = (function(x, y) { return Math.imul(Math.atan(((Math.min((y | 0), (y | 0)) | 0) > (mathy3((x | 0), ( ! -Number.MIN_VALUE)) | 0))), ( - ( + (((Math.tan(((Math.fround((x >>> 0)) >>> 0) | 0)) | 0) | 0) ? (Math.fround(mathy3(Math.fround(y), Math.fround(x))) | 0) : (((((mathy2(Math.PI, (-(2**53+2) | 0)) | 0) >>> 0) - (y >>> 0)) >>> 0) | 0))))); }); ");
/*fuzzSeed-85495475*/count=433; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=434; tryItOut("/*infloop*/for(var b in ((x)(((p={}, (p.z =  /* Comment */({ set 2(e, x, x, x, y, \u3056 = [[1]], c = {}, e, x =  /x/g , x =  '' , b, x, x, eval, window, x, x, w, x, d, x, x, eval, eval, z, x, a, x = /((?:\\d)){2,}/y, c, x, x, x = this, z, z, x, x, x, a, d, eval, x, c, NaN, x, \u3056, b, x = new RegExp(\"((.)+)|[^]{3}\", \"gi\"), \u3056, w, a, b, x, eval, x, x, x, c, x, x, d, eval, x, d, a, NaN, c =  /x/ , eval, \u3056, \u3056, \u3056, window, b, \u3056, b = window, c, y = x, e, NaN, b, NaN, e)\"use asm\";   var imul = stdlib.Math.imul;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -4294967296.0;\n    {\n      {\n        i0 = (((eval = Proxy.createFunction(({/*TOODEEP*/})(17), /*wrap1*/(function(){ \"use strict\"; (null);return function shapeyConstructor(jcsmhf){return this; }})(), eval)) in x));\n      }\n    }\n    return ((((NaN = x = Proxy.create(({/*TOODEEP*/})(x), -2)))+((imul((i0), (1))|0))))|0;\n  }\n  return f;,  get w b (x)eval }))()))))){this.m2.has(this.s2);print(x);Object.prototype.watch.call(o2, \"imul\", (function() { try { v0 = (a1 instanceof g0.e2); } catch(e0) { } print(g0); return b2; })); }");
/*fuzzSeed-85495475*/count=435; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\np0.__proto__ = t2;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+(1.0/0.0));\n    {\n      d1 = (-9.671406556917033e+24);\n    }\n    return +((+((Float32ArrayView[((0xfc7790cd)+(!((((~~(+(0.0/0.0))) > (((0x863bda58)) << ((0xf9097e81))))+(i0))))) >> 2]))));\n    return +((-8589934591.0));\n  }\n  return f; })(this, {ff: new RegExp(\"(?=(?!(?:\\\\D)\\\\w)+[^]\\\\w|.+{1}(?![\\\\\\u829e-\\\\u7A69\\\\S][^]?)+?)\", \"gim\")\n.unwatch(x = Proxy.createFunction(({/*TOODEEP*/})(\"\\u5DA5\"), Float64Array))}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, 0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 0/0, 1, -Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, 0x100000000, 0x07fffffff, -0x080000001, -(2**53), 42, 2**53, -Number.MIN_VALUE, 0x080000000, -1/0, Number.MAX_VALUE, -(2**53+2), 0, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, 1/0, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=436; tryItOut("\"use strict\"; (c ? /*UUV1*/(a.create = \"\\u43D3\") : -9.valueOf(\"number\"));with({}) yield x;");
/*fuzzSeed-85495475*/count=437; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=438; tryItOut("\"use asm\"; testMathyFunction(mathy1, [-0x0ffffffff, 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, Math.PI, -Number.MIN_VALUE, -(2**53-2), -0x080000000, Number.MAX_VALUE, 2**53-2, 0x080000001, 0x07fffffff, -0x100000000, 0x080000000, 1/0, -(2**53), Number.MIN_VALUE, 0, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, -1/0, 1, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 2**53, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-85495475*/count=439; tryItOut("\"use strict\"; for (var v of t2) { try { for (var v of m0) { try { g2.t2.set(t0, 11); } catch(e0) { } try { this.m0 + ''; } catch(e1) { } for (var v of b2) { try { b1 = x; } catch(e0) { } try { m2.delete(o1.g0.s1); } catch(e1) { } try { o1.m0.get(e0); } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(i0, b2); } } } catch(e0) { } try { v2 = i0[\"__proto__\"]; } catch(e1) { } try { v2 = (b0 instanceof p1); } catch(e2) { } Object.defineProperty(this, \"t2\", { configurable: true, enumerable: (x % 3 == 1),  get: function() {  return new Int16Array(a1); } }); }");
/*fuzzSeed-85495475*/count=440; tryItOut("mathy1 = (function(x, y) { return Math.atan(( ! ( - ( + -Number.MAX_VALUE)))); }); testMathyFunction(mathy1, [true, 0.1, 0, ({valueOf:function(){return '0';}}), (function(){return 0;}), [0], NaN, -0, undefined, null, ({toString:function(){return '0';}}), '', (new Boolean(false)), objectEmulatingUndefined(), (new Boolean(true)), (new Number(-0)), (new Number(0)), /0/, '/0/', '0', 1, '\\0', false, ({valueOf:function(){return 0;}}), (new String('')), []]); ");
/*fuzzSeed-85495475*/count=441; tryItOut("h1 = {};");
/*fuzzSeed-85495475*/count=442; tryItOut("\"use strict\"; h1.get = f0;");
/*fuzzSeed-85495475*/count=443; tryItOut("/*infloop*/for(var z = /\\v[\\b-\\ud6C2\ue14a\\d][^]$*?{31,35}?|\\3/yim; e = (4277); x) this.v0 = g2.eval(\"/*bLoop*/for (let ttuvlg = 0; ttuvlg < 121 && ( /x/g ); ++ttuvlg) { if (ttuvlg % 43 == 28) { a2.pop(this.g1); } else { print(x); }  } \");");
/*fuzzSeed-85495475*/count=444; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.abs(((((Math.atan2(Math.max(y, x), Math.atanh(( + Math.fround(Math.cosh(Math.cbrt(Math.fround(Math.sinh(Math.fround(y))))))))) | 0) && (Math.atan2(Math.fround((Math.fround((( + ( ~ x)) >= (-0x080000001 >>> x))) % Math.fround((Math.fround(1/0) >>> x)))), -0x0ffffffff) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, -0x07fffffff, 0/0, 0x07fffffff, 42, 0.000000000000001, -(2**53-2), 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 2**53+2, 0x100000001, Math.PI, -0x0ffffffff, -0x100000001, -0x080000001, -(2**53), 0x0ffffffff, 2**53-2, 1, -0x100000000, -1/0, Number.MIN_SAFE_INTEGER, -0, -(2**53+2), 0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=445; tryItOut("\"use strict\"; v1 + '';\nv0 = false;\n");
/*fuzzSeed-85495475*/count=446; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy1((Math.trunc(mathy2(y, (( + (( + (( ! (x | 0)) | 0)) , ( + Math.min(x, y)))) ? y : y))) == Math.imul(( ! x), (( + x) | 0))), (mathy0((( ~ ((( ! x) ? ( + x) : y) - ( + ( ! ( + y))))) >>> 0), (((x > ((y ^ Math.fround(Math.imul(Math.fround(x), x))) | 0)) ** ( ~ Math.fround(( ! Math.pow(( ! x), y))))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x080000000, 2**53, 0, 1, 1/0, -0x100000001, 0x080000000, Math.PI, -0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -1/0, -(2**53+2), 0/0, -(2**53), -(2**53-2), -0x07fffffff, 42, -Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0, -0x080000001, Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, 0x100000000]); ");
/*fuzzSeed-85495475*/count=447; tryItOut("if(x) { if (y) /*RXUB*/var r = let (b) allocationMarker(); var s = \"\\u001c\"; print(uneval(s.match(r))); } else e0.add(i2);");
/*fuzzSeed-85495475*/count=448; tryItOut("mathy4 = (function(x, y) { return ( + (((Math.fround(Math.cos((Math.fround((Math.fround(( + (-(2**53+2) | 0))) , Math.fround((Math.hypot((x | 0), (x | 0)) | 0)))) | 0))) % ( + y)) >>> 0) & (Math.fround(Math.tanh(Math.fround(y))) >>> 0))); }); testMathyFunction(mathy4, [-0x07fffffff, -(2**53+2), -0x100000001, -0x080000000, 0x0ffffffff, -1/0, -0, -(2**53), 2**53+2, 1, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 0x080000000, Number.MAX_VALUE, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 2**53-2, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 1/0, 0, -(2**53-2), Number.MIN_VALUE, 42]); ");
/*fuzzSeed-85495475*/count=449; tryItOut("\"use strict\"; g2 + s2;");
/*fuzzSeed-85495475*/count=450; tryItOut("i0.toString = (function() { try { selectforgc(o2); } catch(e0) { } try { Array.prototype.forEach.apply(a2, [(function() { o2.toSource = (function mcc_() { var cstvpu = 0; return function() { ++cstvpu; if (/*ICCD*/cstvpu % 11 == 3) { dumpln('hit!'); try { e0.has(b0); } catch(e0) { } try { h2.get = (function mcc_() { var mzsluc = 0; return function() { ++mzsluc; o0.f1(/*ICCD*/mzsluc % 8 == 3);};})(); } catch(e1) { } try { t2[19] = o1; } catch(e2) { } for (var v of b1) { try { t1.set(t0, b); } catch(e0) { } g1.o0.e1 = g1.g1.objectEmulatingUndefined(); } } else { dumpln('miss!'); selectforgc(this.o1); } };})(); throw i2; })]); } catch(e1) { } Object.defineProperty(g1, \"t1\", { configurable: /*RXUE*/( /* Comment */x).exec((x =  '' ) &&  \"\" ), enumerable: (x % 6 == 0),  get: function() { for (var p in o0.m2) { a0.__iterator__ = (function() { try { this.s1 = ''; } catch(e0) { } try { this.v1 = r2.exec; } catch(e1) { } h1.fix = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69, a70, a71, a72, a73, a74, a75, a76, a77, a78) { var r0 = a40 & 1; var r1 = a18 + 8; var r2 = 3 / 8; var r3 = a54 ^ a33; a45 = a75 / a48; a41 = a28 | a19; var r4 = a31 & a66; a75 = 6 / a1; return a50; }); return m1; }); } return new Int32Array(a1); } }); return g1; });");
/*fuzzSeed-85495475*/count=451; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.abs(Math.fround(( + Math.log10(( + (Math.fround((Math.pow((( + ( ~ ( + y))) >>> 0), (y >>> 0)) >>> 0)) && ( + x))))))); }); testMathyFunction(mathy5, [-(2**53+2), 1, 0x100000000, 2**53, 0x07fffffff, 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, -Number.MAX_VALUE, -1/0, 0/0, -0x07fffffff, 2**53+2, -0, 0x100000001, -0x0ffffffff, 0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 1/0, -0x100000001, -0x080000001, 42, 0.000000000000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0, 2**53-2]); ");
/*fuzzSeed-85495475*/count=452; tryItOut("\"use strict\"; g1.h0 = {};\nthis.v0 = true;\n");
/*fuzzSeed-85495475*/count=453; tryItOut("\"use strict\"; t2 = o2.m0.get(e1);");
/*fuzzSeed-85495475*/count=454; tryItOut("window /= w;\n;\n");
/*fuzzSeed-85495475*/count=455; tryItOut("\"use strict\"; {print( /x/g  ===  /x/g ); }\nfor (var v of p0) { try { g0.m1.has(v1); } catch(e0) { } /*MXX1*/o2 = g0.WeakSet.prototype.has; }\n");
/*fuzzSeed-85495475*/count=456; tryItOut("\"use strict\"; h1.getPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -16385.0;\n    var i3 = 0;\n    var d4 = 1073741823.0;\n    var i5 = 0;\n    var d6 = -2097153.0;\n    d2 = (-36893488147419103000.0);\n    return +((abs((~~(1.001953125)))|0));\n    d6 = (d4);\n    {\n      i5 = ((+((new 27())>>>((0xffffffff)))) <= (+(0x86d944a4)));\n    }\n    d4 = (+(1.0/0.0));\n    i0 = ((((-0x8000000)*-0xda73) >> ((0xfb6ec266))));\n    d6 = (d2);\n    switch (((-0x180f0*((4.835703278458517e+24) > (16777217.0))) & ((i5)))) {\n      case -3:\n        {\n          {\n            {\n              i5 = (0xff8d4b53);\n            }\n          }\n        }\n        break;\n      default:\n        i5 = (0x6da60eaa);\n    }\n    i5 = (-0x8000000);\n    return +((((d6)) % ((d2))));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new SharedArrayBuffer(4096));");
/*fuzzSeed-85495475*/count=457; tryItOut("testMathyFunction(mathy3, [Math.PI, -0x100000001, 2**53-2, Number.MIN_VALUE, 0/0, 1, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, 0, 1/0, -0x080000001, -0x0ffffffff, -0x080000000, 0x080000001, 0.000000000000001, 2**53+2, 0x100000001, -Number.MAX_VALUE, -1/0, 0x07fffffff, -0x07fffffff, -(2**53), -0, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 42, -(2**53-2), 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-85495475*/count=458; tryItOut("testMathyFunction(mathy1, [-0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 0x100000000, 0, 0x080000000, 2**53+2, Math.PI, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0x0ffffffff, 0x080000001, 2**53, 0x100000001, 1, -(2**53), -(2**53+2), -0x07fffffff, 42, 2**53-2, 0.000000000000001, -1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000001, -0, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=459; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=460; tryItOut("print(x);let x = (p={}, (p.z =  '' )());");
/*fuzzSeed-85495475*/count=461; tryItOut("h2 + i1;");
/*fuzzSeed-85495475*/count=462; tryItOut("mathy1 = (function(x, y) { return ((( - ( + (Math.log2(x) | 0))) >>> 0) ** (( + ( - ( + (((Math.asinh(Math.expm1(( + y))) >>> 0) % (Math.atan2(x, Math.atan2(x, y)) >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy1, ['/0/', 0, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), null, (new Number(0)), -0, 0.1, ({valueOf:function(){return 0;}}), false, /0/, (new Boolean(false)), true, objectEmulatingUndefined(), undefined, '0', (function(){return 0;}), (new Number(-0)), (new String('')), NaN, '', (new Boolean(true)), '\\0', 1, [0], []]); ");
/*fuzzSeed-85495475*/count=463; tryItOut("/*RXUB*/var r = /((?=(?:(\\1))+?))/gi; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=464; tryItOut("/*oLoop*/for (var qbdueo = 0; qbdueo < 78; ++qbdueo) { f0 = f0; } ");
/*fuzzSeed-85495475*/count=465; tryItOut("\"use strict\"; for (var p in this.t0) { try { Array.prototype.push.apply(a1, [t1]); } catch(e0) { } try { a0[({valueOf: function() { v2 = (p0 instanceof h0);return 16; }})]; } catch(e1) { } /*ODP-2*/Object.defineProperty(o0.e2, \"reduce\", { configurable: (x % 5 != 1), enumerable: true, get: function shapeyConstructor(zyjmtw){return this; }, set: (function() { try { a2 = a2.concat(t1, a2, a0, i1); } catch(e0) { } try { a0.reverse(); } catch(e1) { } v1 = evaluate(\"v2 = a2.reduce, reduceRight();\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: false, sourceIsLazy: (x % 8 == 4), catchTermination: true })); return a2; }) }); }");
/*fuzzSeed-85495475*/count=466; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?!((?=\\1{65,16777280}[^][^])[^\\W\\x85]*?|(?![^\\cS-\\u0415])+|\\b\\D|\\d(?=.)(?![^])[^]|[^]+{3,})))/gyi; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-85495475*/count=467; tryItOut("\"use strict\"; this.g2.i2 = new Iterator(this.m0, true);");
/*fuzzSeed-85495475*/count=468; tryItOut("mathy0 = (function(x, y) { return (Math.min(Math.fround(Math.sinh(Math.fround(( ~ x)))), ( + Math.fround(Math.atan2(((((y | 0) != (y | 0)) | 0) | 0), Math.pow(x, ( + Math.cos(y))))))) >>> 0); }); testMathyFunction(mathy0, [0x100000000, -(2**53), 2**53+2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -0x080000001, -0x080000000, -(2**53-2), 0x080000001, 0, 0/0, 0x080000000, 42, 0x100000001, 0.000000000000001, 2**53, -Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, 1/0, 0x0ffffffff, -0x100000000, 0x07fffffff, 1, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2]); ");
/*fuzzSeed-85495475*/count=469; tryItOut("let([, , {{}: b, x}] = /*RXUE*//\\3/im.exec(\"\"), [x] = false) { throw StopIteration;}yield [, ] = (new /\\B.|(?=[\\u1040-\\\u1226\\s\u0009-\\u009D\\s]*?)(?=[\\S\u2053]){8589934591}\\w[^]+?{2,6}([^])/gi().__defineSetter__(\"y\", /*wrap3*/(function(){ var vuuvuz = \"\u03a0\"; ( { Array.prototype.unshift.call(a0); } )(); })));");
/*fuzzSeed-85495475*/count=470; tryItOut("v0 = evalcx(\"f0.toSource = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    {\\n      d1 = (((d0)) - ((((Float32ArrayView[2])) % ((d0)))));\\n    }\\n    d0 = (+abs(((d1))));\\n    d1 = ((1));\\n    return +((Float32ArrayView[((0xfe77f02b)-(((b = /[^](?=(?!^{4}(?!\\\\b)\\\\s).{3,4})/ym) << ((-0x8000000)+(!(0x6f588d0c)))) < (((!((4277))))|0))) >> 2]));\\n  }\\n  return f; });\", g1);");
/*fuzzSeed-85495475*/count=471; tryItOut("e2 = new Set;");
/*fuzzSeed-85495475*/count=472; tryItOut("\"use strict\"; Array.prototype.shift.call(a2, i0);");
/*fuzzSeed-85495475*/count=473; tryItOut("try { /*MXX3*/g0.Promise.prototype.then = g2.Promise.prototype.then; } catch(window) { /*RXUB*/var r = /$/m; var s = \"\\n\\n\\n\\n\"; print(uneval(r.exec(s)));  } finally { let(a) ((function(){with({}) for(let w in /*FARR*/[(4277), ...new Array(24), [,,], .../*FARR*/[], , , (NaN) = ({a: 25})]) let(y) { yield this.__defineSetter__(\"c\", WeakMap.prototype.get);}})()); } x.stack;");
/*fuzzSeed-85495475*/count=474; tryItOut("\"use strict\"; t2[v1] = this.m2;");
/*fuzzSeed-85495475*/count=475; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.ceil(( + (( + (mathy1(Math.round(( + ((-(2**53-2) | 0) / ( + ( ! ( + x)))))), Math.round((Math.hypot(-Number.MIN_VALUE, (Math.PI | 0)) | 0))) >>> 0)) | 0)))); }); ");
/*fuzzSeed-85495475*/count=476; tryItOut("\"use strict\"; g1 + '';");
/*fuzzSeed-85495475*/count=477; tryItOut("mathy2 = (function(x, y) { return ( + ( ~ ( + (mathy1(((Math.atan2((( ! (Math.max(y, ( ! y)) | 0)) >>> 0), (Math.imul((Math.min((Math.log10((0x080000001 >>> 0)) >>> 0), (( + ( + y)) | 0)) | 0), Math.hypot(x, 0)) | 0)) | 0) >>> 0), ((Math.fround(Math.abs((x | 0))) % y) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-(2**53-2), -0x100000000, 1.7976931348623157e308, 0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 2**53, -0x080000001, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, 1/0, -0x0ffffffff, -(2**53+2), -0, 2**53-2, 0x100000000, 0x0ffffffff, 0/0, -Number.MAX_VALUE, -0x100000001, 0x07fffffff, 0x080000001, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, -1/0, 1]); ");
/*fuzzSeed-85495475*/count=478; tryItOut("switch(((4277) %=  /x/ )) { default: g0.a1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    switch ((((0x569da56d) / (0x5f2cffe1)) << ((0xa445bb35) / (0x5479c845)))) {\n      case -2:\n        d1 = (d1);\n        break;\n      case -2:\n        {\n          return +((+abs(((68719476737.0)))));\n        }\n        break;\n      case 1:\n        {\n          d1 = (1.0);\n        }\n        break;\n      case 1:\n        i0 = (i0);\n      case -2:\n        d1 = (d1);\n        break;\n      case -3:\n        (Float64ArrayView[(((Float64ArrayView[1]))-((((0xffffffff))>>>((0x41be618b))) == (0xe1b4caad))+(/*FFI*/ff((((0x47ddf*(0xcac52a03)) << ((0x8549f66b)+(0xad7c4cfe)))), ((d1)))|0)) >> 3]) = ((Float64ArrayView[((((((0x655b52f9))) >> ((0x6e9f7689))))) >> 3]));\n        break;\n      default:\n        i0 = (0xff1ad61d);\n    }\n    return +((-((-1125899906842625.0))));\n  }\n  return f; })(this, {ff: (void new RegExp(\"\\\\B\", \"ym\")).bind}, new ArrayBuffer(4096));break; t0[14] = ((function(x, y) { return ( + Math.log2(( + ( + ( + ((( - x) | Math.imul(-0x0ffffffff, Math.fround(y))) | 0)))))); }))((4277)); }");
/*fuzzSeed-85495475*/count=479; tryItOut("v2 = (this.t1 instanceof this.g2);");
/*fuzzSeed-85495475*/count=480; tryItOut("/*ODP-1*/Object.defineProperty(f2, \"__parent__\", ({}));");
/*fuzzSeed-85495475*/count=481; tryItOut("print(uneval(o0.s0));");
/*fuzzSeed-85495475*/count=482; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-85495475*/count=483; tryItOut("o0.g0.o1.t2 = new Uint8ClampedArray(this.a1);");
/*fuzzSeed-85495475*/count=484; tryItOut("\"use strict\"; e2.add(h2)");
/*fuzzSeed-85495475*/count=485; tryItOut("testMathyFunction(mathy2, [(new Number(0)), NaN, false, (new Number(-0)), '', null, 0.1, (function(){return 0;}), ({toString:function(){return '0';}}), 0, '0', true, (new String('')), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), /0/, (new Boolean(true)), '/0/', (new Boolean(false)), 1, '\\0', undefined, [], [0], -0, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-85495475*/count=486; tryItOut("\"use asm\"; t1 = g2.objectEmulatingUndefined();");
/*fuzzSeed-85495475*/count=487; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return Math.log(Math.fround(( - (mathy1(Math.hypot(-0x0ffffffff, y), Math.fround(((( + ( + ( ! ( ! x)))) >>> (x >>> 0)) >>> 0))) >>> 0)))); }); testMathyFunction(mathy2, [-1/0, 2**53+2, 0x080000000, 1/0, -(2**53), 0/0, -0x07fffffff, Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, 0x100000000, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -(2**53+2), -0x080000000, 1, Number.MIN_VALUE, 0x0ffffffff, -0, -Number.MAX_VALUE, -0x100000000, 42, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-85495475*/count=488; tryItOut("Array.prototype.reverse.call(o2.a0);");
/*fuzzSeed-85495475*/count=489; tryItOut("try { throw e; } catch(d) { for(let e in ((this)(/.|(?:.{2,2}+){3,}$[^]\\2/gym)++ for (z of ({d: \"\\u5502\", x: window })))) let(z) ((function(){return;})()); } finally { return; } w = [,];");
/*fuzzSeed-85495475*/count=490; tryItOut(";");
/*fuzzSeed-85495475*/count=491; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! mathy0((((x | 0) * ((Math.tan(( + Math.acosh(y))) | 0) | 0)) | 0), ((((( + (Math.atan2(x, ( + mathy0((x | 0), (1/0 | 0)))) | 0)) >> (y << (x | 0))) | 0) ? Math.fround(Math.round(Math.fround((x > y)))) : ( - ((1/0 | 0) == (y >>> 0)))) | 0))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 2**53+2, Number.MIN_VALUE, -(2**53+2), Math.PI, 1, 0x0ffffffff, -(2**53), -0, -0x080000000, 0.000000000000001, -0x100000000, -(2**53-2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 42, 0x080000001, -1/0, 2**53, 0x07fffffff, 2**53-2, Number.MAX_VALUE, -0x080000001, -0x07fffffff, 0, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 1/0]); ");
/*fuzzSeed-85495475*/count=492; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.hypot(Math.hypot((( + y) + Math.tan(y)), x), ( ! x)) || ((( + Math.sign(( + Math.imul(Math.fround((y | 0)), ( + (Math.abs((((x & (x >>> 0)) >>> 0) - x)) | 0)))))) || ( + Math.fround(Math.imul(Math.fround(Math.cosh(Math.sign((( ~ y) | 0)))), Math.fround(Math.fround(Math.cosh(( + Math.max(((-Number.MAX_VALUE | 0) ? 42 : x), ( + (y ? ( + x) : y))))))))))) >>> 0))); }); testMathyFunction(mathy0, [true, undefined, null, '\\0', (new Boolean(true)), ({valueOf:function(){return 0;}}), -0, 0.1, '/0/', 0, (new Boolean(false)), (new Number(0)), (new Number(-0)), '0', /0/, [], ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), false, [0], (new String('')), NaN, ({toString:function(){return '0';}}), '', 1, (function(){return 0;})]); ");
/*fuzzSeed-85495475*/count=493; tryItOut("if(new RegExp(\"(?=\\\\b)[^\\\\xE9-\\\\u896b\\\\u009b-\\\\u97B3]{4,}*(?=(?:\\\\B+?|[^\\\\r-\\\\ua86a]?+?)){0,2}\", \"yim\")) {a0[16];/* no regression tests found */ } else {if(-5) Array.prototype.forEach.apply(a2, [(function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (((Float64ArrayView[4096])) * ((Float32ArrayView[(-0x97508*(0xf9c9d666)) >> 2])));\n    {\n      (Uint16ArrayView[((1)*-0x2dae1) >> 1]) = ((1)+((\n \"\" .unwatch(\"apply\")) ? (((0xa813f*(i1)) << (-0xfffff*(0xffffffff)))) : (0xe8de158f)));\n    }\n    (/*FARR*/[].filter((function(y) { v0 = Array.prototype.every.apply(a0, [/*wrap3*/(function(){ var oiucou = \"\\uC5F1\"; ((/*wrap1*/(function(){ \"use strict\"; throw  /x/ ;return neuter})()).bind())(); })]); }).bind)) = ((((0xd425e94c)+(1)) & ((((/[\\s\u7696\\u008d-\u7dc8][0-\\xE0\\cH-\u316d\\uF69c\u00a9-\\B]|\\2|(\u0094)+?(?:\\u6f47{2,2})|.|[^]|\\u8910[^]|\\B(?=\\d)|(?=\\1)|(?=(?:(?:.)))/g) ? (d0) : (d0))))) / ((-((abs((~~(-67108865.0)))|0) < (0x6b49c340)))|0));\n    (Float32ArrayView[((0xc4116bf4)) >> 2]) = ((0.00390625));\n    i1 = ((0xffffffff));\n    i1 = (i1);\n    switch ((((0xf8e3f064)) >> ((-0x3d7cca2) % (0x7fffffff)))) {\n    }\n    return +((d0));\n  }\n  return f; })]); else  if (timeout(1800)) {m2.delete( '' );null; } else {yield; } }");
/*fuzzSeed-85495475*/count=494; tryItOut("testMathyFunction(mathy2, [1.7976931348623157e308, 0.000000000000001, -1/0, 42, 2**53, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1/0, 0/0, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -0x100000001, 1, -0x080000000, 0, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53+2, 0x100000000, -0x0ffffffff, 0x080000000, -0x100000000, -0, -(2**53), Math.PI, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=495; tryItOut("a1.unshift();");
/*fuzzSeed-85495475*/count=496; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.sign(Math.fround((Math.asinh(((Math.atan2(0x100000000, Math.max(Math.fround(Math.max(( + -Number.MIN_VALUE), Math.fround(y))), x)) ^ ( + ( ~ ( + (( ~ x) | 0))))) | 0)) | 0)))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -0, 2**53-2, -0x080000000, 2**53+2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 0x080000000, -0x0ffffffff, -0x100000000, -0x07fffffff, 2**53, 0/0, -Number.MIN_VALUE, -0x100000001, -1/0, Number.MIN_VALUE, 1, 0x07fffffff, -0x080000001, 0x100000000, Number.MAX_VALUE, 1/0, 0.000000000000001, -(2**53+2), 42, 0, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=497; tryItOut("delete z.\u3056\n;");
/*fuzzSeed-85495475*/count=498; tryItOut("mathy1 = (function(x, y) { return (((( + ( ! ( + (Math.fround(( ! mathy0((0x080000001 >>> 0), ((x >>> 0) !== 0x080000000)))) !== Math.fround(y))))) >>> 0) & (mathy0(( + Math.max(( + Math.fround(mathy0(Math.fround((( ~ 0x07fffffff) >>> 0)), Math.fround(y)))), Math.min(Math.fround(( + 0x07fffffff)), Math.fround(0x100000001)))), (( ! Math.fround((Math.fround(x) ? Math.fround(( - y)) : ((mathy0(x, y) | 0) + (x | 0))))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0x0ffffffff, -0x080000000, 0x0ffffffff, 0x07fffffff, 0x100000000, -1/0, 0x080000000, 2**53-2, 42, 1, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), Math.PI, 0x080000001, 1/0, 0x100000001, 1.7976931348623157e308, -0x100000001, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, 0, 2**53]); ");
/*fuzzSeed-85495475*/count=499; tryItOut("print(x);m0.has(a1);");
/*fuzzSeed-85495475*/count=500; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=501; tryItOut("\"use strict\"; e1.delete(a1);");
/*fuzzSeed-85495475*/count=502; tryItOut("mathy2 = (function(x, y) { return Math.fround(( ! (( + Math.ceil(( + ((( ~ Math.fround(( ! (y | 0)))) | 0) <= ((Math.fround(( + Math.expm1(( + x)))) != Math.fround(( + (x | 0)))) | 0))))) >>> 0))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), -0x080000000, 0, -(2**53), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, 0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, -0x07fffffff, 2**53-2, 0x0ffffffff, 2**53, -0x100000001, Number.MAX_VALUE, -(2**53+2), 0x080000001, 0x100000000, -0x0ffffffff, Math.PI, -0x080000001, -Number.MAX_SAFE_INTEGER, 42, 2**53+2, -0x100000000, -1/0, -0, -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-85495475*/count=503; tryItOut("\"use strict\"; print(f2);const d = x;");
/*fuzzSeed-85495475*/count=504; tryItOut("this.o1.v2 = x;");
/*fuzzSeed-85495475*/count=505; tryItOut("m0.set(9 ? d : null, b2);v0 = this.r1.global;");
/*fuzzSeed-85495475*/count=506; tryItOut("s2.valueOf = (function(j) { if (j) { x = g2.f1; } else { try { /*ODP-1*/Object.defineProperty(o2, \"exp\", ({set: decodeURI, configurable: (x % 2 == 0), enumerable: true})); } catch(e0) { } try { g1.b0 = a0[8]; } catch(e1) { } g0.s1 += s0; } });\nv0 = evaluate(\"function f1(a2)  { \\\"use strict\\\"; return x } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 20 != 7), noScriptRval: true, sourceIsLazy: true, catchTermination: x }));\nm2.has(o0.a2);\n\n");
/*fuzzSeed-85495475*/count=507; tryItOut("testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, -(2**53-2), 2**53-2, -1/0, 0.000000000000001, -0x080000000, -0x100000000, 1, 0/0, 42, 0x080000001, -Number.MIN_VALUE, 1/0, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, 0x100000001, Math.PI, 2**53, -(2**53+2), 0x0ffffffff, 0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, -0x080000001, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, 2**53+2]); ");
/*fuzzSeed-85495475*/count=508; tryItOut("testMathyFunction(mathy3, [-0x100000000, 1.7976931348623157e308, -0x100000001, 0x07fffffff, Math.PI, -0x080000000, -0x080000001, 2**53+2, -(2**53+2), 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -1/0, 42, -Number.MAX_VALUE, 2**53, -(2**53-2), -Number.MIN_VALUE, -(2**53), -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, 0, 1/0]); ");
/*fuzzSeed-85495475*/count=509; tryItOut("m1.set((this), b2);");
/*fuzzSeed-85495475*/count=510; tryItOut("\"use strict\"; v0 = evaluate(\"o1.e0.add(o1.p1);\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 == 0), sourceIsLazy: true, catchTermination: Math.abs(/*UUV2*/(a.clear = a.assign)) }));");
/*fuzzSeed-85495475*/count=511; tryItOut("\"use strict\"; t0.set(t1, x);");
/*fuzzSeed-85495475*/count=512; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.abs(Math.fround(Math.cosh(Math.hypot((Math.imul((x >>> 0), (( - (Math.hypot(Math.PI, ((mathy0((x >>> 0), (y >>> 0)) >>> 0) >>> 0)) | 0)) >>> 0)) >>> 0), (Math.atan2((x | 0), (x >>> 0)) | 0)))))); }); ");
/*fuzzSeed-85495475*/count=513; tryItOut("this.g0.offThreadCompileScript(\"s1 = '';\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: (x % 61 == 17), sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-85495475*/count=514; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\b\", \"im\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-85495475*/count=515; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0.000000000000001, 1.7976931348623157e308, 0, Math.PI, -0x080000001, -(2**53), -1/0, -0x100000000, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0x100000000, -0x080000000, 0/0, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), 42, Number.MIN_VALUE, 0x0ffffffff, -0, 0x080000001, 2**53, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, -0x100000001, 0x080000000, 2**53+2, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=516; tryItOut("testMathyFunction(mathy1, [-0x080000000, 1, 0x100000001, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, 2**53+2, Number.MAX_VALUE, -Number.MAX_VALUE, 1/0, 0x080000000, 2**53, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -(2**53+2), Number.MIN_VALUE, 0x100000000, -0x100000000, -0x0ffffffff, -0x100000001, -0x07fffffff, Math.PI, 0x080000001, 0/0, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, -0, 2**53-2, 42]); ");
/*fuzzSeed-85495475*/count=517; tryItOut("/*tLoop*/for (let c of /*MARR*/[function(){}, x, function(){}, x, x, function(){}]) { e0.valueOf = (function(j) { if (j) { try { i2 = e1.entries; } catch(e0) { } try { v2 = g0.g0.g0.runOffThreadScript(); } catch(e1) { } this.a2 = Array.prototype.concat.call(a2, a1); } else { try { e2.delete(v2); } catch(e0) { } try { print(uneval(this.e0)); } catch(e1) { } try { for (var v of a0) { m0.set(g2, p0); } } catch(e2) { } p1 + p1; } }); }");
/*fuzzSeed-85495475*/count=518; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return Math.imul((((( + ((((-0x100000000 | ( + Math.min(( + y), ( + x)))) + Math.pow(y, Number.MIN_SAFE_INTEGER)) >>> 0) | 0)) ? 0x07fffffff : Math.cos(y)) ^ Math.min(0x080000000, (( - (y >>> 0)) >= (( ~ (y >>> 0)) | 0)))) >>> 0), Math.hypot((( + ((mathy1((x | 0), (x | 0)) | 0) == ( + y))) / ( + (Math.ceil(mathy1(( + ( - x)), (Math.imul(x, x) !== y))) >>> 0))), (Math.min((((2**53-2 ? ((((x ** x) >>> 0) >>> ((( ~ 1) >>> 0) >>> 0)) | 0) : Math.fround(Math.abs(( ! x)))) | 0) >>> 0), (((Math.expm1(x) < 42) <= (42 >>> 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-85495475*/count=519; tryItOut(" /x/g ;");
/*fuzzSeed-85495475*/count=520; tryItOut("for(let y = \ntrue.prototype in \u3056--) v2 = this.g2.runOffThreadScript();");
/*fuzzSeed-85495475*/count=521; tryItOut("a1 = r0.exec(s1);");
/*fuzzSeed-85495475*/count=522; tryItOut("\"use strict\"; o1.v2 = r2.compile;");
/*fuzzSeed-85495475*/count=523; tryItOut("mathy1 = (function(x, y) { return Math.fround(( ~ (((((x || (y >>> 0)) >= (mathy0((Math.fround(Math.clz32(Math.fround(-0x080000000))) | 0), (Math.trunc(Math.ceil((0/0 >>> 0))) | 0)) | 0)) >>> 0) >>> (((( + 0x0ffffffff) >>> 0) >>> (Math.asinh(x) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy1, [(function(){return 0;}), [0], 0.1, [], (new String('')), (new Boolean(true)), /0/, -0, '/0/', (new Number(0)), ({valueOf:function(){return '0';}}), 0, null, '', '\\0', false, objectEmulatingUndefined(), (new Number(-0)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), undefined, '0', 1, (new Boolean(false)), true, NaN]); ");
/*fuzzSeed-85495475*/count=524; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?![^\\\\x38\\\\u005b-\\\\u4EC4])?){0,}|(?!^?|(?:(?=[^]|\\\\\\u00ad+))(?!\\\\B+\\\\b^?[\\\\u7588-\\\\xbB\\\\cT-\\\\ucb50\\\\xef-\\u6f23\\\\w]|[^]{4}))+\", \"gyim\"); var s = \"\\u3b22\\u3b22\\u3b22\\u3b22\\u3b22\\u3b22\\u3b22\\u3b22\"; print(r.test(s)); print(r.lastIndex); function e()Math.imul(0, 0.71)t2 + a0;\n\n");
/*fuzzSeed-85495475*/count=525; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! Math.fround((Math.fround(Math.abs(Math.fround(( + ( - (( + (x | 0)) | 0)))))) != Math.fround(( + ( - y)))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -(2**53), -0x07fffffff, 0x100000001, 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 0/0, 1.7976931348623157e308, -0x0ffffffff, 42, 0x080000001, -(2**53-2), Math.PI, 2**53-2, 2**53+2, 1/0, -Number.MIN_VALUE, 2**53, Number.MAX_VALUE, 0, -1/0, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, -(2**53+2), -0x080000001, 0.000000000000001, -0]); ");
/*fuzzSeed-85495475*/count=526; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=527; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=528; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = (void options('strict_mode')); var s = \"\\uffed\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-85495475*/count=529; tryItOut("/*tLoop*/for (let w of /*MARR*/[new Boolean(true), function(){}, function(){}, function(){}, [,,z1], [,,z1], new Boolean(true), [,,z1], function(){}, [,,z1], [,,z1], new Boolean(true), new Boolean(true), function(){}, function(){}, new Boolean(true), [,,z1], [,,z1], new Boolean(true), function(){}, [,,z1], [,,z1], new Boolean(true), [,,z1], new Boolean(true), function(){}, new Boolean(true), new Boolean(true), function(){}, [,,z1], new Boolean(true), function(){}, new Boolean(true), [,,z1], new Boolean(true), [,,z1], new Boolean(true), [,,z1], function(){}, [,,z1], [,,z1], function(){}, [,,z1], function(){}, [,,z1], function(){}, [,,z1], function(){}, [,,z1]]) { v1 = Object.prototype.isPrototypeOf.call(e1, v1); }");
/*fuzzSeed-85495475*/count=530; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 268435457.0;\n    (Int16ArrayView[4096]) = (((0xf7aa7164))+((((abs((abs((0x3810825))|0))|0) % (((Int8ArrayView[4096])) & ((256.0))))>>>(((-(-0x8000000)) << ((0xf88a6eac)+(0x802291f6))) / (~((0xca3a2810)+(i0))))) != (0xd633ab12)));\n    {\n      switch ((~((!((1025.0) > (-281474976710657.0)))))) {\n        default:\n          d2 = ((+((Int8ArrayView[((0x7fffffff) / (imul((i0), (0x79373102))|0)) >> 0]))) + (-1.0009765625));\n      }\n    }\nyield\n/*MXX1*/g2.o0 = g0.g0.Object.getOwnPropertyDescriptor;    (Float64ArrayView[((0xeff6780)-((((0xe77c76b0)+(-0x8000000))>>>((i0))))-((~~(4.835703278458517e+24)))) >> 3]) = ((-0.0625));\n    i0 = ((((0xfca8a29b)-(0x25b6af29)-(0x4f1d856))>>>((0xc1fdb5c7) / (((0xfd8c2eb2))>>>(this.__defineGetter__(\"c\", function (b) { g0.o0 = new Object; } ))))));\n    d2 = (+abs(((+/*FFI*/ff(((65.0)), ((0x59f90b47)), ((144115188075855870.0)), (((0xa0f69*(0xff5b4c60)) & ((i0)-(/*FFI*/ff()|0)-((1.1805916207174113e+21) >= (-2199023255551.0))))), ((((0xc7190d21)+(0xfe416ee9)+(-0x8000000)) << ((0xf371bb43)))), ((+(-1.0/0.0))), ((NaN)))))));\n    d1 = (eval(\"\\\"use strict\\\"; /*MXX1*/o0 = g0.RegExp.lastParen;\", (eval(\"((void options('strict')))\"))));\n    (Uint8ArrayView[2]) = ((0xb574a025));\n    {\n      d2 = (+abs(((+(((i0)-(((0xcbbb127f) ? (0x2f58f7d1) : (0xfa0a4d29)) ? (0xfb147cd5) : ((((0xa903e256)) | ((0x1bc09ca4)))))) | ((0x62d00ab5)))))));\n    }\n    d2 = (d1);\n    {\n      {\n        i0 = (0x95cc8f3d);\n      }\n    }\n    d1 = (d1);\nprint( /x/g );    return (((imul(((~((Uint16ArrayView[2])))), (-0x8000000))|0) % (0x40c62467)))|0;\n  }\n  return f; })(this, {ff: Object.isFrozen}, new ArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=531; tryItOut("e0.add(e0);");
/*fuzzSeed-85495475*/count=532; tryItOut("g0.toString = Date.prototype.setDate.bind(b1);");
/*fuzzSeed-85495475*/count=533; tryItOut("\"use strict\"; window = (void shapeOf(x)), x, x = Math.atan2(-18, -2), cqpjdz, x, tdvofl, y, d, ygrdpz;s1 += 'x';");
/*fuzzSeed-85495475*/count=534; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (mathy2((Math.fround(Math.max((Math.cos(Math.abs(( + Math.pow(( + y), x)))) >>> 0), Math.fround((( ~ (Math.cos(y) | 0)) | 0)))) >>> 0), ( + Math.min(( + (mathy2((x | 0), ((0x100000000 ** x) | 0)) | 0)), Math.hypot(Math.fround(x), (x | 0))))) % (Math.asinh((Math.imul(( ~ ( + ((( - x) | 0) | 0))), (((Math.pow(y, (x >>> 0)) | 0) ? (((y ^ x) ? -(2**53+2) : (( ! -Number.MAX_VALUE) | 0)) | 0) : x) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-0x100000000, -1/0, -0, 0x080000001, 0x100000000, Math.PI, 0/0, 42, Number.MAX_VALUE, 2**53+2, 0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53, 1/0, -0x07fffffff, 0, -(2**53+2), -(2**53-2), -0x100000001, 1, 0.000000000000001, -0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 0x07fffffff, -(2**53), 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=535; tryItOut("m2.get(e0);");
/*fuzzSeed-85495475*/count=536; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x19309d02)+( /x/ )))|0;\n  }\n  return f; })(this, {ff: function (e, w, [], eval, a, NaN, x, e, x, x, x, x, x, x, z, x, d = [z1], z = new RegExp(\"(?:(?=[^\\\\B-\\ufccd]{2,5}[^M-]])(?![^])){3,}(?=(?:(?!(${8388608,276824064}))))\", \"gm\"), x, b = \"\\u2584\", window, x, e = /\\b|(\u6b25(?:(?:[])))(?:.){1,}{4,4}/gy, x, x, d, window, x, d, x, NaN, x, \u3056 =  /x/g , x, x = new RegExp(\"\\\\d\", \"y\"), x, x, a = this, window, x, /(?=.?)\\S\\W*?|(?:\\b)[^]|\\W+|(?:$)+?/g, z = 21, c, y, x)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\nlet ovgmvn, x, b;/*MXX2*/g1.Math.tanh = h0;    (Float64ArrayView[((((0xe8cc92f)) ? (0xd221b46f) : (0xb1970fb3))*-0x58c76) >> 3]) = ((1152921504606847000.0));\n    return +(((d0)));\n  }\n  return f;}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [/0/, ({toString:function(){return '0';}}), 1, true, -0, objectEmulatingUndefined(), false, (function(){return 0;}), (new Number(0)), ({valueOf:function(){return '0';}}), (new String('')), (new Number(-0)), [], '0', 0.1, (new Boolean(false)), (new Boolean(true)), NaN, ({valueOf:function(){return 0;}}), undefined, 0, '/0/', '\\0', '', [0], null]); ");
/*fuzzSeed-85495475*/count=537; tryItOut("h1 + '';");
/*fuzzSeed-85495475*/count=538; tryItOut("mathy0 = (function(x, y) { return Math.cos(Math.abs((( ~ ( + (y <= ( + Math.cbrt(y))))) !== Math.max(y, x)))); }); testMathyFunction(mathy0, [0x080000001, -(2**53), -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, -0x100000001, Number.MIN_VALUE, 0x07fffffff, Math.PI, 0x100000000, 42, 2**53-2, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, 0x0ffffffff, 0, 0x100000001, 1, 2**53+2, 1/0, -(2**53-2), 0/0, -0, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=539; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d0));\n  }\n  return f; })(this, {ff: function  w (x)((makeFinalizeObserver('nursery')))}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, -(2**53+2), 2**53-2, 0x0ffffffff, -0x080000001, 1/0, 0x100000001, Number.MAX_VALUE, -0x07fffffff, -0x100000000, 0x080000000, 0/0, 0x100000000, Number.MIN_VALUE, -(2**53-2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0, 1, 42, 0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, -(2**53), 2**53, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=540; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=541; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i3 = (i1);\n    (Float64ArrayView[(((((Int16ArrayView[0]))>>>((0xffe3dce9)+(0xfac5829b)+(0xfe942dae))) >= (((0x66a6d5ee) % (0x73d36016))>>>(-(i1))))) >> 3]) = (((0x3bc4a81e)));\n    i1 = (0xffffffff);\n    {\n      i3 = (i2);\n    }\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[1e-81, 1e-81, objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined()]); ");
/*fuzzSeed-85495475*/count=542; tryItOut("v2 = evaluate(\"/*infloop*/for(let (x) in (d || d) ** allocationMarker()) return;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 55 != 12), sourceIsLazy: true, catchTermination: true, element: o2, sourceMapURL: s2 }));");
/*fuzzSeed-85495475*/count=543; tryItOut("\"use strict\"; /*hhh*/function tzoxby(x){Array.prototype.shift.call(a0, p2, a1, i0, x);}tzoxby();");
/*fuzzSeed-85495475*/count=544; tryItOut("m0.get(v0);print(x);");
/*fuzzSeed-85495475*/count=545; tryItOut("testMathyFunction(mathy1, [-0x100000001, 0x080000001, 0x100000000, 0.000000000000001, Number.MIN_VALUE, -0x080000001, -(2**53+2), -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, -0, -(2**53), -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, -Number.MIN_VALUE, Math.PI, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, -(2**53-2), -0x080000000, 0x080000000, -0x0ffffffff, 1/0, Number.MAX_VALUE, 0, 2**53, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 1]); ");
/*fuzzSeed-85495475*/count=546; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[new String('q'), (-0), new Boolean(false), NaN, (-0), (-0), new Boolean(false), new String('q'), new String('q'), NaN, new Boolean(false), new Boolean(false), new String('q'), (-0), new Boolean(false), new String('q'), new String('q'), (-0), new String('q'), NaN, (-0), NaN, new String('q'), new String('q'), new Boolean(false), new String('q'), NaN, new String('q'), NaN, (-0), new Boolean(false), new Boolean(false), (-0), new Boolean(false), new String('q'), new Boolean(false), (-0), NaN, (-0), NaN, new Boolean(false), NaN, (-0), new String('q'), new String('q'), new Boolean(false), NaN, new Boolean(false), new String('q'), (-0), new String('q'), NaN, new Boolean(false), NaN, (-0), new Boolean(false), new String('q'), new Boolean(false), NaN, NaN, new Boolean(false), (-0), NaN, new Boolean(false), NaN, new String('q'), new Boolean(false), NaN, new Boolean(false), (-0), NaN, new String('q'), new String('q'), NaN, NaN, new String('q'), (-0), (-0), new Boolean(false), new Boolean(false), new Boolean(false), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), new String('q'), (-0), NaN, (-0), (-0), new String('q'), new String('q'), (-0), new Boolean(false), NaN, NaN, new Boolean(false), new String('q'), new String('q'), new Boolean(false), new String('q'), new Boolean(false), new String('q'), new String('q'), (-0), NaN, new String('q'), new Boolean(false), (-0), new Boolean(false), new String('q'), NaN, NaN, (-0), NaN, new Boolean(false), NaN, NaN, new String('q'), new Boolean(false), new String('q'), (-0), NaN, new Boolean(false), NaN, (-0), new Boolean(false), (-0), new String('q'), new String('q'), new Boolean(false), new Boolean(false), (-0), new Boolean(false), new Boolean(false), new Boolean(false), (-0), new Boolean(false), NaN, NaN, new Boolean(false), (-0)]) { v1 = Object.prototype.isPrototypeOf.call(g0.s1, f2); }");
/*fuzzSeed-85495475*/count=547; tryItOut("/*tLoop*/for (let a of /*MARR*/[ /x/ , true, true, x]) { decodeURIComponent }");
/*fuzzSeed-85495475*/count=548; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=549; tryItOut("const d = x\u000d;x;function x(d)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (i1);\n    return ((0xfffff*(0x38deed2e)))|0;\n  }\n  return f;const y = [1,,], e, d, ncjbsw, x, sysmlb, d;t2[6] = g0.t1;");
/*fuzzSeed-85495475*/count=550; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.hypot(((( + Math.hypot(y, (Math.min(( + x), (Math.max((Math.fround((Math.ceil(( + 2**53)) >>> 0)) != Math.min(x, ( + x))), (x | 0)) | 0)) | 0))) | 0) >>> 0), (Math.fround(mathy0(Math.fround(mathy0(Math.tan(x), (Math.cos(( + Math.log((Math.expm1(y) | 0)))) >>> 0))), Math.fround(Math.ceil(( ~ x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  '' ,  '' ,  '' , new Boolean(true), new Boolean(true),  '' , new Boolean(true),  '' ,  '' ,  '' , new Boolean(true),  '' , new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-85495475*/count=551; tryItOut("mathy4 = (function(x, y) { return Math.atan2(( + (( + Math.pow((Math.imul(x, (((y | 0) === 2**53) | 0)) | 0), y)) << Math.min(Math.cbrt(Math.round(x)), (( ! (x >>> 0)) >>> 0)))), mathy3(Math.fround(mathy2(( + Math.fround(Math.sin((( - y) | 0)))), x)), Math.hypot(((((mathy0((x >>> 0), (((y | 0) * (x | 0)) >>> 0)) >>> 0) | 0) << (Math.cosh(x) | 0)) | 0), Math.log2((((Math.cbrt((x | 0)) | 0) | 0) >>> ( + y)))))); }); testMathyFunction(mathy4, /*MARR*/[0x080000000,  /x/g , arguments.caller, new String(''), arguments.caller, arguments.caller, arguments.caller, new String(''), new String(''),  /x/g ,  /x/g , 0x080000000,  /x/g , 0x080000000, new String(''), new String(''),  /x/g ,  /x/g , new String(''), arguments.caller,  /x/g , 0x080000000,  /x/g , new String(''),  /x/g , new String(''), arguments.caller, arguments.caller,  /x/g , arguments.caller, new String(''), arguments.caller, new String(''), new String(''), 0x080000000,  /x/g , 0x080000000,  /x/g , 0x080000000, arguments.caller, 0x080000000,  /x/g , new String(''), new String(''), new String(''), arguments.caller, new String(''), arguments.caller, 0x080000000, 0x080000000, arguments.caller, arguments.caller, new String(''), 0x080000000, arguments.caller,  /x/g , arguments.caller,  /x/g , 0x080000000,  /x/g , new String(''), 0x080000000,  /x/g , arguments.caller, new String(''),  /x/g , new String(''),  /x/g ,  /x/g ,  /x/g , arguments.caller, 0x080000000,  /x/g ,  /x/g , new String(''), 0x080000000, arguments.caller, arguments.caller, arguments.caller, arguments.caller, 0x080000000,  /x/g , new String(''), new String(''), arguments.caller, arguments.caller, 0x080000000,  /x/g , arguments.caller, new String(''), arguments.caller, 0x080000000, 0x080000000, 0x080000000, 0x080000000, arguments.caller, new String(''), 0x080000000, arguments.caller, arguments.caller,  /x/g , arguments.caller, 0x080000000, arguments.caller,  /x/g ,  /x/g , 0x080000000, new String(''), arguments.caller, 0x080000000, new String(''), arguments.caller]); ");
/*fuzzSeed-85495475*/count=552; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MAX_VALUE, -(2**53+2), 1, -0x080000000, 0x080000001, -0x0ffffffff, 0x080000000, -0x07fffffff, -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 0, -(2**53), 0.000000000000001, 0/0, 1/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, Math.PI, -0x100000001, 0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 42, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, -0, 0x100000000, 0x100000001]); ");
/*fuzzSeed-85495475*/count=553; tryItOut("\"use strict\"; selectforgc(o0);function b(e, ...\u3056) { return x } /*tLoop*/for (let d of /*MARR*/[NaN]) { /*RXUB*/var r = r1; var s = s0; print(s.split(r));  }");
/*fuzzSeed-85495475*/count=554; tryItOut("for(d in \"\u03a0\") {m2.get(window); }");
/*fuzzSeed-85495475*/count=555; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - (Math.sinh((( + Math.tanh((x | 0))) | 0)) | 0)); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), -0x100000001, 0.000000000000001, -(2**53+2), -0x100000000, Math.PI, 0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, -0, -0x080000001, 1/0, 0, Number.MAX_VALUE, 0x100000001, 2**53-2, 1.7976931348623157e308, -0x0ffffffff, -1/0, -Number.MIN_VALUE, 1, -0x080000000, 0x07fffffff, -Number.MAX_VALUE, 0x080000000, 2**53, 2**53+2, 0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=556; tryItOut("mathy3 = (function(x, y) { return ( ! ( ! (Math.atan2(y, Math.fround((y <= x))) << Math.atanh(( - (Math.asinh(y) | 0)))))); }); ");
/*fuzzSeed-85495475*/count=557; tryItOut("\"use strict\"; s2.toSource = (function() { try { a1 = Array.prototype.slice.apply(g1.a2, [NaN, NaN, o2]); } catch(e0) { } try { delete b2[\"log2\"]; } catch(e1) { } g2.m1.has((timeout(1800))); return o1.p2; });");
/*fuzzSeed-85495475*/count=558; tryItOut("mathy1 = (function(x, y) { return Math.log(Math.fround(Math.atan(((((mathy0(Math.ceil((Math.max((x | 0), (-0 | 0)) | 0)), Math.log1p((((x | 0) >>> (x | 0)) | 0))) >>> 0) , (Math.hypot(Math.fround(((y | 0) ? -0x080000000 : (-Number.MIN_VALUE >>> 0))), Math.fround((( + y) | Math.pow(-0x07fffffff, y)))) >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, -0, -(2**53+2), 0.000000000000001, -0x100000000, 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 0x080000000, -0x080000001, -Number.MAX_VALUE, 1/0, Math.PI, 42, -0x080000000, -0x0ffffffff, -1/0, 0, 0x080000001, 0x07fffffff, -Number.MIN_VALUE, 2**53, -(2**53-2), 0x100000000, 0/0]); ");
/*fuzzSeed-85495475*/count=559; tryItOut("e2 = new Set;");
/*fuzzSeed-85495475*/count=560; tryItOut("this.t1 = new Uint8Array(13);function z(x, NaN, ...e)\"use asm\";   var Infinity = stdlib.Infinity;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i1 = (i1);\n    return +((((Infinity)) - (((+(-1.0/0.0)) + (-2199023255553.0)))));\n  }\n  return f;print(({toSource: this, -14: \"\\uB6F7\" }));");
/*fuzzSeed-85495475*/count=561; tryItOut("L:for(let [x, z] = (mathy5).call( /x/ , this, \"\\uAA6C\") in  \"\" ) [[1]];");
/*fuzzSeed-85495475*/count=562; tryItOut("o1.t1 = new Int32Array(b0, 52, v2);");
/*fuzzSeed-85495475*/count=563; tryItOut("\"use strict\"; with(e in new DataView(new x(({a1:1})), (function ([y]) { })())){/*RXUB*/var r = new RegExp(\"(\\\\B|(\\\\3))(?=[^]+?|(?=(?!\\\\n|[^]))(?=[]))|.(?:(?!(.{2})?))+\", \"gim\"); var s = \"\\u00f1\\u00f1\"; print(s.split(r));  }");
/*fuzzSeed-85495475*/count=564; tryItOut("\"use strict\"; o0.s0 += 'x';");
/*fuzzSeed-85495475*/count=565; tryItOut("/*oLoop*/for (let vrfjju = 0; vrfjju < 69 && (x); ++vrfjju) { o0.g2.__proto__ = i2; } ");
/*fuzzSeed-85495475*/count=566; tryItOut("mathy5 = (function(x, y) { return Math.hypot(( + ( + ( ! ( + Math.fround(Math.cos(Math.fround(Math.sinh(y)))))))), ( + mathy3(( + (((Math.sqrt((x | 0)) | 0) | 0) | ((x !== (Math.atanh(( + -0x0ffffffff)) | 0)) | 0))), Math.min(y, (Math.acos((42 <= Math.fround(y))) & x))))); }); ");
/*fuzzSeed-85495475*/count=567; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-85495475*/count=568; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.max((Math.atanh(Math.imul(Math.fround(Math.max(Math.fround(( + Math.sqrt(( + Math.round(x))))), Math.fround(mathy4(1.7976931348623157e308, (( + (y >>> 0)) >>> 0))))), x)) >>> 0), (( ~ Math.pow(( - ( + mathy4(( + mathy1(( ~ x), (y | 0))), ( + Math.max(Math.hypot(y, y), -0x0ffffffff))))), Math.round(((Math.imul(y, 1.7976931348623157e308) % Number.MIN_VALUE) >>> 0)))) >>> 0)); }); testMathyFunction(mathy5, [(function(){return 0;}), 0, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), true, (new Number(0)), /0/, '', [0], 1, null, '\\0', -0, 0.1, (new String('')), (new Number(-0)), objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), (new Boolean(true)), [], '/0/', NaN, false, undefined, (new Boolean(false)), '0']); ");
/*fuzzSeed-85495475*/count=569; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return Math.ceil((Math.hypot((( + mathy0(( + ( + Math.hypot(Math.asin(Math.fround(( ~ y))), -Number.MAX_VALUE))), ( + (( + Math.max(( + ((mathy0(y, 1/0) % 0) | 0)), ( + -Number.MIN_SAFE_INTEGER))) == Math.atanh((y >>> 0)))))) >>> 0), (Math.fround((Math.fround(( + Math.min(( + Number.MIN_VALUE), ( + (mathy0((-(2**53-2) >>> 0), (y >>> 0)) >>> 0))))) && (x | 0))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=570; tryItOut("/*infloop*/for(let x in ((q => q)((void options('strict_mode')))))h1 = {};");
/*fuzzSeed-85495475*/count=571; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - (mathy0((( + (( + ((x | 0) + ( ! y))) | ( + Math.cos(( + (( + -0x0ffffffff) >= ( + 0.000000000000001))))))) >>> 0), (( + ( ~ ( + Math.hypot(Math.imul(x, 0x100000001), 0/0)))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), 0/0, -0, 0.000000000000001, 2**53, 0x080000000, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, -0x080000000, -0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -0x07fffffff, -1/0, 2**53-2, 1, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -(2**53+2), 0x100000000, -0x100000001, 0x0ffffffff, Number.MAX_VALUE, 42]); ");
/*fuzzSeed-85495475*/count=572; tryItOut("\"use strict\"; var x =  /* Comment */'fafafa'.replace(/a/g, x), x, mkklnq, [] = x, x =  '' , padbjz, x, bkpabe;switch(/*FARR*/[({a1:1}), , , \"\\u07C1\", x,  \"\" , new RegExp(\"[\\\\S\\u0008-\\\\x25\\u9aef]\", \"y\"),  '' , x, new RegExp(\"(?!([^])|.(?:\\\\b)*(?:(?:\\\\d\\\\b+?)))|\\\\b*?\", \"gyi\"), ...[]].some(function(q) { return q; })) { case 8:  }");
/*fuzzSeed-85495475*/count=573; tryItOut("delete h1.get;");
/*fuzzSeed-85495475*/count=574; tryItOut("s2 += this.s1;");
/*fuzzSeed-85495475*/count=575; tryItOut("i0.next();");
/*fuzzSeed-85495475*/count=576; tryItOut("\"use asm\"; o2.a1[3] = t1;");
/*fuzzSeed-85495475*/count=577; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((((Uint16ArrayView[((0x515ef499) / (((0xfbe04e05)) & ((0xafec05e7)))) >> 1])) << ((0xffffffff)+(i0))) % (((!(i0))+(i0)) | (x))))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=578; tryItOut("switch( /x/ ) { default: print(Math);break;  }");
/*fuzzSeed-85495475*/count=579; tryItOut("");
/*fuzzSeed-85495475*/count=580; tryItOut("\"use strict\"; this.m2.delete(e2);");
/*fuzzSeed-85495475*/count=581; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((0x1ded0951)-(i1)))|0;\n  }\n  return f; })(this, {ff: \"\\uCE17\".prototype}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x07fffffff, 0x080000000, -Number.MIN_VALUE, 0x080000001, 1/0, Number.MIN_VALUE, 0x100000000, 2**53, -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 1, -0, -0x100000001, 0, -0x080000001, -1/0, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -0x100000000, 0/0, -0x0ffffffff, 0x100000001, -(2**53+2), 42, -(2**53-2), 0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=582; tryItOut("for (var v of p2) { try { this.g1.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(g2.g2.b1, a0); }");
/*fuzzSeed-85495475*/count=583; tryItOut("print((4277));");
/*fuzzSeed-85495475*/count=584; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1|(?:(?=[^\\D\u6a2b\\s\\d].{1,}\\b+{4,5})|\\3+|.{536870912,}$?)+?/gim; var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-85495475*/count=585; tryItOut("\"use strict\"; v2 = 4;\ng0.offThreadCompileScript(\"function f1(t1)  { return x } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: x, sourceIsLazy: true, catchTermination: (x % 2 != 0) }));\n");
/*fuzzSeed-85495475*/count=586; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-85495475*/count=587; tryItOut("mathy4 = (function(x, y) { return (Math.sin((Math.fround(Math.pow(( + (( + y) << ( ! Math.fround(Math.cos(x))))), Math.fround((Math.min(((Math.trunc((y | 0)) | 0) !== x), -0x0ffffffff) * Math.fround(y))))) | 0)) | 0); }); testMathyFunction(mathy4, [0, -0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), -0x100000001, 0x07fffffff, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 0x100000001, 0x080000000, Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, -0x07fffffff, 1.7976931348623157e308, -(2**53-2), -Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, 0x080000001, -(2**53), 0x0ffffffff, 2**53, 0x100000000, -1/0, -0x080000000, -0, 0/0]); ");
/*fuzzSeed-85495475*/count=588; tryItOut("mathy0 = (function(x, y) { return (Math.pow((Math.fround(((Math.max(y, (x >>> 0)) >>> 0) | Math.min(Math.fround(y), ( + ( - ( + (y << ( ! Math.fround(x))))))))) ? (( - ((Math.cbrt(Number.MIN_VALUE) | 0) >>> 0)) >>> 0) : ( + Math.imul(( + Math.sin(((x + y) | 0))), x))), ( + ((x >>> 0) != (( + Math.fround(y)) | 0)))) >>> 0); }); testMathyFunction(mathy0, [-(2**53+2), Number.MIN_VALUE, -0x080000000, 0, -0x0ffffffff, 0.000000000000001, 2**53, 0x07fffffff, 0x100000000, 1, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -Number.MIN_VALUE, 42, 1.7976931348623157e308, 0x080000001, -0x100000001, -0x100000000, Math.PI, -0x07fffffff, -(2**53-2), 1/0, -(2**53), -1/0, 0x080000000, 0/0]); ");
/*fuzzSeed-85495475*/count=589; tryItOut("/*hhh*/function bcuhpz(\u3056 = x, ...y){for(let b in new RegExp(\"\\\\uebc4*?\", \"gyim\")) {m1 = new WeakMap; }}bcuhpz((4277),  \"\" );");
/*fuzzSeed-85495475*/count=590; tryItOut("\"use strict\"; /*bLoop*/for (awnrpc = 0; awnrpc < 46; ++awnrpc) { if (awnrpc % 6 == 1) { (\"\\uDB92\"); } else { print(new (\"\\u2F81\")(null)); }  } ");
/*fuzzSeed-85495475*/count=591; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 4.722366482869645e+21;\n    var i3 = 0;\n    var d4 = -590295810358705700000.0;\n    i0 = (((((0x89a47dbd) == (0x1a911ab2))+(/*FFI*/ff(((d2)))|0)) | (((+/*FFI*/ff(((((-0x8000000)) ^ ((0x2219ffd0)))), ((-0x8000000)), ((33554433.0)), ((576460752303423500.0)), ((-8589934591.0)), ((-8796093022209.0)), ((-2.4178516392292583e+24)), ((-4.0)), ((-137438953471.0)))) == ((0x7edc50c) ? (0.5) : (-33554433.0)))*-0xd741f)) < ((((((0xffffffff)) >> ((0xd098c48d))) >= (~~(+(0.0/0.0))))-(0xc9d4872b)-((((-0x1183786) / (-0x2fbde54))>>>(((0x204bbfd9)))))) & ((!(((-0xc5cbe*(0xffa0ffe3)) | ((i3)-(0xe5ba763e))))))));\n    i3 = (0xf9249791);\n    return ((-((((0xba7ef89e)*0xab29d) ^ ((x = new RegExp(\"(?!\\\\b+)|[^\\u83c6\\u0012-\\\\\\u267c\\\\s\\\\W](?![^\\\\D\\\\b-5])\\\\b+?\", \"gm\")))))))|0;\n  }\n  return f; })(this, {ff: (e =>  { \"use strict\"; return (21.unwatch(\"z\")) } ).bind(window, x)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=592; tryItOut("print(new RegExp(\"\\\\1\\\\b+{3,4}((?:\\\\S)+?(?:\\\\cW))*?^\\\\B*^|(?!\\\\b|\\\\S){4,6}\", \"i\"));");
/*fuzzSeed-85495475*/count=593; tryItOut("print(({a2:z2}));\n{}\n");
/*fuzzSeed-85495475*/count=594; tryItOut("for(let e of undefined) window.stack;");
/*fuzzSeed-85495475*/count=595; tryItOut("\"use strict\"; a1.pop(e2, a2);");
/*fuzzSeed-85495475*/count=596; tryItOut("/*RXUB*/var r = /\\1[^]\\1+\\1|(?=(?=\\D))*??[\\t-\\u00CD\\u1b08\\W]*|.|.(\\s*)|\\b\\2+/i; var s = \"\\n11\\naeee\\u00ceeeeaa7\\n11\\na\\u3878\\u1b98 a\\na\\n11\\na\\n11\\na\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=597; tryItOut("\"use strict\"; a1.push(g1);");
/*fuzzSeed-85495475*/count=598; tryItOut("\"use strict\"; t2 = g0.t2.subarray(({valueOf: function() { /*ODP-3*/Object.defineProperty(h0, \"getDate\", { configurable: true, enumerable: let (c = x, x = eval =  \"\" , eval = (makeFinalizeObserver('tenured')), eval = x) x, writable: false, value: this.p1 });return 9; }}), v2);");
/*fuzzSeed-85495475*/count=599; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-85495475*/count=600; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.pow(mathy0((( - ( + x)) | 0), Math.atan(length **=  \"\" )), (Math.fround(( + Math.fround(Math.fround(((( + ( ~ ( + (( + Math.atan2(( + ( + (x >>> 0))), ( + 2**53+2))) & x)))) | 0) >> Math.fround(mathy0(Math.min(Math.log10((y >>> 0)), mathy0(x, x)), ( ~ 0x080000001)))))))) >>> 0)) | 0); }); testMathyFunction(mathy1, [-0x07fffffff, 2**53+2, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x100000000, -0, -(2**53+2), 0/0, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, 2**53-2, -0x080000001, 42, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, -0x100000001, 2**53, 0x100000001, 0x080000000, Math.PI, 0x07fffffff, 0x080000001, 0, 1.7976931348623157e308, 1]); ");
/*fuzzSeed-85495475*/count=601; tryItOut("mathy2 = (function(x, y) { return ( ! (((( + Math.fround((((x | 0) <= x) >= (( + x) | 0)))) | 0) * ((Number.MIN_SAFE_INTEGER << x) | 0)) | 0)); }); testMathyFunction(mathy2, [-(2**53), 0/0, -Number.MIN_VALUE, -0, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, 2**53+2, -1/0, -0x080000001, 0x07fffffff, 42, -0x07fffffff, 1, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, -0x100000001, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, 1/0, 2**53, Math.PI, 0, 0x080000000, -(2**53+2), -0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=602; tryItOut("i1.next();");
/*fuzzSeed-85495475*/count=603; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.fround(Math.log2((((Math.fround(( ~ x)) >>> 0) + ((( - ((Math.pow(( + Math.imul(y, x)), x) | 0) | 0)) | 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [(new Boolean(false)), (new Number(-0)), objectEmulatingUndefined(), NaN, '', (new String('')), 0.1, (function(){return 0;}), true, -0, ({toString:function(){return '0';}}), /0/, 0, ({valueOf:function(){return '0';}}), (new Number(0)), '\\0', '0', false, undefined, '/0/', (new Boolean(true)), null, 1, ({valueOf:function(){return 0;}}), [], [0]]); ");
/*fuzzSeed-85495475*/count=604; tryItOut("\"use strict\"; /*oLoop*/for (jirowr = 0, x; jirowr < 14; ++jirowr) { return; } ");
/*fuzzSeed-85495475*/count=605; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ((( - Math.max((((y | 0) < (Math.expm1(x) | 0)) | 0), Math.hypot(( + Math.tanh((( ~ (y | 0)) | 0))), ( + Math.log1p((0x080000000 >>> 0)))))) >>> 0) & ( + ( ! Math.fround(( ! Math.fround(( + mathy0(( + y), (y >>> 0)))))))))); }); testMathyFunction(mathy3, [-1/0, -(2**53), -(2**53+2), 0x0ffffffff, 42, 0/0, -(2**53-2), Math.PI, 1/0, 0x07fffffff, -0x100000001, 0x100000000, Number.MIN_VALUE, 0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x080000001, 1, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 0.000000000000001, 2**53+2, -0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000000, 0x100000001, 0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=606; tryItOut("\"use strict\"; v1 = Array.prototype.some.call(a2, (function(j) { if (j) { t1[({valueOf: function() { o1.toSource = (function mcc_() { var ksewns = 0; return function() { ++ksewns; if (/*ICCD*/ksewns % 3 == 2) { dumpln('hit!'); try { v0 = a2.length; } catch(e0) { } try { e0 = new Set(i1); } catch(e1) { } try { o0.v2 = evalcx(\"function f1(o0.g1.h2) let (eval)  \\\"\\\" \", g1); } catch(e2) { } /*RXUB*/var r = g2.r2; var s = \"\\u008d\"; print(s.search(r));  } else { dumpln('miss!'); try { o0.a1.unshift(p2, this.g0, s1, v1, v2, g0); } catch(e0) { } try { t2 = new Uint8Array(b2, 16, 9); } catch(e1) { } v1 = Object.prototype.isPrototypeOf.call(p2, o2.g0); } };})();return 9; }})] = o1; } else { try { i2.send(i2); } catch(e0) { } try { a2[12]; } catch(e1) { } try { a2.push(this.a1); } catch(e2) { } b1.valueOf = (function(j) { if (j) { try { o2.o2.v2 = g2.runOffThreadScript(); } catch(e0) { } v2 = Array.prototype.reduce, reduceRight.apply(a0, [(function mcc_() { var ibahdn = 0; return function() { ++ibahdn; if (/*ICCD*/ibahdn % 3 == 2) { dumpln('hit!'); try { t0[7] = t0; } catch(e0) { } try { m1 + v0; } catch(e1) { } try { Array.prototype.sort.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (-16385.0);\n    }\n    d0 = (((-1.9342813113834067e+25)) % ((d0)));\n    d0 = (+((3.022314549036573e+23)));\n/*tLoop*/for (let w of /*MARR*/[-0x080000001, new String('q'), [], [], \"\\u1CDE\", new String('q'), \"\\u1CDE\", \"\\u1CDE\", \"\\u1CDE\", \"\\u1CDE\", \"\\u1CDE\", \"\\u1CDE\", \"\\u1CDE\", \"\\u1CDE\", [], ['z'], -0x080000001, [], ['z']]) { v1 = evalcx(\"\\\"use strict\\\"; Array.prototype.unshift.call(a1);\", g2); }    d0 = (((+(0.0/0.0))) * ((+abs(((+(-1.0/0.0)))))));\n    d0 = (+(((0xd721e196))>>>(((0x6583bef7)))));\n    i1 = ((((0x48fea2b7)-(0x46faea34)-(i1))>>>((i1))));\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: (encodeURIComponent).bind}, new ArrayBuffer(4096))]); } catch(e2) { } print(uneval(p1)); } else { dumpln('miss!'); try { e1.add(m2); } catch(e0) { } /*MXX1*/o1 = g2.Map.prototype.get; } };})(), o0.g0.o1.b0, s0, i1, this.e2, (void options('strict')), h0, h2, g2, a0]); } else { try { m0.has(m0); } catch(e0) { } try { v0 = (b1 instanceof g1.g2); } catch(e1) { } try { print(o1); } catch(e2) { } a2.toSource = (function() { /*RXUB*/var r = r1; var s = s0; print(s.split(r));  return o1; }); } }); } }), o0, t0, o2, i2);");
/*fuzzSeed-85495475*/count=607; tryItOut("mathy1 = (function(x, y) { return Math.log2(Math.fround(mathy0(( + ( + ((Math.max((Math.atan(Math.pow(y, y)) | 0), (Number.MIN_VALUE | 0)) | 0) | 0))), mathy0(x, Math.hypot(Math.min(-(2**53-2), (y ? ( + Math.atan2((y | 0), (x | 0))) : x)), -Number.MIN_SAFE_INTEGER))))); }); ");
/*fuzzSeed-85495475*/count=608; tryItOut("mathy4 = (function(x, y) { return Math.hypot(mathy1((Math.sinh(( + (x + Math.max(( + (x % Math.fround((Math.atan2(y, (x >>> 0)) >>> 0)))), Math.min((Math.tan(( + 0x080000001)) | 0), x))))) >>> 0), Math.fround(( + ((Math.tan(x) | 0) === (Math.fround(mathy0((Math.pow(( - ( + y)), y) >>> 0), (Math.log1p(x) >>> 0))) | 0))))), ( + Math.atanh(( + ((((Math.asinh(Number.MIN_SAFE_INTEGER) | 0) >>> 0) == (Math.fround((Math.fround((Math.log10(Math.fround(y)) | 0)) ^ Math.fround(y))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy4, [2**53-2, -0x0ffffffff, -0x100000000, 2**53+2, 0x100000001, -0x080000000, 0x0ffffffff, 1.7976931348623157e308, 2**53, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, -0, 0x07fffffff, -1/0, 0.000000000000001, 42, 0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 1/0, 1, Number.MAX_VALUE, -(2**53), -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-85495475*/count=609; tryItOut("h2 = ({getOwnPropertyDescriptor: function(name) { for (var v of a1) { try { const a1 = []; } catch(e0) { } try { m0.get(b0); } catch(e1) { } try { x = g2.g2.o2.f0; } catch(e2) { } i1.next(); }; var desc = Object.getOwnPropertyDescriptor(s0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { throw b0; var desc = Object.getPropertyDescriptor(s0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e1.add(this.f1);; Object.defineProperty(s0, name, desc); }, getOwnPropertyNames: function() { v0 = evaluate(\"null;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: window, sourceIsLazy: (x % 6 != 1), catchTermination: true }));; return Object.getOwnPropertyNames(s0); }, delete: function(name) { a2 = a0.map((function() { for (var j=0;j<15;++j) { f0(j%2==1); } }), f1);; return delete s0[name]; }, fix: function() { a2.unshift(b0, o1, t0, g1, o2.a0);; if (Object.isFrozen(s0)) { return Object.getOwnProperties(s0); } }, has: function(name) { /*RXUB*/var r = this.r0; var s = o1.s0; print(uneval(r.exec(s))); ; return name in s0; }, hasOwn: function(name) { h0.fix = f2;; return Object.prototype.hasOwnProperty.call(s0, name); }, get: function(receiver, name) { a1.length = 19;; return s0[name]; }, set: function(receiver, name, val) { for (var p in e1) { try { v2 = this.a2.some(); } catch(e0) { } try { v1 = g0.eval(\"this.v1 = Array.prototype.some.apply(a1, [(function() { for (var j=0;j<22;++j) { f1(j%5==0); } })]);\"); } catch(e1) { } i2.next(); }; s0[name] = val; return true; }, iterate: function() { h2 = ({getOwnPropertyDescriptor: function(name) { v2 = (g0 instanceof t2);; var desc = Object.getOwnPropertyDescriptor(m2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g1.a1 = arguments;; var desc = Object.getPropertyDescriptor(m2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v0 = r1.toString;; Object.defineProperty(m2, name, desc); }, getOwnPropertyNames: function() { a1.unshift(x, o1.f1, f2);; return Object.getOwnPropertyNames(m2); }, delete: function(name) { throw o2; return delete m2[name]; }, fix: function() { o2 = t0.__proto__;; if (Object.isFrozen(m2)) { return Object.getOwnProperties(m2); } }, has: function(name) { /*RXUB*/var r = r2; var s = s1; print(s.split(r)); print(r.lastIndex); ; return name in m2; }, hasOwn: function(name) { t1.set(t2, 13);; return Object.prototype.hasOwnProperty.call(m2, name); }, get: function(receiver, name) { a0.splice(4, 17);; return m2[name]; }, set: function(receiver, name, val) { /*MXX1*/o0 = g2.WeakMap.length;; m2[name] = val; return true; }, iterate: function() { Object.defineProperty(this, \"a0\", { configurable: (x % 5 != 4), enumerable: false,  get: function() {  return Array.prototype.slice.call(a0, NaN, NaN, this.h2, o1.b0, v2); } });; return (function() { for (var name in m2) { yield name; } })(); }, enumerate: function() { print(e0);; var result = []; for (var name in m2) { result.push(name); }; return result; }, keys: function() { i0 = new Iterator(g1.p0, true);; return Object.keys(m2); } });; return (function() { for (var name in s0) { yield name; } })(); }, enumerate: function() { return t1; var result = []; for (var name in s0) { result.push(name); }; return result; }, keys: function() { Array.prototype.shift.call(a0);; return Object.keys(s0); } });");
/*fuzzSeed-85495475*/count=610; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround((((Math.asin(Math.fround((((y ^ (( ! 0x100000001) >>> 0)) | 0) >>> Math.fround(( + Math.atan(Math.sin(x))))))) | 0) != (Math.max((( ! (x ? x : x)) | 0), ((Math.pow((y >>> 0), (x >>> 0)) >>> 0) | 0)) | 0)) | 0)) << (( + (( + (((y >= (-0x0ffffffff | 0)) | 0) , (Math.cbrt((y | 0)) >>> 0))) >> ( + ((Math.fround(( ~ (( ! x) | 0))) < (y | 0)) >>> 0)))) >>> 0))); }); ");
/*fuzzSeed-85495475*/count=611; tryItOut("e0.has(b2);");
/*fuzzSeed-85495475*/count=612; tryItOut("mathy0 = (function(x, y) { return Math.acos((( + ((y != Math.clz32(-0x07fffffff)) | 0)) | 0)); }); testMathyFunction(mathy0, [-0x100000001, 0x080000000, 2**53, 42, 0x0ffffffff, -1/0, -(2**53-2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, -0x100000000, -0, 2**53-2, 2**53+2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, 1/0, 0.000000000000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 0, -(2**53), -0x07fffffff, 0x07fffffff, -(2**53+2), 0x100000001, 0/0]); ");
/*fuzzSeed-85495475*/count=613; tryItOut("x = v2;");
/*fuzzSeed-85495475*/count=614; tryItOut("mathy5 = (function(x, y) { return ( + Math.log(( + Math.hypot((Math.sqrt(Math.max(x, Math.fround(Math.max(Math.fround(y), Number.MIN_VALUE)))) | 0), (Math.exp((( + ( + ( + (Math.imul((( + Math.cbrt(x)) | 0), (Math.fround(Math.atan2(Math.fround(x), Math.fround(y))) | 0)) | 0)))) >>> 0)) < Math.tanh((Math.fround(( ! Math.fround(y))) | 0))))))); }); ");
/*fuzzSeed-85495475*/count=615; tryItOut("m0.__proto__ = m1;");
/*fuzzSeed-85495475*/count=616; tryItOut("\"use strict\"; f1(p1);v1 = a1.length;");
/*fuzzSeed-85495475*/count=617; tryItOut("a1[2];");
/*fuzzSeed-85495475*/count=618; tryItOut("");
/*fuzzSeed-85495475*/count=619; tryItOut("\"use strict\"; s2 += s2;");
/*fuzzSeed-85495475*/count=620; tryItOut("mathy4 = (function(x, y) { return (Math.log2(((Math.min(( + (Math.atan((( + Math.atan2(y, x)) & Math.log(x))) | 0)), ( + Math.min(( + Math.atan2(x, Math.pow(x, Math.fround(x)))), ( + y)))) * Math.sqrt(mathy0(( + mathy2((y | (x | 0)), Math.atanh(-(2**53+2)))), (-Number.MAX_SAFE_INTEGER - (((y >>> 0) << x) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [-0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -0x080000000, Number.MAX_VALUE, -(2**53-2), -(2**53), 2**53, 0.000000000000001, -1/0, 1/0, 0x100000000, Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 1, 0x080000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0, -(2**53+2), 0/0, 0x0ffffffff, -0x100000001, -0x100000000, 0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, 1.7976931348623157e308, Math.PI, 0, 2**53+2]); ");
/*fuzzSeed-85495475*/count=621; tryItOut("v1 = o2.g1.eval(\"e2 = new Set;\");");
/*fuzzSeed-85495475*/count=622; tryItOut("a0 = [];");
/*fuzzSeed-85495475*/count=623; tryItOut("i0.next();");
/*fuzzSeed-85495475*/count=624; tryItOut("v1 = evalcx(\"function f0(b2)  { v0 = this.g0.runOffThreadScript(); } \", g1);");
/*fuzzSeed-85495475*/count=625; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=626; tryItOut("print(uneval(o1.a1));");
/*fuzzSeed-85495475*/count=627; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(((((( + Math.expm1(((Math.min(Math.fround(y), (-0x07fffffff | 0)) | 0) >>> 0))) >>> 0) === ((0x100000001 ** y) >>> 0)) >>> 0) > (( + (Math.fround(Math.exp(Math.fround(Math.fround(Math.min((( ! (y | 0)) >>> 0), Math.fround(Math.fround(Math.tanh(Math.fround(x))))))))) >>> Math.fround(Math.min(((y | 0) ? (Math.clz32((-(2**53) | 0)) | 0) : ((x >> y) | 0)), ((-0x100000000 >>> 0) ? (mathy1((( + y) | 0), Math.log2(y)) | 0) : (Math.pow((y >>> 0), ( ~ (x >>> 0))) >>> 0)))))) >>> 0))); }); testMathyFunction(mathy3, [-0x100000000, 0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, -0x100000001, -0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, 0x07fffffff, 0x100000001, 42, 0.000000000000001, -1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53), -(2**53+2), 2**53, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, -0, -0x0ffffffff, Math.PI, 0/0, 1]); ");
/*fuzzSeed-85495475*/count=628; tryItOut("\"use strict\"; i0.send(s2);");
/*fuzzSeed-85495475*/count=629; tryItOut("s0 = s0.charAt(Math);");
/*fuzzSeed-85495475*/count=630; tryItOut("\"use strict\"; s0 = a0[19];");
/*fuzzSeed-85495475*/count=631; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! ( + (mathy1(((Number.MIN_SAFE_INTEGER == -0x07fffffff) | 0), y) | 0))); }); testMathyFunction(mathy2, [2**53, 0, -(2**53+2), -0x100000000, 0x080000000, 42, -1/0, -0x080000001, 0/0, 1.7976931348623157e308, 0x080000001, Math.PI, 0x07fffffff, 0x0ffffffff, 2**53+2, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 2**53-2, -(2**53), 0x100000000, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -0x0ffffffff, 1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=632; tryItOut("a2.pop();s0 = new String(a0);");
/*fuzzSeed-85495475*/count=633; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow((((Math.imul(((Math.imul(x, (Math.fround((Number.MAX_SAFE_INTEGER | 0)) | 0)) === ((y >>> 0) ** ((( + ( - ( + y))) % y) >>> 0))) | 0), (( - (y >>> 0)) >>> 0)) | 0) ? (( + Math.fround(Math.log10(( + Math.max(x, Math.fround(y)))))) | 0) : (((( + Math.fround(Math.round(Math.fround(y)))) >>> 0) || Math.fround(Math.fround((x >>> Math.fround(( - (42 | 0))))))) | 0)) | 0), Math.fround((Math.log2((Math.fround(Math.log1p((Math.pow(2**53, Math.max(x, (y ^ x))) >>> 0))) >>> 0)) | 0))); }); testMathyFunction(mathy0, [1/0, 1, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x080000001, -(2**53+2), -(2**53), 1.7976931348623157e308, 0, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, -0x100000001, 2**53-2, -0x07fffffff, -0, 42, -0x0ffffffff, Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, 0x0ffffffff, 0/0, 2**53, -Number.MIN_VALUE, -0x080000000, Math.PI, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=634; tryItOut("let \u3056 = SimpleObject(), x;print( /x/g  ? /(?=[\u39b9-\\uEd31\uaed9-\ueba6\\u4BE5]$\\v(?=^)\\B)/gy : x);\n/*infloop*/for(x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: (String.prototype.trimRight).apply, enumerate: function() { throw 3; }, keys: undefined, }; })(length), +({})); \"\\uB7B2\"; eval(\"/* no regression tests found */\")) {selectforgc(o0); }\n");
/*fuzzSeed-85495475*/count=635; tryItOut("testMathyFunction(mathy3, [0x100000001, 42, -(2**53+2), -Number.MAX_VALUE, -(2**53), 0x0ffffffff, 0/0, 1/0, 2**53, -Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, 0x080000000, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, -0, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -0x080000000, -0x100000001, 0x100000000, 0x080000001, -0x0ffffffff, 1, -1/0, 2**53-2, 0, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=636; tryItOut("i2.toSource = f0;");
/*fuzzSeed-85495475*/count=637; tryItOut("\"use strict\"; const w = x;const x = w;print(x);\n/*bLoop*/for (var mxfjjm = 0; mxfjjm < 48; ++mxfjjm) { if (mxfjjm % 37 == 1) { print(y); } else { print(x); }  } \n");
/*fuzzSeed-85495475*/count=638; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max(Math.acosh((( - x) ** Math.fround((y << ( ~ Math.max(-0x100000001, y)))))), Math.fround((Math.fround(Math.tanh((Math.sin(Math.tan(x)) | 0))) ? Math.fround(Math.hypot(x, Math.fround(Math.fround(mathy0(Math.fround(Math.max(Math.fround(x), Math.fround((( - x) | 0)))), Math.fround(-Number.MAX_VALUE)))))) : ( + ( + -0x100000001))))); }); testMathyFunction(mathy1, [0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, 0x100000000, 1.7976931348623157e308, -1/0, -0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 2**53, 1, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, Math.PI, -Number.MIN_VALUE, 0x080000000, 42, 0x100000001, -0x0ffffffff, 0x080000001, -0, -0x080000000, -0x080000001, 2**53+2, 0, -0x100000001]); ");
/*fuzzSeed-85495475*/count=639; tryItOut("f1 + '';");
/*fuzzSeed-85495475*/count=640; tryItOut("with(-8 ^ \"\\uDA76\")o0.v0 = evalcx(\"/* no regression tests found */\", g2);var d = new window.watch(\"for\", function shapeyConstructor(ejcxcc){this[\"valueOf\"] = Date.prototype.getMilliseconds;if (false) for (var ytqswwruj in this) { }Object.preventExtensions(this);Object.defineProperty(this, new String(\"2\"), ({configurable: false, enumerable: true}));delete this[\"call\"];return this; })((Math.imul(0, -15)));");
/*fuzzSeed-85495475*/count=641; tryItOut("for (var v of g1.g0.p0) { try { g2.v2 = (t2 instanceof this.t1); } catch(e0) { } try { s1 += 'x'; } catch(e1) { } Object.freeze(h0); }");
/*fuzzSeed-85495475*/count=642; tryItOut("let (//h\nhwjdkj) { ; }");
/*fuzzSeed-85495475*/count=643; tryItOut("testMathyFunction(mathy3, [1/0, 0x080000000, Number.MAX_VALUE, 0x07fffffff, -0x080000000, -0x07fffffff, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), Math.PI, 0x080000001, 0/0, 2**53+2, -0, 0, 2**53, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, -1/0, -0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 1, -Number.MAX_VALUE, 42]); ");
/*fuzzSeed-85495475*/count=644; tryItOut("Object.prototype.unwatch.call(this.f2, \"x\");");
/*fuzzSeed-85495475*/count=645; tryItOut("with({}) return;for(let [a, z] =  /x/  in x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: ((void options('strict'))), defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return []; }, delete: /*wrap2*/(function(){ var yxjcel = new function (d) { for (var v of g2.g0) { try { g0.s1 = new String; } catch(e0) { } Object.seal(o1.t1); } } (\"\\u56E0\"); var xlwbrb = function(y) { return (window = Proxy.create(({/*TOODEEP*/})( /x/g ), new RegExp(\"(?:(?:[\\u00a1-\\u00f2\\u8e9e-\\u00a7]*|[^]*?|[^])).|(?![^]?)[^\\\\\\u00ab-\\\\\\u00f3\\\\\\u008d-\\\\u9fa0\\\\\\u8669\\\\S]\", \"\"))) }; return xlwbrb;})(), fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: undefined, get: Function, set: function(y) { \"use asm\"; return ++y }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(window), (({eval: let (y = /(?:^)*?/gi) \"\\u92A3\" })))) {g2.g1.offThreadCompileScript(\"v0 = Object.prototype.isPrototypeOf.call(h1, o2);\\nreturn  /x/ ;\\n\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy:  /x/  || {} >= (a = window), catchTermination: false }));/*tLoop*/for (let e of /*MARR*/[[1], true, [1], true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, [1], [1], true, true, true, [1], [1]]) { o1 + ''; } }");
/*fuzzSeed-85495475*/count=646; tryItOut("mathy2 = (function(x, y) { return (Math.fround((Math.min(Math.fround(Math.fround(mathy1(Math.fround(mathy0(y, (x >>> x))), Math.fround((Math.trunc(((mathy1(1/0, (x != x)) === Math.fround(x)) >>> 0)) >>> 0))))), Math.fround(((Math.cosh((((x >>> 0) | ( + x)) && -0x0ffffffff)) >>> 0) ** ((Math.imul((x >>> 0), (( + Math.log((y | 0))) >>> 0)) >>> 0) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x080000001, -0x100000000, -Number.MAX_VALUE, 0x100000001, 0x080000000, 2**53+2, 0x0ffffffff, -(2**53+2), -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 1, -0x080000000, Number.MAX_VALUE, 2**53-2, -(2**53-2), 42, Math.PI, -1/0, 0x100000000, -Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, 2**53, -0, 0x080000001, -(2**53)]); ");
/*fuzzSeed-85495475*/count=647; tryItOut("this.v1 = t0.byteOffset;");
/*fuzzSeed-85495475*/count=648; tryItOut("\"use strict\"; i1.toString = (function() { try { for (var v of f1) { try { var v2 = undefined; } catch(e0) { } try { Object.defineProperty(g2, \"s1\", { configurable: true, enumerable: false,  get: function() {  return ''; } }); } catch(e1) { } v0 = (o2 instanceof this.b1); } } catch(e0) { } try { this.e1.has(o2.i0); } catch(e1) { } try { Array.prototype.sort.apply(a2, [f1, a0, z = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: Function, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(\"\\uC228\"), let (c) /([^])/).valueOf(\"number\").yoyo( /x/g )]); } catch(e2) { } a0.forEach((function mcc_() { var ujjhrv = 0; return function() { ++ujjhrv; if (/*ICCD*/ujjhrv % 6 == 0) { dumpln('hit!'); try { /*RXUB*/var r = this.r0; var s = s2; print(s.split(r));  } catch(e0) { } try { Array.prototype.reverse.apply(a2, [s2]); } catch(e1) { } this.v0 = Object.prototype.isPrototypeOf.call(p0, t2); } else { dumpln('miss!'); o1.i2 = a1.iterator; } };})(), h1, v1, this.o0.e0, g1.b2); return h0; });");
/*fuzzSeed-85495475*/count=649; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=650; tryItOut("i1.send(g1.b1);");
/*fuzzSeed-85495475*/count=651; tryItOut("testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, 42, 0/0, -0x080000001, 0x080000000, 0x100000001, 0.000000000000001, 2**53, Number.MIN_VALUE, -0x0ffffffff, -0, Number.MAX_VALUE, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, -0x07fffffff, 2**53+2, 1.7976931348623157e308, 0, Math.PI, 1, 1/0, 0x080000001, 2**53-2, -0x080000000, -(2**53-2), -1/0]); ");
/*fuzzSeed-85495475*/count=652; tryItOut("\"use asm\"; m1.__proto__ = o2.g0;(4277);");
/*fuzzSeed-85495475*/count=653; tryItOut("h0.keys = f1;print(x);");
/*fuzzSeed-85495475*/count=654; tryItOut("r2 = /(?!^){0,}/yi;");
/*fuzzSeed-85495475*/count=655; tryItOut("p0 + o1;");
/*fuzzSeed-85495475*/count=656; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.sin(Math.fround(Math.atan2(Math.imul(( + mathy2(y, Math.log10(0x080000001))), ( + ( + ( - (((2**53+2 , (x >>> 0)) >>> 0) >>> 0))))), ( + mathy1(( + Number.MAX_VALUE), (( + ((-Number.MAX_SAFE_INTEGER >>> 0) / ( + y))) | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[({x:3}),  \"use strict\" , ({x:3}),  /x/g ,  /x/g ,  /x/g ,  /x/g , true,  /x/g , ({x:3}), ({x:3}), true,  \"use strict\" , true, true,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , ({x:3}), ({x:3}), true,  /x/g ,  /x/g ,  /x/g ,  /x/g , ({x:3}), ({x:3}),  \"use strict\" ]); ");
/*fuzzSeed-85495475*/count=657; tryItOut("b0 + '';");
/*fuzzSeed-85495475*/count=658; tryItOut("testMathyFunction(mathy2, [0.000000000000001, -0x0ffffffff, -0x100000000, 0x07fffffff, -(2**53), 1, Math.PI, 2**53, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, -0x080000000, -(2**53+2), -(2**53-2), 0x100000001, 1/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, -Number.MAX_VALUE, 1.7976931348623157e308, 42, 2**53-2, -1/0]); ");
/*fuzzSeed-85495475*/count=659; tryItOut("a1.toString = (function(j) { f1(j); });");
/*fuzzSeed-85495475*/count=660; tryItOut("\"use strict\"; for (var p in p2) { f0 + f1; }print(!x);");
/*fuzzSeed-85495475*/count=661; tryItOut("let (y) { v1 = evalcx(\"(4277)\", g0); }");
/*fuzzSeed-85495475*/count=662; tryItOut("mathy4 = (function(x, y) { return (Math.min((Math.fround(( ~ (Math.max(x, Math.max((y >>> 0), ((-0 / (x >>> 0)) >>> 0))) >>> 0))) | 0), ((((( + (( + Math.log2(x)) >= ( + y))) >>> 0) / (( + mathy0(( + Math.sqrt(y)), Math.fround(y))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, [-0x0ffffffff, -0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, -0x07fffffff, -0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, 2**53+2, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, 0/0, 0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, 0, 1.7976931348623157e308, 42, -0x100000001, -0, -(2**53), Number.MAX_VALUE, 0x100000000, 0x100000001, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=663; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(mathy0(Math.fround(( + (( + ((y !== Math.ceil(mathy1(Number.MIN_VALUE, (x | 0)))) >>> 0)) <= ( + ( + ((Math.log1p((0x07fffffff >>> 0)) >>> 0) == ( + x))))))), ( ! Math.clz32(y)))) || (Math.fround((-0x100000000 ^ Math.atan2(Math.fround(x), Math.fround(( + Math.pow(0/0, ( + ( ! y)))))))) - Math.asin(( ! x)))); }); ");
/*fuzzSeed-85495475*/count=664; tryItOut("this.v0 = (e0 instanceof s2);");
/*fuzzSeed-85495475*/count=665; tryItOut("g2.v2 = t2[({valueOf: function() { /*RXUB*/var r = /(?:$)+?/i; var s = \"\"; print(r.exec(s)); return 13; }})];");
/*fuzzSeed-85495475*/count=666; tryItOut("\"use strict\"; print(x);\n/*ADP-1*/Object.defineProperty(o2.o2.a1, 1, ({}));\n");
/*fuzzSeed-85495475*/count=667; tryItOut("v0 = this.g2[\"0\"];\nv1 = Object.prototype.isPrototypeOf.call(o0, g0.v2);\n");
/*fuzzSeed-85495475*/count=668; tryItOut("print(x);function NaN(...b) { yield \"\\u6FFC\" } m2.has(a2);");
/*fuzzSeed-85495475*/count=669; tryItOut("\"use strict\"; h2.iterate = Object.freeze;");
/*fuzzSeed-85495475*/count=670; tryItOut("g2 + '';");
/*fuzzSeed-85495475*/count=671; tryItOut("/*infloop*/for(let arguments[\"__count__\"] in ((offThreadCompileScript)((4277))))g0.v1 = this.g0.eval(\"e2.has(this.o1.p0);\");");
/*fuzzSeed-85495475*/count=672; tryItOut("\"use strict\"; ;");
/*fuzzSeed-85495475*/count=673; tryItOut("mathy4 = (function(x, y) { return ((((((((y | 0) , ((Math.atanh(Math.fround(y)) | 0) | 0)) | 0) | 0) == \"\\u04F2\") | 0) | ((( + (x != 1.7976931348623157e308)) - x) & mathy2(-0, x))) >>> 0); }); ");
/*fuzzSeed-85495475*/count=674; tryItOut("mathy2 = (function(x, y) { return ( + Math.max(((((Math.min(x, ( + y)) >>> 0) ? (Math.sign(( + x)) >>> 0) : ((mathy0(Math.fround(x), (mathy0((y >>> 0), (( ! (y | 0)) | 0)) | 0)) >>> 0) >>> 0)) >>> 0) & ((Math.fround((( - (2**53+2 >>> 0)) >>> 0)) , Math.fround((((Math.fround(( + 0x100000001)) >>> 0) , Math.fround(Math.atan2(Math.fround(y), Math.fround(( ! (-(2**53-2) >>> 0)))))) >>> 0))) | 0)), Math.sinh(mathy0((-Number.MIN_VALUE >>> y), y)))); }); ");
/*fuzzSeed-85495475*/count=675; tryItOut("v1 = evaluate(\"(4277)\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-85495475*/count=676; tryItOut("mathy5 = (function(x, y) { return Math.fround(( - (( ~ Math.imul(((Math.hypot(( ~ y), x) >= Math.fround((((Math.cosh((x | 0)) | 0) < Math.fround(y)) | 0))) >>> 0), Math.tanh(( + (((x >>> 0) ** ( + x)) | 0))))) | 0))); }); ");
/*fuzzSeed-85495475*/count=677; tryItOut("\"use strict\"; (intern(intern(/^*?/gym)));i2.next();");
/*fuzzSeed-85495475*/count=678; tryItOut("a0.pop();");
/*fuzzSeed-85495475*/count=679; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return Math.min(( + ( + Math.max(( + (Math.imul(((Math.min((Math.max(x, 2**53+2) | 0), (( + ( + y)) | 0)) | 0) | 0), Math.fround(x)) | 0)), ( + (Math.hypot(((Math.pow(y, ( + mathy3(( + y), ( + -Number.MAX_SAFE_INTEGER)))) | 0) | 0), (Math.tan(Math.fround(( + ((Math.fround(x) % ( + x)) >>> 0)))) >>> 0)) | 0))))), ( + ( ! Math.cosh(y)))); }); testMathyFunction(mathy4, [-0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, 0x0ffffffff, 42, 0.000000000000001, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, 1, -1/0, -0, Number.MAX_SAFE_INTEGER, 0, 0x080000000, 1/0, -0x100000000, Number.MAX_VALUE, 0x07fffffff, -0x080000000, 0/0, 2**53+2, 0x100000001, -0x07fffffff, -(2**53-2), -(2**53), 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, -0x100000001]); ");
/*fuzzSeed-85495475*/count=680; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + Math.min(( + ( ~ (mathy0((Math.expm1(y) / (Math.acosh(Math.fround(x)) / (y << x))), (x != (( + ( + (y | 0))) * mathy0(y, 0x0ffffffff)))) | 0))), (Math.hypot(mathy0(Math.log10(((( - Number.MAX_VALUE) >>> 0) >>> 0)), ( + ( + mathy0(Math.fround(( + mathy0(y, y))), x)))), (( + Math.log2(y)) >>> (Math.atan2(Math.fround(Math.round((y | 0))), (Math.min((y | 0), (Math.hypot(((y >>> 0) << x), ((((42 | 0) ? -0x080000000 : ( + y)) | 0) >>> 0)) >>> 0)) | 0)) >>> 0))) >>> 0))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x07fffffff, 0, 0x080000000, 1/0, 0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, -(2**53), -0x100000001, Math.PI, -1/0, 0x100000000, Number.MAX_VALUE, -0x07fffffff, 1, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 2**53, 42, -Number.MAX_VALUE, -0x080000001, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, -0x080000000, 0x080000001]); ");
/*fuzzSeed-85495475*/count=681; tryItOut("\"use strict\"; v2 = this.g1.t1.BYTES_PER_ELEMENT;\n/*RXUB*/var r = /([^\\W].|([^]|[^\\cC-\\xeA])*?)|\\B|\\1|(?=(?:(?=[^])?))(?!(?=(?![\\s\u5e7a\\B-\\u0076\u3b91])[]|\\3))/gi; var s = \"0\\n\\n\"; print(s.search(r)); \n");
/*fuzzSeed-85495475*/count=682; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=683; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=684; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float64ArrayView[0]) = ((Float32ArrayView[((x)-(0xff892d62)) >> 2]));\n    return (((0xbd8d55a2)))|0;\n  }\n  return f; })(this, {ff: function \u000c(e) { \"use strict\"; yield timeout(1800) } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0.000000000000001, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, 1/0, -(2**53), -1/0, -0, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 1, 2**53, 2**53-2, -0x080000000, 42, 0, -(2**53+2), -(2**53-2), -0x07fffffff, -0x0ffffffff, -0x100000001, 0x080000000, 2**53+2, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x100000000, Number.MAX_VALUE, -0x100000000, Math.PI]); ");
/*fuzzSeed-85495475*/count=685; tryItOut("g2.toString = f2;");
/*fuzzSeed-85495475*/count=686; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=687; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ ( + (Math.fround(Math.log2(( + (Math.cbrt(x) && y)))) | (Math.atan2((mathy1(Math.fround(((Math.atan2((y | 0), (y | 0)) | 0) || 0x100000000)), Math.fround((Math.cosh(((0x080000001 != y) | 0)) | 0))) | 0), (Math.trunc(y) >>> 0)) | 0)))); }); testMathyFunction(mathy5, [Math.PI, 2**53-2, -Number.MAX_SAFE_INTEGER, 42, -0x100000001, 1/0, 0x0ffffffff, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_VALUE, -0, 0, -0x07fffffff, 2**53+2, -(2**53), -0x100000000, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 1, 0x100000000, -0x080000001, 0x07fffffff, 0x080000001, -(2**53+2), 0x100000001, -(2**53-2), -0x080000000, 0.000000000000001, -1/0, 0x080000000]); ");
/*fuzzSeed-85495475*/count=688; tryItOut("yield x;");
/*fuzzSeed-85495475*/count=689; tryItOut("/*RXUB*/var r = /\\u0073(?![^][^]*?)*?|(?!\\2)\\w.(?=\\3)\\d\\d(\\B)|[^\\W\\0]*?(?!(?!\\b))*?/gyim; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-85495475*/count=690; tryItOut("/*ODP-2*/Object.defineProperty(e2, \"hypot\", { configurable: true, enumerable: false, get: (1 for (x in [])), set: Array.prototype.sort.bind(s0) });");
/*fuzzSeed-85495475*/count=691; tryItOut("mathy5 = (function(x, y) { return Math.fround(( + ( + (( + (Math.expm1((Math.cbrt((x | 0)) | 0)) | 0)) || ( + ( + ((y | 0) || (y >>> 0)))))))); }); testMathyFunction(mathy5, [[], '', true, 1, '0', false, 0.1, -0, (new Boolean(true)), null, /0/, '\\0', [0], (new String('')), undefined, ({valueOf:function(){return '0';}}), '/0/', ({toString:function(){return '0';}}), (new Number(0)), 0, (new Boolean(false)), ({valueOf:function(){return 0;}}), (function(){return 0;}), (new Number(-0)), NaN, objectEmulatingUndefined()]); ");
/*fuzzSeed-85495475*/count=692; tryItOut("if((x % 2 == 0)) (z) = this ?  ''  : function(id) { return id }; else print(x);");
/*fuzzSeed-85495475*/count=693; tryItOut("testMathyFunction(mathy4, [-(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, 2**53, -0, 1, 0x0ffffffff, 0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, Math.PI, 0, Number.MAX_VALUE, 0/0, 0.000000000000001, 0x080000000, 0x100000000, 0x07fffffff, -1/0, -(2**53+2), 2**53+2, -Number.MIN_VALUE, 42, -0x07fffffff, 1/0, -0x080000000]); ");
/*fuzzSeed-85495475*/count=694; tryItOut("x = (x = [,,] == (x) = true.throw(x).unshift()), eval = (this.__defineSetter__(\"\\u3056\", eval) instanceof (null.__defineSetter__(\"z\", neuter))), \u3056, {e: arguments, ((arguments = x))(x.yoyo(x = (4277))): [, a, {x}, ], e: {}, x: {d: [{y}], d, x}, \u3056: x} = (( ''  != [[1]]) ** /*MARR*/[null, null, false, false, false, (-1/0), undefined, false, 0x40000000, false, undefined, null, undefined].sort(Array.prototype.keys,  /x/g ) <<= yield window), arguments[\"x\"] = ((p={}, (p.z = true)()) >>>= window), x = 1.__defineSetter__(\"w\", decodeURIComponent), [] = new x(), \"0\", [] = (yield c)();m1.set(o1, a1);");
/*fuzzSeed-85495475*/count=695; tryItOut("\"use strict\"; o2.e2 + t2;");
/*fuzzSeed-85495475*/count=696; tryItOut("a0[v0];");
/*fuzzSeed-85495475*/count=697; tryItOut("print(null);");
/*fuzzSeed-85495475*/count=698; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a0, ({valueOf: function() { print(x);return 7; }}), { configurable: false, enumerable: \"\\uBB35\", writable: true, value: g1.t0 });function x(d = (x = {}), w, x, eval, w, c, x =  /x/ , c, x, y, \u3056, \u3056, b, NaN, x, eval, this.eval, x, \u3056, a, x, y, w, x, x, w, x, x, d = /(?=.)+?/yim, y, NaN, x = \"\u03a0\", NaN, z, y = this.e, \u3056, x, x = w, eval, z, z, x, y, d = x, x, yield = this, x, eval, x = -2, x, \u3056, y, w, x, x, x, x, x, NaN, \u3056 = 4, x, a, c, x, x, z = -1, window, x, NaN =  /x/ ) { a2 = a1.map((function(j) { if (j) { o2 = {}; } else { try { /*RXUB*/var r = this.r2; var s = \"\\n\"; print(s.search(r));  } catch(e0) { } try { o2 + ''; } catch(e1) { } h0.iterate = f1; } })); } (x);");
/*fuzzSeed-85495475*/count=699; tryItOut("/*RXUB*/var r = new RegExp(\".?(?=.)*?$|(?!\\\\W)?|(^)+(?:[^\\\\v-\\\\x4e\\\\s])\", \"gy\"); var s = \"\\n\\u000c\\n0\\n\\u000c\\n0\\u001b\"; print(s.replace(r, encodeURI, \"m\")); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=700; tryItOut("testMathyFunction(mathy4, [1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, -(2**53+2), 0x0ffffffff, -0x080000001, 0, 0/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, Math.PI, 1, -1/0, 0x080000001, 0x100000001, 0x07fffffff, -0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, 42, -0x100000001, -(2**53), Number.MIN_VALUE, 2**53-2, 1/0, -0x07fffffff, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=701; tryItOut("testMathyFunction(mathy0, [Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 0x100000001, 0x080000001, 0/0, 0x100000000, -(2**53+2), 2**53, -(2**53), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, 1/0, -0, -Number.MAX_VALUE, -0x100000000, 42, 2**53-2, 0x07fffffff, -0x0ffffffff, -(2**53-2), 1, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, 0, -0x07fffffff, -0x080000000, -1/0, 0.000000000000001, Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=702; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.sinh(((Math.fround(Math.min((((x | 0) * (x | 0)) | 0), (0x100000000 !== ( ! mathy0(y, 42))))) < Math.fround((Math.fround((mathy0((x | 0), y) | 0)) >> Math.fround((( - (0x080000000 | 0)) | 0))))) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=703; tryItOut("mathy1 = (function(x, y) { return mathy0((Math.atanh(( ! x)) >>> 0), mathy0((( ! ((( ~ Math.PI) === ( + ( ~ x))) | 0)) | 0), mathy0(Math.max(Math.max(( + (( + y) <= ( + x))), (0x07fffffff | 0)), ( + Math.pow(( + ( ~ x)), y))), ( - ( + ((y + Number.MAX_VALUE) >>> 0)))))); }); testMathyFunction(mathy1, [2**53, 0, 2**53-2, 0x100000000, 1/0, -Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -0x100000000, -(2**53), 1, 0/0, -0, 2**53+2, -1/0]); ");
/*fuzzSeed-85495475*/count=704; tryItOut("\"use strict\"; selectforgc(o0.o0);");
/*fuzzSeed-85495475*/count=705; tryItOut("\"use strict\"; /*MXX2*/g1.Number.prototype.toPrecision = a1;");
/*fuzzSeed-85495475*/count=706; tryItOut("/*ODP-2*/Object.defineProperty(t1, window, { configurable: false, enumerable: (x % 13 == 11), get: (function mcc_() { var ojvsyh = 0; return function() { ++ojvsyh; f2(/*ICCD*/ojvsyh % 3 == 0);};})(), set: (function() { try { h0.hasOwn = f2; } catch(e0) { } try { Object.defineProperty(this, \"o1.v2\", { configurable: false, enumerable: true,  get: function() {  return g1.runOffThreadScript(); } }); } catch(e1) { } try { f0 + ''; } catch(e2) { } g2.o0.m2 + p1; return f2; }) });");
/*fuzzSeed-85495475*/count=707; tryItOut("new this(window) % -29;");
/*fuzzSeed-85495475*/count=708; tryItOut("Array.prototype.forEach.call(a0, (function() { g1.a1 = arguments; return g1.f1; }));");
/*fuzzSeed-85495475*/count=709; tryItOut("x, \u3056, x, khtoqo, jzgugb, qcwxhp, xwsgky;a0.unshift(a1, o2, this.a2);");
/*fuzzSeed-85495475*/count=710; tryItOut("f1 + v1\n\nconst x = (void options('strict')), x = (x)(x, (4277)), x, x = (this.__defineSetter__(\"y\", /*wrap2*/(function(){ var ivmwpl = undefined; var mufoda = encodeURI; return mufoda;})())), -7 = (yield \"\\u514D\"), x, get = 7, x;g0.e0.has(o1.h0);");
/*fuzzSeed-85495475*/count=711; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.abs(Math.fround(( + (( ! Math.pow(x, ((x == y) >>> 0))) - ( + Math.min((mathy0(Math.fround((1/0 < (( + x) <= ( + 0/0)))), Math.fround(( + (( + Math.atan2(-0x100000000, (-0x080000000 >>> 0))) / x)))) | 0), Math.sinh(x)))))))); }); ");
/*fuzzSeed-85495475*/count=712; tryItOut("var ewoupr;for (var v of e2) { try { e0.delete(t2); } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"\\n\"; print(s.replace(r, 'x')); print(r.lastIndex);  } catch(e1) { } Array.prototype.pop.apply(a1, []); }");
/*fuzzSeed-85495475*/count=713; tryItOut("x = e0;function x(...x) { yield this.__defineGetter__(\"d\", /*wrap1*/(function(){ \"use asm\"; s0 = s0.charAt(4);return new RegExp(\"(?!(?:.)){2,}(?!(?:^*|\\\\s))(?:\\\\b\\\\s)\", \"m\")})()) } m0 = new Map(i1);");
/*fuzzSeed-85495475*/count=714; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=715; tryItOut("\"use strict\";  for (let b of window) {/*RXUB*/var r = /\\1{2,}/i; var s = \"\"; print(r.exec(s));  }");
/*fuzzSeed-85495475*/count=716; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( ~ (Math.cos(( ~ Math.fround(Math.expm1(Math.fround(mathy0(Math.hypot(x, y), ( + y))))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-85495475*/count=717; tryItOut("for (var v of g2.o1.f0) { try { v2 = Infinity; } catch(e0) { } e2 = o0.a1[9]; }");
/*fuzzSeed-85495475*/count=718; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)-(i1)))|0;\n  }\n  return f; })(this, {ff: DataView.prototype.getInt16}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000000, 0, 0x080000001, -(2**53), -1/0, 2**53+2, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -0x080000000, 2**53-2, 2**53, 1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, 42, 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, -0x0ffffffff, -0, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=719; tryItOut("for(let z in ((x)(timeout(1800)))){v1 = evalcx(\"m1.delete(o0);\", g0);const a =  '' ; }");
/*fuzzSeed-85495475*/count=720; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-(2**53), -(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 42, 0x0ffffffff, 0.000000000000001, 2**53, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -0x100000000, 2**53-2, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, 1, 1/0, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -0x080000000, 0, 0/0]); ");
/*fuzzSeed-85495475*/count=721; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.ceil(Math.imul(mathy3(( + Math.imul((y >>> 0), (y >>> 0))), 0.000000000000001), (( + (((((x >>> 0) ? -(2**53) : (0x100000001 >>> 0)) >>> 0) === ( - x)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, /*MARR*/[x, NaN, new String('')]); ");
/*fuzzSeed-85495475*/count=722; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.fround(( + Math.ceil(( + mathy2((Math.expm1(( + (((mathy0((x >>> 0), (y >>> 0)) >>> 0) >= ( - x)) | 0))) >>> 0), ((Math.abs((mathy0(x, (2**53 | 0)) | 0)) | 0) * x)))))))); }); ");
/*fuzzSeed-85495475*/count=723; tryItOut("Object.prototype.watch.call(g1.i1, \"19\", (function(j) { if (j) { h2.has = (function() { for (var j=0;j<14;++j) { f0(j%2==0); } }); } else { try { h1.getOwnPropertyNames = (function() { for (var j=0;j<2;++j) { f0(j%3==1); } }); } catch(e0) { } try { v2 = g1.runOffThreadScript(); } catch(e1) { } v0 = this.o0.g0.eval(\"s1 += 'x';\"); } }));");
/*fuzzSeed-85495475*/count=724; tryItOut("v1 = Object.prototype.isPrototypeOf.call(i1, m1);");
/*fuzzSeed-85495475*/count=725; tryItOut("testMathyFunction(mathy4, [2**53, Number.MAX_VALUE, -(2**53+2), -(2**53), 0x080000000, 0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, 0, 1/0, 42, 0x0ffffffff, -0x080000001, Math.PI, 0/0, -0x07fffffff, 2**53+2, -0, 0x100000000, 2**53-2, -0x0ffffffff, 0x100000001, -0x100000000, 0x07fffffff, 1, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=726; tryItOut("do L:if(x) {t0 = t2[(timeout(1800))]; } else  if (x) {print(x); } else {print((4277)); } while((timeout(1800) %= ((void shapeOf(((p={}, (p.z = 7)())))))) && 0);");
/*fuzzSeed-85495475*/count=727; tryItOut("/*RXUB*/var r = /(?:^(?=(?=[^])))?\\2(\\uBe9d)|\u2a56*^|.*(?![^]|^)(?!\\u00CE)$+?|(?:(?![^]))|\\B|\\b{0,}{2,3}{274877906944,}|\\2(?:(?:(?:\\w)))|((?=\\cS))|(?:[\\D\\cR-\ubc5c\u00bb-\u00c9\\D])[\\F\ua9dc-\u00b0\\u00c4-\\u2Ca2]{0}/y; var s = 22; print(uneval(s.match(r))); ");
/*fuzzSeed-85495475*/count=728; tryItOut("a0.forEach((function() { for (var j=0;j<12;++j) { f1(j%5==1); } }));");
/*fuzzSeed-85495475*/count=729; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + ( ! Math.sign(( + ( - ( ! ( + Math.clz32((y != Math.pow(Math.fround(2**53+2), y)))))))))); }); testMathyFunction(mathy2, [-0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 2**53-2, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, 0x100000001, Math.PI, 0/0, 0x07fffffff, 2**53+2, Number.MIN_VALUE, -0x100000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53, -(2**53), 0, 0x080000001, -Number.MIN_VALUE, 1/0, 1, -0x07fffffff, 0.000000000000001, -1/0, 0x100000000, -0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=730; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.acos(( + mathy0(Math.fround(Math.atanh((Math.hypot(( + Number.MAX_SAFE_INTEGER), ((( + (y | 0)) | 0) | 0)) | 0))), mathy0(Math.pow(x, ( + Math.max(( + 0x080000000), x))), Math.exp(( - x)))))); }); testMathyFunction(mathy1, [0x080000000, 0.000000000000001, -0, 2**53, 0/0, 0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 1, Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, 0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, -(2**53+2), -0x100000000, 0, -Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, -(2**53), 1/0, -0x080000000, -0x07fffffff, -0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=731; tryItOut("print(intern(Float32Array()));");
/*fuzzSeed-85495475*/count=732; tryItOut("c;print([]);");
/*fuzzSeed-85495475*/count=733; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (( - ((((( + ( ~ ( + ( + Math.acosh(Math.acos(y)))))) | 0) === (Math.asin((Math.pow((((((y >> x) != x) >>> x) | 0) | 0), (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[new Number(1.5), (1/0), (1/0), new Number(1.5), (1/0), (1/0), new Number(1.5), (1/0), arguments, arguments, new Number(1.5), (1/0), arguments, arguments, (1/0), arguments, arguments, new Number(1.5), arguments, arguments, new Number(1.5), (1/0), arguments, new Number(1.5), (1/0), (1/0), new Number(1.5), (1/0)]); ");
/*fuzzSeed-85495475*/count=734; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((Float64ArrayView[((i0)+((~~(+(0x834ff55d))))+(0xffffffff)) >> 3]));\n  }\n  return f; })(this, {ff: (4277)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[[1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], [1], objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], [1], [1], [1], [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1]]); ");
/*fuzzSeed-85495475*/count=735; tryItOut("\"use strict\"; v1 = a2.reduce, reduceRight((function() { for (var j=0;j<33;++j) { f2(j%5==0); } }), p1, h2, m2);");
/*fuzzSeed-85495475*/count=736; tryItOut("testMathyFunction(mathy2, [0x0ffffffff, 42, -0x080000001, -0x100000001, 1.7976931348623157e308, -0x0ffffffff, 0x100000000, -0x080000000, Number.MAX_VALUE, 0x080000000, 2**53-2, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -(2**53), Number.MIN_VALUE, -(2**53-2), 1, 0x100000001, 0x07fffffff, 0, -Number.MIN_VALUE, -(2**53+2), 1/0, 0/0, -Number.MAX_VALUE, -0, 0x080000001]); ");
/*fuzzSeed-85495475*/count=737; tryItOut(";");
/*fuzzSeed-85495475*/count=738; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Int16ArrayView[((Int32ArrayView[((~~(-4398046511105.0)) % (imul((0x8b641606), (0x838729c8))|0)) >> 2])) >> 1]) = ((i0));\n    d1 = (d1);\n    return ((-0xfffff*((d1) == (((Infinity))))))|0;\n    d1 = (((+atan2(((1.0)), (-1692410939)))) / ((+(~((i0)-((+(-1.0/0.0)) >= (d1))-(!(-0x8000000)))))));\n    (Int32ArrayView[0]) = ((i0)-(((0xe0b410f6) ? (((x = [])) ? (d1) : (d1)) : (+(1.0/0.0))) != (((1.888946593147858e+22)) - ((+(0x6eb34dda))))));\n    {\n      d1 = (((-4398046511105.0)) * ((+abs(((-8193.0))))));\n    }\n    {\n      (Float32ArrayView[2]) = ((-134217729.0));\n    }\n    (Float64ArrayView[1]) = ((+pow(((d1)), ((-134217727.0)))));\n    {\n      d1 = (+(0.0/0.0));\n    }\n    d1 = (-257.0);\n    d1 = ((1.0));\n    i0 = (!(0x97c3f627));\n    i0 = (((((NaN) != (((-((-1024.0)))) * ((d1))))-(((abs((0x6d3815d4))|0)) ? (i0) : ((((0xf1ec485c)) & ((0x12950c15)))))) ^ (-((+(-1.0/0.0)) == (d1)))) != (((!((((-0x8000000)+(0x48f0a266)) << ((0xd445e5c7) / (0x8b6bbbf4))) <= (~~(+(((0x49cd3f74))>>>((0xfac3ea89)))))))) >> ((i0)+(!(((d1)))))));\n    return (((/*FFI*/ff()|0)-(0xfd7cd37d)))|0;\n    {\n      {\n        (Float32ArrayView[0]) = (new x(new Boolean(\u3056 = Proxy.create(({/*TOODEEP*/})([[]]), \"\\u36C0\"), \"\\u04E7\")));\n      }\n    }\n    d1 = (+(-1.0/0.0));\n    return (((0x9bf39cbb)+(i0)))|0;\n  }\n  return f; })(this, {ff: Float32Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MAX_VALUE, 2**53-2, 0.000000000000001, 0/0, 1.7976931348623157e308, 1, -(2**53-2), 2**53+2, 0x100000000, -(2**53+2), 0x100000001, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0x07fffffff, 0x080000001, -1/0, 0x080000000, 0, 1/0, -0x080000001, 42, -0x0ffffffff, -0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-85495475*/count=739; tryItOut("\"use strict\"; \"use asm\"; for(let d in /*RXUE*//(?=\\b{4,})/gyim.exec(\"\\uef33  \\u00da \\n\\uef33  \\u00da \\n\\uef33  \\u00da \\n\\uef33  \\u00da \\n\\uef33  \\u00da \\n\\uef33  \\u00da \\n\\uef33  \\u00da \\n\\uef33  \\u00da \\n\\uef33  \\u00da \\n\")) print(d);");
/*fuzzSeed-85495475*/count=740; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ ( - Math.clz32(( + ( - ( + ((y !== (((y >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy0, ['\\0', [0], (new Boolean(false)), false, null, NaN, (new String('')), true, ({valueOf:function(){return 0;}}), '/0/', (new Boolean(true)), -0, objectEmulatingUndefined(), [], (new Number(-0)), 1, undefined, '0', 0.1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), /0/, (new Number(0)), '', (function(){return 0;}), 0]); ");
/*fuzzSeed-85495475*/count=741; tryItOut("mathy3 = (function(x, y) { return ( ! ( + Math.tanh(x))); }); testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), 0, undefined, '', 0.1, '\\0', null, (new Number(0)), (new Boolean(false)), /0/, true, objectEmulatingUndefined(), [0], '/0/', false, -0, ({toString:function(){return '0';}}), 1, '0', (function(){return 0;}), [], (new Number(-0)), (new Boolean(true)), ({valueOf:function(){return '0';}}), (new String('')), NaN]); ");
/*fuzzSeed-85495475*/count=742; tryItOut("const w = Math.min(4, -18);/*MXX2*/g0.ReferenceError.length = m2;var b = Math.hypot(-27, 9) ? (-this) : ({toSource:  \"\"  });");
/*fuzzSeed-85495475*/count=743; tryItOut("\"use strict\"; a1[6] = x;");
/*fuzzSeed-85495475*/count=744; tryItOut("var r0 = x + x; var r1 = x & x; var r2 = 5 | x; var r3 = 5 % r2; var r4 = r2 & r0; var r5 = 5 + r2; var r6 = 9 / 2; var r7 = r5 * r0; var r8 = 3 | r4; var r9 = r3 | r3; var r10 = 7 / 1; var r11 = 2 % 5; var r12 = r10 ^ r10; var r13 = r8 - r10; var r14 = r5 | r1; var r15 = r13 / r11; r9 = r9 % r8; r13 = r1 ^ r8; var r16 = 6 - 4; var r17 = r12 / r2; var r18 = 8 ^ r14; var r19 = 9 * 1; x = r14 % r18; r12 = r19 + 3; var r20 = r5 % 5; var r21 = r20 ^ 6; var r22 = r15 / 5; r11 = 6 & r14; var r23 = r13 ^ 2; r9 = r11 + 3; var r24 = r13 / r11; ");
/*fuzzSeed-85495475*/count=745; tryItOut("o2.v0 = evaluate(\"function f1(v0) (4277) & v0\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (makeFinalizeObserver('nursery')), catchTermination: false }));");
/*fuzzSeed-85495475*/count=746; tryItOut("\"use strict\"; for (var v of f0) { try { ; } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(p2, g2.g2); } catch(e2) { } v1 = g1.runOffThreadScript(); }");
/*fuzzSeed-85495475*/count=747; tryItOut("v1 = this.m2.get(o2.b2);");
/*fuzzSeed-85495475*/count=748; tryItOut("for (var v of e2) { t1[(4277)] = s1; }");
/*fuzzSeed-85495475*/count=749; tryItOut("\"use strict\"; /*MXX1*/o1 = g2.Object.length;");
/*fuzzSeed-85495475*/count=750; tryItOut("\"use asm\"; t2.set(g2.a0, ({valueOf: function() { print((Math.min(null, window)) ? \n /x/g  : [,,]);function b(c, e, x, x, c, NaN, \u3056, c = \"\\u372C\", (function(a0) { x = a0 / a0; var r0 = x * a0; var r1 = 7 ^ x; var r2 = r0 % r0; var r3 = r1 ^ r0; var r4 = r1 * r3; var r5 = 1 - r3; var r6 = 5 % a0; var r7 = 6 + r4; var r8 = r7 / r1; var r9 = r4 ^ r1; var r10 = 9 / r3; var r11 = a0 / 2; var r12 = r11 * r11; var r13 = r5 & r7; var r14 = 1 % r3; var r15 = r3 / 9; var r16 = 6 / r6; var r17 = r4 % 4; var r18 = a0 + r4; var r19 = r0 % r10; print(r14); var r20 = r14 * 0; print(r15); r2 = r13 | 5; var r21 = r12 & r13; var r22 = 2 / r10; var r23 = r13 ^ r17; var r24 = r3 / r8; var r25 = r4 | r24; r23 = r5 ^ r7; var r26 = r22 % 2; var r27 = 5 * r12; var r28 = 3 | r27; var r29 = r11 / r16; var r30 = 4 - 0; var r31 = 7 - r20; var r32 = 7 | r1; var r33 = 0 - 6; var r34 = r21 - r10; var r35 = 6 & r21; print(r26); var r36 = 4 % r28; var r37 = r14 + r0; var r38 = r37 % 3; var r39 = 1 - r0; var r40 = 8 - r31; var r41 = 2 + r11; var r42 = r35 - r33; var r43 = r4 / r24; var r44 = r35 - 0; var r45 = r9 & a0; r6 = 9 ^ r4; var r46 = r15 | r35; var r47 = r10 * r11; var r48 = r45 & 6; r39 = r6 & r33; var r49 = r30 * r25; r46 = r25 - r16; r7 = 7 + r48; r14 = 5 | 0; var r50 = 7 * r23; var r51 = r11 % r11; r40 = 2 & 0; r51 = r21 / r39; r20 = r28 & r42; r35 = 4 % 3; r47 = r7 - 8; var r52 = 9 % r51; var r53 = r2 % r21; var r54 = r35 | r5; var r55 = r11 * 4; var r56 = r18 % 3; print(r52); return a0; }), \u3056, z, window = \"\\u635D\", \u3056, this.y, window = new RegExp(\"\\\\3{1,}\", \"gy\"), window, x, window, eval, c, NaN, d, z, window, x, z, x, e, \u3056, x, window, LOG2E, window, x, \u3056, x, this.NaN, x = window, w, y, x, e, x = function(id) { return id }, x, x, a, c, x, x, this.x =  \"\" , window, NaN, w, NaN, d, x, NaN, x = 9, y, x, x =  /x/g , this, x, a, x, x, NaN) { \"use strict\"; let (a, jdtxsz, x, x) { for (var p in h2) { try { Array.prototype.unshift.apply(this.a2, [o0.g0.s1]); } catch(e0) { } try { print(uneval(g1.t2)); } catch(e1) { } try { g2.offThreadCompileScript(\"mathy1 = (function(x, y) { \\\"use strict\\\"; return ( - ( + Math.atan2((y || (y | 0)), Math.fround(Math.imul(Number.MAX_VALUE, (( ~ y) <= y)))))); }); \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 17 != 14), sourceIsLazy: true, catchTermination:  \"\"  })); } catch(e2) { } o1.t2[9]; } } } a2.shift(s0, a0);return 14; }}));");
/*fuzzSeed-85495475*/count=751; tryItOut("\"use strict\"; testMathyFunction(mathy4, [1, '/0/', (new Number(-0)), 0.1, '', null, (new Boolean(false)), ({valueOf:function(){return 0;}}), (new String('')), (new Boolean(true)), /0/, -0, (function(){return 0;}), true, 0, undefined, NaN, '0', objectEmulatingUndefined(), false, ({toString:function(){return '0';}}), [0], '\\0', ({valueOf:function(){return '0';}}), [], (new Number(0))]); ");
/*fuzzSeed-85495475*/count=752; tryItOut("mathy2 = (function(x, y) { return ((((((( - y) | 0) >> ( + Math.fround(( - Math.fround(x))))) | 0) | 0) ? (Math.exp(((((( ! ( ! (y >>> -0x100000000))) | 0) ? mathy0(( - x), Math.min(((Math.max((y ? y : y), (2**53-2 >>> 0)) >>> 0) >>> 0), (-Number.MIN_VALUE >>> 0))) : (((( + Math.tanh(( + Number.MAX_SAFE_INTEGER))) / (( + Math.pow(x, x)) >>> 0)) >>> 0) - y)) | 0) >>> 0)) | 0) : (Math.fround(( ~ ((Math.atan2((Math.min(-0x100000001, Math.asin(( + y))) >>> 0), (y >>> 0)) | 0) % Math.tanh(x)))) ? mathy0(((Math.fround(y) === Math.fround((Math.fround(( + ( + y))) ? ( - ((((-Number.MAX_VALUE >>> 0) > (x >>> 0)) >>> 0) | 0)) : y))) >>> 0), Math.min(Math.fround((((x >>> 0) % 0x080000001) >>> 0)), x)) : (Number.MAX_VALUE , (x >>> 0)))) | 0); }); testMathyFunction(mathy2, [0, Math.PI, Number.MAX_VALUE, -(2**53), -0, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, 0x0ffffffff, -1/0, -0x080000001, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, 0x07fffffff, -0x100000000, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, -0x0ffffffff, -(2**53+2), 1, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -0x080000000, 0x080000001, -Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-85495475*/count=753; tryItOut("M:for\u000c(var z in ((String.prototype.localeCompare)(\u3056 = Proxy.createFunction(({/*TOODEEP*/})(x), q => q, (/*wrap2*/(function(){ var sadhqr = this; var bifemm = EvalError; return bifemm;})()).bind(/[^]|.\\B|[^]*/yi))))){selectforgc(o0); }");
/*fuzzSeed-85495475*/count=754; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; }");
/*fuzzSeed-85495475*/count=755; tryItOut("v1 = Object.prototype.isPrototypeOf.call(i2, p1);");
/*fuzzSeed-85495475*/count=756; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=757; tryItOut("(void schedulegc(this.g1));");
/*fuzzSeed-85495475*/count=758; tryItOut("v2 = Object.prototype.isPrototypeOf.call(m1, h0);function x()\"use asm\";   var cos = stdlib.Math.cos;\n  var NaN = stdlib.NaN;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (+cos(((Float64ArrayView[1]))));\n    {\n      i2 = ((0x3997e605));\n    }\n    return +((NaN));\n  }\n  return f;g0.offThreadCompileScript(\"function f1(h0)  { yield (yield new Array(28)) } \", ({ global: g1.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 44 == 0), noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 4 == 1), element: o1, sourceMapURL: s1 }));");
/*fuzzSeed-85495475*/count=759; tryItOut("mathy0 = (function(x, y) { return ( + (( + ( + (( + ( - ( + ( + (y >> y))))) === 0x0ffffffff))) ** ( + ( + Math.atan2(Math.pow(Math.fround((x + x)), y), Math.fround(Math.max(0x080000001, Math.fround(( - (( ! Math.fround(y)) | 0)))))))))); }); ");
/*fuzzSeed-85495475*/count=760; tryItOut("M:with(timeout(1800))/.{1}/m;");
/*fuzzSeed-85495475*/count=761; tryItOut("this.h2 = ({getOwnPropertyDescriptor: function(name) { s0 = '';; var desc = Object.getOwnPropertyDescriptor(f2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return g1; var desc = Object.getPropertyDescriptor(f2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { m1.has(m0);; Object.defineProperty(f2, name, desc); }, getOwnPropertyNames: function() { i0.next();; return Object.getOwnPropertyNames(f2); }, delete: function(name) { /*RXUB*/var r = o0.r2; var s = s1; print(uneval(r.exec(s))); print(r.lastIndex); ; return delete f2[name]; }, fix: function() { a2.push(v0);; if (Object.isFrozen(f2)) { return Object.getOwnProperties(f2); } }, has: function(name) { this.h0 = {};; return name in f2; }, hasOwn: function(name) { throw g1; return Object.prototype.hasOwnProperty.call(f2, name); }, get: function(receiver, name) { t2 = new Uint32Array(a2);; return f2[name]; }, set: function(receiver, name, val) { selectforgc(o2);; f2[name] = val; return true; }, iterate: function() { v1 = (t0 instanceof o2);; return (function() { for (var name in f2) { yield name; } })(); }, enumerate: function() { v1 = (p0 instanceof i0);; var result = []; for (var name in f2) { result.push(name); }; return result; }, keys: function() { throw f1; return Object.keys(f2); } });");
/*fuzzSeed-85495475*/count=762; tryItOut("mathy5 = (function(x, y) { return Math.atan2(( + (Math.min(Math.fround((Math.fround(mathy4(Math.fround(Math.max(x, Math.log(y))), Math.fround(Math.sinh(( + Number.MAX_VALUE))))) < ( + ( - -0)))), (( + (( - (x | 0)) | 0)) >>> 0)) | 0)), ( + ( ! ( + mathy4(( + (( + ( ~ ( + y))) ** Math.fround(y))), ( + Math.fround((Math.fround((( ! (Math.fround(( - Math.fround(Math.exp((y >>> 0))))) >>> 0)) >>> 0)) & (Math.round(y) >>> 0))))))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), Math.PI, -(2**53-2), 0/0, 0x100000000, 1, -0x080000001, -0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, 0x080000000, 1/0, 0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0, -0x07fffffff, 0x0ffffffff, -0x080000000, -0x100000000, 2**53, 2**53+2, -Number.MIN_VALUE, 0x100000001, 0.000000000000001, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-85495475*/count=763; tryItOut("\"use strict\"; (this);");
/*fuzzSeed-85495475*/count=764; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=765; tryItOut("let ({eval} = (\u3056 = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: Date.prototype.setTime, getOwnPropertyNames: function() { return []; }, delete: /*wrap1*/(function(){ print(((function a_indexing(iwivxw, hxqfjr) { ; if (iwivxw.length == hxqfjr) { i1.next();; return x; } var nplgao = iwivxw[hxqfjr]; var jvlahn = a_indexing(iwivxw, hxqfjr + 1); return /*UUV1*/(x.map =  \"\" ); })(/*MARR*/[null, (1/0), [(void 0)], this, (1/0), this, [(void 0)], (1/0), (0/0), (1/0), [(void 0)], [(void 0)]], 0)));return ({})})(), fix: function() { throw 3; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: undefined, keys: function() { return []; }, }; })((void shapeOf(new RegExp(\"\\\\3\", \"gm\")))\n), /*RXUE*//.\\b|\\W?*?\\3[^]|(?!(\u0013|$\u73c7{0,}))+?/.exec(\"\"), w =>  { return intern(this) } )), d = (void shapeOf(true)), x = (void shapeOf(/((?!(?!(?![^]))))/m)), z, tzuyxe, c = [z1,,], hopylo, zyphkl, w = x) { /*RXUB*/var r = new RegExp(\"\\\\1\", \"gyim\"); var s = \"\\uF886\".yoyo(1); print(r.exec(s)); print(r.lastIndex);  }");
/*fuzzSeed-85495475*/count=766; tryItOut("this.e1 = new Set(b0);");
/*fuzzSeed-85495475*/count=767; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=768; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.imul(Math.fround((Math.atan2(( + ( + (-Number.MIN_SAFE_INTEGER || -0x080000001))), (( ~ x) >>> 0)) >>> 0)), Math.fround((Math.min(Math.fround((Math.fround(x) != Math.fround(x))), Math.fround(Math.imul(x, x))) >>> 0))) | 0) ^ (Math.min(Math.fround((y % Math.fround(((( + mathy2(x, x)) | 0) - (y | 0))))), (( ! Math.fround(( ! Math.fround((Math.acos((Math.fround(mathy0(Math.fround(-Number.MIN_VALUE), x)) >>> 0)) >>> 0))))) | 0)) | 0)); }); testMathyFunction(mathy5, /*MARR*/[new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(true), new Boolean(true), Infinity, new Boolean(false), new Boolean(true), Infinity, new Boolean(false), new Boolean(false), Infinity, Infinity, new Boolean(false), new Boolean(true), Infinity, Infinity, new Boolean(false), new Boolean(false), new Boolean(true), Infinity, new Boolean(false), new Boolean(true), Infinity, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(true), new Boolean(false), Infinity, Infinity, new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(false), Infinity, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), Infinity, new Boolean(true), new Boolean(true), new Boolean(true), Infinity, Infinity, Infinity, new Boolean(false), Infinity, Infinity, new Boolean(false), new Boolean(true), new Boolean(true), Infinity, new Boolean(false), Infinity, new Boolean(false), Infinity, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(false), Infinity, new Boolean(false), new Boolean(false), Infinity, new Boolean(true), new Boolean(true), Infinity, new Boolean(true), Infinity, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-85495475*/count=769; tryItOut("\"use strict\"; v1 = (o2.h0 instanceof this.o0.t2);");
/*fuzzSeed-85495475*/count=770; tryItOut("/*RXUB*/var r = /(\\2){1,}/gyim; var s = \"\\ubebd\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-85495475*/count=771; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=772; tryItOut("g2.t0 = new Uint32Array(b1, 15, 1);");
/*fuzzSeed-85495475*/count=773; tryItOut("testMathyFunction(mathy5, [null, '0', (new Boolean(false)), '/0/', [], (function(){return 0;}), /0/, 0.1, undefined, '\\0', ({valueOf:function(){return 0;}}), (new String('')), false, (new Number(-0)), true, (new Number(0)), [0], (new Boolean(true)), ({toString:function(){return '0';}}), NaN, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), -0, 1, '', 0]); ");
/*fuzzSeed-85495475*/count=774; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ( ! ( + ((Math.sin((Math.fround(Math.tan(Math.fround(y))) <= y)) <= ( ~ ( + (Math.pow(y, ( ~ Math.pow(-1/0, 0/0))) | 0)))) >>> 0)))); }); testMathyFunction(mathy5, [-0x080000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -0x07fffffff, -(2**53), 42, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 1, 2**53-2, -(2**53+2), 0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -(2**53-2), 0.000000000000001, -0x080000001, 0x080000001, -0, -Number.MIN_SAFE_INTEGER, 0, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 0x080000000, 0x07fffffff, 0/0, 0x0ffffffff, 2**53+2, 2**53, -0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=775; tryItOut("mathy2 = (function(x, y) { return (( ~ ((( ! ((((( ! Math.fround(x)) || (y | 0)) | 0) << ( + Math.sinh(mathy0(((0x100000001 | 0) ? (x | 0) : x), (y ^ y))))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0/0, -0, Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 0x100000000, -0x100000000, -Number.MAX_VALUE, 2**53+2, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, 0x100000001, -0x080000000, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, -1/0, 1/0, 2**53-2, 0, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53-2), 1, 0x07fffffff, -(2**53), 42, 0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=776; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.log(( + ((Math.sqrt((( ! y) >>> 0)) & ( - (((Math.imul(( + y), x) == Number.MAX_SAFE_INTEGER) >>> 0) != (y >>> 0)))) >>> 0)))); }); testMathyFunction(mathy2, [-(2**53), -(2**53+2), -0x07fffffff, -0, 0x080000001, 0/0, 2**53+2, -0x080000001, 0x080000000, -0x100000000, -Number.MAX_VALUE, 2**53, 42, -Number.MIN_VALUE, 1/0, Math.PI, Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0x100000001, -(2**53-2), 1]); ");
/*fuzzSeed-85495475*/count=777; tryItOut("with({y: (x)}){print(x);with({a: window}){for (var v of p1) { try { for (var v of this.s1) { try { g0.m2.set(i1, f0); } catch(e0) { } try { t0.set(a0, 17); } catch(e1) { } try { print(i2); } catch(e2) { } i0.valueOf = (function() { try { Array.prototype.splice.call(a0, -11, v0, f2, this.v2); } catch(e0) { } try { /*MXX2*/g2.JSON.stringify = t1; } catch(e1) { } m1.delete(this.a0); return e1; }); } } catch(e0) { } try { h0 + ''; } catch(e1) { } try { this.a2.forEach((function(j) { if (j) { try { m1.delete(h1); } catch(e0) { } try { e1.has(m2); } catch(e1) { } try { /*MXX2*/g0.String.prototype.toLowerCase = b2; } catch(e2) { } delete o2[\"isArray\"]; } else { try { for (var p in g0.a1) { v0 = t0.BYTES_PER_ELEMENT; } } catch(e0) { } try { t1 + o0.o2; } catch(e1) { } for (var p in f2) { try { e2 + ''; } catch(e0) { } try { Array.prototype.pop.apply(a1, [v1]); } catch(e1) { } Array.prototype.forEach.apply(a2, [(function() { for (var j=0;j<21;++j) { f0(j%2==0); } })]); } } }), e2); } catch(e2) { } ; }a2 = Array.prototype.filter.call(a2, (function() { try { v1 = t0.byteLength; } catch(e0) { } try { Array.prototype.pop.call(a0, v0); } catch(e1) { } a0.pop(); return v1; }), g2.p2); } }const c = /*FARR*/[, , (x) = x];");
/*fuzzSeed-85495475*/count=778; tryItOut("\"use asm\"; t0 + '';");
/*fuzzSeed-85495475*/count=779; tryItOut("mathy1 = (function(x, y) { return (( ~ (Math.min((((( + ( ! ( + x))) | 0) * ((mathy0((x | 0), (Math.atan2(x, 0) | 0)) | 0) | 0)) | 0), ((x != ( ! (( + ( + ( + x))) && x))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy1, [Math.PI, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, 0x07fffffff, -(2**53+2), 0x080000000, -0x100000000, 2**53, 1, -(2**53), -0x080000001, -0, Number.MIN_SAFE_INTEGER, 0, -0x100000001, 2**53+2, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -(2**53-2), 42, 1.7976931348623157e308, 0x100000000, Number.MAX_VALUE, -1/0, -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=780; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 42, 0/0, 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), 0, 0x080000000, 2**53-2, -0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, 0.000000000000001, 1, -0, 1/0, -Number.MAX_VALUE, 0x07fffffff, 0x100000000, -0x100000000, 0x100000001, -1/0, -0x080000001, Number.MIN_VALUE, -(2**53+2), 0x080000001]); ");
/*fuzzSeed-85495475*/count=781; tryItOut("\"use strict\"; for (var p in this.v0) { try { p2 = a1[(new RegExp(\"\\\\1\", \"gim\") ? Math.trunc(x) : x <<= NaN)]; } catch(e0) { } v0 = g1.runOffThreadScript(); }");
/*fuzzSeed-85495475*/count=782; tryItOut("/*MXX2*/g0.Date.prototype.getSeconds = e1;");
/*fuzzSeed-85495475*/count=783; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((Float64ArrayView[2]));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000000, -0x07fffffff, 2**53, 0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, 2**53+2, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), -Number.MAX_VALUE, 0x07fffffff, -(2**53), 42, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000000, 2**53-2, -1/0, 1, 0/0, -Number.MAX_SAFE_INTEGER, -0, Math.PI, -0x0ffffffff, 0, 1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=784; tryItOut("h1.valueOf = (function() { try { this.g0.offThreadCompileScript(\"(x) = [,,z1]\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 99 == 27), sourceIsLazy: false, catchTermination: true })); } catch(e0) { } print(uneval(f1)); return h2; });\nthis.v1 = Object.prototype.isPrototypeOf.call(g2, i0);\n");
/*fuzzSeed-85495475*/count=785; tryItOut("mathy5 = (function(x, y) { return ( + Math.pow(( + (Math.asinh((Math.imul(Number.MAX_VALUE, y) >>> 0)) >>> 0)), ( + mathy3(Math.tan(y), ( ~ ( + ( + mathy4(( + (y | (( + -Number.MIN_SAFE_INTEGER) | ( + x)))), Math.pow(( + (Math.fround(x) , (y >>> 0))), mathy2(y, x)))))))))); }); testMathyFunction(mathy5, [0/0, -Number.MAX_SAFE_INTEGER, -0, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, -Number.MAX_VALUE, 2**53-2, -(2**53), 0x080000000, -0x080000001, 0x07fffffff, -0x100000001, -0x07fffffff, -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 0x080000001, 1, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), -1/0, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, Number.MIN_VALUE, 2**53, 0x0ffffffff, 0, 42]); ");
/*fuzzSeed-85495475*/count=786; tryItOut("x = (({/*toXFun*/valueOf: function() { return this; } })), x = x, x = (arguments.callee)().yoyo(/*RXUE*/new RegExp(\"(?:(((?=(\\\\D?)|\\\\b|\\u1abd*))))\", \"i\").exec(\"\")), [, ] = x, z = /*RXUE*//\\b[\\D]{4,6}+??\\1/i.exec(\"1 _0______\\u1abd\\u1abd\\u1abd\\u1abd\") ** let (b) true, fmlhdh, cjqfin, pnpgtl;/*bLoop*/for (var mtplkm = 0, zlnioz; ((4277)) && mtplkm < 24; ++mtplkm) { if (mtplkm % 5 == 3) { a; } else { v1 = new Number(NaN); }  } ");
/*fuzzSeed-85495475*/count=787; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.hypot(mathy1((Math.log(Math.sign((x , 0.000000000000001))) | 0), Math.imul(Math.max(((( + Math.fround((((y >>> 0) / (x >>> 0)) >>> 0))) | 0) >>> 0), Math.imul(mathy3(Math.tanh(x), -0x080000001), ( - (( - (x >>> 0)) >>> 0)))), y)), Math.cbrt((((( + Math.atan2((y >>> 0), -0x100000001)) >>> 0) || (Math.atan2(Math.round(y), (((Math.hypot(-0x100000000, x) | 0) ? (((y >>> 0) >= x) | 0) : (Math.hypot(x, (((x | 0) >>> (y | 0)) | 0)) | 0)) | 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, Number.MIN_VALUE, -0, 2**53, -(2**53-2), -Number.MAX_VALUE, 2**53+2, -0x100000001, Math.PI, 0x080000001, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, 42, -(2**53), Number.MAX_VALUE, 0, -Number.MIN_VALUE, 0x0ffffffff, -0x100000000, 0/0, 1.7976931348623157e308, 0x07fffffff, -0x07fffffff, -1/0, -(2**53+2), 0.000000000000001, 0x100000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-85495475*/count=788; tryItOut("var pvygto = new ArrayBuffer(1); var pvygto_0 = new Uint8Array(pvygto); pvygto_0[0] = 109622866; var pvygto_1 = new Uint8Array(pvygto); var pvygto_2 = new Int32Array(pvygto); pvygto_2[0] = -10; var pvygto_3 = new Uint32Array(pvygto); pvygto_3[0] = -23; var pvygto_4 = new Int16Array(pvygto); var pvygto_5 = new Int16Array(pvygto); print(pvygto_5[0]); pvygto_5[0] = 0.166; var pvygto_6 = new Uint32Array(pvygto); pvygto_6[0] = 8; e1.has(i1);continue L;throw {} = (Math.atan).call( /x/ ,  '' );a2.pop();s2.__iterator__ = (function() { i1 = a0[8]; return this.h1; });");
/*fuzzSeed-85495475*/count=789; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min(Math.fround((( + (Math.atan2(((((( - y) >>> 0) ? (( + (Math.tanh((x >>> 0)) >>> 0)) | 0) : y) >>> 0) >>> -0x080000000), (((x >>> 0) !== ( + Math.imul(( + -0), ( + (y ? Math.fround(mathy0(( + x), (y | 0))) : ( + 0.000000000000001)))))) >>> 0)) | 0)) | 0)), ((((( ~ (x >>> 0)) >>> 0) >>> 0) << ((( - ((( ! y) >= Math.min(y, Math.fround(Math.max(( + y), ( + y))))) | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[x, x, new String('q'), x, x, x, new String('q'), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1.5), x, new String('q'), new String('q'), x, x, new Number(1.5), new Number(1.5), x, new Number(1.5), new Number(1.5), x, x, new String('q'), x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x, x, x, x, new Number(1.5), new String('q'), new String('q'), new String('q'), new String('q'), x, x, new Number(1.5), x, x, new String('q'), new Number(1.5), x, new Number(1.5), x, new String('q'), new String('q'), new Number(1.5), new Number(1.5), x, new Number(1.5), new Number(1.5), x, x, new Number(1.5), x, x, new Number(1.5), x, new String('q'), x, x, new String('q'), new String('q'), new String('q'), x, x]); ");
/*fuzzSeed-85495475*/count=790; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var atan = stdlib.Math.atan;\n  var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (1.5111572745182865e+23);\n    }\n    (Float32ArrayView[((/*FFI*/ff()|0)+((~~(((-1152921504606847000.0)) / ((-1.0078125)))) != (((-0x8000000)) << ((0xf83cd3aa))))-((imul((0x410ea86f), (0x9c3ee418))|0) == (0xdb37966))) >> 2]) = ((d0));\n    {\n      (Uint8ArrayView[((!((((0xffffffff))>>>((0x7462317d))) == (((0xe8cd3dd3))>>>((0xb4498bed)))))-(i1)) >> 0]) = ((i1)-(0x891897be));\n    }\n    i1 = (((((((Int32ArrayView[((0xc2c8eb12)-(0xffffffff)-(0xffffffff)) >> 2]))|0) <= (((0x3e5a506e)-((0xbf565566))) ^ (((18014398509481984.0) > (9.671406556917033e+24))-(0xffddf792)))))>>>((i1)-((0x55be1a45)))));\n    return ((((~~(((((-0x8000000))>>>((0xffc8c959))) > (((-0x4e11434))>>>((0x7456863b)))) ? (d0) : (-274877906945.0))) == (abs(((((0x8cbe7334) ? ((0x5e0859f4)) : ((0x241c746a)))) ^ ((~~(32769.0)) % (((-0x8000000)) ^ ((0xfbae778f))))))|0))-((~~(+atan(((NaN))))) != ((((Uint16ArrayView[4096]))-((((0xff1729dd))>>>((-0x2b1679c))) >= (0xe056c473))-(i1)) >> ((0xf849ba0a)+((0xdda6622) ? (/*FFI*/ff(((-3.8685626227668134e+25)))|0) : (i1)))))))|0;\n    d0 = (((((d0)) / ((+(1.0/0.0))))) / ((NaN)));\n    {\n      switch ((((+pow(((-147573952589676410000.0)), ((-4194305.0)))) + (+(((4277))))))) {\n        case 0:\n          i1 = (i1);\n        case -2:\n          i1 = ((((((((0x77871080))>>>((0xaeab4c31))) / (((-0x8000000))>>>((0xfa19ea17))))>>>((-0x8000000)+(0x3a665c48))) / (0x0))>>>((i1))));\n          break;\n        case -1:\n          {\n            {\n              (Int8ArrayView[1]) = ((i1));\n            }\n          }\n          break;\n        default:\n          d0 = (147573952589676410000.0);\n      }\n    }\n    i1 = (i1);\n    i1 = (i1);\n    switch ((~~(d0))) {\n    }\n    return (((((((~~(d0)))))) % (0xb3883387)))|0;\n  }\n  return f; })(this, {ff: Object.isExtensible}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000000, -0x07fffffff, -1/0, -(2**53), Number.MAX_VALUE, 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, 1, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 42, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, -(2**53-2), 1/0, 2**53-2, Math.PI, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, -(2**53+2), 0.000000000000001, 0, -0x080000000, -0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=791; tryItOut("a2.forEach((function() { try { m1 = new Map; } catch(e0) { } try { h2.set = f2; } catch(e1) { } v1 = undefined; return o0; }), s1, p1, s2, m2, e2);");
/*fuzzSeed-85495475*/count=792; tryItOut("\"use strict\"; a2 = new Array;");
/*fuzzSeed-85495475*/count=793; tryItOut("\"use strict\"; s0 + '';");
/*fuzzSeed-85495475*/count=794; tryItOut("print( /* Comment */Math.acosh( '' ));\na2[13] = o0;\n");
/*fuzzSeed-85495475*/count=795; tryItOut("/*bLoop*/for (bknlel = 0; bknlel < 0; ++bknlel) { if (bknlel % 5 == 3) { yield; } else { /*RXUB*/var r = o1.r0; var s = -0; print(r.test(s));  }  } ");
/*fuzzSeed-85495475*/count=796; tryItOut("testMathyFunction(mathy2, [-Number.MAX_VALUE, -0x080000001, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, -0, 42, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 0, 0x0ffffffff, -0x080000000, -1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, Math.PI, -(2**53-2), 0.000000000000001, 0x100000000, 1, -0x07fffffff, 2**53+2, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -(2**53), -(2**53+2), 0x100000001, 0x080000001, 0/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=797; tryItOut("(void shapeOf( ''  ** x));");
/*fuzzSeed-85495475*/count=798; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((mathy2((Math.acosh(-0x100000001) >>> 0), ((Math.imul((Math.fround((x ? Math.fround(Math.ceil(y)) : 0)) | 0), Math.atan2(y, Math.hypot(Math.min(((((y | 0) ? (y | 0) : y) | 0) | 0), Math.hypot(0x080000001, y)), x))) >>> 0) >>> 0)) >>> 0) > ( + Math.exp(Math.log(1/0)))); }); testMathyFunction(mathy3, /*MARR*/[null, [1].yoyo(delete b.x)]); ");
/*fuzzSeed-85495475*/count=799; tryItOut("\"use strict\"; L: for (var a of ( ''  = 12)) print( /x/ );\n/*vLoop*/for (var nueddq = 0; nueddq < 5; ++nueddq) { let b = nueddq; h2.toSource = f1; } \n");
/*fuzzSeed-85495475*/count=800; tryItOut("h2.toString = (function mcc_() { var jqvrfe = 0; return function() { ++jqvrfe; if (true) { dumpln('hit!'); try { h2.getPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = (0xffffffff);\n    }\n    return (((y ** \u3056)+(0x2490c4)-(0x7e3d3ba1)))|0;\n    d0 = (+acos(((d0))));\n    d0 = (-0.0625);\n    d0 = (d0);\n    d0 = (--URIError.prototype.name);\n    i1 = (i1);\n    (Uint32ArrayView[(((((+(1.0/0.0))) * ((-36893488147419103000.0))) > (d0))+(((z = (Number.prototype.toString).call(\"\\uEC1D\", window,  '' ))))) >> 2]) = ((0x56a49486));\n    (Int8ArrayView[2]) = ((((i1)-((((0xffffffff)) ^ (-0xf91d1*(i1))) <= (~((0xfd845186)-(i1)-((0xc36bcc9) != (0x141969bd))))))|0) / ((((imul(((~~(1025.0))), (i1))|0))+(let (z)  /x/ )) << ((1)-((abs((((0x4cd6fbe4)) << ((0xb9f43c4b))))|0))+(0x347b4479))));\n    return (((-0x8000000)-(0x116d176d)+(21)))|0;\n  }\n  return f; }); } catch(e0) { } try { t2 = t2.subarray(13, ({valueOf: function() { e0.has(s0);return 6; }})); } catch(e1) { } try { b0 = t0.buffer; } catch(e2) { } i1 = this.e2.values; } else { dumpln('miss!'); try { selectforgc(o2); } catch(e0) { } try { /*MXX3*/g1.String.prototype.fontsize = g0.String.prototype.fontsize; } catch(e1) { } try { o1.v2 = (f2 instanceof f0); } catch(e2) { } v0 = evalcx(\"/*RXUB*/var r = r0; var s = g2.s1; print(s.match(r)); \", g0); } };})();");
/*fuzzSeed-85495475*/count=801; tryItOut("\"use asm\"; v1 = g2.runOffThreadScript();");
/*fuzzSeed-85495475*/count=802; tryItOut("let cuwxtq, eval, yzfttc, c = new RegExp(\"(?=\\\\3{0})|(.|\\\\v{2,6}|\\\\s+(?:\\\\b{4}))\", \"\"), a, b, ulxcvw, x, jpvxpy, x;print(uneval(v0));");
/*fuzzSeed-85495475*/count=803; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.max(Math.fround(mathy0(Math.atan2((mathy0((y ? ( + (mathy0(y, -Number.MIN_VALUE) | 0)) : ( + ( ! x))), Math.imul(-0x07fffffff, x)) | 0), y), Math.fround(Math.imul(((Math.atan(( + ( + ( + ( + y))))) / Math.fround(Math.expm1(x))) | 0), ((mathy0(((mathy0((y >>> 0), (y >>> 0)) >>> 0) | 0), ((x << ((Math.imul((Math.ceil((x | 0)) | 0), ((x >= -Number.MIN_VALUE) | 0)) | 0) >>> 0)) | 0)) | 0) | 0))))), (( + ( ! ( + ((y | 0) << (Math.fround(Math.round((Math.PI | 0))) >>> 0))))) >>> 0))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -0x100000001, -0, 2**53-2, -0x080000001, 0.000000000000001, 0/0, 42, 2**53, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 1, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 0, -1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -(2**53-2), -(2**53+2), 0x100000001, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 1/0, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-85495475*/count=804; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=805; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=806; tryItOut("testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, -0x100000001, 1/0, -0, 2**53, -Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, 0x100000000, 42, Number.MIN_VALUE, -(2**53-2), 1, Math.PI, 0/0, 2**53+2, Number.MAX_VALUE, -(2**53), -0x0ffffffff, 2**53-2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0, 0x100000001, 1.7976931348623157e308, 0x080000001, -(2**53+2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001]); ");
/*fuzzSeed-85495475*/count=807; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=808; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-85495475*/count=809; tryItOut("\"use strict\"; for(e = [,,] in (4277)) {Array.prototype.sort.apply(g2.a1, []);e2.has(i1); }");
/*fuzzSeed-85495475*/count=810; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.pow((Math.max(( + ( ~ Math.fround(Math.atanh((Math.atan2(y, (x ^ Math.fround(y))) >>> 0))))), Math.fround((Math.fround((-0x080000001 >= Math.fround(Math.log10(x)))) ? x : Math.fround(( + Math.acos(( + ( - (Number.MIN_SAFE_INTEGER | 0))))))))) >>> 0), (( - Math.min(Math.fround((( + y) && x)), ((Math.exp((( + (x | 0)) | 0)) | 0) ? (0x100000001 | 0) : (( + y) | 0)))) | 0)) | 0); }); testMathyFunction(mathy0, [-0x0ffffffff, 2**53-2, 0x0ffffffff, 0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), Number.MIN_VALUE, 42, -0x100000000, -0x080000001, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, 0x100000001, -0x100000001, 0/0, 0x080000001, -1/0, 1/0, 1, 1.7976931348623157e308, 0.000000000000001, -Number.MIN_VALUE, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=811; tryItOut("\"use strict\"; a0.splice();");
/*fuzzSeed-85495475*/count=812; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[[], [], [], [], [], [], objectEmulatingUndefined(), new Number(1), new String('q'), [], new String('q'), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new Number(1), new Number(1), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new String('q'), [], new String('q'), new String('q'), new String('q'), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new Number(1), objectEmulatingUndefined()]) { a2 = a1.concat(a1, a2, a0, o0.s1); }");
/*fuzzSeed-85495475*/count=813; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.atan2((( + mathy0((( + ( ! Math.fround(( ~ ( + mathy1((Math.pow(y, y) >>> 0), ( + (Math.round((y >>> 0)) >>> 0)))))))) | 0), (( + Math.pow((Math.ceil(((Math.max((0.000000000000001 | 0), (Math.fround((Math.fround(y) * Math.fround(-(2**53)))) | 0)) | 0) | 0)) | 0), x)) | 0))) >>> 0), ((Math.atan(Math.fround((( + Math.fround(mathy0(Math.fround(-0x100000001), 42))) << Math.fround(x)))) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [42, -0x100000001, 0x100000000, 0x100000001, -0x080000000, 0, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0, Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, 0x080000001, 2**53+2, -Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, -(2**53), 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, Math.PI, 0x0ffffffff, -0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, 0/0, -0, 2**53-2, 2**53, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=814; tryItOut("\"use strict\"; h1 = ({getOwnPropertyDescriptor: function(name) { /*ADP-2*/Object.defineProperty(a1, g1.v0, { configurable: false, enumerable: true, get: (function() { g1.offThreadCompileScript(\"function f0(a0)  { v2 = t0.length } \", ({ global: o0.g2, fileName: null, lineNumber: 42, isRunOnce: /*FARR*/[].some(Uint32Array), noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 6 == 3) })); return p1; }), set: (function() { v0 = evalcx(\"for (var p in h2) { try { e1.toString = (function() { try { this.s0 + ''; } catch(e0) { } try { e0.add(h0); } catch(e1) { } v2 = new Number(o2); return g0.o0.o2.t0; }); } catch(e0) { } try { a1.splice(NaN, 19, s2); } catch(e1) { } try { for (var v of g2.f2) { try { e2.toSource = (function() { try { e0 = new Set(v2); } catch(e0) { } Array.prototype.forEach.apply(a0, [(function() { try { this.o0.toString = f1; } catch(e0) { } f2 + ''; return g1; }), g0, this.f0]); throw g0.t0; }); } catch(e0) { } try { h0.getOwnPropertyDescriptor = (function() { try { delete o1.b1[\\\"big\\\"]; } catch(e0) { } try { a1.reverse(i1, window, b2); } catch(e1) { } m2.__proto__ = h0; return f1; }); } catch(e1) { } selectforgc(this.o1); } } catch(e2) { } o0.a2[2] = m0; }\", g1); return m2; }) });; var desc = Object.getOwnPropertyDescriptor(f2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { /*ODP-2*/Object.defineProperty(b2, \"toSource\", { configurable: true, enumerable: true, get: Set.prototype.delete.bind(g1), set: (function(j) { if (j) { try { /*RXUB*/var r = r2; var s = \"0\"; print(s.match(r));  } catch(e0) { } Array.prototype.push.call(this.a0, g2, v1, p2); } else { try { /*RXUB*/var r = r1; var s = \"\\n\"; print(s.match(r));  } catch(e0) { } e2.has(this.g2.o1); } }) });; var desc = Object.getPropertyDescriptor(f2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { h2.getOwnPropertyDescriptor = f0;; Object.defineProperty(f2, name, desc); }, getOwnPropertyNames: function() { m2.valueOf = (function() { try { m1.valueOf = f2; } catch(e0) { } try { a2.forEach((function mcc_() { var kidatr = 0; return function() { ++kidatr; if (/*ICCD*/kidatr % 3 == 2) { dumpln('hit!'); try { v0 = g0.eval(\"/* no regression tests found */\"); } catch(e0) { } h1 + ''; } else { dumpln('miss!'); try { a0 = r1.exec(s1); } catch(e0) { } m2.set(i2, f0); } };})(), p1, o1.h2, s2); } catch(e1) { } try { o0.t1 + g1; } catch(e2) { } s2 += 'x'; return s0; });; return Object.getOwnPropertyNames(f2); }, delete: function(name) { Object.prototype.watch.call(f0, \"padEnd\", f2);; return delete f2[name]; }, fix: function() { Array.prototype.reverse.apply(a0, []);; if (Object.isFrozen(f2)) { return Object.getOwnProperties(f2); } }, has: function(name) { v0 = t1.length;; return name in f2; }, hasOwn: function(name) { for (var p in i0) { try { v0 = Object.prototype.isPrototypeOf.call(e0, h2); } catch(e0) { } try { g0 = this; } catch(e1) { } try { this.v2 = g1.runOffThreadScript(); } catch(e2) { } v1 = g0.runOffThreadScript(); }; return Object.prototype.hasOwnProperty.call(f2, name); }, get: function(receiver, name) { g1.o0.g1.__proto__ = m2;; return f2[name]; }, set: function(receiver, name, val) { m2 = new WeakMap;; f2[name] = val; return true; }, iterate: function() { a1[6];; return (function() { for (var name in f2) { yield name; } })(); }, enumerate: function() { a1.reverse();; var result = []; for (var name in f2) { result.push(name); }; return result; }, keys: function() { h2.valueOf = (function(j) { if (j) { try { g1 + t2; } catch(e0) { } try { a0 + ''; } catch(e1) { } t1[16] = (/*MARR*/[(-1/0), new String('q'), objectEmulatingUndefined(), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new String('q'), -0x5a827999, (-1/0), new String('q'), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, new String('q'), objectEmulatingUndefined(), new String('q'), -0x5a827999, new String('q'), objectEmulatingUndefined(), (-1/0), (-1/0), new String('q'), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, -0x5a827999, new String('q'), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, (-1/0), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, (-1/0), new String('q'), (-1/0), -0x5a827999, (-1/0), (-1/0), (-1/0), objectEmulatingUndefined(), -0x5a827999, new String('q'), (-1/0), (-1/0), (-1/0), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x5a827999, (-1/0), (-1/0), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, new String('q'), -0x5a827999, new String('q'), objectEmulatingUndefined(), (-1/0), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, objectEmulatingUndefined(), (-1/0), -0x5a827999, (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x5a827999, -0x5a827999, (-1/0), objectEmulatingUndefined(), new String('q'), (-1/0), objectEmulatingUndefined(), new String('q'), -0x5a827999, new String('q'), (-1/0), new String('q'), (-1/0), (-1/0), new String('q'), objectEmulatingUndefined(), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, new String('q'), (-1/0), -0x5a827999, (-1/0), (-1/0), (-1/0), objectEmulatingUndefined(), new String('q')].sort(Uint8Array, )); } else { Array.prototype.splice.call(g2.a2, h0, (4277).keys(x), b2, o1, b2, s1, this.o0,  '' , g2.o2); } });; return Object.keys(f2); } });");
/*fuzzSeed-85495475*/count=815; tryItOut("x;Array.prototype.pop.apply(g0.a0, []);");
/*fuzzSeed-85495475*/count=816; tryItOut("/*oLoop*/for (let ampaeh = 0; ampaeh < 41; ++ampaeh) { print(x); } ");
/*fuzzSeed-85495475*/count=817; tryItOut("for (var v of m0) { try { m1.get(a0); } catch(e0) { } v2 = null; }");
/*fuzzSeed-85495475*/count=818; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float32ArrayView[4096]) = (((Infinity) + ((((-36028797018963970.0)) - (((([] = (void options('strict')))) ===  /x/ ))) + (-((+(1.0/0.0)))))));\n    {\n      i1 = (i0);\n    }\n    i0 = (i0);\n    switch (((Int8ArrayView[4096]))) {\n      case -3:\n        return ((((i1) ? (((~((0x1dbdf88b)+(0xfe0e7cac)))) ? (i0) : ((0x19d72758))) : (i1))-(i0)))|0;\n        break;\n    }\n    i0 = (!(i1));\n    (Uint32ArrayView[(-(0xfb2aa53f)) >> 2]) = (this ? x : (encodeURIComponent).call(false, [1]));\n    i1 = (i1);\n    return (((Uint32ArrayView[((!(i0))+(/*FFI*/ff(((Float32ArrayView[((0x6dce00a5)+(i1)) >> 2])), ((562949953421313.0)), (((!(i0)))), ((+(1.0/0.0))), ((((-0x8000000)) << ((0xfb0ed725)))), ((4277)), ((-35184372088831.0)), ((-1.25)), ((65537.0)), ((-4097.0)), ((9.0)), ((-295147905179352830000.0)), ((68719476737.0)), ((-2047.0)), ((-0.5)))|0)) >> 2])))|0;\n    i1 = (i1);\n    return (((/*FFI*/ff(((abs(((0x37f51*(i0)) & (-0xfffff*(i1))))|0)), ((NaN)), ((4097.0)), ((288230376151711740.0)))|0)-(i1)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return ((( - ((y | x) | 0)) | 0) & y); })}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, 1.7976931348623157e308, -0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, -(2**53), -(2**53+2), 0x07fffffff, -0x080000000, -(2**53-2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 0, Number.MAX_VALUE, 0.000000000000001, Math.PI, -0x100000001, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 42, 0x100000000, 0/0, Number.MIN_VALUE, 1/0, 0x080000000, 2**53, -0x100000000, 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=819; tryItOut("t1 = new Uint8Array(6);");
/*fuzzSeed-85495475*/count=820; tryItOut("L:switch(b = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: Date.prototype.setUTCMonth, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { throw 3; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: undefined, }; })(new RegExp(\"\\\\1\", \"gi\")), offThreadCompileScript, function(q) { return q; })) { case ({multiline: delete e.x, 1: ((uneval(d))) }): a1[0] = (\u3056 <<= x); }");
/*fuzzSeed-85495475*/count=821; tryItOut("mathy0 = (function(x, y) { return (( + (Math.atan2(Math.fround(( + Math.fround((x >= (( + Math.imul(0x080000000, 0x080000000)) | 0))))), ( + (( + (( ! -(2**53)) >>> 0)) ? Math.fround(Math.atan2(0.000000000000001, Math.fround((y + Math.fround(Math.log(y)))))) : (Math.sign((1 | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy0, [-0x100000000, 0/0, -1/0, -(2**53+2), 0.000000000000001, 1, 0x100000000, -(2**53), 2**53+2, 42, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -0x080000001, Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, 0x07fffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0, -Number.MIN_VALUE, -0, 2**53, -(2**53-2), 2**53-2, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=822; tryItOut("mathy0 = (function(x, y) { return (( + (Math.acosh(((((( + (Math.atan2((x | 0), (( + Math.clz32(( + Math.min(x, x)))) >>> 0)) | 0)) >>> (x >>> 0)) >>> 0) ? x : Math.fround(Math.round(Math.fround((((y >>> 0) >> y) | 0))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -(2**53-2), -0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 1/0, 0, 1.7976931348623157e308, 1, 0x100000000, -(2**53), 0.000000000000001, -0x0ffffffff, 0x080000000, -0x07fffffff, -0x080000001, Math.PI, 0x100000001, 42, -0x100000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), 2**53-2, Number.MAX_SAFE_INTEGER, -0, -0x100000001, 0x0ffffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=823; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=824; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?:(?:\\D)+?[^]{2}))/; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=825; tryItOut("testMathyFunction(mathy2, [Number.MIN_VALUE, 2**53+2, 0x080000001, 1, 2**53-2, 0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -0, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, -Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, -0x100000001, 0.000000000000001, 1.7976931348623157e308, 0x100000000, -0x100000000, 0x100000001, -0x080000001, 0x0ffffffff, -1/0, 0x080000000, -Number.MAX_VALUE, 2**53, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-85495475*/count=826; tryItOut("e1 = x;");
/*fuzzSeed-85495475*/count=827; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.expm1(Math.fround(Math.hypot(Math.fround((( ! ((x >> y) | 0)) - ( + Math.atanh((( + Math.atan(Math.fround(((y >>> (0x0ffffffff ? y : y)) | 0)))) | 0))))), Math.fround(((Math.asinh(Math.fround(Math.acosh(y))) >>> 0) << 0/0)))))); }); testMathyFunction(mathy0, [(new Boolean(true)), (new Number(-0)), null, (new Boolean(false)), 0, '/0/', ({toString:function(){return '0';}}), false, '', (function(){return 0;}), [0], 1, objectEmulatingUndefined(), undefined, '\\0', ({valueOf:function(){return '0';}}), /0/, NaN, '0', (new String('')), ({valueOf:function(){return 0;}}), 0.1, true, -0, (new Number(0)), []]); ");
/*fuzzSeed-85495475*/count=828; tryItOut("for (var p in g2) { v2 = g0.eval(\"this.a0[({valueOf: function() { this.o0.a2.shift();return 18; }})] = (4277);\"); }");
/*fuzzSeed-85495475*/count=829; tryItOut("o1.o2.i0.send(f1);");
/*fuzzSeed-85495475*/count=830; tryItOut("");
/*fuzzSeed-85495475*/count=831; tryItOut("v1 = g1.eval(\"function g2.o1.f2(e2) \\\"use asm\\\";   var cos = stdlib.Math.cos;\\n  var imul = stdlib.Math.imul;\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    switch (((((0x1456f3cf) == (0x4cc52afe))) ^ ((0xfdb6c186)))) {\\n      case -3:\\n        {\\n          return (((0xe4d73599)-(0xffffffff)-(0xec4b630e)))|0;\\n        }\\n        break;\\n    }\\n    {\\n      return (((0xd1c77015)))|0;\\n    }\\n    d1 = (+((-1.5474250491067253e+26)));\\n    d0 = (d1);\\n    d1 = (+cos(((d1))));\\n    d0 = (+(-1.0/0.0));\\n    (Int32ArrayView[0]) = ((!(0xffffffff))-((+(((0xaaf6f4c4))>>>((-0x8000000)))) != (d0)));\\n    d0 = (((d0)) % ((d1)));\\n    {\\n      d1 = (+((Float64ArrayView[((((0x78df4131)))+(0xdc2bef96)) >> 3])));\\n    }\\n    {\\n      d1 = (d1);\\n    }\\n    (Float32ArrayView[((0x65bc2236)) >> 2]) = ((((d0)) / ((-((d0))))));\\n    switch ((imul(((63.0) > (-576460752303423500.0)), ((((-0x8000000))>>>((0xd4c0bb98)))))|0)) {\\n      case 1:\\n        return (((((Float32ArrayView[0])))-(0xf93c2b2d)-(0xfb45092b)))|0;\\n        break;\\n      case -1:\\n        switch ((((0xfe08989f)+(0xfe93c1d7))|0)) {\\n          default:\\n            d1 = ((+(0.0/0.0)) + (((+(0.0/0.0))) * ((((((0xfb3fe116))>>>((0xb1ebb913)))) ? (d0) : (+(((0x948fef6c))>>>((0xad956457))))))));\\n        }\\n    }\\n    return ((((((0x7dd1d6ee)) | ((0xffffffff)-(0xa09682a5))) >= (((0x7f04019f))|0))))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-85495475*/count=832; tryItOut("/*MXX3*/g2.SharedArrayBuffer.prototype.constructor = g0.SharedArrayBuffer.prototype.constructor;");
/*fuzzSeed-85495475*/count=833; tryItOut("\"use strict\"; /*vLoop*/for (cirahh = 0; cirahh < 111; ++cirahh) { let a = cirahh; o2.e0.delete(v2); } ");
/*fuzzSeed-85495475*/count=834; tryItOut("x;function d(x = yield \"\\uEE61\", w)\"use asm\";   var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (((i1) ? ((-0x8000000)) : ((0xa073dfc7))) ? ((0x17411f79)) : (0xf92e1632));\n    d0 = (NaN);\n    return +((((((2147483649.0)) / ((((Float32ArrayView[(x) >> 2])) % ((Float32ArrayView[((0xff6beaf1)-(0xfed82739)+(0xe105eebd)) >> 2])))))) / ((+pow(((+(-1.0/0.0))), ((-2305843009213694000.0)))))));\n  }\n  return f;for(c = ({/*\n*/-3: x, x: (this.zzz.zzz++) }) in eval(\"a1 + o2.g0.o2.s2;\", let (w = print(x)) let (x = null) window) , x << allocationMarker()) {switch(x |  /x/g ) { case 6: f0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((4095.0));\n  }\n  return f; })(this, {ff:  /x/g }, new ArrayBuffer(4096)); }Array.prototype.sort.call(a1, (function(j) { if (j) { try { g2.valueOf = o2.f2; } catch(e0) { } try { v0 = (f2 instanceof g1); } catch(e1) { } try { /*RXUB*/var r = r2; var s = \"n\"; print(r.exec(s));  } catch(e2) { } /*MXX2*/g0.Promise.name = e1; } else { try { this.g2.i1.next(); } catch(e0) { } try { p2.toString = (function() { try { m2.get(e0); } catch(e0) { } try { o0 = g1.objectEmulatingUndefined(); } catch(e1) { } for (var v of b0) { try { e1 = new Set; } catch(e0) { } try { v0 = g0.eval(\";\"); } catch(e1) { } try { this.a0 + ''; } catch(e2) { } h0 + s2; } return m0; }); } catch(e1) { } try { o0.a1 + ''; } catch(e2) { } o1 = Object.create(e0); } })); }");
/*fuzzSeed-85495475*/count=835; tryItOut("\"use strict\"; Object.defineProperty(this, \"o1.f0\", { configurable: false, enumerable: true,  get: function() {  return (function() { for (var j=0;j<7;++j) { f2(j%3==1); } }); } });");
/*fuzzSeed-85495475*/count=836; tryItOut("mathy0 = (function(x, y) { return Math.clz32(( + ( ! Math.max(Math.acosh((Math.acosh(Math.fround(0x080000001)) | 0)), ( + (((Math.clz32(Math.fround(( ! Math.fround(y)))) >>> 0) ? (y >>> 0) : ( ! x)) >>> 0)))))); }); ");
/*fuzzSeed-85495475*/count=837; tryItOut("e1.has(t2);");
/*fuzzSeed-85495475*/count=838; tryItOut("testMathyFunction(mathy0, [-Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000001, 2**53, 0, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000000, 1, 42, -0x080000001, 0/0, -(2**53+2), 0x100000000, Number.MIN_VALUE, 0.000000000000001, Math.PI, -1/0, 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -(2**53-2), Number.MAX_VALUE, 0x0ffffffff, -(2**53), -0, 2**53-2, 1/0]); ");
/*fuzzSeed-85495475*/count=839; tryItOut("\"use strict\"; delete x.a;");
/*fuzzSeed-85495475*/count=840; tryItOut("with({e: x instanceof /*MARR*/[function(){}, function(){}, function(){}, (1/0), ({x:3}), undefined, ({x:3}), /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), function(){}, ({x:3}), /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), /(?:(?!(?:^[^]*)))+?/gm, /(?:(?!(?:^[^]*)))+?/gm, function(){}, function(){}, (1/0), (1/0), (1/0), function(){}, undefined, (1/0), function(){}, /(?:(?!(?:^[^]*)))+?/gm, /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), (1/0), undefined, undefined, ({x:3}), undefined, undefined, /(?:(?!(?:^[^]*)))+?/gm, undefined, ({x:3}), (1/0), /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), /(?:(?!(?:^[^]*)))+?/gm, undefined, /(?:(?!(?:^[^]*)))+?/gm, (1/0), undefined, (1/0), ({x:3}), /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), function(){}, function(){}, ({x:3}), undefined, /(?:(?!(?:^[^]*)))+?/gm, /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), undefined, ({x:3}), ({x:3}), undefined, /(?:(?!(?:^[^]*)))+?/gm, /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), ({x:3}), undefined, function(){}, /(?:(?!(?:^[^]*)))+?/gm, ({x:3}), undefined, ({x:3}), undefined, /(?:(?!(?:^[^]*)))+?/gm, ({x:3})].filter})a1.unshift(f2, x.yoyo(x));/*MXX2*/this.g0.DataView.prototype.byteLength = i0;");
/*fuzzSeed-85495475*/count=841; tryItOut("\"use strict\"; o1.v0 = Object.prototype.isPrototypeOf.call(this.g0, o0.v1);");
/*fuzzSeed-85495475*/count=842; tryItOut("\"use strict\"; this.a0[yield ((void options('strict_mode')))(x, null)];");
/*fuzzSeed-85495475*/count=843; tryItOut("v2 = a0.length;print(/*UUV1*/(e.getOwnPropertySymbols = function(y) { print(x); }));");
/*fuzzSeed-85495475*/count=844; tryItOut("L:for(let a = (timeout(1800)) in  \"\" ) v1 = (g0 instanceof o0.e0);");
/*fuzzSeed-85495475*/count=845; tryItOut("\"use strict\"; for(var b = URIError(Math, eval) in (Int8Array)(new RegExp(\"(?=.{3,})+?\", \"g\"), -5)) ((Function).call).apply\nArray.prototype.forEach.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -7.737125245533627e+25;\n    d0 = (-4398046511105.0);\n    i1 = (/*FFI*/ff(((abs((((0x5e92883)+((0x888d4e9f) ? ((128.0) != (-18014398509481984.0)) : (i1))) << ((0x4b67b51f))))|0)), ((((d0)) / ((-2097153.0)))), ((abs((0x4c46e21e))|0)), ((d2)), (((((((0xc86dd09)+(0x64d86ef7)) & ((0x2e263b9)))))|0)), ((((d2)) - (((((0xfec9f1fe))))))), ((d0)), ((((0xf05e2686)) | ((0x9fd64545)))), ((~~(-1.125))), ((-4503599627370495.0)), ((1024.0)), ((-1.125)), ((-1.2089258196146292e+24)), ((-140737488355329.0)), ((2.0)))|0);\n    return ((((0x3f1e78ef))+(i1)))|0;\n  }\n  return f; })(this, {ff: String.prototype.endsWith}, new SharedArrayBuffer(4096)), o2.o0, g1.e2, o1]);function eval(\u000dd, ...setter) { yield /([^]($)+(\\d)**?\\b*)/y } return;\n");
/*fuzzSeed-85495475*/count=846; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 129.0;\n    {\n      {\n        i0 = (0xfa9057c2);\n      }\n    }\n    return (((0x20b99585) / (((0x35be5c1b) % (((Int16ArrayView[1]))>>>(-((0x7af8caea)))))>>>((i3)))))|0;\n    i4 = (i4);\n    {\n      return ((((i0) ? (i2) : (0x6f8b1d63))))|0;\n    }\n    (Uint16ArrayView[4096]) = ((i1)-(0xf97117ed));\n    i0 = (i2);\n    i0 = (i1);\n    d5 = (8796093022209.0);\n    i1 = (i3);\n    (Int8ArrayView[((0x74ddb7bd)+(0x19e2767)-((((0xffffffff) / (0x0))>>>((i2))))) >> 0]) = (((i0) ? (0xffffffff) : (i2))+((0x0))-(i0));\n    i4 = (i0);\n    i0 = (i1);\n    d5 = (+((Float32ArrayView[1])));\n    i0 = (i1);\n    i4 = ((Infinity) != (134217729.0));\n    return (((i0)+(i3)))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 0x080000001, -0x080000001, -0x0ffffffff, -0, 0, 42, -1/0, -0x07fffffff, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53), 1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, -0x100000000, 0x100000000, 0x0ffffffff, -(2**53-2), 0x07fffffff, 2**53+2, 0x100000001, 1, 0x080000000]); ");
/*fuzzSeed-85495475*/count=847; tryItOut("/*oLoop*/for (var krqfgt = 0; krqfgt < 84; ++krqfgt) { print(s1); } ");
/*fuzzSeed-85495475*/count=848; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(Math.tanh(Math.fround(( + (( + \"\\uE000\") - ( + ( + (((y == x) ? (Math.atan2(x, x) | 0) : ((Math.min((Number.MIN_VALUE | 0), y) | 0) | 0)) | 0))))))), (Math.log10(Math.fround((( + (((( + Math.acos(( + Math.fround(Math.asinh((x >>> 0)))))) | 0) ? (y | 0) : (y | 0)) | 0)) == Math.hypot(Math.atan2(Math.fround(Math.sin(Math.fround(y))), ( + y)), 0x100000001)))) >>> 0)); }); testMathyFunction(mathy1, [-0x080000001, 0x100000000, -Number.MIN_VALUE, 2**53, 0, 1/0, 0x0ffffffff, 0.000000000000001, 0x080000000, -0x100000000, 0/0, -1/0, 42, -(2**53+2), -Number.MAX_VALUE, -0x100000001, Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, -0, 1, -(2**53), -0x080000000, 2**53+2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=849; tryItOut("g1.h0.getPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return +((Float64ArrayView[((i3)-(i3)) >> 3]));\n  }\n  return f; })(this, {ff: (Function.prototype.apply).bind}, new ArrayBuffer(4096));");
/*fuzzSeed-85495475*/count=850; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-85495475*/count=851; tryItOut("g1.offThreadCompileScript(\"\\\"use strict\\\";  for (let b of eval\\u000c <= this.x) /* no regression tests found */\");");
/*fuzzSeed-85495475*/count=852; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.acosh(Math.pow((Math.pow((( + (Math.fround(Math.pow((-1/0 >>> 0), (y >>> 0))) << Math.fround(Math.fround(( + Math.fround(x)))))) | 0), (Math.fround(( - Math.fround(2**53-2))) | 0)) | 0), (Math.fround(Math.cos(Math.fround(Math.fround(mathy1(x, x))))) ? x : ( ! Math.atan(x))))) | 0); }); testMathyFunction(mathy5, [2**53, 42, -0x07fffffff, 2**53+2, Number.MIN_VALUE, 0.000000000000001, 0x080000001, -Number.MAX_VALUE, -(2**53+2), Math.PI, -0x100000001, -0x100000000, -0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 2**53-2, 1, 0x100000001, 0x080000000, Number.MAX_VALUE, 1/0, -(2**53), -Number.MIN_VALUE, -0x080000000, 0, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -(2**53-2), -0x0ffffffff, -1/0]); ");
/*fuzzSeed-85495475*/count=853; tryItOut("\"use strict\"; e1.add(t0);");
/*fuzzSeed-85495475*/count=854; tryItOut("testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-85495475*/count=855; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.015625;\n    var d3 = 140737488355329.0;\n    {\n      (Uint8ArrayView[(((0x8872811d) ? ((((0x9084b5d1))>>>((0xfa9da426))) <= (((0xfe438fb6))>>>((-0x8000000)))) : ((((0xc4405b26))>>>((0x3f61583b))) != (0x35580203)))) >> 0]) = ((0x4215ed55));\n    }\n/*tLoop*/for (let w of /*MARR*/[(-0), (-0), (-0), [(void 0)], [(void 0)], (-0), (-0), (-0), (-0), [(void 0)], [(void 0)], (-0), [(void 0)], [(void 0)], (-0), (-0), [(void 0)], [(void 0)], (-0), (-0), (-0), (-0), (-0), (-0), [(void 0)], [(void 0)], (-0), [(void 0)], (-0), (-0), (-0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], (-0), [(void 0)], [(void 0)], (-0), (-0), (-0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], (-0), (-0), (-0), (-0), (-0), [(void 0)], (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), [(void 0)], (-0), (-0), (-0), [(void 0)], (-0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], (-0), (-0), [(void 0)], (-0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], (-0), (-0), (-0), (-0), (-0), [(void 0)], (-0), (-0), [(void 0)], (-0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], (-0), [(void 0)], [(void 0)], (-0), [(void 0)], [(void 0)], (-0), (-0), [(void 0)], [(void 0)], (-0), [(void 0)], (-0), [(void 0)], (-0), (-0), [(void 0)], (-0), [(void 0)], (-0), (-0), (-0), (-0), (-0), (-0), [(void 0)], [(void 0)], [(void 0)], (-0), (-0), (-0), [(void 0)], (-0), (-0), (-0), [(void 0)], [(void 0)], [(void 0)], (-0), [(void 0)], [(void 0)], (-0), (-0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], (-0)]) { ; }    {\n      d0 = (d1);\n    }\n    d2 = (d1);\n    d0 = (Infinity);\n    d0 = (d2);\n    /*FFI*/ff(((((0x638f415b)-(0xffffffff)) ^ ((((0x496c7a4d))|0) % (((-0xdee987)+(0xf8ea1ebc)) | ((0x3e5a68c3)*0xf5d22))))));\n    d2 = (+(0.0/0.0));\n    d1 = (d3);\n    {\n      {\n        d2 = (d3);\n      }\n    }\n    d1 = (+abs(((d1))));\n    return +((d1));\n    {\n      {\n        {\n          d3 = (d0);\n        }\n      }\n    }\n    return +((d2));\n    d1 = (+(1.0/0.0));\n    d0 = (+(1.0/0.0));\n    d0 = (d2);\n    (Float32ArrayView[((0xeb4d300d)-((NaN) > (((d1)) % ((Float64ArrayView[2]))))) >> 2]) = ((+(((((((d2))+((((0xfd6cb433))>>>((0x7c90bb05))))) & ((((0xf8903d28))|0) % (((-0x8000000)) >> ((0xbbdbb982)))))))>>>((0x5c74b7b8)+(((abs((-0x8000000))|0)) ? (-0x8000000) : ((((0xba915b45))|0) <= (((0x3e12fd2b))|0)))))));\n    {\n      {\n        d2 = (((uneval( \"\" ))));\n      }\n    }\n    switch ((~~(d2))) {\n      case 1:\n        {\n          d3 = ((+/*FFI*/ff()) + (d1));\n        }\n      case -2:\n        d2 = (+abs(((d0))));\n        break;\n      default:\n        d1 = (((d1)) - ((((((0xf4d3775) == (((0x561e1f66))|0)) ? (+abs(((+((d0)))))) : (d0))) % ((d1)))));\n    }\n    d2 = (147573952589676410000.0);\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: function(q) { \"use strict\"; return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x080000000, 0x0ffffffff, -(2**53-2), 0x100000000, 1, Number.MIN_VALUE, -0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53+2), 42, -Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, -0x080000001, 0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, -0x100000001, 0.000000000000001, -1/0, -0x100000000, -(2**53), 1/0, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, 2**53, -Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=856; tryItOut("");
/*fuzzSeed-85495475*/count=857; tryItOut("testMathyFunction(mathy4, [1, -1/0, -0x100000001, 0.000000000000001, -Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, 1/0, 0x07fffffff, 2**53+2, Number.MAX_VALUE, -0x080000000, 42, 0x080000000, -(2**53+2), 0/0, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Math.PI, 0x100000000, -(2**53), 0x100000001, -0, 0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000]); ");
/*fuzzSeed-85495475*/count=858; tryItOut("let x = this, inlkib, gfcznf, eval = /(?:(?:(?!$|[^]))+?.)/gyi, x = ({14: 0x100000000 >= window >>> a * z = Proxy.createFunction(({/*TOODEEP*/})(\"\\u0CD6\"), /(?!(?!\\b)\\1|\\b*?|\\S{4,})/gyi) });print(uneval(v0));");
/*fuzzSeed-85495475*/count=859; tryItOut("\"use strict\"; v0 = (e2 instanceof g0);");
/*fuzzSeed-85495475*/count=860; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=861; tryItOut("v1 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-85495475*/count=862; tryItOut("x = this.a1;");
/*fuzzSeed-85495475*/count=863; tryItOut("function shapeyConstructor(hxefrk){this[\"w\"] = (0/0);{ Array.prototype.reverse.call(a2);function hxefrk(w, b, ...x) { \"use strict\"; m0.get(t0); } Object.defineProperty(this, \"g0.a1\", { configurable: (x % 3 != 1), enumerable:  /x/ ,  get: function() { Array.prototype.forEach.apply(a1, [(function() { try { m2.set(undefined, v2); } catch(e0) { } try { t2 = t2.subarray(o0.v2, o2.v2); } catch(e1) { } v0 = evaluate(\"print(\\\"\\\\u2796\\\");\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (hxefrk % 3 == 0), noScriptRval: true, sourceIsLazy: true, catchTermination: false })); return e1; }), m2, this.g2]); return []; } }); } return this; }/*tLoopC*/for (let y of {window: []} = []) { try{let icjozc = new shapeyConstructor(y); print('EETT'); print(x);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-85495475*/count=864; tryItOut("mathy1 = (function(x, y) { return Math.sqrt(((Math.fround(Math.hypot(y, Math.pow(y, (Math.atanh((x >>> 0)) >>> 0)))) > (Math.fround(Math.asin(Math.fround(( + Math.tanh(Math.fround(((x >>> 0) ? (y >>> 0) : (x >>> 0)))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0/0, 1/0, -0x07fffffff, -(2**53+2), Number.MAX_VALUE, 42, 0x080000001, -0x100000000, -Number.MAX_VALUE, 0, 0x100000001, 0x080000000, -0x100000001, -Number.MIN_VALUE, 0.000000000000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53, Math.PI, 1, -1/0, -0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -(2**53), -0x080000000, 0x100000000, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=865; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\1)/yi; var s = \"\\u7460\\n\\n\\n\\n\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=866; tryItOut("mathy0 = (function(x, y) { return ((Math.log10(-0x100000000) & ( ! (Math.hypot(y, Math.atan2(((((Math.fround((y ? (x >>> 0) : y)) >>> 0) != ((y > y) | 0)) >>> 0) | 0), (y | 0))) | 0))) % Math.atan2(( + ((( ! (( + (( + ( + Math.max(( + -Number.MAX_SAFE_INTEGER), ( + /*RXUE*//\\b/gm.exec(\"\"))))) / ((x === y) | 0))) >>> 0)) >>> 0) ? Math.asinh(x) : Math.pow(Math.cos(y), Math.fround(((Math.PI >>> 0) != Math.fround(Math.atan((( ~ z) | 0)))))))), Math.sinh(( + (y % 2**53+2))))); }); testMathyFunction(mathy0, [-0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, 0x100000000, -0, -0x080000001, 0x0ffffffff, 1.7976931348623157e308, -(2**53-2), 2**53-2, -0x100000000, 0, -(2**53), -(2**53+2), 0x100000001, 0x07fffffff, 0/0, Number.MIN_VALUE, 0x080000001, 1/0, Math.PI, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, -0x100000001, 2**53+2, -1/0, Number.MAX_SAFE_INTEGER, 1]); ");
/*fuzzSeed-85495475*/count=867; tryItOut("\"use strict\"; /*infloop*/for(w = \"\\u7BFC\"; true;  /x/g ) f1.toSource = String.prototype.concat.bind(a0);");
/*fuzzSeed-85495475*/count=868; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + Math.asinh(((mathy0(y, Math.fround((( + (( + x) >= ( + y))) >>> (Math.fround(y) & Math.fround(y))))) >>> 0) ** Math.max(y, Math.fround(Math.max(Math.fround(( - ( + y))), Math.cosh(y))))))) ? Math.fround(((Math.abs((( ! ((((y | 0) ** Number.MIN_SAFE_INTEGER) | 0) >>> 0)) >>> 0)) ? mathy0(mathy0(y, y), Math.pow(Math.fround(Math.max(x, ( + (( ~ y) == ( + y))))), Math.fround(Math.asin(Math.fround(Math.max((y | 0), -(2**53))))))) : Math.min(((Math.log1p(( + y)) | 0) >>> 0), Math.fround(Math.acos(Math.fround(Math.fround((Math.fround(x) && Math.fround(( + y))))))))) >>> 0)) : Math.fround((mathy0(Math.abs((Math.max(y, ( - x)) | 0)), (((Math.pow(((mathy0(-Number.MAX_VALUE, x) ? (y >>> 0) : Math.fround(y)) >>> 0), x) >>> 0) * (((x >>> 0) != (y >>> 0)) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined()]); ");
/*fuzzSeed-85495475*/count=869; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(( + ( ! ( + ( + (Math.atan2(x, y) >>> 0)))))), Math.fround((Math.asin(x) ? (( + ( + ( - (( + (( + x) && ( + (Math.hypot(y, x) | 0)))) | 0)))) * ( + Math.asinh(( + Math.tan(( + Math.ceil(0x100000000))))))) : (Math.fround(( ! (y | 0))) ** Math.fround(( + Math.min(( + y), ( + y)))))))); }); testMathyFunction(mathy5, [0x100000000, -1/0, -0x07fffffff, -0x100000001, 0, 0.000000000000001, Number.MIN_VALUE, -(2**53-2), Math.PI, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -0x080000001, Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, 2**53-2, 1, Number.MAX_VALUE, 2**53+2, -(2**53), 0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -0x100000000, -0]); ");
/*fuzzSeed-85495475*/count=870; tryItOut("\"use strict\"; /*infloop*/M:for(let w; x; this.__defineGetter__(\"x\", function(y) { return  \"\"  })) a0 + '';");
/*fuzzSeed-85495475*/count=871; tryItOut("let (e) { a1[18]; }");
/*fuzzSeed-85495475*/count=872; tryItOut("mathy0 = (function(x, y) { return Math.abs((Math.log2(( ! ( ! Math.max(Math.acos(y), (( ~ y) | 0))))) >>> 0)); }); testMathyFunction(mathy0, [-(2**53), 1/0, -0x100000001, -Number.MIN_VALUE, 2**53-2, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, -0, 0x100000000, -0x0ffffffff, 0, -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, 0/0, -0x100000000, 2**53, -(2**53-2), Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, 42, 0x07fffffff, 1, -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=873; tryItOut("");
/*fuzzSeed-85495475*/count=874; tryItOut("Array.prototype.shift.call(a0, t0);var a = /*UUV1*/(x.log10 = new Function);");
/*fuzzSeed-85495475*/count=875; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.abs(Math.fround(( ! (mathy3(x, Math.log(x)) ? mathy0(y, (( + y) >>> 0)) : x)))); }); ");
/*fuzzSeed-85495475*/count=876; tryItOut("\"use strict\"; let(c =  '' , x) { (window);}");
/*fuzzSeed-85495475*/count=877; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (((Math.pow(Math.atan2(( + (((((( + Math.pow(x, -(2**53))) * (mathy0(( + -0x100000001), ( + x)) | 0)) | 0) >>> 0) ** ((y ** 2**53) >>> 0)) >>> 0)), Math.atan2(((mathy0(x, x) << y) >>> 0), (Math.min(( + x), ( + Math.imul(y, x))) >>> 0))), (((x | 0) ? Math.hypot(y, x) : ( ~ x)) | 0)) >>> 0) ? (((( + Math.log2((y | 0))) & ( - Math.fround(mathy0(Math.fround(-(2**53)), ((x ^ Math.hypot((Math.ceil(x) | 0), y)) | 0))))) >>> 0) >>> 0) : ( + (Math.fround(Math.sign(Math.fround(x))) ? Math.fround(Math.fround(Math.round(x))) : Math.fround(( + Math.asinh(( + Math.exp((y >>> 0))))))))) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[{}, function ([y]) { }, function ([y]) { }, \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", {}, function ([y]) { }, \"\\u5AA8\", eval, eval, eval, {}, function ([y]) { }, function ([y]) { }, \"\\u5AA8\", {}, \"\\u5AA8\", {}, \"\\u5AA8\", {}, \"\\u5AA8\", {}, {}, function ([y]) { }, \"\\u5AA8\", {}, function ([y]) { }, \"\\u5AA8\", eval, {}, eval, eval, eval, \"\\u5AA8\", function ([y]) { }, \"\\u5AA8\", eval, \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", \"\\u5AA8\", eval, eval, {}]); ");
/*fuzzSeed-85495475*/count=878; tryItOut("testMathyFunction(mathy2, [-0x100000000, 0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000001, 0x080000000, 2**53+2, -(2**53+2), 1, -0x07fffffff, -1/0, -0x100000001, 0x080000001, 2**53-2, -Number.MAX_VALUE, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0, 42, -0, -0x080000000, 0.000000000000001, 1.7976931348623157e308, 2**53, -(2**53-2), Math.PI]); ");
/*fuzzSeed-85495475*/count=879; tryItOut("this.g1.g0.m1.set(e2, p0);");
/*fuzzSeed-85495475*/count=880; tryItOut("/*vLoop*/for (let itvroe = 0, e = /*MARR*/[Infinity, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE].sort(Boolean), x = (4277), z, x = ((function too_much_recursion(llxpmv) { ; if (llxpmv > 0) { ; too_much_recursion(llxpmv - 1); this.g1 + ''; } else {  } print(); })(1)), NaN = (4277); itvroe < 40; ++itvroe) { z = itvroe; /*MXX3*/g0.RegExp.prototype.multiline = g1.RegExp.prototype.multiline; } \ng2.m0.get(o2.g2.b2);\n");
/*fuzzSeed-85495475*/count=881; tryItOut("/*oLoop*/for (var okxetq = 0; okxetq < 104 && (function(y) { yield y; g0.s1 += s1;; yield y; }()); ++okxetq) { v0 = evalcx(\"this.e0.delete(g2);\", g2); } ");
/*fuzzSeed-85495475*/count=882; tryItOut("");
/*fuzzSeed-85495475*/count=883; tryItOut("g2.t0 = t0.subarray(16, 11);");
/*fuzzSeed-85495475*/count=884; tryItOut("v0 = (t0 instanceof this.m1);");
/*fuzzSeed-85495475*/count=885; tryItOut("var x, z, e;s0 = new String;");
/*fuzzSeed-85495475*/count=886; tryItOut("/*infloop*/ for  each(window in ((yield new (/(?:(?=.*)*\u00f8|[]{3,})+/i)(({a2:z2}), \"\\u1C79\"))\u0009) << (Math.acos(\"\\uFDD0\"))) a1 = new Array;");
/*fuzzSeed-85495475*/count=887; tryItOut("testMathyFunction(mathy2, [(new String('')), 1, NaN, [], undefined, '/0/', (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(-0)), (new Number(0)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), false, (function(){return 0;}), (new Boolean(true)), objectEmulatingUndefined(), '0', [0], 0, '\\0', 0.1, null, /0/, true, -0, '']); ");
/*fuzzSeed-85495475*/count=888; tryItOut("mathy0 = (function(x, y) { return ( + Math.trunc(( + (( ~ (Math.asinh(x) | 0)) | 0)))); }); ");
/*fuzzSeed-85495475*/count=889; tryItOut("testMathyFunction(mathy4, [-0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, 0x100000001, 0x07fffffff, 0x100000000, 0/0, -(2**53-2), 2**53+2, -(2**53+2), 0x0ffffffff, -1/0, 0x080000001, 2**53-2, -(2**53), -0x080000000, -Number.MAX_VALUE, -0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, 0, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0x080000001, -0, 0x080000000, 1/0, Math.PI, -Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=890; tryItOut("for(z = x < -5 in ((makeFinalizeObserver('tenured')))) let o0.a0 = a2.filter(f0);");
/*fuzzSeed-85495475*/count=891; tryItOut("mathy4 = (function(x, y) { return (((Math.fround(Math.cos(Math.fround((((mathy2(y, y) | 0) , ((( ! Math.fround(Math.pow(y, (y >>> 0)))) | 0) | 0)) | 0)))) ? Math.pow(((Math.fround(( - (y >>> 0))) | 0) || (Math.atan2(x, y) >>> 0)), y) : ( + ((Math.expm1((( ~ (x >>> 0)) >>> 0)) >>> 0) - Math.fround(0)))) || (( + Math.fround(Math.min((Math.hypot((-0 >>> 0), (x >>> 0)) >>> 0), Math.ceil(y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [2**53, -Number.MAX_VALUE, -(2**53-2), 1/0, 1, 2**53-2, 0x07fffffff, Math.PI, 0x100000001, -0x100000000, 0x0ffffffff, 0x080000000, -(2**53), -0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -0x100000001, -1/0, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -0x080000000, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-85495475*/count=892; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((Math.imul(x, ((( ! (mathy0(y, x) >>> 0)) >>> 0) | 0)) | 0) === Math.fround(( ~ Math.fround(( ! Math.min(( + y), Math.log(-(2**53)))))))) != ( ~ (Math.exp(Math.expm1(y)) | 0))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, 0x100000001, 0x07fffffff, 0, -0, 0x100000000, -0x080000000, Math.PI, 42, 0x080000000, -0x0ffffffff, 1, 0/0, 2**53, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 1/0, -0x100000001, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=893; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(v0, e2);");
/*fuzzSeed-85495475*/count=894; tryItOut("m1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var asin = stdlib.Math.asin;\n  var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (-4.835703278458517e+24);\n    {\n      return +((-3.022314549036573e+23));\n    }\n    d1 = (17592186044415.0);\n    d1 = (3.0);\n    (Uint8ArrayView[0]) = (((((+(((0xa42ee9e6)+(0x76a95952)+(0x81bc280f))>>>(((6.189700196426902e+26) > (-131073.0)))))) - ((d1))) < (+asin((((((window.eval(\"/(?:[\\u2f1c\\ufb8f\\u00f7]*?^*?*?)/gm\")))) % ((d1)))))))+(i0));\n    {\n      {\n        return +(((i0) ? ((-((d1))) + (((Float64ArrayView[((0xcc09450c)+(0xffffffff)-(0x610fe03)) >> 3])) - ((Float64ArrayView[2])))) : (+((((0x3487a104))*-0x92cc2) << ((0xa8fa1519)+(0xfec43240))))));\n      }\n    }\n    i0 = (i0);\n    switch ((((i0)) | ((0xbf43f6f)-(0xe2747953)-(0x9a6254a2)))) {\n      case -1:\n        d1 = (4398046511104.0);\n        break;\n      case 0:\n        return +((((((Float64ArrayView[((!((((0xffffffff)-(0x694487a)+(0xf8ee241f))|0)))) >> 3]))) - ((d1))) + ((i0) ? (+(0xffffffff)) : (((+abs(((Float32ArrayView[((0xfecbc9c2)) >> 2]))))) - ((274877906945.0))))));\n    }\n    i0 = (0xfbe0e69b);\n    i0 = (1);\n    (Int16ArrayView[1]) = (((((((((0xfc272c81))+(-0x8000000))>>>(-0x1c98b*((0x8f771e1) > (0x68285229)))))+(i0)) ^ (0x48084*(0xf8d1aa5c)))));\n    return +((Float64ArrayView[((!(0x52a66ff6))) >> 3]));\n  }\n  return f; });");
/*fuzzSeed-85495475*/count=895; tryItOut("M:if(-17) print(b in w);");
/*fuzzSeed-85495475*/count=896; tryItOut("mathy0 = (function(x, y) { return (( ! ( + ( + ( ~ ( + Math.fround(Math.imul(Math.fround(( + ( + ( - Math.fround(( + Math.clz32(-0x07fffffff))))))), Math.fround(( + -Number.MAX_SAFE_INTEGER))))))))) >>> 0); }); testMathyFunction(mathy0, [0x100000000, -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, 0x0ffffffff, -(2**53), 1/0, 2**53+2, -0x080000000, -(2**53-2), -1/0, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, -0x100000001, -0x07fffffff, Math.PI, 0x080000001, 1, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 42, -0, 2**53, Number.MIN_VALUE, -0x080000001, 0, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=897; tryItOut("\"use strict\"; for(let b in []);");
/*fuzzSeed-85495475*/count=898; tryItOut("/*RXUB*/var r = /(?=(\\b+\\B+|(?!([^]$))*){1})+/gyi; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-85495475*/count=899; tryItOut("Array.prototype.push.call(a0, g2.a0, t1);");
/*fuzzSeed-85495475*/count=900; tryItOut("");
/*fuzzSeed-85495475*/count=901; tryItOut("v2 = true;function eval(NaN, x, ...y) { return ((void options('strict_mode'))) } /* no regression tests found */");
/*fuzzSeed-85495475*/count=902; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=903; tryItOut("");
/*fuzzSeed-85495475*/count=904; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=905; tryItOut("if((x % 2 == 1)) (\u3056); else  if (x) z else this.s2 = new String;");
/*fuzzSeed-85495475*/count=906; tryItOut("\"use strict\"; let (c) { t0 = new Int16Array(a2); }");
/*fuzzSeed-85495475*/count=907; tryItOut("o2 = a1[v2];");
/*fuzzSeed-85495475*/count=908; tryItOut("h1 + '';");
/*fuzzSeed-85495475*/count=909; tryItOut(";");
/*fuzzSeed-85495475*/count=910; tryItOut("for (var p in f0) { function f2(o0)  { yield window }  }\nv1.toString = (function(j) { if (j) { try { a1.sort(f1, h0, f2); } catch(e0) { } v0 = new Number(Infinity); } else { try { /*MXX1*/o1.o0 = g2.Math.hypot; } catch(e0) { } s0 = new String(o1.e0); } });\n");
/*fuzzSeed-85495475*/count=911; tryItOut("with({}) e = NaN;return x;");
/*fuzzSeed-85495475*/count=912; tryItOut("\"use strict\"; m0.get(i1);");
/*fuzzSeed-85495475*/count=913; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=914; tryItOut("\"use strict\"; this.g0.offThreadCompileScript(\"/*tLoop*/for (let d of /*MARR*/[2**53, 2**53, [], 2**53, [], 2**53, null,  \\\"use strict\\\" , 2**53]) { f2.toSource = (function() { try { v2 = Object.prototype.isPrototypeOf.call(b1, o1); } catch(e0) { } try { /*ADP-3*/Object.defineProperty(a0, 3, { configurable: (x % 29 == 23), enumerable: false, writable: true, value: \\\"\\\\uCA41\\\" }); } catch(e1) { } for (var v of this.o1.a0) { try { v0 = Object.prototype.isPrototypeOf.call(g2.i2, h0); } catch(e0) { } try { v2 = g0.eval(\\\"mathy1 = (function(x, y) { return ((( + Math.pow(Math.fround(((x | 0) && (0/0 >>> 0))), Math.fround(mathy0(0x080000000, (Math.min(mathy0(x, y), ((2**53 * y) | 0)) >>> 0))))) >>> 0) >>> Math.fround(( + (Math.max((x | 0), (Math.abs(-0x100000001) | 0)) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[-0x0ffffffff, {},  /x/g , {}, {},  /x/g , {}, -0x0ffffffff,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , {}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff,  /x/g , {}, -0x0ffffffff,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , {},  /x/g , -0x0ffffffff,  /x/g , {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff,  /x/g , {},  /x/g ,  /x/g , {}, -0x0ffffffff, {}, -0x0ffffffff, {},  /x/g ,  /x/g , -0x0ffffffff,  /x/g , {}, -0x0ffffffff,  /x/g , {},  /x/g ,  /x/g , {}, -0x0ffffffff,  /x/g , {},  /x/g , -0x0ffffffff, {}, {},  /x/g , -0x0ffffffff, {}, -0x0ffffffff,  /x/g , {},  /x/g , -0x0ffffffff, -0x0ffffffff, {}, {}, -0x0ffffffff,  /x/g , {}, {},  /x/g , -0x0ffffffff,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , -0x0ffffffff,  /x/g ,  /x/g ,  /x/g , {}, -0x0ffffffff, -0x0ffffffff,  /x/g , {}, {}, {}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {}, {}, {}, -0x0ffffffff, -0x0ffffffff, {}, {}, {}, -0x0ffffffff,  /x/g ,  /x/g ,  /x/g ]); \\\"); } catch(e1) { } try { v0 = a0.length; } catch(e2) { } p1 + m1; } return o1.s0; }); }\");");
/*fuzzSeed-85495475*/count=915; tryItOut("for(let b in []);let(window = x, e = Math.atan2(10, -13), kglxjx, ibhnzl, fxdqcv, widauk, scoeiy) { x =  /x/g ;}");
/*fuzzSeed-85495475*/count=916; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.atanh(( + Math.atan2(( + ( + ( ! ( + (( + Math.asin(Math.atanh(( + Math.log(x))))) | 0))))), Math.atan2((Math.max((x > (x | 0)), x) * x), Math.expm1((y >= (x | 0))))))) | 0); }); testMathyFunction(mathy0, [-0x100000000, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, -0, -0x080000000, 1/0, 0, Math.PI, 1, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, -0x080000001, -(2**53-2), 0x100000001, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 2**53, -0x07fffffff, 2**53+2, 42, 2**53-2]); ");
/*fuzzSeed-85495475*/count=917; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.exp(((x >>> (Math.acos((x | 0)) | 0)) + (( - (( ~ ((y > Number.MAX_SAFE_INTEGER) | 0)) | 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy2, [2**53, 0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, -0x080000001, 2**53+2, -0x100000000, -0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), -(2**53+2), -0, 1/0, 2**53-2, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, -0x080000000, 0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 1, 0x100000001, 0/0]); ");
/*fuzzSeed-85495475*/count=918; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.max(Math.min(Math.imul(( + Math.hypot((x && y), ( + Math.hypot(Number.MIN_VALUE, Math.fround(y))))), y), ( + Math.fround(( - (((Math.trunc(x) >>> 0) & (( - ( + y)) >>> 0)) >>> 0))))), ( + (( + (( ~ ( + (Math.sin((x == x)) ^ 0x100000000))) >>> 0)) | ( + (((( ~ x) >>> 0) | (Math.ceil(x) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [0x100000000, -0, 0.000000000000001, -1/0, 1/0, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, 0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 2**53-2, -0x07fffffff, -0x100000001, -Number.MAX_VALUE, 0/0, 2**53+2, -(2**53-2), 1.7976931348623157e308, 0x080000000, -0x080000000, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, 42, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, 0, 2**53]); ");
/*fuzzSeed-85495475*/count=919; tryItOut("a0.unshift(a0);");
/*fuzzSeed-85495475*/count=920; tryItOut("\"use strict\"; \"use asm\"; Object.freeze(g1);");
/*fuzzSeed-85495475*/count=921; tryItOut("\"use strict\"; o2.t2[16] = g0.e2;");
/*fuzzSeed-85495475*/count=922; tryItOut("var miwrts = new SharedArrayBuffer(8); var miwrts_0 = new Uint8ClampedArray(miwrts); var rrxeuk = new SharedArrayBuffer(16); var rrxeuk_0 = new Float32Array(rrxeuk); rrxeuk_0[0] = 12; throw NaN;g0 + '';");
/*fuzzSeed-85495475*/count=923; tryItOut("/*MXX3*/g0.String.prototype.anchor = g2.String.prototype.anchor;");
/*fuzzSeed-85495475*/count=924; tryItOut("\"use strict\"; print(this.a0);");
/*fuzzSeed-85495475*/count=925; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (i1);\n    return (((0xa00836a2)+((d0) != (-16385.0))))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, 0x080000001, 2**53, 2**53-2, 0x080000000, -(2**53-2), Math.PI, -(2**53+2), -0, -Number.MAX_VALUE, 0/0, 0x0ffffffff, 1.7976931348623157e308, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 0, -0x080000001, 0.000000000000001, -1/0, 42, 2**53+2, -0x0ffffffff, -0x07fffffff, -0x100000001, 0x100000000, Number.MAX_VALUE, -0x100000000, 1/0, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=926; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((-((((((+sqrt(((NaN))))))-(0xd58737b1)+(0x48a28669))>>>(-(0xdd174adf))) > (this)))))|0;\n  }\n  return f; })(this, {ff: (28.unwatch(\"setMinutes\")).call}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, -0x080000000, 0x100000001, -1/0, 0x0ffffffff, Number.MIN_VALUE, 1/0, -0x100000001, -0x100000000, -(2**53+2), -Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 1, 0x080000001, -(2**53), 2**53, 0x07fffffff, Math.PI, 42, -(2**53-2), -0x07fffffff, -Number.MAX_VALUE, -0]); ");
/*fuzzSeed-85495475*/count=927; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.fround(Math.fround(Math.atan2((((Math.asinh(x) >>> 0) / ( + ( + ( + (( ! (2**53-2 | 0)) | 0))))) >>> 0), Math.fround((y << Math.log2(x)))))) - Math.fround(( + Math.fround(( + (Math.min(Math.fround(y), Math.fround(Math.acosh(y))) | 0)))))) | 0); }); ");
/*fuzzSeed-85495475*/count=928; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=929; tryItOut("v1 = t1.length;");
/*fuzzSeed-85495475*/count=930; tryItOut("\"use strict\"; /*MXX3*/g2.String.prototype.slice = g1.String.prototype.slice;");
/*fuzzSeed-85495475*/count=931; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=932; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.fround(mathy0((Math.atan(Math.atan2(Math.max(-0x080000000, y), 2**53-2)) | 0), Math.fround(Math.clz32((Math.hypot(y, ( ~ ( - 2**53-2))) !== Math.fround(x)))))) ? Math.acosh(mathy0(( + Math.min(( + y), ( + (( ~ (Number.MIN_SAFE_INTEGER / ( + x))) >>> 0)))), (( - (mathy0((-0x07fffffff - y), Math.PI) >>> 0)) >>> 0))) : Math.ceil((Math.cosh((Math.max(-0x100000000, (Math.fround(Math.fround(Math.fround((Math.imul((x >>> 0), (y >>> 0)) >>> 0)))) | 0)) | 0)) + x))); }); ");
/*fuzzSeed-85495475*/count=933; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (0xfead6a30);\n    i2 = ((~(((-32769.0) == (6.189700196426902e+26))+(i2)-(0x25883a1e))) < (((i1)) & ((i1))));\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: Set.prototype.forEach}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=934; tryItOut("v2 = true;");
/*fuzzSeed-85495475*/count=935; tryItOut("t0.set(a0, 17);");
/*fuzzSeed-85495475*/count=936; tryItOut("a1 = new Array;");
/*fuzzSeed-85495475*/count=937; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0(Math.fround((Math.acos((Math.log(((Math.imul((0/0 | 0), (( + mathy0(Math.min(-Number.MIN_VALUE, y), (Math.sign(y) | 0))) >>> 0)) | 0) >>> 0)) | 0)) | 0)), Math.fround((mathy0(((( + (( + x) - ( + Math.hypot(( + Math.hypot(x, Math.fround(-Number.MIN_VALUE))), (y >>> 0))))) >= y) >>> 0), ( + (((( ! (0.000000000000001 - Math.fround(( + Math.imul(x, -0x100000000))))) >>> 0) || (y >>> 0)) == ( ! (1.7976931348623157e308 > ((Number.MIN_VALUE | 0) << y)))))) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, 0, -(2**53), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, -0x080000000, -1/0, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, Math.PI, 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, 0x080000000, -(2**53+2), 1, 2**53+2, -0x100000001, 0x080000001, 0x07fffffff, -0, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, -Number.MIN_VALUE, 42]); ");
/*fuzzSeed-85495475*/count=938; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (-4.835703278458517e+24);\n    i0 = ((((i0)) & ((/*FFI*/ff(((abs((abs((abs((abs((((0xfd4e15c9)) | ((0x3621bf85))))|0))|0))|0))|0)), ((-(i2))))|0))));\n    (Int16ArrayView[1]) = ((((0x273655f)) ? (( '' ) >= ((x))) : (/*FFI*/ff(((d1)), ((~((((0xdf84e678)) | ((0xf9dea067))) / (((0x8d6825d0)) >> ((0x3226be22)))))), ((((0x0) % (0xffffffff)) << ((i2)+(0x1596c906)))), ((imul((((void options('strict_mode')))), (/*FFI*/ff(((536870913.0)), ((-4.835703278458517e+24)), ((-70368744177663.0)))|0))|0)), ((abs((((0xfd14d22b)) >> ((0xb8119c33))))|0)), ((67108863.0)))|0)));\n    i0 = ((((((((0x3561e080) != (0x6c02cb5c))-(0xfee71ee0))>>>((0xb94b2d6c) / (0x8c794746))))-((abs((((0xe0bdaba8)) << ((0xff33182d))))|0) <= (0x45f779d7))+((0x3c404e0e) < (((0xffffffff)-(0x8e95d2f))>>>((/*FFI*/ff(((536870911.0)), ((9.671406556917033e+24)), ((6.044629098073146e+23)), ((-65537.0)), ((-257.0)))|0)))))>>>((i0)-(i2))));\n    return (((~(((((i0)-(i0))>>>((0xffc1acf4)-(0xffffffff)-(0xda84e750))))-(0xfd548107)-((((!(-0x8000000))*0x5d167)>>>((0xa28c00c4)))))) / ((((~(-0x831a7*((4194305.0) < (-524289.0)))))+(-0x8000000)) | (((/*FFI*/ff(((65537.0)), ((-9.44473296573929e+21)), ((-274877906945.0)))|0) ? (i2) : (i0))+((((0xffffffff)) & ((0xffffffff))) >= (imul((0x48faa442), (0xfc071086))|0))-(!(i0))))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000000, 0, -(2**53+2), -0, 0x080000001, 0x100000001, -0x0ffffffff, -0x100000000, -1/0, 1/0, -(2**53-2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, -Number.MAX_VALUE, -(2**53), -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, 42, 0x080000000, 2**53, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, 0/0, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=939; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround((( + ((( + Math.fround((( + y) == (x | 0)))) >>> 0) - (Math.max((x >>> 0), (0x100000001 >>> 0)) >>> 0))) - (((Math.log10(((((( ~ y) | 0) ** y) * x) >>> 0)) * ( ! ( ~ Math.fround(( ! ((Math.fround(y) == 1) | 0)))))) >>> 0) >>> 0))); }); testMathyFunction(mathy0, [true, (new String('')), false, (new Number(-0)), undefined, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), NaN, 1, (new Boolean(false)), '/0/', 0.1, '', (function(){return 0;}), -0, '\\0', null, ({valueOf:function(){return 0;}}), (new Boolean(true)), [], '0', /0/, 0, objectEmulatingUndefined(), (new Number(0)), [0]]); ");
/*fuzzSeed-85495475*/count=940; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.hypot(( + Math.fround(( + Math.fround(( + (Math.fround((((x | 0) !== Math.fround((y >= 2**53))) | 0)) ** ( + y))))))), ( + Math.hypot(Math.trunc((Math.atan((Math.exp((-(2**53-2) << (y | 0))) >>> 0)) | 0)), (Math.imul(mathy1(y, ((( + (y >>> 0)) >>> 0) >>> 0)), y) && ( - x))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 2**53-2, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 1/0, 0x080000000, 0x0ffffffff, 0.000000000000001, 0x080000001, -Number.MAX_VALUE, 0/0, 1, -Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, -0, Number.MIN_VALUE, -0x080000000, -0x100000001, -0x0ffffffff, 0, 0x07fffffff, Math.PI, 0x100000001, -Number.MIN_VALUE, 42, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, 1.7976931348623157e308, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-85495475*/count=941; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=942; tryItOut("mathy0 = (function(x, y) { return Math.imul(Math.round(Math.asinh(((( ! (y >>> 0)) >>> 0) ? y : ( ! ( + (Math.round((y >>> 0)) >>> 0)))))), Math.sin(( + ((Math.expm1(((Math.sign((x >>> 0)) >>> 0) | 0)) | 0) & (( ! x) | 0))))); }); testMathyFunction(mathy0, [42, -0x0ffffffff, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -(2**53+2), -0, 1, -1/0, 0, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 0x100000000, 0.000000000000001, -0x07fffffff, -0x100000000, 1/0, 0x080000001, 0/0, 2**53+2, 0x07fffffff, -0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=943; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(b0, \"apply\", ({}));");
/*fuzzSeed-85495475*/count=944; tryItOut("");
/*fuzzSeed-85495475*/count=945; tryItOut("r0 = new RegExp(\"(?!(?!\\\\0).).|(?:(?:.){1,3})+\", \"gym\");");
/*fuzzSeed-85495475*/count=946; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\d{2}\", \"gm\"); var s = \"aaa\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=947; tryItOut("print(window.watch(\"__lookupSetter__\", (b = window) =>  '' ));");
/*fuzzSeed-85495475*/count=948; tryItOut("/*oLoop*/for (var rdujvp = 0; rdujvp < 10; ++rdujvp) { if((x % 6 != 2)) m2.get(g2); } ");
/*fuzzSeed-85495475*/count=949; tryItOut("mathy2 = (function(x, y) { return mathy0((Math.log2(((y & Math.min(x, ((1/0 >>> 0) | Math.log2(( + x))))) - -(2**53))) | 0), Math.pow(Math.fround(mathy1((mathy0((Math.fround(Math.min((Math.max(0x0ffffffff, y) * -Number.MIN_SAFE_INTEGER), (y >>> 0))) | 0), ((Math.abs(Math.fround((mathy0(y, x) >= (0x100000000 && 42)))) >>> 0) | 0)) | 0), (( - y) / ( ! ( ~ x))))), ((0x080000001 >>> (x >>> 0)) >>> 0))); }); ");
/*fuzzSeed-85495475*/count=950; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + (( + (y && ( + Math.log(( + (Math.imul(Math.fround((Math.imul(y, x) > y)), (y < y)) | 0)))))) * ( + (Math.fround((x >= x)) ? Math.fround((Math.asinh(Math.min(y, Math.fround(Math.exp(Math.fround(x))))) | 0)) : Math.max(( ~ y), (x >>> 0)))))) / (( + ((Math.atan2(( + ( ~ x)), -Number.MAX_VALUE) | 0) >>> ((((y >>> 0) > x) ? y : (Math.hypot(Number.MAX_VALUE, y) >>> 0)) | 0))) ^ Math.atan2((Math.max(Number.MIN_VALUE, (x | 0)) | 0), Math.fround(( + ( + (Math.asinh((y >>> 0)) | 0))))))); }); testMathyFunction(mathy0, [2**53-2, -(2**53), 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, 0x100000001, 0.000000000000001, 42, 2**53+2, -0x0ffffffff, -0x080000001, 0x080000000, 2**53, -0x100000000, 0x0ffffffff, -Number.MAX_VALUE, -0, -0x100000001, -0x080000000, -0x07fffffff, 1, -1/0, Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=951; tryItOut("a0 = Array.prototype.filter.call(a1, (function(j) { if (j) { try { b2.__proto__ = p0; } catch(e0) { } Array.prototype.sort.call(a0, (function(j) { if (j) { try { g1.r1 = new RegExp(\"((?:[\\\\u0059\\\\uc4Da-\\\\u00E6\\\\B\\u00d8-\\u9aeb]\\\\D{1}))\\\\b*\", \"m\"); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(i1, o1); } catch(e1) { } try { b0.toString = (function(j) { f2(j); }); } catch(e2) { } a0 = Array.prototype.map.call(a0, (function() { for (var j=0;j<40;++j) { f1(j%5==1); } }), t0); } else { try { m1.set(p0, m2); } catch(e0) { } try { g0.v0 = t0.length; } catch(e1) { } h2.getPropertyDescriptor = f0; } }), b2); } else { try { v1 = Array.prototype.reduce, reduceRight.apply(a2, [((neuter).bind).bind]); } catch(e0) { } v1 = g2.runOffThreadScript(); } }), b2);");
/*fuzzSeed-85495475*/count=952; tryItOut("mathy4 = (function(x, y) { return ((( ~ Math.fround(Math.min(Math.fround(x), Math.fround(( + Math.atan2(( + x), ( + x))))))) | 0) >> (Math.min(Math.imul((Math.atan2(( + (y % Math.max(2**53+2, y))), Math.round(x)) | 0), ( ~ Math.fround(Math.fround(Math.abs(-0x080000000))))), (( ~ (mathy1(y, Math.imul(Math.atan2(Math.fround(y), Math.fround(-0x100000001)), mathy1((x | 0), mathy3(-Number.MAX_SAFE_INTEGER, 2**53-2)))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [0/0, 0x080000000, Number.MAX_SAFE_INTEGER, -1/0, 0, -(2**53+2), -0x07fffffff, 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, -0x100000000, 1, 1/0, Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, -0x080000001, -0, 0x0ffffffff, 0x100000000, -Number.MAX_VALUE, -0x080000000, -(2**53), Math.PI, 0.000000000000001, 0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-85495475*/count=953; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)+((~((/*FFI*/ff(((((-0x8000000) % (0x4fcebffe)) ^ (-0xfffff*(i1)))), ((-0x8000000)), ((((0x7ee8ae9b)*0xdadc4)|0)), ((((-8796093022209.0)) * ((-68719476735.0)))), ((-70368744177665.0)), ((1.0078125)))|0)+((((0x827eb1b9)+(0x33a00f37)) << ((0x90b3ab3) / (0x2c9f6f7b))) < (((0x13740e52)+(-0x8000000)+(0x77cb65f8)) >> (((-0xd877f5))))))) > (~~(576460752303423500.0)))))|0;\n    (Float32ArrayView[(-0xb55ad*(i1)) >> 2]) = ((d0));\n    i1 = (i1);\n    return (((0x3e196e5a) / (((void options('strict_mode')) ? x : \nthis.__defineGetter__(\"a\", new RegExp(\"\\\\d*?(($)(?=\\\\B)?|\\\\S+)+\", \"ym\")))>>>((i1)-(((0x5000e3f) ? (0xffb872e4) : (0xa9f64ba4)) ? (0xfa2c68a0) : (i1))-(0xc2e5bd99)))))|0;\n  }\n  return f; })(this, {ff: q => q}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53+2), -0x0ffffffff, -0, 0x080000000, 0/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 42, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -0x100000001, 2**53-2, 0x0ffffffff, 0x100000000, -Number.MAX_VALUE, -1/0, 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, 0.000000000000001, 1.7976931348623157e308, -(2**53), -0x080000000, -0x080000001, 1, 0x100000001, 2**53, -0x100000000]); ");
/*fuzzSeed-85495475*/count=954; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=955; tryItOut("mathy3 = (function(x, y) { return Math.min(((Math.tanh(((( + Math.max(( + x), y)) == (Math.max((x >>> 0), 1) >>> 0)) >>> 0)) >> ( - ( + -(2**53)))) >>> 0), (Math.fround(Math.cos(Math.fround(-0x07fffffff))) >= ( + ( + (x | Math.fround(x)))))); }); testMathyFunction(mathy3, [-(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 0, Number.MIN_VALUE, -(2**53+2), 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, Number.MAX_VALUE, -1/0, 42, 0x07fffffff, 2**53-2, Math.PI, 2**53, -0x0ffffffff, 0x0ffffffff, -0, -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, 0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000000, -(2**53-2), 0.000000000000001, -0x100000000, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=956; tryItOut("g1.o2.g2.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-85495475*/count=957; tryItOut("testMathyFunction(mathy2, [2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, -0, Number.MAX_SAFE_INTEGER, 42, 0/0, 0, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, -(2**53), Math.PI, -Number.MAX_VALUE, -0x07fffffff, -0x080000001, 1/0, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, 0x07fffffff, 0x080000001, 1, -0x100000000, -0x080000000, -(2**53-2), 2**53, -1/0, -(2**53+2), Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=958; tryItOut("with({b: d})print(\"\\u2603\");");
/*fuzzSeed-85495475*/count=959; tryItOut("\"use strict\"; \"use asm\"; v1 = false;");
/*fuzzSeed-85495475*/count=960; tryItOut("\"use strict\"; print(i2);");
/*fuzzSeed-85495475*/count=961; tryItOut("Array.prototype.shift.call(this.a1)");
/*fuzzSeed-85495475*/count=962; tryItOut("mathy5 = (function(x, y) { return (Math.pow(mathy0(x, (( + y) | 0)), (( ! ( ! (Math.hypot((0x080000000 >>> 0), (( + Math.pow((y | 0), y)) >>> 0)) >>> 0))) >>> 0)) >>> (Math.max((mathy1(( + Math.hypot(Math.log((0x100000000 ^ ((Math.trunc(x) | 0) >>> 0))), ( ! x))), (mathy3((y | 0), 0x100000000) | 0)) | 0), Math.log(( - Math.clz32(x)))) | 0)); }); testMathyFunction(mathy5, [-0, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, 0/0, -(2**53), -(2**53-2), -Number.MAX_SAFE_INTEGER, 1/0, 0x07fffffff, 0x100000000, 1, 2**53-2, 0x0ffffffff, 0x100000001, Math.PI, -0x080000000, 1.7976931348623157e308, -(2**53+2), 0, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 0x080000001, 0.000000000000001, 0x080000000, 42, -0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-85495475*/count=963; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.hypot(( + ((Math.pow(Math.fround(Math.fround((((Math.pow(y, (Math.log1p(y) | 0)) >>> 0) ** (x | 0)) | 0))), (Math.hypot((( + Math.asinh(-(2**53+2))) >>> 0), (Number.MAX_VALUE >>> 0)) >>> 0)) >>> 0) ? (( ~ y) >>> 0) : mathy1((Math.tanh((((y + 1/0) ? x : ( - x)) | 0)) | 0), x))), ( + ( ~ ( ! (Math.atan2((x >>> 0), (1.7976931348623157e308 >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-85495475*/count=964; tryItOut("for (var v of a2) { Array.prototype.push.call(a2, b1, this.t2, s0, s2); }");
/*fuzzSeed-85495475*/count=965; tryItOut("v2 = Object.prototype.isPrototypeOf.call(p1, h1);");
/*fuzzSeed-85495475*/count=966; tryItOut("mathy3 = (function(x, y) { return Math.asin((( - ( ! ( + Math.tan((Math.fround(mathy2(((( + y) ? mathy2(y, (y >>> 0)) : y) | 0), Math.fround(0))) | 0))))) >>> 0)); }); testMathyFunction(mathy3, [0x0ffffffff, -0, 0, Number.MIN_VALUE, 0.000000000000001, 0x100000000, -0x07fffffff, -0x080000001, -Number.MAX_VALUE, 0x07fffffff, 2**53, 0x100000001, -(2**53+2), 2**53+2, 1.7976931348623157e308, 0x080000000, -(2**53-2), -0x100000001, 42, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0x080000001, -0x100000000, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, Math.PI, -(2**53), 0/0, -0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=967; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (mathy2(((( + x) ? Math.cbrt(y) : (( + (( + x) | Math.fround((mathy3(x, y) | 0)))) << y)) | 0), (( + Math.log2(( + ( + Math.hypot(((Math.log(((( ~ x) | 0) >>> 0)) >>> 0) >>> 0), ( + ( ~ (( + (Math.acosh(Math.fround(y)) >>> 0)) >>> 0)))))))) | 0)) | 0); }); testMathyFunction(mathy5, [0x0ffffffff, 0.000000000000001, 0, -0, 0x080000001, 0x07fffffff, -(2**53-2), Number.MAX_VALUE, 2**53+2, 2**53-2, 0x080000000, -0x100000000, 2**53, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, -(2**53+2), -0x080000000, -Number.MIN_VALUE, 1, 0/0, -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, 1/0, Math.PI, 0x100000001, 42, -0x080000001]); ");
/*fuzzSeed-85495475*/count=968; tryItOut("\"use strict\"; a2.reverse();");
/*fuzzSeed-85495475*/count=969; tryItOut("\"use strict\"; print([z1,,]);s0 = Array.prototype.join.call(a0, o0.t1);");
/*fuzzSeed-85495475*/count=970; tryItOut("L:while((x ^ c) && 0)e2.add(b0);");
/*fuzzSeed-85495475*/count=971; tryItOut("g2.g0.e0.valueOf = (function() { for (var j=0;j<75;++j) { f2(j%5==1); } });");
/*fuzzSeed-85495475*/count=972; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.acos((Math.log10(((( ~ (y >>> 0)) / (Math.cbrt((x === -Number.MAX_SAFE_INTEGER)) | 0)) >>> 0)) | 0))); }); ");
/*fuzzSeed-85495475*/count=973; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.hypot(Math.fround(Math.min(( + Math.fround(( + Math.fround(x)))), (Math.atan(((((( - (( + (( + 1.7976931348623157e308) && ( + y))) | 0)) | 0) ^ (Math.fround(Math.min(Math.fround(( - (x >>> 0))), Math.fround(x))) | 0)) | 0) >>> 0)) >>> 0))), ((Math.pow((x | 0), (x | 0)) % ( ! y)) | 0)); }); ");
/*fuzzSeed-85495475*/count=974; tryItOut("/*bLoop*/for (let cwkgiq = 0, (4277), x; cwkgiq < 1; ++cwkgiq) { if (cwkgiq % 2 == 1) { f1 = Proxy.createFunction(h0, f0, o2.f2); } else { \"\\u45A7\"; }  } ");
/*fuzzSeed-85495475*/count=975; tryItOut("/*RXUB*/var r = new RegExp(\"[^\\\\uC15A\\\\W\\\\uFf39](?!\\\\b)|^+.{4,}.{0,}\\\\d*(?=(\\\\\\u00de|\\\\2{274877906943,274877906943})(?:\\\\b?|.*))|^[^]|.\", \"gyim\"); var s = \"___\\n\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=976; tryItOut("a1.push(v0, a2, b1);");
/*fuzzSeed-85495475*/count=977; tryItOut("mathy4 = (function(x, y) { return (( ! ((mathy3(( ! ( + ( + x))), ((( + Math.log1p(( + 1/0))) >>> 0) ? (( + mathy2(y, Math.fround(( ~ y)))) >>> 0) : (Math.fround(( - Math.fround(x))) >>> 0))) && (Math.atan2(Math.hypot(( - y), 1), (( ! (Math.sin(y) | 0)) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000001, -Number.MIN_VALUE, 0x080000001, 42, 0x0ffffffff, -(2**53+2), Math.PI, 2**53, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -1/0, -0x100000000, -(2**53-2), -0x080000000, 0x080000000, 0, -0x100000001, -0, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, 2**53+2, 1, -0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=978; tryItOut("\"use strict\"; v2 = g2.runOffThreadScript();");
/*fuzzSeed-85495475*/count=979; tryItOut("o2.__iterator__ = (function() { try { v0.__proto__ = f1; } catch(e0) { } try { Array.prototype.unshift.apply(a2, [s1, a2, this.f2, m2, f0, o2]); } catch(e1) { } p2.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 18446744073709552000.0;\n    var d3 = 65.0;\n    var d4 = 1.5474250491067253e+26;\n    var i5 = 0;\n    switch ((((0x14d2c64b)-(0xffffffff)+(-0x4779e1)) ^ ((0xfad3547f)))) {\n    }\n    d4 = (+((d3)));\n    return +((d4));\n    switch ((((-0x8000000)+(0x9e275809)+(0xc41bf58d)) << ((0xd9f1b7e8) % (0x0)))) {\n      case -1:\n        i5 = (0xc231ff97);\n      default:\n        d2 = (16777217.0);\n    }\n    d2 = (((-((6.044629098073146e+23)))) * ((((makeFinalizeObserver('tenured'))))));\n    d2 = ((d1) + (d4));\n    switch ((((0xcce35400)+(-0x2b393b8)-(0xffffffff)) & (((function factorial(fpdmis) { \"\\u1116\";; if (fpdmis == 0) { ; return 1; } ; return fpdmis * factorial(fpdmis - 1);  })(27933)) % (uneval(/(?!\\3)+?/))))) {\n      case -1:\n        d2 = (-(((0xdb049370) ? (d2) : (d3))));\n        break;\n      default:\n        (Float64ArrayView[((0xb5413629)) >> 3]) = ((Infinity));\n    }\n    switch ((((0x66183f57) / (0x38ec6e98)) ^ ((1)+(0xffffffff)))) {\n      case -1:\n        switch (((((0x93267fa4))|0))) {\n          default:\n            i5 = (0x6e9a32fd);\n        }\n    }\n    d3 = (16385.0);\n    d2 = (d3);\n    d3 = (+(((-0x8000000)*-0xb7ef6) | ((((((((0xfcb9d52a)) ^ ((0x59b24d58)+(0x3764ec09)))))>>>((0xfd216353)))))));\n    d3 = (d3);\n    i5 = ((0x3d11f7b7));\n    return +((+(-1.0/0.0)));\n    return +((d2));\n  }\n  return f; }); return o2; });");
/*fuzzSeed-85495475*/count=980; tryItOut("\"use strict\"; if([1]) {t1.__iterator__ = (function() { for (var j=0;j<49;++j) { f2(j%4==0); } }); }");
/*fuzzSeed-85495475*/count=981; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.sin((Math.max((Math.hypot(( + Number.MAX_SAFE_INTEGER), (mathy4(x, Math.imul(( + Math.trunc(( + y))), y)) | 0)) >>> 0), Math.max(y, Math.pow(x, y))) << (Math.imul(Math.hypot((( + (0/0 ? mathy0(x, (-Number.MAX_SAFE_INTEGER >>> 0)) : (Number.MAX_VALUE >>> 0))) | 0), ( ~ x)), mathy4(Math.fround(( - 2**53+2)), -(2**53))) >>> 0)))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -(2**53), 0x080000001, -0x100000001, -1/0, -0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -0x0ffffffff, -0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, 1/0, 2**53+2, -(2**53+2), 0x080000000, 0, -Number.MAX_VALUE, 42, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, Number.MAX_VALUE, Math.PI, 1, 0x0ffffffff, 2**53, 0/0, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=982; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(e1, m2);");
/*fuzzSeed-85495475*/count=983; tryItOut("this.v2 = (t2 instanceof this.b0);\nv2 = t1.length;\n");
/*fuzzSeed-85495475*/count=984; tryItOut("o0 = {};");
/*fuzzSeed-85495475*/count=985; tryItOut("do h0.defineProperty = encodeURI; while((x) && 0);");
/*fuzzSeed-85495475*/count=986; tryItOut("\"use strict\"; var w = 7;h1.getOwnPropertyDescriptor = (function() { try { v2 = (s1 instanceof f2); } catch(e0) { } try { a1 = new Array; } catch(e1) { } a0.sort((function() { try { v1 = NaN; } catch(e0) { } try { ; } catch(e1) { } /*ODP-2*/Object.defineProperty(a0, \"__iterator__\", { configurable: true, enumerable: (x % 4 != 0), get: (function() { try { v1 = (b1 instanceof a2); } catch(e0) { } try { v0 = (a2 instanceof o1); } catch(e1) { } s2 + o0; return e1; }), set: w }); return v0; })); return o0.b0; });");
/*fuzzSeed-85495475*/count=987; tryItOut("\"use strict\"; e2.add(this.b0);\nm0.set(g2.i2, o1);\n");
/*fuzzSeed-85495475*/count=988; tryItOut("this.i1 + '';");
/*fuzzSeed-85495475*/count=989; tryItOut("mathy1 = (function(x, y) { return ( + (Math.fround((( + ( + ( + x))) % Math.log2(Math.fround(mathy0(y, ( + (y * y))))))) ? Math.pow((( ~ (-0x080000000 >>> 0)) >>> 0), Math.fround((-Number.MAX_SAFE_INTEGER % Math.fround(y)))) : ( + Math.round(( + Math.pow(( ~ ( + y)), ((y - (x >>> 0)) | 0))))))); }); testMathyFunction(mathy1, [42, 2**53+2, 1.7976931348623157e308, 2**53, 0x080000000, 0x100000000, 0/0, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 0.000000000000001, 0, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, -0, -0x0ffffffff, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MAX_VALUE, 0x100000001, Math.PI, -Number.MIN_VALUE, -(2**53-2), -0x080000001, 1, -0x080000000, -1/0]); ");
/*fuzzSeed-85495475*/count=990; tryItOut("o2.g1 + '';");
/*fuzzSeed-85495475*/count=991; tryItOut("/*bLoop*/for (var oitjgc = 0; oitjgc < 75; ++oitjgc) { if (oitjgc % 58 == 47) { function f2(o0) o0 } else { h2.iterate = f2; }  } ");
/*fuzzSeed-85495475*/count=992; tryItOut("function shapeyConstructor(btsyru){if (btsyru) Object.preventExtensions(btsyru);btsyru[\"valueOf\"] = objectEmulatingUndefined();if (({ set 1() { yield btsyru }  })) { print(btsyru);\nf0 = Proxy.createFunction(h0, this.f2, f0);\n } return btsyru; }/*tLoopC*/for (let e of /*FARR*/[...Math.acos(this), .../*MARR*/[ '' , eval, eval,  '' , eval,  '' , x, x, eval, eval, x, eval, x, eval, eval, x, x, eval,  '' ,  '' , eval, x, eval, x, x,  '' ,  '' , eval,  '' , x,  '' , eval, x, x, x, x, eval, x, eval, eval, eval,  '' ,  '' , x, x, eval, eval,  '' ,  '' , x, eval, eval,  '' , eval, eval,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , eval,  '' , x, x, x, x, x, x, x, eval,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , x, x, x,  '' ,  '' , eval, eval, x, eval, x,  '' ,  '' , eval, x, x,  '' ,  '' , eval, x, eval, eval, eval,  '' , x, x, eval,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , x, x,  '' ,  '' ,  '' ,  '' , x,  '' , x, x,  '' ,  '' ,  '' , eval, x,  '' ,  '' , x, eval,  '' , x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  '' , eval,  '' , x, eval, x, eval], (uneval(({\u3056: \"\\u4026\"}))), , ...Math.log10 for (x of x) for (\u3056 of --w) for each (z in []) if (-16), ...x]) { try{let boymhl = shapeyConstructor(e); print('EETT'); function  boymhl (e) { yield boymhl } }catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-85495475*/count=993; tryItOut("\"use strict\"; t2 = new Int16Array(v0);");
/*fuzzSeed-85495475*/count=994; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.round(Math.fround(( + ( ! (( ~ y) | 0))))); }); ");
/*fuzzSeed-85495475*/count=995; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((Math.fround(((Math.hypot(( + x), (y & x)) || (Math.imul(((-1/0 - ( + Math.log2(( + y)))) | 0), ( ! x)) | 0)) | 0)) < Math.fround(((Math.imul(x, x) | 0) << (Math.hypot((( ~ (( + (Math.hypot(y, Math.fround(y)) != (x || x))) >>> 0)) | 0), Math.trunc((Math.fround(Math.max(( ~ -Number.MIN_SAFE_INTEGER), Math.fround(0x100000001))) | 0))) >>> 0))))); }); testMathyFunction(mathy2, [-0x100000000, 0.000000000000001, 0x080000001, 0x080000000, 0, -0x07fffffff, -0x0ffffffff, -0x080000000, 0x07fffffff, -(2**53-2), 0/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 42, 2**53, -0x100000001, 0x100000000, 1/0, -(2**53+2), 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, -0, -Number.MAX_SAFE_INTEGER, 1, 2**53-2, -(2**53), -1/0, 0x100000001, -0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=996; tryItOut("\"use strict\"; print(t0);");
/*fuzzSeed-85495475*/count=997; tryItOut("\"use strict\"; while(((window ^= -26) -= x) && 0){[z1];/*RXUB*/var r = o0.r1; var s = \"aaaa\"; print(s.match(r)); print(r.lastIndex);  }");
/*fuzzSeed-85495475*/count=998; tryItOut("\"use strict\"; \"use asm\"; s1 = '';");
/*fuzzSeed-85495475*/count=999; tryItOut("\"use asm\"; var scywlr = new ArrayBuffer(0); var scywlr_0 = new Uint16Array(scywlr); scywlr_0[0] = 16; v2 = (v0 instanceof g1);");
/*fuzzSeed-85495475*/count=1000; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max(Math.hypot((Math.hypot((( - y) | 0), (Math.hypot(( + (Math.pow((Number.MIN_VALUE | 0), y) != x)), ( + ( ~ ( + -0x080000000)))) | 0)) | 0), mathy0((( ! ((y << x) | 0)) >>> 0), (( - y) & (((Math.max((-Number.MIN_SAFE_INTEGER >>> 0), (y | 0)) >>> 0) < y) | 0)))), Math.hypot(( + ((Math.imul(( + ( - ( + x))), -1/0) >>> 0) >>> ( + (-0x080000001 <= 2**53+2)))), ( + (( ! Math.sinh(y)) >>> 0)))); }); ");
/*fuzzSeed-85495475*/count=1001; tryItOut("testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , new Number(1), 0x100000000, 0x100000000, 0x100000000, new Number(1), objectEmulatingUndefined(), 0x100000000, objectEmulatingUndefined(), new Number(1), new Number(1), 0x100000000, objectEmulatingUndefined(),  /x/g , new Number(1)]); ");
/*fuzzSeed-85495475*/count=1002; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, 1.7976931348623157e308, 0x100000000, 1, 0x07fffffff, -0x100000001, -0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -0x080000000, 0x080000000, 42, -Number.MAX_SAFE_INTEGER, -0x100000000, 0, 2**53-2, 0x100000001, -(2**53-2), 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, -Number.MAX_VALUE, 1/0, -0x080000001, -(2**53+2), -(2**53), 0/0, -0x0ffffffff, 0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=1003; tryItOut("m1 + b2;");
/*fuzzSeed-85495475*/count=1004; tryItOut("testMathyFunction(mathy2, /*MARR*/[new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, NaN, objectEmulatingUndefined(), NaN, NaN, objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), NaN, NaN, new String(''), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), NaN, new String(''), objectEmulatingUndefined(), NaN, NaN, objectEmulatingUndefined(), new String(''), new String(''), NaN, new String(''), NaN, new String(''), NaN, new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), NaN, NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), NaN, NaN, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), NaN, objectEmulatingUndefined(), NaN, new String(''), NaN, NaN, objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), NaN, new String(''), new String(''), new String(''), NaN, objectEmulatingUndefined(), new String(''), NaN, new String(''), objectEmulatingUndefined(), NaN, NaN, new String(''), objectEmulatingUndefined(), new String(''), NaN, NaN, NaN, NaN, NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), NaN, objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), new String(''), NaN, objectEmulatingUndefined(), new String(''), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, new String(''), NaN, NaN, objectEmulatingUndefined(), NaN, new String(''), NaN, new String(''), NaN, new String(''), new String(''), objectEmulatingUndefined(), new String(''), NaN, new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), NaN, NaN, objectEmulatingUndefined(), new String(''), NaN, NaN, new String(''), NaN, new String(''), NaN, objectEmulatingUndefined(), new String(''), new String(''), NaN, new String('')]); ");
/*fuzzSeed-85495475*/count=1005; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0(Math.fround(mathy0(Math.fround((Math.fround(Math.ceil(Math.fround(x))) ^ Math.fround(Number.MIN_VALUE))), Math.imul(x, (Math.hypot((-0x0ffffffff ? mathy0(Math.fround(0/0), Math.fround(-Number.MAX_SAFE_INTEGER)) : y), Math.sin((mathy0(((-Number.MAX_SAFE_INTEGER ? x : -0x080000000) >>> 0), (y >>> 0)) >>> 0))) | 0)))), Math.fround(Math.cosh(( + ( + ( + ( + Math.log1p(Math.min(x, 1.7976931348623157e308)))))))))); }); ");
/*fuzzSeed-85495475*/count=1006; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1|${0,}(?!\\\\1?)*(?:.)\", \"gi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-85495475*/count=1007; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min(( + Math.expm1(( + (Math.imul(((x === y) >>> 0), (Math.pow(Math.imul(x, (((x | 0) ^ ( + y)) | 0)), x) >>> 0)) >>> 0)))), ( ~ Math.pow(Math.fround(Math.log1p(Math.fround(( ~ Math.pow(y, x))))), (Math.log(-(2**53-2)) ? ( + (1 ^ y)) : (( - (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [1.7976931348623157e308, 2**53+2, 2**53, -1/0, -(2**53+2), -0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 0/0, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53), -0x100000000, Math.PI, 0x07fffffff, 0x100000000, 0x100000001, 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff, 0x080000001, -Number.MAX_VALUE, 0x080000000, -0x07fffffff, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0]); ");
/*fuzzSeed-85495475*/count=1008; tryItOut("\"use asm\"; a1.shift();");
/*fuzzSeed-85495475*/count=1009; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(a0, m1);");
/*fuzzSeed-85495475*/count=1010; tryItOut("v0 = (p2 instanceof o0);");
/*fuzzSeed-85495475*/count=1011; tryItOut("/*MXX3*/g2.DataView.prototype.getInt32 = o1.g1.DataView.prototype.getInt32;/* no regression tests found */");
/*fuzzSeed-85495475*/count=1012; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ~ ( + Math.hypot(Math.fround(( + mathy1(( + x), Math.fround((Math.fround(( + Math.asin(0x0ffffffff))) << Math.hypot(x, -0x0ffffffff)))))), (Math.max((Math.hypot(Math.atan2(x, Math.fround(Math.pow(Math.fround((x >>> y)), Math.fround(y)))), (Math.pow(-Number.MIN_VALUE, ( + (x | 0))) >>> 0)) >>> 0), (Math.fround((Math.max(x, ( + 1.7976931348623157e308)) >>> 0)) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-85495475*/count=1013; tryItOut("L:for(let b in ((Date.prototype.setMonth)([,]))){qqjoak(((e) = [[1]]));/*hhh*/function qqjoak([]){/*MXX1*/o2 = g0.Date.prototype.getFullYear;} }");
/*fuzzSeed-85495475*/count=1014; tryItOut("Array.prototype.shift.call(a1);");
/*fuzzSeed-85495475*/count=1015; tryItOut("L:for([z, d] = yield ((x = new RegExp(\"^|((?:\\\\D){0,})|(?=\\\\b)+\", \"\"))) in new RegExp(\"\\\\3\", \"gim\")) (/(?:(?=[]|\\1+).*(?:(?:$)){4})+/y)");
/*fuzzSeed-85495475*/count=1016; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ! (mathy2(Math.atan2((mathy2(( + ( ! Math.fround(-0x080000001))), (Math.min(Math.pow((x | 0), (y | 0)), y) | 0)) | 0), (Math.fround((-Number.MIN_SAFE_INTEGER | x)) | 0)), ( + (x + (Number.MIN_SAFE_INTEGER | 0)))) | 0)) | 0); }); testMathyFunction(mathy3, [null, (new Number(-0)), false, objectEmulatingUndefined(), '/0/', (new Boolean(true)), (new String('')), 0, (new Number(0)), [0], -0, NaN, /0/, ({valueOf:function(){return '0';}}), 1, true, ({toString:function(){return '0';}}), (function(){return 0;}), '\\0', undefined, '', '0', [], 0.1, ({valueOf:function(){return 0;}}), (new Boolean(false))]); ");
/*fuzzSeed-85495475*/count=1017; tryItOut("Array.prototype.forEach.call(a0, (function(j) { f1(j); }), e0, t1, h2);");
/*fuzzSeed-85495475*/count=1018; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (Math.min(((((( + Math.pow(x, y)) | 0) !== Math.fround(x)) | 0) < (Number.MIN_VALUE | 0)), mathy0((((Math.pow(((Math.fround(Math.exp(( + y))) || y) | 0), (Math.min(x, y) | 0)) >>> 0) ? ( ! (y >>> 0)) : x) >>> 0), ( + (x ? ((x > (x | 0)) | 0) : (Math.fround((((Math.imul(y, x) >>> 0) ** (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)) !== (x === (y | 0))))))) ? ((( ! Math.fround(Math.expm1(Math.fround(y)))) ? Math.atan2(( + y), y) : Math.fround(((( + Math.sinh(( + y))) < Math.fround(x)) < (( - (y | 0)) | 0)))) >>> 0) : Math.atan2(((((Math.fround(Math.min((x | 0), Math.fround(x))) < (x | 0)) | 0) << ( + mathy0(Math.min(x, x), x))) >>> 0), ( ~ x)))); }); testMathyFunction(mathy5, [0, -0x080000001, 2**53, -0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 2**53-2, 42, 0x100000000, -0x100000000, -1/0, -Number.MAX_VALUE, 1/0, 0x080000000, -Number.MIN_VALUE, -(2**53-2), 1, -0, -(2**53), -0x100000001, -0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, 0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-85495475*/count=1019; tryItOut("mathy0 = (function(x, y) { return (Math.tan(Math.min((( + Math.tan(( + y))) >>> 0), ( + Math.fround((Math.fround(x) + Math.fround(Math.sinh(x))))))) | 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 42, 2**53-2, Number.MIN_VALUE, -0x0ffffffff, -1/0, -(2**53), 1, -0x100000001, -Number.MAX_VALUE, -(2**53-2), 0x100000001, 0x0ffffffff, Math.PI, 2**53, 1.7976931348623157e308, 0, 2**53+2, 0x100000000, 0x07fffffff, -0, Number.MAX_VALUE, 1/0, 0/0, -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x100000000, -0x080000001, -0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1020; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a2, [g0.f0]);");
/*fuzzSeed-85495475*/count=1021; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(mathy1((((x | 0) == ( - y)) >>> 0), Math.fround(mathy1(Math.acosh(-0), ( ~ (y | 0)))))), Math.fround(( ! ((Math.atan2(x, y) >>> 0) <= Math.round(y)))))); }); testMathyFunction(mathy5, [2**53+2, Math.PI, 42, -0, -(2**53-2), 1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -1/0, 0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, -Number.MAX_VALUE, 0, Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 2**53, -(2**53), Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, 0x0ffffffff, -0x100000001, 0x100000000, 0x080000000, -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, 0x100000001, -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=1022; tryItOut("v2 = Object.prototype.isPrototypeOf.call(h2, o0.e2);");
/*fuzzSeed-85495475*/count=1023; tryItOut("\"use strict\"; var fherzd = new ArrayBuffer(8); var fherzd_0 = new Uint8Array(fherzd); fherzd_0[0] = -4210233711; var fherzd_1 = new Uint8ClampedArray(fherzd); var fherzd_2 = new Uint16Array(fherzd); fherzd_2[0] = -576460752303423500; var fherzd_3 = new Uint8ClampedArray(fherzd); break ;h2.defineProperty = (function(j) { if (j) { try { a1[5]; } catch(e0) { } try { print(h1); } catch(e1) { } try { o0 + s0; } catch(e2) { } g1 + a2; } else { try { for (var p in a0) { try { g2.__proto__ = v0; } catch(e0) { } try { g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (fherzd_0[0] % 2 == 0), noScriptRval: false, sourceIsLazy: (fherzd_3[9] % 5 != 1), catchTermination: false })); } catch(e1) { } try { g2.g0.offThreadCompileScript(\"( /x/g );\", ({ global: o2.g1.g1, fileName: null, lineNumber: 42, isRunOnce: [], noScriptRval: [z1], sourceIsLazy: false, catchTermination: (fherzd_1 % 5 == 3) })); } catch(e2) { } for (var v of b1) { try { v2 = evaluate(\"function f1(o0.e2)  { \\\"use asm\\\"; yield d } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: (fherzd_3[9] % 3 == 2) })); } catch(e0) { } g2.toSource = (function mcc_() { var pdilas = 0; return function() { ++pdilas; f2(/*ICCD*/pdilas % 5 == 4);};})(); } } } catch(e0) { } h0.getPropertyDescriptor = f2; } });return;(window);");
/*fuzzSeed-85495475*/count=1024; tryItOut("e0.delete(p2);");
/*fuzzSeed-85495475*/count=1025; tryItOut("yield;if(true) { if (\"\\u811D\") v1 = (i2 instanceof i0); else 7;}");
/*fuzzSeed-85495475*/count=1026; tryItOut("m1.get(i0);");
/*fuzzSeed-85495475*/count=1027; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-85495475*/count=1028; tryItOut("v2 = (g1.s1 instanceof o1.a0);");
/*fuzzSeed-85495475*/count=1029; tryItOut("m0.valueOf = (function() { try { v1 = Object.prototype.isPrototypeOf.call(b0, t1); } catch(e0) { } o0 + ''; return i0; });");
/*fuzzSeed-85495475*/count=1030; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 1.125;\n    (Int16ArrayView[1]) = ((!(((Float32ArrayView[4096]))))*-0xe83c3);\n    i0 = (0x89884011);\n    switch (((((0x2f4f5cf7))-(0xfa050a29)) & ((0x9f464d01) / (0x71dc3182)))) {\n      case 1:\n        d2 = (+abs((((((d2) + (36893488147419103000.0))) * ((-1.888946593147858e+22))))));\n        break;\n      case 0:\n        i0 = (/*FFI*/ff(((+abs(((+(0.0/0.0)))))), (((((Uint8ArrayView[2]))) >> ((0xf9826cc3)+(i0)+(0xfc9dd2e5)))), ((Infinity)), ((abs((imul((i0), (i0))|0))|0)), ((-65537.0)), ((((0xfd12095e)*-0x7489) & ((0xa12d917d)))), ((NaN)))|0);\n      case -1:\n        d2 = (+(((i0) ? (-((NaN))) : ((1.5)))));\n        break;\n      case 0:\n        return +((-8193.0));\n        break;\n      case 1:\n        /*FFI*/ff((((((-((Float32ArrayView[0]))) != ((0xffffffff) ? (-2251799813685249.0) : (262145.0)))+(/*FFI*/ff(((0x419136aa)), ((d1)))|0)) & (((Infinity) <= (d2))))), ((+(-1.0/0.0))), ((abs((imul((0xffffffff), (0xe7831f92))|0))|0)), ((((0x97a520f0)-(0xf467dcc))|0)), ((d1)), ((abs((0x9ded8ec))|0)), ((((0xffffffff)) << ((0xfa6ab10b)))), ((129.0)), ((-9007199254740992.0)), ((-16777217.0)), ((140737488355329.0)), ((36028797018963970.0)), ((524289.0)), ((34359738368.0)), ((-68719476737.0)), ((134217729.0)), ((-1.03125)), ((-4398046511105.0)), ((-4194305.0)), ((562949953421311.0)), ((32769.0)), ((-70368744177664.0)));\n      default:\n        {\n          (Int16ArrayView[2]) = ((0xfc1ce7f7)+(0xb215a8ff)-(0x4696ca1f));\n        }\n    }\n    (Float64ArrayView[((0xfa33b29b)) >> 3]) = ((1.0078125));\n    (Uint32ArrayView[((0xf9d2579a)) >> 2]) = ((i0));\n    (Float64ArrayView[(((((0x3e5302df)*-0x4dd0e)>>>((0x2e6e9cc3) / (0x3e3e0b74))) < (0x42acc931))-(0xfe6e9a2f)) >> 3]) = ((-((d2))));\n    d1 = (d2);\n    return +(((((0xffffffff)) ? ((((this.__defineSetter__(\"y\", new RegExp(\"(?=(?![]|\\\\B|\\\\B|.{1}))\", \"gim\").compile)))) / ((d1))) : ((((0xceb0fa6f) ? (+((d1))) : (129.0))) * ((+(-1.0/0.0)))))));\n    i0 = (0xffffffff);\n    (Float64ArrayView[0]) = ((+/*FFI*/ff(((d1)), ((((/*FFI*/ff(((((/*FFI*/ff(((~(((0x60d6590f) < (0x25d20f7))))), ((0x4b7e11d1)), ((+(0x131705b8))), ((8388609.0)), ((-16777215.0)), ((-70368744177663.0)), ((1.2089258196146292e+24)), ((295147905179352830000.0)), ((134217729.0)), ((-562949953421311.0)), ((1.001953125)), ((-536870913.0)), ((68719476737.0)), ((3.777893186295716e+22)), ((8589934593.0)), ((1.5111572745182865e+23)), ((4503599627370497.0)), ((8.0)), ((-1.2089258196146292e+24)), ((-1125899906842625.0)), ((257.0)), ((8193.0)), ((31.0)), ((-4398046511104.0)), ((144115188075855870.0)), ((-4503599627370495.0)), ((-6.044629098073146e+23)), ((2251799813685249.0)))|0)-((0xfb8e0502))) ^ ((i0)*-0xfffff))), ((d2)), ((+/*FFI*/ff((((((0x6aacdeec) == (0x67e75423))+(!(0xb29aec59))) >> ((0x96be4e44)))), ((137438953473.0)), ((+sqrt(((+(0xc5870ada)))))), ((imul((0xfd397091), (0xff833948))|0)), ((-17.0)), ((129.0)), ((-1152921504606847000.0)), ((8589934593.0)), ((274877906945.0)), ((9007199254740992.0)), ((-1.888946593147858e+22)), ((-3.022314549036573e+23)), ((295147905179352830000.0)), ((-524289.0)), ((-17179869185.0)), ((65536.0)), ((-2.4178516392292583e+24)), ((2.0)), ((-36893488147419103000.0)), ((1.125)), ((36893488147419103000.0)), ((-8796093022208.0)), ((140737488355329.0)), ((9.671406556917033e+24)), ((2097153.0)), ((2305843009213694000.0)), ((-17592186044416.0)), ((-1.9342813113834067e+25)), ((9.44473296573929e+21))))), ((((0x9067633a)) ^ ((0xf83e7725)-(0xf89d0696)))), ((Infinity)), ((~((0x731a9d49) / (0x1d0a09b0)))), ((((0xfd67c624)) | ((0xffffffff)))), ((-1.0625)), ((140737488355329.0)), ((274877906945.0)), ((4398046511105.0)), ((274877906943.0)), ((-1.888946593147858e+22)), ((-1.888946593147858e+22)))|0)))), ((3.022314549036573e+23)))));\n    d2 = (+(abs((((0xf9f13ab3)-((0xffffffff) ? ((0xc748312a)) : (!(i0)))) & (((9.671406556917033e+24) < (+abs(((d1))))))))|0));\n    d1 = (1.5111572745182865e+23);\n    d2 = (d1);\n    i0 = (i0);\n    return +((Float64ArrayView[4096]));\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x100000000, 0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 1, -0, 0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 0/0, -(2**53-2), -0x080000001, -Number.MAX_VALUE, 0x0ffffffff, -(2**53+2), 0x080000000, 0.000000000000001, -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, 0, 2**53, 0x07fffffff, -(2**53), 0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, 42, -Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=1031; tryItOut("o1.e0 + '';");
/*fuzzSeed-85495475*/count=1032; tryItOut("\"use strict\"; delete h0.enumerate;");
/*fuzzSeed-85495475*/count=1033; tryItOut("\"use strict\"; v0 = t1.length;");
/*fuzzSeed-85495475*/count=1034; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.cos((( - ( - Math.fround(Math.atan2(((0x07fffffff - (x | 0)) | 0), Math.fround(Math.pow(Math.fround(Math.tan(Math.fround(y))), Math.fround(-Number.MAX_SAFE_INTEGER))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), 0x100000000, -(2**53-2), 2**53-2, 1/0, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, -0x100000000, -0x100000001, -1/0, 1.7976931348623157e308, 2**53+2, -(2**53), Math.PI, 0x100000001, -0x080000001, 0, Number.MAX_VALUE, 42, -0x07fffffff, 0.000000000000001, 0/0, 0x080000001]); ");
/*fuzzSeed-85495475*/count=1035; tryItOut("\"use strict\"; let(x) { throw StopIteration;}");
/*fuzzSeed-85495475*/count=1036; tryItOut("mathy4 = (function(x, y) { return (mathy0((((((Math.imul(Math.fround(x), ( + mathy1(y, ( + y)))) < Math.atan2(y, (x !== (( + (x | 0)) | 0)))) >>> 0) >> (mathy3((y % y), -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0) % (( ! (x % (y >>> 0))) | 0)), ((mathy2(((( ! (x * 0x080000000)) | 0) >>> 0), (mathy1(x, ( + (( ~ (y >>> 0)) >>> 0))) >>> 0)) >>> 0) - (( - y) >> y))) | 0); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, 0x07fffffff, Math.PI, -0x100000000, 42, 2**53, 2**53-2, 0x0ffffffff, 1, -(2**53-2), 0, -0x07fffffff, -0, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, 0.000000000000001, 2**53+2, 0x080000000, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1037; tryItOut("/*tLoop*/for (let c of /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]) { v1 = t1.byteOffset; }");
/*fuzzSeed-85495475*/count=1038; tryItOut("/*vLoop*/for (let ajpkwx = 0; ajpkwx < 6; \u3056 *= this, ++ajpkwx) { var e = ajpkwx; Array.prototype.splice.call(a2, -11, 15, h1, p1); } ");
/*fuzzSeed-85495475*/count=1039; tryItOut("m0 = new Map;");
/*fuzzSeed-85495475*/count=1040; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (+atan2(((d1)), ((d1))));\n    }\n    i0 = ((0x0));\n    d1 = (+/*FFI*/ff(((abs((((0xfd282188)-(i0)) << (((((void options('strict'))) & (((0xb890ef8c) ? (0x95eb8e04) : (0x5d589989)))))-(!(0x430f2b2e))+(0x478349c7))))|0)), ((d1)), ((d1))));\n    i0 = (0x35f05727);\n    i0 = ((134217729.0) != (d1));\n    d1 = (Infinity);\n    i0 = (i0);\n    d1 = (+atan2(((Float64ArrayView[0])), ((Float64ArrayView[2]))));\n    {\n      {\n        i0 = (10);\n      }\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: (new Function(\"((a) = d >> (window &  /x/ ));\"))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=1041; tryItOut("e1 + '';");
/*fuzzSeed-85495475*/count=1042; tryItOut("print(x);\nprint(h2);\n");
/*fuzzSeed-85495475*/count=1043; tryItOut("\"use strict\"; ;");
/*fuzzSeed-85495475*/count=1044; tryItOut("var i2 = new Iterator(b1, true);function y(x, eval) { yield (void version(180)) } print(x);");
/*fuzzSeed-85495475*/count=1045; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.abs((((Math.fround(( - Math.fround(Math.imul((x | 0), y)))) === ( + x)) > Math.fround((Math.min(-Number.MIN_VALUE, Math.atan2(( + x), ((-Number.MIN_SAFE_INTEGER >>> 0) ? x : 0x100000001))) ? ( + Math.pow(mathy0(-Number.MIN_VALUE, 0x080000000), ( + ( + ( + (Math.fround((Math.fround((( - x) | 0)) && x)) >>> 0)))))) : ( + Math.fround(Math.sinh(x)))))) | 0)); }); ");
/*fuzzSeed-85495475*/count=1046; tryItOut("Array.prototype.sort.apply(a0, [(function() { try { v0 = evalcx(\"s1.toString = (function(stdlib, foreign, heap){ \\\"use asm\\\";   function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var d2 = -2147483649.0;\\n    var i3 = 0;\\n    var i4 = 0;\\n    return +((((d0)) * ((d2))));\\n  }\\n  return f; });print(x);\", g1); } catch(e0) { } h1 = ({getOwnPropertyDescriptor: function(name) { v1 = r0.source;; var desc = Object.getOwnPropertyDescriptor(b1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g1.v1 = Object.prototype.isPrototypeOf.call(g2.i2, p1);; var desc = Object.getPropertyDescriptor(b1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { for (var v of i1) { try { i1 = new Iterator(o2.m2, true); } catch(e0) { } /*MXX3*/o0.g0.Math.SQRT1_2 = g2.Math.SQRT1_2; }; Object.defineProperty(b1, name, desc); }, getOwnPropertyNames: function() { /*ODP-3*/Object.defineProperty(this.o0.i2, \"isInteger\", { configurable: (x % 5 == 4), enumerable: false, writable: (\"\u03a0\" in x), value: p1 });; return Object.getOwnPropertyNames(b1); }, delete: function(name) { for (var v of m2) { try { print(g0.m2); } catch(e0) { } a1.push(i0, g2); }; return delete b1[name]; }, fix: function() { /*MXX3*/g1.Object.prototype.isPrototypeOf = g0.Object.prototype.isPrototypeOf;; if (Object.isFrozen(b1)) { return Object.getOwnProperties(b1); } }, has: function(name) { b1 = new ArrayBuffer(7);; return name in b1; }, hasOwn: function(name) { /*MXX3*/g2.Math.atan = g1.Math.atan;; return Object.prototype.hasOwnProperty.call(b1, name); }, get: function(receiver, name) { Object.preventExtensions(v0);; return b1[name]; }, set: function(receiver, name, val) { e2 = new Set;; b1[name] = val; return true; }, iterate: function() { r1 = /\\2/i;; return (function() { for (var name in b1) { yield name; } })(); }, enumerate: function() { (void schedulegc(g0));; var result = []; for (var name in b1) { result.push(name); }; return result; }, keys: function() { t1 = new Uint8Array(b0, 4, ({valueOf: function() { e1.add(x);return 1; }}));; return Object.keys(b1); } }); return this.v2; }), b1]);");
/*fuzzSeed-85495475*/count=1047; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x080000001, -0x080000001, 0.000000000000001, -1/0, -(2**53+2), -0x100000000, Math.PI, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, 1, -0, 2**53, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, 0/0, 0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 0, -Number.MAX_VALUE, -(2**53), -0x0ffffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 42, 0x100000000, 0x100000001]); ");
/*fuzzSeed-85495475*/count=1048; tryItOut("\"use strict\"; for(let x = (Math.imul(22, 6)) in (new Error(2))) (length === true);");
/*fuzzSeed-85495475*/count=1049; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+((d1)));\n    return +((Float64ArrayView[((('fafafa'.replace(/a/g, x)) ? ((((0xfafc8992))>>>((-0x8000000))) != (((0xf8e927d1))>>>((0xffffffff)))) : (0x24efa36f))+((((0xff2c74de)) ^ ((0x8d3ecc15)+((0x533c69a0) ? (-0x8000000) : (0x4208c419)))) >= (((/*wrap3*/(function(){ var zzqyex = (4277); (DFGTrue)(); }).prototype)+(0xb273031c)+(0xb8e5be04)) & ((0xfa711d38))))) >> 3]));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; return x }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000001, -0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, -1/0, -0x07fffffff, -Number.MIN_VALUE, 1/0, Math.PI, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 1, 0x080000001, 42, 2**53, -(2**53+2), 2**53+2, 0.000000000000001, -0x080000000, 0/0, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0, 0, -Number.MAX_VALUE, -(2**53), 0x0ffffffff, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1050; tryItOut(";");
/*fuzzSeed-85495475*/count=1051; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1052; tryItOut("/*bLoop*/for (rhkitu = 0; rhkitu < 7; ++rhkitu) { if (rhkitu % 4 == 2) { print(this.__defineSetter__(\"window\", Uint16Array)); } else { x = \"\\uC619\", smqdrg, fwdyvo, ztvqws, b;p1 + ''; }  } ");
/*fuzzSeed-85495475*/count=1053; tryItOut("testMathyFunction(mathy4, [Number.MIN_VALUE, 0.000000000000001, -0x100000000, -Number.MAX_VALUE, 0x100000000, 0x080000000, -0x07fffffff, -(2**53-2), 1.7976931348623157e308, -(2**53), Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 0x07fffffff, -1/0, 1/0, -(2**53+2), 0/0, 42, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0, -0x100000001, Number.MAX_VALUE, 2**53, 1, -0, -0x080000000]); ");
/*fuzzSeed-85495475*/count=1054; tryItOut("/*oLoop*/for (var cwpupt = 0; cwpupt < 45; ++cwpupt) { v2 = evalcx(\"return;\", g1); } ");
/*fuzzSeed-85495475*/count=1055; tryItOut("\"use strict\"; let eval = x, a, x = x, x = null, dhrgax, x, z;print(x);");
/*fuzzSeed-85495475*/count=1056; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.pow(mathy1(y, (Math.max(( + Math.min(y, ( + x))), x) >>> 0)), (( - (( + ( - (2**53+2 >>> 0))) >>> 0)) | 0))); }); ");
/*fuzzSeed-85495475*/count=1057; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1058; tryItOut("if((x % 3 != 0)) v0 = g2.runOffThreadScript(); else {{print(x); }print((4277) |= new /*wrap3*/(function(){ var zbeveb = new RegExp(\"[^](?=\\\\b)|\\\\3.|(?:[^])|^*\", \"gym\"); (arguments.callee)(); })()); }");
/*fuzzSeed-85495475*/count=1059; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.9342813113834067e+25;\n    d0 = (d1);\n    (Int32ArrayView[1]) = ((((-0xfffff*(0xf9488275)) | ((~~(d1)) % (imul(((0x28e4659f) ? (0xffffffff) : (0x10bd8830)), (0x80f50f8e))|0)))));\n    d0 = (((d0)) % (((d0) + (((d2)) % ((d0))))));\n    return +((d1));\n  }\n  return f; })(this, {ff: (decodeURIComponent).call}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=1060; tryItOut("var dpnzhe, a = (makeFinalizeObserver('tenured')).unwatch(\"toString\"), x = Math.hypot((4277), -25), x;/*RXUB*/var r = new RegExp(\"\\u0093*?\", \"\"); var s = \"\\ud8f7\"; print(r.exec(s)); ");
/*fuzzSeed-85495475*/count=1061; tryItOut("mathy2 = (function(x, y) { return ((((Math.min(mathy1(( + ((y | 0) + x)), (Math.log1p(y) | 0)), ( ~ (( ~ Number.MAX_SAFE_INTEGER) | 0))) >>> 0) <= (((( ! (Math.hypot(y, (Math.cbrt(y) >>> 0)) | 0)) | 0) | 0) && Math.fround(mathy1(y, (( + Math.clz32(( ! ( + (Number.MIN_SAFE_INTEGER << (y | 0)))))) >>> 0))))) ** (( + (( + ( + Math.ceil((( - 1) | 0)))) == ( + Math.round(Math.fround(( ~ -0x07fffffff)))))) | 0)) | 0); }); testMathyFunction(mathy2, [null, (new String('')), -0, 0, (new Number(0)), [0], NaN, 1, ({valueOf:function(){return '0';}}), (function(){return 0;}), objectEmulatingUndefined(), undefined, [], (new Number(-0)), (new Boolean(true)), true, ({valueOf:function(){return 0;}}), /0/, ({toString:function(){return '0';}}), '/0/', 0.1, false, (new Boolean(false)), '\\0', '', '0']); ");
/*fuzzSeed-85495475*/count=1062; tryItOut("\"use strict\"; x = [z1,,], [[, [], {}, eval], {eval: x, x, x}, ] = (4277).pop(-27), NaN = (e = x), xvpxsg, tekmda, ubwquz;/* no regression tests found */");
/*fuzzSeed-85495475*/count=1063; tryItOut("testMathyFunction(mathy2, [0x07fffffff, Number.MAX_VALUE, -0x100000000, -(2**53), -Number.MIN_VALUE, -0x080000001, 0x100000000, -0x07fffffff, Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -0, -0x100000001, -0x0ffffffff, -0x080000000, Math.PI, 2**53+2, 0x080000000, -1/0, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, 0x0ffffffff, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, 0x080000001, 1/0, 1, -Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=1064; tryItOut("print(x);function eval(z, b = /*MARR*/[ '' , new Number(1.5), new Number(1.5), new String('q'), eval, new String(''), new String('q'),  '' , new Number(1.5), new String(''), new Number(1.5), eval, new String('q'),  '' , new String(''), new Number(1.5), new Number(1.5), eval, new String('q'), new Number(1.5), new String('q'), new String(''), eval, eval, new String('q'), eval, new String(''),  '' , new String(''), new String('q'), new Number(1.5), new Number(1.5), new String(''), new Number(1.5)].filter(Array.from), a, x, d, \u3056, a, x, NaN, x, NaN, b, z, b = ({a2:z2}), z, let, z, x, x = window, z = \"\\u93D1\", y, x, NaN =  '' , x, window, x, x =  \"\" , window, \u3056, z = \"\\u23A1\", \u3056, c, x, x, c, this.x, x, x, x = \"\\u780D\", b, this.x, z,  , x, x, x, c, x = new RegExp(\"[^\\\\f-\\u0e3a\\\\x59-\\\\u0036\\\\u0091-\\\\v\\\\u000a-\\u1b28](?:\\\\3)*?|(?!.|[\\\\v\\u0080-\\\\\\ue0b0\\\\s]){4}((?!.|(?:[\\u00f1\\\\xE5-\\\\xf3\\\\D])))|(([\\\\W]))\", \"im\"), w, x = \"\u03a0\", e, d, x, window, x, x, e, c, x, x, a) /x/ .__defineGetter__(\"x\", function(y) { \"use strict\"; yield y;  \"\" ;; yield y; })x;");
/*fuzzSeed-85495475*/count=1065; tryItOut("\"use strict\"; /*vLoop*/for (vqyhzp = 0; ((timeout(1800)) ? (4277) : (4277)) && vqyhzp < 37; ++vqyhzp) { var a = vqyhzp; /*infloop*/M:do {/*infloop*/M:for(let Float32Array in ((Array.prototype.toLocaleString)(false ? a : this))/*\n*/){print((4277));v1 = r1.source; } } while(-6); } ");
/*fuzzSeed-85495475*/count=1066; tryItOut("a0.splice(NaN, 1)");
/*fuzzSeed-85495475*/count=1067; tryItOut("a2 = r0.exec(s2);");
/*fuzzSeed-85495475*/count=1068; tryItOut("\"use strict\"; /*vLoop*/for (var avtyjt = 0, x, luzkzq; avtyjt < 52; ++avtyjt) { b = avtyjt; eval; } ");
/*fuzzSeed-85495475*/count=1069; tryItOut("testMathyFunction(mathy4, [-0x100000000, 1/0, 0x100000000, 1.7976931348623157e308, -0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, -0x080000000, 0x080000000, -0x080000001, -(2**53-2), 0/0, -1/0, 0, Math.PI, 1, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, -Number.MAX_VALUE, 2**53, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, 0.000000000000001, 42, -(2**53)]); ");
/*fuzzSeed-85495475*/count=1070; tryItOut("print(uneval(o0.h0));");
/*fuzzSeed-85495475*/count=1071; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (x > ( + Math.log(( ~ Math.atan2(Math.fround(Math.exp(y)), y))))); }); testMathyFunction(mathy1, [1/0, Math.PI, 0x080000000, -Number.MIN_VALUE, -(2**53+2), -1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, -0x100000000, -(2**53), 0, 42, 0.000000000000001, 0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -(2**53-2), 0/0, 0x080000001, -0x080000001, 0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 1, -0x080000000, -0, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=1072; tryItOut("\"use strict\"; with({z: this}){print(z); }");
/*fuzzSeed-85495475*/count=1073; tryItOut("mathy5 = (function(x, y) { return mathy3(Math.fround(Math.log10((Math.cosh(((Math.fround((( + y) > Math.fround((0x080000001 * y)))) ? ((Math.clz32(0x080000000) | 0) | 0) : (x | 0)) | 0)) == Math.fround(Math.atan2((Math.min(x, x) , (( ~ (-Number.MAX_VALUE | 0)) | 0)), x))))), (((y ^ x) , mathy2(Math.hypot(y, -0x100000001), x)) % ((Math.imul(Math.log(y), y) >>> 0) === Math.fround((( ! Math.fround((( + (x !== ( + (( + y) ? ( + y) : (y | 0))))) || (x | 0)))) >>> 0))))); }); testMathyFunction(mathy5, [({valueOf:function(){return 0;}}), (new Boolean(false)), 0, (new Number(-0)), [0], [], (new Number(0)), objectEmulatingUndefined(), null, ({valueOf:function(){return '0';}}), 0.1, NaN, '', (new String('')), ({toString:function(){return '0';}}), (new Boolean(true)), /0/, true, '/0/', 1, undefined, '0', (function(){return 0;}), '\\0', -0, false]); ");
/*fuzzSeed-85495475*/count=1074; tryItOut("if((x % 4 == 0)) {print(m1); } else {o1.e1 + ''; }");
/*fuzzSeed-85495475*/count=1075; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ((Math.tanh((Math.fround((( ! x) != Math.log1p(y))) >> (( - x) | 0))) >>> Math.atan2(x, ( - (((y ^ y) | 0) >>> 0)))) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=1076; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4((( + Math.fround((Math.fround(Math.expm1((( + (( + (x >>> 0)) >>> 0)) !== ( + ((-0x100000001 == ( + x)) >>> 0))))) + Math.fround(( + Math.atan2(( + ( ! x)), ( + Math.tan(y)))))))) >>> 0), Math.cos(Math.sin(( + (Math.max((Math.max(y, Math.sqrt(x)) >>> 0), x) >>> 0))))); }); testMathyFunction(mathy5, [0, 1, 0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -0x100000001, 0x080000001, -1/0, -Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, 2**53-2, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, 2**53+2, -0x07fffffff, -0x080000001, 0/0, -(2**53), -0, 2**53, 1/0, -(2**53-2), -0x080000000, -0x100000000, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=1077; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.acosh((Math.clz32(( - ( + ( - x)))) ? Math.fround(Math.imul((((2**53 | 0) , (Math.cbrt(2**53-2) + y)) | 0), ( + x))) : (Math.atan2((( + Math.atanh(( + Math.fround((Math.fround(x) == ( ! ( + 2**53-2))))))) | 0), (( + (y === Math.cbrt(-(2**53+2)))) | 0)) | 0)))); }); testMathyFunction(mathy0, [2**53, -Number.MAX_VALUE, Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -(2**53), -0x07fffffff, -0x100000000, -0x080000000, -0x080000001, -(2**53+2), -(2**53-2), -Number.MAX_SAFE_INTEGER, 1/0, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, 0x080000000, 0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -0x100000001, 2**53+2, 2**53-2, 1, 0x07fffffff, 0x100000000, -0]); ");
/*fuzzSeed-85495475*/count=1078; tryItOut("/*iii*/for (var p in f0) { try { s1 += s1; } catch(e0) { } e1.has(o1); }/*hhh*/function bihtnj(y, x){for (var p in o2) { try { v0 = g2.eval(\"mathy5 = (function(x, y) { return Math.cosh((((Math.max((( - x) | 0), (y | 0)) | 0) % y) ? ((y ** (( + 0x100000001) | 0)) >>> 0) : ( ! Math.fround((((Math.max((y >>> 0), (x >>> 0)) | 0) >>> 0) << (x >>> 0)))))); }); testMathyFunction(mathy5, [2**53, Number.MAX_VALUE, -0x07fffffff, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, Math.PI, Number.MIN_VALUE, 0x07fffffff, -0x100000001, -1/0, -0x080000001, 1, -0x080000000, -Number.MIN_VALUE, 1/0, -0x100000000, -Number.MAX_VALUE, 0x080000001, 2**53-2, 2**53+2, 0, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0, -(2**53+2), 0x100000000, 0x0ffffffff, 1.7976931348623157e308, 42]); \"); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(g0.v2, t1); } catch(e1) { } g1.h1.valueOf = (function(j) { if (j) { try { t1[1]; } catch(e0) { } try { g0.a0.push(p2); } catch(e1) { } try { v1 = (h0 instanceof h0); } catch(e2) { } v1 = a1.length; } else { m0.set(h1, g2); } }); }function NaN(x, z, ...d) { return Math.sinh(-28) } print(x);function \u3056(x, x, x, x = x, x, x, x, y, d, x, eval, c, \u3056,   = [1,,], x, c, \u3056, z, b,  \"\"  = [[1]], x, x, e = this, d = window, x, x =  '' , y, x, x, x, z, x, e, b, eval, w = x, x, x = \"\\uD1CF\", y, e = this.z, x, d, x, x, x, y, \u3056, b, d, x, a, x, c, z, x = \"\\u9A1B\", \u3056 = this, NaN, NaN, b, c = \"\\u5A7B\", get, y, x, x, z, x = length, x, this.x, x = a, x, x, w, \u3056, window, x, x, x, x =  \"\" , a)new RegExp(\"(?=\\\\s)+|(?=[\\\\w]{2,}(?:[^]|$)){0,0}\", \"g\")this.p0 + this.i2;}");
/*fuzzSeed-85495475*/count=1079; tryItOut("\"use strict\"; const x = (void options('strict')), window, x = yield  ''  &&  /x/ , dhvgrz, of = this.__defineSetter__(\"z\", (let (e=eval) e)), eval = (a & x), [] = x.eval(\"print(undefined);\") <=  /x/g , c, \u3056;g0.g2.g1.a2 + e1;");
/*fuzzSeed-85495475*/count=1080; tryItOut("const x =  /x/g ;this.v1 = (h2 instanceof s1);");
/*fuzzSeed-85495475*/count=1081; tryItOut("\"use strict\"; (\u000cthis.__defineGetter__(\"x\", true));");
/*fuzzSeed-85495475*/count=1082; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[new Boolean(false), new Boolean(false), -Infinity, null, window, -Infinity, null, window, null, window, null, -Infinity]) { v0 = new Number(e1); }");
/*fuzzSeed-85495475*/count=1083; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.log(( + Math.min((( - (Math.asinh(Math.atan2(y, ( + mathy0((y >>> 0), (y >>> 0))))) | 0)) | 0), ( + (Math.atan2((( + (( + Math.ceil((y < y))) ? ( + Math.fround(( + y))) : (( + (y | 0)) | 0))) | 0), (x | 0)) | 0))))); }); testMathyFunction(mathy1, [0, -(2**53), 0x0ffffffff, -0x100000001, -0x080000001, 0/0, -0x07fffffff, 42, 2**53-2, Number.MAX_VALUE, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, -Number.MAX_VALUE, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, 1.7976931348623157e308, -0, 1, Number.MIN_VALUE, 0x100000000, -Number.MIN_VALUE, 2**53+2, 0x080000001]); ");
/*fuzzSeed-85495475*/count=1084; tryItOut("\"use asm\"; print(x);\n(-900953565);\n");
/*fuzzSeed-85495475*/count=1085; tryItOut("\"use strict\"; ( /x/g );");
/*fuzzSeed-85495475*/count=1086; tryItOut("\"use strict\"; /*oLoop*/for (myqder = 0; myqder < 96; ++myqder) { throw new RegExp(\"\\\\b\", \"g\"); } ");
/*fuzzSeed-85495475*/count=1087; tryItOut("g1 = this;");
/*fuzzSeed-85495475*/count=1088; tryItOut("v2 = (t0 instanceof o0);");
/*fuzzSeed-85495475*/count=1089; tryItOut("v2 = (h1 instanceof i1);");
/*fuzzSeed-85495475*/count=1090; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + (( + y) >= ( + ( + (( + (Math.trunc((( - (Number.MIN_SAFE_INTEGER >>> 0)) | 0)) | 0)) ? ( + -0x100000001) : ( + x)))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 2**53, 1, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0, -0x080000001, 0x080000000, 0x07fffffff, Number.MIN_VALUE, -0x080000000, -0x100000000, 2**53-2, 0/0, 42, 1/0, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, 0x080000001, -0, 0x100000001, -0x100000001, Math.PI, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1091; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-85495475*/count=1092; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ( ~ (Math.hypot(Math.fround(mathy3(( + (( + x) % ( + x))), Math.fround(0x080000001))), ( + ( ~ (x >>> 0)))) >>> 0))) ** ((((mathy2((((Math.atan2(((( + y) ** ( + x)) >>> 0), (x >>> 0)) >>> 0) != ( + Math.pow(y, y))) | 0), Math.fround(Math.atan2(y, (y < y)))) | 0) ? (mathy3((Math.fround(Math.fround(((x | 0) || (( ! y) | 0)))) | (Math.imul(Math.fround(0x080000000), ( + (y || x))) | 0)), (x >= ( + Math.asin((x >>> 0))))) >>> 0) : (( ~ (Math.fround(Math.fround(Math.fround((Math.atan(((Math.atan2((x >>> 0), (y >>> 0)) >>> 0) | 0)) | 0)))) % Math.fround(mathy0(( + 0x07fffffff), Math.atan2(( + 0x0ffffffff), x))))) | 0)) | 0) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=1093; tryItOut("Array.prototype.shift.apply(a1, []);");
/*fuzzSeed-85495475*/count=1094; tryItOut("let (this.x, eihihy, x = (4277)( '' , 0) >>= allocationMarker(), x =  \"\" (1), bknwre, x = \"\\u0BC8\".throw(/^(?:(?!\\v)|[^]\\s{2})+?/i), x, arguments[\"apply\"] = /(?:\\B{3,})/.valueOf(\"number\"), tttmjo) { /*MXX1*/o1 = g2.Uint8Array; }\u000c");
/*fuzzSeed-85495475*/count=1095; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.fround((Math.log2((( - Number.MAX_VALUE) | 0)) | 0))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 1, -(2**53-2), -0x080000000, -(2**53), 0x07fffffff, 42, -(2**53+2), 1.7976931348623157e308, 2**53-2, -0, 2**53, 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -0x07fffffff, 0.000000000000001, 0x100000001, 0x100000000, 1/0, -1/0, 2**53+2, -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0]); ");
/*fuzzSeed-85495475*/count=1096; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: ~x, enumerable: false,  get: function() {  return r1.test; } });");
/*fuzzSeed-85495475*/count=1097; tryItOut("/*vLoop*/for (mqbaye = 0; mqbaye < 50; ++mqbaye) { c = mqbaye; print(/[^\\W\\cA-\\u2078\\W\\S]+?/); } ");
/*fuzzSeed-85495475*/count=1098; tryItOut("let (e) { ((function ([y]) { })());( /x/g ); }");
/*fuzzSeed-85495475*/count=1099; tryItOut("\"use strict\"; h0 = s0;");
/*fuzzSeed-85495475*/count=1100; tryItOut("/*tLoop*/for (let c of /*MARR*/[x, x, x, -0x080000001, -0x080000001,  /x/ , x,  /x/ , -0x080000001]) { var \u3056 = (4277), c = ({}), c, x = /*MARR*/[new Number(1.5), -0x07fffffff, new Number(1.5), null, null, new Number(1.5), -0x07fffffff, new Number(1.5), null, null, new Number(1.5), null, new Number(1.5), new Number(1.5), \"\\u8A09\", \"\\u8A09\", new Number(1.5), -0x07fffffff].some(function(q) { \"use strict\"; return q; }, \"\\u2A19\"), x = (4277), a = ( , /*RXUE*/new RegExp(\"(?=[^])|(?!.)?[^\\\\v-\\\\xd7\\\\cZ]\\\\\\u00b8{1,3}+{1,}\", \"y\").exec(\"\"));t2.set(a2, 18); }");
/*fuzzSeed-85495475*/count=1101; tryItOut("neuter(b1, \"same-data\");");
/*fuzzSeed-85495475*/count=1102; tryItOut("a2.push(o0);");
/*fuzzSeed-85495475*/count=1103; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(mathy4(Math.fround(Math.sin((x && Math.pow(( + ( ! ( + (( + x) * x)))), (Math.imul((Math.sinh(Math.fround(-0x080000001)) >>> 0), Number.MIN_VALUE) >>> 0))))), ((Math.hypot(((Math.max((( ~ mathy0(x, -Number.MIN_VALUE)) >>> 0), (Math.min((y >>> 0), y) >>> 0)) >>> 0) ** (((x <= (x | 0)) | 0) / ( + -0x100000001))), Math.fround(((x ? (x | 0) : (42 | 0)) << ( ~ y)))) <= (Math.log10(Math.hypot(2**53+2, x)) >>> 0)) | 0))); }); testMathyFunction(mathy5, [0, 42, 2**53-2, -0x080000000, 1.7976931348623157e308, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, 0/0, -0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -0, -1/0, 0x080000001, Number.MIN_VALUE, 0x100000000, 2**53, -0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 1, Number.MAX_VALUE, 1/0, -(2**53+2), -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=1104; tryItOut("\"use strict\"; x = i1;\nvar zwwaxo = new ArrayBuffer(0); var zwwaxo_0 = new Int8Array(zwwaxo); print(zwwaxo_0[0]); ;\n");
/*fuzzSeed-85495475*/count=1105; tryItOut("\"use strict\"; print(x);\n(27);\n/*RXUB*/var r = o2.r0; var s = s1; print(s.split(r)); ");
/*fuzzSeed-85495475*/count=1106; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan(( + Math.trunc((( + ( + mathy2(Math.expm1((x >>> 0)), y))) > ( + ( + ( - -Number.MIN_VALUE))))))); }); testMathyFunction(mathy4, [1, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0x100000001, -0x100000001, 42, -0x0ffffffff, -Number.MIN_VALUE, -0, 0, 2**53, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, 0x07fffffff, 2**53+2, 0x100000000, -0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, Number.MIN_VALUE, -(2**53-2), -0x080000000, -0x080000001, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-85495475*/count=1107; tryItOut("mathy4 = (function(x, y) { return Math.sign((Math.acos(Math.fround(mathy3(Math.fround((Math.tanh(-Number.MAX_SAFE_INTEGER) >>> 0)), Math.fround(( + (( + (Math.sinh((Math.min(Math.tanh(x), x) | 0)) >>> 0)) / ( + Math.atan(Math.imul(((x ? y : x) | 0), (y >>> -0x080000001)))))))))) | 0)); }); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), -0, (function(){return 0;}), 0, [], /0/, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), '/0/', (new Boolean(false)), 0.1, NaN, '\\0', (new String('')), (new Number(-0)), 1, (new Number(0)), '0', '', false, undefined, [0], true, (new Boolean(true)), null, objectEmulatingUndefined()]); ");
/*fuzzSeed-85495475*/count=1108; tryItOut("v2.valueOf = (function() { for (var j=0;j<0;++j) { f1(j%3==0); } });");
/*fuzzSeed-85495475*/count=1109; tryItOut("\"use strict\"; o2.g1.h0 = ({getOwnPropertyDescriptor: function(name) { Object.defineProperty(this, \"h1\", { configurable: false, enumerable: (x % 12 != 3),  get: function() {  return ({getOwnPropertyDescriptor: function(name) { this.v1 = (e1 instanceof this.a1);; var desc = Object.getOwnPropertyDescriptor(o0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { for (var p in i2) { try { print(b0); } catch(e0) { } try { o1.g0.offThreadCompileScript(\"return (objectEmulatingUndefined);\"); } catch(e1) { } selectforgc(g2.o0); }; var desc = Object.getPropertyDescriptor(o0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v2 = -Infinity;; Object.defineProperty(o0, name, desc); }, getOwnPropertyNames: function() { for (var v of b1) { try { Array.prototype.push.apply(a2, [i2]); } catch(e0) { } try { v2 = r2.compile; } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(o1.t2, o2.b1); } catch(e2) { } Object.defineProperty(this, \"h1\", { configurable: false, enumerable: (x % 2 != 1),  get: function() {  return ({getOwnPropertyDescriptor: function(name) { Array.prototype.reverse.call(a0);; var desc = Object.getOwnPropertyDescriptor(o1.g1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { this.g1.v0 = evaluate(\"function f1(v0)  { return /*FARR*/[[1],  \\\"\\\" , {}, , ...[], c, new RegExp(\\\"(?:(?!.)(?![]){1,5}){0}\\\", \\\"gy\\\"), ...[],  \\\"\\\" , \\u3056, new RegExp(\\\"(?:^|.+$+?|(?!\\\\\\\\W|\\\\\\\\b$)*?|\\\\uddfe|(?:\\\\\\\\b)+)\\\", \\\"gy\\\"),  /x/ , ...[], c, -8, , 0.09, ...[]].map } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 22 != 4) }));; var desc = Object.getPropertyDescriptor(o1.g1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { neuter(b1, \"change-data\");; Object.defineProperty(o1.g1, name, desc); }, getOwnPropertyNames: function() { Array.prototype.push.apply(a1, [o2.m1, s1]);; return Object.getOwnPropertyNames(o1.g1); }, delete: function(name) { print(i1);; return delete o1.g1[name]; }, fix: function() { Array.prototype.shift.apply(a1, [this.o0, e0]);; if (Object.isFrozen(o1.g1)) { return Object.getOwnProperties(o1.g1); } }, has: function(name) { for (var v of t0) { try { i2.toString = (function() { v2 = new Number(a0); return m1; }); } catch(e0) { } try { v2 = true; } catch(e1) { } for (var p in o1.s2) { try { v2 = Object.prototype.isPrototypeOf.call(f0, v2); } catch(e0) { } try { f1 + ''; } catch(e1) { } t1.set(a0, o1.v1); } }; return name in o1.g1; }, hasOwn: function(name) { /*MXX1*/o1 = g2.String.prototype.fixed;; return Object.prototype.hasOwnProperty.call(o1.g1, name); }, get: function(receiver, name) { Array.prototype.forEach.call(a1, (function() { try { x = o1; } catch(e0) { } a0[19]; return s2; }));; return o1.g1[name]; }, set: function(receiver, name, val) { b1.toSource = (function() { try { v0 = evaluate(\"print(x);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: undefined, sourceIsLazy: true, catchTermination: true })); } catch(e0) { } Object.preventExtensions(h0); return v0; });; o1.g1[name] = val; return true; }, iterate: function() { /*MXX1*/o0 = g0.Set.prototype.forEach;; return (function() { for (var name in o1.g1) { yield name; } })(); }, enumerate: function() { o2.s1 += s1;; var result = []; for (var name in o1.g1) { result.push(name); }; return result; }, keys: function() { throw a0; return Object.keys(o1.g1); } }); } }); }; return Object.getOwnPropertyNames(o0); }, delete: function(name) { b0 + v0;; return delete o0[name]; }, fix: function() { m0.valueOf = (function() { m0.set(a1, ((function sum_slicing(rtcrxp) { ; return rtcrxp.length == 0 ? 0 : rtcrxp[0] + sum_slicing(rtcrxp.slice(1)); })(/*MARR*/[]))); return this.t0; });; if (Object.isFrozen(o0)) { return Object.getOwnProperties(o0); } }, has: function(name) { h0.__proto__ = o0;; return name in o0; }, hasOwn: function(name) { for (var p in p1) { try { m2.set(v0, m2); } catch(e0) { } try { g2.v1 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 6 != 1), catchTermination: var korzdt = new ArrayBuffer(8); var korzdt_0 = new Int32Array(korzdt); korzdt_0[0] = -19; var korzdt_1 = new Uint32Array(korzdt); korzdt_1[0] = -20; print(korzdt_0[0]);const s1 = new String;, element: o1, sourceMapURL: s0 })); } catch(e1) { } for (var p in h1) { print(v0); } }; return Object.prototype.hasOwnProperty.call(o0, name); }, get: function(receiver, name) { m0.delete(this.o0.f0);; return o0[name]; }, set: function(receiver, name, val) { v1 = Object.prototype.isPrototypeOf.call(h0, i1);; o0[name] = val; return true; }, iterate: function() { v0 = (e1 instanceof v1);; return (function() { for (var name in o0) { yield name; } })(); }, enumerate: function() { v0 = Object.prototype.isPrototypeOf.call(b1, e0);; var result = []; for (var name in o0) { result.push(name); }; return result; }, keys: function() { t1[5] = new (Object.defineProperty\n(window, \"toUpperCase\", ({configurable: false, enumerable: false})))();; return Object.keys(o0); } }); } });; var desc = Object.getOwnPropertyDescriptor(f2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { for (var v of f0) { try { for (var p in m1) { try { this.m0.toSource = (function() { try { i2 + ''; } catch(e0) { } neuter(b2, \"change-data\"); return t2; }); } catch(e0) { } try { s0 += g0.s2; } catch(e1) { } a0.pop(); } } catch(e0) { } try { for (var p in f2) { try { h1.toString = (function() { for (var j=0;j<128;++j) { f0(j%5==1); } }); } catch(e0) { } try { a1.splice(2, 9); } catch(e1) { } try { this.v0 = Object.prototype.isPrototypeOf.call(b1, h0); } catch(e2) { } for (var p in g1.s2) { try { e0.has(o1.b1); } catch(e0) { } try { o1.v2 = true; } catch(e1) { } try { a1 = a2.slice(12, 11); } catch(e2) { } var f1 = Proxy.createFunction(h2, f2, f0); } } } catch(e1) { } p2.valueOf = f0; }; var desc = Object.getPropertyDescriptor(f2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { return p1; Object.defineProperty(f2, name, desc); }, getOwnPropertyNames: function() { for (var p in h1) { a2.forEach((function() { for (var j=0;j<16;++j) { o1.f0(j%2==1); } }), b1, this.b0, p0, b0); }; return Object.getOwnPropertyNames(f2); }, delete: function(name) { a1 + m2;; return delete f2[name]; }, fix: function() { g1.offThreadCompileScript(\"a1.shift(s1, t2);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 2 == 1), noScriptRval: (b = timeout(1800)), sourceIsLazy: false, catchTermination: (x % 5 != 2) }));; if (Object.isFrozen(f2)) { return Object.getOwnProperties(f2); } }, has: function(name) { ;; return name in f2; }, hasOwn: function(name) { v1 = t1.length;; return Object.prototype.hasOwnProperty.call(f2, name); }, get: function(receiver, name) { throw t0; return f2[name]; }, set: function(receiver, name, val) { v0 = t1.length;; f2[name] = val; return true; }, iterate: function() { var v2 = g2.runOffThreadScript();; return (function() { for (var name in f2) { yield name; } })(); }, enumerate: function() { return this.h1; var result = []; for (var name in f2) { result.push(name); }; return result; }, keys: function() { v1 = null;; return Object.keys(f2); } });");
/*fuzzSeed-85495475*/count=1110; tryItOut("m2.has(g1);");
/*fuzzSeed-85495475*/count=1111; tryItOut("print(x);");
/*fuzzSeed-85495475*/count=1112; tryItOut("a1[v2];");
/*fuzzSeed-85495475*/count=1113; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1114; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - (Math.max((mathy0(( + (Math.sqrt((x | 0)) | 0)), (( ! (mathy0(-0x100000000, ( - y)) >>> 0)) >>> 0)) >>> 0), (Math.hypot(Math.tanh(( + Math.atan((Math.log10(y) >>> 0)))), x) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), x.unwatch(\"getFloat64\"), 5.0000000000000000000000, new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-85495475*/count=1115; tryItOut("testMathyFunction(mathy2, [-0x07fffffff, 0x0ffffffff, 1/0, Number.MAX_VALUE, -0x0ffffffff, Math.PI, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, -0x100000000, -0, 0.000000000000001, 0x080000001, 0x100000001, -1/0, 1, 0x080000000, -0x100000001, -(2**53-2), Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 2**53, 42, 0x100000000, 0, -Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1116; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.cbrt(Math.imul(( - ( ~ (( ~ x) >>> 0))), Math.cbrt(Math.min(Math.sinh(y), ( ''  ? -1/0 : Math.fround(( + Math.fround(y))))))))); }); ");
/*fuzzSeed-85495475*/count=1117; tryItOut("f0(g1.b2);");
/*fuzzSeed-85495475*/count=1118; tryItOut("\"use strict\"; \"use asm\"; v1 = Object.prototype.isPrototypeOf.call(a1, o1);");
/*fuzzSeed-85495475*/count=1119; tryItOut("\"use strict\"; const b;g1.s1 += s1;");
/*fuzzSeed-85495475*/count=1120; tryItOut("mathy0 = (function(x, y) { return (Math.max((Math.atan2(Math.fround(Math.atan2(Math.max(Math.fround(x), Math.acosh(x)), ( + y))), Math.max(( + ( ! y)), ( + ( ~ ( + ( + (Math.fround(x) - Math.fround(-Number.MIN_VALUE)))))))) | 0), (( + ( ~ ( + ( - (-(2**53-2) | 0))))) ? (((Math.log10(( + ( ~ ((y ? Math.fround(x) : (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)))) >>> 0) !== (y | 0)) | 0) : Math.pow(( + ( + Math.fround(y))), y))) >>> 0); }); ");
/*fuzzSeed-85495475*/count=1121; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.hypot((Math.fround(Math.pow(Math.log2(Math.sinh(Math.asinh(x))), (Math.tan((x | 0)) | 0))) | 0), Math.asin(Math.fround(Math.atan2((Math.tanh((x | 0)) | 0), Math.imul(x, x)))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53), 1.7976931348623157e308, -Number.MAX_VALUE, -0x100000000, 1/0, Math.PI, 1, 0x100000001, Number.MAX_SAFE_INTEGER, -1/0, -(2**53+2), 2**53+2, 42, Number.MAX_VALUE, 0x080000001, 0.000000000000001, -Number.MIN_VALUE, 2**53-2, -0x100000001, -0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0x080000000, -0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0/0, Number.MIN_VALUE, -0x07fffffff, 0, -(2**53-2), 2**53]); ");
/*fuzzSeed-85495475*/count=1122; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.max(Math.fround(( + (((mathy0(y, 2**53-2) | 0) - Math.fround(Math.atanh(Math.fround(0x100000001)))) | 0))), (mathy0(Math.fround(( + (Math.fround(x) ? Math.atan2(Math.ceil(x), Math.max(( ! y), y)) : Math.fround(( - ( + y)))))), ( - Math.clz32(Math.asinh(x)))) | 0)) | 0); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 0x100000000, -0, Math.PI, Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, 2**53+2, 0x0ffffffff, -1/0, 0/0, -0x0ffffffff, 1, -Number.MIN_VALUE, 0x080000000, 2**53-2, -0x080000000, -(2**53+2), -0x100000001, -0x080000001, 0x07fffffff, 2**53, 0]); ");
/*fuzzSeed-85495475*/count=1123; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2(Math.fround(((Math.fround(Math.hypot((((x >>> 0) ^ Math.fround(( ! Math.fround((( ! (x | 0)) >>> 0))))) | 0), y)) >>> 0) % ( + ( ! Math.max((Math.min((( - Number.MIN_VALUE) | 0), (Math.acos((Math.log2(Math.fround(x)) >>> 0)) | 0)) | 0), y))))), Math.fround((Math.fround(((x ^ -0x0ffffffff) == Math.fround(Math.max(( + (x ? y : 0x080000000)), Math.min(x, ((Math.clz32(x) | 0) > Math.fround(y))))))) ? mathy0(42, ( + (( + ( - x)) >>> (( + Math.atan2(( ~ x), y)) | 0)))) : (Math.hypot(x, (Math.atan(mathy2(x, y)) ** x)) , y))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000000, -0x100000001, 2**53, 0, -(2**53-2), 0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, 42, 2**53-2, -0x100000000, Math.PI, 0.000000000000001, 0x07fffffff, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, 1.7976931348623157e308, -(2**53+2), -0, 2**53+2, 0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 0/0]); ");
/*fuzzSeed-85495475*/count=1124; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.min(( + Math.fround((Math.fround(Math.ceil(x)) ? Math.fround(x) : (( + ( ! (Math.imul((x | 0), y) | 0))) ? ( + Math.fround(Math.min(Math.fround(y), Math.fround(mathy2(Math.fround(y), ( + ((y && y) | 0))))))) : Math.acosh(mathy3(( + x), ((y !== (x | 0)) ? y : y))))))), Math.atanh((mathy1(x, Math.imul((Math.pow(y, Math.acosh(x)) >>> 0), ((Math.hypot(Math.fround(Number.MAX_VALUE), -Number.MIN_VALUE) | 0) | 0))) + Math.cos(( + Math.acosh(( + y))))))); }); testMathyFunction(mathy4, [true, (new Number(-0)), '0', (new Boolean(false)), -0, (new String('')), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '/0/', ({valueOf:function(){return 0;}}), null, 0, undefined, /0/, NaN, '\\0', [], false, [0], (new Boolean(true)), 1, ({toString:function(){return '0';}}), 0.1, '', (function(){return 0;}), (new Number(0))]); ");
/*fuzzSeed-85495475*/count=1125; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.asin(( + Math.min(( + x), y)))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, -Number.MIN_SAFE_INTEGER, 0, 2**53+2, 0x100000000, 0/0, -(2**53+2), -0x080000001, -(2**53), -0x0ffffffff, Math.PI, Number.MIN_VALUE, 0.000000000000001, 1, 0x0ffffffff, 0x100000001, -Number.MIN_VALUE, -0x100000000, -1/0, Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, -0x080000000, 42, 2**53-2, 1.7976931348623157e308, -(2**53-2), 0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-85495475*/count=1126; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.log((Math.cosh((function(a0, a1, a2, a3, a4, a5) { var r0 = 9 | a5; a1 = 0 % a4; var r1 = 9 | r0; r0 = a2 ^ a3; r0 = a1 / 5; var r2 = x - 1; var r3 = 8 ^ 4; var r4 = r2 * r0; var r5 = 4 % y; var r6 = a4 & y; var r7 = r2 + r1; r5 = 9 % r2; var r8 = r6 % x; var r9 = x % r4; x = a3 - 3; var r10 = 5 & r3; var r11 = r1 - 5; a4 = a5 % a5; var r12 = r9 + a1; var r13 = r2 - r8; var r14 = r9 % r5; print(a0); print(a5); var r15 = a5 - a1; var r16 = r8 - 9; var r17 = 0 / a1; var r18 = r16 / r6; var r19 = a4 ^ 4; var r20 = r12 % r10; r16 = 4 + r8; var r21 = 1 - 8; var r22 = r11 + 9; var r23 = a4 % a5; a5 = 0 / r16; a4 = r16 % a3; var r24 = r19 / r11; r6 = r19 / a1; a2 = r13 * 8; r5 = r13 / x; var r25 = a2 - 0; print(r1); a2 = x + a5; var r26 = r12 * x; var r27 = r23 * 1; y = a5 * r25; var r28 = r26 + r16; var r29 = r10 - 4; var r30 = r11 + r6; var r31 = 3 & 9; print(r23); var r32 = r29 + r14; var r33 = x & r22; var r34 = r2 % 0; var r35 = 6 % a4; var r36 = 9 / r5; r31 = 2 + 9; r15 = r2 | r11; var r37 = r5 + 2; var r38 = r11 / 3; var r39 = 1 + a1; var r40 = 4 / r28; var r41 = r7 % r10; var r42 = 7 ^ r26; var r43 = r14 * 3; var r44 = 3 * r36; var r45 = r41 & r5; var r46 = r21 + r36; var r47 = r41 ^ r43; var r48 = r27 * r40; var r49 = r11 + 0; var r50 = r24 & 7; r17 = r41 & 4; var r51 = r3 & r0; var r52 = 0 + r30; r31 = r22 / r49; var r53 = r20 / 3; print(r10); var r54 = r6 / 7; var r55 = a5 * r49; var r56 = r49 / 2; var r57 = 3 - r25; var r58 = r51 % r14; r28 = r2 * 4; var r59 = r28 & 6; var r60 = r28 + r7; r33 = 8 % r55; r5 = r10 - r34; var r61 = 7 & 2; r50 = r35 ^ r11; var r62 = r57 * r47; r42 = r16 - r12; var r63 = 0 - 3; var r64 = 5 * r16; var r65 = 5 + r20; var r66 = r38 ^ a2; var r67 = r35 - a5; var r68 = a0 + r39; var r69 = r30 * r66; var r70 = 5 | r19; var r71 = r11 - r5; r51 = x * r64; var r72 = 4 / r38; var r73 = r64 - 7; var r74 = 6 % r24; var r75 = r24 * r21; r46 = r55 & 1; r65 = 4 + 5; var r76 = r5 + 3; r57 = r41 * r42; var r77 = r21 % r16; var r78 = r62 + r48; var r79 = r51 - r66; r15 = 8 | 4; r51 = r25 / 9; print(a0); var r80 = r13 * r42; var r81 = r18 & r9; r1 = r59 - r50; var r82 = r15 % r9; var r83 = r66 * r37; var r84 = 4 & r32; var r85 = r9 / r49; var r86 = r59 | 8; print(a2); r83 = x & 7; print(r27); var r87 = 0 | r72; var r88 = r11 & r62; var r89 = r47 % r82; r4 = 8 ^ r79; var r90 = 6 % r49; var r91 = r86 & 4; return a0; })) >>> 0)); }); testMathyFunction(mathy4, [-(2**53), 1, -0x07fffffff, 2**53-2, 2**53, -0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1/0, Math.PI, 0x0ffffffff, 0.000000000000001, -0x080000001, 42, 2**53+2, 0x100000000, -(2**53-2), -1/0, 0x080000001, -0x0ffffffff, -0x100000000, 0, 0x080000000, 0x100000001, -0x100000001, 0/0, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=1127; tryItOut("\"use strict\"; Object.defineProperty(this.o0, \"g0.v1\", { configurable: (x % 6 != 2), enumerable: (x % 6 == 2),  get: function() {  return t2.length; } });");
/*fuzzSeed-85495475*/count=1128; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-85495475*/count=1129; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1130; tryItOut("/*infloop*/\u0009for(let e; this; \"\\u23C8\") print(e);");
/*fuzzSeed-85495475*/count=1131; tryItOut("a2.forEach(f2);");
/*fuzzSeed-85495475*/count=1132; tryItOut("mathy1 = (function(x, y) { return (((( ~ Math.fround(mathy0(( + Math.pow(y, Math.fround(( + Math.fround(mathy0(x, ( + y))))))), Math.fround(x)))) | 0) ? ((x.__defineGetter__(\"x\", Function)) | 0) : ((Math.exp(Math.min(Math.fround(Math.imul((Math.fround(( + x)) >>> 0), Math.fround((((y | 0) + (y | 0)) | 0)))), Math.fround(( - ( + x))))) * ( + (Math.fround(( ! Math.PI)) >>> ( + x)))) | 0)) | 0); }); ");
/*fuzzSeed-85495475*/count=1133; tryItOut("mathy5 = (function(x, y) { return ( - mathy1(Math.max((( - ( ~ ( + ( ! ( + -0x080000000))))) | 0), Math.asinh(Math.fround(Math.atan2(y, Math.fround((Math.fround(y) | Math.fround(x))))))), Math.atan2(Math.fround(Math.cos(Math.fround((y % 2**53+2)))), x))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 1, 0x100000001, 2**53, Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, Number.MIN_VALUE, 0x080000000, 0, Math.PI, 0x080000001, 0x0ffffffff, -Number.MIN_VALUE, -0x100000001, -(2**53-2), 0x07fffffff, 1.7976931348623157e308, -0x100000000, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -Number.MAX_VALUE, 2**53-2, -0x0ffffffff, 0.000000000000001, -(2**53+2), -0, 2**53+2, -0x080000001, -1/0, 1/0, 42]); ");
/*fuzzSeed-85495475*/count=1134; tryItOut("a0.forEach((function() { try { Array.prototype.splice.call(a0, 1, (4277).__defineGetter__(\"eval\", (x - x)) %= new Number(1.5)); } catch(e0) { } try { m0.has(this.v1); } catch(e1) { } a1.pop(); return g2.m0; }), g2, s1);");
/*fuzzSeed-85495475*/count=1135; tryItOut("m1.delete(i0);");
/*fuzzSeed-85495475*/count=1136; tryItOut("mathy3 = (function(x, y) { return Math.max((( ~ (mathy1(mathy0(x, Math.fround(x)), (( - ( + (Math.max((y >>> 0), (x >>> 0)) >>> 0))) < y)) >>> 0)) | 0), (mathy2(Math.fround(( ~ ( + ( + ( ! ( + ((y >>> 0) + (x >>> 0)))))))), Math.fround(Math.max(y, Math.fround(Math.cos(y))))) | 0)); }); testMathyFunction(mathy3, [-1/0, -0x100000001, -(2**53+2), 0, 2**53-2, -(2**53-2), 2**53, 0x100000001, 1.7976931348623157e308, -0, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 1/0, 0x07fffffff, -0x07fffffff, 42, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, -0x080000001, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, 0x0ffffffff, 1, 0/0]); ");
/*fuzzSeed-85495475*/count=1137; tryItOut("i0.toString = (function() { try { f1 = (function(j) { if (j) { m2 + i2; } else { try { g0.g2.v1 = evaluate(\"/*MXX1*/o2 = g0.RegExp.$+;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 74 == 54), noScriptRval: d == window, sourceIsLazy: false, catchTermination: (x % 99 == 34) })); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { e0.has(o1); } catch(e2) { } m0.set(m0, e1); } }); } catch(e0) { } try { t1.set(this.t0, 15); } catch(e1) { } v2 = evalcx(\"e\", g2); return f0; });");
/*fuzzSeed-85495475*/count=1138; tryItOut("\"use strict\"; t2.__iterator__ = (function mcc_() { var cqwhis = 0; return function() { ++cqwhis; if (/*ICCD*/cqwhis % 4 == 0) { dumpln('hit!'); try { v0 = (o0 instanceof o0.m0); } catch(e0) { } try { t2.__proto__ = v1; } catch(e1) { } /*MXX1*/o2 = g1.Uint32Array.prototype.BYTES_PER_ELEMENT; } else { dumpln('miss!'); try { Array.prototype.shift.apply(a1, []); } catch(e0) { } try { t2[2]; } catch(e1) { } m2.get(this.g2); } };})();");
/*fuzzSeed-85495475*/count=1139; tryItOut("m2.set(p1, i1);\nprint(x)\n");
/*fuzzSeed-85495475*/count=1140; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.sign(( + Math.log(Math.atan2(y, x)))); }); testMathyFunction(mathy2, [-0x080000000, -0, 0x080000001, -(2**53+2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 0x100000001, -0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, 2**53+2, -1/0, -0x100000001, 1, 42, -(2**53), 0.000000000000001, -0x080000001, -0x07fffffff, 1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 0, 0x100000000]); ");
/*fuzzSeed-85495475*/count=1141; tryItOut("mathy0 = (function(x, y) { return Math.imul(((( + Math.fround((Math.min((Math.fround(Math.imul((x | 0), x)) >>> 0), (y >>> 0)) | 0))) % Math.trunc(( - y))) <= Math.pow(y, x)), Math.abs(((Math.fround(( ! Math.fround(x))) == (Math.log1p(0x100000000) & ( - Math.fround(y)))) >>> 0))); }); testMathyFunction(mathy0, [0, -(2**53), -0x080000001, -0x07fffffff, -0, 2**53, -0x080000000, -(2**53-2), 1/0, -0x100000000, -0x100000001, 0/0, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_VALUE, 42, -Number.MAX_VALUE, 2**53-2, 1, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 0x100000000, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, -1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-85495475*/count=1142; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let c of /*MARR*/[x, x, x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]) { if(true) {h1.get = f0; } else  if ( \"\" ) {print(x); } }");
/*fuzzSeed-85495475*/count=1143; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( + ((((Math.fround((Math.fround(x) | y)) | 0) ? (mathy0(y, -Number.MAX_SAFE_INTEGER) | 0) : (y | 0)) | 0) >>> 0)) % (mathy1((((Math.asinh((y | 0)) , ( ! Math.log1p(Number.MIN_SAFE_INTEGER))) >> (Math.tan((x >>> 0)) >>> 0)) >>> 0), ((( + x) == Math.fround(Math.hypot(Math.hypot((y | 0), (Math.fround(x) | 0)), ( + x)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 0, 1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -0x080000001, -0x080000000, -(2**53-2), 0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -(2**53), 0x0ffffffff, 42, 2**53+2, 2**53, 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, -0x100000001, Math.PI, -1/0, -0x0ffffffff, 1, Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=1144; tryItOut("/*infloop*/for(let (y) in new \"\\uB73E\"(\"\\u57BA\",  /x/ )) for (var p in o2) { try { v1 = Object.prototype.isPrototypeOf.call(p1, f2); } catch(e0) { } try { s2 = new String(i2); } catch(e1) { } Object.defineProperty(this, \"s2\", { configurable: (x % 4 == 1), enumerable: (x % 5 == 0),  get: function() {  return new String; } }); }");
/*fuzzSeed-85495475*/count=1145; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + mathy1(( + (( + ( - ( + (((y >>> 0) << (x >>> 0)) >>> 0)))) / Math.hypot(( + ( - Math.tanh(x))), ( ~ x)))), ( + Math.fround(( ! Math.fround(( ! Math.hypot((Math.tanh(x) | 0), Math.atan2(x, ( + Math.min(( + x), ( + x)))))))))))); }); testMathyFunction(mathy4, [false, true, '/0/', /0/, [0], ({valueOf:function(){return 0;}}), '0', (new String('')), (new Boolean(false)), 1, undefined, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), 0, ({toString:function(){return '0';}}), NaN, -0, (new Number(-0)), '\\0', '', (new Number(0)), (new Boolean(true)), null, [], 0.1, (function(){return 0;})]); ");
/*fuzzSeed-85495475*/count=1146; tryItOut("g2.v1 = evaluate(\"/* no regression tests found */\", ({ global: g0.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 == 1), noScriptRval: ('fafafa'.replace(/a/g, (function(y) { \"use strict\"; throw ({a1:1}); }).apply)), sourceIsLazy: true, catchTermination: (x % 41 != 9) }));");
/*fuzzSeed-85495475*/count=1147; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ~ ((Math.log1p((( + (( + x) ? (x ? y : x) : ( + ( + Math.atanh(( + Number.MAX_SAFE_INTEGER)))))) <= Math.fround(-(2**53)))) / Math.log(y)) >>> 0)) != Math.fround((Math.fround(((( + x) || (( + ( - ( + Math.trunc(((x | 0) % y))))) | 0)) | 0)) - Math.fround(( + Math.hypot(( + ((Math.fround((Math.fround(-Number.MAX_SAFE_INTEGER) * Math.fround(Math.max(x, y)))) | 0) ? Math.fround(Math.asin(( + y))) : (Math.fround(Math.trunc((y >>> 0))) | 0))), ( + Number.MAX_VALUE))))))); }); ");
/*fuzzSeed-85495475*/count=1148; tryItOut("m1 = new Map;");
/*fuzzSeed-85495475*/count=1149; tryItOut("\"use strict\"; print(new function shapeyConstructor(bzaagt){this[\"sup\"] = new String('q');Object.defineProperty(this, \"sup\", ({}));return this; }());");
/*fuzzSeed-85495475*/count=1150; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((( ! (((Math.max(x, y) >>> 0) == (Math.max((Math.pow(0/0, -0x100000000) >>> 0), x) >>> 0)) >>> 0)) | 0) << ( - (Math.log10((Math.cbrt((y ^ y)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-0, (new Number(0)), '/0/', '0', 0, (new String('')), null, 1, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), '\\0', (new Boolean(false)), '', [0], ({valueOf:function(){return 0;}}), undefined, (function(){return 0;}), NaN, [], true, (new Number(-0)), /0/, ({toString:function(){return '0';}}), 0.1, false, (new Boolean(true))]); ");
/*fuzzSeed-85495475*/count=1151; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[ '\\0' , new Number(1), new Number(1), --y,  '\\0' , new Number(1), new Number(1), --y, new Number(1), new Number(1),  '\\0' ,  '\\0' ,  '\\0' , new Number(1), new Number(1),  '\\0' , --y, --y,  '\\0' , --y,  '\\0' ,  '\\0' , new Number(1),  '\\0' ,  '\\0' , new Number(1),  '\\0' , --y, new Number(1), new Number(1), --y,  '\\0' ,  '\\0' , --y,  '\\0' ,  '\\0' ,  '\\0' , --y,  '\\0' ,  '\\0' ,  '\\0' , --y, new Number(1),  '\\0' , new Number(1),  '\\0' ,  '\\0' , --y,  '\\0' , --y,  '\\0' , --y, new Number(1), new Number(1), new Number(1), new Number(1),  '\\0' ]) { a0 = a2.slice(NaN, NaN, o2.e0, t0, a0, i2); }");
/*fuzzSeed-85495475*/count=1152; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=1153; tryItOut("\"use strict\"; m2.set(h2, i2);function x(\u3056, b, ...26) { return \u0009/*FARR*/[let (a) window, [1], .../*MARR*/[Infinity, 5.0000000000000000000000, Infinity, -(2**53), x, Infinity, Infinity, 5.0000000000000000000000, 5.0000000000000000000000, x, x, null, -(2**53), Infinity, x, -(2**53), null, 5.0000000000000000000000, -(2**53), null, 5.0000000000000000000000, Infinity, 5.0000000000000000000000, null, 5.0000000000000000000000, -(2**53), 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, null, null, null, 5.0000000000000000000000, Infinity, 5.0000000000000000000000, -(2**53), Infinity, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, x, Infinity, null, Infinity, null, x, Infinity, Infinity, null, -(2**53), Infinity, x, null], this.x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: (1 for (x in [])), has: function() { return false; }, hasOwn: Date.prototype.setUTCMilliseconds, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { return []; }, }; })( '' ), Object.defineProperty), x, .../*FARR*/[.../*FARR*/[, x, new (({x: window }))((x = \"\\u1826\")), x, null, , x, -0\u000d > false, /*UUV2*/(c.normalize = c.log10), x, ({a1:1})], ]].sort(String.prototype.split) } /*oLoop*/for (let uvennc = 0; uvennc < 28; ++uvennc) { print(x); } ");
/*fuzzSeed-85495475*/count=1154; tryItOut("m1.get(this.f1);");
/*fuzzSeed-85495475*/count=1155; tryItOut("\"use asm\"; print(this.o0.b2);");
/*fuzzSeed-85495475*/count=1156; tryItOut("Object.prototype.unwatch.call(a0, \"y\");");
/*fuzzSeed-85495475*/count=1157; tryItOut("\"use strict\"; let(x) { let(x = \"\\uECF3\", \u3056, z = (([]) = null), window, {} = z !== x, x, eval, xhrcsx) ((function(){throw StopIteration;})());}");
/*fuzzSeed-85495475*/count=1158; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.expm1(((Math.sqrt((( ! ( + Math.atan2((Math.atan2((-0x080000000 >>> 0), y) | 0), ( + 1.7976931348623157e308)))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, [-(2**53+2), Math.PI, -(2**53), -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, -0x080000000, 0x080000000, 1/0, 42, -1/0, Number.MAX_VALUE, 0x100000001, 1, 0x07fffffff, 0x0ffffffff, 0.000000000000001, -0, -(2**53-2), -0x0ffffffff, -0x100000000, 0x080000001, Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, -Number.MAX_VALUE, -0x07fffffff, 0/0, 0]); ");
/*fuzzSeed-85495475*/count=1159; tryItOut("Object.defineProperty(this, \"m0\", { configurable: allocationMarker(), enumerable: (x % 6 != 0),  get: function() { this.a0.pop(); return new WeakMap; } });");
/*fuzzSeed-85495475*/count=1160; tryItOut("v2 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-85495475*/count=1161; tryItOut("s1 + e0;");
/*fuzzSeed-85495475*/count=1162; tryItOut("({toString: \"\\u75AE\", /*toXFun*/toString: function() { return this; } });\nprint(g1);\n\nArray.prototype.push.call(a2, g2.v1, v2, p0, i1);\n");
/*fuzzSeed-85495475*/count=1163; tryItOut("\"use strict\"; o0.i1.next();");
/*fuzzSeed-85495475*/count=1164; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; verifyprebarriers(); } void 0; }");
/*fuzzSeed-85495475*/count=1165; tryItOut("\"use strict\"; if(true) {print(uneval(g2));o2.v2 = undefined; } else switch((makeFinalizeObserver('tenured'))) { default: case eval(\"/* no regression tests found */\", 29): break;  }");
/*fuzzSeed-85495475*/count=1166; tryItOut("p1.toSource = (function() { try { a0.push(f2, p0); } catch(e0) { } try { a2.length = 17; } catch(e1) { } try { this.v1 = g2.runOffThreadScript(); } catch(e2) { } m1.get(g2.b0); throw g0.p0; });");
/*fuzzSeed-85495475*/count=1167; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -8589934593.0;\n    return (((((-3.022314549036573e+23)))-(i1)))|0;\n  }\n  return f; })(this, {ff: function (b) { yield {} } }, new ArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=1168; tryItOut("g0.e1 + '';");
/*fuzzSeed-85495475*/count=1169; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[x, (0/0), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), x]) { h2.get = this.f2; }");
/*fuzzSeed-85495475*/count=1170; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (mathy0((((Math.tan(x) >> ((Math.asinh((Math.fround(Math.tan((( + (( ~ x) - y)) >>> 0))) | 0)) | 0) | 0)) | 0) >>> 0), Math.round(Math.fround((((Math.fround(Number.MIN_VALUE) / Math.fround(( + (y && y)))) | 0) >= (( + ( ! ( + Math.pow(((Math.atanh(x) >>> 0) ? x : y), -Number.MIN_VALUE)))) | 0))))) >>> 0); }); testMathyFunction(mathy4, [-0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 2**53+2, Math.PI, 1, -(2**53), 1/0, -1/0, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 2**53-2, 0x07fffffff, 0/0, -0x100000000, 0.000000000000001, -(2**53-2), 42, -0x100000001, -Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, 0x080000001, 0, 0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000]); ");
/*fuzzSeed-85495475*/count=1171; tryItOut("this.v0 = Array.prototype.some.apply(a2, [(function() { try { i1.__proto__ = o1.v1; } catch(e0) { } try { print(o1); } catch(e1) { } try { with(Math.hypot(-1077037259, \"\\uA7AB\") >>> DataView.prototype.setInt16)throw (4277); } catch(e2) { } this.r0 = /(?!.+)*?/yim; return h0; }), o2.h0]);");
/*fuzzSeed-85495475*/count=1172; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(mathy0((Math.acosh((((x >= Math.fround((Math.fround((Math.fround(x) / Math.fround(y))) >>> (y >>> 0)))) | 0) | 0)) >>> 0), Math.sin((Math.log((((( ! ( + x)) >>> 0) & ( + y)) - ((Math.imul(y, y) >>> 0) ? y : ( ! x)))) >>> 0)))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -(2**53), 2**53+2, -Number.MIN_VALUE, 42, -0x100000000, 0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, 1, -(2**53-2), 0, -(2**53+2), 0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53-2, 2**53, 0/0, -1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, -0, -0x080000000, -0x07fffffff, -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=1173; tryItOut("h0 + s0;v2 = t0.length;");
/*fuzzSeed-85495475*/count=1174; tryItOut("testMathyFunction(mathy3, [0x080000000, 0, Number.MIN_VALUE, 42, Math.PI, -0x100000000, 0x100000000, 1/0, -0, 1, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 2**53-2, -0x07fffffff, -1/0, 1.7976931348623157e308, -(2**53), -0x080000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 2**53, 0x07fffffff, -(2**53+2), 0.000000000000001, 0x100000001, -0x080000000, -(2**53-2), 0/0]); ");
/*fuzzSeed-85495475*/count=1175; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1, [], /0/, [0], 0.1, false, null, (function(){return 0;}), objectEmulatingUndefined(), (new Boolean(true)), (new Number(0)), -0, (new Boolean(false)), ({valueOf:function(){return '0';}}), NaN, (new String('')), '0', 0, true, ({valueOf:function(){return 0;}}), '\\0', undefined, '', (new Number(-0)), '/0/', ({toString:function(){return '0';}})]); ");
/*fuzzSeed-85495475*/count=1176; tryItOut("mathy5 = (function(x, y) { return ( ~ ((((Math.asin(x) | 0) && (( - ((( + 0x080000001) / (-Number.MIN_VALUE >>> 0)) >>> 0)) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy5, [-0x080000000, 0.000000000000001, -0x100000001, 0x0ffffffff, 0/0, 0x100000000, 0x080000000, -(2**53), 1/0, Number.MIN_VALUE, 0x07fffffff, 2**53-2, 0x100000001, -0x07fffffff, 0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, 2**53, -0, -1/0, Number.MAX_VALUE, Math.PI, 0, 42, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), 1, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=1177; tryItOut("\"use strict\"; testMathyFunction(mathy5, ['', '\\0', ({valueOf:function(){return '0';}}), true, (new Boolean(true)), 1, [], false, (new Number(0)), objectEmulatingUndefined(), undefined, 0, (new Number(-0)), -0, '0', 0.1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (function(){return 0;}), (new String('')), null, (new Boolean(false)), [0], /0/, '/0/', NaN]); ");
/*fuzzSeed-85495475*/count=1178; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.expm1(( + ( ~ ( + Math.fround(mathy1(Math.fround(mathy1(x, (Math.fround((Math.fround(x) | y)) >>> 0))), Math.fround(Math.fround(mathy0(( + Math.atan2(((((42 | 0) >>> ( + x)) | 0) | 0), (Math.atan2(y, ( + Math.min(x, ( + 1/0)))) | 0))), ( + -0x0ffffffff)))))))))); }); testMathyFunction(mathy2, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, 0.000000000000001, -0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, -0x100000000, 1.7976931348623157e308, 2**53, Number.MIN_VALUE, 0x100000001, -(2**53), Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -0, 2**53-2, -Number.MAX_VALUE, 0x080000001, -0x07fffffff, -(2**53-2), 0, 0x100000000, -Number.MIN_SAFE_INTEGER, 42, -1/0, -(2**53+2), 0x080000000, Math.PI, 0/0]); ");
/*fuzzSeed-85495475*/count=1179; tryItOut("\"use strict\"; a1.length = ({wrappedJSObject: (arguments =  \"\" ), x:  \"\"  });");
/*fuzzSeed-85495475*/count=1180; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=1181; tryItOut("mathy2 = (function(x, y) { return (( ~ ( + Math.atanh((0x080000001 * Math.fround((1/0 * Math.fround(y))))))) != (( ~ (Math.fround((Math.imul(x, ((( + (( + y) | 0)) | 0) | 0)) === Math.sqrt(( + y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [[0], NaN, ({valueOf:function(){return 0;}}), undefined, '\\0', false, 0.1, ({toString:function(){return '0';}}), (new Boolean(false)), [], (new Number(0)), true, objectEmulatingUndefined(), '0', (new String('')), /0/, (new Boolean(true)), null, ({valueOf:function(){return '0';}}), -0, '/0/', '', 1, (function(){return 0;}), (new Number(-0)), 0]); ");
/*fuzzSeed-85495475*/count=1182; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.atan2(( ~ x), ( + Math.min(( + (( + (Math.sin((( + (Math.fround(x) <= Math.fround(Math.fround(Math.pow(y, Math.fround(x)))))) >>> 0)) >>> 0)) ? y : y)), ( + ( ! Math.max(x, (x >>> 0))))))) * ( + Math.hypot((Math.fround(Math.cos(Math.fround(Math.cosh(Math.fround(Math.imul(( ~ y), Math.fround(y))))))) | 0), ( + Math.log10(( + Math.acos(( + y)))))))); }); testMathyFunction(mathy3, [-1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, -0x100000001, Math.PI, 0x080000001, 0/0, 2**53-2, 0x080000000, -0x0ffffffff, 0, 0x07fffffff, 0x0ffffffff, 1, -(2**53), -0x07fffffff, Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, 2**53+2, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 0x100000000, 0x100000001, 0.000000000000001, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-85495475*/count=1183; tryItOut("f2 = (function() { try { g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 != 2), noScriptRval: false, sourceIsLazy: true, catchTermination: ((4277)).yoyo((uneval(true))) })); } catch(e0) { } try { /*RXUB*/var r = r2; var s = \"\"; print(s.split(r));  } catch(e1) { } g2.v2.valueOf = (function() { for (var j=0;j<20;++j) { f1(j%3==0); } }); return a0; });");
/*fuzzSeed-85495475*/count=1184; tryItOut("\"use strict\"; t2 = new Uint32Array(b1, 19, \n-25(( /x/ .throw([z1])), /(\\W|$+?[^]|.|$[^][^])((?=.^)+)|[^](.|[^\\cV]|[^])|(?:(?:\\1)|[^])|\\B+?((?:[^])){2}/ym));");
/*fuzzSeed-85495475*/count=1185; tryItOut("m2.has(o2.g0.f0);");
/*fuzzSeed-85495475*/count=1186; tryItOut("/*hhh*/function wutadx(c){/*oLoop*/for (let alwikr = 0; alwikr < 2; ++alwikr) { v2 = evalcx(\"new RegExp(\\\"(?!(?:[^]))\\\", \\\"gyi\\\")\", g0); } /*RXUB*/var r = /[\\u001e\\r\\d]/i; var s = \"_\"; print(uneval(r.exec(s))); }wutadx();");
/*fuzzSeed-85495475*/count=1187; tryItOut("mathy1 = (function(x, y) { return ((((( + ((x >>> 0) + ( + 42))) & (Math.pow(Math.trunc(Math.fround(mathy0(Math.log10((-0x100000001 | 0)), x))), Math.max((y ? 2**53 : x), y)) >>> 0)) >>> 0) ? Math.log((Math.atan2((-Number.MIN_VALUE >= ( + ( + 0/0))), Math.fround((y !== (Math.log(x) | 0)))) | 0)) : ((Math.fround(( ~ ( + ( ~ y)))) ? mathy0((( + Math.tanh(( ~ Number.MIN_VALUE))) >>> 0), (x >>> 0)) : Math.fround(( ~ Math.fround(x)))) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[new String('q'), arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller]); ");
/*fuzzSeed-85495475*/count=1188; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1189; tryItOut("mathy0 = (function(x, y) { return (Math.exp(Math.fround(Math.imul(Math.pow(Math.atan2(Math.log2(x), Math.fround(x)), Math.fround(Math.round(Math.fround(y)))), Math.fround(( - Math.min(x, 2**53)))))) >>> 0); }); ");
/*fuzzSeed-85495475*/count=1190; tryItOut("with({x: (void version(170))}){for (var v of b2) { try { b0 + ''; } catch(e0) { } try { a1.__proto__ = v1; } catch(e1) { } try { v1 = null; } catch(e2) { } Array.prototype.sort.call(a1, (5).apply); }\ne1.add(/*MARR*/[NaN, undefined, undefined, undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), undefined,  '\\0' , undefined,  '\\0' , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  '\\0' , undefined, objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ].some(() =>  { yield  /x/g  } ));\nm1.get(o0.s2); }");
/*fuzzSeed-85495475*/count=1191; tryItOut("M:with(((Math.tan(-17)))(( \"\" +=((void version(185)))\u0009), (function(stdlib, foreign, heap){ \"use asm\";   var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    (Int8ArrayView[((!(0xff43530e))-(i2)) >> 0]) = ((i3)-(0xfb1a7868)+(i2));\n    return (((0xfc44cc70)+(-0x8000000)))|0;\n  }\n  return f; }).__defineSetter__(\"w\", y)))print(x);");
/*fuzzSeed-85495475*/count=1192; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-85495475*/count=1193; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=1194; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 3.094850098213451e+26;\n    var d3 = -1.25;\n    var i4 = 0;\n    var d5 = 9.44473296573929e+21;\n    d5 = (((((Float32ArrayView[((!((((-0x8000000)-(0xa14a65cb)+(0xcb741c50))|0)))-(0xa7549fca)) >> 2])) / ((+abs(((-1.1805916207174113e+21))))))) % ((+abs(((d3))))));\n    return +((Float64ArrayView[((abs((~~(d2)))|0) % ((0x6f413*(i4)) | ((0x1617072a)+((((0xfe5dfeda)) & ((0xf07bb5f6))))+(i4)))) >> 3]));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x0ffffffff, Math.PI, 0x080000001, 42, Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, 1, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, 0/0, 0x100000001, 2**53, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, -0x080000000, 2**53+2, 0x07fffffff, Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -(2**53-2), 0x080000000, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, 0, -(2**53+2), -1/0, -0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1195; tryItOut("m2.has(i0);");
/*fuzzSeed-85495475*/count=1196; tryItOut("h2.has = (function mcc_() { var qzxkdj = 0; return function() { ++qzxkdj; if (/*ICCD*/qzxkdj % 10 == 6) { dumpln('hit!'); try { v0 = new Number(g1); } catch(e0) { } try { v2 = (o1.f0 instanceof g1.v0); } catch(e1) { } try { this.v2 = g1.g0.runOffThreadScript(); } catch(e2) { } v2 = m1.get(g1); } else { dumpln('miss!'); try { e0.delete(f2); } catch(e0) { } try { v2 = true; } catch(e1) { } e1.has(/*UUV1*/(x.sub = objectEmulatingUndefined)); } };})();");
/*fuzzSeed-85495475*/count=1197; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - (mathy1(y, ( + Math.fround(x))) ? Math.imul(( + ((0x080000001 >>> 0) & x)), Math.atan2(y, x)) : ( + ( ! ( + Math.acos(0.000000000000001)))))) | 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 42, 0.000000000000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, 2**53, -0x0ffffffff, -0, -0x100000001, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, 0/0, Math.PI, -0x080000001, -(2**53+2), -Number.MIN_VALUE, -1/0, -(2**53-2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, 1, -(2**53), 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=1198; tryItOut("\"use strict\"; e1.delete(t0);");
/*fuzzSeed-85495475*/count=1199; tryItOut("mathy0 = (function(x, y) { return Math.atan(( ~ Math.abs((y >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), this * (p={}, (p.z = (4277))()),  'A' , ({}),  'A' , new Boolean(true), this * (p={}, (p.z = (4277))()), this * (p={}, (p.z = (4277))()),  'A' ,  'A' , this * (p={}, (p.z = (4277))()), {x:3}, new Boolean(true), this * (p={}, (p.z = (4277))()), ({}), {x:3},  'A' , ({}), ({}), {x:3}, ({}),  'A' , ({}), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, this * (p={}, (p.z = (4277))()),  'A' , new Boolean(true), ({}), new Boolean(true),  'A' , {x:3}, new Boolean(true), this * (p={}, (p.z = (4277))()), ({}), ({}), this * (p={}, (p.z = (4277))()), {x:3},  'A' , ({}), new Boolean(true), this * (p={}, (p.z = (4277))()), new Boolean(true), new Boolean(true), {x:3}, this * (p={}, (p.z = (4277))()), ({}), new Boolean(true),  'A' , this * (p={}, (p.z = (4277))()),  'A' , this * (p={}, (p.z = (4277))()),  'A' ,  'A' , new Boolean(true), ({}),  'A' ,  'A' , this * (p={}, (p.z = (4277))()),  'A' , this * (p={}, (p.z = (4277))()), ({}), {x:3},  'A' , {x:3}, new Boolean(true),  'A' ,  'A' ,  'A' , new Boolean(true), {x:3}, new Boolean(true), this * (p={}, (p.z = (4277))()), {x:3}, new Boolean(true),  'A' , {x:3}, {x:3}, {x:3}, {x:3}, {x:3},  'A' ]); ");
/*fuzzSeed-85495475*/count=1200; tryItOut("\"use strict\"; \"use asm\"; v0 = a2.length;");
/*fuzzSeed-85495475*/count=1201; tryItOut("v0 = h2[new offThreadCompileScript(new RegExp(\"\\\\2{524288}|([]*?){127}|.*?*?\", \"g\") in (x = x))];");
/*fuzzSeed-85495475*/count=1202; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[arguments.caller, x instanceof a, null, {x:3}, -Infinity, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, {x:3}, {x:3}, {x:3}, x instanceof a, -Infinity, null, {x:3}, x instanceof a, null, x instanceof a, arguments.caller, arguments.caller, arguments.caller, -Infinity, -Infinity, -Infinity, arguments.caller, x instanceof a, null, {x:3}, x instanceof a, -Infinity, arguments.caller, x instanceof a, null, arguments.caller, arguments.caller, {x:3}, -Infinity, arguments.caller, null, -Infinity, x instanceof a, x instanceof a, -Infinity, -Infinity]); ");
/*fuzzSeed-85495475*/count=1203; tryItOut("\"use strict\"; do {/*vLoop*/for (var ijbcsv = 0; ijbcsv < 11; ++ijbcsv) { let w = ijbcsv; print(/((?:.\\w|\\D.+)|\\\uaa54(?:[^])^[^][]*){0}/yi);\nArray.prototype.pop.apply(a2, [this.o1]);\n }  } while((new ((function  x (a, x = (4277), ...x) { \"use strict\"; print(x); } ).call)(this)) && 0);");
/*fuzzSeed-85495475*/count=1204; tryItOut("v1 = (a2 instanceof p2);");
/*fuzzSeed-85495475*/count=1205; tryItOut("for(let y in x) return;x.stack\nbreak ;this.t2 = new Int16Array(t0);");
/*fuzzSeed-85495475*/count=1206; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1207; tryItOut("print(t0);");
/*fuzzSeed-85495475*/count=1208; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (((Math.cos((Math.min((((x ? y : y) != (x >>> 0)) | 0), (Math.hypot(x, Math.fround(x)) | 0)) | 0)) >>> 0) > Math.fround((Math.tan(Math.fround((Math.hypot((y | 0), ( ~ x)) | 0))) >>> 0))) >>> 0); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x080000000, 0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53-2, -Number.MAX_VALUE, 1, 1/0, -0, 0x0ffffffff, -(2**53+2), -0x0ffffffff, -0x080000001, -(2**53-2), -1/0, 2**53, 0x080000001, 2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -0x07fffffff, Math.PI, 0/0, Number.MAX_VALUE, 42, 0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-85495475*/count=1209; tryItOut("var x, d, sxmfzh, rqxefm, x = (++\u0009y), x, awgkrv;this.v1 = t0.length;");
/*fuzzSeed-85495475*/count=1210; tryItOut("v1 = g2.runOffThreadScript();");
/*fuzzSeed-85495475*/count=1211; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1212; tryItOut("mathy2 = (function(x, y) { return ((( + Math.acos(Math.atan2((Math.atan2(( + (( + mathy0(y, Math.fround((Math.fround(x) , Math.fround(-0x100000000))))) ? ( + (x * ( + -0x080000000))) : 0/0)), y) >>> 0), Math.fround(Math.PI)))) > ((Math.round((Math.cos(Math.pow(Math.atan2(( + y), (y ? y : y)), ( + Math.fround(( + Math.min(( - x), 0x0ffffffff)))))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-85495475*/count=1213; tryItOut("mathy1 = (function(x, y) { return ((Math.tanh(Math.hypot(Math.fround(Math.atan2(y, Math.cbrt(x))), x)) !== Math.sign(( + Math.max(( + Math.exp(( + (((1 >>> 0) ? x : 1) >>> 0)))), y)))) >>> 0); }); testMathyFunction(mathy1, [0x100000001, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -Number.MIN_VALUE, 2**53, -0x07fffffff, 0x080000001, 0x07fffffff, Math.PI, 0x080000000, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -1/0, -(2**53+2), 2**53+2, 0/0, Number.MAX_VALUE, 1/0, 0x100000000, 1.7976931348623157e308, 2**53-2, -0x100000001, -(2**53-2), 42, 0.000000000000001, -Number.MAX_VALUE, -0x080000001, -(2**53), 1, -0]); ");
/*fuzzSeed-85495475*/count=1214; tryItOut("const x = [z1], window.__proto__ = (--c), e = y, \u3056, x, window, \u3056, eval;/*RXUB*/var r = new RegExp(\"(?:(?=$?|\\ue114\\\\1|(?:(?!$)[^])*))\", \"gi\"); var s = \"\\u7685\"; print(s.search(r)); ");
/*fuzzSeed-85495475*/count=1215; tryItOut("print(uneval(m0));");
/*fuzzSeed-85495475*/count=1216; tryItOut("t2[11];");
/*fuzzSeed-85495475*/count=1217; tryItOut("/*RXUB*/var r = this.r2; var s = \"____00_________\"; print(s.match(r)); ");
/*fuzzSeed-85495475*/count=1218; tryItOut("\"use strict\"; delete p1[new String(\"18\")];");
/*fuzzSeed-85495475*/count=1219; tryItOut("t0[1] = (makeFinalizeObserver('tenured'));");
/*fuzzSeed-85495475*/count=1220; tryItOut("print(v1);");
/*fuzzSeed-85495475*/count=1221; tryItOut("\"use asm\"; /*RXUB*/var r = g2.r0; var s = this.g1.g2.o1.s1; print(uneval(r.exec(s))); ");
/*fuzzSeed-85495475*/count=1222; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(Math.log2(Math.log10(( ! y)))) <= (Math.imul(( ~ ((x ? Math.hypot(x, (mathy1(Math.fround(2**53), x) << x)) : Math.fround(( + ( ~ ( + x))))) | 0)), (mathy1((Math.atanh(Math.asin(0x07fffffff)) >>> 0), (Math.asin(y) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-(2**53-2), -Number.MIN_VALUE, 0x080000001, -(2**53+2), -(2**53), -1/0, 2**53+2, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0x080000000, 0x100000001, -0x100000001, -0x07fffffff, 1/0, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, -0, 0/0, -0x080000000, 42, 0, 2**53, 2**53-2, -Number.MAX_VALUE, -0x100000000, 0x100000000, 1, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-85495475*/count=1223; tryItOut("this.v2 = evalcx(\"g1.b0.valueOf = Math.sin.bind(f0);\", g1.g2);");
/*fuzzSeed-85495475*/count=1224; tryItOut("{ void 0; minorgc(false); } e1.has(b1);");
/*fuzzSeed-85495475*/count=1225; tryItOut("Object.defineProperty(this, \"g0.i2\", { configurable: Math.log2(('fafafa'.replace(/a/g, function  w (z) { return \"\\u96D6\" } ))), enumerable: false,  get: function() {  return e2.iterator; } });");
/*fuzzSeed-85495475*/count=1226; tryItOut("iloevq();/*hhh*/function iloevq(x, x =  /x/g , x, eval, x, x, x, d){s2 = g2.s1.charAt(18);\nprint( '' );\n}");
/*fuzzSeed-85495475*/count=1227; tryItOut("\"use strict\"; testMathyFunction(mathy1, [2**53-2, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, 2**53, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), -0x07fffffff, 0x080000001, 0x100000001, -0x0ffffffff, -Number.MAX_VALUE, 2**53+2, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0, -0x100000001, 42, 1, 1/0, -1/0, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53)]); ");
/*fuzzSeed-85495475*/count=1228; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! Math.fround(((((Math.fround((Math.min(y, (( + (((y >>> 0) ** ( + Math.atan2((x >>> 0), y))) >>> 0)) | 0)) >>> 0)) >> (( - (Math.exp(y) | 0)) | 0)) | 0) >>> 0) >>> (( ~ mathy0(y, x)) >> (((x >>> 0) | (Number.MIN_SAFE_INTEGER >>> 0)) ? ( ! Math.log2(1/0)) : Math.log(x)))))); }); testMathyFunction(mathy3, [0x07fffffff, -0x080000001, 1, -0x080000000, -1/0, 2**53+2, -0x07fffffff, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, -(2**53), 0x0ffffffff, Math.PI, 0x100000000, 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 42, -(2**53+2), -Number.MAX_VALUE, -0x100000000, -(2**53-2), 0x080000001, 0x080000000, -0x0ffffffff, 0/0, 0x100000001, 2**53, 1/0]); ");
/*fuzzSeed-85495475*/count=1229; tryItOut("\"use strict\"; this;function x(x, x, ...e) { Object.defineProperty(this, \"v2\", { configurable: true, enumerable: undefined,  get: function() {  return evalcx(\"a1.reverse();\", g2); } }); } o0 + g0;");
/*fuzzSeed-85495475*/count=1230; tryItOut("selectforgc(g1.o2);");
/*fuzzSeed-85495475*/count=1231; tryItOut("Array.prototype.sort.call(a1, (function() { try { e2.has(o2.m1); } catch(e0) { } try { v0 = new Number(a2); } catch(e1) { } for (var p in t2) { try { v1 = (g2 instanceof b0); } catch(e0) { } b1 = t1.buffer; } return g2.b1; }), a2, this);function x(eval, ...c)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -0.001953125;\n    var i3 = 0;\n    d2 = (d2);\n    d2 = (d1);\n    return (((0xf8066857)))|0;\n    return (((i3)))|0;\n    return (((0xb4d71012)-(((0xdbbbd*((0xd57dad37) ? (i3) : (!(-0x8000000)))) | ((1)-(i3))))+(0xfd33b53b)))|0;\n  }\n  return f;print(uneval(i0));");
/*fuzzSeed-85495475*/count=1232; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (!(0x980c5827));\n    (Float64ArrayView[((((i0)-(i0))|0) % (~~(d1))) >> 3]) = ((((((+(0x57bc2fc))) % ((+(((Float64ArrayView[4096]))|0))))) - ((9.0))));\n    switch ((((0x5d67af13) % (0x3b8847bb)) >> ((Int32ArrayView[((0x8fc7bacc)) >> 2])))) {\n      case -3:\n        i0 = (-0x8000000);\n        break;\n      case 1:\n        i0 = (i0);\n        break;\n      default:\n        return +(((i0) ? (+((+((576460752303423500.0))))) : (((d1)) - ((+exp(((+sqrt(((-35184372088833.0)))))))))));\n    }\n    i0 = (i0);\n    d1 = (-137438953473.0);\n    switch ((abs((abs((0x518ec4c8))|0))|0)) {\n      case 0:\n        d1 = (d1);\n        break;\n      default:\n        i0 = ((0x339d4d96) > (((0xe736ca27)+(0xdf2e8d80)-(i0))>>>((0x4a1c417c)+(0xfd43b7f4)+(i0))));\n    }\n    {\n      d1 = ((Math.hypot( \"\" , -21)) **= x);\n    }\n    return +((+atan2(((d1)), ((+(0.0/0.0))))));\n  }\n  return f; })(this, {ff: (4277)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0/0, 42, 2**53, Math.PI, -0x100000001, -0, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 2**53+2, 0x07fffffff, -(2**53+2), 0x100000001, 0x0ffffffff, 0x080000000, -(2**53-2), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, 0x080000001, -(2**53), -0x0ffffffff, 1, -0x080000001, 0x100000000, 1.7976931348623157e308, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=1233; tryItOut("v1 = g2.eval(\"/* no regression tests found */\");");
/*fuzzSeed-85495475*/count=1234; tryItOut(";");
/*fuzzSeed-85495475*/count=1235; tryItOut("o2.e0.add(g2);");
/*fuzzSeed-85495475*/count=1236; tryItOut("v1 = t0[17];");
/*fuzzSeed-85495475*/count=1237; tryItOut("\"use strict\"; h0.set = (function(j) { if (j) { try { e2.add((uneval(undefined))); } catch(e0) { } try { print(uneval(e0)); } catch(e1) { } a2.pop(); } else { try { ; } catch(e0) { } try { Array.prototype.sort.call(a2, e =>  { { void 0; try { startgc(117641187); } catch(e) { } } t0 + g2; } ); } catch(e1) { } try { this.a0.length = 4; } catch(e2) { } e2.has(f0); } });");
/*fuzzSeed-85495475*/count=1238; tryItOut("var atzojx = new SharedArrayBuffer(16); var atzojx_0 = new Uint16Array(atzojx); print(atzojx_0[0]); atzojx_0[0] = 14; var atzojx_1 = new Float64Array(atzojx); print(atzojx_1[0]); atzojx_1[0] = -25; var atzojx_2 = new Int32Array(atzojx); atzojx_2[0] = -16; var atzojx_3 = new Int32Array(atzojx); atzojx_3[0] = 15; var atzojx_4 = new Uint8Array(atzojx); var atzojx_5 = new Int8Array(atzojx); var atzojx_6 = new Int16Array(atzojx); var atzojx_7 = new Uint8ClampedArray(atzojx); atzojx_7[0] = -26; var atzojx_8 = new Uint32Array(atzojx); atzojx_8[0] = -27;  for  each(e in 22) v0 = t1.length;");
/*fuzzSeed-85495475*/count=1239; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - Math.fround(Math.pow(Math.fround((((x >>> 0) ** ((((y | 0) && (0x100000000 | 0)) | 0) >>> 0)) >>> 0)), Math.fround((Math.fround(Math.acos(y)) - Math.fround(0x07fffffff)))))) | 0); }); testMathyFunction(mathy3, [2**53, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, Number.MAX_VALUE, -(2**53-2), 0, -0x100000000, -0, 0/0, -(2**53+2), 0x0ffffffff, -(2**53), 0x080000001, Math.PI, 0.000000000000001, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0x100000000, 1, Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, 2**53+2, 0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000001, -1/0]); ");
/*fuzzSeed-85495475*/count=1240; tryItOut("g1.v0 = g0.eval(\"o2.a0.sort(mathy3, e0);let d = x;\");");
/*fuzzSeed-85495475*/count=1241; tryItOut("\"use strict\"; ");
/*fuzzSeed-85495475*/count=1242; tryItOut("m2.has(o2);");
/*fuzzSeed-85495475*/count=1243; tryItOut("const eval = null, atksqz, e, hrynus, c, gkmhnn, NaN, eval, x, sdgjot;v2 = Object.prototype.isPrototypeOf.call(o1, b1);");
/*fuzzSeed-85495475*/count=1244; tryItOut("f0 + '';");
/*fuzzSeed-85495475*/count=1245; tryItOut("mathy4 = (function(x, y) { return Math.pow(Math.fround(Math.fround(mathy2(Math.fround(( ! (( ~ (-0x0ffffffff | 0)) | 0))), (Math.log1p((((y < (( ~ (Math.fround((x | 0)) | 0)) | 0)) | 0) | 0)) | 0)))), (Math.abs(mathy0(y, Math.fround(mathy1(x, y)))) | 0)); }); ");
/*fuzzSeed-85495475*/count=1246; tryItOut("/*vLoop*/for (ufdwpa = 0; ufdwpa < 100; ++ufdwpa) { d = ufdwpa; f1 = Proxy.createFunction(h0, f2, f1); } ");
/*fuzzSeed-85495475*/count=1247; tryItOut("/*tLoop*/for (let y of /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), x, new Number(1.5), x, x, x, x, x, x, x, new Number(1.5), x, x, x, x, x, x, new Number(1.5), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1.5), x, new Number(1.5), new Number(1.5), x, x, new Number(1.5), x, x, x, new Number(1.5), x, new Number(1.5), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1.5), new Number(1.5), x, new Number(1.5), x, new Number(1.5), x, new Number(1.5), x, new Number(1.5), x, x, x, new Number(1.5), x, x, x, x, x, new Number(1.5), x, x, x, x, x, new Number(1.5), x, new Number(1.5), x, new Number(1.5), x, new Number(1.5), new Number(1.5), x, x, new Number(1.5), x, x, x, x, new Number(1.5), x, new Number(1.5), x, x, new Number(1.5), x, x, x, new Number(1.5), new Number(1.5), x, x, new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x, x, x, x, new Number(1.5)]) { e2.add(h1); }");
/*fuzzSeed-85495475*/count=1248; tryItOut("\"use asm\"; s0 = new String(g1.f0);");
/*fuzzSeed-85495475*/count=1249; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0, -Number.MIN_VALUE, 2**53, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -0x0ffffffff, -0x100000000, -(2**53+2), -0x080000001, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, 0/0, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 0x080000000, 0x07fffffff, Math.PI, 1/0, 0x100000001, -0x080000000, 2**53+2, -0, 1, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0]); ");
/*fuzzSeed-85495475*/count=1250; tryItOut("m2.toString = (function() { for (var j=0;j<19;++j) { f1(j%4==1); } });");
/*fuzzSeed-85495475*/count=1251; tryItOut("g1.h2.toString = (function(j) { this.f1(j); });");
/*fuzzSeed-85495475*/count=1252; tryItOut("mathy4 = (function(x, y) { return (( + Math.acosh(( + (Math.atan2((Math.tanh(x) | 0), (Math.cos(Math.fround(( ~ (x >>> 0)))) | 0)) | 0)))) <= Math.imul((mathy1(Math.fround(-(2**53-2)), ( + y)) && mathy2(Math.pow(( + 0.000000000000001), Math.max(( ~ x), Math.asinh(1.7976931348623157e308))), y)), Math.fround((Math.log2(( + (mathy2(Math.fround(-Number.MAX_VALUE), (Math.exp(x) | 0)) | 0))) * ( + mathy2(( + x), ( + Math.hypot(Math.log10(y), Math.sign(Math.fround(( - Math.fround(x)))))))))))); }); testMathyFunction(mathy4, [0x07fffffff, 0, 0x080000001, -0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1, -0x080000001, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 2**53+2, -0x0ffffffff, 2**53, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), -0x100000001, 1/0, -Number.MIN_VALUE, 0x100000001, 0x080000000, -0x100000000, -1/0, 1.7976931348623157e308, -(2**53-2), -0x080000000, 42]); ");
/*fuzzSeed-85495475*/count=1253; tryItOut("/*RXUB*/var r = /(?![^])/gyim; var s = \"\\n\"; print(r.test(s)); ");
/*fuzzSeed-85495475*/count=1254; tryItOut("\"use strict\"; \"\\u4F75\";");
/*fuzzSeed-85495475*/count=1255; tryItOut("h2.enumerate = f0;function x(y)\"use asm\";   var abs = stdlib.Math.abs;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    d1 = (-262145.0);\n    return ((0x95ef*((0x0))))|0;\n    return (((i2)*0x3c415))|0;\n    i3 = ((((i3)) << (-0x1386f*(i2))) > (((i0)) << ((i0))));\n    i0 = ((abs((abs(((0xfffff*((((0xca172505))>>>((0xaf9d62e3))))) ^ ((Uint32ArrayView[((0x318058e6)+(0xfd725b12)-(0xff56279f)) >> 2]))))|0))|0) != (0x31ab2e96));\n    i3 = (1);\n    return ((-0xf6ae*(i0)))|0;\n  }\n  return f;/* no regression tests found */\n");
/*fuzzSeed-85495475*/count=1256; tryItOut("\"use strict\"; \"use asm\"; v2 = (h0 instanceof m2);");
/*fuzzSeed-85495475*/count=1257; tryItOut("a1.push(v0, this.f1);");
/*fuzzSeed-85495475*/count=1258; tryItOut("Object.defineProperty(this, \"a2\", { configurable: true, enumerable: 'fafafa'.replace(/a/g, runOffThreadScript),  get: function() {  return []; } });");
/*fuzzSeed-85495475*/count=1259; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(((Math.asin((((Math.clz32(( + (y / y))) >>> 0) <= y) | 0)) | 0) >>> 0)) >>> 0) , (((x ^ -(2**53-2)) >>> 0) <= ( ~ ((( - Math.fround(mathy0((x >>> 0), x))) | 0) | 0)))); }); testMathyFunction(mathy1, [-0x080000001, Number.MAX_SAFE_INTEGER, 2**53, 0, -0x0ffffffff, 0x0ffffffff, -1/0, -0x100000001, -0x07fffffff, -0, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000001, -(2**53-2), 1/0, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -(2**53), 2**53-2, 42, Math.PI, -0x080000000, 0x080000000, 0.000000000000001, 1, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=1260; tryItOut("\"use strict\"; v1 = g1.r0.flags;");
/*fuzzSeed-85495475*/count=1261; tryItOut("a2 = a1.concat(a0, f1);");
/*fuzzSeed-85495475*/count=1262; tryItOut("mathy4 = (function(x, y) { return Math.max(( + (Math.fround(((Math.max(Math.hypot(x, x), (((Math.log10(1) & y) >>> 0) | 0)) | 0) & y)) / Math.fround(((y + y) , (Math.ceil(( ! mathy2(x, x))) >>> 0))))), Math.min(( + Math.hypot(( + mathy1((((x >>> 0) ? (Math.fround(mathy1(x, Math.fround(x))) >>> 0) : (Number.MIN_SAFE_INTEGER | 0)) | 0), (0.000000000000001 || ( + y)))), ( + Math.min(x, Math.fround(Math.imul(Math.PI, Math.fround(Math.exp(( + ( ! x)))))))))), (( - ((Math.sqrt(mathy0(Math.fround(-Number.MAX_SAFE_INTEGER), -(2**53+2))) | 0) | 0)) | 0))); }); ");
/*fuzzSeed-85495475*/count=1263; tryItOut("(x);");
/*fuzzSeed-85495475*/count=1264; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o1, o0.e0);");
/*fuzzSeed-85495475*/count=1265; tryItOut("var c = x;o0.valueOf = function(y) { \"use strict\"; Array.prototype.push.call(a1, f2); };");
/*fuzzSeed-85495475*/count=1266; tryItOut("/*RXUB*/var r = new RegExp(\"\\uefb1^+?|$.|.?|\\\\W^|\\u5bcb**(?!(?:\\\\b)(?:\\\\D).|\\\\W{3,})*?|.|((.$)*)|(?!(?:\\\\S)|$)(?=[^])|\\\\1[^]{68719476737,68719476737}|\\\\B(?![^]|\\ud142|\\\\b$\\\\3+|\\\\b)\", \"im\"); var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-85495475*/count=1267; tryItOut("delete this.h2.delete;function y(x, w) { return x } ;");
/*fuzzSeed-85495475*/count=1268; tryItOut("\"use strict\"; for(let x = ((y) = a).x in  /x/g ) {g2.t2 = new Uint32Array(0);print(uneval(p0)); }");
/*fuzzSeed-85495475*/count=1269; tryItOut("Array.prototype.push.apply(a2, [t2, b2]);");
/*fuzzSeed-85495475*/count=1270; tryItOut("m2 + '';");
/*fuzzSeed-85495475*/count=1271; tryItOut("mathy5 = (function(x, y) { return ((((mathy4((mathy4(mathy3(Math.log((0x100000001 >>> 0)), Math.asin(Math.log1p(x))), ( ! Math.expm1((Math.hypot(Math.fround(-0), (y >>> 0)) >>> 0)))) | 0), Math.imul(Math.imul(mathy1(y, x), (0x0ffffffff >>> Math.PI)), Math.fround(x))) >>> 0) >>> 0) >>> ((mathy2((( + Math.ceil(Math.expm1(x))) | 0), (Math.atan((Math.sqrt(x) >>> 0)) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), 0x080000000, 2**53-2, -0x0ffffffff, -0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 1/0, -Number.MAX_VALUE, 42, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, 0x080000001, -1/0, 0.000000000000001, 1, -0x080000001, -(2**53-2), -Number.MIN_VALUE, 0/0, 2**53, -(2**53), 0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=1272; tryItOut("f1[\"link\"] = t1;");
/*fuzzSeed-85495475*/count=1273; tryItOut("this.zzz.zzz;let(z) { this.zzz.zzz;}");
/*fuzzSeed-85495475*/count=1274; tryItOut("g0.s0 += 'x';");
/*fuzzSeed-85495475*/count=1275; tryItOut("e1.add(b2);");
/*fuzzSeed-85495475*/count=1276; tryItOut("testMathyFunction(mathy4, [-0x080000000, -0x07fffffff, -0x100000000, -0x080000001, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 42, 0x0ffffffff, -0x0ffffffff, -(2**53+2), 2**53, Number.MIN_VALUE, 2**53-2, 0x100000000, -1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0, -(2**53), -Number.MAX_VALUE, 2**53+2, Math.PI, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, 0/0, -0, -Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0x100000001, 1]); ");
/*fuzzSeed-85495475*/count=1277; tryItOut("m2.set(h1, t1);");
/*fuzzSeed-85495475*/count=1278; tryItOut("v0 = a0.length;");
/*fuzzSeed-85495475*/count=1279; tryItOut("\"use strict\"; /*iii*/print(reabgr);/*hhh*/function reabgr(this, NaN){/*ODP-2*/Object.defineProperty(v1, \"setInt32\", { configurable: false, enumerable: false, get: (function() { for (var j=0;j<2;++j) { f0(j%4==1); } }), set: (function mcc_() { var xlnnjq = 0; return function() { ++xlnnjq; if (/*ICCD*/xlnnjq % 11 == 5) { dumpln('hit!'); for (var p in h0) { try { m1.get(h1); } catch(e0) { } try { this.m1.delete(e2); } catch(e1) { } m2.set(a1, a1); } } else { dumpln('miss!'); t2 = new Uint8Array(t1); } };})() });}return;");
/*fuzzSeed-85495475*/count=1280; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1281; tryItOut("/*infloop*/for(let x in ((Object.entries)((4277)\u000d))){/*bLoop*/for (hbeisu = 0; hbeisu < 100; ++hbeisu) { if (hbeisu % 2 == 1) { (936195717); } else { h2 = ({getOwnPropertyDescriptor: function(name) { v2 = (e2 instanceof m2);; var desc = Object.getOwnPropertyDescriptor(t2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { ;; var desc = Object.getPropertyDescriptor(t2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e0.add(window);; Object.defineProperty(t2, name, desc); }, getOwnPropertyNames: function() { /*ADP-1*/Object.defineProperty(this.a1, 9, ({configurable: true}));; return Object.getOwnPropertyNames(t2); }, delete: function(name) { neuter(b0, \"same-data\");; return delete t2[name]; }, fix: function() { for (var v of b2) { try { i2.send(e2); } catch(e0) { } try { for (var v of i1) { try { g1.offThreadCompileScript(\"false\"); } catch(e0) { } try { t1[b] = \"\\u50EF\"; } catch(e1) { } g1.offThreadCompileScript(\"/* no regression tests found */\"); } } catch(e1) { } a1 + ''; }; if (Object.isFrozen(t2)) { return Object.getOwnProperties(t2); } }, has: function(name) { m0.has(o0.p1);; return name in t2; }, hasOwn: function(name) { g1.i1.next();; return Object.prototype.hasOwnProperty.call(t2, name); }, get: function(receiver, name) { t2 = new Uint16Array(1);; return t2[name]; }, set: function(receiver, name, val) { a1.valueOf = String.prototype.strike.bind(e2);; t2[name] = val; return true; }, iterate: function() { o0.a1.push(g1);; return (function() { for (var name in t2) { yield name; } })(); }, enumerate: function() { throw s2; var result = []; for (var name in t2) { result.push(name); }; return result; }, keys: function() { s2 += 'x';; return Object.keys(t2); } }); }  }  }");
/*fuzzSeed-85495475*/count=1282; tryItOut("\"use asm\"; rqdkqo, icrdnp, z, window, x = let (b = c = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), Function, objectEmulatingUndefined), \u3056, x = \"\\uCBF9\", pksdzf, bwmehe, aognpp, cnqsbm, x, b) x, x, x, y = ++x > x, w;f1 = a2[({valueOf: function() { print(x);(\"\\u68E0\");return 8; }})];");
/*fuzzSeed-85495475*/count=1283; tryItOut("testMathyFunction(mathy3, [42, 2**53-2, 1, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000, -1/0, 1.7976931348623157e308, -(2**53), 0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0, 0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 0x080000001, 0x080000000, 2**53, -0x100000001, 0.000000000000001, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, 1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), 2**53+2, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=1284; tryItOut("/*bLoop*/for (var nyehck = 0; nyehck < 146; ++nyehck) { if (nyehck % 29 == 24) { a0.shift(); } else { x; }  } ");
/*fuzzSeed-85495475*/count=1285; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( ~ ( + Math.abs((Math.imul(Math.ceil(x), ( ! (Math.fround((Math.fround(y) ? Math.pow(2**53, x) : (( ~ -Number.MIN_VALUE) >>> 0))) >>> 0))) | 0))))); }); testMathyFunction(mathy3, [0x080000000, -0x0ffffffff, -0x080000001, 2**53+2, 2**53-2, 0.000000000000001, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, -0x100000001, -0, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 2**53, 1/0, 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, Number.MAX_VALUE, -1/0, 0x07fffffff, 42, 0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, 1, Number.MIN_VALUE, 0x100000000, -0x07fffffff, 0/0, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=1286; tryItOut("var qkkodn = new ArrayBuffer(12); var qkkodn_0 = new Int8Array(qkkodn); var qkkodn_1 = new Int32Array(qkkodn); print(qkkodn_1[0]); qkkodn_1[0] = -20; var qkkodn_2 = new Uint16Array(qkkodn); var qkkodn_3 = new Float64Array(qkkodn); var qkkodn_4 = new Int8Array(qkkodn); qkkodn_4[0] = 1; var qkkodn_5 = new Uint16Array(qkkodn); var qkkodn_6 = new Int8Array(qkkodn); print(qkkodn_6[0]); qkkodn_6[0] = 23; var qkkodn_7 = new Float64Array(qkkodn); qkkodn_7[0] = 23; if(false) f2 + '';/* no regression tests found */m2.delete(a2);/*MXX3*/g0.String.length = g1.String.length;/*vLoop*/for (var higidp = 0; higidp < 6; ++higidp) { var y = higidp; (\u000c-6); } o2 + '';");
/*fuzzSeed-85495475*/count=1287; tryItOut("\"use asm\"; ;\na1.length = ({valueOf: function() { print(m1[\"5\"] = f2);return 9; }});\n");
/*fuzzSeed-85495475*/count=1288; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x100000000, 1, -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, 2**53, -Number.MAX_VALUE, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0, Math.PI, 0, Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, 1/0, 42, 0/0, 2**53+2, -(2**53), 0x07fffffff, -0x0ffffffff, -(2**53-2), -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-85495475*/count=1289; tryItOut("for (var v of this.g0.e0) { try { print(m2); } catch(e0) { } v0 = a1.length; }");
/*fuzzSeed-85495475*/count=1290; tryItOut("\"use strict\"; /*vLoop*/for (var fflzzg = 0; fflzzg < 7; ++fflzzg) { a = fflzzg; print(x); } ");
/*fuzzSeed-85495475*/count=1291; tryItOut("Array.prototype.splice.call(this.a0, NaN, v0, t1, g1);");
/*fuzzSeed-85495475*/count=1292; tryItOut("mathy3 = (function(x, y) { return ( + (Math.clz32(( + (Math.fround(((((x >>> 0) , x) >>> 0) ^ Math.fround(( ! x)))) ? x : -(2**53-2)))) % ( + (Math.asin((( ! ( - (x * x))) | 0)) | 0)))); }); testMathyFunction(mathy3, [(function(){return 0;}), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), [], -0, (new Number(0)), false, 0.1, null, (new Boolean(true)), objectEmulatingUndefined(), 0, undefined, ({valueOf:function(){return 0;}}), '/0/', /0/, [0], '', 1, (new Number(-0)), (new String('')), (new Boolean(false)), '\\0', '0', NaN, true]); ");
/*fuzzSeed-85495475*/count=1293; tryItOut("\"use strict\"; o2.__proto__ = m2;");
/*fuzzSeed-85495475*/count=1294; tryItOut("mathy3 = (function(x, y) { return Math.hypot((Math.min(( + Math.sin(( + Math.max(y, ( + ((y | 0) == y)))))), Math.fround((Math.abs((x | 0)) | 0))) | 0), ( + Math.log2(((( - (( - x) >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy3, [Math.PI, 0x07fffffff, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, 0/0, 1, Number.MAX_VALUE, 0x0ffffffff, -1/0, -0x080000001, 1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), -(2**53), 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -0, -Number.MAX_VALUE, -0x080000000, 0x100000001, Number.MIN_VALUE, 42, -0x100000001, 0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=1295; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.expm1((( + Math.fround(Math.asinh(((Math.imul(x, (x | 0)) | 0) ? Math.hypot(x, y) : y)))) == mathy2(Math.fround((Math.acosh((( + Math.fround(Math.ceil(y))) >>> 0)) >>> 0)), (((( + Math.log2(y)) | 0) != Math.fround(-0)) | 0)))); }); testMathyFunction(mathy5, [1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, -Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -1/0, 2**53, Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, 0, 2**53-2, Math.PI, -Number.MIN_VALUE, -0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -0x080000000, -0x080000001, 1, 0x080000001, 0x080000000, -(2**53), -0x100000001, Number.MAX_VALUE, 0x100000000, 2**53+2, -0x07fffffff, 0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=1296; tryItOut("let(x = this, \u3056, otlrnj, window, eval, b, x, krurnd, vbypxc, x) { x = this.zzz.zzz;}");
/*fuzzSeed-85495475*/count=1297; tryItOut("\"use strict\"; for(let a = x in \n\"\\u3221\") {g0.o2.a0.shift(a2);yield; }var y = x;");
/*fuzzSeed-85495475*/count=1298; tryItOut("t0 + '';");
/*fuzzSeed-85495475*/count=1299; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy1((( + (Math.trunc(y) >>> 0)) >>> 0), ((y ? y : ( ~ Math.imul((y | 0), x))) ? ( ! ( - y)) : (x ? (Math.max(Math.fround(Math.min((Math.exp((y | 0)) | 0), y)), (0x080000001 | 0)) | 0) : y))) || ( + ( ! (Math.fround(Math.hypot((( ! y) < Math.fround((Math.fround(0x07fffffff) ? Math.fround(x) : y))), ( + Math.pow(( + Math.imul(((((x >>> 0) ? (x >>> 0) : x) >>> 0) | 0), (x | 0))), ( + ( - Number.MAX_VALUE)))))) % (Math.min(y, Math.fround(x)) | 0))))); }); testMathyFunction(mathy2, [0x07fffffff, -0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, Math.PI, 0x080000001, -1/0, 0.000000000000001, Number.MAX_VALUE, 2**53, 0x0ffffffff, -0x0ffffffff, 0, 42, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -(2**53+2), 1, 2**53-2, 0x100000001, 0x100000000, -0, 0x080000000, -(2**53-2), 2**53+2, -(2**53)]); ");
/*fuzzSeed-85495475*/count=1300; tryItOut("v1 = a2.length;");
/*fuzzSeed-85495475*/count=1301; tryItOut("testMathyFunction(mathy3, [0x100000001, 0/0, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 1, Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 0.000000000000001, -0x07fffffff, 42, -(2**53-2), 0x07fffffff, -0x080000000, 0x080000000, -0x080000001, 0, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53+2), -1/0, -0x100000001, -0, 0x080000001, 2**53+2, Number.MAX_VALUE, 2**53-2, -Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=1302; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-85495475*/count=1303; tryItOut("M:for(a in ({a2:z2})) continue L;");
/*fuzzSeed-85495475*/count=1304; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh(Math.max(Math.fround(( - (y >>> -0))), ((Math.exp(-(2**53+2)) >>> 0) ? ( - Math.cosh(( + y))) : Math.sinh((x % y))))); }); testMathyFunction(mathy0, [-(2**53), -0x0ffffffff, 2**53-2, -0x080000000, -0x100000000, 1, 0, 0x080000001, -1/0, 0.000000000000001, 42, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), -0x07fffffff, 1/0, 0x100000001, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 0x100000000, 2**53, -0]); ");
/*fuzzSeed-85495475*/count=1305; tryItOut("\"use strict\"; o0.v1 = Object.prototype.isPrototypeOf.call(p0, v2);");
/*fuzzSeed-85495475*/count=1306; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy0((Math.max((((x | 0) >> (((x & y) >>> 0) | 0)) | 0), Math.min(( - (Math.sign((42 >>> 0)) >>> 0)), (x + Math.acosh(y)))) | 0), (Math.sign((mathy0(x, ( ! (y ? ( + x) : y))) ** Math.atan2(Math.fround((Math.fround((Math.pow(y, (y >>> 0)) | 0)) < Math.fround(-0x100000001))), Math.fround(Math.atan2(Math.fround(y), Math.fround(x)))))) | 0)) | 0); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, -0x100000000, -(2**53-2), 0x100000000, 2**53, 0.000000000000001, -0x0ffffffff, -(2**53+2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x080000001, Number.MIN_VALUE, 1/0, 1, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, -0x080000001, 0, -1/0, 0x07fffffff, 0/0]); ");
/*fuzzSeed-85495475*/count=1307; tryItOut("\"use strict\"; for (var p in v2) { try { t2 = new Int32Array(o1.b0); } catch(e0) { } try { s2 += s2; } catch(e1) { } e0.delete(t1); }");
/*fuzzSeed-85495475*/count=1308; tryItOut("\"use strict\"; /*infloop*/for(c =  /* Comment */x.throw(yield  /x/g ); (4277).entries(); (x) = x) g1.t2 = new Float64Array(t2);");
/*fuzzSeed-85495475*/count=1309; tryItOut("\"use strict\"; Int16Array = linkedList(Int16Array, 880);");
/*fuzzSeed-85495475*/count=1310; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( + Math.sqrt(mathy1((x ? x : ((mathy2(-Number.MIN_SAFE_INTEGER, (y | 0)) | 0) != x)), Math.imul(y, (y >>> 0)))))); }); testMathyFunction(mathy3, [0x080000000, Number.MAX_VALUE, -0x100000000, 2**53+2, 0/0, 0x100000001, 0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 2**53-2, 0x080000001, 0x07fffffff, 1, 1.7976931348623157e308, -(2**53+2), 42, -0x0ffffffff, -Number.MIN_VALUE, -0, 1/0, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, -0x080000001, -Number.MAX_VALUE, 0.000000000000001, -(2**53-2), Number.MIN_VALUE, -1/0, 2**53]); ");
/*fuzzSeed-85495475*/count=1311; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((x))|0;\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53+2), Number.MIN_VALUE, Math.PI, 0, 0x0ffffffff, 42, 0x080000000, 0/0, -0x100000001, 2**53-2, -0, -0x080000000, Number.MAX_VALUE, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, 1/0, -(2**53), 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, -0x0ffffffff, -0x080000001, 0.000000000000001, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-85495475*/count=1312; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+abs(((-6.189700196426902e+26))));\n    d0 = (+(0x32af8474));\n    d0 = (d0);\n    {\n      switch ((abs((((i1)+(i1))|0))|0)) {\n        default:\n          i1 = (0xd8d87ad0);\n      }\n    }\n    i1 = (i1);\n    d0 = (+floor(((-((d0))))));\n    d0 = (-1125899906842623.0);\n    i1 = (-0x8000000);\n    {\n      i1 = (0x3132cb7a);\n    }\n    d0 = (d0);\n    {\n      i1 = (-0x8000000);\n    }\n    return (((!(0x6d182df0))))|0;\n  }\n  return f; })(this, {ff: new Function}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0.000000000000001, 0, -0x080000000, -0, Math.PI, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, -(2**53), -Number.MIN_VALUE, -0x100000000, -(2**53+2), 0x100000001, -(2**53-2), Number.MIN_VALUE, -0x100000001, 0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, 2**53, 1/0, 0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -1/0, -0x0ffffffff, 2**53+2, 0x080000001]); ");
/*fuzzSeed-85495475*/count=1313; tryItOut("(x);function x(x, [x], z, x, x = [[]], c(/(?=(((?!(?=\\\u00c9)).[^]?))|\\2|(?!.[^\\B\\cA-\\t]$+?))/gym), e = (4277), x = window, y, b, c, NaN = x, c, \"-26\", e, b = null, y, \u3056, x, x =  /x/g , a, z, y, x = [[1]], a, x = z, y = /^|((?=(?!\\h))){0}\\3|(?![\\w]$)\\1*?/gyi, e, c, a, x = \"\\uB18B\", d, b, x, x, z = this, x, x, e, x, eval =  /x/ , c, c, eval, x, callee, x, x, z, x = null, this.x, x, x, w = new RegExp(\"(?=[^])|([^\\\\W\\\\u3C7c](?![^]*)+)\", \"g\"), x) { return false } const w = [z1,,];(new RegExp(\"$+?\\\\b+|(?!(?!(?=[^])))|\\\\w+|\\\\b|[^]*+?\", \"gyim\"));");
/*fuzzSeed-85495475*/count=1314; tryItOut("\"use asm\"; /*infloop*/for(var x in Math.hypot(undefined, \"\\u4B16\")) {print(f0);(x); }");
/*fuzzSeed-85495475*/count=1315; tryItOut(";");
/*fuzzSeed-85495475*/count=1316; tryItOut("\"use asm\"; a0.shift();");
/*fuzzSeed-85495475*/count=1317; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.fround(( ~ ( ! (Math.fround(Math.sqrt(Math.fround(y))) >>> 0)))) < Math.fround(Math.trunc((( + Math.acos(x)) ? Math.atan2(((Math.min(-0x100000001, x) | 0) >>> 0), ( ! 1/0)) : Math.pow(( + mathy3(( + -0x0ffffffff), Math.imul(y, (((Math.PI | 0) % (x | 0)) | 0)))), x)))))); }); testMathyFunction(mathy4, [-0x07fffffff, -1/0, 0x0ffffffff, -(2**53-2), 0.000000000000001, 0/0, -0x100000000, Math.PI, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 0x07fffffff, 0x100000001, 2**53+2, 0, 1/0, 0x100000000, Number.MAX_VALUE, 42, -(2**53), -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, -0, -0x080000001, 2**53, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1318; tryItOut("mathy5 = (function(x, y) { return (mathy2(( + (Math.cosh((Math.min(Math.atan2(Math.fround(( + Math.fround(0))), (Math.pow(( ! x), (x | 0)) | 0)), (x % ( + 1/0))) >>> 0)) >>> 0)), ( + ((Math.pow((mathy1((Math.fround(x) === x), Math.min((42 && y), ( + (((x | 0) && (-0x080000000 | 0)) | 0)))) >>> 0), (Math.exp(0x0ffffffff) >>> 0)) >>> 0) !== (Math.sign(y) / Math.expm1(y))))) >>> 0); }); ");
/*fuzzSeed-85495475*/count=1319; tryItOut("/*ADP-1*/Object.defineProperty(a2, Math.atan2(17, -18), ({configurable: true, enumerable: true}));");
/*fuzzSeed-85495475*/count=1320; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x100000001, -(2**53-2), -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), 1, 0.000000000000001, 0x080000000, Number.MAX_VALUE, Math.PI, -0x0ffffffff, 2**53+2, -(2**53), 0x080000001, 0, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, 1/0, 2**53-2, 0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, 42, 0x07fffffff, 0x0ffffffff, 0/0]); ");
/*fuzzSeed-85495475*/count=1321; tryItOut("\"use strict\"; h0.getOwnPropertyNames = (function mcc_() { var fwkwob = 0; return function() { ++fwkwob; f2(fwkwob > 4);};})();");
/*fuzzSeed-85495475*/count=1322; tryItOut("\"use strict\"; const z = [[[1]]];print(z);");
/*fuzzSeed-85495475*/count=1323; tryItOut("\"use strict\"; m2.delete(o1);");
/*fuzzSeed-85495475*/count=1324; tryItOut("/*infloop*/ for (var this.zzz.zzz of window) {false; }");
/*fuzzSeed-85495475*/count=1325; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return (Math.cbrt((Math.cbrt(( + ( ~ (-1/0 >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy1, [NaN, '\\0', '', null, 0.1, ({toString:function(){return '0';}}), '0', (new Boolean(false)), -0, (new Boolean(true)), (new Number(-0)), (new Number(0)), [0], ({valueOf:function(){return 0;}}), true, (new String('')), '/0/', [], /0/, 0, objectEmulatingUndefined(), false, ({valueOf:function(){return '0';}}), undefined, 1, (function(){return 0;})]); ");
/*fuzzSeed-85495475*/count=1326; tryItOut("mathy5 = (function(x, y) { return ( + Math.imul(( + (Math.fround((0x080000000 + (y >>> 0))) === ( + (( ~ Math.sinh(y)) % y)))), ( + ( + (( + Math.pow(( + (( ~ (y >>> 0)) % ( + y))), (mathy4(y, Math.fround((Math.asin(( + y)) | 0))) / y))) ? Math.log2(Math.min(x, Math.max(( + (Math.tan((-0x0ffffffff | 0)) | 0)), Math.fround(Math.tan((Math.clz32((x >>> 0)) >>> 0)))))) : ( + (Math.expm1(mathy2(y, Math.fround(( ~ Math.fround(y))))) >>> 0))))))); }); testMathyFunction(mathy5, [0x100000000, 42, 1, 0, Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, -(2**53-2), 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -0, -0x0ffffffff, 0/0, 2**53-2, -Number.MAX_VALUE, -0x080000001, -0x100000001, 2**53+2, -Number.MIN_VALUE, -1/0, 1.7976931348623157e308, 0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, 1/0, 2**53, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=1327; tryItOut("void (Object.defineProperty(c, \"0\", ({})));");
/*fuzzSeed-85495475*/count=1328; tryItOut("\"use strict\"; this.h1 = {};");
/*fuzzSeed-85495475*/count=1329; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + ( - ( + Math.fround(Math.min(((( ~ ((Math.atan(Math.fround(( ~ (Math.cbrt(x) | 0)))) >>> 0) >>> 0)) >>> 0) | 0), Math.fround(Math.cosh((y == Number.MAX_VALUE)))))))) ? Math.atan2(Math.fround(Math.log(x)), ( ! (y >>> 0))) : ( + Math.imul(Math.clz32(( ~ ( ! y))), ( ! Math.fround((( - y) >>> 0)))))); }); testMathyFunction(mathy5, [-0, -(2**53-2), -0x080000000, -0x100000001, 0x100000001, 0x080000000, 1.7976931348623157e308, -1/0, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 42, -0x080000001, 1, 0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, 0x080000001, -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, 0, -(2**53+2), 2**53+2, 0/0]); ");
/*fuzzSeed-85495475*/count=1330; tryItOut("\"use strict\"; h0.get = (function(j) { if (j) { a0.__proto__ = a1; } else { try { m1.set(o1, g1.b1); } catch(e0) { } try { h2.getOwnPropertyNames = f2; } catch(e1) { } try { e0.has(i1); } catch(e2) { } a1 = encodeURIComponent; } });");
/*fuzzSeed-85495475*/count=1331; tryItOut("t1[3];");
/*fuzzSeed-85495475*/count=1332; tryItOut("o1.v1 = Object.prototype.isPrototypeOf.call(o0, g1);");
/*fuzzSeed-85495475*/count=1333; tryItOut("let NaN =  '' , htbgyn, eval, z =  /x/ , wsppql, x = (void options('strict')), diofdo, oqyxuj, ezciso, b;with(arguments){for (var v of p2) { try { o1.g1 + ''; } catch(e0) { } try { f2(m2); } catch(e1) { } try { v2 = this.g1.runOffThreadScript(); } catch(e2) { } t1 = new Uint16Array(b0); }print(x); }");
/*fuzzSeed-85495475*/count=1334; tryItOut("/*bLoop*/for (let oylvio = 0; oylvio < 7; ++oylvio) { if (oylvio % 6 == 3) { L: {e0.has(o2.g0.g1); } } else { b2.__proto__ = t2; }  } \n/*RXUB*/var r = new RegExp(\"\\\\1+(?=(.{1,})+)?\", \"m\"); var s = \"\"; print(s.replace(r, function(q) { \"use asm\"; return q; })); \n");
/*fuzzSeed-85495475*/count=1335; tryItOut("mathy5 = (function(x, y) { return Math.ceil((mathy4(Math.pow((( + (y >>> 0)) >>> 0), x), (((( + Math.abs(0.000000000000001)) | 0) || (y | 0)) | 0)) !== (( + mathy3((0x0ffffffff | 0), ( ! y))) < ((Math.hypot(x, y) | Math.cos(x)) | 0)))); }); testMathyFunction(mathy5, [true, NaN, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), objectEmulatingUndefined(), 1, (new Number(0)), '', false, ({valueOf:function(){return 0;}}), [], undefined, (function(){return 0;}), null, 0.1, (new Boolean(true)), -0, '\\0', [0], (new Boolean(false)), '0', /0/, (new String('')), (new Number(-0)), 0, '/0/']); ");
/*fuzzSeed-85495475*/count=1336; tryItOut("\"use strict\"; v1 = (m2 instanceof v1);");
/*fuzzSeed-85495475*/count=1337; tryItOut("testMathyFunction(mathy0, [-0x100000000, -0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, 1, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -(2**53-2), 0x080000001, 0/0, 2**53, 0x0ffffffff, 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -Number.MAX_VALUE, 0, Math.PI, -Number.MIN_VALUE, -0x080000001, 0x080000000, 42, -1/0, -0, Number.MAX_VALUE, 2**53+2, -0x07fffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-85495475*/count=1338; tryItOut("undefined;\na1.shift();\n\ns0 += s0;\n");
/*fuzzSeed-85495475*/count=1339; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1340; tryItOut("selectforgc(o2);");
/*fuzzSeed-85495475*/count=1341; tryItOut("mathy4 = (function(x, y) { return (mathy1((Math.fround(Math.sinh(Math.ceil(mathy0(mathy1(x, 0x100000001), 0)))) >>> 0), (Math.ceil(Math.fround((Math.max((y | 0), ( + (Math.expm1((y | 0)) | 0))) | 0))) | 0)) >>> 0); }); ");
/*fuzzSeed-85495475*/count=1342; tryItOut("print((yield x = yield a));");
/*fuzzSeed-85495475*/count=1343; tryItOut("\"use strict\"; g0.g1.m1.has(g0);");
/*fuzzSeed-85495475*/count=1344; tryItOut("print(Object(eval(\"{}\")\n));v2 = Object.prototype.isPrototypeOf.call(t1, o0);let y = x;");
/*fuzzSeed-85495475*/count=1345; tryItOut("h2.hasOwn = f1;");
/*fuzzSeed-85495475*/count=1346; tryItOut("mathy1 = (function(x, y) { return (Math.tanh(((( + Math.asinh(( + Math.max(y, Math.pow(y, y))))) - ( - ( + y))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-(2**53+2), -1/0, 1.7976931348623157e308, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 2**53-2, -0x080000001, -0, Number.MAX_VALUE, 1, -0x100000001, -0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -0x080000000, 0.000000000000001, 0x080000000, -(2**53-2), 0, 0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), 0x0ffffffff, 2**53+2, 2**53, -0x0ffffffff, 42, -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=1347; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-85495475*/count=1348; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = (0xfa83b7d2);\n    return +((d0));\n  }\n  return f; })(this, {ff: function  x (SimpleObject.length, [])\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 8796093022208.0;\n    var i3 = 0;\n    var i4 = 0;\n    return ((((((-0x8000000)+(i3)+(i1)) << ((i4)-(i1))))-(i3)))|0;\n  }\n  return f;}, new ArrayBuffer(4096)); ");
/*fuzzSeed-85495475*/count=1349; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(m2, \"some\", ({value: [(eval(\"/* no regression tests found */\"))]}));");
/*fuzzSeed-85495475*/count=1350; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.log2(( ~ mathy0(y, x))) ^ (((((y ? (Math.max(( ! (y | 0)), (y | 0)) >>> 0) : (Math.hypot((x | 0), (-0x080000001 | 0)) | 0)) >>> 0) | 0) !== (( + (( + (Math.asin(mathy0(y, -0x100000000)) >>> 0)) ? ( + -Number.MIN_SAFE_INTEGER) : ( + ( + Math.trunc((Math.min(x, y) | 0)))))) | 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[ '' ,  '' , -0, -0, -0, -0,  '' ,  '' , -0,  '' , -0, -0,  '' ,  '' ,  '' ,  '' , -0,  '' ,  '' , -0, -0, -0, -0, -0,  '' ]); ");
/*fuzzSeed-85495475*/count=1351; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ( - Math.abs(( + (( + (( + Math.imul(x, x)) | 0)) > ( + Math.min(Math.fround(Math.tan(( + Math.log(Math.fround(x))))), y))))))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, -Number.MIN_VALUE, -Number.MIN_VALUE, function(){}, new String('q'), -Number.MIN_VALUE, new String('q'), -Number.MIN_VALUE, new String('q'), new String('q'), -Number.MIN_VALUE, function(){}, -Number.MIN_VALUE, function(){}, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, function(){}, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, function(){}, new String('q'), new String('q'), function(){}, -Number.MIN_VALUE, new String('q'), new String('q'), -Number.MIN_VALUE, new String('q'), function(){}, function(){}, function(){}, new String('q'), -Number.MIN_VALUE, function(){}, function(){}, function(){}, -Number.MIN_VALUE, function(){}, function(){}, new String('q')]); ");
/*fuzzSeed-85495475*/count=1352; tryItOut("\"use strict\"; (arguments);(new RegExp(\"(?!\\\\W\\\\x37+?\\\\w*|.+^*)+\", \"im\"));");
/*fuzzSeed-85495475*/count=1353; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, Math.PI, 0.000000000000001, 0x080000000, 42, 1, 2**53-2, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, 0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, -(2**53-2), -0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), -(2**53), -0, Number.MAX_VALUE, 2**53, 0, -Number.MAX_VALUE, -1/0, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=1354; tryItOut("mathy1 = (function(x, y) { return mathy0((((Math.hypot((( + ( - ( + x))) >>> 0), (Math.min((x >>> 0), (( + (( + x) , ( + -0x0ffffffff))) >>> 0)) >>> 0)) >>> 0) <= ( + (( + ( + Math.acosh(( + y)))) , ( + Math.atan2(x, ( + ((Math.fround((Math.fround(mathy0((y | 0), -(2**53))) / Math.fround(-(2**53-2)))) | 0) - (Math.asin((y | 0)) | 0)))))))) >>> 0), (( ! ( - (( + (( + Math.round(0/0)) ? 0.000000000000001 : ( + x))) >>> 0))) >>> 0)); }); testMathyFunction(mathy1, [2**53+2, Math.PI, 2**53, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -0, -0x080000000, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 1.7976931348623157e308, -(2**53-2), 0x100000001, -0x100000001, 2**53-2, 1, 0/0, -(2**53), 0x0ffffffff, -0x080000001, 0x080000000, 0x100000000, -0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-85495475*/count=1355; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 18014398509481984.0;\n    d1 = (NaN);\n    {\n      (Float64ArrayView[((0x676496f9)+(0xffffffff)+((0x53fb7d17))) >> 3]) = ((d1));\n    }\n    return +((Float64ArrayView[1]));\n  }\n  return f; })(this, {ff: (function(id) { return id }).apply}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0.000000000000001, 42, 0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0x080000001, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53, 0x100000001, 0/0, -0x100000001, 0x100000000, Number.MIN_VALUE, -0, -1/0, 0, 1/0, -0x100000000, 0x07fffffff, 2**53+2, 1, -0x07fffffff]); ");
/*fuzzSeed-85495475*/count=1356; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?![^]|\\D+|\\S|[^\\S\\S\\u5E87-\\u16f9]*(?!\\B+)))|(?:\\1{3,7}|[^\\\uacba\\w]*?|[^]|.?\\S+?)./i; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-85495475*/count=1357; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1358; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1359; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + mathy1(Math.fround(Math.sign(Math.fround(((4277), 'fafafa'.replace(/a/g, function(y) { \"use strict\"; a0.push(t2); }) <= Math.expm1((( - mathy0(( + y), x)) >>> 0)))))), ( + (Math.fround((Math.fround(( - Math.fround(x))) ? Math.fround(( + Math.acosh(( + ( ~ x))))) : Math.fround(Math.fround(( ~ Math.fround(y)))))) ^ ( + ( - Math.fround(Math.tanh(( ! x))))))))); }); ");
/*fuzzSeed-85495475*/count=1360; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?=(?=\\\\D{3}|^++?)(?![^]*?){3}+?)){0,3}\", \"m\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=1361; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (/*FFI*/ff(((+(-1.0/0.0))), ((((((((0xffffffff)) >> ((0x5e8695a3)))) ? (0xb73bf2f4) : ((((0xff082671)) & ((0x583baed7)))))+(0xe6ba3728)) << ((0x7784e3d3)+(!(!((0xe5db3546) ? (0x9ec365e5) : (0xb4ddaf03))))))), ((abs(((((-3.8685626227668134e+25) <= (+((-128.0))))*0x34dd8)|0))|0)), ((((Uint16ArrayView[0])) ^ ((i1)+((0xde485612))))))|0);\n    return +((+(((((((0xffffffff))>>>((0xa00bc724))) / (((0xf86f07c0))>>>((0x4c79f39a)))) ^ (((0xb61c07dc) < (0xc92c37f8))-((-0x3a856e5) > (0x38078b1f)))) % ((((((0x23d8aecb)) | ((0x8c9548ca))))-(/*FFI*/ff()|0))|0)) ^ ((0xdc2659ff)))));\n  }\n  return f; })(this, {ff: (/*MARR*/[ /x/ , true, function(){}, function(){}, true,  /x/ ,  \"use strict\" , arguments.caller, true,  /x/ ,  \"use strict\" , true,  \"use strict\" ,  /x/ ,  /x/ ,  /x/ , arguments.caller,  \"use strict\" , arguments.caller, true,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/ , true, function(){}, arguments.caller].map(d =>  { \"use strict\"; yield  /x/g  } ).eval(\"/* no regression tests found */\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-85495475*/count=1362; tryItOut("with({}) { ( /x/g ); } ");
/*fuzzSeed-85495475*/count=1363; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - ( + (mathy0((( ! (-0x080000001 >>> 0)) | 0), (Math.ceil(Math.asinh((x | 0))) | 0)) | 0))); }); ");
/*fuzzSeed-85495475*/count=1364; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(this.i0, \"callee\", { configurable:  /x/g .eval(\"/* no regression tests found */\"), enumerable: (x % 28 == 19), get: (function() { try { a1 = arguments.callee.arguments; } catch(e0) { } try { v0 = g1.runOffThreadScript(); } catch(e1) { } Object.defineProperty(o0, \"v0\", { configurable: false, enumerable: true,  get: function() {  return a2.length; } }); return t2; }), set: Uint16Array.bind(p2) });");
/*fuzzSeed-85495475*/count=1365; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.max(( + Math.atanh((Math.sinh(Math.fround(( + (Math.fround(Math.pow(Math.fround(( + Math.sinh(y))), Math.fround(x))) ? ( + 0x07fffffff) : ( + x))))) >>> 0))), Math.pow(((Math.ceil(Math.fround(mathy3((((y | 0) ? (( + (( + y) && -1/0)) | 0) : y) >>> 0), ( + Math.min(Number.MIN_SAFE_INTEGER, ( + 0x080000001)))))) | 0) >>> 0), ((Math.cos(((Math.atan2((y | 0), (Math.fround(Math.acosh(( + Math.min(y, x)))) | 0)) | 0) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), {}, x, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, {}, {}, x, x, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, {}, objectEmulatingUndefined(), x, objectEmulatingUndefined(), {}, {}, {}, x, x, objectEmulatingUndefined(), x, {}, x, {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, x, objectEmulatingUndefined(), {}]); ");
/*fuzzSeed-85495475*/count=1366; tryItOut("\"use strict\"; /*RXUB*/var r = /(?![^])/gym; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=1367; tryItOut("\"use strict\"; \"use asm\"; g1.h0.keys = (function() { try { Object.preventExtensions(o0.m2); } catch(e0) { } try { g0.v1 = evaluate(\"function f1(b2)  { v1 = t0.length; } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 14 != 10), noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 2 == 0) })); } catch(e1) { } try { Object.prototype.unwatch.call(i0, \"setUTCFullYear\"); } catch(e2) { } a2 = new Array; return b1; });");
/*fuzzSeed-85495475*/count=1368; tryItOut("\"use strict\"; const s2 = s0.charAt(this.__defineGetter__(\"\\u3056\", Math.sign));");
/*fuzzSeed-85495475*/count=1369; tryItOut("\"use strict\"; x = x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: undefined, fix: function() { throw 3; }, has: (/*wrap3*/(function(){ var vqynum =  /x/g ; ((function(y) { \"use strict\"; return; }).call)(); })).apply, hasOwn: function() { throw 3; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: false, }; })( /x/g ), 3), eval = (/*MARR*/[-Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53+2), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53+2)].sort);t0 = new Int16Array(a2);");
/*fuzzSeed-85495475*/count=1370; tryItOut(" '' .watch(\"bold\", eval);");
/*fuzzSeed-85495475*/count=1371; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1372; tryItOut("Object.prototype.unwatch.call(e2, \"wrappedJSObject\");");
/*fuzzSeed-85495475*/count=1373; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( + (mathy0((Math.expm1((x >>> 0)) | 0), (Math.min(Number.MAX_SAFE_INTEGER, (Math.atanh((((( + y) ? (Math.min(y, x) | 0) : (x >>> 0)) | 0) | 0)) | 0)) | 0)) | 0)) | 0) ? Math.sin((( + ( + (Math.imul(mathy2((0x080000000 != y), x), (y >>> 0)) >>> 0))) , (Math.log10((Math.cos(1/0) >>> 0)) | 0))) : (Math.asinh(( + (Math.atan2(((mathy0(( + mathy1(( + ( - y)), Math.fround(Math.log10((y | 0))))), Math.fround(Math.expm1(Math.imul(y, x)))) >>> 0) | 0), ((x + (y > Math.fround(mathy2(x, y)))) | 0)) | 0))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), -Infinity, -Infinity, -Infinity, -Infinity]); ");
/*fuzzSeed-85495475*/count=1374; tryItOut("e2.has(e2);");
/*fuzzSeed-85495475*/count=1375; tryItOut("for (var p in m0) { try { g2.s0 += 'x'; } catch(e0) { } try { g0.offThreadCompileScript(\"o1.v0 = b0.byteLength;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 5 == 4), noScriptRval: (x % 79 != 12), sourceIsLazy: true, catchTermination: true, element: o0, elementAttributeName: s2 })); } catch(e1) { } selectforgc(o0); }");
/*fuzzSeed-85495475*/count=1376; tryItOut("print(x);break ;");
/*fuzzSeed-85495475*/count=1377; tryItOut("b1 = x;");
/*fuzzSeed-85495475*/count=1378; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.clz32(Math.imul((mathy1((( ~ y) | 0), (0.000000000000001 | 0)) | 0), (((mathy0(1, (Math.fround(Math.log2(x)) | 0)) & Math.fround((Math.fround((Math.atan2(x, (x >>> 0)) >>> 0)) ^ (x | 0)))) >>> 0) | 0))); }); ");
/*fuzzSeed-85495475*/count=1379; tryItOut("\"use strict\"; Object.freeze(f1);o0.e1.add(b1);");
/*fuzzSeed-85495475*/count=1380; tryItOut("\"use strict\"; a2.push(e0, e0, ((makeFinalizeObserver('nursery'))))\n");
/*fuzzSeed-85495475*/count=1381; tryItOut("v1 = new Number(-Infinity);\no1.m0.has(b0);\n");
/*fuzzSeed-85495475*/count=1382; tryItOut("for (var p in a0) { try { for (var p in f2) { v2 = g1.objectEmulatingUndefined(); } } catch(e0) { } try { let v1 = g1.runOffThreadScript(); } catch(e1) { } v0 = Object.prototype.isPrototypeOf.call(m0, a1); }");
/*fuzzSeed-85495475*/count=1383; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.fround(Math.fround(( + Math.log2(( + ( - 0x07fffffff))))))); }); testMathyFunction(mathy2, [-0x080000001, -(2**53), 1.7976931348623157e308, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, 1/0, 0, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, -0x0ffffffff, -0, Number.MAX_SAFE_INTEGER, Math.PI, 0/0, 42, 0x100000001, 1, 0x080000000, Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, -0x100000001, 2**53-2, -1/0, 2**53, -Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=1384; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.fround(((Math.ceil((( ~ (( ! x) | 0)) | 0)) | 0) != (( + ( ! Math.fround(x))) + Math.hypot(x, ( + (Number.MIN_VALUE | 0)))))) ? ( + Math.pow((Math.cos((( + (Number.MAX_VALUE * (Math.atan(x) | 0))) >>> 0)) >>> 0), (( - ((x | (0x07fffffff >>> 0)) >>> 0)) | 0))) : ( + ((( ~ x) | 0) < ( ! (Math.pow((( + y) | 0), ( + (( ~ (( + ( + ( + Math.abs(( + x))))) | 0)) | 0))) | 0))))); }); testMathyFunction(mathy0, /*MARR*/[new String(''), NaN, NaN, NaN, new String(''), new String(''), new String(''), NaN, new String(''), NaN, NaN, new String(''), NaN, NaN, NaN, NaN, new String(''), NaN, new String(''), NaN, NaN, NaN, NaN, new String(''), new String(''), new String(''), NaN, NaN, new String(''), NaN, new String(''), NaN, NaN, NaN, new String(''), new String(''), NaN, NaN, new String(''), NaN, new String(''), new String('')]); ");
/*fuzzSeed-85495475*/count=1385; tryItOut("for(let x in (24.eval(\"mathy5 = (function(x, y) { return mathy0(Math.atan2((Math.hypot((x || Math.fround(Math.max(Math.fround(y), Math.fround(y)))), (Number.MIN_VALUE ? ( + Math.hypot(( + (x ? ( + -0x100000001) : ( + (((y | 0) >>> (x | 0)) | 0)))), x)) : Math.imul(x, Math.fround((Math.fround(x) || Math.fround(y)))))) >>> 0), mathy1(( ! Math.fround(mathy0(Math.fround(0/0), (x >>> 0)))), ( + ( - ( + ((x >>> 0) >= y)))))), ( - (Math.fround(Math.exp(1/0)) ? Math.log10(y) : ( + (Math.max((mathy4(Number.MAX_SAFE_INTEGER, Math.acos(x)) >>> 0), (Math.asin(Math.fround(Math.cosh(x))) >>> 0)) >>> 0))))); }); \") if (((function sum_indexing(pokxat, wdtwmu) { ; return pokxat.length == wdtwmu ? 0 : pokxat[wdtwmu] + sum_indexing(pokxat, wdtwmu + 1); })(/*MARR*/[(0/0),  /x/g ,  /x/g , (0/0), (0/0),  /x/g ,  /x/g ,  /x/g ], 0))))) return ({} = Object.defineProperty(x, \"getYear\", ({configurable:  /x/g })));return (4277);");
/*fuzzSeed-85495475*/count=1386; tryItOut("o2.toSource = f0;");
/*fuzzSeed-85495475*/count=1387; tryItOut("mathy2 = (function(x, y) { return Math.min(Math.cos(((Math.pow(((Math.atan((( + Math.min(x, x)) >>> 0)) >>> 0) >>> 0), ( - mathy0(( + (Math.imul(Math.ceil(-0x080000000), x) >>> 0)), Math.asin(-0x100000001)))) >>> 0) | 0)), ( ~ (Math.atan(((y ** ( + x)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [0x07fffffff, -Number.MAX_VALUE, 0x100000000, 0x080000000, -0x080000000, -0x080000001, -0x0ffffffff, Number.MIN_VALUE, 0/0, 0x0ffffffff, -0x100000000, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), 1.7976931348623157e308, 42, -(2**53-2), 0x080000001, 1, -Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, 2**53, 0, -(2**53), 0.000000000000001, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, Math.PI]); ");
/*fuzzSeed-85495475*/count=1388; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\B)+|\\2{4,6}*?[^]/m; var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-85495475*/count=1389; tryItOut("Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-85495475*/count=1390; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return (((( ~ ( + (Math.expm1((Math.max((y >>> 0), ((x && 1) | 0)) >>> 0)) | 0))) >>> 0) , (( ! (Math.imul(y, ( + (-1/0 % x))) > x)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0, -0x080000001, 1.7976931348623157e308, 2**53+2, -(2**53-2), 0x080000000, Math.PI, 0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, 0.000000000000001, 2**53, -(2**53), -0x100000000, 1/0, 0x0ffffffff, -0x100000001, 0x100000001, 42, 0x100000000, 2**53-2]); ");
/*fuzzSeed-85495475*/count=1391; tryItOut("function shapeyConstructor(xiqkuz){this[\"slice\"] = \"\\uA1A9\";return this; }/*tLoopC*/for (let d of /*MARR*/[[],  \"use strict\" ,  \"use strict\" , NaN, [],  \"use strict\" ,  '\\0' , NaN,  \"use strict\" ,  '\\0' ,  \"use strict\" ,  '\\0' ,  \"use strict\" , [],  \"use strict\" , NaN,  \"use strict\" ,  '\\0' ,  \"use strict\" ]) { try{let dcxile = shapeyConstructor(d); print('EETT'); yield  '' ;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-85495475*/count=1392; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.imul(( + ( + Math.sin(((Math.cbrt((Math.max((Math.fround(( ~ Math.fround(( + Math.acosh(( + mathy1(x, x))))))) | 0), Math.fround((y & y))) | 0)) | 0) | 0)))), (Math.abs((( - ((x % x) / ((mathy4((Number.MAX_VALUE >>> 0), (Math.fround(Math.hypot((( + y) >>> 0), (y >>> 0))) >>> 0)) >>> 0) >>> 0))) | 0)) >>> 0)); }); testMathyFunction(mathy5, [0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, 2**53+2, -(2**53), -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 0, -0, -0x080000001, -0x07fffffff, 1/0, 1.7976931348623157e308, 1, -(2**53+2), -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, 42, 0/0, 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, -1/0, Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-85495475*/count=1393; tryItOut("\"use strict\"; e = x;( /x/g )(false) = y;e = ( ''  <= (4277));");
/*fuzzSeed-85495475*/count=1394; tryItOut("mathy5 = (function(x, y) { return ( + ( - (Math.clz32((( - (Math.round(Math.atan(( + 0x080000001))) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy5, [-1/0, 0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, -0, 2**53, Number.MAX_VALUE, -0x100000001, 0x100000000, 0x07fffffff, -0x080000000, 2**53-2, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, Math.PI, -(2**53), 1.7976931348623157e308, -(2**53-2), 0, 0x0ffffffff, -0x0ffffffff, 1, Number.MIN_VALUE, 1/0, -(2**53+2), -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1395; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min(mathy2(Math.fround(Math.fround(Math.atan2(Math.fround(y), Math.fround((Math.asinh((( + (( + -(2**53+2)) >>> ( + x))) >>> 0)) >>> 0))))), mathy2(( + Math.fround(Math.fround(( ! Math.fround(x))))), ( + Math.trunc(Math.fround(mathy0(Math.fround(-Number.MAX_VALUE), Math.fround(x))))))), Math.tanh(Math.min((Math.sin((((y >>> 0) , ( + mathy0(x, ( + Math.atan(Math.fround(-(2**53+2))))))) >>> 0)) | 0), ( + Math.cbrt(mathy1(0x080000000, x)))))); }); testMathyFunction(mathy3, [(new Boolean(true)), '0', '/0/', objectEmulatingUndefined(), (new String('')), NaN, '\\0', (new Boolean(false)), (new Number(0)), [], (new Number(-0)), true, 0, null, ({toString:function(){return '0';}}), -0, /0/, undefined, ({valueOf:function(){return 0;}}), 0.1, 1, [0], '', (function(){return 0;}), false, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-85495475*/count=1396; tryItOut("Array.prototype.shift.call(a0, e0);");
/*fuzzSeed-85495475*/count=1397; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-85495475*/count=1398; tryItOut("\"use strict\"; v2 = evalcx(\"mathy3 = (function(x, y) { \\\"use strict\\\"; return Math.fround(( ~ Math.fround(Math.imul((Math.log10(Math.fround((Math.imul(1/0, y) >>> 0))) >>> 0), ((((Math.imul((( - x) ? y : y), (x | 0)) >>> 0) ? (Math.atanh(y) >>> 0) : (y >>> 0)) >>> 0) >>> 0))))); }); testMathyFunction(mathy3, [0x080000001, -0x0ffffffff, 2**53+2, 0.000000000000001, 0x07fffffff, 42, -1/0, 0x100000001, -Number.MIN_VALUE, -(2**53), 1, 0x100000000, -(2**53-2), 0x080000000, -Number.MAX_VALUE, 0, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, 0/0, -0x100000000, -0x07fffffff, 0x0ffffffff, 1/0, -0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000001]); \", this.g0);");
/*fuzzSeed-85495475*/count=1399; tryItOut("m2 = new Map;");
/*fuzzSeed-85495475*/count=1400; tryItOut("var fyaxhs = new SharedArrayBuffer(2); var fyaxhs_0 = new Uint32Array(fyaxhs); print(fyaxhs_0[0]); delete this.t2[\"keys\"];v1 = evalcx(\"v1 = a2.length;\", g1);");
/*fuzzSeed-85495475*/count=1401; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"Array.prototype.push.apply(o2.a1, [x | x, t0, this.o1, x]);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 114 != 56), noScriptRval: true, sourceIsLazy: x, catchTermination: [,,] }));");
/*fuzzSeed-85495475*/count=1402; tryItOut("testMathyFunction(mathy0, [0x100000001, 0x080000000, 1/0, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, 0x080000001, Math.PI, 2**53, Number.MIN_SAFE_INTEGER, 1, -(2**53+2), 0, Number.MAX_VALUE, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), 42, 0.000000000000001, Number.MIN_VALUE, -0x100000001, -0, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0x0ffffffff, -0x080000000, -(2**53), 0x07fffffff, 2**53-2]); ");
/*fuzzSeed-85495475*/count=1403; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-85495475*/count=1404; tryItOut("/*infloop*/for(var c = new RegExp(\"\\\\w+(?:$|[^-\\u3c69\\\\d\\\\x78-\\\\xD9]*|${2,5})\\\\b|\\\\1{0}|\\\\b\\\\b+?|\\\\s\", \"yi\"); (b = (let (x = this.x) x)); (void shapeOf(let (w =  '' ) function ([y]) { })) === ( + ( + ( + x)))) {const window = (4277), yield = delete (c =  /x/ ), c, c = (4277), \u3056 = new RegExp(\"(?=(?=\\\\d)+?){17179869183}|[^]{0}\", \"gy\"), w = window.yoyo(false), aplyir;t1 + '';y = ((4277) ? (x = eval * this) : (window >>>=  \"\" )( /x/  >>>= [1], /\\3([\\cD\uac45\\B\\x56-\\u005A]|^)\\3(.)|(?:(?=(?!\\1)))/yim)); }");
/*fuzzSeed-85495475*/count=1405; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1406; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (mathy0(Math.fround(( + (( + (Math.pow(x, Math.min((y >> mathy0(x, -Number.MAX_SAFE_INTEGER)), ( + y))) ? (x ? x : x) : x)) ** (mathy0((((( + Math.atan(( + ( + Math.fround(Math.fround(x)))))) % x) >>> 0) >>> 0), ( + Math.pow(Number.MAX_VALUE, ((((mathy0(x, (y >>> 0)) >>> 0) | 0) * (y | 0)) | 0)))) >>> 0)))), (( + (( + ( + Math.hypot(( + ( + Math.trunc((( + ( + Math.log10(x))) | 0)))), ( + Math.fround(Math.min(Math.fround(-Number.MAX_VALUE), Math.fround(x))))))) < (Math.sign((Math.acosh(y) | 0)) | 0))) | 0)) | 0); }); testMathyFunction(mathy1, [undefined, objectEmulatingUndefined(), NaN, true, 0, '0', (new String('')), /0/, 0.1, '', '/0/', '\\0', false, 1, (new Number(-0)), (function(){return 0;}), (new Boolean(true)), ({valueOf:function(){return 0;}}), -0, [], [0], null, (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-85495475*/count=1407; tryItOut("mathy3 = (function(x, y) { return ( + Math.atan2(( + ( ~ (( + Math.cosh(( + Math.asin(Math.fround(( ~ y)))))) < mathy1(( + (x | 0)), (( + x) * (y >>> 0)))))), Math.exp(Math.log(Math.pow((Math.fround(x) !== y), Math.imul(mathy0(x, (x >>> 0)), -1/0)))))); }); testMathyFunction(mathy3, [1, 0.000000000000001, 42, -0x07fffffff, 0x0ffffffff, -0x100000000, 1/0, Number.MIN_VALUE, -0x080000001, 2**53, -Number.MAX_VALUE, -(2**53-2), 2**53-2, 1.7976931348623157e308, -0x080000000, -(2**53), 0x080000000, -Number.MIN_VALUE, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), Number.MAX_VALUE, 0x100000001, -0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, -1/0, 0x080000001, 0, -0, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1408; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var atan = stdlib.Math.atan;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x652cde77)+((+(-1.0/0.0)) > (d1))))|0;\n    d0 = (+((d1)));\n    d1 = (Infinity);\n    {\n      (Float32ArrayView[(((((0xfcf2efe1)*-0x32074) ^ (((0x1a28f427) != (0x457f252f))+(0x35171f29)-(0x82db3876))))) >> 2]) = ((+(~((0x5068d832)-(/*FFI*/ff(((+(abs((~~((0xffffffff) ? (-1073741825.0) : (4194305.0))))|0))), ((+atan(((d1))))), ((d0)), ((((d0)) % ((+(0.0/0.0))))))|0)))));\n    }\n    d1 = (d0);\n    d0 = (+(imul((0xf87bcedc), (0xfa89d631))|0));\n    d0 = (+((((+(((0xfd32c19f)) << ((0x2a65a0ab)))) >= (d0))+(0xff50d144)+((d1) <= (d1)))>>>((0x6baff638)+(!(0x6cba74b3)))));\n    return (((!(0x6c157532))-((d1) < (3.094850098213451e+26))-(0x34c021d4)))|0;\n  }\n  return f; })(this, {ff: String.prototype.localeCompare}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x080000001, -Number.MIN_VALUE, 1/0, 1.7976931348623157e308, -0x07fffffff, -0x080000000, -(2**53), 2**53-2, -0x100000001, 0x0ffffffff, -0x100000000, -0, 2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 1, -(2**53-2), Math.PI, 0.000000000000001, 0, 0x100000000, -0x0ffffffff, 42, -1/0, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-85495475*/count=1409; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + ((( + (( + ( + ( - ((Math.fround(x) && x) + y)))) + Math.fround((( - mathy0(x, Math.min(Math.fround(y), x))) ? y : ((x >>> 0) === y))))) | 0) | 0)) | 0); }); testMathyFunction(mathy1, [1, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, Number.MAX_VALUE, -0x100000001, -0x100000000, -(2**53-2), Math.PI, 0/0, 42, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, 0.000000000000001, 0x07fffffff, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, -0x080000001, -(2**53), 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, -(2**53+2), 0, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=1410; tryItOut("t1.toSource = (function mcc_() { var jkksjf = 0; return function() { ++jkksjf; if (true) { dumpln('hit!'); try { s0 += s1; } catch(e0) { } try { o2.t1[ /* Comment */x]; } catch(e1) { } h2 = ({getOwnPropertyDescriptor: function(name) { f0 = t1[11];; var desc = Object.getOwnPropertyDescriptor(b1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return e0; var desc = Object.getPropertyDescriptor(b1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a0.forEach((function() { try { i1.next(); } catch(e0) { } try { this.g1.g0.g0.s1 += s0; } catch(e1) { } /*MXX3*/g2.Date.prototype.getDate = g0.Date.prototype.getDate; return e2; }));; Object.defineProperty(b1, name, desc); }, getOwnPropertyNames: function() { p2 + '';; return Object.getOwnPropertyNames(b1); }, delete: function(name) { a1.splice(NaN, print(x);, o1.g1.e1);; return delete b1[name]; }, fix: function() { s1 += 'x';; if (Object.isFrozen(b1)) { return Object.getOwnProperties(b1); } }, has: function(name) { i0.send(g0);; return name in b1; }, hasOwn: function(name) { throw t2; return Object.prototype.hasOwnProperty.call(b1, name); }, get: function(receiver, name) { e0 + o0.g0.o1;; return b1[name]; }, set: function(receiver, name, val) { a0.push(v2);; b1[name] = val; return true; }, iterate: function() { Object.defineProperty(o2, \"v0\", { configurable: true, enumerable: true,  get: function() {  return t2.byteLength; } });; return (function() { for (var name in b1) { yield name; } })(); }, enumerate: function() { throw i1; var result = []; for (var name in b1) { result.push(name); }; return result; }, keys: function() { Array.prototype.push.apply(a2, [g1.g2]);; return Object.keys(b1); } }); } else { dumpln('miss!'); try { o1 = new Object; } catch(e0) { } try { t2 = new Uint8ClampedArray(11); } catch(e1) { } p0.toSource = Array.prototype.unshift.bind(h2); } };})();");
/*fuzzSeed-85495475*/count=1411; tryItOut("g1.o2.o1.a1.sort((function(j) { if (j) { try { t0 = new Uint8ClampedArray(5); } catch(e0) { } s1 = s1.charAt(this.__defineSetter__(\"c\", RegExp.prototype.test)); } else { try { /*ADP-3*/Object.defineProperty(a0, 14, { configurable: (x % 4 != 0), enumerable: true, writable: x, value: h1 }); } catch(e0) { } Array.prototype.sort.apply(a2, [b0, i0, t0, this.s1]); } }));");
/*fuzzSeed-85495475*/count=1412; tryItOut("{ void 0; minorgc(true); } this.h1 + '';");
/*fuzzSeed-85495475*/count=1413; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.min((( + Math.sign((Math.fround(((y | 0) * Math.fround(x))) === Math.tanh((Math.pow(0, x) >>> 0))))) >>> 0), ((Math.pow(Math.hypot((Math.imul(Math.fround(Math.imul(Math.fround(Math.max(((Math.max((y | 0), (x | 0)) | 0) >>> 0), (x >>> 0))), x)), Math.fround(( ! x))) >>> 0), (x | 0)), Math.log2(Math.fround(mathy3(( - y), Math.fround((Math.fround(y) % mathy0((2**53+2 >>> 0), Number.MIN_VALUE))))))) | 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-85495475*/count=1414; tryItOut("mathy4 = (function(x, y) { return (((Math.atan(( + Math.fround(mathy1(Math.fround(Math.fround((Math.max(((x >>> 0) ** (x | 0)), Math.fround(x)) != Math.sign(0x100000001)))), x)))) | 0) - (((( ! y) || Math.fround(x)) / Math.imul(x, (Math.hypot(x, ( + Math.round(Number.MAX_VALUE))) == ( + y)))) >>> 0)) | 0); }); testMathyFunction(mathy4, [1, 0, -(2**53), -0x080000000, 1/0, 0x100000000, -Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -(2**53+2), 2**53-2, Number.MAX_VALUE, Math.PI, 0.000000000000001, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, -0x100000001, 2**53+2, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 42, -0, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -0x07fffffff, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-85495475*/count=1415; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(( + Math.fround((Math.fround(Math.min(( + (( + ( + x)) ? ( + y) : ( + 0x0ffffffff))), Math.log2(((x >>> 0) === -1/0)))) || Math.hypot(Math.fround(Math.atan2(x, ( ~ x))), (Math.fround((Math.fround(y) | 0)) - x)))))); }); testMathyFunction(mathy3, [-(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, 1/0, 1, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, Math.PI, -0x07fffffff, -0x080000000, Number.MAX_VALUE, -0, -(2**53), -(2**53-2), 42, 0x080000000, -0x100000000, 2**53-2, 2**53, -0x0ffffffff, 2**53+2, 0x100000000, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-85495475*/count=1416; tryItOut("");
/*fuzzSeed-85495475*/count=1417; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy0(( + Math.trunc(Math.fround(Math.atan(( + ( ! Math.ceil(( + 2**53-2)))))))), ( + (Math.log1p(Math.atan2((0/0 | x), x)) >>> 0))); }); testMathyFunction(mathy3, [0.000000000000001, -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, Number.MIN_VALUE, 0x100000000, 0x080000001, 0x080000000, 1/0, Math.PI, 0x07fffffff, Number.MAX_VALUE, 1, -0x100000000, -0x080000000, 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0x100000001, -0, -0x0ffffffff, -0x100000001, -0x080000001, 0, -Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 42]); ");
/*fuzzSeed-85495475*/count=1418; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.min(Math.min((( + mathy0(x, x)) ? x : (((Math.tanh(y) >>> 0) / (Math.atan2((x | 0), x) >>> 0)) | 0)), -0x080000000), Math.log2(( + ((( + y) | 0) + ((mathy0((mathy0((x >>> 0), (-(2**53) >>> 0)) >>> 0), (x + -(2**53))) >>> 0) | 0))))) >>> 0) && (( + Math.max(( + (((Math.acos(mathy1(y, ( + Math.cbrt((0x0ffffffff | 0))))) >>> 0) < (Math.abs(-0x100000000) >>> 0)) >>> 0)), ((mathy2(( + (( + ( + Math.exp(-Number.MAX_VALUE))) * ( + (Math.acosh((y | 0)) | 0)))), Math.fround(( ! (( + (x | 0)) | 0)))) / -Number.MIN_SAFE_INTEGER) >>> 0))) >>> 0)) | 0); }); testMathyFunction(mathy3, [42, 0x100000000, -(2**53+2), 0.000000000000001, 2**53, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, 1, -0x07fffffff, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0/0, 0x080000001, -0, 2**53-2, -Number.MAX_SAFE_INTEGER, Math.PI, 0x07fffffff, 0x0ffffffff, -(2**53-2), -(2**53), 2**53+2, -1/0, 0, 1.7976931348623157e308]); ");
/*fuzzSeed-85495475*/count=1419; tryItOut("/*vLoop*/for (var zkzkmn = 0; zkzkmn < 32; ++zkzkmn) { let e = zkzkmn; p1.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 3.8685626227668134e+25;\n    i0 = (i0);\n    (Float64ArrayView[1]) = ((+(((d2)))));\n    return (((!(0xffffffff))-((((17179869184.0)) * ((-((+(((144115188075855870.0)))))))) <= (d2))-((-((+(-1.0/0.0)))) < (d2))))|0;\n  }\n  return f; }); } ");
/*fuzzSeed-85495475*/count=1420; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, 42, 0.000000000000001, 0, 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, 1, -0x0ffffffff, 0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), -1/0, Number.MIN_VALUE, 2**53-2, -(2**53-2), -0x080000000, -(2**53), -Number.MIN_VALUE, Math.PI, 0x100000001, Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, 1/0]); ");
/*fuzzSeed-85495475*/count=1421; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    /*FFI*/ff();\n    d1 = (d0);\n    return +((d1));\n    d0 = (d1);\n    d0 = (d0);\n    return +((d0));\n    return +((((+(1.0/0.0))) * ((+/*FFI*/ff()))));\n  }\n  return f; })(this, {ff:  '' }, new ArrayBuffer(4096)); testMathyFunction(mathy5, [2**53-2, 0x080000001, -(2**53+2), 1.7976931348623157e308, 0x100000000, 0/0, -1/0, 42, Math.PI, 0x100000001, 0x080000000, -0x07fffffff, -Number.MIN_VALUE, -0x080000000, 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -Number.MAX_VALUE, 0, 1/0, 1, 2**53, Number.MIN_VALUE, -0x080000001, -0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=1422; tryItOut("\"use strict\"; this.g0.e0.add(s2);");
/*fuzzSeed-85495475*/count=1423; tryItOut("\"use strict\"; throw arguments[\"toLocaleDateString\"];");
/*fuzzSeed-85495475*/count=1424; tryItOut("testMathyFunction(mathy2, [0x100000000, 42, 0/0, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, Number.MIN_VALUE, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 0x07fffffff, Math.PI, 1/0, 2**53-2, -0x080000001, 0, 0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), -(2**53), 1, 2**53+2, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, -Number.MAX_VALUE, -0, 0.000000000000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1425; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1426; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min((Math.cos(( ! y)) < ( - ( + (Math.sqrt(x) | 0)))), ((((Math.fround(y) , Math.fround(mathy0(x, x))) ? -Number.MAX_VALUE : x) !== (Math.max(Math.hypot(Math.fround(0x080000001), y), (( + (x << 1)) ? Math.imul((y === x), (y % ( + ((1 | 0) / x)))) : x)) | 0)) >>> 0)); }); testMathyFunction(mathy1, [42, 1/0, -(2**53+2), 2**53-2, -Number.MAX_VALUE, 0x080000001, -0x080000000, -0x100000000, 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53-2), Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 1, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 2**53, -0, 0x100000001, 0.000000000000001, 0x100000000, -0x080000001, 0]); ");
/*fuzzSeed-85495475*/count=1427; tryItOut("s2 = new String(f1);");
/*fuzzSeed-85495475*/count=1428; tryItOut("{ void 0; disableSPSProfiling(); } let z = new (RegExp.prototype.compile)((makeFinalizeObserver('nursery')));print(window = []);");
/*fuzzSeed-85495475*/count=1429; tryItOut("print({} = d = Proxy.create(({/*TOODEEP*/})(window),  '' ));");
/*fuzzSeed-85495475*/count=1430; tryItOut("\"use asm\"; throw StopIteration;");
/*fuzzSeed-85495475*/count=1431; tryItOut("v2 = t1[7];");
/*fuzzSeed-85495475*/count=1432; tryItOut("\"use strict\"; o1.a2.forEach((function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var ceil = stdlib.Math.ceil;\n  var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (i0);\n    }\n    i0 = ((+atan((((9.0) + (+((1.5))))))) >= (-576460752303423500.0));\n    /*FFI*/ff(((16777217.0)));\n    i1 = (i1);\n    {\n      (Float32ArrayView[((0x2fe0c00f)*0x629c9) >> 2]) = ((Float32ArrayView[1]));\n    }\n    return +((+(((i0))|0)));\n    return +(((+ceil((((eval(\"\\\"use asm\\\"; Object.defineProperty(this, \\\"v0\\\", { configurable: true, enumerable: true,  get: function() {  return o1.a0.length; } });\"))\n < x)))) + ((((i1))) / ((Float32ArrayView[2])))));\n    i0 = (i1);\n    {\n      {\n        i1 = (/*FFI*/ff(((-((9.44473296573929e+21)))))|0);\n      }\n    }\n    {\n      {\n        i1 = (i1);\n      }\n    }\n    i0 = ((((i1))>>>((i1))));\n    i0 = (i0);\n    i0 = (i1);\n    return +((Infinity));\n    /*FFI*/ff(((((i0)-((+abs(((9223372036854776000.0)))) > (36028797018963970.0))-(i1)) ^ (((Float64ArrayView[2])) / (abs((((0x75e188d8)) >> ((0x889598f))))|0)))), (((((i1)+(i0)))|0)));\n    return +((-17592186044415.0));\n  }\n  return f; })(this, {ff: String.prototype.bold}, new SharedArrayBuffer(4096)), o0.t2);");
/*fuzzSeed-85495475*/count=1433; tryItOut("a1.push(o0.v2, t2, i1, v0, o1);");
/*fuzzSeed-85495475*/count=1434; tryItOut("for (var p in t0) { v2.__iterator__ = (function() { for (var j=0;j<6;++j) { g2.f2(j%4==1); } }); }");
/*fuzzSeed-85495475*/count=1435; tryItOut("s0 = new String(v1);");
/*fuzzSeed-85495475*/count=1436; tryItOut("g1.f2.valueOf = (function() { try { for (var p in b2) { try { g0.offThreadCompileScript(\"/*MXX2*/g1.RangeError.prototype.name = s0;\", ({ global: o0.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 == 2), noScriptRval: (void options('strict_mode')), sourceIsLazy: false, catchTermination: false })); } catch(e0) { } try { i1.valueOf = this.f0; } catch(e1) { } try { Array.prototype.shift.call(a0); } catch(e2) { } o0.t0.valueOf = ({\u3056: x}); } } catch(e0) { } try { s1 = g2.objectEmulatingUndefined(); } catch(e1) { } o2.v1 = a0.length; return v1; });");
/*fuzzSeed-85495475*/count=1437; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( + Math.sinh(( + (( + (( - Math.max((0 >>> 0), Math.fround(x))) ^ (x ** y))) ^ Math.clz32((Math.cosh((x | 0)) | 0)))))) / Math.log2(Math.fround((Math.fround(y) ? Math.fround((x - ( ! Math.asin(( + y))))) : Math.fround(Math.max(x, x)))))); }); testMathyFunction(mathy1, [-0x0ffffffff, 0.000000000000001, Number.MAX_VALUE, 0, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 1, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 42, -1/0, 1/0, -0x100000001, 0x0ffffffff, 0x080000001, Number.MIN_VALUE, -(2**53+2), Math.PI, -0x080000000, -Number.MIN_VALUE, 0x100000000, 0x080000000, 0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, -0]); ");
/*fuzzSeed-85495475*/count=1438; tryItOut("\"use strict\"; m2 + '';");
/*fuzzSeed-85495475*/count=1439; tryItOut("s2 += o2.s0;");
/*fuzzSeed-85495475*/count=1440; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a2, 7, { configurable: true, enumerable: true, writable: (x % 6 != 0), value: o2.v0 });");
/*fuzzSeed-85495475*/count=1441; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.expm1((((((((x != ( + x)) >>> ((Math.sqrt(x) & (x >>> 0)) >>> 0)) | 0) ** (Math.exp((( - y) | 0)) | 0)) | 0) >= Math.tan(Math.acos(Math.fround(( ~ ( - y)))))) | 0)) | 0); }); testMathyFunction(mathy0, [-(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 1.7976931348623157e308, 0, 0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -0x100000001, -0x080000000, 1, -1/0, 2**53+2, -0x07fffffff, 0x100000001, 0x100000000, -0x100000000, 0x080000001, 0x080000000, -Number.MAX_VALUE, -0, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, 2**53, -0x080000001, 42, 0/0]); ");
/*fuzzSeed-85495475*/count=1442; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53+2, Math.PI, 42, 1, -Number.MAX_VALUE, 0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_VALUE, -0x100000000, 0.000000000000001, 2**53, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, -0, 0/0, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, Number.MAX_VALUE, -(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -0x080000001, -0x080000000, 1.7976931348623157e308, 0x100000001, -1/0, 0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=1443; tryItOut("Number();");
/*fuzzSeed-85495475*/count=1444; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x100000001, 0x100000000, 42, 0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 2**53+2, -Number.MAX_VALUE, 2**53, -0, 0/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 1, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, -0x100000000, -Number.MIN_VALUE, -0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -(2**53), 0x080000000, 1.7976931348623157e308, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 1/0]); ");
/*fuzzSeed-85495475*/count=1445; tryItOut("/*RXUB*/var r = /\\B{3,}/g; var s = \"\\n \\n;\\u009e11a\\u60e0\\n \\n;\\u009e11a\\u60e0\\n \\n;\\u009e11a\\u60e0\"; print(s.split(r)); ");
/*fuzzSeed-85495475*/count=1446; tryItOut("(x);");
/*fuzzSeed-85495475*/count=1447; tryItOut("for(var y = (\n(uneval( /x/g ))) in Math.pow((Math.max((x > x), ((x >= -(2**53+2)) | 0)) | 0), x) * /*UUV1*/(eval.getInt8 = /*wrap2*/(function(){ var sdlxkf = window; var qoqdsa = objectEmulatingUndefined; return qoqdsa;})())) {/*hhh*/function gcgeup(){/* no regression tests found */}gcgeup(eval(\"i0 = new Iterator(a1, true);\", ({x: Math.min((4277), /*UUV2*/(NaN.of = NaN.getFloat64)), __iterator__: /*RXUE*/new RegExp(\"(?:(?![^\\\\r\\\\b-\\ue82a]){4,5})\", \"gyi\").exec(\"\\ue829\\uc229\\ue13a\\uc229\\uc229\\uc229\") })), (x >> this < x));(x);const a = (4277);function window(of, c, y, window, x, w, x, this, d, \u3056, e = function ([y]) { }, x, x, window, b, \u3056 = true, b = -7, x, x, x, d =  \"\" , eval, d, NaN, window, this = getter, x, x, x, a, x = false, new RegExp(\"(?=.+[\\\\W\\\\uB2cD](?![^]).$$+)\", \"gi\") = new RegExp(\"(?!.)|(?:(\\\\d))\", \"gyi\"), w = new RegExp(\"(?:\\\\s(?!^))\", \"gi\"), x =  /x/ , x, a, d, \u3056, x, x, d, x, c, w, y, \u3056, d, d, NaN, x, window, x, x, z, x =  \"\" , x, y, of = \"\\u3138\", \u3056, window, z, d, x, ...arguments[new String(\"-11\")]) { return yield window /=  ''  } /*MXX3*/this.g1.EvalError.prototype = g0.EvalError.prototype; }");
/*fuzzSeed-85495475*/count=1448; tryItOut("\"use strict\"; v0 = g1.runOffThreadScript();");
/*fuzzSeed-85495475*/count=1449; tryItOut("testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, -(2**53-2), -0x080000000, -0x080000001, -0x100000000, -(2**53+2), 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 0, 1, -0x100000001, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, -0x0ffffffff, -1/0, -0x07fffffff, 0x100000001, Number.MIN_VALUE, 0x080000000, -(2**53), Math.PI, 0/0, 0x100000000, 1.7976931348623157e308, 2**53-2, 42, -0]); ");
/*fuzzSeed-85495475*/count=1450; tryItOut("g0.v0 = Object.prototype.isPrototypeOf.call(this.p1, m2);");
/*fuzzSeed-85495475*/count=1451; tryItOut("h2.getOwnPropertyNames = f0;");
/*fuzzSeed-85495475*/count=1452; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atan2(((Math.fround((-Number.MAX_SAFE_INTEGER ? (Math.fround(( ! y)) >>> 0) : (Math.atan2(Math.fround((Math.fround(y) - (y !== Math.max(0x07fffffff, Math.fround(x))))), (((x | 0) , (( + Math.imul(( + x), ( + -0x100000000))) | 0)) | 0)) | 0))) ? Math.fround(( + x)) : Math.fround(( + Math.abs(Math.expm1(x))))) >>> 0), (Math.log1p((( + Math.trunc(( ! ( + ( ~ y))))) ^ ( + Math.fround(( - ((Math.sinh((x === y)) >>> 0) | 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x07fffffff, 1.7976931348623157e308, 0x100000000, -0x080000001, Number.MIN_VALUE, 2**53, Number.MAX_VALUE, -1/0, -0x100000000, -0, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), 0x0ffffffff, -(2**53), 0x080000000, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, 0x100000001, 42, 1, -(2**53-2), 0, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-85495475*/count=1453; tryItOut("mathy3 = (function(x, y) { return (Math.atan2(Math.fround((Math.asinh((( + Math.imul(( + -0x100000000), ( + -Number.MAX_VALUE))) >> ((y ? x : y) >>> 0))) >>> 0)), ( + (((Math.trunc(x) >>> 0) !== ((1/0 >>> 0) ? Math.fround(( + ((Math.fround((x !== y)) >>> 0) | (x | 0)))) : (Math.fround((x && ( + (( + x) && x)))) >>> 0))) >>> 0))) | 0); }); ");
/*fuzzSeed-85495475*/count=1454; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1455; tryItOut("mathy1 = (function(x, y) { return ((((mathy0((( ! (( ! (y >>> y)) | 0)) | 0), (( + Math.imul(( + x), Math.cos((x >>> 0)))) > x)) && ( - ( ~ Math.fround(Math.sqrt(y))))) | 0) ** (Math.tanh((( ~ (y >>> 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, -(2**53), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 42, 0/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, 2**53, -(2**53-2), Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -0x100000001, 0x100000000, 2**53+2, 0x080000001, 0x07fffffff, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0x100000001, 2**53-2, Math.PI, -0x100000000, 0x080000000, 0, 1/0, -0x0ffffffff]); ");
/*fuzzSeed-85495475*/count=1456; tryItOut("\"use strict\"; v0 = evalcx(\"mathy1 = (function(x, y) { return (mathy0(( + Math.sin(Math.atan2(((((y >>> 0) ** (Math.atanh(((Math.log10((-0x100000001 | 0)) | 0) | 0)) >>> 0)) >>> 0) | 0), (Math.fround(Math.hypot(Math.fround(x), x)) | 0)))), ( + ( ~ (( ! Math.fround(x)) >>> 0)))) | 0); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -0x100000000, -1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, 1/0, 0/0, 0x100000000, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, 1, -(2**53-2), 2**53-2, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, 2**53, 0x07fffffff, -0x080000000, -0x080000001, -(2**53+2), Number.MAX_VALUE, 2**53+2, 0x0ffffffff, -Number.MAX_VALUE, 0x100000001, -0x100000001, 42, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0]); \", g2);");
/*fuzzSeed-85495475*/count=1457; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[ \"use strict\" ,  \"use strict\" ,  \"use strict\" , {}, Math.PI, Math.PI, {}, Math.PI, false,  \"use strict\" , false,  \"use strict\" ,  \"use strict\" , {},  \"use strict\" , Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, {},  \"use strict\" ]) { print(o1.e1); }");
/*fuzzSeed-85495475*/count=1458; tryItOut("Array.prototype.splice.apply(a2, [NaN, 0, b1, this.t0, o2, ([{}]) = 'fafafa'.replace(/a/g, Date.prototype.getUTCFullYear)]);");
/*fuzzSeed-85495475*/count=1459; tryItOut("testMathyFunction(mathy2, [true, (new Boolean(true)), '0', 0, -0, '/0/', objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), undefined, (new Number(0)), (function(){return 0;}), [0], 1, (new Number(-0)), 0.1, NaN, false, (new String('')), [], '', (new Boolean(false)), null, /0/, ({valueOf:function(){return 0;}}), '\\0']); ");
/*fuzzSeed-85495475*/count=1460; tryItOut("var pqsmta = new SharedArrayBuffer(16); var pqsmta_0 = new Float64Array(pqsmta); pqsmta_0[0] = -9; var pqsmta_1 = new Uint16Array(pqsmta); pqsmta_1[0] = 0; var pqsmta_2 = new Int32Array(pqsmta); var pqsmta_3 = new Uint8Array(pqsmta); pqsmta_3[0] = 26; var pqsmta_4 = new Float32Array(pqsmta); pqsmta_4[0] = 13; var pqsmta_5 = new Float64Array(pqsmta); print(pqsmta_5[0]); pqsmta_5[0] = 8; { void 0; disableSPSProfiling(); } g2.offThreadCompileScript(\"o1.t2[v2];\");c = pqsmta_2;a2.pop();e2 = new Set;print(new RegExp(\"^\", \"im\"));((eval(\"print(x);\")));print(pqsmta_2[7]);");
/*fuzzSeed-85495475*/count=1461; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( ~ (Math.fround(mathy0(Math.fround(( + Math.max((Math.imul(y, mathy0(Math.fround(x), ( + 0x100000000))) >>> 0), Math.fround(42)))), Math.fround(x))) ? (( + (Math.max(y, Math.clz32(x)) === y)) <= Number.MIN_SAFE_INTEGER) : ( + Math.sinh(Math.fround(( + Math.fround(1.7976931348623157e308))))))) | 0); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0/0, 0, -0, -0x07fffffff, 1.7976931348623157e308, -0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, -(2**53-2), -1/0, Math.PI, -0x100000000, -0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, 42, 0.000000000000001, -Number.MAX_VALUE, 2**53, 0x100000000, Number.MIN_VALUE, 1, 0x080000001, -0x0ffffffff, 0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-85495475*/count=1462; tryItOut("mathy0 = (function(x, y) { return Math.atan2((((((Math.fround(Math.exp(Math.fround(Math.atan2(-0x080000000, y)))) | 0) && (( + ( + x)) | 0)) | 0) && (( - ((( + Number.MIN_VALUE) ? ( + 0.000000000000001) : x) | 0)) | 0)) >>> 0), (Math.asinh((((((( + Math.sin(y)) >>> 0) ? ((y ? ( ~ y) : (y >>> 0)) >>> 0) : (( + Math.atan(y)) >>> 0)) >>> 0) - (((Math.max((y >>> 0), (Math.imul(y, Math.fround(y)) >>> 0)) >>> 0) === ( + Math.fround(Math.fround(Math.hypot(Math.fround(2**53), Math.acosh(y)))))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, -0x080000001, 0x07fffffff, 0x080000001, Number.MAX_VALUE, 0x100000000, 2**53, 0x080000000, -0x080000000, -Number.MAX_VALUE, 0, 2**53-2, -(2**53+2), 1/0, 0.000000000000001, -(2**53-2), Math.PI, -0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 42, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, -(2**53), 0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-85495475*/count=1463; tryItOut("\"use strict\"; e2.add(i0);");
/*fuzzSeed-85495475*/count=1464; tryItOut("s1 = p2;");
/*fuzzSeed-85495475*/count=1465; tryItOut("/*bLoop*/for (var wtwryk = 0; wtwryk < 13; ++wtwryk) { if (wtwryk % 2 == 1) { a2 + ''; } else { i2.next(); }  } ");
/*fuzzSeed-85495475*/count=1466; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.hypot((Math.acos(( + (x / ( + (Math.sqrt((Math.tanh((x >>> 0)) | 0)) | 0))))) >>> 0), Math.exp(Math.fround(Math.pow((( + Math.fround(( ~ Math.fround(x)))) * y), x)))); }); testMathyFunction(mathy0, [1/0, Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, 0x100000001, -1/0, -(2**53), 0x07fffffff, -0x0ffffffff, 1, -(2**53+2), -0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, -0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 0, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, 2**53+2, -(2**53-2), -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, 0x080000001, 42]); ");
/*fuzzSeed-85495475*/count=1467; tryItOut("/*hhh*/function krqmso(){o0.g1.a1 = new Array;}/*iii*/for (var v of a0) { try { h1.toSource = (function() { try { p2.toSource = (function(j) { f2(j); }); } catch(e0) { } try { o2 = o0.g2.__proto__; } catch(e1) { } selectforgc(o2); return e1; }); } catch(e0) { } try { g0[\"valueOf\"] = a1; } catch(e1) { } i1 = e1.entries; }");
/*fuzzSeed-85495475*/count=1468; tryItOut("\"use strict\"; with({y: new x = ((Date.prototype.getUTCSeconds).call( '' , new RegExp(\"((?!(?=[^])|^+?|.))|($+?)\\\\w\", \"y\").yoyo(new RegExp(\"\\\\x00\", \"gy\")), (\u3056) = (4277)))()})L:for(c in a = \nMath.imul(-3, \"\\u992E\")) print(x);");
/*fuzzSeed-85495475*/count=1469; tryItOut("o0.o1 = new Object;");
/*fuzzSeed-85495475*/count=1470; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul(( ~ Math.tan(y)), (( - (((((0x07fffffff << x) >> x) > y) >>> 0) ? ((0x100000000 >>> 0) << (y >>> 0)) : (( + ( - Math.fround((Math.fround(Math.trunc(y)) ? Math.fround(x) : (0.000000000000001 >>> 0))))) | 0))) >>> 0)); }); testMathyFunction(mathy0, [Number.MIN_VALUE, 2**53+2, -0x100000000, 0/0, 0x100000000, -(2**53), -1/0, 0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, Math.PI, -(2**53-2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, -0x07fffffff, 1, 0x100000001, 0x07fffffff, -0, 2**53-2, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, -0x100000001, 2**53, 0x080000000, 42, -(2**53+2), 0x080000001, 0.000000000000001, Number.MAX_VALUE]); ");
/*fuzzSeed-85495475*/count=1471; tryItOut("/*vLoop*/for (var tddnky = 0, window; tddnky < 41; ++tddnky) { const a = tddnky; return; } ");
/*fuzzSeed-85495475*/count=1472; tryItOut("this.e1.has(-new RegExp(\"[^]\", \"\"));");
/*fuzzSeed-85495475*/count=1473; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.clz32((((Math.min(Math.log2(y), mathy0((((y < ((y == x) >>> 0)) >>> 0) & Math.imul(y, y)), (( ! (y >>> 0)) >>> 0))) | 0) ^ (( + (( + (Math.fround((y != 42)) , Math.fround(((( - (( + Math.imul(( + x), ( + y))) >>> 0)) >>> 0) ? ( ! 2**53) : y)))) ? ( + Math.tan(-0)) : Math.tanh(x))) | 0)) | 0)); }); testMathyFunction(mathy1, [2**53, 0, -1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 0/0, 0x100000001, -0x07fffffff, 42, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, Number.MAX_VALUE, 0x100000000, Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -(2**53), -0x0ffffffff, 0x080000001, -Number.MIN_VALUE, -(2**53-2), 2**53+2, -0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, 1, -0x100000000, 0x0ffffffff, -0]); ");
/*fuzzSeed-85495475*/count=1474; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-85495475*/count=1475; tryItOut("\"use strict\"; Array.prototype.pop.apply(this.a1, []);");
/*fuzzSeed-85495475*/count=1476; tryItOut("v2 = r0.toString;");
/*fuzzSeed-85495475*/count=1477; tryItOut("mathy2 = (function(x, y) { return (Math.min((( + Math.round(((Math.exp(Math.fround(((x >>> 0) == Math.fround(Math.atan2(x, -(2**53+2)))))) >>> 0) | 0))) | 0), (mathy1(( + Math.fround(Math.fround((((Math.fround((Math.max(y, y) | 0)) | 0) >>> 0) < ( + mathy0(-Number.MIN_SAFE_INTEGER, ( + ( + x)))))))), mathy1(( + ( - (y >>> 0))), ((Math.sqrt(y) >> Number.MAX_SAFE_INTEGER) | 0))) | 0)) | 0); }); ");
/*fuzzSeed-85495475*/count=1478; tryItOut("Array.prototype.unshift.apply(this.a2, [let (c = -2803958656) (4277), a1, ({\"-6\": ((NaN && z) -= ((void version(170)))) })]);");
/*fuzzSeed-85495475*/count=1479; tryItOut("v1 = undefined;");
/*fuzzSeed-85495475*/count=1480; tryItOut("print(uneval(o1.g0));\nt1 = new Uint8ClampedArray(t1);\n");
/*fuzzSeed-85495475*/count=1481; tryItOut("/*vLoop*/for (var drpjcs = 0; drpjcs < 14; ++drpjcs) { var z = drpjcs; a1.reverse(); } ");
/*fuzzSeed-85495475*/count=1482; tryItOut("\"use strict\"; if(false) {this.v2 = o2.g2.eval(\"this\");yield; }");
/*fuzzSeed-85495475*/count=1483; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((+atan2(((+((((((((-288230376151711740.0)) - ((18014398509481984.0))) >= (d1)))) % (~((0x70e4cf2c) % (0x3a6b515d)))) | ((((((0x9f2eaf82) ? (0xf8284465) : (0x5874fff1)))>>>((0xffffffff)+(0xfaf1d5cd)+(-0x8000000))))*-0x4ce0d)))), ((d1)))));\n  }\n  return f; })(this, {ff: NaN =  \"\" }, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false)]); ");
/*fuzzSeed-85495475*/count=1484; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1485; tryItOut("Object.defineProperty(this, \"a1\", { configurable: x, enumerable: 8,  get: function() {  return arguments; } });");
/*fuzzSeed-85495475*/count=1486; tryItOut("\"use strict\"; if(true) Array.prototype.push.call(a2, p0, s0); else  if (yield null.valueOf(\"number\")) s2 += 'x';const y = (Uint32Array).call(/\\2(?:(?:$|(^))*)/gm, (objectEmulatingUndefined)(-2, \"\\u22CC\"));");
/*fuzzSeed-85495475*/count=1487; tryItOut("var vtkppj = new SharedArrayBuffer(16); var vtkppj_0 = new Uint8Array(vtkppj); var vtkppj_1 = new Int32Array(vtkppj); vtkppj_1[0] = -27; print(undefined);;print(vtkppj_0[0]);h0.getPropertyDescriptor = f1;selectforgc(o2);print(\"\\u6058\");break L;");
/*fuzzSeed-85495475*/count=1488; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((( - (Math.hypot(Math.fround(Math.log1p(y)), Math.fround((mathy1((Math.hypot(( + (( + Math.sqrt(Math.fround(y))) ? (mathy0((2**53-2 >>> 0), y) >>> 0) : x)), -(2**53)) >>> 0), (( ~ Math.fround(Math.pow(Math.hypot(y, 0x07fffffff), (-Number.MAX_VALUE | 0)))) | 0)) | 0))) >>> 0)) == (((Math.sqrt(( + ( + Math.log1p((y % (Math.hypot(y, (x | 0)) | 0)))))) & ( + (Math.hypot((mathy1(((1/0 ** mathy0(-0x080000001, x)) | 0), (( + ( - ( + y))) | 0)) | 0), ((Math.fround(( - Math.fround(x))) ? Number.MAX_VALUE : (x % ( + ( + x)))) | 0)) | 0))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [-0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), 0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 0, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, 2**53+2, 0x100000001, Math.PI, -0x100000000, -0x07fffffff, -(2**53), 0x0ffffffff, -(2**53-2), -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 1/0, -0, 2**53, -0x100000001, -0x080000001, 0x080000000, -1/0, Number.MIN_SAFE_INTEGER, 42, 0/0, 2**53-2]); ");
/*fuzzSeed-85495475*/count=1489; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(( ~ Math.fround(Math.min(Math.fround(( + (Math.fround(y) ? x : ( + x)))), Math.fround(Math.fround(( - Math.fround(Math.imul(y, 0x100000001)))))))), (Math.sign(Math.fround(( + (( - Math.fround(x)) >>> 0)))) >>> 0)); }); ");
/*fuzzSeed-85495475*/count=1490; tryItOut("mathy2 = (function(x, y) { return Math.pow((((Math.clz32(( - ((y | 0) ? y : ( + ((0x07fffffff | 0) * (-(2**53-2) | 0)))))) >>> (mathy0((Math.asinh(2**53-2) >>> 0), ( ! (x | 0))) | 0)) >>> 0) >>> 0), Math.fround((Math.fround(( ! (Math.acos(Math.cbrt(x)) >>> 0))) ? (mathy0(Math.atan((( ~ ( ! (y >>> 0))) | 0)), mathy1(Math.fround(Math.hypot(x, y)), mathy1(Math.cosh(x), (y & 0x07fffffff)))) | 0) : Math.fround(( + ( + (Math.max((( ~ (x | 0)) | 0), -Number.MAX_VALUE) | 0))))))); }); testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-85495475*/count=1491; tryItOut("L: {a2 = r0.exec(s0);a0 = this.r1.exec(s2); }");
/*fuzzSeed-85495475*/count=1492; tryItOut("testMathyFunction(mathy1, [2**53-2, -Number.MIN_VALUE, 1/0, -0x100000001, 0x100000001, 2**53, 0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), -0x0ffffffff, 0/0, -0x100000000, 0x100000000, -0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, 42, Math.PI, 0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -1/0, -0, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), Number.MAX_VALUE, -Number.MAX_VALUE, 0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1, 0.000000000000001]); ");
/*fuzzSeed-85495475*/count=1493; tryItOut("while(((/*MARR*/[new Boolean(true), x, x, new Boolean(true), new Boolean(true), x, new Boolean(true), new Boolean(true), x, new Boolean(true), new Boolean(true), new Boolean(true), x, x, x, new Boolean(true), new Boolean(true), x, x, x].map(decodeURIComponent\u0009)) /= (w = [,].throw(x))) && 0){/*ADP-2*/Object.defineProperty(a1, 19, { configurable: false, enumerable: false, get: (function() { t2.set(a0, ({valueOf: function() { (x);return 17; }})); return s2; }), set: (function() { for (var j=0;j<110;++j) { f1(j%5==0); } }) }); }");
/*fuzzSeed-85495475*/count=1494; tryItOut("\"use strict\"; let(b) { throw window;}let(window = [,,], hrrmrw, w, imqnfn, rqqthf) { yield;}\nv1 = Object.prototype.isPrototypeOf.call(this.g0.a0, g2);\n");
/*fuzzSeed-85495475*/count=1495; tryItOut("/*oLoop*/for (var cwnezh = 0; cwnezh < 1 && ((yield /(?=(?![^]{4})|[T-\u0014]|[\\u00Ca\\B\\f\\f-\\u00F5])|\\B|\\3*|(((?:^)){4,5})+/gy).eval(\"/* no regression tests found */\")) && ((makeFinalizeObserver('nursery'))); ++cwnezh) { /*MXX3*/g0.Array.length = o1.g1.Array.length; } ");
/*fuzzSeed-85495475*/count=1496; tryItOut("with(3)v0 = evaluate(\"function f1(t2)  { \\\"use strict\\\"; yield w+=([[]] <<= x) } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 21 != 6), sourceIsLazy: true, catchTermination: (x % 10 == 1) }));");
/*fuzzSeed-85495475*/count=1497; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\b|(?=(?=\\\\2\\\\w|[^]){0})|(?=([^])|(?!.)+??){3,6}+\", \"gi\"); var s = \"\"; print(s.replace(r, (4277), \"yi\")); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=1498; tryItOut("\"use strict\"; this.e0 = new Set(p1);");
/*fuzzSeed-85495475*/count=1499; tryItOut("mathy0 = (function(x, y) { return (((((y , Math.fround((Math.fround(Math.atan2(y, ((( - (-0x0ffffffff | 0)) | 0) | 0))) === Math.fround(-1/0)))) >>> 0) >>> (( + (Math.atanh(y) | (Math.atan2(-0, (y >>> 0)) >>> 0))) >>> 0)) >= ( ~ ((( - (Math.cos(((-Number.MIN_VALUE ** -0x100000001) >>> 0)) >>> 0)) | 0) << ( + Math.imul(y, Math.trunc(( + x))))))) / Math.fround(Math.sinh(Math.fround((( - (Math.tan(0x07fffffff) | 0)) | 0))))); }); ");
/*fuzzSeed-85495475*/count=1500; tryItOut("\"use strict\"; h2.has = (function(j) { if (j) { s2 += 'x'; } else { try { m0.set(g2.e0, g0); } catch(e0) { } e1.has(t2); } });");
/*fuzzSeed-85495475*/count=1501; tryItOut("s1 = a0[v1];");
/*fuzzSeed-85495475*/count=1502; tryItOut("s0 = new String(v0);");
/*fuzzSeed-85495475*/count=1503; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( + mathy1(Math.ceil(x), (Math.max(2**53+2, Math.fround(Math.fround(( - 0x07fffffff)))) !== Math.min(x, (Math.atan2(y, x) | 0)))))); }); testMathyFunction(mathy3, [0x080000001, 0x100000001, -(2**53+2), 0x100000000, -0x0ffffffff, 0/0, Number.MAX_VALUE, 0.000000000000001, 0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 42, 2**53+2, -Number.MIN_VALUE, -0x100000000, 1/0, 2**53-2, -(2**53-2), -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, -0, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, -1/0, 0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-85495475*/count=1504; tryItOut("testMathyFunction(mathy0, /*MARR*/[]); ");
/*fuzzSeed-85495475*/count=1505; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0x100000000, 0.000000000000001, -(2**53+2), 0x080000000, 1, 2**53-2, 2**53+2, 42, -0x080000000, 0/0, 2**53, -(2**53), -0x100000000, 1.7976931348623157e308, -0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000001, -(2**53-2)]); ");
/*fuzzSeed-85495475*/count=1506; tryItOut(" for  each(z in ([]) = x) let (this.a, window, NaN, a, x) { let o2.o1.s2 = ''; }");
/*fuzzSeed-85495475*/count=1507; tryItOut("m0.get(s2);");
/*fuzzSeed-85495475*/count=1508; tryItOut("{ void 0; bailAfter(998); }");
/*fuzzSeed-85495475*/count=1509; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float64ArrayView[0]) = ((((-1125899906842625.0)) % ((+((+pow(((147573952589676410000.0)), ((Infinity)))))))));\n    return +((((+(1.0/0.0))) % ((-4097.0))));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var vyekua = (/*UUV1*/(eval.toGMTString = Object.prototype.hasOwnProperty)); (encodeURI)(); })}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53), Number.MIN_VALUE, -0, -0x100000001, -0x080000000, -(2**53-2), 2**53, -0x080000001, 42, Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 1, Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, 1/0, Math.PI, 0.000000000000001, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -0x07fffffff, 0/0, -(2**53+2), 0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-85495475*/count=1510; tryItOut("mathy4 = (function(x, y) { return Math.min((( - (Math.max((( - -Number.MAX_SAFE_INTEGER) >>> 0), (Math.tanh(Math.fround(Math.pow(y, mathy0(0x080000000, y)))) < Math.fround(Math.hypot(( + ( + ( - ((y & y) >>> 0)))), Math.fround((( ~ (( + mathy3(( + y), x)) >>> 0)) >>> 0)))))) | 0)) >>> 0), ((Math.pow(Math.acos(Math.pow(y, Math.atan2(y, -0x100000000))), -(2**53-2)) <= ( + (( + x) | ( + ((y >= x) ** (mathy2(((0.000000000000001 >>> x) >>> 0), (x >>> 0)) >>> 0)))))) | 0)); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, 0/0, -0, 0x100000001, 2**53+2, -0x100000000, -(2**53+2), 0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 0x080000001, Number.MAX_VALUE, -(2**53), 1, -1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, -0x07fffffff, 1/0, Math.PI, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, 42, 0x100000000, 0x080000000, -0x080000000, -0x100000001]); ");
/*fuzzSeed-85495475*/count=1511; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((Float64ArrayView[2]));\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, Math.PI, 0x0ffffffff, 2**53, 0x080000000, 0x07fffffff, 0.000000000000001, -0x100000000, Number.MAX_VALUE, -0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, Number.MIN_VALUE, 42, -0x080000001, 1/0, 1, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 0, -(2**53-2), -0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, 0x100000000, -0x080000000, -0x0ffffffff, -(2**53+2), 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1512; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ((( ~ Math.sin((0 << (y >>> 0)))) >>> 0) + (Math.pow((( ! ((x ** Math.fround(Math.atan2(Math.fround(1), Math.fround(y)))) >>> 0)) >>> 0), ( + Math.pow(Math.imul(0x080000001, ((Math.min((Math.cosh((Math.imul(y, (x >>> 0)) >>> 0)) | 0), ((Math.max(-0x080000001, x) ? Number.MAX_SAFE_INTEGER : Number.MIN_SAFE_INTEGER) | 0)) | 0) >>> 0)), ((x << Math.imul(y, ( ! ( + y)))) | 0)))) >>> 0)); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, 42, -0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, 0x080000000, 1, 0x100000000, Math.PI, -0x080000001, 0, 2**53+2, -(2**53-2), Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, -0, 1/0, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -1/0, -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -Number.MAX_VALUE, 2**53, -0x100000001]); ");
/*fuzzSeed-85495475*/count=1513; tryItOut("this.a1.unshift(o0.t1, m0, f1, v0, t1, this.i1, v0, o1.i0, f1, s1);");
/*fuzzSeed-85495475*/count=1514; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float64ArrayView[2]) = ((+abs(((Float64ArrayView[1])))));\n    d0 = (d0);\n    (Uint16ArrayView[1]) = ((((0x9000b1ea) <= (0xc4c5588))));\n    i1 = (i1);\n    d0 = (d0);\n    {\n      d0 = (+((((([]) = x))*-0xb67e9) ^ ((0xa804df9d)-(/*FFI*/ff()|0)+(0xffffffff))));\n    }\n    d0 = (+(1.0/0.0));\n    return (((i1)+((-0x8000000) == (((0x9fb7c595)) & ((0xc2d63ef5)+(0xffffffff)+(i1))))))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[[1],  \"use strict\" ,  \"use strict\" ,  /x/g ,  \"use strict\" , [1],  \"use strict\" , function(){},  /x/g , [1], [1],  \"use strict\" , function(){}, new Boolean(true),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Boolean(true), new Boolean(true),  /x/g ,  /x/g ]); ");
/*fuzzSeed-85495475*/count=1515; tryItOut("/*infloop*/for(let x in ((/*wrap2*/(function(){ var pzphlx = (4277); var bnaydy = decodeURIComponent; return bnaydy;})())(x + x))){Array.prototype.shift.call(a2, p0, e0, m2, a0); }");
/*fuzzSeed-85495475*/count=1516; tryItOut("f0 = Proxy.createFunction(o2.h0, f0, g1.f2);");
/*fuzzSeed-85495475*/count=1517; tryItOut("/*ADP-1*/Object.defineProperty(a2, 17, ({get: (q => q).call, enumerable: true}));");
/*fuzzSeed-85495475*/count=1518; tryItOut("\"use strict\"; (void schedulegc(g1));a0.sort((new Function(\"this.g1.h1.getOwnPropertyDescriptor = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var abs = stdlib.Math.abs;\\n  var tan = stdlib.Math.tan;\\n  var atan2 = stdlib.Math.atan2;\\n  var ff = foreign.ff;\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    i0 = ((((/*FFI*/ff(((((-8796093022209.0)) / ((-274877906945.0)))), ((((i0)) | (((-2.4178516392292583e+24) == (-4611686018427388000.0))))), ((((0xffffffff)+(0xffffffff)+(0xff3fcf35)) >> ((0xda971d00) / (0xffffffff)))), ((imul((0x2f03e03d), (0xdf9c66cc))|0)))|0)*-0x111b8) ^ ((-(/*FFI*/ff(((((+(((0x8d289f0e)) | ((0xfe922c80))))) / ((d1)))), ((0x7fffffff)), (((0xfed209d3) ? (-4.835703278458517e+24) : (536870913.0))), ((4294967297.0)), ((((0xef675564)) ^ ((0xfa1de5d3)))), ((1.25)), ((-2047.0)), ((33554433.0)), ((-1.1805916207174113e+21)), ((2.0)), ((2251799813685249.0)), ((-4398046511104.0)), ((-1.5)), ((-2.3611832414348226e+21)), ((-4611686018427388000.0)), ((262145.0)), ((-1.00390625)))|0)))));\\n    {\\n      (Int16ArrayView[((((\\\"\\\\u595A\\\")>>>((0xffffffff))) != ((0x1237c*(0xfea22690))>>>((0xec86c207)-(0xf854fb59))))+(/*FFI*/ff((((((-0.03125) != (513.0))) << ((true.valueOf(\\\"number\\\"))))))|0)) >> 1]) = (((((0x505d83ab)+(i0))>>>((0xef4664c)+(/*FFI*/ff(((((0xd3a77e52)-(0x9ea2b2f0)) ^ ((0xabfc4ad7) % (0x9bf1643b)))))|0))) >= (0x91a086df))*0xa1428);\\n    }\\n    d1 = (4611686018427388000.0);\\n    d1 = (+abs(((+tan(((d1)))))));\\n    {\\n      (Float32ArrayView[(((0xfffff*(i0)) >> ((i0)+(i0))) % (((i0)+((0x4ca1d647))) << ((0xffffffff) / (0x0)))) >> 2]) = ((d1));\\n    }\\n    i0 = ((((0x278fc0ef))>>>((((x))>>>(((0x3712142) > (0x6d5a81f3))-((0x27e0e06c) < (0x1aba1cf9)))) % (((!(0xf0cc795))+((0x7fffffff) == (0x6ad86523)))>>>(((0x21cd0faa) ? (0xf94c8ef8) : (-0x8000000))-(i0))))) != (((i0)+(!((0x961b5fcd) == (0xc75c2efe))))>>>(((((0xa29a1ce6)-(0xccfb78fe)-(0xb319557a))>>>((uneval((\\\"\\u03a0\\\".valueOf(\\\"number\\\").entries()).__defineGetter__(\\\"c\\\", new Function))))) >= (0x0))-(i0))));\\n    switch ((~~(d1))) {\\n      case -1:\\n        return ((-(0x7b6bd9bf)))|0;\\n      case -1:\\n        d1 = ((((Int32ArrayView[1]))) % (((16777215.0) + (+atan2(((+(((0xffbe58f7)) & ((Uint32ArrayView[0]))))), ((2049.0)))))));\\n        break;\\n      default:\\n        (Uint16ArrayView[4096]) = ((0xc2f5c39f)-(i0));\\n    }\\n    d1 = (d1);\\n    d1 = (d1);\\n    {\\n      i0 = ((((+((((((((-2.0)) - ((2251799813685249.0)))) % ((-536870913.0)))) % ((-2305843009213694000.0)))))) / ((d1))) != (-18446744073709552000.0));\\n    }\\n    d1 = (d1);\\n    i0 = (i0);\\n    return ((((((0xf8dc3d8b)-((-0x8000000) >= (-0x8000000))+(i0)) | (((((-0x8000000)) | ((0x8bb7ee31))) >= (~~(-1.25)))+(i0))) != (((0xc9a6fe66)+(-0x8000000)+(i0)) ^ ((i0)-(0xfef7ac81)+((0xffffffff) >= (0x134effea)))))-(0xb1ee32d3)+(i0)))|0;\\n  }\\n  return f; })(this, {ff:  /x/ }, new SharedArrayBuffer(4096));\")), o1, s1, v1, o2, o2, a1, e2, s0, h0, h0, v1, i1);");
/*fuzzSeed-85495475*/count=1519; tryItOut("var uowbbi = new ArrayBuffer(4); var uowbbi_0 = new Uint8ClampedArray(uowbbi); print(uowbbi_0[0]); uowbbi_0[0] = 5; var uowbbi_1 = new Int32Array(uowbbi); print(uowbbi_1[0]); var uowbbi_2 = new Float32Array(uowbbi); print(uowbbi_2[0]); var uowbbi_3 = new Int16Array(uowbbi); print(uowbbi_3[0]); var uowbbi_4 = new Int16Array(uowbbi); print(uowbbi_4[0]); uowbbi_4[0] = -9; var uowbbi_5 = new Float32Array(uowbbi); print(uowbbi_5[0]); /*RXUB*/var r = /\\b(\\b+?([^]){2,}[\\u5dDF\\x20-\u009b\\\u00f6\\W]|(\u001c)[^]|[^\\B-\u719a]{0}|[^])|[^]|(?!(?=\\b|.|\\1|\\W))|(?:[^]*?){0}(?:(\\B)?|(?:[^]){2,})/gy; var s = \" 11\\n \\u00c9\\n11\\n \\u00c9\\n11\\n \\u00c9\\n11\\n \\u00c9\\n11\\n \\u00c9\\n11\\n \\u00c9\\n\\n11\\n \\u00c9\\n11\\n \\u00c9\\n11\\n \\u00c9\\n11\\n \\u00c9\\n\\u001c\"; print(s.split(r)); print(uowbbi_4);");
/*fuzzSeed-85495475*/count=1520; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; }");
/*fuzzSeed-85495475*/count=1521; tryItOut("mathy3 = (function(x, y) { return ((Math.max((((Math.atan2(Math.fround(x), Math.fround(-Number.MIN_VALUE)) , (y + x)) | 0) | x), (( ~ ( + 2**53-2)) | 0)) >>> 0) && Math.hypot(((Math.atan2((x | 0), ((Math.max((x >>> 0), ( ! ( + x))) >>> 0) | 0)) | 0) >>> 0), (( ! y) | 0))); }); testMathyFunction(mathy3, [-(2**53+2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, 0, -0x07fffffff, 0x080000001, -0x080000001, 0x100000001, -Number.MIN_VALUE, -0, 2**53, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 42, -0x080000000, 0/0, 0.000000000000001, 1.7976931348623157e308, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, -0x0ffffffff, 1, Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, 1/0, -0x100000000, -(2**53-2), 2**53-2]); ");
/*fuzzSeed-85495475*/count=1522; tryItOut("/*MXX1*/o0 = g1.Date.prototype.setMilliseconds;a1 = Array.prototype.filter.apply(a1, [(function() { for (var j=0;j<96;++j) { f1(j%5==0); } })]);");
/*fuzzSeed-85495475*/count=1523; tryItOut("m2.has(f2);");
/*fuzzSeed-85495475*/count=1524; tryItOut("/*RXUB*/var r = /\\3*\\\u4aee*?(?=($)\\3)?[^]|(?=\\\u5f16)?|(?:\\\ufd4e{2})|^{3,}(?:$+?){2}/i; var s = [[]]; print(r.test(s)); ");
/*fuzzSeed-85495475*/count=1525; tryItOut("Object.preventExtensions(t1);");
/*fuzzSeed-85495475*/count=1526; tryItOut("Array.prototype.forEach.call(a2, (function() { try { /*ADP-2*/Object.defineProperty(a0, 11, { configurable: false, enumerable: false, get: (function() { for (var j=0;j<41;++j) { f1(j%5==0); } }), set: (function(j) { if (j) { try { v0 = evaluate(\"/* no regression tests found */\", ({ global: g2.g1, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: Math.hypot(-19, 17), sourceIsLazy: false, catchTermination: true })); } catch(e0) { } g2.t1 = t2.subarray(({valueOf: function() { /*RXUB*/var r = /(.){2}/i; var s = \"\\n\"; print(s.match(r)); return 13; }})); } else { this.h0.set = f1; } }) }); } catch(e0) { } try { print(uneval(v0)); } catch(e1) { } print(uneval(p1)); return p0; }));");
/*fuzzSeed-85495475*/count=1527; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( - Math.fround(Math.fround(( - ( + Math.pow(Math.atan2(x, Math.acosh(y)), mathy3(x, mathy2(( + -0x100000000), y)))))))); }); testMathyFunction(mathy4, [-1/0, -0x07fffffff, 2**53, -0x0ffffffff, -0, 2**53+2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, 0, Math.PI, 0x100000001, Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, -0x100000000, 1, -0x080000001, 42]); ");
/*fuzzSeed-85495475*/count=1528; tryItOut("\"use strict\"; switch(x) { default: break;  }");
/*fuzzSeed-85495475*/count=1529; tryItOut("var avslxo = new SharedArrayBuffer(4); var avslxo_0 = new Float32Array(avslxo); print(avslxo_0[0]); avslxo_0[0] = 21; v1 = evaluate(\"window\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: eval, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-85495475*/count=1530; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -268435457.0;\n    var d3 = -34359738369.0;\n    {\n      d3 = (d1);\n    }\n    {\n      {\n        d1 = (+(-1.0/0.0));\n      }\n    }\n    d0 = (-((+(1.0/0.0))));\n    d2 = (d0);\n    (Float64ArrayView[((((0xbf76ef71)) ^ ((0xf9655bc3)+(0xfcf87f5c)+(0xffffffff))) / (abs((imul(((0x44fa67cd) > (0xffffffff)), (0xfa67c188))|0))|0)) >> 3]) = ((d0));\n    d1 = (((+(((0xfc7a8816)) & ((0x6e2d652c))))) - ((((((+(imul((0xfbfef53d), (0x44a6e7e9))|0)) != (d1))) << ((0x7786acd8))) != (~((0xf74dbcd5)+(0x394d5891)+((d2) >= (+pow(((3.094850098213451e+26)), ((268435455.0))))))))));\n    d1 = (x);\n    d0 = (d1);\n    {\n      d0 = (((Float32ArrayView[((/*FFI*/ff((((0x65309ef1) ? (d1) : (NaN))), ((d0)), ((~~(d1))), ((~~(+(1.0/0.0)))), ((d2)), ((d3)), ((-1.015625)), ((1125899906842623.0)), ((-18446744073709552000.0)), ((-18446744073709552000.0)), ((513.0)), ((-549755813887.0)), ((2147483649.0)), ((-2305843009213694000.0)), ((-1.0009765625)), ((-2048.0)), ((131073.0)), ((-31.0)), ((2.3611832414348226e+21)), ((524288.0)), ((-72057594037927940.0)), ((8589934593.0)), ((1.5111572745182865e+23)), ((9007199254740992.0)))|0)+(0xfa4ec289)) >> 2])));\n    }\n    {\n      {\n        (Float32ArrayView[((((this.__defineSetter__(\"x\", Math.pow(-8, x)))) == (+(-1.0/0.0)))-((((Float64ArrayView[((0x7d9aef48)+(0x5e762294)) >> 3]))) > (((0x63a2e531)) << (((0x19c448c3) != (0xfb8d8d9)))))) >> 2]) = ((d2));\n      }\n    }\n    (Float32ArrayView[1]) = ((d2));\n    return (((0xcecd0135)))|0;\n    return ((((~~(d1)) >= ((((0x333875df) == (abs((imul((0xffffffff), (0x88a446ce))|0))|0))-(-0x8000000)+((0xffffffff))) | (((+(((0xe1e85532)-(0x8223f0a9))>>>(0x63804*((0x0) == (0x3f3a173b))))))+(0xb32eda8c))))))|0;\n  }\n  return f; })(this, {ff: String.prototype.strike}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [2**53-2, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, Math.PI, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, 42, -(2**53), 1, 0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 2**53, 1/0, 1.7976931348623157e308, 0x100000001, 0x080000000, -0x100000001, -Number.MAX_VALUE, 2**53+2, -0x080000001, -0x080000000, -(2**53-2), 0x07fffffff, 0x100000000, -0x100000000, 0/0, -(2**53+2)]); ");
/*fuzzSeed-85495475*/count=1531; tryItOut("\"use strict\"; /*MXX3*/g0.String.name = g2.String.name;");
/*fuzzSeed-85495475*/count=1532; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.log10(Math.max(( + (( + Math.cosh(x)) % ((x | 0) ** (mathy0(Math.fround(x), y) | 0)))), (Math.acosh((-0x100000000 >>> 0)) >>> 0))); }); ");
/*fuzzSeed-85495475*/count=1533; tryItOut("/*vLoop*/for (let aevrfg = 0; aevrfg < 17; ++aevrfg) { var x = aevrfg; print(x); } ");
/*fuzzSeed-85495475*/count=1534; tryItOut("let (a) { Object.defineProperty(this, \"v1\", { configurable: (a % 66 == 64), enumerable: true,  get: function() {  return -0; } }); }");
/*fuzzSeed-85495475*/count=1535; tryItOut("t1[x];");
/*fuzzSeed-85495475*/count=1536; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1537; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.max(( + (( + Math.acos((Math.imul((Math.fround((-0x080000000 >>> 0)) | 0), (y | 0)) | 0))) && (((0x080000000 | 0) * (( ! Math.fround(1/0)) | 0)) === y))), (( ! x) | 0)) >>> 0) >> Math.atan2(Math.trunc(Math.atan2(( + Math.cbrt(0x100000000)), y)), (Math.pow(x, x) & ( + (( + ((( + (Math.sign(Math.fround(x)) | 0)) ? (x >>> 0) : (-0x0ffffffff >>> 0)) >>> 0)) <= y))))); }); testMathyFunction(mathy0, [1/0, 42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, -1/0, -Number.MIN_VALUE, 0x100000001, -0x080000001, 2**53, -0x100000000, 2**53-2, Number.MIN_VALUE, 0/0, -(2**53), -0, -(2**53+2), 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, 0.000000000000001, 0x080000001, 2**53+2]); ");
/*fuzzSeed-85495475*/count=1538; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (( + Math.abs(( + Math.cos((( ~ y) | ( + (x | 0))))))) | 0)) | 0); }); testMathyFunction(mathy2, [2**53+2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 2**53, 0x080000001, Number.MAX_SAFE_INTEGER, -0, -(2**53-2), -Number.MAX_VALUE, -0x07fffffff, 0x080000000, 0x0ffffffff, 0, -(2**53), -(2**53+2), 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -1/0, Number.MAX_VALUE, -0x080000001, 0x07fffffff, Math.PI, 0/0, 0.000000000000001, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000000, 42, 1.7976931348623157e308, -0x0ffffffff, 1, 0x100000001]); ");
/*fuzzSeed-85495475*/count=1539; tryItOut("Object.defineProperty(this, \"a0\", { configurable: (y % 58 == 28), enumerable: (x % 12 != 8),  get: function() {  return a1.map((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) { var r0 = a6 % a13; var r1 = 4 & a14; var r2 = 5 & 6; var r3 = a10 / 2; var r4 = 8 - 9; var r5 = a4 * 5; var r6 = 8 ^ a7; a11 = 1 ^ 9; a9 = r2 ^ a15; var r7 = a1 - 1; var r8 = 6 + 5; var r9 = a0 & a15; r8 = a9 | a12; var r10 = 4 * a0; var r11 = x % r1; var r12 = r10 * r1; var r13 = r9 + a12; var r14 = a14 ^ r6; print(r0); var r15 = r6 & r5; var r16 = a15 | 0; var r17 = 5 - 8; var r18 = r8 | a8; var r19 = a8 | r11; r8 = 7 * a11; return a0; })); } });y = e >> x;");
/*fuzzSeed-85495475*/count=1540; tryItOut("g1.h1.has = (function mcc_() { var fssvmf = 0; return function() { ++fssvmf; f1(true);};})();");
/*fuzzSeed-85495475*/count=1541; tryItOut("r2 = new RegExp(\"(?![^]|(?!(\\\\v)+|\\\\D))|(\\\\W)|(?:\\\\W|[^]{2,})\\\\3+?\", \"gyim\");");
/*fuzzSeed-85495475*/count=1542; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.fround(Math.imul((( ! (y >>> 0)) != mathy0(Math.trunc(( ~ 2**53)), y)), Math.fround((x >= (0/0 >>> x))))) % (Math.sin(Math.pow(Math.clz32(x), Math.fround(Math.max(( ~ ( + (( + x) * y))), mathy3(-0x07fffffff, Math.fround(( + Math.fround(Math.sign(Number.MAX_VALUE))))))))) >>> 0)); }); testMathyFunction(mathy4, [-(2**53), -0, -0x07fffffff, Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, -(2**53+2), -0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, -0x0ffffffff, 1/0, -0x080000001, 2**53-2, Number.MIN_VALUE, 0x080000001, 0/0, 1, -0x080000000, -1/0, 0x07fffffff, 0x100000001, 42, 2**53+2, 2**53, 0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-85495475*/count=1543; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-85495475*/count=1544; tryItOut("/*MXX2*/g0.Promise.prototype.constructor = f0;");
/*fuzzSeed-85495475*/count=1545; tryItOut("window;a0.splice(NaN, 11, e2, i0, (encodeURIComponent)( '' ));");
/*fuzzSeed-85495475*/count=1546; tryItOut("\"use strict\"; let(eval = /*MARR*/[new String('q'), function(){}, new String('q'), new String('q'), function(){}, new String('q'), new String('q'), new String('q'), new String('q'), function(){}, new String('q'), function(){}, new String('q'), function(){}, function(){}, function(){}].some(objectEmulatingUndefined, (c = Proxy.create(({/*TOODEEP*/})(window), this))), {NaN: [{x, NaN: [(false ? y : x)((arguments.watch(\"valueOf\", (function(x, y) { return x; })))), [], {}]}]} = (intern((yield [z1]))), x = new function(y) { return Math }(x), x, zuinbk, ewjefi, hyxhck, -Number.MIN_VALUE = (false && [z1,,])) ((function(){(21 == new let (ldnapj, x, x, qprrlg, x, pelujz, vehoyw, \u3056, nowivo, oohnkk) window());})());w.fileName;");
/*fuzzSeed-85495475*/count=1547; tryItOut("/*RXUB*/var r = new RegExp(\"((?:(?:^(?!.)\\\\3?)+)|\\\\1)\", \"y\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-85495475*/count=1548; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( + (( + ( - mathy1(y, x))) && ( + ((((mathy0((y | 0), (Math.fround(Math.max(Math.fround(x), Math.fround((( ! (y | 0)) | 0)))) | 0)) | 0) | 0) == Math.fround(mathy1(( + Math.fround(Math.PI)), Math.asin(Math.fround(Math.fround(Math.asinh((y >>> 0)))))))) | 0)))); }); testMathyFunction(mathy2, [1.7976931348623157e308, Math.PI, 0x100000000, -(2**53+2), 2**53, -0, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0x100000001, 2**53-2, 0x080000001, 0x100000001, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, 0x080000000, 0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 1, -0x07fffffff, 0.000000000000001, -0x080000000, Number.MIN_VALUE, 42, -1/0, 2**53+2, 0]); ");
/*fuzzSeed-85495475*/count=1549; tryItOut("/*infloop*/for(let z in /\\3/gyi) g1.offThreadCompileScript(\"mathy1 = (function(x, y) { return Math.abs(((((x % (( - (Math.exp(-Number.MIN_VALUE) >>> 0)) >>> 0)) >>> 0) || (( - mathy0((Math.pow((((y & -Number.MIN_SAFE_INTEGER) == x) >>> 0), (2**53-2 >>> 0)) >>> 0), Math.fround(( + Math.pow(y, ( + y)))))) | 0)) | 0)); }); testMathyFunction(mathy1, [-0x07fffffff, -Number.MIN_VALUE, -(2**53-2), 42, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 1, 0, -0x080000001, 0x100000000, 1/0, 0/0, -0x100000001, Math.PI, 2**53-2, -0x100000000, -1/0, 0x100000001, 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -(2**53+2), -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001]); \");");
/*fuzzSeed-85495475*/count=1550; tryItOut("\"use strict\"; let(c) ((function(){/*tLoop*/for (let x of /*MARR*/[x, x, {x:3},  /x/ ,  /x/ ,  /x/ , new Number(1), {x:3},  /x/ , new Number(1),  /x/ , {x:3}, x, x, x, {x:3}, {x:3}, new Number(1), {x:3}, x, {x:3},  /x/ ,  /x/ , {x:3}, new Number(1),  /x/ , x, new Number(1), new Number(1), x,  /x/ , {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3},  /x/ , {x:3}, new Number(1), new Number(1), new Number(1), {x:3}, {x:3}, new Number(1), {x:3},  /x/ , new Number(1),  /x/ , {x:3}, new Number(1), new Number(1), {x:3}, x, new Number(1), new Number(1), x,  /x/ ]) { Object.defineProperty(this, \"o2.m0\", { configurable: true, enumerable: (x % 4 == 2),  get: function() {  return new Map(t1); } }); }})());");
/*fuzzSeed-85495475*/count=1551; tryItOut("v0 = Object.prototype.isPrototypeOf.call(f2, s0);");
/*fuzzSeed-85495475*/count=1552; tryItOut("/*RXUB*/var r = /(?=(\\3)[^]|.??)\\u0092+?|\\S{1,2}/im; var s = \"\\n0+y\"; print(s.split(r)); ");
/*fuzzSeed-85495475*/count=1553; tryItOut("\"use strict\";  for (var y of this) /*RXUB*/var r = r0; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-85495475*/count=1554; tryItOut("\"use strict\"; o1.g2.v2 = Object.prototype.isPrototypeOf.call(g1, e1);");
/*fuzzSeed-85495475*/count=1555; tryItOut("/* no regression tests found */");
/*fuzzSeed-85495475*/count=1556; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.atan2(Math.clz32(( + Math.atan2(((-(2**53-2) | 0) & 0/0), x))), ((Number.MIN_SAFE_INTEGER | 0) ? (( + Math.abs(x)) || (y , ( + y))) : (Math.sinh(Math.fround(Math.imul((y >>> 0), (x >>> 0)))) | 0))), ( ! ( - (( + (Math.round(( ! y)) | 0)) >>> 0)))); }); testMathyFunction(mathy5, [0/0, 1/0, -0, -0x100000000, 0x07fffffff, -Number.MIN_VALUE, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x07fffffff, -1/0, 1.7976931348623157e308, 0, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, -(2**53-2), 2**53+2, 2**53-2, 42, 0x100000001, Number.MAX_VALUE, -(2**53+2), -0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 2**53]); ");
/*fuzzSeed-85495475*/count=1557; tryItOut("");
/*fuzzSeed-85495475*/count=1558; tryItOut("m0 = new Map;");
/*fuzzSeed-85495475*/count=1559; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.asin(( + (Math.clz32((( ~ Math.fround(Math.min(Math.fround(Math.hypot((y | 0), (x >>> 0))), Math.fround(x)))) | 0)) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[true, x, NaN, new Number(1.5), null, true, NaN, NaN, null, new Number(1.5), null, null, new Number(1.5), null, x, x, true, null, x, true, new Number(1.5), null, true, x, true, new Number(1.5), null, new Number(1.5), x, x, null, true, NaN, null, true, true, true, x, NaN, new Number(1.5), NaN, null, new Number(1.5), x, null, NaN, null, null, new Number(1.5), NaN, x, new Number(1.5), x, new Number(1.5), new Number(1.5), new Number(1.5), NaN, true, true, null, true, true, null, x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), null, null, null, new Number(1.5), true, null, NaN, true, null, new Number(1.5), null, new Number(1.5)]); ");
/*fuzzSeed-85495475*/count=1560; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?:\\\\xF0)*?|(?![^]{137438953473,137438953474})+|(?:[\\ud49e\\\\cF-Y\\\\W\\\\u8347])|(?![^]|[\\\\\\ufbfd-\\\\x44\\\\xDD]|(?:\\\\D{1,2}[^\\\\W\\\\xfb-\\u1a2b\\\\u00Cc\\\\u]))|(?!\\\\3?)){1,3}\", \"yi\"); var s = \"\"; print(s.replace(r, ({/*TOODEEP*/}))); ");
/*fuzzSeed-85495475*/count=1561; tryItOut("\"use strict\"; a0.push(h2);");
/*fuzzSeed-85495475*/count=1562; tryItOut("s1 = Array.prototype.join.call(a2, s0);");
/*fuzzSeed-85495475*/count=1563; tryItOut("\"use strict\"; (void schedulegc(g0));/*vLoop*/for (var stmvvo = 0; stmvvo < 6; ++stmvvo) { let w = stmvvo; (Uint8ClampedArray); } ");
/*fuzzSeed-85495475*/count=1564; tryItOut("for (var v of t2) { try { v1 = evaluate(\"function f0(a0) (delete (Math.pow(Math.hypot(0xB504F332, new RegExp(\\\"(?=\\\\\\\\2)\\\", \\\"yi\\\")), -23\\n)))\", ({ global: g1.g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: let (NaN = let (d = x) [ \"\" ], w) new RegExp(\"[^]{4,8}(?:(\\\\B|(?:\\\\S)?))\", \"y\"), sourceIsLazy: true, catchTermination: [1,,] })); } catch(e0) { } try { /*RXUB*/var r = r0; var s = s1; print(r.exec(s)); print(r.lastIndex);  } catch(e1) { } g1.v2 = (v1 instanceof f2); }");
/*fuzzSeed-85495475*/count=1565; tryItOut("switch(null) { default: break;  }");
/*fuzzSeed-85495475*/count=1566; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: let (a) (a << a), sourceIsLazy: x, catchTermination: false }));");
/*fuzzSeed-85495475*/count=1567; tryItOut("delete h0.hasOwn;");
/*fuzzSeed-85495475*/count=1568; tryItOut("Object.defineProperty(this, \"t1\", { configurable: (x % 3 == 2), enumerable: timeout(1800),  get: function() {  return new Float32Array(b1); } });");
/*fuzzSeed-85495475*/count=1569; tryItOut("\"use strict\"; /*MXX3*/g1.Number.isFinite = g0.Number.isFinite;");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
