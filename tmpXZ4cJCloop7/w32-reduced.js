

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
/*fuzzSeed-8783892*/count=517; tryItOut("s0 += s0;");
/*fuzzSeed-8783892*/count=518; tryItOut("/*infloop*/while(18){Array.prototype.sort.call(o0.a2, (function() { try { Object.defineProperty(o1.o2, \"v2\", { configurable: false, enumerable: window,  get: function() {  return new Number(-Infinity); } }); } catch(e0) { } h0.getOwnPropertyNames = (function() { for (var j=0;j<16;++j) { f2(j%2==1); } }); throw t2; }));v0 = Object.prototype.isPrototypeOf.call(h1, g0.p0); }\nf1(o2.g2.g1);\n");
/*fuzzSeed-8783892*/count=519; tryItOut("\"use asm\"; testMathyFunction(mathy2, [-0x0ffffffff, 0x080000001, -0x100000001, 2**53, -0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -Number.MAX_VALUE, 0x0ffffffff, -(2**53), 0/0, -0x100000000, -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, 0, 1, 0x080000000, -(2**53-2), 0x100000001, 0.000000000000001, Number.MAX_VALUE, Math.PI, -0x07fffffff, -0, 0x07fffffff, Number.MIN_VALUE, -(2**53+2), -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000]); ");
/*fuzzSeed-8783892*/count=520; tryItOut("v0 = (e1 instanceof g1.f0);");
/*fuzzSeed-8783892*/count=529; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return +(x);\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [42, -0x0ffffffff, -1/0, -(2**53-2), 0.000000000000001, 0, 0x100000000, -0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53, 1.7976931348623157e308, -(2**53), -(2**53+2), 2**53+2, 2**53-2, 0x080000001, -0x100000000, 1, -0x080000001, 1/0, 0x080000000, 0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, -0x080000000, Math.PI, Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-8783892*/count=530; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.sin((Math.acosh(((Number.MAX_SAFE_INTEGER | 0) ? Math.fround(Math.atan2(x, y)) : (( + (Math.trunc(x) | 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy5, [null, (function(){return 0;}), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), false, '', NaN, -0, 1, ({valueOf:function(){return '0';}}), '0', (new Number(-0)), /0/, (new Number(0)), (new Boolean(false)), (new Boolean(true)), 0, ({toString:function(){return '0';}}), (new String('')), [0], '\\0', [], '/0/', true, undefined, 0.1]); ");
/*fuzzSeed-8783892*/count=531; tryItOut("\"use strict\"; g1.valueOf = (function() { try { a0.toSource = (function mcc_() { var zvluox = 0; return function() { ++zvluox; if (/*ICCD*/zvluox % 8 != 6) { dumpln('hit!'); g2.t2[5] = URIError.prototype.toString; } else { dumpln('miss!'); try { g1.g1.o2.v0 = (b1 instanceof o1); } catch(e0) { } ; } };})(); } catch(e0) { } try { this.v0 = (this.e1 instanceof v2); } catch(e1) { } try { Array.prototype.forEach.apply(a2, [(function() { try { m2.has(o0.o2.o0.t1); } catch(e0) { } try { v1.toSource = f0; } catch(e1) { } try { delete g0[ /x/g ]; } catch(e2) { } a2 = new Array; return o2; })]); } catch(e2) { } e0.has(f2); return b1; });");
/*fuzzSeed-8783892*/count=532; tryItOut("/*tLoop*/for (let d of /*MARR*/[x, [], objectEmulatingUndefined(), [],  /x/g , x,  /x/g , x,  /x/g , objectEmulatingUndefined(), x]) { a0.reverse(e1, h1); }\n/*infloop*/M: for (var this.zzz.zzz of /[\u0090-\u5b35\\b\u0017-\\cF]/m) /*RXUB*/var r = /\\w|(?=\\d*)/; var s = \"0\"; print(uneval(r.exec(s))); \n");
/*fuzzSeed-8783892*/count=533; tryItOut("\"use strict\"; this.a0 = a2.map((function() { try { o0.v2 = a1.length; } catch(e0) { } try { v1 = g2.runOffThreadScript(); } catch(e1) { } m1.has(s2); return o1; }));");
/*fuzzSeed-8783892*/count=534; tryItOut("do print(x); while((x = Proxy.createFunction(({/*TOODEEP*/})(this), String.prototype.link)) && 0);");
/*fuzzSeed-8783892*/count=535; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.min(Math.fround(( ~ ( ! ( + (Math.imul(x, ( + Math.hypot(0, x))) >>> 0))))), Math.fround(Math.imul((((( ~ y) >>> 0) <= ((Math.log(((( ~ (Math.cosh(y) >>> 0)) >>> 0) | 0)) | 0) >>> 0)) >>> 0), ( ~ Math.atan2(x, ( + x)))))) >>> 0); }); testMathyFunction(mathy2, [0, -0x100000000, -(2**53+2), -0x0ffffffff, 0.000000000000001, 0x080000000, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), -0x100000001, 2**53, 1/0, -Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, 0x07fffffff, -0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, -0, 42, -0x080000001, 0x100000000, 0x100000001, 0x080000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-8783892*/count=536; tryItOut("mathy2 = (function(x, y) { return (mathy1(((Math.imul((((((Math.pow(0x0ffffffff, ( + ( - x))) >>> 0) % y) | 0) ^ (0 | 0)) | 0), ( + Math.fround(Math.min(Math.imul(( + y), x), Math.fround(Math.atan2(y, (( + (x | 0)) | 0))))))) | 0) | 0), ((((((Math.imul(y, mathy0(y, Math.fround(Math.clz32(y)))) >>> 0) ^ ((((y | 0) + (((y << x) >>> 0) | 0)) | 0) >>> 0)) >>> 0) >>> 0) != Math.hypot(( ~ ( ! ( + Math.max(y, x)))), (mathy0((x | 0), x) | 0))) >>> 0)) | 0); }); testMathyFunction(mathy2, [2**53, -Number.MIN_VALUE, 2**53-2, 0x100000000, Number.MIN_SAFE_INTEGER, 0, -0x080000000, 42, 0x080000001, -1/0, -0x080000001, Math.PI, 1/0, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -0, 1.7976931348623157e308, 1, 2**53+2, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 0/0, -(2**53-2), -(2**53), -0x100000000, -0x0ffffffff, -0x07fffffff, 0x100000001, -Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-8783892*/count=541; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-8783892*/count=542; tryItOut("/*ODP-1*/Object.defineProperty(a0, \"toString\", ({configurable: false}));");
/*fuzzSeed-8783892*/count=543; tryItOut("b1 = Proxy.create(this.h0, e0);");
/*fuzzSeed-8783892*/count=544; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return Math.abs(((( ! ( + (((y + y) | ( + ( - x))) < 2**53))) >>> 0) ? (( + ( - ( + Math.pow(( + Math.asinh(Math.fround(0x0ffffffff))), ( + (( + (( ! ( + (( + y) ? ( + 0) : x))) >>> 0)) | 0)))))) >>> 0) : (Math.imul((Math.fround(Math.max(y, y)) | 0), ( ~ Math.expm1(Math.sqrt(Math.fround(2**53+2))))) | 0))); }); ");
/*fuzzSeed-8783892*/count=545; tryItOut("/*vLoop*/for (pdkjwp = 0; pdkjwp < 22; ++pdkjwp) { z = pdkjwp; this.v0 = a0[2]; } ");
/*fuzzSeed-8783892*/count=546; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return ( + Math.hypot(( + ((((( ~ ( + Math.cos(Math.fround(Math.hypot(0x0ffffffff, -(2**53+2)))))) >>> 0) >> (Math.fround(Math.hypot(( + -0x100000000), Math.fround(y))) | 0)) >>> 0) << Math.fround((( + Math.log10((Math.sqrt((( - (y >>> 0)) >>> 0)) >>> 0))) - y)))), ( + mathy2((Math.fround(Math.max(Math.fround((((y | 0) << (x >>> 0)) | 0)), Math.fround(( + (y >>> 0))))) >>> 0), ((Math.max((( ! (( + (y , y)) < Math.cosh((y >>> 0)))) | 0), Math.fround((Math.min(y, (y - 42)) ^ y))) | 0) >>> 0))))); }); ");
/*fuzzSeed-8783892*/count=547; tryItOut("testMathyFunction(mathy2, [0x080000001, -0, 2**53, 0x100000000, 2**53-2, -0x07fffffff, -0x100000001, 1, 1.7976931348623157e308, -1/0, -0x080000000, Math.PI, -(2**53), 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 2**53+2, 0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, 0/0, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 0, 42]); ");
/*fuzzSeed-8783892*/count=548; tryItOut("print(x);");
/*fuzzSeed-8783892*/count=549; tryItOut("t1[undefined.valueOf(\"number\")];");
/*fuzzSeed-8783892*/count=550; tryItOut("h1.toString = (function() { for (var j=0;j<45;++j) { f1(j%3==0); } });");
/*fuzzSeed-8783892*/count=551; tryItOut("\"use strict\"; x.lineNumber;with({}) (4277);");
/*fuzzSeed-8783892*/count=552; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.log10((( + Math.min(( + Math.ceil((y >>> 0))), ( + ( + Math.max(Math.fround(Math.log1p(Math.hypot(y, x))), x))))) >= (-Number.MIN_SAFE_INTEGER >>> ( + Math.imul(( + mathy0(y, x)), (-Number.MIN_VALUE != (Math.fround(x) < y))))))); }); testMathyFunction(mathy1, [-0x080000000, 2**53, 1/0, Math.PI, Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, -0x100000000, -0x100000001, -1/0, -(2**53), 42, -0, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 2**53+2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), 0.000000000000001, -0x07fffffff, -0x080000001, 2**53-2]); ");
/*fuzzSeed-8783892*/count=553; tryItOut("\"use asm\"; o0.valueOf = (function(j) { if (j) { try { e2 = new Set(o0); } catch(e0) { } try { selectforgc(o1); } catch(e1) { } try { g0.offThreadCompileScript(\"function f2(this.p2)  { return ( ~ (Math.fround(Math.tan(((Math.fround((((this.p2 ? this.p2 : this.p2) | 0) < Math.fround(42))) >>> ( + this.p2)) * Math.imul(( - x), x)))) >>> Math.trunc((((Math.trunc((( ! this.p2) >>> 0)) >>> 0) >> (Math.pow(this.p2, this.p2) | 0)) | 0)))) } \"); } catch(e2) { } f0(s1); } else { try { v1 = Object.prototype.isPrototypeOf.call(i0, o1); } catch(e0) { } try { for (var v of t2) { try { selectforgc(o0); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(b0, e0); } } catch(e1) { } try { print(this.s1); } catch(e2) { } a0[19]; } });");
/*fuzzSeed-8783892*/count=554; tryItOut("mathy5 = (function(x, y) { return (( ! Math.fround(Math.fround(Math.ceil(Math.fround(( ~ ( + ( + y)))))))) >>> 0); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -0, 42, -Number.MAX_VALUE, 0x080000000, 1/0, 0, Math.PI, 0x07fffffff, 2**53-2, Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), -0x080000001, Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, 0x0ffffffff, 0x100000001, -0x07fffffff, 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -(2**53+2), -1/0, 2**53, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, 2**53+2]); ");
/*fuzzSeed-8783892*/count=555; tryItOut("(/*FARR*/[new RegExp(\"[^]\", \"gyim\"),  '' , {}, , true].sort(decodeURIComponent)\n);");
/*fuzzSeed-8783892*/count=556; tryItOut("print(a0);");
/*fuzzSeed-8783892*/count=609; tryItOut("\"use strict\"; t0 = t0.subarray(7, 14);");
/*fuzzSeed-8783892*/count=610; tryItOut("\"use strict\"; \"use asm\"; /*hhh*/function wqxamh(\u3056, x, x, d = w(a), x, NaN, \u3056 = a, c = [[1]], x, y, a, setter, c, window, x, b = z, w, x, x, \u3056, x, \u3056, NaN, x, y, d, x, a, \u3056, c =  /x/g , \u3056, a, x, y = window, x, a, x, x, window, x = x, x, eval, window, z, x, \u3056, c, y, z, d, x, x, \u3056, this.x, x, w, x = -20, c, x, x, x, \"29\", e = \"\\uD9E5\", x, x, y, NaN, b, b, x, NaN, a = window, c, d = z, z, this.x, x, b = a, NaN, window, w = \"\\uA2B4\", x, window, x, \u3056, w, e, d = function ([y]) { }, z, window, a, window, x = 0, ...x){(void schedulegc(g1));}wqxamh(this.__defineSetter__(\"window\", String.prototype.codePointAt));");
/*fuzzSeed-8783892*/count=611; tryItOut("\"use strict\"; /*infloop*/for(let {x: {x}, x: {a: []}} = (4277); /*FARR*/[(p={}, (p.z = Math)()), .../*FARR*/[[],  \"\" ,  '' , ...[], ], , , , ...new Array(-23)].filter(/*wrap1*/(function(){ print(-2);return /*wrap2*/(function(){ var xrfugw = false; var labpna = (new Function(\"Array.prototype.pop.apply(this.a2, [o2]);\")); return labpna;})()})());  '' .__defineGetter__(\"d\", \"\\uC1CB\")) return \"\\u9CAC\";");
/*fuzzSeed-8783892*/count=612; tryItOut("mathy2 = (function(x, y) { return Math.imul((Math.pow(((Math.max((y >>> 0), ((Math.hypot((( + (y | 0)) >>> 0), (Math.imul((-1/0 , Math.pow(( + x), ( + -(2**53)))), Math.max(( + Math.fround(( - 2**53))), x)) | 0)) | 0) >>> 0)) >>> 0) >>> 0), (((y >> (Math.cbrt(Math.pow(0x080000000, Math.fround(-0x0ffffffff))) == Math.hypot(Math.log1p((Math.tan(1/0) | 0)), x))) >>> 0) >>> 0)) >>> 0), ( ~ (((Math.fround(x) != (x | 0)) | 0) < ( + Math.pow((1/0 >>> 0), Math.fround((Math.fround(y) ? Math.fround(y) : ((-0x0ffffffff ^ x) | 0)))))))); }); testMathyFunction(mathy2, [false, 0, -0, '/0/', 1, (function(){return 0;}), '\\0', (new Boolean(false)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Number(-0)), 0.1, (new Boolean(true)), (new Number(0)), objectEmulatingUndefined(), [], '0', (new String('')), [0], null, ({valueOf:function(){return '0';}}), NaN, /0/, true, undefined, '']); ");
/*fuzzSeed-8783892*/count=613; tryItOut("for (var p in m2) { v0.valueOf = (function() { try { this.g2.g2.offThreadCompileScript(\"print(this);\\nprint(\\\"\\\\uDBCE\\\");\\n\"); } catch(e0) { } print(f1); return t1; }); }");
/*fuzzSeed-8783892*/count=614; tryItOut("");
/*fuzzSeed-8783892*/count=615; tryItOut("\"use strict\"; var dgtsdw = new SharedArrayBuffer(0); var dgtsdw_0 = new Uint8ClampedArray(dgtsdw); window;");
/*fuzzSeed-8783892*/count=616; tryItOut("/*RXUB*/var r = /\\3/g; var s = \"ooooo\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-8783892*/count=625; tryItOut("/* no regression tests found */");
/*fuzzSeed-8783892*/count=626; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + Math.cosh(Math.fround((( + Math.asin(Math.hypot(x, Math.fround(( + Math.hypot(( + y), ( + y))))))) || x)))) - ( + Math.fround((Math.fround(Math.sin(Math.fround(mathy0(y, ( - x))))) >= Math.fround(Math.fround(Math.hypot((2**53+2 | 0), (( ~ (x >>> 0)) | 0)))))))); }); testMathyFunction(mathy4, [(new Boolean(true)), (new Number(-0)), (new String('')), false, 0.1, (new Number(0)), '', ({valueOf:function(){return 0;}}), '\\0', 0, undefined, (new Boolean(false)), 1, '0', objectEmulatingUndefined(), true, ({toString:function(){return '0';}}), null, NaN, '/0/', ({valueOf:function(){return '0';}}), /0/, [0], (function(){return 0;}), -0, []]); ");
/*fuzzSeed-8783892*/count=627; tryItOut("mathy3 = (function(x, y) { return Math.fround(( - ( - Math.imul(Math.fround(Math.trunc(y)), x)))); }); ");
/*fuzzSeed-8783892*/count=628; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 2**53, -0x100000000, Math.PI, Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, -(2**53), -0x07fffffff, -0x080000001, 0x0ffffffff, 2**53-2, 42, 0x07fffffff, 1, 0/0, -0, -(2**53+2), -0x080000000, 0x080000001, 1.7976931348623157e308, 2**53+2, -(2**53-2), -0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, -1/0, 0x100000000, 0x080000000]); ");
/*fuzzSeed-8783892*/count=629; tryItOut("mathy1 = (function(x, y) { return ( - ( - ((-0x0ffffffff || Math.fround(Math.asin(Math.fround(mathy0(Math.fround(Math.atan2(x, x)), y))))) | 0))); }); testMathyFunction(mathy1, ['0', true, (new String('')), [0], 0, objectEmulatingUndefined(), 0.1, (new Number(0)), 1, ({toString:function(){return '0';}}), (function(){return 0;}), '/0/', /0/, (new Boolean(true)), '', -0, [], NaN, (new Number(-0)), (new Boolean(false)), '\\0', null, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), false, undefined]); ");
/*fuzzSeed-8783892*/count=630; tryItOut("(p={}, (p.z = window = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { throw 3; }, }; })(y), (1 for (x in [])), Math.pow(12, window)) = function(id) { return id })()) = t2[v2];");
/*fuzzSeed-8783892*/count=631; tryItOut("\"use strict\"; /*bLoop*/for (var bhgrye = 0; bhgrye < 27; ++bhgrye) { if (bhgrye % 4 == 3) { print(x); } else { g0.a1.push(this.b0); }  } ");
/*fuzzSeed-8783892*/count=632; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! ( + Math.sinh(Math.max(y, ((((( - ( + 0x100000001)) >>> 0) >>> 0) >>> (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [-(2**53-2), -Number.MAX_VALUE, -0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, -1/0, 1, -(2**53+2), Number.MIN_VALUE, 2**53+2, 0x07fffffff, -0x100000000, 0x0ffffffff, 0x100000001, Math.PI, 42, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 0x100000000, -0, -0x07fffffff, 0.000000000000001, 2**53, -0x100000001, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, -0x0ffffffff, 0x080000000, 0, -0x080000000]); ");
/*fuzzSeed-8783892*/count=633; tryItOut("");
/*fuzzSeed-8783892*/count=634; tryItOut("this.v1 + '';");
/*fuzzSeed-8783892*/count=635; tryItOut("o0.h1.hasOwn = o0.f0;");
/*fuzzSeed-8783892*/count=636; tryItOut("\"use strict\"; v2 = -0;");
/*fuzzSeed-8783892*/count=637; tryItOut("mathy2 = (function(x, y) { return (( + ( ~ Math.fround(Math.atan2(mathy1((y >>> 0), x), (y % Math.asinh(x)))))) | Math.fround(Math.min(Math.fround(Math.atan2(Math.fround(x), Math.fround(( + ( - ( + Math.abs(x))))))), ( + (( ~ Math.atan2(2**53+2, 1)) >>> 0))))); }); testMathyFunction(mathy2, [-(2**53), 1, -0x080000000, 1/0, -1/0, -(2**53-2), -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, 0x07fffffff, 0x100000000, -0x100000000, -0x080000001, 0x0ffffffff, 0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, -Number.MAX_VALUE, Math.PI, 0x100000001, 2**53, 42, -(2**53+2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, -0x100000001, 0/0]); ");
/*fuzzSeed-8783892*/count=638; tryItOut("mathy2 = (function(x, y) { return ( + ( + ( + Math.cbrt((mathy0((Math.min(y, x) / 1.7976931348623157e308), ( + Math.fround((Math.fround(Math.exp(( + ( + Math.imul((x | 0), ( + x)))))) ? Math.fround(y) : Math.fround(( + ( ! ( + ( ! y))))))))) | 0))))); }); testMathyFunction(mathy2, [0x0ffffffff, -(2**53-2), 0x100000001, -0x0ffffffff, 42, -1/0, 0x080000000, 1, 0.000000000000001, 0, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -0x100000000, -0x080000000, 2**53+2, 2**53, -0x07fffffff, -0, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, -Number.MAX_VALUE, -0x100000001, 0/0, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000000, 0x07fffffff]); ");
/*fuzzSeed-8783892*/count=639; tryItOut("i0 = new Iterator(e0, true);");
/*fuzzSeed-8783892*/count=640; tryItOut("a0.splice(NaN, (window = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(Math.pow((yield arguments), ( /x/g (-256,  \"\" )))), Date.prototype.setYear, Int8Array)), b2, s1);");
/*fuzzSeed-8783892*/count=673; tryItOut("this.t0 = new Int8Array(b0, 32, 6);");
/*fuzzSeed-8783892*/count=674; tryItOut("/* no regression tests found */");
/*fuzzSeed-8783892*/count=675; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(( ~ ( + Math.sin((( + (( + y) >> ( + Math.ceil(( ! Math.atan2((x | 0), Math.fround(x))))))) >>> 0))))); }); testMathyFunction(mathy3, [-0x07fffffff, 0x0ffffffff, 0x07fffffff, 0x100000000, 0.000000000000001, -(2**53), -(2**53-2), 0x100000001, -0x0ffffffff, -1/0, -Number.MAX_VALUE, -(2**53+2), 2**53-2, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 1/0, 0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 0, 2**53+2, -0x100000001, 2**53, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -0, -0x100000000, 42, 1, -Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-8783892*/count=676; tryItOut("((void version(180)));");
/*fuzzSeed-8783892*/count=677; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh(((( + (( ~ ( + ( + ( + x)))) | 0)) | 0) ? Math.max((Math.expm1((x | 0)) | 0), (Math.atan2(x, (x >>> 0)) >>> 0)) : (Math.tan(Math.fround((-(2**53-2) ? (y | 0) : (-0x07fffffff | 0)))) | 0))); }); testMathyFunction(mathy0, [-0x080000001, -0x0ffffffff, 0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53+2), Math.PI, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0x080000000, 1/0, 42, 1, 2**53, 0/0, -0x100000000, -(2**53-2), -0x07fffffff, -0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 0, 2**53-2, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, -1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-8783892*/count=678; tryItOut("testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, 1/0, -0, 0x080000000, -0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, -0x080000000, -0x100000000, -0x100000001, 2**53-2, 1, 2**53, -Number.MAX_VALUE, 0x100000000, -(2**53), -0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, 42, -Number.MAX_SAFE_INTEGER, 0, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 2**53+2, -1/0]); ");
/*fuzzSeed-8783892*/count=679; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\b|\\\\1+(?![^])|(?=(?:^|(?=(?!.))))|\\\\3(?!\\\\x94|[^\\\\f-\\\\v\\u8be4\\\\s]|.|\\\\3)\", \"g\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-8783892*/count=680; tryItOut("this.o2.o0 = Object.create(i1);");
/*fuzzSeed-8783892*/count=689; tryItOut("\"use strict\"; /*vLoop*/for (let igsaow = 0; igsaow < 74; ++igsaow) { var x = igsaow; v2 = evalcx(\"/* no regression tests found */\", g2); } ");
/*fuzzSeed-8783892*/count=690; tryItOut("f1 + '';");
/*fuzzSeed-8783892*/count=691; tryItOut("Array.prototype.shift.apply(a2, [f0, v2, o0, f1, p2, e0]);");
/*fuzzSeed-8783892*/count=692; tryItOut("mathy5 = (function(x, y) { return Math.max((( ! (( ! ( + y)) >>> 0)) >>> 0), ( + Math.fround(((( + y) / ( ! ( + Math.fround((Math.fround(y) && Math.fround(y)))))) || Math.fround((x ^ x)))))); }); testMathyFunction(mathy5, [-0x100000001, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, Number.MIN_VALUE, 0x080000000, 42, 0x0ffffffff, 0x080000001, -0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -0x07fffffff, 0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -1/0, 1.7976931348623157e308, 0x100000001, 1/0, 0, -(2**53+2), 1, 2**53, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -0, 2**53+2]); ");
/*fuzzSeed-8783892*/count=693; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + Math.atan2(Math.min(Math.min((mathy4(y, Math.fround(( ! x))) || Math.max(-0, x)), (Math.ceil((y | 0)) | 0)), Math.acosh(y)), ( + (( + (( ~ ( + y)) | 0)) >= ( + (Math.max(( + y), (( + (-Number.MAX_SAFE_INTEGER | 0)) | 0)) ? x : x)))))) && (Math.hypot(((( ~ (((2**53-2 == y) ? y : ( ! (Math.atan2(y, x) >>> 0))) | 0)) | 0) >>> 0), ( ~ Math.fround(Math.fround(mathy0(x, (x !== x)))))) >>> 0)); }); ");
/*fuzzSeed-8783892*/count=694; tryItOut("(let (y)  /x/ );");
/*fuzzSeed-8783892*/count=695; tryItOut("i1.send(h0);");
/*fuzzSeed-8783892*/count=696; tryItOut("for(z in ((x)( /* Comment */(makeFinalizeObserver('tenured')).throw(x)))){a0.forEach((function() { for (var j=0;j<75;++j) { f1(j%5==1); } }));this; }");
/*fuzzSeed-8783892*/count=697; tryItOut("t1 = t1.subarray(16, 3);/*MXX2*/g1.Set.name = f0;");
/*fuzzSeed-8783892*/count=698; tryItOut("a0 = Array.prototype.concat.apply(a0, [g1.t2, t2, a1]);");
/*fuzzSeed-8783892*/count=699; tryItOut("{ void 0; void gc('compartment'); } for (var v of e0) { try { v2 = (o0.g1 instanceof this.h1); } catch(e0) { } try { const v2 = g2.eval(\"/* no regression tests found */\"); } catch(e1) { } print(p0); }");
/*fuzzSeed-8783892*/count=700; tryItOut("t2[(new encodeURI((yield (y = [1])), (4277).delete()))] = function ([y]) { };");
/*fuzzSeed-8783892*/count=701; tryItOut("/*infloop*/for(let e; (function ()\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return +((-7.737125245533627e+25));\n  }\n  return f;).call( \"\" , );  '' .prototype) \u000cprint( /x/ );");
/*fuzzSeed-8783892*/count=702; tryItOut("\"use strict\"; print(x);\n((Math.atanh(x)));\n");
/*fuzzSeed-8783892*/count=703; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.ceil(Math.fround((( + ((x / Math.fround(Math.asin(x))) ? x : ( + (Math.fround(Math.fround(Math.cbrt(Math.fround(y)))) <= ( + Math.log10((x >>> 0))))))) , ( + Math.max(( + -0x100000001), ( + x))))))); }); testMathyFunction(mathy5, /*MARR*/[ /x/ ,  /x/ , 3, 3,  \"\" , 3,  /x/ , 3,  \"\" ,  \"\" ,  \"\" ,  /x/ , 3, 3, 3,  \"\" ,  /x/ ,  /x/ ,  \"\" ,  /x/ , 3,  \"\" ,  \"\" ,  \"\" ,  /x/ , 3,  /x/ ,  \"\" ,  \"\" ,  \"\" , 3,  /x/ ,  \"\" , 3, 3, 3, 3, 3, 3,  /x/ ,  /x/ ,  \"\" , 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  /x/ ,  /x/ ,  \"\" , 3,  \"\" ,  \"\" ,  \"\" ,  /x/ , 3, 3,  /x/ ,  /x/ ,  /x/ , 3,  /x/ , 3, 3,  \"\" ,  /x/ , 3, 3, 3,  \"\" ,  /x/ ,  \"\" ,  /x/ ,  /x/ , 3]); ");
/*fuzzSeed-8783892*/count=704; tryItOut("v0 + '';a1.pop(m1);");
/*fuzzSeed-8783892*/count=1025; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.fround(Math.trunc(( - Math.fround(x))))); }); testMathyFunction(mathy2, /*MARR*/[(0/0), {}, new String('q'), objectEmulatingUndefined(), new String('q'), {}, {}, new String('q'), (0/0), (0/0), new String('q'), new String('q'), {}, new String('q'), new String('q'), new String('q'), (0/0), objectEmulatingUndefined(), new String('q'), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), {}, (0/0), new String('q'), (0/0), new String('q'), {}, {}, {}, new String('q'), new String('q'), new String('q')]); ");
/*fuzzSeed-8783892*/count=1026; tryItOut("\"use strict\"; L: {do {(void schedulegc(g1));[,]; } while((new RegExp(\"[^](?!\\\\1[^\\\\0-\\\\v]{8388607,}*?[^]{3,7})\", \"y\")) && 0);neuter(b2, \"change-data\"); }");
/*fuzzSeed-8783892*/count=1027; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0/0, -0x080000001, 1, 1/0, 2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000000, -0, 0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_VALUE, 2**53-2, -0x0ffffffff, 0, 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -0x080000000, -0x100000001, -(2**53-2), 42, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 2**53+2, -Number.MIN_VALUE, 0x100000000, 0x07fffffff]); ");
/*fuzzSeed-8783892*/count=1028; tryItOut("var vljvtl, b = this, bwhrlx, a, vialde, rmjyfk, this.w;/* no regression tests found */");
/*fuzzSeed-8783892*/count=1033; tryItOut("\"use strict\"; let (c) { yield c; }");
/*fuzzSeed-8783892*/count=1034; tryItOut("mathy4 = (function(x, y) { return ((Math.fround(Math.pow(Math.fround((((x >> x) | 0) ? (( ! (Number.MIN_VALUE >>> 0)) >>> 0) : (y & Math.imul(x, x)))), Math.fround((-Number.MIN_VALUE ? ((( ~ (y >>> 0)) >>> 0) | 0) : ((Math.hypot(y, x) >>> 0) == 2**53))))) <= ( - x)) && (Math.max(Math.pow((((y | 0) , (-Number.MIN_VALUE | 0)) | 0), Math.round(Math.tan(y))), (( + Math.hypot(((Math.min(( + (( + y) ** y)), (y | 0)) | 0) >>> 0), ( + ( ~ x)))) | 0)) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[-3/0, false, (0/0), (0/0), -3/0, (0/0), false]); ");
/*fuzzSeed-8783892*/count=1035; tryItOut("if(false) print(x);\nv0 = a1.some((function mcc_() { var dsmslf = 0; return function() { ++dsmslf; if (/*ICCD*/dsmslf % 7 == 4) { dumpln('hit!'); try { m2.get(t1); } catch(e0) { } for (var v of e2) { try { this.h0.has = (function(j) { if (j) { try { o2.i2.toString = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((-8589934593.0));\n    switch ((((0xd0ab585e)) | ((0x458339a1)))) {\n      default:\n        i1 = (i1);\n    }\n    {\n      d0 = (NaN);\n    }\n    i1 = (0x5fd50297);\n    i1 = ((3.777893186295716e+22) < (562949953421311.0));\n    {\n      {\n        {\n          d0 = ((+pow(((+(imul((i1), (0x5df27a1a))|0))), ((+(1.0/0.0))))) + (((17179869185.0)) - ((((+pow(((-5.0)), ((4.722366482869645e+21))))) * (((intern(window))))))));\n        }\n      }\n    }\n    {\n      (Uint32ArrayView[((i1)-(0xfbb5cc68)) >> 2]) = ((i1)*0xfffff);\n    }\n    d0 = (+(0xf184b50e));\n    i1 = (0xfb062fbf);\n    i1 = ((a) = -16);\n    d0 = (+((d0)));\n    i1 = ((0x668a121b) ? ((((i1)+(i1)) >> (x)) != (((imul((-0x8000000), (0xc7c21370))|0) % (~~(-262143.0))) | ((!(0x64d7494e))-(0xfc32e05e)))) : ((((!(0xfdae23d1))) >> ((0xef44c598)))));\n    return +((+sqrt(((4.722366482869645e+21)))));\n  }\n  return f; })(this, {ff: Date.prototype.getMonth}, new ArrayBuffer(4096)); } catch(e0) { } try { o2.b2 = o0.t0.buffer; } catch(e1) { } try { m2.get(p2); } catch(e2) { } a0.push(g2.a1, s0); } else { Array.prototype.sort.call(a1, f1, v1, p2, v2, f1, undefined, window); } }); } catch(e0) { } v1 = r1.compile; } } else { dumpln('miss!'); try { g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 != 0), sourceIsLazy: (x % 4 == 3), catchTermination: (x % 10 == 9) })); } catch(e0) { } try { g0.v1 = evalcx(\"(\\\"\\\\u9AE2\\\");\", g2); } catch(e1) { } try { v1 = g2.runOffThreadScript(); } catch(e2) { } a1.unshift(this.o0.o1, o2); } };})());\n else  if (x) /*tLoop*/for (let c of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), function(){},  /x/ , function(){},  /x/ , function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]) { print(/*FARR*/[ '' , 29, ...[], ...[],  \"\" , true, ].sort); }");
/*fuzzSeed-8783892*/count=1036; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = s2; print(s.match(r)); \ns2 = a0.join(s0);\n");
/*fuzzSeed-8783892*/count=1037; tryItOut("a1.sort();");
/*fuzzSeed-8783892*/count=1038; tryItOut("\"use strict\"; \u000cg1.offThreadCompileScript(\"h0.getOwnPropertyNames = f0;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: true }));\n/*infloop*/ for  each(let c in new RegExp(\"(?!\\\\B\\\\b\\u001a|\\u0086*(?:$)+|\\\\b)\", \"m\")) {a0 = arguments;s0 + i0; }\nv1 = new Number(NaN);");
/*fuzzSeed-8783892*/count=1039; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (((( - -(2**53+2)) | 0) || (Math.clz32(( + Math.tanh(( + (Math.ceil((1 >>> 0)) >>> 0))))) | 0)) | 0)); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, Math.PI, 0x100000000, -(2**53+2), 0/0, 0.000000000000001, -(2**53-2), -1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 1.7976931348623157e308, 1, 2**53, 2**53+2, Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, 42, 0x080000001, -0x100000001, -0, -0x100000000, -Number.MIN_VALUE, 0x100000001, 0x07fffffff, 1/0, 0x080000000, -0x080000001, -0x07fffffff]); ");
/*fuzzSeed-8783892*/count=1040; tryItOut("\"use strict\"; /*RXUB*/var r = /^/gm; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-8783892*/count=1041; tryItOut("e0.has(this.e0);h2.getPropertyDescriptor = f1;");
/*fuzzSeed-8783892*/count=1042; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.asin(( ! (( ~ ((( ! x) | 0) ? Number.MAX_SAFE_INTEGER : (Math.clz32(( ! ( + x))) | 0))) | 0))); }); testMathyFunction(mathy4, [-0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53, 42, 0x080000000, 0.000000000000001, 0x07fffffff, 0/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, 0, Math.PI, -0x100000000, -Number.MIN_VALUE, 2**53-2, 1/0, 0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0x100000001, 2**53+2, -0x100000001, -(2**53-2), -0, -0x07fffffff, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-8783892*/count=1043; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-8783892*/count=1044; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((y ^ (((Math.round(( + Math.max(x, (-0x080000001 >>> 0)))) >>> 0) ? (Number.MAX_SAFE_INTEGER >>> 0) : (((Math.fround(Math.ceil((y >>> 0))) << 0x100000000) ? Math.fround(-(2**53-2)) : 42) >>> 0)) | 0)) >>> ((((Math.expm1((2**53 >>> 0)) >>> 0) | 0) || y) >>> (( - ( - y)) / ( + Math.hypot(( + Math.imul(x, x)), ( + 2**53+2)))))) && (Math.max(-0x080000000, mathy2(Number.MAX_SAFE_INTEGER, Math.cbrt((Math.max((Math.ceil(y) >>> 0), ((y ** (y >>> 0)) >>> 0)) >>> 0)))) == (Math.fround(x) >> y))); }); testMathyFunction(mathy4, /*MARR*/[x, null, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-8783892*/count=1045; tryItOut("\"use strict\"; ");
/*fuzzSeed-8783892*/count=1046; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ((( ! (( + ( + (((( ! x) && ((Math.clz32((x >>> 0)) >>> 0) | 0)) | 0) <= (Math.atan2((x >>> 0), y) <= Math.fround(-0x0ffffffff))))) / Math.round(y))) >>> 0) != Math.fround(Math.log(Math.sinh(x))))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), {}, undefined, (-1/0), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), (-1/0), undefined, objectEmulatingUndefined(), (-1/0), -0x0ffffffff, (-1/0), (-1/0), -0x0ffffffff, -0x0ffffffff, (-1/0), undefined, (-1/0), undefined, (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, -0x0ffffffff, undefined, -0x0ffffffff, (-1/0), -0x0ffffffff, undefined, {}, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, undefined, objectEmulatingUndefined(), undefined, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {}, (-1/0), {}, objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), -0x0ffffffff, {}]); ");
/*fuzzSeed-8783892*/count=1047; tryItOut("b, c = (yield new RegExp(\".^|\\ufe2a*?\\\\xAB{2}\\ue51f+?\", \"yim\")), window = c = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: undefined, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: mathy1, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: encodeURIComponent, set: function() { throw 3; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })((intern(null))), function(y) { yield y; /*tLoop*/for (let d of /*MARR*/[new String('q'), y, y, y, y, y, y, y, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), y, new String('q'), new String('q'), y, y, y, y, y, y, y, y, y, y, new String('q'), new String('q'), y, y, new String('q'), new String('q'), new String('q'), y, new String('q'), new String('q'), new String('q'), new String('q'), y, new String('q'), y, new String('q'), y, y, y, new String('q'), y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, new String('q'), y, new String('q'), y, new String('q'), y, new String('q'), y, y, new String('q'), new String('q'), y, new String('q'), y, y, y, new String('q'), y, y, y, y, new String('q'), new String('q'), y, y, y, new String('q'), y, new String('q'), new String('q'), new String('q'), y, new String('q'), y, y, y, y, new String('q')]) { for (var v of b0) { v2 = evalcx(\"eval\", o2.g2); } }; yield y; }), x, x(x) = window(), y, NaN = (4277), x = this.__defineSetter__(\"e\", Date.prototype.setHours), bywzss, z = -20;((makeFinalizeObserver('tenured')));\nb2 = new ArrayBuffer(152);\n");
/*fuzzSeed-8783892*/count=1048; tryItOut("for (var v of m2) { try { v0 = undefined; } catch(e0) { } try { h2 = ({getOwnPropertyDescriptor: function(name) { a0 = a0.concat(t2, m2, e0, /\\B*?|(?![^]){0}/gm, o0.m2, f2);; var desc = Object.getOwnPropertyDescriptor(f0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v0 = this.a2.length;; var desc = Object.getPropertyDescriptor(f0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw m2; Object.defineProperty(f0, name, desc); }, getOwnPropertyNames: function() { this.a2.pop();; return Object.getOwnPropertyNames(f0); }, delete: function(name) { return a2; return delete f0[name]; }, fix: function() { m1 = new WeakMap;; if (Object.isFrozen(f0)) { return Object.getOwnProperties(f0); } }, has: function(name) { this.v0 = a2.length;; return name in f0; }, hasOwn: function(name) { v1 = new Number(b1);; return Object.prototype.hasOwnProperty.call(f0, name); }, get: function(receiver, name) { /*MXX1*/o0 = g1.Object.length;; return f0[name]; }, set: function(receiver, name, val) { g2.a0.pop();; f0[name] = val; return true; }, iterate: function() { i1 + '';; return (function() { for (var name in f0) { yield name; } })(); }, enumerate: function() { return m1; var result = []; for (var name in f0) { result.push(name); }; return result; }, keys: function() { this.a1.unshift(s2, g2.v1, b0, t2, g2);; return Object.keys(f0); } }); } catch(e1) { } try { print(uneval(e1)); } catch(e2) { } var o1 = Object.create(p0); }");
/*fuzzSeed-8783892*/count=1049; tryItOut("(let (c = (4277)) );");
/*fuzzSeed-8783892*/count=1050; tryItOut("\"use strict\"; \"use asm\"; a1.__proto__ = m0;");
/*fuzzSeed-8783892*/count=1051; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ ( ! ( + Math.round(Math.log10(( ! (Math.round((y | 0)) | 0))))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0x080000000, -(2**53-2), 0x100000001, 1.7976931348623157e308, -(2**53+2), 0x0ffffffff, 1, -0x0ffffffff, -1/0, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), -0, 0/0, 0x100000000, -0x07fffffff, Math.PI, Number.MAX_VALUE, 2**53+2, 0, 0x080000001, 2**53-2, -0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, Number.MIN_VALUE, 1/0, 42, 0.000000000000001]); ");
/*fuzzSeed-8783892*/count=1052; tryItOut("/*RXUB*/var r = /(?!([^])\\B?[^]*?|(?:(?!([^]){2}))+)\\B/; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-8783892*/count=1053; tryItOut("mathy0 = (function(x, y) { return Math.atan2(Math.log1p(((( - (Math.fround(Math.pow(y, Math.fround(0.000000000000001))) | y)) | 0) | 0)), ( + (( + (((( + (Math.atan(Math.fround(Math.atan(Math.fround((Math.ceil(0x100000001) | 0))))) | 0)) | 0) | 0) << (y % (Math.atan2((((y | 0) === (-0x080000001 | 0)) | 0), (x | 0)) | 0)))) == ( + (Math.clz32(x) >> Math.log2(( - (-0x080000001 & x)))))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0/0, 2**53, -Number.MAX_VALUE, -(2**53-2), 0x100000000, -0x080000000, 42, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, 2**53+2, 0x07fffffff, -0x100000000, 0, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, 1, -0x100000001, -0, -0x0ffffffff, -0x080000001, Number.MIN_VALUE]); ");
/*fuzzSeed-8783892*/count=1054; tryItOut("mathy1 = (function(x, y) { return mathy0((( + ((Math.log10((y | 0)) , ( + ( ! (Number.MAX_VALUE >>> 0)))) >>> 0)) >>> 0), Math.max(Math.fround(((Math.clz32(( - ( + Math.min(2**53+2, y)))) | 0) && y)), ( + (( ~ (Math.min(( + Math.atan(( + -(2**53+2)))), (( - ((mathy0((x | 0), (Math.atan2(y, x) >>> 0)) | 0) >>> 0)) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy1, [-0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, Number.MAX_VALUE, 0.000000000000001, -0x100000001, 0x100000000, -(2**53-2), Math.PI, -Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, -(2**53+2), Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0/0, 1, 42, 2**53, 2**53-2, -0x100000000, -0x080000000, 0x100000001, 0x080000001, 0x07fffffff, -0x0ffffffff, 0, -(2**53)]); ");
/*fuzzSeed-8783892*/count=1055; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + (( + Math.min((( + (x >>> 0)) >>> 0), (((( + Math.imul(y, ( + x))) ? ( ~ y) : (x * 0x07fffffff)) || (((2**53-2 >>> 0) ? (( + ((y >>> 0) ^ (y | 0))) >>> 0) : (y >>> 0)) >>> 0)) >>> 0))) | Math.fround((((((( + ( + Math.max(( + 1.7976931348623157e308), ( + ( + (-0x0ffffffff * y)))))) === Math.sin(y)) >>> 0) && x) >>> 0) && (Math.fround(Math.hypot(Number.MIN_VALUE, ( + Math.round(( + x))))) >>> 0))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, -Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, 1, -(2**53+2), 0x100000001, 0x080000000, -1/0, -0x0ffffffff, -(2**53-2), -0, -0x07fffffff, -0x080000001, -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, 0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, 42, 2**53+2, -0x080000000, Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, 0]); ");
/*fuzzSeed-8783892*/count=1056; tryItOut("v0 = a0.length;");
/*fuzzSeed-8783892*/count=1057; tryItOut("v1 = new Number(-Infinity);\n/*ADP-3*/Object.defineProperty(a2, 7, { configurable: false, enumerable: true, writable: false, value: e2 });\ng1.i1.next();\n\n");
/*fuzzSeed-8783892*/count=1058; tryItOut("for (var v of v1) { try { Array.prototype.splice.apply(a0, [NaN, 8]); } catch(e0) { } try { o1.i1.__proto__ = a1; } catch(e1) { } try { e1.has(this.o1); } catch(e2) { } i0.next(); }");
/*fuzzSeed-8783892*/count=1059; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (( + ( + mathy1(Math.atan2(mathy0(y, x), ( + Math.log2(( ! y)))), (Math.asinh(((( + (( + ((x === y) | 0)) ? ( + x) : ( + y))) > 0x080000000) >>> 0)) >>> 0)))) ? ( + (Math.expm1((Math.imul(( + x), Math.atan2(Math.fround(Math.atan2(Math.imul(y, y), ((y >>> 0) || (Math.pow(0x080000000, (x >>> 0)) >>> 0)))), (( ! ((mathy0((-0x080000000 >>> 0), x) >>> 0) | 0)) | 0))) | 0)) | 0)) : ( + ((Math.sin(Math.sin(Math.fround(Math.atan2(x, ( + ( - ( + ( + Math.cos(x))))))))) | 0) || (Math.log1p(y) | 0))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -0, 0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, -0x100000001, -(2**53+2), -(2**53), -0x100000000, 1, Math.PI, -1/0, -(2**53-2), -0x0ffffffff, 0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, 0/0, 1/0, 2**53, -Number.MAX_VALUE, 0, 0x0ffffffff, 2**53+2, -0x07fffffff, -0x080000001, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001]); ");
/*fuzzSeed-8783892*/count=1060; tryItOut("/*vLoop*/for (zctebc = 0; zctebc < 32; ++zctebc) { var e = zctebc; v0 = evaluate(\"\\\"\\\\u91CF\\\"\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: (4277) })); } ");
/*fuzzSeed-8783892*/count=1061; tryItOut("v2 = new Number(s2);");
/*fuzzSeed-8783892*/count=1062; tryItOut("\"use strict\"; g0 + '';Array.prototype.reverse.call(a2);");
/*fuzzSeed-8783892*/count=1063; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\3)\", \"yim\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-8783892*/count=1064; tryItOut("/*RXUB*/var r = /\\u7Dfc[^]|(?=\\S|$?|[^]*?)*?+?|(?!\\3){2}/yi; var s = [z1,,]; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-8783892*/count=1065; tryItOut("v0 = (m2 instanceof i2);");
/*fuzzSeed-8783892*/count=1066; tryItOut("if(true) {/*oLoop*/for (let sksgrf = 0; sksgrf < 46; ++sksgrf) { (window); } const gjmesg, vzmuvn, window, xjajty, ufjxdv, eval;s0 + o1.a2; }o0.s2 = a1.join(s0, t2);");
/*fuzzSeed-8783892*/count=1067; tryItOut("\"use strict\"; v0.toString = (function mcc_() { var ufbbes = 0; return function() { ++ufbbes; if (false) { dumpln('hit!'); try { m2.set(e0, this.m1); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(g0.b2, i2); } catch(e1) { } try { g2.toSource = (function() { try { m0.set(g1, b0); } catch(e0) { } try { a1 = Array.prototype.map.apply(a2, [(function mcc_() { var vibyuq = 0; return function() { ++vibyuq; if (/*ICCD*/vibyuq % 2 == 1) { dumpln('hit!'); try { s2 = o1.a2.join(s1, f2); } catch(e0) { } try { this.o0.v2 = Object.prototype.isPrototypeOf.call(f0, o1.g0); } catch(e1) { } this.o0.m1.has(h0); } else { dumpln('miss!'); try { t1.set(o1.a1, 4); } catch(e0) { } try { for (var p in e2) { s0 += s2; } } catch(e1) { } print(o2.g1); } };})()]); } catch(e1) { } try { Array.prototype.reverse.apply(a1, []); } catch(e2) { } g0.v2 = t2.length; return e2; }); } catch(e2) { } f2 + b2; } else { dumpln('miss!'); try { o1 = i0.__proto__; } catch(e0) { } try { Array.prototype.reverse.apply(a0, []); } catch(e1) { } Object.defineProperty(this, \"v2\", { configurable: false, enumerable: (x % 4 != 1),  get: function() {  return evalcx(\"/* no regression tests found */\", this.g0); } }); } };})();");
/*fuzzSeed-8783892*/count=1068; tryItOut("print(x);i2 = s0;");
/*fuzzSeed-8783892*/count=1069; tryItOut("v0 + m1;");
/*fuzzSeed-8783892*/count=1070; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.log((Math.fround(mathy0(( + Math.ceil(( + (Math.atan2((( - Math.pow(y, y)) | 0), ((mathy1((0x080000001 >>> 0), (((-0x100000001 | 0) % 0x0ffffffff) | 0)) | 0) >>> 0)) >>> 0)))), Math.clz32((Math.min(x, (Math.fround((2**53+2 , Math.imul(y, x))) >>> 0)) >>> 0)))) >> Math.imul(( + (((Math.fround(y) ? x : (x ^ y)) | 0) ? (Math.pow((y >>> 0), (((y | 0) % ((Math.pow((x | 0), Math.fround(-Number.MIN_SAFE_INTEGER)) | 0) | 0)) | 0)) | 0) : (x | 0))), ((Math.fround(Math.atan2(Math.fround(x), (y | 0))) !== 0x100000000) ^ -0x100000001)))); }); testMathyFunction(mathy2, [1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53, 0, -0x080000000, -(2**53-2), 0x100000000, -(2**53+2), -0x100000000, 2**53+2, 0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 42, 0x100000001, -Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, 0/0, Number.MIN_VALUE, -0, -0x07fffffff, -0x0ffffffff, -(2**53), -1/0, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1]); ");
/*fuzzSeed-8783892*/count=1071; tryItOut("Object.prototype.unwatch.call(h2, \"__count__\");\nselectforgc(o1);\n");
/*fuzzSeed-8783892*/count=1072; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.trunc((( ~ Math.fround((Math.fround(mathy3(((-Number.MIN_VALUE | 0) ? y : ( + Math.asin(( + x)))), ( + (( + Math.acosh(x)) | ( + Math.imul(y, ( + Math.fround(0x07fffffff)))))))) / Math.fround(y)))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new Boolean(false), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new Boolean(false), new RegExp(\"[^](?=([^])?)\", \"gyi\"), new RegExp(\"[^](?=([^])?)\", \"gyi\")]); ");
/*fuzzSeed-8783892*/count=1073; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 281474976710657.0;\n    (Float64ArrayView[2]) = ((d0));\n    (Int8ArrayView[2]) = (((imul((0x5db3fa20), (-0x123aec4))|0) < (abs((((Int32ArrayView[((z)+((-131073.0) < (-7.555786372591432e+22))) >> 2])) & (0xdb1a3*(0x4c80663f))))|0))-(0xf778b4));\n    {\n;    }\n    return +((d0));\n  }\n  return f; })(this, {ff: (window & \u3056)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, -Number.MAX_VALUE, 0x100000001, 1, 0x080000000, 0x100000000, 0/0, -0x100000000, -0x0ffffffff, 42, 0x07fffffff, -(2**53), 0, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, Math.PI, -Number.MIN_VALUE, -(2**53+2), -0x07fffffff, 2**53, Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-8783892*/count=1074; tryItOut("for (var p in o2.o1) { try { s0 += s0; } catch(e0) { } try { o0.t2[3] = t2; } catch(e1) { } r0 = /[^](?!\\1)/i; }");
/*fuzzSeed-8783892*/count=1075; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = (0xf8051bba);\n    }\n    {\n      {\n        return +((d0));\n      }\n    }\n    {\n      d0 = (d0);\n    }\n    {\n      return +(intern(x));\n    }\n    (Float32ArrayView[1]) = ((-2097153.0));\n    i1 = (/*FFI*/ff(((((0x6161ea79) % ((Math.imul(Math.pow(window, 0.889), x))))|0)), ((\"\\uC637\")), ((36893488147419103000.0)), ((6.189700196426902e+26)), ((imul((0xff0240c9), ((((0xffffffff))>>>((-0x8000000))) > (0xffffffff)))|0)), ((0x7fffffff)), (((-0xd995e*(0xa2d6f6)) & ((0xc3035194)*-0xfffff))), ((~~(+(0xb70daca8)))), ((-16385.0)), ((-131073.0)), ((-36028797018963970.0)), ((9.671406556917033e+24)), ((-4194304.0)), ((-1125899906842625.0)), ((7.555786372591432e+22)), ((1.0078125)))|0);\n    (Float64ArrayView[((0xfba306de)) >> 3]) = ((-9007199254740992.0));\n    (Float32ArrayView[2]) = ((35184372088833.0));\n    return +((-4398046511105.0));\n  }\n  return f; })(this, {ff: (function(x, y) { return y; })}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53-2), 0x080000001, -0x100000001, -0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 1, 2**53-2, 0x07fffffff, 1/0, 42, -0x0ffffffff, Math.PI, 1.7976931348623157e308, -0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0, 0x100000001, 0/0, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, -(2**53), 0x100000000, -Number.MAX_VALUE, -0x080000000, 0x080000000, -0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-8783892*/count=1076; tryItOut("eval = w;");
/*fuzzSeed-8783892*/count=1077; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((((( + Math.fround(Math.abs(Math.fround(2**53-2)))) ? ((y | 0) !== (( ! ( + (((y | 0) == (y | 0)) | 0))) !== Math.fround(y))) : x) , Math.max(( + Math.acos(Math.asinh(Math.fround(mathy0(x, (x | 0)))))), ( + ( - ( + (( + x) << ( + x))))))) >>> 0) / (((Math.imul(((( ! ((((Math.sqrt((x | Math.fround(y))) >>> 0) != (mathy0(x, ((Math.fround(y) , y) >>> 0)) >>> 0)) >>> 0) | 0)) | 0) | 0), (((((y | 0) * (Math.expm1(y) | 0)) | 0) << Math.fround(Math.min(Math.fround(0x07fffffff), Math.fround(x)))) | 0)) | 0) << ( + ( + ( ~ ( + ( + (Math.fround((mathy0((2**53+2 | 0), (-1/0 | 0)) | 0)) % x))))))) | 0)); }); testMathyFunction(mathy1, /*MARR*/[arguments.caller, (0/0), (0/0), null, arguments.caller, null, (0/0), function(){}, (0/0), null, null, (0/0), arguments.caller, function(){}, null, null, arguments.caller, arguments.caller, null, function(){}, function(){}, (0/0), function(){}, function(){}, null, function(){}, (0/0), arguments.caller, null, (0/0), null, null, null, null, arguments.caller, function(){}, null, arguments.caller, function(){}, function(){}, function(){}, function(){}, arguments.caller, function(){}, function(){}, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), function(){}, null, function(){}, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, null, null, null, arguments.caller, arguments.caller, null, (0/0), function(){}, arguments.caller, (0/0), arguments.caller, function(){}, arguments.caller, arguments.caller, (0/0), (0/0), arguments.caller, function(){}, arguments.caller, arguments.caller, null, arguments.caller, arguments.caller, (0/0), null, (0/0), arguments.caller, null, function(){}, null, null, function(){}, null, arguments.caller, function(){}, null, arguments.caller, arguments.caller, null, null, (0/0)]); ");
/*fuzzSeed-8783892*/count=1078; tryItOut("\"use strict\"; /*RXUB*/var r = /[^]/gim; var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-8783892*/count=1079; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?![\\\\\\u7f9b\\u0d59-\\udff1T-\\\\\\u00cc]))|(?:\\\\cE)\", \"gy\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-8783892*/count=1080; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((Math.fround((((Math.max((42 ^ Math.fround(Math.abs(Math.pow(y, -0x080000001)))), ( + (Math.cosh((x | 0)) | 0))) >>> 0) & ( + Math.hypot(( + ( + (( + Math.sign(( + y))) ? (-Number.MAX_SAFE_INTEGER | 0) : ( + x)))), Math.trunc(Math.pow(y, Math.sin(-0x080000001)))))) | 0)) ? ((Math.fround(Math.cos(( + Math.min(0x080000001, ( + (( + x) % ( + (( ! y) >>> 0)))))))) | Math.sign(( ~ Math.fround((y - Math.fround(((x >>> 0) >= ( + 0.000000000000001)))))))) >>> 0) : ( + Math.fround(( - ( + Math.atan2(Math.max(((( ~ y) | 0) / (Math.exp(( + 2**53)) >>> 0)), (((Math.min(0x100000000, y) >>> 0) | (y >>> 0)) >>> 0)), x))))))); }); testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), 0.1, /0/, ({valueOf:function(){return '0';}}), '0', (new Number(-0)), [], [0], (new Boolean(false)), 1, '\\0', ({toString:function(){return '0';}}), 0, '/0/', null, undefined, (new String('')), '', (new Number(0)), true, NaN, -0, (new Boolean(true)), (function(){return 0;}), objectEmulatingUndefined(), false]); ");
/*fuzzSeed-8783892*/count=1081; tryItOut("m0.get(m2);");
/*fuzzSeed-8783892*/count=1082; tryItOut("v1 = r0.sticky;");
/*fuzzSeed-8783892*/count=1083; tryItOut("/*oLoop*/for (let koiglr = 0; koiglr < 20; ++koiglr) { a0.splice(NaN, ({valueOf: function() { this.v2 = 4;return 19; }}), g1.g1, m2); } ");
/*fuzzSeed-8783892*/count=1084; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -288230376151711740.0;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    var i6 = 0;\n    i5 = (0x6e90a205);\n    i3 = (i4);\n    return ((-(0xcfec415f)))|0;\n  }\n  return f; })(this, {ff: (x) =  /x/ }, new ArrayBuffer(4096)); ");
/*fuzzSeed-8783892*/count=1085; tryItOut("testMathyFunction(mathy2, [false, 1, undefined, [], objectEmulatingUndefined(), '', (new Boolean(true)), '0', 0.1, true, NaN, ({valueOf:function(){return 0;}}), (new Number(-0)), ({valueOf:function(){return '0';}}), [0], (new Boolean(false)), (new Number(0)), ({toString:function(){return '0';}}), null, -0, (function(){return 0;}), 0, /0/, '\\0', '/0/', (new String(''))]); ");
/*fuzzSeed-8783892*/count=1086; tryItOut("Array.prototype.splice.apply(a1, [-8, 8, p1]);");
/*fuzzSeed-8783892*/count=1087; tryItOut("mathy3 = (function(x, y) { return (Math.fround(Math.asinh(( + (( + Math.imul(Math.fround(Math.cos((y >>> 0))), x)) >>> ( + (((( - y) | 0) + y) | 0)))))) * (Math.max(( + Math.log10(Math.ceil(((-1/0 !== x) | 0)))), ( + Math.imul(( + ((Math.max(Math.max(x, (Math.hypot((y >>> 0), (x | 0)) >>> 0)), -Number.MAX_VALUE) <= Math.acosh(Math.log1p(y))) | 0)), ( + (( + ( + x)) ? (mathy1((( ~ Math.sign(x)) | 0), ( + (y != x))) | 0) : Math.fround(Math.tanh(-1/0))))))) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (/*FARR*/[, \"\\uC0A1\"]), objectEmulatingUndefined(), objectEmulatingUndefined(), (/*FARR*/[, \"\\uC0A1\"]), objectEmulatingUndefined(), (/*FARR*/[, \"\\uC0A1\"]), objectEmulatingUndefined()]); ");
/*fuzzSeed-8783892*/count=1088; tryItOut("m2.set(this.e2, g1);");
/*fuzzSeed-8783892*/count=1089; tryItOut("Array.prototype.unshift.apply(a0, [o0, v0, this.g0.g0.b2]);");
/*fuzzSeed-8783892*/count=1090; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.imul((Math.hypot((mathy4((y | 0), (Math.clz32(((Math.asin(( + x)) | 0) | 0)) | 0)) >>> 0), ( + Math.max(( + Math.fround(Math.atanh(Math.fround(Math.atan2(x, x))))), ( + ( + Math.atan2(( + -0), ( + x))))))) | 0), Math.min(Math.exp(Math.fround(((( + 1/0) ? ( + x) : x) >>> 0))), mathy0((Math.max((0 | 0), (Math.min(-Number.MIN_SAFE_INTEGER, Math.PI) | 0)) | 0), (Math.pow((Math.acos((y | 0)) | 0), Math.imul(Math.cbrt((x === x)), x)) | 0)))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 0x100000001, -0x07fffffff, 0x07fffffff, 0x080000001, 0x080000000, Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, 42, -0x080000001, -1/0, -0x100000000, 1/0, Math.PI, Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001, -0x080000000, -0, 0x0ffffffff, -(2**53+2), 0, 0/0, 2**53-2, -(2**53-2), -Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-8783892*/count=1091; tryItOut("\"use strict\"; /*RXUB*/var r = /[\\S\\S\u0010-\\cQ]/ym; var s = \"0\"; print(s.search(r)); ");
/*fuzzSeed-8783892*/count=1092; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - (Math.cosh((y | 0)) / Math.hypot((Math.max(( + Math.hypot(( + Math.log2(Math.fround(1/0))), Math.max(Math.fround(((x >>> 0) ? y : 2**53-2)), y))), Math.fround(Math.fround((Math.fround(Math.max(-(2**53-2), x)) || 1)))) | 0), (x ? x : Math.clz32(x))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -(2**53-2), -0, 1/0, 2**53-2, 0x07fffffff, 0, -0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, -0x100000000, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, -0x100000001, Math.PI, -1/0, -Number.MAX_VALUE, -(2**53), 0x080000001, 2**53+2, -(2**53+2), 1, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, -0x080000000, 42, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-8783892*/count=1093; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-8783892*/count=1094; tryItOut("v0 = g2.eval(\"(Math.hypot(x, 0)) %= /*UUV1*/(x.round = q => q) instanceof (runOffThreadScript)([,,], new RegExp(\\\"\\\\\\\\3\\\", \\\"ym\\\"))\");");
/*fuzzSeed-8783892*/count=1095; tryItOut("g0 = t0[(4277)];");
/*fuzzSeed-8783892*/count=1096; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(i0, f0);");
/*fuzzSeed-8783892*/count=1097; tryItOut(";");
/*fuzzSeed-8783892*/count=1098; tryItOut("v0 = this.t2.length;");
/*fuzzSeed-8783892*/count=1099; tryItOut("\"use strict\"; v2 = (e1 instanceof i1);");
/*fuzzSeed-8783892*/count=1100; tryItOut("mathy2 = (function(x, y) { return ((Math.fround((((Math.log2(Math.fround(x)) | 0) ? (Math.fround(( + Math.tanh(((( ~ (y ? y : x)) > (Math.hypot(x, ( + x)) >>> 0)) >>> 0)))) | 0) : ((Math.fround(( + ( ! y))) ? (( ! ( + Math.exp(x))) >>> 0) : Math.fround(x)) | 0)) | 0)) == ((( - Math.cbrt(0x080000000)) === (( + x) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[arguments.callee, new Number(1), 2, new String(''), new String(''), new Number(1), eval, arguments.callee, 2, 2, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, arguments.callee, 2, eval, 2, 2, arguments.callee, 2, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, new Number(1), eval, new Number(1), new Number(1), new String(''), new Number(1), eval, 2, new String(''), new String(''), new String(''), 2, new String(''), arguments.callee, eval, eval, arguments.callee, new Number(1), arguments.callee, new String(''), 2, arguments.callee, arguments.callee, arguments.callee, arguments.callee, 2, new Number(1), 2, new Number(1), arguments.callee, eval, new String(''), 2, new String(''), 2, 2, new Number(1), 2, new Number(1), eval, 2, 2, eval, eval, eval, new String(''), new String(''), eval, arguments.callee, 2, 2, arguments.callee, arguments.callee, arguments.callee, new String(''), eval, eval, arguments.callee, new Number(1), 2, arguments.callee, new String(''), eval, new String(''), 2, new Number(1), 2, eval, eval, 2, new String(''), new Number(1), new Number(1), new String('')]); ");
/*fuzzSeed-8783892*/count=1101; tryItOut("\"use strict\"; /*MXX2*/g2.Int32Array.prototype = g1.v0;");
/*fuzzSeed-8783892*/count=1102; tryItOut("\"use strict\"; \"use asm\"; ");
/*fuzzSeed-8783892*/count=1103; tryItOut("L: {/* no regression tests found *//*MXX3*/g0.Number.prototype.toExponential = g0.Number.prototype.toExponential; }");
/*fuzzSeed-8783892*/count=1104; tryItOut("print(x);");
/*fuzzSeed-8783892*/count=1153; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((Float64ArrayView[(((+(0x2fe397bf)))) >> 3]));\n  }\n  return f; })(this, {ff: function(y) { return \ny }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53+2), 0, -0x100000001, -0x07fffffff, 42, 0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53, 0x080000000, 0/0, -(2**53-2), 0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 1/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, 1.7976931348623157e308, 0x07fffffff, 0x100000001, -(2**53), 0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, -0, -0x100000000, -0x080000000]); ");
/*fuzzSeed-8783892*/count=1154; tryItOut("/*oLoop*/for (var aippyl = 0; aippyl < 7 && ((void options('strict_mode'))); ++aippyl) { /*RXUB*/var r = new RegExp(\"(?!((?!(?=$))\\\\d+?)+?|\\\\W\\\\2[S-\\ucde7\\\\s\\\\cB].\\\\B?*?)\", \"ym\"); var s = \"\"; print(s.match(r)); print(r.lastIndex);  } ");
/*fuzzSeed-8783892*/count=1155; tryItOut("\"use strict\"; t1 = this.t2.subarray(/\\S/gym);");
/*fuzzSeed-8783892*/count=1156; tryItOut("m0.has(f0);\ne0.has(o0.o0);\n");
/*fuzzSeed-8783892*/count=1157; tryItOut("testMathyFunction(mathy4, [0x07fffffff, Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, -0x080000001, 1/0, -(2**53), 2**53-2, -0x100000000, -0, 2**53, -(2**53+2), -Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 1, 0.000000000000001, 0, -Number.MIN_VALUE, 2**53+2, -0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-8783892*/count=1158; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return (((Math.fround(( ! Math.hypot(Math.log1p(Math.fround(Math.tan(( + Math.imul(( + Number.MAX_VALUE), ( + y)))))), Math.hypot(x, Math.fround(Math.exp(Math.fround(y))))))) | 0) | (Math.pow(( ~ (( + x) | 0)), ( ~ (y > Math.max(x, 0x080000000)))) | 0)) | 0); }); testMathyFunction(mathy4, [2**53, 0.000000000000001, 42, -0x100000001, -0, 0x100000001, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x080000000, -Number.MAX_VALUE, -(2**53-2), -0x080000001, 1/0, 0x0ffffffff, 0x07fffffff, 0, 1, Math.PI, -(2**53+2), 0x100000000, 1.7976931348623157e308, -(2**53), -1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, -0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-8783892*/count=1159; tryItOut("const e = Promise();print(x);");
/*fuzzSeed-8783892*/count=1160; tryItOut(";");
/*fuzzSeed-8783892*/count=1161; tryItOut("h2.enumerate = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((+((8796093022209.0))));\n  }\n  return f; })(this, {ff: [((4277))()]}, new ArrayBuffer(4096));");
/*fuzzSeed-8783892*/count=1162; tryItOut("{h1 + g2;/*infloop*/L: for  each(var (y) in x) v2 = (v0 instanceof h2); }");
/*fuzzSeed-8783892*/count=1163; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-8783892*/count=1164; tryItOut("mathy4 = (function(x, y) { return Math.atan2((((((Math.log10((x > y)) | 0) | 0) / (( + (Math.fround(Math.atan2(( + x), Math.fround(0))) % Math.log2(Math.fround(( - Math.fround(y)))))) >>> 0)) > (( - Math.fround((mathy1((y >>> 0), (x | 0)) >>> 0))) >>> 0)) | 0), (mathy1((Math.max((-1/0 >>> 0), (Math.ceil(y) >>> 0)) >>> 0), Math.atan(Math.sqrt((Math.atan2(( + ( - y)), y) | 0)))) | 0)); }); ");
/*fuzzSeed-8783892*/count=1169; tryItOut("with((void options('strict_mode')))print(x);");
/*fuzzSeed-8783892*/count=1170; tryItOut("while(((4277)) && 0)do v2 = (g1 instanceof m1); while((x) && 0);");
/*fuzzSeed-8783892*/count=1171; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(o0.e1, \"concat\", ({value: (/*FARR*/[].filter(encodeURI)) <<= null, writable: true}));");
/*fuzzSeed-8783892*/count=1172; tryItOut("/* no regression tests found */");
/*fuzzSeed-8783892*/count=1173; tryItOut("v2 = new Number(-0);");
/*fuzzSeed-8783892*/count=1174; tryItOut("x.name;function \u3056(NaN) { yield Math.sin((Math.log(( + ( ~ ( + ( + ( ~ ( + -Number.MAX_VALUE))))))) >>> 0)) } f1 + o1.f1;");
/*fuzzSeed-8783892*/count=1175; tryItOut("e2.toSource = (function() { a1.unshift(o2, o0.e0, g0, e2); return v0; });");
/*fuzzSeed-8783892*/count=1176; tryItOut("\"use strict\"; print(a1);");
/*fuzzSeed-8783892*/count=1177; tryItOut("/*tLoop*/for (let x of /*MARR*/[]) { for (var v of o1.g0.g1) { v2 = evalcx(\"s1 + '';\", this.g2.g0); } }");
/*fuzzSeed-8783892*/count=1178; tryItOut("\"use strict\"; { void 0; try { startgc(1); } catch(e) { } } /*iii*/print(zdmskf);/*hhh*/function zdmskf(e, b){(\"\\uF3B6\".valueOf(\"number\")) , (4277);}");
/*fuzzSeed-8783892*/count=1179; tryItOut("\"use strict\"; this.zzz.zzz;");
/*fuzzSeed-8783892*/count=1180; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return (Math.acos(( + ((( + Math.atan2(y, (42 <= x))) >>> 0) << (mathy1(((Math.log10(-(2**53-2)) - (( - mathy0((y >>> 0), x)) | 0)) >>> 0), ((Math.sign(( ~ x)) >>> 0) >>> 0)) >>> 0)))) >>> 0); }); testMathyFunction(mathy2, [-0x080000000, 2**53, 2**53+2, 1, -(2**53+2), -0, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, Math.PI, 42, -Number.MIN_VALUE, 0/0, 0, -(2**53), -0x07fffffff, 1/0, -(2**53-2), 0.000000000000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 0x080000000, 0x100000001]); ");
/*fuzzSeed-8783892*/count=1181; tryItOut("\n( \"\" );\n");
/*fuzzSeed-8783892*/count=1182; tryItOut("mathy3 = (function(x, y) { return ( + Math.atan2(Math.pow((( - (Math.hypot(Math.hypot(Math.atan((x | 0)), 0x100000000), Math.pow(Math.fround(Math.max(x, x)), y)) | 0)) | 0), Math.atan2(( ~ Math.expm1(( + 2**53))), Math.fround(Math.sign(Math.acos(mathy1(2**53+2, Math.fround(2**53+2))))))), Math.fround(Math.cbrt(((Math.tanh(Math.atanh((mathy0((y >>> 2**53-2), Math.fround(( ~ (x && y)))) >>> 0))) | 0) | 0))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, -(2**53+2), -0, 0/0, -1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 42, -Number.MAX_VALUE, -0x07fffffff, 2**53+2, -(2**53-2), -(2**53), 0x080000000, 0x080000001, -Number.MIN_VALUE, 2**53-2, -0x080000000, 0x0ffffffff, 0x100000000, -0x080000001, 1, 0x07fffffff, Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-8783892*/count=1183; tryItOut("m1.has(g1);");
/*fuzzSeed-8783892*/count=1184; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 72057594037927940.0;\n    var d4 = -1.9342813113834067e+25;\n    var d5 = -6.044629098073146e+23;\n    switch ((imul(((0x7e606ae6) < (0x812da703)), (0x31ead52c))|0)) {\n      default:\n        {\n          i1 = ((((((/*FFI*/ff()|0))>>>((i1)+(i1)+(0xd81b403d))) % (((((0x4efbc2d7))>>>((0xffffffff))) / (0xebf61f62))>>>((i2)+((0xe692cd2c)))))|0));\n        }\n    }\n    return (((i1)+(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.getYear}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[false, x, false, x, x, x, x, x, x, x, false, false, new String('q'), new String('q'), false, false, false, x, x, x, x, new String('q'), x, x, false, false, x, new String('q'), new String('q'), x, new String('q'), new String('q'), x, new String('q'), x, x, false, false, x]); ");
/*fuzzSeed-8783892*/count=1185; tryItOut("mathy3 = (function(x, y) { return (Math.max((( + (( + ( + Math.expm1(y))) < ( - (mathy2(((-0x100000001 | Number.MAX_SAFE_INTEGER) >>> 0), (Math.sin(x) >>> 0)) >>> 0)))) >>> 0), (Math.sqrt((((Math.asinh(Math.fround(( + ((y !== 2**53-2) >>> 0)))) | 0) === Math.PI) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x100000001, 1.7976931348623157e308, -0x080000000, 2**53+2, 0x080000000, -0x100000000, -(2**53), -0x07fffffff, 1/0, -Number.MAX_VALUE, Number.MAX_VALUE, -0, 0x100000000, -0x0ffffffff, -1/0, 0, -(2**53+2), Math.PI, 2**53-2, -(2**53-2), 0/0, 0.000000000000001, -Number.MIN_VALUE, -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 2**53, 42, 0x07fffffff, 0x0ffffffff, -0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-8783892*/count=1186; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var abs = stdlib.Math.abs;\n  var acos = stdlib.Math.acos;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (((((0x75dee2fe) % (((0xe256daed)-(0x1a159c9e)-(0x18bac9d3))>>>(((0x3e685227))))) | ((i1)-((+ceil(((((67108865.0)) % ((-1.9342813113834067e+25)))))) != (-5.0))))) ? ((+abs(((+(1.0/0.0))))) == (3.777893186295716e+22)) : (i0));\n    i1 = ((((i0)-((2199023255553.0) <= (+((+acos(((Float32ArrayView[4096])))))))) | ((i0)+(i0))) != (~((i1)-(((((-0x8000000)) | ((0x86fe1271))) != (((0x4b00960)) | ((0x2b598e75)))) ? ((i0)) : (0x8fe23b9)))));\n    i0 = (0xac87ddf3);\n    return +((((+(1.0/0.0))) * ((Infinity))));\n  }\n  return f; })(this, {ff: Int32Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), 1, -1/0, -0, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, -0x080000000, -0x080000001, 42, 0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -0x100000001, 2**53+2, 0x080000001, 1/0, Math.PI, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 0x100000001, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-8783892*/count=1187; tryItOut("let(x, \u3056 = this, x = x.eval(\"print(h0);\"), x = Math.expm1(x = (({}) /= /\u0016\\b|.+|\\W+\\D+/gym))) { throw StopIteration;}");
/*fuzzSeed-8783892*/count=1188; tryItOut("{(this); }");
/*fuzzSeed-8783892*/count=1189; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((( + Math.min(x, 0.000000000000001)) | 0) ? (Math.sin(((mathy0(y, (( + x) | 0)) | 0) > Math.imul((Math.max((y >>> 0), (x >>> 0)) >>> 0), y))) | 0) : ( + ( - ( + (x * ( + (Math.hypot(Math.atan2(Math.asinh(Math.fround(-(2**53))), x), ( + ( - x))) >>> 0))))))) | 0); }); testMathyFunction(mathy1, [undefined, [], null, NaN, [0], (new Boolean(false)), true, '', (function(){return 0;}), '\\0', 0, (new Boolean(true)), /0/, '/0/', false, (new Number(-0)), 0.1, -0, '0', 1, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}}), (new String('')), objectEmulatingUndefined()]); ");
/*fuzzSeed-8783892*/count=1190; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + Math.atanh(( + (Math.fround(Math.cos(Math.fround(y))) + ( ! (mathy0((Math.fround(( + y)) >>> 0), ((y ? (( ~ (mathy0(Math.fround(y), y) >>> 0)) >>> 0) : (( + Math.asinh(( + x))) >>> 0)) >>> 0)) | 0)))))); }); testMathyFunction(mathy2, [0x100000000, 1.7976931348623157e308, -0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, -(2**53), -0x100000000, 42, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 0/0, 0x100000001, 2**53, Number.MAX_VALUE, Math.PI, -0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, 0x080000000, -0, -(2**53+2), 0, -0x080000000, 1, 0x0ffffffff, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-8783892*/count=1191; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ! (((Math.imul((Math.cbrt((Math.min((Math.fround(Math.atan2(y, x)) >>> 0), Math.fround((Math.fround(x) ? Math.fround(y) : ( + x)))) | 0)) | 0), Math.fround(( - Math.fround(x)))) >>> 0) ? (((x >>> (y * 42)) ? -1/0 : x) + ((( + (Math.fround(Math.log(y)) >>> 0)) >>> 0) | 0)) : ((( + Math.imul(y, ( + Math.sinh(Math.fround(y))))) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-0, -0x100000001, 0x080000001, 1.7976931348623157e308, -(2**53+2), 0x07fffffff, 1, -0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2, -0x080000001, -0x0ffffffff, Math.PI, -0x080000000, 2**53, 1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, -(2**53), 0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0, Number.MAX_VALUE, -1/0, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, 0x0ffffffff, 42]); ");
/*fuzzSeed-8783892*/count=1192; tryItOut("mathy3 = (function(x, y) { return Math.imul(((mathy0(mathy1(Math.fround(( ! Math.fround(2**53-2))), ( + y)), x) ^ Math.min(y, Math.pow(-Number.MAX_VALUE, (x & (x + -0x100000000))))) << (z / y)), (( - Math.fround(Math.fround(( - Math.fround(mathy1(Math.fround(Math.fround(((x | 0) << (y | 0)))), Math.fround(y))))))) >>> 0)); }); testMathyFunction(mathy3, [Math.PI, 0x07fffffff, 0, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 0x100000000, -0x100000001, -(2**53+2), -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 2**53-2, -0x080000000, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, 1, -(2**53), 2**53, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 1.7976931348623157e308, 0.000000000000001, 0/0, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-8783892*/count=1193; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ! ( + Math.fround(Math.fround(( + (Math.fround(Math.min(-0x080000000, x)) ? y : -0x07fffffff)))))); }); ");
/*fuzzSeed-8783892*/count=1194; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    {\n      d1 = (+/*FFI*/ff());\n    }\n    i3 = (i0);\n    {\n      i2 = (i3);\n    }\n    d1 = ((i0) ? (-1048577.0) : (+abs(((Float64ArrayView[((i2)-(!(0x32071ce9))) >> 3])))));\n    i2 = (i0);\n    (Float32ArrayView[(-((0xd14240a7) == (((i3))>>>((0x76f92d4d)-(-0x8000000))))) >> 2]) = ((Float64ArrayView[1]));\n    return (((i2)))|0;\n    {\n/* no regression tests found */    }\n    return (((i3)))|0;\n  }\n  return f; })(this, {ff: Object.is}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-8783892*/count=1195; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return (((Math.pow(((( ~ Math.log(( + x))) | 0) ** (( + (( + (Math.fround((Math.fround(y) >> 1)) === y)) >= (y | 0))) | Math.fround(( ! Math.fround(Math.expm1(y)))))), (y ? (Math.max((function shapeyConstructor(plumsp){\"use strict\"; if (plumsp) Object.preventExtensions(this);this[\"caller\"] = neuter;if (plumsp) this[\"caller\"] = -0x100000001;Object.defineProperty(this, new String(\"5\"), ({get: objectEmulatingUndefined}));this[\"caller\"] = offThreadCompileScript;if (plumsp) this[\"caller\"] = (y *= window);delete this[\"caller\"];this[\"0\"] = eval;for (var ytqdbdwjj in this) { }this[\"0\"] = new Number(1);return this; } | 0), (x | 0)) | 0) : Math.fround(( + ( + (((-0x100000001 >>> 0) ** Math.fround(-(2**53+2))) >>> 0)))))) | 0) ? (Math.hypot(((Math.tan(((Math.fround(Math.cosh(( + y))) * ((Math.expm1(y) >>> 0) ? x : (x >>> 0))) | 0)) | 0) >> y), Math.cos(y)) | 0) : (Math.log2(Math.fround(Math.ceil(Math.fround(( - Math.log(mathy0(( + x), ( ! x)))))))) | 0)) | 0); }); testMathyFunction(mathy2, [0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -(2**53+2), 0x080000000, Number.MIN_SAFE_INTEGER, 42, -0x100000001, 0x0ffffffff, 1, -0x0ffffffff, -(2**53), -(2**53-2), -0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, 0, 2**53+2, 0x100000000, -0, -Number.MAX_VALUE, -1/0, 0x100000001, 0x07fffffff, 2**53, Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, 1/0, 0/0]); ");
/*fuzzSeed-8783892*/count=1196; tryItOut("\"use strict\"; while((\n(eval(\"\\\"use strict\\\"; throw w;\"))) && 0)o1 + m0;");
/*fuzzSeed-8783892*/count=1197; tryItOut("p2.toSource = g1.f0;");
/*fuzzSeed-8783892*/count=1198; tryItOut("\"use strict\"; m2 + this.f0;");
/*fuzzSeed-8783892*/count=1199; tryItOut("Array.prototype.shift.call(a2);");
/*fuzzSeed-8783892*/count=1200; tryItOut("(-216730059);throw \"\\uD312\"");
/*fuzzSeed-8783892*/count=1201; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[[,,], [,,], 0x2D413CCC, [,,], 0x2D413CCC, [,,], [,,], 0x2D413CCC, [,,], 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, [,,], 0x2D413CCC, 0x2D413CCC, 0x2D413CCC]) { print(true); }");
/*fuzzSeed-8783892*/count=1202; tryItOut("selectforgc(o2);");
/*fuzzSeed-8783892*/count=1203; tryItOut("Object.prototype.unwatch.call(h1, \"toString\");");
/*fuzzSeed-8783892*/count=1204; tryItOut("\"use strict\"; const x, x, x = z, gpzpna, {} = x, ikqhxb, \u3056 = [x];selectforgc(o2);");
/*fuzzSeed-8783892*/count=1205; tryItOut("M:if(false) {for (var p in e1) { try { print(uneval(b0)); } catch(e0) { } try { v1 = evaluate(\"h0.fix = f2;\", ({ global: o1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 28 != 0), catchTermination: (x % 105 == 9) })); } catch(e1) { } try { o2.g1.a2.push(g2.i1, s2); } catch(e2) { } Object.seal(a1); } } else {g2.v1 = g0.g0.eval(\"/* no regression tests found */\"); }\nArray.prototype.unshift.call(a2, ({e: {}}) = x = undefined, this.s2);\n");
/*fuzzSeed-8783892*/count=1206; tryItOut("/*RXUB*/var r = /(?!(?=((?!(?=(?!.)){0})))(?=(\\2))|\\S[^\\cO\\x6D-\\\udc3f](?!.)+?|\\w+)/gym; var s =  /x/ ; print(uneval(s.match(r))); ");
/*fuzzSeed-8783892*/count=1207; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-8783892*/count=1208; tryItOut("\"use strict\"; neuter(o2.b2, \"change-data\");");
/*fuzzSeed-8783892*/count=1209; tryItOut("/*RXUB*/var r = /(?:(?![^])*)*?{1,2}/gyim; var s = false; print(r.test(s)); ");
/*fuzzSeed-8783892*/count=1210; tryItOut("");
/*fuzzSeed-8783892*/count=1211; tryItOut("a0 = (function() { yield (arguments.callee.caller.caller.arguments%=x = window.unwatch(\"wrappedJSObject\")); } })();");
/*fuzzSeed-8783892*/count=1212; tryItOut("f1(o0);");
/*fuzzSeed-8783892*/count=1213; tryItOut("testMathyFunction(mathy1, [-0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000000, -(2**53+2), -(2**53-2), 0x100000001, 2**53-2, 0, 2**53, Number.MAX_SAFE_INTEGER, -0, -(2**53), Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, 1/0, -Number.MAX_VALUE, -1/0, Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 42, -0x0ffffffff, 2**53+2, 0.000000000000001, -0x080000001, 1, 0x100000000, 1.7976931348623157e308, 0x07fffffff]); ");
/*fuzzSeed-8783892*/count=1214; tryItOut("testMathyFunction(mathy0, [-Number.MAX_VALUE, -1/0, 0x100000001, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0x080000000, 0.000000000000001, 0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, 0x080000001, 0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), -0x0ffffffff, 2**53-2, -0x07fffffff, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -0, 0/0, 2**53+2, 1, -0x100000001, -(2**53), 0x07fffffff]); ");
/*fuzzSeed-8783892*/count=1215; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((Math.sinh(Math.trunc(-Number.MAX_VALUE)) ? Math.asinh(Math.hypot(Math.fround(x), ( + Math.atan2(((x >>> 0) % ((mathy2(Math.fround(y), (y >>> 0)) >>> 0) >>> 0)), ( + x))))) : Math.fround(Math.atan2(( + Math.exp(Math.fround(Math.sign(Math.fround(x))))), (Math.exp(Math.fround(2**53-2)) | 0)))) | 0) ? ( + ( + (( + Math.pow((mathy2(mathy0(y, Number.MIN_SAFE_INTEGER), x) + Math.PI), ( ~ -0x100000000))) === ( + ( ~ Math.fround(((x === Math.fround(Math.exp(Number.MAX_VALUE))) >>> Math.fround(y)))))))) : (Math.fround((Math.fround((( + (((y * y) >= y) >>> 0)) | 0)) + Math.fround((Math.clz32(y) ** (Math.fround(Math.sinh(y)) | x))))) / ((Math.asinh(((((y >>> 0) % mathy3(1.7976931348623157e308, 0x080000000)) >>> 0) >>> 0)) >>> 0) != y))); }); ");
/*fuzzSeed-8783892*/count=1216; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-8783892*/count=1285; tryItOut("\"use strict\"; v0 = t2.length;");
/*fuzzSeed-8783892*/count=1286; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan(Math.max((Math.fround(Math.pow(Math.fround(x), Math.fround((Math.hypot(y, ((x ** y) >>> 0)) >= ( - 0x080000000))))) + Math.atanh(Math.fround((y > ( - ( + y)))))), Math.imul(Math.fround(((Math.imul(((y == y) >>> 0), Math.fround(x)) >>> 0) >>> (((x | 0) >> (Math.trunc(x) >>> 0)) + y))), Math.fround(Math.max(x, ( ~ (Math.fround((y >>> (y | 0))) ? y : y))))))); }); testMathyFunction(mathy0, [0x080000000, 1, -0x100000001, 1.7976931348623157e308, 0x100000000, -(2**53-2), -Number.MIN_VALUE, 0, 0x07fffffff, 0x100000001, 0.000000000000001, 2**53+2, -0, 42, -0x100000000, 1/0, 0/0, Number.MIN_VALUE, Math.PI, 0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, -(2**53+2), 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-8783892*/count=1287; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min((Math.imul(((Math.log1p((Math.fround(Math.hypot(Math.fround(1/0), (mathy1(Math.fround(2**53-2), mathy4((y | 0), (-(2**53) | 0))) | 0))) | 0)) | 0) | 0), (( ! 42) | 0)) | 0), Math.fround(Math.sinh((( ~ y) == ( + mathy4(Math.fround(Math.abs(y)), ( + Math.atan2(x, ( + y))))))))); }); testMathyFunction(mathy5, [0, 1.7976931348623157e308, -0x100000001, -0x080000000, 0x07fffffff, 2**53, 1/0, -Number.MAX_VALUE, 0.000000000000001, 0x100000001, -0x07fffffff, -(2**53), Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, -(2**53-2), -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, 0x0ffffffff, -0x100000000, 0x100000000, 2**53+2, 1, -(2**53+2), -0x0ffffffff, -0, 0/0, Math.PI, 0x080000001, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-8783892*/count=1288; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    /*FFI*/ff(((+pow(((+(1.0/0.0))), ((NaN))))), ((imul((0x7be4dc4f), (0x598c9503))|0)), (((((+(1.0/0.0)) != (d0))) >> (((Uint16ArrayView[1]))-(0xffffffff)))), ((+(0xe44d8223))), ((d0)));\n    d0 = (2199023255553.0);\n    {\n      i1 = (((((d0)) - ((Float64ArrayView[((0x67837939) / (0x25761be1)) >> 3]))) > (+(1.0/0.0))) ? (i1) : ((d0) != (5.0)));\n    }\n    d0 = (+(~(((d0) > (2305843009213694000.0)))));\n    d0 = (+(1.0/0.0));\n    {\n      i1 = (0x80ff5643);\n    }\n    {\n      i1 = (0x7753c36f);\n    }\n    i1 = (0xc43c87cf);\n    switch ((((0xffffffff)+(0x3ca1004c)+(0xfb5bdbb0)) >> (((-35184372088833.0) < (1.001953125))-(i1)))) {\n    }\n    (Uint8ArrayView[((x)) >> 0]) = ((0xffec955e));\n    return +((d0));\n  }\n  return f; })(this, {ff: function shapeyConstructor(myfiyk){this[\"getOwnPropertyDescriptor\"] = (makeFinalizeObserver('tenured'));for (var ytqdbvnfu in this) { }Object.seal(this);return this; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, -0x080000000, -1/0, -0x100000000, 1, -0x0ffffffff, -0x080000001, 0, -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0.000000000000001, -0x100000001, -Number.MAX_VALUE, -0, 1.7976931348623157e308, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 2**53-2, 42, 0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, -(2**53), -(2**53-2)]); ");
/*fuzzSeed-8783892*/count=1289; tryItOut("/*RXUB*/var r = new RegExp(\".(?:(?!8{3}|(?:.*?\\\\B{3,})))\", \"gyim\"); var s = \"m\"; print(s.split(r)); ");
/*fuzzSeed-8783892*/count=1290; tryItOut("i0.next();");
/*fuzzSeed-8783892*/count=1291; tryItOut("");
/*fuzzSeed-8783892*/count=1292; tryItOut("\"use strict\"; Object.prototype.watch.call(o0.b0, \"log\", o1.f1);");
/*fuzzSeed-8783892*/count=1293; tryItOut("/*vLoop*/for (let juhhkh = 0; juhhkh < 128; ++juhhkh) { a = juhhkh; a2 = o2.a2.concat(a0, t1, a0, a0, o2.g1.t0); } ");
/*fuzzSeed-8783892*/count=1294; tryItOut("\"use strict\"; v2 = (x % 4 != 1);");
/*fuzzSeed-8783892*/count=1295; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x07fffffff, -0x080000000, -0, 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, -0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 42, Math.PI, 0x0ffffffff, 2**53+2, 1, -(2**53-2), Number.MIN_VALUE, -(2**53+2), 0x07fffffff, 0x100000001, 2**53-2, -0x100000001, 0x100000000, 1.7976931348623157e308, 0x080000000, 0x080000001, -Number.MAX_VALUE, 1/0, -1/0, -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-8783892*/count=1296; tryItOut("\"use strict\"; for (var p in v2) { try { Object.prototype.watch.call(g0.b2, \"valueOf\", (function mcc_() { var wnexge = 0; return function() { ++wnexge; if (/*ICCD*/wnexge % 10 != 8) { dumpln('hit!'); try { this.g2.__iterator__ = [] = yield ({a2:z2}); } catch(e0) { } /*MXX3*/g1.g2.Array.prototype.splice = this.o1.g0.g2.Array.prototype.splice; } else { dumpln('miss!'); try { g0.offThreadCompileScript(\"h0.getPropertyDescriptor = f1;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (q => q)(false), noScriptRval: true, sourceIsLazy: true, catchTermination: let (x) [,,] })); } catch(e0) { } try { (void schedulegc(g0)); } catch(e1) { } t1.set(a1, v2); } };})()); } catch(e0) { } try { m0.get(b0); } catch(e1) { } this.g2.t2.toSource = offThreadCompileScript; }");
/*fuzzSeed-8783892*/count=1297; tryItOut("\"use strict\"; a0.pop(e0, g0);");
/*fuzzSeed-8783892*/count=1298; tryItOut("\"use strict\"; s2.__iterator__ = f2;");
/*fuzzSeed-8783892*/count=1299; tryItOut("\"use strict\"; a1.forEach(this.f2);");
/*fuzzSeed-8783892*/count=1300; tryItOut("\"use strict\"; L:with( /x/g ){return;e2.add(f2); }function z(x)(void version(185))this.a2 = a0[9];");
/*fuzzSeed-8783892*/count=1301; tryItOut("\"use strict\"; v1 = (s0 instanceof f2);");
/*fuzzSeed-8783892*/count=1302; tryItOut("mathy2 = (function(x, y) { return ( + mathy0(Math.fround(( ~ ( ~ Math.fround(Math.fround(( ! Math.fround(Math.atan2(( + y), ( + ( + ( + y))))))))))), Math.fround(Math.imul((Math.hypot(( + (( + y) >= Math.clz32(x))), x) >>> 0), mathy1(( + ( ~ mathy1((0x080000000 >>> 0), (((-(2**53) | 0) ? y : y) >>> 0)))), ( + y)))))); }); testMathyFunction(mathy2, [0x100000000, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, -0x0ffffffff, 42, -0x100000001, 1/0, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0, -(2**53-2), Math.PI, 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x080000001, 0x100000001, Number.MIN_VALUE, -0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 1, -1/0, 0.000000000000001, -(2**53), 2**53+2, 0x080000000]); ");
/*fuzzSeed-8783892*/count=1303; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (( ~ Math.fround(Math.clz32(( + ( + ( + Math.hypot(( + x), x))))))) - Math.atanh((( - ((Math.ceil((1/0 | 0)) | 0) | 0)) | 0)))); }); ");
/*fuzzSeed-8783892*/count=1304; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x080000000, Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, -0x080000001, 0/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 0x07fffffff, 0x080000001, -1/0, -0x100000000, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, 0, -0x0ffffffff, 1/0, 0x100000001, -0, 0x0ffffffff, 42, -0x07fffffff, 2**53, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-8783892*/count=1305; tryItOut("/*bLoop*/for (gszjnl = 0; gszjnl < 69; ++gszjnl) { if (gszjnl % 38 == 12) { Array.prototype.forEach.apply(a2, [(function(j) { if (j) { h2.__proto__ = m1; } else { try { a2 = Array.prototype.map.call(a2, (function() { try { Array.prototype.forEach.call(a2, (function() { print(uneval(h0)); return o2; })); } catch(e0) { } for (var v of h2) { v1 = (a1 instanceof g1); } return h2; }), i1, g0); } catch(e0) { } try { g0.v1 = (a2 instanceof s0); } catch(e1) { } try { e1.add(t0); } catch(e2) { } o2.s1.toString = (function() { try { this.a1 = Array.prototype.slice.call(o1.a1, -1, 6); } catch(e0) { } try { o1.v1 = g0.eval(\"/* no regression tests found */\"); } catch(e1) { } try { /*ADP-3*/Object.defineProperty(a1, 1, { configurable: (x % 38 == 22), enumerable:  /x/g , writable: true, value: s2 }); } catch(e2) { } s2 += this.s0; throw e2; }); } }), m0, b0, e1, o0, b0]); } else { print(x); }  } ");
/*fuzzSeed-8783892*/count=1306; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ((( + Math.pow(y, (( + Math.hypot(( + (((Number.MIN_VALUE >>> 0) << (y | 0)) | 0)), ( + x))) >> y))) - (Math.tan(( + Math.hypot(Math.atan2((-Number.MAX_VALUE | Math.fround(-0x0ffffffff)), x), ((x >>> 0) ? Math.fround(Math.fround((y | 0))) : (Math.min((Math.fround((x | 0)) >>> 0), (x >>> 0)) >>> 0))))) >>> 0)) ? (Math.pow((((((Math.trunc(Math.trunc(y)) || x) | 0) != (x | 0)) | 0) | 0), (Math.fround(( ! ( + ((((((x >>> 0) > ((((Math.log(y) | 0) === (x | 0)) | 0) >>> 0)) >>> 0) | 0) & ((( + (((((x ? x : Math.fround(x)) | 0) > ( + (Math.asin((x >>> 0)) >>> 0))) | 0) >>> 0)) >>> 0) | 0)) | 0)))) | 0)) | 0) : Math.atanh(Math.fround(Math.atan2(Math.fround(Math.min(Math.fround(x), Math.fround(( + Math.acosh((((( + x) | 0) , (x | 0)) | 0)))))), Math.fround(x))))); }); testMathyFunction(mathy0, /*MARR*/[0x3FFFFFFF, new Number(1.5)]); ");
/*fuzzSeed-8783892*/count=1307; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      (Uint8ArrayView[2]) = ((/*FFI*/ff(((imul(((134217727.0) < (-7.737125245533627e+25)), (i1))|0)), ((delete x.d)), ((72057594037927940.0)), ((-6.044629098073146e+23)), ((imul((!((0x7efb055a) < (-0x8000000))), (i1))|0)), ((+(0.0/0.0))))|0)+(i1));\n    }\n    {\n      i0 = ((abs(((((abs((abs((((0xf9d5d029))|0))|0))|0) > (~((-0x3f7555)+(0xffffffff)+(0x6f54bad6))))+(/*FFI*/ff(((0x4c3c5757)), ((4398046511105.0)), ((((0x33775c78)-(-0x8000000)+(0xb3757dd5))|0)))|0)) >> (((+/*FFI*/ff(((imul((0x9f40717a), (0xa31584c7))|0)), ((((-0x8000000)) & ((0x6bcf7c0)))), ((-536870913.0)), ((-17.0)))) == (-65.0))+(i1))))|0));\n    }\n    i1 = (!(i1));\n    {\ng2 = this;    }\n    i0 = (!(i1));\n    i0 = (0xffffffff);\n    switch ((-0x57705ca)) {\n    }\n    return +((34359738368.0));\n  }\n  return f; })(this, {ff: String.prototype.repeat}, new ArrayBuffer(4096)); ");
/*fuzzSeed-8783892*/count=1308; tryItOut("\"use strict\"; v0 = (s1 instanceof v0);");
/*fuzzSeed-8783892*/count=1313; tryItOut("for (var p in this.i0) { /*MXX2*/g1.g2.EvalError.prototype.message = g2.v2; }");
/*fuzzSeed-8783892*/count=1314; tryItOut("o2.v2 = t1.length;");
/*fuzzSeed-8783892*/count=1315; tryItOut("print(b1);");
/*fuzzSeed-8783892*/count=1316; tryItOut("\"use strict\"; /*infloop*/ for  each(var x[\"constructor\"] in true) Object.preventExtensions(i0);");
/*fuzzSeed-8783892*/count=1317; tryItOut("/* no regression tests found */");
/*fuzzSeed-8783892*/count=1318; tryItOut("testMathyFunction(mathy4, [-1/0, 0/0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -0, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0x080000000, -0x080000000, Math.PI, 0x080000001, 1, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 0, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, 0x100000001, 0.000000000000001, -0x0ffffffff, -(2**53), 0x0ffffffff, -(2**53+2), 2**53, -Number.MAX_VALUE, 2**53+2, -(2**53-2), 1/0, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-8783892*/count=1319; tryItOut("\"use strict\"; o0.t0[7] = ( '' ) = \"\\u1F9A\";");
/*fuzzSeed-8783892*/count=1320; tryItOut("mathy2 = (function(x, y) { return (((mathy1((mathy1(y, ((( - x) >>> 0) | 0)) | 0), ( - (( + (y >>> 0)) >>> 0))) ? Math.fround(( ! (((y >>> 0) > (x | 0)) | 0))) : (((Math.cosh(( + ( + (x >>> 0)))) >>> 0) <= Math.atan2(y, 1.7976931348623157e308)) >>> 0)) % Math.fround(( ! Math.fround((Math.log((y | 0)) | 0))))) >>> 0); }); testMathyFunction(mathy2, [-0x080000000, Number.MIN_VALUE, 0x07fffffff, -(2**53), 2**53, -Number.MAX_VALUE, -0x080000001, 1, 1/0, 0x100000000, 42, 0x100000001, 0, -0x100000001, -(2**53+2), -Number.MIN_VALUE, -0, 0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -1/0, 2**53+2, Number.MAX_VALUE, 0x080000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Math.PI, 0/0, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-8783892*/count=1321; tryItOut("i0.__proto__ = g2;");
/*fuzzSeed-8783892*/count=1322; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.imul(Math.fround(Math.abs(Math.log10((mathy4(Math.fround(y), (Math.max(-(2**53+2), (( + mathy0(( + y), ( + -(2**53)))) >>> 0)) >>> 0)) | 0)))), (Math.fround((( + mathy4(Math.fround(((((y > ( + ((x ** (x >>> 0)) | 0))) | 0) & y) | 0)), ((Math.imul(-(2**53+2), y) ? (0x0ffffffff | 0) : y) | 0))) - Math.fround(mathy4(Math.fround(Math.imul(y, Math.fround(Math.imul(Math.fround(x), Math.fround(2**53+2))))), Math.fround(y))))) >>> 0))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 1, Number.MIN_VALUE, 0x080000000, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0, -(2**53), -0x0ffffffff, 0x0ffffffff, 0x07fffffff, 1/0, -1/0, 0.000000000000001, -(2**53-2), 2**53, Number.MAX_VALUE, 0x100000001, -0x100000001, -0x100000000, 0x080000001, 0x100000000, -Number.MIN_VALUE, Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, 2**53+2, -(2**53+2), 0/0]); ");
/*fuzzSeed-8783892*/count=1323; tryItOut("\"use strict\"; \"\\uBEDB\";");
/*fuzzSeed-8783892*/count=1324; tryItOut("mathy1 = (function(x, y) { return ((((Math.atan2((( + ((( ~ Math.ceil((x >>> 0))) >>> 0) !== ( ! x))) | 0), ((mathy0(Math.pow(y, (x | 0)), (Math.fround(Math.log2(Math.fround((y ? -Number.MAX_SAFE_INTEGER : y)))) | 0)) >>> (mathy0(( + y), ( + -0x07fffffff)) | 0)) | 0)) | 0) >>> 0) ? Math.fround(mathy0(( + (Math.fround((Math.fround(( + x)) << Math.fround(( ! Math.fround(Math.hypot(Math.fround((y >>> 1.7976931348623157e308)), (Math.min(( + x), x) | 0))))))) - (Math.pow(1.7976931348623157e308, y) / Math.imul(y, Math.tanh(x))))), (( + (Math.sqrt((y | 0)) | 0)) % ( ~ 0x080000001)))) : ((( ~ ((Math.cbrt(((Math.fround(((x >>> 0) === ( - ( - Number.MAX_SAFE_INTEGER)))) >>> 0) << (Math.imul((x >>> 0), (2**53-2 >>> 0)) >>> 0))) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined()]); ");
/*fuzzSeed-8783892*/count=1325; tryItOut("\"use strict\"; a1.unshift(o0.s1, new ((uneval(window)))((Float64Array((/*MARR*/[0x40000001, 0x40000001].some(window)))), ((/*UUV2*/(x.fromCharCode = x.setUTCDate)).__defineSetter__(\"c\", decodeURIComponent))) + 8 , x, g1.g0.e0, p1, t1, h0, m2, Math.atan2(window =  '' .eval(\"e2.add(g2.f1);\") + (makeFinalizeObserver('tenured')), -11));");
/*fuzzSeed-8783892*/count=1326; tryItOut("");
/*fuzzSeed-8783892*/count=1327; tryItOut("/*\n*/(-12);");
/*fuzzSeed-8783892*/count=1328; tryItOut("mathy2 = (function(x, y) { return Math.max((((((( + (Math.fround(mathy1(Math.fround((( + y) << Math.fround(y))), Math.fround(x))) * mathy0(Number.MAX_SAFE_INTEGER, 0x100000001))) == ( + (Math.fround(x) <= Math.log2(Math.fround((Math.fround(-0x080000000) != Math.fround(x))))))) >>> 0) | 0) * (Math.fround((Math.max((Math.max(y, 0x0ffffffff) ? y : Math.fround(-0x0ffffffff)), y) ** Math.hypot((( + Math.hypot((Math.acos(y) | 0), x)) | 0), (mathy0(Math.imul(( + Math.trunc(( + x))), Number.MAX_VALUE), (((x >>> 0) & (y >>> 0)) >>> 0)) >>> 0)))) >>> 0)) >>> 0), Math.atanh(Math.round(Math.asin((((Math.min(( + x), x) >>> 0) === ((((Number.MAX_VALUE | 0) ? Number.MAX_VALUE : (y | 0)) | 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [(new Number(0)), '/0/', (new Boolean(false)), 0, undefined, '\\0', null, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 1, ({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return '0';}}), '', [], (new Boolean(true)), [0], NaN, '0', /0/, (function(){return 0;}), -0, 0.1, (new String('')), true, false]); ");
/*fuzzSeed-8783892*/count=1329; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!([^\\\\u0035\\\\\\u5c02\\\\xA2\\\\W]\\\\t(\\\\x29)+))(?!\\\\1)[\\u0019-\\\\cV\\\\D]+?|(?=(((?:^))*)(?=.[^\\\\\\u00d3-\\\\u47d1\\\\u9040\\\\cK])|(?:.)+?|\\\\2+?)[\\\\cC-\\u0681\\u0dcb]{4,7}\", \"ym\"); var s = \")))\\u00b8\\u020e\\u0dcb\"; print(uneval(s.match(r))); ");
/*fuzzSeed-8783892*/count=1330; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, 1/0, -1/0, -(2**53-2), 0x080000000, -(2**53+2), 0x0ffffffff, 0x07fffffff, 2**53, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, 0, 0/0, 1, -0, 0x080000001, 0.000000000000001, Math.PI, -Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-8783892*/count=1331; tryItOut("testMathyFunction(mathy4, /*MARR*/[(-1/0), new Number(1), new Number(1), {x:3}, (-1/0), new Number(1), new Number(1), (-1/0), {x:3}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1), {x:3}, new Number(1), (-1/0), {x:3}, {x:3}, (-1/0), new Number(1), {x:3}, (-1/0), new Number(1), (-1/0), (-1/0), new Number(1), (-1/0), {x:3}, new Number(1), (-1/0), {x:3}, {x:3}, {x:3}, (-1/0), {x:3}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), {x:3}, (-1/0), new Number(1), (-1/0), new Number(1), (-1/0), new Number(1), {x:3}, new Number(1), new Number(1), {x:3}, (-1/0), (-1/0), new Number(1), new Number(1), new Number(1), (-1/0), new Number(1), new Number(1), new Number(1), (-1/0), new Number(1), {x:3}, {x:3}, {x:3}, new Number(1), (-1/0), {x:3}, (-1/0), {x:3}, {x:3}, new Number(1), {x:3}, new Number(1), new Number(1)]); ");
/*fuzzSeed-8783892*/count=1332; tryItOut("Array.prototype.reverse.call(a1);");
/*fuzzSeed-8783892*/count=1333; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a2, v1, { configurable: (4277), enumerable: (x % 2 == 0), get: function  setter (w)((Math.hypot((x | 0), (-0x07fffffff | 0)) | 0)), set: (function() { try { a2.__proto__ = e0; } catch(e0) { } Object.prototype.watch.call(e1, \"call\", Object.keys.bind(o0)); return e1; }) });");
/*fuzzSeed-8783892*/count=1334; tryItOut("\"use strict\"; e2 = new Set(this.f1);");
/*fuzzSeed-8783892*/count=1335; tryItOut("\"use strict\"; v0 = a2.length;v0 = Object.prototype.isPrototypeOf.call(t2, o2);\nvar doarod = new ArrayBuffer(24); var doarod_0 = new Int32Array(doarod); doarod_0[0] = 4; b1 = t2.buffer;\n");
/*fuzzSeed-8783892*/count=1336; tryItOut("print(let (z = this) c);");
/*fuzzSeed-8783892*/count=1337; tryItOut("/* no regression tests found */");
/*fuzzSeed-8783892*/count=1338; tryItOut("\"use strict\"; t1 = g2.t2.subarray(17);");
/*fuzzSeed-8783892*/count=1339; tryItOut("\"use asm\"; delete h2.keys;");
/*fuzzSeed-8783892*/count=1340; tryItOut("\"use strict\"; let x = x;(void schedulegc(g2));");
/*fuzzSeed-8783892*/count=1341; tryItOut("p1.__proto__ = b1;");
/*fuzzSeed-8783892*/count=1342; tryItOut("\"use asm\";  '' ;function eval(w) { {f2.valueOf = (function(j) { if (j) { /*ODP-3*/Object.defineProperty(o1, new String(\"-1\"), { configurable: false, enumerable: (x % 9 != 8), writable: \"\\uBB53\", value: g1 }); } else { try { v2 = Object.prototype.isPrototypeOf.call(t0, v0); } catch(e0) { } try { t0.set(a1, 13); } catch(e1) { } try { h2.defineProperty = f0; } catch(e2) { } i1.next(); } });o2.o0.t2.__iterator__ = (function() { try { g2.s1 = Array.prototype.join.call(a1, o1.s0, v1); } catch(e0) { } delete h0.getOwnPropertyDescriptor; return v1; }); } } switch(eval(\"/* no regression tests found */\", false)) { case 1: break;  }");
/*fuzzSeed-8783892*/count=1343; tryItOut("Array.prototype.shift.apply(a2, [v2]);");
/*fuzzSeed-8783892*/count=1344; tryItOut("\"use asm\"; /*bLoop*/for (let qohuuk = 0; qohuuk < 80; ++qohuuk) { if (qohuuk % 2 == 0) { a0.reverse(); } else { /*RXUB*/var r = /(.)/gym; var s = \"\"; print(s.replace(r, 'x'));  }  } ");
/*fuzzSeed-8783892*/count=1345; tryItOut("i1.__iterator__ = (function mcc_() { var iseisy = 0; return function() { ++iseisy; if (/*ICCD*/iseisy % 7 == 3) { dumpln('hit!'); try { v0 = Object.prototype.isPrototypeOf.call(v1, e0); } catch(e0) { } try { v0 + ''; } catch(e1) { } a2[10] = p1; } else { dumpln('miss!'); try { i2.next(); } catch(e0) { } try { g1.v1 = t2.length; } catch(e1) { } try { print(uneval(o1.e0)); } catch(e2) { } /*ODP-1*/Object.defineProperty(f1, new String(\"9\"), ({configurable: false, enumerable: new Boolean(false)})); } };})();");
/*fuzzSeed-8783892*/count=1346; tryItOut("/*bLoop*/for (ujlzqs = 0; ujlzqs < 74; ++ujlzqs) { if (ujlzqs % 5 == 2) { g0.v0 = Object.prototype.isPrototypeOf.call(p1, e1); } else { m1 = new Map; }  } ");
/*fuzzSeed-8783892*/count=1347; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.log2((Math.log2(( + x)) | 0)), ( - (( ~ -0x080000000) | 0)))); }); testMathyFunction(mathy2, [0x0ffffffff, -0x100000001, 1/0, -0x080000000, -1/0, 0.000000000000001, 42, 0x07fffffff, 2**53-2, -0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 0x080000000, 0x100000001, -Number.MIN_VALUE, 0, 2**53, -0x0ffffffff, Math.PI, 0/0, 0x100000000, 1, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, -(2**53), 0x080000001]); ");
/*fuzzSeed-8783892*/count=1348; tryItOut("b2.toString = neuter;");
/*fuzzSeed-8783892*/count=1349; tryItOut("a1[14] = Math.trunc(-28);");
/*fuzzSeed-8783892*/count=1350; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x0ffffffff, -Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, 42, -(2**53), -0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 1, -1/0, Math.PI, 2**53+2, 0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, 2**53-2, 2**53, 0x07fffffff, -Number.MIN_VALUE, 0, 1.7976931348623157e308, Number.MAX_VALUE, -0x07fffffff, 0x080000001, 1/0, -0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-8783892*/count=1351; tryItOut("testMathyFunction(mathy3, [1/0, -0x0ffffffff, 0, -Number.MIN_VALUE, 0x100000000, -(2**53), 2**53, 0x100000001, 0x080000000, 1, Math.PI, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000001, 0/0, 2**53-2, Number.MIN_VALUE, -0x080000000, -0x080000001, -1/0, -0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), 0x07fffffff, -0, 42, -Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-8783892*/count=1352; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (!((-4398046511105.0) <= (8193.0)));\n    }\n    return (((Uint32ArrayView[1])))|0;\n  }\n  return f; })(this, {ff: Math.tan}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[x, x, function(){}, x, x, x, function(){}, x, x, x, function(){}, x, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, x, x, x, function(){}, x, function(){}, function(){}, x]); ");
/*fuzzSeed-8783892*/count=1353; tryItOut("Array.prototype.push.call(a0, o1, s1, m2, t1, g0, s1);");
/*fuzzSeed-8783892*/count=1354; tryItOut("\"use strict\"; /* no regression tests found */\nprint(new EvalError(true, 67108864));function d() { \"use strict\"; yield (4277) } i0 = new Iterator(f2, true)");
/*fuzzSeed-8783892*/count=1355; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-8783892*/count=1356; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! ( + (Math.hypot(( + Math.imul(Math.fround(y), ( + (( + x) === ( + Math.fround(mathy1(((( ! ( + x)) >>> 0) >>> 0), (Math.pow(y, Number.MAX_VALUE) >>> 0)))))))), ( + x)) && (x != (Math.sqrt((y >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [-(2**53+2), -0x0ffffffff, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, 42, 2**53-2, 2**53, 1/0, -Number.MAX_VALUE, -0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, -(2**53), 0/0, -1/0, 0, 0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, 1, -Number.MIN_VALUE, -0x07fffffff, -0, 0x0ffffffff]); ");
/*fuzzSeed-8783892*/count=1357; tryItOut("p0.__proto__ = g0;");
/*fuzzSeed-8783892*/count=1358; tryItOut("\"use strict\"; function f0(g1) (timeout(1800))");
/*fuzzSeed-8783892*/count=1359; tryItOut("mathy3 = (function(x, y) { return (Math.sqrt(Math.fround(Math.fround(mathy0(Math.fround(Math.ceil(-0)), Math.max(y, Math.trunc(2**53)))))) <= Math.fround(Math.exp((( ~ Math.fround(Math.sin(Math.fround(y)))) | 0)))); }); testMathyFunction(mathy3, [-0x0ffffffff, 0x07fffffff, 0/0, 2**53-2, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, -0x080000001, 0x080000001, -Number.MAX_VALUE, -1/0, 2**53+2, -0, -0x07fffffff, 1/0, 0.000000000000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, 0x100000001, -(2**53), -Number.MIN_VALUE, 1, 0x080000000, 0x100000000, -0x100000000]); ");
/*fuzzSeed-8783892*/count=1360; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.cbrt(Math.fround((((Math.ceil(( + ( ! 0x080000000))) >>> 0) | 0) > (x | 0)))), (Math.atan2(((Math.max((( + Math.atan2(x, Math.atan2((y >>> 0), ((Math.atan((y | 0)) >>> 0) >>> 0)))) >>> 0), x) !== ( ~ y)) >>> 0), Math.asin((x | 0))) >>> 0)); }); ");
/*fuzzSeed-8783892*/count=1393; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.sign(Math.pow(Math.max(Math.acosh((mathy0(x, y) | (0/0 | 0))), Math.atan2(Math.min(y, x), (mathy2(( + mathy0(y, x)), Math.fround(( ! y))) >>> 0))), ( + ((Math.tan(y) <= y) | ( ~ ( + y)))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -1/0, 2**53, -0x100000000, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, 1, 0x100000000, -0x0ffffffff, 0x07fffffff, -0x080000000, -0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0/0, 0x100000001, -0x080000001, 0x0ffffffff, 0, -0x07fffffff, 2**53-2, -Number.MIN_VALUE, -(2**53-2), 1/0, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 0x080000000, 0.000000000000001]); ");
/*fuzzSeed-8783892*/count=1394; tryItOut("/*vLoop*/for (dncskf = 0; dncskf < 21; ++dncskf) { var y = dncskf; /*bLoop*/for (gotkzy = 0; gotkzy < 109; ++gotkzy) { if (gotkzy % 12 == 10) { /*infloop*/for(let e = this; function ([y]) { }; -20) {g0.toSource = (function() { for (var j=0;j<6;++j) { this.f2(j%2==0); } }); } } else { h1.defineProperty = f2; }  }  } ");
/*fuzzSeed-8783892*/count=1395; tryItOut("/*RXUB*/var r = /[\u0005-\\t\\d]|\\\u8339.{3,}\\b|\\D?\\1|\\2/gym; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-8783892*/count=1396; tryItOut("/*MXX2*/g1.g1.WeakMap.prototype = o0;");
/*fuzzSeed-8783892*/count=1397; tryItOut("b1.toSource = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 128.0;\n    var i3 = 0;\n    d1 = (-4096.0);\n    return +((140737488355329.0));\n  }\n  return f; });");
/*fuzzSeed-8783892*/count=1398; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new Boolean(false)), 1, 0.1, /0/, null, (new Boolean(true)), '', false, undefined, '\\0', ({valueOf:function(){return 0;}}), [0], (new Number(-0)), '/0/', NaN, (new Number(0)), 0, objectEmulatingUndefined(), ({toString:function(){return '0';}}), -0, '0', (function(){return 0;}), [], ({valueOf:function(){return '0';}}), (new String('')), true]); ");
/*fuzzSeed-8783892*/count=1399; tryItOut("/*oLoop*/for (let tefjyj = 0; tefjyj < 112; ++tefjyj) { /*RXUB*/var r = new RegExp(\"(\\\\s*(\\\\B+)*?+?)|(?:[\\\\v-\\\\\\ud02f\\\\xf5][^]{0,1}|\\\\W*?$)\", \"y\").__defineGetter__(\"x\", String.prototype.trimRight); var s = x; print(s.split(r));  } ");
/*fuzzSeed-8783892*/count=1400; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(o2, o0);");
/*fuzzSeed-8783892*/count=1401; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-8783892*/count=1402; tryItOut("{v0 = t2.BYTES_PER_ELEMENT;v1 = evaluate(\"\\\"use strict\\\"; mathy5 = (function(x, y) { return Math.asin(Math.min((Math.log((( ! x) >>> 0)) >>> mathy4((((x == -Number.MAX_VALUE) !== Math.log2(y)) >>> 0), ( + mathy3(( + y), Math.fround(y))))), Math.hypot((Math.imul(Math.min(y, Math.imul(x, ( + Math.log2(x)))), ( + (( + (y ? -0 : x)) * ( + (x ? y : y))))) | 0), y))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x0ffffffff, -0x100000001, -0x080000000, 0x07fffffff, 0x080000000, 2**53, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, 42, -1/0, 1, -Number.MAX_VALUE, -0x080000001, 0x080000001, 0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000001, 0/0, -(2**53-2), -(2**53), -0, 0.000000000000001, -0x0ffffffff, Number.MIN_VALUE]); \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: \n11 })); }");
/*fuzzSeed-8783892*/count=1403; tryItOut("\"use strict\"; g2 = this;var tlhogk = new SharedArrayBuffer(2); var tlhogk_0 = new Int8Array(tlhogk); var tlhogk_1 = new Int8Array(tlhogk); tlhogk_1[0] = Number.MAX_SAFE_INTEGER; var tlhogk_2 = new Int32Array(tlhogk); var tlhogk_3 = new Float32Array(tlhogk); tlhogk_3[0] = 9; var tlhogk_4 = new Int16Array(tlhogk); var tlhogk_5 = new Uint8ClampedArray(tlhogk); tlhogk_5[0] = 25; var tlhogk_6 = new Uint8ClampedArray(tlhogk); tlhogk_6[0] = -19; var tlhogk_7 = new Uint16Array(tlhogk); print(tlhogk_7[0]); tlhogk_7[0] = 25; throw this;( \"\" );a2.__proto__ = g0.g2;g2.offThreadCompileScript(\"/* no regression tests found */\");t0 = t1.subarray(v0, 9);o0.o2.h1.valueOf = (function() { try { i2 = m0.keys; } catch(e0) { } try { v1 = g1.runOffThreadScript(); } catch(e1) { } Array.prototype.forEach.apply(a0, [f1, this.a1, f0]); return this.h2; });a0.sort(this.o0.f1, i0);throw  '' ;g0.m2.delete(f0);h1.getPropertyDescriptor = Object.getOwnPropertyNames.bind(m2);");
/*fuzzSeed-8783892*/count=1404; tryItOut("g0.valueOf = (function() { for (var j=0;j<41;++j) { f0(j%2==0); } });");
/*fuzzSeed-8783892*/count=1405; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround(Math.cos(( + Math.acosh(Math.sinh((x / Number.MIN_SAFE_INTEGER))))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -1/0, 42, -0, -(2**53+2), -0x0ffffffff, 0/0, Math.PI, 1/0, 0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 0x100000001, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, 2**53-2, 0x080000001, 0x100000000, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, -(2**53), -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-8783892*/count=1406; tryItOut("/* no regression tests found *//* no regression tests found */");
/*fuzzSeed-8783892*/count=1407; tryItOut("");
/*fuzzSeed-8783892*/count=1408; tryItOut("a0.splice(NaN, 15, f1, i2);");
/*fuzzSeed-8783892*/count=1473; tryItOut("\"use strict\"; v0 = new Number(this.p2);");
/*fuzzSeed-8783892*/count=1474; tryItOut("Array.prototype.push.call(a2);\nv1 = (g2 instanceof i2);\n");
/*fuzzSeed-8783892*/count=1475; tryItOut("\"use strict\"; {o0.a0 = [];print(x); }");
/*fuzzSeed-8783892*/count=1476; tryItOut("s0.valueOf = (function mcc_() { var kulqaj = 0; return function() { ++kulqaj; f2(/*ICCD*/kulqaj % 11 == 6);};})();");
/*fuzzSeed-8783892*/count=1477; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.fround((Math.round((x ** 2**53-2)) | 0)) | 0); }); ");
/*fuzzSeed-8783892*/count=1478; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[x, x, x, x,  /x/g ,  /x/g , x,  /x/g , x, x,  /x/g , x, x,  /x/g , x,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g , x, x,  /x/g ,  /x/g , x, x, x,  /x/g ,  /x/g ,  /x/g , x, x, x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x,  /x/g , x, x,  /x/g , x,  /x/g , x, x, x,  /x/g , x, x, x, x,  /x/g ,  /x/g , x,  /x/g , x,  /x/g ]); ");
/*fuzzSeed-8783892*/count=1479; tryItOut("\"use strict\"; with(Math.clz32((x ,  \"\" )) in (Math.abs(x)))/*RXUB*/var r = /\\3(?:((?:[^])*?))(?:[^\\u0074\\cF])|(?!-)?|\\1{0,4}|(?:\\d\\W)|\\2\\3{1048577}+/im; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-8783892*/count=1480; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.fround(( ~ ((((((mathy0(Math.hypot(x, x), x) | 0) & Math.fround(( + ( - ( + Math.log10((x | 0))))))) | 0) >>> 0) >> (( + ( - ( + x))) >>> 0)) >>> 0))) ? Math.imul(Math.fround(mathy0(Math.imul(Math.fround(Math.fround(Math.pow(-0x100000000, x))), y), (( + Math.fround(x)) >>> 0))), Math.fround((Math.imul(( - x), (x === x)) | 0))) : ((Math.max(( ~ Math.max(x, Math.log(0x0ffffffff))), ( + Math.hypot(Math.tan((1 >>> 0)), (y ? 0x080000001 : ( ! y))))) / ( + Math.max(( + ( + (Math.expm1(( ! 0x080000001)) | 0))), ( + (Math.atan2((Math.fround(mathy0(Math.fround(x), Math.fround(x))) >>> 0), (( - (Math.pow(-(2**53), (y | 0)) | 0)) >>> 0)) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [0.000000000000001, 1/0, 0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, 0x080000000, -0x080000000, 0/0, Number.MIN_VALUE, 0x07fffffff, Math.PI, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000000, -0x080000001, 0, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, 1, 1.7976931348623157e308, -(2**53+2), 2**53, 42, -Number.MAX_VALUE, -0, 0x080000001, 0x100000001, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), 2**53-2]); ");
/*fuzzSeed-8783892*/count=1481; tryItOut("\"use strict\"; ([] =  /* Comment */x);\u0009");
/*fuzzSeed-8783892*/count=1482; tryItOut("o0 + '';");
/*fuzzSeed-8783892*/count=1483; tryItOut("testMathyFunction(mathy0, [-0x080000001, -1/0, 2**53-2, 1, -0x100000001, 0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, 2**53, 0x100000001, Number.MAX_VALUE, 0x080000000, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, -0, -(2**53+2), -Number.MIN_VALUE, 2**53+2, -0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, 42, -(2**53-2), -0x080000000, -0x0ffffffff, 0.000000000000001, 0x0ffffffff, -0x07fffffff, 0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-8783892*/count=1484; tryItOut("testMathyFunction(mathy0, [-0, 2**53+2, 0x100000000, -Number.MAX_VALUE, Math.PI, -(2**53+2), Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff, 42, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 2**53, 0x080000001, Number.MAX_VALUE, -0x100000000, -1/0, 0x080000000, 0x100000001, 0/0, 0.000000000000001, -0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, -(2**53)]); ");
/*fuzzSeed-8783892*/count=1485; tryItOut("\"use strict\"; a1.sort((function() { m2.toString = this.f2; throw t2; }));");
/*fuzzSeed-8783892*/count=1486; tryItOut("mathy5 = (function(x, y) { return ( + mathy4((( + Math.round(( + ( ! ( + ((mathy3((y | 0), (x >>> 0)) | 0) !== ( + x))))))) | 0), ( + ( + ( ! (Math.expm1(((mathy0(( + 0/0), ( + ( + (x & (Math.atan2((y >>> 0), (Math.clz32(x) >>> 0)) >>> 0))))) | 0) | 0)) | 0)))))); }); ");
/*fuzzSeed-8783892*/count=1487; tryItOut("f0 = Proxy.createFunction(h1, o0.f1, f1);");
/*fuzzSeed-8783892*/count=1488; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (mathy1((( ~ [1]) >>> 0), ((((((Math.asinh((x >>> 0)) == Math.imul(y, 2**53+2)) | 0) | 0) && (Math.fround(Math.hypot(Math.fround(y), Math.fround(Math.fround(( ~ Math.fround((( - -Number.MIN_SAFE_INTEGER) >>> 0))))))) | 0)) | 0) >>> 0)) >>> 0)) > ( + (( - Math.fround(Math.hypot(Math.min(( + x), ( + y)), y))) >>> 0))); }); ");
/*fuzzSeed-8783892*/count=1489; tryItOut("s0 = new String(e2);");
/*fuzzSeed-8783892*/count=1490; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( + mathy2(Math.min(( ~ y), Math.fround(( ! (y & x)))), (Math.trunc(((( + ( + ( - ( + x)))) >>> Math.fround(mathy2(y, Math.cos(mathy1(1, x))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [-0x100000001, Number.MIN_SAFE_INTEGER, 1, -(2**53-2), -(2**53), 0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, -Number.MIN_VALUE, 2**53+2, -0x080000001, 1/0, Number.MIN_VALUE, 1.7976931348623157e308, 0, -0, 0x0ffffffff, 42, 0x080000001, -Number.MAX_VALUE, -0x0ffffffff, -0x080000000, 0x100000000, -(2**53+2), 0.000000000000001, 2**53, 0x07fffffff, -0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-8783892*/count=1491; tryItOut("\"use strict\"; /\\3/gymreturn -9;");
/*fuzzSeed-8783892*/count=1492; tryItOut("const x, [, , y] = (w & window), y = (4277).eval(\"Array.prototype.unshift.call(a2, f2, o0.g2.e0, x, f2, o2);\");for (var p in e0) { try { h0 = ({getOwnPropertyDescriptor: function(name) { g2 + v0;; var desc = Object.getOwnPropertyDescriptor(a0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { for (var p in h1) { try { v1 = r1.sticky; } catch(e0) { } try { v1 = (m0 instanceof g2); } catch(e1) { } g0.e2.has(b0); }; var desc = Object.getPropertyDescriptor(a0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { function f0(o2.f0)  { yield /*RXUE*//(?=([^])\\uC0ab|\\d{4,4})(?=\\2)+{1,5}[^\\v\\f\ube32-\\cM\\t-\ude8b]/gyim.exec(\"\\uA59F\") } ; Object.defineProperty(a0, name, desc); }, getOwnPropertyNames: function() { for (var v of e0) { try { o1.e0.has(o2.p1); } catch(e0) { } try { a2.splice(14, \"\\uD44B\"); } catch(e1) { } try { v1 = g1.runOffThreadScript(); } catch(e2) { } /*ADP-1*/Object.defineProperty(a0, 17, ({})); }; return Object.getOwnPropertyNames(a0); }, delete: function(name) { this.o0.o0.a1 = Array.prototype.concat.call(a1, t2, g1.b1);; return delete a0[name]; }, fix: function() { a1.shift(h1, e1);; if (Object.isFrozen(a0)) { return Object.getOwnProperties(a0); } }, has: function(name) { Array.prototype.reverse.call(a1, g0.t2);; return name in a0; }, hasOwn: function(name) { a0.forEach((function() { try { v2 = new Number(Infinity); } catch(e0) { } i1 = new Iterator(s1); return p2; }));; return Object.prototype.hasOwnProperty.call(a0, name); }, get: function(receiver, name) { e1 = x;; return a0[name]; }, set: function(receiver, name, val) { f0(o0);; a0[name] = val; return true; }, iterate: function() { throw g2; return (function() { for (var name in a0) { yield name; } })(); }, enumerate: function() { g0.b1 = t0.buffer;; var result = []; for (var name in a0) { result.push(name); }; return result; }, keys: function() { Object.seal(this.s2);; return Object.keys(a0); } }); } catch(e0) { } try { i0.__proto__ = s2; } catch(e1) { } i1.next(); }");
/*fuzzSeed-8783892*/count=1493; tryItOut("this.h0.set = (function() { try { function f0(f0) \"use asm\";   var abs = stdlib.Math.abs;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = ((abs((~((i0)+(1))))|0));\n    return +((-6.044629098073146e+23));\n  }\n  return f; } catch(e0) { } try { g0.o2.e0.has(o2); } catch(e1) { } try { f2.toSource = (function() { try { e1.delete(v2); } catch(e0) { } try { v2 = g0.g0.runOffThreadScript(); } catch(e1) { } try { print(x); } catch(e2) { } a0 + v2; throw h1; }); } catch(e2) { } v0 = a2.length; return g2; });");
/*fuzzSeed-8783892*/count=1494; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-8783892*/count=1495; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( ~ Math.fround(Math.min(((Math.min((Math.expm1(x) >>> 0), (((( - Math.fround(x)) | 0) ? (Math.min((y >>> 0), (y | 0)) >>> 0) : ( + Math.log2(x))) >>> 0)) >>> 0) | 0), ( + ((( + (x >>> 0)) >>> 0) >= Math.acosh(( + Math.max(( + Math.log10(x)), ( + ( ! 2**53)))))))))) | 0); }); testMathyFunction(mathy0, /*MARR*/[null, null, null, null, null, null, null, arguments.callee, null, null, arguments.callee, null, null, arguments.callee, arguments.callee, null, null, null, null, null, null, null, null, null, arguments.callee, arguments.callee, arguments.callee, null, arguments.callee, arguments.callee, null, arguments.callee, null, null, null, null, arguments.callee, null, null, null, null, arguments.callee, null, null, arguments.callee, null, null, null, null, null, null, null, null, null, null, null, null, null, null, arguments.callee, arguments.callee, null, arguments.callee, null, null, null, null, null, arguments.callee, arguments.callee, arguments.callee, null, arguments.callee, null, null, arguments.callee, null, null, null, arguments.callee, null, arguments.callee, null, null, null, null, arguments.callee, null, null, arguments.callee]); ");
/*fuzzSeed-8783892*/count=1496; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\"; Function  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 1.00390625;\n    return (((i2)+(0x26605ff7)-(!(i2))))|0;\n  }\n  return f; })(this, {ff: (eval).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x0ffffffff, -0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 0, -Number.MAX_VALUE, 1/0, -0x080000000, -(2**53), 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, -0, Number.MIN_VALUE, 42, -(2**53+2), 0x080000001, 2**53+2, Math.PI, 0.000000000000001, 1, 0x100000000, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53-2), 0x07fffffff, -0x100000001, 0x080000000]); ");
/*fuzzSeed-8783892*/count=1505; tryItOut("mathy5 = (function(x, y) { return ( + Math.sin((Math.imul((Math.atan((((( + Math.imul(( + y), ( + ( + mathy2(( + 0x080000001), ( + x)))))) >>> 0) >>> ( + Math.fround(( - x)))) >>> 0)) >>> 0), Math.imul(Math.pow(Math.acosh(x), x), (Math.asinh(x) >>> 0))) | 0))); }); testMathyFunction(mathy5, [0x100000000, 0, -0x0ffffffff, 1.7976931348623157e308, 0x080000000, -0x07fffffff, -0x100000001, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, 0x07fffffff, 1/0, 0.000000000000001, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0x100000001, -0x080000001, -0x080000000, 2**53+2, -(2**53), -1/0, -(2**53-2), -0x100000000, 1, 2**53, -0, 0x080000001]); ");
/*fuzzSeed-8783892*/count=1506; tryItOut("\"use strict\"; \"use asm\"; /*oLoop*/for (let wquxsl = 0; wquxsl < 2; ++wquxsl) { /* no regression tests found */ } ");
/*fuzzSeed-8783892*/count=1507; tryItOut("let (eval, y = new SyntaxError(), metlph, x = let (window, mxmyll, x, a, ytvcmz, window) [,,z1], [] = ((Int16Array).apply).call(this,  /x/g , this), uyzbtg, b, cfxfnv, akxcch, x) { switch( /x/ ) { case 4: print(x); } }");
/*fuzzSeed-8783892*/count=1508; tryItOut("\"use strict\"; Array.prototype.forEach.call(a0, (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 129.0;\n    var d3 = -1024.0;\n    var d4 = -36028797018963970.0;\n    d1 = (((Float64ArrayView[((/*FFI*/ff(((((+(-1.0/0.0))) - (((0x98d1f544) ? (-1.888946593147858e+22) : (1073741824.0))))))|0)-(0xfa4d2213)) >> 3])) - ((-((d4)))));\n    (Float64ArrayView[((Uint16ArrayView[(((x) == (+(0.0/0.0)))+(i0)) >> 1])) >> 3]) = ((d4));\n    return ((-0x4fee3*(/*FFI*/ff(((d2)), ((imul((0x8a189cde), ((((i0))|0) <= (~~(d1))))|0)))|0)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)), a0, p2);");
/*fuzzSeed-8783892*/count=1509; tryItOut("v1 = Object.prototype.isPrototypeOf.call(i0, b2);");
/*fuzzSeed-8783892*/count=1510; tryItOut("/*infloop*/ for  each(let x in ({a2:z2})) yield;");
/*fuzzSeed-8783892*/count=1511; tryItOut("i1.next();");
/*fuzzSeed-8783892*/count=1512; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((Math.imul(Math.tanh((-0 ? Math.fround(x) : Math.fround(Math.fround(( - (mathy3(( + 2**53-2), Math.fround(mathy2(y, 2**53+2))) >>> 0)))))), ((( ~ (( + (( + Math.round(( + x))) | y)) >>> 0)) | 0) | 0)) | 0) , ( + ( - (Math.imul(mathy0(y, 0x080000000), x) | y)))); }); testMathyFunction(mathy4, [-(2**53), 0x0ffffffff, -0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, 2**53, 2**53-2, -1/0, -0x100000001, -0, -0x080000000, Math.PI, 0x07fffffff, 0x100000000, 0x080000001, -0x100000000, 0x080000000, 0x100000001, 1.7976931348623157e308, 2**53+2, 1/0, -Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, 0.000000000000001, -(2**53+2), 1, 0/0, -0x0ffffffff, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-8783892*/count=1513; tryItOut("v1 = evalcx(\"function f0(t0)  { return a = [] } \", g1.g2);");
/*fuzzSeed-8783892*/count=1514; tryItOut(";");
/*fuzzSeed-8783892*/count=1515; tryItOut("zkxvgo();/*hhh*/function zkxvgo(y){with({}) { y.stack; } }");
/*fuzzSeed-8783892*/count=1516; tryItOut("\"use strict\"; a1 = Array.prototype.concat.apply(a1, [a2, t0, o0]);/*bLoop*/for (var vmbswg = 0; vmbswg < 0; ++vmbswg) { if (vmbswg % 3 == 0) { t0[[z1,,]] = true; } else { h2.enumerate = f2; }  } ");
/*fuzzSeed-8783892*/count=1517; tryItOut("h2.enumerate = (function() { try { Array.prototype.pop.call(a1); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a1, -13, ({set: objectEmulatingUndefined, enumerable: (x % 5 == 0)})); } catch(e1) { } m1 = new Map(i1); return f0; });print(x);");
/*fuzzSeed-8783892*/count=1518; tryItOut("v2 = g2.eval(\"g1 = this;\");");
/*fuzzSeed-8783892*/count=1519; tryItOut("e1 + f2;");
/*fuzzSeed-8783892*/count=1520; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(( + Math.fround(mathy0(mathy0(( + Math.imul(Math.fround(y), ( + Math.atan2(0x100000000, (x | 0))))), Math.hypot(x, x)), (Math.log1p((y | 0)) >>> 0))))); }); testMathyFunction(mathy1, [-(2**53+2), 0x07fffffff, 0x080000001, Number.MIN_VALUE, 0/0, 0.000000000000001, 1.7976931348623157e308, -0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), -0x080000000, -(2**53-2), -0x0ffffffff, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, -0x100000000, 0x100000001, -0, Number.MAX_SAFE_INTEGER, 1/0, -1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, Math.PI, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000000, 42, 0, 2**53-2, 2**53]); ");
/*fuzzSeed-8783892*/count=1521; tryItOut("\"use strict\"; x;");
/*fuzzSeed-8783892*/count=1522; tryItOut("i1.next();");
/*fuzzSeed-8783892*/count=1523; tryItOut("mathy4 = (function(x, y) { return (Math.imul(Math.sign(Math.ceil(x)), Math.clz32(Math.fround(( ! Math.fround(mathy3(x, Math.fround(Math.sin((-(2**53+2) | 0))))))))) >>> 0); }); testMathyFunction(mathy4, [0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, -1/0, -0, -Number.MAX_SAFE_INTEGER, 1, 0x100000001, 42, 0x100000000, 2**53, 0.000000000000001, 0, -0x100000001, 0x07fffffff, -0x080000001, Number.MIN_VALUE, -0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), -Number.MAX_VALUE, -0x07fffffff, 0x080000000, -(2**53), 2**53+2, 1/0, -0x100000000, 0/0]); ");
/*fuzzSeed-8783892*/count=1524; tryItOut("{t2.set(a1, 10);(\"\\u554B\"); }");
/*fuzzSeed-8783892*/count=1525; tryItOut("m2.delete(a0);");
/*fuzzSeed-8783892*/count=1526; tryItOut("\"use strict\"; return  /x/ ;//h\n;");
/*fuzzSeed-8783892*/count=1527; tryItOut("let(\u3056, w, [] = \"\\uFE9B\", eval, zobkas, w, venzvl, __parent__, msjhhp) ((function(){throw y;})());");
/*fuzzSeed-8783892*/count=1528; tryItOut("eval = linkedList(eval, 7238);");
/*fuzzSeed-8783892*/count=1857; tryItOut("mathy1 = (function(x, y) { return (Math.imul((Math.tanh((((( - (y | 0)) | 0) / (y == y)) && y)) | 0), (Math.fround(Math.atan2((Math.imul((Math.ceil(Math.fround(-0x100000001)) | 0), (((Math.fround(x) ? Math.fround(y) : Math.fround(x)) === Math.max((y >>> 0), 0x080000000)) | 0)) | 0), Math.exp((mathy0((( + (( + y) >= ( + x))) | 0), x) | 0)))) | 0)) >>> 0); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, Math.PI, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, 0, 1, 1/0, 0x100000000, 0x080000000, 42, -0x07fffffff, -1/0, -0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, -0, 0x080000001, Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -Number.MAX_VALUE, -0x080000000, 2**53, 0.000000000000001, 0x07fffffff, -(2**53+2), 1.7976931348623157e308, 2**53-2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000001]); ");
/*fuzzSeed-8783892*/count=1858; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.fround(( + Math.fround(mathy1(( ! Math.atan2((y >>> 0), Math.fround((Math.fround(x) , Math.fround(0.000000000000001))))), x)))), mathy1(Math.fround(Math.atan((x & y))), (mathy3(x, (( ! y) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-8783892*/count=1859; tryItOut("\"use strict\"; with( /x/ ){; }");
/*fuzzSeed-8783892*/count=1860; tryItOut("/*MXX3*/g2.Date.prototype.constructor = g0.Date.prototype.constructor;\n/*oLoop*/for (let yzjekq = 0; yzjekq < 1; ++yzjekq) {  } \n");
/*fuzzSeed-8783892*/count=1861; tryItOut("g0.v0 = (a1 instanceof g2.h0);");
/*fuzzSeed-8783892*/count=1862; tryItOut("testMathyFunction(mathy5, /*MARR*/[-Number.MIN_SAFE_INTEGER, 033, (4277), (4277), (4277), 033, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (4277), (4277), -Number.MIN_SAFE_INTEGER, 033, (4277), -Number.MIN_SAFE_INTEGER, (4277), 033, (4277), -Number.MIN_SAFE_INTEGER, 033, 033, 033, 033, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (4277), -Number.MIN_SAFE_INTEGER, (4277), -Number.MIN_SAFE_INTEGER, 033, -Number.MIN_SAFE_INTEGER, (4277), -Number.MIN_SAFE_INTEGER, 033, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (4277), (4277), (4277), (4277), (4277), 033, (4277), (4277), -Number.MIN_SAFE_INTEGER, (4277), (4277), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (4277), (4277), 033, (4277), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (4277), 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, (4277), (4277), (4277), -Number.MIN_SAFE_INTEGER, 033]); ");
/*fuzzSeed-8783892*/count=1863; tryItOut("/*RXUB*/var r = (decodeURIComponent()); var s = \"\\uAF4F\"; print(uneval(r.exec(s))); ((p={}, (p.z = x.eval(\"\\\"\\\\u5AE6\\\"\"))()));");
/*fuzzSeed-8783892*/count=1864; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + (( + (( + ( + ( - ( + Math.atan(y))))) !== ((( + (((y | 0) , (( + Math.sin(y)) | 0)) | 0)) ? mathy0((y | 0), Math.tanh(Math.fround(Number.MAX_VALUE))) : y) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[[], true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new String(''), ({}), true, new String(''), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], true, ({}), true, [], ({}), new String(''), [], new String(''), true, ({}), true, true, true, true, new String(''), ({}), new String(''), ({}), [], ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), [], ({})]); ");
/*fuzzSeed-8783892*/count=1865; tryItOut("\"use strict\"; print(x);\nselectforgc(o1.o1);\n");
/*fuzzSeed-8783892*/count=1866; tryItOut("p1 = t0[1];\nprint(uneval(this.t1));\n");
/*fuzzSeed-8783892*/count=1867; tryItOut("print(((function too_much_recursion(kqfmsy) { ; if (kqfmsy > 0) { ; too_much_recursion(kqfmsy - 1);  } else { v2 = Object.prototype.isPrototypeOf.call(a1, o0); }  })(23903)));");
/*fuzzSeed-8783892*/count=1868; tryItOut("v0 = evalcx(\"/*ODP-1*/Object.defineProperty(v2, new String(\\\"12\\\"), ({value: ((x.x = x.unwatch(\\\"x\\\")))}));\", o1.o1.g0);");
/*fuzzSeed-8783892*/count=1869; tryItOut("mathy0 = (function(x, y) { return (( ! (Math.log2(Math.fround(Math.expm1(Math.fround((Math.log10(Math.fround(Math.imul((((x >>> 0) & (y >>> 0)) >>> 0), Math.fround(Math.pow(x, x))))) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy0, [-0x080000001, 1/0, -0, -(2**53+2), 1.7976931348623157e308, 2**53, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0x100000001, -(2**53-2), -0x080000000, Number.MAX_VALUE, 2**53-2, 0, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -0x100000001, 0x080000001, -1/0, 0x0ffffffff, 0x080000000, 0x100000000, -0x100000000, 42, 0/0]); ");
/*fuzzSeed-8783892*/count=1870; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.pow((Math.hypot((Math.cos((( ! x) >>> 0)) >>> 0), (((2**53+2 >>> 0) ? (y >>> 0) : (Math.hypot(Math.log(Math.fround((Math.fround(x) > Math.fround(y)))), (mathy4(x, x) >>> -(2**53+2))) >>> 0)) >>> 0)) | 0), (Math.fround((Math.fround(Math.max(((((Math.max(x, y) | 0) ? (0 ? (Math.round((x | 0)) | 0) : 0x100000001) : Math.fround(Math.sqrt(x))) >>> 0) | 0), Math.log(( + (((Math.atanh(0x080000000) | 0) << Math.max(y, Math.fround(Math.acosh(x)))) | 0))))) > Math.fround(Math.max(( + (( + y) === ( + y))), (mathy4(y, (Math.fround(mathy2(y, Math.fround((Math.trunc(( + x)) >>> 0)))) >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[(-1/0), new Number(1),  /x/g ,  /x/g , (-1/0),  /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new Number(1), new Number(1),  /x/g , new Number(1), (-1/0),  /x/g , new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), (-1/0), new Number(1), (-1/0)]); ");
/*fuzzSeed-8783892*/count=1871; tryItOut("\"use strict\"; print(let (vikkec, x, rcrnnw)  \"\" );");
/*fuzzSeed-8783892*/count=1872; tryItOut("h1.has = (function(a0, a1, a2, a3, a4, a5, a6) { var r0 = a1 & a5; print(a5); var r1 = a5 * a0; var r2 = a4 * 9; var r3 = r2 + a5; r0 = r0 * a0; var r4 = 2 & 8; var r5 = a1 ^ r1; var r6 = r0 * r2; var r7 = a2 ^ r0; r1 = a5 ^ r3; var r8 = 7 / a1; var r9 = r5 + a4; var r10 = a0 + r8; r4 = r10 + r9; var r11 = 8 % 9; a2 = r3 & a4; var r12 = r8 & r1; var r13 = r11 % r10; var r14 = a6 + 3; r1 = 7 % r4; var r15 = a0 - 0; r6 = a1 ^ 7; var r16 = r12 ^ r11; var r17 = 9 % r4; print(a2); var r18 = 8 & 9; var r19 = r16 ^ r5; var r20 = 2 | 2; var r21 = r14 & 9; var r22 = 9 | 6; var r23 = 2 | x; var r24 = r21 | 5; var r25 = 7 * 8; var r26 = r21 - r19; var r27 = 2 * r21; var r28 = 6 - 4; var r29 = r12 * r7; var r30 = r25 + 6; var r31 = 5 | r20; a2 = r31 * r8; var r32 = a5 * 6; r22 = x + r26; r29 = r3 % 9; var r33 = r28 * r5; var r34 = a6 - r21; var r35 = 3 % 7; r30 = 6 ^ a4; var r36 = r23 | r16; var r37 = 2 & 3; var r38 = r16 + r37; var r39 = 4 - r6; var r40 = a5 / r31; var r41 = r5 | r14; var r42 = r20 - r36; var r43 = r37 * 7; var r44 = r29 - r38; var r45 = r44 % 6; var r46 = a4 | r11; var r47 = r8 * 6; var r48 = r26 & r10; var r49 = r47 & 8; r43 = r33 % r9; var r50 = r14 * 3; r23 = r44 ^ r6; var r51 = r20 & r22; var r52 = x * a1; r33 = 6 * r39; var r53 = 0 * r2; print(r37); r12 = 4 % r17; var r54 = r16 & 9; var r55 = 8 - r52; var r56 = x * r10; var r57 = 5 / r16; r48 = 7 + a6; r34 = 6 * 8; var r58 = 1 / r2; r54 = 8 & a5; a2 = r53 % r42; r0 = r30 | 4; var r59 = r17 + 7; var r60 = r0 / r13; var r61 = r51 ^ r19; var r62 = r15 ^ a1; var r63 = r16 ^ r43; print(r12); var r64 = 4 - 0; var r65 = 1 - r5; var r66 = r25 | a5; var r67 = 4 + a5; r29 = 6 + r67; var r68 = r18 / r27; var r69 = r18 / r20; var r70 = a4 | r22; r69 = r51 ^ 0; var r71 = r63 * r23; var r72 = r40 ^ 7; var r73 = r28 ^ r11; var r74 = r40 * r33; var r75 = a5 ^ r10; r15 = 7 / r21; var r76 = 4 ^ 8; var r77 = r6 + r64; r67 = r31 * 8; var r78 = r70 * 8; var r79 = r15 | r30; var r80 = r3 % 6; var r81 = r17 * 1; r25 = r77 | a5; r18 = r34 / a0; a0 = r55 % r49; r66 = r49 % r36; var r82 = r58 - 6; var r83 = r29 ^ 8; var r84 = 0 & r76; var r85 = r84 + r64; var r86 = r46 + r55; var r87 = r17 / r66; var r88 = r84 | 5; var r89 = x | 8; var r90 = 3 / r42; var r91 = r37 / r67; var r92 = 0 & r90; var r93 = 5 / 3; var r94 = r2 % r83; var r95 = r75 | r82; var r96 = r39 * r21; var r97 = r58 + 4; var r98 = 2 / r28; var r99 = r46 * 0; r76 = r88 | 6; var r100 = r37 % r91; var r101 = 0 + a2; var r102 = r32 & 7; var r103 = r56 ^ r22; var r104 = r100 ^ r77; var r105 = r43 - 8; r74 = r73 * r44; var r106 = 1 & 5; var r107 = r77 + r21; a4 = r1 | 5; var r108 = 1 + 4; var r109 = r73 / r60; var r110 = 4 - r23; r55 = 3 - 1; var r111 = a0 & r48; var r112 = r20 / r4; var r113 = r16 ^ 4; return a0; });");
/*fuzzSeed-8783892*/count=1873; tryItOut("for (var v of g1.t1) { v2 = Object.prototype.isPrototypeOf.call(g1.m1, p0); }");
/*fuzzSeed-8783892*/count=1874; tryItOut("testMathyFunction(mathy3, /*MARR*/[x]); ");
/*fuzzSeed-8783892*/count=1875; tryItOut("i0 = new Iterator(this.o1, true);/*tLoop*/for (let w of /*MARR*/[b, 0x100000000, new Boolean(true), 0x100000000, new Boolean(true), b, new Boolean(true), new Boolean(true), 0x100000000, b, new Boolean(true), 0x100000000, 0x100000000, b, new Boolean(true), new Boolean(true), 0x100000000, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, 0x100000000, b, 0x100000000, 0x100000000, b, b, new Boolean(true), b, 0x100000000, b, 0x100000000, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), 0x100000000, new Boolean(true), b, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), b, b, b, new Boolean(true), 0x100000000, 0x100000000, 0x100000000, b, 0x100000000, new Boolean(true), b, new Boolean(true), 0x100000000, new Boolean(true), b, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, b, 0x100000000, b, new Boolean(true), b, 0x100000000, 0x100000000, 0x100000000, new Boolean(true), 0x100000000, 0x100000000, new Boolean(true), 0x100000000]) { g2.i1 = new Iterator(h0); }");
/*fuzzSeed-8783892*/count=1876; tryItOut("o1.toSource = (function() { for (var j=0;j<8;++j) { f0(j%3==0); } });\nh2 = ({getOwnPropertyDescriptor: function(name) { v0 = true;; var desc = Object.getOwnPropertyDescriptor(a2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { print(m1);; var desc = Object.getPropertyDescriptor(a2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e2.add(g1.f1);; Object.defineProperty(a2, name, desc); }, getOwnPropertyNames: function() { Array.prototype.unshift.apply(a0, [this.a0, g0.i1, g0.g2.g2]);; return Object.getOwnPropertyNames(a2); }, delete: function(name) { \"\\uFD18\" = t1[14];; return delete a2[name]; }, fix: function() { g1.a2.sort((function(j) { if (j) { f2.toString = (function() { try { for (var p in v0) { o1.v0 = (b1 instanceof g2); } } catch(e0) { } try { a1.forEach(String.prototype.trim); } catch(e1) { } o2.o0 = p1.__proto__; return t2; }); } else { try { r2 = new RegExp(\"(?=\\\\2|(?:\\uddc2(?:^)*)*?)\", \"gym\"); } catch(e0) { } try { /*MXX1*/g2.o0 = g0.ReferenceError.length; } catch(e1) { } try { o2.__proto__ = b1; } catch(e2) { } f1 = Proxy.createFunction(h2, f0, f2); } }));; if (Object.isFrozen(a2)) { return Object.getOwnProperties(a2); } }, has: function(name) { throw a0; return name in a2; }, hasOwn: function(name) { b0.toString = (function() { i0 = m2.entries; return h1; });; return Object.prototype.hasOwnProperty.call(a2, name); }, get: function(receiver, name) { return v2; return a2[name]; }, set: function(receiver, name, val) { /*RXUB*/var r = r1; var s = \"\"; print(r.test(s)); print(r.lastIndex); ; a2[name] = val; return true; }, iterate: function() { v1 = o2.g2.eval(\"function f1(t1) \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    {\\n      i0 = (i0);\\n    }\\n    (Uint8ArrayView[1]) = (((0x0) != (0x20f19a5))*-0xb3156);\\n    i1 = (i0);\\n    return +((-576460752303423500.0));\\n    return +((Infinity));\\n  }\\n  return f;\");; return (function() { for (var name in a2) { yield name; } })(); }, enumerate: function() { v1 = Object.prototype.isPrototypeOf.call(s2, b2);; var result = []; for (var name in a2) { result.push(name); }; return result; }, keys: function() { print(g1);; return Object.keys(a2); } });\n");
/*fuzzSeed-8783892*/count=1877; tryItOut("var dsbrfv = new SharedArrayBuffer(16); var dsbrfv_0 = new Float64Array(dsbrfv); print(dsbrfv_0[0]); dsbrfv_0[0] = 11; var dsbrfv_1 = new Int32Array(dsbrfv); print(dsbrfv_1[0]); dsbrfv_1[0] = 21; o1.o0.a1.sort((function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d1);\n    return (((-0x8000000)))|0;\n  }\n  return f; }), o2, b2, p0, i2, s1);");
/*fuzzSeed-8783892*/count=1878; tryItOut("{ void 0; minorgc(false); } /*vLoop*/for (let qkmxhu = 0; qkmxhu < 41; ++qkmxhu) { const y = qkmxhu; g2.a2.pop(i1); } ");
/*fuzzSeed-8783892*/count=1879; tryItOut("testMathyFunction(mathy5, [-(2**53), -0x080000000, -0x080000001, -Number.MAX_VALUE, 2**53, 0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, 2**53-2, 0x080000001, 1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 0x100000001, -(2**53-2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 0, Math.PI, 0/0, 42, -0, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000000, -1/0, 0.000000000000001, 1, 0x080000000]); ");
/*fuzzSeed-8783892*/count=1880; tryItOut("s1 += 'x';");
/*fuzzSeed-8783892*/count=1881; tryItOut("\"use strict\"; s0 += 'x';Array.prototype.reverse.call(a0, b1);");
/*fuzzSeed-8783892*/count=1882; tryItOut("mathy2 = (function(x, y) { return Math.log10(Math.atan2(((( + mathy1(( + x), ( + y))) === Math.asin(Math.hypot(y, x))) | 0), (Math.imul(( ~ ( - x)), ( - Number.MIN_SAFE_INTEGER)) | 0))); }); testMathyFunction(mathy2, [-(2**53), -(2**53+2), 0x07fffffff, 2**53, Number.MAX_VALUE, 0x100000001, 1/0, -1/0, -0x07fffffff, 0x080000000, -0x100000001, -Number.MAX_VALUE, -0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1, 42, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x0ffffffff, -(2**53-2), -0x080000001, 0x0ffffffff, 0/0, 2**53-2, -Number.MIN_VALUE, 0, -0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-8783892*/count=1883; tryItOut("\"use strict\"; \"use strict\"; e0 + '';");
/*fuzzSeed-8783892*/count=1884; tryItOut("\"use strict\"; e1.delete(m1);");
/*fuzzSeed-8783892*/count=1885; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.min(((( + y) && ( + ( + Math.sinh((x >>> 0))))) >>> 0), Math.fround((Math.fround(Math.fround(Math.fround(y))) ? Math.fround((((y | 0) === ( + (( + Math.hypot((-(2**53) - Number.MIN_VALUE), x)) !== Math.fround(Math.hypot(Math.fround(x), Math.fround(Math.exp(-Number.MIN_VALUE))))))) | 0)) : Math.fround((x == x))))) & Math.fround(Math.ceil(( ~ Math.trunc(((( ~ x) | 0) - Math.fround(( + Math.fround(0x100000000))))))))); }); testMathyFunction(mathy0, /*MARR*/[true, -(2**53), true, -(2**53), true,  /x/ ,  \"use strict\" ]); ");
/*fuzzSeed-8783892*/count=1886; tryItOut("/*MXX1*/o1 = g0.Date.prototype.toUTCString;");
/*fuzzSeed-8783892*/count=1887; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x07fffffff, -0x0ffffffff, 42, -0, 2**53+2, -0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 0, -0x07fffffff, -(2**53-2), -0x100000001, 1/0, 0x080000000, -1/0, 2**53, -0x100000000, 2**53-2, -Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, 0/0, 0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE, 1, -0x080000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-8783892*/count=1888; tryItOut("print(new function () { yield /*UUV2*/(x.valueOf = x.toGMTString) } ());");
/*fuzzSeed-8783892*/count=1897; tryItOut("print(x);\ns0.toString = (function() { for (var j=0;j<42;++j) { f2(j%2==1); } });\n");
/*fuzzSeed-8783892*/count=1898; tryItOut("\"use strict\"; {m0.has(a2);for (var v of v0) { try { m0.toString = (function mcc_() { var iihjce = 0; return function() { ++iihjce; if (/*ICCD*/iihjce % 4 == 0) { dumpln('hit!'); try { ; } catch(e0) { } try { e0.has(t1); } catch(e1) { } a1 = g1.a1.map((function() { h2 = {}; return h2; }), o2.i0, b1, this); } else { dumpln('miss!'); try { this.v1 = a0.length; } catch(e0) { } /*MXX2*/g0.URIError.prototype.name = f2; } };})(); } catch(e0) { } try { m0.get(g2.g1); } catch(e1) { } this.v0 = Object.prototype.isPrototypeOf.call(v1, h1); } }");
/*fuzzSeed-8783892*/count=1899; tryItOut("let (c) { Number(); }");
/*fuzzSeed-8783892*/count=1900; tryItOut("/*iii*/i1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (-((d1)));\n    return +((d0));\n  }\n  return f; });/*hhh*/function nxgouq(NaN = this){(function(x, y) { return y; })\nprint(x);\n}");
/*fuzzSeed-8783892*/count=1901; tryItOut("v2 = Object.prototype.isPrototypeOf.call(s1, p0);");
/*fuzzSeed-8783892*/count=1902; tryItOut("v1 = Object.prototype.isPrototypeOf.call(this.e0, b1);");
/*fuzzSeed-8783892*/count=1903; tryItOut("b0 = new SharedArrayBuffer(20);");
/*fuzzSeed-8783892*/count=1904; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-8783892*/count=1913; tryItOut("\"use strict\"; youqbp(encodeURI.prototype);/*hhh*/function youqbp(x, d, d, c, b, setter = undefined, x, window, a, x, x = b, w, this.x, w, a, x, c, x, x, b = d, x = \"\\u5A82\", x, NaN, e, x = /\\d/ym, e, x, w = new RegExp(\"\\\\3{3}\", \"gyim\")){(void schedulegc(g0));}");
/*fuzzSeed-8783892*/count=1914; tryItOut("print(uneval(h2));");
/*fuzzSeed-8783892*/count=1915; tryItOut("mathy3 = (function(x, y) { return (( - (((Math.asin((( ~ y) | 0)) >>> 0) < Math.hypot((Math.max(( + mathy0(Math.pow(( + y), x), (y * (x | 0)))), ( + x)) >>> 0), (( ~ Math.pow(( + ( + Math.trunc(( + (mathy1((1/0 >>> 0), y) >>> 0))))), -1/0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, 0x100000000, Math.PI, -1/0, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -0x080000001, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -0, -(2**53+2), 1, -0x100000000, -Number.MAX_VALUE, 0x080000000, 0.000000000000001, -0x0ffffffff, 42, 2**53+2, 1/0, 2**53, -(2**53-2)]); ");
/*fuzzSeed-8783892*/count=1916; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var sqrt = stdlib.Math.sqrt;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -262143.0;\n    (Int16ArrayView[((((0x98a38666)-((0x137c942c) != (0x2c10243a))) ^ (((0xf982d82c) ? (0xffffffff) : (0xe02583d8))+((0x41a3ab9)))) / (((x)*-0x61a0b) & ((0x67f2a8f4) % (0x65044cd1)))) >> 1]) = ((((((Int8ArrayView[((/*FFI*/ff()|0)+(0x7840daf)) >> 0]))) ^ ((0xf897e67f))) >= (abs((~~(-((d1)))))|0))+(0xffbedfed)+(0x81d979a2));\n-25;    d1 = (d0);\n    {\n      d2 = (((Float32ArrayView[1])) - ((+(0.0/0.0))));\n    }\n    d0 = (d2);\n    {\n      d1 = (+(0x287ed9d1));\n    }\n    d2 = (+abs(((1.0625))));\n    switch ((((/*FFI*/ff(((((Infinity))|0)), ((((0x9351c22f)) | ((-0x8000000)))), ((-1.0625)), ((-1.03125)), ((-1.1805916207174113e+21)), ((-513.0)))|0))|0)) {\n    }\n    return ((((((~((0x8cddf75a))) > (imul((0xfef4f307), ((((-0x8000000))>>>((0x27fb1650)))))|0))) ^ (-(/*FFI*/ff()|0))) % (~~(+sqrt(((+pow(((Float32ArrayView[1])), ((NaN))))))))))|0;\n  }\n  return f; })(this, {ff: new /(?=^)[^][^]^*?|(?=$\\S*)(\\cI){3}\\t\\1/gim( '' , undefined)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[x, -Number.MIN_VALUE, -Number.MIN_VALUE, {}, x, true, -Number.MIN_VALUE, -Number.MIN_VALUE, x, x, x, true, x, {}, true, -Number.MIN_VALUE, true, {}, -Number.MIN_VALUE, -Number.MIN_VALUE, {}]); ");
/*fuzzSeed-8783892*/count=1917; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"$\", \"yim\"); var s = \"L\"; print(r.test(s)); ");
/*fuzzSeed-8783892*/count=1918; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2(Math.fround(Math.fround((Math.fround(Math.imul(( + Math.max(( + Math.cbrt(-(2**53+2))), ( + ( + mathy2(( + ( + y)), (x >>> 0)))))), ( + Math.clz32((-(2**53+2) ? ( + x) : ( ~ y)))))) ** (-0x080000000 >= x)))), Math.fround(Math.atanh(mathy4(((2**53 < 0) >>> 0), (mathy3(Math.fround(( ~ mathy3(x, x))), Math.fround((Math.max((x >>> 0), Math.fround(mathy3(( + y), y))) >>> 0))) >>> 0)))))); }); testMathyFunction(mathy5, [-0x100000000, -0x07fffffff, 1, -0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), 0, 42, -0x100000001, 0.000000000000001, 0x07fffffff, 0x080000001, 0x0ffffffff, -0x080000000, 0x100000001, 1.7976931348623157e308, 0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, 0/0, 1/0, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, Math.PI, -0, -Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-8783892*/count=1919; tryItOut("this.v2 = t1.byteOffset;");
/*fuzzSeed-8783892*/count=1920; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(\\\\2(\\\\1|((?:\\\\u007F))?){2097151,}([]))\", \"g\"); var s = \"\\n\\n\\u00f0\"; print(s.replace(r, (undefined), \"m\")); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
