

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
/*fuzzSeed-159544250*/count=1; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.imul(Math.atan2((( + mathy2(( + Math.asin(( + y))), (Math.fround(Math.round(Math.fround(-Number.MAX_VALUE))) >>> 0))) !== ((( ! 0x0ffffffff) ? x : Math.imul(x, mathy0(y, -(2**53-2)))) >>> 0)), ( ! Number.MAX_SAFE_INTEGER)), ( + mathy0(Math.hypot((mathy0(Math.fround(( ~ y)), Math.fround(y)) | 0), (Math.max((y | 0), (x | 0)) | 0)), (Math.hypot(Math.fround(Math.max(Math.max(y, Math.ceil(x)), Math.fround(x))), Math.imul(x, ( ~ (x >>> 0)))) >>> 0)))); }); testMathyFunction(mathy5, [42, -0x080000001, -0x07fffffff, 2**53-2, -(2**53-2), 0/0, -0x0ffffffff, -0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, -0, Number.MAX_VALUE, 2**53, -1/0, 0.000000000000001, 2**53+2, 0, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), 0x080000001, 0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=2; tryItOut("/*infloop*/for(x; var rrsotu = new SharedArrayBuffer(16); var rrsotu_0 = new Int8Array(rrsotu); var rrsotu_1 = new Uint8Array(rrsotu); print(rrsotu_1[0]); rrsotu_1[0] = \"\\uBC62\"; var rrsotu_2 = new Int8Array(rrsotu); print(rrsotu_2[0]); v0 = a2.length;v1 = (e0 instanceof m0);-7;\n; ((void options('strict'))) <= x) switch(let (w = z) \"\\u5D8D\") { default: break; case 0: v2 = evalcx(\"function f2(t2)  { return window } \", this.g1);break; case 7: this.s1 = g2.objectEmulatingUndefined();s2 = '';break;  }");
/*fuzzSeed-159544250*/count=3; tryItOut("xezdae((p={}, (p.z = (Math.min(28, -21)))()), x);/*hhh*/function xezdae(\u3056 = Math.pow(8, arguments.__defineSetter__(\"w\", true))){f0 = Proxy.createFunction(h1, f2, f0);}");
/*fuzzSeed-159544250*/count=4; tryItOut("\"use strict\"; this.zzz.zzz;yield x > x;");
/*fuzzSeed-159544250*/count=5; tryItOut("for(var b in x) /*tLoop*/for (let y of /*MARR*/[ \"\" , 1e81,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new Boolean(true), function(){}, new Boolean(true), new Boolean(true), 1e81, 1e81, function(){},  \"\" , 1e81, Math.PI, function(){}, new Boolean(true), Math.PI, function(){},  \"\" , 1e81, 1e81, function(){}, function(){},  \"\" , function(){},  \"\" , function(){}, new Boolean(true), Math.PI, function(){}, function(){}, function(){}, function(){},  \"\" , Math.PI, function(){},  \"\" ,  \"\" , function(){}, Math.PI, 1e81, 1e81, new Boolean(true), 1e81, 1e81, function(){}, function(){},  \"\" , Math.PI, 1e81,  \"\" , function(){},  \"\" , function(){}, new Boolean(true), new Boolean(true),  \"\" , new Boolean(true), function(){}, new Boolean(true), new Boolean(true), Math.PI,  \"\" ,  \"\" , new Boolean(true), Math.PI, new Boolean(true), 1e81, function(){},  \"\" , 1e81, 1e81, function(){}, Math.PI, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), Math.PI, Math.PI, new Boolean(true), function(){}, Math.PI, Math.PI,  \"\" ,  \"\" , new Boolean(true),  \"\" , function(){}, function(){}, function(){},  \"\" , Math.PI, Math.PI,  \"\" , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  \"\" , Math.PI,  \"\" , Math.PI, 1e81]) { x = e0; }");
/*fuzzSeed-159544250*/count=6; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.acosh(Math.imul(mathy3(y, ( + Math.fround(Math.ceil(Math.fround(x))))), mathy3((Math.min((x >>> 0), (x >>> 0)) >>> 0), Math.log1p(-1/0)))); }); ");
/*fuzzSeed-159544250*/count=7; tryItOut("mathy0 = (function(x, y) { return Math.exp(Math.fround(Math.log(( + x)))); }); ");
/*fuzzSeed-159544250*/count=8; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:((?=\\\\b))+?)\", \"gim\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=9; tryItOut("mathy0 = (function(x, y) { return (Math.min((( + Math.clz32(( + Math.hypot(y, x)))) | 0), ( ~ ( + Math.max((((((Math.fround((x | 0)) | 0) && x) >>> 0) ** (y >>> 0)) >>> 0), ( + (( ~ ((Math.sin(y) ? 0x100000000 : y) | 0)) | 0)))))) | 0); }); testMathyFunction(mathy0, [-0x07fffffff, -Number.MAX_VALUE, 1, 0x100000000, 2**53-2, -0x100000001, 0/0, -0x080000000, 0x0ffffffff, 0x07fffffff, -0, -(2**53), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, -(2**53-2), 0.000000000000001, Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 42, 1/0, 0, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), 2**53, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-159544250*/count=10; tryItOut("\"use strict\"; var byrmja = new SharedArrayBuffer(4); var byrmja_0 = new Uint32Array(byrmja); byrmja_0[0] = 17; o0.s0 += 'x';eval = linkedList(eval, 2257);");
/*fuzzSeed-159544250*/count=11; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((((i1))>>>((((~~(-2305843009213694000.0))) ? (/*FFI*/ff()|0) : (/*FFI*/ff()|0))*0x17269)));\n    i1 = ((i0));\n    (Float32ArrayView[4096]) = ((+(-1.0/0.0)));\n    i0 = ((((i1)-(i1))>>>((((i1)) << (((0x649b0ee8))-((2147483649.0) != (65.0))-((0x6ad6bc2e)))) % (~~(((Float64ArrayView[((0xffffffff)) >> 3])) % ((Float32ArrayView[2])))))));\n    i1 = ((0x364b1b21) <= (0xb607121d));\n    i0 = ((4277));\n    return ((((~~(-1.9342813113834067e+25)))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000001, -(2**53), 0, -(2**53-2), 0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, Number.MIN_VALUE, -1/0, 2**53+2, 0x080000001, 0x080000000, -0x080000001, 0x100000000, 0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), 2**53-2, 0x07fffffff, 0.000000000000001, 42, -0x100000000, -0x0ffffffff, 1/0, -0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -0]); ");
/*fuzzSeed-159544250*/count=12; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.expm1((((Math.atan2(Math.hypot(-(2**53-2), x), (x >>> 0)) - mathy3(Math.fround(Math.min(x, (Math.min((x >>> 0), (y >>> 0)) >>> 0))), Math.pow(( + x), Math.pow((y | 0), (x | 0))))) >>> 0) & ( + (Math.fround(Math.atanh(Math.fround(Math.PI))) % (x >>> 0)))))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -(2**53), -(2**53-2), -Number.MAX_VALUE, 0x080000000, 0.000000000000001, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, 0x07fffffff, -0x080000000, 42, 2**53-2, -(2**53+2), 0x100000001, Number.MIN_VALUE, -0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_VALUE, 2**53, 1, -0x080000001, -0, 0x100000000, -0x07fffffff, Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, -1/0, Math.PI]); ");
/*fuzzSeed-159544250*/count=13; tryItOut("/*MXX2*/g1.String.prototype.valueOf = p2;function x() { \"use strict\"; v2 = (g2.b0 instanceof o1); } \u000cg2.offThreadCompileScript(\"function f1(g0.m2) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var d3 = -17179869185.0;\\n    {\\n      {\\n        {\\n          d3 = (+abs(((536870912.0))));\\n        }\\n      }\\n    }\\n    i0 = (i2);\\n    return +((((((1.0)) - ((( ! Math.hypot(( + -0x100000000), x)))))) % ((+((+(1.0/0.0)))))));\\n  }\\n  return f;\");");
/*fuzzSeed-159544250*/count=14; tryItOut("testMathyFunction(mathy2, [-(2**53+2), -(2**53), Number.MIN_VALUE, -0x0ffffffff, -0x080000000, 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0, 0/0, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, -0x100000001, -0, 42, 0x100000000, 0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, Math.PI, 0.000000000000001, 0x080000000, 1/0, -0x100000000, 2**53, -(2**53-2), 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=15; tryItOut("\"use strict\"; m1.set(f1, o2.o1);const x = this;");
/*fuzzSeed-159544250*/count=16; tryItOut("\"use strict\"; M:for(w in timeout(1800)) a0.push(p0, i2, s2, t1, g0.t2);");
/*fuzzSeed-159544250*/count=17; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - Math.fround(mathy0(Math.imul((( - Math.log2(0x0ffffffff)) | 0), mathy0(2**53-2, Math.atan2((x >>> 0), (y >>> 0)))), Math.log2(Math.cosh(-(2**53-2)))))) ? ( + (( + Math.fround(( ~ Math.fround((x <= (Math.max(Number.MAX_VALUE, x) >>> 0)))))) * (Math.min((Math.tan(( + (mathy0((-0x080000000 ? x : y), ( ~ Math.atan2(x, x))) | 0))) | 0), (0x080000001 | 0)) >>> 0))) : (( ~ (( - ( + ( + y))) | 0)) | 0)); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 1, Number.MIN_VALUE, -0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -0, -(2**53-2), 0.000000000000001, -(2**53), 0x080000000, 2**53-2, 2**53, -0x0ffffffff, -0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, 1/0, -1/0, 42, 0x100000001, 0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, 2**53+2, 0x100000000]); ");
/*fuzzSeed-159544250*/count=18; tryItOut("/*RXUB*/var r = /(?=[]{2,4})/m; var s = \"\\u000d\\u000d\\u000d\\u000d\\u000d\\u000d\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=19; tryItOut("");
/*fuzzSeed-159544250*/count=20; tryItOut("b0 = new SharedArrayBuffer(64);");
/*fuzzSeed-159544250*/count=21; tryItOut("let (a) { for (var v of p0) { try { o2.a2 = g1.g1.a1.map((function() { try { for (var p in m2) { try { f0 = Proxy.createFunction(h0, f0, this.g2.f1); } catch(e0) { } try { print(p2); } catch(e1) { } try { o0.i2 = new Iterator(this.t1); } catch(e2) { } e1.has(v2); } } catch(e0) { } try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = newGlobal({ cloneSingletons: (a % 3 != 0), disableLazyParsing: this }); f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = fillShellSandbox(evalcx('')); f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e1) { } this.h1 + ''; return v0; })); } catch(e0) { } try { /*MXX2*/g2.Date.prototype.getUTCMonth = this.f0; } catch(e1) { } /*MXX3*/g2.Math.log1p = g0.Math.log1p; } }");
/*fuzzSeed-159544250*/count=22; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.round(Math.fround(Math.cbrt(( + Math.fround((x - -0x07fffffff))))))); }); ");
/*fuzzSeed-159544250*/count=23; tryItOut("\"use strict\"; Array.prototype.forEach.call(a2, f1, v2);");
/*fuzzSeed-159544250*/count=24; tryItOut("mathy1 = (function(x, y) { return Math.pow(mathy0(mathy0(Math.hypot(0x080000000, x), mathy0(y, Math.fround((mathy0(x, (Math.atan2((x | 0), y) | 0)) ^ Math.trunc(( + y)))))), Math.acos(Math.sin(x))), Math.fround(( + ( ! Math.log2(( + Math.fround(Math.pow((x ? x : y), Math.tan(0x100000001))))))))); }); testMathyFunction(mathy1, /*MARR*/[new String(''), new String(''), NaN, NaN, new String(''), new String('')]); ");
/*fuzzSeed-159544250*/count=25; tryItOut("\"use asm\"; Array.prototype.splice.call(a0, 1, ({valueOf: function() { /*RXUB*/var r = new RegExp(\"(?!\\\\1\\\\B)+?|(?=(?![\\uc138\\\\u001b\\\\w\\\\t-\\\\r]){3,16386}){1}^?.{3,}\\\\\\udc31[^]{3}|\\\\2\\\\3{3}\\u00bb|\\\\d\\\\b|\\\\uF1bC{2}{1}?\", \"im\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); return 16; }}), h0);");
/*fuzzSeed-159544250*/count=26; tryItOut(";");
/*fuzzSeed-159544250*/count=27; tryItOut("this.i0.send(m1);");
/*fuzzSeed-159544250*/count=28; tryItOut("\"use strict\"; var xxtmtg = new ArrayBuffer(0); var xxtmtg_0 = new Uint32Array(xxtmtg); print(xxtmtg_0[0]); for (var v of a1) { try { /*ODP-1*/Object.defineProperty(o1.p1, \"1\", ({configurable: (xxtmtg_0[0] % 29 == 16), enumerable: (xxtmtg_0[5] % 5 != 0)})); } catch(e0) { } m2.toSource = runOffThreadScript; }");
/*fuzzSeed-159544250*/count=29; tryItOut("/*bLoop*/for (jecaig = 0; jecaig < 31; ++jecaig) { if (jecaig % 6 == 2) { {} } else { v1 = Object.prototype.isPrototypeOf.call(g2, i2); }  } ");
/*fuzzSeed-159544250*/count=30; tryItOut("\"use strict\"; testMathyFunction(mathy3, [true, '/0/', objectEmulatingUndefined(), undefined, [], ({valueOf:function(){return '0';}}), 1, false, ({valueOf:function(){return 0;}}), NaN, [0], ({toString:function(){return '0';}}), '0', (new Boolean(false)), (new Number(0)), (new Boolean(true)), 0.1, '\\0', -0, (new Number(-0)), null, (function(){return 0;}), /0/, 0, '', (new String(''))]); ");
/*fuzzSeed-159544250*/count=31; tryItOut("/*ODP-1*/Object.defineProperty(v0, \"caller\", ({writable: false, configurable: true}));");
/*fuzzSeed-159544250*/count=32; tryItOut("mathy2 = (function(x, y) { return Math.fround((( + Math.imul(Math.cos(-0x100000001), (Math.trunc(mathy0((-Number.MIN_VALUE >>> 0), (( + Math.hypot(Number.MAX_SAFE_INTEGER, y)) >>> 0))) >>> 0))) % Math.fround((Math.hypot(((Math.abs(( + y)) | 0) >>> 0), Math.fround((( + (Math.log2(Math.clz32((x * -(2**53+2)))) | 0)) | 0))) >>> 0)))); }); ");
/*fuzzSeed-159544250*/count=33; tryItOut("a2 = r0.exec(g1.s1);");
/*fuzzSeed-159544250*/count=34; tryItOut("\"use strict\"; /*iii*//*ODP-1*/Object.defineProperty(s2, 12, ({get: ({apply: new RegExp(\"\\\\1\", \"gim\") }).getOwnPropertySymbols, set: /*wrap2*/(function(){ \"use strict\"; var mdnxlp = ({ get x()\"use asm\";   var acos = stdlib.Math.acos;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (!((-1.2089258196146292e+24) != (262145.0)));\n    i0 = ((i0) ? (i1) : (!(i1)));\n    i0 = (i0);\n    i0 = (!(i0));\n    i1 = (1);\n    i1 = (0xf941176f);\nprint(x);    {\n      return +((+acos(((Float64ArrayView[(((((0x27c6e54d))-(i1)+(i1))>>>(((0xffffffff) == (0x0))+((0x16fd16c8) < (0x68c483ba))+(i1))) % (((((0xf81dd591))>>>((0xcb08f2c7))) / (((0xfbb257fa))>>>((0xfe8ba5b9))))>>>((\"\\u5C16\")+((0x361f2828))+(i1)))) >> 3])))));\n    }\n    return +((1125899906842623.0));\n  }\n  return f; }) **= ((window)(y) = xtkxbi); var kolnpr = ((URIError).call( /x/ , )); return kolnpr;})(), enumerable: true}));/*hhh*/function xtkxbi(c = new (decodeURIComponent)(\"\\uBB8F\", (makeFinalizeObserver('nursery'))), y =  /x/g , x, x = (length(\"\\u2B81\").unwatch(\"toString\")), NaN, x, b, x, b, w, e, b, c, y, x, NaN, z, z, \u3056, \u3056 = x, w, x, a, d = undefined, y, x, x, a, w, x, x, x, x, c, a, w = window, \u3056, c, x, eval, x, NaN, a = window, x = /(?!(?!(?=\\B\\d|[^])|(?:(?:[^\\cD\\n-\\cX\\W\\u00f4-\u4566])?))|\\b|(?!(?:.))*?+)/gm, x, get, y, x, a, x, b = length, x, NaN, y = undefined, NaN, z, window = /(?:(?=\u00fd|\\w[^\\0]{0,3})(?!\\D{3})+*)/gm, NaN = window, x, NaN, x, x, eval, x, z, d = -16, x, x, y, y, x = d, x = \"\\uF9B0\", w, a, y, \u3056, d, eval, a, a, w){/*vLoop*/for (var onhbgs = 0; onhbgs < 15; ++onhbgs) { const e = onhbgs; (x); } }");
/*fuzzSeed-159544250*/count=35; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((Math.sign((Math.fround(Math.hypot(Math.fround(Math.fround(mathy0(( ! Math.fround(((y & ( + Math.abs(y))) >>> 0))), ( + ((( + y) >= ( + ( + 2**53+2))) | 0))))), Math.fround(y))) | 0)) | 0) == (Math.sqrt(((((x >>> 0) ? (mathy0(((Math.imul(Math.fround(y), (x | 0)) | 0) >>> 0), (y >>> 0)) >>> 0) : ((Math.fround((( + Math.cosh(( + x))) + ( + Math.pow(y, x)))) & ( + (( + 2**53+2) && ( + x)))) | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, -0x0ffffffff, 42, Number.MAX_VALUE, -0x07fffffff, -Number.MAX_VALUE, -0x100000001, 2**53-2, -0x100000000, -Number.MIN_VALUE, 0/0, -(2**53+2), Math.PI, -(2**53-2), -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), -0, 0x080000000, 0x100000001, 0x100000000, 0, 2**53, -0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-159544250*/count=36; tryItOut("mathy5 = (function(x, y) { return ( - Math.fround(Math.asin(Math.fround(( + (( + Math.hypot(( + ( + ( - Math.imul(y, y)))), ( + ( ! ( + ( - (y >>> 0))))))) ? ( + Math.min(x, ((Math.asin((y | 0)) >>> 0) | 0))) : ( + Math.fround(((Math.fround(Math.min(( + (((( + Math.pow(( + x), ( + 0x0ffffffff))) | 0) ? (-0x07fffffff | 0) : (x | 0)) | 0)), Number.MAX_SAFE_INTEGER)) >>> 0) , ( + Math.tan(Math.fround((x ? x : x))))))))))))); }); testMathyFunction(mathy5, [1, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, 0, 1/0, -0x100000001, -(2**53), 0x100000001, -0x07fffffff, 0/0, -Number.MIN_VALUE, -0x080000000, 0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -1/0, 0x080000000, -0x0ffffffff, Math.PI, 2**53, -0, -0x100000000, 42, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, -(2**53-2), 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=37; tryItOut("\"use strict\"; \"use asm\"; /*infloop*/ for (var (w) of delete x.x) /*iii*/s0 + m2;/*hhh*/function gfycbg(d, x, {}, e = y = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), function(y) { a2 = new Array; }, function(y) { \"use strict\"; o0 = new Object; }), a, eval, get =  /x/g , e, b, d, \u3056, x = x, NaN =  \"\" , b, get, c, \"\\uAD3E\", x, y, y, window, \u3056 = \"\\u9B63\", a, eval, NaN, NaN, x, eval, window =  /x/g , x =  /x/g , a = \"\\u3059\", x, yield, x, b, x, x, x, y = true, x){g2.v0 = evaluate(\"/*ODP-1*/Object.defineProperty(a2, \\\"__count__\\\", ({configurable: (x % 6 == 4)}));\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: w, noScriptRval: true, sourceIsLazy: false, catchTermination: y }));}");
/*fuzzSeed-159544250*/count=38; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.tanh(Math.fround(((Math.fround(( + Math.fround(Math.tan(Math.hypot((y | 0), ( + ((y | 0) / Math.cosh(y)))))))) | 0) >>> (( - Math.fround(Math.sign(Math.fround(Math.fround(Math.expm1((( + x) | 0))))))) >>> 0))))); }); ");
/*fuzzSeed-159544250*/count=39; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy4((mathy2(Math.hypot(Math.cosh(mathy2((x | 0), Math.acosh(y))), (Math.log2((( + Math.tan(1.7976931348623157e308)) >>> 0)) >>> 0)), Math.acos(((( - (x >>> 0)) >>> 0) >>> 0))) >>> 0), Math.max((( - ( + ((( + Math.min(( + mathy0(( + Number.MAX_SAFE_INTEGER), y)), (y | 0))) - mathy3(y, (Math.atan(( + y)) << -(2**53-2)))) | 0))) >>> 0), Math.fround(Math.max(mathy4(y, ( + Math.min(0/0, x))), ( + mathy4(( + y), ( + 0x100000000))))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 42, 0/0, -1/0, -0x080000000, -(2**53+2), -0x07fffffff, 0x080000001, 1.7976931348623157e308, 0x100000000, -(2**53), -(2**53-2), -Number.MIN_VALUE, Math.PI, 0x0ffffffff, 0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, -0, 2**53+2, 1, 0x080000000, 2**53, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -0x080000001, 2**53-2, -Number.MAX_VALUE, Number.MIN_VALUE, 1/0, 0]); ");
/*fuzzSeed-159544250*/count=40; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((( + mathy0(( + (Math.max((((Math.fround((Math.fround(x) - Math.fround(x))) >>> 0) ^ (x >>> 0)) >>> 0), (Math.asinh((mathy0(Math.tanh(Math.fround(x)), (y >> ( + Math.pow(( + x), -0x080000000)))) | 0)) | 0)) | 0)), ( + (( + Math.sqrt((x >> (((-0x080000001 | 0) || (x | 0)) | 0)))) >> ( + Math.clz32(Math.fround(x))))))) ? (((( + (( + mathy1(Math.fround(y), (Math.log1p((Math.fround((Math.fround(-(2**53)) >>> Math.fround(x))) >>> 0)) | 0))) < (Math.sinh((( - x) | 0)) | 0))) / ((( ! (y >>> 0)) >>> 0) | 0)) | 0) | 0) : ((mathy3((Math.fround(mathy0(Math.fround((Math.min((Math.fround(y) >>> 0), x) >>> 0)), Math.fround((Math.clz32(Math.hypot(( + y), y)) >>> 0)))) % Math.fround(( ! x))), ((( + x) % (((Number.MAX_VALUE | 0) ? (mathy2(y, -Number.MAX_VALUE) | 0) : Math.fround(Math.cbrt(Math.fround(x)))) | 0)) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy4, [Math.PI, -1/0, Number.MAX_VALUE, 2**53, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 42, 0x080000000, 2**53+2, 0x07fffffff, 0.000000000000001, -0x080000000, -Number.MIN_VALUE, 2**53-2, 0x100000000, -Number.MIN_SAFE_INTEGER, 0, 1, -(2**53), -Number.MAX_VALUE, -0x0ffffffff, -0x100000001, 0x0ffffffff, -0, -0x07fffffff, 0/0, -0x080000001, -(2**53+2), -0x100000000, 0x080000001, 1/0, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=41; tryItOut("mathy1 = (function(x, y) { return ( + ( + Math.sign(( + ((((((Number.MAX_SAFE_INTEGER === Math.fround(Math.hypot(Math.fround(0x0ffffffff), Math.fround(x)))) >= (Math.min(( ! Math.log(x)), 0x080000000) | 0)) >>> 0) >>> 0) !== (( ~ x) >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, -0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000000, 0, Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, -(2**53), 0x0ffffffff, 2**53+2, -0x100000001, 0x100000000, Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, -(2**53+2), -Number.MIN_VALUE, 1, 0x080000001, -0x0ffffffff, -0x07fffffff, 2**53, 0x100000001, 1/0, 42, -Number.MAX_VALUE, Math.PI, -0]); ");
/*fuzzSeed-159544250*/count=42; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 562949953421313.0;\n    var d3 = 4.722366482869645e+21;\n    var i4 = 0;\n    var i5 = 0;\n    var d6 = -262145.0;\n    d2 = (+(((0xffffffff)+(/*FFI*/ff(((d6)))|0)-((((Uint16ArrayView[0]))>>>((0xfc253c32)-(0xfc315273))) == ((-0x6e361*(0xfdc9d013))>>>(-0x67cac*(-0x8000000)))))>>>(((i4) ? (/*FFI*/ff(((+exp(((-4096.0))))), ((549755813889.0)))|0) : ((((0xf8f9d13d))>>>((0xfb3ce1b9)))))+(i1)+(0x46a75d71))));\n    d3 = ((((+(0x6f3c303a))) * ((-((Float64ArrayView[4096]))))) + (d2));\n    return (((i1)+(0x6b4cf653)-(this.__defineGetter__(\"e\", \u3056).__defineGetter__(\"NaN\", /*RXUE*/new RegExp(\"(?:([^][^]))|((?=(?!\\\\xFc[^])|[\\\\t-\\\\u00e2\\\\w\\\\w\\\\f])){0}\", \"gy\").exec(\"\\u00fc\\n\")))))|0;\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[[,,], x, x, [,,], x, x, x, x, x, x, [,,], [,,], x, [,,], [,,], [,,], x, [,,], x, [,,], x, [,,], [,,]]); ");
/*fuzzSeed-159544250*/count=43; tryItOut("\"use strict\"; ((p={}, (p.z = false)()));\nprint(x);\n");
/*fuzzSeed-159544250*/count=44; tryItOut("mathy4 = (function(x, y) { return ( ~ (Math.sqrt((((Math.fround((y || -0x100000000)) & (mathy2(Math.fround(Math.abs(x)), Math.fround(Math.abs(Math.fround(x)))) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-0x0ffffffff, 0x080000000, 0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, 1, -0x100000000, 1/0, Number.MAX_SAFE_INTEGER, 42, -0, -0x100000001, -(2**53+2), -Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, 0x080000001, -Number.MIN_VALUE, 2**53-2, Math.PI, -0x080000001, -(2**53-2), 2**53, 0, -(2**53), Number.MAX_VALUE, -0x07fffffff, 0x100000001, 0x100000000, -0x080000000, 2**53+2, 0/0, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=45; tryItOut("\"use strict\"; this.t1 + g0.g1;");
/*fuzzSeed-159544250*/count=46; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ~ Math.fround(mathy1(Math.fround((( + y) !== y)), (Math.tan((( + (((Math.hypot((y | 0), (( + Math.min((( + Math.tanh(x)) >>> 0), ( + ( ! Math.fround(-(2**53+2)))))) | 0)) | 0) | 0) === (0x100000000 == ( + Math.log2(Number.MIN_VALUE))))) | 0)) | 0)))) | 0); }); testMathyFunction(mathy2, [-0x100000001, -0, 1, 1/0, -(2**53+2), Number.MIN_VALUE, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, -0x100000000, 0x080000001, Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, 0/0, -0x0ffffffff, 0x080000000, 0x0ffffffff, Math.PI, 42, -(2**53-2), -0x080000000, -(2**53)]); ");
/*fuzzSeed-159544250*/count=47; tryItOut("\"use strict\"; a0 = arguments.callee.caller.caller.arguments;\nprint((neuter).call(x, (new (String.prototype.padStart)(x, x)),  '' ));\nr1 = /[\\w\\cX-\u00b6]/ym;\n\n");
/*fuzzSeed-159544250*/count=48; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=49; tryItOut("testMathyFunction(mathy4, [(function(){return 0;}), false, '\\0', [0], '', ({valueOf:function(){return '0';}}), undefined, ({valueOf:function(){return 0;}}), '0', objectEmulatingUndefined(), 0.1, -0, (new Number(0)), (new String('')), (new Boolean(true)), (new Boolean(false)), true, [], 1, null, /0/, 0, '/0/', (new Number(-0)), NaN, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-159544250*/count=50; tryItOut("rkemub, bkhwzi, window, y, eval, y, b, z, z, a;print(0);");
/*fuzzSeed-159544250*/count=51; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=52; tryItOut("\"use strict\"; v1 = 4;");
/*fuzzSeed-159544250*/count=53; tryItOut("mathy5 = (function(x, y) { return (Math.fround((Math.fround((Math.fround(Math.max(Math.max(-0x080000001, Math.PI), Math.acos(x))) * Math.fround(Math.atanh(Math.fround(Number.MIN_VALUE))))) ** ( + Math.fround(Math.cbrt((Math.log(((( + (0x100000001 > x)) ? Math.pow(Math.sinh(y), (Math.max((y | 0), y) | 0)) : ( + (((0/0 | 0) < (y | 0)) | 0))) | 0)) | 0)))))) / ( ! ( - ( + mathy3(( + x), x))))); }); testMathyFunction(mathy5, [42, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, -(2**53-2), 0x0ffffffff, -0x0ffffffff, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -0x080000001, 1/0, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 0x100000001, -(2**53+2), 0x100000000, 0x080000000, 1.7976931348623157e308, 0x07fffffff, 2**53-2, 1, -0, -1/0, Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53, -0x100000001, -Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=54; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.log2(((( + mathy1(-Number.MIN_SAFE_INTEGER, (((( - y) >>> 0) < (y >>> 0)) >>> 0))) | 0) >> (Math.trunc((( - (x | 0)) >>> 0)) | 0)))); }); testMathyFunction(mathy2, [0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, -0x080000001, -1/0, Number.MAX_VALUE, 2**53, -0x100000001, 0, 0x080000001, -0, 1.7976931348623157e308, 42, 0x100000001, -0x100000000, 2**53-2, -0x0ffffffff, -0x07fffffff, 1/0, 0x080000000, 0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, -Number.MIN_VALUE, -0x080000000, 2**53+2, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=55; tryItOut("/*tLoop*/for (let z of /*MARR*/[function(){}, (1/0), [(void 0)], (1/0), [(void 0)], [(void 0)], (1/0), (1/0), [(void 0)], [], (1/0), function(){}, (-1/0), [(void 0)], (1/0), (1/0), [(void 0)], function(){}, (-1/0), function(){}, (-1/0), (1/0), [(void 0)], function(){}, (-1/0), (1/0), function(){}, [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], (-1/0), function(){}, [], [(void 0)], (-1/0), (-1/0), (1/0), (-1/0), (-1/0), (1/0), (-1/0), (-1/0), function(){}, function(){}, [(void 0)], [(void 0)], [], [], [], (1/0), [], (1/0), [], [], function(){}, (-1/0), [], [(void 0)], (1/0), (1/0), [], (-1/0), [], [], function(){}, [], function(){}, function(){}, (1/0), (-1/0), function(){}, (1/0), (-1/0), (-1/0), (1/0), [], function(){}]) { print(w); }");
/*fuzzSeed-159544250*/count=56; tryItOut("\"use strict\"; x;");
/*fuzzSeed-159544250*/count=57; tryItOut("a1.pop(s1);");
/*fuzzSeed-159544250*/count=58; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=59; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.atan2(Math.fround((Math.log((( - x) | 0)) >>> 0)), Math.fround(( + Math.atan2(Math.fround(-(2**53)), mathy2((y | 0), Math.fround(( ! (y | 0)))))))) >>> 0) ? (Math.hypot((Math.asin(y) >>> 0), Math.fround((Math.fround(mathy2((mathy1(Math.atan(-(2**53-2)), ( + ( - ( + x)))) | 0), x)) == ( + Math.tanh(Math.fround(( + Math.fround(x)))))))) >>> 0) : Math.sign(((Math.cos(x) << ((Math.fround(( - y)) ? (y ? -0x0ffffffff : (Math.hypot(x, x) >>> 0)) : (( ~ Math.fround(y)) >>> 0)) % -(2**53))) >>> 0))); }); testMathyFunction(mathy3, [0, -0x07fffffff, -(2**53+2), -0x100000001, -(2**53), 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, 0x100000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 42, 2**53-2, 1.7976931348623157e308, 0x080000001, -1/0, 1, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0, 1/0, Number.MIN_VALUE, 0/0, 0x100000001, -Number.MAX_VALUE, -0x080000001, Math.PI, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=60; tryItOut("t0 = new Int8Array(let (y) y);");
/*fuzzSeed-159544250*/count=61; tryItOut("\"use strict\"; ;");
/*fuzzSeed-159544250*/count=62; tryItOut("t1 = t2.subarray(16, v0);");
/*fuzzSeed-159544250*/count=63; tryItOut("for (var p in e2) { for (var p in p2) { try { for (var v of f2) { try { a2.forEach((function() { try { m2.get(h2); } catch(e0) { } try { h1.getPropertyDescriptor = f0; } catch(e1) { } try { m0.set(o0.v0, i1); } catch(e2) { } t2 = t1.subarray(7, 4); return this.m1; }), f1, o2); } catch(e0) { } try { h0.delete = f2; } catch(e1) { } g2.t0 = new Int32Array(-2 >=  /x/g  > (void shapeOf(e =  /x/ ))); } } catch(e0) { } this.m0.get(i1); } }");
/*fuzzSeed-159544250*/count=64; tryItOut("g1.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-159544250*/count=65; tryItOut("v0 = t0.length;");
/*fuzzSeed-159544250*/count=66; tryItOut("\"use strict\"; \"use asm\"; a0.splice(NaN, [[1]], v1);");
/*fuzzSeed-159544250*/count=67; tryItOut("/*RXUB*/var r = /(?=^)/gm; var s = \"\\u008e\\n\\n\\n\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=68; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-159544250*/count=69; tryItOut("\"use asm\"; testMathyFunction(mathy3, [[0], false, NaN, (new Number(0)), 1, '', null, ({valueOf:function(){return 0;}}), (new Boolean(true)), (function(){return 0;}), -0, '0', '/0/', [], 0, (new Number(-0)), (new String('')), /0/, objectEmulatingUndefined(), true, undefined, ({valueOf:function(){return '0';}}), (new Boolean(false)), ({toString:function(){return '0';}}), '\\0', 0.1]); ");
/*fuzzSeed-159544250*/count=70; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ! ( - ( - (( + mathy0(y, x)) * ((Math.atan2((Math.tan(1.7976931348623157e308) | 0), (Math.acosh(x) | 0)) | 0) > x))))); }); testMathyFunction(mathy1, [0.000000000000001, -0x07fffffff, 1, 1.7976931348623157e308, 2**53-2, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -0, 0/0, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, -Number.MIN_VALUE, 0, 42, Number.MAX_VALUE, -(2**53), -1/0, 2**53, 0x0ffffffff, Number.MIN_VALUE, 0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), -0x0ffffffff, -0x080000000, 0x080000001]); ");
/*fuzzSeed-159544250*/count=71; tryItOut("M:for(let x = (uneval((new WeakMap(\"\\u8631\", (void shapeOf(false)))))) in null) let v1 = t2.length;");
/*fuzzSeed-159544250*/count=72; tryItOut("for(let b in ((undefined)(eval(\"(x);\", /((?!\\D)$|(?=\\s)*)/ym)))){Object.preventExtensions(g0.o1.o0.o2); }");
/*fuzzSeed-159544250*/count=73; tryItOut("\"use strict\"; yield x;");
/*fuzzSeed-159544250*/count=74; tryItOut("\"use strict\"; L:for(var w in  '' ) {a1[7] = 9; }");
/*fuzzSeed-159544250*/count=75; tryItOut("\"use strict\"; i2.send(a0);");
/*fuzzSeed-159544250*/count=76; tryItOut("throw StopIteration;for(let c in /*MARR*/[null, new Number(1), new Number(1), null, null, new Number(1), null, null, null]) let(w) ((function(){let(e) ((function(){( \"\" );})());})());");
/*fuzzSeed-159544250*/count=77; tryItOut("o0.a0.forEach();");
/*fuzzSeed-159544250*/count=78; tryItOut("\"use strict\"; testMathyFunction(mathy3, [({toString:function(){return '0';}}), (new Number(0)), '', (new Boolean(false)), NaN, 0, 0.1, -0, 1, true, (function(){return 0;}), null, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), [], '0', /0/, '/0/', [0], (new Boolean(true)), (new String('')), undefined, '\\0', ({valueOf:function(){return 0;}}), (new Number(-0)), false]); ");
/*fuzzSeed-159544250*/count=79; tryItOut("/*ADP-1*/Object.defineProperty(a2, 18, ({}));");
/*fuzzSeed-159544250*/count=80; tryItOut("testMathyFunction(mathy0, [1.7976931348623157e308, -(2**53), -0x07fffffff, 1, 42, -0x100000000, -1/0, 0x080000001, 2**53-2, 0x07fffffff, 0x080000000, 0, 0x100000000, 2**53+2, -0x080000001, Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), -0x080000000, -0x100000001, -Number.MIN_VALUE, 0/0, Math.PI, 0x100000001, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=81; tryItOut("mathy1 = (function(x, y) { return ((Math.pow(Math.log(( ! ( + y))), Math.fround(Math.atan(x))) ^ (( - mathy0((Math.sinh(( + x)) >>> 0), ((Math.hypot((Number.MIN_SAFE_INTEGER | 0), (-Number.MAX_VALUE | 0)) | 0) ** Math.fround(Math.ceil(Math.fround(x)))))) | 0)) | 0); }); testMathyFunction(mathy1, [0x0ffffffff, 0, 42, 0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -0x07fffffff, -(2**53-2), 0x080000001, -0x080000001, 1/0, -0, 1, -0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, -Number.MAX_VALUE, -0x100000000, 2**53, Number.MAX_VALUE, 0x100000000, -(2**53+2), 0x100000001, Number.MIN_VALUE, 2**53+2, 0/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, -(2**53), 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=82; tryItOut("\"use strict\"; Array.prototype.splice.apply(a2, [NaN, 17]);");
/*fuzzSeed-159544250*/count=83; tryItOut("t0 + '';");
/*fuzzSeed-159544250*/count=84; tryItOut("s0 = new String;");
/*fuzzSeed-159544250*/count=85; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.pow(Math.fround(( ! ( - ((x * Math.fround(( ! (mathy0((y >>> 0), (-0x0ffffffff >>> 0)) >>> 0)))) >>> 0)))), Math.trunc(( + ( + (1/0 ? x : y))))); }); testMathyFunction(mathy1, [-1/0, 0x080000001, -0, Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -0x07fffffff, -0x080000001, 0, 0x080000000, -Number.MIN_VALUE, -(2**53), 0x100000001, 0.000000000000001, 1/0, 0x0ffffffff, -(2**53-2), -0x100000000, 1, 42, -0x080000000, 2**53, 0/0, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 2**53-2, Number.MAX_VALUE, 0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=86; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.cosh((mathy1(Math.fround(mathy2(Math.fround(((Math.atanh(( + (( ~ x) >>> 0))) | 0) != ( + Math.atan2(Math.fround(x), Math.fround(Number.MAX_VALUE))))), Math.fround(( - (mathy2((x >>> 0), y) | 0))))), ( + ( ~ ( + Math.min((((y >>> 0) ? (y >>> 0) : (42 >>> 0)) >>> 0), y))))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[false, function(){}, (0/0), function(){}, NaN, NaN, false, false, NaN, function(){}, function(){}, function(){}, false, (0/0), (0/0), NaN, NaN, false, function(){}, false, function(){}, false, NaN, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, (0/0), function(){}, function(){}, function(){}, false, false, false, NaN, false, false, function(){}, (0/0), false, (0/0), false, function(){}, false, false, NaN, function(){}, false, false, false, false, NaN, (0/0), NaN, false, function(){}, false, (0/0), false, (0/0), function(){}, false, (0/0), false, NaN, (0/0), (0/0), false, function(){}, function(){}, function(){}, NaN, false]); ");
/*fuzzSeed-159544250*/count=87; tryItOut("mathy1 = (function(x, y) { return ((mathy0(x, Math.cbrt(Math.min(Math.imul(y, 0), x))) < mathy0(Math.sin((x >>> 0)), mathy0((((Math.max(Math.fround(y), (-Number.MAX_VALUE | 0)) | 0) | 0) & (x | 0)), y))) !== Math.acos((Math.fround(Math.clz32((Math.fround(x) >= x))) >>> 0))); }); testMathyFunction(mathy1, [1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, 0, Number.MAX_VALUE, 0.000000000000001, -0x080000001, 0x100000001, 0x0ffffffff, -(2**53+2), -0x100000000, -1/0, 0x080000000, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -0, 42, 1, -0x100000001, Math.PI, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE, 2**53+2, 0x080000001, 2**53-2, 2**53, -Number.MAX_VALUE, -(2**53), 0x100000000, -0x080000000]); ");
/*fuzzSeed-159544250*/count=88; tryItOut("\"use strict\"; s2 += s2;");
/*fuzzSeed-159544250*/count=89; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=90; tryItOut("for (var v of t0) { try { m2.delete(h1); } catch(e0) { } try { /*RXUB*/var r = g0.r1; var s = s0; print(s.match(r)); print(r.lastIndex);  } catch(e1) { } Object.prototype.unwatch.call(o0.f1, \"valueOf\"); }");
/*fuzzSeed-159544250*/count=91; tryItOut("\"use strict\"; i0.valueOf = (function() { v1 = g2.eval(\"v1 = g0.eval(\\\"(makeFinalizeObserver('nursery'))\\\");\"); throw h0; });");
/*fuzzSeed-159544250*/count=92; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot((( + ( - 0x080000001)) > x), ((0.000000000000001 | (( + Math.asinh(( + Math.imul(x, -0x100000000)))) >>> 0)) ? ((Math.fround(Math.asinh(((Math.hypot((y | 0), (x | 0)) | 0) | 0))) >>> 0) , Math.fround(x)) : (( ! y) >>> 0))) ? ( - Math.tanh(y)) : (((Math.fround(( + Math.log(y))) ? (Math.fround(Math.sign(Math.fround(y))) === Math.hypot((Math.fround(Math.min(Math.fround(x), Math.fround(y))) >>> 0), x)) : (-0x100000000 | 0)) | 0) ^ (Math.atan2((( + Math.fround(y)) > (Math.min(x, 42) | 0)), (( + Math.hypot(x, y)) >>> 0)) ^ Math.fround((( ~ -(2**53)) | -0x080000001))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0x07fffffff, 0.000000000000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), -0, Number.MAX_VALUE, 0, 0x100000000, Math.PI, 2**53-2, Number.MIN_VALUE, 42, 1.7976931348623157e308, 0x100000001, -Number.MIN_VALUE, -1/0, -0x080000000, -0x080000001, 0x080000000, -Number.MAX_VALUE, 0/0, 2**53, 0x0ffffffff, -(2**53), 1, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-159544250*/count=93; tryItOut("/*oLoop*/for (rcjwrp = 0; rcjwrp < 52; ++rcjwrp) { /*MXX3*/g1.g1.ArrayBuffer.prototype.byteLength = g0.ArrayBuffer.prototype.byteLength; } ");
/*fuzzSeed-159544250*/count=94; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2/yim; var s = \"\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=95; tryItOut("mathy2 = (function(x, y) { return (( - ((Math.pow(Math.pow(mathy0((x >>> 0), 0), Math.fround(x)), (Math.sinh(-Number.MAX_VALUE) >>> 0)) * Math.min(y, (((Number.MIN_VALUE | 0) != ( + Math.max(( - -0x0ffffffff), x))) | 0))) >>> 0)) | 0); }); ");
/*fuzzSeed-159544250*/count=96; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! Math.log1p((( ~ ((( + ( + ( + x))) >>> 0) | 0)) >>> 0))); }); testMathyFunction(mathy5, [42, 0, -0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, -0x080000000, Number.MIN_VALUE, -0x100000000, -(2**53+2), -Number.MIN_VALUE, 0/0, 2**53, 0.000000000000001, 0x100000000, -1/0, Number.MAX_VALUE, -(2**53-2), -0x080000001, Number.MAX_SAFE_INTEGER, 1, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -(2**53), 1/0, 0x080000001, -0x100000001, 0x07fffffff, -0, 2**53-2, 1.7976931348623157e308, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=97; tryItOut("a0 = new Array;");
/*fuzzSeed-159544250*/count=98; tryItOut("mathy5 = (function(x, y) { return Math.abs(( + (( + (Math.hypot(( - (Math.fround(( ~ y)) == x)), y) | 0)) === (Math.imul(Math.fround((( + -(2**53+2)) < ( + -0))), (Math.log10(mathy0(Math.min((x >>> 0), (x >>> 0)), Math.atan2(y, (y >>> 0)))) | 0)) | 0)))); }); testMathyFunction(mathy5, [0/0, -(2**53-2), 1/0, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, 1, 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, -0x100000001, 0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, -1/0, -0, 42, -0x0ffffffff, 2**53, -0x100000000, 0, 2**53+2, 0x0ffffffff, -(2**53), -0x080000001, -(2**53+2), 1.7976931348623157e308, -0x080000000, -0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=99; tryItOut("delete e1[\"callee\"];");
/*fuzzSeed-159544250*/count=100; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[(void 0), [], [], Infinity, (1/0), (1/0), x, Infinity, (void 0), (1/0), x, x, (1/0), Infinity, x, [], Infinity, Infinity, (1/0), (1/0), Infinity, x, Infinity, Infinity, (void 0), (void 0), x, Infinity, (void 0), Infinity, Infinity, x, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), x, x, Infinity, (1/0), (void 0), x, Infinity, (1/0), Infinity, [], (void 0), (1/0), [], Infinity, [], (void 0), (1/0), (1/0), (void 0), [], (1/0), Infinity, Infinity, [], [], Infinity, x, (void 0), (void 0), [], (void 0), (void 0), x, x, x, [], (void 0), x, x, Infinity, Infinity, (1/0), (void 0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), x, x]) { o0.t2 = new Int32Array(b1); }");
/*fuzzSeed-159544250*/count=101; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.log10(Math.fround((( + ( ~ (-0 ? (Math.fround(Math.imul(Math.fround(mathy0(Math.fround(y), Math.cbrt(y))), Math.fround(x))) >>> 0) : Math.tanh(y)))) != ( ~ x))))); }); testMathyFunction(mathy1, [NaN, (new Number(-0)), '0', [0], ({valueOf:function(){return '0';}}), (function(){return 0;}), true, '', [], 1, (new Number(0)), (new Boolean(true)), undefined, '\\0', 0, false, /0/, -0, ({toString:function(){return '0';}}), (new String('')), '/0/', null, objectEmulatingUndefined(), (new Boolean(false)), 0.1, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-159544250*/count=102; tryItOut("v1 = p1[\"arguments\"];");
/*fuzzSeed-159544250*/count=103; tryItOut("\"use asm\"; print(i0);");
/*fuzzSeed-159544250*/count=104; tryItOut("\"use strict\"; testMathyFunction(mathy5, [({toString:function(){return '0';}}), undefined, (new String('')), false, (new Boolean(true)), (new Boolean(false)), /0/, '\\0', [], objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), '/0/', (new Number(0)), '', 1, (function(){return 0;}), NaN, null, '0', 0, true, [0], (new Number(-0)), ({valueOf:function(){return '0';}}), -0]); ");
/*fuzzSeed-159544250*/count=105; tryItOut("\"use strict\"; var osmdls = new ArrayBuffer(1); var osmdls_0 = new Uint32Array(osmdls); osmdls_0[0] = 6; print(b0);");
/*fuzzSeed-159544250*/count=106; tryItOut("mathy3 = (function(x, y) { return Math.hypot((((mathy1(( + ( ! ( + x))), y) * ((( + Math.fround(Number.MAX_SAFE_INTEGER)) | 0) >>> 0)) >>> 0) >>> 0), Math.fround(Math.fround(Math.sqrt(Math.fround((( - (Number.MAX_VALUE | 0)) - (mathy2((-0x07fffffff >>> 0), (Math.sin(Math.fround(x)) | 0)) >>> 0))))))); }); testMathyFunction(mathy3, [1, true, false, (new Boolean(true)), ({valueOf:function(){return 0;}}), 0.1, 0, '\\0', '/0/', ({valueOf:function(){return '0';}}), (new Number(-0)), (function(){return 0;}), undefined, '0', '', /0/, null, NaN, -0, ({toString:function(){return '0';}}), (new String('')), [], (new Boolean(false)), objectEmulatingUndefined(), [0], (new Number(0))]); ");
/*fuzzSeed-159544250*/count=107; tryItOut("mathy3 = (function(x, y) { return ( + ( - ((( ~ (Math.atan2(-(2**53), (((y >>> 0) !== (y | 0)) >>> y)) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy3, /*MARR*/[({}), objectEmulatingUndefined(), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), objectEmulatingUndefined(), ({}), objectEmulatingUndefined(), true, true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}), ({}), objectEmulatingUndefined(), ({}), true, ({}), ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-159544250*/count=108; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return Math.hypot((Math.max(((( + (Math.atan2(((Math.tan(-0x0ffffffff) >>> 0) || -0x07fffffff), Math.min((Math.fround(x) || (1 | 0)), ( + x))) >>> 0)) | 0) >>> 0), (Math.max(Math.fround(Math.fround(Math.min(Math.atanh(x), Math.fround((Math.sin(x) >>> 0))))), Math.fround(x)) >>> 0)) >>> 0), ( + (( + (((Math.fround((Math.fround(Math.asinh(Math.fround(Math.atan2(x, x)))) ? (Math.pow(y, Math.fround((( + x) === Math.fround(x)))) | 0) : ( + Math.atan2(y, (Math.tan((var yzffud = new ArrayBuffer(6); var yzffud_0 = new Float64Array(yzffud); print(yzffud_0[10]); >>> 0)) >>> 0))))) >>> 0) - (( + ( ~ x)) >>> 0)) >>> 0)) >> ( + (Math.sign(((Math.min(x, ( ~ x)) | 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -(2**53+2), 0x100000001, -0, 0x100000000, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 42, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -0x080000001, -1/0, 0x080000000, 1, 2**53-2, 2**53+2, -0x100000000, 0/0, 0x080000001, 0, -0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=109; tryItOut("mathy5 = (function(x, y) { return (mathy2(( + Math.fround(Math.min(Math.fround(( - Math.fround(( ~ -0x100000000)))), Math.fround(x)))), ((( - ((mathy2(((y < (( - Math.fround(( ! Math.fround(-(2**53))))) | 0)) | 0), ((((((Math.sinh(0x0ffffffff) >>> 0) ? (x >>> 0) : (Math.sinh(y) >>> 0)) >>> 0) <= ( + y)) % Math.PI) | 0)) | 0) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy5, [-0x080000001, -(2**53-2), 2**53-2, 0x080000000, -(2**53+2), 2**53, 1.7976931348623157e308, -Number.MIN_VALUE, 0x0ffffffff, -0x100000000, 0x100000000, -0x07fffffff, -0x080000000, -1/0, Number.MIN_SAFE_INTEGER, 0, 0x100000001, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0.000000000000001, Math.PI, -0x0ffffffff, Number.MIN_VALUE, 1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, 42, 2**53+2]); ");
/*fuzzSeed-159544250*/count=110; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.log1p(Math.fround((( - (Math.ceil(x) >>> 0)) ^ ( + (Math.log10(Math.fround(y)) ? (((( ~ ((( ~ (y >>> 0)) >>> 0) >>> 0)) >>> 0) >>> ((Math.ceil(y) | 0) >>> 0)) >>> 0) : ( - x)))))); }); testMathyFunction(mathy4, /*MARR*/[ /x/g ,  /x/g , 0x3FFFFFFF, 0x3FFFFFFF,  /x/g , 0x3FFFFFFF,  /x/g ,  /x/g , 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF,  /x/g , 0x3FFFFFFF,  /x/g , 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF,  /x/g , 0x3FFFFFFF, 0x3FFFFFFF,  /x/g ,  /x/g ,  /x/g ,  /x/g , 0x3FFFFFFF]); ");
/*fuzzSeed-159544250*/count=111; tryItOut("a1.__proto__ = f0;");
/*fuzzSeed-159544250*/count=112; tryItOut("for (var v of b2) { try { /*vLoop*/for (var ypsnuk = 0; ypsnuk < 80; ++ypsnuk) { var y = ypsnuk; print(delete d.c); }  } catch(e0) { } try { o1.g2.__proto__ = o0; } catch(e1) { } s1.valueOf = (function() { for (var j=0;j<28;++j) { f2(j%5==0); } }); }");
/*fuzzSeed-159544250*/count=113; tryItOut(";");
/*fuzzSeed-159544250*/count=114; tryItOut("var gmzbaa = new ArrayBuffer(1); var gmzbaa_0 = new Float64Array(gmzbaa); v0 = t2.length;print(28);/*ADP-3*/Object.defineProperty(a0, 17, { configurable: true, enumerable: (x % 3 != 1), writable: false, value: s1 });");
/*fuzzSeed-159544250*/count=115; tryItOut("o2.v0 = Object.prototype.isPrototypeOf.call(i2, o0);");
/*fuzzSeed-159544250*/count=116; tryItOut("/*RXUB*/var r = /([^\\uC57b-\ua9c7\u83bc])/gim; var s = \"\\u839c\"; print(r.test(s)); ");
/*fuzzSeed-159544250*/count=117; tryItOut("mathy1 = (function(x, y) { return ((x = (/*FARR*/[, [z1], -25, , ...[],  \"\" , \"\\uDE8A\",  \"\" ].map(Number.prototype.toPrecision)) >>> 0) || (( ! ( + (((( ! (y | 0)) | 0) >>> 0) && ( + x)))) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[new String('q'), new String('q'), new String('q'), 0x3FFFFFFE, 0x3FFFFFFE, new String('q'), new String('q'), 0x3FFFFFFE, new String('q'), new String('q'), 0x3FFFFFFE, new String('q'), 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, new String('q'), 0x3FFFFFFE]); ");
/*fuzzSeed-159544250*/count=118; tryItOut("/*RXUB*/var r = /*FARR*/[, ...[], \"\\u731E\", this,  /x/ ,  /x/ , , , ...[], ...[], ...[], ,  '' , [1], \"\\uFD25\", ...[], [z1], ...[], ...[], ...[], c].sort(Date.prototype.toJSON); var s = \"\\u008f\\u008f\\u008f\\u008f\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=119; tryItOut("mathy4 = (function(x, y) { return (((Math.fround(( ! Math.fround((( ! (Math.log2(y) >>> 0)) >>> 0)))) >>> 0) ? Math.abs((Math.min(mathy2(y, mathy1(Math.hypot(Math.fround(y), x), Number.MAX_SAFE_INTEGER)), Math.log1p((Math.sinh(-0x100000001) >>> 0))) | 0)) : ((((mathy1(( + y), Math.imul(x, x)) >>> 0) % ( + Math.fround(( - Math.fround(y))))) >>> 0) >= ( + Math.max(x, ( - (Math.sin(y) == x)))))) >>> 0); }); testMathyFunction(mathy4, ['/0/', null, undefined, ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Number(-0)), 0.1, [], NaN, (new Boolean(true)), ({toString:function(){return '0';}}), 1, ({valueOf:function(){return '0';}}), '\\0', '', /0/, -0, '0', [0], (new String('')), 0, (function(){return 0;}), false, true, (new Number(0)), objectEmulatingUndefined()]); ");
/*fuzzSeed-159544250*/count=120; tryItOut("var c =  /* Comment */w;;");
/*fuzzSeed-159544250*/count=121; tryItOut("\"use strict\"; v0 = new Number(b0);\n/*RXUB*/var r = /\\W/gyi; var s = \"0\"; print(uneval(r.exec(s))); print(r.lastIndex); \nx.fileName;");
/*fuzzSeed-159544250*/count=122; tryItOut("g1 = this;");
/*fuzzSeed-159544250*/count=123; tryItOut("testMathyFunction(mathy2, [-(2**53+2), 0x100000001, -0x0ffffffff, -0, -0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 2**53-2, Math.PI, Number.MAX_VALUE, 0.000000000000001, -0x080000000, 0/0, -0x080000001, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, -(2**53), 42, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -(2**53-2), Number.MIN_VALUE, 0x080000001, 2**53, Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0]); ");
/*fuzzSeed-159544250*/count=124; tryItOut("e0.has(o1);");
/*fuzzSeed-159544250*/count=125; tryItOut("/*RXUB*/var r = r0; var s = \"\\u464e\"; print(s.split(r)); ");
/*fuzzSeed-159544250*/count=126; tryItOut("if(false) {e1 = t0[15]; } else  if (Math.asin(8)) p1.valueOf = WeakSet.prototype.has.bind(this.t1); else {let this = Math.hypot(-14, eval(\"/* no regression tests found */\") -= undefined);/* no regression tests found */ }");
/*fuzzSeed-159544250*/count=127; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0(Math.fround(Math.atan(( + (((Math.imul(x, x) >>> 0) >> (( + Math.clz32(( + ( + Math.min(( + (Math.fround(x) << Math.fround(x))), ( + x)))))) >>> 0)) >>> 0)))), Math.fround(Math.fround(Math.min(((-0x080000001 <= y) ? 0x0ffffffff : (Math.fround(Math.log((x >>> 0))) >> (x >>> 0))), ( + Math.clz32(Number.MIN_VALUE))))))); }); testMathyFunction(mathy1, /*MARR*/[function(){}, function(){}, 0x2D413CCC, new Boolean(true), new Boolean(true), new Boolean(true), x, objectEmulatingUndefined(), 0x2D413CCC, new Boolean(true), 0x2D413CCC, new Boolean(true), function(){}, objectEmulatingUndefined(), x, function(){}, x, 0x2D413CCC, function(){}, function(){}, function(){}, new Boolean(true), function(){}, 0x2D413CCC, function(){}, x, new Boolean(true), function(){}, x, function(){}, objectEmulatingUndefined(), 0x2D413CCC, 0x2D413CCC, new Boolean(true), 0x2D413CCC, new Boolean(true), objectEmulatingUndefined(), 0x2D413CCC, x, 0x2D413CCC, x, new Boolean(true), 0x2D413CCC, objectEmulatingUndefined(), objectEmulatingUndefined(), x, function(){}, x, new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), 0x2D413CCC, function(){}, x, objectEmulatingUndefined(), function(){}, 0x2D413CCC]); ");
/*fuzzSeed-159544250*/count=128; tryItOut("\"use strict\"; for (var p in f2) { v0 = -Infinity; }\n");
/*fuzzSeed-159544250*/count=129; tryItOut("/*hhh*/function dnyzeu(x, ...x){false;}dnyzeu((/*MARR*/[0x10000000, 1.3, 1.3, 0x10000000, 0x10000000, 0x10000000,  \"use strict\" ,  \"use strict\" , (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), NaN, (-1/0), 1.3, 1.3, NaN, 0x10000000, 1.3, (-1/0), 1.3, (-1/0), NaN,  \"use strict\" , 1.3, NaN, 1.3, 1.3, 1.3, (-1/0),  \"use strict\" ,  \"use strict\" , 0x10000000, 1.3,  \"use strict\" , (-1/0), 1.3, 1.3,  \"use strict\" ,  \"use strict\" , (-1/0), NaN,  \"use strict\" , 1.3, (-1/0),  \"use strict\" , 1.3, (-1/0), 0x10000000, 0x10000000, 1.3, 0x10000000, (-1/0), 0x10000000,  \"use strict\" ,  \"use strict\" , 0x10000000, 1.3, 1.3, 0x10000000,  \"use strict\" , (-1/0), 1.3, 0x10000000, (-1/0), NaN, 1.3, (-1/0), NaN, 1.3,  \"use strict\" , NaN, (-1/0),  \"use strict\" , (-1/0),  \"use strict\" ,  \"use strict\" , (-1/0),  \"use strict\" ,  \"use strict\" , 0x10000000, 0x10000000,  \"use strict\" , NaN, (-1/0), NaN,  \"use strict\" , 0x10000000,  \"use strict\" , (-1/0),  \"use strict\" , (-1/0),  \"use strict\" , NaN, NaN, (-1/0), 0x10000000, 0x10000000,  \"use strict\" , 0x10000000, NaN,  \"use strict\" , 0x10000000, (-1/0), (-1/0),  \"use strict\" , 1.3, 1.3,  \"use strict\" , 1.3, 1.3, (-1/0), NaN, (-1/0), (-1/0),  \"use strict\" , 1.3, NaN, 1.3, 0x10000000, 0x10000000, (-1/0), (-1/0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (-1/0), 1.3].map(((Date.prototype.getUTCFullYear).bind()).apply)), (x(x = eval)));");
/*fuzzSeed-159544250*/count=130; tryItOut("\"use strict\"; var rbtwrc = new ArrayBuffer(8); var rbtwrc_0 = new Uint8ClampedArray(rbtwrc); var rbtwrc_1 = new Uint8ClampedArray(rbtwrc); var rbtwrc_2 = new Int8Array(rbtwrc); print(rbtwrc_2[0]); var rbtwrc_3 = new Uint32Array(rbtwrc); print(rbtwrc_3[0]); var rbtwrc_4 = new Uint32Array(rbtwrc); this.a1 = [];");
/*fuzzSeed-159544250*/count=131; tryItOut("function f2(o0.e1)  { return x } ");
/*fuzzSeed-159544250*/count=132; tryItOut("print(s1);");
/*fuzzSeed-159544250*/count=133; tryItOut("/*iii*/for (var v of b2) { try { v2 = (v0 instanceof e2); } catch(e0) { } try { g0.a0 = r2.exec(s0); } catch(e1) { } /*ODP-2*/Object.defineProperty(b0, \"toSource\", { configurable:  '' , enumerable: (eprpfc % 50 == 47), get: (function mcc_() { var mfcbid = 0; return function() { ++mfcbid; if (/*ICCD*/mfcbid % 2 == 1) { dumpln('hit!'); try { e1.has(o1); } catch(e0) { } try { h1.get = o2.f1; } catch(e1) { } try { print(o2.a0); } catch(e2) { } for (var v of o1.f1) { try { e2.valueOf = (function() { for (var j=0;j<27;++j) { f1(j%3==0); } }); } catch(e0) { } try { t1 + ''; } catch(e1) { } try { print(m0); } catch(e2) { } this.t2[2] = a1; } } else { dumpln('miss!'); try { v2 = t1.length; } catch(e0) { } try { selectforgc(o0); } catch(e1) { } try { v0 = a0[7]; } catch(e2) { } Array.prototype.reverse.call(a0); } };})(), set: (function() { try { t0[9] = this; } catch(e0) { } try { p1 = a2[({valueOf: function() { v1 = (b1 instanceof t2);return 0; }})]; } catch(e1) { } t2 = new Uint16Array(b2); return this.e0; }) }); }/*hhh*/function eprpfc(){o2.s2 = this.a2.join(s2);}\nArray.prototype.shift.apply(a2, [m0]);t2 + '';\n");
/*fuzzSeed-159544250*/count=134; tryItOut("/*RXUB*/var r = /\\S(?!(\\S)(?:[^]?)|[^\\B-\\\u48ed\\0-\\u6Efd]|\u7196\\3*).|\\w(?=.|\\b^)|[^]*?(\\b)+?(\\W|.)\\B*?{0,}+?|.|(?:\\B)*?/gy; var s = \"\\uf8b5aa\"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=135; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ! (Math.cos((Math.log(x) | 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[new Number(1.5), x, new Number(1.5)]); ");
/*fuzzSeed-159544250*/count=136; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(.){3}\\\\1*\\\\3|\\\\3*|(\\\\d){3,3}+.\\\\s?{0}\", \"i\"); var s = \"\\naaaaa 100\"; print(s.search(r)); print(r.lastIndex); e1.has(b1);");
/*fuzzSeed-159544250*/count=137; tryItOut("mathy5 = (function(x, y) { return (Math.log1p((Math.fround((Math.fround((Math.imul((Math.fround(Math.hypot(-(2**53), Math.fround(mathy1(y, -0x080000000)))) >>> 0), ((Math.atanh(( + (x | (x | 0)))) , y) >>> 0)) >>> 0)) | Math.fround((Math.asinh(-0) , x)))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[(void 0), (void 0), (-1/0), (void 0), (0/0), 0x50505050, (0/0), (-1/0), (void 0), (-1/0), (-1/0), (-1/0), (void 0), (0/0), 0x50505050, (-1/0), (-1/0), (-1/0), (0/0), (void 0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (void 0), (void 0), (0/0), (-1/0), (void 0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), 0x50505050, (-1/0), (0/0), (0/0), (-1/0), 0x50505050, (0/0), (void 0), (0/0), (0/0), 0x50505050, 0x50505050, (0/0), 0x50505050, (void 0), (-1/0), (0/0), (0/0), (-1/0), (void 0), (-1/0), (-1/0), 0x50505050, (-1/0), (0/0), 0x50505050, (-1/0), 0x50505050, (0/0), (void 0), (0/0), (void 0), (void 0), (-1/0), 0x50505050, (0/0), (0/0), (void 0), (-1/0), (void 0), (0/0), (-1/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), 0x50505050, (void 0), 0x50505050, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), 0x50505050, (0/0), (void 0), (0/0), 0x50505050, (0/0), (-1/0), (0/0), (0/0), 0x50505050, 0x50505050, (void 0), (0/0), (-1/0), (void 0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (-1/0), (void 0), (0/0), 0x50505050, 0x50505050, (-1/0), (void 0), (void 0), 0x50505050, (-1/0), 0x50505050, 0x50505050, 0x50505050, (0/0), 0x50505050, (0/0), 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1/0), 0x50505050, (-1/0), 0x50505050, 0x50505050, 0x50505050, 0x50505050, (-1/0), 0x50505050, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), 0x50505050, (-1/0), (0/0), (void 0), (void 0), (void 0), (0/0), (void 0), 0x50505050, 0x50505050, (void 0), (0/0), (void 0), 0x50505050, (0/0), (-1/0), (-1/0), 0x50505050, (0/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0)]); ");
/*fuzzSeed-159544250*/count=138; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(Math.fround(( ! Math.fround((( ! y) >>> 0))))), Math.fround(Math.log10(Math.fround(((x / (Math.fround(Math.max(((( ! (y | 0)) | 0) === Math.fround(Math.abs(y))), (x | ( + Math.imul(x, y))))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -0x100000000, -Number.MAX_VALUE, -0x07fffffff, -(2**53+2), -0x0ffffffff, -(2**53), 1, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0, 1.7976931348623157e308, -0x080000001, 0x0ffffffff, 1/0, 0x07fffffff, 2**53+2, -0x100000001, 2**53, -1/0, 0x100000000, Number.MIN_VALUE, 0/0, 0x100000001, -0, Number.MAX_VALUE, 2**53-2, -(2**53-2), -0x080000000, Math.PI]); ");
/*fuzzSeed-159544250*/count=139; tryItOut("x = [,,], x = \u3056++ **= new RegExp(\"(?=..?)^\", \"yi\"), \u3056 = -2 ? -21 : window, b = -12, x, eval, cchbzj, x, zzysrh;/* no regression tests found */");
/*fuzzSeed-159544250*/count=140; tryItOut("const b =  \"\" ;/*RXUB*/var r = r2; var s = this.s1; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=141; tryItOut("\"use strict\"; /*oLoop*/for (var hhdkep = 0, (Math.round(-24)); hhdkep < 101; ++hhdkep) { b0.toString = (function() { try { m2.has(o1); } catch(e0) { } try { ; } catch(e1) { } try { h1.getOwnPropertyNames = (function() { v1 = (g0.e1 instanceof g0.e2); return t1; }); } catch(e2) { } h1.defineProperty = f1; throw g2.m2; }); } ");
/*fuzzSeed-159544250*/count=142; tryItOut("g1.v1 = g1.runOffThreadScript();");
/*fuzzSeed-159544250*/count=143; tryItOut("v2 = Array.prototype.reduce, reduceRight.call(a0, (function(j) { if (j) { try { a1.splice(NaN, v0); } catch(e0) { } try { Array.prototype.forEach.call(a0, f2); } catch(e1) { } v2 = false; } else { try { m1.get(t2); } catch(e0) { } try { for (var p in p2) { s1 + m1; } } catch(e1) { } try { a2 = Array.prototype.filter.apply(a2, [(function(j) { if (j) { g1.t0[11] = x; } else { try { this.g1.v2 = new Number(g2); } catch(e0) { } try { /*RXUB*/var r = r1; var s = s2; print(s.match(r));  } catch(e1) { } a1.shift(); } })]); } catch(e2) { } v1 = (this.e2 instanceof b1); } }));");
/*fuzzSeed-159544250*/count=144; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; print((yield x) += (eval = NaN)); }}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [1.7976931348623157e308, -0, -Number.MAX_VALUE, 1/0, 42, 2**53+2, -(2**53-2), -Number.MIN_VALUE, 0x080000001, Math.PI, Number.MIN_VALUE, 2**53, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0x100000001, 0x100000000, 0/0, 0x07fffffff, 0, -(2**53), 2**53-2, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, -0x100000001, 1]); ");
/*fuzzSeed-159544250*/count=145; tryItOut("\"use strict\"; v1 = a0.length;");
/*fuzzSeed-159544250*/count=146; tryItOut("mathy1 = (function(x, y) { return ( + Math.fround((( + Math.max(y, ( + Math.max(Math.fround(Math.hypot(Math.fround(x), (x | 0))), y)))) ? ( + ( ! Math.fround((x * x)))) : (Math.log(( + ( + ((y | 0) ? ( + (1.7976931348623157e308 , (( ! (y | 0)) | 0))) : ( + Math.fround(Math.tan(-0x100000000))))))) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -0, -(2**53-2), 1.7976931348623157e308, 0x100000001, -(2**53), 0/0, Number.MIN_VALUE, -1/0, 0x0ffffffff, Math.PI, -(2**53+2), -Number.MAX_VALUE, -0x100000001, -0x100000000, 42, Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 1, 2**53, 0x100000000, 1/0, -0x07fffffff, -0x080000000, 0x080000000, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=147; tryItOut("/*vLoop*/for (var gnsxsr = 0; gnsxsr < 134; ++gnsxsr) { const d = gnsxsr; m1.toString = f0; } ");
/*fuzzSeed-159544250*/count=148; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.abs((Math.imul(Math.sin(Math.ceil((x != (x | y)))), ( + Math.round(( + (Math.max(Math.fround(x), ((y / ( + (Math.fround(x) / ( + x)))) | 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[null, null, null, null, null, null, null, null, null, null, null, null, false, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, null, false, false, false, false, false, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, null, false, -Number.MAX_SAFE_INTEGER, false, null, false, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, false, false, false, -Number.MAX_SAFE_INTEGER, null, -Number.MAX_SAFE_INTEGER, null, null, null]); ");
/*fuzzSeed-159544250*/count=149; tryItOut("f0 = (function mcc_() { var nixgxm = 0; return function() { ++nixgxm; if (/*ICCD*/nixgxm % 4 == 3) { dumpln('hit!'); try { Array.prototype.reverse.call(o1.a2); } catch(e0) { } try { v1 = g0.eval(\"length;\"); } catch(e1) { } try { selectforgc(g2.o0); } catch(e2) { } v0 = (e0 instanceof p0); } else { dumpln('miss!'); v0 = (e1 instanceof b1); } };})();b = (~x);");
/*fuzzSeed-159544250*/count=150; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.min((( + ( + Math.min(( + Math.exp(-(2**53+2))), ( + y)))) >>> 0), (Math.log10(Math.atan2(( + ( + ( + (Math.sinh(-1/0) >>> 0)))), (((x & Math.fround(Math.max(x, y))) >>> 0) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0/0, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, 2**53, 0x080000000, 42, 0x100000001, -0x080000001, -(2**53), -0x07fffffff, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 2**53+2, -(2**53-2), 0x080000001, 0, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff, -1/0]); ");
/*fuzzSeed-159544250*/count=151; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.pow((Math.imul((mathy0(Math.fround((( + (( - y) | 0)) | 0)), Math.fround((((( + x) >>> 0) << x) / (Math.fround(y) > y)))) | 0), (( + (-Number.MAX_SAFE_INTEGER ? ( + Math.imul(y, y)) : y)) === Math.fround((Math.fround(( + mathy0(Math.PI, ( + y)))) == Math.fround(( ! (Math.log2((0x100000000 | 0)) >>> 0))))))) | 0), (( + (( + (-0x0ffffffff >>> y)) * Math.fround(x))) | (Math.atanh(( + -Number.MIN_VALUE)) >>> 0))) | 0); }); testMathyFunction(mathy3, [1, (function(){return 0;}), objectEmulatingUndefined(), null, false, 0.1, 0, (new Boolean(false)), undefined, (new Boolean(true)), ({toString:function(){return '0';}}), true, [], (new Number(0)), -0, (new Number(-0)), [0], '/0/', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '0', /0/, '\\0', (new String('')), NaN, '']); ");
/*fuzzSeed-159544250*/count=152; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, -(2**53-2), 1.7976931348623157e308, Math.PI, 0x080000001, -0x100000000, 2**53, -0x080000001, Number.MIN_SAFE_INTEGER, -0, 1/0, 0.000000000000001, -0x100000001, 2**53+2, 0/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, 0x07fffffff, 1, 0x100000000, 42, -0x080000000, -(2**53), Number.MIN_VALUE, 0x100000001, 2**53-2, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=153; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return Math.fround(Math.atan2(Math.imul(( + (((mathy1((( + (((x | 0) >> (y | 0)) >>> 0)) >>> 0), (y >>> 0)) >>> 0) >>> 0) , (( + (( + Math.fround(( + 2**53))) ? ( + Math.min(mathy0(y, (y >> 2**53)), (Math.pow((-(2**53) >>> 0), (( + ((-0x07fffffff >>> 0) !== ( + Number.MAX_SAFE_INTEGER))) >>> 0)) >>> 0))) : ( + y))) >>> 0))), (Math.max((mathy1(( + (( + y) & Math.fround(x))), y) | 0), (Math.atan2(x, x) >>> 0)) + Math.fround(( + (mathy0((y | 0), (mathy1(x, -(2**53-2)) | 0)) | 0))))), Math.fround((Math.atan2((Math.hypot(Math.fround(Math.max(y, (Math.exp(( + -0)) >>> 0))), x) | 0), (Math.tan((Math.fround((Math.fround(( + x)) ** Math.fround(mathy1(Math.fround(Number.MAX_SAFE_INTEGER), ((y ? Math.fround(y) : 0x07fffffff) >>> 0))))) | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -0, 1, -0x080000000, -0x080000001, -0x100000001, 1.7976931348623157e308, 1/0, 0, 2**53-2, -0x07fffffff, 0x07fffffff, 0x080000000, 0/0, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 0x100000000, Number.MIN_VALUE, 2**53+2, -0x100000000, -1/0, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=154; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=155; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=156; tryItOut("/*infloop*/ for  each(var ((void options('strict')))[\"wrappedJSObject\"] in  \"\" ) {(Math); }");
/*fuzzSeed-159544250*/count=157; tryItOut("this.a1 = arguments.callee.caller.caller.arguments;");
/*fuzzSeed-159544250*/count=158; tryItOut("print(x >>>= x);\n/* no regression tests found */\n");
/*fuzzSeed-159544250*/count=159; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ (Math.fround((Math.sin(Math.fround(Math.fround(Math.asinh(Math.fround(Math.max(0x100000000, (((x | 0) ? (Math.log10(0x100000001) | 0) : (Math.expm1((y | 0)) | 0)) | 0))))))) | 0)) / Math.fround(Math.atan2(Math.log2(x), Math.fround(Math.acos(x)))))); }); ");
/*fuzzSeed-159544250*/count=160; tryItOut("mathy1 = (function(x, y) { return ( - ( + (Math.fround(Math.fround((( + Math.fround(Math.pow(y, ( + Math.cbrt((0x0ffffffff & x)))))) < ( + ( + Math.asinh(( + (( - (y >>> 0)) >>> 0)))))))) << ( + (Math.cbrt(( ! x)) || mathy0(Math.fround(Math.asin((Math.max((y | 0), ( + y)) | 0))), Math.atan2((Math.hypot((x | 0), ((( + 0x080000000) >>> 0) | 0)) | 0), Math.fround(((y <= (y >>> 0)) | 0))))))))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, -(2**53+2), -0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, 1, 0.000000000000001, -(2**53-2), -0x080000000, 2**53, 2**53-2, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53), -Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -0, 2**53+2, -0x0ffffffff, -0x080000001, 0/0, 0x100000001, -1/0, 42, 0x07fffffff, Number.MIN_VALUE, Math.PI, -0x07fffffff, 0]); ");
/*fuzzSeed-159544250*/count=161; tryItOut("mathy4 = (function(x, y) { return mathy1(( + (Math.cos(mathy2(y, ( ~ (x ? x : (( + y) , 0x07fffffff))))) >>> 0)), Math.fround(Math.fround(( - Math.fround((Math.asin((( ~ ( + (( + y) || ( + x)))) | 0)) | 0)))))); }); ");
/*fuzzSeed-159544250*/count=162; tryItOut("mathy3 = (function(x, y) { return (Math.imul(Math.pow((42 + ( + x)), Math.tanh((Math.abs((x | 0)) | 0))), (Math.ceil((y === ((2**53 === (Math.fround((Math.pow((-1/0 >>> 0), (x >>> 0)) >>> 0)) < ( + Math.atan2(x, x)))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, -1/0, 0x100000000, 0.000000000000001, 0x080000000, -Number.MIN_VALUE, -0x100000001, 1, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MAX_VALUE, -(2**53+2), -(2**53-2), Number.MIN_VALUE, -(2**53), 0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 0x080000001, 0, 42, -Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, 1/0, -0, 2**53]); ");
/*fuzzSeed-159544250*/count=163; tryItOut("/*RXUB*/var r = /(?=(?=.+?|\\cT))\\3|(?=(?:.))|(?!(?![^]))(?=(?!.{2,3})){0}|(?=([^][\\\u0016-\u00b1-\u1c30\\u005F\\D\\S])){4}|(?:($)){0,}|[^]+?(\\D{1})*\u00bb+/y; var s = \"\\n\\uaf89\\uaf89\\uaf89\\u009b\\uaf89\\uaf89\\uaf89\\u009b\\uaf89\\uaf89\\uaf89\\u009b\\n\\n\\n0\"; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=164; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=165; tryItOut("for (var p in e2) { try { s1 += 'x'; } catch(e0) { } try { h2[\"apply\"] = p2; } catch(e1) { } v2 = a1.length; }");
/*fuzzSeed-159544250*/count=166; tryItOut("nabkar, uzdfiq;let (x) { /*oLoop*/for (tnjriu = 0; tnjriu < 13; ++tnjriu) {  }  }");
/*fuzzSeed-159544250*/count=167; tryItOut("g2.f1 = (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i1 = (0xfa53ae0a);\n    }\n    return ((((0x3def8c8a) <= (new RegExp(\"(?!(?!(?:$*?)*?[^]))|((?=\\\\u8fb4|\\\\B[^]))|([\\\\W]?)*\", \"gyi\")))+((+((Float32ArrayView[((Uint8ArrayView[(((0x45945de1) ? (0x891e8ca0) : (-0x4a5810f))) >> 0])) >> 2]))) > (257.0))))|0;\n  }\n  return f; });");
/*fuzzSeed-159544250*/count=168; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(Math.fround(Math.fround(( + Math.fround((Math.log2((mathy0((( + ((Math.atan2((2**53 | 0), (Number.MIN_SAFE_INTEGER | 0)) | 0) << y)) | 0), mathy1(-0, ( + Math.pow(x, x)))) | 0)) | 0))))), Math.fround(Math.tan(Math.fround(( + (( + 0x100000001) && ((x | 0) << (Math.fround(Math.sin(x)) | 0))))))))); }); testMathyFunction(mathy2, [-1/0, 0x100000001, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -0x0ffffffff, 42, Number.MAX_VALUE, 1, 0x100000000, 2**53, -Number.MIN_VALUE, -(2**53), 0x080000000, -0x080000000, 0.000000000000001, -0x100000001, -0x100000000, Math.PI, 1/0, Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, -(2**53-2), 0x07fffffff, 1.7976931348623157e308, -0x080000001, 2**53-2, -0]); ");
/*fuzzSeed-159544250*/count=169; tryItOut("return;function x() { \"use strict\"; return window } i2[\"getPrototypeOf\"] = g2;");
/*fuzzSeed-159544250*/count=170; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      (Int8ArrayView[2]) = ((((((0x7fffffff) >= (0x22b5f3aa))-(0xff34e855)) ^ (((0x2b9bb637) == (((0x7c8ff211)) << ((0xf96c99d6))))+((((-0x8000000)-(0x7a4b6fe1))>>>((0x3c1717) % (0x4d56eb28)))))) <= (((0xf965872c)) ^ ((i0)-((+abs(((-3.0)))) > (+(((0xfee0400d))>>>((0xfba3dba1))))))))*-0x25fbd);\n    }\n    i0 = (-0x8000000);\n    i0 = ((0xffffffff) >= ((((imul(((0x7ed50844) <= (0x7fffffff)), (i0))|0))-((0xa7a3e12c)))>>>(-(!(0xfd099f71)))));\n    i0 = ((0xeee3a255));\n    return ((((0x71124d92) > ((uneval(new RegExp(\"\\\\1(?:[\\\\w\\\\u0032-\\\\xfE]{3,5})+(?!.*?)|[^][^\\\\w\\\\u007b-\\u9cf1\\\\D\\0-\\\\x9D]+[^\\\\B-\\\\xBB\\\\s]\", \"im\"))) ? x : ( ''  ===  \"\" )))))|0;\n    i0 = (0xf963eab5);\n    d1 = (d1);\n    d1 = (-1.2089258196146292e+24);\n    i0 = ((Float64ArrayView[((0xf94cb16c)+(0xffffffff)+((0x8101f2a7))) >> 3]));\n    return (((i0)-(0x149b6796)-(i0)))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=171; tryItOut("a0 = arguments;");
/*fuzzSeed-159544250*/count=172; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((Math.pow(y, mathy1(( + mathy4(( + ( ~ x)), ( + Math.sign(x)))), Math.round((Math.clz32(x) >>> 0)))) ? Math.fround(Math.clz32((Math.max((Math.fround(Math.imul(Math.fround(Math.pow(y, y)), x)) != mathy0(2**53-2, x)), ( + Math.clz32(( + x)))) >>> 0))) : (y && Math.imul(x, Math.log1p(x)))) >>> 0) === ((Math.sin(( + y)) | 0) ? ( ~ x) : Math.fround((Math.fround((y !== y)) <= Math.fround(((0x080000001 >>> 0) , y)))))); }); testMathyFunction(mathy5, [1/0, 0x100000000, 0.000000000000001, -0x080000000, -Number.MIN_VALUE, 0x080000001, -(2**53-2), 0x100000001, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, Math.PI, -0x100000001, -(2**53), -0x080000001, 1, 2**53, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 0x080000000, 0/0]); ");
/*fuzzSeed-159544250*/count=173; tryItOut("\"use strict\"; m0.get(g0);");
/*fuzzSeed-159544250*/count=174; tryItOut("\"use strict\"; e1.has(e1);");
/*fuzzSeed-159544250*/count=175; tryItOut("g1.toSource = (function mcc_() { var dqpipi = 0; return function() { ++dqpipi; if (/*ICCD*/dqpipi % 10 == 2) { dumpln('hit!'); s2 += s1; } else { dumpln('miss!'); print(uneval(h1)); } };})();");
/*fuzzSeed-159544250*/count=176; tryItOut("a0 = x;");
/*fuzzSeed-159544250*/count=177; tryItOut("\"use strict\"; /*vLoop*/for (let qayvvk = 0, Number.isNaN.prototype.valueOf(\"number\"); qayvvk < 94; ++qayvvk) { let d = qayvvk; m0.get(g2); } ");
/*fuzzSeed-159544250*/count=178; tryItOut("Object.prototype.watch.call(i0, \"x\", (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 144115188075855870.0;\n    var i3 = 0;\n    var i4 = 0;\n    i0 = (((((!((((0xb49564c8)) ^ ((0xfa98e1ce)))))+((~((0xfbf1748d))) <= (((0x3482bfbd))|0)))>>>((-0x8000000)+(0xffffffff)-(i4)))) ? (0x93177010) : (((-9.0) + (+(-1.0/0.0))) > (+((((Int32ArrayView[0]))-(i4)) << ((0xa2128a39)+(0xfee19891))))));\n    d1 = (d1);\n    return (((((((((((i3))>>>(function  x (x = x, e = (allocationMarker())) { yield Math.atan2(-6, ({\"-27\": 24})) } ))))>>>((i3))))+(((~((0xfeb7d778))) == (((0xffffffff)) & ((0x5315d3a1)))) ? (i3) : (((2.0)))))) % (0xffffffff)))|0;\n  }\n  return f; })(this, {ff: ({a: {x: yield, \u3056: {a: NaN}}, z, x, x: {z, window: {}, this.x: {NaN}, x: {}, x: {x, x: [, , [], ], window}}, x: y, b: arguments.callee.caller.arguments}, y = (/*FARR*/[.../*PTHR*/(function() { \"use strict\"; for (var i of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), -0x5a827999, objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, -Infinity, -0x5a827999, objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), Number.MIN_VALUE, -0x5a827999, objectEmulatingUndefined(), -0x5a827999, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, -Infinity, objectEmulatingUndefined(), Number.MIN_VALUE, objectEmulatingUndefined(), -Infinity, -Infinity, -0x5a827999, -Infinity, objectEmulatingUndefined(), -0x5a827999, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x5a827999, -Infinity, -0x5a827999, -Infinity, Number.MIN_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x5a827999, -Infinity, -0x5a827999, -0x5a827999, Number.MIN_VALUE, objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, Number.MIN_VALUE, -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Number.MIN_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x5a827999, -0x5a827999, Number.MIN_VALUE, objectEmulatingUndefined(), Number.MIN_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), Number.MIN_VALUE, -0x5a827999, Number.MIN_VALUE, -Infinity, objectEmulatingUndefined()]) { yield i; } })(), z = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function(y) { this.v2 = Object.prototype.isPrototypeOf.call(g1.a0, this.g2.b0); }, fix: function() { return []; }, has: b =>  { return new RegExp(\"$\", \"\") } , hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: function() { return []; }, keys: function() { return []; }, }; })(function(id) { return id }), (24 ** 14))].filter(/*wrap2*/(function(){ \"use strict\"; var gutstw = (4277); var aiinll = ( ''  / \"\\u5DC6\").localeCompare; return aiinll;})(), (this.__defineGetter__(\"y\", runOffThreadScript))))) =>  { \"use strict\"; yield y = yield (void shapeOf(\"\\u4489\")) } }, new SharedArrayBuffer(4096)));");
/*fuzzSeed-159544250*/count=179; tryItOut("a0.splice(NaN, o1.v2, g1);");
/*fuzzSeed-159544250*/count=180; tryItOut("(void schedulegc(this.g2));");
/*fuzzSeed-159544250*/count=181; tryItOut("\"use strict\"; /*RXUB*/var r = ((4277)); var s = x; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=182; tryItOut("p2 = t0[({valueOf: function() { v1 = evaluate(\"m0.has(m1);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 4 != 2), sourceIsLazy: (~(void version(185))), catchTermination: (x % 25 != 23) }));return 9; }})];");
/*fuzzSeed-159544250*/count=183; tryItOut("const z = (makeFinalizeObserver('nursery')), NaN = (mathy0), x;for (var p in t0) { try { e0.add(o1); } catch(e0) { } Array.prototype.splice.apply(a2, [NaN, v1, x]); }");
/*fuzzSeed-159544250*/count=184; tryItOut("\"use strict\"; var mrkdtk = new ArrayBuffer(8); var mrkdtk_0 = new Uint16Array(mrkdtk); var mrkdtk_1 = new Float32Array(mrkdtk); mrkdtk_1[0] = (4277); { void 0; verifyprebarriers(); } this.o1 + '';h0 + p1;/*RXUB*/var r = new RegExp(\"(?:(?=[^]))\", \"yim\"); var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); print(uneval(v2));print(mrkdtk_0[0]);");
/*fuzzSeed-159544250*/count=185; tryItOut("mathy4 = (function(x, y) { return ( + (mathy2(Math.round((Math.pow(x, x) >>> 0)), ( ~ Math.ceil((( + Math.max(Math.fround((y >>> 0)), y)) >>> 0)))) % ( + ((((y << (Math.trunc(mathy2(((0.000000000000001 * (-Number.MAX_SAFE_INTEGER > x)) | 0), (Math.trunc((y | 0)) | 0))) | 0)) | 0) ? (( ! ( + Math.hypot(( + 0x080000000), ( + (Math.min(( + y), (x | 0)) | 0))))) | 0) : ((42 > ((Math.pow(-(2**53+2), Math.atan(x)) % y) | 0)) | 0)) | 0)))); }); testMathyFunction(mathy4, [Math.PI, 1/0, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 0x100000000, 0x080000000, 0x0ffffffff, 0, 0x100000001, -(2**53), 1.7976931348623157e308, -0, 0/0, 2**53+2, 2**53-2, Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, -Number.MAX_VALUE, 1, 0x080000001, -0x0ffffffff, -1/0, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, 2**53, 42, Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=186; tryItOut("(window);let (x, [, ] = x, z = (yield true), x = 18(), mggyuj) { switch(x ==  \"\" ) { default: s2 += 'x'; } }");
/*fuzzSeed-159544250*/count=187; tryItOut("v1 + '';");
/*fuzzSeed-159544250*/count=188; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( - Math.atan2(( ~ Math.fround(Math.max(Math.log(y), Math.fround(Number.MAX_SAFE_INTEGER)))), Math.fround(Math.exp(Math.fround(( + ( + 42))))))); }); testMathyFunction(mathy3, [0/0, -0x100000001, -0x0ffffffff, 0x100000000, 42, 0x080000000, -Number.MAX_VALUE, 2**53-2, 0x07fffffff, -(2**53+2), -0x080000001, -0x100000000, 2**53+2, -1/0, 0, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, Math.PI, 0x080000001, -(2**53-2), 0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, Number.MIN_VALUE, -0]); ");
/*fuzzSeed-159544250*/count=189; tryItOut("h0.keys = (function() { a2 = Array.prototype.map.call(a1, (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return +(((!(i2)) ? (x) : ((0x261d70b4) ? (-8589934591.0) : (295147905179352830000.0))));\n  }\n  return f; })); throw h1; });");
/*fuzzSeed-159544250*/count=190; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((d1));\n    (Float64ArrayView[((0xfc9487a7)-(/*UUV2*/(w.hypot = w.forEach))+(i0)) >> 3]) = ((562949953421311.0));\n    return +((d1));\n    d1 = (-2199023255551.0);\n    return +((d1));\n    /*FFI*/ff(((d1)), (((((~~((0x119b1543) ? (-1152921504606847000.0) : (6.044629098073146e+23))) == (~~(((2.0)) % ((36893488147419103000.0)))))+(i0))|0)), ((d1)), ((0x27317371)));\n    d1 = (+atan2(((4.722366482869645e+21)), ((d1))));\n    i0 = ((((0xca78b013)+(/*FFI*/ff(((((0x60faea0a) / (0x23a0460)) << ((i0)-(0xc9775219)))), ((d1)))|0))>>>((0x9b04362))));\n    return +((-6.044629098073146e+23));\n  }\n  return f; })(this, {ff: Math.cosh}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [/0/, ({valueOf:function(){return 0;}}), 0.1, (new Boolean(true)), true, '\\0', (new String('')), [0], undefined, 1, (function(){return 0;}), '/0/', [], false, (new Number(-0)), '0', NaN, objectEmulatingUndefined(), -0, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), '', null, (new Boolean(false)), 0, (new Number(0))]); ");
/*fuzzSeed-159544250*/count=191; tryItOut("let (w) { a0.unshift(o0); }");
/*fuzzSeed-159544250*/count=192; tryItOut("g1 = this;");
/*fuzzSeed-159544250*/count=193; tryItOut("\"use strict\"; for (var v of o2.o0.g2) { try { selectforgc(o0.o0); } catch(e0) { } /*RXUB*/var r = r1; var s = s0; print(uneval(s.match(r))); print(r.lastIndex);  }");
/*fuzzSeed-159544250*/count=194; tryItOut("a1.forEach((function() { try { g0 = this; } catch(e0) { } try { Array.prototype.splice.apply(a0, [8, 10, o0.a0, h2, s2, i0]); } catch(e1) { } for (var p in a0) { try { Array.prototype.reverse.call(a2); } catch(e0) { } e1.has(a1); } return o0; }), this.e1);");
/*fuzzSeed-159544250*/count=195; tryItOut("i0 = g2.objectEmulatingUndefined();");
/*fuzzSeed-159544250*/count=196; tryItOut("var croxsb, [] = (4277), this.d = (w) = /(.)*?|\\2/g.unwatch(\"pow\"), ucdysf, x, eval = (4277), e = new ((makeFinalizeObserver('tenured')))//h\n(), x = x >  /x/g ;g2.g1.v0.toString = (function() { for (var j=0;j<66;++j) { f2(j%4==0); } });");
/*fuzzSeed-159544250*/count=197; tryItOut("var rycitj, xwowym, x = (Math.pow(3, -22)(x, (4277))), window, z = (this.toGMTString()), {x: c, x: -28} = a = Proxy.createFunction(({/*TOODEEP*/})(window), /*wrap1*/(function(){ this.p2.valueOf =  '' ;return Date.prototype.setUTCHours})(), /*wrap3*/(function(){ var dzkkvh = false; (/*wrap2*/(function(){ var gjpqae = [,,z1]; var vitrkz = Function; return vitrkz;})())(); })), c;h1.set = (function() { for (var j=0;j<1;++j) { f2(j%2==0); } });");
/*fuzzSeed-159544250*/count=198; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions(); } void 0; } o0.p1.__proto__ = g0.h1;");
/*fuzzSeed-159544250*/count=199; tryItOut("/*hhh*/function syyboe(\u3056, b, e, eval, x, x, x = let (c) b, x, x, d =  /x/g , w, x, z, x =  /x/ , c, b, w = new RegExp(\"\\\\u5fb9*\", \"gm\"), window, a, b, x, c, d, x, eval, x, x, eval = -22, x = x, a = [], z, x, y, NaN, window, NaN, b, y, x =  '' , b, x, \u3056, name = window, x = this, this, x, e, x, a, x, x, arguments, NaN, d, z, x, NaN =  /x/g , x, x, x = 0, x, window, x, x, a){let(x, x = (-15.watch(\"getUTCDate\", Math.log1p))) { let(w) { this.zzz.zzz;}}}/*iii*/var lyuxnv = new ArrayBuffer(12); var lyuxnv_0 = new Uint8ClampedArray(lyuxnv); L:with({w: ((makeFinalizeObserver('tenured')))}){ \"\" ;var b0 = t0.buffer; }");
/*fuzzSeed-159544250*/count=200; tryItOut("mathy3 = (function(x, y) { return ( + ( + Math.hypot(( + (Math.fround(Math.min(-Number.MIN_VALUE, -1/0)) / x)), ( + Math.fround(( ! Math.fround(( ~ (( + ( ! y)) | 0))))))))); }); testMathyFunction(mathy3, /*MARR*/[({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), objectEmulatingUndefined(), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), objectEmulatingUndefined(), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\")), ({}) = (+new RegExp(\"(?:(\\\\d)?)?\", \"im\"))]); ");
/*fuzzSeed-159544250*/count=201; tryItOut("print(p0);");
/*fuzzSeed-159544250*/count=202; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0.1, objectEmulatingUndefined(), (new Boolean(false)), [0], 1, -0, undefined, ({toString:function(){return '0';}}), NaN, (new Number(-0)), ({valueOf:function(){return 0;}}), '0', (function(){return 0;}), /0/, (new String('')), null, false, true, '/0/', ({valueOf:function(){return '0';}}), (new Number(0)), 0, [], '', '\\0', (new Boolean(true))]); ");
/*fuzzSeed-159544250*/count=203; tryItOut("/*bLoop*/for (var lnhtsq = 0; lnhtsq < 43; ++lnhtsq) { if (lnhtsq % 8 == 1) { /*RXUB*/var r =  /x/g ; var s = \"w\"; print(uneval(r.exec(s)));  } else { for (var v of o0) { try { h0 = {}; } catch(e0) { } for (var p in b1) { try { o1.v1 = Object.prototype.isPrototypeOf.call(s0, this.a1); } catch(e0) { } /*MXX1*/o1 = g1.Number.MAX_SAFE_INTEGER; } } }  } ");
/*fuzzSeed-159544250*/count=204; tryItOut("/*RXUB*/var r = new RegExp(\"([^\\\\u0031Y-\\\\cQ\\\\W]?)?|\\\\2{4,7}+?|((?:\\\\2))|\\\\d^|\\\\W\\ue0d6{2}|^|.$|(?![^].)(?:\\\\B){3,}.\\\\1(?:\\\\x3f|\\\\B)(?:((?:\\\\1))|(?=(?:\\\\1))|(.){0,}|\\\\3+)\", \"y\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=205; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - Math.imul((Math.log10((x >> (( + x) >>> 0))) | 0), ((( - -Number.MIN_VALUE) ? (y >= x) : -0x100000001) >>> 0))) != (((Math.fround((Math.imul(Math.fround((( + (y | 0)) | 0)), Math.max(x, var ptdpit = new SharedArrayBuffer(8); var ptdpit_0 = new Int32Array(ptdpit); for (var v of t1) { try { delete v2[z]; } catch(e0) { } try { Object.prototype.watch.call(o1, \"then\", (function(j) { if (j) { try { neuter(g2.o1.b2, \"change-data\"); } catch(e0) { } try { g2.o2 = s2.__proto__; } catch(e1) { } try { t1 = new Uint16Array(t2); } catch(e2) { } this.v0 = Object.prototype.isPrototypeOf.call(m1, v0); } else { try { f1 = Proxy.createFunction(o0.h2, f1, f1); } catch(e0) { } try { i0.send(o1); } catch(e1) { } v1 = evaluate(\"print(this);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: false, sourceMapURL: s0 })); } })); } catch(e1) { } o0.valueOf = (function() { v2 = (e1 instanceof v1); return this.o2.p0; }); })) ? ( + (( + (y >>> 0)) >>> 0)) : Math.fround((y >>> (mathy2(2**53, y) ? y : ( + x)))))) ? mathy4(x, Math.atanh((Math.pow(x, x) | 0))) : Math.fround(Math.atan2((( + Math.imul(Math.imul((y >>> 0), 0x100000001), ( + y))) >>> 0), Math.fround(Math.imul(y, Math.hypot(0x100000001, 1/0)))))) >>> Math.log10((x && Math.atanh(( + y))))) >>> 0)); }); testMathyFunction(mathy5, [1, Number.MIN_VALUE, -0x100000000, -0x080000001, 2**53, 1.7976931348623157e308, -0x080000000, 2**53+2, 0/0, 42, Number.MAX_SAFE_INTEGER, Math.PI, 1/0, 0.000000000000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -0, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), -1/0, Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 2**53-2, -(2**53+2), -0x100000001, 0]); ");
/*fuzzSeed-159544250*/count=206; tryItOut("\"use strict\"; print(x);/*infloop*/for(b; new Object(new RegExp(\".\", \"gm\")); x) {a1[18] = h1; }");
/*fuzzSeed-159544250*/count=207; tryItOut("const npjtyj, c, guturh, NaN, etvuzn, ogkshl, yikzta, b, eyqqwb;v0 = b1.byteLength;");
/*fuzzSeed-159544250*/count=208; tryItOut("/*vLoop*/for (let mtsszj = 0; mtsszj < 29; ++mtsszj) { y = mtsszj; /*RXUB*/var r = new RegExp(\"(?!(?=$))+?\\\\B|(?!(?=((?![\\\\D\\\\W\\u00f6-\\\\u5D87]))|(^{3,5}))|\\\\3)\\\\D.|[^\\\\s\\u5348]{1,4}[^]|[^]*{2,6}{2}\", \"y\"); var s = \"   1\"; print(s.search(r));  } ");
/*fuzzSeed-159544250*/count=209; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x100000000, 0x07fffffff, Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, -(2**53+2), -0x07fffffff, -0, -Number.MAX_VALUE, 0.000000000000001, 0, 0x080000000, -0x080000001, -0x0ffffffff, -0x080000000, 1/0, 42, 0x100000001, -1/0, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0/0, 0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, 0x080000001, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=210; tryItOut("/*RXUB*/var r = /\\w+?(\\b\\uE209){4,}|((...+))[\\cB\\W\\D\\n-\\u00C2]??/m; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=211; tryItOut("(window);");
/*fuzzSeed-159544250*/count=212; tryItOut("m0.has(this.i2);");
/*fuzzSeed-159544250*/count=213; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.imul(( + ( + (Math.fround((2**53-2 >= x)) ** Math.fround(((( + (x | 0)) | 0) % Math.sqrt((y >>> 0))))))), (Math.acos(( + Math.atan2(( + y), -0x100000001))) || (x | 0)))); }); testMathyFunction(mathy2, [1/0, -Number.MAX_VALUE, -1/0, -(2**53-2), -0, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, -(2**53), -0x0ffffffff, 0.000000000000001, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000000, 0, -0x07fffffff, 1.7976931348623157e308, -0x100000001, 0x07fffffff, 2**53, 42, 1, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, 0x080000000, Math.PI, 2**53+2]); ");
/*fuzzSeed-159544250*/count=214; tryItOut("\"use strict\"; a2.splice(3, (b = false), p0, g0.h0);");
/*fuzzSeed-159544250*/count=215; tryItOut("");
/*fuzzSeed-159544250*/count=216; tryItOut("s1 = '';");
/*fuzzSeed-159544250*/count=217; tryItOut("mathy3 = (function(x, y) { return ( + ( + ( + mathy0(( ~ (((x >>> 0) / (mathy2((Math.clz32(y) >>> 0), (x ? y : x)) >>> 0)) >>> 0)), ( - (Math.imul((Math.PI | 0), (x | 0)) | 0)))))); }); testMathyFunction(mathy3, [2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, 1/0, 42, Math.PI, Number.MIN_VALUE, -(2**53), 1, 0, 0x080000000, -0, -0x080000001, 2**53, Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), -0x100000000, 0x100000000, 0x100000001, 0x07fffffff, 0/0, -0x100000001, 0x080000001, -Number.MIN_VALUE, 2**53-2, -(2**53+2), -1/0, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-159544250*/count=218; tryItOut("switch((4277)\u000c.unshift(x, [z1,,])) { case 3:  }");
/*fuzzSeed-159544250*/count=219; tryItOut("\"use strict\"; g0.__proto__ = i1;");
/*fuzzSeed-159544250*/count=220; tryItOut("print(uneval(g0));");
/*fuzzSeed-159544250*/count=221; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1{1,4}\", \"gim\"); var s = \"\"; print(s.replace(r, true)); ");
/*fuzzSeed-159544250*/count=222; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?:\\\\3))|(?=.^\\\\3{1,}{4194305,4227074})?(?!\\\\s)\", \"gi\"); var s = \"0\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=223; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + (Math.atan2(((Math.acos(Math.fround(( + Math.cos(( + ((Math.fround(x) || (y | 0)) | 0)))))) >>> 0) | 0), (Math.fround(( ~ Math.clz32(( + Math.abs(( + y)))))) | 0)) | 0)); }); testMathyFunction(mathy0, [-0x0ffffffff, 1/0, 0x07fffffff, -1/0, -Number.MAX_VALUE, 1, -(2**53-2), -(2**53+2), -0x100000001, Number.MAX_VALUE, -0x080000000, 0.000000000000001, 0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 0/0, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, Number.MIN_VALUE, 0x080000000, 42, 2**53, 0, -(2**53), 2**53+2, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000001]); ");
/*fuzzSeed-159544250*/count=224; tryItOut("/*infloop*/while((x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: function() { return []; }, keys: /*wrap3*/(function(){ var wbfihw = this; ((new Function(\"(y);\")))(); }), }; })(x), \"\\u1C4D\"))){m2.has(o1);print(x); }");
/*fuzzSeed-159544250*/count=225; tryItOut("m0.get(o0.t0);");
/*fuzzSeed-159544250*/count=226; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-159544250*/count=227; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[ /x/ , x,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, ((void options('strict'))), ((void options('strict'))), x, x, x, ((void options('strict'))),  /x/ , x]); ");
/*fuzzSeed-159544250*/count=228; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.min(( + (Math.trunc(Math.fround(x)) > mathy1(( + Math.sqrt(x)), Math.fround(x)))), ( + (( + y) !== Math.max(( + Math.atan2(0x080000000, Math.fround((Math.acos((x >>> 0)) >>> 0)))), Number.MIN_VALUE))))) >>> 0) << (mathy0(mathy0(x, (mathy0(y, x) + -(2**53+2))), (Math.imul((Math.cosh(Math.fround(Math.log10(Math.fround(x)))) >>> 0), (Math.max(( + Math.trunc(mathy1(Math.fround(( + -0x080000001)), y))), ( ~ x)) >>> 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [null, [0], true, [], 0.1, NaN, objectEmulatingUndefined(), /0/, 1, ({valueOf:function(){return 0;}}), 0, (new Number(0)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '', '/0/', (function(){return 0;}), '\\0', -0, (new Boolean(true)), undefined, '0', (new Number(-0)), false, (new Boolean(false)), (new String(''))]); ");
/*fuzzSeed-159544250*/count=229; tryItOut("\"use strict\"; h1.fix = g1.f0;");
/*fuzzSeed-159544250*/count=230; tryItOut("\"use asm\"; testMathyFunction(mathy5, [Number.MAX_VALUE, -Number.MIN_VALUE, 42, 0x07fffffff, 0x080000000, Number.MIN_VALUE, -0, -1/0, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 2**53+2, 1/0, -(2**53), -0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 0/0, -0x080000001, 0x080000001, 1, 0.000000000000001, 0, 2**53, -Number.MAX_VALUE, -0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=231; tryItOut("\"use strict\"; for (var v of b0) { try { t2 = new Uint32Array(b0, 24, [z1]); } catch(e0) { } try { selectforgc(o0); } catch(e1) { } m0.__proto__ = g2.a0; }");
/*fuzzSeed-159544250*/count=232; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.fround(Math.pow((x << 0.000000000000001), (( ~ Math.fround(( ! x))) >>> 0))) ^ (Math.tan((( + Math.min(((( + 1.7976931348623157e308) >>> x) >>> 0), ( + (x != y)))) >>> 0)) >>> 0)) / ( + Math.log(Math.imul((Math.pow(y, ((((mathy0(y, -Number.MIN_VALUE) | 0) + x) | 0) | 0)) | 0), (Math.log(Math.max(x, (x | 0))) | 0))))); }); ");
/*fuzzSeed-159544250*/count=233; tryItOut("/*RXUB*/var r = this.r0; var s = this.s0; print(s.split(r)); ");
/*fuzzSeed-159544250*/count=234; tryItOut("mathy4 = (function(x, y) { return Math.cbrt(Math.tanh(Math.cbrt(( ~ y)))); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), (new Boolean(false)), '\\0', ({toString:function(){return '0';}}), 0, /0/, [0], [], undefined, 0.1, (new Number(-0)), NaN, false, (function(){return 0;}), 1, (new Number(0)), (new String('')), -0, true, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '0', '/0/', null, (new Boolean(true)), '']); ");
/*fuzzSeed-159544250*/count=235; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.tan(Math.min((Math.cbrt((((( + 42) | 0) / Math.fround(Math.trunc((x >>> 0)))) != Math.max(y, (y | 0)))) >>> 0), ( + ( - Math.clz32((x && y)))))); }); testMathyFunction(mathy0, [0x100000001, -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 42, 0.000000000000001, -0x100000001, -0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -(2**53-2), 1/0, 0x080000001, 0x07fffffff, 0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, 0, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, -1/0, Math.PI, -0x0ffffffff, -0, Number.MIN_VALUE, 2**53, 1, 2**53-2, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=236; tryItOut("(void schedulegc(o0.g1));");
/*fuzzSeed-159544250*/count=237; tryItOut("selectforgc(o2);");
/*fuzzSeed-159544250*/count=238; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.pow(( + mathy2(( + Math.log2(( + x))), ( + (Math.acos(( + 2**53-2)) | 0)))), ((/* no regression tests found */ | 0) ? (0x07fffffff , (((x >>> 0) ? ( + y) : Math.fround(y)) >>> 0)) : x)) ? Math.min(((( - Math.fround(( + ( - ( + Math.tan(x)))))) != y) | 0), Math.imul((( + mathy2(-Number.MAX_SAFE_INTEGER, (0.000000000000001 >>> 0))) === ( + mathy2((x >>> 0), (x >>> 0)))), Math.fround(Math.round(Math.fround(( + Math.max(( + (Math.sin((x | 0)) >>> 0)), ( + Math.fround((Math.fround(y) + Math.fround(-Number.MAX_VALUE))))))))))) : (Math.fround(Math.hypot(( + (Math.expm1((Math.fround(Math.log(/(?=(?!(?=([^]){17,}))\\w)/gyim)) ? (Math.pow((y >>> 0), (y >>> 0)) >>> 0) : x)) | 0)), ( + (Math.pow(((Math.round((x && 0x0ffffffff)) | 0) >>> 0), 0) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy4, [Math.PI, 2**53-2, 1/0, 42, 0x100000001, 0x07fffffff, 1.7976931348623157e308, 0x0ffffffff, -0, 2**53+2, 1, -0x080000000, 0.000000000000001, 2**53, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), 0x080000000, -(2**53), 0/0, -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -0x100000001, -1/0, 0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=239; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.cbrt(Math.fround(Math.atan(Math.sign(( + Math.imul(1/0, (x >= x)))))))); }); testMathyFunction(mathy1, [(new Number(-0)), (new Boolean(false)), false, '/0/', '\\0', 0, 1, [], '0', ({valueOf:function(){return 0;}}), (new String('')), [0], 0.1, undefined, null, (function(){return 0;}), true, NaN, /0/, '', ({toString:function(){return '0';}}), (new Boolean(true)), objectEmulatingUndefined(), (new Number(0)), ({valueOf:function(){return '0';}}), -0]); ");
/*fuzzSeed-159544250*/count=240; tryItOut("\"use strict\"; \"use asm\"; /*iii*/print(-6);/*hhh*/function smyegl(\u3056, ...eval){/*RXUB*/var r = this.o2.r1; var s = true; print(s.replace(r, 'x', \"g\")); print(r.lastIndex); }");
/*fuzzSeed-159544250*/count=241; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.trunc(Math.asinh(( + Math.clz32(Math.fround(mathy0(( + mathy0(( + ((Math.fround(x) < Math.fround(-Number.MIN_SAFE_INTEGER)) | 0)), y)), ( + mathy1(y, Math.fround(( ! -0x080000000)))))))))) | 0); }); testMathyFunction(mathy2, [0/0, 0x0ffffffff, 2**53, -0x0ffffffff, -0x080000000, 0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, -0x100000001, Number.MIN_VALUE, 0x100000001, 0x080000001, 2**53+2, Math.PI, -1/0, -0x100000000, -(2**53-2), 0, -(2**53), -Number.MAX_VALUE, -(2**53+2), 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, 42, 1, -0, Number.MAX_VALUE, -0x07fffffff, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=242; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=243; tryItOut("\"use strict\"; p2.toSource = (function() { o1.valueOf = f1; return g0.e1; });");
/*fuzzSeed-159544250*/count=244; tryItOut("v1 = r2.constructor;");
/*fuzzSeed-159544250*/count=245; tryItOut("/*RXUB*/var r = r1; var s = s2; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=246; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( - (mathy3((Math.asinh(Math.pow((y >>> 0), (mathy2(( - y), Math.asin(x)) >>> 0))) >>> 0), Math.fround((Math.fround((Math.log1p(mathy0(Math.fround(Math.atanh(Math.fround(y))), 0x07fffffff)) | 0)) ? Math.fround(( + ( + (mathy0((( ~ y) >>> 0), ((( - x) >>> 0) >>> 0)) >>> 0)))) : Math.fround(y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000001, -0, 0x080000000, 0x100000000, 2**53, 0x0ffffffff, -0x0ffffffff, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 2**53-2, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, 0/0, 42, 1, 0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -(2**53+2), 0x100000001, -0x080000001, -0x07fffffff, -0x100000000, -(2**53), 0x080000001]); ");
/*fuzzSeed-159544250*/count=247; tryItOut("testMathyFunction(mathy1, [0x100000001, 0x07fffffff, -Number.MIN_VALUE, 1, 0/0, -(2**53-2), 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 2**53, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, -0, 0, Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, -1/0, 2**53-2, 0x0ffffffff, -0x07fffffff, -(2**53), -0x100000000, -0x080000000, -0x0ffffffff, 0x080000000, 42]); ");
/*fuzzSeed-159544250*/count=248; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(g1.a0, 18, { configurable: ((x = [,,]) ? throw -22 : Math.tanh(new RegExp(\"((?![^])|.\\u84ed*{2}){3,}|\\u0011\", \"\"))), enumerable: false, writable: true, value: o2 });");
/*fuzzSeed-159544250*/count=249; tryItOut("for(let b in \u0009x) print(b);");
/*fuzzSeed-159544250*/count=250; tryItOut("mathy0 = (function(x, y) { return ((( - ( + Math.atan2(( + Number.MIN_SAFE_INTEGER), Math.pow(Math.hypot(y, (-0x0ffffffff - y)), Math.min(x, ( + ( - ( + x)))))))) | (( - x) | 0)) == ( + Math.acosh(Math.fround(Math.tan(x))))); }); testMathyFunction(mathy0, [2**53, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, 0x0ffffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), 42, -0x100000000, -0x07fffffff, 2**53+2, -0x080000000, 0x07fffffff, -1/0, -0x080000001, 0/0, 1, 0x100000001, 1.7976931348623157e308, -0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, 0, 0x100000000, Math.PI, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=251; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return mathy1(mathy3((Math.min(2**53-2, (x === (((Math.log1p(x) | 0) / ( + -0)) >>> 0))) && (((mathy1((y | 0), (x | 0)) | 0) == x) > (Math.imul(((Math.fround(y) ? Math.fround(x) : y) | 0), 1) | 0))), (( ! (Math.ceil(( + y)) >>> 0)) & (Math.fround(( + ( + mathy4(-0x080000001, y)))) | 0))), Math.fround(Math.fround(( ~ Math.fround(mathy2(Math.atan(Math.fround(Math.fround(( - ( + ( ! ( + -(2**53-2)))))))), ( + mathy3(( + (Math.max((x >>> (-Number.MIN_SAFE_INTEGER >>> 0)), Math.atan2(Number.MIN_SAFE_INTEGER, x)) >>> 0)), ( + Math.fround(Math.fround((( + x) / mathy0(-Number.MIN_SAFE_INTEGER, x))))))))))))); }); ");
/*fuzzSeed-159544250*/count=252; tryItOut("this.t0[19] = g2.m0;");
/*fuzzSeed-159544250*/count=253; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=254; tryItOut("\"use strict\"; o1.t0 = new Int16Array(b2);");
/*fuzzSeed-159544250*/count=255; tryItOut("/*tLoop*/for (let y of /*MARR*/[-0x07fffffff, NaN, function(){}, -0x07fffffff, function(){}, true, true, function(){}, function(){}, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, Number.MAX_VALUE, NaN, -0x07fffffff, -0x07fffffff, Number.MAX_VALUE]) { \n(let (x =  \"\" , qnibxv, btmqdl, odsycm, eval, dvsppx, khxway, fawmij) (4277)); }");
/*fuzzSeed-159544250*/count=256; tryItOut("\"use strict\"; Array.prototype.pop.call(a1, a2, (x = var wymlkn = new SharedArrayBuffer(4); var wymlkn_0 = new Int32Array(wymlkn); wymlkn_0[0] = -26; print(x)), p2, this.s0);");
/*fuzzSeed-159544250*/count=257; tryItOut("o0 = m2.__proto__;");
/*fuzzSeed-159544250*/count=258; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    i0 = ((((let (cfnvuk, dgzops, pempdd, ttxdzz, jeqeel, e, x, x, yuoijk) window.watch(\"fontsize\", \u0009encodeURI))-((0x76ab8720)))>>>((i0)*-0x510f8)));\n    switch (((((0x73616d7e) > (0xe8364754))) ^ ((0xffffffff)-(0xbdba4941)-(0xf92b6997)))) {\n      case 1:\n        d1 = (+(-1.0/0.0));\n        break;\n    }\n    return (((0xffcb9a36)-((i0) ? (0xf9539ff2) : (/*FFI*/ff(((~~(d1))), ((1.0009765625)), ((d1)), ((~~(+(1.0/0.0)))), ((Infinity)), ((-1048577.0)), ((3.777893186295716e+22)))|0))))|0;\n    d1 = (d1);\n    d1 = (+/*FFI*/ff((((((\"\u03a0\"))) | ((!((0x390138c8)))+(0xfb8e9d7d)))), ((((((-0x6401c*(0xb6fcf65)) & ((0x5106f945) % (0x243063c8))))-(/*FFI*/ff()|0)) >> ((!(((-(0x7b6a1eae))>>>((-0x8000000) % (0x7fffffff)))))+((((0xbd0de6b6))|0) > ((0xfffff*(0xfdd9ee0b)) ^ ((0xa7211d2)+(0x4fac992f))))))), ((-1025.0)), (((-0x533bf*(i0))|0)), ((((i0)-((0xf2bd1ad9) <= (0x0))) | (((0xfcfd9588) ? (0xf91dedd0) : (0x7b654293))))), ((NaN)), ((Infinity)), ((((0x2fce0e8d)) ^ ((0xb6425b09)))), ((((-36028797018963970.0)) / ((3.0)))), ((7.0)), ((1.5111572745182865e+23)), ((140737488355329.0)), ((-2049.0)), ((34359738369.0)), ((-1.1805916207174113e+21))));\n    (Int32ArrayView[1]) = ((((( \"\" )+(i0)-(i0))>>>((/*FFI*/ff()|0)-((0xffffffff)))) <= (0xdd5a6f81)));\n    (Int16ArrayView[((Int32ArrayView[(((!(0x6cb2e0c0)) ? (0xd7ebfbdb) : ((0xefba08ea) == (0x7ddbdc52)))) >> 2])) >> 1]) = (((0xf5974da3) ? ((i0) ? (0xfa046dd) : (0xfab5686c)) : ((((0x508c7285)-(0xc926fb1)) >> (((0x6b5b52e3) == (0x6ebbf12)))) == ((((-0x4c26142) < (-0x2c0ec56))) ^ ((0x4f476b25)+(0xbc38ca36)))))-((((0x4e97673d) % (abs((((0xffffffff)) >> ((0x1adfffee))))|0))>>>(0xb8286*(/*FFI*/ff(((abs((((0xb6922039))|0))|0)), ((((0xcb96a136)) ^ ((0x4c48f1ef)))), ((-1073741825.0)), ((7.555786372591432e+22)), ((-1.888946593147858e+22)), ((-2251799813685249.0)), ((73786976294838210000.0)), ((-8796093022209.0)), ((-129.0)), ((4294967295.0)))|0))) < (((i0)*0x4318e)>>>((!(i0))+(/*FFI*/ff(((+(-1.0/0.0))), ((67108863.0)), ((3.094850098213451e+26)), ((2251799813685249.0)), ((2199023255552.0)))|0)-(0xfb6dce54))))-(i0));\n    d1 = (d1);\n    return ((((+atan2(((2.3611832414348226e+21)), ((((((2.4178516392292583e+24)) - ((-0.5)))) / (((4277))))))) < (+abs(((((Infinity)) * ((d1)))))))+(i0)-(0x12eeb484)))|0;\n  }\n  return f; })(this, {ff: (void shapeOf(5))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -1/0, -(2**53+2), -(2**53-2), Number.MIN_VALUE, -0x100000000, 1, Number.MAX_SAFE_INTEGER, -0, -0x080000000, 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -(2**53), 0.000000000000001, -Number.MAX_SAFE_INTEGER, Math.PI, 0x0ffffffff, -0x080000001, -0x07fffffff, 1/0, -Number.MAX_VALUE, 0x080000001, 2**53-2, 42, 2**53+2, 0x100000001, -0x100000001, 0x080000000, 0]); ");
/*fuzzSeed-159544250*/count=259; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ((Math.cbrt(2**53) ? Math.fround((Math.acosh((x >>> 0)) >>> 0)) : ( - y)) < Math.atan2((( + Math.fround(x)) >>> 0), ( + x)))); }); ");
/*fuzzSeed-159544250*/count=260; tryItOut("/*infloop*/for(var x in ((function(q) { return q; })('fafafa'.replace(/a/g, arguments.callee))))g2.v0 = g2.runOffThreadScript();");
/*fuzzSeed-159544250*/count=261; tryItOut("a1.__proto__ = b0;");
/*fuzzSeed-159544250*/count=262; tryItOut("var {} =  \"\" ;g1.m0.has(o0.o2.v1);");
/*fuzzSeed-159544250*/count=263; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=264; tryItOut("\"use strict\"; v1 = g2.runOffThreadScript();");
/*fuzzSeed-159544250*/count=265; tryItOut("/*infloop*/for(let x = e\u000c; ({eval: new RegExp(\"(?=.)+?[^]{2,}\", \"i\")}); this.__defineGetter__(\"x\", (/*wrap2*/(function(){ var hhnhyp =  /x/g ; var hlucoh = new RegExp(\"(?!(.))(?![^])+[^]{3}(?=.)|(?=\\\\S.(?:[^]))|.*\", \"m\"); return hlucoh;})()).apply)) {([](x = x, new (Symbol.prototype.valueOf)(x, z))); }");
/*fuzzSeed-159544250*/count=266; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((Math.imul((Math.atan2(((x ? Number.MIN_SAFE_INTEGER : ((y / 2**53+2) >>> 0)) >>> 0), (Math.round((Math.hypot(( + Math.fround(x)), 42) | 0)) | 0)) | 0), Math.expm1(x)) | 0) !== (Math.exp((Math.hypot(x, Math.max((Math.fround(Math.sign(x)) > y), x)) | 0)) | 0)); }); testMathyFunction(mathy0, [-0, Number.MIN_VALUE, -0x0ffffffff, 1, 0x100000000, -0x100000000, 2**53-2, 0x100000001, 1/0, 42, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 0.000000000000001, 0x0ffffffff, -0x080000000, 2**53+2, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0, 2**53, -1/0, -(2**53), Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=267; tryItOut("\"use strict\"; m0.has(p2);");
/*fuzzSeed-159544250*/count=268; tryItOut("\"use strict\"; /*RXUB*/var r = /./gm; var s = \"\\n\"; print(r.exec(s)); \nthis.i0 + v0;\nv2 = g1.eval(\"function f1(g1.b1)  { \\\"use strict\\\"; return window } \");\n\n");
/*fuzzSeed-159544250*/count=269; tryItOut("\"use asm\"; g1.a0[12] = g0;");
/*fuzzSeed-159544250*/count=270; tryItOut("t0.set(t0, 3);");
/*fuzzSeed-159544250*/count=271; tryItOut("\"use strict\"; switch(\"\\uC080\") { case 9: v2 = (m2 instanceof o0.g1.h1);break; g0.v1 = Object.prototype.isPrototypeOf.call(p1, o2.h2);break; case 7: print(x);break; case 1: yield;break; case 0: break; default: break; Array.prototype.unshift.apply(a0, [p1, h2, a2, this.t2, m0, b2, this.o2]);break;  }");
/*fuzzSeed-159544250*/count=272; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-159544250*/count=273; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log1p(( + Math.atan(( + mathy2(( + ( + Math.atan2(y, Math.min(( + x), Number.MAX_VALUE)))), mathy2((y >>> 0), (Math.fround(Math.max(Math.fround(y), y)) >>> 0))))))); }); ");
/*fuzzSeed-159544250*/count=274; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.tan(( - (( ! (( + Math.hypot((x === x), (mathy0(Math.min(((Math.exp((x | 0)) | 0) | 0), y), x) >>> 0))) | 0)) >>> 0))); }); ");
/*fuzzSeed-159544250*/count=275; tryItOut("e2.add(o2);");
/*fuzzSeed-159544250*/count=276; tryItOut("/*bLoop*/for (var gyzdiz = 0; gyzdiz < 7; ++gyzdiz) { if (gyzdiz % 6 == 4) { v1 = Object.prototype.isPrototypeOf.call(o2.a1, g2.t0); } else { return /*FARR*/[x,  \"\" , -9,  \"\" ,  '' ].filter(() =>  { \"use strict\"; return \"\\uA6C9\" } , x); }  } ");
/*fuzzSeed-159544250*/count=277; tryItOut("/*tLoop*/for (let d of /*MARR*/[new RegExp(\"([^\\\\dp-v]+\\\\d[^])(?!\\\\b)\", \"gm\"), new Number(1.5), Infinity, new Number(1.5), x, new RegExp(\"([^\\\\dp-v]+\\\\d[^])(?!\\\\b)\", \"gm\"), Infinity, Infinity, new Number(1.5), new Number(1.5), new RegExp(\"([^\\\\dp-v]+\\\\d[^])(?!\\\\b)\", \"gm\"), new RegExp(\"([^\\\\dp-v]+\\\\d[^])(?!\\\\b)\", \"gm\"), Infinity, new Number(1.5), Infinity, Infinity, new Number(1.5), new Number(1.5), x]) { a1.forEach(f2, o2.b1, m1); }");
/*fuzzSeed-159544250*/count=278; tryItOut("mathy1 = (function(x, y) { return Math.expm1(((( + (y << (Math.max(Math.fround(mathy0(x, 42)), Math.fround(y)) | 0))) !== ((((Math.fround(( ! (y >>> 0))) ? x : Math.round(( + ((y >>> 0) ? ( + x) : ( + y))))) ? Math.pow(y, (0x0ffffffff - y)) : Math.fround(Math.fround(((( + (x ? (x >>> 0) : mathy0(Math.fround(x), (y | 0)))) | 0) > (-1/0 ? x : ( + ( ! ( + (Math.min((y >>> 0), (-0x0ffffffff >>> 0)) >>> 0))))))))) | 0) | 0)) | 0)); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -Number.MAX_VALUE, -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, 1/0, -0x080000001, -Number.MIN_VALUE, 2**53-2, 0/0, 2**53+2, -0x07fffffff, -0, Math.PI, 42, 0, 1, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, Number.MAX_VALUE, -0x100000001, -0x080000000, -(2**53), 0.000000000000001, 0x100000001, -0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-159544250*/count=279; tryItOut("\"use strict\"; o1 + '';");
/*fuzzSeed-159544250*/count=280; tryItOut("\"use strict\"; {/*MXX2*/g2.Error.length = g0;/*hhh*/function npbcww(...x){( \"\" );}/*iii*/print((makeFinalizeObserver('tenured'))); }");
/*fuzzSeed-159544250*/count=281; tryItOut("\"use strict\"; v2 = g0.runOffThreadScript();");
/*fuzzSeed-159544250*/count=282; tryItOut("m2 = new Map;");
/*fuzzSeed-159544250*/count=283; tryItOut("mathy1 = (function(x, y) { return (( + ((mathy0(Math.cbrt(((y >> y) | 0)), (y | 0)) | 0) + (Math.atan2(((Math.log2((Math.max((x >= x), ( - Math.fround(x))) >>> 0)) >>> 0) | 0), (Math.hypot(y, Number.MIN_VALUE) | 0)) | 0))) + Math.fround(Math.clz32(Math.round(((Math.log((x | 0)) >>> ( + -(2**53+2))) | 0))))); }); testMathyFunction(mathy1, [0, Number.MIN_VALUE, 2**53-2, 1/0, 0x080000001, -(2**53+2), 1, -(2**53), -(2**53-2), -Number.MIN_VALUE, 42, Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, 0x07fffffff, 0x100000001, 2**53+2, Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, 0x0ffffffff, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, 0x100000000, -0, -1/0, 2**53, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-159544250*/count=284; tryItOut("throw StopIteration;x.stack;");
/*fuzzSeed-159544250*/count=285; tryItOut("const itealc, hllbwg, [] = x, x = timeout(1800), rkivar;/*tLoop*/for (let z of /*MARR*/[[], 0x20000000, 0x20000000,  'A' , 0x20000000, 0x20000000,  '\\0' , [],  'A' , 0x20000000,  'A' , [],  'A' , 0x20000000, 0x20000000,  'A' , 0x20000000,  'A' , [], [], [], [], [], [], [], [], [], [], [], 0x20000000, [], 0x20000000, [], 0x20000000,  'A' ,  'A' , [], [],  'A' ,  'A' ,  'A' , 0x20000000, 0x20000000,  '\\0' ,  '\\0' ,  'A' ,  'A' ,  'A' ,  'A' , [], [], [], [], [], [], [], [], [], [], [], [], [],  'A' ,  'A' , 0x20000000, [],  '\\0' ,  'A' ,  '\\0' , 0x20000000,  'A' , [], [], 0x20000000, [],  '\\0' ,  '\\0' , [], [], [],  '\\0' , [],  'A' ]) { t2.set(a1, 10); }");
/*fuzzSeed-159544250*/count=286; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=287; tryItOut("mathy4 = (function(x, y) { return ( + Math.asinh(Math.fround(Math.pow(Math.fround(Math.expm1((Math.log2(((2**53+2 ? -0 : y) | 0)) | 0))), Math.fround(((((Math.fround(mathy1(Math.imul(x, y), x)) ** ( ~ y)) | 0) < (x | 0)) | 0)))))); }); testMathyFunction(mathy4, /*MARR*/[null, null, 1e4, null, null, null, 1e4, null, 1e4, null, 1e4, null, null, null, null, 1e4, null, 1e4, null, 1e4, 1e4, 1e4, null, 1e4, null, 1e4, 1e4, 1e4, 1e4, null, 1e4, null, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, null, 1e4, null, null, null, 1e4, 1e4, null, null, 1e4, 1e4, 1e4, null, 1e4, null, null, null, 1e4, null, 1e4, 1e4, null, null, 1e4, null, 1e4, 1e4, null, null, 1e4, 1e4, null, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, 1e4, null, null, null, null, 1e4, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 1e4, null, 1e4, null, null, 1e4, 1e4, null, 1e4, 1e4, null, 1e4, null, null, null, null, null, null, 1e4, null, 1e4, null, 1e4, 1e4]); ");
/*fuzzSeed-159544250*/count=288; tryItOut("\"use strict\"; o0.toString = (function() { try { h0.getOwnPropertyDescriptor = this.f1; } catch(e0) { } /*MXX3*/g2.Math.expm1 = g0.Math.expm1; throw g2.h2; });");
/*fuzzSeed-159544250*/count=289; tryItOut("s0 += 'x';");
/*fuzzSeed-159544250*/count=290; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-159544250*/count=291; tryItOut("print(uneval(o2.b1));");
/*fuzzSeed-159544250*/count=292; tryItOut("for (var v of o2) { try { m2.set(b1, o1); } catch(e0) { } try { for (var p in s2) { try { t0 = new Int8Array(b1, 80, v1); } catch(e0) { } /*RXUB*/var r = r2; var s = \"\\n\"; print(s.match(r));  } } catch(e1) { } try { t1 = new Float32Array(b1); } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(e0, o1); }");
/*fuzzSeed-159544250*/count=293; tryItOut("/*oLoop*/for (npnxgi = 0; npnxgi < 3; ++npnxgi) { o0.v1 = t0[\"length\"]; } ");
/*fuzzSeed-159544250*/count=294; tryItOut("/*ODP-1*/Object.defineProperty(h1, \"abs\", ({configurable: (x % 3 == 1)}));");
/*fuzzSeed-159544250*/count=295; tryItOut("g2 = a2[13];");
/*fuzzSeed-159544250*/count=296; tryItOut("\"use strict\"; var koplbb = new ArrayBuffer(8); var koplbb_0 = new Int16Array(koplbb); var koplbb_1 = new Float32Array(koplbb); print(koplbb_1[0]); koplbb_1[0] = -27; var koplbb_2 = new Int16Array(koplbb); koplbb_2[0] = 22; g2.e2.delete(p0);v0 = evalcx(\"function f0(o1.h1)  { print((4277)); } \", g1);g2.a0.unshift(v0, m1, m0, a0);/*oLoop*/for (var plqtmm = 0; plqtmm < 14; ++plqtmm) { print(koplbb_0); } s0 += 'x';this.t0[koplbb_1];i2 = m0.entries;");
/*fuzzSeed-159544250*/count=297; tryItOut("/*MXX1*/this.o0 = g2.DataView.prototype.getFloat32;function z(x, eval, ...window) { return new ((([] = x)))((new SyntaxError(/\\2*/yim, [z1,,])),  /x/ ) } for (var v of o0.p1) { try { a1 + ''; } catch(e0) { } try { r0 = new RegExp(\"([^].?\\\\B+?){0,4}|(?:(?=[^].+))*?\", \"\"); } catch(e1) { } try { print(v1); } catch(e2) { } g2.offThreadCompileScript(\"function f0(g2.i1)  { (g2.i1.unwatch(\\\"toString\\\")); } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 5 == 4), noScriptRval: Math.max(this, \"\\uD227\"), sourceIsLazy: (x % 6 != 1), catchTermination: true })); }");
/*fuzzSeed-159544250*/count=298; tryItOut("i1.send(e2);");
/*fuzzSeed-159544250*/count=299; tryItOut("let (b) { this.t1 = new Uint32Array(11); }");
/*fuzzSeed-159544250*/count=300; tryItOut("a1[({valueOf: function() { v2 = (v1 instanceof i0);return 19; }})] = -16;\n \"\" ;\n");
/*fuzzSeed-159544250*/count=301; tryItOut("\"use strict\"; \"use asm\"; (void schedulegc(g1));\nv0 = o2.t2.byteOffset;\n");
/*fuzzSeed-159544250*/count=302; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.asin(( ~ Math.fround((Math.fround((y ? x : y)) ^ Math.fround(( - (((y >= Math.fround(Math.min(x, x))) >>> 0) / Math.fround(mathy0(y, (2**53-2 | 0))))))))))); }); testMathyFunction(mathy4, [-(2**53), -0x100000000, Number.MAX_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 0, 1, 0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, 0x100000000, 2**53-2, Number.MIN_VALUE, -1/0, -Number.MIN_VALUE, 0x07fffffff, -0, -0x100000001, 0/0, 1/0, -(2**53-2), 0.000000000000001, -0x07fffffff, Number.MAX_VALUE, 2**53+2, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, 0x080000001, -Number.MAX_VALUE, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=303; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2\", \"m\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=304; tryItOut("throw x;");
/*fuzzSeed-159544250*/count=305; tryItOut("mathy3 = (function(x, y) { return (mathy0((Math.log10(Math.hypot(y, x)) >>> 0), ( + mathy1(Math.max(mathy2(mathy2(y, y), y), Math.atan2(Math.fround(x), Math.atan2(y, y))), Math.pow(Math.pow(( ! x), Number.MIN_SAFE_INTEGER), (y >>> 0))))) | 0); }); testMathyFunction(mathy3, [Math.PI, 0x080000001, 2**53-2, -0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), -Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, 42, 1, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 1/0, 0.000000000000001, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -0x0ffffffff, 0, 1.7976931348623157e308, 0x080000000, -(2**53-2), -Number.MAX_VALUE, -(2**53), 2**53+2, -0x080000000, Number.MAX_VALUE, -0x100000001, 2**53, -0x07fffffff, 0/0]); ");
/*fuzzSeed-159544250*/count=306; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=307; tryItOut("m1 = new Map;i0.next();");
/*fuzzSeed-159544250*/count=308; tryItOut("\"use strict\"; g0.h0.has = this.f2;");
/*fuzzSeed-159544250*/count=309; tryItOut("{ void 0; void gc('compartment'); }");
/*fuzzSeed-159544250*/count=310; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = r2; var s = s2; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=311; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -4611686018427388000.0;\n    {\n      {\n        {\n          return +((Float32ArrayView[(((~~(((+pow(((d1)), ((36893488147419103000.0))))) % ((d1)))))) >> 2]));\n        }\n      }\n    }\n    d1 = (d2);\n    i0 = ((a = x) > (+(0xc15b1c69)));\n    (Float32ArrayView[4096]) = ((+(1.0/0.0)));\n    i0 = ((34359738369.0) <= (d2));\n    d1 = (x);\n    d2 = (d2);\n    /*FFI*/ff(((abs((0x1cba0923))|0)), ((d2)));\n    d1 = (d2);\n    switch (((-((9223372036854776000.0) > (262145.0))) ^ (((0xfbf140cb) ? (0x8468fb67) : (0xfbaf1e76))))) {\n      case -3:\n        d1 = (+(0x1c881cc0));\n    }\n    return +((((((+((+/*FFI*/ff(((d1)), ((d2)), ((0x5de93170)), ((((0xfe54ec46)) ^ ((0xf97c9804)))), ((-0.5)), ((17179869184.0)), ((1.001953125)), ((524289.0)), ((2251799813685249.0)), ((3.0)), ((-9.0)), ((1.03125))))))) * ((d2)))) % ((d2))));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var rdqdks = (p={}, (p.z = undefined)()); var uirzzb = /*wrap1*/(function(){ print(this.h2);return eval =  /x/g })(); return uirzzb;})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, ['/0/', /0/, ({valueOf:function(){return '0';}}), (new Number(-0)), '0', null, 0, '\\0', 1, false, true, ({toString:function(){return '0';}}), undefined, NaN, 0.1, (function(){return 0;}), ({valueOf:function(){return 0;}}), [], objectEmulatingUndefined(), (new Boolean(false)), (new Number(0)), [0], '', (new String('')), (new Boolean(true)), -0]); ");
/*fuzzSeed-159544250*/count=312; tryItOut("\"use strict\"; print(function(y) { yield y; s2 += this.s1;; yield y; });");
/*fuzzSeed-159544250*/count=313; tryItOut("mathy2 = (function(x, y) { return Math.log10(Math.pow(Math.fround(Math.cbrt(Math.fround(Math.asin((Math.atan2((x | 0), (y | 0)) | 0))))), ( - (( + Math.tan(( + (x !== 0x080000001)))) ** -Number.MIN_VALUE)))); }); testMathyFunction(mathy2, [0, -0x100000000, 1.7976931348623157e308, 0x100000000, -(2**53+2), -Number.MIN_VALUE, 1/0, Math.PI, -Number.MAX_VALUE, -1/0, 0.000000000000001, Number.MAX_VALUE, 0x080000001, 0x07fffffff, 0/0, 0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, 1, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -0, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -0x0ffffffff, 0x080000000, 2**53-2, 0x0ffffffff, 2**53, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=314; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i0 = ((i1) ? (i1) : (i0));\n    {\n      return +((+abs((((x) ? (((-((+(0.0/0.0))))) * ((-3.022314549036573e+23))) : (-((+((-36028797018963970.0))))))))));\n    }\n    {\n      i1 = (i1);\n    }\n    i1 = (i1);\n    (Float32ArrayView[((i0)-((/*FFI*/ff()|0) ? ((-1048577.0) != (-4194304.0)) : (i0))+((+(0.0/0.0)) >= (4398046511103.0))) >> 2]) = ((+/*FFI*/ff(((abs((((((((-35184372088833.0) <= (144115188075855870.0)))|0) == (abs((((-0x8000000)) & ((0xaaaf0d4b))))|0))-(i1)-((imul((0x7d52c705), (0xfe0b7efa))|0) != (((i0))|0))) | ((/*FFI*/ff(((-134217729.0)))|0)*0x88d00)))|0)), ((~~(+(1.0/0.0)))), ((((Int32ArrayView[(((imul((0xf8c85197), (0xffffffff))|0))+(i1)) >> 2]))|0)), ((imul((i0), ((-2.4178516392292583e+24) != (32767.0)))|0)))));\n    i1 = ((+atan2(((+(0xc77a600c))), ((+(0xc20700b6))))) > (Infinity));\n    i0 = (i1);\n    return +((+(0.0/0.0)));\n    i1 = (i1);\n    i1 = (i1);\n    {\n      i0 = (0x69f1c66c);\n    }\n    i0 = (i1);\n    {\n      {\n        i0 = (i1);\n      }\n    }\n    i1 = (!(i0));\n    return +((-73786976294838210000.0));\n  }\n  return f; })(this, {ff: Symbol.prototype.valueOf}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [false, 1, /0/, (function(){return 0;}), 0.1, (new String('')), ({valueOf:function(){return 0;}}), [0], '', NaN, true, '/0/', (new Boolean(false)), '\\0', -0, [], (new Number(0)), ({valueOf:function(){return '0';}}), (new Boolean(true)), objectEmulatingUndefined(), 0, ({toString:function(){return '0';}}), undefined, (new Number(-0)), null, '0']); ");
/*fuzzSeed-159544250*/count=315; tryItOut("mathy5 = (function(x, y) { return (( ! ( + ((Math.ceil(mathy2(( + Math.cosh(( + ( - x)))), ( + Math.atan2(( + x), (Math.max(y, y) >>> 0))))) >>> 0) ** (Math.expm1(Math.fround(Math.pow(( + x), (y | 0)))) >>> 0)))) >>> 0); }); testMathyFunction(mathy5, [-0x100000001, -(2**53), -Number.MAX_VALUE, 42, -0x07fffffff, -0x080000001, 2**53, -0x080000000, Math.PI, 0x100000000, -0x100000000, 0x07fffffff, 1/0, 2**53+2, -Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 0.000000000000001, 0x080000001, -(2**53+2), 2**53-2, -0, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -(2**53-2), Number.MAX_VALUE, 0x080000000, 0x100000001]); ");
/*fuzzSeed-159544250*/count=316; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=317; tryItOut("v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: Math.sinh((void options('strict_mode'))), noScriptRval: Number.MIN_SAFE_INTEGER, sourceIsLazy: (x % 29 != 11), catchTermination: true }));");
/*fuzzSeed-159544250*/count=318; tryItOut("/*MXX2*/g0.ArrayBuffer.isView = g0.o1.m1;");
/*fuzzSeed-159544250*/count=319; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ! Math.min(Math.max(Math.ceil((Number.MAX_SAFE_INTEGER | 0)), (Math.log10(x) >>> 0)), Math.fround(Math.imul(Math.fround((mathy3((y | 0), (y | 0)) | 0)), Math.fround(-0x07fffffff))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0, -(2**53), 0x07fffffff, Number.MAX_VALUE, 42, -0x080000001, -0x0ffffffff, 0.000000000000001, 0x100000001, -0, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 0x0ffffffff, -1/0, -0x080000000, 1/0, 1, 2**53, 0x080000000, 0/0, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, -(2**53-2), -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-159544250*/count=320; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ((uneval((uneval(let (d = NaN) window)))) / Math.imul(( + Math.atan(Math.fround(((( ! (y | 0)) | 0) <= (Math.max(((( + 0x080000001) * ( + -Number.MAX_SAFE_INTEGER)) >>> 0), Math.fround(y)) >>> 0))))), ( + Math.fround(Math.fround(Math.fround(((Math.ceil((x | 0)) | 0) , (((-Number.MAX_VALUE | 0) / x) + x))))))))); }); testMathyFunction(mathy0, [0/0, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 0x07fffffff, 0.000000000000001, -(2**53), -Number.MAX_VALUE, 1/0, 2**53-2, -0x100000001, -Number.MIN_VALUE, -1/0, 0, -0x080000001, -(2**53-2), 2**53+2, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -0x0ffffffff, 0x080000001, -0x07fffffff, 42, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, Math.PI, -(2**53+2), Number.MIN_VALUE, -0, 1]); ");
/*fuzzSeed-159544250*/count=321; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + ( ~ ( + ( + ( + ( ! ( + (Math.pow((Number.MAX_VALUE >>> 0), ((( ! x) ? ( + Math.hypot(x, ( + -(2**53-2)))) : ( + ( ~ x))) >>> 0)) >>> 0)))))))) || ( + ( - ( + Math.fround(( + Math.fround((Math.pow(Math.abs(x), x) | 0)))))))); }); testMathyFunction(mathy2, [-(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, -0, 0x100000001, 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -1/0, -0x0ffffffff, 0x080000001, 1, Math.PI, -0x100000001, -(2**53+2), -0x100000000, 0/0, 0.000000000000001, 0x100000000, 0x080000000, 2**53, 42, 0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, 0, Number.MAX_VALUE, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=322; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=323; tryItOut("m1.has(a2);");
/*fuzzSeed-159544250*/count=324; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\u36dF?(:))(?!\\\\\\u226b{4}|.){2,4}+\", \"gim\"); var s = \"\\u36df:\\u226b\\u226b\\u226b\\u226b\\u226b\\u36df:\\u226b\\u226b\\u226b\\u226b\\u226b\\u36df:\\u226b\\u226b\\u226b\\u226b\\u226b\\u36df:\\u226b\\u226b\\u226b\\u226b\\u226b\\u36df:\\u226b\\u226b\\u226b\\u226b\\u226b\\u36df:\\u226b\\u226b\\u226b\\u226b\\u226b\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=325; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-159544250*/count=326; tryItOut("print(a0);");
/*fuzzSeed-159544250*/count=327; tryItOut("/*oLoop*/for (let dskrsi = 0; dskrsi < 60; ++dskrsi) { print(\"\\u7500\"); } ");
/*fuzzSeed-159544250*/count=328; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.asinh((Math.cos((Math.abs((( + Math.fround(( ! ( + (x !== (y | 0)))))) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), -0, false, ({valueOf:function(){return 0;}}), '/0/', (new Boolean(true)), [0], NaN, undefined, '', (new Number(0)), 0, 1, 0.1, null, [], (new String('')), ({toString:function(){return '0';}}), /0/, objectEmulatingUndefined(), (new Number(-0)), '\\0', true, (function(){return 0;}), (new Boolean(false)), '0']); ");
/*fuzzSeed-159544250*/count=329; tryItOut("\"use strict\"; /*RXUB*/var r = /((?![\\cQ\\u0070-\u2b4d\\u00Ac-\u00ce]+))?/yi; var s = \"\\u00ad\\u00ad\\u00ad\\u00ad\\u00ad\\u00ad\"; print(r.exec(s)); print(r.lastIndex); \n");
/*fuzzSeed-159544250*/count=330; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return ((((Math.tan((2**53 >>> 0)) >>> 0) ? Math.fround(( ~ Math.fround(( + Math.imul(Math.fround(( ~ y)), x))))) : ((mathy0(y, (y | 0)) ? ( + ( + (((( - x) >>> 0) ? -Number.MAX_SAFE_INTEGER : (y >>> 0)) >>> 0))) : Math.log10(Math.fround((Math.fround(( ~ y)) ^ Math.fround(( + (( + x) || ( + x)))))))) | 0)) <= Math.atan2((mathy0((mathy1(x, Math.fround(((((2**53 | 0) - (y | 0)) | 0) < ( + 1.7976931348623157e308)))) | 0), 1/0) | 0), (mathy0((( ! x) | 0), mathy1(( + mathy0(Math.fround(Math.hypot(Math.fround(y), -Number.MIN_SAFE_INTEGER)), x)), ( + (( - (Math.asinh(x) >>> 0)) >>> 0)))) | 0))) >>> 0); }); testMathyFunction(mathy2, [-0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000000, 42, Number.MIN_SAFE_INTEGER, 1/0, Math.PI, -(2**53+2), 1, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, Number.MAX_VALUE, -0, Number.MIN_VALUE, -0x080000001, 0x080000001, -(2**53), 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, 0, 0x100000000, -1/0, 0/0, 2**53, 2**53-2, 0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, -(2**53-2), 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=331; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + Math.max(Math.acosh(( - Math.fround(Math.hypot(Math.fround(( - (x >>> 0))), x)))), ( + ( - ((((mathy2((( + (y | 0)) | 0), (y | 0)) | 0) >>> 0) <= ( + ( ~ (Math.fround(Math.atan(mathy0(x, x))) | 0)))) >>> 0))))) >>> 0); }); testMathyFunction(mathy5, [(new Number(0)), -0, (function(){return 0;}), /0/, ({valueOf:function(){return 0;}}), true, '\\0', ({valueOf:function(){return '0';}}), undefined, null, '', 1, (new Number(-0)), (new Boolean(true)), 0.1, (new Boolean(false)), (new String('')), ({toString:function(){return '0';}}), [0], [], '0', objectEmulatingUndefined(), 0, '/0/', NaN, false]); ");
/*fuzzSeed-159544250*/count=332; tryItOut("a0.push(g1, g1.v1);");
/*fuzzSeed-159544250*/count=333; tryItOut("function shapeyConstructor(korrlu){return korrlu; }/*tLoopC*/for (let x of /*FARR*/[.../*FARR*/[(4277), \"\\u3618\", (4277)], ...[x for each (x in /*FARR*/[.../*MARR*/[-Number.MAX_VALUE, new Boolean(true), -Number.MAX_VALUE, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), -Number.MAX_VALUE, -Number.MAX_VALUE, new Boolean(true), new Boolean(true), -Number.MAX_VALUE, new Boolean(true), -Number.MAX_VALUE, new Boolean(true), -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), -Number.MAX_VALUE, new Boolean(true), -Number.MAX_VALUE], , (Math.sin(2)), , x, ...x for (\u3056 of  /x/g ), x, , x]) for each (x in (x = window)) if (())]]) { try{let xywolo = new shapeyConstructor(x); print('EETT'); print(x);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-159544250*/count=334; tryItOut("mathy4 = (function(x, y) { return x; }); testMathyFunction(mathy4, /*MARR*/[Math.PI, Math.PI, Math.PI]); ");
/*fuzzSeed-159544250*/count=335; tryItOut("o0 = {};");
/*fuzzSeed-159544250*/count=336; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, 0/0, 2**53+2, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, Number.MAX_VALUE, 0, -Number.MAX_VALUE, -0x080000000, 1/0, -0, 0x080000001, -1/0, -0x07fffffff, 1, -0x100000001, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53-2), -0x0ffffffff, 0x100000000, Math.PI, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-159544250*/count=337; tryItOut("/*tLoop*/for (let x of /*MARR*/[0x50505050, 0x50505050,  /x/g , 0x50505050, [],  /x/g ,  /x/g ,  /x/g , [], [], []]) { v0 = Object.prototype.isPrototypeOf.call(e2, p1); }for (var p in g0.o2) { try { this.v1 = g1.eval(\"( ''  >=  \\\"\\\" )\"); } catch(e0) { } try { m1.set(m0, (4277)); } catch(e1) { } try { p2 + ''; } catch(e2) { } m0 + g0.i1; }");
/*fuzzSeed-159544250*/count=338; tryItOut("v1 = (h2 instanceof g2.m0);");
/*fuzzSeed-159544250*/count=339; tryItOut("L:for(var x = Math.imul(-21, NaN) in new ( /x/ )().valueOf(\"number\")) e0.has(b0);");
/*fuzzSeed-159544250*/count=340; tryItOut("if(true) {for (var p in i1) { try { a1.forEach((function() { try { this.g2 = this; } catch(e0) { } v0 = evalcx(\"print(z);\", g2); return m1; })); } catch(e0) { } Array.prototype.shift.call(a1, a1, b0, m1, p2); }\nprint(x);\nfunction a() { \"use strict\"; return (x) } print(x);\n((x = ({a1:1})));\n } else  if (timeout(1800)) {Array.prototype.shift.call(a2, e0); }");
/*fuzzSeed-159544250*/count=341; tryItOut("s2.toSource = (function() { try { t1 = t0.subarray(({valueOf: function() { (void schedulegc(g2));return 8; }})); } catch(e0) { } p0 = x; return v0; });");
/*fuzzSeed-159544250*/count=342; tryItOut("v1 = t2.length;");
/*fuzzSeed-159544250*/count=343; tryItOut("\"use strict\"; v2 = g1.eval(\"t1[11] = s2;\");");
/*fuzzSeed-159544250*/count=344; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Uint32ArrayView[((/*FFI*/ff(((((0xbc69ecd5) ? (0xdf8f5ffe) : (-0xc34a4)) ? (-274877906945.0) : (-1.2089258196146292e+24))), ((((!((0x483297fe)))) & ((0x1dceb3cb) % (0x587f6a53)))), ((Infinity)), ((((0x35bf0d18)-(0xfb70f300))|0)), ((((-0x8000000)) << ((0x57b6c657)))), ((-4398046511103.0)), ((-1073741825.0)), ((-4.835703278458517e+24)), ((131073.0)), ((2147483647.0)), ((147573952589676410000.0)))|0)) >> 2]) = ((i0)+((0x0)));\n    (Float64ArrayView[(((Infinity) < (d1))+(i0)) >> 3]) = ((+/*FFI*/ff(((((((((0x6dfc9cf1))+(0x326edb2c)) ^ ((0x4204305))) <= (((i2)) << (((imul((0xfab214ba), (0xd067bb3))|0)))))) & (0xfffff*((0x7873ed5d) ? (!(/*FFI*/ff(((((0x54aa6210)) << ((0xfd5ec2ae)))), ((576460752303423500.0)), ((-2305843009213694000.0)), ((16777217.0)), ((8589934593.0)), ((-3.022314549036573e+23)), ((-1.2089258196146292e+24)))|0)) : (/*FFI*/ff(((536870912.0)), ((+(0.0/0.0))), ((16.0)), ((-134217729.0)), ((-1025.0)), ((-72057594037927940.0)))|0))))))));\n    i2 = (0xffffffff);\n    return (((/*FFI*/ff()|0)))|0;\n  }\n  return f; })(this, {ff: Number.prototype.toExponential}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=345; tryItOut("L: Array.prototype.pop.call(a1);for(let x in []);");
/*fuzzSeed-159544250*/count=346; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( ~ ( + mathy0((((mathy0(Math.hypot(-(2**53), 0x100000001), -Number.MIN_VALUE) | 0) && (y >>> 0)) >>> 0), (Math.trunc((x >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-159544250*/count=347; tryItOut("\"use strict\"; testMathyFunction(mathy0, [[], ({valueOf:function(){return 0;}}), undefined, 0.1, (new Number(-0)), '\\0', null, -0, ({valueOf:function(){return '0';}}), '/0/', '', objectEmulatingUndefined(), /0/, 1, NaN, true, ({toString:function(){return '0';}}), (new Boolean(true)), '0', false, [0], (new Boolean(false)), (new Number(0)), (function(){return 0;}), (new String('')), 0]); ");
/*fuzzSeed-159544250*/count=348; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + ( + (( + (Math.asinh(( + (((y >>> 0) < (x >>> 0)) >>> 0))) | 0)) === ( + Math.cbrt(-0))))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -(2**53-2), Math.PI, -0, 2**53+2, -0x080000000, 1, 2**53-2, -0x100000000, Number.MIN_VALUE, -0x100000001, -0x080000001, 0x080000000, 2**53, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 42, 0x100000000, 0x0ffffffff, -1/0, 1/0, 0x080000001, -(2**53), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0]); ");
/*fuzzSeed-159544250*/count=349; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var log = stdlib.Math.log;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 18446744073709552000.0;\n    var i3 = 0;\n    {\n      {\n        i1 = (i1);\n      }\n    }\n    {\n      (Uint8ArrayView[((0x802a89f0)-((0xfe7ea798) != (((0x59e07ba6) / (-0x8000000))>>>((-0x8000000)*-0x862a1)))) >> 0]) = ((0xff483bc5)-(0xffffffff));\n    }\n    {\n      d0 = (+(1.0/0.0));\n    }\n    i3 = (0xf841cbc9);\n    d0 = (NaN);\n    i3 = (w = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: undefined, iterate: undefined, enumerate: function() { return []; }, keys: function() { return []; }, }; })((function ([y]) { })()), ((({})).bind(new RegExp(\"(?=(?:(?!\\\\w){0,1073741824})*?)|[\\\\d\\\\S]{32768}.+[^][^\\\\s\\\\xf5-\\\\\\ue716\\\\D\\ufe59]{2}(\\\\B)|\\\\B\", \"g\"), new RegExp(\"(?:.(?=[^])|[\\\\d\\\\s\\\\\\u00f5-\\n]+\\\\b*?{4,8}|\\\\1)\", \"gim\"))).call, (mathy3).bind));\n    d2 = (((Float64ArrayView[0])) / ((+(-1.0/0.0))));\n    (Int16ArrayView[0]) = ((i3));\n    return +((17592186044417.0));\n    d0 = (2049.0);\n    i3 = ((((0xa8d742a7)+(0x77b0481c)) & ((!((0x422eb396) ? (i3) : (i1)))+((~~(+log(((Float64ArrayView[2])))))))));\n    i1 = (i1);\n    (Float64ArrayView[1]) = ((((Float64ArrayView[((0x270060a2) / (0xf935a39)) >> 3])) % ((((+(imul((i1), (0x913f5a01))|0))) % ((d0))))));\n    d2 = (((+((d0)))) % ((-0.0009765625)));\n    i3 = ((((((((0xe6636571)) | ((-0x8000000))) % (~~(-7.737125245533627e+25))) | ((/*FFI*/ff(((((281474976710657.0)) % ((-16385.0)))), ((73786976294838210000.0)), ((-147573952589676410000.0)), ((-2.3611832414348226e+21)), ((549755813888.0)), ((-65.0)), ((4294967297.0)))|0)-(!(0xfb3a9373)))) / ((0x2b1e0*(i1)) >> (((0xdb4a534c) != (0xf1bbd01f))+(0xffffffff)))) << ((0x29343133))));\n    d0 = ((Float32ArrayView[2]));\n    return +((2.4178516392292583e+24));\n  }\n  return f; })(this, {ff: (new Function(\"Object.preventExtensions(o0.h2);\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x080000001, -0x100000000, -1/0, -(2**53+2), 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, 0x080000000, -(2**53-2), 2**53+2, Math.PI, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, -0x100000001, -0x080000000, 0, 0/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, 1, -(2**53), -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, -0]); ");
/*fuzzSeed-159544250*/count=350; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=351; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return ( - Math.pow(Math.max((( + ( - y)) ^ Math.ceil(( + Math.log(x)))), Math.fround(Math.log((Math.cosh((y >>> 0)) >>> 0)))), ( + Math.acosh((Math.imul(Math.sqrt((Number.MAX_VALUE | 0)), (( ~ (Math.fround(( + Math.atan2(y, -Number.MAX_VALUE))) | 0)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, /*MARR*/[(-1/0), allocationMarker(), allocationMarker(), x, allocationMarker(), 0x40000000, (-1/0), allocationMarker(), allocationMarker(), 0x40000000, allocationMarker(), x, (-1/0), (-1/0), 0x40000000, 0x40000000, x, 0x40000000, allocationMarker(), x, allocationMarker(), (-1/0), 0x40000000, (-1/0), x, (-1/0), 0x40000000, 0x40000000, 0x40000000, x, allocationMarker(), (-1/0), allocationMarker(), (-1/0), allocationMarker(), allocationMarker(), 0x40000000, x, 0x40000000, x, (-1/0), 0x40000000, x, x, (-1/0), (-1/0), (-1/0), 0x40000000]); ");
/*fuzzSeed-159544250*/count=352; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=353; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (((( ! Math.fround(Math.pow(y, y))) < (( ! Math.fround(Math.cosh(-0x07fffffff))) | 0)) ? Math.acosh(Math.fround(( ~ Math.fround(( ! x))))) : ( + ( + Math.hypot((mathy1((y >>> 0), x) >>> 0), mathy0(( ! ( + Math.pow(Number.MIN_VALUE, x))), 0x0ffffffff))))) + ( + (( + ( + Math.abs(( + Math.log(-Number.MAX_SAFE_INTEGER))))) == ( + ( - Math.sqrt(-Number.MAX_SAFE_INTEGER)))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 0x080000001, 2**53-2, -0, -(2**53), 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, -0x080000000, Number.MIN_VALUE, 2**53+2, 0x100000001, -0x100000001, 0x100000000, -1/0, -0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -Number.MAX_VALUE, 1, -0x07fffffff, -(2**53-2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, 2**53, -Number.MIN_SAFE_INTEGER, 0, 42, 0x0ffffffff, 1/0]); ");
/*fuzzSeed-159544250*/count=354; tryItOut("\"use strict\"; for(var x in  /x/ ) {print( /x/g );for (var v of i0) { try { v1 = Object.prototype.isPrototypeOf.call(o2, s0); } catch(e0) { } try { Array.prototype.push.apply(a0, [o2.i0]); } catch(e1) { } i0 = t2[ /x/g ]; } }\n");
/*fuzzSeed-159544250*/count=355; tryItOut("testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, -0x100000000, 42, Number.MAX_VALUE, 0x080000001, 0x100000000, 0, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, -0, 0x07fffffff, -(2**53), -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, -(2**53-2), 1, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 0x100000001, -(2**53+2), -0x080000001, -1/0, 0/0]); ");
/*fuzzSeed-159544250*/count=356; tryItOut("o0.a0[19] = v2;");
/*fuzzSeed-159544250*/count=357; tryItOut("\"use strict\"; t1.set(a2, (intern((({\"27\": \"\\uC47D\",  set length(d = window, window =  /x/ , ...b)\"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (((1.5474250491067253e+26)) / ((+abs((((this) % ((1125899906842624.0))))))));\n    }\n    (Int8ArrayView[((0x424c5656)*-0xb0c8) >> 0]) = (x);\n    d1 = (+atan2(((1.0)), ((d1))));\n    return +((d1));\n    return +((NaN));\n  }\n  return f; }))((4277)))));");
/*fuzzSeed-159544250*/count=358; tryItOut("\"use strict\"; a2[15];");
/*fuzzSeed-159544250*/count=359; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy3, [-0x100000000, 0x100000000, 0x080000000, -(2**53+2), Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 0x100000001, 1, -0x080000001, 0, 2**53, -Number.MAX_VALUE, -0x080000000, 0x080000001, -Number.MIN_VALUE, -0x0ffffffff, -0, -1/0, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53), 42, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, Number.MIN_VALUE, 1/0, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=360; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.hypot(Math.max(Math.fround((Math.atan2(Math.fround(( ! (((y >>> 0) >>> x) >>> 0))), (( + Math.log10(Math.fround(( ~ x)))) | 0)) | 0)), Math.fround(Math.sign((mathy4(2**53-2, (y >>> 0)) >>> 0)))), Math.fround(Math.hypot(Math.fround(Math.pow(Math.clz32(x), y)), (Math.hypot(( + ( ! ( + y))), y) >>> 0)))); }); testMathyFunction(mathy5, ['', [], null, ({toString:function(){return '0';}}), (new Number(0)), [0], 1, ({valueOf:function(){return 0;}}), NaN, '\\0', (function(){return 0;}), -0, (new Boolean(true)), '/0/', /0/, undefined, (new Boolean(false)), 0.1, (new String('')), false, (new Number(-0)), true, 0, '0', objectEmulatingUndefined(), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-159544250*/count=361; tryItOut("b2 = Proxy.create(h0, g0);");
/*fuzzSeed-159544250*/count=362; tryItOut("/*MXX3*/g2.Set.prototype.add = this.g0.Set.prototype.add;");
/*fuzzSeed-159544250*/count=363; tryItOut("o1 = t2[v1];");
/*fuzzSeed-159544250*/count=364; tryItOut("\"use strict\"; /*MXX1*/Object.defineProperty(this, \"o1\", { configurable: (x % 45 != 14), enumerable: false,  get: function() {  return g1.TypeError.length; } });");
/*fuzzSeed-159544250*/count=365; tryItOut("\"use strict\"; e1.delete(f0);");
/*fuzzSeed-159544250*/count=366; tryItOut("/*RXUB*/var r = \u000cnew (Int32Array(+(new (let (e = null, x, e, a, vdhurn, opnieh, kcopcy, vhmonu, rlohod, x)  /x/ )([1], new function(y) { yield y; t0.set(a2, 0);; yield y; }())), WebAssemblyMemoryMode((void version(170)))))(this |=  /x/ ); var s = \"\\ud0be\\ud0be1\\ud3c2\\ud3c2\\ud3c2\\u00c2\\ud0be\\ud0be\\ud0be\\ud0be\\u00c2\\ud0be\"; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=367; tryItOut("\"use strict\"; if(true) this.o2 = t0[({valueOf: function() { let arbxme, b;e1.has(f0);return 3; }})]; else  if (a = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: (x % d), has: function() { return false; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { return []; }, }; })(intern((d ? /[^\\I-\\\u00a0\u34ab-\\v\\S]|./m : eval))), (/*UUV2*/(b.valueOf = b.setUint32)).apply, Date.prototype.toDateString)) {v2 = evalcx(\"this.h1.getOwnPropertyDescriptor = f2;\", g1);Array.prototype.shift.call(a2); }");
/*fuzzSeed-159544250*/count=368; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(Math.fround(Math.tan(( + ((Math.fround((y >>> 0)) >>> 0) == ( + Math.round((((2**53+2 | 0) !== (( + (( + x) < ( + -Number.MIN_VALUE))) >>> 0)) | 0))))))), Math.fround((Math.sinh((Math.hypot((( ~ ( + mathy0(Math.imul(((Math.fround(y) | Math.fround(y)) | 0), x), ( + ( - (y | 0)))))) | 0), (Math.log1p(( - Math.atan(x))) | 0)) | 0)) | 0))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, -0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, 2**53-2, Math.PI, -(2**53), 2**53+2, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, -(2**53-2), 0x07fffffff, -(2**53+2), 0x080000000, -0, 0, 42, -0x080000001, 0.000000000000001, 0/0, 1/0, 0x100000000, 0x0ffffffff, -0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-159544250*/count=369; tryItOut("f2 = Proxy.createFunction(h2, f1, f2);");
/*fuzzSeed-159544250*/count=370; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((( ! Math.sin(Math.sqrt(y))) >>> 0) < ((( ~ (Math.ceil(-0x0ffffffff) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0, -(2**53), 0x100000000, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000000, 42, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -(2**53+2), 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -0x080000000, 0x100000001, 1/0, 0, -Number.MAX_VALUE, -0x080000001, 0/0, -1/0, 1, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 2**53, 2**53-2, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=371; tryItOut("try { let(ibcgtb) { for(let y in /*FARR*/[.../*FARR*/[.../*FARR*/[,  /x/ , ...(function() { yield x; } })(), (uneval(x)), , (eval = y(y >>>= x, x)), objectEmulatingUndefined()], (4277), x, ,  /x/g , ('fafafa'.replace(/a/g, ArrayBuffer.isView)), new RegExp(\"[\\\\cW\\\\w]{3,4}|(?=\\\\W)\\\\Z|^|(?!\\\\D)+?|(?=[^\\\\u00BE\\\\d])(?!(?!\\\\w[\\\\\\u000f\\u0017\\\\d])?){2}*\", \"i\").__defineSetter__(\"x\", (function(x, y) { return Number.MIN_SAFE_INTEGER; })), ...[Math.imul(-5, 17) for (x of (window)()) for (e of /*FARR*/[x].some(offThreadCompileScript)) if (Uint8Array((encodeURIComponent)))], (4277), , , x, arguments[new String(\"0\")]+=({x: (++w), getTime: (/.|[^]{2}/ for (x of z)) })], , ...Math.max(x, 26) for each (x in (makeFinalizeObserver('tenured'))) for each (z in /*MARR*/[Math.atan2(18, -18),  \"\" , Math.atan2(18, -18), Math.atan2(18, -18), Math.atan2(18, -18),  \"\" , Math.atan2(18, -18), Math.atan2(18, -18), Math.atan2(18, -18),  \"\" ,  \"\" , Math.atan2(18, -18),  \"\" ,  \"\" , Math.atan2(18, -18), Math.atan2(18, -18), Math.atan2(18, -18),  \"\" ,  \"\" ,  \"\" , Math.atan2(18, -18),  \"\" , Math.atan2(18, -18),  \"\" , Math.atan2(18, -18), Math.atan2(18, -18), Math.atan2(18, -18),  \"\" ,  \"\" , Math.atan2(18, -18), Math.atan2(18, -18), Math.atan2(18, -18), Math.atan2(18, -18),  \"\" , Math.atan2(18, -18), Math.atan2(18, -18),  \"\" ,  \"\" , Math.atan2(18, -18),  \"\" ,  \"\" ,  \"\" , Math.atan2(18, -18)]) for (2 of window.__defineGetter__(\"x\", new RegExp(\"\\\\2\", \"gyim\"))) for (x of (Object.defineProperty(eval, 2, ({get: undefined.toExponential, set: (undefined).call, enumerable: (x % 71 != 1)})))) for (y of delete z.eval) for (y of String.prototype.padStart) for each (c in undefined) for each (NaN in x) for (z of  /x/ ), ]) let(tmratf, NaN, y, cdaptk, nmohof, 17 = (this.__defineSetter__(\"NaN\", ((let (e=eval) e)).bind))) { throw NaN;}} } catch(this.e if (function(){for(let a in function(y) { ( /x/ ); }.prototype) return /*UUV1*/(a.toString = (String.prototype.sub).bind);})()) { for(let x in []); } catch(0) { try { 0.name; } catch(a) { let(x) { z = \u3056;} } finally { with({}) z = e; }  } with({}) { d = NaN; } ");
/*fuzzSeed-159544250*/count=372; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.max(( - (Math.atan2((Math.fround((Math.fround(x) + Math.fround(y))) >>> 0), Math.log2(( ~ Math.fround(y)))) >>> 0)), (( + ( + ( - ( + (((( ! y) | 0) > Math.fround((Math.fround(-0) >= ( + x)))) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, 0/0, -0x080000000, Number.MIN_VALUE, 0x100000000, Math.PI, 0x100000001, 0x080000001, 1/0, -0x0ffffffff, -0x07fffffff, 42, 0x07fffffff, -(2**53), 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53, -0x100000000, -(2**53+2), -0, 1.7976931348623157e308, 0]); ");
/*fuzzSeed-159544250*/count=373; tryItOut("o0.v1 = g2.eval(\"var lrvwyf = new SharedArrayBuffer(4); var lrvwyf_0 = new Uint8Array(lrvwyf); print(lrvwyf_0[0]); lrvwyf_0[0] = 26; var lrvwyf_1 = new Int16Array(lrvwyf); print(lrvwyf_1[0]); lrvwyf_1[0] = 14; v1 = g1.runOffThreadScript();g2.v0 = g0.runOffThreadScript();yield [z1,,];print((q => q)());print(s0);v2 = evaluate(\\\"a1.shift(g1);\\\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (lrvwyf_0[3] % 103 != 33), sourceIsLazy: 2, catchTermination: (lrvwyf_0 % 41 != 31) }));\\ne1.has(i1);\\n\");");
/*fuzzSeed-159544250*/count=374; tryItOut("testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), (new Boolean(false)), '0', (function(){return 0;}), '', -0, '/0/', 0, objectEmulatingUndefined(), [], (new Number(0)), undefined, (new Number(-0)), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (new Boolean(true)), true, null, '\\0', NaN, (new String('')), false, 1, /0/, [0], 0.1]); ");
/*fuzzSeed-159544250*/count=375; tryItOut("/*RXUB*/var r = intern(true); var s = \"\\u0011\\u00ca\"; print(s.match(r)); function \u3056(eval) { return \n ''  } /* no regression tests found */");
/*fuzzSeed-159544250*/count=376; tryItOut("let (b, x) { /* no regression tests found */ }");
/*fuzzSeed-159544250*/count=377; tryItOut("const c = /*MARR*/[(null.eval(\"/* no regression tests found */\")), (0/0), (0/0), function(){}, x, function(){}];Math.acosh(c);");
/*fuzzSeed-159544250*/count=378; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ ( + ( + ( + (( ~ -Number.MIN_SAFE_INTEGER) ? ( + mathy0(Math.fround(Math.hypot(0x080000000, x)), Math.fround(y))) : (x - ( ~ 0x080000000))))))); }); testMathyFunction(mathy1, [-0, -0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, 0/0, 2**53-2, -Number.MAX_VALUE, -(2**53), Math.PI, 1/0, 42, 1.7976931348623157e308, 2**53+2, -1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, -0x100000000, -0x100000001, 0x080000000, 0x080000001, 0.000000000000001, 0, Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), 0x07fffffff, -Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-159544250*/count=379; tryItOut("v2.toSource = (function(j) { o1.f0(j); });");
/*fuzzSeed-159544250*/count=380; tryItOut("\"use strict\"; m2.has(m0);");
/*fuzzSeed-159544250*/count=381; tryItOut("Array.prototype.forEach.call(a2, (function mcc_() { var jefypv = 0; return function() { ++jefypv; if (/*ICCD*/jefypv % 2 == 1) { dumpln('hit!'); try { i1.toString = f2; } catch(e0) { } try { Array.prototype.pop.call(a1); } catch(e1) { } Object.defineProperty(o1, \"v2\", { configurable: true, enumerable: ((makeFinalizeObserver('nursery'))),  get: function() {  return evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 12 != 6), noScriptRval: true, sourceIsLazy: (x % 3 == 1), catchTermination: (x % 7 == 3) })); } }); } else { dumpln('miss!'); a2.length = (makeFinalizeObserver('nursery')); } };})(), (4277), o2);");
/*fuzzSeed-159544250*/count=382; tryItOut("this.i1 + o1;");
/*fuzzSeed-159544250*/count=383; tryItOut("let b, eval, x, odqyut, [] = delete y.set, aaccql, zwrpqq, window = undefined, x, jnvmjq;print(window = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { throw 3; }, fix: undefined, has: function() { throw 3; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })(x), ({/*TOODEEP*/}), Float64Array));");
/*fuzzSeed-159544250*/count=384; tryItOut("mathy2 = (function(x, y) { return Math.fround(mathy0(Math.fround(Math.atan2(( + ( ! ( + Math.fround(( ! x))))), Math.fround(Math.acosh(Math.fround(( + Math.min(( + (x ? y : Math.atan2(x, (y >>> 0)))), x))))))), (( ~ ( + Math.pow(Math.fround(Math.sin(Math.fround(x))), ( + Math.fround((Math.cosh((Math.fround((Math.fround(x) <= (x | 0))) === mathy1(0, x))) !== Math.fround(y))))))) >>> 0))); }); testMathyFunction(mathy2, /*MARR*/[false, false, x, false, false, false, x, x, false, x, x, x, x, x, x, false, false, x, x, x, false, x, false, x, false, false, false, x, false, x, x, x, x]); ");
/*fuzzSeed-159544250*/count=385; tryItOut("e0.add(i1);");
/*fuzzSeed-159544250*/count=386; tryItOut("\"use strict\"; t0 + g2.b1;");
/*fuzzSeed-159544250*/count=387; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=388; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return +((9223372036854776000.0));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-1/0, 0x080000000, 0x080000001, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), -0x100000001, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0, 1/0, 1, 0.000000000000001, -0x100000000, 42, Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, 2**53, 2**53+2, 0x100000000, 0x0ffffffff, -0x080000000, -Number.MAX_VALUE, 0x07fffffff, 0/0, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, -(2**53), Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=389; tryItOut("(x);");
/*fuzzSeed-159544250*/count=390; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.max(( ~ ( + (mathy2(( + ((x | 0) !== Math.fround(x))), ( + x)) | 0))), Math.atan(( + mathy0(( + (( + ( + y)) >>> 0)), ( + x))))); }); testMathyFunction(mathy5, [0x100000001, -Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, 2**53+2, Math.PI, -0x07fffffff, -(2**53+2), -(2**53-2), Number.MAX_VALUE, -0, -0x0ffffffff, 0, -(2**53), 0/0, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 2**53-2, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, 1, 0x080000000, 0x100000000, 0x07fffffff, -0x100000001, 0.000000000000001, -0x080000001, 42, -1/0]); ");
/*fuzzSeed-159544250*/count=391; tryItOut("\"use strict\"; L:while((Math.imul(13, -25)) && 0){b1 = x;/* no regression tests found */ }\nprint(v2);\n");
/*fuzzSeed-159544250*/count=392; tryItOut("/*vLoop*/for (var bzlhnr = 0; bzlhnr < 35; ++bzlhnr) { var e = bzlhnr; b1.toSource = (function() { try { t1 = g2.t1.subarray(v1, ({valueOf: function() { print(e);return 0; }})); } catch(e0) { } ; return v2; });v2 = this.a0.length; } ");
/*fuzzSeed-159544250*/count=393; tryItOut("e1 + p0;");
/*fuzzSeed-159544250*/count=394; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((( + Math.min(Math.fround(mathy2(Math.min((( + Math.tan(( + -0x080000001))) | 0), y), x)), ( + ((((-0x07fffffff | 0) + (mathy0(Number.MIN_SAFE_INTEGER, -0x080000000) | 0)) | 0) / ( ~ ( + (-0 >>> (Math.hypot((( + Math.abs(x)) >>> 0), (((-0x100000000 >>> 0) != (x >>> 0)) >>> 0)) >>> 0)))))))) || ((Math.fround(( + Math.atan2(( + (Math.cbrt(((Math.abs((x | 0)) | 0) >>> 0)) >>> 0)), ( + (x >>> Math.cbrt(y)))))) ? ((mathy0(( + ( - x)), ( + y)) >>> 0) | 0) : (Math.pow(( + Math.imul(( + x), ( + ( - (x | 0))))), Math.fround(( - Math.fround(Math.fround(Math.min((( + (x >>> 0)) >>> 0), Math.fround(x))))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy3, [/0/, (new String('')), '\\0', '0', 1, undefined, (function(){return 0;}), ({valueOf:function(){return 0;}}), -0, 0.1, [0], (new Number(0)), '/0/', true, [], '', 0, (new Boolean(true)), false, ({valueOf:function(){return '0';}}), null, NaN, ({toString:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), (new Boolean(false))]); ");
/*fuzzSeed-159544250*/count=395; tryItOut("mathy5 = (function(x, y) { return (Math.asinh((( - ( + ( + Math.max((y | 0), (Math.min(( ~ Math.fround(y)), (Math.hypot(-(2**53-2), (Math.atan2(-Number.MIN_VALUE, y) >>> 0)) | 0)) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 42, 1, Number.MAX_VALUE, 0x080000000, -0, 0/0, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -(2**53-2), -0x080000001, -0x100000001, -(2**53), 0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, Math.PI, -Number.MIN_VALUE, -0x080000000, 1/0, 0x0ffffffff, 0, 0x100000001, 1.7976931348623157e308, 2**53-2, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, 2**53, -0x100000000]); ");
/*fuzzSeed-159544250*/count=396; tryItOut("mathy3 = (function(x, y) { return ( + ( ~ ( + ( + Math.fround(x))))); }); testMathyFunction(mathy3, /*MARR*/[Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, Number.MAX_VALUE, (void 0), Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, (void 0), (void 0), (void 0), Number.MAX_VALUE, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), (void 0), (void 0), Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, Number.MAX_VALUE, (void 0), Number.MAX_VALUE, (void 0), Number.MAX_VALUE, Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, (void 0), (void 0), Number.MAX_VALUE, Number.MAX_VALUE, (void 0)]); ");
/*fuzzSeed-159544250*/count=397; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return mathy0(Math.min(Math.fround(( - Math.fround(Math.atan2(( + Math.min((( - y) | 0), ( + x))), (( ~ x) >>> 0))))), ( + ((( + ( + ( + (0x0ffffffff >>> 0)))) >>> 0) | x))), (Math.hypot(mathy0(y, Math.fround(Math.hypot(y, x))), ((( + (Math.imul((Math.clz32(y) | 0), 1) >>> 0)) | (( ~ (Math.fround(mathy0((2**53-2 / y), 0x0ffffffff)) >>> 0)) >>> 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-159544250*/count=398; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4(Math.hypot((( + x) , Math.pow(Math.fround(Math.fround((y ? ( + (x !== (Math.imul((y >>> 0), x) >>> 0))) : (x ? y : Math.fround(x))))), (( - (-(2**53-2) | 0)) | 0))), (y !== -0)), (( + ( - ( + Math.tanh(Math.fround(Math.min(0x0ffffffff, Math.fround(mathy0(x, -0x080000001)))))))) === ( ! (Math.pow((y ** 0x080000000), Math.fround(x)) | 0)))); }); testMathyFunction(mathy5, [Math.PI, 0x080000000, -0x080000000, -(2**53), -Number.MIN_VALUE, 0x07fffffff, 2**53+2, -Number.MAX_VALUE, 1, 0, -Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), 0x0ffffffff, -(2**53-2), -0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, 2**53-2, 0x080000001, 42, -0x080000001, 2**53, 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=399; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return mathy0(Math.sqrt((( - ( + mathy0(1.7976931348623157e308, (Math.fround(y) ? Math.PI : Math.fround((((x | 0) || (x | 0)) | 0)))))) >>> 0)), (Math.log1p(( + (mathy0(y, Math.atan2((x >>> 0), Math.log2(Math.fround(y)))) >>> 0))) | 0)); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 2**53-2, -0x100000001, 0x080000000, 42, 0x100000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, -0x100000000, -0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, 0x07fffffff, 0/0, 0.000000000000001, 1/0, -(2**53-2), -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, 2**53, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -1/0, -(2**53+2), 0]); ");
/*fuzzSeed-159544250*/count=400; tryItOut("\"use strict\"; this.v2 = Object.prototype.isPrototypeOf.call(h2, e1);");
/*fuzzSeed-159544250*/count=401; tryItOut("");
/*fuzzSeed-159544250*/count=402; tryItOut("'x'");
/*fuzzSeed-159544250*/count=403; tryItOut("\"use asm\"; ");
/*fuzzSeed-159544250*/count=404; tryItOut("mathy4 = (function(x, y) { return Math.cosh(( + Math.min(Math.exp(Math.abs(Math.sinh((( + (x | 0)) | 0)))), (( + Math.imul(( + Math.cbrt(0x0ffffffff)), ( + 0x100000000))) | 0)))); }); ");
/*fuzzSeed-159544250*/count=405; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      (Uint8ArrayView[4096]) = (((+tan(((d0))))));\n    }\n    /*FFI*/ff(((((delete d.x)) >> ((i1)))), ((d0)), ((+(-1.0/0.0))));\n    d0 = (+/*FFI*/ff(((NaN)), ((((x)+(0x51db27b4)+(0xfb8c84c3)) | (-((((-0x8000000)+(0xf8791dee)-(0x8641c8fd)) & ((0xb23565db)-(0xd5e806fb)-(-0x8000000)))))))));\n    d0 = (+abs(((d0))));\n    return (((new Proxy(x))+(i1)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.toString}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=406; tryItOut("m0.get(v0);");
/*fuzzSeed-159544250*/count=407; tryItOut("\"use strict\"; i0.toString = (function(j) { if (j) { try { v1 = Object.prototype.isPrototypeOf.call(p1, v1); } catch(e0) { } o0.v0.toSource = (function() { try { for (var p in a2) { try { o2.i1.toSource = (function(j) { if (j) { t0.set(a1, 18); } else { try { this.h0 + ''; } catch(e0) { } try { s1.valueOf = (function() { try { m0.__proto__ = o0; } catch(e0) { } try { a0.length = 11; } catch(e1) { } try { m0.get(g0); } catch(e2) { } s2 += 'x'; return f2; }); } catch(e1) { } h2.valueOf = (function() { try { a2 = r1.exec(s1); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a0, 17, ({configurable:  /x/g , enumerable: (x % 4 != 3)})); } catch(e1) { } v0 + o1; return i2; }); } }); } catch(e0) { } try { v1 = (v0 instanceof o1); } catch(e1) { } try { t1 = new Uint8ClampedArray(b1); } catch(e2) { } selectforgc(this.o1); } } catch(e0) { } /*RXUB*/var r = r2; var s = \"\"; print(s.replace(r, '', \"gim\"));  return h0; }); } else { try { this.s1 = ''; } catch(e0) { } h1.has = f0; } });");
/*fuzzSeed-159544250*/count=408; tryItOut("\"use strict\"; a2 = [];");
/*fuzzSeed-159544250*/count=409; tryItOut("m1.__proto__ = this.t0;");
/*fuzzSeed-159544250*/count=410; tryItOut("m0 = new WeakMap;a2[({valueOf: function() { /* no regression tests found */return 8; }})];");
/*fuzzSeed-159544250*/count=411; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), new Boolean(false), ((-26)(x) = ('fafafa'.replace(/a/g, Function))), x, objectEmulatingUndefined(), new Boolean(false), x, objectEmulatingUndefined(), ((-26)(x) = ('fafafa'.replace(/a/g, Function))), objectEmulatingUndefined(), ((-26)(x) = ('fafafa'.replace(/a/g, Function))), objectEmulatingUndefined(), objectEmulatingUndefined(), ((-26)(x) = ('fafafa'.replace(/a/g, Function))), ((-26)(x) = ('fafafa'.replace(/a/g, Function))), ((-26)(x) = ('fafafa'.replace(/a/g, Function))), new Boolean(false), new Boolean(false), x, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Boolean(false)]); ");
/*fuzzSeed-159544250*/count=412; tryItOut("\"use strict\"; g2.v1 = a2.some((function() { try { o1.e2 = new Set; } catch(e0) { } e2.add(f2); return g1; }));");
/*fuzzSeed-159544250*/count=413; tryItOut("/*RXUB*/var r = r2; var s = s0; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=414; tryItOut("Array.prototype.push.apply(a1, [t2, o0, e2, ({x, NaN: [], b, w: [[], {}, z]}, c) => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = (i0);\n    return +((+(0.0/0.0)));\n    return +((-7.737125245533627e+25));\n  }\n  return f;.prototype]);");
/*fuzzSeed-159544250*/count=415; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 3.8685626227668134e+25;\n    var d3 = -6.189700196426902e+26;\n    d0 = (+atan2(((+(-1.0/0.0))), ((((Float32ArrayView[1])) % ((d2))))));\n    {\n      (Int32ArrayView[1]) = (0x3ff11*((((0xffffffff)-((-16777217.0)))>>>(((d0) == (-2049.0))*-0xfcf89))));\n    }\n    i1 = ((((((0x40d0a996)+(0xfeffbe15))>>>((0x183c6e50)-(-0x8000000))) / (((0xfba89bcb))>>>((0x5369d93a) % (0x533442f0))))>>>((0x27757c45)+(0xfc91d7b1))) == ((((((0xf83f2cd0)+(0x4b238304)+(0xffffffff))>>>((0xff54fe98))))*0x302f)>>>(-0xfc166*(0xff66a842))));\n    switch ((~~(+(0xa57de5e2)))) {\n    }\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; return ((x(window) =  \"\"  , d)) }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x080000001, 1, 0x100000000, -Number.MAX_VALUE, -0x080000001, -(2**53+2), 42, -(2**53-2), 2**53-2, 0/0, 2**53, -1/0, -(2**53), Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -0x080000000, -0, 1.7976931348623157e308, -0x100000001, 0x080000000, 0, -0x100000000, 0x100000001, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 1/0, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-159544250*/count=416; tryItOut("with(yield eval){ if (!isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; } (\u0009this);");
/*fuzzSeed-159544250*/count=417; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0x100000001, -(2**53), 0/0, 2**53, 0.000000000000001, 0x100000000, 0x0ffffffff, -0x080000001, 1/0, 2**53-2, 1.7976931348623157e308, 42, 0, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, Math.PI, 1, -0x0ffffffff, -(2**53+2), 0x080000001, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-159544250*/count=418; tryItOut("mathy4 = (function(x, y) { return ((Math.log10((Math.fround((((x >> y) | 0) > (( ~ ( + ( - ( + y)))) | 0))) | 0)) | 0) ? ( + Math.cbrt(( + Math.asin(( + y))))) : ( ! ( + ( ~ ( + ( - y)))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 0x0ffffffff, -0x080000001, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, -0x100000001, -0x080000000, 0, -1/0, -(2**53-2), 0x080000000, 1.7976931348623157e308, Math.PI, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, -(2**53+2), 0x080000001, 2**53, -Number.MIN_VALUE, -0, 0x100000001, 0x07fffffff, -0x100000000, 2**53+2, 1, 0x100000000]); ");
/*fuzzSeed-159544250*/count=419; tryItOut("v1.toString = f2;");
/*fuzzSeed-159544250*/count=420; tryItOut("print(\"\\uA67B\");\nv2 = t0.length;\n\no1.g0.v0 = Object.prototype.isPrototypeOf.call(h1, m0);\n");
/*fuzzSeed-159544250*/count=421; tryItOut("/*MXX1*/const this.o0 = g0.String.prototype.italics;");
/*fuzzSeed-159544250*/count=422; tryItOut("testMathyFunction(mathy2, /*MARR*/[new Number(1.5), 0x5a827999, 0x5a827999, 0x5a827999, [1], [1], [1], 0x5a827999, \"\u03a0\", \"\u03a0\", \"\u03a0\", \"\u03a0\", 0x5a827999, new Number(1.5), [1], new Number(1.5), [1], \"\u03a0\", [1], new Number(1.5), new Number(1.5), 0x5a827999]); ");
/*fuzzSeed-159544250*/count=423; tryItOut("print(x);\nprint(window);\n");
/*fuzzSeed-159544250*/count=424; tryItOut("e2 = new Set;");
/*fuzzSeed-159544250*/count=425; tryItOut("g1.r1 = new RegExp(\"(?=[^](?![^])*[\\\\da\\\\\\u00c3-\\\\0]|\\\\B|\\\\b)($)\", \"yim\");");
/*fuzzSeed-159544250*/count=426; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return (mathy2(((Math.max((mathy3(y, ( + x)) >>> 0), (Number.MAX_VALUE >>> 0)) >>> 0) !== ( ~ ( - Math.fround(x)))), Math.fround(( ! y))) << ( - ( + (Math.expm1(x) << Math.fround(( + x)))))); }); ");
/*fuzzSeed-159544250*/count=427; tryItOut("testMathyFunction(mathy1, [-(2**53-2), 2**53+2, 0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 0/0, 0, 1.7976931348623157e308, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 42, -0, -0x07fffffff, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, -1/0, 0x080000001, 0x100000001, -0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, 0x100000000, Math.PI, -(2**53+2), 2**53]); ");
/*fuzzSeed-159544250*/count=428; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=429; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[ \"\" ,  '' ,  '' , new Number(1), new Number(1), new Number(1),  \"\" ,  \"\" ,  '' ,  '' ,  '' , new Number(1), new Number(1),  '' ,  \"\" ,  '' ,  \"\" ,  \"\" ,  \"\" ,  '' , new Number(1), new Number(1), new Number(1),  '' ,  \"\" , new Number(1),  '' ]) { ((e) = eval(\"(/(?!(?!(?=\\\\s))|[^][^]|(?!$){0,1})?|(?:(?!(?=(.)))|(?!\\\\s{0,})|(?=\\u3303{131073,131077}))/i).call\"))\u0009; }");
/*fuzzSeed-159544250*/count=430; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((( ~ Math.PI) ^ (Math.tanh((Math.atan(Math.asin((y != y))) >>> 0)) >>> 0)) + ( + Math.fround(Math.atan2(Math.fround(Math.trunc(y)), Math.fround(Math.log((x >>> 0))))))) > Math.fround(( + (Math.fround((y * ( + x))) >>> Math.sinh(x))))); }); testMathyFunction(mathy0, [0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, -Number.MIN_VALUE, 1/0, -0x080000001, -Number.MAX_VALUE, 42, 0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -0, -0x080000000, -0x100000000, 0x100000000, 0, 2**53-2, 0x07fffffff, 2**53+2, Math.PI, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, 1, 1.7976931348623157e308, Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=431; tryItOut("a2.shift();\nprint(allocationMarker());\n");
/*fuzzSeed-159544250*/count=432; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=433; tryItOut("/*RXUB*/var r = r1; var s = s2; print(r.test(s)); ");
/*fuzzSeed-159544250*/count=434; tryItOut("v2 = g0.eval(\"\\\"use strict\\\"; mathy1 = (function(x, y) { \\\"use strict\\\"; return ( ! Math.fround(Math.asinh(Math.fround((Math.atanh((Math.log2(x) >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [Math.PI, 0, -0x080000000, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0, 42, 0/0, -1/0, 0x080000001, -(2**53), 0x100000001, -0x100000000, 2**53, 1, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 0x080000000, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, 2**53+2, -0x0ffffffff, 0x0ffffffff, -Number.MAX_VALUE, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 1.7976931348623157e308]); \");");
/*fuzzSeed-159544250*/count=435; tryItOut("\"use strict\"; { void 0; void gc(this); }");
/*fuzzSeed-159544250*/count=436; tryItOut("/*RXUB*/var r = /(?=[^]){3}|[^\u000b-\u97dc\\cQ\\W]|${2,}+|\\b{3,524291}|(?:\\B*?|(\\1{2,5})|[^]*?(?=[\uf9cb\\d])(?:\\B{1,4})|\\2+?|(?=^+|\\s[\\x94\\0-\\u00f7\\d]\\W)(?:\\B)\\u0020+?)/gi; var s = \"      1a   \"; print(s.split(r)); ");
/*fuzzSeed-159544250*/count=437; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(?:(?=(\\\\2{0,4}))))|(?:.|\\\\W)\\\\w.|\\\\d{4}|\\ufdcf^(?=[\\\\u005F\\\\s\\\\\\u7390-\\\\u4E7A\\u00d7-\\udab3])\\\\2+|(?:(?:(?![^])))|\\\\2|$|(?=((?=\\\\b|$|.?|.|.\\\\b?)(?!(?:(?![\\\\cK-e\\\\w\\\\d]))*?)))\", \"m\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-159544250*/count=438; tryItOut("v1 = evalcx(\"a0.reverse();\", o2.g0);");
/*fuzzSeed-159544250*/count=439; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=440; tryItOut("\"use strict\"; let (a) { a1.push(s2); }");
/*fuzzSeed-159544250*/count=441; tryItOut("a0.forEach((function() { try { v0 = Object.prototype.isPrototypeOf.call(a0, g2.a2); } catch(e0) { } try { t0 = new Int32Array(g0.a2); } catch(e1) { } a0 = arguments; return a1; }), this.o1);");
/*fuzzSeed-159544250*/count=442; tryItOut("\"use strict\"; b0 + p2;");
/*fuzzSeed-159544250*/count=443; tryItOut("v1 = new (('fafafa'.replace(/a/g, (eval).call)))((new ( /x/g )(new RegExp(\"((?=^)[\\\\S])(\\u4f36{2,}^*?{4,8})|.{1}\", \"ym\"))), x);");
/*fuzzSeed-159544250*/count=444; tryItOut("mathy2 = (function(x, y) { return Math.cbrt(Math.max(( + (Math.max(Math.fround(Math.pow((( + (Math.max(Math.atan2(Math.fround(x), y), (Math.min((x | 0), (0 | 0)) | 0)) >>> 0)) >>> 0),  /x/ )), ( + Math.asin(Math.sign(y)))) >>> 0)), (((Math.fround(Math.min(Math.fround(( ~ Math.fround(y))), -0x080000000)) >>> 0) >> (((x ? y : (y | 0)) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [0x100000001, -1/0, Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 0.000000000000001, -(2**53), 0x07fffffff, Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -Number.MAX_VALUE, -0, -0x100000000, -0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, Number.MIN_VALUE, 0x080000001, 2**53, 0, 2**53-2, Math.PI, -(2**53+2), 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0/0, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=445; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (mathy0((mathy0(( ! x), (Math.fround((y << -Number.MIN_VALUE)) >>> 0)) >>> 0), Math.fround((( ~ ( ! mathy0((Math.exp((x | 0)) | 0), -0x100000000))) ? ((((((Math.pow((( + Math.cos(( + (1.7976931348623157e308 && x)))) >>> 0), x) >>> 0) >>> 0) - (Math.log1p(x) >>> 0)) >>> 0) > Math.fround(Math.hypot((Math.atan2(( + ( + 2**53+2)), (y >>> 0)) | 0), ((x != mathy0(( + y), ( - x))) | 0)))) >>> 0) : Math.atan2(( + ( + ( + Math.tan(Math.fround(mathy0(Math.fround(x), (y >>> 0))))))), x)))) >>> 0); }); ");
/*fuzzSeed-159544250*/count=446; tryItOut("\"use strict\"; (void schedulegc(g0));");
/*fuzzSeed-159544250*/count=447; tryItOut("\"use strict\"; /*oLoop*/for (var byyeym = 0; byyeym < 25; ++byyeym) { Array.prototype.pop.call(a2, h1, s1, a0, g1, this.s1, h2); } ");
/*fuzzSeed-159544250*/count=448; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan2(Math.atan2(((Math.min(Math.log2((0 , (Math.trunc(y) | 0))), (((( + y) << x) | 0) >>> y)) >>> 0) > (( - y) ? 0/0 : Math.min(Math.fround(y), (Math.clz32(Math.fround(Number.MAX_SAFE_INTEGER)) >>> 0)))), Math.pow(( + (((Math.round(x) - -0x080000000) | 0) % (( + Math.hypot((Math.fround((( + Math.atan((y >>> 0))) | Math.fround(y))) >>> 0), ( + Math.fround(Math.exp((-(2**53) | 0)))))) | 0))), y)), Math.min((Math.imul(x, Math.pow(0x080000001, ( ~ x))) == ((Math.imul(Math.fround(-0x080000000), (Math.min(x, (Math.atanh(Math.fround(((42 >>> 0) < (y >>> 0)))) >>> 0)) >>> 0)) >>> 0) | 0)), ( + (( + (Math.fround(((( + (x | 0)) | 0) - -(2**53-2))) & (Math.fround(y) == ( + (( + x) != ( + x)))))) === ( + ((( + x) === ( + x)) | 0)))))); }); testMathyFunction(mathy0, [0x0ffffffff, Number.MIN_VALUE, -0, 0x100000001, -0x100000000, -(2**53+2), 0/0, 1/0, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), -0x080000001, -0x080000000, -1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0x100000000, 42, 2**53, 0x080000001, -0x0ffffffff, Number.MAX_VALUE, 0, 0x080000000, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE, Math.PI, 2**53+2, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=449; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:(^)))*|(?:[]{4}((?:[^\\\\d\\\\ub059-\\uba4d\\u00a6-\\\\u00c2\\\\u00bc-\\\\u00CF])+){0}){3}(?:[^\\\\W])+?\", \"gyi\"); var s = yield ( ! Math.min(( - x), ( + Math.asin((Math.max(Math.ceil(-0), x) >>> 0))))); print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=450; tryItOut("\"use strict\"; let (a) { ((function ([y]) { })()); }");
/*fuzzSeed-159544250*/count=451; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.fround(Math.atan2(Math.atan2(((( ~ Math.fround((Math.hypot(( + x), ( + -0)) ? Math.fround((Math.expm1((y >>> 0)) >>> 0)) : Math.fround(1.7976931348623157e308)))) | 0) >>> 0), 0x07fffffff), Math.fround((Math.imul(-0x07fffffff, (Math.pow((x >>> 0), y) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [-0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 42, -(2**53), 0/0, -(2**53+2), Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff, 0x080000000, Number.MAX_VALUE, 2**53+2, 2**53, 0x100000000, -1/0, 0, -0, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -0x100000000, -0x080000000, 2**53-2, -0x100000001, 0x100000001, 1]); ");
/*fuzzSeed-159544250*/count=452; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\".\", \"gm\"); var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=453; tryItOut("g2.t1[15] = g2;");
/*fuzzSeed-159544250*/count=454; tryItOut("/*RXUB*/var r = /(?!\\3)/gm; var s = \"\\u00a1\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u00a1\"; print(r.test(s)); ");
/*fuzzSeed-159544250*/count=455; tryItOut("\"use strict\"; g1 + '';");
/*fuzzSeed-159544250*/count=456; tryItOut("mathy1 = (function(x, y) { return mathy0((( ~ (Math.hypot(( + Math.exp(((Math.fround(Math.PI) && x) >>> 0))), (y | 0)) | 0)) % ((Math.atan2((Math.sinh(y) | 0), y) ^ ( + ( - (0x100000001 + ( + x))))) | 0)), Math.fround((( + Math.min(( + ((Math.fround(y) || Math.fround(-Number.MAX_VALUE)) | 0)), (Math.hypot((x | 0), ((( + (y >>> 0)) >>> 0) | 0)) | 0))) ? ( + Math.fround(Math.sign(Math.tanh(Math.atan2(x, Math.fround((Math.fround(x) ? Math.fround(-0x080000001) : (x | 0)))))))) : ( + ( + Math.hypot(mathy0(y, 0.000000000000001), Math.fround(mathy0(Math.atan2(x, Math.fround(Math.ceil((((x | 0) === (y | 0)) | 0)))), ((x >>> 0) == (x >>> 0)))))))))); }); ");
/*fuzzSeed-159544250*/count=457; tryItOut("/*vLoop*/for (let rnyilc = 0; rnyilc < 116; ++rnyilc) { y = rnyilc; /*tLoop*/for (let c of /*MARR*/[objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(),  /x/g , new Number(1.5),  /x/g ,  /x/g , new Number(1.5), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new Number(1.5),  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , new Number(1.5), objectEmulatingUndefined(),  /x/g , new Number(1.5)]) { h1 = x; } } ");
/*fuzzSeed-159544250*/count=458; tryItOut("h1.delete = f1;");
/*fuzzSeed-159544250*/count=459; tryItOut("\"use strict\"; Array.prototype.splice.apply(o0.a0, [NaN, 7, m0]);");
/*fuzzSeed-159544250*/count=460; tryItOut("e0 = new Set(this.s2);");
/*fuzzSeed-159544250*/count=461; tryItOut("/*iii*/a1 + s0;/*hhh*/function ziafns(x, ...y){if(true) {(null);yield this; } else ;}");
/*fuzzSeed-159544250*/count=462; tryItOut("/*infloop*/for(window; \"\\uB73D\"; /\\2*?/m) yield;");
/*fuzzSeed-159544250*/count=463; tryItOut("\"use strict\"; v1 = t2.length;");
/*fuzzSeed-159544250*/count=464; tryItOut("testMathyFunction(mathy4, [0, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, Number.MAX_VALUE, -(2**53+2), -(2**53-2), 0x0ffffffff, -0, 2**53+2, 1/0, -Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 2**53-2, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -0x100000001, Math.PI, -0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, 0/0, Number.MIN_VALUE, -0x080000000, 0x07fffffff, -1/0, 42]); ");
/*fuzzSeed-159544250*/count=465; tryItOut("Object.defineProperty(this, \"o2\", { configurable: (x % 3 != 0), enumerable: \"\u03a0\",  get: function() {  return new Object; } });v2 = Object.prototype.isPrototypeOf.call(v1, f0);");
/*fuzzSeed-159544250*/count=466; tryItOut("o2 = o2.o1.__proto__;");
/*fuzzSeed-159544250*/count=467; tryItOut("(eval(\"\\\"use strict\\\"; v0 = g1.eval(\\\"testMathyFunction(mathy0, [42, -Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, 1/0, 1, Math.PI, 0x080000000, 1.7976931348623157e308, 2**53-2, Number.MIN_VALUE, Number.MAX_VALUE, -1/0, 0x100000001, -Number.MIN_VALUE, -(2**53), -(2**53+2), -0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, 2**53+2, 0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 0/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, 0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); \\\");\"));");
/*fuzzSeed-159544250*/count=468; tryItOut("mathy3 = (function(x, y) { return Math.atan((( + (Math.tanh(( ! ( + ( + Math.cbrt(x))))) | 0)) | 0)); }); ");
/*fuzzSeed-159544250*/count=469; tryItOut("Object.freeze(v2);");
/*fuzzSeed-159544250*/count=470; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.atan2(Math.min(mathy0(Math.sin(( + Math.max((x >>> 0), ( + y)))), Math.min((x | 0), Math.fround(42))), (( ! x) | 0)), Math.fround(( ~ Math.fround(Math.trunc(Math.fround((((Math.fround(Math.log(Math.fround(x))) | 0) % Math.fround(Math.expm1(Math.sin(y)))) | 0))))))); }); testMathyFunction(mathy2, ['/0/', '\\0', (new String('')), 1, null, NaN, 0.1, true, /0/, '0', (new Number(0)), '', (new Boolean(false)), [], objectEmulatingUndefined(), (new Number(-0)), ({toString:function(){return '0';}}), (function(){return 0;}), undefined, -0, (new Boolean(true)), false, ({valueOf:function(){return 0;}}), 0, [0], ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-159544250*/count=471; tryItOut(";");
/*fuzzSeed-159544250*/count=472; tryItOut("h2.set = g1.f2;");
/*fuzzSeed-159544250*/count=473; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (d0);\n    return (((0xfa8eac54)-(0xa6e96504)-(0xaea95cc5)))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, -Number.MIN_VALUE, -(2**53-2), 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 0x100000000, 2**53-2, Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, -0x100000001, 1.7976931348623157e308, 2**53, 0x080000001, -0x080000001, 1, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, Math.PI, -0x07fffffff, 42, 0x100000001, -0x0ffffffff, -(2**53+2), 0.000000000000001, -0x080000000, -(2**53), 0/0]); ");
/*fuzzSeed-159544250*/count=474; tryItOut("mathy5 = (function(x, y) { return (( - ( ~ Math.cosh((Math.sign((x | 0)) | 0)))) | 0); }); testMathyFunction(mathy5, [(new Number(-0)), '\\0', true, (new Number(0)), '0', '/0/', null, 0, [], ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 0.1, -0, false, /0/, '', objectEmulatingUndefined(), (new Boolean(true)), (function(){return 0;}), (new String('')), 1, (new Boolean(false)), NaN, [0], ({valueOf:function(){return '0';}}), undefined]); ");
/*fuzzSeed-159544250*/count=475; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\".\", \"m\"); var s = \"\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=476; tryItOut("mathy0 = (function(x, y) { return (((((Math.fround(Math.trunc(Math.fround(( - 0x080000001)))) >>> 0) % ((( + -0x100000000) << x) >>> 0)) | 0) ? (( + Math.atan2(( + ( + Math.min(Math.imul(y, (Math.pow(x, (y | 0)) | 0)), y))), ( + (Math.fround(x) >>> 0)))) ? (Math.atan2((y >>> 0), y) | -(2**53)) : Math.fround((Math.fround(y) || ( + (y != ( ~ y)))))) : Math.min(( + ( ~ (Math.min(x, x) | 0))), Math.fround(Math.atan2(Math.fround(Math.pow(y, ((((-Number.MIN_VALUE >>> 0) != (Math.abs(( ! y)) | 0)) >>> 0) >>> 0))), Math.fround(Math.fround((((y | 0) >>> Math.fround(((( ~ y) | 0) % x))) | 0))))))) >>> 0); }); testMathyFunction(mathy0, [1/0, 0x07fffffff, 0x100000000, 2**53+2, -0x080000000, 0x0ffffffff, Number.MIN_VALUE, -1/0, 2**53, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -0x080000001, -0x07fffffff, -0, -(2**53), -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, Math.PI, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), 42, 2**53-2, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, 0x080000001, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=477; tryItOut("\"use strict\"; /*MXX2*/g1.Math.hypot = this.b1;");
/*fuzzSeed-159544250*/count=478; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((i0)-((((i1)-(i1)-(0x5d862bfe))>>>((i2)+((imul((0xfdff3ee0), (0xbda55c73))|0) >= (~((0x4b46b882)+(0xfe0aefd2)))))) != ((-(i0))>>>((0x7f8c33f6)+(/*FFI*/ff(((imul((0x4faaf99f), (0x88ee2b3e))|0)), ((((-18446744073709552000.0)) / ((-1.2089258196146292e+24)))))|0)-(i0))))))|0;\n  }\n  return f; })(this, {ff: Object.preventExtensions}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [(new Boolean(true)), /0/, '', '0', ({toString:function(){return '0';}}), 1, true, ({valueOf:function(){return '0';}}), '/0/', undefined, (function(){return 0;}), (new Boolean(false)), (new Number(-0)), 0, (new String('')), ({valueOf:function(){return 0;}}), -0, [0], NaN, [], false, 0.1, '\\0', null, (new Number(0)), objectEmulatingUndefined()]); ");
/*fuzzSeed-159544250*/count=479; tryItOut("\"use strict\"; \"use asm\"; s1.__proto__ = o2.m2;");
/*fuzzSeed-159544250*/count=480; tryItOut("o0.s2 += 'x';");
/*fuzzSeed-159544250*/count=481; tryItOut("mathy1 = (function(x, y) { return ( + (Math.fround((Math.fround(Math.pow((( + x) ? Math.imul((x | 0x080000001), ( - ( + 2**53))) : ( + ((y - (Math.imul(y, x) | 0)) | 0))), ((Math.fround(x) & ( ~ (2**53-2 | 0))) || ((( + Math.cosh(y)) ? (x | 0) : ((((y ? 0/0 : y) >>> ((Math.tan((x >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0)))) << Math.fround(Math.asin(Math.fround(( + Math.imul(y, ( + x)))))))) * (Math.abs((Math.hypot(y, ( + ( ! ( + x)))) >>> 0)) != (Math.hypot(Math.fround(Math.exp((Math.hypot(y, ( ~ (x >= x))) >>> 0))), (Math.fround(Math.sqrt(Math.fround(y))) | 0)) | 0)))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, 42, 0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, -0, 2**53-2, -(2**53), -Number.MAX_VALUE, -(2**53-2), -0x080000001, 0x100000000, -0x0ffffffff, 2**53+2, -1/0, -0x080000000, 0, 0x080000000, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, 0.000000000000001, 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, 1, -0x07fffffff, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=482; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.sqrt(( + Math.fround(( ~ Math.fround((mathy0((( - ( + Math.round(x))) >>> 0), ((x >>> (x | 0)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy4, [[], false, '/0/', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), -0, NaN, ({valueOf:function(){return '0';}}), 1, true, [0], (new Boolean(false)), '0', (function(){return 0;}), (new Boolean(true)), undefined, (new String('')), 0, (new Number(0)), 0.1, '\\0', null, (new Number(-0)), ({toString:function(){return '0';}}), /0/, '']); ");
/*fuzzSeed-159544250*/count=483; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(m2, 7, { configurable: (x % 6 != 3), enumerable: (void options('strict')), writable: false, value: e1 });\n(window);\n");
/*fuzzSeed-159544250*/count=484; tryItOut("\"use strict\"; e2.delete(p1);");
/*fuzzSeed-159544250*/count=485; tryItOut("for (var p in v0) { Array.prototype.pop.call(a1, f0, a1); }");
/*fuzzSeed-159544250*/count=486; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a2, 8, { configurable: (x % 12 != 5), enumerable: /*MARR*/[new String(''), new Boolean(false), new String(''), new String(''), new String(''), new String(''), new Boolean(false), new Boolean(false), new String(''), new String(''), new String(''), new Boolean(false), new String(''), new Boolean(false), new Boolean(false), new String(''), new Boolean(false), new String(''), -1, -1, -1, -1, -1, new Boolean(false), new Boolean(false), new String(''), new String(''), -1, -1, new String(''), -1, -1, new String(''), new String(''), -1, new Boolean(false), new Boolean(false), new Boolean(false), -1, new String(''), new String(''), new String(''), new String(''), -1, -1, new String(''), -1, new String(''), -1].sort, get: f0, set: (function mcc_() { var lkpbxs = 0; return function() { ++lkpbxs; f1(/*ICCD*/lkpbxs % 10 == 7);};})() });");
/*fuzzSeed-159544250*/count=487; tryItOut("/*oLoop*/for (ebahlm = 0; ebahlm < 13; ++ebahlm) { v1 = true; } ");
/*fuzzSeed-159544250*/count=488; tryItOut("\"use strict\"; var qlcnbk = new SharedArrayBuffer(24); var qlcnbk_0 = new Uint16Array(qlcnbk); print(qlcnbk_0[0]); qlcnbk_0[0] = -17; selectforgc(o0);");
/*fuzzSeed-159544250*/count=489; tryItOut("this.v1 = t1.length;");
/*fuzzSeed-159544250*/count=490; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.clz32((( + Math.pow((( + (Math.log2(Math.fround(Math.abs((y | 0)))) | 0)) | 0), ( + Math.min(y, x)))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[ /x/ ,  /x/ ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  /x/ ,  \"\" , false,  \"\" ,  \"\" ,  \"\" ,  /x/ ,  /x/ ,  /x/ , false, false, false, false, false,  /x/ ]); ");
/*fuzzSeed-159544250*/count=491; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a0, 13, ({}));");
/*fuzzSeed-159544250*/count=492; tryItOut("\"use strict\"; delete h1.delete;");
/*fuzzSeed-159544250*/count=493; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot(((Math.fround(Math.log((x >>> 0))) <= Math.fround((Math.log10(((y ? x : x) | 0)) | 0))) >>> 0), Math.fround(( + (( + ( + ( ! ( + Math.round(Math.fround(mathy4(Math.fround(Math.max(( + y), ( + -0x100000000))), x))))))) >= ( + Math.fround(( + Math.fround(mathy0((x | 0), (( + Math.abs(x)) | 0))))))))))); }); testMathyFunction(mathy5, [0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0, 42, -(2**53+2), 0x080000000, -0x100000001, 1, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -0x0ffffffff, 0x080000001, -0, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, -1/0, 0x100000001, 0/0, 2**53, -0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, 0x100000000, Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=494; tryItOut("\"use strict\"; \"use asm\"; v2 = (e1 instanceof f2);");
/*fuzzSeed-159544250*/count=495; tryItOut("\"use strict\"; a1.reverse(a2);");
/*fuzzSeed-159544250*/count=496; tryItOut("v1 = evalcx(\"(makeFinalizeObserver('nursery'))\", this.g2.g1);");
/*fuzzSeed-159544250*/count=497; tryItOut("\"use strict\"; t1.set(a1, x);");
/*fuzzSeed-159544250*/count=498; tryItOut("testMathyFunction(mathy1, [2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000000, -0, 0/0, 0x100000001, Math.PI, 0x080000000, 1/0, 0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, 1, 0, 42, -(2**53+2), -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 2**53-2, -(2**53-2), 1.7976931348623157e308, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x080000001, -0x080000000, -0x0ffffffff, -(2**53), -1/0]); ");
/*fuzzSeed-159544250*/count=499; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Uint32ArrayView[((i2)+(i2)) >> 2]) = ((((0xe21d1*((-144115188075855870.0) == (-8192.0)))>>>((i2)))));\n    return +((x));\n    return +((1.5111572745182865e+23));\n  }\n  return f; })(this, {ff: (NaN, z) => \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -9.44473296573929e+21;\n    var d3 = -32769.0;\n    var i4 = 0;\n    var d5 = -590295810358705700000.0;\n    return (((0xaffd22f3)*-0x9f55c))|0;\n  }\n  return f;}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000000, 0x080000001, -(2**53+2), 0, -0x080000000, -0x0ffffffff, 0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, 1, 0.000000000000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -(2**53), -0, -0x100000001, 2**53+2, -Number.MAX_VALUE, Math.PI, 0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, 1/0, 42, -0x080000001, Number.MIN_VALUE, 2**53, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=500; tryItOut("v0 = g0.runOffThreadScript();");
/*fuzzSeed-159544250*/count=501; tryItOut("v0 = g2.runOffThreadScript();");
/*fuzzSeed-159544250*/count=502; tryItOut("for(let z of [new RegExp(\"(?=.*?)|\\ua517|(?=(?!\\\\3)+?)|(?=.\\\\b)*?\", \"y\") for (d in let (a) true) for each (x in Math.acos(-20)) for each (eval in [(window.eval(\"{}\")) for (this.\u3056 of ((4277) for each (x in true) for each (c in []))) if (/(?!.|$|(?=^))/gym)]) for (window of (\"\\u8126\" if ( '' ))) for each (z in /*UUV2*/(z.fontcolor = z.keyFor))]) return ({ set eval(...b) { yield allocationMarker() } , apply: -0x07fffffff });/*bLoop*/for (ifbizp = 0; ifbizp < 87; ++ifbizp) { if (ifbizp % 5 == 2) { m0 + b0; } else { print(z); }  } ");
/*fuzzSeed-159544250*/count=503; tryItOut("\"use strict\"; \"use asm\"; x;\nprint(this.unwatch(new String(\"-1\")));\nt2 = new Uint8Array(v0);");
/*fuzzSeed-159544250*/count=504; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[null, function(){}, null, null, function(){}, -0, null, null, -0, null, null, null, null, null, -0, null, null, -0, function(){}, null, null, null, null, null, function(){}, null, -0, function(){}, null, null, function(){}, null, -0, null, function(){}, null, null, function(){}, function(){}, function(){}, null, null, function(){}, null, function(){}, null, -0, -0, null, function(){}, null, null, -0, function(){}, null, function(){}, -0, null, -0, null, null, null, null, null, null, null, null, null, function(){}, null, -0, -0, null, null, null, null, null, null, -0, -0, -0, null, -0, -0, -0, -0, function(){}, null, null, null]) { return; }");
/*fuzzSeed-159544250*/count=505; tryItOut("\"use strict\"; g2.t2[v2] = o0;");
/*fuzzSeed-159544250*/count=506; tryItOut("{ void 0; void hasChild(this, this); } a0[1] = this.g2.p0;");
/*fuzzSeed-159544250*/count=507; tryItOut("\u0009x;m0.has(o1);");
/*fuzzSeed-159544250*/count=508; tryItOut("a0 = Array.prototype.filter.apply(a1, [f0, i2, o0, m2]);");
/*fuzzSeed-159544250*/count=509; tryItOut("a0.splice(t1, o2.i1);");
/*fuzzSeed-159544250*/count=510; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions(); } void 0; }");
/*fuzzSeed-159544250*/count=511; tryItOut("testMathyFunction(mathy4, [1.7976931348623157e308, -Number.MIN_VALUE, 2**53, Math.PI, -(2**53-2), 0x080000000, 0x100000000, -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, -(2**53), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53+2), 0x0ffffffff, Number.MIN_VALUE, -0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -0, 42, 0/0, 0, 1, 1/0, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, 0x080000001]); ");
/*fuzzSeed-159544250*/count=512; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(( ! (Math.fround(Math.min(( + ( - ( + ( ! ( + (2**53 + (y | 0))))))), ( ! Math.fround(Math.min(x, ((x ? Math.fround(Math.fround(Math.atanh(( + y)))) : x) * mathy1(( + 0x0ffffffff), ( + mathy1(( + x), x))))))))) >>> 0))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0.000000000000001, 1, -0x07fffffff, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 0x100000001, 0x0ffffffff, Math.PI, 0x080000001, -(2**53+2), 2**53+2, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), 42, 2**53-2, 1/0, 0/0, 2**53, Number.MAX_VALUE, -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, -0, -0x100000000, Number.MIN_VALUE, 0, -Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=513; tryItOut("/* no regression tests found */t2 = new Float64Array(a0);");
/*fuzzSeed-159544250*/count=514; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"-25\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 2 == 0), catchTermination: (x % 4 != 1) }));");
/*fuzzSeed-159544250*/count=515; tryItOut("\"use strict\"; o1.o1.s2 += s2;");
/*fuzzSeed-159544250*/count=516; tryItOut("selectforgc(this.o2);");
/*fuzzSeed-159544250*/count=517; tryItOut("\"use asm\"; testMathyFunction(mathy3, /*MARR*/[(void 0), new String('q'), new String('q'), new String('q'), (void 0), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), (void 0), new String('q'), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), (void 0), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), (void 0), objectEmulatingUndefined(), (void 0), new String('q'), new String('q'), new String('q')]); ");
/*fuzzSeed-159544250*/count=518; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.imul(( + Math.fround(Math.log1p(( + Math.pow(Math.fround((y ? ((Math.log(y) >>> 0) >= x) : mathy2(0x100000000, y))), Math.trunc(Math.max(x, (( + y) >>> 0)))))))), (( ~ ( ! -Number.MAX_SAFE_INTEGER)) , mathy0(( ! Math.min(y, 2**53)), ( ~ ( + (( + (( + (y >>> 0)) >>> 0)) >> (-0 ? x : Math.fround(y))))))))); }); ");
/*fuzzSeed-159544250*/count=519; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.cosh((( + (mathy1(x, Math.fround(( + (((x >>> 0) <= (x >>> 0)) >>> 0)))) | 0)) ** (( + ( + Math.tanh(Math.ceil((( - -0x0ffffffff) | 0))))) | 0))) | 0); }); testMathyFunction(mathy2, [-(2**53+2), 1, 1.7976931348623157e308, 0x100000000, Number.MIN_SAFE_INTEGER, 42, 2**53, -0x100000000, -0, -0x100000001, 0x080000001, -(2**53-2), -Number.MIN_VALUE, 2**53+2, -1/0, -0x080000001, -0x080000000, -0x07fffffff, Math.PI, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, -(2**53), 0/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 1/0, 0, -0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-159544250*/count=520; tryItOut("testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), ((makeFinalizeObserver('nursery'))), objectEmulatingUndefined(), ((makeFinalizeObserver('nursery'))), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, ((makeFinalizeObserver('nursery'))), objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), ((makeFinalizeObserver('nursery'))), ((makeFinalizeObserver('nursery'))), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x100000001, objectEmulatingUndefined(), 0x100000001, true, 0x100000001, true, objectEmulatingUndefined(), ((makeFinalizeObserver('nursery'))), ((makeFinalizeObserver('nursery'))), true, true, ((makeFinalizeObserver('nursery'))), true, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, ((makeFinalizeObserver('nursery'))), 0x100000001, ((makeFinalizeObserver('nursery'))), true, true, objectEmulatingUndefined(), 0x100000001, true, objectEmulatingUndefined(), 0x100000001, 0x100000001, ((makeFinalizeObserver('nursery'))), objectEmulatingUndefined(), ((makeFinalizeObserver('nursery'))), objectEmulatingUndefined(), true, true, 0x100000001, true, 0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x100000001, objectEmulatingUndefined(), true, ((makeFinalizeObserver('nursery'))), objectEmulatingUndefined(), ((makeFinalizeObserver('nursery'))), 0x100000001, ((makeFinalizeObserver('nursery'))), 0x100000001, objectEmulatingUndefined(), true, true, true, objectEmulatingUndefined(), 0x100000001, objectEmulatingUndefined(), 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, 0x100000001, ((makeFinalizeObserver('nursery'))), objectEmulatingUndefined(), true, true, 0x100000001, 0x100000001, 0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, ((makeFinalizeObserver('nursery'))), ((makeFinalizeObserver('nursery'))), ((makeFinalizeObserver('nursery'))), ((makeFinalizeObserver('nursery')))]); ");
/*fuzzSeed-159544250*/count=521; tryItOut("\"use strict\"; {e1 = x; '' .__defineSetter__(\"eval\", (new Function(\"Array.prototype.unshift.call(a0, a2, g0, m1, m2, p1);\"))); }");
/*fuzzSeed-159544250*/count=522; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[x, objectEmulatingUndefined(), ['z'], ['z'], -Infinity, -Infinity, x, objectEmulatingUndefined(), x, ['z'], -Infinity, x, -Infinity, -Infinity, -Infinity, objectEmulatingUndefined(), ['z'], ['z'], objectEmulatingUndefined(), -Infinity, x, x, ['z'], ['z'], ['z'], -Infinity, x, -Infinity, ['z'], objectEmulatingUndefined(), -Infinity, ['z'], x, x, ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], objectEmulatingUndefined(), ['z'], ['z'], x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x]); ");
/*fuzzSeed-159544250*/count=523; tryItOut("delete h1.delete;function z(x) { \"use strict\"; a2 = g1.a1.slice(NaN, -16); } print(x);");
/*fuzzSeed-159544250*/count=524; tryItOut("mathy2 = (function(x, y) { return Math.expm1((Math.atan2(mathy1(Math.fround(((42 | 0) ? (x | 0) : (x | 0))), Math.imul(Math.fround(( - y)), (( ! ( + x)) >>> 0))), (Math.abs(x) ? Math.tan(x) : -0x100000000)) | 0)); }); testMathyFunction(mathy2, [-1/0, -0x100000001, Math.PI, -0x0ffffffff, 1/0, 0x07fffffff, -0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -0, Number.MAX_VALUE, 0/0, Number.MIN_VALUE, 0x100000001, 0x100000000, 0, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), -0x100000000, -Number.MAX_VALUE, 0.000000000000001, -(2**53-2), 2**53+2, -0x07fffffff, 42, 2**53]); ");
/*fuzzSeed-159544250*/count=525; tryItOut("/*ADP-2*/Object.defineProperty(a0, 17, { configurable: true, enumerable: (x % 2 != 0), get: (function() { try { g1.i0.send(t1); } catch(e0) { } g1.offThreadCompileScript(\"mathy4 = (function(x, y) { \\\"use strict\\\"; return Math.fround(Math.log10(((((( - ( + x)) >>> 0) - (Math.fround(( ! (( - (Math.fround(y) === Math.fround(y))) >>> 0))) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy4, [-0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, -(2**53), -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), -0x080000001, 0/0, 1.7976931348623157e308, 42, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 1, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, Math.PI, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, -0x080000000, 2**53-2, -1/0, 0, 0x100000000, 0x080000000, 0.000000000000001]); \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 40 != 22), catchTermination: x, sourceMapURL: g0.s2 })); return b1; }), set: (function() { try { o0.g0.s1 = new String; } catch(e0) { } a1.splice(NaN, 10, a1); return o2; }) });");
/*fuzzSeed-159544250*/count=526; tryItOut("testMathyFunction(mathy0, [Math.PI, 2**53+2, 1.7976931348623157e308, -Number.MAX_VALUE, 0, -Number.MIN_VALUE, -0x0ffffffff, 0x080000001, -(2**53+2), -(2**53-2), 0x07fffffff, 42, -0, 0.000000000000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 1/0, 2**53, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, 0x100000001, Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, Number.MIN_VALUE, 2**53-2, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, -0x080000000, -0x080000001, -(2**53)]); ");
/*fuzzSeed-159544250*/count=527; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy0(((Math.fround((Math.fround(y) ? (Math.fround((Math.fround(y) | Math.fround(x))) >>> 0) : Math.fround(mathy3((( - (( + -(2**53)) | 0)) >>> 0), ( + ( + ( + -(2**53-2)))))))) >>> (((( + mathy0((y >>> 0), (y >>> 0))) | 0) ^ (Math.hypot((x | 0), (-0x07fffffff | 0)) | 0)) | 0)) | 0), Math.max(((y | 0/0) | 0), mathy3(Math.atan(y), (mathy0((-0 >>> 0), (Math.hypot(Math.fround((Math.fround(x) ** Math.fround(( - y)))), ( ! (y >>> 0))) | 0)) >>> 0)))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, -0x080000000, Math.PI, Number.MIN_VALUE, 1/0, 0x0ffffffff, 0x100000000, -(2**53), 0x080000000, 2**53+2, 0/0, 42, 1, 0.000000000000001, -0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0, -0x07fffffff, -0x0ffffffff, -1/0, -0x100000000, 0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53-2), -(2**53+2), 2**53-2, -0x100000001]); ");
/*fuzzSeed-159544250*/count=528; tryItOut("m2.delete(o2.g1);");
/*fuzzSeed-159544250*/count=529; tryItOut("h2.enumerate = f2;([]);");
/*fuzzSeed-159544250*/count=530; tryItOut("this.a1.push(v2);");
/*fuzzSeed-159544250*/count=531; tryItOut("/*oLoop*/for (var snhhkk = 0; snhhkk < 8; ++snhhkk) { ; } ");
/*fuzzSeed-159544250*/count=532; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow((Math.imul(( + Math.expm1(y)), (Math.asinh((Math.clz32(y) | 0)) | 0)) >>> 0), ( + Math.pow(( + Math.max(( + ( ~ Math.fround(((x | 0) > (y | 0))))), ( + mathy0(Math.pow(y, Math.fround(((Math.fround(x) || y) & Math.fround(2**53+2)))), Math.expm1(((((x >>> 0) ? (-0x080000001 >>> 0) : (y >>> 0)) >>> 0) | 0)))))), (Math.atan2((((((( ! x) >>> 0) >>> 0) === (( + ((( + (x | 0)) | 0) >>> 0)) >>> 0)) >>> 0) | 0), mathy0(0, y)) | 0)))); }); ");
/*fuzzSeed-159544250*/count=533; tryItOut("(x);");
/*fuzzSeed-159544250*/count=534; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(mathy0((Math.fround(( ~ Math.cbrt(y))) == (( + mathy0(( + x), ( + -(2**53-2)))) , Math.abs((mathy0(x, y) | 0)))), ( ! ( - x))), ( ! mathy0(mathy0(x, x), Math.max(y, x)))); }); testMathyFunction(mathy1, [0, -(2**53+2), 0x100000000, -Number.MIN_VALUE, 0.000000000000001, -(2**53-2), 1/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, 42, 0x0ffffffff, 1.7976931348623157e308, 2**53-2, 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0x080000000, 1, 0/0, -0x100000001, 0x07fffffff, -0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 2**53+2, -0x100000000, Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-159544250*/count=535; tryItOut("mathy4 = (function(x, y) { return (( + ((Math.cosh((((( - (y | 0)) | 0) , (mathy2(((Math.asin(( + (x ** Math.fround(y)))) | 0) >>> 0), (x >>> 0)) >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-(2**53-2), 0.000000000000001, 1.7976931348623157e308, 0x100000000, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, 2**53-2, -0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 0/0, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, 0, -0x100000000, -0x100000001, 2**53, 0x100000001, 2**53+2, 1/0, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 42, -(2**53), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, 1, -0x080000001]); ");
/*fuzzSeed-159544250*/count=536; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan((( - ( + Math.cbrt(( + ( ~ (-(2**53+2) | 0)))))) >>> 0))); }); ");
/*fuzzSeed-159544250*/count=537; tryItOut("\"use strict\"; a1.unshift(\u3056 = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: Date.prototype.toISOString, defineProperty: (function(x, y) { \"use strict\"; return x; }), getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return false; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function() { return false; }, get: false, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(-27), objectEmulatingUndefined) /  \"\" .__defineSetter__(\"x\", function(q) { return q; }));");
/*fuzzSeed-159544250*/count=538; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (Math.fround(Math.trunc(mathy3(Math.ceil(( + 0)), ((Math.imul((Math.hypot((( + ( ~ (x >>> 0))) | 0), (-Number.MIN_VALUE | 0)) | 0), ( + 0)) | 0) | 0)))) >= ( + Math.acosh((( ~ Math.fround((x >= Math.fround(x)))) , mathy1(Math.fround(Math.acosh(Math.fround((y !== x)))), (( - (mathy0((x | 0), -Number.MIN_VALUE) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, -0x100000000, 1, 0x100000000, 1/0, 0x080000000, 1.7976931348623157e308, -(2**53-2), 42, 0x0ffffffff, 0x080000001, Number.MAX_VALUE, -0x0ffffffff, -0x080000001, 2**53-2, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), -0, 2**53, 0.000000000000001, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 0, Number.MIN_VALUE, -0x100000001, -(2**53+2), -1/0, 0/0, 0x100000001]); ");
/*fuzzSeed-159544250*/count=539; tryItOut("\"use strict\"; a0 = arguments.callee.caller.caller.caller.arguments;");
/*fuzzSeed-159544250*/count=540; tryItOut("m0.has(o2.s2);");
/*fuzzSeed-159544250*/count=541; tryItOut("testMathyFunction(mathy0, [0.000000000000001, -0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, 1, Number.MIN_VALUE, 0/0, 42, 2**53-2, 0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53-2), -0x07fffffff, 0x080000001, -0x100000001, 2**53, -0, -1/0, -(2**53+2), -(2**53), 1/0, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 2**53+2, -0x080000001, 0, -0x0ffffffff, -0x080000000, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=542; tryItOut("/*RXUB*/var r = /(?!(?:^)|(?=[\\d\\S\\cT-\u6782])|\\u307A(?!(\\B)|\u070b)|(?!(?=\\2^{3,}))^){0}/im; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=543; tryItOut("\"use strict\"; g2 = this.a2[x];");
/*fuzzSeed-159544250*/count=544; tryItOut("/*infloop*/for(let {} =  /x/ .slice(true,  /x/g ); x; /*UUV2*/(x.findIndex = x.entries)) {([[1]]); }");
/*fuzzSeed-159544250*/count=545; tryItOut("/*MXX2*/g2.Array.prototype.includes = h0;");
/*fuzzSeed-159544250*/count=546; tryItOut("\"use strict\"; print(( /x/  %=  /x/g .add(x = eval(\"\\\"use strict\\\"; o1.a2[16];\"), (window) = (uneval(x))) |= \u000918));");
/*fuzzSeed-159544250*/count=547; tryItOut("\"use strict\"; var x = new RegExp(\"[^]-\\\\uc167\\u001b\\\\d]|\\\\w(?![\\\\f-\\u00b8\\\\t-\\\\x46\\\\D])|\\\\B\\\\d+?|\\u5699\", \"yi\")\n, x, x, \u3056, x;");
/*fuzzSeed-159544250*/count=548; tryItOut("bqtftg();/*hhh*/function bqtftg(){/* no regression tests found */}");
/*fuzzSeed-159544250*/count=549; tryItOut("o2 = Proxy.create(h0, p1);");
/*fuzzSeed-159544250*/count=550; tryItOut("o0.m2.delete(f1);\na0.toString = (function() { try { g1.toString = Math.atan2.bind(g0); } catch(e0) { } try { a1[8] = m1; } catch(e1) { } v2 = evaluate(\"function this.f2(a1) \\\"use asm\\\";   var atan2 = stdlib.Math.atan2;\\n  var imul = stdlib.Math.imul;\\n  var pow = stdlib.Math.pow;\\n  var abs = stdlib.Math.abs;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    {\\n      d0 = (0.0009765625);\\n    }\\n    (Float64ArrayView[0]) = ((+(0.0/0.0)));\\n    {\\n      d0 = (-1.2089258196146292e+24);\\n    }\\n    {\\n      i1 = (i2);\\n    }\\n    d0 = (+((d0)));\\n    d0 = (-((2097153.0)));\\n    {\\n      i1 = (((-13 = x)) < (0xffffffff));\\n    }\\n    i1 = ((~~(+atan2(((576460752303423500.0)), ((Float32ArrayView[((i1)-(1)+(i1)) >> 2]))))));\\n    {\\n      (Uint8ArrayView[((((0xf45a0816) < (0xcff6a8bd)) ? ((Float64ArrayView[((0xcdd1b950)) >> 3])) : (1))-((((i2)*-0xbb861)|0))) >> 0]) = (((((0xfe73ac00)) & (((((0x9e2f8281)-(-0x8000000)+(0x1fae30d4)) ^ ((0x36742cdc) / (0x932c523e))) != (0x25eac90b))-((0xe5f4d10) ? (i2) : ((4097.0) <= (9.0)))-(((NaN) = /\\\\1+?|(?!\\\\r{0,0})+?/ym)))))+(!(0x4814fb3e)));\\n    }\\n    return ((((d0) > (-70368744177665.0))+(0x6deefbd2)-(0xffffffff)))|0;\\n    i2 = ((+((d0))) < (+(1.0/0.0)));\\n    switch ((~~(d0))) {\\n      case -3:\\n        i2 = (i1);\\n        break;\\n      case -3:\\n        (Uint8ArrayView[0]) = ((i1));\\n        break;\\n      case 1:\\n        (Float32ArrayView[(--this.zzz.zzz) >> 2]) = ((3.094850098213451e+26));\\n      default:\\n        d0 = (((((imul((0xfee572bb), (0xfd0c4b5c))|0) / (imul((0x21a829e0), (0x54033485))|0)) & (((0x0))+((0x29703826) > (0x98a02b31)))) >= (~(((0xcb22c8c) == (0x62de47c4))+(i1)-((0x2a1c2341) > (-0x8000000))))) ? (d0) : (-36028797018963970.0));\\n    }\\n    d0 = (d0);\\n    i2 = ((i2) ? (0xfcd6530c) : (i1));\\n    (NaN , \\u3056 < this) = ((((((((+pow(((36028797018963970.0)), ((1048577.0))))) * (((d = x)()))) == (+abs(((d0))))))>>>((((-(!(-0x8000000)))>>>((!(0xe92bb48e))-((0xfee7eadf) ? (0xaf49bca3) : (0xf84efb87)))) != (((0xb9cf64a8)+((0x7fd3f23d) <= (0x691ac600)))>>>((-0x4ccc7e3)*0x5bb92))))) == (function(id) { return id })));\\n    i2 = ((0xffffffff) != (0x635e8563));\\n    {\\n      i2 = (i2);\\n    }\\n    i1 = (1);\\n    i2 = (0xe2b42a8d);\\n    {\\n      (Float64ArrayView[((i2)-(!((Int32ArrayView[0])))+(i1)) >> 3]) = ((+((-((+(-1.0/0.0)))))));\\n    }\\n    return (((!(((0xc6931*(i1))>>>((((0xff12c65c)) ^ ((0x3476b0e7))) / (imul((0xfb57397a), (0xfdd6ab37))|0))) >= ((-0x4ecb1*(i2))>>>(((0xffffffff))))))*0x560b0))|0;\\n  }\\n  return f;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 38 != 24), sourceIsLazy: false, catchTermination: true })); return e1; });\n");
/*fuzzSeed-159544250*/count=551; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (NaN);\n    }\n    i1 = (/*FFI*/ff(((-0x77f286f)), ((-((+(1.0/0.0))))), ((d0)), (x), ((d0)), ((-((-(((-144115188075855870.0) + (-0.015625))))))), ((-72057594037927940.0)), (((i1))), (((-((67108864.0))))), ((-8193.0)), ((-536870912.0)), ((72057594037927940.0)), ((-137438953472.0)))|0);\n    d0 = (d0);\n    return +((((abs((((0x37d57c61)+((0x8fd57850) == (0x94e3188e))-(i1)) | ((Int32ArrayView[((0x15eca000) / (0x65463a65)) >> 2]))))|0)) ? (-((((-524287.0)) / ((d0))))) : (-68719476737.0)));\n  }\n  return f; })(this, {ff: ((function(y) { yield y; v1 = NaN;; yield y; }).bind(x)).call}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53), Math.PI, -0x100000000, 0.000000000000001, 42, -(2**53+2), -1/0, -0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, 0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, 0x100000001, -0x100000001, -(2**53-2), 0x080000000, Number.MIN_VALUE, 1, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, 0, 2**53-2, 0/0, 0x100000000, -0x080000001, Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-159544250*/count=552; tryItOut("L: {print(this.s0);var nyduyl = new ArrayBuffer(8); var nyduyl_0 = new Float32Array(nyduyl); v1 = Array.prototype.reduce, reduceRight.call(a1, f0, this.e2); }");
/*fuzzSeed-159544250*/count=553; tryItOut("\"use strict\"; v1 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 6 == 4), sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-159544250*/count=554; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.min(Math.fround(Math.fround(( + ((Math.fround(0/0) == (( + y) | ( + y))) | 0)))), Math.fround((Math.pow(((Math.fround((Math.fround((x >>> Math.fround(( + ( + -(2**53)))))) <= Math.fround((Math.hypot((x | 0), y) | 0)))) == (( ! ((mathy2(x, (x - Math.fround(( ! (y >>> 0))))) >>> 0) | 0)) | 0)) >>> 0), (Math.fround(mathy0((( ! (x >>> 0)) >>> 0), (((-0x080000000 ? Math.atan2(y, x) : Math.tanh(Math.max(-0x080000000, -Number.MIN_VALUE))) >>> 0) >>> 0))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [-1/0, 0x080000000, -0x07fffffff, 1, 1/0, 2**53, Number.MAX_SAFE_INTEGER, -0x100000000, 0, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -0x080000000, Math.PI, 0/0, -(2**53-2), 0.000000000000001, 1.7976931348623157e308, 2**53-2, 0x100000001, -(2**53), -Number.MAX_VALUE, 0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 42, Number.MIN_VALUE, -0x080000001, 0x100000000]); ");
/*fuzzSeed-159544250*/count=555; tryItOut("\"use strict\"; print(g0);");
/*fuzzSeed-159544250*/count=556; tryItOut("{print(x); }");
/*fuzzSeed-159544250*/count=557; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=558; tryItOut("");
/*fuzzSeed-159544250*/count=559; tryItOut("v0 = a0.length;");
/*fuzzSeed-159544250*/count=560; tryItOut("testMathyFunction(mathy1, [0.000000000000001, -0x07fffffff, -(2**53+2), 0, -0, Number.MAX_VALUE, -1/0, 1, -0x0ffffffff, 2**53+2, 0/0, -(2**53), 0x100000000, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 42, 2**53-2, Number.MIN_VALUE, 1.7976931348623157e308, 2**53, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-159544250*/count=561; tryItOut("\"use strict\"; v1 = new Number(f0);");
/*fuzzSeed-159544250*/count=562; tryItOut("L: for (a of /*UUV2*/(x.toLocaleString = x.forEach)) {print(x); }/*\n*/");
/*fuzzSeed-159544250*/count=563; tryItOut("h0.hasOwn = f2;");
/*fuzzSeed-159544250*/count=564; tryItOut("mathy5 = (function(x, y) { return (mathy3(( ~ ((((Math.fround(Math.atan(Math.fround((( + Math.hypot(x, ( + x))) / Math.atanh((Number.MAX_VALUE | 0)))))) | 0) <= Math.fround((Math.fround((Math.expm1((( - (2**53-2 >>> 0)) >>> 0)) | 0)) < Math.fround(( + ( - 0x07fffffff)))))) | 0) >>> 0)), ((Math.min((( + Math.log1p(( + ( + Math.max(Math.hypot(y, y), ( ! Number.MAX_VALUE)))))) | 0), ( + mathy1(( + (mathy1(((x < (Math.clz32((1 | 0)) ? y : y)) | 0), (0x080000001 | 0)) | 0)), ( + ((Math.imul((( + Math.pow(x, ( + Number.MAX_SAFE_INTEGER))) | 0), Math.fround(((y >>> 0) == Math.fround(y)))) >> (mathy0(Math.fround(y), Math.fround(((y === x) >>> 0))) | 0)) | 0))))) | 0) | 0)) | 0); }); testMathyFunction(mathy5, [/0/, null, NaN, undefined, 0, '\\0', '/0/', -0, '0', (new Number(-0)), 1, ({toString:function(){return '0';}}), objectEmulatingUndefined(), false, '', [0], (new Boolean(false)), (new Number(0)), [], (new String('')), (new Boolean(true)), ({valueOf:function(){return 0;}}), (function(){return 0;}), ({valueOf:function(){return '0';}}), true, 0.1]); ");
/*fuzzSeed-159544250*/count=565; tryItOut("\"use strict\"; {m2.get(p1);/*oLoop*/for (var aioxqh = 0; aioxqh < 31; ++aioxqh) { for (var v of m1) { try { i0.next(); } catch(e0) { } try { this.a0.forEach((function() { for (var j=0;j<8;++j) { f2(j%2==0); } }), h1, e2, i2, o1.p0, m1); } catch(e1) { } g2.v1 = Object.prototype.isPrototypeOf.call(v1, t2); } }  }this.e2.has(g2);function x(window = (x) = Math.max(-27, 4)) { \"use strict\"; print(23);objectEmulatingUndefined } /*MXX3*/this.g1.RangeError.name = g0.RangeError.name;\n{o1 = Object.create(p0);o0.o2 + m2; }\n");
/*fuzzSeed-159544250*/count=566; tryItOut("\"use strict\"; for(let c in (4277)) {/*hhh*/function wvrpqc(x = (4277), w){t2.toSource = (function() { try { v1 = t2.length; } catch(e0) { } try { s1 = new String; } catch(e1) { } try { r2 = /\\1/gim; } catch(e2) { } e2.add(a1); return b1; });}/*iii*/m2.delete(this.p2);\n/*vLoop*/for (lbrnci = 0, true &=  \"\" ; lbrnci < 27; ++lbrnci) { const y = lbrnci; h2.getOwnPropertyNames = f2; } \n }");
/*fuzzSeed-159544250*/count=567; tryItOut("\"use strict\"; a1 = Array.prototype.concat.call(a2, a2, i2, i1);");
/*fuzzSeed-159544250*/count=568; tryItOut("let qsirok; '' ;");
/*fuzzSeed-159544250*/count=569; tryItOut("Array.prototype.unshift.call(a0, ([1,,]), o0);");
/*fuzzSeed-159544250*/count=570; tryItOut("do e1.has(m0); while(([1,,].eval(\"h1.get = f1;\")) && 0);function \u3056(c, this) { \"use strict\"; /*oLoop*/for (let dnnpon = 0; dnnpon < 9 && (z); ++dnnpon) { v2 = t0.length; }  } return;\nreturn;\n");
/*fuzzSeed-159544250*/count=571; tryItOut("testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, 1/0, Number.MIN_VALUE, 0/0, 0x100000001, 2**53+2, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 1, -1/0, 0x080000000, -(2**53+2), 2**53-2, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 2**53, 0.000000000000001, -0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, Math.PI, -0x07fffffff, -0x080000001, 0, -Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=572; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (((Math.cosh(( + Math.max(( + (y % (Math.max(( - y), ( + x)) | 0))), ( + Math.asinh(x))))) | 0) === ((Math.atan2(((( + (-(2**53+2) >>> 0)) >>> 0) ? x : Math.cosh(y)), Math.acos(y)) >> Math.atanh(Math.log(Math.fround(( + Math.fround(x)))))) | 0)) | 0); }); testMathyFunction(mathy5, [0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), Math.PI, -0x100000000, -0x080000001, 1, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 0x080000001, -1/0, -0, 0x100000001, 0/0, 2**53, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 2**53+2, -Number.MAX_VALUE, 42, 0x0ffffffff, 1/0, 0, 0x100000000, -0x080000000, 0x07fffffff, Number.MIN_VALUE, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=573; tryItOut("testMathyFunction(mathy4, [0.000000000000001, 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, 1/0, 2**53+2, 2**53, 1.7976931348623157e308, -(2**53-2), 42, -Number.MIN_SAFE_INTEGER, 1, -0x100000001, -0x07fffffff, -0x100000000, -1/0, 2**53-2, -(2**53+2), 0x080000001, 0/0, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), 0, -0, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-159544250*/count=574; tryItOut("mathy0 = (function(x, y) { return Math.log2((( + (Math.hypot(( + (-0x100000000 % Math.hypot(( ~ Math.PI), Math.fround(Math.min(x, 0x07fffffff))))), (Math.fround((x === -0x080000000)) >> x)) ? ( + ( + (((((x >>> 0) ? ((x ? Math.sqrt(x) : (Math.atanh((x | 0)) | 0)) >>> 0) : (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) >>> Math.min(x, Math.hypot(y, Math.fround(( + 1.7976931348623157e308))))) >>> 0))) : ( + (((Math.trunc(Math.fround(Math.pow(( + y), x))) | 0) / (( ! (( ! ( + 2**53-2)) >>> 0)) | 0)) | 0)))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[[(void 0)], [(void 0)], [(void 0)], x, x, [(void 0)], [(void 0)], [(void 0)], [(void 0)], x, x, x, [(void 0)], x, x, x, x, x, x, [(void 0)], x, [(void 0)], x, x]); ");
/*fuzzSeed-159544250*/count=575; tryItOut("mathy1 = (function(x, y) { return ((( + (( ~ Math.fround(Math.round(((x ? (false >>> 0) : ( + x)) >>> 0)))) == (Math.tanh(( ! (mathy0(y, x) | 0))) | 0))) >= (Math.ceil((( ! Math.fround(( ~ ( + Math.cos(mathy0(-0x100000000, Math.atan2(-1/0, y))))))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 1, 42, -0x07fffffff, 0x07fffffff, -0x100000001, -0, 0, 0x100000000, -0x080000001, 0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, 2**53, 2**53+2, -Number.MIN_VALUE, 0/0, -1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, -(2**53), 1/0, 0x0ffffffff, -(2**53+2), 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, -0x100000000, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-159544250*/count=576; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.hypot(mathy0((( + ( + ( + Math.sin(mathy2((( ~ x) | 0), -0x0ffffffff))))) | 0), (Math.fround(Math.trunc(Math.fround(((2**53 >>> 0) >= ((Math.fround(0.000000000000001) >= (mathy1(y, y) | 0)) | 0))))) >>> 0)), ( ~ ( + (Math.fround(( + x)) - Math.fround(( + ( ! mathy1(y, x)))))))); }); testMathyFunction(mathy3, [null, false, (new String('')), 0.1, '0', (new Boolean(false)), 1, ({valueOf:function(){return 0;}}), '\\0', objectEmulatingUndefined(), '', (new Boolean(true)), -0, true, undefined, (new Number(-0)), '/0/', ({valueOf:function(){return '0';}}), /0/, NaN, [], 0, ({toString:function(){return '0';}}), (new Number(0)), (function(){return 0;}), [0]]); ");
/*fuzzSeed-159544250*/count=577; tryItOut("mathy3 = (function(x, y) { return Math.sin((( ~ Math.log1p(Math.fround(( ~ Math.fround(y))))) | 0)); }); testMathyFunction(mathy3, [-0x080000000, 1, 42, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, 0.000000000000001, 0x080000001, Math.PI, 0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 0x100000001, 0, 2**53+2, -0x07fffffff, -0, 0x07fffffff, 1.7976931348623157e308, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), 0x100000000, 0/0, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=578; tryItOut("");
/*fuzzSeed-159544250*/count=579; tryItOut("\"use strict\"; s0 = new String(h2);");
/*fuzzSeed-159544250*/count=580; tryItOut("var e0 = new Set;");
/*fuzzSeed-159544250*/count=581; tryItOut("i1 = new Iterator(this.a1);");
/*fuzzSeed-159544250*/count=582; tryItOut("\"use strict\"; for(let c in []);(/(?:(?:\\1)\\u0945{4}\\b\\b\\1{4,7}|\u4869\\D+?\\1.)/i)(x) = e;");
/*fuzzSeed-159544250*/count=583; tryItOut("s2.valueOf = (function() { for (var j=0;j<141;++j) { f1(j%4==0); } });");
/*fuzzSeed-159544250*/count=584; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.abs((( ~ (((y | 0) ? Math.fround((Math.fround(y) * Math.fround(Math.atan2(x, ( + mathy2(( + 0x0ffffffff), ( + -Number.MAX_VALUE))))))) : x) | 0)) ^ (Math.min((y == Math.fround((y , x))), (( + Math.cbrt(Math.log10((x >>> 0)))) | 0)) ? x : (( + Math.max(x, ( + y))) >>> (Math.asin(y) >>> 0))))); }); testMathyFunction(mathy3, [-(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, 0/0, -0x080000000, 1, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, 0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, 0x100000001, 1.7976931348623157e308, -(2**53+2), 2**53+2, -1/0, -0x100000001, 0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, -0x100000000, 0x080000000, Number.MAX_VALUE, -0x07fffffff, -0, Number.MIN_VALUE, 1/0, 0.000000000000001, 2**53-2, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=585; tryItOut("\"use strict\"; for (var p in g0.b1) { g0 + ''; }");
/*fuzzSeed-159544250*/count=586; tryItOut("m1.__iterator__ = (function() { for (var j=0;j<43;++j) { f1(j%3==1); } });");
/*fuzzSeed-159544250*/count=587; tryItOut("\"use strict\"; print((Int16Array.prototype = 'fafafa'.replace(/a/g, WeakSet)));\n/*RXUB*/var r = new RegExp(\"(?![^\\ufb5a\\\\cM\\\\x2B\\u00b8]|(?=\\u788a)|\\\\\\u92fa{3,})\", \"gyim\"); var s = \"\"; print(uneval(r.exec(s))); \n");
/*fuzzSeed-159544250*/count=588; tryItOut("m2.set(p1, h0);");
/*fuzzSeed-159544250*/count=589; tryItOut("testMathyFunction(mathy0, [2**53-2, 0x100000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -Number.MIN_VALUE, -0x0ffffffff, 0/0, -(2**53), -0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, -1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, -0x100000000, 1/0, 0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, 42, 1, -0, -0x100000001, 0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), 0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=590; tryItOut("\"use strict\"; Array.prototype.unshift.call(o0.a1, t2);");
/*fuzzSeed-159544250*/count=591; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-159544250*/count=592; tryItOut("/*RXUB*/var r = /(?!((?!.)?)(?:\\2|\\u007b.|\\x01{4,8}|\\B))*/im; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=593; tryItOut("let (w) { print((4277)); }");
/*fuzzSeed-159544250*/count=594; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy0((Math.hypot((((42 >>> 0) == (x >>> 2**53-2)) >>> 0), (((y ? x : ( + (x + Math.cosh(y)))) >>> 0) >>> 0)) >>> 0), ( - (mathy0(((( + y) != ( + mathy2(y, mathy2(y, y)))) >>> 0), mathy0((x >>> 0), (( + (x == Math.imul((y | 0), (y | 0)))) >>> 0))) | 0))); }); testMathyFunction(mathy3, [-0x100000000, 0x080000001, -(2**53+2), Number.MIN_VALUE, 2**53+2, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -0, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), 1.7976931348623157e308, -(2**53), 0x0ffffffff, 0, 0x100000000, 2**53, 0x100000001, 0/0, Number.MAX_VALUE, -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000001, 1, 1/0]); ");
/*fuzzSeed-159544250*/count=595; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return ( - (( - (Math.hypot((x | 0), (((( - (x | 0)) | 0) ? (Math.hypot(((Math.imul((x | 0), (Math.pow(x, x) | 0)) | 0) | 0), (1/0 | 0)) >>> 0) : y) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy1, [0/0, -0x100000001, -0x100000000, 42, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, -Number.MAX_VALUE, -0x080000000, 0.000000000000001, 0x080000001, 1, 0x07fffffff, -0x07fffffff, -(2**53), 2**53+2, -(2**53-2), -(2**53+2), -Number.MIN_VALUE, Math.PI, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53, -0x080000001, 2**53-2, -0, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 0, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=596; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return ((mathy0((mathy0(((Math.clz32(-0x080000001) >>> 0) >>> 0), (Math.abs(y) >>> 0)) >>> 0), Math.fround((Number.MAX_SAFE_INTEGER < (Math.min(42, x) % ( + (( + x) >>> ( + (((y >>> 0) <= (x >>> 0)) >>> 0)))))))) >>> 0) ? ((Math.fround(Math.pow(( ! ( + mathy0(( ! Math.fround(y)), ( ~ ( + x))))), x)) && ((Math.fround(((y >>> 0) ? 2**53-2 : Math.fround(( + ( + ( + ( + Number.MAX_SAFE_INTEGER))))))) ? ( + (( + Number.MIN_SAFE_INTEGER) << Math.fround(x))) : (( + Math.pow(Math.fround(((y | 0) ** (x | 0))), ( + x))) | 0)) >>> 0)) >>> 0) : (Math.atan2((Math.cbrt((-0x100000001 >>> 0)) >>> 0), x) | (mathy0((x | 0), ((x || (( + (( ~ Math.atan2(Math.fround(0x100000001), -Number.MIN_VALUE)) | 0)) | 0)) | 0)) | 0))); }); testMathyFunction(mathy1, [2**53+2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, 2**53-2, -(2**53+2), 0x080000000, -0x100000000, 0x100000000, 2**53, 1/0, -0x100000001, 42, 0x100000001, 1.7976931348623157e308, Math.PI, 0x0ffffffff, -(2**53-2), 0x080000001, -(2**53), -0x07fffffff, -0x080000000, 0, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -0x080000001, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=597; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.fround(Math.log1p(((( ~ Math.fround((( + (Math.hypot(Math.fround(y), (-Number.MIN_VALUE | 0)) | 0)) < Math.fround(-0x100000001)))) >>> 0) | 0))), ( + Math.asin((Math.fround(((((Math.round(y) >>> 0) && x) >>> 0) * ( + Math.cosh(((x >>> 0) ? x : x))))) , Math.fround((Math.sqrt((( - ( - x)) | 0)) | 0)))))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, 0x100000000, -(2**53-2), -Number.MAX_VALUE, -0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -0x080000001, -0x07fffffff, 0x07fffffff, 0x0ffffffff, 0/0, -(2**53+2), 2**53+2, 0.000000000000001, 1, 0, 2**53-2, -(2**53), Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 42, 0x100000001, -0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 1/0, 2**53, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=598; tryItOut("let d = ({\"-13\": intern(2) }), x = x, [] = objectEmulatingUndefined();i1 + s0;");
/*fuzzSeed-159544250*/count=599; tryItOut("\"use strict\"; m2.delete(s1);/*RXUB*/var r = /(?=(\\W|((${3,}){1023,}))(?!(?!(?!\\W([^])))|(?=\\1{4,})))|(?:((?=(?=\\b)\\d){3,}))/y; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-159544250*/count=600; tryItOut("\"use strict\"; \"use asm\"; for (var p in o1.o0) { try { ((eval(\"delete x.w\", 'fafafa'.replace(/a/g, (let (c)  \"\" )))))((((function sum_slicing(xkxakz) { o1.t0.toString = (function() { a1[v1] = v0; return g1; });; return xkxakz.length == 0 ? 0 : xkxakz[0] + sum_slicing(xkxakz.slice(1)); })(/*MARR*/[0x10000000, 0x10000000, (0/0), 0x10000000, (0/0), 0x10000000, 0x10000000, (0/0), (0/0), (0/0), (0/0), 0x10000000])) ^ length) <<= (x =  '' ), ( /* Comment */null)) = o1.a2[19]; } catch(e0) { } Array.prototype.unshift.apply(this.a1, [o1, t2, m1, s1, h2, g2]); }");
/*fuzzSeed-159544250*/count=601; tryItOut("v0 = Object.prototype.isPrototypeOf.call(s2, i2);");
/*fuzzSeed-159544250*/count=602; tryItOut("\"use strict\"; i1.send(t1);");
/*fuzzSeed-159544250*/count=603; tryItOut("function f0(g2)  { \"use strict\"; return null } ");
/*fuzzSeed-159544250*/count=604; tryItOut("mathy5 = (function(x, y) { return Math.fround(( ~ Math.cbrt(( + (( + x) > ( + -Number.MAX_SAFE_INTEGER)))))); }); testMathyFunction(mathy5, [-0x07fffffff, 0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53-2, -(2**53-2), -(2**53+2), 2**53, -0, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 0/0, -0x100000001, 0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, 1, 1.7976931348623157e308, -Number.MIN_VALUE, Math.PI, 0x100000001, -1/0, 0x07fffffff, 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 0x080000000, -(2**53), -0x080000000, -0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=605; tryItOut("mathy5 = (function(x, y) { return ( ! (mathy1((Math.asinh(Math.trunc(-(2**53+2))) >>> 0), (mathy0(((x >>> 0) << Math.fround(Math.max(Math.fround(y), Math.fround(y)))), ((x << (mathy4((-0x100000001 | 0), x) > (y | 0))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[2**53+2, x, new Number(1), 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, x, 2**53+2, 2**53+2, x, 2**53+2, new Number(1), new Number(1), 2**53+2, new Number(1), x, 2**53+2, x, new Number(1), 2**53+2, new Number(1), new Number(1), 2**53+2, x, x, new Number(1), new Number(1), x, 2**53+2, x, 2**53+2, new Number(1)]); ");
/*fuzzSeed-159544250*/count=606; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-159544250*/count=607; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -0.25;\n    return (((/*FFI*/ff(((d0)))|0)*0x4eb7b))|0;\n  }\n  return f; })(this, {ff: function(y) { t0[[[]]] = new RegExp(\"\\\\3\\\\d{1,}\\\\1*+|^|((?!.|[\\\\u0035r-\\\\cR]{2})|\\\\+){0,1}\", \"gi\");throw new RegExp(\"\\\\d|((?:\\\\x06)*?|[^])\\\\2+\", \"gyim\"); }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x080000001, 0x0ffffffff, -0x07fffffff, 0, 2**53-2, 1.7976931348623157e308, -1/0, 42, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 0x080000000, 1, -0x100000001, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -0x080000001, Math.PI, Number.MIN_VALUE, 1/0, 0x100000001, -Number.MAX_VALUE, -(2**53-2), 2**53, -(2**53), 0x100000000, -(2**53+2), 0.000000000000001, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=608; tryItOut("testMathyFunction(mathy2, [0x080000001, -0x0ffffffff, 2**53+2, 2**53-2, -1/0, Number.MAX_VALUE, -(2**53), 0x080000000, 0.000000000000001, -0x080000001, 0, 42, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MAX_VALUE, -0x100000001, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 2**53, 1, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, -(2**53-2), -Number.MIN_VALUE, 0x0ffffffff, 1/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), 0x100000000, 0/0]); ");
/*fuzzSeed-159544250*/count=609; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-159544250*/count=610; tryItOut("\"use strict\"; t1 + '';function eval(y)x/*infloop*/ for  each(let x in new Proxy(\n \"\" )) /*UUV2*/(c.getUTCMilliseconds = c.toDateString)\u000d;");
/*fuzzSeed-159544250*/count=611; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(( - Math.fround(Math.round(Math.abs(x))))); }); testMathyFunction(mathy4, /*MARR*/[false, (-1/0), (-1/0), (-1/0), (-1/0), false, false, (-1/0), false, (-1/0), (-1/0), false, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), false, false, (-1/0), false, (-1/0), x, x, (-1/0), x, x, (-1/0), x, false, (-1/0), false, (-1/0), x, false, (-1/0), x, x, false, x, x, false, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, false, x, x, false, false, (-1/0), x, false, (-1/0), (-1/0), (-1/0), x, x, false, x, x, false, x, false, x, x, (-1/0), false, false, (-1/0), x, false, x, false, (-1/0), false, (-1/0), false, (-1/0), false, false, (-1/0), false, (-1/0), x, false, false, (-1/0), (-1/0), (-1/0), x, false, false, false, (-1/0), false, (-1/0), (-1/0), false, x, false, false, (-1/0), false, false, x, x, (-1/0), false, (-1/0), x, x, false, false, x, x, (-1/0)]); ");
/*fuzzSeed-159544250*/count=612; tryItOut("\"use strict\"; a0.pop(v2, h0);");
/*fuzzSeed-159544250*/count=613; tryItOut("x.message;");
/*fuzzSeed-159544250*/count=614; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2(( ~ mathy2(Math.imul(mathy2(x, y), Math.fround((Math.fround(Math.fround(((y | 0) ** (-1/0 | 0)))) , y))), (Math.trunc(Math.round(Math.fround(x))) | 0))), (Math.min(( + ( + Math.abs(( + x)))), Math.tanh(x)) >>> 0)); }); ");
/*fuzzSeed-159544250*/count=615; tryItOut("\"use strict\"; let (c) { Array.prototype.push.call(a1, o2.a2, new Map(new RegExp(\"\\\\1\", \"gym\").__defineGetter__(\"eval\", ({/*TOODEEP*/}))), yield 15); }");
/*fuzzSeed-159544250*/count=616; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.max(((((Math.atan2(Math.sign(Math.min((Math.cosh((x >>> 0)) >>> 0), ((( + Number.MAX_SAFE_INTEGER) * ( + (x < x))) >>> 0))), Math.fround((Math.imul(-0x100000001, ( + Math.asinh(1.7976931348623157e308))) ? Math.fround(((((-0x0ffffffff | 0) >>> ( + Number.MAX_VALUE)) | 0) ? (y | 0) : (y | 0))) : (Math.fround((( + ( - y)) >>> 0)) >>> 0)))) >>> 0) >>> ((Math.atan2(Math.fround((mathy0((y === y), (y >>> 0)) >>> 0)), (Math.asinh(x) >>> 0)) + ( + mathy1(x, (( - (Math.fround((((y | 0) , y) - Math.fround(y))) | 0)) | 0)))) >>> 0)) >>> 0) | 0), (Math.log1p((((Math.imul(Math.fround(y), Math.fround(( + Math.pow(Math.fround(x), Math.fround(y))))) >>> 0) ? Math.pow((x >>> 0), (( ! (y >>> 0)) >>> 0)) : ((Math.cosh(( + (Math.hypot(x, (( + ( + ( + -0x100000001))) | 0)) | 0))) <= (Math.fround(Math.pow(y, ( + 1.7976931348623157e308))) != Math.fround(-0x100000000))) >>> 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[-Infinity, null, {x:3}, -Infinity, {x:3}, {x:3}, -Infinity, {x:3}, null, null, {x:3}, null, -Infinity, {x:3}, -Infinity, null, {x:3}, {x:3}, -Infinity, -Infinity, {x:3}, null, null, -Infinity, -Infinity, {x:3}, -Infinity, null, -Infinity, -Infinity, -Infinity, -Infinity, {x:3}, {x:3}, -Infinity, {x:3}, -Infinity, null, null, null, {x:3}, {x:3}, {x:3}, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, {x:3}, null, {x:3}, -Infinity, {x:3}, {x:3}, null, null, null, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, null, -Infinity, null, null, null, null, -Infinity, -Infinity, {x:3}, null, -Infinity, -Infinity, null, -Infinity, -Infinity, -Infinity]); ");
/*fuzzSeed-159544250*/count=617; tryItOut("L:with({c: this.__defineSetter__(\"\\u3056\", function(y) { ; }).eval(\"(intern([[1]]))\")}){m1.get(o1.s2); }");
/*fuzzSeed-159544250*/count=618; tryItOut("v2 = a0.length;");
/*fuzzSeed-159544250*/count=619; tryItOut("v1 = t2.length;");
/*fuzzSeed-159544250*/count=620; tryItOut("/*RXUB*/var r = r0; var s = s1; print(s.match(r)); ");
/*fuzzSeed-159544250*/count=621; tryItOut("/*MXX1*/o0 = g2.Error.name;");
/*fuzzSeed-159544250*/count=622; tryItOut("e1 = new Set;");
/*fuzzSeed-159544250*/count=623; tryItOut("t1[this.v2] = g1;");
/*fuzzSeed-159544250*/count=624; tryItOut("{/* no regression tests found */ }");
/*fuzzSeed-159544250*/count=625; tryItOut("testMathyFunction(mathy0, /*MARR*/[function(){}, \ntimeout(1800), function(){}, \ntimeout(1800), function(){}, function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, \ntimeout(1800), \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, function(){}, function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, \ntimeout(1800), function(){}, \ntimeout(1800), function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, \ntimeout(1800), \ntimeout(1800), function(){}, function(){}, function(){}, function(){}, \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), \ntimeout(1800), function(){}, \ntimeout(1800), function(){}, \ntimeout(1800), function(){}]); ");
/*fuzzSeed-159544250*/count=626; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (NaN);\n    /*FFI*/ff(((d1)), ((d1)), ((d1)), ((+(((0x75164dc1)-(0xf8d23f21)-(-0x436bfa9))>>>((0x96fe64da)+(0xbd00331a))))), ((imul((0xfbb3a0f2), ((/*FFI*/ff()|0)))|0)));\n    (Int32ArrayView[2]) = (((0x469d0204) ? ((0x2517db49) ? (/*FFI*/ff()|0) : ((4277))) : ((((0x278ac387)-(0x3695773b)) >> ((new ((4277))(let (z =  \"\" ) true))))))-(i0)+((((((0xdb4c575a)+(-0x21dcf82))>>>((0xffffffff)+(0xc158de4d))) % (((0x49bc6e9c)-(0x781a5306))>>>((0x2ee13b1e)+(0x26ecf207)))) << ((!((0xb22e6ffe) ? (0xff96e9c4) : (0xfbcfd765)))+(i0)))));\n    {\n      return +((((Float64ArrayView[((0xfce4b1db)) >> 3])) - ((d1))));\n    }\n    d1 = (274877906945.0);\n    d1 = (+(~~(+abs(((d1))))));\n    {\n      /*FFI*/ff(((4.722366482869645e+21)), ((NaN)), ((+abs(((Infinity))))), ((+(-1.0/0.0))), ((+atan2(((d1)), ((((-1.1805916207174113e+21)) / ((0.25))))))), ((-((+/*FFI*/ff())))), ((((0xfdc75926))|0)), ((1.2089258196146292e+24)), ((1125899906842625.0)), ((63.0)));\n    }\n    return +((Map(({-29: x }), )));\n    i0 = ((0x45ab3c28) ? (i0) : (/*FFI*/ff()|0));\n    (Int8ArrayView[0]) = (((0xffffffff))+((+abs(((+(1.0/0.0))))) != (arguments.callee.arguments--)));\n    {\n      (Float64ArrayView[2]) = (((+(1.0/0.0)) + (2049.0)));\n    }\n    (Int32ArrayView[4096]) = (((((i0)-(i0))|0)));\n    return +((d1));\n    return +((-36028797018963970.0));\n  }\n  return f; })(this, {ff: Set.prototype.delete}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x0ffffffff, 0.000000000000001, -0x100000000, -1/0, -Number.MIN_VALUE, 0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 1/0, 1.7976931348623157e308, 2**53-2, Math.PI, -0x080000001, -(2**53+2), 0x080000001, -(2**53), 0x07fffffff, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, 0, -0x100000001, 2**53+2, -(2**53-2), 42]); ");
/*fuzzSeed-159544250*/count=627; tryItOut("v2 = Object.prototype.isPrototypeOf.call(o2, f1);");
/*fuzzSeed-159544250*/count=628; tryItOut("mathy5 = (function(x, y) { return (((Math.exp(Math.fround((Math.clz32((x | 0)) , ( + (( ! Math.fround(Math.fround(Math.acosh(( + (Math.atan2((x | 0), x) | 0)))))) | 0))))) >>> 0) >= (( + Math.fround(((Math.fround((Math.hypot(((Math.max(y, ( + ((y | 0) * ( + 42)))) | 0) | 0), (Math.acos((x | 0)) | 0)) | 0)) !== Math.fround((mathy1(((y !== 0x080000000) | 0), (0x0ffffffff | 0)) | 0))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000000, 0, -0, 0x100000001, 2**53-2, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, 0x07fffffff, -0x100000001, -(2**53+2), -0x080000001, -0x080000000, -Number.MAX_VALUE, -(2**53-2), 42, -Number.MIN_VALUE, 2**53+2, 2**53, 0.000000000000001, -1/0, 1, 0x0ffffffff, Math.PI, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=629; tryItOut("\"use strict\"; v1 = new Number(-Infinity);");
/*fuzzSeed-159544250*/count=630; tryItOut("\"use strict\"; for (var v of a0) { o1 + ''; }");
/*fuzzSeed-159544250*/count=631; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(o1.a0, 14, { configurable: false, enumerable: (function(y) { return 0x100000001 })(URIError+=Math.hypot((function ([y]) { })(), -26)), writable: true, value: g0 });w = e = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function (eval, x)this, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: neuter, iterate: function() { throw 3; }, enumerate: function() { throw 3; }, keys: function() { throw 3; }, }; })( '' ), (4277));");
/*fuzzSeed-159544250*/count=632; tryItOut("\"use strict\"; t1 = new Uint16Array(b1);");
/*fuzzSeed-159544250*/count=633; tryItOut("for (var v of h0) { try { v0 = undefined; } catch(e0) { } try { e2 = new Set; } catch(e1) { } h0.valueOf = (function() { for (var j=0;j<30;++j) { f1(j%4==0); } }); }");
/*fuzzSeed-159544250*/count=634; tryItOut("print(--window);");
/*fuzzSeed-159544250*/count=635; tryItOut("\"use strict\"; s0 = '';");
/*fuzzSeed-159544250*/count=636; tryItOut("s2 += s2;");
/*fuzzSeed-159544250*/count=637; tryItOut("\"use strict\"; ;");
/*fuzzSeed-159544250*/count=638; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.abs(( + mathy1((( ~ Math.fround(Math.fround(Math.pow(mathy0(Math.PI, x), x)))) >>> 0), ( + mathy1(x, Math.pow(( + 0x080000000), Math.acosh(Math.fround(x)))))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -Number.MIN_VALUE, -0, 1/0, 0x0ffffffff, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, -Number.MAX_VALUE, -0x0ffffffff, -0x080000001, 0x080000001, 0x080000000, 0/0, Number.MIN_VALUE, 2**53+2, -(2**53-2), 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000000, -0x07fffffff, 0x07fffffff, -1/0, 0, 1, -0x100000000, 1.7976931348623157e308, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=639; tryItOut("\"use strict\"; a1 = Array.prototype.filter.call(a2);");
/*fuzzSeed-159544250*/count=640; tryItOut("{print((Math.log2([,,].throw( /x/ ))));(b = -3); }");
/*fuzzSeed-159544250*/count=641; tryItOut("\"use strict\"; /*oLoop*/for (tqwqxe = 0; tqwqxe < 60; ++tqwqxe) { EvalError.prototype.toString } ");
/*fuzzSeed-159544250*/count=642; tryItOut("m0 = new Map;");
/*fuzzSeed-159544250*/count=643; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var wrctum = this; var tlpwes = Function; return tlpwes;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, 0/0, 2**53, Number.MIN_VALUE, 0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, 1, Number.MAX_VALUE, 0, 0x0ffffffff, -(2**53-2), -Number.MIN_VALUE, 42, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 0.000000000000001, 1/0, Math.PI, 0x100000001, 0x07fffffff, -0, -0x080000000, -(2**53+2), 0x080000000]); ");
/*fuzzSeed-159544250*/count=644; tryItOut("\"use strict\"; e2.has(m2);function x(NaN = (timeout(1800))) { \"use strict\"; yield [,] } window;");
/*fuzzSeed-159544250*/count=645; tryItOut("\"use strict\"; i2.send(f1);");
/*fuzzSeed-159544250*/count=646; tryItOut("\"use strict\"; s0 = s0.charAt(19);");
/*fuzzSeed-159544250*/count=647; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.max(mathy1(Math.atan2((0 == Math.log2(y)), (( ~ ( + (( + y) ? ( + y) : ( + 42)))) | 0)), (Math.pow(Math.fround((Math.fround(y) === ( + Math.fround(2**53+2)))), Math.trunc(Math.sqrt(y))) > y)), (((( + ( + (((y ** (( + (-Number.MIN_SAFE_INTEGER >= 1.7976931348623157e308)) >>> 0)) >>> 0) + ( + x)))) <= Math.tanh((Math.imul((y >>> 0), (x >>> 0)) | 0))) == Math.fround(Math.imul(Math.fround((( + (( ! (y >>> 0)) >>> 0)) ? (Math.log10((x >>> 0)) >>> 0) : ( - y))), Math.sign(Math.log1p(-0x100000001))))) | 0)); }); testMathyFunction(mathy2, [0x0ffffffff, -(2**53-2), -Number.MIN_VALUE, 0x100000001, 0, -0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 2**53, 0x080000001, 1, Number.MAX_VALUE, 0.000000000000001, -1/0, Math.PI, 0x100000000, 0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, -0, -(2**53), -0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, 2**53+2, 0x080000000, -(2**53+2), -0x080000001]); ");
/*fuzzSeed-159544250*/count=648; tryItOut("a2.shift(p2);");
/*fuzzSeed-159544250*/count=649; tryItOut("\"use strict\"; print(x);\nthis.v2 = evalcx(\"function o2.f0(a2)  { return  /x/  } \", g2);\n");
/*fuzzSeed-159544250*/count=650; tryItOut("\"use strict\"; b2.__proto__ = m1;");
/*fuzzSeed-159544250*/count=651; tryItOut("\"use strict\"; a2 = /*FARR*/[.../*MARR*/[new String(''), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('')], (/*FARR*/[timeout(1800), (Math.sin( /x/ )), x, , eval(\"true\"), .../*MARR*/[new String(''), objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined()], , delete x.NaN].sort((void options('strict'))))];");
/*fuzzSeed-159544250*/count=652; tryItOut("\"use strict\"; o0.v1 = r2.unicode;");
/*fuzzSeed-159544250*/count=653; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(b0, v1);function x(x = (4277).eval(\"/* no regression tests found */\"), window) { v1 = Object.prototype.isPrototypeOf.call(this.t0, b2); } t0.set(t2, v2);");
/*fuzzSeed-159544250*/count=654; tryItOut("/*infloop*/do break ;\n while( \"\" );");
/*fuzzSeed-159544250*/count=655; tryItOut("mathy5 = (function(x, y) { return ( ! Math.atan2(Math.hypot(Math.pow((((x | 0) ? (-0x080000001 >>> 0) : (y >>> 0)) | 0), Math.ceil(Math.fround(Math.abs(Math.fround(x))))), x), (Math.imul(((Math.imul(x, 2**53+2) >>> 0) & y), y) ? 42 : (( - (( + x) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-159544250*/count=656; tryItOut("\"use strict\"; this.o1 + this.b2;;");
/*fuzzSeed-159544250*/count=657; tryItOut("/*bLoop*/for (var cdccei = 0; cdccei < 11; ++cdccei) { if (cdccei % 7 == 3) { /*oLoop*/for (qznszb = 0; qznszb < 89; ++qznszb, /[^\\D](\\uEd20|[^]*)\\2(?!\\s{4,6})|[^\u0084-\\\u6c40\\D@\\v-\\cK]\\f|.{1,}/im) { f1.__proto__ = i2; }  } else { t1 = t2.subarray( '' , ({a: [], \u3056} = {d})); }  } ");
/*fuzzSeed-159544250*/count=658; tryItOut("g0.i2 + b1;");
/*fuzzSeed-159544250*/count=659; tryItOut("testMathyFunction(mathy1, /*MARR*/[-Infinity, -0, -Infinity, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, -0, -0, x, -0, arguments.caller, arguments.caller, -0, x, arguments.caller, -Infinity, x, arguments.caller, arguments.caller, arguments.caller, -Infinity, x, x, -0, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, x, -0, x, x, arguments.caller, arguments.caller, x, -Infinity, -Infinity, -0, -0, -0, -Infinity, arguments.caller, x, -Infinity, arguments.caller, x, -0, arguments.caller, x, arguments.caller, -0, -0, x, x, arguments.caller, -0, -0, -0, x, x, -0, x, -0, -Infinity, x, arguments.caller, x, arguments.caller, -0, x, -Infinity, -Infinity, x, x, x, -0, x, x, arguments.caller, arguments.caller, -Infinity, -Infinity, -0, -0, arguments.caller, arguments.caller, arguments.caller, arguments.caller, -Infinity, -Infinity, arguments.caller, x, -Infinity, x, -0, -0, x, -Infinity, x, x, -Infinity, -Infinity, -Infinity, x, arguments.caller, x, x, x, x]); ");
/*fuzzSeed-159544250*/count=660; tryItOut("/*infloop*/ for  each(let arguments in c) {return; }");
/*fuzzSeed-159544250*/count=661; tryItOut("\"use strict\"; (({} = new this()));");
/*fuzzSeed-159544250*/count=662; tryItOut("if(true) selectforgc(this.o2); else  if (new RegExp(\"[^]\", \"yim\")) {var ryahdw = new SharedArrayBuffer(4); var ryahdw_0 = new Uint16Array(ryahdw); selectforgc(o2);(void schedulegc(g2));o1.o2.toString = (function mcc_() { var axalkq = 0; return function() { ++axalkq; if (/*ICCD*/axalkq % 10 == 7) { dumpln('hit!'); o2.f1(h1); } else { dumpln('miss!'); try { v1 = (o0 instanceof g1); } catch(e0) { } try { i0 = new Iterator(m2, true); } catch(e1) { } o2.valueOf = (function() { for (var j=0;j<32;++j) { f1(j%3==1); } }); } };})(); } else {/* no regression tests found *//*RXUB*/var r = new RegExp(\"(\\\\2{1,1})\", \"im\"); var s = \"\"; print(r.exec(s));  }");
/*fuzzSeed-159544250*/count=663; tryItOut("\"use strict\"; var y = x = Proxy.create(({/*TOODEEP*/})(/^/gyim), 19);print(x);");
/*fuzzSeed-159544250*/count=664; tryItOut("g0.a1.push(p2, p2, o2.g0.p1);");
/*fuzzSeed-159544250*/count=665; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    return +((d1));\n    return +((+abs(((+floor(((1.9342813113834067e+25))))))));\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), new String('q'), (void 0), new String('q'), new Boolean(true), new String('q'), new Number(1), new String('q'), new Number(1), new String('q'), new Number(1), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1), new Number(1), new String('q'), new Boolean(true), new Number(1), new Boolean(true), new Number(1), new Number(1), new String('q'), new String('q'), new Boolean(true)]); ");
/*fuzzSeed-159544250*/count=666; tryItOut("testMathyFunction(mathy0, [-0, -0x100000000, Math.PI, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, -0x07fffffff, -(2**53), -0x0ffffffff, -0x080000000, 2**53-2, 0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -0x100000001, 0/0, 2**53, 2**53+2, 0x080000000, -(2**53+2), -0x080000001, 0x100000001, Number.MIN_VALUE, -(2**53-2), 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=667; tryItOut("\"use strict\"; /*infloop*/while(\"\\u674E\"){v0 = 4.2; }/*RXUB*/var r = /(?!\\S){2,6}/yim; var s = \"0000000\"; print(s.replace(r, x)); ");
/*fuzzSeed-159544250*/count=668; tryItOut("\"use strict\"; yield x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { throw 3; }, has: d, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(\"\\u74A8\"), Date.prototype.setUTCMinutes);");
/*fuzzSeed-159544250*/count=669; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.atan2(( + (( + Math.log2(x)) | Math.atanh(x))), ( + (( + mathy3(Math.sign(mathy0(x, -0x100000000)), Math.hypot(x, ((mathy1(Math.min(Math.fround(y), Math.fround(-Number.MIN_VALUE)), ((x % (y | 0)) | 0)) | 0) >>> 0)))) , ( + (( ! (Math.cosh(y) | 0)) / ((((y | 0) - (mathy2(Math.fround((( ! (x | 0)) | 0)), y) >>> 0)) >>> 0) & y)))))) >>> 0); }); testMathyFunction(mathy4, [-0, 0x07fffffff, -0x080000001, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53, -1/0, 0/0, 2**53-2, Math.PI, 1/0, -(2**53), -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 0, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 2**53+2, 0.000000000000001, Number.MIN_VALUE, 42, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 1, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=670; tryItOut("e2.add(p2);");
/*fuzzSeed-159544250*/count=671; tryItOut("\"use strict\"; o0.v1 = evalcx(\"/* no regression tests found */\", g0);");
/*fuzzSeed-159544250*/count=672; tryItOut("mathy1 = (function(x, y) { return ( + Math.fround(Math.max(Math.fround(Math.fround(((( - y) >>> 0) < Math.log1p((( - ((mathy0((2**53+2 >>> 0), (x >>> 0)) >>> 0) !== y)) >>> 0))))), Math.fround((Math.fround(mathy0(( ! Math.fround(0x080000001)), Math.fround(y))) != Math.fround(Math.exp(Math.fround(Math.cbrt(x))))))))); }); testMathyFunction(mathy1, [0x080000000, 1, Number.MAX_VALUE, 0, 1.7976931348623157e308, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, 42, -(2**53-2), Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, -0x100000000, 0x07fffffff, -0, 2**53+2, 2**53-2, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 0/0, -1/0, -Number.MIN_VALUE, 0x100000000, 0x080000001, -(2**53), 2**53]); ");
/*fuzzSeed-159544250*/count=673; tryItOut("mathy0 = (function(x, y) { return (((Math.min(((y >>> 0) + -1/0), ((Math.cbrt(y) | 0) | 0)) >> ( + ( - Math.fround(Math.cos(Math.fround(Math.fround(( ~ Math.fround(Math.cosh((( - (y >>> 0)) >>> 0))))))))))) | 0) || Math.exp(Math.hypot(((x || x) | 0), ( + Math.sign(( + (( + Math.asinh(y)) ? (x | 0) : (-0x100000001 >>> 0)))))))); }); testMathyFunction(mathy0, [(new Boolean(false)), 1, undefined, objectEmulatingUndefined(), false, -0, [0], true, (new String('')), 0.1, ({valueOf:function(){return '0';}}), '\\0', /0/, (new Number(-0)), '/0/', NaN, ({toString:function(){return '0';}}), (new Boolean(true)), '', null, [], (function(){return 0;}), ({valueOf:function(){return 0;}}), '0', (new Number(0)), 0]); ");
/*fuzzSeed-159544250*/count=674; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(i1, h0);");
/*fuzzSeed-159544250*/count=675; tryItOut("");
/*fuzzSeed-159544250*/count=676; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=677; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.pow(Math.atan2(Math.max(0x100000000, (Math.cbrt(x) ? ((y >= (-Number.MAX_VALUE < -(2**53+2))) >>> 0) : Math.imul(x, x))), mathy1(Math.fround(Math.imul(x, ( + x))), (1.7976931348623157e308 && x))), (Math.trunc(Math.atan2((Math.cosh((Math.imul(x, y) | 0)) >>> 0), ( ! ( + x)))) >>> 0))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, -0x0ffffffff, -(2**53-2), 0x100000000, 2**53+2, -1/0, Math.PI, Number.MAX_VALUE, 2**53-2, 1, 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, -0x100000001, 0x100000001, 0.000000000000001, -0x080000001, 0, 0x0ffffffff, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 0x080000000, -0x100000000, -0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=678; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.atan2(Math.fround((mathy4((Math.atanh(Math.atan2((( ~ (x >>> 0)) | 0), x)) | 0), (( + ( ! x)) >> Math.min(0.000000000000001, x))) ? ((((x | 0) ? ((( + (x & x)) >> Math.trunc((x | 0))) | 0) : (Math.pow(Math.imul(x, ( ! (Math.cbrt((x >>> 0)) >>> 0))), Math.trunc(Math.fround(mathy4(Math.clz32(0x07fffffff), x)))) | 0)) | 0) | 0) : Math.sin(Math.fround(Math.max(x, (Math.imul(2**53+2, Math.clz32((x >>> 0))) | 0)))))), Math.fround((((((Math.fround((x | ( ~ Number.MAX_VALUE))) - (Math.clz32(Math.fround(mathy2(Math.fround(x), Math.fround(mathy2(( + x), y))))) | 0)) | 0) >>> 0) <= ((x | 0) / (-1/0 - ( + ( + ( + ( ~ x))))))) >>> 0)))); }); testMathyFunction(mathy5, [-0x0ffffffff, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 0x100000000, 2**53+2, 1/0, 0x080000000, 42, -(2**53-2), -(2**53+2), -0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -(2**53), 0/0, 1, 0.000000000000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, 2**53, Number.MIN_SAFE_INTEGER, -0, -0x100000001, 0x100000001, 0x07fffffff, -0x080000001, -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=679; tryItOut("mathy5 = (function(x, y) { return (Math.imul((( + (( + (mathy4(Math.fround(mathy2(x, ( + Math.exp(y)))), (mathy4((y * -Number.MAX_SAFE_INTEGER), y) | 0)) | 0)) >= ( + ( + Math.min((Math.atanh(y) >>> 0), ((((mathy1((y | 0), -Number.MAX_VALUE) >>> 0) < ( ! ( + (Math.log(((x || Math.PI) | 0)) | 0)))) >>> 0) >>> 0)))))) >>> 0), (( + Math.round(( ~ (( - Math.fround(x)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0, 0.1, '0', undefined, [0], (new Number(-0)), true, objectEmulatingUndefined(), ({toString:function(){return '0';}}), (function(){return 0;}), NaN, '\\0', null, ({valueOf:function(){return 0;}}), /0/, 1, ({valueOf:function(){return '0';}}), (new Boolean(false)), false, '/0/', (new String('')), [], '', -0, (new Number(0)), (new Boolean(true))]); ");
/*fuzzSeed-159544250*/count=680; tryItOut("mathy3 = (function(x, y) { return Math.atan2((Math.hypot(( + ( + ( ~ ( + mathy2(( + 0x0ffffffff), ( + x)))))), Math.fround(( ~ Math.fround((((Math.min(y, x) | 0) == x) >>> 0))))) >>> 0), Math.imul(( - ( + ( + mathy2(Math.fround(y), Math.hypot((mathy2(Math.fround(x), (-(2**53+2) | 0)) | 0), ( + x)))))), (y ** 2**53))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, -0, Number.MIN_VALUE, -0x100000001, 0x080000001, -0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -(2**53), Number.MAX_VALUE, 0x07fffffff, 2**53-2, 0x080000000, 0/0, 2**53, Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), 1, 0.000000000000001, -0x07fffffff, Math.PI, 1/0, 2**53+2, -Number.MIN_VALUE, 0x100000000, -0x080000000, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=681; tryItOut("\"use strict\"; a0.sort((function() { try { o2 = Proxy.create(h1, h1); } catch(e0) { } try { t0[8] = g2; } catch(e1) { } try { g0.offThreadCompileScript(\"function f2(p0) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    d0 = (4611686018427388000.0);\\n;    i2 = (0x69a9d51c);\\n    d0 = (d0);\\n    (Float64ArrayView[((!(i1))+(x)) >> 3]) = ((1.9342813113834067e+25));\\n    i1 = (i2);\\n    (Float32ArrayView[0]) = ((!(i2)));\\n    i1 = ((i1) ? (-0x8000000) : (1));\\n    i2 = ((Float32ArrayView[((i1)+(i1)) >> 2]));\\n    i2 = (1);\\n    (Int16ArrayView[((((0x6a1ad6c3) != (0x273d72e4)) ? (0x490310af) : (i1))-(0xfbd0d303)-(0xffffffff)) >> 1]) = ((i1));\\n    switch ((((0x2d41d5ca)+((0x5cac3b31) > (0x7fffffff))) >> ((i1)-(i2)))) {\\n      case -2:\\n        i2 = (i2);\\n        break;\\n      case 0:\\n        {\\n          i1 = (0xf01144e6);\\n        }\\n        break;\\n      case -3:\\n        {\\n          {\\n            i2 = (i1);\\n          }\\n        }\\n        break;\\n      case -1:\\n        {\\n          i2 = ((0xfee17442) ? (i2) : (((i1) ? (0xfdb44c88) : (i2)) ? (i1) : (i1)));\\n        }\\n        break;\\n      case 0:\\n        i2 = (i1);\\n        break;\\n      case 1:\\n        d0 = (d0);\\n    }\\n    d0 = (+abs(((8191.0))));\\n    i2 = (i1);\\n    d0 = (d0);\\n    return +((-2.3611832414348226e+21));\\n  }\\n  return f;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce:  /x/g , noScriptRval: false, sourceIsLazy: false, catchTermination: false })); } catch(e2) { } g0.offThreadCompileScript(\"x\"); return t0; }));");
/*fuzzSeed-159544250*/count=682; tryItOut("m2.get(s1);a0.unshift(p0, h0, p2, f1, s2);");
/*fuzzSeed-159544250*/count=683; tryItOut("\ns1 += 'x';\n");
/*fuzzSeed-159544250*/count=684; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.sin(Math.cos(Math.fround((Math.acos((0x080000000 >>> 0)) | 0))))); }); ");
/*fuzzSeed-159544250*/count=685; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.log((( + Math.fround(Math.trunc(( + Math.imul(( + (Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround(0x080000001))) ? x : 1/0)), ( - Math.atan(y))))))) - ( + (( + ( ~ (y | 0))) >= ( + Math.max(mathy4(y, (-0 >>> 0)), ((mathy3(y, (x | 0)) | 0) && x))))))); }); testMathyFunction(mathy5, [(new Boolean(false)), '/0/', [0], undefined, (function(){return 0;}), (new Number(0)), '\\0', /0/, NaN, (new Boolean(true)), objectEmulatingUndefined(), (new Number(-0)), -0, 0.1, '', ({valueOf:function(){return 0;}}), 1, ({toString:function(){return '0';}}), (new String('')), true, 0, '0', false, [], null, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-159544250*/count=686; tryItOut("new String(null);");
/*fuzzSeed-159544250*/count=687; tryItOut("e2.valueOf = (function(j) { if (j) { for (var v of b2) { try { t1[(void shapeOf(\"\\u7EA2\"))] = g2; } catch(e0) { } Object.freeze(h0); } } else { try { m0.has(h2); } catch(e0) { } try { t0 = new Int16Array(this.t2); } catch(e1) { } try { g2.m2.get('fafafa'.replace(/a/g, /*wrap1*/(function(){ f0 + v0;return Array.prototype.indexOf})())); } catch(e2) { } Array.prototype.unshift.call(a0, v0); } });");
/*fuzzSeed-159544250*/count=688; tryItOut("this.g1.g2.f2 + t2;");
/*fuzzSeed-159544250*/count=689; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    {\n      i1 = (i2);\n    }\n    i1 = (i1);\n    i1 = (i0);\n    (Float32ArrayView[2]) = ((Float32ArrayView[((i3)-((0x62aeecd5))) >> 2]));\n    i3 = (0x80736afb);\n    return +(((+atan2(((Float32ArrayView[((i0)+(i1)) >> 2])), (((4277))))) + (+ceil(((+(1.0/0.0)))))));\n;    return +((295147905179352830000.0));\n  }\n  return f; })(this, {ff: DataView.prototype.setInt8}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 42, 2**53-2, 2**53+2, 0x100000001, Math.PI, 1.7976931348623157e308, 0x080000001, 0x100000000, 0/0, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, -(2**53+2), -Number.MAX_VALUE, -(2**53), 0x080000000, 1, 0, 1/0, Number.MAX_VALUE, 2**53, -0x100000000, -Number.MIN_VALUE, -0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-159544250*/count=690; tryItOut("\"use strict\"; /*bLoop*/for (eabkgi = 0, {eval: {x: [[], ], e, x}} = (window = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(-3 <= \"\\uC00F\"), Float32Array, (4277)\n)); eabkgi < 72; ++eabkgi) { if (eabkgi % 49 == 0) { this.m2.has(p0); } else { /*vLoop*/for (gtqlfn = 0; gtqlfn < 102; new RegExp(\"$\", \"gyi\"), ++gtqlfn) { var z = gtqlfn; s1.toSource = (function() { try { for (var v of s0) { m0.delete(this.m0); } } catch(e0) { } a2 = x; return e1; }); }  }  } ");
/*fuzzSeed-159544250*/count=691; tryItOut("m2.set((4277), h1);");
/*fuzzSeed-159544250*/count=692; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( ~ Math.pow(/(?:$\\S)/gm, -11) | x)) ^ Math.fround(( ! (Math.hypot(Math.fround(Math.cos(((Math.imul((x | 0), (mathy0(y, (y | 0)) | 0)) | 0) && ( ! 2**53+2)))), Math.atanh((y | (y ^ y)))) >>> 0))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 0x080000001, -0x080000001, 0x0ffffffff, 0x07fffffff, -0x080000000, 2**53+2, -0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 1/0, 0/0, -Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, 0x100000000, -(2**53), 0x100000001, -1/0, -Number.MAX_VALUE, -0, 0x080000000, 42, 0, -(2**53-2), -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-159544250*/count=693; tryItOut("\"use strict\"; for (var v of g0) { try { t1[8]; } catch(e0) { } Object.defineProperty(this, \"t0\", { configurable: /\\x36/gm, enumerable: false,  get: function() {  return t0.subarray(1); } }); }\n;\n");
/*fuzzSeed-159544250*/count=694; tryItOut("/*infloop*/for(let Object.prototype in ((Number.prototype.toExponential)(( /x/g  <  /x/ ))))print(x);");
/*fuzzSeed-159544250*/count=695; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2((Math.atan2(Math.hypot(x, (((((Math.sin((Number.MIN_VALUE | 0)) | 0) < (y >>> 0)) >>> 0) <= (2**53-2 >>> 0)) | 0)), ((Math.asin(( + ( ! y))) >>> 0) >>> 0)) | 0), ( + Math.acosh(Math.imul(Math.atan2(Math.fround(( ! x)), Math.fround(y)), mathy0(x, (Math.atan2((Math.max((y >>> 0), (2**53 >>> 0)) >>> 0), (x >>> 0)) | 0)))))); }); testMathyFunction(mathy3, [2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -(2**53), -0x080000001, 2**53, -0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0, 42, 0x100000000, 1/0, -0x0ffffffff, -0x100000000, Number.MAX_VALUE, -1/0, 0x07fffffff, -(2**53+2), 0x080000001, 0x080000000, 1, -Number.MIN_VALUE, -(2**53-2), 0/0, -0x080000000, -0, 2**53-2]); ");
/*fuzzSeed-159544250*/count=696; tryItOut("t0 = t1.subarray(v2);");
/*fuzzSeed-159544250*/count=697; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\b?.)\", \"gym\"); var s = \"\\u64cd1\\n  \\u64cd1\\n  \"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=698; tryItOut("mathy4 = (function(x, y) { return Math.imul(Math.fround(Math.cbrt((( - (Math.fround(Math.cos(-0)) >>> 0)) ? ( + ( + (Math.max((Math.max(x, Math.fround(x)) >>> 0), (Math.min(y, Math.cbrt(y)) | 0)) | 0))) : Math.fround(( - (y <= x)))))), ( + Math.cos(Math.fround(Math.max(( + y), ( + ( + ( ! Math.max((Math.min((y | 0), y) >>> 0), (y | 0)))))))))); }); ");
/*fuzzSeed-159544250*/count=699; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(mathy3(Math.fround(Math.log10((Math.fround((Math.fround((Math.fround(( + Math.max(( + y), ( + x)))) && Math.fround(( + ( + Math.hypot(( + y), -Number.MIN_SAFE_INTEGER)))))) * Math.fround((((x | 0) ? ((Math.cbrt(( + y)) >>> 0) | 0) : (-Number.MIN_SAFE_INTEGER | 0)) ? Math.atan2(Math.fround(Math.pow(Math.fround(x), Math.fround(y))), Math.fround(( ! -0x100000001))) : Math.fround(Math.tan(Math.fround(x))))))) >>> 0))), Math.fround((mathy1((Math.cosh(( + ( ~ (y ? 1/0 : Math.ceil(Math.fround(Math.fround(y))))))) >>> 0), (( + Math.hypot(( + (0x07fffffff > x)), ( + mathy1(( + mathy3(Number.MAX_VALUE, Math.fround(Math.ceil(x)))), ( + y))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [-0, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x100000001, -0x080000001, 0, -0x080000000, 0x07fffffff, Math.PI, 1, 0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53), -Number.MIN_VALUE, 2**53, 0x100000000, 1/0, 42, 2**53-2, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, -1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53-2), 0x100000001, 0x0ffffffff, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=700; tryItOut("/*tLoop*/for (let x of /*MARR*/[[undefined], (1/0), new Number(1.5), (1/0), new Number(1.5), [undefined], objectEmulatingUndefined(), new Number(1.5), [undefined], objectEmulatingUndefined(), objectEmulatingUndefined()]) { /(?:(?=\\u1dd9(?:\\W){3}))/g; }");
/*fuzzSeed-159544250*/count=701; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atan((( ~ (( - (( ! ( + (1.7976931348623157e308 ? x : -0x100000000))) | 0)) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-159544250*/count=702; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=703; tryItOut("g2 = a2[15];");
/*fuzzSeed-159544250*/count=704; tryItOut("/*bLoop*/for (let zoghni = 0; zoghni < 123; ++zoghni) { if (zoghni % 5 == 3) { s2 += s0; } else { h1.fix = f1;; }  } ");
/*fuzzSeed-159544250*/count=705; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (((( + ( + Math.max(( + (Math.atan2(Math.fround(Math.pow((Math.atan(x) | 0), (( ! 0x080000000) >>> 0))), x) === y)), Math.fround(x)))) >>> 0) % ((Math.pow(((( - (( ! ((Math.round(y) | 0) ** y)) | 0)) | 0) | 0), (( + ((( + (Math.min((y !== ( + ( ! ( + x)))), (( + x) >= (Math.atan2(Number.MIN_VALUE, (y | 0)) | 0))) >>> 0)) >>> 0) | 0)) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x0ffffffff, 0/0, 1, -(2**53), -Number.MIN_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, Number.MIN_VALUE, -0x100000000, 0x07fffffff, Math.PI, 1.7976931348623157e308, -0x080000000, -Number.MAX_VALUE, -(2**53+2), -0x080000001, 2**53, 0x100000001, -(2**53-2), Number.MAX_VALUE, -1/0, 0.000000000000001, -0x100000001, 0x0ffffffff, 0x100000000, -0x07fffffff, 0x080000001, -0, 1/0, 0, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=706; tryItOut("/*oLoop*/for (muslwy = 0; muslwy < 34; ++muslwy) { /*RXUB*/var r = \"\\uA2A0\"; var s = \"\"; print(s.split(r)); print(r.lastIndex);  } ");
/*fuzzSeed-159544250*/count=707; tryItOut("mathy0 = (function(x, y) { return Math.atanh((((((Math.pow((x >>> 0), ( + ((Math.fround(x) ? Math.fround(y) : (Math.tan(y) >>> 0)) | 0))) / (Math.min(y, ( ~ 0x080000001)) >>> 0)) >>> 0) <= (Math.log10(( + Math.log2(( + ((((-0x100000000 ? Math.atan(y) : x) >>> 0) + (x >>> 0)) >>> 0))))) >>> 0)) | 0) >>> 0)); }); testMathyFunction(mathy0, [0x080000001, -1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 42, 2**53-2, -0x100000001, -(2**53-2), 0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, 0/0, -(2**53+2), -0, 0x080000000, 2**53, Number.MAX_VALUE, -0x07fffffff, 1, -0x080000001, 2**53+2, -0x0ffffffff, Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1/0, 0, -Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=708; tryItOut("e1.has(b2);");
/*fuzzSeed-159544250*/count=709; tryItOut("Array.prototype.push.call(a1, h0, e0);");
/*fuzzSeed-159544250*/count=710; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.exp(((((Math.fround((-(2**53) && Math.pow(x, Math.acos((x | 0))))) ? 2**53+2 : ( + (( + x) >>> Math.fround(Math.fround((Math.fround(Math.min(y, y)) == Math.fround(42))))))) !== ( + Math.imul(2**53-2, x))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 2**53+2, 0.000000000000001, 0x07fffffff, -0, 42, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 0/0, -Number.MAX_VALUE, -0x07fffffff, 2**53, -0x0ffffffff, 2**53-2, -0x100000001, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 0x100000001, -0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 0, 1, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=711; tryItOut("print(b2);\nf2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((Float32ArrayView[0]));\n  }\n  return f; });\n");
/*fuzzSeed-159544250*/count=712; tryItOut("a2 = Array.prototype.concat.apply(a2, [t0, a1, a0]);");
/*fuzzSeed-159544250*/count=713; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=714; tryItOut("var sqzwxe = new ArrayBuffer(8); var sqzwxe_0 = new Float64Array(sqzwxe); sqzwxe_0[0] = -1653588649.5; NaN;");
/*fuzzSeed-159544250*/count=715; tryItOut("a2.forEach((function(j) { if (j) { try { v2 = 4; } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\\n\\u001a\\n\\u001a_\"; print(s.search(r));  } catch(e1) { } Array.prototype.sort.call(a2, Boolean.prototype.valueOf); } else { a1.sort((function() { try { v0 = (t2 instanceof this.v0); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(a1, v1); } catch(e1) { } Object.prototype.watch.call(a1, \"atan\", (function(j) { if (j) { try { v0 = r2.sticky; } catch(e0) { } v2 = -Infinity; } else { /*MXX1*/this.o0 = g1.Array.prototype; } })); throw s0; }), g0.p2, e0, t2); } }));");
/*fuzzSeed-159544250*/count=716; tryItOut("testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, -0x07fffffff, 2**53, 0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000001, -0, 1, 2**53+2, 42, -Number.MAX_VALUE, 2**53-2, -1/0, 0x080000001, 0/0, Number.MIN_VALUE, -0x080000001, -0x080000000, 0x0ffffffff, 0x080000000, -(2**53-2), -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=717; tryItOut("L: {/*RXUB*/var r = new RegExp(\"(?:\\\\b)\", \"gyim\"); var s = (makeFinalizeObserver('tenured')); print(uneval(r.exec(s))); v1 = Object.prototype.isPrototypeOf.call(m0, f1); }");
/*fuzzSeed-159544250*/count=718; tryItOut("/*hhh*/function cmnwfo(){b0 + f2;}cmnwfo(Math.imul(-23, -10), RegExp());");
/*fuzzSeed-159544250*/count=719; tryItOut("\"use strict\"; a2.pop(i0, h2);");
/*fuzzSeed-159544250*/count=720; tryItOut("NaN;while((eval(\"( '' );\")) && 0){print(x); }");
/*fuzzSeed-159544250*/count=721; tryItOut("\"use strict\"; e1.delete(x);");
/*fuzzSeed-159544250*/count=722; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! (Math.sin(( + (( + ( + (Math.fround(((( ~ (Math.imul(y, y) >>> 0)) | 0) >>> 0)) >>> 0))) << Math.log2((mathy0((y >>> 0), (y >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy3, [-0x080000000, -0x100000000, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, Math.PI, 2**53+2, -0x07fffffff, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 0x07fffffff, 42, 0x0ffffffff, 0x080000001, 1, 0x100000000, -0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), -0x0ffffffff, -0x100000001, -0, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 0]); ");
/*fuzzSeed-159544250*/count=723; tryItOut("testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), x,  /x/g , Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16),  /x/g , x, x, x, Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), x, Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/g ,  /x/g , x, Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), x, x, x, x, x, x, Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), x, x, x, x, x, x, x, x, x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16),  /x/g , x, Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16),  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g , objectEmulatingUndefined(), x, Math.atan2( ''  ? (4277) : ( ''  -=  /x/ ), -16), x]); ");
/*fuzzSeed-159544250*/count=724; tryItOut("Array.prototype.sort.apply(a2, [(function() { v1 = Array.prototype.some.apply(a0, [(function() { try { h0 = {}; } catch(e0) { } f1 = Proxy.createFunction(h2, f0, f1); return b0; }), i0, g0.h0, e1]); return s1; }), f1]);");
/*fuzzSeed-159544250*/count=725; tryItOut("Array.prototype.unshift.call(o1.a2, g0.h1, h0, b1, e0, p1);");
/*fuzzSeed-159544250*/count=726; tryItOut("v0 = o2.g2.runOffThreadScript();");
/*fuzzSeed-159544250*/count=727; tryItOut("\"use strict\"; d;let c = new RegExp(\"(?=(?:[^\\\\cM\\\\xb3\\\\-\\\\s]))?\", \"yim\");");
/*fuzzSeed-159544250*/count=728; tryItOut("/*oLoop*/for (var ltlxzo = 0; ( \"\" ) && ltlxzo < 6; \"\\u4B34\", ++ltlxzo) { e1.has(i1); } ");
/*fuzzSeed-159544250*/count=729; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-159544250*/count=730; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! Math.atan2((( + mathy1(( + ( - y)), ( + ( + ( ~ ( + ( ! -Number.MIN_VALUE))))))) >>> 0), ((Math.fround((((mathy0(2**53, Math.fround((x % ( + x)))) >>> 0) ? (0/0 >>> 0) : ((y ** ( ! y)) >>> 0)) >>> 0)) || y) >>> 0))); }); testMathyFunction(mathy3, [0x07fffffff, -0x100000001, 42, 0x080000001, -0x0ffffffff, -1/0, -0x100000000, -Number.MAX_VALUE, 0x080000000, Math.PI, -0, 1.7976931348623157e308, 0x100000000, 2**53, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -(2**53+2), -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 1/0, 0x100000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 2**53-2, 0, -(2**53), 0/0]); ");
/*fuzzSeed-159544250*/count=731; tryItOut("");
/*fuzzSeed-159544250*/count=732; tryItOut("mathy2 = (function(x, y) { return ( + Math.clz32(( + ( ~ ( ~ Math.cos((y >>> 0))))))); }); testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), 1, true, -0, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Number(0)), (new Boolean(false)), '\\0', null, ({toString:function(){return '0';}}), [0], false, (new Number(-0)), NaN, '0', (function(){return 0;}), (new Boolean(true)), /0/, '', [], undefined, 0, (new String('')), '/0/', 0.1]); ");
/*fuzzSeed-159544250*/count=733; tryItOut("a0[({valueOf: function() { /* no regression tests found */return 9; }})];");
/*fuzzSeed-159544250*/count=734; tryItOut("\"use strict\"; with({c: new RegExp(\"(\\\\s{32}|\\\\Bh+?)*?\", \"im\")}){Object.seal(a1);h2.delete = (function() { try { s0 += s1; } catch(e0) { } try { Array.prototype.push.apply(a2, [o2, f1, p2, o2, i0, g0.o2]); } catch(e1) { } m2.delete(g2.a2); return o0.p0; }); }");
/*fuzzSeed-159544250*/count=735; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -1/0, -Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -0, -0x080000000, 42, -(2**53), Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -0x07fffffff, 0x100000000, 0x080000001, 0.000000000000001, 0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -Number.MAX_VALUE, 1, 2**53+2, 1/0, Number.MIN_SAFE_INTEGER, 0/0, -(2**53+2), Math.PI, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=736; tryItOut("var kryhdn = new ArrayBuffer(0); var kryhdn_0 = new Uint8Array(kryhdn); kryhdn_0[0] = -6; var kryhdn_1 = new Float64Array(kryhdn); kryhdn_1[0] = 5; var kryhdn_2 = new Uint8ClampedArray(kryhdn); print(kryhdn_2[0]); kryhdn_2[0] = -13; var kryhdn_3 = new Uint32Array(kryhdn); print(kryhdn_3[0]); var kryhdn_4 = new Uint8Array(kryhdn); print(kryhdn_4[0]); kryhdn_4[0] = 12; var kryhdn_5 = new Uint32Array(kryhdn); kryhdn_5[0] = 13; var kryhdn_6 = new Uint16Array(kryhdn); var kryhdn_7 = new Float32Array(kryhdn); print(kryhdn_7[0]); kryhdn_7[0] = 4; \"\\uE978\";print(uneval(e0));");
/*fuzzSeed-159544250*/count=737; tryItOut("Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-159544250*/count=738; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround((Math.pow(( + ( ~ (Number.MAX_VALUE % (0x080000001 && y)))), ( + (Math.hypot((Math.imul(y, Math.fround((Number.MAX_VALUE == Math.fround(x)))) | 0), x) ? ((Math.cos(x) >>> 0) >>> 0) : Math.tanh(0x080000001)))) === Math.fround(( - (( - ((( - ( - x)) + y) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [-0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 42, 0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, 1, -(2**53), 2**53, -0, -1/0, -0x080000001, -0x0ffffffff, -0x100000000, -(2**53+2), 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, 0.000000000000001, -0x07fffffff, Math.PI, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 1/0, 0x0ffffffff, 0x080000001, Number.MAX_VALUE, 0]); ");
/*fuzzSeed-159544250*/count=739; tryItOut("\"use strict\"; m2.set(v0, e2);");
/*fuzzSeed-159544250*/count=740; tryItOut("mathy2 = (function(x, y) { return (Math.ceil((Math.imul((( + Math.hypot(( + (Math.acosh((y | 0)) | 0)), y)) >>> 0), ( + ( - ( + y)))) | 0)) / (Math.imul(Math.fround(Math.fround(( ! (((x ? Math.fround((y - 1/0)) : y) ^ Math.fround((((Math.fround((((x >>> 0) || ( + x)) >>> 0)) !== x) | 0) < ( ! x)))) | 0)))), (mathy1((Math.fround(( - x)) >>> 0), Math.pow(Math.tan(x), y)) !== x)) >>> 0)); }); testMathyFunction(mathy2, [-0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -1/0, -0x100000000, -Number.MAX_VALUE, 2**53, -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, -0x100000001, -0, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0x0ffffffff, 2**53-2, 0x07fffffff, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff, Number.MIN_VALUE, 0x080000001, 42, 0/0, 1, -(2**53-2), 0x100000001, -(2**53+2), 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=741; tryItOut("i2.toString = (function(j) { f2(j); });");
/*fuzzSeed-159544250*/count=742; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=743; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.acosh((( + (mathy2((( ~ Math.fround(( + x))) | 0), (((((Math.max((-0x0ffffffff >>> 0), (x >>> 0)) >>> 0) >>> 0) >>> (y >>> 0)) >>> 0) < Math.round(Math.exp(Math.fround(y))))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-159544250*/count=744; tryItOut("\"use strict\"; m0.set(e2, o2);");
/*fuzzSeed-159544250*/count=745; tryItOut("\"use strict\"; var r0 = x / x; var r1 = r0 + r0; var r2 = x % 9; var r3 = 3 - r0; var r4 = r3 & 4; var r5 = r1 / r1; var r6 = r1 * 5; var r7 = x ^ r6; var r8 = 6 + r4; var r9 = r6 ^ 2; var r10 = r6 & r9; var r11 = 3 | r7; r11 = r7 & 7; var r12 = r2 - r0; var r13 = r6 & r9; var r14 = r1 & r4; var r15 = 9 & r3; var r16 = 0 - 3; var r17 = r15 | r3; var r18 = 7 & r7; var r19 = x ^ r7; var r20 = r18 - r6; var r21 = r16 | 2; var r22 = 3 / r4; var r23 = 7 | 0; var r24 = x | 8; r14 = 8 ^ r19; var r25 = r15 ^ r10; var r26 = r8 % r9; var r27 = 0 % r17; var r28 = r3 - r2; var r29 = r3 * r17; var r30 = r22 * r16; var r31 = 1 * 8; r18 = r1 & r27; r29 = r30 * r7; var r32 = r21 + r10; var r33 = 2 * r4; var r34 = r12 * 1; var r35 = r11 % r1; var r36 = r1 % 7; var r37 = 4 + x; var r38 = 6 % r34; var r39 = r12 / r37; print(r9); var r40 = 6 ^ 1; var r41 = 7 - r15; var r42 = r36 ^ r4; r28 = 3 + r34; var r43 = 8 / 3; var r44 = r7 + r0; var r45 = r36 ^ r9; var r46 = r17 * r3; var r47 = r9 * r19; var r48 = r11 ^ 7; var r49 = r41 ^ r18; var r50 = r2 + r9; var r51 = 4 ^ r1; var r52 = r19 + r45; r47 = r17 / 5; var r53 = r48 / r9; var r54 = r4 | r2; var r55 = r16 / r47; print(r40); var r56 = r7 | r34; var r57 = r9 / 3; var r58 = r42 | r21; print(r29); r52 = r20 + r19; var r59 = r58 & 6; r13 = 9 - r14; var r60 = 3 / r27; var r61 = r4 % 8; print(r7); var r62 = 4 | 9; r17 = r61 + r13; var r63 = r60 ^ 5; var r64 = r25 | r6; var r65 = r1 % 1; r55 = 5 ^ r53; var r66 = r25 | r37; r39 = r26 % r35; var r67 = r61 - r24; var r68 = r5 * 5; var r69 = r59 ^ r47; var r70 = r31 & r56; print(r37); var r71 = 7 + r62; r17 = r52 ^ 4; r29 = r54 & r23; var r72 = 8 - 7; var r73 = 7 % 9; var r74 = r73 - 9; var r75 = r74 & r61; var r76 = 9 | 3; var r77 = 1 ^ r30; var r78 = r48 & r9; var r79 = r66 - 8; var r80 = r29 / 4; var r81 = 7 - r38; var r82 = r70 ^ 1; var r83 = 1 * 6; var r84 = r65 - r25; var r85 = r27 / r1; r78 = r19 | r16; var r86 = 5 ^ r70; var r87 = r63 % 6; r76 = r61 + r44; var r88 = r87 ^ 6; var r89 = 3 / r38; var r90 = r71 | r44; var r91 = r75 * r62; var r92 = 8 ^ r53; r88 = 2 & 7; var r93 = 0 * r40; var r94 = 0 ^ 4; var r95 = r86 - r80; r45 = 2 * 4; var r96 = 8 & r62; var r97 = 2 % r7; var r98 = 6 * 3; var r99 = 1 | r84; var r100 = r14 ^ r32; var r101 = 3 * r60; var r102 = r41 - r47; var r103 = r51 - r37; var r104 = 7 | r27; var r105 = r44 % r68; var r106 = 0 | r21; var r107 = 1 * r17; var r108 = 5 ^ r11; print(r87); var r109 = 5 + r16; var r110 = 0 | r19; var r111 = r39 - r91; var r112 = r46 ^ r104; var r113 = r9 * r110; var r114 = 3 | 1; r20 = r111 * 5; var r115 = 8 ^ r14; var r116 = r12 + 0; r13 = r60 + r75; r95 = 5 ^ r1; var r117 = r78 + 0; var r118 = r81 - r102; r74 = r48 - r7; var r119 = 3 - r21; var r120 = r93 / r11; print(r88); var r121 = r118 % r7; var r122 = r109 & r73; var r123 = 2 / r104; print(r95); r111 = r102 % r46; r35 = 1 ^ r21; var r124 = r29 | 6; var r125 = r41 + r77; r109 = r121 + 5; var r126 = 2 - r92; ");
/*fuzzSeed-159544250*/count=746; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=747; tryItOut("m1.get(t2);");
/*fuzzSeed-159544250*/count=748; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.hypot(((((Math.pow(-Number.MAX_VALUE, 1) >>> 0) ? (Number.MAX_VALUE >>> 2**53+2) : (x ? x : -(2**53+2))) ? Math.max(Math.round(( + y)), y) : ( + (( + y) < ( + x)))) + Math.atan2(0, ( ! ( + (( + y) & ( + x)))))), (((Math.imul((y !== ( + x)), Math.sinh(Math.hypot(y, x))) | 0) == (Math.atanh(2**53) | 0)) | 0)); }); testMathyFunction(mathy0, [Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0, -1/0, 0x080000000, -0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -(2**53), -0, -0x080000001, 2**53, 0.000000000000001, 0x07fffffff, 0x080000001, -0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -(2**53+2), Math.PI, 2**53+2, 0x0ffffffff, 2**53-2, 42]); ");
/*fuzzSeed-159544250*/count=749; tryItOut("s2 += 'x';\nfor (var v of i2) { try { a2.sort(i1, g2.p0); } catch(e0) { } try { this.h0.__proto__ = s1; } catch(e1) { } v2 = evalcx(\"/* no regression tests found */\", g0); }\n");
/*fuzzSeed-159544250*/count=750; tryItOut("if((x % 6 == 3)) {a0.sort((function mcc_() { var fcdwur = 0; return function() { ++fcdwur; f1(/*ICCD*/fcdwur % 6 == 1);};})(), o0.o0.s1, this.v1);print(new ([,,z1])(\"\\u7293\", -3)); } else  if (({ get x()e + x, setFullYear: \"\\u0112\" })) {this.m0.set(e2, g1); }");
/*fuzzSeed-159544250*/count=751; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - ( + Math.imul((y >>> 0), (x << Math.fround((Math.fround((-(2**53-2) ? Math.fround(y) : ( + y))) ? (x | 0) : Math.fround((Math.log((y | 0)) | 0)))))))); }); ");
/*fuzzSeed-159544250*/count=752; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.fround(mathy1(Math.imul(Math.fround(mathy2(( + Math.clz32(x)), ((x >> (1.7976931348623157e308 >>> 0)) >>> 0))), Math.fround(Math.max(y, Math.fround(x)))), Math.sin(-Number.MAX_SAFE_INTEGER)))); }); testMathyFunction(mathy3, [0x080000001, -Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, 0x100000000, 1/0, 0/0, 0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -(2**53-2), Number.MIN_VALUE, 0x080000000, 1, -0x080000000, -0x100000000, 2**53+2, -1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -0, 0x100000001, 0x0ffffffff, -0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -0x080000001, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53)]); ");
/*fuzzSeed-159544250*/count=753; tryItOut("b2 + '';");
/*fuzzSeed-159544250*/count=754; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( + ( - ((Math.atan2((Math.pow(Number.MIN_SAFE_INTEGER, Math.max(Math.fround(x), Math.fround((Math.hypot((x | 0), (y | 0)) | 0)))) | 0), (x | 0)) | 0) != (Math.min(x, y) ? (( + ((y ? x : ( + x)) >>> x)) | 0) : y)))) + ((Math.cos(Math.acos(x)) === ( - x)) | 0)); }); ");
/*fuzzSeed-159544250*/count=755; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=756; tryItOut("a2.reverse();function x(x, x)\"use asm\";   var Infinity = stdlib.Infinity;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    d0 = (Infinity);\n    i1 = (i2);\n    switch (( \"\" )) {\n      case -2:\n        {\n          {\n            d0 = (2199023255553.0);\n          }\n        }\n        break;\n      case -2:\n        (Float64ArrayView[((0x0) / (((1)-(i1))>>>((!(i1))))) >> 3]) = ((((Infinity))));\n      case 0:\n        (Float64ArrayView[4096]) = ((+(-1.0/0.0)));\n        break;\n      case -1:\n        i1 = (i2);\n        break;\n      default:\n        (Float32ArrayView[(0x59cbb*(((0xe10e91e)) ? (i3) : (0x2753325e))) >> 2]) = ((+(0.0/0.0)));\n    }\n    d0 = (Infinity);\n    i3 = (i1);\n    i1 = (0xa839240a);\n    i2 = (-0x8000000);\n    i1 = (0xffffffff);\n    return (((!((0x9f1de3f9) >= (0x710e355c)))))|0;\n    i3 = (0xffffffff);\n    (Float64ArrayView[2]) = ((4277));\n    i2 = (0xfa830048);\n    return ((((0x72b23a2c))-(i2)))|0;\n  }\n  return f;a1.toSource = f2;");
/*fuzzSeed-159544250*/count=757; tryItOut("e1 + i2;");
/*fuzzSeed-159544250*/count=758; tryItOut("(let (x, a = (4277), window = undefined.unwatch(\"__count__\"), x = ({}), xbkzyc) -7);");
/*fuzzSeed-159544250*/count=759; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! (Math.pow(( ! (( + ( - y)) ? ( + mathy0(( + ( + ( - y))), ( + y))) : Math.ceil(Math.pow(Number.MIN_VALUE, x)))), Math.atan((( ! ( + (( + -(2**53)) < ( + Math.sqrt(-Number.MIN_VALUE))))) | 0))) >>> 0)); }); ");
/*fuzzSeed-159544250*/count=760; tryItOut("\"use strict\"; /*oLoop*/for (rrkgls = 0; rrkgls < 91; ++rrkgls) { print(x); } ");
/*fuzzSeed-159544250*/count=761; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0, this.v1);");
/*fuzzSeed-159544250*/count=762; tryItOut("mathy3 = (function(x, y) { return ((Math.trunc(Math.atan2(mathy0((( + (-0x0ffffffff * y)) & y), ( + ( - (Math.abs((mathy2(x, Math.fround(-(2**53))) | 0)) | 0)))), 1)) + ( - (Math.fround(Math.cosh(Math.fround(x))) + y))) | 0); }); testMathyFunction(mathy3, [-0x0ffffffff, 0x100000001, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, 42, 1.7976931348623157e308, -0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 0.000000000000001, 0x100000000, 1, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), Math.PI, 0x080000000, 0, 1/0, 2**53-2, -0x07fffffff, 0/0, -Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, -(2**53), 2**53+2, -1/0, 2**53, -0x080000000]); ");
/*fuzzSeed-159544250*/count=763; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.acosh((Math.min((((Math.cbrt(y) | 0) * (Math.max(( + y), ((x !== y) | 0)) | 0)) | 0), (Math.tan(y) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [42, 0, 0x100000000, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -0x080000000, 0x080000000, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, 0x100000001, -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 2**53+2, 2**53, 0.000000000000001, 1.7976931348623157e308, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -0x100000001, Number.MAX_VALUE, Math.PI, -(2**53+2), -1/0, 0/0, Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=764; tryItOut("e2.delete(this.a2);");
/*fuzzSeed-159544250*/count=765; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2(Math.fround(((((Math.atan2(((y !== y) | 0), (y | 0)) | 0) | 0) << (Math.fround(( ~ (Math.fround(Math.tanh(( + (( + 2**53+2) % y)))) >>> 0))) | 0)) | 0)), (( + mathy0(( + ( ! Math.atanh(Math.fround(( ~ (( ! (y | 0)) >>> 0)))))), ( + (Math.imul(Math.fround(Math.sin((Math.imul((Math.log1p(y) >>> 0), (y | 0)) | 0))), Math.atan2(( ! Math.min(x, y)), (y >>> 0))) >>> 0)))) >>> 0))); }); testMathyFunction(mathy1, [0x080000000, -Number.MIN_VALUE, 42, -(2**53-2), -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, 0, -0x0ffffffff, 1.7976931348623157e308, 0/0, -0x07fffffff, -0x080000000, 1, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, 0x100000001, 2**53+2, -0, -Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 0.000000000000001, 0x100000000, -0x100000000, Math.PI, 0x0ffffffff, 1/0, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=766; tryItOut("mathy3 = (function(x, y) { return Math.fround(( + Math.fround((Math.imul(0x100000001, Math.sin((((Math.min(( + (x ? -0x080000001 : y)), (y >>> 0)) | 0) ? (Math.exp(x) | 0) : y) | 0))) ^ Math.fround(Math.acos(Math.sqrt(Math.cos(2**53+2)))))))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new String('')), '', 1, null, 0, 0.1, '\\0', '0', NaN, '/0/', (new Number(-0)), ({toString:function(){return '0';}}), true, -0, objectEmulatingUndefined(), [0], false, (function(){return 0;}), (new Number(0)), (new Boolean(true)), (new Boolean(false)), undefined, [], /0/]); ");
/*fuzzSeed-159544250*/count=767; tryItOut("m2.set(this.m0, g1);");
/*fuzzSeed-159544250*/count=768; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.asin(Math.fround(((Math.fround((( ~ x) >>> 0)) || Math.fround(mathy1(mathy3(y, ( - (y >>> 0))), 0.000000000000001))) & (Math.fround(Math.log(((Math.tan((Math.expm1((Math.pow((y | 0), (x | 0)) | 0)) >>> 0)) >>> 0) | 0))) >>> 0))))); }); testMathyFunction(mathy4, [0.1, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), 1, -0, '/0/', '', ({valueOf:function(){return 0;}}), '0', null, 0, '\\0', /0/, NaN, ({toString:function(){return '0';}}), (new Number(0)), [0], (new Boolean(false)), undefined, (new String('')), (new Number(-0)), [], (new Boolean(true)), true, false, (function(){return 0;})]); ");
/*fuzzSeed-159544250*/count=769; tryItOut("\"use strict\"; /*RXUB*/var r = /((\\B))+[^\\\u0098]?/gm; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-159544250*/count=770; tryItOut("/*vLoop*/for (var nnhxuq = 0; nnhxuq < 133; ++nnhxuq) { var y = nnhxuq; f1(f0); } ");
/*fuzzSeed-159544250*/count=771; tryItOut("/*hhh*/function jqtizk(...x){for (var v of g2.i0) { for (var p in p0) { try { Array.prototype.splice.apply(a0, []); } catch(e0) { } try { v1 = g2.runOffThreadScript(); } catch(e1) { } try { e1.delete(i0); } catch(e2) { } b0.toSource = (function(j) { if (j) { try { v2 = (f1 instanceof o2); } catch(e0) { } try { m2 = new Map; } catch(e1) { } v1 = evaluate(\"v0 = new Number(-0);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 3), noScriptRval: true, sourceIsLazy: false, catchTermination: false })); } else { try { v0 = a2.length; } catch(e0) { } try { /*MXX3*/g1.RangeError.prototype.toString = this.g1.RangeError.prototype.toString; } catch(e1) { } s1 = a0.join(s2, t2); } }); } }}jqtizk((( /x/ .valueOf(\"number\")) ? (Math.imul(-19, z)) : allocationMarker()), x);");
/*fuzzSeed-159544250*/count=772; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan2(Math.fround(( - Math.fround(Math.cos((y ? Math.fround(Math.cos(Math.fround((x || y)))) : 0.000000000000001))))), (( + Math.fround(( ! (x | 0)))) || Math.pow(((Math.imul((Math.pow(x, (y >>> 0)) | 0), ( ! Math.fround(0x07fffffff))) | 0) | 0), y))); }); testMathyFunction(mathy4, [-0x100000001, 0/0, 2**53+2, -0, -(2**53), -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 0x080000001, 2**53, 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, 0x07fffffff, 0x0ffffffff, -(2**53+2), -0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 1, Number.MAX_VALUE, -Number.MAX_VALUE, 0, Math.PI, -0x080000000, 1/0, 0.000000000000001, -0x0ffffffff, 0x080000000, 0x100000000, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-159544250*/count=773; tryItOut("\"use strict\"; this.o2.g0.__proto__ = e2;");
/*fuzzSeed-159544250*/count=774; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return mathy0(Math.pow((Math.atan2((Math.atanh((Math.cos(-0x0ffffffff) | 0)) | 0), (mathy0((mathy0(((x > (y >>> 0)) >>> 0), ( ! x)) | 0), Math.sign((Math.sin((y | 0)) | 0))) | 0)) >>> 0), ( + Math.tan(( + ( + Math.cos(x)))))), ( ! (( ~ (Math.cos((( + (Math.pow(x, Math.PI) , Math.atan2(( + Math.imul(( + y), ( + y))), Math.log1p(x)))) | 0)) | 0)) >>> 0))); }); testMathyFunction(mathy1, [1/0, -Number.MAX_VALUE, 0x080000000, 1, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 0, 0x100000000, 0x07fffffff, 42, -(2**53), -0x100000000, Math.PI, -0x100000001, 2**53, 2**53+2, 0/0, -(2**53+2), 0.000000000000001, -0x0ffffffff, -0x080000001, 0x080000001, 0x0ffffffff, 2**53-2, 1.7976931348623157e308, -1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=775; tryItOut("testMathyFunction(mathy5, [0x07fffffff, -0x080000000, -0x080000001, -(2**53), Number.MIN_VALUE, -(2**53+2), 0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, 0x100000000, -0x07fffffff, -1/0, 2**53+2, 1.7976931348623157e308, -0x0ffffffff, 2**53, 1, Number.MAX_VALUE, 0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, -0, 0/0, 1/0, Number.MIN_SAFE_INTEGER, 2**53-2, 42]); ");
/*fuzzSeed-159544250*/count=776; tryItOut("print(uneval(s2));");
/*fuzzSeed-159544250*/count=777; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.log2(Math.fround(Math.asin(Math.fround((((y | 0) !== (Math.fround(Math.cos(Math.PI)) | 0)) | 0)))))); }); testMathyFunction(mathy5, [0x080000001, 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 2**53-2, 0, 1/0, 0x100000001, -(2**53+2), Math.PI, 0/0, -(2**53-2), -0x100000001, 1, 0x0ffffffff, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, 0x100000000, -0x080000001, -0x07fffffff, 0.000000000000001, 42, -0, -1/0, 0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=778; tryItOut("\"use strict\"; for(let c in /*MARR*/[ /x/g , function(){}, function(){}, function(){}, 2**53+2, 2**53+2,  /x/g , 2**53+2, 2**53+2, true, function(){}, 2**53+2, true, 2**53+2, 2**53+2, 2**53+2,  /x/g , true, true, true, true, true, true, true, function(){}, 2**53+2, true, function(){}, 2**53+2, 2**53+2, function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ]) with({}) Math.atan2((z)( \"\" , []), x / x);let(z =  '' , dkqrjl, x, lhmwhu, \u3056 = x, x = arguments[\"length\"] = this) { for(let y in []);}");
/*fuzzSeed-159544250*/count=779; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.expm1(( ~ Math.min(Math.cosh(( + (( + 0) !== x))), (( + (Math.atan2(y, y) ^ ((y !== x) >>> 0))) * (Math.PI >>> 0))))); }); testMathyFunction(mathy3, [null, true, '\\0', objectEmulatingUndefined(), NaN, '/0/', '', 0, (new String('')), (new Boolean(false)), '0', [], 1, -0, false, undefined, ({valueOf:function(){return 0;}}), (new Boolean(true)), ({toString:function(){return '0';}}), (new Number(0)), ({valueOf:function(){return '0';}}), (function(){return 0;}), /0/, 0.1, [0], (new Number(-0))]); ");
/*fuzzSeed-159544250*/count=780; tryItOut("i0.send(this.f1);");
/*fuzzSeed-159544250*/count=781; tryItOut("\"use strict\"; m0.get(p0);");
/*fuzzSeed-159544250*/count=782; tryItOut(";");
/*fuzzSeed-159544250*/count=783; tryItOut("e0.add(g2);");
/*fuzzSeed-159544250*/count=784; tryItOut("\"use strict\"; m0.has(o0);");
/*fuzzSeed-159544250*/count=785; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( ~ mathy3(x, ((mathy0((Math.max((x >>> 0), ((Math.atan2(x, ( + -1/0)) >>> 0) >>> 0)) | 0), (x | 0)) | 0) >>> 0))) / Math.imul((mathy1(Math.fround(( ! ( ! x))), Math.expm1(( - y))) >>> 0), ( + ( ~ x)))) ^ Math.fround(Math.sin(Math.fround((( - -Number.MAX_VALUE) ? Math.atanh(((Math.fround(Math.tanh(y)) >= Math.fround(y)) | 0)) : Math.atan2(( + (x - x)), x)))))); }); testMathyFunction(mathy4, [false, (new Number(0)), undefined, objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), 1, true, (new String('')), [], NaN, '', ({toString:function(){return '0';}}), null, (new Number(-0)), [0], ({valueOf:function(){return '0';}}), /0/, 0, -0, '0', '\\0', (function(){return 0;}), (new Boolean(true)), '/0/', (new Boolean(false))]); ");
/*fuzzSeed-159544250*/count=786; tryItOut("Array.prototype.unshift.call(a1, i0);let d = /*RXUE*/new RegExp(\"(?:(?:.))\", \"i\").exec(\"\\n\");");
/*fuzzSeed-159544250*/count=787; tryItOut("\"use strict\"; o1.b0.__iterator__ = (function() { try { g1.t0 = t1.subarray(/(?=(?:^)+|(?=\\b)|\u00da\\B)([^])|(?:\\s)\\u00A1*?/g); } catch(e0) { } g0.v1 = a0.length; return s0; });Object.defineProperty(o2, \"v1\", { configurable: (eval(\"mathy5 = (function(x, y) { return ((Math.fround(mathy3(Math.fround(( - ((2**53-2 ** 0x080000001) >= Math.imul(((Math.min((x | 0), (y | 0)) | 0) >>> 0), (x >>> 0))))), Math.fround(((Math.max(Math.min(x, ( + ( ~ y))), (( ~ (Math.fround(x) | Math.fround(y))) | 0)) ? (x >>> 0) : (Math.fround(Math.sinh(Math.fround(Math.hypot(y, Math.fround((Math.fround(0x07fffffff) ? ( + x) : y)))))) >>> 0)) >>> 0)))) ? ((Math.asin((Math.hypot(( ~ y), ( + (Math.cbrt((x | 0)) | 0))) ^ mathy3((x | 0), ( - y)))) ? (Math.pow(((( ~ (Math.imul(0.000000000000001, x) | 0)) | 0) >>> 0), (Math.atan2(y, Math.exp(y)) >>> 0)) >>> 0) : ( + Math.hypot((( ~ ( ~ ( + (-0x080000001 == x)))) >>> 0), ( + x)))) >>> 0) : ( + (Math.tanh(( + ( - Math.fround((\\\"\\\\u06E0\\\" && Math.max(( + -(2**53)), Math.trunc(x))))))) | 0))) | 0); }); testMathyFunction(mathy5, [-(2**53), 2**53, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0, -0x100000001, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, 0x100000001, 1, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, -0x080000001, 0x080000000, 0x07fffffff, -(2**53+2), 0/0, -1/0, 0, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, 2**53+2, -0x07fffffff]); \", /*MARR*/[(void 0), new Boolean(true), (void 0), [], [], [], (void 0), new Boolean(true), (void 0), new Boolean(true),  \"\" ,  \"\" , [], (void 0), (void 0), (void 0), [], [],  \"\" , (void 0), (void 0),  \"\" , new Boolean(true)].some)), enumerable: false,  get: function() {  return b2.byteLength; } });");
/*fuzzSeed-159544250*/count=788; tryItOut("t0 = t0.subarray(15);");
/*fuzzSeed-159544250*/count=789; tryItOut("\"use strict\"; /*RXUB*/var r = o0.r0; var s = \"\\u00a4a\\u00a4a\\u00a4a\\u00a4a\\n\"; print(s.match(r)); print(r.lastIndex); function d(w, b, c, c, y = (function ([y]) { })(), NaN, \u3056, x =  /x/g , y, e, x, window, x, w, w, x = \u3056, y, x =  /x/g , x, z, eval, window, x, window, y, c = \"\\u4F89\", b =  /x/g , x =  '' , NaN, x, x, x, \u3056, x, z, x = \"\\u7180\", e, y, eval)\u000c { v1 = g2.eval(\"\\\"use asm\\\"; v1 = a1.reduce, reduceRight((function mcc_() { var gubtwf = 0; return function() { ++gubtwf; if (gubtwf > 8) { dumpln('hit!'); try { Object.preventExtensions(o0.m0); } catch(e0) { } try { /*RXUB*/var r = r0; var s = s0; print(uneval(s.match(r)));  } catch(e1) { } try { this.e1.add(f2); } catch(e2) { } e0.add(g1.g0.a1); } else { dumpln('miss!'); try { /*MXX3*/this.g2.RangeError.prototype = g0.RangeError.prototype; } catch(e0) { } try { m0.set(h1, b); } catch(e1) { } try { print(uneval(g2)); } catch(e2) { } print(uneval(s0)); } };})(), s2);\"); } ;");
/*fuzzSeed-159544250*/count=790; tryItOut("\"use strict\"; v2 = r1.flags;");
/*fuzzSeed-159544250*/count=791; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-159544250*/count=792; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3\", \"g\"); var s = \"h\"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=793; tryItOut("i0.send(g0);");
/*fuzzSeed-159544250*/count=794; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.ceil(( + Math.atan((Math.fround((((Math.pow(x, x) >>> 0) >> -Number.MAX_VALUE) >>> 0)) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-159544250*/count=795; tryItOut("t1 = t0.subarray(12);");
/*fuzzSeed-159544250*/count=796; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround((Math.fround(Math.hypot((Math.sinh((Math.sin(( ! ( ~ x))) >>> 0)) >>> 0), Math.pow((Math.min(x, ( +  \"\" )) | 0), ((( + ( ~ ( + y))) << y) | 0)))) < Math.fround(((Math.abs((( + Math.hypot((( ~ (Math.fround((Math.fround(x) / Math.fround(y))) | 0)) | 0), y)) | 0)) | 0) < Math.fround(Math.min(Math.fround(x), Math.fround(Math.fround(( - -0x100000001))))))))); }); ");
/*fuzzSeed-159544250*/count=797; tryItOut("testMathyFunction(mathy5, [({valueOf:function(){return 0;}}), NaN, '', objectEmulatingUndefined(), [], true, '/0/', false, ({toString:function(){return '0';}}), (new Number(-0)), [0], ({valueOf:function(){return '0';}}), /0/, null, (new Boolean(true)), -0, '0', '\\0', 0, (new Number(0)), (new Boolean(false)), (new String('')), 0.1, 1, (function(){return 0;}), undefined]); ");
/*fuzzSeed-159544250*/count=798; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\u0EaC|(?!(?:(.|\\\\b|[^]*[\\\\w\\\\d]+?))((?!$)*|\\u5ecd.|[^])*)\", \"g\"); var s = \"\"; print(s.split(r)); { void 0; disableSPSProfiling(); }");
/*fuzzSeed-159544250*/count=799; tryItOut("\"use strict\"; p0 = t0[({valueOf: function() { m0.delete(this);return 15; }})];");
/*fuzzSeed-159544250*/count=800; tryItOut("testMathyFunction(mathy1, [-0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 42, -(2**53-2), 0x100000000, 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MIN_VALUE, -0x100000001, 2**53+2, -0x100000000, -1/0, -Number.MAX_VALUE, -0x07fffffff, 0x100000001, 0/0, Number.MAX_VALUE, 2**53-2, 0x080000000, 1.7976931348623157e308, 0x07fffffff, -0, 2**53, -0x080000001, 0, Math.PI, 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-159544250*/count=801; tryItOut("b0 = m0.get(s0);");
/*fuzzSeed-159544250*/count=802; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=803; tryItOut("m2.get(s0);");
/*fuzzSeed-159544250*/count=804; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.imul(Math.hypot((mathy1((Math.atan2((-(2**53) >>> 0), ((-0x0ffffffff ? ((-(2**53) | 0) & x) : Math.fround((-Number.MIN_VALUE < (Math.fround(Math.cbrt(Math.fround(y))) >>> 0)))) >>> 0)) >>> 0), (x < Math.asinh(( + (( + x) & ( + ( - x))))))) >>> 0), (Math.pow(((Math.log(x) | Math.tanh(y)) | 0), (( - x) | 0)) | 0)), Math.asin(Math.max(( + Math.min(Number.MIN_SAFE_INTEGER, x)), ( ~ (((( ~ x) | 0) <= (x >> x)) | 0))))); }); testMathyFunction(mathy5, [-(2**53), 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, -0x100000000, -0x0ffffffff, 1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), 0, 0x100000000, 0x0ffffffff, 1.7976931348623157e308, 1, 0x080000000, Math.PI, -1/0, 0.000000000000001, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 0/0, -0x080000001, -0x100000001, -Number.MIN_VALUE, -0]); ");
/*fuzzSeed-159544250*/count=805; tryItOut("\"use strict\"; yield [,,z1];");
/*fuzzSeed-159544250*/count=806; tryItOut("t0.toString = (function() { t1.set(t1, 12); return o2; });");
/*fuzzSeed-159544250*/count=807; tryItOut("");
/*fuzzSeed-159544250*/count=808; tryItOut("\"use strict\"; m0 = new WeakMap;");
/*fuzzSeed-159544250*/count=809; tryItOut("([,,]);");
/*fuzzSeed-159544250*/count=810; tryItOut("\"use strict\"; a1.splice(NaN, 17, o0, o0.a2);");
/*fuzzSeed-159544250*/count=811; tryItOut("/*bLoop*/for (jbbqzw = 0; (x) && jbbqzw < 13; ++jbbqzw) { if (jbbqzw % 55 == 11) { (void schedulegc(g1)); } else { print(uneval(v1)); }  } ");
/*fuzzSeed-159544250*/count=812; tryItOut("a1 + '';");
/*fuzzSeed-159544250*/count=813; tryItOut("var favdek = new SharedArrayBuffer(4); var favdek_0 = new Uint16Array(favdek); favdek_0[0] = 23; throw  /x/g ;( \"\" );for (var v of p1) { try { this.v2 + ''; } catch(e0) { } Array.prototype.pop.apply(a1, []); }");
/*fuzzSeed-159544250*/count=814; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, -0x0ffffffff, 2**53-2, -0x080000000, Math.PI, 0/0, -0x080000001, -1/0, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000001, -0x100000000, -(2**53+2), -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, 0, 1/0, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 2**53+2, 42, 0x07fffffff, 0x080000001, 1, 0x080000000, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-159544250*/count=815; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.max(Math.acos(( ~ Math.hypot(( + -(2**53-2)), Math.fround(Math.round((( + 2**53+2) >>> 0)))))), Math.atan2(((( + Math.trunc(( + (( + mathy0(( + -Number.MAX_SAFE_INTEGER), ( + x))) >>> 0)))) ? (x | 0) : Math.fround((Math.fround(mathy0(mathy0(x, ( + (mathy0((-Number.MIN_VALUE | 0), x) | 0))), y)) > ( + (Math.atan2(((Math.max((y >>> 0), (0x07fffffff >>> 0)) >>> 0) >>> 0), (-(2**53-2) | 0)) | 0))))) | 0), ( + ( + Math.min(0x100000000, ( + y)))))) | 0); }); testMathyFunction(mathy1, [1, NaN, (new Number(0)), 0.1, [0], objectEmulatingUndefined(), (new Boolean(false)), [], 0, '\\0', null, (new Boolean(true)), true, (new Number(-0)), '0', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), undefined, false, '/0/', '', (function(){return 0;}), ({toString:function(){return '0';}}), /0/, -0, (new String(''))]); ");
/*fuzzSeed-159544250*/count=816; tryItOut("\"use asm\"; /*ADP-3*/Object.defineProperty(this.a0, v1, { configurable: false, enumerable: (x % 6 != 5), writable: new new RegExp(\"\\\\n\", \"ym\") == print(x), value: this.f1 });");
/*fuzzSeed-159544250*/count=817; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3|\\\\S+\", \"gym\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-159544250*/count=818; tryItOut("\"use strict\"; s0 + m1;");
/*fuzzSeed-159544250*/count=819; tryItOut("\"use strict\"; switch((((4277))(( /x/g )(window, x), \u3056))) { default: case 5: break;  }");
/*fuzzSeed-159544250*/count=820; tryItOut("/*tLoop*/for (let y of /*MARR*/[x, true, x, x, true, true, true]) { a2.splice(i0, this.p1);s1 = m0; }");
/*fuzzSeed-159544250*/count=821; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1.0078125;\n    var d3 = 3.777893186295716e+22;\n    var i4 = 0;\n    var i5 = 0;\n    return (((-0x8000000)-(0x46decfed)))|0;\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, 0x0ffffffff, 0x100000001, -0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, -0x080000000, 0, 2**53, -0x100000000, 0/0, 0.000000000000001, -Number.MAX_VALUE, 42, -(2**53-2), -0x100000001, -1/0, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 0x07fffffff, 1, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 2**53+2, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=822; tryItOut("(window = \"\\uC109\".valueOf(\"number\"));");
/*fuzzSeed-159544250*/count=823; tryItOut("let(a) ((function(){with({}) x *= e.__proto__ = w;})());throw StopIteration;");
/*fuzzSeed-159544250*/count=824; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\3|^|\\2|(?=[^\\w\\w\u00e3\\d]|\\0)\\3+?{3}[\\v\\\u4577-\ua720\u00bb\u16ce-\u3b69]+?)/gm; var s = \"\\u4c3c\"; print(uneval(r.exec(s))); function x() { return y >>= b } /*RXUB*/var r = /Y|\\D|^|[^]|\\f{0,}+|(?!(?:[\\S\u652e-\\\u771c\\S\\u003F-\\u1ACd]+))*?(?!\\3){4}/yim; var s = \"y\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=825; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( - ((mathy0(((Math.expm1(((((Number.MIN_SAFE_INTEGER >>> 0) >= ((( ~ ((2**53 <= (Math.acosh(Math.fround(y)) >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0), Math.pow(( + ( ! ( + y))), Math.fround((Math.min(Math.cosh((Math.atan2((y | 0), y) >>> 0)), (mathy1(x, y) >>> 0)) >>> 0)))) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, ['/0/', objectEmulatingUndefined(), '0', (new Number(0)), 1, ({valueOf:function(){return 0;}}), -0, /0/, true, (new Boolean(true)), ({toString:function(){return '0';}}), '', (function(){return 0;}), (new Number(-0)), [0], 0.1, [], NaN, null, (new Boolean(false)), (new String('')), 0, undefined, '\\0', ({valueOf:function(){return '0';}}), false]); ");
/*fuzzSeed-159544250*/count=826; tryItOut("mathy3 = (function(x, y) { return ((Math.log10((Math.fround(mathy0(Math.fround((((( ~ ((Math.min((y >>> 0), (x >>> 0)) >>> 0) | 0)) >>> 0) <= -0x07fffffff) >>> 0)), Math.fround(( + x)))) >>> 0)) >>> 0) <= Math.fround(( ! ( ~ Math.max(2**53-2, (( + ( + (mathy0((x >>> 0), (x >>> 0)) >>> 0))) == Number.MIN_VALUE)))))); }); testMathyFunction(mathy3, [1, -0x080000000, 42, 0x0ffffffff, -Number.MAX_VALUE, 0x080000000, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, -1/0, Number.MAX_VALUE, -0, Math.PI, -0x07fffffff, 0/0, 0, 0x07fffffff, -(2**53-2), 2**53+2, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 1/0, 2**53]); ");
/*fuzzSeed-159544250*/count=827; tryItOut("\"use strict\"; o0 = Proxy.create(h0, o2.b2);");
/*fuzzSeed-159544250*/count=828; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.min(( ~ ( + Math.trunc((y | 0)))), (( + (Math.clz32(y) | 0)) + ( ! ( + y)))); }); testMathyFunction(mathy1, [-0x0ffffffff, 0x080000001, 1.7976931348623157e308, 42, 2**53-2, 2**53, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, -0x080000001, Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -0, 1/0, -Number.MIN_SAFE_INTEGER, -1/0, 1, -(2**53), 0x07fffffff, -0x100000001, -(2**53+2), -0x080000000, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, 0x080000000, Math.PI, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=829; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return mathy0((Math.sin((( ~ (Math.trunc((( + mathy1(0x100000001, mathy1(-Number.MAX_VALUE, x))) >>> 0)) >>> 0)) >>> 0)) | 0), Math.fround(( - ( + ( ~ (Math.asin(( + (( + -Number.MIN_VALUE) === ( ~ ( + y))))) >>> 0)))))); }); testMathyFunction(mathy2, [false, 0, (function(){return 0;}), [], 1, [0], undefined, '\\0', ({valueOf:function(){return 0;}}), '', null, objectEmulatingUndefined(), '0', (new String('')), (new Number(0)), 0.1, /0/, NaN, (new Boolean(true)), (new Boolean(false)), true, -0, (new Number(-0)), '/0/', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-159544250*/count=830; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\S\", \"gy\"); var s = \"0\"; print(s.replace(r, let (z)  /x/g )); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=831; tryItOut("h1 + '';");
/*fuzzSeed-159544250*/count=832; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - (mathy2((Math.expm1(mathy3(((((Math.max(y, x) | 0) >>> 0) === Math.atan(x)) >>> 0), x)) | 0), (((x | 0) - (Math.fround(Math.min((x ** x), y)) % -1/0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [0, ({valueOf:function(){return '0';}}), '/0/', objectEmulatingUndefined(), (new Boolean(true)), '\\0', '0', [], null, (function(){return 0;}), true, 0.1, (new Number(0)), 1, -0, ({valueOf:function(){return 0;}}), (new Number(-0)), (new Boolean(false)), NaN, '', undefined, /0/, [0], (new String('')), ({toString:function(){return '0';}}), false]); ");
/*fuzzSeed-159544250*/count=833; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.atanh((Math.fround(( + Math.fround(( ! -0x07fffffff)))) | 0))); }); testMathyFunction(mathy5, [2**53-2, 1, -(2**53), 0/0, Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 0x07fffffff, -(2**53-2), 1.7976931348623157e308, Math.PI, -(2**53+2), -0x07fffffff, 0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, 2**53+2, 2**53, -Number.MAX_VALUE, 0x100000001, 0.000000000000001, 0x080000000, 1/0, -0x080000001, -0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 42, -1/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=834; tryItOut("Array.prototype.push.apply(a2, [a2, g2]);");
/*fuzzSeed-159544250*/count=835; tryItOut("mathy5 = (function(x, y) { return (Math.imul((((Math.fround(((( + (( + ((y !== (Math.cosh((0/0 >>> 0)) >>> 0)) >>> 0)) >>> 0)) << mathy3(0x080000001, Math.log(x))) >>> 0)) , Math.fround(Math.fround(mathy1((x >> ( + Math.atan2(( + y), ( + x)))), (Math.expm1((x >>> 0)) >>> 0))))) | 0) | 0), ((( + (( + x) != ( - Math.fround(Math.log(Math.fround(( + ((y >>> 0) % (y >>> 0))))))))) == Math.fround(Math.hypot(Math.fround(Math.imul(x, Math.fround(y))), ((y <= ((Math.max((( - y) >>> 0), Math.pow(Math.pow((-(2**53+2) >>> 0), (y >>> 0)), x)) | 0) | 0)) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy5, [Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, -0, -0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, 0x100000001, -0x080000000, -(2**53), 0x0ffffffff, 0, 0/0, 2**53+2, Math.PI, -Number.MIN_VALUE, 0x07fffffff, -(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0x080000000, 0x100000000, 2**53, -(2**53-2), 1/0, 1.7976931348623157e308, 1, 0x080000001, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=836; tryItOut("\"use strict\"; v2 = g0.o0.g2.g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-159544250*/count=837; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=838; tryItOut("g2.e1.has(t0);");
/*fuzzSeed-159544250*/count=839; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.log1p(Math.fround(/*RXUE*/new RegExp(\"(?:(?!\\\\b)[^](?:\\\\W)*).\", \"y\").exec(\"\\n\"))); }); testMathyFunction(mathy5, [-0, ({valueOf:function(){return 0;}}), 1, true, objectEmulatingUndefined(), false, 0, undefined, [0], /0/, (new Number(0)), NaN, '0', (new Boolean(false)), (new Number(-0)), null, (new String('')), '', ({valueOf:function(){return '0';}}), 0.1, ({toString:function(){return '0';}}), [], '\\0', (function(){return 0;}), '/0/', (new Boolean(true))]); ");
/*fuzzSeed-159544250*/count=840; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.max(((Math.fround(Math.asin(Math.fround(Math.fround(( ! Math.fround(0x080000000)))))) , (Math.tanh(Math.fround(mathy2(x, (x >>> 0)))) * x)) || (Math.hypot((( ! Math.fround(mathy0((( + y) ? ( + ( ~ Math.fround(x))) : ( + x)), (Number.MIN_VALUE | 0)))) | 0), (-Number.MAX_VALUE | 0)) | 0)), (((mathy0(((( + Math.sqrt(y)) % Math.pow(x, x)) | 0), y) | 0) >>> 0) ? ((Math.asinh((Math.atan(-Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0) ? Math.sign((Math.ceil((x | 0)) | 0)) : Math.max(Math.max(( + (x % x)), y), Math.fround(y))) : (Math.cosh(((Math.pow(((Math.min(Number.MIN_SAFE_INTEGER, x) | 0) >>> 0), ((mathy1((Number.MIN_VALUE | 0), (x | 0)) | 0) >>> 0)) >>> 0) ? x : Math.fround(Math.hypot(Math.fround(x), Math.fround(x))))) | 0))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 1/0, -(2**53-2), -0x080000001, 0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0x100000000, -Number.MAX_VALUE, -(2**53), 1, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000001, -0, -0x080000000, 0/0, 0, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 2**53-2, 42, -Number.MIN_VALUE, Number.MIN_VALUE, 0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=841; tryItOut("mathy3 = (function(x, y) { return (Math.cosh(( + ( + Math.fround(y)))) < ( + ( + Math.trunc(( + ( + (( + Math.max((( + (x ? x : (x * y))) !== ( + x)), (((y >>> 0) !== (mathy0(0x080000001, x) | 0)) | 0))) ? ( + ( + Math.abs(y))) : ( + 0x100000001)))))))); }); testMathyFunction(mathy3, [2**53, Number.MAX_VALUE, 0, 0x100000001, 2**53+2, -(2**53-2), -0x080000000, -0x100000001, -0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -1/0, -0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -(2**53), 42, -(2**53+2), 1/0, 2**53-2, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, 1, Math.PI, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=842; tryItOut("\"use strict\"; /*iii*/-28;/*hhh*/function skkbye(w, ...z){g0 = v2;}\u000c");
/*fuzzSeed-159544250*/count=843; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\1?)*^?*?\", \"m\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=844; tryItOut("\"use strict\"; /*bLoop*/for (var jtvnuh = 0; jtvnuh < 97; ++jtvnuh) { if (jtvnuh % 30 == 27) { return; } else { a1[13] = \"\\u0148\"; }  } ");
/*fuzzSeed-159544250*/count=845; tryItOut("const NaN = function(id) { return id }, xnpuka;\"\u03a0\";");
/*fuzzSeed-159544250*/count=846; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(Math.fround((( - ((((x >>> 0) ? (Math.fround(( ~ y)) >>> 0) : Math.fround(Math.fround(x))) | 0) | 0)) | 0)), ((Math.max((Math.atan((Math.sin(-0x080000000) >>> 0)) | 0), ((Math.exp((Math.sign((2**53 | 0)) | 0)) | 0) | 0)) | 0) | 0))); }); testMathyFunction(mathy1, [2**53, -0x080000001, Number.MIN_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 0x100000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -(2**53+2), 0, -0x080000000, Math.PI, 0/0, -0, -(2**53), 42, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0x100000000, -Number.MAX_VALUE, -1/0, -0x100000000, 0x080000001, -0x100000001, 2**53+2, -(2**53-2), 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=847; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=848; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!\\3(^|\\d?)|[^\\\0\\D]\\W.|.*?+|(.)){3}/ym; var s = \"_\\n_00_00\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=849; tryItOut("w;");
/*fuzzSeed-159544250*/count=850; tryItOut("f2.valueOf = (function() { try { a0.splice(NaN, 0, b1); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(b0, o0.g0); return e2; });\ni0 = new Iterator(this.h1);\n");
/*fuzzSeed-159544250*/count=851; tryItOut("mathy5 = (function(x, y) { return Math.pow((Math.log2((( + ( ~ Math.fround(x))) ? ( + x) : ( + (Math.atan2(y, (Math.max(Math.fround(x), Math.pow(Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER)) >>> 0)) ? y : ((-Number.MAX_VALUE << ( + ( - ( + mathy1(x, x))))) | 0))))) | 0), Math.hypot(mathy1(Math.hypot(( + Math.fround(Math.imul(Math.fround(0x07fffffff), Math.fround(mathy4(-Number.MIN_VALUE, Math.fround((Math.fround(y) == (x | 0)))))))), ( + ( ! mathy2(mathy1(Math.fround(y), Number.MIN_VALUE), y)))), (( ~ x) | 0)), (( - ((y ? -1/0 : mathy1(Math.PI, Math.atan2(x, ( + x)))) | 0)) | 0))); }); testMathyFunction(mathy5, [2**53+2, -Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, 42, 0x100000000, 0x0ffffffff, 1.7976931348623157e308, 0x100000001, -1/0, -(2**53+2), 2**53, 0x080000001, 0x080000000, -(2**53), 0x07fffffff, 1/0, Number.MAX_VALUE, -0x100000001, Math.PI, 1, -(2**53-2), 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -0, 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-159544250*/count=852; tryItOut("\"use strict\"; e1.delete(o2.g1);");
/*fuzzSeed-159544250*/count=853; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sign(Math.asin((( + ( - Math.hypot(Math.fround((Math.fround(x) % Math.fround(y))), ( + ( + Math.fround(x)))))) | 0))); }); testMathyFunction(mathy0, [-0x080000001, 0x100000000, 2**53, 0.000000000000001, -Number.MAX_VALUE, 0x0ffffffff, 42, -0, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 0/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 1/0, 0, 1.7976931348623157e308, Math.PI, -(2**53-2), -0x080000000, 0x080000000, -1/0, 0x07fffffff, 0x080000001, Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), -0x100000001, -0x100000000, 2**53+2]); ");
/*fuzzSeed-159544250*/count=854; tryItOut("\"use strict\"; g1.b1 = t2.buffer;");
/*fuzzSeed-159544250*/count=855; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul(Math.hypot(Math.fround((Math.sin(( + (Math.hypot((y >>> 0), (Math.imul(x, (y | 0)) >>> 0)) >>> 0))) >>> 0)), (Math.hypot(( + Math.fround(y)), ( - x)) | 0)), Math.fround(( - ( + ( - Math.fround((((-(2**53) | 0) >> (( ~ x) | 0)) | 0))))))); }); testMathyFunction(mathy3, [-0x100000001, -0x080000001, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 2**53-2, 1, 1/0, 2**53+2, -0x100000000, 0x100000001, Number.MIN_VALUE, -1/0, 2**53, Number.MAX_SAFE_INTEGER, 0/0, 0, Math.PI, 0x07fffffff, 0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -0x0ffffffff, 0x100000000, -Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0, -(2**53)]); ");
/*fuzzSeed-159544250*/count=856; tryItOut("h1.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-159544250*/count=857; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+(0x1b07736f));\n    i1 = (i1);\n    (Float64ArrayView[4096]) = ((((+log(((-4503599627370497.0))))) / ((+abs(((d0)))))));\n    i1 = ((0xe891f34));\n    return (((imul((i1), ((+/*FFI*/ff(((~~((0xffffffff) ? (0.125) : (-3.094850098213451e+26)))))) < (-72057594037927940.0)))|0) / (((i1)) << (((((0xf8b967fa)) | ((0x7669a842))) != (((-0x8000000)) | ((0x771b1620))))+(/*FFI*/ff(((+(1.0/0.0))))|0)+(i1)))))|0;\n    {\n      i1 = (i1);\n    }\n    return (((Uint16ArrayView[2])))|0;\n  }\n  return f; })(this, {ff: (Math.imul(26, (this >>>=  '' )))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[null, undefined, null, undefined]); ");
/*fuzzSeed-159544250*/count=858; tryItOut("\"use strict\"; t1[14] = v2;");
/*fuzzSeed-159544250*/count=859; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2\\cN(.)+{274877906944,274877906944}/gm; var s = \"\\n\\u000e\\n\\u000e\\n\\n\\n\\n\\n\\u000e\\n\\u000e\\n\\u000e\\n\\u000e\\n\\u000e\\n\\u000e\\n\\u000e\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=860; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.cbrt(Math.atan(((x | Math.min(x, (mathy3(Math.fround((Number.MIN_SAFE_INTEGER && Number.MAX_SAFE_INTEGER)), ((x >> ( + ((y | 0) == (0x0ffffffff | 0)))) | 0)) >>> 0))) | 0))); }); testMathyFunction(mathy5, [2**53-2, -(2**53-2), -0x080000001, 1, -0x080000000, Math.PI, 0, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), 1.7976931348623157e308, 2**53, 0/0, 2**53+2, 0.000000000000001, -Number.MAX_VALUE, 0x080000000, 42, 0x100000000, -0x100000000, -0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0, Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, 0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=861; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(( ~ Math.fround(Math.max(((0x080000001 || (y >>> 0)) >>> 0), (Math.hypot((Math.log10(y) | 0), Math.abs(( + ( - ( + (((y >>> 0) - (-(2**53) >>> 0)) >>> 0)))))) >>> 0))))) !== (Math.sqrt(( + Math.asinh(( + Math.imul(( + 0x080000001), ( + Math.abs(y))))))) | 0)); }); testMathyFunction(mathy3, [-0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -0x07fffffff, -0, 0x100000000, -1/0, 0/0, -0x080000000, 2**53+2, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 0, 0x080000000, -0x100000000, -0x080000001, -0x100000001, 1, Math.PI, 0x080000001, 1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 2**53-2, 0.000000000000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=862; tryItOut("x ==  /x/ ;");
/*fuzzSeed-159544250*/count=863; tryItOut("s2 = this.s1.charAt(g0.v1);");
/*fuzzSeed-159544250*/count=864; tryItOut("mathy4 = (function(x, y) { return (Math.sinh(((( + (Math.sqrt(( + Math.max(0.000000000000001, (( + ( ~ Math.fround(x))) | 0)))) >>> 0)) === ( + Math.hypot(Math.acosh(Math.fround(Math.clz32(( + mathy1(y, y))))), x))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [0.1, objectEmulatingUndefined(), '0', ({toString:function(){return '0';}}), (new Boolean(false)), (function(){return 0;}), [0], '', (new Boolean(true)), ({valueOf:function(){return '0';}}), -0, null, true, [], (new Number(0)), '/0/', 0, NaN, (new Number(-0)), false, /0/, (new String('')), '\\0', ({valueOf:function(){return 0;}}), undefined, 1]); ");
/*fuzzSeed-159544250*/count=865; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.abs(( + Math.log2(( + (y ** (((x >>> 0) ? (Math.pow(0x100000001, y) >>> 0) : ((( + y) >>> 0) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy1, [-(2**53+2), -(2**53-2), 0x080000000, -1/0, 2**53+2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, 1, 0x080000001, 0x100000000, 0.000000000000001, 42, Number.MIN_VALUE, 0x0ffffffff, 0/0, 0x100000001, 0, 1/0, -0, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, 2**53, -(2**53), -0x100000001, 2**53-2]); ");
/*fuzzSeed-159544250*/count=866; tryItOut("\"use strict\"; ");
/*fuzzSeed-159544250*/count=867; tryItOut("a2 + o0;");
/*fuzzSeed-159544250*/count=868; tryItOut("nekjob, c, y, bywzwl, jdcdpb, x, z, fwnqsu, ohybbu;a1 = Array.prototype.map.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((Int32ArrayView[((0xf92b6db7)-(0x4c5ceb8e)+(((((0x7a8d05af)))>>>((0xd6c0f07d))) == (0xa523ce64))) >> 2])))|0;\n    d0 = (Infinity);\n    d0 = (d0);\n    d0 = (+(~((0x96b56e42) % (((((-33554431.0) + (274877906944.0)) != (-33.0))-(0x50667742))>>>((0xcb69e54d) % (0xf2b8b763))))));\n    return ((((((i2)+(0xdb98de82)-((abs((0x7fffffff))|0) != ( \"\" )))>>>((-0x8000000)+((((0xfacf85ac)) << ((-0x50e3f7c))) == (~~(d1))))) > (((0xfc27115b))>>>((0xfde3c32b)+(((1099511627777.0) < (-8193.0)) ? (1) : (i2)))))+(i2)))|0;\n  }\n  return f; }), h1, t0]);");
/*fuzzSeed-159544250*/count=869; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( - (( + (Math.fround((( - -Number.MAX_SAFE_INTEGER) === ( + Math.imul(y, y)))) < ( + (( ! (x | 0)) | 0)))) * ( + Math.sqrt((((y ? Math.expm1(( + y)) : ( + -0x07fffffff)) | 0) | 0))))); }); ");
/*fuzzSeed-159544250*/count=870; tryItOut("\"use strict\"; /*oLoop*/for (let cqduud = 0, ((yield (NaN) = c)); cqduud < 146; ++cqduud) { v0.__proto__ = g0; } ");
/*fuzzSeed-159544250*/count=871; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 562949953421312.0;\n    return (((!(0xc15b2952))))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var wfxqeq = false; ((yield (function ([y]) { })()))(); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x080000001, Number.MIN_VALUE, -0x100000001, 2**53, -0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 0x100000000, 0x07fffffff, 0.000000000000001, -0, -Number.MAX_VALUE, -(2**53), -0x0ffffffff, Math.PI, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, -0x080000000, -(2**53+2), 0x080000001, -(2**53-2), 1.7976931348623157e308, 0x100000001, 0/0, 1, 0x0ffffffff, 42, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-159544250*/count=872; tryItOut("testMathyFunction(mathy3, [0x100000001, 0/0, 2**53-2, -(2**53-2), Math.PI, 0x080000001, 1.7976931348623157e308, 0x0ffffffff, 2**53+2, -0, 1/0, -0x100000001, 0, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, Number.MIN_VALUE, -0x0ffffffff, 0x100000000, -0x080000001, -0x07fffffff, -Number.MAX_VALUE, -(2**53), -0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -1/0, 0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=873; tryItOut("\"use strict\"; /*RXUB*/var r = g0.r0; var s = s0; print(s.match(r)); /*oLoop*/for (let ssclxi = 0; ssclxi < 0; ++ssclxi) { a1 = new Array; } ");
/*fuzzSeed-159544250*/count=874; tryItOut("\"use strict\"; throw x;throw w;");
/*fuzzSeed-159544250*/count=875; tryItOut("/*bLoop*/for (blumzk = 0, (4277); ((0.714.watch(\"x\", ({/*TOODEEP*/})))) && blumzk < 30; 21.throw( /x/ ), ++blumzk) { if (blumzk % 104 == 73) { print(x != \nnew RegExp(\"\\\\1{1}\", \"ym\")); } else { print(x); }  } ");
/*fuzzSeed-159544250*/count=876; tryItOut("this.o0.i2.send(g1);");
/*fuzzSeed-159544250*/count=877; tryItOut("testMathyFunction(mathy3, /*MARR*/[2**53+2, x,  \"\" , new Number(1), x, 2**53+2, 2**53+2, 2**53+2]); ");
/*fuzzSeed-159544250*/count=878; tryItOut("v1 = (i2 instanceof h2);");
/*fuzzSeed-159544250*/count=879; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(((Math.max(( + mathy0((( + Math.asin(( + x))) | 0), Math.fround((Math.acos((-Number.MAX_VALUE | 0)) | 0)))), (Math.clz32(-Number.MIN_SAFE_INTEGER) >>> 0)) > (Math.atanh(Math.min((mathy2(x, x) | 0), (x | 0))) | 0)) <= (( ! Math.expm1(Math.fround(x))) >>> Math.imul(Math.PI, ( + y))))); }); testMathyFunction(mathy3, [-0x100000001, 2**53-2, 0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), 0/0, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, -0x0ffffffff, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, 42, -1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53+2, 0x07fffffff, -(2**53), -0x07fffffff, 2**53, 1/0, -0, 1, 0, 1.7976931348623157e308, -0x080000001]); ");
/*fuzzSeed-159544250*/count=880; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(t2, this.s1);var c =  /* Comment */[b = Proxy.createFunction(({/*TOODEEP*/})(134217728), function shapeyConstructor(dcqfcy){\"use strict\"; this[new String(\"13\")] = \"\\uB60C\";this[new String(\"13\")] = function ([y]) { };delete this[\"0\"];this[\"0\"] = \"\\u2432\";Object.defineProperty(this, \"0\", ({value: b, writable: true, enumerable: \"\\uBA89\"}));return this; })];");
/*fuzzSeed-159544250*/count=881; tryItOut("if(false) { if (((( + ((((x >>> 0) >= (x >>> 0)) >>> 0) || (Math.fround(Math.sqrt(( + Math.log(x)))) & (( + Math.atan2(( + x), ( + (Math.pow(Math.fround(x), (x | 0)) | 0)))) | 0)))) + Math.fround(((( ! x) >>> 0) != x))))) {/* no regression tests found */h2.enumerate = (function() { for (var j=0;j<32;++j) { f1(j%2==0); } }); }} else {this.v0 = evaluate(\"function f1(v2) \\\"use asm\\\";   var atan2 = stdlib.Math.atan2;\\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    (Uint16ArrayView[((((((function(y) { print(x); }).apply)(false, ((x) =  \\\"\\\" )))))) >> 1]) = (((((((!(0x28a3e9c2)))>>>((i2)*0x55db2)) >= (((0xffffffff))>>>((0xffffffff)))))>>>((Uint16ArrayView[((0xffb9170b)+(0x705279d7)) >> 1]))) / (((0x8b47b76e))>>>((i2))));\\n    {\\n      {\\n        {\\n          d1 = (((+atan2((((Uint16ArrayView[((-0x8000000)-(0xabbdf833)-(0x2bae284c)) >> 1]))), ((d1))))) - ((d0)));\\n        }\\n      }\\n    }\\n    {\\n      return +((3.8685626227668134e+25));\\n    }\\n    d0 = (+(((((i2) ? (0xfb40c0e9) : ((0x414a5a9b))) ? (0x8c56b76b) : (0xc51eae1a)))>>>(-0xaab9c*(((i2) ? (+(0xf04ff9bb)) : (((17.0)) % ((-8193.0)))) >= (d1)))));\\n    {\\n      d1 = (-70368744177665.0);\\n    }\\n    return +((+(1.0/0.0)));\\n  }\\n  return f;\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: ({x: x}) }));t0 = new Float64Array(b1, 136, \"\\u8E58\"); }");
/*fuzzSeed-159544250*/count=882; tryItOut("mathy3 = (function(x, y) { return ( + (( + Math.cosh(( + Math.sinh(( + ( + ( ~ (x | 0)))))))) <= ( + Math.atan(Math.fround(Math.asinh((Math.imul(x, (Math.pow((y | 0), (x | 0)) | 0)) | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[function(){}, function(){},  /x/g , function(){},  /x/g , new Number(1), function(){}, new Number(1), function(){}, new Number(1), new Number(1),  /x/g ,  /x/g , function(){},  /x/g , function(){}, new Number(1), new Number(1), function(){}, new Number(1), new Number(1),  /x/g , function(){}, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1),  /x/g ,  /x/g , function(){}, function(){}, new Number(1),  /x/g , function(){}, function(){},  /x/g , new Number(1), new Number(1), new Number(1), new Number(1), function(){}, new Number(1), function(){}, function(){}, new Number(1), function(){}, function(){}, function(){}, new Number(1), new Number(1),  /x/g , new Number(1),  /x/g , new Number(1), new Number(1), function(){}, new Number(1), function(){},  /x/g , function(){}, function(){}, new Number(1),  /x/g ,  /x/g ,  /x/g ]); ");
/*fuzzSeed-159544250*/count=883; tryItOut("\"use strict\"; /*MXX3*/g1.Number = this.g1.Number;");
/*fuzzSeed-159544250*/count=884; tryItOut("/*oLoop*/for (ujliml = 0; ujliml < 78; x, ++ujliml) { /*RXUB*/var r = new RegExp(\"(\\\\w\\\\1{0,33554431}{2})[^]\", \"i\"); var s = \"\\u0096\\n\\n\\u0096\\n\\n\\u0096\\n\\n\\u0096\\n\\n\\n\"; print(uneval(r.exec(s)));  } ");
/*fuzzSeed-159544250*/count=885; tryItOut("testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-159544250*/count=886; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+abs(((d1))));\n    return (((0x3e37dec7)*-0x6d95b))|0;\n    (Int16ArrayView[1]) = ((0x6779b235)-(!(0xfa5bedc7)));\n    d1 = (+(0x10b42cd8));\n    {\n      return (((((0xffffffff))>>>((0xd7fc40dc))) / (0x9a3306ce)))|0;\n    }\n    {\n      return ((-(-0x8000000)))|0;\n    }\n    d1 = (((d0)) / ((d1)));\n    d1 = (d0);\n    d0 = (d0);\n    d1 = (d0);\n    d0 = (d1);\n    switch ((~~(d1))) {\n      default:\n        d0 = (+(-1.0/0.0));\n    }\n    {\n      d0 = (d1);\n    }\n    d1 = (+sqrt(((-1.0009765625))));\n    d0 = (-((+((d0)))));\n    return (((/*FFI*/ff((((+(1.0/0.0)) + (((d0)) * ((d1))))), ((abs((((0xffffffff)+(0xe1508f5b)) << ((!(0xfc2aab9f))-(0xffffffff))))|0)), ((d0)), ((0x5d9076c3)))|0)+(!(0xd6bee084))))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: undefined, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: function ()\"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (((562949953421313.0)) * ((Float32ArrayView[1])));\n    }\n    d1 = (+(0x0));\n    i0 = (0xf9f6c2d9);\n    i0 = (0xff227285);\n    d1 = (2.3611832414348226e+21);\n    d1 = (4194303.0);\n    i0 = (0x700fcbfa);\n    d1 = (d1);\n    i0 = (i0);\n    {\n      {\n        switch ((((-0x8000000)) >> (((0x55924800) <= (0x7fffffff))+((0x3d3093f1))))) {\n          case -2:\n            {\n              (Uint8ArrayView[(((((!(!(0xfd99e463)))+(1)+(i0)) & (((((0x5bd89a32))>>>((0xfb8ab26c))))+(i0))))) >> 0]) = ((i0));\n            }\n          case -3:\n            d1 = (Infinity);\n            break;\n          case -1:\n            i0 = (1);\n          case 1:\n            {\n              i0 = (0xffffffff);\n            }\n            break;\n          case 0:\n            i0 = (i0);\n            break;\n          case -1:\n            i0 = (0x79e29b2d);\n            break;\n          case -3:\n            {\n              {\n                d1 = (-17.0);\n              }\n            }\n            break;\n          case -2:\n            d1 = (((Float32ArrayView[(((0x0) <= (((0xfb1474c1))>>>(((0x18aa931f))-((0x6272475e) ? (0xd1a2a89b) : (0xffffffff)))))) >> 2])) / ((+abs(((3.777893186295716e+22))))));\n            break;\n        }\n      }\n    }\n    (Float32ArrayView[4096]) = ((Float64ArrayView[((~~(+((((-3.777893186295716e+22) < (-1.001953125))) << ((Int8ArrayView[0]))))) % (abs((((!(i0))-(0x48a71aaf)) << (0x186b6*(i0))))|0)) >> 3]));\n    d1 = (((Float32ArrayView[((0xffffffff) % (0xdecca921)) >> 2])) * ((+(abs((0x47601370))|0))));\n    return +((((134217727.0)) / ((+((d1))))));\n  }\n  return f;/*RXUE*//\\b/gm.exec(\"\\u6cca\"), }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, -(2**53-2), 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER, -1/0, 42, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -0, 0x100000000, -0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), 0x080000001, 0, 0x080000000, 2**53+2, -(2**53+2), 1, 0x100000001, Math.PI, -0x080000001, 0x0ffffffff, -0x0ffffffff, 2**53, -0x100000001]); ");
/*fuzzSeed-159544250*/count=887; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 3.022314549036573e+23;\n    var d3 = -9007199254740992.0;\n    return +((144115188075855870.0));\n  }\n  return f; })(this, {ff: Object.defineProperty}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x0ffffffff, 0x080000001, 42, Math.PI, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, -1/0, 0x100000000, 1/0, 1, 0/0, -0x07fffffff, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0, 0, 1.7976931348623157e308, 2**53+2, 2**53, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -0x100000001, -(2**53), Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=888; tryItOut("\"use strict\"; var vegbnt = new SharedArrayBuffer(8); var vegbnt_0 = new Uint8Array(vegbnt); var vegbnt_1 = new Uint32Array(vegbnt); var vegbnt_2 = new Uint8ClampedArray(vegbnt); vegbnt_2[0] = -25; var vegbnt_3 = new Uint8ClampedArray(vegbnt); vegbnt_3[0] = -21; var vegbnt_4 = new Int32Array(vegbnt); var vegbnt_5 = new Float64Array(vegbnt); print(vegbnt_5[0]); vegbnt_5[0] = 22; a2 + '';vegbnt_2[2]print(new RegExp(\"(?=[^])\", \"\"));m1.get(v0);v0 + '';a1.forEach((function() { try { f0 = m2.get(m0); } catch(e0) { } try { t1 + ''; } catch(e1) { } v2 = evalcx(\"e1.delete(m2);\", o2.g0); return s2; }), p2,  '' , a1);this;neuter(b2, \"change-data\");g0.s1 += this.s0;Array.prototype.pop.call(a2);/*MXX2*/g0.Object.getOwnPropertyDescriptor = g0.m0;");
/*fuzzSeed-159544250*/count=889; tryItOut("\"use strict\"; /*iii*/a0 = Array.prototype.slice.apply(a2, [NaN, 1, a2, g0, h1, t2]);/*hhh*/function fltotd(...c){print(x);}");
/*fuzzSeed-159544250*/count=890; tryItOut("v2 = (m1 instanceof i1);");
/*fuzzSeed-159544250*/count=891; tryItOut("testMathyFunction(mathy1, [-Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -1/0, 0x080000000, -(2**53-2), 1, 2**53+2, 1.7976931348623157e308, 0, 0/0, 0x0ffffffff, 42, 0x07fffffff, 2**53-2, -(2**53), Math.PI, -(2**53+2), 0x100000001, -0x080000001, -0x100000001, -0, 0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 1/0, -0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=892; tryItOut("o2.b0 = t0[16];");
/*fuzzSeed-159544250*/count=893; tryItOut("mathy4 = (function(x, y) { return ( + Math.pow(( + ( ~ Math.min((( ~ Math.fround(Math.fround(mathy0(Math.fround(Math.fround(Math.acos(y))), mathy3((x ? y : (y >>> 0)), 0x0ffffffff))))) >>> 0), mathy3((Math.trunc(y) | 0), (((( + y) | 0) >= (-0x100000001 | 0)) | 0))))), (Math.max(Math.fround(mathy1(y, Math.fround((Math.imul((( - x) | 0), ((x & (((( + Math.acosh(y)) >>> 0) ? (x >>> 0) : (Math.max(0x100000001, y) >>> 0)) | 0)) | 0)) | 0)))), (Math.fround((Math.fround(Math.fround(Math.max(Math.fround(Math.max(mathy0((x >>> 0), (y >>> 0)), ( + y))), Math.fround(mathy1(Math.sinh((x | 0)), y))))) * Math.fround(( + Math.asin(( + ( + Math.atan2(( + x), ( + (((x & y) <= (y >>> 0)) >>> 0)))))))))) | 0)) >>> 0))); }); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), (new Number(-0)), (new String('')), '', '0', ({valueOf:function(){return 0;}}), 0, objectEmulatingUndefined(), null, (new Boolean(true)), (new Boolean(false)), (function(){return 0;}), undefined, 0.1, '/0/', [0], true, '\\0', (new Number(0)), 1, false, -0, /0/, ({toString:function(){return '0';}}), [], NaN]); ");
/*fuzzSeed-159544250*/count=894; tryItOut("h1.keys = (function() { for (var j=0;j<4;++j) { f1(j%2==0); } });");
/*fuzzSeed-159544250*/count=895; tryItOut("\"use strict\"; print(x);v0 = a0.length;");
/*fuzzSeed-159544250*/count=896; tryItOut("Array.prototype.sort.apply(a2, [(function(j) { if (j) { try { let t2 = new Float32Array(b1, 96, 4); } catch(e0) { } try { o0.e1.__proto__ = t2; } catch(e1) { } o2.g0.m2.get(o0); } else { try { t0 = new Uint8ClampedArray(t2); } catch(e0) { } Object.prototype.watch.call(h1, \"max\", (function mcc_() { var vgdwqt = 0; return function() { ++vgdwqt; if (/*ICCD*/vgdwqt % 11 == 5) { dumpln('hit!'); try { for (var v of h0) { try { o0.v1 = evalcx(\"yield y = x;\", g2); } catch(e0) { } h1.has = Map.prototype.set.bind(g0); } } catch(e0) { } v2 = g2.runOffThreadScript(); } else { dumpln('miss!'); this.m1.set(new Uint16Array( /x/g ), v1); } };})()); } }), i0, a2, s2]);");
/*fuzzSeed-159544250*/count=897; tryItOut("(function(id) { return id });");
/*fuzzSeed-159544250*/count=898; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.imul((Math.atan((( + (((x && (y | 0)) | 0) & ( + ( + mathy0(( + (Math.log2(x) >>> 0)), Math.fround(( ~ Math.cosh(y)))))))) >>> 0)) >>> 0), Math.asin(Math.round(Math.hypot(Math.fround(Math.max(y, Math.max(Math.pow(x, y), Math.pow(x, y)))), y)))); }); testMathyFunction(mathy1, [/0/, null, 0.1, ({valueOf:function(){return 0;}}), [], NaN, (new Boolean(false)), 1, ({valueOf:function(){return '0';}}), false, -0, [0], (new String('')), (new Number(-0)), objectEmulatingUndefined(), (function(){return 0;}), true, '\\0', '0', '', 0, undefined, (new Boolean(true)), (new Number(0)), ({toString:function(){return '0';}}), '/0/']); ");
/*fuzzSeed-159544250*/count=899; tryItOut("print(/(?:^)?/m);");
/*fuzzSeed-159544250*/count=900; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=901; tryItOut("");
/*fuzzSeed-159544250*/count=902; tryItOut("testMathyFunction(mathy2, [0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 2**53-2, 1.7976931348623157e308, -(2**53+2), 0.000000000000001, -0, -0x080000001, 0x100000000, 42, -Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, Number.MIN_VALUE, Math.PI, 0/0, 0x07fffffff, 0x0ffffffff, 1, -0x0ffffffff, -0x100000000, -1/0, 1/0, -Number.MIN_VALUE, -0x100000001, 0, 2**53, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-159544250*/count=903; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ~ Math.max(Math.expm1(( + y)), Math.fround(Math.fround(Math.hypot((x >>> 0), (Math.trunc((x >>> 0)) >>> 0)))))) | 0); }); testMathyFunction(mathy3, [0, '', [], ({toString:function(){return '0';}}), [0], '\\0', '/0/', null, (new Boolean(true)), /0/, false, '0', (new String('')), (new Boolean(false)), undefined, -0, ({valueOf:function(){return 0;}}), 0.1, 1, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Number(0)), NaN, true, (function(){return 0;}), (new Number(-0))]); ");
/*fuzzSeed-159544250*/count=904; tryItOut("\"use strict\"; v2 = (o2 instanceof m2);");
/*fuzzSeed-159544250*/count=905; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + ( + ( ~ ((( ! (Math.cosh((x | 0)) | 0)) >>> 0) >= (x >>> 0))))) ? ( + (Math.atan2(((Math.sign((( + Math.hypot(( + x), ( + y))) | 0)) | 0) >>> y), Math.fround(Math.round(y))) ? Math.atan(Math.pow((( - 0.000000000000001) | 0), y)) : Math.fround(( ! Math.fround((Math.atan2((Math.acos(x) | 0), (x | 0)) | 0)))))) : (( + Math.log(( + Math.cbrt(( ! Math.fround(Math.pow(x, ( + (x - y))))))))) >>> 0))); }); ");
/*fuzzSeed-159544250*/count=906; tryItOut("\"use asm\"; e2 = Proxy.create(h0, f0);");
/*fuzzSeed-159544250*/count=907; tryItOut("/*RXUB*/var r = r2; var s = s1; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=908; tryItOut("\"use strict\"; e0 = new Set;\nfor (var v of o0) { try { g0.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e0) { } try { v2 = g2.runOffThreadScript(); } catch(e1) { } v0 = null; }\n");
/*fuzzSeed-159544250*/count=909; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -35184372088831.0;\n    return +( '' );\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [42, 0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, -(2**53), -1/0, 0/0, 0x100000001, -(2**53+2), -(2**53-2), -0x100000001, 0.000000000000001, 0x100000000, 0x0ffffffff, -0x080000001, Math.PI, 2**53-2, 1, -0, 1.7976931348623157e308, 2**53+2, -Number.MAX_VALUE, 0x080000001, -0x07fffffff, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=910; tryItOut("s2 += g1.s2;");
/*fuzzSeed-159544250*/count=911; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=912; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 262145.0;\n    var d3 = -4294967297.0;\n    var i4 = 0;\n    {\n      {\n        (Float32ArrayView[1]) = ((4398046511103.0));\n      }\n    }\n    return (((i1)))|0;\n    {\n(x = \"\\u3323\");    }\n    return (((!(!((-0x8000000) ? (i0) : ((0x42b44a83)))))+((~((((0x4b2f5*(0xf95366fd))>>>((0xff03a8f8)-(0xffffffff))))-((0xb89012eb) <= (((0xa48f570))>>>((0x1f7c9f5f))))-(/*FFI*/ff(((+(0.0/0.0))))|0))) >= (((Uint16ArrayView[((((makeFinalizeObserver('nursery'))))*-0x71f15) >> 1]))|0))))|0;\n  }\n  return f; })(this, {ff: mathy4}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -(2**53), 0x0ffffffff, 1.7976931348623157e308, 1, 42, 0.000000000000001, -0x100000000, 0, 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, -0x080000000, Math.PI, 0x080000001, 1/0, -0x080000001, 0x100000001, -0, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, -(2**53-2), -0x07fffffff, 0/0]); ");
/*fuzzSeed-159544250*/count=913; tryItOut("\"use strict\"; Array.prototype.splice.call(a0, NaN, 11, a2);");
/*fuzzSeed-159544250*/count=914; tryItOut("\"use strict\"; e2.delete(b0);");
/*fuzzSeed-159544250*/count=915; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.clz32(Math.fround(Math.clz32(Math.round(Math.log2(Math.fround(( - ( + ( - x)))))))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, 1, -0x100000001, 0.000000000000001, -1/0, -(2**53+2), -0x07fffffff, 0, -(2**53), 2**53, 0x080000000, 0x080000001, 2**53-2, Math.PI, -0x080000000, 42, 0x100000000, -0, 0/0, 2**53+2, -(2**53-2), -0x0ffffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=916; tryItOut("\"use strict\"; switch(x = window) { default: break; case 3: g1.s2 + ''; }");
/*fuzzSeed-159544250*/count=917; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-159544250*/count=918; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-159544250*/count=919; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[(1/0), (1/0),  /x/ ,  /x/ , null, (1/0), (1/0), (1/0),  /x/ , (1/0), null,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , null,  /x/ , (1/0),  /x/ , null, (1/0),  /x/ ,  /x/ , (1/0),  /x/ ,  /x/ , (1/0),  /x/ , (1/0), (1/0),  /x/ ,  /x/ , (1/0), null, (1/0), null, (1/0), null, null, null, null,  /x/ , null,  /x/ ,  /x/ ,  /x/ , null,  /x/ ,  /x/ , (1/0), (1/0), null,  /x/ , (1/0), null, (1/0), (1/0), null, null,  /x/ ,  /x/ , (1/0),  /x/ ,  /x/ , null,  /x/ ,  /x/ , (1/0), (1/0), null, (1/0), (1/0),  /x/ ,  /x/ ,  /x/ , null, (1/0), (1/0), (1/0),  /x/ , null,  /x/ ,  /x/ , (1/0),  /x/ ,  /x/ , (1/0), (1/0),  /x/ , null, null, null,  /x/ , (1/0),  /x/ , (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), null, (1/0),  /x/ , null, (1/0),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , null, (1/0), null, null, (1/0),  /x/ , (1/0), (1/0), null, (1/0),  /x/ , (1/0), (1/0), null, (1/0), null, null, (1/0)]) { null; }");
/*fuzzSeed-159544250*/count=920; tryItOut("\"use strict\"; \"use asm\"; /*ADP-2*/Object.defineProperty(g1.a1, 9, { configurable: new RegExp(\"\\\\B\", \"y\") , (x * function(q) { return q; }( /x/ )\n), enumerable: false, get: (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 17.0;\n    var d5 = -68719476737.0;\n    var i6 = 0;\n    var d7 = 4611686018427388000.0;\n    var i8 = 0;\n    var i9 = 0;\n    return (((i3)))|0;\n  }\n  return f; }), set: (function() { for (var j=0;j<142;++j) { f1(j%2==0); } }) });");
/*fuzzSeed-159544250*/count=921; tryItOut("print(-8.unwatch(\"0\"));");
/*fuzzSeed-159544250*/count=922; tryItOut("mathy5 = (function(x, y) { return Math.tanh(Math.fround(( + (((( + -1/0) === x) & Math.fround(Math.min(Math.fround((y <= x)), Math.fround(( + Math.atan2(( + mathy3((0x0ffffffff | 0), (x | 0))), ( + y))))))) ? ((( ~ ( + (y != ((0x100000001 === (x >>> 0)) >>> 0)))) | 0) - (mathy4(Math.asin(x), (Math.hypot((y <= y), x) | 0)) | 0)) : ( ! ( - ( + ( + ( + Math.min(y, x)))))))))); }); testMathyFunction(mathy5, [-1/0, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x100000001, 1.7976931348623157e308, Math.PI, 0, 0x100000000, 0.000000000000001, 0x080000000, -(2**53+2), 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), -(2**53-2), -0x080000001, 0x07fffffff, 0x080000001, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 42]); ");
/*fuzzSeed-159544250*/count=923; tryItOut("this.f1 + '';w = ('fafafa'.replace(/a/g, new Function));");
/*fuzzSeed-159544250*/count=924; tryItOut("mathy2 = (function(x, y) { return Math.min(( + Math.expm1(( + ( ~ (Math.fround(y) / Math.fround(x)))))), (( + Math.fround(( ! (( - ( + (0x100000000 ? -0x080000000 : (((y >>> 0) / (y >>> 0)) >>> 0)))) | 0)))) << (mathy1(((Math.fround((Math.fround((x >> y)) ^ Math.fround(Number.MIN_VALUE))) - ( + ( ! 1.7976931348623157e308))) >>> 0), ( + ( ~ Math.fround(x)))) >>> 0))); }); testMathyFunction(mathy2, [-(2**53+2), 0, 0.000000000000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x080000001, Number.MAX_VALUE, 2**53, 42, -0x100000000, -0x100000001, 1, -(2**53), -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, 0x080000000, Number.MIN_VALUE, 0x100000001, -0x07fffffff, 1/0, -Number.MAX_VALUE, 0/0, -(2**53-2), -Number.MIN_VALUE, -0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-159544250*/count=925; tryItOut("var t1 = new Uint32Array(a0);");
/*fuzzSeed-159544250*/count=926; tryItOut("mathy0 = (function(x, y) { return ( + Math.pow(( - (Math.tan(x) | 0)), ((Math.fround((x ? Math.fround((Math.log((y | 0)) | 0)) : y)) ? y : x) ? y : Math.max((y | 0), 0/0)))); }); ");
/*fuzzSeed-159544250*/count=927; tryItOut(";");
/*fuzzSeed-159544250*/count=928; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x080000001, 0x0ffffffff, -0, 1/0, Math.PI, 0, 0/0, -0x080000000, 0.000000000000001, 42, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), -0x100000000, 2**53+2, -(2**53+2), 0x100000000, 0x07fffffff, 2**53-2, -1/0, 0x100000001, -(2**53), -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001]); ");
/*fuzzSeed-159544250*/count=929; tryItOut("/*infloop*/ for (let e of x) {((new Int32Array((x) =  \"\" , () =>  { \"use strict\"; yield window } ))); }v2 = evaluate(\"function f0(s2) \\\"use asm\\\";   function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    var d3 = -18446744073709552000.0;\\n    return +((d0));\\n  }\\n  return f;\", ({ global: g1.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval:  /x/g , sourceIsLazy: (NaN) = new RegExp(\"(?!(?!(?!.*?))*?|\\\\x28|(?:.)\\\\cR+?{0}){3}\", \"gyi\") **= \"\\uBF01\", catchTermination: false }));");
/*fuzzSeed-159544250*/count=930; tryItOut("g1.g0.t2[14] = Object.defineProperty(x, \"0\", ({}));");
/*fuzzSeed-159544250*/count=931; tryItOut("a1.forEach((function() { try { (void schedulegc(g0)); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(g1.a1, 19, ({value: /*wrap2*/(function(){ var ubuijs = -15; var afvvyw = (NaN, x) =>  { yield; } ; return afvvyw;})()(), enumerable: false})); } catch(e1) { } a0.unshift(i2, s0, v1, o0, h1); return e1; }), this.b2, a0, h2, let (x = new RegExp(\"(?=[^]|.(?:\\\\S|[^\\\\W\\\\n-\\\\xfd-\\u00d9\\\\cZ])((?!.)?)(?!\\\\B)|((\\u00be)))\", \"y\")) new (objectEmulatingUndefined)(-17, -1));");
/*fuzzSeed-159544250*/count=932; tryItOut("\"use asm\"; ");
/*fuzzSeed-159544250*/count=933; tryItOut("\"use strict\"; /*infloop*/\u000c for (let arguments.callee.caller.caller.arguments of w) {Object.defineProperty(this, \"v0\", { configurable: true, enumerable: (x % 31 != 3),  get: function() { a2.shift(); return g1.eval(\"Object.defineProperty(this, \\\"this.s1\\\", { configurable: false, enumerable: false,  get: function() { Object.defineProperty(this, \\\"v2\\\", { configurable: true, enumerable:  '' ,  get: function() {  return null; } }); return s2.charAt(v1); } });\"); } }); }\nv1 = false;\n");
/*fuzzSeed-159544250*/count=934; tryItOut("/*tLoop*/for (let x of /*MARR*/[this, this]) { ; }");
/*fuzzSeed-159544250*/count=935; tryItOut("L: for (var e of (4277)) {/* no regression tests found */ }");
/*fuzzSeed-159544250*/count=936; tryItOut("mathy0 = (function(x, y) { return (Math.atan2((Math.sin(( - Math.abs(x))) >>> 0), (Math.atan2(( - x), ( - x)) >>> 0)) ? Math.fround(( ~ Math.fround(Math.max((( - (( + x) | 0)) | 0), (0.000000000000001 * ( + Math.asinh(Math.imul(Math.fround(x), x)))))))) : ( + ((y == Math.ceil(y)) << Math.fround(Math.cosh(Math.fround(( + x))))))); }); testMathyFunction(mathy0, [0x080000000, 0x0ffffffff, 2**53-2, 42, 0, 1/0, -Number.MIN_VALUE, 1, -1/0, -(2**53+2), Math.PI, Number.MIN_VALUE, 0/0, 0x100000001, 0x100000000, -0x080000001, 2**53+2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -0, 0.000000000000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, 1.7976931348623157e308, -0x100000000, Number.MAX_VALUE, -0x07fffffff, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=937; tryItOut("mathy0 = (function(x, y) { return ( - Math.round(Math.pow((y | 0), (Math.sign(( + x)) | 0)))); }); ");
/*fuzzSeed-159544250*/count=938; tryItOut("\"use strict\"; g2 = this;");
/*fuzzSeed-159544250*/count=939; tryItOut("for(\u000cx = ((function sum_slicing(hhwrex) { ; return hhwrex.length == 0 ? 0 : hhwrex[0] + sum_slicing(hhwrex.slice(1)); })(/*MARR*/[true, (void 0), new Boolean(true), true, true, true])) in [] = (uneval( /x/ ))) print(v1);");
/*fuzzSeed-159544250*/count=940; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.hypot(( + Math.min(mathy0((mathy4((2**53 % 2**53-2), ((Math.atan2((Math.fround(-(2**53+2)) >>> 0), Math.fround(( + ( ! ( + y))))) >>> 0) >>> 0)) >>> 0), (((x >>> 0) <= y) >>> 0)), Math.sin(( + Math.hypot((Math.sinh((((x | 0) == (x | 0)) | 0)) >>> 0), (mathy0((y >>> 0), (( + Math.imul(( + y), ( + y))) >>> 0)) >>> 0)))))), ( + (mathy4(Math.pow((Math.log(x) | 0), (Math.pow(Math.pow((y >>> 0), x), (((Math.fround(mathy2(2**53+2, ( + y))) >>> 0) ? (y >>> 0) : ((Math.acosh(( + Number.MIN_SAFE_INTEGER)) | 0) >>> 0)) >>> 0)) | 0)), (((Math.fround(2**53+2) / Math.fround(2**53)) % (Math.pow(y, ( + ( - Math.pow(x, Number.MAX_SAFE_INTEGER)))) , x)) | 0)) >>> 0))) | 0); }); testMathyFunction(mathy5, [-1/0, Number.MIN_VALUE, -Number.MIN_VALUE, 0.000000000000001, 2**53-2, Number.MAX_VALUE, -(2**53-2), 0x100000001, 2**53+2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, Math.PI, -0x080000001, -Number.MAX_VALUE, 0, 0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 1/0, 0x100000000, 1, -0, Number.MIN_SAFE_INTEGER, -0x100000000, 42, -0x0ffffffff, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=941; tryItOut("var ((4277))(0x2D413CCC).__proto__ = Math.log(NaN = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: [-29], iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })((Math.cbrt((4277)))), this ? (undefined.unwatch(\"1\")).toTimeString(Math.log(-9), window) : /*FARR*/[this, ].map(Array.prototype.pop, undefined), /*wrap3*/(function(){ var pqyvlf = x; (q => q)(); }))), x = let (e, w =  /x/ , fkdgmz, x, b = (4277), eval) (x.valueOf(\"number\")), x = (Object.defineProperty(x, \"wrappedJSObject\", ({set: /^/g, configurable: false})) ? x :  /x/ ), \u3056, xdxojr, a = x-=\"\\u8E0C\", \u3056, x = (4277).__defineGetter__(\"\\u3056\", new RegExp(\"\\\\2|\\\\b(\\\\v*)[^\\u0014-\\u0745\\\\x2A\\\\u0036-\\u6176\\\\B-\\\\uC599]*\", \"yim\")), x = x, c;g1.t0.toString = (function(j) { if (j) { try { /*ADP-1*/Object.defineProperty(a0, 19, ({get: Math.imul, configurable: (x % 5 == 3)})); } catch(e0) { } try { /*RXUB*/var r = r2; var s = s2; print(s.split(r)); print(r.lastIndex);  } catch(e1) { } i0 = e0.values; } else { try { m0.set((x <<= NaN), g0); } catch(e0) { } Array.prototype.shift.call(this.a2, m0); } });");
/*fuzzSeed-159544250*/count=942; tryItOut("var lwnfax;[z1,,];");
/*fuzzSeed-159544250*/count=943; tryItOut("v1 = true;");
/*fuzzSeed-159544250*/count=944; tryItOut("\"use strict\"; { void 0; deterministicgc(true); } Array.prototype.sort.call(a0, (function() { try { m2.delete(e1); } catch(e0) { } a1.toString = f0; throw o0.g1.i1; }), a2, x,  /x/g );");
/*fuzzSeed-159544250*/count=945; tryItOut("h0.getPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 3.022314549036573e+23;\n    return ((((~((1)-(0x16cac5e))))))|0;\n  }\n  return f; });");
/*fuzzSeed-159544250*/count=946; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=947; tryItOut("mathy3 = (function(x, y) { return (Math.fround((Math.fround(Math.atan((1/0 | 0))) + Math.fround(Math.atan2((Math.fround(Math.acos(Math.sinh(Math.fround(( + Math.log((0x100000000 | 0))))))) ? Math.fround(Math.tan(Math.fround(( ! (Number.MAX_SAFE_INTEGER | 0))))) : mathy2(y, x)), (mathy1((mathy0((Math.asinh(x) >>> 0), x) >>> 0), ((Math.sin((y >>> 0)) >>> 0) >>> 0)) >>> 0))))) || (( + mathy2(x, mathy0(mathy1(0x100000000, (x >>> 0)), y))) | 0)); }); testMathyFunction(mathy3, [0x080000001, 0, Number.MAX_SAFE_INTEGER, 1/0, 1, 0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -1/0, -(2**53), Number.MAX_VALUE, 0.000000000000001, -0x080000000, 2**53-2, -0x07fffffff, -0, 0x100000001, 2**53+2, -(2**53-2), Math.PI, 2**53, -0x080000001, 0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -Number.MIN_VALUE, 42]); ");
/*fuzzSeed-159544250*/count=948; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a0, []);");
/*fuzzSeed-159544250*/count=949; tryItOut("v2 = r2.constructor;");
/*fuzzSeed-159544250*/count=950; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0, -0x100000000, -(2**53), 0x100000001, -0x07fffffff, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, 0/0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), 1, 2**53+2, -0x080000000, -0, 0x0ffffffff, 0.000000000000001, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, 42, 2**53, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -1/0, Number.MAX_VALUE, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-159544250*/count=951; tryItOut("\"use strict\"; /*oLoop*/for (let yntelo = 0; yntelo < 51; ++yntelo) { /*MXX3*/g1.String.prototype.toLocaleLowerCase = g1.String.prototype.toLocaleLowerCase; } ");
/*fuzzSeed-159544250*/count=952; tryItOut("testMathyFunction(mathy4, [0x080000000, -(2**53+2), -0x0ffffffff, -0x080000001, -1/0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, 0, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, -(2**53), 1.7976931348623157e308, -0, 0.000000000000001, -0x07fffffff, 0x0ffffffff, 42, 0/0, 2**53, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, Number.MAX_VALUE, -0x080000000, -(2**53-2), 0x100000000, 0x080000001]); ");
/*fuzzSeed-159544250*/count=953; tryItOut("/*ADP-3*/Object.defineProperty(g2.a0, 5, { configurable: false, enumerable: (x % 107 == 104), writable: (x % 12 == 9), value: t2 });;");
/*fuzzSeed-159544250*/count=954; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.tan(( - ( ! (0x07fffffff | 0))))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -1/0, -Number.MAX_VALUE, -(2**53), -0, 0, -0x100000000, -0x080000001, -0x07fffffff, Math.PI, -0x0ffffffff, 0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 1/0, -(2**53+2), 0x0ffffffff, 0x080000001, 1, 2**53+2, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 42, 2**53-2, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=955; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.cos((( ~ (( + Math.min(( + (Math.fround(Math.expm1(Math.fround(-(2**53-2)))) ? ( + (0x100000001 && y)) : (( ~ x) >>> 0))), ( + Math.fround((Math.fround(Math.fround((Math.fround(y) + Math.fround(y)))) + Math.fround((Math.hypot(( + y), ( + Math.cbrt(Number.MIN_VALUE))) | 0))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, ['/0/', (new Number(0)), /0/, ({toString:function(){return '0';}}), false, ({valueOf:function(){return 0;}}), [], objectEmulatingUndefined(), '', 0, [0], -0, 1, (new Boolean(true)), ({valueOf:function(){return '0';}}), 0.1, '0', undefined, true, (new Number(-0)), (new String('')), null, NaN, '\\0', (function(){return 0;}), (new Boolean(false))]); ");
/*fuzzSeed-159544250*/count=956; tryItOut("var x = (({\u3056: window, eval:  /x/  })), x, a = (4277), e = \"\\u8A29\", d, jnftwa, oxabqy, x, bojthl;i1.toString = (function(j) { if (j) { v0 = null; } else { try { o1 + ''; } catch(e0) { } a2 = []; } });");
/*fuzzSeed-159544250*/count=957; tryItOut("mathy5 = (function(x, y) { return (Math.cosh(((x === y) >>> 0)) ^ (Math.cosh(x) << ( + mathy3(Math.fround((Math.fround(Math.atan(y)) && Math.fround(Math.min((x & Math.trunc(y)), -Number.MAX_VALUE)))), ( + (Math.fround(0x080000001) % (-0x080000000 !== y))))))); }); testMathyFunction(mathy5, [-0x07fffffff, -0x0ffffffff, 0/0, 0, -1/0, Number.MIN_VALUE, 0x100000000, 2**53, -0x100000000, 0x080000001, 0x0ffffffff, -0x080000001, Number.MAX_VALUE, -0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1/0, 0x100000001, -0x080000000, -0, 0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), -Number.MIN_VALUE, -Number.MAX_VALUE, 42, 1, -(2**53), 0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-159544250*/count=958; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - Math.sin(Math.log2(Math.min(( ~ (y != y)), (( ~ y) >>> (( - y) >>> 0)))))); }); testMathyFunction(mathy3, [2**53, 0, 0x080000000, -Number.MAX_VALUE, -0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, 42, 0x080000001, 0x100000001, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, -1/0, 0x100000000, -0x080000000, -0x100000001, Math.PI, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53+2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0x100000000, Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -0x080000001, 1/0, 2**53-2]); ");
/*fuzzSeed-159544250*/count=959; tryItOut("mathy5 = (function(x, y) { return Math.cos((( ~ (Math.exp(( + Number.MIN_VALUE)) | 0)) | 0)); }); ");
/*fuzzSeed-159544250*/count=960; tryItOut("\"use strict\"; /*vLoop*/for (let ztvhxb = 0, (e < a); ztvhxb < 116; ++ztvhxb) { c = ztvhxb; g0.offThreadCompileScript(\"yield  \\\"\\\" .watch(\\\"clz32\\\", Object.entries)\"); } ");
/*fuzzSeed-159544250*/count=961; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[new String('q'), intern(x).trunc((void options('strict'))), (void 0),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , ((uneval((/*UUV2*/(z.toLocaleLowerCase = z.indexOf))))), ((uneval((/*UUV2*/(z.toLocaleLowerCase = z.indexOf))))), (void 0), ((uneval((/*UUV2*/(z.toLocaleLowerCase = z.indexOf))))), (void 0), ((uneval((/*UUV2*/(z.toLocaleLowerCase = z.indexOf))))), intern(x).trunc((void options('strict'))), intern(x).trunc((void options('strict'))), intern(x).trunc((void options('strict'))), (void 0), new String('q'), intern(x).trunc((void options('strict'))),  \"\" ,  \"\" , new String('q'),  \"\" , intern(x).trunc((void options('strict'))),  \"\" ,  \"\" , new String('q'), intern(x).trunc((void options('strict'))),  \"\" , (void 0),  \"\" , intern(x).trunc((void options('strict'))), ((uneval((/*UUV2*/(z.toLocaleLowerCase = z.indexOf))))), intern(x).trunc((void options('strict'))),  \"\" , intern(x).trunc((void options('strict')))]) { with(undefined){a1.valueOf = (function() { try { v1 = Array.prototype.some.call(this.a1, (function(j) { if (j) { s2 += 'x'; } else { try { a0.sort(\"\\u8817\", e0, g1.e2, this.t1, m0); } catch(e0) { } s2 += s2; } })); } catch(e0) { } try { a2.shift(a1); } catch(e1) { } s1 += s0; return o0; }); } }");
/*fuzzSeed-159544250*/count=962; tryItOut("Object.defineProperty(this, \"v0\", { configurable: false, enumerable: false,  get: function() {  return evalcx(\"v2 = t2.BYTES_PER_ELEMENT;\", o0.g2); } });");
/*fuzzSeed-159544250*/count=963; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + mathy2(( - ( + Math.trunc(( + y)))), ( ! Math.hypot(( + x), Math.imul((Math.sqrt(-0x080000000) | 0), x))))); }); testMathyFunction(mathy3, [-0x080000001, 0.000000000000001, 2**53+2, -0, 42, 2**53, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), 0x080000000, -(2**53-2), 1/0, 0x100000001, 0/0, -(2**53+2), -Number.MAX_VALUE, -1/0, 2**53-2, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, -0x080000000, 0, -0x0ffffffff, 0x100000000, -0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, 0x080000001]); ");
/*fuzzSeed-159544250*/count=964; tryItOut("/*infloop*/while(d = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { return []; }, has: function() { return false; }, hasOwn: Array.prototype.lastIndexOf, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: undefined, }; })(undefined), x))neuter(b1, \"same-data\");");
/*fuzzSeed-159544250*/count=965; tryItOut("mathy5 = (function(x, y) { return Math.min(Math.fround(Math.hypot(Math.fround(( + ( + ( ~ -0x0ffffffff)))), ( + ( ~ (Math.abs(( + (y | 0))) | 0))))), Math.fround(Math.tanh(((( + Math.fround(Math.min(mathy4(0x080000000, -0x0ffffffff), Math.fround(Math.atan(( + Math.pow(( + Number.MAX_SAFE_INTEGER), x))))))) | 0) | 0)))); }); ");
/*fuzzSeed-159544250*/count=966; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - (Math.fround((((Math.hypot(y, x) >>> 0) != (mathy0(y, ( + y)) >>> 0)) >>> 0)) >= (Math.fround(y) * (Math.PI % Math.acos((Math.sin(y) >>> 0)))))); }); testMathyFunction(mathy4, [-0x080000001, 0x080000001, 0x07fffffff, 0x100000001, 2**53+2, 2**53, -(2**53+2), 0.000000000000001, -1/0, -(2**53), 2**53-2, -0, -Number.MIN_VALUE, 0/0, Math.PI, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, -0x080000000, 0x100000000, -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, 1, 0x080000000, 1/0, Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=967; tryItOut("\"use strict\"; i2.toString = (function() { try { m0.get(null); } catch(e0) { } try { f0 = m1.get(o0); } catch(e1) { } try { v1 = g0.runOffThreadScript(); } catch(e2) { } Array.prototype.splice.call(g2.g2.a1, NaN, ({valueOf: function() { x = g0.s0;return 2; }}), this.p0, p0, h1, g0.h1, v2, b2, b1, m2); return s1; });");
/*fuzzSeed-159544250*/count=968; tryItOut("print(uneval(f1));");
/*fuzzSeed-159544250*/count=969; tryItOut("m0.has(m0);");
/*fuzzSeed-159544250*/count=970; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( ! (Math.atanh((Math.tan(Math.min(x, y)) >>> 0)) >>> 0)) - ( + (((mathy4((Math.asin((0x080000000 | 0)) | 0), -Number.MAX_VALUE) | 0) & Math.fround(Math.trunc(Math.fround(Math.imul(x, 42))))) >>> 0))) | 0); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 0x080000001, -0, -Number.MAX_VALUE, 0/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0x100000001, 0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 2**53+2, 42, 0x100000000, -(2**53+2), 1, -0x080000000, 0, -0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53), -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53, 1/0, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), Math.PI, 0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=971; tryItOut("mathy2 = (function(x, y) { return Math.imul(Math.fround(Math.max(Math.fround(( ! Math.fround(Math.min(Math.fround(Math.atan2(((x >>> 0) * ( + x)), y)), Math.fround(mathy1(y, y)))))), (( + y) >>> 0))), ( ~ Math.atan2(-0x080000001, Math.log1p((x | 0))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 0x080000001, -(2**53+2), 0x0ffffffff, 1/0, 2**53-2, Number.MIN_VALUE, -0x080000001, 0x07fffffff, -0x07fffffff, 42, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -(2**53-2), Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, 2**53, -1/0, 0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -0x0ffffffff, 1, 0.000000000000001, -0x080000000, -0x100000000, -0]); ");
/*fuzzSeed-159544250*/count=972; tryItOut("\"use strict\"; a1[\"arguments\"] = o2.o0;");
/*fuzzSeed-159544250*/count=973; tryItOut("this.v2 = Object.prototype.isPrototypeOf.call(v0, e0);");
/*fuzzSeed-159544250*/count=974; tryItOut("\"use strict\"; /*oLoop*/for (twigkq = 0; twigkq < 45; ++twigkq) { /*oLoop*/for (luszyp = 0, x; luszyp < 125; \"\\u6D24\", ++luszyp) { print(x); } f1(s1); } ");
/*fuzzSeed-159544250*/count=975; tryItOut("v1 = a1.reduce, reduceRight((function() { for (var j=0;j<37;++j) { f2(j%5==1); } }), g2.e2);let e = \n/*MARR*/[].filter(Date.prototype.getMinutes, /[^]\\2/gy);");
/*fuzzSeed-159544250*/count=976; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=977; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[new String(''), new String(''), new String(''), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new String(''), new Number(1.5), new Number(1.5), new String(''), new String(''), new String(''), new String(''), new String(''), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new String(''), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), new String(''), new String(''), new String(''), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new String('')]); ");
/*fuzzSeed-159544250*/count=978; tryItOut("/*infloop*/for(x; ((TypeError.prototype)++); (eval(\"mathy2 = (function(x, y) { return Math.max((Math.cbrt(( ~ Math.cos((( + Math.fround(x)) >>> 0)))) >>> 0), ((Math.expm1(((Math.imul(-(2**53), (( + (( + x) & (Math.log10((x | 0)) | 0))) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy2, [-0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), -0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 1/0, -(2**53+2), -(2**53-2), Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, 2**53-2, -1/0, -Number.MAX_VALUE, 0x080000000, 42, -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -0x080000001, 2**53+2, 1, 0x080000001, 0x0ffffffff, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, Math.PI, 0x100000001]); \", (4277)))) this.g1 + i2;");
/*fuzzSeed-159544250*/count=979; tryItOut("\"use strict\"; ");
/*fuzzSeed-159544250*/count=980; tryItOut("\"use strict\"; if(false) {v0 = g0.eval(\"function f1(t0) true\");y; } else  if (timeout(1800)) {yield window;e0.delete(i2); }");
/*fuzzSeed-159544250*/count=981; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.tanh(Math.fround(Math.imul(Math.fround(( ! ( ~ 2**53-2))), (((( ! (( + Math.fround(x)) != 0)) >>> 0) === (( + y) | 0)) >>> 0)))); }); testMathyFunction(mathy0, [42, -1/0, 0x07fffffff, -Number.MAX_VALUE, 2**53, 0x080000001, Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, -(2**53), -Number.MIN_VALUE, Math.PI, -0x080000000, 0.000000000000001, 0/0, -0x0ffffffff, 2**53+2, -0x100000001, 1/0, 1.7976931348623157e308, 1, -0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000001, 0x100000000, -(2**53-2), 2**53-2, Number.MIN_VALUE, 0, -0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=982; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.min(( + (mathy0((Math.atan2((( ! (( + Math.imul(( + ( + (-1/0 ** (Number.MIN_SAFE_INTEGER >>> 0)))), ( + y))) & Math.log10(x))) | 0), ( ! y)) >>> 0), (Math.atan(x) >>> 0)) >>> 0)), Math.fround(Math.exp((Math.atanh(Math.fround(((0x07fffffff >> ( + ( + ( + x)))) >>> ( + ( ! Math.fround(x)))))) | 0))))); }); testMathyFunction(mathy1, [-0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 1/0, -(2**53-2), 0x07fffffff, -Number.MAX_VALUE, 0, -(2**53+2), -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 42, 2**53+2, -1/0, -0, -0x100000000, 0/0, -0x080000000, 0.000000000000001, 0x100000000, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 0x080000001, 0x080000000, 2**53-2, 1, 2**53, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=983; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=984; tryItOut("\"use strict\";  for  each(\u0009var y in (let (e = Math.pow(/\\1/gy, 18)) (function(q) { \"use strict\"; return q; })(/\\3/gy, 20)) <<= delete x.x) {a1.shift();var yjetbr = new ArrayBuffer(16); var yjetbr_0 = new Float64Array(yjetbr); print(yjetbr_0[0]); var yjetbr_1 = new Uint8ClampedArray(yjetbr); yjetbr_1[0] = 0; var yjetbr_2 = new Int16Array(yjetbr); var yjetbr_3 = new Uint8Array(yjetbr); print(yjetbr_3[0]); yjetbr_3[0] = -29; v0 = NaN; }");
/*fuzzSeed-159544250*/count=985; tryItOut("/*infloop*/L:for(let a = (w = delete  \"\" .eval); new \"\\u7DB3\"; x) {var iddjle = new SharedArrayBuffer(6); var iddjle_0 = new Uint32Array(iddjle); print(iddjle_0[0]); iddjle_0[0] = -10; var iddjle_1 = new Uint8ClampedArray(iddjle); iddjle_1[0] = 13; var iddjle_2 = new Float32Array(iddjle); print(iddjle_2[0]); iddjle_2[0] = 19; /*RXUB*/var r = this.r2; var s = \"a\"; print(uneval(r.exec(s))); (\"\\uE3CE\");a2.length = 10;Object.defineProperty(this, \"h0\", { configurable: (iddjle_0[1] % 8 != 1), enumerable: true,  get: function() {  return ({getOwnPropertyDescriptor: function(name) { print(e0);; var desc = Object.getOwnPropertyDescriptor(o0.f0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { /*ODP-2*/Object.defineProperty(s0, \"toSource\", { configurable: [[]], enumerable: false, get: (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14) { var r0 = iddjle * iddjle_0[0]; var r1 = r0 | a7; a8 = a % iddjle_2[7]; var r2 = iddjle_1 ^ 7; var r3 = iddjle_0[0] + 5; var r4 = iddjle_2[7] ^ a2; var r5 = a6 & a12; var r6 = iddjle_0 / iddjle_2[0]; var r7 = a5 & a10; var r8 = 7 - r2; iddjle = 1 * iddjle_1; var r9 = a4 & 3; var r10 = 4 - 6; var r11 = iddjle_1 % a13; var r12 = a5 & 5; print(r4); a14 = r4 - a3; var r13 = a2 * iddjle_2; var r14 = a2 + a1; var r15 = iddjle_1[0] / 4; var r16 = 7 - 3; var r17 = 4 % 3; r3 = a14 & 8; var r18 = r17 % a0; var r19 = iddjle_0[1] - a12; var r20 = r12 / 1; var r21 = a10 ^ a8; a4 = iddjle_0 ^ 6; var r22 = r0 % r16; var r23 = r1 & a13; print(r16); var r24 = 5 - r13; var r25 = 5 + a13; r0 = a1 & a14; var r26 = a4 / a14; var r27 = 8 + r14; var r28 = 3 * a7; var r29 = iddjle_1 / r6; var r30 = r13 | r23; var r31 = r12 & 2; var r32 = r17 + 4; var r33 = a14 * r10; var r34 = 4 * 1; var r35 = 2 * 3; a1 = 2 % iddjle_1[0]; r22 = 0 + 8; var r36 = r23 ^ 8; var r37 = iddjle_1[0] - 9; var r38 = r3 + r21; a11 = 4 / r10; var r39 = a14 * r20; var r40 = iddjle_0[1] / a8; var r41 = r17 | r12; iddjle_0 = r33 / r36; var r42 = 4 / 4; var r43 = 1 | r7; print(a11); var r44 = a0 + iddjle_2[0]; var r45 = 1 * r10; var r46 = r42 + r22; var r47 = 8 % iddjle_1[0]; var r48 = 8 % r36; var r49 = r10 / r8; var r50 = r49 % r38; var r51 = iddjle_0 + iddjle_1[0]; var r52 = 5 + r10; iddjle_2[0] = r36 | a11; var r53 = 5 & 9; var r54 = 0 + r32; var r55 = r4 & 0; var r56 = 8 * 8; var r57 = 1 & iddjle_2; var r58 = iddjle_0[1] * 8; var r59 = 7 % r3; print(a1); var r60 = iddjle_2[0] + 6; var r61 = r54 % 7; var r62 = r8 % a8; var r63 = 6 | 9; var r64 = 9 % 9; var r65 = 3 * r3; var r66 = 0 ^ 0; var r67 = 2 * r31; var r68 = r14 % r58; r50 = a5 - iddjle_1; var r69 = r0 * a; var r70 = a8 * r34; var r71 = r41 & 5; var r72 = r33 / r31; iddjle_2[0] = r11 + r65; a2 = a5 / 2; var r73 = r41 % r34; var r74 = r18 + 2; var r75 = r61 | 5; var r76 = r9 & r12; var r77 = 4 % x; r18 = 6 ^ r58; var r78 = r33 ^ r50; var r79 = 1 | 9; var r80 = r78 & iddjle_1[0]; var r81 = a5 & r22; var r82 = r49 % r28; var r83 = r43 ^ 5; var r84 = r78 % 5; print(r42); var r85 = 7 & r34; var r86 = iddjle_2[0] + a1; r6 = r50 & r74; var r87 = 3 + iddjle_0[0]; var r88 = 3 * 4; r0 = 8 + 4; var r89 = r63 * 6; var r90 = r8 % r70; var r91 = r77 - r62; var r92 = 6 | 6; var r93 = 7 % iddjle; var r94 = a11 ^ r51; print(iddjle); var r95 = 0 | r34; var r96 = 1 - r42; var r97 = r45 * 3; var r98 = r53 | r54; var r99 = r83 - 2; r60 = 6 & a12; var r100 = a1 ^ 5; var r101 = 3 - r59; var r102 = r49 + a14; r62 = r17 + r69; var r103 = r54 & 5; r15 = 0 + r24; var r104 = r28 & r99; var r105 = r1 / r42; var r106 = 9 * r61; var r107 = r12 | 5; r106 = r36 * 3; var r108 = 8 - 6; r31 = iddjle_1[0] * 7; var r109 = r6 & r15; var r110 = 3 * 6; var r111 = r66 * r20; var r112 = r87 + r86; var r113 = 7 * r56; var r114 = r13 ^ r95; var r115 = r30 * a0; r44 = r73 + r90; var r116 = r87 & 3; var r117 = a7 ^ r49; print(r39); var r118 = r4 + 2; a8 = r40 | r51; var r119 = r111 + 8; var r120 = r90 - r65; var r121 = 4 + 5; var r122 = 2 | r118; var r123 = r99 & r36; r62 = 1 - a7; var r124 = iddjle_1[0] ^ r22; var r125 = 8 / 9; r13 = 5 - 0; r118 = 3 - r89; var r126 = r2 - a1; print(r119); var r127 = 1 + r34; var r128 = r17 / 3; var r129 = r53 % 6; var r130 = 0 & r35; r57 = 1 & r28; var r131 = r124 / r114; r90 = r116 / 0; r10 = r51 ^ r125; iddjle_1[0] = r77 & 9; var r132 = r72 | r65; var r133 = r119 ^ 0; r126 = r76 / r87; var r134 = 0 * r1; var r135 = 2 - 5; r47 = iddjle_1[0] - r131; r75 = r92 - 8; var r136 = r91 % r3; var r137 = 3 + r100; var r138 = 6 % a2; r71 = a3 + r78; print(r51); r0 = 5 ^ r79; r122 = a5 % 1; var r139 = r124 % r20; var r140 = iddjle_2 & 0; var r141 = r85 | r127; r103 = r69 + 4; var r142 = r74 * r80; var r143 = r51 - r24; var r144 = 8 % r60; r41 = 5 % 9; var r145 = r16 / r107; var r146 = 0 % 7; print(a9); var r147 = 3 / r67; var r148 = r9 % r60; var r149 = 5 ^ 3; r37 = 6 / r65; var r150 = 2 + r136; var r151 = 6 % r150; var r152 = r8 / 5; r30 = r74 | r141; var r153 = r2 + a4; iddjle_2 = r12 | 0; var r154 = r75 % r145; var r155 = x ^ 1; var r156 = r54 - 8; var r157 = r137 & 8; var r158 = r145 / 6; r116 = r76 / r6; var r159 = r72 & r55; var r160 = 4 ^ 3; r8 = r76 & a11; var r161 = r116 * 1; var r162 = r160 ^ r37; var r163 = r69 & x; var r164 = r143 / 3; var r165 = r102 & r134; var r166 = 6 | r90; var r167 = r147 * r79; var r168 = r37 ^ 0; r29 = r98 ^ r160; var r169 = r44 % r29; r116 = r7 * iddjle_2; var r170 = r99 + r20; var r171 = r150 * r128; var r172 = iddjle * r112; r127 = r101 & a9; var r173 = r134 & 1; var r174 = r173 % r47; r79 = r84 ^ 5; var r175 = x % 1; r85 = 0 & 5; var r176 = r70 + 4; var r177 = r6 / r14; var r178 = 6 * r38; var r179 = r177 * iddjle_2[7]; var r180 = r115 + r70; r112 = r51 & r108; var r181 = 7 - r19; var r182 = 3 * r35; var r183 = r96 - 0; r87 = 6 / 2; var r184 = r108 | r59; var r185 = r48 % r145; var r186 = r5 | r131; r164 = 8 * x; print(r160); var r187 = r135 | 7; print(r50); var r188 = iddjle_1[0] - r5; var r189 = 4 | 8; var r190 = 8 % iddjle_2[0]; var r191 = 2 ^ r119; var r192 = r111 / r75; var r193 = r7 % 8; r44 = r147 | r35; var r194 = r139 & iddjle_2[0]; var r195 = r120 * 0; var r196 = r107 | iddjle_0[0]; var r197 = 8 * 0; var r198 = r125 & 9; var r199 = 5 + r34; var r200 = a3 - r87; var r201 = 4 & r102; var r202 = 4 + r133; r194 = r168 ^ r101; var r203 = r70 % 4; var r204 = r136 & r151; r149 = r7 ^ r38; var r205 = r8 & r65; var r206 = 8 & r96; var r207 = iddjle * r91; var r208 = 8 * 2; var r209 = iddjle_2[0] & r79; print(r149); var r210 = 3 - 5; var r211 = r54 + 4; var r212 = r11 - 0; var r213 = 3 / 3; print(r9); var r214 = r121 ^ r191; var r215 = 4 - r15; var r216 = 9 - 6; var r217 = r80 + 0; var r218 = r14 - r75; var r219 = 3 * 7; var r220 = 6 & 5; r117 = 7 | 8; var r221 = 5 ^ 3; r101 = r30 + r67; var r222 = r101 | 9; var r223 = r74 * 0; var r224 = 4 / r151; var r225 = r74 + 8; var r226 = r123 % r135; var r227 = r61 / r3; a7 = r75 + r44; var r228 = r173 | r209; var r229 = r228 ^ r113; var r230 = r143 & 0; var r231 = r138 % r113; var r232 = 1 & r41; var r233 = r160 / 0; var r234 = iddjle_0 & r45; var r235 = r93 / r220; var r236 = r104 ^ r71; var r237 = 6 ^ r232; r138 = r96 & r140; var r238 = r183 - 9; var r239 = r82 ^ r184; var r240 = r23 - 1; var r241 = 3 / 4; var r242 = r180 ^ r226; r157 = r178 + 4; var r243 = 2 + 7; var r244 = r100 + r158; var r245 = r227 ^ r174; return a12; }), set: (function() { Array.prototype.reverse.call(a1); return t0; }) });; var desc = Object.getPropertyDescriptor(o0.f0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { o1.e0.add(p0);; Object.defineProperty(o0.f0, name, desc); }, getOwnPropertyNames: function() { ;; return Object.getOwnPropertyNames(o0.f0); }, delete: function(name) { Object.defineProperty(this, \"i2\", { configurable: true, enumerable: (iddjle_1[0] % 24 == 16),  get: function() {  return e0.values; } });; return delete o0.f0[name]; }, fix: function() { i1 = e2.entries;; if (Object.isFrozen(o0.f0)) { return Object.getOwnProperties(o0.f0); } }, has: function(name) { this.a2[8] = x;; return name in o0.f0; }, hasOwn: function(name) { for (var v of o2.o1) { try { /*MXX3*/g0.Date.prototype.setUTCSeconds = g2.Date.prototype.setUTCSeconds; } catch(e0) { } try { s0.__proto__ = g1; } catch(e1) { } v1 = t0.length; }; return Object.prototype.hasOwnProperty.call(o0.f0, name); }, get: function(receiver, name) { h2.defineProperty = f1;; return o0.f0[name]; }, set: function(receiver, name, val) { v0 = (p2 instanceof b1);; o0.f0[name] = val; return true; }, iterate: function() { return this.b1; return (function() { for (var name in o0.f0) { yield name; } })(); }, enumerate: function() { return o2; var result = []; for (var name in o0.f0) { result.push(name); }; return result; }, keys: function() { e0.toSource = (function() { for (var j=0;j<38;++j) { f2(j%2==1); } });; return Object.keys(o0.f0); } }); } }); /x/ ;let (e = \n({}) = \"\\u54CB\" & (4277), wvnjgy, [] = (Math.exp(\u0009 \"\"  /=  \"\" ))) { v2 = Object.prototype.isPrototypeOf.call(b0, p1); } }");
/*fuzzSeed-159544250*/count=986; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! Math.imul(mathy0((y * 2**53-2), Math.fround(Math.atanh(x))), Math.max(( ! Number.MAX_VALUE), ((y - -0x100000000) >>> 0)))); }); testMathyFunction(mathy2, [42, Math.PI, 0.000000000000001, -0x0ffffffff, 0, -Number.MIN_VALUE, -(2**53+2), 0x100000001, -(2**53-2), -0, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 0x080000001, -0x080000001, 2**53, 0x100000000, -0x100000001, -(2**53), 1/0, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, 0/0, 0x080000000, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=987; tryItOut("g0.i2.send(o2.t1);");
/*fuzzSeed-159544250*/count=988; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(Math.max(Math.fround(Math.round(( + Math.max(Math.fround(mathy0(x, ( + (( + -(2**53+2)) == ( + x))))), ( ! x))))), ( - ( ~ Math.fround(mathy2(-0x080000000, ( + x))))))) > Math.max(( + Math.sin(( + ((x | 0) != ( + mathy2(y, x)))))), ( ! ( ! y)))); }); testMathyFunction(mathy3, /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), 0x080000000, new Boolean(false), 0x080000000, new Boolean(false), 0x080000000, new Boolean(false), 0x080000000, new Boolean(false), new Boolean(false), new Boolean(false), 0x080000000, 0x080000000, new Boolean(false), new Boolean(false), new Boolean(false), 0x080000000, 0x080000000, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 0x080000000, 0x080000000, new Boolean(false), 0x080000000, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 0x080000000, new Boolean(false), 0x080000000, 0x080000000, new Boolean(false), new Boolean(false), 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, new Boolean(false), new Boolean(false), 0x080000000, 0x080000000, 0x080000000, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 0x080000000, 0x080000000, 0x080000000, new Boolean(false), new Boolean(false), new Boolean(false), 0x080000000, 0x080000000, 0x080000000, 0x080000000, 0x080000000, new Boolean(false), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-159544250*/count=989; tryItOut("\"use strict\"; g0 = this;\nlet (x, d, epiodr, tjdalr, b =  '' , jzspuq) { /*vLoop*/for (var rtjdob = 0; rtjdob < 13; ++rtjdob) { b = rtjdob; let v1 = this.a1.length; }  }\n");
/*fuzzSeed-159544250*/count=990; tryItOut("\"use strict\"; g0.v1 = g2.eval(\"function f1(o0) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    (Uint8ArrayView[((i1)+(-0x8000000)-((abs((((-0x8000000)) & ((0x6b2ec304))))|0))) >> 0]) = ((-0x8000000)-(-0x8000000));\\n    return +(((d0) + (8796093022209.0)));\\n  }\\n  return f;\");");
/*fuzzSeed-159544250*/count=991; tryItOut("\"use strict\"; o0.__proto__ = b2;");
/*fuzzSeed-159544250*/count=992; tryItOut("mathy5 = (function(x, y) { return ( ! Math.fround(( ! Math.fround(( + mathy2(x, x)))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, 42, 0/0, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, 0x080000000, -Number.MAX_VALUE, 0x100000001, -0x100000000, 1/0, 2**53-2, Math.PI, 1, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, 2**53, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0, 0, -(2**53+2), 0x0ffffffff, -(2**53), -0x100000001, -0x080000001, -(2**53-2), -0x080000000]); ");
/*fuzzSeed-159544250*/count=993; tryItOut("(void options('strict_mode'));");
/*fuzzSeed-159544250*/count=994; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[(-1/0), function(){}, function(){},  '\\0' ,  '\\0' , Infinity, function(){}, (-1/0), Infinity, Infinity, (-1/0),  '\\0' , Infinity, Infinity, Infinity,  '\\0' ,  '\\0' , function(){}, (-1/0), (-1/0), function(){},  '\\0' , Infinity,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , function(){}, function(){}, function(){}, (-1/0), Infinity, function(){}, function(){}, (-1/0), Infinity, Infinity,  '\\0' , (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0),  '\\0' , (-1/0), Infinity, (-1/0), function(){}, function(){}, function(){}, function(){}, Infinity, function(){}, function(){}, Infinity, (-1/0),  '\\0' , function(){}, Infinity, function(){},  '\\0' ,  '\\0' , Infinity, Infinity, function(){}, function(){}, (-1/0), (-1/0),  '\\0' , function(){}, (-1/0)]) { print( /x/g ); }");
/*fuzzSeed-159544250*/count=995; tryItOut("v1 = g2.eval(\"/*bLoop*/for (let pdcmhc = 0; pdcmhc < 37; ++pdcmhc) { if (pdcmhc % 4 == 3) { Object.preventExtensions(m0); } else { for (var v of t1) { try { a0.unshift(o2.f1); } catch(e0) { } try { a2.__proto__ = g1.f0; } catch(e1) { } this.i2.valueOf = (function() { o0.g0 + ''; throw h2; }); } }  } \");");
/*fuzzSeed-159544250*/count=996; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-159544250*/count=997; tryItOut("s1 += s1;");
/*fuzzSeed-159544250*/count=998; tryItOut("x ^= \u3056;");
/*fuzzSeed-159544250*/count=999; tryItOut("a0 = a1.map((function() { try { v2 = g1.eval(\"function f2(b0)  { yield (4277) ? (/*wrap1*/(function(){ (({}));return decodeURI})().prototype) : (this\\n) } \\u000c\"); } catch(e0) { } let a2 = Array.prototype.slice.call(a0, NaN, NaN, ({} = {} % x\n), o0); return g2; }));g2.v1 = g1.runOffThreadScript();");
/*fuzzSeed-159544250*/count=1000; tryItOut("\"use strict\"; g2 + i2;a2.forEach((function() { try { g2 + this.t1; } catch(e0) { } try { for (var p in this.o2) { s1 += s0; } } catch(e1) { } s2 += 'x'; return i1; }));");
/*fuzzSeed-159544250*/count=1001; tryItOut("Array.prototype.splice.apply(a2, [NaN, 15]);");
/*fuzzSeed-159544250*/count=1002; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s0; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=1003; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=1004; tryItOut("\"use strict\"; yield;\ns2 = '';\n");
/*fuzzSeed-159544250*/count=1005; tryItOut("\"use strict\"; a2.__iterator__ = (function() { for (var j=0;j<33;++j) { f2(j%3==0); } });");
/*fuzzSeed-159544250*/count=1006; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot(( + ( + (y ? ((( + (x >>> 0)) >>> 0) & (( ~ ( + Math.round(( + x)))) | 0)) : ( + (( + ((makeFinalizeObserver('nursery')))) !== ( + Math.PI)))))), Math.log1p((mathy0(Math.fround(Math.tan(Math.fround(x))), 2**53-2) << Math.round(( + y))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, 0x080000000, 0.000000000000001, 2**53, -0x100000001, -0x080000001, 0x080000001, -0x07fffffff, 1, Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000000, 2**53-2, 1/0, -0x080000000, -0, -(2**53-2), -Number.MIN_VALUE, 0, 1.7976931348623157e308, 0x0ffffffff, 0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-159544250*/count=1007; tryItOut("testMathyFunction(mathy2, [0x080000001, 1, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -0, 1/0, -0x100000000, 2**53+2, Math.PI, 0/0, 0x0ffffffff, -1/0, 0x080000000, 0x100000000, -(2**53+2), 0.000000000000001, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, 42, -(2**53), 0x100000001, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, 0]); ");
/*fuzzSeed-159544250*/count=1008; tryItOut("mathy1 = (function(x, y) { return (Math.asin(((Math.imul((Math.hypot((Math.imul((Math.pow(( + ( + Math.cbrt(( + y)))), ( + (-(2**53-2) | 0))) | 0), ((Math.hypot(((( ~ (y | 0)) | 0) ? -(2**53-2) : y), Math.fround(x)) >>> 0) | 0)) | 0), (( ~ (y >>> 0)) >>> 0)) >>> 0), ( + (((( ~ y) >>> 0) || (( - (y >>> 0)) | 0)) ^ -0x080000001))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy1, [-0x07fffffff, -(2**53-2), -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0, 0x080000000, -1/0, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 2**53+2, -0x080000001, -(2**53), 0x100000000, Math.PI, -0x080000000, 2**53-2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1, 42, -0x100000001, 0/0, 0, 1.7976931348623157e308, -0x0ffffffff, 0x0ffffffff, -Number.MAX_VALUE, 2**53, 0x07fffffff, 0x100000001]); ");
/*fuzzSeed-159544250*/count=1009; tryItOut("v2 = t1.length;");
/*fuzzSeed-159544250*/count=1010; tryItOut("this.v0 = Object.prototype.isPrototypeOf.call(this.g0.t1, m1);");
/*fuzzSeed-159544250*/count=1011; tryItOut("\"use strict\"; m0.delete(o0.t0);v2 = Object.prototype.isPrototypeOf.call(p2, g1);");
/*fuzzSeed-159544250*/count=1012; tryItOut("\"use strict\"; print( '' .__defineGetter__(\"w\", Date.prototype.setTime));\np0 = m0.get(b1);\n");
/*fuzzSeed-159544250*/count=1013; tryItOut("s2 += 'x';");
/*fuzzSeed-159544250*/count=1014; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1015; tryItOut("this.a2.forEach(decodeURI);");
/*fuzzSeed-159544250*/count=1016; tryItOut("Array.prototype.shift.call(a0);");
/*fuzzSeed-159544250*/count=1017; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( ! ( + ( + ( + (( + Math.sign(( ~ x))) | 0))))) >>> 0); }); testMathyFunction(mathy1, [-0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, 0x100000000, 2**53+2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -0x080000000, -0x100000001, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, 1.7976931348623157e308, 0/0, -(2**53), 2**53, 0x080000001, 0, -Number.MAX_SAFE_INTEGER, Math.PI, 1, -0, -Number.MIN_VALUE, 1/0, -(2**53-2), Number.MAX_VALUE, -(2**53+2), -0x080000001, 42, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-159544250*/count=1018; tryItOut("s0 += 'x';");
/*fuzzSeed-159544250*/count=1019; tryItOut("mathy2 = (function(x, y) { return ( + ( ~ ( + Math.fround(mathy1(Math.fround((( + Math.cosh((x !== Math.fround(( + Math.fround(y)))))) < (( + Math.fround(Math.ceil((-(2**53) & 0x0ffffffff)))) | 0))), Math.fround((( ! (( + (0x0ffffffff !== Number.MAX_SAFE_INTEGER)) | 0)) | 0))))))); }); testMathyFunction(mathy2, [0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, -0x0ffffffff, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -(2**53-2), 1, -0x080000000, Math.PI, 0/0, -0x080000001, -Number.MIN_VALUE, -0x07fffffff, -(2**53), 0x07fffffff, -(2**53+2), 2**53, 42, 0.000000000000001, 0x080000001, 0, 0x100000000, -0]); ");
/*fuzzSeed-159544250*/count=1020; tryItOut("if(false) print(new Set()); else  if ((p={}, (p.z =  /* Comment */((x)|=(p={}, (p.z =  /x/ )())))())) yield (4277);");
/*fuzzSeed-159544250*/count=1021; tryItOut("\"use strict\"; /*infloop*/for(var y; let (z) window; Math.clz32(((uneval( /x/ ))))) {s1 += s0; }");
/*fuzzSeed-159544250*/count=1022; tryItOut("\"use strict\"; M:for(d = ((p={}, (p.z = \"\\u3EB4\")())) in (4277)) {\u000cm0.get(m1); }");
/*fuzzSeed-159544250*/count=1023; tryItOut("");
/*fuzzSeed-159544250*/count=1024; tryItOut("i2.next();");
/*fuzzSeed-159544250*/count=1025; tryItOut("\"use strict\"; f0 + '';");
/*fuzzSeed-159544250*/count=1026; tryItOut("for(e = (({}) = -0.553) in Math.atan2(-2, -14)) {(\"\\uF41E\"); }");
/*fuzzSeed-159544250*/count=1027; tryItOut("/*oLoop*/for (xfvhzo = 0; xfvhzo < 8; ++xfvhzo) { x => -15let x = /(?:\\1|\\S\\ueBC9+?+?)[^]/yi; } ");
/*fuzzSeed-159544250*/count=1028; tryItOut("const x = x, x = x, x = let (b) c = Proxy.create(({/*TOODEEP*/})(\"\\u44FD\"),  '' ), fmheor, ythenu, ysopei, a = x + window;oraktf(x, \"\\uBF24\");/*hhh*/function oraktf(){for (var v of t1) { try { o1 = {}; } catch(e0) { } o2.h2.getPropertyDescriptor = (function mcc_() { var sqrhls = 0; return function() { ++sqrhls; if (/*ICCD*/sqrhls % 8 == 4) { dumpln('hit!'); try { Array.prototype.unshift.apply(a1, [ /x/ , f1, a1]); } catch(e0) { } try { m0.has(b1); } catch(e1) { } this.o0.h2.__iterator__ = (function(j) { if (j) { try { o2.m2.valueOf = (function() { try { i0.send(b1); } catch(e0) { } m0.has(m2); return a0; }); } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"\\n\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\\u000c\"; print(s.replace(r,  '' , \"yi\"));  } catch(e1) { } t1[10] =  /x/ ; } else { /*MXX3*/g1.Promise.all = g1.Promise.all; } }); } else { dumpln('miss!'); try { v1 = evalcx(\"print(/(?=\\\\B){4}|[^\\\\b\\\\S\\\\W]|\\\\2(?=.+?+)*/gyim);\", g1); } catch(e0) { } v0 = evaluate(\"this.v1 = Object.prototype.isPrototypeOf.call(g2.e2, f2);\", ({ global: g0.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: 5, catchTermination: this })); } };})(); }}");
/*fuzzSeed-159544250*/count=1029; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 144115188075855870.0;\n    var d5 = -8796093022207.0;\n    var i6 = 0;\n    var d7 = 3.777893186295716e+22;\n    i3 = (0x1bb5cb34);\n    d5 = (((2.0)) - ((+(0x8ef9a76d))));\n    (Uint16ArrayView[(((0x7988bab5))) >> 1]) = ((0x47a1b30d)*0x55403);\n    return +((17592186044417.0));\n    return +((-137438953473.0));\n  }\n  return f; })(this, {ff: (getInt16, w = \"\\uCEAA\" >>> \"\\u80FB\") =>  { \"use strict\"; ; } \u0009}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -0x080000001, 0x07fffffff, -0, -(2**53), 0/0, -0x100000000, 42, 0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), 0x0ffffffff, 0.000000000000001, Math.PI, 1/0, 2**53-2, 2**53, -0x0ffffffff, 1, -0x100000001, Number.MAX_VALUE, 0x080000001, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1030; tryItOut("a2.reverse(v0);");
/*fuzzSeed-159544250*/count=1031; tryItOut("for (var p in i2) { try { o1 + ''; } catch(e0) { } this.v0 = 4; }");
/*fuzzSeed-159544250*/count=1032; tryItOut("v2 = a1.length;");
/*fuzzSeed-159544250*/count=1033; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.exp(( + Math.fround((Math.tanh(Math.clz32((( ! Math.fround(( ! Math.fround(0x100000001)))) >>> 0))) > Math.fround((( - Math.min(y, x)) >>> 0))))))); }); ");
/*fuzzSeed-159544250*/count=1034; tryItOut("\"use strict\"; \"use asm\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = ((0xffffffff) > (((i0)*-0x810ec)>>>((i0)-(i1))));\n    return +((((((+(1.0/0.0))) / ((+(-1.0/0.0))))) % ((+(-1.0/0.0)))));\n  }\n  return f; })(this, {ff:  ''  >= -27}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 0, -(2**53-2), 0.000000000000001, -0x0ffffffff, 42, -0x080000001, 2**53-2, -1/0, 0x100000000, -0, 0x080000001, -0x07fffffff, -(2**53), -(2**53+2), Math.PI, 2**53+2, 1.7976931348623157e308, 0x080000000, 1, -0x080000000, 0x07fffffff, -0x100000000, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1035; tryItOut("/*vLoop*/for (var bxldya = 0, ({lastMatch: (new Set() ^ (4277)),  get length(x, c) { \"use strict\"; yield (eval = /(?=\\3)*(?=(?!\\D)|\\b?){0}/yi) }  }); bxldya < 0; ++bxldya) { z = bxldya; /*bLoop*/for (let nldrlt = 0; nldrlt < 107; ++nldrlt) { if (nldrlt % 80 == 43) { /*infloop*/for(var \"\\uACE1\".x in ((String.prototype.big)(z))){Array.prototype.reverse.call(this.a2, e0);for (var p in i2) { print(19); } } } else { /*RXUB*/var r = /(([^]\\3|\\b*?)).^{0,}|[^]/i; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex);  }  }  } ");
/*fuzzSeed-159544250*/count=1036; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1037; tryItOut("for (var v of i1) { i0.send(h0); }");
/*fuzzSeed-159544250*/count=1038; tryItOut("testMathyFunction(mathy4, [-(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -0x100000000, -1/0, 0x080000001, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, -0, 0x100000000, 0, -0x100000001, 2**53+2, -0x080000000, -(2**53+2), 1, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0/0, 2**53, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1039; tryItOut("\"use strict\"; /*MXX3*/g1.Array.isArray = g0.Array.isArray;");
/*fuzzSeed-159544250*/count=1040; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i1)+(i1)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [(new Number(0)), [], /0/, true, 1, 0, (function(){return 0;}), '/0/', '\\0', 0.1, [0], ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Number(-0)), NaN, ({valueOf:function(){return '0';}}), '', null, -0, objectEmulatingUndefined(), '0', undefined, (new Boolean(true)), ({toString:function(){return '0';}}), (new String('')), false]); ");
/*fuzzSeed-159544250*/count=1041; tryItOut("\"use strict\"; { void 0; deterministicgc(true); }");
/*fuzzSeed-159544250*/count=1042; tryItOut("m2.toString = f1;");
/*fuzzSeed-159544250*/count=1043; tryItOut("f1.__iterator__ = Date.prototype.toLocaleString.bind(a2);");
/*fuzzSeed-159544250*/count=1044; tryItOut("\"use strict\"; let(x, x, x = (\u000c /* Comment */0x080000001), this.d = x, x = let (kpfkvh, w, x, xbgfdl, x, y, kdenxs) undefined) ((function(){x.message;})());");
/*fuzzSeed-159544250*/count=1045; tryItOut("\"use strict\"; Object.prototype.unwatch.call(g2, \"arguments\");");
/*fuzzSeed-159544250*/count=1046; tryItOut("this.s2 += s0;");
/*fuzzSeed-159544250*/count=1047; tryItOut("let (e = 25 || \"\\u859D\") (/\\b{0,}|(?=\\b)[\\s\\d]|\\2+?(?:\u9933*?)*?{268435456}/g)(-29,  /x/g );\u0009");
/*fuzzSeed-159544250*/count=1048; tryItOut("x.constructor;");
/*fuzzSeed-159544250*/count=1049; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((( + Math.hypot(Math.fround(( + Math.cos(( + Math.fround(Math.min(( + (0 >>> 0)), x)))))), Math.fround(Math.fround(mathy3(Math.fround(( ~ Math.fround(( + (( + y) === ( + x)))))), (( + Math.pow(-0x100000001, mathy2(Math.fround(mathy3((y >>> 0), y)), ( + 2**53+2)))) >>> 0)))))) === Math.fround(mathy0(((x ^ Math.hypot(Math.min(( + x), ( ~ ( - y))), Math.log2(2**53))) | 0), (( + Math.hypot(Math.atan2(Math.fround(y), y), y)) >>> 0)))) | 0); }); ");
/*fuzzSeed-159544250*/count=1050; tryItOut("m2.get(e2);");
/*fuzzSeed-159544250*/count=1051; tryItOut("let(z) ((function(){with({}) { b = \u3056; } })());");
/*fuzzSeed-159544250*/count=1052; tryItOut("o0.e0.delete( /x/g );");
/*fuzzSeed-159544250*/count=1053; tryItOut("/*vLoop*/for (let eecjzs = 0; eecjzs < 116 && ((4277)(\"\\u2052\")); ++eecjzs) { b = eecjzs; a2.forEach((function(j) { if (j) { try { neuter(b1, \"change-data\"); } catch(e0) { } try { m0.set(g1, p0); } catch(e1) { } try { for (var p in m2) { Object.preventExtensions(m0); } } catch(e2) { } /*RXUB*/var r = r0; var s = \"\"; print(uneval(s.match(r)));  } else { try { this.v2 = t0.byteLength; } catch(e0) { } a1[v1] =  '' ; } })); } ");
/*fuzzSeed-159544250*/count=1054; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return Math.log1p(mathy0(Math.fround(Math.fround(Math.min(Math.clz32(Math.log1p((( - x) >>> 0))), Math.ceil(((Math.expm1(Math.fround(Math.asinh((x >>> 0)))) | 0) | 0))))), (y - mathy0((Math.atan2(Math.imul(Math.asin(y), y), y) >>> 0), ( + y))))); }); testMathyFunction(mathy1, [0.000000000000001, -0x100000000, Number.MIN_VALUE, -1/0, -(2**53), 2**53-2, -0x080000001, 0x080000001, 2**53+2, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, 0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, 1/0, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -0x100000001, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, 1, 0x0ffffffff, -Number.MAX_VALUE, -0x080000000, 42, -Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1055; tryItOut("s0 += 'x';");
/*fuzzSeed-159544250*/count=1056; tryItOut("mathy3 = (function(x, y) { return Math.atan2(Math.ceil((Math.max(Math.max(Math.tanh(0x100000001), (y | 0)), ( + Math.asin(Math.max(1.7976931348623157e308, y)))) | 0)), ( + ( ~ ( + ( ! x))))); }); testMathyFunction(mathy3, [-0x080000001, 0/0, -1/0, -0x07fffffff, 42, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, -0x100000000, 1, -0x080000000, 0x100000000, Number.MAX_VALUE, 1/0, 0x080000000, 0, Math.PI, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, 1.7976931348623157e308, 2**53, 0.000000000000001, -0, 0x080000001]); ");
/*fuzzSeed-159544250*/count=1057; tryItOut("");
/*fuzzSeed-159544250*/count=1058; tryItOut("mathy4 = (function(x, y) { return Math.fround((( + Math.tan((((Math.log(Math.cos(y)) != (-(2**53) | 0)) * Math.sin(( - x))) >>> 0))) - ( + ( + ( ! Math.fround(((((Math.acosh(x) | 0) >>> 0) != ((Math.fround(( + Math.fround(x))) !== ( ~ 2**53)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy4, [-1/0, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 2**53, 1, -0x080000000, -0, Number.MAX_VALUE, 0x100000000, 0x100000001, 2**53-2, -0x080000001, Number.MIN_VALUE, 1/0, -0x0ffffffff, -(2**53-2), 42, Math.PI, -0x07fffffff, -Number.MAX_VALUE, 0, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -0x100000001, -(2**53), 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=1059; tryItOut("\"use strict\"; var uyzjjy = new SharedArrayBuffer(8); var uyzjjy_0 = new Int16Array(uyzjjy); var uyzjjy_1 = new Uint8Array(uyzjjy); var uyzjjy_2 = new Uint8ClampedArray(uyzjjy); print(uyzjjy_2[0]); uyzjjy_2[0] = -4; var uyzjjy_3 = new Int32Array(uyzjjy); uyzjjy_3[0] = -27; var uyzjjy_4 = new Float64Array(uyzjjy); for (var v of b0) { Array.prototype.shift.call(a0, \"\\u7932\", g1, f1); }v1 = evalcx(\"/* no regression tests found */\", g2);v1 = Object.prototype.isPrototypeOf.call(s0, this.p1);/*bLoop*/for (sbbaxc = 0; sbbaxc < 11; ++sbbaxc) { if (sbbaxc % 4 == 1) { e1.add(g0); } else { a0.push(); }  } a0.toString = (function(j) { if (j) { try { v1 = evalcx(\"encodeURI\", g1); } catch(e0) { } try { Array.prototype.splice.call(a1, NaN, ({valueOf: function() { for (var v of this.f2) { try { a0 = arguments.callee.arguments; } catch(e0) { } try { print(uneval(e1)); } catch(e1) { } o2.i0.toString = DataView.prototype.setUint32.bind(g1); }return 2; }}), i0, (4277)); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(g2, o2.g0); } catch(e2) { } s0 += 'x'; } else { try { m2.delete(f1); } catch(e0) { } print(uneval(i2)); } });");
/*fuzzSeed-159544250*/count=1060; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"end\" }); }");
/*fuzzSeed-159544250*/count=1061; tryItOut("with({}) { x = e; } let(x = ({x: -10}), x = ((true.round(x)) ^= let (y) y = Proxy.createFunction(({/*TOODEEP*/})(\"\\uC929\"),  \"\" , length)), {NaN: [], w: {x, this.__defineSetter__(\"x\", \"\\u5C4A\"): NaN}, x: x} = (4277), b, lkmxqz, nmuxth, velqaw, a =  /x/ ) ((function(){let(tqvlln, x =  /x/g , tqpjxv, zueobd, c, a =  /x/g , z = \"\\u052C\", a, kccwyt, x) ((function(){x.stack;})());})());");
/*fuzzSeed-159544250*/count=1062; tryItOut("/*ADP-2*/Object.defineProperty(a2, 17, { configurable: false, enumerable: (x % 3 != 2), get: (function() { try { (void schedulegc(g0)); } catch(e0) { } try { Array.prototype.push.apply(a0, [m1]);\nyield \"\\u3A71\";\n } catch(e1) { } try { ; } catch(e2) { } /*MXX2*/g2.Object.getOwnPropertyDescriptor = o2; return o0.o1.o1.p2; }), set: (function(j) { if (j) { try { for (var v of s2) { e0.delete(NaN = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })((uneval(-23))), function  a (a) { Array.prototype.forEach.apply(a1, [(function(j) { f0(j); })]); } , (void shapeOf(-9)))); } } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(g2.b2, o2.o0); } catch(e1) { } try { Array.prototype.forEach.call(a2, (function() { for (var j=0;j<138;++j) { f2(j%4==0); } }), i2); } catch(e2) { } Array.prototype.unshift.apply(a0, [h1]); } else { try { v0 = Object.prototype.isPrototypeOf.call(a0, a0); } catch(e0) { } Array.prototype.unshift.apply(a2, [s0, o0.t0, p2, this.o1.o2]); } }) });");
/*fuzzSeed-159544250*/count=1063; tryItOut("e0.add(g0);");
/*fuzzSeed-159544250*/count=1064; tryItOut("o2.a2 = [];");
/*fuzzSeed-159544250*/count=1065; tryItOut("\"use strict\"; v2 = g0.g1.a2.length;");
/*fuzzSeed-159544250*/count=1066; tryItOut("return x;");
/*fuzzSeed-159544250*/count=1067; tryItOut("mathy3 = (function(x, y) { return Math.imul((( + (Math.atan2((x | 0), (( + -(2**53-2)) | 0)) | 0)) | 0), ((mathy1((Math.pow(( + ( + ( + Math.fround(Math.hypot(Math.hypot(0x100000000, -0x080000000), (((0x07fffffff >>> 0) || (y >>> 0)) >>> 0)))))), y) >>> 0), mathy0(y, Math.fround(( + Math.max(( + Math.max(Math.ceil(1), x)), ( ! Number.MIN_VALUE)))))) - (( ! ((Math.imul(( + Math.log1p(( + x))), y) | 0) | 0)) | 0)) | 0)); }); testMathyFunction(mathy3, [0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53+2, 0x080000000, 0x100000000, -(2**53+2), -0x0ffffffff, 42, Math.PI, -1/0, 0x100000001, -(2**53-2), -0x100000001, -(2**53), -Number.MAX_VALUE, -0x07fffffff, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, -Number.MIN_VALUE, -0x080000001, 0/0, 1, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-159544250*/count=1068; tryItOut("\"use strict\"; s2.valueOf = (function mcc_() { var antivf = 0; return function() { ++antivf; f1(/*ICCD*/antivf % 4 == 0);};})();");
/*fuzzSeed-159544250*/count=1069; tryItOut("\"use strict\"; o0.h2.fix = f1;");
/*fuzzSeed-159544250*/count=1070; tryItOut("\"use strict\"; Array.prototype.unshift.apply(a0, [this.o0, b2, f1, i1]);");
/*fuzzSeed-159544250*/count=1071; tryItOut("var dszldq = new ArrayBuffer(12); var dszldq_0 = new Float32Array(dszldq); dszldq_0[0] = 13; var dszldq_1 = new Uint32Array(dszldq); dszldq_1[0] = -4; var dszldq_2 = new Int16Array(dszldq); dszldq_2[0] = -20; var dszldq_3 = new Float32Array(dszldq); dszldq_3[0] = 9; var dszldq_4 = new Int16Array(dszldq); dszldq_4[0] = -26; var dszldq_5 = new Float64Array(dszldq); print(dszldq_5[0]); dszldq_5[0] = -10; var dszldq_6 = new Int8Array(dszldq); var dszldq_7 = new Uint8Array(dszldq); print(dszldq_7[0]); dszldq_7[0] = -1; g0.a0 = new Array;o0.s0 = '';\nprint(\"\\uAC1A\");\nv1 = evalcx(\"(dszldq_0\\n)\", g0);Object.defineProperty(this, \"v0\", { configurable: [1,,], enumerable: (dszldq_5[4] % 57 != 23),  get: function() {  return evaluate(\"function f1(g1.p1)  { \\\"use strict\\\"; yield (makeFinalizeObserver('tenured')) } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: /(?!\\b[^])/g })); } });/*MXX1*/o2 = this.o2.g1.RegExp.multiline;");
/*fuzzSeed-159544250*/count=1072; tryItOut("m0.has(this.b2);");
/*fuzzSeed-159544250*/count=1073; tryItOut("\"use strict\"; h0.iterate = (function() { try { v2.__proto__ = g1; } catch(e0) { } try { h2.getOwnPropertyDescriptor = (function() { for (var j=0;j<18;++j) { f1(j%2==1); } }); } catch(e1) { } try { s0 += s0; } catch(e2) { } s1 += 'x'; return p0; });m1.get(a2);");
/*fuzzSeed-159544250*/count=1074; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1075; tryItOut("\"use strict\"; v2 = Proxy.create(h2, s2);g1.v0 = (f1 instanceof b1);");
/*fuzzSeed-159544250*/count=1076; tryItOut("\"use strict\"; t0[v2] = (new (function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: undefined, delete: undefined, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: (void options('strict_mode')).setUint16, hasOwn: function() { throw 3; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; })());");
/*fuzzSeed-159544250*/count=1077; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot((( ! x) ? try { let(y, [] = yield  \"\" , x, NaN, uzlbmd, vatscr, window, ibajmu, lksyzr) ((function(){throw StopIteration;})()); } finally { with({}) let(wjhlun, x =  /x/ , ptbhhl, this.d, pxqlap, vnblxu, y, y, adtgph, zyazur) { let(qrgsew, a) { yield;}} }  : ( + Math.cos(Math.fround(((( + x) | 0) , (-Number.MAX_SAFE_INTEGER | 0)))))), ( + Math.fround((Math.fround(( + Math.sign(( + ( + ( ! (((y >>> 0) === (0x100000001 >>> 0)) >>> 0))))))) ? Math.fround(((Math.cbrt(( - (((Number.MAX_VALUE | 0) * 2**53) | 0))) == (x | 0)) | 0)) : Math.fround(( - Math.acos(-(2**53-2)))))))); }); testMathyFunction(mathy0, /*MARR*/[null, (1/0), (1/0), (1/0), null, null, (1/0), (1/0), null, null, (1/0), null, (1/0), (1/0), null, null, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), null]); ");
/*fuzzSeed-159544250*/count=1078; tryItOut("g0.offThreadCompileScript(\"print(b2);\", ({ global: this.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 49 != 10), sourceIsLazy: (x % 2 == 1), catchTermination: (x % 73 != 57) }));");
/*fuzzSeed-159544250*/count=1079; tryItOut("mathy4 = (function(x, y) { return (Math.pow(( + (Math.fround(((Math.atan((((mathy2(0.000000000000001, 2**53-2) << (y | 0)) | 0) | 0)) | 0) <= ((y | 0) ? ( + (( + x) ^ y)) : (y ** Math.trunc(x))))) / Math.fround(mathy0(Math.atan2((Math.pow((x | 0), (y | 0)) | 0), (( ! Number.MAX_SAFE_INTEGER) >>> 0)), (Math.pow(-0x0ffffffff, Math.acos(y)) | 0))))), ( + Math.acos(( + (Math.cosh(( + (Math.fround(Math.pow(( + x), -0)) | 0))) < (0/0 ? Math.imul(Math.log(x), x) : -Number.MAX_VALUE)))))) >>> 0); }); testMathyFunction(mathy4, [-(2**53-2), Number.MAX_VALUE, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -0x080000000, 0x080000000, 0x100000000, -0x100000001, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 2**53+2, -0, 0x080000001, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -1/0, Number.MIN_VALUE, Math.PI, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, 42, -0x080000001, -Number.MAX_VALUE, 0x0ffffffff, 1]); ");
/*fuzzSeed-159544250*/count=1080; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-159544250*/count=1081; tryItOut("a1[0];");
/*fuzzSeed-159544250*/count=1082; tryItOut("/*RXUB*/var r = new RegExp(\"(((?=(?:(?=[\\\\\\u00ea-\\\\u00ed\\u4870-\\\\u14C9\\\\b-\\\\cV\\\\S]))?){4,4}))\", \"gim\"); var s = \"\"; print(s.replace(r, arguments[(encodeURIComponent).call(undefined, )] = /*FARR*/[...(function() { \"use strict\"; yield Math.acos(-5); } })(), ...(this) for each (\u3056 in  /x/g ) for each (x in 0.971) for each (w in []), ...( /x/  >>> -16), ...((function a_indexing(kgeaqm, hcdzkm) { ; if (kgeaqm.length == hcdzkm) { ; return 14 ^ undefined &= window; } var uhvfyh = kgeaqm[hcdzkm]; var jfvhpk = a_indexing(kgeaqm, hcdzkm + 1); (void schedulegc(g1)); })(/*MARR*/[[1]], 0)), ...( /x/g  if (window)), , ].some( \"\" ,  >= x.unwatch(\"fixed\")), \"ym\")); ");
/*fuzzSeed-159544250*/count=1083; tryItOut("\"use strict\"; var cfercg = new SharedArrayBuffer(0); var cfercg_0 = new Uint32Array(cfercg); cfercg_0[0] = -19; var cfercg_1 = new Int8Array(cfercg); cfercg_1[0] = -7; var cfercg_2 = new Int32Array(cfercg); print(cfercg_2[0]); cfercg_2[0] = -27; var cfercg_3 = new Uint16Array(cfercg); cfercg_3[0] = -21; var cfercg_4 = new Uint8ClampedArray(cfercg); cfercg_4[0] = -1; var cfercg_5 = new Int16Array(cfercg); print(cfercg_5[0]); cfercg_5[0] = -13; var cfercg_6 = new Uint8Array(cfercg); print(cfercg_6[0]); var cfercg_7 = new Int32Array(cfercg); cfercg_7[0] = 28; var cfercg_8 = new Int32Array(cfercg); cfercg_8[0] = -28; yield;Array.prototype.sort.call(a2, NaN.__defineGetter__(\"cfercg_1\", (new Function(\"t1 = new Uint32Array(b0);\"))), h2, new ((4277))(new Function() instanceof (DataView.prototype.getInt8).call(new RegExp(\"\\u9e8e|\\\\2|(?=\\\\x05)\\\\2+?{2}\", \"i\"),  \"\" , false)));23;(cfercg_2.yoyo((void options('strict_mode'))));g1 = this;/*hhh*/function tnkmki(x){h1.iterate = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((288230376151711740.0));\n    {\n      return +(((+((Float64ArrayView[((-0x8000000)) >> 3]))) + (-576460752303423500.0)));\n    }\n    return +((NaN));\n    return +((d1));\n  }\n  return f; });}/*iii*/print(x);v2 = this.p2[new String(\"14\")];print(cfercg_2[7]);");
/*fuzzSeed-159544250*/count=1084; tryItOut("\"use strict\"; Array.prototype.splice.apply(this.o0.a0, []);function NaN(\n) { \"use strict\"; yield (Math.acosh(Math.fround(Math.min((( ~ (Math.log1p((( - Math.fround(-0x07fffffff)) >>> 0)) >>> 0)) | 0), (( + Math.cos(Math.cos((Math.round(x) , Math.pow(Math.fround(2**53), x))))) >>> 0)))) * Math.fround(Math.imul(( + ( ! Math.pow((( + Math.imul(( + Math.trunc(( + x))), x)) | 0), x))), (((Math.tan(( + x)) >>> 0) == (( + ( ! ( + ( ! 0)))) >>> 0)) >>> 0)))) } this.v0 = evalcx(\"function f1(p1)  { return (eval(\\\"/* no regression tests found */\\\", (/*MARR*/[ '' , new Number(1), new String('q'), new String('q'), this,  '' , new String('q'),  '' , 1e4, this, this, 1e4, this, 1e4, new String('q'), 1e4, new Number(1), this, new String('q'), new String('q'), 1e4, new String('q'), this, new Number(1),  '' , this, this,  '' , new Number(1),  '' , new String('q'), new String('q'),  '' , this, new String('q'), this,  '' ,  '' , this, new Number(1), new String('q'), new Number(1),  '' , new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1),  '' , this, new Number(1),  '' , new Number(1), new Number(1), this, this, new String('q'), 1e4,  '' ].some)) ^= yield.setFloat64(x, x)) } \", o0.g1.g2);");
/*fuzzSeed-159544250*/count=1085; tryItOut("v1 = true;");
/*fuzzSeed-159544250*/count=1086; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.tanh((Math.imul(((Math.pow(Math.fround((y / (y | 0))), (-0x100000000 >>> x)) ** ( + Math.pow(( + y), ( + y)))) | 0), Math.fround(Math.cbrt(Math.fround((( + Math.asinh(( + (Math.pow(x, 0x080000000) ? y : -0x100000001)))) >= /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, undefined, objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, undefined, undefined, undefined, objectEmulatingUndefined()]))))) | 0)); }); testMathyFunction(mathy0, [2**53+2, 0, 2**53, -0x100000001, -Number.MIN_VALUE, 42, 0.000000000000001, 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 0/0, -0x07fffffff, 1/0, -0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, 0x100000001, -0, -(2**53), 0x07fffffff, 1, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1087; tryItOut("/*RXUB*/var r = /\\1/gm; var s = \"___\"; print(s.replace(r, new ((this * this))((new [z1,,]())))); ");
/*fuzzSeed-159544250*/count=1088; tryItOut("o2.e1.has(m0);");
/*fuzzSeed-159544250*/count=1089; tryItOut("this.m2 + o2;");
/*fuzzSeed-159544250*/count=1090; tryItOut("\"use strict\"; for (var p in t0) { try { i1 + ''; } catch(e0) { } try { Array.prototype.pop.apply(a0, [b1, this.g1.a0]); } catch(e1) { } t1 = new Uint16Array(7); }");
/*fuzzSeed-159544250*/count=1091; tryItOut("mathy3 = (function(x, y) { return (( - Math.hypot((Math.fround(Math.tan(y)) === x), Math.atan2((x / y), mathy0(y, 0x080000001)))) > Math.fround(( + ( + ((Math.hypot((( ! x) | 0), (Math.fround((x >= y)) >>> 0)) | 0) % ( + -Number.MIN_VALUE)))))); }); testMathyFunction(mathy3, [-0x07fffffff, Number.MAX_VALUE, 1/0, 0, 0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -(2**53+2), -0, 0/0, Math.PI, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, -0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53-2, -0x100000001, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, -0x0ffffffff, -0x100000000, -0x080000000, -(2**53), 0x100000000, -1/0]); ");
/*fuzzSeed-159544250*/count=1092; tryItOut("x;");
/*fuzzSeed-159544250*/count=1093; tryItOut("\"use strict\"; v2 + '';");
/*fuzzSeed-159544250*/count=1094; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -17592186044417.0;\n    d2 = (d2);\n    return ((0xfffff*(/*FFI*/ff(((((i1)) | (((((d2))) != (((-9007199254740992.0)) % ((33554433.0))))))), (((((0x67204680)-((((0xb7cbc090))>>>((0xf82652dc))) != (0xb198a414)))) << ((0xa11c81a6)+((0xfb74b749) ? (0xfba133ad) : (0xfccf6048))+((((0xa8b8cf04))>>>((0x4b906097))))))))|0)))|0;\n    {\n      {\n        d2 = (d2);\n      }\n    }\n    return (((0xbd176232)+(i0)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=1095; tryItOut("\"use strict\"; for (var p in s1) { try { m1.get(a2); } catch(e0) { } try { t2.toString = Object.isSealed.bind(m1); } catch(e1) { } try { a0.forEach((function mcc_() { var hjpplw = 0; return function() { ++hjpplw; f2(/*ICCD*/hjpplw % 3 == 2);};})(), o2, i0, f0); } catch(e2) { } m0 = new Map(g2.g1); }");
/*fuzzSeed-159544250*/count=1096; tryItOut("function ([y]) { };\nlet ufoueq, x, window, axmrpb, fgiygc;print(x);\n");
/*fuzzSeed-159544250*/count=1097; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.cosh((Math.pow(( ! (((mathy0(Math.imul((y | 0), x), Math.exp((2**53-2 | 0))) | 0) ? ( + mathy2(( + y), ( + ( + mathy0(( + x), ( + x)))))) : (Math.max(x, Number.MAX_SAFE_INTEGER) | 0)) | 0)), ((( + Math.fround(( + Math.fround(Math.fround(mathy0(mathy1(Math.fround(x), Math.fround(y)), -0x100000001)))))) || x) | 0)) | 0)); }); testMathyFunction(mathy4, [-(2**53), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 0x080000000, 2**53-2, -0x07fffffff, 2**53, -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, 0x100000000, -Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0, Math.PI, 2**53+2, -(2**53+2), 0x080000001, -0x100000000, -0x080000001, -0x100000001, -0x0ffffffff, Number.MIN_VALUE, 42, -(2**53-2), 1/0]); ");
/*fuzzSeed-159544250*/count=1098; tryItOut("mathy3 = (function(x, y) { return ( ~ ( ! mathy0((y | 0), (Math.log1p(Math.imul(x, 2**53-2)) >>> 0)))); }); ");
/*fuzzSeed-159544250*/count=1099; tryItOut("a2.pop();");
/*fuzzSeed-159544250*/count=1100; tryItOut("let \u000c(a, window, abnhbu) { ; }");
/*fuzzSeed-159544250*/count=1101; tryItOut("v1 = Array.prototype.every.apply(a0, [this.o2.f0]);");
/*fuzzSeed-159544250*/count=1102; tryItOut("mathy1 = (function(x, y) { return ( - (((0.000000000000001 - (((-0x07fffffff >>> 0) / (x | 0)) , ( ! x))) && ( + (( + (1.7976931348623157e308 || Math.clz32(y))) ** ( + 42)))) >>> 0)); }); ");
/*fuzzSeed-159544250*/count=1103; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.tan(( + Math.min(( + ( ~ (x >>> 0))), ((Math.imul((y | 0), x) | 0) < ( + (( + ( - (Math.log10((y >>> 0)) >>> 0))) * ( + 2**53-2))))))) >>> 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 2**53, -0, -Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0, 1, 0x100000000, -0x080000000, 0x080000000, 0/0, -(2**53+2), Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0x07fffffff, -0x100000001, 0.000000000000001, -(2**53-2), -1/0, -(2**53), -0x080000001, 2**53+2, 0x100000001, Number.MIN_VALUE, -0x07fffffff, 1/0]); ");
/*fuzzSeed-159544250*/count=1104; tryItOut("\"use strict\"; { void 0; gcPreserveCode(); }");
/*fuzzSeed-159544250*/count=1105; tryItOut("a1.unshift(a0, t1, a1, a2, s1, s0);");
/*fuzzSeed-159544250*/count=1106; tryItOut("\"use strict\"; p0.__proto__ = g1;");
/*fuzzSeed-159544250*/count=1107; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (Math.pow(Math.fround((Math.imul(42, -0x080000000) || (Math.imul(x, x) >>> 0))), (Math.pow(Math.imul((( - (x ? x : (y >>> 0))) ? y : (( ! (y | 0)) | 0)), y), Math.abs((Math.hypot(( + -Number.MAX_SAFE_INTEGER), ( + (( + x) <= ( + x)))) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-159544250*/count=1108; tryItOut("mathy0 = (function(x, y) { return (((Math.hypot(( ! ( ~ ((Math.atanh(Math.PI) >>> 0) !== (( ~ (y | 0)) | 0)))), Math.min(( + ( + ( + (Math.fround((Math.fround(Math.max(y, -Number.MAX_VALUE)) % Math.fround(x))) <= ( + (2**53+2 === x)))))), ( + ( - -0x100000001)))) >>> 0) >= (Math.max(Math.fround(((Math.tanh(Math.pow(x, ( ~ ( + y)))) > (((Math.clz32(((Math.trunc(( + x)) <= -(2**53)) | 0)) | 0) ? (x | 0) : x) >>> 0)) >>> 0)), ((Math.fround(Math.hypot((( - (Math.fround(( + ( + x))) | 0)) >>> 0), Math.fround(x))) > ( + (( + y) ^ ( + Math.fround((Math.fround(y) !== x)))))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0, -0, 0x100000000, -(2**53+2), 0x080000001, 2**53-2, Math.PI, 1.7976931348623157e308, 0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, 1, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x080000000, -(2**53), 0x0ffffffff, 1/0, 0.000000000000001, -0x080000001, -Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, -0x0ffffffff, 2**53, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=1109; tryItOut("\"use strict\"; o0.__proto__ = o0;");
/*fuzzSeed-159544250*/count=1110; tryItOut("\"use strict\"; print(a1);\nwhile((x) && 0){for (var v of o0) { m1.set(g0.f2, f2); }throw x; }\ns0 += 'x';");
/*fuzzSeed-159544250*/count=1111; tryItOut("\"use strict\"; b2 = t0.buffer;");
/*fuzzSeed-159544250*/count=1112; tryItOut("mathy5 = (function(x, y) { return mathy2(Math.pow(Math.fround(Math.hypot((-0x100000001 >>> 0), Math.fround(( + Math.sin(( + y)))))), ( ~ (( + Math.min(0x080000001, Math.fround((( + Math.imul(y, y)) ? ( + mathy2(y, ( + (( + 42) * ( + y))))) : ((x % x) - -0x100000001))))) | 0))), ((( + ( ! (Math.sinh((x >>> 0)) >>> 0))) ? ( - x) : (((( + y) >> (x >>> 0)) >>> 0) | 0)) ? Math.fround(( + Math.fround((Math.ceil(Math.atan2(y, 0)) | 0)))) : Math.atan2((( ! 0x100000001) >>> 0), Math.pow((x / ((x - 0x0ffffffff) | 0)), (( ~ -0x080000000) >>> 0))))); }); testMathyFunction(mathy5, [1/0, 0, -(2**53), -(2**53+2), 0x0ffffffff, 42, 0x07fffffff, -0x100000000, Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 1, -1/0, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, -0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, -0x07fffffff, -0x100000001, Math.PI, 0.000000000000001, -Number.MAX_VALUE, 0x100000000, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, -0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-159544250*/count=1113; tryItOut("testMathyFunction(mathy1, ['', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), /0/, '0', -0, '/0/', true, 1, (new Number(0)), (new String('')), (new Boolean(true)), (new Boolean(false)), [], ({toString:function(){return '0';}}), (new Number(-0)), 0, '\\0', undefined, (function(){return 0;}), 0.1, NaN, null, false, [0]]); ");
/*fuzzSeed-159544250*/count=1114; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Math.PI, -0x080000000, -(2**53), -0, 0x080000001, -0x100000001, -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 0, -Number.MIN_SAFE_INTEGER, 1/0, 42, -0x07fffffff, -(2**53+2), 0x0ffffffff, 2**53, 2**53-2, -0x100000000, 0x100000001, 0x07fffffff, -1/0, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, Number.MIN_VALUE, -Number.MIN_VALUE, 0/0, 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=1115; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.min((Math.pow(((y ^ ( + ( ! ( + ( + Math.min(Math.pow(x, x), (y | 0))))))) !== y), ( + ( ! ( + mathy0(x, ( ~ Math.imul(x, ( + x)))))))) | 0), (( + Math.round(( + ((( - x) - y) < ( + x))))) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, 1/0, 0x100000000, Math.PI, 0, 0x080000001, 2**53-2, Number.MAX_VALUE, -0x080000000, 0/0, -(2**53-2), 0x100000001, -0x07fffffff, -0x100000001, -0x080000001, 42, 0x080000000, 0x0ffffffff, -0, -1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, -0x0ffffffff, -Number.MIN_VALUE, 2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=1116; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?!(?=(?:[^]*)))){4,8}\", \"g\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=1117; tryItOut("mathy5 = (function(x, y) { return Math.max((Math.max(((Math.asin(( + Math.pow(x, ((Math.min(y, y) | 0) << Math.fround(Number.MIN_VALUE))))) | 0) >>> 0), (((Math.hypot((x >>> 0), (Math.fround(( ~ Math.fround(0.000000000000001))) >>> 0)) >>> 0) >>> (Math.cosh(((Math.atan2((x >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)) | 0), (( + Math.hypot(( + ( + Math.fround(Math.hypot(Math.fround(Math.fround(Math.atan2(Math.fround(2**53-2), Math.fround(y)))), Math.fround(y))))), ( + Math.cbrt(Math.sin(y))))) | 0)); }); testMathyFunction(mathy5, [2**53+2, 0x080000000, 0/0, -(2**53-2), 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, -1/0, -(2**53), -0x080000001, 0x07fffffff, -(2**53+2), 0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, 2**53, Math.PI, 1/0, 0x100000001, -0x100000001, 0x100000000, 0x080000001, -0x100000000, 0, 1]); ");
/*fuzzSeed-159544250*/count=1118; tryItOut("Array.prototype.splice.call(this.a2, 12, (new runOffThreadScript(false,  /x/ )), o1.o2, this.m2, x *= x, b1, new (\"\\u8F04\")() = new false(x, this))\nv2 = Object.prototype.isPrototypeOf.call(b0, b2);");
/*fuzzSeed-159544250*/count=1119; tryItOut("mathy0 = (function(x, y) { return (Math.log((Math.hypot((( ! (x | 0)) | 0), (Math.fround(( + y)) | 0)) | 0)) ? Math.atan2((Math.sqrt(( - x)) >>> 0), Math.imul(((Math.pow((42 >>> 0), (Math.round((x ** x)) >>> 0)) >>> 0) == (42 + ( - Math.fround(1)))), (Math.fround(( + (( - (Number.MIN_VALUE >>> 0)) >>> 0))) / Math.fround(Math.cbrt(Math.fround((Math.exp((Math.atan2(y, y) >>> 0)) >>> 0))))))) : (Math.hypot(Math.sin(Math.log1p(Math.tanh(-0x0ffffffff))), (Math.atanh((x >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [2**53-2, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 1/0, -0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 42, -1/0, Math.PI, -0x07fffffff, -0x0ffffffff, 0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, 1, -Number.MAX_SAFE_INTEGER, 0, 2**53, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, 0x100000000, -0x080000000, -Number.MIN_VALUE, 0/0, -(2**53), -0x100000001, 0x07fffffff, -(2**53+2), 0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=1120; tryItOut("r1 = new RegExp(\"\\\\1\", \"gyi\");");
/*fuzzSeed-159544250*/count=1121; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[({}), (4277), ['z'], (4277), ['z'], ({}),  /x/g ,  /x/g , (4277), ({}), ['z'], ({}), 2**53+2, (4277), 2**53+2,  /x/g , ['z'], ({}), ['z'], (4277), 2**53+2, ['z'], (4277), ['z'], ({}), ['z'], 2**53+2, 2**53+2,  /x/g , 2**53+2, ({}), 2**53+2, ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], 2**53+2, ({}),  /x/g ,  /x/g , 2**53+2,  /x/g , ({}), 2**53+2, ['z'], ['z'],  /x/g , 2**53+2, ['z'], 2**53+2]) { v1 = a2.reduce, reduceRight((function() { e1.delete(m1); throw v2; }), s1); }");
/*fuzzSeed-159544250*/count=1122; tryItOut("mathy3 = (function(x, y) { return ((Math.acosh(Math.atanh(( + mathy1((0x07fffffff | 0), (-(2**53+2) | 0))))) + ( + Math.imul(( + x), (Math.atan2((y | 0), (( ! (-(2**53-2) >>> 0)) >>> 0)) | 0)))) !== ((Math.fround((Math.asinh(Math.pow((19 | 0), (2**53-2 | 0))) | 0)) | 0) << (x % Math.hypot(Math.fround(( + ( + -(2**53-2)))), x)))); }); testMathyFunction(mathy3, /*MARR*/[[1], {}, true, true, [1], {}, {}, true, [1], true, true, [1], true, {}, [1], {}, {}, true, {}, true, {}, {}, {}, [1], [1], {}, {}, true, [1], [1], {}, true, true, true, [1], true, true, {}, [1], [1], true, {}, [1], [1]]); ");
/*fuzzSeed-159544250*/count=1123; tryItOut("a1 = r1.exec(s2);");
/*fuzzSeed-159544250*/count=1124; tryItOut("mathy5 = (function(x, y) { return ( + Math.round(Math.fround(Math.min((( + (Math.fround(( + Math.fround(42))) === 2**53+2)) / y), ((x === (( ! (((( + y) >>> 0) < ( + Math.pow(y, (0x07fffffff >>> x)))) >>> 0)) | 0)) >>> 0))))); }); testMathyFunction(mathy5, [42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, 0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 1.7976931348623157e308, 0x0ffffffff, -0x100000001, 0x080000000, 2**53-2, -Number.MIN_VALUE, 0.000000000000001, -1/0, 0x100000000, -0x0ffffffff, -0x080000001, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, -0, 0/0, 0x080000001, 2**53+2, -(2**53-2), Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1125; tryItOut("\"use strict\"; /*infloop*/for(var [] = window; (void options('strict_mode')) += window !== /[^\\w\\w\\0\\w]{4,}/im; x) a2.forEach((function() { for (var j=0;j<121;++j) { f0(j%5==1); } }));t0 = new Int8Array(b0, 6, 1);");
/*fuzzSeed-159544250*/count=1126; tryItOut("let rbdmlp, z, w = 0, \u3056, w;if( '' ) for (var v of p0) { m1 = new Map(this.b0); } else  if (new RegExp(\"\\\\w|\\\\d[\\\\w\\\\d\\\\u00D3-\\\\\\u00f1].?\\\\b|^*[\\\\xf9\\u0018]|.|^|\\\\1|(?!\\u00b2[\\u001d-\\\\\\u4692h\\\\W\\\\d])\", \"gy\")) /*MXX3*/g2.Map.prototype.set = g1.Map.prototype.set;\u000c else { \"\" ;true; }");
/*fuzzSeed-159544250*/count=1127; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(( + Math.fround(((((y / ( + (( + (y , (1/0 | 0))) || x))) >>> 0) >> y) >= ( ~ (x > Math.abs(y)))))), Math.fround(( ! Math.fround((( ~ (( ~ (x >>> 0)) >>> 0)) | 0))))); }); testMathyFunction(mathy2, [1, -0x080000001, -(2**53-2), Number.MAX_VALUE, 2**53-2, -0x100000001, 1/0, Number.MIN_VALUE, -0, 42, 0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0.000000000000001, 0x100000001, 0x080000000, -Number.MIN_VALUE, 0x100000000, 2**53, -0x100000000, -0x0ffffffff, Math.PI, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000]); ");
/*fuzzSeed-159544250*/count=1128; tryItOut("v0 = (o2.s1 instanceof g2);");
/*fuzzSeed-159544250*/count=1129; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return Math.fround(Math.trunc(( + Math.atan2(Math.fround(Math.round((( + (x != y)) ? Math.cbrt(( + x)) : ( + mathy1(y, mathy1((Math.asinh((x >>> 0)) | 0), y)))))), Math.fround(Math.sin((Math.PI >>> 0))))))); }); testMathyFunction(mathy2, [1.7976931348623157e308, -(2**53+2), 0/0, -0x07fffffff, -0x0ffffffff, 0x100000000, -0, 0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), Number.MIN_VALUE, Math.PI, 0.000000000000001, 2**53, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, -1/0, -0x080000001, 0x080000001, 1/0, 0x080000000, 0, -0x100000000, 2**53-2, 42, 0x100000001]); ");
/*fuzzSeed-159544250*/count=1130; tryItOut("a0.sort(f1);");
/*fuzzSeed-159544250*/count=1131; tryItOut("v0 = (x % 5 != 0);");
/*fuzzSeed-159544250*/count=1132; tryItOut("Array.prototype.shift.apply(a1, [f0, g0.o1.h1]);");
/*fuzzSeed-159544250*/count=1133; tryItOut("if(false) var abyxar;print(x); else  if ((Math.imul(\"\\u0C79\", z) %= x)) [[1]];");
/*fuzzSeed-159544250*/count=1134; tryItOut("i1 = new Iterator(v2);");
/*fuzzSeed-159544250*/count=1135; tryItOut("\"use strict\"; /*infloop*/for((x) in Math.atan(-9)) e1 + '';");
/*fuzzSeed-159544250*/count=1136; tryItOut("/*tLoop*/for (let e of /*MARR*/[undefined, undefined, undefined, undefined, x, x, x, undefined, undefined, x, undefined, undefined, x, undefined]) { h0 = a1; }");
/*fuzzSeed-159544250*/count=1137; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(( - (( + mathy0(x, ((mathy0(-0x080000000, y) >>> 0) != x))) | 0)))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0, -0x100000000, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, -(2**53+2), -0, Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE, 0/0, 0x080000000, 2**53, Math.PI, -(2**53), 0x100000001, 0x100000000, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, 1, -0x080000000, 2**53-2, 2**53+2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, 1/0, 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -1/0]); ");
/*fuzzSeed-159544250*/count=1138; tryItOut("o0.v0 = g2.eval(\"(q => q)\");");
/*fuzzSeed-159544250*/count=1139; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"NaN\");");
/*fuzzSeed-159544250*/count=1140; tryItOut("testMathyFunction(mathy3, [1, 1.7976931348623157e308, -1/0, 2**53+2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0x080000000, -0x07fffffff, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, Number.MIN_SAFE_INTEGER, 42, -0x080000000, 2**53-2, 0, 0x0ffffffff, -Number.MIN_VALUE, 2**53, -(2**53-2), 0x100000000, -0x080000001, -0x100000001, 1/0, Number.MIN_VALUE, -0, Math.PI, 0x080000001]); ");
/*fuzzSeed-159544250*/count=1141; tryItOut("\"use strict\"; {s1 + ''; }");
/*fuzzSeed-159544250*/count=1142; tryItOut("mathy0 = (function(x, y) { return ( + Math.imul(( + ((Math.fround(Math.pow((( - ( + Math.cosh(y))) >>> 0), ((Math.fround(( ~ Math.fround(Math.max(y, (((-0x100000001 | 0) << Math.fround(x)) | 0))))) | 0) >>> 0))) ? Math.fround(Math.acosh(Math.imul((Math.max(y, (x >>> 0)) >>> 0), (( - ( + Math.fround(-Number.MAX_SAFE_INTEGER))) >>> 0)))) : (( + (Math.atan2(Math.sign(y), (Math.abs((x >>> 0)) >>> 0)) >>> 0)) !== (( ~ ((x , (Math.atanh((Math.pow(-1/0, Math.fround(y)) | 0)) | 0)) | 0)) >>> 0))) | 0)), ( + ((((Math.max((( - ( + Math.log10(( + Number.MAX_SAFE_INTEGER)))) >>> 0), (Math.pow(x, x) >>> 0)) >>> 0) | 0) && ((Math.sign(Math.sinh((Math.imul((-0x100000001 >>> 0), Math.fround(Math.max(Math.fround(Math.cosh(x)), Math.fround(Math.atan(1/0))))) >>> 0))) | 0) >>> 0)) | 0)))); }); testMathyFunction(mathy0, [0x080000000, 0x07fffffff, -Number.MAX_VALUE, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, Math.PI, 1, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, -0x080000000, 42, -1/0, 2**53, -0x07fffffff, 1/0, 1.7976931348623157e308, 0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 2**53-2, -Number.MIN_VALUE, 0, -(2**53), -0]); ");
/*fuzzSeed-159544250*/count=1143; tryItOut("v1 = Object.prototype.isPrototypeOf.call(p2, t0);");
/*fuzzSeed-159544250*/count=1144; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\1{2,}\ufcff?)+/; var s = \"\"; print(s.replace(r, this.c = (4277))); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1145; tryItOut("/*hhh*/function wjgfzj(x, \u3056){w = (void options('strict_mode'));/*infloop*/for(var {} = 25; \"\\uDFDB\"; let (w, ddljzg, nxyheg, jrdtil) -28) a2.pop();}/*iii*//* no regression tests found */");
/*fuzzSeed-159544250*/count=1146; tryItOut("\"use strict\"; /*RXUB*/var r = /$*/yim; var s = \"\\uae34\\nd\\n\\n\\uae34\\nd\\n\\n\\uae34\\nd\\n\\n\\uae34\\nd\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-159544250*/count=1147; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[new String('q'), new String('q'), new Boolean(false), new Boolean(false), new String('q'),  /x/g ,  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  /x/g , new String('q'),  /x/g , new String('q'),  /x/g , new Boolean(false), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(false), new String('q'), new String('q'),  /x/g , new String('q'), new String('q'),  /x/g , new String('q'), new String('q'),  /x/g , new String('q'),  /x/g ,  /x/g , new String('q'), new String('q'), new String('q'),  /x/g , new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(false), new String('q'),  /x/g ,  /x/g ]) { for(var [a, e] = ((yield (/*MARR*/[function(){}, function(){}, null, null,  '\\0' ,  '\\0' ,  '' ,  '' , null,  '\\0' ,  '\\0' ,  '\\0' , function(){},  '\\0' , function(){}, function(){}, null,  '\\0' , null,  '\\0' ,  '' ,  '' ,  '\\0' ].map(new RegExp(\"[^\\\\xa7\\\\v]|(?!.)\\\\3|.*+\", \"gm\"))))) in (makeFinalizeObserver('tenured')) >>>= a) (a); }");
/*fuzzSeed-159544250*/count=1148; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + Math.round(Math.hypot(((( + Math.min((y >>> 0), (x >>> 0))) ? x : Math.fround(y)) >>> 0), Math.hypot((x >>> 0), Math.pow((x % 0x07fffffff), ( + Math.min(( + (Math.tan((y >>> 0)) >>> 0)), ( + y)))))))) , ( + ( + Math.tanh(((x ? Math.cos(Math.log2(( ! (y | 0)))) : (Math.fround(y) >= Math.fround(( + Math.pow(( + (Math.sinh(x) | 0)), (-1/0 | 0)))))) | 0)))))); }); ");
/*fuzzSeed-159544250*/count=1149; tryItOut("\"use strict\"; v2 = (h0 instanceof a0);");
/*fuzzSeed-159544250*/count=1150; tryItOut("\"use strict\"; delete o1[\"-10\"];");
/*fuzzSeed-159544250*/count=1151; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 129.0;\n    var i3 = 0;\n    var i4 = 0;\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, -0x100000000, 2**53-2, -1/0, -(2**53), Math.PI, 0x080000001, -0x080000001, 0x0ffffffff, -0x100000001, -0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, 0, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0, 0/0, 1/0, Number.MAX_VALUE, 2**53+2, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=1152; tryItOut("\"use strict\"; (this);\nprint(x);\n");
/*fuzzSeed-159544250*/count=1153; tryItOut("\"use strict\"; Array.prototype.pop.apply(a0, [e0, s2, s0, h2]);");
/*fuzzSeed-159544250*/count=1154; tryItOut("e1.delete(v1);");
/*fuzzSeed-159544250*/count=1155; tryItOut("\"use strict\"; \"use asm\"; a0 = /*MARR*/[(0/0), (-1/0), [], (0/0), (void 0), (0/0)];");
/*fuzzSeed-159544250*/count=1156; tryItOut("t0[19] = b2;");
/*fuzzSeed-159544250*/count=1157; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1158; tryItOut("Array.prototype.sort.apply(a1, [(function() { try { s0 += 'x'; } catch(e0) { } m0 = Proxy.create(h1, e1); return e0; }), (( + ( - x)) << ( + Math.round(x))), s2, s2, s0, g0, h0]);");
/*fuzzSeed-159544250*/count=1159; tryItOut("testMathyFunction(mathy2, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 42, 1/0, 0.000000000000001, -0x100000001, -0x0ffffffff, -0x080000000, Math.PI, 2**53-2, 1, 1.7976931348623157e308, 2**53+2, 0/0, 0x080000001, -(2**53-2), -0x080000001, 2**53, 0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -(2**53), -0, -1/0, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1160; tryItOut("\"use strict\"; o1.v2 = g0.a2.length;");
/*fuzzSeed-159544250*/count=1161; tryItOut("i2.toString = (function() { try { h0.getOwnPropertyNames = f0; } catch(e0) { } try { s2 += 'x'; } catch(e1) { } try { m2.get(h0); } catch(e2) { } g2.t0 + ''; return g0; });d = (4277);");
/*fuzzSeed-159544250*/count=1162; tryItOut("Array.prototype.forEach.apply(a2, [(function(j) { if (j) { v0 = (o1 instanceof t0); } else { try { o2.g1.a2.splice(-3, ({valueOf: function() { p2.valueOf = (function() { this.a2 = a2[8]; return b2; });return 0; }}), v0); } catch(e0) { } try { for (var p in a1) { m2.has(o1); } } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(o2.v0, this.f0); } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(g1.f0, g0); } }), f1, b2]);");
/*fuzzSeed-159544250*/count=1163; tryItOut("g1.v1 = a2.length;");
/*fuzzSeed-159544250*/count=1164; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.cos((( + (mathy1((x >>> 0), (-0 >>> 0)) >>> 0)) === ( + Math.fround(mathy1(Math.fround((( - ( + mathy0(( + (Math.fround(y) ** ( + mathy0(y, y)))), -Number.MAX_VALUE))) | 0)), Math.fround((Math.pow(Math.fround(Math.acos(Math.fround(y))), ( + ( ~ 0x080000001))) >>> 0))))))); }); testMathyFunction(mathy2, [-0x0ffffffff, Number.MAX_VALUE, -(2**53+2), 0x07fffffff, -0, -(2**53), 0x080000000, 0x080000001, 0/0, 1/0, -Number.MIN_VALUE, 2**53, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, 2**53+2, -0x07fffffff, -0x080000000, -1/0, 42, 1.7976931348623157e308, Number.MIN_VALUE, Math.PI, -0x100000001, 0x100000000, 0.000000000000001, 2**53-2, -0x100000000, -(2**53-2), 1, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001]); ");
/*fuzzSeed-159544250*/count=1165; tryItOut("L: o2.t1[g0.v1] = g0.t1;");
/*fuzzSeed-159544250*/count=1166; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((( ! Math.fround(Math.imul(Math.fround((y && ( + Math.sin(( + y))))), Math.fround((( ~ (2**53+2 | 0)) | 0))))) ? Math.atan2((Math.fround(Math.sin(Math.sqrt((Math.acosh(Number.MIN_VALUE) >>> 0)))) | 0), (Math.asin(y) | 0)) : ((( + Math.imul(Math.imul(y, -(2**53-2)), (Math.__defineSetter__(\"function ([y]) { }\", Proxy)))) >= ( + -Number.MIN_VALUE)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0, -0x080000000, -(2**53-2), Number.MAX_VALUE, 0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -(2**53+2), 2**53, 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -0x100000001, 0x07fffffff, 2**53+2, 0.000000000000001, -0x080000001, 42, -0, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, Math.PI, -1/0, 0x080000001, 0x0ffffffff, 0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1167; tryItOut("o1.__iterator__ = f1;");
/*fuzzSeed-159544250*/count=1168; tryItOut("/*RXUB*/var r = /(?!(?:(?:\\x8c){3,}|\\1(?!\\b)|$+)*?)/ym; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=1169; tryItOut("mathy2 = (function(x, y) { return Math.min(( - (Math.fround((Math.fround(Math.fround(Math.pow(-Number.MAX_SAFE_INTEGER, Math.acos(-(2**53+2))))) || Math.fround(Math.sign(( + Math.pow(( + y), y)))))) >>> 0)), (mathy0((Math.hypot(Math.fround((Math.fround(( ! Math.log(x))) >> (Math.imul((y | 0), ((1 ? y : (x | 0)) | 0)) | 0))), ( + ( ~ ( + y)))) | 0), ((( ~ ( ~ (y | 0))) + x) | 0)) | 0)); }); testMathyFunction(mathy2, [0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, 1, -Number.MIN_VALUE, -(2**53+2), -(2**53), -(2**53-2), -Number.MAX_VALUE, -0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, 1/0, 0x100000001, 0/0, Math.PI, -0x07fffffff, 0x07fffffff, -0x100000000, 1.7976931348623157e308, 2**53, 0, 42, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -0, 0x100000000, 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-159544250*/count=1170; tryItOut("v1 = evalcx(\"(Math.abs(-11))\", o2.g2);");
/*fuzzSeed-159544250*/count=1171; tryItOut("var a0 = a1.slice(-14, -7);");
/*fuzzSeed-159544250*/count=1172; tryItOut("testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 0x100000000, 2**53, -Number.MIN_VALUE, Math.PI, 0x100000001, 2**53-2, 0, 0x07fffffff, -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, 42, -1/0, -(2**53), 2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 1, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 1/0, -0x0ffffffff, -(2**53+2), -0x080000000, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=1173; tryItOut("window = Proxy.create(({/*TOODEEP*/})(false), [,]);");
/*fuzzSeed-159544250*/count=1174; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-Number.MIN_VALUE, -(2**53+2), 0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 1/0, 42, -0x080000000, -0x080000001, 1.7976931348623157e308, 0x100000001, 0, Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, 2**53+2, 0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, -(2**53-2), -0x100000000, 0x0ffffffff, -0x07fffffff, 0x100000000, -(2**53), -0x100000001, -Number.MAX_VALUE, 2**53, 0/0]); ");
/*fuzzSeed-159544250*/count=1175; tryItOut("mathy1 = (function(x, y) { return ( + Math.imul(( + Math.fround((Math.fround(Math.fround((Math.fround(Math.fround(Math.hypot((((y || (y * ( + (( + x) >> y)))) >>> 0) >>> 0), (y == ( - x))))) << Math.fround(x)))) == Math.fround((( + 0x100000000) - Math.fround((y || (((y | 0) / (((( ! Number.MAX_VALUE) || (y | 0)) | 0) | 0)) | 0)))))))), (( + Math.hypot(( + ( ! (mathy0((y >>> x), ((((((y >>> 0) > (y | 0)) >>> 0) | 0) ** (x | 0)) | 0)) >>> 0))), Math.fround(( + (Math.exp(Math.fround(Math.asin(Math.fround(x)))) && Math.fround(Math.cosh(Math.fround(x)))))))) | 0))); }); ");
/*fuzzSeed-159544250*/count=1176; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + (( + (((( ~ (( ~ Math.fround(Math.hypot(Math.fround(( ~ Math.fround((( + (2**53 >>> 0)) >>> 0)))), Math.fround(Math.fround(Math.exp(Math.fround(Math.fround(y)))))))) >>> 0)) >>> 0) == ( + mathy0(y, Math.fround(( + ( + mathy1(x, (Math.imul((Math.min((x | 0), x) | 0), x) >>> 0)))))))) >>> 0)) === ( + Math.imul(Math.imul(Math.fround(Math.pow(Math.fround(-(2**53-2)), Math.fround(mathy0(Math.fround(Math.acos(Math.fround(y))), ( + ( ! x)))))), y), ( - (y | 0)))))); }); ");
/*fuzzSeed-159544250*/count=1177; tryItOut("testMathyFunction(mathy4, [-(2**53-2), -0x100000000, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, -0x07fffffff, 0, 2**53-2, -0x100000001, Math.PI, 0x100000001, 0x07fffffff, -1/0, 1/0, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 42, 0x100000000, 2**53+2, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), 0/0, Number.MAX_SAFE_INTEGER, 1, 0x080000000, -(2**53+2), 1.7976931348623157e308, 0x0ffffffff, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-159544250*/count=1178; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1179; tryItOut("mathy3 = (function(x, y) { return (mathy0(( + Math.imul(Math.fround(Math.fround(Math.fround((( - Math.fround(Math.exp((( - x) >>> 0)))) | 0)))), mathy2(1.7976931348623157e308, ( + Math.pow(( + Math.atan(Math.fround(mathy0(y, y)))), ( + (Math.hypot((-1/0 | 0), (mathy2(y, ( + y)) | 0)) | 0))))))), (( + (( + ( ~ (( + (y == (((-0 >>> 0) + (Math.fround(Math.log10(Math.fround(y))) >>> 0)) >>> 0))) || -Number.MAX_VALUE))) != (Math.pow(Math.pow(Number.MIN_SAFE_INTEGER, (-1/0 >>> 0)), Math.sinh(Math.atan2(x, x))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [2**53+2, 0x100000001, -(2**53), -(2**53+2), 0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -(2**53-2), 0x080000001, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, 1/0, Number.MIN_VALUE, 0/0, 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_VALUE, 42, -Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -0x07fffffff, -1/0, 1, -0x080000000, 2**53-2, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1180; tryItOut("t1 = new Int8Array(a2);");
/*fuzzSeed-159544250*/count=1181; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        i0 = (((-67108864.0)));\n      }\n    }\n    i0 = (i0);\n    d1 = (+(((!(0xccf68265)))>>>((0x12577fe3))));\n    return +((-274877906945.0));\n  }\n  return f; })(this, {ff: (Array.prototype.toLocaleString).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x080000001, 0x100000001, -0x100000000, -0, -(2**53), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 0x07fffffff, Math.PI, Number.MIN_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -0x100000001, 42, -Number.MAX_VALUE, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, -Number.MIN_VALUE, 2**53+2, -0x080000000, 1, -1/0, Number.MAX_VALUE, 0/0, 0x080000000]); ");
/*fuzzSeed-159544250*/count=1182; tryItOut("m2.delete(e1);");
/*fuzzSeed-159544250*/count=1183; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"begin\" }); } p1 + '';");
/*fuzzSeed-159544250*/count=1184; tryItOut("");
/*fuzzSeed-159544250*/count=1185; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.imul(Math.acosh(mathy4(( + x), (y + Math.fround(Math.pow(Math.fround(x), Math.trunc(x)))))), Math.fround((((( + (y | 0)) >>> 0) >>> 0) ? ((Math.hypot((2**53-2 >>> 0), (( + y) >>> 0)) >>> 0) >>> 0) : (( ! (0/0 ? ( ~ (0x07fffffff >>> 0)) : ( + y))) >>> 0))))); }); ");
/*fuzzSeed-159544250*/count=1186; tryItOut("\"use strict\"; v2 = (s1 instanceof g2.b1);");
/*fuzzSeed-159544250*/count=1187; tryItOut("t2 = new Uint32Array(t0);");
/*fuzzSeed-159544250*/count=1188; tryItOut("mathy5 = (function(x, y) { return ( ! (Math.log10(Math.log1p(( + x))) >>> 0)); }); testMathyFunction(mathy5, [(function(){return 0;}), 0.1, ({valueOf:function(){return '0';}}), 0, objectEmulatingUndefined(), true, /0/, (new Number(-0)), (new Boolean(false)), [0], null, '\\0', false, '/0/', ({toString:function(){return '0';}}), undefined, '', (new Boolean(true)), -0, ({valueOf:function(){return 0;}}), (new String('')), [], (new Number(0)), 1, NaN, '0']); ");
/*fuzzSeed-159544250*/count=1189; tryItOut("\"use strict\"; v0 = new Number(t1);");
/*fuzzSeed-159544250*/count=1190; tryItOut("testMathyFunction(mathy0, [(new Boolean(true)), '0', (new Number(0)), (new String('')), ({toString:function(){return '0';}}), 1, NaN, /0/, [0], null, (function(){return 0;}), ({valueOf:function(){return '0';}}), undefined, (new Boolean(false)), 0, false, objectEmulatingUndefined(), '\\0', '', 0.1, ({valueOf:function(){return 0;}}), (new Number(-0)), '/0/', true, -0, []]); ");
/*fuzzSeed-159544250*/count=1191; tryItOut("mathy3 = (function(x, y) { return Math.abs(( + (( + mathy2((Math.hypot(((Math.fround(x) ? x : Math.fround(x)) | 0), ( + x)) | 0), Math.atan2(((y >>> Math.hypot(x, x)) >>> 0), y))) < ( + ((Math.tanh(((0/0 * x) | 0)) | 0) >> y))))); }); testMathyFunction(mathy3, [0x0ffffffff, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, 0x07fffffff, 1, -(2**53), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -(2**53+2), 0.000000000000001, 0x100000000, 0, 1/0, 2**53, -0x0ffffffff, 0/0, 1.7976931348623157e308, 2**53-2, -Number.MIN_VALUE, -1/0, 2**53+2, -0, -0x100000000, 42, -0x080000000, Math.PI]); ");
/*fuzzSeed-159544250*/count=1192; tryItOut("\"use strict\"; o1.v0 = Object.prototype.isPrototypeOf.call(g0, f1);");
/*fuzzSeed-159544250*/count=1193; tryItOut("m1.delete(b0);");
/*fuzzSeed-159544250*/count=1194; tryItOut("/*RXUB*/var r = /(?:\\u0086|[^]{4194303}){1,4}/gim; var s = \"\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\\u0086\"; print(r.test(s)); h1 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.push.apply(a2, [o1.o1.o1, i1]);; var desc = Object.getOwnPropertyDescriptor(g2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { m1 = new WeakMap;; var desc = Object.getPropertyDescriptor(g2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v2 = evaluate(\"print(this.o1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 == 0), noScriptRval: (x % 4 == 1), sourceIsLazy: false, catchTermination: true, element: this.g2.o1, elementAttributeName: s2 }));; Object.defineProperty(g2, name, desc); }, getOwnPropertyNames: function() { s2 = new String(h2);; return Object.getOwnPropertyNames(g2); }, delete: function(name) { s1.__proto__ = o2;; return delete g2[name]; }, fix: function() { /*RXUB*/var r = r0; var s = s1; print(s.split(r)); ; if (Object.isFrozen(g2)) { return Object.getOwnProperties(g2); } }, has: function(name) { /*RXUB*/var r = r0; var s = \"\"; print(s.replace(r, r, \"i\")); print(r.lastIndex); ; return name in g2; }, hasOwn: function(name) { v0 = Object.prototype.isPrototypeOf.call(g0, i2);; return Object.prototype.hasOwnProperty.call(g2, name); }, get: function(receiver, name) { t0 + '';; return g2[name]; }, set: function(receiver, name, val) { return g1; g2[name] = val; return true; }, iterate: function() { h1.getPropertyDescriptor = f0;; return (function() { for (var name in g2) { yield name; } })(); }, enumerate: function() { a2.pop();; var result = []; for (var name in g2) { result.push(name); }; return result; }, keys: function() { g1.m1.delete(p0);; return Object.keys(g2); } });");
/*fuzzSeed-159544250*/count=1195; tryItOut("\"use strict\"; testMathyFunction(mathy3, [2**53+2, -1/0, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 2**53-2, -Number.MIN_VALUE, 0.000000000000001, -(2**53), -0x07fffffff, -0x080000000, 2**53, Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, -0, 0x100000000, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, -0x100000001, -(2**53+2), 0x080000000, 1/0, Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 42]); ");
/*fuzzSeed-159544250*/count=1196; tryItOut("testMathyFunction(mathy5, [-0x100000001, 0x100000001, 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, -0x080000000, -(2**53+2), 0.000000000000001, Math.PI, -(2**53), 0, -1/0, 2**53+2, -0x080000001, 0/0, -(2**53-2), 1/0, -Number.MIN_SAFE_INTEGER, -0, 0x080000000, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_VALUE, 1, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-159544250*/count=1197; tryItOut("c = linkedList(c, 5330);");
/*fuzzSeed-159544250*/count=1198; tryItOut("\"use strict\"; g1.p1.toString = f0;");
/*fuzzSeed-159544250*/count=1199; tryItOut("v2 = r0.compile;");
/*fuzzSeed-159544250*/count=1200; tryItOut("mathy5 = (function(x, y) { return Math.pow((((Math.cosh(x) | 0) , (Math.asinh(Math.fround((Math.fround(Math.pow(Math.fround((((x | 0) ^ (y | 0)) | 0)), Math.fround(mathy1(y, Number.MIN_SAFE_INTEGER)))) != (Math.pow((x ** y), (x | 0)) | 0)))) | 0)) >>> 0), (( + ((Math.pow(Math.PI, (y >>> 0)) >>> 0) >> mathy2(y, -Number.MIN_SAFE_INTEGER))) >>> 0)); }); ");
/*fuzzSeed-159544250*/count=1201; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=1202; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.fround(Math.min(Math.fround(mathy1(( + ( + Math.sinh(( + ((( + (x >>> 0)) >>> 0) >>> ( + y)))))), Math.fround(Math.exp(( + mathy3(Math.asin(y), ( + ((0x0ffffffff >>> 0) > 0x100000001)))))))), Math.fround(((( + Math.log10(( + Math.imul((x >>> 0), (y >>> 0))))) <= ( + (Math.fround(Math.pow(( + (y || Math.fround(x))), y)) ? y : Math.max(((x != Math.fround(x)) >>> 0), 2**53-2)))) >>> 0)))) || Math.fround(Math.atan2(Math.fround(Math.sign(Math.fround((Math.fround(( + Math.min(( + x), ( + 0x080000000)))) > Math.fround(Math.fround(Math.imul(y, Number.MAX_SAFE_INTEGER))))))), (Math.min(Math.fround(Math.imul(Math.fround((Math.fround(y) % Math.pow(Math.fround(y), x))), Math.acosh(( ~ x)))), ((((Math.atanh(x) | 0) | (mathy3(Math.hypot(y, x), -Number.MIN_SAFE_INTEGER) | 0)) | 0) | 0)) | 0)))); }); testMathyFunction(mathy4, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53, 0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -0, 0x07fffffff, -0x080000001, 2**53+2, 0, -(2**53), -0x080000000, 1/0, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 2**53-2, 0/0, -Number.MAX_VALUE, 0x100000000, Number.MIN_VALUE, 42, 0x100000001, 1, -0x100000000, Number.MAX_VALUE, -1/0, 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=1203; tryItOut("for (var p in a0) { try { v1 = g1.eval(\"/* no regression tests found */\"); } catch(e0) { } o2.s2 += 'x'; }");
/*fuzzSeed-159544250*/count=1204; tryItOut("\"use strict\"; a1.toSource = (function mcc_() { var uvencc = 0; return function() { ++uvencc; if (uvencc > 4) { dumpln('hit!'); try { s1 = a0.join(s1, p0, a1); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(s1, g0); } catch(e1) { } this.v2 = t2.byteOffset; } else { dumpln('miss!'); try { e2.add(i1); } catch(e0) { } print(o1); } };})();");
/*fuzzSeed-159544250*/count=1205; tryItOut("mathy1 = (function(x, y) { return ( + Math.hypot((Math.max(y, Math.acos(y)) / ( + ( + ( + ( ! (Math.max(x, (Math.fround(Math.min(Math.fround(x), Math.fround(Math.PI))) >>> 0)) >>> 0)))))), Math.atan2(((Math.min((( + y) >>> 0), (x ? Math.fround((Math.fround((Math.pow(Math.fround(y), (y >>> 0)) | 0)) || -Number.MIN_SAFE_INTEGER)) : ( + -0x080000001))) >>> 0) | 0), Math.log1p(y)))); }); ");
/*fuzzSeed-159544250*/count=1206; tryItOut("print(uneval(s1));");
/*fuzzSeed-159544250*/count=1207; tryItOut("\"use strict\"; var rdwfds = new ArrayBuffer(1); var rdwfds_0 = new Int32Array(rdwfds); var rdwfds_1 = new Uint8ClampedArray(rdwfds); var rdwfds_2 = new Float32Array(rdwfds); var rdwfds_3 = new Uint16Array(rdwfds); print(rdwfds_3[0]); var rdwfds_4 = new Uint32Array(rdwfds); rdwfds_4[0] = 16; var rdwfds_5 = new Float64Array(rdwfds); rdwfds_5[0] = 7; var rdwfds_6 = new Float64Array(rdwfds); print(rdwfds_6[0]); rdwfds_6[0] = -5; print(x);m0.delete(this.p1);a1.unshift();a1.unshift(h0, g0.s0, e1);(this ? /\\B\u00c3/gy : this);s0 += 'x';");
/*fuzzSeed-159544250*/count=1208; tryItOut("\"use strict\"; f2(h0);");
/*fuzzSeed-159544250*/count=1209; tryItOut("");
/*fuzzSeed-159544250*/count=1210; tryItOut("Object.defineProperty(this, \"v0\", { configurable: false, enumerable: false,  get: function() { v1 = evaluate(\"function f0(t0)  { \\\"use strict\\\"; yield t0 } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 0), noScriptRval: x, sourceIsLazy: (x % 42 == 40), catchTermination: true })); return new Number(NaN); } });");
/*fuzzSeed-159544250*/count=1211; tryItOut("/*infloop*/for(let x in (('fafafa'.replace(/a/g,  /x/g ).toString)(((void options('strict')))))){Array.prototype.sort.apply(a1, [(function() { s1 += s0; throw b1; })]);a2.pop(this.h1, i0); }");
/*fuzzSeed-159544250*/count=1212; tryItOut("selectforgc(o2);");
/*fuzzSeed-159544250*/count=1213; tryItOut("this.i0.next();");
/*fuzzSeed-159544250*/count=1214; tryItOut("m0.set( '' , e1);");
/*fuzzSeed-159544250*/count=1215; tryItOut("e1 = g1.objectEmulatingUndefined();");
/*fuzzSeed-159544250*/count=1216; tryItOut("\"use strict\"; this.o0.a0.unshift(h2, a1);");
/*fuzzSeed-159544250*/count=1217; tryItOut("m2.delete(this.s0);(x);");
/*fuzzSeed-159544250*/count=1218; tryItOut("\"use strict\"; i2.send(b0);for (var p in b0) { try { a1.shift(f2, m1); } catch(e0) { } try { i1 = o1.a0.entries; } catch(e1) { } m1 + ''; }");
/*fuzzSeed-159544250*/count=1219; tryItOut("(/(?=(?!(?![\\S\\D\\n-\\x63\\x44]|[]+?)*?)|(?!(?:\\\uac24{2147483647,}|[\\s\\n-\\ufebD\u0087-\u5625\\S])))/yi);");
/*fuzzSeed-159544250*/count=1220; tryItOut("\"use strict\"; g1.b1 = t1.buffer;");
/*fuzzSeed-159544250*/count=1221; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(g0.b2, p2);");
/*fuzzSeed-159544250*/count=1222; tryItOut("mathy1 = (function(x, y) { return (Math.imul((Math.max(( ! ( ~ 0/0)), mathy0((-0x100000001 | 0), Math.fround((Math.min((( + (y == ( + x))) | 0), ((( + 1) & (-(2**53-2) != (( ! (y >>> 0)) >>> 0))) | 0)) | 0)))) | 0), (((mathy0((Math.fround(Math.atan2(Math.fround((((0x080000001 >>> 0) !== (x >>> 0)) >>> 0)), Math.fround(Math.imul(Math.fround((Math.atan(x) < x)), x)))) >>> 0), (((Math.abs(1) | 0) >> (((-0 % x) | 0) | 0)) | 0)) >>> 0) / ( + ( + Math.min(( + (((Number.MIN_SAFE_INTEGER !== ( + (( + x) ? ( + 0x080000001) : ( + x)))) >= ( + ( ! ( + -Number.MIN_VALUE)))) | 0)), ( + x))))) | 0)) | 0); }); testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), (new String('')), false, '0', (new Number(-0)), 1, 0, null, ({toString:function(){return '0';}}), -0, 0.1, [0], (new Boolean(true)), [], (function(){return 0;}), /0/, ({valueOf:function(){return '0';}}), NaN, undefined, objectEmulatingUndefined(), '/0/', (new Number(0)), '', (new Boolean(false)), true, '\\0']); ");
/*fuzzSeed-159544250*/count=1223; tryItOut("/*RXUB*/var r = /\\1+?|(?:(?=(?!(?!.|.))|\\x02\\B$*?))*/yim; var s = (4277); print(s.split(r)); ");
/*fuzzSeed-159544250*/count=1224; tryItOut("mathy5 = (function(x, y) { return Math.min(mathy4(( + (y && mathy0(-Number.MIN_SAFE_INTEGER, (x <= ( + Number.MIN_SAFE_INTEGER))))), ( + ( + ((Math.imul(x, x) | 0) * ( + mathy1(x, (Math.fround(Math.clz32(y)) && x))))))), (Math.pow(Math.exp(( + (y === mathy0(( + mathy1(( + 0x100000001), x)), (x | 0))))), Math.cosh((Math.trunc(x) >>> 0))) >>> 0)); }); testMathyFunction(mathy5, [-0x100000000, -0x07fffffff, 2**53+2, -0x080000001, 0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 2**53-2, -0x080000000, 0x0ffffffff, -1/0, -0, -(2**53+2), 0, 1/0, 0/0, 0.000000000000001, 0x080000001, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53-2), 2**53, 0x100000000, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=1225; tryItOut("Array.prototype.unshift.apply(a1, [({x: x, x: ([]) = /*MARR*/[new String(''),  '' ,  '' ,  '' , \"\\uD252\", false, new String(''),  '' , new String(''),  '' , \"\\uD252\", new String(''), \"\\uD252\", false, new String(''), new String(''), \"\\uD252\",  '' , \"\\uD252\", new String(''), \"\\uD252\", new String(''),  '' , new String(''), \"\\uD252\", \"\\uD252\",  '' ,  '' ,  '' , new String(''),  '' ,  '' , new String(''), false, false, false, new String(''), false, new String(''), false,  '' , \"\\uD252\",  '' , false,  '' ,  '' , \"\\uD252\",  '' , false, false, new String(''), false, false,  '' , false, false, new String(''), \"\\uD252\",  '' , \"\\uD252\", \"\\uD252\", false, new String(''), false, \"\\uD252\",  '' , false, \"\\uD252\",  '' ,  '' , new String(''), new String(''),  '' , new String(''), false, new String(''),  '' , false, new String(''), \"\\uD252\"].sort }), s2]);");
/*fuzzSeed-159544250*/count=1226; tryItOut("o1 = b0.__proto__;");
/*fuzzSeed-159544250*/count=1227; tryItOut("\"use asm\"; for (var p in this.t1) { try { Object.defineProperty(this, \"v0\", { configurable: (x % 4 != 1), enumerable: false,  get: function() {  return o0.a2.reduce, reduceRight((function(j) { if (j) { try { v2 = evaluate(\"function f2(g1.t1)  { yield \\\"\\\\uB287\\\" } \", ({ global: g2.g2, fileName: null, lineNumber: 42, isRunOnce: window, noScriptRval: (x % 19 != 2), sourceIsLazy: true, catchTermination: false })); } catch(e0) { } /*ADP-3*/Object.defineProperty(a1, 11, { configurable: false, enumerable: false, writable: x, value: g2 }); } else { try { s0 + ''; } catch(e0) { } try { Object.freeze(o0.i2); } catch(e1) { } a0.reverse(); } }), /.?/yi); } }); } catch(e0) { } e0 + p2; }\nv2 = Array.prototype.every.call(a2, (function() { m0.get(v2); throw e0; }), e2);\n");
/*fuzzSeed-159544250*/count=1228; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[-Number.MAX_SAFE_INTEGER, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, -Number.MAX_SAFE_INTEGER,  '\\0' , -Number.MAX_SAFE_INTEGER,  '\\0' , -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER,  '\\0' , true, true, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,  '\\0' , -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, true, -Number.MAX_SAFE_INTEGER,  '\\0' , true,  '\\0' ,  '\\0' ,  '\\0' , true,  '\\0' , true, true, true,  '\\0' , true, true,  '\\0' , true, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, true,  '\\0' , -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, true, true, true, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, true,  '\\0' , -Number.MAX_SAFE_INTEGER, true,  '\\0' , true, -Number.MAX_SAFE_INTEGER, true,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , -Number.MAX_SAFE_INTEGER,  '\\0' ,  '\\0' , -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER,  '\\0' , -Number.MAX_SAFE_INTEGER, true,  '\\0' , true, true, true, true,  '\\0' , true, -Number.MAX_SAFE_INTEGER, true, -Number.MAX_SAFE_INTEGER,  '\\0' , true, -Number.MAX_SAFE_INTEGER,  '\\0' , -Number.MAX_SAFE_INTEGER, true, true,  '\\0' , -Number.MAX_SAFE_INTEGER, true, -Number.MAX_SAFE_INTEGER, true]); ");
/*fuzzSeed-159544250*/count=1229; tryItOut("o0.b2.toString = (function(j) { f2(j); });");
/*fuzzSeed-159544250*/count=1230; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.hypot((Math.log10(( ! ( ! x))) | 0), (( - (Math.cosh(Math.sin(mathy0(x, ((1 | 0) || -0x0ffffffff)))) | 0)) | 0)), (( - Math.sinh(((Math.imul((Math.fround(mathy0(Math.fround(mathy0(x, ((y ? y : x) >>> 0))), Math.fround(x))) >>> 0), Number.MAX_VALUE) >>> 0) | 0))) >>> 0)); }); testMathyFunction(mathy1, [-(2**53-2), 1.7976931348623157e308, 0x080000001, -0x07fffffff, 2**53, 0.000000000000001, 42, -0x100000001, -0, -(2**53+2), 0x100000000, -0x100000000, -Number.MIN_VALUE, -(2**53), Number.MIN_VALUE, 0/0, 0x07fffffff, 1, -Number.MAX_VALUE, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, -0x0ffffffff, 2**53+2, 0x100000001, 0x080000000, Math.PI, 2**53-2, -0x080000000, -1/0, -0x080000001]); ");
/*fuzzSeed-159544250*/count=1231; tryItOut("function shapeyConstructor(cmhzws){\"use strict\"; this[\"valueOf\"] = function(){};this[\"5\"] = intern(null);Object.preventExtensions(this);this[\"concat\"] = null;this[\"concat\"] = function(y) { {}v0 = evalcx(\"new RegExp(\\\".(?![\\\\\\\\u00B5\\\\\\\\W])*|([^])*[^]|\\\\u14ce{3}{2,}\\\", \\\"ym\\\")\", g2); };this[\"5\"] = b =>  { return mathy0.prototype } ;Object.preventExtensions(this);this[\"concat\"] = encodeURIComponent;Object.defineProperty(this, \"concat\", ({value: ((function sum_indexing(feloft, ttbfvq) { v0 = Object.prototype.isPrototypeOf.call(f2, g1.p0);; return feloft.length == ttbfvq ? 0 : feloft[ttbfvq] + sum_indexing(feloft, ttbfvq + 1); })(/*MARR*/[(1/0), [(void 0)], x, [(void 0)]], 0))}));Object.preventExtensions(this);return this; }/*tLoopC*/for (let x of (function() { yield [1]; } })()) { try{let xpigyb = new shapeyConstructor(x); print('EETT'); /* no regression tests found */}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-159544250*/count=1232; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\3)*\", \"i\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1233; tryItOut("mathy2 = (function(x, y) { return Math.imul(( + ( ~ (( + ( + Math.acosh(( + 2**53+2)))) >>> 0))), (Math.trunc((Math.fround(( + Math.fround(mathy1(Math.fround(mathy1(Math.fround(y), Math.fround(x))), x)))) >> ((Math.imul(-(2**53-2), Math.tan(x)) >>> 0) === x))) | 0)); }); testMathyFunction(mathy2, /*MARR*/[window = \"\u03a0\" === x, undefined, -0x080000000, window = \"\u03a0\" === x, window = \"\u03a0\" === x, undefined, window = \"\u03a0\" === x, window = \"\u03a0\" === x, window = \"\u03a0\" === x, undefined, -0x080000000, -0x080000000, window = \"\u03a0\" === x, -0x080000000, window = \"\u03a0\" === x, window = \"\u03a0\" === x, undefined, -0x080000000, window = \"\u03a0\" === x, undefined, -0x080000000, -0x080000000]); ");
/*fuzzSeed-159544250*/count=1234; tryItOut("x = (-18()), vfhpoc, pgshtj, x, mxmkht, x, w;s0 += s0;");
/*fuzzSeed-159544250*/count=1235; tryItOut("/*tLoop*/for (let w of /*MARR*/[]) { v2 = a0.length; }");
/*fuzzSeed-159544250*/count=1236; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(Math.atan2(Math.fround(Math.min(Math.fround((Math.fround(Math.max(y, (x | 0))) ** ( + (Math.fround(y) < x)))), Math.fround(((Math.fround(Math.expm1(Math.pow(y, 2**53+2))) >>> 0) , Math.imul((Math.pow((0/0 >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0), Math.tan(-Number.MAX_SAFE_INTEGER)))))), (Math.sinh(( + Math.fround(Math.asinh(Math.fround((((-Number.MIN_VALUE >= (x | 0)) | 0) >= y)))))) >>> 0))) && Math.log2(Math.fround((Math.fround(x) >>> ( - (Math.tanh(Math.sin(Math.fround(y))) >>> 0)))))); }); testMathyFunction(mathy0, [Math.PI, 2**53, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, -(2**53-2), -Number.MAX_VALUE, Number.MAX_VALUE, 1/0, 0, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000000, -0x07fffffff, 0x080000001, 0x100000001, 42, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -1/0, Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 1, 0.000000000000001, 0x100000000, -0x0ffffffff, -(2**53), 2**53+2]); ");
/*fuzzSeed-159544250*/count=1237; tryItOut("");
/*fuzzSeed-159544250*/count=1238; tryItOut("s2 = new String;");
/*fuzzSeed-159544250*/count=1239; tryItOut("\"use strict\"; for (var v of s0) { a0.pop(h2); }");
/*fuzzSeed-159544250*/count=1240; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.pow(Math.fround(Math.max((( + ( + x)) >>> 0), (( + mathy0(( + ( ~ x)), ( + ( + Math.atanh(( + (Math.imul(y, y) | 0))))))) ? mathy0((Math.sinh(-0x100000000) >>> 0), ( + Math.fround((Math.fround(x) / Math.fround(x))))) : Math.imul((( ~ y) >>> 0), (Math.atan2((x | 0), y) >>> 0))))), Math.fround(((Math.fround(x) >>> 0) ? ( + ( ~ ( + y))) : (Math.imul((Math.hypot(Math.fround(x), Math.fround(Math.fround(( ! Math.fround(y))))) >>> 0), (( + (( + ((( + x) > y) >>> 0)) != ( + x))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [-0x080000000, 42, -Number.MIN_VALUE, 0x100000001, 2**53+2, -0x080000001, -0x07fffffff, 1.7976931348623157e308, -(2**53+2), -0x0ffffffff, 0.000000000000001, -(2**53-2), 0/0, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -0, 0x080000000, 2**53-2, -Number.MAX_VALUE, 1/0, 1, -1/0, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 0x0ffffffff, 0x07fffffff, 0, 2**53, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1241; tryItOut("this.t1[1];");
/*fuzzSeed-159544250*/count=1242; tryItOut("\"use strict\"; v2 = evalcx(\"o0.a0 + '';\", g0);");
/*fuzzSeed-159544250*/count=1243; tryItOut("");
/*fuzzSeed-159544250*/count=1244; tryItOut("\"use strict\"; h2.getOwnPropertyNames = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 8388609.0;\n    return +((+sin(((d3)))));\n  }\n  return f; });");
/*fuzzSeed-159544250*/count=1245; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.imul(((( ! (Math.atan(( + Math.expm1((y >>> 0)))) | 0)) >>> 0) | 0), Math.fround(( + (( + Math.pow((( + Math.log1p((x ? (Math.acos(y) >>> 0) : x))) ? Math.fround(Math.atan2(Math.fround(x), x)) : (( + (x && ( + ( + Math.imul(( ! y), (Math.fround(Math.atan2(Math.fround(Math.PI), Math.fround(y))) | 0)))))) >>> 0)), x)) ? ( - -0x0ffffffff) : ( + Math.log1p((((( + x) >>> 0) !== (y >>> 0)) >>> 0))))))) | 0); }); ");
/*fuzzSeed-159544250*/count=1246; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(( ~ mathy0(Math.fround((Math.fround(x) >>> Math.fround(1))), Math.cosh((Math.fround((Math.fround(x) != Math.fround((((( - y) | 0) | x) >>> 0)))) | 0)))), (Math.tanh(-0x07fffffff) === ( + Math.fround((Math.fround(Math.expm1(( + ( ~ ((y ^ y) | 0))))) >> Math.fround(Math.min(( + ( ! (y >>> 0))), y))))))); }); testMathyFunction(mathy2, [0/0, 0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 0x100000001, -0x080000000, -Number.MAX_VALUE, 42, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 2**53-2, -(2**53), -0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), 1, 0, -1/0, 0x080000001, 0x07fffffff, -0, -0x080000001, -0x100000001, -Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=1247; tryItOut("v1 = (e1 instanceof m1);");
/*fuzzSeed-159544250*/count=1248; tryItOut("\"use asm\"; t2 = new Int16Array(b2, 10, 1);");
/*fuzzSeed-159544250*/count=1249; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.sinh(Math.expm1(Math.atanh(Math.max(x, (( ~ ( - y)) | 0)))))); }); testMathyFunction(mathy5, [-(2**53), -0x080000001, 2**53, 1, -0x0ffffffff, 0.000000000000001, 0x100000000, 0x080000001, -0x07fffffff, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, -0, 42, 0/0, -0x100000001, -(2**53-2), 1/0, 0x080000000, 0x100000001, 0, Math.PI, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, 2**53+2, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-159544250*/count=1250; tryItOut("testMathyFunction(mathy4, [-0x0ffffffff, -Number.MIN_VALUE, 1/0, 42, -(2**53), 0, -0x100000001, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, Math.PI, 2**53+2, -0, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, 2**53, 0x100000000, 0x080000001, -(2**53+2), -0x07fffffff, 1.7976931348623157e308, -0x100000000, 0.000000000000001, 1, -0x080000000, -0x080000001, 0x07fffffff, 0x100000001, 0x080000000, 0/0]); ");
/*fuzzSeed-159544250*/count=1251; tryItOut("\"use strict\"; testMathyFunction(mathy5, [(function(){return 0;}), (new String('')), true, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), 1, 0.1, (new Number(-0)), '0', 0, '', [], false, NaN, /0/, '/0/', (new Boolean(false)), -0, (new Boolean(true)), '\\0', (new Number(0)), undefined, objectEmulatingUndefined(), [0], null, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-159544250*/count=1252; tryItOut("for (var v of p2) { try { m2.set(f1, s2); } catch(e0) { } g2.a0[10] = \"\\u4425\"; }");
/*fuzzSeed-159544250*/count=1253; tryItOut("h1.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-159544250*/count=1254; tryItOut("v1 = Object.prototype.isPrototypeOf.call(this.m1, b2);");
/*fuzzSeed-159544250*/count=1255; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (mathy1(Math.fround(Math.tan(Math.fround(( + Math.log10(( + Math.acos(Math.fround(x)))))))), (Math.fround((Math.fround(Math.atan2(x, Math.fround(((y | y) === x)))) !== Math.fround(Math.max(Math.max((Math.sin((y | 0)) >>> 0), Math.fround(Math.round(((( + 2**53-2) !== y) | 0)))), Math.atan2(mathy0((-Number.MAX_SAFE_INTEGER | 0), (( ! (Math.asinh((x >>> 0)) >>> 0)) | 0)), ( + ( - ( + ( - x))))))))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[arguments, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), 2**53, arguments, arguments, 2**53, arguments, 2**53, (1/0), function(){}, arguments, 2**53, arguments, (void 0), function(){}, (void 0), function(){}, function(){}, function(){}, function(){}, (1/0), function(){}, arguments, (1/0), (1/0), function(){}, (void 0), (void 0), (1/0), arguments, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (void 0), (void 0), 2**53, (void 0), (1/0), (void 0), (1/0), arguments, (void 0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), 2**53, (void 0), (void 0), 2**53, arguments, arguments, 2**53, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, arguments, (1/0), (1/0), function(){}, function(){}, arguments, arguments, (void 0), arguments, 2**53, (void 0), function(){}, (1/0), arguments, function(){}, (1/0), arguments, (1/0), arguments, arguments, arguments, arguments, (void 0), function(){}, 2**53, function(){}, 2**53, arguments, function(){}, (void 0), (1/0), function(){}, (void 0), function(){}, arguments, (1/0), 2**53, function(){}, function(){}, function(){}, (1/0), function(){}, (void 0), arguments, 2**53, function(){}, (1/0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (void 0), 2**53, 2**53, (void 0), 2**53, 2**53, function(){}, (1/0), (void 0), function(){}, (void 0), (void 0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), arguments, (void 0), 2**53]); ");
/*fuzzSeed-159544250*/count=1256; tryItOut("\"use strict\"; e2.add(o2);\na0 = a2.concat(a1, g1.o1);\n");
/*fuzzSeed-159544250*/count=1257; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ ( + ((-0x0ffffffff ^ ( + (x << y))) && (((x === (((y | 0) ? (y | 0) : (mathy2((mathy0(y, 2**53-2) >>> 0), (Math.abs(y) >>> 0)) >>> 0)) >>> 0)) >>> 0) * ((Math.pow((y >>> 0), y) >>> 0) > Math.fround(x)))))); }); testMathyFunction(mathy5, [-0x100000000, 2**53, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 0, 0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, 1, 0/0, 2**53-2, -0x100000001, 0x0ffffffff, 0x080000001, -0x080000000, 0x100000000, -0, -Number.MAX_VALUE, 0x080000000, 0x07fffffff, 42, 1.7976931348623157e308, 2**53+2, -0x07fffffff, -0x0ffffffff, Math.PI, -(2**53-2), -(2**53), 1/0]); ");
/*fuzzSeed-159544250*/count=1258; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=1259; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1260; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((( ~ ((Math.max(Math.fround(( + ( ! ( + ((x | 0) ? (y | 0) : ((y && (((y | 0) || (x | 0)) | 0)) | 0)))))), ( + ( + Math.log2(x)))) >>> 0) >>> 0)) >>> 0) == ((( + Math.atan2(((mathy0(Math.fround(0), ((Math.cbrt((0x080000001 >>> 0)) >>> 0) | 0)) >>> 0) | 0), Math.fround(((2**53-2 >>> 0) ? Math.fround(x) : x)))) >= Math.atan2(Math.atan2((mathy0(y, y) | 0), 0), (Math.atan(( + x)) | 0))) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -(2**53+2), 2**53+2, -0x07fffffff, 0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, Number.MAX_VALUE, -0x100000001, 1/0, -0x100000000, -1/0, 0x080000001, 0/0, 0x100000001, 42, -(2**53), 0x0ffffffff, -0x080000001, -0, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 0, -0x0ffffffff, 0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 0x07fffffff, 1]); ");
/*fuzzSeed-159544250*/count=1261; tryItOut("/*hhh*/function bcyjql(NaN = x){x ?  '' .watch(\"get\", ({/*TOODEEP*/})) : x = Proxy.create(({/*TOODEEP*/})(c), false);}bcyjql();");
/*fuzzSeed-159544250*/count=1262; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - Math.log(Math.fround(Math.fround(mathy0(Math.fround((mathy0((x | 0), (y | 0)) | 0)), Math.fround(Math.acosh(x))))))); }); ");
/*fuzzSeed-159544250*/count=1263; tryItOut("\"use strict\"; f2.__proto__ = g0;");
/*fuzzSeed-159544250*/count=1264; tryItOut("\"use strict\"; (window);print(x);");
/*fuzzSeed-159544250*/count=1265; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Math.PI, -Number.MIN_VALUE, 42, -0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, 0x080000000, 1, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, -0x080000000, -0x07fffffff, -0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 0x100000000, 0x07fffffff, 2**53, 0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, 0, -0, 0x080000001, -(2**53+2), -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-159544250*/count=1266; tryItOut("mathy0 = (function(x, y) { return (( + (( ! (Math.cos((y | 0)) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy0, [(new Boolean(true)), '/0/', false, null, undefined, (new Number(-0)), 1, 0, -0, true, [0], ({valueOf:function(){return 0;}}), /0/, ({valueOf:function(){return '0';}}), [], (new Number(0)), '\\0', NaN, (new String('')), objectEmulatingUndefined(), '', ({toString:function(){return '0';}}), (new Boolean(false)), 0.1, '0', (function(){return 0;})]); ");
/*fuzzSeed-159544250*/count=1267; tryItOut("v0 = t2.length;");
/*fuzzSeed-159544250*/count=1268; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (( ! Math.hypot(Math.fround(((Math.fround(y) > ( + ( ~ ( + x)))) >>> 0)), (( ! ( + Math.atan2([[1]], y))) >>> 0))) % Math.expm1(Math.fround(Math.min(Math.imul(x, 0.000000000000001), Math.fround((((Math.sqrt(x) | 0) != Number.MAX_VALUE) | 0)))))); }); testMathyFunction(mathy0, [1/0, -0x080000000, 2**53+2, Math.PI, 1, 0/0, 0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -0x07fffffff, 0x100000001, -0x0ffffffff, -(2**53-2), -0, 42, -(2**53), -(2**53+2), -0x080000001, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, -Number.MIN_VALUE, 0x100000000, 0, -0x100000001, 0x0ffffffff, -1/0, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1269; tryItOut("/*oLoop*/for (oohebu = 0; oohebu < 13; ++oohebu) { o2.h2.iterate = f1; } ");
/*fuzzSeed-159544250*/count=1270; tryItOut("\"use strict\"; x, x, [[, , {\u3056: []}], [, [], window], , [, w], []] = (return new RegExp(\"(?:[^](?:\\\\d)|[^][^]*)+?|\\\\b|\\\\d+?.$+\\\\s.{1}$?{2,}\\\\3\", \"gyi\")).yoyo(x);this.g0.offThreadCompileScript(\"e1 = new Set;\");");
/*fuzzSeed-159544250*/count=1271; tryItOut("\"use strict\"; a0.reverse(t0);");
/*fuzzSeed-159544250*/count=1272; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((((( ~ Math.fround(Math.hypot(Math.max(x, ( + mathy2((x >>> 0), ( + x)))), 0))) >>> 0) <= ((Math.hypot(Math.fround(( + Math.ceil(Number.MAX_SAFE_INTEGER))), ((x / Math.sinh(( + Math.fround(( + x))))) >>> 0)) >>> 0) | 0)) | 0) >>> ( + Math.atan2(( + ( + mathy0(( ~ (mathy0(y, ((y ? y : y) >>> 0)) | 0)), Math.log10(( - x))))), ( + Math.max(Math.ceil(Math.sign(Math.fround(2**53))), Math.tan(((0.000000000000001 | 0) / Math.hypot((y | 0), 0x0ffffffff)))))))); }); ");
/*fuzzSeed-159544250*/count=1273; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1274; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(p2, s1);");
/*fuzzSeed-159544250*/count=1275; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[x, function(){}, -Infinity, null, -Infinity, function(){}, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, x, null, null, x, x, null, x, -Infinity, -Infinity, -Infinity, x, function(){}, null, x, x, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, null, function(){}, null, x, x, -Infinity, function(){}, function(){}, -Infinity, x, -Infinity, -Infinity, null, x, function(){}, x, null, -Infinity, x]) { m0 = new Map(v2); }");
/*fuzzSeed-159544250*/count=1276; tryItOut("/*bLoop*/for (var oflxho = 0; oflxho < 15 && (x); ++oflxho) { if (oflxho % 2 == 0) { t1 + ''; } else { a1 + g2.e1; }  } ");
/*fuzzSeed-159544250*/count=1277; tryItOut("with([,,])delete h0.getOwnPropertyNames;");
/*fuzzSeed-159544250*/count=1278; tryItOut("/*bLoop*/for (let dwmgih = 0, window; dwmgih < 58; ++dwmgih) { if (dwmgih % 3 == 1) { print(x); } else { return this; }  } ");
/*fuzzSeed-159544250*/count=1279; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.abs(((Math.pow((Math.fround(mathy1(Math.fround((Math.fround(y) ** (mathy2((mathy4(1.7976931348623157e308, x) >>> 0), y) >>> 0))), Math.fround(( + Math.cbrt(( + Math.fround(( - Math.fround(((-(2**53+2) ? y : x) >>> 0)))))))))) >>> 0), ((Math.fround(mathy1(Math.fround(Math.sinh(y)), Math.fround(( ~ y)))) == Math.log1p(Math.imul(y, x))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, /*MARR*/[[], [], [], (1/0), (1/0), (-1/0), (1/0), (-1/0), (-1/0), true, (-1/0), (-1/0), arguments.callee, (1/0), [], arguments.callee, (-1/0), (1/0), (-1/0), arguments.callee, true, (1/0), [], (-1/0), true, (-1/0), [], arguments.callee, (-1/0), true, true, arguments.callee, (-1/0), (1/0), true, [], [], true, arguments.callee, (-1/0), (1/0), (-1/0), (-1/0), (-1/0), true, arguments.callee, true]); ");
/*fuzzSeed-159544250*/count=1280; tryItOut("/*hhh*/function vhepyt(window){print(length);}/*iii*/v2 = Object.prototype.isPrototypeOf.call(s2, t1);");
/*fuzzSeed-159544250*/count=1281; tryItOut("v2 = g2.m2.get(s0);");
/*fuzzSeed-159544250*/count=1282; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.pow(( + Math.max(Math.atan2(y, ( + Math.sqrt(( + Math.sqrt((x | 0)))))), (( - (( + Math.pow(Math.fround(y), ( + ( + (0x0ffffffff % ( + Math.hypot((y || y), ( + x)))))))) >>> 0)) >>> 0))), (Math.log((( ! x) >>> 0)) < Math.imul((Math.abs(Math.fround(( ~ ( + ((Math.cos((x >>> 0)) >>> 0) >>> 0))))) | 0), x)))); }); testMathyFunction(mathy0, [1/0, -0x100000000, 0x100000001, 0x080000001, 2**53, -0, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, -1/0, 0x0ffffffff, -(2**53), -0x07fffffff, -Number.MIN_VALUE, 0x07fffffff, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), 42, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 2**53+2, -0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1283; tryItOut("/* no regression tests found */\nh1 = t1[1];\n");
/*fuzzSeed-159544250*/count=1284; tryItOut("\"use strict\"; v1 = (x % 40 != 11);");
/*fuzzSeed-159544250*/count=1285; tryItOut("\"use strict\"; { void 0; minorgc(false); } for(let d in ((b => \"\\u3113\" += d.throw(-0.48))(Math.min( '' , 9))))s0 += 'x';");
/*fuzzSeed-159544250*/count=1286; tryItOut("\"use strict\"; o2.m2.set(a0, h0);");
/*fuzzSeed-159544250*/count=1287; tryItOut("s1 += 'x';");
/*fuzzSeed-159544250*/count=1288; tryItOut("e1 = new Set(m1);");
/*fuzzSeed-159544250*/count=1289; tryItOut("Array.prototype.splice.apply(a1, [NaN, 7]);");
/*fuzzSeed-159544250*/count=1290; tryItOut("");
/*fuzzSeed-159544250*/count=1291; tryItOut("\"use strict\"; /*bLoop*/for (rftmqf = 0; rftmqf < 4 && (new RegExp(\"\\\\d(?![^]){4,}\", \"i\")); ++rftmqf) { if (rftmqf % 11 == 4) { Array.prototype.pop.apply(a2, []); } else { print(x); }  } ");
/*fuzzSeed-159544250*/count=1292; tryItOut("");
/*fuzzSeed-159544250*/count=1293; tryItOut("mathy0 = (function(x, y) { return Math.cbrt((( + (((-0x100000001 | 0) || Math.fround(Math.max(-1/0, ( ! ((y >>> 0) - Math.fround(y)))))) | 0)) | 0)); }); testMathyFunction(mathy0, [0x080000001, 0/0, -(2**53), Number.MAX_VALUE, -0x100000000, -0x080000000, 0x100000000, 0x0ffffffff, 2**53+2, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 42, Math.PI, 2**53-2, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, 0, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, 0x07fffffff, -Number.MAX_VALUE, -0x100000001, -(2**53+2), 1/0, 2**53, -1/0, -(2**53-2), 1, Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-159544250*/count=1294; tryItOut("r0 = /\\u00a5(?:(?=(?:\\b)))\\3+/gyim;");
/*fuzzSeed-159544250*/count=1295; tryItOut("o0.t0.set(a0, 13);");
/*fuzzSeed-159544250*/count=1296; tryItOut("/*vLoop*/for (var kfhmke = 0; kfhmke < 7; ++kfhmke) { let e = kfhmke; g1 + f0; } ");
/*fuzzSeed-159544250*/count=1297; tryItOut("testMathyFunction(mathy4, [0x080000001, -1/0, 0x080000000, 1/0, -0x100000001, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, 0x100000001, 0.000000000000001, -Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, -Number.MAX_VALUE, Number.MIN_VALUE, -0x100000000, Math.PI, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 2**53+2, 2**53, 0, 0x07fffffff, -(2**53-2), 0/0]); ");
/*fuzzSeed-159544250*/count=1298; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( - mathy1((( + ((Math.fround(( ! Math.fround(y))) > Math.atan(mathy0(0x080000000, y))) | 0)) >>> 0), mathy0(x, x))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0x080000001, 0, Number.MAX_VALUE, 1/0, 0x0ffffffff, -0x080000000, 1.7976931348623157e308, -0x07fffffff, 0x100000000, -Number.MIN_VALUE, 42, 0/0, Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, -0, 0x080000000, 0x080000001, 1, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x100000000, 2**53-2, 0x07fffffff, -0x100000001, 0x100000001, Math.PI, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=1299; tryItOut("f1.toString = (function() { try { v2 = (m0 instanceof m0); } catch(e0) { } try { let v0 = evaluate(\"\\\"use strict\\\"; Object.prototype.unwatch.call(p2, \\\"indexOf\\\");\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 56 == 39), noScriptRval: false, sourceIsLazy: (x % 4 != 3), catchTermination: (4277), sourceMapURL: s1 })); } catch(e1) { } v1 = a1.length; return o1; });");
/*fuzzSeed-159544250*/count=1300; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -590295810358705700000.0;\n    return (((i2)*-0xbf6ba))|0;\n  }\n  return f; })(this, {ff: (new String.prototype.endsWith(eval, [1]))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Math.PI, 2**53, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0x100000000, 0x080000000, 0x100000001, 0x0ffffffff, 0x100000000, -0x080000000, -(2**53-2), 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, -(2**53), 1, -0, 1/0, -0x0ffffffff, -1/0, -(2**53+2), 42, -0x100000001, -Number.MIN_VALUE, 0, 0.000000000000001, Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1301; tryItOut("var dunrze = new ArrayBuffer(2); var dunrze_0 = new Uint16Array(dunrze); print(dunrze_0[0]); var dunrze_1 = new Uint32Array(dunrze); print(dunrze_1[0]); dunrze_1[0] = -25; print(false);o1.f0 = f1;Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-159544250*/count=1302; tryItOut("\"use strict\"; h0 + '';");
/*fuzzSeed-159544250*/count=1303; tryItOut("v0 = evalcx(\"v1 = t0.length;\", g0.g2);");
/*fuzzSeed-159544250*/count=1304; tryItOut("var x = undefined, x = /*MARR*/[0x080000001, false, false, 0x080000001, false, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, 0x080000001, false, false, 0x080000001, false, 0x080000001, false, 0x080000001, false, false, 0x080000001, false, false, false, 0x080000001, false, false, 0x080000001, 0x080000001, 0x080000001, false, false, 0x080000001, 0x080000001, false, 0x080000001].filter, y = ({length: -25 }), omcunx, tyhmfk, arguments[new String(\"-19\")] = ([,,z1]), y, x = (4277), eval =  '' , vmppcg;m1.set(e1, this.e0);");
/*fuzzSeed-159544250*/count=1305; tryItOut("g0.v2 = evaluate(\"a1.splice(t2);\", ({ global: o0.g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: \"\\u83CC\", sourceIsLazy: 19, catchTermination: false }));");
/*fuzzSeed-159544250*/count=1306; tryItOut("\"use strict\"; M:if((x % 5 != 3)) M: for  each(z in false) {(\"\\u76DE\"); }");
/*fuzzSeed-159544250*/count=1307; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = s0; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1308; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, 2**53, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, Math.PI, 0x0ffffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, -0x07fffffff, 0x080000001, Number.MIN_VALUE, 0x080000000, 0x100000001, 2**53+2, 1/0, 0.000000000000001, -1/0, 0x07fffffff, -(2**53+2), -0, -0x100000000, 42, Number.MIN_SAFE_INTEGER, 0/0, 0]); ");
/*fuzzSeed-159544250*/count=1309; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.imul(Math.exp(Math.sign(Math.atan2(((((x >>> 0) && (x >>> 0)) >>> 0) | 0), ((Math.hypot(-0x0ffffffff, (Math.hypot(y, ( + x)) >>> 0)) | 0) | 0)))), ( + ((0/0 | 0) >> Math.fround((Math.fround(0.000000000000001) | Math.fround(y)))))); }); testMathyFunction(mathy0, [-0x0ffffffff, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 2**53, -0x080000000, 2**53+2, -0x080000001, 1/0, 0x07fffffff, 1, 0x080000001, 0x0ffffffff, -0x100000001, -0, 0/0, -1/0, -0x100000000, 0x080000000, -0x07fffffff, 1.7976931348623157e308, 0x100000001, -(2**53-2), Number.MIN_VALUE, 0, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 42, 0.000000000000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=1310; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(x, Math.abs((((x + (Math.sqrt((( - ( + -(2**53))) >>> 0)) | 0)) | 0) + (x | 0)))); }); testMathyFunction(mathy2, /*MARR*/[0x100000001, arguments, 0x3FFFFFFE, 0x100000001, (-1/0), arguments, objectEmulatingUndefined(), (-1/0), 0x3FFFFFFE, objectEmulatingUndefined(), 0x100000001, arguments, (-1/0), arguments, (-1/0), 0x3FFFFFFE, 0x100000001, objectEmulatingUndefined(), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), 0x3FFFFFFE, objectEmulatingUndefined(), 0x3FFFFFFE, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x100000001, 0x100000001, (-1/0), 0x100000001, 0x3FFFFFFE, 0x100000001, objectEmulatingUndefined(), 0x3FFFFFFE, 0x3FFFFFFE, 0x100000001, objectEmulatingUndefined(), 0x100000001, arguments, 0x3FFFFFFE, arguments, arguments, (-1/0), 0x3FFFFFFE, arguments, 0x3FFFFFFE, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x3FFFFFFE, arguments, 0x3FFFFFFE, objectEmulatingUndefined(), 0x100000001, 0x3FFFFFFE, 0x3FFFFFFE, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments, 0x100000001, 0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, arguments, arguments, objectEmulatingUndefined()]); ");
/*fuzzSeed-159544250*/count=1311; tryItOut("o2.v2 = (this.i0 instanceof g0);");
/*fuzzSeed-159544250*/count=1312; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atanh(Math.acosh(((Math.hypot(1/0, x) | 0) / ( - (( ! y) | x))))); }); ");
/*fuzzSeed-159544250*/count=1313; tryItOut("\"use strict\"; t2[11] = window;");
/*fuzzSeed-159544250*/count=1314; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.log1p((( + ( ! (Math.fround(Math.atan(Math.fround(( ~ (( + (mathy0(-0x080000001, -0) >>> 0)) >>> 0))))) >>> 0))) >>> 0)); }); testMathyFunction(mathy2, [0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, 2**53, -0x080000000, -0, -0x100000001, 0, -(2**53-2), 0x100000000, -1/0, -0x0ffffffff, 0x100000001, -0x07fffffff, -(2**53+2), 0x080000000, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, 2**53+2, 42, Math.PI, Number.MIN_SAFE_INTEGER, 1, -(2**53), Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1315; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return (Math.abs((Math.asinh((((Math.asinh(y) | 0) ? (y | 0) : (Math.fround((0x080000001 != (x >>> 0))) | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy1, [(new Boolean(false)), '', 1, [0], (function(){return 0;}), ({valueOf:function(){return 0;}}), [], NaN, '\\0', (new Number(0)), 0, -0, true, false, (new Number(-0)), /0/, objectEmulatingUndefined(), '/0/', (new Boolean(true)), ({valueOf:function(){return '0';}}), 0.1, (new String('')), undefined, ({toString:function(){return '0';}}), null, '0']); ");
/*fuzzSeed-159544250*/count=1316; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.pow((Math.expm1(Math.fround((Math.fround(y) << Math.fround(x)))) | 0), ((Math.tanh(Math.fround(Math.max(x, y))) | 0) | 0)); }); testMathyFunction(mathy2, /*MARR*/[x, -0x07fffffff, x, null, -0x07fffffff, -0x07fffffff, new String('q'), x, x, -0x07fffffff, new String('q'), null, x, x, x, new String('q'), null, -0x07fffffff, x, -0x07fffffff, null, new String('q'), -0x07fffffff, -0x07fffffff, x, null, new String('q'), -0x07fffffff, x, -0x07fffffff, -0x07fffffff, -0x07fffffff, new String('q'), -0x07fffffff, null, new String('q'), -0x07fffffff, new String('q'), new String('q'), -0x07fffffff, x, null, new String('q'), new String('q'), x, -0x07fffffff, new String('q'), new String('q'), x, -0x07fffffff, -0x07fffffff, new String('q'), -0x07fffffff, -0x07fffffff, new String('q'), new String('q'), null, -0x07fffffff, -0x07fffffff, -0x07fffffff, null, -0x07fffffff, null, -0x07fffffff, -0x07fffffff, null, x, -0x07fffffff, new String('q'), new String('q'), -0x07fffffff, -0x07fffffff, null, new String('q'), x, new String('q'), new String('q'), null, x, new String('q'), x, -0x07fffffff, null, null, new String('q'), -0x07fffffff, new String('q'), new String('q'), x, x, new String('q'), x, new String('q'), -0x07fffffff, -0x07fffffff, new String('q'), new String('q'), null, -0x07fffffff, -0x07fffffff, null, -0x07fffffff, new String('q'), new String('q'), new String('q'), x, null, -0x07fffffff, null, new String('q'), -0x07fffffff, null, x, -0x07fffffff, x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q')]); ");
/*fuzzSeed-159544250*/count=1317; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.expm1(((Math.log(Math.hypot(( + x), ( + y))) % Math.fround(Math.ceil(Math.fround(( + mathy3(( + x), ( + x))))))) | 0)); }); testMathyFunction(mathy5, [2**53, 1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 0x100000001, -0x0ffffffff, Math.PI, Number.MIN_VALUE, 2**53-2, -0x100000000, 0, 0x0ffffffff, 42, -0, 0x080000001, -0x07fffffff, 0x080000000, -(2**53-2), 1.7976931348623157e308, -1/0, -(2**53), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, 1, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1318; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.fround(Math.cbrt((Math.fround(Math.log(Math.fround(-Number.MIN_VALUE))) << Math.sign((Math.min(Math.imul((x >>> 0), (Math.atan2(y, x) >>> 0)), x) >>> 0))))); }); testMathyFunction(mathy5, [2**53+2, 2**53, 0x080000001, 0x0ffffffff, 0, -0, -0x100000001, -0x07fffffff, -1/0, 1, -0x080000000, Number.MAX_VALUE, 0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 2**53-2, -(2**53), -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53+2), 0/0, -0x0ffffffff, 0x100000001, -Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 0x100000000, -0x100000000]); ");
/*fuzzSeed-159544250*/count=1319; tryItOut(";\nv1 = a0.some((function() { for (var j=0;j<100;++j) { f1(j%5==1); } }));\n");
/*fuzzSeed-159544250*/count=1320; tryItOut("L:if(true) { if (({}) = (delete x.c)) v2 = Object.prototype.isPrototypeOf.call(i1, this.b2); else v2 = evalcx(\"/* no regression tests found */\", g1);}");
/*fuzzSeed-159544250*/count=1321; tryItOut("mathy3 = (function(x, y) { return ( + Math.pow(( + Math.atan2((Math.cbrt(Math.sin(y)) ? (( - (Math.atan2(( + y), (y >>> 0)) >>> 0)) >>> 0) : ((y & (( + ((Math.clz32(Math.fround(x)) >>> 0) < ((x <= Number.MIN_SAFE_INTEGER) >>> 0))) | 0)) | 0)), Math.sin(((x >>> 0) >> (Number.MAX_VALUE | 0))))), Math.fround(( + x)))); }); testMathyFunction(mathy3, [-(2**53+2), 0x080000000, 0x080000001, -(2**53), -1/0, -0x080000000, 1/0, -0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 42, -0x100000001, 0x100000000, -0x100000000, 0.000000000000001, Math.PI, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, 0x0ffffffff, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 1, -0x080000001, 0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-159544250*/count=1322; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.min((mathy3((mathy3(x, y) >>> 0), (Math.log((x >>> 0)) | 0)) >>> 0), Math.max(( ! Math.atanh((-Number.MAX_VALUE || (0x080000001 | 0)))), ( + ( ! (Math.fround(((Math.asin(Math.fround(x)) >>> 0) % y)) | 0))))); }); ");
/*fuzzSeed-159544250*/count=1323; tryItOut("mathy2 = (function(x, y) { return (Math.hypot((((Math.fround(Math.acos(Math.fround(x))) | 0) ? ((( - (( ~ Math.fround(Math.clz32((0x080000001 - y)))) | 0)) | 0) | 0) : (Math.hypot(((0x100000001 != ((((Math.fround((y >>> 0)) >>> 0) >>> 0) <= (Math.fround(( - Math.fround(2**53))) >>> 0)) >>> 0)) | 0), (Math.atan2(Math.fround(( ~ ( + y))), y) | 0)) | 0)) | 0), Math.atan2(Math.fround(Math.imul(Math.fround(Math.asinh(Math.fround(y))), Math.fround(( - (Math.atan2(x, ( + Math.cos(( + x)))) | 0))))), (Math.max((Math.clz32(Math.fround((x >>> Math.fround(y)))) >>> 0), Math.log2((Math.acos((((( + y) === x) & x) | 0)) | 0))) >>> 0))) | 0); }); testMathyFunction(mathy2, [1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), 1/0, -0x07fffffff, Math.PI, 2**53, 0x0ffffffff, -0, 0.000000000000001, 2**53+2, -Number.MAX_VALUE, -1/0, -0x080000000, 0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, -(2**53), 0x100000001, 0x07fffffff, 1, -(2**53+2), 0, -Number.MIN_VALUE, 0/0, 42]); ");
/*fuzzSeed-159544250*/count=1324; tryItOut("\"use strict\"; testMathyFunction(mathy3, [1/0, 2**53, -0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, 1, 0x0ffffffff, 0x080000000, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x100000000, -0x07fffffff, -(2**53), 0x080000001, -0x100000001, -(2**53-2), -0x0ffffffff, -(2**53+2), -0, 0, Math.PI, 2**53+2, Number.MAX_VALUE, 0x100000001, 0/0, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1325; tryItOut("delete g2.h1.enumerate;function e()\"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var exp = stdlib.Math.exp;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (8796093022209.0);\n    (Uint32ArrayView[1]) = ((0xf83f7d61)+(1));\n    {\n      d0 = (((d1)) % ((d1)));\n    }\n    return +(((-0x8000000) ? (Infinity) : (((+atan2(((((d0)) % ((Float32ArrayView[2])))), ((d1))))) % (((!((0x2db54966) < (0x1e479e8d))) ? (d1) : (d0))))));\n    {\n      {\n        d1 = (d1);\n      }\n    }\n    switch ((~(delete \"0\".x))) {\n      case -2:\n        d1 = (((NaN)) / ((Infinity)));\n        break;\n      default:\n        (Int16ArrayView[((0xfa321515)-(0xd5c0cfdb)) >> 1]) = (-0xfffff*((0x1a344bb1) <= (((((((Float64ArrayView[0])) - ((Float32ArrayView[2]))))) / (((0x7fffffff) / (0x32f1d769)) ^ ((0x549a89a4) % (-0x9f9475))))>>>(0x86fa4*(0x91a830b1)))));\n    }\n    return +((+exp(((-((d0)))))));\n  }\n  return f;g2.a2[8] = (4277);/*MXX3*/o0.g2.g2.ReferenceError.prototype.toString = this.g2.ReferenceError.prototype.toString;[1,,];");
/*fuzzSeed-159544250*/count=1326; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-159544250*/count=1327; tryItOut("\"use strict\"; Array.prototype.pop.apply(this.a2, []);");
/*fuzzSeed-159544250*/count=1328; tryItOut("\"use strict\"; \"use asm\"; this.o1.v2 = a2.length;");
/*fuzzSeed-159544250*/count=1329; tryItOut("x.fileName;arguments = b;");
/*fuzzSeed-159544250*/count=1330; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( ! (((((Math.log(-0x100000000) >>> 0) <= y) >>> 0) <= ( + (( + Math.min(x, ( + y))) ** ( ~ x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0, Number.MIN_VALUE, -1/0, 2**53+2, 42, 0x100000001, 1, 0x07fffffff, -0x080000001, -(2**53), 0/0, 0x080000000, Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -0, 2**53-2, 1/0, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-159544250*/count=1331; tryItOut("/*bLoop*/for (let kyumnm = 0; kyumnm < 1; ++kyumnm) { if (kyumnm % 2 == 0) { v0 = Array.prototype.every.call(a1, (function() { try { o0.g1.v1 = (f0 instanceof t1); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a2, 2, ({set: d/*\n*/.ceil, configurable: (x % 12 != 1), enumerable: true})); } catch(e1) { } try { t0 = t0.subarray(19); } catch(e2) { } for (var p in f1) { try { a1.unshift(g1, t0); } catch(e0) { } try { f2 + m2; } catch(e1) { } try { t0 = t1.subarray(5); } catch(e2) { } h2.__proto__ = t1; } return o2; }), s2, i2); } else { Array.prototype.splice.call(a1, 1, 19, this.g0); }  } ");
/*fuzzSeed-159544250*/count=1332; tryItOut("let(w) { throw StopIteration;}");
/*fuzzSeed-159544250*/count=1333; tryItOut("/*infloop*/L:for(c in  '' ) for (var p in f1) { try { b1.toString = f0; } catch(e0) { } try { Array.prototype.unshift.apply(a1, [v1]); } catch(e1) { } v0 = g0.runOffThreadScript(); }");
/*fuzzSeed-159544250*/count=1334; tryItOut("a1.pop(v0);");
/*fuzzSeed-159544250*/count=1335; tryItOut("s1 += s2;");
/*fuzzSeed-159544250*/count=1336; tryItOut("(c = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: undefined, has: decodeURIComponent, hasOwn: function() { return false; }, get: function() { return undefined }, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { return []; }, keys: undefined, }; })(x), Function));");
/*fuzzSeed-159544250*/count=1337; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( ! Math.hypot((( + ( ~ x)) | 0), mathy3((-1/0 >= x), (x <= ( + ( - ( + y)))))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, 0.000000000000001, -(2**53-2), -1/0, 2**53-2, 2**53+2, 1/0, -0x100000001, 42, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, 0/0, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 0x080000000, 2**53, Math.PI, Number.MIN_VALUE, 0x07fffffff, -0x100000000, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -(2**53), 0, 0x0ffffffff, -0x07fffffff, -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-159544250*/count=1338; tryItOut("e2.has(this.s2);");
/*fuzzSeed-159544250*/count=1339; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ! (( ~ (( + Math.expm1((Math.fround(( ~ ( - y))) >>> 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, Number.MIN_VALUE, -0x100000001, 2**53, 0.000000000000001, 1/0, -(2**53+2), -0, 1, -Number.MIN_SAFE_INTEGER, 0, -1/0, -(2**53), 0x100000001, 1.7976931348623157e308, 0x07fffffff, -0x080000001, 42, Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, 0x0ffffffff, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), 0/0, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000]); ");
/*fuzzSeed-159544250*/count=1340; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\\\3\\\\B[\\\\d\\\\w\\u0007\\\\W]*?)\", \"gi\"); var s = \"\"; print(s.replace(r, '\\u0341')); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1341; tryItOut("\"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -2251799813685247.0;\n    i2 = (i0);\n    return (((i0)+(0xdf2fcf07)))|0;\n    return (((0xfcca8dd9)+((0x1e220438))))|0;\n  }\n  return f; })(this, {ff: Math.abs}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0, -0x100000000, 0x100000001, 2**53, -(2**53-2), Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000001, 0x080000000, -1/0, -(2**53+2), -Number.MIN_VALUE, -0x07fffffff, 1, Math.PI, 0x100000000, 0x07fffffff, Number.MIN_VALUE, 1/0, -0x080000000, 2**53+2, 42, 0/0, -0x0ffffffff, -Number.MAX_VALUE, -0, -(2**53), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1342; tryItOut("\"use strict\"; let(x = Math.pow(this.b =  /x/ , (4277)), {z: x.__proto__, d: x, valueOf: {}, x: []} = /*RXUE*//(?:(?=\\v*\u00b0))*?\\1[^]/gyi.exec(\"\\n\"), x = allocationMarker().acosh(), w = [,], x = new (x)((undefined()),  \"\" ), x) { let(w) { yield w;}}");
/*fuzzSeed-159544250*/count=1343; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((( + Math.clz32(( + (( ! Math.asinh(Math.fround(((y >>> 0) >>> (y >>> 0))))) & ( - Math.ceil(y)))))) | 0) ? (Math.fround(Math.imul(Math.fround(Math.max(Math.atan((y >>> 0)), (Math.max((Math.pow(y, x) >>> 0), (Math.fround(( ~ (( + Math.fround(y)) | 0))) >>> 0)) >>> 0))), Math.fround((((( ~ ( + y)) | (Math.atan2((((-0x100000000 << (2**53 | 0)) | 0) , x), -0x07fffffff) | 0)) >>> 0) <= (Math.cosh(x) | 0))))) | 0) : ((( ~ (( + Math.fround(Math.max(mathy1((Math.atan2(x, x) >>> 0), (x >>> 0)), (x >>> 0)))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy3, [-1/0, -0x100000000, -0x0ffffffff, 0, 0x080000000, 42, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, -0x07fffffff, 0.000000000000001, -0x080000000, 1.7976931348623157e308, Math.PI, -(2**53+2), -(2**53), 1, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0x100000001, -(2**53-2), 0x0ffffffff, -0, Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-159544250*/count=1344; tryItOut("\"use strict\"; ;");
/*fuzzSeed-159544250*/count=1345; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i0)-((((x) = ((function factorial_tail(klpfbh, rkrwyo) { ; if (klpfbh == 0) { ; return rkrwyo; } ; return factorial_tail(klpfbh - 1, rkrwyo * klpfbh);  })(0, 1)) >>=  /* Comment */window).yoyo(let (mnlhxn, x, kxdjnm, eval) ++window)) ? (i0) : (i0))+(((-(/*FFI*/ff(((~((!(-0x8000000))*0xe65a7))), ((+abs(((+((-3.777893186295716e+22))))))))|0))|0) <= (0x7fffffff))))|0;\n    return ((((0xb2183ac4) < (0x543ac59c))+(i1)))|0;\n  }\n  return f; })(this, {ff: (-27.revocable( /x/ ).pow).bind((Math.fround)([,,z1]) ^=  ''  || /.|.|\uf5c3|(\\B)(?:(?=[\\S\\cW\u5f1e\u0082-\u9358])){268435457,268435461}(?=(?:\\B))${4,262148}/g)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53-2), 0x080000001, 0x100000001, -0x100000001, -(2**53+2), 2**53+2, -0x07fffffff, 2**53-2, -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0, 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53), 2**53, 42, 1, -0x080000000, 1.7976931348623157e308, -0, -1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, 0x100000000, 0/0, Number.MIN_VALUE, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1346; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=1347; tryItOut("\"use strict\"; for (var v of g0.g2) { try { h2.defineProperty = f1; } catch(e0) { } try { o0.f2 = Proxy.createFunction(h2, o0.f1, f1); } catch(e1) { } try { this.v2 = r1.unicode; } catch(e2) { } e2.delete(o0); }");
/*fuzzSeed-159544250*/count=1348; tryItOut("/*oLoop*/for (bjganu = 0; bjganu < 43; ++bjganu) { Object.defineProperty(this, \"this.v2\", { configurable: false, enumerable: (x % 2 == 1),  get: function() {  return t2.byteOffset; } }); } ");
/*fuzzSeed-159544250*/count=1349; tryItOut("\"use strict\"; v1 = evaluate(\"m1 + h2;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 == 0), sourceIsLazy: true, catchTermination: (x % 3 != 0) }));");
/*fuzzSeed-159544250*/count=1350; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      return ((((0x241af913))))|0;\n    }\n    i0 = (i0);\n    i0 = (i0);\n    d1 = (1.888946593147858e+22);\n    d1 = (-1.03125);\n    d1 = (d1);\n    return ((((((0x572ec999)-((((0xfd301127)-(0xfcd6d9b3)+(0xf23620f4)) & ((-0x8000000)-(0xff6d77a9)-(0xffffffff))) <= (-0x8000000))) & ((0x0) % ((0x43b59*(i0))>>>(((-0x7e95b2) > (0x3b26701a))-(((void options('strict')))))))))-(i0)+(0x9d3a7bd6)))|0;\n  }\n  return f; })(this, {ff: function(y) { for (var v of b0) { try { v0 = Object.prototype.isPrototypeOf.call(b0, b2); } catch(e0) { } try { a2.shift(i0, [,]); } catch(e1) { } /*RXUB*/var r = r0; var s = \"\"; print(r.test(s)); print(r.lastIndex);  } }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [1/0, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, -(2**53-2), -0x100000001, -0x080000001, -(2**53+2), 0x100000000, 42, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, Math.PI, 2**53-2, 0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, 0, 0x07fffffff, -0x0ffffffff, -1/0, 2**53+2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, -Number.MIN_VALUE, 1, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=1351; tryItOut("this.v2 = (a1 instanceof h1);");
/*fuzzSeed-159544250*/count=1352; tryItOut("\"use asm\"; testMathyFunction(mathy5, [1, -0, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 0, 2**53+2, 0x100000000, 0/0, -Number.MAX_VALUE, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, -0x080000001, -1/0, 42, 0x07fffffff, 2**53, -0x100000001, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, 2**53-2, -(2**53), 0x100000001, Math.PI, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=1353; tryItOut("testMathyFunction(mathy5, ['/0/', (function(){return 0;}), '\\0', (new Number(-0)), true, '0', ({valueOf:function(){return '0';}}), 0, (new Boolean(false)), (new Boolean(true)), -0, null, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new String('')), false, 1, [], 0.1, '', NaN, [0], undefined, (new Number(0)), /0/]); ");
/*fuzzSeed-159544250*/count=1354; tryItOut("selectforgc(o2)\n");
/*fuzzSeed-159544250*/count=1355; tryItOut("return;");
/*fuzzSeed-159544250*/count=1356; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.log(( + ( + Math.pow(Math.min(Math.ceil(y), ( + Math.expm1(((1/0 ? ( + ( ~ (-(2**53-2) | 0))) : x) >>> 0)))), Math.fround((( + Math.min(Math.expm1(( + 0x100000001)), Math.hypot(( + Math.hypot(( + x), ( + x))), Math.cosh(( + x))))) >>> 0)))))) | 0); }); testMathyFunction(mathy3, [0x07fffffff, -Number.MIN_VALUE, 1, 0x080000001, -0x100000000, -0x07fffffff, Number.MIN_VALUE, -(2**53), -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 0x100000001, 42, -0x080000000, -1/0, Math.PI, -0, -Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, -Number.MAX_VALUE, 0x080000000, 2**53+2, 0, -0x100000001, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0]); ");
/*fuzzSeed-159544250*/count=1357; tryItOut("mathy2 = (function(x, y) { return ( + ( + ( + Math.asin(( + Math.min(( + y), (void options('strict_mode')))))))); }); ");
/*fuzzSeed-159544250*/count=1358; tryItOut("v2 = null;");
/*fuzzSeed-159544250*/count=1359; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.atanh(( ! (((((x ** ((( + x) | 0) === ( + y))) >>> 0) >> ( + Math.fround(Math.log2(Math.fround(y))))) | 0) < ( ~ y))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, 0x080000000, 0x080000001, -(2**53+2), -1/0, -0x080000001, 0x100000001, 2**53+2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, -0x100000001, Number.MIN_VALUE, 1, -Number.MIN_VALUE, -(2**53), 0.000000000000001, 1.7976931348623157e308, -0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, Math.PI, 2**53-2, 2**53, -(2**53-2), -0x07fffffff, 0, -0, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0]); ");
/*fuzzSeed-159544250*/count=1360; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        i1 = (((((~((0xffffffff) / (0xee44a80d))) < (~~(((((-4398046511105.0)) / ((-17179869185.0)))) % ((-1.2089258196146292e+24)))))) << ((-0x8000000))));\n      }\n    }\n    return (((0xba5a4500)-(0xfe81b086)))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(mttocp){for (var ytqbceiav in this) { }this[\"toString\"] = a;return this; }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=1361; tryItOut("\"use strict\"; print(x);let (omclkj, getter, \u3056, x, cfzwsp) { if((x % 4 != 0)) {m2.set(i1, o2.g2.a1); } }");
/*fuzzSeed-159544250*/count=1362; tryItOut("testMathyFunction(mathy2, [Math.PI, -(2**53+2), -Number.MIN_VALUE, 1/0, 1, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -0x100000000, 0x080000000, 0x080000001, 2**53-2, -(2**53-2), Number.MAX_VALUE, 0x07fffffff, -0x080000001, 42, Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -1/0, -0x07fffffff, 0x0ffffffff, -0x100000001, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, 0, -Number.MIN_SAFE_INTEGER, 2**53, -0]); ");
/*fuzzSeed-159544250*/count=1363; tryItOut("f0 = s2;");
/*fuzzSeed-159544250*/count=1364; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min((Math.sign(( + ( - (Math.atan2(Math.imul(x, ( ! y)), y) >>> 0)))) >>> 0), mathy0((((Math.asin((( + y) | 0)) >>> 0) || mathy0(( + (Math.hypot(y, Math.atan2(y, x)) ? Math.log10(Number.MAX_VALUE) : Math.fround(( + -Number.MIN_SAFE_INTEGER)))), (x < -Number.MIN_VALUE))) >>> 0), ( + Math.hypot(x, (x ? Math.asin((0x0ffffffff >>> 0)) : ( + (mathy0((( + mathy0(( + x), (Number.MAX_SAFE_INTEGER | 0))) | 0), (0 | 0)) >>> 0))))))); }); testMathyFunction(mathy1, [0x100000000, Number.MAX_VALUE, 2**53-2, -(2**53+2), 0/0, 0x080000000, Math.PI, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, 0, 0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, 2**53+2, -0x080000001, 1/0, -0x07fffffff, 1, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, 42, 2**53, -(2**53-2), -(2**53), -0x100000000]); ");
/*fuzzSeed-159544250*/count=1365; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1366; tryItOut("mathy3 = (function(x, y) { return ( + mathy0(( + ( - (( + Math.fround((x ? (y >>> 0) : ))) | 0))), ( + ( ! ( + Math.log2(Math.fround((Math.fround(Math.asin(x)) !== ((-Number.MIN_SAFE_INTEGER % (-0x080000001 | 0)) | 0))))))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -0x080000001, 0/0, 1, 42, 0x080000001, -1/0, -(2**53), 0x100000001, -Number.MAX_VALUE, 2**53-2, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 0x080000000, 0.000000000000001, -0x100000001, -(2**53+2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 0, Math.PI, 1/0, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0x100000000, -0, -0x080000000, 2**53+2, -0x100000000]); ");
/*fuzzSeed-159544250*/count=1367; tryItOut("\"use strict\"; testMathyFunction(mathy1, [42, 0.000000000000001, -0, 1, 0x100000000, -1/0, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 0x080000000, -Number.MAX_VALUE, 2**53, -(2**53), -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000001, 2**53-2, -0x07fffffff, 0/0, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), Math.PI, 0x080000001, 0x100000001, 0x0ffffffff, -0x100000000, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1368; tryItOut("switch((x ? (void version(185)) : this.__defineSetter__(\"yield\", /(?!.|[^])*?/gym))) { default: o1 = g0.objectEmulatingUndefined();break; case 1: o1 + '';break;  }");
/*fuzzSeed-159544250*/count=1369; tryItOut("testMathyFunction(mathy5, [-(2**53+2), 1.7976931348623157e308, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 42, -0x080000001, -0, 0/0, -0x07fffffff, Math.PI, 0x0ffffffff, 2**53+2, 0x100000000, -Number.MAX_VALUE, 1/0, -(2**53-2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, -0x0ffffffff, 0.000000000000001, 0, -Number.MIN_VALUE, -0x100000001, 1, 0x07fffffff, -1/0, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-159544250*/count=1370; tryItOut("a0 + g1.m2;\nyield -17;\n");
/*fuzzSeed-159544250*/count=1371; tryItOut("v1 = Array.prototype.reduce, reduceRight.apply(this.a1, [(function() { try { g2.offThreadCompileScript(\"t2 = new Uint32Array(a1);\"); } catch(e0) { } try { a0.splice(NaN, v1, t2, i1, e1, x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: neuter, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; })((/.|(^|($)\\cM|[^]{0,4}){1,1}/yim >>>=  /x/ ) >>>= (void options('strict'))), Object.prototype.__defineSetter__, (new Function(\"arguments.callee\"))), (WeakMap.prototype.delete).bind(), g2.m2); } catch(e1) { } Array.prototype.sort.apply(a0, [(function() { try { s0.valueOf = f0; } catch(e0) { } i0.next(); return p1; }), h2]); return g0.t1; }), i2]);");
/*fuzzSeed-159544250*/count=1372; tryItOut("\"use strict\"; i2.next();");
/*fuzzSeed-159544250*/count=1373; tryItOut("const x, this.c, nhrsfq, wasmtk, \u3056;s2 + t2;");
/*fuzzSeed-159544250*/count=1374; tryItOut("mathy2 = (function(x, y) { return (Math.pow(((((( - x) | 0) > Math.cosh(Math.exp((-0x100000000 === Math.fround(Math.imul(Math.fround(x), Math.fround(y))))))) >>> 0) | 0), (Math.fround(( ~ mathy1(( + (x | 0)), mathy0(( + x), ( - x))))) | 0)) | 0); }); testMathyFunction(mathy2, [0x080000000, 42, -0x100000001, -Number.MAX_VALUE, -(2**53+2), Number.MAX_VALUE, 0x100000000, 0, -0, 2**53, 0x080000001, -0x080000000, -Number.MIN_VALUE, 1/0, -0x100000000, -1/0, 0x100000001, 1.7976931348623157e308, -0x080000001, 2**53+2, 0x07fffffff, -(2**53), -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1375; tryItOut("\"use strict\"; i1.next();print(x);");
/*fuzzSeed-159544250*/count=1376; tryItOut("Array.prototype.forEach.apply(this.a1, [o0.i0]);");
/*fuzzSeed-159544250*/count=1377; tryItOut("v0 = new Number(i2);");
/*fuzzSeed-159544250*/count=1378; tryItOut("selectforgc(o2);");
/*fuzzSeed-159544250*/count=1379; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float32ArrayView[((0x2c06f26c)) >> 2]) = ((Infinity));\n    {\n      {\n        d1 = (d0);\n      }\n    }\n    {\n      switch ((~(((0x9756e5a) ? (-0x8000000) : (0xfc76e75c))-(0x8a365167)))) {\n        case -1:\n          d0 = (+(-1.0/0.0));\n        case 0:\n          {\n            /*FFI*/ff((((((0xffffffff) ? ((abs((0x5d161e30))|0)) : (-0x8000000))) | (((((0xce4a6ef3))>>>((0xd5f2338b))) < (0x0))-(0xf6b0a878)+(-0xb1990f)))), (((((d0) != (d0))*-0xfffff) >> (((((0xc83b1f15))>>>((0x181d66ff))))+(0xfe2f78ae)))), (((((0xeb58fb21) >= (0x3df781ae))-((0xa077537) == (0x494b271c))) ^ ((0x7ac59228)+(-0x8000000)))));\n          }\n          break;\n        case -1:\n          d1 = (d1);\n          break;\n        case -3:\n          d0 = ((d1) + (+(-1.0/0.0)));\n          break;\n      }\n    }\n    {\n      (Int8ArrayView[((0x12941b6d) % ((((131072.0) > (1.001953125)))>>>(((((0xe0386381))>>>((0xfe2846cd))))))) >> 0]) = (((((-0x8000000)-(-0x533cbfe)-((((0x1fc3eb9c))>>>((0xdb249070))) <= (0x1e911cf2)))>>>((((void version(180)))))))+(/*FFI*/ff(((d0)), ((+((d1)))))|0)+(/*FFI*/ff(((((!(!(0x5937640c)))*-0xc65a4) >> ((0x2d019f)+(0xff15ef53)+((((0x5442e84d)) >> ((-0x8000000))) >= (((0x8ad4d82a)) >> ((0xffffffff))))))))|0));\n    }\n    return (((0xfd67357a)-(/*FFI*/ff(((d0)), ((d0)), ((0x55b4adc8)), ((d1)), ((+(0xa6993b82))), ((+(((!(0xfaa5963e)))|0))), ((d0)))|0)))|0;\n  }\n  return f; })(this, {ff: mathy4}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MAX_VALUE, -0x080000000, -0x07fffffff, -0x100000000, 2**53+2, 0x100000000, 0x07fffffff, Number.MIN_VALUE, -(2**53), Math.PI, 0, 42, -1/0, -0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0x080000001, -0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, -(2**53+2), 1/0, 0x0ffffffff, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-159544250*/count=1380; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ! (Math.log1p((Math.hypot(x, y) >>> 0)) >>> 0)) === (((mathy4(( + ( + ( + y))), Math.hypot(mathy2(x, y), Math.fround(x))) ? ( + Math.tan((((Number.MIN_SAFE_INTEGER | 0) ** (( ~ ( + x)) | 0)) | 0))) : ((x ? ( + x) : x) | 0)) | 0) ? ( - x) : ( + ( + ((Math.max((Math.hypot(-0x100000000, Math.fround((( ! (y | 0)) | 0))) >>> 0), ( + (Math.fround(Math.cosh((((0/0 | 0) !== (1/0 | 0)) | 0))) ? (y != -1/0) : y))) >>> 0) < Number.MAX_VALUE))))); }); ");
/*fuzzSeed-159544250*/count=1381; tryItOut("mathy4 = (function(x, y) { return (Math.imul((((( ! Math.fround((Math.fround((y | 0)) | 0))) >>> 0) ^ (( ! y) >>> 0)) >>> 0), Math.asin((Math.max((Math.atan(((Math.atan(y) >>> 0) >>> 0)) | 0), (x | 0)) | 0))) >>> 0); }); ");
/*fuzzSeed-159544250*/count=1382; tryItOut("\"use strict\"; a2 = Array.prototype.map.call(a2, this.f1, g0);");
/*fuzzSeed-159544250*/count=1383; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x080000000, -0x07fffffff, 0x080000000, Number.MIN_VALUE, 0x100000001, -(2**53+2), -0x080000001, Math.PI, -Number.MAX_VALUE, 2**53+2, 2**53, Number.MAX_SAFE_INTEGER, -0x100000001, 42, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -1/0, 0.000000000000001, 1/0, -Number.MIN_VALUE, 0, -0x100000000, 1, -(2**53), 0/0, -0x0ffffffff, 0x080000001, 0x07fffffff, -0, 2**53-2]); ");
/*fuzzSeed-159544250*/count=1384; tryItOut("\"use strict\"; let w, \u3056 = x = (y) = 16, w = x, xybocm, x = timeout(1800), eval, a, NaN = this, y;/*RXUB*/var r = /.*?|(?=.{65})(($*))|(?:\\cV|[]{0,0})|(?:\\W+?){4,5}/ym; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=1385; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var exp = stdlib.Math.exp;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      (Float32ArrayView[0]) = ((1.25));\n    }\n    {\n      return +((-((Float64ArrayView[0]))));\n    }\n    i0 = (i1);\n    i1 = (i0);\n    i0 = ((0xcebdfc31));\n    {\n      /*FFI*/ff();\n    }\n    i1 = (((((abs((((0xf94479c8)-(0x22e4fa0f)-(0xf999f933)) | (0xfffff*(i1))))|0) <= (imul(((0xffffffff) ? (0x4db15070) : (0xf37ca3f6)), (i0))|0)))>>>((/*FARR*/[].sort(Math.expm1, timeout(1800))))));\n    i1 = (((-(i1))>>>((i1))) <= ((0xfffff*(i0))>>>(((((i1)+(i0))>>>((/*MARR*/[(-1/0), (-1/0), (void 0), (-1/0), ({x:3}), (-1/0), (-1/0), (void 0), (void 0), (-1/0), (void 0)].filter(Int8Array,  '' )))) <= (0xb6162905)))));\n    return +((((1.0009765625)) - ((+exp(((-36028797018963970.0)))))));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var dngzln = []; var usikpn = dngzln += a >>>= dngzln; return usikpn;})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, 0.000000000000001, 0x100000000, 2**53+2, -0x100000000, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, 42, -(2**53), 0, -0x100000001, -Number.MIN_VALUE, 0x0ffffffff, -1/0, 2**53-2, -0x080000001, Number.MAX_VALUE, 0/0, 1, 1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -(2**53-2), -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=1386; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (+pow(((288230376151711740.0)), ((36893488147419103000.0))));\n    d1 = (+(1.0/0.0));\n    {\n      i0 = (0x63e4ecfb);\n    }\n    d1 = (-4398046511104.0);\n    {\n      i0 = ((((0xfd697ed8)) & ((0xe37b188f) / (0x8fe6085a))));\n    }\n    d1 = (+abs(((+pow(((+(0.0/0.0))), ((+(1.0/0.0))))))));\n    {\n      d1 = (65.0);\n    }\n    return ((((0xb5985057) >= (0xaa3d90ff))-((~((i2)-(i0))) <= (((0xf8487740)) << ((0xfdd5f0a2)*-0xe24af)))+(0xfa60b53a)))|0;\n  }\n  return f; })(this, {ff: Math.hypot}, new ArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=1387; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.round(( + Math.atanh(( + Math.hypot((((y | 0) << (( + ({/*TOODEEP*/})) | 0)) >> x), 0x100000000)))))); }); testMathyFunction(mathy0, [2**53+2, -0x080000000, 2**53, -0, 0x080000000, 0/0, 1.7976931348623157e308, 0x080000001, -(2**53), 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, 42, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0x100000000, -(2**53-2), 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, Math.PI, -0x100000001, -0x080000001, Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 0.000000000000001, 1, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1388; tryItOut("g0.v2 = Object.prototype.isPrototypeOf.call(m1, h1);");
/*fuzzSeed-159544250*/count=1389; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1390; tryItOut("\"use strict\"; v0 = (g2 instanceof g0);");
/*fuzzSeed-159544250*/count=1391; tryItOut("\"use strict\"; Array.prototype.splice.apply(a1, [NaN, 5]);");
/*fuzzSeed-159544250*/count=1392; tryItOut("s0 = t2[6];");
/*fuzzSeed-159544250*/count=1393; tryItOut("a0[({valueOf: function() { print(uneval(t2));return 8; }})] = h2;");
/*fuzzSeed-159544250*/count=1394; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return ((((Math.exp((Math.atan2(( + Math.fround(mathy1(Math.fround(x), Math.fround(y)))), ( + y)) >>> 0)) >>> 0) != ( + ( ~ x))) | 0) < (((( ! ( + ((( + -0x080000000) | y) | 0))) ? y : ( + Math.fround(Math.fround(Math.abs((((( + Math.atan2((y >>> 0), (-0x080000001 >>> 0))) | 0) & x) | 0)))))) >>> 0) , Math.log1p((( + (Math.hypot(y, (Math.fround(( - (y | 0))) , Math.fround(y))) | 0)) | 0)))); }); testMathyFunction(mathy4, [-(2**53+2), 0x080000001, Number.MAX_VALUE, 2**53, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, 0x100000001, 1, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, 2**53+2, 2**53-2, 1/0, -1/0, 0x080000000, 0, 0x0ffffffff, -(2**53-2), -0x100000001, -0x080000000, 0/0, 42, -(2**53), -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -0]); ");
/*fuzzSeed-159544250*/count=1395; tryItOut("\"use strict\"; /*vLoop*/for (let kijmpf = 0; kijmpf < 5; ++kijmpf) { var b = kijmpf; [,,z1]; } ");
/*fuzzSeed-159544250*/count=1396; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?=(?!^^|\\\\b|(\\\\B)+?|[^]|.?))?)\", \"gm\"); var s = \"\\n\\n\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1397; tryItOut("\"use strict\"; v0 = (b0 instanceof o0.e1);");
/*fuzzSeed-159544250*/count=1398; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.max(Math.fround(((((((( + Math.fround(mathy1((((x >>> 0) === x) >>> 0), x))) | 0) != ( + ( - Math.imul(((( + mathy0((y >>> 0), ( + x))) / y) >>> 0), y)))) >>> 0) | 0) * (Math.fround(Math.sinh(( + (Math.round(2**53+2) | 0)))) | 0)) | 0)), Math.fround(Math.max((Math.hypot(Math.log10((((x ? 1/0 : y) < y) % y)), (Math.log2((y >>> 0)) >>> 0)) | 0), ((Math.imul((( ! Math.fround((Math.fround(( ! x)) ? y : Math.fround(x)))) >>> 0), (( + ( - ( + y))) >>> 0)) >>> 0) | 0))))); }); ");
/*fuzzSeed-159544250*/count=1399; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1400; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^b-\\\\u8EC8\\\\S\\\\u0004-\\\\u8C31\\\\w]*?\\\\W+*(?:([^])){1,}\", \"gym\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-159544250*/count=1401; tryItOut("do a1.sort((function() { try { v2 = evaluate(\"print(uneval(o1.e1));\", ({ global: this.g2.g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (mathy0)((Math.min(-14, -27)), 5), sourceIsLazy: false, catchTermination: (x % 22 == 0) })); } catch(e0) { } try { g1[16] = g2.a1; } catch(e1) { } /*MXX1*/o0 = g1.g2.Date.prototype.getTime; return g0.g1.i0; })); while((null) && 0);");
/*fuzzSeed-159544250*/count=1402; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.round(Math.atan2(((Math.sqrt((((((y <= -1/0) | 0) >>> 0) ? (y >>> 0) : (y >>> 0)) >>> 0)) >>> 0) & Math.trunc(Math.fround(x))), (Math.tanh((Math.sqrt(( + (( ~ Math.fround(x)) >>> 0))) | 0)) | 0))); }); testMathyFunction(mathy0, [0x0ffffffff, -0x0ffffffff, -0x080000001, 0.000000000000001, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -1/0, 0x07fffffff, 1, -0, 0, -(2**53+2), 0x080000000, 0/0, 2**53-2, 0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 0x100000000, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53, -(2**53), 0x080000001, 42, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=1403; tryItOut("i2 + '';");
/*fuzzSeed-159544250*/count=1404; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var asin = stdlib.Math.asin;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((((0xfe405673)-((((/*FFI*/ff(((((0xfe5c4847)) << ((0xf133daf2)))), ((-295147905179352830000.0)), ((1048577.0)), ((2.3611832414348226e+21)), ((-1.9342813113834067e+25)))|0)*0xfffff)>>>(((((0x3a9bc90f)-(0xf05ca2a6)-(0xfc2c9fa2)) << ((i0)))))))) << (0x53131*(i1))));\n    i1 = (!(!(i1)));\n    i1 = ((+pow(((-1.5474250491067253e+26)), (((timeout(1800)))))));\n    return +((+pow(((0.125)), ((+asin(((4.835703278458517e+24))))))));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), (new Boolean(false)), (new Boolean(true)), undefined, '', -0, true, 0, 1, 0.1, (new Number(0)), '0', /0/, (new Number(-0)), null, false, [0], (function(){return 0;}), NaN, (new String('')), '/0/', [], ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '\\0']); ");
/*fuzzSeed-159544250*/count=1405; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.cosh(( + Math.fround(Math.asin(-(2**53+2))))); }); testMathyFunction(mathy4, [NaN, undefined, (new Number(0)), /0/, '/0/', 1, '\\0', (new Boolean(true)), -0, (new Number(-0)), ({toString:function(){return '0';}}), (function(){return 0;}), [0], objectEmulatingUndefined(), 0.1, '', ({valueOf:function(){return '0';}}), false, 0, true, [], (new Boolean(false)), '0', (new String('')), null, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-159544250*/count=1406; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul(Math.fround(Math.fround(Math.log10(Math.fround((Math.fround(0x080000001) + (y >>> 0)))))), Math.fround(Math.acosh(Math.atan2((((y | 0) << (( ! ((Math.clz32((x >>> 0)) >>> 0) | 0)) | 0)) >>> 0), y)))); }); testMathyFunction(mathy0, [({valueOf:function(){return 0;}}), (new Number(0)), 1, objectEmulatingUndefined(), '', NaN, false, -0, (function(){return 0;}), [0], undefined, '0', (new Number(-0)), ({toString:function(){return '0';}}), 0.1, /0/, [], (new Boolean(true)), true, null, (new String('')), '\\0', 0, ({valueOf:function(){return '0';}}), (new Boolean(false)), '/0/']); ");
/*fuzzSeed-159544250*/count=1407; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.min(Math.fround(mathy2(Math.fround(Math.fround(Math.max(Math.fround(( + ( ~ ( + Math.max(Math.min(x, y), Math.fround(Math.imul(Math.fround(Math.hypot(-0x080000001, x)), Math.fround(Number.MIN_SAFE_INTEGER)))))))), (Math.hypot(( ~ -0x080000001), Math.abs(y)) | 0)))), Math.fround(( + (y | 0))))), ((Math.imul((((-0x100000000 >>> 0) != (x >>> 0)) >>> 0), (( ~ (((Math.atan2(((Math.min(-0x080000001, (Math.fround(Math.max(( + x), Math.fround(y))) | 0)) | 0) >>> 0), ( + y)) | 0) >>> y) >>> 0)) >>> 0)) >>> 0) | 0))); }); ");
/*fuzzSeed-159544250*/count=1408; tryItOut("y = x;v0 + '';");
/*fuzzSeed-159544250*/count=1409; tryItOut("switch((--z)) { default: e0 = new Set(g1);/* no regression tests found */h2.defineProperty = f1;break; break; break; break; case 2: break;  }");
/*fuzzSeed-159544250*/count=1410; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +(x);\n  }\n  return f; })(this, {ff: Object.entries}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [2**53, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, 0x080000000, Number.MAX_SAFE_INTEGER, 1, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 2**53+2, 1.7976931348623157e308, -(2**53), 0x0ffffffff, -0x0ffffffff, 1/0, -0, -(2**53+2), 0, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, Number.MAX_VALUE, 0/0, -(2**53-2), Number.MIN_VALUE, 0.000000000000001, 0x100000000, Math.PI, -Number.MAX_VALUE, 2**53-2, -1/0, -0x100000000, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1411; tryItOut("v0 = b1.byteLength;");
/*fuzzSeed-159544250*/count=1412; tryItOut(";/*infloop*/ for  each(let x in  \"\" ) print(x);");
/*fuzzSeed-159544250*/count=1413; tryItOut(";\n/*bLoop*/for (var khiuem = 0, d; khiuem < 51; ++khiuem) { if (khiuem % 6 == 2) { print(x); } else { o2.t0 = new Uint16Array(v1); }  } \n");
/*fuzzSeed-159544250*/count=1414; tryItOut("mathy2 = (function(x, y) { return (mathy1(Math.fround(( + Math.round(Math.fround((Math.fround(Math.max(Math.hypot(-0x080000001, x), 0x080000000)) != ( + Math.atan2(( - (Math.round(y) >>> 0)), ( + y)))))))), ((Math.atan2(( + (Math.asinh((x * (Math.fround(Math.sign(y)) >>> 0))) | 0)), ( + Math.atan2(Math.hypot(y, y), ( + Math.pow(0x080000000, x))))) ? (( - mathy1(mathy0(( + Math.max(( + y), -0x100000000)), y), -0)) , ( ! ( + 0))) : Math.asin((( ~ (eval(\"/* no regression tests found */\"))) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-159544250*/count=1415; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.clz32(Math.fround((((Math.asinh(x) / Math.log(x)) / Math.acosh(( + ((y !== y) >>> 0)))) - Math.imul(Math.fround(Math.fround(((((Math.imul((0x100000001 | 0), ((Math.fround(y) & Math.fround(-0x080000001)) | 0)) | 0) << x) >>> 0) | (( ! (Math.log1p(y) >>> 0)) >>> 0)))), Math.fround(Math.cbrt((Math.imul(0.000000000000001, (Math.asinh(( + 0x0ffffffff)) | 0)) >>> 0))))))); }); testMathyFunction(mathy0, [2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -0x080000001, -0x0ffffffff, -(2**53), -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, -1/0, -0x100000001, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 0, 1, 2**53+2, -(2**53+2), 1/0, 0x100000000, Math.PI, 0x07fffffff, -0, 0x0ffffffff, 0x100000001, 0x080000000]); ");
/*fuzzSeed-159544250*/count=1416; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x07fffffff, -0x0ffffffff, -0, Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, 0x0ffffffff, 1, 0.000000000000001, Math.PI, -(2**53-2), 0x080000000, -(2**53+2), 0x100000000, Number.MIN_VALUE, -0x100000000, 0/0, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, -1/0, 42, 1/0, 0x080000001, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1417; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(Math.acosh((Math.atan2((Math.min(Math.sin(x), ( ~ ((-0x0ffffffff , 0.000000000000001) != 0.000000000000001))) >>> 0), (((Math.sqrt(( - (1.7976931348623157e308 | 0))) != (x >>> 0)) ^ Math.log(y)) >>> 0)) >>> 0))) - Math.sin(( + Math.imul(Math.clz32(Math.min((( ! x) | 0), (x - y))), ( + y))))); }); testMathyFunction(mathy0, [0x080000000, 0x100000001, -0x080000001, 0/0, 0, 0x080000001, Number.MIN_VALUE, 2**53-2, 0.000000000000001, -0x080000000, 1, -(2**53), 2**53, -0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53-2), -0x100000000, -Number.MAX_VALUE, -0x0ffffffff, 0x100000000, -0, 2**53+2, Number.MAX_VALUE, -1/0, Math.PI, 0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1418; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"(?=(?=\\\\2{0,}|.[^\\u06d8-\\\\\\u00ff\\\\0\\\\r]+?[^]\\u000b{34359738369}(?=(\\\\b))|\\\\d|\\uc34a|\\\\B[^]+?|\\\\B+?|^|(?:[\\\\u00cD\\u3b0e-\\ua181](\\\\b))|[^]))\", \"gi\"); var s = \"\\n \\n\\n\\u26f7\\u26f7\\u26f7\\u000b\\n\\u000b\\u26f7\\u26f7\\u26f7\\u000b\\u26f7\\u26f7\\u26f7\\u000b\\u26f7\\u26f7\\u26f7\\u000b\\u26f7\\u26f7\\u26f7\\u000b\\u26f7\\u26f7\\u26f7\\u000b\\u26f7\\u26f7\\u26f7\\u000b\\u26f7\\u26f7\\u26f7\\u000b{\\u000b1\\u008f1\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1419; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-159544250*/count=1420; tryItOut("/*RXUB*/var r = o1.o2.r1; var s = \"\\u0013\"; print(s.replace(r, (/*RXUE*//[^]|(?=.)/gim.exec(\"\\n\")), \"\")); ");
/*fuzzSeed-159544250*/count=1421; tryItOut("\"use strict\"; for(let e in (function() { yield (4277); } })()) let(x, sjfxfn, x = new (new RegExp(\"(?:[^\\\\d\\\\cU-\\u009b\\\\S\\\\w])|.|\\\\x60{2,}(?:(.)|.*?)*|.+?|(?=\\\\1)|(?:(?=[\\ue671\\\\s!\\\\B-\\u0300]){4}.)\", \"i\"))(arguments), e, {} = e, c, e = e, a = (4277), b = \"\\uF676\", lhxaom) { b2 = new SharedArrayBuffer(7);}");
/*fuzzSeed-159544250*/count=1422; tryItOut("\"use strict\"; f2 = Proxy.createFunction(h1, f0, o2.g0.f1);let c = (true >> SyntaxError((undefined)(), \"\\u8AA0\"));");
/*fuzzSeed-159544250*/count=1423; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (72057594037927940.0);\n    switch ((0x3c67505d)) {\n      case -1:\n        return +((Float64ArrayView[0]));\n        break;\n      default:\n        i1 = (0xffffffff);\n    }\n    i1 = (0xc9e3a6bc);\n    {\n      {\n        {\n          i1 = ((0xbed24109));\n        }\n      }\n    }\n    return +(((4.722366482869645e+21)));\n  }\n  return f; })(this, {ff: (neuter).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0.000000000000001, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, -Number.MAX_VALUE, 0x080000000, -(2**53-2), 1/0, 2**53+2, Number.MAX_VALUE, -(2**53), -0, -1/0, Math.PI, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -0x100000000, 0x080000001, Number.MIN_VALUE, 0/0, -0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, 2**53-2, 0, -0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, -0x100000001, 0x100000001]); ");
/*fuzzSeed-159544250*/count=1424; tryItOut("\"use strict\"; print(eval(\"/* no regression tests found */\"));function yield(x, x) { return (4277) } /*ADP-3*/Object.defineProperty(this.a0, 19, { configurable: (x % 20 == 7), enumerable: false, writable: true, value: g2 });");
/*fuzzSeed-159544250*/count=1425; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (( ~ ((mathy1(( + ( + ( + x))), ((mathy0((x | 0), (mathy3(y, ( + x)) | 0)) >>> 0) >>> 0)) << ( - Math.fround((y && y)))) | 0)) | 0)); }); ");
/*fuzzSeed-159544250*/count=1426; tryItOut("t0[17] = x;");
/*fuzzSeed-159544250*/count=1427; tryItOut("\"use strict\"; /*vLoop*/for (sygnxr = 0; sygnxr < 28; ++sygnxr) { const a = sygnxr; arguments; } ");
/*fuzzSeed-159544250*/count=1428; tryItOut("/*oLoop*/for (var cydaot = 0; cydaot < 23; ([]), ++cydaot) { Array.prototype.push.apply(this.a0, [i0, f0]); } ");
/*fuzzSeed-159544250*/count=1429; tryItOut("print(s0);");
/*fuzzSeed-159544250*/count=1430; tryItOut("\"use strict\"; for (var v of h2) { try { for (var p in g2.v2) { g2.s0 += s2; } } catch(e0) { } try { neuter(b1, \"change-data\"); } catch(e1) { } try { v2 = r1.ignoreCase; } catch(e2) { } o2.o2.t2.set(t0, 17); }");
/*fuzzSeed-159544250*/count=1431; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.pow(( ! (mathy1(Math.tanh(Math.fround((Math.fround(0x080000001) !== Math.fround(Math.fround((-(2**53-2) >>> y)))))), (x | 0)) | 0)), (Math.hypot((Math.log2((Math.fround(( - y)) >>> 0)) >>> 0), Math.exp(( - ( + ((x | 0) === (x | 0)))))) | 0)); }); ");
/*fuzzSeed-159544250*/count=1432; tryItOut("if(true) print(x); else  if (/*FARR*/[].sort(runOffThreadScript)) {x = v2; }");
/*fuzzSeed-159544250*/count=1433; tryItOut("\"use strict\"; /*infloop*/ for (var arguments[\"toString\"] of -19) {g0.m2.get(v2);; }");
/*fuzzSeed-159544250*/count=1434; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.log1p((( ~ Math.fround(Math.max(( + ( + mathy0(( + -0), ( + x)))), x))) | 0)) | 0), Math.imul(( + Math.fround(((Math.fround(Math.cbrt(Math.fround(( - x)))) || ( + Math.log1p(( + x)))) != (mathy0((Math.max(x, 42) | 0), (Math.acosh(( + 1.7976931348623157e308)) | 0)) | 0)))), Math.sqrt(( ! -Number.MAX_SAFE_INTEGER)))); }); ");
/*fuzzSeed-159544250*/count=1435; tryItOut("/*RXUB*/var r = /(?:(?=[^\\s\\s]*?))/gy; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=1436; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?![\\\\b-\\ud005\\\\W]{3}))*\", \"gi\"); var s = \"{{{{\\u0009{\\u0009\\u0009\\u0009\\u0009\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1437; tryItOut("\"use strict\"; e1.has(g0.a0);");
/*fuzzSeed-159544250*/count=1438; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -0x100000000, 0x080000001, -(2**53), 0x100000001, -(2**53+2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, 0x07fffffff, 0, 1.7976931348623157e308, -0x100000001, 0x100000000, -(2**53-2), 42, -0x07fffffff, Math.PI, 0/0, 2**53, Number.MAX_VALUE, 0x080000000, -0x080000000, -1/0, -0, -0x0ffffffff, -0x080000001, 1, 2**53-2, 1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1439; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-159544250*/count=1440; tryItOut("\"use strict\"; /* no regression tests found */function \u3056(x, x, x, x, c, x, z, x, {x: {x: []}}, {x: x}, eval, x, x = \"\\u99EE\", x, x, c, x = function ([y]) { }, NaN, c, \u3056, x, eval, e, x, x =  /x/g , x, w, a = -3, x, x, x, x, d, w, this.x = /(\\2)(?:\\B{0})|\\b+.+\\B|\\w{3}/yim, e, x =  /x/g , e, c, e, b = e, d = \"\\uBC29\", x, b, x, b =  /x/ , x, y, x, x, x, \u3056, x =  \"\" , d, x = \"\\u973B\", \u3056, x, w = window, window, e, window, y, x, x = \"\\u6262\", y, x, x, \u3056, x, x, b, ...c) { return (x--) } a2 = g2.objectEmulatingUndefined();");
/*fuzzSeed-159544250*/count=1441; tryItOut("print(h1);");
/*fuzzSeed-159544250*/count=1442; tryItOut("mathy5 = (function(x, y) { return ( - (( + ( + ( - Math.fround((y >>> Math.fround(mathy2(((y == ( + Math.round(x))) >>> 0), (x >>> 0)))))))) >>> 0)); }); testMathyFunction(mathy5, [2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), 0x100000001, Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, 2**53-2, 0x07fffffff, -0x100000001, -(2**53-2), -0x07fffffff, 2**53, 0x0ffffffff, 1/0, -Number.MAX_VALUE, 0x080000001, 0x080000000, 1, 0, Math.PI, 0x100000000, -0, -Number.MAX_SAFE_INTEGER, -0x080000000, 42]); ");
/*fuzzSeed-159544250*/count=1443; tryItOut("testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0, Number.MIN_VALUE, 1, -Number.MAX_VALUE, -0x080000000, -(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, -0x0ffffffff, 0/0, -0x07fffffff, 1.7976931348623157e308, Math.PI, 42, -0x100000000, 1/0, 0x07fffffff, -1/0, -0x100000001, 0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, 0x100000001, 0x080000000, 2**53-2, Number.MAX_VALUE, -0, 2**53]); ");
/*fuzzSeed-159544250*/count=1444; tryItOut("/*ADP-3*/Object.defineProperty(a1, 16, { configurable: true, enumerable: (x % 6 == 0), writable: (x % 6 != 2), value: b2 });");
/*fuzzSeed-159544250*/count=1445; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround(Math.imul((( + (y ? -0x07fffffff : (((Math.round(y) | 0) + (y | 0)) | 0))) && ( + (Math.fround((x ? Math.fround(y) : x)) < Math.max((1.7976931348623157e308 | 0), x)))), ( + (( + (( - (y | 0)) | 0)) === (Math.max((y >>> 0), (((0 & x) ** x) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy5, [0.1, objectEmulatingUndefined(), 1, (new Boolean(false)), -0, '\\0', ({valueOf:function(){return 0;}}), undefined, '0', (new Number(0)), (new Number(-0)), (new Boolean(true)), (function(){return 0;}), 0, [], true, false, [0], '', '/0/', ({toString:function(){return '0';}}), null, ({valueOf:function(){return '0';}}), NaN, /0/, (new String(''))]); ");
/*fuzzSeed-159544250*/count=1446; tryItOut("let z = this.zzz.zzz = x, {} = x, grjker, x = (4277), \u3056 = \nintern(this.__defineSetter__(\"x\", function(y) { \"use strict\"; yield y; throw /\\x94/ym;; yield y; })), yctgvb;((4277))\nlet v2 = g2.eval(\"mathy2 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var Infinity = stdlib.Infinity;\\n  var ff = foreign.ff;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    var d3 = -536870913.0;\\n    return +((+(1.0/0.0)));\\n    (Float32ArrayView[0]) = ((d0));\\n    i1 = ((-34359738369.0) <= (2049.0));\\n    i1 = (i2);\\n    i2 = (/*FFI*/ff(((-1.001953125)), ((-576460752303423500.0)), ((i2)), ((+abs(((Infinity))))), ((((((0xfeea750e))>>>((-0x8000000))) / (((0xfd4d4b58))>>>((0xd176b94e)))) | ((i2)+(0xc37bafca)-(i2)))), ((d3)), ((~((0x667c5e9) / (0x54886d63)))), ((((0xffffffff)) & ((0xa9cc6133)))), ((((0xfcedadf4)) << ((0x97fcd4a0)))), ((1.001953125)), ((32768.0)), ((-34359738369.0)))|0);\\n    i2 = (i1);\\n    d0 = (274877906945.0);\\n    return +((-1.2089258196146292e+24));\\n  }\\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); \");");
/*fuzzSeed-159544250*/count=1447; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(((Math.fround(((( + ((Math.acosh(((-Number.MAX_SAFE_INTEGER >>> 0) <= (Math.trunc(Math.fround(y)) >>> 0))) >>> 0) >>> 0)) >>> 0) / y)) >> ((Math.pow(Math.exp((( + -Number.MAX_SAFE_INTEGER) === ( + Math.imul(-Number.MIN_VALUE, y)))), (Math.acosh(x) >>> 0)) >>> 0) > Math.max(Math.acosh((( ~ y) >>> 0)), x))) >>> 0)), Math.fround(Math.min((Math.fround(mathy2((x >>> 0), (Math.fround(Math.asinh(Math.fround(y))) >>> 0))) | 0), Math.abs(( - -(2**53-2)))))); }); testMathyFunction(mathy3, [-0x0ffffffff, Number.MAX_VALUE, 0x080000001, -0, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 1, 0x100000000, 1/0, -0x100000000, 0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, 2**53+2, -Number.MIN_VALUE, 0x07fffffff, -1/0, -(2**53), 42, 0, 0x080000000, 2**53, -(2**53+2), -0x07fffffff, 1.7976931348623157e308, 0x100000001, -(2**53-2), Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-159544250*/count=1448; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.exp(Math.hypot(Math.max((Math.fround((( ! x) ^ Math.fround(x))) | 0), Math.sign((Number.MIN_VALUE < x))), ( + ( - Number.MAX_VALUE)))); }); testMathyFunction(mathy3, [-0x100000000, 0x100000000, Number.MAX_VALUE, 1/0, -Number.MIN_VALUE, -1/0, -0x080000001, 42, 0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, 0.000000000000001, -0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, -(2**53), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0, 0/0, 0, 0x100000001, 2**53, 0x080000000, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), Math.PI, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1449; tryItOut("\"use strict\"; Array.prototype.shift.apply(a0, [m0, b2]);");
/*fuzzSeed-159544250*/count=1450; tryItOut("h2.iterate = (function(j) { f2(j); });");
/*fuzzSeed-159544250*/count=1451; tryItOut("\"use strict\"; print(x = x);");
/*fuzzSeed-159544250*/count=1452; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + (( + Math.atan2(( + mathy0(( + mathy0((( ! (Math.PI >>> 0)) >>> 0), x)), ( + (Math.log1p(( + ( ~ (x >>> 0)))) >>> 0)))), Math.atan2(Math.imul(x, Math.imul(Math.cos(-(2**53-2)), x)), -0x100000001))) , Math.fround(Math.clz32(( + (( - ((Math.max(x, Array.prototype.forEach.call(g2.a1, (function mcc_() { var wnoxlo = 0; return function() { ++wnoxlo; if (wnoxlo > 5) { dumpln('hit!'); try { o2.toString = (function() { try { selectforgc(o0); } catch(e0) { } v2 + this.s1; return e1; }); } catch(e0) { } try { for (var p in s2) { try { (void schedulegc(g1)); } catch(e0) { } Object.defineProperty(this, \"v2\", { configurable: \"\\u3E42\", enumerable: false,  get: function() {  return t1.length; } }); } } catch(e1) { } g1.v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: this, noScriptRval: true, sourceIsLazy: true, catchTermination: false, sourceMapURL: o0.s1 })); } else { dumpln('miss!'); s1 + ''; } };})());) >>> 0) >>> 0)) >>> 0)))))), ( + Math.fround(( - Math.atan2(( ! y), ( + x))))))); }); ");
/*fuzzSeed-159544250*/count=1453; tryItOut("/*RXUB*/var r = /\\2/ym; var s = x; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=1454; tryItOut("\"use strict\"; let (y) { m0.get(a2); }");
/*fuzzSeed-159544250*/count=1455; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy0((Math.acos(( + Math.fround(Math.sqrt(Math.fround((Math.pow(y, (Math.clz32(Math.fround(x)) | 0)) | 0)))))) | 0), (Math.fround(mathy0(Math.fround(Math.atanh((( ! (x >>> 0)) >>> 0))), Math.fround(x))) ? ( + y) : Math.fround(Math.exp(x)))) < Math.round(Math.log(Math.fround(( ~ (Number.MAX_VALUE ** (x | 0))))))); }); ");
/*fuzzSeed-159544250*/count=1456; tryItOut("m0 = new Map(t0);");
/*fuzzSeed-159544250*/count=1457; tryItOut("var fdqpcy, x, qjoyeh, x = (yield false), x = ({/*toXFun*/valueOf: function() { return  /x/ ; },  set blink \u3056 (...\u3056) { i2 + o2.g1.o0.m2; }  }), e = \"\\u653F\", b, b, x, yuxneq;print(/*MARR*/[-0x100000001, 0x0ffffffff, -0x100000001, 0x0ffffffff, (void 0), 0x0ffffffff, NaN, (void 0), NaN, (void 0), (void 0), -0x100000001, -0x100000001, (void 0), (void 0), NaN, NaN, -0x100000001, NaN, -0x100000001, 0x0ffffffff, -0x100000001].map(new Function));");
/*fuzzSeed-159544250*/count=1458; tryItOut("tkxoyb(({x: Math.sign(x)}));/*hhh*/function tkxoyb(){let (uxbmcy, x = new RegExp(\"\\u0082\", \"gyi\").__defineGetter__(\"x\", (...eval) =>  { yield /(?!\\W)(?:(\\b+)){0,2}(?!(?:\\u0014)|[^])+/gy } ), x = x - true, x = /*RXUE*/new RegExp(\"\\\\D*|\\\\u00B6|\\\\W{1,}\", \"gyi\").exec(\"\\u00d6a\\u00d6a\\u00d6a\\u00d6a\\u00d6a\\u00d6a0\\u00d6a\\u00d6a\"), d, z) { for (var p in v2) { t0 = t1.subarray(8, 0); } }}");
/*fuzzSeed-159544250*/count=1459; tryItOut("\"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+/*FFI*/ff(((~~(-140737488355329.0))), ((+(0.0/0.0))), ((-1.25)))));\n    return +((1125899906842625.0));\n  }\n  return f; })(this, {ff: new Function}, new ArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=1460; tryItOut("");
/*fuzzSeed-159544250*/count=1461; tryItOut("\"use strict\"; t0 = t0.subarray(new Boolean(true), v1);");
/*fuzzSeed-159544250*/count=1462; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return Math.atan2(Math.ceil(Math.imul(( - Math.fround(2**53-2)), (( + Math.imul(y, ( ! x))) >>> 0))), Math.atan(Math.fround(Math.fround(((Math.hypot(y, x) >>> 0) ^ (x >>> 0)))))); }); testMathyFunction(mathy5, /*MARR*/[(-1), undefined, (-1), undefined, undefined, undefined, undefined, (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), undefined, undefined, (-1), undefined, (-1), undefined, (-1), undefined, (-1), undefined, undefined, (-1), undefined, undefined, undefined, (-1), (-1), undefined, undefined, undefined, undefined, undefined, (-1), undefined, (-1), undefined, (-1), (-1), (-1), undefined, (-1), undefined, (-1), (-1), undefined, (-1), undefined, undefined, undefined, (-1), (-1), (-1), (-1), (-1)]); ");
/*fuzzSeed-159544250*/count=1463; tryItOut("/* no regression tests found */function a() /x/g v0 = Object.prototype.isPrototypeOf.call(p2, i1);");
/*fuzzSeed-159544250*/count=1464; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.acosh(((Math.pow(Math.fround(Math.pow((Math.min((x ? Math.fround(( + y)) : x), y) | 0), (Math.hypot((Math.max((x ^ y), -Number.MIN_SAFE_INTEGER) >>> 0), ((mathy0((-Number.MAX_VALUE >>> 0), (x >>> 0)) >>> 0) >>> 0)) >>> 0))), y) - Math.sinh(( + Math.hypot(y, ( + y))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-159544250*/count=1465; tryItOut("/*RXUB*/var r = new RegExp(\"(?:[^]?)\", \"gy\"); var s = \"\\n\\n\\n\"; print(s.replace(r, '')); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1466; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=1467; tryItOut("mathy5 = (function(x, y) { return mathy0(( + ( + (Math.fround(Math.imul((mathy2(Math.fround((( + ( + ( + ( + x)))) * ( + x))), y) >>> 0), (Math.hypot(Math.fround(x), y) >>> 0))) >>> 0))), Math.ceil((Math.acosh(Math.log10(x)) >>> 0))); }); testMathyFunction(mathy5, /*MARR*/[({}), [(void 0)], ({}), arguments, [(void 0)], ({}), ({}), [(void 0)], [(void 0)], null, null, null, arguments, null, null, [(void 0)], arguments, null, [(void 0)], [(void 0)], [(void 0)], ({}),  '\\0' , null, [(void 0)], [(void 0)], ({}), ({}), null, [(void 0)],  '\\0' , ({}), null, null,  '\\0' , null, ({}), null, arguments, arguments, ({}), arguments, null, ({}), [(void 0)], [(void 0)], null, [(void 0)], ({}), arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments,  '\\0' , arguments, arguments, [(void 0)], arguments, ({}), arguments,  '\\0' , ({}), null, arguments, ({}),  '\\0' ,  '\\0' , [(void 0)], [(void 0)], arguments, null, arguments, [(void 0)], null, ({}), ({}),  '\\0' , null, [(void 0)], ({}),  '\\0' , ({}), ({}), ({}),  '\\0' , arguments, null, null, arguments,  '\\0' ]); ");
/*fuzzSeed-159544250*/count=1468; tryItOut("\"use strict\"; a0.reverse(i2);");
/*fuzzSeed-159544250*/count=1469; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-159544250*/count=1470; tryItOut("for(let b = (4277) in (String.prototype.slice.prototype)) g2.t2[8] = Uint16Array((4277), b);");
/*fuzzSeed-159544250*/count=1471; tryItOut("f0 = a2[(4277)];");
/*fuzzSeed-159544250*/count=1472; tryItOut("mathy0 = (function(x, y) { return ((( + ( ! Math.atan2(Math.fround(y), Math.fround(x)))) != Math.fround(( ! y))) % (Math.sqrt((( ~ ( + (( + Math.hypot(0.000000000000001, Math.fround(-0x100000001))) > x))) | 0)) | 0)); }); testMathyFunction(mathy0, [1/0, 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), 0.000000000000001, 42, 0x100000001, 0x080000000, -0x080000000, 2**53, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0, -0x080000001, -0x0ffffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, Math.PI, -1/0, -(2**53-2), 0x07fffffff, 2**53+2, -0x100000001, -(2**53), 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, 0x080000001, -0x100000000]); ");
/*fuzzSeed-159544250*/count=1473; tryItOut("\"use strict\"; function shapeyConstructor(bntaxf){this[new String(\"12\")] = new ({/*TOODEEP*/})();return this; }/*tLoopC*/for (let x of x for (window in  /* Comment */[[]].throw( /x/g )) for (e of ((makeFinalizeObserver('tenured'))))) { try{let lqxowh = shapeyConstructor(x); print('EETT'); \u000cx%=y;/*oLoop*/for (var gtkcmj = 0, null; gtkcmj < 3; ++gtkcmj) { o2 + f2; } }catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-159544250*/count=1474; tryItOut("\"use strict\"; a1.sort((function() { try { v1 = null; } catch(e0) { } try { s1 = t2[--8589934592]; } catch(e1) { } try { Array.prototype.sort.call(a0, (function() { try { this.v1 = t0.length; } catch(e0) { } try { this.e1.has(x); } catch(e1) { } try { g1.offThreadCompileScript(\"m2.has(v1);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (void options('strict')), noScriptRval: false, sourceIsLazy: new (d)() %= (4277), catchTermination: (x % 10 == 8) })); } catch(e2) { } o0.valueOf = f1; return o2; })); } catch(e2) { } o2.m0.set(t2, o2.o0.b1); return v1; }), i2);");
/*fuzzSeed-159544250*/count=1475; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + ( + ( + (Math.fround(x) == Math.fround(y))))), ( + ( ! (( - (( ! (Math.fround(Math.imul(Math.fround(y), Math.fround((mathy0(1, (x >>> 0)) % y)))) | 0)) | 0)) >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), arguments.callee, 2, arguments, objectEmulatingUndefined(), arguments, arguments, arguments, 2, objectEmulatingUndefined(), arguments.callee, arguments, 2, arguments.callee, 2, objectEmulatingUndefined(), arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.callee, arguments.callee, arguments, objectEmulatingUndefined(), 2, arguments.callee, objectEmulatingUndefined(), arguments, objectEmulatingUndefined(), arguments, arguments.callee, arguments.callee, arguments, arguments.callee, arguments.callee, arguments.callee, arguments, 2, objectEmulatingUndefined(), arguments, arguments.callee, arguments, objectEmulatingUndefined(), arguments.callee, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments.callee, arguments.callee]); ");
/*fuzzSeed-159544250*/count=1476; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.max(( + ((0.000000000000001 ** y) >>> Math.fround((( - y) || Number.MAX_VALUE)))), ((Math.fround(( - ((Math.cbrt((x >>> 0)) >>> 0) >>> 0))) >>> 0) ** ((mathy2((x | 0), x) >>> 0) >>> 0))) * ((( + x) | Math.fround(( + ( + Math.acos(2**53-2))))) ** Math.imul(( + Math.imul(-(2**53-2), (( - y) ** Math.fround(Math.max(Math.fround(x), Math.fround(y)))))), ( + Math.ceil(y))))); }); ");
/*fuzzSeed-159544250*/count=1477; tryItOut("\"use strict\"; var b = /*MARR*/[new Number(1), (void 0), (void 0), (void 0), new String('q'), new String('q'), new String('q'), new Number(1), {x:3}, new String('q'), new Number(1), (void 0), new Number(1), (void 0), new Number(1), new Number(1), new Number(1), {x:3}, (void 0), (void 0)].filter(Boolean, (uneval(new RegExp(\"(?!(?!\\\\B)|\\\\b{9,})\", \"yim\")))), tqianb, x = x, x, \u3056, d =  /x/ , \u3056, z;M: for (var a of e) (window);");
/*fuzzSeed-159544250*/count=1478; tryItOut("/*tLoop*/for (let z of /*MARR*/[ /x/ ,  /x/ , new Number(1.5), [], [], new Number(1.5), [],  /x/ , new Number(1.5), [], [],  /x/ , new Number(1.5), [],  /x/ , new Number(1.5), new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ ,  /x/ , new Number(1.5), new Number(1.5),  /x/ ,  /x/ ]) { Object.defineProperty(this, \"v2\", { configurable: this.__defineSetter__(\"z\", ({/*TOODEEP*/})), enumerable: true,  get: function() {  return evalcx(\"v2 = g0.eval(\\\"print(x);\\\");\", this.g1); } }); }");
/*fuzzSeed-159544250*/count=1479; tryItOut("p1 + '';");
/*fuzzSeed-159544250*/count=1480; tryItOut("mathy4 = (function(x, y) { return ((((Math.asin(((Math.tanh(x) >>> 0) | 0)) | 0) >>> 0) == (( + Math.hypot(( + (( + (y >>> 0)) >>> 0)), Math.fround(y))) ? y : (2**53-2 ? (( ! (( ! x) | 0)) | 0) : (x | 0)))) - Math.fround(Math.pow(Math.acos((Math.sin((( + (x * 0x080000000)) >>> 0)) | 0)), Math.fround(Math.atan2(Math.fround(Math.min((x >= Number.MIN_VALUE), ((((((( + Math.acosh(x)) | 0) % (y | 0)) | 0) >>> 0) >= (x >>> 0)) >>> 0))), Math.fround((Math.fround((Math.fround(( + (( + x) ? ( + x) : y))) & ( ~ -Number.MAX_SAFE_INTEGER))) == x))))))); }); testMathyFunction(mathy4, /*MARR*/[ '' , null, null, null,  /x/g , true,  /x/g , null, true,  '' , true,  '' ,  '' , null, null,  '' , true,  /x/g ,  '' , null, true, true, true, null]); ");
/*fuzzSeed-159544250*/count=1481; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    switch (((((0x69747aff) <= (0x38387d9b))-(0xaa3cabe7)) << (((0x41293241) < (0x362d42b4))+((0xb1d18e04) > (0x0))))) {\n      default:\n        {\n          i0 = (-0x8000000);\n        }\n    }\n    return ((((0x446b2371))+(0x2daa412e)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0, Number.MAX_VALUE, 2**53+2, -(2**53), 0x0ffffffff, 0x100000000, 1, 0/0, 1.7976931348623157e308, Number.MIN_VALUE, 42, -1/0, -0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, 0x100000001, -(2**53+2), 2**53-2, -Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, -0x07fffffff, -0x0ffffffff, -0x100000000, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=1482; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.cos(( + ( ! ((( ! (0x100000000 >>> 0)) >>> 0) > Math.fround(mathy0(Math.max((y != (y | 0)), (x >= 1)), 0x080000001)))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x07fffffff, 1/0, 2**53+2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -0x080000000, -Number.MIN_VALUE, 0x100000001, -0, -0x080000001, 42, -0x100000000, Number.MAX_VALUE, 0x080000001, 1, 0, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, 0x07fffffff, -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, 0x080000000, 2**53, 2**53-2, 0.000000000000001, 0/0]); ");
/*fuzzSeed-159544250*/count=1483; tryItOut("v1 = t0.byteOffset;");
/*fuzzSeed-159544250*/count=1484; tryItOut("for(let y in (((((4277)).call(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; })(window), mathy2), ) ^ x))(x))){o1.v0 = (h2 instanceof h0); }");
/*fuzzSeed-159544250*/count=1485; tryItOut("/*RXUB*/var r = /(?!$|[\\u4D4a-\\uA2D1\\S]*?*?|(?!\\2|\\b|[^]\\1)+?)/gyi; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=1486; tryItOut("/*RXUB*/var r = /[^\\w\\t]|\\u00fA|.|\\s{2,4}[^\\u0047-\u00ee\\x42][^]\\b{2,}{2,}/y; var s = \"\\u00fa\\u00fa0000_\\u0091\\nda8\\naa1\\ufac6\\u907ea1F0000_\\u0091\\nda8\\naa1\\ufac6\\u907ea1F0000_\\u0091\\nda8\\naa1\\ufac6\\u907ea1F\"; print(s.replace(r, '', \"gyi\")); ");
/*fuzzSeed-159544250*/count=1487; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((Math.fround((( + ( ~ ( + x))) * Math.fround((( - Math.fround(( - Math.fround(( ! Math.fround(x)))))) >>> 0)))) , ((( + Math.fround(Math.sqrt(Math.fround(mathy0(y, -1/0))))) - (Math.min((x | 0), (Math.atan2((x | 0), (( + Math.min(( + x), ( + mathy0(y, 0x0ffffffff)))) | 0)) | 0)) | 0)) | 0)) ? Math.acosh(Math.ceil(Math.hypot((( + (Math.tan(y) | 0)) | 0), ((( + mathy0(-0x07fffffff, (mathy0(1/0, x) | 0))) != (y | 0)) | 0)))) : (((Math.sign(Math.fround((Math.fround(Math.log1p((y | 0))) >> Math.fround(Math.min(x, 0))))) | 0) < (mathy0((y >>> 0), (Math.atan2(Math.fround(mathy0(Math.fround(y), Math.fround(x))), Math.imul(y, (x >>> 0))) !== -0x100000000)) | 0)) | 0)); }); testMathyFunction(mathy1, [-0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 1/0, Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, 2**53+2, 0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0x100000001, 0, -(2**53-2), 0/0, Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -0x07fffffff, -Number.MAX_VALUE, -0x080000000, 42, 1, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), 2**53, -0x100000000, -0x080000001, 0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1488; tryItOut("\"use strict\"; switch(e = false) { default: (void schedulegc(g2));case 8: print(x);break; print(x);break; break;  }");
/*fuzzSeed-159544250*/count=1489; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ (((Math.min(y, Math.fround(Math.hypot(( + Math.clz32(( + y))), (-Number.MIN_SAFE_INTEGER >>> 0)))) >>> 0) % (Math.min(y, x) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, 0, -0x080000001, 42, 0.000000000000001, -0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), 2**53+2, -Number.MAX_VALUE, 2**53-2, -(2**53), -0x100000001, -0x07fffffff, 0x080000000, -0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, 2**53, -1/0, 0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, Math.PI, 1, Number.MAX_VALUE, -0, 0/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1490; tryItOut("/*vLoop*/for (let phxabw = 0; phxabw < 61; ++phxabw) { a = phxabw; while((a) && 0){print([1,,]);yield; } } ");
/*fuzzSeed-159544250*/count=1491; tryItOut("/*RXUB*/var r = new RegExp(\"$(?=[]$|(..?)|\\\\1)\\\\2\\\\1|(?:(?=[].)\\\\3+?|\\\\s{1})\", \"y\"); var s = \"\\u074a\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-159544250*/count=1492; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((Math.trunc((( ! (2**53 >>> 0)) >>> 0)) | 0) <= (Math.max(Math.pow(2**53-2, ( + ( - ( + (Number.MAX_VALUE !== -0x080000000))))), Math.fround((Math.clz32((( ~ ( ~ ( + ( ! x)))) | 0)) | 0))) | 0)) | 0); }); ");
/*fuzzSeed-159544250*/count=1493; tryItOut("if(false) (\"\\u0746\"); else o0.g2.offThreadCompileScript(\"v0 = g2.eval(\\\"m0.set(f0, f1);\\\");\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-159544250*/count=1494; tryItOut("\"use strict\"; v2 = (f0 instanceof f2);");
/*fuzzSeed-159544250*/count=1495; tryItOut("\"use strict\"; /*oLoop*/for (nctuay = 0, new decodeURIComponent(); nctuay < 94; ++nctuay) { ((new RegExp(\"(?=((?![^])))\\\\B|\\\\3\", \"gim\"))(a)); } ");
/*fuzzSeed-159544250*/count=1496; tryItOut("mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return mathy2((mathy1((( ~ y) >>> 0), ((( + ((x * Math.fround((Math.fround(y) >> Math.fround(y)))) | 0)) ** (Math.hypot(x, (y >>> 0)) | 0)) | 0)) || ( + Math.fround(y))), Math.min((Math.fround(((( ! (Math.atan2(0x07fffffff, (x | 0)) >>> 0)) ^ x) >>> 0)) <= mathy0(((Math.exp((x >>> 0)) >>> 0) !== x), ( + Math.fround(( + ( + mathy2(( + -Number.MAX_SAFE_INTEGER), ( + y)))))))), Math.fround(Math.log2(1)))); }); ");
/*fuzzSeed-159544250*/count=1497; tryItOut("v1 = Object.prototype.isPrototypeOf.call(h0, g1.t0);");
/*fuzzSeed-159544250*/count=1498; tryItOut("/*vLoop*/for (dcuunf = 0; dcuunf < 3; ++dcuunf) { var e = dcuunf; print(e); } ");
/*fuzzSeed-159544250*/count=1499; tryItOut("mathy3 = (function(x, y) { return Math.hypot(( - Math.atanh(Math.cbrt((( ~ 0x0ffffffff) >>> 0)))), Math.atan(Math.exp((-Number.MIN_SAFE_INTEGER >>> 0)))); }); ");
/*fuzzSeed-159544250*/count=1500; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 16777216.0;\n    var d3 = -6.189700196426902e+26;\n    var i4 = 0;\n    {\n      d2 = (+(-1.0/0.0));\n    }\n    return +(((((Uint8ArrayView[2]))) % ((-1.5111572745182865e+23))));\n    d2 = (-2049.0);\n    (Float64ArrayView[((Int16ArrayView[((!(i4))) >> 1])) >> 3]) = (((+abs(((3.0))))));\n    i1 = ((0x21e5e083) ? ((((i0)-((d3) != (((2.3611832414348226e+21)) - ((36028797018963970.0)))))>>>((!(0x45953c46))-(0xaf406d31)+(i1)))) : (((((-3.022314549036573e+23))-(i0))>>>((i0)-(i0))) > (((i0)+((0xbd4e2a61) <= (0x0))-(0xf8e7c916))>>>((0x611f4be3)+(0x3cb748e1)))));\n    d2 = (((+log(((17592186044417.0))))) % ((d2)));\n    i4 = (0x75c48c2b);\n    return +((d3));\n  }\n  return f; })(this, {ff: Number.isSafeInteger}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[0x100000000, new Number(1)]); ");
/*fuzzSeed-159544250*/count=1501; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1502; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    d0 = (1.125);\n    (Float64ArrayView[4096]) = ((d1));\n    (Int8ArrayView[(-0xa14e3*(i2)) >> 0]) = (((0xac76a627))+(i3));\n    d0 = (d0);\n    i2 = (i4);\n    d1 = (+(1.0/0.0));\n    return +((NaN));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [1.7976931348623157e308, 0.000000000000001, Number.MIN_VALUE, 0x100000001, -1/0, -(2**53-2), -0x080000000, 0/0, 42, Math.PI, -0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53, 1, 2**53-2, -0x080000001, 0x080000000, -(2**53), 2**53+2, -(2**53+2), 0, 0x080000001, 0x07fffffff, -0x07fffffff, Number.MAX_VALUE, 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1503; tryItOut("for(let z in ((x)(eval(\"/* no regression tests found */\", [])))){m1.get(b1); }");
/*fuzzSeed-159544250*/count=1504; tryItOut("o0.o0.s1 += s2;");
/*fuzzSeed-159544250*/count=1505; tryItOut("let v2 = g1.runOffThreadScript();");
/*fuzzSeed-159544250*/count=1506; tryItOut("\"use asm\"; return delete eval.x;");
/*fuzzSeed-159544250*/count=1507; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.ceil(mathy1(mathy1((Math.hypot((x | 0), y) | 0), y), (Math.expm1(mathy2(-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER)) >>> 0))) >>> 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -0x0ffffffff, 2**53-2, -0x100000000, 2**53, 42, -(2**53), Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, -0x080000000, 0/0, 1.7976931348623157e308, -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, Math.PI, 0x100000001, 2**53+2, 1/0, -0, 0x080000001, 0x07fffffff, 0, 1, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1508; tryItOut("\"use strict\"; e2.add((/*FARR*/[].filter(encodeURI)) & \nthis);\nArray.prototype.splice.apply(a1, [NaN, ({valueOf: function() { v2 = (b2 instanceof e1);\nyield this;\nreturn 9; }})]);\n");
/*fuzzSeed-159544250*/count=1509; tryItOut("testMathyFunction(mathy1, [2**53, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), 0x0ffffffff, -0x07fffffff, -1/0, -0x0ffffffff, 1, -0x100000000, 0, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, -(2**53+2), 0/0, 0x080000000, -0, 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, 42, Math.PI, Number.MIN_VALUE, 1/0, Number.MAX_VALUE, 0x080000001, -0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1510; tryItOut("for (var p in o1) { try { e2.add(i0); } catch(e0) { } try { Array.prototype.shift.call(a1); } catch(e1) { } try { s2 += s0; } catch(e2) { } g1[\"NaN\"] = h1; }i2 + '';");
/*fuzzSeed-159544250*/count=1511; tryItOut("/*infloop*/L:while(let (a) window)print(x);");
/*fuzzSeed-159544250*/count=1512; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s2; print(s.search(r)); \nv2 = a1.every(f2, /*FARR*/[].filter, t0, t2);\n");
/*fuzzSeed-159544250*/count=1513; tryItOut("throw \"\\u031A\";print(x);\nv1 = a0.length;\n\n/*oLoop*/for (var przaas = 0; przaas < 13; ++przaas) { i0.next(); } \n");
/*fuzzSeed-159544250*/count=1514; tryItOut("Object.preventExtensions(p1);{}");
/*fuzzSeed-159544250*/count=1515; tryItOut("\"use strict\"; t2 = new Float64Array(t2);");
/*fuzzSeed-159544250*/count=1516; tryItOut("o1.v0 = a2.some((function() { for (var j=0;j<9;++j) { f0(j%5==1); } }), this.a2);");
/*fuzzSeed-159544250*/count=1517; tryItOut("\"use strict\"; var yatzrs = new ArrayBuffer(8); var yatzrs_0 = new Uint32Array(yatzrs); print(yatzrs_0[0]); var yatzrs_1 = new Uint8Array(yatzrs); var yatzrs_2 = new Int32Array(yatzrs); for (var p in t1) { Object.defineProperty(this, \"v1\", { configurable: (yatzrs_2[0] % 6 != 2), enumerable: (yatzrs_0[0] % 2 == 1),  get: function() { Object.defineProperty(this, \"v0\", { configurable: true, enumerable: false,  get: function() {  return -0; } }); return g2.eval(\"m0.__proto__ = s1;\"); } }); }s0 += s1;var syoftw = new SharedArrayBuffer(8); var syoftw_0 = new Uint8ClampedArray(syoftw); var syoftw_1 = new Uint32Array(syoftw); syoftw_1[0] = -5; var syoftw_2 = new Uint8Array(syoftw); syoftw_2[0] = -7; var syoftw_3 = new Int8Array(syoftw); syoftw_3[0] = 0; var syoftw_4 = new Uint8ClampedArray(syoftw); print(syoftw_4[0]); syoftw_4[0] = -14; /*vLoop*/for (noftqy = 0, \"\\uF730\"; noftqy < 11; ++noftqy) { const x = noftqy; v1 = (t1 instanceof v0); } m0.has(window);(/(?!\\B|\\u00C8|.+)?[^]?/gyi);(function(x, y) { return x; })/* no regression tests found *//* no regression tests found */");
/*fuzzSeed-159544250*/count=1518; tryItOut("\"use strict\"; for (var p in g1.e1) { try { m1.get(a2); } catch(e0) { } try { g0.toString = (function() { try { for (var p in m0) { try { a0.toString = Date.prototype.getMilliseconds.bind(g1); } catch(e0) { } try { for (var p in v1) { try { /*ADP-1*/Object.defineProperty(a2, v0, ({set: arguments.callee.caller.caller, configurable: false})); } catch(e0) { } s0 = new String; } } catch(e1) { } p2 = e0; } } catch(e0) { } try { s0 += s2; } catch(e1) { } try { t0 = new Uint32Array(this.b0); } catch(e2) { } h1.getPropertyDescriptor = (function() { try { this.e0.add(o2.m0); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { Object.defineProperty(this, \"v1\", { configurable: (x % 3 == 0), enumerable:  \"\" ,  get: function() {  return g0.runOffThreadScript(); } }); } catch(e2) { } v2.toString = (function(j) { if (j) { try { neuter(b1, \"change-data\"); } catch(e0) { } try { for (var v of g0) { try { Object.defineProperty(g1, \"o2.v2\", { configurable: true, enumerable: window,  get: function() {  return r0.unicode; } }); } catch(e0) { } try { a1[v2] =  \"\" ; } catch(e1) { } v0 = t1.length; } } catch(e1) { } v1 = evalcx(\"\\\"use strict\\\"; new RegExp(\\\"\\\\\\\\2\\\", \\\"\\\");\", g1); } else { try { a0.sort(f1); } catch(e0) { } this.h0.enumerate = function(y) { return  /x/g  }; } }); return t2; }); return t1; }); } catch(e1) { } s2 = t2[13]; }");
/*fuzzSeed-159544250*/count=1519; tryItOut("print(x);\nv2 = new Number(0);\n");
/*fuzzSeed-159544250*/count=1520; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.hypot((((((-0x080000001 >= y) | 0) ? ( + Math.fround(Math.log10(Math.tanh((Math.atanh((x | 0)) === (Math.max((y >>> 0), (y >>> 0)) >>> 0)))))) : Math.cos(Math.atan2((-Number.MAX_VALUE >>> 0), x))) | 0) > (( ~ Math.asinh(Math.fround(Math.hypot(Math.fround(mathy3(( + x), y)), ( + Math.atan2(( + ( + Math.cosh(x))), ( + 0x080000000))))))) >>> 0)), (( + mathy3((( + (( - (Math.atan2(Math.fround((x < Math.fround(x))), -0x080000001) | 0)) >>> 0)) >>> 0), (( + ( + ((( + Math.min(Math.fround(((x >>> 0) ? Math.fround(x) : Math.fround(-0))), (x > x))) / ( + x)) | 0))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[(void 0), (void 0), (void 0), new String('q'), new String('q'), (void 0), new String('q'), (void 0), (void 0), (void 0), new String('q'), (void 0), (void 0), new String('q'), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new String('q'), (void 0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (void 0), new String('q'), (void 0), (void 0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (void 0), new String('q'), (void 0), (void 0), new String('q'), new String('q'), (void 0), (void 0), new String('q'), new String('q'), new String('q'), (void 0), (void 0), (void 0), new String('q'), (void 0), new String('q'), (void 0), new String('q'), (void 0), new String('q')]); ");
/*fuzzSeed-159544250*/count=1521; tryItOut("testMathyFunction(mathy0, [-0x100000001, 2**53+2, -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0x100000000, 0x0ffffffff, -0, 0x080000000, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 2**53-2, -(2**53), -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, 2**53, -(2**53-2), -0x07fffffff, -0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 0x100000001, 42, -0x0ffffffff, 0, Math.PI, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1522; tryItOut("((({}) >= -9)((makeFinalizeObserver('tenured'))));");
/*fuzzSeed-159544250*/count=1523; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +(-1);\n    i1 = (0x825d562c);\n    {\n      i1 = ((0x3fd8e8ab));\n    }\n    {\n      d0 = (-274877906944.0);\n    }\n    return +((((+/*FFI*/ff(((+((8589934593.0)))), ((~~(+((d0))))), ((-0x8000000))))) / ((((Float64ArrayView[(((0xcf817a4d) > (0xffffffff))-(i1)-(0x6aef5448)) >> 3])) / ((-7.555786372591432e+22))))));\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ \"use strict\"; v1 = a0.reduce, reduceRight((function(j) { if (j) { m1.has(g1.a0); } else { try { g2 = this; } catch(e0) { } try { m0.delete(\"\\uBF3D\"); } catch(e1) { } t1 = new Int16Array(a1); } }), x);return Function})()}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE, -0x100000001, -0x080000001, -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -(2**53+2), -1/0, -0, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, Math.PI, 0x07fffffff, 2**53, 0, 1/0, 0x080000001, 0x0ffffffff, 0/0, -(2**53-2), 0x080000000, 1, 2**53-2, -(2**53), -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1524; tryItOut("\"use strict\"; Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-159544250*/count=1525; tryItOut("\"use strict\"; for(var   = (timeout(1800)) in ((y) = undefined)) {g0.offThreadCompileScript(\"\\\"use strict\\\"; b0.__iterator__ = (function(j) { if (j) { o2.m1.has(b0); } else { try { g0 = Proxy.create(o1.h1, o2.o2.i1); } catch(e0) { } try { v2 = g2.runOffThreadScript(); } catch(e1) { } try { a2[({valueOf: function() { print(x);return 16; }})]; } catch(e2) { } v2 = a2.every(f1); } });\"); }");
/*fuzzSeed-159544250*/count=1526; tryItOut("\"use strict\"; x.name;(this.zzz.zzz = (yield -1));");
/*fuzzSeed-159544250*/count=1527; tryItOut("this.v1 = 0;");
/*fuzzSeed-159544250*/count=1528; tryItOut("mathy4 = (function(x, y) { return ( + (( + (( + ( + y)) >>> ((((((( + y) >>> ( + ( ! y))) | 0) != (Math.ceil(y) | 0)) | 0) & ((Math.fround(Math.tan(0x0ffffffff)) != Number.MIN_VALUE) >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, 0/0, -0x080000000, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 0x080000000, 0x100000001, 2**53+2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, -Number.MIN_VALUE, -Number.MAX_VALUE, -0, 42, -1/0, 0.000000000000001, 0x100000000, Number.MAX_VALUE, 1/0, 0x080000001, -(2**53), -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, 1.7976931348623157e308, 0x07fffffff, -(2**53+2), 0]); ");
/*fuzzSeed-159544250*/count=1529; tryItOut("/*RXUB*/var r = /(^|[^](?=(?=(?!.))|\\2|(?!(?=(?!\\w)*)))|(?!(\\2){3,})[^]+?(?=(?:$))|(?:$\\B)|\\w|[^]{2}+)/yi; var s = \"FFFFF\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=1530; tryItOut("/*infloop*/M:for(let y in  /x/ ) ([1,,]);");
/*fuzzSeed-159544250*/count=1531; tryItOut("var x = Math.asin(x), d = (4277), nbhibm;o0.v1 = o2.a2.length;");
/*fuzzSeed-159544250*/count=1532; tryItOut("testMathyFunction(mathy1, [0x080000000, 0x07fffffff, 0x100000001, Math.PI, 0, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, 2**53, -1/0, -Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 2**53+2, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, -0, -0x07fffffff, 0/0, 1, -(2**53-2), 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_VALUE, 1/0, -0x100000000, -0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-159544250*/count=1533; tryItOut("v2 = evaluate(\"for (var v of o2) { try { /*MXX3*/g1.Number.EPSILON = g1.Number.EPSILON; } catch(e0) { } try { o0.v2 = NaN; } catch(e1) { } h1.get = (function() { for (var j=0;j<104;++j) { f1(j%2==1); } }); }\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: y = x, sourceIsLazy: (4277), catchTermination: e--.yoyo(x >= z), elementAttributeName: s1, sourceMapURL: s1 }));");
/*fuzzSeed-159544250*/count=1534; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ (Math.hypot(Math.fround(Math.hypot((( + ( ! ( + 0x100000001))) | 0), Math.fround(( + Math.sin(( + ( + x))))))), Math.fround(( + ( ~ ( + x))))) | 0)); }); testMathyFunction(mathy2, [-0x07fffffff, -Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, -1/0, 0/0, 1, 0x080000000, -0, 1.7976931348623157e308, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 0x100000001, Math.PI, -(2**53+2), 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -0x100000001, -0x080000001, 0, -(2**53-2), -0x0ffffffff, -0x080000000, -(2**53)]); ");
/*fuzzSeed-159544250*/count=1535; tryItOut("/*RXUB*/var r = /(?!\\b|[].{0,1}([^\\s\u00bd-\u0012\\w]{2,}).|\\cS+\\b$^|[\\0-\\u00FB\\xE1\\D\\v]\\B?{2,3})/gim; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=1536; tryItOut("\"use asm\"; /*RXUB*/var r = r1; var s = s0; print(uneval(s.match(r))); ");
/*fuzzSeed-159544250*/count=1537; tryItOut("/*tLoop*/for (let e of /*MARR*/[objectEmulatingUndefined(), x, new String(''), x, new String('')]) { t0[10] = e1; }");
/*fuzzSeed-159544250*/count=1538; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! ((( - (mathy2(y, y) >>> 0)) == (( ~ mathy4(( - -(2**53)), Math.cbrt(x))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 2**53, -0x080000001, 0x100000000, -(2**53), 0, 0x100000001, -0, 2**53-2, 0x0ffffffff, -0x100000000, -0x07fffffff, 0.000000000000001, -0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, -0x100000001, 1.7976931348623157e308, 0x07fffffff, 0x080000001, 42, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), Number.MAX_VALUE, 2**53+2, -(2**53-2), -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1539; tryItOut("throw StopIteration;let(x = (yield  '' ), z) ((function(){yield eval(\"/* no regression tests found */\");})());");
/*fuzzSeed-159544250*/count=1540; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=1541; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.expm1((Math.abs((Math.min((-0x0ffffffff - x), 0x0ffffffff) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[([, , , ] =  '' ), null, objectEmulatingUndefined(), null, true, objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, true, ([, , , ] =  '' ), objectEmulatingUndefined(), null, null, ([, , , ] =  '' ), true, true, objectEmulatingUndefined(), null, ([, , , ] =  '' ), ([, , , ] =  '' ), null, objectEmulatingUndefined(), null, null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-159544250*/count=1542; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround((( + mathy2(Math.fround(( ~ Math.fround((Math.cos(( + ( ~ x))) | 0)))), ((((x | 0) ? (x | 0) : (x | 0)) | 0) / x))) ? ( + Math.fround(Math.log1p(Math.fround(x)))) : ( + Math.atan2(( + Math.sinh(( + ( ~ x)))), Math.max(( + Math.max(x, Math.fround((Math.fround((x ? (-Number.MIN_VALUE | 0) : (x >>> 0))) - (x | 0))))), Math.fround(( ! Math.log(y)))))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 0x100000000, 0/0, 42, -0x100000001, 1.7976931348623157e308, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 2**53, 1, 0, -(2**53+2), Number.MAX_VALUE, -0x080000001, -0x100000000, -(2**53), 0.000000000000001, -0, 0x080000000, -Number.MAX_VALUE, Math.PI, -0x080000000, -(2**53-2), 0x0ffffffff, -Number.MIN_VALUE, -1/0, 0x080000001, 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=1543; tryItOut("Array.prototype.pop.call(a0, i2);");
/*fuzzSeed-159544250*/count=1544; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-159544250*/count=1545; tryItOut("testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, Math.PI, 0, -(2**53), -0x100000000, 2**53+2, Number.MIN_VALUE, 0x100000000, -(2**53+2), 0x080000000, 0x07fffffff, -1/0, -0x0ffffffff, -(2**53-2), 0x100000001, 0x0ffffffff, 0.000000000000001, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 1/0, -0x080000000, 1, -0x080000001, 2**53, 0x080000001, 42, -0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1546; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((((Math.cosh(( + Math.fround(Math.min(Math.fround(Math.log(-Number.MAX_VALUE)), Math.fround((Math.asinh(Math.fround(Math.cos(( + y)))) | 0)))))) | 0) | 0) >> Math.atanh(( + (mathy2((( + ( + y)) != (0 <= -0x100000001)), 2**53-2) << ( + ( ! Math.hypot(y, Math.fround(-0x07fffffff)))))))) | 0); }); ");
/*fuzzSeed-159544250*/count=1547; tryItOut("");
/*fuzzSeed-159544250*/count=1548; tryItOut("mathy1 = (function(x, y) { return ( ~ ( ~ Math.fround(mathy0(x, x)))); }); ");
/*fuzzSeed-159544250*/count=1549; tryItOut("\"use strict\"; var d = eval(\"/* no regression tests found */\", (makeFinalizeObserver('tenured')));var lgwqvn = new SharedArrayBuffer(0); var lgwqvn_0 = new Int8Array(lgwqvn); print(lgwqvn_0[0]); print(x);print(lgwqvn);a1 = a1.filter((function() { try { this.a2 = this.a1.slice(4, -2, h0); } catch(e0) { } v0 = a1.length; return o2.e2; }));");
/*fuzzSeed-159544250*/count=1550; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1551; tryItOut("v2 = Object.prototype.isPrototypeOf.call(o0.h2, b0);");
/*fuzzSeed-159544250*/count=1552; tryItOut("\"use strict\"; /*infloop*/L: for (arguments[\"toDateString\"] of x) /*bLoop*/for (hzfdac = 0; hzfdac < 45; ++hzfdac) { if (hzfdac % 16 == 14) { e2.delete(i2); } else { function(id) { return id }; }  } ");
/*fuzzSeed-159544250*/count=1553; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; void readSPSProfilingStack(); } void 0; }");
/*fuzzSeed-159544250*/count=1554; tryItOut("print(uneval(a0));");
/*fuzzSeed-159544250*/count=1555; tryItOut("\"use strict\"; t1[11] = ((makeFinalizeObserver('tenured')));");
/*fuzzSeed-159544250*/count=1556; tryItOut("/*RXUB*/var r = new RegExp(\"((?!\\\\2{1}))*?\", \"gy\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=1557; tryItOut("{}function z()\"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -140737488355329.0;\n    var d3 = -65.0;\n    var d4 = 1073741825.0;\n    (Int32ArrayView[2]) = (((((0x905684d1)) >> ((((0xaadaeef0)) ? (x) : (i1)))))-(i1));\n    d2 = (+abs(((-(z)))));\n    (Uint16ArrayView[(((((0xa664b696))>>>(-(0xfa618617))) == (((0xf1a6eb9)+(0xf98fef3d)-(0xd8f8ba0d))>>>((0x6264fa20) % (0x414be2f8))))) >> 1]) = ((i0));\n    (Int32ArrayView[2]) = (((d4))+(0xfc31b231));\n    (Uint32ArrayView[2]) = ((0x399a08f)+(0x1d73a935));\n    i1 = (1);\n    return (((i0)))|0;\n    d4 = (+(-1.0/0.0));\n    d3 = (-1.2089258196146292e+24);\n    d3 = (+((d2)));\n    {\n      (Float64ArrayView[((0x0) % (((0x7da492c7) / (0x2e7671a2))>>>(((0x0) <= (0xe8d34a0e))))) >> 3]) = ((+(1.0/0.0)));\n    }\n    {\n      {\n        d3 = (NaN);\n      }\n    }\n    i0 = (0x2ede7ae4);\n    (Int16ArrayView[4096]) = ((!(i1))+((0xcfdaff03))+(1));\n    switch ((~((0x3c0bccbc) / (((0x9eface88))>>>((0xffffffff)))))) {\n      case 0:\n        {\n          d4 = (+((-4611686018427388000.0)));\n        }\n      case 1:\n        d4 = (-17179869183.0);\n      case 0:\n        {\n          i1 = (i1);\n        }\n        break;\n    }\n    d4 = ((d2) + ((+((NaN))) + (d4)));\n    return ((((i1) ? ((0xffffffff)) : (0xfb081295))+((((0x13375*((0x7fffffff) > (0x72fbc82e))) | ((0xd1924fc)))) ? ((0xfe578afb) ? (0xf92001f1) : (-0x8000000)) : (((0xfbf7b494) ? (d4) : ((3.8685626227668134e+25) + (-524288.0))) >= (67108863.0)))))|0;\n    return (((((((0xd0e8ac38)*0xb041)>>>((0x872a9963)-(0x58b23b73))) > (0xc7e6bce9)) ? (-0x8000000) : (1))+(1)-(0xed4c959e)))|0;\n  }\n  return f;print(Math);");
/*fuzzSeed-159544250*/count=1558; tryItOut("const x = x, \u3056, xhdpga, trbixa, fyhnmy, eval, x;this.v1 = Object.prototype.isPrototypeOf.call(g1, f1);");
/*fuzzSeed-159544250*/count=1559; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a2, Object.defineProperty(x, \"1\", ({})), ({configurable: \nx}));");
/*fuzzSeed-159544250*/count=1560; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.clz32(( + (mathy2(((Math.imul((( ~ -0) | 0), Math.fround(x)) - Math.sign(x)) >>> 0), (( + (( ! Math.pow(( + Math.hypot(y, 42)), (Math.fround(((Number.MAX_VALUE >>> 0) , 0x100000001)) != Math.fround(x)))) ? ( + Math.pow(0.000000000000001, ( ~ Math.fround(Math.imul(y, (-0x080000000 | 0)))))) : ( + Math.trunc(mathy2(-0x0ffffffff, x))))) >>> 0)) | 0))); }); testMathyFunction(mathy3, [-(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, 0x080000000, 0x0ffffffff, 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, 1/0, 0x100000000, -(2**53+2), 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, -0x080000001, 0, -0x080000000, Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, 1, -1/0, -0, 2**53+2, 42, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-159544250*/count=1561; tryItOut("v1 = t0.length;");
/*fuzzSeed-159544250*/count=1562; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?:[])(?=[^]*?|^){4,}|[^]${4,5}|(?=((?!\\w)(?![^\\cY]))?)|(.)|[\\d\\D][\u044e-\ue9ac])*/ym; var s = \"a\\ufff9a\\ufff9\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1563; tryItOut("for (var v of p1) { t0[12] = h1; }");
/*fuzzSeed-159544250*/count=1564; tryItOut("o1.__proto__ = b2;");
/*fuzzSeed-159544250*/count=1565; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.cos(Math.fround(( ! (( + Math.sign(Math.atan((Math.atanh(y) | 0)))) | 0))))); }); testMathyFunction(mathy3, [-0x100000000, -0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), -0, 0/0, 0x100000001, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000000, 42, -Number.MAX_VALUE, 0, -(2**53), 0x0ffffffff, Number.MIN_VALUE, 1/0, -0x07fffffff, -0x080000001, 2**53, -1/0, 0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, 1, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1566; tryItOut("\"use strict\"; g0 + v1;");
/*fuzzSeed-159544250*/count=1567; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy0(( + Math.log10(( + (Math.atanh((Number.MAX_VALUE >>> 0)) >>> 0)))), ( + ( - Math.log2(Math.fround(( - -0x100000001)))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 1, 42, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000001, 0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 0x100000001, 0x100000000, -1/0, -Number.MIN_VALUE, 0/0, 2**53+2, 1/0, -0x0ffffffff, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, -(2**53+2), 0x0ffffffff, -(2**53), -(2**53-2), 0x07fffffff, Math.PI, 0.000000000000001, 2**53, 0x080000000]); ");
/*fuzzSeed-159544250*/count=1568; tryItOut("/*infloop*/for(let w;  /* Comment */ \"\" \u000c; ((b = x))) {if(false) /*tLoop*/for (let y of /*MARR*/[0x5a827999, 0x07fffffff, 0x5a827999, 0x07fffffff, -(2**53+2), 0x07fffffff, 0x07fffffff, -(2**53+2), 0x5a827999, 0x5a827999]) { return ((w) = x); } else  if ((4277)) {s2 += 'x';allocationMarker()\u000c; } else g2.a1[15] = f0; }");
/*fuzzSeed-159544250*/count=1569; tryItOut("/*MXX1*/o2 = g2.String.prototype.bold;");
/*fuzzSeed-159544250*/count=1570; tryItOut("M:with({w: d\n})print(x);");
/*fuzzSeed-159544250*/count=1571; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.clz32(Math.fround(Math.hypot(Math.fround(-Number.MIN_VALUE), Math.fround((((-0x07fffffff | 0) || (x | 0)) | 0))))) ** (((((x | 0) + (Math.fround((( + mathy0(( + x), ( + Math.fround(( ! Math.fround(x)))))) | (y | 0))) | 0)) | 0) * Math.max(x, (((( ~ x) >>> 0) % (Math.trunc(Math.fround(Math.sinh(x))) >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy1, [0, -0x080000000, -0x100000001, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, -(2**53), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, 1, -0x080000001, -0, 2**53-2, 0x080000000, -1/0, 0x100000000, -(2**53-2), -0x07fffffff, 2**53+2, 2**53, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 0x07fffffff, -0x0ffffffff, -0x100000000, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=1572; tryItOut("\"use strict\"; for (var v of o0.g1.v0) { try { g1.s1 = new String; } catch(e0) { } try { v0 = undefined; } catch(e1) { } try { v1.toString = (function() { g1.f2 = Proxy.createFunction(h0, f1, f1); throw this.o1; }); } catch(e2) { } delete h0.set; }");
/*fuzzSeed-159544250*/count=1573; tryItOut("print(Math.trunc(-17));");
/*fuzzSeed-159544250*/count=1574; tryItOut("v1 = (o2.b1 instanceof o2.s0);");
/*fuzzSeed-159544250*/count=1575; tryItOut("testMathyFunction(mathy4, [-0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -0x080000000, 0x080000001, 0, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), 1, Math.PI, -0, 2**53+2, 0/0, -1/0, -(2**53+2), 1/0, -Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 42, 0x100000000, 0x080000000, -0x07fffffff, 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=1576; tryItOut("mathy0 = (function(x, y) { return ( ! ( + ((Math.fround(Math.trunc(Math.fround(x))) + -0) <= Math.max(( ! Math.fround(Math.fround((Math.asinh(((y < 1) | 0)) | 0)))), Math.pow(Math.log1p(y), ( + x)))))); }); ");
/*fuzzSeed-159544250*/count=1577; tryItOut("\"use strict\"; g1 = this;");
/*fuzzSeed-159544250*/count=1578; tryItOut("mathy2 = (function(x, y) { return Math.min((Math.fround(Math.hypot(Math.fround((Math.hypot(Math.atan2((-(2**53-2) >>> 0), ( + x)), (x << (y & x))) ? y : ((-0 > x) >>> 0))), Math.fround((Math.max(Math.atan2((((x >>> 0) !== ( + y)) >>> 0), (y >>> 0)), Math.pow(y, (Math.log2(x) > x))) | 0)))) >>> 0), (( ! (Math.fround((Math.fround((Math.fround(Math.tan(-0x100000000)) >> x)) === Math.fround(((Math.fround(y) , ((( + Math.hypot(( + Number.MAX_VALUE), ( + x))) !== x) >>> 0)) >>> 0)))) | 0)) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), 2**53+2, 2**53+2, new Number(1.5), new String('q'), new String('q'), new String('q'), new Number(1.5), undefined, new String('q'), new Number(1.5), 2**53+2, -0x100000001, new Number(1.5), undefined, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, undefined, 2**53+2, new String('q'), -0x100000001, new String('q'), 2**53+2, new String('q'), new Number(1.5), 2**53+2, undefined, new Number(1.5), undefined, new String('q'), -0x100000001, new String('q'), new Number(1.5), undefined, new Number(1.5), undefined, 2**53+2, -0x100000001, new Number(1.5), undefined, 2**53+2, new Number(1.5), undefined, new Number(1.5), 2**53+2]); ");
/*fuzzSeed-159544250*/count=1579; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(g1.b2, this.e0);");
/*fuzzSeed-159544250*/count=1580; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(g1, p1);");
/*fuzzSeed-159544250*/count=1581; tryItOut("\"use strict\";  for  each(let y in null) {/*bLoop*/for (let ejmkbd = 0, ismodh; ejmkbd < 0; ++ejmkbd) { if (ejmkbd % 24 == 6) { m2 = new Map; } else { v0 = new Number(Infinity); }  }  }");
/*fuzzSeed-159544250*/count=1582; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ (Math.fround(( + Math.fround(( + Math.sqrt((Math.atanh((( + (0/0 | 0)) | 0)) >>> 0)))))) >>> 0)); }); testMathyFunction(mathy2, [2**53+2, -Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, -0x07fffffff, Math.PI, 2**53, 0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 42, Number.MAX_VALUE, 0, -0x080000000, -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -(2**53+2), 1.7976931348623157e308, Number.MIN_VALUE, 2**53-2, 0/0, 1, -0x100000000, 0.000000000000001, -(2**53), -(2**53-2), -Number.MIN_VALUE, 0x080000000, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1583; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = ((function(y) { m2.delete(g1); })());\n    i2 = (0xfa0ed527);\n    d0 = (d1);\n    {\n      switch (((((4277))-((-7.737125245533627e+25) < (-1.00390625))) >> ((i2)+(i2)))) {\n        case -3:\n          (Uint16ArrayView[((i2)-(0xe3311b33)) >> 1]) = (-(0xb8c531d2));\n      }\n    }\n    switch (((((0x0) < (0xffffffff))-(0xfff013e4))|0)) {\n      case 1:\n        d1 = (d0);\n        break;\n      case -1:\n        switch ((((0x64c7e6ea) / (-0x8000000)) >> (((0x10edfaab))*-0x8ebb8))) {\n          case -1:\n            d0 = ((-8589934593.0) + (((d0)) - ((-73786976294838210000.0))));\n            break;\n          case -3:\n            i2 = ((((i2)+(/*FFI*/ff(((((0xf9d13176)-(0xa283602d)) << (((0x780c4064) >= (0x5d6e55a6))))), ((d1)), ((((0xffc348d1)) ^ ((0xd1cb0381)))), ((-268435457.0)), ((-2147483649.0)), ((1048575.0)))|0)-(0x80873d6b)) >> (((Float64ArrayView[(0xe1b8f*((0xc637a5f9) ? (-0x8000000) : (0xf8e901a5))) >> 3])))) >= (((0x5be5d0cd)+(-0x8000000)) << ((0xf99e3755))));\n            break;\n        }\n    }\n    return +((+abs(((d1)))));\n  }\n  return f; })(this, {ff: ((( /x/ ).bind).bind).apply}, new ArrayBuffer(4096)); ");
/*fuzzSeed-159544250*/count=1584; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\W){4,5}(?!\\b|.(\\cW)\\1{1073741824,}|[^]{4,}.|(?!\\2){0,})(?:(?:\\3))/i; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=1585; tryItOut("a2[16];");
/*fuzzSeed-159544250*/count=1586; tryItOut("mathy1 = (function(x, y) { return ( + ((Math.abs((Math.pow(( + Math.atan2(( + ( + ( + x))), y)), y) >>> 0)) >>> 0) / Math.imul(Math.fround((Math.fround(0) ** Math.fround(y))), Math.log(y)))); }); testMathyFunction(mathy1, [-0x080000001, 1/0, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0x07fffffff, 42, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, Math.PI, -0x100000000, 2**53-2, -(2**53), -0, -Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, 1, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 2**53, 0x080000001, -1/0, 0.000000000000001, 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=1587; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.acos(Math.exp(Math.cos(Math.fround(Math.fround(Math.hypot(x, Math.fround(x)))))))); }); testMathyFunction(mathy2, [NaN, ({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return '0';}}), '', undefined, true, '0', null, false, 0, [0], [], ({valueOf:function(){return 0;}}), (function(){return 0;}), (new Boolean(false)), 1, objectEmulatingUndefined(), (new String('')), (new Number(0)), (new Boolean(true)), -0, '\\0', '/0/', /0/, 0.1]); ");
/*fuzzSeed-159544250*/count=1588; tryItOut("a0[4];");
/*fuzzSeed-159544250*/count=1589; tryItOut("mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(( ! Math.fround(Math.log(((Math.atan2((( ! ( + Math.acosh(( + Math.tanh(x))))) | 0), (x | 0)) | 0) >>> 0))))); }); testMathyFunction(mathy0, [-0x080000001, 0x080000001, Math.PI, 2**53+2, 0x0ffffffff, -0x100000000, -Number.MIN_VALUE, 0.000000000000001, 2**53-2, -0x0ffffffff, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 42, 1, -1/0, 0x080000000, 0x100000000, -Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, 0/0, -0x100000001, -0, 1/0, -(2**53-2), -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53), 0, 0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1590; tryItOut("\"use strict\"; e0.has(a2);");
/*fuzzSeed-159544250*/count=1591; tryItOut("\"use strict\"; m1.toSource = Date.prototype.getUTCMilliseconds.bind(o0.f1);");
/*fuzzSeed-159544250*/count=1592; tryItOut("a1.forEach(Object.setPrototypeOf, Math.max(-0.666,  /x/ ));");
/*fuzzSeed-159544250*/count=1593; tryItOut("\"use strict\";  for  each(e in x) i1 = t2[v2];");
/*fuzzSeed-159544250*/count=1594; tryItOut("v1 = r1.sticky;");
/*fuzzSeed-159544250*/count=1595; tryItOut("g2.v2 = evaluate(\"(({\\u000c get __proto__(e) { g0.m2.set(s0, b1); } ,  get prototype z () { return \\\"\\u03a0\\\" }  }))\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 17 != 6), noScriptRval: (x % 4 != 1), sourceIsLazy: (4277).valueOf(\"number\"), catchTermination: (x % 3 == 1) }));");
/*fuzzSeed-159544250*/count=1596; tryItOut("g0.s0 = new String;");
/*fuzzSeed-159544250*/count=1597; tryItOut("\"use strict\"; /*oLoop*/for (let ylqtvy = 0; ylqtvy < 107; ++ylqtvy) { print(this); } ");
/*fuzzSeed-159544250*/count=1598; tryItOut("/*RXUB*/var r = /(?=\\B(?=(?:[\\S\\n]\\1)))\\2+?/i; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=1599; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! (mathy4(Math.clz32((((( + (Math.hypot((y >>> 0), (( - y) >>> 0)) >>> 0)) | 0) ** ((Math.log1p(Math.fround(y)) | 0) | 0)) | 0)), (Math.fround(Math.atan2(( + x), x)) >>> 0)) | 0)); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 0x080000000, -0x07fffffff, -0x080000001, 0x080000001, 1, 1.7976931348623157e308, 0x100000001, -Number.MAX_VALUE, -1/0, Math.PI, 42, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, -0x100000000, 2**53+2, 0x07fffffff, -(2**53+2), -(2**53), 0.000000000000001, -0x080000000, 2**53, -(2**53-2), 2**53-2, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 1/0, -0x100000001]); ");
/*fuzzSeed-159544250*/count=1600; tryItOut("\"use strict\";  for  each(let a in /*UUV2*/(y.italics = y.//h\ngetUTCMilliseconds)) /*oLoop*/for (let ibmxro = 0; (true) && ibmxro < 7; ++ibmxro) { print(x); } ");
/*fuzzSeed-159544250*/count=1601; tryItOut("print(x);");
/*fuzzSeed-159544250*/count=1602; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(mathy0(((y / Math.asin(x)) >>> 0), (((( - Math.pow(( + 0x0ffffffff), x)) <= (Math.sin((new ([,,])(4194305) | 0)) | 0)) | 0) >>> 0))) >= (Math.fround(Math.pow(Math.pow(Math.fround(Math.sqrt((( + ( ! y)) * (x >>> 0)))), Math.fround(y)), Math.fround(Math.asinh(( + (x != ( + (Math.fround(mathy0((x >>> 0), (x >>> 0))) ? x : x)))))))) > Math.fround(Math.pow(Math.fround(Math.pow(Math.fround((( ! x) >>> 0)), Math.fround(mathy0(0x100000000, x)))), Math.fround(Math.imul((( + Math.atan2(( + (Math.hypot((y | 0), (x | 0)) | 0)), ( + Math.tanh((Number.MAX_SAFE_INTEGER && Number.MAX_SAFE_INTEGER))))) >>> 0), x)))))); }); testMathyFunction(mathy2, [0x100000001, 0x080000001, 0/0, 1/0, -(2**53-2), -Number.MIN_VALUE, 0x080000000, 2**53, Number.MIN_VALUE, 2**53-2, -0x07fffffff, 0.000000000000001, -Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, -0x100000001, -0x080000001, 0, 1, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, 42, -0x0ffffffff, -0x100000000, -(2**53), -1/0]); ");
/*fuzzSeed-159544250*/count=1603; tryItOut("/*bLoop*/for (let xdjouz = 0; xdjouz < 4; ++xdjouz) { if (xdjouz % 27 == 2) { print(x); } else { print(\"\\uAC13\"); }  } ");
/*fuzzSeed-159544250*/count=1604; tryItOut("\"use strict\"; v0 = b0.byteLength;");
/*fuzzSeed-159544250*/count=1605; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( ! Math.fround((((( + (( + ( - ( + Math.fround((mathy2(( + y), y) || Math.fround(x)))))) | 0)) | 0) >>> 0) && ((Math.fround(( + ( ! Math.fround(y)))) ** (Math.sin(42) | 0)) | 0)))) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, 0, 1.7976931348623157e308, -1/0, 0x100000001, 2**53-2, -Number.MAX_VALUE, 0x100000000, 42, 2**53+2, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, -(2**53), -0, -0x0ffffffff, 0x080000001, 1/0, Math.PI, -(2**53-2), -0x080000000, Number.MAX_VALUE, 2**53, -0x100000000, -Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-159544250*/count=1606; tryItOut("\"use strict\"; delete this.f1[\"toString\"];");
/*fuzzSeed-159544250*/count=1607; tryItOut("fwodlq(x * x, (({c:  /x/ , SQRT1_2: true })));/*hhh*/function fwodlq(){v0 = g1.eval(\"mathy5 = (function(x, y) { return (Math.imul(( + ( + ( + (( ! x) & ( + x))))), ( + (((mathy1(Math.sign((x | 0)), 1.7976931348623157e308) | 0) / (Math.imul(( + Math.hypot(( + ( ! Math.fround(Math.clz32(-Number.MAX_SAFE_INTEGER)))), mathy3(x, x))), Math.acos(( ~ (y | 0)))) | 0)) | 0))) >>> 0); }); testMathyFunction(mathy5, [0/0, -0x07fffffff, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), -(2**53), -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, -0, 42, -1/0, Number.MIN_VALUE, 0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 0x100000001, -(2**53+2), 2**53+2, 0, 0.000000000000001, Math.PI, -0x100000000, 0x080000000, 0x100000000]); \");}");
/*fuzzSeed-159544250*/count=1608; tryItOut("\"use strict\"; ");
/*fuzzSeed-159544250*/count=1609; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + (( + ((((mathy1(Math.asinh(y), y) | 0) || (x | 0)) | 0) !== ( + ( ! 0/0)))) - ( + ( + ( ~ ( + (x !== (( + ((x | 0) , ( + Math.atan2(x, -Number.MAX_VALUE)))) >>> 0)))))))); }); testMathyFunction(mathy3, [0/0, 2**53, -0, -0x080000000, -0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 0, -(2**53-2), -0x07fffffff, -0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, 42, 0x07fffffff, -0x0ffffffff, 0x100000001, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 2**53-2, -0x080000001, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=1610; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0.000000000000001, 0/0, -0x0ffffffff, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -1/0, 2**53+2, 1.7976931348623157e308, 0, 0x100000001, -Number.MAX_VALUE, 0x080000001, 2**53-2, 0x080000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 42, -(2**53), -0x080000001, -(2**53-2), -0x080000000, 0x07fffffff, 2**53, -0, Math.PI, 0x0ffffffff, -0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 1/0]); ");
/*fuzzSeed-159544250*/count=1611; tryItOut("\"use strict\"; t1 = new Int32Array(b2, 13, 2);");
/*fuzzSeed-159544250*/count=1612; tryItOut("testMathyFunction(mathy0, /*MARR*/[new String(''), new String(''), /*UUV2*/(x.entries = x.big), objectEmulatingUndefined(), /*UUV2*/(x.entries = x.big), new String(''), objectEmulatingUndefined(), new String(''), /*UUV2*/(x.entries = x.big), null, objectEmulatingUndefined(), new String(''), /*UUV2*/(x.entries = x.big), new String(''), null, new String(''), null]); ");
/*fuzzSeed-159544250*/count=1613; tryItOut("\"use strict\"; for(var c in ((((function too_much_recursion(ytlyow) { print(\"\\u1845\");; if (ytlyow > 0) { ; too_much_recursion(ytlyow - 1);  } else {  }  })(53298)))(x))){o1.v0 = Object.prototype.isPrototypeOf.call(s0, s2); }\n/*RXUB*/var r = Math.atanh(a); var s = \"\"; print(r.exec(s)); \n");
/*fuzzSeed-159544250*/count=1614; tryItOut("/*RXUB*/var r = /(?=\\W|\\b+)/gyi; var s = \"\\n\\u0016 \"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=1615; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.fround((Math.ceil((x < (( + Math.fround(x)) >>> 0))) + Math.fround((mathy1(Math.fround(((Math.atanh((( + Math.abs(( + x))) >>> 0)) >>> 0) + y)), Math.fround(y)) >>> 0))))); }); ");
/*fuzzSeed-159544250*/count=1616; tryItOut("/*RXUB*/var r = /[\u33ae\\W\u89d6-\ub3f1\\t]/gm; var s = \"\\u89d5\"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=1617; tryItOut("\"use strict\"; {var ywibqt = new ArrayBuffer(4); var ywibqt_0 = new Uint32Array(ywibqt); print(ywibqt_0[0]); ywibqt_0[0] = -0; var ywibqt_1 = new Float64Array(ywibqt); ywibqt_1[0] = 1; var ywibqt_2 = new Uint32Array(ywibqt); print(ywibqt_2[0]); ywibqt_2[0] = 21; var ywibqt_3 = new Int32Array(ywibqt); print(ywibqt_3[0]); var ywibqt_4 = new Uint8Array(ywibqt); ywibqt_4[0] = 4; pruwxq(ywibqt_3[10] ^ ywibqt_2[0], /*MARR*/[arguments.callee, arguments.callee, (void 0), new Number(1.5), (void 0), 5.0000000000000000000000, function(){}, arguments.callee, arguments.callee, 5.0000000000000000000000, new Number(1.5), function(){}, (void 0), arguments.callee, function(){}, 5.0000000000000000000000, (void 0), function(){}, 5.0000000000000000000000, arguments.callee, 5.0000000000000000000000, new Number(1.5), new Number(1.5), 5.0000000000000000000000, arguments.callee, new Number(1.5), 5.0000000000000000000000, new Number(1.5), function(){}, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, function(){}, new Number(1.5), new Number(1.5), arguments.callee, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, new Number(1.5), arguments.callee, 5.0000000000000000000000, new Number(1.5), (void 0), arguments.callee, arguments.callee].some(encodeURIComponent));/*hhh*/function pruwxq(NaN, ywibqt_4, ...d){Array.prototype.reverse.call(a0, g1.s2, f1, m1);}/*infloop*/for(var y; \u0009/*UUV1*/(x.toString = (function(y) { return  /x/  }).call); b = e) {(void schedulegc(g1));((eval(\"a0 + a0;\", new RegExp(\"(?=[^\\u0015-\\\\xcB\\\\u6580\\u2a84-\\u7d38\\\\s])$|[^]{536870912,}\\ub6f3{4,}\\\\d\", \"m\")))); } }");
/*fuzzSeed-159544250*/count=1618; tryItOut("v0 = a1.length;");
/*fuzzSeed-159544250*/count=1619; tryItOut("\"use strict\"; var pkwmbm = new SharedArrayBuffer(0); var pkwmbm_0 = new Int8Array(pkwmbm); pkwmbm_0[0] = eval = Proxy.createFunction(({/*TOODEEP*/})(-5), Function); var pkwmbm_1 = new Uint8Array(pkwmbm); var pkwmbm_2 = new Float64Array(pkwmbm); /*RXUB*/var r = r0; var s = s0; print(r.exec(s)); window = t1[({valueOf: function() { function(q) { \"use strict\"; return q; }return 5; }})];( '' );b1 + '';e0.delete(v2);v0.__proto__ = p0;");
/*fuzzSeed-159544250*/count=1620; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1.1805916207174113e+21;\n    var i3 = 0;\n    i1 = (i1);\n    return ((((i3) ? (i1) : (/*FFI*/ff(((imul((i3), (i0))|0)), ((((-70368744177665.0)) % ((Float64ArrayView[((-0x8000000)) >> 3])))), ((((0xffffffff)-(0x34f9f0c5)+(0x695eb1d3)) >> ((i3)))))|0))-(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0/0, -1/0, -0x100000000, 1, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, 1/0, -0x080000000, Number.MAX_VALUE, 0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -0x080000001, 1.7976931348623157e308, 0x080000000, -0x07fffffff, 0.000000000000001, 2**53, -0x100000001, 2**53+2, 2**53-2, 0x080000001, -(2**53-2), 42, -(2**53+2), 0x0ffffffff, 0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, -0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1621; tryItOut("mathy4 = (function(x, y) { return ((((( + (( + (Math.pow(((Math.cbrt((y >>> 0)) >>> 0) | 0), -0x100000000) | 0)) ? ( + -(2**53+2)) : ( + Math.acosh(y)))) ** (Math.asin((Math.hypot(( ~ x), -Number.MAX_VALUE) | 0)) >>> 0)) >>> 0) !== ((( + Math.trunc(( + x))) >> Math.atan2((Math.sinh((y | 0)) | 0), (( + Math.tan((y >> Math.atan2((y >>> 0), -0)))) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [0x080000000, -0x0ffffffff, 2**53, Number.MIN_VALUE, 0, 0/0, -0, -0x100000000, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, 42, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, 2**53+2, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, 1, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, 0x100000000, 0x07fffffff, -(2**53-2), -1/0, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-159544250*/count=1622; tryItOut("\"use strict\"; { void 0; minorgc(false); } a2.valueOf = (function(j) { if (j) { try { g2.o0.b2[\"toString\"] = v0; } catch(e0) { } try { Object.defineProperty(this, \"v1\", { configurable: (x % 11 != 2), enumerable: (x % 2 != 1),  get: function() {  return -Infinity; } }); } catch(e1) { } /*MXX2*/g0.Math.atan = h0; } else { try { a2.splice(NaN, ({valueOf: function() { Object.defineProperty(this, \"g1.t1\", { configurable: true, enumerable: false,  get: function() {  return new Uint16Array(6); } });return 18; }}), e2); } catch(e0) { } m1.set(o2.t0, b0); } });");
/*fuzzSeed-159544250*/count=1623; tryItOut("mathy5 = (function(x, y) { return ( + Math.min(( + (Math.fround(Math.min(Math.atan2((Math.fround(( - Math.fround(( ~ (Math.asinh((-0x100000000 >>> 0)) >>> 0))))) | 0), (y | 0)), Math.PI)) && (( + y) + ( + Math.atan2(( + 1), (y >>> 0)))))), Math.fround((mathy1((( + Math.pow((x >>> 0), (( + y) >>> 0))) >>> 0), ((( + Math.ceil(x)) * ( + -0x080000000)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [1/0, 0, -0x080000001, 2**53-2, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, -(2**53-2), -(2**53+2), Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, 2**53, -Number.MAX_VALUE, -(2**53), 42, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 1.7976931348623157e308, 1, 0/0, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, -0, Number.MIN_VALUE, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-159544250*/count=1624; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.atan2(mathy0(Math.fround(( + (-(2**53) ? ( + (((-0x100000000 | 0) && ((y < -0x080000001) === x)) | 0)) : ( + ( ~ ( + (((y | 0) >> x) | 0))))))), ( ! Math.cos(y))), Math.hypot(mathy1((x | 0), (-0x0ffffffff >>> 0)), ((Math.fround(mathy1(y, x)) ? Math.log(x) : Math.fround(Math.max(x, -(2**53-2)))) | 0))); }); testMathyFunction(mathy5, [0/0, 42, -1/0, 2**53, 0x080000001, -0x100000000, -0x100000001, -0x0ffffffff, -0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, 0x07fffffff, -0x080000000, 0x080000000, 0x100000000, -0x07fffffff, -(2**53+2), -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 2**53+2, 1, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, 0, -Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=1625; tryItOut("/*RXUB*/var r = /[^]/gyi; var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-159544250*/count=1626; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0(( + Math.atan(( + Math.fround(( ! Math.fround((y !== (x >>> 0)))))))), ( + ( + mathy0(((Math.fround(y) <= (x && (Math.tanh((x | 0)) != x))) >>> 0), ( + ( + x))))))); }); testMathyFunction(mathy1, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-159544250*/count=1627; tryItOut("Object.defineProperty(g0, \"h2\", { configurable: /*RXUE*//\\2/gyim.exec(\"\\n\\n\\n\\n\\n\\n\"), enumerable: let (a = (--NaN) | (function shapeyConstructor(yipkjd){\"use strict\"; Object.freeze(yipkjd);yipkjd[\"length\"] = decodeURIComponent;yipkjd[\"length\"] = Error;{ print(getter); } Object.defineProperty(yipkjd, \"constructor\", ({}));if (yipkjd) Object.preventExtensions(yipkjd);yipkjd[\"length\"] =  /x/g ;yipkjd[\"length\"] = Function;delete yipkjd[\"length\"];yipkjd[\"length\"] = \"\\u51AC\";return yipkjd; }).call(window, \"\\uD771\")) (eval = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { return undefined }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(NaN), function  z (c) { \"use strict\"; f0(m1); } )),  get: function() {  return m0.get(v1); } });");
/*fuzzSeed-159544250*/count=1628; tryItOut("\"use asm\"; s0 += s1;");
/*fuzzSeed-159544250*/count=1629; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -9223372036854776000.0;\n    {\n      d2 = (+(1.0/0.0));\n    }\n    return (((((i0))|0) % (0x7fffffff)))|0;\n  }\n  return f; })(this, {ff: /*MARR*/[function(){}, true, arguments.caller, true, function(){}, function(){}, function(){}, true, arguments.caller, function(){}, arguments.caller, function(){}].sort}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53+2), 1, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, 0x080000000, 0x100000000, 2**53-2, 0, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, -(2**53), -0, -(2**53-2), 0x080000001, -0x080000000, 2**53, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 2**53+2, Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-159544250*/count=1630; tryItOut("mathy1 = (function(x, y) { return (mathy0(Math.atanh(Math.fround(Math.fround((Math.fround(Math.cosh(((x % (x | 0)) | 0))) !== Math.fround(( + x)))))), (Math.atanh(Math.min(Math.pow(Math.fround((( + x) ** ( + y))), Math.min(0x100000001, y)), Math.cos(-0x100000000))) | 0)) | 0); }); testMathyFunction(mathy1, [0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 0/0, 0.000000000000001, -0x0ffffffff, -0, 2**53-2, -(2**53-2), Math.PI, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, -0x100000001, 2**53+2, 0x100000000, 0x07fffffff, 1/0, -0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 42, 1, -(2**53+2)]); ");
/*fuzzSeed-159544250*/count=1631; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.hypot(Math.fround((Math.min(((((( + ((Math.imul((Math.min(x, -0x080000001) | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0) | ( + 0x080000001))) | 0) % (y | 0)) | 0) | 0), ((Math.min((mathy3(Math.fround((Math.ceil((0x0ffffffff | 0)) | 0)), (Math.max(( + ( - x)), (x | 0)) | 0)) >>> 0), (( ! x) >>> 0)) >>> 0) | 0)) | 0)), Math.fround(mathy0(( + Math.acos((Math.trunc(Math.fround(Math.min(Math.fround(Math.atan2(Math.fround(x), Math.fround(2**53+2))), x))) | 0))), Math.tan((Math.max(((x >> x) | 0), x) ** Number.MIN_VALUE))))); }); testMathyFunction(mathy5, [Math.PI, 0x100000001, -0x080000000, -0x100000001, 0/0, 1.7976931348623157e308, 1/0, 2**53+2, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 1, 2**53, -(2**53-2), 0x100000000, 0, 0x080000000, 0.000000000000001, -Number.MAX_VALUE, 0x080000001, -0, -0x100000000, -1/0, -0x07fffffff, 0x0ffffffff, 0x07fffffff, 42, -Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1632; tryItOut("/*RXUB*/var r = -13; var s = \"\\u00dd\"; print(uneval(s.match(r))); const d = (4277);");
/*fuzzSeed-159544250*/count=1633; tryItOut("i1 = new Iterator(this.t1, true);");
/*fuzzSeed-159544250*/count=1634; tryItOut("{ void 0; void schedulegc(481); }");
/*fuzzSeed-159544250*/count=1635; tryItOut("m1.set(o0.h2, new String.prototype.toLocaleLowerCase((4277), /*MARR*/[/.?(?:$.{3})($){0,}/gm,  \"use strict\" , function(){}, function(){}, function(){}, [(void 0)], [(void 0)], [(void 0)], /.?(?:$.{3})($){0,}/gm,  \"use strict\" ]));");
/*fuzzSeed-159544250*/count=1636; tryItOut("const v2 = o2.t2.byteOffset;");
/*fuzzSeed-159544250*/count=1637; tryItOut("( /x/ );");
/*fuzzSeed-159544250*/count=1638; tryItOut("mathy1 = (function(x, y) { return (((Math.log1p(mathy0(x, Math.min(Math.atan2(((Math.fround(mathy0(1, ( + 1))) ^ (x | 0)) >>> 0), ( - x)), ((x | 0) >>> y)))) | 0) == ((( + mathy0(( + (( + Math.atan2((( ~ (-Number.MIN_VALUE | 0)) | 0), Math.fround(y))) , ( + y))), ( + (( ! (( ! 1) | 0)) | 0)))) >> (( + (x | 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[null, (0/0), (0/0), new Boolean(false), new Boolean(false), new Boolean(false), (0/0), null, null, null, null, null, null, null, null, null, null]); ");
/*fuzzSeed-159544250*/count=1639; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n{}    d0 = ((((i1) ? (+(-1.0/0.0)) : (-((Float64ArrayView[(((-0x736b7a) ? (0x2f905941) : (0xf86a680e))) >> 3]))))) - ((Float32ArrayView[((0x60ec6220)-(0x39938ab0)) >> 2])));\n    return +((d0));\n  }\n  return f; })(this, {ff: new RegExp(\"(?:\\\\W)*\", \"yi\")}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_VALUE, Math.PI, 0x100000001, -0x100000000, 2**53-2, 1.7976931348623157e308, -0, Number.MAX_SAFE_INTEGER, -(2**53+2), 42, 1, 0x100000000, -0x0ffffffff, 2**53, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), -(2**53), 0x080000000, 0/0, 2**53+2, -0x07fffffff, -1/0, -0x100000001, 0, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1640; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1641; tryItOut("(a);");
/*fuzzSeed-159544250*/count=1642; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.fround(( ! Math.hypot(((Math.min((x >>> 0), (-0x100000001 | 0)) | 0) | 0), 42))) * (Math.log1p(((Math.fround(Math.acos(Math.fround(x))) <= Math.tanh(((Math.pow(0, y) | 0) + y))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-159544250*/count=1643; tryItOut("/*tLoop*/for (let e of /*MARR*/[ /x/ , false,  /x/ , undefined,  /x/ ,  /x/ ,  /x/ , Infinity, Infinity, undefined, Infinity,  /x/ ,  /x/ , false]) { for (var p in i0) { v2 = new Number(0); } }");
/*fuzzSeed-159544250*/count=1644; tryItOut("testMathyFunction(mathy0, ['0', (new Boolean(false)), (new String('')), 0, NaN, true, (new Number(-0)), (new Boolean(true)), 0.1, ({valueOf:function(){return 0;}}), 1, '', /0/, '/0/', [0], [], ({toString:function(){return '0';}}), '\\0', -0, ({valueOf:function(){return '0';}}), (function(){return 0;}), objectEmulatingUndefined(), (new Number(0)), null, false, undefined]); ");
/*fuzzSeed-159544250*/count=1645; tryItOut("Object.defineProperty(this, \"o2.i2\", { configurable: (x % 4 == 1), enumerable: (x % 5 == 3),  get: function() {  return new Iterator(this.t1, true); } });");
/*fuzzSeed-159544250*/count=1646; tryItOut("m0.has(o1.h2);");
/*fuzzSeed-159544250*/count=1647; tryItOut("\"use strict\"; t1[v2] = d > NaN;function window(NaN, window, x, this.zzz.zzz, b, x, x, x, x, x = 25, x, x = window, d, b = this, x = x, e, w, c, NaN, x = false, x, b, x, x,  , x =  '' , w, w, \u3056 =  /x/ , x, \u3056, window, b, a = true, x,  '' , w, x, x = [[1]], x = \"\\u3D96\", w = undefined, eval, w, c, x, d, a, eval =  /x/ , z, \u3056, x, x = true, x =  '' , x, e, eval, d =  \"\" , x, x, window, e, b, z, w, a = null, x, d, x, x = window, x, w, e, x, x, d = b, NaN, \u3056, b, \u3056, x = y, b = /(?:$|$)?(?=\uf5c6?){1,}|(?!^)?+/y, -19, x, c = -15, x, x =  /x/ , x = window, y) { yield x } print(x);");
/*fuzzSeed-159544250*/count=1648; tryItOut("mathy2 = (function(x, y) { return (( ~ mathy1((Math.min(Math.pow(x, x), 2**53) | 0), ((y === Math.imul(0x100000000, (Math.fround(mathy1(Math.fround(-Number.MAX_VALUE), Math.fround(Math.atan2(Math.fround(0x0ffffffff), y)))) < x))) | 0))) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, 2**53+2, 0, Number.MIN_VALUE, -0x07fffffff, 0x100000001, -(2**53), Number.MAX_VALUE, 0x080000001, 0x080000000, -0x080000001, 2**53-2, 2**53, -0x100000001, -0x100000000, -1/0, -0, -(2**53+2), 1.7976931348623157e308, 0x07fffffff, 0x0ffffffff, -0x080000000, -(2**53-2), 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, Math.PI, 1, 42]); ");
/*fuzzSeed-159544250*/count=1649; tryItOut("/* no regression tests found */function c\u0009(e, {b}) { m2[\"valueOf\"] = f0; } v2 = g2.runOffThreadScript();");
/*fuzzSeed-159544250*/count=1650; tryItOut("\"use strict\"; g2 + '';");
/*fuzzSeed-159544250*/count=1651; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.atan2(Math.fround(Math.hypot(Math.fround(( + (( + ((Math.atan2(Math.atan2((y >>> 0), Math.fround(1/0)), x) >>> 0) !== (((y >>> 0) ? (x >>> 0) : (x >>> 0)) >>> 0))) >> ( + x)))), ((( + (y & (y | 0))) <= (Math.fround(Math.round(y)) == -(2**53))) | 0))), Math.fround((Math.fround(( ~ Math.fround(Math.cosh(y)))) !== (Math.fround((mathy0(y, ( + ((x | 0) & (42 | 0)))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [-0x100000000, 2**53, -0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -1/0, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, 0x100000000, 0x080000001, -(2**53-2), -0x0ffffffff, 1, -0x080000000, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, 42, 2**53-2, Number.MIN_VALUE, Math.PI, -0x100000001, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, 0/0, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=1652; tryItOut("let (y) { v1 = Object.prototype.isPrototypeOf.call(g0, a0); }");
/*fuzzSeed-159544250*/count=1653; tryItOut("\"use strict\"; v1 = (p2 instanceof m2);");
/*fuzzSeed-159544250*/count=1654; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.round(((Math.hypot((x >>> 0), ((Math.log2(( + Math.fround(Math.abs((-0x100000000 | 0))))) | 0) >>> 0)) >>> 0) >>> Math.fround(Math.imul(x, Math.fround(Math.asin(( + (Math.acos(( + mathy2(Number.MIN_SAFE_INTEGER, ( + y)))) | 0)))))))); }); testMathyFunction(mathy4, [-0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x100000001, Math.PI, 1, -0x0ffffffff, 0x080000001, -(2**53-2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, 2**53, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_VALUE, -0, -(2**53), 0x07fffffff, 0, 1.7976931348623157e308, 0x080000000, 2**53+2, 0.000000000000001, 0x100000000, -0x080000000, Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-159544250*/count=1655; tryItOut("\"use strict\"; {print(x);this.v1 = Object.prototype.isPrototypeOf.call(m1, f2); }");
/*fuzzSeed-159544250*/count=1656; tryItOut("\"use strict\"; this.zzz.zzz;let(rpwmjj) ((function(){3;})());");
/*fuzzSeed-159544250*/count=1657; tryItOut("/*vLoop*/for (let rceeyk = 0, x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })(/\\2|${4}(?![^])/y), (a =>  { return; } ).apply, arguments.callee); rceeyk < 2; ++rceeyk) { const d = rceeyk; g0.t1 = new Float64Array(t2); } ");
/*fuzzSeed-159544250*/count=1658; tryItOut("\"use strict\"; /*RXUB*/var r = Math.expm1(-27); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-159544250*/count=1659; tryItOut("\"use strict\"; testMathyFunction(mathy4, [42, -Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 0, -(2**53+2), -0, -0x080000000, 1/0, -0x100000001, 0x080000000, 0x080000001, 0/0, 0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), -0x0ffffffff, 0x100000001, -0x100000000, Number.MAX_VALUE, 2**53, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1660; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.min(Math.fround((( ! x) >>> 0)), ( + Math.hypot(( ! y), Math.fround((Math.fround(y) | (42 | 0)))))), Math.fround(Math.max(( ~ y), (Math.fround((( + mathy2(( + -Number.MAX_VALUE), (Math.fround(mathy1((Math.asin((x != x)) | 0), Math.fround(y))) >>> 0))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [objectEmulatingUndefined(), [0], (new String('')), ({valueOf:function(){return 0;}}), (function(){return 0;}), false, 0, null, 1, '/0/', '0', (new Number(-0)), [], ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), -0, /0/, (new Boolean(true)), true, (new Number(0)), NaN, (new Boolean(false)), '\\0', undefined, '', 0.1]); ");
/*fuzzSeed-159544250*/count=1661; tryItOut("testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, 0x07fffffff, -(2**53), 1.7976931348623157e308, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, -(2**53+2), -0x100000000, Math.PI, -0x07fffffff, -Number.MIN_VALUE, 0x100000000, 42, -0x0ffffffff, 1, -0x100000001, Number.MIN_VALUE, 0.000000000000001, -(2**53-2), 0x0ffffffff, -1/0, -0x080000000, -0, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2]); ");
/*fuzzSeed-159544250*/count=1662; tryItOut("v1 = a0.length;");
/*fuzzSeed-159544250*/count=1663; tryItOut("");
/*fuzzSeed-159544250*/count=1664; tryItOut("for (var v of g2) { try { m0.get(t2); } catch(e0) { } o1.m1.get(g2); }");
/*fuzzSeed-159544250*/count=1665; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-159544250*/count=1666; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy3(Math.fround(mathy2((Math.acos(x) ? ( + (Math.log2(x) ** ( + ( ~ ( + -Number.MAX_SAFE_INTEGER))))) : (Math.asin((x | 0)) | 0)), Math.fround(Math.cosh(Math.fround(( + Math.max(( + (Math.log10(y) | 0)), ( + (Math.clz32(-Number.MIN_SAFE_INTEGER) ? (Math.cosh(x) | 0) : Math.fround(Math.max(Number.MIN_VALUE, Math.fround(Math.fround(Math.hypot(Math.fround(y), -0)))))))))))))), ((Math.pow(((Math.ceil((Math.fround(y) >> x)) | 0) ^ ( + ( - y))), Math.min((x | (y | 0)), y)) % (( + Math.atan2(Math.fround(Math.fround(Math.fround(Math.fround(y)))), ( + Math.cosh(( + -0x0ffffffff))))) | 0)) | 0)); }); ");
/*fuzzSeed-159544250*/count=1667; tryItOut("/*bLoop*/for (var pvdfag = 0; (window) && pvdfag < 32; ++pvdfag) { if (pvdfag % 4 == 1) {  '' ; } else { t0.set(t1, 2); }  } ");
/*fuzzSeed-159544250*/count=1668; tryItOut("/*ODP-3*/Object.defineProperty(e0, \"cos\", { configurable: (x % 33 != 30), enumerable: (x % 4 != 1), writable: (x % 55 != 35), value: v0 });");
/*fuzzSeed-159544250*/count=1669; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1670; tryItOut("/*iii*/e2.has(g2);/*hhh*/function kwkisl(...e){/*bLoop*/for (var wkdaiu = 0; wkdaiu < 9; ++wkdaiu) { if (wkdaiu % 2 == 0) { v1 = t2.length; } else { print(\"\\u02BB\"); }  } }");
/*fuzzSeed-159544250*/count=1671; tryItOut("\"use strict\"; {}function \u3056(...a)({})f1(i1);");
/*fuzzSeed-159544250*/count=1672; tryItOut("/* no regression tests found */\ng1.t2 = new Uint8ClampedArray(b1);\n{ if (!isAsmJSCompilationAvailable()) { void 0; gcslice(921222342); } void 0; }");
/*fuzzSeed-159544250*/count=1673; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(Math.max(Math.fround((Math.cos((Math.fround(0x080000001) ** (y | 0))) , (Math.hypot((mathy0(x, Math.fround(( - (Math.ceil(x) | 0)))) | 0), (Math.log10(Math.fround(mathy0(Math.fround(x), Math.fround(0x100000000)))) | 0)) | 0))), Math.fround(( + mathy0(( + ( ! Math.fround(( - ( + Math.tanh(( + Number.MAX_VALUE))))))), ( ~ Math.hypot(( + ((y >>> 0) >= (2**53-2 >>> 0))), x))))))); }); testMathyFunction(mathy1, [-0x0ffffffff, 42, 0x100000000, 0.000000000000001, Number.MIN_VALUE, 0, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, 2**53, -0, 0/0, 2**53+2, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, -(2**53), -0x100000001, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, -0x07fffffff, 1/0, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, Math.PI, Number.MAX_VALUE]); ");
/*fuzzSeed-159544250*/count=1674; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.max(( ~ Math.min((y >= ((y , (y >>> 0)) | 0)), x)), ( + Math.atanh(( + ( + ((( ~ (x | 0)) | 0) * (-0x07fffffff >>> 0)))))))); }); testMathyFunction(mathy5, [0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, Math.PI, -(2**53), 0x080000001, 1, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 2**53+2, 2**53-2, -(2**53+2), -0x100000001, -(2**53-2), -0x080000001, 0, -1/0, 1/0, 0x100000000, -Number.MAX_VALUE, -0x080000000, Number.MAX_VALUE, 0x080000000, -0, Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 0x100000001, 2**53]); ");
/*fuzzSeed-159544250*/count=1675; tryItOut("/*bLoop*/for (let ikddzg = 0; ikddzg < 58; ++ikddzg) { if (ikddzg % 17 == 1) { selectforgc(o1); } else { x = x++, Math.imul(e, 26), x = +this, pvbzoz, lemhba, ibtkva, hfgzyb, nmfiyn;a1.splice(NaN, v0, p0); }  } ");
/*fuzzSeed-159544250*/count=1676; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1677; tryItOut("e2.has(p0);");
/*fuzzSeed-159544250*/count=1678; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.fround((Math.min((Math.trunc(Math.log10(x)) | 0), ((( ! x) | 0) | 0)) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[0x2D413CCC, [1], {}, 0x2D413CCC, 0x2D413CCC, (0/0), 0x2D413CCC, [1], (0/0), [1], (-1/0), {}, 0x2D413CCC, {}, [1], {}, [1], {}, 0x2D413CCC, (-1/0), (0/0), 0x2D413CCC, 0x2D413CCC, (0/0), {}, {}, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, [1], {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, (-1/0), [1], (-1/0), (-1/0), {}, (0/0), {}, (-1/0), (-1/0), (-1/0), 0x2D413CCC, {}, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, {}, (0/0)]); ");
/*fuzzSeed-159544250*/count=1679; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((Math.expm1(Math.atan2(y, x)) | 0) & (Math.cbrt(((Math.fround((Math.imul(x, (x | 0)) | 0)) | 0) | 0)) >>> 0)) !== Math.imul(( + Math.cos(( + (( - (y >>> 0)) >>> 0)))), Math.imul(Math.fround(( ! Math.fround((42 === y)))), x))); }); testMathyFunction(mathy0, [2**53+2, -0x100000000, 0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), 0, -0x07fffffff, Math.PI, -Number.MAX_VALUE, 0/0, 0x07fffffff, Number.MIN_VALUE, -0x080000000, 0x080000000, 0x0ffffffff, -(2**53+2), -0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 42, 1, 2**53-2, 2**53, 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -0, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=1680; tryItOut("\"use strict\"; /*hhh*/function krevla(e, e = x){/*RXUB*/var r = /^/gim; var s = \"\\u3969\"; print(s.split(r)); }/*iii*/s1 = Array.prototype.join.call(a0, g2.s0, t1, t0, i2, s1);");
/*fuzzSeed-159544250*/count=1681; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround(( + Math.fround((Math.hypot(Math.sqrt(x), (y > -(2**53))) && Number.MAX_VALUE)))))); }); testMathyFunction(mathy4, [0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, 0.000000000000001, 2**53+2, -(2**53-2), 0x07fffffff, 0x100000000, -Number.MAX_VALUE, -0x100000001, -0x080000000, 2**53, 2**53-2, 1, -(2**53+2), -0, Math.PI, 1/0, 1.7976931348623157e308, -0x0ffffffff, -0x07fffffff, -0x100000000, 0x080000001, -1/0, 0x0ffffffff]); ");
/*fuzzSeed-159544250*/count=1682; tryItOut("\"use strict\"; let w = x, gnbpmm, a;/*RXUB*/var r = new RegExp(\"(?:(?=\\u4245)*?\\\\b+?\\\\b|.{0,}|\\\\b(\\\\b[^\\\\u006e-\\\\u00b5\\\\s\\\\w]\\\\2)|\\\\D\\\\B|[^]+?{2,3}{2,4}|($)(?=\\\\D)**?)\", \"gm\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-159544250*/count=1683; tryItOut("/*vLoop*/for (var pjrenn = 0; pjrenn < 93; ++pjrenn) { let x = pjrenn; /*RXUB*/var r = /(?!\\1)*|\\3|\\3*|(?:(?:[^\\cU-}])?|\\b)\\b+?+/ym; var s = \"\"; print(s.split(r));  } ");
/*fuzzSeed-159544250*/count=1684; tryItOut("i1.next();\ndelete o0[\"__iterator__\"];\n");
/*fuzzSeed-159544250*/count=1685; tryItOut("g1.o0.o2.t2[({valueOf: function() { h1 + '';continue ;return 5; }})];");
/*fuzzSeed-159544250*/count=1686; tryItOut("a0.reverse();");
/*fuzzSeed-159544250*/count=1687; tryItOut("\"use strict\"; ;");
/*fuzzSeed-159544250*/count=1688; tryItOut("with({x: new RegExp(\"\\\\2\", \"yim\")})f1.toSource = (function() { v2 = t2.length; return o0.o1.o0.f2; });let(z, of, ymkaau, b, xzhvwp, hdnhkl, z, avwcut, c, hqfymm) ((function(){ '' ;})());");
/*fuzzSeed-159544250*/count=1689; tryItOut("let z = [,], x, x, x;return this;");
/*fuzzSeed-159544250*/count=1690; tryItOut("z =  \"\" (z).__defineSetter__(\"x\", neuter), e = \n /x/ , d = \"\\u7746\", ggxnqm, z, dsgeiu;a1.shift(h2);");
/*fuzzSeed-159544250*/count=1691; tryItOut("Object.preventExtensions(g1.h2);");
/*fuzzSeed-159544250*/count=1692; tryItOut("\"use strict\"; v0 = i1[\"add\"];");
/*fuzzSeed-159544250*/count=1693; tryItOut("\"use strict\"; /*infloop*/for(let b in  \"\" ) {g2.v2 = t0.length;print([z1]); }");
/*fuzzSeed-159544250*/count=1694; tryItOut("WeakSet.prototype.has = z;e = x;");
/*fuzzSeed-159544250*/count=1695; tryItOut("/*infloop*/L:while((4277))print(x);");
/*fuzzSeed-159544250*/count=1696; tryItOut("s0 += s2;");
/*fuzzSeed-159544250*/count=1697; tryItOut("a0.sort(f0);");
/*fuzzSeed-159544250*/count=1698; tryItOut("\"use strict\"; e2.has(b0);");
/*fuzzSeed-159544250*/count=1699; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, -0x080000000, Math.PI, 1.7976931348623157e308, 0, 0x0ffffffff, -0x0ffffffff, -0x100000000, Number.MAX_VALUE, -0, 2**53+2, 0x080000001, 0/0, -0x100000001, 2**53-2, 1/0, 0x080000000, 1, 2**53, 42, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, 0.000000000000001, 0x100000001, -(2**53-2), -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1700; tryItOut("\"use strict\"; /*vLoop*/for (buogfg = 0; buogfg < 31; ++buogfg) { const w = buogfg; t0[6] = o0.f2; } ");
/*fuzzSeed-159544250*/count=1701; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.min(Math.pow((Math.fround((Math.fround(Math.max(y, y)) & Math.fround(( ~ y)))) < ( + y)), Math.fround((Math.imul((( + Math.max(( + 0/0), ( + x))) >>> 0), Math.abs(x)) >>> 0))), ( ! ((Math.fround(( - (((2**53 | 0) ? (x | 0) : (y | 0)) | 0))) / (mathy0(y, Math.atan(-(2**53+2))) >>> (( - Math.fround(0x100000001)) * x))) | 0))); }); testMathyFunction(mathy2, [-0x100000001, 0x100000000, 2**53+2, 1, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -0, 2**53, 0x100000001, 1.7976931348623157e308, 0/0, 0.000000000000001, Number.MAX_VALUE, 0, 0x080000000, -(2**53+2), Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -0x080000000, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, 0x0ffffffff, 1/0, 0x07fffffff, -Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-159544250*/count=1702; tryItOut("\"use strict\"; w, x;v0 = g0.runOffThreadScript();");
/*fuzzSeed-159544250*/count=1703; tryItOut("testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), /0/, (new Boolean(true)), 1, [], ({toString:function(){return '0';}}), [0], null, objectEmulatingUndefined(), -0, (new String('')), '\\0', (new Number(0)), '/0/', false, '0', true, '', undefined, 0, (function(){return 0;}), (new Number(-0)), NaN, 0.1, (new Boolean(false)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-159544250*/count=1704; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1705; tryItOut("\"use strict\"; testMathyFunction(mathy2, ['/0/', -0, (new Number(-0)), (new Boolean(false)), /0/, [], undefined, 0.1, [0], '\\0', 0, ({valueOf:function(){return 0;}}), '0', (function(){return 0;}), '', false, (new Boolean(true)), 1, (new Number(0)), objectEmulatingUndefined(), null, NaN, (new String('')), true, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-159544250*/count=1706; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( ! (Math.hypot((( + Math.sinh(mathy0((x | 0), ( + x)))) >>> 0), ((Math.imul(((( + ( ! y)) >>> (( - (( - y) >>> 0)) | 0)) | 0), (( - ( + Math.asin(y))) | 0)) <= Math.atanh((-0x100000000 | 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 2**53, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, 0, 1.7976931348623157e308, 0/0, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, 1, 0x080000000, Number.MIN_VALUE, 0x080000001, -0x07fffffff, -0x080000000, 0x0ffffffff, -(2**53+2), -0x100000000, 2**53+2, -0x0ffffffff, -0, -(2**53), 0x100000001, Math.PI, 0.000000000000001, 42, 2**53-2, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1707; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.hypot(( ~ ((( - Math.fround(Math.fround(Math.hypot((( + x) * y), ( + Math.atan2((x >>> 0), (( ! (y >>> 0)) >>> 0))))))) | 0) >> ( ~ Math.fround((y ? ( + y) : Math.fround(Math.cosh(x))))))), (( + ( ~ ( + x))) < Math.cbrt(( + Math.atanh(( + Math.imul(( - 0x0ffffffff), (Math.log1p(Math.fround(Number.MIN_SAFE_INTEGER)) >>> 0)))))))); }); testMathyFunction(mathy1, [0/0, -0x100000000, 0, -1/0, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, Math.PI, 1/0, -0x07fffffff, 0x080000000, 0x100000000, 0x100000001, 1, -0x100000001, -0x0ffffffff, -0, 0x080000001, Number.MAX_VALUE, -0x080000001, -Number.MAX_VALUE, 2**53, -0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-159544250*/count=1708; tryItOut("\"use strict\"; /*oLoop*/for (bpuzob = 0; bpuzob < 48 && (((makeFinalizeObserver('nursery')))); ++bpuzob) { \u000cg2.v1 = Object.prototype.isPrototypeOf.call(t1, h1);{} } ");
/*fuzzSeed-159544250*/count=1709; tryItOut("\"use strict\"; for (var p in p0) { try { v2 = this.a1.length; } catch(e0) { } this.a1.forEach((function() { for (var j=0;j<30;++j) { f2(j%4==1); } })); }");
/*fuzzSeed-159544250*/count=1710; tryItOut("");
/*fuzzSeed-159544250*/count=1711; tryItOut("Array.prototype.splice.apply(a0, [-18, /*UUV1*/(b.setUTCDate = function  b (x, z) { yield (NaN ^= x) } )]);");
/*fuzzSeed-159544250*/count=1712; tryItOut("mathy5 = (function(x, y) { return (mathy0((((( + Math.atanh(( + (Math.cosh(( + ( ! Math.fround(y)))) >>> 0)))) >>> 0) ? (((Math.log(Math.fround(x)) ? (x ? y : Math.imul(x, -(2**53-2))) : (( - (Math.fround(( ! (1.7976931348623157e308 | 0))) | 0)) | 0)) | 0) >>> 0) : ( ! Math.abs((( + ( ! -0x0ffffffff)) | 0)))) >>> 0), Math.fround(Math.max(Math.hypot(( ~ ( + Math.fround(Math.max(( + y), ( + x))))), Math.atan2(( + ( - x)), Math.fround(Math.pow(Math.fround(x), Math.fround(-(2**53-2)))))), Math.fround(Math.atan2(Math.fround((( - (( ~ (2**53-2 + y)) >>> 0)) >>> 0)), ( + ( ! ( + x)))))))) >>> 0); }); testMathyFunction(mathy5, [2**53-2, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, 2**53+2, -0x080000001, -1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), Number.MAX_VALUE, 0x07fffffff, 42, Math.PI, 0/0, 0x0ffffffff, -0, -0x100000001, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0x080000000, 2**53, -0x0ffffffff, -(2**53+2), 0x100000000, -Number.MIN_VALUE, 0, 0x080000001]); ");
/*fuzzSeed-159544250*/count=1713; tryItOut("v0 = g0.runOffThreadScript();");
/*fuzzSeed-159544250*/count=1714; tryItOut("i1.toSource = (function() { try { m1.delete(v1); } catch(e0) { } try { s0 += s2; } catch(e1) { } m0.set(h0, o0.a2); return e1; });");
/*fuzzSeed-159544250*/count=1715; tryItOut("m0.delete(t1);");
/*fuzzSeed-159544250*/count=1716; tryItOut("mathy1 = (function(x, y) { return (Math.cosh(( + (Math.expm1(Math.fround(Math.pow((x == mathy0((mathy0((x >>> 0), (x >>> 0)) >>> 0), ( + x))), x))) << ( ! ((( + (( + y) >>> ( + Math.fround(((y >>> 0) >>> (Math.acosh((-0x0ffffffff | 0)) | 0)))))) + (( + ( ! x)) | 0)) >>> 0))))) >>> 0); }); ");
/*fuzzSeed-159544250*/count=1717; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.atanh(( + Math.expm1(Math.cosh(( + Math.tan(Math.log1p(((((Math.atan((x >>> 0)) >>> 0) >>> 0) % (x >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy5, [undefined, '0', objectEmulatingUndefined(), [0], 1, ({valueOf:function(){return 0;}}), '', 0, (new Boolean(false)), null, false, [], ({toString:function(){return '0';}}), 0.1, true, (new Number(0)), NaN, (function(){return 0;}), '/0/', (new Boolean(true)), ({valueOf:function(){return '0';}}), (new Number(-0)), /0/, '\\0', -0, (new String(''))]); ");
/*fuzzSeed-159544250*/count=1718; tryItOut("/*RXUB*/var r = /(?!((?:[^]))|[\\2-\\u4Df6\\D]?)+?/y; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=1719; tryItOut("mathy4 = (function(x, y) { return (Math.max((( + (Math.tan(y) | 0)) | 0), ( + Math.ceil(( + x)))) < Math.sinh(Math.pow(Math.fround(Math.max(0/0, Math.pow(y, -0x07fffffff))), (x & ( + y))))); }); testMathyFunction(mathy4, /*MARR*/[{x:3}, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), {x:3}, ({x:3}), {x:3}, ({x:3}), ({x:3}), ({x:3}), ({x:3}), objectEmulatingUndefined(), x, objectEmulatingUndefined(), ({x:3}), ({x:3}), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x, {x:3}, ({x:3}), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), x, new Number(1.5), objectEmulatingUndefined(), ({x:3}), new Number(1.5), {x:3}, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), {x:3}, {x:3}, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), x, {x:3}, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), ({x:3}), objectEmulatingUndefined(), x, x, new Number(1.5), new Number(1.5), new Number(1.5), ({x:3}), ({x:3}), {x:3}, {x:3}, new Number(1.5), {x:3}, objectEmulatingUndefined(), x, objectEmulatingUndefined(), ({x:3}), new Number(1.5), {x:3}, new Number(1.5), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), ({x:3}), ({x:3}), {x:3}, ({x:3}), ({x:3}), new Number(1.5), x, x, ({x:3}), ({x:3}), objectEmulatingUndefined(), ({x:3}), x, x, x, x, x, x, x, x, x, x, x, x, ({x:3}), x, ({x:3}), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), ({x:3}), objectEmulatingUndefined(), ({x:3}), objectEmulatingUndefined(), ({x:3}), {x:3}, x, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), x, x, {x:3}, objectEmulatingUndefined(), objectEmulatingUndefined(), ({x:3}), {x:3}, ({x:3}), objectEmulatingUndefined(), x, objectEmulatingUndefined(), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), {x:3}, new Number(1.5), objectEmulatingUndefined(), {x:3}, ({x:3}), ({x:3}), x, new Number(1.5)]); ");
/*fuzzSeed-159544250*/count=1720; tryItOut("v1 = g2.runOffThreadScript();");
/*fuzzSeed-159544250*/count=1721; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 8589934591.0;\n    var d4 = -1025.0;\n    return +((1.5474250491067253e+26));\n  }\n  return f; })(this, {ff: RegExp.prototype.test}, new ArrayBuffer(4096)); testMathyFunction(mathy4, ['/0/', ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (new Boolean(true)), -0, [0], '0', (new String('')), undefined, 1, '\\0', [], (function(){return 0;}), (new Number(0)), 0.1, ({valueOf:function(){return 0;}}), /0/, (new Boolean(false)), true, 0, null, '', false, objectEmulatingUndefined(), (new Number(-0)), NaN]); ");
/*fuzzSeed-159544250*/count=1722; tryItOut("\"use strict\"; Array.prototype.splice.apply(a0, [12, ({valueOf: function() { g1.p0 + h1;return 10; }})]);");
/*fuzzSeed-159544250*/count=1723; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround((((( + Math.trunc(Math.fround((((y | 0) < (mathy0(0.000000000000001, Math.log2(x)) >>> 0)) | 0)))) >>> 0) ? (((Math.fround(Math.tan(( + Math.sqrt(y)))) ? ( + Math.atan2((x ? Math.imul(y, Math.fround(( ~ Math.fround(y)))) : y), x)) : Math.fround(( ~ y))) >>> 0) | 0) : Math.fround((Math.fround((Math.max(Math.fround((y == x)), Math.fround(x)) >>> 0)) | y))) | 0)) !== Math.fround(((( + Math.max(( + ( ~ y)), mathy0(Math.log10(2**53), Number.MIN_SAFE_INTEGER))) | 0) <= (Math.pow(((( + Math.asinh(x)) >>> ( ~ Math.fround(( ~ Math.fround(x))))) >>> 0), (x | 0)) >>> 0))))); }); testMathyFunction(mathy1, [-0x07fffffff, 0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, -0x080000001, 1, Math.PI, -(2**53), -Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, -0x0ffffffff, 42, 0, -Number.MIN_VALUE, 0.000000000000001, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -(2**53-2), 0x080000000, 0x080000001, Number.MAX_VALUE, 0/0, -Number.MAX_VALUE, 2**53-2, 1.7976931348623157e308, -0x100000001, 2**53+2, -1/0, 1/0, 0x07fffffff, 2**53]); ");
/*fuzzSeed-159544250*/count=1724; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1725; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o1.p2, t0);");
/*fuzzSeed-159544250*/count=1726; tryItOut("v0 = Object.prototype.isPrototypeOf.call(a1, f1);");
/*fuzzSeed-159544250*/count=1727; tryItOut("/*vLoop*/for (let lqzldk = 0; lqzldk < 17; ++lqzldk) { e = lqzldk; i0.send(t0); } ");
/*fuzzSeed-159544250*/count=1728; tryItOut("for (var v of i1) { try { v0 = a0.length; } catch(e0) { } try { m0.set(s0, eval(\"print(\\\"\\\\u6740\\\");\", [] = [])); } catch(e1) { } e1 = new Set; }");
/*fuzzSeed-159544250*/count=1729; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.max((Math.sinh(( + Math.fround(x))) >>> 0), mathy0(Math.min(Math.pow(y, ( + y)), mathy0(( + x), Math.fround(Number.MAX_VALUE))), ( + ((( + ( ~ x)) ? Math.fround(( + x)) : y) ? Math.fround(( - ((Number.MIN_VALUE % y) | 0))) : ( ~ Math.fround(y))))))); }); ");
/*fuzzSeed-159544250*/count=1730; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.sign(Math.imul(Math.pow(Math.fround(mathy0(Math.min(y, x), x)), (( + (mathy0(Math.fround(x), Math.fround(Math.asinh(-0x080000001))) >>> 0)) >>> 0)), (x ** Math.fround(Math.imul((Math.fround(y) >= Math.fround(y)), Math.fround(-(2**53-2))))))), (Math.fround(Math.atan2(Math.fround(Math.min(Math.pow((( ! (x >>> 0)) >>> 0), (((y >>> 0) >>> y) | 0)), 0.000000000000001)), Math.fround(y))) + ( - x))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 1, -0, 2**53-2, 0x100000000, 42, 2**53+2, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), -0x080000001, 0x080000001, 0x07fffffff, -0x100000000, Math.PI, Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, 0x080000000, -0x080000000, 0.000000000000001, -(2**53-2), 0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-159544250*/count=1731; tryItOut("g2.offThreadCompileScript(\"function f2(v2)  { return this.__defineSetter__(\\\"y\\\", (this.__defineGetter__(\\\"setter\\\", (1 for (x in []))).resolve).apply) } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 3 != 1), sourceIsLazy: (x % 3 != 1), catchTermination: true }));");
/*fuzzSeed-159544250*/count=1732; tryItOut("o0.__proto__ = o1;");
/*fuzzSeed-159544250*/count=1733; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( + (( ~ ((Math.imul(( + ((y | 0) ? ( + 1/0) : (y | 0))), Math.fround(y)) * ((y | 0) << y)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, Math.PI, -0x07fffffff, 2**53-2, -Number.MIN_VALUE, -1/0, -(2**53-2), 0, 0x100000001, 0x0ffffffff, -0x080000000, -0x0ffffffff, 2**53+2, 2**53, 1.7976931348623157e308, 1/0, -0, 42, -0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0x080000001, 0/0, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 1, 0x100000000]); ");
/*fuzzSeed-159544250*/count=1734; tryItOut("this.v1 = g0.eval(\"a1[11] = (/*UUV2*/(x.toString = x.getPrototypeOf));\");");
/*fuzzSeed-159544250*/count=1735; tryItOut("h2.getOwnPropertyNames = ((eval).apply).apply;");
/*fuzzSeed-159544250*/count=1736; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-159544250*/count=1737; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = o2.s1; print(s.replace(r, ((c = 3)))); ");
/*fuzzSeed-159544250*/count=1738; tryItOut("\"use strict\"; {}");
/*fuzzSeed-159544250*/count=1739; tryItOut("testMathyFunction(mathy3, ['\\0', null, '', (new String('')), [], ({toString:function(){return '0';}}), [0], false, (new Number(-0)), 1, undefined, 0, /0/, -0, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), (new Boolean(true)), '/0/', (function(){return 0;}), '0', (new Boolean(false)), true, NaN, (new Number(0)), 0.1]); ");
/*fuzzSeed-159544250*/count=1740; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-159544250*/count=1741; tryItOut("\"use asm\"; /*bLoop*/for (hpodpa = 0; hpodpa < 27; ++hpodpa) { if (hpodpa % 10 == 9) { print(x);\na0 = new Array;\n } else { g1.g2.a2 = []; }  } ");
/*fuzzSeed-159544250*/count=1742; tryItOut("\"use strict\"; testMathyFunction(mathy4, [1.7976931348623157e308, -(2**53-2), -(2**53+2), 2**53+2, -1/0, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 1, 0x080000001, -0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, -(2**53), -Number.MAX_VALUE, 0, -0x080000001, -Number.MIN_VALUE, 42, -0x100000001, Math.PI, 0x07fffffff, 2**53-2, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, -0, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, 0.000000000000001]); ");
/*fuzzSeed-159544250*/count=1743; tryItOut("(e = x);");
/*fuzzSeed-159544250*/count=1744; tryItOut("\"use strict\"; neuter(b2, \"same-data\");function NaN(x, e = null)\"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -576460752303423500.0;\n    var i3 = 0;\n    var d4 = -140737488355329.0;\n    var i5 = 0;\n    var d6 = -1.5474250491067253e+26;\n    var d7 = 33554433.0;\n    i1 = (!(0xe5f06b18));\n    d4 = (d6);\n    i0 = ((1.0) == (+(1.0/0.0)));\n    d7 = (-7.555786372591432e+22);\n    {\n      d6 = (-268435457.0);\n    }\n    (Float64ArrayView[1]) = ((+(abs((((((((-0x8000000) >= (0x7679b928))-(i3))>>>((i3)+((0x9251fab) >= (0x5105dde7)))))*0xc1a06) | ((i5)-(!(0x443f1266)))))|0)));\n    i1 = ((!(0xcf575d85)) ? ((((((0xcdd1a678)) >> ((0xfafbe703))) / (~((0xc143b16d)))) ^ ((i1)-((0x35e90af5) ? (0xffffffff) : (0x3302fdf2)))) > (0x3b70b4d4)) : (1));\n    i0 = (i5);\n    {\n      (Int16ArrayView[2]) = ((!(1))+(String.prototype.toLocaleLowerCase(7, new (WeakSet.prototype.delete)(x,  /x/g )))+(0xfcd7e655));\n    }\n    d6 = (((NaN)) / ((d6)));\n    i1 = (i0);\n    {\n      i3 = (i3);\n    }\n    return +((d7));\n    {\n      i1 = (i3);\n    }\n    return +(((i1) ? (((d2)) / ((Float32ArrayView[((i1)-(0xfebdadc0)-(i0)) >> 2]))) : (+(-1.0/0.0))));\n  }\n  return f;continue ;");
/*fuzzSeed-159544250*/count=1745; tryItOut("\"use strict\"; ");
/*fuzzSeed-159544250*/count=1746; tryItOut("L: o2.toString = (function() { try { v0 = Object.prototype.isPrototypeOf.call(o2.m0, f0); } catch(e0) { } for (var p in o2) { v2 = a1.length; } return p1; });");
/*fuzzSeed-159544250*/count=1747; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan(( + Math.tanh(( + Math.tanh(x))))); }); testMathyFunction(mathy4, /*MARR*/[false,  /x/ , false,  /x/g , function(){}, false,  /x/ ,  /x/g ,  /x/ , false, false,  /x/g , false,  /x/ , false,  /x/g ,  /x/g ,  /x/ , false,  /x/ , function(){},  /x/ , function(){}, function(){},  /x/g , false, function(){},  /x/g ,  /x/ ,  /x/ , function(){},  /x/g ,  /x/g , function(){},  /x/g , function(){},  /x/ ,  /x/g ,  /x/ ,  /x/ , function(){}, function(){}, false, function(){}, false,  /x/ ,  /x/ ,  /x/g ,  /x/g ,  /x/g ,  /x/ , function(){},  /x/g , function(){}, false,  /x/g , false, false, false, false, function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , false,  /x/g , function(){}, false,  /x/ , false, false,  /x/ ,  /x/g ,  /x/ , false, function(){}, false,  /x/g ,  /x/g ,  /x/ , function(){}, false, function(){},  /x/g , false,  /x/g , function(){},  /x/g , false,  /x/g , false,  /x/g , function(){},  /x/ , function(){},  /x/g , function(){}, false, function(){}, function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , false,  /x/g ,  /x/ ,  /x/g ,  /x/ ,  /x/ ,  /x/g ,  /x/g ,  /x/ , false,  /x/g , function(){}, false,  /x/ , false, function(){},  /x/g , function(){},  /x/g , false, function(){},  /x/g ,  /x/ , false,  /x/g , function(){},  /x/ , function(){}, function(){}, false, false, false,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){},  /x/g ,  /x/g ,  /x/ ,  /x/ , false, false, function(){},  /x/ ,  /x/ ,  /x/g ,  /x/g , false, false,  /x/ ]); ");
/*fuzzSeed-159544250*/count=1748; tryItOut("\"use strict\"; /*iii*/s2 += 'x';/*hhh*/function vkbxuw(x, w){v0 = evalcx(\"x\", g0);}");
/*fuzzSeed-159544250*/count=1749; tryItOut("v2 = (h1 instanceof g0);");
/*fuzzSeed-159544250*/count=1750; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((Uint16ArrayView[0])))|0;\n    return ((((((/*FFI*/ff(((d1)))|0)) ^ ((((0xfffff*(i0))>>>((i0)+(0x98f6be1e)))))) != (((i0)-(i0)) << ((-0x1536ca8)-(/*FFI*/ff(((abs((((0x1c5a3226)) << ((0x3a4d9423))))|0)))|0))))-((((0x3766cd3e) % (0x5d9d566e))>>>((i0)+(-0x8000000)-((d1) == (d1)))))))|0;\n  }\n  return f; })(this, {ff: (Date.prototype.toGMTString).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x07fffffff, -0x080000000, 0x080000001, 0x100000001, 1, 0x100000000, 0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, -(2**53), Number.MIN_VALUE, 0/0, -(2**53-2), -0x100000000, Number.MAX_VALUE, Math.PI, 0.000000000000001, 0x0ffffffff, 2**53, -(2**53+2), -Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 2**53-2, -0x100000001, 42, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-159544250*/count=1751; tryItOut("var juccat = new ArrayBuffer(12); var juccat_0 = new Int16Array(juccat); juccat_0[0] = -9; var juccat_1 = new Int8Array(juccat); var juccat_2 = new Uint32Array(juccat); juccat_2[0] = -6; var juccat_3 = new Uint16Array(juccat); juccat_3[0] = 2; var juccat_4 = new Int32Array(juccat); juccat_4[0] = -3; v0 = evaluate(\"new RegExp(\\\"\\\\\\\\B|\\\\\\\\D+\\\\\\\\S^(?=(\\\\\\\\b)?)?(?!\\\\\\\\S{16384}\\\\\\\\3*){3,}\\\", \\\"ym\\\") ^ \\\"\\\\u93FE\\\"\", ({ global: o1.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: (juccat_3[2] % 2 != 0), element: g2.o1.o0.o0, sourceMapURL: s2 }));print((\"\\u5C94\".juccat_4[0] =  /x/ .getOwnPropertyNames()));v2 = false;");
/*fuzzSeed-159544250*/count=1752; tryItOut("\"use asm\"; testMathyFunction(mathy0, ['', (new Number(0)), undefined, (new Number(-0)), ({valueOf:function(){return 0;}}), false, '/0/', NaN, null, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), (new String('')), [0], true, 0.1, (new Boolean(true)), (new Boolean(false)), /0/, '\\0', '0', [], ({toString:function(){return '0';}}), (function(){return 0;}), -0, 1, 0]); ");
/*fuzzSeed-159544250*/count=1753; tryItOut("/*infloop*/for(z; (eval(\"\\\"use strict\\\"; mathy5 = (function(x, y) { return Math.log2(Math.cbrt(Math.atan2(( ~ y), ( + x)))); }); testMathyFunction(mathy5, [false, true, -0, (new String('')), (new Number(-0)), ({valueOf:function(){return '0';}}), (new Number(0)), '/0/', (new Boolean(false)), 1, (new Boolean(true)), 0, 0.1, '\\\\0', /0/, ({toString:function(){return '0';}}), [], undefined, NaN, '', [0], ({valueOf:function(){return 0;}}), '0', null, (function(){return 0;}), objectEmulatingUndefined()]); \",  /x/ )); x % x) {a2.reverse(t2); }");
/*fuzzSeed-159544250*/count=1754; tryItOut("/* no regression tests found */");
/*fuzzSeed-159544250*/count=1755; tryItOut("mathy1 = (function(x, y) { return ( ~ ( + ( + ( + -Number.MIN_VALUE)))); }); ");
/*fuzzSeed-159544250*/count=1756; tryItOut("((//h\n{z: c})%=(void version(185)));");
/*fuzzSeed-159544250*/count=1757; tryItOut("Array.prototype.push.apply(a2, [h2]);");
/*fuzzSeed-159544250*/count=1758; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((abs((~~(d1)))|0) % (-0x5e11209)))|0;\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ \"use strict\"; var dhellk = (x = (4277)); var rfiwrj = new RegExp(\"\\\\b*.?|[^\\\\b\\\\D_-\\u27b9]?\", \"gm\").acosh; return rfiwrj;})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000001, 2**53, -Number.MAX_VALUE, 2**53-2, -0x080000001, 0, -0, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), Number.MIN_VALUE, -(2**53), -0x100000000, Number.MAX_VALUE, 0x100000000, Math.PI, 0x0ffffffff, 0x07fffffff, 42, 1.7976931348623157e308, 1, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, 0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 1/0, -1/0]); ");
/*fuzzSeed-159544250*/count=1759; tryItOut("/*RXUB*/var r = new RegExp(\"((?:\\\\b)(?=[\\\\r-\\\\f\\\\S])|\\\\b?|(?:[]*?))\\\\3*?+?\", \"ym\"); var s = \"\\u68d0a\\u68d0a\"; print(s.replace(r, -12)); ");
/*fuzzSeed-159544250*/count=1760; tryItOut("v1 = r0.ignoreCase;");
/*fuzzSeed-159544250*/count=1761; tryItOut("\"use strict\"; this.v0 = Object.prototype.isPrototypeOf.call(t2, b0);");
/*fuzzSeed-159544250*/count=1762; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[x, \"\\u25A2\", x, \"\\u25A2\", x, x, \"\\u25A2\", x, \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", x, x, \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", x, \"\\u25A2\", x, x, \"\\u25A2\", x, \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", x, \"\\u25A2\", \"\\u25A2\", x, \"\\u25A2\", \"\\u25A2\", \"\\u25A2\", \"\\u25A2\"]) { print(Math.max([[1]], this)); }");
/*fuzzSeed-159544250*/count=1763; tryItOut("/*RXUB*/var r = x; var s = \"\\n\\n\\u00c5\\n\\uffff\\uffff\\uffff\\uffff\\n\\n\\u00c5\\n\\uffff\\uffff\\uffff\\uffff\\n\\n\\u00c5\\n\\uffff\\uffff\\uffff\\uffff\"; print(r.exec(s)); ");
/*fuzzSeed-159544250*/count=1764; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:\\\\S|(\\\\x9A?|(?=\\\\0)*[^])){4194304,4194306})\", \"i\"); var s = \"___zzz\\n___\\n_zzz\\n\"; print(r.test(s)); print(r.lastIndex); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
