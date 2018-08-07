

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
/*fuzzSeed-211892750*/count=1; tryItOut("{o0.v0 = g1.runOffThreadScript();print(x);print(x); }");
/*fuzzSeed-211892750*/count=2; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( ! Math.fround(Math.sqrt(Math.fround((Math.imul((( - ( ~ (Math.sinh((-Number.MIN_VALUE >>> 0)) >>> 0))) >>> 0), (Math.min(( + ( + y)), (Math.max(x, mathy3(x, -Number.MIN_VALUE)) >>> 0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy4, [(new String('')), null, ({toString:function(){return '0';}}), /0/, (new Boolean(true)), (new Boolean(false)), (new Number(0)), 0.1, '0', '/0/', [], -0, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), true, objectEmulatingUndefined(), 0, (new Number(-0)), undefined, '', '\\0', false, NaN, (function(){return 0;}), 1, [0]]); ");
/*fuzzSeed-211892750*/count=3; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.imul(Math.pow((Math.fround(Math.cosh((( ~ (/*MXX1*/o2 = g2.o0.g0.OSRExit; | 0)) | 0))) >>> 0), (Math.fround(Math.imul(( ! Math.log10(x)), ( + (((Math.max(( + 0/0), x) | 0) > (x | 0)) | 0)))) >>> 0)), (Math.cosh(Math.atan(((x > x) + y))) >>> 0))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -(2**53), -0x07fffffff, -1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000, 1, 0/0, -0x100000001, 0x07fffffff, 2**53-2, -0x100000000, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 0x080000001, -Number.MAX_VALUE, 42, -0, -0x0ffffffff, 0.000000000000001, 0, 0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-211892750*/count=4; tryItOut("Array.prototype.reverse.call(a2, b0, m1);");
/*fuzzSeed-211892750*/count=5; tryItOut("a0.forEach((function() { for (var j=0;j<11;++j) { f2(j%5==1); } }), s0, \"\\u2714\", i1, v0);");
/*fuzzSeed-211892750*/count=6; tryItOut("/*RXUB*/var r = new RegExp(\"((?=\\\\1*))\", \"i\"); var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=7; tryItOut("\"use strict\"; /*hhh*/function ngqlcv(){s1 + v0;}/*iii*/var a = let (eval = ({a1:1}), w, nytnru, qozzbl, rucmxy) ngqlcv = /(?:[^]+?)(?!(?!(?!\\B))|(?:\\W)*){1,5}.^*?/;o0.v0 = (i2 instanceof this.p0);function w(e = ) { \"use strict\"; g2.a1.unshift(s2, [z1,,]); } for (var p in m1) { try { a0.push(a1, o2, o0, p2); } catch(e0) { } try { for (var v of f2) { a0.reverse(t0, g1, e1); } } catch(e1) { } try { o1.t1.set(a1, 1); } catch(e2) { } Array.prototype.pop.apply(a2, []); }");
/*fuzzSeed-211892750*/count=8; tryItOut("\"use strict\"; /*bLoop*/for (let kytpmj = 0; kytpmj < 19; ++kytpmj) { if (kytpmj % 3 == 0) { m1.has(this.i1); } else { delete h1.has; }  } ");
/*fuzzSeed-211892750*/count=9; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    {\n      i1 = ((0xe83d31) > ((((/*FFI*/ff()|0) ? (0xf99cb3d6) : ((0x6c08e5b4) ? (0xffffffff) : (0xa0a52128)))+(i0)) >> (((((-1.5)) % ((+/*FFI*/ff(((~((0x266a6bef)))), ((-590295810358705700000.0)))))) >= (-((+(1.0/0.0))))))));\n    }\n    return (((i1)-((-134217729.0))+(!(i1))))|0;\n  }\n  return f; })(this, {ff: /\\D|$[^]{1}\\1{4}|[^]/gym.watch(\"isFrozen\", function(q) { \"use strict\"; return q; }).clear}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-211892750*/count=10; tryItOut("print(uneval(this.g2));");
/*fuzzSeed-211892750*/count=11; tryItOut("\"use strict\"; /*hhh*/function fbzpch(c, d){z = linkedList(z, 656);}fbzpch(eval(\"/* no regression tests found */\", x|=-22));");
/*fuzzSeed-211892750*/count=12; tryItOut("a2 = Array.prototype.filter.apply(a1, [(function() { for (var j=0;j<34;++j) { o1.f1(j%2==0); } }), g0.v2, v0, e2, g2.i0]);");
/*fuzzSeed-211892750*/count=13; tryItOut("\"use strict\"; Array.prototype.sort.call(a1, (function() { try { i2.__proto__ = g1.e0; } catch(e0) { } try { s0 += s1; } catch(e1) { } try { s0.__proto__ = a1; } catch(e2) { } h2.iterate = (function() { for (var j=0;j<124;++j) { f1(j%5==1); } }); return e1; }));");
/*fuzzSeed-211892750*/count=14; tryItOut("\"use strict\"; this.v0 = g1.a2.length;");
/*fuzzSeed-211892750*/count=15; tryItOut("with(x)t0 = this.a1[v0];");
/*fuzzSeed-211892750*/count=16; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + Math.cbrt((Math.log10(( + (Math.cos(Math.fround(Math.min(((Number.MAX_VALUE , y) , 0x080000000), ((Math.fround(Math.min(( + x), Math.min(-0x07fffffff, -(2**53)))) % ((Math.expm1((Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) >>> 0)) >>> 0)))) >>> 0))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[eval, this, [undefined], this, this, eval, [undefined], false, new Number(1.5), new Number(1.5), [undefined], [undefined]]); ");
/*fuzzSeed-211892750*/count=17; tryItOut("\"use strict\"; { void 0; void gc(this, 'shrinking'); }");
/*fuzzSeed-211892750*/count=18; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ! mathy1(mathy2((Math.abs(Math.log((x >>> 0))) | 0), Math.fround(-1/0)), Math.log(( ~ (Math.min(x, y) >>> 0))))) | 0); }); testMathyFunction(mathy4, [-0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, 1, 42, 0x100000000, 0.000000000000001, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, 2**53+2, 0/0, 0x07fffffff, Math.PI, Number.MAX_VALUE, 2**53, -(2**53), 2**53-2, -0x100000001, 0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, -(2**53+2), 0x100000001, 0, -(2**53-2), -0x0ffffffff, Number.MIN_VALUE, -0x080000001, -0x100000000]); ");
/*fuzzSeed-211892750*/count=19; tryItOut("mathy5 = (function(x, y) { return Math.fround(( - (( ! (Math.fround(-(2**53-2)) <= Math.fround((Math.imul(2**53, ( + x)) | 0)))) | 0))); }); testMathyFunction(mathy5, [0/0, Math.PI, 1, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, -0x07fffffff, -0x080000001, 0, 2**53+2, -1/0, 0x0ffffffff, -0x100000000, 0x100000001, Number.MIN_VALUE, -0x0ffffffff, 42, 2**53, 0x080000001, -0x100000001, -Number.MAX_VALUE, -(2**53), -(2**53-2), 0.000000000000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -(2**53+2), 0x100000000, Number.MAX_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0]); ");
/*fuzzSeed-211892750*/count=20; tryItOut("a0.pop(h1, Math.asinh(12), a0, (4277) <= ({eval: NaN}) += 20 >>> false);");
/*fuzzSeed-211892750*/count=21; tryItOut("a+=w;");
/*fuzzSeed-211892750*/count=22; tryItOut("mathy5 = (function(x, y) { return ((mathy0(( + Math.cosh(y)), ( + ( ! ( + ( + Math.trunc(( + Math.sign(( + ( ! x)))))))))) | 0) || ((Math.ceil(( ~ Math.tan(y))) | 0) >= ((( + (y >>> 0)) >>> 0) | ( ! Math.atan2((0x100000001 !== -0x0ffffffff), (1/0 >>> 0)))))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 1/0, -0, 2**53, -1/0, -Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -(2**53), -0x07fffffff, 0x100000000, 2**53-2, Math.PI, -0x100000001, 42, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, 0/0, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, 0, 0x080000001, 2**53+2, Number.MIN_VALUE, 0x080000000, 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-211892750*/count=23; tryItOut("mathy5 = (function(x, y) { return Math.cosh((Math.round((Math.min(( + ( + Math.atan2(( + (y ** (Math.clz32((y >>> 0)) >>> 0))), ( + x)))), mathy3(x, Math.tan(x))) | 0)) | 0)); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 2**53, -1/0, 0x07fffffff, 0.000000000000001, 1/0, -0x100000001, 0x100000001, 0x080000000, -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 2**53+2, 42, 0x100000000, Number.MAX_VALUE, -0x080000001, 0, 1, Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-211892750*/count=24; tryItOut("mathy4 = (function(x, y) { return ( - (Math.atan2(((( - (Math.min((x | 0), (-0x07fffffff | 0)) | 0)) | 0) >>> 0), ((Math.fround(Math.acos(( + y))) + Math.fround((Math.asin((Math.fround(Math.acosh((( + Math.sqrt(x)) >>> 0))) | 0)) | 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [1, 0.000000000000001, -(2**53-2), 0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, -(2**53+2), -0x100000000, 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 0, 0x100000000, -1/0, 42, 0/0, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, -0, -(2**53), -0x080000001, 0x080000001, Math.PI, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=25; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3{0,}\", \"gy\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-211892750*/count=26; tryItOut("v1 = (e2 instanceof g1.a1);");
/*fuzzSeed-211892750*/count=27; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + (Math.ceil(Math.min((x ? Math.fround(y) : y), (( ! ( ! y)) >>> 0))) >>> 0)) >> ( + Math.fround(Math.atan2(Math.fround(Math.log2(( ! ( ! -0x07fffffff)))), Math.fround(Math.asinh((( ~ (x >>> 0)) >>> 0))))))); }); ");
/*fuzzSeed-211892750*/count=28; tryItOut("\"use strict\"; \"use asm\"; /*vLoop*/for (var lblobl = 0; lblobl < 112; ++lblobl) { var z = lblobl; print(uneval(m1)); } ");
/*fuzzSeed-211892750*/count=29; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -4611686018427388000.0;\n    {\n      {\n        {\n          d1 = (+pow(((d0)), ((d1))));\n        }\n      }\n    }\n    (Float64ArrayView[((((0x17515c92)-(0x7015ba06))>>>((/*FFI*/ff(((-17.0)), ((-144115188075855870.0)), ((-524289.0)), ((-268435456.0)), ((281474976710657.0)), ((-1.015625)), ((-6.189700196426902e+26)), ((6.189700196426902e+26)), ((9007199254740992.0)), ((524289.0)), ((-1.0009765625)), ((-262145.0)))|0)-(0xfb489688))) / ((((0x44b6851e))*0x3931e)>>>((0xffffffff)))) >> 3]) = ((Float32ArrayView[((Uint32ArrayView[4096])) >> 2]));\n    {\n      (Float64ArrayView[4096]) = ((d0));\n    }\n    {\n      switch ((((0xffffffff) / (0x52d6ba8f)) >> (((0xffffffff) ? (0xfc16a856) : (0x17005ffb))-(0x257895cb)))) {\n      }\n    }\n    d1 = (d1);\n    return +((d1));\n  }\n  return f; })(this, {ff: eval(\"/*FARR*/[].map((let (e=eval) e),  '' )\", x)}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[-Infinity, -Infinity, false, false, -Infinity, false, false, false, -Infinity, -Infinity, false, false, false, false, -Infinity, false, -Infinity, -Infinity, false, -Infinity, false, -Infinity, -Infinity, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, -Infinity, false, false, false, false, false, -Infinity, -Infinity, false, -Infinity, -Infinity, false, false, false, -Infinity, false, false, false, -Infinity, -Infinity, -Infinity, false, false, false, -Infinity, false, false, -Infinity, false, false, -Infinity, false, -Infinity, false, -Infinity, -Infinity, false, false, -Infinity, false, -Infinity, false, false, -Infinity, false, -Infinity, false, -Infinity, false, false, -Infinity, -Infinity, false, false, false, -Infinity, -Infinity, -Infinity, false, false, false, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, false, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, false, false, false, false, false, false, -Infinity, -Infinity, false, false, -Infinity, false, false, false, -Infinity, false, false, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, false, false, -Infinity]); ");
/*fuzzSeed-211892750*/count=30; tryItOut("function shapeyConstructor(lpliat){\"use strict\"; return this; }/*tLoopC*/for (let a of /*PTHR*/(function() { for (var i of /*FARR*/[(/*UUV2*/(d.log10 = d.__lookupGetter__)) * undefined, x, , (allocationMarker()), (makeFinalizeObserver('nursery')),  /x/  += (void version(180)), eval(\"/* no regression tests found */\", ((/\\u00B6/g)())), .../*FARR*/[~/*UUV1*/(NaN.getFloat64 = /*wrap2*/(function(){ var okgezf =  /x/g ; var uyvepy = encodeURI; return uyvepy;})()) & delete eval.toSource, x ? x : {x: [], \u3056} = [, ], , , , x, x, , ...neuter, .../*FARR*/[, length\n, (new RegExp(\"[\\\\u0040-{]\\\\3*\", \"m\").c = /*MARR*/[new Number(1.5), new String('q'), new String('q'), new String('q'), new String('q'),  '\\0' ,  '\\0' ,  '\\0' , new Number(1.5), new String('q'),  '\\0' , new String('q'), new String('q'), new String('q'), new String('q'),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' , new Number(1.5), new String('q'),  '\\0' , new String('q'),  '\\0' , new String('q'), new String('q'),  '\\0' , new String('q'), new String('q'), new Number(1.5),  '\\0' , new String('q'),  '\\0' ,  '\\0' , new String('q'),  '\\0' , new String('q'), new Number(1.5),  '\\0' , new Number(1.5), new String('q'), new Number(1.5), new String('q'),  '\\0' , new String('q'),  '\\0' , new Number(1.5)].map(Array.prototype.lastIndexOf,  /x/g )).throw(x).watch(\"__proto__\", x), , .../*FARR*/[], ({a2:z2}) + delete x.c, ...new Array(-21), ( /x/g ).apply(Math.hypot( '' , [1,,]), (4277))], (\u3056 =  /x/ ), (yield false), (Math.log10(new (Function)( \"\" , window)) ? ((void version(185))) :  \"\" .valueOf(\"number\").__defineGetter__(\"x\", neuter) **= x), Math.log((Math.max(27, 3))), x, ], (void options('strict_mode')).unwatch(\"11\"), e = /*MARR*/['fafafa'.replace(/a/g, [,,z1]), new Boolean(false), new Boolean(false), new Boolean(false), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(true), new Boolean(false), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(true), new Boolean(true), 'fafafa'.replace(/a/g, [,,z1]), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(false), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(true), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(false), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(false), new Boolean(true), new Boolean(false), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(true), 'fafafa'.replace(/a/g, [,,z1]), 'fafafa'.replace(/a/g, [,,z1]), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(false), new Boolean(false), 'fafafa'.replace(/a/g, [,,z1]), new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(true)].map(arguments.callee), (4277), .../*MARR*/[-0x07fffffff]]) { yield i; } })()) { try{let iqvylr = shapeyConstructor(a); print('EETT'); Array.prototype.shift.call(a0);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-211892750*/count=31; tryItOut("\"use strict\";  for (var z of -4611686018427388000) /*RXUB*/var r = new RegExp(\"(?=\\\\b*?(?=\\\\1+.(?=(?=[\\ufe6f\\\\cT-\\\\xdF\\\\u75e7])){4,5})[^])|$\\\\s\", \"\"); var s = eval(\"/* no regression tests found */\", /*FARR*/[].sort(3)); print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=32; tryItOut("v0 = Object.prototype.isPrototypeOf.call(v1, h0);");
/*fuzzSeed-211892750*/count=33; tryItOut("qwgslo;this.o0.e0.has(v2);");
/*fuzzSeed-211892750*/count=34; tryItOut("\"use strict\"; \"use asm\"; a0 = Array.prototype.filter.apply(a2, [(function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18) { var r0 = a14 * a14; r0 = a17 + a11; var r1 = a1 - 7; var r2 = r0 % a11; print(a11); var r3 = 2 - a15; a6 = a15 & 3; a18 = a11 / a12; var r4 = a3 ^ a0; var r5 = r4 & a1; var r6 = x * a3; var r7 = a17 * a5; a3 = a13 * 3; var r8 = a7 | r6; var r9 = 5 + a7; a5 = a9 ^ 7; var r10 = 7 / 0; var r11 = a14 % r0; var r12 = a11 / a3; a2 = a12 ^ a6; var r13 = a14 / 8; a0 = r9 ^ 5; print(a16); var r14 = a1 / r11; a12 = a15 / 2; var r15 = a7 / r8; var r16 = 2 / r8; var r17 = 9 | r15; print(r1); var r18 = r2 % a10; var r19 = x ^ 5; a0 = r9 - r4; r10 = 1 % 7; var r20 = 4 / a8; var r21 = r20 / a10; var r22 = a1 + a7; r22 = 0 - a16; print(r9); var r23 = 4 | 1; var r24 = r2 | a13; var r25 = 7 - 1; var r26 = r0 ^ r18; var r27 = r22 % r7; r8 = r22 * r10; var r28 = a16 / 3; var r29 = a2 - a0; var r30 = 6 * r2; var r31 = 4 - r9; a11 = r28 & a6; r23 = 8 % 5; var r32 = r11 & r21; var r33 = 5 & r7; var r34 = r2 ^ r31; var r35 = 4 * r8; var r36 = a2 ^ r32; var r37 = r11 & 9; var r38 = r18 + r23; var r39 = r27 * 7; var r40 = a9 ^ 7; var r41 = 8 ^ r6; var r42 = 8 - 5; print(a10); r34 = r2 % 5; var r43 = r24 | 7; var r44 = 8 * r1; var r45 = a7 - r44; print(r16); var r46 = r35 / r34; var r47 = 6 - 5; r9 = r10 & r14; var r48 = a12 / r10; var r49 = 6 - 2; a12 = r44 / 3; r28 = 0 / r19; r47 = r12 * r31; r1 = r33 % r14; var r50 = 4 * r9; var r51 = r45 / a18; var r52 = 3 + 6; print(a15); var r53 = r33 ^ 3; a1 = r41 + 4; var r54 = r46 * r45; r26 = 9 / 1; var r55 = a0 * r7; var r56 = r44 - r28; a8 = r6 | a1; var r57 = r35 - a5; var r58 = 2 % 4; var r59 = r47 & r52; var r60 = a2 ^ 3; var r61 = r54 + r30; var r62 = 9 / r40; a12 = a6 / r3; var r63 = r32 ^ r55; var r64 = r8 - r55; var r65 = a13 / r52; var r66 = r8 + r14; var r67 = 9 / r36; var r68 = a2 & 0; a5 = r44 | 2; var r69 = 8 + a10; var r70 = r10 % 2; var r71 = 1 | 2; var r72 = a16 * a7; var r73 = r41 + r60; a13 = 9 % a15; var r74 = 5 | r45; var r75 = r19 % r7; var r76 = 5 & r31; var r77 = 0 & r25; var r78 = 7 % 3; r47 = r20 % r44; var r79 = 3 + 4; var r80 = 5 - r13; var r81 = r52 ^ r45; var r82 = 6 / 3; var r83 = r51 % r23; var r84 = 7 + r50; var r85 = 8 - r19; var r86 = r74 * r26; var r87 = r66 - r51; var r88 = r82 - 1; var r89 = r70 + a7; var r90 = x * 5; r29 = r31 ^ r43; print(r52); var r91 = r64 % r9; var r92 = r30 / 4; r91 = 7 & 4; var r93 = 5 % 3; var r94 = a13 / r72; var r95 = r23 / r43; var r96 = a4 | r26; var r97 = a2 | r75; var r98 = a17 * 3; var r99 = r11 ^ r82; var r100 = 2 + r86; var r101 = 9 % 6; var r102 = r71 ^ r60; var r103 = 7 & r2; var r104 = 9 | r81; var r105 = r39 / a12; var r106 = r78 & r0; var r107 = a10 % r36; print(r20); r49 = r19 | a8; var r108 = r43 - r42; var r109 = a12 & r29; var r110 = r49 % r3; a2 = a4 & 9; var r111 = 7 * r63; var r112 = 1 / 3; var r113 = 6 * r73; print(r67); var r114 = r16 + r95; print(a13); var r115 = r14 | 2; var r116 = 7 / r87; var r117 = r47 & r102; print(r80); print(a8); var r118 = r25 * r87; var r119 = 4 / 4; var r120 = a9 | r25; r16 = r119 + 0; var r121 = 2 + r46; var r122 = r107 - 0; r82 = r50 * r59; print(r104); r114 = 2 - 7; var r123 = r119 - r8; var r124 = r40 / 2; return x; }), (function(y) { return this.__defineGetter__(\"eval\", Math.tan) != (NaN = [[1]]).valueOf(\"number\") }((void options('strict_mode')), (4277))), f0]);");
/*fuzzSeed-211892750*/count=35; tryItOut("mathy0 = (function(x, y) { return Math.fround(( - Math.fround((Math.cosh(y) / (Math.log1p(((Math.fround(( ~ (y | 0))) ? (y | 0) : x) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-211892750*/count=36; tryItOut("this.f2(a1);");
/*fuzzSeed-211892750*/count=37; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var atan = stdlib.Math.atan;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      i0 = ((((0xfffff*((0x62e6eada) > (0x23a1284))) >> ((0xf8d1140a)-(i0))) >= (((i2))|0)) ? (0xb342bcad) : ((0x881e3bae)));\n    }\n    i2 = (0xffffffff);\n    i0 = (i2);\n    return (((i2)+(i2)-((0x52ced3d2) == (0x8f5777a9))))|0;\n    i0 = (/*FFI*/ff(((~~(8796093022209.0))), ((+/*FFI*/ff((9), ((d1)), ((imul((0xfe850626), ((((-0x8000000))>>>((0xe584dd46))) > (((0xe335ccf9))>>>((0xf6e04f20)))))|0)), ((-67108865.0)), ((((x)) << ((0x24872000) / (0x6ffcf62f)))), ((~~(((8589934593.0)) * ((1.888946593147858e+22)))))))), ((d1)))|0);\n    return ((((/*FFI*/ff(((((0x3e91b92d)+((0x8d19d953) ? (0xfa623a29) : (-0x8000000))-((Float64ArrayView[2]))) ^ (-0xd8e5f*(i0)))), ((+(0x5889af27))), ((((0xffffffff)*0x75d9a) & ((0xfbae2352)-(0xcd4ddede)))), ((+(0xa95c88ff))), ((+atan(((-3.8685626227668134e+25))))), ((4611686018427388000.0)), ((9223372036854776000.0)), ((68719476735.0)))|0) ? ((~(((i0) ? ((0xd895ef2)) : ((0xcf888337) >= (0x82bc236c)))))) : (i2))-(i2)))|0;\n  }\n  return f; })(this, {ff: \"\\u15D6\".unwatch(\"__iterator__\")}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, -(2**53+2), Number.MAX_VALUE, 0x100000000, 0, 0x080000001, -0x0ffffffff, 0x100000001, 1/0, 0x07fffffff, 2**53-2, -1/0, -0x080000000, -0x100000000, -0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, -0, -(2**53), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1, 2**53, 0/0]); ");
/*fuzzSeed-211892750*/count=38; tryItOut("m2 + p1;");
/*fuzzSeed-211892750*/count=39; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - (( + ( + ( - ( + Math.imul(((0x080000001 >>> 0) + (y >>> 0)), Math.fround(x)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 1, Math.PI, -1/0, 0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, -0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), 0x080000000, 0x100000001, Number.MIN_VALUE, -0x100000001, -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 42, 2**53+2, 2**53, 0x0ffffffff, 1.7976931348623157e308, -(2**53)]); ");
/*fuzzSeed-211892750*/count=40; tryItOut("\"use strict\"; print([,,]);");
/*fuzzSeed-211892750*/count=41; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return (( ! (Math.imul(Math.fround(( - ( ~ (Math.log10(Math.log2(Number.MAX_VALUE)) | 0)))), Math.fround(( ~ x))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000000, 0x07fffffff, -(2**53-2), Number.MAX_VALUE, 2**53, Math.PI, -(2**53), 2**53+2, -Number.MAX_VALUE, -0, Number.MIN_VALUE, 0x100000000, -0x0ffffffff, -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 0, 1, 0/0, -(2**53+2), 2**53-2, -0x080000000, 0x080000000, 0x0ffffffff, -0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 42, -1/0]); ");
/*fuzzSeed-211892750*/count=42; tryItOut("");
/*fuzzSeed-211892750*/count=43; tryItOut("v2 = g0.eval(\"function f1(a1)  { \\\"use strict\\\"; return (4277).eval(\\\"for (var p in g0.b1) { try { a2.push(new 28(new RegExp(\\\\\\\"(?!(((?=([^\\\\\\\\\\\\\\\\\\\\\\\\u3056-\\\\\\\\u773d\\\\\\\\u00d1\\\\\\\\u9d24])\\\\\\\\\\\\\\\\b))))?\\\\\\\", \\\\\\\"gy\\\\\\\")), g0); } catch(e0) { } v0 = (g0 instanceof this.b1); }\\\") } \");");
/*fuzzSeed-211892750*/count=44; tryItOut("testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, -1/0, -0x080000000, 1/0, 2**53+2, -0x100000000, 1, -0x07fffffff, 2**53, 0x080000001, 42, 0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, 0x100000001, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff, Math.PI, 0/0, 2**53-2, 0x07fffffff, -(2**53-2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-211892750*/count=45; tryItOut("Array.prototype.pop.apply(a2, [x instanceof x]);");
/*fuzzSeed-211892750*/count=46; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 9007199254740992.0;\n    i0 = (0x1e9e6029);\n    return (((i1)))|0;\n    (Uint8ArrayView[4096]) = ((i0));\n    i0 = (i0);\n    return ((((((0x982652c9)-(i2)-(0x1264e58b))|0))+(i0)+(i0)))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy0, ['0', NaN, null, false, '/0/', /0/, 0, -0, [], (new String('')), ({toString:function(){return '0';}}), (new Boolean(true)), undefined, ({valueOf:function(){return 0;}}), [0], '', '\\0', (new Number(-0)), (new Boolean(false)), true, (function(){return 0;}), 1, 0.1, ({valueOf:function(){return '0';}}), (new Number(0)), objectEmulatingUndefined()]); ");
/*fuzzSeed-211892750*/count=47; tryItOut("mathy1 = (function(x, y) { return mathy0((Math.fround(Math.pow((( ~ Math.min(( + 0x100000000), ( + ( + Math.pow(Math.pow(y, y), (Math.min((( ~ (x >>> 0)) >>> 0), Math.pow(y, y)) >>> 0)))))) | 0), Math.fround((x && ((((Math.pow(Math.fround(y), Math.fround(Math.imul(( + x), (Math.log10(Math.fround(Number.MAX_SAFE_INTEGER)) | 0)))) >>> 0) >>> 0) != ((mathy0(( ~ Math.log(y)), (-Number.MAX_VALUE >>> 0)) >>> 0) >>> 0)) >>> 0))))) >>> 0), ((Math.hypot(((( + ((y < (-0x0ffffffff | 0)) | 0)) * ((((y | 0) % x) | 0) >>> 0)) >>> 0), (x < Math.fround(Math.tan((Math.hypot(( + (-0x0ffffffff < ( + -0x080000000))), ( + (( + y) ? ( + y) : ( + x)))) >>> 0))))) | 0) ? (((Math.cbrt(Math.acosh(y)) >>> 0) % (Math.abs(-0x080000000) | 0)) >>> 0) : ( - Math.min(Math.abs((Math.atan2(x, y) & ( + mathy0(( + x), ( + Number.MAX_VALUE))))), (( ! (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), -0x100000001, 1, -Number.MAX_VALUE, -0x100000000, 2**53, 0x080000001, 0x07fffffff, Number.MAX_VALUE, -0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x0ffffffff, 0/0, 0, -1/0, Math.PI, 0.000000000000001, -(2**53-2), 2**53+2, 1/0, 42, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=48; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (mathy1(((Math.fround(Math.atanh(Math.fround(1.7976931348623157e308))) | 0) <= Math.max(((y | 0) ? x : 0.000000000000001), Number.MIN_SAFE_INTEGER)), (( ! (Math.fround(mathy3(Math.fround(x), Math.fround(Math.fround(Math.round(Math.fround(( ! y))))))) >>> 0)) >>> 0)) != -27); }); testMathyFunction(mathy4, [(new Number(-0)), '0', null, ({valueOf:function(){return 0;}}), (new Boolean(false)), [0], undefined, (new Number(0)), '/0/', NaN, ({toString:function(){return '0';}}), '\\0', [], ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '', 0, /0/, false, 0.1, 1, (new Boolean(true)), -0, (function(){return 0;}), (new String('')), true]); ");
/*fuzzSeed-211892750*/count=49; tryItOut("f1.valueOf = f1;");
/*fuzzSeed-211892750*/count=50; tryItOut("mathy0 = (function(x, y) { return y = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: (function(q) { return q; }).call, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: d =>  { \"use strict\"; print(x); } , iterate: function() { return (function() { throw StopIteration; }); }, enumerate: x, keys: function() { return []; }, }; })(-23), (\u3056 === NaN)); }); ");
/*fuzzSeed-211892750*/count=51; tryItOut("v0 = Object.prototype.isPrototypeOf.call(b0, g2.g1);");
/*fuzzSeed-211892750*/count=52; tryItOut("\"use strict\"; t0[({valueOf: function() { /*bLoop*/for (let gyogqu = 0; gyogqu < 45; ++gyogqu) { if (gyogqu % 65 == 46) { m0.__proto__ = e2; } else { s0 += s0;function d()/.{4,6}/imprint(x); }  } return 10; }})];");
/*fuzzSeed-211892750*/count=53; tryItOut("mathy2 = (function(x, y) { return ( + Math.tan(( + 0x0ffffffff))); }); testMathyFunction(mathy2, [-0, -0x100000000, 0x0ffffffff, -0x100000001, -0x0ffffffff, 0x100000000, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, 0x07fffffff, 2**53-2, -(2**53), 2**53, 2**53+2, 42, -Number.MIN_VALUE, -0x080000000, -1/0, 0, Math.PI, 0x080000001, 1/0, 0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 0/0, 1.7976931348623157e308, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=54; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x100000001, -0x0ffffffff, Number.MAX_VALUE, -0x080000000, 0x080000000, -0x100000001, -0x080000001, 0.000000000000001, -(2**53+2), 0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, 0/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 1/0, -1/0, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, -(2**53-2), 2**53-2, -Number.MAX_VALUE, 2**53, -0x07fffffff, 1, -(2**53), 1.7976931348623157e308, 42, -0x100000000, 2**53+2]); ");
/*fuzzSeed-211892750*/count=55; tryItOut("Array.prototype.pop.apply(a2, [p0]);");
/*fuzzSeed-211892750*/count=56; tryItOut("\"use strict\"; f2.valueOf = (function mcc_() { var mtjblh = 0; return function() { ++mtjblh; if (/*ICCD*/mtjblh % 7 == 5) { dumpln('hit!'); try { t1[0] = g2.h1; } catch(e0) { } try { v2 = r2.global; } catch(e1) { } const v1 = evaluate(\"/* no regression tests found */\", ({ global: this.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 7 != 2), noScriptRval: false, sourceIsLazy: false, catchTermination: true })); } else { dumpln('miss!'); try { o0 = Object.create(p0); } catch(e0) { } try { o2 = g1.t0[13]; } catch(e1) { } for (var p in p1) { try { b0 + ''; } catch(e0) { } try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = fillShellSandbox(newGlobal({ sameZoneAs: /\\w|.|\\n|[^]{3,5}|((?=(?=^)))+|\\1?*/, cloneSingletons: false, disableLazyParsing:  /x/g () })); f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e1) { } try { v2 = null; } catch(e2) { } v2 = (o1.p0 instanceof t2); } } };})();");
/*fuzzSeed-211892750*/count=57; tryItOut(";");
/*fuzzSeed-211892750*/count=58; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s1; print(s.match(r)); ");
/*fuzzSeed-211892750*/count=59; tryItOut("g0.g0.f2 + '';");
/*fuzzSeed-211892750*/count=60; tryItOut("(((function(x, y) { return (( + (y | 0)) | 0); })));");
/*fuzzSeed-211892750*/count=61; tryItOut("/*vLoop*/for (cohbup = 0, {} = undefined, w - delete; cohbup < 54; ++cohbup) { let z = cohbup; print(/*UUV1*/(\u3056.setUTCSeconds = offThreadCompileScript)); } ");
/*fuzzSeed-211892750*/count=62; tryItOut("v1 = r0.multiline;");
/*fuzzSeed-211892750*/count=63; tryItOut("\"use asm\"; /*infloop*/for(let (void shapeOf(x)) in (((let (e=eval) e))(e < x)))b0.toString = (function mcc_() { var vledfx = 0; return function() { ++vledfx; if (/*ICCD*/vledfx % 3 == 1) { dumpln('hit!'); try { g2.m2.toSource = (function() { try { v0 = Object.prototype.isPrototypeOf.call(s1, g2); } catch(e0) { } try { v0 = evalcx(\"function f2(h0) b\", g1); } catch(e1) { } v1 = g0.runOffThreadScript(); return o2.f1; }); } catch(e0) { } v2 = g2.eval(\"/* no regression tests found */\"); } else { dumpln('miss!'); try { /*ODP-3*/Object.defineProperty(i1, \"for\", { configurable: \"\\u5F81\", enumerable: true, writable: false, value: a1 }); } catch(e0) { } o0 + b2; } };})();");
/*fuzzSeed-211892750*/count=64; tryItOut("\"\\uA25A\";");
/*fuzzSeed-211892750*/count=65; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((mathy0(Math.fround((Math.fround((((x >= x) ** x) != ( + y))) ** Math.fround((mathy2(Math.fround(y), ( + x)) | (mathy2((2**53 >>> 0), ((x <= Math.PI) | 0)) >>> 0))))), ( + (x != Math.cosh(x)))) | 0) !== (( ! ( ~ Math.fround(( ! Math.fround(x))))) | 0)) | 0); }); testMathyFunction(mathy3, [-0x07fffffff, 1/0, 0x080000001, -Number.MAX_VALUE, -0x100000001, -(2**53+2), 2**53-2, -0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, 2**53+2, 0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53), 0/0, 2**53, Math.PI, -(2**53-2), -1/0, Number.MAX_VALUE, -0x100000000, -0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, -0x080000000, -0x080000001, 0x07fffffff, 1, -Number.MIN_VALUE, 0x080000000, 42]); ");
/*fuzzSeed-211892750*/count=66; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\2)\", \"gyi\"); var s = \"\\na\\n1a\"; print(r.exec(s)); ");
/*fuzzSeed-211892750*/count=67; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = ((~~(2.0)));\n    return +((x[\"__count__\"]) = x);\n  }\n  return f; })(this, {ff: DataView.prototype.setUint8}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x080000001, -1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, 1/0, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -0, 0, 1.7976931348623157e308, -0x100000001, 2**53+2, 1, 42, -Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, 0x07fffffff, 2**53, Math.PI, 0x100000000, -(2**53), -0x080000000, 0x100000001, 0x080000000, 0/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=68; tryItOut("a0.forEach(f0, ((yield window)));");
/*fuzzSeed-211892750*/count=69; tryItOut("s1 += this.s2;");
/*fuzzSeed-211892750*/count=70; tryItOut("f1(o1);");
/*fuzzSeed-211892750*/count=71; tryItOut("/*bLoop*/for (let jtgnbn = 0; jtgnbn < 114; ++jtgnbn) { if (jtgnbn % 4 == 1) { p2 + o2; } else { o2.v0 = undefined\nconst v2 = a1.some((function(j) { if (j) { try { this.a0.splice(NaN, 11); } catch(e0) { } try { /*MXX2*/g0.ArrayBuffer.prototype.slice = h1; } catch(e1) { } try { s2 += 'x'; } catch(e2) { } i0.next(); } else { try { o0.toString = (function() { for (var j=0;j<166;++j) { f0(j%2==1); } }); } catch(e0) { } try { s2 += s2; } catch(e1) { } try { s2 += s0; } catch(e2) { } v1 = evalcx(\"print(b0);\", o2.g1); } })); }  } ");
/*fuzzSeed-211892750*/count=72; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-211892750*/count=73; tryItOut("Array.prototype.reverse.apply(a2, []);");
/*fuzzSeed-211892750*/count=74; tryItOut("/*hhh*/function tydjvd(c = RangeError(timeout(1800)), w = [[1]]){(x);}tydjvd();");
/*fuzzSeed-211892750*/count=75; tryItOut("let(uiabch, \u3056) { throw StopIteration;}");
/*fuzzSeed-211892750*/count=76; tryItOut("this.m2.delete(t1);");
/*fuzzSeed-211892750*/count=77; tryItOut("h2.__proto__ = m2;");
/*fuzzSeed-211892750*/count=78; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((Math.sin(( + ( + ( - y)))) + Math.trunc(Math.fround(mathy0(-Number.MIN_VALUE, (Math.atan(42) ? y : ( + mathy0(Math.fround(( - 0x07fffffff)), ( + x)))))))) >>> 0) > ( + Math.atan(( + ((Math.fround((Math.fround(((x >>> 0) == ( - y))) >> ( ~ (((x >>> 0) , (y >>> 0)) >>> 0)))) - Math.cbrt((x , x))) | 0))))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), null ** (4277), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x]); ");
/*fuzzSeed-211892750*/count=79; tryItOut("\"use strict\"; o2.v0 = evalcx(\"/* no regression tests found */\", o0.g0);");
/*fuzzSeed-211892750*/count=80; tryItOut("v2 = Object.prototype.isPrototypeOf.call(b2, g2);");
/*fuzzSeed-211892750*/count=81; tryItOut("/*MXX3*/g0.Object.isSealed = g1.Object.isSealed;");
/*fuzzSeed-211892750*/count=82; tryItOut("a1 = /*FARR*/[let (x = Boolean()) (yield (\u3056 >= window)), ([new RegExp(\"\\\\w|[^]\\\\d+[^]|\\\\u001E+|(?=[^]|(?:\\u00b7))\", \"y\")].prototype), , .../*FARR*/[...function(q) { return q; }], ];");
/*fuzzSeed-211892750*/count=83; tryItOut("mathy0 = (function(x, y) { return ( + ((((( + (( + ( + Math.imul(( + (x ? y : Math.fround(Math.fround((y >>> 0))))), ( + Math.imul(y, (((y | 0) ^ Math.fround(x)) >>> 0)))))) >> ( + y))) + (Math.fround(Math.sin(( ! (y >>> 0)))) >>> 0)) >>> 0) >>> 0) + ( + Math.min(( + (Math.fround(Math.round(( + ( ! Math.acosh(x))))) || (( + Math.imul(( + x), ( + Math.min(y, y)))) ? y : ( ! ( ~ ((y ? y : Number.MIN_VALUE) | 0)))))), ( ~ (Math.log2(((0/0 | 0) ? y : x)) | 0)))))); }); testMathyFunction(mathy0, [2**53, 0x080000000, -Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -0x0ffffffff, 2**53-2, -(2**53-2), Math.PI, -1/0, 42, -0x100000001, 2**53+2, Number.MAX_VALUE, 0/0, -0, -Number.MIN_VALUE, -0x100000000, 0, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 0x080000001, 1/0, 0.000000000000001, -(2**53+2), -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 0x100000001, -0x080000001]); ");
/*fuzzSeed-211892750*/count=84; tryItOut("testMathyFunction(mathy4, [(new Number(0)), null, objectEmulatingUndefined(), (new String('')), (new Boolean(true)), [], 1, true, /0/, 0.1, ({valueOf:function(){return '0';}}), 0, [0], (new Number(-0)), '\\0', false, ({toString:function(){return '0';}}), NaN, (new Boolean(false)), '', -0, ({valueOf:function(){return 0;}}), undefined, '/0/', '0', (function(){return 0;})]); ");
/*fuzzSeed-211892750*/count=85; tryItOut("a1 + '';");
/*fuzzSeed-211892750*/count=86; tryItOut("mathy2 = (function(x, y) { return Math.min(((((0x100000001 + Math.fround(( + Math.hypot(( + x), ( + -Number.MAX_VALUE))))) >>> 0) == (( ! (Math.expm1((x | 0)) | 0)) >>> 0)) >>> 0), (( + Math.fround(( + ( ! ( + ( + ( + ( + (y && x))))))))) >>> 0)); }); testMathyFunction(mathy2, [-(2**53), 0, -(2**53+2), 0x0ffffffff, -0x100000001, Math.PI, -0, -0x080000000, 2**53, 1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 2**53+2, -0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -1/0, 0x100000001, -0x0ffffffff, 2**53-2, Number.MAX_VALUE, -0x07fffffff, -0x080000001, 0/0]); ");
/*fuzzSeed-211892750*/count=87; tryItOut("v2 = evaluate(\"x =  /x/g , b, x, \\u3056, z;this.v1 = evalcx(\\\"/* no regression tests found */\\\", g1);{ if (!isAsmJSCompilationAvailable()) { void 0; try { startgc(281197065); } catch(e) { } } void 0; }\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 105 != 33), sourceIsLazy: (x % 42 != 26), catchTermination: true }));");
/*fuzzSeed-211892750*/count=88; tryItOut("if((void shapeOf(Math.min((makeFinalizeObserver('nursery')), -15)))) { if (\"\\uE432\") {print((NaN !== c));print( /* Comment */allocationMarker().yoyo((/*UUV2*/(x.toString = x.log10)))\u000c); } else {t2[v2];\nf0 + '';\n }}");
/*fuzzSeed-211892750*/count=89; tryItOut("/*RXUB*/var r = new RegExp(\"(?=([^]){4,}(?:(?=.)){1,2}|[\\u762a\\\\u00eE])\", \"y\"); var s = \"\\n\\n\\n\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-211892750*/count=90; tryItOut("\"use strict\"; /*iii*/m2 + '';/*hhh*/function xcuqxk(...c){(\"\\u1C6B\");Array.prototype.forEach.call(a0, (function() { try { this.a2.toString = (function(j) { f1(j); }); } catch(e0) { } print(\"\\u5536\"); return t0; }), p1, /\\b(?=[^])|\\d|\\d{268435455,}(?:\\D)|[^]+?/gyim, m2, a1);}");
/*fuzzSeed-211892750*/count=91; tryItOut("/*tLoop*/for (let y of /*MARR*/[(void 0), (void 0), -0x100000001, -0x100000001,  /x/g , new Boolean(false), (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (void 0), new Boolean(false), -0x100000001, new Boolean(false),  /x/g ,  /x/g , (void 0), (void 0), (void 0),  /x/g , -0x100000001, (void 0),  /x/g ,  /x/g , new Boolean(false),  /x/g , new Boolean(false), -0x100000001, (void 0), (void 0), -0x100000001, (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0),  /x/g ,  /x/g , -0x100000001, new Boolean(false),  /x/g , new Boolean(false),  /x/g , -0x100000001, new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0),  /x/g ,  /x/g , (void 0), -0x100000001, -0x100000001, new Boolean(false), -0x100000001, -0x100000001, new Boolean(false), -0x100000001,  /x/g , (void 0),  /x/g , -0x100000001, new Boolean(false),  /x/g , -0x100000001, -0x100000001, (void 0),  /x/g ,  /x/g ,  /x/g , new Boolean(false), new Boolean(false), (void 0), -0x100000001, -0x100000001, new Boolean(false), -0x100000001, new Boolean(false),  /x/g , new Boolean(false),  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -0x100000001, -0x100000001, (void 0), -0x100000001, (void 0), (void 0), new Boolean(false),  /x/g ,  /x/g , (void 0), (void 0), new Boolean(false),  /x/g , -0x100000001,  /x/g , new Boolean(false),  /x/g ,  /x/g , -0x100000001, (void 0),  /x/g , -0x100000001,  /x/g , new Boolean(false), -0x100000001, new Boolean(false),  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), -0x100000001,  /x/g , -0x100000001, (void 0), -0x100000001, -0x100000001, (void 0), -0x100000001, (void 0), (void 0), -0x100000001, new Boolean(false), -0x100000001, new Boolean(false), (void 0),  /x/g , (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false),  /x/g , (void 0), (void 0), new Boolean(false), new Boolean(false), -0x100000001, new Boolean(false),  /x/g , new Boolean(false), (void 0), (void 0), -0x100000001, (void 0),  /x/g , new Boolean(false)]) { print(y); }");
/*fuzzSeed-211892750*/count=92; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=93; tryItOut("/*bLoop*/for (let ynwcto = 0; ynwcto < 35 && ((4277)); ++ynwcto) { if (ynwcto % 27 == 20) { for (var p in e0) { try { g2.offThreadCompileScript(\"print(x);\"); } catch(e0) { } try { m1.set(f1, v2); } catch(e1) { } try { Object.defineProperty(o2, \"v2\", { configurable: /(\\b|(?!\\b)\\2|\\uFb88+)/yi, enumerable: \"\\uE5A5\",  get: function() {  return a2.reduce, reduceRight((function(j) { if (j) { try { o0.e1.has(m1); } catch(e0) { } s1 += 'x'; } else { try { e0 = new Set; } catch(e0) { } try { Array.prototype.reverse.call(a0, g2.t0, o1.e2); } catch(e1) { } Object.prototype.watch.call(f2, \"toString\", (function(a0, a1, a2, a3, a4, a5, a6, a7) { var r0 = a3 * a3; var r1 = a5 - a7; var r2 = a3 + a1; var r3 = 2 + 3; var r4 = 1 / a4; var r5 = r4 ^ a6; var r6 = r4 ^ r3; print(a3); var r7 = 4 & a2; print(r5); var r8 = r6 - r6; var r9 = 4 & a5; var r10 = a1 % 3; var r11 = r9 + a7; a6 = 0 ^ 1; var r12 = a2 - r6; r7 = r1 - a2; var r13 = r4 % 3; var r14 = 4 % a2; var r15 = r7 - r0; print(r0); a1 = a7 / 8; var r16 = a0 | r8; a4 = 5 ^ a4; var r17 = 2 / r1; var r18 = 8 / 2; var r19 = r13 % 4; var r20 = r17 - a3; var r21 = r7 % r6; var r22 = 8 / r5; var r23 = r11 - x; var r24 = r9 / 7; var r25 = a6 | x; r11 = 6 % a3; var r26 = a3 / a7; r23 = r11 | 6; print(a5); var r27 = a5 - r15; var r28 = 5 + 9; var r29 = 6 + 6; var r30 = r27 + r29; var r31 = 9 - r29; var r32 = 1 % x; var r33 = a2 % 2; var r34 = 6 ^ 3; var r35 = r15 + r9; r32 = r33 ^ 2; r4 = 6 ^ a7; a1 = r12 & a0; var r36 = r6 | 6; var r37 = 9 * 2; var r38 = r34 / r34; var r39 = r16 % a0; var r40 = 3 % x; r22 = 1 & r29; var r41 = r1 - r34; var r42 = 1 ^ 2; var r43 = 9 | r12; r5 = 9 ^ r27; var r44 = r15 / 3; var r45 = r2 - 7; print(r0); var r46 = r27 ^ r35; var r47 = r32 + 6; var r48 = r47 | 8; var r49 = r4 - r4; r13 = r35 + r19; r23 = 3 / a7; r32 = a7 / r34; var r50 = 7 % r18; var r51 = r41 % r28; var r52 = a5 - r3; r24 = 1 + r48; var r53 = 5 % 3; r28 = r46 + r20; var r54 = r52 % 4; var r55 = r53 | 1; var r56 = 4 - 8; a7 = 4 - r53; var r57 = 0 * r43; var r58 = r25 & r54; var r59 = 0 + 8; var r60 = r38 * 4; var r61 = r55 + r22; var r62 = r45 | r28; var r63 = r44 ^ a1; var r64 = r52 / r61; var r65 = 6 % 8; return a0; })); } })); } }); } catch(e2) { } f0 = (function(j) { f2(j); }); } } else { with({c: 25.unwatch(\"valueOf\")})g0.offThreadCompileScript(\"o0.g1.a0.length = ({valueOf: function() { Array.prototype.unshift.apply(a2, [null]);return 12; }});\"); }  } ");
/*fuzzSeed-211892750*/count=94; tryItOut("\"use strict\"; /*bLoop*/for (let gpwlaa = 0, pytmsc; ( \"use strict\" ) && gpwlaa < 44; ++gpwlaa) { if (gpwlaa % 11 == 4) { /*infloop*/do  \"\" ; while(d); } else { /*RXUB*/var r = /^\\u50d8|\\2{1,}|(?:(?:(\\n){1,}+?))/i; var s = \"\\u0094\"; print(uneval(r.exec(s)));  }  } ");
/*fuzzSeed-211892750*/count=95; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -576460752303423500.0;\n    i0 = (i1);\n    d2 = (d2);\n    switch (((-0xfffff*((Float64ArrayView[1]))) >> ((0xffffffff)-(-0x8000000)-(0x5197c8ef)))) {\n      case -2:\n        d2 = (d2);\n        break;\n      default:\n        {\n          i1 = (0xa38e78c8);\n        }\n    }\n    return +((+/*FFI*/ff(((15.0)), ((+(1.0/0.0))), ((((590295810358705700000.0)) * ((268435457.0)))), ((-1.03125)), ((-0x8000000)), ((0.03125)), (((((-0x8000000) / (0x7f5532d6))) ^ (((0xb302a037))))), ((((0x7f51e602)) << ((0xb866c141)))), ( /x/g ))));\n  }\n  return f; })(this, {ff: function(y) { return (\"\\uC081\" instanceof y = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"\\\\2\", \"\")),  '' ,  /x/ )) }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-211892750*/count=96; tryItOut("this.i0.send(b0);");
/*fuzzSeed-211892750*/count=97; tryItOut(";");
/*fuzzSeed-211892750*/count=98; tryItOut("mathy0 = (function(x, y) { return Math.fround((( - ( ! (Math.max((Math.fround((Math.fround(( ! Number.MAX_SAFE_INTEGER)) * Math.fround(x))) | 0), (x | 0)) | 0))) | (Math.fround(Math.sin((((x && (2**53 >>> 0)) >>> 0) == (x >>> 0)))) | ((-1/0 % (y == (y === Math.cosh(x)))) | 0)))); }); testMathyFunction(mathy0, [-0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), Math.PI, 0x080000000, 1, 0, -0, 2**53+2, 0x100000000, -0x100000001, -1/0, -0x0ffffffff, 0x100000001, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 42, 0/0, 1.7976931348623157e308, -0x080000001, 2**53, -(2**53-2), 0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-211892750*/count=99; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-211892750*/count=100; tryItOut("mathy0 = (function(x, y) { return Math.atan((Math.atan2((Math.fround(Math.hypot(Math.expm1((y ^ Math.tan(0x080000000))), Math.fround((0.000000000000001 ? -0x0ffffffff : y)))) | 0), (( - x) * ((Number.MIN_VALUE >>> 0) | x))) < Math.fround(( - Math.acos(Math.atan2(x, (y | 0))))))); }); testMathyFunction(mathy0, [0x07fffffff, 0.000000000000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), Number.MIN_VALUE, -0x080000001, 1/0, 0x080000000, 0, 0x100000000, 1, Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -0, -0x080000000, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, 0/0, 0x0ffffffff, -(2**53+2), -0x100000000, 42, -Number.MAX_VALUE, 0x080000001, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-211892750*/count=101; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=102; tryItOut("mathy0 = (function(x, y) { return (Math.min(( ! Math.asinh(Math.fround(Math.sin((Math.hypot(-0x0ffffffff, x) >>> 0))))), ( ~ ((x === (Math.cosh(Math.tanh((y % y))) | 0)) | 0))) | 0); }); testMathyFunction(mathy0, [0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 0.000000000000001, 0/0, Math.PI, -1/0, 0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000000, -0, 42, 2**53, 2**53+2, -0x080000001, -(2**53), 1, -(2**53-2), 0x0ffffffff, -Number.MIN_VALUE, 0x080000000, -0x100000000, 0x100000001, Number.MAX_VALUE, 2**53-2, 1/0, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-211892750*/count=103; tryItOut("\"use strict\"; /*infloop*/while((({\"-18\": ({} = (this > Math)), /*toXFun*/valueOf: function() { return this; } })))(void version(185));");
/*fuzzSeed-211892750*/count=104; tryItOut("\"use strict\"; s1 += s1;");
/*fuzzSeed-211892750*/count=105; tryItOut("{ \"\" ;function d({}) { yield  ''  } this.v1 = (g1.a1 instanceof p1);o0.a2.push(x); }");
/*fuzzSeed-211892750*/count=106; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-211892750*/count=107; tryItOut("\"use strict\"; v0 = (b1 instanceof a2);");
/*fuzzSeed-211892750*/count=108; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -513.0;\n    return +((++\u3056 >= x = Proxy.createFunction(({/*TOODEEP*/})(11), offThreadCompileScript, [[]])));\n  }\n  return f; })(this, {ff: WebAssemblyMemoryMode}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[0x080000001]); ");
/*fuzzSeed-211892750*/count=109; tryItOut("this.a1.shift();");
/*fuzzSeed-211892750*/count=110; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + (mathy0((Math.fround((Math.fround(Math.atanh(Math.round(y))) ? Math.fround(x) : Math.max(y, y))) | 0), (x | 0)) | 0)) % ((((mathy0((x | 0), (Math.fround(Math.sqrt(Math.fround(Math.fround(( ! y))))) | 0)) | 0) < (( ! x) >>> 0)) || ((Math.log1p((((Math.fround(((mathy0((((0x080000000 | 0) ? (x | 0) : (x | 0)) | 0), x) >>> 0) === (( + -0x080000001) ? x : Math.fround(Math.min(Math.fround(x), x))))) < x) >>> 0) >>> 0)) >>> 0) | 0)) | 0)); }); ");
/*fuzzSeed-211892750*/count=111; tryItOut("mathy3 = (function(x, y) { return mathy2((( + ( + ( + ( + ( ! (Math.sinh(Math.fround(x)) >>> 0)))))) * (Math.hypot((( + (( + -0x100000001) , ( + mathy1(Math.fround(Math.fround(( - Math.fround(0x080000000)))), Math.fround(y))))) >>> 0), ((x , 1) >>> 0)) >>> 0)), ((mathy0(x, ( + Math.max(( + mathy1(0/0, Math.sinh(( + (( ! x) | 0))))), ( + Math.atan2(x, (Math.atan2(x, ( + ( ! ( + x)))) >>> 0)))))) >>> 0) ? ( + Math.acosh(( + Math.abs(y)))) : Math.trunc(( ~ -(2**53-2))))); }); ");
/*fuzzSeed-211892750*/count=112; tryItOut("function shapeyConstructor(vnyugy){Object.freeze(vnyugy);delete vnyugy[\"preventExtensions\"];vnyugy[\"isNaN\"] = (intern(9));{ (this | \"\\u7319\"); } if (/*MARR*/[{}, new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), {}, objectEmulatingUndefined(), new Number(1), {}, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined()].some(Function)) for (var ytqiikisj in vnyugy) { }Object.freeze(vnyugy);delete vnyugy[-17];Object.preventExtensions(vnyugy);if (vnyugy) vnyugy[\"isNaN\"] = (0/0);vnyugy[\"isNaN\"] = (4277);return vnyugy; }/*tLoopC*/for (let e of /*PTHR*/(function() { \"use strict\"; for (var i of (function() { \"use asm\"; yield b = window; } })()) { yield i; } })()) { try{let upaqrx = new shapeyConstructor(e); print('EETT'); return;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-211892750*/count=113; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g1, v2)");
/*fuzzSeed-211892750*/count=114; tryItOut("(yield \"\\u3D45\");");
/*fuzzSeed-211892750*/count=115; tryItOut("mathy1 = (function(x, y) { return mathy0((((((( + Math.imul(false, x)) < (Math.fround((( + x) && Math.fround(y))) * mathy0(( + ( ! -(2**53+2))), ( + ( + x))))) >>> 0) == Math.fround((Math.pow(Math.fround((Math.min(x, x) <= (Math.atanh((Math.fround(Math.fround(0x100000000)) >>> 0)) >>> 0))), Math.exp((Math.fround((Math.fround(x) | Math.fround(x))) | 0))) | ( + Math.cos(0x100000000))))) >>> 0) | 0), Math.pow(Math.pow((-Number.MIN_SAFE_INTEGER / Math.fround(Math.log10(((Math.max((y | 0), ((y + -(2**53)) | 0)) | 0) | 0)))), mathy0((Math.log2(x) >>> 0), (-0 ? 0x100000001 : (mathy0(x, ( + -0x100000001)) | 0)))), (Math.atan((x | ( + (Math.max(x, x) >>> 0)))) | 0))); }); testMathyFunction(mathy1, /*MARR*/[(1/0), (-1/0), {x:3}, {x:3}, (-1/0), {x:3}, (1/0), (-1/0), (-1/0), (1/0), (-1/0), (1/0), (-1/0), {x:3}, {x:3}, (-1/0), {x:3}, (-1/0), {x:3}, {x:3}, (1/0), (-1/0), (-1/0), {x:3}, {x:3}, (-1/0), {x:3}, {x:3}, (1/0), {x:3}, (1/0), {x:3}, (-1/0), (1/0), {x:3}, (-1/0), (-1/0), (-1/0), (-1/0), {x:3}, (1/0), (-1/0), (1/0), (1/0), (1/0), (1/0), {x:3}, {x:3}, (-1/0), (-1/0), {x:3}, (-1/0), (-1/0), (-1/0), (1/0)]); ");
/*fuzzSeed-211892750*/count=116; tryItOut("/*MXX2*/g1.g0.Function.length = v0;");
/*fuzzSeed-211892750*/count=117; tryItOut("testMathyFunction(mathy2, [2**53+2, 0x080000001, 1, -(2**53-2), 42, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 0, 0x0ffffffff, Math.PI, -(2**53+2), -0x0ffffffff, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 0.000000000000001, -0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 0x080000000, -Number.MAX_VALUE, -0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0/0, 0x100000000, 1/0, -0x080000001, 0x100000001]); ");
/*fuzzSeed-211892750*/count=118; tryItOut(";");
/*fuzzSeed-211892750*/count=119; tryItOut("L: {for (var p in p1) { try { v0 = g2.a2.length; } catch(e0) { } try { v1 = a0.length; } catch(e1) { } m2 + f1; }print(x); }");
/*fuzzSeed-211892750*/count=120; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.expm1((( ~ (Math.pow(( + mathy1(( + -Number.MIN_SAFE_INTEGER), ( + x))), ((-Number.MIN_VALUE | 0) % Math.imul(( + ( - ( + y))), mathy4(y, -Number.MIN_SAFE_INTEGER)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-211892750*/count=121; tryItOut("s2 += 'x';");
/*fuzzSeed-211892750*/count=122; tryItOut("a1.sort(a1, g2.g0.t1, this.i2);");
/*fuzzSeed-211892750*/count=123; tryItOut("mathy5 = (function(x, y) { return Math.pow(( ~ (Math.fround((Math.fround(x) / ( - x))) % Math.fround(( - x)))), (Math.atan2(( + Math.imul(Math.atan(Math.fround(-0x07fffffff)), ( + -Number.MAX_VALUE))), (((Math.fround(Math.pow(((x ? x : x) >>> 0), ( + Math.fround(Math.imul(Math.fround(x), Math.fround(0x080000000)))))) | 0) * 0.000000000000001) | 0)) | 0)); }); testMathyFunction(mathy5, [0x100000000, 0/0, 0.000000000000001, 1.7976931348623157e308, 0x07fffffff, -0x0ffffffff, Math.PI, 0, -0x080000001, Number.MAX_VALUE, 2**53+2, 2**53-2, -Number.MAX_VALUE, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -0x080000000, -0x100000000, -1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53, 1, -0x07fffffff, 42, 0x0ffffffff, 0x100000001, -0x100000001, -0]); ");
/*fuzzSeed-211892750*/count=124; tryItOut("switch((neuter).call(Object.defineProperty(a, (4277), ({writable: true, configurable: (x % 3 != 0), enumerable:  /x/g })), (4277))) { case 2: switch(x + \n \"\" ) { case 8: g0.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 3 != 0), sourceIsLazy: (x % 6 != 4), catchTermination: false })); }break; break; case 9: g2.s1 + '';break; case 5: f1 = Proxy.createFunction(h2, f2, f0);(x.watch(window, (new Function(\"(window);\"))));break; return; }");
/*fuzzSeed-211892750*/count=125; tryItOut("o2.m0 + this.a1;");
/*fuzzSeed-211892750*/count=126; tryItOut("/*MXX1*/o2 = g2.g2.String.prototype.slice;");
/*fuzzSeed-211892750*/count=127; tryItOut("mathy0 = (function(x, y) { return Math.round((Math.pow(y, y) > Math.fround((Math.fround(( - Math.fround(0x100000001))) || Math.fround((( + (0x080000001 | 0)) | 0)))))); }); testMathyFunction(mathy0, /*MARR*/[[(void 0)], [(void 0)], [(void 0)], [(void 0)], (x !== \"\u03a0\" - [1]), (1/0), (1/0), 0x3FFFFFFE, (x !== \"\u03a0\" - [1]), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), 0x3FFFFFFE, 0x3FFFFFFE, [(void 0)], [(void 0)], (1/0), 0x3FFFFFFE, 0x3FFFFFFE, (1/0), [(void 0)], (1/0), [(void 0)], (x !== \"\u03a0\" - [1]), [(void 0)]]); ");
/*fuzzSeed-211892750*/count=128; tryItOut("\"use strict\"; h2.__proto__ = this.m0;");
/*fuzzSeed-211892750*/count=129; tryItOut("\"use strict\"; /*bLoop*/for (let rqrypw = 0; rqrypw < 122; ++rqrypw) { if (rqrypw % 4 == 1) { h0.has = f0; } else { print(window); }  } ");
/*fuzzSeed-211892750*/count=130; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot((( + Math.asin((Math.atan2(((( + Math.cos(y)) | 0) >>> 0), Math.fround(Math.expm1(Math.fround(((( ! (0.000000000000001 >>> 0)) >>> 0) & y))))) >>> 0))) >>> 0), ((Math.abs(Math.fround(Math.cos(Math.fround(( ~ -(2**53-2)))))) | ( - ( + (Math.max((Math.fround(( - Math.max(x, x))) ** x), Math.fround(Math.atan2(Math.fround(y), Math.fround(x)))) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x080000001, 0x100000000, -0, -Number.MAX_VALUE, 2**53-2, 1/0, 0/0, -0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53, -Number.MIN_VALUE, -1/0, -(2**53), -0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 0.000000000000001, 0x100000001, -(2**53-2), Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, 2**53+2, 0x0ffffffff, -(2**53+2), 1, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, 0x080000000, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=131; tryItOut("\"use strict\"; e0.has(x);");
/*fuzzSeed-211892750*/count=132; tryItOut("/*tLoop*/for (let z of /*MARR*/[3/0, [1], 2**53+2, null, 2**53+2, 3/0, 3/0, 2**53+2, 2**53+2, 2**53+2, 3/0, 2**53+2, 2**53+2, null, 2**53+2, [1], [1], 2**53+2, 2**53+2, [1], [1], null, [1], 3/0, 2**53+2, 3/0, 3/0, 3/0, [1], null, null, [1], null, 2**53+2, null, 3/0, null, [1], 2**53+2, null, null, 3/0, 3/0, 2**53+2, 2**53+2]) { /*tLoop*/for (let x of /*MARR*/[ '' , new Number(1.5),  '' ,  '' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), null, new Number(1.5), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, new Number(1.5), new Number(1.5),  '' , null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '' , null, null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), null, new Number(1.5), new Number(1.5),  '' ,  '' , new Number(1.5), new Number(1.5),  '' , null, null, null,  '' , new Number(1.5), null,  '' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '' ,  '' ,  '' ,  '' , null,  '' , new Number(1.5),  '' , new Number(1.5), null,  '' , new Number(1.5), new Number(1.5), null, null,  '' , null, new Number(1.5),  '' , new Number(1.5), null,  '' , null, null, new Number(1.5),  '' , null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '' ,  '' , new Number(1.5), null, null,  '' ,  '' , null,  '' ,  '' , new Number(1.5), new Number(1.5), null, new Number(1.5), null,  '' ,  '' , null,  '' ,  '' ,  '' ,  '' , null, new Number(1.5), new Number(1.5),  '' , new Number(1.5),  '' ,  '' , new Number(1.5),  '' ]) { z; } }");
/*fuzzSeed-211892750*/count=133; tryItOut("\"use strict\"; v0 = evalcx(\"m1.delete(v2);\", g2.g0);");
/*fuzzSeed-211892750*/count=134; tryItOut("h2 = ({getOwnPropertyDescriptor: function(name) { a0.valueOf = f2;; var desc = Object.getOwnPropertyDescriptor(h2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { /*RXUB*/var r = r1; var s = s1; print(s.split(r)); print(r.lastIndex); ; var desc = Object.getPropertyDescriptor(h2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { s2 += s0;; Object.defineProperty(h2, name, desc); }, getOwnPropertyNames: function() { h0.getOwnPropertyDescriptor = (function() { o0.t0 = t0.subarray(({valueOf: function() { g2.offThreadCompileScript(\"/*MXX3*/g2.Float32Array.BYTES_PER_ELEMENT = this.g1.Float32Array.BYTES_PER_ELEMENT;\");function x()\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1.888946593147858e+22;\n    var i3 = 0;\n    return (((~~(d2)) / (((i1)-(0xed3a790))|0)))|0;\n  }\n  return f;(\"\\u3F98\");return 2; }})); return g1; });; return Object.getOwnPropertyNames(h2); }, delete: function(name) { /*MXX1*/o2 = g2.String.prototype.bold;; return delete h2[name]; }, fix: function() { a2.valueOf = f0;; if (Object.isFrozen(h2)) { return Object.getOwnProperties(h2); } }, has: function(name) { o2 = g1.objectEmulatingUndefined();; return name in h2; }, hasOwn: function(name) { e0.has(m2);; return Object.prototype.hasOwnProperty.call(h2, name); }, get: function(receiver, name) { this.g1.e1 = new Set;; return h2[name]; }, set: function(receiver, name, val) { for (var p in b0) { try { e0.has(g2); } catch(e0) { } try { Object.freeze(p0); } catch(e1) { } try { e2.valueOf = (function(a0, a1, a2, a3, a4) { var r0 = a0 % 2; var r1 = r0 - a1; print(r0); var r2 = a3 ^ a2; var r3 = 0 ^ 1; var r4 = r1 / 3; var r5 = 8 & x; var r6 = 7 ^ r4; var r7 = a2 - 2; r7 = 6 | r6; var r8 = r0 & 2; r4 = r4 | a4; var r9 = a0 / r5; r6 = r6 + a1; var r10 = a0 & r7; var r11 = r8 % a1; var r12 = r9 % 1; var r13 = 2 | r0; var r14 = r2 ^ r9; print(r5); var r15 = r12 % r7; var r16 = r11 + 6; r1 = r10 ^ r5; var r17 = r8 - r8; r3 = 7 % 1; var r18 = 5 + 2; var r19 = r4 - r18; var r20 = a2 ^ a0; var r21 = a4 | 7; r3 = r11 % 0; var r22 = r19 / 5; var r23 = 6 / r0; var r24 = r4 | 2; a2 = r13 + 7; a4 = 1 % r7; var r25 = r20 % 6; var r26 = r8 / a4; var r27 = r8 ^ r22; var r28 = a2 * 6; print(r3); a2 = a2 % r22; r7 = 9 - 0; r17 = 3 & a3; var r29 = r27 & 1; var r30 = x - r21; var r31 = r10 % 3; var r32 = r29 + 5; var r33 = r7 & 1; var r34 = 3 + x; var r35 = 3 / 8; var r36 = 6 / r28; var r37 = r10 - 5; var r38 = 1 & 3; var r39 = r33 % r22; var r40 = a2 / 2; var r41 = r25 + 7; var r42 = 1 & a4; r20 = r29 & 9; r38 = 1 & r8; var r43 = r6 - r29; r32 = r33 / r9; r13 = r17 * 8; var r44 = r32 | 9; print(a2); var r45 = r15 + r33; var r46 = r14 % 9; var r47 = r12 / r11; var r48 = r38 + a3; var r49 = r12 / r9; var r50 = 1 / 5; var r51 = r21 + 8; var r52 = r11 - r48; var r53 = a2 + r50; var r54 = r16 | r23; var r55 = r26 - 2; var r56 = r4 % 7; var r57 = r29 | r17; r28 = 7 % r35; var r58 = 1 / r25; r54 = r24 ^ r55; var r59 = 3 & r43; r35 = r55 ^ 9; var r60 = 4 / r56; var r61 = 6 / r42; var r62 = r40 + r49; var r63 = r38 % 2; r9 = r23 & r10; r62 = r31 / r13; var r64 = r4 + r54; var r65 = 9 - 3; r31 = 5 | r61; var r66 = r15 & r42; var r67 = r0 + 5; var r68 = r11 - r16; r22 = r52 ^ 2; var r69 = a4 ^ r4; var r70 = 2 & 1; var r71 = r10 / r5; var r72 = r29 & 9; var r73 = r65 ^ r5; r51 = 5 - r51; var r74 = 0 + 2; r16 = r2 % 5; print(r65); var r75 = r11 * r43; x = r72 & r1; var r76 = r25 / r47; r42 = r70 + r6; var r77 = 2 | a4; var r78 = 5 + r0; a1 = r32 ^ a3; var r79 = r7 / r6; var r80 = r15 * 9; var r81 = 5 + 2; var r82 = r70 - r16; r58 = r17 | r20; var r83 = r62 * 7; print(a2); var r84 = r76 / 6; r9 = r61 * r63; var r85 = r13 % r40; var r86 = r56 % r67; var r87 = r37 * r69; return a1; }); } catch(e2) { } i0.toSource = (function mcc_() { var xfhvby = 0; return function() { ++xfhvby; f2(/*ICCD*/xfhvby % 8 == 6);};})(); }; h2[name] = val; return true; }, iterate: function() { /*MXX1*/o0 = g2.Set.prototype.forEach;; return (function() { for (var name in h2) { yield name; } })(); }, enumerate: function() { o2.s1 = new String;; var result = []; for (var name in h2) { result.push(name); }; return result; }, keys: function() { v0 = a2.reduce, reduceRight((function() { for (var j=0;j<8;++j) { this.f1(j%5==0); } }), m0);; return Object.keys(h2); } });");
/*fuzzSeed-211892750*/count=135; tryItOut("L:for(var c in (4277)) kxmsdo((new (function  c (NaN = \"\\uF071\", new RegExp(\"(\\\\B)\", \"im\"))-21)()), \"\\u3364\" >>= ('fafafa'.replace(/a/g, String.prototype.strike)));/*hhh*/function kxmsdo(){v0 = a2.length;}");
/*fuzzSeed-211892750*/count=136; tryItOut("\"use strict\"; /*infloop*/L:for(/(?!(?=\\2|(?=(.|\\b))){3})/y; window = [];  \"\" ) {v2 = Object.prototype.isPrototypeOf.call(i1, g1);Math.imul(\"\\u33AE\", window); }");
/*fuzzSeed-211892750*/count=137; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x080000001, 0x07fffffff, 2**53, 0, 1, -(2**53-2), -Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000001, 42, -0x07fffffff, 0x100000001, 1/0, -0, 2**53-2, Number.MAX_VALUE, -0x100000000, -(2**53+2), 0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0, Number.MIN_VALUE, -1/0, 0.000000000000001, 0x0ffffffff, 0x100000000, 1.7976931348623157e308, -0x080000000]); ");
/*fuzzSeed-211892750*/count=138; tryItOut("g2.v0 = t0.length;");
/*fuzzSeed-211892750*/count=139; tryItOut("\"use strict\"; Array.prototype.unshift.apply(a1, [(((TypeError)()\n)(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: [1,,], set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(/*MARR*/[-Infinity, true, new String('q'), new String('q'), -Infinity, true, -Infinity, true, true, -Infinity, true, true, -Infinity, -Infinity, -Infinity, -Infinity, new String('q')].some(function(y) { s2.toSource = (function() { for (var j=0;j<3;++j) { f1(j%4==1); } }); }, x)), /*wrap2*/(function(){ var khivwq = Math.pow(17, 10); var juwrda = /*wrap2*/(function(){ var nkqpkg = Math , new RegExp(\"(?!\\\\b[^]+?{4})*\", \"gim\"); var xmlvju = /*wrap1*/(function(){ e0.add(h2);return encodeURI})(); return xmlvju;})(); return juwrda;})(), function (b) { print(x); } ))), t2]);");
/*fuzzSeed-211892750*/count=140; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return Math.fround(( ~ ((Math.acosh(Math.atan2((x ? (x >> Math.hypot(( + -0x100000000), ( + (y + -Number.MAX_VALUE)))) : ( - (y ? y : -1/0))), Math.imul((x * -0x100000001), (x | 0)))) >>> 0) >>> 0))); }); ");
/*fuzzSeed-211892750*/count=141; tryItOut("g1.s0 = s1.charAt(14);");
/*fuzzSeed-211892750*/count=142; tryItOut("e0.has(b0);");
/*fuzzSeed-211892750*/count=143; tryItOut("\"use strict\"; this.v0 = null;");
/*fuzzSeed-211892750*/count=144; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.min(/*toXFun*/toString: function() { return this; }, ((Math.max((y >>> 0), (y >= x)) >>> 0) ? Math.max(x, x) : y)) > ( + (Math.ceil((( + ((y >>> 0) <= Math.fround(Math.cbrt(Math.fround(x))))) | 0)) | 0))); }); ");
/*fuzzSeed-211892750*/count=145; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.round((( + (( + Math.min(( + (( + ( + Math.log(x))) * x)), ( + ( + Math.log10(Math.atanh(-Number.MAX_VALUE)))))) ? ( + ((( ~ Number.MAX_SAFE_INTEGER) <= ( + (( + mathy0(0x080000000, y)) >= y))) | (Math.fround(Math.sinh(y)) < Math.fround(x)))) : ( + (((y | 0) ? (Math.pow(( + (( + Math.fround(Number.MAX_SAFE_INTEGER)) , ((x | 0) < (0x0ffffffff | 0)))), ( + Number.MIN_VALUE)) | 0) : (( ! x) % -Number.MIN_SAFE_INTEGER)) | 0)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-211892750*/count=146; tryItOut("testMathyFunction(mathy3, [-0x100000001, -Number.MIN_VALUE, 2**53, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, 42, 0x100000000, 0/0, -0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -0, Number.MIN_VALUE, 0, 1.7976931348623157e308, -(2**53-2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), -0x07fffffff, 0x0ffffffff, -0x080000000, 2**53-2, -0x0ffffffff, 0x100000001, 1, 2**53+2]); ");
/*fuzzSeed-211892750*/count=147; tryItOut("g2.v2.valueOf = f1;");
/*fuzzSeed-211892750*/count=148; tryItOut("\"use strict\"; ");
/*fuzzSeed-211892750*/count=149; tryItOut("s1 += 'x';");
/*fuzzSeed-211892750*/count=150; tryItOut("with({}) for(let d in /*FARR*/[ \"\" .getUTCMinutes(true), false]) with({}) yield new SharedArrayBuffer(((function sum_slicing(aqgyhg) { ; return aqgyhg.length == 0 ? 0 : aqgyhg[0] + sum_slicing(aqgyhg.slice(1)); })(/*MARR*/[-Infinity, -Infinity, -Infinity, -Infinity,  '\\0' ,  '\\0' , -Infinity,  '\\0' ,  '\\0' , -Infinity, -Infinity, -Infinity,  '\\0' ,  '\\0' , -Infinity, -Infinity,  '\\0' , -Infinity,  '\\0' ,  '\\0' ,  '\\0' , -Infinity])));with({}) { for(let d in []); } ");
/*fuzzSeed-211892750*/count=151; tryItOut("mathy0 = (function(x, y) { return (( + ( + Math.imul(( + ( + Math.cbrt(Math.abs(Math.expm1(y))))), Math.max((((x | 0) ? (Math.expm1(y) >>> 0) : -0x07fffffff) | 0), ( + ( + Math.atanh(x))))))) >>> (Math.asin(((Math.clz32(((Math.fround(Math.pow((((Math.fround(Math.atanh((x | 0))) === x) >>> 0) | 0), Math.fround(0/0))) & 2**53-2) >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, 0x080000000, 1/0, 1.7976931348623157e308, Math.PI, -0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, -0x080000001, 0, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, 0x0ffffffff, -(2**53+2), -1/0, 1, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, 2**53, 42, 2**53-2, -0, Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-211892750*/count=152; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-211892750*/count=153; tryItOut("/*oLoop*/for (ehzvrl = 0; ehzvrl < 18; ++ehzvrl) { this; } ");
/*fuzzSeed-211892750*/count=154; tryItOut("L:for(let y in ((function (d)\"use asm\";   var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var sqrt = stdlib.Math.sqrt;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float64ArrayView[((Uint8ArrayView[4096])) >> 3]) = ((NaN));\n    d1 = ((i0) ? (-3.8685626227668134e+25) : (0.5));\n    {\n      d1 = (+(((((i0) ? (eval(\"{}\", (eval))) : (2049.0))) - ((+pow(((+sqrt(((Float32ArrayView[(((-1099511627776.0) != (144115188075855870.0))-(!(0xea3882d3))) >> 2]))))), ((Float64ArrayView[0]))))))));\n    }\n    return (((1)))|0;\n  }\n  return f;)( /x/g ))){this.h0.fix = f2; }");
/*fuzzSeed-211892750*/count=155; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-211892750*/count=156; tryItOut("\"use asm\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((-6.189700196426902e+26) <= (+(0xb99ec78d)));\n    return (((/*FFI*/ff((((((~(((i0)))) == (imul((0x3767c9c2), (x))|0))))), ((\n /x/  ? window : this)), ((134217729.0)))|0)+(i1)))|0;\n    i1 = (i0);\n    (Float64ArrayView[0]) = ((+/*FFI*/ff(((imul(((!(i1)) ? (!(i1)) : (/*FFI*/ff(((-0x38c3b*(i0))), ((((0x246b07e7)) ^ ((0x219831e1)))))|0)), (i1))|0)), ((1.2089258196146292e+24)), ((-0.03125)), ((-524289.0)), (((-67108865.0) + (-9.671406556917033e+24))), ((((i0)-(i0)) >> ((0x5dd1a6ec)-(0x72e061fc)-(0xdf4b477a)))))));\n    i1 = ((~((i0))) >= ((((0xc1db56e1) >= (c = x))) ^ ((i1)*0xfffff)));\n    switch ((((i1)-((0x377d7f86))) ^ ((0xf85f59fe)-(0x66968c80)+(0x169be687)))) {\n      default:\n        i1 = (i1);\n    }\n    i0 = (0xfd9a5fb0);\n    i0 = ((0x5f12ae66) == (((i0)-(!(((Uint16ArrayView[((0x3a4c857b)) >> 1]))))-(i1))>>>(((0x0) > ((((0x54d4dabd) > (-0x4834c24)))>>>((0x5862ed26)*-0x611f5)))+(i0))));\n    i0 = (i0);\n    i0 = (i1);\n    i1 = (i1);\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-211892750*/count=157; tryItOut("\"use strict\"; for (var p in g0.a2) { try { v2 = (p1 instanceof f0); } catch(e0) { } try { t0.set(o2.a2, 2); } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(v0, h2); } catch(e2) { } o0.m0.has(b0); }");
/*fuzzSeed-211892750*/count=158; tryItOut("/*infloop*/for(e; (x =  /x/g ); (4277)) {s0.toString = (function() { try { o2.a0.length = 3; } catch(e0) { } try { Array.prototype.reverse.apply(a0, []); } catch(e1) { } try { o1.toString = (function() { try { Object.preventExtensions(s1); } catch(e0) { } s2 = Array.prototype.join.call(a2, s2); return g0.o1.g0.o2; }); } catch(e2) { } s2 += s0; return h1; }); }");
/*fuzzSeed-211892750*/count=159; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.atan2((( + mathy0(y, ( + ( ~ ( + y))))) == Math.cosh(y)), Math.pow(( + Math.hypot(( + Math.max(x, y)), ( + Math.round(y)))), y)), ((Math.imul(y, Math.acos(y)) / ((Math.log2((y >>> 0)) >>> 0) | 0)) ? (Math.fround(Math.sin(Math.fround((Math.max(( ! y), Math.fround(Math.clz32((x === -(2**53+2))))) | 0)))) / Math.exp((( ! -(2**53+2)) | 0))) : ( + Math.sqrt(( - ( + (y == y))))))); }); testMathyFunction(mathy1, [0x07fffffff, 0.000000000000001, 1/0, 1, 0x100000001, Math.PI, 42, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, -1/0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 2**53+2, Number.MIN_VALUE, -0, -0x080000001, 0x100000000, -(2**53), Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, 0, -(2**53-2), 0x080000001, -0x07fffffff, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-211892750*/count=160; tryItOut("/*tLoop*/for (let d of /*MARR*/[x, new String('q')]) { var x, ctunrt;/*RXUB*/var r = true; var s = \"\"; print(s.search(r));  }");
/*fuzzSeed-211892750*/count=161; tryItOut("mathy1 = (function(x, y) { return Math.fround((mathy0((( ! (mathy0(Math.imul(x, x), Math.log(( + x))) | 0)) | 0), Math.hypot(( ~ (Math.max(Math.imul(Math.fround(y), (0x080000001 | 0)), (( + Math.max(( + -Number.MAX_SAFE_INTEGER), x)) | 0)) >>> 0)), ( - x))) ? Math.imul(Math.fround(Math.round(x)), ( ! ( ! ( + Math.fround((Math.fround(Math.min(Math.fround(x), Math.fround(x))) | Math.atan(-0))))))) : mathy0((Math.pow(Math.fround(y), Math.pow(0x100000000, y)) / Math.fround(Math.fround((Math.fround(x) * Math.fround(x))))), ( + (((x <= ( - x)) | 0) >>> ( + -Number.MAX_VALUE)))))); }); ");
/*fuzzSeed-211892750*/count=162; tryItOut("(x);");
/*fuzzSeed-211892750*/count=163; tryItOut("o1.o0 = {};");
/*fuzzSeed-211892750*/count=164; tryItOut("\"use strict\"; Array.prototype.pop.call(a0);this.v0 = a0.reduce, reduceRight();");
/*fuzzSeed-211892750*/count=165; tryItOut("e0 + o1.b2;");
/*fuzzSeed-211892750*/count=166; tryItOut("mathy0 = (function(x, y) { return ( - Math.min(Math.exp(( + ( + Math.atan2(( + Math.atan(y)), ( + x))))), (( ! Math.round(1)) | 0))); }); testMathyFunction(mathy0, [0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 0.000000000000001, 42, 2**53, 0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, -0, -0x100000001, Math.PI, Number.MIN_VALUE, -1/0, 0x07fffffff, -0x080000001, 0/0, -0x0ffffffff, -0x07fffffff, -(2**53), -(2**53-2), 0x0ffffffff, -(2**53+2), 1/0, 1.7976931348623157e308, -0x100000000, 2**53+2, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=167; tryItOut("b2[\"indexOf\"] = o0.p2;");
/*fuzzSeed-211892750*/count=168; tryItOut("\"use strict\"; print(/*UUV2*/(x.fixed = x.indexOf));var y = x;");
/*fuzzSeed-211892750*/count=169; tryItOut("mathy2 = (function(x, y) { return mathy0(Math.fround(mathy0((Math.fround(( ~ y)) === Math.fround(Math.min(x, Math.fround((( ~ ((((y | 0) > (Math.imul(x, y) | 0)) >>> 0) >>> 0)) >>> 0))))), Math.fround((Math.fround(y) ? Math.fround(0) : Math.fround(2**53))))), mathy1(Math.fround(Math.cos(Math.fround(y))), ( + ( ! ( + Math.clz32(y)))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 0, 1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), 0x07fffffff, -0, 0x100000001, 2**53+2, 0x100000000, -0x080000000, Number.MIN_VALUE, -1/0, Number.MAX_VALUE, 0.000000000000001, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, 0x080000000, 0/0, -(2**53+2), 0x080000001, -(2**53), -0x100000001, Math.PI, 42, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=170; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.imul((Math.atan(( ~ -Number.MIN_VALUE)) | 0), (( + (( + (mathy0((Math.imul(( + -(2**53-2)), ( + y)) | 0), (y | 0)) | 0)) % ( + Math.fround((Math.imul(y, -(2**53+2)) ? -Number.MAX_VALUE : Math.hypot(Math.fround(2**53+2), y)))))) <= ( ~ ((((Math.cosh(Math.fround((y >>> (((2**53 >>> 0) === y) >>> 0)))) | 0) >>> 0) | (y >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [-0x100000000, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, -0x100000001, 2**53-2, 0, -(2**53), -0x07fffffff, 42, -0, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -1/0, -0x080000001, Math.PI, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, 0x100000000, -(2**53+2), 0x07fffffff, 1, -0x080000000, 2**53]); ");
/*fuzzSeed-211892750*/count=171; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=172; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[null,  \"\" ,  \"\" ,  \"\" , null, x, x, null,  \"\" ,  \"\" ,  \"\" ,  \"\" , null,  \"\" ,  \"\" , x,  \"\" , x, null, null, null, null, x]) { v0 = (o2.o2.f0 instanceof o0); }");
/*fuzzSeed-211892750*/count=173; tryItOut("h2 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.pop.call(a2);; var desc = Object.getOwnPropertyDescriptor(e1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v2 = evalcx(\"p2.valueOf = ((let (e=eval) e)).bind(Uint32Array.prototype);\", g0);; var desc = Object.getPropertyDescriptor(e1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { print(uneval(g0.v0));; Object.defineProperty(e1, name, desc); }, getOwnPropertyNames: function() { throw o2.e0; return Object.getOwnPropertyNames(e1); }, delete: function(name) { selectforgc(this.g1.o0);; return delete e1[name]; }, fix: function() { a2 = arguments.callee.caller.arguments;; if (Object.isFrozen(e1)) { return Object.getOwnProperties(e1); } }, has: function(name) { v0 = this.g2.runOffThreadScript();; return name in e1; }, hasOwn: function(name) { e0.add(t2);; return Object.prototype.hasOwnProperty.call(e1, name); }, get: function(receiver, name) { a0.pop();; return e1[name]; }, set: function(receiver, name, val) { /*ADP-3*/Object.defineProperty(a0, 19, { configurable: (x % 57 == 31), enumerable: (x % 4 != 2), writable: (x % 3 == 0), value: g1 });; e1[name] = val; return true; }, iterate: function() { for (var p in i2) { g0.v2 = Object.prototype.isPrototypeOf.call(b1, m0); }; return (function() { for (var name in e1) { yield name; } })(); }, enumerate: function() { g1.i2.send(f2);; var result = []; for (var name in e1) { result.push(name); }; return result; }, keys: function() { v0 = g1.o2.r1.multiline;; return Object.keys(e1); } });");
/*fuzzSeed-211892750*/count=174; tryItOut("b0.toSource = (function() { for (var v of o0) { try { e0.add(f2); } catch(e0) { } try { this.g1.h1.getPropertyDescriptor = (function(j) { if (j) { m2.has(h1); } else { try { v1 = (s2 instanceof i2); } catch(e0) { } try { v2 = (v1 instanceof p2); } catch(e1) { } /*MXX3*/g1.String.prototype.startsWith = g2.String.prototype.startsWith; } }); } catch(e1) { } v2 = evalcx(\"x\", g2); } return i1; });");
/*fuzzSeed-211892750*/count=175; tryItOut("/*MXX2*/g1.Map.prototype.forEach = g2.h0;");
/*fuzzSeed-211892750*/count=176; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=177; tryItOut("testMathyFunction(mathy0, [Number.MIN_VALUE, 1, -Number.MIN_VALUE, 0x080000001, -0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 2**53+2, 42, -0, 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, -0x100000000, 0.000000000000001, 0/0, 0x100000000, -0x100000001, -0x080000000, 0x100000001, -0x080000001, Math.PI, -(2**53-2), 2**53, -(2**53), 0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-211892750*/count=178; tryItOut("/*MXX2*/g2.Element.length = b1;");
/*fuzzSeed-211892750*/count=179; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g2, g0.p1);");
/*fuzzSeed-211892750*/count=180; tryItOut("\"use strict\"; this.p1 + '';");
/*fuzzSeed-211892750*/count=181; tryItOut("print(uneval(h2));");
/*fuzzSeed-211892750*/count=182; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=183; tryItOut("/*bLoop*/for (let zopuml = 0; zopuml < 2; ++zopuml) { if (zopuml % 3 == 2) { print(false); } else { (x = \"\\uBB6C\"); }  } ");
/*fuzzSeed-211892750*/count=184; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=185; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=186; tryItOut("\"use strict\"; /*infloop*/for(let b; (this.throw(1/0));  \"\" ) try { yield a; } catch(eval if (function(){throw this;})()) { (-20); } catch(b if (function(){0;})()) { print(e2); } ");
/*fuzzSeed-211892750*/count=187; tryItOut("yield (4277);\u000d(x);{print(\"\\u3B4B\");o1 = Object.create(t2); }");
/*fuzzSeed-211892750*/count=188; tryItOut(" for  each(let x in (void version(170))) throw (x = function(id) { return id });");
/*fuzzSeed-211892750*/count=189; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ((( ~ ( + (( + (Math.min(( + ((-Number.MIN_VALUE >>> 0) ^ (y >>> 0))), x) ^ ( + x))) <= Math.atan2(Math.max(y, 2**53-2), mathy0(x, Math.fround(( + (( + mathy0((-0 >>> 0), x)) % Math.fround(y))))))))) >>> 0) ** Math.ceil(Math.min((Math.max((y >>> 0), (Math.cosh(Number.MAX_VALUE) >>> 0)) + Math.max(x, ( ~ x))), ((x % (Math.asin((-0x080000001 | 0)) | 0)) | 0)))); }); testMathyFunction(mathy1, [1.7976931348623157e308, -0, 0x100000000, Number.MAX_VALUE, 0x080000001, 42, -(2**53+2), -Number.MAX_VALUE, -0x080000001, 1, Number.MAX_SAFE_INTEGER, 0, -0x080000000, Number.MIN_VALUE, 0x100000001, -0x100000000, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -1/0, Math.PI, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, -(2**53), 2**53+2, -0x100000001, 0x0ffffffff, 0x080000000, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-211892750*/count=190; tryItOut(";");
/*fuzzSeed-211892750*/count=191; tryItOut("a0.reverse(o2);var d = x;");
/*fuzzSeed-211892750*/count=192; tryItOut("\"use strict\"; ;");
/*fuzzSeed-211892750*/count=193; tryItOut("\"use asm\"; testMathyFunction(mathy4, [1/0, 0, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, 1, 0x100000000, -0x07fffffff, -0, -(2**53), 0x080000001, Number.MIN_VALUE, -0x0ffffffff, 2**53-2, 0x100000001, -(2**53+2), 0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -0x100000001, -0x080000000, -0x100000000, 2**53, 42, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-211892750*/count=194; tryItOut("\"use strict\"; m2.set(g2, g0);s1 += 'x';");
/*fuzzSeed-211892750*/count=195; tryItOut("testMathyFunction(mathy3, [0x100000001, -1/0, 0x080000001, 1/0, -0x100000000, -0x100000001, 1.7976931348623157e308, Math.PI, 1, -0x080000001, -(2**53), -0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, 2**53, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 0, Number.MIN_VALUE, 2**53-2, 0.000000000000001, 0x07fffffff, 0/0, -0x080000000]); ");
/*fuzzSeed-211892750*/count=196; tryItOut("/*hhh*/function jdzrgr(c){f0 = p0;}jdzrgr();");
/*fuzzSeed-211892750*/count=197; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround(((((Math.min(Math.fround(( - (Math.round(( - (x >>> 0))) >>> 0))), (Math.ceil(y) ? Math.trunc(Math.fround((Math.fround((Math.atan2(y, (0x0ffffffff | 0)) | 0)) < (x >>> 0)))) : (Math.min((0x07fffffff >>> 0), (x >>> 0)) >>> 0))) | 0) | 0) << (((Math.pow(( + Math.acosh(( + ( + y)))), 0) - -1/0) >= Math.fround((Math.atan2(Math.fround(x), (x ? x : x)) | 0))) | 0)) | 0)) || Math.fround(Math.acosh((( - ( - Math.max(Math.fround(( ~ Math.fround(x))), 2**53-2))) >>> 0))))); }); testMathyFunction(mathy0, [0x080000001, 0x080000000, 2**53, -0x100000001, 0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -(2**53+2), 1, -Number.MIN_VALUE, Math.PI, 0.000000000000001, -0x07fffffff, 42, -0x0ffffffff, 0/0, -Number.MAX_VALUE, 0, 0x100000000, -(2**53-2), -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, -0, -1/0, -(2**53), 2**53+2, 1.7976931348623157e308]); ");
/*fuzzSeed-211892750*/count=198; tryItOut("/*infloop*/L: for  each(var arguments in 'fafafa'.replace(/a/g, function  NaN (x, z)\"\\uE98F\")) v1 = g0.runOffThreadScript();");
/*fuzzSeed-211892750*/count=199; tryItOut("mathy4 = (function(x, y) { return mathy2(( + ( + Math.log10(Math.fround((Math.fround(mathy1(x, (Math.cos(((Math.min((y | 0), (Math.fround(Math.pow(x, x)) | 0)) | 0) | 0)) | 0))) / Math.hypot(x, y)))))), ( + (Math.atan2((Math.cosh(Math.expm1(mathy1(Math.min(y, y), -0x0ffffffff))) | 0), (( - y) | 0)) | 0))); }); testMathyFunction(mathy4, [1/0, 2**53, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0x0ffffffff, 0x0ffffffff, -1/0, 0/0, Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 2**53+2, -(2**53), 0x100000000, 1, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, Math.PI, -0x080000001, 0x07fffffff, 0, -(2**53+2), -(2**53-2), -0x100000001]); ");
/*fuzzSeed-211892750*/count=200; tryItOut("\"use strict\"; var z = ((makeFinalizeObserver('tenured')));f1(f1);");
/*fuzzSeed-211892750*/count=201; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.max((Math.fround(Math.asin(Math.fround(((-0x100000000 ? -0 : 1/0) | Math.fround(Math.max(-0x080000001, x)))))) & (Math.sign((y >>> 0)) >>> 0)), Math.imul((Math.atan2((( + x) >>> 0), (Math.expm1((Math.atan2((y | 0), (x | 0)) | 0)) | 0)) | 0), Math.atan2((2**53+2 | (-0x080000001 >>> 0)), Math.pow((((x == -(2**53-2)) < (x | 0)) >>> 0), (42 >>> 0)))))); }); testMathyFunction(mathy3, [null, false, [], undefined, (new Boolean(false)), objectEmulatingUndefined(), true, (new String('')), NaN, '', '\\0', 0.1, ({valueOf:function(){return '0';}}), 1, (new Number(0)), '0', [0], 0, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Number(-0)), /0/, '/0/', -0, (function(){return 0;}), (new Boolean(true))]); ");
/*fuzzSeed-211892750*/count=202; tryItOut("for([e, c] = (timeout(1800)) in (void options('strict'))) {let [[[], ]] = objectEmulatingUndefined.__defineGetter__(\"NaN\", Number.isFinite), ({b: Math}) = /*UUV1*/(this.parseFloat = eval), window, x, vfluqe, [] = eval(\"\\\"use strict\\\"; Array.prototype.reverse.apply(o0.a1, [v1, o0.o0.s2]);\", null), x = \"\\uF547\", wbnrsz, taambu;const a = /*MARR*/[-0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, Infinity, Infinity, Infinity, -0x07fffffff, Infinity, -0x07fffffff, -0x07fffffff, Infinity, Infinity, Infinity, Infinity, -0x07fffffff, Infinity, -0x07fffffff, -0x07fffffff, Infinity, Infinity, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, Infinity, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, Infinity, Infinity, -0x07fffffff, Infinity, Infinity, -0x07fffffff, Infinity, -0x07fffffff, Infinity, Infinity].map(this, NaN = e).unwatch(\"10\");for(var b in ((function  a (y)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1073741825.0;\n    return (((0xd2334ebe)))|0;\n  }\n  return f;)(x))){t0 = t2.subarray(18, v1);print(\"\\u71C8\"); } }");
/*fuzzSeed-211892750*/count=203; tryItOut("\"use strict\"; with(7)yield function ([y]) { };");
/*fuzzSeed-211892750*/count=204; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=205; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -549755813889.0;\n    var d3 = 549755813888.0;\n    var i4 = 0;\n    var d5 = 274877906945.0;\n    (Float64ArrayView[((/*FFI*/ff((((((1.5111572745182865e+23) != (17.0))+(0xf4b6d0e7)) << (((0x5ffe5fcf))))), ((d3)), (((0xfa167f2b) ? (274877906945.0) : (-140737488355329.0))))|0)*0x40408) >> 3]) = ((+(-1.0/0.0)));\n    {\n      switch ((((0x42ea7630) / (0x2847152b)) << ((i0)-((0x0) != (0xf1109eb2))))) {\n      }\n    }\n    (Int8ArrayView[4096]) = (( \"\" )-((0xcd170c78) == (((0xd303a908) / ((((-0x8000000) ? (0xf8e00cc3) : (0x99cbdfe2)))>>>((0x65a7fba8) / (0x51275a33))))>>>(-0x9472c*(/*FFI*/ff(((+pow(((((1.0078125)) % ((-35184372088833.0)))), (((0xf9a8355c) ? (3.8685626227668134e+25) : (-33554431.0)))))), ((+(((-0x8000000)) | ((0xfda03979))))))|0)))));\n    {\n      {\n        (Float32ArrayView[((Int16ArrayView[1])) >> 2]) = ((+sqrt(((d5)))));\n      }\n    }\n    (Float32ArrayView[2]) = ((+(0.0/0.0)));\n    {\n      return +((-36893488147419103000.0));\n    }\n    i0 = ((((((((0x3f7ca7b0) > (0x7b5ae104)))>>>(((9.44473296573929e+21) > (-8589934592.0)))) > (((0x64c4654f) / (0x937bfc76))>>>((0xd780b4d2)+(0x1a43d6fc))))-(0x892bf160)) >> ((0xff4566a5)-((x)))) > (((/*FFI*/ff(((x)), ((+abs(((Float64ArrayView[((0xfbf710f5)) >> 3]))))), ((2147483649.0)), ((((-17179869183.0)) * ((-32.0)))))|0)+(0x6bf20a4)) & ((i4)-(i0))));\n    d2 = (-4294967296.0);\n    return +((-2305843009213694000.0));\n    return +(((d3) + (((((-0x8000000)-(0xc08b6ccd)+(0xd3dbcbb8))>>>((0xffffffff)+(0x5930319c)))) ? (+(1.0/0.0)) : (d3))));\n  }\n  return f; })(this, {ff: Set.prototype.entries}, new ArrayBuffer(4096)); ");
/*fuzzSeed-211892750*/count=206; tryItOut("for (var p in h0) { try { t1[16]; } catch(e0) { } try { v0 = evaluate(\"/*vLoop*/for (let iagmvo = 0, (4277); iagmvo < 19; ++iagmvo) { var d = iagmvo; print(d); } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 != 3), noScriptRval: true, sourceIsLazy: (x % 5 != 4), catchTermination: (Math.pow(undefined, (x) = -8)) })); } catch(e1) { } print(f1); }");
/*fuzzSeed-211892750*/count=207; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, e1);");
/*fuzzSeed-211892750*/count=208; tryItOut("for (var p in this.g0) { try { /*MXX3*/g1.RegExp.$2 = g2.RegExp.$2; } catch(e0) { } try { for (var p in i1) { try { s0 += s0; } catch(e0) { } try { this.a1.splice(NaN, 19); } catch(e1) { } try { /*ODP-1*/Object.defineProperty(v0, \"toString\", ({})); } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(o2.e1, this.a2); } } catch(e1) { } try { /*MXX3*/g2.TypeError = g1.TypeError; } catch(e2) { } for (var p in e1) { try { v0 = false; } catch(e0) { } m0.has(o1.g1.t2); } }");
/*fuzzSeed-211892750*/count=209; tryItOut("a2.reverse(b0, p0);");
/*fuzzSeed-211892750*/count=210; tryItOut("\"use strict\"; o1 = Object.create(g0);");
/*fuzzSeed-211892750*/count=211; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.atan2(Math.log10((( + (((y | 0) === (x | 0)) | 0)) * Math.sinh(((Math.min((y | 0), (((Math.pow(Math.fround(x), y) | 0) === y) | 0)) | 0) | 0)))), ( + ( - ( + ( + ( ~ (((((x !== ( + y)) && (x >>> 0)) >>> 0) === (mathy2(((Math.max(x, (Math.imul(1.7976931348623157e308, 0/0) >>> 0)) >>> 0) >>> 0), (x >>> 0)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy3, [0x080000001, -0x0ffffffff, 2**53, 0/0, 1/0, 0x100000000, 0x0ffffffff, -1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, -0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 1.7976931348623157e308, -(2**53-2), Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -0, 42, -0x100000000, 0, -(2**53), 0x080000000, 1, 0x100000001, 2**53+2]); ");
/*fuzzSeed-211892750*/count=212; tryItOut("mathy2 = (function(x, y) { return Math.clz32(Math.max(( + mathy0((((mathy1((x >>> 0), ((( ! ((mathy0((y | 0), (0x080000001 | 0)) | 0) | 0)) | 0) >>> 0)) >>> 0) | 0) ^ Math.fround((( - y) ? x : 0x080000000))), ( + Math.sqrt(( + (x / Math.fround((0x080000000 >>> 0)))))))), (Math.imul(( + (( + (mathy1(x, ( ~ x)) >>> 0)) >>> 0)), (Math.tanh(((Math.atan2((y | ( + x)), (0x100000000 >>> 0)) >>> 0) >>> 0)) | 0)) >>> 0))); }); ");
/*fuzzSeed-211892750*/count=213; tryItOut("Array.prototype.splice.call(a0, NaN, 14, 3);\ns0 += s2;\n");
/*fuzzSeed-211892750*/count=214; tryItOut("v1 = t2.length;\no1.e1.__proto__ = i1;\n\nprint(uneval(this.s0));\n");
/*fuzzSeed-211892750*/count=215; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.hypot(((Math.exp(((( ! x) | 0) !== (((((Math.acosh(y) >>> 0) >>> 0) !== (x >>> 0)) >>> 0) | 0))) | 0) | 0), (((Math.asinh((Math.asinh(( + ( + Math.pow(( + (Math.cos(-0x100000000) | 0)), Math.min(y, x))))) | 0)) | 0) >>> ((Math.log2(Math.hypot(x, ( + ( + Math.atan2(( + y), Math.fround(( ! y))))))) >>> 0) >>> 0)) | 0)); }); ");
/*fuzzSeed-211892750*/count=216; tryItOut("mathy3 = (function(x, y) { return mathy2(Math.fround(Math.asin(( + Math.atanh((mathy1(( + (((x | 0) >= ((( ~ 2**53+2) >>> 0) | 0)) | 0)), ( + ((x | 0) % (Math.pow(2**53+2, -Number.MIN_VALUE) | 0)))) >>> 0))))), Math.fround(Math.max(Math.cosh(Math.fround(( + x))), (((mathy2((Math.sqrt((y >>> 0)) >>> 0), -0x100000000) >>> 0) ? mathy0(x, (((Math.acos(( + x)) - x) | 0) >> (((-Number.MAX_VALUE | 0) === (0x080000000 | 0)) | 0))) : x) >>> 0)))); }); testMathyFunction(mathy3, [-1/0, -0x07fffffff, -(2**53), Number.MIN_VALUE, 2**53, Math.PI, 42, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 0.000000000000001, 0/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, -(2**53-2), -0x100000001, 0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000000, 1, 1/0, 2**53+2, 0x100000001, -(2**53+2), 2**53-2, 0x080000001, -Number.MAX_VALUE, -0, -0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=217; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[-3/0,  /x/ , -3/0, -3/0, -3/0, this, this, this, this, this,  /x/ ,  /x/ ,  /x/ , -3/0, this, this, -3/0, -3/0, -3/0, this, this, -3/0, -3/0, -3/0, -3/0, this,  /x/ , -3/0, this, -3/0, this, -3/0,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , this, this, -3/0, this,  /x/ , -3/0, this,  /x/ , -3/0, -3/0, this, this, this,  /x/ , this, -3/0, -3/0]) { kpwdbk, w = null;y; }");
/*fuzzSeed-211892750*/count=218; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.cos(Math.fround(((0.000000000000001 ? Math.max(y, 0x080000001) : ( + ((y | 0) ? Math.fround(y) : Math.fround(( ! y))))) !== (((y / 0) || x) | 0))))); }); testMathyFunction(mathy0, [1.7976931348623157e308, 0.000000000000001, 2**53+2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -1/0, 0/0, -(2**53+2), 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -0x100000000, 0x100000001, 1/0, -0x080000001, 0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, -(2**53-2), 2**53, 42, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000000, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 1, 0x07fffffff]); ");
/*fuzzSeed-211892750*/count=219; tryItOut("\"use strict\"; v1 = a0.length;");
/*fuzzSeed-211892750*/count=220; tryItOut("L: /* no regression tests found */");
/*fuzzSeed-211892750*/count=221; tryItOut("");
/*fuzzSeed-211892750*/count=222; tryItOut("z = (arguments[new String(\"-3\")] = x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( '' ), x));/*RXUB*/var r = new RegExp(\"(?!\\\\2|[^\\\\B-\\\\r\\\\u0030-\\u7e72]{2,2}|^{2}^|^*?|\\\\1|(?:\\\\s(?=(.))){0,3}){4}\", \"gyim\"); var s = \"_\\n_\\n_\\n_\\n\\n_\\n_\\n_\\n_\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=223; tryItOut("p2 + '';");
/*fuzzSeed-211892750*/count=224; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=225; tryItOut("\"use strict\"; v1 = -0;");
/*fuzzSeed-211892750*/count=226; tryItOut("a0[6];");
/*fuzzSeed-211892750*/count=227; tryItOut("\"use strict\"; if((x % 21 != 4)) { if (x) {t1 = o1.t1.subarray(16); }} else {g0.__proto__ = f0d = new x((4277), x.throw((/*UUV2*/(x.revocable = x.setFullYear))).yoyo(this.x = x)); }");
/*fuzzSeed-211892750*/count=228; tryItOut("/*infloop*/L:for(var y; \n-3481414489; [z1,,]) v2 = a2.length;");
/*fuzzSeed-211892750*/count=229; tryItOut("/*hhh*/function eldyqf({x: [], d: {}, window: e}){v2 = this.g0.runOffThreadScript();}/*iii*/g2.v2 = Object.prototype.isPrototypeOf.call(t0, p0);");
/*fuzzSeed-211892750*/count=230; tryItOut("/*infloop*/for(var z = new ()(window, -906248705 >>> function(id) { return id }); /*UUV1*/(eval.big = Date.prototype.setUTCMinutes).yoyo(x); (makeFinalizeObserver('nursery'))) /*ODP-3*/Object.defineProperty(g0.g1, \"has\", { configurable: true, enumerable: (x % 6 == 0), writable: false, value: b2 });const y = z;");
/*fuzzSeed-211892750*/count=231; tryItOut("\"use strict\"; m1.get(t0);");
/*fuzzSeed-211892750*/count=232; tryItOut("mathy4 = (function(x, y) { return Math.fround(((( + (( + Math.asin(( + y))) | 0)) >>> 0) ? (( + Math.min(Math.imul(( + ( ~ ( + (Math.min((x >>> 0), (x >>> 0)) >>> 0)))), y), Math.cbrt(( ~ Math.fround(mathy0((Math.acos((y >>> 0)) >>> 0), (Math.fround(Math.tanh((Math.fround(((x | 0) || (y >>> 0))) | 0))) >>> 0))))))) >>> 0) : ( ! (Math.imul((mathy2(((( + Math.sinh(( + x))) | 0) !== Number.MAX_SAFE_INTEGER), x) >>> 0), (-1/0 >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x07fffffff, 0x100000000, 0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, Math.PI, 2**53, 2**53-2, 0, 1, 0/0, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, -(2**53+2), -Number.MAX_VALUE, 1/0, -(2**53), -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, 1.7976931348623157e308, 0x080000001, -0, 0x080000000, 0.000000000000001, -1/0, -0x080000000]); ");
/*fuzzSeed-211892750*/count=233; tryItOut("delete t2[17];");
/*fuzzSeed-211892750*/count=234; tryItOut("\"use strict\"; print(x);function x([]) { \"use strict\"; v1 = r2.toString; } {}");
/*fuzzSeed-211892750*/count=235; tryItOut("m2.delete(f1);");
/*fuzzSeed-211892750*/count=236; tryItOut("f1 = (function mcc_() { var tdaebz = 0; return function() { ++tdaebz; f2(/*ICCD*/tdaebz % 9 == 5);};})();");
/*fuzzSeed-211892750*/count=237; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.log(Math.atan2((x ? Math.expm1(-(2**53-2)) : Math.fround(( + y))), ((x ? mathy0(y, ( + x)) : ( ~ ( + mathy0(Math.fround(mathy0(Math.fround(mathy0(-0x100000001, Math.fround(x))), x)), ( - Math.fround(x)))))) >>> 0))) >>> 0); }); testMathyFunction(mathy1, [0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 0x080000000, Number.MAX_VALUE, 0x080000001, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, 0, -(2**53+2), Math.PI, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, -0x100000000, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, 0x100000000, 1/0, 0x100000001, -0x0ffffffff, -0x080000000, -0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -(2**53), -Number.MAX_SAFE_INTEGER, 0/0, 1]); ");
/*fuzzSeed-211892750*/count=238; tryItOut("v1 = (m2 instanceof f1);");
/*fuzzSeed-211892750*/count=239; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=240; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.fround(mathy0(Math.fround(Math.fround(mathy0(( + ( ! Math.acosh(( + mathy0(2**53, Math.PI))))), Math.fround(Math.cbrt(y))))), ( + (((( ~ x) >>> 0) >>> (( - Math.hypot(x, ((x | 0) * x))) >>> 0)) >>> 0)))) ^ Math.tan((y === (mathy0(mathy0(1, x), (Math.pow((Math.max(1.7976931348623157e308, y) >>> 0), Math.fround((Math.fround(x) >= x))) | 0)) | 0)))); }); testMathyFunction(mathy1, [-0x080000001, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1/0, 0, 2**53-2, 0x100000001, -1/0, -(2**53+2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), 0x0ffffffff, -0, 2**53, -Number.MAX_SAFE_INTEGER, 1, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 0.000000000000001, 42, -0x07fffffff, Math.PI, 0x07fffffff, 0x080000000, -0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=241; tryItOut("t1 = new Uint8ClampedArray(t0)");
/*fuzzSeed-211892750*/count=242; tryItOut("a1.push(f0, o1.s2);");
/*fuzzSeed-211892750*/count=243; tryItOut("\"use strict\"; let y = (4277);throw NaN;");
/*fuzzSeed-211892750*/count=244; tryItOut("mathy3 = (function(x, y) { return Math.pow((Math.fround(Math.atan2(Math.fround(mathy0((0x100000001 & (x < x)), Math.fround(y))), ((Math.atan2(((y !== x) | 0), (42 | 0)) | 0) % y))) ? Math.min(Math.exp(Math.cbrt(x)), ( ~ Math.round((x | 0)))) : (((( + Math.log(( + -Number.MIN_SAFE_INTEGER))) || Number.MIN_SAFE_INTEGER) != ( + Math.pow(Math.log2(Math.fround(0x080000001)), (mathy1((x >>> 0), (( + Math.pow(( + x), Math.fround(x))) | 0)) >>> 0)))) >>> 0)), mathy1(((Math.imul((( - (x >>> 0)) >>> 0), y) >>> 0) != Math.atan2((( ~ (-Number.MAX_SAFE_INTEGER >>> 0)) | 0), (Math.min(( ! Math.atan2(y, 2**53-2)), x) | 0))), (((y | 0) - ( + Math.hypot(x, (mathy1((Math.imul(x, x) >>> 0), y) > (mathy0((-(2**53-2) >>> 0), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))))) >>> 0))); }); testMathyFunction(mathy3, [-(2**53-2), 0x080000001, 2**53+2, Math.PI, -0, 0x080000000, 0x100000001, 1/0, -0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, -Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, 0x07fffffff, 1, 1.7976931348623157e308, Number.MIN_VALUE, 0.000000000000001, 0, -Number.MAX_VALUE, 0/0, -0x080000000, 42, 2**53, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-211892750*/count=245; tryItOut("\"use strict\"; v1 = evaluate(\"function this.f2(m1) allocationMarker()\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (4277), sourceIsLazy: (x % 3 == 0), catchTermination: eval(\"e0.delete(m0);\", null) }));");
/*fuzzSeed-211892750*/count=246; tryItOut(";function w(this, x, x, c, eval, /\\B+?((?:^\\W|\\u00b6))|(?=(?:[]|.)*?){1,}(?!.|[^]+\\x87)/gyi, x, window, y =  \"\" , x, a, NaN, x, x, x, x, y = 10, y, w, \u3056, w = NaN, NaN)function(y) { \"use strict\"; return [[]] }.prototypereturn;");
/*fuzzSeed-211892750*/count=247; tryItOut("/*bLoop*/for (let uyylda = 0; uyylda < 28; ++uyylda) { if (uyylda % 5 == 1) { print(Math.min(7, -21)); } else { print((makeFinalizeObserver('nursery'))); }  } \nlet(y) ((function(){with({}) { x = b; } })());\n");
/*fuzzSeed-211892750*/count=248; tryItOut("\"use strict\"; m1.has(b1);");
/*fuzzSeed-211892750*/count=249; tryItOut("mathy1 = (function(x, y) { return ( ! ( + (((( + (( - x) ? ( ~ (0x080000001 | 0)) : -Number.MIN_VALUE)) | 0) ? (Math.fround(( ! Math.exp(( + Math.imul(y, Math.fround(((x / y) >>> 0))))))) | 0) : (((0.000000000000001 << ( + (( - Math.fround(x)) | 0))) >>> 0) >>> 0)) | 0))); }); testMathyFunction(mathy1, [0x07fffffff, 0x100000001, 1/0, 1.7976931348623157e308, -0, -(2**53), -(2**53-2), Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, Math.PI, 0, -0x100000001, 0.000000000000001, -0x07fffffff, -1/0, -Number.MAX_VALUE, -0x100000000, 42, 2**53-2, 0x0ffffffff, 0x080000000, 1, -0x080000000, 0/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, -Number.MIN_VALUE, 2**53, 0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=250; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[-Infinity, -Infinity, -0x2D413CCC, {},  /x/ , {}, -Infinity,  /x/ , {}, -Infinity, {},  /x/ ,  /x/ , {}, {}, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  /x/ , -0x2D413CCC,  /x/ , {}, -Infinity, -0x2D413CCC, -Infinity, -0x2D413CCC, {}, {}, {}, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -Infinity,  /x/ ,  /x/ ,  /x/ , {}, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -Infinity, -0x2D413CCC, -Infinity, -Infinity, {},  /x/ , -Infinity, -Infinity,  /x/ ,  /x/ ,  /x/ , -0x2D413CCC, -Infinity, -0x2D413CCC, -Infinity, -Infinity,  /x/ , {}, -0x2D413CCC,  /x/ ,  /x/ , -0x2D413CCC,  /x/ ,  /x/ ,  /x/ ,  /x/ , -Infinity,  /x/ , -Infinity,  /x/ , {}, -Infinity, -0x2D413CCC, -Infinity, -Infinity,  /x/ , -0x2D413CCC, {},  /x/ , -Infinity, {}, -Infinity, -Infinity, -Infinity, -0x2D413CCC, {}, -Infinity, {}, {}, {},  /x/ , -Infinity, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC,  /x/ , -Infinity,  /x/ , -Infinity]); ");
/*fuzzSeed-211892750*/count=251; tryItOut("v1 = t0.length;");
/*fuzzSeed-211892750*/count=252; tryItOut("a0.pop(g1.i1);");
/*fuzzSeed-211892750*/count=253; tryItOut("f0 + p1;");
/*fuzzSeed-211892750*/count=254; tryItOut("/*RXUB*/var r = new RegExp(\"(?:.)|(?!(\\\\1{2})).+{1}\", \"yim\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-211892750*/count=255; tryItOut("s1 += 'x';");
/*fuzzSeed-211892750*/count=256; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    {\n      switch (((((0x16f154c7) == (0x4ac6eaad))-(i0)) >> ((i0)))) {\n        case -1:\n          i0 = ((+(0.0/0.0)) >= (137438953473.0));\n          break;\n      }\n    }\n    {\n      i0 = ((1152921504606847000.0) <= (4503599627370497.0));\n    }\n    d1 = (d1);\n    {\n      d1 = (+(0.0/0.0));\n    }\n    (Float64ArrayView[1]) = ((+(-1.0/0.0)));\n    (Int8ArrayView[0]) = ((0xf8d377f8)-(-0x8000001));\n    {\n      d1 = (d1);\n    }\n    d1 = (70368744177663.0);\n    return +((144115188075855870.0));\n    i0 = (i0);\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: Math.exp}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MIN_VALUE, 1, 0x07fffffff, -0x100000000, 2**53-2, -0x080000001, -0x080000000, 2**53, 0x080000001, 0/0, 42, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, -0, 0, 0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), 0x100000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -1/0, 2**53+2, 0x080000000]); ");
/*fuzzSeed-211892750*/count=257; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\B\", \"gym\"); var s = \"a a1 a 1\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=258; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.log10(Math.tanh(( ~ (((Math.fround(( ~ Math.fround(y))) === Math.fround(y)) | 0) | 0)))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -0x0ffffffff, Math.PI, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53), 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0, -1/0, 2**53, 2**53-2, 42, 1/0, -Number.MAX_VALUE, -0x100000001, Number.MAX_VALUE, 0/0, 0x0ffffffff, 2**53+2, -(2**53+2), -0, -0x080000000, 0.000000000000001, 1, Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000]); ");
/*fuzzSeed-211892750*/count=259; tryItOut("\"use strict\"; ");
/*fuzzSeed-211892750*/count=260; tryItOut("o1.v1 = g0.eval(\"var artgiw = new SharedArrayBuffer(8); var artgiw_0 = new Uint16Array(artgiw); print(artgiw_0[0]); var artgiw_1 = new Float64Array(artgiw); artgiw_1[0] = 15; var artgiw_2 = new Uint32Array(artgiw); g0.v0 = g2.t0.byteOffset;;s2 = new String(f2);\");");
/*fuzzSeed-211892750*/count=261; tryItOut("/*RXUB*/var r = r1; var s = s2; print(s.search(r)); \no1.t2[12];");
/*fuzzSeed-211892750*/count=262; tryItOut("let (eval = x, w =  /x/g ) { this.e2.has(this.h0); }");
/*fuzzSeed-211892750*/count=263; tryItOut("\"use strict\"; v0 = evalcx(\"/* no regression tests found */\", g0);");
/*fuzzSeed-211892750*/count=264; tryItOut("\"use strict\"; x = this.h1;");
/*fuzzSeed-211892750*/count=265; tryItOut("a0.toSource = (function() { b1 + ''; return o1; });");
/*fuzzSeed-211892750*/count=266; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(a0, s2);");
/*fuzzSeed-211892750*/count=267; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ~ (( + Math.fround(( + Math.fround(Math.min(Math.abs(( + y)), (( ~ ((Math.fround(y) ? x : Math.fround(y)) | x)) >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -0x0ffffffff, 0/0, Number.MIN_VALUE, -(2**53+2), -0x080000000, 0x100000001, 2**53-2, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0, -1/0, -0x100000001, 1.7976931348623157e308, -0x080000001, -0x100000000, 1/0, -0, 0x080000001, Math.PI, 1, -Number.MIN_VALUE, 0x0ffffffff, 2**53, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-211892750*/count=268; tryItOut("Object.defineProperty(this, \"v0\", { configurable: (x % 21 == 7), enumerable: (x % 31 != 0),  get: function() {  return t1.byteOffset; } });");
/*fuzzSeed-211892750*/count=269; tryItOut("v1 = Array.prototype.some.call(a2, (function mcc_() { var uhrpgc = 0; return function() { ++uhrpgc; if (/*ICCD*/uhrpgc % 3 == 1) { dumpln('hit!'); try { v1 = Array.prototype.every.call(a0, f2); } catch(e0) { } try { print(g2); } catch(e1) { } g1.o0.e1.add(h0); } else { dumpln('miss!'); try { v1 = g0.runOffThreadScript(); } catch(e0) { } f2 = a0[[1]]; } };})());");
/*fuzzSeed-211892750*/count=270; tryItOut("m1.delete(this.h2);");
/*fuzzSeed-211892750*/count=271; tryItOut("\"use strict\"; a2.valueOf = (function() { try { let a1 = Array.prototype.filter.apply(a1, [(function() { b1 + e1; return h1; }), t1, m0, (void options('strict')), o0.v2, h1]); } catch(e0) { } try { s2 = new String; } catch(e1) { } Object.defineProperty(this, \"e1\", { configurable: false, enumerable: true,  get: function() {  return new Set(o1.i2); } }); return g1; });");
/*fuzzSeed-211892750*/count=272; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.acos(Math.fround(Math.log1p(Math.fround((y >= Math.sinh(( + (Math.fround((Math.fround(x) > Math.fround(y))) + mathy0(y, y))))))))); }); testMathyFunction(mathy3, [NaN, ({toString:function(){return '0';}}), (new String('')), '\\0', (function(){return 0;}), [], '/0/', (new Number(-0)), /0/, 0.1, ({valueOf:function(){return 0;}}), (new Boolean(false)), false, [0], 1, -0, objectEmulatingUndefined(), undefined, (new Number(0)), '0', 0, (new Boolean(true)), '', null, true, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-211892750*/count=273; tryItOut("\"use asm\"; m2.set(i0, s1);function shapeyConstructor(etvjas){for (var ytqcpahuc in etvjas) { }etvjas[17] = Math.pow;delete etvjas[17];return etvjas; }/*tLoopC*/for (let e of /*MARR*/[new Boolean(false),  /x/ , new Boolean(false), false, new Number(1.5), false, false, new Boolean(false), new Boolean(false), false, new Boolean(false), new Boolean(false), new Number(1.5), false, new Number(1.5),  /x/ , new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5), false,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , false,  /x/ , false,  /x/ , new Number(1.5),  /x/ ,  /x/ , new Number(1.5), new Boolean(false), new Number(1.5), new Boolean(false),  /x/ , new Number(1.5), new Boolean(false), false,  /x/ , new Boolean(false), new Boolean(false), false, new Number(1.5), new Number(1.5), new Boolean(false), new Number(1.5),  /x/ ,  /x/ , false, new Number(1.5), new Boolean(false),  /x/ ]) { try{let tqdxwr = shapeyConstructor(e); print('EETT'); ( /x/g );}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-211892750*/count=274; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((( - ( - mathy4(0x080000001, 1))) + (mathy2(((y , (( - ( ! y)) >>> 0)) >>> 0), (((1/0 ? ( + y) : (Math.atan2(y, y) >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0) != mathy4((Math.max((( ~ (mathy2((0/0 << Math.fround(y)), ((( + x) >> Math.PI) | 0)) | 0)) | 0), x) | 0), Math.fround(mathy0(Math.fround(( + -Number.MIN_VALUE)), Math.tan(x))))); }); ");
/*fuzzSeed-211892750*/count=275; tryItOut("\"use asm\"; v1 = evaluate(\" /x/g \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 9 != 5), noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-211892750*/count=276; tryItOut("\"use strict\"; m0.has(g2);");
/*fuzzSeed-211892750*/count=277; tryItOut("print(this.s2);");
/*fuzzSeed-211892750*/count=278; tryItOut("\"use strict\"; v2 = Array.prototype.some.apply(g2.a2, [f0]);");
/*fuzzSeed-211892750*/count=279; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ (mathy2(mathy2((Math.log2(Math.fround(( ! y))) + (Math.fround(x) / c)), (Math.hypot(-0x080000000, y) ** x)), 1/0) | ( ~ timeout(1800)))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 2**53-2, 42, 0x07fffffff, -0x07fffffff, -0x080000001, -1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 1/0, 0, 1.7976931348623157e308, -0x0ffffffff, 0x080000000, 1, 0/0, -(2**53-2), 0x100000000, -(2**53), -Number.MIN_VALUE, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-211892750*/count=280; tryItOut("/*RXUB*/var r = new RegExp(\"[^]{34359738369,}\", \"i\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=281; tryItOut("");
/*fuzzSeed-211892750*/count=282; tryItOut("\"use strict\"; v1 = -0;var c = (Math.imul(15, -22));");
/*fuzzSeed-211892750*/count=283; tryItOut("b2.__proto__ = g1.s2;");
/*fuzzSeed-211892750*/count=284; tryItOut("print(this.s0);");
/*fuzzSeed-211892750*/count=285; tryItOut("\"use strict\"; a0 = /*MARR*/[x,  /x/g , x, (void 0), (void 0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0),  /x/g ,  /x/g ,  /x/g , (void 0),  /x/g , (void 0), x,  /x/g , x,  /x/g , (void 0), (1/0), (void 0), (void 0), (void 0),  /x/g , (1/0), x,  /x/g ,  /x/g , (1/0),  /x/g , (void 0), x, (void 0), (1/0), x,  /x/g ,  /x/g , (1/0), (1/0),  /x/g ,  /x/g ,  /x/g , (1/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0),  /x/g , x,  /x/g , (1/0)];");
/*fuzzSeed-211892750*/count=286; tryItOut("/*infloop*/while(((function factorial_tail(wtmyuj, newtek) { ; if (wtmyuj == 0) { ; return newtek; } v2 = new Number(e0);; return factorial_tail(wtmyuj - 1, newtek * wtmyuj);  })(90983, 1))){x, x, x, bgblli, aidqcr, x, zfuaeo, e, b, ekakqx;this.m0.delete(o0);function w() { /* no regression tests found */ } print(undefined);/*infloop*/for(let x in (4277)) print(0); }");
/*fuzzSeed-211892750*/count=287; tryItOut("mathy5 = (function(x, y) { return Math.min((( ~ (( ~ Math.atan2(( + mathy1(Math.asin(x), y)), x)) | 0)) | 0), Math.fround(Math.atan2((((y >>> 0) ^ ((Math.fround(y) | 0) >>> 0)) | 0), Math.fround(((mathy2(Math.fround((-0x080000000 ^ (x | 0))), x) >> (( ! ( + y)) | 0)) !== Math.cbrt(((y == (x != x)) | 0))))))); }); ");
/*fuzzSeed-211892750*/count=288; tryItOut("i0 + '';");
/*fuzzSeed-211892750*/count=289; tryItOut("{v1 = Object.prototype.isPrototypeOf.call(e0, o0.o0);z <<= x = t0[(x) = eval *= (x--)]; }");
/*fuzzSeed-211892750*/count=290; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.max(( + (( + ( + (( + (Math.atan2(y, Math.imul(x, x)) <= Math.fround(( - Math.fround(mathy1(y, y)))))) ^ ( + ((Math.atan2(y, x) | 0) * ( + (Math.exp(y) & y))))))) & ( + Math.ceil(Math.max((( + Math.sqrt(-0x0ffffffff)) >>> 0), x))))), (((( + (Math.pow((Math.sinh(( + (((-Number.MIN_SAFE_INTEGER >>> 0) ** y) != x))) | 0), ( ~ ((Math.fround(( + 0)) - (mathy0(42, y) | 0)) | 0))) | 0)) != ( + ( + ((( ~ -Number.MIN_SAFE_INTEGER) != y) === -0x0ffffffff)))) | 0) | 0)); }); testMathyFunction(mathy4, [2**53-2, 0x07fffffff, 0x080000000, 1.7976931348623157e308, Math.PI, 0/0, 0x100000000, Number.MAX_VALUE, 2**53, -0x080000000, -Number.MIN_VALUE, -(2**53+2), -(2**53), 1/0, 0, -0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -1/0, -0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -0x07fffffff, 2**53+2, 0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, 1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 42]); ");
/*fuzzSeed-211892750*/count=291; tryItOut("M:for(x = /*FARR*/[(x) = new Uint16Array([z1,,]), .../*PTHR*/(function() { \"use strict\"; for (var i of /*FARR*/[x,  \"\" , (void options('strict')), (eval = Proxy.createFunction(({/*TOODEEP*/})(false), /*wrap1*/(function(){ ;return Object.values})()).prototype), (let (y)  \"\" )]) { yield i; } })(), , delete x.x, (({window: //h\n})), /*MARR*/[[], [], x, x, [], x, [], x, [], [], [], [], [], x, x, x, [], [], x, [], [], x, x, [], x, [], [], [], []].sort(arguments.callee.caller.caller), , ...[ /x/g  for (this.zzz.zzz in \"\\u4F68\") for each (NaN in (yield (4277) if ( /* Comment */false))) for (x of x) for (x of (function() { yield  /x/g ; } })()) for (window in x) if (x)]].sort(function (x, x, x, window, c =  /x/g , x = ((void version(170))), x, x, y, x, window, NaN, x, y, x, w, NaN, eval, a, x, w, eval, a, x, e, y = true, c, x, y, w, d, yield, x, window, x, x =  \"\" , window, w = x, x, x, eval, z, x = {}, x, x = ({a2:z2}), y, x, y, y, x = new RegExp(\"^\", \"g\"), a = this, y, w, z, w, z, NaN, x, x, NaN, a, x =  /x/ , x, w, y, b, x = window, NaN, d, x, x = /(?!\\1|(?:.+)+?\\u006A?\\b+)/gim, window, x, w, y\u000c) { \"use strict\"; while((Math.fround(1106334663)) && 0)s2 += 'x'; } ) in timeout(1800)) {h2.valueOf = (function(j) { if (j) { try { print(o0); } catch(e0) { } v0 = g0.runOffThreadScript(); } else { try { (void schedulegc(g2)); } catch(e0) { } this.v2 = (m1 instanceof h2); } }); }");
/*fuzzSeed-211892750*/count=292; tryItOut("o1.g0.v2[\"fill\"] = /*UUV1*/(z.abs = function shapeyConstructor(dxuacw){if (window) this[13] = dxuacw;this[13] = new RegExp(\"(?=\\\\W)\\\\B\", \"gi\");delete this[13];if (c) this[13] = -Infinity;delete this[13];this[13] = [[1]];this[13] = [[1]];return this; });");
/*fuzzSeed-211892750*/count=293; tryItOut("mathy3 = (function(x, y) { return (((( ! ( + mathy1(( + Math.log1p((y ? (Math.acosh((y | 0)) >>> 0) : Math.fround(mathy1((x >>> 0), Math.fround(-0x07fffffff)))))), ( + ( + ((Math.fround(mathy1(y, y)) === 0x080000000) >>> 0)))))) | 0) <= Math.sqrt(( + Math.round((42 ? x : Math.fround(Math.atan2(Math.fround((x === (Math.asin(y) | 0))), Math.fround(y)))))))) >>> 0); }); testMathyFunction(mathy3, [0x100000000, 0/0, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, -0x080000001, 2**53, Math.PI, -(2**53-2), -0x100000001, -(2**53), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0, Number.MIN_VALUE, 0.000000000000001, 0x100000001, Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 1/0, 1, -0, -0x07fffffff, 42, -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=294; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.tan((mathy2(( + ( ! ( - y))), ( ! Math.log(x))) >>> 0))); }); testMathyFunction(mathy3, [-0x080000001, Math.PI, 1/0, -1/0, -(2**53), 1, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 42, 0x0ffffffff, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x100000000, 2**53, 0, 0.000000000000001, 0x080000001, -0x100000001, 0x100000001, 2**53+2, 0x100000000, -0x07fffffff, -(2**53+2), 0x080000000, -0, Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=295; tryItOut("delete b0[\"4\"];");
/*fuzzSeed-211892750*/count=296; tryItOut("\"use strict\"; a1.sort((function(j) { if (j) { try { o2.s1 += s0; } catch(e0) { } a0.shift(); } else { b2 = a2[14]; } }));");
/*fuzzSeed-211892750*/count=297; tryItOut("\"use asm\"; break M\no2 = Object.create(o0);");
/*fuzzSeed-211892750*/count=298; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-211892750*/count=299; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      d0 = (d0);\n    }\n    (Uint8ArrayView[((0xff4af791)) >> 0]) = (-0x28883*(0xfbb6f098));\n    return (((-0x8000000)))|0;\n    d0 = (Infinity);\n    return ((-(0xca4223ed)))|0;\n  }\n  return f; })(this, {ff: function(y) { print(x); }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53), 0x100000001, 0.000000000000001, 1.7976931348623157e308, 0x0ffffffff, -(2**53-2), -0x080000001, -0x080000000, -Number.MIN_VALUE, 0/0, 0x07fffffff, 1, -1/0, -0x0ffffffff, Number.MAX_VALUE, 0, -0, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 0x080000001, -0x100000000, -0x100000001, -0x07fffffff, -(2**53+2), Number.MIN_VALUE, Math.PI, 42, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=300; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.cosh(((( - Math.fround(mathy2(mathy3(y, (( ! 1) < x)), Math.fround(x)))) | 0) / ( + mathy4(( + 0.000000000000001), ( + (( ! (Math.atan(y) | 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-1/0, -0x07fffffff, -(2**53+2), 1, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, -(2**53-2), -0x080000000, 0x100000000, Math.PI, -0x080000001, 0.000000000000001, 0x07fffffff, 2**53+2, 1.7976931348623157e308, 0x080000000, Number.MAX_VALUE, 2**53, 0x0ffffffff, 0x100000001, 1/0, -0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, 42, -Number.MAX_SAFE_INTEGER, 0x080000001, 0, -0, -0x100000000]); ");
/*fuzzSeed-211892750*/count=301; tryItOut("\"use strict\"; this.s1 += 'x';");
/*fuzzSeed-211892750*/count=302; tryItOut("\"use strict\"; a0.sort((function(a0, a1, a2, a3, a4, a5, a6) { x = a5 / 9; var r0 = 0 ^ a2; var r1 = 0 ^ a3; a6 = a3 - 4; var r2 = x & a5; var r3 = 6 & r1; var r4 = a3 % a1; var r5 = r1 % a3; var r6 = r3 ^ a6; var r7 = x + x; var r8 = r4 - a1; var r9 = r0 / r3; var r10 = a1 / x; var r11 = 1 / 0; var r12 = 9 & a4; var r13 = r12 + r2; var r14 = r2 % r13; r5 = r3 ^ r6; a3 = r9 | r1; var r15 = 5 & 8; var r16 = 5 ^ 1; a1 = r10 / a5; var r17 = 6 % 1; var r18 = 1 | r15; var r19 = r8 / 4; var r20 = r5 ^ r2; r10 = a3 % r10; var r21 = r1 ^ 6; var r22 = 7 | 8; var r23 = 7 - r21; var r24 = r5 | 9; var r25 = a3 ^ r17; var r26 = r25 & 5; var r27 = r11 & 9; var r28 = r3 + 6; var r29 = r24 & r13; var r30 = 9 % 2; var r31 = r10 ^ r28; var r32 = r0 - a6; var r33 = 6 & 2; var r34 = r24 + 6; var r35 = 3 * 2; var r36 = 6 & r29; var r37 = r9 * a4; var r38 = 4 ^ r27; var r39 = r36 * 9; var r40 = r36 ^ r15; var r41 = r14 % r1; var r42 = r34 & r6; a4 = r30 ^ r23; var r43 = 8 + r39; var r44 = r6 - r1; var r45 = r38 % 6; var r46 = 6 + 9; var r47 = r11 + r41; var r48 = x + 6; print(r36); print(r2); var r49 = 4 % a6; r31 = r1 / 8; var r50 = r32 | 3; var r51 = 0 % 5; var r52 = r25 ^ r42; var r53 = r20 & a2; var r54 = 0 ^ 0; var r55 = 8 + r33; var r56 = 3 - 4; var r57 = r34 ^ r42; var r58 = r5 / r54; r24 = r23 & 2; var r59 = 4 % r39; var r60 = a5 ^ 9; var r61 = r37 + r13; print(r18); var r62 = r51 * 1; var r63 = 7 % r53; var r64 = r58 % r20; var r65 = r32 % 4; var r66 = 6 % r61; var r67 = r46 | 9; var r68 = r63 | 7; var r69 = r56 * r54; var r70 = r27 * a0; var r71 = 1 ^ r66; var r72 = r13 % r12; var r73 = r9 / 6; var r74 = r62 | r58; var r75 = r49 + 0; var r76 = r26 / r25; var r77 = r27 ^ 0; var r78 = 6 | r8; var r79 = 9 % r58; r77 = r64 % r43; var r80 = 2 & r24; var r81 = r75 & 4; var r82 = a0 & r30; var r83 = r7 + r27; print(r9); var r84 = r4 + a4; var r85 = r6 | r34; var r86 = r44 | r24; var r87 = 1 & 2; var r88 = 6 - 8; var r89 = r43 & r61; var r90 = r21 % r70; var r91 = r31 | r46; print(r83); var r92 = r18 * 2; var r93 = r14 + r26; var r94 = 7 ^ r38; var r95 = 1 / r57; var r96 = r84 | 4; a6 = a2 + r20; r8 = 4 % r13; var r97 = r2 / r37; var r98 = r94 ^ r58; var r99 = 3 - r79; var r100 = 6 % r10; var r101 = 4 * r17; var r102 = r58 % r95; r95 = 0 - 0; var r103 = r16 / 5; var r104 = 9 + r48; var r105 = r83 / r48; var r106 = 6 - 9; var r107 = 7 | r15; var r108 = r107 & r42; var r109 = r25 - r90; var r110 = r47 / r11; var r111 = r72 / 2; r67 = r60 & r76; print(r11); var r112 = r51 | r2; print(r27); print(x); var r113 = r72 * r22; var r114 = r76 / r84; var r115 = 3 + 9; var r116 = r4 * 2; var r117 = 7 / r77; var r118 = r84 / r99; var r119 = a4 ^ 7; r30 = r68 * r96; r82 = r20 / 2; var r120 = 9 / r51; var r121 = 5 % 9; var r122 = r115 & r78; var r123 = 9 - r119; var r124 = r66 * r39; print(a3); var r125 = r37 - r75; r25 = r65 + r88; var r126 = r32 & a2; var r127 = r33 ^ 5; var r128 = 8 & r109; print(r101); r77 = 2 * r97; var r129 = r54 & r49; var r130 = r127 / r39; var r131 = 8 ^ r0; var r132 = r65 & r18; var r133 = r107 * 9; var r134 = r42 % 4; var r135 = r119 & 6; var r136 = a1 | r108; var r137 = 6 % r18; var r138 = r102 & r102; r5 = 5 ^ 9; var r139 = a2 & 4; var r140 = r114 - r108; var r141 = 0 ^ 7; r4 = 1 - 8; var r142 = 0 + r59; var r143 = 3 * 9; r20 = r132 | r10; var r144 = r135 | r54; var r145 = r104 ^ r70; var r146 = r75 & a1; var r147 = r123 % r143; var r148 = r146 + 8; var r149 = r104 - r100; print(r33); r123 = r83 | 7; r11 = 1 * 5; r126 = r66 ^ 0; print(r9); var r150 = 8 + r9; var r151 = r60 ^ 6; var r152 = 0 / 1; var r153 = a0 + r104; var r154 = r119 + 1; r92 = r67 - r150; return a1; }));");
/*fuzzSeed-211892750*/count=303; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.max(Math.acos(Math.fround(Math.min(y, x))), Math.fround((Math.fround((y >> y)) <= x))) != (Math.fround(((Math.hypot((42 | 0), (x | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-(2**53), 2**53-2, 0, 0x07fffffff, Number.MAX_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, 1, 0x080000001, Math.PI, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, 1/0, -(2**53-2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0.000000000000001, 0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -1/0, -0, 0x100000000, -0x07fffffff, 0/0, 2**53, -Number.MIN_VALUE, 42]); ");
/*fuzzSeed-211892750*/count=304; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! Math.atan2((( + ( - ((( ~ (y | 0)) >>> 0) >>> 0))) >>> 0), ( ! (Math.max(y, (Math.ceil((Math.max(y, Math.fround(Math.asin((0.000000000000001 >>> 0)))) | 0)) | 0)) >>> 0)))); }); ");
/*fuzzSeed-211892750*/count=305; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[(void 0), (void 0), new String('q')]); ");
/*fuzzSeed-211892750*/count=306; tryItOut("with( \"\" )window;");
/*fuzzSeed-211892750*/count=307; tryItOut("\"use strict\"; /*infloop*/for(d = ({x:  '' }); (uneval((\u3056--))); false) {v0 = evaluate(\"mathy2 = (function(x, y) { \\\"use strict\\\"; return Math.fround(Math.trunc(((Math.fround(Math.min(( + Math.pow(( + x), ( + ( + x)))), x)) ? Math.fround(( ~ Math.fround(0/0))) : Math.fround(Math.atan2(Math.log10(-0x100000001), y))) !== ((( - ( + Math.sqrt(( + x)))) || ( ~ y)) ? ( - ( + (((( + (Math.atan2((x | 0), x) | 0)) < (x | 0)) >>> 0) ? 0x0ffffffff : Number.MAX_SAFE_INTEGER))) : (x ? Math.acosh(( + Math.max(-0x0ffffffff, -0x100000000))) : Math.fround(Math.imul(x, y))))))); }); \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: eval, noScriptRval: false, sourceIsLazy: (x % 5 != 1), catchTermination: (d % 10 == 5), element: o1 }));for (var p in m2) { for (var v of h1) { try { i0.next(); } catch(e0) { } g0.offThreadCompileScript(\"a1.reverse();\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: false })); } } }");
/*fuzzSeed-211892750*/count=308; tryItOut("let x = ((makeFinalizeObserver('tenured')));this.v1 = Array.prototype.reduce, reduceRight.apply(a0, [(function() { try { g2.offThreadCompileScript(\"function g1.f1(f0) \\\"use asm\\\";   function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    return ((-(i1)))|0;\\n  }\\n  return f;\", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 3 == 2), sourceIsLazy: false, catchTermination: false, sourceMapURL: s0 })); } catch(e0) { } v1 = a2.length; return t1; })]);\nvar wdrpiz = new SharedArrayBuffer(0); var wdrpiz_0 = new Int32Array(wdrpiz); print(wdrpiz_0[0]); var wdrpiz_1 = new Uint32Array(wdrpiz); print(wdrpiz_1[0]); var wdrpiz_2 = new Uint16Array(wdrpiz); var wdrpiz_3 = new Uint32Array(wdrpiz); wdrpiz_3[0] = 28; var wdrpiz_4 = new Float32Array(wdrpiz); var wdrpiz_5 = new Int8Array(wdrpiz); print(wdrpiz_5[0]); e0.toString = (function mcc_() { var dhluce = 0; return function() { ++dhluce; if (/*ICCD*/dhluce % 9 == 4) { dumpln('hit!'); try { v2 = (h0 instanceof g0); } catch(e0) { } f0.valueOf = (function(j) { if (j) { try { for (var v of g2.g0.o1) { try { /*ODP-3*/Object.defineProperty(b1, \"getMilliseconds\", { configurable: true, enumerable: true, writable: eval, value: m2 }); } catch(e0) { } a2 = t0[({valueOf: function() { o0.e2.toSource = String.prototype.toLowerCase.bind(b0);return 9; }})]; } } catch(e0) { } try { (void schedulegc(this.g0)); } catch(e1) { } try { t1[\"\\u5291\"] = this.i1; } catch(e2) { } g0.v1 = r1.compile; } else { try { h0.delete = f2; } catch(e0) { } v1 = 4.2; } }); } else { dumpln('miss!'); try { a0[11] = \"\\uFB75\"; } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(v1, f1); } };})();thisprint(wdrpiz_5);var a1 = new Array;const b = this;\n");
/*fuzzSeed-211892750*/count=309; tryItOut("\"use strict\"; v1 = g1.t1.length;");
/*fuzzSeed-211892750*/count=310; tryItOut("testMathyFunction(mathy3, [Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, 0x100000001, -0x0ffffffff, 0x100000000, 0, 0x07fffffff, Number.MAX_VALUE, 1/0, 1, -Number.MAX_VALUE, 2**53+2, 2**53-2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x100000001, -1/0, -0x080000000, -0x07fffffff, 2**53, Math.PI, 42, -(2**53), -(2**53-2), 0/0, -(2**53+2), -0, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001]); ");
/*fuzzSeed-211892750*/count=311; tryItOut("g0.a0 = arguments;");
/*fuzzSeed-211892750*/count=312; tryItOut("o2 = new Object;");
/*fuzzSeed-211892750*/count=313; tryItOut("x;");
/*fuzzSeed-211892750*/count=314; tryItOut("this.e0.delete((4277));");
/*fuzzSeed-211892750*/count=315; tryItOut("\"use strict\"; o2.s1.toString = (function(j) { if (j) { try { for (var p in g1) { try { ; } catch(e0) { } v1 = Array.prototype.some.call(g2.o0.o1.g1.o2.a1, (function(j) { f2(j); })); } } catch(e0) { } try { v0 = r2.exec; } catch(e1) { } try { this.v1 = (b1 instanceof t1); } catch(e2) { } o0.a2.shift(); } else { for (var v of v0) { try { s0 += g1.s0; } catch(e0) { } try { this.s1 += 'x'; } catch(e1) { } try { o0 + ''; } catch(e2) { } e1.has(o1.b1); } } });");
/*fuzzSeed-211892750*/count=316; tryItOut("mathy3 = (function(x, y) { return (( ! (( + (Math.asinh(Math.pow(( + (( + x) >> ( + x))), Math.fround(Math.PI))) > Math.fround(Math.atanh(Math.fround(0x07fffffff))))) === (Math.log1p(x) + Math.fround((((( ~ ((( - y) | 0) >>> 0)) >>> 0) | 0) || y))))) | 0); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, -0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, -(2**53), -0x07fffffff, -0x080000000, 1.7976931348623157e308, 2**53-2, 0x080000000, 0, -Number.MIN_SAFE_INTEGER, -1/0, 1, 0/0, 0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), 0x080000001, 42, 1/0, -0x100000001, -0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, 2**53]); ");
/*fuzzSeed-211892750*/count=317; tryItOut("mathy4 = (function(x, y) { return Math.fround(( - Math.max((Math.fround(Math.expm1(Math.fround(((Math.sinh((( - y) == x)) | 0) | y)))) >>> 0), Math.exp(( + Math.pow((Math.fround(( + ((Math.min(x, (x >>> 0)) ? x : y) >>> 0))) >>> 0), x)))))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, 42, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, 0x080000001, 0/0, Math.PI, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, 2**53, -(2**53+2), 1, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, -0x080000000, 0x080000000, 1/0, -1/0, -0x100000001, -Number.MAX_VALUE, 0, 1.7976931348623157e308, -0, 0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-211892750*/count=318; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.round(Math.expm1(( + (Math.sinh(2**53+2) , Math.fround(Math.log2(Math.imul(x, y))))))) >>> 0); }); ");
/*fuzzSeed-211892750*/count=319; tryItOut("e0.has(e2);");
/*fuzzSeed-211892750*/count=320; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + ( - ( + (((Number.MIN_SAFE_INTEGER >>> (( ~ Math.pow(Math.atan(( + x)), 1.7976931348623157e308)) | 0)) | 0) | 0)))) >>> 0); }); testMathyFunction(mathy0, [0.000000000000001, 0x0ffffffff, -(2**53), -0x100000001, -1/0, 0, Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, 42, -0x100000000, -0x080000000, 0x080000000, 0x100000001, -0x080000001, 0x07fffffff, 0x100000000, -0x07fffffff, -(2**53-2), 0/0, 2**53, Number.MAX_VALUE, 1, -Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, -0x0ffffffff, Number.MIN_VALUE, -(2**53+2), 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=321; tryItOut("\"use strict\"; { void 0; setIonCheckGraphCoherency(false); }");
/*fuzzSeed-211892750*/count=322; tryItOut("L:do this.m0.set(p0, t1);(\"\\u0FE6\"); /x/g ; while((x) && 0);");
/*fuzzSeed-211892750*/count=323; tryItOut("\"use strict\"; testMathyFunction(mathy0, ['0', /0/, true, (new Number(-0)), -0, (new String('')), '\\0', [], 0, (new Boolean(true)), (function(){return 0;}), ({valueOf:function(){return '0';}}), '/0/', null, ({valueOf:function(){return 0;}}), false, 0.1, (new Boolean(false)), '', ({toString:function(){return '0';}}), objectEmulatingUndefined(), undefined, 1, NaN, (new Number(0)), [0]]); ");
/*fuzzSeed-211892750*/count=324; tryItOut("ipsgbu, x = x, x, x = (4277), NaN = arguments, qsroqx;Array.prototype.push.call(a2, s1, b1);");
/*fuzzSeed-211892750*/count=325; tryItOut("mathy1 = (function(x, y) { return ((((( - Math.pow(Math.pow((x >>> 0), ((y == x) - (x || -1/0))), ( ~ ( ! (x != (y >>> 0)))))) | 0) >>> 0) != ((((Math.fround((Math.fround(y) & ((Math.fround(y) / Math.fround(( + Math.atan2(( + x), Number.MIN_SAFE_INTEGER)))) >>> 0))) >>> 0) ^ (mathy0((x > y), ( ! (y <= 0x07fffffff))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[0x50505050, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), false, 0x50505050, 0x50505050, 0x50505050, objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), 0x50505050, 0x50505050, x, x, false, objectEmulatingUndefined(), x, (1/0), 0x50505050, false, x, objectEmulatingUndefined(), 0x50505050, false, objectEmulatingUndefined()]); ");
/*fuzzSeed-211892750*/count=326; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=327; tryItOut("Array.prototype.push.apply(a0, [v2, s0, v2, t0]);");
/*fuzzSeed-211892750*/count=328; tryItOut("i0.toString = f0;");
/*fuzzSeed-211892750*/count=329; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ((Math.fround((Math.fround(((y << x) ? Math.fround((( + x) ** ( + ((y > x) >>> 0)))) : Math.cos(0x080000001))) ? Math.fround(y) : Math.log1p(x))) | 0) === (( + x) >>> 0))); }); testMathyFunction(mathy3, [-(2**53+2), 1/0, -Number.MAX_VALUE, 0, 2**53-2, 1.7976931348623157e308, -0x080000001, 0x100000000, -0x100000001, 0/0, -(2**53), Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0, 42, -0x100000000, 0x0ffffffff, 2**53, -0x0ffffffff, -0x07fffffff, 1, 0x080000000, 0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff]); ");
/*fuzzSeed-211892750*/count=330; tryItOut("print(true);function y(x, b) { return (4277) } print(x);");
/*fuzzSeed-211892750*/count=331; tryItOut("\"use strict\"; new RegExp(\"\\\\3\", \"im\");");
/*fuzzSeed-211892750*/count=332; tryItOut("Array.prototype.push.call(a0, g2);");
/*fuzzSeed-211892750*/count=333; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.imul(Math.hypot((mathy1(Math.fround(Math.atan2(Math.fround(Math.trunc(( + y))), ( ! ( + Math.round(( + x)))))), -(2**53+2)) | 0), x), ( ~ Math.atan2(((mathy0((x >>> 0), 0x0ffffffff) >>> 0) >>> 0), 1/0))) ? Math.hypot(Math.pow((Math.fround(mathy0(Math.fround(Math.sin(1)), Math.fround(((( + x) == y) >>> 0)))) >>> 0), ( + ( ~ y))), ((( ! (Math.fround(Math.clz32((0.000000000000001 >>> 0))) | 0)) | 0) * mathy1(( + y), ( + 0x100000000)))) : (Math.log10(((( + ((( ~ (((x > ((-(2**53-2) | ((y | 0) ? (y >>> 0) : y)) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-211892750*/count=334; tryItOut("(void schedulegc(o1.g1));");
/*fuzzSeed-211892750*/count=335; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.max(( - Math.atan2(Math.fround(x), Math.fround(x))), mathy3((mathy1(( ~ (((Math.atan2((0x100000001 >>> 0), y) >>> 0) ? (x >>> 0) : Math.fround(y)) >>> 0)), ( + ( + (((Math.exp((Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) | 0) % (( + Math.cos(Math.cbrt(y))) | 0))))) >>> 0), (x >>> 0)))); }); testMathyFunction(mathy4, /*MARR*/[ '\\0' , 0.1,  '\\0' ,  '\\0' ,  '\\0' , 0.1, 0.1, null,  '\\0' , 0.1, 0.1, 0.1, null, null, 0.1, 0.1, 0.1, 0.1, 0.1, null, 0.1, 0.1,  '\\0' ,  '\\0' , null, 0.1, 0.1, null, 0.1,  '\\0' ,  '\\0' ,  '\\0' , 0.1,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1,  '\\0' , null, 0.1,  '\\0' , null,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , 0.1, null, null, 0.1, 0.1, null, null, 0.1,  '\\0' , 0.1, null, 0.1, 0.1,  '\\0' ,  '\\0' , 0.1, null,  '\\0' , 0.1,  '\\0' , 0.1, 0.1, null, 0.1, null, null, 0.1, 0.1,  '\\0' ]); ");
/*fuzzSeed-211892750*/count=336; tryItOut("mathy3 = (function(x, y) { return (Math.hypot((Math.cos((( ~ ( - Math.fround(Math.pow(Math.fround(y), Math.fround((y ? Math.fround(x) : x)))))) | 0)) >>> 0), Math.atan2(((( + -1/0) > y) && ((Math.max((x | 0), ( + 2**53+2)) | 0) >>> 0)), ( + Math.min(mathy1(Math.fround((mathy1(x, x) >>> 0)), Math.imul(y, ( + y))), y)))) >>> 0); }); testMathyFunction(mathy3, [1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, -0x100000001, -0, -1/0, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, -0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0x100000001, 0/0, 2**53+2, 0x0ffffffff, 0x080000001, 0x100000000, 1.7976931348623157e308, Math.PI, 0x07fffffff, 2**53, 42, -(2**53), -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), -0x080000001, -Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-211892750*/count=337; tryItOut("\"use strict\"; m2.set(h2, NaN);");
/*fuzzSeed-211892750*/count=338; tryItOut("mathy4 = (function(x, y) { return mathy1((Math.tan(( - x)) | (( ! (Math.atan2((0x080000001 >>> 0), (x >>> 0)) && Math.fround(1/0))) | 0)), (((( ~ ((( ! x) | 0) >>> 0)) | 0) % ((mathy1(Math.fround((Math.fround(y) * (x >>> 0))), ( + y)) || ( + (Math.hypot((y >>> 0), (Math.log10(x) >>> 0)) >>> 0))) | 0)) | 0)); }); testMathyFunction(mathy4, [(new Boolean(true)), null, 0.1, undefined, ({toString:function(){return '0';}}), '\\0', -0, /0/, NaN, '', ({valueOf:function(){return 0;}}), (new Number(-0)), [0], ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(false)), '/0/', true, (new Number(0)), 1, '0', 0, [], (new String('')), false, (function(){return 0;})]); ");
/*fuzzSeed-211892750*/count=339; tryItOut("e2.has(p1);");
/*fuzzSeed-211892750*/count=340; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2*|(?!((?:[^])))|\\\\2\", \"m\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-211892750*/count=341; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-211892750*/count=342; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var cos = stdlib.Math.cos;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\nh0.get = (function(j) { if (j) { try { a2.push(a1, b1, o0.o2.o2); } catch(e0) { } try { selectforgc(o2); } catch(e1) { } m2.has(o0.e1); } else { try { Array.prototype.splice.apply(a0, [NaN, \"\\u4822\"]); } catch(e0) { } try { v2 = r1.ignoreCase; } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(e2, o2); } catch(e2) { } e0.add(g0.s1); } });    return +((Float32ArrayView[((i1)-(0xffffffff)) >> 2]));\n    i1 = (i0);\n    i0 = ((i0) ? ((+cos(((((-281474976710656.0)) - ((Float32ArrayView[0])))))) < (((+((Float32ArrayView[0])))) % ((+((34359738369.0)))))) : ((i1) ? ((Float64ArrayView[2])) : (((((0xf8a91cf6) ? (0x8077fa58) : (-0x8000000)))>>>((i0))))));\n    i1 = ((-0x4760293));\n    i0 = ((imul((i0), (i0))|0) > (abs((0xf127346))|0));\n    i1 = (i1);\n    i0 = (/*FFI*/ff(((abs((imul((0xfcd13c5b), (i1))|0))|0)), ((abs((((i1)-((~~(((-140737488355329.0)) - ((3.0)))))+((0xe1fd022d) <= (((-0x8000000))>>>((0xdfcb5604))))) >> ((i1)+(i1)-((imul((0xf864f000), (0xaca0d37a))|0)))))|0)), ((-9007199254740992.0)), (((((0x122cc8ef) != (imul((0xc05fe8ff), (0xf8f8237a))|0))) & ((0x6bda6b14) / (((0x749e7ea9))>>>((0x590791a5)))))), ((1.0)), ((((i1)*-0x3bbb8) & ((0xbfb7bd5d) / (0xffffffff)))), ((+(-1.0/0.0))), ((imul((0xffffffff), (0x4f9cfc86))|0)), (((void version(180)))), ((-1099511627777.0)))|0);\n    {\n      (Int32ArrayView[4096]) = ((/*FFI*/ff(((((/*FFI*/ff((((((0x61a7a9b7) <= (-0x8000000))-(i0))|0)), ((((i0)) << ((eval = ((makeFinalizeObserver('tenured')).yoyo(x++)))))), ((((0xfc750585)) & ((0xe6f06a1)))))|0)+(0x3889b478)) ^ ((0xec9c6b25)))), ((549755813889.0)), ((-549755813889.0)), ((~~(-3.0))), ((~~(+/*FFI*/ff()))), ((((Uint16ArrayView[((0x8176ea30)) >> 1]))|0)), ((-7.555786372591432e+22)), (((0x71da15b) ? (-9.671406556917033e+24) : (-513.0))), ((-18014398509481984.0)))|0)+((((i0)-(i0))>>>((!(i1)))) == (0x6f4cf33e)));\n    }\n    (Uint32ArrayView[0]) = ((i0)-((0x3271eb44)));\n    i0 = (/*FFI*/ff(((((((i0) ? (i0) : (i1)) ? (i0) : (i1))) << ((~~(+abs(((1152921504606847000.0))))) / (0x204a638f)))))|0);\n    i1 = (i1);\n    i0 = (i1);\n    i1 = (((((((0xffffffff)) | ((0xf7e14026))) < (((0xafb96a49)-(0xff12461d))|0))-(i1)+(i0))>>>(((0xbffd86eb) <= ((i0)))+((0x43ddb1eb) < (0xffffffff)))) != (((i1)+(i1))>>>((Int8ArrayView[2]))));\n    (Float32ArrayView[(((-0x5a4a4*((0x3edb8afe)))>>>((0x59bfc2d1) / (0x25675275))) % (0x90b42aa9)) >> 2]) = ((((2.3611832414348226e+21)) % ((-2049.0))));\n    i1 = (((0x4398c*(i0))>>>((((/*FFI*/ff(((~((0x94420b75)))), ((4503599627370495.0)), ((-262145.0)), ((-134217729.0)))|0)) ^ ((0x795c619e)-(-0x8000000)+(0xfd00459c))) / ((((-68719476735.0) >= (2199023255552.0))*-0xd4601) ^ (x)))) > (0xb7c9a6d1));\n    {\n      return +((((+((1073741825.0)))) / ((8796093022209.0))));\n    }\n    (Uint32ArrayView[((((0xfe3ee9e0)+(0x9c6d09eb)+(0xa782198))>>>((0x28aa7563) % (0xf634fd7e))) % (((i0)-(i1))>>>((i1)))) >> 2]) = ((!(((abs((imul((0x602205ca), (0xa11827aa))|0))|0)) ? (i0) : ((((0xbe890e54)) ^ ((0xf8a22bb3))) == (~~(16777216.0)))))-(i0)-(i1));\n    (Uint8ArrayView[2]) = (((+(0x565efa16)) < (+(1.0/0.0))));\n    return +((+(imul(((0xcf46652) != (0x184aa0e7)), (/*FFI*/ff(((NaN)), ((((i1)) ^ (0x66a88*((0x9719f7d8) != (0x0))))), ((((i1)) >> ((i1)+(i1)))))|0))|0)));\n  }\n  return f; })(this, {ff: Boolean.prototype.toString}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [({toString:function(){return '0';}}), (new Number(-0)), 0.1, [], 1, false, -0, NaN, '', '\\0', (function(){return 0;}), true, '/0/', (new Boolean(true)), 0, undefined, null, (new String('')), objectEmulatingUndefined(), (new Number(0)), /0/, ({valueOf:function(){return 0;}}), [0], ({valueOf:function(){return '0';}}), '0', (new Boolean(false))]); ");
/*fuzzSeed-211892750*/count=343; tryItOut("\"use strict\"; for (var v of v1) { try { /*iii*/v0 = (p2 instanceof p0);/*hhh*/function ffztti(x = (Math.cbrt(6)), x = function ([y]) { }.watch(\"ceil\", DataView.prototype.setUint16)){v0 = 0;} } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(o1.p0, o0.v2); } catch(e1) { } v0 = a2.some((function() { f0 = f1; return s0; }), v2); }");
/*fuzzSeed-211892750*/count=344; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ! Math.fround(Math.fround(mathy0(Math.fround(( ~ ( + y))), Math.fround(Math.min(Math.fround((Math.min((Math.hypot(Math.fround(y), x) | 0), y) >>> ((y < x) >= Math.fround(Math.atan2(Math.fround(( + (( + y) < ( + x)))), Math.fround(x)))))), Math.expm1(x)))))))); }); ");
/*fuzzSeed-211892750*/count=345; tryItOut("s1.__proto__ = g2;");
/*fuzzSeed-211892750*/count=346; tryItOut("g0.v1 = Array.prototype.every.apply(a0, [(function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) { var r0 = 0 & a12; a8 = 4 / a15; a6 = a4 - 3; var r1 = a2 & a11; a4 = a11 + 2; var r2 = a11 % 5; var r3 = 6 * a12; var r4 = 7 * a3; var r5 = 0 % 6; var r6 = 5 % 6; var r7 = r1 + a15; var r8 = 9 | 5; var r9 = 2 * 5; var r10 = r5 - 3; var r11 = 3 & r5; var r12 = 4 - a3; a11 = 6 % 4; a4 = 9 & 1; var r13 = a0 ^ a8; a7 = 3 ^ a7; var r14 = r7 + a10; var r15 = a1 - a0; a10 = x | a3; var r16 = a4 + 2; a9 = r7 + 2; var r17 = x * r11; var r18 = 9 / r8; var r19 = r13 - a8; var r20 = a11 | a5; var r21 = 9 + a3; a15 = r1 * 2; r1 = a12 / a1; var r22 = 6 * a1; var r23 = r6 ^ r5; var r24 = r6 * r19; var r25 = 2 / a10; var r26 = 2 * r6; var r27 = r18 - a11; var r28 = 2 + 0; r6 = 9 ^ r9; var r29 = 5 + a13; var r30 = a10 ^ a16; var r31 = r6 / 2; var r32 = 8 & r3; var r33 = 7 ^ r28; r4 = 1 ^ r25; a1 = a10 * r29; var r34 = 8 - a10; var r35 = 7 | 0; r15 = r19 | a6; var r36 = r4 & 6; r18 = 2 & r3; var r37 = a13 - r3; var r38 = a14 ^ r5; var r39 = r3 & 1; var r40 = a12 - r1; var r41 = 8 / r22; r18 = 8 - a9; a11 = r40 & 3; var r42 = 0 ^ r34; var r43 = a1 | 9; var r44 = r35 + 9; var r45 = 7 + r31; r34 = r34 % r20; r19 = r21 & a16; var r46 = 5 / 9; var r47 = a6 & r5; r20 = r17 / 6; var r48 = 0 % r45; var r49 = r38 % 9; var r50 = a3 | 1; var r51 = r3 | a15; var r52 = r21 - r25; var r53 = r16 + 5; var r54 = r33 ^ a16; a8 = a12 - a3; var r55 = 3 % 9; var r56 = 9 % r31; var r57 = 3 % r53; var r58 = 0 % r31; var r59 = a15 & 7; var r60 = a0 - 6; var r61 = 9 & 7; r56 = r61 - r54; print(r26); var r62 = 6 & r35; var r63 = r4 | r15; var r64 = 2 + r40; r18 = 5 - r10; print(r35); var r65 = r52 * 4; var r66 = r64 / r65; var r67 = r12 % r51; var r68 = r43 * 5; r13 = r30 % r46; var r69 = r7 | 6; var r70 = r55 - a0; var r71 = 4 * 7; var r72 = r24 + 3; print(r58); var r73 = r11 % 8; var r74 = 6 - r66; var r75 = 8 - r53; print(r4); var r76 = a12 & r1; var r77 = 9 * r27; var r78 = r12 | a10; var r79 = r10 * 5; var r80 = 4 | a3; var r81 = 0 ^ r64; var r82 = r16 ^ a0; var r83 = r25 + r6; var r84 = a13 * 6; var r85 = r76 * r20; print(a3); var r86 = 3 / 1; var r87 = 2 ^ a3; var r88 = r69 % r75; var r89 = 7 ^ r10; a10 = 0 + r30; var r90 = 5 * r85; var r91 = r89 & r11; var r92 = r55 | r7; var r93 = 5 | 8; r58 = a10 / r6; var r94 = a13 - r1; var r95 = a14 % r50; var r96 = r35 + a7; var r97 = r10 * r16; r32 = r25 / r62; var r98 = r43 * r22; print(r62); var r99 = r19 ^ r51; r10 = 4 ^ 0; var r100 = r87 * r78; var r101 = r99 & 0; var r102 = r53 % 6; var r103 = r1 % a13; var r104 = 1 ^ 4; var r105 = r30 * r77; var r106 = r19 / a3; var r107 = 6 / a4; var r108 = 3 * r58; var r109 = r93 / r80; var r110 = r52 / r83; var r111 = 5 - r7; var r112 = r102 * 6; var r113 = r46 - r36; var r114 = 7 % 7; var r115 = r0 + r34; var r116 = r61 / r109; var r117 = r103 | 1; var r118 = 2 - a12; var r119 = a11 / r57; var r120 = r53 + 1; print(r42); var r121 = r116 * r7; var r122 = r111 + r34; r97 = r60 % r53; var r123 = a6 ^ r98; return a11; })]);");
/*fuzzSeed-211892750*/count=347; tryItOut("h2 + '';");
/*fuzzSeed-211892750*/count=348; tryItOut("\"use asm\"; with({}) with({}) { let(d, w =  \"\" , x, gbjjfd, islxoo, x) { x.name;} } \ng2 + '';\n");
/*fuzzSeed-211892750*/count=349; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((mathy1((( + (( + ((y && Math.cbrt(x)) | 0)) , mathy1(x, x))) >>> 0), (mathy2(Math.tanh(x), Math.abs((mathy1((x | 0), (x | 0)) | 0))) >>> 0)) >>> 0) - Math.imul(Math.fround(Math.cosh(Math.fround((Math.tanh(( + ( ! ( + (Math.hypot((x | 0), (0x080000000 | 0)) | 0))))) | 0)))), (Math.fround(Math.max(Math.fround(x), Math.fround((Math.log2(((( + x) ** ( + x)) >>> 0)) >>> 0)))) >> y))); }); testMathyFunction(mathy3, [-0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -0x100000001, -(2**53), 1, -0x100000000, 2**53, 0/0, Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, 0x080000001, 42, -(2**53+2), 2**53+2, 1/0, 0x100000001, 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, -0, Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, -0x0ffffffff, -(2**53-2), Math.PI, -Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=350; tryItOut("testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0x100000001, 0, Number.MIN_VALUE, 0/0, -0x100000000, Math.PI, -0x07fffffff, -0, Number.MAX_VALUE, -(2**53-2), -0x080000000, 42, 1, -0x0ffffffff, -(2**53), 2**53, 0x0ffffffff, 0x07fffffff, 2**53-2, -0x100000001, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000000, -0x080000001, -1/0]); ");
/*fuzzSeed-211892750*/count=351; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ! mathy1((Math.cos((( + Math.sign(y)) ? 0x100000001 : Math.asinh(Math.fround(Math.asin((x / y)))))) | 0), Math.atan(Math.asinh(y)))); }); testMathyFunction(mathy3, [Math.PI, -0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 1.7976931348623157e308, 1/0, 2**53, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, 0x100000000, -0x080000000, Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, 1, 0x07fffffff, 42, -(2**53-2), 0x0ffffffff, 0/0, 0x080000000, 0, -0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 0x080000001]); ");
/*fuzzSeed-211892750*/count=352; tryItOut("testMathyFunction(mathy2, [0x080000000, -0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, -0x080000000, -0x07fffffff, Number.MAX_VALUE, -(2**53), 2**53+2, 2**53, 0/0, Number.MIN_VALUE, -(2**53+2), 0x100000001, 1.7976931348623157e308, -(2**53-2), 1, -Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, -0x080000001, 2**53-2, 42, 0x100000000, 0x07fffffff, 0, 0x080000001, -0, Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-211892750*/count=353; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((Math.fround(( ~ (y | 0))) * Math.atan2(Number.MIN_VALUE, (y | 0))) - ( + mathy0(/\\2{2}/gy, (Math.sqrt(Math.cbrt(Math.sign(x))) >>> 0)))); }); testMathyFunction(mathy2, [-0x100000001, 0x100000000, 1, 0x100000001, 1/0, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, -(2**53-2), 42, 2**53+2, 0.000000000000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), -0x100000000, 0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -0, -Number.MIN_VALUE, 2**53-2, 0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, Math.PI]); ");
/*fuzzSeed-211892750*/count=354; tryItOut("var ygrjww = new SharedArrayBuffer(8); var ygrjww_0 = new Float64Array(ygrjww); var ygrjww_1 = new Float64Array(ygrjww); print(ygrjww_1[0]); s2 += s1;t1.set(a0, ({}));");
/*fuzzSeed-211892750*/count=355; tryItOut("v0 = o1.r1.test;");
/*fuzzSeed-211892750*/count=356; tryItOut("Array.prototype.reverse.call(a1);");
/*fuzzSeed-211892750*/count=357; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ( + ( ! ( + Math.fround(( + (Math.tan(( + ( - 42))) >>> 0)))))); }); testMathyFunction(mathy1, [2**53+2, -(2**53), 0x100000001, 1, -0x100000000, -0x07fffffff, 2**53, -Number.MAX_VALUE, -0x080000001, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 0x100000000, 0.000000000000001, 0x0ffffffff, Number.MAX_VALUE, -0, Number.MIN_VALUE, 0x080000001, 0, 2**53-2, Math.PI, 0x080000000, -(2**53-2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53+2), 42, -0x100000001, 1/0, 0/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=358; tryItOut("\"use strict\"; \"use strict\"; t1[({valueOf: function() { return;return 16; }})] = g0.g2.g2.i0;");
/*fuzzSeed-211892750*/count=359; tryItOut("for (var p in v0) { t2 = new Uint16Array(v2); }");
/*fuzzSeed-211892750*/count=360; tryItOut("mathy2 = (function(x, y) { return Math.fround(( - ( + ( - ( + (Math.pow(( + mathy0(( ~ (( + (y | 0)) | 0)), y)), y) ^ ( + ( + Math.pow((-Number.MAX_SAFE_INTEGER / x), Math.PI))))))))); }); testMathyFunction(mathy2, [-0, -0x100000000, -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, -0x100000001, 42, 2**53-2, -(2**53-2), -0x0ffffffff, 0, -0x080000001, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, 1, 0x100000000, Number.MAX_VALUE, 0x07fffffff, -1/0, -(2**53), 0x100000001, 2**53+2, Math.PI, Number.MIN_VALUE, 0/0, -0x07fffffff]); ");
/*fuzzSeed-211892750*/count=361; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((Float32ArrayView[2]));\n  }\n  return f; })(this, {ff:  /x/ }, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0, 1, 0x080000000, Number.MAX_VALUE, 0x100000000, 0/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, -0x07fffffff, -1/0, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 2**53-2, 2**53+2, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, 0x100000001, 42, 1/0, Number.MIN_VALUE, -(2**53-2), -0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-211892750*/count=362; tryItOut("Array.prototype.forEach.call(a0, f0, this.b0, this.s1);");
/*fuzzSeed-211892750*/count=363; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    (Uint32ArrayView[1]) = (((imul(((0x74bd6783) <= (0x626602d4)), ((makeFinalizeObserver('nursery'))))|0))-(/*FFI*/ff()|0)-(i1));\n    return +((65.0));\n    i1 = (i0);\n    i0 = (((i0) ? (i1) : (0xfea06b1e)) ? (i1) : (i1));\n    i1 = (i1);\n    return +((((Infinity)) - ((( - ( + (( ~ (Math.imul(((Math.fround((Math.fround(x) >>> Math.fround(x))) ? ((Math.min((1 | 0), ( + x)) | 0) >>> 0) : (x != -Number.MAX_VALUE)) | 0), Math.fround(( ~ (( ~ (( ~ x) >>> 0)) >>> 0)))) | 0)) | 0)))))));\n  }\n  return f; })(this, {ff: Math.acosh}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, 0x100000001, 1.7976931348623157e308, 0x080000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 0x07fffffff, 2**53+2, 1, 42, Number.MAX_VALUE, 2**53-2, -(2**53+2), -0, 0x100000000, Math.PI, -0x080000000, 0x080000001, 2**53, 1/0, -Number.MIN_VALUE, -0x080000001, 0]); ");
/*fuzzSeed-211892750*/count=364; tryItOut("\"use strict\"; i0.send(g1);");
/*fuzzSeed-211892750*/count=365; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan = stdlib.Math.atan;\n  var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    i0 = (i0);\n    i0 = (i0);\n    i1 = (i1);\n    return (((i0)-(i0)-(/*FFI*/ff(((((/*FFI*/ff(((-6.189700196426902e+26)), ((abs((((0xfcca2ffa))|0))|0)), ((((0x63db4f36)) << ((0xf85b34c6)))), ((-131071.0)))|0)-((0xffffffff))) ^ ((i1)))), ((+atan(((-524289.0))))), ((+((+pow(((+(((-0x8000000)) ^ ((0x593ad005))))), ((((0.03125)) / ((-4.722366482869645e+21))))))))), ((((i0)-(/*FFI*/ff(((1.2089258196146292e+24)), ((18014398509481984.0)), ((-1048577.0)), ((0.0009765625)), ((-281474976710657.0)), ((1.5111572745182865e+23)), ((-65537.0)), ((18446744073709552000.0)), ((-2199023255553.0)))|0))|0)), ((-1.888946593147858e+22)), ((1.5474250491067253e+26)), ((imul((0x722f8233), (0x77a333e3))|0)), ((-2305843009213694000.0)), ((-9223372036854776000.0)), ((140737488355329.0)), ((-1152921504606847000.0)), ((-0.125)), ((8388609.0)), ((7.555786372591432e+22)), ((4611686018427388000.0)), ((-2199023255553.0)))|0)))|0;\n    i1 = (((-(((((0xff2bed20))>>>((0xffffffff))) < (((0x29f9918f))>>>((0x670e759d)))) ? ((0x211a9441) == (~((-0x62bf079)))) : ((0xfb06d4fd) ? (0x8ead8c61) : (0xf8d975ec))))>>>((i0))));\n    i0 = (/*FFI*/ff()|0);\n    i0 = (0xf860cadd);\n    i0 = (((+abs(((((3.022314549036573e+23)) - ((-549755813889.0))))))));\n    i1 = (0xfe2b3c5b);\n    (Float32ArrayView[(-(i0)) >> 2]) = ((-1.0625));\n    i1 = ((i0) ? (0xfbb316b5) : (i1));\n    (Float32ArrayView[0]) = ((-16.0));\n    i0 = (i1);\n    ((makeFinalizeObserver('tenured'))) = ((((i0)+((0x6a80ee39) == ((((0x74b010a4))-(i1))>>>(((18014398509481984.0) > (-4194305.0))+(i0)))))|0) % (~~(+pow(((6.044629098073146e+23)), ((Float32ArrayView[(((0xe93b7586) < (0x0))-(({\"11\": {} }))) >> 2]))))));\n    return ((yield new window()))|0;\n  }\n  return f; })(this, {ff: w =>  { yield timeout(1800) } }, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-211892750*/count=366; tryItOut("a0.pop();");
/*fuzzSeed-211892750*/count=367; tryItOut("\"use strict\"; t0 = h1;");
/*fuzzSeed-211892750*/count=368; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions(this); } void 0; }");
/*fuzzSeed-211892750*/count=369; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.ceil(( + Math.hypot(( + (mathy0((mathy0(x, Math.imul(( + x), ( + -Number.MIN_SAFE_INTEGER))) >>> 0), (42 >>> 0)) | 0)), Math.atan2(( + Math.log(Math.asin(x))), (( ~ (Math.trunc(mathy0((Math.sinh(Number.MIN_SAFE_INTEGER) | 0), ( ! x))) | 0)) | 0)))))); }); testMathyFunction(mathy1, [(new Number(0)), (new Boolean(false)), [], false, -0, (new Boolean(true)), NaN, ({toString:function(){return '0';}}), 0, undefined, objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), (new String('')), (function(){return 0;}), '\\0', true, (new Number(-0)), /0/, ({valueOf:function(){return '0';}}), [0], 1, '', null, '/0/', '0']); ");
/*fuzzSeed-211892750*/count=370; tryItOut("{ void 0; fullcompartmentchecks(false); } (27);");
/*fuzzSeed-211892750*/count=371; tryItOut("testMathyFunction(mathy4, [1, 0.000000000000001, 1/0, -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -0x100000001, -0x100000000, 0x100000000, 0, 2**53+2, -1/0, 1.7976931348623157e308, -0x080000001, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, 0x080000000, 0x080000001, Number.MIN_VALUE, -(2**53-2), 0/0, -0, 42, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, -(2**53), -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=372; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.pow(( + (( + ( + (( + Math.fround(Math.abs(x))) || ( + -0x0ffffffff)))) + ( + Math.min(( + (0x07fffffff < (Math.ceil(y) | 0))), ( + (((y >>> 0) / ((( + Number.MAX_SAFE_INTEGER) < ( ! ( + y))) >>> 0)) >>> 0)))))), (( - (mathy0((Math.min(( + x), (((-0x100000000 <= y) | 0) | 0)) | 0), ((Math.atan2(Math.fround(-1/0), Math.fround(-0x080000001)) >>> 0) + y)) >>> 0)) >>> 0)) >>> 0) ? (Math.pow((Math.cos(( + y)) | 0), ((( ! Math.asin(( + Math.abs(y)))) | 0) >>> 0)) >>> 0) : ((Math.fround(Math.clz32((Math.pow((y | 0), ((( ! (y | 0)) | 0) | 0)) | 0))) | Math.fround(x)) >> ( - -0x080000001))) >>> 0); }); testMathyFunction(mathy3, [-(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -0x07fffffff, -Number.MAX_VALUE, -(2**53+2), -0x100000001, -0x0ffffffff, 0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, Number.MIN_VALUE, 2**53, 0x080000000, 0x100000000, -1/0, 42, -0x100000000, -0, 1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, 2**53-2, 0, 1, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=373; tryItOut("\"use strict\"; g2.s1 = a0[2];");
/*fuzzSeed-211892750*/count=374; tryItOut("o1.i2.next();");
/*fuzzSeed-211892750*/count=375; tryItOut("p0[\"getMonth\"] = i1;");
/*fuzzSeed-211892750*/count=376; tryItOut("Object.defineProperty(g0.g2, \"v1\", { configurable: (x % 3 == 0), enumerable: false,  get: function() {  return evalcx(\"t1 + '';\", g2); } });");
/*fuzzSeed-211892750*/count=377; tryItOut("mathy3 = (function(x, y) { return ( - Math.max(( + ( ! x)), (Math.imul(( + Math.fround(Math.pow(x, x))), (Math.fround(0x080000001) <= ( + x))) | 0))); }); testMathyFunction(mathy3, [-(2**53), 0/0, -(2**53-2), -(2**53+2), 0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -0, 42, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -0x080000000, -0x07fffffff, 2**53-2, 0x0ffffffff, -1/0, Number.MIN_VALUE, 2**53+2, 1/0, 0x100000001, -0x100000001, 1, -0x080000001, -Number.MAX_VALUE, 2**53, 0x080000000, -0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-211892750*/count=378; tryItOut("print(2**53-2);");
/*fuzzSeed-211892750*/count=379; tryItOut("\"use strict\"; Array.prototype.pop.call(a2, this.v2);");
/*fuzzSeed-211892750*/count=380; tryItOut("mathy2 = (function(x, y) { return Math.sign(Math.imul(Math.hypot((( - (x | 0)) | 0), Math.max(Number.MAX_SAFE_INTEGER, 42)), Math.ceil(( + Math.acos(Math.PI))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, 42, Math.PI, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1, 0x080000001, 1.7976931348623157e308, -0x100000000, 0, -Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, -1/0, -0x0ffffffff, 2**53-2, 2**53+2, 2**53, -(2**53), -0x080000001, 0x100000001, -(2**53+2), 0x100000000, -0x100000001, Number.MIN_VALUE, -0, -0x080000000, 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=381; tryItOut("testMathyFunction(mathy3, [null, '/0/', (new String('')), (new Boolean(false)), false, 1, objectEmulatingUndefined(), '0', NaN, 0, true, (new Number(0)), ({toString:function(){return '0';}}), (new Number(-0)), (new Boolean(true)), [], /0/, -0, undefined, ({valueOf:function(){return 0;}}), '', '\\0', ({valueOf:function(){return '0';}}), 0.1, (function(){return 0;}), [0]]); ");
/*fuzzSeed-211892750*/count=382; tryItOut(";");
/*fuzzSeed-211892750*/count=383; tryItOut("e2 = new Set;");
/*fuzzSeed-211892750*/count=384; tryItOut("/*tLoop*/for (let c of /*MARR*/[this, function(){}, function(){}, -Infinity, -Infinity, this, this, this, function(){}, -Infinity, this, function(){}, this, this, function(){}, -Infinity, this, this, this, -Infinity, -Infinity, -Infinity, function(){}, function(){}, this, function(){}, -Infinity, -Infinity, function(){}, -Infinity, -Infinity, function(){}, this, function(){}, this, function(){}, function(){}, this, -Infinity, function(){}, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, this, this, this, function(){}, -Infinity, this, function(){}, this, function(){}, this, this, function(){}, function(){}, function(){}, -Infinity, -Infinity, this, -Infinity, -Infinity, -Infinity, -Infinity, this, this, -Infinity, -Infinity, function(){}, this, this, function(){}, -Infinity, function(){}]) { break ; }function x(\u3056 = x, b) { \"use strict\"; yield ((/*FARR*/[].sort(Int8Array, this)).__defineSetter__(\"b\", /*wrap1*/(function(){ v1 = g2.t2.byteOffset;return  '' })())) } /*RXUB*/var r = r2; var s = s0; print(s.search(r)); \u000cfunction window(x, x, x, z, b =  \"\" , d, x, x, x, x, x, x, x)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 3.8685626227668134e+25;\n    return +((d2));\n  }\n  return f;o1 + '';");
/*fuzzSeed-211892750*/count=385; tryItOut("\"use strict\"; ");
/*fuzzSeed-211892750*/count=386; tryItOut("\"use strict\"; t2.valueOf = (function() { try { Array.prototype.sort.call(this.g0.a0, (function() { a1[18] = x; return p1; }), t1, o0.i0, f2); } catch(e0) { } try { v0 = (m2 instanceof e2); } catch(e1) { } try { i1 + ''; } catch(e2) { } Object.defineProperty(g0, \"v0\", { configurable: x, enumerable: (({/*toXFun*/toString: Math.imul(e, 19), x: ([\"\\u9DC0\"] << x) })),  get: function() {  return t1.length; } }); return i0; });");
/*fuzzSeed-211892750*/count=387; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-211892750*/count=388; tryItOut("var pqbuog = new SharedArrayBuffer(8); var pqbuog_0 = new Int16Array(pqbuog); pqbuog_0[0] = -5; print(pqbuog_0[9]);g0.v2 = Object.prototype.isPrototypeOf.call(s1, t1);");
/*fuzzSeed-211892750*/count=389; tryItOut("a2.length = ({valueOf: function() { /*RXUB*/var r = /(?=\\2)/gyi; var s = \"C\"; print(r.test(s)); print(r.lastIndex); return 19; }});");
/*fuzzSeed-211892750*/count=390; tryItOut("this.g1.a1 = new Array;");
/*fuzzSeed-211892750*/count=391; tryItOut("testMathyFunction(mathy0, [0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, -0x100000000, -(2**53+2), 0x080000000, -1/0, 1, -Number.MIN_VALUE, 0/0, -0, 2**53-2, Math.PI, -0x07fffffff, 2**53+2, 42, -0x100000001, -(2**53), 0x0ffffffff, -0x080000000, 0x07fffffff, 0.000000000000001, -(2**53-2), 0]); ");
/*fuzzSeed-211892750*/count=392; tryItOut("mathy5 = (function(x, y) { return ( - ( ! Math.fround(Math.hypot(((Math.atan2((( - y) | 0), ((x <= ( + x)) >>> 0)) >>> 0) | 0), y)))); }); testMathyFunction(mathy5, [-1/0, Number.MIN_VALUE, 1.7976931348623157e308, 2**53, 0x100000000, -0x080000000, 0x07fffffff, -0x07fffffff, 2**53-2, 1, -Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, 0x080000001, -0x100000001, Number.MAX_VALUE, Math.PI, 0, -(2**53-2), -0, -Number.MIN_VALUE, 0/0, 42, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, 0x080000000, 2**53+2, 1/0, -(2**53+2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=393; tryItOut("mathy5 = (function(x, y) { return mathy1(Math.fround((( + ((mathy1((mathy4(x, x) | 0), (Math.fround((Math.fround(Math.sin(y)) | -(2**53-2))) | 0)) | 0) + ( ! x))) ? ( + ((y | 0) % Math.clz32((Math.fround((( + ( + (( + x) | ( + y)))) >>> ( + -Number.MIN_SAFE_INTEGER))) < -0x080000000)))) : (( + ( + ( + Math.log2((( ~ ( + ( + 0))) >>> 0))))) | 0))), (Math.log2(((( ! Math.fround(( + Math.cosh(( + x))))) | 0) | 0)) >>> 0)); }); ");
/*fuzzSeed-211892750*/count=394; tryItOut("mathy2 = (function(x, y) { return ((( + (( + ( ! y)) >= (( + ( + ( + (( + 0x080000001) || ( + (( ! (Math.atan2(( + Math.tan(-1/0)), x) | 0)) | 0)))))) | 0))) | (( + (( - ( + (Math.max(( + mathy1((Math.abs((y >>> 0)) >>> 0), (( ~ ( + x)) >>> 0))), x) % ( + Math.imul(Math.clz32(x), Math.fround(Math.PI)))))) & Math.fround(( ! Math.fround(Math.max(( + x), x)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x),  '' , new ( /x/g )(window, this.x),  '' ,  '' ,  '' ,  '' ,  '' , new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x),  '' ,  '' , new ( /x/g )(window, this.x),  '' ,  '' ,  '' , new ( /x/g )(window, this.x),  '' ,  '' , new ( /x/g )(window, this.x),  '' ,  '' , new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x),  '' , new ( /x/g )(window, this.x),  '' ,  '' ,  '' ,  '' , new ( /x/g )(window, this.x), new ( /x/g )(window, this.x), new ( /x/g )(window, this.x),  '' ,  '' , new ( /x/g )(window, this.x),  '' ,  '' ,  '' ]); ");
/*fuzzSeed-211892750*/count=395; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min(Math.fround(Math.min(mathy0(( + y), (( + (Math.min((-0x07fffffff | 0), -0) >>> 0)) >>> 0)), Math.fround(((Math.atan2(Math.atan(x), (y * (( - (Math.max(x, x) | 0)) | 0))) | 0) || (x > ( + mathy0(( + x), x))))))), (mathy0((((-0x07fffffff >>> 0) && (Math.ceil(x) / y)) >>> 0), ((( ~ (y >>> 0)) >>> 0) == -Number.MIN_VALUE)) >>> Math.atan2(Math.atanh(( + ( + Math.round(( + x))))), Math.imul(y, ( + 0x080000000))))); }); testMathyFunction(mathy1, [[], (new Boolean(false)), (new Number(0)), '0', undefined, (new Number(-0)), 1, ({toString:function(){return '0';}}), '', 0.1, false, 0, objectEmulatingUndefined(), (new String('')), (new Boolean(true)), /0/, -0, [0], null, ({valueOf:function(){return 0;}}), '\\0', '/0/', ({valueOf:function(){return '0';}}), true, (function(){return 0;}), NaN]); ");
/*fuzzSeed-211892750*/count=396; tryItOut("\"use strict\"; for (var v of o0) { try { Object.defineProperty(this, \"v1\", { configurable: (x % 5 != 3), enumerable: false,  get: function() {  return a2.reduce, reduceRight(RegExp.prototype.exec.bind(g2), g1.t0, t0); } }); } catch(e0) { } try { v2 = new Number(o1.v0); } catch(e1) { } /*MXX3*/g2.SharedArrayBuffer.name = g2.g2.SharedArrayBuffer.name; }i2 + '';");
/*fuzzSeed-211892750*/count=397; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow(Math.fround(( - Math.fround(( - Math.sin((y == (( + y) | 0))))))), ( + Math.max((Math.pow((( + (y >>> 0)) >>> 0), ( ~ -0x100000001)) >>> 0), ( + (( + Math.max(Math.ceil((x > x)), Math.max((mathy0(Math.PI, x) >>> 0), (y >>> 0)))) ? (( ~ Math.fround(mathy0(Math.fround(x), Math.fround(Math.cbrt(y))))) % (( - (0x100000000 >>> 0)) >>> 0)) : ( + Math.hypot(x, Math.fround(Math.ceil((y >>> 0)))))))))); }); testMathyFunction(mathy1, [null, (new Number(-0)), '\\0', 1, (new Number(0)), [], '0', objectEmulatingUndefined(), undefined, [0], /0/, '', 0.1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (function(){return 0;}), -0, NaN, '/0/', ({valueOf:function(){return '0';}}), (new Boolean(true)), true, (new String('')), 0, false, (new Boolean(false))]); ");
/*fuzzSeed-211892750*/count=398; tryItOut("v1 = Object.prototype.isPrototypeOf.call(s2, o0);");
/*fuzzSeed-211892750*/count=399; tryItOut("/*infloop*/M:while(((function a_indexing(zwybsg, cwhrha) { ; if (zwybsg.length == cwhrha) { ; return zwybsg ^= (Object.defineProperty(zwybsg, \"window\", ({enumerable: (x % 13 != 7)}))); } var factnp = zwybsg[cwhrha]; var cxpbkx = a_indexing(zwybsg, cwhrha + 1); /* no regression tests found */ })(/*MARR*/[arguments,  \"\" , arguments, x, [undefined], arguments, [undefined], arguments, x, x, new Boolean(false), arguments, [undefined], new Boolean(false), new Boolean(false),  \"\" , [undefined], new Boolean(false), arguments,  \"\" , arguments, new Boolean(false),  \"\" , new Boolean(false), [undefined], [undefined], arguments, x, arguments,  \"\" , new Boolean(false), new Boolean(false), x,  \"\" ,  \"\" , new Boolean(false), new Boolean(false), [undefined], x, new Boolean(false), arguments, arguments, arguments,  \"\" , x,  \"\" , new Boolean(false), arguments,  \"\" , new Boolean(false),  \"\" , x, x, new Boolean(false),  \"\" , x, new Boolean(false), new Boolean(false), [undefined], new Boolean(false), [undefined], arguments, [undefined], new Boolean(false), new Boolean(false), new Boolean(false),  \"\" , new Boolean(false), [undefined], arguments, [undefined],  \"\" , arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments,  \"\" , [undefined], new Boolean(false), x, x, arguments,  \"\" ,  \"\" , new Boolean(false),  \"\" , arguments, [undefined],  \"\" , [undefined], x], 0))){( '' );a1 + ''; }");
/*fuzzSeed-211892750*/count=400; tryItOut("this.e1.add(g1.p1);");
/*fuzzSeed-211892750*/count=401; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.hypot((Math.acosh((( + Math.sinh(x)) | 0)) | 0), (Math.trunc((x | 0)) | 0)), (Math.asin((( - (y ? ( ~ (x | 0)) : y)) | 0)) | 0)); }); testMathyFunction(mathy1, [2**53-2, -0x07fffffff, -0x100000001, -0x0ffffffff, -0x080000000, -0, 0.000000000000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -0x100000000, 0x080000001, -1/0, -(2**53+2), 0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, -(2**53), 2**53, Number.MIN_VALUE, 0/0, -0x080000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, 0, Number.MIN_SAFE_INTEGER, 42, 1]); ");
/*fuzzSeed-211892750*/count=402; tryItOut("testMathyFunction(mathy0, [-1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), Number.MIN_VALUE, 1, 2**53, -0x0ffffffff, 2**53+2, -(2**53), 0, 0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, 0x07fffffff, 2**53-2, -(2**53-2), Number.MAX_VALUE, -0x080000001, -0, -Number.MAX_VALUE, 0x0ffffffff, Math.PI, 1.7976931348623157e308, 0.000000000000001, -0x100000000, 42, 0x100000000, 0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=403; tryItOut("mathy5 = (function(x, y) { return (( + (Math.cbrt(Math.log10(0x080000000)) | 0)) << Math.atan2((Math.fround(Math.imul((Math.fround(Math.round(0x080000000)) > (((mathy1(x, -Number.MIN_SAFE_INTEGER) >>> 0) != (y >>> 0)) >>> 0)), x)) | 0), (( - (x >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, 0x080000001, 1, -0, -(2**53-2), 0x080000000, 2**53, -0x0ffffffff, 0x0ffffffff, 0, -1/0, -0x080000001, -(2**53+2), 1.7976931348623157e308, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, 0x100000001, 2**53-2, 2**53+2, -(2**53), 0.000000000000001, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 42, -Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=404; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a1, ({valueOf: function() { for (var v of i1) { try { i2 = new Iterator(g1.g2.h1); } catch(e0) { } try { i0.send(m1); } catch(e1) { } try { Array.prototype.sort.apply(a1, [(function() { for (var j=0;j<0;++j) { o1.f0(j%4==1); } }),  '' ]); } catch(e2) { } o0.o1.t2[2] = g0; }return 17; }}), ({enumerable: (this)(-20, x)}));");
/*fuzzSeed-211892750*/count=405; tryItOut("for (var p in v2) { try { h1.hasOwn = f1; } catch(e0) { } try { /*ADP-2*/Object.defineProperty(g2.a1, ({valueOf: function() { print(m0);return 5; }}), { configurable: false, enumerable: 'fafafa'.replace(/a/g, ({}) = /((\\1{2}){2}|\\cS|\\W{0}{3,5})/yi)\n, get: (function() { try { this.o1.h2.has = (function mcc_() { var cybmnl = 0; return function() { ++cybmnl; f0(/*ICCD*/cybmnl % 10 == 2);};})(); } catch(e0) { } try { x = p2; } catch(e1) { } try { for (var v of f0) { try { v0 = Array.prototype.reduce, reduceRight.call(a0, arguments.callee.caller.caller.caller); } catch(e0) { } try { Object.preventExtensions(g1.e0); } catch(e1) { } try { e0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var asin = stdlib.Math.asin;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 524289.0;\n    var i3 = 0;\n    var i4 = 0;\n    {\n      i3 = (0x4136a3a9);\n    }\n    i0 = (0xf9bc8851);\n    d1 = (+(0x8c8b6d9e));\n    d2 = ((eval) =  '' );\n    return ((((((/*FFI*/ff(((-1125899906842623.0)), ((((0xe1d45ccf)*-0xfffff) ^ ((Float32ArrayView[1])))), ((+(-1.0/0.0))), ((\"\\uDD07\")), ((18446744073709552000.0)), ((36028797018963970.0)), ((1.0078125)), ((-1.2089258196146292e+24)), ((3.094850098213451e+26)), ((-268435457.0)), ((-137438953473.0)), ((72057594037927940.0)), ((-2305843009213694000.0)), ((-1099511627775.0)), ((4398046511105.0)), ((-2048.0)), ((274877906945.0)), ((-140737488355327.0)), ((-262145.0)))|0)+((0x30aadad2) == (~((/*FFI*/ff(((-72057594037927940.0)))|0)-(i4))))) >> (((d1) != (d2))+(/*FFI*/ff(((((d1)) - ((d2)))), ((d2)), ((NaN)), ((~((0xffffffff)))))|0))))-(/*FFI*/ff(((+asin(((+((d1))))))), ((((+(0x7fffffff))) - ((d2)))))|0)))|0;\n    return ((-(i0)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.toUTCString}, new ArrayBuffer(4096)); } catch(e2) { } /*RXUB*/var r = this.r2; var s = \"(aa(aa(aa\"; print(s.split(r));  } } catch(e2) { } v2 = (h2 instanceof g1.h2); return h1; }), set: (function() { for (var j=0;j<46;++j) { f0(j%2==0); } }) }); } catch(e1) { } g0.t1 = t2.subarray(1, 17); }");
/*fuzzSeed-211892750*/count=406; tryItOut("mathy2 = (function(x, y) { return ((((mathy1((Math.fround(mathy1(Math.fround(0), y)) >>> 0), Math.asinh(Math.round((Math.pow((-Number.MIN_SAFE_INTEGER >>> 0), (Math.fround(Math.atan2(x, Math.fround(y))) >>> 0)) >>> 0)))) >>> 0) >= (Math.max(( + Math.cbrt((y & Math.atan2(y, y)))), (Math.min(Math.hypot(Math.fround(mathy0(x, x)), (( - x) >>> 0)), mathy1(x, x)) | 0)) | 0)) === ((((Math.log10(-(2**53+2)) - Math.hypot(Math.atan2(Math.fround(( ~ x)), Number.MAX_VALUE), Math.fround(Math.max(Math.fround(mathy0(y, Math.hypot(y, -(2**53+2)))), Math.fround(0x080000000))))) >>> 0) === ( + Math.fround((Math.fround(Math.expm1((Math.atan2(x, Math.fround((x >> y))) >>> 0))) > Math.fround((y , Math.fround(y))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [Math.PI, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, 0x07fffffff, 1/0, -(2**53), 42, 0/0, Number.MAX_VALUE, -(2**53-2), 2**53-2, -(2**53+2), 0x100000001, 1, 0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, -1/0, 0, Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, -Number.MAX_VALUE, 0x100000000, -0x080000000, -0x07fffffff, 0x080000001, Number.MIN_VALUE, 0.000000000000001, 2**53+2, -Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=407; tryItOut("m1.get((4277));");
/*fuzzSeed-211892750*/count=408; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + ( + Math.hypot((( - Math.fround(Math.atan2(Math.fround(x), Math.fround(( - 1.7976931348623157e308))))) >>> 0), mathy0(Math.fround((y >>> Math.fround((( - (x >>> 0)) >>> 0)))), 1/0)))) ? Math.fround((Math.hypot((( + Math.min(( + Math.pow(Math.atan2(Math.tan(Math.fround(mathy0(Math.fround(x), Math.fround(x)))), y), (( ! (y >>> 0)) >>> 0))), ( + ( + (( + (Math.sin(Math.fround(1.7976931348623157e308)) | 0)) ? ( + (Math.clz32((y >>> 0)) >>> 0)) : (new Function(\"(e);\"))()))))) >>> 0), (Math.sin(Math.fround(Math.max(Math.fround(y), Math.fround(( + (y / Math.fround((y * Math.fround((Math.pow((0 | 0), Math.fround(Number.MAX_VALUE)) | 0)))))))))) >>> 0)) >>> 0)) : Math.fround(Math.fround(( + (Math.fround(mathy0(Math.fround(Math.sqrt(( + Math.max(Math.max(x, ( + x)), (x | 0))))), Math.fround(Number.MAX_SAFE_INTEGER))) | 0))))); }); testMathyFunction(mathy1, [-(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), 2**53, 0x080000000, -0x07fffffff, -Number.MIN_VALUE, 2**53-2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, -Number.MAX_VALUE, 0, 1, Math.PI, -0x100000001, -0x100000000, -0x080000001, -1/0, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 42, -(2**53+2), Number.MAX_VALUE, 0x100000000, -0x0ffffffff, 0/0, -0, 0x100000001]); ");
/*fuzzSeed-211892750*/count=409; tryItOut("{m1 = new WeakMap; }");
/*fuzzSeed-211892750*/count=410; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=411; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((Math.asin((Math.hypot((Math.hypot(Math.fround(mathy0(Math.fround(-Number.MIN_VALUE), x)), (y >>> 0)) >>> 0), ( + Math.fround(( + Math.atan(( + y)))))) | 0)) >>> 0) | 0) >= (Math.fround(( ~ Math.fround(Math.imul((Math.cos(mathy0(y, (Math.pow(y, x) | 0))) >>> 0), (y >>> 0))))) | 0)); }); testMathyFunction(mathy1, [42, Number.MAX_SAFE_INTEGER, 1, -(2**53), -0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), 1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, Number.MAX_VALUE, 0x080000001, -1/0, 2**53+2, Math.PI, Number.MIN_VALUE, -0, 0x080000000, 0/0, -Number.MIN_VALUE, 0, -0x07fffffff, 0x0ffffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, 2**53-2, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-211892750*/count=412; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(Math.pow(Math.fround((((x >>> 0) ? (y >>> 0) : Math.fround((Math.fround((( ~ (y | 0)) | 0)) << Math.fround(x)))) >>> 0)), Math.fround(((( + mathy2(Math.fround(mathy0(Math.fround(1), Math.fround(( + mathy0(( + 2**53-2), Math.fround((x != y))))))), 1/0)) >>> ( + Math.fround(( - mathy2(0/0, y))))) | 0)))), Math.fround(mathy2(Math.fround(( ! Math.sign((0x0ffffffff >>> 0)))), Math.fround(Math.atan2(Math.fround(Math.min((x | 0), Math.fround(( ! Math.fround(x))))), (( + Math.max((Math.imul(1/0, Math.fround(( - 0))) | 0), ( + x))) | 0)))))); }); testMathyFunction(mathy3, [-0x100000001, 0x100000000, 0x080000001, 0x080000000, 2**53+2, Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 1, -0x07fffffff, 0x100000001, -0x080000000, -(2**53+2), 0x07fffffff, -(2**53), -0x080000001, Math.PI, 2**53, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, 42, -0x0ffffffff, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, 1/0, 0/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=413; tryItOut("\"use strict\"; t0[\"arguments\"] = o1;");
/*fuzzSeed-211892750*/count=414; tryItOut("\"use strict\"; let(NaN = x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: (NaN, x, window, b, \u3056, z, x, e, x, NaN, x, eval, x, z = this, x, d, NaN, x, x, c = \"\\uD0C0\", x, x = new RegExp(\"(?=\\\\1{0}){1,5}|\\\\s\\\\S|(?!(?:(.)))*\", \"gy\"), x =  /x/ , a, false, x =  '' , NaN, x, x, x, y, window, x, x, \u3056, x, a, x =  /x/ , eval, d, c = new RegExp(\"(?!(?!(\\\\1)))\", \"gim\"), x, x, x, b = /(?:[^\\0-\\x55f-\\u9f02\u8a98])/gy, \u3056, window =  /x/ , z, x = false, x, x, z, x, eval = \"\\u00CA\", e, d, x, a, a, a, x = z) =>  { for (var v of e2) { try { v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: false })); } catch(e0) { } try { g0.v1 = t2.byteOffset; } catch(e1) { } /*MXX1*/var o2 = g0.EvalError.prototype; } } , }; })(x), w\u0009 % w, RangeError.prototype.toString), \u3056 = (((decodeURI((4277))))), a = (Date.prototype.setUTCFullYear)(), coonqq, this.x = new DFGTrue(window), x = delete x.y) ((function(){y = \u3056;})());return x;");
/*fuzzSeed-211892750*/count=415; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.cosh(( + Math.log2(Math.fround(Math.round(Math.fround(Math.log2(x)))))))); }); testMathyFunction(mathy4, [0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, -0x080000001, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, 0/0, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, 1/0, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53-2), 0x100000000, -0x0ffffffff, Math.PI, -1/0, 42, -0x100000001, -(2**53), 1.7976931348623157e308, 0x0ffffffff, -0, 2**53+2, 0x100000001, -(2**53+2)]); ");
/*fuzzSeed-211892750*/count=416; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.min(Math.fround(Math.imul((Math.hypot((x ** Math.min((Number.MAX_SAFE_INTEGER | 0), y)), (((Math.fround((x ? ( + ( + Math.log(( + x)))) : y)) | 0) == ( ~ x)) | 0)) | 0), Math.atan2(Math.fround((( + Math.expm1(y)) << ( + Math.atan2(y, ((x && x) ? x : x))))), Math.fround(( ~ (Math.cos((x >>> 0)) >>> 0)))))), Math.fround(Math.fround(((Math.ceil(x) | 0) === Math.fround((( ! Math.max(y, Math.fround((x < Math.trunc(-0))))) >>> 0))))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, 1/0, -0x0ffffffff, 1, -0x100000000, 2**53-2, -0x080000001, -0x100000001, -(2**53+2), 2**53+2, -(2**53-2), -Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, Math.PI, -0, 0, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, -0x080000000, 0x07fffffff, 42, 0x100000000, 0x080000000, 0x100000001, 0x080000001]); ");
/*fuzzSeed-211892750*/count=417; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[ 'A' , 4., -3/0, -3/0, 4.,  'A' ,  'A' , -3/0, 4., 4., -3/0,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ]) { /*vLoop*/for (var nhrvkc = 0; nhrvkc < 45; ++nhrvkc) { const y = nhrvkc; for (var v of t2) { try { m0 = e2; } catch(e0) { } try { this.v2 = a0.length; } catch(e1) { } this.e2 = p2; } } \nthrow Math.sqrt(29);\n }");
/*fuzzSeed-211892750*/count=418; tryItOut("\"use strict\"; \"use asm\"; t1 = new Uint16Array(b1);");
/*fuzzSeed-211892750*/count=419; tryItOut("for([b, w] = 17 >>> x in x) print(w);");
/*fuzzSeed-211892750*/count=420; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( + ( + (mathy2(Math.fround((mathy2(((Math.cosh((((x >>> 0) || (Math.min((y >>> 0), (-0x100000000 >>> 0)) >>> 0)) | 0)) | 0) != ( ! Math.cbrt((( + (y | 0)) | 0)))), x) | 0)), Math.imul(Math.acosh((-Number.MIN_VALUE >>> 0)), Math.fround(Math.atan2(Math.fround((((y | 0) ? ((Math.cbrt((( ~ y) >>> 0)) >>> 0) | 0) : Math.imul(-(2**53), x)) | 0)), Math.fround(( - x)))))) >>> 0))) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -0x100000001, 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 42, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), 0x080000001, 0x100000001, -0x080000001, 2**53-2, 2**53, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, 1/0, -(2**53+2), 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, 0, -1/0, 2**53+2, -Number.MIN_VALUE, -0x080000000, 0x100000000, -0]); ");
/*fuzzSeed-211892750*/count=421; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( - (Math.atan2((Math.atan2(Math.exp(y), (Math.atan2((x < x), (y >>> 0)) << (y >>> 0))) | 0), (Math.atan2((( + Math.atan2(Math.acosh(0/0), ( + x))) | 0), (( + Math.pow(y, Math.fround(y))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [1.7976931348623157e308, 0x0ffffffff, 0, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -0x080000001, 42, Number.MIN_VALUE, 0x080000001, -0x080000000, 2**53, -0, 0x07fffffff, 1, -0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, Math.PI, -0x07fffffff, 1/0, -(2**53+2), -1/0]); ");
/*fuzzSeed-211892750*/count=422; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.atan2(Math.max((((Math.min(y, (Math.fround(( ~ ((((x >>> 0) % ((y ? 0/0 : x) >>> 0)) >>> 0) >>> 0))) | 0)) >>> 0) >>> mathy1(( + ( + ( + Math.atan2(( + y), x)))), ( + Math.max(Math.fround(x), Math.fround(x))))) >>> 0), Math.fround((Math.acos((mathy1((Math.max((x >>> 0), (y >>> 0)) >>> 0), y) | 0)) | 0))), Math.fround((Math.hypot((Math.fround(Math.cos(Math.fround((Math.acosh((x >>> 0)) >>> 0)))) >>> 0), (Math.fround(mathy1(( + (Math.fround(Math.sign(Math.fround(x))) % ( + (Math.asin(y) >>> 0)))), (Math.atan2((Math.abs((Math.log2((x | 0)) >>> 0)) >>> 0), (Math.min(-0x100000000, Math.max(x, y)) >>> 0)) , ( + (x - ( + Math.max(x, y))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [-0x100000000, -Number.MAX_VALUE, -0, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 0/0, 2**53+2, 2**53, Math.PI, -0x07fffffff, 0x100000000, -(2**53-2), Number.MAX_VALUE, 0.000000000000001, -0x080000000, 1.7976931348623157e308, 0, -1/0, 0x07fffffff, 1, -0x0ffffffff, -(2**53), 0x080000001, 42, 2**53-2]); ");
/*fuzzSeed-211892750*/count=423; tryItOut("");
/*fuzzSeed-211892750*/count=424; tryItOut("\"use strict\"; var r0 = x + x; r0 = 9 | r0; var r1 = r0 % 6; var r2 = 6 & r1; print(r1); r2 = 0 / 4; var r3 = r2 % r2; var r4 = r1 ^ r3; var r5 = r4 - r4; var r6 = 7 & r3; var r7 = r2 + x; var r8 = r2 + r4; var r9 = r5 | r3; var r10 = 3 / 1; var r11 = 2 & r1; var r12 = r10 % r0; var r13 = 3 & 3; print(r12); var r14 = r6 % r9; var r15 = r13 / 5; var r16 = 0 | 1; var r17 = 8 ^ x; var r18 = 8 / 2; var r19 = r7 ^ 3; ");
/*fuzzSeed-211892750*/count=425; tryItOut("/*bLoop*/for (adazwb = 0; adazwb < 5; ++adazwb) { if (adazwb % 6 == 3) { yield /(?:\\B(?=..){0,1}{3,}){4}/yi; } else { Array.prototype.shift.apply(this.a1, [o0.m1, s2, this.h1, e0, p2, i2]); }  } ");
/*fuzzSeed-211892750*/count=426; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! ( + ( + Math.log2(( + ((Math.cbrt(Math.fround(((-0x07fffffff + mathy4(x, 1.7976931348623157e308)) | 0))) >>> 0) , ( + mathy2(Math.max(x, ( + ( ! ( + y)))), (y | 0))))))))) | 0); }); testMathyFunction(mathy5, /*MARR*/[x, x, function(){}, function(){}, function(){}, x, function(){}, x, function(){}, x, function(){}, function(){}, function(){}, x, x, x]); ");
/*fuzzSeed-211892750*/count=427; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(m1, a0);function z(...y) { e2 = new Set(t1); } (((makeFinalizeObserver('nursery'))));");
/*fuzzSeed-211892750*/count=428; tryItOut("/*RXUB*/var r = Math.max((({}).valueOf(\u000c\"number\")), 10) |= x(([]) = timeout(1800), (4277)()); var s = \"\\u3dae\"; print(r.test(s)); ");
/*fuzzSeed-211892750*/count=429; tryItOut("testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined()]); ");
/*fuzzSeed-211892750*/count=430; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 31.0;\n    i0 = (0xf9897e96);\n    d1 = (+(-1.0/0.0));\n    d1 = (d2);\n    return ((-((Float64ArrayView[((0xffc7be84)) >> 3]))))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53+2), 1/0, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, -0x080000000, 1, -Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, -0x100000001, 0x0ffffffff, 0x100000000, 2**53-2, -(2**53), -Number.MIN_VALUE, 0/0, 0x100000001, 2**53, 0x080000000, -0x07fffffff, -0, -0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, 1.7976931348623157e308, -(2**53-2), 42, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-211892750*/count=431; tryItOut("var y = (x.valueOf(\"number\"));g0.a1.splice(-6, v2);function eval(...y)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return +((Float32ArrayView[((0xe61623df) / (((x)+(1)-(0x3621e9fc))>>>(((0xbc25c0e) >= (((0x81321518))>>>((-0x8000000))))))) >> 2]));\n  }\n  return f;(/*MARR*/[[z1,,], new Boolean(false),  /x/g , new String('q'), (void 0), [z1,,], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0),  /x/g , new Boolean(false), new Boolean(false), new Boolean(false),  /x/g , new String('q'),  /x/g , [z1,,], new Boolean(false), [z1,,], new String('q'),  /x/g , (void 0), (void 0), (void 0), new String('q'), [z1,,],  /x/g ,  /x/g , [z1,,],  /x/g , new String('q'),  /x/g , new Boolean(false), [z1,,],  /x/g , new Boolean(false)].some(Set.prototype.entries));");
/*fuzzSeed-211892750*/count=432; tryItOut("testMathyFunction(mathy2, [Number.MIN_VALUE, -0x0ffffffff, 1, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, 0, -(2**53+2), -0x080000000, -0x100000001, 0x080000001, Math.PI, 42, 2**53-2, 0x100000000, Number.MAX_VALUE, 2**53+2, 0.000000000000001, 2**53, 0x0ffffffff, 0x080000000, -0x080000001, -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, -Number.MIN_VALUE, -(2**53), -0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-211892750*/count=433; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=434; tryItOut("a1.forEach((function() { try { s0 + ''; } catch(e0) { } Array.prototype.splice.call(a0, 8, x ? x : ([, ] = {}), m1, g1, i2, this.g0); return h2; }));");
/*fuzzSeed-211892750*/count=435; tryItOut("print(x);/*RXUB*/var r = new RegExp(\"(?:(?=(?=^{3})?\\\\B*))|[^]\", \"ym\"); var s = \"da\"; print(s.replace(r, '')); ");
/*fuzzSeed-211892750*/count=436; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x080000000, -0x07fffffff, 42, -0x080000001, 2**53, -Number.MAX_VALUE, 0x100000000, -1/0, -0, 2**53-2, 2**53+2, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 0x100000001, -0x100000001, Number.MAX_VALUE, 0x080000001, 0x07fffffff, 0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, 1, 0/0, Math.PI]); ");
/*fuzzSeed-211892750*/count=437; tryItOut("/*RXUB*/var r = /(?=(?![^\\D\\S\\0-\u0080]|(\\\uc27b)[^]^|[^]*)|\\1?)/gy; var s = eval(\"\\\"use strict\\\"; mathy4 = (function(x, y) { return (mathy3((Math.max(((Math.fround((((Math.round(((((0x080000001 >>> 0) ? (y >>> 0) : ( + x)) >>> 0) | 0)) | 0) ^ (y | 0)) | 0)) || ( + (( + Math.asin(-0x0ffffffff)) >= (Math.fround(((( ! y) >>> 0) , Math.fround(x))) >>> 0)))) | 0), (( ! ( + ( + ((y >>> 0) > (mathy3(Math.fround(2**53-2), x) >>> 0))))) >>> 0)) | 0), Math.round(((mathy0(Math.fround(Math.abs(x)), Math.fround((Math.fround(( ! y)) > Math.fround((Math.fround(y) + ( + y)))))) >>> 0) >= (Math.sin(x) >>> 0)))) | 0); }); testMathyFunction(mathy4, [0x100000001, 2**53, 0x100000000, 1.7976931348623157e308, Math.PI, 0, -(2**53-2), 0x080000000, -0x080000000, 1/0, 0x07fffffff, 2**53-2, 0x080000001, -1/0, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 1, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), -0x100000000, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001]); \"); print(r.test(s)); ");
/*fuzzSeed-211892750*/count=438; tryItOut("mathy3 = (function(x, y) { return mathy0(Math.fround(Math.clz32(( + ( + (mathy2(( + ( ~ ( + x))), (( ! y) | 0)) ? ( ! (-1/0 | 0)) : x))))), Math.fround(Math.hypot(( + Math.hypot(( + ( + (( + Math.atan(x)) >= ( + x)))), ( + Math.fround(( + ( + ( ! 0x080000001))))))), Math.min(((x !== (Math.cosh(Math.fround(Math.atan2(((( ~ ( + -0x07fffffff)) >>> 0) >>> 0), y))) | 0)) >>> 0), (y >>> 0))))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -1/0, -0, 42, Math.PI, 2**53, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, 1/0, -Number.MIN_VALUE, 0x080000000, 0x100000001, Number.MAX_VALUE, -(2**53+2), 0/0, 0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -0x080000001, 1, -(2**53-2), 0, 0x07fffffff, 2**53+2, -0x080000000, Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=439; tryItOut("/*infloop*/for(z = x; (void shapeOf(/(\\2[^\ub200]{4,}|\\b[^]|(?!.)+?[\\D\\S\\b-\ue36a])/ym)); NaN >= b) /*RXUB*/var r = new RegExp(\"(?:\\\\b(.[\\ud709\\\\s\\\\w]\\\\b){2}\\\\2|[\\\\w\\\\d]|[\\\\D\\u1cef\\\\WL-\\\\\\u014a]{1,4}{2}|[^])\", \"\"); var s = \"\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=440; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.forEach.apply(a2, []);");
/*fuzzSeed-211892750*/count=441; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(((((eval(\"/* no regression tests found */\", new RegExp(\".{64}|(?:${0})|(?![^\\ud1a2\\\\d\\\\s]{4,8})|(?:\\\\B)|(?=(?:[^\\\\cL-=])){0,3}\", \"gy\") >>> /\\b|(?:(\\b[^]{1})+)/gy), y >>> 0) >= (Math.asin(( + ( + y))) >>> 0)) >>> 0) >= (((( ~ x) | 0) + (( ~ Math.fround(x)) | 0)) | 0))); }); ");
/*fuzzSeed-211892750*/count=442; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((imul((((((0xf24949ec) >= (0x922025c5))-(i1)) << (((makeFinalizeObserver('tenured'))))) < (((/*FFI*/ff()|0)) >> ((i1)+(i0)))), (i0))|0) == (~((i1))));\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [42, 0x07fffffff, Math.PI, 0x080000000, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, -0x0ffffffff, 2**53, -1/0, 2**53+2, 0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, -(2**53-2), -Number.MAX_VALUE, 1/0, 0x100000000, 1.7976931348623157e308, 0, -0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 0x100000001, 0.000000000000001, 1, 0/0, 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=443; tryItOut("\"use strict\"; delete this.h1[new String(\"4\")];");
/*fuzzSeed-211892750*/count=444; tryItOut("\"use asm\"; let(x, eval, hixwfk, wzheko, x = d =  /x/ .__defineSetter__(\"e\", /*wrap2*/(function(){ \"use strict\"; var igtjmy = \"\\u5D4B\"; var rqelrq = encodeURI; return rqelrq;})()), x, xbcmkm, d, d = [z1,,], rzjenv) ((function(){yield ((x !== x)\n);})());");
/*fuzzSeed-211892750*/count=445; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.exp(( + Math.fround(((Math.log(((Math.log((Math.hypot(y, Math.fround(x)) | 0)) | 0) > (-(2**53+2) | 0))) >>> 0) ? Math.fround(Math.fround(( ! Math.fround(y)))) : ( + Math.cbrt(Math.hypot(( + Math.max(Math.fround(x), x)), Math.pow(x, (x | 0))))))))); }); testMathyFunction(mathy0, [0x0ffffffff, -0, 0, 1.7976931348623157e308, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, -0x0ffffffff, 0.000000000000001, -(2**53), -0x080000001, Math.PI, Number.MIN_VALUE, 2**53-2, -(2**53+2), 1, -Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, -0x100000001, -1/0, 0x100000001, Number.MAX_VALUE, 2**53+2, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, 0x100000000]); ");
/*fuzzSeed-211892750*/count=446; tryItOut("s2.valueOf = (function() { try { e1.has(i2); } catch(e0) { } try { p0.__iterator__ = (function(a0, a1, a2, a3, a4, a5, a6, a7) { a1 = 0 * 4; var r0 = a0 & a5; a3 = x & a6; var r1 = 3 ^ a2; var r2 = x % a2; var r3 = r0 & 5; a7 = r0 | a2; var r4 = r2 & a4; a0 = 3 & r0; var r5 = 9 - a7; var r6 = 8 / a2; var r7 = r1 % 9; var r8 = a4 / 5; var r9 = 0 ^ r1; var r10 = a0 & a4; var r11 = 0 | a6; var r12 = r1 + 7; var r13 = r3 * 4; var r14 = a3 ^ r2; var r15 = r10 / 9; var r16 = 3 % 9; var r17 = r11 & a2; var r18 = r3 - a4; r1 = a4 ^ 0; r17 = r9 & a4; a7 = 2 / r7; var r19 = r5 & a6; var r20 = r8 % r17; a7 = 1 - r3; var r21 = r6 | r15; r8 = a3 ^ r10; r4 = r15 % 4; var r22 = 8 + r10; var r23 = r12 * a1; var r24 = 2 ^ r11; var r25 = r13 / a7; r12 = r2 & a4; var r26 = 6 ^ r13; var r27 = r22 % 3; r15 = r19 | r1; var r28 = 7 * r23; var r29 = 4 - r19; var r30 = a5 ^ r12; r19 = 8 | r18; var r31 = 5 * r29; r12 = r26 + 3; var r32 = r4 ^ r23; var r33 = a5 % r29; var r34 = r9 + a5; var r35 = 5 + a2; var r36 = r13 | 1; r18 = r21 * r1; var r37 = r32 % a7; var r38 = r1 * r26; var r39 = a4 / a0; var r40 = r32 / r5; var r41 = r24 | r35; var r42 = 2 * r39; r0 = r6 * 4; var r43 = 7 - 6; r4 = 0 ^ r41; var r44 = r22 / r26; var r45 = 4 ^ 2; var r46 = r36 & r30; var r47 = r34 - a0; print(r40); r45 = r11 + r5; var r48 = 6 / r45; var r49 = 1 + 5; r5 = a7 | a6; var r50 = 6 ^ r45; var r51 = r11 & 3; var r52 = r16 ^ 7; var r53 = a5 | 0; var r54 = r13 ^ 6; var r55 = r0 - 5; var r56 = 6 + a7; var r57 = r31 ^ r15; var r58 = r24 % r9; var r59 = 9 & r37; var r60 = r54 + 4; var r61 = r36 - r20; var r62 = r59 + 0; var r63 = r48 / r11; r43 = r32 % r54; var r64 = 0 % r4; var r65 = 6 / 5; var r66 = 5 % r15; var r67 = r65 * 2; print(r25); var r68 = r7 & r25; var r69 = r53 + r15; var r70 = 7 + 3; r14 = r54 + a4; r39 = r32 * 6; var r71 = r44 | r19; var r72 = r44 ^ r15; print(r31); var r73 = 7 / a1; var r74 = r53 % r27; var r75 = 8 | 5; var r76 = r15 - r59; var r77 = r63 * r76; var r78 = 1 & 3; print(r56); var r79 = a1 % r54; var r80 = r64 + 9; return a7; }); } catch(e1) { } try { v1 = Object.prototype.isPrototypeOf.call(g2, f2); } catch(e2) { } v2 = Array.prototype.reduce, reduceRight.apply(a1, [Date.prototype.getUTCFullYear.bind(m0), v1, o1.e2, p2]); return i1; });");
/*fuzzSeed-211892750*/count=447; tryItOut("\"use strict\"; var w = (4277)();v0 = g0.eval(\"function f2(this.e2)  \\\"\\\" \");\nArray.prototype.sort.call(a2, this.f0);\n");
/*fuzzSeed-211892750*/count=448; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return ( ! (( ~ y) ? ( + ((( - (0.000000000000001 >>> 0)) >>> 0) - ((( + 1.7976931348623157e308) + y) | 0))) : (Math.cos((Math.log1p(mathy1(x, (Math.imul(Math.fround(x), -Number.MIN_SAFE_INTEGER) >>> 0))) | 0)) | 0))); }); testMathyFunction(mathy5, [-0x080000001, 1, 0x0ffffffff, 2**53+2, 2**53-2, 2**53, 1/0, 42, -(2**53-2), 0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, 0x080000000, 0.000000000000001, 0x100000000, -0x07fffffff, 0x100000001, Math.PI, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -(2**53), 0x07fffffff, 0, -0x100000000, -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=449; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ ( + Math.asinh(( + Math.atan2(( + (Number.MIN_SAFE_INTEGER == Math.fround(( ~ -Number.MIN_VALUE)))), ( + (((( + Math.pow(( + (y || x)), ( + Math.fround(( + x))))) | 0) ? (y | 0) : (y | 0)) | 0))))))) | 0); }); testMathyFunction(mathy0, /*MARR*/[Number.MIN_SAFE_INTEGER, 0.1, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.1, Number.MIN_SAFE_INTEGER, 0.1, Number.MIN_SAFE_INTEGER, 0.1, 0.1, 0.1, 0.1]); ");
/*fuzzSeed-211892750*/count=450; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - (((Math.hypot(( + ( + ((Math.hypot((y >>> 0), (0x100000000 >>> 0)) >>> 0) ? y : Math.max(y, y)))), y) | 0) === (0x100000000 && (mathy0(((y || x) >>> 0), Math.fround(Math.min(Math.pow(y, y), y))) && (Math.max((Math.fround(( ~ (Number.MIN_SAFE_INTEGER | 0))) | 0), (( + Math.atan2(( + 1/0), ( + x))) | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, -(2**53), 1/0, Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 2**53-2, 0x100000001, 0x100000000, -0x100000001, 2**53, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 42, 0x080000000, 2**53+2, 0, -0, 1, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), 0x07fffffff, 0x0ffffffff, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-211892750*/count=451; tryItOut("x.constructor;this.zzz.zzz;");
/*fuzzSeed-211892750*/count=452; tryItOut("m2.get(m2);");
/*fuzzSeed-211892750*/count=453; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=454; tryItOut("\"use strict\"; m1.get(t1);");
/*fuzzSeed-211892750*/count=455; tryItOut("print(h1);\na0.valueOf = (function() { for (var j=0;j<68;++j) { f2(j%3==1); } });\n");
/*fuzzSeed-211892750*/count=456; tryItOut("/*tLoop*/for (let d of /*MARR*/[]) { e1.delete(f1); }");
/*fuzzSeed-211892750*/count=457; tryItOut("s2 += g1.s2;");
/*fuzzSeed-211892750*/count=458; tryItOut("a0 + p0;");
/*fuzzSeed-211892750*/count=459; tryItOut("\"use strict\"; x;");
/*fuzzSeed-211892750*/count=460; tryItOut("/*ADP-1*/Object.defineProperty(g0.a0, 9, ({writable: (x % 6 == 5), enumerable: (x % 4 != 2)}));");
/*fuzzSeed-211892750*/count=461; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 2**53+2, -0x07fffffff, -0x0ffffffff, 1/0, -(2**53+2), -0x100000001, Math.PI, 0x100000000, -(2**53), -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 2**53, -1/0, 0x080000000, -0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, -0, -(2**53-2), 0/0, 0.000000000000001, -0x100000000, 1]); ");
/*fuzzSeed-211892750*/count=462; tryItOut("o1.v2 = Object.prototype.isPrototypeOf.call(f2, h2);");
/*fuzzSeed-211892750*/count=463; tryItOut("let(w) ((function(){with({}) return /*MARR*/[{}, {}, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, /.+/gi, {}, new String(''), {}].filter(Date.prototype.getDay, x);})());");
/*fuzzSeed-211892750*/count=464; tryItOut("v1 = Object.prototype.isPrototypeOf.call(p2, h1);");
/*fuzzSeed-211892750*/count=465; tryItOut("testMathyFunction(mathy2, [1, Number.MAX_SAFE_INTEGER, -1/0, 0/0, 0x0ffffffff, Number.MAX_VALUE, -0x080000001, -(2**53), -0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, 2**53-2, -0, Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 42, 0x100000001, -0x100000000, -(2**53-2), -Number.MIN_VALUE, 1/0, -0x100000001, 0x080000001, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, -0x0ffffffff, 0.000000000000001, 0x100000000, 1.7976931348623157e308, 0]); ");
/*fuzzSeed-211892750*/count=466; tryItOut("mathy5 = (function(x, y) { return (Math.sqrt((Math.min(( ~ (mathy1(((((x | 0) >>> (Math.fround(( ~ Math.fround(x))) | 0)) | 0) | 0), (( + Math.atan2(( + x), ( + x))) | 0)) | 0)), Math.log10((x >>> (Math.imul(y, y) << (((x >>> 0) , (0.000000000000001 >>> 0)) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0, -0x100000001, 42, 2**53+2, 1/0, 0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, -Number.MAX_VALUE, -0x100000000, 0/0, 1, 2**53-2, -0, 0x100000001, -0x080000000, 0x080000000, -0x07fffffff, -0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, -(2**53), 0x100000000, -(2**53+2), 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=467; tryItOut("for(let [e, b] = ((Function =  /* Comment */-10).valueOf(\"number\")) in \"\\u925E\" | -6 ? x : d) {print((4277));print(b); }");
/*fuzzSeed-211892750*/count=468; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.pow((( + (( + ( + Math.cos(( + ((Math.min(Math.PI, 0x07fffffff) | 0) !== y))))) ? ((y && ( ! ( ~ x))) | 0) : ( + Math.fround(Math.min(Math.fround(2**53+2), Math.fround(Math.sign(Math.fround((x >>> 0))))))))) | 0), (((Math.max(Math.fround(((y ^ y) >>> 0)), Math.asinh(((( + (Math.fround(( + ( + Number.MAX_VALUE))) && (y | 0))) ? (( + Math.imul(Math.fround(x), ((y & -Number.MIN_SAFE_INTEGER) | 0))) | 0) : Math.fround((Math.fround(-(2**53-2)) >>> (-0x080000001 >>> 0)))) >>> 0))) | 0) , ( + (Math.pow((( + ( ~ ((x - (y | 0)) & ( + Math.pow(x, ( + y)))))) >>> 0), (( + -0x100000000) - ( + (Math.min(((( ~ (y | 0)) | 0) | 0), ( + ((y | 0) >> (Math.fround(Math.max(Math.fround(x), Math.fround(y))) | 0)))) | 0)))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy0, [0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), -0x080000000, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, -0x100000001, 0x100000001, Math.PI, -Number.MIN_VALUE, 2**53-2, 0x080000000, -(2**53+2), 0x0ffffffff, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, 2**53+2, 42, 0x07fffffff, 0.000000000000001, -1/0, -(2**53), 0, Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -0x080000001, -0x07fffffff]); ");
/*fuzzSeed-211892750*/count=469; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=470; tryItOut("\"use strict\"; /*iii*/g1 + o1.o2.e2;/*hhh*/function rszwqp([, [e], , ]){r0 = /\\3/gy;}function x(x, c) { var ufjajg = new ArrayBuffer(6); var ufjajg_0 = new Uint16Array(ufjajg); print(ufjajg_0[0]); v0 = a1[10];print(ufjajg_0[4]);print(x);p2 + p1;Object.defineProperty(this, \"i1\", { configurable: true, enumerable: (ufjajg % 4 == 3),  get: function() {  return m1.values; } }); } v1 = (v1 instanceof this.i0);");
/*fuzzSeed-211892750*/count=471; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.fround(Math.max((( + (( + (x || (y >>> 0))) ? ( + x) : ( + y))) == y), ((((mathy1((x | 0), (( + 2**53-2) === x)) | 0) >>> 0) % ( + (x ? Math.atan(( + -(2**53))) : Math.max(Math.fround(( + Math.fround(x))), x)))) | 0))) - ( + Math.acos((Math.fround(((Math.asin((y | 0)) | 0) ? ( ! x) : ( + Math.cosh(( + mathy0(y, ( ! y))))))) >>> 0))))); }); testMathyFunction(mathy2, [(function(){return 0;}), '/0/', '0', (new Number(-0)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Number(0)), null, [0], 1, (new Boolean(false)), '\\0', ({toString:function(){return '0';}}), 0.1, /0/, NaN, ({valueOf:function(){return 0;}}), true, undefined, false, -0, '', 0, [], (new String('')), (new Boolean(true))]); ");
/*fuzzSeed-211892750*/count=472; tryItOut("{ void 0; selectforgc(this); }");
/*fuzzSeed-211892750*/count=473; tryItOut("yield ((function sum_indexing(uclnnl, nbkglx) { ; return uclnnl.length == nbkglx ? 0 : uclnnl[nbkglx] + sum_indexing(uclnnl, nbkglx + 1); })(/*MARR*/[new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), new String('q'), function(){}, objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q')], 0));with({}) { let(w) ((function(){for(let w in /*MARR*/[(-1/0), (-1/0), (-1/0), (-1/0), (-1/0)]) let(w) ((function(){with({}) { w = w; } })());})()); } ");
/*fuzzSeed-211892750*/count=474; tryItOut(" /x/ ;\nv2 = t0.length;\n");
/*fuzzSeed-211892750*/count=475; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.min(((((Math.pow((( + Math.min((y >>> 0), y)) | 0), ((Math.imul(((Math.log((x | 0)) >>> 0) >>> 0), (( + (( + y) == y)) >>> 0)) | 0) | 0)) | 0) | 0) === ( + (Math.fround(Math.imul(x, Math.round(1/0))) ** Math.fround(( + (y >>> 0)))))) && ( + Math.sqrt(( + Math.fround(((Math.fround(mathy1(Math.fround(y), y)) >>> 0) >= x)))))), Math.min(Math.imul((((mathy0(((( + y) == y) | 0), (x >>> 0)) >>> 0) >> (x >>> 0)) >>> 0), (mathy0(( ! x), ( + ( ! y))) >>> 0)), (((( ! ((( - (x | 0)) | 0) >>> 0)) >>> 0) ** (x | 0)) | 0))); }); testMathyFunction(mathy5, [false, (new Boolean(true)), undefined, (new Number(-0)), NaN, ({toString:function(){return '0';}}), '0', '/0/', 0, 0.1, -0, (new Number(0)), [], 1, ({valueOf:function(){return 0;}}), '', true, ({valueOf:function(){return '0';}}), '\\0', [0], null, objectEmulatingUndefined(), /0/, (new String('')), (function(){return 0;}), (new Boolean(false))]); ");
/*fuzzSeed-211892750*/count=476; tryItOut("h2.getOwnPropertyNames = f1;");
/*fuzzSeed-211892750*/count=477; tryItOut("\"use strict\"; m1 = new Map;");
/*fuzzSeed-211892750*/count=478; tryItOut("t1 = t1.subarray(({valueOf: function() { p0.valueOf = f1;return 8; }}));");
/*fuzzSeed-211892750*/count=479; tryItOut("\"use strict\"; h1.getOwnPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        return ((((((Int8ArrayView[4096]))) ? (i1) : ((0x777ed175)))+(-0x70b4800)))|0;\n      }\n    }\n    i1 = (0xcaf96cf8);\n    i1 = ((i1) ? ((!(((Uint32ArrayView[1])) >= (((-0x8000000))>>>((0xfa7dd87a))))) ? (!(i1)) : (i1)) : (((Infinity) + (+(-1.0/0.0))) > (d0)));\n    return (((((0xf940cf79))>>>(((1.1805916207174113e+21))+(0xfdfb4b15))) / (0x60175787)))|0;\n  }\n  return f; });");
/*fuzzSeed-211892750*/count=480; tryItOut("v0 = (s0 instanceof g0);");
/*fuzzSeed-211892750*/count=481; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ~ (( + Math.pow(Math.fround(Math.fround((Math.fround(( ~ x)) == ( + y)))), ( + Math.acosh((y | 0))))) << Math.fround(((Math.max((x | 0), (x | 0)) | 0) , (Math.min(((Math.min(x, Math.fround(Math.imul(1, y))) >>> 0) | 0), (0x0ffffffff | 0)) | 0))))); }); ");
/*fuzzSeed-211892750*/count=482; tryItOut("\"use strict\"; Array.prototype.shift.call(a1);");
/*fuzzSeed-211892750*/count=483; tryItOut("\"use strict\"; { void 0; void 0; } m2.set(this.o2, undefined);");
/*fuzzSeed-211892750*/count=484; tryItOut("\"use strict\"; a0.forEach((function(j) { if (j) { Array.prototype.reverse.call(a1); } else { try { Array.prototype.sort.call(a2, (function() { for (var j=0;j<6;++j) { f0(j%5==1); } }), x = x); } catch(e0) { } try { e1.has(e0); } catch(e1) { } m1.get(a2); } }));");
/*fuzzSeed-211892750*/count=485; tryItOut("Object.defineProperty(this, \"g0.b0\", { configurable: true, enumerable: e,  get: function() {  return t1.buffer; } });");
/*fuzzSeed-211892750*/count=486; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; setGCCallback({ action: \"minorGC\", phases: \"begin\" }); } void 0; }");
/*fuzzSeed-211892750*/count=487; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ Math.imul(Math.hypot((y | 0), Math.fround(((x & x) | 0))), (y > Math.tan(((((y ^ ( ~ x)) | 0) ? ( + (mathy1((x >>> 0), (x >>> 0)) >>> 0)) : (x | 0)) | 0))))); }); testMathyFunction(mathy5, [0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, 42, 0x07fffffff, -0, 2**53-2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 1/0, Number.MAX_VALUE, 0, Math.PI, -0x100000000, 0x100000000, -(2**53-2), -1/0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0/0, -0x0ffffffff, Number.MIN_VALUE, 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 1, 1.7976931348623157e308, -0x080000001]); ");
/*fuzzSeed-211892750*/count=488; tryItOut("\"use strict\"; /*infloop*/do {v0 = evalcx(\"/* no regression tests found */\", g0);/*tLoop*/for (let c of /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), false,  'A' , new Boolean(false), false, false, false, new Boolean(false), new Number(1.5),  'A' , false,  /x/ ,  'A' , new Boolean(false),  /x/ , false,  'A' , false,  'A' , false, false,  /x/ , new Boolean(false), new Boolean(false), new Boolean(false), false, false,  'A' ]) { let this.i1 = new Iterator(e2); } } while(/*UUV2*/(a.valueOf = a.push));");
/*fuzzSeed-211892750*/count=489; tryItOut("this.v0 = t0.length;");
/*fuzzSeed-211892750*/count=490; tryItOut("g2.t1 + '';");
/*fuzzSeed-211892750*/count=491; tryItOut("{ void 0; verifyprebarriers(); } a2.forEach((function() { try { v0 = new Number(-Infinity); } catch(e0) { } try { return; } catch(e1) { } try { v1 = a2.length; } catch(e2) { } a0.reverse(b2, o1); return o2.h2; }), e2);");
/*fuzzSeed-211892750*/count=492; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (((((0xf87008b)))>>>((i0)+((0xe872f113)))));\n    i2 = (i0);\n    return (((((i1)-(i1)))-(i0)))|0;\n  }\n  return f; })(this, {ff: a => \u3056}, new ArrayBuffer(4096)); ");
/*fuzzSeed-211892750*/count=493; tryItOut("\"use asm\"; let z = (4277), smujoi, cdcgid, b;/*vLoop*/for (var qychhu = 0; qychhu < 32; ++qychhu) { var z = qychhu; { void 0; abortgc(); } } ");
/*fuzzSeed-211892750*/count=494; tryItOut("mathy4 = (function(x, y) { return ( + Math.expm1(Math.max(( + mathy2(y, Math.fround((Math.tanh((((2**53 | 0) + (Math.imul(x, ( + x)) >>> 0)) >>> 0)) >>> 0)))), ( + Math.tan(( + Number.MIN_VALUE)))))); }); testMathyFunction(mathy4, [false, true, [], (new Boolean(false)), 0.1, '/0/', 0, -0, ({valueOf:function(){return '0';}}), (function(){return 0;}), 1, (new String('')), (new Boolean(true)), (new Number(0)), [0], null, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), undefined, NaN, (new Number(-0)), '\\0', objectEmulatingUndefined(), '0', /0/, '']); ");
/*fuzzSeed-211892750*/count=495; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.exp(( + (Math.imul(((Math.imul(( + Math.asin(( + Math.log2(y)))), x) % ((y >>> -0x080000001) >>> 0)) >>> 0), Math.ceil((mathy2(Math.hypot(-Number.MIN_VALUE, (Math.hypot((-Number.MIN_SAFE_INTEGER | 0), (x | 0)) | 0)), ( + Math.expm1(( + y)))) | 0))) | 0))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 2**53-2, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, 0, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), 1, Math.PI, 1/0, -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, -0, -(2**53), 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, 2**53, -Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -0x080000000, -0x100000001, -1/0, 0x080000000, -0x100000000, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-211892750*/count=496; tryItOut("Array.prototype.unshift.apply(a2, [b2, window, p2, i2]);");
/*fuzzSeed-211892750*/count=497; tryItOut("Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-211892750*/count=498; tryItOut("\"use strict\"; this.s2 = new String;");
/*fuzzSeed-211892750*/count=499; tryItOut("const x = /*MARR*/[[], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), [],  /x/g ,  /x/g , [], new Boolean(false), [], [],  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), []].filter, eval, jvhtsh, x = /*MARR*/[new String(''), (-1/0), new String(''), new String(''), (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (-1/0), new String(''), new String(''), new Number(1.5), new String(''), new String('q'), new String('q'), new String('q'), new String('q'), new String(''), new String(''), new String(''), (-1/0), new Number(1.5), new String('q'), new Number(1.5), new Number(1.5), new String(''), new String(''), new String('q'), (-1/0), new String('')].map(Function, function(){}), d, gndpnp, gjfryy, ehbxom;selectforgc(o2);");
/*fuzzSeed-211892750*/count=500; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return (((Math.asin((( + (mathy0(Math.fround(0x0ffffffff), Math.fround(( + y))) | 0)) | 0)) >>> 0) == Math.atan2(Math.trunc(mathy0(y, y)), ((( ~ (y * Math.fround(y))) / (x | 0)) | 0))) >>> 0); }); testMathyFunction(mathy4, [1/0, -(2**53+2), -0x07fffffff, 42, 2**53+2, 0/0, 0x0ffffffff, -0x100000000, -(2**53), -0, 0x080000001, 2**53, 0x07fffffff, Number.MAX_VALUE, 1, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, 0, -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, Math.PI, 0x100000001]); ");
/*fuzzSeed-211892750*/count=501; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=502; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -536870913.0;\n    return (((0xf846f233)))|0;\n    {\n      {\n        i0 = ((~((0xff345db4)+(!(!((~~((134217727.0) + (-2.4178516392292583e+24))) > (0x131786af)))))) != (((Uint16ArrayView[1])) | ((0x86b67c17)+((0xf305e970) < (0xcd0bb939))-(i0))));\n      }\n    }\n    i0 = (/*FFI*/ff(((+tan(((d1))))), ((((!(i0))+(0xfcb60fed)) & ((i0)*0x232f5))))|0);\n    {\n      {\n        (Int32ArrayView[2]) = (-0x3b54f*(0xf2fd612b));\n      }\n    }\n    (Float32ArrayView[( \"\" ) >> 2]) = ((+((((Float64ArrayView[((((/*FFI*/ff(((((0x2ce7cba1)) >> ((0x18556a36)))), ((d1)), ((70368744177665.0)), ((2.3611832414348226e+21)), ((-15.0)))|0)-(0xc254f502)))+(0xffffffff)) >> 3])) % ((-549755813889.0))))));\n    i0 = (0xfdda670e);\n    i0 = (0xce36202b);\n    d1 = (+atan2(((d2)), ((0.0009765625))));\n    d2 = (d1);\n    return (((((-(((0x881c166d)+(-0x8000000)+(0xf91491e3)))) | ((i0)-((((0x6ca31c13)-(-0x8000000)-(0x262ac7b6))>>>((0x522b3872)+(0xfe5f0675)-(-0x8000000))) >= (0xdac337e3))+(0x26370bb6))))))|0;\n  }\n  return f; })(this, {ff: Array.prototype.join}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[(4277), new Number(1), 0/0, new Number(1), new Number(1), 0/0, new Number(1), (4277), new Number(1)]); ");
/*fuzzSeed-211892750*/count=503; tryItOut("a2.sort(f2, new Int32Array(x), s2, o2);");
/*fuzzSeed-211892750*/count=504; tryItOut("v1 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-211892750*/count=505; tryItOut("mathy0 = (function(x, y) { return ( + Math.abs(Math.atan2(Math.cbrt((Math.sin((( ! (Math.max(0/0, y) >>> 0)) >>> 0)) > x)), Math.max((y / (x === -0x100000001)), (Math.fround((x >> Math.fround(2**53-2))) !== ( ! ( + Math.imul(x, 2**53+2)))))))); }); testMathyFunction(mathy0, [2**53-2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -0x100000000, 2**53, 0x07fffffff, -0, Number.MIN_VALUE, 2**53+2, 0, 0x080000001, -0x100000001, -(2**53), 0x080000000, 0/0, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -Number.MAX_VALUE, 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), Number.MAX_VALUE, Math.PI, -0x0ffffffff, 42, -0x07fffffff, 0x100000000]); ");
/*fuzzSeed-211892750*/count=506; tryItOut("mathy0 = (function(x, y) { return ( + (( + ( + ( - ( + ( ! (Math.max((Math.PI | 0), (( + ((0x100000001 <= 42) <= ( + x))) | 0)) | 0)))))) + ( + Math.cbrt(Math.trunc(( + ( - Math.pow((y | 0), (y | 0))))))))); }); testMathyFunction(mathy0, /*MARR*/[(4277),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (4277), (4277),  \"use strict\" , (4277),  \"use strict\" ,  \"use strict\" , function(){},  \"use strict\" ,  \"use strict\" , (4277), (4277), function(){},  \"use strict\" , (4277), (4277), function(){}, function(){}, (4277), function(){},  \"use strict\" , function(){},  \"use strict\" , function(){},  \"use strict\" , function(){},  \"use strict\" , function(){}, (4277),  \"use strict\" , function(){}, function(){},  \"use strict\" , (4277), (4277), (4277),  \"use strict\" , function(){},  \"use strict\" , function(){},  \"use strict\" ,  \"use strict\" , (4277),  \"use strict\" ,  \"use strict\" , function(){},  \"use strict\" , (4277), (4277), function(){}, function(){}, (4277), function(){}, (4277),  \"use strict\" ,  \"use strict\" , function(){},  \"use strict\" , function(){}, function(){}, (4277), function(){}, (4277),  \"use strict\" , function(){},  \"use strict\" , (4277), (4277), function(){}, (4277),  \"use strict\" ,  \"use strict\" , (4277), function(){}, (4277),  \"use strict\" , (4277),  \"use strict\" , (4277), function(){}, (4277), (4277), (4277), function(){}, (4277), (4277),  \"use strict\" , function(){}, function(){}, (4277), (4277), function(){}, function(){}, function(){},  \"use strict\" , function(){}, (4277), (4277), (4277),  \"use strict\" ,  \"use strict\" , function(){}, (4277), (4277),  \"use strict\" ,  \"use strict\" , (4277), (4277), (4277), (4277),  \"use strict\" , function(){}, function(){}, (4277),  \"use strict\" , (4277), (4277),  \"use strict\" , (4277), (4277),  \"use strict\" , (4277), function(){}, (4277), function(){}, function(){},  \"use strict\" , (4277),  \"use strict\" ,  \"use strict\" , function(){},  \"use strict\" , (4277), function(){},  \"use strict\" , function(){},  \"use strict\" , (4277), (4277), function(){},  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , function(){}, (4277), (4277),  \"use strict\" , (4277), function(){}, (4277), (4277), (4277), (4277), (4277),  \"use strict\" , (4277), function(){},  \"use strict\" , (4277),  \"use strict\" , function(){}, function(){}, (4277), function(){},  \"use strict\" , (4277),  \"use strict\" , function(){},  \"use strict\" , function(){}]); ");
/*fuzzSeed-211892750*/count=507; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.pow((Math.fround(Math.max(Math.fround((( - ( + y)) | 0)), Math.fround(Math.imul(x, ( + ( ~ (x | 0))))))) >> Math.atan2(( + x), (( + (( + ( + Math.fround(x))) >> 1.7976931348623157e308)) >>> 0))), (( + y) === (Math.fround((x | Math.fround(((y ? Math.trunc((x >>> 0)) : x) != y)))) >>> ( + ( ! (( + x) << y)))))); }); testMathyFunction(mathy0, [42, -1/0, 0x0ffffffff, -(2**53-2), 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 0/0, Math.PI, 0x07fffffff, -0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, Number.MIN_VALUE, 0, 0.000000000000001, 2**53+2, -0x0ffffffff, -Number.MAX_VALUE, 1/0, -0x07fffffff, -0, -0x080000001, 0x100000001, 1, -(2**53), 1.7976931348623157e308, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=508; tryItOut("/*infloop*/for(new c = window(d = this,  '' ); (([] =  '' )); (true).bind(\"\\u0B7E\", new RegExp(\"[^\\\\u0028-\\\\xEf-\\u001e\\u2f9e-\\\\u43bA\\u6b7a-\\\\uC5c5]\", \"gyim\"))()) x;\u000c");
/*fuzzSeed-211892750*/count=509; tryItOut("v1 = -Infinity;");
/*fuzzSeed-211892750*/count=510; tryItOut("\"use asm\"; let {} = delete x.e;{ if (isAsmJSCompilationAvailable()) { void 0; void schedulegc(9); } void 0; }");
/*fuzzSeed-211892750*/count=511; tryItOut("m0 + '';const b = (-18 << \"\\u1AD5\");");
/*fuzzSeed-211892750*/count=512; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 0x080000001, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, Math.PI, -0x080000000, -0, 0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 0, 1/0, 2**53, -0x080000001, -(2**53-2), 0/0, 2**53-2, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, -0x07fffffff, -(2**53), -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 0x100000000, -(2**53+2)]); ");
/*fuzzSeed-211892750*/count=513; tryItOut("c = ({length: x, name:  });print(x);");
/*fuzzSeed-211892750*/count=514; tryItOut("mathy0 = (function(x, y) { return (( + (( ! ( + Math.sinh(( + (Math.atan2((Math.expm1(x) * (( - (( + Math.log(( + x))) | 0)) | 0)), ((Math.atan2(( + x), 0) | 0) | 0)) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -0x080000001, 0x080000001, -Number.MIN_VALUE, 1/0, -(2**53), 42, -0x0ffffffff, 2**53+2, -0x07fffffff, Number.MIN_VALUE, -0x100000001, 0x100000001, 2**53, 0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, 0.000000000000001, 0, 1.7976931348623157e308, 0/0, 0x07fffffff, 2**53-2, -Number.MAX_VALUE, -(2**53+2), -0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=515; tryItOut("print(uneval(this.t2));");
/*fuzzSeed-211892750*/count=516; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return (( + Math.fround(Math.hypot(Math.fround(( + Math.fround(x))), Math.fround(((((( + mathy2(0x080000001, ( + y))) >>> 0) >>> 0) >>> (( ! Math.fround(( + ( - ( + y))))) >>> 0)) >>> 0))))) % ( + Math.max(( + (( + (mathy2(( + (( + mathy2(y, (Math.sin(y) | 0))) <= ( + y))), x) >>> 0)) >>> 0)), ( + ((((Math.fround(Math.min(((x >> y) >>> 0), ( + ( ~ ( + x))))) ? y : Math.PI) | 0) < (((((Math.sin(x) | 0) == y) | 0) | 0) >>> (Math.min(Math.fround(y), Math.fround(mathy1(Math.cosh(x), (y >>> 0)))) | 0))) | 0))))); }); testMathyFunction(mathy3, [2**53+2, -0x0ffffffff, -0x07fffffff, -(2**53+2), -Number.MIN_VALUE, 0/0, -0x100000000, -0, 0x100000000, 2**53-2, 0x100000001, 0.000000000000001, Number.MIN_VALUE, -1/0, 0x080000001, 0x0ffffffff, 1.7976931348623157e308, Math.PI, 0, 0x080000000, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -0x100000001, -(2**53-2), Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-211892750*/count=517; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.imul(Math.fround(( ! (Math.fround(( ~ ( + (Math.ceil(x) && Math.log10(y))))) | 0))), Math.fround(( ~ Math.fround(Math.fround(( - Math.fround(mathy2((((y == Math.exp(-0)) | 0) | 0), ( + Math.sin(( + Math.hypot(0x100000000, y))))))))))))); }); testMathyFunction(mathy4, [1, 0/0, -(2**53), 1/0, 42, -Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -0x07fffffff, 0, -0, -0x080000001, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, 0x100000000, -0x100000000, -0x0ffffffff, -(2**53-2), -0x080000000]); ");
/*fuzzSeed-211892750*/count=518; tryItOut("a1 = a2.filter(f1, p1);");
/*fuzzSeed-211892750*/count=519; tryItOut("\"use strict\"; b1 = a1[6];");
/*fuzzSeed-211892750*/count=520; tryItOut("f2 = a0[12];");
/*fuzzSeed-211892750*/count=521; tryItOut("\"use strict\"; \u3056 = linkedList(\u3056, 4048);");
/*fuzzSeed-211892750*/count=522; tryItOut("\"use strict\"; if((x % 28 != 17)) {for (var v of v2) { try { /*MXX1*/o0 = g0.Int8Array.BYTES_PER_ELEMENT; } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(b0, b2); } catch(e1) { } v2 = (b1 instanceof a0); } }");
/*fuzzSeed-211892750*/count=523; tryItOut("\"use strict\"; e0 + g0.b2;");
/*fuzzSeed-211892750*/count=524; tryItOut("\"use strict\"; { void 0; validategc(false); } print((({x: 16.watch(\"random\", ({/*TOODEEP*/}))\n, apply: /*FARR*/[this,  /x/ ,  \"\" , false].map(eval) })));");
/*fuzzSeed-211892750*/count=525; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return mathy0((Math.hypot((Math.log(Math.tan(y)) >>> 0), (Math.max(Math.fround(( + Math.imul(x, Math.fround(Math.expm1(Math.fround(x)))))), Math.fround(( ~ y))) >>> 0)) >>> 0), ( + Math.sign(( + (( + Math.atanh(( + Math.atan2(( + x), ( + y))))) - ( + Math.hypot((Math.sinh(mathy0(y, x)) >>> 0), (((Math.acosh(y) | 0) < (( + Math.log(( + Number.MAX_SAFE_INTEGER))) | 0)) | 0)))))))); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), true, (new Boolean(true)), [0], '0', -0, 0, [], '/0/', /0/, (new String('')), (function(){return 0;}), (new Number(0)), (new Boolean(false)), false, '', null, ({valueOf:function(){return 0;}}), 0.1, undefined, ({valueOf:function(){return '0';}}), NaN, (new Number(-0)), 1, '\\0', objectEmulatingUndefined()]); ");
/*fuzzSeed-211892750*/count=526; tryItOut("\"use strict\"; m0.get(t0);");
/*fuzzSeed-211892750*/count=527; tryItOut("Object.prototype.watch.call(f2, \"x\", (function() { try { v0 = g1.eval(\"function f1(t1) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    i1 = (!(-0x705a54c));\\n    return +((((d0)) % ((-73786976294838210000.0))));\\n    d0 = (+((((d0)) / ((Float32ArrayView[4096])))));\\n    {\\n      {\\n        i1 = (0x2c40454b);\\n      }\\n    }\\n    d0 = (128.0);\\n    {\\n      (Float32ArrayView[((((((Int32ArrayView[4096])) >> ((-0x8000000)-(0x1228051d)+(0xd0ad320b)))) > (+(((x.parseFloat((window = \\\"\\\\uE49C\\\"), -3)).eval(\\\"print(x);\\\")))))+((((0x76f8d45d))>>>((1))) != (0x623b134d))) >> 2]) = ((+((d0))));\\n    }\\n    return +((+abs(((Float32ArrayView[(-0xc136*((-0x8000000) < (~(((0xc11ea077) ? (0x7ca9bc13) : (-0x8000000))-(i1))))) >> 2])))));\\n  }\\n  return f;\"); } catch(e0) { } a0.pop(g2); return m1; }));function x(d\u000c)[,,z1].getInt8( /x/ )Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-211892750*/count=528; tryItOut("let (x = (4277), b = \"\\u36B8\" ?  ''  : [1], tsrxaf, kxeizq, x) { { sameZoneAs: ((let (e=eval) e))(({a2:z2}), \"\\u3587\"), cloneSingletons: (x % 3 != 2) } }");
/*fuzzSeed-211892750*/count=529; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53, 0x100000001, Number.MIN_VALUE, 0x07fffffff, 1/0, -0x100000000, -0x080000000, 1, 0.000000000000001, 1.7976931348623157e308, 0/0, 2**53-2, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, -0, -0x0ffffffff, 42, -0x07fffffff, 0x0ffffffff, 0x080000001, -1/0, 0, -Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-211892750*/count=530; tryItOut("mathy3 = (function(x, y) { return mathy0(( ~ (Math.atan2(x, ((Math.asinh((((y | 0) | (x >>> 0)) >>> 0)) >>> 0) | 0)) | 0)), ((Math.acos((y >>> 0)) * ( - Math.atan2((x == Math.fround(0x07fffffff)), x))) ? ( + mathy2(y, (mathy2(Math.fround(y), Math.fround(x)) | 0))) : ( + ( + (( + ( ~ (-0x080000001 > y))) / ( + Math.log(-1/0))))))); }); testMathyFunction(mathy3, [-(2**53+2), 2**53-2, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, -0x100000000, -0x100000001, Number.MIN_VALUE, -0x0ffffffff, -0x080000001, 42, Number.MAX_SAFE_INTEGER, 0, 0/0, 0x100000001, 2**53+2, 0x100000000, Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, 0x080000001, 2**53, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0, -Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, 1, 0.000000000000001, -(2**53-2), -1/0]); ");
/*fuzzSeed-211892750*/count=531; tryItOut("yield;let x = a;");
/*fuzzSeed-211892750*/count=532; tryItOut("\"use strict\"; do print(x); while(((x = Proxy.create(({/*TOODEEP*/})(\"\\u46E4\"),  /x/ ))) && 0);");
/*fuzzSeed-211892750*/count=533; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a1, ({valueOf: function() { a2 = new Array;function x() { \"use strict\"; v0 = NaN; } this.p1.toSource = f0;return 10; }}), { configurable: false, enumerable: false, get: (function(j) { f1(j); }), set: (function() { try { g0.g2.s1 = new String; } catch(e0) { } try { this.g2.v0 = g1.runOffThreadScript(); } catch(e1) { } e2.add(t2); return m2; }) });");
/*fuzzSeed-211892750*/count=534; tryItOut("{ void 0; minorgc(false); }");
/*fuzzSeed-211892750*/count=535; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0/0, -0x100000001, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), 2**53+2, -0x0ffffffff, 1, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -0, 1.7976931348623157e308, Number.MIN_VALUE, 42, 0, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, Number.MAX_VALUE, -0x07fffffff, -(2**53), 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, -1/0, -0x080000000, 2**53-2, -0x080000001, 2**53, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=536; tryItOut("mathy4 = (function(x, y) { return (Math.clz32(Math.fround(( ~ Math.fround(Math.fround((Math.fround(( ! (Math.atan2((-Number.MIN_VALUE || y), x) | 0))) ? Math.fround(Math.acos((Math.pow((Math.sinh(y) | 0), x) * (y | 0)))) : Math.fround(y))))))) >>> 0); }); testMathyFunction(mathy4, [0x07fffffff, -0x100000000, 0, 42, 0/0, Number.MIN_VALUE, 0x080000001, 0x100000000, -(2**53), 2**53-2, Math.PI, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, 1, Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, -0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 1.7976931348623157e308, 2**53, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-211892750*/count=537; tryItOut("m0.delete(o2);");
/*fuzzSeed-211892750*/count=538; tryItOut("testMathyFunction(mathy5, [0.000000000000001, -Number.MIN_SAFE_INTEGER, -0, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0x0ffffffff, 0x07fffffff, 2**53-2, 0x080000000, -(2**53+2), 42, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, 0x080000001, Math.PI, 1.7976931348623157e308, -0x100000001, -Number.MAX_VALUE, -0x100000000, -(2**53), 0x100000001, Number.MAX_VALUE, 0, -(2**53-2), 0/0, Number.MAX_SAFE_INTEGER, 2**53+2, 1, 1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-211892750*/count=539; tryItOut("let x;print(\"\\uDEBF\");");
/*fuzzSeed-211892750*/count=540; tryItOut("mathy1 = (function(x, y) { return Math.fround(( - ( + Math.hypot(( + (Math.atanh(y) + ( + (Math.asinh((x | 0)) | 0)))), ((( - Math.fround(Math.min(Number.MIN_VALUE, x))) >>> 0) === ( + (( + (Math.tan((-(2**53+2) >>> 0)) >>> 0)) >>> 0))))))); }); ");
/*fuzzSeed-211892750*/count=541; tryItOut("/*vLoop*/for (cobool = 0; cobool < 31; ++cobool) { b = cobool;  } ");
/*fuzzSeed-211892750*/count=542; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.log(Math.fround(Math.fround(Math.fround(((((mathy2(x, (x | 0)) | 0) ? Math.fround(((y % x) | 0)) : Math.fround(x)) | 0) ? Math.fround(Math.hypot((x >>> 0), (( + mathy0(-0, (Math.ceil((x >>> 0)) >>> 0))) ? ( ! (2**53+2 >>> 0)) : (x | 0)))) : mathy4((((Math.fround(Math.sign(((y >>> 0) ? (y >>> 0) : y))) >>> 0) & (Math.min((Math.fround(y) ? x : y), x) >>> 0)) >>> 0), ( + y))))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 1/0, 2**53-2, -0x100000001, 0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 2**53+2, -(2**53), 0x0ffffffff, -1/0, 0.000000000000001, -0x0ffffffff, 0/0, 0, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 1, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53, -0, -(2**53-2), 1.7976931348623157e308, Math.PI, -0x100000000, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-211892750*/count=543; tryItOut("b = window & eval(\"return;\",  \"\" );/*ADP-1*/Object.defineProperty(a2, x, ({configurable: new RangeError(z % b, /*UUV1*/(x.toString = encodeURIComponent)), enumerable: true}));");
/*fuzzSeed-211892750*/count=544; tryItOut("\"use strict\"; a2.sort((function(j) { if (j) { try { t0[x]; } catch(e0) { } try { m2.has(g0.v2); } catch(e1) { } try { print(o2); } catch(e2) { } Array.prototype.splice.call(a1, -7, 19, h0, h1); } else { v0 = Object.prototype.isPrototypeOf.call(a0, m0); } }));");
/*fuzzSeed-211892750*/count=545; tryItOut("mathy4 = (function(x, y) { return Math.round((Math.expm1((Math.fround(Math.hypot((mathy2(Math.log1p(( + y)), x) >>> 0), Math.fround((Math.min(Number.MAX_SAFE_INTEGER, Math.acosh(x)) << Math.fround(Math.ceil(Math.fround(Math.sinh((1 >>> 0))))))))) | 0)) | 0)); }); testMathyFunction(mathy4, /*MARR*/[true, new Number(1.5), new Number(1.5), true, new Number(1.5), new Number(1.5), true, new Number(1.5), true, new Number(1.5), new Number(1.5), true, new Number(1.5), true, new Number(1.5), true, new Number(1.5), new Number(1.5), true, new Number(1.5), true, true, true, new Number(1.5), true, true, true, true, new Number(1.5), true, true, true, new Number(1.5), true, true, true, true, true, new Number(1.5), true, new Number(1.5), true, new Number(1.5), true, new Number(1.5), new Number(1.5), new Number(1.5), true, new Number(1.5), true, true, true, true, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), true, true, new Number(1.5), true, true, true, new Number(1.5), new Number(1.5), true, true, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), true, true, true, true, true, true, true, new Number(1.5), new Number(1.5), true, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), true, true, true, true, new Number(1.5), new Number(1.5), true, true, true, new Number(1.5), true]); ");
/*fuzzSeed-211892750*/count=546; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(Math.min((( + (Math.log1p(((Math.fround(mathy0(y, y)) < Math.fround(x)) | 0)) ^ Math.sinh(Math.atan2(-0, y)))) === ( + (Number.MIN_VALUE === ( ~ ( + ( + Math.imul(( + Math.asin(0/0)), ( + ((y | 0) ** (x >>> 0)))))))))), Math.fround((Math.fround(Math.exp((x + Math.pow(x, x)))) < Math.fround((Math.pow(Math.fround(Math.sign((-0x080000001 | 0))), ((y << x) >>> 0)) | 0))))), (mathy0(( ! ( + Math.hypot(( + Math.acosh(x)), ( + x)))), Math.fround(( ~ Math.fround(( + Math.fround((Number.MAX_SAFE_INTEGER < x))))))) , (Math.cbrt(((Math.hypot((x >>> 0), ((Math.fround(Math.round(x)) == y) >>> 0)) | 0) == 1.7976931348623157e308)) >>> 0))); }); testMathyFunction(mathy1, [Math.PI, 0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 0x100000001, 1, -0x080000000, 0/0, -0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 42, 2**53, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), 0.000000000000001, -1/0, -0x100000001, -0x080000001, 0x080000000, Number.MIN_VALUE, 2**53+2, 0x07fffffff, 1/0, 0x0ffffffff, -(2**53), -Number.MIN_VALUE, -0x100000000, -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-211892750*/count=547; tryItOut("mathy3 = (function(x, y) { return (Math.exp((Math.max((Math.pow(((Math.fround(Math.hypot(0x07fffffff, ( + (Math.imul(0.000000000000001, x) ? ( + Math.fround(Math.atan2(Math.fround(x), Math.fround(y)))) : ( + ((x ? ( + y) : -Number.MAX_SAFE_INTEGER) >>> 0)))))) ? ( + -0x100000000) : ( + mathy1(x, x))) >>> 0), (Math.log(((( + x) ^ (Math.hypot(( + y), ( + 0x100000000)) >>> 0)) >>> 0)) >>> 0)) >>> 0), Math.fround(mathy0(( + Math.ceil(( + (( + ( ~ ( + y))) || (( + Math.cbrt(0/0)) | ( + x)))))), Math.hypot((y | 0), Math.fround(-(2**53)))))) | 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_VALUE, -0x100000000, -0x100000001, -(2**53-2), -Number.MIN_VALUE, -0x080000001, 0x100000000, -0x0ffffffff, 0x07fffffff, 0, -Number.MAX_VALUE, 2**53+2, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, -0x080000000, 0/0, 2**53, 1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 1, -0, -1/0, -(2**53+2), 2**53-2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, 0x080000000, 0x100000001]); ");
/*fuzzSeed-211892750*/count=548; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( ! ( + (Math.atan2(x, (( ~ ((y | x) >>> 0)) >>> 0)) >>> 0))) ^ (Math.cos(((Math.hypot((Math.log2(y) | 0), (x | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[(0/0)]); ");
/*fuzzSeed-211892750*/count=549; tryItOut("");
/*fuzzSeed-211892750*/count=550; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! Math.min(Math.fround(( ! Math.fround(((( ~ x) == -(2**53+2)) >>> 0)))), ( ! Math.fround(0x080000000)))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 1, 0x0ffffffff, 0x100000001, 0, 1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, 2**53+2, 0x080000001, 42, 2**53, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, 0x100000000, Number.MAX_VALUE, -(2**53), 2**53-2, Number.MIN_VALUE, -0x100000001, Math.PI, -(2**53+2), -(2**53-2), -1/0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff]); ");
/*fuzzSeed-211892750*/count=551; tryItOut("mathy1 = (function(x, y) { return mathy0(((((Math.min(Math.fround((Math.fround(1) % Math.fround(x))), Math.max(( + y), ( + -0x100000000))) >>> 0) >>> 0) < Math.fround((Math.fround((mathy0((Math.log2(x) | 0), ((( ~ (0x080000001 >>> 0)) >>> 0) | 0)) | 0)) <= Math.fround((((( ~ (y >>> 0)) !== Math.imul(0/0, 1.7976931348623157e308)) % (((y >>> 0) > (0x100000000 >>> 0)) >>> 0)) < x))))) >>> 0), (( ~ (Math.hypot(Math.fround(( ~ ((Math.fround(( ! Math.fround(x))) >= x) || Math.atan2(x, mathy0(y, x))))), (Math.fround((Math.fround(1/0) > Math.fround(((2**53-2 && y) | 0)))) % x)) | 0)) | 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x080000001, -(2**53), 0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 0x100000001, 1, -Number.MIN_SAFE_INTEGER, 42, -0x080000001, Math.PI, -1/0, 0.000000000000001, -0x100000000, 0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 1/0, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 2**53, 0, -Number.MAX_VALUE, -0x100000001, -(2**53-2), 2**53-2, -0]); ");
/*fuzzSeed-211892750*/count=552; tryItOut("g1.offThreadCompileScript(\"for (var v of o0.v2) { try { g2.a2.pop(t1, g0.m1); } catch(e0) { } try { Object.defineProperty(this, \\\"this.v1\\\", { configurable: 11, enumerable: true,  get: function() {  return t2.byteLength; } }); } catch(e1) { } try { selectforgc(o2); } catch(e2) { } g1.offThreadCompileScript(\\\"function this.f0(b1)  { yield (intern(/*wrap1*/(function(){ print(window);return mathy2})().prototype)) % Math.hypot(({ get getUTCMilliseconds(d, w) { throw  /x/g ; } , \\\\\\\"997757515\\\\\\\": [[]] }), 20) } \\\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 25 != 18), noScriptRval: (x % 3 == 2), sourceIsLazy: 28, catchTermination: (x % 6 != 0) })); }\", ({ global: o2.g2, fileName: null, lineNumber: 42, isRunOnce: (x % 2 != 1), noScriptRval: /*MARR*/[allocationMarker(), allocationMarker(), x, arguments, arguments, arguments, arguments, 1e81, allocationMarker(), 1e81, (-1), allocationMarker(), (-1), arguments, 1e81, arguments, x, x, allocationMarker(), x, arguments, 1e81, allocationMarker(), arguments, allocationMarker(), x, (-1), x, arguments, x, x, arguments, (-1), (-1), x, 1e81, 1e81, allocationMarker(), allocationMarker(), 1e81, allocationMarker(), arguments, allocationMarker(), 1e81, x, 1e81, x, arguments, (-1), arguments, arguments, arguments, allocationMarker(), arguments, arguments].sort, sourceIsLazy: true, catchTermination: (x % 5 == 0) }));");
/*fuzzSeed-211892750*/count=553; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((((((mathy0((x > Math.tanh(( + y))), ((Math.min((-(2**53) >>> 0), (( + (0x0ffffffff | 0)) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0) !== (x | 0)) | 0) << mathy0(((y >>> 0) * ( ~ x)), (mathy2((Math.cos((x >>> 0)) >>> 0), Math.pow(x, y)) >>> 0))) ? ( ! ( ~ (Math.acos(((Math.max((Math.atan2(y, x) >>> 0), (Math.cosh(y) >>> 0)) >>> 0) | 0)) | 0))) : Math.fround(Math.asin(( + ( - (Math.pow(Math.fround(Math.fround(( + Math.fround(y)))), Number.MAX_SAFE_INTEGER) >>> 0)))))); }); testMathyFunction(mathy3, [0x0ffffffff, 0, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 1, 0x07fffffff, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 2**53-2, -0x100000000, -0x07fffffff, -0x100000001, 0x080000000, 1/0, -0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0x080000001, 0x100000000, -0x0ffffffff, -0x080000000, -(2**53), Math.PI, Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -0, -(2**53+2), 42, -Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=554; tryItOut("g0.v2 = Object.prototype.isPrototypeOf.call(a2, p1);");
/*fuzzSeed-211892750*/count=555; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - ((( + Math.round(( + y))) ? y : y) === -(2**53-2))) <= ( + Math.fround(Math.acos(Math.fround(Math.pow(Math.sqrt(y), (Math.acosh(0x07fffffff) | 0))))))); }); testMathyFunction(mathy5, [-0x100000000, 0.000000000000001, -0x0ffffffff, 1/0, -0x080000000, 1.7976931348623157e308, -0x080000001, 0x100000001, 0x07fffffff, 0/0, -1/0, Math.PI, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000000, -(2**53-2), 2**53+2, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53), 42, 0, 0x080000000, 0x080000001, -0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000001]); ");
/*fuzzSeed-211892750*/count=556; tryItOut("s0 += 'x';");
/*fuzzSeed-211892750*/count=557; tryItOut("m0.set(i1, h0);");
/*fuzzSeed-211892750*/count=558; tryItOut("a0.unshift(o1);");
/*fuzzSeed-211892750*/count=559; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.expm1(Math.pow(( + mathy4(-(2**53-2), (0x080000000 ? ((y >>> 0) / 2**53-2) : x))), mathy2(Math.fround(Math.fround(( - this))), x))); }); testMathyFunction(mathy5, [0x100000001, -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -0, -(2**53+2), -0x080000000, -Number.MAX_VALUE, -0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 42, 0x0ffffffff, Number.MIN_VALUE, 2**53-2, -(2**53), 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 2**53+2, Number.MAX_VALUE, -0x100000000, 1, -0x0ffffffff, Math.PI, 0.000000000000001, -0x07fffffff, 0]); ");
/*fuzzSeed-211892750*/count=560; tryItOut("/*tLoop*/for (let e of /*MARR*/[(0/0), new String('q')]) { {return /\\B/gym; } }");
/*fuzzSeed-211892750*/count=561; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-211892750*/count=562; tryItOut("for (var p in m2) { try { g0.offThreadCompileScript(\";\"); } catch(e0) { } try { m1 = new Map; } catch(e1) { } try { delete h2.hasOwn; } catch(e2) { } s0 += s2; }");
/*fuzzSeed-211892750*/count=563; tryItOut("o2 + '';");
/*fuzzSeed-211892750*/count=564; tryItOut("Array.prototype.sort.call(a2, f0, (/*MARR*/[x,  /x/g , null, null,  /x/g ,  /x/g ,  /x/g , null, x, x, x, x, null, x,  /x/g , x,  /x/g , null, x,  /x/g ,  /x/g , x, null, x,  /x/g , x, null, x, null,  /x/g ,  /x/g ,  /x/g , null, null, null,  /x/g , x, x,  /x/g ,  /x/g , x, x, x,  /x/g , x,  /x/g ,  /x/g , x, x, x, x, null, x, null,  /x/g , x, x, x,  /x/g , x, null, x, null,  /x/g , x, null, null,  /x/g ,  /x/g , x, x, null, x, x, x, x,  /x/g , x, null,  /x/g , x,  /x/g , x, x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , null, x,  /x/g , x,  /x/g , x,  /x/g ,  /x/g , null, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x, x, x, x,  /x/g , x].map(new Function)), o0);");
/*fuzzSeed-211892750*/count=565; tryItOut("\"use strict\"; v0 = evalcx(\"x-=x %= x(/\\\\2*/yi, true\\u0009)\", g0);");
/*fuzzSeed-211892750*/count=566; tryItOut("print(x);print(uneval(s1));");
/*fuzzSeed-211892750*/count=567; tryItOut("(x);function window()\"use asm\";   var Infinity = stdlib.Infinity;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 2097152.0;\n    return +((Infinity));\n  }\n  return f;print(x);");
/*fuzzSeed-211892750*/count=568; tryItOut("{ void 0; minorgc(true); } m0.has(t0);");
/*fuzzSeed-211892750*/count=569; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-211892750*/count=570; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( - (( - ( + Math.pow(( + (Math.imul(Math.asinh(( + Math.max(x, 2**53))), (Math.atan2(( + Math.fround((x + y))), (Math.min((Number.MAX_VALUE | 0), 0.000000000000001) | 0)) | 0)) ? Math.fround(Math.atan2(( + (( + 2**53) !== ( + x))), Math.log(( + (( - (y >>> 0)) >>> 0))))) : Math.fround(( - Math.fround(x))))), x))) >>> 0))); }); ");
/*fuzzSeed-211892750*/count=571; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var tan = stdlib.Math.tan;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 144115188075855870.0;\n    var d3 = 33554433.0;\n    var i4 = 0;\n    {\n      {\n        /*FFI*/ff(((0x2d85673e)));\n      }\n    }\n    d0 = (562949953421311.0);\n    d2 = (d2);\n    i4 = (0xffffffff);\n    {\n      return +((+ceil(((36893488147419103000.0)))));\n    }\n    d2 = (+tan(((d3))));\n    (Float32ArrayView[4096]) = ((d2));\n    d3 = (d2);\n    d3 = (+(-1.0/0.0));\n    {\n      {\n        d2 = (((Float64ArrayView[2])) / ((-4097.0)));\n      }\n    }\n    d2 = (+(-1.0/0.0));\n    {\n      d0 = (d0);\n    }\n;    i4 = (i1);\n    return +((-1.5111572745182865e+23));\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-211892750*/count=572; tryItOut("mathy3 = (function(x, y) { return ( + ((Math.imul(( + (Math.sinh((Math.acos(Math.PI) | 0)) | 0)), Math.fround(Math.imul(Math.fround(y), x))) && (Math.cosh(mathy0(((Math.pow(y, x) | 0) >>> 0), ( + Math.max(Math.max(Math.fround(y), Math.fround(x)), x)))) >>> 0)) | 0)); }); testMathyFunction(mathy3, [42, 0, -0x080000001, 2**53-2, 0x080000001, 0.000000000000001, -0, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -(2**53+2), 2**53+2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 1, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 1/0, 2**53, -(2**53), -(2**53-2), -Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-211892750*/count=573; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 4.835703278458517e+24;\n    var d5 = -65536.0;\n    (Uint8ArrayView[(((~((0xff831e5f)-(-0x8000000)-(0x4a7c094f))) < (abs((((0x2eadfa01)) ^ ((0xffffffff))))|0))-((d5) < (+(1.0/0.0)))+(/*FFI*/ff(((2147483649.0)), ((((0x1e017946)) >> ((0xffffffff)))), ((((-0x56f0f80)) & ((0xff2d912c)))), ((-36028797018963970.0)), ((1.015625)), ((8796093022209.0)), ((-2049.0)), ((-67108865.0)), ((513.0)), ((0.0009765625)), ((2147483648.0)), ((1.25)), ((-1099511627777.0)), ((-2097152.0)), ((7.737125245533627e+25)))|0)) >> 0]) = ((i3)+(i1));\n    d4 = (NaN);\n    i2 = ((0x44344e89));\n    return (((!(!(((Uint8ArrayView[0])))))))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 0x080000000, -0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, -0, 0x080000001, -(2**53+2), 0, 0/0, -(2**53), -(2**53-2), -0x100000000, 0x100000001, 0.000000000000001, 1/0, -0x080000001, -Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -1/0, 2**53+2, 0x07fffffff, 2**53, 2**53-2, -0x100000001, 0x0ffffffff, Math.PI]); ");
/*fuzzSeed-211892750*/count=574; tryItOut("\"use strict\"; /*RXUB*/var r = x; var s = ({x: x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { throw 3; }, delete: function(y) { return /(?=\\1)/ym }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: undefined, iterate:  '' , enumerate: function() { return []; }, keys: function() { return []; }, }; })([z1]), (1 for (x in []))) }); print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=575; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - (Math.exp((Math.hypot(Math.cos(-1/0), y) ** Math.log10(( + (((x | 0) - (x | 0)) | 0))))) | 0)); }); testMathyFunction(mathy5, [0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, 42, 0x100000000, -0x100000001, 0x0ffffffff, -0x080000000, -0x100000000, -0, 1/0, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 1, -1/0, 0, -0x080000001, 2**53+2, -(2**53), 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 2**53, Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, 0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-211892750*/count=576; tryItOut("\"use asm\"; /*MXX2*/g2.DataView.BYTES_PER_ELEMENT = f1;");
/*fuzzSeed-211892750*/count=577; tryItOut("\"use asm\"; s0 = g2.g2.g2.objectEmulatingUndefined();");
/*fuzzSeed-211892750*/count=578; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.imul(( + (mathy4((Math.atanh((mathy2(x, Number.MAX_VALUE) | 0)) | 0), Math.fround(((( ~ y) || ((Math.ceil(x) << Math.atan2((1 > -0x07fffffff), x)) >>> 0)) >>> 0))) >>> 0)), (Math.sinh(( + (Math.atan2(x, mathy4((Math.min(Math.fround(x), (2**53+2 | 0)) >>> 0), (Math.atan2(y, -Number.MAX_SAFE_INTEGER) >>> 0))) >>> 0))) >>> 0)); }); testMathyFunction(mathy5, [[0], (function(){return 0;}), '/0/', (new Boolean(false)), (new String('')), false, '\\0', ({valueOf:function(){return '0';}}), 1, '0', null, (new Number(0)), objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), (new Number(-0)), (new Boolean(true)), 0, true, NaN, ({toString:function(){return '0';}}), -0, /0/, '', undefined, []]); ");
/*fuzzSeed-211892750*/count=579; tryItOut("t0 = new Uint8ClampedArray(17);");
/*fuzzSeed-211892750*/count=580; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.expm1((Math.fround(( ! Math.fround(( + (( + x) , ( + (mathy0(( - (( + y) ? ( + y) : Number.MAX_SAFE_INTEGER)), Math.cbrt(x)) >>> 0))))))) | 0)) | 0); }); testMathyFunction(mathy4, [-1/0, 2**53+2, 2**53-2, Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, -0x07fffffff, -(2**53+2), 0x07fffffff, Number.MIN_VALUE, 0x080000001, 0.000000000000001, 1.7976931348623157e308, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53, 42, -0x080000001, -0, -Number.MAX_VALUE, 0x080000000, 0x0ffffffff, -(2**53), -0x0ffffffff, Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, 1, 0, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=581; tryItOut("mathy0 = (function(x, y) { return Math.atan2(( ~ (Math.atanh(( ~ (Math.pow((x >>> 0), x) >>> 0))) | 0)), (( ! (((Math.fround((x >>> Math.round(x))) ? Math.fround(0x080000001) : (0x080000001 | 0)) , (Math.log1p(0x07fffffff) | 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-211892750*/count=582; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.cosh(Math.hypot(( + Math.min(( + ( ~ ((((( ~ (( + ( + -(2**53-2))) | 0)) | 0) | 0) & (( - Math.sign(y)) | 0)) | 0))), ( + Math.min((x < mathy1(y, x)), ( - -(2**53)))))), ((( + -Number.MAX_SAFE_INTEGER) & ( ! Math.hypot(x, 2**53))) | 0))); }); testMathyFunction(mathy5, [Math.PI, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, 2**53+2, 0x080000000, 1.7976931348623157e308, 1, 0x07fffffff, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, 0x100000001, 2**53, -Number.MIN_VALUE, -1/0, -0x07fffffff, -0x080000001, 1/0, -(2**53+2), Number.MIN_VALUE, -(2**53), 0x080000001, -(2**53-2), 0x100000000, 0/0, 0x0ffffffff, -0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, 0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=583; tryItOut("g2.m2.has(f2);m2.toString = (function(stdlib, foreign, heap){ \"use asm\";   var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.2089258196146292e+24;\n    var i3 = 0;\n    i3 = (i3);\n    {\n      d2 = (d0);\n    }\n    return +(([1,,] ? arguments : window));\n    i3 = ((((i3)+(x)-(-0x8000000))>>>(((((-0x8000000)-((0xa8c2009d) == (0x2f8cf47d))-(0xfd5438e0))>>>((~((0xffffffff))) / (~((0xa3a7f32e))))))+(i3))));\n    (Uint8ArrayView[4096]) = (((((0x977d2f58))>>>((Int16ArrayView[((i3)-(0x3e138381)) >> 1]))) <= (0x4cbadfb4)));\n    {\n      d1 = ((c = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: Function, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: undefined, enumerate: (function  x (b) { \"use strict\"; yield undefined } ).apply, keys: function() { return []; }, }; })(-21), decodeURIComponent)));\n    }\n    return +((-2049.0));\n  }\n  return f; });");
/*fuzzSeed-211892750*/count=584; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.exp(((((mathy0(2**53, (0x100000000 | 0)) | 0) | 0) >= (Math.abs((( + y) / ( - ( + Math.sign((( - Number.MAX_SAFE_INTEGER) | 0)))))) | 0)) | 0)); }); testMathyFunction(mathy1, [1.7976931348623157e308, 2**53-2, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, -0x07fffffff, -0, -0x100000001, 1/0, 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, 0.000000000000001, 0x100000001, -1/0, -0x080000001, 1, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -(2**53-2), -(2**53+2), 0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, 2**53+2, 0x0ffffffff, 0]); ");
/*fuzzSeed-211892750*/count=585; tryItOut("Object.freeze(t2);");
/*fuzzSeed-211892750*/count=586; tryItOut("this.a2 = arguments;");
/*fuzzSeed-211892750*/count=587; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ! (( - mathy1((mathy0((x === x), (Math.PI | 0)) >>> 0), (((Math.fround(Math.max(Math.fround(y), Math.fround(y))) >>> 0) > (( + Math.pow(((y & x) | 0), ( + mathy1(x, (x | 0))))) >>> 0)) >>> 0))) | 0))); }); testMathyFunction(mathy4, [-1/0, 0x100000001, -0x080000001, -0x100000001, 2**53+2, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 0, -0x100000000, 0x080000001, 0.000000000000001, Number.MIN_VALUE, 0x07fffffff, 42, 0/0, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, 1/0, 1.7976931348623157e308, -(2**53-2), -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, -0, -Number.MIN_VALUE, -0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 1, 2**53, -(2**53)]); ");
/*fuzzSeed-211892750*/count=588; tryItOut("/*RXUB*/var r = /([^])|(?!\\D)|\\D{3}|\\b|[^]|\\1.(?!\\b)+?/gm; var s = \"\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-211892750*/count=589; tryItOut("{ void 0; minorgc(false); } a2.pop();");
/*fuzzSeed-211892750*/count=590; tryItOut("\"use strict\"; Array.prototype.shift.call(a2);{let c =  /x/ ;print(c); }");
/*fuzzSeed-211892750*/count=591; tryItOut("v0.valueOf = (function() { try { let a1 = a2.slice(NaN, -4); } catch(e0) { } try { t2.toString = (function(j) { f0(j); }); } catch(e1) { } a1.forEach(f2); return a0; });");
/*fuzzSeed-211892750*/count=592; tryItOut("mathy3 = (function(x, y) { return ( + Math.min(( + ((x, y < Math.fround((Math.fround((x - 0x100000000)) ** Math.fround(Math.fround(Math.sin((Math.fround(y) >= x))))))) / (((( ! mathy1((-0 >>> 0), ( + Math.asin(x)))) | 0) ** Math.fround(Math.pow(Math.fround(y), (mathy0(((( - (x >>> 0)) >>> 0) >>> 0), (Math.fround(Math.max(Math.fround(( + Math.sign(( + y)))), Math.fround(Math.hypot(y, 0.000000000000001)))) >>> 0)) >>> 0)))) >>> 0))), (( + ((Math.clz32(x) >>> 0) - (Math.max(x, x) >>> 0))) << (x / y)))); }); testMathyFunction(mathy3, [0x080000001, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 2**53+2, Math.PI, -Number.MIN_VALUE, -0x0ffffffff, -0x080000001, Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, 1/0, 0x0ffffffff, 0.000000000000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0, 0, 1, -0x07fffffff, 0x080000000, -(2**53-2), -1/0, -0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, -0x100000000, Number.MAX_VALUE, 0x100000001, 0x100000000, -(2**53), -(2**53+2)]); ");
/*fuzzSeed-211892750*/count=593; tryItOut("const [, , , ] = (makeFinalizeObserver('tenured')), uqsfhl, b, NaN = x **= e, y, e = (( ~ Math.fround(Math.imul(0x080000000, 0.000000000000001))) > 0x080000001), pcdhny, z = ({ set constructor x (c) { return x\n } , name: x }), eval, x;let(e) { 0 = b;}");
/*fuzzSeed-211892750*/count=594; tryItOut("var jdvqvg = new ArrayBuffer(0); var jdvqvg_0 = new Uint32Array(jdvqvg); jdvqvg_0[0] = 8; var jdvqvg_1 = new Int8Array(jdvqvg); print(jdvqvg_1[0]); var jdvqvg_2 = new Int32Array(jdvqvg); jdvqvg_2[0] = 0.303; var jdvqvg_3 = new Uint8ClampedArray(jdvqvg); var jdvqvg_4 = new Int8Array(jdvqvg); jdvqvg_4[0] = 9; var jdvqvg_5 = new Int32Array(jdvqvg); print(jdvqvg_5[0]); var jdvqvg_6 = new Float32Array(jdvqvg); var jdvqvg_7 = new Uint32Array(jdvqvg); jdvqvg_7[0] = 8; var jdvqvg_8 = new Uint32Array(jdvqvg); print(jdvqvg_8[0]); jdvqvg_8[0] = 13; var jdvqvg_9 = new Int16Array(jdvqvg); print(jdvqvg_9[0]); jdvqvg_9[0] = 25; g2.offThreadCompileScript(\"\\\"use strict\\\"; print(new RegExp(\\\"(?!.+\\\\\\\\d{4294967295})\\\", \\\"yi\\\"));\", ({ global: o0.g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: ({a1:1}), sourceIsLazy: true, catchTermination: (jdvqvg_4 % 4 == 3), element: o2 }));({});yield;print(jdvqvg_7[10]);Object.seal(s0);/*MXX2*/g1.SyntaxError.prototype.message = m1;;for (var v of this.o1) { try { /*MXX2*/g0.Math.LN2 = b2; } catch(e0) { } try { for (var p in h0) { try { v0 = (f1 instanceof s1); } catch(e0) { } try { a0.splice(3, v0, o0, p0); } catch(e1) { } try { v1 = g2.runOffThreadScript(); } catch(e2) { } t0 + ''; } } catch(e1) { } f1(v0); }");
/*fuzzSeed-211892750*/count=595; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a0, this.__defineSetter__(\"x\", (let (e = function ([y]) { })  \"\" )), { configurable: (mathy2).call(x, x, Date(this, undefined)), enumerable: true, writable: true, value: h2 });");
/*fuzzSeed-211892750*/count=596; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((( + ( + Math.hypot(( ~ Math.exp(x)), ( + Math.min(x, (x ^ Math.max(( + -Number.MIN_SAFE_INTEGER), x))))))) ? Math.pow(((( + ( + ( + ( ~ Math.fround(x))))) + (Math.fround(y) <= (Math.ceil((x | 0)) | 0))) >>> 0), (((Math.abs(y) >>> 0) * (x >>> 0)) >>> 0)) : ((Math.fround(Math.acos(Math.fround(x))) ? ((Math.log10(-0) >>> 0) | 0) : (Math.fround(Math.asinh(Math.fround((Math.exp(x) ? (((y | 0) >> (Math.acosh(y) | 0)) | 0) : y)))) | 0)) | 0)) | 0) > (( + ( + (Math.sin(Math.round(Math.pow(x, Math.fround((Math.fround(-Number.MAX_SAFE_INTEGER) !== y))))) >>> 0))) | 0)); }); testMathyFunction(mathy0, [-0x100000000, 1, -0x07fffffff, -(2**53), 0/0, 0x0ffffffff, 0x100000000, -Number.MAX_VALUE, 0x07fffffff, 1/0, -0x080000000, 0x100000001, 0, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -0, 1.7976931348623157e308, -0x100000001, Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 0x080000001, 2**53-2, 0.000000000000001, Number.MAX_VALUE, -(2**53+2), -(2**53-2), -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=597; tryItOut("{o1.a2.reverse(m2, t0, g1);(4277); }");
/*fuzzSeed-211892750*/count=598; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + (Math.acos(( + x)) >>> 0)) != mathy2(Math.min(0x080000001, (Math.acos(( + -1/0)) != y)), ( ~ (Math.hypot((( + mathy3(y, y)) | 0), (x | 0)) | 0)))); }); ");
/*fuzzSeed-211892750*/count=599; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.pow(Math.fround(Math.atan2((Math.sin((((x >>> 0) ? (Math.imul(x, x) >>> 0) : (Math.fround(Math.atan((-(2**53-2) | 0))) | 0)) >>> 0)) >>> 0), Math.max(-Number.MIN_VALUE, Math.min(( + ( ! y)), ( + Math.hypot(x, (0 | 0))))))), Math.acos((Math.hypot((Math.atan2(y, y) >>> 0), (((((Math.sqrt(x) < y) | 0) ? x : (( + y) | 0)) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [(function(){return 0;}), [0], 0, 0.1, (new String('')), null, -0, ({valueOf:function(){return '0';}}), (new Boolean(true)), ({valueOf:function(){return 0;}}), NaN, '', '/0/', undefined, 1, false, (new Number(-0)), true, [], /0/, objectEmulatingUndefined(), '\\0', ({toString:function(){return '0';}}), '0', (new Number(0)), (new Boolean(false))]); ");
/*fuzzSeed-211892750*/count=600; tryItOut("\"use strict\"; M:if(true) {/*RXUB*/var r = r0; var s = \"\"; print(s.match(r));  } else {for (var p in i1) { try { a2.reverse(h0, this.b0); } catch(e0) { } try { a1[({valueOf: function() { true;return 10; }})] = (allocationMarker()); } catch(e1) { } try { i1.send(i0); } catch(e2) { } b0 = new ArrayBuffer(11); }t2 = t2.subarray(2, 0); }");
/*fuzzSeed-211892750*/count=601; tryItOut("v2 = new Number(o0);");
/*fuzzSeed-211892750*/count=602; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.exp(Math.hypot(( + Math.fround(Math.imul(x, x))), x))); }); ");
/*fuzzSeed-211892750*/count=603; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((( ~ (Math.atan2((( - ( + Math.trunc(( + ( + Math.atan2(( + x), ( + Math.fround(Math.log1p(Math.fround(2**53-2)))))))))) | 0), ((Math.fround(Math.min(Math.fround(-0x080000001), x)) | 0) + Math.cos(-0x100000001))) >>> 0)) >>> 0) ? Math.ceil(mathy4(y, (Math.min((y | 0), (x | 0)) | 0))) : ( - (Math.trunc(y) >>> 0))); }); testMathyFunction(mathy5, [-0x100000000, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, -(2**53), 0.000000000000001, -(2**53+2), -0x080000000, 2**53, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 0, 2**53-2, -(2**53-2), -0x080000001, 42, 1, -Number.MAX_VALUE, 0x0ffffffff, -0x100000001, 0x100000001, 0x100000000, 0x080000000, -0, 2**53+2]); ");
/*fuzzSeed-211892750*/count=604; tryItOut("v0 = this.a1.length;");
/*fuzzSeed-211892750*/count=605; tryItOut("a1[0];");
/*fuzzSeed-211892750*/count=606; tryItOut("m1.set(s1, o2.t0);");
/*fuzzSeed-211892750*/count=607; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 16385.0;\n    var i4 = 0;\n    i4 = (0x7fd902c0);\n    i2 = (0xfce4e91a);\n    i4 = (!(0xfe388654));\n    {\n      return +((NaN));\n    }\n    (Float64ArrayView[(((4277))+(i1)) >> 3]) = ((-576460752303423500.0));\n    {\n      {\n        {\n          d0 = (+(1.0/0.0));\n        }\n      }\n    }\n    d0 = (d0);\n    i4 = (((((imul((i2), ((((0x66731631))|0)))|0))+((((0xfe4b69ef))>>>((0x72d8b2ed))) < (0x7b430509))+((Uint32ArrayView[4096]))) >> ((Float32ArrayView[((((0xfcdf6eeb)) & ((0xb1d48e7c))) % (~~(((0xc2a36f1f)+(0x30d153f9)+(0xfeaf220c))))) >> 2]))) == ((-(i1))|0));\n    (Uint8ArrayView[((i1)+(!((((0x110dbe8a)*0x11aa3)>>>((0xfe2dd23b)+(0x21d09fe9)+(0xc01e4a7)))))) >> 0]) = ((0xfd0c3962));\n    i1 = ((((i2)-(i2))>>>((4277))) != (((0xe0349aa0))>>>((i4)-((d0) != (d0)))));\n    {\n      {\n        {\n          (Float64ArrayView[((0xbd055273)) >> 3]) = ((((-147573952589676410000.0)) / ((+abs(((-1.2089258196146292e+24)))))));\n        }\n      }\n    }\n    {\n      d3 = (Infinity);\n    }\n    (Float64ArrayView[((/*FFI*/ff(((~~(NaN))), ((((d0)) - ((d3)))), ((abs((abs((((0x130dabc)) >> ((0xff740ab0))))|0))|0)))|0)) >> 3]) = (((!(i2)) ? (1.125) : (d3)));\n    i1 = ((0xffffffff) > (0xffffffff));\n    i1 = (0xc6ada9c3);\n    return +(((+(1.0/0.0))));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [42, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, 0x080000001, -1/0, 0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), 0x080000000, 0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -(2**53), -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, 2**53, 1/0, -0x100000001, 2**53-2, 0, Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, 2**53+2, Number.MAX_VALUE, -0x080000000, 0.000000000000001, -0x07fffffff, 1]); ");
/*fuzzSeed-211892750*/count=608; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-211892750*/count=609; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy1(Math.fround(mathy0((( + ((Math.log((( ! (((x >>> 0) & (Number.MAX_SAFE_INTEGER >>> 0)) | 0)) >>> 0)) >>> 0) | 0)) | 0), mathy4((((mathy4(x, y) >>> 0) ? Math.atanh(x) : (((-0x080000001 | 0) ^ ((Math.fround(y) >>> 0) | 0)) | 0)) >>> 0), Math.fround(Math.max(Math.fround(y), ( + x)))))), ( + ((Math.imul((mathy0(y, 1/0) >>> 0), ((Math.log2(2**53) | Math.acosh(y)) >>> 0)) >>> 0) , ( + (Math.min((Math.atan2(y, Math.fround(((x >>> 0) + Math.fround(y)))) >>> 0), (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x080000001, -0x100000001, 2**53, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, 1, 42, 2**53-2, Math.PI, 0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, 1.7976931348623157e308, 0, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -1/0, -0x100000000, 0x07fffffff, -(2**53-2), -0x0ffffffff, -0, 0x080000001, -Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, 0x100000000, -(2**53+2)]); ");
/*fuzzSeed-211892750*/count=610; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.atan2((Math.min(((x ? ( + Math.max(Math.fround(x), ((Math.fround(Math.acosh(y)) === y) | 0))) : ( ! (Math.sign(0x080000001) >>> 0))) >>> 0), (Math.cbrt(Math.expm1(( + Math.sign(x)))) >>> 0)) >>> 0), Math.fround(Math.asinh(mathy0(((( + (( + ( + (x || Number.MIN_SAFE_INTEGER))) ** ( + y))) && x) | 0), x)))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, -0x100000001, 42, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, 0.000000000000001, 0x100000000, 0, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 0x080000001, 1/0, -0x07fffffff, Math.PI, -0x080000000, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, 0x100000001, -0, -(2**53-2), 1, 0/0, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, 1.7976931348623157e308]); ");
/*fuzzSeed-211892750*/count=611; tryItOut("e1 = new Set\n");
/*fuzzSeed-211892750*/count=612; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( ! ((((Math.asin((mathy0(Math.fround(y), y) | 0)) >>> 0) ^ ((( ! (( + Math.max(( + ((y | 0) >> x)), (Number.MAX_VALUE | 0))) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0)) != ( + Math.log2(-0))); }); testMathyFunction(mathy1, [1, 42, 0x100000000, Math.PI, -0x100000001, -0x080000001, -0x0ffffffff, -(2**53-2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), 1.7976931348623157e308, -0, 2**53+2, 0, 0x080000001, 0x0ffffffff, -0x080000000, 1/0, 0x100000001, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, 0x080000000, -1/0, 0/0, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=613; tryItOut("h2.has = f0;");
/*fuzzSeed-211892750*/count=614; tryItOut("\"use strict\"; for (var p in s2) { try { g2.g2.i2 = e1.values; } catch(e0) { } try { v1 = g2.eval(\"(4277)\"); } catch(e1) { } try { a1.push(g1.m0, e0, o2.e0); } catch(e2) { } s2 = Array.prototype.join.apply(g0.a1, [g2.s1]); }");
/*fuzzSeed-211892750*/count=615; tryItOut("\"use strict\"; Object.defineProperty(this, \"o2\", { configurable: %=, enumerable: (x % 52 != 7),  get: function() { ; return new Object; } });");
/*fuzzSeed-211892750*/count=616; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=617; tryItOut("function f2(this.p1)  { if(true) { if (/*wrap2*/(function(){ var iwrfyb =  /x/ ; var dbakkf = Set.prototype.delete; return dbakkf;})().prototype) Array.prototype.splice.call(a2, 3, ({valueOf: function() { ((yield  /x/g .eval(\"(\\\"\\\\uEE4F\\\");\")));return 2; }})); else {print(this.p1); }} } ");
/*fuzzSeed-211892750*/count=618; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.cosh(Math.fround(mathy3(Math.atan2(( ! ((y ? x : -0x0ffffffff) >>> 0)), ( ! Math.fround(x))), (mathy4(Math.fround(Math.log2(Math.fround(x))), ( + Math.fround(Math.pow(mathy4(Math.acos(2**53+2), Math.acos(y)), x)))) >>> 0)))); }); testMathyFunction(mathy5, [0x080000000, 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, 1/0, 0/0, 1, -Number.MAX_VALUE, -(2**53-2), -0x080000001, -(2**53), 0x07fffffff, 0, Number.MAX_SAFE_INTEGER, 0x100000000, 0x100000001, -0x080000000, -0x0ffffffff, Math.PI, 2**53, 0x0ffffffff, Number.MIN_VALUE, -0, -0x07fffffff, 42, 2**53+2, -(2**53+2), 0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-211892750*/count=619; tryItOut("\"use strict\"; \"use asm\"; o0.h0.defineProperty = f2;");
/*fuzzSeed-211892750*/count=620; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! ( - Math.fround((Math.fround(mathy0(x, y)) / Math.fround(y))))); }); testMathyFunction(mathy5, [-0x100000001, -0x100000000, 2**53-2, -0, -(2**53), -Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, 1.7976931348623157e308, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x080000001, 0x080000000, 0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, -Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), 0x07fffffff, 1, 0x100000001, -(2**53+2), Number.MAX_VALUE, 0/0, 0x080000001, 42, 2**53, Number.MIN_VALUE, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-211892750*/count=621; tryItOut("for (var v of g2) { try { Object.defineProperty(this, \"t2\", { configurable: true, enumerable: (new RegExp(\"[^\\\\u962D\\u82a2-\\\\uD0A6E]|(?=\\\\w|\\\\w{0}+)+?\", \"i\") / /(\\1|\\B|.+\uf0c2|$*?|[^])|([^]|\\B?|.)/gyi &= x),  get: function() {  return t2.subarray(({valueOf: function() { t1[15] = x;return 5; }})); } }); } catch(e0) { } try { this.g2.m1.set(i2, p1); } catch(e1) { } try { s0 + a0; } catch(e2) { } Array.prototype.shift.apply(this.a2, [b2]); }");
/*fuzzSeed-211892750*/count=622; tryItOut("\"use strict\"; /*hhh*/function xubogf(a, eval = (([] = x) <= (4277)), ...d){with(((void options('strict_mode')))){throw Math.hypot(17, -70368744177663); }}xubogf();");
/*fuzzSeed-211892750*/count=623; tryItOut("/*RXUB*/var r = /(?=(\\B)?)\\2(?:([^\\D\u00fd-\\0\\w]\u5506)+?\\D|\\W?)*?{0,3}/gyim; var s = \"\\n\"; print(s.split(r)); ");
/*fuzzSeed-211892750*/count=624; tryItOut("\"use strict\"; /*vLoop*/for (xkrvqw = 0; xkrvqw < 8; ++xkrvqw) { var e = xkrvqw; m1 = Proxy.create(h2, g1); } ");
/*fuzzSeed-211892750*/count=625; tryItOut("/*oLoop*/for (qcvtqy = 0, x = [] = {}; qcvtqy < 23; ++qcvtqy) { /*RXUB*/var r = new RegExp(\"$?|\\\\1(?:.$.(\\\\B\\\\b)*?\\\\b)\", \"yim\"); var s = \"\\n\"; print(r.exec(s)); print(r.lastIndex);  } ");
/*fuzzSeed-211892750*/count=626; tryItOut("mathy4 = (function(x, y) { return (Math.trunc(((Math.log10((Math.imul((( + Math.min(( + -(2**53)), (y >>> 0))) - Math.PI), Math.fround((Math.atan2(((( + ( + ( + x))) >= y) >>> 0), x) >>> 0))) >>> 0)) >>> 0) | 0)) >= Math.log1p(Math.fround(Math.pow(Math.fround(Math.hypot((((x >>> 0) ? Math.fround(x) : (( + Math.fround(( ! Math.fround(y)))) >>> 0)) >>> 0), (Math.sign((Math.acosh(Math.fround(y)) | 0)) | 0))), Math.fround(( - Math.imul(y, ( + (x < (x >>> 0)))))))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, 2**53+2, 0x080000001, 2**53, Math.PI, -(2**53-2), 0, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 1, -(2**53+2), -0, -0x080000001, -1/0, 0x0ffffffff, -Number.MAX_VALUE, 42, Number.MAX_VALUE, 0x100000000, 0x080000000, -0x0ffffffff, 2**53-2, 0.000000000000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), 1.7976931348623157e308, 0x07fffffff, 0/0, -0x080000000]); ");
/*fuzzSeed-211892750*/count=627; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a0, [b0]);");
/*fuzzSeed-211892750*/count=628; tryItOut("testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 2**53-2, -(2**53), 0.000000000000001, 0, -0x100000001, 0/0, 1/0, 42, 0x100000000, Number.MIN_VALUE, 1, 0x100000001, -1/0, 2**53+2, 1.7976931348623157e308, -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), -(2**53+2), Math.PI, 0x080000001, -0x07fffffff, 0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, -0, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-211892750*/count=629; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(Math.fround(Math.expm1(Math.fround(Math.atan2((( ! mathy0((x | 0), x)) | 0), Math.sign(x)))))) ** Math.fround(( ~ Math.fround((( ! (y | 0)) | 0))))) >>> 0); }); testMathyFunction(mathy1, [0x07fffffff, 2**53-2, 1.7976931348623157e308, -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -0x080000001, 2**53, 0, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, Math.PI, 0x100000001, -1/0, 0x0ffffffff, -0x100000001, 1/0, -(2**53+2), 42, -0, 1, 0x080000000, -0x07fffffff, 0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 0/0, -0x0ffffffff]); ");
/*fuzzSeed-211892750*/count=630; tryItOut("for(let e = ((/*UUV1*/(z.fround = Array.prototype.shift))) in undefined) let x = this.__defineGetter__(\"e\", /*wrap2*/(function(){ \"use strict\"; var jmazwl =  '' ; var brsoty = Float32Array; return brsoty;})()), c, b = z, swxzmh;v0 = g0.o1.g2.eval(\"this\");");
/*fuzzSeed-211892750*/count=631; tryItOut("M:for(var c = this in  /x/ ) {m0.get(h1);( /x/ ); }m2.set(x, o2.p0);");
/*fuzzSeed-211892750*/count=632; tryItOut("\"use strict\"; print(uneval(o2));");
/*fuzzSeed-211892750*/count=633; tryItOut("b0 + '';");
/*fuzzSeed-211892750*/count=634; tryItOut("L:with(window)Array.prototype.push.apply(a0, [g1.e0, p2]);");
/*fuzzSeed-211892750*/count=635; tryItOut("/*RXUB*/var r = (makeFinalizeObserver('tenured')); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-211892750*/count=636; tryItOut("\"use strict\"; with((++y)){print(x); }");
/*fuzzSeed-211892750*/count=637; tryItOut("\"use strict\"; e0.has(i2);");
/*fuzzSeed-211892750*/count=638; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; }");
/*fuzzSeed-211892750*/count=639; tryItOut("a1[14] = (/*FARR*/[/(?:(.\\1*?))|(?=(?=([^\u00db\\xd9\\S\\u006A])+?)+)?/gyim,  /x/g , /[\\S\\W]\\b{1,}|.\\3{31}|(?![\u7546\\xaB]+?)|\\B*?|./gyim, ...[]].some(neuter, x)) %= (4277);");
/*fuzzSeed-211892750*/count=640; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((mathy0(((Math.min(((mathy0((-(2**53+2) | 0), (-Number.MAX_VALUE | 0)) | 0) >>> 0), ( + ( + ( + (x === (( + y) | 0)))))) >>> 0) | 0), (Math.fround(Math.atan(( + ((Math.hypot(2**53-2, y) | 0) & ( + (x != ( + x))))))) | 0)) | 0) <= ( ~ ((Math.min((Math.fround(Math.asinh(( + x))) >>> 0), (x >>> 0)) >>> 0) | 0))); }); ");
/*fuzzSeed-211892750*/count=641; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[(void 0), NaN, (void 0), NaN, (void 0), (void 0), NaN, NaN, (void 0), (void 0), NaN, NaN, NaN, NaN, NaN, NaN, (void 0), (void 0), NaN, (void 0), NaN, NaN, NaN, (void 0), (void 0), (void 0), NaN, (void 0), (void 0)]); ");
/*fuzzSeed-211892750*/count=642; tryItOut("const x = (d-=x.__defineSetter__(\"x\", (function(x, y) { return x; }))) instanceof (this) != (/*MARR*/[[], [], [], [], [], [], [], [], [], [],  /x/ , true, true, (-1/0), [], [],  /x/ ,  /x/ , [], true, true, true, (-1/0), (-1/0), [], true,  /x/ , [],  /x/ , [], (-1/0), (-1/0), true, [], (-1/0), true, true, [], true,  /x/ , [], (-1/0), [], [],  /x/ , [],  /x/ , (-1/0), (-1/0), true, true,  /x/ , [],  /x/ , (-1/0), [], [],  /x/ , []].map(Array.prototype.values, false)), w = ({} =  \"\" .watch(\"expm1\", WeakSet.prototype.add)), csjzak;{ void 0; try { startgc(599349503); } catch(e) { } } h0 = h2;");
/*fuzzSeed-211892750*/count=643; tryItOut("t0 = new Uint16Array(b2, 40, 15);");
/*fuzzSeed-211892750*/count=644; tryItOut("a0.forEach((function() { for (var j=0;j<1;++j) { f2(j%3==0); } }), this.p1, f1);");
/*fuzzSeed-211892750*/count=645; tryItOut("v1 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-211892750*/count=646; tryItOut("/*oLoop*/for (let katzzk = 0; katzzk < 68; ++katzzk) { print(/\\f+|(?=^+?){3}+?\\b*?/yi); } var x = //h\nReferenceError(Math.atan2(15, null))\u000c;");
/*fuzzSeed-211892750*/count=647; tryItOut("v0 = Object.prototype.isPrototypeOf.call(b0, p0);");
/*fuzzSeed-211892750*/count=648; tryItOut("const a = (new ReferenceError(((makeFinalizeObserver('nursery'))), (4277)));/*tLoop*/for (let b of /*MARR*/[(1/0),  \"use strict\" , new Boolean(false), new String('q'), (1/0), (1/0), new String('q'), new String('q'), undefined, undefined,  \"use strict\" , new Boolean(false), undefined,  \"use strict\" , undefined, undefined, (1/0), undefined,  \"use strict\" , new Boolean(false), new Boolean(false), (1/0), undefined, new String('q'),  \"use strict\" , new Boolean(false), new String('q'), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, new String('q'), undefined, undefined, new String('q'), (1/0), new Boolean(false), new String('q'), new Boolean(false),  \"use strict\" , undefined, new Boolean(false),  \"use strict\" , new Boolean(false),  \"use strict\" , new String('q'), new String('q'),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Boolean(false), new Boolean(false), undefined, undefined, undefined, (1/0), undefined, new Boolean(false), new String('q'), (1/0), new String('q'), new String('q'),  \"use strict\" , new String('q'),  \"use strict\" , new Boolean(false), (1/0), undefined,  \"use strict\" , new String('q'), (1/0), new Boolean(false)]) { /*bLoop*/for (let aizbex = 0; aizbex < 10; function ([y]) { }, ++aizbex) { if (aizbex % 9 == 1) { for (var p in p2) { try { o2.m1.get(b2); } catch(e0) { } for (var v of s1) { try { (void schedulegc(g2)); } catch(e0) { } print(uneval(s1)); } } } else { t2 = new Uint32Array(b0); }  }  }");
/*fuzzSeed-211892750*/count=649; tryItOut("print(x);y = (y);");
/*fuzzSeed-211892750*/count=650; tryItOut("v2 = Array.prototype.every.call(a1, (function() { try { var v2 = false; } catch(e0) { } try { m0.has(a2); } catch(e1) { } try { t2[({valueOf: function() { for(var [z, d] = ({} = ( /x/  ? /((?!.){0})/im : \"\\u6652\")) in this.__defineSetter__(\"x\", Array.prototype.values)) ( '' );return 4; }})] = this.e2; } catch(e2) { } this.v0 = g1.runOffThreadScript(); return e0; }));");
/*fuzzSeed-211892750*/count=651; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[objectEmulatingUndefined(), (-1/0), (-1/0), eval, objectEmulatingUndefined(), eval, (-1/0), objectEmulatingUndefined(), (-1/0), (-1/0), (-1/0), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), (-1/0), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), eval, objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined()]) { /* no regression tests found */\n }");
/*fuzzSeed-211892750*/count=652; tryItOut("mathy0 = (function(x, y) { return (Math.exp((( + x) & ( + ( - (( + y) / ((x < Number.MAX_SAFE_INTEGER) | 0)))))) ? Math.hypot((( + Math.log2((((( ! x) | 0) || (Math.hypot(x, y) >>> 0)) | 0))) || (Math.atanh((Math.fround(( ! Math.fround(y))) < Math.fround(y))) >>> 0)), ( + Math.atan2(( + x), ( + x)))) : Math.fround((Math.fround((( ! (( + Math.sin(( + Math.sinh(y)))) >>> 0)) >>> 0)) == Math.fround((( ! (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [Math.PI, -Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0, 1/0, -(2**53-2), -0x080000001, -0x080000000, 0.000000000000001, 0/0, -0x100000001, 0x080000000, 1, -0, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, 0x0ffffffff, 2**53, 0x080000001, 42, -0x07fffffff, 0x100000000, -(2**53+2), 1.7976931348623157e308, -(2**53)]); ");
/*fuzzSeed-211892750*/count=653; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o2, g2.v2);");
/*fuzzSeed-211892750*/count=654; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - Math.cbrt(( + ( + ( ~ ( + mathy0(((x >> x) >>> 0), x))))))); }); testMathyFunction(mathy4, [0, -1/0, 0x100000001, 0x080000001, 1, -0x080000000, -0x080000001, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53, 0x0ffffffff, 0x100000000, -0, -(2**53+2), -(2**53), 0.000000000000001, 0x07fffffff, 1.7976931348623157e308, -0x07fffffff, 42, Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x100000001, 0/0]); ");
/*fuzzSeed-211892750*/count=655; tryItOut("print(x);const c = (b = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: new RegExp(\"((\\\\u0041)+(?:.(?=.))?)|(?:0+?|(?!\\\\S*?))[^]\\\\3\", \"yim\"), has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: new Function, keys: (let (e=eval) e), }; })(this), objectEmulatingUndefined, () =>  { \"use strict\"; s0 = g1.s1.charAt(5); } ));");
/*fuzzSeed-211892750*/count=656; tryItOut("v2 = g0.eval(\"function f1(a2)  { \\\"use strict\\\"; /*MXX2*/this.g0.Number.prototype.toExponential = f1;x = (new Int16Array((yield Object.defineProperty(a2, \\\"toGMTString\\\", ({get: function(q) { \\\"use strict\\\"; return q; }, configurable: {}, enumerable: false}))))); } \");");
/*fuzzSeed-211892750*/count=657; tryItOut("mathy4 = (function(x, y) { return ( + Math.cos(Math.fround(Math.atan((((Math.tan(-(2**53-2)) | 0) != Math.exp(y)) >>> 0))))); }); testMathyFunction(mathy4, [0.000000000000001, -1/0, 0x100000001, -(2**53+2), 42, Math.PI, 2**53+2, 0x080000000, -0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -0, 2**53, 0x100000000, -0x100000001, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -0x0ffffffff, 2**53-2, 0x07fffffff, 1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, 0x0ffffffff, -(2**53), 0/0, -Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-211892750*/count=658; tryItOut("v2.__proto__ = g0.p2;");
/*fuzzSeed-211892750*/count=659; tryItOut("if(true) ; else {var gkoabd = new ArrayBuffer(2); var gkoabd_0 = new Uint8ClampedArray(gkoabd); gkoabd_0[0] = -0; var gkoabd_1 = new Uint8ClampedArray(gkoabd); gkoabd_1[0] = -10; var gkoabd_2 = new Float32Array(gkoabd); gkoabd_2[0] = 13; ; /x/ ;i2.next();print( \"use strict\" ); }");
/*fuzzSeed-211892750*/count=660; tryItOut("mathy0 = (function(x, y) { return Math.imul(( + Math.pow(Math.fround((( ! (Math.expm1(y) >>> 0)) << ( + Math.acosh((x >= Math.sinh(y)))))), Math.fround(( - Math.sign(( + y)))))), (Math.acosh(Math.fround(Math.max(Math.fround(Math.sin(Math.sign((y >>> 0)))), Math.fround(( - y))))) >> Math.round((Math.hypot((x | (( ~ x) | 0)), y) | 0)))); }); testMathyFunction(mathy0, [-0x100000000, 1.7976931348623157e308, -1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 1/0, 2**53, 0x080000001, -0x100000001, 0x100000000, -(2**53+2), -0x0ffffffff, 2**53-2, 0x0ffffffff, Math.PI, Number.MIN_VALUE, 0x100000001, 0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, 0, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -0x07fffffff, 1, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, 42, 0/0]); ");
/*fuzzSeed-211892750*/count=661; tryItOut("/*RXUB*/var r = /(?:\\B)+?|$+?|\\B(^{0,}$)\u00a3{2}(?=$?)+?/gy; var s = \"\"; print(uneval(r.exec(s))); \nfor (var p in o2) { try { var v0 = Array.prototype.reduce, reduceRight.call(a1, f1, e1, v0, undefined, o1.e2, this.b0); } catch(e0) { } v1 = g1.runOffThreadScript(); }function  /x/ (...NaN) { return \"\\u13B7\" }  \"\" ;\n");
/*fuzzSeed-211892750*/count=662; tryItOut("try { g1.m2.delete(o2.s2); } catch(w) { yield ({ set c e (...eval) { \"use strict\"; yield  \"\"  }  }); } ");
/*fuzzSeed-211892750*/count=663; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.abs(Math.fround(((x !== Math.min(Math.fround(mathy0(-0x080000000, Math.fround(y))), Math.fround(( ! y)))) > Math.fround(( ! Math.fround((mathy0(y, (x | 0)) | 0))))))) >>> 0); }); testMathyFunction(mathy1, [0x100000001, -0x100000000, 0/0, -(2**53), Math.PI, 0x100000000, -1/0, 0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -Number.MAX_VALUE, -0, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, 1, -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0, 2**53, -(2**53-2), 0x0ffffffff, -0x0ffffffff, -0x100000001, 1.7976931348623157e308, 2**53+2]); ");
/*fuzzSeed-211892750*/count=664; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max((((Math.hypot((( + x) !== (y >>> 0)), -0x080000001) ? (x >>> Math.acos(-0)) : (Math.sqrt((Math.sinh((42 | 0)) >>> 0)) >>> 0)) << ( ! (Math.trunc(( + x)) | 0))) >>> Math.pow(y, Math.fround(( - (y | 0))))), (Math.max(((( ! (( + Math.max(Math.fround(Math.tanh(x)), ( + (-Number.MIN_SAFE_INTEGER , -0x080000000)))) | 0)) | 0) >>> 0), (Math.asinh((y >= ( + x))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-0x100000001, 2**53+2, 2**53, 1/0, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -0, -(2**53-2), 0x0ffffffff, 0x07fffffff, 0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, 1, -Number.MIN_VALUE, 0x080000001, Math.PI, -0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000000, 0.000000000000001, 0x100000001, -0x100000000, 0x080000000, 0/0, -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-211892750*/count=665; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.atan2(( + (( + Math.trunc(x)) && ( + (((y | 0) | (y | 0)) | 0)))), Math.fround((Math.fround((( ! (Math.min(x, x) >>> 0)) >>> 0)) && ( ~ ((((y >= (( ~ x) >>> 0)) >>> 0) === (((y | 0) , (y | 0)) | 0)) | 0))))); }); testMathyFunction(mathy2, [-0x080000000, 0/0, Number.MIN_VALUE, 0x07fffffff, -1/0, -(2**53), 0x080000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, 2**53, 42, 0x100000001, -0x100000000, -Number.MAX_VALUE, 0, 2**53+2, 1/0, -0x07fffffff, 1, 0x080000001, -0x100000001, -0, -(2**53-2), Math.PI, -(2**53+2), -0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-211892750*/count=666; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.acos(( + (( + ( + Math.fround(Math.acosh(Math.fround(x))))) >> Math.cos(Math.fround(Math.pow(x, x))))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -(2**53), -0x080000000, -0, 1/0, -1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, Number.MAX_SAFE_INTEGER, 42, -0x100000001, 0, 0x100000000, Math.PI, 0x0ffffffff, 1, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 2**53, 0x080000000, 1.7976931348623157e308, 0.000000000000001, -0x0ffffffff, 0x080000001, -Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, -(2**53-2), -0x100000000]); ");
/*fuzzSeed-211892750*/count=667; tryItOut("\"use strict\"; m1.toString = (function() { for (var j=0;j<7;++j) { g1.f1(j%2==0); } });");
/*fuzzSeed-211892750*/count=668; tryItOut("\"use strict\"; h1.keys = f2;");
/*fuzzSeed-211892750*/count=669; tryItOut("mathy1 = (function(x, y) { return ( + ((((( + ( ! y)) | 0) | 0) ? Math.fround((( ! ((((y >>> 0) != ((Math.atan2(x, y) ^ (x >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0)) : (( + mathy0(( + ((y << Math.fround(( + mathy0(( + ( + Math.hypot(y, 2**53))), ( + ((x % y) | 0)))))) | 0)), ( + Math.pow(-Number.MAX_VALUE, Math.min((mathy0((x | 0), ((-Number.MAX_VALUE ? (y | 0) : 2**53-2) | 0)) | 0), mathy0(0x080000000, ((Math.asin(-(2**53-2)) | 0) | 0))))))) | 0)) >>> 0)); }); testMathyFunction(mathy1, [1.7976931348623157e308, 2**53, -0x100000000, 1/0, 0, -(2**53-2), 0.000000000000001, Math.PI, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, 0x080000001, 2**53+2, -(2**53), 0x080000000, 0/0, -0, -1/0, 42, -0x100000001, 1, 0x100000000, 0x100000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-211892750*/count=670; tryItOut("this.s0 + '';");
/*fuzzSeed-211892750*/count=671; tryItOut("e2 = new Set;");
/*fuzzSeed-211892750*/count=672; tryItOut("print(d = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: x =>  { v0 = Array.prototype.reduce, reduceRight.call(a1, (function() { try { /*RXUB*/var r = r2; var s = \"\"; print(uneval(s.match(r)));  } catch(e0) { } try { t1 = g1.g1.t2.subarray(5); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(p1, s0); } catch(e2) { } /*RXUB*/var r = r0; var s = \"\"; print(s.split(r)); print(r.lastIndex);  return i0; }), b0, v2, f0); } , iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })(-14), [1,,].eval(\"/* no regression tests found */\")));\nprint(x);\n");
/*fuzzSeed-211892750*/count=673; tryItOut("\"use strict\"; yield \"\\u1822\";decodeURIfunction x(c, NaN, ...window) { \"use strict\"; return return } x = g2.f2;");
/*fuzzSeed-211892750*/count=674; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=675; tryItOut("/*RXUB*/var r = (x++); var s = \"\\n\\n\\n\\n\"; print(r.exec(s)); function x(\u3056 = new RegExp(\"\\\\1\\\\2\", \"m\").unwatch(({ get floor(c, x, NaN, y, x, this, eval, e, x =  '' , d, c, b, \u3056, eval, a, NaN, x, w, x, x, x, e = new RegExp(\"(?:(?=..^|[]?[]){2,5})*\", \"gm\"), x, x = this, c, x, window, c, z, b, w, b, x, w, window)(d = undefined), 0: (Math.atan2(\"\\u856E\", -6)) }))) { \"use strict\"; return (p={}, (p.z = x)()) } v2 = evaluate(\"mathy4 = (function(x, y) { return ( + mathy1(( + Math.hypot((Math.hypot(((Math.max(((Math.acosh(( + ( + ( + x)))) | 0) | 0), x) | 0) >>> 0), ((Math.exp(x) >>> 0) | 0)) >>> 0), ( + (( + (( - (y << x)) | 0)) >>> ( + (( + 2**53-2) << Math.max(Math.fround(-0x080000001), Math.fround(( - x))))))))), ( + ( + ( + (Math.log10((Math.log2(-0x100000000) | 0)) === ( - ( + mathy1(Math.acosh((y >>> 0)), x))))))))); }); testMathyFunction(mathy4, [0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 0/0, 42, -0x080000000, 1, -0x07fffffff, -0x100000000, 0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -0, 0x100000001, -0x080000001, Number.MAX_VALUE, 2**53, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, 0.000000000000001, 1/0, -0x0ffffffff, 2**53+2, 0x07fffffff, 0x080000001, -(2**53), -(2**53-2), -0x100000001, 0]); \", ({ global: o0.g2, fileName: null, lineNumber: 42, isRunOnce: (function ([y]) { })(), noScriptRval: false, sourceIsLazy: x, catchTermination: true, elementAttributeName: s1, sourceMapURL: s1 }));");
/*fuzzSeed-211892750*/count=676; tryItOut("\"use asm\"; v2.toSource = (function() { try { g0.h1.keys = f0; } catch(e0) { } try { v1 = t0.length; } catch(e1) { } Array.prototype.pop.apply(o1.a2, []); return this.e0; });");
/*fuzzSeed-211892750*/count=677; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.expm1((Math.fround(( ~ ( + (Math.min((Math.fround(Math.atan2((1/0 >>> 0), ((mathy1(Math.cbrt(Math.fround(x)), y) ** ( + Math.abs(y))) >>> 0))) | 0), ((( ! ((y >= Math.hypot(y, x)) >>> 0)) && Math.max(Math.fround(Math.imul(0x100000001, x)), Math.fround(mathy1(Math.imul(y, x), (y + x))))) | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy3, [-0x0ffffffff, 2**53-2, -0, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, -0x080000000, 1/0, -0x07fffffff, 0x100000000, 0/0, Number.MAX_VALUE, 0x07fffffff, -0x080000001, 1, Number.MIN_VALUE, -0x100000001, 42, 0x080000000, 0x0ffffffff, 0.000000000000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -0x100000000, -1/0]); ");
/*fuzzSeed-211892750*/count=678; tryItOut("\"use strict\"; s1 = new String(g1.h1);");
/*fuzzSeed-211892750*/count=679; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.min((( + Math.imul(( + ( + (Math.pow((-(2**53+2) >>> 0), ((( - (x | 0)) | 0) >>> 0)) , ( + Math.fround(Math.asinh(Math.fround((Math.trunc((y | 0)) | 0)))))))), ( + Math.max(( + Math.tanh(( + ((x / Math.fround(y)) ? 0 : ( - y))))), ((((x % ((Math.fround((y == y)) + y) | 0)) | 0) ? Math.fround((y && Math.fround(( ! (Math.sqrt(x) >>> 0))))) : y) | 0))))) | 0), (Math.fround(((Math.max(( + (Math.imul(((x ? x : x) | 0), (0/0 | 0)) | 0)), ((Math.fround(Math.max((x | 0), ( + x))) << Math.fround(-1/0)) ? (( - (x | 0)) | 0) : ( - Math.PI))) | 0) | (Math.max((x & x), Math.fround(mathy2(((mathy0((0x0ffffffff >>> 0), (y >>> 0)) >>> 0) | 0), ((( + (( + y) <= ( + y))) % 0x07fffffff) | 0)))) | 0))) | 0)) | 0); }); ");
/*fuzzSeed-211892750*/count=680; tryItOut("\"use strict\"; this.s1 = Array.prototype.join.apply(a0, [o0.o2,  /x/ ]);");
/*fuzzSeed-211892750*/count=681; tryItOut("let x = null, surndj, x = [[1]], mrtycl, kevupw, \u3056, a, d, eval, x;t0 = new Float32Array(b0, 12, this);");
/*fuzzSeed-211892750*/count=682; tryItOut("for (var v of v2) { try { v1 = g1.eval(\"[String(x,  '' )]\"); } catch(e0) { } h2 + ''; }");
/*fuzzSeed-211892750*/count=683; tryItOut("mathy3 = (function(x, y) { return (( ! ((mathy1((( ! Math.expm1(( ~ (y ? -0x100000001 : x)))) | 0), mathy0(x, Math.expm1(y))) | 0) | 0)) | 0); }); testMathyFunction(mathy3, [null, objectEmulatingUndefined(), (function(){return 0;}), (new String('')), (new Number(0)), true, (new Boolean(false)), 0.1, ({valueOf:function(){return '0';}}), -0, ({valueOf:function(){return 0;}}), (new Number(-0)), [], /0/, false, [0], NaN, ({toString:function(){return '0';}}), '\\0', (new Boolean(true)), '/0/', '', '0', 0, undefined, 1]); ");
/*fuzzSeed-211892750*/count=684; tryItOut("/*bLoop*/for (var ropemy = 0; ropemy < 27; ++ropemy) { if (ropemy % 3 == 2) { print(/\\3\\1(?![^])\\u4dA8/yim); } else { s1 += 'x'; }  } function z(window) { \"use strict\"; return ((function factorial(fvqwck) { x = false;; if (fvqwck == 0) { ; return 1; } ; return fvqwck * factorial(fvqwck - 1);  })(82610)) } v1 = g1.eval(\"a0.shift(f0);\");");
/*fuzzSeed-211892750*/count=685; tryItOut("mathy1 = (function(x, y) { return ((( ! ( + (mathy0(-Number.MAX_SAFE_INTEGER, ((x ? (( + ( ~ ( + x))) | 0) : Math.fround(y)) | 0)) | 0))) ? (((Math.fround(Math.atan2(Math.fround(y), Math.fround(Math.fround(Math.abs(( + 0)))))) >>> 0) ? (mathy0(1.7976931348623157e308, Math.fround(( + (( + Math.fround(( - Math.pow(Math.fround(x), Math.fround(y))))) / ( + mathy0(y, -0x080000000)))))) >>> 0) : ((( + (( + y) / ( + Math.min(Math.log1p(Math.fround(y)), (y >>> 0))))) ** x) >>> 0)) >>> 0) : (Math.atanh(Math.fround((Math.hypot(((( + mathy0(( + x), ( + -0x100000001))) | 0) , Number.MIN_SAFE_INTEGER), 0/0) >>> 0))) | 0)) !== Math.pow((Math.sqrt(Math.atan2((y >>> 0), mathy0(y, mathy0(y, y)))) >>> 0), Math.max(Math.max((mathy0((Math.max((Math.fround(x) << x), y) | 0), (y | 0)) >>> 0), y), ((Math.exp(Math.fround(Math.fround(Math.tan(Math.tan(y))))) >>> 0) >>> 0)))); }); testMathyFunction(mathy1, [0x080000000, -0, -0x07fffffff, 2**53, -Number.MAX_VALUE, 0, Math.PI, 0x07fffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 1, 42, 0x080000001, 0.000000000000001, -Number.MIN_VALUE, -0x0ffffffff, -0x100000000, -0x080000001, -1/0, -0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x080000000]); ");
/*fuzzSeed-211892750*/count=686; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.pow(( + (Math.imul(Math.hypot(Math.abs(Math.fround((Math.fround(Math.imul(x, y)) == Math.fround(0x100000001)))), (( + Math.exp(((y >>> 0) !== (y | 0)))) | 0)), (x | 0)) ? Math.fround(Math.sin(Math.fround(Math.cbrt(x)))) : Math.round((Math.fround(Math.abs(y)) >>> 0)))), ( + ( ! Math.imul(( + (y && x)), ( + Math.acos(( + x)))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 0x080000001, 0x080000000, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, -(2**53+2), 1, 42, 1.7976931348623157e308, 0/0, 2**53, -0x080000000, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 0x07fffffff, -0x100000001, 1/0, 0x100000001, -0x07fffffff, -0x100000000, -(2**53-2), -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=687; tryItOut("t0 = t1.subarray(3);");
/*fuzzSeed-211892750*/count=688; tryItOut("for (var v of a2) { try { a2.pop(o0); } catch(e0) { } try { t2 = new Float32Array(7); } catch(e1) { } try { t1[9] = p1; } catch(e2) { } o1 = m0.__proto__; }");
/*fuzzSeed-211892750*/count=689; tryItOut("v2 = Object.prototype.isPrototypeOf.call(p0, f2);");
/*fuzzSeed-211892750*/count=690; tryItOut("mathy5 = (function(x, y) { return ( - (((Math.fround(Math.imul((Math.sqrt((0x080000001 >>> 0)) >>> 0), (0x0ffffffff | 0))) >>> 0) || (Math.abs(Math.fround((1/0 , x))) <= ( + (Math.round(x) * y)))) | (Math.atanh((( + (( + y) ? ( ! ( + ((x >= y) >> y))) : ( + y))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-211892750*/count=691; tryItOut("\"use strict\"; for(let b in ((/*wrap2*/(function(){ var jqpiox = window; var rqyklg = (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: decodeURIComponent, defineProperty:  '' , getOwnPropertyNames: (function(y) { return 20 }).call, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: undefined, get: function(y) { \"use strict\"; return  \"\"  }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; }); return rqyklg;})())(x))){s0 + h0; }");
/*fuzzSeed-211892750*/count=692; tryItOut("g1.offThreadCompileScript(\"new RegExp(\\\"(?:(?:^(?:(?![^\\\\\\\\w\\\\\\\\\\\\ub3ff]))+?){1,})\\\", \\\"ym\\\")\\n\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 90 == 9), sourceIsLazy: false, catchTermination: y }));");
/*fuzzSeed-211892750*/count=693; tryItOut("/*RXUB*/var r = /(?!\\2)(.(?!\\s){1,}|(?:$)|(?=[^])*)|[^]?/yi; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=694; tryItOut("\"use strict\"; e = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: runOffThreadScript, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: b = Proxy.create(({/*TOODEEP*/})(x), -24), }; })(eval = window), encodeURI, x).throw(Math.min(-19, (4277)));");
/*fuzzSeed-211892750*/count=695; tryItOut("\"use strict\"; e2 = new Set(m2);");
/*fuzzSeed-211892750*/count=696; tryItOut("e2.has(p2);");
/*fuzzSeed-211892750*/count=697; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.ceil((((( + Math.imul(y, Math.fround((Math.fround(Math.max(-Number.MAX_SAFE_INTEGER, ((y ** Math.fround(x)) && x))) , Math.fround(x))))) >>> 0) ? (Math.atanh(Math.fround(( ! Math.fround(((y >>> 0) , Math.fround(( ! Math.fround(0x100000000)))))))) >>> 0) : (Math.fround(Math.clz32(y)) >>> 0)) | 0)); }); ");
/*fuzzSeed-211892750*/count=698; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53), 2**53+2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, 0, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53-2), 0x07fffffff, Number.MIN_VALUE, -0x07fffffff, -0x100000001, 0x100000000, -0x100000000, -0, -Number.MAX_VALUE, 42, 0.000000000000001, 1, -0x080000000, -0x0ffffffff, 2**53, -(2**53+2), 0x080000000, 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -1/0, -0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=699; tryItOut("mathy4 = (function(x, y) { return Math.max(Math.fround(( + Math.max(( + (Math.abs(((Math.fround(( + (( + y) , ( + x)))) , (Math.fround((Math.fround(x) != Math.fround(-(2**53)))) >>> 0)) >>> 0)) >>> 0)), ( + (Math.imul((Math.pow(Math.fround(Math.sin((x >>> 0))), Math.fround(mathy1(Math.atan2(y, ( + -Number.MIN_VALUE)), Math.imul(x, (y | 0))))) >>> 0), (( + (Math.expm1(y) >>> 0)) >>> 0)) >>> 0))))), Math.fround(((((( + Math.ceil(( + y))) / Math.fround((Math.fround(y) ? Math.fround(( + ( ! ( + (Math.sin(Math.fround((( + x) | Math.fround(y)))) >>> 0))))) : Math.fround(-(2**53-2))))) | 0) != ((( + Math.min(( + -(2**53)), ( + Math.max((y >>> 0), -0)))) || x) | 0)) | 0))); }); testMathyFunction(mathy4, [2**53-2, 0/0, 42, -Number.MIN_VALUE, -0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 0x07fffffff, 0x080000000, -(2**53-2), 1/0, -0x07fffffff, -(2**53), -0x100000001, 2**53+2, Number.MIN_VALUE, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, Math.PI, 0x080000001, 0.000000000000001, 0x100000001, 1, -(2**53+2)]); ");
/*fuzzSeed-211892750*/count=700; tryItOut("\"use strict\"; var x =  \"\" ;print((new WeakMap((4277))));");
/*fuzzSeed-211892750*/count=701; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x64d4679d)))|0;\n    {\n      (Float32ArrayView[0]) = ((+(((0x8b7e9764)) & (((0xf1a89401))-(((-0xd66f8*(0xf8c4515a))|0))))));\n    }\n    d1 = (d1);\n    d1 = (d0);\n    switch (((((3.022314549036573e+23) < (131073.0))+(0xcd8c623b)) >> ((/*FFI*/ff(((3.777893186295716e+22)), ((-1.0)), ((-1.5111572745182865e+23)), ((4611686018427388000.0)), ((-2097151.0)), ((34359738368.0)), ((70368744177665.0)), ((1.5474250491067253e+26)), ((0.125)), ((3.022314549036573e+23)), ((16385.0)), ((-134217729.0)), ((2199023255553.0)), ((-72057594037927940.0)))|0)-(/*FFI*/ff()|0)))) {\n      default:\n        d0 = ((Float32ArrayView[0]));\n    }\n    return ((((0x4a00a0b) != (((0xe6f4c65a))>>>((0x7463dfc4))))+((abs((~~(d1)))|0) != (imul((0xc998e829), ((+(-1.0/0.0)) > (d0)))|0))))|0;\n  }\n  return f; })(this, {ff: Symbol.keyFor}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000001, -Number.MIN_VALUE, 2**53, 0x0ffffffff, -(2**53), Number.MAX_VALUE, -0x080000000, 0/0, -0x100000000, 0, 1.7976931348623157e308, -0x100000001, Number.MIN_VALUE, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, -0, -(2**53-2), -1/0, 1, 0x100000001, 1/0, 0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 42, -0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=702; tryItOut("L:do {(null);print(x); } while((new RegExp(\"[^]\", \"yim\")) && 0);");
/*fuzzSeed-211892750*/count=703; tryItOut("/*hhh*/function tioxzm(\u000cy = d++){return false;print(x);}tioxzm();");
/*fuzzSeed-211892750*/count=704; tryItOut("t1.set(a2, 0);");
/*fuzzSeed-211892750*/count=705; tryItOut("\"use strict\"; /*bLoop*/for (let afnplt = 0; afnplt < 34; null, ++afnplt) { if (afnplt % 3 == 0) { print(x); } else { for (var v of i0) { try { /*MXX2*/g2.Date.prototype.getUTCFullYear = s1; } catch(e0) { } try { /*RXUB*/var r = r2; var s = ({}); print(uneval(r.exec(s)));  } catch(e1) { } try { f0.toSource = (function() { for (var j=0;j<13;++j) { f0(j%4==1); } }); } catch(e2) { } Array.prototype.pop.call(a1); } }  } ");
/*fuzzSeed-211892750*/count=706; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x100000000, -0x100000000, 1.7976931348623157e308, 0x07fffffff, Number.MIN_VALUE, 42, -0x0ffffffff, -(2**53), Math.PI, Number.MAX_VALUE, 0, 0x080000001, -1/0, -0x080000001, -0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 0/0, 1/0, -0x100000001, -(2**53+2), -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0, 2**53+2, 1]); ");
/*fuzzSeed-211892750*/count=707; tryItOut("Object.defineProperty(g0, \"a1\", { configurable: (c % 3 == 0), enumerable: (x % 51 != 10),  get: function() { this.i2.send(o1.v1); return this.r0.exec(this.s2); } });c = {} = c;");
/*fuzzSeed-211892750*/count=708; tryItOut("\"use strict\"; /*infloop*/do Array.prototype.reverse.apply(a1, []); while((4277));");
/*fuzzSeed-211892750*/count=709; tryItOut("/*infloop*/ for (let e of \"\\u8111\") {t1.set(t1, 2); }");
/*fuzzSeed-211892750*/count=710; tryItOut("mathy0 = (function(x, y) { return (Math.atan2(( + ( + Math.max(( + Math.expm1(Math.pow(2**53+2, -Number.MAX_VALUE))), y))), (Math.log10(y) , (Math.min((y >>> 0), Math.fround((x === 2**53-2))) >>> 0))) ? (Math.acosh(((( ~ (Math.max((x | 0), ((y && x) | 0)) | 0)) ** Math.expm1(Math.atan2(2**53-2, y))) >>> 0)) >>> 0) : Math.imul(Math.imul((( + ((Math.atan2(((Math.atan2((x | 0), (y >>> 0)) >>> 0) | 0), ((1.7976931348623157e308 ? x : y) | 0)) | 0) >>> 0)) >>> 0), (Math.hypot((Math.min(( + (( + x) !== (Math.fround(( ~ (x >>> 0))) >>> 0))), ( + Math.fround((Math.fround(-1/0) > Math.fround(y))))) >>> 0), (Math.fround(( - Math.fround(y))) >>> 0)) >>> 0)), ((y ^ (Math.abs(-(2**53)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [0x080000000, -0x07fffffff, -0x100000000, 0, 0x0ffffffff, -0x080000000, 0/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -Number.MAX_VALUE, 42, -0, -0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000000, 1, Number.MAX_VALUE, -1/0, -0x0ffffffff, 0x100000001, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 0x080000001, 2**53+2, 2**53, -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-211892750*/count=711; tryItOut("h2 = {};");
/*fuzzSeed-211892750*/count=712; tryItOut("\"use strict\"; window;");
/*fuzzSeed-211892750*/count=713; tryItOut("/*RXUB*/var r = /(?:(.|[\ub5eb-\ub95a\\u0013-u\\u4Ee0])^|(?!^+)|$+?\u009c{4,4})/ym; var s =  /x/g ; print(uneval(r.exec(s))); ");
/*fuzzSeed-211892750*/count=714; tryItOut("/*RXUB*/var r = r0; var s = g0.s0; print(r.test(s)); ");
/*fuzzSeed-211892750*/count=715; tryItOut("{ void 0; try { startgc(31); } catch(e) { } } /*ODP-1*/Object.defineProperty(m2, 17, ({set: /*wrap3*/(function(){ var ttbjmf = (makeFinalizeObserver('nursery')); (new Function)(); }), configurable: false}));");
/*fuzzSeed-211892750*/count=716; tryItOut("Array.prototype.pop.call(a1, this.i0, t0);");
/*fuzzSeed-211892750*/count=717; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=718; tryItOut("/*oLoop*/for (let bddamf = 0, eval(\"\\\"use strict\\\"; g1.m2.get(o0.t0);\") instanceof (a = false); bddamf < 66; ++bddamf) { /*bLoop*/for (let zsysyl = 0; zsysyl < 28; (4277), ++zsysyl) { if (zsysyl % 30 == 12) { (false); } else { Object.defineProperty(o2, \"a2\", { configurable: (x % 14 != 10), enumerable: false,  get: function() {  return this.a0.map(String.raw.bind(v2)); } }); }  }  } ");
/*fuzzSeed-211892750*/count=719; tryItOut("\"use strict\"; for (var p in b1) { try { e0.add(((Math.pow(-28, Object.defineProperty(x, false, ({configurable: true})))))((Object.defineProperty(of, \"prototype\", ({configurable: false, enumerable: false}))), a >= (x))); } catch(e0) { } try { e2 = new Set; } catch(e1) { } try { for (var v of this.e2) { try { Array.prototype.shift.call(a2); } catch(e0) { } try { o0.toString = f1; } catch(e1) { } o2.m0.get(b1); } } catch(e2) { } v1 = o2.g2.t0.length; }");
/*fuzzSeed-211892750*/count=720; tryItOut("\"use strict\"; var pjhowp = new ArrayBuffer(12); var pjhowp_0 = new Int8Array(pjhowp); var pjhowp_1 = new Uint32Array(pjhowp); pjhowp_1[0] = 0; var pjhowp_2 = new Uint32Array(pjhowp); print(pjhowp_2[0]); (({}));function b() { \"use strict\"; v1 + p1; } print(pjhowp_1[6]);/*RXUB*/var r = new RegExp(\"\\\\b\", \"\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=721; tryItOut("");
/*fuzzSeed-211892750*/count=722; tryItOut("/*tLoop*/for (let w of /*MARR*/[0x50505050, 1.3, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x50505050, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 0x50505050, -Number.MIN_SAFE_INTEGER, 0x50505050, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 1.3, 0x50505050, 0x50505050, 1.3, 0x50505050, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 1.3, 0x50505050, -Number.MIN_SAFE_INTEGER, 1.3, 1.3, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x50505050, 0x50505050, 1.3, 0x50505050, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 0x50505050, 0x50505050, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x50505050, 1.3, -Number.MIN_SAFE_INTEGER, 0x50505050, 0x50505050, -Number.MIN_SAFE_INTEGER, 0x50505050, -Number.MIN_SAFE_INTEGER, 0x50505050, 1.3, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 1.3, -Number.MIN_SAFE_INTEGER, 1.3]) { /* no regression tests found */ }");
/*fuzzSeed-211892750*/count=723; tryItOut("const y = ((function fibonacci(aimhby) { ; if (aimhby <= 1) { ; return 1; } e0.add(this.e0);; return fibonacci(aimhby - 1) + fibonacci(aimhby - 2);  })(5));/*RXUB*/var r = NaN; var s =  \"\" ; print(uneval(r.exec(s))); ");
/*fuzzSeed-211892750*/count=724; tryItOut("v1 = this.g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-211892750*/count=725; tryItOut("\"use strict\"; v0 = -0;");
/*fuzzSeed-211892750*/count=726; tryItOut("var s1 = a1.join(s2, f1);");
/*fuzzSeed-211892750*/count=727; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=728; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.max(( + Math.hypot((Math.hypot(((( + Math.fround((y & Math.fround(Math.min(x, x))))) >>> 0) | 0), (Math.max(x, Math.hypot(x, -0x100000000)) | 0)) | 0), ((y < ((Math.atan2(( + 0/0), ( + -Number.MAX_VALUE)) >>> 0) >>> 0)) >>> 0))), ( + ((((x ? ( + Math.atan2(x, (( ~ (y >>> 0)) >>> 0))) : y) || (y | 0)) | 0) != (Math.log2(((((x >>> 0) ? Math.cos(Math.fround(Math.imul(( + x), Math.fround(y)))) : (-0 - y)) >>> 0) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-211892750*/count=729; tryItOut("Array.prototype.unshift.call(a2, this.v2, e2, this.h2);");
/*fuzzSeed-211892750*/count=730; tryItOut("\"use strict\"; for (var p in o0.f2) { try { e1.delete(this.h2); } catch(e0) { } try { v2 = r0.flags; } catch(e1) { } try { v0 = this.a0.length; } catch(e2) { } t2 = new Int16Array(a0); }");
/*fuzzSeed-211892750*/count=731; tryItOut("\"use strict\"; this.b1.toString = (function() { try { e0.add(m0); } catch(e0) { } m2 = new WeakMap; return h0; });");
/*fuzzSeed-211892750*/count=732; tryItOut("\"use strict\"; o2.r2 = /(?!\\b)/gy;");
/*fuzzSeed-211892750*/count=733; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=734; tryItOut("o0.e2.__proto__ = e0;");
/*fuzzSeed-211892750*/count=735; tryItOut("\"use strict\"; m0.toString = (function(j) { if (j) { try { for (var v of g0.v0) { for (var p in o0) { try { s1 + this.t1; } catch(e0) { } for (var v of t2) { try { for (var v of b1) { try { h1.getPropertyDescriptor = (function(j) { if (j) { try { g2.v2 = Object.prototype.isPrototypeOf.call(b2, o0.e0); } catch(e0) { } try { Array.prototype.splice.call(a2, NaN, \"\\u0548\"); } catch(e1) { } o0 = s0.__proto__; } else { try { i0 = o2.a0.keys; } catch(e0) { } a2.unshift(false, /.*/ym,  /x/g , h1, g0.a2, this.t1, b2, a2, v1); } }); } catch(e0) { } this.a0.forEach((function(j) { if (j) { try { Object.freeze(v1); } catch(e0) { } try { s2 += 'x'; } catch(e1) { } v2 = (i0 instanceof s0); } else { try { Object.prototype.unwatch.call(e1, \"big\"); } catch(e0) { } try { h1.getOwnPropertyDescriptor = (function(a0) { var r0 = 0 % x; a0 = a0 * x; var r1 = x + 6; var r2 = a0 - 4; var r3 = 2 % r1; var r4 = a0 + a0; var r5 = 6 - 2; var r6 = r2 | r3; var r7 = r6 * a0; var r8 = 6 & r1; r6 = 6 % r0; var r9 = r5 & 1; var r10 = x ^ 0; r8 = 8 | 2; print(r9); var r11 = r1 ^ r6; var r12 = r6 & r0; var r13 = 5 % 8; r8 = x & 8; var r14 = a0 + r13; print(r5); var r15 = 6 / r0; var r16 = 1 | 0; a0 = 0 - 6; var r17 = r7 / r0; var r18 = r6 * 9; var r19 = 3 | r11; r16 = 5 * r1; var r20 = r16 % 9; var r21 = r14 | 2; var r22 = 4 % r14; var r23 = 0 % r4; var r24 = r15 ^ r6; print(r19); var r25 = r17 * r14; var r26 = x * r10; var r27 = r14 + r25; var r28 = a0 + r25; var r29 = 3 ^ 2; var r30 = 4 + 8; var r31 = r5 & 1; var r32 = r23 & r8; var r33 = r14 / a0; var r34 = r22 * r6; var r35 = r4 | r32; r6 = 6 % r28; var r36 = r11 % 8; r9 = r19 | a0; var r37 = r14 * r23; var r38 = 3 * r16; var r39 = r33 * r18; var r40 = r24 / r34; var r41 = r12 & r39; var r42 = r3 & r32; r26 = r17 - r16; var r43 = 5 ^ r18; var r44 = r6 / r14; var r45 = r13 + r5; var r46 = r7 % r10; var r47 = x | 3; var r48 = 7 / r10; var r49 = r15 - r1; var r50 = 7 | r27; var r51 = r45 ^ 6; var r52 = r1 & 9; var r53 = 7 * 1; var r54 = 3 ^ r24; var r55 = 2 + r10; var r56 = 6 / 0; var r57 = r39 - r25; r56 = r15 - r32; r55 = 5 - r13; var r58 = r33 - 5; var r59 = r57 * 2; var r60 = r4 % r38; var r61 = r43 * r44; var r62 = r28 | r38; var r63 = 8 ^ r48; var r64 = r46 + r41; var r65 = 2 + r42; var r66 = r63 | r5; var r67 = r39 | r45; var r68 = r57 - 6; r35 = r8 / 2; var r69 = r20 | 6; var r70 = r31 | r68; r11 = 2 | r28; var r71 = 2 + r61; r31 = r29 * r44; r56 = r33 / r50; var r72 = 8 ^ 2; var r73 = r31 & r49; var r74 = 2 + 4; var r75 = r10 + r62; var r76 = 7 % 0; var r77 = r56 ^ r41; var r78 = r3 ^ r1; var r79 = 6 % r41; r59 = r19 % r31; var r80 = r67 ^ 4; r62 = 5 + r69; var r81 = r54 * r26; print(r27); r46 = r43 / 2; var r82 = 2 + 1; r79 = 5 % r70; var r83 = r54 + r12; r13 = 9 % r64; var r84 = r57 - 1; var r85 = 9 ^ r73; var r86 = r2 + 3; print(r47); var r87 = 4 | 7; r68 = r47 - 7; var r88 = r66 & r67; var r89 = 9 & r27; var r90 = r15 | 8; var r91 = r86 + 5; var r92 = r7 / r56; var r93 = r47 + r91; var r94 = r56 + r67; var r95 = 3 % r56; var r96 = r80 + 6; var r97 = r24 % 5; var r98 = r79 & r58; var r99 = r50 | 7; var r100 = 5 / 5; var r101 = r88 - r97; var r102 = r86 * r100; var r103 = r29 ^ r43; var r104 = r5 | 8; var r105 = r63 / r72; var r106 = 7 * r56; var r107 = r59 + r60; var r108 = r48 | r93; var r109 = 8 / 3; var r110 = 1 | r98; return x; }); } catch(e1) { } try { for (var v of g1.g2.g1) { try { g2.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e0) { } try { a1.pop(); } catch(e1) { } try { a2.unshift(m1, a1, g0.o0.o2.p1); } catch(e2) { } Array.prototype.shift.apply(g0.a1, []); } } catch(e2) { } g1.e1 = new Set(m2); } })); } } catch(e0) { } try { t2 = g2.t2.subarray(15, 19); } catch(e1) { } Object.defineProperty(this, \"o0.i0\", { configurable: true, enumerable: {},  get: function() {  return new Iterator(f0, true); } }); } } } } catch(e0) { } g2.offThreadCompileScript(\"(void schedulegc(this.g0));\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 27 == 23), sourceIsLazy: true, catchTermination: false })); } else { try { const i2 = new Iterator(this.e1, true); } catch(e0) { } try { /*RXUB*/var r = r0; var s = this.s0; print(r.test(s)); print(r.lastIndex);  } catch(e1) { } v0 = g1.eval(\"function f0(s0)  { return (4277) } \"); } });\n/*RXUB*/var r = /(?=\\w?)?/i; var s = \"\"; print(s.match(r)); \n");
/*fuzzSeed-211892750*/count=736; tryItOut("for (var v of o0.m0) { try { g0.a0 = arguments; } catch(e0) { } try { m1.set(b1, v0); } catch(e1) { } Array.prototype.shift.apply(a1, []); }");
/*fuzzSeed-211892750*/count=737; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^].?\", \"gym\"); var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-211892750*/count=738; tryItOut("\"use strict\"; v0 = t2.byteOffset;");
/*fuzzSeed-211892750*/count=739; tryItOut("/*MXX2*/g1.RegExp.leftContext = t0;");
/*fuzzSeed-211892750*/count=740; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sqrt((( ! ((( + (( + 0) ? ( + ( + x)) : ( + x))) >>> 0) + Math.fround(Math.fround((x | 0))))) >>> 0)); }); ");
/*fuzzSeed-211892750*/count=741; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=742; tryItOut("v0 = Object.prototype.isPrototypeOf.call(p0, m1);");
/*fuzzSeed-211892750*/count=743; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2|\\\\b+?|[^]|.\\\\b^{4}+?(?!\\\\W*)$|\\\\b*?{1,}\", \"yim\"); var s = \"\\n\"; print(s.replace(r, 'x')); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=744; tryItOut("o1 + '';");
/*fuzzSeed-211892750*/count=745; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ~ Math.log2(Math.fround(( - (y >>> 0))))); }); testMathyFunction(mathy2, /*MARR*/[x, -(2**53+2), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, -(2**53+2), x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x]); ");
/*fuzzSeed-211892750*/count=746; tryItOut("\"use strict\"; testMathyFunction(mathy2, [42, -Number.MAX_SAFE_INTEGER, 0, 1, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0x100000001, 2**53-2, -0x0ffffffff, -0x100000000, Number.MIN_VALUE, -0, -Number.MAX_VALUE, 2**53+2, 0/0, Math.PI, 2**53, 0x07fffffff, -0x080000000, 0x100000000, 0x100000001, 0x080000001, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, 0.000000000000001, -1/0]); ");
/*fuzzSeed-211892750*/count=747; tryItOut("m1.has(m2);");
/*fuzzSeed-211892750*/count=748; tryItOut("\"use strict\"; i0 + '';");
/*fuzzSeed-211892750*/count=749; tryItOut("mathy1 = (function(x, y) { return ((Math.fround((Math.atan2(x, x) ? (( + (x !== ( + (((( + y) << x) | 0) ^ x)))) >= Math.acos(x)) : Math.fround(2**53))) == ( + mathy0(( + (((1/0 >>> 0) ? ((x ? y : Math.PI) | 0) : (x | 0)) | 0)), ( + (y >>> Math.acosh(Math.acos(x))))))) / mathy0((Math.hypot((y | 0), ( - y)) >>> 0), (Math.imul((1/0 >>> 0), (Math.log(( ~ (y | 0))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-211892750*/count=750; tryItOut("v0 = Object.prototype.isPrototypeOf.call(v0, p2);");
/*fuzzSeed-211892750*/count=751; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.log2(((( ~ (Math.cbrt(( + ((Math.sign((( - (-1/0 | 0)) | 0)) >>> 0) + (Math.imul(x, (x >>> 0)) | 0)))) >>> 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x0ffffffff, 0x07fffffff, 0x080000001, 0x080000000, 1/0, 1.7976931348623157e308, 0, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 0x100000000, -0, -0x100000000, Math.PI, 0/0, -(2**53-2), 2**53, -0x080000001, 2**53-2, 0x0ffffffff, -(2**53), -0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, -0x080000000, 2**53+2, 42, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001]); ");
/*fuzzSeed-211892750*/count=752; tryItOut("v2 = Infinity;");
/*fuzzSeed-211892750*/count=753; tryItOut("\"use strict\"; Object.defineProperty(this, \"v0\", { configurable: false, enumerable: (makeFinalizeObserver('tenured')),  get: function() {  return g0.eval(\"e2 + '';\"); } });");
/*fuzzSeed-211892750*/count=754; tryItOut("e1.delete(g0);");
/*fuzzSeed-211892750*/count=755; tryItOut("/*bLoop*/for (yguisi = 0; yguisi < 73; ++yguisi) { if (yguisi % 46 == 31) { /*oLoop*/for (let ftjmeh = 0; ftjmeh < 48 && (24); ++ftjmeh) { print(o2); }  } else { selectforgc(this.o2); }  } ");
/*fuzzSeed-211892750*/count=756; tryItOut("\"use strict\"; let gioegq, a, d, c = (/*FARR*/[].filter((let (e=eval) e), (Math += 8))(x)), window = window, phnkcj;/*ODP-1*/Object.defineProperty(t1, \"4\", ({configurable: false, enumerable: true}));");
/*fuzzSeed-211892750*/count=757; tryItOut("print(uneval(f0));");
/*fuzzSeed-211892750*/count=758; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.cos((Math.min(mathy2(( + mathy0(( + x), ( + x))), (Math.max((y | 0), (y | 0)) | 0)), (Math.asinh(0x07fffffff) | 0)) ? ( ~ Math.sqrt((Math.fround(x) & -0x0ffffffff))) : mathy0((x >>> 0), ((mathy1(((Math.atanh(Number.MIN_SAFE_INTEGER) | 0) >>> 0), (y >>> 0)) >>> 0) * ( + Math.trunc(( + Math.atan2(y, (Math.hypot((y >>> 0), (x >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy5, [/0/, ({toString:function(){return '0';}}), '', undefined, -0, 0, (new Number(0)), ({valueOf:function(){return '0';}}), null, (function(){return 0;}), [0], true, NaN, 1, objectEmulatingUndefined(), [], ({valueOf:function(){return 0;}}), 0.1, (new Boolean(false)), (new Boolean(true)), '\\0', '/0/', (new Number(-0)), (new String('')), false, '0']); ");
/*fuzzSeed-211892750*/count=759; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( ! (Math.expm1((Math.imul(x, ( ~ ((x ? x : y) | 0))) | 0)) ? y : Math.fround(( ~ Math.fround(2**53)))))) !== Math.fround(Math.fround(( - Math.hypot(( + (((Math.ceil((-0 >>> 0)) >>> 0) || (((x | 0) && x) | 0)) ? y : 0x0ffffffff)), ( + mathy0(Math.min(x, (x >>> 0)), Math.atanh(Math.atan(( + y))))))))))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -Number.MIN_VALUE, 0, 0/0, 1.7976931348623157e308, 42, Number.MIN_VALUE, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), 0x080000001, 0.000000000000001, -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 1/0, 0x100000001, 0x0ffffffff, -0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000000, 1, Number.MAX_VALUE, Math.PI, 0x100000000, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-211892750*/count=760; tryItOut("Array.prototype.unshift.call(this.a2, this.h2, i0, v2);");
/*fuzzSeed-211892750*/count=761; tryItOut(";const c = 19;");
/*fuzzSeed-211892750*/count=762; tryItOut("v2 = o0.t0.byteOffset;\ng1.h0 = ({getOwnPropertyDescriptor: function(name) { return i1; var desc = Object.getOwnPropertyDescriptor(a0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { i0.next();; var desc = Object.getPropertyDescriptor(a0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw g0.g1; Object.defineProperty(a0, name, desc); }, getOwnPropertyNames: function() { print(v2);; return Object.getOwnPropertyNames(a0); }, delete: function(name) { a2 = arguments;; return delete a0[name]; }, fix: function() { s2 = this.a0.join(s1);; if (Object.isFrozen(a0)) { return Object.getOwnProperties(a0); } }, has: function(name) { f0(a0);; return name in a0; }, hasOwn: function(name) { 22 = a1[19];; return Object.prototype.hasOwnProperty.call(a0, name); }, get: function(receiver, name) { Object.defineProperty(this, \"v0\", { configurable: true, enumerable: true,  get: function() {  return o0.a1.some((function(j) { if (j) { try { m2.has(e0); } catch(e0) { } try { yield; } catch(e1) { } f0.__proto__ = e2; } else { for (var v of g0.g1) { m1 + ''; } } }), p1, p2, this.v1, i1); } });; return a0[name]; }, set: function(receiver, name, val) { v1 = (f0 instanceof b0);; a0[name] = val; return true; }, iterate: function() { v2 = evalcx(\"e1.has(t1);\", g0.o2.g2);; return (function() { for (var name in a0) { yield name; } })(); }, enumerate: function() { Object.seal(o2.f0);; var result = []; for (var name in a0) { result.push(name); }; return result; }, keys: function() { Array.prototype.shift.apply(a1, []);; return Object.keys(a0); } });\n");
/*fuzzSeed-211892750*/count=763; tryItOut("Array.prototype.push.apply(a1, [this.g2.o2, p0, b2]);");
/*fuzzSeed-211892750*/count=764; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Uint32ArrayView[(((+(((0xc5f36fb4)) ^ ((0xff474f17)))) > (-33554433.0))+(((((!(0x6c5ea39))) >> ((0x65c5aa40) / (0x5cb9b129)))) > (0xe07c4cc))) >> 2]) = ((((i1)) ^ (((((Uint32ArrayView[1]))>>>((i1))) != (0x3bfba779)))) / (((0xb8702147))|0));\n    {\n      d0 = (+(-1.0/0.0));\n    }\n    return +((+((d0))));\n  }\n  return f; })(this, {ff: String.prototype.fontsize}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x0ffffffff, -0, 0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, -(2**53), -0x0ffffffff, 1/0, 1.7976931348623157e308, 0x07fffffff, 42, -0x080000000, -0x07fffffff, -0x100000000, 0.000000000000001, 0x100000001, -1/0, 0/0, 2**53-2, -Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 0, 2**53, Math.PI, 2**53+2, -Number.MAX_VALUE]); ");
/*fuzzSeed-211892750*/count=765; tryItOut("m2 = new Map(this.t2);o1.valueOf = (function() { for (var j=0;j<34;++j) { this.f0(j%2==0); } });");
/*fuzzSeed-211892750*/count=766; tryItOut("/*ODP-2*/Object.defineProperty(m0, \"isArray\", { configurable: (x % 11 == 6), enumerable: (x % 3 != 1), get: function(y) { \"use strict\"; return [] = print(y) }, set: (function() { o0.a2.__proto__ = b0; throw b1; }) });");
/*fuzzSeed-211892750*/count=767; tryItOut("a2 = arguments;");
/*fuzzSeed-211892750*/count=768; tryItOut("/*hhh*/function bufsak(x, eval, a, this.e, x, window = true, eval, x = \"\\u03B6\", x, eval, x, a, z, b = window, x, x, NaN = [1], x = \"\\u3DE3\", eval, getter, x, x, w, w, d, NaN, x, x = \"\\u2A8A\", b, x, x, x, window, d, NaN, x =  /x/ , x, \u3056, x, x, x, window, z, x, b, y, x){print(x);}bufsak();function b(x)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((36028797018963970.0));\n  }\n  return f;h1.toString = (function(j) { if (j) { try { f1(i0); } catch(e0) { } try { o0.h0.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i0 = (((0xe8772*(i0))>>>(((i0) ? (i1) : (let (c) (void options('strict_mode'))))*-0x50ab9)));\n    i1 = ((~~(524289.0)) == (~((i1)-((+(-1.0/0.0)) > (-513.0)))));\n    return +((3.022314549036573e+23));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); } catch(e1) { } try { v0 = (b2 instanceof b2); } catch(e2) { } s0 = ''; } else { try { a1.shift(this); } catch(e0) { } try { v1 + ''; } catch(e1) { } try { a2 = a2.filter((function() { try { Object.defineProperty(this, \"v1\", { configurable: true, enumerable: false,  get: function() {  return o1.a2.length; } }); } catch(e0) { } s0 = s2.charAt(9); return g2; })); } catch(e2) { } for (var p in o1.g0) { try { v1 = g0.runOffThreadScript(); } catch(e0) { } t2 = new Int32Array(a0); } } });");
/*fuzzSeed-211892750*/count=769; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + ((Math.sinh(((Math.fround(x) + ((( + 1) || Math.fround((Math.fround(x) - Math.fround(-0x100000000)))) | 0)) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1/0, 0x100000001, 0/0, -Number.MIN_VALUE, 2**53, 0x080000001, -0x0ffffffff, -0x100000001, Math.PI, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, 0.000000000000001, -0, -1/0, 0x080000000, 42, 0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x080000001, -(2**53-2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1]); ");
/*fuzzSeed-211892750*/count=770; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=771; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((~((Uint8ArrayView[((-0x8000000)-(!((0x2a3de00) < (((0xffd1154b)) & ((0xfb491cef)))))) >> 0]))));\n    return (((i1)+(/*FFI*/ff((((-0x44c*(i1)) & (-0x293b9*(i1)))), ((((((((0xffffffff)*0xae014)>>>((0x5ce3624b)+(0xc033f79e)+(0x337c9981))))-(((0x223e16b9)) ? ((1.0) > (0.015625)) : (i0))) << (((0xffffffff) <= (0x85c92408)))))), (((-((0xe8b20a41))) & (((0x5caa075d) > (0x0))-(Math.exp(-29))+(i0)))), ((~~((+/*FFI*/ff(((9.0)), ((17592186044417.0)), ((-36893488147419103000.0)), ((-1.5474250491067253e+26)), ((-1.001953125)), ((-8589934593.0)), ((-32769.0)), ((8589934593.0)), ((-8193.0)), ((-73786976294838210000.0)), ((1.0)), ((262145.0)))) + (34359738367.0)))), ((+(-1.0/0.0))), (((((-0x8000000) != (0x31b2b6b0)))|0)), ((0x4bf8e901)), ((~~(1152921504606847000.0))), ((-2147483649.0)))|0)))|0;\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var nstqqt = 3875198477; var leqzqg = decodeURIComponent; return leqzqg;})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53-2), 0x080000000, 0.000000000000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, Number.MIN_VALUE, 1/0, 0x100000000, 2**53, 0, -0x100000000, -(2**53+2), 1, 2**53-2, -(2**53), 2**53+2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -1/0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, Math.PI, 0x0ffffffff, Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, -0, -0x07fffffff, 0x100000001]); ");
/*fuzzSeed-211892750*/count=772; tryItOut("undefined;");
/*fuzzSeed-211892750*/count=773; tryItOut("\"use strict\"; /*infloop*/for(let y; (~(({x: true}))); new (this)(false,  /x/ )) {print(window);\"\\uECDE\";g2.v0 = (a0 instanceof f1); }");
/*fuzzSeed-211892750*/count=774; tryItOut("\"use strict\"; v1 = a0.some((function() { v1 = (o0.v0 instanceof i0); return g0; }));");
/*fuzzSeed-211892750*/count=775; tryItOut("\"use strict\"; /*bLoop*/for (nybype = 0; nybype < 58; ++nybype) { if (nybype % 4 == 1) { (mathy1 ? new (String.prototype.concat)(e = /(?!(?=[^\\\ucd78\\W\\cG\\x97-\\xaf]|[^]*(?!.){4,4}+?))/ym, /.|(?!\\b\u00c4)+?{3}(?!\\B+?){3,3}(?!(?:[\\uA9Fb-\\u0033])\u001e)\\3{4,5}/im) : (eval === eval)); } else { a0.unshift(x, s0, p2, i1, t2); }  } ");
/*fuzzSeed-211892750*/count=776; tryItOut("(/*MARR*/[].sort);");
/*fuzzSeed-211892750*/count=777; tryItOut("print(x);");
/*fuzzSeed-211892750*/count=778; tryItOut("mathy2 = (function(x, y) { return (((((((Math.hypot((y | 0), 1/0) | 0) ? Math.fround(y) : (y | 0)) | 0) >>> 0) ? ((Math.pow((Math.ceil(Math.fround(Math.hypot(Math.fround(x), Math.fround(y)))) | 0), (Math.clz32((0.000000000000001 | 0)) | 0)) | 0) >>> 0) : (( + mathy0(( + -Number.MIN_SAFE_INTEGER), Math.clz32((Math.fround(Math.log2(0x080000001)) >>> 0)))) >>> 0)) >>> 0) !== Math.imul(((Math.tanh((1 | 0)) | 0) | 0), (( - Math.expm1(y)) >>> 0))); }); testMathyFunction(mathy2, [2**53, -(2**53-2), 0x100000001, -(2**53+2), -0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, -(2**53), -0x080000000, 0/0, -0x0ffffffff, 0, 2**53+2, -1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, 1, 42, -Number.MIN_VALUE, -0x100000000, 0x080000000, 0x080000001, -0x100000001, 1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=779; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(e1, i0);");
/*fuzzSeed-211892750*/count=780; tryItOut("mathy1 = (function(x, y) { return Math.fround(( ~ Math.fround(( + Math.hypot(( + (( + Number.MAX_VALUE) | 0)), ((((Math.pow((( ! (x ? x : (Math.log1p(Math.fround(x)) | 0))) >>> 0), (y >>> 0)) >>> 0) | 0) % ((Math.pow(Math.fround(y), Math.fround((( + ((( + x) ** x) | 0)) | 0))) >>> 0) | 0)) | 0)))))); }); testMathyFunction(mathy1, [-(2**53), -(2**53+2), 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 0x100000000, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 0x100000001, 42, 0x080000001, -Number.MAX_VALUE, 2**53, 0x0ffffffff, 0/0, -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, -1/0, -0, Number.MIN_VALUE, -0x080000001, 0x07fffffff, 1.7976931348623157e308, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-211892750*/count=781; tryItOut("e0.has(f2);");
/*fuzzSeed-211892750*/count=782; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 36893488147419103000.0;\n    return (((0xffffffff)+(0x453215fe)))|0;\n  }\n  return f; })(this, {ff: (/*RXUE*//\\2{1,}/g.exec(\"\\n\\u00ac_\\n\\u00ac_\\n\\u00ac_\\n\\u00ac_\\n\\u00ac_\\n\\u00ac_\\n\\n\\n\\u00ac_\\n\\u00ac_\\nO\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, 0x080000000, -0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 1.7976931348623157e308, 1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000001, 0/0, 0, 0x100000000, -0, 2**53, 2**53-2, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, 1, 0x100000001, 0x080000001, -(2**53-2), 42, -0x0ffffffff, Math.PI]); ");
/*fuzzSeed-211892750*/count=783; tryItOut("Object.seal(e2);");
/*fuzzSeed-211892750*/count=784; tryItOut("L:with({y: x});");
/*fuzzSeed-211892750*/count=785; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((( + Math.imul(y, (x >>> 0))) * ((mathy0(( + Math.trunc(( ! Math.fround(Math.max(( - x), y))))), ( + (( + mathy0(( + ((( ! x) >>> 0) * (( - y) | 0))), ( + y))) && -0x080000000))) | 0) | 0)) | 0); }); testMathyFunction(mathy1, [0x0ffffffff, -(2**53+2), 1, -0, -(2**53), 2**53+2, 0, 0x100000000, -0x100000000, -0x080000001, 1.7976931348623157e308, -1/0, 2**53-2, -(2**53-2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, -0x100000001, Math.PI, Number.MAX_VALUE, 2**53, 0x080000001, 0/0, 42, 0x100000001]); ");
/*fuzzSeed-211892750*/count=786; tryItOut("\"use strict\"; for (var p in o2) { /*RXUB*/var r = r0; var s = s1; print(s.replace(r, ((new \"\\uD807\"(false, valueOf)))(\"\\u6759\" in \"\\u913A\")));  }");
/*fuzzSeed-211892750*/count=787; tryItOut(";");
/*fuzzSeed-211892750*/count=788; tryItOut("mathy0 = (function(x, y) { return ( + ( ! ( + (((Math.max(((y << -Number.MIN_SAFE_INTEGER) | 0), (y | 0)) | 0) | 0) % ( + ( - Math.fround(x))))))); }); ");
/*fuzzSeed-211892750*/count=789; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((0x44a7f8c7)-(0x77762fc9)))|0;\n    return (((((i2))>>>((0xfb74ff91)+(i2))) / (((0x9a9b82fa)+(i2)+(0xe697b64e))>>>((i2)))))|0;\n  }\n  return f; })(this, {ff: (function shapeyConstructor(fhcxdo){for (var ytqkuveif in this) { }this[ \"\" ] =  /x/ ;{  } this[ \"\" ] = fhcxdo;this[ \"\" ] = ({a1:1});this[ \"\" ] = eval;{ print(5); } return this; }).call(z =>  { \"use strict\"; print(x); } (), )}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x07fffffff, 0x080000001, 0x0ffffffff, -1/0, -Number.MIN_VALUE, 0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, 0, 0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 0/0, -0x100000000, 2**53-2, 0x07fffffff, -0, 0x080000000, 1, 2**53, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -0x100000001, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-211892750*/count=790; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + Math.imul(((( + Math.asin(Math.sqrt((mathy0(Math.fround(x), ( + y)) >>> 0)))) | 0) ** ((x === y) | 0)), ( + (0x100000001 ? ( ~ mathy0((y | x), ( + ( ! 0x080000001)))) : (((( + x) >>> 0) | 0) + x))))) >> ( + Math.max(Math.fround(mathy0((Math.fround(Math.min(Math.fround(y), Math.fround((Math.tanh((0x07fffffff >>> 0)) >>> 0)))) | 0), ( ! Math.fround(( + Math.trunc(( + ( ~ (0.000000000000001 >>> 0))))))))), (( + Math.log2((Math.max(( + ( + Math.log(y))), ( ~ y)) < y))) % ( + Math.fround((Math.tan((x | 0)) | 0))))))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, -Number.MIN_SAFE_INTEGER, 0, -(2**53+2), 2**53+2, Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, 1/0, -0, -0x0ffffffff, Math.PI, 1, Number.MAX_VALUE, 42, -0x100000000, 2**53, 0x080000001, -0x100000001, -1/0, 0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x080000000]); ");
/*fuzzSeed-211892750*/count=791; tryItOut("/*bLoop*/for (drpuzf = 0, qgnwwb; drpuzf < 117; ++drpuzf) { if (drpuzf % 43 == 36) { this.a1 = []; } else { const \u3056, window, y, oqwtrb, x;print(\"\\uB295\"); }  } for(let y = (4277) in window) {Array.prototype.unshift.apply(a2, [p1, this.i2]);i0.toSource = (function() { try { m1.has(b1); } catch(e0) { } try { v2 = a1.length; } catch(e1) { } e2 = new Set(i0); throw this.f1; }); }c = (uneval( \"\" ));");
/*fuzzSeed-211892750*/count=792; tryItOut("mathy4 = (function(x, y) { return (Math.imul(Math.fround((Math.ceil(x) ? Math.hypot(( + y), ( + ( + (( + ( ! -Number.MIN_SAFE_INTEGER)) !== ( + (((1/0 >>> 0) >= (y >>> 0)) >>> 0)))))) : Math.log10(Math.atanh(Math.fround((Math.fround(Math.hypot(y, y)) % ( + -Number.MAX_SAFE_INTEGER))))))), Math.fround((( ~ ((Math.max((0/0 | 0), ((x != Math.fround(Number.MAX_SAFE_INTEGER)) | 0)) | 0) >>> 0)) >>> 0))) ? ((( + x) >>> 0) && ( + Math.sin(mathy2(mathy0(((y !== Math.fround(Number.MIN_VALUE)) | 0), x), ( + (((x | 0) !== ( + Math.log1p(y))) >>> 0)))))) : ( + ( + ( + Math.atanh(Math.min(x, ( + Math.acosh(( + x))))))))); }); testMathyFunction(mathy4, [(new Number(-0)), ({valueOf:function(){return 0;}}), undefined, 0.1, '', null, NaN, (new Number(0)), ({toString:function(){return '0';}}), 1, ({valueOf:function(){return '0';}}), (new Boolean(false)), (new Boolean(true)), true, '/0/', 0, /0/, (new String('')), [0], '\\0', [], false, '0', -0, objectEmulatingUndefined(), (function(){return 0;})]); ");
/*fuzzSeed-211892750*/count=793; tryItOut("/*RXUB*/var r = /(?!(?:\u11d7{3,7}){1})/gyim; var s = \"\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\\u9a7b\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-211892750*/count=794; tryItOut("L:if((x % 37 != 0)) {m0.toString = (function() { for (var j=0;j<2;++j) { f0(j%2==0); } });print(x); } else  if (null) print(-3);");
/*fuzzSeed-211892750*/count=795; tryItOut("\"use strict\"; /*infloop*/for(let \u3056 in ((Number)((4277)))){Object.preventExtensions(f2);print(x); }");
/*fuzzSeed-211892750*/count=796; tryItOut("mathy2 = (function(x, y) { return ( + ( ~ Math.min(( ! ( + (Math.min((0.000000000000001 | 0), ( + x)) | 0))), mathy1(( + Math.max(Math.min(Math.fround(y), Math.fround(Math.tanh(( + x)))), ( ! 0/0))), y)))); }); ");
/*fuzzSeed-211892750*/count=797; tryItOut("mathy1 = (function(x, y) { return (Math.clz32(( + ( + (mathy0((Math.min(x, ( + y)) >>> 0), (( + Math.cos(x)) >>> 0)) >>> 0)))) >>> 0); }); testMathyFunction(mathy1, [-0x07fffffff, 0x080000000, -(2**53-2), 1, 1.7976931348623157e308, -0x0ffffffff, 2**53+2, 0x0ffffffff, 2**53-2, 0/0, -0x080000001, Math.PI, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, 0, -0, 0x100000001, -(2**53), 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000001, -1/0, -(2**53+2), 2**53, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-211892750*/count=798; tryItOut("\"use asm\"; var zjshfw = new SharedArrayBuffer(12); var zjshfw_0 = new Uint16Array(zjshfw); print(zjshfw_0[0]); zjshfw_0[0] = 29; var zjshfw_1 = new Int32Array(zjshfw); var zjshfw_2 = new Uint8Array(zjshfw); print(zjshfw_2[0]); zjshfw_2[0] = -11; var zjshfw_3 = new Int16Array(zjshfw); zjshfw_3[0] = -10; var zjshfw_4 = new Int16Array(zjshfw); zjshfw_4[0] = 9; var zjshfw_5 = new Uint8Array(zjshfw); { void 0; gcslice(16149878); } /*RXUB*/var r = new RegExp(\"[^\\\\r-\\\\u000F\\u0019-\\\\u8dF0]\", \"gy\"); var s = \"\\u000e\"; print(uneval(s.match(r))); for(let c in window) g1.m2.set(g2, v1);print(!\"\\u5098\");{\u000ccibwhe();/*hhh*/function cibwhe(zjshfw_4, eval, ...zjshfw_4){Array.prototype.reverse.apply(g2.a1, []);} }");
/*fuzzSeed-211892750*/count=799; tryItOut("testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -0x080000000, -0x100000001, 2**53+2, 0, -0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -1/0, 0.000000000000001, 0x080000000, Number.MIN_VALUE, 0x100000001, 0x080000001, -Number.MIN_VALUE, -0x100000000, 0x100000000, 1/0, 1, Math.PI, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, -0x080000001, -(2**53-2), -0x0ffffffff, -Number.MAX_VALUE, 2**53-2, -(2**53+2)]); ");
/*fuzzSeed-211892750*/count=800; tryItOut("\"use strict\"; testMathyFunction(mathy1, [2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 0x07fffffff, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, 0.000000000000001, -(2**53+2), 0x0ffffffff, 0/0, -(2**53), -0, 0x100000001, 2**53, Number.MIN_VALUE, -1/0, -0x07fffffff, -0x100000001, -0x080000001, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 42, 0, -0x100000000, 0x100000000, 2**53+2, -0x080000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-211892750*/count=801; tryItOut("\"use strict\"; e0.add(o2);");
/*fuzzSeed-211892750*/count=802; tryItOut(" /x/g ;");
/*fuzzSeed-211892750*/count=803; tryItOut("");
/*fuzzSeed-211892750*/count=804; tryItOut("m2.has(i2);");
/*fuzzSeed-211892750*/count=805; tryItOut("m0.__proto__ = h0;");
/*fuzzSeed-211892750*/count=806; tryItOut("var oksuyi = new SharedArrayBuffer(4); var oksuyi_0 = new Uint8ClampedArray(oksuyi); oksuyi_0[0] = -5; var oksuyi_1 = new Uint8ClampedArray(oksuyi); var oksuyi_2 = new Uint8ClampedArray(oksuyi); oksuyi_2[0] = 16777215; var oksuyi_3 = new Uint8ClampedArray(oksuyi); print(oksuyi_3[0]); oksuyi_3[0] = 15; var oksuyi_4 = new Float32Array(oksuyi); print(oksuyi_4[0]); oksuyi_4[0] = -2; var oksuyi_5 = new Float64Array(oksuyi); print(oksuyi_5[0]); var oksuyi_6 = new Uint32Array(oksuyi); oksuyi_6[0] = 0; var oksuyi_7 = new Uint32Array(oksuyi); oksuyi_7[0] = 24; var oksuyi_8 = new Uint8ClampedArray(oksuyi); oksuyi_8[0] = -27; a0 = arguments.callee.arguments;yield Math.sqrt(-24)\ns0 += 'x';");
/*fuzzSeed-211892750*/count=807; tryItOut("this.h2.keys = f2;");
/*fuzzSeed-211892750*/count=808; tryItOut("mathy0 = (function(x, y) { return ( ~ ((Math.atanh((Math.fround(y) > Math.fround((( + Math.hypot(Math.fround(y), y)) , x)))) ? Math.fround(( - Math.fround(Math.sin(y)))) : ( - Math.tanh(-1/0))) | 0)); }); testMathyFunction(mathy0, [2**53-2, 0/0, 0x100000001, Math.PI, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -(2**53), 0.000000000000001, 1.7976931348623157e308, -(2**53-2), -1/0, 0x080000001, 42, -0x080000001, 0, -0x100000000, -0x080000000, 0x080000000, Number.MAX_VALUE, -(2**53+2), 1, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 1/0, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-211892750*/count=809; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + (( - ( + Math.log(( + (Math.tanh(y) | 0))))) | 0)) === ( + (Math.fround((( ! Math.fround(Math.max(y, Math.fround(( ! Math.fround(-(2**53))))))) >= ((( + (-(2**53-2) | 0)) | 0) ^ (Math.imul(( + 42), Math.fround(x)) >>> 0)))) < Math.fround(( + ( + (( + ((x * 0x07fffffff) >>> ((( + (x ? x : x)) , (y | 0)) >>> 0))) ? x : ((0.652 < y) >>> 0)))))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, 0, 0x080000001, -0x07fffffff, Math.PI, 0x100000000, 0x07fffffff, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x100000001, 0x080000000, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, 42, Number.MIN_VALUE, 0x100000001, -(2**53), 1, -0, 2**53+2, 0x0ffffffff, -(2**53-2), -(2**53+2), -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, 1/0, -Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=810; tryItOut("/*oLoop*/for (var alaazc = 0; alaazc < 70; ++alaazc) { c = linkedList(c, 850); } ");
/*fuzzSeed-211892750*/count=811; tryItOut("intern(window);");
/*fuzzSeed-211892750*/count=812; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.cbrt(Math.fround(Math.fround(( - Math.fround(mathy1(x, (y <= Math.trunc(x)))))))) >>> 0); }); testMathyFunction(mathy3, [0x07fffffff, 0x100000000, -1/0, 0/0, 0x080000000, -(2**53+2), -Number.MAX_VALUE, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), -0, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 1, 42, -0x0ffffffff, 0x100000001, 1.7976931348623157e308, 2**53+2, Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -0x07fffffff, 0.000000000000001, 0x0ffffffff, 2**53-2, -Number.MIN_VALUE, -0x080000001, 1/0]); ");
/*fuzzSeed-211892750*/count=813; tryItOut("mathy2 = (function(x, y) { return (( + mathy0(mathy1(mathy1(x, x), Math.hypot(Math.min(2**53, (( + ( - (y >>> 0))) | 0)), y)), (( + x) ? y : y))) | 0); }); testMathyFunction(mathy2, ['0', [0], ({toString:function(){return '0';}}), (function(){return 0;}), 0, -0, true, 0.1, '/0/', (new Boolean(false)), false, objectEmulatingUndefined(), [], ({valueOf:function(){return 0;}}), undefined, (new Number(-0)), '\\0', /0/, null, ({valueOf:function(){return '0';}}), (new Number(0)), (new Boolean(true)), NaN, (new String('')), '', 1]); ");
/*fuzzSeed-211892750*/count=814; tryItOut("{e2.add(o1); }");
/*fuzzSeed-211892750*/count=815; tryItOut("/*iii*///h\nyield y;/*MXX1*/o1 = g2.DataView.prototype.getFloat32;/*hhh*/function nxtwat(b, ...c){/*hhh*/function tiymxk(y, x){yield;}tiymxk(undefined, ( '' .eval(\"/* no regression tests found */\")));}");
/*fuzzSeed-211892750*/count=816; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-(2**53), -0, 0, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, 42, 0x080000001, -0x100000000, 1, 0x07fffffff, -(2**53+2), -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000000, -1/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, -0x080000000, 0x100000000, 0.000000000000001, 0x0ffffffff, 0/0, 2**53-2, Math.PI, -0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-211892750*/count=817; tryItOut("(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: (1 for (x in [])), delete: undefined, fix: undefined, has: function(name) { return name in x; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: undefined, }; })(Math.ceil(9)), String.prototype.toString));");
/*fuzzSeed-211892750*/count=818; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0, 0x080000000, -Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, -0x100000001, 1/0, -0x0ffffffff, -0x080000001, -0x07fffffff, 2**53+2, 0x100000001, Math.PI, 2**53-2, Number.MIN_VALUE, 0x080000001, -1/0, -(2**53), 1.7976931348623157e308, 0.000000000000001, -0, -(2**53-2), 0/0, 1, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000]); ");
/*fuzzSeed-211892750*/count=819; tryItOut("\"use strict\"; e1 = new Set(g2.s1);");
/*fuzzSeed-211892750*/count=820; tryItOut("mathy0 = (function(x, y) { return ((((((( ~ Math.fround(((( ! Math.fround(y)) >>> 0) === y))) >>> 0) ^ (Math.min(( ! 1), (( ~ (x | 0)) | 0)) >>> 0)) >>> 0) >>> 0) ? ((( - (x >>> (-0x100000000 >> y))) <= ( ! (Math.fround(x) / -Number.MIN_SAFE_INTEGER))) >>> 0) : (Math.pow(( + ( - (x | 0))), ((((Math.max(-Number.MIN_VALUE, ((( + Math.fround(( ! x))) >>> 0) ^ x)) | 0) | 0) <= (( + ( ~ ( + y))) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, 1.7976931348623157e308, -(2**53), 0x080000001, Number.MIN_VALUE, 2**53, -0x100000000, -Number.MIN_VALUE, -(2**53-2), 2**53-2, 0x080000000, 0.000000000000001, -0x07fffffff, -0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, 42, -(2**53+2), -0x080000000, 1, 1/0, Math.PI, 0x100000001, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, 0, -0x100000001, 2**53+2]); ");
/*fuzzSeed-211892750*/count=821; tryItOut("mathy5 = (function(x, y) { return mathy4((( + (( + Math.fround(Math.imul(Math.fround(-0), Math.exp(Math.PI)))) >>> 0)) >>> 0), ((((mathy1(((mathy2((y | 0), ((2**53-2 >> x) | 0)) | 0) >>> 0), (y >>> 0)) >>> 0) * ((( - ((( + x) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0) % Math.acos((Math.hypot(-1/0, (0.000000000000001 | 0)) + ((y <= (x >= (Math.log((y | 0)) | 0))) | 0))))); }); testMathyFunction(mathy5, [0x080000000, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 1, 0.000000000000001, 0/0, -Number.MAX_VALUE, 42, 2**53, -(2**53-2), 0x0ffffffff, -1/0, -0x0ffffffff, -0x080000000, 0, -0x100000001, Number.MIN_VALUE, Math.PI, -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-211892750*/count=822; tryItOut("mathy3 = (function(x, y) { return (((Math.fround(mathy2((Number.MAX_VALUE >>> 0), (( + ( + ((x | 0) < Math.atan2(y, ( + mathy1(1, y)))))) >>> 0))) || Math.acosh(( + x))) | 0) >= (Math.atan2(((((x === y) !== y) !== y) | 0), (( - (1.7976931348623157e308 , ( + Math.log(y)))) < x)) | 0)); }); testMathyFunction(mathy3, [true, /0/, [0], (new Boolean(true)), '/0/', ({toString:function(){return '0';}}), [], 0.1, null, '', ({valueOf:function(){return 0;}}), 1, NaN, objectEmulatingUndefined(), (new Number(-0)), undefined, (new Number(0)), -0, false, (new Boolean(false)), '\\0', '0', 0, (function(){return 0;}), ({valueOf:function(){return '0';}}), (new String(''))]); ");
/*fuzzSeed-211892750*/count=823; tryItOut("");
/*fuzzSeed-211892750*/count=824; tryItOut("a2.splice(-6, 18);");
/*fuzzSeed-211892750*/count=825; tryItOut("\"use strict\"; /*RXUB*/var r = g0.r0; var s = (p={}, (p.z = ((Function)((window | e))))()); print(uneval(r.exec(s))); ");
/*fuzzSeed-211892750*/count=826; tryItOut("mathy0 = (function(x, y) { return (( + Math.hypot((y + Math.atan2(( + -Number.MAX_VALUE), eval)), (( ! Math.exp(y)) >>> 0))) << ( + Math.fround(Math.asinh(Math.fround(x))))); }); ");
/*fuzzSeed-211892750*/count=827; tryItOut("Array.prototype.splice.call(a0, NaN, ({valueOf: function() { /*RXUB*/var r =  /x/ ; var s = \"\\ub88d\\ub88d\\ub88d\\u0087\\u0087\\ub88d\\ub88d\\ub88d\"; print(uneval(r.exec(s))); return 6; }}));s0 + '';");
/*fuzzSeed-211892750*/count=828; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! (((((( - y) | 0) ? Math.cosh(( + Math.fround(Math.min(Math.fround((( ! Math.fround(x)) ** x)), Math.fround(y))))) : Math.fround(x)) | 0) >>> 0) != ( + Math.round(( + Math.imul((( + ( + ( ~ ( + y)))) >= Math.fround((Math.fround(y) ? Math.fround((( + y) < ( + x))) : Math.fround(-0x07fffffff)))), y)))))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 1, 1/0, 1.7976931348623157e308, 0x080000000, -0x100000001, 0x07fffffff, -(2**53), -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, 0, -0, 0x100000001, -(2**53+2), -0x0ffffffff, 0x0ffffffff, -0x080000000, Number.MAX_VALUE, 0x100000000, 2**53+2, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), 42, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 2**53, 2**53-2, -0x07fffffff, 0.000000000000001, Math.PI, -0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-211892750*/count=829; tryItOut("e1.delete(g0.p2);");
/*fuzzSeed-211892750*/count=830; tryItOut("Array.prototype.shift.call(a0, t2);");
/*fuzzSeed-211892750*/count=831; tryItOut("L:if(true) { if (\"\\u43F8\") a0.forEach((function() { try { h1.valueOf = (function() { for (var j=0;j<31;++j) { f1(j%3==1); } }); } catch(e0) { } try { t0 + a0; } catch(e1) { } try { g1.offThreadCompileScript(\"for (var p in g1) { try { /*RXUB*/var r = r2; var s = \\\"\\\\u4314\\\\uf62d\\\\n\\\\u9ce7\\\\n\\\"; print(uneval(r.exec(s)));  } catch(e0) { } try { this.o1.i0 + g0.e2; } catch(e1) { } try { x = b0; } catch(e2) { } t2 = new Uint8ClampedArray(a1); }\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: false, sourceMapURL: s0 })); } catch(e2) { } s1 += 'x'; return this.v0; })); else this.m1 = new Map;}");
/*fuzzSeed-211892750*/count=832; tryItOut("function f1(e2)  { yield (e2%=(4277)) } ");
/*fuzzSeed-211892750*/count=833; tryItOut("\"use strict\"; { void 0; minorgc(false); } let (x = null, d = window.eval(\"mathy2 = (function(x, y) { return (mathy1((Math.min(mathy0((Math.atan(y) | 0), x), (Math.expm1(((( ! x) | 0) == y)) >>> 0)) >>> 0), Math.max(Math.log2(Math.min(x, mathy1(-1/0, y))), Math.fround(Math.pow((Math.min(Math.fround(Math.pow(Math.fround(0x080000000), (Math.fround(Math.tanh(Math.fround(Math.imul(x, x)))) >>> 0))), (y >>> 0)) >>> 0), Math.fround(( ! (( + Math.log10(x)) < (x >>> 0)))))))) | 0); }); \"), d = (4277), eval = (x = Proxy.create(({/*TOODEEP*/})(/\\b/gim), new RegExp(\"((?!\\\\ub5c5)\\\\W{4,}(?!(?=.)){3,}*?)\", \"yim\"))), window, agymmf, xnopgh, a, e) { /*vLoop*/for (hdxsvt = 0; hdxsvt < 3; (4277), (eval(\"/* no regression tests found */\", (Math instanceof /\\2/gi))), ++hdxsvt) { y = hdxsvt; m1 + i1; }  }");
/*fuzzSeed-211892750*/count=834; tryItOut("/*vLoop*/for (let kiqvtr = 0; kiqvtr < 21; ++kiqvtr) { let a = kiqvtr; m1.get(t0); } ");
/*fuzzSeed-211892750*/count=835; tryItOut("\"use strict\"; Object.freeze(p1);");
/*fuzzSeed-211892750*/count=836; tryItOut("\"use strict\"; print(x);\nObject.defineProperty(this, \"a0\", { configurable: (x % 5 != 1), enumerable: (x % 56 != 39),  get: function() {  return arguments.callee.arguments; } });\n");
/*fuzzSeed-211892750*/count=837; tryItOut("a2.__iterator__ = (function() { g0.e1.add(o0); return m0; });");
/*fuzzSeed-211892750*/count=838; tryItOut("(({\"-26\": \"\u03a0\",  get __proto__ e () { ( /x/g ); }  }));function x(x, x, b, NaN = (4277), window, this, e, window, d = window, c, z, e, x, x, x = null, NaN =  /x/ , x, \u3056, window, x = d, a, w, [,,], c, z, y, x, c, x, x, a, \u3056, z, eval, x = 25, x, c, x, x = true, b, b, set, \u3056, d, x, w, x, \"13\", \u3056, b, x, z, b, y, a, window, x, x, b, a, window, eval, x, x, eval = /(?:\\0)+?/g, NaN = -25, c, c, x, x = (function ([y]) { })(), \u3056, b = eval, a, x, x, x, eval, d, this.x, x, z, w = \"\\u0EA2\", \u3056, w, of, x, x, x, NaN, window, x, d, x, e, e) { \"use strict\"; yield (/*FARR*/[new RegExp(\"\\\\b|.(?:.){1,4}*?[\\\\d]{4,6}\", \"yi\"),  '' ].sort(y)) **= yield new RegExp(\"(?!${4,}){4,4}\", \"i\") |= (function(y) { print(window); }).call(undefined, ) } /*vLoop*/for (let rpznwk = 0; rpznwk < 51; ++rpznwk) { var z = rpznwk; v0 = Object.prototype.isPrototypeOf.call(e2, e2); } function x(a, ...x) { return (makeFinalizeObserver('nursery')) } v2 = this.g1.g0.runOffThreadScript();");
/*fuzzSeed-211892750*/count=839; tryItOut("L: h0 = a2[{e} = e];");
/*fuzzSeed-211892750*/count=840; tryItOut("(this.zzz.zzz = x);");
/*fuzzSeed-211892750*/count=841; tryItOut("this.s0.__proto__ = a2;");
/*fuzzSeed-211892750*/count=842; tryItOut("\"use strict\"; [1] ? x :  \"\" ;");
/*fuzzSeed-211892750*/count=843; tryItOut("mathy5 = (function(x, y) { return (((((mathy3((Math.min(y, ( + y)) >>> 0), ((mathy4((Math.pow(0, Math.imul(x, (y ? x : 1))) >>> 0), (( + (y >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0) <= ( + mathy3(( + mathy2(((((( + (( + Math.sign(y)) | 0)) | 0) | 0) ? Math.fround((( + (x | 0)) | 0)) : (0/0 | 0)) | 0), Math.fround((( ~ y) === ( + x))))), 1.7976931348623157e308))) >>> 0) >= (mathy4((Math.pow(((-(2**53+2) >>> 0) < x), Math.fround((Math.fround((x >>> x)) % Math.fround(( + Math.log(2**53-2)))))) >>> 0), Math.imul(0x100000001, ( + ( ! ( + x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, /*MARR*/[false, NaN, -0x100000000, false, false, -0x100000000, x = \"\\uD89A\" instanceof  /x/ , -0x100000000, NaN, NaN, x = \"\\uD89A\" instanceof  /x/ , -0x100000000, NaN, [], x = \"\\uD89A\" instanceof  /x/ , x = \"\\uD89A\" instanceof  /x/ , x = \"\\uD89A\" instanceof  /x/ , [], false, -0x100000000, x = \"\\uD89A\" instanceof  /x/ , -0x100000000, [], x = \"\\uD89A\" instanceof  /x/ , -0x100000000, false, -0x100000000, [], -0x100000000]); ");
/*fuzzSeed-211892750*/count=844; tryItOut("/*hhh*/function ovhctw(window, b){Array.prototype.forEach.apply(a1, [f1]);\no0.v2 = v0[\"17\"];\n}/*iii*//*RXUB*/var r = new RegExp(\"(\\\\1(?:\\\\1?))\", \"gy\"); var s = \"\\ub5c5aaaaaaaaaa\\n\\n\\n\"; print(s.replace(r, (4277))); ");
/*fuzzSeed-211892750*/count=845; tryItOut("\"use strict\"; var uqodpn = new ArrayBuffer(0); var uqodpn_0 = new Uint8Array(uqodpn); print(uqodpn_0[0]); uqodpn_0[0] = -4; this.v1 = g2.eval(\"/* no regression tests found */\");");
/*fuzzSeed-211892750*/count=846; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-211892750*/count=847; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan(Math.log((Math.pow(( + (( - x) ? ((( + x) , ( + x)) | 0) : (x | 0))), ((( - ( + x)) - x) | Math.fround(( ~ Math.fround(( ~ 0.000000000000001)))))) | 0))); }); testMathyFunction(mathy0, /*MARR*/[]); ");
/*fuzzSeed-211892750*/count=848; tryItOut("Array.prototype.push.call(g2.a0, s0, s1, b0);");
/*fuzzSeed-211892750*/count=849; tryItOut("Object.defineProperty(this, \"v2\", { configurable: true, enumerable: false,  get: function() {  return t1.BYTES_PER_ELEMENT; } });");
/*fuzzSeed-211892750*/count=850; tryItOut("Array.prototype.shift.apply(a0, []);\nthis.o0.t0 + this.t1;\n");
/*fuzzSeed-211892750*/count=851; tryItOut("throw StopIteration;");
/*fuzzSeed-211892750*/count=852; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.max(( + Math.hypot((Math.min(( + mathy1(( + (((x | 0) <= ((Math.pow(Number.MIN_VALUE, -Number.MAX_VALUE) >>> 0) | 0)) | 0)), ( + (x & Math.min(x, Math.log2(1)))))), (Math.max(Number.MAX_VALUE, ( + x)) | 0)) >>> 0), ( + ( - ( + y))))), (( ~ (Math.fround(Math.log2(Math.log((Math.sqrt((x | 0)) | 0)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-211892750*/count=853; tryItOut("mathy2 = (function(x, y) { return Math.cosh((Math.ceil((( + ( ~ ( ~ (2**53 >>> 0)))) ? Math.fround(( ~ mathy0(y, (0x100000001 << (y >>> 0))))) : ( + y))) || Math.acos(( ! ( ~ Math.fround(0x080000000)))))); }); testMathyFunction(mathy2, [2**53+2, 0x080000000, 2**53, -1/0, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -(2**53-2), 1, -0x0ffffffff, Math.PI, -0x080000001, Number.MAX_VALUE, 0/0, -0, -(2**53), 0x0ffffffff, 0x100000001, 0, 0.000000000000001, -0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0x080000001, 42]); ");
/*fuzzSeed-211892750*/count=854; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -0.00390625;\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: Math.acosh}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-211892750*/count=855; tryItOut("m1.set(x, v1);");
/*fuzzSeed-211892750*/count=856; tryItOut("return;/* no regression tests found */");
/*fuzzSeed-211892750*/count=857; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + (Math.log10((( + Math.fround(( + (y && y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, -(2**53), -0, -0x0ffffffff, -0x100000000, 2**53-2, -0x100000001, 1.7976931348623157e308, 0, -(2**53-2), Number.MAX_VALUE, 0x080000000, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, -1/0, -0x080000001, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 0x080000001, 42, Math.PI, -0x07fffffff, 1, -(2**53+2), 1/0, 2**53, 0x100000001]); ");
/*fuzzSeed-211892750*/count=858; tryItOut("mathy2 = (function(x, y) { return (Math.pow(( + ((mathy0((Math.fround(x) | 0), ((0 % Math.max(y, x)) & Math.sign(Math.fround(mathy0(Math.fround(x), Math.fround(y)))))) >>> 0) < (( + ( - ( + (( ~ x) << (( - ((( - Math.fround(0x100000000)) | 0) | 0)) | 0))))) >>> 0))), ( + Math.expm1((( + Math.cbrt(Math.tan(((y >= Math.fround(y)) >>> 0)))) || (mathy1(Math.fround(y), ( + (((0x100000001 >>> 0) ? ( + y) : (y >>> 0)) >>> 0))) >>> 0))))) | 0); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -1/0, Math.PI, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, 2**53, -(2**53), 0x07fffffff, 1, -0, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, 2**53+2, 0x080000000, -Number.MAX_VALUE, 0x100000001, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, 42, -(2**53+2), -(2**53-2), -0x080000000]); ");
/*fuzzSeed-211892750*/count=859; tryItOut("\"use strict\"; g2.t1.set(a1, 9)");
/*fuzzSeed-211892750*/count=860; tryItOut("p0.__proto__ = a1;");
/*fuzzSeed-211892750*/count=861; tryItOut("/* no regression tests found */");
/*fuzzSeed-211892750*/count=862; tryItOut("t1 = m1;");
/*fuzzSeed-211892750*/count=863; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x080000000, 2**53, -Number.MAX_VALUE, 1/0, 42, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 0x100000001, Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), Number.MIN_VALUE, 0x080000001, 0x07fffffff, -0x080000001, -1/0, -0x0ffffffff, Math.PI, 2**53-2, -0x07fffffff, 1, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, 0, -0x100000001, -Number.MIN_SAFE_INTEGER, 0/0, -0]); ");
/*fuzzSeed-211892750*/count=864; tryItOut("\"use strict\"; /*oLoop*/for (var ytuulk = 0; ytuulk < 5; ++ytuulk) { /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { print(-28);return 1; }}), { configurable: (x % 33 != 5), enumerable: -17, get: o0.f2, set: f0 }); } ");
/*fuzzSeed-211892750*/count=865; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-211892750*/count=866; tryItOut("\"use strict\"; a1.splice(13, 16);");
/*fuzzSeed-211892750*/count=867; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return Math.atanh(Math.atan2(( + ( - ( + (Math.tanh(-Number.MIN_SAFE_INTEGER) , (( ! y) | 0))))), ( + Math.hypot(( + (( + Math.min(( + ((y >>> y) / (-(2**53) | 0))), y)) >>> ( + (Math.log2((x | 0)) | 0)))), (((Math.fround(Math.hypot(( + Math.hypot(42, y)), Math.fround((0x100000001 ? x : -0x0ffffffff)))) | 0) | x) | 0))))); }); ");
/*fuzzSeed-211892750*/count=868; tryItOut("testMathyFunction(mathy1, /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (-1/0), (-1/0), new String('q'), null, objectEmulatingUndefined()]); ");
/*fuzzSeed-211892750*/count=869; tryItOut("/*RXUB*/var r = /(?!(?=(.|\\D|\\D|\\b{0})))/im; var s = \"\\n\"; print(r.exec(s)); ");
/*fuzzSeed-211892750*/count=870; tryItOut("\"use strict\"; for (var p in v2) { try { p1 + g0; } catch(e0) { } try { /*ADP-2*/Object.defineProperty(a0, 13, { configurable: true, enumerable: true, get: f2, set: (function() { try { v2 = (g0 instanceof i2); } catch(e0) { } try { Array.prototype.splice.apply(a1, [NaN, 6, g1, b0, i1]); } catch(e1) { } a0 = new Array; throw o2.m0; }) }); } catch(e1) { } v0 = g2.t2.length; }\n");
/*fuzzSeed-211892750*/count=871; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.acosh((Math.hypot(((( ~ Math.fround(Math.log(( + y)))) | 0) >>> 0), ((( + (( + (Math.fround(( + y)) & Math.fround(Math.fround(Math.hypot(Math.fround(x), y))))) <= ( + (Math.atan((x >>> 0)) >>> 0)))) >= ( - ( + y))) >>> 0)) | 0)); }); testMathyFunction(mathy0, [(new Boolean(true)), NaN, 1, true, '', ({valueOf:function(){return '0';}}), false, objectEmulatingUndefined(), (new String('')), (new Number(0)), (new Number(-0)), 0, ({toString:function(){return '0';}}), 0.1, -0, [], [0], (function(){return 0;}), ({valueOf:function(){return 0;}}), '\\0', null, '/0/', (new Boolean(false)), '0', undefined, /0/]); ");
/*fuzzSeed-211892750*/count=872; tryItOut("mathy1 = (function(x, y) { return ( + (( + ((Math.hypot(mathy0(Math.fround(y), Math.fround(Math.pow(0, Math.fround(( + ( ~ (x >>> 0))))))), -0x0ffffffff) ** (Math.asin((Math.trunc(y) >>> 0)) >>> 0)) ? (Math.max((y | 0), (( + (Math.min(-Number.MAX_SAFE_INTEGER, (-Number.MIN_VALUE | 0)) | 0)) | 0)) | 0) : ((( - (Math.round(x) | 0)) ? y : ( + mathy0(((Math.min((y >>> 0), (y >>> 0)) >>> 0) >>> 0), ( + ( + ( + (((x >>> 0) | (y >>> 0)) >>> 0))))))) >>> 0))) ** (( - (Math.atanh((( ~ y) >>> 0)) | 0)) | 0))); }); ");
/*fuzzSeed-211892750*/count=873; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.sinh(Math.fround((( ~ (( ! ((mathy2((Math.exp((( - (x >>> 0)) >>> 0)) >>> 0), (Math.trunc(y) >>> 0)) >>> 0) ? Math.fround(mathy1(Math.fround(x), Math.fround((((y >>> 0) > (x >>> 0)) >>> 0)))) : ( + Math.log10(( + 0x07fffffff))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-211892750*/count=874; tryItOut("\"use strict\"; /*oLoop*/for (let cxnijd = 0; cxnijd < 12; ++cxnijd) { for (var p in e2) { try { o0.m1 + ''; } catch(e0) { } try { for (var p in m0) { try { t1 = new Float64Array(b2); } catch(e0) { } try { a0.pop(h1, t2, t0); } catch(e1) { } try { a2.unshift(p1, v0, -25, g0); } catch(e2) { } e0.has(p1); } } catch(e1) { } try { print(uneval(i0)); } catch(e2) { } v0 = Array.prototype.some.apply(g0.a2, [f0, m2, o0, true]); } } ");
/*fuzzSeed-211892750*/count=875; tryItOut("v2 = evalcx(\"g2.t0[({valueOf: function() {  for  each(var a in [1,,]) 25;return 18; }})];\", g0);");
/*fuzzSeed-211892750*/count=876; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround((Math.tan(( + (Math.tan(( + (( + (Math.tanh(Math.fround(x)) | 0)) ? ( + Math.fround(Math.imul(y, x))) : ( + Math.fround(Math.min(Math.fround((y ? y : ( - y))), Math.fround(( ! x)))))))) | 0))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-211892750*/count=877; tryItOut("/*hhh*/function uhkkab(d, ...x){while(([] = yield ({a1:1}) instanceof (e = Proxy.createFunction(({/*TOODEEP*/})(undefined), mathy4))) && 0){/*ODP-1*/Object.defineProperty(this.b1, x, ({set: ((Function.prototype.toString)( /x/g )).log10, enumerable: true}));yield; }}/*iii*/let (c) /(?!\\B*|[^]|.{2,4}.\\B\\s+{2,5})/yim;");
/*fuzzSeed-211892750*/count=878; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+(0x34bd1ead));\n    d1 = (+(0.0/0.0));\n    (Int8ArrayView[((((-(0x2b215642)) | ((0x49fa1f5a))) < (~~(d0)))-((((0x3e81e7a3) % (0x6b37af8f))>>>((0x9caa606c)-(0x84890670))) != (0x52029342))) >> 0]) = (((abs(((((0xfdf383e2) ? (0xfd369254) : (0xffffffff))+(0xe602050b)-(0x92046eaf)) & ((0xf9a6c801))))|0) > (((0x70fcae54)) ^ ((0xfa834430)+(0x1e02e3c4)))));\n    d0 = (d0);\n    d0 = (-((x = Proxy(x, \"\\u8552\"))));\n    d0 = (((d0)) * ((+(1.0/0.0))));\n    return +((((d0)) / ((d0))));\n  }\n  return f; })(this, {ff: (new Function(\"/*RXUB*/var r = r2; var s = s2; print(s.match(r)); \"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, ['/0/', false, '', ({toString:function(){return '0';}}), null, undefined, 0, (new String('')), NaN, [0], -0, '0', ({valueOf:function(){return '0';}}), (function(){return 0;}), true, (new Boolean(true)), (new Boolean(false)), 1, objectEmulatingUndefined(), (new Number(0)), /0/, 0.1, ({valueOf:function(){return 0;}}), [], (new Number(-0)), '\\0']); ");
/*fuzzSeed-211892750*/count=879; tryItOut("/*RXUB*/var r = new RegExp(\"(?:^){4,8}((\\\\d(?!\\\\S)|[^]*?){134217728})\", \"gm\"); var s = \"\\n\\n\\n\\n\"; print(s.split(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
